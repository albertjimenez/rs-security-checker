//! Broad secret discovery: orphaned private keys, `.env` files and stored Git credentials.
//!
//! The Jenkins stage runs `find` over a handful of well-known roots. This module does the same
//! with an explicit argv, skips roots that do not exist, and bounds the number of paths copied
//! into the report so a huge home directory cannot exhaust memory.

use std::path::PathBuf;

use crate::audit::{StageContext, first_lines};
use crate::exec::Cmd;
use crate::report::{Severity, StageId, StageReport, StageStatus};

const MAX_KEY_FILES: usize = 100;
const MAX_ENV_FILES: usize = 20;
const MAX_GIT_FILES: usize = 100;

const KEY_PREDICATES: [&str; 14] = [
    "(",
    "-name",
    "*.pem",
    "-o",
    "-name",
    "*.key",
    "-o",
    "-name",
    "id_rsa",
    "-o",
    "-name",
    "id_ed25519",
    ")",
    "!",
];

/// Roots inspected by this stage. Tests replace them with temporary directories.
struct SecretRoots {
    key_roots: Vec<PathBuf>,
    env_roots: Vec<PathBuf>,
    git_roots: Vec<PathBuf>,
}

impl Default for SecretRoots {
    fn default() -> Self {
        Self {
            key_roots: paths(&["/home", "/root", "/var/www", "/opt"]),
            env_roots: paths(&["/home", "/var/www", "/opt"]),
            git_roots: paths(&["/home", "/root"]),
        }
    }
}

fn paths(values: &[&str]) -> Vec<PathBuf> {
    values.iter().map(PathBuf::from).collect()
}

pub fn run(ctx: &StageContext<'_>) -> StageReport {
    run_with_paths(ctx, &SecretRoots::default())
}

fn run_with_paths(ctx: &StageContext<'_>, paths: &SecretRoots) -> StageReport {
    let mut report = StageReport::new(StageId::BroadSecrets);
    let mut timed_out = false;

    report.push_header("=== ORPHANED SSH PRIVATE KEYS ===");
    check_find(
        ctx,
        &paths.key_roots,
        &key_predicates(),
        MAX_KEY_FILES,
        "No orphaned private keys found.",
        "orphaned SSH private key(s) found outside standard .ssh directories",
        Severity::Medium,
        &mut report,
        &mut timed_out,
    );

    report.push_header("=== ENVIRONMENT (.env) FILES ===");
    check_find(
        ctx,
        &paths.env_roots,
        &["-name", ".env"],
        MAX_ENV_FILES,
        "No standard .env files located in web or user roots.",
        ".env file(s) found; check them manually for hardcoded database/API secrets",
        Severity::Low,
        &mut report,
        &mut timed_out,
    );

    report.push_header("=== STORED GIT CREDENTIALS ===");
    check_find(
        ctx,
        &paths.git_roots,
        &["-name", ".git-credentials"],
        MAX_GIT_FILES,
        "No plaintext .git-credentials found.",
        "plaintext Git credential file(s) found on disk",
        Severity::High,
        &mut report,
        &mut timed_out,
    );

    if timed_out {
        report.finish(Some(StageStatus::TimedOut));
    } else {
        report.finish(None);
    }
    report
}

/// Shared `find` execution and reporting for the three secret categories.
#[allow(clippy::too_many_arguments)]
fn check_find(
    ctx: &StageContext<'_>,
    roots: &[PathBuf],
    predicates: &[&str],
    limit: usize,
    empty_message: &str,
    finding_message: &str,
    severity: Severity,
    report: &mut StageReport,
    timed_out: &mut bool,
) {
    if ctx.cfg.dry_run {
        report.push_block("", "Skipped: dry-run does not run find.");
        report.note("dry-run: secret discovery was not executed");
        return;
    }
    if !ctx.tool_exists("find") {
        report.push_block("", "Skipped: find command not found.");
        report.finding(
            Severity::Low,
            "find is unavailable; broad secret discovery could not be audited",
        );
        return;
    }

    let roots = existing_roots(roots);
    if roots.is_empty() {
        report.push_block("", empty_message);
        report.note("none of the configured secret-search roots exist");
        return;
    }

    let output = ctx.run(find_command(&roots, predicates));
    if output.timed_out {
        *timed_out = true;
        report.push_block(&output.combined(), "(no output)");
        report.finding(
            Severity::Medium,
            format!("{finding_message}: find timed out"),
        );
        return;
    }
    if !output.success() {
        report.note(format!(
            "find failed: {}",
            first_lines(&output.combined(), 1)
        ));
    }

    let (entries, truncated) = capped_lines(&output.stdout, limit);
    if entries.is_empty() {
        if output.success() {
            report.push_block("", empty_message);
        } else {
            report.push_block("", "Skipped: find failed before producing results.");
        }
        return;
    }

    let mut listing = entries.join("\n");
    if truncated {
        listing.push_str(&format!("\n[truncated at {limit} paths]"));
    }
    report.push_block(
        &format!("[-] [{severity}] {finding_message}:\n{listing}"),
        "",
    );
    report.finding(
        severity,
        format!("{} {} found", entries.len(), finding_message),
    );
}

fn key_predicates() -> Vec<&'static str> {
    let mut predicates = KEY_PREDICATES.to_vec();
    predicates.extend(["-path", "*/.ssh/*"]);
    predicates
}

fn find_command(roots: &[PathBuf], predicates: &[&str]) -> Cmd {
    Cmd::new("find")
        .args(roots)
        .args(["-type", "f"])
        .args(predicates)
        .sudo(true)
}

fn existing_roots(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut existing = Vec::new();
    for root in roots {
        if root.exists() && !existing.contains(root) {
            existing.push(root.clone());
        }
    }
    existing
}

fn capped_lines(stdout: &str, limit: usize) -> (Vec<String>, bool) {
    let all = stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let truncated = all.len() > limit;
    let entries = all
        .into_iter()
        .take(limit)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    (entries, truncated)
}

#[allow(dead_code)]
#[cfg(test)]
mod tests {
    use std::path::Path;

    use tempfile::TempDir;

    use super::*;
    use crate::audit::test_support::{FakeRunner, exit, ok, stage_context, timed_out};
    use crate::config::test_config;
    use crate::report::StageStatus;

    fn roots_for(root: &Path) -> SecretRoots {
        SecretRoots {
            key_roots: vec![root.to_path_buf()],
            env_roots: vec![root.to_path_buf()],
            git_roots: vec![root.to_path_buf()],
        }
    }

    fn command_key(command: &Cmd) -> String {
        let mut key = command.program().to_owned();
        for argument in command.arguments() {
            key.push(' ');
            key.push_str(&argument.to_string_lossy());
        }
        key
    }

    fn key_command(roots: &[PathBuf]) -> String {
        command_key(&find_command(roots, &key_predicates()))
    }

    fn env_command(roots: &[PathBuf]) -> String {
        command_key(&find_command(roots, &["-name", ".env"]))
    }

    fn git_command(roots: &[PathBuf]) -> String {
        command_key(&find_command(roots, &["-name", ".git-credentials"]))
    }

    fn run_with(runner: &FakeRunner, root: &Path) -> StageReport {
        let cfg = test_config();
        let ui = crate::test_support::ui();
        let ctx = stage_context(&cfg, runner, &ui);
        run_with_paths(&ctx, &roots_for(root))
    }

    fn temp_root(dir: &TempDir) -> PathBuf {
        let root = dir.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn git_credentials_are_high_severity() {
        let dir = tempfile::tempdir().unwrap();
        let root = temp_root(&dir);
        let roots = vec![root.clone()];
        let runner = FakeRunner::new(&["find"])
            .respond(&key_command(&roots), ok(""))
            .respond(&env_command(&roots), ok(""))
            .respond(
                &git_command(&roots),
                ok(format!("{}\n", root.join(".git-credentials").display())),
            );
        let report = run_with(&runner, &root);
        assert_eq!(report.highest_severity(), Severity::High);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("Git credential"))
        );
    }

    #[test]
    fn private_keys_are_medium_severity() {
        let dir = tempfile::tempdir().unwrap();
        let root = temp_root(&dir);
        let roots = vec![root.clone()];
        let runner = FakeRunner::new(&["find"])
            .respond(
                &key_command(&roots),
                ok(format!("{}\n", root.join("deploy.pem").display())),
            )
            .respond(&env_command(&roots), ok(""))
            .respond(&git_command(&roots), ok(""));
        let report = run_with(&runner, &root);
        assert_eq!(report.highest_severity(), Severity::Medium);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("private key"))
        );
    }

    #[test]
    fn env_files_are_low_severity() {
        let dir = tempfile::tempdir().unwrap();
        let root = temp_root(&dir);
        let roots = vec![root.clone()];
        let runner = FakeRunner::new(&["find"])
            .respond(&key_command(&roots), ok(""))
            .respond(
                &env_command(&roots),
                ok(format!("{}\n", root.join(".env").display())),
            )
            .respond(&git_command(&roots), ok(""));
        let report = run_with(&runner, &root);
        assert_eq!(report.highest_severity(), Severity::Low);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains(".env file"))
        );
    }

    #[test]
    fn clean_root_passes() {
        let dir = tempfile::tempdir().unwrap();
        let root = temp_root(&dir);
        let roots = vec![root.clone()];
        let runner = FakeRunner::new(&["find"])
            .respond(&key_command(&roots), ok(""))
            .respond(&env_command(&roots), ok(""))
            .respond(&git_command(&roots), ok(""));
        let report = run_with(&runner, &root);
        assert_eq!(report.status, StageStatus::Passed);
        assert!(
            report
                .output
                .contains("No plaintext .git-credentials found.")
        );
    }

    #[test]
    fn missing_roots_are_noted() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        let report = run_with(&FakeRunner::new(&["find"]), &missing);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("none of the configured secret-search roots exist"))
        );
    }

    #[test]
    fn missing_find_is_low_severity() {
        let dir = tempfile::tempdir().unwrap();
        let root = temp_root(&dir);
        let report = run_with(&FakeRunner::new(&[]), &root);
        assert_eq!(report.highest_severity(), Severity::Low);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("find is unavailable"))
        );
    }

    #[test]
    fn find_timeout_is_medium_severity() {
        let dir = tempfile::tempdir().unwrap();
        let root = temp_root(&dir);
        let roots = vec![root.clone()];
        let runner = FakeRunner::new(&["find"]).respond(&key_command(&roots), timed_out());
        let report = run_with(&runner, &root);
        assert_eq!(report.status, StageStatus::TimedOut);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("find timed out"))
        );
    }

    #[test]
    fn find_failure_is_noted() {
        let dir = tempfile::tempdir().unwrap();
        let root = temp_root(&dir);
        let roots = vec![root.clone()];
        let runner =
            FakeRunner::new(&["find"]).respond(&key_command(&roots), exit(1, "permission denied"));
        let report = run_with(&runner, &root);
        assert!(report.notes.iter().any(|note| note.contains("find failed")));
    }

    #[test]
    fn dry_run_is_noted() {
        let dir = tempfile::tempdir().unwrap();
        let root = temp_root(&dir);
        let mut cfg = test_config();
        cfg.dry_run = true;
        let runner = FakeRunner::new(&["find"]);
        let ui = crate::test_support::ui();
        let ctx = stage_context(&cfg, &runner, &ui);
        let report = run_with_paths(&ctx, &roots_for(&root));
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("secret discovery was not executed"))
        );
    }

    #[test]
    fn output_is_capped_and_marked() {
        let (entries, truncated) = capped_lines("a\nb\nc\n", 2);
        assert_eq!(entries, vec!["a", "b"]);
        assert!(truncated);
    }
}
