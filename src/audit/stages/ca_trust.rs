//! CA trust store and eMudhra/emSign compromise audit.
//!
//! The shell pipeline greps the Debian CA configuration and the compiled certificate bundle for
//! the compromised eMudhra/emSign authorities, then checks whether a `ca-certificates` update is
//! still pending. This stage keeps the same checks but reads the files directly and executes
//! `apt-get` with an explicit argv.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

use crate::audit::{StageContext, first_lines};
use crate::exec::Cmd;
use crate::fsutil::read_limited;
use crate::report::{Severity, StageId, StageReport, StageStatus};

const CA_CONFIG: &str = "/etc/ca-certificates.conf";
const CA_BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";
/// The bundle is normally a few hundred KiB; the cap protects against a hostile replacement.
const MAX_CA_FILE_BYTES: u64 = 16 * 1024 * 1024;

static EMUDHRA: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)emudhra|emsign").expect("valid eMudhra/emSign regex"));

/// CA files inspected by this stage. Tests replace them with a temporary tree.
struct CaPaths {
    config: PathBuf,
    bundle: PathBuf,
}

impl Default for CaPaths {
    fn default() -> Self {
        Self {
            config: PathBuf::from(CA_CONFIG),
            bundle: PathBuf::from(CA_BUNDLE),
        }
    }
}

pub fn run(ctx: &StageContext<'_>) -> StageReport {
    run_with_paths(ctx, &CaPaths::default())
}

fn run_with_paths(ctx: &StageContext<'_>, paths: &CaPaths) -> StageReport {
    let mut report = StageReport::new(StageId::CaTrust);
    let mut timed_out = false;

    report.push_header("=== CA TRUST & eMUDHRA COMPROMISE AUDIT ===");
    check_config(&paths.config, &mut report);
    check_bundle(&paths.bundle, &mut report);

    if ctx.cfg.dry_run {
        report.push_block("", "Skipped: dry-run does not run apt-get.");
        report.note("dry-run: pending ca-certificates upgrade check was not executed");
    } else if !ctx.tool_exists("apt-get") {
        report.push_block("", "Skipped: apt-get command not found.");
        report.finding(
            Severity::Low,
            "apt-get is unavailable; pending ca-certificates updates could not be audited",
        );
    } else {
        let update = ctx.run(Cmd::new("apt-get").args(["update", "-qq"]).sudo(true));
        if update.timed_out {
            timed_out = true;
            report.finding(Severity::Medium, "apt-get update timed out");
        } else if !update.success() {
            report.note(format!(
                "apt-get update failed: {}",
                first_lines(&update.combined(), 1)
            ));
        }

        let upgrades =
            ctx.run(Cmd::new("apt-get").args(["--just-print", "upgrade", "ca-certificates"]));
        if upgrades.dry_run {
            report.push_block(&upgrades.stdout, "(no output)");
            report.note("dry-run: pending ca-certificates upgrade check was not executed");
        } else if upgrades.timed_out {
            timed_out = true;
            report.finding(
                Severity::Medium,
                "apt-get --just-print upgrade ca-certificates timed out",
            );
        } else {
            let pending = pending_ca_update(&upgrades.stdout);
            if pending.is_empty() {
                report.push_block("", "[+] ca-certificates OS package is fully up to date.");
                report.note("ca-certificates package is up to date");
            } else {
                report.push_block(&pending, "");
                report.finding(
                    Severity::Medium,
                    "pending ca-certificates update; the package usually carries upstream distrust lists",
                );
            }
            if !upgrades.success() {
                report.note(format!(
                    "apt-get --just-print upgrade ca-certificates failed: {}",
                    first_lines(&upgrades.combined(), 1)
                ));
            }
        }
    }

    if timed_out {
        report.finish(Some(StageStatus::TimedOut));
    } else {
        report.finish(None);
    }
    report
}

fn check_config(path: &Path, report: &mut StageReport) {
    match read_limited(path, MAX_CA_FILE_BYTES) {
        Ok(text) => {
            let entries = active_matches(&text);
            if entries.is_empty() {
                report.push_block(
                    "",
                    "[+] No eMudhra/emSign entries active in /etc/ca-certificates.conf.",
                );
                report.note("no active eMudhra/emSign entries in the CA configuration");
            } else {
                let listing = entries.join("\n");
                report.push_block(
                    &format!(
                        "[-] [HIGH] eMudhra or emSign certificates are active in {}:\n{listing}\n--> ACTION: Verify if these match the compromised CAs (e.g., emSign ECC Root CA - G3).",
                        path.display()
                    ),
                    "",
                );
                report.finding(
                    Severity::High,
                    format!(
                        "{} active eMudhra/emSign entr{} in {}",
                        entries.len(),
                        if entries.len() == 1 { "y" } else { "ies" },
                        path.display()
                    ),
                );
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            report.push_block("", &format!("Skipped: {} not found.", path.display()));
            report.note(format!(
                "{} was not found; the CA configuration was not audited",
                path.display()
            ));
        }
        Err(error) => {
            report.push_block("", &format!("Could not read {}: {error}", path.display()));
            report.finding(
                Severity::Medium,
                format!("could not read {}: {error}", path.display()),
            );
        }
    }
}

fn check_bundle(path: &Path, report: &mut StageReport) {
    match read_limited(path, MAX_CA_FILE_BYTES) {
        Ok(text) => {
            if EMUDHRA.is_match(&text) {
                report.push_block(
                    &format!(
                        "[-] [HIGH] Found eMudhra/emSign string matches in {}!\n--> ACTION: A manual distrust or package update is required.",
                        path.display()
                    ),
                    "",
                );
                report.finding(
                    Severity::High,
                    format!("found eMudhra/emSign string matches in {}", path.display()),
                );
            } else {
                report.push_block(
                    "",
                    "[+] The compiled CA bundle does not contain eMudhra/emSign strings.",
                );
                report.note("the compiled CA bundle does not contain eMudhra/emSign strings");
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            report.push_block("", &format!("Skipped: {} not found.", path.display()));
            report.note(format!(
                "{} was not found; the compiled CA bundle was not audited",
                path.display()
            ));
        }
        Err(error) => {
            report.push_block("", &format!("Could not read {}: {error}", path.display()));
            report.finding(
                Severity::Medium,
                format!("could not read {}: {error}", path.display()),
            );
        }
    }
}

/// Return non-comment, non-disabled CA entries that mention eMudhra or emSign.
fn active_matches(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with('!'))
        .filter(|line| EMUDHRA.is_match(line))
        .map(str::to_owned)
        .collect()
}

fn pending_ca_update(stdout: &str) -> String {
    stdout
        .lines()
        .filter(|line| line.trim_start().starts_with("Inst ca-certificates"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use tempfile::TempDir;

    use super::*;
    use crate::audit::test_support::{FakeRunner, dry, ok, stage_context};
    use crate::config::test_config;
    use crate::report::StageStatus;

    const UPDATE: &str = "apt-get update -qq";
    const UPGRADES: &str = "apt-get --just-print upgrade ca-certificates";

    fn write_file(dir: &TempDir, name: &str, contents: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    fn run_with(runner: &FakeRunner, config: &Path, bundle: &Path) -> StageReport {
        let cfg = test_config();
        let ui = crate::test_support::ui();
        let ctx = stage_context(&cfg, runner, &ui);
        run_with_paths(
            &ctx,
            &CaPaths {
                config: config.to_path_buf(),
                bundle: bundle.to_path_buf(),
            },
        )
    }

    #[test]
    fn active_emudhra_entry_is_high_severity() {
        let dir = tempfile::tempdir().unwrap();
        let config = write_file(
            &dir,
            "ca-certificates.conf",
            "# comment\nemSign ECC Root CA - G3\n",
        );
        let bundle = write_file(&dir, "ca-certificates.crt", "clean bundle\n");
        let report = run_with(&FakeRunner::new(&[]), &config, &bundle);
        assert_eq!(report.highest_severity(), Severity::High);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("active eMudhra/emSign"))
        );
    }

    #[test]
    fn commented_and_disabled_entries_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let config = write_file(
            &dir,
            "ca-certificates.conf",
            "# emSign Root CA\n!emSign ECC Root CA - G3\n",
        );
        let bundle = write_file(&dir, "ca-certificates.crt", "clean bundle\n");
        let report = run_with(&FakeRunner::new(&[]), &config, &bundle);
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.message.contains("active eMudhra/emSign"))
        );
    }

    #[test]
    fn bundle_match_is_high_severity() {
        let dir = tempfile::tempdir().unwrap();
        let config = write_file(&dir, "ca-certificates.conf", "clean\n");
        let bundle = write_file(
            &dir,
            "ca-certificates.crt",
            "-----BEGIN CERTIFICATE-----\nemSign Root\n",
        );
        let report = run_with(&FakeRunner::new(&[]), &config, &bundle);
        assert_eq!(report.highest_severity(), Severity::High);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("eMudhra/emSign string matches"))
        );
    }

    #[test]
    fn pending_ca_update_is_medium_severity() {
        let dir = tempfile::tempdir().unwrap();
        let config = write_file(&dir, "ca-certificates.conf", "clean\n");
        let bundle = write_file(&dir, "ca-certificates.crt", "clean\n");
        let runner = FakeRunner::new(&["apt-get"])
            .respond(UPDATE, ok(""))
            .respond(
                UPGRADES,
                ok("Inst ca-certificates [2023] (2024 Debian:stable [all])\n"),
            );
        let report = run_with(&runner, &config, &bundle);
        assert_eq!(report.highest_severity(), Severity::Medium);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("pending ca-certificates update"))
        );
    }

    #[test]
    fn up_to_date_ca_package_passes() {
        let dir = tempfile::tempdir().unwrap();
        let config = write_file(&dir, "ca-certificates.conf", "clean\n");
        let bundle = write_file(&dir, "ca-certificates.crt", "clean\n");
        let runner = FakeRunner::new(&["apt-get"])
            .respond(UPDATE, ok(""))
            .respond(UPGRADES, ok("Inst other [1.0] (1.1 Debian:stable [all])\n"));
        let report = run_with(&runner, &config, &bundle);
        assert_eq!(report.status, StageStatus::Passed);
        assert!(report.output.contains("fully up to date"));
    }

    #[test]
    fn dry_run_skips_apt() {
        let dir = tempfile::tempdir().unwrap();
        let config = write_file(&dir, "ca-certificates.conf", "clean\n");
        let bundle = write_file(&dir, "ca-certificates.crt", "clean\n");
        let mut cfg = test_config();
        cfg.dry_run = true;
        let runner = FakeRunner::new(&["apt-get"]);
        let ui = crate::test_support::ui();
        let ctx = stage_context(&cfg, &runner, &ui);
        let report = run_with_paths(&ctx, &CaPaths { config, bundle });
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("pending ca-certificates upgrade check was not executed"))
        );
    }

    #[test]
    fn dry_run_upgrade_output_is_noted() {
        let dir = tempfile::tempdir().unwrap();
        let config = write_file(&dir, "ca-certificates.conf", "clean\n");
        let bundle = write_file(&dir, "ca-certificates.crt", "clean\n");
        let runner = FakeRunner::new(&["apt-get"])
            .respond(UPDATE, ok(""))
            .respond(UPGRADES, dry());
        let report = run_with(&runner, &config, &bundle);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("pending ca-certificates upgrade check was not executed"))
        );
    }

    #[test]
    fn missing_files_are_noted_not_failed() {
        let dir = tempfile::tempdir().unwrap();
        let report = run_with(
            &FakeRunner::new(&["apt-get"])
                .respond(UPDATE, ok(""))
                .respond(UPGRADES, ok("")),
            &dir.path().join("missing.conf"),
            &dir.path().join("missing.crt"),
        );
        assert_eq!(report.status, StageStatus::Passed);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("was not found"))
        );
    }

    #[test]
    fn active_matches_filters_comments_and_disabled_lines() {
        let entries =
            active_matches("# emSign Root\n!emSign ECC Root CA - G3\nemSign TLS Root CA\nother\n");
        assert_eq!(entries, vec!["emSign TLS Root CA"]);
    }

    #[test]
    fn pending_ca_update_only_keeps_ca_certificates() {
        let output = "Inst ca-certificates [1.0] (1.1 Debian:stable [all])\nInst curl [1.0] (1.1 Debian:stable [amd64])\n";
        let pending = pending_ca_update(output);
        assert_eq!(pending.lines().count(), 1);
        assert!(pending.contains("ca-certificates"));
    }
}
