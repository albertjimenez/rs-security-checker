//! Authentication log analysis.
//!
//! Reads a bounded tail of `/var/log/auth.log` (Debian), `/var/log/secure` (RHEL) and custom
//! `--auth-log` paths. It detects SSH brute force, invalid-user probing, break-in markers and
//! successful logins that follow a burst of failures.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

use crate::audit::StageContext;
use crate::logs;
use crate::report::{Severity, StageId, StageReport, StageStatus};
use crate::text::truncate_with_ellipsis;

const MAX_LOG_FILES: usize = 16;
const MAX_SAMPLES: usize = 5;
const MAX_SAMPLE_CHARS: usize = 300;
const FAILURE_MEDIUM: usize = 10;
const FAILURE_HIGH: usize = 100;
const INVALID_MEDIUM: usize = 50;
const SUCCESS_AFTER_FAILURE_MIN: usize = 5;

const DEFAULT_LOG_ROOTS: [&str; 3] = ["/var/log", "/var/log/secure", "/var/log/auth.log"];

#[derive(Default)]
struct AuthStats {
    lines: usize,
    failures_by_ip: BTreeMap<String, usize>,
    failures_by_user: BTreeMap<String, usize>,
    invalid_users: BTreeMap<String, usize>,
    accepted: usize,
    accepted_root: usize,
    accepted_after_failures: Vec<String>,
    pending_failures: BTreeMap<String, usize>,
    breakins: Vec<String>,
    sudo_denials: Vec<String>,
}

impl AuthStats {
    fn ingest(&mut self, text: &str) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            self.lines += 1;

            if let Some(captures) = FAILED_RE.captures(line) {
                let user = captures["user"].to_owned();
                let ip = captures["ip"].to_owned();
                *self.failures_by_ip.entry(ip.clone()).or_insert(0) += 1;
                *self.pending_failures.entry(ip).or_insert(0) += 1;
                *self.failures_by_user.entry(user).or_insert(0) += 1;
            } else if let Some(captures) = PAM_FAILURE_RE.captures(line) {
                let ip = captures["ip"].to_owned();
                *self.failures_by_ip.entry(ip.clone()).or_insert(0) += 1;
                *self.pending_failures.entry(ip).or_insert(0) += 1;
            }

            if let Some(captures) = INVALID_USER_RE.captures(line) {
                *self
                    .invalid_users
                    .entry(captures["user"].to_owned())
                    .or_insert(0) += 1;
            }

            if let Some(captures) = ACCEPTED_RE.captures(line) {
                let user = captures["user"].to_owned();
                let ip = captures["ip"].to_owned();
                self.accepted += 1;
                if user == "root" {
                    self.accepted_root += 1;
                }
                let failures = self.pending_failures.remove(&ip).unwrap_or(0);
                if failures >= SUCCESS_AFTER_FAILURE_MIN {
                    self.accepted_after_failures
                        .push(format!("{user} from {ip} after {failures} failure(s)"));
                }
            }

            if BREAKIN_RE.is_match(line) {
                push_sample(&mut self.breakins, line);
            }
            if SUDO_DENIAL_RE.is_match(line) {
                push_sample(&mut self.sudo_denials, line);
            }
        }
    }

    fn failure_total(&self) -> usize {
        self.failures_by_ip.values().sum()
    }

    fn invalid_total(&self) -> usize {
        self.invalid_users.values().sum()
    }
}

fn push_sample(samples: &mut Vec<String>, line: &str) {
    if samples.len() < MAX_SAMPLES {
        samples.push(truncate_with_ellipsis(line, MAX_SAMPLE_CHARS));
    }
}

pub fn run(ctx: &StageContext<'_>) -> StageReport {
    let roots = if ctx.cfg.auth_log_paths.is_empty() {
        DEFAULT_LOG_ROOTS.iter().map(PathBuf::from).collect()
    } else {
        ctx.cfg.auth_log_paths.clone()
    };
    let files = logs::collect_files(&roots, is_auth_log, MAX_LOG_FILES);
    run_files(ctx, &files)
}

fn run_files(ctx: &StageContext<'_>, files: &[PathBuf]) -> StageReport {
    let mut report = StageReport::new(StageId::Auth);
    report.push_header("=== AUTHENTICATION LOGS ===");

    if files.is_empty() {
        report.push_block(
            "Skipped: no auth.log/secure logs found.",
            "Skipped: no authentication logs found.",
        );
        report.note("no authentication logs were found; auth log analysis skipped");
        report.finish(Some(StageStatus::Skipped));
        return report;
    }

    let mut stats = AuthStats::default();
    let (sources, unreadable) =
        crate::audit::read_log_tails(files, ctx.cfg.log_tail_bytes, |text| stats.ingest(text));

    report.push_header("=== LOG SOURCES ===");
    report.push_block(&sources.join("\n"), "No readable authentication logs.");

    if unreadable > 0 {
        report.finding(
            Severity::Medium,
            format!("{unreadable} authentication log file(s) could not be read"),
        );
    }

    report.push_header("=== SUMMARY ===");
    report.push_block(
        &format!(
            "lines: {}\nfailed authentications: {}\ninvalid users: {}\nsuccessful logins: {}\nroot logins: {}\nbreak-in markers: {}\nsudo denials: {}",
            stats.lines,
            stats.failure_total(),
            stats.invalid_total(),
            stats.accepted,
            stats.accepted_root,
            stats.breakins.len(),
            stats.sudo_denials.len()
        ),
        "No authentication events parsed.",
    );

    let failures = stats.failure_total();
    if failures >= FAILURE_MEDIUM {
        let severity = if failures >= FAILURE_HIGH {
            Severity::High
        } else {
            Severity::Medium
        };
        report.finding(
            severity,
            format!(
                "SSH authentication failures: {failures}; top source IPs: {}",
                logs::top_counts(&stats.failures_by_ip, 5)
            ),
        );
        report.push_block(
            &format!(
                "top targeted users: {}",
                logs::top_counts(&stats.failures_by_user, 5)
            ),
            "",
        );
    }

    let invalid = stats.invalid_total();
    if invalid >= 5 {
        let severity = if invalid >= INVALID_MEDIUM {
            Severity::Medium
        } else {
            Severity::Low
        };
        report.finding(
            severity,
            format!(
                "SSH invalid-user probes: {invalid}; top usernames: {}",
                logs::top_counts(&stats.invalid_users, 5)
            ),
        );
    }

    if !stats.accepted_after_failures.is_empty() {
        report.finding(
            Severity::High,
            format!(
                "successful login after repeated failures: {}",
                stats.accepted_after_failures.join("; ")
            ),
        );
        for sample in stats.accepted_after_failures.iter().take(MAX_SAMPLES) {
            report.push_block(&format!("login after failures: {sample}"), "");
        }
    }

    if !stats.breakins.is_empty() {
        report.finding(
            Severity::High,
            format!(
                "{} authentication break-in marker(s) in the logs",
                stats.breakins.len()
            ),
        );
        for sample in &stats.breakins {
            report.push_block(&format!("break-in marker: {sample}"), "");
        }
    }

    if !stats.sudo_denials.is_empty() {
        report.finding(
            Severity::Low,
            format!(
                "{} sudo denial(s); a user attempted commands outside sudoers",
                stats.sudo_denials.len()
            ),
        );
        for sample in &stats.sudo_denials {
            report.push_block(&format!("sudo denial: {sample}"), "");
        }
    }

    if stats.accepted_root > 0 {
        report.finding(
            Severity::Info,
            format!(
                "{} successful root login(s); verify they are expected",
                stats.accepted_root
            ),
        );
    }

    if failures == 0 && stats.accepted == 0 && stats.breakins.is_empty() {
        report.note("no authentication failures or break-in markers were found");
    } else {
        report.note(format!(
            "analyzed {} authentication log file(s)",
            files.len()
        ));
    }
    report.finish(None);
    report
}

fn is_auth_log(path: &Path) -> bool {
    crate::audit::is_uncompressed_log(path, |name| {
        name.contains("auth")
            || name.contains("secure")
            || name.starts_with("sshd")
            || name == "sudo"
    })
}

static FAILED_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Failed \S+ for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
        .expect("valid failed-login regex")
});

static ACCEPTED_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Accepted (?:\S+) for (?P<user>\S+) from (?P<ip>\S+)")
        .expect("valid accepted-login regex")
});

static INVALID_USER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)Invalid user (?P<user>\S+) from (?P<ip>\S+)")
        .expect("valid invalid-user regex")
});

static PAM_FAILURE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"pam_unix\([^)]*\): authentication failure.*rhost=(?P<ip>\S+)")
        .expect("valid PAM failure regex")
});

static BREAKIN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(BREAK-IN ATTEMPT|Possible break-in attempt|reverse mapping checking getaddrinfo .* failed)",
    )
    .expect("valid break-in regex")
});

static SUDO_DENIAL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"sudo:.*NOT in sudoers").expect("valid sudo denial regex"));

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::test_support::{
        FakeRunner, finding, finding_message, note, run_stage, write,
    };
    use crate::config::test_config;

    fn run_with_text(text: &str, name: &str) -> StageReport {
        crate::audit::test_support::run_with_file(text, name, |ctx, path| {
            run_files(ctx, std::slice::from_ref(path))
        })
    }

    #[test]
    fn skips_when_no_auth_logs_exist() {
        let report = run_stage(StageId::Auth, &FakeRunner::new(&[]), &test_config());
        assert_eq!(report.status, StageStatus::Skipped);
        assert!(note(&report, "auth"));
    }

    #[test]
    fn detects_failed_logins_and_brute_force() {
        let mut text = String::new();
        for index in 0..12 {
            text.push_str(&format!(
                "Jan  1 00:00:00 host sshd[1]: Failed password for invalid user admin from 10.0.0.{index} port 22 ssh2\n"
            ));
        }
        let report = run_with_text(&text, "auth.log");
        assert_eq!(report.status, StageStatus::Warnings);
        assert!(finding_message(&report, "authentication failures"));
        assert!(report.output.contains("top targeted users"));
    }

    #[test]
    fn detects_pam_failures_without_sshd_lines() {
        let mut text = String::new();
        for _ in 0..10 {
            text.push_str(
                "Jan  1 00:00:00 host sudo: pam_unix(sudo:auth): authentication failure; logname=uid=0 euid=0 tty=/dev/pts/0 ruser= rhost=10.1.2.3 user=root\n",
            );
        }
        let report = run_with_text(&text, "auth.log");
        assert!(finding_message(&report, "authentication failures"));
    }

    #[test]
    fn flags_successful_login_after_failures() {
        let mut text = String::new();
        for _ in 0..5 {
            text.push_str(
                "Jan  1 00:00:00 host sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2\n",
            );
        }
        text.push_str(
            "Jan  1 00:00:01 host sshd[1]: Accepted publickey for root from 10.0.0.1 port 22 ssh2\n",
        );
        let report = run_with_text(&text, "auth.log");
        assert!(finding(&report, Severity::High, "after repeated failures"));
        assert!(finding_message(&report, "root login"));
    }

    #[test]
    fn flags_breakin_markers_and_sudo_denials() {
        let text = "\
Jan  1 00:00:00 host sshd[1]: Possible break-in attempt!
Jan  1 00:00:00 host sudo: bob : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/sh
";
        let report = run_with_text(text, "auth.log");
        assert!(finding_message(&report, "break-in"));
        assert!(finding_message(&report, "sudo denial"));
    }

    #[test]
    fn invalid_user_probes_and_high_failure_counts_scale_severity() {
        let mut text = "\n".to_owned();
        for index in 0..100 {
            text.push_str(&format!(
                "Jan  1 00:00:00 host sshd[1]: Failed password for invalid user probe{index} from 10.0.0.1 port 22 ssh2\n"
            ));
        }
        let report = run_with_text(&text, "auth.log");
        assert!(finding(&report, Severity::High, "authentication failures"));
        assert!(finding(
            &report,
            Severity::Medium,
            "invalid-user probes: 100"
        ));
    }

    #[test]
    fn custom_auth_log_paths_are_used() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("custom-auth.log");
        write(
            &path,
            "Jan  1 00:00:00 host sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2\n",
        );
        let mut cfg = test_config();
        cfg.auth_log_paths = vec![path];
        let report = run_stage(StageId::Auth, &FakeRunner::new(&[]), &cfg);
        assert!(report.output.contains("custom-auth.log"));
    }

    #[test]
    fn clean_auth_logs_pass() {
        let text = "Jan  1 00:00:00 host sshd[1]: Accepted publickey for alice from 10.0.0.9 port 22 ssh2\n";
        let report = run_with_text(text, "auth.log");
        assert_eq!(report.status, StageStatus::Passed);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn unreadable_auth_logs_are_reported() {
        let runner = FakeRunner::new(&[]);
        let ui = crate::test_support::ui();
        let cfg = test_config();
        let ctx = crate::audit::test_support::stage_context(&cfg, &runner, &ui);
        let report = run_files(&ctx, &[PathBuf::from("/definitely/not/an/auth-log")]);
        assert!(finding_message(&report, "could not be read"));
    }

    #[test]
    fn auth_log_names_are_filtered() {
        assert!(is_auth_log(Path::new("/var/log/auth.log")));
        assert!(is_auth_log(Path::new("/var/log/secure")));
        assert!(is_auth_log(Path::new("/var/log/auth.log.1")));
        assert!(!is_auth_log(Path::new("/var/log/auth.log.gz")));
        assert!(!is_auth_log(Path::new("/var/log/nginx/access.log")));
    }
}
