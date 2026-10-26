//! Stage 6: Persistence & Account Audit.

use std::path::Path;

use crate::audit::{StageContext, first_lines};
use crate::exec::Cmd;
use crate::fsutil::read_limited;
use crate::report::{Severity, StageId, StageReport};

const CRONTAB_DIR: &str = "/var/spool/cron/crontabs";
const PASSWD_FILE: &str = "/etc/passwd";
/// `/etc/passwd` is small; the cap protects the audit from a maliciously large replacement.
const MAX_PASSWD_BYTES: u64 = 1024 * 1024;

pub fn run(ctx: &StageContext<'_>) -> StageReport {
    run_with_paths(ctx, Path::new(PASSWD_FILE), Path::new(CRONTAB_DIR))
}

fn run_with_paths(ctx: &StageContext<'_>, passwd_path: &Path, crontab_dir: &Path) -> StageReport {
    let mut report = StageReport::new(StageId::Persistence);

    report.push_header("=== UID 0 ACCOUNTS ===");
    match read_limited(passwd_path, MAX_PASSWD_BYTES) {
        Ok(passwd) => {
            let accounts = uid_zero_accounts(&passwd);
            if accounts.is_empty() {
                report.push_block("", "(no UID 0 accounts found)");
                report.finding(Severity::High, "no UID 0 account exists in /etc/passwd");
            } else {
                for account in &accounts {
                    report.output.push_str(&format!("{account}\n"));
                    if account != "root" {
                        report.finding(
                            Severity::Critical,
                            format!("non-root account `{account}` has UID 0"),
                        );
                    }
                }
            }
        }
        Err(error) => {
            report.push_block("", &format!("Could not read /etc/passwd: {error}"));
            report.finding(
                Severity::Medium,
                format!("could not read /etc/passwd: {error}"),
            );
        }
    }

    report.push_header("=== SYSTEM & USER CRONTABS ===");
    if crontab_dir.is_dir() {
        let crontabs = ctx.run(
            Cmd::new("find")
                .arg(crontab_dir)
                .args([
                    "-maxdepth",
                    "1",
                    "-type",
                    "f",
                    "-exec",
                    "tail",
                    "-n",
                    "+1",
                    "{}",
                    "+",
                ])
                .sudo(true),
        );
        if crontabs.dry_run {
            report.push_block(&crontabs.stdout, "No spool crontabs.");
            report.note("dry-run: crontab enumeration was not executed");
        } else if crontabs.timed_out {
            report.push_block(&crontabs.combined(), "(no output)");
            report.finding(Severity::Medium, "crontab enumeration timed out");
        } else if crontabs.success() && !crontabs.stdout.trim().is_empty() {
            report.push_block(&crontabs.stdout, "No spool crontabs.");
            report.finding(Severity::Info, "spool crontab entries are present");
        } else {
            report.push_block("", "No spool crontabs.");
            if !crontabs.success() {
                report.note(format!(
                    "could not enumerate spool crontabs: {}",
                    first_lines(&crontabs.combined(), 1)
                ));
            }
        }
    } else {
        report.push_block("", "No spool crontabs.");
    }

    report.push_header("=== ALL AUTHORIZED KEYS ===");
    let keys = ctx.run(
        Cmd::new("find")
            .args([
                "/root",
                "/home",
                "/var/lib",
                "-maxdepth",
                "4",
                "-name",
                "authorized_keys",
                "-exec",
                "ls",
                "-la",
                "{}",
                "+",
            ])
            .sudo(true),
    );
    if keys.dry_run {
        report.push_block(&keys.stdout, "No authorized_keys found.");
        report.note("dry-run: authorized_keys enumeration was not executed");
    } else if keys.timed_out {
        report.push_block(&keys.combined(), "(no output)");
        report.finding(Severity::Medium, "authorized_keys enumeration timed out");
    } else if keys.success() && !keys.stdout.trim().is_empty() {
        let count = keys.stdout.lines().filter(|l| !l.trim().is_empty()).count();
        report.push_block(&keys.stdout, "No authorized_keys found.");
        report.finding(
            Severity::Low,
            format!("{count} authorized_keys file(s) found for review"),
        );
    } else {
        report.push_block("", "No authorized_keys found.");
        if !keys.success() {
            report.note(format!(
                "authorized_keys enumeration failed: {}",
                first_lines(&keys.combined(), 1)
            ));
        }
    }

    report.push_header("=== SUSPICIOUS SYSTEMD UNITS ===");
    if ctx.tool_exists("systemctl") {
        let units = ctx.run(Cmd::new("systemctl").args([
            "list-unit-files",
            "--state=enabled",
            "--no-pager",
        ]));
        if units.dry_run {
            report.push_block(&units.stdout, "(no output)");
            report.note("dry-run: systemctl was not executed");
        } else if units.timed_out {
            report.push_block(&units.combined(), "(no output)");
            report.finding(Severity::Medium, "systemd unit enumeration timed out");
        } else if units.success() {
            let suspicious = suspicious_units(&units.stdout);
            if suspicious.is_empty() {
                report.push_block("", "No suspicious units.");
            } else {
                report.push_block(&suspicious, "No suspicious units.");
                report.finding(
                    Severity::Medium,
                    format!(
                        "enabled systemd units match local/custom/run/tmp: {}",
                        first_lines(&suspicious, 3)
                    ),
                );
            }
        } else {
            report.push_block("", "Skipped: systemctl could not list units.");
            report.note(format!(
                "systemctl failed: {}",
                first_lines(&units.combined(), 1)
            ));
        }
    } else {
        report.push_block("", "Skipped: systemctl command not found.");
        report.note("`systemctl` was not found; unit audit skipped");
    }

    report.finish(None);
    report
}

fn uid_zero_accounts(passwd: &str) -> Vec<String> {
    passwd
        .lines()
        .filter_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?;
            let _password = fields.next()?;
            let uid = fields.next()?;
            (uid == "0" && !name.is_empty()).then(|| name.to_owned())
        })
        .collect()
}

fn suspicious_units(stdout: &str) -> String {
    stdout
        .lines()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            ["local", "custom", "run", "tmp"]
                .iter()
                .any(|needle| lower.contains(needle))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use tempfile::TempDir;

    use super::*;
    use crate::audit::test_support::{FakeRunner, dry, exit, ok, stage_context, timed_out};
    use crate::config::{Config, test_config};
    use crate::report::StageStatus;
    use crate::ui::{ColorMode, Ui};

    const KEYS: &str =
        "find /root /home /var/lib -maxdepth 4 -name authorized_keys -exec ls -la {} +";
    const SYSTEMCTL: &str = "systemctl list-unit-files --state=enabled --no-pager";

    fn write_passwd(dir: &TempDir, contents: &str) -> PathBuf {
        let path = dir.path().join("passwd");
        std::fs::write(&path, contents).unwrap();
        path
    }

    fn run_with(runner: &FakeRunner, cfg: &Config, passwd: &Path, crontabs: &Path) -> StageReport {
        let ui = Ui::new(ColorMode::Never, true, false, false);
        let ctx = stage_context(cfg, runner, &ui);
        run_with_paths(&ctx, passwd, crontabs)
    }

    fn root_passwd() -> String {
        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n".to_owned()
    }

    fn crontab_command(dir: &Path) -> String {
        format!(
            "find {} -maxdepth 1 -type f -exec tail -n +1 {{}} +",
            dir.display()
        )
    }

    #[test]
    fn parses_uid_zero_accounts() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\nevil:x:0:0::/:/bin/sh\n";
        assert_eq!(uid_zero_accounts(passwd), vec!["root", "evil"]);
    }

    #[test]
    fn filters_suspicious_units_case_insensitively() {
        let units = "ssh.service enabled\nLOCAL-backdoor.service enabled\nsystemd-tmpfiles-setup.service enabled\n";
        let filtered = suspicious_units(units);
        assert!(filtered.contains("LOCAL-backdoor.service"));
        assert!(filtered.contains("systemd-tmpfiles-setup.service"));
        assert!(!filtered.contains("ssh.service"));
    }

    #[test]
    fn root_only_account_passes() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = write_passwd(&dir, &root_passwd());
        let report = run_with(
            &FakeRunner::new(&[]),
            &test_config(),
            &passwd,
            dir.path().join("none").as_path(),
        );
        assert_eq!(report.status, StageStatus::Passed);
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.severity == Severity::Critical)
        );
    }

    #[test]
    fn non_root_uid_zero_is_critical() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = write_passwd(
            &dir,
            "root:x:0:0:root:/root:/bin/bash\nevil:x:0:0::/:/bin/sh\n",
        );
        let report = run_with(
            &FakeRunner::new(&[]),
            &test_config(),
            &passwd,
            dir.path().join("none").as_path(),
        );
        assert_eq!(report.highest_severity(), Severity::Critical);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("`evil` has UID 0"))
        );
    }

    #[test]
    fn missing_uid_zero_account_is_high_severity() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = write_passwd(&dir, "daemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n");
        let report = run_with(
            &FakeRunner::new(&[]),
            &test_config(),
            &passwd,
            dir.path().join("none").as_path(),
        );
        assert_eq!(report.highest_severity(), Severity::High);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("no UID 0 account"))
        );
    }

    #[test]
    fn unreadable_passwd_is_medium_severity() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing-passwd");
        let report = run_with(
            &FakeRunner::new(&[]),
            &test_config(),
            &missing,
            dir.path().join("none").as_path(),
        );
        assert_eq!(report.highest_severity(), Severity::Medium);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("could not read /etc/passwd"))
        );
    }

    #[test]
    fn crontab_entries_are_informational() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = write_passwd(&dir, &root_passwd());
        let crontabs = dir.path().join("crontabs");
        std::fs::create_dir_all(&crontabs).unwrap();
        let runner = FakeRunner::new(&[]).respond(
            &crontab_command(&crontabs),
            ok("0 * * * * root /usr/bin/true\n"),
        );
        let report = run_with(&runner, &test_config(), &passwd, &crontabs);
        assert_eq!(report.highest_severity(), Severity::Info);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("spool crontab entries"))
        );
    }

    #[test]
    fn crontab_dry_run_is_noted() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = write_passwd(&dir, &root_passwd());
        let crontabs = dir.path().join("crontabs");
        std::fs::create_dir_all(&crontabs).unwrap();
        let runner = FakeRunner::new(&[]).respond(&crontab_command(&crontabs), dry());
        let report = run_with(&runner, &test_config(), &passwd, &crontabs);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("crontab enumeration was not executed"))
        );
    }

    #[test]
    fn crontab_timeout_is_medium_severity() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = write_passwd(&dir, &root_passwd());
        let crontabs = dir.path().join("crontabs");
        std::fs::create_dir_all(&crontabs).unwrap();
        let runner = FakeRunner::new(&[]).respond(&crontab_command(&crontabs), timed_out());
        let report = run_with(&runner, &test_config(), &passwd, &crontabs);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("crontab enumeration timed out"))
        );
    }

    #[test]
    fn crontab_failure_is_noted() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = write_passwd(&dir, &root_passwd());
        let crontabs = dir.path().join("crontabs");
        std::fs::create_dir_all(&crontabs).unwrap();
        let runner =
            FakeRunner::new(&[]).respond(&crontab_command(&crontabs), exit(1, "permission denied"));
        let report = run_with(&runner, &test_config(), &passwd, &crontabs);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("could not enumerate spool crontabs"))
        );
    }

    #[test]
    fn authorized_keys_are_low_severity() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = write_passwd(&dir, &root_passwd());
        let runner = FakeRunner::new(&[]).respond(
            KEYS,
            ok("-rw------- 1 root root 400 /root/.ssh/authorized_keys\n"),
        );
        let report = run_with(&runner, &test_config(), &passwd, &dir.path().join("none"));
        assert_eq!(report.highest_severity(), Severity::Low);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("authorized_keys file(s)"))
        );
    }

    #[test]
    fn authorized_keys_dry_run_is_noted() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = write_passwd(&dir, &root_passwd());
        let runner = FakeRunner::new(&[]).respond(KEYS, dry());
        let report = run_with(&runner, &test_config(), &passwd, &dir.path().join("none"));
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("authorized_keys enumeration was not executed"))
        );
    }

    #[test]
    fn authorized_keys_timeout_is_medium_severity() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = write_passwd(&dir, &root_passwd());
        let runner = FakeRunner::new(&[]).respond(KEYS, timed_out());
        let report = run_with(&runner, &test_config(), &passwd, &dir.path().join("none"));
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("authorized_keys enumeration timed out"))
        );
    }

    #[test]
    fn authorized_keys_failure_is_noted() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = write_passwd(&dir, &root_passwd());
        let runner = FakeRunner::new(&[]).respond(KEYS, exit(1, "permission denied"));
        let report = run_with(&runner, &test_config(), &passwd, &dir.path().join("none"));
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("authorized_keys enumeration failed"))
        );
    }

    #[test]
    fn missing_systemctl_is_noted() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = write_passwd(&dir, &root_passwd());
        let report = run_with(
            &FakeRunner::new(&[]),
            &test_config(),
            &passwd,
            &dir.path().join("none"),
        );
        assert!(report.notes.iter().any(|note| note.contains("systemctl")));
    }

    #[test]
    fn systemctl_dry_run_is_noted() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = write_passwd(&dir, &root_passwd());
        let runner = FakeRunner::new(&["systemctl"]).respond(SYSTEMCTL, dry());
        let report = run_with(&runner, &test_config(), &passwd, &dir.path().join("none"));
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("systemctl was not executed"))
        );
    }

    #[test]
    fn systemctl_timeout_is_medium_severity() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = write_passwd(&dir, &root_passwd());
        let runner = FakeRunner::new(&["systemctl"]).respond(SYSTEMCTL, timed_out());
        let report = run_with(&runner, &test_config(), &passwd, &dir.path().join("none"));
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("systemd unit enumeration timed out"))
        );
    }

    #[test]
    fn suspicious_units_are_medium_severity() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = write_passwd(&dir, &root_passwd());
        let runner = FakeRunner::new(&["systemctl"]).respond(
            SYSTEMCTL,
            ok("ssh.service enabled\nlocal-backdoor.service enabled\n"),
        );
        let report = run_with(&runner, &test_config(), &passwd, &dir.path().join("none"));
        assert_eq!(report.highest_severity(), Severity::Medium);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("local/custom/run/tmp"))
        );
    }

    #[test]
    fn clean_units_pass() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = write_passwd(&dir, &root_passwd());
        let runner =
            FakeRunner::new(&["systemctl"]).respond(SYSTEMCTL, ok("ssh.service enabled\n"));
        let report = run_with(&runner, &test_config(), &passwd, &dir.path().join("none"));
        assert_eq!(report.status, StageStatus::Passed);
        assert!(report.output.contains("No suspicious units."));
    }

    #[test]
    fn systemctl_failure_is_noted() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = write_passwd(&dir, &root_passwd());
        let runner =
            FakeRunner::new(&["systemctl"]).respond(SYSTEMCTL, exit(1, "dbus unavailable"));
        let report = run_with(&runner, &test_config(), &passwd, &dir.path().join("none"));
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("systemctl failed"))
        );
    }
}
