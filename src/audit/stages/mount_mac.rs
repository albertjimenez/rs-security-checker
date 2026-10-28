//! Temporary-directory mount hardening and Mandatory Access Control audit.
//!
//! This replaces the shell `mount | grep` and `aa-status`/`getenforce` checks. Mount information
//! is parsed from `/proc/self/mounts`, which is the same data the `mount` command prints but
//! without spawning a process or depending on locale and column formatting.

use std::io;
use std::path::PathBuf;

use crate::audit::{StageContext, first_lines};
use crate::exec::Cmd;
use crate::fsutil::read_limited;
use crate::report::{Severity, StageId, StageReport, StageStatus};

const MOUNTS_FILE: &str = "/proc/self/mounts";
const TEMP_DIRS: [&str; 3] = ["/tmp", "/var/tmp", "/dev/shm"];
const REQUIRED_FLAGS: [&str; 3] = ["noexec", "nosuid", "nodev"];
const MAX_MOUNTS_BYTES: u64 = 1024 * 1024;

/// Mount table inspected by this stage. Tests replace it with a temporary file.
struct MountPaths {
    mounts: PathBuf,
}

impl Default for MountPaths {
    fn default() -> Self {
        Self {
            mounts: PathBuf::from(MOUNTS_FILE),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MountEntry {
    source: String,
    mount_point: String,
    filesystem: String,
    options: Vec<String>,
}

pub fn run(ctx: &StageContext<'_>) -> StageReport {
    run_with_paths(ctx, &MountPaths::default())
}

fn run_with_paths(ctx: &StageContext<'_>, paths: &MountPaths) -> StageReport {
    let mut report = StageReport::new(StageId::MountMac);
    let mut timed_out = false;

    report.push_header("=== TEMPORARY DIRECTORY MOUNTS ===");
    match read_limited(&paths.mounts, MAX_MOUNTS_BYTES) {
        Ok(text) => {
            let mounts = parse_mounts(&text);
            for directory in TEMP_DIRS {
                check_temporary_mount(&mounts, directory, &mut report);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            report.push_block("", "Skipped: mount table is not available.");
            report.finding(
                Severity::Low,
                "the mount table is unavailable; temporary-directory hardening was not audited",
            );
        }
        Err(error) => {
            report.push_block("", &format!("Could not read the mount table: {error}"));
            report.finding(
                Severity::Medium,
                format!("could not read the mount table: {error}"),
            );
        }
    }

    report.push_header("=== MANDATORY ACCESS CONTROL ===");
    if ctx.tool_exists("aa-status") {
        let status = ctx.run(Cmd::new("aa-status").arg("--profiled").sudo(true));
        if status.timed_out {
            timed_out = true;
            report.push_block(&status.combined(), "(no output)");
            report.finding(Severity::Medium, "AppArmor status check timed out");
        } else if status.success() {
            match parse_apparmor_profiles(&status.stdout) {
                Some(count) if count > 0 => {
                    report.push_block(
                        &format!("[+] AppArmor is active and profiling {count} binaries."),
                        "",
                    );
                    report.note(format!("AppArmor is profiling {count} binaries"));
                }
                Some(_) => {
                    report.push_block(
                        "[-] [MEDIUM] AppArmor is installed but not profiling any binaries.",
                        "",
                    );
                    report.finding(
                        Severity::Medium,
                        "AppArmor is installed but not profiling any binaries",
                    );
                }
                None => {
                    report.push_block("", "AppArmor status could not be parsed.");
                    report.note(format!(
                        "`aa-status --profiled` returned unexpected output: {}",
                        first_lines(&status.stdout, 1)
                    ));
                    report.finding(
                        Severity::Low,
                        "AppArmor profile count could not be determined",
                    );
                }
            }
        } else {
            report.push_block("", "AppArmor status is unavailable.");
            report.note(format!(
                "aa-status failed: {}",
                first_lines(&status.combined(), 1)
            ));
        }
    } else if ctx.tool_exists("getenforce") {
        let status = ctx.run(Cmd::new("getenforce"));
        if status.timed_out {
            timed_out = true;
            report.finding(Severity::Medium, "SELinux status check timed out");
        } else if status.success() {
            let state = status.stdout.trim();
            report.push_block(&format!("SELinux status: {state}"), "");
            if state == "Disabled" || state == "Permissive" {
                report.finding(
                    Severity::Medium,
                    format!("SELinux is not in Enforcing mode ({state})"),
                );
            }
        } else {
            report.push_block("", "SELinux status is unavailable.");
            report.note(format!(
                "getenforce failed: {}",
                first_lines(&status.combined(), 1)
            ));
        }
    } else {
        report.push_block("", "[-] [LOW] No AppArmor or SELinux tooling detected.");
        report.finding(Severity::Low, "no AppArmor or SELinux tooling was detected");
    }

    if timed_out {
        report.finish(Some(StageStatus::TimedOut));
    } else {
        report.finish(None);
    }
    report
}

fn check_temporary_mount(mounts: &[MountEntry], directory: &str, report: &mut StageReport) {
    let Some(entry) = mounts.iter().find(|entry| entry.mount_point == directory) else {
        report.push_block(
            &format!(
                "[-] [LOW] {directory} is not mounted as a separate partition (harder to restrict)."
            ),
            "",
        );
        report.finding(
            Severity::Low,
            format!("{directory} is not mounted as a separate partition"),
        );
        return;
    };

    let options = entry.options.join(",");
    report.push_block(
        &format!(
            "{directory} is mounted: {} on {directory} type {} ({options})",
            entry.source, entry.filesystem
        ),
        "",
    );
    for flag in REQUIRED_FLAGS {
        if entry.options.iter().any(|option| option == flag) {
            report.output.push_str(&format!("  [+] Has {flag}\n"));
        } else {
            report
                .output
                .push_str(&format!("  [-] [MEDIUM] Missing {flag}\n"));
            report.finding(
                Severity::Medium,
                format!("{directory} is mounted without {flag}"),
            );
        }
    }
}

fn parse_mounts(text: &str) -> Vec<MountEntry> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let source = fields.next()?;
            let mount_point = fields.next()?;
            let filesystem = fields.next()?;
            let options = fields.next()?;
            Some(MountEntry {
                source: unescape_mount_field(source),
                mount_point: unescape_mount_field(mount_point),
                filesystem: unescape_mount_field(filesystem),
                options: options.split(',').map(str::to_owned).collect(),
            })
        })
        .collect()
}

/// Decode the octal escapes used in `/proc/self/mounts` (space, tab, newline and backslash).
fn unescape_mount_field(value: &str) -> String {
    let mut decoded = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(character) = chars.next() {
        if character != '\\' {
            decoded.push(character);
            continue;
        }
        let digits = (0..3).filter_map(|_| chars.next()).collect::<String>();
        let octal = (digits.len() == 3
            && digits
                .chars()
                .all(|character| ('0'..='7').contains(&character)))
        .then(|| u8::from_str_radix(&digits, 8).ok())
        .flatten();
        match octal {
            Some(byte) => decoded.push(byte as char),
            None => {
                decoded.push('\\');
                decoded.push_str(&digits);
            }
        }
    }
    decoded
}

fn parse_apparmor_profiles(stdout: &str) -> Option<u64> {
    stdout
        .lines()
        .find_map(|line| line.split_whitespace().next()?.parse::<u64>().ok())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use tempfile::TempDir;

    use super::*;
    use crate::audit::test_support::{FakeRunner, exit, ok, stage_context, timed_out};
    use crate::config::test_config;

    const AA: &str = "aa-status --profiled";
    const SELINUX: &str = "getenforce";

    fn write_mounts(dir: &TempDir, contents: &str) -> PathBuf {
        let path = dir.path().join("mounts");
        std::fs::write(&path, contents).unwrap();
        path
    }

    fn run_with(runner: &FakeRunner, mounts: &Path) -> StageReport {
        let cfg = test_config();
        let ui = crate::test_support::ui();
        let ctx = stage_context(&cfg, runner, &ui);
        run_with_paths(
            &ctx,
            &MountPaths {
                mounts: mounts.to_path_buf(),
            },
        )
    }

    fn hardened_mounts() -> String {
        "/dev/sda1 / ext4 rw,relatime 0 0\n\
         tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime 0 0\n\
         tmpfs /var/tmp tmpfs rw,nosuid,nodev,noexec,relatime 0 0\n\
         tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec,relatime 0 0\n"
            .to_owned()
    }

    #[test]
    fn fully_hardened_temporary_mounts_and_apparmor_pass() {
        let dir = tempfile::tempdir().unwrap();
        let mounts = write_mounts(&dir, &hardened_mounts());
        let runner = FakeRunner::new(&["aa-status"]).respond(AA, ok("42\n"));
        let report = run_with(&runner, &mounts);
        assert_eq!(report.status, StageStatus::Passed);
        assert!(report.output.contains("profiling 42 binaries"));
    }

    #[test]
    fn missing_temporary_mount_is_low_severity() {
        let dir = tempfile::tempdir().unwrap();
        let mounts = write_mounts(&dir, "/dev/sda1 / ext4 rw 0 0\n");
        let runner = FakeRunner::new(&["aa-status"]).respond(AA, ok("1\n"));
        let report = run_with(&runner, &mounts);
        assert_eq!(report.highest_severity(), Severity::Low);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("not mounted as a separate partition"))
        );
    }

    #[test]
    fn missing_mount_flag_is_medium_severity() {
        let dir = tempfile::tempdir().unwrap();
        let mounts = write_mounts(
            &dir,
            "/dev/sda1 / ext4 rw 0 0\n\
             tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n\
             tmpfs /var/tmp tmpfs rw,nosuid,nodev,noexec 0 0\n\
             tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec 0 0\n",
        );
        let runner = FakeRunner::new(&["aa-status"]).respond(AA, ok("1\n"));
        let report = run_with(&runner, &mounts);
        assert_eq!(report.highest_severity(), Severity::Medium);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("/tmp is mounted without noexec"))
        );
    }

    #[test]
    fn apparmor_without_profiles_is_medium_severity() {
        let dir = tempfile::tempdir().unwrap();
        let mounts = write_mounts(&dir, &hardened_mounts());
        let runner = FakeRunner::new(&["aa-status"]).respond(AA, ok("0\n"));
        let report = run_with(&runner, &mounts);
        assert_eq!(report.highest_severity(), Severity::Medium);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("not profiling any binaries"))
        );
    }

    #[test]
    fn permissive_selinux_is_medium_severity() {
        let dir = tempfile::tempdir().unwrap();
        let mounts = write_mounts(&dir, &hardened_mounts());
        let runner = FakeRunner::new(&["getenforce"]).respond(SELINUX, ok("Permissive\n"));
        let report = run_with(&runner, &mounts);
        assert_eq!(report.highest_severity(), Severity::Medium);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("SELinux is not in Enforcing mode"))
        );
    }

    #[test]
    fn missing_mac_tooling_is_low_severity() {
        let dir = tempfile::tempdir().unwrap();
        let mounts = write_mounts(&dir, &hardened_mounts());
        let report = run_with(&FakeRunner::new(&[]), &mounts);
        assert_eq!(report.highest_severity(), Severity::Low);
        assert!(
            report
                .output
                .contains("No AppArmor or SELinux tooling detected.")
        );
    }

    #[test]
    fn missing_mount_table_is_low_severity() {
        let dir = tempfile::tempdir().unwrap();
        let report = run_with(
            &FakeRunner::new(&["aa-status"]).respond(AA, ok("1\n")),
            &dir.path().join("missing-mounts"),
        );
        assert_eq!(report.highest_severity(), Severity::Low);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("mount table is unavailable"))
        );
    }

    #[test]
    fn apparmor_timeout_is_medium_severity() {
        let dir = tempfile::tempdir().unwrap();
        let mounts = write_mounts(&dir, &hardened_mounts());
        let runner = FakeRunner::new(&["aa-status"]).respond(AA, timed_out());
        let report = run_with(&runner, &mounts);
        assert_eq!(report.status, StageStatus::TimedOut);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("AppArmor status check timed out"))
        );
    }

    #[test]
    fn apparmor_failure_is_noted() {
        let dir = tempfile::tempdir().unwrap();
        let mounts = write_mounts(&dir, &hardened_mounts());
        let runner = FakeRunner::new(&["aa-status"]).respond(AA, exit(1, "not available"));
        let report = run_with(&runner, &mounts);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("aa-status failed"))
        );
    }

    #[test]
    fn unparsable_apparmor_output_is_low_severity() {
        let dir = tempfile::tempdir().unwrap();
        let mounts = write_mounts(&dir, &hardened_mounts());
        let runner = FakeRunner::new(&["aa-status"]).respond(AA, ok("unknown\n"));
        let report = run_with(&runner, &mounts);
        assert_eq!(report.highest_severity(), Severity::Low);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("profile count could not be determined"))
        );
    }

    #[test]
    fn parses_mounts_and_octal_escapes() {
        let mounts = parse_mounts("/dev/sda1 /tmp\\040dir ext4 rw,noexec 0 0\n");
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].mount_point, "/tmp dir");
        assert_eq!(mounts[0].options, vec!["rw", "noexec"]);
    }
}
