//! Stage 7: Network Sockets & Pending Patches.

use std::sync::LazyLock;

use regex::Regex;

use crate::audit::{StageContext, first_lines};
use crate::exec::Cmd;
use crate::report::{Severity, StageId, StageReport, StageStatus};

static SECURITY_UPDATE: LazyLock<Regex> = LazyLock::new(|| {
    // Debian/Ubuntu security pockets, Ubuntu ESM/ESM-Apps pockets, and Ubuntu Pro notices.
    Regex::new(r"(?i)security|esm(?:apps)?[:/]|ubuntu pro").expect("valid security-update regex")
});

pub fn run(ctx: &StageContext<'_>) -> StageReport {
    let mut report = StageReport::new(StageId::Network);
    let ss_available = ctx.tool_exists("ss");
    let apt_available = ctx.tool_exists("apt-get");
    let mut timed_out = false;

    if !ss_available && !apt_available {
        report.push_header("=== PUBLIC LISTENING PORTS (0.0.0.0 or [::]) ===");
        report.push_block("", "Skipped: ss command not found.");
        report.push_header("=== ESTABLISHED OUTBOUND CONNECTIONS ===");
        report.push_block("", "Skipped: ss command not found.");
        report.push_header("=== PENDING DEBIAN SECURITY PATCHES ===");
        report.push_block("", "Skipped: apt-get command not found.");
        report.note("neither `ss` nor `apt-get` was found; network audit skipped");
        report.finish(Some(StageStatus::Skipped));
        return report;
    }

    report.push_header("=== PUBLIC LISTENING PORTS (0.0.0.0 or [::]) ===");
    if ss_available {
        let sockets = ctx.run(Cmd::new("ss").args(["-tulpn"]).sudo(true));
        if sockets.timed_out {
            timed_out = true;
            report.push_block(&sockets.combined(), "(no output)");
            report.finding(Severity::Medium, "socket enumeration timed out");
        } else {
            let listening = filter_listening(&sockets.stdout);
            if listening.is_empty() {
                report.push_block("", "No wildcard listening ports.");
            } else {
                report.push_block(&listening, "No wildcard listening ports.");
                let count = listening.lines().count();
                report.finding(
                    Severity::Low,
                    format!("{count} wildcard listening socket(s) found (0.0.0.0/::: )"),
                );
            }
            if !sockets.success() {
                report.note(format!(
                    "ss -tulpn failed: {}",
                    first_lines(&sockets.combined(), 1)
                ));
            }
        }
    } else {
        report.push_block("", "Skipped: ss command not found.");
        report.finding(
            Severity::Low,
            "ss is unavailable; listening sockets could not be audited",
        );
    }

    report.push_header("=== ESTABLISHED OUTBOUND CONNECTIONS ===");
    if ss_available {
        let established = ctx.run(
            Cmd::new("ss")
                .args(["-tpn", "state", "established"])
                .sudo(true),
        );
        if established.timed_out {
            timed_out = true;
            report.push_block(&established.combined(), "(no output)");
            report.finding(
                Severity::Medium,
                "established-connection enumeration timed out",
            );
        } else {
            report.push_block(&established.stdout, "(none)");
            if !established.success() {
                report.note(format!(
                    "ss established query failed: {}",
                    first_lines(&established.combined(), 1)
                ));
            }
        }
    } else {
        report.push_block("", "Skipped: ss command not found.");
    }

    report.push_header("=== PENDING DEBIAN SECURITY PATCHES ===");
    if apt_available {
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
        let update_output = update.combined();
        if !update_output.trim().is_empty() {
            report.push_block(&update_output, "");
        }

        let upgrades = ctx.run(Cmd::new("apt-get").args(["--just-print", "upgrade"]));
        if upgrades.dry_run {
            report.push_block(&upgrades.stdout, "(no output)");
            report.note("dry-run: pending patch check was not executed");
        } else if upgrades.timed_out {
            timed_out = true;
            report.finding(Severity::Medium, "apt-get --just-print upgrade timed out");
        } else {
            let security = filter_security_updates(&upgrades.stdout);
            if security.is_empty() {
                report.push_block("", "All security patches up to date.");
            } else {
                report.push_block(&security, "All security patches up to date.");
                let count = security.lines().count();
                report.finding(
                    Severity::High,
                    format!(
                        "{count} pending Debian security update(s): {}",
                        first_lines(&security, 3)
                    ),
                );
            }
            if !upgrades.success() {
                report.note(format!(
                    "apt-get --just-print upgrade failed: {}",
                    first_lines(&upgrades.combined(), 1)
                ));
            }
        }
    } else {
        report.push_block("", "Skipped: apt-get command not found.");
        report.finding(
            Severity::Low,
            "apt-get is unavailable; pending security patches could not be audited",
        );
    }

    if timed_out {
        report.finish(Some(StageStatus::TimedOut));
    } else {
        report.finish(None);
    }
    report
}

fn filter_listening(stdout: &str) -> String {
    stdout
        .lines()
        .filter(|line| {
            // `ss -tulpn` columns: Netid State Recv-Q Send-Q Local:Port Peer:Port Process.
            // Inspect only the local address so a wildcard peer does not create a false positive.
            let local = line.split_whitespace().nth(4).unwrap_or(line);
            local.contains("0.0.0.0") || local.contains("[::]") || local.contains(":::")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn filter_security_updates(stdout: &str) -> String {
    stdout
        .lines()
        .filter(|line| SECURITY_UPDATE.is_match(line))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::test_support::{FakeRunner, dry, exit, ok, run_stage, timed_out};
    use crate::config::test_config;

    const SOCKETS: &str = "ss -tulpn";
    const ESTABLISHED: &str = "ss -tpn state established";
    const UPDATE: &str = "apt-get update -qq";
    const UPGRADES: &str = "apt-get --just-print upgrade";

    fn run(runner: &FakeRunner) -> StageReport {
        run_stage(StageId::Network, runner, &test_config())
    }

    #[test]
    fn filters_wildcard_listeners() {
        let output = "\
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   LISTEN 0      128    0.0.0.0:22       0.0.0.0:*         users:((\"sshd\",pid=1))
tcp   LISTEN 0      128    127.0.0.1:5432   0.0.0.0:*
tcp   LISTEN 0      128    [::]:443         [::]:*
";
        let filtered = filter_listening(output);
        assert!(filtered.contains("0.0.0.0:22"));
        assert!(filtered.contains("[::]:443"));
        assert!(!filtered.contains("127.0.0.1:5432"));
    }

    #[test]
    fn filters_security_updates_case_insensitively() {
        let output = "\
Inst libfoo [1.0] (1.1 Debian:stable-security/updates [amd64])
Inst bar [2.0] (2.1 Debian:stable [amd64])
Inst baz [3.0] (3.1 Debian-Security [amd64])
";
        let filtered = filter_security_updates(output);
        assert_eq!(filtered.lines().count(), 2);
    }

    #[test]
    fn filters_ubuntu_esm_and_esm_apps_updates() {
        let output = "\
Inst libssl3 [3.0.0] (3.0.1 UbuntuESM:22.04/jammy-infra-updates [amd64])
Inst apparmor [3.0.4] (3.0.5 UbuntuESMApps:22.04/jammy-apps-updates [amd64])
Inst curl [7.81.0] (7.81.1 Ubuntu:22.04/jammy-updates [amd64])
";
        let filtered = filter_security_updates(output);
        assert_eq!(filtered.lines().count(), 2);
        assert!(filtered.contains("UbuntuESM:"));
        assert!(filtered.contains("UbuntuESMApps:"));
    }

    #[test]
    fn no_tools_skips_the_stage() {
        let report = run(&FakeRunner::new(&[]));
        assert_eq!(report.status, StageStatus::Skipped);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("neither `ss` nor `apt-get`"))
        );
    }

    #[test]
    fn missing_ss_is_low_severity() {
        let report = run(&FakeRunner::new(&["apt-get"]));
        assert_eq!(report.highest_severity(), Severity::Low);
        assert!(report.output.contains("Skipped: ss command not found."));
    }

    #[test]
    fn missing_apt_get_is_low_severity() {
        let report = run(&FakeRunner::new(&["ss"]));
        assert_eq!(report.highest_severity(), Severity::Low);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("apt-get is unavailable"))
        );
    }

    #[test]
    fn socket_timeout_is_medium_severity() {
        let runner = FakeRunner::new(&["ss", "apt-get"]).respond(SOCKETS, timed_out());
        let report = run(&runner);
        assert_eq!(report.status, StageStatus::TimedOut);
        assert_eq!(report.highest_severity(), Severity::Medium);
    }

    #[test]
    fn wildcard_listener_is_low_severity() {
        let runner = FakeRunner::new(&["ss", "apt-get"]).respond(
            SOCKETS,
            ok("tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1))\n"),
        );
        let report = run(&runner);
        assert_eq!(report.highest_severity(), Severity::Low);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("wildcard listening socket"))
        );
    }

    #[test]
    fn no_wildcard_listener_passes() {
        let runner = FakeRunner::new(&["ss", "apt-get"]).respond(
            SOCKETS,
            ok("tcp LISTEN 0 128 127.0.0.1:22 0.0.0.0:* users:((\"sshd\",pid=1))\n"),
        );
        let report = run(&runner);
        assert_eq!(report.status, StageStatus::Passed);
        assert!(report.output.contains("No wildcard listening ports."));
    }

    #[test]
    fn socket_failure_is_noted() {
        let runner =
            FakeRunner::new(&["ss", "apt-get"]).respond(SOCKETS, exit(1, "permission denied"));
        let report = run(&runner);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("ss -tulpn failed"))
        );
    }

    #[test]
    fn established_timeout_is_medium_severity() {
        let runner = FakeRunner::new(&["ss", "apt-get"]).respond(ESTABLISHED, timed_out());
        let report = run(&runner);
        assert_eq!(report.status, StageStatus::TimedOut);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("established-connection"))
        );
    }

    #[test]
    fn established_failure_is_noted() {
        let runner = FakeRunner::new(&["ss", "apt-get"])
            .respond(ESTABLISHED, exit(1, "netlink unavailable"));
        let report = run(&runner);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("ss established query failed"))
        );
    }

    #[test]
    fn apt_update_timeout_is_medium_severity() {
        let runner = FakeRunner::new(&["ss", "apt-get"]).respond(UPDATE, timed_out());
        let report = run(&runner);
        assert_eq!(report.status, StageStatus::TimedOut);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("apt-get update timed out"))
        );
    }

    #[test]
    fn apt_update_failure_is_noted_and_output_is_kept() {
        let runner = FakeRunner::new(&["ss", "apt-get"])
            .respond(UPDATE, exit(1, "Could not resolve archive.debian.org"));
        let report = run(&runner);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("apt-get update failed"))
        );
        assert!(report.output.contains("Could not resolve"));
    }

    #[test]
    fn upgrades_dry_run_is_noted() {
        let runner = FakeRunner::new(&["ss", "apt-get"]).respond(UPGRADES, dry());
        let report = run(&runner);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("pending patch check was not executed"))
        );
    }

    #[test]
    fn security_updates_are_high_severity() {
        let runner = FakeRunner::new(&["ss", "apt-get"]).respond(
            UPGRADES,
            ok("Inst openssl [3.0.1] (3.0.2 Debian:stable-security [amd64])\n"),
        );
        let report = run(&runner);
        assert_eq!(report.highest_severity(), Severity::High);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("pending Debian security update"))
        );
    }

    #[test]
    fn no_security_updates_passes() {
        let runner = FakeRunner::new(&["ss", "apt-get"])
            .respond(UPGRADES, ok("Inst foo [1.0] (1.1 Debian:stable [amd64])\n"));
        let report = run(&runner);
        assert_eq!(report.status, StageStatus::Passed);
        assert!(report.output.contains("All security patches up to date."));
    }

    #[test]
    fn upgrades_timeout_is_medium_severity() {
        let runner = FakeRunner::new(&["ss", "apt-get"]).respond(UPGRADES, timed_out());
        let report = run(&runner);
        assert_eq!(report.status, StageStatus::TimedOut);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("--just-print upgrade timed out"))
        );
    }

    #[test]
    fn upgrades_failure_is_noted() {
        let runner = FakeRunner::new(&["ss", "apt-get"]).respond(UPGRADES, exit(1, "dpkg locked"));
        let report = run(&runner);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("apt-get --just-print upgrade failed"))
        );
    }
}
