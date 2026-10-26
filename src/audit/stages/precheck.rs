//! Stage 1: Precheck & Dependencies.

use crate::audit::{StageContext, first_lines};
use crate::exec::Cmd;
use crate::report::{Severity, StageId, StageReport, StageStatus};

pub const REQUIRED_PACKAGES: [&str; 6] = [
    "clamav",
    "clamav-freshclam",
    "debsums",
    "rkhunter",
    "chkrootkit",
    "iproute2",
];

pub fn run(ctx: &StageContext<'_>) -> StageReport {
    let mut report = StageReport::new(StageId::Precheck);
    report.push_header("Checking required audit tools...");

    if !ctx.tool_exists("dpkg") {
        report.note("`dpkg` was not found; this audit targets Debian-based hosts");
        report.finding(
            Severity::High,
            "dpkg is unavailable; dependency precheck cannot run",
        );
        report.finish(Some(StageStatus::Failed));
        return report;
    }

    let mut missing = Vec::new();
    for package in REQUIRED_PACKAGES {
        let output = ctx.run(Cmd::new("dpkg").args(["-s", package]));
        if output.success() {
            report
                .output
                .push_str(&format!("[+] Installed: {package}\n"));
            ctx.ui.debug(format!("installed: {package}"));
        } else if output.error.is_some() {
            report.output.push_str(&format!(
                "[-] Unknown: {package} ({})\n",
                output.exit_description()
            ));
            missing.push(package);
        } else {
            report
                .output
                .push_str(&format!("[-] Missing package: {package}\n"));
            missing.push(package);
        }
    }

    if missing.is_empty() {
        report
            .output
            .push_str("All required audit utilities are already present.\n");
        report.note("all required packages are installed");
        report.finish(Some(StageStatus::Passed));
        return report;
    }

    report.output.push_str(&format!(
        "Missing dependencies:{}\n",
        missing
            .iter()
            .map(|package| format!(" {package}"))
            .collect::<String>()
    ));

    if !ctx.cfg.install_deps {
        report.finding(
            Severity::Medium,
            format!(
                "{} required audit package(s) are missing: {}",
                missing.len(),
                missing.join(", ")
            ),
        );
        report.note(
            "dependency installation is disabled; rerun with --install-deps to allow apt-get",
        );
        report.finish(None);
        return report;
    }

    report.push_header("Installing missing dependencies");
    let update = ctx.run(Cmd::new("apt-get").args(["update", "-qq"]).sudo(true));
    if !update.success() {
        report.finding(
            Severity::High,
            format!(
                "apt-get update failed: {}",
                first_lines(&update.combined(), 2)
            ),
        );
        report.finish(Some(StageStatus::Failed));
        return report;
    }

    let mut install = Cmd::new("apt-get")
        .args(["install", "-y", "-qq"])
        .args([
            "-o",
            "Dpkg::Options::=--force-confdef",
            "-o",
            "Dpkg::Options::=--force-confold",
        ])
        .env("DEBIAN_FRONTEND", "noninteractive")
        .sudo(true);
    for package in &missing {
        install = install.arg(package);
    }

    let install = ctx.run(install);
    report.push_block(&install.combined(), "(no output)");
    if install.success() {
        report
            .output
            .push_str("Dependencies successfully installed.\n");
        report.note(format!(
            "installed missing packages, so no missing-dependency finding was raised: {}",
            missing.join(", ")
        ));
        report.finish(None);
    } else {
        report.finding(
            Severity::High,
            format!(
                "apt-get install failed: {}",
                first_lines(&install.combined(), 2)
            ),
        );
        report.finish(Some(StageStatus::Failed));
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::test_support::{FakeRunner, command_error, exit, ok, run_stage};
    use crate::config::test_config;

    fn run(runner: &FakeRunner, cfg: &crate::config::Config) -> StageReport {
        run_stage(StageId::Precheck, runner, cfg)
    }

    #[test]
    fn dpkg_unavailable_fails_the_stage() {
        let report = run(&FakeRunner::new(&[]), &test_config());
        assert_eq!(report.status, StageStatus::Failed);
        assert_eq!(report.highest_severity(), Severity::High);
    }

    #[test]
    fn all_packages_installed_passes() {
        let runner = FakeRunner::new(&["dpkg"]);
        let report = run(&runner, &test_config());
        assert_eq!(report.status, StageStatus::Passed);
        assert!(report.output.contains("All required audit utilities"));
        assert!(runner.calls().iter().any(|call| call == "dpkg -s clamav"));
    }

    #[test]
    fn missing_package_is_a_medium_finding_when_installation_is_disabled() {
        let runner = FakeRunner::new(&["dpkg"]).respond("dpkg -s clamav", exit(1, ""));
        let report = run(&runner, &test_config());
        assert_eq!(report.status, StageStatus::Warnings);
        assert_eq!(report.highest_severity(), Severity::Medium);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("--install-deps"))
        );
        assert!(report.output.contains("Missing package: clamav"));
    }

    #[test]
    fn dpkg_errors_are_reported_as_unknown_packages() {
        let runner = FakeRunner::new(&["dpkg"])
            .respond("dpkg -s debsums", command_error("database is locked"));
        let report = run(&runner, &test_config());
        assert_eq!(report.status, StageStatus::Warnings);
        assert_eq!(report.highest_severity(), Severity::Medium);
        assert!(report.output.contains("Unknown: debsums"));
    }

    #[test]
    fn successful_installation_clears_the_missing_package_finding() {
        let mut cfg = test_config();
        cfg.install_deps = true;
        let runner = FakeRunner::new(&["dpkg"])
            .respond("dpkg -s clamav", exit(1, ""))
            .respond("apt-get update -qq", ok(""))
            .respond(
                "apt-get install -y -qq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold clamav",
                ok("installed"),
            );
        let report = run(&runner, &cfg);
        assert_eq!(report.status, StageStatus::Passed);
        assert!(report.findings.is_empty());
        assert!(
            report
                .output
                .contains("Dependencies successfully installed.")
        );
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("installed missing packages"))
        );
    }

    #[test]
    fn apt_update_failure_fails_the_stage() {
        let mut cfg = test_config();
        cfg.install_deps = true;
        let runner = FakeRunner::new(&["dpkg"])
            .respond("dpkg -s clamav", exit(1, ""))
            .respond("apt-get update -qq", exit(1, "network down"));
        let report = run(&runner, &cfg);
        assert_eq!(report.status, StageStatus::Failed);
        assert_eq!(report.highest_severity(), Severity::High);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("apt-get update failed"))
        );
    }

    #[test]
    fn apt_install_failure_fails_the_stage() {
        let mut cfg = test_config();
        cfg.install_deps = true;
        let runner = FakeRunner::new(&["dpkg"])
            .respond("dpkg -s clamav", exit(1, ""))
            .respond("apt-get update -qq", ok(""))
            .respond(
                "apt-get install -y -qq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold clamav",
                exit(100, "E: broken package"),
            );
        let report = run(&runner, &cfg);
        assert_eq!(report.status, StageStatus::Failed);
        assert_eq!(report.highest_severity(), Severity::High);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("apt-get install failed"))
        );
    }
}
