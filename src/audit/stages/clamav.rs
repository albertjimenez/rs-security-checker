//! Stage 3: ClamAV Scan.

use crate::audit::{StageContext, first_lines};
use crate::exec::Cmd;
use crate::fsutil::absolute_existing;
use crate::report::{Severity, StageId, StageReport, StageStatus};

pub fn run(ctx: &StageContext<'_>) -> StageReport {
    let mut report = StageReport::new(StageId::Clamav);

    if !ctx.tool_exists("clamscan") {
        report.push_block("", "Skipped: clamscan command not found.");
        report.note("`clamscan` was not found; ClamAV scan skipped");
        report.finish(Some(StageStatus::Skipped));
        return report;
    }

    if ctx.tool_exists("freshclam") {
        let freshclam = ctx.run(Cmd::new("freshclam").arg("--quiet").sudo(true));
        if freshclam.dry_run {
            report.note("dry-run: freshclam was not executed");
        } else if freshclam.success() {
            ctx.ui.debug("ClamAV signatures updated");
        } else if freshclam.timed_out {
            report.note("freshclam timed out; scanning with the existing signature database");
        } else {
            let detail = first_lines(&freshclam.combined(), 2);
            report.note(format!(
                "freshclam failed ({}); scanning with the existing signature database{}",
                freshclam.exit_description(),
                if detail.is_empty() {
                    String::new()
                } else {
                    format!(": {detail}")
                }
            ));
            report.finding(
                Severity::Low,
                "ClamAV signature update failed; scan coverage may be stale",
            );
        }
    } else {
        report.note("`freshclam` was not found; using the existing signature database");
    }

    let mut roots = Vec::new();
    for path in &ctx.cfg.clamav_paths {
        if path.exists() {
            roots.push(absolute_existing(path));
        } else {
            report.note(format!(
                "scan path `{}` does not exist; skipped",
                path.display()
            ));
        }
    }

    if roots.is_empty() {
        report.push_block("", "Skipped: none of the configured scan paths exist.");
        report.note("no ClamAV scan path exists on this host");
        report.finish(Some(StageStatus::Skipped));
        return report;
    }

    let mut scan = Cmd::new("clamscan")
        .args(["-r", "--infected", "--suppress-ok-results"])
        .sudo(true);
    for root in &roots {
        scan = scan.arg(root);
    }
    let scan = ctx.run(scan);

    if scan.dry_run {
        report.push_block(&scan.stdout, "(no output)");
        report.note("dry-run: ClamAV scan was not executed");
        report.finish(Some(StageStatus::Passed));
        return report;
    }

    let combined = scan.combined();
    report.push_block(&combined, "(no output)");

    let mut infected = 0usize;
    for line in combined.lines() {
        if line.contains("FOUND") {
            infected += 1;
            report.finding(Severity::Critical, line.trim().to_owned());
        }
    }

    if scan.timed_out {
        report.finding(
            Severity::High,
            format!(
                "ClamAV scan timed out before completing ({})",
                roots
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
        report.finish(Some(StageStatus::TimedOut));
        return report;
    }

    if infected > 0 {
        report.note(format!("{infected} infected file(s) detected"));
    } else if scan.success() {
        report.note("no infected files were detected");
    } else if scan.code == Some(1) {
        report.finding(
            Severity::Medium,
            "clamscan exited with status 1 but did not report a FOUND line",
        );
    } else {
        crate::audit::record_failure(&mut report, &scan, "ClamAV scan");
    }

    report.finish(None);
    report
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::audit::test_support::{FakeRunner, dry, exit, ok, run_stage, timed_out};
    use crate::config::test_config;

    fn scan_config(root: &Path) -> crate::config::Config {
        let mut cfg = test_config();
        cfg.clamav_paths = vec![root.to_path_buf()];
        cfg
    }

    fn scan_command(root: &Path) -> String {
        format!(
            "clamscan -r --infected --suppress-ok-results {}",
            root.display()
        )
    }

    #[test]
    fn missing_clamscan_skips_the_stage() {
        let report = run_stage(StageId::Clamav, &FakeRunner::new(&[]), &test_config());
        assert_eq!(report.status, StageStatus::Skipped);
        assert!(report.notes.iter().any(|note| note.contains("clamscan")));
    }

    #[test]
    fn no_existing_scan_paths_skips_the_stage() {
        let mut cfg = test_config();
        cfg.clamav_paths = vec!["/definitely/not/a/real/path".into()];
        let report = run_stage(StageId::Clamav, &FakeRunner::new(&["clamscan"]), &cfg);
        assert_eq!(report.status, StageStatus::Skipped);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("does not exist"))
        );
    }

    #[test]
    fn missing_freshclam_is_noted() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let runner = FakeRunner::new(&["clamscan"]);
        let report = run_stage(StageId::Clamav, &runner, &scan_config(&root));
        assert!(report.notes.iter().any(|note| note.contains("freshclam")));
    }

    #[test]
    fn freshclam_dry_run_is_noted() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let runner =
            FakeRunner::new(&["clamscan", "freshclam"]).respond("freshclam --quiet", dry());
        let report = run_stage(StageId::Clamav, &runner, &scan_config(&root));
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("freshclam was not executed"))
        );
    }

    #[test]
    fn freshclam_timeout_is_noted() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let runner =
            FakeRunner::new(&["clamscan", "freshclam"]).respond("freshclam --quiet", timed_out());
        let report = run_stage(StageId::Clamav, &runner, &scan_config(&root));
        assert!(report.notes.iter().any(|note| note.contains("timed out")));
    }

    #[test]
    fn freshclam_failure_is_a_low_finding() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let runner = FakeRunner::new(&["clamscan", "freshclam"])
            .respond("freshclam --quiet", exit(1, "update failed"));
        let report = run_stage(StageId::Clamav, &runner, &scan_config(&root));
        assert_eq!(report.highest_severity(), Severity::Low);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("freshclam failed"))
        );
    }

    #[test]
    fn scan_dry_run_passes() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let runner = FakeRunner::new(&["clamscan"]).respond(&scan_command(&root), dry());
        let report = run_stage(StageId::Clamav, &runner, &scan_config(&root));
        assert_eq!(report.status, StageStatus::Passed);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("scan was not executed"))
        );
    }

    #[test]
    fn infected_files_are_critical() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let runner = FakeRunner::new(&["clamscan"]).respond(
            &scan_command(&root),
            ok("eicar: Win.Test.EICAR_HDB-1 FOUND\n"),
        );
        let report = run_stage(StageId::Clamav, &runner, &scan_config(&root));
        assert_eq!(report.highest_severity(), Severity::Critical);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("1 infected file"))
        );
    }

    #[test]
    fn scan_timeout_is_high_severity() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let runner = FakeRunner::new(&["clamscan"]).respond(&scan_command(&root), timed_out());
        let report = run_stage(StageId::Clamav, &runner, &scan_config(&root));
        assert_eq!(report.status, StageStatus::TimedOut);
        assert_eq!(report.highest_severity(), Severity::High);
    }

    #[test]
    fn clean_scan_passes() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let report = run_stage(
            StageId::Clamav,
            &FakeRunner::new(&["clamscan"]),
            &scan_config(&root),
        );
        assert_eq!(report.status, StageStatus::Passed);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("no infected files"))
        );
    }

    #[test]
    fn exit_one_without_found_is_a_medium_finding() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let runner = FakeRunner::new(&["clamscan"]).respond(&scan_command(&root), exit(1, ""));
        let report = run_stage(StageId::Clamav, &runner, &scan_config(&root));
        assert_eq!(report.highest_severity(), Severity::Medium);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("status 1"))
        );
    }

    #[test]
    fn other_scan_failures_are_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let runner = FakeRunner::new(&["clamscan"])
            .respond(&scan_command(&root), exit(2, "permission denied"));
        let report = run_stage(StageId::Clamav, &runner, &scan_config(&root));
        assert_eq!(report.status, StageStatus::Warnings);
        assert_eq!(report.highest_severity(), Severity::Medium);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("ClamAV scan failed"))
        );
    }
}
