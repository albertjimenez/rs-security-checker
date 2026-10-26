//! Stage 4: Debsums Integrity.

use crate::audit::{StageContext, first_lines};
use crate::exec::Cmd;
use crate::report::{Severity, StageId, StageReport, StageStatus};

pub fn run(ctx: &StageContext<'_>) -> StageReport {
    let mut report = StageReport::new(StageId::Debsums);

    if !ctx.tool_exists("debsums") {
        report.push_block("", "Skipped: debsums command not found.");
        report.note("`debsums` was not found; integrity check skipped");
        report.finish(Some(StageStatus::Skipped));
        return report;
    }

    let output = ctx.run(Cmd::new("debsums").args(["-cs"]).sudo(true));
    if output.dry_run {
        report.push_block(&output.stdout, "(no output)");
        report.note("dry-run: debsums was not executed");
        report.finish(Some(StageStatus::Passed));
        return report;
    }
    let combined = output.combined();
    report.push_block(&combined, "(no output)");

    if output.timed_out {
        report.finding(Severity::High, "debsums integrity check timed out");
        report.finish(Some(StageStatus::TimedOut));
        return report;
    }

    if output.success() {
        if combined.trim().is_empty() {
            report.note("no changed package files were detected");
        } else {
            report.finding(
                Severity::Medium,
                format!(
                    "debsums reported changed package files: {}",
                    first_lines(&combined, 3)
                ),
            );
        }
    } else if combined.trim().is_empty() {
        // debsums commonly exits 2 when some packages have no md5sums database.
        report.finding(
            Severity::Low,
            format!(
                "debsums exited with {} and produced no output; some packages may lack md5sums",
                output.exit_description()
            ),
        );
    } else {
        report.finding(
            Severity::Medium,
            format!(
                "debsums reported integrity problems ({}): {}",
                output.exit_description(),
                first_lines(&combined, 3)
            ),
        );
    }

    report.finish(None);
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::test_support::{FakeRunner, dry, exit, ok, run_stage, timed_out};
    use crate::config::test_config;

    fn run(runner: &FakeRunner) -> StageReport {
        run_stage(StageId::Debsums, runner, &test_config())
    }

    #[test]
    fn missing_debsums_skips_the_stage() {
        let report = run(&FakeRunner::new(&[]));
        assert_eq!(report.status, StageStatus::Skipped);
        assert!(report.notes.iter().any(|note| note.contains("debsums")));
    }

    #[test]
    fn dry_run_passes() {
        let report = run(&FakeRunner::new(&["debsums"]).respond("debsums -cs", dry()));
        assert_eq!(report.status, StageStatus::Passed);
        assert!(report.notes.iter().any(|note| note.contains("dry-run")));
    }

    #[test]
    fn timeout_is_high_severity() {
        let report = run(&FakeRunner::new(&["debsums"]).respond("debsums -cs", timed_out()));
        assert_eq!(report.status, StageStatus::TimedOut);
        assert_eq!(report.highest_severity(), Severity::High);
    }

    #[test]
    fn clean_success_passes() {
        let report = run(&FakeRunner::new(&["debsums"]).respond("debsums -cs", ok("")));
        assert_eq!(report.status, StageStatus::Passed);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("no changed package files"))
        );
    }

    #[test]
    fn changed_files_on_success_are_a_medium_finding() {
        let report =
            run(&FakeRunner::new(&["debsums"])
                .respond("debsums -cs", ok("md5sum mismatch /bin/ls\n")));
        assert_eq!(report.status, StageStatus::Warnings);
        assert_eq!(report.highest_severity(), Severity::Medium);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("changed package files"))
        );
    }

    #[test]
    fn empty_failure_is_a_low_finding() {
        let report = run(&FakeRunner::new(&["debsums"]).respond("debsums -cs", exit(2, "")));
        assert_eq!(report.highest_severity(), Severity::Low);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("md5sums"))
        );
    }

    #[test]
    fn failure_with_output_is_a_medium_finding() {
        let report =
            run(&FakeRunner::new(&["debsums"])
                .respond("debsums -cs", exit(2, "missing /usr/bin/foo")));
        assert_eq!(report.status, StageStatus::Warnings);
        assert_eq!(report.highest_severity(), Severity::Medium);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("integrity problems"))
        );
    }
}
