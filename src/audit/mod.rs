//! Audit orchestration and stage dispatch.

pub mod stages;

use std::path::Path;
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::exec::{Cmd, CommandOutput, CommandRunner};
use crate::report::{Severity, StageId, StageReport, StageStatus};
use crate::ui::Ui;

#[cfg(test)]
pub(crate) mod test_support;

pub struct StageContext<'a> {
    pub cfg: &'a Config,
    pub runner: &'a dyn CommandRunner,
    pub ui: &'a Ui,
    pub deadline: Instant,
}

impl StageContext<'_> {
    pub fn run(&self, cmd: Cmd) -> CommandOutput {
        self.runner.run(&cmd, self.deadline)
    }

    pub fn tool_exists(&self, program: &str) -> bool {
        self.runner.tool_exists(program)
    }

    pub fn remaining(&self) -> Option<Duration> {
        self.deadline.checked_duration_since(Instant::now())
    }

    pub fn expired(&self) -> bool {
        self.remaining().is_none()
    }
}

pub fn execute(stage: StageId, ctx: &StageContext<'_>) -> StageReport {
    let started = Instant::now();
    let mut report = if ctx.expired() {
        let mut report = StageReport::new(stage);
        report.note("global timeout reached before this stage started");
        report.finish(Some(StageStatus::TimedOut));
        report
    } else {
        // A stage is a large amount of parser code; contain a panic so one bad input cannot abort
        // the whole audit. The parallel path relies on this for the same guarantee.
        let dispatch = std::panic::AssertUnwindSafe(|| match stage {
            StageId::Precheck => stages::precheck::run(ctx),
            StageId::Docker => stages::docker::run(ctx),
            StageId::Clamav => stages::clamav::run(ctx),
            StageId::Debsums => stages::debsums::run(ctx),
            StageId::Rootkit => stages::rootkit::run(ctx),
            StageId::Persistence => stages::persistence::run(ctx),
            StageId::Network => stages::network::run(ctx),
            StageId::Web => stages::web::run(ctx),
            StageId::Auth => stages::auth::run(ctx),
            StageId::Hardening => stages::hardening::run(ctx),
            StageId::Aws => stages::aws::run(ctx),
            StageId::CaTrust => stages::ca_trust::run(ctx),
            StageId::ProcessForensics => stages::process_forensics::run(ctx),
            StageId::MountMac => stages::mount_mac::run(ctx),
            StageId::BroadSecrets => stages::broad_secrets::run(ctx),
        });
        match std::panic::catch_unwind(dispatch) {
            Ok(report) => report,
            Err(_) => panicked_report(stage),
        }
    };
    report.finalize(started.elapsed());
    report
}

/// Execute lightweight analysis stages concurrently, preserving the requested report order.
///
/// At most `jobs` stages run at once. A stage panic is converted into a failed report so one bad
/// analysis cannot take down the whole audit. Callers must only pass stages for which
/// [`StageId::is_parallel_safe`] is true.
pub fn execute_parallel(
    stages: &[StageId],
    ctx: &StageContext<'_>,
    jobs: usize,
) -> Vec<StageReport> {
    debug_assert!(stages.iter().all(|stage| stage.is_parallel_safe()));
    execute_parallel_with(stages, jobs, |stage| execute(stage, ctx))
}

fn execute_parallel_with<F>(stages: &[StageId], jobs: usize, run: F) -> Vec<StageReport>
where
    F: Fn(StageId) -> StageReport + Sync,
{
    let jobs = jobs.max(1);
    if jobs == 1 {
        return stages
            .iter()
            .copied()
            .map(|stage| {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(stage)))
                    .unwrap_or_else(|_| panicked_report(stage))
            })
            .collect();
    }

    let mut reports = Vec::with_capacity(stages.len());
    for chunk in stages.chunks(jobs) {
        let chunk_reports = std::thread::scope(|scope| {
            let run = &run;
            let handles = chunk
                .iter()
                .copied()
                .map(|stage| (stage, scope.spawn(move || run(stage))))
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|(stage, handle)| handle.join().unwrap_or_else(|_| panicked_report(stage)))
                .collect::<Vec<_>>()
        });
        reports.extend(chunk_reports);
    }
    reports
}

fn panicked_report(stage: StageId) -> StageReport {
    let mut report = StageReport::new(stage);
    report.finding(
        Severity::High,
        "stage panicked; see the audit log and report this as a bug",
    );
    report.finish(Some(StageStatus::Failed));
    report
}

/// Record a failed command as a finding unless it is explicitly allowed to fail.
pub fn record_failure(report: &mut StageReport, output: &CommandOutput, context: &str) {
    if output.timed_out {
        report.finding(
            Severity::High,
            format!(
                "{context}: command timed out ({})",
                output.display_command()
            ),
        );
        report.finish(Some(StageStatus::TimedOut));
        return;
    }
    if let Some(error) = &output.error {
        report.finding(Severity::Medium, format!("{context}: {error}"));
        return;
    }
    if !output.success() {
        let detail = first_lines(&output.combined(), 3);
        let suffix = if detail.is_empty() {
            String::new()
        } else {
            format!(": {detail}")
        };
        report.finding(
            Severity::Medium,
            format!(
                "{context} failed ({}): `{}`{suffix}",
                output.exit_description(),
                output.display_command()
            ),
        );
    }
}

pub fn first_lines(text: &str, count: usize) -> String {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(count)
        .collect::<Vec<_>>()
        .join(" | ")
}

/// Read the bounded tail of every log file, feeding each successfully read text to `ingest`.
///
/// Returns one human-readable source line per file and the number of unreadable files. Stage
/// reports use the source list to show which files contributed and how many lines each had.
pub fn read_log_tails(
    files: &[std::path::PathBuf],
    tail_bytes: usize,
    mut ingest: impl FnMut(&str),
) -> (Vec<String>, usize) {
    let mut sources = Vec::with_capacity(files.len());
    let mut unreadable = 0usize;
    for file in files {
        match crate::logs::read_tail(file, tail_bytes) {
            Ok(text) => {
                let lines = text.lines().count();
                ingest(&text);
                sources.push(format!("{} ({lines} line(s))", file.display()));
            }
            Err(error) => {
                unreadable += 1;
                sources.push(format!("{} (unreadable: {error})", file.display()));
            }
        }
    }
    (sources, unreadable)
}

/// Filter log paths by compression and a lowercase filename predicate.
pub fn is_uncompressed_log(path: &Path, matches: impl FnOnce(&str) -> bool) -> bool {
    if crate::logs::is_compressed(path) {
        return false;
    }
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    matches(&name)
}

#[cfg(test)]
mod tests {
    use super::test_support::{
        FakeRunner, command_error, exit, expired_context, ok, stage_context, timed_out,
    };
    use super::*;
    use crate::config::test_config;
    use crate::test_support::ui;

    #[test]
    fn first_lines_trims_filters_and_limits() {
        let text = "\n  one  \n\n two\nthree\nfour\n";
        assert_eq!(first_lines(text, 2), "one | two");
        assert_eq!(first_lines("", 3), "");
    }

    #[test]
    fn record_failure_marks_timeouts_as_timed_out() {
        let mut report = StageReport::new(StageId::Debsums);
        record_failure(&mut report, &timed_out(), "demo");
        assert_eq!(report.status, StageStatus::TimedOut);
        assert_eq!(report.highest_severity(), Severity::High);
        assert!(report.findings[0].message.contains("timed out"));
    }

    #[test]
    fn record_failure_handles_spawn_errors() {
        let mut report = StageReport::new(StageId::Debsums);
        record_failure(&mut report, &command_error("spawn failed"), "demo");
        assert_eq!(report.highest_severity(), Severity::Medium);
        assert!(report.findings[0].message.contains("spawn failed"));
    }

    #[test]
    fn record_failure_includes_output_details() {
        let mut report = StageReport::new(StageId::Debsums);
        record_failure(
            &mut report,
            &exit(2, "first problem\nsecond problem"),
            "demo",
        );
        assert_eq!(report.highest_severity(), Severity::Medium);
        assert!(
            report.findings[0]
                .message
                .contains("first problem | second problem")
        );
    }

    #[test]
    fn record_failure_omits_empty_details() {
        let mut report = StageReport::new(StageId::Debsums);
        record_failure(&mut report, &exit(2, ""), "demo");
        assert!(report.findings[0].message.ends_with("`test`"));
    }

    #[test]
    fn record_failure_ignores_success() {
        let mut report = StageReport::new(StageId::Debsums);
        record_failure(&mut report, &ok("all good"), "demo");
        assert!(report.findings.is_empty());
        assert_eq!(report.status, StageStatus::Passed);
    }

    #[test]
    fn expired_deadline_skips_the_stage() {
        let cfg = test_config();
        let runner = FakeRunner::new(&[]);
        let ui = ui();
        let ctx = expired_context(&cfg, &runner, &ui);
        let report = execute(StageId::Docker, &ctx);
        assert_eq!(report.status, StageStatus::TimedOut);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("global timeout"))
        );
        assert!(ctx.expired());
        assert!(ctx.remaining().is_none());
    }

    #[test]
    fn every_stage_is_dispatched() {
        let cfg = test_config();
        let runner = FakeRunner::new(&[]);
        let ui = ui();
        let ctx = stage_context(&cfg, &runner, &ui);
        assert!(!ctx.expired());
        assert!(ctx.remaining().is_some());

        for stage in StageId::ALL {
            let report = execute(stage, &ctx);
            assert_eq!(report.id, stage);
            assert!(
                !report
                    .notes
                    .iter()
                    .any(|note| note.contains("global timeout"))
            );
        }
    }

    #[test]
    fn parallel_execution_preserves_order_and_contains_panics() {
        let stages = [StageId::Web, StageId::Auth, StageId::Aws];
        let reports = execute_parallel_with(&stages, 2, |stage| {
            if stage == StageId::Auth {
                panic!("simulated stage panic");
            }
            let mut report = StageReport::new(stage);
            report.finish(None);
            report
        });

        assert_eq!(
            reports.iter().map(|report| report.id).collect::<Vec<_>>(),
            stages
        );
        assert_eq!(reports[0].status, StageStatus::Passed);
        assert_eq!(reports[1].status, StageStatus::Failed);
        assert_eq!(reports[1].highest_severity(), Severity::High);
        assert!(reports[1].findings[0].message.contains("panicked"));
        assert_eq!(reports[2].status, StageStatus::Passed);
    }

    #[test]
    fn parallel_execution_with_one_job_stays_sequential() {
        let stages = [StageId::Web, StageId::Auth];
        let reports = execute_parallel_with(&stages, 1, |stage| {
            let mut report = StageReport::new(stage);
            report.finish(None);
            report
        });
        assert_eq!(
            reports.iter().map(|report| report.id).collect::<Vec<_>>(),
            stages
        );
    }

    #[test]
    fn sequential_execution_contains_panics() {
        let stages = [StageId::Web, StageId::Auth];
        let reports = execute_parallel_with(&stages, 1, |stage| {
            if stage == StageId::Auth {
                panic!("simulated stage panic");
            }
            let mut report = StageReport::new(stage);
            report.finish(None);
            report
        });

        assert_eq!(reports[0].status, StageStatus::Passed);
        assert_eq!(reports[1].status, StageStatus::Failed);
        assert!(reports[1].findings[0].message.contains("panicked"));
    }

    #[test]
    fn parallel_execution_uses_the_real_dispatch() {
        let cfg = test_config();
        let runner = FakeRunner::new(&[]);
        let ui = ui();
        let ctx = stage_context(&cfg, &runner, &ui);
        let stages = [StageId::Web, StageId::Auth];
        let reports = execute_parallel(&stages, &ctx, 2);
        assert_eq!(
            reports.iter().map(|report| report.id).collect::<Vec<_>>(),
            stages
        );
    }

    #[test]
    fn stage_context_is_shareable_between_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<StageContext<'static>>();
    }
}
