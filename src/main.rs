//! Safe Rust port of the Debian security-audit Jenkins pipeline.

mod audit;
mod cli;
mod config;
mod constants;
mod decision;
mod error;
mod exec;
mod fsutil;
#[cfg(feature = "laya")]
mod laya;
mod lock;
mod logging;
mod logs;
#[cfg(feature = "notifications")]
mod notify;
mod report;
#[cfg(test)]
mod test_support;
mod text;
mod ui;

use std::fs;
use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use clap::Parser;

use tracing::info;

use crate::audit::StageContext;
use crate::cli::Cli;
use crate::error::Result;
use crate::exec::Runner;
use crate::lock::InstanceLock;
use crate::report::{
    AuditSummary, NotificationDecision, NotificationOutcome, Severity, StageId, StageReport,
    StageStatus, now_rfc3339,
};
use crate::ui::Ui;

fn main() -> ExitCode {
    exec::install_graceful_interrupt();
    let cli = Cli::parse();
    logging::init(cli.verbose, cli.quiet);
    if cli.list_stages {
        cli::print_stages();
        return ExitCode::SUCCESS;
    }

    match run(cli) {
        Ok(code) => ExitCode::from(code as u8),
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<i32> {
    let config = cli.into_config()?;
    config.validate()?;

    info!(
        parallel_jobs = config.parallel_jobs,
        dry_run = config.dry_run,
        json = config.json,
        "audit configuration validated"
    );

    let ui = Ui::new(config.color, config.quiet, config.verbose, config.json);
    ui.debug(format!(
        "features: laya={}, notifications={}",
        cfg!(feature = "laya"),
        cfg!(feature = "notifications")
    ));

    fs::create_dir_all(&config.output_dir)?;
    let output_dir =
        fs::canonicalize(&config.output_dir).unwrap_or_else(|_| config.output_dir.clone());

    let _lock = if config.dry_run || config.no_lock {
        None
    } else {
        Some(InstanceLock::acquire(&config.lock_file)?)
    };

    let runner = Runner::new(
        config.sudo_mode,
        config.dry_run,
        config.command_timeout,
        config.max_output_bytes,
        ui,
    );
    ui.debug(format!(
        "sudo available={} root={} active={}",
        runner.sudo_available(),
        runner.is_root(),
        runner.uses_sudo()
    ));

    let selected = config.selected_stages();
    let total = selected.len();
    let started_at = now_rfc3339();
    let started = Instant::now();
    let deadline = started + config.global_timeout;
    let parallel_jobs = effective_parallel_jobs(config.parallel_jobs);
    ui.debug(format!(
        "parallel analysis workers={parallel_jobs} (web, auth, hardening, aws)"
    ));

    let mut reports = Vec::with_capacity(total);
    let mut stopped_early = false;
    let ctx = StageContext {
        cfg: &config,
        runner: &runner,
        ui: &ui,
        deadline,
    };
    let mut index = 0;

    while index < selected.len() {
        let stage = selected[index];

        if stopped_early {
            reports.push(skipped_report(stage, "--fail-fast stopped the audit"));
            index += 1;
            continue;
        }

        if parallel_jobs > 1 && stage.is_parallel_safe() {
            // Group consecutive lightweight stages. Heavy stages act as barriers so their ordering
            // and resource use stay predictable.
            let mut end = index + 1;
            while end < selected.len() && selected[end].is_parallel_safe() {
                end += 1;
            }
            let batch = &selected[index..end];
            let mut batch_failed = false;
            let mut offset = 0;

            for chunk in batch.chunks(parallel_jobs) {
                if config.fail_fast && batch_failed {
                    for stage in chunk {
                        reports.push(skipped_report(*stage, "--fail-fast stopped the audit"));
                    }
                    offset += chunk.len();
                    continue;
                }

                for (position, stage) in chunk.iter().enumerate() {
                    ui.stage_start(index + offset + position + 1, total, stage.title());
                }
                for report in audit::execute_parallel(chunk, &ctx, parallel_jobs) {
                    let report = record_report(report, &output_dir, &ui);
                    batch_failed |= report.status.is_bad();
                    reports.push(report);
                }
                offset += chunk.len();
            }

            if config.fail_fast && batch_failed {
                stopped_early = true;
            }
            index = end;
            continue;
        }

        ui.stage_start(index + 1, total, stage.title());
        let report = record_report(audit::execute(stage, &ctx), &output_dir, &ui);
        let failed = report.status.is_bad();
        reports.push(report);

        if config.fail_fast && failed {
            stopped_early = true;
        }
        index += 1;
    }

    if !config.exception_patterns.is_empty() {
        apply_exceptions(&mut reports, &config.exception_patterns);
        info!(
            patterns = config.exception_patterns.len(),
            "applied false-positive exceptions"
        );
    }

    let finished_at = now_rfc3339();
    let duration_ms = started.elapsed().as_millis() as u64;

    #[allow(unused_mut)]
    let mut decision = if config.notify_enabled {
        decision::heuristic(&config, &reports)
    } else {
        NotificationDecision::disabled("notifications are disabled")
    };

    #[allow(unused_mut)]
    let mut summary = AuditSummary::new(
        hostname(),
        started_at,
        finished_at,
        duration_ms,
        output_dir.display().to_string(),
        reports,
        NotificationOutcome::default(),
        decision.clone(),
        None,
        None,
        0,
    );

    #[cfg(feature = "laya")]
    if config.laya_enabled {
        match laya::assess(&config, &summary) {
            Ok(assessment) => {
                if config.notify_enabled {
                    decision =
                        NotificationDecision::laya(assessment.notify, assessment.reason.clone());
                    summary.notification_decision = decision.clone();
                }
                summary.laya = Some(assessment);
            }
            Err(error) => {
                ui.warn(format!(
                    "laya triage failed; using the heuristic decision: {error}"
                ));
                summary.laya_error = Some(error.to_string());
            }
        }
    }

    #[cfg(feature = "notifications")]
    if config.notify_enabled {
        if summary.notification_decision.notify {
            summary.notification = notify::dispatch(&config, &summary);
        } else {
            summary.notification = NotificationOutcome {
                enabled: true,
                ..NotificationOutcome::default()
            };
        }
    }

    let exit_code = compute_exit_code(&summary.stages, config.fail_on, summary.highest_severity);
    summary.exit_code = exit_code;

    let json_path = output_dir.join("audit-summary.json");
    let markdown_path = output_dir.join("audit-summary.md");
    fsutil::write_atomic(&json_path, summary.to_json()?.as_bytes())?;
    fsutil::write_atomic(&markdown_path, summary.markdown().as_bytes())?;

    let mut report_paths = summary
        .stages
        .iter()
        .filter_map(|stage| {
            stage
                .artifact
                .as_ref()
                .map(|artifact| output_dir.join(artifact).display().to_string())
        })
        .collect::<Vec<_>>();
    report_paths.push(json_path.display().to_string());
    report_paths.push(markdown_path.display().to_string());

    ui.summary(&summary, &report_paths);
    if config.json {
        println!("{}", summary.to_json()?);
    }

    Ok(exit_code)
}

fn record_report(mut report: StageReport, output_dir: &Path, ui: &Ui) -> StageReport {
    if let Some(artifact) = report.artifact.as_deref() {
        let path = output_dir.join(artifact);
        if let Err(error) = fsutil::write_atomic(&path, report.output.as_bytes()) {
            ui.error(format!("could not write {}: {error}", path.display()));
            report.note(format!(
                "could not write artifact `{}`: {error}",
                path.display()
            ));
            report.status = StageStatus::Failed;
        }
    }

    ui.stage_end(&report);
    report
}

fn skipped_report(stage: StageId, reason: &str) -> StageReport {
    let mut report = StageReport::new(stage);
    report.note(reason);
    report.finish(Some(StageStatus::Skipped));
    report
}

/// Resolve `--parallel-jobs`: 0 means a conservative 2-4 workers, 1 disables concurrency.
fn effective_parallel_jobs(configured: usize) -> usize {
    if configured > 0 {
        return configured;
    }
    std::thread::available_parallelism()
        .map_or(2, |count| count.get())
        .clamp(2, 4)
}

fn apply_exceptions(reports: &mut [StageReport], patterns: &[String]) {
    for report in reports.iter_mut() {
        let before = report.findings.len();
        report.findings.retain(|finding| {
            !patterns
                .iter()
                .any(|pattern| exception_matches(pattern, report.id, &finding.message))
        });
        if report.findings.len() != before {
            recompute_status(report);
        }
    }
}

/// Recompute the status after findings were removed, but never downgrade a stage that failed or
/// timed out: those statuses describe lost coverage, not the findings themselves.
fn recompute_status(report: &mut StageReport) {
    if matches!(report.status, StageStatus::Warnings | StageStatus::Passed) {
        report.status = if report.highest_severity().at_least(Severity::Low) {
            StageStatus::Warnings
        } else {
            StageStatus::Passed
        };
    }
}

fn exception_matches(pattern: &str, stage: StageId, message: &str) -> bool {
    let message = message.to_lowercase();
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return false;
    }

    if let Some((raw_stage, needle)) = pattern.split_once(':') {
        let raw_stage = raw_stage.trim().to_ascii_lowercase();
        // Only a real stage id (or `*`) makes the prefix stage-scoped. Otherwise a plain message
        // such as `debsums: checksum mismatch` must still match as a whole string.
        let stage_scoped = raw_stage == "*"
            || StageId::ALL
                .iter()
                .any(|candidate| candidate.as_str() == raw_stage);
        if stage_scoped {
            let needle = needle.trim();
            if needle.is_empty() {
                return false;
            }
            if raw_stage != "*" && stage.as_str() != raw_stage {
                return false;
            }
            return message.contains(&needle.to_lowercase());
        }
    }

    message.contains(&pattern.to_lowercase())
}

fn compute_exit_code(stages: &[StageReport], fail_on: Option<Severity>, highest: Severity) -> i32 {
    let stage_failed = stages.iter().any(|stage| stage.status.is_bad());
    let threshold_reached = fail_on.is_some_and(|threshold| highest.at_least(threshold));
    i32::from(stage_failed || threshold_reached)
}

fn hostname() -> String {
    fsutil::read_limited(Path::new("/etc/hostname"), 4096)
        .ok()
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
        .or_else(|| {
            std::env::var("HOSTNAME")
                .ok()
                .map(|name| name.trim().to_owned())
                .filter(|name| !name.is_empty())
        })
        .or_else(|| {
            nix::unistd::gethostname()
                .ok()
                .and_then(|name| name.into_string().ok())
                .map(|name| name.trim().to_owned())
                .filter(|name| !name.is_empty())
        })
        .unwrap_or_else(|| "unknown".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stage(status: StageStatus) -> StageReport {
        let mut report = StageReport::new(StageId::Docker);
        report.finish(Some(status));
        report
    }

    #[test]
    fn exit_code_is_zero_for_a_clean_run() {
        assert_eq!(
            compute_exit_code(&[stage(StageStatus::Passed)], None, Severity::Info),
            0
        );
        assert_eq!(
            compute_exit_code(&[], Some(Severity::High), Severity::Low),
            0
        );
    }

    #[test]
    fn failed_or_timed_out_stages_set_exit_code_one() {
        assert_eq!(
            compute_exit_code(&[stage(StageStatus::Failed)], None, Severity::Info),
            1
        );
        assert_eq!(
            compute_exit_code(&[stage(StageStatus::TimedOut)], None, Severity::Info),
            1
        );
    }

    #[test]
    fn fail_on_threshold_sets_exit_code_one() {
        assert_eq!(
            compute_exit_code(
                &[stage(StageStatus::Warnings)],
                Some(Severity::High),
                Severity::High
            ),
            1
        );
        assert_eq!(
            compute_exit_code(
                &[stage(StageStatus::Warnings)],
                Some(Severity::Critical),
                Severity::High
            ),
            0
        );
    }

    #[test]
    fn exception_patterns_can_be_global_or_stage_scoped() {
        assert!(exception_matches(
            "socket",
            StageId::Docker,
            "mounts the socket"
        ));
        assert!(exception_matches(
            "docker:socket",
            StageId::Docker,
            "mounts the socket"
        ));
        assert!(!exception_matches(
            "docker:socket",
            StageId::Network,
            "mounts the socket"
        ));
        assert!(exception_matches(
            "*:socket",
            StageId::Network,
            "mounts the socket"
        ));
        // A colon that is not a stage id stays part of the message pattern.
        assert!(exception_matches(
            "debsums: checksum mismatch",
            StageId::Debsums,
            "debsums: checksum mismatch found"
        ));
        assert!(!exception_matches(
            "debsums: checksum mismatch",
            StageId::Docker,
            "debsums: checksum mismatch found"
        ));
    }

    #[test]
    fn applying_exceptions_recomputes_warnings_but_not_failures() {
        let mut warnings = StageReport::new(StageId::Docker);
        warnings.finding(Severity::High, "mounts the Docker socket");
        warnings.finish(None);
        assert_eq!(warnings.status, StageStatus::Warnings);

        let mut failed = StageReport::new(StageId::Debsums);
        failed.finding(Severity::Medium, "checksum mismatch");
        failed.finish(Some(StageStatus::Failed));

        let mut reports = vec![warnings, failed];
        apply_exceptions(&mut reports, &["docker:mounts the Docker socket".into()]);
        assert!(reports[0].findings.is_empty());
        assert_eq!(reports[0].status, StageStatus::Passed);
        // The scoped pattern did not apply to the second stage.
        assert_eq!(reports[1].findings.len(), 1);
        assert_eq!(reports[1].status, StageStatus::Failed);

        apply_exceptions(&mut reports, &["checksum mismatch".into()]);
        assert!(reports[1].findings.is_empty());
        assert_eq!(reports[1].status, StageStatus::Failed);
    }

    #[test]
    fn hostname_is_never_empty() {
        assert!(!hostname().is_empty());
    }

    #[test]
    fn automatic_parallel_jobs_stay_bounded() {
        assert!((2..=4).contains(&effective_parallel_jobs(0)));
        assert_eq!(effective_parallel_jobs(1), 1);
        assert_eq!(effective_parallel_jobs(8), 8);
    }

    #[test]
    fn record_report_writes_the_artifact() {
        let dir = tempfile::tempdir().unwrap();
        let ui = Ui::new(ui::ColorMode::Never, true, false, false);
        let mut report = StageReport::new(StageId::Web);
        report.output = "web findings\n".to_owned();
        report.finish(None);

        let report = record_report(report, dir.path(), &ui);
        assert_eq!(report.status, StageStatus::Passed);
        assert_eq!(
            fs::read_to_string(dir.path().join("web-logs-report.txt")).unwrap(),
            "web findings\n"
        );
    }

    #[test]
    fn skipped_reports_carry_the_reason() {
        let report = skipped_report(StageId::Aws, "--fail-fast stopped the audit");
        assert_eq!(report.status, StageStatus::Skipped);
        assert_eq!(report.notes, vec!["--fail-fast stopped the audit"]);
    }
}
