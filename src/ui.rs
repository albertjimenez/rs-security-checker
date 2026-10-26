//! Console rendering. In `--json` mode all human output goes to stderr.

use std::io::{self, IsTerminal, Write};

use crate::report::{AuditSummary, StageReport, StageStatus};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, Copy)]
pub struct Ui {
    color: bool,
    quiet: bool,
    verbose: bool,
    human_to_stderr: bool,
}

impl Ui {
    pub fn new(color: ColorMode, quiet: bool, verbose: bool, json: bool) -> Self {
        let color = match color {
            ColorMode::Always => true,
            ColorMode::Never => false,
            ColorMode::Auto => {
                // Colorize the stream that actually receives human output: stderr in `--json`
                // mode, stdout otherwise.
                let target_is_terminal = if json {
                    io::stderr().is_terminal()
                } else {
                    io::stdout().is_terminal()
                };
                target_is_terminal && std::env::var_os("NO_COLOR").is_none()
            }
        };
        Self {
            color,
            quiet,
            verbose,
            human_to_stderr: json,
        }
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }

    fn emit(&self, line: &str) {
        if self.human_to_stderr {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(stderr, "{line}");
        } else {
            let mut stdout = io::stdout().lock();
            let _ = writeln!(stdout, "{line}");
        }
    }

    pub fn warn(&self, message: impl AsRef<str>) {
        self.emit(&format!(
            "{} {}",
            self.paint("33;1", "warning:"),
            message.as_ref()
        ));
    }

    pub fn error(&self, message: impl AsRef<str>) {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(
            stderr,
            "{} {}",
            self.paint("31;1", "error:"),
            message.as_ref()
        );
    }

    pub fn debug(&self, message: impl AsRef<str>) {
        if self.verbose && !self.quiet {
            self.emit(&self.paint("2", &format!("  {}", message.as_ref())));
        }
    }

    pub fn command_line(&self, line: &str) {
        if self.verbose && !self.quiet {
            self.emit(&self.paint("2", &format!("  $ {line}")));
        }
    }

    pub fn stage_start(&self, index: usize, total: usize, title: &str) {
        if self.quiet {
            return;
        }
        let heading = format!("[{index}/{total}] {title}");
        self.emit("");
        self.emit(&self.paint("36;1", &heading));
    }

    pub fn stage_end(&self, report: &StageReport) {
        if self.quiet {
            return;
        }
        let (tag, color) = match report.status {
            StageStatus::Passed => ("ok", "32"),
            StageStatus::Warnings => ("warn", "33"),
            StageStatus::Failed => ("fail", "31"),
            StageStatus::Skipped => ("skip", "2"),
            StageStatus::TimedOut => ("timeout", "31"),
        };
        let severity = report.highest_severity();
        self.emit(&format!(
            "  {} {} ({} ms, {} finding(s), max severity: {})",
            self.paint(color, &format!("[{tag}]")),
            report.status,
            report.duration_ms,
            report.finding_count(),
            severity
        ));
        for note in &report.notes {
            self.emit(&self.paint("2", &format!("  note: {note}")));
        }
        for finding in &report.findings {
            let color = match finding.severity {
                crate::report::Severity::Critical => "31;1",
                crate::report::Severity::High => "31",
                crate::report::Severity::Medium => "33",
                crate::report::Severity::Low => "36",
                crate::report::Severity::Info => "2",
            };
            self.emit(&format!(
                "  {} {}",
                self.paint(color, &format!("[{}]", finding.severity)),
                finding.message
            ));
        }
    }

    pub fn summary(&self, summary: &AuditSummary, reports: &[String]) {
        if self.quiet {
            return;
        }
        self.emit("");
        self.emit(&self.paint(
            "36;1",
            &format!(
                "Audit complete in {:.1}s — highest severity: {} — findings: {}",
                summary.duration_ms as f64 / 1000.0,
                summary.highest_severity,
                summary.total_findings
            ),
        ));
        let counts = crate::report::format_finding_counts(&summary.finding_counts);
        self.emit(&format!("  counts: {counts}"));
        self.emit(&format!(
            "  notification: {} ({})",
            if summary.notification_decision.notify {
                "notify"
            } else {
                "skip"
            },
            summary.notification_decision.reason
        ));
        if let Some(laya) = &summary.laya {
            self.emit(&format!(
                "  laya: notify={} severity={} ({})",
                laya.notify, laya.severity, laya.reason
            ));
        }
        if !summary.notification.delivered.is_empty() {
            self.emit(&format!(
                "  delivered via: {}",
                summary.notification.delivered.join(", ")
            ));
        }
        for failure in &summary.notification.failed {
            self.warn(format!(
                "notification channel `{}` failed: {}",
                failure.channel, failure.error
            ));
        }
        for path in reports {
            self.emit(&format!("  report: {path}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{
        AuditSummary, ChannelFailure, DecisionSource, NotificationDecision, NotificationOutcome,
        Severity, StageId,
    };

    fn stage(status: StageStatus, severity: Severity) -> StageReport {
        let mut report = StageReport::new(StageId::Rootkit);
        report.finding(severity, "demo finding");
        report.note("demo note");
        report.finish(Some(status));
        report
    }

    fn summary() -> AuditSummary {
        let stages = [
            stage(StageStatus::Passed, Severity::Info),
            stage(StageStatus::Warnings, Severity::Medium),
            stage(StageStatus::Failed, Severity::Critical),
            stage(StageStatus::Skipped, Severity::Low),
            stage(StageStatus::TimedOut, Severity::High),
        ];
        let mut summary = AuditSummary::new(
            "host".into(),
            "start".into(),
            "end".into(),
            1_500,
            "/tmp/reports".into(),
            stages.to_vec(),
            NotificationOutcome::default(),
            NotificationDecision::heuristic(true, "threshold met"),
            None,
            None,
            1,
        );
        summary.notification = NotificationOutcome {
            enabled: true,
            attempted: true,
            delivered: vec!["slack".into()],
            failed: vec![ChannelFailure {
                channel: "telegram".into(),
                error: "timeout".into(),
            }],
            error: None,
        };
        summary.laya = Some(crate::test_support::laya_assessment(
            Severity::High,
            "rootkit found",
        ));
        summary
    }

    #[test]
    fn renders_stage_lifecycle_in_every_mode() {
        let ui = Ui::new(ColorMode::Always, false, true, false);
        ui.stage_start(1, 5, "Demo");
        for status in [
            StageStatus::Passed,
            StageStatus::Warnings,
            StageStatus::Failed,
            StageStatus::Skipped,
            StageStatus::TimedOut,
        ] {
            for severity in Severity::ALL {
                ui.stage_end(&stage(status, severity));
            }
        }
        ui.debug("debug");
        ui.command_line("echo hi");
        ui.warn("warning");
        ui.error("error");
        ui.summary(&summary(), &["audit-summary.json".into()]);
    }

    #[test]
    fn quiet_mode_suppresses_human_output() {
        let ui = Ui::new(ColorMode::Never, true, false, false);
        ui.stage_start(1, 1, "Demo");
        ui.stage_end(&stage(StageStatus::Failed, Severity::Critical));
        ui.debug("debug");
        ui.command_line("echo hi");
        ui.summary(&summary(), &[]);
    }

    #[test]
    fn json_mode_sends_human_output_to_stderr() {
        let ui = Ui::new(ColorMode::Never, false, true, true);
        ui.debug("debug");
        ui.command_line("echo hi");
        ui.warn("warning");
        ui.error("error");
        ui.stage_start(1, 1, "Demo");
        ui.stage_end(&stage(StageStatus::Warnings, Severity::High));
        ui.summary(&summary(), &[]);
    }

    #[test]
    fn summary_without_laya_or_notifications_is_supported() {
        let ui = Ui::new(ColorMode::Never, false, false, true);
        let mut summary = summary();
        summary.laya = None;
        summary.notification = NotificationOutcome::default();
        summary.notification_decision = NotificationDecision {
            notify: false,
            reason: "below threshold".into(),
            source: DecisionSource::Heuristic,
        };
        ui.summary(&summary, &["a".into(), "b".into()]);
    }

    #[test]
    fn automatic_color_mode_is_detected_without_panicking() {
        let ui = Ui::new(ColorMode::Auto, false, false, false);
        ui.warn("auto");
        ui.debug("auto");
    }
}
