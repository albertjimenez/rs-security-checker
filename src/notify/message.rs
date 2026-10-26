//! Human-readable notification message built from the audit summary.

use std::fmt::Write as _;

use crate::report::{AuditSummary, StageStatus};
use crate::text::truncate;

pub struct Message {
    pub title: String,
    pub body: String,
}

pub fn build(summary: &AuditSummary) -> Message {
    let title = format!(
        "[{}] Security audit on {}",
        summary.highest_severity.as_str().to_uppercase(),
        summary.host
    );

    let mut body = String::new();
    let _ = writeln!(body, "Host: {}", summary.host);
    let _ = writeln!(body, "Started: {}", summary.started_at);
    let _ = writeln!(
        body,
        "Duration: {:.1}s",
        summary.duration_ms as f64 / 1000.0
    );
    let _ = writeln!(body, "Highest severity: {}", summary.highest_severity);
    let _ = writeln!(
        body,
        "Findings: {} ({})",
        summary.total_findings,
        crate::report::format_finding_counts(&summary.finding_counts)
    );

    let warnings = summary
        .stages
        .iter()
        .filter(|stage| stage.status == StageStatus::Warnings)
        .count();
    let failed = summary
        .stages
        .iter()
        .filter(|stage| stage.status.is_bad())
        .count();
    let skipped = summary
        .stages
        .iter()
        .filter(|stage| stage.status == StageStatus::Skipped)
        .count();
    let _ = writeln!(
        body,
        "Stages: {} total, {warnings} warning(s), {failed} failed, {skipped} skipped",
        summary.stages.len()
    );
    let _ = writeln!(
        body,
        "Decision: {} via {} ({})",
        if summary.notification_decision.notify {
            "notify"
        } else {
            "skip"
        },
        summary.notification_decision.source,
        summary.notification_decision.reason
    );
    if let Some(laya) = &summary.laya {
        let _ = writeln!(
            body,
            "Local model: notify={} severity={} ({})",
            laya.notify, laya.severity, laya.reason
        );
    }

    let mut findings = summary
        .stages
        .iter()
        .flat_map(|stage| {
            stage
                .findings
                .iter()
                .map(move |finding| (stage.title.as_str(), finding))
        })
        .collect::<Vec<_>>();
    findings.sort_by_key(|(_, finding)| std::cmp::Reverse(finding.severity));

    if findings.is_empty() {
        body.push_str("Top findings: none\n");
    } else {
        body.push_str("Top findings:\n");
        for (stage, finding) in findings.iter().take(8) {
            let _ = writeln!(
                body,
                "  - [{}] {stage}: {}",
                finding.severity.as_str().to_uppercase(),
                truncate(&finding.message, 220)
            );
        }
        if findings.len() > 8 {
            let _ = writeln!(body, "  ... and {} more", findings.len() - 8);
        }
    }

    let _ = writeln!(body, "Reports: {}", summary.output_dir);

    Message { title, body }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{AuditSummary, NotificationDecision, Severity, StageId, StageReport};

    fn summary(stages: Vec<StageReport>) -> AuditSummary {
        crate::test_support::summary_with(
            stages,
            NotificationDecision::heuristic(true, "threshold met"),
        )
    }

    fn stage(status: StageStatus, findings: &[(Severity, &str)]) -> StageReport {
        let mut report = StageReport::new(StageId::Docker);
        for (severity, message) in findings {
            report.finding(*severity, (*message).to_owned());
        }
        report.finish(Some(status));
        report
    }

    #[test]
    fn build_includes_title_counts_and_stage_status() {
        let message = build(&summary(vec![
            stage(
                StageStatus::Warnings,
                &[(Severity::High, "privileged container")],
            ),
            stage(StageStatus::Failed, &[]),
            stage(StageStatus::Skipped, &[]),
        ]));

        assert_eq!(message.title, "[HIGH] Security audit on host");
        assert!(message.body.contains("Host: host"));
        assert!(message.body.contains("Duration: 1.5s"));
        assert!(
            message
                .body
                .contains("Stages: 3 total, 1 warning(s), 1 failed, 1 skipped")
        );
        assert!(
            message
                .body
                .contains("Decision: notify via heuristic (threshold met)")
        );
        assert!(message.body.contains("Top findings:"));
        assert!(
            message
                .body
                .contains("[HIGH] Docker Security Audit: privileged container")
        );
    }

    #[test]
    fn build_handles_an_empty_audit() {
        let message = build(&summary(Vec::new()));
        assert!(message.body.contains("Top findings: none"));
        assert!(message.body.contains("Findings: 0"));
        assert!(message.body.contains("Stages: 0 total"));
    }

    #[test]
    fn build_mentions_the_local_model_when_present() {
        let mut summary = summary(Vec::new());
        summary.laya = Some(crate::test_support::laya_assessment(
            Severity::Critical,
            "rootkit found",
        ));

        let message = build(&summary);
        assert!(
            message
                .body
                .contains("Local model: notify=true severity=critical (rootkit found)")
        );
    }

    #[test]
    fn build_sorts_findings_by_severity_and_caps_the_list() {
        let findings = [
            (Severity::Low, "low"),
            (Severity::Critical, "critical"),
            (Severity::Medium, "medium"),
            (Severity::Critical, "critical two"),
            (Severity::High, "high"),
        ];
        let mut stages = vec![stage(StageStatus::Warnings, &findings)];
        for index in 0..6 {
            stages.push(stage(StageStatus::Warnings, &[(Severity::Low, "extra")]));
            let _ = index;
        }

        let message = build(&summary(stages));
        let critical = message.body.find("critical").unwrap();
        let low = message.body.rfind("low").unwrap();
        assert!(critical < low, "critical findings must be listed first");
        assert!(message.body.contains("... and 3 more"));
    }

    #[test]
    fn build_truncates_long_findings_on_char_boundaries() {
        let long = format!("{}é", "a".repeat(219));
        let message = build(&summary(vec![stage(
            StageStatus::Warnings,
            &[(Severity::High, &long)],
        )]));
        assert!(message.body.contains(&"a".repeat(219)));
        assert!(!message.body.contains('é'));
    }
}
