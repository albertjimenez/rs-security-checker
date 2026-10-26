//! Deterministic notification policy used when the local model is not available.

use crate::config::Config;
use crate::report::{NotificationDecision, Severity, StageReport};

pub fn heuristic(cfg: &Config, stages: &[StageReport]) -> NotificationDecision {
    if !cfg.notify_enabled {
        return NotificationDecision::disabled("notifications are disabled");
    }

    let highest = stages
        .iter()
        .flat_map(|stage| stage.findings.iter())
        .map(|finding| finding.severity)
        .max()
        .unwrap_or(Severity::Info);
    let failed: Vec<&StageReport> = stages
        .iter()
        .filter(|stage| stage.status.is_bad())
        .collect();
    let finding_count = stages
        .iter()
        .map(|stage| stage.findings.len())
        .sum::<usize>();

    if cfg.notify_always {
        return NotificationDecision::heuristic(
            true,
            "notify-always is enabled; the local model may still veto the notification",
        );
    }

    if !failed.is_empty() {
        let names = failed
            .iter()
            .map(|stage| stage.title.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return NotificationDecision::heuristic(
            true,
            format!("{} stage(s) failed or timed out: {names}", failed.len()),
        );
    }

    if highest.at_least(cfg.notify_on) {
        return NotificationDecision::heuristic(
            true,
            format!(
                "highest severity {highest} meets the notification threshold {} ({finding_count} finding(s))",
                cfg.notify_on
            ),
        );
    }

    NotificationDecision::heuristic(
        false,
        format!(
            "highest severity {highest} is below the notification threshold {} ({finding_count} finding(s))",
            cfg.notify_on
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_config;
    use crate::report::{StageId, StageStatus};

    fn config() -> Config {
        Config {
            notify_enabled: true,
            slack_webhook: Some("https://example.invalid".into()),
            ..test_config()
        }
    }

    #[test]
    fn notifications_disabled_short_circuit() {
        let mut cfg = config();
        cfg.notify_enabled = false;
        let decision = heuristic(&cfg, &[]);
        assert!(!decision.notify);
        assert_eq!(decision.source, crate::report::DecisionSource::Disabled);
    }

    #[test]
    fn notify_always_wins() {
        let mut cfg = config();
        cfg.notify_always = true;
        let decision = heuristic(&cfg, &[]);
        assert!(decision.notify);
        assert!(decision.reason.contains("notify-always"));
    }

    #[test]
    fn notifies_when_threshold_is_met() {
        let mut stage = StageReport::new(StageId::Rootkit);
        stage.finding(Severity::High, "suspicious");
        stage.finish(None);
        let decision = heuristic(&config(), &[stage]);
        assert!(decision.notify);
    }

    #[test]
    fn stays_quiet_below_threshold() {
        let mut stage = StageReport::new(StageId::Debsums);
        stage.finding(Severity::Low, "changed config");
        stage.finish(None);
        let decision = heuristic(&config(), &[stage]);
        assert!(!decision.notify);
    }

    #[test]
    fn failed_stage_always_notifies() {
        let mut stage = StageReport::new(StageId::Clamav);
        stage.finish(Some(StageStatus::Failed));
        let decision = heuristic(&config(), &[stage]);
        assert!(decision.notify);
    }
}
