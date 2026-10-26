//! Notification channels (`notifications` feature).
//!
//! Both channels are opt-in at runtime: the feature makes the code available, `--notify` (or
//! `NOTIFY_ENABLED=true`) actually enables delivery. A channel that is not configured is simply
//! not registered.

pub mod message;

mod slack;
mod telegram;

use std::time::Duration;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::report::{AuditSummary, ChannelFailure, NotificationOutcome};

pub trait Channel {
    fn name(&self) -> &'static str;
    fn send(&self, message: &message::Message) -> Result<()>;
}

pub fn dispatch(cfg: &Config, summary: &AuditSummary) -> NotificationOutcome {
    let mut outcome = NotificationOutcome {
        enabled: true,
        ..NotificationOutcome::default()
    };

    let channels = build_channels(cfg);
    if channels.is_empty() {
        outcome.error = Some(
            "notifications are enabled but no channel is configured (set SLACK_WEBHOOK_URL or TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID)"
                .to_owned(),
        );
        return outcome;
    }

    let message = message::build(summary);
    outcome.attempted = true;

    for channel in channels {
        match channel.send(&message) {
            Ok(()) => outcome.delivered.push(channel.name().to_owned()),
            Err(error) => outcome.failed.push(ChannelFailure {
                channel: channel.name().to_owned(),
                error: error.to_string(),
            }),
        }
    }

    outcome
}

fn build_channels(cfg: &Config) -> Vec<Box<dyn Channel>> {
    let mut channels: Vec<Box<dyn Channel>> = Vec::new();
    if let Some(webhook) = cfg
        .slack_webhook
        .as_deref()
        .filter(|webhook| !webhook.trim().is_empty())
    {
        channels.push(Box::new(slack::Slack::new(webhook.to_owned())));
    }
    if let (Some(token), Some(chat_id)) = (
        cfg.telegram_bot_token
            .as_deref()
            .filter(|token| !token.trim().is_empty()),
        cfg.telegram_chat_id
            .as_deref()
            .filter(|chat| !chat.trim().is_empty()),
    ) {
        channels.push(Box::new(telegram::Telegram::new(
            token.to_owned(),
            chat_id.to_owned(),
        )));
    }
    channels
}

pub(crate) fn http_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|error| Error::http(format!("could not build HTTP client: {error}")))
}

pub(crate) fn redact(text: &str, secret: &str) -> String {
    if secret.is_empty() {
        return text.to_owned();
    }
    text.replace(secret, "<redacted>")
}

pub(crate) fn truncate(text: &str, max_bytes: usize) -> String {
    crate::report::truncate_chars(text, max_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_config;
    use crate::report::{AuditSummary, DecisionSource, NotificationDecision};
    use crate::test_support::serve_once;

    fn summary() -> AuditSummary {
        crate::test_support::summary_with(
            Vec::new(),
            NotificationDecision {
                notify: true,
                reason: "threshold met".into(),
                source: DecisionSource::Heuristic,
            },
        )
    }

    #[test]
    fn build_channels_skips_blanks_and_registers_configured_channels() {
        let mut cfg = test_config();
        assert!(build_channels(&cfg).is_empty());

        cfg.slack_webhook = Some("   ".into());
        assert!(build_channels(&cfg).is_empty());

        cfg.slack_webhook = Some("https://hooks.slack.com/services/demo".into());
        assert_eq!(build_channels(&cfg).len(), 1);

        cfg.telegram_bot_token = Some("token".into());
        cfg.telegram_chat_id = Some("42".into());
        let channels = build_channels(&cfg);
        assert_eq!(channels.len(), 2);
        assert_eq!(channels[0].name(), "slack");
        assert_eq!(channels[1].name(), "telegram");
    }

    #[test]
    fn dispatch_reports_missing_configuration() {
        let mut cfg = test_config();
        cfg.notify_enabled = true;
        let outcome = dispatch(&cfg, &summary());
        assert!(outcome.enabled);
        assert!(!outcome.attempted);
        assert!(outcome.delivered.is_empty());
        assert!(outcome.error.as_deref().unwrap().contains("no channel"));
    }

    #[test]
    fn dispatch_delivers_to_slack() {
        let (base, server) = serve_once("200 OK", "");
        let mut cfg = test_config();
        cfg.notify_enabled = true;
        cfg.slack_webhook = Some(format!("{base}/services/demo"));

        let outcome = dispatch(&cfg, &summary());
        assert!(outcome.enabled);
        assert!(outcome.attempted);
        assert_eq!(outcome.delivered, vec!["slack"]);
        assert!(outcome.failed.is_empty());
        assert!(outcome.error.is_none());

        let request = server.join().unwrap();
        assert!(request.starts_with("POST /services/demo"));
        assert!(request.contains("\"text\""));
        assert!(request.contains("Security audit on host"));
    }

    #[test]
    fn dispatch_records_channel_failures() {
        let (base, server) = serve_once("500 Internal Server Error", "webhook exploded");
        let mut cfg = test_config();
        cfg.notify_enabled = true;
        cfg.slack_webhook = Some(format!("{base}/services/demo"));

        let outcome = dispatch(&cfg, &summary());
        assert!(outcome.attempted);
        assert!(outcome.delivered.is_empty());
        assert_eq!(outcome.failed.len(), 1);
        assert_eq!(outcome.failed[0].channel, "slack");
        assert!(outcome.failed[0].error.contains("500"));
        assert!(outcome.failed[0].error.contains("webhook exploded"));
        server.join().unwrap();
    }

    #[test]
    fn redaction_and_truncation_are_safe() {
        assert_eq!(redact("token=secret", "secret"), "token=<redacted>");
        assert_eq!(redact("token=secret", ""), "token=secret");
        assert_eq!(truncate("short", 100), "short");
        assert!(truncate(&"x".repeat(50), 10).len() <= 42);
    }
}
