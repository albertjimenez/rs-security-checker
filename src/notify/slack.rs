//! Slack incoming-webhook channel.

use super::message::Message;
use super::{Channel, http_client, redact, truncate};
use crate::error::{Error, Result};

const MAX_SLACK_TEXT: usize = 35_000;

pub struct Slack {
    webhook: String,
}

impl Slack {
    pub fn new(webhook: String) -> Self {
        Self { webhook }
    }
}

impl Channel for Slack {
    fn name(&self) -> &'static str {
        "slack"
    }

    fn send(&self, message: &Message) -> Result<()> {
        let client = http_client()?;
        let text = format_text(message);
        let payload = serde_json::json!({ "text": text });

        let response = client
            .post(&self.webhook)
            .json(&payload)
            .send()
            .map_err(|error| {
                Error::http(redact(
                    &format!("Slack request failed: {error}"),
                    &self.webhook,
                ))
            })?;

        let status = response.status();
        let body = response.text().unwrap_or_default();
        if !status.is_success() {
            return Err(Error::http(redact(
                &format!("Slack returned {status}: {}", truncate(body.trim(), 500)),
                &self.webhook,
            )));
        }
        Ok(())
    }
}

fn format_text(message: &Message) -> String {
    truncate(
        &format!("*{}*\n{}", message.title, message.body),
        MAX_SLACK_TEXT,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_title_and_body() {
        let message = Message {
            title: "Test".into(),
            body: "Body".into(),
        };
        let text = format_text(&message);
        assert!(text.starts_with("*Test*"));
        assert!(text.contains("Body"));
    }

    #[test]
    fn truncates_large_messages() {
        let message = Message {
            title: "Test".into(),
            body: "x".repeat(MAX_SLACK_TEXT + 100),
        };
        assert!(format_text(&message).len() <= MAX_SLACK_TEXT + 32);
    }
}
