//! Telegram Bot API channel.

use serde::Deserialize;

use super::message::Message;
use super::{Channel, http_client, redact, truncate};
use crate::error::{Error, Result};

const MAX_TELEGRAM_TEXT: usize = 4_000;

pub struct Telegram {
    token: String,
    chat_id: String,
}

impl Telegram {
    pub fn new(token: String, chat_id: String) -> Self {
        Self { token, chat_id }
    }

    fn redact(&self, text: &str) -> String {
        redact(text, &self.token)
    }
}

#[derive(Deserialize)]
struct TelegramResponse {
    ok: bool,
    #[serde(default)]
    description: Option<String>,
}

impl Channel for Telegram {
    fn name(&self) -> &'static str {
        "telegram"
    }

    fn send(&self, message: &Message) -> Result<()> {
        let client = http_client()?;
        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.token);
        let text = format_text(message);
        let payload = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "disable_web_page_preview": true,
        });

        let response = client.post(&url).json(&payload).send().map_err(|error| {
            Error::http(self.redact(&format!("Telegram request failed: {error}")))
        })?;

        let status = response.status();
        let body = response.text().unwrap_or_default();
        if !status.is_success() {
            let message = format!("Telegram returned {status}: {}", truncate(body.trim(), 500));
            return Err(Error::http(self.redact(&message)));
        }

        let parsed: TelegramResponse = serde_json::from_str(&body).map_err(|error| {
            Error::http(self.redact(&format!("Telegram returned invalid JSON: {error}")))
        })?;
        if !parsed.ok {
            let description = parsed
                .description
                .unwrap_or_else(|| "unknown Telegram error".to_owned());
            let message = format!("Telegram rejected the message: {description}");
            return Err(Error::http(self.redact(&message)));
        }
        Ok(())
    }
}

fn format_text(message: &Message) -> String {
    truncate(
        &format!("{}\n\n{}", message.title, message.body),
        MAX_TELEGRAM_TEXT,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_plain_text() {
        let message = Message {
            title: "Test".into(),
            body: "Body".into(),
        };
        let text = format_text(&message);
        assert!(text.starts_with("Test"));
        assert!(text.contains("Body"));
    }

    #[test]
    fn keeps_messages_within_telegram_limit() {
        let message = Message {
            title: "Test".into(),
            body: "x".repeat(MAX_TELEGRAM_TEXT + 100),
        };
        assert!(format_text(&message).len() <= MAX_TELEGRAM_TEXT + 32);
    }
}
