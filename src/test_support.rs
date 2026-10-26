//! Shared fixtures for unit tests across optional modules.

#[cfg(any(feature = "laya", feature = "notifications"))]
use std::io::{BufRead, BufReader, Read, Write};
#[cfg(any(feature = "laya", feature = "notifications"))]
use std::net::TcpListener;
#[cfg(any(feature = "laya", feature = "notifications"))]
use std::thread;

#[cfg(any(feature = "laya", feature = "notifications"))]
use crate::report::{AuditSummary, NotificationDecision, NotificationOutcome, StageReport};
use crate::report::{LayaAssessment, Severity};
use crate::ui::{ColorMode, Ui};

pub(crate) fn ui() -> Ui {
    Ui::new(ColorMode::Never, true, false, false)
}

/// Build a minimal audit summary with a caller-chosen notification decision.
#[cfg(any(feature = "laya", feature = "notifications"))]
pub(crate) fn summary_with(
    stages: Vec<StageReport>,
    decision: NotificationDecision,
) -> AuditSummary {
    AuditSummary::new(
        "host".into(),
        "start".into(),
        "end".into(),
        1_500,
        "/tmp/reports".into(),
        stages,
        NotificationOutcome::default(),
        decision,
        None,
        None,
        0,
    )
}

/// Build a minimal local-model assessment for display tests.
pub(crate) fn laya_assessment(severity: Severity, reason: &str) -> LayaAssessment {
    LayaAssessment {
        endpoint: "http://127.0.0.1:8080/v1".into(),
        api: "openai".into(),
        model: "laya-triage".into(),
        notify: true,
        severity,
        reason: reason.into(),
        latency_ms: 12,
    }
}

/// Serve one HTTP request with a fixed response and return the request text.
#[cfg(any(feature = "laya", feature = "notifications"))]
pub(crate) fn serve_once(status: &str, body: &str) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let status = status.to_owned();
    let body = body.to_owned();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request = String::new();
        reader.read_line(&mut request).unwrap();
        let mut content_length = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" || line.is_empty() {
                break;
            }
            if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
        let mut payload = vec![0; content_length];
        reader.read_exact(&mut payload).unwrap();
        request.push_str(&String::from_utf8_lossy(&payload));

        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.flush().unwrap();
        request
    });
    (format!("http://{address}"), handle)
}
