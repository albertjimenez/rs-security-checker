//! Local-model triage (`laya` feature).
//!
//! By default the audit summary is evaluated in-process by the Laya typed-decision model. The
//! optional `openai` backend speaks the OpenAI-compatible model-server protocol instead, for teams
//! that serve a fine-tuned generative model. Only a compact, structured summary is sent to a
//! server; full report artifacts never leave the host, and non-loopback endpoints are rejected
//! unless `--laya-allow-remote` is explicitly set.

use std::time::Instant;

use laya_inference::{Agent, Options, Question};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use url::Url;

use crate::config::{Config, LayaApi};
use crate::constants::{
    LAYA_BYTES_PER_TOKEN, LAYA_SPECIAL_TOKEN_RESERVE, LAYA_TOKEN_SAFETY_PERCENT,
    LAYA_TOKEN_WARN_PERCENT, MAX_LAYA_MAX_TOKENS,
};
use crate::error::{Error, Result};
use crate::report::{AuditSummary, LayaAssessment, Severity};
use crate::text::truncate;

const MAX_FINDINGS_IN_CONTEXT: usize = 40;
const MAX_FINDING_CHARS: usize = 400;

pub fn assess(cfg: &Config, summary: &AuditSummary) -> Result<LayaAssessment> {
    let endpoint = match cfg.laya_api {
        LayaApi::Laya => "local".to_owned(),
        LayaApi::Openai => validate_endpoint(&cfg.laya_url, cfg.laya_allow_remote)?.to_string(),
    };

    let started = Instant::now();
    let decision = match cfg.laya_api {
        LayaApi::Laya => call_laya(cfg, summary)?,
        LayaApi::Openai => {
            let client = http_client(cfg)?;
            let prompt = build_prompt(cfg, summary);
            parse_decision(
                &call_openai(&client, cfg, &prompt)?,
                summary.highest_severity,
            )?
        }
    };
    let latency_ms = started.elapsed().as_millis() as u64;

    Ok(LayaAssessment {
        endpoint,
        api: cfg.laya_api.as_str().to_owned(),
        model: cfg.laya_model.clone(),
        notify: decision.notify,
        severity: decision.severity,
        reason: decision.reason,
        latency_ms,
    })
}

fn http_client(cfg: &Config) -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(cfg.laya_timeout)
        .build()
        .map_err(|error| Error::http(error.to_string()))
}

fn validate_endpoint(raw: &str, allow_remote: bool) -> Result<Url> {
    let url =
        Url::parse(raw).map_err(|error| Error::config(format!("invalid LAYA_URL: {error}")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(Error::config("LAYA_URL must use http or https"));
    }
    if url.host_str().is_none() {
        return Err(Error::config("LAYA_URL must include a host"));
    }
    if !allow_remote && !is_loopback(&url) {
        return Err(Error::config(
            "refusing to send audit data to a non-loopback model endpoint; pass --laya-allow-remote to override",
        ));
    }
    Ok(url)
}

fn is_loopback(url: &Url) -> bool {
    url.host_str().is_some_and(crate::config::is_loopback_host)
}

fn build_prompt(cfg: &Config, summary: &AuditSummary) -> String {
    let context = build_context(summary, cfg.laya_max_chars);
    PROMPT_TEMPLATE.replace("{context}", &context)
}

const PROMPT_TEMPLATE: &str = r#"You are a security triage assistant for a Debian or Ubuntu host. Decide whether the following audit warrants a notification to the on-call engineer.

Notification rules:
- notify=true for critical or high severity findings: malware, rootkits, non-root UID 0 accounts, privileged containers, Docker socket mounts, exposed AWS credentials, IMDSv1 enabled, failed or timed-out security stages, or pending Debian/Ubuntu security patches.
- notify=false for informational noise, expected configuration warnings, benign authorized_keys listings, missing optional AWS agents on non-ECS hosts, or findings that do not require action.
- A failed or timed-out audit stage means coverage was lost; treat it as worth notifying unless the failure is clearly environmental and harmless.
- Never invent findings. Base the decision only on the supplied context.
- The reason must be one short sentence suitable for Slack/Telegram.

Respond with exactly one JSON object and nothing else. The schema is:
{"notify": true, "severity": "critical|high|medium|low|info", "reason": "one sentence"}

Audit context:
{context}
"#;

fn build_context(summary: &AuditSummary, max_chars: usize) -> String {
    #[derive(Serialize)]
    struct Stage<'a> {
        title: &'a str,
        status: &'a str,
        highest_severity: Severity,
        findings: usize,
        notes: &'a [String],
    }

    #[derive(Serialize)]
    struct Finding<'a> {
        stage: &'a str,
        severity: Severity,
        message: &'a str,
    }

    #[derive(Serialize)]
    struct Context<'a> {
        host: &'a str,
        started_at: &'a str,
        highest_severity: Severity,
        total_findings: usize,
        finding_counts: &'a std::collections::BTreeMap<String, usize>,
        stages: Vec<Stage<'a>>,
        findings: Vec<Finding<'a>>,
    }

    let stages = summary
        .stages
        .iter()
        .map(|stage| Stage {
            title: &stage.title,
            status: stage.status.as_str(),
            highest_severity: stage.highest_severity(),
            findings: stage.finding_count(),
            notes: &stage.notes,
        })
        .collect();

    let mut findings = Vec::new();
    for stage in &summary.stages {
        for finding in &stage.findings {
            if findings.len() >= MAX_FINDINGS_IN_CONTEXT {
                break;
            }
            findings.push(Finding {
                stage: &stage.title,
                severity: finding.severity,
                message: truncate(&finding.message, MAX_FINDING_CHARS),
            });
        }
    }

    let context = Context {
        host: &summary.host,
        started_at: &summary.started_at,
        highest_severity: summary.highest_severity,
        total_findings: summary.total_findings,
        finding_counts: &summary.finding_counts,
        stages,
        findings,
    };

    let json = serde_json::to_string_pretty(&context).unwrap_or_else(|_| "{}".to_owned());
    if json.len() <= max_chars {
        return json;
    }
    let mut end = max_chars;
    while end > 0 && !json.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n[context truncated]", &json[..end])
}

/// Run the Laya typed-decision model in-process. No model server is involved: the checkpoint in
/// `--laya-model` is loaded directly and answers the `notify`/`severity` questions in one pass.
fn call_laya(cfg: &Config, summary: &AuditSummary) -> Result<ParsedDecision> {
    let context = build_context(summary, cfg.laya_max_chars);
    let questions = laya_questions();

    let mut agent = Agent::from_dir(&cfg.laya_model, Options::default()).map_err(|error| {
        Error::LayaResponse(format!(
            "could not load the Laya checkpoint `{}`: {error}",
            cfg.laya_model
        ))
    })?;

    // The shipped checkpoints default to a 512–1,024-token sequence budget, which silently
    // cuts long audit contexts off. The encoder supports 8,192 positions, so use the
    // configured budget (8,192 by default) and reject a context that would not fit.
    agent.cfg.max_len = cfg.laya_max_tokens;
    let budget = check_token_budget(&context, agent.cfg.max_len, agent.cfg.head_max_len)?;
    if budget.is_close() {
        tracing::warn!(
            estimated_tokens = budget.estimated,
            available_tokens = budget.available,
            max_tokens = budget.max,
            "Laya audit context is close to the token limit"
        );
    }

    let response = agent
        .system_one(&Value::String(context), &questions)
        .map_err(|error| Error::LayaResponse(format!("Laya inference failed: {error}")))?;

    tracing::debug!(
        input_tokens = response.usage.input_tokens,
        max_tokens = agent.cfg.max_len,
        "Laya inference token usage"
    );

    decision_from_answers(&response.answers, summary.highest_severity)
}

/// The naive token budget check for one audit context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TokenBudget {
    estimated: usize,
    available: usize,
    max: usize,
}

impl TokenBudget {
    fn is_close(self) -> bool {
        self.estimated * 100 >= self.available * LAYA_TOKEN_WARN_PERCENT
    }
}

/// Estimate tokens without loading a tokenizer.
///
/// Laya's tokenizer splits pretty-printed JSON at roughly 2.8 bytes per token, so dividing by
/// three and adding a ten-percent safety margin keeps the estimate conservative for both JSON
/// and prose. It is a guard, not a replacement for the tokenizer's exact count.
fn estimate_tokens(text: &str) -> usize {
    let base = text.len().div_ceil(LAYA_BYTES_PER_TOKEN);
    base.saturating_add(base * LAYA_TOKEN_SAFETY_PERCENT / 100)
}

/// Reject a context that would be truncated by the sequence budget.
///
/// `head_max_len` is the checkpoint's cap for the typed question head, so subtracting it (plus
/// room for the surrounding special tokens) gives the state room available for the audit JSON.
fn check_token_budget(
    context: &str,
    max_tokens: usize,
    head_max_len: usize,
) -> Result<TokenBudget> {
    let reserved = head_max_len.saturating_add(LAYA_SPECIAL_TOKEN_RESERVE);
    let available = max_tokens.saturating_sub(reserved);
    if available == 0 {
        return Err(Error::LayaResponse(format!(
            "Laya token budget {max_tokens} leaves no room for the audit context after the \
             {reserved}-token question head; raise --laya-max-tokens"
        )));
    }

    let estimated = estimate_tokens(context);
    if estimated > available {
        return Err(Error::LayaResponse(format!(
            "audit context is too long for Laya: ~{estimated} tokens for a {available}-token \
             state budget ({max_tokens} total minus {reserved} for the question head); lower \
             --laya-max-chars or raise --laya-max-tokens (max {MAX_LAYA_MAX_TOKENS})"
        )));
    }

    Ok(TokenBudget {
        estimated,
        available,
        max: max_tokens,
    })
}

fn laya_questions() -> Vec<(String, Question)> {
    vec![
        (
            "notify".to_owned(),
            Question::choice(
                "Does this audit warrant notifying the on-call engineer?",
                ["true", "false"],
            ),
        ),
        (
            "severity".to_owned(),
            Question::choice(
                "What is the highest triage severity warranted by this audit?",
                ["info", "low", "medium", "high", "critical"],
            ),
        ),
    ]
}

fn decision_from_answers(
    answers: &Map<String, Value>,
    fallback: Severity,
) -> Result<ParsedDecision> {
    // A missing or unrecognized answer must not silently become `notify=false`: that would hide a
    // real alert. Returning an error lets the caller fall back to the deterministic heuristic.
    let notify_choice = choice_answer(answers, "notify").ok_or_else(|| {
        Error::LayaResponse("Laya did not answer the `notify` question".to_owned())
    })?;
    let notify = match notify_choice.trim().to_ascii_lowercase().as_str() {
        "true" => true,
        "false" => false,
        other => {
            return Err(Error::LayaResponse(format!(
                "Laya returned an unexpected `notify` answer `{other}`"
            )));
        }
    };
    let severity = choice_answer(answers, "severity")
        .and_then(parse_severity)
        .unwrap_or(fallback);
    let reason = if notify {
        format!("Laya recommends notification at {severity} severity.")
    } else {
        "Laya found no notification-worthy findings.".to_owned()
    };

    Ok(ParsedDecision {
        notify,
        severity,
        reason,
    })
}

fn choice_answer<'a>(answers: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    answers.get(key)?.get("choice")?.as_str()
}

fn call_openai(client: &reqwest::blocking::Client, cfg: &Config, prompt: &str) -> Result<String> {
    #[derive(Serialize)]
    struct Message<'a> {
        role: &'a str,
        content: &'a str,
    }

    #[derive(Serialize)]
    struct Request<'a> {
        model: &'a str,
        messages: Vec<Message<'a>>,
        temperature: f32,
        stream: bool,
    }

    #[derive(Deserialize)]
    struct MessageResponse {
        content: Option<String>,
    }

    #[derive(Deserialize)]
    struct Choice {
        message: MessageResponse,
    }

    #[derive(Deserialize)]
    struct Response {
        choices: Vec<Choice>,
    }

    let base = cfg.laya_url.trim_end_matches('/');
    let url = if base.ends_with("/v1") {
        format!("{base}/chat/completions")
    } else {
        format!("{base}/v1/chat/completions")
    };
    let request = Request {
        model: &cfg.laya_model,
        messages: vec![Message {
            role: "user",
            content: prompt,
        }],
        temperature: 0.0,
        stream: false,
    };
    let response: Response = post_json(client, &url, &request, cfg.laya_api_key.as_deref())?;
    response
        .choices
        .into_iter()
        .next()
        .and_then(|choice| choice.message.content)
        .filter(|content| !content.trim().is_empty())
        .ok_or_else(|| {
            Error::LayaResponse("OpenAI response contained no message content".to_owned())
        })
}

fn post_json<T: Serialize, R: for<'de> Deserialize<'de>>(
    client: &reqwest::blocking::Client,
    url: &str,
    body: &T,
    api_key: Option<&str>,
) -> Result<R> {
    let mut request = client.post(url).json(body);
    if let Some(key) = api_key {
        request = request.bearer_auth(key);
    }
    let response = request
        .send()
        .map_err(|error| Error::http(format!("request to {url} failed: {error}")))?;
    let status = response.status();
    let text = response
        .text()
        .map_err(|error| Error::http(format!("could not read response: {error}")))?;
    if !status.is_success() {
        return Err(Error::http(format!(
            "{url} returned {status}: {}",
            truncate(text.trim(), 1_000)
        )));
    }
    serde_json::from_str::<R>(&text)
        .map_err(|error| Error::LayaResponse(format!("invalid JSON from {url}: {error}")))
}

#[derive(Debug)]
struct ParsedDecision {
    notify: bool,
    severity: Severity,
    reason: String,
}

#[derive(Deserialize)]
struct RawDecision {
    notify: bool,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

fn parse_decision(raw: &str, fallback: Severity) -> Result<ParsedDecision> {
    let json = extract_json(raw);
    let raw: RawDecision = serde_json::from_str(json).map_err(|error| {
        Error::LayaResponse(format!(
            "model did not return the expected JSON object: {error}; response: {}",
            truncate(raw.trim(), 500)
        ))
    })?;
    let severity = raw
        .severity
        .as_deref()
        .and_then(parse_severity)
        .unwrap_or(fallback);
    let reason = raw
        .reason
        .map(|reason| reason.trim().to_owned())
        .filter(|reason| !reason.is_empty())
        .unwrap_or_else(|| "the local model did not provide a reason".to_owned());

    Ok(ParsedDecision {
        notify: raw.notify,
        severity,
        reason,
    })
}

fn parse_severity(value: &str) -> Option<Severity> {
    match value.trim().to_ascii_lowercase().as_str() {
        "info" | "informational" => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" | "moderate" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" | "crit" => Some(Severity::Critical),
        _ => None,
    }
}

fn extract_json(raw: &str) -> &str {
    let mut trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix("```json") {
        trimmed = rest;
    } else if let Some(rest) = trimmed.strip_prefix("```") {
        trimmed = rest;
    }
    if let Some(rest) = trimmed.strip_suffix("```") {
        trimmed = rest;
    }
    let trimmed = trimmed.trim();
    match (trimmed.find('{'), trimmed.rfind('}')) {
        (Some(start), Some(end)) if end >= start => &trimmed[start..=end],
        _ => trimmed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{AuditSummary, NotificationDecision, StageId, StageReport, StageStatus};
    use crate::test_support::serve_once;

    fn summary_with(stages: Vec<StageReport>) -> AuditSummary {
        crate::test_support::summary_with(stages, NotificationDecision::disabled("test"))
    }

    fn summary() -> AuditSummary {
        let mut stage = StageReport::new(StageId::Rootkit);
        stage.finding(Severity::High, "INFECTED: /tmp/evil");
        stage.finish(Some(StageStatus::Warnings));
        summary_with(vec![stage])
    }

    fn laya_config(url: String, api: LayaApi) -> Config {
        let mut cfg = crate::config::test_config();
        cfg.laya_enabled = true;
        cfg.laya_url = url;
        cfg.laya_api = api;
        cfg
    }

    #[test]
    fn prompt_template_keeps_the_openai_contract() {
        assert!(PROMPT_TEMPLATE.contains("You are a security triage assistant"));
        assert!(PROMPT_TEMPLATE.contains("{context}"));

        let cfg = laya_config("http://127.0.0.1:8080".into(), LayaApi::Openai);
        let prompt = build_prompt(&cfg, &summary());
        assert!(prompt.contains("\"host\": \"host\""));
        assert!(prompt.contains("\"notify\": true"));
        assert!(!prompt.contains("{context}"));
    }

    #[test]
    fn parses_fenced_json_and_uppercase_severity() {
        let raw = "```json\n{\"notify\": true, \"severity\": \"HIGH\", \"reason\": \"rootkit found\"}\n```";
        let parsed = parse_decision(raw, Severity::Info).unwrap();
        assert!(parsed.notify);
        assert_eq!(parsed.severity, Severity::High);
        assert_eq!(parsed.reason, "rootkit found");
    }

    #[test]
    fn falls_back_to_summary_severity() {
        let parsed = parse_decision(
            "{\"notify\": false, \"reason\": \"benign\"}",
            Severity::Medium,
        )
        .unwrap();
        assert!(!parsed.notify);
        assert_eq!(parsed.severity, Severity::Medium);
    }

    #[test]
    fn unknown_severity_and_blank_reason_use_defaults() {
        let parsed = parse_decision(
            "{\"notify\": true, \"severity\": \"urgent\", \"reason\": \"   \"}",
            Severity::Low,
        )
        .unwrap();
        assert!(parsed.notify);
        assert_eq!(parsed.severity, Severity::Low);
        assert_eq!(parsed.reason, "the local model did not provide a reason");

        let parsed = parse_decision("{\"notify\": false}", Severity::Critical).unwrap();
        assert_eq!(parsed.severity, Severity::Critical);
        assert_eq!(parsed.reason, "the local model did not provide a reason");
    }

    #[test]
    fn severity_aliases_are_recognized() {
        for (name, expected) in [
            ("info", Severity::Info),
            ("informational", Severity::Info),
            ("low", Severity::Low),
            ("medium", Severity::Medium),
            ("moderate", Severity::Medium),
            ("high", Severity::High),
            ("critical", Severity::Critical),
            ("crit", Severity::Critical),
        ] {
            assert_eq!(parse_severity(name), Some(expected), "alias {name}");
        }
        assert_eq!(parse_severity("  HIGH  "), Some(Severity::High));
        assert_eq!(parse_severity("severe"), None);
    }

    #[test]
    fn rejects_non_json_output() {
        assert!(parse_decision("I think you should notify", Severity::Info).is_err());
    }

    #[test]
    fn extracts_json_from_prose_fences_and_bare_braces() {
        assert_eq!(
            extract_json("```json\n{\"notify\":true}\n```"),
            "{\"notify\":true}"
        );
        assert_eq!(
            extract_json("```\n{\"notify\":true}\n```"),
            "{\"notify\":true}"
        );
        assert_eq!(
            extract_json("Here is my answer: {\"notify\":true} thanks"),
            "{\"notify\":true}"
        );
        assert_eq!(extract_json("  no braces here  "), "no braces here");
    }

    #[test]
    fn rejects_remote_endpoints_by_default() {
        assert!(validate_endpoint("http://192.168.1.10:8080", false).is_err());
        assert!(validate_endpoint("http://192.168.1.10:8080", true).is_ok());
    }

    #[test]
    fn accepts_loopback_endpoints() {
        assert!(validate_endpoint("http://127.0.0.1:8080", false).is_ok());
        assert!(validate_endpoint("http://localhost:8080", false).is_ok());
        assert!(validate_endpoint("http://[::1]:8080", false).is_ok());
        assert!(validate_endpoint("http://triage.localhost:8080", false).is_ok());
    }

    #[test]
    fn rejects_invalid_schemes_hosts_and_urls() {
        assert!(validate_endpoint("ftp://127.0.0.1:8080", false).is_err());
        assert!(validate_endpoint("http:///missing-host", false).is_err());
        assert!(validate_endpoint("not a url", false).is_err());
    }

    #[test]
    fn local_questions_use_typed_choice_labels() {
        let questions = laya_questions();
        assert_eq!(questions.len(), 2);

        let (id, question) = &questions[0];
        assert_eq!(id, "notify");
        assert_eq!(question.qtype, laya_inference::QType::Choice);
        assert_eq!(
            question.render_options().unwrap(),
            vec!["true".to_owned(), "false".to_owned()]
        );

        let (id, question) = &questions[1];
        assert_eq!(id, "severity");
        assert_eq!(
            question.render_options().unwrap(),
            vec![
                "info".to_owned(),
                "low".to_owned(),
                "medium".to_owned(),
                "high".to_owned(),
                "critical".to_owned()
            ]
        );
    }

    #[test]
    fn dataset_questions_match_the_runtime_contract() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("laya-dataset/data/questions.json");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
        let documented: Value = serde_json::from_str(&text)
            .unwrap_or_else(|error| panic!("{} is not valid JSON: {error}", path.display()));

        let mut runtime = Map::new();
        for (id, question) in laya_questions() {
            runtime.insert(
                id,
                serde_json::to_value(question).expect("question is serializable"),
            );
        }

        assert_eq!(
            documented,
            Value::Object(runtime),
            "{} is out of sync with laya_questions(); run laya-dataset/tools/build_dataset.py",
            path.display()
        );
    }

    #[test]
    fn local_answers_are_parsed_into_a_decision() {
        let answers = serde_json::json!({
            "notify": {"type": "choice", "choice": "TRUE"},
            "severity": {"type": "choice", "choice": "HIGH"}
        });
        let decision = decision_from_answers(answers.as_object().unwrap(), Severity::Low).unwrap();
        assert!(decision.notify);
        assert_eq!(decision.severity, Severity::High);
        assert!(decision.reason.contains("high"));
    }

    #[test]
    fn local_answers_fall_back_when_the_model_is_uncertain() {
        let answers = serde_json::json!({
            "notify": {"type": "choice", "choice": "false"},
            "severity": {"type": "choice", "choice": "unexpected"}
        });
        let decision =
            decision_from_answers(answers.as_object().unwrap(), Severity::Medium).unwrap();
        assert!(!decision.notify);
        assert_eq!(decision.severity, Severity::Medium);
        assert!(decision.reason.contains("no notification-worthy findings"));
    }

    #[test]
    fn local_answers_require_a_valid_notify_choice() {
        let missing = serde_json::json!({
            "severity": {"type": "choice", "choice": "high"}
        });
        let error = decision_from_answers(missing.as_object().unwrap(), Severity::High)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("did not answer the `notify` question"),
            "{error}"
        );

        let unexpected = serde_json::json!({
            "notify": {"type": "choice", "choice": "maybe"}
        });
        let error = decision_from_answers(unexpected.as_object().unwrap(), Severity::High)
            .unwrap_err()
            .to_string();
        assert!(error.contains("unexpected `notify` answer"), "{error}");
    }

    #[test]
    fn local_backend_reports_a_clear_missing_checkpoint_error() {
        let mut cfg = laya_config("http://192.168.1.10:8080".into(), LayaApi::Laya);
        cfg.laya_model = "/definitely/missing/laya-checkpoint".into();

        let error = assess(&cfg, &summary()).unwrap_err().to_string();
        assert!(
            error.contains("could not load the Laya checkpoint"),
            "{error}"
        );
        // The in-process backend must not apply the server endpoint policy.
        assert!(!error.contains("non-loopback"), "{error}");
    }

    #[test]
    fn token_estimate_stays_above_a_chars_per_four_guess() {
        assert_eq!(estimate_tokens(""), 0);
        assert!(estimate_tokens("abcd") >= 1);

        let context = r#"{"host":"audit-host","findings":[{"severity":"high","message":"x"}]}"#;
        assert!(
            estimate_tokens(context) > context.len() / 4,
            "the guard must not assume four bytes per JSON token"
        );
    }

    #[test]
    fn token_budget_rejects_a_context_that_would_be_truncated() {
        let context = "x".repeat(3_000);
        let error = check_token_budget(&context, 1_024, 256)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("audit context is too long for Laya"),
            "{error}"
        );
        assert!(error.contains("--laya-max-chars"), "{error}");
        assert!(error.contains("--laya-max-tokens"), "{error}");
    }

    #[test]
    fn token_budget_warns_only_near_the_limit() {
        let context = "x".repeat(1_000);
        assert!(!check_token_budget(&context, 8_192, 256).unwrap().is_close());
        assert!(!check_token_budget(&context, 512, 64).unwrap().is_close());
        assert!(check_token_budget(&context, 448, 64).unwrap().is_close());
    }

    #[test]
    fn token_budget_rejects_a_head_larger_than_the_sequence() {
        assert!(check_token_budget("context", 300, 300).is_err());
    }

    #[test]
    fn default_context_budget_fits_the_default_window() {
        let max_context =
            "x".repeat(crate::constants::DEFAULT_LAYA_MAX_CHARS + "\n[context truncated]".len());
        let budget =
            check_token_budget(&max_context, crate::constants::DEFAULT_LAYA_MAX_TOKENS, 256)
                .unwrap();
        assert!(budget.estimated <= budget.available);
    }

    #[test]
    fn context_caps_findings_and_truncates_long_payloads() {
        let mut stage = StageReport::new(StageId::Rootkit);
        for index in 0..(MAX_FINDINGS_IN_CONTEXT + 5) {
            stage.finding(Severity::Low, format!("finding {index}"));
        }
        stage.finish(Some(StageStatus::Warnings));
        let summary = summary_with(vec![stage]);

        let context: serde_json::Value =
            serde_json::from_str(&build_context(&summary, usize::MAX)).unwrap();
        assert_eq!(
            context["findings"].as_array().unwrap().len(),
            MAX_FINDINGS_IN_CONTEXT
        );

        let truncated = build_context(&summary, 40);
        assert!(truncated.ends_with("[context truncated]"));
        assert!(truncated.len() <= 40 + "\n[context truncated]".len());
    }

    #[test]
    fn prompt_describes_the_rules_and_embeds_the_context() {
        let cfg = laya_config("http://127.0.0.1:8080".into(), LayaApi::Openai);
        let prompt = build_prompt(&cfg, &summary());
        assert!(prompt.contains("security triage assistant"));
        assert!(prompt.contains("Debian or Ubuntu host"));
        assert!(prompt.contains("exposed AWS credentials"));
        assert!(prompt.contains("IMDSv1"));
        assert!(prompt.contains("Audit context:"));
        assert!(prompt.contains("host"));
        assert!(prompt.contains("INFECTED"));
    }

    #[test]
    fn openai_decisions_are_parsed_into_an_assessment() {
        let raw = serde_json::json!({
            "choices": [{
                "message": {
                    "content": "{\"notify\": false, \"severity\": \"low\", \"reason\": \"benign\"}"
                }
            }]
        })
        .to_string();
        let (base, server) = serve_once("200 OK", &raw);
        let cfg = laya_config(format!("{base}/v1"), LayaApi::Openai);

        let assessment = assess(&cfg, &summary()).unwrap();
        assert_eq!(assessment.api, "openai");
        assert!(!assessment.notify);
        assert_eq!(assessment.severity, Severity::Low);
        assert_eq!(assessment.reason, "benign");

        let request = server.join().unwrap();
        assert!(request.starts_with("POST /v1/chat/completions"));
        assert!(request.contains("\"role\":\"user\""));
    }

    #[test]
    fn openai_adds_the_v1_prefix_when_missing() {
        let raw = serde_json::json!({
            "choices": [{"message": {"content": "{\"notify\": true}"}}]
        })
        .to_string();
        let (base, server) = serve_once("200 OK", &raw);
        let cfg = laya_config(base, LayaApi::Openai);

        assess(&cfg, &summary()).unwrap();
        let request = server.join().unwrap();
        assert!(request.starts_with("POST /v1/chat/completions"));
    }

    #[test]
    fn http_errors_include_the_status_and_body() {
        let (base, server) = serve_once("500 Internal Server Error", "model is down");
        let cfg = laya_config(base, LayaApi::Openai);

        let error = assess(&cfg, &summary()).unwrap_err().to_string();
        assert!(error.contains("returned 500"));
        assert!(error.contains("model is down"));
        server.join().unwrap();
    }

    #[test]
    fn malformed_and_empty_responses_are_rejected() {
        let (base, server) = serve_once("200 OK", "not-json");
        let cfg = laya_config(base, LayaApi::Openai);
        assert!(assess(&cfg, &summary()).is_err());
        server.join().unwrap();

        let (base, server) = serve_once("200 OK", "{\"choices\":[]}");
        let cfg = laya_config(base, LayaApi::Openai);
        let error = assess(&cfg, &summary()).unwrap_err().to_string();
        assert!(error.contains("no message content"));
        server.join().unwrap();

        let (base, server) = serve_once(
            "200 OK",
            "{\"choices\":[{\"message\":{\"content\":\"   \"}}]}",
        );
        let cfg = laya_config(base, LayaApi::Openai);
        assert!(assess(&cfg, &summary()).is_err());
        server.join().unwrap();
    }
}
