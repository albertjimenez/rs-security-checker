//! Serializable audit model: severities, findings, stage reports and the final summary.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Maximum number of structured findings kept per stage. The full artifact is always kept on disk.
const MAX_FINDINGS_PER_STAGE: usize = 200;
/// Maximum number of output bytes copied into the JSON summary.
const EXCERPT_BYTES: usize = 8 * 1024;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
#[value(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const ALL: [Self; 5] = [
        Self::Info,
        Self::Low,
        Self::Medium,
        Self::High,
        Self::Critical,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub const fn rank(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }

    pub fn at_least(self, threshold: Self) -> bool {
        self.rank() >= threshold.rank()
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    clap::ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum StageId {
    Precheck,
    Docker,
    Clamav,
    Debsums,
    Rootkit,
    Persistence,
    Network,
    Web,
    Auth,
    Hardening,
    Aws,
}

impl StageId {
    pub const ALL: [Self; 11] = [
        Self::Precheck,
        Self::Docker,
        Self::Clamav,
        Self::Debsums,
        Self::Rootkit,
        Self::Persistence,
        Self::Network,
        Self::Web,
        Self::Auth,
        Self::Hardening,
        Self::Aws,
    ];

    pub const fn title(self) -> &'static str {
        match self {
            Self::Precheck => "Precheck & Dependencies",
            Self::Docker => "Docker Security Audit",
            Self::Clamav => "ClamAV Scan",
            Self::Debsums => "Debsums Integrity",
            Self::Rootkit => "Rootkit Audits",
            Self::Persistence => "Persistence & Account Audit",
            Self::Network => "Network Sockets & Pending Patches",
            Self::Web => "Web Server Logs",
            Self::Auth => "Authentication Logs",
            Self::Hardening => "Host Hardening",
            Self::Aws => "AWS Host & Metadata",
        }
    }

    /// Stable CLI/value name (`--only`, `--skip`, JSON ids).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Precheck => "precheck",
            Self::Docker => "docker",
            Self::Clamav => "clamav",
            Self::Debsums => "debsums",
            Self::Rootkit => "rootkit",
            Self::Persistence => "persistence",
            Self::Network => "network",
            Self::Web => "web",
            Self::Auth => "auth",
            Self::Hardening => "hardening",
            Self::Aws => "aws",
        }
    }

    /// Artifact filename used by the original Jenkins pipeline (`archiveArtifacts`).
    pub const fn artifact(self) -> Option<&'static str> {
        match self {
            Self::Precheck => None,
            Self::Docker => Some("docker-audit-report.txt"),
            Self::Clamav => Some("clamav-report.txt"),
            Self::Debsums => Some("debsums-report.txt"),
            Self::Rootkit => Some("rootkit-report.txt"),
            Self::Persistence => Some("persistence-report.txt"),
            Self::Network => Some("network-updates-report.txt"),
            Self::Web => Some("web-logs-report.txt"),
            Self::Auth => Some("auth-logs-report.txt"),
            Self::Hardening => Some("hardening-report.txt"),
            Self::Aws => Some("aws-report.txt"),
        }
    }

    /// Whether this stage is cheap enough to run alongside other analysis stages.
    ///
    /// ClamAV, rootkit scans, package integrity checks and package-manager operations stay serial
    /// because they are CPU-, disk- or lock-intensive. Log parsing, host configuration inspection
    /// and metadata lookups can overlap safely.
    pub const fn is_parallel_safe(self) -> bool {
        matches!(self, Self::Web | Self::Auth | Self::Hardening | Self::Aws)
    }
}

impl fmt::Display for StageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.title())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageStatus {
    Passed,
    Warnings,
    Failed,
    Skipped,
    TimedOut,
}

impl StageStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Warnings => "warnings",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
            Self::TimedOut => "timed_out",
        }
    }

    pub const fn is_bad(self) -> bool {
        matches!(self, Self::Failed | Self::TimedOut)
    }
}

impl fmt::Display for StageStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageReport {
    pub id: StageId,
    pub title: String,
    pub status: StageStatus,
    pub started_at: String,
    pub duration_ms: u64,
    pub findings: Vec<Finding>,
    pub notes: Vec<String>,
    pub artifact: Option<String>,
    /// Short, JSON-friendly preview of the artifact.
    pub excerpt: String,
    /// Full artifact text. Not serialized into the summary to keep it small.
    #[serde(skip)]
    pub output: String,
    #[serde(skip)]
    findings_truncated: bool,
}

impl StageReport {
    pub fn new(id: StageId) -> Self {
        Self {
            id,
            title: id.title().to_owned(),
            status: StageStatus::Passed,
            started_at: now_rfc3339(),
            duration_ms: 0,
            findings: Vec::new(),
            notes: Vec::new(),
            artifact: id.artifact().map(str::to_owned),
            excerpt: String::new(),
            output: String::new(),
            findings_truncated: false,
        }
    }

    pub fn note(&mut self, message: impl Into<String>) {
        self.notes.push(message.into());
    }

    pub fn finding(&mut self, severity: Severity, message: impl Into<String>) {
        if self.findings.len() < MAX_FINDINGS_PER_STAGE {
            self.findings.push(Finding {
                severity,
                message: message.into(),
            });
        } else if !self.findings_truncated {
            self.findings_truncated = true;
            self.notes.push(format!(
                "additional findings were truncated at {MAX_FINDINGS_PER_STAGE}; see the artifact for the full output"
            ));
        }
    }

    pub fn finish(&mut self, forced: Option<StageStatus>) {
        self.status = forced.unwrap_or_else(|| {
            if self.highest_severity().at_least(Severity::Low) {
                StageStatus::Warnings
            } else {
                StageStatus::Passed
            }
        });
        self.excerpt = truncate_chars(&self.output, EXCERPT_BYTES);
    }

    /// Set the wall-clock duration and refresh the JSON excerpt after the stage completed.
    pub fn finalize(&mut self, duration: std::time::Duration) {
        self.duration_ms = duration.as_millis() as u64;
        self.excerpt = truncate_chars(&self.output, EXCERPT_BYTES);
    }

    pub fn highest_severity(&self) -> Severity {
        self.findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Info)
    }

    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }

    pub fn push_header(&mut self, title: &str) {
        if !self.output.is_empty() {
            self.output.push('\n');
        }
        self.output.push_str(title);
        self.output.push('\n');
    }

    pub fn push_block(&mut self, text: &str, when_empty: &str) {
        let text = text.trim_end_matches(['\r', '\n']);
        if text.trim().is_empty() {
            self.output.push_str(when_empty);
            self.output.push('\n');
        } else {
            self.output.push_str(text);
            self.output.push('\n');
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
    pub laya_compiled: bool,
    pub notifications_compiled: bool,
}

impl ToolInfo {
    pub fn current() -> Self {
        Self {
            name: env!("CARGO_PKG_NAME").to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            laya_compiled: cfg!(feature = "laya"),
            notifications_compiled: cfg!(feature = "notifications"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DecisionSource {
    #[default]
    Disabled,
    Heuristic,
    Laya,
}

impl fmt::Display for DecisionSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => f.write_str("disabled"),
            Self::Heuristic => f.write_str("heuristic"),
            Self::Laya => f.write_str("laya"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NotificationDecision {
    pub notify: bool,
    pub reason: String,
    pub source: DecisionSource,
}

impl NotificationDecision {
    pub fn disabled(reason: impl Into<String>) -> Self {
        Self {
            notify: false,
            reason: reason.into(),
            source: DecisionSource::Disabled,
        }
    }

    pub fn heuristic(notify: bool, reason: impl Into<String>) -> Self {
        Self {
            notify,
            reason: reason.into(),
            source: DecisionSource::Heuristic,
        }
    }

    #[cfg_attr(not(feature = "laya"), allow(dead_code))]
    pub fn laya(notify: bool, reason: impl Into<String>) -> Self {
        Self {
            notify,
            reason: reason.into(),
            source: DecisionSource::Laya,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelFailure {
    pub channel: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NotificationOutcome {
    pub enabled: bool,
    pub attempted: bool,
    pub delivered: Vec<String>,
    pub failed: Vec<ChannelFailure>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayaAssessment {
    pub endpoint: String,
    pub api: String,
    pub model: String,
    pub notify: bool,
    pub severity: Severity,
    pub reason: String,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSummary {
    pub tool: ToolInfo,
    pub host: String,
    pub started_at: String,
    pub finished_at: String,
    pub duration_ms: u64,
    pub output_dir: String,
    pub stages: Vec<StageReport>,
    pub highest_severity: Severity,
    pub finding_counts: BTreeMap<String, usize>,
    pub total_findings: usize,
    pub notification: NotificationOutcome,
    pub notification_decision: NotificationDecision,
    pub laya: Option<LayaAssessment>,
    pub laya_error: Option<String>,
    pub exit_code: i32,
}

impl AuditSummary {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host: String,
        started_at: String,
        finished_at: String,
        duration_ms: u64,
        output_dir: String,
        stages: Vec<StageReport>,
        notification: NotificationOutcome,
        notification_decision: NotificationDecision,
        laya: Option<LayaAssessment>,
        laya_error: Option<String>,
        exit_code: i32,
    ) -> Self {
        let mut finding_counts = BTreeMap::new();
        for severity in Severity::ALL {
            finding_counts.insert(severity.as_str().to_owned(), 0);
        }
        let mut highest = Severity::Info;
        let mut total = 0;
        for stage in &stages {
            for finding in &stage.findings {
                total += 1;
                highest = highest.max(finding.severity);
                *finding_counts
                    .entry(finding.severity.as_str().to_owned())
                    .or_insert(0) += 1;
            }
        }

        Self {
            tool: ToolInfo::current(),
            host,
            started_at,
            finished_at,
            duration_ms,
            output_dir,
            stages,
            highest_severity: highest,
            finding_counts,
            total_findings: total,
            notification,
            notification_decision,
            laya,
            laya_error,
            exit_code,
        }
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn markdown(&self) -> String {
        use std::fmt::Write as _;

        let mut out = String::new();
        out.push_str("# Security Audit Summary\n\n");
        let _ = writeln!(out, "- **Host:** `{}`", self.host);
        let _ = writeln!(
            out,
            "- **Tool:** `{} {}`",
            self.tool.name, self.tool.version
        );
        let _ = writeln!(
            out,
            "- **Features:** laya=`{}`, notifications=`{}`",
            self.tool.laya_compiled, self.tool.notifications_compiled
        );
        let _ = writeln!(out, "- **Started:** {}", self.started_at);
        let _ = writeln!(out, "- **Finished:** {}", self.finished_at);
        let _ = writeln!(out, "- **Duration:** {} ms", self.duration_ms);
        let _ = writeln!(out, "- **Highest severity:** `{}`", self.highest_severity);
        let _ = writeln!(out, "- **Findings:** {}", self.total_findings);
        let _ = writeln!(out, "- **Output directory:** `{}`", self.output_dir);
        let _ = writeln!(
            out,
            "- **Notification decision:** `{}` via `{}` ({})",
            if self.notification_decision.notify {
                "notify"
            } else {
                "skip"
            },
            self.notification_decision.source,
            self.notification_decision.reason
        );

        out.push_str("\n## Stages\n\n");
        out.push_str("| Stage | Status | Severity | Findings | Duration | Artifact |\n");
        out.push_str("|---|---|---|---:|---:|---|\n");
        for stage in &self.stages {
            let _ = writeln!(
                out,
                "| {} | `{}` | `{}` | {} | {} ms | {} |",
                stage.title,
                stage.status,
                stage.highest_severity(),
                stage.finding_count(),
                stage.duration_ms,
                stage.artifact.as_deref().unwrap_or("-")
            );
        }

        out.push_str("\n## Findings\n\n");
        if self.total_findings == 0 {
            out.push_str("No findings.\n");
        } else {
            for stage in &self.stages {
                if stage.findings.is_empty() {
                    continue;
                }
                let _ = writeln!(out, "### {}\n", stage.title);
                for finding in &stage.findings {
                    let _ = writeln!(
                        out,
                        "- **{}** {}",
                        finding.severity.as_str().to_uppercase(),
                        finding.message
                    );
                }
                out.push('\n');
            }
        }

        if let Some(laya) = &self.laya {
            out.push_str("\n## Local model triage (laya)\n\n");
            let _ = writeln!(out, "- **Endpoint:** `{}`", laya.endpoint);
            let _ = writeln!(out, "- **API / model:** `{}` / `{}`", laya.api, laya.model);
            let _ = writeln!(out, "- **Notify:** `{}`", laya.notify);
            let _ = writeln!(out, "- **Severity:** `{}`", laya.severity);
            let _ = writeln!(out, "- **Reason:** {}", laya.reason);
            let _ = writeln!(out, "- **Latency:** {} ms", laya.latency_ms);
        }
        if let Some(err) = &self.laya_error {
            let _ = writeln!(out, "\n> laya error: {err}");
        }

        out.push_str("\n## Notifications\n\n");
        if !self.notification.enabled {
            out.push_str("Notifications are disabled.\n");
        } else {
            let _ = writeln!(out, "- **Attempted:** {}", self.notification.attempted);
            let _ = writeln!(
                out,
                "- **Delivered:** {}",
                if self.notification.delivered.is_empty() {
                    "none".to_owned()
                } else {
                    self.notification.delivered.join(", ")
                }
            );
            for failure in &self.notification.failed {
                let _ = writeln!(
                    out,
                    "- **Failed:** `{}`: {}",
                    failure.channel, failure.error
                );
            }
            if let Some(error) = &self.notification.error {
                let _ = writeln!(out, "- **Error:** {error}");
            }
        }

        out
    }
}

pub fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".to_owned())
}

pub fn truncate_chars(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let mut truncated = crate::text::truncate(text, max_bytes).to_owned();
    truncated.push_str("\n[truncated]");
    truncated
}

/// Render finding counts as `critical=1, high=2` for CLI output and notifications.
pub fn format_finding_counts(counts: &BTreeMap<String, usize>) -> String {
    counts
        .iter()
        .map(|(severity, count)| format!("{severity}={count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(id: StageId, severity: Severity, message: &str) -> StageReport {
        let mut report = StageReport::new(id);
        report.finding(severity, message);
        report.finish(None);
        report
    }

    fn summary_with(stages: Vec<StageReport>) -> AuditSummary {
        AuditSummary::new(
            "host".into(),
            "start".into(),
            "end".into(),
            1,
            ".".into(),
            stages,
            NotificationOutcome::default(),
            NotificationDecision::disabled("test"),
            None,
            None,
            0,
        )
    }

    #[test]
    fn severity_ordering_is_stable() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High.at_least(Severity::High));
        assert!(!Severity::Medium.at_least(Severity::High));
    }

    #[test]
    fn severity_metadata_is_complete() {
        let names = Severity::ALL.map(Severity::as_str);
        assert_eq!(names, ["info", "low", "medium", "high", "critical"]);
        for severity in Severity::ALL {
            assert_eq!(severity.to_string(), severity.as_str());
        }
        assert_eq!(Severity::Info.rank(), 0);
        assert_eq!(Severity::Critical.rank(), 4);
    }

    #[test]
    fn stage_metadata_is_complete() {
        for stage in StageId::ALL {
            assert!(!stage.title().is_empty());
            assert!(!stage.as_str().is_empty());
            assert_eq!(stage.to_string(), stage.title());
        }
        assert_eq!(StageId::Precheck.artifact(), None);
        assert_eq!(StageId::Docker.artifact(), Some("docker-audit-report.txt"));
        assert_eq!(StageId::Clamav.artifact(), Some("clamav-report.txt"));
        assert_eq!(StageId::Debsums.artifact(), Some("debsums-report.txt"));
        assert_eq!(StageId::Rootkit.artifact(), Some("rootkit-report.txt"));
        assert_eq!(
            StageId::Persistence.artifact(),
            Some("persistence-report.txt")
        );
        assert_eq!(
            StageId::Network.artifact(),
            Some("network-updates-report.txt")
        );
        assert_eq!(StageId::Web.artifact(), Some("web-logs-report.txt"));
        assert_eq!(StageId::Auth.artifact(), Some("auth-logs-report.txt"));
        assert_eq!(StageId::Hardening.artifact(), Some("hardening-report.txt"));
        assert_eq!(StageId::Aws.artifact(), Some("aws-report.txt"));
    }

    #[test]
    fn only_lightweight_analysis_stages_are_parallel_safe() {
        for stage in StageId::ALL {
            let expected = matches!(
                stage,
                StageId::Web | StageId::Auth | StageId::Hardening | StageId::Aws
            );
            assert_eq!(stage.is_parallel_safe(), expected, "{stage:?}");
        }
    }

    #[test]
    fn stage_status_metadata_is_complete() {
        assert_eq!(StageStatus::Passed.as_str(), "passed");
        assert_eq!(StageStatus::Warnings.as_str(), "warnings");
        assert_eq!(StageStatus::Failed.as_str(), "failed");
        assert_eq!(StageStatus::Skipped.as_str(), "skipped");
        assert_eq!(StageStatus::TimedOut.as_str(), "timed_out");
        assert!(!StageStatus::Passed.is_bad());
        assert!(!StageStatus::Warnings.is_bad());
        assert!(!StageStatus::Skipped.is_bad());
        assert!(StageStatus::Failed.is_bad());
        assert!(StageStatus::TimedOut.is_bad());
        assert_eq!(StageStatus::Warnings.to_string(), "warnings");
    }

    #[test]
    fn stage_report_marks_warnings_for_findings() {
        let mut report = StageReport::new(StageId::Docker);
        report.finding(Severity::High, "privileged container");
        report.finish(None);
        assert_eq!(report.status, StageStatus::Warnings);
        assert_eq!(report.highest_severity(), Severity::High);
    }

    #[test]
    fn stage_report_passes_without_findings() {
        let mut report = StageReport::new(StageId::Debsums);
        report.finish(None);
        assert_eq!(report.status, StageStatus::Passed);
        assert_eq!(report.highest_severity(), Severity::Info);
        assert_eq!(report.finding_count(), 0);
    }

    #[test]
    fn stage_report_supports_notes_headers_and_blocks() {
        let mut report = StageReport::new(StageId::Rootkit);
        report.note("note");
        report.push_header("header");
        report.push_block("  body  \n", "empty");
        report.push_block("   ", "empty");
        assert_eq!(report.output, "header\n  body  \nempty\n");
        assert_eq!(report.notes, vec!["note"]);
    }

    #[test]
    fn stage_report_truncates_excess_findings() {
        let mut report = StageReport::new(StageId::Rootkit);
        for index in 0..MAX_FINDINGS_PER_STAGE + 5 {
            report.finding(Severity::Low, format!("finding {index}"));
        }
        assert_eq!(report.finding_count(), MAX_FINDINGS_PER_STAGE);
        assert!(report.notes.iter().any(|note| note.contains("truncated")));
    }

    #[test]
    fn finalize_updates_duration_and_excerpt() {
        let mut report = StageReport::new(StageId::Docker);
        report.output = "x".repeat(EXCERPT_BYTES + 10);
        report.finalize(std::time::Duration::from_millis(12));
        assert_eq!(report.duration_ms, 12);
        assert!(report.excerpt.len() <= EXCERPT_BYTES + 32);
        assert!(report.excerpt.ends_with("[truncated]"));
    }

    #[test]
    fn truncation_respects_utf8_boundaries() {
        let text = "a".repeat(10) + "é";
        let truncated = truncate_chars(&text, 11);
        assert!(truncated.is_char_boundary(truncated.len()));
        assert!(truncated.ends_with("[truncated]"));
        assert_eq!(truncate_chars("short", 100), "short");
    }

    #[test]
    fn tool_info_reports_compiled_features() {
        let info = ToolInfo::current();
        assert_eq!(info.name, env!("CARGO_PKG_NAME"));
        assert_eq!(info.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(info.laya_compiled, cfg!(feature = "laya"));
        assert_eq!(info.notifications_compiled, cfg!(feature = "notifications"));
    }

    #[test]
    fn decision_sources_render() {
        assert_eq!(DecisionSource::Disabled.to_string(), "disabled");
        assert_eq!(DecisionSource::Heuristic.to_string(), "heuristic");
        assert_eq!(DecisionSource::Laya.to_string(), "laya");
    }

    #[test]
    fn decision_constructors_set_the_source() {
        let disabled = NotificationDecision::disabled("off");
        assert_eq!(disabled.source, DecisionSource::Disabled);
        assert!(!disabled.notify);

        let heuristic = NotificationDecision::heuristic(true, "threshold");
        assert_eq!(heuristic.source, DecisionSource::Heuristic);
        assert!(heuristic.notify);

        let laya = NotificationDecision::laya(false, "veto");
        assert_eq!(laya.source, DecisionSource::Laya);
        assert!(!laya.notify);
    }

    #[test]
    fn summary_counts_findings() {
        let a = report(StageId::Docker, Severity::High, "one");
        let mut b = StageReport::new(StageId::Rootkit);
        b.finding(Severity::Critical, "two");
        b.finding(Severity::High, "three");
        b.finish(None);

        let summary = summary_with(vec![a, b]);
        assert_eq!(summary.total_findings, 3);
        assert_eq!(summary.highest_severity, Severity::Critical);
        assert_eq!(summary.finding_counts["high"], 2);
        assert_eq!(summary.finding_counts["critical"], 1);
        assert_eq!(summary.finding_counts["info"], 0);
    }

    #[test]
    fn summary_json_round_trips() {
        let summary = summary_with(vec![report(StageId::Docker, Severity::High, "one")]);
        let json = summary.to_json().unwrap();
        let parsed: AuditSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_findings, 1);
        assert_eq!(parsed.stages.len(), 1);
        assert_eq!(parsed.stages[0].id, StageId::Docker);
    }

    #[test]
    fn summary_markdown_includes_findings_and_integrations() {
        let mut summary = summary_with(vec![
            report(StageId::Docker, Severity::High, "privileged container"),
            report(StageId::Clamav, Severity::Critical, "malware found"),
        ]);
        summary.laya = Some(crate::test_support::laya_assessment(
            Severity::High,
            "malware",
        ));
        summary.laya_error = Some("prior error".into());
        summary.notification = NotificationOutcome {
            enabled: true,
            attempted: true,
            delivered: vec!["slack".into()],
            failed: vec![ChannelFailure {
                channel: "telegram".into(),
                error: "timeout".into(),
            }],
            error: Some("one channel failed".into()),
        };
        summary.notification_decision = NotificationDecision::heuristic(true, "threshold met");

        let markdown = summary.markdown();
        assert!(markdown.contains("# Security Audit Summary"));
        assert!(markdown.contains("Docker Security Audit"));
        assert!(markdown.contains("privileged container"));
        assert!(markdown.contains("Local model triage"));
        assert!(markdown.contains("prior error"));
        assert!(markdown.contains("Delivered:** slack"));
        assert!(markdown.contains("telegram"));
        assert!(markdown.contains("one channel failed"));
        assert!(markdown.contains("threshold met"));
    }

    #[test]
    fn summary_markdown_handles_empty_and_disabled_cases() {
        let mut summary = summary_with(Vec::new());
        summary.notification_decision = NotificationDecision::disabled("notifications are off");
        let markdown = summary.markdown();
        assert!(markdown.contains("No findings."));
        assert!(markdown.contains("Notifications are disabled."));
        assert!(markdown.contains("notifications are off"));
    }

    #[test]
    fn timestamps_are_rfc3339() {
        let timestamp = now_rfc3339();
        assert!(timestamp.contains('T'));
        assert!(timestamp.ends_with('Z'));
    }
}
