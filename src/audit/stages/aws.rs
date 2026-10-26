//! AWS host and EC2 metadata security audit.
//!
//! Ubuntu/Debian hosts on EC2 have a few attack paths that generic hardening checks miss:
//! IMDSv1 credential theft from SSRF, long-term AWS keys left on disk, secrets embedded in
//! cloud-init user-data, and inactive AWS agents. This stage inspects those locally and only
//! queries the link-local metadata service; it never calls the AWS APIs and never prints secrets.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use crate::audit::StageContext;
use crate::exec::Cmd;
use crate::fsutil::read_limited;
use crate::report::{Severity, StageId, StageReport, StageStatus};
use crate::text::{for_each_key_value, truncate_with_ellipsis};

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_CREDENTIAL_FILES: usize = 64;
const MAX_PROFILE_FILES: usize = 32;

use crate::constants::{AWS_METADATA_ROOT, IMDS_TOKEN_TTL_SECONDS};

const METADATA_ROOT: &str = AWS_METADATA_ROOT;
/// Short, fixed curl options: the metadata service is link-local and must never go through a proxy.
const CURL_ARGS: [&str; 8] = [
    "-sS",
    "-f",
    "--noproxy",
    "*",
    "--connect-timeout",
    "1",
    "--max-time",
    "2",
];

/// Locations inspected by this stage. Tests replace them with a temporary tree.
struct AwsPaths {
    os_release: PathBuf,
    user_data: Vec<PathBuf>,
    home_roots: Vec<PathBuf>,
    env_files: Vec<PathBuf>,
    profile_dir: PathBuf,
    ecs_config: PathBuf,
    metadata_root: String,
}

impl Default for AwsPaths {
    fn default() -> Self {
        let mut home_roots = vec![PathBuf::from("/root"), PathBuf::from("/home")];
        if let Some(home) = std::env::var_os("HOME") {
            let home = PathBuf::from(home);
            if !home_roots.contains(&home) {
                home_roots.push(home);
            }
        }
        Self {
            os_release: PathBuf::from("/etc/os-release"),
            user_data: vec![PathBuf::from("/var/lib/cloud/instance/user-data.txt")],
            home_roots,
            env_files: vec![PathBuf::from("/etc/environment")],
            profile_dir: PathBuf::from("/etc/profile.d"),
            ecs_config: PathBuf::from("/etc/ecs/ecs.config"),
            metadata_root: METADATA_ROOT.to_owned(),
        }
    }
}

pub fn run(ctx: &StageContext<'_>) -> StageReport {
    run_with_paths(ctx, &AwsPaths::default())
}

fn run_with_paths(ctx: &StageContext<'_>, paths: &AwsPaths) -> StageReport {
    let mut report = StageReport::new(StageId::Aws);

    report.push_header("=== OPERATING SYSTEM ===");
    check_os(paths, &mut report);

    report.push_header("=== EC2 INSTANCE METADATA (IMDS) ===");
    let mut timed_out = check_metadata(ctx, paths, &mut report);

    report.push_header("=== AWS CREDENTIAL EXPOSURE ===");
    check_credentials(paths, &mut report);

    report.push_header("=== AWS AGENTS & TIME SYNC ===");
    timed_out |= check_services(ctx, &paths.ecs_config, &mut report);

    if ctx.expired() {
        timed_out = true;
        report.finding(
            Severity::Medium,
            "AWS host audit reached the global deadline before completing",
        );
    }

    if timed_out {
        report.finish(Some(StageStatus::TimedOut));
    } else {
        report.finish(None);
    }
    report
}

// ---------------------------------------------------------------------------
// OS identification (Ubuntu/Debian readiness)
// ---------------------------------------------------------------------------

fn check_os(paths: &AwsPaths, report: &mut StageReport) {
    let text = match read_limited(&paths.os_release, MAX_CONFIG_BYTES) {
        Ok(text) => text,
        Err(error) => {
            report.push_block(
                &format!("could not read {}: {error}", paths.os_release.display()),
                "OS information unavailable.",
            );
            report.finding(
                Severity::Low,
                format!(
                    "could not read {}; Debian/Ubuntu compatibility was not verified",
                    paths.os_release.display()
                ),
            );
            return;
        }
    };

    let values = parse_os_release(&text);
    let id = values.get("id").map(String::as_str).unwrap_or("");
    let version = values.get("version_id").map(String::as_str).unwrap_or("");
    let pretty = values
        .get("pretty_name")
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or(id);

    report.push_block(
        &format!(
            "{pretty}\nID: {}\nVERSION_ID: {}",
            if id.is_empty() { "unknown" } else { id },
            if version.is_empty() {
                "unknown"
            } else {
                version
            }
        ),
        "OS information unavailable.",
    );

    if id != "ubuntu" && id != "debian" {
        report.finding(
            Severity::Low,
            format!(
                "host OS `{}` is not Debian/Ubuntu; dpkg/apt and package-file checks may not apply",
                if id.is_empty() { "unknown" } else { id }
            ),
        );
    } else {
        report.note(format!("Debian/Ubuntu-compatible host detected: {pretty}"));
    }
}

fn parse_os_release(text: &str) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for_each_key_value(text, false, |key, value| {
        values.insert(key.to_ascii_lowercase(), value.trim_matches('"').to_owned());
    });
    values
}

// ---------------------------------------------------------------------------
// IMDS
// ---------------------------------------------------------------------------

fn check_metadata(ctx: &StageContext<'_>, paths: &AwsPaths, report: &mut StageReport) -> bool {
    if ctx.cfg.dry_run {
        report.push_block(
            "Skipped: dry-run does not query the EC2 metadata service.",
            "Skipped: dry-run.",
        );
        report.note("dry-run: IMDS checks were not executed");
        return false;
    }
    if !ctx.tool_exists("curl") {
        report.push_block("", "Skipped: curl command not found.");
        report.finding(
            Severity::Low,
            "curl is unavailable; EC2 IMDSv1/IMDSv2 state could not be audited",
        );
        return false;
    }

    let root = paths.metadata_root.trim_end_matches('/');
    let mut timed_out = false;

    let instance_id = ctx.run(curl_get(&format!("{root}/meta-data/instance-id"), None));
    let v1_reachable = instance_id.success() && !instance_id.stdout.trim().is_empty();
    if instance_id.timed_out {
        timed_out = true;
        report.finding(
            Severity::Medium,
            "EC2 IMDSv1 probe timed out; metadata protection is unknown",
        );
    }

    let token_output = ctx.run(curl_token(root));
    let token = token_output
        .success()
        .then(|| token_output.stdout.trim().to_owned())
        .filter(|token| !token.is_empty());
    if token_output.timed_out {
        timed_out = true;
        report.finding(
            Severity::Medium,
            "EC2 IMDSv2 token request timed out; metadata protection is unknown",
        );
    }

    if !v1_reachable && token.is_none() {
        report.push_block(
            "IMDSv1: unreachable\nIMDSv2: token endpoint unreachable",
            "EC2 metadata service unreachable.",
        );
        report.note(
            "EC2 instance metadata service is not reachable; AWS metadata checks were skipped",
        );
        return timed_out;
    }

    if v1_reachable {
        report.push_block(
            "IMDSv1: reachable without a session token",
            "IMDSv1: unknown",
        );
        report.finding(
            Severity::High,
            "EC2 IMDSv1 is enabled; require IMDSv2 (HttpTokens=required) to prevent SSRF credential theft",
        );
    } else {
        report.push_block(
            "IMDSv1: blocked (session token required)",
            "IMDSv1: unknown",
        );
        report.note("IMDSv1 is blocked; IMDSv2 appears to be required");
    }

    let Some(token) = token else {
        report.push_block("IMDSv2: token endpoint unavailable", "IMDSv2: unknown");
        report.finding(
            Severity::Low,
            "EC2 IMDSv2 token could not be obtained; metadata hardening could not be verified",
        );
        return timed_out;
    };

    report.push_block("IMDSv2: token issued", "IMDSv2: unknown");

    let document = ctx.run(curl_get(
        &format!("{root}/dynamic/instance-identity/document"),
        Some(&token),
    ));
    if document.success() {
        report_identity_document(&document.stdout, report);
    } else if document.timed_out {
        timed_out = true;
        report.finding(
            Severity::Medium,
            "EC2 instance identity document request timed out",
        );
    } else {
        report.note("EC2 instance identity document was not available");
    }

    let roles = ctx.run(curl_get(
        &format!("{root}/meta-data/iam/security-credentials/"),
        Some(&token),
    ));
    if roles.success()
        && let Some(role) = first_non_empty_line(&roles.stdout)
    {
        let role = truncate(role, 120);
        report.push_block(&format!("instance profile role: {role}"), "");
        report.note(format!("EC2 instance profile attached: {role}"));
    } else if roles.timed_out {
        timed_out = true;
        report.finding(Severity::Medium, "EC2 IAM role enumeration timed out");
    }

    timed_out
}

fn curl_get(url: &str, token: Option<&str>) -> Cmd {
    let mut command = Cmd::new("curl").args(CURL_ARGS);
    if let Some(token) = token {
        command = command
            .arg("-H")
            .arg(format!("X-aws-ec2-metadata-token: {token}"));
    }
    command.arg(url)
}

fn curl_token(root: &str) -> Cmd {
    let ttl_header = format!("X-aws-ec2-metadata-token-ttl-seconds: {IMDS_TOKEN_TTL_SECONDS}");
    Cmd::new("curl")
        .args(CURL_ARGS)
        .args(["-X", "PUT", "-H", &ttl_header])
        .arg(format!("{root}/api/token"))
}

fn report_identity_document(text: &str, report: &mut StageReport) {
    let Ok(document) = serde_json::from_str::<Value>(text) else {
        report.note("EC2 instance identity document was not valid JSON");
        return;
    };
    let field = |name: &str| {
        document
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or("-")
            .to_owned()
    };
    report.push_block(
        &format!(
            "instance-id: {}\nregion: {}\navailability-zone: {}\ninstance-type: {}\nimage-id: {}",
            field("instanceId"),
            field("region"),
            field("availabilityZone"),
            field("instanceType"),
            field("imageId")
        ),
        "EC2 instance identity document unavailable.",
    );
}

fn first_non_empty_line(text: &str) -> Option<&str> {
    text.lines().map(str::trim).find(|line| !line.is_empty())
}

fn truncate(text: &str, max_bytes: usize) -> String {
    truncate_with_ellipsis(text, max_bytes)
}

// ---------------------------------------------------------------------------
// credential exposure
// ---------------------------------------------------------------------------

static AWS_KEY_FIELD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\baws_(?:access_key_id|secret_access_key|session_token)\b\s*[=:]")
        .expect("valid AWS credential-field regex")
});
static AWS_ACCESS_KEY_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").expect("valid AWS access-key regex")
});
static PRIVATE_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
        .expect("valid private-key regex")
});

/// Read one candidate config file. Missing and empty files are ignored; other read errors are
/// recorded as notes so one unreadable path never aborts the scan.
fn read_candidate(file: &Path, what: &str, report: &mut StageReport) -> Option<String> {
    match read_limited(file, MAX_CONFIG_BYTES) {
        Ok(text) if !text.trim().is_empty() => Some(text),
        Ok(_) => None,
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => {
            let description = if what.is_empty() {
                file.display().to_string()
            } else {
                format!("{what} {}", file.display())
            };
            report.note(format!("could not read {description}: {error}"));
            None
        }
    }
}

fn check_credentials(paths: &AwsPaths, report: &mut StageReport) {
    let mut scanned = 0usize;
    let mut exposed = 0usize;

    for file in credential_files(paths) {
        match read_limited(&file, MAX_CONFIG_BYTES) {
            Ok(text) => {
                scanned += 1;
                if contains_aws_key_material(&text) {
                    exposed += 1;
                    report.finding(
                        Severity::High,
                        format!(
                            "long-term AWS credential material is stored in {}",
                            file.display()
                        ),
                    );
                }
                if let Ok(metadata) = fs::symlink_metadata(&file)
                    && metadata.is_file()
                    && metadata.permissions().mode() & 0o077 != 0
                {
                    report.finding(
                        Severity::Medium,
                        format!(
                            "{} is readable by group/others (mode {:04o}); expected 0600",
                            file.display(),
                            metadata.permissions().mode() & 0o777
                        ),
                    );
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => report.note(format!("could not read {}: {error}", file.display())),
        }
    }

    for file in &paths.user_data {
        if let Some(text) = read_candidate(file, "user-data", report) {
            scanned += 1;
            if contains_aws_key_material(&text) {
                exposed += 1;
                report.finding(
                    Severity::High,
                    format!(
                        "AWS credential material is embedded in EC2 user-data: {}",
                        file.display()
                    ),
                );
            }
            if PRIVATE_KEY.is_match(&text) {
                report.finding(
                    Severity::High,
                    format!(
                        "private key material is embedded in EC2 user-data: {}",
                        file.display()
                    ),
                );
            }
        }
    }

    let mut env_files = paths.env_files.clone();
    env_files.extend(shell_profile_files(&paths.profile_dir));
    for file in env_files {
        if let Some(text) = read_candidate(&file, "environment file", report) {
            scanned += 1;
            if contains_aws_key_material(&text) {
                exposed += 1;
                report.finding(
                    Severity::High,
                    format!("AWS credentials are exported by {}", file.display()),
                );
            }
        }
    }

    if let Some(text) = read_candidate(&paths.ecs_config, "", report) {
        scanned += 1;
        if contains_aws_key_material(&text) {
            exposed += 1;
            report.finding(
                Severity::High,
                format!(
                    "AWS credentials are embedded in the ECS agent config: {}",
                    paths.ecs_config.display()
                ),
            );
        }
    }

    if scanned == 0 {
        report.push_block("", "No AWS-related files were found to scan.");
        report.note("no static AWS credentials were found in the scanned locations");
    } else {
        report.push_block(
            &format!(
                "scanned {scanned} AWS-related file(s); {exposed} contained credential material"
            ),
            "",
        );
        if exposed == 0 {
            report.note("no static AWS credentials were found in the scanned locations");
        }
    }
}

fn contains_aws_key_material(text: &str) -> bool {
    AWS_KEY_FIELD.is_match(text) || AWS_ACCESS_KEY_VALUE.is_match(text)
}

fn credential_files(paths: &AwsPaths) -> Vec<PathBuf> {
    let mut files = BTreeSet::new();
    for root in &paths.home_roots {
        if files.len() >= MAX_CREDENTIAL_FILES {
            break;
        }
        let is_home_root = root.file_name().is_some_and(|name| name == "home");
        if is_home_root {
            let Ok(entries) = fs::read_dir(root) else {
                continue;
            };
            let mut homes = entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.is_dir())
                .collect::<Vec<_>>();
            homes.sort();
            for home in homes {
                add_aws_files(&home, &mut files);
            }
        } else {
            add_aws_files(root, &mut files);
        }
    }
    files.into_iter().take(MAX_CREDENTIAL_FILES).collect()
}

fn add_aws_files(home: &Path, files: &mut BTreeSet<PathBuf>) {
    files.insert(home.join(".aws/credentials"));
    files.insert(home.join(".aws/config"));
}

fn shell_profile_files(dir: &Path) -> Vec<PathBuf> {
    crate::fsutil::files_with_extension(dir, "sh", MAX_PROFILE_FILES)
}

// ---------------------------------------------------------------------------
// AWS agents and time sync
// ---------------------------------------------------------------------------

fn check_services(ctx: &StageContext<'_>, ecs_config: &Path, report: &mut StageReport) -> bool {
    if ctx.cfg.dry_run {
        report.push_block(
            "Skipped: dry-run does not query systemd units.",
            "Skipped: dry-run.",
        );
        report.note("dry-run: AWS agent and time-sync checks were not executed");
        return false;
    }

    let mut timed_out = false;
    if ctx.tool_exists("systemctl") {
        for unit in [
            "amazon-ssm-agent.service",
            "amazon-cloudwatch-agent.service",
            "ecs.service",
        ] {
            let status = unit_status(ctx, unit, report, &mut timed_out);
            report_unit(unit, status, ecs_config, report);
        }
    } else {
        report.push_block("", "Skipped: systemctl command not found.");
        report.note("`systemctl` was not found; AWS agent checks skipped");
    }

    if ctx.tool_exists("timedatectl") {
        let sync = ctx.run(Cmd::new("timedatectl").args([
            "show",
            "--property=NTPSynchronized",
            "--value",
        ]));
        if sync.timed_out {
            timed_out = true;
            report.finding(Severity::Medium, "NTP synchronization check timed out");
        } else if sync.success() {
            let state = sync.stdout.trim();
            report.push_block(&format!("clock synchronized: {state}"), "");
            if state == "no" {
                report.finding(
                    Severity::Low,
                    "system clock is not NTP-synchronized; AWS SigV4 signatures may fail",
                );
            }
        } else {
            report.note("timedatectl could not report clock synchronization state");
        }
    } else {
        report.push_block("", "Skipped: timedatectl command not found.");
        report.note("`timedatectl` was not found; clock synchronization was not checked");
    }

    timed_out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnitStatus {
    Active,
    Inactive,
    Missing,
    Unknown,
}

fn unit_status(
    ctx: &StageContext<'_>,
    unit: &str,
    report: &mut StageReport,
    timed_out: &mut bool,
) -> UnitStatus {
    let output = ctx.run(Cmd::new("systemctl").args([
        "show",
        unit,
        "--property=LoadState,ActiveState",
        "--no-pager",
    ]));
    if output.timed_out {
        *timed_out = true;
        report.finding(Severity::Medium, format!("systemctl show {unit} timed out"));
        return UnitStatus::Unknown;
    }
    if !output.success() {
        return UnitStatus::Unknown;
    }

    let mut load = None;
    let mut active = None;
    for_each_key_value(&output.stdout, false, |key, value| match key {
        "LoadState" => load = Some(value.to_owned()),
        "ActiveState" => active = Some(value.to_owned()),
        _ => {}
    });

    match (load.as_deref(), active.as_deref()) {
        (Some("not-found"), _) | (None, None) => UnitStatus::Missing,
        (_, Some("active")) => UnitStatus::Active,
        _ => UnitStatus::Inactive,
    }
}

fn report_unit(unit: &str, status: UnitStatus, ecs_config: &Path, report: &mut StageReport) {
    match status {
        UnitStatus::Active => {
            report.push_block(&format!("{unit}: active"), "");
            report.note(format!("{unit} is active"));
        }
        UnitStatus::Inactive => {
            report.push_block(&format!("{unit}: inactive"), "");
            match unit {
                "amazon-ssm-agent.service" => {
                    report.finding(Severity::Low, "AWS SSM agent is installed but not running")
                }
                "amazon-cloudwatch-agent.service" => report.finding(
                    Severity::Info,
                    "CloudWatch agent is installed but not running",
                ),
                "ecs.service" => report.finding(
                    Severity::Medium,
                    "ECS agent is installed but not running on an ECS host",
                ),
                _ => {}
            }
        }
        UnitStatus::Missing => {
            report.push_block(&format!("{unit}: not installed"), "");
            if unit == "ecs.service" && ecs_config.exists() {
                report.finding(
                    Severity::Medium,
                    format!(
                        "{} exists but the ECS agent unit is not installed",
                        ecs_config.display()
                    ),
                );
            }
        }
        UnitStatus::Unknown => {
            report.push_block(&format!("{unit}: unknown"), "");
        }
    }
}

#[cfg(test)]
include!("aws_tests.rs");
