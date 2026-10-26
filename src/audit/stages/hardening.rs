//! Host hardening audit.
//!
//! Unlike the command-oriented stages, this stage inspects configuration files and file modes.
//! It covers the usual Debian hardening baseline: SSH daemon options, kernel sysctl values,
//! firewall state, sudoers `NOPASSWD` rules, SUID/SGID binaries, world-writable paths and
//! password hygiene. Every location is injectable so the checks can be tested on temporary
//! directories without touching the host.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

use crate::audit::StageContext;
use crate::exec::Cmd;
use crate::report::{Severity, StageId, StageReport, StageStatus};

/// Upper bound for a single configuration file. `/etc` files are small; the cap protects the
/// audit from a maliciously large replacement.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
/// Recursive file-mode scan bounds. A full filesystem walk is neither necessary nor safe.
const MAX_SCAN_ENTRIES: usize = 50_000;
const MAX_SCAN_DEPTH: usize = 8;
/// Maximum number of paths printed per section.
const MAX_LISTED: usize = 20;

/// Binaries that are commonly SUID/SGID on Debian. Everything else is worth a manual look.
const KNOWN_PRIVILEGED: [&str; 40] = [
    "Xorg",
    "at",
    "beep",
    "bsd-write",
    "chage",
    "chfn",
    "chsh",
    "crontab",
    "dbus-daemon-launch-helper",
    "dotlockfile",
    "expiry",
    "fusermount",
    "fusermount3",
    "gpasswd",
    "krb5_child",
    "locate",
    "lppasswd",
    "mlocate",
    "mount",
    "newgrp",
    "ntfs-3g",
    "passwd",
    "ping",
    "ping6",
    "pkexec",
    "polkit-agent-helper-1",
    "postdrop",
    "postqueue",
    "pppd",
    "procmail",
    "qemu-bridge-helper",
    "sendmail",
    "sg",
    "snap-confine",
    "ssh-agent",
    "ssh-keysign",
    "su",
    "sudo",
    "suexec",
    "umount",
];

/// File-system locations inspected by this stage. Tests build a temp-directory variant.
struct HardeningPaths {
    sshd_config: PathBuf,
    sshd_config_dir: PathBuf,
    sysctl_conf: PathBuf,
    sysctl_dir: PathBuf,
    passwd: PathBuf,
    shadow: PathBuf,
    sudoers: PathBuf,
    sudoers_dir: PathBuf,
    scan_roots: Vec<PathBuf>,
}

impl Default for HardeningPaths {
    fn default() -> Self {
        Self {
            sshd_config: PathBuf::from("/etc/ssh/sshd_config"),
            sshd_config_dir: PathBuf::from("/etc/ssh/sshd_config.d"),
            sysctl_conf: PathBuf::from("/etc/sysctl.conf"),
            sysctl_dir: PathBuf::from("/etc/sysctl.d"),
            passwd: PathBuf::from("/etc/passwd"),
            shadow: PathBuf::from("/etc/shadow"),
            sudoers: PathBuf::from("/etc/sudoers"),
            sudoers_dir: PathBuf::from("/etc/sudoers.d"),
            scan_roots: [
                "/usr/bin",
                "/usr/sbin",
                "/usr/local/bin",
                "/usr/local/sbin",
                "/opt",
                "/tmp",
                "/var/tmp",
                "/home",
                "/srv",
                "/var/www",
            ]
            .iter()
            .map(PathBuf::from)
            .collect(),
        }
    }
}

pub fn run(ctx: &StageContext<'_>) -> StageReport {
    run_with_paths(ctx, &HardeningPaths::default())
}

fn run_with_paths(ctx: &StageContext<'_>, paths: &HardeningPaths) -> StageReport {
    let mut report = StageReport::new(StageId::Hardening);
    report.push_header("=== SSH DAEMON CONFIGURATION ===");
    let (settings, source) = ssh_settings(ctx, paths);
    report.push_block(&format!("source: {source}"), "source: unavailable");
    check_ssh(&settings, &mut report);

    report.push_header("=== SYSCTL / KERNEL HARDENING ===");
    let mut sysctl = load_sysctl(&paths.sysctl_conf, &paths.sysctl_dir);
    if !ctx.cfg.dry_run && ctx.tool_exists("sysctl") {
        let output = ctx.run(Cmd::new("sysctl").arg("-a"));
        if output.success() {
            merge_sysctl(&mut sysctl, &output.stdout);
        }
    }
    check_sysctl(&sysctl, &mut report);

    report.push_header("=== FIREWALL ===");
    let mut timed_out = check_firewall(ctx, &mut report);

    report.push_header("=== SUDOERS ===");
    check_sudoers(paths, &mut report);

    report.push_header("=== FILE PERMISSIONS (SUID/SGID & WORLD-WRITABLE) ===");
    if ctx.cfg.dry_run {
        report.push_block(
            "Skipped: dry-run does not walk the filesystem.",
            "Skipped: dry-run.",
        );
        report.note("dry-run: SUID/SGID and world-writable scan was not executed");
    } else {
        let scan = scan_filesystem(&paths.scan_roots);
        report_scan(&scan, &mut report);
    }

    report.push_header("=== ACCOUNT & PASSWORD HYGIENE ===");
    check_accounts(paths, &mut report);

    if ctx.expired() {
        timed_out = true;
        report.finding(
            Severity::Medium,
            "hardening audit reached the global deadline before completing",
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
// SSH
// ---------------------------------------------------------------------------

fn ssh_settings(
    ctx: &StageContext<'_>,
    paths: &HardeningPaths,
) -> (BTreeMap<String, String>, String) {
    if !ctx.cfg.dry_run && ctx.tool_exists("sshd") {
        let output = ctx.run(Cmd::new("sshd").arg("-T").sudo(true));
        if output.success() {
            let settings = parse_ssh_settings(&output.stdout, false);
            if !settings.is_empty() {
                return (settings, "sshd -T (effective configuration)".to_owned());
            }
        }
    }
    if ctx.cfg.dry_run && ctx.tool_exists("sshd") {
        return (
            load_sshd_files(&paths.sshd_config, &paths.sshd_config_dir),
            format!("{} (file fallback, dry-run)", paths.sshd_config.display()),
        );
    }
    (
        load_sshd_files(&paths.sshd_config, &paths.sshd_config_dir),
        format!("{} (file fallback)", paths.sshd_config.display()),
    )
}

/// Read the main sshd config plus drop-ins. Debian includes `sshd_config.d/*.conf` near the top,
/// so drop-ins are merged first; the first value for a keyword wins, matching sshd semantics.
fn load_sshd_files(main: &Path, dir: &Path) -> BTreeMap<String, String> {
    let mut settings = BTreeMap::new();
    for path in config_files(dir) {
        if let Ok(text) = read_limited(&path) {
            merge_ssh_settings(&mut settings, parse_ssh_settings(&text, true));
        }
    }
    if let Ok(text) = read_limited(main) {
        merge_ssh_settings(&mut settings, parse_ssh_settings(&text, true));
    }
    settings
}

fn merge_ssh_settings(settings: &mut BTreeMap<String, String>, parsed: BTreeMap<String, String>) {
    for (key, value) in parsed {
        settings.entry(key).or_insert(value);
    }
}

/// Parse `key value` lines from `sshd -T` or `sshd_config`. Comments are ignored. When
/// `stop_at_match` is set, conditional `Match` blocks are not treated as global settings.
fn parse_ssh_settings(text: &str, stop_at_match: bool) -> BTreeMap<String, String> {
    let mut settings = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else {
            continue;
        };
        let key = key.to_ascii_lowercase();
        if stop_at_match && key == "match" {
            break;
        }
        let value = parts
            .next()
            .unwrap_or("")
            .trim_matches('"')
            .to_ascii_lowercase();
        if key.is_empty() || value.is_empty() {
            continue;
        }
        settings.entry(key).or_insert(value);
    }
    settings
}

fn check_ssh(settings: &BTreeMap<String, String>, report: &mut StageReport) {
    if settings.is_empty() {
        report.finding(
            Severity::Low,
            "SSH daemon configuration could not be read; SSH hardening was not audited",
        );
        return;
    }

    match settings.get("permitrootlogin").map(String::as_str) {
        Some("yes") => report.finding(
            Severity::High,
            "SSH root login is enabled (`PermitRootLogin yes`)",
        ),
        Some("without-password" | "prohibit-password") => report.finding(
            Severity::Info,
            "SSH root login is limited to key-based authentication",
        ),
        Some("forced-commands-only") => report.finding(
            Severity::Low,
            "SSH root login is allowed only for forced commands",
        ),
        _ => {}
    }

    for (key, severity, message) in [
        (
            "passwordauthentication",
            Severity::Medium,
            "SSH password authentication is enabled; prefer keys only",
        ),
        (
            "permitemptypasswords",
            Severity::High,
            "SSH permits empty passwords (`PermitEmptyPasswords yes`)",
        ),
        (
            "permituserenvironment",
            Severity::Medium,
            "SSH accepts user environment files (`PermitUserEnvironment yes`)",
        ),
        (
            "usepam",
            Severity::Medium,
            "SSH has PAM disabled (`UsePAM no`)",
        ),
        (
            "x11forwarding",
            Severity::Low,
            "SSH X11 forwarding is enabled",
        ),
    ] {
        if let Some(value) = settings.get(key) {
            let risky = match key {
                "usepam" => value == "no",
                _ => value == "yes",
            };
            if risky {
                report.finding(severity, message);
            }
        }
    }

    if let Some(value) = settings.get("maxauthtries")
        && let Ok(attempts) = value.parse::<u32>()
        && attempts > 6
    {
        report.finding(
            Severity::Low,
            format!("SSH allows {attempts} authentication attempts; expected 6 or fewer"),
        );
    }
    if let Some(value) = settings.get("logingracetime")
        && let Ok(seconds) = value.parse::<u32>()
        && seconds > 60
    {
        report.finding(
            Severity::Low,
            format!("SSH LoginGraceTime is {seconds}s; expected 60s or less"),
        );
    }
    if settings
        .get("clientaliveinterval")
        .is_some_and(|value| value == "0")
    {
        report.finding(
            Severity::Low,
            "SSH idle sessions never expire (`ClientAliveInterval 0`)",
        );
    }

    report.push_block(
        &format!(
            "permitrootlogin: {}\npasswordauthentication: {}\nmaxauthtries: {}\n\
             x11forwarding: {}\nclientaliveinterval: {}",
            settings
                .get("permitrootlogin")
                .map(String::as_str)
                .unwrap_or("-"),
            settings
                .get("passwordauthentication")
                .map(String::as_str)
                .unwrap_or("-"),
            settings
                .get("maxauthtries")
                .map(String::as_str)
                .unwrap_or("-"),
            settings
                .get("x11forwarding")
                .map(String::as_str)
                .unwrap_or("-"),
            settings
                .get("clientaliveinterval")
                .map(String::as_str)
                .unwrap_or("-")
        ),
        "No SSH settings parsed.",
    );
}

// ---------------------------------------------------------------------------
// sysctl
// ---------------------------------------------------------------------------

fn load_sysctl(conf: &Path, dir: &Path) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    if let Ok(text) = read_limited(conf) {
        merge_sysctl(&mut values, &text);
    }
    // Drop-in files are applied in lexicographic order; later files win.
    for path in config_files(dir) {
        if let Ok(text) = read_limited(&path) {
            merge_sysctl(&mut values, &text);
        }
    }
    values
}

fn merge_sysctl(values: &mut BTreeMap<String, String>, text: &str) {
    crate::text::for_each_key_value(text, true, |key, value| {
        if !value.is_empty() {
            values.insert(key.to_owned(), value.to_owned());
        }
    });
}

fn check_sysctl(values: &BTreeMap<String, String>, report: &mut StageReport) {
    const CHECKS: [(&str, &[&str], Severity, &str); 15] = [
        (
            "kernel.randomize_va_space",
            &["2"],
            Severity::Medium,
            "full address-space layout randomisation",
        ),
        (
            "net.ipv4.tcp_syncookies",
            &["1"],
            Severity::Medium,
            "SYN-cookie protection",
        ),
        (
            "net.ipv4.conf.all.accept_redirects",
            &["0"],
            Severity::Medium,
            "ICMP redirect acceptance",
        ),
        (
            "net.ipv4.conf.default.accept_redirects",
            &["0"],
            Severity::Medium,
            "ICMP redirect acceptance on new interfaces",
        ),
        (
            "net.ipv4.conf.all.send_redirects",
            &["0"],
            Severity::Low,
            "ICMP redirect emission",
        ),
        (
            "net.ipv4.conf.all.accept_source_route",
            &["0"],
            Severity::Medium,
            "source-routed packets",
        ),
        (
            "net.ipv4.conf.all.log_martians",
            &["1"],
            Severity::Low,
            "logging of martian packets",
        ),
        (
            "net.ipv4.conf.all.rp_filter",
            &["1", "2"],
            Severity::Low,
            "reverse-path filtering",
        ),
        (
            "net.ipv6.conf.all.accept_redirects",
            &["0"],
            Severity::Medium,
            "IPv6 redirect acceptance",
        ),
        (
            "kernel.dmesg_restrict",
            &["1"],
            Severity::Low,
            "kernel log restriction",
        ),
        (
            "kernel.kptr_restrict",
            &["1", "2"],
            Severity::Low,
            "kernel pointer restriction",
        ),
        (
            "kernel.yama.ptrace_scope",
            &["1", "2", "3"],
            Severity::Low,
            "ptrace restriction",
        ),
        (
            "fs.protected_hardlinks",
            &["1"],
            Severity::Low,
            "hardlink protection",
        ),
        (
            "fs.protected_symlinks",
            &["1"],
            Severity::Low,
            "symlink protection",
        ),
        (
            "net.ipv4.ip_forward",
            &["0"],
            Severity::Low,
            "IP forwarding on a non-router host",
        ),
    ];

    let mut checked = 0usize;
    for (key, expected, severity, description) in CHECKS {
        let Some(value) = values.get(key) else {
            continue;
        };
        checked += 1;
        if !expected.contains(&value.as_str()) {
            report.finding(
                severity,
                format!(
                    "sysctl {key} = {value}; expected {} ({description})",
                    expected.join("/")
                ),
            );
        }
    }

    if values.is_empty() {
        report.finding(
            Severity::Low,
            "no sysctl configuration was found; kernel hardening was not audited",
        );
    } else {
        report.push_block(
            &format!(
                "{checked}/{} security-relevant sysctl keys configured",
                CHECKS.len()
            ),
            "No security-relevant sysctl keys configured.",
        );
    }
}

// ---------------------------------------------------------------------------
// firewall
// ---------------------------------------------------------------------------

fn check_firewall(ctx: &StageContext<'_>, report: &mut StageReport) -> bool {
    if ctx.cfg.dry_run {
        report.push_block(
            "Skipped: dry-run does not query firewall state.",
            "Skipped: dry-run.",
        );
        report.note("dry-run: firewall state was not queried");
        return false;
    }

    let mut timed_out = false;
    let mut active = None;
    let mut observed = Vec::new();

    if ctx.tool_exists("ufw") {
        let output = ctx.run(Cmd::new("ufw").arg("status").sudo(true));
        if output.timed_out {
            timed_out = true;
            report.finding(Severity::Medium, "ufw status timed out");
        } else if output.success()
            && output
                .stdout
                .to_ascii_lowercase()
                .contains("status: active")
        {
            active = Some("ufw");
        } else {
            observed.push("ufw is installed but not active");
        }
    }

    if active.is_none() && ctx.tool_exists("nft") {
        let output = ctx.run(Cmd::new("nft").args(["list", "ruleset"]).sudo(true));
        if output.timed_out {
            timed_out = true;
            report.finding(Severity::Medium, "nft list ruleset timed out");
        } else if output.success()
            && output
                .stdout
                .lines()
                .any(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        {
            active = Some("nftables");
        } else {
            observed.push("nftables has no rules");
        }
    }

    if active.is_none() && ctx.tool_exists("iptables") {
        let output = ctx.run(Cmd::new("iptables").arg("-S").sudo(true));
        if output.timed_out {
            timed_out = true;
            report.finding(Severity::Medium, "iptables -S timed out");
        } else if output.success() && count_iptables_rules(&output.stdout) > 0 {
            active = Some("iptables");
        } else {
            observed.push("iptables has no rules");
        }
    }

    if let Some(firewall) = active {
        report.push_block(
            &format!("active firewall: {firewall}"),
            "active firewall: unknown",
        );
        report.note(format!("active firewall detected: {firewall}"));
    } else {
        report.push_block(&observed.join("\n"), "No firewall tooling detected.");
        if observed.is_empty() && !timed_out {
            report.finding(
                Severity::Low,
                "no firewall tooling (ufw, nft or iptables) was found",
            );
        } else if !timed_out {
            report.finding(
                Severity::Medium,
                "no active firewall rules detected (ufw/nft/iptables)",
            );
        }
    }

    timed_out
}

fn count_iptables_rules(stdout: &str) -> usize {
    stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("-P") && !line.starts_with("-N"))
        .count()
}

// ---------------------------------------------------------------------------
// sudoers
// ---------------------------------------------------------------------------

static NOPASSWD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bNOPASSWD\s*:").expect("valid NOPASSWD regex"));
static NOAUTH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^\s*Defaults(?:@\S+|\s+[^#]*)?\s+!authenticate\b")
        .expect("valid !authenticate regex")
});

fn check_sudoers(paths: &HardeningPaths, report: &mut StageReport) {
    let mut files = vec![paths.sudoers.clone()];
    let Ok(entries) = fs::read_dir(&paths.sudoers_dir) else {
        // A missing include directory is normal.
        files.retain(|path| path.exists());
        inspect_sudoers(&files, report);
        return;
    };
    let mut includes = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .file_name()
                    .map(|name| {
                        let name = name.to_string_lossy();
                        !name.starts_with('.') && !name.ends_with('~') && !name.contains('.')
                    })
                    .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    includes.sort();
    files.extend(includes);
    inspect_sudoers(&files, report);
}

fn inspect_sudoers(files: &[PathBuf], report: &mut StageReport) {
    let mut nopasswd = Vec::new();
    let mut noauth = Vec::new();
    let mut unreadable = 0usize;

    for file in files {
        let text = match read_limited(file) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => {
                unreadable += 1;
                continue;
            }
        };
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if NOPASSWD_RE.is_match(line) {
                nopasswd.push(format!("{}:{}", file.display(), index + 1));
            }
            if NOAUTH_RE.is_match(line) {
                noauth.push(format!("{}:{}", file.display(), index + 1));
            }
        }
    }

    if !nopasswd.is_empty() {
        report.finding(
            Severity::Medium,
            format!(
                "{} sudo rule(s) use NOPASSWD: {}",
                nopasswd.len(),
                nopasswd
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    }
    if !noauth.is_empty() {
        report.finding(
            Severity::High,
            format!(
                "sudo authentication is disabled by `!authenticate` in {}",
                noauth
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    }
    if unreadable > 0 {
        report.note(format!(
            "{unreadable} sudoers file(s) could not be read (run as root for a complete audit)"
        ));
    }
    if nopasswd.is_empty() && noauth.is_empty() {
        report.push_block("no NOPASSWD or !authenticate rules found", "");
    }
}

// ---------------------------------------------------------------------------
// file modes
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ScanResult {
    suid: Vec<PathBuf>,
    sgid: Vec<PathBuf>,
    world_writable_files: Vec<PathBuf>,
    world_writable_dirs: Vec<PathBuf>,
    entries: usize,
    truncated: bool,
}

fn scan_filesystem(roots: &[PathBuf]) -> ScanResult {
    let mut result = ScanResult::default();
    let mut stack = roots
        .iter()
        .rev()
        .map(|root| (root.clone(), 0usize))
        .collect::<Vec<_>>();

    while let Some((path, depth)) = stack.pop() {
        if result.entries >= MAX_SCAN_ENTRIES {
            result.truncated = true;
            break;
        }
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            continue;
        }
        result.entries += 1;
        let mode = metadata.permissions().mode();

        if metadata.is_dir() {
            if mode & 0o002 != 0 && mode & 0o1000 == 0 && !is_temp_location(&path) {
                result.world_writable_dirs.push(path.clone());
            }
            if depth < MAX_SCAN_DEPTH
                && let Ok(entries) = fs::read_dir(&path)
            {
                let mut children = entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.path())
                    .collect::<Vec<_>>();
                children.sort();
                for child in children.into_iter().rev() {
                    stack.push((child, depth + 1));
                }
            }
            continue;
        }

        if !metadata.is_file() {
            continue;
        }
        if mode & 0o4000 != 0 {
            result.suid.push(path.clone());
        }
        if mode & 0o2000 != 0 {
            result.sgid.push(path.clone());
        }
        if mode & 0o002 != 0 && !is_temp_location(&path) {
            result.world_writable_files.push(path);
        }
    }

    result.suid.sort();
    result.sgid.sort();
    result.world_writable_files.sort();
    result.world_writable_dirs.sort();
    result
}

fn is_temp_location(path: &Path) -> bool {
    has_component(path, &["tmp", "shm"])
}

fn is_shared_location(path: &Path) -> bool {
    is_temp_location(path) || has_component(path, &["home", "srv", "www"])
}

fn has_component(path: &Path, names: &[&str]) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(|name| names.contains(&name))
    })
}

fn is_known_privileged(path: &Path) -> bool {
    path.file_name()
        .map(|name| KNOWN_PRIVILEGED.contains(&name.to_string_lossy().as_ref()))
        .unwrap_or(false)
}

fn report_scan(scan: &ScanResult, report: &mut StageReport) {
    let mut unexpected = scan
        .suid
        .iter()
        .chain(scan.sgid.iter())
        .filter(|path| !is_known_privileged(path))
        .cloned()
        .collect::<Vec<_>>();
    unexpected.sort();
    unexpected.dedup();

    let exposed = unexpected
        .iter()
        .filter(|path| is_shared_location(path))
        .cloned()
        .collect::<Vec<_>>();

    if !exposed.is_empty() {
        report.finding(
            Severity::High,
            format!(
                "{} SUID/SGID file(s) in a user-writable or shared location",
                exposed.len()
            ),
        );
        report.push_block(&join_paths(&exposed), "");
    }
    let other = {
        let exposed_set = exposed
            .iter()
            .map(PathBuf::as_path)
            .collect::<BTreeSet<_>>();
        unexpected
            .iter()
            .filter(|path| !exposed_set.contains(path.as_path()))
            .cloned()
            .collect::<Vec<_>>()
    };
    if !other.is_empty() {
        report.finding(
            Severity::Low,
            format!(
                "{} unexpected SUID/SGID file(s); review the list",
                other.len()
            ),
        );
    }

    let mut suid_block = format!(
        "SUID: {} file(s)\nSGID: {} file(s)",
        scan.suid.len(),
        scan.sgid.len()
    );
    let listed = scan
        .suid
        .iter()
        .chain(scan.sgid.iter())
        .take(MAX_LISTED)
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>();
    if !listed.is_empty() {
        suid_block.push('\n');
        suid_block.push_str(&listed.join("\n"));
    }
    report.push_block(
        &suid_block,
        "No SUID/SGID files found in the scanned roots.",
    );

    if !scan.world_writable_files.is_empty() {
        report.finding(
            Severity::Medium,
            format!(
                "{} world-writable file(s) outside temporary directories",
                scan.world_writable_files.len()
            ),
        );
        report.push_block(&join_paths(&scan.world_writable_files), "");
    }
    if !scan.world_writable_dirs.is_empty() {
        report.finding(
            Severity::Medium,
            format!(
                "{} world-writable directories without the sticky bit",
                scan.world_writable_dirs.len()
            ),
        );
        report.push_block(&join_paths(&scan.world_writable_dirs), "");
    }
    if scan.world_writable_files.is_empty() && scan.world_writable_dirs.is_empty() {
        report.push_block("no world-writable files or directories found", "");
    }

    if scan.truncated {
        report.note(format!(
            "filesystem scan stopped after {MAX_SCAN_ENTRIES} entries; results are partial"
        ));
    } else {
        report.note(format!(
            "scanned {} filesystem entries for dangerous modes",
            scan.entries
        ));
    }
}

fn join_paths(paths: &[PathBuf]) -> String {
    let mut text = paths
        .iter()
        .take(MAX_LISTED)
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join("\n");
    if paths.len() > MAX_LISTED {
        text.push_str(&format!("\n... and {} more", paths.len() - MAX_LISTED));
    }
    text
}

// ---------------------------------------------------------------------------
// accounts
// ---------------------------------------------------------------------------

fn check_accounts(paths: &HardeningPaths, report: &mut StageReport) {
    if let Ok(text) = read_limited(&paths.passwd) {
        let mut uid_zero = Vec::new();
        let mut empty = Vec::new();
        for line in text.lines() {
            let fields = line.split(':').collect::<Vec<_>>();
            if fields.len() < 7 {
                continue;
            }
            let (name, password, uid) = (fields[0], fields[1], fields[2]);
            if uid == "0" && name != "root" {
                uid_zero.push(name.to_owned());
            }
            if password.is_empty() && !name.is_empty() {
                empty.push(name.to_owned());
            }
        }
        if !uid_zero.is_empty() {
            report.finding(
                Severity::High,
                format!(
                    "additional UID 0 account(s) in /etc/passwd: {}",
                    uid_zero.join(", ")
                ),
            );
        }
        if !empty.is_empty() {
            report.finding(
                Severity::High,
                format!(
                    "account(s) with an empty password field in /etc/passwd: {}",
                    empty.join(", ")
                ),
            );
        }
    }

    match read_limited(&paths.shadow) {
        Ok(text) => {
            let mut empty = Vec::new();
            let mut weak = Vec::new();
            let mut locked = 0usize;
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let fields = line.split(':').collect::<Vec<_>>();
                if fields.len() < 2 {
                    continue;
                }
                let (name, hash) = (fields[0], fields[1]);
                if name.is_empty() {
                    continue;
                }
                if hash.is_empty() {
                    empty.push(name.to_owned());
                } else if hash.starts_with('!') || hash.starts_with('*') {
                    locked += 1;
                } else if hash.starts_with("$1$") {
                    weak.push(name.to_owned());
                }
            }
            if !empty.is_empty() {
                report.finding(
                    Severity::High,
                    format!(
                        "account(s) with an empty shadow password: {}",
                        empty.join(", ")
                    ),
                );
            }
            if !weak.is_empty() {
                report.finding(
                    Severity::Low,
                    format!(
                        "account(s) using weak MD5 password hashes: {}",
                        weak.join(", ")
                    ),
                );
            }
            report.push_block(
                &format!(
                    "{} locked account(s), {} account(s) with an empty password, {} MD5 hash(es)",
                    locked,
                    empty.len(),
                    weak.len()
                ),
                "No shadow entries parsed.",
            );
        }
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            report.note("cannot read /etc/shadow without root; password hashes were not audited");
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            report.note("/etc/shadow not found; password hashes were not audited");
        }
        Err(error) => {
            report.note(format!("could not read /etc/shadow: {error}"));
        }
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn config_files(dir: &Path) -> Vec<PathBuf> {
    crate::fsutil::files_with_extension(dir, "conf", usize::MAX)
}

fn read_limited(path: &Path) -> io::Result<String> {
    crate::fsutil::read_limited(path, MAX_CONFIG_BYTES)
}

#[cfg(test)]
include!("hardening_tests.rs");
