use std::fs::OpenOptions;
use std::process::{Command, Output};

fn binary() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rs-security-checker"));
    // Keep the host environment from silently enabling optional integrations.
    for variable in [
        "NOTIFY_ENABLED",
        "LAYA_ENABLED",
        "LAYA_ALLOW_REMOTE",
        "NOTIFY_ON",
        "SLACK_WEBHOOK_URL",
        "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_CHAT_ID",
        "LAYA_URL",
        "LAYA_MODEL",
        "LAYA_API",
        "LAYA_API_KEY",
    ] {
        command.env_remove(variable);
    }
    command
}

fn run(args: &[&str]) -> Output {
    binary().args(args).output().unwrap()
}

#[test]
fn dry_run_writes_machine_readable_summary() {
    let dir = tempfile::tempdir().unwrap();
    let output = run(&[
        "--dry-run",
        "--only",
        "persistence",
        "--output-dir",
        dir.path().to_str().unwrap(),
        "--json",
        "--color",
        "never",
        "--no-lock",
    ]);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["stages"][0]["id"], "persistence");
    assert_eq!(
        summary["tool"]["notifications_compiled"].as_bool().unwrap(),
        cfg!(feature = "notifications")
    );
    assert!(dir.path().join("audit-summary.json").exists());
    assert!(dir.path().join("audit-summary.md").exists());
    assert!(dir.path().join("persistence-report.txt").exists());
}

#[test]
fn all_stages_can_be_dry_run() {
    let dir = tempfile::tempdir().unwrap();
    let output = run(&[
        "--dry-run",
        "--skip",
        "precheck",
        "--output-dir",
        dir.path().to_str().unwrap(),
        "--json",
        "--color",
        "never",
        "--no-lock",
    ]);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["stages"].as_array().unwrap().len(), 10);
    assert!(dir.path().join("audit-summary.json").exists());
    assert!(dir.path().join("audit-summary.md").exists());
}

#[test]
fn all_stages_can_run_with_parallelism_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let output = run(&[
        "--dry-run",
        "--parallel-jobs",
        "1",
        "--skip",
        "precheck",
        "--output-dir",
        dir.path().to_str().unwrap(),
        "--json",
        "--color",
        "never",
        "--no-lock",
    ]);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["stages"].as_array().unwrap().len(), 10);
}

#[test]
fn excessive_parallel_jobs_exit_with_code_two() {
    let output = run(&[
        "--parallel-jobs",
        "33",
        "--dry-run",
        "--no-lock",
        "--only",
        "web",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--parallel-jobs must be at most 32"),
        "{stderr}"
    );
}

#[test]
fn list_stages_prints_every_stage() {
    let output = run(&["--list-stages"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for stage in [
        "precheck",
        "docker",
        "clamav",
        "debsums",
        "rootkit",
        "persistence",
        "network",
        "web",
        "auth",
        "hardening",
        "aws",
    ] {
        assert!(stdout.contains(stage), "missing {stage} in:\n{stdout}");
    }
}

#[test]
fn invalid_configuration_exits_with_code_two() {
    let output = run(&["--timeout", "0", "--dry-run", "--no-lock"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--timeout must be greater than zero"),
        "{stderr}"
    );
}

#[test]
fn a_held_lock_exits_with_code_two() {
    let dir = tempfile::tempdir().unwrap();
    let lock_path = dir.path().join("audit.lock");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .unwrap();
    file.try_lock().unwrap();

    let output = run(&[
        "--only",
        "precheck",
        "--lock-file",
        lock_path.to_str().unwrap(),
        "--quiet",
        "--color",
        "never",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("another audit instance"), "{stderr}");
}

#[cfg(not(feature = "notifications"))]
#[test]
fn notifications_reject_a_build_without_the_feature() {
    let output = run(&[
        "--notify",
        "--dry-run",
        "--no-lock",
        "--only",
        "persistence",
        "--quiet",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("feature `notifications` is not compiled in"),
        "{stderr}"
    );
}

#[cfg(not(feature = "laya"))]
#[test]
fn laya_rejects_a_build_without_the_feature() {
    let output = run(&[
        "--laya",
        "--dry-run",
        "--no-lock",
        "--only",
        "persistence",
        "--quiet",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("feature `laya` is not compiled in"),
        "{stderr}"
    );
}

#[cfg(feature = "laya")]
#[test]
fn laya_rejects_remote_endpoints_by_default() {
    let output = run(&[
        "--laya",
        "--laya-api",
        "openai",
        "--laya-url",
        "http://192.168.1.10:8080",
        "--dry-run",
        "--no-lock",
        "--only",
        "persistence",
        "--quiet",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("non-loopback"), "{stderr}");
}
