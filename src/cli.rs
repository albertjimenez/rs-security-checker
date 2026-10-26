//! Command-line interface.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

use crate::config::{
    Config, DEFAULT_GLOBAL_TIMEOUT_SECS, DEFAULT_LAYA_MAX_CHARS, DEFAULT_LAYA_MAX_TOKENS,
    DEFAULT_LAYA_TIMEOUT_SECS, DEFAULT_LOG_TAIL_BYTES, DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_PARALLEL_JOBS, LayaApi, default_lock_path, env_flag,
};
use crate::error::{Error, Result};
use crate::exec::SudoMode;
use crate::report::{Severity, StageId};
use crate::ui::ColorMode;

#[derive(Debug, Parser)]
#[command(
    name = "rs-security-checker",
    version,
    about = "Safe Debian security audit (Rust port of the Jenkins security pipeline)",
    long_about = "Runs the audit stages from jenkins-pipeline/Jenkinsfile without a shell.\n\
                  Optional build features add local-model triage (`laya`) and Slack/Telegram\n\
                  notifications (`notifications`). Both integrations are off at compile time by\n\
                  default and must also be enabled explicitly at runtime."
)]
pub struct Cli {
    /// Directory where reports and the JSON/Markdown summary are written.
    #[arg(short, long, default_value = ".", value_name = "DIR")]
    pub output_dir: PathBuf,

    /// Lock file used to prevent concurrent audit runs.
    #[arg(long, value_name = "PATH")]
    pub lock_file: Option<PathBuf>,

    /// Do not acquire the concurrency lock.
    #[arg(long)]
    pub no_lock: bool,

    /// Global audit timeout in seconds (Jenkins uses 30 minutes).
    #[arg(long, default_value_t = DEFAULT_GLOBAL_TIMEOUT_SECS, value_name = "SECS")]
    pub timeout: u64,

    /// Per-command timeout in seconds. Defaults to the remaining global timeout.
    #[arg(long, value_name = "SECS")]
    pub command_timeout: Option<u64>,

    /// Maximum bytes captured from each command (stdout and stderr separately).
    #[arg(long, default_value_t = DEFAULT_MAX_OUTPUT_BYTES, value_name = "BYTES")]
    pub max_output_bytes: usize,

    /// Allow the precheck stage to run apt-get install for missing packages.
    #[arg(long)]
    pub install_deps: bool,

    /// Stop after the first failed or timed-out stage.
    #[arg(long)]
    pub fail_fast: bool,

    /// Exit with status 1 when a finding reaches this severity.
    #[arg(long, value_enum, value_name = "SEVERITY")]
    pub fail_on: Option<Severity>,

    /// Print commands instead of executing them.
    #[arg(long)]
    pub dry_run: bool,

    /// Print the JSON summary to stdout (human logs go to stderr).
    #[arg(long)]
    pub json: bool,

    /// Only print errors.
    #[arg(short, long, conflicts_with = "verbose")]
    pub quiet: bool,

    /// Print every command and extra diagnostics.
    #[arg(short, long)]
    pub verbose: bool,

    /// Color output mode.
    #[arg(long, value_enum, default_value = "auto")]
    pub color: ColorMode,

    /// How to use sudo for privileged commands.
    #[arg(long, value_enum, default_value = "auto")]
    pub sudo_mode: SudoMode,

    /// Skip one or more stages (comma-separated or repeated).
    #[arg(long, value_enum, value_delimiter = ',', value_name = "STAGE")]
    pub skip: Vec<StageId>,

    /// Run only the listed stages (comma-separated or repeated).
    #[arg(long, value_enum, value_delimiter = ',', value_name = "STAGE")]
    pub only: Vec<StageId>,

    /// Additional ClamAV scan root (repeatable). Defaults to the Jenkins paths.
    #[arg(long = "clamav-path", value_name = "PATH")]
    pub clamav_paths: Vec<PathBuf>,

    /// Additional web-server log file or directory (repeatable, nginx/apache/caddy defaults).
    #[arg(long = "web-log", value_name = "PATH")]
    pub web_log_paths: Vec<PathBuf>,

    /// Additional authentication log file or directory (repeatable).
    #[arg(long = "auth-log", value_name = "PATH")]
    pub auth_log_paths: Vec<PathBuf>,

    /// Maximum bytes read from the tail of each log file.
    #[arg(long, default_value_t = DEFAULT_LOG_TAIL_BYTES, value_name = "BYTES")]
    pub log_tail_bytes: usize,

    /// Concurrent workers for lightweight stages (web, auth, hardening, aws). 0 = auto, 1 = off.
    #[arg(long, default_value_t = DEFAULT_PARALLEL_JOBS, value_name = "JOBS")]
    pub parallel_jobs: usize,

    /// Ignore a finding whose message contains this text (repeatable or comma-separated).
    /// Prefix with a stage id to scope it, e.g. `docker:mounts the Docker socket`.
    #[arg(long = "allow-finding", value_name = "PATTERN")]
    pub allow_finding: Vec<String>,

    /// File with one exception pattern per line. Empty lines and `#` comments are ignored.
    #[arg(long = "exceptions-file", value_name = "PATH")]
    pub exceptions_file: Option<PathBuf>,
    /// List stage names and exit.
    #[arg(long)]
    pub list_stages: bool,

    /// Enable notifications after the audit (requires the `notifications` feature).
    #[arg(long)]
    pub notify: bool,

    /// Minimum severity that triggers a notification when using the built-in heuristic.
    #[arg(
        long,
        env = "NOTIFY_ON",
        value_enum,
        default_value = "high",
        value_name = "SEVERITY"
    )]
    pub notify_on: Severity,

    /// Notify even when the heuristic finds nothing (laya can still veto).
    #[arg(long)]
    pub notify_always: bool,

    /// Slack incoming-webhook URL. Prefer the environment variable.
    #[arg(long, env = "SLACK_WEBHOOK_URL", hide_env_values = true)]
    pub slack_webhook: Option<String>,

    /// Telegram bot token. Prefer the environment variable.
    #[arg(long, env = "TELEGRAM_BOT_TOKEN", hide_env_values = true)]
    pub telegram_bot_token: Option<String>,

    /// Telegram chat id. Prefer the environment variable.
    #[arg(long, env = "TELEGRAM_CHAT_ID", hide_env_values = true)]
    pub telegram_chat_id: Option<String>,

    /// Enable local-model triage (requires the `laya` feature).
    #[arg(long)]
    pub laya: bool,

    /// Base URL for the optional OpenAI-compatible model server. Ignored by the in-process backend.
    #[arg(
        long,
        env = "LAYA_URL",
        default_value = "http://127.0.0.1:8080/v1",
        value_name = "URL"
    )]
    pub laya_url: String,

    /// Laya checkpoint directory (in-process) or model name understood by a model server.
    #[arg(
        long,
        env = "LAYA_MODEL",
        default_value = "models/laya-base",
        value_name = "MODEL"
    )]
    pub laya_model: String,

    /// Triage backend: in-process Laya inference, or an OpenAI-compatible model server.
    #[arg(long, env = "LAYA_API", value_enum, default_value = "laya")]
    pub laya_api: LayaApi,

    /// Optional bearer token for OpenAI-compatible servers. Ignored by the in-process backend.
    #[arg(long, env = "LAYA_API_KEY", hide_env_values = true)]
    pub laya_api_key: Option<String>,

    /// HTTP request timeout for server backends in seconds. Ignored by the in-process backend.
    #[arg(long, default_value_t = DEFAULT_LAYA_TIMEOUT_SECS, value_name = "SECS")]
    pub laya_timeout: u64,

    /// Allow sending the audit summary to a non-loopback server backend.
    #[arg(long)]
    pub laya_allow_remote: bool,

    /// Maximum characters of audit context sent to the local model.
    #[arg(long, default_value_t = DEFAULT_LAYA_MAX_CHARS, value_name = "CHARS")]
    pub laya_max_chars: usize,

    /// Maximum Laya sequence tokens. Checkpoints ship with 1024; the encoder reads up to 8192.
    #[arg(long, env = "LAYA_MAX_TOKENS", default_value_t = DEFAULT_LAYA_MAX_TOKENS, value_name = "TOKENS")]
    pub laya_max_tokens: usize,
}

impl Cli {
    pub fn into_config(self) -> Result<Config> {
        let notify_enabled = self.notify || env_flag("NOTIFY_ENABLED");
        let laya_enabled = self.laya || env_flag("LAYA_ENABLED");
        let laya_allow_remote = self.laya_allow_remote || env_flag("LAYA_ALLOW_REMOTE");

        let mut exception_patterns = self.allow_finding;
        if let Some(path) = self.exceptions_file {
            // A missing or unreadable allowlist must be an error: silently ignoring it would make
            // the audit report findings the operator believes are already suppressed.
            let read_error = |error: std::io::Error| {
                Error::config(format!(
                    "could not read --exceptions-file `{}`: {error}",
                    path.display()
                ))
            };
            let metadata = std::fs::metadata(&path).map_err(read_error)?;
            if metadata.len() > crate::constants::ONE_MIB as u64 {
                return Err(Error::config(format!(
                    "--exceptions-file `{}` is larger than 1 MiB",
                    path.display()
                )));
            }
            let text = std::fs::read_to_string(&path).map_err(read_error)?;
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                exception_patterns.push(line.to_owned());
            }
        }

        let skip = self.skip.into_iter().collect::<BTreeSet<_>>();
        let only = if self.only.is_empty() {
            None
        } else {
            Some(self.only.into_iter().collect::<BTreeSet<_>>())
        };

        let clamav_paths = if self.clamav_paths.is_empty() {
            vec![
                PathBuf::from("/var/lib/docker/volumes"),
                PathBuf::from("/tmp"),
                PathBuf::from("/var/tmp"),
                PathBuf::from("/dev/shm"),
            ]
        } else {
            self.clamav_paths
        };

        Ok(Config {
            output_dir: self.output_dir,
            lock_file: self.lock_file.unwrap_or_else(default_lock_path),
            no_lock: self.no_lock,
            global_timeout: Duration::from_secs(self.timeout),
            command_timeout: self
                .command_timeout
                .filter(|seconds| *seconds > 0)
                .map(Duration::from_secs),
            max_output_bytes: self.max_output_bytes,
            install_deps: self.install_deps,
            fail_fast: self.fail_fast,
            fail_on: self.fail_on,
            dry_run: self.dry_run,
            json: self.json,
            quiet: self.quiet,
            verbose: self.verbose,
            color: self.color,
            sudo_mode: self.sudo_mode,
            skip,
            only,
            clamav_paths,
            web_log_paths: self.web_log_paths,
            auth_log_paths: self.auth_log_paths,
            log_tail_bytes: self.log_tail_bytes,
            parallel_jobs: self.parallel_jobs,
            exception_patterns,
            notify_enabled,
            notify_on: self.notify_on,
            notify_always: self.notify_always,
            slack_webhook: clean_secret(self.slack_webhook),
            telegram_bot_token: clean_secret(self.telegram_bot_token),
            telegram_chat_id: clean_secret(self.telegram_chat_id),
            laya_enabled,
            laya_url: self.laya_url,
            laya_model: self.laya_model,
            laya_api: self.laya_api,
            laya_api_key: clean_secret(self.laya_api_key),
            laya_timeout: Duration::from_secs(self.laya_timeout),
            laya_allow_remote,
            laya_max_chars: self.laya_max_chars,
            laya_max_tokens: self.laya_max_tokens,
        })
    }
}

fn clean_secret(value: Option<String>) -> Option<String> {
    value.map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
}

pub fn print_stages() {
    println!("Available stages:");
    for stage in StageId::ALL {
        match stage.artifact() {
            Some(artifact) => println!(
                "  {:<12} {}  (artifact: {artifact})",
                stage_value(stage),
                stage.title()
            ),
            None => println!("  {:<12} {}", stage_value(stage), stage.title()),
        }
    }
}

fn stage_value(stage: StageId) -> &'static str {
    stage.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Config {
        let mut argv = vec!["rs-security-checker"];
        argv.extend_from_slice(args);
        Cli::try_parse_from(argv).unwrap().into_config().unwrap()
    }

    #[test]
    fn defaults_map_to_a_safe_config() {
        let cfg = parse(&[]);
        assert_eq!(cfg.output_dir, PathBuf::from("."));
        assert_eq!(
            cfg.global_timeout,
            Duration::from_secs(DEFAULT_GLOBAL_TIMEOUT_SECS)
        );
        assert_eq!(cfg.command_timeout, None);
        assert_eq!(cfg.max_output_bytes, DEFAULT_MAX_OUTPUT_BYTES);
        assert_eq!(cfg.clamav_paths.len(), 4);
        assert!(cfg.web_log_paths.is_empty());
        assert!(cfg.auth_log_paths.is_empty());
        assert_eq!(cfg.log_tail_bytes, DEFAULT_LOG_TAIL_BYTES);
        assert_eq!(cfg.parallel_jobs, DEFAULT_PARALLEL_JOBS);
        assert!(!cfg.install_deps);
        assert!(!cfg.dry_run);
        assert!(!cfg.notify_enabled);
        assert!(!cfg.laya_enabled);
        assert!(!cfg.laya_allow_remote);
        assert_eq!(cfg.laya_api, LayaApi::Laya);
        assert_eq!(cfg.laya_model, "models/laya-base");
    }

    #[test]
    fn flags_are_mapped_to_config_fields() {
        let cfg = parse(&[
            "--output-dir",
            "/tmp/out",
            "--timeout",
            "10",
            "--command-timeout",
            "5",
            "--max-output-bytes",
            "2048",
            "--install-deps",
            "--fail-fast",
            "--fail-on",
            "high",
            "--dry-run",
            "--json",
            "--quiet",
            "--color",
            "never",
            "--sudo-mode",
            "never",
            "--skip",
            "precheck",
            "--only",
            "network,docker",
            "--clamav-path",
            "/tmp",
            "--web-log",
            "/var/log/nginx",
            "--auth-log",
            "/var/log/auth.log",
            "--log-tail-bytes",
            "2048",
            "--parallel-jobs",
            "3",
            "--notify",
            "--notify-on",
            "medium",
            "--notify-always",
            "--slack-webhook",
            " https://example.invalid ",
            "--telegram-chat-id",
            "42",
            "--laya",
            "--laya-model",
            "demo",
            "--laya-api",
            "openai",
            "--laya-api-key",
            " key ",
            "--laya-timeout",
            "5",
            "--laya-allow-remote",
            "--laya-max-chars",
            "300",
            "--laya-max-tokens",
            "2048",
        ]);

        assert_eq!(cfg.output_dir, PathBuf::from("/tmp/out"));
        assert_eq!(cfg.global_timeout, Duration::from_secs(10));
        assert_eq!(cfg.command_timeout, Some(Duration::from_secs(5)));
        assert_eq!(cfg.max_output_bytes, 2048);
        assert!(cfg.install_deps);
        assert!(cfg.fail_fast);
        assert_eq!(cfg.fail_on, Some(Severity::High));
        assert!(cfg.dry_run);
        assert!(cfg.json);
        assert!(cfg.quiet);
        assert_eq!(cfg.color, ColorMode::Never);
        assert_eq!(cfg.sudo_mode, SudoMode::Never);
        assert!(cfg.skip.contains(&StageId::Precheck));
        assert_eq!(
            cfg.only,
            Some([StageId::Docker, StageId::Network].into_iter().collect())
        );
        assert_eq!(cfg.clamav_paths, vec![PathBuf::from("/tmp")]);
        assert_eq!(cfg.web_log_paths, vec![PathBuf::from("/var/log/nginx")]);
        assert_eq!(cfg.auth_log_paths, vec![PathBuf::from("/var/log/auth.log")]);
        assert_eq!(cfg.log_tail_bytes, 2048);
        assert_eq!(cfg.parallel_jobs, 3);
        assert!(cfg.notify_enabled);
        assert_eq!(cfg.notify_on, Severity::Medium);
        assert!(cfg.notify_always);
        assert_eq!(
            cfg.slack_webhook.as_deref(),
            Some("https://example.invalid")
        );
        assert_eq!(cfg.telegram_chat_id.as_deref(), Some("42"));
        assert!(cfg.laya_enabled);
        assert_eq!(cfg.laya_model, "demo");
        assert_eq!(cfg.laya_api, LayaApi::Openai);
        assert_eq!(cfg.laya_api_key.as_deref(), Some("key"));
        assert_eq!(cfg.laya_timeout, Duration::from_secs(5));
        assert!(cfg.laya_allow_remote);
        assert_eq!(cfg.laya_max_chars, 300);
        assert_eq!(cfg.laya_max_tokens, 2048);
    }

    #[test]
    fn zero_command_timeout_disables_the_per_command_limit() {
        let cfg = parse(&["--command-timeout", "0"]);
        assert_eq!(cfg.command_timeout, None);
    }

    #[test]
    fn blank_secrets_are_discarded() {
        let cfg = parse(&[
            "--slack-webhook",
            "   ",
            "--telegram-bot-token",
            "",
            "--telegram-chat-id",
            "   ",
            "--laya-api-key",
            "",
        ]);
        assert_eq!(cfg.slack_webhook, None);
        assert_eq!(cfg.telegram_bot_token, None);
        assert_eq!(cfg.telegram_chat_id, None);
        assert_eq!(cfg.laya_api_key, None);
    }

    #[test]
    fn exceptions_file_is_read_and_comments_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("exceptions.txt");
        std::fs::write(
            &path,
            "# a comment\n\ndocker:mounts the socket\n  network:public port  \n",
        )
        .unwrap();

        let cfg = parse(&[
            "--exceptions-file",
            path.to_str().unwrap(),
            "--allow-finding",
            "global-pattern",
        ]);
        assert_eq!(
            cfg.exception_patterns,
            vec![
                "global-pattern",
                "docker:mounts the socket",
                "network:public port"
            ]
        );
    }

    #[test]
    fn unreadable_exceptions_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.txt");
        let cli = Cli::try_parse_from([
            "rs-security-checker",
            "--exceptions-file",
            missing.to_str().unwrap(),
        ])
        .unwrap();

        let error = cli.into_config().unwrap_err().to_string();
        assert!(
            error.contains("could not read --exceptions-file"),
            "{error}"
        );
    }

    #[test]
    fn list_stages_flag_is_parsed() {
        let cli = Cli::try_parse_from(["rs-security-checker", "--list-stages"]).unwrap();
        assert!(cli.list_stages);
    }

    #[test]
    fn print_stages_covers_every_stage() {
        print_stages();
    }
}
