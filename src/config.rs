//! Runtime configuration assembled from CLI flags and environment variables.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::exec::SudoMode;
use crate::report::{Severity, StageId};
use crate::ui::ColorMode;

pub use crate::constants::{
    DEFAULT_GLOBAL_TIMEOUT_SECS, DEFAULT_LAYA_MAX_CHARS, DEFAULT_LAYA_MAX_TOKENS,
    DEFAULT_LAYA_TIMEOUT_SECS, DEFAULT_LOG_TAIL_BYTES, DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_PARALLEL_JOBS, MAX_GLOBAL_TIMEOUT_SECS, MAX_PARALLEL_JOBS,
};
#[cfg(feature = "laya")]
pub use crate::constants::{MAX_LAYA_MAX_TOKENS, MIN_LAYA_MAX_CHARS, MIN_LAYA_MAX_TOKENS};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum LayaApi {
    /// In-process Laya typed-decision inference. No model server is required.
    Laya,
    /// OpenAI-compatible `/v1/chat/completions` endpoint.
    Openai,
}

impl LayaApi {
    #[cfg_attr(not(feature = "laya"), allow(dead_code))]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Laya => "laya",
            Self::Openai => "openai",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub output_dir: PathBuf,
    pub lock_file: PathBuf,
    pub no_lock: bool,
    pub global_timeout: Duration,
    pub command_timeout: Option<Duration>,
    pub max_output_bytes: usize,
    pub install_deps: bool,
    pub fail_fast: bool,
    pub fail_on: Option<Severity>,
    pub dry_run: bool,
    pub json: bool,
    pub quiet: bool,
    pub verbose: bool,
    pub color: ColorMode,
    pub sudo_mode: SudoMode,
    pub skip: BTreeSet<StageId>,
    pub only: Option<BTreeSet<StageId>>,
    pub clamav_paths: Vec<PathBuf>,
    /// Extra web-server log files or directories. Empty means the built-in Debian paths.
    pub web_log_paths: Vec<PathBuf>,
    /// Extra authentication log files or directories. Empty means the built-in Debian paths.
    pub auth_log_paths: Vec<PathBuf>,
    /// Maximum bytes read from the tail of each log file.
    pub log_tail_bytes: usize,
    /// Worker count for lightweight analysis stages. `0` means automatic.
    pub parallel_jobs: usize,
    /// False-positive exception patterns. A pattern beginning with `<stage>:` only applies
    /// to that stage; otherwise it applies to every stage. Matching is case-insensitive and
    /// uses substring containment against finding messages.
    pub exception_patterns: Vec<String>,
    pub notify_enabled: bool,
    #[cfg_attr(not(feature = "notifications"), allow(dead_code))]
    pub notify_on: Severity,
    #[cfg_attr(not(feature = "notifications"), allow(dead_code))]
    pub notify_always: bool,
    #[cfg_attr(not(feature = "notifications"), allow(dead_code))]
    pub slack_webhook: Option<String>,
    #[cfg_attr(not(feature = "notifications"), allow(dead_code))]
    pub telegram_bot_token: Option<String>,
    #[cfg_attr(not(feature = "notifications"), allow(dead_code))]
    pub telegram_chat_id: Option<String>,

    pub laya_enabled: bool,
    #[cfg_attr(not(feature = "laya"), allow(dead_code))]
    pub laya_url: String,
    #[cfg_attr(not(feature = "laya"), allow(dead_code))]
    pub laya_model: String,
    #[cfg_attr(not(feature = "laya"), allow(dead_code))]
    pub laya_api: LayaApi,
    #[cfg_attr(not(feature = "laya"), allow(dead_code))]
    pub laya_api_key: Option<String>,
    #[cfg_attr(not(feature = "laya"), allow(dead_code))]
    pub laya_timeout: Duration,
    #[cfg_attr(not(feature = "laya"), allow(dead_code))]
    pub laya_allow_remote: bool,
    #[cfg_attr(not(feature = "laya"), allow(dead_code))]
    pub laya_max_chars: usize,
    #[cfg_attr(not(feature = "laya"), allow(dead_code))]
    pub laya_max_tokens: usize,
}

impl Config {
    pub fn selected_stages(&self) -> Vec<StageId> {
        StageId::ALL
            .into_iter()
            .filter(|stage| {
                self.only
                    .as_ref()
                    .is_none_or(|selection| selection.contains(stage))
                    && !self.skip.contains(stage)
            })
            .collect()
    }

    pub fn validate(&self) -> Result<()> {
        if self.global_timeout.is_zero() {
            return Err(Error::config("--timeout must be greater than zero"));
        }
        if self.global_timeout > Duration::from_secs(MAX_GLOBAL_TIMEOUT_SECS) {
            return Err(Error::config(format!(
                "--timeout must be at most {MAX_GLOBAL_TIMEOUT_SECS} seconds"
            )));
        }
        if self.selected_stages().is_empty() {
            return Err(Error::config(
                "no audit stages selected; check --only/--skip",
            ));
        }
        if self.max_output_bytes < 1024 {
            return Err(Error::config("--max-output-bytes must be at least 1024"));
        }
        if self.log_tail_bytes < 1024 {
            return Err(Error::config("--log-tail-bytes must be at least 1024"));
        }
        if self.parallel_jobs > MAX_PARALLEL_JOBS {
            return Err(Error::config(format!(
                "--parallel-jobs must be at most {MAX_PARALLEL_JOBS}"
            )));
        }

        if self.notify_enabled {
            #[cfg(not(feature = "notifications"))]
            return Err(Error::FeatureDisabled {
                feature: "notifications",
            });

            #[cfg(feature = "notifications")]
            {
                let slack = self
                    .slack_webhook
                    .as_deref()
                    .is_some_and(|v| !v.trim().is_empty());
                let telegram_token = self
                    .telegram_bot_token
                    .as_deref()
                    .is_some_and(|v| !v.trim().is_empty());
                let telegram_chat = self
                    .telegram_chat_id
                    .as_deref()
                    .is_some_and(|v| !v.trim().is_empty());
                if !slack && !telegram_token && !telegram_chat {
                    return Err(Error::config(
                        "--notify requires SLACK_WEBHOOK_URL or TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID",
                    ));
                }
                if telegram_token != telegram_chat {
                    return Err(Error::config(
                        "Telegram needs both TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID",
                    ));
                }
            }
        }

        if self.laya_enabled {
            #[cfg(not(feature = "laya"))]
            return Err(Error::FeatureDisabled { feature: "laya" });

            #[cfg(feature = "laya")]
            {
                if self.laya_model.trim().is_empty() {
                    return Err(Error::config(
                        "LAYA_MODEL must be a model name or a Laya checkpoint directory",
                    ));
                }
                // The in-process backend never contacts a URL. URL, timeout and
                // remote-endpoint policy only apply to the OpenAI-compatible server.
                if self.laya_api != LayaApi::Laya {
                    if !(self.laya_url.starts_with("http://")
                        || self.laya_url.starts_with("https://"))
                    {
                        return Err(Error::config(
                            "LAYA_URL must start with http:// or https://",
                        ));
                    }
                    if !self.laya_allow_remote && !is_loopback_url(&self.laya_url) {
                        return Err(Error::config(
                            "refusing to send audit data to a non-loopback model endpoint; pass --laya-allow-remote to override",
                        ));
                    }
                    if self.laya_timeout.is_zero() {
                        return Err(Error::config("--laya-timeout must be greater than zero"));
                    }
                }
                if self.laya_max_chars < MIN_LAYA_MAX_CHARS {
                    return Err(Error::config(format!(
                        "--laya-max-chars must be at least {MIN_LAYA_MAX_CHARS}"
                    )));
                }
                if !(MIN_LAYA_MAX_TOKENS..=MAX_LAYA_MAX_TOKENS).contains(&self.laya_max_tokens) {
                    return Err(Error::config(format!(
                        "--laya-max-tokens must be between {MIN_LAYA_MAX_TOKENS} and {MAX_LAYA_MAX_TOKENS}"
                    )));
                }
            }
        }

        Ok(())
    }
}

/// Whether `host` names the local machine: `localhost`, a `*.localhost` name or a loopback IP.
pub fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_matches(['[', ']']);
    host.eq_ignore_ascii_case("localhost")
        || host.ends_with(".localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

/// Best-effort loopback check used before the feature-gated `url` parser is available.
#[cfg_attr(not(feature = "laya"), allow(dead_code))]
pub fn is_loopback_url(raw: &str) -> bool {
    let authority = raw
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(raw)
        .split('/')
        .next()
        .unwrap_or_default();
    // Drop any `user:password@` prefix before parsing the host.
    let authority = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority);
    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next().unwrap_or_default()
    } else {
        authority
            .rsplit_once(':')
            .map(|(host, _)| host)
            .unwrap_or(authority)
    };
    is_loopback_host(host)
}

pub fn default_lock_path() -> PathBuf {
    if nix::unistd::Uid::effective().is_root() {
        PathBuf::from("/var/run/security_audit.lock")
    } else {
        std::env::temp_dir().join("security_audit.lock")
    }
}

/// Parse a boolean environment variable, accepting the usual truthy spellings.
pub fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

#[cfg(test)]
pub(crate) fn test_config() -> Config {
    Config {
        output_dir: PathBuf::from("."),
        lock_file: std::env::temp_dir().join("rs-security-checker-test.lock"),
        no_lock: true,
        global_timeout: Duration::from_secs(60),
        command_timeout: None,
        max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
        install_deps: false,
        fail_fast: false,
        fail_on: None,
        dry_run: false,
        json: false,
        quiet: true,
        verbose: false,
        color: ColorMode::Never,
        sudo_mode: SudoMode::Never,
        skip: BTreeSet::new(),
        only: None,
        clamav_paths: Vec::new(),
        web_log_paths: Vec::new(),
        auth_log_paths: Vec::new(),
        log_tail_bytes: DEFAULT_LOG_TAIL_BYTES,
        parallel_jobs: DEFAULT_PARALLEL_JOBS,
        exception_patterns: Vec::new(),
        notify_enabled: false,
        notify_on: Severity::High,
        notify_always: false,
        slack_webhook: None,
        telegram_bot_token: None,
        telegram_chat_id: None,
        laya_enabled: false,
        laya_url: "http://127.0.0.1:8080/v1".to_owned(),
        laya_model: "models/laya-base".to_owned(),
        laya_api: LayaApi::Laya,
        laya_api_key: None,
        laya_timeout: Duration::from_secs(10),
        laya_allow_remote: false,
        laya_max_chars: DEFAULT_LAYA_MAX_CHARS,
        laya_max_tokens: DEFAULT_LAYA_MAX_TOKENS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> Config {
        test_config()
    }

    #[test]
    fn stage_selection_respects_only_and_skip() {
        let mut config = base_config();
        config.only = Some([StageId::Docker, StageId::Clamav].into_iter().collect());
        config.skip = [StageId::Clamav].into_iter().collect();
        assert_eq!(config.selected_stages(), vec![StageId::Docker]);
    }

    #[test]
    fn empty_selection_is_rejected() {
        let mut config = base_config();
        config.skip = StageId::ALL.into_iter().collect();
        assert!(config.validate().is_err());
    }

    #[test]
    fn loopback_detection_covers_common_forms() {
        assert!(is_loopback_url("http://127.0.0.1:8080"));
        assert!(is_loopback_url("http://localhost:8080/v1"));
        assert!(is_loopback_url("http://[::1]:8080"));
        assert!(is_loopback_url("http://user:secret@localhost:8080/v1"));
        assert!(is_loopback_url("https://LOCALHOST"));
        assert!(is_loopback_url("https://triage.localhost/v1"));
        assert!(is_loopback_url("localhost"));
        assert!(!is_loopback_url("http://192.168.1.10:8080"));
        assert!(!is_loopback_url("http://user:secret@192.168.1.10:8080"));
        assert!(!is_loopback_url("https://example.com"));
        assert!(!is_loopback_url("http://127.0.0.1.example.com"));
    }

    #[test]
    fn defaults_validate() {
        assert!(test_config().validate().is_ok());
    }

    #[test]
    fn global_timeout_must_be_positive_and_bounded() {
        let mut cfg = test_config();
        cfg.global_timeout = Duration::ZERO;
        assert!(cfg.validate().is_err());

        cfg.global_timeout = Duration::from_secs(MAX_GLOBAL_TIMEOUT_SECS);
        assert!(cfg.validate().is_ok());
        cfg.global_timeout = Duration::from_secs(MAX_GLOBAL_TIMEOUT_SECS + 1);
        assert!(cfg.validate().is_err());
    }

    #[cfg(feature = "laya")]
    #[test]
    fn laya_max_chars_must_leave_usable_context() {
        let mut cfg = test_config();
        cfg.laya_enabled = true;
        cfg.laya_max_chars = MIN_LAYA_MAX_CHARS - 1;
        assert!(cfg.validate().is_err());
        cfg.laya_max_chars = MIN_LAYA_MAX_CHARS;
        assert!(cfg.validate().is_ok());
    }

    #[cfg(feature = "laya")]
    #[test]
    fn laya_max_tokens_must_fit_the_encoder_window() {
        let mut cfg = test_config();
        cfg.laya_enabled = true;
        cfg.laya_max_tokens = MIN_LAYA_MAX_TOKENS - 1;
        assert!(cfg.validate().is_err());
        cfg.laya_max_tokens = MIN_LAYA_MAX_TOKENS;
        assert!(cfg.validate().is_ok());
        cfg.laya_max_tokens = MAX_LAYA_MAX_TOKENS;
        assert!(cfg.validate().is_ok());
        cfg.laya_max_tokens = MAX_LAYA_MAX_TOKENS + 1;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn output_limit_must_be_reasonable() {
        let mut cfg = test_config();
        cfg.max_output_bytes = 1023;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn log_tail_limit_must_be_reasonable() {
        let mut cfg = test_config();
        cfg.log_tail_bytes = 1023;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn parallel_jobs_accepts_auto_and_rejects_excessive_values() {
        let mut cfg = test_config();
        cfg.parallel_jobs = 0;
        assert!(cfg.validate().is_ok());
        cfg.parallel_jobs = MAX_PARALLEL_JOBS;
        assert!(cfg.validate().is_ok());
        cfg.parallel_jobs = MAX_PARALLEL_JOBS + 1;
        assert!(cfg.validate().is_err());
    }

    #[cfg(not(feature = "notifications"))]
    #[test]
    fn notifications_require_the_feature() {
        let mut cfg = test_config();
        cfg.notify_enabled = true;
        assert!(matches!(cfg.validate(), Err(Error::FeatureDisabled { .. })));
    }

    #[cfg(feature = "notifications")]
    #[test]
    fn notifications_require_a_configured_channel() {
        let mut cfg = test_config();
        cfg.notify_enabled = true;
        assert!(matches!(cfg.validate(), Err(Error::Config(_))));
    }

    #[cfg(feature = "notifications")]
    #[test]
    fn slack_alone_satisfies_notifications() {
        let mut cfg = test_config();
        cfg.notify_enabled = true;
        cfg.slack_webhook = Some("https://hooks.slack.com/services/demo".into());
        assert!(cfg.validate().is_ok());
    }

    #[cfg(feature = "notifications")]
    #[test]
    fn telegram_pair_satisfies_notifications() {
        let mut cfg = test_config();
        cfg.notify_enabled = true;
        cfg.telegram_bot_token = Some("token".into());
        cfg.telegram_chat_id = Some("42".into());
        assert!(cfg.validate().is_ok());
    }

    #[cfg(feature = "notifications")]
    #[test]
    fn telegram_requires_both_values() {
        let mut cfg = test_config();
        cfg.notify_enabled = true;
        cfg.telegram_bot_token = Some("token".into());
        assert!(matches!(cfg.validate(), Err(Error::Config(_))));

        cfg.telegram_chat_id = Some("42".into());
        cfg.telegram_bot_token = None;
        assert!(matches!(cfg.validate(), Err(Error::Config(_))));
    }

    #[cfg(not(feature = "laya"))]
    #[test]
    fn laya_requires_the_feature() {
        let mut cfg = test_config();
        cfg.laya_enabled = true;
        assert!(matches!(cfg.validate(), Err(Error::FeatureDisabled { .. })));
    }

    #[cfg(feature = "laya")]
    #[test]
    fn laya_url_must_use_http_and_have_a_host_for_server_backends() {
        let mut cfg = test_config();
        cfg.laya_enabled = true;
        cfg.laya_api = LayaApi::Openai;

        cfg.laya_url = "ftp://127.0.0.1:8080".into();
        assert!(cfg.validate().is_err());

        cfg.laya_url = "not a url".into();
        assert!(cfg.validate().is_err());

        cfg.laya_url = "http://127.0.0.1:8080".into();
        assert!(cfg.validate().is_ok());
    }

    #[cfg(feature = "laya")]
    #[test]
    fn server_backends_reject_remote_endpoints_unless_allowed() {
        let mut cfg = test_config();
        cfg.laya_enabled = true;
        cfg.laya_api = LayaApi::Openai;

        cfg.laya_url = "http://192.168.1.10:8080".into();
        assert!(cfg.validate().is_err());

        cfg.laya_allow_remote = true;
        assert!(cfg.validate().is_ok());
    }

    #[cfg(feature = "laya")]
    #[test]
    fn local_laya_backend_ignores_the_model_url() {
        let mut cfg = test_config();
        cfg.laya_enabled = true;
        cfg.laya_api = LayaApi::Laya;
        cfg.laya_url = "http://192.168.1.10:8080".into();
        cfg.laya_model = "models/laya-base".into();
        assert!(cfg.validate().is_ok());
    }

    #[cfg(feature = "laya")]
    #[test]
    fn laya_model_must_not_be_empty() {
        let mut cfg = test_config();
        cfg.laya_enabled = true;
        cfg.laya_model = "  ".into();
        assert!(cfg.validate().is_err());
    }

    #[cfg(feature = "laya")]
    #[test]
    fn laya_timeout_must_be_positive_for_server_backends() {
        let mut cfg = test_config();
        cfg.laya_enabled = true;
        cfg.laya_api = LayaApi::Openai;
        cfg.laya_timeout = Duration::ZERO;
        assert!(cfg.validate().is_err());

        // The in-process backend has no HTTP timeout, so the value is irrelevant there.
        cfg.laya_api = LayaApi::Laya;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn env_flag_accepts_common_truthy_spellings() {
        const NAME: &str = "RS_SECURITY_CHECKER_TEST_FLAG";
        for value in ["1", "true", "YES", " on "] {
            // SAFETY: the variable name is unique to this test.
            unsafe { std::env::set_var(NAME, value) };
            assert!(env_flag(NAME), "expected `{value}` to be truthy");
        }
        for value in ["0", "false", "", "off"] {
            // SAFETY: the variable name is unique to this test.
            unsafe { std::env::set_var(NAME, value) };
            assert!(!env_flag(NAME), "expected `{value}` to be falsy");
        }
        // SAFETY: the variable name is unique to this test.
        unsafe { std::env::remove_var(NAME) };
        assert!(!env_flag(NAME));
    }

    #[test]
    fn default_lock_path_is_non_empty() {
        assert!(!default_lock_path().as_os_str().is_empty());
    }

    #[test]
    fn laya_api_names_match_the_wire_protocol() {
        assert_eq!(LayaApi::Laya.as_str(), "laya");
        assert_eq!(LayaApi::Openai.as_str(), "openai");
    }
}
