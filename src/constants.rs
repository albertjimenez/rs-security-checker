#![allow(dead_code)]

//! Centralized constants for `rs-security-checker`.
//!
//! The goal is one ownership point for shared magic numbers, paths, feature defaults,
//! IMDS addresses and external command strings. Stage modules keep their specialized
//! parser thresholds locally, while the values that cross module boundaries live here.

// ---------------------------------------------------------------------------
// Runtime defaults (used by the CLI and `Config`)
// ---------------------------------------------------------------------------

pub const DEFAULT_GLOBAL_TIMEOUT_SECS: u64 = 30 * 60;
/// Upper bound for `--timeout`. Prevents an overflowing `Instant + Duration` deadline.
pub const MAX_GLOBAL_TIMEOUT_SECS: u64 = 7 * 24 * 60 * 60;
pub const DEFAULT_LAYA_TIMEOUT_SECS: u64 = 120;
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
/// Chosen so even a truncated context (the marker included) fits the default 8,192-token
/// window under the naive estimate below: 21,000 bytes is ~7,700 estimated tokens, inside the
/// 7,928-token state budget left after the question head.
pub const DEFAULT_LAYA_MAX_CHARS: usize = 21_000;
/// Below this the model receives no usable audit context.
pub const MIN_LAYA_MAX_CHARS: usize = 256;
/// Laya checkpoints ship with a 512–1,024-token sequence budget, but the encoder reads up to
/// 8,192 positions. The checker raises the budget so long audit contexts are not silently cut.
pub const DEFAULT_LAYA_MAX_TOKENS: usize = 8_192;
pub const MIN_LAYA_MAX_TOKENS: usize = 256;
pub const MAX_LAYA_MAX_TOKENS: usize = 8_192;
/// Naive token estimate: Laya's tokenizer splits pretty-printed JSON at roughly 2.8 bytes per
/// token. Dividing by three and adding a safety margin keeps the guard conservative.
pub const LAYA_BYTES_PER_TOKEN: usize = 3;
pub const LAYA_TOKEN_SAFETY_PERCENT: usize = 10;
/// Warn when the estimated context uses at least this percentage of the state budget.
pub const LAYA_TOKEN_WARN_PERCENT: usize = 90;
/// Room for `[CLS]`/`[SEP]` tokens around the question head and state.
pub const LAYA_SPECIAL_TOKEN_RESERVE: usize = 8;
/// Bytes read from the end of each log file. Logs can be large; only the recent tail matters.
pub const DEFAULT_LOG_TAIL_BYTES: usize = 4 * 1024 * 1024;
/// Worker count for lightweight stages. `0` selects a conservative automatic value.
pub const DEFAULT_PARALLEL_JOBS: usize = 0;
/// Upper bound accepted from `--parallel-jobs` to keep audits predictable.
pub const MAX_PARALLEL_JOBS: usize = 32;

// ---------------------------------------------------------------------------
// Execution environment
// ---------------------------------------------------------------------------

/// Fixed `PATH` used for every child process.
pub const FIXED_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
/// Reserved user account used by the Debian/Ubuntu base image and several containers.
pub const ROOT_ACCOUNT: &str = "root";
/// Debian family identifiers accepted by the precheck stage.
pub const DEBIAN_OS_IDS: [&str; 2] = ["debian", "ubuntu"];

// ---------------------------------------------------------------------------
// AWS EC2 metadata service (link-local only)
// ---------------------------------------------------------------------------

pub const AWS_METADATA_ROOT: &str = "http://169.254.169.254/latest";
pub const AWS_INSTANCE_ID_URL: &str = "http://169.254.169.254/latest/meta-data/instance-id";
pub const AWS_TOKEN_URL: &str = "http://169.254.169.254/latest/api/token";
pub const AWS_INSTANCE_IDENTITY_DOCUMENT_URL: &str =
    "http://169.254.169.254/latest/dynamic/instance-identity/document";
/// Short-lived IMDSv2 token: the audit needs it for a handful of requests only.
pub const IMDS_TOKEN_TTL_SECONDS: &str = "60";

// ---------------------------------------------------------------------------
// Hardcoded external command templates shared across stages
// ---------------------------------------------------------------------------

pub const DOCKER_INSPECT_PRIVILEGED: &str =
    "docker inspect --format {{.Name}} {{.HostConfig.Privileged}}";
pub const DOCKER_INSPECT_MOUNTS: &str = "docker inspect --format {{json .Mounts}}";

// ---------------------------------------------------------------------------
// Shared limits
// ---------------------------------------------------------------------------

pub const ONE_MIB: usize = 1024 * 1024;
pub const EIGHT_MIB: usize = 8 * 1024 * 1024;
pub const FOUR_KIB: usize = 4 * 1024;
