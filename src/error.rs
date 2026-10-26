//! Error types shared by the CLI, the audit engine and the optional integrations.

use std::io;
use std::path::PathBuf;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid configuration: {0}")]
    Config(String),

    // Only reachable from builds that lack at least one optional feature; with both compiled
    // there is nothing left to reject.
    #[cfg_attr(all(feature = "laya", feature = "notifications"), allow(dead_code))]
    #[error("feature `{feature}` is not compiled in; rebuild with `--features {feature}`")]
    FeatureDisabled { feature: &'static str },

    #[error("another audit instance already holds the lock `{0}`")]
    Locked(PathBuf),

    #[cfg(any(feature = "laya", feature = "notifications"))]
    #[error("HTTP request failed: {0}")]
    Http(String),

    #[cfg(feature = "laya")]
    #[error("local model returned an invalid response: {0}")]
    LayaResponse(String),
}

impl Error {
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    #[cfg(any(feature = "laya", feature = "notifications"))]
    pub fn http(message: impl Into<String>) -> Self {
        Self::Http(message.into())
    }
}
