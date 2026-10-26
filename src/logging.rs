//! Structured, production-grade logging.
//!
//! Logs are emitted as newline-delimited JSON to stderr so they can be captured without
//! interfering with machine-readable audit output (`--json`) on stdout.

use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

pub fn init(verbose: bool, quiet: bool) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        if quiet {
            EnvFilter::new("error")
        } else if verbose {
            EnvFilter::new("debug")
        } else {
            EnvFilter::new("info")
        }
    });

    let fmt_layer = fmt::layer()
        .json()
        .with_current_span(true)
        .with_span_list(false)
        .with_writer(std::io::stderr);

    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .try_init();
}
