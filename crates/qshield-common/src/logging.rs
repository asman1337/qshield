use tracing_subscriber::{EnvFilter, fmt, prelude::*};

/// Initialise the global tracing subscriber for a QShield service.
///
/// Reads log level from the `RUST_LOG` environment variable.
/// Falls back to `info` in production and `debug` in debug builds.
///
/// Log format:
/// - In release builds: structured JSON (suitable for log aggregators)
/// - In debug builds: human-readable pretty format
///
/// # Panics
/// Panics if called more than once (tracing subscriber is already set).
pub fn init() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        if cfg!(debug_assertions) {
            EnvFilter::new("debug")
        } else {
            EnvFilter::new("info")
        }
    });

    if cfg!(debug_assertions) {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().pretty())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().json())
            .init();
    }
}

/// Initialise logging for tests — uses compact human-readable format.
/// Safe to call multiple times (subsequent calls are no-ops).
pub fn init_test() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug")),
        )
        .with_test_writer()
        .try_init();
}
