//! QS-004 — Telemetry: Prometheus metrics, OpenTelemetry tracing, health types.
//!
//! # Usage
//!
//! ```rust,ignore
//! use qshield_common::telemetry::{TelemetryConfig, install_prometheus, init_tracing};
//!
//! let prom = install_prometheus("my-service")?;
//! init_tracing(&TelemetryConfig::minimal("my-service"))?;
//! ```

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use opentelemetry_sdk::trace::SdkTracerProvider;
use serde::Serialize;
use std::sync::OnceLock;

use crate::QShieldError;

static TRACER_PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();

// ── Config ────────────────────────────────────────────────────────────────────

/// Telemetry initialisation configuration.
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    /// `service.name` OTel resource attribute and Prometheus global label.
    pub service_name: &'static str,
    /// OTLP HTTP base URL for trace export, e.g. `http://otel-collector:4318`.
    /// When `None`, traces are not exported (local/dev mode).
    pub otlp_endpoint: Option<String>,
}

impl TelemetryConfig {
    /// Minimal config: service name only, no OTLP export.
    #[must_use]
    pub fn minimal(service_name: &'static str) -> Self {
        Self { service_name, otlp_endpoint: None }
    }

    /// Config with OTLP export enabled.
    #[must_use]
    pub fn with_otlp(service_name: &'static str, endpoint: impl Into<String>) -> Self {
        Self { service_name, otlp_endpoint: Some(endpoint.into()) }
    }
}

// ── Metrics ───────────────────────────────────────────────────────────────────

/// Install the Prometheus metrics recorder globally and return a handle.
///
/// The handle's `render()` method produces the payload for `GET /metrics`.
/// Call once at service startup. Subsequent calls will fail because a recorder
/// can only be installed once per process.
///
/// # Errors
/// Returns [`QShieldError::Internal`] if the recorder cannot be installed
/// (most likely because one was already installed).
pub fn install_prometheus(service_name: &'static str) -> Result<PrometheusHandle, QShieldError> {
    PrometheusBuilder::new()
        .with_recommended_naming(true)
        .add_global_label("service", service_name)
        .install_recorder()
        .map_err(|e| QShieldError::Internal { message: e.to_string() })
}

// ── Tracing ───────────────────────────────────────────────────────────────────

/// Initialise the global `tracing` subscriber.
///
/// Log level is read from the `RUST_LOG` environment variable (default: `info`).
/// Structured JSON is always emitted to stdout (12-factor app style).
///
/// When `cfg.otlp_endpoint` is `Some`, spans are additionally exported via
/// OTLP HTTP/JSON. The OTLP endpoint is `{cfg.otlp_endpoint}/v1/traces`.
///
/// # Errors
/// Returns [`QShieldError::Internal`] if the OTLP exporter fails to build or
/// if the tracing subscriber has already been initialised.
pub fn init_tracing(cfg: &TelemetryConfig) -> Result<(), QShieldError> {
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::{SpanExporter, WithExportConfig};
    use opentelemetry_sdk::trace::SdkTracerProvider;
    use tracing_opentelemetry::OpenTelemetryLayer;
    use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let fmt_layer = fmt::layer().json().flatten_event(true);

    if let Some(endpoint) = &cfg.otlp_endpoint {
        let resource = opentelemetry_sdk::Resource::builder_empty()
            .with_service_name(cfg.service_name)
            .build();

        let exporter = SpanExporter::builder()
            .with_http()
            .with_endpoint(format!("{}/v1/traces", endpoint.trim_end_matches('/')))
            .build()
            .map_err(|e| QShieldError::Internal { message: format!("OTLP exporter: {e}") })?;

        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter)
            .with_resource(resource)
            .build();

        let tracer = provider.tracer(cfg.service_name);

        TRACER_PROVIDER
            .set(provider)
            .map_err(|_| QShieldError::Internal { message: "tracer provider already set".into() })?;

        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .with(OpenTelemetryLayer::new(tracer))
            .try_init()
            .map_err(|e| QShieldError::Internal { message: format!("tracing init: {e}") })?;
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .try_init()
            .map_err(|e| QShieldError::Internal { message: format!("tracing init: {e}") })?;
    }

    Ok(())
}

/// Flush in-flight spans and shut down the OTel tracer provider.
///
/// Call during graceful shutdown, before the process exits.
pub fn shutdown_tracing() {
    if let Some(provider) = TRACER_PROVIDER.get() {
        if let Err(e) = provider.shutdown() {
            tracing::warn!("tracer provider shutdown error: {e}");
        }
    }
}

// ── Health types ──────────────────────────────────────────────────────────────

/// Outcome of a health check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Ok,
    Degraded,
}

/// Health check response body for `GET /healthz` and `GET /readyz`.
#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    pub status: HealthStatus,
    pub service: &'static str,
    pub version: &'static str,
}

impl HealthResponse {
    /// Liveness response (`/healthz`): always `ok` while the process is alive.
    #[must_use]
    pub fn alive(service: &'static str) -> Self {
        Self {
            status: HealthStatus::Ok,
            service,
            version: env!("CARGO_PKG_VERSION"),
        }
    }

    /// Readiness response (`/readyz`): `ok` when all dependencies are reachable,
    /// `degraded` otherwise.
    #[must_use]
    pub fn ready(service: &'static str, deps_ok: bool) -> Self {
        Self {
            status: if deps_ok { HealthStatus::Ok } else { HealthStatus::Degraded },
            service,
            version: env!("CARGO_PKG_VERSION"),
        }
    }

    /// HTTP status code matching this health status (`200` or `503`).
    #[must_use]
    pub fn http_status_code(&self) -> u16 {
        match self.status {
            HealthStatus::Ok => 200,
            HealthStatus::Degraded => 503,
        }
    }
}

// ── Axum handlers ─────────────────────────────────────────────────────────────

/// Axum handler for `GET /metrics`. Renders Prometheus-format text output.
///
/// Register on a router that has `PrometheusHandle` as state:
/// ```rust,ignore
/// let handle = install_prometheus("my-service")?;
/// Router::new()
///     .route("/metrics", get(metrics_handler))
///     .with_state(handle)
/// ```
pub async fn metrics_handler(
    axum::extract::State(handle): axum::extract::State<PrometheusHandle>,
) -> impl axum::response::IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        handle.render(),
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_response_alive_is_ok() {
        let r = HealthResponse::alive("test-svc");
        assert_eq!(r.status, HealthStatus::Ok);
        assert_eq!(r.http_status_code(), 200);
    }

    #[test]
    fn health_response_ready_degraded() {
        let r = HealthResponse::ready("test-svc", false);
        assert_eq!(r.status, HealthStatus::Degraded);
        assert_eq!(r.http_status_code(), 503);
    }

    #[test]
    fn health_response_serializes_correctly() {
        let r = HealthResponse::alive("test-svc");
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"status\":\"ok\""));
        assert!(json.contains("\"service\":\"test-svc\""));
    }

    #[test]
    fn telemetry_config_minimal() {
        let cfg = TelemetryConfig::minimal("svc");
        assert!(cfg.otlp_endpoint.is_none());
        assert_eq!(cfg.service_name, "svc");
    }

    #[test]
    fn telemetry_config_with_otlp() {
        let cfg = TelemetryConfig::with_otlp("svc", "http://localhost:4318");
        assert_eq!(cfg.otlp_endpoint.as_deref(), Some("http://localhost:4318"));
    }
}
