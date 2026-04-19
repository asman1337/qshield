use std::fmt;

use chrono::{DateTime, Utc};
use thiserror::Error;
use uuid::Uuid;

/// The top-level error type shared across all QShield crates.
///
/// # Security
/// Error messages are deliberately kept vague for externally-visible variants.
/// Internal details (stack traces, key material, plaintext) MUST NOT be included.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum QShieldError {
    // ── Crypto (QS-1XX) ───────────────────────────────────────────────────────
    #[error("key generation failed for algorithm {algorithm}")]
    KeyGeneration {
        algorithm: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("encapsulation failed for algorithm {algorithm}")]
    Encapsulation { algorithm: &'static str },

    #[error("decapsulation failed")]
    Decapsulation { algorithm: &'static str },

    #[error("signature creation failed")]
    SignatureCreation { algorithm: &'static str },

    #[error("signature verification failed")]
    SignatureVerification { algorithm: &'static str },

    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("key derivation failed")]
    KeyDerivation { reason: &'static str },

    #[error("invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonce { expected: usize, actual: usize },

    #[error("unsupported algorithm: {name}")]
    UnsupportedAlgorithm { name: String },

    // ── Transport (QS-2XX) ────────────────────────────────────────────────────
    #[error("TLS handshake failed with {peer}")]
    TlsHandshake { peer: String, reason: String },

    #[error("upstream unreachable: {target}")]
    UpstreamUnreachable { target: String },

    #[error("certificate expired for {subject}")]
    CertificateExpired {
        subject: String,
        expiry: DateTime<Utc>,
    },

    // ── Vault (QS-3XX) ────────────────────────────────────────────────────────
    #[error("vault is locked")]
    VaultLocked,

    /// Deliberately vague — must not reveal whether the key, ciphertext, or tag was wrong.
    #[error("decryption failed")]
    DecryptionFailed,

    #[error("item not found: {item_id}")]
    ItemNotFound { item_id: Uuid },

    // ── Auth (QS-4XX) ─────────────────────────────────────────────────────────
    #[error("token has expired")]
    TokenExpired,

    #[error("token is invalid")]
    TokenInvalid,

    #[error("insufficient scope: required '{required}'")]
    InsufficientScope { required: String },

    #[error("unauthorized")]
    Unauthorized,

    // ── General ───────────────────────────────────────────────────────────────
    #[error("configuration error: {message}")]
    Config { message: String },

    #[error("database error")]
    Database(#[from] sqlx::Error),

    #[error("IO error")]
    Io(#[from] std::io::Error),

    /// For bugs — the message is logged server-side but never shown to clients.
    #[error("internal error")]
    Internal { message: String },
}

impl QShieldError {
    /// Returns the machine-readable error code for use in HTTP JSON responses.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::KeyGeneration { .. } => "KEY_GENERATION_FAILED",
            Self::Encapsulation { .. } => "ENCAPSULATION_FAILED",
            Self::Decapsulation { .. } => "DECAPSULATION_FAILED",
            Self::SignatureCreation { .. } => "SIGNATURE_CREATION_FAILED",
            Self::SignatureVerification { .. } => "SIGNATURE_VERIFICATION_FAILED",
            Self::InvalidKeyLength { .. } => "INVALID_KEY_LENGTH",
            Self::KeyDerivation { .. } => "KEY_DERIVATION_FAILED",
            Self::InvalidNonce { .. } => "INVALID_NONCE",
            Self::UnsupportedAlgorithm { .. } => "UNSUPPORTED_ALGORITHM",
            Self::TlsHandshake { .. } => "TLS_HANDSHAKE_FAILED",
            Self::UpstreamUnreachable { .. } => "UPSTREAM_UNREACHABLE",
            Self::CertificateExpired { .. } => "CERTIFICATE_EXPIRED",
            Self::VaultLocked => "VAULT_LOCKED",
            Self::DecryptionFailed => "DECRYPTION_FAILED",
            Self::ItemNotFound { .. } => "ITEM_NOT_FOUND",
            Self::TokenExpired => "TOKEN_EXPIRED",
            Self::TokenInvalid => "TOKEN_INVALID",
            Self::InsufficientScope { .. } => "INSUFFICIENT_SCOPE",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::Config { .. } => "CONFIG_ERROR",
            Self::Database(_) => "DATABASE_ERROR",
            Self::Io(_) => "IO_ERROR",
            Self::Internal { .. } => "INTERNAL_ERROR",
        }
    }

    /// HTTP status code appropriate for this error.
    #[must_use]
    pub fn http_status(&self) -> u16 {
        match self {
            Self::VaultLocked | Self::TokenExpired | Self::TokenInvalid | Self::Unauthorized => 401,
            Self::InsufficientScope { .. } => 403,
            Self::ItemNotFound { .. } => 404,
            Self::Config { .. } | Self::Internal { .. } | Self::Database(_) | Self::Io(_) => 500,
            _ => 400,
        }
    }

    /// Whether this error should be surfaced to the client with its message,
    /// or replaced with a generic "internal error" message.
    #[must_use]
    pub fn is_client_safe(&self) -> bool {
        !matches!(
            self,
            Self::Internal { .. } | Self::Database(_) | Self::Io(_)
        )
    }

    /// Build an `Internal` error from any displayable value.
    pub fn internal(msg: impl fmt::Display) -> Self {
        Self::Internal {
            message: msg.to_string(),
        }
    }
}

/// Serialisable error body for HTTP API responses.
///
/// ```json
/// {
///   "error": {
///     "code": "VAULT_LOCKED",
///     "message": "Vault is locked. Unlock with master password.",
///     "request_id": "01904d3a-..."
///   }
/// }
/// ```
#[derive(Debug, serde::Serialize)]
pub struct ErrorResponse {
    pub error: ErrorBody,
}

#[derive(Debug, serde::Serialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
    pub request_id: Uuid,
}

impl ErrorResponse {
    #[must_use]
    pub fn from_error(err: &QShieldError, request_id: Uuid) -> Self {
        let message = if err.is_client_safe() {
            err.to_string()
        } else {
            "An internal error occurred. Please try again or contact support.".into()
        };
        Self {
            error: ErrorBody {
                code: err.code().into(),
                message,
                request_id,
            },
        }
    }
}
