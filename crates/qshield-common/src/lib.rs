//! `qshield-common` — Shared types, error hierarchy, and logging for all QShield crates.
//!
//! # Security contract
//! Key material, passwords, and secrets MUST NEVER appear in error messages or log output.
//! Use [`Redacted`] to wrap sensitive values. All error variants are deliberately vague
//! where leaking internal details would aid an attacker.

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod error;
pub mod id;
pub mod logging;
pub mod redacted;
pub mod telemetry;

pub use error::QShieldError;
pub use id::new_id;
pub use redacted::Redacted;
