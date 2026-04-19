// Note: unsafe IS permitted in qshield-core per QS-007 (FFI & perf-critical
// crypto operations). Every unsafe block must carry a `// SAFETY:` comment.
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod dsa;
pub mod kem;

pub use dsa::{dsa_keygen, dsa_sign, dsa_verify, DsaKeyPair, DsaLevel, DsaSignature, DsaVerifyingKey};
pub use kem::{kem_decapsulate, kem_encapsulate, kem_keygen, KemCiphertext, KemKeyPair, KemLevel, KemPublicKey, KemSecretKey, SharedSecret};
