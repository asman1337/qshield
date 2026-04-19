// Note: unsafe IS permitted in qshield-core per QS-007 (FFI & perf-critical
// crypto operations). Every unsafe block must carry a `// SAFETY:` comment.
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod dsa;
pub mod hybrid;
pub mod kem;
pub mod zeroize_audit;

pub use dsa::{dsa_keygen, dsa_sign, dsa_verify, DsaKeyPair, DsaLevel, DsaSignature, DsaVerifyingKey};
pub use hybrid::{
    classical_only_decapsulate, hybrid_decapsulate, hybrid_encapsulate, hybrid_keygen,
    HybridCiphertext, HybridKeyPair, HybridMode, HybridPublicKey, HybridResult, HybridSecretKey,
    NegotiatedAlgorithm,
};
pub use kem::{kem_decapsulate, kem_encapsulate, kem_keygen, KemCiphertext, KemKeyPair, KemLevel, KemPublicKey, KemSecretKey, SharedSecret};
