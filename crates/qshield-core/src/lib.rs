// Note: unsafe IS permitted in qshield-core per QS-007 (FFI & perf-critical
// crypto operations). Every unsafe block must carry a `// SAFETY:` comment.
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod aead;
pub mod dsa;
pub mod hybrid;
pub mod hybrid_sig;
pub mod kdf;
pub mod kem;
pub mod wire;
pub mod zeroize_audit;

pub use aead::{
    aes256gcm_decrypt, aes256gcm_decrypt_streaming, aes256gcm_encrypt, aes256gcm_encrypt_streaming,
    chacha20poly1305_decrypt, chacha20poly1305_encrypt, generate_nonce, NonceCounter, NONCE_LEN,
    TAG_LEN,
};
pub use dsa::{dsa_keygen, dsa_sign, dsa_verify, DsaKeyPair, DsaLevel, DsaSignature, DsaVerifyingKey};
pub use hybrid::{
    classical_only_decapsulate, hybrid_decapsulate, hybrid_encapsulate, hybrid_keygen,
    HybridCiphertext, HybridKeyPair, HybridMode, HybridPublicKey, HybridResult, HybridSecretKey,
    NegotiatedAlgorithm,
};
pub use kdf::{derive_key_256, hkdf_sha256, hkdf_sha3_256};
pub use hybrid_sig::{
    extract_classical_sig, hybrid_sign, hybrid_sig_keygen, hybrid_verify, HybridSigMode,
    HybridSignature, HybridSigningKey, HybridVerifyingKey,
};
pub use kem::{kem_decapsulate, kem_encapsulate, kem_keygen, KemCiphertext, KemKeyPair, KemLevel, KemPublicKey, KemSecretKey, SharedSecret};
pub use wire::{AlgorithmCode, from_envelope_b64, KeyType, QskeEnvelope, to_envelope_b64};
