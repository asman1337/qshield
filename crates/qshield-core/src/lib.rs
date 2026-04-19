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
    NONCE_LEN, NonceCounter, TAG_LEN, aes256gcm_decrypt, aes256gcm_decrypt_streaming,
    aes256gcm_encrypt, aes256gcm_encrypt_streaming, chacha20poly1305_decrypt,
    chacha20poly1305_encrypt, generate_nonce,
};
pub use dsa::{
    DsaKeyPair, DsaLevel, DsaSignature, DsaVerifyingKey, dsa_keygen, dsa_sign, dsa_sign_bytes,
    dsa_verify,
};
pub use hybrid::{
    HybridCiphertext, HybridKeyPair, HybridMode, HybridPublicKey, HybridResult, HybridSecretKey,
    NegotiatedAlgorithm, classical_only_decapsulate, hybrid_decapsulate, hybrid_encapsulate,
    hybrid_keygen,
};
pub use hybrid_sig::{
    HybridSigMode, HybridSignature, HybridSigningKey, HybridVerifyingKey, extract_classical_sig,
    hybrid_sig_keygen, hybrid_sign, hybrid_verify,
};
pub use kdf::{derive_key_256, hkdf_sha3_256, hkdf_sha256};
pub use kem::{
    KemCiphertext, KemKeyPair, KemLevel, KemPublicKey, KemSecretKey, SharedSecret, kem_decapsulate,
    kem_encapsulate, kem_keygen,
};
pub use wire::{AlgorithmCode, KeyType, QskeEnvelope, from_envelope_b64, to_envelope_b64};
