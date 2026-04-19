//! Symmetric AEAD primitives -- QS-108.
//!
//! Provides AES-256-GCM and ChaCha20-Poly1305 with a consistent API.
//! Both ciphers are quantum-safe at 256-bit key strength (Grover's algorithm
//! requires 2^128 operations against AES-256, still infeasible).
//!
//! # Nonce handling
//!
//! **Never reuse a nonce with the same key.**
//! Use [`generate_nonce`] for random nonces (safe up to ~2^48 messages/key).
//! For high-volume encryption, use [`NonceCounter`] for deterministic
//! counter-based nonces.
//!
//! # Wire format
//!
//! `encrypt` appends the 16-byte authentication tag to the ciphertext:
//! `[ciphertext bytes][16-byte tag]`
//!
//! `decrypt` expects the same layout and strips the tag internally.

use aes_gcm::{
    Aes256Gcm, Nonce as AesNonce,
    aead::{Aead, KeyInit, Payload},
};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce};
use rand_core::OsRng;
use rand_core::RngCore;

use qshield_common::QShieldError;

/// Nonce length for both AES-256-GCM and ChaCha20-Poly1305 (96 bits).
pub const NONCE_LEN: usize = 12;
/// Authentication tag length for both ciphers (128 bits).
pub const TAG_LEN: usize = 16;

// -- Nonce generation --------------------------------------------------------

/// Generate a random 96-bit nonce from the OS CSPRNG.
///
/// Safe for random nonce strategies up to ~2^48 messages per key
/// (birthday-bound collision probability < 2^{-32}).
#[must_use]
pub fn generate_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Counter-based nonce for high-volume encryption under a single key.
///
/// Uses a 64-bit big-endian counter in the upper 8 bytes, with a 4-byte
/// fixed prefix (e.g. a session ID fragment). The prefix prevents nonce
/// collisions across sessions sharing the same key.
///
/// # Panics
/// Panics if the counter wraps around (2^64 messages per prefix).
pub struct NonceCounter {
    prefix: [u8; 4],
    counter: u64,
}

impl NonceCounter {
    /// Create a new counter starting at zero with the given 4-byte prefix.
    #[must_use]
    pub fn new(prefix: [u8; 4]) -> Self {
        Self { prefix, counter: 0 }
    }

    /// Advance and return the next nonce. Thread-safety is the caller's responsibility.
    ///
    /// # Panics
    /// Panics on counter overflow (after 2^64 - 1 nonces).
    pub fn advance(&mut self) -> [u8; NONCE_LEN] {
        let c = self.counter.checked_add(1).expect("NonceCounter overflow");
        self.counter = c;
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..4].copy_from_slice(&self.prefix);
        nonce[4..].copy_from_slice(&c.to_be_bytes());
        nonce
    }
}

// -- AES-256-GCM -------------------------------------------------------------

/// Encrypt `plaintext` with AES-256-GCM.
///
/// Returns `ciphertext || 16-byte tag`.
///
/// # Errors
/// - `InvalidKeyLength` if `key.len() != 32`.
/// - `InvalidNonce` if `nonce.len() != 12`.
/// - `Internal` on cipher initialization failure (should never happen for valid inputs).
pub fn aes256gcm_encrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, QShieldError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| QShieldError::Internal {
        message: "AES-256-GCM key init failed".into(),
    })?;
    let n = AesNonce::from_slice(nonce);
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    cipher
        .encrypt(n, payload)
        .map_err(|_| QShieldError::Internal {
            message: "AES-256-GCM encrypt failed".into(),
        })
}

/// Decrypt `ciphertext_with_tag` (ciphertext || 16-byte tag) with AES-256-GCM.
///
/// Returns the plaintext. The returned `Vec` is **not** wrapped in `Zeroizing`
/// -- callers handling sensitive plaintext should wrap it themselves.
///
/// # Errors
/// - `DecryptionFailed` if authentication fails (tag mismatch, wrong key, tampered AAD).
pub fn aes256gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    ciphertext_with_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, QShieldError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| QShieldError::Internal {
        message: "AES-256-GCM key init failed".into(),
    })?;
    let n = AesNonce::from_slice(nonce);
    let payload = Payload {
        msg: ciphertext_with_tag,
        aad,
    };
    cipher
        .decrypt(n, payload)
        .map_err(|_| QShieldError::DecryptionFailed)
}

// -- ChaCha20-Poly1305 --------------------------------------------------------

/// Encrypt `plaintext` with ChaCha20-Poly1305 (RFC 8439).
///
/// Returns `ciphertext || 16-byte tag`.
/// Preferred on platforms without hardware AES acceleration (mobile, some ARM).
///
/// # Errors
/// - `Internal` on cipher initialization failure (should never happen for 32-byte key).
pub fn chacha20poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, QShieldError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| QShieldError::Internal {
        message: "ChaCha20Poly1305 key init failed".into(),
    })?;
    let n = ChaNonce::from_slice(nonce);
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    cipher
        .encrypt(n, payload)
        .map_err(|_| QShieldError::Internal {
            message: "ChaCha20Poly1305 encrypt failed".into(),
        })
}

/// Decrypt `ciphertext_with_tag` (ciphertext || 16-byte tag) with ChaCha20-Poly1305.
///
/// # Errors
/// - `DecryptionFailed` if authentication fails.
pub fn chacha20poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    ciphertext_with_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, QShieldError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| QShieldError::Internal {
        message: "ChaCha20Poly1305 key init failed".into(),
    })?;
    let n = ChaNonce::from_slice(nonce);
    let payload = Payload {
        msg: ciphertext_with_tag,
        aad,
    };
    cipher
        .decrypt(n, payload)
        .map_err(|_| QShieldError::DecryptionFailed)
}

// -- Streaming AEAD -----------------------------------------------------------

/// A single encrypted chunk: `(nonce, ciphertext_with_tag)`.
pub type StreamChunk = ([u8; NONCE_LEN], Vec<u8>);

/// Encrypt a large payload in fixed-size chunks using AES-256-GCM.
///
/// Each chunk is encrypted under the same key with a monotonically increasing
/// nonce derived from `base_nonce` via a counter appended to bytes 4..12.
/// The base nonce's first 4 bytes are preserved as a stream ID.
///
/// `chunk_size` must be > 0. The last chunk may be smaller.
///
/// Returns a `Vec` of `(nonce, ciphertext_with_tag)` pairs -- one per chunk.
///
/// # Errors
/// - `KeyDerivation` if `chunk_size == 0`.
/// - Propagates encryption errors.
pub fn aes256gcm_encrypt_streaming(
    key: &[u8; 32],
    base_nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
    chunk_size: usize,
) -> Result<Vec<StreamChunk>, QShieldError> {
    if chunk_size == 0 {
        return Err(QShieldError::KeyDerivation {
            reason: "chunk_size must be > 0",
        });
    }
    let mut prefix = [0u8; 4];
    prefix.copy_from_slice(&base_nonce[..4]);
    let mut counter = NonceCounter::new(prefix);

    plaintext
        .chunks(chunk_size)
        .map(|chunk| {
            let nonce = counter.advance();
            let ct = aes256gcm_encrypt(key, &nonce, chunk, aad)?;
            Ok((nonce, ct))
        })
        .collect()
}

/// Decrypt a chunked stream produced by [`aes256gcm_encrypt_streaming`].
///
/// The `chunks` must be in the same order as produced by encryption.
///
/// # Errors
/// - `DecryptionFailed` on any authentication failure.
pub fn aes256gcm_decrypt_streaming(
    key: &[u8; 32],
    chunks: &[StreamChunk],
    aad: &[u8],
) -> Result<Vec<u8>, QShieldError> {
    let mut plaintext = Vec::new();
    for (nonce, ct) in chunks {
        let pt = aes256gcm_decrypt(key, nonce, ct, aad)?;
        plaintext.extend_from_slice(&pt);
    }
    Ok(plaintext)
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Helpers --------------------------------------------------------------

    fn random_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        k
    }

    // -- AES-256-GCM ----------------------------------------------------------

    #[test]
    fn aes256gcm_round_trip() {
        let key = random_key();
        let nonce = generate_nonce();
        let pt = b"hello, quantum world!";
        let aad = b"context";

        let ct = aes256gcm_encrypt(&key, &nonce, pt, aad).expect("encrypt");
        assert_eq!(ct.len(), pt.len() + TAG_LEN, "ciphertext = plaintext + tag");

        let recovered = aes256gcm_decrypt(&key, &nonce, &ct, aad).expect("decrypt");
        assert_eq!(recovered, pt);
    }

    #[test]
    fn aes256gcm_tampered_ciphertext_fails() {
        let key = random_key();
        let nonce = generate_nonce();
        let mut ct = aes256gcm_encrypt(&key, &nonce, b"sensitive data", b"").expect("encrypt");
        ct[0] ^= 0xff; // flip a byte
        assert!(matches!(
            aes256gcm_decrypt(&key, &nonce, &ct, b""),
            Err(QShieldError::DecryptionFailed)
        ));
    }

    #[test]
    fn aes256gcm_tampered_aad_fails() {
        let key = random_key();
        let nonce = generate_nonce();
        let ct = aes256gcm_encrypt(&key, &nonce, b"secret", b"original aad").expect("encrypt");
        assert!(matches!(
            aes256gcm_decrypt(&key, &nonce, &ct, b"tampered aad"),
            Err(QShieldError::DecryptionFailed)
        ));
    }

    #[test]
    fn aes256gcm_empty_plaintext() {
        let key = random_key();
        let nonce = generate_nonce();
        let ct = aes256gcm_encrypt(&key, &nonce, b"", b"aad").expect("encrypt empty");
        assert_eq!(ct.len(), TAG_LEN, "empty plaintext produces tag only");
        let pt = aes256gcm_decrypt(&key, &nonce, &ct, b"aad").expect("decrypt empty");
        assert!(pt.is_empty());
    }

    // NIST AES-GCM test vector (GCM-AES-256, case from NIST SP 800-38D)
    // IUT: key=0x0000...0 (32 bytes), IV=0x0000...0 (12 bytes), PT=empty, AAD=empty
    // Expected CT: empty, Tag: 0x530f8afbc74536b9a963b4f1c4cb738b
    #[test]
    fn nist_aes_gcm_vector_empty() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let ct = aes256gcm_encrypt(&key, &nonce, b"", b"").expect("nist vector encrypt");
        let tag: &[u8] = &ct; // entire output is the tag when PT is empty
        let expected_tag = hex::decode("530f8afbc74536b9a963b4f1c4cb738b").unwrap();
        assert_eq!(
            tag,
            expected_tag.as_slice(),
            "NIST AES-GCM-256 vector (empty PT)"
        );
    }

    // -- ChaCha20-Poly1305 ----------------------------------------------------

    #[test]
    fn chacha20poly1305_round_trip() {
        let key = random_key();
        let nonce = generate_nonce();
        let pt = b"post-quantum secure";
        let aad = b"metadata";

        let ct = chacha20poly1305_encrypt(&key, &nonce, pt, aad).expect("encrypt");
        assert_eq!(ct.len(), pt.len() + TAG_LEN);

        let recovered = chacha20poly1305_decrypt(&key, &nonce, &ct, aad).expect("decrypt");
        assert_eq!(recovered, pt);
    }

    #[test]
    fn chacha20poly1305_tampered_ciphertext_fails() {
        let key = random_key();
        let nonce = generate_nonce();
        let mut ct = chacha20poly1305_encrypt(&key, &nonce, b"secret", b"").expect("encrypt");
        *ct.last_mut().unwrap() ^= 0x01;
        assert!(matches!(
            chacha20poly1305_decrypt(&key, &nonce, &ct, b""),
            Err(QShieldError::DecryptionFailed)
        ));
    }

    #[test]
    fn chacha20poly1305_tampered_aad_fails() {
        let key = random_key();
        let nonce = generate_nonce();
        let ct = chacha20poly1305_encrypt(&key, &nonce, b"msg", b"good aad").expect("encrypt");
        assert!(matches!(
            chacha20poly1305_decrypt(&key, &nonce, &ct, b"evil aad"),
            Err(QShieldError::DecryptionFailed)
        ));
    }

    // Verify our output matches a known value by checking encrypt->decrypt
    // and that ciphertext != plaintext. Full RFC 8439 Appendix A.5 vector to
    // be added once an authoritative hex source is confirmed.
    #[test]
    fn chacha20poly1305_cipher_differs_from_plaintext() {
        let key = hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .unwrap();
        let nonce = hex::decode("070000004041424344454647").unwrap();
        let pt = b"Ladies and Gentlemen of the class of '99";
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();

        let key_arr: [u8; 32] = key.try_into().unwrap();
        let nonce_arr: [u8; 12] = nonce.try_into().unwrap();

        let ct = chacha20poly1305_encrypt(&key_arr, &nonce_arr, pt, &aad).expect("encrypt");
        assert_eq!(ct.len(), pt.len() + TAG_LEN);
        assert_ne!(
            &ct[..pt.len()],
            pt.as_slice(),
            "ciphertext must differ from plaintext"
        );

        let decrypted = chacha20poly1305_decrypt(&key_arr, &nonce_arr, &ct, &aad).expect("decrypt");
        assert_eq!(decrypted.as_slice(), pt.as_slice());
    }

    // -- Streaming ------------------------------------------------------------

    #[test]
    fn streaming_round_trip() {
        let key = random_key();
        let base_nonce = generate_nonce();
        let plaintext: Vec<u8> = (0u8..200).collect();
        let aad = b"stream";

        let chunks = aes256gcm_encrypt_streaming(&key, &base_nonce, &plaintext, aad, 64)
            .expect("stream encrypt");
        assert_eq!(
            chunks.len(),
            4,
            "200 bytes / 64-byte chunks = 4 chunks (64+64+64+8)"
        );

        let recovered = aes256gcm_decrypt_streaming(&key, &chunks, aad).expect("stream decrypt");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn streaming_tampered_chunk_fails() {
        let key = random_key();
        let base_nonce = generate_nonce();
        let plaintext = vec![0u8; 128];

        let mut chunks =
            aes256gcm_encrypt_streaming(&key, &base_nonce, &plaintext, b"", 64).expect("encrypt");
        chunks[0].1[0] ^= 0xff; // tamper first chunk

        assert!(aes256gcm_decrypt_streaming(&key, &chunks, b"").is_err());
    }

    #[test]
    fn nonce_counter_increments() {
        let mut counter = NonceCounter::new([0xDE, 0xAD, 0xBE, 0xEF]);
        let n1 = counter.advance();
        let n2 = counter.advance();
        assert_ne!(n1, n2, "nonces must be unique");
        assert_eq!(&n1[..4], &[0xDE, 0xAD, 0xBE, 0xEF]);
        // counter starts at 1 (checked_add before storing)
        assert_eq!(&n1[4..], &1u64.to_be_bytes());
        assert_eq!(&n2[4..], &2u64.to_be_bytes());
    }

    #[test]
    fn generate_nonce_is_unique() {
        // Statistical test: 1000 random nonces should all be distinct
        let nonces: std::collections::HashSet<[u8; 12]> =
            (0..1000).map(|_| generate_nonce()).collect();
        assert_eq!(nonces.len(), 1000, "all 1000 random nonces must be unique");
    }

    #[test]
    fn zero_chunk_size_errors() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let err = aes256gcm_encrypt_streaming(&key, &nonce, b"data", b"", 0).unwrap_err();
        assert!(matches!(err, QShieldError::KeyDerivation { .. }));
    }
}
