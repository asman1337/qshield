//! Hybrid KEM: X25519 + ML-KEM -- QS-103.
//!
//! Combines a classical (X25519) ECDH with a post-quantum (ML-KEM-768 or
//! ML-KEM-1024) KEM. The resulting shared secret is derived with HKDF-SHA-256:
//!
//! ```text
//! ikm  = x25519_ss (32 B) || pqc_ss (32 B)
//! salt = b"QShield-Hybrid-KEM-v1"
//! info = mode-label (e.g. b"X25519Kyber768")
//! okm  = 32 bytes
//! ```
//!
//! This matches the hybrid construction deployed by Chrome and Cloudflare
//! (draft-ietf-tls-hybrid-design).

use std::fmt;

use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use qshield_common::QShieldError;

use crate::kem::{
    KemCiphertext, KemLevel, KemPublicKey, KemSecretKey, SharedSecret, kem_decapsulate,
    kem_encapsulate, kem_keygen,
};

const HKDF_SALT: &[u8] = b"QShield-Hybrid-KEM-v1";

// -- Mode -------------------------------------------------------------------

/// Supported hybrid KEM combinations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HybridMode {
    /// X25519 + ML-KEM-768. Default -- matches Chrome/Cloudflare deployment.
    X25519Kyber768,
    /// X25519 + ML-KEM-1024. For high-security environments.
    X25519Kyber1024,
}

impl HybridMode {
    #[must_use]
    pub fn kem_level(self) -> KemLevel {
        match self {
            Self::X25519Kyber768 => KemLevel::Kem768,
            Self::X25519Kyber1024 => KemLevel::Kem1024,
        }
    }

    pub(crate) fn info(self) -> &'static [u8] {
        match self {
            Self::X25519Kyber768 => b"X25519Kyber768",
            Self::X25519Kyber1024 => b"X25519Kyber1024",
        }
    }

    /// Human-readable label for this mode.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::X25519Kyber768 => "X25519Kyber768",
            Self::X25519Kyber1024 => "X25519Kyber1024",
        }
    }
}

// -- Key types --------------------------------------------------------------

/// Receiver's hybrid public key (given to encapsulators).
pub struct HybridPublicKey {
    /// Static X25519 public key.
    pub classical: X25519Public,
    /// ML-KEM encapsulation key.
    pub pqc: KemPublicKey,
    /// Hybrid mode (determines ML-KEM level and HKDF info string).
    pub mode: HybridMode,
}

/// Receiver's hybrid secret key. Both halves zeroize on drop:
/// - `StaticSecret` via `x25519-dalek`'s `ZeroizeOnDrop` (zeroize feature)
/// - `KemSecretKey` via `ml-kem`'s zeroize feature
pub struct HybridSecretKey {
    pub(crate) classical: StaticSecret,
    pub(crate) pqc: KemSecretKey,
    /// Hybrid mode carried alongside the key.
    pub mode: HybridMode,
}

/// Full hybrid key pair returned by [`hybrid_keygen`].
pub struct HybridKeyPair {
    pub public_key: HybridPublicKey,
    pub secret_key: HybridSecretKey,
}

/// Hybrid ciphertext sent from encapsulator to receiver.
///
/// Wire format (via [`HybridCiphertext::to_bytes`] / [`HybridCiphertext::from_bytes`]):
/// `[32 B ephemeral X25519 public key][N B ML-KEM ciphertext]`
#[derive(Clone)]
pub struct HybridCiphertext {
    /// Ephemeral X25519 public key (32 bytes).
    pub classical_ek: [u8; 32],
    /// ML-KEM ciphertext.
    pub pqc_ct: KemCiphertext,
}

impl HybridCiphertext {
    /// Encode as bytes: `[32 B ek_classical][pqc_ct bytes]`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.pqc_ct.to_bytes().len());
        out.extend_from_slice(&self.classical_ek);
        out.extend_from_slice(self.pqc_ct.to_bytes());
        out
    }

    /// Reconstruct from bytes.
    ///
    /// # Errors
    /// Returns `InvalidKeyLength` if `bytes` is too short or the ML-KEM
    /// ciphertext length does not match `mode`.
    pub fn from_bytes(mode: HybridMode, bytes: &[u8]) -> Result<Self, QShieldError> {
        if bytes.len() < 32 {
            return Err(QShieldError::InvalidKeyLength {
                expected: 32,
                actual: bytes.len(),
            });
        }
        let mut classical_ek = [0u8; 32];
        classical_ek.copy_from_slice(&bytes[..32]);
        let pqc_ct = KemCiphertext::from_bytes(mode.kem_level(), &bytes[32..])?;
        Ok(Self {
            classical_ek,
            pqc_ct,
        })
    }
}

// -- Negotiation result -----------------------------------------------------

/// Which algorithms were actually negotiated in a hybrid exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiatedAlgorithm {
    /// Full hybrid (classical + PQC).
    Hybrid(HybridMode),
    /// Classical X25519 only (peer does not support PQC).
    ClassicalOnly,
}

/// Result of a hybrid decapsulation: the derived shared secret and the
/// negotiated algorithm set.
pub struct HybridResult {
    pub shared_secret: SharedSecret,
    pub algorithm: NegotiatedAlgorithm,
}

// -- Drop / zeroize --------------------------------------------------------

impl Zeroize for HybridSecretKey {
    fn zeroize(&mut self) {
        self.classical.zeroize();
        self.pqc.zeroize();
        // self.mode is not sensitive -- not zeroed
    }
}

impl Drop for HybridSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for HybridSecretKey {}

// -- Debug impls (no key material) ------------------------------------------

impl fmt::Debug for HybridPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridPublicKey(mode={:?})", self.mode)
    }
}

impl fmt::Debug for HybridSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridSecretKey([REDACTED] mode={:?})", self.mode)
    }
}

impl fmt::Debug for HybridCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HybridCiphertext(classical_ek=32B, pqc_ct={}B)",
            self.pqc_ct.to_bytes().len()
        )
    }
}

// -- HKDF combiner ----------------------------------------------------------

/// Combine X25519 and PQC shared secrets with HKDF-SHA-256.
///
/// IKM = `x25519_ss || pqc_ss`. The concatenated IKM buffer is zeroized before
/// this function returns.
pub(crate) fn hkdf_combine(x25519_ss: &[u8; 32], pqc_ss: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(x25519_ss);
    ikm[32..].copy_from_slice(pqc_ss);

    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), ikm.as_ref());
    let mut okm = [0u8; 32];
    // 32-byte output length is always within the HKDF-SHA-256 limit (8160 B).
    hk.expand(info, &mut okm)
        .expect("HKDF expand: 32-byte output is always within limit");
    okm
}

// -- Key serialization helpers ---------------------------------------------

impl HybridSecretKey {
    /// Serialize to bytes: `[32 B classical key][pqc sk bytes]`.
    ///
    /// # Security
    /// The returned bytes are highly sensitive -- handle and erase with care.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let classical = self.classical.to_bytes();
        let pqc = self.pqc.to_bytes();
        let mut out = Vec::with_capacity(32 + pqc.len());
        out.extend_from_slice(&classical);
        out.extend_from_slice(&pqc);
        out
    }

    /// Reconstruct from bytes produced by [`HybridSecretKey::to_bytes`].
    ///
    /// # Errors
    /// Returns `InvalidKeyLength` if `bytes` is too short or the PQC key
    /// length does not match `mode`.
    pub fn from_bytes(mode: HybridMode, bytes: &[u8]) -> Result<Self, QShieldError> {
        if bytes.len() < 32 {
            return Err(QShieldError::InvalidKeyLength {
                expected: 32,
                actual: bytes.len(),
            });
        }
        let mut classical_arr = [0u8; 32];
        classical_arr.copy_from_slice(&bytes[..32]);
        let classical = StaticSecret::from(classical_arr);
        let pqc = KemSecretKey::from_bytes(mode.kem_level(), &bytes[32..])?;
        Ok(Self {
            classical,
            pqc,
            mode,
        })
    }
}

// -- Public API -------------------------------------------------------------

/// Generate a new hybrid key pair for the given mode.
///
/// Uses the OS CSPRNG for both halves of the key pair.
///
/// # Errors
/// Propagates any error from ML-KEM key generation (currently infallible).
#[allow(clippy::similar_names)]
pub fn hybrid_keygen(mode: HybridMode) -> Result<HybridKeyPair, QShieldError> {
    let classical_sk = StaticSecret::random_from_rng(OsRng);
    let classical_pk = X25519Public::from(&classical_sk);
    let pqc_kp = kem_keygen(mode.kem_level())?;

    Ok(HybridKeyPair {
        public_key: HybridPublicKey {
            classical: classical_pk,
            pqc: pqc_kp.public_key,
            mode,
        },
        secret_key: HybridSecretKey {
            classical: classical_sk,
            pqc: pqc_kp.secret_key,
            mode,
        },
    })
}

/// Encapsulate a shared secret to the holder of `pk`.
///
/// Internally generates an ephemeral X25519 key pair (consumed after DH) and
/// encapsulates to the ML-KEM public key. Both individual shared secrets are
/// zeroized before the function returns.
///
/// Returns `(combined_shared_secret, ciphertext_to_send_to_receiver)`.
///
/// # Errors
/// Propagates any error from ML-KEM encapsulation.
#[allow(clippy::similar_names)]
pub fn hybrid_encapsulate(
    pk: &HybridPublicKey,
) -> Result<(SharedSecret, HybridCiphertext), QShieldError> {
    // Ephemeral X25519 -- consumed by diffie_hellman, preventing reuse.
    let ephemeral_sk = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_pk = X25519Public::from(&ephemeral_sk);

    // X25519 DH: ephemeral_sk is moved (consumed) here.
    let x25519_dh = ephemeral_sk.diffie_hellman(&pk.classical);
    let x25519_ss = Zeroizing::new(*x25519_dh.as_bytes());

    // ML-KEM encapsulation.
    let (pqc_shared, pqc_ct) = kem_encapsulate(&pk.pqc)?;

    // Combine with HKDF; hkdf_combine zeroizes its internal IKM buffer.
    let mut combined = hkdf_combine(&x25519_ss, pqc_shared.as_bytes(), pk.mode.info());
    let ss = SharedSecret::from_raw(combined);
    combined.zeroize();

    Ok((
        ss,
        HybridCiphertext {
            classical_ek: ephemeral_pk.to_bytes(),
            pqc_ct,
        },
    ))
}

/// Decapsulate `ct` with `sk` to recover the shared secret.
///
/// Both individual shared secrets are zeroized before the function returns.
///
/// # Errors
/// Returns `Decapsulation` on ML-KEM failure or mode mismatch.
pub fn hybrid_decapsulate(
    sk: &HybridSecretKey,
    ct: &HybridCiphertext,
) -> Result<HybridResult, QShieldError> {
    // Reconstruct the ephemeral X25519 public key from the ciphertext.
    let ephemeral_pk = X25519Public::from(ct.classical_ek);

    // X25519 DH with the receiver's static classical secret key.
    let x25519_dh = sk.classical.diffie_hellman(&ephemeral_pk);
    let x25519_ss = Zeroizing::new(*x25519_dh.as_bytes());

    // ML-KEM decapsulation.
    let pqc_shared = kem_decapsulate(&sk.pqc, &ct.pqc_ct)?;

    // Combine with HKDF.
    let mut combined = hkdf_combine(&x25519_ss, pqc_shared.as_bytes(), sk.mode.info());
    let ss = SharedSecret::from_raw(combined);
    combined.zeroize();

    Ok(HybridResult {
        shared_secret: ss,
        algorithm: NegotiatedAlgorithm::Hybrid(sk.mode),
    })
}

/// Classical-only (X25519) key exchange -- explicit fallback for peers that do
/// not support PQC.
///
/// Returns `HybridResult` with `algorithm = NegotiatedAlgorithm::ClassicalOnly`
/// so callers can detect and log the downgrade.
///
/// `ephemeral_ek_bytes` is the sender's 32-byte ephemeral X25519 public key.
///
/// # Errors
/// Currently infallible; returns `Result` for API consistency.
pub fn classical_only_decapsulate(
    sk: &HybridSecretKey,
    ephemeral_ek_bytes: &[u8; 32],
) -> Result<HybridResult, QShieldError> {
    let ephemeral_pk = X25519Public::from(*ephemeral_ek_bytes);
    let dh = sk.classical.diffie_hellman(&ephemeral_pk);
    let raw = *dh.as_bytes();
    Ok(HybridResult {
        shared_secret: SharedSecret::from_raw(raw),
        algorithm: NegotiatedAlgorithm::ClassicalOnly,
    })
}

// -- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(mode: HybridMode) {
        let kp = hybrid_keygen(mode).expect("keygen");
        let (ss_send, ct) = hybrid_encapsulate(&kp.public_key).expect("encapsulate");
        let result = hybrid_decapsulate(&kp.secret_key, &ct).expect("decapsulate");

        assert_eq!(
            ss_send.as_bytes(),
            result.shared_secret.as_bytes(),
            "shared secrets must match for {}",
            mode.label()
        );
        assert_eq!(result.algorithm, NegotiatedAlgorithm::Hybrid(mode));
    }

    #[test]
    fn round_trip_x25519_kyber768() {
        round_trip(HybridMode::X25519Kyber768);
    }

    #[test]
    fn round_trip_x25519_kyber1024() {
        round_trip(HybridMode::X25519Kyber1024);
    }

    #[test]
    fn hybrid_differs_from_either_component_alone() {
        // Two independent uses of a fixed IKM show that HKDF combines both inputs.
        let x_ss = [0x11u8; 32];
        let pqc_ss = [0x22u8; 32];
        let info = HybridMode::X25519Kyber768.info();

        let combined = hkdf_combine(&x_ss, &pqc_ss, info);

        // Combined must differ from each component.
        assert_ne!(combined, x_ss, "combined must differ from x25519 SS alone");
        assert_ne!(combined, pqc_ss, "combined must differ from PQC SS alone");

        // Zeroing out either component must change the output.
        let x_only = hkdf_combine(&x_ss, &[0u8; 32], info);
        let pqc_only = hkdf_combine(&[0u8; 32], &pqc_ss, info);
        assert_ne!(
            combined, x_only,
            "combined must differ from x25519-only HKDF"
        );
        assert_ne!(
            combined, pqc_only,
            "combined must differ from PQC-only HKDF"
        );
    }

    #[test]
    fn hkdf_is_deterministic() {
        let x_ss = [0xabu8; 32];
        let pqc_ss = [0xcdu8; 32];
        let info = HybridMode::X25519Kyber768.info();

        let out1 = hkdf_combine(&x_ss, &pqc_ss, info);
        let out2 = hkdf_combine(&x_ss, &pqc_ss, info);
        assert_eq!(
            out1, out2,
            "HKDF must be deterministic for identical inputs"
        );
    }

    #[test]
    fn different_modes_produce_different_secrets() {
        let x_ss = [0x55u8; 32];
        let pqc_ss = [0x66u8; 32];

        let out768 = hkdf_combine(&x_ss, &pqc_ss, HybridMode::X25519Kyber768.info());
        let out1024 = hkdf_combine(&x_ss, &pqc_ss, HybridMode::X25519Kyber1024.info());
        assert_ne!(
            out768, out1024,
            "different modes must produce different secrets (different HKDF info)"
        );
    }

    #[test]
    fn classical_fallback_is_flagged() {
        let kp = hybrid_keygen(HybridMode::X25519Kyber768).expect("keygen");

        // Simulate a classical-only sender.
        let ephemeral_sk = EphemeralSecret::random_from_rng(OsRng);
        let ephemeral_pk = X25519Public::from(&ephemeral_sk);

        let result = classical_only_decapsulate(&kp.secret_key, &ephemeral_pk.as_bytes())
            .expect("classical_only_decapsulate");

        assert_eq!(
            result.algorithm,
            NegotiatedAlgorithm::ClassicalOnly,
            "classical-only fallback must be flagged"
        );
        // Shared secret must be non-zero (DH of random keys is never zero with overwhelming probability).
        assert_ne!(result.shared_secret.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn ciphertext_roundtrip_serialization() {
        let kp = hybrid_keygen(HybridMode::X25519Kyber768).expect("keygen");
        let (_, ct) = hybrid_encapsulate(&kp.public_key).expect("encapsulate");

        let bytes = ct.to_bytes();
        let ct2 =
            HybridCiphertext::from_bytes(HybridMode::X25519Kyber768, &bytes).expect("from_bytes");

        assert_eq!(ct.classical_ek, ct2.classical_ek);
        assert_eq!(ct.pqc_ct.to_bytes(), ct2.pqc_ct.to_bytes());
    }
}
