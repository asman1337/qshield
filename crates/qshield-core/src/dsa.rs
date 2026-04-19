//! ML-DSA (FIPS 204) digital signatures — QS-102.
//!
//! Wraps the `ml-dsa` RustCrypto crate. Uses hedged (randomized) signing by
//! default to protect against fault attacks. A deterministic variant is
//! provided for test reproducibility.

use std::fmt;

use ml_dsa::{
    signature::Verifier,
    EncodedSignature, EncodedVerifyingKey, KeyGen, KeyPair, MlDsa44, MlDsa65, MlDsa87,
    MlDsaParams, Signature, SigningKey, VerifyingKey,
};
use rand_core::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use qshield_common::QShieldError;

// ── Algorithm names ────────────────────────────────────────────────────────

const ALG_44: &str = "ML-DSA-44";
const ALG_65: &str = "ML-DSA-65";
const ALG_87: &str = "ML-DSA-87";

// ── Public types ───────────────────────────────────────────────────────────

/// Which ML-DSA parameter set to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DsaLevel {
    /// NIST security level 2 — general use.
    Dsa44,
    /// NIST security level 3 — QShield default.
    Dsa65,
    /// NIST security level 5 — high-security environments.
    Dsa87,
}

impl DsaLevel {
    #[must_use]
    pub fn algorithm_name(self) -> &'static str {
        match self {
            Self::Dsa44 => ALG_44,
            Self::Dsa65 => ALG_65,
            Self::Dsa87 => ALG_87,
        }
    }
}

/// ML-DSA key pair (signing + verifying). Signing key is zeroized on drop
/// via `Option::take()` which triggers `SigningKey`'s `ZeroizeOnDrop`.
pub struct DsaKeyPair {
    inner: Option<KpInner>,
    level: DsaLevel,
}

/// ML-DSA verifying (public) key.
#[derive(Clone)]
pub struct DsaVerifyingKey {
    bytes: Vec<u8>,
    level: DsaLevel,
}

/// An ML-DSA signature.
#[derive(Clone)]
pub struct DsaSignature {
    bytes: Vec<u8>,
    level: DsaLevel,
}

// ── Private inner enums ────────────────────────────────────────────────────

enum KpInner {
    Dsa44(KeyPair<MlDsa44>),
    Dsa65(KeyPair<MlDsa65>),
    Dsa87(KeyPair<MlDsa87>),
}

// ── Drop / zeroize ──────────────────────────────────────────────────────────────────────────

impl Zeroize for DsaKeyPair {
    fn zeroize(&mut self) {
        // `Option::take` moves the inner `KeyPair<P>` out and drops it here,
        // triggering `SigningKey<P>`'s `ZeroizeOnDrop` — no keygen needed.
        drop(self.inner.take());
    }
}

impl Drop for DsaKeyPair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DsaKeyPair {}

// ── Debug impls (security: never print key material) ──────────────────────

impl fmt::Debug for DsaKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DsaKeyPair([REDACTED] level={:?})", self.level)
    }
}

impl fmt::Debug for DsaVerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DsaVerifyingKey([{} bytes] level={:?})", self.bytes.len(), self.level)
    }
}

impl fmt::Debug for DsaSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DsaSignature([{} bytes] level={:?})", self.bytes.len(), self.level)
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn vk_to_bytes<P: MlDsaParams>(vk: &VerifyingKey<P>) -> Vec<u8> {
    // `encode()` returns `hybrid_array::Array<u8, N>`; use AsRef<[u8]> via slice index.
    let enc = vk.encode();
    enc[..].to_vec()
}

fn sig_to_bytes<P: MlDsaParams>(sig: &Signature<P>) -> Vec<u8> {
    let enc = sig.encode();
    enc[..].to_vec()
}

fn vk_from_bytes<P: MlDsaParams>(bytes: &[u8]) -> Option<VerifyingKey<P>> {
    let enc = EncodedVerifyingKey::<P>::try_from(bytes).ok()?;
    Some(VerifyingKey::<P>::decode(&enc))
}

fn sig_from_bytes<P: MlDsaParams>(bytes: &[u8]) -> Option<Signature<P>> {
    let enc = EncodedSignature::<P>::try_from(bytes).ok()?;
    Signature::<P>::decode(&enc)
}

// ── Key pair accessors ─────────────────────────────────────────────────────

impl DsaKeyPair {
    /// Extract the verifying (public) key, serialized to bytes.
    #[must_use]
    pub fn verifying_key(&self) -> DsaVerifyingKey {
        let bytes = match self.inner.as_ref().expect("DsaKeyPair already zeroized") {
            KpInner::Dsa44(kp) => vk_to_bytes(kp.verifying_key()),
            KpInner::Dsa65(kp) => vk_to_bytes(kp.verifying_key()),
            KpInner::Dsa87(kp) => vk_to_bytes(kp.verifying_key()),
        };
        DsaVerifyingKey { bytes, level: self.level }
    }

    #[must_use]
    pub fn level(&self) -> DsaLevel {
        self.level
    }
}

impl DsaVerifyingKey {
    /// Raw bytes of the verifying key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn level(&self) -> DsaLevel {
        self.level
    }
}

impl DsaSignature {
    /// Raw bytes of the signature.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn level(&self) -> DsaLevel {
        self.level
    }

    /// Construct from raw bytes and a known level (crate-internal use only).
    pub(crate) fn from_raw(bytes: Vec<u8>, level: DsaLevel) -> Self {
        Self { bytes, level }
    }
}

// ── Core API ───────────────────────────────────────────────────────────────

/// Generate a new ML-DSA key pair for the given security level.
///
/// Uses the OS CSPRNG (`OsRng`) for key generation.
///
/// # Errors
/// Currently infallible, but returns `Result` for API consistency.
pub fn dsa_keygen(level: DsaLevel) -> Result<DsaKeyPair, QShieldError> {
    let mut rng = OsRng;
    let inner = match level {
        DsaLevel::Dsa44 => KpInner::Dsa44(MlDsa44::key_gen(&mut rng)),
        DsaLevel::Dsa65 => KpInner::Dsa65(MlDsa65::key_gen(&mut rng)),
        DsaLevel::Dsa87 => KpInner::Dsa87(MlDsa87::key_gen(&mut rng)),
    };
    Ok(DsaKeyPair { inner: Some(inner), level })
}

/// Sign `message` using hedged (randomized) ML-DSA.
///
/// Hedged signing mixes OS randomness into the nonce to defend against fault
/// attacks and RNG reuse. Use `dsa_sign_deterministic` only for test vectors.
///
/// # Errors
/// Returns `SignatureCreation` on internal failure.
pub fn dsa_sign(kp: &DsaKeyPair, message: &[u8]) -> Result<DsaSignature, QShieldError> {
    let mut rng = OsRng;
    let (bytes, level) = match kp.inner.as_ref().expect("DsaKeyPair already zeroized") {
        KpInner::Dsa44(pair) => {
            let sk: &SigningKey<MlDsa44> = pair.signing_key();
            let sig = sk
                .sign_randomized(message, &[], &mut rng)
                .map_err(|_| QShieldError::SignatureCreation { algorithm: ALG_44 })?;
            (sig_to_bytes(&sig), DsaLevel::Dsa44)
        }
        KpInner::Dsa65(pair) => {
            let sk: &SigningKey<MlDsa65> = pair.signing_key();
            let sig = sk
                .sign_randomized(message, &[], &mut rng)
                .map_err(|_| QShieldError::SignatureCreation { algorithm: ALG_65 })?;
            (sig_to_bytes(&sig), DsaLevel::Dsa65)
        }
        KpInner::Dsa87(pair) => {
            let sk: &SigningKey<MlDsa87> = pair.signing_key();
            let sig = sk
                .sign_randomized(message, &[], &mut rng)
                .map_err(|_| QShieldError::SignatureCreation { algorithm: ALG_87 })?;
            (sig_to_bytes(&sig), DsaLevel::Dsa87)
        }
    };
    Ok(DsaSignature { bytes, level })
}

/// Sign `message` deterministically (for test vectors only).
///
/// # Errors
/// Returns `SignatureCreation` on internal failure.
pub fn dsa_sign_deterministic(kp: &DsaKeyPair, message: &[u8]) -> Result<DsaSignature, QShieldError> {
    let (bytes, level) = match kp.inner.as_ref().expect("DsaKeyPair already zeroized") {
        KpInner::Dsa44(pair) => {
            let sk: &SigningKey<MlDsa44> = pair.signing_key();
            let sig = sk
                .sign_deterministic(message, &[])
                .map_err(|_| QShieldError::SignatureCreation { algorithm: ALG_44 })?;
            (sig_to_bytes(&sig), DsaLevel::Dsa44)
        }
        KpInner::Dsa65(pair) => {
            let sk: &SigningKey<MlDsa65> = pair.signing_key();
            let sig = sk
                .sign_deterministic(message, &[])
                .map_err(|_| QShieldError::SignatureCreation { algorithm: ALG_65 })?;
            (sig_to_bytes(&sig), DsaLevel::Dsa65)
        }
        KpInner::Dsa87(pair) => {
            let sk: &SigningKey<MlDsa87> = pair.signing_key();
            let sig = sk
                .sign_deterministic(message, &[])
                .map_err(|_| QShieldError::SignatureCreation { algorithm: ALG_87 })?;
            (sig_to_bytes(&sig), DsaLevel::Dsa87)
        }
    };
    Ok(DsaSignature { bytes, level })
}

/// Verify a signature.
///
/// Returns `Ok(true)` for a valid signature, `Ok(false)` for an invalid one.
/// Never panics on malformed inputs — returns `Ok(false)` for structurally
/// bad signatures, `Err` only for level mismatches.
///
/// # Errors
/// Returns `SignatureVerification` if the signature level doesn't match `vk`.
pub fn dsa_verify(
    vk: &DsaVerifyingKey,
    message: &[u8],
    sig: &DsaSignature,
) -> Result<bool, QShieldError> {
    if vk.level != sig.level {
        return Err(QShieldError::SignatureVerification {
            algorithm: "ML-DSA (level mismatch)",
        });
    }
    match vk.level {
        DsaLevel::Dsa44 => {
            let Some(vk_inner) = vk_from_bytes::<MlDsa44>(&vk.bytes) else {
                return Ok(false);
            };
            let Some(sig_inner) = sig_from_bytes::<MlDsa44>(&sig.bytes) else {
                return Ok(false);
            };
            Ok(vk_inner.verify(message, &sig_inner).is_ok())
        }
        DsaLevel::Dsa65 => {
            let Some(vk_inner) = vk_from_bytes::<MlDsa65>(&vk.bytes) else {
                return Ok(false);
            };
            let Some(sig_inner) = sig_from_bytes::<MlDsa65>(&sig.bytes) else {
                return Ok(false);
            };
            Ok(vk_inner.verify(message, &sig_inner).is_ok())
        }
        DsaLevel::Dsa87 => {
            let Some(vk_inner) = vk_from_bytes::<MlDsa87>(&vk.bytes) else {
                return Ok(false);
            };
            let Some(sig_inner) = sig_from_bytes::<MlDsa87>(&sig.bytes) else {
                return Ok(false);
            };
            Ok(vk_inner.verify(message, &sig_inner).is_ok())
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const MSG: &[u8] = b"QShield post-quantum signature test vector";

    fn round_trip(level: DsaLevel) {
        let kp = dsa_keygen(level).expect("keygen");
        let vk = kp.verifying_key();
        let sig = dsa_sign(&kp, MSG).expect("sign");
        let valid = dsa_verify(&vk, MSG, &sig).expect("verify");
        assert!(valid, "signature must verify");
    }

    /// Run `f` on a thread with 8 MB stack (needed for ML-DSA-87's large
    /// stack-allocated matrices).
    fn with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(f)
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn round_trip_dsa44() {
        with_large_stack(|| round_trip(DsaLevel::Dsa44));
    }

    #[test]
    fn round_trip_dsa65() {
        with_large_stack(|| round_trip(DsaLevel::Dsa65));
    }

    #[test]
    fn round_trip_dsa87() {
        with_large_stack(|| round_trip(DsaLevel::Dsa87));
    }

    #[test]
    fn deterministic_sign_is_reproducible() {
        with_large_stack(|| {
            let kp = dsa_keygen(DsaLevel::Dsa65).unwrap();
            let sig1 = dsa_sign_deterministic(&kp, MSG).unwrap();
            let sig2 = dsa_sign_deterministic(&kp, MSG).unwrap();
            assert_eq!(sig1.as_bytes(), sig2.as_bytes(), "deterministic signing must be reproducible");
        });
    }

    #[test]
    fn wrong_message_fails_verification() {
        with_large_stack(|| {
            let kp = dsa_keygen(DsaLevel::Dsa65).unwrap();
            let vk = kp.verifying_key();
            let sig = dsa_sign(&kp, MSG).unwrap();
            let valid = dsa_verify(&vk, b"tampered message", &sig).unwrap();
            assert!(!valid, "tampered message must not verify");
        });
    }

    #[test]
    fn malformed_signature_does_not_panic() {
        with_large_stack(|| {
            let kp = dsa_keygen(DsaLevel::Dsa65).unwrap();
            let vk = kp.verifying_key();
            let bad_sig =
                DsaSignature { bytes: vec![0xde, 0xad, 0xbe, 0xef], level: DsaLevel::Dsa65 };
            let result = dsa_verify(&vk, MSG, &bad_sig);
            assert!(result.is_ok(), "must not error on malformed sig");
            assert!(!result.unwrap(), "malformed sig must not verify");
        });
    }

    #[test]
    fn level_mismatch_returns_error() {
        with_large_stack(|| {
            let kp44 = dsa_keygen(DsaLevel::Dsa44).unwrap();
            let kp65 = dsa_keygen(DsaLevel::Dsa65).unwrap();
            let vk44 = kp44.verifying_key();
            let sig65 = dsa_sign(&kp65, MSG).unwrap();
            assert!(dsa_verify(&vk44, MSG, &sig65).is_err());
        });
    }

    #[test]
    fn signature_sizes_are_correct() {
        with_large_stack(|| {
            for (level, expected) in [
                (DsaLevel::Dsa44, 2420_usize),
                (DsaLevel::Dsa65, 3309),
                (DsaLevel::Dsa87, 4627),
            ] {
                let kp = dsa_keygen(level).unwrap();
                let sig = dsa_sign_deterministic(&kp, MSG).unwrap();
                assert_eq!(sig.as_bytes().len(), expected, "{level:?} signature size");
            }
        });
    }
}
