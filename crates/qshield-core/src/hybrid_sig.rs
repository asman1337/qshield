//! Hybrid Signatures (Ed25519 + ML-DSA-65) — QS-104.
//!
//! Combines a classical Ed25519 signature with a PQC ML-DSA-65 signature so the
//! composite is secure if *either* algorithm holds.
//!
//! ## Wire format of `HybridSignature`
//! ```text
//! [2B classical_len BE] [classical_sig_bytes] [2B pqc_len BE] [pqc_sig_bytes]
//! ```
//! Verification requires **both** sub-signatures to pass.

use std::fmt;

use ed25519_dalek::{Signature as Ed25519Sig, Signer, SigningKey as Ed25519SigningKey,
                   Verifier, VerifyingKey as Ed25519VerifyingKey};
use rand_core::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use qshield_common::QShieldError;

use crate::dsa::{dsa_keygen, dsa_sign, dsa_verify, DsaKeyPair, DsaLevel, DsaSignature,
                 DsaVerifyingKey};

// ── Mode enum ──────────────────────────────────────────────────────────────

/// Supported hybrid signature combinations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HybridSigMode {
    /// Ed25519 (classical, NIST security level 1) + ML-DSA-65 (PQC, level 3).
    Ed25519Dilithium65,
}

// ── Public types ───────────────────────────────────────────────────────────

/// Hybrid signing key (Ed25519 + ML-DSA-65). Zeroized on drop.
pub struct HybridSigningKey {
    mode: HybridSigMode,
    /// Wrapped in `Option` so `zeroize()` can `take()` + drop to trigger `ZeroizeOnDrop`.
    ed25519: Option<Ed25519SigningKey>,
    /// Boxed to keep the large ML-DSA key material (~7.5 KB) off the stack.
    pqc: Box<DsaKeyPair>,
}

/// Hybrid verifying (public) key.
#[derive(Clone)]
pub struct HybridVerifyingKey {
    mode: HybridSigMode,
    ed25519_vk_bytes: [u8; 32],
    pqc: DsaVerifyingKey,
}

/// A serialized hybrid signature (both sub-signatures packed together).
#[derive(Clone)]
pub struct HybridSignature {
    bytes: Vec<u8>,
}

// ── Zeroize ────────────────────────────────────────────────────────────────

impl Zeroize for HybridSigningKey {
    fn zeroize(&mut self) {
        // `take()` moves the key out and drops it here, triggering `ZeroizeOnDrop`.
        drop(self.ed25519.take());
        self.pqc.zeroize();
    }
}

impl Drop for HybridSigningKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for HybridSigningKey {}

// ── Debug (no key material) ────────────────────────────────────────────────

impl fmt::Debug for HybridSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridSigningKey([REDACTED] mode={:?})", self.mode)
    }
}

impl fmt::Debug for HybridVerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridVerifyingKey(mode={:?})", self.mode)
    }
}

impl fmt::Debug for HybridSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridSignature([{} bytes])", self.bytes.len())
    }
}

// ── Accessors ──────────────────────────────────────────────────────────────

impl HybridSigningKey {
    #[must_use]
    pub fn mode(&self) -> HybridSigMode {
        self.mode
    }

    /// Derive the hybrid verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> HybridVerifyingKey {
        let ed = self.ed25519.as_ref().expect("HybridSigningKey already zeroized");
        HybridVerifyingKey {
            mode: self.mode,
            ed25519_vk_bytes: ed.verifying_key().to_bytes(),
            pqc: self.pqc.verifying_key(),
        }
    }
}

impl HybridVerifyingKey {
    #[must_use]
    pub fn mode(&self) -> HybridSigMode {
        self.mode
    }
}

impl HybridSignature {
    /// Serialized hybrid signature bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Reconstruct from bytes produced by `as_bytes()`.
    ///
    /// # Errors
    /// Returns `SignatureVerification` if the bytes are structurally invalid.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, QShieldError> {
        // Validate parse-ability up front so callers get a clear error.
        sig_parse(bytes)?;
        Ok(Self { bytes: bytes.to_vec() })
    }
}

// ── Wire-format helpers ────────────────────────────────────────────────────

/// Encode classical and PQC sub-signatures into the hybrid wire format.
fn sig_encode(classical: &[u8], pqc: &[u8]) -> Result<Vec<u8>, QShieldError> {
    let c_len = u16::try_from(classical.len()).map_err(|_| QShieldError::SignatureCreation {
        algorithm: "hybrid-sig: classical part exceeds 65535 bytes",
    })?;
    let p_len = u16::try_from(pqc.len()).map_err(|_| QShieldError::SignatureCreation {
        algorithm: "hybrid-sig: PQC part exceeds 65535 bytes",
    })?;

    let mut out = Vec::with_capacity(2 + classical.len() + 2 + pqc.len());
    out.extend_from_slice(&c_len.to_be_bytes());
    out.extend_from_slice(classical);
    out.extend_from_slice(&p_len.to_be_bytes());
    out.extend_from_slice(pqc);
    Ok(out)
}

/// Parse the wire format, returning `(classical_bytes, pqc_bytes)`.
fn sig_parse(bytes: &[u8]) -> Result<(&[u8], &[u8]), QShieldError> {
    let malformed = || QShieldError::SignatureVerification {
        algorithm: "hybrid-sig: malformed wire format",
    };

    if bytes.len() < 4 {
        return Err(malformed());
    }
    let c_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    let after_c = bytes.get(2..2 + c_len).ok_or_else(malformed)?;
    let pqc_prefix = bytes.get(2 + c_len..).ok_or_else(malformed)?;
    if pqc_prefix.len() < 2 {
        return Err(malformed());
    }
    let p_len = u16::from_be_bytes([pqc_prefix[0], pqc_prefix[1]]) as usize;
    let pqc = pqc_prefix.get(2..2 + p_len).ok_or_else(malformed)?;

    Ok((after_c, pqc))
}

// ── Core API ───────────────────────────────────────────────────────────────

/// Generate a new hybrid signing key pair.
///
/// # Errors
/// Propagates any error from `dsa_keygen` (currently infallible).
pub fn hybrid_sig_keygen(mode: HybridSigMode) -> Result<HybridSigningKey, QShieldError> {
    let mut rng = OsRng;
    let ed25519 = Some(Ed25519SigningKey::generate(&mut rng));
    let pqc = Box::new(dsa_keygen(DsaLevel::Dsa65)?);
    Ok(HybridSigningKey { mode, ed25519, pqc })
}

/// Sign `msg` with a hybrid key. **Both** sub-signatures are computed.
///
/// # Errors
/// Returns `SignatureCreation` if ML-DSA signing fails.
pub fn hybrid_sign(sk: &HybridSigningKey, msg: &[u8]) -> Result<HybridSignature, QShieldError> {
    let ed = sk.ed25519.as_ref().expect("HybridSigningKey already zeroized");
    let ed_sig: Ed25519Sig = ed.sign(msg);
    let classical_bytes = ed_sig.to_bytes();

    let pqc_sig = dsa_sign(&sk.pqc, msg)?;
    let bytes = sig_encode(&classical_bytes, pqc_sig.as_bytes())?;
    Ok(HybridSignature { bytes })
}

/// Verify a hybrid signature. Returns `true` only if **both** sub-signatures are valid.
///
/// # Errors
/// Returns `SignatureVerification` for structural errors (bad wire format, bad key bytes,
/// wrong ML-DSA level). Returns `Ok(false)` for cryptographically invalid signatures.
pub fn hybrid_verify(
    pk: &HybridVerifyingKey,
    msg: &[u8],
    sig: &HybridSignature,
) -> Result<bool, QShieldError> {
    let (classical_bytes, pqc_bytes) = sig_parse(&sig.bytes)?;

    // ── Ed25519 ──
    let ed_vk = Ed25519VerifyingKey::from_bytes(&pk.ed25519_vk_bytes).map_err(|_| {
        QShieldError::SignatureVerification { algorithm: "Ed25519 (invalid public key bytes)" }
    })?;
    let ed_sig_arr: [u8; 64] = classical_bytes.try_into().map_err(|_| {
        QShieldError::SignatureVerification { algorithm: "Ed25519 (wrong signature length)" }
    })?;
    let ed_sig = Ed25519Sig::from_bytes(&ed_sig_arr);
    if ed_vk.verify(msg, &ed_sig).is_err() {
        return Ok(false);
    }

    // ── ML-DSA-65 ──
    let pqc_sig = DsaSignature::from_raw(pqc_bytes.to_vec(), DsaLevel::Dsa65);
    let pqc_ok = dsa_verify(&pk.pqc, msg, &pqc_sig)?;
    Ok(pqc_ok)
}

/// Extract just the classical Ed25519 sub-signature bytes.
///
/// Use this to produce a backward-compatible signature for verifiers that
/// cannot yet handle the PQC component.
///
/// # Errors
/// Returns `SignatureVerification` if `sig` has a malformed wire format.
pub fn extract_classical_sig(sig: &HybridSignature) -> Result<Vec<u8>, QShieldError> {
    let (classical_bytes, _) = sig_parse(&sig.bytes)?;
    Ok(classical_bytes.to_vec())
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const MSG: &[u8] = b"QShield hybrid-sig test message";
    const ALT_MSG: &[u8] = b"different message";

    fn keygen_and_sign() -> (HybridSigningKey, HybridVerifyingKey, HybridSignature) {
        let sk = hybrid_sig_keygen(HybridSigMode::Ed25519Dilithium65).unwrap();
        let vk = sk.verifying_key();
        let sig = hybrid_sign(&sk, MSG).unwrap();
        (sk, vk, sig)
    }

    // ── Round-trip ────────────────────────────────────────────────────────

    #[test]
    fn round_trip_ed25519_dilithium65() {
        let (_, vk, sig) = keygen_and_sign();
        assert!(hybrid_verify(&vk, MSG, &sig).unwrap());
    }

    // ── Tamper tests ──────────────────────────────────────────────────────

    #[test]
    fn tampered_classical_sig_fails() {
        let (_, vk, sig) = keygen_and_sign();
        let (classical, pqc) = sig_parse(sig.as_bytes()).unwrap();
        // Flip a byte in the classical signature.
        let mut bad_classical = classical.to_vec();
        bad_classical[10] ^= 0xFF;
        let bad_bytes = sig_encode(&bad_classical, pqc).unwrap();
        let bad_sig = HybridSignature { bytes: bad_bytes };
        assert!(!hybrid_verify(&vk, MSG, &bad_sig).unwrap());
    }

    #[test]
    fn tampered_pqc_sig_fails() {
        let (_, vk, sig) = keygen_and_sign();
        let (classical, pqc) = sig_parse(sig.as_bytes()).unwrap();
        // Flip a byte in the PQC signature.
        let mut bad_pqc = pqc.to_vec();
        bad_pqc[100] ^= 0xFF;
        let bad_bytes = sig_encode(classical, &bad_pqc).unwrap();
        let bad_sig = HybridSignature { bytes: bad_bytes };
        assert!(!hybrid_verify(&vk, MSG, &bad_sig).unwrap());
    }

    #[test]
    fn wrong_message_fails() {
        let (_, vk, sig) = keygen_and_sign();
        assert!(!hybrid_verify(&vk, ALT_MSG, &sig).unwrap());
    }

    // ── Classical extraction ──────────────────────────────────────────────

    #[test]
    fn classical_extraction_is_valid_ed25519() {
        let (sk, _vk, sig) = keygen_and_sign();
        let classical_bytes = extract_classical_sig(&sig).unwrap();
        assert_eq!(classical_bytes.len(), 64, "Ed25519 signature is always 64 bytes");

        // Verify independently using ed25519-dalek directly.
        let ed = sk.ed25519.as_ref().unwrap();
        let ed_vk = ed.verifying_key();
        let ed_sig_arr: [u8; 64] = classical_bytes.try_into().unwrap();
        let ed_sig = Ed25519Sig::from_bytes(&ed_sig_arr);
        assert!(ed_vk.verify(MSG, &ed_sig).is_ok(), "classical sub-sig must be independently valid");
    }

    // ── Sub-signature independence ────────────────────────────────────────

    #[test]
    fn sub_signatures_are_independently_valid() {
        let (sk, vk, sig) = keygen_and_sign();

        // Classical is valid against the Ed25519 verifying key.
        let classical_bytes = extract_classical_sig(&sig).unwrap();
        let ed_sig_arr: [u8; 64] = classical_bytes.as_slice().try_into().unwrap();
        let ed_sig = Ed25519Sig::from_bytes(&ed_sig_arr);
        let ed = sk.ed25519.as_ref().unwrap();
        assert!(ed.verifying_key().verify(MSG, &ed_sig).is_ok());

        // PQC is valid against the ML-DSA-65 verifying key.
        let (_, pqc_bytes) = sig_parse(sig.as_bytes()).unwrap();
        let pqc_sig = DsaSignature::from_raw(pqc_bytes.to_vec(), DsaLevel::Dsa65);
        assert!(dsa_verify(&vk.pqc, MSG, &pqc_sig).unwrap());
    }

    // ── Wire format ───────────────────────────────────────────────────────

    #[test]
    fn from_bytes_round_trip() {
        let (_, _, sig) = keygen_and_sign();
        let reconstructed = HybridSignature::from_bytes(sig.as_bytes()).unwrap();
        assert_eq!(sig.as_bytes(), reconstructed.as_bytes());
    }

    #[test]
    fn from_bytes_rejects_truncated_input() {
        assert!(HybridSignature::from_bytes(&[0u8; 3]).is_err());
    }

    #[test]
    fn mode_accessor() {
        let sk = hybrid_sig_keygen(HybridSigMode::Ed25519Dilithium65).unwrap();
        assert_eq!(sk.mode(), HybridSigMode::Ed25519Dilithium65);
        assert_eq!(sk.verifying_key().mode(), HybridSigMode::Ed25519Dilithium65);
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let sk = hybrid_sig_keygen(HybridSigMode::Ed25519Dilithium65).unwrap();
        let debug_str = format!("{sk:?}");
        assert!(debug_str.contains("REDACTED"));
    }
}
