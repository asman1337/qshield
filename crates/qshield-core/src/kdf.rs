//! Key Derivation Functions — QS-107.
//!
//! # Functions
//!
//! | Function | Hash | Notes |
//! |---|---|---|
//! | [`hkdf_sha256`] | SHA-256 | TLS/HPKE compatible |
//! | [`hkdf_sha3_256`] | SHA3-256 | Higher quantum-security margin |
//! | [`derive_key_256`] | SHA3-256 | Convenience: always 32 bytes |
//!
//! All output buffers are wrapped in [`Zeroizing`] so they are wiped when
//! dropped. The input key material is **not** copied — callers are responsible
//! for zeroizing `ikm` themselves.

use hkdf::Hkdf;
use sha2::Sha256;
use sha3::Sha3_256;
use zeroize::Zeroizing;

use qshield_common::QShieldError;

// HKDF-SHA-256: max output = 255 * 32 = 8160 bytes
const HKDF_SHA256_MAX: usize = 255 * 32;
// HKDF-SHA3-256: max output = 255 * 32 = 8160 bytes
const HKDF_SHA3_256_MAX: usize = 255 * 32;

/// HKDF-SHA-256 (RFC 5869).
///
/// Compatible with TLS 1.3, HPKE (RFC 9180), and the hybrid KEM in
/// `qshield-core::hybrid`.
///
/// # Errors
/// - `KeyDerivation` if `output_len == 0` or `output_len > 8160`.
pub fn hkdf_sha256(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    output_len: usize,
) -> Result<Zeroizing<Vec<u8>>, QShieldError> {
    validate_output_len(output_len, HKDF_SHA256_MAX)?;
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = Zeroizing::new(vec![0u8; output_len]);
    hk.expand(info, &mut okm)
        .map_err(|_| QShieldError::KeyDerivation {
            reason: "HKDF-SHA256 expand: output_len exceeds limit",
        })?;
    Ok(okm)
}

/// HKDF-SHA3-256.
///
/// Preferred for new QShield protocols — SHA-3's sponge construction provides
/// a higher security margin against quantum adversaries than SHA-2.
///
/// # Errors
/// - `KeyDerivation` if `output_len == 0` or `output_len > 8160`.
pub fn hkdf_sha3_256(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    output_len: usize,
) -> Result<Zeroizing<Vec<u8>>, QShieldError> {
    validate_output_len(output_len, HKDF_SHA3_256_MAX)?;
    let hk = Hkdf::<Sha3_256>::new(salt, ikm);
    let mut okm = Zeroizing::new(vec![0u8; output_len]);
    hk.expand(info, &mut okm)
        .map_err(|_| QShieldError::KeyDerivation {
            reason: "HKDF-SHA3-256 expand: output_len exceeds limit",
        })?;
    Ok(okm)
}

/// Convenience wrapper: derive exactly 32 bytes with HKDF-SHA3-256.
///
/// The returned array is stack-allocated and zeroized on drop.
///
/// # Errors
/// Propagates `KeyDerivation` on HKDF failure (should never happen for 32 bytes).
pub fn derive_key_256(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
) -> Result<Zeroizing<[u8; 32]>, QShieldError> {
    let hk = Hkdf::<Sha3_256>::new(salt, ikm);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(info, okm.as_mut())
        .map_err(|_| QShieldError::KeyDerivation {
            reason: "HKDF-SHA3-256 expand: unexpected failure for 32-byte output",
        })?;
    Ok(okm)
}

// ── Internal helpers ────────────────────────────────────────────────────────

fn validate_output_len(len: usize, max: usize) -> Result<(), QShieldError> {
    if len == 0 {
        return Err(QShieldError::KeyDerivation {
            reason: "output_len must be > 0",
        });
    }
    if len > max {
        return Err(QShieldError::KeyDerivation {
            reason: "output_len exceeds HKDF maximum (255 * HashLen)",
        });
    }
    Ok(())
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 5869 Test Case 1 (HMAC-SHA-256)
    // https://www.rfc-editor.org/rfc/rfc5869#appendix-A.1
    #[test]
    fn rfc5869_test_case_1() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let expected = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )
        .unwrap();

        let okm = hkdf_sha256(&ikm, Some(&salt), &info, 42).expect("hkdf_sha256");
        assert_eq!(&okm[..], &expected[..], "RFC 5869 test case 1 mismatch");
    }

    // RFC 5869 Test Case 2 (longer, no salt)
    #[test]
    fn rfc5869_test_case_2() {
        let ikm = hex::decode(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
             404142434445464748494a4b4c4d4e4f",
        )
        .unwrap();
        let salt = hex::decode(
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
             808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
             a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        )
        .unwrap();
        let info = hex::decode(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
             d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        )
        .unwrap();
        let expected = hex::decode(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f1d87",
        )
        .unwrap();

        let okm = hkdf_sha256(&ikm, Some(&salt), &info, 82).expect("hkdf_sha256 tc2");
        assert_eq!(&okm[..], &expected[..], "RFC 5869 test case 2 mismatch");
    }

    // RFC 5869 Test Case 3 (no salt, no info)
    #[test]
    fn rfc5869_test_case_3() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let expected = hex::decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8",
        )
        .unwrap();

        let okm = hkdf_sha256(&ikm, None, &[], 42).expect("hkdf_sha256 tc3");
        assert_eq!(&okm[..], &expected[..], "RFC 5869 test case 3 mismatch");
    }

    #[test]
    fn hkdf_sha3_256_deterministic() {
        let ikm = b"test input key material";
        let salt = b"test salt";
        let info = b"test context";

        let out1 = hkdf_sha3_256(ikm, Some(salt), info, 64).expect("first");
        let out2 = hkdf_sha3_256(ikm, Some(salt), info, 64).expect("second");
        assert_eq!(&out1[..], &out2[..], "HKDF-SHA3-256 must be deterministic");
    }

    #[test]
    fn hkdf_sha3_256_different_info_differs() {
        let ikm = b"same key material";
        let out_a = hkdf_sha3_256(ikm, None, b"purpose:a", 32).expect("a");
        let out_b = hkdf_sha3_256(ikm, None, b"purpose:b", 32).expect("b");
        assert_ne!(
            &out_a[..],
            &out_b[..],
            "different info must produce different output"
        );
    }

    #[test]
    fn derive_key_256_is_32_bytes() {
        let key = derive_key_256(b"master secret", Some(b"salt"), b"subkey:enc").expect("derive");
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn zero_output_len_errors() {
        let err = hkdf_sha256(b"ikm", None, b"", 0).unwrap_err();
        assert!(matches!(err, QShieldError::KeyDerivation { .. }));
    }

    #[test]
    fn over_limit_output_len_errors() {
        // 8161 > 255 * 32 = 8160
        let err = hkdf_sha256(b"ikm", None, b"", 8161).unwrap_err();
        assert!(matches!(err, QShieldError::KeyDerivation { .. }));
    }

    #[test]
    fn output_is_zeroized_type() {
        // Compile-time: return type is Zeroizing<Vec<u8>> — zeroize on drop
        let _: Zeroizing<Vec<u8>> = hkdf_sha256(b"k", None, b"i", 32).expect("ok");
        let _: Zeroizing<[u8; 32]> = derive_key_256(b"k", None, b"i").expect("ok");
    }
}
