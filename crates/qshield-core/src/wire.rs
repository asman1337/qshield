//! QShield Key Envelope (QSKE) wire format -- QS-113.
//!
//! Canonical serialization for keys and signatures that cross language/network
//! boundaries. Two representations are provided:
//!
//! 1. **Binary envelope** -- compact, CRC32C-protected.
//! 2. **PEM** -- human-readable, base64-encoded envelope for config files and
//!    copy-paste.
//!
//! ## Binary wire layout
//!
//! ```text
//! +------------------------------------------+
//! | magic:       4 bytes  ("QSKE")           |
//! | version:     1 byte   (0x01)             |
//! | algorithm:   2 bytes  (big-endian u16)   |
//! | key_type:    1 byte                      |
//! | payload_len: 4 bytes  (big-endian u32)   |
//! | payload:     [payload_len bytes]         |
//! | checksum:    4 bytes  (CRC32C of above)  |
//! +------------------------------------------+
//! ```
//!
//! The checksum covers every byte before it (magic through payload inclusive).

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use qshield_common::QShieldError;

// -- Constants --------------------------------------------------------------

const MAGIC: &[u8; 4] = b"QSKE";
const VERSION: u8 = 0x01;
/// Bytes before payload: magic(4) + version(1) + algo(2) + `key_type`(1) + `payload_len`(4)
const HEADER_LEN: usize = 12;
const CHECKSUM_LEN: usize = 4;
const MIN_ENVELOPE_LEN: usize = HEADER_LEN + CHECKSUM_LEN; // zero-length payload

// -- Algorithm codes --------------------------------------------------------

/// Identifies the cryptographic algorithm in an envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AlgorithmCode {
    MlKem512,
    MlKem768,
    MlKem1024,
    MlDsa44,
    MlDsa65,
    MlDsa87,
    SlhDsaSha2128s,
    SlhDsaSha2192f,
    X25519MlKem768,
    Ed25519MlDsa65,
}

impl AlgorithmCode {
    /// 2-byte big-endian encoding as specified in the QSKE wire format.
    #[must_use]
    pub fn to_u16(self) -> u16 {
        match self {
            Self::MlKem512 => 0x0101,
            Self::MlKem768 => 0x0102,
            Self::MlKem1024 => 0x0103,
            Self::MlDsa44 => 0x0201,
            Self::MlDsa65 => 0x0202,
            Self::MlDsa87 => 0x0203,
            Self::SlhDsaSha2128s => 0x0301,
            Self::SlhDsaSha2192f => 0x0302,
            Self::X25519MlKem768 => 0x0F01,
            Self::Ed25519MlDsa65 => 0x0F02,
        }
    }

    /// Parse from the 2-byte wire value.
    ///
    /// # Errors
    /// Returns `UnsupportedAlgorithm` for unrecognised codes.
    pub fn from_u16(v: u16) -> Result<Self, QShieldError> {
        match v {
            0x0101 => Ok(Self::MlKem512),
            0x0102 => Ok(Self::MlKem768),
            0x0103 => Ok(Self::MlKem1024),
            0x0201 => Ok(Self::MlDsa44),
            0x0202 => Ok(Self::MlDsa65),
            0x0203 => Ok(Self::MlDsa87),
            0x0301 => Ok(Self::SlhDsaSha2128s),
            0x0302 => Ok(Self::SlhDsaSha2192f),
            0x0F01 => Ok(Self::X25519MlKem768),
            0x0F02 => Ok(Self::Ed25519MlDsa65),
            other => Err(QShieldError::UnsupportedAlgorithm {
                name: format!("QSKE: unknown algorithm code 0x{other:04X}"),
            }),
        }
    }

    /// Human-readable label used in PEM headers.
    #[must_use]
    pub fn pem_label(self) -> &'static str {
        match self {
            Self::MlKem512 => "ML-KEM-512",
            Self::MlKem768 => "ML-KEM-768",
            Self::MlKem1024 => "ML-KEM-1024",
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
            Self::SlhDsaSha2128s => "SLH-DSA-SHA2-128S",
            Self::SlhDsaSha2192f => "SLH-DSA-SHA2-192F",
            Self::X25519MlKem768 => "X25519-ML-KEM-768",
            Self::Ed25519MlDsa65 => "ED25519-ML-DSA-65",
        }
    }
}

// -- Key type ---------------------------------------------------------------

/// Distinguishes how the payload bytes should be interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyType {
    Public = 0x01,
    Secret = 0x02,
    Pair = 0x03,
    Signature = 0x04,
    Ciphertext = 0x05,
}

impl KeyType {
    #[must_use]
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// # Errors
    /// Returns `UnsupportedAlgorithm` for unrecognised type bytes.
    pub fn from_u8(v: u8) -> Result<Self, QShieldError> {
        match v {
            0x01 => Ok(Self::Public),
            0x02 => Ok(Self::Secret),
            0x03 => Ok(Self::Pair),
            0x04 => Ok(Self::Signature),
            0x05 => Ok(Self::Ciphertext),
            _ => Err(QShieldError::UnsupportedAlgorithm {
                name: format!("QSKE: unknown key type byte 0x{v:02X}"),
            }),
        }
    }

    /// Label used in PEM headers.
    #[must_use]
    pub fn pem_label(self) -> &'static str {
        match self {
            Self::Public => "PUBLIC KEY",
            Self::Secret => "SECRET KEY",
            Self::Pair => "KEY PAIR",
            Self::Signature => "SIGNATURE",
            Self::Ciphertext => "CIPHERTEXT",
        }
    }
}

// -- QskeEnvelope ----------------------------------------------------------

/// A parsed QSKE envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QskeEnvelope {
    pub algorithm: AlgorithmCode,
    pub key_type: KeyType,
    pub payload: Vec<u8>,
}

impl QskeEnvelope {
    /// Encode the envelope to binary wire format.
    ///
    /// # Panics
    /// Panics if `payload.len()` exceeds `u32::MAX` (4 GB -- won't happen in practice).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let payload_len = u32::try_from(self.payload.len()).expect("payload exceeds 4 GB");
        let total = HEADER_LEN + self.payload.len() + CHECKSUM_LEN;
        let mut buf = Vec::with_capacity(total);

        buf.extend_from_slice(MAGIC);
        buf.push(VERSION);
        buf.extend_from_slice(&self.algorithm.to_u16().to_be_bytes());
        buf.push(self.key_type.to_u8());
        buf.extend_from_slice(&payload_len.to_be_bytes());
        buf.extend_from_slice(&self.payload);

        let checksum = crc32c::crc32c(&buf);
        buf.extend_from_slice(&checksum.to_be_bytes());
        buf
    }

    /// Decode from binary wire format.
    ///
    /// # Errors
    /// - `InvalidKeyLength` if the byte slice is too short.
    /// - `UnsupportedAlgorithm` for unknown algorithm/key-type codes.
    /// - `DecryptionFailed` (checksum mismatch -- integrity violation).
    pub fn decode(bytes: &[u8]) -> Result<Self, QShieldError> {
        if bytes.len() < MIN_ENVELOPE_LEN {
            return Err(QShieldError::InvalidKeyLength {
                expected: MIN_ENVELOPE_LEN,
                actual: bytes.len(),
            });
        }

        // Check magic.
        if &bytes[0..4] != MAGIC {
            return Err(QShieldError::UnsupportedAlgorithm {
                name: "QSKE: bad magic bytes".to_string(),
            });
        }

        // Version check -- accept only 0x01 for now.
        if bytes[4] != VERSION {
            return Err(QShieldError::UnsupportedAlgorithm {
                name: format!("QSKE: unsupported envelope version 0x{:02X}", bytes[4]),
            });
        }

        let algorithm = AlgorithmCode::from_u16(u16::from_be_bytes([bytes[5], bytes[6]]))?;
        let key_type = KeyType::from_u8(bytes[7])?;
        let payload_len = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;

        let expected_total = HEADER_LEN + payload_len + CHECKSUM_LEN;
        if bytes.len() != expected_total {
            return Err(QShieldError::InvalidKeyLength {
                expected: expected_total,
                actual: bytes.len(),
            });
        }

        // Verify CRC32C over everything before the checksum field.
        let data_end = HEADER_LEN + payload_len;
        let stored_crc = u32::from_be_bytes([
            bytes[data_end],
            bytes[data_end + 1],
            bytes[data_end + 2],
            bytes[data_end + 3],
        ]);
        let computed_crc = crc32c::crc32c(&bytes[..data_end]);
        if stored_crc != computed_crc {
            return Err(QShieldError::DecryptionFailed); // integrity violation
        }

        let payload = bytes[HEADER_LEN..data_end].to_vec();
        Ok(Self {
            algorithm,
            key_type,
            payload,
        })
    }

    // -- PEM ---------------------------------------------------------------

    /// Encode to PEM format.
    ///
    /// ```text
    /// -----BEGIN QSHIELD ML-KEM-768 PUBLIC KEY-----
    /// <base64 of binary envelope, 64-char lines>
    /// -----END QSHIELD ML-KEM-768 PUBLIC KEY-----
    /// ```
    ///
    /// # Panics
    /// Panics if the base64 output is not valid UTF-8 (cannot happen in practice).
    #[must_use]
    pub fn to_pem(&self) -> String {
        let label = self.pem_label();
        let encoded_bytes = self.encode();
        let b64 = BASE64.encode(&encoded_bytes);

        // Wrap base64 at 64 chars per line.
        let lines: String = b64
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("\n");

        format!("-----BEGIN QSHIELD {label}-----\n{lines}\n-----END QSHIELD {label}-----\n")
    }

    /// Decode from PEM format.
    ///
    /// # Errors
    /// Returns `UnsupportedAlgorithm` if the PEM is malformed, and propagates
    /// errors from `decode()`.
    pub fn from_pem(pem: &str) -> Result<Self, QShieldError> {
        let malformed = || QShieldError::UnsupportedAlgorithm {
            name: "QSKE: malformed PEM".to_string(),
        };

        // Find begin line.
        let begin_marker = "-----BEGIN QSHIELD ";
        let end_marker = "-----END QSHIELD ";

        let begin_pos = pem.find(begin_marker).ok_or_else(malformed)?;
        let end_pos = pem.find(end_marker).ok_or_else(malformed)?;

        // Extract base64 body (everything between the two header lines).
        let after_begin_line = pem[begin_pos..]
            .find('\n')
            .map(|p| begin_pos + p + 1)
            .ok_or_else(malformed)?;

        let b64_body: String = pem[after_begin_line..end_pos]
            .lines()
            .collect::<Vec<_>>()
            .join("");

        let envelope_bytes = BASE64.decode(b64_body.trim()).map_err(|_| malformed())?;
        Self::decode(&envelope_bytes)
    }

    // -- Private helpers ---------------------------------------------------

    fn pem_label(&self) -> String {
        format!(
            "{} {}",
            self.algorithm.pem_label(),
            self.key_type.pem_label()
        )
    }
}

// -- Serde support ----------------------------------------------------------
//
// Key types use custom Serialize/Deserialize implementations in their own
// modules (kem.rs, dsa.rs, hybrid_sig.rs). Here we provide helpers they can
// use without duplicating base64/envelope logic.

/// Serialize a payload to a base64-encoded QSKE envelope string.
/// Used by key-type serde impls.
#[must_use]
pub fn to_envelope_b64(algorithm: AlgorithmCode, key_type: KeyType, payload: &[u8]) -> String {
    let env = QskeEnvelope {
        algorithm,
        key_type,
        payload: payload.to_vec(),
    };
    BASE64.encode(env.encode())
}

/// Deserialize a payload from a base64-encoded QSKE envelope string,
/// asserting the expected algorithm and key type.
///
/// # Errors
/// Returns `InvalidKeyLength` / `UnsupportedAlgorithm` / `DecryptionFailed`
/// on any parse/validation failure.
pub fn from_envelope_b64(
    b64: &str,
    expected_algo: AlgorithmCode,
    expected_key_type: KeyType,
) -> Result<Vec<u8>, QShieldError> {
    let bytes = BASE64
        .decode(b64)
        .map_err(|_| QShieldError::UnsupportedAlgorithm {
            name: "QSKE: invalid base64".to_string(),
        })?;
    let env = QskeEnvelope::decode(&bytes)?;
    if env.algorithm != expected_algo {
        return Err(QShieldError::UnsupportedAlgorithm {
            name: format!(
                "QSKE: algorithm mismatch: expected 0x{:04X}, got 0x{:04X}",
                expected_algo.to_u16(),
                env.algorithm.to_u16()
            ),
        });
    }
    if env.key_type != expected_key_type {
        return Err(QShieldError::UnsupportedAlgorithm {
            name: format!(
                "QSKE: key type mismatch: expected 0x{:02X}, got 0x{:02X}",
                expected_key_type.to_u8(),
                env.key_type.to_u8()
            ),
        });
    }
    Ok(env.payload)
}

// -- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_envelope() -> QskeEnvelope {
        QskeEnvelope {
            algorithm: AlgorithmCode::MlKem768,
            key_type: KeyType::Public,
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03],
        }
    }

    // -- Binary encode/decode ----------------------------------------------

    #[test]
    fn binary_round_trip() {
        let env = sample_envelope();
        let bytes = env.encode();
        let decoded = QskeEnvelope::decode(&bytes).unwrap();
        assert_eq!(decoded, env);
    }

    #[test]
    fn binary_magic_is_qske() {
        let bytes = sample_envelope().encode();
        assert_eq!(&bytes[0..4], b"QSKE");
    }

    #[test]
    fn binary_version_is_01() {
        let bytes = sample_envelope().encode();
        assert_eq!(bytes[4], 0x01);
    }

    #[test]
    fn binary_empty_payload_round_trip() {
        let env = QskeEnvelope {
            algorithm: AlgorithmCode::MlDsa65,
            key_type: KeyType::Signature,
            payload: vec![],
        };
        let decoded = QskeEnvelope::decode(&env.encode()).unwrap();
        assert_eq!(decoded, env);
    }

    // -- CRC32C integrity --------------------------------------------------

    #[test]
    fn checksum_detects_single_bit_corruption() {
        let mut bytes = sample_envelope().encode();
        // Flip a bit in the payload area (byte 13, safely inside payload).
        bytes[13] ^= 0x01;
        assert!(QskeEnvelope::decode(&bytes).is_err());
    }

    #[test]
    fn checksum_detects_header_corruption() {
        let mut bytes = sample_envelope().encode();
        // Flip a bit in the algorithm field.
        bytes[5] ^= 0x01;
        assert!(QskeEnvelope::decode(&bytes).is_err());
    }

    // -- Error paths -------------------------------------------------------

    #[test]
    fn unknown_algorithm_code_returns_err() {
        let env = sample_envelope();
        let mut bytes = env.encode();
        // Overwrite algorithm bytes with an unknown code (0xFFFF).
        bytes[5] = 0xFF;
        bytes[6] = 0xFF;
        // Fix the checksum so the error comes from algorithm parsing.
        let crc = crc32c::crc32c(&bytes[..bytes.len() - 4]);
        let n = bytes.len();
        bytes[n - 4..].copy_from_slice(&crc.to_be_bytes());
        let err = QskeEnvelope::decode(&bytes).unwrap_err();
        assert!(matches!(err, QShieldError::UnsupportedAlgorithm { .. }));
    }

    #[test]
    fn bad_magic_returns_err() {
        let mut bytes = sample_envelope().encode();
        bytes[0] = b'X';
        assert!(QskeEnvelope::decode(&bytes).is_err());
    }

    #[test]
    fn too_short_returns_err() {
        assert!(QskeEnvelope::decode(&[0u8; 5]).is_err());
    }

    #[test]
    fn truncated_payload_returns_err() {
        let bytes = sample_envelope().encode();
        // Drop the last byte (truncates checksum).
        assert!(QskeEnvelope::decode(&bytes[..bytes.len() - 1]).is_err());
    }

    // -- PEM ---------------------------------------------------------------

    #[test]
    fn pem_round_trip() {
        let env = sample_envelope();
        let pem = env.to_pem();
        let decoded = QskeEnvelope::from_pem(&pem).unwrap();
        assert_eq!(decoded, env);
    }

    #[test]
    fn pem_contains_correct_header() {
        let pem = sample_envelope().to_pem();
        assert!(pem.contains("-----BEGIN QSHIELD ML-KEM-768 PUBLIC KEY-----"));
        assert!(pem.contains("-----END QSHIELD ML-KEM-768 PUBLIC KEY-----"));
    }

    #[test]
    fn pem_roundtrip_all_algorithms() {
        for (algo, kt) in [
            (AlgorithmCode::MlKem512, KeyType::Public),
            (AlgorithmCode::MlDsa87, KeyType::Secret),
            (AlgorithmCode::Ed25519MlDsa65, KeyType::Signature),
            (AlgorithmCode::X25519MlKem768, KeyType::Ciphertext),
        ] {
            let env = QskeEnvelope {
                algorithm: algo,
                key_type: kt,
                payload: vec![1, 2, 3],
            };
            let decoded = QskeEnvelope::from_pem(&env.to_pem()).unwrap();
            assert_eq!(decoded, env);
        }
    }

    #[test]
    fn pem_malformed_returns_err() {
        assert!(QskeEnvelope::from_pem("not pem at all").is_err());
        assert!(QskeEnvelope::from_pem("-----BEGIN QSHIELD ML-KEM-768 PUBLIC KEY-----\n!!!invalid base64!!!\n-----END QSHIELD ML-KEM-768 PUBLIC KEY-----\n").is_err());
    }

    // -- Envelope helpers --------------------------------------------------

    #[test]
    fn envelope_b64_helpers_round_trip() {
        let payload = b"some key bytes here";
        let b64 = to_envelope_b64(AlgorithmCode::MlDsa65, KeyType::Public, payload);
        let out = from_envelope_b64(&b64, AlgorithmCode::MlDsa65, KeyType::Public).unwrap();
        assert_eq!(out.as_slice(), payload);
    }

    #[test]
    fn envelope_b64_algo_mismatch_returns_err() {
        let b64 = to_envelope_b64(AlgorithmCode::MlDsa65, KeyType::Public, b"x");
        assert!(from_envelope_b64(&b64, AlgorithmCode::MlKem768, KeyType::Public).is_err());
    }

    #[test]
    fn envelope_b64_key_type_mismatch_returns_err() {
        let b64 = to_envelope_b64(AlgorithmCode::MlDsa65, KeyType::Public, b"x");
        assert!(from_envelope_b64(&b64, AlgorithmCode::MlDsa65, KeyType::Secret).is_err());
    }

    // -- Serde JSON for key types (QS-113 acceptance criterion) -----------

    #[test]
    fn serde_json_kem_public_key() {
        use crate::kem::{KemLevel, kem_keygen};
        let kp = kem_keygen(KemLevel::Kem768).unwrap();
        let json = serde_json::to_string(&kp.public_key).unwrap();
        let restored: crate::kem::KemPublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(kp.public_key.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn serde_json_kem_ciphertext() {
        use crate::kem::{KemLevel, kem_encapsulate, kem_keygen};
        let kp = kem_keygen(KemLevel::Kem512).unwrap();
        let (_ss, ct) = kem_encapsulate(&kp.public_key).unwrap();
        let json = serde_json::to_string(&ct).unwrap();
        let restored: crate::kem::KemCiphertext = serde_json::from_str(&json).unwrap();
        assert_eq!(ct.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn serde_json_dsa_verifying_key() {
        use crate::dsa::{DsaLevel, dsa_keygen};
        let kp = dsa_keygen(DsaLevel::Dsa65).unwrap();
        let vk = kp.verifying_key();
        let json = serde_json::to_string(&vk).unwrap();
        let restored: crate::dsa::DsaVerifyingKey = serde_json::from_str(&json).unwrap();
        assert_eq!(vk.as_bytes(), restored.as_bytes());
    }

    #[test]
    fn serde_json_dsa_signature() {
        use crate::dsa::{DsaLevel, dsa_keygen, dsa_sign};
        let kp = dsa_keygen(DsaLevel::Dsa44).unwrap();
        let sig = dsa_sign(&kp, b"msg").unwrap();
        let json = serde_json::to_string(&sig).unwrap();
        let restored: crate::dsa::DsaSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig.as_bytes(), restored.as_bytes());
    }

    #[test]
    fn serde_json_hybrid_signature() {
        use crate::hybrid_sig::{HybridSigMode, hybrid_sig_keygen, hybrid_sign};
        let sk = hybrid_sig_keygen(HybridSigMode::Ed25519Dilithium65).unwrap();
        let sig = hybrid_sign(&sk, b"msg").unwrap();
        let json = serde_json::to_string(&sig).unwrap();
        let restored: crate::hybrid_sig::HybridSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig.as_bytes(), restored.as_bytes());
    }
}
