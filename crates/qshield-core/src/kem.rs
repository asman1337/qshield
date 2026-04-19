//! ML-KEM (FIPS 203) key encapsulation -- QS-101.
//!
//! Wraps the `ml-kem` RustCrypto crate. Keys are stored in their native
//! in-memory form; serialization to/from raw bytes is available via
//! `to_bytes()` / `from_bytes()`.

use std::fmt;

use ml_kem::{
    EncodedSizeUser, KemCore, MlKem512, MlKem512Params, MlKem768, MlKem768Params, MlKem1024,
    MlKem1024Params,
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey},
};
use rand_core::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use qshield_common::QShieldError;

// -- Algorithm names --------------------------------------------------------

const ALG_512: &str = "ML-KEM-512";
const ALG_768: &str = "ML-KEM-768";
const ALG_1024: &str = "ML-KEM-1024";

// -- Public types -----------------------------------------------------------

/// Which ML-KEM parameter set to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemLevel {
    /// NIST security level 1 (~AES-128 classical equivalent).
    Kem512,
    /// NIST security level 3 -- QShield default.
    Kem768,
    /// NIST security level 5 -- high-security environments.
    Kem1024,
}

impl KemLevel {
    #[must_use]
    pub fn algorithm_name(self) -> &'static str {
        match self {
            Self::Kem512 => ALG_512,
            Self::Kem768 => ALG_768,
            Self::Kem1024 => ALG_1024,
        }
    }
}

/// ML-KEM encapsulation (public) key.
pub struct KemPublicKey {
    inner: EkInner,
    level: KemLevel,
}

/// ML-DSA decapsulation (secret) key. Zeroized on drop via `Option::take()`
/// which triggers `DecapsulationKey`'s `ZeroizeOnDrop` (ml-kem zeroize feature).
pub struct KemSecretKey {
    inner: Option<DkInner>,
    level: KemLevel,
}

/// A generated ML-KEM key pair.
pub struct KemKeyPair {
    pub public_key: KemPublicKey,
    pub secret_key: KemSecretKey,
}

/// An ML-KEM ciphertext (encapsulated shared secret).
/// Stored as raw bytes to avoid fighting with `hybrid_array` type-level sizes.
#[derive(Clone)]
pub struct KemCiphertext {
    bytes: Vec<u8>,
    level: KemLevel,
}

/// A 32-byte shared secret. Zeroized on drop via `ZeroizeOnDrop` derive.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; 32]);

// -- Private inner enums ----------------------------------------------------

enum EkInner {
    Kem512(EncapsulationKey<MlKem512Params>),
    Kem768(EncapsulationKey<MlKem768Params>),
    Kem1024(EncapsulationKey<MlKem1024Params>),
}

enum DkInner {
    Kem512(DecapsulationKey<MlKem512Params>),
    Kem768(DecapsulationKey<MlKem768Params>),
    Kem1024(DecapsulationKey<MlKem1024Params>),
}

// -- Helpers ----------------------------------------------------------------

/// Convert an `EncodedSizeUser` (key/ciphertext) to bytes without fighting the
/// `AsRef<T>` type-inference issue on `hybrid_array::Array`.
fn encoded_to_vec<T: EncodedSizeUser>(v: &T) -> Vec<u8>
where
    ml_kem::Encoded<T>: AsRef<[u8]>,
{
    v.as_bytes().as_ref().to_vec()
}

/// Shared-secret bytes ? `[u8; 32]` via Deref to `[u8]` slice.
fn ss_to_arr(ss: &[u8]) -> [u8; 32] {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(ss);
    arr
}

// -- Drop / zeroize ---------------------------------------------------------

// SharedSecret uses #[derive(Zeroize, ZeroizeOnDrop)] — see its definition.

impl Zeroize for KemSecretKey {
    fn zeroize(&mut self) {
        // `Option::take` moves the inner `DecapsulationKey<P>` out and drops
        // it here, triggering ml-kem's `ZeroizeOnDrop` — no keygen needed.
        drop(self.inner.take());
    }
}

impl Drop for KemSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for KemSecretKey {}

// -- Debug impls (security: never print key material) ----------------------

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedSecret([REDACTED])")
    }
}

impl fmt::Debug for KemPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KemPublicKey(level={:?})", self.level)
    }
}

impl fmt::Debug for KemSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KemSecretKey([REDACTED] level={:?})", self.level)
    }
}

impl fmt::Debug for KemCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KemCiphertext([{} bytes] level={:?})",
            self.bytes.len(),
            self.level
        )
    }
}

// -- Serialization ----------------------------------------------------------

impl KemPublicKey {
    /// Encode the encapsulation key as raw bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        match &self.inner {
            EkInner::Kem512(ek) => encoded_to_vec(ek),
            EkInner::Kem768(ek) => encoded_to_vec(ek),
            EkInner::Kem1024(ek) => encoded_to_vec(ek),
        }
    }

    /// Reconstruct from raw bytes.
    ///
    /// # Errors
    /// Returns `InvalidKeyLength` if the byte slice length does not match the
    /// expected size for `level`.
    pub fn from_bytes(level: KemLevel, bytes: &[u8]) -> Result<Self, QShieldError> {
        let inner = match level {
            KemLevel::Kem512 => {
                if bytes.len() != 800 {
                    return Err(QShieldError::InvalidKeyLength {
                        expected: 800,
                        actual: bytes.len(),
                    });
                }
                #[allow(deprecated)]
                EkInner::Kem512(EncapsulationKey::<MlKem512Params>::from_bytes(
                    ml_kem::array::Array::from_slice(bytes),
                ))
            }
            KemLevel::Kem768 => {
                if bytes.len() != 1184 {
                    return Err(QShieldError::InvalidKeyLength {
                        expected: 1184,
                        actual: bytes.len(),
                    });
                }
                #[allow(deprecated)]
                EkInner::Kem768(EncapsulationKey::<MlKem768Params>::from_bytes(
                    ml_kem::array::Array::from_slice(bytes),
                ))
            }
            KemLevel::Kem1024 => {
                if bytes.len() != 1568 {
                    return Err(QShieldError::InvalidKeyLength {
                        expected: 1568,
                        actual: bytes.len(),
                    });
                }
                #[allow(deprecated)]
                EkInner::Kem1024(EncapsulationKey::<MlKem1024Params>::from_bytes(
                    ml_kem::array::Array::from_slice(bytes),
                ))
            }
        };
        Ok(Self { inner, level })
    }

    #[must_use]
    pub fn level(&self) -> KemLevel {
        self.level
    }
}

impl KemSecretKey {
    /// Encode the decapsulation key as raw bytes.
    ///
    /// # Security
    /// The returned bytes are sensitive -- handle and erase with care.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        match self.inner.as_ref().expect("KemSecretKey already zeroized") {
            DkInner::Kem512(dk) => encoded_to_vec(dk),
            DkInner::Kem768(dk) => encoded_to_vec(dk),
            DkInner::Kem1024(dk) => encoded_to_vec(dk),
        }
    }

    #[must_use]
    pub fn level(&self) -> KemLevel {
        self.level
    }

    /// Reconstruct a decapsulation key from raw bytes.
    ///
    /// # Errors
    /// Returns `InvalidKeyLength` if byte length doesn't match the level.
    pub fn from_bytes(level: KemLevel, bytes: &[u8]) -> Result<Self, QShieldError> {
        let expected = match level {
            KemLevel::Kem512 => 1632,
            KemLevel::Kem768 => 2400,
            KemLevel::Kem1024 => 3168,
        };
        if bytes.len() != expected {
            return Err(QShieldError::InvalidKeyLength {
                expected,
                actual: bytes.len(),
            });
        }
        let inner = match level {
            KemLevel::Kem512 =>
            {
                #[allow(deprecated)]
                DkInner::Kem512(
                    ml_kem::kem::DecapsulationKey::<ml_kem::MlKem512Params>::from_bytes(
                        ml_kem::array::Array::from_slice(bytes),
                    ),
                )
            }
            KemLevel::Kem768 =>
            {
                #[allow(deprecated)]
                DkInner::Kem768(
                    ml_kem::kem::DecapsulationKey::<ml_kem::MlKem768Params>::from_bytes(
                        ml_kem::array::Array::from_slice(bytes),
                    ),
                )
            }
            KemLevel::Kem1024 =>
            {
                #[allow(deprecated)]
                DkInner::Kem1024(
                    ml_kem::kem::DecapsulationKey::<ml_kem::MlKem1024Params>::from_bytes(
                        ml_kem::array::Array::from_slice(bytes),
                    ),
                )
            }
        };
        Ok(KemSecretKey {
            inner: Some(inner),
            level,
        })
    }
}

impl KemCiphertext {
    /// Raw bytes of this ciphertext.
    #[must_use]
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Reconstruct from raw bytes.
    ///
    /// # Errors
    /// Returns `InvalidKeyLength` if byte length doesn't match the level.
    pub fn from_bytes(level: KemLevel, bytes: &[u8]) -> Result<Self, QShieldError> {
        let expected = match level {
            KemLevel::Kem512 => 768,
            KemLevel::Kem768 => 1088,
            KemLevel::Kem1024 => 1568,
        };
        if bytes.len() != expected {
            return Err(QShieldError::InvalidKeyLength {
                expected,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            level,
        })
    }

    #[must_use]
    pub fn level(&self) -> KemLevel {
        self.level
    }
}

impl SharedSecret {
    /// Access the raw 32 bytes of the shared secret.
    ///
    /// # Security
    /// Use only within cryptographic operations. Never log.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Construct from raw bytes. Crate-internal — callers must ensure bytes
    /// are already cryptographically strong and will be zeroized on drop.
    pub(crate) fn from_raw(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

// -- Core API ---------------------------------------------------------------

/// Generate a new ML-KEM key pair for the given security level.
///
/// Uses the OS CSPRNG (`OsRng`) for key generation.
///
/// # Errors
/// Currently infallible, but returns `Result` for API consistency.
pub fn kem_keygen(level: KemLevel) -> Result<KemKeyPair, QShieldError> {
    let mut rng = OsRng;
    let (dk_inner, ek_inner) = match level {
        KemLevel::Kem512 => {
            let (dk, ek) = MlKem512::generate(&mut rng);
            (DkInner::Kem512(dk), EkInner::Kem512(ek))
        }
        KemLevel::Kem768 => {
            let (dk, ek) = MlKem768::generate(&mut rng);
            (DkInner::Kem768(dk), EkInner::Kem768(ek))
        }
        KemLevel::Kem1024 => {
            let (dk, ek) = MlKem1024::generate(&mut rng);
            (DkInner::Kem1024(dk), EkInner::Kem1024(ek))
        }
    };
    Ok(KemKeyPair {
        public_key: KemPublicKey {
            inner: ek_inner,
            level,
        },
        secret_key: KemSecretKey {
            inner: Some(dk_inner),
            level,
        },
    })
}

/// Encapsulate a shared secret to the holder of `pk`.
///
/// Returns `(SharedSecret, KemCiphertext)`. Send the ciphertext to the holder
/// of the corresponding secret key; use the shared secret locally.
///
/// # Errors
/// Returns `Encapsulation` on failure (currently infallible in ml-kem).
pub fn kem_encapsulate(pk: &KemPublicKey) -> Result<(SharedSecret, KemCiphertext), QShieldError> {
    let mut rng = OsRng;
    match &pk.inner {
        EkInner::Kem512(ek) => {
            let (ct, ss) = ek
                .encapsulate(&mut rng)
                .map_err(|_| QShieldError::Encapsulation { algorithm: ALG_512 })?;
            let ct_bytes: Vec<u8> = AsRef::<[u8]>::as_ref(&ct).to_vec();
            let ss_bytes: &[u8] = AsRef::<[u8]>::as_ref(&ss);
            Ok((
                SharedSecret(ss_to_arr(ss_bytes)),
                KemCiphertext {
                    bytes: ct_bytes,
                    level: pk.level,
                },
            ))
        }
        EkInner::Kem768(ek) => {
            let (ct, ss) = ek
                .encapsulate(&mut rng)
                .map_err(|_| QShieldError::Encapsulation { algorithm: ALG_768 })?;
            let ct_bytes: Vec<u8> = AsRef::<[u8]>::as_ref(&ct).to_vec();
            let ss_bytes: &[u8] = AsRef::<[u8]>::as_ref(&ss);
            Ok((
                SharedSecret(ss_to_arr(ss_bytes)),
                KemCiphertext {
                    bytes: ct_bytes,
                    level: pk.level,
                },
            ))
        }
        EkInner::Kem1024(ek) => {
            let (ct, ss) = ek
                .encapsulate(&mut rng)
                .map_err(|_| QShieldError::Encapsulation {
                    algorithm: ALG_1024,
                })?;
            let ct_bytes: Vec<u8> = AsRef::<[u8]>::as_ref(&ct).to_vec();
            let ss_bytes: &[u8] = AsRef::<[u8]>::as_ref(&ss);
            Ok((
                SharedSecret(ss_to_arr(ss_bytes)),
                KemCiphertext {
                    bytes: ct_bytes,
                    level: pk.level,
                },
            ))
        }
    }
}

/// Decapsulate a shared secret from `ct` using `sk`.
///
/// # Errors
/// Returns `Decapsulation` if the level of `sk` and `ct` do not match, or on
/// internal failure.
pub fn kem_decapsulate(
    sk: &KemSecretKey,
    ct: &KemCiphertext,
) -> Result<SharedSecret, QShieldError> {
    if sk.level != ct.level {
        return Err(QShieldError::Decapsulation {
            algorithm: "ML-KEM (level mismatch)",
        });
    }
    match sk.inner.as_ref().expect("KemSecretKey already zeroized") {
        DkInner::Kem512(dk) => {
            #[allow(deprecated)]
            let ct_arr = ml_kem::array::Array::from_slice(&ct.bytes);
            let ss = dk
                .decapsulate(ct_arr)
                .map_err(|_| QShieldError::Decapsulation { algorithm: ALG_512 })?;
            Ok(SharedSecret(ss_to_arr(ss.as_ref())))
        }
        DkInner::Kem768(dk) => {
            #[allow(deprecated)]
            let ct_arr = ml_kem::array::Array::from_slice(&ct.bytes);
            let ss = dk
                .decapsulate(ct_arr)
                .map_err(|_| QShieldError::Decapsulation { algorithm: ALG_768 })?;
            Ok(SharedSecret(ss_to_arr(ss.as_ref())))
        }
        DkInner::Kem1024(dk) => {
            #[allow(deprecated)]
            let ct_arr = ml_kem::array::Array::from_slice(&ct.bytes);
            let ss = dk
                .decapsulate(ct_arr)
                .map_err(|_| QShieldError::Decapsulation {
                    algorithm: ALG_1024,
                })?;
            Ok(SharedSecret(ss_to_arr(ss.as_ref())))
        }
    }
}

// -- Serde (QS-113) ---------------------------------------------------------
//
// KemPublicKey, KemSecretKey, and KemCiphertext serialize as base64-encoded
// QSKE envelopes (JSON-safe strings).

use crate::wire::{AlgorithmCode, KeyType, QskeEnvelope};
use base64::Engine as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

fn level_to_algo(level: KemLevel) -> AlgorithmCode {
    match level {
        KemLevel::Kem512 => AlgorithmCode::MlKem512,
        KemLevel::Kem768 => AlgorithmCode::MlKem768,
        KemLevel::Kem1024 => AlgorithmCode::MlKem1024,
    }
}

fn algo_to_level(algo: AlgorithmCode) -> Result<KemLevel, QShieldError> {
    match algo {
        AlgorithmCode::MlKem512 => Ok(KemLevel::Kem512),
        AlgorithmCode::MlKem768 => Ok(KemLevel::Kem768),
        AlgorithmCode::MlKem1024 => Ok(KemLevel::Kem1024),
        _ => Err(QShieldError::UnsupportedAlgorithm {
            name: format!(
                "KemLevel: unexpected algorithm code 0x{:04X}",
                algo.to_u16()
            ),
        }),
    }
}

fn decode_kem_envelope<'de, D: Deserializer<'de>>(
    d: D,
    expected_kt: KeyType,
) -> Result<(KemLevel, Vec<u8>), D::Error> {
    let b64 = String::deserialize(d)?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(serde::de::Error::custom)?;
    let env = QskeEnvelope::decode(&raw).map_err(serde::de::Error::custom)?;
    if env.key_type != expected_kt {
        return Err(serde::de::Error::custom("QSKE key_type mismatch"));
    }
    let level = algo_to_level(env.algorithm).map_err(serde::de::Error::custom)?;
    Ok((level, env.payload))
}

impl Serialize for KemPublicKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let env = QskeEnvelope {
            algorithm: level_to_algo(self.level),
            key_type: KeyType::Public,
            payload: self.to_bytes(),
        };
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(env.encode()))
    }
}

impl<'de> Deserialize<'de> for KemPublicKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let (level, payload) = decode_kem_envelope(d, KeyType::Public)?;
        KemPublicKey::from_bytes(level, &payload).map_err(serde::de::Error::custom)
    }
}

impl Serialize for KemSecretKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let env = QskeEnvelope {
            algorithm: level_to_algo(self.level),
            key_type: KeyType::Secret,
            payload: self.to_bytes(),
        };
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(env.encode()))
    }
}

impl<'de> Deserialize<'de> for KemSecretKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let (level, payload) = decode_kem_envelope(d, KeyType::Secret)?;
        let inner = match level {
            KemLevel::Kem512 =>
            {
                #[allow(deprecated)]
                DkInner::Kem512(
                    ml_kem::kem::DecapsulationKey::<ml_kem::MlKem512Params>::from_bytes(
                        ml_kem::array::Array::from_slice(&payload),
                    ),
                )
            }
            KemLevel::Kem768 =>
            {
                #[allow(deprecated)]
                DkInner::Kem768(
                    ml_kem::kem::DecapsulationKey::<ml_kem::MlKem768Params>::from_bytes(
                        ml_kem::array::Array::from_slice(&payload),
                    ),
                )
            }
            KemLevel::Kem1024 =>
            {
                #[allow(deprecated)]
                DkInner::Kem1024(
                    ml_kem::kem::DecapsulationKey::<ml_kem::MlKem1024Params>::from_bytes(
                        ml_kem::array::Array::from_slice(&payload),
                    ),
                )
            }
        };
        Ok(KemSecretKey {
            inner: Some(inner),
            level,
        })
    }
}

impl Serialize for KemCiphertext {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let env = QskeEnvelope {
            algorithm: level_to_algo(self.level),
            key_type: KeyType::Ciphertext,
            payload: self.bytes.clone(),
        };
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(env.encode()))
    }
}

impl<'de> Deserialize<'de> for KemCiphertext {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let (level, payload) = decode_kem_envelope(d, KeyType::Ciphertext)?;
        KemCiphertext::from_bytes(level, &payload).map_err(serde::de::Error::custom)
    }
}

// -- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(level: KemLevel) {
        let kp = kem_keygen(level).expect("keygen");
        let (ss_send, ct) = kem_encapsulate(&kp.public_key).expect("encapsulate");
        let ss_recv = kem_decapsulate(&kp.secret_key, &ct).expect("decapsulate");
        assert_eq!(
            ss_send.as_bytes(),
            ss_recv.as_bytes(),
            "shared secrets must match"
        );
    }

    #[test]
    fn round_trip_kem512() {
        round_trip(KemLevel::Kem512);
    }

    #[test]
    fn round_trip_kem768() {
        round_trip(KemLevel::Kem768);
    }

    #[test]
    fn round_trip_kem1024() {
        round_trip(KemLevel::Kem1024);
    }

    #[test]
    fn wrong_level_fails() {
        let kp512 = kem_keygen(KemLevel::Kem512).unwrap();
        let kp768 = kem_keygen(KemLevel::Kem768).unwrap();
        let (_, ct) = kem_encapsulate(&kp768.public_key).unwrap();
        assert!(kem_decapsulate(&kp512.secret_key, &ct).is_err());
    }

    #[test]
    fn ciphertext_serialization_round_trip() {
        let kp = kem_keygen(KemLevel::Kem768).unwrap();
        let (ss_orig, ct) = kem_encapsulate(&kp.public_key).unwrap();
        let bytes = ct.to_bytes();
        assert_eq!(bytes.len(), 1088, "ML-KEM-768 ciphertext is 1088 bytes");
        let ct2 = KemCiphertext::from_bytes(KemLevel::Kem768, bytes).unwrap();
        let ss2 = kem_decapsulate(&kp.secret_key, &ct2).unwrap();
        assert_eq!(ss_orig.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn public_key_serialization_round_trip() {
        let kp = kem_keygen(KemLevel::Kem768).unwrap();
        let pk_bytes = kp.public_key.to_bytes();
        assert_eq!(pk_bytes.len(), 1184, "ML-KEM-768 public key is 1184 bytes");
        let pk2 = KemPublicKey::from_bytes(KemLevel::Kem768, &pk_bytes).unwrap();
        let (ss1, ct) = kem_encapsulate(&pk2).unwrap();
        let ss2 = kem_decapsulate(&kp.secret_key, &ct).unwrap();
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }
}
