// QShield Node.js bindings (QS-110) -- NAPI-RS 3
//
// Exposes qshield-core's KEM, DSA, hybrid KEM, AEAD, and KDF functionality
// to Node.js/TypeScript as a native addon (`@qshield/core`).
//
// Design:
//   - All byte I/O uses `Buffer` (Node.js Buffer, compatible with Uint8Array).
//   - Key classes store raw bytes internally for thread safety across async tasks.
//   - CPU-intensive operations (keygen, sign, encapsulate) run on the libuv
//     thread pool via NAPI-RS `AsyncTask`, never blocking the event loop.
//   - TypeScript types are generated automatically by NAPI-RS.

#![deny(clippy::all)]
#![allow(clippy::module_name_repetitions)]
// NAPI-RS async Task structs are internal impl details; their types appear in
// public function signatures but are opaque to JS callers.
#![allow(private_interfaces)]

use napi::bindgen_prelude::*;
use napi_derive::napi;
use rand::RngCore;
use x25519_dalek::PublicKey as X25519Public;

use qshield_core::{
    DsaLevel as CoreDsaLevel, DsaSignature as CoreDsaSignature,
    DsaVerifyingKey as CoreDsaVerifyingKey, HybridCiphertext as CoreHybridCiphertext,
    HybridKeyPair as CoreHybridKeyPair, HybridMode as CoreHybridMode,
    HybridPublicKey as CoreHybridPublicKey, HybridSecretKey as CoreHybridSecretKey,
    KemCiphertext as CoreKemCiphertext, KemKeyPair as CoreKemKeyPair, KemLevel as CoreKemLevel,
    KemPublicKey as CoreKemPublicKey, KemSecretKey as CoreKemSecretKey, NONCE_LEN,
    aes256gcm_decrypt as core_aes256gcm_decrypt, aes256gcm_encrypt as core_aes256gcm_encrypt,
    chacha20poly1305_decrypt as core_chacha20poly1305_decrypt,
    chacha20poly1305_encrypt as core_chacha20poly1305_encrypt, dsa_keygen as core_dsa_keygen,
    dsa_sign_bytes as core_dsa_sign_bytes, dsa_verify as core_dsa_verify,
    hkdf_sha3_256 as core_hkdf_sha3_256, hybrid_decapsulate as core_hybrid_decapsulate,
    hybrid_encapsulate as core_hybrid_encapsulate, hybrid_keygen as core_hybrid_keygen,
    kem_decapsulate as core_kem_decapsulate, kem_encapsulate as core_kem_encapsulate,
    kem_keygen as core_kem_keygen,
};

// -- Error helper ----------------------------------------------------------

fn into_err(e: impl std::fmt::Display) -> napi::Error {
    napi::Error::from_reason(e.to_string())
}

// -- Enums -----------------------------------------------------------------

/// ML-KEM security level.
#[napi]
pub enum KemLevel {
    /// NIST level 1 (~AES-128). Not recommended for new deployments.
    L512,
    /// NIST level 3. QShield default. Matches Chrome/Cloudflare deployment.
    L768,
    /// NIST level 5. High-security environments.
    L1024,
}

/// ML-DSA security level.
#[napi]
pub enum DsaLevel {
    /// NIST level 2 (ML-DSA-44). General use.
    L2,
    /// NIST level 3 (ML-DSA-65). QShield default.
    L3,
    /// NIST level 5 (ML-DSA-87). High-security environments.
    L5,
}

/// Hybrid X25519 + ML-KEM mode.
#[napi]
pub enum HybridMode {
    /// X25519 + ML-KEM-768. Default -- matches Chrome/Cloudflare.
    X25519Kyber768,
    /// X25519 + ML-KEM-1024. High-security environments.
    X25519Kyber1024,
}

fn to_core_kem(level: KemLevel) -> CoreKemLevel {
    match level {
        KemLevel::L512 => CoreKemLevel::Kem512,
        KemLevel::L768 => CoreKemLevel::Kem768,
        KemLevel::L1024 => CoreKemLevel::Kem1024,
    }
}

fn to_core_dsa(level: DsaLevel) -> CoreDsaLevel {
    match level {
        DsaLevel::L2 => CoreDsaLevel::Dsa44,
        DsaLevel::L3 => CoreDsaLevel::Dsa65,
        DsaLevel::L5 => CoreDsaLevel::Dsa87,
    }
}

fn to_core_hybrid(mode: HybridMode) -> CoreHybridMode {
    match mode {
        HybridMode::X25519Kyber768 => CoreHybridMode::X25519Kyber768,
        HybridMode::X25519Kyber1024 => CoreHybridMode::X25519Kyber1024,
    }
}

// -- KEM classes -----------------------------------------------------------

/// ML-KEM encapsulation (public) key.
#[napi]
pub struct KemPublicKey {
    pub(crate) bytes: Vec<u8>,
    pub(crate) level: CoreKemLevel,
}

#[napi]
impl KemPublicKey {
    /// Return raw bytes of this public key.
    #[napi]
    pub fn to_bytes(&self) -> Buffer {
        Buffer::from(self.bytes.clone())
    }
}

/// ML-KEM decapsulation (secret) key.
#[napi]
pub struct KemSecretKey {
    pub(crate) bytes: Vec<u8>,
    pub(crate) level: CoreKemLevel,
}

#[napi]
impl KemSecretKey {
    /// Return raw bytes of this secret key. Handle with care.
    #[napi]
    pub fn to_bytes(&self) -> Buffer {
        Buffer::from(self.bytes.clone())
    }
}

/// A generated ML-KEM key pair.
#[napi]
pub struct KemKeypair {
    pub(crate) pk_bytes: Vec<u8>,
    pub(crate) sk_bytes: Vec<u8>,
    pub(crate) level: CoreKemLevel,
}

#[napi]
impl KemKeypair {
    /// The ML-KEM public (encapsulation) key.
    #[napi(getter, js_name = "publicKey")]
    pub fn public_key(&self) -> KemPublicKey {
        KemPublicKey {
            bytes: self.pk_bytes.clone(),
            level: self.level,
        }
    }

    /// The ML-KEM secret (decapsulation) key.
    #[napi(getter, js_name = "secretKey")]
    pub fn secret_key(&self) -> KemSecretKey {
        KemSecretKey {
            bytes: self.sk_bytes.clone(),
            level: self.level,
        }
    }
}

/// Result of a KEM encapsulation: shared secret + ciphertext.
#[napi(object)]
pub struct KemEncapsulateResult {
    pub shared_secret: Buffer,
    pub ciphertext: Buffer,
}

// -- KEM async tasks -------------------------------------------------------

struct KemKeygenTask {
    level: CoreKemLevel,
}

impl Task for KemKeygenTask {
    type Output = (Vec<u8>, Vec<u8>);
    type JsValue = KemKeypair;

    fn compute(&mut self) -> napi::Result<(Vec<u8>, Vec<u8>)> {
        let kp = core_kem_keygen(self.level).map_err(into_err)?;
        let CoreKemKeyPair {
            public_key,
            secret_key,
        } = kp;
        Ok((public_key.to_bytes(), secret_key.to_bytes()))
    }

    fn resolve(&mut self, _env: Env, (pk, sk): (Vec<u8>, Vec<u8>)) -> napi::Result<KemKeypair> {
        Ok(KemKeypair {
            pk_bytes: pk,
            sk_bytes: sk,
            level: self.level,
        })
    }
}

/// Generate an ML-KEM key pair asynchronously.
///
/// Defaults to `KemLevel.L768` (ML-KEM-768, NIST level 3).
#[napi(js_name = "kemKeygen")]
pub fn kem_keygen(level: Option<KemLevel>) -> AsyncTask<KemKeygenTask> {
    let lvl = level.map(to_core_kem).unwrap_or(CoreKemLevel::Kem768);
    AsyncTask::new(KemKeygenTask { level: lvl })
}

struct KemEncapsulateTask {
    pk_bytes: Vec<u8>,
    level: CoreKemLevel,
}

impl Task for KemEncapsulateTask {
    type Output = (Vec<u8>, Vec<u8>);
    type JsValue = KemEncapsulateResult;

    fn compute(&mut self) -> napi::Result<(Vec<u8>, Vec<u8>)> {
        let pk = CoreKemPublicKey::from_bytes(self.level, &self.pk_bytes).map_err(into_err)?;
        let (ss, ct) = core_kem_encapsulate(&pk).map_err(into_err)?;
        Ok((ss.as_bytes().to_vec(), ct.to_bytes().to_vec()))
    }

    fn resolve(
        &mut self,
        _env: Env,
        (ss, ct): (Vec<u8>, Vec<u8>),
    ) -> napi::Result<KemEncapsulateResult> {
        Ok(KemEncapsulateResult {
            shared_secret: Buffer::from(ss),
            ciphertext: Buffer::from(ct),
        })
    }
}

/// Encapsulate a shared secret using an ML-KEM public key.
#[napi(js_name = "kemEncapsulate")]
pub fn kem_encapsulate(public_key: &KemPublicKey) -> AsyncTask<KemEncapsulateTask> {
    AsyncTask::new(KemEncapsulateTask {
        pk_bytes: public_key.bytes.clone(),
        level: public_key.level,
    })
}

struct KemDecapsulateTask {
    sk_bytes: Vec<u8>,
    ct_bytes: Vec<u8>,
    level: CoreKemLevel,
}

impl Task for KemDecapsulateTask {
    type Output = Vec<u8>;
    type JsValue = Buffer;

    fn compute(&mut self) -> napi::Result<Vec<u8>> {
        let sk = CoreKemSecretKey::from_bytes(self.level, &self.sk_bytes).map_err(into_err)?;
        let ct = CoreKemCiphertext::from_bytes(self.level, &self.ct_bytes).map_err(into_err)?;
        let ss = core_kem_decapsulate(&sk, &ct).map_err(into_err)?;
        Ok(ss.as_bytes().to_vec())
    }

    fn resolve(&mut self, _env: Env, bytes: Vec<u8>) -> napi::Result<Buffer> {
        Ok(Buffer::from(bytes))
    }
}

/// Recover the shared secret from a KEM ciphertext using the secret key.
#[napi(js_name = "kemDecapsulate")]
pub fn kem_decapsulate(
    secret_key: &KemSecretKey,
    ciphertext: Buffer,
) -> AsyncTask<KemDecapsulateTask> {
    AsyncTask::new(KemDecapsulateTask {
        sk_bytes: secret_key.bytes.clone(),
        ct_bytes: ciphertext.to_vec(),
        level: secret_key.level,
    })
}

// -- DSA classes -----------------------------------------------------------

/// ML-DSA verifying (public) key.
#[napi]
pub struct DsaVerifyingKey {
    pub(crate) bytes: Vec<u8>,
    pub(crate) level: CoreDsaLevel,
}

#[napi]
impl DsaVerifyingKey {
    /// Return raw bytes of this verifying key.
    #[napi]
    pub fn to_bytes(&self) -> Buffer {
        Buffer::from(self.bytes.clone())
    }
}

/// An ML-DSA key pair (signing + verifying).
#[napi]
pub struct DsaKeypair {
    pub(crate) sk_bytes: Vec<u8>,
    pub(crate) vk_bytes: Vec<u8>,
    pub(crate) level: CoreDsaLevel,
}

#[napi]
impl DsaKeypair {
    /// The ML-DSA verifying (public) key.
    #[napi(getter, js_name = "verifyingKey")]
    pub fn verifying_key(&self) -> DsaVerifyingKey {
        DsaVerifyingKey {
            bytes: self.vk_bytes.clone(),
            level: self.level,
        }
    }
}

// -- DSA async tasks -------------------------------------------------------

struct DsaKeygenTask {
    level: CoreDsaLevel,
}

impl Task for DsaKeygenTask {
    type Output = (Vec<u8>, Vec<u8>);
    type JsValue = DsaKeypair;

    fn compute(&mut self) -> napi::Result<(Vec<u8>, Vec<u8>)> {
        let kp = core_dsa_keygen(self.level).map_err(into_err)?;
        let vk_bytes = kp.verifying_key().as_bytes().to_vec();
        let sk_bytes = kp.signing_key_bytes();
        Ok((sk_bytes, vk_bytes))
    }

    fn resolve(&mut self, _env: Env, (sk, vk): (Vec<u8>, Vec<u8>)) -> napi::Result<DsaKeypair> {
        Ok(DsaKeypair {
            sk_bytes: sk,
            vk_bytes: vk,
            level: self.level,
        })
    }
}

/// Generate an ML-DSA key pair asynchronously.
///
/// Defaults to `DsaLevel.L3` (ML-DSA-65, NIST level 3).
#[napi(js_name = "dsaKeygen")]
pub fn dsa_keygen(level: Option<DsaLevel>) -> AsyncTask<DsaKeygenTask> {
    let lvl = level.map(to_core_dsa).unwrap_or(CoreDsaLevel::Dsa65);
    AsyncTask::new(DsaKeygenTask { level: lvl })
}

struct DsaSignTask {
    sk_bytes: Vec<u8>,
    level: CoreDsaLevel,
    message: Vec<u8>,
}

impl Task for DsaSignTask {
    type Output = Vec<u8>;
    type JsValue = Buffer;

    fn compute(&mut self) -> napi::Result<Vec<u8>> {
        let sig =
            core_dsa_sign_bytes(self.level, &self.sk_bytes, &self.message).map_err(into_err)?;
        Ok(sig.as_bytes().to_vec())
    }

    fn resolve(&mut self, _env: Env, bytes: Vec<u8>) -> napi::Result<Buffer> {
        Ok(Buffer::from(bytes))
    }
}

/// Sign a message using an ML-DSA key pair. Returns the signature bytes.
#[napi(js_name = "dsaSign")]
pub fn dsa_sign(keypair: &DsaKeypair, message: Buffer) -> AsyncTask<DsaSignTask> {
    AsyncTask::new(DsaSignTask {
        sk_bytes: keypair.sk_bytes.clone(),
        level: keypair.level,
        message: message.to_vec(),
    })
}

struct DsaVerifyTask {
    vk_bytes: Vec<u8>,
    level: CoreDsaLevel,
    message: Vec<u8>,
    signature: Vec<u8>,
}

impl Task for DsaVerifyTask {
    type Output = bool;
    type JsValue = bool;

    fn compute(&mut self) -> napi::Result<bool> {
        let vk = CoreDsaVerifyingKey::from_raw(self.vk_bytes.clone(), self.level);
        let sig = CoreDsaSignature::from_raw(self.signature.clone(), self.level);
        core_dsa_verify(&vk, &self.message, &sig).map_err(into_err)
    }

    fn resolve(&mut self, _env: Env, valid: bool) -> napi::Result<bool> {
        Ok(valid)
    }
}

/// Verify an ML-DSA signature. Returns `true` if valid, `false` otherwise.
#[napi(js_name = "dsaVerify")]
pub fn dsa_verify(
    verifying_key: &DsaVerifyingKey,
    message: Buffer,
    signature: Buffer,
) -> AsyncTask<DsaVerifyTask> {
    AsyncTask::new(DsaVerifyTask {
        vk_bytes: verifying_key.bytes.clone(),
        level: verifying_key.level,
        message: message.to_vec(),
        signature: signature.to_vec(),
    })
}

// -- Hybrid KEM classes ----------------------------------------------------

/// Hybrid X25519 + ML-KEM public key (given to encapsulators).
#[napi]
pub struct HybridPublicKey {
    pub(crate) classical_bytes: Vec<u8>,
    pub(crate) pqc_bytes: Vec<u8>,
    pub(crate) mode: CoreHybridMode,
}

#[napi]
impl HybridPublicKey {
    /// Return raw bytes: `[32 B X25519 key][ML-KEM public key bytes]`.
    #[napi]
    pub fn to_bytes(&self) -> Buffer {
        let mut out = Vec::with_capacity(32 + self.pqc_bytes.len());
        out.extend_from_slice(&self.classical_bytes);
        out.extend_from_slice(&self.pqc_bytes);
        Buffer::from(out)
    }

    /// The hybrid mode label ("X25519Kyber768" or "X25519Kyber1024").
    #[napi(getter)]
    pub fn mode(&self) -> &str {
        self.mode.label()
    }
}

/// Hybrid X25519 + ML-KEM secret key (kept by the receiver).
#[napi]
pub struct HybridSecretKey {
    pub(crate) sk_bytes: Vec<u8>,
    pub(crate) mode: CoreHybridMode,
}

#[napi]
impl HybridSecretKey {
    /// The hybrid mode label.
    #[napi(getter)]
    pub fn mode(&self) -> &str {
        self.mode.label()
    }
}

/// A generated hybrid X25519 + ML-KEM key pair.
#[napi]
pub struct HybridKeypair {
    pk_classical: Vec<u8>,
    pk_pqc: Vec<u8>,
    sk_bytes: Vec<u8>,
    mode: CoreHybridMode,
}

#[napi]
impl HybridKeypair {
    /// The hybrid public key.
    #[napi(getter, js_name = "publicKey")]
    pub fn public_key(&self) -> HybridPublicKey {
        HybridPublicKey {
            classical_bytes: self.pk_classical.clone(),
            pqc_bytes: self.pk_pqc.clone(),
            mode: self.mode,
        }
    }

    /// The hybrid secret key.
    #[napi(getter, js_name = "secretKey")]
    pub fn secret_key(&self) -> HybridSecretKey {
        HybridSecretKey {
            sk_bytes: self.sk_bytes.clone(),
            mode: self.mode,
        }
    }
}

/// Result of a hybrid encapsulation: shared secret + ciphertext.
#[napi(object)]
pub struct HybridEncapsulateResult {
    pub shared_secret: Buffer,
    pub ciphertext: Buffer,
}

// -- Hybrid KEM async tasks ------------------------------------------------

struct HybridKeygenTask {
    mode: CoreHybridMode,
}

impl Task for HybridKeygenTask {
    type Output = (Vec<u8>, Vec<u8>, Vec<u8>);
    type JsValue = HybridKeypair;

    fn compute(&mut self) -> napi::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let kp = core_hybrid_keygen(self.mode).map_err(into_err)?;
        let CoreHybridKeyPair {
            public_key,
            secret_key,
        } = kp;
        let pk_classical = public_key.classical.as_bytes().to_vec();
        let pk_pqc = public_key.pqc.to_bytes();
        let sk_bytes = secret_key.to_bytes();
        Ok((pk_classical, pk_pqc, sk_bytes))
    }

    fn resolve(
        &mut self,
        _env: Env,
        (pk_classical, pk_pqc, sk_bytes): (Vec<u8>, Vec<u8>, Vec<u8>),
    ) -> napi::Result<HybridKeypair> {
        Ok(HybridKeypair {
            pk_classical,
            pk_pqc,
            sk_bytes,
            mode: self.mode,
        })
    }
}

/// Generate a hybrid X25519 + ML-KEM key pair asynchronously.
///
/// Defaults to `HybridMode.X25519Kyber768`.
#[napi(js_name = "hybridKeygen")]
pub fn hybrid_keygen(mode: Option<HybridMode>) -> AsyncTask<HybridKeygenTask> {
    let m = mode
        .map(to_core_hybrid)
        .unwrap_or(CoreHybridMode::X25519Kyber768);
    AsyncTask::new(HybridKeygenTask { mode: m })
}

struct HybridEncapsulateTask {
    pk_classical: Vec<u8>,
    pk_pqc: Vec<u8>,
    mode: CoreHybridMode,
}

impl Task for HybridEncapsulateTask {
    type Output = (Vec<u8>, Vec<u8>);
    type JsValue = HybridEncapsulateResult;

    fn compute(&mut self) -> napi::Result<(Vec<u8>, Vec<u8>)> {
        let arr: [u8; 32] = self.pk_classical[..32]
            .try_into()
            .map_err(|_| napi::Error::from_reason("invalid classical key bytes"))?;
        let classical = X25519Public::from(arr);
        let pqc =
            CoreKemPublicKey::from_bytes(self.mode.kem_level(), &self.pk_pqc).map_err(into_err)?;
        let core_pk = CoreHybridPublicKey {
            classical,
            pqc,
            mode: self.mode,
        };
        let (ss, ct) = core_hybrid_encapsulate(&core_pk).map_err(into_err)?;
        Ok((ss.as_bytes().to_vec(), ct.to_bytes()))
    }

    fn resolve(
        &mut self,
        _env: Env,
        (ss, ct): (Vec<u8>, Vec<u8>),
    ) -> napi::Result<HybridEncapsulateResult> {
        Ok(HybridEncapsulateResult {
            shared_secret: Buffer::from(ss),
            ciphertext: Buffer::from(ct),
        })
    }
}

/// Encapsulate a shared secret using a hybrid public key.
#[napi(js_name = "hybridEncapsulate")]
pub fn hybrid_encapsulate(public_key: &HybridPublicKey) -> AsyncTask<HybridEncapsulateTask> {
    AsyncTask::new(HybridEncapsulateTask {
        pk_classical: public_key.classical_bytes.clone(),
        pk_pqc: public_key.pqc_bytes.clone(),
        mode: public_key.mode,
    })
}

struct HybridDecapsulateTask {
    sk_bytes: Vec<u8>,
    ct_bytes: Vec<u8>,
    mode: CoreHybridMode,
}

impl Task for HybridDecapsulateTask {
    type Output = Vec<u8>;
    type JsValue = Buffer;

    fn compute(&mut self) -> napi::Result<Vec<u8>> {
        let sk = CoreHybridSecretKey::from_bytes(self.mode, &self.sk_bytes).map_err(into_err)?;
        let ct = CoreHybridCiphertext::from_bytes(self.mode, &self.ct_bytes).map_err(into_err)?;
        let result = core_hybrid_decapsulate(&sk, &ct).map_err(into_err)?;
        Ok(result.shared_secret.as_bytes().to_vec())
    }

    fn resolve(&mut self, _env: Env, bytes: Vec<u8>) -> napi::Result<Buffer> {
        Ok(Buffer::from(bytes))
    }
}

/// Recover the shared secret from a hybrid ciphertext using the secret key.
#[napi(js_name = "hybridDecapsulate")]
pub fn hybrid_decapsulate(
    secret_key: &HybridSecretKey,
    ciphertext: Buffer,
) -> AsyncTask<HybridDecapsulateTask> {
    AsyncTask::new(HybridDecapsulateTask {
        sk_bytes: secret_key.sk_bytes.clone(),
        ct_bytes: ciphertext.to_vec(),
        mode: secret_key.mode,
    })
}

// -- AEAD functions --------------------------------------------------------

// -- AEAD byte-array helpers --------------------------------------------------

fn to_key32(buf: &Buffer) -> napi::Result<[u8; 32]> {
    buf.as_ref()
        .try_into()
        .map_err(|_| napi::Error::from_reason("key must be exactly 32 bytes"))
}

fn to_nonce12(buf: &Buffer) -> napi::Result<[u8; 12]> {
    buf.as_ref()
        .try_into()
        .map_err(|_| napi::Error::from_reason("nonce must be exactly 12 bytes"))
}

/// Encrypt data with AES-256-GCM.
///
/// - `key`: 32-byte key.
/// - `nonce`: 12-byte nonce (use `generateNonce()` for random nonces).
/// - `plaintext`: data to encrypt.
/// - `aad`: optional additional authenticated data.
///
/// Returns ciphertext + 16-byte authentication tag.
#[napi(js_name = "aes256gcmEncrypt")]
pub fn aes256gcm_encrypt(
    key: Buffer,
    nonce: Buffer,
    plaintext: Buffer,
    aad: Option<Buffer>,
) -> napi::Result<Buffer> {
    let key_arr = to_key32(&key)?;
    let nonce_arr = to_nonce12(&nonce)?;
    let aad_bytes = aad.as_deref().unwrap_or(&[]);
    let ct =
        core_aes256gcm_encrypt(&key_arr, &nonce_arr, &plaintext, aad_bytes).map_err(into_err)?;
    Ok(Buffer::from(ct))
}

/// Decrypt data with AES-256-GCM.
///
/// Returns plaintext, or throws if authentication fails.
#[napi(js_name = "aes256gcmDecrypt")]
pub fn aes256gcm_decrypt(
    key: Buffer,
    nonce: Buffer,
    ciphertext: Buffer,
    aad: Option<Buffer>,
) -> napi::Result<Buffer> {
    let key_arr = to_key32(&key)?;
    let nonce_arr = to_nonce12(&nonce)?;
    let aad_bytes = aad.as_deref().unwrap_or(&[]);
    let pt =
        core_aes256gcm_decrypt(&key_arr, &nonce_arr, &ciphertext, aad_bytes).map_err(into_err)?;
    Ok(Buffer::from(pt))
}

/// Encrypt data with ChaCha20-Poly1305.
#[napi(js_name = "chacha20poly1305Encrypt")]
pub fn chacha20poly1305_encrypt(
    key: Buffer,
    nonce: Buffer,
    plaintext: Buffer,
    aad: Option<Buffer>,
) -> napi::Result<Buffer> {
    let key_arr = to_key32(&key)?;
    let nonce_arr = to_nonce12(&nonce)?;
    let aad_bytes = aad.as_deref().unwrap_or(&[]);
    let ct = core_chacha20poly1305_encrypt(&key_arr, &nonce_arr, &plaintext, aad_bytes)
        .map_err(into_err)?;
    Ok(Buffer::from(ct))
}

/// Decrypt data with ChaCha20-Poly1305.
#[napi(js_name = "chacha20poly1305Decrypt")]
pub fn chacha20poly1305_decrypt(
    key: Buffer,
    nonce: Buffer,
    ciphertext: Buffer,
    aad: Option<Buffer>,
) -> napi::Result<Buffer> {
    let key_arr = to_key32(&key)?;
    let nonce_arr = to_nonce12(&nonce)?;
    let aad_bytes = aad.as_deref().unwrap_or(&[]);
    let pt = core_chacha20poly1305_decrypt(&key_arr, &nonce_arr, &ciphertext, aad_bytes)
        .map_err(into_err)?;
    Ok(Buffer::from(pt))
}

// -- KDF function ---------------------------------------------------------

/// Derive key material with HKDF-SHA3-256.
///
/// - `ikm`: input key material.
/// - `salt`: optional salt (recommended; use random 32 bytes).
/// - `info`: optional context info.
/// - `length`: output length in bytes (default 32).
#[napi(js_name = "hkdfSha3256")]
pub fn hkdf_sha3_256(
    ikm: Buffer,
    salt: Option<Buffer>,
    info: Option<Buffer>,
    length: Option<u32>,
) -> napi::Result<Buffer> {
    let salt_opt = salt.as_deref();
    let info_bytes = info.as_deref().unwrap_or(&[]);
    let len = length.unwrap_or(32) as usize;
    let okm = core_hkdf_sha3_256(&ikm, salt_opt, info_bytes, len).map_err(into_err)?;
    Ok(Buffer::from(okm.as_slice()))
}

// -- Utility ---------------------------------------------------------------

/// Return `n` cryptographically random bytes from the OS CSPRNG.
#[napi(js_name = "randomBytes")]
pub fn random_bytes(n: u32) -> Buffer {
    let mut buf = vec![0u8; n as usize];
    rand::rng().fill_bytes(&mut buf);
    Buffer::from(buf)
}

/// Return a random 12-byte nonce suitable for AES-256-GCM or ChaCha20-Poly1305.
#[napi(js_name = "generateNonce")]
pub fn generate_nonce() -> Buffer {
    let mut buf = vec![0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut buf);
    Buffer::from(buf)
}
