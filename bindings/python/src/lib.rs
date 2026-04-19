// QShield Python bindings (QS-109) — PyO3 + maturin
//
// Exposes qshield-core's KEM, DSA, hybrid KEM, AEAD, and KDF functionality
// to Python as a native extension module named `qshield`.
//
// Error handling: every Rust `QShieldError` variant maps to a Python
// `QShieldError` exception subclass (see `exceptions` module below).

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use qshield_common::QShieldError;
use qshield_core::{
    DsaLevel, HybridMode, KemLevel, NONCE_LEN, aes256gcm_decrypt as core_aes256gcm_decrypt,
    aes256gcm_encrypt as core_aes256gcm_encrypt,
    chacha20poly1305_decrypt as core_chacha20poly1305_decrypt,
    chacha20poly1305_encrypt as core_chacha20poly1305_encrypt, dsa_keygen as core_dsa_keygen,
    dsa_sign as core_dsa_sign, dsa_verify as core_dsa_verify, hkdf_sha3_256 as core_hkdf_sha3_256,
    hybrid_decapsulate as core_hybrid_decapsulate, hybrid_encapsulate as core_hybrid_encapsulate,
    hybrid_keygen as core_hybrid_keygen, kem_decapsulate as core_kem_decapsulate,
    kem_encapsulate as core_kem_encapsulate, kem_keygen as core_kem_keygen,
};
use rand::RngCore;

// ── Python exception hierarchy ─────────────────────────────────────────────

create_exception!(
    qshield,
    PyQShieldError,
    PyException,
    "Base exception for all QShield errors."
);
create_exception!(
    qshield,
    PyDecapsulationError,
    PyQShieldError,
    "Decapsulation or AEAD authentication failed."
);
create_exception!(
    qshield,
    PyInvalidKeyLengthError,
    PyQShieldError,
    "Key or ciphertext has wrong byte length."
);
create_exception!(
    qshield,
    PySignatureError,
    PyQShieldError,
    "Signature creation or verification failed."
);
create_exception!(
    qshield,
    PyKeyDerivationError,
    PyQShieldError,
    "HKDF key derivation failed."
);
create_exception!(
    qshield,
    PyUnsupportedAlgorithmError,
    PyQShieldError,
    "Algorithm code or level is not supported."
);

// Convert a Rust QShieldError into the most appropriate Python exception.
fn to_py_err(e: QShieldError) -> PyErr {
    match &e {
        QShieldError::DecryptionFailed | QShieldError::Decapsulation { .. } => {
            PyDecapsulationError::new_err(e.to_string())
        }
        QShieldError::InvalidKeyLength { .. } | QShieldError::InvalidNonce { .. } => {
            PyInvalidKeyLengthError::new_err(e.to_string())
        }
        QShieldError::SignatureCreation { .. } | QShieldError::SignatureVerification { .. } => {
            PySignatureError::new_err(e.to_string())
        }
        QShieldError::KeyDerivation { .. } => PyKeyDerivationError::new_err(e.to_string()),
        QShieldError::UnsupportedAlgorithm { .. } => {
            PyUnsupportedAlgorithmError::new_err(e.to_string())
        }
        _ => PyQShieldError::new_err(e.to_string()),
    }
}

// ── Parsing helpers ────────────────────────────────────────────────────────

fn parse_kem_level(level: &str) -> PyResult<KemLevel> {
    match level {
        "512" => Ok(KemLevel::Kem512),
        "768" => Ok(KemLevel::Kem768),
        "1024" => Ok(KemLevel::Kem1024),
        other => Err(PyUnsupportedAlgorithmError::new_err(format!(
            "unknown KEM level {other:?}; expected \"512\", \"768\", or \"1024\""
        ))),
    }
}

fn parse_dsa_level(level: &str) -> PyResult<DsaLevel> {
    match level {
        "44" => Ok(DsaLevel::Dsa44),
        "65" => Ok(DsaLevel::Dsa65),
        "87" => Ok(DsaLevel::Dsa87),
        other => Err(PyUnsupportedAlgorithmError::new_err(format!(
            "unknown DSA level {other:?}; expected \"44\", \"65\", or \"87\""
        ))),
    }
}

fn parse_hybrid_mode(mode: &str) -> PyResult<HybridMode> {
    match mode {
        "X25519Kyber768" => Ok(HybridMode::X25519Kyber768),
        "X25519Kyber1024" => Ok(HybridMode::X25519Kyber1024),
        other => Err(PyUnsupportedAlgorithmError::new_err(format!(
            "unknown hybrid mode {other:?}; expected \"X25519Kyber768\" or \"X25519Kyber1024\""
        ))),
    }
}

fn kem_level_str(level: KemLevel) -> &'static str {
    match level {
        KemLevel::Kem512 => "512",
        KemLevel::Kem768 => "768",
        KemLevel::Kem1024 => "1024",
    }
}

fn dsa_level_str(level: DsaLevel) -> &'static str {
    match level {
        DsaLevel::Dsa44 => "44",
        DsaLevel::Dsa65 => "65",
        DsaLevel::Dsa87 => "87",
    }
}

// ── KEM Python classes ─────────────────────────────────────────────────────

/// ML-KEM encapsulation (public) key.
#[pyclass(name = "KemPublicKey", module = "qshield")]
struct PyKemPublicKey {
    inner: qshield_core::KemPublicKey,
}

#[pymethods]
impl PyKemPublicKey {
    /// Returns the raw bytes of this public key.
    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.to_bytes())
    }

    /// Security level: "512", "768", or "1024".
    #[getter]
    fn level(&self) -> &'static str {
        kem_level_str(self.inner.level())
    }

    fn __repr__(&self) -> String {
        format!(
            "KemPublicKey(level=\"{}\")",
            kem_level_str(self.inner.level())
        )
    }
}

/// ML-KEM decapsulation (secret) key. Bytes are zeroized when this object
/// is garbage collected.
#[pyclass(name = "KemSecretKey", module = "qshield")]
struct PyKemSecretKey {
    inner: qshield_core::KemSecretKey,
}

#[pymethods]
impl PyKemSecretKey {
    /// Returns the raw bytes of this secret key.
    /// **Handle with care** — store encrypted at rest.
    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.to_bytes())
    }

    /// Security level: "512", "768", or "1024".
    #[getter]
    fn level(&self) -> &'static str {
        kem_level_str(self.inner.level())
    }

    fn __repr__(&self) -> String {
        format!(
            "KemSecretKey(level=\"{}\")",
            kem_level_str(self.inner.level())
        )
    }
}

/// ML-KEM ciphertext (encapsulated shared secret).
#[pyclass(name = "KemCiphertext", module = "qshield")]
struct PyKemCiphertext {
    inner: qshield_core::KemCiphertext,
}

#[pymethods]
impl PyKemCiphertext {
    /// Returns the raw bytes of this ciphertext.
    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.to_bytes())
    }

    /// Security level: "512", "768", or "1024".
    #[getter]
    fn level(&self) -> &'static str {
        kem_level_str(self.inner.level())
    }

    fn __repr__(&self) -> String {
        format!(
            "KemCiphertext(level=\"{}\")",
            kem_level_str(self.inner.level())
        )
    }
}

/// ML-KEM key pair returned by `kem_keygen`.
#[pyclass(name = "KemKeypair", module = "qshield")]
struct PyKemKeypair {
    public_key: Py<PyKemPublicKey>,
    secret_key: Py<PyKemSecretKey>,
}

#[pymethods]
impl PyKemKeypair {
    #[getter]
    fn public_key(&self, py: Python<'_>) -> Py<PyKemPublicKey> {
        self.public_key.clone_ref(py)
    }

    #[getter]
    fn secret_key(&self, py: Python<'_>) -> Py<PyKemSecretKey> {
        self.secret_key.clone_ref(py)
    }

    fn __repr__(&self, py: Python<'_>) -> String {
        let level = self.public_key.borrow(py).level();
        format!("KemKeypair(level=\"{level}\")")
    }
}

// ── DSA Python classes ─────────────────────────────────────────────────────

/// ML-DSA verifying (public) key.
#[pyclass(name = "DsaVerifyingKey", module = "qshield")]
struct PyDsaVerifyingKey {
    inner: qshield_core::DsaVerifyingKey,
}

#[pymethods]
impl PyDsaVerifyingKey {
    /// Returns the raw bytes of this verifying key.
    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.as_bytes())
    }

    /// Security level: "44", "65", or "87".
    #[getter]
    fn level(&self) -> &'static str {
        dsa_level_str(self.inner.level())
    }

    fn __repr__(&self) -> String {
        format!(
            "DsaVerifyingKey(level=\"{}\")",
            dsa_level_str(self.inner.level())
        )
    }
}

/// ML-DSA signature.
#[pyclass(name = "DsaSignature", module = "qshield")]
struct PyDsaSignature {
    inner: qshield_core::DsaSignature,
}

#[pymethods]
impl PyDsaSignature {
    /// Returns the raw bytes of this signature.
    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.as_bytes())
    }

    /// Security level: "44", "65", or "87".
    #[getter]
    fn level(&self) -> &'static str {
        dsa_level_str(self.inner.level())
    }

    fn __repr__(&self) -> String {
        format!(
            "DsaSignature(level=\"{}\")",
            dsa_level_str(self.inner.level())
        )
    }
}

/// ML-DSA key pair. Signing key bytes are zeroized on drop.
#[pyclass(name = "DsaKeypair", module = "qshield")]
struct PyDsaKeypair {
    inner: qshield_core::DsaKeyPair,
}

#[pymethods]
impl PyDsaKeypair {
    /// Returns a copy of the verifying (public) key.
    #[getter]
    fn verifying_key(&self) -> PyDsaVerifyingKey {
        PyDsaVerifyingKey {
            inner: self.inner.verifying_key(),
        }
    }

    /// Security level: "44", "65", or "87".
    #[getter]
    fn level(&self) -> &'static str {
        dsa_level_str(self.inner.level())
    }

    fn __repr__(&self) -> String {
        format!(
            "DsaKeypair(level=\"{}\")",
            dsa_level_str(self.inner.level())
        )
    }
}

// ── Hybrid KEM Python classes ──────────────────────────────────────────────

/// Hybrid (X25519 + ML-KEM) public key. Stored as serialized bytes internally
/// to avoid PyO3 Send constraints on the underlying x25519 type.
#[pyclass(name = "HybridPublicKey", module = "qshield")]
struct PyHybridPublicKey {
    /// 32-byte X25519 public key.
    classical_bytes: [u8; 32],
    /// ML-KEM public key bytes.
    pqc_bytes: Vec<u8>,
    /// KEM level derived from mode.
    kem_level: KemLevel,
    /// Hybrid mode label.
    mode: HybridMode,
}

impl PyHybridPublicKey {
    fn from_core(pk: &qshield_core::HybridPublicKey) -> Self {
        Self {
            classical_bytes: *pk.classical.as_bytes(),
            pqc_bytes: pk.pqc.to_bytes(),
            kem_level: pk.pqc.level(),
            mode: pk.mode,
        }
    }

    fn to_core(&self) -> PyResult<qshield_core::HybridPublicKey> {
        use qshield_core::KemPublicKey;
        use x25519_dalek::PublicKey as X25519Public;
        let classical = X25519Public::from(self.classical_bytes);
        let pqc = KemPublicKey::from_bytes(self.kem_level, &self.pqc_bytes).map_err(to_py_err)?;
        Ok(qshield_core::HybridPublicKey {
            classical,
            pqc,
            mode: self.mode,
        })
    }
}

#[pymethods]
impl PyHybridPublicKey {
    /// Returns raw bytes: 32-byte X25519 key || ML-KEM public key bytes.
    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        let mut out = Vec::with_capacity(32 + self.pqc_bytes.len());
        out.extend_from_slice(&self.classical_bytes);
        out.extend_from_slice(&self.pqc_bytes);
        PyBytes::new(py, &out)
    }

    /// Hybrid mode: "X25519Kyber768" or "X25519Kyber1024".
    #[getter]
    fn mode(&self) -> &'static str {
        self.mode.label()
    }

    fn __repr__(&self) -> String {
        format!("HybridPublicKey(mode=\"{}\")", self.mode.label())
    }
}

/// Hybrid (X25519 + ML-KEM) secret key. All key material is zeroized on drop.
#[pyclass(name = "HybridSecretKey", module = "qshield")]
struct PyHybridSecretKey {
    inner: qshield_core::HybridSecretKey,
}

#[pymethods]
impl PyHybridSecretKey {
    /// Hybrid mode: "X25519Kyber768" or "X25519Kyber1024".
    #[getter]
    fn mode(&self) -> &'static str {
        self.inner.mode.label()
    }

    fn __repr__(&self) -> String {
        format!("HybridSecretKey(mode=\"{}\")", self.inner.mode.label())
    }
}

/// Hybrid ciphertext sent from encapsulator to receiver.
#[pyclass(name = "HybridCiphertext", module = "qshield")]
struct PyHybridCiphertext {
    inner: qshield_core::HybridCiphertext,
    mode: HybridMode,
}

#[pymethods]
impl PyHybridCiphertext {
    /// Returns raw bytes: 32-byte ephemeral X25519 key || ML-KEM ciphertext.
    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.to_bytes())
    }

    /// Hybrid mode: "X25519Kyber768" or "X25519Kyber1024".
    #[getter]
    fn mode(&self) -> &'static str {
        self.mode.label()
    }

    fn __repr__(&self) -> String {
        format!("HybridCiphertext(mode=\"{}\")", self.mode.label())
    }
}

/// Hybrid key pair returned by `hybrid_keygen`.
#[pyclass(name = "HybridKeypair", module = "qshield")]
struct PyHybridKeypair {
    public_key: Py<PyHybridPublicKey>,
    secret_key: Py<PyHybridSecretKey>,
}

#[pymethods]
impl PyHybridKeypair {
    #[getter]
    fn public_key(&self, py: Python<'_>) -> Py<PyHybridPublicKey> {
        self.public_key.clone_ref(py)
    }

    #[getter]
    fn secret_key(&self, py: Python<'_>) -> Py<PyHybridSecretKey> {
        self.secret_key.clone_ref(py)
    }

    fn __repr__(&self, py: Python<'_>) -> String {
        let mode = self.public_key.borrow(py).mode();
        format!("HybridKeypair(mode=\"{mode}\")")
    }
}

// ── KEM functions ──────────────────────────────────────────────────────────

/// Generate an ML-KEM key pair.
///
/// Args:
///     level: Security level — "512", "768" (default), or "1024".
///
/// Returns:
///     KemKeypair with `.public_key` and `.secret_key` attributes.
#[pyfunction]
#[pyo3(signature = (level = "768"))]
fn kem_keygen(py: Python<'_>, level: &str) -> PyResult<PyKemKeypair> {
    let kem_level = parse_kem_level(level)?;
    let kp = core_kem_keygen(kem_level).map_err(to_py_err)?;
    let qshield_core::KemKeyPair {
        public_key,
        secret_key,
    } = kp;
    let py_pk = Py::new(py, PyKemPublicKey { inner: public_key })?;
    let py_sk = Py::new(py, PyKemSecretKey { inner: secret_key })?;
    Ok(PyKemKeypair {
        public_key: py_pk,
        secret_key: py_sk,
    })
}

/// Encapsulate a shared secret using an ML-KEM public key.
///
/// Args:
///     public_key: A KemPublicKey returned by kem_keygen.
///
/// Returns:
///     Tuple of (shared_secret: bytes, ciphertext: KemCiphertext).
#[pyfunction]
fn kem_encapsulate<'py>(
    py: Python<'py>,
    public_key: &PyKemPublicKey,
) -> PyResult<(Bound<'py, PyBytes>, PyKemCiphertext)> {
    let (ss, ct) = core_kem_encapsulate(&public_key.inner).map_err(to_py_err)?;
    let ss_bytes = PyBytes::new(py, ss.as_bytes());
    Ok((ss_bytes, PyKemCiphertext { inner: ct }))
}

/// Recover a shared secret from an ML-KEM ciphertext using a secret key.
///
/// Args:
///     secret_key: A KemSecretKey returned by kem_keygen.
///     ciphertext: A KemCiphertext returned by kem_encapsulate.
///
/// Returns:
///     The 32-byte shared secret as bytes.
#[pyfunction]
fn kem_decapsulate<'py>(
    py: Python<'py>,
    secret_key: &PyKemSecretKey,
    ciphertext: &PyKemCiphertext,
) -> PyResult<Bound<'py, PyBytes>> {
    let ss = core_kem_decapsulate(&secret_key.inner, &ciphertext.inner).map_err(to_py_err)?;
    Ok(PyBytes::new(py, ss.as_bytes()))
}

// ── DSA functions ──────────────────────────────────────────────────────────

/// Generate an ML-DSA key pair.
///
/// Args:
///     level: Security level — "44", "65" (default), or "87".
///
/// Returns:
///     DsaKeypair with `.verifying_key` and `.level` attributes.
#[pyfunction]
#[pyo3(signature = (level = "65"))]
fn dsa_keygen(level: &str) -> PyResult<PyDsaKeypair> {
    let dsa_level = parse_dsa_level(level)?;
    let kp = core_dsa_keygen(dsa_level).map_err(to_py_err)?;
    Ok(PyDsaKeypair { inner: kp })
}

/// Sign a message with an ML-DSA key pair (hedged / randomized).
///
/// Args:
///     keypair: A DsaKeypair returned by dsa_keygen.
///     message: The message bytes to sign.
///
/// Returns:
///     DsaSignature object.
#[pyfunction]
fn dsa_sign(keypair: &PyDsaKeypair, message: &[u8]) -> PyResult<PyDsaSignature> {
    let sig = core_dsa_sign(&keypair.inner, message).map_err(to_py_err)?;
    Ok(PyDsaSignature { inner: sig })
}

/// Verify an ML-DSA signature.
///
/// Args:
///     verifying_key: A DsaVerifyingKey.
///     message: The message bytes.
///     signature: The DsaSignature to verify.
///
/// Returns:
///     True if the signature is valid.
///
/// Raises:
///     SignatureError: If the signature is invalid.
#[pyfunction]
fn dsa_verify(
    verifying_key: &PyDsaVerifyingKey,
    message: &[u8],
    signature: &PyDsaSignature,
) -> PyResult<bool> {
    let valid =
        core_dsa_verify(&verifying_key.inner, message, &signature.inner).map_err(to_py_err)?;
    Ok(valid)
}

// ── Hybrid KEM functions ───────────────────────────────────────────────────

/// Generate a hybrid X25519 + ML-KEM key pair.
///
/// Args:
///     mode: "X25519Kyber768" (default) or "X25519Kyber1024".
///
/// Returns:
///     HybridKeypair with `.public_key` and `.secret_key` attributes.
#[pyfunction]
#[pyo3(signature = (mode = "X25519Kyber768"))]
fn hybrid_keygen(py: Python<'_>, mode: &str) -> PyResult<PyHybridKeypair> {
    let hybrid_mode = parse_hybrid_mode(mode)?;
    let kp = core_hybrid_keygen(hybrid_mode).map_err(to_py_err)?;
    let qshield_core::HybridKeyPair {
        public_key,
        secret_key,
    } = kp;
    let py_pk = Py::new(py, PyHybridPublicKey::from_core(&public_key))?;
    let py_sk = Py::new(py, PyHybridSecretKey { inner: secret_key })?;
    Ok(PyHybridKeypair {
        public_key: py_pk,
        secret_key: py_sk,
    })
}

/// Encapsulate a shared secret using a hybrid public key.
///
/// Args:
///     public_key: A HybridPublicKey returned by hybrid_keygen.
///
/// Returns:
///     Tuple of (shared_secret: bytes, ciphertext: HybridCiphertext).
#[pyfunction]
fn hybrid_encapsulate<'py>(
    py: Python<'py>,
    public_key: &PyHybridPublicKey,
) -> PyResult<(Bound<'py, PyBytes>, PyHybridCiphertext)> {
    let core_pk = public_key.to_core()?;
    let result = core_hybrid_encapsulate(&core_pk).map_err(to_py_err)?;
    let mode = public_key.mode;
    let ss_bytes = PyBytes::new(py, result.0.as_bytes());
    Ok((
        ss_bytes,
        PyHybridCiphertext {
            inner: result.1,
            mode,
        },
    ))
}

/// Recover a shared secret from a hybrid ciphertext using a secret key.
///
/// Args:
///     secret_key: A HybridSecretKey returned by hybrid_keygen.
///     ciphertext: A HybridCiphertext returned by hybrid_encapsulate.
///
/// Returns:
///     The 32-byte shared secret as bytes.
#[pyfunction]
fn hybrid_decapsulate<'py>(
    py: Python<'py>,
    secret_key: &PyHybridSecretKey,
    ciphertext: &PyHybridCiphertext,
) -> PyResult<Bound<'py, PyBytes>> {
    let result =
        core_hybrid_decapsulate(&secret_key.inner, &ciphertext.inner).map_err(to_py_err)?;
    Ok(PyBytes::new(py, result.shared_secret.as_bytes()))
}

// ── AEAD functions ─────────────────────────────────────────────────────────

/// Encrypt with AES-256-GCM.
///
/// Args:
///     key: 32-byte key.
///     nonce: 12-byte nonce (use random_bytes(12) for each message).
///     plaintext: Data to encrypt.
///     aad: Additional authenticated data (may be empty bytes).
///
/// Returns:
///     ciphertext || 16-byte authentication tag as bytes.
#[pyfunction]
fn aes256gcm_encrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let key: &[u8; 32] = key.try_into().map_err(|_| {
        PyInvalidKeyLengthError::new_err(format!("AES key must be 32 bytes, got {}", key.len()))
    })?;
    let nonce: &[u8; NONCE_LEN] = nonce.try_into().map_err(|_| {
        PyInvalidKeyLengthError::new_err(format!(
            "AES nonce must be {NONCE_LEN} bytes, got {}",
            nonce.len()
        ))
    })?;
    let ct = core_aes256gcm_encrypt(key, nonce, plaintext, aad).map_err(to_py_err)?;
    Ok(PyBytes::new(py, &ct))
}

/// Decrypt with AES-256-GCM.
///
/// Args:
///     key: 32-byte key.
///     nonce: 12-byte nonce (must match the nonce used to encrypt).
///     ciphertext: ciphertext || 16-byte tag (output of aes256gcm_encrypt).
///     aad: Additional authenticated data (must match what was passed to encrypt).
///
/// Returns:
///     The decrypted plaintext bytes.
///
/// Raises:
///     DecapsulationError: If authentication fails (tampered data, wrong key/nonce/AAD).
#[pyfunction]
fn aes256gcm_decrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let key: &[u8; 32] = key.try_into().map_err(|_| {
        PyInvalidKeyLengthError::new_err(format!("AES key must be 32 bytes, got {}", key.len()))
    })?;
    let nonce: &[u8; NONCE_LEN] = nonce.try_into().map_err(|_| {
        PyInvalidKeyLengthError::new_err(format!(
            "AES nonce must be {NONCE_LEN} bytes, got {}",
            nonce.len()
        ))
    })?;
    let pt = core_aes256gcm_decrypt(key, nonce, ciphertext, aad).map_err(to_py_err)?;
    Ok(PyBytes::new(py, &pt))
}

/// Encrypt with ChaCha20-Poly1305.
///
/// Preferred over AES-256-GCM on platforms without hardware AES acceleration.
///
/// Args:
///     key: 32-byte key.
///     nonce: 12-byte nonce.
///     plaintext: Data to encrypt.
///     aad: Additional authenticated data.
///
/// Returns:
///     ciphertext || 16-byte authentication tag as bytes.
#[pyfunction]
fn chacha20poly1305_encrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let key: &[u8; 32] = key.try_into().map_err(|_| {
        PyInvalidKeyLengthError::new_err(format!("ChaCha key must be 32 bytes, got {}", key.len()))
    })?;
    let nonce: &[u8; NONCE_LEN] = nonce.try_into().map_err(|_| {
        PyInvalidKeyLengthError::new_err(format!(
            "ChaCha nonce must be {NONCE_LEN} bytes, got {}",
            nonce.len()
        ))
    })?;
    let ct = core_chacha20poly1305_encrypt(key, nonce, plaintext, aad).map_err(to_py_err)?;
    Ok(PyBytes::new(py, &ct))
}

/// Decrypt with ChaCha20-Poly1305.
///
/// Raises:
///     DecapsulationError: If authentication fails.
#[pyfunction]
fn chacha20poly1305_decrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let key: &[u8; 32] = key.try_into().map_err(|_| {
        PyInvalidKeyLengthError::new_err(format!("ChaCha key must be 32 bytes, got {}", key.len()))
    })?;
    let nonce: &[u8; NONCE_LEN] = nonce.try_into().map_err(|_| {
        PyInvalidKeyLengthError::new_err(format!(
            "ChaCha nonce must be {NONCE_LEN} bytes, got {}",
            nonce.len()
        ))
    })?;
    let pt = core_chacha20poly1305_decrypt(key, nonce, ciphertext, aad).map_err(to_py_err)?;
    Ok(PyBytes::new(py, &pt))
}

// ── KDF functions ──────────────────────────────────────────────────────────

/// Derive a key using HKDF-SHA3-256.
///
/// Args:
///     ikm: Input key material.
///     salt: Optional salt bytes (pass b"" for no salt).
///     info: Context/application-specific info string.
///     length: Output length in bytes (1–8160).
///
/// Returns:
///     Derived key bytes.
#[pyfunction]
fn hkdf_sha3_256<'py>(
    py: Python<'py>,
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> PyResult<Bound<'py, PyBytes>> {
    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    let okm = core_hkdf_sha3_256(ikm, salt_opt, info, length).map_err(to_py_err)?;
    Ok(PyBytes::new(py, &okm))
}

// ── Utility functions ──────────────────────────────────────────────────────

/// Return `n` cryptographically random bytes (from the OS CSPRNG).
#[pyfunction]
fn random_bytes<'py>(py: Python<'py>, n: usize) -> Bound<'py, PyBytes> {
    let mut buf = vec![0u8; n];
    rand::rng().fill_bytes(&mut buf);
    PyBytes::new(py, &buf)
}

// ── Module registration ────────────────────────────────────────────────────

/// QShield — post-quantum cryptography for Python.
///
/// Provides ML-KEM, ML-DSA, hybrid X25519+Kyber, AES-256-GCM,
/// ChaCha20-Poly1305, and HKDF-SHA3-256 via a Rust native extension.
#[pymodule]
fn qshield(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Exceptions
    m.add("QShieldError", m.py().get_type::<PyQShieldError>())?;
    m.add(
        "DecapsulationError",
        m.py().get_type::<PyDecapsulationError>(),
    )?;
    m.add(
        "InvalidKeyLengthError",
        m.py().get_type::<PyInvalidKeyLengthError>(),
    )?;
    m.add("SignatureError", m.py().get_type::<PySignatureError>())?;
    m.add(
        "KeyDerivationError",
        m.py().get_type::<PyKeyDerivationError>(),
    )?;
    m.add(
        "UnsupportedAlgorithmError",
        m.py().get_type::<PyUnsupportedAlgorithmError>(),
    )?;

    // KEM classes
    m.add_class::<PyKemPublicKey>()?;
    m.add_class::<PyKemSecretKey>()?;
    m.add_class::<PyKemCiphertext>()?;
    m.add_class::<PyKemKeypair>()?;

    // DSA classes
    m.add_class::<PyDsaVerifyingKey>()?;
    m.add_class::<PyDsaSignature>()?;
    m.add_class::<PyDsaKeypair>()?;

    // Hybrid classes
    m.add_class::<PyHybridPublicKey>()?;
    m.add_class::<PyHybridSecretKey>()?;
    m.add_class::<PyHybridCiphertext>()?;
    m.add_class::<PyHybridKeypair>()?;

    // KEM functions
    m.add_function(wrap_pyfunction!(kem_keygen, m)?)?;
    m.add_function(wrap_pyfunction!(kem_encapsulate, m)?)?;
    m.add_function(wrap_pyfunction!(kem_decapsulate, m)?)?;

    // DSA functions
    m.add_function(wrap_pyfunction!(dsa_keygen, m)?)?;
    m.add_function(wrap_pyfunction!(dsa_sign, m)?)?;
    m.add_function(wrap_pyfunction!(dsa_verify, m)?)?;

    // Hybrid functions
    m.add_function(wrap_pyfunction!(hybrid_keygen, m)?)?;
    m.add_function(wrap_pyfunction!(hybrid_encapsulate, m)?)?;
    m.add_function(wrap_pyfunction!(hybrid_decapsulate, m)?)?;

    // AEAD functions
    m.add_function(wrap_pyfunction!(aes256gcm_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes256gcm_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(chacha20poly1305_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(chacha20poly1305_decrypt, m)?)?;

    // KDF / utility
    m.add_function(wrap_pyfunction!(hkdf_sha3_256, m)?)?;
    m.add_function(wrap_pyfunction!(random_bytes, m)?)?;

    Ok(())
}
