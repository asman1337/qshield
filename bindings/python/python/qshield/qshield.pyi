"""
Type stubs for qshield — the QShield native extension module.

These stubs provide IDE autocomplete and static type checking support.
"""

from __future__ import annotations

# ── Exceptions ────────────────────────────────────────────────────────────

class QShieldError(Exception):
    """Base exception for all QShield errors."""
    ...

class DecapsulationError(QShieldError):
    """Decapsulation or AEAD authentication tag verification failed."""
    ...

class InvalidKeyLengthError(QShieldError):
    """Key, nonce, or ciphertext has wrong byte length."""
    ...

class SignatureError(QShieldError):
    """Signature creation or verification failed."""
    ...

class KeyDerivationError(QShieldError):
    """HKDF key derivation failed (e.g. output_len == 0 or too large)."""
    ...

class UnsupportedAlgorithmError(QShieldError):
    """Algorithm level or mode string is not recognized."""
    ...

# ── KEM classes ───────────────────────────────────────────────────────────

class KemPublicKey:
    """ML-KEM encapsulation (public) key."""

    @property
    def level(self) -> str:
        """Security level: "512", "768", or "1024"."""
        ...

    def to_bytes(self) -> bytes:
        """Return the raw bytes of this public key."""
        ...

    def __repr__(self) -> str: ...

class KemSecretKey:
    """ML-KEM decapsulation (secret) key. Bytes are zeroized on GC."""

    @property
    def level(self) -> str:
        """Security level: "512", "768", or "1024"."""
        ...

    def to_bytes(self) -> bytes:
        """Return the raw bytes. Handle with care — store encrypted."""
        ...

    def __repr__(self) -> str: ...

class KemCiphertext:
    """ML-KEM ciphertext (encapsulated shared secret)."""

    @property
    def level(self) -> str:
        """Security level: "512", "768", or "1024"."""
        ...

    def to_bytes(self) -> bytes:
        """Return the raw bytes of this ciphertext."""
        ...

    def __repr__(self) -> str: ...

class KemKeypair:
    """ML-KEM key pair returned by kem_keygen."""

    @property
    def public_key(self) -> KemPublicKey: ...

    @property
    def secret_key(self) -> KemSecretKey: ...

    def __repr__(self) -> str: ...

# ── DSA classes ───────────────────────────────────────────────────────────

class DsaVerifyingKey:
    """ML-DSA verifying (public) key."""

    @property
    def level(self) -> str:
        """Security level: "44", "65", or "87"."""
        ...

    def to_bytes(self) -> bytes:
        """Return the raw bytes of this verifying key."""
        ...

    def __repr__(self) -> str: ...

class DsaSignature:
    """ML-DSA signature."""

    @property
    def level(self) -> str:
        """Security level: "44", "65", or "87"."""
        ...

    def to_bytes(self) -> bytes:
        """Return the raw bytes of this signature."""
        ...

    def __repr__(self) -> str: ...

class DsaKeypair:
    """ML-DSA key pair. Signing key bytes are zeroized on drop."""

    @property
    def verifying_key(self) -> DsaVerifyingKey:
        """A copy of the verifying (public) key."""
        ...

    @property
    def level(self) -> str:
        """Security level: "44", "65", or "87"."""
        ...

    def __repr__(self) -> str: ...

# ── Hybrid KEM classes ────────────────────────────────────────────────────

class HybridPublicKey:
    """Hybrid X25519 + ML-KEM public key."""

    @property
    def mode(self) -> str:
        """Hybrid mode: "X25519Kyber768" or "X25519Kyber1024"."""
        ...

    def to_bytes(self) -> bytes:
        """32-byte X25519 key || ML-KEM public key bytes."""
        ...

    def __repr__(self) -> str: ...

class HybridSecretKey:
    """Hybrid X25519 + ML-KEM secret key. Zeroized on GC."""

    @property
    def mode(self) -> str:
        """Hybrid mode: "X25519Kyber768" or "X25519Kyber1024"."""
        ...

    def __repr__(self) -> str: ...

class HybridCiphertext:
    """Hybrid ciphertext: 32-byte ephemeral X25519 key || ML-KEM ciphertext."""

    @property
    def mode(self) -> str:
        """Hybrid mode: "X25519Kyber768" or "X25519Kyber1024"."""
        ...

    def to_bytes(self) -> bytes:
        """Return the raw bytes of this ciphertext."""
        ...

    def __repr__(self) -> str: ...

class HybridKeypair:
    """Hybrid key pair returned by hybrid_keygen."""

    @property
    def public_key(self) -> HybridPublicKey: ...

    @property
    def secret_key(self) -> HybridSecretKey: ...

    def __repr__(self) -> str: ...

# ── KEM functions ─────────────────────────────────────────────────────────

def kem_keygen(level: str = "768") -> KemKeypair:
    """
    Generate an ML-KEM key pair.

    Args:
        level: Security level — "512", "768" (default), or "1024".

    Returns:
        KemKeypair with .public_key and .secret_key.
    """
    ...

def kem_encapsulate(public_key: KemPublicKey) -> tuple[bytes, KemCiphertext]:
    """
    Encapsulate a shared secret using an ML-KEM public key.

    Args:
        public_key: A KemPublicKey from kem_keygen.

    Returns:
        (shared_secret: bytes, ciphertext: KemCiphertext)
    """
    ...

def kem_decapsulate(secret_key: KemSecretKey, ciphertext: KemCiphertext) -> bytes:
    """
    Recover the shared secret from a KEM ciphertext.

    Args:
        secret_key: A KemSecretKey from kem_keygen.
        ciphertext: A KemCiphertext from kem_encapsulate.

    Returns:
        32-byte shared secret.
    """
    ...

# ── DSA functions ─────────────────────────────────────────────────────────

def dsa_keygen(level: str = "65") -> DsaKeypair:
    """
    Generate an ML-DSA key pair.

    Args:
        level: Security level — "44", "65" (default), or "87".

    Returns:
        DsaKeypair with .verifying_key and .level.
    """
    ...

def dsa_sign(keypair: DsaKeypair, message: bytes) -> DsaSignature:
    """
    Sign a message with ML-DSA (hedged / randomized).

    Args:
        keypair: A DsaKeypair from dsa_keygen.
        message: Message bytes to sign.

    Returns:
        DsaSignature.
    """
    ...

def dsa_verify(
    verifying_key: DsaVerifyingKey,
    message: bytes,
    signature: DsaSignature,
) -> bool:
    """
    Verify an ML-DSA signature.

    Args:
        verifying_key: The signer's DsaVerifyingKey.
        message: The original message bytes.
        signature: The DsaSignature to check.

    Returns:
        True if the signature is valid.

    Raises:
        SignatureError: If the signature is invalid.
    """
    ...

# ── Hybrid KEM functions ──────────────────────────────────────────────────

def hybrid_keygen(mode: str = "X25519Kyber768") -> HybridKeypair:
    """
    Generate a hybrid X25519 + ML-KEM key pair.

    Args:
        mode: "X25519Kyber768" (default) or "X25519Kyber1024".

    Returns:
        HybridKeypair with .public_key and .secret_key.
    """
    ...

def hybrid_encapsulate(
    public_key: HybridPublicKey,
) -> tuple[bytes, HybridCiphertext]:
    """
    Encapsulate a shared secret using a hybrid public key.

    Args:
        public_key: A HybridPublicKey from hybrid_keygen.

    Returns:
        (shared_secret: bytes, ciphertext: HybridCiphertext)
    """
    ...

def hybrid_decapsulate(
    secret_key: HybridSecretKey,
    ciphertext: HybridCiphertext,
) -> bytes:
    """
    Recover a shared secret from a hybrid ciphertext.

    Args:
        secret_key: A HybridSecretKey from hybrid_keygen.
        ciphertext: A HybridCiphertext from hybrid_encapsulate.

    Returns:
        32-byte shared secret.
    """
    ...

# ── AEAD functions ────────────────────────────────────────────────────────

def aes256gcm_encrypt(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes,
) -> bytes:
    """
    Encrypt with AES-256-GCM.

    Args:
        key:       32-byte key.
        nonce:     12-byte nonce (use random_bytes(12) per message).
        plaintext: Data to encrypt.
        aad:       Additional authenticated data (b"" for none).

    Returns:
        ciphertext || 16-byte authentication tag.
    """
    ...

def aes256gcm_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    aad: bytes,
) -> bytes:
    """
    Decrypt with AES-256-GCM.

    Args:
        key:        32-byte key.
        nonce:      12-byte nonce (must match encrypt call).
        ciphertext: Output of aes256gcm_encrypt (includes auth tag).
        aad:        Additional authenticated data (must match encrypt call).

    Returns:
        Decrypted plaintext.

    Raises:
        DecapsulationError: If authentication fails.
    """
    ...

def chacha20poly1305_encrypt(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes,
) -> bytes:
    """
    Encrypt with ChaCha20-Poly1305 (prefer on platforms without AES-NI).

    Args:
        key:       32-byte key.
        nonce:     12-byte nonce.
        plaintext: Data to encrypt.
        aad:       Additional authenticated data.

    Returns:
        ciphertext || 16-byte tag.
    """
    ...

def chacha20poly1305_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    aad: bytes,
) -> bytes:
    """
    Decrypt with ChaCha20-Poly1305.

    Raises:
        DecapsulationError: If authentication fails.
    """
    ...

# ── KDF / utility ─────────────────────────────────────────────────────────

def hkdf_sha3_256(
    ikm: bytes,
    salt: bytes,
    info: bytes,
    length: int,
) -> bytes:
    """
    Derive a key using HKDF-SHA3-256 (RFC 5869 with SHA-3/256 as the hash).

    Args:
        ikm:    Input key material.
        salt:   Salt bytes (b"" for no salt).
        info:   Context / application-specific info.
        length: Output length in bytes (1–8160).

    Returns:
        Derived key bytes of the requested length.
    """
    ...

def random_bytes(n: int) -> bytes:
    """
    Return `n` cryptographically random bytes from the OS CSPRNG.

    Args:
        n: Number of bytes to generate.

    Returns:
        Random bytes.
    """
    ...
