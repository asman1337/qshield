"""
QShield — post-quantum cryptography for Python.

Exposes ML-KEM, ML-DSA, hybrid X25519+Kyber KEM, AES-256-GCM,
ChaCha20-Poly1305, and HKDF-SHA3-256 via a Rust native extension.
"""

from .qshield import (
    # Exceptions
    QShieldError,
    DecapsulationError,
    InvalidKeyLengthError,
    SignatureError,
    KeyDerivationError,
    UnsupportedAlgorithmError,
    # KEM
    KemPublicKey,
    KemSecretKey,
    KemCiphertext,
    KemKeypair,
    kem_keygen,
    kem_encapsulate,
    kem_decapsulate,
    # DSA
    DsaVerifyingKey,
    DsaSignature,
    DsaKeypair,
    dsa_keygen,
    dsa_sign,
    dsa_verify,
    # Hybrid KEM
    HybridPublicKey,
    HybridSecretKey,
    HybridCiphertext,
    HybridKeypair,
    hybrid_keygen,
    hybrid_encapsulate,
    hybrid_decapsulate,
    # AEAD
    aes256gcm_encrypt,
    aes256gcm_decrypt,
    chacha20poly1305_encrypt,
    chacha20poly1305_decrypt,
    # KDF / utility
    hkdf_sha3_256,
    random_bytes,
)

__all__ = [
    "QShieldError",
    "DecapsulationError",
    "InvalidKeyLengthError",
    "SignatureError",
    "KeyDerivationError",
    "UnsupportedAlgorithmError",
    "KemPublicKey",
    "KemSecretKey",
    "KemCiphertext",
    "KemKeypair",
    "kem_keygen",
    "kem_encapsulate",
    "kem_decapsulate",
    "DsaVerifyingKey",
    "DsaSignature",
    "DsaKeypair",
    "dsa_keygen",
    "dsa_sign",
    "dsa_verify",
    "HybridPublicKey",
    "HybridSecretKey",
    "HybridCiphertext",
    "HybridKeypair",
    "hybrid_keygen",
    "hybrid_encapsulate",
    "hybrid_decapsulate",
    "aes256gcm_encrypt",
    "aes256gcm_decrypt",
    "chacha20poly1305_encrypt",
    "chacha20poly1305_decrypt",
    "hkdf_sha3_256",
    "random_bytes",
]
