"""
QS-109 acceptance-test suite for the qshield Python bindings.

Run after building the extension with maturin:
    maturin develop --manifest-path bindings/python/Cargo.toml
    pytest bindings/python/tests/ -v

All tests are pure-Python; they exercise the spec's example code paths
and verify correctness, error handling, and type contracts.
"""

import pytest

import qshield


# ── Exception hierarchy ────────────────────────────────────────────────────

class TestExceptionHierarchy:
    def test_base_exception(self):
        assert issubclass(qshield.QShieldError, Exception)

    def test_decapsulation_is_qshield(self):
        assert issubclass(qshield.DecapsulationError, qshield.QShieldError)

    def test_invalid_key_length_is_qshield(self):
        assert issubclass(qshield.InvalidKeyLengthError, qshield.QShieldError)

    def test_signature_error_is_qshield(self):
        assert issubclass(qshield.SignatureError, qshield.QShieldError)

    def test_key_derivation_is_qshield(self):
        assert issubclass(qshield.KeyDerivationError, qshield.QShieldError)

    def test_unsupported_algorithm_is_qshield(self):
        assert issubclass(qshield.UnsupportedAlgorithmError, qshield.QShieldError)


# ── random_bytes ──────────────────────────────────────────────────────────

class TestRandomBytes:
    def test_length(self):
        assert len(qshield.random_bytes(32)) == 32

    def test_zero_length(self):
        assert qshield.random_bytes(0) == b""

    def test_uniqueness(self):
        a = qshield.random_bytes(32)
        b = qshield.random_bytes(32)
        assert a != b  # astronomically unlikely to collide

    def test_returns_bytes(self):
        assert isinstance(qshield.random_bytes(16), bytes)


# ── KEM ───────────────────────────────────────────────────────────────────

class TestKem:
    @pytest.mark.parametrize("level", ["512", "768", "1024"])
    def test_round_trip(self, level: str):
        keypair = qshield.kem_keygen(level=level)
        assert keypair.public_key.level == level
        assert keypair.secret_key.level == level

        shared_secret, ciphertext = qshield.kem_encapsulate(keypair.public_key)
        recovered = qshield.kem_decapsulate(keypair.secret_key, ciphertext)

        assert shared_secret == recovered
        assert len(shared_secret) == 32

    def test_default_level_is_768(self):
        keypair = qshield.kem_keygen()
        assert keypair.public_key.level == "768"

    def test_keypair_repr(self):
        kp = qshield.kem_keygen(level="768")
        assert "768" in repr(kp)

    def test_public_key_to_bytes(self):
        kp = qshield.kem_keygen()
        raw = kp.public_key.to_bytes()
        assert isinstance(raw, bytes)
        assert len(raw) > 0

    def test_secret_key_to_bytes(self):
        kp = qshield.kem_keygen()
        raw = kp.secret_key.to_bytes()
        assert isinstance(raw, bytes)
        assert len(raw) > 0

    def test_ciphertext_to_bytes(self):
        kp = qshield.kem_keygen()
        _, ct = qshield.kem_encapsulate(kp.public_key)
        raw = ct.to_bytes()
        assert isinstance(raw, bytes)
        assert len(raw) > 0

    def test_two_encapsulations_produce_different_secrets(self):
        kp = qshield.kem_keygen()
        ss1, _ = qshield.kem_encapsulate(kp.public_key)
        ss2, _ = qshield.kem_encapsulate(kp.public_key)
        assert ss1 != ss2

    def test_invalid_level_raises(self):
        with pytest.raises(qshield.UnsupportedAlgorithmError):
            qshield.kem_keygen(level="999")

    def test_spec_example(self):
        """Verbatim from QS-109 spec."""
        keypair = qshield.kem_keygen(level="768")
        shared_secret, ciphertext = qshield.kem_encapsulate(keypair.public_key)
        recovered = qshield.kem_decapsulate(keypair.secret_key, ciphertext)
        assert shared_secret == recovered


# ── DSA ───────────────────────────────────────────────────────────────────

class TestDsa:
    @pytest.mark.parametrize("level", ["44", "65", "87"])
    def test_sign_verify_round_trip(self, level: str):
        keypair = qshield.dsa_keygen(level=level)
        message = b"QShield integration test"
        signature = qshield.dsa_sign(keypair, message)
        valid = qshield.dsa_verify(keypair.verifying_key, message, signature)
        assert valid is True

    def test_default_level_is_65(self):
        kp = qshield.dsa_keygen()
        assert kp.level == "65"

    def test_wrong_message_fails(self):
        kp = qshield.dsa_keygen()
        sig = qshield.dsa_sign(kp, b"hello")
        with pytest.raises(qshield.SignatureError):
            qshield.dsa_verify(kp.verifying_key, b"world", sig)

    def test_signature_to_bytes(self):
        kp = qshield.dsa_keygen()
        sig = qshield.dsa_sign(kp, b"test")
        raw = sig.to_bytes()
        assert isinstance(raw, bytes)
        assert len(raw) > 0

    def test_verifying_key_to_bytes(self):
        kp = qshield.dsa_keygen()
        vk_bytes = kp.verifying_key.to_bytes()
        assert isinstance(vk_bytes, bytes)
        assert len(vk_bytes) > 0

    def test_invalid_level_raises(self):
        with pytest.raises(qshield.UnsupportedAlgorithmError):
            qshield.dsa_keygen(level="128")

    def test_spec_example(self):
        """Verbatim from QS-109 spec."""
        keypair = qshield.dsa_keygen(level="65")
        signature = qshield.dsa_sign(keypair, b"hello")
        valid = qshield.dsa_verify(keypair.verifying_key, b"hello", signature)
        assert valid is True


# ── Hybrid KEM ────────────────────────────────────────────────────────────

class TestHybridKem:
    @pytest.mark.parametrize("mode", ["X25519Kyber768", "X25519Kyber1024"])
    def test_round_trip(self, mode: str):
        keypair = qshield.hybrid_keygen(mode=mode)
        assert keypair.public_key.mode == mode
        assert keypair.secret_key.mode == mode

        shared_secret, ciphertext = qshield.hybrid_encapsulate(keypair.public_key)
        recovered = qshield.hybrid_decapsulate(keypair.secret_key, ciphertext)

        assert shared_secret == recovered
        assert len(shared_secret) == 32

    def test_default_mode_is_x25519_kyber768(self):
        kp = qshield.hybrid_keygen()
        assert kp.public_key.mode == "X25519Kyber768"

    def test_public_key_to_bytes(self):
        kp = qshield.hybrid_keygen()
        raw = kp.public_key.to_bytes()
        assert isinstance(raw, bytes)
        # 32 (X25519) + KEM-768 public key bytes
        assert len(raw) > 32

    def test_ciphertext_to_bytes(self):
        kp = qshield.hybrid_keygen()
        _, ct = qshield.hybrid_encapsulate(kp.public_key)
        raw = ct.to_bytes()
        assert isinstance(raw, bytes)
        assert len(raw) > 32

    def test_invalid_mode_raises(self):
        with pytest.raises(qshield.UnsupportedAlgorithmError):
            qshield.hybrid_keygen(mode="RSA2048")

    def test_spec_example(self):
        """Verbatim from QS-109 spec."""
        keypair = qshield.hybrid_keygen(mode="X25519Kyber768")
        shared_secret, ciphertext = qshield.hybrid_encapsulate(keypair.public_key)
        recovered = qshield.hybrid_decapsulate(keypair.secret_key, ciphertext)
        assert shared_secret == recovered


# ── AES-256-GCM ──────────────────────────────────────────────────────────

class TestAes256Gcm:
    def test_round_trip(self):
        key = qshield.random_bytes(32)
        nonce = qshield.random_bytes(12)
        ct = qshield.aes256gcm_encrypt(key, nonce, b"secret message", b"aad")
        pt = qshield.aes256gcm_decrypt(key, nonce, ct, b"aad")
        assert pt == b"secret message"

    def test_tampered_tag_raises(self):
        key = qshield.random_bytes(32)
        nonce = qshield.random_bytes(12)
        ct = qshield.aes256gcm_encrypt(key, nonce, b"hello", b"")
        tampered = bytes([ct[0] ^ 0xFF]) + ct[1:]
        with pytest.raises(qshield.DecapsulationError):
            qshield.aes256gcm_decrypt(key, nonce, tampered, b"")

    def test_wrong_aad_raises(self):
        key = qshield.random_bytes(32)
        nonce = qshield.random_bytes(12)
        ct = qshield.aes256gcm_encrypt(key, nonce, b"hello", b"correct")
        with pytest.raises(qshield.DecapsulationError):
            qshield.aes256gcm_decrypt(key, nonce, ct, b"wrong")

    def test_wrong_key_length_raises(self):
        with pytest.raises(qshield.InvalidKeyLengthError):
            qshield.aes256gcm_encrypt(b"short", b"\x00" * 12, b"data", b"")

    def test_wrong_nonce_length_raises(self):
        with pytest.raises(qshield.InvalidKeyLengthError):
            qshield.aes256gcm_encrypt(b"\x00" * 32, b"short", b"data", b"")

    def test_empty_plaintext(self):
        key = qshield.random_bytes(32)
        nonce = qshield.random_bytes(12)
        ct = qshield.aes256gcm_encrypt(key, nonce, b"", b"")
        pt = qshield.aes256gcm_decrypt(key, nonce, ct, b"")
        assert pt == b""

    def test_spec_example(self):
        """Verbatim from QS-109 spec."""
        key = qshield.random_bytes(32)
        nonce = qshield.random_bytes(12)
        ct = qshield.aes256gcm_encrypt(key, nonce, b"secret", b"aad")
        pt = qshield.aes256gcm_decrypt(key, nonce, ct, b"aad")
        assert pt == b"secret"


# ── ChaCha20-Poly1305 ─────────────────────────────────────────────────────

class TestChaCha20Poly1305:
    def test_round_trip(self):
        key = qshield.random_bytes(32)
        nonce = qshield.random_bytes(12)
        ct = qshield.chacha20poly1305_encrypt(key, nonce, b"hello chacha", b"")
        pt = qshield.chacha20poly1305_decrypt(key, nonce, ct, b"")
        assert pt == b"hello chacha"

    def test_tampered_raises(self):
        key = qshield.random_bytes(32)
        nonce = qshield.random_bytes(12)
        ct = qshield.chacha20poly1305_encrypt(key, nonce, b"data", b"")
        tampered = ct[:-1] + bytes([ct[-1] ^ 0x01])
        with pytest.raises(qshield.DecapsulationError):
            qshield.chacha20poly1305_decrypt(key, nonce, tampered, b"")


# ── HKDF-SHA3-256 ─────────────────────────────────────────────────────────

class TestHkdfSha3_256:
    def test_returns_correct_length(self):
        out = qshield.hkdf_sha3_256(b"ikm", b"salt", b"info", 32)
        assert len(out) == 32

    def test_variable_length(self):
        for n in [1, 16, 32, 64, 128]:
            out = qshield.hkdf_sha3_256(b"ikm", b"salt", b"info", n)
            assert len(out) == n

    def test_deterministic(self):
        a = qshield.hkdf_sha3_256(b"ikm", b"salt", b"info", 32)
        b = qshield.hkdf_sha3_256(b"ikm", b"salt", b"info", 32)
        assert a == b

    def test_different_info_differs(self):
        a = qshield.hkdf_sha3_256(b"ikm", b"salt", b"info-a", 32)
        b = qshield.hkdf_sha3_256(b"ikm", b"salt", b"info-b", 32)
        assert a != b

    def test_empty_salt(self):
        out = qshield.hkdf_sha3_256(b"ikm", b"", b"info", 32)
        assert len(out) == 32

    def test_zero_length_raises(self):
        with pytest.raises(qshield.KeyDerivationError):
            qshield.hkdf_sha3_256(b"ikm", b"salt", b"info", 0)

    def test_spec_example(self):
        """Verbatim from QS-109 spec."""
        derived = qshield.hkdf_sha3_256(
            ikm=b"input key material",
            salt=b"optional salt",
            info=b"context",
            length=32,
        )
        assert len(derived) == 32
        assert isinstance(derived, bytes)
