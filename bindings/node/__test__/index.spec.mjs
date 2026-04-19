// @qshield/core — Vitest test suite (QS-110 acceptance criteria)
//
// Tests cover all exported operations and verify correct cryptographic behavior.
// Run: npm test (after building the native addon with `npm run build`)

import { describe, it, expect } from 'vitest'
import {
  KemLevel,
  DsaLevel,
  HybridMode,
  kemKeygen,
  kemEncapsulate,
  kemDecapsulate,
  dsaKeygen,
  dsaSign,
  dsaVerify,
  hybridKeygen,
  hybridEncapsulate,
  hybridDecapsulate,
  aes256gcmEncrypt,
  aes256gcmDecrypt,
  chacha20poly1305Encrypt,
  chacha20poly1305Decrypt,
  hkdfSha3256,
  randomBytes,
  generateNonce,
} from '../index.js'

// ── KEM ──────────────────────────────────────────────────────────────────

describe('KEM — ML-KEM key encapsulation', () => {
  it('kemKeygen returns a KemKeypair with public and secret keys', async () => {
    const kp = await kemKeygen()
    expect(kp).toBeDefined()
    expect(kp.publicKey).toBeDefined()
    expect(kp.secretKey).toBeDefined()
  })

  it('kemKeygen with L768 returns 1184-byte public key', async () => {
    const kp = await kemKeygen(KemLevel.L768)
    expect(kp.publicKey.toBytes().length).toBe(1184)
  })

  it('kemKeygen with L1024 returns 1568-byte public key', async () => {
    const kp = await kemKeygen(KemLevel.L1024)
    expect(kp.publicKey.toBytes().length).toBe(1568)
  })

  it('kemEncapsulate returns 32-byte shared secret and ciphertext', async () => {
    const kp = await kemKeygen(KemLevel.L768)
    const { sharedSecret, ciphertext } = await kemEncapsulate(kp.publicKey)
    expect(sharedSecret.length).toBe(32)
    expect(ciphertext.length).toBeGreaterThan(0)
  })

  it('kemDecapsulate recovers the same shared secret', async () => {
    const kp = await kemKeygen(KemLevel.L768)
    const { sharedSecret, ciphertext } = await kemEncapsulate(kp.publicKey)
    const recovered = await kemDecapsulate(kp.secretKey, ciphertext)
    expect(recovered).toEqual(sharedSecret)
  })

  it('round-trip works for L512', async () => {
    const kp = await kemKeygen(KemLevel.L512)
    const { sharedSecret, ciphertext } = await kemEncapsulate(kp.publicKey)
    const recovered = await kemDecapsulate(kp.secretKey, ciphertext)
    expect(recovered).toEqual(sharedSecret)
  })

  it('round-trip works for L1024', async () => {
    const kp = await kemKeygen(KemLevel.L1024)
    const { sharedSecret, ciphertext } = await kemEncapsulate(kp.publicKey)
    const recovered = await kemDecapsulate(kp.secretKey, ciphertext)
    expect(recovered).toEqual(sharedSecret)
  })

  it('different encapsulations produce different shared secrets', async () => {
    const kp = await kemKeygen()
    const { sharedSecret: ss1 } = await kemEncapsulate(kp.publicKey)
    const { sharedSecret: ss2 } = await kemEncapsulate(kp.publicKey)
    // Probabilistically different (would fail ~1/2^256 of the time)
    expect(Buffer.compare(ss1, ss2)).not.toBe(0)
  })

  it('kemKeygen does not block event loop', async () => {
    let timeoutFired = false
    const timer = setTimeout(() => { timeoutFired = true }, 0)
    await kemKeygen()
    clearTimeout(timer)
    expect(timeoutFired).toBe(true)
  })
})

// ── DSA ──────────────────────────────────────────────────────────────────

describe('DSA — ML-DSA digital signatures', () => {
  it('dsaKeygen returns a DsaKeypair with verifyingKey', async () => {
    const kp = await dsaKeygen()
    expect(kp).toBeDefined()
    expect(kp.verifyingKey).toBeDefined()
  })

  it('dsaSign returns non-empty signature bytes', async () => {
    const kp = await dsaKeygen()
    const msg = Buffer.from('hello qshield')
    const sig = await dsaSign(kp, msg)
    expect(sig.length).toBeGreaterThan(0)
  })

  it('dsaVerify returns true for valid signature', async () => {
    const kp = await dsaKeygen()
    const msg = Buffer.from('test message')
    const sig = await dsaSign(kp, msg)
    const valid = await dsaVerify(kp.verifyingKey, msg, sig)
    expect(valid).toBe(true)
  })

  it('dsaVerify returns false for wrong message', async () => {
    const kp = await dsaKeygen()
    const msg = Buffer.from('original')
    const sig = await dsaSign(kp, msg)
    const valid = await dsaVerify(kp.verifyingKey, Buffer.from('tampered'), sig)
    expect(valid).toBe(false)
  })

  it('dsaVerify returns false for tampered signature', async () => {
    const kp = await dsaKeygen()
    const msg = Buffer.from('test')
    const sig = await dsaSign(kp, msg)
    const tampered = Buffer.from(sig)
    tampered[0] ^= 0xff
    const valid = await dsaVerify(kp.verifyingKey, msg, tampered)
    expect(valid).toBe(false)
  })

  it('round-trip works for L2 (ML-DSA-44)', async () => {
    const kp = await dsaKeygen(DsaLevel.L2)
    const msg = Buffer.from('level 2 test')
    const sig = await dsaSign(kp, msg)
    expect(await dsaVerify(kp.verifyingKey, msg, sig)).toBe(true)
  })

  it('round-trip works for L5 (ML-DSA-87)', async () => {
    const kp = await dsaKeygen(DsaLevel.L5)
    const msg = Buffer.from('level 5 test')
    const sig = await dsaSign(kp, msg)
    expect(await dsaVerify(kp.verifyingKey, msg, sig)).toBe(true)
  })
})

// ── Hybrid KEM ───────────────────────────────────────────────────────────

describe('Hybrid KEM — X25519 + ML-KEM', () => {
  it('hybridKeygen returns a HybridKeypair with public and secret keys', async () => {
    const kp = await hybridKeygen()
    expect(kp.publicKey).toBeDefined()
    expect(kp.secretKey).toBeDefined()
  })

  it('publicKey mode label is "X25519Kyber768" by default', async () => {
    const kp = await hybridKeygen()
    expect(kp.publicKey.mode).toBe('X25519Kyber768')
  })

  it('hybridEncapsulate returns 32-byte shared secret and ciphertext', async () => {
    const kp = await hybridKeygen()
    const { sharedSecret, ciphertext } = await hybridEncapsulate(kp.publicKey)
    expect(sharedSecret.length).toBe(32)
    expect(ciphertext.length).toBeGreaterThan(0)
  })

  it('hybridDecapsulate recovers the same shared secret', async () => {
    const kp = await hybridKeygen()
    const { sharedSecret, ciphertext } = await hybridEncapsulate(kp.publicKey)
    const recovered = await hybridDecapsulate(kp.secretKey, ciphertext)
    expect(recovered).toEqual(sharedSecret)
  })

  it('round-trip works for X25519Kyber1024', async () => {
    const kp = await hybridKeygen(HybridMode.X25519Kyber1024)
    const { sharedSecret, ciphertext } = await hybridEncapsulate(kp.publicKey)
    const recovered = await hybridDecapsulate(kp.secretKey, ciphertext)
    expect(recovered).toEqual(sharedSecret)
  })
})

// ── AES-256-GCM ──────────────────────────────────────────────────────────

describe('AEAD — AES-256-GCM', () => {
  const key = randomBytes(32)
  const nonce = generateNonce()
  const plaintext = Buffer.from('Hello, QShield!')

  it('encrypt returns ciphertext longer than plaintext (tag appended)', () => {
    const ct = aes256gcmEncrypt(key, nonce, plaintext)
    expect(ct.length).toBe(plaintext.length + 16)
  })

  it('decrypt recovers the original plaintext', () => {
    const ct = aes256gcmEncrypt(key, nonce, plaintext)
    const pt = aes256gcmDecrypt(key, nonce, ct)
    expect(pt).toEqual(plaintext)
  })

  it('decrypt with wrong key throws', () => {
    const ct = aes256gcmEncrypt(key, nonce, plaintext)
    const wrongKey = randomBytes(32)
    expect(() => aes256gcmDecrypt(wrongKey, nonce, ct)).toThrow()
  })

  it('decrypt with tampered ciphertext throws', () => {
    const ct = Buffer.from(aes256gcmEncrypt(key, nonce, plaintext))
    ct[0] ^= 0xff
    expect(() => aes256gcmDecrypt(key, nonce, ct)).toThrow()
  })

  it('round-trip with AAD', () => {
    const aad = Buffer.from('additional data')
    const ct = aes256gcmEncrypt(key, nonce, plaintext, aad)
    const pt = aes256gcmDecrypt(key, nonce, ct, aad)
    expect(pt).toEqual(plaintext)
  })

  it('decrypt with wrong AAD throws', () => {
    const aad = Buffer.from('correct aad')
    const ct = aes256gcmEncrypt(key, nonce, plaintext, aad)
    expect(() => aes256gcmDecrypt(key, nonce, ct, Buffer.from('wrong aad'))).toThrow()
  })
})

// ── ChaCha20-Poly1305 ────────────────────────────────────────────────────

describe('AEAD — ChaCha20-Poly1305', () => {
  const key = randomBytes(32)
  const nonce = generateNonce()
  const plaintext = Buffer.from('ChaCha test data')

  it('round-trip encrypts and decrypts correctly', () => {
    const ct = chacha20poly1305Encrypt(key, nonce, plaintext)
    const pt = chacha20poly1305Decrypt(key, nonce, ct)
    expect(pt).toEqual(plaintext)
  })

  it('decrypt with wrong key throws', () => {
    const ct = chacha20poly1305Encrypt(key, nonce, plaintext)
    expect(() => chacha20poly1305Decrypt(randomBytes(32), nonce, ct)).toThrow()
  })
})

// ── HKDF ─────────────────────────────────────────────────────────────────

describe('KDF — HKDF-SHA3-256', () => {
  it('produces 32 bytes by default', () => {
    const okm = hkdfSha3256(randomBytes(32))
    expect(okm.length).toBe(32)
  })

  it('produces requested length', () => {
    const okm = hkdfSha3256(randomBytes(32), undefined, undefined, 64)
    expect(okm.length).toBe(64)
  })

  it('same inputs produce same output', () => {
    const ikm = Buffer.from('test-ikm')
    const salt = Buffer.from('test-salt')
    const info = Buffer.from('test-info')
    const okm1 = hkdfSha3256(ikm, salt, info, 32)
    const okm2 = hkdfSha3256(ikm, salt, info, 32)
    expect(okm1).toEqual(okm2)
  })

  it('different IKM produces different output', () => {
    const okm1 = hkdfSha3256(randomBytes(32))
    const okm2 = hkdfSha3256(randomBytes(32))
    expect(Buffer.compare(okm1, okm2)).not.toBe(0)
  })
})

// ── Utilities ────────────────────────────────────────────────────────────

describe('Utilities', () => {
  it('randomBytes returns a Buffer of the requested size', () => {
    expect(randomBytes(16).length).toBe(16)
    expect(randomBytes(32).length).toBe(32)
    expect(randomBytes(64).length).toBe(64)
  })

  it('randomBytes produces different output each call', () => {
    const a = randomBytes(32)
    const b = randomBytes(32)
    expect(Buffer.compare(a, b)).not.toBe(0)
  })

  it('generateNonce returns 12 bytes', () => {
    expect(generateNonce().length).toBe(12)
  })

  it('publicKey toBytes round-trips through kemKeygen', async () => {
    const kp = await kemKeygen()
    const bytes = kp.publicKey.toBytes()
    expect(bytes.length).toBe(1184) // ML-KEM-768
  })
})
