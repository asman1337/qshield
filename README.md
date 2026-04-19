# QShield

**Quantum-safe by default.**

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-APACHE)
[![Status](https://img.shields.io/badge/status-alpha-yellow.svg)]()
[![NIST FIPS 203/204/205](https://img.shields.io/badge/NIST-FIPS%20203%20%7C%20204%20%7C%20205-green.svg)]()
[![Rust](https://img.shields.io/badge/rust-2024%20edition-orange.svg)]()
[![Made in India](https://img.shields.io/badge/made%20in-India-FF9933.svg)]()
[![Contributing](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)

---

QShield is the full-stack post-quantum cryptography (PQC) migration platform. It secures all four layers of a modern system — transport, authentication, secrets storage, and credentials — under one open core, before quantum computers make today's encryption obsolete.

Built in Rust. Aligned to NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA). India-first, enterprise- and government-ready.

> "1Password secures passwords. Cloudflare secures transport. Nobody secures all four layers under one brand with one open core. QShield is the only full-stack PQC migration platform."

---

## Why Now

NIST finalized ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205) in August 2024. India's CERT-In, RBI, and SEBI are issuing PQC migration directives. Adversaries are executing **harvest now, decrypt later** attacks — archiving today's encrypted traffic to decrypt once quantum computers arrive.

The window to migrate is open. It will not stay open.

---

## Quick Start

### Node.js

```bash
npm install @qshield/core
```

```typescript
import { kemKeygen, kemEncapsulate, kemDecapsulate, KemLevel } from '@qshield/core';

// Generate a key pair (ML-KEM-768, NIST Level 3)
const keyPair = kemKeygen(KemLevel.Kem768);

// Sender: encapsulate a shared secret
const { sharedSecret: senderSS, ciphertext } = kemEncapsulate(keyPair.publicKey);

// Receiver: recover the same shared secret
const receiverSS = kemDecapsulate(keyPair.secretKey, ciphertext);
// senderSS === receiverSS ✓
```

### Python

```bash
pip install qshield-core
```

```python
from qshield_core import kem_keygen, kem_encapsulate, kem_decapsulate, KemLevel

# Generate a key pair
kp = kem_keygen(KemLevel.Kem768)

# Sender
sender_ss, ciphertext = kem_encapsulate(kp.public_key)

# Receiver
receiver_ss = kem_decapsulate(kp.secret_key, ciphertext)
assert sender_ss == receiver_ss
```

### Rust

```toml
[dependencies]
qshield-core = "0.1"
```

```rust
use qshield_core::{kem_keygen, kem_encapsulate, kem_decapsulate, KemLevel};

let kp = kem_keygen(KemLevel::Kem768)?;
let (sender_ss, ct) = kem_encapsulate(&kp.public_key)?;
let receiver_ss = kem_decapsulate(&kp.secret_key, &ct)?;
assert_eq!(sender_ss.as_bytes(), receiver_ss.as_bytes());
```

---

## Performance

All numbers are **median latency** on a release build (`cargo bench`), x86_64 Windows, single-threaded. Throughput columns apply to streaming AEAD only.

### Key Encapsulation (ML-KEM vs. X25519)

| Operation | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 | X25519 (classical) |
|-----------|:----------:|:----------:|:-----------:|:------------------:|
| Keygen    | 36 µs      | 60 µs      | 95 µs       | 27 µs              |
| Encapsulate | 33 µs    | 31 µs      | 86 µs       | 119 µs †           |
| Decapsulate | 44 µs    | 72 µs      | 54 µs       | 29 µs              |

† X25519 encapsulate = ephemeral key generation + DH; OsRng syscall overhead on Windows accounts for the difference.

**Takeaway:** ML-KEM-768 (the QShield default) is within **2–3×** of classical X25519 for keygen and decapsulate, and is actually *faster* at encapsulation on this platform due to batched polynomial arithmetic vs. per-call RNG overhead.

### Digital Signatures (ML-DSA vs. Ed25519)

| Operation | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 | Ed25519 (classical) |
|-----------|:---------:|:---------:|:---------:|:-------------------:|
| Keygen    | 182 µs    | 219 µs    | 363 µs    | 11.6 µs             |
| Sign      | 269 µs    | 461 µs    | 449 µs    | 13.3 µs             |
| Verify    | 68 µs     | 111 µs    | 196 µs    | 21.8 µs             |

ML-DSA keygen is ~15–31× slower than Ed25519, and signing is ~20–35× slower. Verify is ~3–9× slower. The tradeoff is quantum resistance — classical Ed25519 offers none.

### Hybrid KEM (X25519 + ML-KEM)

| Operation | X25519+ML-KEM-768 | X25519+ML-KEM-1024 |
|-----------|:-----------------:|:------------------:|
| Keygen    | 60 µs             | 70 µs              |
| Encapsulate | 79 µs           | 86 µs              |
| Decapsulate | 69 µs           | 90 µs              |

Hybrid mode costs roughly the sum of X25519 + ML-KEM individually, as expected.

### Key Derivation

| Operation | Output length | Median |
|-----------|:-------------:|:------:|
| HKDF-SHA3-256 | 32 B      | 2.0 µs |
| HKDF-SHA3-256 | 256 B     | 5.9 µs |

### Symmetric AEAD Throughput

| Cipher | 64 B | 1 KB | 1 MB | 100 MB |
|--------|------|------|------|--------|
| AES-256-GCM encrypt | 169 ns | 597 ns / 1.60 GiB/s | 1.10 ms / 912 MiB/s | 75.6 ms / 1.29 GiB/s |
| AES-256-GCM decrypt | 219 ns | 658 ns / 1.45 GiB/s | 686 µs / 1.42 GiB/s | 68.3 ms / 1.43 GiB/s |
| ChaCha20-Poly1305 encrypt | 973 ns | 1.36 µs / 718 MiB/s | 734 µs / 1.33 GiB/s | 69.8 ms / 1.40 GiB/s |
| ChaCha20-Poly1305 decrypt | 990 ns | 1.39 µs / 701 MiB/s | 710 µs / 1.38 GiB/s | 71.9 ms / 1.36 GiB/s |

AES-256-GCM benefits from AES-NI hardware acceleration (Intel/AMD x86_64). ChaCha20-Poly1305 is pure software but remains competitive and is preferred on mobile/embedded targets without AES-NI.

---

## Products

| Product | Description | Model |
|---------|-------------|-------|
| **QShield Core** | Open-source PQC cryptography library. ML-KEM, ML-DSA, hybrid classical+PQC. Rust native with Node.js, Python, and WASM bindings. | Open source (MIT/Apache-2.0) |
| **QShield Proxy** | Drop-in PQC-hybrid TLS termination proxy. Add quantum-safe TLS to any service with zero application code changes. | OSS + hosted |
| **QShield Vault** | PQC-first password and secrets manager. Zero-knowledge architecture. Browser extension, desktop, mobile. | Freemium |
| **QShield Auth** | PQC-ready identity middleware. Drop-in Auth0/Clerk replacement issuing ML-DSA-signed JWTs, OAuth 2.1, SSH CA. | SaaS |
| **QShield Enterprise** | Migration intelligence platform. Scan codebases, score PQC readiness, generate CERT-In / RBI / SEBI compliance reports. | B2B / B2G |

---

## Algorithms

| Primitive | Algorithm | Standard | Security Level | QShield Default |
|-----------|-----------|----------|----------------|-----------------|
| Key Encapsulation | ML-KEM-512 / 768 / 1024 | NIST FIPS 203 | 1 / 3 / 5 | ML-KEM-768 |
| Digital Signature | ML-DSA-44 / 65 / 87 | NIST FIPS 204 | 2 / 3 / 5 | ML-DSA-65 |
| Hash-based Signature | SLH-DSA | NIST FIPS 205 | configurable | — (Phase 2) |
| Hybrid KEM | X25519 + ML-KEM-768/1024 | IETF draft | 3 / 5 | X25519+ML-KEM-768 |
| Hybrid Signature | Ed25519 + ML-DSA-65 | Composite draft | 3 | Ed25519+ML-DSA-65 |
| Symmetric Encryption | AES-256-GCM | NIST SP 800-38D | — | AES-256-GCM |
| Symmetric Encryption | ChaCha20-Poly1305 | RFC 8439 | — | (mobile/embedded) |
| Key Derivation | HKDF-SHA3-256 | RFC 5869 | — | HKDF-SHA3-256 |

All algorithms are from vetted upstream crates (`ml-kem`, `ml-dsa`, `x25519-dalek`, `ed25519-dalek`, `aes-gcm`, `chacha20poly1305`). No custom cryptography.

---

## Repository Structure

```
QShield/
├── README.md              ← you are here
├── CONTRIBUTING.md        ← contribution guide
├── SECURITY.md            ← vulnerability disclosure policy
├── Cargo.toml             ← Rust workspace root
├── justfile               ← task runner (just build, just test, etc.)
├── deny.toml              ← cargo-deny: license + advisory checks
│
├── crates/
│   ├── qshield-core/      ← PQC crypto primitives (this repo's main output)
│   │   ├── src/           ← kem, dsa, hybrid, hybrid_sig, aead, kdf, wire, zeroize_audit
│   │   └── benches/       ← criterion benchmarks (kem, dsa, hybrid, aead, kdf)
│   ├── qshield-common/    ← shared error types, logging
│   ├── qshield-proxy/     ← TLS termination proxy (Phase 2)
│   ├── qshield-vault-api/ ← vault backend (Phase 2)
│   └── qshield-auth/      ← identity middleware (Phase 2)
│
├── bindings/
│   ├── node/              ← Node.js native addon (NAPI-RS)
│   ├── python/            ← Python bindings (PyO3 + maturin)
│   └── wasm/              ← WASM build (wasm-pack, Phase 2)
│
├── apps/                  ← Frontend applications (Phase 2+)
│   ├── vault-web/         ← Next.js 15 vault frontend
│   ├── vault-extension/   ← Manifest V3 browser extension
│   ├── vault-desktop/     ← Tauri 2 desktop app
│   ├── vault-mobile/      ← Flutter mobile app
│   └── auth-dashboard/    ← Auth admin dashboard
│
└── tests/                 ← integration tests (cross-crate)
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Core language | Rust 2024 edition |
| PQC primitives | `ml-kem` 0.2, `ml-dsa` 0.0.4, `x25519-dalek` 2, `ed25519-dalek` |
| Symmetric | `aes-gcm`, `chacha20poly1305` |
| KDF | `hkdf` + `sha3` |
| Bindings | PyO3 / maturin (Python), NAPI-RS (Node.js), wasm-bindgen (WASM) |
| Async runtime | Tokio |
| Web framework | Axum |
| Frontend | Next.js 15, Tauri 2 (desktop), Flutter (mobile) |
| Database | PostgreSQL 18 + sqlx |
| Benchmarking | criterion 0.5 |

---

## Security

QShield's threat model covers quantum adversaries and classical attackers. All cryptographic decisions follow NIST post-quantum standards. No custom cryptography is written or used.

Key material is zeroized on drop throughout — `KemSecretKey`, `SharedSecret`, `DsaSigningKey`, and hybrid equivalents all implement `ZeroizeOnDrop`. The `zeroize_audit` module contains compile-time assertions enforcing this.

Found a vulnerability? **Do not open a public issue.** See [SECURITY.md](SECURITY.md) for responsible disclosure policy.

---

## Contributing

QShield Core (the cryptography library) is **open for contributions**. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

Good first issues to look at:
- Adding NIST Known Answer Test (KAT) vectors for ML-KEM, ML-DSA (QS-101/102)
- SLH-DSA (SPHINCS+) implementation (QS-105)
- WASM build target and browser integration (QS-117)
- Go bindings via CGo FFI (QS-111)
- CI benchmark regression detection (QS-115)

The Phase 2 products (Proxy, Vault, Auth) are still in early design. Contributions there are welcome but please open an issue to discuss before submitting a large PR.

---

## License

Copyright 2026 Asman Mirza.

Dual-licensed under [MIT](LICENSE-MIT) or [Apache License, Version 2.0](LICENSE-APACHE), at your option. See the license files for the full text.

Commercial add-ons (QShield Vault Pro, QShield Auth SaaS, QShield Enterprise) are subject to separate commercial licensing terms.
