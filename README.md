# QShield

**Quantum-safe by default.**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-pre--alpha-orange.svg)]()
[![NIST FIPS 203](https://img.shields.io/badge/NIST-FIPS%20203%20%7C%20204%20%7C%20205-green.svg)]()
[![Made in India](https://img.shields.io/badge/made%20in-India-FF9933.svg)]()

---

QShield is the full-stack post-quantum cryptography (PQC) migration platform. It secures all four layers of a modern system - transport, authentication, secrets storage, and credentials - under one open core, before quantum computers make today's encryption obsolete.

Built in Rust. Aligned to NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA). India-first, enterprise- and government-ready.

> "1Password secures passwords. Cloudflare secures transport. Nobody secures all four layers under one brand with one open core. QShield is the only full-stack PQC migration platform."

---

## Products

| Product | Description | Model |
|---------|-------------|-------|
| **QShield Core** | Open-source PQC cryptography library. ML-KEM, ML-DSA, hybrid classical+PQC. Rust native with Python, Node, Go, and Java bindings. | Open source |
| **QShield Proxy** | Drop-in PQC-hybrid TLS termination proxy. Add quantum-safe TLS to any service with zero application code changes. | OSS + hosted |
| **QShield Vault** | PQC-first password and secrets manager. Zero-knowledge architecture. Browser extension, desktop, mobile. | Freemium |
| **QShield Auth** | PQC-ready identity middleware. Drop-in Auth0/Clerk replacement issuing ML-DSA-signed JWTs, OAuth 2.1, SSH CA. | SaaS |
| **QShield Enterprise** | Migration intelligence platform. Scan codebases, score PQC readiness, generate CERT-In / RBI / SEBI compliance reports. | B2B / B2G |

---

## Why Now

NIST finalized ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205) in August 2024. India's CERT-In, RBI, and SEBI are issuing PQC migration directives. Adversaries are executing **harvest now, decrypt later** attacks — archiving today's encrypted traffic to decrypt once quantum computers arrive.

The window to migrate is open. It will not stay open.

---

## Repository Structure

```
QShield/
├── README.md              ← you are here
├── LICENSE                ← Apache 2.0
├── Cargo.toml             ← workspace root (coming)
├── justfile               ← task runner (coming)
│
├── crates/
│   ├── qshield-core/      ← PQC crypto primitives
│   ├── qshield-proxy/     ← TLS termination proxy
│   ├── qshield-auth/      ← identity middleware
│   ├── qshield-vault-api/ ← vault backend
│   └── qshield-common/    ← shared error types, logging
│
├── apps/
│   ├── vault-web/         ← Next.js 15 vault frontend
│   ├── vault-extension/   ← Manifest V3 browser extension
│   ├── vault-desktop/     ← Tauri 2 desktop app
│   ├── vault-mobile/      ← Flutter mobile app
│   └── auth-dashboard/    ← Auth admin dashboard
│
└── packages/
    ├── qshield-node/      ← Node.js / TypeScript bindings (NAPI-RS)
    ├── qshield-python/    ← Python bindings (PyO3 + maturin)
    └── qshield-wasm/      ← WASM build (wasm-pack)

```

---

## Tech Stack

- **Language:** Rust 2024 edition (all backend); TypeScript / Next.js 15 (frontend); Flutter (mobile)
- **PQC algorithms:** ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204), SLH-DSA (FIPS 205)
- **Symmetric:** AES-256-GCM, ChaCha20-Poly1305
- **KDF:** Argon2id (passwords), HKDF-SHA3-256 (key derivation)
- **Database:** PostgreSQL 18 + sqlx (compile-time checked queries)
- **Async runtime:** Tokio
- **Web framework:** Axum
- **Desktop:** Tauri 2
- **Bindings:** PyO3 (Python), NAPI-RS (Node.js), wasm-pack (WASM)

---

## Security

QShield's threat model is quantum adversaries and classical attackers. All cryptographic decisions follow NIST post-quantum standards. No custom cryptography.

Found a vulnerability? Please **do not open a public issue**. See [SECURITY.md](SECURITY.md) (coming).

---

## Contributing

QShield is pre-alpha. The project is not yet accepting external contributions while the foundational implementation is in progress.

Once the core library (QS-101 through QS-114) is stable, contribution guidelines will be published.

---

## License

Copyright 2026 Asman Mirza.

Licensed under the [Apache License, Version 2.0](LICENSE).

You may use, distribute, and modify this software under the terms of the Apache 2.0 license. See [LICENSE](LICENSE) for the full text.

Commercial add-ons (QShield Vault Pro, QShield Auth SaaS, QShield Enterprise) are subject to separate commercial licensing terms.
