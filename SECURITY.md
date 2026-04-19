# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please email us at: **security@qshield.dev**

For sensitive reports, encrypt your message with our PGP key (see below).

We commit to:
- **48 hours** — acknowledgment of your report
- **7 days** — initial assessment and severity classification
- **90 days** — coordinated disclosure window (we will work with you on timing)

If you believe the issue is being mishandled, you may disclose after 90 days.

---

## PGP Key

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
(Key to be added upon project public launch)
-----END PGP PUBLIC KEY BLOCK-----
```

Key fingerprint: `(To be generated)`

---

## Scope

The following are **in scope**:

| Component | Crate / Path |
|-----------|--------------|
| Crypto primitives | `crates/qshield-core/` |
| Vault API | `crates/qshield-vault-api/` |
| Auth service | `crates/qshield-auth/` |
| TLS Proxy | `crates/qshield-proxy/` |
| Browser Extension | `apps/vault-extension/` |
| Desktop App | `apps/vault-desktop/` |

The following are **out of scope** for bounty consideration:
- Issues in third-party dependencies (report those upstream)
- Theoretical vulnerabilities without a proof of concept
- Issues already known and tracked in the issue tracker

---

## Severity Classification

We use CVSS 3.1 scores as a baseline, adjusted for cryptographic impact:

| Severity | CVSS Range | Examples |
|----------|------------|---------|
| Critical | 9.0–10.0 | Key material leakage, decryption oracle, signature forgery |
| High | 7.0–8.9 | Authentication bypass, privilege escalation |
| Medium | 4.0–6.9 | Information disclosure, DoS |
| Low | 0.1–3.9 | Minor information leak, low-impact behavior |

---

## Pre-Release Security Checklist

Before any `vX.Y.Z` release tag is pushed, the following must pass:

- [ ] `cargo audit` — zero known CVEs in dependency tree
- [ ] `cargo deny check` — license compliance, no banned crates
- [ ] NIST KAT vectors pass for ML-KEM-512/768/1024 and ML-DSA-44/65/87
- [ ] No `unsafe` blocks without `// SAFETY:` justification comment
- [ ] All public API inputs validated at entry points
- [ ] Fuzzing targets run for minimum 60 seconds each on CI
- [ ] Dependency tree reviewed — no new transitive deps without approval
- [ ] `#![forbid(unsafe_code)]` present in all non-core crates
- [ ] No secrets, keys, or tokens in committed files (`git secrets` scan)
- [ ] Docker images built and scanned with Trivy (0 critical CVEs)

---

## Unsafe Code Policy

- `crates/qshield-core/` **MAY** use `unsafe` for FFI boundaries and
  performance-critical constant-time operations. Every `unsafe` block
  **MUST** have a `// SAFETY:` comment explaining the invariant upheld.
- All other crates use `#![forbid(unsafe_code)]` with no exceptions.
- Reviewers must explicitly approve any new `unsafe` blocks.

---

## Fuzzing

Fuzzing targets live in `fuzz/` (to be populated per QS-007):

| Target | What it tests |
|--------|--------------|
| `fuzz_kem_decapsulate` | Malformed/corrupted KEM ciphertexts |
| `fuzz_dsa_verify` | Malformed signature bytes |
| `fuzz_vault_decrypt` | Corrupted vault blobs |
| `fuzz_tls_handshake` | Malformed TLS ClientHello (proxy) |
| `fuzz_key_deserialize` | Malformed key byte sequences |

Run locally: `cargo fuzz run fuzz_kem_decapsulate -- -max_total_time=60`

---

## Hall of Fame

Researchers who responsibly disclose valid security issues will be credited here
(with their permission):

*No entries yet — be the first!*

---

## Contact

- **Security email:** security@qshield.dev
- **General issues:** https://github.com/asman1337/qshield/issues
- **Project:** https://github.com/asman1337/qshield

---

*This policy follows the [coordinated vulnerability disclosure](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html) model.*
