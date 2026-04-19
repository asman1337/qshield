# Contributing to QShield

Thank you for your interest in contributing. QShield Core — the cryptography library — is open for community contributions. This document explains how to get started.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [What We Accept](#what-we-accept)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Security Contributions](#security-contributions)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Good First Issues](#good-first-issues)

---

## Code of Conduct

Be respectful. Harassment, discrimination, or hostile behaviour of any kind will not be tolerated. We follow the [Contributor Covenant v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

---

## What We Accept

| Area | Status |
|------|--------|
| `crates/qshield-core` — bug fixes | ✅ Open |
| `crates/qshield-core` — new features (discussed first) | ✅ Open |
| `bindings/node`, `bindings/python` — bug fixes | ✅ Open |
| `bindings/node`, `bindings/python` — new exposed APIs | ✅ Open (discuss first) |
| `crates/qshield-proxy`, `crates/qshield-vault-api`, `crates/qshield-auth` | 🟡 Phase 2, discuss first |
| `docs/specs/` — clarifications and corrections | ✅ Open |
| New algorithms not in the spec | ❌ Open an issue first |
| Dependencies that are not actively audited | ❌ Unlikely to accept |

If your change is large or architecturally significant, **open an issue before writing code**. This avoids wasted effort if the direction doesn't fit the roadmap.

---

## Getting Started

### Prerequisites

- **Rust** ≥ 1.85 (the workspace uses the 2024 edition — `rustup update stable` is sufficient)
- **Node.js** ≥ 20 + **pnpm** ≥ 9 (only needed if working on Node.js bindings)
- **Python** ≥ 3.9 + **maturin** (only needed if working on Python bindings)
- **just** — task runner (`cargo install just`)
- **cargo-deny** — license and advisory checks (`cargo install cargo-deny`)

### Fork and clone

```bash
git clone https://github.com/asman1337/qshield.git
cd qshield
```

### Build everything

```bash
just build        # builds all Rust crates
just test         # runs all tests
just lint         # clippy + rustfmt check
```

Or directly with Cargo:

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --check
```

---

## Development Workflow

1. Create a branch from `main`:
   ```bash
   git checkout -b feat/your-feature-name
   # or
   git checkout -b fix/issue-123
   ```

2. Make your changes. Keep commits focused — one logical change per commit.

3. Run the full test suite:
   ```bash
   cargo test -p qshield-core
   ```

4. Run clippy with no warnings allowed:
   ```bash
   cargo clippy -p qshield-core -- -D warnings
   ```

5. Format your code:
   ```bash
   cargo fmt
   ```

6. Run benchmarks if you changed any hot path (to confirm no regression):
   ```bash
   cargo bench -p qshield-core
   ```

7. Push and open a PR.

---

## Coding Standards

### Rust

- Follow `rustfmt` defaults (enforced by CI). Run `cargo fmt` before committing.
- No clippy warnings. CI runs `cargo clippy -- -D warnings`.
- **No `unsafe` code** in `qshield-core` without a detailed safety comment and maintainer approval. The goal is a safe-Rust crypto library.
- **No custom cryptography.** Use the vetted upstream crates (`ml-kem`, `ml-dsa`, `aes-gcm`, `chacha20poly1305`, etc.). If you need a new primitive, justify the crate choice in the PR.
- All secrets (`SecretKey`, `SharedSecret`, etc.) must implement `ZeroizeOnDrop`. Use the `zeroize` crate.
- Prefer `Result<T, QShieldError>` over panicking. The library must not panic on malformed external input.
- Use `OsRng` for key generation. Never use `thread_rng()` or user-seeded RNGs for real key material.

### Commit messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(core): add SLH-DSA keygen support
fix(kem): return Err on malformed ciphertext instead of panicking
docs(contributing): add Python binding setup instructions
bench(dsa): fix stack overflow on Windows by spawning with 64 MB stack
```

Allowed types: `feat`, `fix`, `docs`, `bench`, `test`, `refactor`, `chore`, `ci`.

Scope is the crate or area: `core`, `node`, `python`, `wasm`, `proxy`, `vault`, `auth`, `ci`, `deps`.

---

## Testing Requirements

Every PR that changes `qshield-core` must include or update tests.

- **Unit tests** live in the same file as the code (`#[cfg(test)]` at the bottom of each module).
- **Integration tests** live in `tests/`.
- Test names must be descriptive: `round_trip_kem768`, `tampered_ciphertext_returns_err`, not `test1`.
- All tests must pass: `cargo test -p qshield-core`.
- Tests must not be flaky. Benchmarks and timing-dependent tests belong in `benches/`, not `tests/`.

### NIST Known Answer Tests (KAT)

If you're adding or modifying a NIST algorithm implementation, KAT test vectors are required. The NIST FIPS 203/204/205 documents contain the test vectors. Add them to the relevant `src/*.rs` test section.

---

## Security Contributions

If your contribution touches cryptographic logic, key handling, or serialization:

- Read the threat model in `SECURITY.md` before writing code.
- Ensure secrets are **never logged**, even at TRACE level.
- Ensure all secret types zeroize on drop.
- Constant-time comparisons must use `subtle::ConstantTimeEq`, never `==` on secret byte arrays.
- If you find a security vulnerability while contributing, **stop and report it privately** via `security@qshield.dev` before disclosing anything in the PR.

---

## Submitting a Pull Request

1. **Title:** Use Conventional Commits format (see above).
2. **Description:** Explain *what* changed and *why*. Link related issues with `Closes #123`.
3. **Tests:** All new code has tests. All existing tests pass.
4. **Checklist** (add this to your PR body):

```
- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace -- -D warnings` passes
- [ ] `cargo fmt --check` passes
- [ ] No new `unsafe` blocks without safety comments
- [ ] New secret types implement `ZeroizeOnDrop`
- [ ] CHANGELOG or spec updated if this changes public API
```

5. CI must be green before merge.
6. At least one maintainer review is required.

---

## Good First Issues

These are well-scoped tasks that don't require deep cryptography knowledge:

| Issue | Description | Difficulty |
|-------|-------------|------------|
| QS-115 | CI benchmark regression detection — alert if any bench regresses >10% | Easy |
| QS-101/102 | Add NIST KAT vectors for ML-KEM and ML-DSA to the test suite | Medium |
| QS-105 | SLH-DSA (SPHINCS+) implementation using an audited crate | Medium |
| QS-117 | WASM build target (`wasm-pack build`) for browser integration | Medium |
| QS-111 | Go bindings via CGo FFI | Hard |
| QS-106 | HPKE (RFC 9180) implementation with Kyber KEM | Hard |

Search [open issues](https://github.com/asman1337/qshield/issues) for the `good first issue` label.

---

## Questions?

Open a [GitHub Discussion](https://github.com/asman1337/qshield/discussions) or reach out via email at `dev@qshield.dev`.
