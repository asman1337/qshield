# QShield justfile
# Run `just --list` to see all available commands.

set shell := ["powershell", "-Command"]
set dotenv-load := true

# Default: list all targets
default:
    @just --list

# ─── Rust ────────────────────────────────────────────────────────────────────

# Check all workspace crates
check:
    cargo check --workspace

# Build all workspace crates (debug)
build:
    cargo build --workspace

# Build all workspace crates (release)
build-release:
    cargo build --workspace --release

# Run all tests
test:
    cargo test --workspace

# Run clippy (fail on warnings)
lint:
    cargo clippy --workspace -- -D warnings

# Run formatter check
fmt-check:
    cargo fmt --all -- --check

# Format all code
fmt:
    cargo fmt --all

# Run cargo audit for advisories
audit:
    cargo audit

# Run cargo deny (license + ban checks)
deny:
    cargo deny check

# ─── Frontend ────────────────────────────────────────────────────────────────

# Install all JS dependencies
js-install:
    pnpm install

# Build all frontend apps
js-build:
    pnpm -r build

# Lint all frontend apps
js-lint:
    pnpm -r lint

# TypeScript type-check all apps
js-typecheck:
    pnpm -r typecheck

# ─── Dev servers ─────────────────────────────────────────────────────────────

# Start vault-web dev server
dev-vault:
    pnpm --filter vault-web dev

# Start auth-dashboard dev server
dev-auth:
    pnpm --filter auth-dashboard dev

# ─── Docker ──────────────────────────────────────────────────────────────────

# Build a specific service Docker image (e.g. just docker-build qshield-proxy)
docker-build service:
    docker build -f deploy/docker/Dockerfile.{{service}} -t ghcr.io/asman1337/{{service}}:dev .

# ─── CI helpers ──────────────────────────────────────────────────────────────

# Full CI gate (mirrors GitHub Actions PR check)
ci: fmt-check lint test audit deny

# ─── Database ────────────────────────────────────────────────────────────────

# Run vault-api migrations
migrate-vault:
    cd crates/qshield-vault-api && sqlx migrate run

# Run auth migrations
migrate-auth:
    cd crates/qshield-auth && sqlx migrate run

# ─── Docs ────────────────────────────────────────────────────────────────────

# Build rustdoc for all public crates
doc:
    cargo doc --workspace --no-deps --open
