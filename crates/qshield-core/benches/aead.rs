// AEAD benchmarks (QS-115)
//
// Measures AES-256-GCM and ChaCha20-Poly1305 encrypt/decrypt throughput at
// four payload sizes: 64 B, 1 KB, 1 MB, and 100 MB.
//
// Throughput (GB/s) is reported alongside latency so results can be compared
// directly to hardware AES-NI / ChaCha20 software baselines.
//
// Note: the same key/nonce pair is reused across iterations for benchmark
// repeatability.  This is intentional and safe for a benchmark only.

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use qshield_core::{
    aes256gcm_decrypt, aes256gcm_encrypt, chacha20poly1305_decrypt, chacha20poly1305_encrypt,
};

const KEY: &[u8; 32] = b"bench_key_____32_bytes__________";
const NONCE: &[u8; 12] = b"bench_nonce!";

const SIZES: [(usize, &str); 4] = [
    (64, "64B"),
    (1_024, "1KB"),
    (1_024 * 1_024, "1MB"),
    (100 * 1_024 * 1_024, "100MB"),
];

// ── AES-256-GCM ──────────────────────────────────────────────────────────────

fn bench_aes256gcm_encrypt(c: &mut Criterion) {
    let mut g = c.benchmark_group("aes256gcm_encrypt");

    for (size, label) in SIZES {
        g.throughput(Throughput::Bytes(size as u64));
        let plaintext = vec![0xab_u8; size];
        g.bench_with_input(
            BenchmarkId::new("AES-256-GCM", label),
            &plaintext,
            |b, pt| {
                b.iter(|| {
                    aes256gcm_encrypt(black_box(KEY), black_box(NONCE), black_box(pt), b"").unwrap()
                })
            },
        );
    }

    g.finish();
}

fn bench_aes256gcm_decrypt(c: &mut Criterion) {
    let mut g = c.benchmark_group("aes256gcm_decrypt");

    for (size, label) in SIZES {
        g.throughput(Throughput::Bytes(size as u64));
        let plaintext = vec![0xab_u8; size];
        let ciphertext = aes256gcm_encrypt(KEY, NONCE, &plaintext, b"").unwrap();
        g.bench_with_input(
            BenchmarkId::new("AES-256-GCM", label),
            &ciphertext,
            |b, ct| {
                b.iter(|| {
                    aes256gcm_decrypt(black_box(KEY), black_box(NONCE), black_box(ct), b"").unwrap()
                })
            },
        );
    }

    g.finish();
}

// ── ChaCha20-Poly1305 ─────────────────────────────────────────────────────────

fn bench_chacha20_encrypt(c: &mut Criterion) {
    let mut g = c.benchmark_group("chacha20poly1305_encrypt");

    for (size, label) in SIZES {
        g.throughput(Throughput::Bytes(size as u64));
        let plaintext = vec![0xab_u8; size];
        g.bench_with_input(
            BenchmarkId::new("ChaCha20-Poly1305", label),
            &plaintext,
            |b, pt| {
                b.iter(|| {
                    chacha20poly1305_encrypt(black_box(KEY), black_box(NONCE), black_box(pt), b"")
                        .unwrap()
                })
            },
        );
    }

    g.finish();
}

fn bench_chacha20_decrypt(c: &mut Criterion) {
    let mut g = c.benchmark_group("chacha20poly1305_decrypt");

    for (size, label) in SIZES {
        g.throughput(Throughput::Bytes(size as u64));
        let plaintext = vec![0xab_u8; size];
        let ciphertext = chacha20poly1305_encrypt(KEY, NONCE, &plaintext, b"").unwrap();
        g.bench_with_input(
            BenchmarkId::new("ChaCha20-Poly1305", label),
            &ciphertext,
            |b, ct| {
                b.iter(|| {
                    chacha20poly1305_decrypt(black_box(KEY), black_box(NONCE), black_box(ct), b"")
                        .unwrap()
                })
            },
        );
    }

    g.finish();
}

criterion_group!(
    aead_benches,
    bench_aes256gcm_encrypt,
    bench_aes256gcm_decrypt,
    bench_chacha20_encrypt,
    bench_chacha20_decrypt
);
criterion_main!(aead_benches);
