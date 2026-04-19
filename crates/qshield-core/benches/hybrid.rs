// Hybrid KEM benchmarks (QS-115)
//
// Covers X25519+ML-KEM-768 and X25519+ML-KEM-1024 keygen, encapsulate,
// and decapsulate.  These are the modes used in QShield's TLS proxy and
// Vault E2E encryption.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use qshield_core::{HybridMode, hybrid_decapsulate, hybrid_encapsulate, hybrid_keygen};

fn bench_hybrid_keygen(c: &mut Criterion) {
    let mut g = c.benchmark_group("hybrid_keygen");

    for (label, mode) in [
        ("X25519+ML-KEM-768", HybridMode::X25519Kyber768),
        ("X25519+ML-KEM-1024", HybridMode::X25519Kyber1024),
    ] {
        g.bench_function(label, |b| {
            b.iter(|| hybrid_keygen(black_box(mode)).unwrap())
        });
    }

    g.finish();
}

fn bench_hybrid_encapsulate(c: &mut Criterion) {
    let mut g = c.benchmark_group("hybrid_encapsulate");

    for (label, mode) in [
        ("X25519+ML-KEM-768", HybridMode::X25519Kyber768),
        ("X25519+ML-KEM-1024", HybridMode::X25519Kyber1024),
    ] {
        let kp = hybrid_keygen(mode).unwrap();
        g.bench_function(label, |b| {
            b.iter(|| hybrid_encapsulate(black_box(&kp.public_key)).unwrap())
        });
    }

    g.finish();
}

fn bench_hybrid_decapsulate(c: &mut Criterion) {
    let mut g = c.benchmark_group("hybrid_decapsulate");

    for (label, mode) in [
        ("X25519+ML-KEM-768", HybridMode::X25519Kyber768),
        ("X25519+ML-KEM-1024", HybridMode::X25519Kyber1024),
    ] {
        let kp = hybrid_keygen(mode).unwrap();
        let (_, ct) = hybrid_encapsulate(&kp.public_key).unwrap();
        g.bench_function(label, |b| {
            b.iter(|| hybrid_decapsulate(black_box(&kp.secret_key), black_box(&ct)).unwrap())
        });
    }

    g.finish();
}

criterion_group!(
    hybrid_benches,
    bench_hybrid_keygen,
    bench_hybrid_encapsulate,
    bench_hybrid_decapsulate
);
criterion_main!(hybrid_benches);
