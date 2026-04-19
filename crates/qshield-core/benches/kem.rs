// KEM benchmarks (QS-115)
//
// Covers ML-KEM-512/768/1024 keygen, encapsulate, and decapsulate.
// X25519 classical DH is included as a performance baseline in each group.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use qshield_core::{KemLevel, kem_decapsulate, kem_encapsulate, kem_keygen};
use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public, StaticSecret};

fn bench_kem_keygen(c: &mut Criterion) {
    let mut g = c.benchmark_group("kem_keygen");

    for (label, level) in [
        ("ML-KEM-512", KemLevel::Kem512),
        ("ML-KEM-768", KemLevel::Kem768),
        ("ML-KEM-1024", KemLevel::Kem1024),
    ] {
        g.bench_function(label, |b| b.iter(|| kem_keygen(black_box(level)).unwrap()));
    }

    // Classical baseline: X25519 static keypair generation.
    g.bench_function("X25519 (baseline)", |b| {
        b.iter(|| {
            let sk = StaticSecret::random_from_rng(OsRng);
            black_box(X25519Public::from(&sk))
        })
    });

    g.finish();
}

fn bench_kem_encapsulate(c: &mut Criterion) {
    let mut g = c.benchmark_group("kem_encapsulate");

    for (label, level) in [
        ("ML-KEM-512", KemLevel::Kem512),
        ("ML-KEM-768", KemLevel::Kem768),
        ("ML-KEM-1024", KemLevel::Kem1024),
    ] {
        let kp = kem_keygen(level).unwrap();
        g.bench_function(label, |b| {
            b.iter(|| kem_encapsulate(black_box(&kp.public_key)).unwrap())
        });
    }

    // Classical baseline: ephemeral X25519 DH (sender side == "encapsulate").
    let receiver_sk = StaticSecret::random_from_rng(OsRng);
    let receiver_pk = X25519Public::from(&receiver_sk);
    g.bench_function("X25519 (baseline)", |b| {
        b.iter(|| {
            let eph = EphemeralSecret::random_from_rng(OsRng);
            let eph_pk = X25519Public::from(&eph);
            let ss = eph.diffie_hellman(black_box(&receiver_pk));
            black_box((eph_pk, ss))
        })
    });

    g.finish();
}

fn bench_kem_decapsulate(c: &mut Criterion) {
    let mut g = c.benchmark_group("kem_decapsulate");

    for (label, level) in [
        ("ML-KEM-512", KemLevel::Kem512),
        ("ML-KEM-768", KemLevel::Kem768),
        ("ML-KEM-1024", KemLevel::Kem1024),
    ] {
        let kp = kem_keygen(level).unwrap();
        let (_, ct) = kem_encapsulate(&kp.public_key).unwrap();
        g.bench_function(label, |b| {
            b.iter(|| kem_decapsulate(black_box(&kp.secret_key), black_box(&ct)).unwrap())
        });
    }

    // Classical baseline: static X25519 DH (receiver side == "decapsulate").
    let receiver_sk = StaticSecret::random_from_rng(OsRng);
    let eph_sk = EphemeralSecret::random_from_rng(OsRng);
    let eph_pk = X25519Public::from(&eph_sk);
    g.bench_function("X25519 (baseline)", |b| {
        b.iter(|| {
            let ss = receiver_sk.diffie_hellman(black_box(&eph_pk));
            black_box(ss)
        })
    });

    g.finish();
}

criterion_group!(
    kem_benches,
    bench_kem_keygen,
    bench_kem_encapsulate,
    bench_kem_decapsulate
);
criterion_main!(kem_benches);
