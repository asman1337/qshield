// DSA benchmarks (QS-115)
//
// Covers ML-DSA-44/65/87 keygen, sign (hedged), and verify.
// Ed25519 is included as a performance baseline in each group.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ed25519_dalek::{Signer, SigningKey, Verifier};
use qshield_core::{dsa_keygen, dsa_sign, dsa_verify, DsaLevel};
use rand_core::OsRng;

/// A representative 64-byte message for signature benchmarks.
const MESSAGE: &[u8] = b"QShield benchmark message -- a representative 64-byte payload!!";

fn bench_dsa_keygen(c: &mut Criterion) {
    let mut g = c.benchmark_group("dsa_keygen");

    for (label, level) in [
        ("ML-DSA-44", DsaLevel::Dsa44),
        ("ML-DSA-65", DsaLevel::Dsa65),
        ("ML-DSA-87", DsaLevel::Dsa87),
    ] {
        g.bench_function(label, |b| {
            b.iter(|| dsa_keygen(black_box(level)).unwrap())
        });
    }

    // Classical baseline: Ed25519 keypair generation.
    g.bench_function("Ed25519 (baseline)", |b| {
        b.iter(|| black_box(SigningKey::generate(&mut OsRng)))
    });

    g.finish();
}

fn bench_dsa_sign(c: &mut Criterion) {
    let mut g = c.benchmark_group("dsa_sign");

    for (label, level) in [
        ("ML-DSA-44", DsaLevel::Dsa44),
        ("ML-DSA-65", DsaLevel::Dsa65),
        ("ML-DSA-87", DsaLevel::Dsa87),
    ] {
        let kp = dsa_keygen(level).unwrap();
        g.bench_function(label, |b| {
            // hedged signing draws from OsRng each call — realistic cost.
            b.iter(|| dsa_sign(black_box(&kp), black_box(MESSAGE)).unwrap())
        });
    }

    // Classical baseline: Ed25519 sign.
    let ed_sk = SigningKey::generate(&mut OsRng);
    g.bench_function("Ed25519 (baseline)", |b| {
        b.iter(|| black_box(ed_sk.sign(black_box(MESSAGE))))
    });

    g.finish();
}

fn bench_dsa_verify(c: &mut Criterion) {
    let mut g = c.benchmark_group("dsa_verify");

    for (label, level) in [
        ("ML-DSA-44", DsaLevel::Dsa44),
        ("ML-DSA-65", DsaLevel::Dsa65),
        ("ML-DSA-87", DsaLevel::Dsa87),
    ] {
        let kp = dsa_keygen(level).unwrap();
        let vk = kp.verifying_key();
        let sig = dsa_sign(&kp, MESSAGE).unwrap();
        g.bench_function(label, |b| {
            b.iter(|| dsa_verify(black_box(&vk), black_box(MESSAGE), black_box(&sig)).unwrap())
        });
    }

    // Classical baseline: Ed25519 verify.
    let ed_sk = SigningKey::generate(&mut OsRng);
    let ed_vk = ed_sk.verifying_key();
    let ed_sig = ed_sk.sign(MESSAGE);
    g.bench_function("Ed25519 (baseline)", |b| {
        b.iter(|| black_box(ed_vk.verify(black_box(MESSAGE), black_box(&ed_sig))))
    });

    g.finish();
}

criterion_group!(dsa_benches, bench_dsa_keygen, bench_dsa_sign, bench_dsa_verify);
criterion_main!(dsa_benches);
