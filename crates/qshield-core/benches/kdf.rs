// KDF benchmarks (QS-115)
//
// Measures HKDF-SHA3-256 key derivation at two output lengths: 32 B and 256 B.

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use qshield_core::hkdf_sha3_256;

const IKM: &[u8] = b"bench_input_key_material_32bytes";
const SALT: &[u8] = b"bench_salt_32_bytes_for_hkdf____";
const INFO: &[u8] = b"qshield benchmark context";

fn bench_hkdf_sha3_256(c: &mut Criterion) {
    let mut g = c.benchmark_group("hkdf_sha3_256");

    for (output_len, label) in [(32_usize, "32B"), (256_usize, "256B")] {
        g.bench_with_input(
            BenchmarkId::new("HKDF-SHA3-256", label),
            &output_len,
            |b, &len| {
                b.iter(|| {
                    hkdf_sha3_256(
                        black_box(IKM),
                        Some(black_box(SALT)),
                        black_box(INFO),
                        black_box(len),
                    )
                    .unwrap()
                })
            },
        );
    }

    g.finish();
}

criterion_group!(kdf_benches, bench_hkdf_sha3_256);
criterion_main!(kdf_benches);
