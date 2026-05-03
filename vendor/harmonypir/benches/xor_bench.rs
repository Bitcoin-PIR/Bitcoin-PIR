//! Microbenchmark for `xor_bytes_into` at sizes that match the BitcoinPIR hot path.
//!
//! - 168 B / 352 B mirror the INDEX / CHUNK row sizes (bucket=4).
//! - 256 B / 4096 B are round buffer sizes for cross-comparison.
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use harmonypir::util::xor_bytes_into;

/// Reference: original byte-at-a-time implementation, kept here for A/B numbers.
#[inline(never)]
fn xor_bytes_into_scalar(dst: &mut [u8], src: &[u8]) {
    assert_eq!(dst.len(), src.len());
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

fn bench_xor_bytes_into(c: &mut Criterion) {
    let mut group = c.benchmark_group("xor_bytes_into");
    for &n in &[168usize, 256, 352, 4096] {
        let src: Vec<u8> = (0..n).map(|i| (i as u8).wrapping_mul(31)).collect();
        let mut dst: Vec<u8> = (0..n).map(|i| (i as u8).wrapping_mul(17)).collect();
        group.throughput(Throughput::Bytes(n as u64));
        group.bench_function(BenchmarkId::new("chunked", n), |b| {
            b.iter(|| {
                xor_bytes_into(black_box(&mut dst), black_box(&src));
            });
        });
        group.bench_function(BenchmarkId::new("scalar", n), |b| {
            b.iter(|| {
                xor_bytes_into_scalar(black_box(&mut dst), black_box(&src));
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_xor_bytes_into);
criterion_main!(benches);
