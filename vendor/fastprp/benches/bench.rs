use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use fastprp::FastPrp;

fn bench_modes(c: &mut Criterion) {
    let key = [0x42u8; 16];

    let mut group = c.benchmark_group("permute_modes");

    for log_n in [21u32, 23, 27] {
        let n = 1u64 << log_n;
        let prp = FastPrp::new(&key, n);

        group.bench_function(BenchmarkId::new("1x", format!("2^{log_n}")), |b| {
            let mut x = 0u64;
            b.iter(|| {
                let r = prp.permute(black_box(x % n));
                x = x.wrapping_add(1);
                r
            });
        });

        group.bench_function(BenchmarkId::new("4x_total", format!("2^{log_n}")), |b| {
            let mut x = 0u64;
            b.iter(|| {
                let inputs = [x % n, (x + 1) % n, (x + 2) % n, (x + 3) % n];
                let r = prp.permute_4(black_box(inputs));
                x = x.wrapping_add(4);
                r
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_modes);
criterion_main!(benches);
