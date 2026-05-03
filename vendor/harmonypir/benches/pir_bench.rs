//! Benchmarks for HarmonyPIR components.
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use harmonypir::prp::alf::AlfPrp;
use harmonypir::prp::fast::FastPrpWrapper;
use harmonypir::prp::ff1::Ff1Prp;
use harmonypir::prp::hoang::HoangPrp;
use harmonypir::prp::{BatchPrp, Prp};

/// Benchmark Hoang PRP forward evaluation at domain 2N = 2^28.
///
/// Parameters:
///   N  = 2^27 = 134,217,728
///   2N = 2^28 = 268,435,456
///   r  = ceil(log2(2^28)) + 40 = 68  (multiple of 4, no rounding needed)
///   Phases = 68/4 = 17 AES calls per evaluation
fn bench_hoang_prp_forward(c: &mut Criterion) {
    let n: usize = 1 << 27;
    let domain = 2 * n; // 2^28
    let log_domain = (domain as f64).log2().ceil() as usize; // 28
    let r_raw = log_domain + 40; // 68
    let beta = 4;
    let r = ((r_raw + beta - 1) / beta) * beta; // 68

    let key = [0x42u8; 16];
    let prp = HoangPrp::new(domain, r, &key);

    println!("Hoang PRP — Domain: {domain}, r: {r}, phases: {}", r / beta);

    let mut group = c.benchmark_group("hoang_prp");

    // Benchmark single forward evaluation (Criterion will run many iterations)
    group.bench_function(BenchmarkId::new("forward", domain), |b| {
        let mut x: usize = 0;
        b.iter(|| {
            let result = prp.forward(x);
            x = (x + 1) % domain;
            criterion::black_box(result)
        });
    });

    // Benchmark single inverse evaluation
    group.bench_function(BenchmarkId::new("inverse", domain), |b| {
        let mut x: usize = 0;
        b.iter(|| {
            let result = prp.inverse(x);
            x = (x + 1) % domain;
            criterion::black_box(result)
        });
    });

    // Benchmark batch of 1000 forward evaluations (amortizes overhead)
    group.bench_function(BenchmarkId::new("forward_batch_1000", domain), |b| {
        b.iter(|| {
            let mut sum = 0usize;
            for i in 0..1000 {
                sum = sum.wrapping_add(prp.forward(i));
            }
            criterion::black_box(sum)
        });
    });

    group.finish();
}

/// Quick timing test: forward PRP on a smaller sample to extrapolate full-domain time.
fn bench_hoang_prp_extrapolate(c: &mut Criterion) {
    let n: usize = 1 << 27;
    let domain = 2 * n;
    let r = 68;
    let key = [0x42u8; 16];
    let prp = HoangPrp::new(domain, r, &key);

    let sample_size = 10_000;

    let mut group = c.benchmark_group("hoang_prp_extrapolate");
    group.sample_size(20); // fewer samples since each iteration does 10K evals

    group.bench_function(BenchmarkId::new("forward_10k", domain), |b| {
        b.iter(|| {
            let mut sum = 0usize;
            for i in 0..sample_size {
                sum = sum.wrapping_add(prp.forward(i));
            }
            criterion::black_box(sum)
        });
    });

    group.finish();
}

/// Benchmark FF1 PRP (HarmonyPIR1) at domain 2N = 2^28.
///
/// FF1 uses radix-2 BinaryNumeralString with cycle-walking.
/// Domain 2^28 = 268,435,456 ≥ 10^6 (FF1 minimum).
/// Since 2^28 is a power of 2, cycle-walking should rarely trigger
/// (BNS domain = 2^(4*8) = 2^32 for 4 bytes, so ~6.25% cycle-walk overhead).
fn bench_ff1_prp(c: &mut Criterion) {
    let n: usize = 1 << 27;
    let domain = 2 * n; // 2^28

    let key = [0x42u8; 16];
    let prp = Ff1Prp::new(domain, &key);

    let num_bits = usize::BITS - (domain - 1).leading_zeros();
    let num_bytes = ((num_bits as usize + 7) / 8).max(1);
    let bns_domain = 1usize << (num_bytes * 8);
    let cycle_walk_overhead = bns_domain as f64 / domain as f64;

    println!(
        "FF1 PRP — Domain: {domain}, num_bytes: {num_bytes}, BNS domain: {bns_domain}, \
         cycle-walk overhead: {cycle_walk_overhead:.3}x"
    );

    let mut group = c.benchmark_group("ff1_prp");

    // Single forward
    group.bench_function(BenchmarkId::new("forward", domain), |b| {
        let mut x: usize = 0;
        b.iter(|| {
            let result = prp.forward(x);
            x = (x + 1) % domain;
            criterion::black_box(result)
        });
    });

    // Single inverse
    group.bench_function(BenchmarkId::new("inverse", domain), |b| {
        let mut x: usize = 0;
        b.iter(|| {
            let result = prp.inverse(x);
            x = (x + 1) % domain;
            criterion::black_box(result)
        });
    });

    // Batch 1000 forward
    group.bench_function(BenchmarkId::new("forward_batch_1000", domain), |b| {
        b.iter(|| {
            let mut sum = 0usize;
            for i in 0..1000 {
                sum = sum.wrapping_add(prp.forward(i));
            }
            criterion::black_box(sum)
        });
    });

    group.finish();
}

/// Benchmark FF1 at a more Bitcoin-realistic domain: 2N = 6,000,000 (data PBC group).
fn bench_ff1_prp_bitcoin(c: &mut Criterion) {
    let domain = 6_000_000usize; // ~2 × 3M entries per data-level PBC group

    let key = [0x42u8; 16];
    let prp = Ff1Prp::new(domain, &key);

    let num_bits = usize::BITS - (domain - 1).leading_zeros();
    let num_bytes = ((num_bits as usize + 7) / 8).max(1);
    let bns_domain = 1usize << (num_bytes * 8);
    let cycle_walk_overhead = bns_domain as f64 / domain as f64;

    println!(
        "FF1 PRP (Bitcoin) — Domain: {domain}, num_bytes: {num_bytes}, BNS domain: {bns_domain}, \
         cycle-walk overhead: {cycle_walk_overhead:.3}x"
    );

    let mut group = c.benchmark_group("ff1_prp_bitcoin");

    group.bench_function(BenchmarkId::new("forward", domain), |b| {
        let mut x: usize = 0;
        b.iter(|| {
            let result = prp.forward(x);
            x = (x + 1) % domain;
            criterion::black_box(result)
        });
    });

    group.bench_function(BenchmarkId::new("inverse", domain), |b| {
        let mut x: usize = 0;
        b.iter(|| {
            let result = prp.inverse(x);
            x = (x + 1) % domain;
            criterion::black_box(result)
        });
    });

    group.finish();
}

/// Benchmark FastPRP at Bitcoin-realistic domain: 2N = 6,000,000.
fn bench_fastprp_bitcoin(c: &mut Criterion) {
    let domain = 6_000_000usize;
    let key = [0x42u8; 16];

    println!("FastPRP — Domain: {domain}, building cache...");
    let prp = FastPrpWrapper::new(&key, domain);
    println!(
        "FastPRP — Cache built. Stride: {}, cache size: {} KB",
        prp.batch_permute_raw().len(), // just to warm up
        0 // placeholder; cache size is internal
    );

    let mut group = c.benchmark_group("fastprp_bitcoin");

    group.bench_function(BenchmarkId::new("forward", domain), |b| {
        let mut x: usize = 0;
        b.iter(|| {
            let result = prp.forward(x);
            x = (x + 1) % domain;
            criterion::black_box(result)
        });
    });

    group.bench_function(BenchmarkId::new("inverse", domain), |b| {
        let mut x: usize = 0;
        b.iter(|| {
            let result = prp.inverse(x);
            x = (x + 1) % domain;
            criterion::black_box(result)
        });
    });

    group.finish();
}

/// Benchmark FastPRP batch_permute (full domain table generation).
fn bench_fastprp_batch(c: &mut Criterion) {
    let domain = 1_000_000usize; // 1M for reasonable bench time
    let key = [0x42u8; 16];
    let prp = FastPrpWrapper::new(&key, domain);

    let mut group = c.benchmark_group("fastprp_batch");
    group.sample_size(10);

    group.bench_function(BenchmarkId::new("batch_forward", domain), |b| {
        b.iter(|| criterion::black_box(prp.batch_forward()));
    });

    group.finish();
}

/// Benchmark ALF PRP at Bitcoin-realistic domain: 2N = 6,000,000.
fn bench_alf_prp_bitcoin(c: &mut Criterion) {
    let domain = 6_000_000usize;
    let key = [0x42u8; 16];
    let tweak = [0u8; 16];
    let prp = AlfPrp::new(&key, domain, &tweak, 0);

    let mut group = c.benchmark_group("alf_prp_bitcoin");

    group.bench_function(BenchmarkId::new("forward", domain), |b| {
        let mut x: usize = 0;
        b.iter(|| {
            let result = prp.forward(x);
            x = (x + 1) % domain;
            criterion::black_box(result)
        });
    });

    group.bench_function(BenchmarkId::new("inverse", domain), |b| {
        let mut x: usize = 0;
        b.iter(|| {
            let result = prp.inverse(x);
            x = (x + 1) % domain;
            criterion::black_box(result)
        });
    });

    // Batch 1000 forward
    group.bench_function(BenchmarkId::new("forward_batch_1000", domain), |b| {
        b.iter(|| {
            let mut sum = 0usize;
            for i in 0..1000 {
                sum = sum.wrapping_add(prp.forward(i));
            }
            criterion::black_box(sum)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_hoang_prp_forward,
    bench_hoang_prp_extrapolate,
    bench_ff1_prp,
    bench_ff1_prp_bitcoin,
    bench_fastprp_bitcoin,
    bench_fastprp_batch,
    bench_alf_prp_bitcoin
);
criterion_main!(benches);
