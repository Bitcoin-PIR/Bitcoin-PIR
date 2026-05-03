//! Benchmarks for DPF operations

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use libdpf::{Dpf, Block};

fn bench_gen(c: &mut Criterion) {
    let dpf = Dpf::with_default_key();
    
    let mut group = c.benchmark_group("gen");
    
    for n in [12u8, 16, 20, 24].iter() {
        group.bench_with_input(BenchmarkId::new("n", n), n, |b, &n| {
            let alpha = (1u64 << (n - 1)) + 123;
            b.iter(|| {
                dpf.gen(black_box(alpha), black_box(n))
            });
        });
    }
    
    group.finish();
}

fn bench_eval(c: &mut Criterion) {
    let dpf = Dpf::with_default_key();
    
    let mut group = c.benchmark_group("eval");
    
    for n in [12u8, 16, 20, 24].iter() {
        let alpha = (1u64 << (n - 1)) + 123;
        let (k0, _) = dpf.gen(alpha, *n);
        
        group.bench_with_input(BenchmarkId::new("n", n), n, |b, _| {
            b.iter(|| {
                dpf.eval(black_box(&k0), black_box(alpha))
            });
        });
    }
    
    group.finish();
}

fn bench_eval_full(c: &mut Criterion) {
    let dpf = Dpf::with_default_key();
    
    let mut group = c.benchmark_group("eval_full");
    
    for n in [12u8, 16, 20].iter() {
        let alpha = (1u64 << (n - 1)) + 123;
        let (k0, _) = dpf.gen(alpha, *n);
        
        group.bench_with_input(BenchmarkId::new("n", n), n, |b, _| {
            b.iter(|| {
                dpf.eval_full(black_box(&k0))
            });
        });
    }
    
    group.finish();
}

fn bench_eval_partial(c: &mut Criterion) {
    let dpf = Dpf::with_default_key();

    let mut group = c.benchmark_group("eval_partial");

    // For n=16 (domain 2^16 = 65536), benchmark partial at various fractions
    let n: u8 = 16;
    let alpha = (1u64 << (n - 1)) + 123;
    let (k0, _) = dpf.gen(alpha, n);

    for num_points in [128u64, 1024, 4096, 16384, 32768, 65536] {
        group.bench_with_input(
            BenchmarkId::new("n16", num_points),
            &num_points,
            |b, &np| {
                b.iter(|| {
                    dpf.eval_partial(black_box(&k0), black_box(np))
                });
            },
        );
    }

    // For n=20, compare partial vs full
    let n: u8 = 20;
    let alpha = (1u64 << (n - 1)) + 123;
    let (k0, _) = dpf.gen(alpha, n);

    for num_points in [1024u64, 16384, 131072, 524288, 1048576] {
        group.bench_with_input(
            BenchmarkId::new("n20", num_points),
            &num_points,
            |b, &np| {
                b.iter(|| {
                    dpf.eval_partial(black_box(&k0), black_box(np))
                });
            },
        );
    }

    group.finish();
}

fn bench_block_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("block_ops");
    
    let a = Block::new(0x123456789ABCDEF0, 0xFEDCBA9876543210);
    let b = Block::new(0xABCDEF0123456789, 0x9876543210FEDCBA);
    
    group.bench_function("xor", |bencher| {
        bencher.iter(|| black_box(a.xor(&b)))
    });
    
    group.bench_function("lsb", |bencher| {
        bencher.iter(|| black_box(a.lsb()))
    });
    
    group.bench_function("left_shift_1", |bencher| {
        bencher.iter(|| black_box(a.left_shift(1)))
    });
    
    group.bench_function("left_shift_64", |bencher| {
        bencher.iter(|| black_box(a.left_shift(64)))
    });
    
    group.bench_function("set_lsb_zero", |bencher| {
        bencher.iter(|| black_box(a.set_lsb_zero()))
    });
    
    group.bench_function("to_bytes", |bencher| {
        bencher.iter(|| black_box(a.to_bytes()))
    });
    
    group.bench_function("from_bytes", |bencher| {
        let bytes = a.to_bytes();
        bencher.iter(|| black_box(Block::from_bytes(&bytes)))
    });
    
    group.finish();
}

fn bench_complete_workflow(c: &mut Criterion) {
    let dpf = Dpf::with_default_key();
    
    c.bench_function("complete_workflow_n16", |b| {
        b.iter(|| {
            let alpha: u64 = 26943;
            let n: u8 = 16;
            let (k0, k1) = dpf.gen(alpha, n);
            let r0 = dpf.eval(&k0, alpha);
            let r1 = dpf.eval(&k1, alpha);
            black_box(r0.xor(&r1))
        });
    });
}

criterion_group!(
    benches,
    bench_gen,
    bench_eval,
    bench_eval_full,
    bench_eval_partial,
    bench_block_operations,
    bench_complete_workflow,
);

criterion_main!(benches);