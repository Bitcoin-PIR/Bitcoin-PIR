//! Native parallel benchmark: simulates a full address lookup (75 INDEX + 80 CHUNK buckets)
//! with 1, 2, 4, 8, 16 threads using rayon.

use harmonypir::prp::alf::AlfPrp;
use harmonypir::prp::fast::FastPrpWrapper;
use harmonypir::prp::hoang::HoangPrp;
use harmonypir::prp::Prp;
use rayon::prelude::*;
use std::time::Instant;

const INDEX_DOMAIN: usize = 1 << 21; // 2^21
const CHUNK_DOMAIN: usize = 1 << 22; // 2^22
const INDEX_T: usize = 1024;
const CHUNK_T: usize = 2048;
const INDEX_N: usize = 75;
const CHUNK_N: usize = 80;
const HOANG_ROUNDS: usize = 64;

/// Simulate one HarmonyPIR online query on one bucket: T forward + T inverse.
fn query_bucket(prp: &dyn Prp, t: usize) -> usize {
    let domain = prp.domain();
    let mut sum: usize = 0;
    for i in 0..t {
        sum = sum.wrapping_add(prp.forward(i % domain));
    }
    for i in 0..t {
        sum = sum.wrapping_add(prp.inverse(i % domain));
    }
    sum
}

fn bench_hoang(threads: usize) -> f64 {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .unwrap();

    // Pre-build all PRPs
    let index_prps: Vec<HoangPrp> = (0..INDEX_N)
        .map(|b| {
            let mut key = [0x42u8; 16];
            key[0] = (b & 0xFF) as u8;
            HoangPrp::new(INDEX_DOMAIN, HOANG_ROUNDS, &key)
        })
        .collect();
    let chunk_prps: Vec<HoangPrp> = (0..CHUNK_N)
        .map(|b| {
            let mut key = [0x42u8; 16];
            key[0] = (b & 0xFF) as u8;
            key[1] = 1;
            HoangPrp::new(CHUNK_DOMAIN, HOANG_ROUNDS, &key)
        })
        .collect();

    let start = Instant::now();
    pool.install(|| {
        let s1: usize = index_prps.par_iter().map(|p| query_bucket(p, INDEX_T)).sum();
        let s2: usize = chunk_prps.par_iter().map(|p| query_bucket(p, CHUNK_T)).sum();
        std::hint::black_box(s1.wrapping_add(s2));
    });
    start.elapsed().as_secs_f64() * 1000.0
}

fn bench_alf(threads: usize) -> f64 {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .unwrap();

    let key = [0x42u8; 16];
    let index_prps: Vec<AlfPrp> = (0..INDEX_N)
        .map(|b| {
            let mut tweak = [0u8; 16];
            tweak[..8].copy_from_slice(&(b as u64).to_le_bytes());
            AlfPrp::new(&key, INDEX_DOMAIN, &tweak, 0)
        })
        .collect();
    let chunk_prps: Vec<AlfPrp> = (0..CHUNK_N)
        .map(|b| {
            let mut tweak = [0u8; 16];
            tweak[..8].copy_from_slice(&((b + 1000) as u64).to_le_bytes());
            AlfPrp::new(&key, CHUNK_DOMAIN, &tweak, 0)
        })
        .collect();

    let start = Instant::now();
    pool.install(|| {
        let s1: usize = index_prps.par_iter().map(|p| query_bucket(p, INDEX_T)).sum();
        let s2: usize = chunk_prps.par_iter().map(|p| query_bucket(p, CHUNK_T)).sum();
        std::hint::black_box(s1.wrapping_add(s2));
    });
    start.elapsed().as_secs_f64() * 1000.0
}

fn bench_fastprp(threads: usize) -> (f64, f64) {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .unwrap();

    // Build phase (includes cache construction)
    let build_start = Instant::now();
    let (index_prps, chunk_prps) = pool.install(|| {
        let idx: Vec<FastPrpWrapper> = (0..INDEX_N)
            .into_par_iter()
            .map(|b| {
                let mut key = [0x42u8; 16];
                key[0] = (b & 0xFF) as u8;
                FastPrpWrapper::new(&key, INDEX_DOMAIN)
            })
            .collect();
        let chk: Vec<FastPrpWrapper> = (0..CHUNK_N)
            .into_par_iter()
            .map(|b| {
                let mut key = [0x42u8; 16];
                key[0] = (b & 0xFF) as u8;
                key[1] = 1;
                FastPrpWrapper::new(&key, CHUNK_DOMAIN)
            })
            .collect();
        (idx, chk)
    });
    let build_ms = build_start.elapsed().as_secs_f64() * 1000.0;

    // Query phase
    let start = Instant::now();
    pool.install(|| {
        let s1: usize = index_prps.par_iter().map(|p| query_bucket(p, INDEX_T)).sum();
        let s2: usize = chunk_prps.par_iter().map(|p| query_bucket(p, CHUNK_T)).sum();
        std::hint::black_box(s1.wrapping_add(s2));
    });
    let query_ms = start.elapsed().as_secs_f64() * 1000.0;

    (build_ms, query_ms)
}

fn main() {
    println!("Native parallel benchmark: 75 INDEX + 80 CHUNK buckets (1-chunk address lookup)");
    println!("INDEX: domain=2^21, T=1024 (2048 PRP calls/bucket)");
    println!("CHUNK: domain=2^22, T=2048 (4096 PRP calls/bucket)");
    println!();

    let thread_counts = [1, 2, 4, 8, 16];

    // Hoang
    println!("=== Hoang PRP ===");
    println!("{:>8} {:>10} {:>10}", "threads", "ms", "speedup");
    let hoang_base = bench_hoang(1);
    for &t in &thread_counts {
        let ms = bench_hoang(t);
        println!("{:>8} {:>10.0} {:>10.1}x", t, ms, hoang_base / ms);
    }
    println!();

    // ALF
    println!("=== ALF PRP ===");
    println!("{:>8} {:>10} {:>10}", "threads", "ms", "speedup");
    let alf_base = bench_alf(1);
    for &t in &thread_counts {
        let ms = bench_alf(t);
        println!("{:>8} {:>10.0} {:>10.1}x", t, ms, alf_base / ms);
    }
    println!();

    // FastPRP
    println!("=== FastPRP ===");
    println!("{:>8} {:>10} {:>10} {:>10}", "threads", "build ms", "query ms", "speedup");
    let (_, fp_base_q) = bench_fastprp(1);
    for &t in &thread_counts {
        let (build, query) = bench_fastprp(t);
        println!(
            "{:>8} {:>10.0} {:>10.0} {:>10.1}x",
            t, build, query, fp_base_q / query
        );
    }
    println!();

    // Summary
    println!("=== Summary (query only, best parallel) ===");
    let hoang_best = bench_hoang(16);
    let alf_best = bench_alf(16);
    let (_, fp_best) = bench_fastprp(16);
    println!("ALF    16t: {:.0} ms", alf_best);
    println!("Hoang  16t: {:.0} ms", hoang_best);
    println!("FastPRP 16t: {:.0} ms (query only)", fp_best);
}
