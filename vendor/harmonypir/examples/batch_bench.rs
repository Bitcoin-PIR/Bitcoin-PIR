use harmonypir::prp::alf::AlfPrp;
use harmonypir::prp::fast::FastPrpWrapper;
use harmonypir::prp::hoang::HoangPrp;
use harmonypir::prp::Prp;
use rayon::prelude::*;
use std::time::Instant;

// 1/10 scale: 8 INDEX + 8 CHUNK buckets
const INDEX_DOMAIN: usize = 1 << 21;
const CHUNK_DOMAIN: usize = 1 << 22;
const INDEX_BUCKETS: usize = 8;
const CHUNK_BUCKETS: usize = 8;

fn batch_alf(threads: usize) -> f64 {
    let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build().unwrap();
    let key = [0x42u8; 16];
    let start = Instant::now();
    pool.install(|| {
        (0..INDEX_BUCKETS).into_par_iter().for_each(|b| {
            let mut tw = [0u8; 16]; tw[0] = b as u8;
            let prp = AlfPrp::new(&key, INDEX_DOMAIN, &tw, 0);
            let t: Vec<usize> = (0..INDEX_DOMAIN).map(|x| prp.forward(x)).collect();
            std::hint::black_box(&t);
        });
        (0..CHUNK_BUCKETS).into_par_iter().for_each(|b| {
            let mut tw = [0u8; 16]; tw[0] = (b + 100) as u8;
            let prp = AlfPrp::new(&key, CHUNK_DOMAIN, &tw, 0);
            let t: Vec<usize> = (0..CHUNK_DOMAIN).map(|x| prp.forward(x)).collect();
            std::hint::black_box(&t);
        });
    });
    start.elapsed().as_secs_f64() * 1000.0
}

fn batch_hoang(threads: usize) -> f64 {
    let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build().unwrap();
    let start = Instant::now();
    pool.install(|| {
        (0..INDEX_BUCKETS).into_par_iter().for_each(|b| {
            let mut key = [0x42u8; 16]; key[0] = b as u8;
            let prp = HoangPrp::new(INDEX_DOMAIN, 64, &key);
            let t: Vec<usize> = (0..INDEX_DOMAIN).map(|x| prp.forward(x)).collect();
            std::hint::black_box(&t);
        });
        (0..CHUNK_BUCKETS).into_par_iter().for_each(|b| {
            let mut key = [0x42u8; 16]; key[0] = b as u8; key[1] = 1;
            let prp = HoangPrp::new(CHUNK_DOMAIN, 64, &key);
            let t: Vec<usize> = (0..CHUNK_DOMAIN).map(|x| prp.forward(x)).collect();
            std::hint::black_box(&t);
        });
    });
    start.elapsed().as_secs_f64() * 1000.0
}

fn batch_fastprp(threads: usize) -> (f64, f64) {
    let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build().unwrap();
    let start = Instant::now();
    pool.install(|| {
        (0..INDEX_BUCKETS).into_par_iter().for_each(|b| {
            let mut key = [0x42u8; 16]; key[0] = b as u8;
            let prp = FastPrpWrapper::new(&key, INDEX_DOMAIN);
            let t = prp.batch_permute_raw();
            std::hint::black_box(&t);
        });
        (0..CHUNK_BUCKETS).into_par_iter().for_each(|b| {
            let mut key = [0x42u8; 16]; key[0] = b as u8; key[1] = 1;
            let prp = FastPrpWrapper::new(&key, CHUNK_DOMAIN);
            let t = prp.batch_permute_raw();
            std::hint::black_box(&t);
        });
    });
    let total = start.elapsed().as_secs_f64() * 1000.0;
    (total, total) // build+query combined for FastPRP
}

fn main() {
    println!("Batch construction (8 INDEX + 8 CHUNK buckets)");
    println!("Scale to full: multiply by ~10x (75/8 INDEX, 80/8 CHUNK)\n");

    for &t in &[8, 16] {
        let alf = batch_alf(t);
        let hoang = batch_hoang(t);
        let (fp, _) = batch_fastprp(t);
        println!("{:>2} threads:  ALF {:>7.0}ms  Hoang {:>7.0}ms  FastPRP {:>7.0}ms", t, alf, hoang, fp);
    }

    // Also 1-thread for per-bucket baseline
    println!("\nSingle-bucket baselines (1 INDEX + 1 CHUNK, 1 thread):");
    let key = [0x42u8; 16]; let tw = [0u8; 16];
    
    let s = Instant::now();
    let prp = AlfPrp::new(&key, INDEX_DOMAIN, &tw, 0);
    let _: Vec<usize> = (0..INDEX_DOMAIN).map(|x| prp.forward(x)).collect();
    let alf_idx = s.elapsed().as_secs_f64() * 1000.0;
    
    let s = Instant::now();
    let prp = AlfPrp::new(&key, CHUNK_DOMAIN, &tw, 0);
    let _: Vec<usize> = (0..CHUNK_DOMAIN).map(|x| prp.forward(x)).collect();
    let alf_chk = s.elapsed().as_secs_f64() * 1000.0;

    let s = Instant::now();
    let prp = HoangPrp::new(INDEX_DOMAIN, 64, &key);
    let _: Vec<usize> = (0..INDEX_DOMAIN).map(|x| prp.forward(x)).collect();
    let hoang_idx = s.elapsed().as_secs_f64() * 1000.0;

    let s = Instant::now();
    let prp = HoangPrp::new(CHUNK_DOMAIN, 64, &key);
    let _: Vec<usize> = (0..CHUNK_DOMAIN).map(|x| prp.forward(x)).collect();
    let hoang_chk = s.elapsed().as_secs_f64() * 1000.0;

    let s = Instant::now();
    let prp = FastPrpWrapper::new(&key, INDEX_DOMAIN);
    let _ = prp.batch_permute_raw();
    let fp_idx = s.elapsed().as_secs_f64() * 1000.0;

    let s = Instant::now();
    let prp = FastPrpWrapper::new(&key, CHUNK_DOMAIN);
    let _ = prp.batch_permute_raw();
    let fp_chk = s.elapsed().as_secs_f64() * 1000.0;

    println!("  ALF:     INDEX {:>6.0}ms  CHUNK {:>6.0}ms", alf_idx, alf_chk);
    println!("  Hoang:   INDEX {:>6.0}ms  CHUNK {:>6.0}ms", hoang_idx, hoang_chk);
    println!("  FastPRP: INDEX {:>6.0}ms  CHUNK {:>6.0}ms (build+batch)", fp_idx, fp_chk);
}
