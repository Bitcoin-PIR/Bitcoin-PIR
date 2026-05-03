use fastprp::FastPrp;
use std::time::Instant;

fn main() {
    let key: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    ];

    // ── Single-element permute / unpermute ──
    let n = 1_000_000u64;
    let prp = FastPrp::new(&key, n);

    println!("FastPRP  N = {n}");
    println!("  cache stride = {}", prp.cache_stride());
    println!("  cache size   = {} KB\n", prp.cache_size_bytes() / 1024);

    for x in [0, 1, 42, 999_999] {
        let y = prp.permute(x);
        let x_back = prp.unpermute(y);
        println!("  permute({x:>7}) = {y:>7}   unpermute -> {x_back}");
        assert_eq!(x_back, x);
    }

    // ── 4-way batched permute ──
    let inputs = [0, 100, 200, 300];
    let results = prp.permute_4(inputs);
    println!("\n  permute_4({inputs:?}) = {results:?}");

    // ── Full-domain batch permute ──
    let n_small = 1u64 << 14;
    let prp_small = FastPrp::new(&key, n_small);

    let start = Instant::now();
    let table = prp_small.batch_permute();
    let elapsed = start.elapsed();

    println!("\n  batch_permute(N={n_small}): {:.2} ms", elapsed.as_secs_f64() * 1000.0);
    println!("  table[0..8] = {:?}", &table[..8]);

    // Verify round-trip via inverse table.
    let mut inv = vec![0u64; n_small as usize];
    for (x, &y) in table.iter().enumerate() {
        inv[y as usize] = x as u64;
    }
    for x in 0..n_small {
        assert_eq!(inv[table[x as usize] as usize], x);
    }
    println!("  inverse table verified OK");
}
