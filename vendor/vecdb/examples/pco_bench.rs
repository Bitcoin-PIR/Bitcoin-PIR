use std::time::Instant;

use pco::{
    ChunkConfig,
    standalone::{simple_compress, simple_decompress, simple_decompress_into},
};

fn main() {
    // Generate test data - different patterns
    let sequential: Vec<u32> = (0..1_000_000).collect();
    let repeated: Vec<u32> = (0..1_000_000).map(|i| (i % 1000) as u32).collect();
    let random: Vec<u32> = (0..1_000_000)
        .map(|i| ((i * 17 + 31) % 100_000) as u32)
        .collect();

    let datasets = [
        ("sequential", &sequential),
        ("repeated", &repeated),
        ("pseudo-random", &random),
    ];

    let levels = [0, 4, 8, 12];

    println!("Benchmarking pco compression levels (1M u32 values)\n");
    println!(
        "{:<15} {:>6} {:>12} {:>12} {:>12} {:>10}",
        "Dataset", "Level", "Compress", "Decompress", "Size", "Ratio"
    );
    println!("{}", "-".repeat(75));

    for (name, data) in &datasets {
        let raw_size = data.len() * 4;

        for &level in &levels {
            let config = ChunkConfig::default()
                .with_compression_level(level)
                .with_enable_8_bit(true);

            // Benchmark compression
            let start = Instant::now();
            let compressed = simple_compress(data, &config).unwrap();
            let compress_time = start.elapsed();

            // Benchmark decompression
            let start = Instant::now();
            let _decompressed: Vec<u32> = simple_decompress(&compressed).unwrap();
            let decompress_time = start.elapsed();

            let ratio = raw_size as f64 / compressed.len() as f64;

            println!(
                "{:<15} {:>6} {:>10.2}ms {:>10.2}ms {:>10} {:>10.2}x",
                name,
                level,
                compress_time.as_secs_f64() * 1000.0,
                decompress_time.as_secs_f64() * 1000.0,
                compressed.len(),
                ratio
            );
        }
        println!();
    }

    // Benchmark decompress vs decompress_into (buffer reuse)
    println!("\nBenchmarking decompress vs decompress_into (buffer reuse)\n");
    println!(
        "{:<15} {:>15} {:>15} {:>10}",
        "Dataset", "decompress", "decompress_into", "Speedup"
    );
    println!("{}", "-".repeat(60));

    let config = ChunkConfig::default().with_enable_8_bit(true);
    let iterations = 100;

    for (name, data) in &datasets {
        let compressed = simple_compress(data, &config).unwrap();
        let len = data.len();

        // Benchmark simple_decompress (allocates each time)
        let start = Instant::now();
        for _ in 0..iterations {
            let _: Vec<u32> = simple_decompress(&compressed).unwrap();
        }
        let alloc_time = start.elapsed();

        // Benchmark simple_decompress_into (reuses buffer)
        let mut buffer: Vec<u32> = vec![0; len];
        let start = Instant::now();
        for _ in 0..iterations {
            simple_decompress_into(&compressed, &mut buffer).unwrap();
        }
        let reuse_time = start.elapsed();

        let speedup = alloc_time.as_secs_f64() / reuse_time.as_secs_f64();

        println!(
            "{:<15} {:>13.2}ms {:>13.2}ms {:>10.2}x",
            name,
            alloc_time.as_secs_f64() * 1000.0 / iterations as f64,
            reuse_time.as_secs_f64() * 1000.0 / iterations as f64,
            speedup
        );
    }
}
