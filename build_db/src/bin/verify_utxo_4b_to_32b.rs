//! Verify the utxo_4b_to_32b.bin mapping file against the MPHF.
//!
//! This tool reads entries from utxo_4b_to_32b.bin (each 36 bytes: 4-byte x + 32-byte z)
//! and verifies that MPHF(z) == x for every entry.
//!
//! Usage:
//!   verify_utxo_4b_to_32b

use bitcoinpir::mpfh::Mphf;
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::path::Path;
use std::time::Instant;

/// Path to the MPHF file for TXID mapping
const MPHF_FILE: &str = "/Volumes/Bitcoin/data/txid_mphf.bin";

/// Path to the file to verify
const INPUT_FILE: &str = "/Volumes/Bitcoin/data/utxo_4b_to_32b.bin";

/// Size of each entry in bytes (4 + 32)
const ENTRY_SIZE: usize = 36;

/// Load MPHF from file
fn load_mphf(path: &Path) -> Result<Mphf<[u8; 32]>, String> {
    println!("Loading MPHF from {}...", path.display());
    let start = Instant::now();

    let data = std::fs::read(path)
        .map_err(|e| format!("Failed to read MPHF file: {}", e))?;

    let mphf: Mphf<[u8; 32]> = bincode::deserialize(&data)
        .map_err(|e| format!("Failed to deserialize MPHF: {}", e))?;

    println!(
        "MPHF loaded successfully ({} bytes) in {:.2?}",
        data.len(),
        start.elapsed()
    );
    Ok(mphf)
}

/// Convert bytes to hex string
fn bin2hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    println!("=== Verify utxo_4b_to_32b ===");
    println!();

    // Step 1: Load MPHF
    println!("[1] Loading MPHF...");
    let mphf = match load_mphf(Path::new(MPHF_FILE)) {
        Ok(m) => {
            println!("✓ MPHF loaded successfully");
            m
        }
        Err(e) => {
            eprintln!("✗ {}", e);
            std::process::exit(1);
        }
    };

    // Step 2: Open input file
    println!();
    println!("[2] Opening input file: {}", INPUT_FILE);
    let file = match File::open(INPUT_FILE) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("✗ Failed to open input file: {}", e);
            std::process::exit(1);
        }
    };

    let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let total_entries = file_len / ENTRY_SIZE as u64;
    println!(
        "  File size: {} bytes ({} entries of {} bytes)",
        file_len, total_entries, ENTRY_SIZE
    );

    if file_len % ENTRY_SIZE as u64 != 0 {
        eprintln!(
            "✗ Warning: file size {} is not a multiple of entry size {}. {} trailing bytes.",
            file_len,
            ENTRY_SIZE,
            file_len % ENTRY_SIZE as u64
        );
    }

    let mut reader = BufReader::with_capacity(1024 * 1024, file);

    // Step 3: Verify entries
    println!();
    println!("[3] Verifying entries...");
    let start = Instant::now();

    let mut buf = [0u8; ENTRY_SIZE];
    let mut count: u64 = 0;
    let mut errors: u64 = 0;
    let report_interval = std::cmp::max(1, total_entries / 1000);

    loop {
        match reader.read_exact(&mut buf) {
            Ok(()) => {}
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                eprintln!("✗ Read error at entry {}: {}", count, e);
                std::process::exit(1);
            }
        }

        // Parse entry: first 4 bytes = x (u32 LE), next 32 bytes = z
        let x = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let z: [u8; 32] = buf[4..36].try_into().unwrap();

        // Run MPHF over z
        match mphf.try_hash(&z) {
            Some(hash) => {
                let hash_u32 = hash as u32;
                if hash_u32 != x {
                    eprintln!(
                        "✗ MISMATCH at entry {}: expected x={}, got MPHF(z)={}, z={}",
                        count, x, hash_u32, bin2hex(&z)
                    );
                    errors += 1;
                }
            }
            None => {
                eprintln!(
                    "✗ MPHF returned None for entry {}: x={}, z={}",
                    count, x, bin2hex(&z)
                );
                errors += 1;
            }
        }

        count += 1;

        // Progress reporting
        if count % report_interval == 0 {
            let elapsed = start.elapsed().as_secs_f64();
            let progress = count as f64 / total_entries as f64 * 100.0;
            let rate = count as f64 / elapsed;
            let eta = if rate > 0.0 {
                (total_entries - count) as f64 / rate
            } else {
                0.0
            };
            print!(
                "\r  Progress: {:.1}% ({}/{}) | Errors: {} | {:.0} entries/s | ETA: {:.0}s  ",
                progress, count, total_entries, errors, rate, eta
            );
            io::stdout().flush().ok();
        }
    }

    let elapsed = start.elapsed();
    println!();
    println!();

    // Step 4: Report results
    println!("=== Results ===");
    println!("Total entries verified: {}", count);
    println!("Total errors: {}", errors);
    println!("Time elapsed: {:.2?}", elapsed);
    if elapsed.as_secs_f64() > 0.0 {
        println!(
            "Rate: {:.0} entries/s",
            count as f64 / elapsed.as_secs_f64()
        );
    }

    if errors == 0 {
        println!();
        println!("✓ All {} entries verified successfully! Every MPHF(z) == x.", count);
    } else {
        println!();
        eprintln!("✗ Verification FAILED: {} errors out of {} entries.", errors, count);
        std::process::exit(1);
    }
}
