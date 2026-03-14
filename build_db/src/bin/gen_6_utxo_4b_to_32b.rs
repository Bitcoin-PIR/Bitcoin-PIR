//! Tool to count unique 4-byte TXIDs in the remapped UTXO set
//!
//! This reads the remapped_utxo_set.bin file and extracts the 4-byte TXID
//! from each 40-byte entry, storing them in a HashSet to count unique TXIDs.
//! Then maps each 4-byte TXID to its 32-byte TXID by reading txid.bin.
//!
//! Entry format (40 bytes):
//! - Bytes 0-19: RIPEMD-160 hash of script (20 bytes)
//! - Bytes 20-23: 4-byte TXID (4 bytes) <-- We extract this (it's the txid_index in txid.bin)
//! - Bytes 24-27: vout (4 bytes)
//! - Bytes 28-31: block height (4 bytes)
//! - Bytes 32-39: amount (8 bytes)

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::time::Instant;

/// Path to the remapped UTXO set file
const INPUT_FILE: &str = "/Volumes/Bitcoin/data/remapped_utxo_set.bin";

/// Path to the txid.bin file (contains 32-byte TXIDs)
const TXID_FILE: &str = "/Volumes/Bitcoin/data/txid.bin";

/// Output file for 4-byte to 32-byte TXID mapping
const OUTPUT_FILE: &str = "/Volumes/Bitcoin/data/utxo_4b_to_32b.bin";

/// Size of each entry in bytes
const ENTRY_SIZE: usize = 40;

/// Offset of the 4-byte TXID within each entry
const TXID_OFFSET: usize = 20;

fn main() {
    println!("=== Count Unique TXIDs ===");
    println!("Input file: {}", INPUT_FILE);
    println!();

    // Open the file
    let file = match File::open(INPUT_FILE) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error opening file: {}", e);
            std::process::exit(1);
        }
    };

    // Get file size
    let file_size = match file.metadata() {
        Ok(m) => m.len(),
        Err(e) => {
            eprintln!("Error getting file metadata: {}", e);
            std::process::exit(1);
        }
    };

    let total_entries = file_size / ENTRY_SIZE as u64;
    println!(
        "File size: {} bytes ({:.2} MB)",
        file_size,
        file_size as f64 / (1024.0 * 1024.0)
    );
    println!("Expected entries: {}", total_entries);
    println!();

    // Create buffered reader with 8MB buffer for efficient reading
    let mut reader = BufReader::with_capacity(8 * 1024 * 1024, file);

    // HashSet to store unique 4-byte TXIDs
    let mut unique_txids: HashSet<[u8; 4]> = HashSet::new();

    // Buffer for reading entries
    let mut entry_buffer = [0u8; ENTRY_SIZE];
    let mut entries_read: u64 = 0;

    let start_time = Instant::now();

    // Progress tracking
    let report_interval = std::cmp::max(1, total_entries / 100); // Report every 1%
    let mut last_reported_percent = 0u64;

    println!("Reading entries...");

    loop {
        // Read one entry
        match reader.read_exact(&mut entry_buffer) {
            Ok(_) => {
                // Extract the 4-byte TXID (bytes 20-23)
                let txid: [u8; 4] = [
                    entry_buffer[TXID_OFFSET],
                    entry_buffer[TXID_OFFSET + 1],
                    entry_buffer[TXID_OFFSET + 2],
                    entry_buffer[TXID_OFFSET + 3],
                ];

                // Insert into HashSet
                unique_txids.insert(txid);

                entries_read += 1;

                // Progress update every 1%
                let current_percent = entries_read / report_interval;
                if current_percent > last_reported_percent && current_percent <= 100 {
                    let elapsed = start_time.elapsed().as_secs_f64();
                    let entries_per_sec = entries_read as f64 / elapsed;
                    print!("\rProgress: {:.0}% | Entries: {} | Unique TXIDs: {} | Speed: {:.0} entries/sec",
                           current_percent, entries_read, unique_txids.len(), entries_per_sec);
                    std::io::stdout().flush().ok();
                    last_reported_percent = current_percent;
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    // End of file reached
                    break;
                } else {
                    eprintln!("\nError reading file: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }

    let elapsed = start_time.elapsed();

    println!(
        "\rProgress: 100% | Entries: {} | Unique TXIDs: {}",
        entries_read,
        unique_txids.len()
    );
    println!();
    println!("=== Summary ===");
    println!("Total entries read: {}", entries_read);
    println!("Unique 4-byte TXIDs: {}", unique_txids.len());
    println!("Time elapsed: {:.2?}", elapsed);
    println!(
        "Entries per second: {:.0}",
        entries_read as f64 / elapsed.as_secs_f64()
    );
    println!();

    // =========================================================================
    // Step 1: Convert HashSet to a sorted Vec<u32> (small to large)
    // =========================================================================
    println!("=== Step 1: Convert HashSet to sorted Vec<u32> ===");
    let step_time = Instant::now();

    let mut sorted_txids: Vec<u32> = unique_txids
        .iter()
        .map(|bytes| u32::from_le_bytes(*bytes))
        .collect();
    sorted_txids.sort_unstable();

    println!(
        "Sorted {} unique TXIDs in {:.2?}",
        sorted_txids.len(),
        step_time.elapsed()
    );
    println!();

    // =========================================================================
    // Step 2: Read txid.bin — for each x (4-byte TXID), read 32 bytes at offset 32*x
    //         to get the 32-byte TXID z. Store (x, z) pairs.
    //         Note: The 4-byte TXID x IS the txid_index in txid.bin.
    // =========================================================================
    println!("=== Step 2: Read txid.bin (using 4-byte TXID as index) ===");
    let step_time = Instant::now();

    let txid_file = File::open(TXID_FILE).unwrap_or_else(|e| {
        eprintln!("Error opening {}: {}", TXID_FILE, e);
        std::process::exit(1);
    });
    let mut txid_reader = BufReader::with_capacity(8 * 1024 * 1024, txid_file);

    let total_lookups = sorted_txids.len();
    let mut xz_pairs: Vec<(u32, [u8; 32])> = Vec::with_capacity(total_lookups);
    let mut z_buf = [0u8; 32];

    // sorted_txids is sorted, so offsets 32*x are monotonically increasing.
    // We use seek_relative to skip forward.
    let mut current_pos: u64 = 0;

    for (i, &x) in sorted_txids.iter().enumerate() {
        let target_pos = (x as u64) * 32;
        let rel = target_pos as i64 - current_pos as i64;
        txid_reader.seek_relative(rel).unwrap_or_else(|e| {
            eprintln!("Error seeking in txid.bin at x={}: {}", x, e);
            std::process::exit(1);
        });
        txid_reader.read_exact(&mut z_buf).unwrap_or_else(|e| {
            eprintln!("Error reading txid.bin at x={}: {}", x, e);
            std::process::exit(1);
        });
        xz_pairs.push((x, z_buf));
        current_pos = target_pos + 32;

        if (i + 1) % 1_000_000 == 0 || i + 1 == total_lookups {
            print!("\rRead {}/{} txids", i + 1, total_lookups);
            std::io::stdout().flush().ok();
        }
    }
    // Close txid_reader
    drop(txid_reader);

    println!(
        "\rRead {}/{} txids in {:.2?}",
        total_lookups,
        total_lookups,
        step_time.elapsed()
    );
    println!();

    // =========================================================================
    // Step 3: Write (x, z) pairs to output file
    // =========================================================================
    println!("=== Step 3: Write output ===");
    let step_time = Instant::now();

    // xz_pairs is already sorted by x (since we iterated over sorted_txids)

    let out_file = File::create(OUTPUT_FILE).unwrap_or_else(|e| {
        eprintln!("Error creating {}: {}", OUTPUT_FILE, e);
        std::process::exit(1);
    });
    let mut writer = BufWriter::with_capacity(8 * 1024 * 1024, out_file);

    for &(x, ref z) in &xz_pairs {
        writer.write_all(&x.to_le_bytes()).unwrap_or_else(|e| {
            eprintln!("Error writing x to output: {}", e);
            std::process::exit(1);
        });
        writer.write_all(z).unwrap_or_else(|e| {
            eprintln!("Error writing z to output: {}", e);
            std::process::exit(1);
        });
    }
    writer.flush().unwrap_or_else(|e| {
        eprintln!("Error flushing output: {}", e);
        std::process::exit(1);
    });

    let total_elapsed = start_time.elapsed();
    let output_size = xz_pairs.len() as u64 * 36;
    println!(
        "Wrote {} entries ({} bytes, {:.2} MB) to {} in {:.2?}",
        xz_pairs.len(),
        output_size,
        output_size as f64 / (1024.0 * 1024.0),
        OUTPUT_FILE,
        step_time.elapsed()
    );
    println!();
    println!("=== All Done ===");
    println!("Total time: {:.2?}", total_elapsed);
}