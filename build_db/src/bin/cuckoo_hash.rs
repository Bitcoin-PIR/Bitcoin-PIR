//! Build a Cuckoo hash table from utxo_4b_to_32b.bin and output the
//! remapped file utxo_4b_to_32b_cuckoo.bin.
//!
//! Input: each entry is 36 bytes (4-byte key LE + 32-byte data).
//! Output: m = 2*n entries of 36 bytes each, placed at their cuckoo positions.
//!         Empty slots are zero-filled.
//!
//! The cuckoo hashing uses the 4-byte key for hashing. We store entry indices
//! in the table during construction, then build the output by copying full
//! 36-byte entries to their final positions.

use memmap2::Mmap;
use std::fs::File;
use std::io::{self, Write};
use std::time::Instant;

/// Path to the input file
const INPUT_FILE: &str = "/Volumes/Bitcoin/data/utxo_4b_to_32b.bin";

/// Path to the output file
const OUTPUT_FILE: &str = "/Volumes/Bitcoin/data/utxo_4b_to_32b_cuckoo.bin";

/// Size of each entry in bytes
const ENTRY_SIZE: usize = 36;

/// Sentinel value for empty table slots (no valid entry index)
const EMPTY: u32 = u32::MAX;

/// Maximum number of eviction attempts before sending to stash
const MAX_KICKS: usize = 500;

/// Hash function 1: murmurhash3-style finalizer
#[inline(always)]
fn hash1(key: u32, table_size: usize) -> usize {
    let mut h = key;
    h ^= h >> 16;
    h = h.wrapping_mul(0x45d9f3b);
    h ^= h >> 16;
    h as u64 as usize % table_size
}

/// Hash function 2: different mixing constants
#[inline(always)]
fn hash2(key: u32, table_size: usize) -> usize {
    let mut h = key;
    h ^= h >> 15;
    h = h.wrapping_mul(0x735a2d97);
    h ^= h >> 15;
    h = h.wrapping_mul(0x0bef6c35);
    h ^= h >> 16;
    h as u64 as usize % table_size
}

/// Read the 4-byte key for entry at given index from the mmap
#[inline(always)]
fn read_key(mmap: &[u8], entry_idx: u32) -> u32 {
    let offset = entry_idx as usize * ENTRY_SIZE;
    u32::from_le_bytes([
        mmap[offset],
        mmap[offset + 1],
        mmap[offset + 2],
        mmap[offset + 3],
    ])
}

/// Get the alternate position for an entry currently at `pos`
#[inline(always)]
fn other_pos(key: u32, pos: usize, table_size: usize) -> usize {
    let h1 = hash1(key, table_size);
    let h2 = hash2(key, table_size);
    if pos == h1 {
        h2
    } else {
        h1
    }
}

fn main() {
    println!("=== Cuckoo Hashing: Build utxo_4b_to_32b_cuckoo.bin ===");
    println!();

    // Step 1: Memory-map the input file
    println!("[1] Opening input file: {}", INPUT_FILE);
    let start = Instant::now();

    let file = File::open(INPUT_FILE).expect("Failed to open input file");
    let file_len = file.metadata().unwrap().len() as usize;
    let n = file_len / ENTRY_SIZE;

    println!("  File size:  {} bytes", file_len);
    println!("  Entry size: {} bytes", ENTRY_SIZE);
    println!("  Number of entries (n): {}", n);

    if file_len % ENTRY_SIZE != 0 {
        eprintln!(
            "  Warning: file size is not a multiple of entry size ({} trailing bytes)",
            file_len % ENTRY_SIZE
        );
    }

    let mmap = unsafe { Mmap::map(&file).expect("Failed to mmap file") };
    println!("  File mapped in {:.2?}", start.elapsed());

    let table_size = 2 * n; // m = 2n
    println!();
    println!("  Table size (m): {} (2 × {})", table_size, n);
    println!(
        "  Output file size: {:.2} GB ({} bytes)",
        (table_size * ENTRY_SIZE) as f64 / (1024.0 * 1024.0 * 1024.0),
        table_size * ENTRY_SIZE
    );

    // Step 2: Build Cuckoo hash table (stores entry indices, not keys)
    println!();
    println!("[2] Building Cuckoo hash table...");
    let build_start = Instant::now();

    // Table stores entry indices (0..n-1), EMPTY = u32::MAX for empty slots
    let mut table: Vec<u32> = vec![EMPTY; table_size];
    let mut stash_count: u64 = 0;

    let report_interval = std::cmp::max(1, n / 100);

    for entry_idx in 0..n {
        let idx = entry_idx as u32;
        let key = read_key(&mmap, idx);

        let pos1 = hash1(key, table_size);
        if table[pos1] == EMPTY {
            table[pos1] = idx;
        } else {
            let pos2 = hash2(key, table_size);
            if table[pos2] == EMPTY {
                table[pos2] = idx;
            } else {
                // Eviction chain: we track entry indices
                let mut current_idx = idx;
                let mut current_key = key;
                let mut current_pos = pos1;
                let mut placed = false;

                for _kick in 0..MAX_KICKS {
                    // Evict whoever is at current_pos
                    let evicted_idx = table[current_pos];
                    table[current_pos] = current_idx;

                    current_idx = evicted_idx;
                    current_key = read_key(&mmap, current_idx);

                    // Find the other position for the evicted entry
                    let alt = other_pos(current_key, current_pos, table_size);
                    if table[alt] == EMPTY {
                        table[alt] = current_idx;
                        placed = true;
                        break;
                    }
                    current_pos = alt;
                }

                if !placed {
                    // This shouldn't happen with m=2n, but handle gracefully
                    stash_count += 1;
                    eprintln!(
                        "  STASH: entry_idx={} key={} (stash_count={})",
                        current_idx, current_key, stash_count
                    );
                }
            }
        }

        // Progress
        if (entry_idx + 1) % report_interval == 0 || entry_idx + 1 == n {
            let elapsed = build_start.elapsed().as_secs_f64();
            let progress = (entry_idx + 1) as f64 / n as f64 * 100.0;
            let rate = (entry_idx + 1) as f64 / elapsed;
            let eta = if rate > 0.0 {
                (n - entry_idx - 1) as f64 / rate
            } else {
                0.0
            };
            print!(
                "\r  Progress: {:.1}% ({}/{}) | Stash: {} | {:.0} keys/s | ETA: {:.0}s   ",
                progress,
                entry_idx + 1,
                n,
                stash_count,
                rate,
                eta
            );
            io::stdout().flush().ok();
        }
    }
    println!();
    println!("  Build completed in {:.2?}", build_start.elapsed());
    println!("  Stash count: {}", stash_count);

    // Step 3: Build output buffer
    println!();
    println!("[3] Building output buffer ({:.2} GB)...", (table_size * ENTRY_SIZE) as f64 / (1024.0 * 1024.0 * 1024.0));
    let output_start = Instant::now();

    let output_size = table_size * ENTRY_SIZE;
    let mut output: Vec<u8> = vec![0u8; output_size];

    let mut placed_count: usize = 0;
    for slot in 0..table_size {
        let entry_idx = table[slot];
        if entry_idx != EMPTY {
            let src_offset = entry_idx as usize * ENTRY_SIZE;
            let dst_offset = slot * ENTRY_SIZE;
            output[dst_offset..dst_offset + ENTRY_SIZE]
                .copy_from_slice(&mmap[src_offset..src_offset + ENTRY_SIZE]);
            placed_count += 1;
        }
        // Empty slots remain zero-filled
    }

    println!("  Output buffer built in {:.2?}", output_start.elapsed());
    println!("  Entries placed: {} / {} slots", placed_count, table_size);

    // Step 4: Write output file
    println!();
    println!("[4] Writing output file: {}", OUTPUT_FILE);
    let write_start = Instant::now();

    let mut out_file = File::create(OUTPUT_FILE).expect("Failed to create output file");
    out_file.write_all(&output).expect("Failed to write output file");
    out_file.sync_all().expect("Failed to sync output file");

    println!("  Written {:.2} GB in {:.2?}", output_size as f64 / (1024.0 * 1024.0 * 1024.0), write_start.elapsed());

    // Step 5: Verify a sample
    println!();
    println!("[5] Quick verification (checking all entries can be looked up)...");
    let verify_start = Instant::now();
    let mut errors = 0u64;

    for entry_idx in 0..n {
        let key = read_key(&mmap, entry_idx as u32);
        let pos1 = hash1(key, table_size);
        let pos2 = hash2(key, table_size);

        // Check if the entry is at pos1 or pos2 in the output
        let found = {
            let out_key1 = u32::from_le_bytes([
                output[pos1 * ENTRY_SIZE],
                output[pos1 * ENTRY_SIZE + 1],
                output[pos1 * ENTRY_SIZE + 2],
                output[pos1 * ENTRY_SIZE + 3],
            ]);
            let out_key2 = u32::from_le_bytes([
                output[pos2 * ENTRY_SIZE],
                output[pos2 * ENTRY_SIZE + 1],
                output[pos2 * ENTRY_SIZE + 2],
                output[pos2 * ENTRY_SIZE + 3],
            ]);
            out_key1 == key || out_key2 == key
        };

        if !found {
            errors += 1;
            if errors <= 10 {
                eprintln!("  ERROR: entry_idx={} key={} not found at pos1={} or pos2={}", entry_idx, key, pos1, pos2);
            }
        }
    }

    println!("  Verification done in {:.2?}", verify_start.elapsed());
    println!("  Errors: {}", errors);

    // Summary
    println!();
    println!("========================================");
    println!("  Input:   {} entries × {} bytes = {:.2} GB",
        n, ENTRY_SIZE, file_len as f64 / (1024.0 * 1024.0 * 1024.0));
    println!("  Output:  {} entries × {} bytes = {:.2} GB",
        table_size, ENTRY_SIZE, output_size as f64 / (1024.0 * 1024.0 * 1024.0));
    println!("  Stash:   {}", stash_count);
    println!("  Errors:  {}", errors);
    println!("  Total time: {:.2?}", start.elapsed());
    println!("========================================");
}
