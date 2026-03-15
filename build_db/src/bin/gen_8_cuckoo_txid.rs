//! Bucketed Cuckoo Hashing experiment.
//!
//! Input: utxo_4b_to_32b.bin (36-byte entries: 4-byte key + 32-byte data)
//!
//! Parameters:
//!   - 2 hash functions
//!   - Bucket size B = 4
//!   - Load factor α = 0.95
//!   - Total slots = ceil(n / 0.95), rounded up to multiple of B
//!   - Number of buckets = total_slots / B
//!
//! Each hash function maps a key to a bucket (not a slot). When inserting,
//! we check if either of the two buckets has a free slot. If not, we evict
//! a random entry from one of the two buckets and repeat.

use memmap2::Mmap;
use std::fs::File;
use std::io::{self, Write};
use std::time::Instant;

const INPUT_FILE: &str = "/Volumes/Bitcoin/data/utxo_4b_to_32b.bin";
const OUTPUT_FILE: &str = "/Volumes/Bitcoin/data/utxo_4b_to_32b_cuckoo.bin";
const ENTRY_SIZE: usize = 36;
const BUCKET_SIZE: usize = 4;
const LOAD_FACTOR: f64 = 0.95;
const EMPTY: u32 = u32::MAX;
const MAX_KICKS: usize = 500;

/// Hash function 1: murmurhash3-style finalizer
#[inline(always)]
fn hash1(key: u32, num_buckets: usize) -> usize {
    let mut h = key;
    h ^= h >> 16;
    h = h.wrapping_mul(0x45d9f3b);
    h ^= h >> 16;
    h as u64 as usize % num_buckets
}

/// Hash function 2: different mixing constants
#[inline(always)]
fn hash2(key: u32, num_buckets: usize) -> usize {
    let mut h = key;
    h ^= h >> 15;
    h = h.wrapping_mul(0x735a2d97);
    h ^= h >> 15;
    h = h.wrapping_mul(0x0bef6c35);
    h ^= h >> 16;
    h as u64 as usize % num_buckets
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

/// Find a free slot in a bucket, returns Some(slot_index_within_bucket) or None
#[inline]
fn find_free_slot(table: &[u32], bucket: usize) -> Option<usize> {
    let base = bucket * BUCKET_SIZE;
    for i in 0..BUCKET_SIZE {
        if table[base + i] == EMPTY {
            return Some(i);
        }
    }
    None
}

/// Get the other bucket for a key
#[inline(always)]
fn other_bucket(key: u32, current_bucket: usize, num_buckets: usize) -> usize {
    let b1 = hash1(key, num_buckets);
    let b2 = hash2(key, num_buckets);
    if current_bucket == b1 {
        b2
    } else {
        b1
    }
}

fn main() {
    println!("=== Bucketed Cuckoo Hashing Experiment ===");
    println!("  Bucket size: {}", BUCKET_SIZE);
    println!("  Load factor: {}", LOAD_FACTOR);
    println!("  Hash functions: 2");
    println!();

    // Step 1: Memory-map the input file
    println!("[1] Opening input file: {}", INPUT_FILE);

    let file = File::open(INPUT_FILE).expect("Failed to open input file");
    let file_len = file.metadata().unwrap().len() as usize;
    let n = file_len / ENTRY_SIZE;

    println!("  Number of entries (n): {}", n);

    let mmap = unsafe { Mmap::map(&file).expect("Failed to mmap file") };

    // Calculate table dimensions
    let total_slots_needed = (n as f64 / LOAD_FACTOR).ceil() as usize;
    // Round up to multiple of BUCKET_SIZE
    let num_buckets = (total_slots_needed + BUCKET_SIZE - 1) / BUCKET_SIZE;
    let total_slots = num_buckets * BUCKET_SIZE;
    let actual_load_factor = n as f64 / total_slots as f64;

    println!();
    println!("  Table dimensions:");
    println!("    Total slots:    {}", total_slots);
    println!(
        "    Num buckets:    {} (each holds {} entries)",
        num_buckets, BUCKET_SIZE
    );
    println!("    Actual max LF:  {:.6}", actual_load_factor);
    println!(
        "    Table memory (indices): {:.2} MB",
        (total_slots * 4) as f64 / (1024.0 * 1024.0)
    );
    println!(
        "    Output file size (if built): {:.2} GB ({} bytes)",
        (total_slots * ENTRY_SIZE) as f64 / (1024.0 * 1024.0 * 1024.0),
        total_slots * ENTRY_SIZE
    );

    // For comparison
    let two_n_size = 2 * n * ENTRY_SIZE;
    println!();
    println!("  === Size comparison ===");
    println!(
        "    Previous (m=2n):      {:.2} GB ({} slots)",
        two_n_size as f64 / (1024.0 * 1024.0 * 1024.0),
        2 * n
    );
    println!(
        "    Bucketed (α=0.95):    {:.2} GB ({} slots)",
        (total_slots * ENTRY_SIZE) as f64 / (1024.0 * 1024.0 * 1024.0),
        total_slots
    );
    println!(
        "    Savings:              {:.2} GB ({:.1}%)",
        (two_n_size as f64 - (total_slots * ENTRY_SIZE) as f64) / (1024.0 * 1024.0 * 1024.0),
        (1.0 - total_slots as f64 / (2 * n) as f64) * 100.0
    );

    // Step 2: Build bucketed cuckoo hash table
    println!();
    println!("[2] Building bucketed Cuckoo hash table...");
    let build_start = Instant::now();

    // Table stores entry indices
    let mut table: Vec<u32> = vec![EMPTY; total_slots];
    let mut stash: Vec<u32> = Vec::new();

    // Simple RNG for picking which slot to evict (xorshift32)
    let mut rng_state: u32 = 0xDEADBEEF;
    let mut xorshift = || -> u32 {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 17;
        rng_state ^= rng_state << 5;
        rng_state
    };

    let report_interval = std::cmp::max(1, n / 100);

    for entry_idx in 0..n {
        let idx = entry_idx as u32;
        let key = read_key(&mmap, idx);

        let b1 = hash1(key, num_buckets);
        let b2 = hash2(key, num_buckets);

        // Try bucket 1
        if let Some(slot) = find_free_slot(&table, b1) {
            table[b1 * BUCKET_SIZE + slot] = idx;
        } else if let Some(slot) = find_free_slot(&table, b2) {
            // Try bucket 2
            table[b2 * BUCKET_SIZE + slot] = idx;
        } else {
            // Need eviction chain
            let mut current_idx = idx;
            let mut current_key;
            // Pick a random bucket to start evicting from
            let mut current_bucket = if xorshift() & 1 == 0 { b1 } else { b2 };
            let mut placed = false;

            for _kick in 0..MAX_KICKS {
                // Pick a random slot in current_bucket to evict
                let evict_slot = (xorshift() as usize) % BUCKET_SIZE;
                let base = current_bucket * BUCKET_SIZE;

                let evicted_idx = table[base + evict_slot];
                table[base + evict_slot] = current_idx;

                current_idx = evicted_idx;
                current_key = read_key(&mmap, current_idx);

                // Try to place evicted entry in its other bucket
                let alt_bucket = other_bucket(current_key, current_bucket, num_buckets);
                if let Some(slot) = find_free_slot(&table, alt_bucket) {
                    table[alt_bucket * BUCKET_SIZE + slot] = current_idx;
                    placed = true;
                    break;
                }
                current_bucket = alt_bucket;
            }

            if !placed {
                stash.push(current_idx);
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
                stash.len(),
                rate,
                eta
            );
            io::stdout().flush().ok();
        }
    }
    println!();
    println!("  Build completed in {:.2?}", build_start.elapsed());

    // Step 3: Statistics
    println!();
    println!("=== Results ===");
    let occupied = table.iter().filter(|&&v| v != EMPTY).count();
    println!("  Total keys:          {}", n);
    println!("  Total slots:         {}", total_slots);
    println!(
        "  Num buckets:         {} (×{} = {} slots)",
        num_buckets, BUCKET_SIZE, total_slots
    );
    println!("  Slots occupied:      {}", occupied);
    println!(
        "  Load factor:         {:.6}",
        occupied as f64 / total_slots as f64
    );
    println!("  Stash size:          {}", stash.len());
    println!(
        "  Stash fraction:      {:.8}%",
        stash.len() as f64 / n as f64 * 100.0
    );

    // Verify
    println!();
    println!("[3] Verifying all entries can be found...");
    let verify_start = Instant::now();
    let mut errors = 0u64;
    let stash_set: std::collections::HashSet<u32> = stash.iter().copied().collect();

    for entry_idx in 0..n {
        let idx = entry_idx as u32;
        let key = read_key(&mmap, idx);
        let b1 = hash1(key, num_buckets);
        let b2 = hash2(key, num_buckets);

        let mut found = false;
        for i in 0..BUCKET_SIZE {
            if table[b1 * BUCKET_SIZE + i] == idx || table[b2 * BUCKET_SIZE + i] == idx {
                found = true;
                break;
            }
        }
        // Also check if key (by value, not idx) is in stash
        if !found && !stash_set.contains(&idx) {
            errors += 1;
            if errors <= 10 {
                eprintln!("  ERROR: entry_idx={} key={} not found", entry_idx, key);
            }
        }
    }
    println!("  Verification done in {:.2?}", verify_start.elapsed());
    println!("  Errors: {}", errors);

    // Step 4: Build output buffer and write file
    println!();
    let output_size = total_slots * ENTRY_SIZE;
    println!(
        "[4] Building output buffer ({:.2} GB)...",
        output_size as f64 / (1024.0 * 1024.0 * 1024.0)
    );
    let output_start = Instant::now();

    let mut output: Vec<u8> = vec![0u8; output_size];
    let mut placed_count: usize = 0;
    for slot in 0..total_slots {
        let entry_idx = table[slot];
        if entry_idx != EMPTY {
            let src_offset = entry_idx as usize * ENTRY_SIZE;
            let dst_offset = slot * ENTRY_SIZE;
            output[dst_offset..dst_offset + ENTRY_SIZE]
                .copy_from_slice(&mmap[src_offset..src_offset + ENTRY_SIZE]);
            placed_count += 1;
        }
    }
    println!(
        "  Output buffer built in {:.2?} ({} entries placed)",
        output_start.elapsed(),
        placed_count
    );

    println!("  Writing to {}...", OUTPUT_FILE);
    let write_start = Instant::now();
    let mut out_file = File::create(OUTPUT_FILE).expect("Failed to create output file");
    out_file
        .write_all(&output)
        .expect("Failed to write output file");
    out_file.sync_all().expect("Failed to sync output file");
    println!(
        "  Written {:.2} GB in {:.2?}",
        output_size as f64 / (1024.0 * 1024.0 * 1024.0),
        write_start.elapsed()
    );

    // Size summary
    println!();
    println!("========================================");
    println!("  BUCKETED CUCKOO HASHING SUMMARY");
    println!("========================================");
    println!("  n = {} entries", n);
    println!("  Bucket size = {}", BUCKET_SIZE);
    println!("  Load factor target = {}", LOAD_FACTOR);
    println!(
        "  Total slots = {} ({:.4}× n)",
        total_slots,
        total_slots as f64 / n as f64
    );
    println!("  Stash size = {}", stash.len());
    println!();
    println!("  File sizes (36-byte entries):");
    println!(
        "    Original input:            {:.2} GB",
        (n * ENTRY_SIZE) as f64 / (1024.0 * 1024.0 * 1024.0)
    );
    println!(
        "    Previous cuckoo (m=2n):    {:.2} GB  (2.00× n)",
        (2 * n * ENTRY_SIZE) as f64 / (1024.0 * 1024.0 * 1024.0)
    );
    println!(
        "    Bucketed cuckoo (α=0.95):  {:.2} GB  ({:.4}× n)",
        (total_slots * ENTRY_SIZE) as f64 / (1024.0 * 1024.0 * 1024.0),
        total_slots as f64 / n as f64
    );
    println!(
        "    Space saving vs 2n:        {:.1}%",
        (1.0 - total_slots as f64 / (2 * n) as f64) * 100.0
    );
    println!("========================================");
}
