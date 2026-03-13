//! Build location index for transaction IDs using MPHF
//!
//! This program loads the pre-built MPHF and creates a location index file
//! that maps each txid's MPHF hash to its position in the txid.bin file.
//!
//! Processes 100,000,000 txids per invocation with progress tracking.
//! Uses memory-mapped file for efficient random writes.
//! Run multiple times to complete the entire file.
//!
//! Usage: cargo run --release --bin build_location_index

use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

use bitcoinpir::mpfh::Mphf;
use memmap2::MmapMut;

const TXID_FILE: &str = "/Volumes/Bitcoin/data/txid.bin";
const MPHF_FILE: &str = "/Volumes/Bitcoin/data/txid_mphf.bin";
const LOCATION_FILE: &str = "/Volumes/Bitcoin/data/txid_locations.bin";
const PROGRESS_FILE: &str = "/Volumes/Bitcoin/data/location_index_progress.txt";
const TXID_SIZE: usize = 32;
const LOCATION_SIZE: usize = 4; // 4 bytes per location (u32)

/// Number of txids to process per invocation
const TXIDS_PER_BATCH: u64 = 100_000_000;

/// Total number of entries in the location index
const TOTAL_ENTRIES: u64 = 2 * 1267151381;

/// Total size of the location index file in bytes
const LOCATION_FILE_SIZE: usize = (TOTAL_ENTRIES * LOCATION_SIZE as u64) as usize;

/// Txids to skip (these caused issues during MPHF construction)
/// 68b45f58b674e94eb881cd67b04c2cba07fe5552dbf1d5385637b0d4073dbfe3
const SKIP_TXID_1: [u8; 32] = [
    0x68, 0xb4, 0x5f, 0x58, 0xb6, 0x74, 0xe9, 0x4e,
    0xb8, 0x81, 0xcd, 0x67, 0xb0, 0x4c, 0x2c, 0xba,
    0x07, 0xfe, 0x55, 0x52, 0xdb, 0xf1, 0xd5, 0x38,
    0x56, 0x37, 0xb0, 0xd4, 0x07, 0x3d, 0xbf, 0xe3,
];

/// 9985d82954e10f2233a08905dc7b490eb444660c8759e324c7dfa3d28779d2d5
const SKIP_TXID_2: [u8; 32] = [
    0x99, 0x85, 0xd8, 0x29, 0x54, 0xe1, 0x0f, 0x22,
    0x33, 0xa0, 0x89, 0x05, 0xdc, 0x7b, 0x49, 0x0e,
    0xb4, 0x44, 0x66, 0x0c, 0x87, 0x59, 0xe3, 0x24,
    0xc7, 0xdf, 0xa3, 0xd2, 0x87, 0x79, 0xd2, 0xd5,
];

/// Check if a txid should be skipped
#[inline]
fn should_skip(txid: &[u8; 32]) -> bool {
    txid == &SKIP_TXID_1 || txid == &SKIP_TXID_2
}

/// Get current progress (txid index) from progress file
fn get_progress() -> u64 {
    match std::fs::read_to_string(PROGRESS_FILE) {
        Ok(s) => s.trim().parse().unwrap_or(0),
        Err(_) => 0,
    }
}

/// Save current progress
fn save_progress(txid_index: u64) {
    if let Err(e) = std::fs::write(PROGRESS_FILE, txid_index.to_string()) {
        eprintln!("Warning: Failed to save progress: {}", e);
    }
}

/// Print a progress bar similar to generate_txid_file.rs
fn print_progress(current: u64, total: u64, txid_index: u64, elapsed: std::time::Duration) {
    let percent = (current * 100) / total;
    let filled = (current * 50) / total;
    let empty = 50 - filled;

    let txids_per_sec = if elapsed.as_secs() > 0 {
        current as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };

    let bar = format!(
        "[{}{}] {:3}% | Txid {} | {:.0} txids/s",
        "=".repeat(filled as usize),
        " ".repeat(empty as usize),
        percent,
        txid_index,
        txids_per_sec
    );

    print!("\r{}", bar);
    std::io::stdout().flush().unwrap();
}

/// Load MPHF from file using bincode deserialization
fn load_mphf(path: &Path) -> io::Result<Mphf<[u8; 32]>> {
    println!("Loading MPHF from {}...", path.display());

    let file = File::open(path)?;
    let metadata = file.metadata()?;
    println!("MPHF file size: {} bytes ({:.2} GB)", metadata.len(), metadata.len() as f64 / 1e9);

    let mphf: Mphf<[u8; 32]> = bincode::deserialize_from(file).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to deserialize MPHF: {}", e),
        )
    })?;

    println!("MPHF loaded successfully!");
    Ok(mphf)
}

/// Write a u32 value at a specific position in the mmap
#[inline]
fn write_location_at(mmap: &mut [u8], position: u64, value: u32) {
    let offset = (position * LOCATION_SIZE as u64) as usize;
    let bytes = value.to_le_bytes();
    mmap[offset..offset + 4].copy_from_slice(&bytes);
}

/// Build location index by processing a batch of txids using memory-mapped file
fn build_location_index_batch(
    mphf: &Mphf<[u8; 32]>,
    txid_path: &Path,
    location_path: &Path,
    start_index: u64,
    count: u64,
) -> io::Result<u64> {
    println!("\n=== Building Location Index ===");
    println!("Processing txids {} to {} ({} txids)", start_index, start_index + count - 1, count);

    // Open the location file for memory mapping
    let location_file = File::options()
        .read(true)
        .write(true)
        .open(location_path)?;

    // Verify file size
    let file_size = location_file.metadata()?.len() as usize;
    if file_size != LOCATION_FILE_SIZE {
        eprintln!("Warning: Location file size {} != expected {}", file_size, LOCATION_FILE_SIZE);
    }

    println!("Memory-mapping location file ({:.2} GB)...", LOCATION_FILE_SIZE as f64 / 1e9);
    
    // Create mutable memory map
    let mut mmap = unsafe { MmapMut::map_mut(&location_file)? };
    println!("Memory mapping created successfully!");

    // Open txid file and seek to start position
    let mut txid_file = File::open(txid_path)?;
    txid_file.seek(SeekFrom::Start(start_index * TXID_SIZE as u64))?;

    // Create buffered reader for txid file
    let mut reader = BufReader::with_capacity(1024 * 1024 * 100, txid_file); // 100MB buffer

    let start = std::time::Instant::now();
    let mut last_progress_update = std::time::Instant::now();
    let mut processed: u64 = 0;

    // Process txids in this batch
    for i in 0..count {
        // Read txid
        let mut txid_buf = [0u8; TXID_SIZE];
        if reader.read_exact(&mut txid_buf).is_err() {
            println!("\nReached end of txid file at index {}", start_index + i);
            break;
        }

        let txid_index = start_index + i;

        // Skip problematic txids that couldn't be assigned unique hashes during MPHF construction
        if should_skip(&txid_buf) {
            processed += 1;
            continue;
        }

        // Get the MPHF hash for this txid
        let hash = mphf.hash(&txid_buf);

        // Check for potential hash overflow (hash should be < TOTAL_ENTRIES)
        if hash >= TOTAL_ENTRIES {
            eprintln!("\nWarning: Hash {} exceeds total entries {} for txid at index {}", 
                      hash, TOTAL_ENTRIES, txid_index);
            processed += 1;
            continue;
        }

        // Write the location (txid_index as u32) at the hash position
        if txid_index <= u32::MAX as u64 {
            write_location_at(&mut mmap, hash, txid_index as u32);
        } else {
            eprintln!("\nError: txid_index {} exceeds u32::MAX", txid_index);
        }

        processed += 1;

        // Print progress every 100ms or every 100,000 txids
        if last_progress_update.elapsed().as_millis() >= 100 || processed % 100_000 == 0 || processed == count {
            print_progress(processed, count, txid_index, start.elapsed());
            last_progress_update = std::time::Instant::now();
        }
    }

    let duration = start.elapsed();

    println!();
    println!();
    println!("=== Flushing changes to disk ===");
    
    // Flush the memory map to disk
    mmap.flush()?;

    println!("Changes flushed successfully!");

    println!();
    println!("=== Batch Summary ===");
    println!("Txids processed: {}", processed);
    println!("Time elapsed: {:?}", duration);
    if duration.as_secs() > 0 {
        println!("Processing rate: {:.0} txids/sec", processed as f64 / duration.as_secs_f64());
    }

    Ok(processed)
}

/// Verify the location index by sampling some entries
fn verify_location_index(mphf: &Mphf<[u8; 32]>, txid_path: &Path, location_path: &Path) -> io::Result<()> {
    println!("\n=== Verifying Location Index ===");

    // Open files for verification
    let location_file = File::open(location_path)?;
    let mmap = unsafe { memmap2::Mmap::map(&location_file)? };

    let mut txid_file = File::open(txid_path)?;

    // Read and verify a few samples from recent batch
    let total_txids = match std::fs::metadata(txid_path) {
        Ok(m) => m.len() / TXID_SIZE as u64,
        Err(_) => 0,
    };

    // Sample from different parts of the file
    let sample_indices: Vec<u64> = if total_txids > 0 {
        vec![
            0,
            std::cmp::min(1000, total_txids - 1),
            std::cmp::min(100000, total_txids - 1),
            std::cmp::min(1000000, total_txids - 1),
            std::cmp::min(total_txids - 1, total_txids / 2),
            std::cmp::min(total_txids - 1, total_txids - 1),
        ]
    } else {
        println!("No txids to verify");
        return Ok(());
    };

    for sample_txid_index in sample_indices {
        // Read the txid at this index
        txid_file.seek(SeekFrom::Start(sample_txid_index * TXID_SIZE as u64))?;
        let mut txid_buf = [0u8; TXID_SIZE];
        txid_file.read_exact(&mut txid_buf)?;

        // Skip if this is a skipped txid
        if should_skip(&txid_buf) {
            println!("⊗ Txid index: {} (skipped - not in MPHF)", sample_txid_index);
            continue;
        }

        // Get MPHF hash
        let hash = mphf.hash(&txid_buf);

        // Read the location at this hash position
        let offset = (hash * LOCATION_SIZE as u64) as usize;
        let stored_index = u32::from_le_bytes([mmap[offset], mmap[offset+1], mmap[offset+2], mmap[offset+3]]);

        let status = if stored_index as u64 == sample_txid_index {
            "✓"
        } else {
            "✗"
        };

        println!("{} Txid index: {}, MPHF hash: {}, Stored index: {}",
                 status, sample_txid_index, hash, stored_index);
    }

    Ok(())
}

fn main() {
    println!("=== Location Index Builder for Bitcoin Transaction IDs ===");
    println!("This program creates a location index file that maps MPHF hashes to txid positions");
    println!("Processes {} txids per invocation", TXIDS_PER_BATCH);
    println!("Uses memory-mapped file for efficient random writes");
    println!();

    // Check if required files exist
    let txid_path = Path::new(TXID_FILE);
    let mphf_path = Path::new(MPHF_FILE);
    let location_path = Path::new(LOCATION_FILE);

    if !txid_path.exists() {
        eprintln!("✗ Error: txid file '{}' not found!", TXID_FILE);
        std::process::exit(1);
    }

    if !mphf_path.exists() {
        eprintln!("✗ Error: MPHF file '{}' not found!", MPHF_FILE);
        eprintln!("  Please run build_mphf first to create the MPHF file.");
        std::process::exit(1);
    }

    if !location_path.exists() {
        eprintln!("✗ Error: location file '{}' not found!", LOCATION_FILE);
        eprintln!("  Please create the sparse file first:");
        eprintln!("  truncate -s {} {}", LOCATION_FILE_SIZE, LOCATION_FILE);
        std::process::exit(1);
    }

    // Get total txid count
    let total_txids = match std::fs::metadata(txid_path) {
        Ok(m) => m.len() / TXID_SIZE as u64,
        Err(_) => 0,
    };
    println!("Total txids in file: {}", total_txids);

    // Check current progress
    let start_index = get_progress();
    println!("✓ Starting from txid index: {}", start_index);

    if start_index >= total_txids {
        println!();
        println!("✓ All txids have been processed!");
        println!("✓ Location index is complete.");
        return;
    }

    // Calculate end index for this batch
    let end_index = std::cmp::min(start_index + TXIDS_PER_BATCH, total_txids);
    let count = end_index - start_index;

    println!("Will process {} txids (from index {} to {})", count, start_index, end_index - 1);
    println!();

    // Step 1: Load MPHF
    let mphf = match load_mphf(mphf_path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("✗ Error loading MPHF: {}", e);
            std::process::exit(1);
        }
    };

    // Step 2: Build location index for this batch
    let processed = match build_location_index_batch(&mphf, txid_path, location_path, start_index, count) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("✗ Error building location index: {}", e);
            std::process::exit(1);
        }
    };

    // Save final progress (after mmap flush)
    save_progress(start_index + processed);

    // Step 3: Verify the index (optional, can skip for speed)
    if std::env::var("SKIP_VERIFY").is_err() {
        if let Err(e) = verify_location_index(&mphf, txid_path, location_path) {
            eprintln!("✗ Error verifying location index: {}", e);
        }
    }

    println!();
    println!("=== Done ===");
    println!("Progress saved to: {}", PROGRESS_FILE);
    
    let new_progress = start_index + processed;
    if new_progress < total_txids {
        let remaining = total_txids - new_progress;
        println!("Remaining txids: {} (run {} more times)", remaining, (remaining + TXIDS_PER_BATCH - 1) / TXIDS_PER_BATCH);
        println!();
        println!("Run this tool again to continue from where you left off!");
    } else {
        println!("✓ All txids have been processed!");
    }
}