//! Find the biggest UTXO entry in the chunks index
//!
//! Reads `/Volumes/Bitcoin/data/utxo_chunks_index.bin` which has entries:
//!   [20B script_hash] [4B start_offset u32 LE]
//!
//! The size of each entry is calculated by the delta between consecutive start_offsets.
//! This script identifies the entry with the largest size.
//!
//! Usage:
//!   find_biggest_utxo_entry [index_path] [chunks_path]
//!
//! Example:
//!   find_biggest_utxo_entry /Volumes/Bitcoin/data/utxo_chunks_index.bin /Volumes/Bitcoin/data/utxo_chunks.bin

use memmap2::Mmap;
use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::time::Instant;

/// Default paths
const DEFAULT_INDEX_PATH: &str = "/Volumes/Bitcoin/data/utxo_chunks_index.bin";
const DEFAULT_CHUNKS_PATH: &str = "/Volumes/Bitcoin/data/utxo_chunks.bin";

/// Size of each index entry: 20 bytes (script_hash) + 4 bytes (start_offset)
const INDEX_ENTRY_SIZE: usize = 24;

/// Size of script hash in bytes
const SCRIPT_HASH_SIZE: usize = 20;

/// Convert bytes to hex string
fn bin2hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Format a duration in seconds to a human-readable string
fn format_duration(secs: f64) -> String {
    if secs.is_infinite() || secs.is_nan() {
        return "calculating...".to_string();
    }
    let total_secs = secs as u64;
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;
    if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}

/// Format bytes to human-readable size
fn format_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    let bytes_f = bytes as f64;
    if bytes_f >= GB {
        format!("{:.2} GB", bytes_f / GB)
    } else if bytes_f >= MB {
        format!("{:.2} MB", bytes_f / MB)
    } else if bytes_f >= KB {
        format!("{:.2} KB", bytes_f / KB)
    } else {
        format!("{} bytes", bytes)
    }
}

/// Result of finding the biggest entry
struct BiggestEntry {
    /// Index of the entry in the index file
    index: u64,
    /// Script hash (20 bytes)
    script_hash: [u8; 20],
    /// Start offset in chunks file
    start_offset: u32,
    /// Size of the chunk (bytes)
    size: u64,
}

/// Find the biggest UTXO entry in the index
fn find_biggest_entry(index_path: &Path, chunks_path: &Path) -> Result<BiggestEntry, String> {
    println!("=== Find Biggest UTXO Entry ===");
    println!();
    println!("Index path:  {}", index_path.display());
    println!("Chunks path: {}", chunks_path.display());
    println!();

    // Open and mmap the index file
    println!("[1] Opening index file...");
    let index_file = File::open(index_path).map_err(|e| format!("Failed to open index file: {}", e))?;
    
    let index_mmap = unsafe { Mmap::map(&index_file) }
        .map_err(|e| format!("Failed to mmap index file: {}", e))?;
    
    let index_file_size = index_mmap.len();
    if index_file_size % INDEX_ENTRY_SIZE != 0 {
        return Err(format!(
            "Index file size ({}) is not a multiple of entry size ({})",
            index_file_size, INDEX_ENTRY_SIZE
        ));
    }

    let entry_count = index_file_size / INDEX_ENTRY_SIZE;
    println!(
        "    Index file: {} ({} entries)",
        format_size(index_file_size as u64),
        entry_count
    );

    // Get the total size of chunks file (for calculating last entry's size)
    println!("[2] Getting chunks file size...");
    let chunks_file = File::open(chunks_path)
        .map_err(|e| format!("Failed to open chunks file: {}", e))?;
    
    let chunks_metadata = chunks_file.metadata()
        .map_err(|e| format!("Failed to get chunks file metadata: {}", e))?;
    
    let total_chunks_size = chunks_metadata.len();
    println!("    Chunks file: {}", format_size(total_chunks_size));
    println!();

    // Scan through all entries to find the biggest
    println!("[3] Scanning entries for largest chunk...");
    let scan_start = Instant::now();

    let mut biggest = BiggestEntry {
        index: 0,
        script_hash: [0u8; 20],
        start_offset: 0,
        size: 0,
    };

    let one_percent = std::cmp::max(1, entry_count / 100);
    let mut last_pct = 0u64;

    for i in 0..entry_count {
        let base = i * INDEX_ENTRY_SIZE;
        
        // Read script_hash (first 20 bytes)
        let mut script_hash = [0u8; 20];
        script_hash.copy_from_slice(&index_mmap[base..base + SCRIPT_HASH_SIZE]);
        
        // Read start_offset (next 4 bytes, little-endian u32)
        let start_offset = u32::from_le_bytes([
            index_mmap[base + 20],
            index_mmap[base + 21],
            index_mmap[base + 22],
            index_mmap[base + 23],
        ]);

        // Calculate size: difference between this and next offset
        // For the last entry, use total_chunks_size
        let size = if i + 1 < entry_count {
            let next_base = (i + 1) * INDEX_ENTRY_SIZE;
            let next_offset = u32::from_le_bytes([
                index_mmap[next_base + 20],
                index_mmap[next_base + 21],
                index_mmap[next_base + 22],
                index_mmap[next_base + 23],
            ]);
            (next_offset as u64).saturating_sub(start_offset as u64)
        } else {
            // Last entry: size = total_chunks_size - start_offset
            total_chunks_size.saturating_sub(start_offset as u64)
        };

        // Update biggest if this is larger
        if size > biggest.size {
            biggest = BiggestEntry {
                index: i as u64,
                script_hash,
                start_offset,
                size,
            };
        }

        // Progress reporting
        let current_pct = (i as u64 + 1) / one_percent as u64;
        if current_pct > last_pct && current_pct <= 100 {
            let elapsed = scan_start.elapsed().as_secs_f64();
            let frac = current_pct as f64 / 100.0;
            let eta = if frac > 0.0 {
                (elapsed / frac) * (1.0 - frac)
            } else {
                0.0
            };
            print!(
                "\r    Progress: {}% | ETA: {} | Entries: {}/{} | Current biggest: {}",
                current_pct,
                format_duration(eta),
                i + 1,
                entry_count,
                format_size(biggest.size)
            );
            io::stdout().flush().ok();
            last_pct = current_pct;
        }
    }

    let scan_elapsed = scan_start.elapsed();
    println!();
    println!(
        "✓ Scan complete in {:.2?} ({:.0} entries/sec)",
        scan_elapsed,
        entry_count as f64 / scan_elapsed.as_secs_f64()
    );
    println!();

    Ok(biggest)
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let (index_path, chunks_path) = if args.len() < 2 {
        (Path::new(DEFAULT_INDEX_PATH), Path::new(DEFAULT_CHUNKS_PATH))
    } else if args.len() == 2 {
        (Path::new(&args[1]), Path::new(DEFAULT_CHUNKS_PATH))
    } else {
        (Path::new(&args[1]), Path::new(&args[2]))
    };

    match find_biggest_entry(index_path, chunks_path) {
        Ok(biggest) => {
            println!("=== Result ===");
            println!();
            println!("Biggest UTXO entry found:");
            println!("  Index:         {} (0x{:x})", biggest.index, biggest.index);
            println!("  Script hash:   {}", bin2hex(&biggest.script_hash));
            println!("  Start offset:  {} (0x{:x})", biggest.start_offset, biggest.start_offset);
            println!("  Size:          {} ({} bytes)", format_size(biggest.size), biggest.size);
            println!();
        }
        Err(e) => {
            eprintln!("✗ Error: {}", e);
            std::process::exit(1);
        }
    }
}