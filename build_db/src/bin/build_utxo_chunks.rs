//! Build UTXO chunks from the remapped UTXO set
//!
//! Reads `/Volumes/Bitcoin/data/remapped_utxo_set.bin` (40-byte entries),
//! groups entries by ScriptPubKey hash, and writes compact output to:
//! - `/Volumes/Bitcoin/data/utxo_chunks.bin`      — compact UTXO data by address
//! - `/Volumes/Bitcoin/data/utxo_chunks_index.bin` — index (script_hash → offset)
//!
//! Input entry format (40 bytes each):
//!   [0..20)  ScriptPubKey hash (RIPEMD-160)
//!   [20..24) TXID  (u32 LE, mapped via MPHF)
//!   [24..28) vout  (u32 LE)
//!   [28..32) height (u32 LE)
//!   [32..40) amount (u64 LE)
//!
//! Output chunk format (utxo_chunks.bin):
//!   For each group (no script_hash prefix — use the index to find groups):
//!     [varint entry_count]
//!     Entry 0: [4B txid LE] [varint vout] [varint amount]
//!     Entry i>0: [varint delta_txid] [varint vout] [varint amount]
//!   (entries sorted by height descending; delta_txid = prev_txid wrapping_sub this_txid)
//!
//! Output index format (utxo_chunks_index.bin):
//!   For each group: [20B script_hash] [8B start_offset u64 LE]

use memmap2::Mmap;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::time::Instant;

/// Input file path
const INPUT_FILE: &str = "/Volumes/Bitcoin/data/remapped_utxo_set.bin";

/// Output file paths
const CHUNKS_FILE: &str = "/Volumes/Bitcoin/data/utxo_chunks.bin";
const INDEX_FILE: &str = "/Volumes/Bitcoin/data/utxo_chunks_index.bin";

/// Size of each input entry in bytes
const ENTRY_SIZE: usize = 40;

/// Size of the ScriptPubKey hash
const SCRIPT_HASH_SIZE: usize = 20;

/// A shortened UTXO entry (fields 2–5 from the original 40-byte record)
#[derive(Clone, Copy)]
struct ShortenedEntry {
    txid: u32,
    vout: u32,
    height: u32,
    amount: u64,
}

/// Write a value as unsigned LEB128 (VarInt) to a writer.
/// Returns the number of bytes written.
#[inline]
fn write_varint(writer: &mut impl Write, mut value: u64) -> io::Result<usize> {
    let mut bytes_written = 0usize;
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        writer.write_all(&[byte])?;
        bytes_written += 1;
        if value == 0 {
            break;
        }
    }
    Ok(bytes_written)
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

fn main() {
    println!("=== Build UTXO Chunks ===");
    println!();

    let total_start = Instant::now();

    // ── Step 1: Memory-map the input file ──────────────────────────────
    println!("[1] Memory-mapping input file...");
    println!("    Path: {}", INPUT_FILE);

    let input_file = File::open(INPUT_FILE).unwrap_or_else(|e| {
        eprintln!("✗ Failed to open input file: {}", e);
        std::process::exit(1);
    });

    let mmap = unsafe { Mmap::map(&input_file) }.unwrap_or_else(|e| {
        eprintln!("✗ Failed to mmap input file: {}", e);
        std::process::exit(1);
    });

    let file_size = mmap.len();
    if file_size % ENTRY_SIZE != 0 {
        eprintln!(
            "✗ Input file size ({}) is not a multiple of entry size ({})",
            file_size, ENTRY_SIZE
        );
        std::process::exit(1);
    }

    let entry_count = file_size / ENTRY_SIZE;
    println!(
        "✓ Mapped {} bytes ({:.2} GB), {} entries",
        file_size,
        file_size as f64 / (1024.0 * 1024.0 * 1024.0),
        entry_count
    );
    println!();

    // ── Step 2: Build the HashMap ──────────────────────────────────────
    println!("[2] Building HashMap (grouping by ScriptPubKey hash)...");
    let step2_start = Instant::now();

    // Pre-allocate with an estimate of unique addresses
    // (~50-80M unique ScriptPubKey hashes expected)
    let mut map: HashMap<[u8; 20], Vec<ShortenedEntry>> =
        HashMap::with_capacity(80_000_000);

    let one_percent = std::cmp::max(1, entry_count / 100);
    let mut last_pct = 0u64;

    for i in 0..entry_count {
        let base = i * ENTRY_SIZE;
        let chunk = &mmap[base..base + ENTRY_SIZE];

        // Extract ScriptPubKey hash (first 20 bytes)
        let mut script_hash = [0u8; 20];
        script_hash.copy_from_slice(&chunk[..SCRIPT_HASH_SIZE]);

        // Parse shortened entry (bytes 20..40)
        let txid = u32::from_le_bytes([chunk[20], chunk[21], chunk[22], chunk[23]]);
        let vout = u32::from_le_bytes([chunk[24], chunk[25], chunk[26], chunk[27]]);
        let height = u32::from_le_bytes([chunk[28], chunk[29], chunk[30], chunk[31]]);
        let amount = u64::from_le_bytes([
            chunk[32], chunk[33], chunk[34], chunk[35],
            chunk[36], chunk[37], chunk[38], chunk[39],
        ]);

        map.entry(script_hash)
            .or_insert_with(Vec::new)
            .push(ShortenedEntry {
                txid,
                vout,
                height,
                amount,
            });

        // Progress reporting
        let current_pct = (i as u64 + 1) / one_percent as u64;
        if current_pct > last_pct && current_pct <= 100 {
            let elapsed = step2_start.elapsed().as_secs_f64();
            let frac = current_pct as f64 / 100.0;
            let eta = if frac > 0.0 {
                (elapsed / frac) * (1.0 - frac)
            } else {
                0.0
            };
            print!(
                "\r    Building: {}% | ETA: {} | Entries: {}/{} | Unique keys: {}",
                current_pct,
                format_duration(eta),
                i + 1,
                entry_count,
                map.len()
            );
            io::stdout().flush().ok();
            last_pct = current_pct;
        }
    }
    println!();

    let unique_keys = map.len();
    let step2_elapsed = step2_start.elapsed();
    println!(
        "✓ HashMap built in {:.2?} — {} entries, {} unique ScriptPubKey hashes",
        step2_elapsed, entry_count, unique_keys
    );
    println!();

    // ── Step 3: Open output files ──────────────────────────────────────
    println!("[3] Opening output files...");
    println!("    Chunks: {}", CHUNKS_FILE);
    println!("    Index:  {}", INDEX_FILE);

    let chunks_file = File::create(CHUNKS_FILE).unwrap_or_else(|e| {
        eprintln!("✗ Failed to create chunks file: {}", e);
        std::process::exit(1);
    });
    let mut chunks_writer = BufWriter::with_capacity(1024 * 1024, chunks_file);

    let index_file = File::create(INDEX_FILE).unwrap_or_else(|e| {
        eprintln!("✗ Failed to create index file: {}", e);
        std::process::exit(1);
    });
    let mut index_writer = BufWriter::with_capacity(1024 * 1024, index_file);

    println!("✓ Output files opened");
    println!();

    // ── Step 4: Process groups, write compact output ───────────────────
    println!("[4] Processing {} groups and writing output...", unique_keys);
    let step4_start = Instant::now();

    let mut current_offset: u64 = 0; // tracks byte position in utxo_chunks.bin
    let mut groups_written: u64 = 0;
    let mut total_entries_written: u64 = 0;
    let one_percent_groups = std::cmp::max(1, unique_keys / 100);
    let mut last_group_pct = 0u64;

    // drain() consumes entries from the HashMap, freeing memory progressively
    for (script_hash, mut entries) in map.drain() {
        // 4a. Sort entries by height descending (higher heights first)
        entries.sort_unstable_by(|a, b| b.height.cmp(&a.height));

        // 4b. Record start offset for the index
        let start_offset = current_offset;

        // 4c. Write to utxo_chunks.bin
        //     First: write varint entry count, then the entries themselves
        let n = write_varint(&mut chunks_writer, entries.len() as u64).unwrap_or_else(|e| {
            eprintln!("✗ Failed to write entry count: {}", e);
            std::process::exit(1);
        });
        current_offset += n as u64;

        let mut prev_txid: u32 = 0;

        for (i, entry) in entries.iter().enumerate() {
            if i == 0 {
                // First entry: write raw 4-byte TXID (LE)
                chunks_writer
                    .write_all(&entry.txid.to_le_bytes())
                    .unwrap_or_else(|e| {
                        eprintln!("✗ Failed to write txid: {}", e);
                        std::process::exit(1);
                    });
                current_offset += 4;
            } else {
                // Subsequent entries: write VarInt(prev_txid wrapping_sub this_txid)
                let delta = prev_txid.wrapping_sub(entry.txid) as u64;
                let n = write_varint(&mut chunks_writer, delta).unwrap_or_else(|e| {
                    eprintln!("✗ Failed to write txid delta: {}", e);
                    std::process::exit(1);
                });
                current_offset += n as u64;
            }
            prev_txid = entry.txid;

            // Write vout as VarInt
            let n = write_varint(&mut chunks_writer, entry.vout as u64).unwrap_or_else(|e| {
                eprintln!("✗ Failed to write vout: {}", e);
                std::process::exit(1);
            });
            current_offset += n as u64;

            // Write amount as VarInt
            let n = write_varint(&mut chunks_writer, entry.amount).unwrap_or_else(|e| {
                eprintln!("✗ Failed to write amount: {}", e);
                std::process::exit(1);
            });
            current_offset += n as u64;

            total_entries_written += 1;
        }

        if start_offset > u32::MAX as u64 {
            eprintln!("✗ Start offset {} exceeds u32 max value, cannot be stored in index", start_offset);
            std::process::exit(1);
        }

        // 4d. Write to utxo_chunks_index.bin
        // [20B script_hash] [4B start_offset LE]
        index_writer.write_all(&script_hash).unwrap_or_else(|e| {
            eprintln!("✗ Failed to write index script hash: {}", e);
            std::process::exit(1);
        });
        index_writer
            .write_all(&(start_offset as u32).to_le_bytes())
            .unwrap_or_else(|e| {
                eprintln!("✗ Failed to write index offset: {}", e);
                std::process::exit(1);
            });

        groups_written += 1;

        // Progress reporting
        let current_pct = groups_written / one_percent_groups as u64;
        if current_pct > last_group_pct && current_pct <= 100 {
            let elapsed = step4_start.elapsed().as_secs_f64();
            let frac = current_pct as f64 / 100.0;
            let eta = if frac > 0.0 {
                (elapsed / frac) * (1.0 - frac)
            } else {
                0.0
            };
            print!(
                "\r    Writing: {}% | ETA: {} | Groups: {}/{} | Entries: {} | Chunks size: {:.2} MB",
                current_pct,
                format_duration(eta),
                groups_written,
                unique_keys,
                total_entries_written,
                current_offset as f64 / (1024.0 * 1024.0)
            );
            io::stdout().flush().ok();
            last_group_pct = current_pct;
        }
    }
    println!();

    // ── Step 5: Flush and report ───────────────────────────────────────
    println!();
    println!("[5] Flushing output files...");

    chunks_writer.flush().unwrap_or_else(|e| {
        eprintln!("✗ Failed to flush chunks file: {}", e);
        std::process::exit(1);
    });
    index_writer.flush().unwrap_or_else(|e| {
        eprintln!("✗ Failed to flush index file: {}", e);
        std::process::exit(1);
    });

    let step4_elapsed = step4_start.elapsed();
    let total_elapsed = total_start.elapsed();

    println!("✓ Done!");
    println!();
    println!("=== Summary ===");
    println!("Input entries:        {}", entry_count);
    println!("Unique addresses:     {}", unique_keys);
    println!("Entries written:      {}", total_entries_written);
    println!("Groups written:       {}", groups_written);
    println!();
    println!(
        "Chunks file size:     {} bytes ({:.2} MB)",
        current_offset,
        current_offset as f64 / (1024.0 * 1024.0)
    );
    let index_size = groups_written * 24;
    println!(
        "Index file size:      {} bytes ({:.2} MB)",
        index_size,
        index_size as f64 / (1024.0 * 1024.0)
    );
    println!();

    // Compression ratio
    let original_size = entry_count as f64 * ENTRY_SIZE as f64;
    let compact_size = current_offset as f64 + index_size as f64;
    println!(
        "Original size:        {:.2} MB",
        original_size / (1024.0 * 1024.0)
    );
    println!(
        "Compact size:         {:.2} MB (chunks + index)",
        compact_size / (1024.0 * 1024.0)
    );
    println!(
        "Compression ratio:    {:.2}x",
        original_size / compact_size
    );
    println!();
    println!("HashMap build time:   {:.2?}", step2_elapsed);
    println!("Write time:           {:.2?}", step4_elapsed);
    println!("Total time:           {:.2?}", total_elapsed);
}
