//! Tool to build remapped UTXO set from Bitcoin Core UTXO snapshot
//!
//! This tool reads a UTXO snapshot file created by `bitcoin-cli dumptxoutset`
//! and produces a remapped UTXO set for the PIR system.
//!
//! Features:
//! 1. Read UTXO snapshot file (created by `bitcoin-cli dumptxoutset`)
//! 2. Map 32-byte TXID to 4-byte TXID using MPHF + txid_locations.bin lookup
//! 3. Compute RIPEMD-160 hash of script
//! 4. Write remapped UTXO entries to output file
//!
//! Output format per UTXO (36 bytes):
//! - 20 bytes: RIPEMD-160 hash of script
//! - 4 bytes: TXID (looked up from txid_locations.bin using MPHF hash as index)
//! - 4 bytes: vout (u32)
//! - 8 bytes: amount (u64)
//!
//! Usage:
//!   gen_4_utxo_remapped <utxo_snapshot_file>
//!
//! Example:
//!   gen_4_utxo_remapped /path/to/utxo.dat

use bitcoin::hashes::{ripemd160, Hash};
use bitcoinpir::mpfh::Mphf;
use bitcoinpir::utils;
use memmap2::Mmap;
use std::env;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::time::Instant;
use txoutset::Dump;

/// Path to the MPHF file for TXID mapping
const MPHF_FILE: &str = "/Volumes/Bitcoin/data/txid_mphf.bin";

/// Path to the txid_locations.bin file (MPHF hash -> txid_index mapping)
const TXID_LOCATIONS_FILE: &str = "/Volumes/Bitcoin/data/txid_locations.bin";

/// Output file for remapped UTXO set
const OUTPUT_FILE: &str = "/Volumes/Bitcoin/data/remapped_utxo_set.bin";


/// Load txid_locations.bin as a memory-mapped file
/// This file maps MPHF hash -> txid_index (position in txid.bin)
/// Each entry is 4 bytes (u32), so for MPHF hash x, the txid_index is at offset 4*x
fn load_txid_locations(path: &Path) -> Result<Mmap, String> {
    println!("Loading txid_locations from {}...", path.display());

    let file = File::open(path).map_err(|e| format!("Failed to open txid_locations file: {}", e))?;

    let metadata = file.metadata().map_err(|e| format!("Failed to get file metadata: {}", e))?;
    println!(
        "txid_locations file size: {} bytes ({:.2} GB)",
        metadata.len(),
        metadata.len() as f64 / 1e9
    );

    let mmap = unsafe { Mmap::map(&file) }
        .map_err(|e| format!("Failed to memory-map txid_locations file: {}", e))?;

    println!("txid_locations memory-mapped successfully");
    Ok(mmap)
}

/// Look up the actual 4-byte TXID from txid_locations.bin
/// Given the MPHF hash, read 4 bytes at offset 4*hash to get the txid_index
#[inline]
fn lookup_txid_4b(locations: &Mmap, mphf_hash: u64) -> u32 {
    let offset = (mphf_hash * 4) as usize;
    u32::from_le_bytes([
        locations[offset],
        locations[offset + 1],
        locations[offset + 2],
        locations[offset + 3],
    ])
}

/// Convert bytes to hex string
fn bin2hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Write a remapped UTXO entry to the output file
/// Format: script_hash (20B RIPEMD-160) + txid_4b (4B) + vout (4B) + amount (8B) = 36 bytes
fn write_remapped_utxo(
    writer: &mut BufWriter<File>,
    script_hash: &[u8; 20],
    txid_4b: u32,
    vout: u32,
    amount: u64,
) -> io::Result<()> {
    // Write script hash (20 bytes - RIPEMD-160)
    writer.write_all(script_hash)?;

    // Write 4-byte TXID (little-endian)
    writer.write_all(&txid_4b.to_le_bytes())?;

    // Write vout (4 bytes, little-endian)
    writer.write_all(&vout.to_le_bytes())?;

    // Write amount (8 bytes, little-endian)
    writer.write_all(&amount.to_le_bytes())?;

    Ok(())
}

/// Process the UTXO snapshot and write remapped UTXOs
fn process_utxo_snapshot(
    snapshot_path: &Path,
    mphf: &Mphf<[u8; 32]>,
    txid_locations: &Mmap,
) -> Result<(), String> {
    println!();
    println!("[1] Opening UTXO snapshot...");
    println!("    Snapshot path: {}", snapshot_path.display());

    // Check snapshot file exists
    if !snapshot_path.exists() {
        return Err(format!(
            "snapshot file does not exist: {}",
            snapshot_path.display()
        ));
    }

    // Open the dump (compute_addresses = false)
    let dump = match Dump::new(snapshot_path, txoutset::ComputeAddresses::No) {
        Ok(dump) => dump,
        Err(e) => return Err(format!("Unable to open UTXO snapshot: {:?}", e)),
    };

    println!("    Block hash: {}", dump.block_hash);
    println!("    UTXO set size: {}", dump.utxo_set_size);

    let total_entries = dump.utxo_set_size;

    // Open output file for writing remapped UTXOs
    println!();
    println!("[2] Opening output file: {}", OUTPUT_FILE);
    let output_file =
        File::create(OUTPUT_FILE).map_err(|e| format!("Failed to create output file: {}", e))?;
    let mut writer = BufWriter::with_capacity(1024 * 1024, output_file); // 1MB buffer

    println!();
    println!("[3] Processing UTXOs...");
    println!();

    // Set variables
    let mut total_utxos: u64 = 0;
    let mut total_amount: u64 = 0;
    let mut entry_count: u64 = 0;
    let mut txid_cache_hits: u64 = 0;
    let mut txid_mphf_lookups: u64 = 0;
    let mut txid_mappings_successful: u64 = 0;
    let start_time = Instant::now();

    // Local cache for TXID mapping (previous 32B TXID -> 4B TXID)
    let mut cached_txid: Option<[u8; 32]> = None;
    let mut cached_txid_4b: Option<u32> = None;

    // Progress tracking (every 0.1%)
    let one_tenth_percent = std::cmp::max(1, total_entries / 1000);
    let mut last_reported_permille = 0u64;

    // Iterate through UTXOs
    for txout in dump {
        entry_count += 1;

        // Update progress every 0.1%
        let current_permille = entry_count / one_tenth_percent;
        if current_permille > last_reported_permille && current_permille <= 1000 {
            let elapsed = start_time.elapsed().as_secs_f64();
            let progress_fraction = current_permille as f64 / 1000.0;
            let eta_secs = if progress_fraction > 0.0 {
                (elapsed / progress_fraction) * (1.0 - progress_fraction)
            } else {
                0.0
            };
            let eta_str = utils::format_duration(eta_secs);
            print!(
                "\rProcessing: {:.1}% | ETA: {} | Entries: {}/{} | UTXOs: {} | Cache hits: {}",
                current_permille as f64 / 10.0,
                eta_str,
                entry_count,
                total_entries,
                total_utxos,
                txid_cache_hits
            );
            io::stdout().flush().ok();
            last_reported_permille = current_permille;
        }

        // Get TXID bytes (little-endian)
        let txid_bytes = txout.out_point.txid.to_byte_array();

        // Skip TXIDs that caused issues during MPHF construction
        if utils::should_skip(&txid_bytes) {
            continue;
        }

        // Get height and vout
        let height = txout.height;
        let vout = txout.out_point.vout;

        // Skip entries with height >= our MPHF limit
        if height >= 940_612 {
            continue;
        }

        // Get amount
        let amount: u64 = txout.amount.into();

        // Get script pubkey
        let script = txout.script_pubkey;

        // Map TXID to 4-byte using MPHF + txid_locations.bin lookup with local cache
        let txid_4b = if cached_txid == Some(txid_bytes) {
            // Cache hit - use cached 4B TXID
            txid_cache_hits += 1;
            cached_txid_4b.unwrap()
        } else {
            // Cache miss - lookup in MPHF using try_hash
            txid_mphf_lookups += 1;
            match mphf.try_hash(&txid_bytes) {
                Some(mphf_hash) => {
                    // MPHF found - now lookup the actual 4-byte TXID from txid_locations.bin
                    let actual_txid_4b = lookup_txid_4b(txid_locations, mphf_hash);

                    // Successfully mapped - increment counter
                    txid_mappings_successful += 1;

                    // Update cache
                    cached_txid = Some(txid_bytes);
                    cached_txid_4b = Some(actual_txid_4b);

                    actual_txid_4b
                }
                None => {
                    // TXID not found in MPHF - try reversed version for debugging
                    let mut reversed_txid = txid_bytes;
                    reversed_txid.reverse();

                    match mphf.try_hash(&reversed_txid) {
                        Some(hash) => {
                            // Reversed version found - this indicates byte order issue
                            eprintln!("!!! DEBUG: TXID not found in MPHF");
                            eprintln!("    Original:           {}", bin2hex(&txid_bytes));
                            eprintln!("    Reversed:           {}", bin2hex(&reversed_txid));
                            eprintln!("    Reversed version found with hash: {}", hash);
                            eprintln!("    Its script hex:     {}", bin2hex(script.as_bytes()));
                            eprintln!(
                                "    Successfully mapped TXIDs before this error: {}",
                                txid_mappings_successful
                            );
                            return Err(format!(
                                "TXID found only in reversed byte order: {} (reversed: {})",
                                bin2hex(&txid_bytes),
                                bin2hex(&reversed_txid)
                            ));
                        }
                        None => {
                            // Neither original nor reversed found
                            eprintln!("Warning: TXID not found in MPHF (neither original nor reversed): {}", bin2hex(&txid_bytes));
                            return Err(format!(
                                "TXID not found in MPHF (neither original nor reversed): {}",
                                bin2hex(&txid_bytes)
                            ));
                        }
                    }
                }
            }
        };

        // Compute RIPEMD-160 hash of the script
        let script_hash = ripemd160::Hash::hash(script.as_bytes());
        let script_hash_array: [u8; 20] = script_hash.to_byte_array();

        // Write remapped UTXO entry to output file
        if let Err(e) = write_remapped_utxo(
            &mut writer,
            &script_hash_array,
            txid_4b,
            vout,
            amount,
        ) {
            return Err(format!("Failed to write UTXO: {}", e));
        }

        // Count UTXOs
        total_utxos += 1;
        total_amount += amount;
    }

    // Flush the writer
    if let Err(e) = writer.flush() {
        return Err(format!("Failed to flush output file: {}", e));
    }

    let elapsed = start_time.elapsed();

    println!(
        "\rProcessing: 100.0% | Complete | Entries: {}/{} | UTXOs: {} | Cache hits: {}",
        entry_count, total_entries, total_utxos, txid_cache_hits
    );
    println!();
    println!("=== Summary ===");
    println!("Total entries: {}", entry_count);
    println!("Total UTXOs: {}", total_utxos);
    println!("Total amount: {} BTC", total_amount as f64 / 100_000_000.0);
    println!(
        "TXID cache hits: {} ({:.1}%)",
        txid_cache_hits,
        100.0 * txid_cache_hits as f64 / (txid_cache_hits + txid_mphf_lookups) as f64
    );
    println!("TXID MPHF lookups: {}", txid_mphf_lookups);
    println!("Successfully mapped TXIDs: {}", txid_mappings_successful);
    println!("Output file: {}", OUTPUT_FILE);
    println!("Time elapsed: {:.2?}", elapsed);
    println!(
        "Entries per second: {:.0}",
        entry_count as f64 / elapsed.as_secs_f64()
    );
    println!(
        "UTXOs per second: {:.0}",
        total_utxos as f64 / elapsed.as_secs_f64()
    );

    // Get output file size
    if let Ok(metadata) = std::fs::metadata(OUTPUT_FILE) {
        println!(
            "Output file size: {} bytes ({:.2} MB)",
            metadata.len(),
            metadata.len() as f64 / (1024.0 * 1024.0)
        );
        println!(
            "Average UTXO entry size: {} bytes",
            metadata.len() / total_utxos.max(1)
        );
    }

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <utxo_snapshot_file>", args[0]);
        eprintln!();
        eprintln!("Create a UTXO snapshot with: bitcoin-cli dumptxoutset <path>");
        std::process::exit(1);
    }

    let snapshot_path = Path::new(&args[1]);

    println!("=== Build Remapped UTXO from Snapshot ===");
    println!("snapshot: {}", snapshot_path.display());
    println!();

    // Load MPHF for TXID mapping
    println!("[0.1] Loading MPHF for TXID mapping...");
    let mphf_path = Path::new(MPHF_FILE);
    if !mphf_path.exists() {
        eprintln!("✗ MPHF file not found: {}", MPHF_FILE);
        eprintln!("  Please run build_mphf first to create the MPHF file.");
        std::process::exit(1);
    }

    let mphf = match utils::load_mphf(mphf_path) {
        Ok(mphf) => {
            println!("✓ MPHF loaded successfully");
            mphf
        }
        Err(e) => {
            eprintln!("✗ {}", e);
            std::process::exit(1);
        }
    };

    // Load txid_locations.bin for TXID mapping
    println!();
    println!("[0.2] Loading txid_locations.bin for TXID index lookup...");
    let txid_locations_path = Path::new(TXID_LOCATIONS_FILE);
    if !txid_locations_path.exists() {
        eprintln!("✗ txid_locations file not found: {}", TXID_LOCATIONS_FILE);
        eprintln!("  Please run build_location_index first to create the locations file.");
        std::process::exit(1);
    }

    let txid_locations = match load_txid_locations(txid_locations_path) {
        Ok(locations) => {
            println!("✓ txid_locations loaded successfully");
            locations
        }
        Err(e) => {
            eprintln!("✗ {}", e);
            std::process::exit(1);
        }
    };

    // Process UTXO snapshot
    if let Err(e) = process_utxo_snapshot(snapshot_path, &mphf, &txid_locations) {
        eprintln!("✗ {}", e);
        std::process::exit(1);
    }

    println!();
    println!("Done.");
}