//! Count UTXOs for a specific script pubkey in UTXO snapshot
//!
//! This script reads a UTXO snapshot file and counts all UTXOs
//! whose script's RIPEMD160 hash matches the target value.
//!
//! Usage:
//!   debug_count_utxo_script <utxo_snapshot_file> <script_hex>
//!
//! Example:
//!   debug_count_utxo_script /path/to/utxo.dat 76a914b64513c1f1b889a556463243cca9c26ee626b9a088ac

use bitcoin::hashes::{ripemd160, Hash};
use std::env;
use std::io::{self, Write};
use std::path::Path;
use std::time::Instant;
use txoutset::Dump;

/// Convert bytes to hex string
fn bin2hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Convert hex string to bytes
fn hex2bin(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim();
    if hex.len() % 2 != 0 {
        return Err("Hex string must have even length".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("Invalid hex character: {}", e))
        })
        .collect()
}

/// Format duration in seconds to a human-readable string
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

/// Process the UTXO snapshot and count UTXOs for target hash
fn process_utxo_snapshot(snapshot_path: &Path, target_hash: &[u8; 20]) -> Result<(u64, u64), String> {
    println!();
    println!("[1] Opening UTXO snapshot...");
    println!("    Snapshot path: {}", snapshot_path.display());
    println!("    Target RIPEMD160 hash: {}", bin2hex(target_hash));

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

    println!();
    println!("[2] Scanning UTXOs for target hash...");
    println!();

    let mut entry_count: u64 = 0;
    let mut match_count: u64 = 0;
    let mut total_amount: u64 = 0;
    let start_time = Instant::now();

    let total_entries = dump.utxo_set_size;
    let report_interval = std::cmp::max(1, total_entries / 1000);
    let mut last_reported_permille = 0u64;

    // Iterate through UTXOs
    for txout in dump {
        entry_count += 1;

        // Update progress
        let current_permille = entry_count / report_interval;
        if current_permille > last_reported_permille && current_permille <= 1000 {
            let elapsed = start_time.elapsed().as_secs_f64();
            let progress_fraction = current_permille as f64 / 1000.0;
            let eta_secs = if progress_fraction > 0.0 {
                (elapsed / progress_fraction) * (1.0 - progress_fraction)
            } else {
                0.0
            };
            let eta_str = format_duration(eta_secs);
            print!(
                "\rProgress: {:.1}% | ETA: {} | Entries: {} | Found: {} ({:.4} BTC)",
                current_permille as f64 / 10.0,
                eta_str,
                entry_count,
                match_count,
                total_amount as f64 / 100_000_000.0
            );
            io::stdout().flush().ok();
            last_reported_permille = current_permille;
        }

        // Get script pubkey
        let script = &txout.script_pubkey;

        // Compute RIPEMD-160 hash of the script
        let script_hash = ripemd160::Hash::hash(script.as_bytes());
        let script_hash_array: [u8; 20] = script_hash.to_byte_array();

        // Check if this matches our target
        if script_hash_array == *target_hash {
            match_count += 1;
            total_amount += u64::from(txout.amount);
        }
    }

    let elapsed = start_time.elapsed();

    println!();
    println!(
        "\rProgress: 100.0% | Complete | Entries: {} | Found: {} ({:.8} BTC)",
        entry_count, match_count, total_amount as f64 / 100_000_000.0
    );
    println!();
    println!("=== Summary ===");
    println!("Total entries scanned: {}", entry_count);
    println!("Target hash: {}", bin2hex(target_hash));
    println!("Matching UTXOs: {}", match_count);
    println!("Total amount: {} satoshis ({:.8} BTC)", total_amount, total_amount as f64 / 100_000_000.0);
    println!("Time elapsed: {:.2?}", elapsed);
    println!(
        "Entries per second: {:.0}",
        entry_count as f64 / elapsed.as_secs_f64()
    );

    Ok((match_count, total_amount))
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} <utxo_snapshot_file> <script_hex>", args[0]);
        eprintln!();
        eprintln!("Arguments:");
        eprintln!("  utxo_snapshot_file  Path to UTXO snapshot (created by bitcoin-cli dumptxoutset)");
        eprintln!("  script_hex          Script pubkey in hex format");
        eprintln!();
        eprintln!("Example:");
        eprintln!("  {} /path/to/utxo.dat 76a914b64513c1f1b889a556463243cca9c26ee626b9a088ac", args[0]);
        std::process::exit(1);
    }

    let snapshot_path = Path::new(&args[1]);
    let script_hex = &args[2];

    // Parse script hex
    let script = match hex2bin(script_hex) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error parsing script hex: {}", e);
            std::process::exit(1);
        }
    };

    // Compute RIPEMD160 hash
    let script_hash = ripemd160::Hash::hash(&script);
    let target_hash: [u8; 20] = script_hash.to_byte_array();

    println!("=== Count UTXO by Script ===");
    println!("Script hex:   {}", script_hex);
    println!("Script bytes: {} bytes", script.len());
    println!("RIPEMD160:    {}", bin2hex(&target_hash));
    println!("Snapshot:     {}", snapshot_path.display());
    println!();

    // Process UTXO snapshot
    if let Err(e) = process_utxo_snapshot(snapshot_path, &target_hash) {
        eprintln!("✗ {}", e);
        std::process::exit(1);
    }

    println!();
    println!("Done.");
}