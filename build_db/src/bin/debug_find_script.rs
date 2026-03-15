//! Debug tool to find a script pubkey by its RIPEMD160 hash in UTXO snapshot
//!
//! This script reads a UTXO snapshot file and searches for a UTXO
//! whose script's RIPEMD160 hash matches the target value.
//!
//! Usage:
//!   debug_find_script <utxo_snapshot_file>
//!
//! Example:
//!   debug_find_script /path/to/utxo.dat

use bitcoin::hashes::{ripemd160, Hash};
use std::env;
use std::io::{self, Write};
use std::path::Path;
use txoutset::Dump;

/// Target RIPEMD160 hash to search for (20 bytes)
/// First 20 bytes of: c1d142de046d07eb91e32d161ca0ccfecd32d3cc
const TARGET_HASH: [u8; 20] = [
    0xc1, 0xd1, 0x42, 0xde, 0x04, 0x6d, 0x07, 0xeb, 0x91, 0xe3,
    0x2d, 0x16, 0x1c, 0xa0, 0xcc, 0xfe, 0xcd, 0x32, 0xd3, 0xcc,
];

/// Convert bytes to hex string
fn bin2hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
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

/// Process the UTXO snapshot and search for the target hash
fn process_utxo_snapshot(snapshot_path: &Path) -> Result<(), String> {
    println!();
    println!("[1] Opening UTXO snapshot...");
    println!("    Snapshot path: {}", snapshot_path.display());
    println!("    Target RIPEMD160 hash: {}", bin2hex(&TARGET_HASH));

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
    let start_time = std::time::Instant::now();

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
                "\rProgress: {:.1}% | ETA: {} | Entries: {}",
                current_permille as f64 / 10.0,
                eta_str,
                entry_count
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
        if script_hash_array == TARGET_HASH {
            let txid = txout.out_point.txid;
            let vout = txout.out_point.vout;
            let height = txout.height;
            let amount: u64 = txout.amount.into();

            println!();
            println!();
            println!("========== FOUND MATCH! ==========");
            println!();
            println!("TXID:                 {}", txid);
            println!("Vout:                 {}", vout);
            println!("Block Height:         {}", height);
            println!(
                "Amount:               {} satoshis ({} BTC)",
                amount,
                amount as f64 / 100_000_000.0
            );
            println!("Script hex:           {}", bin2hex(script.as_bytes()));
            println!("Script len:           {} bytes", script.len());
            println!("RIPEMD160 hash:       {}", bin2hex(&script_hash_array));
            println!();

            // Try to decode the script type
            let script_bytes = script.as_bytes();
            if script_bytes.is_empty() {
                println!("Script type:          Empty script");
            } else if script_bytes.len() == 25
                && script_bytes[0] == 0x76
                && script_bytes[1] == 0xa9
                && script_bytes[2] == 0x14
                && script_bytes[23] == 0x88
                && script_bytes[24] == 0xac
            {
                // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
                println!("Script type:          P2PKH (Pay to Public Key Hash)");
                println!("Public Key Hash:      {}", bin2hex(&script_bytes[3..23]));
            } else if script_bytes.len() == 23
                && script_bytes[0] == 0xa9
                && script_bytes[1] == 0x14
                && script_bytes[22] == 0x87
            {
                // P2SH: OP_HASH160 <20 bytes> OP_EQUAL
                println!("Script type:          P2SH (Pay to Script Hash)");
                println!("Script Hash:          {}", bin2hex(&script_bytes[2..22]));
            } else if script_bytes.len() == 22 && script_bytes[0] == 0x00 && script_bytes[1] == 0x14 {
                // P2WPKH: OP_0 <20 bytes>
                println!("Script type:          P2WPKH (Pay to Witness Public Key Hash)");
                println!("Witness Program:      {}", bin2hex(&script_bytes[2..22]));
            } else if script_bytes.len() == 34 && script_bytes[0] == 0x00 && script_bytes[1] == 0x20 {
                // P2WSH: OP_0 <32 bytes>
                println!("Script type:          P2WSH (Pay to Witness Script Hash)");
                println!("Witness Program:      {}", bin2hex(&script_bytes[2..34]));
            } else {
                println!("Script type:          Unknown/non-standard");
            }

            println!();
            println!("==================================");

            // Continue searching for more matches (there might be multiple UTXOs with same script)
        }
    }

    let elapsed = start_time.elapsed();

    println!();
    println!(
        "\rProgress: 100.0% | Complete | Entries: {}",
        entry_count
    );
    println!();
    println!("=== Summary ===");
    println!("Total entries scanned: {}", entry_count);
    println!("Target hash: {}", bin2hex(&TARGET_HASH));
    println!("Time elapsed: {:.2?}", elapsed);
    println!(
        "Entries per second: {:.0}",
        entry_count as f64 / elapsed.as_secs_f64()
    );

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

    println!("=== Find Script by RIPEMD160 Hash ===");
    println!("snapshot: {}", snapshot_path.display());
    println!("target hash: {}", bin2hex(&TARGET_HASH));
    println!();

    // Process UTXO snapshot
    if let Err(e) = process_utxo_snapshot(snapshot_path) {
        eprintln!("✗ {}", e);
        std::process::exit(1);
    }

    println!();
    println!("Done.");
}