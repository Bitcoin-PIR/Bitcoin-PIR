//! Search for a TXID in txid.bin file
//!
//! Usage: cargo run --bin search_txid -- <txid>
//! Example: cargo run --bin search_txid -- 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
//!
//! This tool performs a linear scan of the txid.bin file to find the given TXID.

use std::env;
use std::fs::File;
use std::io::{BufReader, Read};
use std::str::FromStr;
use std::time::{Duration, Instant};

use bitcoin::hashes::Hash;
use bitcoin::Txid;

const TXID_FILE: &str = "/Volumes/Bitcoin/data/txid.bin";
const BUFFER_SIZE: usize = 8 * 1024 * 1024; // 8MB buffer for reading

/// Print a progress indicator
fn print_progress(txs_checked: u64, elapsed: Duration) {
    let txs_per_sec = if elapsed.as_secs() > 0 {
        txs_checked as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };

    eprint!(
        "\rChecked {} transactions... ({:.1} tx/s)",
        txs_checked, txs_per_sec
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <txid>", args[0]);
        eprintln!();
        eprintln!("Search for a transaction ID in {}", TXID_FILE);
        eprintln!();
        eprintln!("Arguments:");
        eprintln!("  <txid>    Transaction ID (64 hex characters)");
        eprintln!();
        eprintln!("Example:");
        eprintln!(
            "  {} 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            args[0]
        );
        eprintln!();
        eprintln!("The TXID can be in either normal or reversed byte order.");
        std::process::exit(1);
    }

    let txid_str = &args[1];

    // Parse the TXID (bitcoin crate accepts both normal and reversed order)
    let target_txid = match Txid::from_str(txid_str) {
        Ok(txid) => txid,
        Err(e) => {
            eprintln!("Error: Invalid TXID format: {}", e);
            eprintln!("TXID must be 64 hexadecimal characters.");
            std::process::exit(1);
        }
    };

    let target_bytes: [u8; 32] = target_txid.to_byte_array();

    println!("=== TXID Search Tool ===");
    println!("Searching for TXID: {}", txid_str);
    println!("Target bytes (hex): {}", hex::encode(target_bytes));
    println!("File: {}", TXID_FILE);
    println!();

    // Open the file
    let file = match File::open(TXID_FILE) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error: Failed to open file '{}': {}", TXID_FILE, e);
            std::process::exit(1);
        }
    };

    // Get file size
    let file_size = match file.metadata() {
        Ok(m) => m.len(),
        Err(e) => {
            eprintln!("Error: Failed to get file metadata: {}", e);
            std::process::exit(1);
        }
    };

    let total_txs = file_size / 32;
    println!("File size: {} bytes", file_size);
    println!("Total transactions in file: {}", total_txs);
    println!("Performing linear search...");
    println!();

    // Create buffered reader
    let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);

    let start_time = Instant::now();
    let mut txs_checked: u64 = 0;
    let mut buffer = [0u8; 32];
    let mut found = false;
    let mut position: u64 = 0;

    // Linear scan through the file
    while txs_checked < total_txs {
        // Read 32 bytes for one TXID
        match reader.read_exact(&mut buffer) {
            Ok(_) => {
                // Compare with target TXID
                if buffer == target_bytes {
                    found = true;
                    position = txs_checked;
                    break;
                }

                txs_checked += 1;

                // Print progress every 100,000 transactions
                if txs_checked % 100_000 == 0 {
                    print_progress(txs_checked, start_time.elapsed());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // End of file reached
                eprintln!();
                break;
            }
            Err(e) => {
                eprintln!();
                eprintln!("Error reading file: {}", e);
                std::process::exit(1);
            }
        }
    }

    let elapsed = start_time.elapsed();

    // Clear progress line
    eprint!("\r{:80}\r", " ");

    println!();
    println!("=== Results ===");
    println!("Transactions checked: {}", txs_checked);
    println!("Time elapsed: {:.2} seconds", elapsed.as_secs_f64());

    if txs_checked > 0 {
        println!(
            "Search speed: {:.1} tx/s",
            txs_checked as f64 / elapsed.as_secs_f64()
        );
    }
    println!();

    if found {
        println!("✓ TXID FOUND!");
        println!("Position in file: transaction #{}", position);
        println!("Byte offset: {} bytes", position * 32);
    } else {
        println!("✗ TXID NOT FOUND in file");
        println!();
        println!("Possible reasons:");
        println!("  - The TXID is not in this file");
        println!("  - The TXID is from a block that hasn't been indexed yet");
        println!("  - The TXID format is incorrect");
    }
}
