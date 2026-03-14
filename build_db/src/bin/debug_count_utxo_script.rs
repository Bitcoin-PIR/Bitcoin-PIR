//! Count UTXOs for a specific script pubkey in Bitcoin chainstate
//!
//! This script reads the Bitcoin chainstate database and counts all UTXOs
//! whose script's RIPEMD160 hash matches the target value.
//!
//! Usage:
//!   count_utxo_by_script [script_hex] [datadir]
//!
//! Example:
//!   count_utxo_by_script 76a914b64513c1f1b889a556463243cca9c26ee626b9a088ac /Volumes/Bitcoin/bitcoin

use bitcoin::hashes::{ripemd160, Hash};
use nix::fcntl::{Flock, FlockArg};
use rusty_leveldb::{LdbIterator, Options, DB};
use secp256k1::PublicKey;
use std::env;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

/// Check if bitcoind process is running
fn is_bitcoind_running() -> Result<bool, String> {
    let output = Command::new("ps")
        .args(["aux"])
        .output()
        .map_err(|e| format!("Failed to execute ps aux: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "ps aux command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        if line.contains("grep") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 11 {
            let command = parts[10];
            if command == "bitcoind" || command.ends_with("/bitcoind") {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Create .lock file in datadir and acquire Advisory Lock
fn acquire_datadir_lock(datadir: &Path) -> Result<Flock<std::fs::File>, String> {
    let lock_path = datadir.join(".lock");

    if !datadir.exists() {
        return Err(format!("datadir does not exist: {}", datadir.display()));
    }

    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .mode(0o666)
        .open(&lock_path)
        .map_err(|e| format!("Failed to create/open .lock file: {}", e))?;

    match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
        Ok(flock) => Ok(flock),
        Err((_file, e)) => match e {
            nix::errno::Errno::EAGAIN => Err(format!(
                "Cannot acquire lock on .lock file: another process holds the lock ({})",
                lock_path.display()
            )),
            _ => Err(format!("Failed to acquire file lock: {}", e)),
        },
    }
}

/// Deobfuscate a value using the obfuscate key
fn deobfuscate(obfuscate_key: &[u8], value: &[u8]) -> Vec<u8> {
    if obfuscate_key.is_empty() {
        return value.to_vec();
    }

    let key_len = obfuscate_key.len();
    value
        .iter()
        .enumerate()
        .map(|(i, &byte)| byte ^ obfuscate_key[i % key_len])
        .collect()
}

/// Decode a UTXO key to extract txid and vout
fn decode_utxo_key(key: &[u8]) -> (Vec<u8>, u32) {
    let txid = key[1..33].to_vec();
    let vout = decode_varint(&key[33..]);
    (txid, vout)
}

/// Decode a varint from bytes
fn decode_varint(data: &[u8]) -> u32 {
    let mut result: u32 = 0;
    let mut shift = 0;

    for byte in data {
        let val = (*byte & 0x7f) as u32;
        result |= val << shift;

        if *byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }

    result
}

/// Read a varint chunk from the value at the given offset
fn read_chunk(data: &Vec<u8>, offset: usize) -> (u64, usize) {
    let length = get_vint(&data, &offset);
    let chunk: u64 = decode_vint(&length);
    let new_offset: usize = offset + length.len();
    (chunk, new_offset)
}

pub fn get_vint(data: &Vec<u8>, offset: &usize) -> Vec<u8> {
    let mut res: Vec<u8> = Vec::new();

    for x in *offset as u16..data.len() as u16 {
        res.push(data[x as usize]);

        if (data[x as usize] & 0b1000_0000) == 0 {
            return res;
        }
    }

    res
}

pub fn decode_vint(data: &Vec<u8>) -> u64 {
    let mut n: u64 = 0;
    for b in data {
        n = n << 7;
        n = n | (b & 127) as u64;
        if b & 128 != 0 {
            n = n + 1;
        }
    }
    n
}

pub fn convert_amount(input: u64) -> u64 {
    // Check for zero
    if input == 0 {
        return input;
    }

    // Decompress
    let e = (input - 1) % 10;
    let num = (input + 1) / 10;

    // If remainder less than 9
    let mut amount: f64;
    if e < 9 {
        let d: f64 = num as f64 % 9.0;
        amount = (num as f64 / 9.0) * 10.0 + d + 1.0;
    } else {
        amount = num as f64 + 1.0;
    }

    // Get final amount
    let base: f64 = 10.0;
    amount = amount * (base.powf(e as f64));

    amount as u64
}

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

/// Process the chainstate database and count UTXOs for target hash
fn process_chainstate(chainstate_dir: &Path, target_hash: &[u8; 20]) -> Result<(u64, u64), String> {
    println!();
    println!("[3] Opening chainstate database...");
    println!("    Chainstate path: {}", chainstate_dir.display());
    println!("    Target RIPEMD160 hash: {}", bin2hex(target_hash));

    if !chainstate_dir.exists() {
        return Err(format!(
            "chainstate directory does not exist: {}",
            chainstate_dir.display()
        ));
    }

    let options = Options {
        create_if_missing: false,
        reuse_logs: false,
        reuse_manifest: false,        
        compressor: 1, // Use Snappy compression for reading (Bitcoin Core uses Snappy)
        ..Default::default()
    };

    let mut db = match DB::open(chainstate_dir, options) {
        Ok(db) => db,
        Err(e) => return Err(format!("Unable to open LevelDB, error: {:?}", e)),
    };

    println!();
    println!("[4] Scanning UTXOs for target hash...");
    println!();

    let mut obfuscate_key: Vec<u8> = Vec::new();
    let mut entry_count: u64 = 0;
    let mut utxo_count: u64 = 0;
    let mut match_count: u64 = 0;
    let mut total_amount: u64 = 0;
    let start_time = Instant::now();

    // Create iterator
    let mut iter = match db.new_iter() {
        Ok(iter) => iter,
        Err(e) => return Err(format!("Failed to create iterator: {:?}", e)),
    };

    // Progress tracking
    let total_entries = 164957265u64;
    let report_interval = std::cmp::max(1, total_entries / 1000);
    let mut last_reported_permille = 0u64;

    // Iterate through key-value pairs
    while iter.advance() {
        let Some((k, v)) = iter.current() else {
            continue;
        };

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
                "\rProgress: {:.1}% | ETA: {} | Entries: {} | UTXOs: {} | Found: {} ({:.4} BTC)",
                current_permille as f64 / 10.0,
                eta_str,
                entry_count,
                utxo_count,
                match_count,
                total_amount as f64 / 100_000_000.0
            );
            io::stdout().flush().ok();
            last_reported_permille = current_permille;
        }

        if k.is_empty() {
            continue;
        }

        match k[0] {
            // Obfuscate key entry (byte 14 = 0x0e)
            14 => {
                if !v.is_empty() {
                    obfuscate_key = v[1..].to_vec();
                }
            }

            // UTXO entry ('C' = 0x43 = 67)
            67 => {
                let value = deobfuscate(&obfuscate_key, &v);
                let (_txid, _vout) = decode_utxo_key(&k);

                // Read first chunk (block height and coinbase)
                let (first_chunk, offset) = read_chunk(&value, 0);
                let _height = first_chunk >> 1;
                let _coinbase = (first_chunk & 1) == 1;

                // Get second chunk and amount
                let (second_chunk, offset) = read_chunk(&value, offset);
                let amount = convert_amount(second_chunk);

                // Get third chunk (script type)
                let (script_type, offset) = read_chunk(&value, offset);

                // Get remaining bytes (script)
                let script = match script_type {
                    0 => {
                        // P2PKH
                        let hash = &value[offset..offset + 20];
                        let mut script = Vec::with_capacity(25);
                        script.extend_from_slice(&[0x76, 0xa9, 0x14]);
                        script.extend_from_slice(hash);
                        script.extend_from_slice(&[0x88, 0xac]);

                        script
                    }

                    1 => {
                        // P2SH
                        let hash = &value[offset..offset + 20];
                        let mut script = Vec::with_capacity(23);
                        script.extend_from_slice(&[0xa9, 0x14]);
                        script.extend_from_slice(hash);
                        script.push(0x87);

                        script
                    }

                    2 | 3 => {
                        // compressed P2PK
                        let x = &value[offset..offset + 32];
                        let prefix = if script_type == 2 { 0x02 } else { 0x03 };

                        let mut script = Vec::with_capacity(35);
                        script.push(33); // pushdata
                        script.push(prefix);
                        script.extend_from_slice(x);
                        script.push(0xac); // OP_CHECKSIG

                        script
                    }

                    4 | 5 => {
                        // uncompressed P2PK (Bitcoin Core reconstructs pubkey from compressed form)
                        let x = &value[offset..offset + 32];
                        let prefix = if script_type == 4 { 0x02 } else { 0x03 };

                        // Build compressed pubkey: prefix (1 byte) + X (32 bytes) = 33 bytes
                        let mut compressed_pubkey_bytes = [0u8; 33];
                        compressed_pubkey_bytes[0] = prefix;
                        compressed_pubkey_bytes[1..33].copy_from_slice(x);

                        // Parse compressed pubkey and decompress to uncompressed form
                        let compressed_pubkey = match PublicKey::from_slice(&compressed_pubkey_bytes) {
                            Ok(pk) => pk,
                            Err(_e) => {
                                continue; // Skip this UTXO entry
                            }
                        };

                        // Decompress to get the full 65-byte uncompressed pubkey
                        let uncompressed_pubkey = compressed_pubkey.serialize_uncompressed();

                        // Build script: PUSHDATA(65 bytes) + pubkey (65 bytes) + OP_CHECKSIG
                        let mut script = Vec::with_capacity(67);
                        script.push(65); // PUSHDATA: push 65 bytes
                        script.extend_from_slice(&uncompressed_pubkey);
                        script.push(0xac); // OP_CHECKSIG

                        script
                    }

                    n => {
                        // raw script
                        let len = (n - 6) as usize;

                        let script = value[offset..offset + len].to_vec();

                        script
                    }
                };

                // Compute RIPEMD-160 hash of the script
                let script_hash = ripemd160::Hash::hash(&script);
                let script_hash_array: [u8; 20] = script_hash.to_byte_array();

                // Check if this matches our target
                if script_hash_array == *target_hash {
                    match_count += 1;
                    total_amount += amount;
                }

                utxo_count += 1;
            }
            _ => {}
        }
    }

    let elapsed = start_time.elapsed();

    println!();
    println!(
        "\rProgress: 100.0% | Complete | Entries: {} | UTXOs: {} | Found: {} ({:.8} BTC)",
        entry_count, utxo_count, match_count, total_amount as f64 / 100_000_000.0
    );
    println!();
    println!("=== Summary ===");
    println!("Total entries scanned: {}", entry_count);
    println!("Total UTXOs scanned: {}", utxo_count);
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

/// Default Bitcoin data directory
const DEFAULT_BITCOIN_DATADIR: &str = "/Volumes/Bitcoin/bitcoin";

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <script_hex> [datadir]", args[0]);
        eprintln!();
        eprintln!("Arguments:");
        eprintln!("  script_hex  Script pubkey in hex format");
        eprintln!("  datadir     Bitcoin data directory (default: {})", DEFAULT_BITCOIN_DATADIR);
        eprintln!();
        eprintln!("Example:");
        eprintln!("  {} 76a914b64513c1f1b889a556463243cca9c26ee626b9a088ac", args[0]);
        std::process::exit(1);
    }

    let script_hex = &args[1];
    let datadir = if args.len() >= 3 {
        Path::new(&args[2]).to_path_buf()
    } else {
        Path::new(DEFAULT_BITCOIN_DATADIR).to_path_buf()
    };

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
    println!("Datadir:      {}", datadir.display());
    println!();

    // Step 1: Check if bitcoind process is running
    println!("[1] Checking for bitcoind process...");
    match is_bitcoind_running() {
        Ok(true) => {
            println!("✗ Detected bitcoind process running, exiting.");
            std::process::exit(1);
        }
        Ok(false) => {
            println!("✓ No bitcoind process detected");
        }
        Err(e) => {
            eprintln!("✗ Failed to check process: {}", e);
            std::process::exit(1);
        }
    }

    // Step 2: Acquire datadir lock
    println!();
    println!("[2] Acquiring datadir lock...");
    let lock_path = datadir.join(".lock");
    println!("    Lock file path: {}", lock_path.display());

    let _lock = match acquire_datadir_lock(&datadir) {
        Ok(lock) => {
            println!("✓ Successfully acquired Advisory Lock on .lock file");
            lock
        }
        Err(e) => {
            eprintln!("✗ {}", e);
            std::process::exit(1);
        }
    };

    // Step 3: Process chainstate database
    let chainstate_dir = datadir.join("chainstate");
    if let Err(e) = process_chainstate(&chainstate_dir, &target_hash) {
        eprintln!("✗ {}", e);
        std::process::exit(1);
    }

    println!();
    println!("Done. Lock will be released when program exits.");
}