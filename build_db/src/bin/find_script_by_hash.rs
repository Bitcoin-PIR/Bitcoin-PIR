//! Debug tool to find a script pubkey by its RIPEMD160 hash in Bitcoin chainstate
//!
//! This script reads the Bitcoin chainstate database and searches for a UTXO
//! whose script's RIPEMD160 hash matches the target value.
//!
//! Usage:
//!   find_script_by_hash [datadir] [chainstate_dir]
//!
//! Example:
//!   find_script_by_hash /Volumes/Bitcoin/bitcoin /Volumes/Bitcoin/bitcoin/chainstate

use bitcoin::hashes::{ripemd160, Hash};
use nix::fcntl::{Flock, FlockArg};
use rusty_leveldb::{DB, LdbIterator, Options};
use std::env;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::Command;

/// Target RIPEMD160 hash to search for (20 bytes)
/// First 20 bytes of: 00000000000000000000000000000000b13bd8fd61128983
const TARGET_HASH: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xb1, 0x3b, 0xd8, 0xfd,
];

/// Check if bitcoind process is running
/// Returns true if bitcoind process is found
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
        Err((_file, e)) => {
            match e {
                nix::errno::Errno::EAGAIN => {
                    Err(format!(
                        "Cannot acquire lock on .lock file: another process holds the lock ({})",
                        lock_path.display()
                    ))
                }
                _ => Err(format!("Failed to acquire file lock: {}", e)),
            }
        }
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

/// Process the chainstate database and search for the target hash
fn process_chainstate(chainstate_dir: &Path) -> Result<(), String> {
    println!();
    println!("[3] Opening chainstate database...");
    println!("    Chainstate path: {}", chainstate_dir.display());
    println!("    Target RIPEMD160 hash: {}", bin2hex(&TARGET_HASH));

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
    let start_time = std::time::Instant::now();

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
            print!("\rProgress: {:.1}% | ETA: {} | Entries: {} | UTXOs: {} | Found: 0", 
                   current_permille as f64 / 10.0, eta_str, entry_count, utxo_count);
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
                let (txid, vout) = decode_utxo_key(&k);

                // Read first chunk (block height and coinbase)
                let (first_chunk, offset) = read_chunk(&value, 0);
                let height = first_chunk >> 1;
                let _coinbase = (first_chunk & 1) == 1;

                if height >= 922_511 {
                    continue; // Skip entries with blockheight >= 922,511 (our TXID map is up to 922510 block)
                }

                // Get second chunk and amount
                let (second_chunk, offset) = read_chunk(&value, offset);
                let amount = convert_amount(second_chunk);

                // Get third chunk (script type)
                let (script_type, mut offset) = read_chunk(&value, offset);

                // Adjust offset for certain script types
                if script_type > 1 && script_type < 6 {
                    offset = offset.saturating_sub(1);
                }

                // Get script bytes
                let script: &[u8] = if offset < value.len() {
                    &value[offset..]
                } else {
                    &[]
                };

                // Compute RIPEMD-160 hash of the script
                let script_hash = ripemd160::Hash::hash(script);
                let script_hash_array: [u8; 20] = script_hash.to_byte_array();

                // Check if this matches our target
                if script_hash_array == TARGET_HASH {
                    println!();
                    println!();
                    println!("========== FOUND MATCH! ==========");
                    println!();
                    println!("TXID (little-endian): {}", bin2hex(&txid));
                    
                    // Also show reversed (big-endian) format which is more common
                    let mut txid_reversed = txid.clone();
                    txid_reversed.reverse();
                    println!("TXID (big-endian):    {}", bin2hex(&txid_reversed));
                    
                    println!("Vout:                 {}", vout);
                    println!("Block Height:         {}", height);
                    println!("Amount:               {} satoshis ({} BTC)", amount, amount as f64 / 100_000_000.0);
                    println!("Script hex:           {}", bin2hex(script));
                    println!("Script len:           {} bytes", script.len());
                    println!("Script type:          {}", script_type);
                    println!("RIPEMD160 hash:       {}", bin2hex(&script_hash_array));
                    println!();
                    
                    // Try to decode the script type
                    if script.is_empty() {
                        println!("Script type:          Empty script");
                    } else if script.len() == 25 
                        && script[0] == 0x76 
                        && script[1] == 0xa9 
                        && script[2] == 0x14 
                        && script[23] == 0x88 
                        && script[24] == 0xac {
                        // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
                        println!("Script type:          P2PKH (Pay to Public Key Hash)");
                        println!("Public Key Hash:      {}", bin2hex(&script[3..23]));
                    } else if script.len() == 23 
                        && script[0] == 0xa9 
                        && script[1] == 0x14 
                        && script[22] == 0x87 {
                        // P2SH: OP_HASH160 <20 bytes> OP_EQUAL
                        println!("Script type:          P2SH (Pay to Script Hash)");
                        println!("Script Hash:          {}", bin2hex(&script[2..22]));
                    } else if script.len() == 22 
                        && script[0] == 0x00 
                        && script[1] == 0x14 {
                        // P2WPKH: OP_0 <20 bytes>
                        println!("Script type:          P2WPKH (Pay to Witness Public Key Hash)");
                        println!("Witness Program:      {}", bin2hex(&script[2..22]));
                    } else if script.len() == 34 
                        && script[0] == 0x00 
                        && script[1] == 0x20 {
                        // P2WSH: OP_0 <32 bytes>
                        println!("Script type:          P2WSH (Pay to Witness Script Hash)");
                        println!("Witness Program:      {}", bin2hex(&script[2..34]));
                    } else {
                        println!("Script type:          Unknown/non-standard");
                    }
                    
                    println!();
                    println!("==================================");
                    
                    // Continue searching for more matches (there might be multiple UTXOs with same script)
                }

                utxo_count += 1;
            }
            _ => {}
        }
    }

    let elapsed = start_time.elapsed();

    println!();
    println!("\rProgress: 100.0% | Complete | Entries: {} | UTXOs: {}", entry_count, utxo_count);
    println!();
    println!("=== Summary ===");
    println!("Total entries scanned: {}", entry_count);
    println!("Total UTXOs scanned: {}", utxo_count);
    println!("Target hash: {}", bin2hex(&TARGET_HASH));
    println!("Time elapsed: {:.2?}", elapsed);
    println!("Entries per second: {:.0}", entry_count as f64 / elapsed.as_secs_f64());

    Ok(())
}

/// Default Bitcoin data directory
const DEFAULT_BITCOIN_DATADIR: &str = "/Volumes/Bitcoin/bitcoin";

fn main() {
    let args: Vec<String> = env::args().collect();

    let (datadir, chainstate_dir) = if args.len() < 2 {
        let datadir = Path::new(DEFAULT_BITCOIN_DATADIR);
        let chainstate_dir = datadir.join("chainstate");
        (datadir.to_path_buf(), chainstate_dir)
    } else {
        let datadir = Path::new(&args[1]);
        let chainstate_dir = if args.len() >= 3 {
            Path::new(&args[2]).to_path_buf()
        } else {
            datadir.join("chainstate")
        };
        (datadir.to_path_buf(), chainstate_dir)
    };

    println!("=== Find Script by RIPEMD160 Hash ===");
    println!("datadir: {}", datadir.display());
    println!("chainstate: {}", chainstate_dir.display());
    println!("target hash: {}", bin2hex(&TARGET_HASH));
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
    if let Err(e) = process_chainstate(&chainstate_dir) {
        eprintln!("✗ {}", e);
        std::process::exit(1);
    }

    println!();
    println!("Done. Lock will be released when program exits.");
}