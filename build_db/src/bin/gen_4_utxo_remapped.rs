//! Tool to build remapped UTXO set from Bitcoin chainstate
//!
//! Features:
//! 1. Check if bitcoind process is running via `ps aux`
//! 2. Create .lock file in the given datadir and acquire Advisory Lock
//! 3. Open and iterate over the chainstate LevelDB database
//! 4. Map 32-byte TXID to 4-byte TXID using MPHF + txid_locations.bin lookup
//! 5. Compute RIPEMD-160 hash of script
//! 6. Write remapped UTXO entries to output file
//!
//! Output format per UTXO (40 bytes):
//! - 20 bytes: RIPEMD-160 hash of script
//! - 4 bytes: TXID (looked up from txid_locations.bin using MPHF hash as index)
//! - 4 bytes: vout (u32)
//! - 4 bytes: block height (u32)
//! - 8 bytes: amount (u64)
//!
//! Usage:
//!   build_remapped_utxo <datadir> [chainstate_dir]
//!
//! Example:
//!   build_remapped_utxo /Volumes/Bitcoin/bitcoin /Volumes/Bitcoin/bitcoin/chainstate

use bitcoin::hashes::{ripemd160, Hash};
use bitcoinpir::mpfh::Mphf;
use memmap2::Mmap;
use secp256k1::PublicKey;
use nix::fcntl::{Flock, FlockArg};
use rusty_leveldb::{LdbIterator, Options, DB};
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

/// Path to the MPHF file for TXID mapping
const MPHF_FILE: &str = "/Volumes/Bitcoin/data/txid_mphf.bin";

/// Path to the txid_locations.bin file (MPHF hash -> txid_index mapping)
const TXID_LOCATIONS_FILE: &str = "/Volumes/Bitcoin/data/txid_locations.bin";

/// Output file for remapped UTXO set
const OUTPUT_FILE: &str = "/Volumes/Bitcoin/data/remapped_utxo_set.bin";

/// Txids to skip (these caused issues during MPHF construction)
/// 68b45f58b674e94eb881cd67b04c2cba07fe5552dbf1d5385637b0d4073dbfe3
const SKIP_TXID_1: [u8; 32] = [
    0x68, 0xb4, 0x5f, 0x58, 0xb6, 0x74, 0xe9, 0x4e, 0xb8, 0x81, 0xcd, 0x67, 0xb0, 0x4c, 0x2c, 0xba,
    0x07, 0xfe, 0x55, 0x52, 0xdb, 0xf1, 0xd5, 0x38, 0x56, 0x37, 0xb0, 0xd4, 0x07, 0x3d, 0xbf, 0xe3,
];

/// 9985d82954e10f2233a08905dc7b490eb444660c8759e324c7dfa3d28779d2d5
const SKIP_TXID_2: [u8; 32] = [
    0x99, 0x85, 0xd8, 0x29, 0x54, 0xe1, 0x0f, 0x22, 0x33, 0xa0, 0x89, 0x05, 0xdc, 0x7b, 0x49, 0x0e,
    0xb4, 0x44, 0x66, 0x0c, 0x87, 0x59, 0xe3, 0x24, 0xc7, 0xdf, 0xa3, 0xd2, 0x87, 0x79, 0xd2, 0xd5,
];

/// UTXO information extracted from chainstate
#[derive(Debug)]
pub struct UtxoInfo {
    pub txid: String,
    pub vout: u32,
    pub height: u64,
    pub coinbase: bool,
    pub amount: u64,
}

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

    // Check each line for bitcoind process
    // Skip grep lines to avoid false positives
    for line in stdout.lines() {
        // Skip lines containing "grep" (user might be filtering with grep)
        if line.contains("grep") {
            continue;
        }
        // Check for bitcoind
        // ps aux output format: USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND
        // We check the COMMAND column (index 10) for bitcoind
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 11 {
            let command = parts[10]; // COMMAND column
                                     // Check if command is bitcoind or path ends with /bitcoind
            if command == "bitcoind" || command.ends_with("/bitcoind") {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Create .lock file in datadir and acquire Advisory Lock
/// Returns Flock wrapper that holds the lock
fn acquire_datadir_lock(datadir: &Path) -> Result<Flock<std::fs::File>, String> {
    let lock_path = datadir.join(".lock");

    // Ensure datadir exists
    if !datadir.exists() {
        return Err(format!("datadir does not exist: {}", datadir.display()));
    }

    // Create or open .lock file
    // Use 0666 mode (default permissions, subject to umask)
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .mode(0o666)
        .open(&lock_path)
        .map_err(|e| format!("Failed to create/open .lock file: {}", e))?;

    // Acquire Exclusive Lock (Write Lock)
    // Use non-blocking mode; return error immediately if lock cannot be acquired
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

/// Load MPHF from file
fn load_mphf(path: &Path) -> Result<Mphf<[u8; 32]>, String> {
    println!("Loading MPHF from {}...", path.display());

    let data = std::fs::read(path).map_err(|e| format!("Failed to read MPHF file: {}", e))?;

    let mphf: Mphf<[u8; 32]> =
        bincode::deserialize(&data).map_err(|e| format!("Failed to deserialize MPHF: {}", e))?;

    println!("MPHF loaded successfully ({} bytes)", data.len());
    Ok(mphf)
}

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
/// Key format: 'C' (0x43) + txid (32 bytes, little-endian) + vout (varint)
fn decode_utxo_key(key: &[u8]) -> (Vec<u8>, u32) {
    // Skip first byte ('C' = 0x43)
    // Next 32 bytes are txid (little-endian)
    let txid = key[1..33].to_vec();

    // Remaining bytes encode vout as varint
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
/// Returns (value, new_offset)
fn read_chunk(data: &Vec<u8>, offset: usize) -> (u64, usize) {
    let length = get_vint(&data, &offset);
    let chunk: u64 = decode_vint(&length);
    let new_offset: usize = offset + length.len();

    (chunk, new_offset)
}

pub fn get_vint(data: &Vec<u8>, offset: &usize) -> Vec<u8> {
    // Initialize
    let mut res: Vec<u8> = Vec::new();

    // Start reading bytes
    for x in *offset as u16..data.len() as u16 {
        res.push(data[x as usize]);

        // Check if 8th bit not set
        if (data[x as usize] & 0b1000_0000) == 0 {
            return res;
        }
    }

    // Unable to read
    res
}

pub fn decode_vint(data: &Vec<u8>) -> u64 {
    let mut n: u64 = 0;
    for b in data {
        n = n << 7;

        n = n | (b & 127) as u64;
        //if (b & 0b1000_0000) == 0 {
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

/// Format duration in seconds to a human-readable string (e.g., "2h 15m 30s")
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

/// Write a remapped UTXO entry to the output file
/// Format: script_hash (20B RIPEMD-160) + txid_4b (4B) + vout (4B) + height (4B) + amount (8B) = 40 bytes
fn write_remapped_utxo(
    writer: &mut BufWriter<File>,
    script_hash: &[u8; 20],
    txid_4b: u32,
    vout: u32,
    height: u32,
    amount: u64,
) -> io::Result<()> {
    // Write script hash (20 bytes - RIPEMD-160)
    writer.write_all(script_hash)?;

    // Write 4-byte TXID (little-endian)
    writer.write_all(&txid_4b.to_le_bytes())?;

    // Write vout (4 bytes, little-endian)
    writer.write_all(&vout.to_le_bytes())?;

    // Write block height (4 bytes, little-endian)
    writer.write_all(&height.to_le_bytes())?;

    // Write amount (8 bytes, little-endian)
    writer.write_all(&amount.to_le_bytes())?;

    Ok(())
}

/// Count total entries in the chainstate database (Pass 1)
fn count_chainstate_entries(chainstate_dir: &Path) -> Result<u64, String> {
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

    let mut iter = match db.new_iter() {
        Ok(iter) => iter,
        Err(e) => return Err(format!("Failed to create iterator: {:?}", e)),
    };

    let mut count: u64 = 0;
    while iter.advance() {
        if iter.current().is_some() {
            count += 1;
        }
    }

    Ok(count)
}

/// Process the chainstate database and write remapped UTXOs
fn process_chainstate(
    chainstate_dir: &Path,
    mphf: &Mphf<[u8; 32]>,
    txid_locations: &Mmap,
) -> Result<(), String> {
    println!();
    println!("[3] Opening chainstate database...");
    println!("    Chainstate path: {}", chainstate_dir.display());

    // Check chainstate directory exists
    if !chainstate_dir.exists() {
        return Err(format!(
            "chainstate directory does not exist: {}",
            chainstate_dir.display()
        ));
    }

    // First pass: count total entries for progress bar
    println!();
    println!("[4] Counting entries (Pass 1/2)...");
    let count_start = Instant::now();
    let total_entries = count_chainstate_entries(chainstate_dir)?;
    println!("    Found {} entries in {:.2}s", total_entries, count_start.elapsed().as_secs_f64());

    // Open output file for writing remapped UTXOs
    println!();
    println!("[5] Opening output file: {}", OUTPUT_FILE);
    let output_file =
        File::create(OUTPUT_FILE).map_err(|e| format!("Failed to create output file: {}", e))?;
    let mut writer = BufWriter::with_capacity(1024 * 1024, output_file); // 1MB buffer

    // Configure LevelDB options with read-only safeguards:
    // - create_if_missing: false - don't create new database
    // - reuse_logs: false - don't reuse/modify log files
    // - reuse_manifest: false - don't reuse/modify manifest files
    let options = Options {
        create_if_missing: false,
        reuse_logs: false,
        reuse_manifest: false,
        compressor: 1, // Use Snappy compression for reading (Bitcoin Core uses Snappy)
        ..Default::default()
    };

    // Open the database
    let mut db = match DB::open(chainstate_dir, options) {
        Ok(db) => db,
        Err(e) => return Err(format!("Unable to open LevelDB, error: {:?}", e)),
    };

    println!();
    println!("[6] Processing UTXOs (Pass 2/2)...");
    println!();

    // Set variables
    let mut obfuscate_key: Vec<u8> = Vec::new();
    let mut total_utxos: u64 = 0;
    let mut total_amount: u64 = 0;
    let mut entry_count: u64 = 0;
    let mut txid_cache_hits: u64 = 0;
    let mut txid_mphf_lookups: u64 = 0;
    let mut txid_mappings_successful: u64 = 0; // Counter for successfully mapped TXIDs
    let start_time = Instant::now();

    // Local cache for TXID mapping (previous 32B TXID -> 4B TXID)
    // This is because TXIDs often appear consecutively in the UTXO set
    let mut cached_txid: Option<[u8; 32]> = None;
    let mut cached_txid_4b: Option<u32> = None;

    // Create iterator
    let mut iter = match db.new_iter() {
        Ok(iter) => iter,
        Err(e) => return Err(format!("Failed to create iterator: {:?}", e)),
    };

    // Progress tracking (every 0.1%)
    let one_tenth_percent = std::cmp::max(1, total_entries / 1000);
    let mut last_reported_permille = 0u64;

    // Iterate through key-value pairs
    while iter.advance() {
        let Some((k, v)) = iter.current() else {
            continue;
        };

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
            let eta_str = format_duration(eta_secs);
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

        // Check first byte
        if k.is_empty() {
            continue;
        }

        match k[0] {
            // Obfuscate key entry (byte 14 = 0x0e)
            14 => {
                if !v.is_empty() {
                    // First byte of value is the key marker, rest is the obfuscate key
                    obfuscate_key = v[1..].to_vec();
                }
            }

            // UTXO entry ('C' = 0x43 = 67)
            67 => {
                // Deobfuscate the leveldb value
                let value = deobfuscate(&obfuscate_key, &v);

                // Decode txid and vout
                let (txid, vout) = decode_utxo_key(&k);

                // Convert txid to [u8; 32] for MPHF lookup
                let txid_array: [u8; 32] = match txid.as_slice().try_into() {
                    Ok(arr) => arr,
                    Err(_) => continue, // Skip invalid TXIDs
                };

                // Skip TXIDs that caused issues during MPHF construction
                if txid_array == SKIP_TXID_1 || txid_array == SKIP_TXID_2 {
                    continue;
                }

                // Read first chunk, get blockheight and coinbase
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
                        // The stored 32 bytes is the X coordinate
                        // script_type 4 -> prefix 0x02 (even Y)
                        // script_type 5 -> prefix 0x03 (odd Y)
                        let x = &value[offset..offset + 32];
                        let prefix = if script_type == 4 { 0x02 } else { 0x03 };

                        // Build compressed pubkey: prefix (1 byte) + X (32 bytes) = 33 bytes
                        let mut compressed_pubkey_bytes = [0u8; 33];
                        compressed_pubkey_bytes[0] = prefix;
                        compressed_pubkey_bytes[1..33].copy_from_slice(x);

                        // Parse compressed pubkey and decompress to uncompressed form
                        let compressed_pubkey = match PublicKey::from_slice(&compressed_pubkey_bytes) {
                            Ok(pk) => pk,
                            Err(e) => {
                                return Err(format!("Failed to parse compressed pubkey: {:?}", e));
                            }
                        };

                        // Decompress to get the full 65-byte uncompressed pubkey
                        let uncompressed_pubkey = compressed_pubkey.serialize_uncompressed();

                        // Build script: PUSHDATA(65 bytes) + pubkey (65 bytes) + OP_CHECKSIG
                        // Total: 1 + 65 + 1 = 67 bytes
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

                // Map TXID to 4-byte using MPHF + txid_locations.bin lookup with local cache
                let txid_4b = if cached_txid == Some(txid_array) {
                    // Cache hit - use cached 4B TXID
                    txid_cache_hits += 1;
                    cached_txid_4b.unwrap()
                } else {
                    // Cache miss - lookup in MPHF using try_hash
                    txid_mphf_lookups += 1;
                    match mphf.try_hash(&txid_array) {
                        Some(mphf_hash) => {
                            // MPHF found - now lookup the actual 4-byte TXID from txid_locations.bin
                            // The MPHF hash is the index into txid_locations.bin (at offset 4*mphf_hash)
                            let actual_txid_4b = lookup_txid_4b(txid_locations, mphf_hash);

                            // Successfully mapped - increment counter
                            txid_mappings_successful += 1;

                            // Update cache
                            cached_txid = Some(txid_array);
                            cached_txid_4b = Some(actual_txid_4b);

                            actual_txid_4b
                        }
                        None => {
                            // TXID not found in MPHF - try reversed version for debugging
                            let mut reversed_txid = txid_array;
                            reversed_txid.reverse();

                            match mphf.try_hash(&reversed_txid) {
                                Some(hash) => {
                                    // Reversed version found - this indicates byte order issue
                                    eprintln!("!!! DEBUG: TXID not found in MPHF");
                                    eprintln!("    Original:           {}", bin2hex(&txid_array));
                                    eprintln!(
                                        "    Reversed:           {}",
                                        bin2hex(&reversed_txid)
                                    );
                                    eprintln!("    Reversed version found with hash: {}", hash);
                                    eprintln!("    Its height:         {}", height);
                                    eprintln!("    Its script hex:     {}", bin2hex(&script));
                                    eprintln!(
                                        "    Successfully mapped TXIDs before this error: {}",
                                        txid_mappings_successful
                                    );
                                    return Err(format!(
                                        "TXID found only in reversed byte order: {} (reversed: {})",
                                        bin2hex(&txid_array),
                                        bin2hex(&reversed_txid)
                                    ));
                                }
                                None => {
                                    // Neither original nor reversed found
                                    eprintln!("Warning: TXID not found in MPHF (neither original nor reversed): {}", bin2hex(&txid_array));
                                    return Err(format!(
                                        "TXID not found in MPHF (neither original nor reversed): {}",
                                        bin2hex(&txid_array)
                                    ));
                                }
                            }
                        }
                    }
                };

                // Compute RIPEMD-160 hash of the script
                let script_hash = ripemd160::Hash::hash(&script);
                let script_hash_array: [u8; 20] = script_hash.to_byte_array();

                // Write remapped UTXO entry to output file
                if let Err(e) = write_remapped_utxo(
                    &mut writer,
                    &script_hash_array,
                    txid_4b,
                    vout,
                    height as u32,
                    amount,
                ) {
                    return Err(format!("Failed to write UTXO: {}", e));
                }

                // Count UTXOs
                total_utxos += 1;
                total_amount += amount;
            }
            _ => {
                // Other entry types - skip
            }
        }
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

/// Default Bitcoin data directory
const DEFAULT_BITCOIN_DATADIR: &str = "/Volumes/Bitcoin/bitcoin";

fn main() {
    let args: Vec<String> = env::args().collect();

    // Use hardcoded default path or override from command line
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

    println!("=== Build Remapped UTXO ===");
    println!("datadir: {}", datadir.display());
    println!("chainstate: {}", chainstate_dir.display());
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

    // Step 2.5: Load MPHF for TXID mapping
    println!();
    println!("[2.5] Loading MPHF for TXID mapping...");
    let mphf_path = Path::new(MPHF_FILE);
    if !mphf_path.exists() {
        eprintln!("✗ MPHF file not found: {}", MPHF_FILE);
        eprintln!("  Please run build_mphf first to create the MPHF file.");
        std::process::exit(1);
    }

    let mphf = match load_mphf(mphf_path) {
        Ok(mphf) => {
            println!("✓ MPHF loaded successfully");
            mphf
        }
        Err(e) => {
            eprintln!("✗ {}", e);
            std::process::exit(1);
        }
    };

    // Step 2.6: Load txid_locations.bin for TXID mapping
    println!();
    println!("[2.6] Loading txid_locations.bin for TXID index lookup...");
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

    // Step 3 & 4: Process chainstate database
    if let Err(e) = process_chainstate(&chainstate_dir, &mphf, &txid_locations) {
        eprintln!("✗ {}", e);
        std::process::exit(1);
    }

    println!();
    println!("Done. Lock will be released when program exits.");
}
