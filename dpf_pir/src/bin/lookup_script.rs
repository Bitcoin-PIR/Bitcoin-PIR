//! Lookup UTXO data by script pubkey hex
//!
//! This tool integrates:
//! 1. Script hex → RIPEMD160 hash
//! 2. Cuckoo hash lookup in utxo_chunks_cuckoo.bin → offset in utxo_chunks.bin
//! 3. Fetch chunks and parse UTXO data (handles multi-chunk spanning)
//! 4. Display all UTXOs for the given script hash
//!
//! Usage:
//!   cargo run --bin lookup_script -- <script_hex_or_hash> [--hash] [--count]
//!
//! Example:
//!   cargo run --bin lookup_script -- 76a914e4986f7364f238102f1889ef9d24d80e2d2d7a4488ac
//!   cargo run --bin lookup_script -- 09d9fb5e2c298cdf69a06fdc188334305e9cb20d --hash
//!   cargo run --bin lookup_script -- 76a914b64513c1f1b889a556463243cca9c26ee626b9a088ac --count

use dpf_pir::UtxoChunkDatabase;
use memmap2::Mmap;
use ripemd::{Ripemd160, Digest};
use std::env;
use std::fs::File;

/// Path to the cuckoo index file
const CUCKOO_INDEX_PATH: &str = "/Volumes/Bitcoin/pir/utxo_chunks_cuckoo.bin";

/// Path to the chunks data file
const CHUNKS_PATH: &str = "/Volumes/Bitcoin/pir/utxo_chunks.bin";

/// Entry size in the cuckoo index (20-byte key + 4-byte offset)
const INDEX_ENTRY_SIZE: usize = 24;

/// Key size (RIPEMD160 hash)
const KEY_SIZE: usize = 20;

/// Bucket size in cuckoo hash
const BUCKET_SIZE: usize = 4;

/// Chunk size in bytes
const CHUNK_SIZE: usize = 1024;

/// Number of entries in the chunks database
const NUM_ENTRIES: usize = 1_208_236;

/// A parsed UTXO entry
#[derive(Debug)]
struct UtxoEntry {
    txid: u32,
    vout: u32,
    amount: u64,
}

/// Hash function 1 for 20-byte script hash (same as cuckoo_chunks.rs)
fn hash1(key: &[u8; 20], num_buckets: usize) -> usize {
    let mut h: u64 = 0xcbf29ce484222325; // FNV offset basis
    for i in 0..KEY_SIZE {
        h ^= key[i] as u64;
        h = h.wrapping_mul(0x100000001b3); // FNV prime
    }
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51afd7ed558ccd);
    h ^= h >> 33;
    (h as usize) % num_buckets
}

/// Hash function 2 for 20-byte script hash (same as cuckoo_chunks.rs)
fn hash2(key: &[u8; 20], num_buckets: usize) -> usize {
    let mut h: u64 = 0x517cc1b727220a95; // Different seed
    for i in 0..KEY_SIZE {
        h ^= key[i] as u64;
        h = h.wrapping_mul(0x9e3779b97f4a7c15); // Different prime
    }
    h ^= h >> 32;
    h = h.wrapping_mul(0xbf58476d1ce4e5b9);
    h ^= h >> 32;
    (h as usize) % num_buckets
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

/// Look up a script hash in the cuckoo index
/// Returns the offset in utxo_chunks.bin, or None if not found
fn lookup_cuckoo(mmap: &Mmap, script_hash: &[u8; 20]) -> Option<u32> {
    let file_size = mmap.len();
    let total_slots = file_size / INDEX_ENTRY_SIZE;
    let num_buckets = total_slots / BUCKET_SIZE;

    let b1 = hash1(script_hash, num_buckets);
    let b2 = hash2(script_hash, num_buckets);

    // Check both buckets
    for bucket in [b1, b2] {
        for slot in 0..BUCKET_SIZE {
            let idx = (bucket * BUCKET_SIZE + slot) * INDEX_ENTRY_SIZE;
            if idx + INDEX_ENTRY_SIZE > mmap.len() {
                continue;
            }

            // Read the key (first 20 bytes)
            let key = &mmap[idx..idx + KEY_SIZE];

            // Check if this slot is empty (all zeros)
            if key.iter().all(|&b| b == 0) {
                continue;
            }

            // Check if the key matches
            if key == script_hash {
                // Read the offset (4 bytes after the key)
                let offset = u32::from_le_bytes([
                    mmap[idx + KEY_SIZE],
                    mmap[idx + KEY_SIZE + 1],
                    mmap[idx + KEY_SIZE + 2],
                    mmap[idx + KEY_SIZE + 3],
                ]);
                return Some(offset);
            }
        }
    }

    None
}

/// Streaming reader for UTXO chunks that handles multi-chunk data
struct ChunkReader {
    db: UtxoChunkDatabase,
    /// Current global offset in the chunks file
    global_offset: usize,
    /// Current chunk index
    chunk_index: usize,
    /// Current position within the chunk
    chunk_pos: usize,
    /// Current chunk data
    chunk: Vec<u8>,
}

impl ChunkReader {
    fn new(db: UtxoChunkDatabase, start_offset: usize) -> Result<Self, String> {
        let chunk_index = start_offset / CHUNK_SIZE;
        let chunk_pos = start_offset % CHUNK_SIZE;
        
        let chunk = db.read_entry(chunk_index)?;
        
        Ok(Self {
            db,
            global_offset: start_offset,
            chunk_index,
            chunk_pos,
            chunk,
        })
    }
    
    /// Read a single byte, fetching next chunk if needed
    fn read_byte(&mut self) -> Result<u8, String> {
        if self.chunk_pos >= self.chunk.len() {
            // Need to fetch next chunk
            self.chunk_index += 1;
            if self.chunk_index >= NUM_ENTRIES {
                return Err("End of database reached".to_string());
            }
            self.chunk = self.db.read_entry(self.chunk_index)?;
            self.chunk_pos = 0;
        }
        
        let byte = self.chunk[self.chunk_pos];
        self.chunk_pos += 1;
        self.global_offset += 1;
        Ok(byte)
    }
    
    /// Read a varint (LEB128 encoded), handling multi-chunk spanning
    fn read_varint(&mut self) -> Result<u64, String> {
        let mut result: u64 = 0;
        let mut shift = 0;
        
        loop {
            let byte = self.read_byte()?;
            result |= ((byte & 0x7F) as u64) << shift;
            
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            
            if shift >= 64 {
                return Err("VarInt too large".to_string());
            }
        }
        
        Ok(result)
    }
    
    /// Read 4 bytes as little-endian u32
    fn read_u32_le(&mut self) -> Result<u32, String> {
        let b0 = self.read_byte()?;
        let b1 = self.read_byte()?;
        let b2 = self.read_byte()?;
        let b3 = self.read_byte()?;
        Ok(u32::from_le_bytes([b0, b1, b2, b3]))
    }
    
    /// Get current global offset
    #[allow(dead_code)]
    fn current_offset(&self) -> usize {
        self.global_offset
    }
    
    /// Get current position within chunk
    #[allow(dead_code)]
    fn chunk_position(&self) -> usize {
        self.chunk_pos
    }
    
    /// Get current chunk index
    #[allow(dead_code)]
    fn current_chunk_index(&self) -> usize {
        self.chunk_index
    }
}

/// Parse all UTXO entries for a script hash starting at the given offset
fn parse_utxo_entries(db: UtxoChunkDatabase, start_offset: usize) -> Result<Vec<UtxoEntry>, String> {
    let mut reader = ChunkReader::new(db, start_offset)?;
    
    // Read entry count (varint)
    let entry_count = reader.read_varint()? as usize;
    
    if entry_count == 0 {
        return Ok(Vec::new());
    }
    
    let mut entries = Vec::with_capacity(entry_count);
    
    // Read first entry: [4B txid LE] [varint vout] [varint amount]
    let txid = reader.read_u32_le()?;
    let vout = reader.read_varint()? as u32;
    let amount = reader.read_varint()?;
    
    entries.push(UtxoEntry { txid, vout, amount });
    
    // Read remaining entries: [varint delta_txid] [varint vout] [varint amount]
    // delta_txid = prev_txid wrapping_sub this_txid
    // So: this_txid = prev_txid wrapping_sub delta_txid
    let mut prev_txid = txid;
    
    for _ in 1..entry_count {
        let delta = reader.read_varint()? as u32;
        let txid = prev_txid.wrapping_sub(delta);
        let vout = reader.read_varint()? as u32;
        let amount = reader.read_varint()?;
        
        entries.push(UtxoEntry { txid, vout, amount });
        prev_txid = txid;
    }
    
    Ok(entries)
}

/// Count UTXO entries and compute total amount without storing all entries
/// This is memory-efficient for scripts with huge numbers of UTXOs
fn count_utxo_entries(db: UtxoChunkDatabase, start_offset: usize) -> Result<(usize, u64), String> {
    let mut reader = ChunkReader::new(db, start_offset)?;
    
    // Read entry count (varint)
    let entry_count = reader.read_varint()? as usize;
    
    if entry_count == 0 {
        return Ok((0, 0));
    }
    
    let mut total_amount: u64 = 0;
    
    // Read first entry: [4B txid LE] [varint vout] [varint amount]
    let _txid = reader.read_u32_le()?;
    let _vout = reader.read_varint()? as u32;
    let amount = reader.read_varint()?;
    total_amount += amount;
    
    // Read remaining entries: [varint delta_txid] [varint vout] [varint amount]
    for _ in 1..entry_count {
        let _delta = reader.read_varint()?;
        let _vout = reader.read_varint()?;
        let amount = reader.read_varint()?;
        total_amount += amount;
    }
    
    Ok((entry_count, total_amount))
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <script_hex_or_hash> [--hash] [--count]", args[0]);
        eprintln!();
        eprintln!("Arguments:");
        eprintln!("  script_hex_or_hash  Either a script pubkey hex or a RIPEMD160 hash");
        eprintln!("  --hash              Treat input as a 20-byte RIPEMD160 hash (40 hex chars)");
        eprintln!("  --count             Only count UTXOs (memory-efficient for large scripts)");
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  # Using script pubkey hex:");
        eprintln!("  {} 76a914e4986f7364f238102f1889ef9d24d80e2d2d7a4488ac", args[0]);
        eprintln!();
        eprintln!("  # Using RIPEMD160 hash directly:");
        eprintln!("  {} 09d9fb5e2c298cdf69a06fdc188334305e9cb20d --hash", args[0]);
        eprintln!();
        eprintln!("  # Count only (for scripts with many UTXOs):");
        eprintln!("  {} 76a914b64513c1f1b889a556463243cca9c26ee626b9a088ac --count", args[0]);
        std::process::exit(1);
    }

    let input = &args[1];
    let use_hash = args.iter().any(|a| a == "--hash");
    let count_only = args.iter().any(|a| a == "--count");

    let script_hash: [u8; 20];

    if use_hash {
        // Input is already a RIPEMD160 hash
        println!("=== Step 1: Parse RIPEMD160 Hash ===");
        let hash_bytes = match hex2bin(input) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("Error parsing hash hex: {}", e);
                std::process::exit(1);
            }
        };
        if hash_bytes.len() != 20 {
            eprintln!("Error: RIPEMD160 hash must be exactly 20 bytes (40 hex chars), got {} bytes", hash_bytes.len());
            std::process::exit(1);
        }
        script_hash = hash_bytes.try_into().unwrap();
        println!("RIPEMD160:    {}", bin2hex(&script_hash));
    } else {
        // Input is a script pubkey hex
        println!("=== Step 1: Parse Script Hex ===");
        let script = match hex2bin(input) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error parsing script hex: {}", e);
                std::process::exit(1);
            }
        };
        println!("Script hex:   {}", input);
        println!("Script bytes: {} bytes", script.len());

        // Step 2: Compute RIPEMD160 hash
        println!();
        println!("=== Step 2: Compute RIPEMD160 Hash ===");
        let mut hasher = Ripemd160::new();
        hasher.update(&script);
        let result = hasher.finalize();
        script_hash = result.try_into().unwrap();
        println!("RIPEMD160:    {}", bin2hex(&script_hash));
    }

    // Step 3: Open cuckoo index and look up offset
    println!();
    println!("=== Step 3: Look up in Cuckoo Index ===");
    println!("Opening: {}", CUCKOO_INDEX_PATH);

    let index_file = match File::open(CUCKOO_INDEX_PATH) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error opening cuckoo index: {}", e);
            std::process::exit(1);
        }
    };

    let index_mmap = unsafe {
        match Mmap::map(&index_file) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("Error memory-mapping index: {}", e);
                std::process::exit(1);
            }
        }
    };

    println!("Index size:   {} bytes", index_mmap.len());
    println!("Index entries: {} ({} buckets)", 
        index_mmap.len() / INDEX_ENTRY_SIZE,
        index_mmap.len() / INDEX_ENTRY_SIZE / BUCKET_SIZE);

    let offset = match lookup_cuckoo(&index_mmap, &script_hash) {
        Some(o) => o,
        None => {
            println!();
            println!("✗ Script hash not found in cuckoo index");
            println!("  This address has no UTXOs in the database.");
            std::process::exit(0);
        }
    };

    println!("✓ Found offset: {} (0x{:x})", offset, offset);

    // Step 4: Calculate chunk index and local offset
    println!();
    println!("=== Step 4: Calculate Chunk Location ===");
    let chunk_index = offset as usize / CHUNK_SIZE;
    let local_offset = offset as usize % CHUNK_SIZE;
    println!("Offset:       {}", offset);
    println!("Chunk index:  {} (offset / {})", chunk_index, CHUNK_SIZE);
    println!("Local offset: {} (offset % {})", local_offset, CHUNK_SIZE);

    // Step 5: Open chunks database and parse entries
    println!();
    println!("=== Step 5: Parse UTXO Entries ===");
    println!("Opening: {}", CHUNKS_PATH);

    let db = match UtxoChunkDatabase::with_mmap(
        "utxo_chunks",
        CHUNKS_PATH,
        NUM_ENTRIES,
        CHUNK_SIZE,
    ) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("Error opening chunks database: {}", e);
            std::process::exit(1);
        }
    };

    println!("Database file size: {} bytes", db.file_size());
    println!("Expected size:      {} bytes", db.expected_size());
    println!();

    if count_only {
        // Count-only mode: memory-efficient for large scripts
        let (entry_count, total_amount) = match count_utxo_entries(db, offset as usize) {
            Ok(result) => result,
            Err(e) => {
                eprintln!("Error counting UTXO entries: {}", e);
                std::process::exit(1);
            }
        };

        println!("✓ Counted {} UTXO entries", entry_count);
        println!();

        // Summary
        println!("=== Summary ===");
        println!("Input:         {}", input);
        println!("RIPEMD160:     {}", bin2hex(&script_hash));
        println!("Start offset:  {}", offset);
        println!("Entries:       {}", entry_count);
        println!("Total amount:  {} satoshis ({:.8} BTC)", total_amount, total_amount as f64 / 100_000_000.0);
    } else {
        // Full parse mode: store all entries in memory
        let entries = match parse_utxo_entries(db, offset as usize) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("Error parsing UTXO entries: {}", e);
                std::process::exit(1);
            }
        };

        println!("✓ Parsed {} UTXO entries", entries.len());
        println!();

        // Display all entries
        println!("=== Step 6: UTXO Data ===");
        println!();
        
        let total_amount: u64 = entries.iter().map(|e| e.amount).sum();
        
        for (i, entry) in entries.iter().enumerate() {
            println!("UTXO #{}:", i + 1);
            println!("  TXID (4B mapped): {}", entry.txid);
            println!("  Vout:             {}", entry.vout);
            println!("  Amount:           {} satoshis ({:.8} BTC)", entry.amount, entry.amount as f64 / 100_000_000.0);
            println!();
        }

        // Summary
        println!("=== Summary ===");
        println!("Input:         {}", input);
        println!("RIPEMD160:     {}", bin2hex(&script_hash));
        println!("Start offset:  {}", offset);
        println!("Entries:       {}", entries.len());
        println!("Total amount:  {} satoshis ({:.8} BTC)", total_amount, total_amount as f64 / 100_000_000.0);
    }
}
