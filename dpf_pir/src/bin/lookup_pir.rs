//! Two-Phase DPF-PIR Client for UTXO Lookup
//!
//! This client performs private UTXO lookups using two servers:
//! - Phase 1: Query cuckoo index to get chunk offset
//! - Phase 2: Query chunks database to get UTXO data
//!
//! Usage:
//!   cargo run --bin lookup_pir -- <script_hex_or_hash> [--hash]
//!
//! Example:
//!   cargo run --bin lookup_pir -- 76a914e4986f7364f238102f1889ef9d24d80e2d2d7a4488ac
//!   cargo run --bin lookup_pir -- 09d9fb5e2c298cdf69a06fdc188334305e9cb20d --hash

use dpf_pir::{
    ClientConfig, cuckoo_locations_default,
    Request, Response, ScriptHash, KEY_SIZE,
    SERVER1_PORT, SERVER2_PORT,
};
use libdpf::Dpf;
use log::{debug, error, info};
use ripemd::{Digest, Ripemd160};
use std::env;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ============================================================================
// CONSTANTS
// ============================================================================

/// Database ID for the cuckoo index
const CUCKOO_DB_ID: &str = "utxo_cuckoo_index";

/// Database ID for the chunks data
const CHUNKS_DB_ID: &str = "utxo_chunks_data";

/// Number of buckets in the cuckoo index
const CUCKOO_NUM_BUCKETS: usize = 14_008_355;

/// Number of entries in the chunks database
const CHUNKS_NUM_ENTRIES: usize = 37_758;

/// Chunk size in bytes (32KB)
const CHUNK_SIZE: usize = 32 * 1024;

/// Entry size in cuckoo index (20-byte key + 4-byte offset)
const CUCKOO_ENTRY_SIZE: usize = 24;

/// Bucket size in cuckoo index
const CUCKOO_BUCKET_SIZE: usize = 4;

// ============================================================================
// PIR CLIENT
// ============================================================================

/// PIR Client for two-phase UTXO lookup
struct PIRClient {
    /// Client configuration
    config: ClientConfig,
}

impl PIRClient {
    /// Create a new PIR client
    fn new(config: ClientConfig) -> Self {
        Self { config }
    }

    /// Phase 1: Query cuckoo index to get chunk offset for a script hash
    /// 
    /// Returns Some(offset) if found, None if not found
    async fn query_cuckoo_index(&self, script_hash: &ScriptHash) -> Result<Option<u32>, String> {
        info!("Phase 1: Querying cuckoo index for script hash");

        // Compute cuckoo hash locations directly using the hash function
        let (loc1, loc2) = cuckoo_locations_default(script_hash, CUCKOO_NUM_BUCKETS);
        info!("Cuckoo locations: loc1={}, loc2={}", loc1, loc2);

        // Calculate DPF domain size
        let n = (CUCKOO_NUM_BUCKETS as f64).log2().ceil() as u8;
        let dpf = Dpf::with_default_key();

        // Generate DPF keys for both locations
        let (k0_loc1, k1_loc1) = dpf.gen(loc1 as u64, n);
        let (k0_loc2, k1_loc2) = dpf.gen(loc2 as u64, n);

        info!("DPF keys generated: domain=2^{}", n);

        // Query Server 1
        let result1 = self.query_server_two_keys(
            &self.config.server1_addr,
            CUCKOO_DB_ID,
            &k0_loc1.to_bytes(),
            &k0_loc2.to_bytes(),
        ).await?;

        // Query Server 2
        let result2 = self.query_server_two_keys(
            &self.config.server2_addr,
            CUCKOO_DB_ID,
            &k1_loc1.to_bytes(),
            &k1_loc2.to_bytes(),
        ).await?;

        // XOR results from both servers
        let combined_loc1 = xor_bytes(&result1.0, &result2.0);
        let combined_loc2 = xor_bytes(&result1.1, &result2.1);

        info!("Combined results: loc1={} bytes, loc2={} bytes", 
              combined_loc1.len(), combined_loc2.len());

        // Search for matching key in both bucket results
        for (bucket_data, loc_name) in [(&combined_loc1, "loc1"), (&combined_loc2, "loc2")] {
            for i in 0..CUCKOO_BUCKET_SIZE {
                let offset = i * CUCKOO_ENTRY_SIZE;
                if offset + CUCKOO_ENTRY_SIZE > bucket_data.len() {
                    continue;
                }
                
                let key = &bucket_data[offset..offset + KEY_SIZE];
                
                // Skip empty entries
                if key.iter().all(|&b| b == 0) {
                    continue;
                }
                
                // Check if this is our key
                if key == script_hash.as_slice() {
                    let value = u32::from_le_bytes([
                        bucket_data[offset + KEY_SIZE],
                        bucket_data[offset + KEY_SIZE + 1],
                        bucket_data[offset + KEY_SIZE + 2],
                        bucket_data[offset + KEY_SIZE + 3],
                    ]);
                    info!("Found matching key at {} with offset {}", loc_name, value);
                    return Ok(Some(value));
                }
            }
        }

        info!("Script hash not found in cuckoo index");
        Ok(None)
    }

    /// Phase 2: Query chunks database at a specific chunk index
    async fn query_chunk(&self, chunk_index: usize) -> Result<Vec<u8>, String> {
        debug!("Querying chunks database for chunk {}", chunk_index);

        // Calculate DPF domain size
        let n = (CHUNKS_NUM_ENTRIES as f64).log2().ceil() as u8;
        let dpf = Dpf::with_default_key();

        // Generate DPF key for single location
        let (k0, k1) = dpf.gen(chunk_index as u64, n);

        // Query Server 1
        let result1 = self.query_server_single(
            &self.config.server1_addr,
            CHUNKS_DB_ID,
            &k0.to_bytes(),
        ).await?;

        // Query Server 2
        let result2 = self.query_server_single(
            &self.config.server2_addr,
            CHUNKS_DB_ID,
            &k1.to_bytes(),
        ).await?;

        // XOR results
        let combined = xor_bytes(&result1, &result2);
        debug!("Chunk data retrieved: {} bytes", combined.len());

        Ok(combined)
    }

    /// Query a server with two DPF keys (cuckoo index)
    async fn query_server_two_keys(
        &self,
        addr: &str,
        db_id: &str,
        key1: &[u8],
        key2: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        info!("Connecting to {} for database '{}' query", addr, db_id);

        let mut stream = TcpStream::connect(addr).await
            .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;

        let request = Request::QueryDatabase {
            database_id: db_id.to_string(),
            dpf_key1: key1.to_vec(),
            dpf_key2: key2.to_vec(),
        };

        send_request(&mut stream, &request).await?;
        let response = receive_response(&mut stream).await?;

        match response {
            Response::QueryTwoResults { data1, data2 } => {
                info!("Received results from {}: data1={} bytes, data2={} bytes", 
                      addr, data1.len(), data2.len());
                Ok((data1, data2))
            }
            Response::Error { message } => Err(format!("Server error: {}", message)),
            _ => Err(format!("Unexpected response: {:?}", response)),
        }
    }

    /// Query a server with a single DPF key (chunks database)
    async fn query_server_single(
        &self,
        addr: &str,
        db_id: &str,
        key: &[u8],
    ) -> Result<Vec<u8>, String> {
        debug!("Connecting to {} for database '{}' single query", addr, db_id);

        let mut stream = TcpStream::connect(addr).await
            .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;

        let request = Request::QueryDatabaseSingle {
            database_id: db_id.to_string(),
            dpf_key: key.to_vec(),
        };

        send_request(&mut stream, &request).await?;
        let response = receive_response(&mut stream).await?;

        match response {
            Response::QueryResult { data } => {
                debug!("Received result from {}: {} bytes", addr, data.len());
                Ok(data)
            }
            Response::Error { message } => Err(format!("Server error: {}", message)),
            _ => Err(format!("Unexpected response: {:?}", response)),
        }
    }

    /// Full two-phase lookup for a script hash
    /// Returns the offset in the chunks database if found
    async fn lookup_utxo(&self, script_hash: &ScriptHash) -> Result<Option<u32>, String> {
        // Phase 1: Get offset from cuckoo index
        let offset = match self.query_cuckoo_index(script_hash).await? {
            Some(o) => o,
            None => return Ok(None),
        };

        // Calculate chunk index from offset
        let chunk_index = offset as usize / CHUNK_SIZE;
        let local_offset = offset as usize % CHUNK_SIZE;
        info!("Offset {} -> chunk_index={}, local_offset={}", offset, chunk_index, local_offset);

        Ok(Some(offset))
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// XOR two byte vectors together
fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    let min_len = a.len().min(b.len());
    let mut result = vec![0u8; min_len];
    for i in 0..min_len {
        result[i] = a[i] ^ b[i];
    }
    result
}

/// Send a request to the server
async fn send_request(stream: &mut TcpStream, request: &Request) -> Result<(), String> {
    let request_bytes = bincode::serialize(request)
        .map_err(|e| format!("Failed to serialize request: {}", e))?;

    // Send request length (4 bytes, big-endian)
    let len = request_bytes.len() as u32;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| format!("Failed to write request length: {}", e))?;

    // Send request body
    stream
        .write_all(&request_bytes)
        .await
        .map_err(|e| format!("Failed to write request body: {}", e))?;

    Ok(())
}

/// Receive a response from the server
async fn receive_response(stream: &mut TcpStream) -> Result<Response, String> {
    // Read response length (4 bytes, big-endian)
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| format!("Failed to read response length: {}", e))?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;

    // Read response body
    let mut resp_buf = vec![0u8; resp_len];
    stream
        .read_exact(&mut resp_buf)
        .await
        .map_err(|e| format!("Failed to read response body: {}", e))?;

    // Deserialize the response
    bincode::deserialize(&resp_buf)
        .map_err(|e| format!("Failed to deserialize response: {}", e))
}

/// Convert script hex to RIPEMD160 hash
fn script_to_hash(script_hex: &str) -> Result<ScriptHash, String> {
    let script_bytes = hex::decode(script_hex)
        .map_err(|e| format!("Invalid hex: {}", e))?;
    
    let ripemd160_hash = Ripemd160::digest(&script_bytes);
    
    let mut hash = [0u8; KEY_SIZE];
    hash.copy_from_slice(&ripemd160_hash);
    
    Ok(hash)
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

/// Convert bytes to hex string
fn bin2hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ============================================================================
// UTXO PARSING
// ============================================================================

/// A parsed UTXO entry
#[derive(Debug, Clone)]
struct UtxoEntry {
    txid: u32,
    vout: u32,
    amount: u64,
}

/// Statistics for PIR queries
#[derive(Debug, Clone, Default)]
struct QueryStats {
    /// Number of chunk queries made
    chunk_queries: usize,
    /// Total bytes received from PIR queries
    total_bytes_received: usize,
    /// Starting chunk index
    start_chunk_index: usize,
    /// Ending chunk index
    end_chunk_index: usize,
    /// Bytes read from the chunks (actual data consumed)
    bytes_read: usize,
}

/// Streaming reader for UTXO chunks that handles multi-chunk data
/// Fetches subsequent chunks from PIR servers when needed
struct ChunkReader<'a> {
    /// Reference to PIR client for fetching chunks
    client: &'a PIRClient,
    /// Current chunk index
    chunk_index: usize,
    /// Current position within the chunk
    chunk_pos: usize,
    /// Current chunk data
    chunk: Vec<u8>,
    /// Query statistics
    stats: QueryStats,
}

impl<'a> ChunkReader<'a> {
    async fn new(client: &'a PIRClient, start_offset: usize) -> Result<Self, String> {
        let chunk_index = start_offset / CHUNK_SIZE;
        let chunk_pos = start_offset % CHUNK_SIZE;
        
        let chunk = client.query_chunk(chunk_index).await?;
        let chunk_len = chunk.len();
        
        Ok(Self {
            client,
            chunk_index,
            chunk_pos,
            chunk,
            stats: QueryStats {
                chunk_queries: 1,
                total_bytes_received: chunk_len,
                start_chunk_index: chunk_index,
                end_chunk_index: chunk_index,
                bytes_read: 0,
            },
        })
    }
    
    /// Read a single byte, fetching next chunk from PIR servers if needed
    async fn read_byte(&mut self) -> Result<u8, String> {
        if self.chunk_pos >= self.chunk.len() {
            // Need to fetch next chunk from PIR servers
            self.chunk_index += 1;
            if self.chunk_index >= CHUNKS_NUM_ENTRIES {
                return Err("End of database reached".to_string());
            }
            self.chunk = self.client.query_chunk(self.chunk_index).await?;
            self.chunk_pos = 0;
            
            // Update statistics
            self.stats.chunk_queries += 1;
            self.stats.total_bytes_received += self.chunk.len();
            self.stats.end_chunk_index = self.chunk_index;
        }
        
        let byte = self.chunk[self.chunk_pos];
        self.chunk_pos += 1;
        self.stats.bytes_read += 1;
        Ok(byte)
    }
    
    /// Get query statistics
    fn get_stats(&self) -> &QueryStats {
        &self.stats
    }
    
    /// Read a varint (LEB128 encoded), handling multi-chunk spanning
    async fn read_varint(&mut self) -> Result<u64, String> {
        let mut result: u64 = 0;
        let mut shift = 0;
        
        loop {
            let byte = self.read_byte().await?;
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
    async fn read_u32_le(&mut self) -> Result<u32, String> {
        let b0 = self.read_byte().await?;
        let b1 = self.read_byte().await?;
        let b2 = self.read_byte().await?;
        let b3 = self.read_byte().await?;
        Ok(u32::from_le_bytes([b0, b1, b2, b3]))
    }
    
    /// Get current chunk index
    #[allow(dead_code)]
    fn current_chunk_index(&self) -> usize {
        self.chunk_index
    }
    
    /// Get current position within chunk
    #[allow(dead_code)]
    fn chunk_position(&self) -> usize {
        self.chunk_pos
    }
}

/// Print a progress bar to stderr
fn print_progress(current: usize, total: usize, width: usize) {
    if total == 0 {
        return;
    }
    let percent = (current * 100) / total;
    let filled = (current * width) / total;
    let bar: String = "█".repeat(filled);
    let empty: String = "░".repeat(width - filled);
    eprint!("\r  Reading entries: [{}{}] {}% ({}/{})", bar, empty, percent, current, total);
    if current == total {
        eprintln!();
    }
}

/// Result of parsing UTXO entries
struct ParseResult {
    /// Parsed UTXO entries
    entries: Vec<UtxoEntry>,
    /// Query statistics
    stats: QueryStats,
}

/// Parse UTXO entries starting at the given offset, fetching chunks via PIR as needed
async fn parse_utxo_entries(client: &PIRClient, start_offset: usize) -> Result<ParseResult, String> {
    let mut reader = ChunkReader::new(client, start_offset).await?;
    
    // Read entry count (varint)
    let entry_count = reader.read_varint().await? as usize;
    
    if entry_count == 0 {
        let stats = reader.get_stats().clone();
        return Ok(ParseResult {
            entries: Vec::new(),
            stats,
        });
    }
    
    // Show progress for large entry counts
    let show_progress = entry_count > 100;
    if show_progress {
        eprintln!("  Fetching {} UTXO entries...", entry_count);
    }
    
    let mut entries = Vec::with_capacity(entry_count.min(10000)); // Cap preallocation
    
    // Read first entry: [4B txid LE] [varint vout] [varint amount]
    let txid = reader.read_u32_le().await?;
    let vout = reader.read_varint().await? as u32;
    let amount = reader.read_varint().await?;
    
    entries.push(UtxoEntry { txid, vout, amount });
    
    if show_progress {
        print_progress(1, entry_count, 30);
    }
    
    // Read remaining entries: [varint delta_txid] [varint vout] [varint amount]
    // delta_txid = prev_txid wrapping_sub this_txid
    // So: this_txid = prev_txid wrapping_sub delta_txid
    let mut prev_txid = txid;
    
    // Progress update interval (update every 1% or at least every 100 entries)
    let progress_interval = ((entry_count / 100).max(100)).min(1000);
    
    for i in 1..entry_count {
        let delta = reader.read_varint().await? as u32;
        let txid = prev_txid.wrapping_sub(delta);
        let vout = reader.read_varint().await? as u32;
        let amount = reader.read_varint().await?;
        
        entries.push(UtxoEntry { txid, vout, amount });
        prev_txid = txid;
        
        // Update progress periodically
        if show_progress && (i % progress_interval == 0 || i == entry_count - 1) {
            print_progress(i + 1, entry_count, 30);
        }
    }
    
    let stats = reader.get_stats().clone();
    Ok(ParseResult { entries, stats })
}

/// Count UTXO entries and compute total amount without storing all entries
/// This is memory-efficient for scripts with huge numbers of UTXOs
#[allow(dead_code)]
async fn count_utxo_entries(client: &PIRClient, start_offset: usize) -> Result<(usize, u64), String> {
    let mut reader = ChunkReader::new(client, start_offset).await?;
    
    // Read entry count (varint)
    let entry_count = reader.read_varint().await? as usize;
    
    if entry_count == 0 {
        return Ok((0, 0));
    }
    
    let mut total_amount: u64 = 0;
    
    // Read first entry
    let _txid = reader.read_u32_le().await?;
    let _vout = reader.read_varint().await? as u32;
    let amount = reader.read_varint().await?;
    total_amount += amount;
    
    // Read remaining entries
    for _ in 1..entry_count {
        let _delta = reader.read_varint().await?;
        let _vout = reader.read_varint().await?;
        let amount = reader.read_varint().await?;
        total_amount += amount;
    }
    
    Ok((entry_count, total_amount))
}

// ============================================================================
// COMMAND LINE PARSING
// ============================================================================

/// Parse command line arguments
fn parse_args(args: &[String]) -> (ClientConfig, Option<String>, bool) {
    let mut config = ClientConfig::default();
    let mut script_input: Option<String> = None;
    let mut use_hash = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--server1" | "-s1" => {
                if i + 1 < args.len() {
                    config.server1_addr = args[i + 1].clone();
                    i += 1;
                }
            }
            "--server2" | "-s2" => {
                if i + 1 < args.len() {
                    config.server2_addr = args[i + 1].clone();
                    i += 1;
                }
            }
            "--hash" => {
                use_hash = true;
            }
            "--help" | "-h" => {
                print_help(&args[0]);
                std::process::exit(0);
            }
            _ => {
                if !args[i].starts_with('-') && script_input.is_none() {
                    script_input = Some(args[i].clone());
                }
            }
        }
        i += 1;
    }

    (config, script_input, use_hash)
}

fn print_help(program: &str) {
    println!("Two-Phase DPF-PIR Client for UTXO Lookup");
    println!();
    println!("Usage:");
    println!("  {} [OPTIONS] <SCRIPT_HEX_OR_HASH>", program);
    println!();
    println!("Arguments:");
    println!("  <SCRIPT_HEX_OR_HASH>  Script pubkey hex or RIPEMD160 hash");
    println!();
    println!("Options:");
    println!("  --server1, -s1 <ADDR>  Server 1 address (default: 127.0.0.1:{})", SERVER1_PORT);
    println!("  --server2, -s2 <ADDR>  Server 2 address (default: 127.0.0.1:{})", SERVER2_PORT);
    println!("  --hash                 Treat input as RIPEMD160 hash (40 hex chars)");
    println!("  --help, -h             Show this help message");
    println!();
    println!("Examples:");
    println!("  # Single query with script pubkey:");
    println!("  {} 76a914e4986f7364f238102f1889ef9d24d80e2d2d7a4488ac", program);
    println!();
    println!("  # Single query with RIPEMD160 hash:");
    println!("  {} 09d9fb5e2c298cdf69a06fdc188334305e9cb20d --hash", program);
}

// ============================================================================
// MAIN
// ============================================================================

#[tokio::main]
async fn main() {
    // Initialize logger
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let args: Vec<String> = env::args().collect();
    let (config, script_input, use_hash) = parse_args(&args);

    // Create client
    let client = PIRClient::new(config);

    // Get script hex
    let script_hex = match script_input {
        Some(s) => s,
        None => {
            error!("No script provided. Use --help for usage.");
            std::process::exit(1);
        }
    };

    // Compute script hash
    let script_hash = if use_hash {
        // Input is already a RIPEMD160 hash
        let hash_bytes = match hex2bin(&script_hex) {
            Ok(h) => h,
            Err(e) => {
                error!("Error parsing hash hex: {}", e);
                std::process::exit(1);
            }
        };
        if hash_bytes.len() != KEY_SIZE {
            error!("RIPEMD160 hash must be exactly 20 bytes (40 hex chars), got {} bytes", 
                   hash_bytes.len());
            std::process::exit(1);
        }
        let mut hash = [0u8; KEY_SIZE];
        hash.copy_from_slice(&hash_bytes);
        hash
    } else {
        // Input is a script pubkey hex
        match script_to_hash(&script_hex) {
            Ok(h) => h,
            Err(e) => {
                error!("Error computing script hash: {}", e);
                std::process::exit(1);
            }
        }
    };

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║              Two-Phase DPF-PIR UTXO Lookup                   ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║ Script input: {:<46}║", &script_hex[..std::cmp::min(script_hex.len(), 46)]);
    println!("║ RIPEMD160:    {:<46}║", bin2hex(&script_hash));
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // Perform two-phase lookup
    match client.lookup_utxo(&script_hash).await {
        Ok(Some(offset)) => {
            let local_offset = offset as usize % CHUNK_SIZE;
            println!("✓ Lookup successful!");
            println!("  Chunk offset: {}", offset);
            println!("  Chunk index:  {}", offset as usize / CHUNK_SIZE);
            println!("  Local offset: {}", local_offset);
            println!();

            // Parse UTXO entries (fetches chunks via PIR as needed)
            match parse_utxo_entries(&client, offset as usize).await {
                Ok(result) => {
                    let total_amount: u64 = result.entries.iter().map(|e| e.amount).sum();
                    let stats = &result.stats;
                    
                    println!("╔══════════════════════════════════════════════════════════════╗");
                    println!("║                    UTXO QUERY RESULT                        ║");
                    println!("╠══════════════════════════════════════════════════════════════╣");
                    println!("║ UTXO Count:   {:<45}║", result.entries.len());
                    println!("║ Total Amount: {:<45}║", format!("{} satoshis ({:.8} BTC)", 
                        total_amount, total_amount as f64 / 100_000_000.0));
                    println!("╠══════════════════════════════════════════════════════════════╣");
                    println!("║                    QUERY STATISTICS                         ║");
                    println!("╠══════════════════════════════════════════════════════════════╣");
                    println!("║ Chunk Queries:    {:<40}║", stats.chunk_queries);
                    println!("║ Chunks Range:     {:<40}║", 
                        format!("[{}..{}]", stats.start_chunk_index, stats.end_chunk_index));
                    println!("║ Data Retrieved:   {:<40}║", 
                        format!("{} bytes ({:.2} KB)", stats.total_bytes_received, 
                               stats.total_bytes_received as f64 / 1024.0));
                    println!("║ Data Consumed:    {:<40}║", 
                        format!("{} bytes", stats.bytes_read));
                    println!("╚══════════════════════════════════════════════════════════════╝");
                    println!();

                    // Display UTXO entries (limit to first 20 for display)
                    let display_count = result.entries.len().min(20);
                    if result.entries.len() > 20 {
                        println!("Showing first 20 of {} UTXOs:", result.entries.len());
                    } else {
                        println!("UTXO Entries:");
                    }
                    println!();

                    for (i, entry) in result.entries.iter().take(display_count).enumerate() {
                        println!("  UTXO #{}:", i + 1);
                        println!("    TXID (4B mapped): {}", entry.txid);
                        println!("    Vout:             {}", entry.vout);
                        println!("    Amount:           {} satoshis ({:.8} BTC)", 
                            entry.amount, entry.amount as f64 / 100_000_000.0);
                    }

                    if result.entries.len() > 20 {
                        println!();
                        println!("  ... and {} more UTXOs", result.entries.len() - 20);
                    }
                }
                Err(e) => {
                    error!("Failed to parse UTXO entries: {}", e);
                    println!("Chunk data retrieved but parsing failed: {}", e);
                }
            }
        }
        Ok(None) => {
            println!("✗ Script hash not found in database.");
            println!("  This address has no UTXOs in the database.");
        }
        Err(e) => {
            error!("Lookup failed: {}", e);
            std::process::exit(1);
        }
    }
}