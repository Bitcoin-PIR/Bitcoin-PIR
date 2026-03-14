//! DPF-PIR Client
//!
//! This binary runs a PIR client that queries two servers for scriptPubkey data.
//! It can also peek at the local data file to verify PIR query results.
//!
//! The client supports querying specific databases on the server through the
//! database ID parameter.

use dpf_pir::{
    ClientConfig, Database, DatabaseConfig, CuckooDatabase, 
    Request, Response, ScriptHash, KEY_SIZE, DEFAULT_DATABASE_ID,
    cuckoo_locations_default,
};
use libdpf::Dpf;
use log::{error, info, warn};
use ripemd::{Digest, Ripemd160};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Default data file path for peeking
const DEFAULT_DATA_FILE: &str = "/Volumes/Bitcoin/pir/utxo_chunks_cuckoo.bin";

/// PIR Client
struct Client {
    config: ClientConfig,
    database_id: String,
}

impl Client {
    /// Create a new client with the given configuration
    fn new(config: ClientConfig, database_id: String) -> Self {
        Self { config, database_id }
    }

    /// Query for a script hash using two-location (cuckoo) hashing
    async fn query_two_locations(
        &self,
        script_hash: &ScriptHash,
        num_buckets: usize,
        loc1: usize,
        loc2: usize,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        info!(
            "Querying for script hash: loc1={}, loc2={}",
            loc1, loc2
        );

        // Calculate the domain size parameter n (domain is 2^n)
        // We need 2^n >= num_buckets, so n = ceil(log2(num_buckets))
        let n = (self.config.num_buckets as f64).log2().ceil() as u8;
        let domain_size = 1u64 << n;
        info!("Using DPF domain: 2^{} = {} (num_buckets={})", n, domain_size, self.config.num_buckets);

        // Create DPF instance
        let dpf = Dpf::with_default_key();

        // Generate DPF keys for both locations
        let (k0_loc1, k1_loc1) = dpf.gen(loc1 as u64, n);
        let (k0_loc2, k1_loc2) = dpf.gen(loc2 as u64, n);

        // Serialize the DPF keys
        let k0_loc1_bytes = k0_loc1.to_bytes();
        let k1_loc1_bytes = k1_loc1.to_bytes();
        let k0_loc2_bytes = k0_loc2.to_bytes();
        let k1_loc2_bytes = k1_loc2.to_bytes();

        info!("DPF key sizes: loc1={} bytes, loc2={} bytes", k0_loc1_bytes.len(), k0_loc2_bytes.len());

        // Query both servers concurrently
        // Use the new QueryDatabase request with database ID
        let server1_future = self.query_server_database(
            &self.config.server1_addr,
            &self.database_id,
            &k0_loc1_bytes,
            &k0_loc2_bytes,
        );
        let server2_future = self.query_server_database(
            &self.config.server2_addr,
            &self.database_id,
            &k1_loc1_bytes,
            &k1_loc2_bytes,
        );

        let (result1, result2) = tokio::try_join!(server1_future, server2_future)?;

        // XOR results from both servers for each query independently
        let combined_loc1 = xor_bytes(&result1.0, &result2.0);
        let combined_loc2 = xor_bytes(&result1.1, &result2.1);
        
        info!("Combined results: loc1={} bytes, loc2={} bytes", combined_loc1.len(), combined_loc2.len());
        
        Ok((combined_loc1, combined_loc2))
    }

    /// Query a server for a specific database with two locations
    async fn query_server_database(
        &self,
        addr: &str,
        database_id: &str,
        dpf_key1: &[u8],
        dpf_key2: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        info!("Connecting to server at {} for database '{}' query", addr, database_id);

        // Connect to the server
        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;

        // Create the request with database ID
        let request = Request::QueryDatabase {
            database_id: database_id.to_string(),
            dpf_key1: dpf_key1.to_vec(),
            dpf_key2: dpf_key2.to_vec(),
        };

        // Serialize and send the request
        send_request(&mut stream, &request).await?;

        // Receive and parse the response
        let response = receive_response(&mut stream).await?;

        match response {
            Response::QueryTwoResults { data1, data2 } => {
                info!("Received two results from {}: data1={} bytes, data2={} bytes", 
                      addr, data1.len(), data2.len());
                Ok((data1, data2))
            }
            Response::QueryResult { .. } => Err("Unexpected single QueryResult response".to_string()),
            Response::Error { message } => Err(format!("Server error: {}", message)),
            _ => Err(format!("Unexpected response: {:?}", response)),
        }
    }

    /// Query a server for a specific database with a single location
    #[allow(dead_code)]
    async fn query_server_single(
        &self,
        addr: &str,
        database_id: &str,
        dpf_key: &[u8],
    ) -> Result<Vec<u8>, String> {
        info!("Connecting to server at {} for database '{}' single query", addr, database_id);

        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;

        let request = Request::QueryDatabaseSingle {
            database_id: database_id.to_string(),
            dpf_key: dpf_key.to_vec(),
        };

        send_request(&mut stream, &request).await?;
        let response = receive_response(&mut stream).await?;

        match response {
            Response::QueryResult { data } => {
                info!("Received result from {}: {} bytes", addr, data.len());
                Ok(data)
            }
            Response::Error { message } => Err(format!("Server error: {}", message)),
            _ => Err(format!("Unexpected response: {:?}", response)),
        }
    }

    /// List available databases on a server
    async fn list_databases(&self, addr: &str) -> Result<Vec<dpf_pir::DatabaseInfo>, String> {
        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;

        let request = Request::ListDatabases;
        send_request(&mut stream, &request).await?;
        let response = receive_response(&mut stream).await?;

        match response {
            Response::DatabaseList { databases } => Ok(databases),
            Response::Error { message } => Err(format!("Server error: {}", message)),
            _ => Err(format!("Unexpected response: {:?}", response)),
        }
    }

    /// Get information about a specific database
    async fn get_database_info(&self, addr: &str, database_id: &str) -> Result<dpf_pir::DatabaseInfo, String> {
        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;

        let request = Request::GetDatabaseInfo {
            database_id: database_id.to_string(),
        };
        send_request(&mut stream, &request).await?;
        let response = receive_response(&mut stream).await?;

        match response {
            Response::DatabaseInfo { info } => Ok(info),
            Response::Error { message } => Err(format!("Server error: {}", message)),
            _ => Err(format!("Unexpected response: {:?}", response)),
        }
    }

    /// Ping a server to check if it's alive
    #[allow(dead_code)]
    async fn ping(&self, addr: &str) -> Result<bool, String> {
        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;

        let request = Request::Ping;
        send_request(&mut stream, &request).await?;
        let response = receive_response(&mut stream).await?;

        Ok(matches!(response, Response::Pong))
    }
}

/// Send a request to the server
async fn send_request(stream: &mut TcpStream, request: &Request) -> Result<(), String> {
    let request_bytes = bincode::serialize(request)
        .map_err(|e| format!("Failed to serialize request: {}", e))?;

    // Send request length (4 bytes)
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
    // Read response length (4 bytes)
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

/// XOR two byte vectors together (helper for combining DPF results)
fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    let min_len = a.len().min(b.len());
    let mut result = vec![0u8; min_len];
    for i in 0..min_len {
        result[i] = a[i] ^ b[i];
    }
    result
}

/// Peek at the local data file using a Database trait object
fn peek_at_locations(
    db: &dyn Database,
    script_hash: &ScriptHash,
) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>), String> {
    // Compute locations using the database's hash functions
    let locations = db.compute_locations(script_hash);
    
    if locations.len() < 2 {
        return Err("Expected at least 2 locations for cuckoo hash".to_string());
    }
    
    let loc1 = locations[0];
    let loc2 = locations[1];

    // Read bucket entries at each location
    let entries_loc1 = db.read_bucket(loc1)?
        .into_iter()
        .filter(|entry| entry[..KEY_SIZE].iter().any(|&b| b != 0))
        .collect();

    let entries_loc2 = db.read_bucket(loc2)?
        .into_iter()
        .filter(|entry| entry[..KEY_SIZE].iter().any(|&b| b != 0))
        .collect();

    Ok((entries_loc1, entries_loc2))
}

/// Parse a bucket response (bucket_size * entry_size bytes) into individual entries.
/// Returns a vector of (key, offset) tuples for non-empty entries.
fn parse_bucket_response(response: &[u8], entry_size: usize, bucket_size: usize) -> Vec<([u8; KEY_SIZE], u32)> {
    let mut entries = Vec::new();
    
    let expected_size = bucket_size * entry_size;
    if response.len() < expected_size {
        warn!("Response too small: {} < {}", response.len(), expected_size);
        return entries;
    }
    
    for i in 0..bucket_size {
        let offset = i * entry_size;
        let key: [u8; KEY_SIZE] = response[offset..offset + KEY_SIZE]
            .try_into()
            .unwrap_or([0u8; KEY_SIZE]);
        
        // Check if entry is non-empty (key is not all zeros)
        if key.iter().all(|&b| b == 0) {
            continue;
        }
        
        // Extract value/offset (assumes 4-byte value after key)
        let value_offset = if offset + KEY_SIZE + 4 <= response.len() {
            u32::from_le_bytes([
                response[offset + KEY_SIZE],
                response[offset + KEY_SIZE + 1],
                response[offset + KEY_SIZE + 2],
                response[offset + KEY_SIZE + 3],
            ])
        } else {
            0
        };
        
        entries.push((key, value_offset));
    }
    
    entries
}

/// Compute RIPEMD160(SHA256(script)) - the Bitcoin script hash
fn script_to_hash(script_hex: &str) -> Result<ScriptHash, String> {
    // Decode the script from hex
    let script_bytes = hex::decode(script_hex).map_err(|e| format!("Invalid hex: {}", e))?;
    
    // Compute RIPEMD160(script)
    let ripemd160_hash = Ripemd160::digest(&script_bytes);
    
    // The result is 20 bytes (KEY_SIZE)
    let mut hash = [0u8; KEY_SIZE];
    hash.copy_from_slice(&ripemd160_hash);
    
    info!("Script hex: {} ({} bytes)", script_hex, script_bytes.len());
    info!("RIPEMD160 (script hash): {}", hex::encode(&hash));
    
    Ok(hash)
}

#[tokio::main]
async fn main() {
    // Initialize logger
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    let (config, script_hex, data_file, database_id, list_databases, db_info) = parse_args(&args);

    // Create the client
    let client = Client::new(config.clone(), database_id.clone());

    // Handle --list-databases option
    if list_databases {
        match client.list_databases(&config.server1_addr).await {
            Ok(databases) => {
                println!("Available databases on server:");
                for db in &databases {
                    println!("  - {} ({} buckets, {} locations)", 
                        db.id, db.num_buckets, db.num_locations);
                }
            }
            Err(e) => {
                error!("Failed to list databases: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    // Handle --db-info option
    if let Some(db_id) = db_info {
        match client.get_database_info(&config.server1_addr, &db_id).await {
            Ok(info) => {
                println!("Database: {}", info.id);
                println!("  Path: {}", info.data_path);
                println!("  Entry size: {} bytes", info.entry_size);
                println!("  Bucket size: {} entries", info.bucket_size);
                println!("  Num buckets: {}", info.num_buckets);
                println!("  Num locations: {}", info.num_locations);
                println!("  Total size: {} bytes", info.total_size);
            }
            Err(e) => {
                error!("Failed to get database info: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    // Convert script hex to script hash (RIPEMD160(script))
    let script_hash = match script_to_hash(&script_hex) {
        Ok(h) => h,
        Err(e) => {
            error!("Failed to process script: {}", e);
            std::process::exit(1);
        }
    };

    // Create a local database for peeking (using the Database trait)
    let db_config = DatabaseConfig::new(
        &database_id,
        &data_file,
        24,  // entry_size (20-byte key + 4-byte offset)
        4,   // bucket_size
        config.num_buckets,
        2,   // num_locations (cuckoo)
    );
    
    let local_db = match CuckooDatabase::new(db_config) {
        Ok(db) => db,
        Err(e) => {
            warn!("Could not open local database for peeking: {}", e);
            warn!("PIR query will proceed without local verification.");
            
            // Perform the PIR query without peeking
            perform_pir_query(&client, &script_hash, None).await;
            return;
        }
    };

    // Compute cuckoo hash locations for display
    let locations = local_db.compute_locations(&script_hash);
    let (loc1, loc2) = if locations.len() >= 2 {
        (locations[0], locations[1])
    } else {
        error!("Expected 2 locations from cuckoo hash");
        std::process::exit(1);
    };

    info!("Cuckoo hash locations: loc1={}, loc2={}", loc1, loc2);

    // Peek at the local data file
    let peek_result = peek_at_locations(&local_db as &dyn Database, &script_hash);
    
    // Find the expected offset from peeked data
    let expected_offset = match &peek_result {
        Ok((entries_loc1, entries_loc2)) => {
            let mut offset = None;
            // Look for matching entry in loc1
            for entry in entries_loc1 {
                if &entry[..KEY_SIZE] == script_hash.as_slice() {
                    offset = Some(u32::from_le_bytes([
                        entry[KEY_SIZE],
                        entry[KEY_SIZE + 1],
                        entry[KEY_SIZE + 2],
                        entry[KEY_SIZE + 3],
                    ]));
                    info!("Found expected entry at loc1 with offset {}", offset.unwrap());
                    break;
                }
            }

            if offset.is_none() {
                // Look for matching entry in loc2
                for entry in entries_loc2 {
                    if &entry[..KEY_SIZE] == script_hash.as_slice() {
                        offset = Some(u32::from_le_bytes([
                            entry[KEY_SIZE],
                            entry[KEY_SIZE + 1],
                            entry[KEY_SIZE + 2],
                            entry[KEY_SIZE + 3],
                        ]));
                        info!("Found expected entry at loc2 with offset {}", offset.unwrap());
                        break;
                    }
                }
            }

            offset
        }
        Err(e) => {
            warn!("Failed to peek at data file: {}", e);
            None
        }
    };

    // Perform the PIR query
    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                    DPF-PIR QUERY RESULT                     ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║ Database: {:<50}║", database_id);
    println!("║ Script Hash: {:<47}║", hex::encode(&script_hash));
    println!("║ Cuckoo Locations: {:>10}, {:>10}              ║", loc1, loc2);
    println!("╚══════════════════════════════════════════════════════════════╝");

    perform_pir_query(&client, &script_hash, expected_offset).await;
}

/// Perform the PIR query and display results
async fn perform_pir_query(
    client: &Client,
    script_hash: &ScriptHash,
    expected_offset: Option<u32>,
) {
    // Use constants for bucket/entry sizes (standard cuckoo index values)
    let bucket_size = 4;
    let entry_size = 24;

    // Compute cuckoo locations directly using the hash function
    let (loc1, loc2) = cuckoo_locations_default(script_hash, client.config.num_buckets);

    match client.query_two_locations(script_hash, client.config.num_buckets, loc1, loc2).await {
        Ok((result_loc1, result_loc2)) => {
            // Parse both bucket responses
            let entries_loc1 = parse_bucket_response(&result_loc1, entry_size, bucket_size);
            let entries_loc2 = parse_bucket_response(&result_loc2, entry_size, bucket_size);
            
            // Find matching entry in either result
            let mut found_match = None;
            
            // Search in loc1 result
            for (key, offset) in &entries_loc1 {
                if key == script_hash.as_slice() {
                    found_match = Some((*offset, "loc1", loc1));
                    break;
                }
            }
            
            // Search in loc2 result if not found in loc1
            if found_match.is_none() {
                for (key, offset) in &entries_loc2 {
                    if key == script_hash.as_slice() {
                        found_match = Some((*offset, "loc2", loc2));
                        break;
                    }
                }
            }
            
            // Display result
            println!();
            match found_match {
                Some((offset, location, bucket)) => {
                    println!("╔══════════════════════════════════════════════════════════════╗");
                    println!("║  ✅ MATCH FOUND!                                             ║");
                    println!("╠══════════════════════════════════════════════════════════════╣");
                    println!("║  Location: {:<48}║", format!("bucket {} ({})", bucket, location));
                    println!("║  Chunk Offset: {:<44}║", offset);
                    println!("╠══════════════════════════════════════════════════════════════╣");
                    
                    // Compare with expected offset
                    if let Some(expected) = expected_offset {
                        if expected == offset {
                            println!("║  Verification: ✅ Offset matches expected value             ║");
                        } else {
                            println!("║  Verification: ⚠️  Offset mismatch (expected: {})            ║", expected);
                        }
                    }
                    println!("╚══════════════════════════════════════════════════════════════╝");
                    
                    // Show bucket contents
                    println!();
                    println!("┌─ Bucket Contents (from {}) ─────────────────────────────────┐", location);
                    let entries = if location == "loc1" { &entries_loc1 } else { &entries_loc2 };
                    for (i, (key, off)) in entries.iter().enumerate() {
                        let marker = if key == script_hash.as_slice() { " ◄── MATCH" } else { "" };
                        println!("│ Entry {}: key={} offset={:>10}{}", 
                            i, hex::encode(&key[..8]), off, marker);
                    }
                    println!("└──────────────────────────────────────────────────────────────┘");
                }
                None => {
                    println!("╔══════════════════════════════════════════════════════════════╗");
                    println!("║  ❌ NO MATCH FOUND                                           ║");
                    println!("╠══════════════════════════════════════════════════════════════╣");
                    println!("║  The script hash was not found in either bucket response.    ║");
                    println!("║                                                              ║");
                    println!("║  Response sizes: loc1={} bytes, loc2={} bytes", 
                        result_loc1.len(), result_loc2.len());
                    println!("║  Entries found: loc1={}, loc2={}", 
                        entries_loc1.len(), entries_loc2.len());
                    println!("╚══════════════════════════════════════════════════════════════╝");
                }
            }
        }
        Err(e) => {
            println!();
            println!("╔══════════════════════════════════════════════════════════════╗");
            println!("║  ❌ QUERY FAILED                                             ║");
            println!("╠══════════════════════════════════════════════════════════════╣");
            println!("║  Error: {:<53}║", e);
            println!("╚══════════════════════════════════════════════════════════════╝");
            std::process::exit(1);
        }
    }
}

/// Parse command line arguments
fn parse_args(args: &[String]) -> (ClientConfig, String, String, String, bool, Option<String>) {
    let mut config = ClientConfig::default();
    let mut script_hex = String::new();
    let mut data_file = String::from(DEFAULT_DATA_FILE);
    let mut database_id = String::from(DEFAULT_DATABASE_ID);
    let mut list_databases = false;
    let mut db_info = None;

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
            "--buckets" | "-b" => {
                if i + 1 < args.len() {
                    config.num_buckets = args[i + 1].parse().unwrap_or(config.num_buckets);
                    i += 1;
                }
            }
            "--data" | "-d" => {
                if i + 1 < args.len() {
                    data_file = args[i + 1].clone();
                    i += 1;
                }
            }
            "--database" | "--db" => {
                if i + 1 < args.len() {
                    database_id = args[i + 1].clone();
                    i += 1;
                }
            }
            "--list-databases" | "-l" => {
                list_databases = true;
            }
            "--db-info" => {
                if i + 1 < args.len() {
                    db_info = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--help" | "-h" => {
                print_help(&args[0]);
                std::process::exit(0);
            }
            _ => {
                if args[i].starts_with('-') {
                    warn!("Unknown argument: {}", args[i]);
                } else if script_hex.is_empty() {
                    script_hex = args[i].clone();
                }
            }
        }
        i += 1;
    }

    // If listing databases or getting info, we don't need a script
    if !list_databases && db_info.is_none() && script_hex.is_empty() {
        error!("No script provided. Use --help for usage.");
        std::process::exit(1);
    }

    (config, script_hex, data_file, database_id, list_databases, db_info)
}

fn print_help(program: &str) {
    println!("DPF-PIR Client");
    println!("Usage: {} [OPTIONS] <SCRIPT_HEX>", program);
    println!();
    println!("Arguments:");
    println!("  <SCRIPT_HEX>            Script (scriptPubkey) in hex format");
    println!("                          The client will compute RIPEMD160(script)");
    println!("                          to get the 20-byte script hash for querying.");
    println!();
    println!("Options:");
    println!("  --server1, -s1 <ADDR>   Server 1 address (default: {})", ClientConfig::default().server1_addr);
    println!("  --server2, -s2 <ADDR>   Server 2 address (default: {})", ClientConfig::default().server2_addr);
    println!("  --buckets, -b <NUM>     Number of buckets (default: {})", ClientConfig::default().num_buckets);
    println!("  --data, -d <PATH>       Data file for peeking (default: {})", DEFAULT_DATA_FILE);
    println!("  --database, --db <ID>   Database ID to query (default: {})", DEFAULT_DATABASE_ID);
    println!("  --list-databases, -l    List available databases on the server");
    println!("  --db-info <ID>          Get information about a specific database");
    println!("  --help, -h              Show this help message");
    println!();
    println!("Examples:");
    println!("  # Query the default database");
    println!("  {} 76a914...{}", program, ""); // truncated for display
    println!();
    println!("  # List available databases");
    println!("  {} --list-databases", program);
    println!();
    println!("  # Query a specific database");
    println!("  {} --database map1 76a914...{}", program, "");
}