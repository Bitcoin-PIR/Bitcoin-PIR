//! DPF-PIR Client
//!
//! This binary runs a PIR client that queries two servers for scriptPubkey data.

use dpf_pir::{cuckoo_locations, ClientConfig, Request, Response, ScriptHash, KEY_SIZE};
use libdpf::Dpf;
use log::{error, info, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// PIR Client
struct Client {
    config: ClientConfig,
}

impl Client {
    /// Create a new client with the given configuration
    fn new(config: ClientConfig) -> Self {
        Self { config }
    }

    /// Query for a script hash
    async fn query(&self, script_hash: &ScriptHash) -> Result<Vec<u8>, String> {
        // Compute the two cuckoo hash locations
        let (loc1, loc2) = cuckoo_locations(script_hash, self.config.num_buckets);
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
        // For loc1: generate (k0_loc1, k1_loc1)
        // For loc2: generate (k0_loc2, k1_loc2)
        let (k0_loc1, k1_loc1) = dpf.gen(loc1 as u64, n);
        let (k0_loc2, k1_loc2) = dpf.gen(loc2 as u64, n);

        // Serialize the DPF keys
        let k0_loc1_bytes = k0_loc1.to_bytes();
        let k1_loc1_bytes = k1_loc1.to_bytes();
        let k0_loc2_bytes = k0_loc2.to_bytes();
        let k1_loc2_bytes = k1_loc2.to_bytes();

        info!("DPF key sizes: loc1={} bytes, loc2={} bytes", k0_loc1_bytes.len(), k0_loc2_bytes.len());

        // Query both servers concurrently
        // Server 1 gets k0 for both locations
        // Server 2 gets k1 for both locations
        // We need to query both locations since cuckoo hash puts item at one of two positions
        let server1_future = self.query_server_both_locs(
            &self.config.server1_addr, 
            loc1 as u64, &k0_loc1_bytes,
            loc2 as u64, &k0_loc2_bytes
        );
        let server2_future = self.query_server_both_locs(
            &self.config.server2_addr,
            loc1 as u64, &k1_loc1_bytes,
            loc2 as u64, &k1_loc2_bytes
        );

        let (result1, result2) = tokio::try_join!(server1_future, server2_future)?;

        // Combine results: XOR the results from both servers
        // The result should reveal the value at the queried location
        let combined = xor_bytes(&result1, &result2);
        info!("Combined result: {} bytes", combined.len());
        
        Ok(combined)
    }

    /// Query a server for both cuckoo hash locations
    async fn query_server_both_locs(
        &self,
        addr: &str,
        loc1: u64,
        dpf_key1: &[u8],
        loc2: u64,
        dpf_key2: &[u8],
    ) -> Result<Vec<u8>, String> {
        info!("Connecting to server at {} for 2-location query", addr);

        // Connect to the server
        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;

        // Create the request with both locations
        let request = Request::QueryTwoLocations {
            loc1,
            dpf_key1: dpf_key1.to_vec(),
            loc2,
            dpf_key2: dpf_key2.to_vec(),
        };

        // Serialize the request
        let request_bytes = bincode::serialize(&request)
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
        let response: Response = bincode::deserialize(&resp_buf)
            .map_err(|e| format!("Failed to deserialize response: {}", e))?;

        match response {
            Response::QueryResult { data } => {
                info!("Received {} bytes from {}", data.len(), addr);
                Ok(data)
            }
            Response::Error { message } => Err(format!("Server error: {}", message)),
            Response::Pong => Err("Unexpected pong response".to_string()),
        }
    }

    /// Query a single server
    #[allow(dead_code)]
    async fn query_server(
        &self,
        addr: &str,
        bucket_index: u64,
        dpf_key: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        info!("Connecting to server at {}", addr);

        // Connect to the server
        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;

        // Create the request
        let request = Request::Query {
            bucket_index,
            dpf_key,
        };

        // Serialize the request
        let request_bytes = bincode::serialize(&request)
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
        let response: Response = bincode::deserialize(&resp_buf)
            .map_err(|e| format!("Failed to deserialize response: {}", e))?;

        match response {
            Response::QueryResult { data } => {
                info!("Received {} bytes from {}", data.len(), addr);
                Ok(data)
            }
            Response::Error { message } => Err(format!("Server error: {}", message)),
            Response::Pong => Err("Unexpected pong response".to_string()),
        }
    }

    /// Ping a server to check if it's alive
    #[allow(dead_code)]
    async fn ping(&self, addr: &str) -> Result<bool, String> {
        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;

        let request = Request::Ping;
        let request_bytes = bincode::serialize(&request)
            .map_err(|e| format!("Failed to serialize request: {}", e))?;

        let len = request_bytes.len() as u32;
        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| format!("Failed to write request length: {}", e))?;

        stream
            .write_all(&request_bytes)
            .await
            .map_err(|e| format!("Failed to write request body: {}", e))?;

        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| format!("Failed to read response length: {}", e))?;
        let resp_len = u32::from_be_bytes(len_buf) as usize;

        let mut resp_buf = vec![0u8; resp_len];
        stream
            .read_exact(&mut resp_buf)
            .await
            .map_err(|e| format!("Failed to read response body: {}", e))?;

        let response: Response = bincode::deserialize(&resp_buf)
            .map_err(|e| format!("Failed to deserialize response: {}", e))?;

        Ok(matches!(response, Response::Pong))
    }
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

/// Parse a script hash from hex string
fn parse_script_hash(hex: &str) -> Result<ScriptHash, String> {
    let bytes = hex::decode(hex).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != KEY_SIZE {
        return Err(format!(
            "Script hash must be {} bytes, got {}",
            KEY_SIZE,
            bytes.len()
        ));
    }
    let mut hash = [0u8; KEY_SIZE];
    hash.copy_from_slice(&bytes);
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
    let (config, script_hash_hex) = parse_args(&args);

    // Create the client
    let client = Client::new(config);

    // Parse the script hash
    let script_hash = match parse_script_hash(&script_hash_hex) {
        Ok(h) => h,
        Err(e) => {
            error!("Failed to parse script hash: {}", e);
            std::process::exit(1);
        }
    };

    info!("Querying for script hash: {}", script_hash_hex);

    // Perform the query
    match client.query(&script_hash).await {
        Ok(data) => {
            info!("Query successful! Result: {} bytes", data.len());
            println!("Result: {}", hex::encode(&data));
        }
        Err(e) => {
            error!("Query failed: {}", e);
            std::process::exit(1);
        }
    }
}

/// Parse command line arguments
fn parse_args(args: &[String]) -> (ClientConfig, String) {
    let mut config = ClientConfig::default();
    let mut script_hash = String::new();

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
            "--help" | "-h" => {
                println!("DPF-PIR Client");
                println!("Usage: {} [OPTIONS] <SCRIPT_HASH>", args[0]);
                println!();
                println!("Arguments:");
                println!("  <SCRIPT_HASH>           Script hash to query (40 hex characters)");
                println!();
                println!("Options:");
                println!("  --server1, -s1 <ADDR>   Server 1 address (default: {})", config.server1_addr);
                println!("  --server2, -s2 <ADDR>   Server 2 address (default: {})", config.server2_addr);
                println!("  --buckets, -b <NUM>     Number of buckets (default: {})", config.num_buckets);
                println!("  --help, -h              Show this help message");
                std::process::exit(0);
            }
            _ => {
                if args[i].starts_with('-') {
                    warn!("Unknown argument: {}", args[i]);
                } else if script_hash.is_empty() {
                    script_hash = args[i].clone();
                }
            }
        }
        i += 1;
    }

    if script_hash.is_empty() {
        error!("No script hash provided. Use --help for usage.");
        std::process::exit(1);
    }

    (config, script_hash)
}