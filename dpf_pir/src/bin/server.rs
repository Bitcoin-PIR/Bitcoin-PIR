//! DPF-PIR Server
//!
//! This binary runs a PIR server that listens for client queries.
//!
//! The server evaluates DPF keys to produce a bitmap indicating which buckets
//! to include in the XOR computation, then either:
//! - Streams through the data file with BufReader and computes XOR (memory-efficient)
//! - Loads data into memory at startup and computes XOR (faster for repeated queries)

use dpf_pir::{Request, Response, ServerConfig};
use libdpf::{Dpf, DpfKey};
use log::{error, info, warn};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// In-memory data storage (optional)
struct DataStore {
    /// The loaded data (if load_to_memory is true)
    data: Option<Vec<u8>>,
    /// Path to the data file
    path: String,
    /// Number of buckets
    num_buckets: usize,
    /// Size of each bucket in bytes (entry_size * bucket_size)
    bucket_bytes: usize,
}

impl DataStore {
    /// Create a new data store
    fn new(config: &ServerConfig) -> std::io::Result<Self> {
        let bucket_bytes = config.bucket_size * config.entry_size;
        
        let mut store = Self {
            data: None,
            path: config.data_path.clone(),
            num_buckets: config.num_buckets,
            bucket_bytes,
        };
        
        if config.load_to_memory {
            store.load_data()?;
        }
        
        Ok(store)
    }
    
    /// Load data into memory
    fn load_data(&mut self) -> std::io::Result<()> {
        info!("Loading data into memory from {}...", self.path);
        
        let file = File::open(&self.path)?;
        let metadata = file.metadata()?;
        let file_size = metadata.len() as usize;
        
        info!("File size: {} bytes", file_size);
        
        let mut data = Vec::with_capacity(file_size);
        let mut reader = BufReader::new(file);
        reader.read_to_end(&mut data)?;
        
        let expected_size = self.num_buckets * self.bucket_bytes;
        if data.len() < expected_size {
            warn!(
                "Data file smaller than expected: {} < {} ({} buckets * {} bytes/bucket)",
                data.len(), expected_size, self.num_buckets, self.bucket_bytes
            );
        }
        
        self.data = Some(data);
        info!("Data loaded: {} bytes", self.data.as_ref().unwrap().len());
        
        Ok(())
    }
    
    /// Compute XOR of buckets indicated by the bitmap (in-memory version)
    fn xor_buckets_memory(&self, bitmap: &[u8]) -> Result<Vec<u8>, String> {
        let data = self.data.as_ref().ok_or("Data not loaded into memory")?;
        
        // Initialize result with zeros
        let mut result = vec![0u8; self.bucket_bytes];
        
        // Number of bits in bitmap
        let num_bits = bitmap.len() * 8;
        let buckets_to_process = num_bits.min(self.num_buckets);
        
        let mut buckets_included = 0usize;
        
        // Iterate through each bit in the bitmap
        for bucket_idx in 0..buckets_to_process {
            // Get the byte and bit position
            let byte_idx = bucket_idx / 8;
            let bit_idx = bucket_idx % 8;
            
            // Check if this bit is set
            if (bitmap[byte_idx] >> bit_idx) & 1 == 1 {
                // Compute offset for this bucket
                let offset = bucket_idx * self.bucket_bytes;
                
                // Check bounds
                if offset + self.bucket_bytes <= data.len() {
                    // XOR with result
                    for i in 0..self.bucket_bytes {
                        result[i] ^= data[offset + i];
                    }
                    buckets_included += 1;
                }
            }
        }
        
        info!("XORed {} buckets (from memory)", buckets_included);
        Ok(result)
    }
    
    /// Compute XOR of buckets indicated by the bitmap (streaming version)
    fn xor_buckets_streaming(&self, bitmap: &[u8]) -> Result<Vec<u8>, String> {
        let file = File::open(&self.path)
            .map_err(|e| format!("Failed to open data file: {}", e))?;
        let mut reader = BufReader::new(file);
        
        // Initialize result with zeros
        let mut result = vec![0u8; self.bucket_bytes];
        
        // Number of bits in bitmap
        let num_bits = bitmap.len() * 8;
        let buckets_to_process = num_bits.min(self.num_buckets);
        
        let mut buckets_included = 0usize;
        let mut current_offset: u64 = 0;
        
        // Buffer for reading a single bucket
        let mut bucket_buf = vec![0u8; self.bucket_bytes];
        
        // Iterate through each bit in the bitmap
        for bucket_idx in 0..buckets_to_process {
            // Get the byte and bit position
            let byte_idx = bucket_idx / 8;
            let bit_idx = bucket_idx % 8;
            
            // Check if this bit is set
            if (bitmap[byte_idx] >> bit_idx) & 1 == 1 {
                // Compute offset for this bucket
                let target_offset = (bucket_idx * self.bucket_bytes) as u64;
                
                // Seek if needed
                if current_offset != target_offset {
                    reader.seek(SeekFrom::Start(target_offset))
                        .map_err(|e| format!("Failed to seek: {}", e))?;
                    current_offset = target_offset;
                }
                
                // Read the bucket
                reader.read_exact(&mut bucket_buf)
                    .map_err(|e| format!("Failed to read bucket {}: {}", bucket_idx, e))?;
                current_offset += self.bucket_bytes as u64;
                
                // XOR with result
                for i in 0..self.bucket_bytes {
                    result[i] ^= bucket_buf[i];
                }
                buckets_included += 1;
            }
        }
        
        info!("XORed {} buckets (streaming from disk)", buckets_included);
        Ok(result)
    }
    
    /// Compute XOR of buckets indicated by the bitmap
    fn xor_buckets(&self, bitmap: &[u8]) -> Result<Vec<u8>, String> {
        if self.data.is_some() {
            self.xor_buckets_memory(bitmap)
        } else {
            self.xor_buckets_streaming(bitmap)
        }
    }
}

/// Convert DPF evaluation results (Vec<Block>) to a bitmap
/// Each block is 128 bits, and each bit in the block indicates whether
/// the corresponding bucket should be included in the XOR
fn dpf_results_to_bitmap(results: &[libdpf::Block], num_buckets: usize) -> Vec<u8> {
    // Calculate bitmap size: we need num_buckets bits, rounded up to nearest byte
    let bitmap_size = (num_buckets + 7) / 8;
    let mut bitmap = vec![0u8; bitmap_size];
    
    // Each block represents 128 buckets (one bit per bucket)
    // The block's bit at position i indicates bucket (block_idx * 128 + i)
    for (block_idx, block) in results.iter().enumerate() {
        let block_bytes = block.to_bytes();
        
        // Each block has 16 bytes = 128 bits
        for (byte_idx, &byte) in block_bytes.iter().enumerate() {
            let bucket_base = block_idx * 128 + byte_idx * 8;
            if bucket_base >= num_buckets {
                break;
            }
            
            // Determine the position in the bitmap
            let bitmap_byte_idx = bucket_base / 8;
            
            // Copy bits, respecting num_buckets boundary
            let bits_to_copy = if bucket_base + 8 <= num_buckets {
                8
            } else {
                num_buckets - bucket_base
            };
            
            // We need to place these bits at the correct position in the bitmap
            // The byte at byte_idx in the block corresponds to bits [bucket_base, bucket_base+7)
            // In the bitmap, this is at byte bitmap_byte_idx (assuming alignment)
            
            if byte_idx == 0 && block_idx * 128 % 8 == 0 {
                // Aligned case - direct copy
                if bitmap_byte_idx < bitmap.len() {
                    let valid_mask = if bits_to_copy < 8 {
                        (1u8 << bits_to_copy) - 1
                    } else {
                        0xFF
                    };
                    bitmap[bitmap_byte_idx] = byte & valid_mask;
                }
            } else {
                // General case - copy bit by bit
                for bit_idx in 0..bits_to_copy {
                    let bucket_idx = bucket_base + bit_idx;
                    if bucket_idx >= num_buckets {
                        break;
                    }
                    
                    if (byte >> bit_idx) & 1 == 1 {
                        let bitmap_byte = bucket_idx / 8;
                        let bitmap_bit = bucket_idx % 8;
                        if bitmap_byte < bitmap.len() {
                            bitmap[bitmap_byte] |= 1 << bitmap_bit;
                        }
                    }
                }
            }
        }
    }
    
    bitmap
}

/// Handle a single client connection
async fn handle_connection(mut stream: TcpStream, config: &ServerConfig, data_store: &DataStore) {
    let addr = stream.peer_addr().unwrap_or_else(|_| "unknown".parse().unwrap());
    info!("New connection from {}", addr);

    // Read the request length (4 bytes)
    let mut len_buf = [0u8; 4];
    if let Err(e) = stream.read_exact(&mut len_buf).await {
        error!("Failed to read request length from {}: {}", addr, e);
        return;
    }
    let req_len = u32::from_be_bytes(len_buf) as usize;

    // Read the request body
    let mut req_buf = vec![0u8; req_len];
    if let Err(e) = stream.read_exact(&mut req_buf).await {
        error!("Failed to read request body from {}: {}", addr, e);
        return;
    }

    // Deserialize the request
    let request: Request = match bincode::deserialize(&req_buf) {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to deserialize request from {}: {}", addr, e);
            let response = Response::Error {
                message: format!("Invalid request: {}", e),
            };
            send_response(&mut stream, &response).await;
            return;
        }
    };

    // Handle the request
    let response = match request {
        Request::Ping => Response::Pong,
        Request::Query { bucket_index, dpf_key } => {
            handle_query(bucket_index, dpf_key, config, data_store).await
        }
        Request::QueryTwoLocations { loc1, dpf_key1, loc2, dpf_key2 } => {
            handle_query_two_locations(loc1, dpf_key1, loc2, dpf_key2, config, data_store).await
        }
    };

    // Send the response
    send_response(&mut stream, &response).await;
    info!("Connection from {} closed", addr);
}

/// Handle a PIR query request
async fn handle_query(
    bucket_index: u64,
    dpf_key: Vec<u8>,
    config: &ServerConfig,
    data_store: &DataStore,
) -> Response {
    info!(
        "Received query for bucket {}, DPF key length: {}",
        bucket_index,
        dpf_key.len()
    );

    // Parse the DPF key
    let key = match DpfKey::from_bytes(&dpf_key) {
        Ok(k) => k,
        Err(e) => {
            return Response::Error {
                message: format!("Invalid DPF key: {}", e),
            };
        }
    };

    info!("DPF key parsed: n={}, domain=2^{}", key.n, key.n);

    // Create DPF evaluator
    let dpf = Dpf::with_default_key();

    // Evaluate DPF at all points in the domain
    // The result is a vector of 2^(n-7) blocks
    let results = dpf.eval_full(&key);
    
    info!("DPF evaluation complete: {} blocks", results.len());

    // Convert DPF results to a bitmap
    // Each block is 128 bits, each bit indicates whether to include that bucket
    let bitmap = dpf_results_to_bitmap(&results, config.num_buckets);
    
    info!("Bitmap created: {} bytes ({} buckets)", bitmap.len(), config.num_buckets);

    // Count set bits for logging
    let set_bits: usize = bitmap.iter().map(|b| b.count_ones() as usize).sum();
    info!("Bitmap has {} bits set", set_bits);

    // Compute XOR of buckets indicated by the bitmap
    match data_store.xor_buckets(&bitmap) {
        Ok(data) => {
            info!("Query result: {} bytes", data.len());
            Response::QueryResult { data }
        }
        Err(e) => {
            error!("Failed to compute XOR: {}", e);
            Response::Error {
                message: format!("Failed to compute result: {}", e),
            }
        }
    }
}

/// Handle a query for two locations (cuckoo hash has two possible positions)
async fn handle_query_two_locations(
    loc1: u64,
    dpf_key1: Vec<u8>,
    loc2: u64,
    dpf_key2: Vec<u8>,
    config: &ServerConfig,
    data_store: &DataStore,
) -> Response {
    info!(
        "Received two-location query: loc1={}, key1_len={}, loc2={}, key2_len={}",
        loc1, dpf_key1.len(), loc2, dpf_key2.len()
    );

    // Parse both DPF keys
    let key1 = match DpfKey::from_bytes(&dpf_key1) {
        Ok(k) => k,
        Err(e) => {
            return Response::Error {
                message: format!("Invalid DPF key1: {}", e),
            };
        }
    };

    let key2 = match DpfKey::from_bytes(&dpf_key2) {
        Ok(k) => k,
        Err(e) => {
            return Response::Error {
                message: format!("Invalid DPF key2: {}", e),
            };
        }
    };

    info!("DPF keys parsed: key1.n={}, key2.n={}", key1.n, key2.n);

    // Create DPF evaluator
    let dpf = Dpf::with_default_key();

    // Evaluate both DPFs
    let results1 = dpf.eval_full(&key1);
    let results2 = dpf.eval_full(&key2);

    info!("DPF evaluations complete: {} blocks each", results1.len());

    // Convert both results to bitmaps
    let bitmap1 = dpf_results_to_bitmap(&results1, config.num_buckets);
    let bitmap2 = dpf_results_to_bitmap(&results2, config.num_buckets);
    
    // XOR the two bitmaps together (since we need combined result from both locations)
    let combined_bitmap: Vec<u8> = bitmap1.iter()
        .zip(bitmap2.iter())
        .map(|(b1, b2)| b1 ^ b2)
        .collect();

    // Count set bits for logging
    let set_bits: usize = combined_bitmap.iter().map(|b| b.count_ones() as usize).sum();
    info!("Combined bitmap has {} bits set", set_bits);

    // Compute XOR of buckets indicated by the combined bitmap
    match data_store.xor_buckets(&combined_bitmap) {
        Ok(data) => {
            info!("Two-location query result: {} bytes", data.len());
            Response::QueryResult { data }
        }
        Err(e) => {
            error!("Failed to compute XOR: {}", e);
            Response::Error {
                message: format!("Failed to compute result: {}", e),
            }
        }
    }
}

/// Send a response to the client
async fn send_response(stream: &mut TcpStream, response: &Response) {
    let response_bytes = match bincode::serialize(response) {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to serialize response: {}", e);
            return;
        }
    };

    // Send response length (4 bytes)
    let len = response_bytes.len() as u32;
    if let Err(e) = stream.write_all(&len.to_be_bytes()).await {
        error!("Failed to write response length: {}", e);
        return;
    }

    // Send response body
    if let Err(e) = stream.write_all(&response_bytes).await {
        error!("Failed to write response body: {}", e);
    }
}

#[tokio::main]
async fn main() {
    // Initialize logger
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    let config = parse_args(&args);

    info!("Starting DPF-PIR server on port {}", config.port);
    info!("Data path: {}", config.data_path);
    info!("Number of buckets: {}", config.num_buckets);
    info!("Entry size: {} bytes", config.entry_size);
    info!("Bucket size: {} entries ({} bytes)", config.bucket_size, config.bucket_size * config.entry_size);
    info!("Load to memory: {}", config.load_to_memory);

    // Initialize data store
    let data_store = match DataStore::new(&config) {
        Ok(store) => Arc::new(store),
        Err(e) => {
            error!("Failed to initialize data store: {}", e);
            std::process::exit(1);
        }
    };

    // Bind to the port
    let addr: SocketAddr = format!("0.0.0.0:{}", config.port)
        .parse()
        .expect("Invalid address");

    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind to {}: {}", addr, e);
            std::process::exit(1);
        }
    };

    info!("Server listening on {}", addr);

    // Accept connections loop
    loop {
        let (stream, _peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!("Failed to accept connection: {}", e);
                continue;
            }
        };

        let config = config.clone();
        let data_store = Arc::clone(&data_store);
        tokio::spawn(async move {
            handle_connection(stream, &config, &data_store).await;
        });
    }
}

/// Parse command line arguments
fn parse_args(args: &[String]) -> ServerConfig {
    let mut config = ServerConfig::default();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" => {
                if i + 1 < args.len() {
                    config.port = args[i + 1].parse().unwrap_or(config.port);
                    i += 1;
                }
            }
            "--data" | "-d" => {
                if i + 1 < args.len() {
                    config.data_path = args[i + 1].clone();
                    i += 1;
                }
            }
            "--buckets" | "-b" => {
                if i + 1 < args.len() {
                    config.num_buckets = args[i + 1].parse().unwrap_or(config.num_buckets);
                    i += 1;
                }
            }
            "--entry-size" | "-e" => {
                if i + 1 < args.len() {
                    config.entry_size = args[i + 1].parse().unwrap_or(config.entry_size);
                    i += 1;
                }
            }
            "--bucket-size" | "-s" => {
                if i + 1 < args.len() {
                    config.bucket_size = args[i + 1].parse().unwrap_or(config.bucket_size);
                    i += 1;
                }
            }
            "--load-memory" | "-m" => {
                config.load_to_memory = true;
            }
            "--help" | "-h" => {
                println!("DPF-PIR Server");
                println!("Usage: {} [OPTIONS]", args[0]);
                println!("Options:");
                println!("  --port, -p <PORT>         Port to listen on (default: {})", config.port);
                println!("  --data, -d <PATH>         Path to data file (default: {})", config.data_path);
                println!("  --buckets, -b <NUM>       Number of buckets (default: {})", config.num_buckets);
                println!("  --entry-size, -e <SIZE>   Size of each entry in bytes (default: {})", config.entry_size);
                println!("  --bucket-size, -s <NUM>   Number of entries per bucket (default: {})", config.bucket_size);
                println!("  --load-memory, -m         Load data into memory at startup");
                println!("  --help, -h                Show this help message");
                std::process::exit(0);
            }
            _ => {
                warn!("Unknown argument: {}", args[i]);
            }
        }
        i += 1;
    }

    config
}