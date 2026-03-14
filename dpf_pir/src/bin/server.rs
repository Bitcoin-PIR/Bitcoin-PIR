//! DPF-PIR Server
//!
//! This binary runs a PIR server that listens for client queries.
//!
//! The server evaluates DPF keys to produce a bitmap indicating which buckets
//! to include in the XOR computation, then either:
//! - Streams through the data file with BufReader and computes XOR (memory-efficient)
//! - Loads data into memory at startup and computes XOR (faster for repeated queries)
//!
//! ## Database Registration
//!
//! Databases are registered in `dpf_pir/src/server_config.rs`.
//! Modify the `load_configuration()` function to add your databases.
//!
//! No command-line arguments are needed - the server automatically loads all
//! registered databases from the configuration.

use dpf_pir::{DatabaseRegistry, Request, Response, load_configuration};
use libdpf::{Dpf, DpfKey};
use log::{error, info, warn};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// In-memory data storage for a single database
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
    fn new(path: &str, num_buckets: usize, entry_size: usize, bucket_size: usize, load_to_memory: bool) -> std::io::Result<Self> {
        let bucket_bytes = bucket_size * entry_size;
        
        let mut store = Self {
            data: None,
            path: path.to_string(),
            num_buckets,
            bucket_bytes,
        };
        
        if load_to_memory {
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
    /// Streams through ALL buckets in order, using bitmap to decide whether to XOR each bucket
    fn xor_buckets_memory(&self, bitmap: &[u8]) -> Result<Vec<u8>, String> {
        let data = self.data.as_ref().ok_or("Data not loaded into memory")?;
        
        // Initialize result with zeros
        let mut result = vec![0u8; self.bucket_bytes];
        
        let mut buckets_included = 0usize;
        
        // Stream through ALL buckets sequentially
        for bucket_idx in 0..self.num_buckets {
            // Get the byte and bit position in the bitmap
            let byte_idx = bucket_idx / 8;
            let bit_idx = bucket_idx % 8;
            
            // Compute offset for this bucket
            let offset = bucket_idx * self.bucket_bytes;
            
            // Check bounds
            if offset + self.bucket_bytes > data.len() {
                break;
            }
            
            // Check if this bit is set in the bitmap - if so, XOR the bucket
            if byte_idx < bitmap.len() && (bitmap[byte_idx] >> bit_idx) & 1 == 1 {
                // XOR with result
                for i in 0..self.bucket_bytes {
                    result[i] ^= data[offset + i];
                }
                buckets_included += 1;
            }
        }
        
        info!("XORed {} buckets (from memory, streamed {} buckets)", buckets_included, self.num_buckets);
        Ok(result)
    }
    
    /// Compute XOR of buckets indicated by the bitmap (streaming version)
    /// Streams through ALL buckets in order from disk, using bitmap to decide whether to XOR each bucket
    fn xor_buckets_streaming(&self, bitmap: &[u8]) -> Result<Vec<u8>, String> {
        let file = File::open(&self.path)
            .map_err(|e| format!("Failed to open data file: {}", e))?;
        let mut reader = BufReader::new(file);
        
        // Initialize result with zeros
        let mut result = vec![0u8; self.bucket_bytes];
        
        let mut buckets_included = 0usize;
        
        // Buffer for reading a single bucket
        let mut bucket_buf = vec![0u8; self.bucket_bytes];
        
        // Stream through ALL buckets sequentially - no seeking needed
        for bucket_idx in 0..self.num_buckets {
            // Get the byte and bit position in the bitmap
            let byte_idx = bucket_idx / 8;
            let bit_idx = bucket_idx % 8;
            
            // Read the bucket (always read, no seeking)
            match reader.read_exact(&mut bucket_buf) {
                Ok(()) => {},
                Err(e) => {
                    // End of file or read error
                    warn!("Stopped reading at bucket {}: {}", bucket_idx, e);
                    break;
                }
            }
            
            // Check if this bit is set in the bitmap - if so, XOR the bucket
            if byte_idx < bitmap.len() && (bitmap[byte_idx] >> bit_idx) & 1 == 1 {
                // XOR with result
                for i in 0..self.bucket_bytes {
                    result[i] ^= bucket_buf[i];
                }
                buckets_included += 1;
            }
        }
        
        info!("XORed {} buckets (streaming from disk, read {} buckets)", buckets_included, self.num_buckets);
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

/// Data store manager that holds all database data stores
struct DataStoreManager {
    stores: HashMap<String, DataStore>,
}

impl DataStoreManager {
    fn new() -> Self {
        Self {
            stores: HashMap::new(),
        }
    }

    fn add(&mut self, id: String, store: DataStore) {
        self.stores.insert(id, store);
    }

    fn get(&self, id: &str) -> Option<&DataStore> {
        self.stores.get(id)
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
async fn handle_connection(
    mut stream: TcpStream,
    store_manager: &DataStoreManager,
    registry: &DatabaseRegistry,
) {
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
        
        Request::ListDatabases => {
            Response::DatabaseList {
                databases: registry.list_info(),
            }
        }
        
        Request::GetDatabaseInfo { database_id } => {
            match registry.get(&database_id) {
                Some(db) => Response::DatabaseInfo {
                    info: dpf_pir::DatabaseInfo::from(db.as_ref()),
                },
                None => Response::Error {
                    message: format!("Database '{}' not found", database_id),
                },
            }
        }
        
        Request::Query { bucket_index: _, dpf_key } => {
            // Legacy single query - use first database with single location
            let first_db_id = registry.list().first().map(|s| s.to_string());
            match first_db_id {
                Some(id) => handle_database_query_single(id, dpf_key, store_manager).await,
                None => Response::Error {
                    message: "No databases registered".to_string(),
                },
            }
        }
        
        Request::QueryTwoLocations { dpf_key1, dpf_key2 } => {
            // Legacy two-location query - use first database
            let first_db_id = registry.list().first().map(|s| s.to_string());
            match first_db_id {
                Some(id) => handle_database_query_two_locations(id, dpf_key1, dpf_key2, store_manager).await,
                None => Response::Error {
                    message: "No databases registered".to_string(),
                },
            }
        }
        
        Request::QueryDatabase { database_id, dpf_key1, dpf_key2 } => {
            handle_database_query_two_locations(database_id, dpf_key1, dpf_key2, store_manager).await
        }
        
        Request::QueryDatabaseSingle { database_id, dpf_key } => {
            handle_database_query_single(database_id, dpf_key, store_manager).await
        }
    };

    // Send the response
    send_response(&mut stream, &response).await;
    info!("Connection from {} closed", addr);
}

/// Handle a database query for two locations
async fn handle_database_query_two_locations(
    database_id: String,
    dpf_key1: Vec<u8>,
    dpf_key2: Vec<u8>,
    store_manager: &DataStoreManager,
) -> Response {
    let start_time = Instant::now();
    
    info!(
        "Received database query for '{}': key1_len={}, key2_len={}",
        database_id, dpf_key1.len(), dpf_key2.len()
    );

    // Get the data store for this database
    let store = match store_manager.get(&database_id) {
        Some(s) => s,
        None => {
            return Response::Error {
                message: format!("Database '{}' not found", database_id),
            };
        }
    };

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

    // Evaluate both DPFs independently
    let results1 = dpf.eval_full(&key1);
    let results2 = dpf.eval_full(&key2);

    info!("DPF evaluations complete: {} blocks each", results1.len());

    // Convert both results to bitmaps independently
    let bitmap1 = dpf_results_to_bitmap(&results1, store.num_buckets);
    let bitmap2 = dpf_results_to_bitmap(&results2, store.num_buckets);

    // Compute XOR of buckets for each bitmap
    let result1 = match store.xor_buckets(&bitmap1) {
        Ok(data) => data,
        Err(e) => {
            return Response::Error {
                message: format!("Failed to compute result for query1: {}", e),
            };
        }
    };

    let result2 = match store.xor_buckets(&bitmap2) {
        Ok(data) => data,
        Err(e) => {
            return Response::Error {
                message: format!("Failed to compute result for query2: {}", e),
            };
        }
    };

    let elapsed = start_time.elapsed();
    info!("Database '{}' query results: data1={} bytes, data2={} bytes", database_id, result1.len(), result2.len());
    info!("Query completed in {:?}", elapsed);
    Response::QueryTwoResults {
        data1: result1,
        data2: result2,
    }
}

/// Handle a database query for a single location
async fn handle_database_query_single(
    database_id: String,
    dpf_key: Vec<u8>,
    store_manager: &DataStoreManager,
) -> Response {
    let start_time = Instant::now();
    
    info!(
        "Received single-location database query for '{}': key_len={}",
        database_id, dpf_key.len()
    );

    // Get the data store for this database
    let store = match store_manager.get(&database_id) {
        Some(s) => s,
        None => {
            return Response::Error {
                message: format!("Database '{}' not found", database_id),
            };
        }
    };

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
    let results = dpf.eval_full(&key);

    info!("DPF evaluation complete: {} blocks", results.len());

    // Convert DPF results to a bitmap
    let bitmap = dpf_results_to_bitmap(&results, store.num_buckets);

    // Compute XOR of buckets
    let result = match store.xor_buckets(&bitmap) {
        Ok(data) => data,
        Err(e) => {
            return Response::Error {
                message: format!("Failed to compute result: {}", e),
            };
        }
    };

    let elapsed = start_time.elapsed();
    info!("Database '{}' query result: {} bytes", database_id, result.len());
    info!("Query completed in {:?}", elapsed);
    Response::QueryResult { data: result }
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

    // Parse command line arguments for port
    let args: Vec<String> = std::env::args().collect();
    let mut port = None;
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" => {
                if i + 1 < args.len() {
                    port = args[i + 1].parse::<u16>().ok();
                    i += 1;
                }
            }
            "--help" | "-h" => {
                println!("DPF-PIR Server");
                println!("Usage: {} [OPTIONS]", args[0]);
                println!();
                println!("Options:");
                println!("  --port, -p <PORT>  Port to listen on (default: from config)");
                println!("  --help, -h         Show this help message");
                return;
            }
            _ => {}
        }
        i += 1;
    }

    // Load configuration (databases are registered in server_config.rs)
    let mut server_config = load_configuration();
    
    // Override port if specified on command line
    if let Some(p) = port {
        server_config.port = p;
    }

    info!("Starting DPF-PIR server on port {}", server_config.port);
    info!("Load to memory: {}", server_config.load_to_memory);

    // Create data store manager
    let mut store_manager = DataStoreManager::new();

    // Initialize data stores for each registered database
    for db_id in server_config.registry.list() {
        if let Some(db) = server_config.registry.get(db_id) {
            info!("Initializing data store for database '{}':", db_id);
            info!("  Path: {}", db.data_path());
            info!("  Buckets: {}", db.num_buckets());
            info!("  Entry size: {} bytes", db.entry_size());
            info!("  Bucket size: {} entries", db.bucket_size());
            info!("  Locations: {}", db.num_locations());

            let store = DataStore::new(
                db.data_path(),
                db.num_buckets(),
                db.entry_size(),
                db.bucket_size(),
                server_config.load_to_memory,
            ).unwrap_or_else(|e| {
                error!("Failed to create data store for '{}': {}", db_id, e);
                std::process::exit(1);
            });

            store_manager.add(db_id.to_string(), store);
        }
    }

    info!("Registered {} database(s)", server_config.registry.len());

    // Check if any databases are registered
    if server_config.registry.is_empty() {
        error!("No databases registered. Edit dpf_pir/src/server_config.rs to add databases.");
        std::process::exit(1);
    }

    // Bind to the port
    let addr: SocketAddr = format!("0.0.0.0:{}", server_config.port)
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
    info!("Use --list-databases on client to see available databases");

    // Wrap in Arc for sharing across tasks
    let store_manager = Arc::new(store_manager);
    let registry = Arc::new(server_config.registry);

    // Accept connections loop
    loop {
        let (stream, _peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!("Failed to accept connection: {}", e);
                continue;
            }
        };

        let store_manager = Arc::clone(&store_manager);
        let registry = Arc::clone(&registry);
        tokio::spawn(async move {
            handle_connection(stream, &store_manager, &registry).await;
        });
    }
}