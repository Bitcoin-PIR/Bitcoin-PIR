//! WebSocket protocol handler for PIR server
//! 
//! Handles WebSocket connections with binary message support.
//! Uses the Simple Binary Protocol (SBP) for reliable communication.

use crate::{PirRequest as Request, PirResponse as Response, DatabaseRegistry};
use libdpf::{Dpf, DpfKey};
use tokio_tungstenite::WebSocketStream;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use log::{info, error, warn};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::sync::Arc;
use std::time::Instant;

/// In-memory data storage for a single database
pub struct DataStore {
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
    pub fn new(path: &str, num_buckets: usize, entry_size: usize, bucket_size: usize, load_to_memory: bool) -> std::io::Result<Self> {
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
    fn xor_buckets_memory(&self, bitmap: &[u8]) -> Result<Vec<u8>, String> {
        let data = self.data.as_ref().ok_or("Data not loaded into memory")?;
        
        let mut result = vec![0u8; self.bucket_bytes];
        let mut buckets_included = 0usize;
        
        for bucket_idx in 0..self.num_buckets {
            let byte_idx = bucket_idx / 8;
            let bit_idx = bucket_idx % 8;
            let offset = bucket_idx * self.bucket_bytes;
            
            if offset + self.bucket_bytes > data.len() {
                break;
            }
            
            if byte_idx < bitmap.len() && (bitmap[byte_idx] >> bit_idx) & 1 == 1 {
                for i in 0..self.bucket_bytes {
                    result[i] ^= data[offset + i];
                }
                buckets_included += 1;
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
        
        let mut result = vec![0u8; self.bucket_bytes];
        let mut buckets_included = 0usize;
        let mut bucket_buf = vec![0u8; self.bucket_bytes];
        
        for bucket_idx in 0..self.num_buckets {
            let byte_idx = bucket_idx / 8;
            let bit_idx = bucket_idx % 8;
            
            match reader.read_exact(&mut bucket_buf) {
                Ok(()) => {},
                Err(e) => {
                    warn!("Stopped reading at bucket {}: {}", bucket_idx, e);
                    break;
                }
            }
            
            if byte_idx < bitmap.len() && (bitmap[byte_idx] >> bit_idx) & 1 == 1 {
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
    pub fn xor_buckets(&self, bitmap: &[u8]) -> Result<Vec<u8>, String> {
        if self.data.is_some() {
            self.xor_buckets_memory(bitmap)
        } else {
            self.xor_buckets_streaming(bitmap)
        }
    }
    
    /// Get number of buckets
    pub fn num_buckets(&self) -> usize {
        self.num_buckets
    }
}

/// Data store manager that holds all database data stores
pub struct DataStoreManager {
    stores: HashMap<String, DataStore>,
}

impl DataStoreManager {
    pub fn new() -> Self {
        Self {
            stores: HashMap::new(),
        }
    }

    pub fn add(&mut self, id: String, store: DataStore) {
        self.stores.insert(id, store);
    }

    pub fn get(&self, id: &str) -> Option<&DataStore> {
        self.stores.get(id)
    }
}

/// Convert DPF evaluation results (Vec<Block>) to a bitmap
fn dpf_results_to_bitmap(results: &[libdpf::Block], num_buckets: usize) -> Vec<u8> {
    let bitmap_size = (num_buckets + 7) / 8;
    let mut bitmap = vec![0u8; bitmap_size];
    
    for (block_idx, block) in results.iter().enumerate() {
        let block_bytes = block.to_bytes();
        
        for (byte_idx, &byte) in block_bytes.iter().enumerate() {
            let bucket_base = block_idx * 128 + byte_idx * 8;
            if bucket_base >= num_buckets {
                break;
            }
            
            let bitmap_byte_idx = bucket_base / 8;
            let bits_to_copy = if bucket_base + 8 <= num_buckets {
                8
            } else {
                num_buckets - bucket_base
            };
            
            if byte_idx == 0 && block_idx * 128 % 8 == 0 {
                if bitmap_byte_idx < bitmap.len() {
                    let valid_mask = if bits_to_copy < 8 {
                        (1u8 << bits_to_copy) - 1
                    } else {
                        0xFF
                    };
                    bitmap[bitmap_byte_idx] = byte & valid_mask;
                }
            } else {
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

/// Handle a WebSocket connection
pub async fn handle_websocket_connection<S>(
    ws_stream: WebSocketStream<S>,
    store_manager: Arc<DataStoreManager>,
    registry: Arc<DatabaseRegistry>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let addr = "websocket_client";
    info!("New WebSocket connection from {}", addr);
    
    let mut ws_stream = ws_stream;
    
    while let Some(msg_result) = ws_stream.next().await {
        match msg_result {
            Ok(msg) => {
                if msg.is_binary() {
                    let data = msg.into_data();
                    
                    let request: Request = match Request::decode(&data) {
                        Ok(r) => r,
                        Err(e) => {
                            error!("Failed to decode WebSocket request: {}", e);
                            let response = Response::Error {
                                message: format!("Invalid request: {}", e),
                            };
                            send_ws_response(&mut ws_stream, response).await;
                            continue;
                        }
                    };
                    
                    let response = handle_request(request, &store_manager, &registry).await;
                    send_ws_response(&mut ws_stream, response).await;
                } else if msg.is_close() {
                    info!("WebSocket connection closed by client");
                    break;
                } else if msg.is_ping() {
                    // Respond with pong
                    let _ = ws_stream.send(Message::Pong(vec![])).await;
                }
            }
            Err(e) => {
                error!("WebSocket error: {}", e);
                break;
            }
        }
    }
    
    info!("WebSocket connection ended");
}

/// Handle a single request
async fn handle_request(
    request: Request,
    store_manager: &DataStoreManager,
    registry: &DatabaseRegistry,
) -> Response {
    match request {
        Request::Ping => Response::Pong,
        
        Request::ListDatabases => {
            Response::DatabaseList {
                databases: registry.list_info(),
            }
        }
        
        Request::GetDatabaseInfo { database_id } => {
            match registry.get(&database_id) {
                Some(db) => Response::DatabaseInfo {
                    info: crate::DatabaseInfo::from(db.as_ref()),
                },
                None => Response::Error {
                    message: format!("Database '{}' not found", database_id),
                },
            }
        }
        
        Request::Query { bucket_index: _, dpf_key } => {
            let first_db_id = registry.list().first().map(|s| s.to_string());
            match first_db_id {
                Some(id) => handle_database_query_single(id, dpf_key, store_manager).await,
                None => Response::Error {
                    message: "No databases registered".to_string(),
                },
            }
        }
        
        Request::QueryTwoLocations { dpf_key1, dpf_key2 } => {
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
    }
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

    let store = match store_manager.get(&database_id) {
        Some(s) => s,
        None => {
            return Response::Error {
                message: format!("Database '{}' not found", database_id),
            };
        }
    };

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

    let dpf = Dpf::with_default_key();

    let results1 = dpf.eval_full(&key1);
    let results2 = dpf.eval_full(&key2);

    info!("DPF evaluations complete: {} blocks each", results1.len());

    let bitmap1 = dpf_results_to_bitmap(&results1, store.num_buckets());
    let bitmap2 = dpf_results_to_bitmap(&results2, store.num_buckets());

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

    let store = match store_manager.get(&database_id) {
        Some(s) => s,
        None => {
            return Response::Error {
                message: format!("Database '{}' not found", database_id),
            };
        }
    };

    let key = match DpfKey::from_bytes(&dpf_key) {
        Ok(k) => k,
        Err(e) => {
            return Response::Error {
                message: format!("Invalid DPF key: {}", e),
            };
        }
    };

    info!("DPF key parsed: n={}, domain=2^{}", key.n, key.n);

    let dpf = Dpf::with_default_key();

    let results = dpf.eval_full(&key);

    info!("DPF evaluation complete: {} blocks", results.len());

    let bitmap = dpf_results_to_bitmap(&results, store.num_buckets());

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

/// Send a response over WebSocket
async fn send_ws_response<S>(
    ws_stream: &mut WebSocketStream<S>,
    response: Response,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let response_bytes = response.encode();
    
    if let Err(e) = ws_stream.send(Message::Binary(response_bytes)).await {
        error!("Failed to send WebSocket response: {}", e);
    }
}
