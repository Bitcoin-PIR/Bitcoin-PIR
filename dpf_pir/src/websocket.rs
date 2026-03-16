//! WebSocket protocol handler for PIR server
//!
//! Handles WebSocket connections with binary message support.
//! Uses the Simple Binary Protocol (SBP) for reliable communication.
//!
//! The actual PIR query processing is delegated to a `PirBackend`
//! implementation, making this module protocol-agnostic.

use crate::{PirRequest as Request, PirResponse as Response, DatabaseRegistry};
use crate::pir_backend::PirBackend;
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

    /// Get the size of each bucket in bytes
    pub fn bucket_bytes(&self) -> usize {
        self.bucket_bytes
    }

    /// Get a reference to the raw data (if loaded into memory)
    pub fn data(&self) -> Option<&[u8]> {
        self.data.as_deref()
    }

    /// Get the path to the data file
    pub fn path(&self) -> &str {
        &self.path
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

/// Handle a WebSocket connection
pub async fn handle_websocket_connection<S>(
    ws_stream: WebSocketStream<S>,
    store_manager: Arc<DataStoreManager>,
    registry: Arc<DatabaseRegistry>,
    backend: Arc<dyn PirBackend>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    info!("New WebSocket connection (backend: {})", backend.name());

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

                    let response = handle_request(request, &store_manager, &registry, &*backend).await;
                    send_ws_response(&mut ws_stream, response).await;
                } else if msg.is_close() {
                    info!("WebSocket connection closed by client");
                    break;
                } else if msg.is_ping() {
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
    backend: &dyn PirBackend,
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

        Request::Query { bucket_index: _, pir_query } => {
            let first_db_id = registry.list().first().map(|s| s.to_string());
            match first_db_id {
                Some(id) => process_single_query(id, pir_query, store_manager, backend).await,
                None => Response::Error {
                    message: "No databases registered".to_string(),
                },
            }
        }

        Request::QueryTwoLocations { pir_query1, pir_query2 } => {
            let first_db_id = registry.list().first().map(|s| s.to_string());
            match first_db_id {
                Some(id) => process_two_queries(id, pir_query1, pir_query2, store_manager, backend).await,
                None => Response::Error {
                    message: "No databases registered".to_string(),
                },
            }
        }

        Request::QueryDatabase { database_id, pir_query1, pir_query2 } => {
            process_two_queries(database_id, pir_query1, pir_query2, store_manager, backend).await
        }

        Request::QueryDatabaseSingle { database_id, pir_query } => {
            process_single_query(database_id, pir_query, store_manager, backend).await
        }
    }
}

/// Process two PIR queries against a database (e.g., for two cuckoo hash locations)
async fn process_two_queries(
    database_id: String,
    query1: Vec<u8>,
    query2: Vec<u8>,
    store_manager: &DataStoreManager,
    backend: &dyn PirBackend,
) -> Response {
    let start_time = Instant::now();

    info!(
        "Received two-query request for '{}': q1_len={}, q2_len={} (backend: {})",
        database_id, query1.len(), query2.len(), backend.name()
    );

    let store = match store_manager.get(&database_id) {
        Some(s) => s,
        None => {
            return Response::Error {
                message: format!("Database '{}' not found", database_id),
            };
        }
    };

    let result1 = match backend.process_query(&query1, store) {
        Ok(data) => data,
        Err(e) => {
            return Response::Error {
                message: format!("Failed to process query1: {}", e),
            };
        }
    };

    let result2 = match backend.process_query(&query2, store) {
        Ok(data) => data,
        Err(e) => {
            return Response::Error {
                message: format!("Failed to process query2: {}", e),
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

/// Process a single PIR query against a database
async fn process_single_query(
    database_id: String,
    query: Vec<u8>,
    store_manager: &DataStoreManager,
    backend: &dyn PirBackend,
) -> Response {
    let start_time = Instant::now();

    info!(
        "Received single query for '{}': q_len={} (backend: {})",
        database_id, query.len(), backend.name()
    );

    let store = match store_manager.get(&database_id) {
        Some(s) => s,
        None => {
            return Response::Error {
                message: format!("Database '{}' not found", database_id),
            };
        }
    };

    let result = match backend.process_query(&query, store) {
        Ok(data) => data,
        Err(e) => {
            return Response::Error {
                message: format!("Failed to process query: {}", e),
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
