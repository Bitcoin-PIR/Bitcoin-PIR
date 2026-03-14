//! Communication protocol for DPF-PIR client-server interaction.
//!
//! This module defines the message types and communication protocol
//! between the client and servers.

use serde::{Deserialize, Serialize};

// Re-export DatabaseInfo from database module
pub use crate::database::DatabaseInfo;

/// Re-export KEY_SIZE from hash module
pub use crate::hash::KEY_SIZE;

/// Script hash type (20 bytes for Bitcoin scriptPubkey hash)
pub type ScriptHash = [u8; KEY_SIZE];

/// Default ports for the two servers
pub const SERVER1_PORT: u16 = 8081;
pub const SERVER2_PORT: u16 = 8082;

/// Default database ID for UTXO chunks
pub const DEFAULT_DATABASE_ID: &str = "utxo_chunks";

/// Request from client to server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    /// Query for a script hash at a specific bucket location (legacy)
    Query {
        /// The bucket index to query
        bucket_index: u64,
        /// DPF key for the query (serialized)
        dpf_key: Vec<u8>,
    },
    /// Query for both cuckoo hash locations in one request (legacy)
    /// The location is encoded in the DPF key, so we don't send it separately
    QueryTwoLocations {
        /// DPF key for first location (serialized)
        dpf_key1: Vec<u8>,
        /// DPF key for second location (serialized)
        dpf_key2: Vec<u8>,
    },
    /// Query a specific database at two cuckoo hash locations (new)
    QueryDatabase {
        /// Database ID to query
        database_id: String,
        /// DPF key for first location (serialized)
        dpf_key1: Vec<u8>,
        /// DPF key for second location (serialized)
        dpf_key2: Vec<u8>,
    },
    /// Query a single-location database (new)
    QueryDatabaseSingle {
        /// Database ID to query
        database_id: String,
        /// DPF key for the query (serialized)
        dpf_key: Vec<u8>,
    },
    /// List available databases on the server
    ListDatabases,
    /// Get information about a specific database
    GetDatabaseInfo {
        /// Database ID to query
        database_id: String,
    },
    /// Health check
    Ping,
}

/// Response from server to client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    /// Query result containing the value at the queried location
    QueryResult {
        /// The result data (encrypted/encoded)
        data: Vec<u8>,
    },
    /// Query result for two-location query (two independent results)
    QueryTwoResults {
        /// Result for first DPF key query
        data1: Vec<u8>,
        /// Result for second DPF key query
        data2: Vec<u8>,
    },
    /// List of available databases
    DatabaseList {
        /// List of database information
        databases: Vec<DatabaseInfo>,
    },
    /// Information about a specific database
    DatabaseInfo {
        /// Database information
        info: DatabaseInfo,
    },
    /// Error response
    Error {
        message: String,
    },
    /// Pong response for health check
    Pong,
}

/// Configuration for the PIR client
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Server 1 address (host:port)
    pub server1_addr: String,
    /// Server 2 address (host:port)
    pub server2_addr: String,
    /// Number of buckets in the cuckoo hash table
    pub num_buckets: usize,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server1_addr: format!("127.0.0.1:{}", SERVER1_PORT),
            server2_addr: format!("127.0.0.1:{}", SERVER2_PORT),
            num_buckets: crate::hash::NUM_BUCKETS,
        }
    }
}

/// Configuration for the PIR server
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Port to listen on
    pub port: u16,
    /// Path to the data file (mmap)
    pub data_path: String,
    /// Number of buckets in the cuckoo hash table
    pub num_buckets: usize,
    /// Size of each entry in bytes (e.g., 20-byte key + 32-byte value = 52)
    pub entry_size: usize,
    /// Number of entries per bucket
    pub bucket_size: usize,
    /// Whether to load data into memory at startup (vs streaming from disk)
    pub load_to_memory: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: SERVER1_PORT,
            data_path: String::from("data.bin"),
            num_buckets: crate::hash::NUM_BUCKETS,
            entry_size: crate::hash::ENTRY_SIZE,
            bucket_size: 1, // Default: 1 entry per bucket
            load_to_memory: false, // Default: streaming mode
        }
    }
}
