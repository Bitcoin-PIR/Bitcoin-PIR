//! Simple binary protocol for two-level Batch PIR.
//!
//! All integers are little-endian. Messages are length-prefixed:
//!   [4B total_len][1B variant][payload...]
//!
//! The outer 4-byte length includes the variant byte.

use std::io;

// ─── Request variants ───────────────────────────────────────────────────────

pub const REQ_PING: u8 = 0x00;
pub const REQ_GET_INFO: u8 = 0x01;
pub const REQ_INDEX_BATCH: u8 = 0x11;
pub const REQ_CHUNK_BATCH: u8 = 0x21;

// ─── Response variants ──────────────────────────────────────────────────────

pub const RESP_PONG: u8 = 0x00;
pub const RESP_INFO: u8 = 0x01;
pub const RESP_INDEX_BATCH: u8 = 0x11;
pub const RESP_CHUNK_BATCH: u8 = 0x21;
pub const RESP_ERROR: u8 = 0xFF;

// ─── Request types ──────────────────────────────────────────────────────────

/// A batch of DPF keys for one level.
/// Each bucket has N DPF keys (one per cuckoo hash function).
#[derive(Clone, Debug)]
pub struct BatchQuery {
    /// 0 for index, 1 for chunk
    pub level: u8,
    /// Round ID (only meaningful for chunk level; 0 for index)
    pub round_id: u16,
    /// Per-bucket: list of DPF keys. Length = K (75) or K_CHUNK (80).
    /// Inner Vec length = number of cuckoo hash functions (2 for index, 3 for chunks).
    pub keys: Vec<Vec<Vec<u8>>>,
}

pub enum Request {
    Ping,
    GetInfo,
    IndexBatch(BatchQuery),
    ChunkBatch(BatchQuery),
}

// ─── Response types ─────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct ServerInfo {
    pub index_bins_per_table: u32,
    pub chunk_bins_per_table: u32,
    pub index_k: u8,
    pub chunk_k: u8,
    pub tag_seed: u64,
}

#[derive(Clone, Debug)]
pub struct BatchResult {
    pub level: u8,
    pub round_id: u16,
    /// Per-bucket: list of results. Same structure as request keys.
    pub results: Vec<Vec<Vec<u8>>>,
}

pub enum Response {
    Pong,
    Info(ServerInfo),
    IndexBatch(BatchResult),
    ChunkBatch(BatchResult),
    Error(String),
}

// ─── Encoding ───────────────────────────────────────────────────────────────

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        match self {
            Request::Ping => {
                payload.push(REQ_PING);
            }
            Request::GetInfo => {
                payload.push(REQ_GET_INFO);
            }
            Request::IndexBatch(q) => {
                payload.push(REQ_INDEX_BATCH);
                encode_batch_query(&mut payload, q);
            }
            Request::ChunkBatch(q) => {
                payload.push(REQ_CHUNK_BATCH);
                encode_batch_query(&mut payload, q);
            }
        }
        let mut msg = Vec::with_capacity(4 + payload.len());
        msg.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        msg.extend_from_slice(&payload);
        msg
    }

    pub fn decode(data: &[u8]) -> io::Result<Self> {
        if data.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "empty request"));
        }
        match data[0] {
            REQ_PING => Ok(Request::Ping),
            REQ_GET_INFO => Ok(Request::GetInfo),
            REQ_INDEX_BATCH => {
                let q = decode_batch_query(&data[1..])?;
                Ok(Request::IndexBatch(q))
            }
            REQ_CHUNK_BATCH => {
                let q = decode_batch_query(&data[1..])?;
                Ok(Request::ChunkBatch(q))
            }
            v => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown request variant: 0x{:02x}", v),
            )),
        }
    }
}

impl Response {
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        match self {
            Response::Pong => {
                payload.push(RESP_PONG);
            }
            Response::Info(info) => {
                payload.push(RESP_INFO);
                payload.extend_from_slice(&info.index_bins_per_table.to_le_bytes());
                payload.extend_from_slice(&info.chunk_bins_per_table.to_le_bytes());
                payload.push(info.index_k);
                payload.push(info.chunk_k);
                payload.extend_from_slice(&info.tag_seed.to_le_bytes());
            }
            Response::IndexBatch(r) => {
                payload.push(RESP_INDEX_BATCH);
                encode_batch_result(&mut payload, r);
            }
            Response::ChunkBatch(r) => {
                payload.push(RESP_CHUNK_BATCH);
                encode_batch_result(&mut payload, r);
            }
            Response::Error(msg) => {
                payload.push(RESP_ERROR);
                let bytes = msg.as_bytes();
                payload.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                payload.extend_from_slice(bytes);
            }
        }
        let mut msg = Vec::with_capacity(4 + payload.len());
        msg.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        msg.extend_from_slice(&payload);
        msg
    }

    pub fn decode(data: &[u8]) -> io::Result<Self> {
        if data.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "empty response"));
        }
        match data[0] {
            RESP_PONG => Ok(Response::Pong),
            RESP_INFO => {
                if data.len() < 19 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "info too short"));
                }
                Ok(Response::Info(ServerInfo {
                    index_bins_per_table: u32::from_le_bytes(data[1..5].try_into().unwrap()),
                    chunk_bins_per_table: u32::from_le_bytes(data[5..9].try_into().unwrap()),
                    index_k: data[9],
                    chunk_k: data[10],
                    tag_seed: u64::from_le_bytes(data[11..19].try_into().unwrap()),
                }))
            }
            RESP_INDEX_BATCH => {
                let r = decode_batch_result(&data[1..])?;
                Ok(Response::IndexBatch(r))
            }
            RESP_CHUNK_BATCH => {
                let r = decode_batch_result(&data[1..])?;
                Ok(Response::ChunkBatch(r))
            }
            RESP_ERROR => {
                let len = u32::from_le_bytes(data[1..5].try_into().unwrap()) as usize;
                let msg = String::from_utf8_lossy(&data[5..5 + len]).to_string();
                Ok(Response::Error(msg))
            }
            v => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown response variant: 0x{:02x}", v),
            )),
        }
    }
}

// ─── Batch encoding helpers ─────────────────────────────────────────────────

/// Wire format:
///   [2B round_id][1B num_buckets][1B keys_per_bucket]
///   For each bucket:
///     For each key (keys_per_bucket times):
///       [2B key_len][key_data]
fn encode_batch_query(buf: &mut Vec<u8>, q: &BatchQuery) {
    buf.extend_from_slice(&q.round_id.to_le_bytes());
    buf.push(q.keys.len() as u8);
    let keys_per_bucket = q.keys.first().map_or(0, |k| k.len()) as u8;
    buf.push(keys_per_bucket);
    for bucket_keys in &q.keys {
        for k in bucket_keys {
            buf.extend_from_slice(&(k.len() as u16).to_le_bytes());
            buf.extend_from_slice(k);
        }
    }
}

fn decode_batch_query(data: &[u8]) -> io::Result<BatchQuery> {
    let mut pos = 0;
    if data.len() < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "batch query too short"));
    }
    let round_id = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap());
    pos += 2;
    let num_buckets = data[pos] as usize;
    pos += 1;
    let keys_per_bucket = data[pos] as usize;
    pos += 1;
    let mut keys = Vec::with_capacity(num_buckets);
    for _ in 0..num_buckets {
        let mut bucket_keys = Vec::with_capacity(keys_per_bucket);
        for _ in 0..keys_per_bucket {
            if pos + 2 > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated key"));
            }
            let len = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
            pos += 2;
            if pos + len > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated key data"));
            }
            bucket_keys.push(data[pos..pos + len].to_vec());
            pos += len;
        }
        keys.push(bucket_keys);
    }
    Ok(BatchQuery {
        level: 0,
        round_id,
        keys,
    })
}

fn encode_batch_result(buf: &mut Vec<u8>, r: &BatchResult) {
    buf.extend_from_slice(&r.round_id.to_le_bytes());
    buf.push(r.results.len() as u8);
    let results_per_bucket = r.results.first().map_or(0, |r| r.len()) as u8;
    buf.push(results_per_bucket);
    for bucket_results in &r.results {
        for res in bucket_results {
            buf.extend_from_slice(&(res.len() as u16).to_le_bytes());
            buf.extend_from_slice(res);
        }
    }
}

fn decode_batch_result(data: &[u8]) -> io::Result<BatchResult> {
    let mut pos = 0;
    if data.len() < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "batch result too short"));
    }
    let round_id = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap());
    pos += 2;
    let num_buckets = data[pos] as usize;
    pos += 1;
    let results_per_bucket = data[pos] as usize;
    pos += 1;
    let mut results = Vec::with_capacity(num_buckets);
    for _ in 0..num_buckets {
        let mut bucket_results = Vec::with_capacity(results_per_bucket);
        for _ in 0..results_per_bucket {
            if pos + 2 > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated result"));
            }
            let len = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
            pos += 2;
            if pos + len > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated result data"));
            }
            bucket_results.push(data[pos..pos + len].to_vec());
            pos += len;
        }
        results.push(bucket_results);
    }
    Ok(BatchResult {
        level: 0,
        round_id,
        results,
    })
}
