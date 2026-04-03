//! WASM bindings for pir-core: hash functions, codec, and PBC utilities.
//!
//! Exposes the core PIR functions to JavaScript/TypeScript via wasm-bindgen.
//! u64 values are passed as two u32 halves (hi, lo) since wasm-bindgen's
//! BigInt support can be clunky in practice.

use wasm_bindgen::prelude::*;

// ─── Helpers: u64 ↔ (hi, lo) ─────────────────────────────────────────────

#[inline]
fn u64_from_parts(hi: u32, lo: u32) -> u64 {
    ((hi as u64) << 32) | (lo as u64)
}

#[inline]
fn u64_to_le8(v: u64) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

// ─── splitmix64 ───────────────────────────────────────────────────────────

/// Splitmix64 finalizer. Input and output are split into (hi, lo) u32 halves.
/// Returns 8 bytes (result as LE bytes).
#[wasm_bindgen]
pub fn splitmix64(x_hi: u32, x_lo: u32) -> Vec<u8> {
    let result = pir_core::hash::splitmix64(u64_from_parts(x_hi, x_lo));
    u64_to_le8(result)
}

// ─── Fingerprint tag ──────────────────────────────────────────────────────

/// Compute an 8-byte fingerprint tag for a script_hash.
/// tag_seed is split into (hi, lo). Returns 8 LE bytes.
#[wasm_bindgen]
pub fn compute_tag(tag_seed_hi: u32, tag_seed_lo: u32, script_hash: &[u8]) -> Vec<u8> {
    let seed = u64_from_parts(tag_seed_hi, tag_seed_lo);
    let tag = pir_core::hash::compute_tag(seed, script_hash);
    u64_to_le8(tag)
}

// ─── INDEX-level bucket assignment ────────────────────────────────────────

/// Derive 3 distinct bucket indices for a script_hash.
/// `k` is the number of buckets. Returns a Vec<u32> of 3 indices.
#[wasm_bindgen]
pub fn derive_buckets(script_hash: &[u8], k: u32) -> Vec<u32> {
    let buckets = pir_core::hash::derive_buckets_3(script_hash, k as usize);
    buckets.iter().map(|&b| b as u32).collect()
}

// ─── INDEX-level cuckoo key derivation ────────────────────────────────────

/// Derive a cuckoo hash function key for (bucket_id, hash_fn).
/// master_seed is split into (hi, lo). Returns 8 LE bytes (the key).
#[wasm_bindgen]
pub fn derive_cuckoo_key(
    master_seed_hi: u32,
    master_seed_lo: u32,
    bucket_id: u32,
    hash_fn: u32,
) -> Vec<u8> {
    let seed = u64_from_parts(master_seed_hi, master_seed_lo);
    let key = pir_core::hash::derive_cuckoo_key(seed, bucket_id as usize, hash_fn as usize);
    u64_to_le8(key)
}

// ─── INDEX-level cuckoo hash ──────────────────────────────────────────────

/// Cuckoo hash a script_hash with a derived key, returning a bin index.
/// key is split into (hi, lo).
#[wasm_bindgen]
pub fn cuckoo_hash(script_hash: &[u8], key_hi: u32, key_lo: u32, num_bins: u32) -> u32 {
    let key = u64_from_parts(key_hi, key_lo);
    pir_core::hash::cuckoo_hash(script_hash, key, num_bins as usize) as u32
}

// ─── CHUNK-level bucket assignment ────────────────────────────────────────

/// Derive 3 distinct bucket indices for a chunk_id.
/// `k` is the number of buckets. Returns Vec<u32> of 3 indices.
#[wasm_bindgen]
pub fn derive_chunk_buckets(chunk_id: u32, k: u32) -> Vec<u32> {
    let buckets = pir_core::hash::derive_int_buckets_3(chunk_id, k as usize);
    buckets.iter().map(|&b| b as u32).collect()
}

// ─── CHUNK-level cuckoo key derivation ────────────────────────────────────

/// Derive a chunk-level cuckoo hash function key.
/// master_seed is split into (hi, lo). Returns 8 LE bytes.
#[wasm_bindgen]
pub fn derive_chunk_cuckoo_key(
    master_seed_hi: u32,
    master_seed_lo: u32,
    bucket_id: u32,
    hash_fn: u32,
) -> Vec<u8> {
    let seed = u64_from_parts(master_seed_hi, master_seed_lo);
    let key = pir_core::hash::derive_cuckoo_key(seed, bucket_id as usize, hash_fn as usize);
    u64_to_le8(key)
}

// ─── CHUNK-level cuckoo hash ──────────────────────────────────────────────

/// Cuckoo hash an integer chunk_id with a derived key, returning a bin index.
/// key is split into (hi, lo).
#[wasm_bindgen]
pub fn cuckoo_hash_int(chunk_id: u32, key_hi: u32, key_lo: u32, num_bins: u32) -> u32 {
    let key = u64_from_parts(key_hi, key_lo);
    pir_core::hash::cuckoo_hash_int(chunk_id, key, num_bins as usize) as u32
}

// ─── Varint codec ─────────────────────────────────────────────────────────

/// Read a LEB128 varint from `data` starting at `offset`.
/// Returns [value_lo, value_hi, bytes_consumed] as Vec<u32>.
#[wasm_bindgen]
pub fn read_varint(data: &[u8], offset: u32) -> Vec<u32> {
    let slice = &data[offset as usize..];
    let (value, consumed) = pir_core::codec::read_varint(slice);
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    vec![lo, hi, consumed as u32]
}

// ─── UTXO data decoding ──────────────────────────────────────────────────

/// Decode UTXO data from a binary blob. Returns JSON (serialized via serde).
///
/// Output format: array of `{ txid: string (hex), vout: number, amount: number }`
#[wasm_bindgen]
pub fn decode_utxo_data(data: &[u8]) -> JsValue {
    let entries = pir_core::codec::parse_utxo_data(data);
    let json_entries: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "txid": hex_encode(&e.txid),
                "vout": e.vout,
                "amount": e.amount,
            })
        })
        .collect();
    serde_wasm_bindgen::to_value(&json_entries).unwrap_or(JsValue::NULL)
}

/// Encode bytes as lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ─── PBC cuckoo placement ─────────────────────────────────────────────────

/// Cuckoo-place items into buckets.
///
/// `cand_buckets_flat` is a flat array of candidate bucket indices,
/// `num_items` items each having `num_hashes` candidates (so length =
/// num_items * num_hashes). Returns Vec<i32> of bucket assignments per item
/// (-1 if unplaced).
#[wasm_bindgen]
pub fn cuckoo_place(
    cand_buckets_flat: &[u32],
    num_items: u32,
    num_buckets: u32,
    max_kicks: u32,
    num_hashes: u32,
) -> Vec<i32> {
    let ni = num_items as usize;
    let nh = num_hashes as usize;
    let nb = num_buckets as usize;

    // Unflatten candidate buckets
    let cand_buckets: Vec<Vec<usize>> = (0..ni)
        .map(|i| {
            (0..nh)
                .map(|h| cand_buckets_flat[i * nh + h] as usize)
                .collect()
        })
        .collect();

    let mut bucket_owner: Vec<Option<usize>> = vec![None; nb];

    for qi in 0..ni {
        let saved = bucket_owner.clone();
        if !pir_core::pbc::pbc_cuckoo_place(
            &cand_buckets,
            &mut bucket_owner,
            qi,
            max_kicks as usize,
            nh,
        ) {
            bucket_owner = saved;
        }
    }

    // Build per-item assignment: item_index -> bucket_id (or -1)
    let mut assignments = vec![-1i32; ni];
    for (b, owner) in bucket_owner.iter().enumerate() {
        if let Some(qi) = owner {
            assignments[*qi] = b as i32;
        }
    }
    assignments
}

// ─── PBC multi-round planning ─────────────────────────────────────────────

/// Plan multi-round PBC placement.
///
/// `item_buckets_flat` is a flat array: num_items * items_per candidates.
/// Returns JSON: array of rounds, each round is array of [item_index, bucket_id].
#[wasm_bindgen]
pub fn plan_rounds(
    item_buckets_flat: &[u32],
    items_per: u32,
    num_buckets: u32,
    num_hashes: u32,
    max_kicks: u32,
) -> JsValue {
    let ip = items_per as usize;
    let num_items = item_buckets_flat.len() / ip;

    let item_buckets: Vec<Vec<usize>> = (0..num_items)
        .map(|i| {
            (0..ip)
                .map(|h| item_buckets_flat[i * ip + h] as usize)
                .collect()
        })
        .collect();

    let rounds = pir_core::pbc::pbc_plan_rounds(
        &item_buckets,
        num_buckets as usize,
        num_hashes as usize,
        max_kicks as usize,
    );

    // Convert to JSON: Vec<Vec<[usize, usize]>>
    let json_rounds: Vec<Vec<[usize; 2]>> = rounds
        .iter()
        .map(|round| round.iter().map(|&(item, bucket)| [item, bucket]).collect())
        .collect();

    serde_wasm_bindgen::to_value(&json_rounds).unwrap_or(JsValue::NULL)
}
