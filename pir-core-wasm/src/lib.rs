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

// ─── INDEX-level group assignment ────────────────────────────────────────

/// Derive 3 distinct group indices for a script_hash.
/// `k` is the number of groups. Returns a Vec<u32> of 3 indices.
#[wasm_bindgen]
pub fn derive_groups(script_hash: &[u8], k: u32) -> Vec<u32> {
    let groups = pir_core::hash::derive_groups_3(script_hash, k as usize);
    groups.iter().map(|&b| b as u32).collect()
}

// ─── INDEX-level cuckoo key derivation ────────────────────────────────────

/// Derive a cuckoo hash function key for (group_id, hash_fn).
/// master_seed is split into (hi, lo). Returns 8 LE bytes (the key).
#[wasm_bindgen]
pub fn derive_cuckoo_key(
    master_seed_hi: u32,
    master_seed_lo: u32,
    group_id: u32,
    hash_fn: u32,
) -> Vec<u8> {
    let seed = u64_from_parts(master_seed_hi, master_seed_lo);
    let key = pir_core::hash::derive_cuckoo_key(seed, group_id as usize, hash_fn as usize);
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

// ─── CHUNK-level group assignment ────────────────────────────────────────

/// Derive 3 distinct group indices for a chunk_id.
/// `k` is the number of groups. Returns Vec<u32> of 3 indices.
#[wasm_bindgen]
pub fn derive_chunk_groups(chunk_id: u32, k: u32) -> Vec<u32> {
    let groups = pir_core::hash::derive_int_groups_3(chunk_id, k as usize);
    groups.iter().map(|&b| b as u32).collect()
}

// ─── CHUNK-level cuckoo key derivation ────────────────────────────────────

/// Derive a chunk-level cuckoo hash function key.
/// master_seed is split into (hi, lo). Returns 8 LE bytes.
#[wasm_bindgen]
pub fn derive_chunk_cuckoo_key(
    master_seed_hi: u32,
    master_seed_lo: u32,
    group_id: u32,
    hash_fn: u32,
) -> Vec<u8> {
    let seed = u64_from_parts(master_seed_hi, master_seed_lo);
    let key = pir_core::hash::derive_cuckoo_key(seed, group_id as usize, hash_fn as usize);
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

/// Cuckoo-place items into groups.
///
/// `cand_groups_flat` is a flat array of candidate group indices,
/// `num_items` items each having `num_hashes` candidates (so length =
/// num_items * num_hashes). Returns Vec<i32> of group assignments per item
/// (-1 if unplaced).
#[wasm_bindgen]
pub fn cuckoo_place(
    cand_groups_flat: &[u32],
    num_items: u32,
    num_groups: u32,
    max_kicks: u32,
    num_hashes: u32,
) -> Vec<i32> {
    let ni = num_items as usize;
    let nh = num_hashes as usize;
    let nb = num_groups as usize;

    // Unflatten candidate groups
    let cand_groups: Vec<Vec<usize>> = (0..ni)
        .map(|i| {
            (0..nh)
                .map(|h| cand_groups_flat[i * nh + h] as usize)
                .collect()
        })
        .collect();

    let mut group_owner: Vec<Option<usize>> = vec![None; nb];

    for qi in 0..ni {
        let saved = group_owner.clone();
        if !pir_core::pbc::pbc_cuckoo_place(
            &cand_groups,
            &mut group_owner,
            qi,
            max_kicks as usize,
            nh,
        ) {
            group_owner = saved;
        }
    }

    // Build per-item assignment: item_index -> group_id (or -1)
    let mut assignments = vec![-1i32; ni];
    for (b, owner) in group_owner.iter().enumerate() {
        if let Some(qi) = owner {
            assignments[*qi] = b as i32;
        }
    }
    assignments
}

// ─── PBC multi-round planning ─────────────────────────────────────────────

/// Plan multi-round PBC placement.
///
/// `item_groups_flat` is a flat array: num_items * items_per candidates.
/// Returns JSON: array of rounds, each round is array of [item_index, group_id].
#[wasm_bindgen]
pub fn plan_rounds(
    item_groups_flat: &[u32],
    items_per: u32,
    num_groups: u32,
    num_hashes: u32,
    max_kicks: u32,
) -> JsValue {
    let ip = items_per as usize;
    let num_items = item_groups_flat.len() / ip;

    let item_groups: Vec<Vec<usize>> = (0..num_items)
        .map(|i| {
            (0..ip)
                .map(|h| item_groups_flat[i * ip + h] as usize)
                .collect()
        })
        .collect();

    let rounds = pir_core::pbc::pbc_plan_rounds(
        &item_groups,
        num_groups as usize,
        num_hashes as usize,
        max_kicks as usize,
    );

    // Convert to JSON: Vec<Vec<[usize, usize]>>
    let json_rounds: Vec<Vec<[usize; 2]>> = rounds
        .iter()
        .map(|round| round.iter().map(|&(item, group)| [item, group]).collect())
        .collect();

    serde_wasm_bindgen::to_value(&json_rounds).unwrap_or(JsValue::NULL)
}
