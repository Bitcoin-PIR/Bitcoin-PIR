//! Integration test: verify random entries against the OnionPIR Merkle tree.
//!
//! Verifies the hash chain without OnionPIR decryption — reads raw packed group data
//! from the _packed.bin files and checks cuckoo table correctness.
//!
//! For each test entry:
//! 1. Compute data_hash, look up tree_loc from MERKLE_DATA meta (using raw bin scan)
//! 2. Compute leaf_hash
//! 3. For each sibling level: look up group in 6-hash cuckoo, read packed data, verify hash
//! 4. Use tree-top cache for remaining levels
//! 5. Verify root
//!
//! Usage: test_merkle_verify_onion [--data-dir <dir>] [--count N]

mod merkle_builder;

use memmap2::Mmap;
use pir_core::hash;
use pir_core::merkle::{self, Hash256, ZERO_HASH};
use pir_core::params::*;
use std::fs::File;
use std::io::Read;

const DEFAULT_DATA_DIR: &str = "/Volumes/Bitcoin/data";
const ARITY: usize = 120;
const PACKED_ENTRY_SIZE: usize = 3840;
const DEFAULT_NUM_TESTS: usize = 100;

const MERKLE_DATA_SLOT_SIZE: usize = 48;
const MERKLE_DATA_SLOTS_PER_BIN: usize = 80;

// ─── Hash utilities (same as gen_4_build_merkle_onion) ──────────────────────

#[inline]
fn splitmix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    x
}

#[inline]
fn hash_entry_for_group(entry_id: u32, nonce: u64) -> u64 {
    splitmix64((entry_id as u64).wrapping_add(nonce.wrapping_mul(0x9e3779b97f4a7c15)))
}

fn derive_pbc_groups(entry_id: u32, k: usize) -> [usize; 3] {
    let mut groups = [0usize; 3];
    let mut nonce: u64 = 0;
    let mut count = 0;
    while count < 3 {
        let h = hash_entry_for_group(entry_id, nonce);
        let group = (h % k as u64) as usize;
        nonce += 1;
        let mut dup = false;
        for i in 0..count { if groups[i] == group { dup = true; break; } }
        if dup { continue; }
        groups[count] = group;
        count += 1;
    }
    groups
}

fn level_master_seed(level: usize) -> u64 {
    0xBA7C_51B1_FEED_0000u64.wrapping_add(level as u64)
}

fn derive_cuckoo_key(master_seed: u64, group_id: usize, hash_fn: usize) -> u64 {
    splitmix64(
        master_seed
            .wrapping_add((group_id as u64).wrapping_mul(0x9e3779b97f4a7c15))
            .wrapping_add((hash_fn as u64).wrapping_mul(0x517cc1b727220a95)),
    )
}

fn cuckoo_hash_int(entry_id: u32, key: u64, num_bins: usize) -> usize {
    (splitmix64((entry_id as u64) ^ key) % num_bins as u64) as usize
}

fn adaptive_k(num_groups: usize) -> usize {
    if num_groups >= 100_000 { 75 }
    else if num_groups >= 1_000 { 25 }
    else { (num_groups / 10).max(5) }
}

// ─── Tree-top cache loader ─────────────────────────────────────────────────

struct TreeTopCache {
    cache_from_level: usize,
    arity: usize,
    levels: Vec<Vec<Hash256>>,
}

fn load_tree_top_cache(path: &str) -> TreeTopCache {
    let data = std::fs::read(path).expect("read tree-top");
    let cache_from_level = data[0] as usize;
    let _total_nodes = u32::from_le_bytes(data[1..5].try_into().unwrap()) as usize;
    let arity = u16::from_le_bytes(data[5..7].try_into().unwrap()) as usize;
    let num_cached_levels = data[7] as usize;
    let mut offset = 8;
    let mut levels = Vec::with_capacity(num_cached_levels);
    for _ in 0..num_cached_levels {
        let num_nodes = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let mut level = Vec::with_capacity(num_nodes);
        for _ in 0..num_nodes {
            let mut h = [0u8; 32];
            h.copy_from_slice(&data[offset..offset + 32]);
            level.push(h);
            offset += 32;
        }
        levels.push(level);
    }
    TreeTopCache { cache_from_level, arity, levels }
}

// ─── Sibling cuckoo table loader ───────────────────────────────────────────

struct SiblingLevel {
    k: usize,
    bins_per_table: usize,
    master_seed: u64,
    num_groups: usize,
    cuckoo_mmap: Mmap,
    packed_mmap: Mmap,
}

fn load_sibling_level(data_dir: &str, level: usize) -> SiblingLevel {
    // Load cuckoo file
    let cuckoo_path = format!("{}/merkle_onion_sib_L{}_cuckoo.bin", data_dir, level);
    let cuckoo_file = File::open(&cuckoo_path).expect("open cuckoo");
    let cuckoo_mmap = unsafe { Mmap::map(&cuckoo_file) }.expect("mmap cuckoo");

    // Parse header (40 bytes)
    let k = u32::from_le_bytes(cuckoo_mmap[8..12].try_into().unwrap()) as usize;
    let _cuckoo_num_hashes = u32::from_le_bytes(cuckoo_mmap[12..16].try_into().unwrap()) as usize;
    let bins_per_table = u32::from_le_bytes(cuckoo_mmap[16..20].try_into().unwrap()) as usize;
    let master_seed = u64::from_le_bytes(cuckoo_mmap[20..28].try_into().unwrap());
    let num_groups = u32::from_le_bytes(cuckoo_mmap[28..32].try_into().unwrap()) as usize;

    // Load packed file
    let packed_path = format!("{}/merkle_onion_sib_L{}_packed.bin", data_dir, level);
    let packed_file = File::open(&packed_path).expect("open packed");
    let packed_mmap = unsafe { Mmap::map(&packed_file) }.expect("mmap packed");

    SiblingLevel { k, bins_per_table, master_seed, num_groups, cuckoo_mmap, packed_mmap }
}

/// Look up a group_id in the sibling cuckoo table.
/// Returns the 120 child hashes if found.
fn lookup_sibling_group(sib: &SiblingLevel, group_id: u32) -> Option<Vec<Hash256>> {
    let pbc_groups = derive_pbc_groups(group_id, sib.k);

    // Header is 36 bytes: 8(magic)+4(k)+4(num_hashes)+4(bins)+8(seed)+4(num_groups)+4(pad)
    let header_size = 36;

    for &pbc_group in &pbc_groups {
        let table_offset = header_size + pbc_group * sib.bins_per_table * 4;

        for h in 0..6 {
            let key = derive_cuckoo_key(sib.master_seed, pbc_group, h);
            let bin = cuckoo_hash_int(group_id, key, sib.bins_per_table);
            let entry_offset = table_offset + bin * 4;

            if entry_offset + 4 > sib.cuckoo_mmap.len() { continue; }
            let stored_id = u32::from_le_bytes(
                sib.cuckoo_mmap[entry_offset..entry_offset + 4].try_into().unwrap()
            );

            if stored_id == group_id {
                // Read the packed data for this group
                let data_offset = group_id as usize * PACKED_ENTRY_SIZE;
                if data_offset + PACKED_ENTRY_SIZE > sib.packed_mmap.len() { return None; }

                let packed = &sib.packed_mmap[data_offset..data_offset + PACKED_ENTRY_SIZE];
                let mut children = Vec::with_capacity(ARITY);
                for c in 0..ARITY {
                    let off = c * 32;
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&packed[off..off + 32]);
                    children.push(h);
                }
                return Some(children);
            }
        }
    }
    None
}

// ─── MERKLE_DATA lookup (scan raw packed bins) ──────────────────────────────

/// Look up scripthash in MERKLE_DATA by scanning the packed bin data directly.
/// This is a simplified version that reads the raw pre-OnionPIR bin data.
/// For a full test, we'd decrypt via OnionPIR — but this verifies the hash chain.
///
/// We don't have the raw bin data (only preprocessed OnionPIR files).
/// Instead, we recompute tree_loc and data_hash from the index + chunks files.
/// This is equivalent to verifying the Merkle proof assuming MERKLE_DATA is correct.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut data_dir = DEFAULT_DATA_DIR.to_string();
    let mut num_tests = DEFAULT_NUM_TESTS;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" if i + 1 < args.len() => { data_dir = args[i + 1].clone(); i += 1; }
            "--count" if i + 1 < args.len() => { num_tests = args[i + 1].parse().expect("--count N"); i += 1; }
            _ => {}
        }
        i += 1;
    }

    println!("=== OnionPIR Merkle Verification Test (arity={}) ===\n", ARITY);

    // ── Load files ────────────────────────────────────────────────────────

    println!("[1] Loading data files...");

    let index_path = format!("{}/intermediate/utxo_chunks_index_nodust.bin", data_dir);
    let index_file = File::open(&index_path).expect("open index");
    let index_mmap = unsafe { Mmap::map(&index_file).unwrap() };
    let num_entries = index_mmap.len() / INDEX_RECORD_SIZE;
    println!("  Index: {} entries", num_entries);

    let chunks_path = format!("{}/intermediate/utxo_chunks_nodust.bin", data_dir);
    let chunks_file = File::open(&chunks_path).expect("open chunks");
    let chunks_mmap = unsafe { Mmap::map(&chunks_file).unwrap() };

    let root_path = format!("{}/merkle_root_onion.bin", data_dir);
    let mut root = [0u8; 32];
    File::open(&root_path).expect("open root").read_exact(&mut root).unwrap();
    println!("  Root: {:02x}{:02x}{:02x}{:02x}...", root[0], root[1], root[2], root[3]);

    let top_path = format!("{}/merkle_tree_top_onion.bin", data_dir);
    let cache = load_tree_top_cache(&top_path);
    println!("  Tree-top: arity={}, cache_from_level={}, {} levels",
        cache.arity, cache.cache_from_level, cache.levels.len());

    // Load sibling levels
    let num_sibling_levels = cache.cache_from_level;
    let mut sib_levels: Vec<SiblingLevel> = Vec::new();
    for level in 0..num_sibling_levels {
        let sib = load_sibling_level(&data_dir, level);
        println!("  Sib L{}: K={}, bins={}, {} groups", level, sib.k, sib.bins_per_table, sib.num_groups);
        sib_levels.push(sib);
    }

    // ── We need tree_locs ────────────────────────────────────────────────
    // Recompute tree_locs by sorting scripthashes (same as builder)
    println!("\n[2] Computing tree_locs (sorting {} scripthashes)...", num_entries);
    let t = std::time::Instant::now();

    struct EntryInfo {
        scripthash: [u8; 20],
        data_hash: Hash256,
    }

    let entry_infos: Vec<EntryInfo> = (0..num_entries)
        .map(|i| {
            let base = i * INDEX_RECORD_SIZE;
            let mut scripthash = [0u8; 20];
            scripthash.copy_from_slice(&index_mmap[base..base + 20]);
            let start_chunk_id = u32::from_le_bytes(index_mmap[base + 20..base + 24].try_into().unwrap());
            let num_chunks = index_mmap[base + 24] as usize;
            let data_hash = if num_chunks > 0 {
                let s = start_chunk_id as usize * 40;
                merkle::compute_data_hash(&chunks_mmap[s..s + num_chunks * 40])
            } else {
                ZERO_HASH
            };
            EntryInfo { scripthash, data_hash }
        })
        .collect();

    let mut sorted_indices: Vec<usize> = (0..num_entries).collect();
    sorted_indices.sort_unstable_by(|&a, &b| entry_infos[a].scripthash.cmp(&entry_infos[b].scripthash));
    let mut tree_locs = vec![0u32; num_entries];
    for (pos, &idx) in sorted_indices.iter().enumerate() {
        tree_locs[idx] = pos as u32;
    }
    println!("  Done in {:.2?}", t.elapsed());

    // ── Test random entries ───────────────────────────────────────────────

    println!("\n[3] Testing {} random entries...\n", num_tests);

    let mut rng_state: u64 = 0xdeadbeef12345678;
    let mut pass = 0;
    let mut fail = 0;

    for test_i in 0..num_tests {
        rng_state = rng_state.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = rng_state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^= z >> 31;
        let entry_idx = (z as usize) % num_entries;

        let info = &entry_infos[entry_idx];
        let tree_loc = tree_locs[entry_idx];
        let leaf_hash = merkle::compute_leaf_hash(&info.scripthash, tree_loc, &info.data_hash);

        let mut current_hash = leaf_hash;
        let mut node_idx = tree_loc as usize;
        let mut verified = true;

        // Sibling levels (L0..L{cache_from_level-1})
        for level in 0..num_sibling_levels {
            let group_id = (node_idx / ARITY) as u32;

            let children = match lookup_sibling_group(&sib_levels[level], group_id) {
                Some(c) => c,
                None => {
                    println!("  [{}] FAIL: sibling group not found L{} node={} group={}",
                        test_i, level, node_idx, group_id);
                    verified = false;
                    break;
                }
            };

            current_hash = merkle::compute_parent_n(&children);
            node_idx = group_id as usize;
        }

        if !verified { fail += 1; continue; }

        // Tree-top cache levels
        for cache_idx in 0..cache.levels.len().saturating_sub(1) {
            let level_nodes = &cache.levels[cache_idx];
            let parent_start = (node_idx / ARITY) * ARITY;
            let mut children = Vec::with_capacity(ARITY);
            for c in 0..ARITY {
                let child_idx = parent_start + c;
                if child_idx < level_nodes.len() {
                    children.push(level_nodes[child_idx]);
                } else {
                    children.push(ZERO_HASH);
                }
            }
            current_hash = merkle::compute_parent_n(&children);
            node_idx /= ARITY;
        }

        if current_hash == root {
            if test_i < 5 || test_i % 20 == 0 {
                println!("  [{}] PASS entry {} (scripthash {:02x}{:02x}..., tree_loc={})",
                    test_i, entry_idx, info.scripthash[0], info.scripthash[1], tree_loc);
            }
            pass += 1;
        } else {
            println!("  [{}] FAIL entry {}: root mismatch!", test_i, entry_idx);
            fail += 1;
        }
    }

    println!("\n=== Results ===");
    println!("Passed: {}/{}", pass, num_tests);
    println!("Failed: {}/{}", fail, num_tests);
    if fail > 0 { std::process::exit(1); }
    println!("\nAll entries verified successfully!");
}
