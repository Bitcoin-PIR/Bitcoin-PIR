//! Build PER-GROUP Merkle trees for OnionPIR — one tree per PBC group.
//!
//! Phase 3 of the per-group Merkle redesign (PLAN_MERKLE_CODING.md /
//! MERKLE_COLOCATION_REVIEW.md §2–§6). Replaces the old flat per-table
//! trees — which spanned every PBC group and so needed a `gid`-cuckoo for
//! the sibling fetch (the batch-size leak, §1) — with one independent
//! tree per PBC group: 75 INDEX trees + 80 DATA(=CHUNK) trees.
//!
//! Each group's tree is arity-`ARITY` (`= onionpir entry_size / 32`, ≈104)
//! over that group's cuckoo bins. Leaf hashes are read verbatim from
//! `onion_{index,data}_bin_hashes.bin` — gen_2/gen_3 already applied
//! OnionPIR's no-prefix `SHA256(bin)` leaf hash (§2e), so the leaves are
//! never recomputed here. Internal nodes use `merkle::compute_parent_n`,
//! exactly as the old flat onion build did.
//!
//! Tree-top split: every level except the leaf level is cached
//! client-side (the "tree-top"); the single PIR sibling level (leaf →
//! level-1) is served by a tiny per-group OnionPIR FHE-PIR database whose
//! plaintexts are the level-1 parent rows (99 INDEX / 364 DATA — sized
//! exactly, no padding, since onionpir ≥ `aa7710d`; see the §3.2
//! experiment `experiment_onion_sibling_pir`).
//!
//! Output files (the contract for the 3b server + 3d client):
//!   merkle_onion_sib_index.bin / merkle_onion_sib_data.bin
//!       — consolidated per-group sibling DBs: `[24B header][K NTT DBs]`,
//!         each DB a `save_db` blob the server `load_db_from_borrowed`s.
//!   merkle_onion_tree_tops.bin  — 155 per-group tree-tops, concatenated.
//!   merkle_onion_roots.bin      — 155 per-group roots (32B each).
//!   merkle_onion_root.bin       — super-root = SHA256(concat 155 roots) (§2f).
//!
//! Usage: gen_4_build_merkle_onion [--data-dir <dir>]

use onionpir::{self, Server as PirServer};
use pir_core::merkle::{self, Hash256, ZERO_HASH};
use pir_core::onion_unpack;
use rayon::prelude::*;
use std::fs::File;
use std::io::{BufWriter, Write as IoWrite};
use std::time::Instant;

const DEFAULT_DATA_DIR: &str = "/Volumes/Bitcoin/data";

/// `cache_from_level = 1`: the leaf level (level 0) is the single PIR
/// sibling level; every level from 1 up is held in the tree-top cache.
const CACHE_FROM_LEVEL: usize = 1;

/// OnionPIR Merkle arity = `entry_size / 32`, so one internal node's
/// ARITY child hashes pack into exactly one OnionPIR plaintext.
fn onion_merkle_arity() -> usize {
    onionpir::params_info(0).entry_size as usize / 32
}

fn parse_data_dir() -> String {
    let args: Vec<String> = std::env::args().collect();
    let mut data_dir = DEFAULT_DATA_DIR.to_string();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--data-dir" && i + 1 < args.len() {
            data_dir = args[i + 1].clone();
            i += 1;
        }
        i += 1;
    }
    data_dir
}

/// Consolidated sibling-file magic (low byte = table type: 0 index, 1 data).
fn sib_magic(tree_kind: &str) -> u64 {
    match tree_kind {
        "index" => 0xBA7C_0E51_0000_0000,
        "data" => 0xBA7C_0E51_0000_0001,
        _ => panic!("unknown tree_kind: {}", tree_kind),
    }
}

// ─── Read leaf (bin) hashes ─────────────────────────────────────────────────

/// Read bin hashes written by gen_2/gen_3.
/// Format: `[4B K LE][4B bins_per_table LE][K * bins_per_table * 32B hashes]`.
/// The hashes are OnionPIR's no-prefix `SHA256(bin)` leaves (§2e).
fn read_bin_hashes(path: &str) -> (usize, usize, Vec<Hash256>) {
    let data = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {}", path, e));
    assert!(data.len() >= 8, "{} too short", path);
    let k = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let bins_per_table = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
    let total_bins = k * bins_per_table;
    assert_eq!(
        data.len(),
        8 + total_bins * 32,
        "{} size mismatch: expected {} got {}",
        path,
        8 + total_bins * 32,
        data.len()
    );

    let mut hashes = Vec::with_capacity(total_bins);
    for i in 0..total_bins {
        let off = 8 + i * 32;
        let mut h = [0u8; 32];
        h.copy_from_slice(&data[off..off + 32]);
        hashes.push(h);
    }
    (k, bins_per_table, hashes)
}

// ─── Per-group tree ─────────────────────────────────────────────────────────

/// One PBC group's arity-N Merkle tree.
struct PerGroupTree {
    /// `levels[0]` = leaf hashes, `levels[depth]` = `[root]`.
    levels: Vec<Vec<Hash256>>,
    root: Hash256,
}

/// Build a group's arity-N tree from its (already-hashed) leaves.
///
/// Incomplete final groups at each level pad with `ZERO_HASH` — no
/// power-of-arity padding (mirrors `merkle_bucket_builder::build_group_tree`).
fn build_group_tree(leaf_hashes: Vec<Hash256>, arity: usize) -> PerGroupTree {
    let mut levels: Vec<Vec<Hash256>> = vec![leaf_hashes];
    loop {
        let prev = levels.last().unwrap();
        if prev.len() <= 1 {
            break;
        }
        let next_len = prev.len().div_ceil(arity);
        let mut next_level = Vec::with_capacity(next_len);
        for i in 0..next_len {
            let start = i * arity;
            let end = (start + arity).min(prev.len());
            let mut children: Vec<Hash256> = prev[start..end].to_vec();
            children.resize(arity, ZERO_HASH);
            next_level.push(merkle::compute_parent_n(&children));
        }
        levels.push(next_level);
    }
    let root = levels.last().unwrap()[0];
    PerGroupTree { levels, root }
}

// ─── Per-group sibling OnionPIR DB ──────────────────────────────────────────

/// Build the OnionPIR FHE-PIR sibling database for one group's single
/// sibling level (leaf → level-1).
///
/// The DB has `tree.levels[1].len()` plaintexts; plaintext `r` holds the
/// `arity` leaf hashes that are children of level-1 node `r` — i.e. the
/// siblings the client fetches to recompute that level-1 node. Returns
/// the `save_db` blob (preprocessed DB, header + payload) — the server
/// `load_db_from_borrowed`s it as a sub-slice of the consolidated file.
fn build_group_sibling_db(
    tree: &PerGroupTree,
    arity: usize,
    poly_degree: usize,
    entry_size_pt: usize,
    group_id: usize,
    tree_kind: &str,
    data_dir: &str,
) -> Vec<u8> {
    let leaves = &tree.levels[0];
    let num_pt = tree.levels[CACHE_FROM_LEVEL].len();

    // Pack each level-1 parent's ARITY children into one plaintext.
    let mut all_coeffs: Vec<u64> = Vec::with_capacity(num_pt * poly_degree);
    let mut row = vec![0u8; entry_size_pt];
    for r in 0..num_pt {
        for c in 0..arity {
            let idx = r * arity + c;
            let dst = &mut row[c * 32..c * 32 + 32];
            if idx < leaves.len() {
                dst.copy_from_slice(&leaves[idx]);
            } else {
                dst.copy_from_slice(&ZERO_HASH);
            }
        }
        let coeffs = onion_unpack::pack_bytes_into_coefficients(&row, entry_size_pt, poly_degree);
        all_coeffs.extend_from_slice(&coeffs);
    }

    let mut server = PirServer::new(num_pt as u64);
    assert!(
        server.push_plaintexts(&all_coeffs, num_pt as u64, 0, &[]),
        "push_plaintexts failed for {} group {}",
        tree_kind,
        group_id
    );

    // `save_db` only writes to a path; round-trip through a temp file to
    // get the blob bytes, then concatenate into the consolidated file.
    let temp = format!("{}/.merkle_onion_sib_{}_g{}.savetmp", data_dir, tree_kind, group_id);
    assert!(
        server.save_db(&temp),
        "save_db failed for {} group {}",
        tree_kind,
        group_id
    );
    let blob = std::fs::read(&temp).unwrap_or_else(|e| panic!("read {}: {}", temp, e));
    let _ = std::fs::remove_file(&temp);
    blob
}

// ─── Build one tree kind (75 INDEX or 80 DATA groups) ───────────────────────

/// Build all `k` per-group trees for one tree kind, write the consolidated
/// sibling DB, and return the trees (for tree-tops + roots).
fn build_tree_kind(
    tree_kind: &str,
    k: usize,
    bins_per_table: usize,
    leaf_hashes: Vec<Hash256>,
    arity: usize,
    data_dir: &str,
) -> Vec<PerGroupTree> {
    assert_eq!(leaf_hashes.len(), k * bins_per_table);
    let t = Instant::now();

    // 1. Build the k per-group trees in parallel (pure hashing).
    let trees: Vec<PerGroupTree> = (0..k)
        .into_par_iter()
        .map(|g| {
            let start = g * bins_per_table;
            let group_leaves = leaf_hashes[start..start + bins_per_table].to_vec();
            build_group_tree(group_leaves, arity)
        })
        .collect();

    // Every group has the same bins_per_table → identical tree shape.
    assert!(
        trees[0].levels.len() >= 2,
        "{} tree has no level-1 — bins_per_table {} too small",
        tree_kind,
        bins_per_table
    );
    let depth = trees[0].levels.len() - 1;
    let num_pt = trees[0].levels[CACHE_FROM_LEVEL].len();
    assert!(
        num_pt >= 2,
        "{} sibling DB would have {} plaintext(s) — too small",
        tree_kind,
        num_pt
    );
    for (g, tree) in trees.iter().enumerate() {
        assert_eq!(
            tree.levels.len() - 1,
            depth,
            "{} group {} tree depth differs from group 0",
            tree_kind,
            g
        );
        assert_eq!(
            tree.levels[CACHE_FROM_LEVEL].len(),
            num_pt,
            "{} group {} sibling-DB size differs from group 0",
            tree_kind,
            g
        );
    }
    let shape: Vec<usize> = trees[0].levels.iter().map(|l| l.len()).collect();
    println!(
        "  [{}] {} groups, {} leaves/group, tree shape {:?} (depth {})",
        tree_kind, k, bins_per_table, shape, depth
    );
    println!(
        "  [{}] sibling DB: {} plaintexts/group (level-1 parent rows)",
        tree_kind, num_pt
    );

    // 2. OnionPIR params for the per-group sibling DB.
    let p = onionpir::params_info(num_pt as u64);
    assert_eq!(
        p.num_plaintexts as usize, num_pt,
        "OnionPIR shaped the {} sibling DB to {} plaintexts, expected exactly {} \
         — single-dimension exact sizing required (onionpir >= aa7710d)",
        tree_kind, p.num_plaintexts, num_pt
    );
    assert_eq!(
        p.entry_size as usize,
        arity * 32,
        "onionpir entry_size {} != arity*32 ({}) — stale onionpir crate linked",
        p.entry_size,
        arity * 32
    );
    let poly_degree = p.poly_degree as usize;
    let entry_size_pt = p.entry_size as usize;

    // 3. Build the k per-group sibling NTT DBs (serial — each NTT uses all
    //    cores internally; the DBs are tiny so the loop is fast).
    println!("  [{}] building {} per-group sibling NTT DBs...", tree_kind, k);
    let t_sib = Instant::now();
    let blobs: Vec<Vec<u8>> = (0..k)
        .map(|g| {
            build_group_sibling_db(
                &trees[g],
                arity,
                poly_degree,
                entry_size_pt,
                g,
                tree_kind,
                data_dir,
            )
        })
        .collect();

    // 4. Write the consolidated sibling file. Every per-group DB has the
    //    same num_pt → identical blob length, so a fixed-stride layout
    //    needs no offset table.
    let blob_len = blobs[0].len();
    for (g, b) in blobs.iter().enumerate() {
        assert_eq!(
            b.len(),
            blob_len,
            "{} group {} sibling-DB blob is {} B, expected {} B",
            tree_kind,
            g,
            b.len(),
            blob_len
        );
    }
    let sib_path = format!("{}/merkle_onion_sib_{}.bin", data_dir, tree_kind);
    {
        let f = File::create(&sib_path).expect("create sibling file");
        let mut w = BufWriter::with_capacity(16 * 1024 * 1024, f);
        // 24-byte header: magic, K, arity, num_pt, blob_len.
        w.write_all(&sib_magic(tree_kind).to_le_bytes()).unwrap();
        w.write_all(&(k as u32).to_le_bytes()).unwrap();
        w.write_all(&(arity as u32).to_le_bytes()).unwrap();
        w.write_all(&(num_pt as u32).to_le_bytes()).unwrap();
        w.write_all(&(blob_len as u32).to_le_bytes()).unwrap();
        for b in &blobs {
            w.write_all(b).unwrap();
        }
        w.flush().unwrap();
    }
    let sib_size = 24 + k * blob_len;
    println!(
        "  [{}] wrote {} — {} groups × {} B = {:.1} MB ({:.2?})",
        tree_kind,
        sib_path,
        k,
        blob_len,
        sib_size as f64 / 1e6,
        t_sib.elapsed()
    );
    println!("  [{}] done in {:.2?}", tree_kind, t.elapsed());

    trees
}

// ─── Tree-top + roots writers ───────────────────────────────────────────────

/// Write the 155 per-group tree-tops (75 INDEX then 80 DATA) to one blob.
///
/// Format:
///   `[4B num_trees LE]`
///   Per tree: `[1B cache_from_level][4B total_nodes LE][2B arity LE]`
///             `[1B num_cached_levels]`
///             Per cached level: `[4B num_nodes LE][num_nodes × 32B]`
fn write_tree_tops(
    path: &str,
    index_trees: &[PerGroupTree],
    data_trees: &[PerGroupTree],
    arity: usize,
) {
    let f = File::create(path).expect("create tree tops");
    let mut w = BufWriter::with_capacity(4 * 1024 * 1024, f);

    let num_trees = (index_trees.len() + data_trees.len()) as u32;
    w.write_all(&num_trees.to_le_bytes()).unwrap();
    for tree in index_trees.iter().chain(data_trees.iter()) {
        write_one_tree_top(&mut w, tree, arity);
    }
    w.flush().unwrap();

    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    println!("  tree-tops: {} trees, {:.2} MB → {}", num_trees, size as f64 / 1e6, path);
}

fn write_one_tree_top(w: &mut impl IoWrite, tree: &PerGroupTree, arity: usize) {
    let cached = &tree.levels[CACHE_FROM_LEVEL..];
    let total_nodes: usize = cached.iter().map(|l| l.len()).sum();
    w.write_all(&[CACHE_FROM_LEVEL as u8]).unwrap();
    w.write_all(&(total_nodes as u32).to_le_bytes()).unwrap();
    w.write_all(&(arity as u16).to_le_bytes()).unwrap();
    w.write_all(&[cached.len() as u8]).unwrap();
    for level in cached {
        w.write_all(&(level.len() as u32).to_le_bytes()).unwrap();
        for h in level {
            w.write_all(h).unwrap();
        }
    }
}

/// Write the 155 per-group roots and the super-root (§2f).
fn write_roots(data_dir: &str, index_trees: &[PerGroupTree], data_trees: &[PerGroupTree]) {
    let roots: Vec<Hash256> = index_trees
        .iter()
        .chain(data_trees.iter())
        .map(|t| t.root)
        .collect();

    let roots_path = format!("{}/merkle_onion_roots.bin", data_dir);
    {
        let f = File::create(&roots_path).expect("create roots");
        let mut w = BufWriter::new(f);
        for r in &roots {
            w.write_all(r).unwrap();
        }
        w.flush().unwrap();
    }

    let mut preimage = Vec::with_capacity(roots.len() * 32);
    for r in &roots {
        preimage.extend_from_slice(r);
    }
    let super_root = merkle::sha256(&preimage);
    let super_root_path = format!("{}/merkle_onion_root.bin", data_dir);
    std::fs::write(&super_root_path, super_root).expect("write super-root");

    let hex: String = super_root.iter().take(8).map(|b| format!("{:02x}", b)).collect();
    println!("  roots: {} per-group roots → {}", roots.len(), roots_path);
    println!("  super-root: {}... → {}", hex, super_root_path);
}

// ─── Main ───────────────────────────────────────────────────────────────────

fn main() {
    let data_dir = parse_data_dir();
    let arity = onion_merkle_arity();

    println!("=== Gen 4: Build Per-Group OnionPIR Merkle Trees ===");
    println!("Data dir:  {}", data_dir);
    println!("Arity:     {} (onionpir entry_size / 32)", arity);
    println!("Layout:    one tree per PBC group; 1 PIR sibling level (leaf → level-1)");
    println!();
    let t_total = Instant::now();

    // 1. Read leaf hashes (gen_2/gen_3 output; OnionPIR no-prefix SHA256).
    let index_path = format!("{}/onion_index_bin_hashes.bin", data_dir);
    println!("[1] Reading INDEX bin hashes from {}...", index_path);
    let (index_k, index_bins, index_hashes) = read_bin_hashes(&index_path);
    println!(
        "    K={}, bins/group={}, leaves={}",
        index_k,
        index_bins,
        index_k * index_bins
    );

    let data_path = format!("{}/onion_data_bin_hashes.bin", data_dir);
    println!("[2] Reading DATA bin hashes from {}...", data_path);
    let (data_k, data_bins, data_hashes) = read_bin_hashes(&data_path);
    println!(
        "    K={}, bins/group={}, leaves={}",
        data_k,
        data_bins,
        data_k * data_bins
    );

    // 2. Build per-group trees + per-group sibling DBs.
    println!("\n[3] Building INDEX per-group trees...");
    let index_trees = build_tree_kind("index", index_k, index_bins, index_hashes, arity, &data_dir);

    println!("\n[4] Building DATA per-group trees...");
    let data_trees = build_tree_kind("data", data_k, data_bins, data_hashes, arity, &data_dir);

    // 3. Tree-tops + roots + super-root.
    println!("\n[5] Writing tree-tops + roots...");
    let tree_tops_path = format!("{}/merkle_onion_tree_tops.bin", data_dir);
    write_tree_tops(&tree_tops_path, &index_trees, &data_trees, arity);
    write_roots(&data_dir, &index_trees, &data_trees);

    println!();
    println!("=== Summary ===");
    println!("Arity:        {}", arity);
    println!("INDEX:        {} trees, {} leaves/group", index_k, index_bins);
    println!("DATA:         {} trees, {} leaves/group", data_k, data_bins);
    println!("Total trees:  {}", index_k + data_k);
    println!("Total time:   {:.1}s", t_total.elapsed().as_secs_f64());
}
