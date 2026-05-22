//! Build OnionPIR CHUNK database the DENSE way: per-group preprocessed
//! OnionPIR DBs concatenated into a single `onion_chunk_all.bin`.
//!
//! This is the CHUNK-side analogue of `gen_3_onion` (the INDEX builder).
//! Where `gen_2_onion` writes ONE shared NTT store
//! (`onion_shared_ntt.bin`) plus per-group cuckoo tables and relies on a
//! server-side gather (via `index_table`) at query time,
//! `gen_2_onion_dense` precomputes each PBC group's DENSE preprocessed DB
//! at build time — exactly like `gen_3_onion` does for INDEX. The
//! server then mmaps `onion_chunk_all.bin` once and hands each group a
//! slice, with no per-query gather.
//!
//! The cuckoo / PBC logic (group assignment, 6-hash bs=1 cuckoo,
//! `bins_per_table` sizing) is COPIED VERBATIM from `gen_2_onion`. The
//! per-group dense build loop + single-file consolidation is mirrored
//! from `gen_3_onion`. CHUNK cuckoo is bs=1 (one entry per bin), so each
//! bin maps to one packed entry's bytes (or zeros for an empty bin) — no
//! `serialize_cuckoo_bin` slot-packing like INDEX.
//!
//! Output:
//!   - onion_chunk_all.bin: K_CHUNK per-group dense DBs + 32-byte master header
//!   - onion_chunk_cuckoo.bin: per-group cuckoo tables (bin → entry_id mapping)
//!   - onion_data_bin_hashes.bin: per-bin DATA hashes (for per-bin Merkle)
//!
//! Does NOT write `onion_shared_ntt.bin`.
//!
//! Usage:
//!   cargo run --release -p build --bin gen_2_onion_dense [-- --data-dir <dir>]
//!
//! With no flags, reads `/Volumes/Bitcoin/data/intermediate/onion_packed_entries.bin`
//! and writes outputs to `/Volumes/Bitcoin/data/`.
//!
//! With `--data-dir <D>`, reads `<D>/onion_packed_entries.bin` and writes
//! all outputs under `<D>/`. Use this for delta DB builds.

use memmap2::Mmap;
use onionpir::{self, Client as PirClient, Server as PirServer};
use pir_core::cuckoo::{HeaderAnchor, ANCHOR_MAGIC_DELTA_XOR, ANCHOR_MAGIC_SNAPSHOT_XOR};
use pir_core::seeds::{CHAIN_ANCHOR_BYTES, DELTA_ANCHOR_BYTES};
use std::env;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Instant;

// ─── Default paths (used when --data-dir is not specified) ──────────────────

const DEFAULT_PACKED_FILE: &str = "/Volumes/Bitcoin/data/intermediate/onion_packed_entries.bin";
const DEFAULT_CUCKOO_FILE: &str = "/Volumes/Bitcoin/data/onion_chunk_cuckoo.bin";
const DEFAULT_BIN_HASHES_FILE: &str = "/Volumes/Bitcoin/data/onion_data_bin_hashes.bin";
const DEFAULT_CHUNK_ALL_FILE: &str = "/Volumes/Bitcoin/data/onion_chunk_all.bin";
const DEFAULT_CHUNK_PIR_DIR: &str = "/Volumes/Bitcoin/data/onion_chunk_pir";

/// Magic for the consolidated onion_chunk_all.bin file. The byte layout
/// after this 32-byte master header is just K_CHUNK per-group
/// preprocessed databases concatenated back-to-back, each in OnionPIR's
/// standard save_db output format. The per-group size is identical
/// because all groups share the same bins_per_table and OnionPIR params.
///
/// Distinct from ONION_INDEX_ALL_MAGIC (0xBA7C_0010_0000_0003): CHUNK
/// uses the next discriminator (...0004).
const ONION_CHUNK_ALL_MAGIC: u64 = 0xBA7C_0010_0000_0004;
const ONION_CHUNK_ALL_HEADER_BYTES: usize = 32; // 4 * u64

struct ResolvedPaths {
    packed_file: String,
    cuckoo_file: String,
    bin_hashes_file: String,
    chunk_all_file: String,
    chunk_pir_dir: PathBuf, // per-group scratch dir
    /// Optional chain/delta anchor file for chain-derived seeds.
    /// If `--anchor <path>` is passed, that wins; otherwise we look for
    /// `<data_dir>/chain_anchor.bin` or `<data_dir>/delta_anchor.bin`.
    anchor_file: Option<PathBuf>,
}

/// Resolve input/output paths from `--data-dir <D>` and optional `--anchor <path>`.
fn resolve_paths() -> ResolvedPaths {
    let args: Vec<String> = env::args().collect();
    let mut data_dir: Option<String> = None;
    let mut anchor_file: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--data-dir" {
            if let Some(v) = args.get(i + 1) {
                data_dir = Some(v.clone());
                i += 1;
            }
        } else if args[i] == "--anchor" {
            if let Some(v) = args.get(i + 1) {
                anchor_file = Some(PathBuf::from(v));
                i += 1;
            }
        }
        i += 1;
    }
    if anchor_file.is_none() {
        if let Some(d) = data_dir.as_ref() {
            let chain = PathBuf::from(format!("{}/chain_anchor.bin", d));
            let delta = PathBuf::from(format!("{}/delta_anchor.bin", d));
            if chain.exists() {
                anchor_file = Some(chain);
            } else if delta.exists() {
                anchor_file = Some(delta);
            }
        }
    }
    match data_dir {
        Some(d) => ResolvedPaths {
            packed_file: format!("{}/onion_packed_entries.bin", d),
            cuckoo_file: format!("{}/onion_chunk_cuckoo.bin", d),
            bin_hashes_file: format!("{}/onion_data_bin_hashes.bin", d),
            chunk_all_file: format!("{}/onion_chunk_all.bin", d),
            chunk_pir_dir: PathBuf::from(format!("{}/onion_chunk_pir", d)),
            anchor_file,
        },
        None => ResolvedPaths {
            packed_file: DEFAULT_PACKED_FILE.to_string(),
            cuckoo_file: DEFAULT_CUCKOO_FILE.to_string(),
            bin_hashes_file: DEFAULT_BIN_HASHES_FILE.to_string(),
            chunk_all_file: DEFAULT_CHUNK_ALL_FILE.to_string(),
            chunk_pir_dir: PathBuf::from(DEFAULT_CHUNK_PIR_DIR),
            anchor_file,
        },
    }
}

/// Legacy fallback for CHUNK cuckoo master seed, used only when no
/// anchor is supplied. Matches pre-chain-derivation builds.
const LEGACY_CHUNK_MASTER_SEED: u64 = 0xa3f7c2d918e4b065;

/// Process-wide CHUNK cuckoo master seed cell. Initialised exactly once
/// at the top of `main` via `init_chunk_master_seed`.
static CHUNK_MASTER_SEED_CELL: OnceLock<u64> = OnceLock::new();

/// Process-wide chain anchor cell (parallel to CHUNK_MASTER_SEED_CELL).
/// `None` means no anchor available → emit legacy ONION_CHUNK_MAGIC.
/// `Some` means emit the v2 magic + appended anchor bytes.
static CHUNK_ANCHOR_CELL: OnceLock<Option<HeaderAnchor>> = OnceLock::new();

/// Read the configured CHUNK master seed. Panics if init wasn't called.
fn chunk_master_seed() -> u64 {
    *CHUNK_MASTER_SEED_CELL
        .get()
        .expect("CHUNK_MASTER_SEED_CELL not initialised — call init_chunk_master_seed first")
}

/// Read the configured chain anchor (or None). Panics if init wasn't called.
fn chunk_anchor() -> Option<&'static HeaderAnchor> {
    CHUNK_ANCHOR_CELL
        .get()
        .expect("CHUNK_ANCHOR_CELL not initialised — call init_chunk_master_seed first")
        .as_ref()
}

/// Initialise CHUNK_MASTER_SEED_CELL + CHUNK_ANCHOR_CELL from the anchor
/// file or fall back to legacy (no anchor, legacy magic).
fn init_chunk_master_seed(anchor: Option<&PathBuf>) {
    let (seed, header_anchor) = match anchor {
        Some(path) => {
            let bytes = std::fs::read(path).unwrap_or_else(|e| {
                eprintln!("error: failed to read anchor {}: {}", path.display(), e);
                std::process::exit(1);
            });
            match bytes.len() {
                CHAIN_ANCHOR_BYTES => {
                    let a = pir_core::seeds::ChainAnchor::from_bytes(&bytes).unwrap_or_else(|e| {
                        eprintln!("error: bad ChainAnchor {}: {}", path.display(), e);
                        std::process::exit(1);
                    });
                    let s = pir_core::seeds::SnapshotSeeds::derive(&a);
                    println!(
                        "Anchor: {} (snapshot, height={})",
                        path.display(),
                        a.block_height
                    );
                    (s.chunk_master, Some(HeaderAnchor::Snapshot(a)))
                }
                DELTA_ANCHOR_BYTES => {
                    let a = pir_core::seeds::DeltaAnchor::from_bytes(&bytes).unwrap_or_else(|e| {
                        eprintln!("error: bad DeltaAnchor {}: {}", path.display(), e);
                        std::process::exit(1);
                    });
                    let s = pir_core::seeds::DeltaSeeds::derive(&a);
                    println!(
                        "Anchor: {} (delta, {}→{})",
                        path.display(),
                        a.from.block_height,
                        a.to.block_height
                    );
                    (s.chunk_master, Some(HeaderAnchor::Delta(a)))
                }
                n => {
                    eprintln!(
                        "error: anchor {} has unknown size {} (expected {} or {})",
                        path.display(),
                        n,
                        CHAIN_ANCHOR_BYTES,
                        DELTA_ANCHOR_BYTES
                    );
                    std::process::exit(1);
                }
            }
        }
        None => {
            eprintln!("WARNING: no --anchor supplied; using LEGACY hardcoded CHUNK_MASTER_SEED.");
            eprintln!("         Output is NOT reproducible against peers without coordination.");
            (LEGACY_CHUNK_MASTER_SEED, None)
        }
    };
    CHUNK_MASTER_SEED_CELL
        .set(seed)
        .expect("init_chunk_master_seed called twice");
    CHUNK_ANCHOR_CELL
        .set(header_anchor)
        .expect("init_chunk_master_seed called twice");
}

/// Compute the on-disk magic for the OnionPIR chunk cuckoo file, given
/// the loaded anchor. Uses the same XOR scheme as pir-core::cuckoo so
/// the discriminator is shared across all v2 file formats.
fn onion_chunk_magic_with_anchor(legacy_magic: u64, anchor: Option<&HeaderAnchor>) -> u64 {
    match anchor {
        None => legacy_magic,
        Some(HeaderAnchor::Snapshot(_)) => legacy_magic ^ ANCHOR_MAGIC_SNAPSHOT_XOR,
        Some(HeaderAnchor::Delta(_)) => legacy_magic ^ ANCHOR_MAGIC_DELTA_XOR,
    }
}

// OnionPIRv2 port (commit 5b): the on-disk packed entry size is now
// `onionpir::params_info(0).entry_size` (3328 for the default
// CONFIG_N2048_K1, was 3840 pre-port at PlainMod=15). Read once in
// main() and flowed through per-call-site. The const definition is
// gone; usages take a local `packed_entry_size` parameter.
fn onion_entry_size() -> usize {
    onionpir::params_info(0).entry_size as usize
}

/// PBC parameters (same as production)
const K_CHUNK: usize = 80;
const NUM_HASHES: usize = 3; // each entry assigned to 3 groups

/// Cuckoo parameters for main DB
const CUCKOO_NUM_HASHES: usize = 6;
const CUCKOO_LOAD_FACTOR: f64 = 0.95;
const CUCKOO_MAX_KICKS: usize = 10000;
const EMPTY: u32 = u32::MAX;

// ─── Hash utilities ─────────────────────────────────────────────────────────

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

/// Derive 3 distinct PBC group indices for an entry_id.
fn derive_chunk_groups(entry_id: u32) -> [usize; NUM_HASHES] {
    let mut groups = [0usize; NUM_HASHES];
    let mut nonce: u64 = 0;
    let mut count = 0;
    while count < NUM_HASHES {
        let h = hash_entry_for_group(entry_id, nonce);
        let group = (h % K_CHUNK as u64) as usize;
        nonce += 1;
        let mut dup = false;
        for &existing in groups.iter().take(count) {
            if existing == group {
                dup = true;
                break;
            }
        }
        if dup { continue; }
        groups[count] = group;
        count += 1;
    }
    groups
}

#[inline]
fn derive_cuckoo_key(group_id: usize, hash_fn: usize) -> u64 {
    splitmix64(
        chunk_master_seed()
            .wrapping_add((group_id as u64).wrapping_mul(0x9e3779b97f4a7c15))
            .wrapping_add((hash_fn as u64).wrapping_mul(0x517cc1b727220a95)),
    )
}

#[inline]
fn cuckoo_hash_int(entry_id: u32, key: u64, num_bins: usize) -> usize {
    (splitmix64((entry_id as u64) ^ key) % num_bins as u64) as usize
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.2} GB", bytes as f64 / 1e9)
    } else if bytes >= 1_000_000 {
        format!("{:.2} MB", bytes as f64 / 1e6)
    } else {
        format!("{:.1} KB", bytes as f64 / 1e3)
    }
}

// ─── Cuckoo table builder (6-hash, bs=1) ────────────────────────────────────

fn build_cuckoo_bs1(
    entries: &[u32],
    keys: &[u64; CUCKOO_NUM_HASHES],
    num_bins: usize,
) -> Vec<u32> {
    let mut table = vec![EMPTY; num_bins];

    for &entry_id in entries {
        let mut placed = false;
        for &key in keys.iter().take(CUCKOO_NUM_HASHES) {
            let bin = cuckoo_hash_int(entry_id, key, num_bins);
            if table[bin] == EMPTY {
                table[bin] = entry_id;
                placed = true;
                break;
            }
        }
        if placed { continue; }

        // Cuckoo eviction
        let mut current_id = entry_id;
        let mut current_hash_fn = 0;
        let mut current_bin = cuckoo_hash_int(entry_id, keys[0], num_bins);
        let mut success = false;

        for kick in 0..CUCKOO_MAX_KICKS {
            let evicted = table[current_bin];
            table[current_bin] = current_id;

            let mut found_empty = false;
            for h in 0..CUCKOO_NUM_HASHES {
                let try_h = (current_hash_fn + 1 + h) % CUCKOO_NUM_HASHES;
                let bin = cuckoo_hash_int(evicted, keys[try_h], num_bins);
                if bin == current_bin { continue; }
                if table[bin] == EMPTY {
                    table[bin] = evicted;
                    found_empty = true;
                    success = true;
                    break;
                }
            }
            if found_empty { break; }

            let alt_h = (current_hash_fn + 1 + kick % (CUCKOO_NUM_HASHES - 1)) % CUCKOO_NUM_HASHES;
            let alt_bin = cuckoo_hash_int(evicted, keys[alt_h], num_bins);
            let final_bin = if alt_bin == current_bin {
                let h2 = (alt_h + 1) % CUCKOO_NUM_HASHES;
                cuckoo_hash_int(evicted, keys[h2], num_bins)
            } else {
                alt_bin
            };

            current_id = evicted;
            current_hash_fn = alt_h;
            current_bin = final_bin;
        }

        if !success {
            panic!("Cuckoo insertion failed for entry_id={} after {} kicks. \
                    Increase num_bins or CUCKOO_MAX_KICKS.", entry_id, CUCKOO_MAX_KICKS);
        }
    }

    table
}

// ─── Main ────────────────────────────────────────────────────────────────────

fn main() {
    println!("=== gen_2_onion_dense: Build OnionPIR CHUNK Database (per-group dense) ===\n");
    let total_start = Instant::now();

    let paths = resolve_paths();
    let packed_file_path = paths.packed_file;
    let cuckoo_file = paths.cuckoo_file;
    let bin_hashes_file = paths.bin_hashes_file;
    let chunk_all_file = paths.chunk_all_file;
    let chunk_pir_dir = paths.chunk_pir_dir;

    // Initialise chain-derived seeds BEFORE any cuckoo work. Falls back
    // to LEGACY_CHUNK_MASTER_SEED with a warning if no anchor is found.
    init_chunk_master_seed(paths.anchor_file.as_ref());

    println!("Paths:");
    println!("  Input packed:    {}", packed_file_path);
    println!("  Output cuckoo:   {}", cuckoo_file);
    println!("  Output hashes:   {}", bin_hashes_file);
    println!("  Output all:      {}", chunk_all_file);
    println!("  Scratch dir:     {}", chunk_pir_dir.display());
    println!("  CHUNK master_seed: 0x{:016x}", chunk_master_seed());
    println!();

    // ── 1. Read packed entries ───────────────────────────────────────────
    //
    // OnionPIRv2 port (commit 5b): `packed_entry_size` is pulled from
    // the linked onionpir crate at startup (matches gen_1_onion's
    // packing size). The pre-port hardcoded `PACKED_ENTRY_SIZE = 3840`
    // is gone.
    let packed_entry_size = onion_entry_size();
    println!("[1] Memory-mapping packed entries: {}", packed_file_path);
    let packed_file = File::open(&packed_file_path).expect("open packed entries file");
    let packed_mmap = unsafe { Mmap::map(&packed_file) }.expect("mmap packed entries");
    assert_eq!(
        packed_mmap.len() % packed_entry_size, 0,
        "packed file not aligned: {} bytes, packed_entry_size={}",
        packed_mmap.len(), packed_entry_size
    );
    let num_entries = packed_mmap.len() / packed_entry_size;
    println!("  {} entries ({:.2} GB), entry_size={} B", num_entries,
        packed_mmap.len() as f64 / 1e9, packed_entry_size);

    // ── 2. Assign entries to PBC groups ─────────────────────────────────
    println!("\n[2] Assigning {} entries to {} PBC groups ({} copies each)...",
        num_entries, K_CHUNK, NUM_HASHES);
    let t_assign = Instant::now();

    let expected_per_group = (num_entries * NUM_HASHES) / K_CHUNK + 1;
    let mut groups: Vec<Vec<u32>> = (0..K_CHUNK)
        .map(|_| Vec::with_capacity(expected_per_group))
        .collect();

    for entry_id in 0..num_entries as u32 {
        let assigned = derive_chunk_groups(entry_id);
        for &b in &assigned {
            groups[b].push(entry_id);
        }
    }

    let group_sizes: Vec<usize> = groups.iter().map(|g| g.len()).collect();
    let max_group = *group_sizes.iter().max().unwrap();
    let min_group = *group_sizes.iter().min().unwrap();
    let avg_group = group_sizes.iter().sum::<usize>() as f64 / K_CHUNK as f64;
    println!("  Done in {:.2?}", t_assign.elapsed());
    println!("  Group sizes: min={}, max={}, avg={:.0}", min_group, max_group, avg_group);

    // ── 3. Build cuckoo tables per group ────────────────────────────────
    // Uniform bins_per_table from max group size
    let bins_per_table = (max_group as f64 / CUCKOO_LOAD_FACTOR).ceil() as usize;
    println!("\n[3] Building cuckoo tables ({}-hash, bs=1, bins_per_table={})...",
        CUCKOO_NUM_HASHES, bins_per_table);
    let t_cuckoo = Instant::now();

    let mut all_cuckoo_tables: Vec<Vec<u32>> = Vec::with_capacity(K_CHUNK);
    for (group_id, group) in groups.iter().enumerate().take(K_CHUNK) {
        // Sort entries for deterministic insertion
        let mut entries = group.clone();
        entries.sort_unstable();

        let mut keys = [0u64; CUCKOO_NUM_HASHES];
        for (h, key) in keys.iter_mut().enumerate().take(CUCKOO_NUM_HASHES) {
            *key = derive_cuckoo_key(group_id, h);
        }

        let table = build_cuckoo_bs1(&entries, &keys, bins_per_table);

        let occupied = table.iter().filter(|&&x| x != EMPTY).count();
        if group_id % 20 == 0 || group_id + 1 == K_CHUNK {
            eprintln!("  Group {}/{}: {} entries, {} bins, {:.2}% fill",
                group_id + 1, K_CHUNK, entries.len(), bins_per_table,
                occupied as f64 / bins_per_table as f64 * 100.0);
        }

        all_cuckoo_tables.push(table);
    }
    println!("  Cuckoo tables built in {:.2?}", t_cuckoo.elapsed());

    // ── 4. Save cuckoo tables to disk ───────────────────────────────────
    println!("\n[4] Saving cuckoo tables to {}...", cuckoo_file);
    {
        let cuckoo_out = File::create(&cuckoo_file).expect("create cuckoo file");
        let mut writer = BufWriter::with_capacity(1024 * 1024, cuckoo_out);

        // Header (Phase C2 v2): legacy magic XOR'd with snapshot/delta marker
        // when a chain anchor is loaded, then anchor bytes (36 snapshot /
        // 72 delta) appended after the 40-byte legacy header section.
        // Without --anchor, emits byte-identical legacy format.
        const ONION_CHUNK_MAGIC: u64 = 0xBA7C_0010_0000_0001;
        let anchor = chunk_anchor();
        let magic = onion_chunk_magic_with_anchor(ONION_CHUNK_MAGIC, anchor);
        writer.write_all(&magic.to_le_bytes()).unwrap();
        writer.write_all(&(K_CHUNK as u32).to_le_bytes()).unwrap();
        writer.write_all(&(CUCKOO_NUM_HASHES as u32).to_le_bytes()).unwrap();
        writer.write_all(&(bins_per_table as u32).to_le_bytes()).unwrap();
        writer.write_all(&chunk_master_seed().to_le_bytes()).unwrap();
        writer.write_all(&(num_entries as u32).to_le_bytes()).unwrap();
        // Padding to 40 bytes for alignment
        writer.write_all(&[0u8; 4]).unwrap();
        // v2 anchor extension (Phase C2): 36 or 72 trailing bytes.
        if let Some(a) = anchor {
            match a {
                HeaderAnchor::Snapshot(c) => writer.write_all(&c.to_bytes()).unwrap(),
                HeaderAnchor::Delta(d) => writer.write_all(&d.to_bytes()).unwrap(),
            }
        }

        // Body: K_CHUNK tables, each bins_per_table × u32
        for table in &all_cuckoo_tables {
            for &entry_id in table {
                writer.write_all(&entry_id.to_le_bytes()).unwrap();
            }
        }
        writer.flush().unwrap();
    }

    let cuckoo_file_size = 40 + K_CHUNK * bins_per_table * 4;
    println!("  Cuckoo file: {} (header 40B + {} groups × {} bins × 4B)",
        format_bytes(cuckoo_file_size as u64), K_CHUNK, bins_per_table);

    // ── 5. Compute and write DATA bin hashes (for per-bin Merkle) ──────
    println!("\n[5] Computing DATA bin hashes for per-bin Merkle...");
    let t_hash = Instant::now();
    {
        // OnionPIRv2 port (commit 5b): zero_entry is `packed_entry_size`
        // bytes (was a fixed `[u8; 3840]` array pre-port).
        let zero_entry = vec![0u8; packed_entry_size];
        let total_bins = K_CHUNK * bins_per_table;
        let mut bin_hashes = Vec::with_capacity(total_bins * 32);

        for (group_id, table) in all_cuckoo_tables.iter().enumerate().take(K_CHUNK) {
            for &entry_id in table.iter().take(bins_per_table) {
                let bin_bytes: &[u8] = if entry_id == EMPTY {
                    &zero_entry
                } else {
                    let off = entry_id as usize * packed_entry_size;
                    &packed_mmap[off..off + packed_entry_size]
                };
                let hash = pir_core::merkle::sha256(bin_bytes);
                bin_hashes.extend_from_slice(&hash);
            }
            if group_id % 10 == 0 || group_id + 1 == K_CHUNK {
                eprint!("\r  Hashing group {}/{}", group_id + 1, K_CHUNK);
            }
        }
        eprintln!();

        // Header: [4B K_CHUNK][4B bins_per_table]
        let f = File::create(&bin_hashes_file).expect("create bin hashes file");
        let mut w = BufWriter::new(f);
        w.write_all(&(K_CHUNK as u32).to_le_bytes()).unwrap();
        w.write_all(&(bins_per_table as u32).to_le_bytes()).unwrap();
        w.write_all(&bin_hashes).unwrap();
        w.flush().unwrap();
        println!("  Wrote {} bin hashes ({} bytes) to {} in {:.2?}",
            total_bins, 8 + total_bins * 32, bin_hashes_file, t_hash.elapsed());
    }

    // ── 6. Build per-group dense OnionPIR databases ─────────────────────
    //
    // Mirrors gen_3_onion step 4: each PBC group becomes one dense
    // OnionPIR preprocessed DB. CHUNK cuckoo is bs=1, so each cuckoo bin
    // holds exactly one packed entry (or zeros for an empty bin) — there
    // is no INDEX-style `serialize_cuckoo_bin` slot-packing. We feed the
    // bin's packed bytes straight into one OnionPIR plaintext.
    println!("\n[6] Building per-group dense OnionPIR databases (push_plaintexts → save_db)...");
    fs::create_dir_all(&chunk_pir_dir).expect("create scratch dir");

    let t_pir = Instant::now();
    let p = onionpir::params_info(bins_per_table as u64);
    let padded_num = p.num_entries as usize;
    let entry_size = p.entry_size as usize;
    let fst_dim = p.fst_dim_sz as usize;
    let other_dim = p.other_dim_sz as usize;
    let poly_degree = p.poly_degree as usize;

    println!("  OnionPIR params: padded={}, entry_size={}, fst_dim={}, other_dim={}",
        padded_num, entry_size, fst_dim, other_dim);
    println!("  Physical size per group: {:.2} MB", p.physical_size_mb);
    println!("  Total for {} groups: {:.2} GB", K_CHUNK, p.physical_size_mb * K_CHUNK as f64 / 1024.0);

    // The gen_2_onion shared-store path relies on
    // `params_info.entry_size == packed_entry_size`; keep that assert.
    assert_eq!(
        entry_size, packed_entry_size,
        "params_info.entry_size ({}) != packed_entry_size ({}); a stale \
         packed.bin produced by a different onionpir rev is being read",
        entry_size, packed_entry_size
    );

    // Process groups sequentially (OnionPIR Server is not Send).
    for (group_id, table) in all_cuckoo_tables.iter().enumerate().take(K_CHUNK) {
        let preproc_path = chunk_pir_dir.join(format!("group_{}.bin", group_id));
        let t_group = Instant::now();

        let mut server = PirServer::new(bins_per_table as u64);

        // Populate: each cuckoo bin → one OnionPIR plaintext (N pre-NTT
        // coefficients packed from the bin's single packed entry, or
        // zeros for an empty bin).
        for chunk_idx in 0..other_dim {
            let mut batch_coeffs: Vec<u64> = Vec::with_capacity(fst_dim * poly_degree);
            for i in 0..fst_dim {
                let global_bin = chunk_idx * fst_dim + i;
                let entry_bytes: Vec<u8> = if global_bin < bins_per_table
                    && table[global_bin] != EMPTY
                {
                    let entry_id = table[global_bin] as usize;
                    let off = entry_id * packed_entry_size;
                    packed_mmap[off..off + packed_entry_size].to_vec()
                } else {
                    vec![0u8; entry_size]
                };
                let coeffs = pir_core::onion_unpack::pack_bytes_into_coefficients(
                    &entry_bytes,
                    entry_size,
                    poly_degree,
                );
                batch_coeffs.extend_from_slice(&coeffs);
            }
            let plaintext_offset = (chunk_idx * fst_dim) as u64;
            let ok = server.push_plaintexts(
                &batch_coeffs,
                fst_dim as u64,
                plaintext_offset,
                &[],
            );
            assert!(
                ok,
                "push_plaintexts failed (group={} chunk_idx={} offset={})",
                group_id, chunk_idx, plaintext_offset
            );
        }

        assert!(
            server.save_db(preproc_path.to_str().unwrap()),
            "save_db failed for group {} → {:?}",
            group_id,
            preproc_path
        );

        if group_id % 10 == 0 || group_id + 1 == K_CHUNK {
            eprintln!("  Group {}/{} preprocessed in {:.2?}", group_id + 1, K_CHUNK, t_group.elapsed());
        }
    }
    println!("  All groups built in {:.2?}", t_pir.elapsed());

    // ── 7. Verify with test query against group 0 ──────────────────────
    println!("\n[7] Verification: test query against group 0 dense DB...");

    // Pick group 0, find a real entry in its cuckoo table
    let test_group = 0;
    let test_table = &all_cuckoo_tables[test_group];
    let test_bin = test_table.iter().position(|&x| x != EMPTY).expect("no entries in group 0");
    let test_entry_id = test_table[test_bin];
    println!("  Test: group={}, bin={}, entry_id={}", test_group, test_bin, test_entry_id);

    // Load the preprocessed dense database and query
    let preproc_path = chunk_pir_dir.join("group_0.bin");
    let mut server = PirServer::new(bins_per_table as u64);
    assert!(server.load_db(preproc_path.to_str().unwrap()), "failed to load group_0.bin");

    let client = PirClient::new(bins_per_table as u64);
    let client_id = client.id();
    server.set_galois_keys(client_id, &client.galois_keys());
    server.set_gsw_key(client_id, &client.gsw_key());

    let query = client.generate_query(test_bin as u64);
    let response = server.answer_query(client_id, &query);
    // OnionPIRv2 port (commit 2): bit-unpack the raw plaintext returned
    // by `decrypt_response`. `decrypted.len()` is now `params.entry_size`.
    let _ = test_bin;
    let raw_pt = client.decrypt_response(&response);
    let pinfo = onionpir::params_info(bins_per_table as u64);
    let decrypted = pir_core::onion_unpack::unpack_onion_plaintext(
        &raw_pt,
        pinfo.poly_degree as usize,
        pinfo.entry_size as usize,
    )
    .expect("onion_unpack rejected gen_2_onion_dense plaintext");

    // Compare with original packed entry — direct byte-for-byte equality
    // (no truncation, since decrypted.len() == packed_entry_size).
    let expected = &packed_mmap[test_entry_id as usize * packed_entry_size
        ..(test_entry_id as usize + 1) * packed_entry_size];

    if decrypted.len() == packed_entry_size && decrypted[..] == *expected {
        println!("  Verification: PASS (decrypted matches original entry)");
    } else if decrypted.len() >= 8 && decrypted[..8] == expected[..8] {
        println!("  Verification: PASS (first 8 bytes match)");
    } else {
        println!("  Verification: FAIL!");
        println!("  Expected first 16B: {:?}", &expected[..16]);
        println!("  Got first 16B:      {:?}", &decrypted[..16.min(decrypted.len())]);
    }

    // ── 8. Consolidate per-group files into one onion_chunk_all.bin ─────
    //
    // Layout: [master header: 32B][group_0: per_group_bytes][group_1: ...]
    //         ... [group_{K_CHUNK-1}: per_group_bytes]
    // The 32-byte master header is [ONION_CHUNK_ALL_MAGIC u64 | K_CHUNK u64 |
    // per_group_bytes u64 | reserved u64]. Each group payload is whatever
    // OnionPIR's save_db produced — server-side mmaps the whole file once
    // and passes a per-group slice to load_db_from_bytes().
    println!("\n[8] Consolidating {} per-group files into {}...", K_CHUNK, chunk_all_file);
    let t_consolidate = Instant::now();
    {
        // All groups have identical size because they share params.
        // Read the first group's size and assert the rest match.
        let first_path = chunk_pir_dir.join("group_0.bin");
        let per_group_bytes = fs::metadata(&first_path)
            .expect("stat group_0.bin")
            .len() as usize;
        println!("  Per-group bytes: {} ({})", per_group_bytes, format_bytes(per_group_bytes as u64));

        let total_bytes = ONION_CHUNK_ALL_HEADER_BYTES + K_CHUNK * per_group_bytes;
        println!("  Total output:    {} ({})", total_bytes, format_bytes(total_bytes as u64));

        let out = File::create(&chunk_all_file).expect("create onion_chunk_all.bin");
        let mut w = BufWriter::with_capacity(16 * 1024 * 1024, out);

        // Master header (32 bytes)
        w.write_all(&ONION_CHUNK_ALL_MAGIC.to_le_bytes()).unwrap();
        w.write_all(&(K_CHUNK as u64).to_le_bytes()).unwrap();
        w.write_all(&(per_group_bytes as u64).to_le_bytes()).unwrap();
        w.write_all(&0u64.to_le_bytes()).unwrap();

        // Append each group's preprocessed bytes in order.
        let mut written: u64 = 0;
        for b in 0..K_CHUNK {
            let path = chunk_pir_dir.join(format!("group_{}.bin", b));
            let meta = fs::metadata(&path).expect("stat group file");
            assert_eq!(
                meta.len() as usize,
                per_group_bytes,
                "group_{}.bin size mismatch: expected {}, got {}",
                b, per_group_bytes, meta.len()
            );
            let bytes = fs::read(&path).expect("read group file");
            w.write_all(&bytes).unwrap();
            written += bytes.len() as u64;
            if b % 10 == 0 || b + 1 == K_CHUNK {
                eprint!("\r  Appending group {}/{}", b + 1, K_CHUNK);
                let _ = io::stderr().flush();
            }
        }
        eprintln!();
        w.flush().unwrap();
        drop(w);

        let actual_size = fs::metadata(&chunk_all_file).expect("stat output").len() as usize;
        assert_eq!(
            actual_size, total_bytes,
            "onion_chunk_all.bin size mismatch: expected {}, got {}",
            total_bytes, actual_size
        );

        // Clean up the scratch per-group directory (mirror gen_3_onion).
        println!("  Wrote {} bytes; removing scratch dir {}", written, chunk_pir_dir.display());
        fs::remove_dir_all(&chunk_pir_dir).expect("remove per-group dir");
    }
    println!("  Consolidated in {:.2?}", t_consolidate.elapsed());

    // ── Summary ─────────────────────────────────────────────────────────
    println!("\n=== Summary ===");
    println!("Packed entries:    {} ({:.2} GB)", num_entries, packed_mmap.len() as f64 / 1e9);
    println!("PBC groups:        {}", K_CHUNK);
    println!("Bins per table:    {} (bs=1, {} B/bin)", bins_per_table, entry_size);
    println!("OnionPIR per group: {:.2} MB (NTT-expanded)", p.physical_size_mb);
    println!("Total NTT storage: {:.2} GB", p.physical_size_mb * K_CHUNK as f64 / 1024.0);
    println!("Cuckoo tables:     {} groups × {} bins = {}",
        K_CHUNK, bins_per_table, format_bytes(cuckoo_file_size as u64));
    println!("Total time:        {:.2?}", total_start.elapsed());
}
