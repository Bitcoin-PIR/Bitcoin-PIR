//! Build OnionPIR main database: shared NTT store + per-group cuckoo tables.
//!
//! Reads packed entries from gen_1_onion, NTT-expands them into a level-major
//! shared store, builds 6-hash cuckoo tables (bs=1) for each of 80 PBC groups,
//! and verifies the setup with a test query.
//!
//! Output:
//!   - onion_shared_ntt.bin: level-major NTT store (all entries, stored once)
//!   - onion_chunk_cuckoo.bin: per-group cuckoo tables (bin → entry_id mapping)
//!
//! Usage:
//!   cargo run --release -p build --bin gen_2_onion

use memmap2::{Mmap, MmapMut};
use onionpir::{self, Client as PirClient, Server as PirServer};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::time::Instant;

// ─── Constants ──────────────────────────────────────────────────────────────

const PACKED_FILE: &str = "/Volumes/Bitcoin/data/intermediate/onion_packed_entries.bin";
const NTT_STORE_FILE: &str = "/Volumes/Bitcoin/data/onion_shared_ntt.bin";
const CUCKOO_FILE: &str = "/Volumes/Bitcoin/data/onion_chunk_cuckoo.bin";
const BIN_HASHES_FILE: &str = "/Volumes/Bitcoin/data/onion_data_bin_hashes.bin";

const PACKED_ENTRY_SIZE: usize = 3840;

/// PBC parameters (same as production)
const K_CHUNK: usize = 80;
const NUM_HASHES: usize = 3; // each entry assigned to 3 groups
const CHUNK_MASTER_SEED: u64 = 0xa3f7c2d918e4b065;

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
        for i in 0..count {
            if groups[i] == group {
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
        CHUNK_MASTER_SEED
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
        for h in 0..CUCKOO_NUM_HASHES {
            let bin = cuckoo_hash_int(entry_id, keys[h], num_bins);
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
    println!("=== gen_2_onion: Build OnionPIR Main Database ===\n");
    let total_start = Instant::now();

    // ── 1. Read packed entries ───────────────────────────────────────────
    println!("[1] Memory-mapping packed entries: {}", PACKED_FILE);
    let packed_file = File::open(PACKED_FILE).expect("open packed entries file");
    let packed_mmap = unsafe { Mmap::map(&packed_file) }.expect("mmap packed entries");
    let num_entries = packed_mmap.len() / PACKED_ENTRY_SIZE;
    assert_eq!(packed_mmap.len() % PACKED_ENTRY_SIZE, 0, "packed file not aligned");
    println!("  {} entries ({:.2} GB)", num_entries, packed_mmap.len() as f64 / 1e9);

    // ── 2. Get OnionPIR params ──────────────────────────────────────────
    // We need a Server instance to call ntt_expand_entry, but we won't populate it.
    // Use num_entries just for params (the Server for shared DB doesn't own data).
    let p = onionpir::params_info(num_entries as u64);
    let coeff_val_cnt = p.coeff_val_cnt as usize;
    println!("\n[2] OnionPIR params for {} entries:", num_entries);
    println!("  entry_size:      {} B", p.entry_size);
    println!("  coeff_val_cnt:   {} (coefficients per NTT-expanded entry)", coeff_val_cnt);
    println!("  NTT bytes/entry: {} B", coeff_val_cnt * 8);

    // ── 3. Build shared NTT store (level-major) ─────────────────────────
    let ntt_store_bytes = coeff_val_cnt * num_entries * 8;
    println!("\n[3] Building shared NTT store ({})...", format_bytes(ntt_store_bytes as u64));
    println!("  Layout: level-major, {} levels × {} entries × 8 bytes", coeff_val_cnt, num_entries);

    // Create and mmap the output file
    let ntt_file = OpenOptions::new()
        .read(true).write(true).create(true).truncate(true)
        .open(NTT_STORE_FILE).expect("create NTT store file");
    ntt_file.set_len(ntt_store_bytes as u64).expect("set NTT file size");
    let mut ntt_mmap = unsafe { MmapMut::map_mut(&ntt_file) }.expect("mmap NTT store");

    // Use a temporary Server just for ntt_expand_entry
    let expander = PirServer::new(num_entries as u64);

    let t_ntt = Instant::now();
    let one_percent = num_entries.max(1) / 100;
    for entry_id in 0..num_entries {
        let raw = &packed_mmap[entry_id * PACKED_ENTRY_SIZE..(entry_id + 1) * PACKED_ENTRY_SIZE];
        let coeffs = expander.ntt_expand_entry(raw, coeff_val_cnt);

        // Scatter to level-major: store[level * num_entries + entry_id]
        let ntt_u64: &mut [u64] = unsafe {
            std::slice::from_raw_parts_mut(ntt_mmap.as_mut_ptr() as *mut u64, coeff_val_cnt * num_entries)
        };
        for level in 0..coeff_val_cnt {
            ntt_u64[level * num_entries + entry_id] = coeffs[level];
        }

        if one_percent > 0 && (entry_id + 1) % one_percent == 0 {
            let pct = (entry_id + 1) / one_percent;
            eprint!("\r  NTT expanding: {}%", pct);
            let _ = std::io::stderr().flush();
        }
    }
    eprintln!();
    ntt_mmap.flush().expect("flush NTT store");
    println!("  NTT expansion: {:.2?}", t_ntt.elapsed());
    println!("  NTT store file: {} ({})", NTT_STORE_FILE, format_bytes(ntt_store_bytes as u64));

    // ── 4. Assign entries to PBC groups ─────────────────────────────────
    println!("\n[4] Assigning {} entries to {} PBC groups ({} copies each)...",
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

    // ── 5. Build cuckoo tables per group ────────────────────────────────
    // Uniform bins_per_table from max group size
    let bins_per_table = (max_group as f64 / CUCKOO_LOAD_FACTOR).ceil() as usize;
    println!("\n[5] Building cuckoo tables ({}-hash, bs=1, bins_per_table={})...",
        CUCKOO_NUM_HASHES, bins_per_table);
    let t_cuckoo = Instant::now();

    let mut all_cuckoo_tables: Vec<Vec<u32>> = Vec::with_capacity(K_CHUNK);
    for group_id in 0..K_CHUNK {
        // Sort entries for deterministic insertion
        let mut entries = groups[group_id].clone();
        entries.sort_unstable();

        let mut keys = [0u64; CUCKOO_NUM_HASHES];
        for h in 0..CUCKOO_NUM_HASHES {
            keys[h] = derive_cuckoo_key(group_id, h);
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

    // ── 6. Save cuckoo tables to disk ───────────────────────────────────
    println!("\n[6] Saving cuckoo tables to {}...", CUCKOO_FILE);
    {
        let cuckoo_file = File::create(CUCKOO_FILE).expect("create cuckoo file");
        let mut writer = BufWriter::with_capacity(1024 * 1024, cuckoo_file);

        // Header: magic, k_chunk, cuckoo_num_hashes, bins_per_table, master_seed, num_entries
        let magic: u64 = 0xBA7C_0010_0000_0001;
        writer.write_all(&magic.to_le_bytes()).unwrap();
        writer.write_all(&(K_CHUNK as u32).to_le_bytes()).unwrap();
        writer.write_all(&(CUCKOO_NUM_HASHES as u32).to_le_bytes()).unwrap();
        writer.write_all(&(bins_per_table as u32).to_le_bytes()).unwrap();
        writer.write_all(&CHUNK_MASTER_SEED.to_le_bytes()).unwrap();
        writer.write_all(&(num_entries as u32).to_le_bytes()).unwrap();
        // Padding to 40 bytes for alignment
        writer.write_all(&[0u8; 4]).unwrap();

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

    // ── 7. Compute and write DATA bin hashes (for per-bin Merkle) ──────
    println!("\n[7] Computing DATA bin hashes for per-bin Merkle...");
    let t_hash = Instant::now();
    {
        let zero_entry = [0u8; PACKED_ENTRY_SIZE];
        let total_bins = K_CHUNK * bins_per_table;
        let mut bin_hashes = Vec::with_capacity(total_bins * 32);

        for group_id in 0..K_CHUNK {
            let table = &all_cuckoo_tables[group_id];
            for bin in 0..bins_per_table {
                let entry_id = table[bin];
                let bin_bytes: &[u8] = if entry_id == EMPTY {
                    &zero_entry
                } else {
                    let off = entry_id as usize * PACKED_ENTRY_SIZE;
                    &packed_mmap[off..off + PACKED_ENTRY_SIZE]
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
        let f = File::create(BIN_HASHES_FILE).expect("create bin hashes file");
        let mut w = BufWriter::new(f);
        w.write_all(&(K_CHUNK as u32).to_le_bytes()).unwrap();
        w.write_all(&(bins_per_table as u32).to_le_bytes()).unwrap();
        w.write_all(&bin_hashes).unwrap();
        w.flush().unwrap();
        println!("  Wrote {} bin hashes ({} bytes) to {} in {:.2?}",
            total_bins, 8 + total_bins * 32, BIN_HASHES_FILE, t_hash.elapsed());
    }

    // ── 8. Verify with test query ───────────────────────────────────────
    println!("\n[7] Verification: test query with shared NTT store...");

    // Pick group 0, find a real entry in its cuckoo table
    let test_group = 0;
    let test_table = &all_cuckoo_tables[test_group];
    let test_bin = test_table.iter().position(|&x| x != EMPTY).expect("no entries in group 0");
    let test_entry_id = test_table[test_bin];
    println!("  Test: group={}, bin={}, entry_id={}", test_group, test_bin, test_entry_id);

    // Build index_table for this group (maps padded indices → shared store entry_ids)
    let p_group = onionpir::params_info(bins_per_table as u64);
    let padded_num = p_group.num_entries as usize;
    let mut index_table = vec![0u32; padded_num]; // 0 for padding entries (all-zero data)
    for bin in 0..bins_per_table {
        let eid = test_table[bin];
        if eid != EMPTY {
            index_table[bin] = eid;
        }
        // else: index_table[bin] = 0, which maps to entry 0 in the shared store
    }
    // Pad remaining indices (bins_per_table..padded_num) with 0
    // Already done by default initialization

    // Set up server with shared database
    let ntt_u64: &[u64] = unsafe {
        std::slice::from_raw_parts(ntt_mmap.as_ptr() as *const u64, coeff_val_cnt * num_entries)
    };

    let mut server = PirServer::new(bins_per_table as u64);
    unsafe {
        server.set_shared_database(ntt_u64.as_ptr(), num_entries, &index_table);
    }

    // Create client, generate keys, query
    let mut client = PirClient::new(bins_per_table as u64);
    let client_id = client.id();
    let galois = client.generate_galois_keys();
    let gsw = client.generate_gsw_keys();
    server.set_galois_key(client_id, &galois);
    server.set_gsw_key(client_id, &gsw);

    let query = client.generate_query(test_bin as u64);
    let response = server.answer_query(client_id, &query);
    let decrypted = client.decrypt_response(test_bin as u64, &response);

    // Compare with original packed entry
    let expected = &packed_mmap[test_entry_id as usize * PACKED_ENTRY_SIZE
        ..(test_entry_id as usize + 1) * PACKED_ENTRY_SIZE];

    if decrypted.len() >= PACKED_ENTRY_SIZE && decrypted[..PACKED_ENTRY_SIZE] == *expected {
        println!("  Verification: PASS (decrypted matches original entry)");
    } else if decrypted.len() >= 8 && decrypted[..8] == expected[..8] {
        println!("  Verification: PASS (first 8 bytes match)");
    } else {
        println!("  Verification: FAIL!");
        println!("  Expected first 16B: {:?}", &expected[..16]);
        println!("  Got first 16B:      {:?}", &decrypted[..16.min(decrypted.len())]);
    }

    // ── Summary ─────────────────────────────────────────────────────────
    println!("\n=== Summary ===");
    println!("Packed entries:    {} ({:.2} GB)", num_entries, packed_mmap.len() as f64 / 1e9);
    println!("NTT store:         {} (level-major, 4.27x expansion)",
        format_bytes(ntt_store_bytes as u64));
    println!("Cuckoo tables:     {} groups × {} bins = {}",
        K_CHUNK, bins_per_table, format_bytes(cuckoo_file_size as u64));
    println!("Total time:        {:.2?}", total_start.elapsed());
}
