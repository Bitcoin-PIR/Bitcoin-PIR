//! HarmonyPIR end-to-end test with verbose debug logging.
//!
//! Builds a synthetic database, computes hints, writes a state file,
//! reloads it, makes queries with full algorithm trace, saves again,
//! reloads, makes more queries, and verifies correctness.
//!
//! Usage:
//!   cargo run --release -p runtime --bin harmonypir_e2e_test

use harmonypir::params::{Params, BETA};
use harmonypir::prp::hoang::HoangPrp;
use harmonypir::prp::Prp;
use harmonypir::relocation::{RelocationDS, EMPTY};
use harmonypir_wasm::state::{self, BucketEntry, StateFileHeader};
use harmonypir_wasm::{
    HarmonyBucket, PRP_HOANG, PRP_FASTPRP, PRP_ALF,
    compute_rounds, derive_bucket_key, find_best_t, pad_n_for_t,
    verify_protocol_impl,
};

use std::io::Cursor;
use std::time::Instant;

const DEBUG: bool = true;

fn hex(bytes: &[u8]) -> String {
    if bytes.len() <= 16 {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    } else {
        let head: String = bytes[..8].iter().map(|b| format!("{:02x}", b)).collect();
        let tail: String = bytes[bytes.len()-4..].iter().map(|b| format!("{:02x}", b)).collect();
        format!("{}...{} ({} bytes)", head, tail, bytes.len())
    }
}

fn main() {
    println!("=== HarmonyPIR End-to-End Test (verbose) ===\n");

    let n: u32 = 256;
    let w: u32 = 42;
    let num_buckets: u32 = 2;
    let key = [0x42u8; 16];
    let backend_name = "Hoang PRP";

    let t_raw = find_best_t(n);
    let (padded_n, t_val) = pad_n_for_t(n, t_raw);
    let pn = padded_n as usize;
    let n_usize = n as usize;
    let w_usize = w as usize;
    let t_usize = t_val as usize;
    let t = t_val;
    let domain = 2 * pn;
    let r = compute_rounds(padded_n);

    let params = Params::new(pn, w_usize, t_usize).unwrap();
    let m = params.m;

    println!("[CONFIG]");
    println!("  PRP backend:  {} (PRP_HOANG=0)", backend_name);
    println!("  real_N:       {}", n);
    println!("  padded_N:     {} (+{} virtual rows)", pn, pn - n_usize);
    println!("  w (entry sz): {} bytes", w);
    println!("  T (seg size): {}", t);
    println!("  M (segments): {} = 2*padded_N/T = {}/{}", m, domain, t);
    println!("  max_queries:  {} = padded_N/T", params.max_queries);
    println!("  domain:       {} = 2*padded_N", domain);
    println!("  PRP rounds:   {} = ceil(log2({})) + 40, rounded to mult of {}", r, domain, BETA);
    println!("  master key:   {}", hex(&key));
    println!();

    // ─── Build test database ────────────────────────────────────────────
    println!("[1] Building test database: {} entries × {} bytes", n, w);
    let db: Vec<Vec<u8>> = (0..n_usize)
        .map(|i| {
            let mut entry = vec![0u8; w_usize];
            let bytes = (i as u64).to_le_bytes();
            entry[..bytes.len().min(w_usize)].copy_from_slice(&bytes[..bytes.len().min(w_usize)]);
            if w_usize > 8 { entry[8] = (i * 37) as u8; }
            entry
        })
        .collect();
    if DEBUG {
        println!("  DB[0]   = {}", hex(&db[0]));
        println!("  DB[1]   = {}", hex(&db[1]));
        println!("  DB[128] = {}", hex(&db[128]));
        println!("  DB[255] = {}", hex(&db[255]));
    }
    println!();

    // ─── Compute hints (Hint Server simulation) ─────────────────────────
    println!("[2] Computing hints for bucket 0 (Hint Server simulation)...");
    let t_start = Instant::now();

    let derived_key_0 = derive_bucket_key(&key, 0);
    if DEBUG {
        println!("  derived_key[bucket=0] = {}", hex(&derived_key_0));
    }

    let prp0: Box<dyn Prp> = Box::new(HoangPrp::new(domain, r, &derived_key_0));

    if DEBUG {
        println!("  PRP forward samples:");
        for x in [0, 1, 2, n_usize - 1, n_usize, domain - 1] {
            println!("    P({}) = {}", x, prp0.forward(x));
        }
        println!("  PRP inverse samples:");
        for y in [0, 1, 2] {
            println!("    P^{{-1}}({}) = {}", y, prp0.inverse(y));
        }
    }

    let ds0 = RelocationDS::new(pn, t_usize, prp0).unwrap();

    if DEBUG {
        println!("\n  DS' initial layout (first 8 values → cells → segments):");
        for v in 0..8.min(n_usize) {
            let cell = ds0.locate(v).unwrap();
            let seg = cell / t_usize;
            let pos = cell % t_usize;
            println!("    value {} → cell {} (segment {}, position {})", v, cell, seg, pos);
        }
        println!("    ...");
        for v in [n_usize / 2, n_usize - 1] {
            let cell = ds0.locate(v).unwrap();
            let seg = cell / t_usize;
            let pos = cell % t_usize;
            println!("    value {} → cell {} (segment {}, position {})", v, cell, seg, pos);
        }
    }

    // Compute hint parities: H[s] = XOR of DB[v] for all v in segment s.
    // Iterate over padded_n (real + virtual). Virtual rows (>= n) are zeros.
    let mut hints0: Vec<Vec<u8>> = (0..m).map(|_| vec![0u8; w_usize]).collect();
    let mut entries_per_seg: Vec<usize> = vec![0; m];
    for k in 0..pn {
        let cell = ds0.locate(k).unwrap();
        let seg = cell / t_usize;
        entries_per_seg[seg] += 1;
        if k < n_usize {
            for (d, s) in hints0[seg].iter_mut().zip(db[k].iter()) {
                *d ^= s;
            }
        }
    }

    if DEBUG {
        println!("\n  Hint parities (XOR of DB entries per segment):");
        for s in 0..4.min(m) {
            println!("    H[{}] = {} ({} entries XOR'd in)", s, hex(&hints0[s]), entries_per_seg[s]);
        }
        println!("    ... ({} total segments)", m);
    }
    println!("  Hints computed in {:.2?}\n", t_start.elapsed());

    // Also compute hints for bucket 1.
    let derived_key_1 = derive_bucket_key(&key, 1);
    let prp1: Box<dyn Prp> = Box::new(HoangPrp::new(domain, r, &derived_key_1));
    let ds1 = RelocationDS::new(pn, t_usize, prp1).unwrap();
    let mut hints1: Vec<Vec<u8>> = (0..m).map(|_| vec![0u8; w_usize]).collect();
    for k in 0..pn {
        let cell = ds1.locate(k).unwrap();
        let seg = cell / t_usize;
        if k < n_usize {
            for (d, s) in hints1[seg].iter_mut().zip(db[k].iter()) { *d ^= s; }
        }
    }

    // ─── Create buckets and serialize ───────────────────────────────────
    println!("[3] Creating HarmonyBucket instances and writing state file...");
    let mut bucket0 = HarmonyBucket::new_with_backend(n, w, t, &key, 0, PRP_HOANG).unwrap();
    let flat0: Vec<u8> = hints0.iter().flat_map(|h| h.iter().copied()).collect();
    bucket0.load_hints(&flat0).unwrap();

    let mut bucket1 = HarmonyBucket::new_with_backend(n, w, t, &key, 1, PRP_HOANG).unwrap();
    let flat1: Vec<u8> = hints1.iter().flat_map(|h| h.iter().copied()).collect();
    bucket1.load_hints(&flat1).unwrap();

    let header = StateFileHeader {
        prp_backend: PRP_HOANG,
        prp_key: key,
        index_bins_per_table: n,
        chunk_bins_per_table: n,
        tag_seed: 0xDEAD_BEEF,
    };

    let entries = vec![
        BucketEntry { bucket_id: 0, level: 0, data: bucket0.serialize() },
        BucketEntry { bucket_id: 1, level: 0, data: bucket1.serialize() },
    ];
    let mut file_buf: Vec<u8> = Vec::new();
    state::write_state_file(&mut file_buf, &header, &entries).unwrap();
    println!("  State file: {} bytes\n", file_buf.len());

    // ─── Reload from file ───────────────────────────────────────────────
    println!("[4] Loading state file and reconstructing buckets...");
    let state = state::read_state_file(&mut Cursor::new(&file_buf)).unwrap();
    let mut buckets: Vec<HarmonyBucket> = state.buckets.iter()
        .map(|e| HarmonyBucket::deserialize(&e.data, &key, e.bucket_id).unwrap())
        .collect();
    println!("  Loaded {} buckets, {} queries remaining each\n",
        buckets.len(), buckets[0].queries_remaining());

    // ─── Phase 1: queries with verbose trace ────────────────────────────
    let queries = [0usize, 1, 128, 255];
    println!("[5] Phase 1: querying {:?} with verbose trace...\n", queries);

    // We also need a standalone DS' for tracing (since HarmonyBucket's DS is private).
    let prp_trace: Box<dyn Prp> = Box::new(HoangPrp::new(domain, r, &derived_key_0));
    let mut ds_trace = RelocationDS::new(pn, t_usize, prp_trace).unwrap();

    for &q in &queries {
        println!("  ──── Query q={} ────", q);
        println!("    DB[{}] = {}", q, hex(&db[q]));

        // Step 1: Locate q.
        let c = ds_trace.locate(q).unwrap();
        let s = c / t_usize;
        let r_pos = c % t_usize;
        println!("    Locate({}) = cell {} → segment s={}, position r={}", q, c, s, r_pos);

        // Step 2: Build request Q.
        if DEBUG {
            println!("    Request Q (T={} indices):", t);
            let mut shown = 0;
            for i in 0..t_usize {
                let val = ds_trace.access(s * t_usize + i).unwrap();
                if i == r_pos {
                    println!("      Q[{}] = <random dummy> (r position, hiding query)", i);
                } else if shown < 4 || i == t_usize - 1 {
                    if val == EMPTY {
                        println!("      Q[{}] = Access(cell {}) = EMPTY", i, s * t_usize + i);
                    } else {
                        println!("      Q[{}] = Access(cell {}) = {} (DB index)", i, s * t_usize + i, val);
                    }
                    shown += 1;
                } else if shown == 4 {
                    println!("      ... ({} more positions)", t_usize - 5);
                    shown += 1;
                }
            }
        }

        // Actually execute the query through HarmonyBucket.
        let req = buckets[0].build_request(q as u32).unwrap();
        println!("    HarmonyBucket.build_request({}) → segment={}, position={}", q, req.segment(), req.position());

        // Parse request indices for display.
        let req_bytes = req.request();
        let count = req_bytes.len() / 4;
        if DEBUG {
            println!("    Request: {} sorted non-empty indices (T={}, ~{:.0}% reduction)",
                count, t, (1.0 - count as f64 / t_usize as f64) * 100.0);
            if count > 0 {
                let first_idx = u32::from_le_bytes(req_bytes[0..4].try_into().unwrap());
                let last_idx = u32::from_le_bytes(req_bytes[(count-1)*4..count*4].try_into().unwrap());
                println!("    Indices: [{}..{}] (sorted)", first_idx, last_idx);
            }
        }

        // Simulate Query Server: return entries for each sorted non-empty index.
        let mut response = Vec::with_capacity(count * w_usize);
        for j in 0..count {
            let idx = u32::from_le_bytes(req_bytes[j*4..(j+1)*4].try_into().unwrap());
            if idx as usize >= n_usize {
                response.extend(std::iter::repeat(0u8).take(w_usize));
            } else {
                response.extend_from_slice(&db[idx as usize]);
            }
        }
        println!("    Server response: {} bytes ({} entries × {}B)",
            response.len(), count, w);

        // Process response (XOR with hints to recover answer).
        if DEBUG {
            // Show what the XOR computation looks like.
            // answer = H[s] XOR (all R[i] for i != r)
            println!("    Computing answer:");
            println!("      H[s={}] = {}", req.segment(), hex(&hints0[req.segment() as usize]));
            println!("      answer = H[s] ⊕ Σ(R[i] for i≠r)");
        }

        let result = buckets[0].process_response(&response).unwrap();
        let correct = result == db[q];
        println!("    Answer:   {}", hex(&result));
        println!("    Expected: {}", hex(&db[q]));
        println!("    Correct:  {}", if correct { "YES ✓" } else { "NO ✗" });

        // Show relocation.
        if DEBUG {
            let relocated_count = buckets[0].queries_used();
            println!("    Post-query: RelocateSegment(s={}) done", s);
            println!("    Total relocated segments: {}", relocated_count);
            println!("    Queries remaining: {}", buckets[0].queries_remaining());
        }

        // Keep trace DS in sync.
        ds_trace.relocate_segment(s).unwrap();

        assert!(correct, "Query q={} FAILED!", q);
        println!();
    }

    println!("  Phase 1: all {} queries correct!\n", queries.len());

    // ─── Save and reload ────────────────────────────────────────────────
    println!("[6] Saving state after {} queries...", queries.len());
    let entries2 = vec![
        BucketEntry { bucket_id: 0, level: 0, data: buckets[0].serialize() },
        BucketEntry { bucket_id: 1, level: 0, data: buckets[1].serialize() },
    ];
    let mut file_buf2 = Vec::new();
    state::write_state_file(&mut file_buf2, &header, &entries2).unwrap();
    println!("  State file: {} bytes (delta: +{} bytes from relocated segments)\n",
        file_buf2.len(), file_buf2.len() as i64 - file_buf.len() as i64);

    println!("[7] Reloading state file...");
    let state2 = state::read_state_file(&mut Cursor::new(&file_buf2)).unwrap();
    let mut buckets2: Vec<HarmonyBucket> = state2.buckets.iter()
        .map(|e| HarmonyBucket::deserialize(&e.data, &key, e.bucket_id).unwrap())
        .collect();
    println!("  Bucket 0: {} queries used, {} remaining",
        buckets2[0].queries_used(), buckets2[0].queries_remaining());
    if DEBUG {
        println!("  (DS' reconstructed by replaying {} segment relocations)", queries.len());
    }
    println!();

    // ─── Phase 2: queries after reload ──────────────────────────────────
    let queries2 = [3usize, 100, 64, 254];
    println!("[8] Phase 2: querying {:?} (post-reload)...\n", queries2);

    for &q in &queries2 {
        let result = do_query(&mut buckets2[0], q as u32, &db);
        let correct = result == db[q];
        println!("  query({:>3}) → {} {}", q, hex(&result[..8.min(result.len())]), if correct { "✓" } else { "✗" });
        assert!(correct, "Phase 2: query({}) FAILED!", q);
    }
    println!("\n  Phase 2: all {} queries correct!\n", queries2.len());

    // ─── Cross-bucket test ──────────────────────────────────────────────
    println!("[9] Cross-bucket test: bucket 1, query(42)...");
    let result = do_query(&mut buckets2[1], 42, &db);
    let correct = result == db[42];
    println!("  query(42) → {} {}", hex(&result[..8.min(result.len())]), if correct { "✓" } else { "✗" });
    assert!(correct);

    println!("\n=== PASS: end-to-end test with {} ===", backend_name);
    println!("  Total queries: {} (phase 1) + {} (phase 2) + 1 (cross-bucket) = {}",
        queries.len(), queries2.len(), queries.len() + queries2.len() + 1);
    println!("  Serialize/deserialize round-trip: verified");

    // ═══════════════════════════════════════════════════════════════════
    // Multi-backend verification
    // ═══════════════════════════════════════════════════════════════════
    println!("\n\n=== Multi-PRP Backend Verification ===\n");

    // FastPRP (N=256 is fine — no minimum domain)
    {
        let t0 = Instant::now();
        let ok = verify_protocol_impl(256, 42, PRP_FASTPRP);
        println!("[FastPRP]  N=256, w=42 → {} ({:.2?})", if ok { "PASS ✓" } else { "FAIL ✗" }, t0.elapsed());
        assert!(ok, "FastPRP test failed!");
    }

    // ALF (requires domain >= 65536, so N >= 32768)
    {
        let alf_n: u32 = 33000;
        let t0 = Instant::now();
        let ok = verify_protocol_impl(alf_n, 42, PRP_ALF);
        println!("[ALF]      N={}, w=42 → {} ({:.2?})", alf_n, if ok { "PASS ✓" } else { "FAIL ✗" }, t0.elapsed());
        assert!(ok, "ALF test failed!");
    }

    // Also verify Hoang at larger N to be thorough.
    {
        let t0 = Instant::now();
        let ok = verify_protocol_impl(1024, 42, PRP_HOANG);
        println!("[Hoang]    N=1024, w=42 → {} ({:.2?})", if ok { "PASS ✓" } else { "FAIL ✗" }, t0.elapsed());
        assert!(ok, "Hoang (large N) test failed!");
    }

    println!("\n=== ALL PRP BACKENDS PASS ===");
}

/// Execute a single query with simulated server.
fn do_query(bucket: &mut HarmonyBucket, q: u32, db: &[Vec<u8>]) -> Vec<u8> {
    let req = bucket.build_request(q).unwrap();
    let w = bucket.w() as usize;
    let n = bucket.real_n() as usize;
    let req_bytes = req.request();
    let count = req_bytes.len() / 4;

    let mut response = Vec::with_capacity(count * w);
    for j in 0..count {
        let idx = u32::from_le_bytes(req_bytes[j*4..(j+1)*4].try_into().unwrap());
        if idx as usize >= n {
            response.extend(std::iter::repeat(0u8).take(w));
        } else {
            response.extend_from_slice(&db[idx as usize]);
        }
    }

    bucket.process_response(&response).unwrap()
}
