//! Experiment: does OnionPIR's FHE PIR work on the tiny per-group Merkle
//! "sibling DBs" the per-group redesign needs?
//!
//! Retired PLAN_MERKLE_CODING.md Phase 3 / MERKLE_COLOCATION_REVIEW.md §3.2: the
//! per-group OnionPIR Merkle redesign queries one FHE-PIR "sibling DB"
//! per PBC group. Those DBs are tiny — the INDEX sibling DB is ~99 rows,
//! the CHUNK one ~364 rows — versus the production data DB's 2^16 rows.
//! The human's expectation is that the existing OnionPIR FHE params
//! "just work" at small `n`, only with a smaller query ciphertext. This
//! binary checks that empirically:
//!
//!   1. params_info() sweep — the DB shape (`fst_dim_sz`, `other_dim_sz`,
//!      ndim) the engine computes as `n` shrinks. For small `n`,
//!      `other_dim_sz` collapses to 1 → ndim=1, the degenerate
//!      single-dimension case (no GSW-expanded dimension).
//!   2. full query → answer → decrypt round-trip per target `n` —
//!      correctness check (`decrypt_response` == `get_original_plaintext`).
//!   3. ciphertext sizes — query / response / Galois key / GSW key.
//!
//! `onionpir` (git rev f164451) is plaintext-indexed: `generate_query`
//! takes a plaintext index in `[0, num_plaintexts)`, `gen_data` fills the
//! DB with random data (recording the indices we will verify).
//!
//! Run (defaults to the two sibling-DB sizes, 99 and 364):
//!   cargo run --release -p build --bin experiment_onion_sibling_pir
//! Or pass explicit plaintext counts (0 = the compile-time default DB):
//!   cargo run --release -p build --bin experiment_onion_sibling_pir -- 99 364 0

use onionpir::{params_info, Client, Server};
use std::time::Instant;

fn main() {
    println!("=== OnionPIR small-DB (per-group Merkle sibling) experiment ===\n");

    // ── Phase 1: params_info() sweep — cheap (just the shape math) ──
    println!("--- params_info() sweep: DB shape vs requested n ---");
    println!(
        "{:>8}  {:>10}  {:>10}  {:>9}  {:>8}  {:>10}  {:>11}",
        "req_n", "num_entr", "num_pt", "entry_B", "fst_dim", "other_dim", "db_size_MB",
    );
    for &n in &[16u64, 64, 99, 128, 256, 257, 364, 512, 1024, 4096, 0] {
        let p = params_info(n);
        println!(
            "{:>8}  {:>10}  {:>10}  {:>9}  {:>8}  {:>10}  {:>11.3}",
            n,
            p.num_entries,
            p.num_plaintexts,
            p.entry_size,
            p.fst_dim_sz,
            p.other_dim_sz,
            p.db_size_mb,
        );
    }
    println!(
        "\nnote: other_dim_sz=1 → single-dimension DB (first BFV dimension only,\n\
         no GSW-expanded dimension). The per-group sibling DBs the redesign\n\
         wants are INDEX≈99 plaintexts, CHUNK≈364 plaintexts.\n"
    );

    // ── Phase 2: full round-trip per target n ──
    let targets: Vec<u64> = {
        let args: Vec<u64> = std::env::args().skip(1).filter_map(|a| a.parse().ok()).collect();
        if args.is_empty() {
            vec![99, 364]
        } else {
            args
        }
    };

    let mut summary: Vec<(u64, bool, String)> = Vec::new();
    for &n in &targets {
        println!("\n========== round-trip: requested n = {} ==========", n);
        match std::panic::catch_unwind(|| run_round_trip(n)) {
            Ok(Ok(line)) => summary.push((n, true, line)),
            Ok(Err(msg)) => summary.push((n, false, msg)),
            Err(_) => summary.push((n, false, "PANICKED — see stderr above".into())),
        }
    }

    println!("\n=== SUMMARY ===");
    for (n, ok, line) in &summary {
        println!("  n={:<6} {}  {}", n, if *ok { "PASS" } else { "FAIL" }, line);
    }
    if summary.iter().all(|(_, ok, _)| *ok) {
        println!("\nAll round-trips correct — small-n OnionPIR PIR works.");
    } else {
        println!("\nSome round-trips FAILED — §3.2 needs attention (see above).");
        std::process::exit(1);
    }
}

/// Build a tiny PIR DB with random data, run query → answer → decrypt
/// for boundary plaintext indices, verify each against the server's
/// recorded original, and measure ciphertext sizes. Returns a one-line
/// summary on success, or an error string on a logical failure.
fn run_round_trip(n: u64) -> Result<String, String> {
    let info = params_info(n);
    println!("params: {:#?}", info);

    let num_pt = info.num_plaintexts;
    if num_pt == 0 {
        return Err("num_plaintexts == 0 — degenerate params".into());
    }
    // Plaintext indices to query (and to record for verification).
    let targets = boundary_targets(num_pt);

    // ── Build DB (random data; record the indices we will verify) ──
    let t = Instant::now();
    let mut server = Server::new(n);
    server.gen_data(&targets);
    let gen_ms = t.elapsed().as_millis();

    // ── Client keys ──
    let t = Instant::now();
    let client = Client::new(n);
    let client_id = client.id();
    let galois = client.galois_keys();
    let gsw = client.gsw_key();
    server.set_galois_keys(client_id, &galois);
    server.set_gsw_key(client_id, &gsw);
    let keygen_ms = t.elapsed().as_millis();

    // ── Query / answer / decrypt for each boundary index ──
    let mut query_len = 0usize;
    let mut resp_len = 0usize;
    let mut answer_ms_total = 0u128;
    for &pt in &targets {
        let query = client.generate_query(pt);
        query_len = query.len();

        let t = Instant::now();
        let response = server.answer_query(client_id, &query);
        answer_ms_total += t.elapsed().as_millis();
        resp_len = response.len();

        let decrypted = client.decrypt_response(&response);
        let expected = server.get_original_plaintext(pt);
        if decrypted.is_empty() {
            return Err(format!("pt {}: empty decrypted plaintext", pt));
        }
        if expected.is_empty() {
            return Err(format!("pt {}: server returned empty original plaintext", pt));
        }
        if decrypted != expected {
            let same_len = decrypted.len() == expected.len();
            return Err(format!(
                "pt {}: round-trip MISMATCH — decrypted {} B vs expected {} B{}",
                pt,
                decrypted.len(),
                expected.len(),
                if same_len { " (equal length, content differs)" } else { "" },
            ));
        }
    }

    let line = format!(
        "num_pt={} dims=[fst={} other={}] entry={}B | \
         query={}B resp={}B galois={}KB gsw={}KB | \
         gen_data={}ms keygen={}ms answer~{}ms/q ({} indices ok)",
        num_pt,
        info.fst_dim_sz,
        info.other_dim_sz,
        info.entry_size,
        query_len,
        resp_len,
        galois.len() / 1024,
        gsw.len() / 1024,
        gen_ms,
        keygen_ms,
        answer_ms_total / targets.len() as u128,
        targets.len(),
    );
    println!("OK: {}", line);
    Ok(line)
}

/// Boundary + interior plaintext indices in `[0, num_pt)`, so a single
/// off-by-one cannot slip past.
fn boundary_targets(num_pt: u64) -> Vec<u64> {
    let mut t = vec![0, 1, num_pt / 2, num_pt.saturating_sub(2), num_pt - 1];
    t.retain(|&x| x < num_pt);
    t.sort_unstable();
    t.dedup();
    t
}
