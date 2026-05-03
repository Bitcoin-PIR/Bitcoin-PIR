//! End-to-end PIR smoke test.
//!
//! Drives a full PIR round-trip through the Rust FFI: build a database,
//! preprocess, register client keys, generate a query, answer it, and
//! decrypt. Asserts the decrypted entry has the expected length and that
//! the first 8 bytes (which `utils::writeIdxToEntry` on the C++ side
//! reserves for the entry index, big-endian) match the queried index.
//!
//! Marked `#[ignore]` because it exercises the full SEAL/HEXL stack
//! (preprocess + answer dominate runtime). Run explicitly:
//!
//! ```sh
//! cargo test --release -- --ignored smoke_pir_query_round_trip
//! ```
//!
//! On x86_64 Linux this also serves as the runtime sanity check that
//! HEXL was wired in correctly: the build flag flips, link succeeds,
//! and `component_wise_mult_direct_mod`'s HEXL path runs without SIGILL.
//! Deeper byte-for-byte correctness across all coefficients is exercised
//! by the C++ `Onion-PIR` test target's `test_pir()` (which has access
//! to `direct_get_entry` only in `_DEBUG` builds).

use onionpir::{params_info, Client, Server};

#[test]
#[ignore]
fn smoke_pir_query_round_trip() {
    // Use the compile-time default num_entries (matches DatabaseConstants).
    // Passing 0 → server uses DatabaseConstants::NumEntries.
    let info = params_info(0);
    eprintln!("smoke params: {:#?}", info);

    assert!(info.entry_size >= 8, "entry_size must be ≥ 8 to encode an index");
    assert!(info.num_entries > 0);
    assert!(info.other_dim_sz > 0);

    let entry_size = info.entry_size as usize;
    let num_entries = info.num_entries as usize;
    let other_dim_sz = info.other_dim_sz as usize;
    let chunk_entries = num_entries / other_dim_sz;
    let chunk_bytes = chunk_entries * entry_size;

    // Deterministic entries: bytes [0..8] = entry-id big-endian (matches
    // utils::writeIdxToEntry); bytes [8..] = id-derived pseudo-random
    // pattern so we don't feed SEAL all-zero plaintexts.
    let make_entry = |i: usize| -> Vec<u8> {
        let mut e = vec![0u8; entry_size];
        e[..8].copy_from_slice(&(i as u64).to_be_bytes());
        // Cheap LCG-style fill for the payload region.
        let mut x = (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xDEAD_BEEF;
        for byte in &mut e[8..] {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *byte = (x >> 56) as u8;
        }
        e
    };

    // Server: push one chunk at a time, then preprocess.
    let mut server = Server::new(0);
    for chunk_idx in 0..other_dim_sz {
        let mut chunk = Vec::with_capacity(chunk_bytes);
        for k in 0..chunk_entries {
            let global_idx = chunk_idx * chunk_entries + k;
            chunk.extend_from_slice(&make_entry(global_idx));
        }
        assert_eq!(chunk.len(), chunk_bytes);
        server.push_chunk(&chunk, chunk_idx);
    }
    server.preprocess();

    // Client: keys → register with server.
    let mut client = Client::new(0);
    let client_id = client.id();
    let galois = client.generate_galois_keys();
    let gsw = client.generate_gsw_keys();
    server.set_galois_key(client_id, &galois);
    server.set_gsw_key(client_id, &gsw);

    // Query a handful of targets so a single off-by-one doesn't slip by.
    for &target in &[0u64, 1, 42, (num_entries as u64) / 2, (num_entries as u64) - 1] {
        let query = client.generate_query(target);
        assert!(!query.is_empty(), "empty query for index {}", target);

        let response = server.answer_query(client_id, &query);
        assert!(!response.is_empty(), "empty response for index {}", target);

        let decrypted = client.decrypt_response(target, &response);
        assert_eq!(
            decrypted.len(),
            entry_size,
            "decrypted entry length mismatch for index {}",
            target,
        );

        // The first 8 bytes encode the entry index. With sufficient noise
        // budget and correctly wired NTT/HEXL paths these survive
        // round-trip exactly.
        let recovered = u64::from_be_bytes(decrypted[..8].try_into().unwrap());
        assert_eq!(
            recovered, target,
            "PIR index round-trip mismatch: queried {}, decrypted index field {}",
            target, recovered,
        );
    }
}
