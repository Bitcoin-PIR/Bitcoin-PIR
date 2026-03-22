//! OnionPIRv2-based 1-server Batch PIR client.
//!
//! Queries a Bitcoin script hash through a single PIR server:
//!   0. Key exchange (galois + GSW keys — sent once per session)
//!   1. Level 1: index PIR → (offset, num_chunks, flags)
//!   2. Level 2: chunk PIR → actual UTXO data (multi-round)
//!
//! Unlike the 2-server DPF client, this connects to a SINGLE server.
//! Privacy is provided by FHE (OnionPIR) rather than secret-shared DPF.
//!
//! Usage:
//!   cargo run --release -p runtime --bin onionpir_client -- \
//!     --server ws://localhost:8090 \
//!     --hash <40-char hex script hash>

use runtime::eval;
use runtime::onionpir::*;
use runtime::protocol;
use build::common::*;
use futures_util::{SinkExt, StreamExt};
use onionpir::Client as PirClient;
use std::time::Instant;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

// ─── CLI args ───────────────────────────────────────────────────────────────

struct Args {
    server: String,
    script_hash: [u8; SCRIPT_HASH_SIZE],
}

fn parse_args() -> Args {
    let args: Vec<String> = std::env::args().collect();
    let mut server = "ws://localhost:8090".to_string();
    let mut hash_hex = String::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--server" | "-s" => { server = args[i + 1].clone(); i += 1; }
            "--hash" | "-h" => { hash_hex = args[i + 1].clone(); i += 1; }
            "--help" => {
                println!("Usage: onionpir_client --hash <hex> [--server URL]");
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }

    if hash_hex.len() != 40 {
        eprintln!("Error: --hash must be a 40-character hex string (20 bytes)");
        std::process::exit(1);
    }

    let mut script_hash = [0u8; SCRIPT_HASH_SIZE];
    for j in 0..SCRIPT_HASH_SIZE {
        script_hash[j] = u8::from_str_radix(&hash_hex[j * 2..j * 2 + 2], 16)
            .expect("invalid hex in --hash");
    }

    Args { server, script_hash }
}

// ─── WebSocket helpers ──────────────────────────────────────────────────────

type WsSink = futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    Message,
>;
type WsStream = futures_util::stream::SplitStream<
    tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
>;

/// Receive the next binary message, handling pings transparently.
async fn recv_binary(stream: &mut WsStream, sink: &mut WsSink) -> Vec<u8> {
    loop {
        let msg = stream.next().await.expect("no response").expect("read error");
        match msg {
            Message::Binary(b) => return b.to_vec(),
            Message::Ping(p) => { let _ = sink.send(Message::Pong(p)).await; }
            _ => continue,
        }
    }
}

// ─── Cuckoo assignment for chunk level (same as DPF client) ─────────────────

fn plan_chunk_rounds(chunk_ids: &[u32]) -> Vec<Vec<(u32, u8)>> {
    let mut remaining: Vec<u32> = chunk_ids.to_vec();
    let mut rounds = Vec::new();

    while !remaining.is_empty() {
        let candidates: Vec<(u32, [usize; NUM_HASHES])> = remaining
            .iter()
            .map(|&cid| (cid, derive_chunk_buckets(cid)))
            .collect();

        let mut buckets: [Option<usize>; K_CHUNK] = [None; K_CHUNK];
        let mut round_entries: Vec<(u32, u8)> = Vec::new();
        let mut placed_set = Vec::new();

        let cand_buckets: Vec<[usize; NUM_HASHES]> = candidates.iter().map(|c| c.1).collect();

        for i in 0..candidates.len() {
            if round_entries.len() >= K_CHUNK {
                break;
            }
            let saved = buckets;
            if cuckoo_place(&cand_buckets, &mut buckets, i, 500) {
                placed_set.push(i);
            } else {
                buckets = saved;
            }
        }

        for b in 0..K_CHUNK {
            if let Some(ci) = buckets[b] {
                round_entries.push((candidates[ci].0, b as u8));
            }
        }

        if round_entries.is_empty() {
            eprintln!("ERROR: could not place any chunks in round, {} remaining", remaining.len());
            break;
        }

        let placed_ids: Vec<u32> = placed_set.iter().map(|&i| candidates[i].0).collect();
        remaining.retain(|cid| !placed_ids.contains(cid));

        rounds.push(round_entries);
    }

    rounds
}

fn cuckoo_place(
    cand_buckets: &[[usize; NUM_HASHES]],
    buckets: &mut [Option<usize>; K_CHUNK],
    qi: usize,
    max_kicks: usize,
) -> bool {
    let cands = &cand_buckets[qi];
    for &c in cands {
        if buckets[c].is_none() {
            buckets[c] = Some(qi);
            return true;
        }
    }
    let mut current_qi = qi;
    let mut current_bucket = cand_buckets[current_qi][0];

    for kick in 0..max_kicks {
        let evicted_qi = buckets[current_bucket].unwrap();
        buckets[current_bucket] = Some(current_qi);
        let ev_cands = &cand_buckets[evicted_qi];

        for offset in 0..NUM_HASHES {
            let c = ev_cands[(kick + offset) % NUM_HASHES];
            if c == current_bucket { continue; }
            if buckets[c].is_none() {
                buckets[c] = Some(evicted_qi);
                return true;
            }
        }

        let mut next_bucket = ev_cands[0];
        for offset in 0..NUM_HASHES {
            let c = ev_cands[(kick + offset) % NUM_HASHES];
            if c != current_bucket {
                next_bucket = c;
                break;
            }
        }
        current_qi = evicted_qi;
        current_bucket = next_bucket;
    }
    false
}

// ─── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let args = parse_args();
    let hash_hex: String = args.script_hash.iter().map(|b| format!("{:02x}", b)).collect();

    println!("=== OnionPIR 1-Server Batch PIR Client ===");
    println!("  Script hash: {}", hash_hex);
    println!("  Server:      {}", args.server);
    println!();

    let total_start = Instant::now();

    // ── Connect ─────────────────────────────────────────────────────────
    println!("[1] Connecting...");
    let (ws, _) = connect_async(&args.server).await.expect("connect server");
    let (mut sink, mut stream) = ws.split();
    println!("  Connected.");
    println!();

    // ── Get server info ─────────────────────────────────────────────────
    println!("[2] Getting server info...");
    {
        let mut req = Vec::with_capacity(5);
        req.extend_from_slice(&1u32.to_le_bytes());
        req.push(protocol::REQ_GET_INFO);
        sink.send(Message::Binary(req.into())).await.expect("send");
    }
    let info_bytes = recv_binary(&mut stream, &mut sink).await;
    let info_payload = &info_bytes[4..]; // skip length prefix
    let info = OnionPirServerInfo::decode(&info_payload[1..]).expect("decode info");

    let index_bins = info.index_bins_per_table as usize;
    let chunk_bins = info.chunk_bins_per_table as usize;
    let tag_seed = info.tag_seed;

    println!("  Index: K={}, bins_per_table={}", info.index_k, index_bins);
    println!("  Chunk: K={}, bins_per_table={}", info.chunk_k, chunk_bins);
    println!("  tag_seed: 0x{:016x}", tag_seed);
    println!("  OnionPIR: entry_size={}, num_entries={}", info.onionpir_entry_size, info.onionpir_num_entries);
    println!();

    // ── Create OnionPIR client and exchange keys ────────────────────────
    println!("[3] Generating encryption keys...");
    let key_start = Instant::now();

    // num_entries must match the server's value
    let mut pir_client = PirClient::new(index_bins as u64);
    let galois_keys = pir_client.generate_galois_keys();
    let gsw_keys = pir_client.generate_gsw_keys();

    println!("  Key generation: {:.2?}", key_start.elapsed());
    println!("  Galois keys: {} bytes", galois_keys.len());
    println!("  GSW keys:    {} bytes", gsw_keys.len());

    let reg_start = Instant::now();
    let reg_msg = RegisterKeysMsg {
        galois_keys: galois_keys.clone(),
        gsw_keys: gsw_keys.clone(),
    };
    sink.send(Message::Binary(reg_msg.encode().into())).await.expect("send keys");
    let ack = recv_binary(&mut stream, &mut sink).await;
    assert_eq!(ack[4], RESP_KEYS_ACK, "Expected keys ack");
    println!("  Key exchange: {:.2?}", reg_start.elapsed());
    println!();

    // ══════════════════════════════════════════════════════════════════════
    // LEVEL 1: Index PIR
    // ══════════════════════════════════════════════════════════════════════
    println!("[4] Level 1: Index PIR...");
    let l1_start = Instant::now();

    // Compute PBC bucket assignment for our script hash
    let my_buckets = derive_buckets(&args.script_hash);
    let assigned_bucket = my_buckets[0]; // use first bucket for single query

    // Within the assigned bucket, compute cuckoo hash locations.
    // We need to query each possible cuckoo hash function to find where the
    // entry was placed. With INDEX_CUCKOO_NUM_HASHES = 2, we query 2 locations.
    let mut my_cuckoo_bins: Vec<usize> = Vec::new();
    for h in 0..INDEX_CUCKOO_NUM_HASHES {
        let key = derive_cuckoo_key(assigned_bucket, h);
        my_cuckoo_bins.push(cuckoo_hash(&args.script_hash, key, index_bins));
    }

    println!("  Assigned bucket: {}", assigned_bucket);
    println!("  Cuckoo bins: {:?}", my_cuckoo_bins);

    // Generate OnionPIR queries for all K buckets.
    // For the assigned bucket, we generate INDEX_CUCKOO_NUM_HASHES queries
    // (one for each possible cuckoo location). For dummy buckets, we query
    // a random index to maintain privacy.
    //
    // NOTE: With OnionPIR each query targets a single entry index.
    // We need to try each cuckoo hash function because we don't know which
    // one was used to place our entry. This means INDEX_CUCKOO_NUM_HASHES
    // queries for the real bucket.
    //
    // For the initial implementation, we send one query per bucket and try
    // cuckoo hash functions sequentially if the first doesn't match.

    // First attempt: query using cuckoo hash function 0 for the assigned bucket
    let mut queries: Vec<Vec<u8>> = Vec::with_capacity(K);
    let mut rng_state: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap()
        .as_nanos() as u64;

    for b in 0..K {
        let target_index = if b == assigned_bucket {
            my_cuckoo_bins[0] as u64
        } else {
            rng_state = splitmix64(rng_state.wrapping_add(0x9e3779b97f4a7c15));
            rng_state % index_bins as u64
        };
        queries.push(pir_client.generate_query(target_index));
    }

    // Send query batch
    let batch = OnionPirBatchQuery { round_id: 0, queries };
    let encoded = batch.encode(REQ_ONIONPIR_INDEX_QUERY);
    sink.send(Message::Binary(encoded.into())).await.expect("send index query");

    // Receive response
    let resp_bytes = recv_binary(&mut stream, &mut sink).await;
    let resp_payload = &resp_bytes[4..];
    assert_eq!(resp_payload[0], RESP_ONIONPIR_INDEX_RESULT);
    let result_batch = OnionPirBatchResult::decode(&resp_payload[1..]).expect("decode index result");

    // Decrypt the response for our assigned bucket
    let entry_bytes = pir_client.decrypt_response(my_cuckoo_bins[0] as u64, &result_batch.results[assigned_bucket]);

    // The decrypted entry is `entry_size` bytes, but only the first `bin_byte_size`
    // bytes are meaningful. A cuckoo bin contains CUCKOO_BUCKET_SIZE (3) slots of
    // INDEX_SLOT_SIZE (14) bytes each = 42 bytes total.
    let index_bin_size = CUCKOO_BUCKET_SIZE * INDEX_SLOT_SIZE;
    let bin_data = &entry_bytes[..index_bin_size];

    // Compute expected tag
    let my_tag = compute_tag(tag_seed, &args.script_hash);

    // Search the bin's slots for our tag
    let mut found_entry = eval::find_entry_in_index_result(bin_data, my_tag);

    // If not found with hash function 0, try hash function 1
    if found_entry.is_none() && INDEX_CUCKOO_NUM_HASHES > 1 {
        println!("  Cuckoo hash 0 miss, trying hash 1...");

        // Generate a new query for the second cuckoo location
        let mut queries2: Vec<Vec<u8>> = Vec::with_capacity(K);
        for b in 0..K {
            let target_index = if b == assigned_bucket {
                my_cuckoo_bins[1] as u64
            } else {
                rng_state = splitmix64(rng_state.wrapping_add(0x9e3779b97f4a7c15));
                rng_state % index_bins as u64
            };
            queries2.push(pir_client.generate_query(target_index));
        }

        let batch2 = OnionPirBatchQuery { round_id: 1, queries: queries2 };
        let encoded2 = batch2.encode(REQ_ONIONPIR_INDEX_QUERY);
        sink.send(Message::Binary(encoded2.into())).await.expect("send index query 2");

        let resp_bytes2 = recv_binary(&mut stream, &mut sink).await;
        let resp_payload2 = &resp_bytes2[4..];
        assert_eq!(resp_payload2[0], RESP_ONIONPIR_INDEX_RESULT);
        let result_batch2 = OnionPirBatchResult::decode(&resp_payload2[1..]).expect("decode index result 2");

        let entry_bytes2 = pir_client.decrypt_response(
            my_cuckoo_bins[1] as u64,
            &result_batch2.results[assigned_bucket],
        );
        let bin_data2 = &entry_bytes2[..index_bin_size];
        found_entry = eval::find_entry_in_index_result(bin_data2, my_tag);
    }

    let (start_chunk, num_chunks, flags) = found_entry
        .unwrap_or_else(|| {
            eprintln!("ERROR: script hash not found in index PIR result!");
            std::process::exit(1);
        });

    let num_units = (num_chunks as usize + CHUNKS_PER_UNIT - 1) / CHUNKS_PER_UNIT;
    let placement = eval::decode_placement(flags);

    println!("  Found: start_chunk={}, num_chunks={}, flags=0x{:02x}", start_chunk, num_chunks, flags);
    if let Some(ref p) = placement {
        println!("  Placement bits: h={:?}", p);
    }
    println!("  Units to fetch: {}", num_units);
    println!("  Level 1 time: {:.2?}", l1_start.elapsed());
    println!();

    // ── Whale detection ─────────────────────────────────────────────────
    if num_chunks == 0 && (flags & FLAG_WHALE) != 0 {
        println!("=== WHALE ADDRESS (EXCLUDED) ===");
        println!("  This address has too many UTXOs and was excluded from the PIR database.");
        println!("  Total time: {:.2?}", total_start.elapsed());
        return;
    }

    // ══════════════════════════════════════════════════════════════════════
    // LEVEL 2: Chunk PIR (multi-round)
    // ══════════════════════════════════════════════════════════════════════
    println!("[5] Level 2: Chunk PIR...");
    let l2_start = Instant::now();

    // If chunk bins differ from index bins, we need a separate PirClient
    // with the chunk num_entries. For now, create one unconditionally.
    let mut chunk_pir_client = PirClient::new(chunk_bins as u64);
    {
        // Register chunk-level keys (reuse or regenerate)
        // In practice, if index and chunk have different num_entries,
        // the client needs separate SEAL contexts.
        let chunk_galois = chunk_pir_client.generate_galois_keys();
        let chunk_gsw = chunk_pir_client.generate_gsw_keys();

        // Send keys (the server registers with chunk-level servers)
        let reg = RegisterKeysMsg {
            galois_keys: chunk_galois,
            gsw_keys: chunk_gsw,
        };
        sink.send(Message::Binary(reg.encode().into())).await.expect("send chunk keys");
        let ack = recv_binary(&mut stream, &mut sink).await;
        assert_eq!(ack[4], RESP_KEYS_ACK, "Expected chunk keys ack");
    }

    let chunk_ids: Vec<u32> = (0..num_units)
        .map(|u| start_chunk + (u as u32) * CHUNKS_PER_UNIT as u32)
        .collect();

    let rounds = plan_chunk_rounds(&chunk_ids);
    println!("  {} chunks → {} rounds", chunk_ids.len(), rounds.len());

    let mut recovered_chunks: std::collections::HashMap<u32, Vec<u8>> =
        std::collections::HashMap::new();

    let chunk_bin_byte_size = CHUNK_CUCKOO_BUCKET_SIZE * CHUNK_SLOT_SIZE; // 2 * 44 = 88

    for (ri, round_plan) in rounds.iter().enumerate() {
        // For each bucket with a real query, compute the target cuckoo bin.
        // With OnionPIR we query ONE bin per bucket (using placement if available,
        // otherwise we try cuckoo hash 0 first).
        let mut bucket_targets: Vec<Option<(u32, usize)>> = vec![None; K_CHUNK]; // (chunk_id, bin_index)
        let first_chunk_groups = derive_chunk_buckets(start_chunk);

        for &(chunk_id, bucket_id) in round_plan {
            let b = bucket_id as usize;

            // Determine which cuckoo hash function placed this chunk
            let h = if chunk_id == start_chunk {
                if let Some(ref p) = placement {
                    let group_idx = first_chunk_groups.iter().position(|&g| g == b)
                        .expect("bucket_id must be one of the chunk's groups");
                    p[group_idx]
                } else {
                    0 // try hash 0 first
                }
            } else {
                0 // no placement info for non-first chunks; try hash 0
            };

            let key = derive_chunk_cuckoo_key(b, h);
            let bin = cuckoo_hash_int(chunk_id, key, chunk_bins);
            bucket_targets[b] = Some((chunk_id, bin));
        }

        // Generate OnionPIR queries
        let mut queries: Vec<Vec<u8>> = Vec::with_capacity(K_CHUNK);
        for b in 0..K_CHUNK {
            let target_index = match &bucket_targets[b] {
                Some((_, bin)) => *bin as u64,
                None => {
                    rng_state = splitmix64(rng_state.wrapping_add(0x9e3779b97f4a7c15));
                    rng_state % chunk_bins as u64
                }
            };
            queries.push(chunk_pir_client.generate_query(target_index));
        }

        // Send
        let batch = OnionPirBatchQuery { round_id: ri as u16, queries };
        let encoded = batch.encode(REQ_ONIONPIR_CHUNK_QUERY);
        sink.send(Message::Binary(encoded.into())).await.expect("send chunk query");

        // Receive
        let resp_bytes = recv_binary(&mut stream, &mut sink).await;
        let resp_payload = &resp_bytes[4..];
        assert_eq!(resp_payload[0], RESP_ONIONPIR_CHUNK_RESULT);
        let result_batch = OnionPirBatchResult::decode(&resp_payload[1..]).expect("decode chunk result");

        // Decrypt and extract
        for &(chunk_id, bucket_id) in round_plan {
            let b = bucket_id as usize;
            let (_, bin_index) = bucket_targets[b].unwrap();

            let entry_bytes = chunk_pir_client.decrypt_response(
                bin_index as u64,
                &result_batch.results[b],
            );
            let bin_data = &entry_bytes[..chunk_bin_byte_size];

            if let Some(data) = eval::find_chunk_in_result(bin_data, chunk_id) {
                recovered_chunks.insert(chunk_id, data.to_vec());
            } else {
                // If using hash 0 and it missed, we'd need to retry with other hashes.
                // For now, log a warning. A full implementation would retry.
                eprintln!("  WARNING: chunk {} not found in round {} bucket {} (may need cuckoo retry)",
                    chunk_id, ri, b);
            }
        }

        if (ri + 1) % 10 == 0 || ri + 1 == rounds.len() {
            println!("  Round {}/{}: recovered {}/{} chunks",
                ri + 1, rounds.len(), recovered_chunks.len(), chunk_ids.len());
        }
    }

    println!("  Level 2 time: {:.2?}", l2_start.elapsed());
    println!();

    // ══════════════════════════════════════════════════════════════════════
    // Reassemble and output (identical to DPF client)
    // ══════════════════════════════════════════════════════════════════════
    println!("[6] Reassembling UTXO data...");

    let mut full_data = Vec::new();
    let mut missing = 0;
    for &cid in &chunk_ids {
        if let Some(d) = recovered_chunks.get(&cid) {
            full_data.extend_from_slice(d);
        } else {
            missing += 1;
            full_data.extend_from_slice(&vec![0u8; UNIT_DATA_SIZE]);
        }
    }

    println!("  Recovered: {}/{} units", chunk_ids.len() - missing, chunk_ids.len());
    if missing > 0 {
        println!("  WARNING: {} units missing!", missing);
    }
    println!("  Total data: {} bytes", full_data.len());
    println!();

    // Decode UTXO entries
    println!("[7] Decoding UTXO entries:");
    {
        let mut pos = 0;
        let (num_entries, bytes_read) = read_varint(&full_data[pos..]);
        pos += bytes_read;
        println!("  Number of UTXOs: {}", num_entries);
        println!();

        let mut total_sats: u64 = 0;
        for i in 0..num_entries as usize {
            if pos + 32 > full_data.len() {
                println!("  (data truncated at entry {})", i);
                break;
            }
            let txid_bytes = &full_data[pos..pos + 32];
            pos += 32;

            let mut txid_rev = [0u8; 32];
            for j in 0..32 {
                txid_rev[j] = txid_bytes[31 - j];
            }
            let txid_hex: String = txid_rev.iter().map(|b| format!("{:02x}", b)).collect();

            let (vout, vr) = read_varint(&full_data[pos..]);
            pos += vr;
            let (amount, ar) = read_varint(&full_data[pos..]);
            pos += ar;

            total_sats += amount;
            let btc = amount as f64 / 100_000_000.0;
            println!("  UTXO #{}: {}:{} — {} sats ({:.8} BTC)",
                i + 1, txid_hex, vout, amount, btc);
        }

        println!();
        let total_btc = total_sats as f64 / 100_000_000.0;
        println!("  Total: {} sats ({:.8} BTC) across {} UTXOs",
            total_sats, total_btc, num_entries);
    }

    println!();
    println!("=== Done ===");
    println!("  Total time: {:.2?}", total_start.elapsed());
    println!("  Script hash: {}", hash_hex);
    println!("  Chunks: {}, Rounds: {}", num_chunks, rounds.len());
}

fn read_varint(data: &[u8]) -> (u64, usize) {
    let mut value: u64 = 0;
    let mut shift = 0;
    for (i, &byte) in data.iter().enumerate() {
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return (value, i + 1);
        }
        shift += 7;
        if shift >= 64 {
            panic!("varint too large");
        }
    }
    panic!("unexpected end of varint data");
}
