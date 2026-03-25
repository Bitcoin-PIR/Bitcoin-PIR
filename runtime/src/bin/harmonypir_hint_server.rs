//! HarmonyPIR Hint Server.
//!
//! Loads the same cuckoo table files as the DPF server. When a client
//! connects and sends a PRP key, computes hint parities for each PBC
//! bucket and streams them back.
//!
//! Usage:
//!   cargo run --release -p runtime --bin harmonypir_hint_server -- --port 8093

use build::common::*;
use runtime::protocol::*;

use futures_util::{SinkExt, StreamExt};
use memmap2::Mmap;
use rayon::prelude::*;
use std::fs::File;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

use harmonypir::params::{Params, BETA};
use harmonypir::prp::hoang::HoangPrp;
use harmonypir::prp::Prp;
use harmonypir::relocation::RelocationDS;

// ─── Server data ────────────────────────────────────────────────────────────

struct HintServerData {
    index_cuckoo: Mmap,
    index_bins_per_table: usize,
    tag_seed: u64,

    chunk_cuckoo: Mmap,
    chunk_bins_per_table: usize,
}

impl HintServerData {
    fn load() -> Self {
        println!("[1] Loading index cuckoo: {}", CUCKOO_FILE);
        let f = File::open(CUCKOO_FILE).expect("open index cuckoo");
        let index_cuckoo = unsafe { Mmap::map(&f) }.expect("mmap index cuckoo");
        let (index_bins_per_table, tag_seed) = read_cuckoo_header(&index_cuckoo);
        println!("  bins_per_table = {}, tag_seed = 0x{:016x}", index_bins_per_table, tag_seed);

        println!("[2] Loading chunk cuckoo: {}", CHUNK_CUCKOO_FILE);
        let f = File::open(CHUNK_CUCKOO_FILE).expect("open chunk cuckoo");
        let chunk_cuckoo = unsafe { Mmap::map(&f) }.expect("mmap chunk cuckoo");
        let chunk_bins_per_table = read_chunk_cuckoo_header(&chunk_cuckoo);
        println!("  bins_per_table = {}", chunk_bins_per_table);

        HintServerData {
            index_cuckoo,
            index_bins_per_table,
            tag_seed,
            chunk_cuckoo,
            chunk_bins_per_table,
        }
    }

    /// Compute hint parities for one bucket.
    ///
    /// Returns (bucket_id, n, t, m, flat_hints) where flat_hints is M × w bytes.
    fn compute_hints_for_bucket(
        &self,
        prp_key: &[u8; 16],
        level: u8,
        bucket_id: u8,
    ) -> (u8, u32, u32, u32, Vec<u8>) {
        let (table_bytes, bins_per_table, entry_size, header_size, k_offset) = match level {
            0 => (
                &self.index_cuckoo[..],
                self.index_bins_per_table,
                CUCKOO_BUCKET_SIZE * INDEX_SLOT_SIZE,
                HEADER_SIZE,
                0u32,
            ),
            1 => (
                &self.chunk_cuckoo[..],
                self.chunk_bins_per_table,
                CHUNK_CUCKOO_BUCKET_SIZE * (4 + CHUNK_SIZE),
                CHUNK_HEADER_SIZE,
                K as u32, // Chunk buckets use offset bucket IDs for PRP derivation
            ),
            _ => panic!("invalid level"),
        };

        let n = bins_per_table;
        let w = entry_size;

        // Compute T (must divide 2N).
        let t = find_best_t(n);

        let params = Params::new(n, w, t).expect("valid params");
        let m = params.m;

        // Derive per-bucket PRP key (same derivation as WASM client).
        let derived_key = derive_bucket_key(prp_key, k_offset + bucket_id as u32);

        // Compute PRP rounds.
        let domain = 2 * n;
        let log_domain = (domain as f64).log2().ceil() as usize;
        let r_raw = log_domain + 40;
        let r = ((r_raw + BETA - 1) / BETA) * BETA;

        let prp: Box<dyn Prp> = Box::new(HoangPrp::new(domain, r, &derived_key));
        let ds = RelocationDS::new(n, t, prp).expect("DS init");

        // Compute hint parities.
        let mut hints: Vec<Vec<u8>> = (0..m).map(|_| vec![0u8; w]).collect();

        let table_offset = header_size + bucket_id as usize * bins_per_table * entry_size;
        for k in 0..n {
            let cell = ds.locate(k).expect("locate during hint computation");
            let segment = cell / t;

            let entry_offset = table_offset + k * entry_size;
            let entry = &table_bytes[entry_offset..entry_offset + entry_size];
            xor_into(&mut hints[segment], entry);
        }

        // Flatten hints.
        let flat: Vec<u8> = hints.into_iter().flat_map(|h| h.into_iter()).collect();

        (bucket_id, n as u32, t as u32, m as u32, flat)
    }
}

/// XOR src into dst.
fn xor_into(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

/// Derive per-bucket PRP key. Must match WASM client derivation.
fn derive_bucket_key(master_key: &[u8; 16], bucket_id: u32) -> [u8; 16] {
    let mut key = *master_key;
    let id_bytes = bucket_id.to_le_bytes();
    for i in 0..4 {
        key[12 + i] ^= id_bytes[i];
    }
    key
}

/// Find balanced T that divides 2*n. Must match WASM client computation.
fn find_best_t(n: usize) -> usize {
    let two_n = 2 * n;
    let t_approx = (two_n as f64).sqrt() as usize;
    if t_approx > 0 && two_n % t_approx == 0 {
        return t_approx;
    }
    for delta in 1..t_approx {
        let up = t_approx + delta;
        if up <= two_n && two_n % up == 0 {
            return up;
        }
        if t_approx > delta {
            let down = t_approx - delta;
            if down > 0 && two_n % down == 0 {
                return down;
            }
        }
    }
    1
}

// ─── Main ───────────────────────────────────────────────────────────────────

fn parse_port() -> u16 {
    let args: Vec<String> = std::env::args().collect();
    let mut port = 8093u16;
    let mut i = 1;
    while i < args.len() {
        if (args[i] == "--port" || args[i] == "-p") && i + 1 < args.len() {
            port = args[i + 1].parse().unwrap_or(8093);
            i += 1;
        }
        i += 1;
    }
    port
}

#[tokio::main]
async fn main() {
    let port = parse_port();

    println!("=== HarmonyPIR Hint Server ===");
    println!();

    let start = Instant::now();
    let data = HintServerData::load();
    println!();
    println!("Data loaded in {:.2?}", start.elapsed());
    println!();

    let data = Arc::new(data);

    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();
    let listener = TcpListener::bind(addr).await.expect("bind");
    println!("Listening on ws://{}", addr);
    println!("  Index: K={}, bins_per_table={}", K, data.index_bins_per_table);
    println!("  Chunk: K_CHUNK={}, bins_per_table={}", K_CHUNK, data.chunk_bins_per_table);
    println!();

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("Accept error: {}", e);
                continue;
            }
        };

        let data = Arc::clone(&data);
        tokio::spawn(async move {
            let ws = match accept_async(stream).await {
                Ok(ws) => ws,
                Err(e) => {
                    eprintln!("[{}] Handshake failed: {}", peer, e);
                    return;
                }
            };
            println!("[{}] Connected", peer);
            let (mut sink, mut stream) = ws.split();

            while let Some(msg) = stream.next().await {
                let bin = match msg {
                    Ok(Message::Binary(b)) => b,
                    Ok(Message::Ping(_)) => continue,
                    Ok(Message::Close(_)) | Err(_) => break,
                    _ => continue,
                };

                if bin.len() < 4 {
                    continue;
                }
                let payload = &bin[4..];

                let request = match Request::decode(payload) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("[{}] Bad request: {}", peer, e);
                        let resp = Response::Error(format!("decode error: {}", e));
                        let _ = sink.send(Message::Binary(resp.encode().into())).await;
                        continue;
                    }
                };

                match request {
                    Request::Ping => {
                        let _ = sink.send(Message::Binary(Response::Pong.encode().into())).await;
                    }
                    Request::HarmonyGetInfo | Request::GetInfo => {
                        let resp = Response::HarmonyInfo(ServerInfo {
                            index_bins_per_table: data.index_bins_per_table as u32,
                            chunk_bins_per_table: data.chunk_bins_per_table as u32,
                            index_k: K as u8,
                            chunk_k: K_CHUNK as u8,
                            tag_seed: data.tag_seed,
                        });
                        let _ = sink.send(Message::Binary(resp.encode().into())).await;
                    }
                    Request::HarmonyHints(hint_req) => {
                        let t_start = Instant::now();
                        let level = hint_req.level;
                        let num = hint_req.bucket_ids.len();
                        println!("[{}] Hint request: level={} buckets={}", peer, level, num);

                        // Compute hints in parallel using rayon.
                        let prp_key: [u8; 16] = hint_req.prp_key;
                        let bucket_ids = hint_req.bucket_ids.clone();
                        let data_ref = Arc::clone(&data);

                        let results: Vec<_> = tokio::task::spawn_blocking(move || {
                            bucket_ids.par_iter().map(|&bid| {
                                data_ref.compute_hints_for_bucket(&prp_key, level, bid)
                            }).collect()
                        }).await.unwrap();

                        // Stream results back.
                        for (bucket_id, n, t, m, flat_hints) in results {
                            // Wire: [4B len][1B RESP_HARMONY_HINTS][1B bucket_id][4B n][4B t][4B m][hints...]
                            let hint_payload_len = 1 + 1 + 4 + 4 + 4 + flat_hints.len();
                            let mut resp = Vec::with_capacity(4 + hint_payload_len);
                            resp.extend_from_slice(&(hint_payload_len as u32).to_le_bytes());
                            resp.push(RESP_HARMONY_HINTS);
                            resp.push(bucket_id);
                            resp.extend_from_slice(&n.to_le_bytes());
                            resp.extend_from_slice(&t.to_le_bytes());
                            resp.extend_from_slice(&m.to_le_bytes());
                            resp.extend_from_slice(&flat_hints);

                            if let Err(e) = sink.send(Message::Binary(resp.into())).await {
                                eprintln!("[{}] Send error: {}", peer, e);
                                break;
                            }
                        }

                        println!("[{}] Hints sent: level={} buckets={} in {:.2?}",
                            peer, level, num, t_start.elapsed());
                    }
                    _ => {
                        let resp = Response::Error("unsupported request on hint server".into());
                        let _ = sink.send(Message::Binary(resp.encode().into())).await;
                    }
                }
            }

            println!("[{}] Disconnected", peer);
        });
    }
}
