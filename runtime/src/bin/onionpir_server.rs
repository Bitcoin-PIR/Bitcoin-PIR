//! OnionPIRv2-based 1-server Batch PIR WebSocket server.
//!
//! Loads cuckoo tables, populates OnionPIR databases (one per PBC bucket),
//! and serves encrypted PIR queries. Unlike the 2-server DPF protocol,
//! this is a single server — privacy comes from FHE, not secret sharing.
//!
//! The OnionPIR `Server` objects are not Send/Sync (OpenMP internally),
//! so all PIR operations run on a dedicated OS thread via a channel.
//!
//! Usage:
//!   cargo run --release -p runtime --bin onionpir_server -- --port 8090

use runtime::onionpir::*;
use runtime::protocol;
use build::common::*;
use futures_util::{SinkExt, StreamExt};
use memmap2::Mmap;
use std::fs::File;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

// ─── Commands sent to the PIR worker thread ─────────────────────────────────

enum PirCommand {
    /// Register a client's keys with all bucket servers.
    RegisterKeys {
        client_id: u64,
        level: u8, // 0 = index, 1 = chunk
        galois_keys: Vec<u8>,
        gsw_keys: Vec<u8>,
        reply: oneshot::Sender<()>,
    },
    /// Answer a batch of queries for one level.
    AnswerBatch {
        client_id: u64,
        level: u8,
        round_id: u16,
        queries: Vec<Vec<u8>>,
        reply: oneshot::Sender<Vec<Vec<u8>>>,
    },
}

// ─── Server shared state (read-only after init) ─────────────────────────────

struct SharedState {
    index_bins_per_table: usize,
    chunk_bins_per_table: usize,
    tag_seed: u64,
    entry_size: usize,
    padded_num_entries: usize,
    pir_tx: mpsc::Sender<PirCommand>,
}

// ─── Main ───────────────────────────────────────────────────────────────────

fn parse_args() -> (u16, PathBuf) {
    let args: Vec<String> = std::env::args().collect();
    let mut port = 8090u16;
    let mut preprocess_dir = PathBuf::from("/Volumes/Bitcoin/data/onionpir");
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" => {
                port = args[i + 1].parse().unwrap_or(8090);
                i += 1;
            }
            "--preprocess-dir" | "-d" => {
                preprocess_dir = PathBuf::from(&args[i + 1]);
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    (port, preprocess_dir)
}

#[tokio::main]
async fn main() {
    let (port, preprocess_dir) = parse_args();

    println!("=== OnionPIR 1-Server Batch PIR Server ===");
    println!();

    // ── Load cuckoo table files (same format as DPF server) ──────────────
    let load_start = Instant::now();

    println!("[1] Loading index cuckoo table: {}", CUCKOO_FILE);
    let index_file = File::open(CUCKOO_FILE).expect("open index cuckoo");
    let index_mmap = unsafe { Mmap::map(&index_file) }.expect("mmap index cuckoo");
    let (index_bins_per_table, tag_seed) = read_cuckoo_header(&index_mmap);
    let index_bin_byte_size = CUCKOO_BUCKET_SIZE * INDEX_SLOT_SIZE; // 3 * 14 = 42
    println!("  bins_per_table={}, bin_byte_size={}", index_bins_per_table, index_bin_byte_size);

    println!("[2] Loading chunk cuckoo table: {}", CHUNK_CUCKOO_FILE);
    let chunk_file = File::open(CHUNK_CUCKOO_FILE).expect("open chunk cuckoo");
    let chunk_mmap = unsafe { Mmap::map(&chunk_file) }.expect("mmap chunk cuckoo");
    let chunk_bins_per_table = read_chunk_cuckoo_header(&chunk_mmap);
    let chunk_bin_byte_size = CHUNK_CUCKOO_BUCKET_SIZE * CHUNK_SLOT_SIZE; // 2 * 44 = 88
    println!("  bins_per_table={}, bin_byte_size={}", chunk_bins_per_table, chunk_bin_byte_size);

    // ── Build/load OnionPIR databases on a dedicated thread ──────────────
    // OnionPIR Server is not Send/Sync, so we keep everything on one OS thread
    // and communicate via channels.

    let (pir_tx, mut pir_rx) = mpsc::channel::<PirCommand>(64);

    let index_preproc = preprocess_dir.join("index");
    let chunk_preproc = preprocess_dir.join("chunk");

    // Spawn the PIR worker thread (blocking — not a tokio task)
    let _pir_thread = std::thread::spawn(move || {
        println!();
        println!("[3] Building OnionPIR index databases (K={} buckets)...", K);
        let t = Instant::now();
        let mut index_servers = BucketServers::load(
            &index_mmap,
            HEADER_SIZE,
            K,
            index_bins_per_table,
            index_bin_byte_size,
            &index_preproc,
        );
        println!("  Index databases ready in {:.2?}", t.elapsed());

        println!("[4] Building OnionPIR chunk databases (K={} buckets)...", K_CHUNK);
        let t = Instant::now();
        let mut chunk_servers = BucketServers::load(
            &chunk_mmap,
            CHUNK_HEADER_SIZE,
            K_CHUNK,
            chunk_bins_per_table,
            chunk_bin_byte_size,
            &chunk_preproc,
        );
        println!("  Chunk databases ready in {:.2?}", t.elapsed());
        println!();

        // Event loop: process commands from async tasks
        while let Some(cmd) = pir_rx.blocking_recv() {
            match cmd {
                PirCommand::RegisterKeys { client_id, level, galois_keys, gsw_keys, reply } => {
                    let t = Instant::now();
                    match level {
                        0 => index_servers.register_client(client_id, &galois_keys, &gsw_keys),
                        1 => chunk_servers.register_client(client_id, &galois_keys, &gsw_keys),
                        _ => eprintln!("Unknown level {} for key registration", level),
                    }
                    println!("[keys] client {} level {} registered in {:.2?}",
                        client_id, level, t.elapsed());
                    let _ = reply.send(());
                }
                PirCommand::AnswerBatch { client_id, level, round_id, queries, reply } => {
                    let t = Instant::now();
                    let n = queries.len();
                    let results = match level {
                        0 => index_servers.answer_batch(client_id, &queries),
                        1 => chunk_servers.answer_batch(client_id, &queries),
                        _ => {
                            eprintln!("Unknown level {} for query", level);
                            vec![Vec::new(); n]
                        }
                    };
                    let wall = t.elapsed();
                    let level_name = if level == 0 { "index" } else { "chunk" };
                    println!("[{}] r{} {} buckets answered in {:.2?}",
                        level_name, round_id, n, wall);
                    let _ = reply.send(results);
                }
            }
        }
    });

    // Wait briefly for the worker to finish building databases
    // (In production, we'd use a ready signal. For now, we proceed
    //  since the channel will queue commands until the worker is ready.)

    let entry_size = onionpir::params_info(index_bins_per_table as u64).entry_size as usize;
    let padded_num_entries = onionpir::params_info(index_bins_per_table as u64).num_entries as usize;

    let state = Arc::new(SharedState {
        index_bins_per_table,
        chunk_bins_per_table,
        tag_seed,
        entry_size,
        padded_num_entries,
        pir_tx,
    });

    println!("Data loaded in {:.2?}", load_start.elapsed());
    println!();

    // ── Accept WebSocket connections ─────────────────────────────────────

    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();
    let listener = TcpListener::bind(addr).await.expect("bind");
    println!("Listening on ws://{}", addr);
    println!("  Index: K={}, bins_per_table={}", K, index_bins_per_table);
    println!("  Chunk: K={}, bins_per_table={}", K_CHUNK, chunk_bins_per_table);
    println!("  OnionPIR entry_size={}, padded_num_entries={}", entry_size, padded_num_entries);
    println!();

    // Simple client ID counter
    let client_counter = std::sync::atomic::AtomicU64::new(1);

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("Accept error: {}", e);
                continue;
            }
        };

        let client_id = client_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        println!("[{}] Connected (client_id={})", peer, client_id);

        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let ws = match accept_async(stream).await {
                Ok(ws) => ws,
                Err(e) => {
                    eprintln!("[{}] WebSocket handshake failed: {}", peer, e);
                    return;
                }
            };

            let (mut sink, mut ws_stream) = ws.split();

            while let Some(msg) = ws_stream.next().await {
                let msg = match msg {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!("[{}] Read error: {}", peer, e);
                        break;
                    }
                };

                let bin = match msg {
                    Message::Binary(b) => b,
                    Message::Ping(p) => {
                        let _ = sink.send(Message::Pong(p)).await;
                        continue;
                    }
                    Message::Close(_) => break,
                    _ => continue,
                };

                if bin.len() < 5 {
                    continue;
                }
                let payload = &bin[4..]; // skip 4-byte length prefix
                let variant = payload[0];
                let body = &payload[1..];

                match variant {
                    // ── Ping ──
                    protocol::REQ_PING => {
                        let mut resp = Vec::with_capacity(5);
                        resp.extend_from_slice(&1u32.to_le_bytes());
                        resp.push(protocol::RESP_PONG);
                        let _ = sink.send(Message::Binary(resp.into())).await;
                    }

                    // ── GetInfo ──
                    protocol::REQ_GET_INFO => {
                        let info = OnionPirServerInfo {
                            index_bins_per_table: state.index_bins_per_table as u32,
                            chunk_bins_per_table: state.chunk_bins_per_table as u32,
                            index_k: K as u8,
                            chunk_k: K_CHUNK as u8,
                            tag_seed: state.tag_seed,
                            onionpir_entry_size: state.entry_size as u32,
                            onionpir_num_entries: state.padded_num_entries as u32,
                        };
                        let encoded = info.encode();
                        let _ = sink.send(Message::Binary(encoded.into())).await;
                    }

                    // ── Register Keys ──
                    REQ_REGISTER_KEYS => {
                        match RegisterKeysMsg::decode(body) {
                            Ok(keys_msg) => {
                                // Register with both index and chunk servers
                                let (tx0, rx0) = oneshot::channel();
                                let (tx1, rx1) = oneshot::channel();
                                let _ = state.pir_tx.send(PirCommand::RegisterKeys {
                                    client_id,
                                    level: 0,
                                    galois_keys: keys_msg.galois_keys.clone(),
                                    gsw_keys: keys_msg.gsw_keys.clone(),
                                    reply: tx0,
                                }).await;
                                let _ = rx0.await;
                                let _ = state.pir_tx.send(PirCommand::RegisterKeys {
                                    client_id,
                                    level: 1,
                                    galois_keys: keys_msg.galois_keys,
                                    gsw_keys: keys_msg.gsw_keys,
                                    reply: tx1,
                                }).await;
                                let _ = rx1.await;

                                // Send ack
                                let mut resp = Vec::with_capacity(5);
                                resp.extend_from_slice(&1u32.to_le_bytes());
                                resp.push(RESP_KEYS_ACK);
                                let _ = sink.send(Message::Binary(resp.into())).await;
                            }
                            Err(e) => {
                                eprintln!("[{}] Bad keys message: {}", peer, e);
                            }
                        }
                    }

                    // ── OnionPIR Index Query ──
                    REQ_ONIONPIR_INDEX_QUERY => {
                        match OnionPirBatchQuery::decode(body) {
                            Ok(batch) => {
                                let (tx, rx) = oneshot::channel();
                                let _ = state.pir_tx.send(PirCommand::AnswerBatch {
                                    client_id,
                                    level: 0,
                                    round_id: batch.round_id,
                                    queries: batch.queries,
                                    reply: tx,
                                }).await;
                                let results = rx.await.unwrap();
                                let result_msg = OnionPirBatchResult {
                                    round_id: batch.round_id,
                                    results,
                                };
                                let encoded = result_msg.encode(RESP_ONIONPIR_INDEX_RESULT);
                                let _ = sink.send(Message::Binary(encoded.into())).await;
                            }
                            Err(e) => {
                                eprintln!("[{}] Bad index query: {}", peer, e);
                            }
                        }
                    }

                    // ── OnionPIR Chunk Query ──
                    REQ_ONIONPIR_CHUNK_QUERY => {
                        match OnionPirBatchQuery::decode(body) {
                            Ok(batch) => {
                                let (tx, rx) = oneshot::channel();
                                let _ = state.pir_tx.send(PirCommand::AnswerBatch {
                                    client_id,
                                    level: 1,
                                    round_id: batch.round_id,
                                    queries: batch.queries,
                                    reply: tx,
                                }).await;
                                let results = rx.await.unwrap();
                                let result_msg = OnionPirBatchResult {
                                    round_id: batch.round_id,
                                    results,
                                };
                                let encoded = result_msg.encode(RESP_ONIONPIR_CHUNK_RESULT);
                                let _ = sink.send(Message::Binary(encoded.into())).await;
                            }
                            Err(e) => {
                                eprintln!("[{}] Bad chunk query: {}", peer, e);
                            }
                        }
                    }

                    v => {
                        eprintln!("[{}] Unknown request variant: 0x{:02x}", peer, v);
                    }
                }
            }

            println!("[{}] Disconnected (client_id={})", peer, client_id);
        });
    }
}
