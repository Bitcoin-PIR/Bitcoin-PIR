use crate::cli::{CliArgs, ServerRole};
use crate::io::*;
use crate::session_grant::is_query_bearing_variant;
use crate::state::UnifiedServerData;
use crate::unsafe_debug_log;
use futures_util::{SinkExt, StreamExt};
use runtime::protocol::*;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_tungstenite::accept_async_with_config;
use tokio_tungstenite::tungstenite::Message;
use zeroize::Zeroizing;

pub(crate) async fn serve_connections(
    args: &CliArgs,
    role_name: String,
    server: Arc<UnifiedServerData>,
) {
    let index_k = server.main_db().index.params.k;
    let chunk_k = server.main_db().chunk.params.k;
    let num_databases = server.state.databases.len();

    // ── Accept WebSocket connections ────────────────────────────────────

    // The default `[::]:port` preserves the production dual-stack behavior:
    // it accepts IPv6 and (where IPV6_V6ONLY=0) IPv4-mapped connections. An
    // explicit --bind-address lets operators and deterministic local tests
    // narrow the listener to one interface without a proxy or firewall trick.
    let addr = SocketAddr::new(args.bind_address, args.port);
    let listener = TcpListener::bind(addr).await.expect("bind");
    println!("Listening on ws://{}", addr);
    println!("  Role: {}", role_name);
    println!(
        "  Index: K={}, bins_per_table={}",
        index_k,
        server.main_db().index.bins_per_table
    );
    println!(
        "  Chunk: K={}, bins_per_table={}",
        chunk_k,
        server.main_db().chunk.bins_per_table
    );
    println!("  Databases: {}", num_databases);
    println!(
        "  OnionPIR: {}",
        if server.has_any_onionpir() {
            "enabled"
        } else if args.disable_onion {
            "disabled (--disable-onion)"
        } else if args.role == ServerRole::Secondary {
            "disabled (secondary role never loads OnionPIR)"
        } else {
            "disabled (no onion_*.bin files in any DB dir)"
        }
    );
    match args.role {
        ServerRole::Primary => println!("  HarmonyPIR: query server"),
        ServerRole::Secondary => println!("  HarmonyPIR: hint server"),
    }
    if server.main_db().has_bucket_merkle() {
        println!("  Merkle: available (per-bucket)");
    }
    println!();

    let client_counter = std::sync::atomic::AtomicU64::new(1);
    let connection_limiter = Arc::new(Semaphore::new(args.max_connections));
    let reassembly_limiter = Arc::new(Semaphore::new(MAX_GLOBAL_REASSEMBLY_BYTES));
    let websocket_handshake_timeout = Duration::from_millis(args.websocket_handshake_timeout_ms);
    let connection_idle_timeout = Duration::from_millis(args.connection_idle_timeout_ms);

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("Accept error: {}", e);
                continue;
            }
        };
        let connection_permit = match Arc::clone(&connection_limiter).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                // Drop before WebSocket parsing. The reverse proxy/edge is
                // expected to convert saturation into its normal retry path.
                drop(stream);
                continue;
            }
        };

        let client_id = client_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let server = Arc::clone(&server);
        let reassembly_limiter = Arc::clone(&reassembly_limiter);
        let role_name = role_name.clone();

        tokio::spawn(async move {
            let _connection_permit = connection_permit;
            #[allow(deprecated)]
            let ws_config = production_ws_config_v1();
            let ws = match tokio::time::timeout(
                websocket_handshake_timeout,
                accept_async_with_config(stream, Some(ws_config)),
            )
            .await
            {
                Ok(Ok(ws)) => ws,
                Ok(Err(e)) => {
                    unsafe_debug_log!("[{}] Handshake failed: {}", peer, e);
                    return;
                }
                Err(_) => {
                    unsafe_debug_log!("[{}] Handshake timed out", peer);
                    return;
                }
            };
            unsafe_debug_log!("[{}] Connected (id={})", peer, client_id);
            let (mut sink, mut ws_stream) = ws.split();

            // Per-connection admin auth state. Lives until the connection
            // drops; disconnecting is logging out.
            let mut admin_state = pir_runtime_core::admin::AdminConnectionState::default();

            // Per-connection encrypted-channel session. `None` until the
            // client sends REQ_HANDSHAKE; `Some` after we've derived the
            // session key. While Some, every outgoing response is sealed
            // (via send_resp below), and incoming frames whose first byte
            // is `pir_channel::ENCRYPTED_FRAME_MAGIC` are decrypted at the
            // top of the dispatch loop.
            //
            // We KEEP cleartext support per-frame even after the session
            // is established — a client can mix cleartext probes (e.g.
            // REQ_PING) with encrypted PIR queries on the same socket.
            // Privacy-conscious clients (the browser SDK) wrap every
            // application frame; legacy clients keep working.
            let mut channel_session: Option<pir_runtime_core::channel::Session> = None;

            // Per-connection session grant: the id of the last grant this
            // client presented successfully (REQ_SESSION_GRANT_PRESENT).
            // Credits live in the server-wide ledger, not here.
            let mut session_grant: Option<pir_session_grant::GrantId> = None;

            // Per-connection transport-level chunk reassembly state. A
            // client that sends a multi-MB message (OnionPIR RegisterKeys
            // / query batches) splits it into CHUNK_MAGIC frames; we
            // reassemble before dispatch. `client_supports_chunks` flips
            // true on the first chunk frame seen and gates whether the
            // server chunks its (large) responses back.
            let mut chunk_acc: Vec<u8> = Vec::new();
            let mut chunk_expected: u16 = 0;
            let mut chunk_total: u16 = 0;
            let mut chunk_permits = Vec::new();
            let mut client_supports_chunks = false;

            loop {
                let Some(msg) =
                    (match tokio::time::timeout(connection_idle_timeout, ws_stream.next()).await {
                        Ok(message) => message,
                        Err(_) => {
                            unsafe_debug_log!("[{}] idle timeout", peer);
                            break;
                        }
                    })
                else {
                    break;
                };
                let msg = match msg {
                    Ok(m) => m,
                    Err(e) => {
                        unsafe_debug_log!("[{}] Read error: {}", peer, e);
                        break;
                    }
                };
                let raw_bin = match msg {
                    Message::Binary(b) => b,
                    Message::Ping(p) => {
                        // Control traffic cannot keep a partial upload alive.
                        chunk_acc.clear();
                        chunk_permits.clear();
                        chunk_expected = 0;
                        {
                            match tokio::time::timeout(
                                connection_idle_timeout,
                                sink.send(Message::Pong(p)),
                            )
                            .await
                            {
                                Ok(Ok(())) => {}
                                Ok(Err(_)) | Err(_) => break,
                            }
                        }
                        continue;
                    }
                    Message::Close(_) => break,
                    _ => {
                        chunk_acc.clear();
                        chunk_permits.clear();
                        chunk_expected = 0;
                        continue;
                    }
                };

                // Transport-level chunk reassembly. A chunk frame is
                // `[4B len][CHUNK_MAGIC][seq:u16][total:u16][piece]`; a
                // normal message never carries CHUNK_MAGIC at offset 4.
                let mut completed_chunk_permits = Vec::new();
                let bin: Vec<u8> = if raw_bin.len() >= 4 + CHUNK_HDR && raw_bin[4] == CHUNK_MAGIC {
                    client_supports_chunks = true;
                    let seq = u16::from_le_bytes([raw_bin[5], raw_bin[6]]);
                    let total = u16::from_le_bytes([raw_bin[7], raw_bin[8]]);
                    let declared = usize::try_from(u32::from_le_bytes([
                        raw_bin[0], raw_bin[1], raw_bin[2], raw_bin[3],
                    ]))
                    .unwrap_or(usize::MAX);
                    let allowed_reassembled = MAX_REASSEMBLED;
                    if declared != raw_bin.len().saturating_sub(4)
                        || total == 0
                        || usize::from(total) > MAX_CHUNK_FRAMES
                        || seq >= total
                        || seq != chunk_expected
                    {
                        unsafe_debug_log!(
                            "[{}] bad chunk frame (seq={} total={} expected={}) — closing",
                            peer,
                            seq,
                            total,
                            chunk_expected
                        );
                        break;
                    }
                    if seq == 0 {
                        chunk_total = total;
                        chunk_acc.clear();
                        chunk_permits.clear();
                    } else if total != chunk_total {
                        unsafe_debug_log!("[{}] chunk total changed mid-stream — closing", peer);
                        break;
                    }
                    let piece = &raw_bin[4 + CHUNK_HDR..];
                    let Some(next_len) = chunk_acc.len().checked_add(piece.len()) else {
                        break;
                    };
                    if piece.is_empty() || next_len > allowed_reassembled {
                        unsafe_debug_log!(
                            "[{}] reassembled message exceeds active cap — closing",
                            peer
                        );
                        break;
                    }
                    let Ok(piece_permits) = u32::try_from(piece.len()) else {
                        break;
                    };
                    let permit = match Arc::clone(&reassembly_limiter)
                        .try_acquire_many_owned(piece_permits)
                    {
                        Ok(permit) => permit,
                        Err(_) => {
                            unsafe_debug_log!("[{}] global reassembly budget exhausted", peer);
                            break;
                        }
                    };
                    if chunk_acc.try_reserve(piece.len()).is_err() {
                        unsafe_debug_log!("[{}] reassembly allocation failed", peer);
                        break;
                    }
                    chunk_acc.extend_from_slice(piece);
                    chunk_permits.push(permit);
                    chunk_expected += 1;
                    if chunk_expected < chunk_total {
                        continue; // wait for the next chunk frame
                    }
                    chunk_expected = 0;
                    completed_chunk_permits = std::mem::take(&mut chunk_permits);
                    std::mem::take(&mut chunk_acc)
                } else {
                    if !chunk_acc.is_empty() {
                        unsafe_debug_log!("[{}] non-chunk frame interrupted chunk upload", peer);
                        break;
                    }
                    raw_bin
                };
                // Hold process-wide permits until this request has completed
                // decoding and backend dispatch; early `continue` paths drop
                // them automatically.
                let _completed_chunk_permits = completed_chunk_permits;

                if bin.len() < 5 {
                    continue;
                }
                let outer_payload = &bin[4..];

                // Encrypted-frame demux. If the first byte is the channel
                // magic AND we have an established session, open the frame
                // and dispatch the inner request as if it were cleartext.
                // If the magic appears but no session is established, that's
                // a protocol error (clients must REQ_HANDSHAKE first).
                let decrypted: Zeroizing<Vec<u8>>;
                let request_was_encrypted = outer_payload.first()
                    == Some(&pir_runtime_core::channel::ENCRYPTED_FRAME_MAGIC);
                let payload: &[u8] = if request_was_encrypted {
                    match channel_session.as_mut() {
                        Some(s) => {
                            match s.open(
                                pir_runtime_core::channel::Direction::ClientToServer,
                                outer_payload,
                            ) {
                                Ok(buf) => {
                                    decrypted = Zeroizing::new(buf);
                                    decrypted.as_slice()
                                }
                                Err(e) => {
                                    unsafe_debug_log!("[{}] channel open failed: {}", peer, e);
                                    let err =
                                        Response::Error(format!("channel open failed: {}", e));
                                    let _ = send_resp(
                                        &mut sink,
                                        channel_session.as_mut(),
                                        err.encode(),
                                    )
                                    .await;
                                    continue;
                                }
                            }
                        }
                        None => {
                            unsafe_debug_log!(
                                "[{}] received encrypted frame without established session",
                                peer
                            );
                            let err = Response::Error("encrypted frame received but no session established (run REQ_HANDSHAKE first)".into());
                            let _ =
                                send_resp(&mut sink, channel_session.as_mut(), err.encode()).await;
                            continue;
                        }
                    }
                } else {
                    outer_payload
                };

                if payload.is_empty() {
                    continue;
                }
                let variant = payload[0];

                // Mode gate: reject hint or query requests this server isn't
                // configured for (`--serve-hints` / `--serve-queries` flags).
                // Whitelisted opcodes (info / ping / attest / handshake /
                // credential / admin / db-catalog) always pass —
                // they don't expose hint or query content, only metadata
                // needed for clients to discover the server's capabilities.
                if !server.serve_hints {
                    match variant {
                        REQ_HARMONY_HINTS | REQ_HARMONY_HINTS_V2 | REQ_HARMONY_HINTS_V2_HALF => {
                            let resp = Response::Error(
                                "server not configured to serve hints — start with --serve-hints (see deploy/systemd/*.service)".into(),
                            );
                            let _ =
                                send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            continue;
                        }
                        _ => {}
                    }
                }
                if !server.serve_queries && is_query_bearing_variant(variant) {
                    let resp = Response::Error(
                        "server not configured to answer queries — start with --serve-queries (see deploy/systemd/*.service)".into(),
                    );
                    let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                    continue;
                }

                // Session-grant gate: query-bearing variants spend one credit
                // of the presented grant, or are refused when grants are
                // required and none was presented. Runs after the mode gates
                // so a frame this host does not serve never costs a credit.
                if let Some(gate) = server.session_grants.as_ref() {
                    if is_query_bearing_variant(variant) {
                        let refusal = match session_grant {
                            Some(grant_id) => current_unix_seconds_v1()
                                .and_then(|now| gate.consume(&grant_id, now))
                                .err(),
                            None if gate.require() => Some(
                                "session grant required — send REQ_SESSION_GRANT_PRESENT first"
                                    .to_owned(),
                            ),
                            None => None,
                        };
                        if let Some(message) = refusal {
                            let resp = Response::Error(message);
                            let _ =
                                send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            continue;
                        }
                    }
                }

                crate::dispatch::handle_variant(
                    payload,
                    &mut sink,
                    &mut channel_session,
                    Arc::clone(&server),
                    request_was_encrypted,
                    &role_name,
                    client_id,
                    peer,
                    &mut admin_state,
                    &mut session_grant,
                    client_supports_chunks,
                )
                .await;
            }

            unsafe_debug_log!("[{}] Disconnected (id={})", peer, client_id);
        });
    }
}
