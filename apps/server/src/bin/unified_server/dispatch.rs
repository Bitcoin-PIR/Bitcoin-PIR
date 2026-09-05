use crate::harmony_hints::*;
use crate::io::*;
use crate::onion::PirCommand;
use crate::state::{UnifiedServerData, V2HalfPending};
use crate::unsafe_debug_log;
use rayon::prelude::*;
use runtime::hint_pool;
use runtime::onionpir::*;
use runtime::protocol::*;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::Message;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_variant<S>(
    payload: &[u8],
    sink: &mut S,
    channel_session: &mut Option<pir_runtime_core::channel::Session>,
    server: Arc<UnifiedServerData>,
    request_was_encrypted: bool,
    role_name: &str,
    client_id: u64,
    peer: std::net::SocketAddr,
    admin_state: &mut pir_runtime_core::admin::AdminConnectionState,
    session_grant: &mut Option<pir_session_grant::GrantId>,
    client_supports_chunks: bool,
) where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let variant = payload[0];
    let body = &payload[1..];
    // Route by variant byte
    match variant {
                    // ── Shared: info / ping ──────────────────────────────
                    REQ_PING => {
                        let _ = send_resp(sink, channel_session.as_mut(), Response::Pong.encode()).await;
                    }
                    REQ_GET_INFO => {
                        let _ = send_resp(sink, channel_session.as_mut(), Response::Info(server.server_info()).encode()).await;
                    }
                    0x03 /* REQ_GET_INFO_JSON */ => {
                        let _ = send_resp(sink, channel_session.as_mut(), server.encode_info_json_response(0x03)).await;
                    }
                    // 0x33 was REQ_ONIONPIR_GET_INFO (binary ServerInfoV2), now removed.
                    // All clients should use 0x03 (JSON) instead.
                    REQ_GET_DB_CATALOG => {
                        let _ = send_resp(sink, channel_session.as_mut(), Response::DbCatalog(server.build_catalog()).encode()).await;
                    }
                    REQ_GET_DB_PROOF => {
                        if body.len() != 1 {
                            let resp = Response::Error(
                                "malformed REQ_GET_DB_PROOF: expected one db_id byte".into(),
                            );
                            let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                            return;
                        }
                        let db_id = body[0];
                        let resp = match server
                            .state
                            .get_db(db_id)
                            .and_then(|db| db.db_proof.as_ref())
                        {
                            Some(bundle) => Response::DbProof(bundle.clone()),
                            None => Response::Error(format!(
                                "db proof not configured for db_id {}",
                                db_id
                            )),
                        };
                        let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                    }
                    REQ_GET_DB_PROOF_V2 => {
                        if body.len() != 1 {
                            let resp = Response::Error(
                                "malformed REQ_GET_DB_PROOF_V2: expected one db_id byte".into(),
                            );
                            let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                            return;
                        }
                        let db_id = body[0];
                        let resp = match server
                            .state
                            .get_db(db_id)
                            .and_then(|db| db.db_proof_v2.as_ref())
                        {
                            Some(bundle) => Response::DbProofV2(bundle.clone()),
                            None => Response::Error(format!(
                                "db proof v2 not configured for db_id {}",
                                db_id
                            )),
                        };
                        let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                    }
                    REQ_SESSION_GRANT_PRESENT => {
                        // Wire format: [1B variant=0x0b][133B session grant]
                        let resp = match server.session_grants.as_ref() {
                            None => Response::Error(
                                "session grants not enabled on this server".into(),
                            ),
                            Some(gate) => match current_unix_seconds_v1()
                                .and_then(|now| gate.present(body, now))
                            {
                                Ok((grant_id, remaining_credits)) => {
                                    *session_grant = Some(grant_id);
                                    Response::SessionGrantOk { remaining_credits }
                                }
                                Err(message) => {
                                    *session_grant = None;
                                    Response::Error(message)
                                }
                            },
                        };
                        let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                    }
                    REQ_ADMIN_AUTH_CHALLENGE => {
                        match server.admin_config {
                            None => {
                                let resp = Response::Error("admin auth disabled (server started without --admin-pubkey-hex)".into());
                                let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                            }
                            Some(_) => {
                                let nonce = admin_state.issue_challenge();
                                let resp = Response::AdminAuthChallenge(
                                    pir_runtime_core::protocol::AdminAuthChallenge { nonce },
                                );
                                let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                            }
                        }
                    }
                    REQ_ADMIN_AUTH_RESPONSE => {
                        let cfg = match server.admin_config.as_ref() {
                            Some(c) => c,
                            None => {
                                let resp = Response::Error("admin auth disabled".into());
                                let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                                return;
                            }
                        };
                        let signature = if let Ok(Request::AdminAuthResponse { signature }) = Request::decode(payload) {
                            signature
                        } else {
                            let resp = Response::Error("malformed REQ_ADMIN_AUTH_RESPONSE".into());
                            let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                            return;
                        };
                        let result = match admin_state.verify_response(&signature, cfg) {
                            Ok(()) => {
                                println!("admin authenticated");
                                pir_runtime_core::protocol::AdminAuthResult { ok: true, msg: "ok".into() }
                            }
                            Err(e) => {
                                eprintln!("admin auth failed: {}", e);
                                pir_runtime_core::protocol::AdminAuthResult { ok: false, msg: e.to_string() }
                            }
                        };
                        let _ = send_resp(sink, channel_session.as_mut(), Response::AdminAuthResponse(result).encode()).await;
                    }
                    REQ_ADMIN_DB_UPLOAD_BEGIN | REQ_ADMIN_DB_UPLOAD_CHUNK
                    | REQ_ADMIN_DB_UPLOAD_FINALIZE | REQ_ADMIN_DB_ACTIVATE => {
                        if !admin_state.authenticated {
                            let resp = Response::Error("not authenticated; complete REQ_ADMIN_AUTH_* first".into());
                            let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                            return;
                        }
                        let req = match Request::decode(payload) {
                            Ok(r) => r,
                            Err(e) => {
                                let resp = Response::Error(format!("decode admin request: {}", e));
                                let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                                return;
                            }
                        };
                        let resp = match req {
                            Request::AdminDbUploadBegin { name, manifest_toml } => {
                                let r = match admin_state.begin_upload(name.clone(), manifest_toml, &server.data_root) {
                                    Ok(()) => {
                                        println!("admin upload BEGIN {:?}", name);
                                        pir_runtime_core::protocol::AdminAck { ok: true, msg: "ok".into() }
                                    }
                                    Err(e) => {
                                        eprintln!("admin upload BEGIN failed: {}", e);
                                        pir_runtime_core::protocol::AdminAck { ok: false, msg: e.to_string() }
                                    }
                                };
                                Response::AdminDbUploadBegin(r)
                            }
                            Request::AdminDbUploadChunk { name, file_path, offset, data } => {
                                let r = match admin_state.write_chunk(&name, &file_path, offset, &data) {
                                    Ok(()) => pir_runtime_core::protocol::AdminAck { ok: true, msg: "ok".into() },
                                    Err(e) => pir_runtime_core::protocol::AdminAck { ok: false, msg: e.to_string() },
                                };
                                Response::AdminDbUploadChunk(r)
                            }
                            Request::AdminDbUploadFinalize { name } => {
                                let r = match admin_state.finalize_upload(&name) {
                                    Ok(root) => pir_runtime_core::protocol::AdminFinalizeResult {
                                        ok: true,
                                        msg: "verified".into(),
                                        manifest_root: root,
                                    },
                                    Err(e) => pir_runtime_core::protocol::AdminFinalizeResult {
                                        ok: false,
                                        msg: e.to_string(),
                                        manifest_root: [0u8; 32],
                                    },
                                };
                                Response::AdminDbUploadFinalize(r)
                            }
                            Request::AdminDbActivate { name, target_path } => {
                                let r = match admin_state.activate(&name, &target_path, &server.data_root) {
                                    Ok(()) => {
                                        println!(
                                            "admin ACTIVATE {:?} → {:?} (restart server to load)",
                                            name, target_path
                                        );
                                        pir_runtime_core::protocol::AdminAck {
                                            ok: true,
                                            msg: "activated; restart server to load".into(),
                                        }
                                    }
                                    Err(e) => pir_runtime_core::protocol::AdminAck { ok: false, msg: e.to_string() },
                                };
                                Response::AdminDbActivate(r)
                            }
                            _ => unreachable!("variant byte already filtered"),
                        };
                        let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                    }
                    REQ_ATTEST => {
                        if let Ok(Request::Attest { nonce }) = Request::decode(payload) {
                            let s = Arc::clone(&server);
                            let resp = tokio::task::spawn_blocking(move || {
                                use pir_runtime_core::attest;
                                let manifest_roots: Vec<[u8; 32]> = s.state.databases.iter()
                                    .map(|db| db.manifest_root.unwrap_or([0u8; 32]))
                                    .collect();
                                let binary_sha256 = attest::self_exe_sha256();
                                let server_static_pub = s.state.server_static_pub;
                                let git_rev = attest::GIT_REV;
                                let report_data = attest::build_report_data(
                                    nonce,
                                    &manifest_roots,
                                    binary_sha256,
                                    server_static_pub,
                                    git_rev,
                                );
                                let sev_snp_report = attest::fetch_report(report_data)
                                    .ok().flatten().unwrap_or_default();
                                Response::Attest(pir_runtime_core::protocol::AttestResult {
                                    sev_snp_report,
                                    manifest_roots,
                                    binary_sha256,
                                    server_static_pub,
                                    git_rev: git_rev.to_string(),
                                    ark_pem: s.state.ark_pem.clone(),
                                    ask_pem: s.state.ask_pem.clone(),
                                    vcek_pem: s.state.vcek_pem.clone(),
                                })
                            }).await.unwrap();
                            let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                        }
                    }
                    REQ_ANNOUNCE => {
                        // Operator-signed identity bundle, built at startup
                        // into `ServerState.announcement_bundle` when the
                        // --identity-* flags are set. `None` means the server
                        // lacks an identity key / operator cert.
                        let resp = build_announce_response(&server.state.announcement_bundle);
                        let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                    }
                    REQ_HANDSHAKE => {
                        // Encrypted-channel handshake. The reply MUST go out
                        // in cleartext — the client doesn't have the session
                        // key until it processes RESP_HANDSHAKE. So we mint
                        // the Session AFTER the send, and the next inbound
                        // frame the client sends will be encrypted.
                        if channel_session.is_some() {
                            let err = Response::Error(
                                "secure channel is already established on this connection".into(),
                            );
                            let _ = send_resp(
                                sink,
                                channel_session.as_mut(),
                                err.encode(),
                            )
                            .await;
                            return;
                        }
                        if let Ok(Request::Handshake { client_eph_pub, nonce }) = Request::decode(payload) {
                            let server_hs = server.channel_keypair.new_handshake();
                            let server_eph_pub = server_hs.server_eph_pub();
                            let new_session = server_hs.complete_handshake(&client_eph_pub, &nonce);
                            let resp = Response::Handshake(
                                pir_runtime_core::protocol::HandshakeResult { server_eph_pub },
                            );
                            // Cleartext send (force `None` so send_resp doesn't seal).
                            if let Err(error) = send_resp(sink, None, resp.encode()).await {
                                unsafe_debug_log!(
                                    "[{}] handshake response send failed: {}",
                                    peer,
                                    error
                                );
                                return;
                            }
                            // Now switch the connection into encrypted mode for
                            // all subsequent client→server and server→client
                            // frames.
                            *channel_session = Some(new_session);
                        } else {
                            let err = Response::Error(
                                "malformed REQ_HANDSHAKE (expected client_eph_pub:32 + nonce:32)".into(),
                            );
                            let _ = send_resp(sink, channel_session.as_mut(), err.encode()).await;
                        }
                    }
                    // ── DPF batch queries (both roles) ──────────────────
                    REQ_INDEX_BATCH => {
                        if let Ok(Request::IndexBatch(q)) = Request::decode(payload) {
                            let s = Arc::clone(&server);
                            let resp = tokio::task::spawn_blocking(move || {
                                let db = match s.state.get_db(q.db_id) {
                                    Some(db) => db,
                                    None => return Response::Error(format!("unknown db_id {}", q.db_id)),
                                };
                                let t = Instant::now();
                                let n = q.keys.len();
                                let (batch, dpf_sum, fetch_sum) = s.process_index_batch(&q, db);
                                let wall = t.elapsed();
                                unsafe_debug_log!("[index] db={} {} groups {:.2?} | dpf {:.2?} fetch+xor {:.2?}", q.db_id, n, wall, dpf_sum, fetch_sum);
                                Response::IndexBatch(batch)
                            }).await.unwrap();
                            let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                        }
                    }
                    REQ_CHUNK_BATCH => {
                        if let Ok(Request::ChunkBatch(q)) = Request::decode(payload) {
                            let s = Arc::clone(&server);
                            let resp = tokio::task::spawn_blocking(move || {
                                let db = match s.state.get_db(q.db_id) {
                                    Some(db) => db,
                                    None => return Response::Error(format!("unknown db_id {}", q.db_id)),
                                };
                                let t = Instant::now();
                                let n = q.keys.len();
                                let round = q.round_id;
                                let (batch, dpf_sum, fetch_sum) = s.process_chunk_batch(&q, db);
                                let wall = t.elapsed();
                                unsafe_debug_log!("[chunk] db={} r{} {} groups {:.2?} | dpf {:.2?} fetch+xor {:.2?}", q.db_id, round, n, wall, dpf_sum, fetch_sum);
                                Response::ChunkBatch(batch)
                            }).await.unwrap();
                            let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                        }
                    }

                    // (0x31 REQ_MERKLE_SIBLING_BATCH / 0x32 REQ_MERKLE_TREE_TOP
                    //  retired — legacy global N-ary tree Merkle. The per-bucket
                    //  bin Merkle arms below are the active scheme.)

                    // ── Per-bucket bin Merkle sibling batch queries ──────
                    REQ_BUCKET_MERKLE_SIB_BATCH => {
                        if let Ok(Request::BucketMerkleSibBatch(q)) = Request::decode(payload) {
                            let s = Arc::clone(&server);
                            let resp = tokio::task::spawn_blocking(move || {
                                let db = match s.state.get_db(q.db_id) {
                                    Some(db) if db.has_bucket_merkle() => db,
                                    _ => return Response::Error(format!("db {} has no bucket merkle", q.db_id)),
                                };
                                let t = Instant::now();
                                let n = q.keys.len();
                                // round_id encodes: table_type * 100 + level
                                let table_type = q.round_id / 100;
                                let level = (q.round_id % 100) as usize;
                                let sib_tables = if table_type == 0 {
                                    &db.bucket_merkle_index_siblings
                                } else {
                                    &db.bucket_merkle_chunk_siblings
                                };
                                if level >= sib_tables.len() {
                                    return Response::Error(format!("bucket merkle: invalid level {}", level));
                                }
                                let sib = &sib_tables[level];
                                let (batch, dpf_sum, fetch_sum) = s.process_generic_batch(&q, sib);
                                let wall = t.elapsed();
                                unsafe_debug_log!("[bkt-merkle-sib] db={} T{} L{} {} groups {:.2?} | dpf {:.2?} fetch {:.2?}",
                                    q.db_id, table_type, level, n, wall, dpf_sum, fetch_sum);
                                Response::BucketMerkleSibBatch(batch)
                            }).await.unwrap();
                            let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                        }
                    }

                    // ── Per-bucket Merkle tree-tops fetch ────────────────
                    REQ_BUCKET_MERKLE_TREE_TOPS => {
                        // Optional db_id byte: payload[1] if present, else 0.
                        let db_id = if payload.len() > 1 { payload[1] } else { 0 };
                        let db = server.state.get_db(db_id);
                        let tops = db.and_then(|d| d.bucket_merkle_tree_tops.as_ref());
                        if let Some(tops) = tops {
                            let payload_len = 1 + tops.len();
                            let mut msg = Vec::with_capacity(4 + payload_len);
                            msg.extend_from_slice(&(payload_len as u32).to_le_bytes());
                            msg.push(RESP_BUCKET_MERKLE_TREE_TOPS);
                            msg.extend_from_slice(tops);
                            // Tree-top blobs for the live main database are
                            // larger than a browser-safe WebSocket frame.
                            // All current SDK transports reassemble the
                            // shared CHUNK_MAGIC envelope, so use it here
                            // unconditionally rather than allowing a large
                            // single-frame write to stall until the
                            // pre-authorization deadline.
                            if let Err(error) = send_resp_chunked(
                                sink,
                                channel_session.as_mut(),
                                msg,
                                true,
                            )
                            .await
                            {
                                unsafe_debug_log!(
                                    "[{}] bucket Merkle tree-tops send error: {}",
                                    peer,
                                    error
                                );
                                return;
                            }
                            unsafe_debug_log!("[bkt-merkle-tops] db={} sent {} bytes", db_id, tops.len());
                        } else {
                            let err = Response::Error(format!("db {} has no bucket merkle tree-tops", db_id));
                            let _ = send_resp(sink, channel_session.as_mut(), err.encode()).await;
                        }
                    }

                    // ── HarmonyPIR ────────────────────────────────────────
                    // Both roles respond to ALL HarmonyPIR ops. The
                    // role flag controls only OnionPIR loading at startup
                    // (and `--disable-onion` overrides even that). The
                    // CLIENT decides which server to send hint requests
                    // vs query requests to — the protocol's two-server
                    // non-collusion guarantee comes from picking
                    // independent endpoints, not from server-side dispatch
                    // gating. This decoupling lets operators allocate
                    // workload (hint is ~6× CPU of query per Hetzner
                    // production stats) to whichever endpoint has the
                    // matching hardware capacity, without re-rolling the
                    // role flag and the systemd unit.
                    REQ_HARMONY_GET_INFO => {
                        let _ = send_resp(
                            sink,
                            channel_session.as_mut(),
                            Response::HarmonyInfo(server.server_info()).encode(),
                        ).await;
                    }
                    REQ_HARMONY_HINTS => {
                        if let Ok(Request::HarmonyHints(hint_req)) = Request::decode(payload) {
                            let t_start = Instant::now();
                            let level = hint_req.level;
                            let num = hint_req.group_ids.len();
                            let prp_key: [u8; 16] = hint_req.prp_key;
                            let prp_backend = hint_req.prp_backend;
                            let group_ids = hint_req.group_ids.clone();
                            let db_id = hint_req.db_id;
                            if let Err(msg) = hint_pool::validate_prp_backend(prp_backend) {
                                let resp = Response::Error(msg);
                                let _ = send_resp(
                                    sink,
                                    channel_session.as_mut(),
                                    resp.encode(),
                                )
                                .await;
                                return;
                            }
                            // Validate backend, db_id, level, and group_ids before
                            // spawning blocking work — all four come off
                            // the wire (S4: an out-of-range group_id or
                            // unknown level previously panicked inside the
                            // rayon pool, aborting the whole server).
                            match server.state.get_db(db_id) {
                                None => {
                                    let resp = Response::Error(format!("unknown db_id {}", db_id));
                                    let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                                    return;
                                }
                                Some(db) => {
                                    if let Err(msg) = validate_harmony_hints_request(db, level, &group_ids) {
                                        let resp = Response::Error(msg);
                                        let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                                        return;
                                    }
                                }
                            }
                            let s = Arc::clone(&server);

                            let (tx, mut rx) = tokio::sync::mpsc::channel::<(u8, u32, u32, u32, Vec<u8>)>(4);
                            tokio::task::spawn_blocking(move || {
                                let db = s.state.get_db(db_id).expect("db_id checked before spawn");
                                group_ids.par_iter().for_each_with(tx, |tx, &bid| {
                                    // Validated above; an Err here would only
                                    // drop this group's record, not the process.
                                    if let Ok(result) = compute_hints_for_group(db, &prp_key, prp_backend, level, bid) {
                                        let _ = tx.blocking_send(result);
                                    }
                                });
                            });

                            // Coalesce per-group records into ~HINT_BATCH_BYTES
                            // WS messages so the browser sees ~30 onmessage
                            // events instead of `num` (~155). Each record
                            // retains its per-record `[4B len][body]`
                            // framing inside the buffer (sealed
                            // individually if the channel is active) so
                            // the client's existing one-record-per-recv()
                            // contract holds — see `send_resp_batch` and
                            // `WsConnection::recv` for the demux.
                            let mut sent = 0;
                            let mut batches = 0usize;
                            let mut pending: Vec<Vec<u8>> = Vec::new();
                            let mut pending_bytes = 0usize;
                            while let Some((group_id, n, t, m, flat_hints)) = rx.recv().await {
                                let hint_len = 1 + 1 + 4 + 4 + 4 + flat_hints.len();
                                let mut record = Vec::with_capacity(4 + hint_len);
                                record.extend_from_slice(&(hint_len as u32).to_le_bytes());
                                record.push(RESP_HARMONY_HINTS);
                                record.push(group_id);
                                record.extend_from_slice(&n.to_le_bytes());
                                record.extend_from_slice(&t.to_le_bytes());
                                record.extend_from_slice(&m.to_le_bytes());
                                record.extend_from_slice(&flat_hints);
                                pending_bytes += record.len();
                                pending.push(record);
                                if pending_bytes >= HINT_BATCH_BYTES {
                                    let batch = std::mem::take(&mut pending);
                                    pending_bytes = 0;
                                    if let Err(e) = send_resp_batch(sink, channel_session.as_mut(), batch).await {
                                        unsafe_debug_log!("[{}] Send error: {}", peer, e);
                                        break;
                                    }
                                    batches += 1;
                                }
                                sent += 1;
                            }
                            if !pending.is_empty() {
                                if let Err(e) = send_resp_batch(sink, channel_session.as_mut(), pending).await {
                                    unsafe_debug_log!("[{}] Final-batch send error: {}", peer, e);
                                } else {
                                    batches += 1;
                                }
                            }
                            unsafe_debug_log!("[harmony-hint] db={} L{} {}/{} groups in {:.2?} ({} WS batches)",
                                db_id, level, sent, num, t_start.elapsed(), batches);
                        }
                    }
                    REQ_HARMONY_HINTS_V2 => {
                        // V2: server generates PRP key, serves pre-computed frames from pool.
                        let t_start = Instant::now();
                        let v2_req = match Request::decode(payload) {
                            Ok(Request::HarmonyHintsV2(h)) => h,
                            Ok(other) => {
                                let resp = Response::Error(format!("unexpected request type for V2 hints: {:?}", other));
                                let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                                return;
                            }
                            Err(e) => {
                                let resp = Response::Error(format!("V2 hint request decode error: {}", e));
                                let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                                return;
                            }
                        };
                        let db_id = v2_req.db_id;
                        if server.state.get_db(db_id).is_none() {
                            let resp = Response::Error(format!("unknown db_id {}", db_id));
                            let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                            return;
                        }

                        let pool = match server.hint_pools.get(&db_id) {
                            Some(pool) => pool,
                            None => {
                                let resp = Response::Error(
                                    format!("V2 hints not available for db_id {db_id}")
                                );
                                let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                                return;
                            }
                        };

                        let entry = match pool.try_take() {
                            Some(entry) => entry,
                            None => {
                                let resp = Response::Error(
                                    "V2 hint pool temporarily empty/unavailable".into(),
                                );
                                let _ = send_resp(
                                    sink,
                                    channel_session.as_mut(),
                                    resp.encode(),
                                )
                                .await;
                                return;
                            }
                        };

                        // 1. Send key preamble as its own (small) WS Binary
                        //    message — keeps the existing wire shape for the
                        //    preamble + makes the client's first recv()
                        //    return just the preamble. (The client picks the
                        //    PRP key out of it before building HarmonyGroup
                        //    instances.)
                        if let Err(e) = send_resp(sink, channel_session.as_mut(), entry.key_preamble.clone()).await {
                            unsafe_debug_log!("[{}] V2 preamble send error: {}", peer, e);
                            return;
                        }

                        // 2. Coalesce INDEX + CHUNK frames into
                        //    ~HINT_BATCH_BYTES WS messages. Each record
                        //    retains its per-record `[4B len][body]`
                        //    framing (sealed individually if the channel
                        //    is on) so the client's
                        //    one-record-per-recv() contract holds — see
                        //    `send_resp_batch` + `WsConnection::recv`
                        //    for the demux. A typical pool entry's ~155
                        //    frames now flush as ~10 WS messages
                        //    instead of 155.
                        let mut sent = 0usize;
                        let mut batches = 0usize;
                        let mut pending: Vec<Vec<u8>> = Vec::new();
                        let mut pending_bytes = 0usize;
                        let frame_iter = entry.index_frames.iter().chain(entry.chunk_frames.iter());
                        for frame in frame_iter {
                            pending_bytes += frame.len();
                            pending.push(frame.clone());
                            if pending_bytes >= HINT_BATCH_BYTES {
                                let batch = std::mem::take(&mut pending);
                                pending_bytes = 0;
                                if let Err(e) = send_resp_batch(sink, channel_session.as_mut(), batch).await {
                                    unsafe_debug_log!("[{}] V2 frame batch send error: {}", peer, e);
                                    break;
                                }
                                batches += 1;
                            }
                            sent += 1;
                        }
                        if !pending.is_empty() {
                            if let Err(e) = send_resp_batch(sink, channel_session.as_mut(), pending).await {
                                unsafe_debug_log!("[{}] V2 final-batch send error: {}", peer, e);
                            } else {
                                batches += 1;
                            }
                        }

                        // 3. Terminal sentinel: group_id=0xFF signals
                        //    end-of-stream. Sent as its own (small) message
                        //    so the client's last recv() returns just the
                        //    sentinel, matching the legacy unbatched shape.
                        let terminal_len: u32 = 1 + 1; // variant + group_id
                        let mut terminal = Vec::with_capacity(4 + terminal_len as usize);
                        terminal.extend_from_slice(&terminal_len.to_le_bytes());
                        terminal.push(RESP_HARMONY_HINTS);
                        terminal.push(0xFFu8);
                        let _ = send_resp(sink, channel_session.as_mut(), terminal).await;

                        let elapsed = t_start.elapsed();
                        unsafe_debug_log!(
                            "[harmony-hint-v2] db={} {} groups served from pool ({} WS batches) in {:.2?}",
                            db_id, sent, batches, elapsed,
                        );
                    }
                    REQ_HARMONY_HINTS_V2_HALF => {
                        // Half-stream V2: serve INDEX (side=0) or CHUNK
                        // (side=1) frames from a pool entry shared with
                        // a matching session_token request.
                        let t_start = Instant::now();
                        let v2half_req = match Request::decode(payload) {
                            Ok(Request::HarmonyHintsV2Half(h)) => h,
                            Ok(other) => {
                                let resp = Response::Error(format!(
                                    "unexpected request type for V2 half hints: {:?}",
                                    other
                                ));
                                let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                                return;
                            }
                            Err(e) => {
                                let resp = Response::Error(format!(
                                    "V2 half hint request decode error: {}",
                                    e
                                ));
                                let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                                return;
                            }
                        };
                        let db_id = v2half_req.db_id;
                        if server.state.get_db(db_id).is_none() {
                            let resp =
                                Response::Error(format!("unknown db_id {}", db_id));
                            let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                            return;
                        }

                        let pool = match server.hint_pools.get(&db_id) {
                            Some(pool) => pool,
                            None => {
                                let resp = Response::Error(
                                    format!("V2 half hints not available for db_id {db_id}"),
                                );
                                let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                                return;
                            }
                        };

                        let token = v2half_req.session_token;
                        let side = v2half_req.side;
                        let side_bit: u8 = 1 << side;

                        // Look up (or allocate) the pending entry for
                        // this token. Held under one short critical
                        // section — we drop the lock before serving
                        // frames because send/feed yield the task.
                        let entry_arc: Arc<hint_pool::PoolEntry> = {
                            let mut map = server.v2_half_pending.lock().await;
                            match map.get_mut(&token) {
                                Some(pend) => {
                                    if let Err(message) =
                                        validate_harmony_v2_half_database(pend.db_id, db_id)
                                    {
                                        drop(map);
                                        let resp = Response::Error(message);
                                        let _ = send_resp(
                                            sink,
                                            channel_session.as_mut(),
                                            resp.encode(),
                                        )
                                        .await;
                                        return;
                                    }
                                    if pend.sides_served & side_bit != 0 {
                                        // Same side already served on
                                        // this token — protocol error.
                                        drop(map);
                                        let resp = Response::Error(format!(
                                            "V2 half: side {} already served for this token",
                                            side
                                        ));
                                        let _ = send_resp(
                                            sink,
                                            channel_session.as_mut(),
                                            resp.encode(),
                                        )
                                        .await;
                                        return;
                                    }
                                    let arc = Arc::clone(&pend.entry);
                                    pend.sides_served |= side_bit;
                                    // If both sides now served, the
                                    // entry is no longer pending — drop
                                    // it from the map (the Arc keeps
                                    // the data alive in our local
                                    // `entry_arc` for the remainder of
                                    // this serve loop).
                                    if pend.sides_served == 0b11 {
                                        map.remove(&token);
                                    }
                                    arc
                                }
                                None => {
                                    // First half to arrive — allocate a
                                    // fresh pool entry.
                                    let entry = match pool.try_take() {
                                        Some(e) => e,
                                        None => {
                                            drop(map);
                                            let resp = Response::Error(
                                                "V2 hint pool temporarily empty/unavailable"
                                                    .into(),
                                            );
                                            let _ = send_resp(
                                                sink,
                                                channel_session.as_mut(),
                                                resp.encode(),
                                            )
                                            .await;
                                            return;
                                        }
                                    };
                                    let arc = Arc::new(entry);
                                    map.insert(
                                        token,
                                        V2HalfPending {
                                            db_id,
                                            entry: Arc::clone(&arc),
                                            sides_served: side_bit,
                                            created_at: Instant::now(),
                                        },
                                    );
                                    arc
                                }
                            }
                        };

                        // 1. Send key preamble (same for both halves
                        //    since they share the entry). Kept as its own
                        //    small WS Binary message so the client's first
                        //    recv() returns just the preamble.
                        if let Err(e) = send_resp(
                            sink,
                            channel_session.as_mut(),
                            entry_arc.key_preamble.clone(),
                        )
                        .await
                        {
                            unsafe_debug_log!(
                                "[{}] V2-half preamble send error: {}",
                                peer, e
                            );
                            return;
                        }

                        // 2. Coalesce the selected half's frames into
                        //    ~HINT_BATCH_BYTES WS messages. Each record
                        //    retains its per-record `[4B len][body]`
                        //    framing (sealed individually if the
                        //    channel is on) so the client's
                        //    one-record-per-recv() contract holds. A
                        //    typical half (~78 INDEX or ~77 CHUNK
                        //    frames @ ~74 KB) now flushes as ~5 WS
                        //    messages instead of ~78.
                        let frames: &[Vec<u8>] = if side == 0 {
                            &entry_arc.index_frames
                        } else {
                            &entry_arc.chunk_frames
                        };
                        let mut sent = 0usize;
                        let mut batches = 0usize;
                        let mut pending: Vec<Vec<u8>> = Vec::new();
                        let mut pending_bytes = 0usize;
                        for frame in frames {
                            pending_bytes += frame.len();
                            pending.push(frame.clone());
                            if pending_bytes >= HINT_BATCH_BYTES {
                                let batch = std::mem::take(&mut pending);
                                pending_bytes = 0;
                                if let Err(e) = send_resp_batch(
                                    sink,
                                    channel_session.as_mut(),
                                    batch,
                                )
                                .await
                                {
                                    unsafe_debug_log!(
                                        "[{}] V2-half frame batch send error (side={}, group={}): {}",
                                        peer, side, sent, e
                                    );
                                    break;
                                }
                                batches += 1;
                            }
                            sent += 1;
                        }
                        if !pending.is_empty() {
                            if let Err(e) = send_resp_batch(
                                sink,
                                channel_session.as_mut(),
                                pending,
                            )
                            .await
                            {
                                unsafe_debug_log!(
                                    "[{}] V2-half final-batch send error (side={}): {}",
                                    peer, side, e
                                );
                            } else {
                                batches += 1;
                            }
                        }

                        // 3. Send terminal sentinel.
                        let terminal_len: u32 = 1 + 1;
                        let mut terminal = Vec::with_capacity(4 + terminal_len as usize);
                        terminal.extend_from_slice(&terminal_len.to_le_bytes());
                        terminal.push(RESP_HARMONY_HINTS);
                        terminal.push(0xFFu8);
                        let _ = send_resp(
                            sink,
                            channel_session.as_mut(),
                            terminal,
                        )
                        .await;

                        let elapsed = t_start.elapsed();
                        let side_name = if side == 0 { "INDEX" } else { "CHUNK" };
                        unsafe_debug_log!(
                            "[harmony-hint-v2-half] db={} side={} {} groups served from pool ({} WS batches) in {:.2?}",
                            db_id, side_name, sent, batches, elapsed,
                        );
                    }
                    REQ_HARMONY_QUERY => {
                        if let Ok(Request::HarmonyQuery(q)) = Request::decode(payload) {
                            // Validate db_id before dispatching to a worker.
                            if server.state.get_db(q.db_id).is_none() {
                                let resp = Response::Error(format!("unknown db_id {}", q.db_id));
                                let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                                return;
                            }
                            let s = Arc::clone(&server);
                            let resp = tokio::task::spawn_blocking(move || s.handle_harmony_query(&q)).await.unwrap();
                            let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                        }
                    }
                    REQ_HARMONY_BATCH_QUERY => {
                        if let Ok(Request::HarmonyBatchQuery(q)) = Request::decode(payload) {
                            // Validate db_id before dispatching to a worker.
                            if server.state.get_db(q.db_id).is_none() {
                                let resp = Response::Error(format!("unknown db_id {}", q.db_id));
                                let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                                return;
                            }
                            let t = Instant::now();
                            let n = q.items.len();
                            let level = q.level;
                            let db_id = q.db_id;
                            let s = Arc::clone(&server);
                            let resp = tokio::task::spawn_blocking(move || s.handle_harmony_batch_query(&q)).await.unwrap();
                            unsafe_debug_log!("[harmony-batch] db={} L{} {} groups in {:.2?}", db_id, level, n, t.elapsed());
                            // Harmony batch responses scale as K × (T−1) ×
                            // entry_size (~4 MiB per level against the live
                            // main database), far above both the 512 KiB
                            // single-message cap and the 2 MiB write-buffer
                            // cap.  A single large WebSocket message would
                            // wedge the sink (WriteBufferFull) and the
                            // previously swallowed error left the client
                            // waiting forever.  Every current SDK transport
                            // reassembles the shared CHUNK_MAGIC envelope,
                            // so always chunk this response, exactly like the
                            // bucket tree-tops preflight above.
                            if let Err(error) = send_resp_chunked(
                                sink,
                                channel_session.as_mut(),
                                resp.encode(),
                                true,
                            )
                            .await
                            {
                                unsafe_debug_log!(
                                    "[{}] harmony-batch response send error: {}",
                                    peer,
                                    error
                                );
                            }
                        }
                    }
                    REQ_ORAM_LOOKUP => {
                        if !request_was_encrypted {
                            let resp = Response::Error(
                                "REQ_ORAM_LOOKUP must be sent inside the encrypted channel".into(),
                            );
                            let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                            return;
                        }
                        match Request::decode(payload) {
                            Ok(Request::OramLookup(q)) => {
                                let s = Arc::clone(&server);
                                let resp = tokio::task::spawn_blocking(move || {
                                    s.handle_oram_lookup(&q)
                                })
                                .await
                                .unwrap();
                                let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                            }
                            Ok(other) => {
                                let resp = Response::Error(format!(
                                    "unexpected request type for ORAM lookup: {:?}",
                                    other
                                ));
                                let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                            }
                            Err(e) => {
                                let resp =
                                    Response::Error(format!("ORAM lookup decode error: {}", e));
                                let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                            }
                        }
                    }

                    // ── OnionPIR (primary only, if available) ────────────
                    REQ_REGISTER_KEYS if server.has_any_onionpir() => {
                        match RegisterKeysMsg::decode(body) {
                            Ok(keys_msg) => {
                                let db_id = keys_msg.db_id;
                                let tx = match server.onionpir_tx_for(db_id) {
                                    Some(t) => t.clone(),
                                    None => {
                                        let resp = Response::Error(format!("OnionPIR not available for db_id={}", db_id));
                                        let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                                        return;
                                    }
                                };
                                let (reply_tx, reply_rx) = oneshot::channel();
                                let _ = tx.send(PirCommand::RegisterKeys {
                                    client_id,
                                    galois_keys: keys_msg.galois_keys,
                                    gsw_keys: keys_msg.gsw_keys,
                                    reply: reply_tx,
                                }).await;
                                let _ = reply_rx.await;
                                let mut resp = Vec::with_capacity(5);
                                resp.extend_from_slice(&1u32.to_le_bytes());
                                resp.push(RESP_KEYS_ACK);
                                let _ = send_resp(sink, channel_session.as_mut(), resp).await;
                            }
                            Err(error) => {
                                let response = Response::Error(format!(
                                    "OnionPIR key registration decode error: {error}"
                                ));
                                let _ = send_resp(
                                    sink,
                                    channel_session.as_mut(),
                                    response.encode(),
                                )
                                .await;
                            }
                        }
                    }
                    REQ_ONIONPIR_INDEX_QUERY if server.has_any_onionpir() => {
                        if let Ok(batch) = OnionPirBatchQuery::decode(body) {
                            let tx = match server.onionpir_tx_for(batch.db_id) {
                                Some(t) => t.clone(),
                                None => {
                                    let resp = Response::Error(format!("OnionPIR not available for db_id={}", batch.db_id));
                                    let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                                    return;
                                }
                            };
                            let (reply_tx, reply_rx) = oneshot::channel();
                            let _ = tx.send(PirCommand::AnswerBatch {
                                client_id, level: 0,
                                round_id: batch.round_id,
                                queries: batch.queries, reply: reply_tx,
                            }).await;
                            let results = reply_rx.await.unwrap();
                            let result_msg = OnionPirBatchResult { round_id: batch.round_id, results };
                            let _ = send_resp_chunked(sink, channel_session.as_mut(), result_msg.encode(RESP_ONIONPIR_INDEX_RESULT), client_supports_chunks).await;
                        }
                    }
                    REQ_ONIONPIR_CHUNK_QUERY if server.has_any_onionpir() => {
                        if let Ok(batch) = OnionPirBatchQuery::decode(body) {
                            let tx = match server.onionpir_tx_for(batch.db_id) {
                                Some(t) => t.clone(),
                                None => {
                                    let resp = Response::Error(format!("OnionPIR not available for db_id={}", batch.db_id));
                                    let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                                    return;
                                }
                            };
                            let (reply_tx, reply_rx) = oneshot::channel();
                            let _ = tx.send(PirCommand::AnswerBatch {
                                client_id, level: 1,
                                round_id: batch.round_id,
                                queries: batch.queries, reply: reply_tx,
                            }).await;
                            let results = reply_rx.await.unwrap();
                            let result_msg = OnionPirBatchResult { round_id: batch.round_id, results };
                            let _ = send_resp_chunked(sink, channel_session.as_mut(), result_msg.encode(RESP_ONIONPIR_CHUNK_RESULT), client_supports_chunks).await;
                        }
                    }
                    REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP if server.has_any_onionpir_merkle() => {
                        // Optional db_id byte: payload[1] if present, else 0.
                        let db_id = if payload.len() > 1 { payload[1] } else { 0 };
                        let om = match server.onionpir_merkle_for(db_id) {
                            Some(om) => om,
                            None => {
                                let resp = Response::Error(format!("OnionPIR Merkle not available for db_id={}", db_id));
                                let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                                return;
                            }
                        };
                        // Per-group redesign: one consolidated 155-tree
                        // tree-top blob, served whole on either request.
                        let top = &om.tree_tops;
                        let payload_len = 1 + top.len();
                        let mut msg = Vec::with_capacity(4 + payload_len);
                        msg.extend_from_slice(&(payload_len as u32).to_le_bytes());
                        msg.push(RESP_ONIONPIR_MERKLE_INDEX_TREE_TOP);
                        msg.extend_from_slice(top);
                        let _ = send_resp_chunked(sink, channel_session.as_mut(), msg, client_supports_chunks).await;
                        unsafe_debug_log!("[onion-merkle-tree-tops] db={} (index req) sent {} bytes", db_id, top.len());
                    }
                    REQ_ONIONPIR_MERKLE_DATA_TREE_TOP if server.has_any_onionpir_merkle() => {
                        // Optional db_id byte: payload[1] if present, else 0.
                        let db_id = if payload.len() > 1 { payload[1] } else { 0 };
                        let om = match server.onionpir_merkle_for(db_id) {
                            Some(om) => om,
                            None => {
                                let resp = Response::Error(format!("OnionPIR Merkle not available for db_id={}", db_id));
                                let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                                return;
                            }
                        };
                        // Per-group redesign: one consolidated 155-tree
                        // tree-top blob, served whole on either request.
                        let top = &om.tree_tops;
                        let payload_len = 1 + top.len();
                        let mut msg = Vec::with_capacity(4 + payload_len);
                        msg.extend_from_slice(&(payload_len as u32).to_le_bytes());
                        msg.push(RESP_ONIONPIR_MERKLE_DATA_TREE_TOP);
                        msg.extend_from_slice(top);
                        let _ = send_resp_chunked(sink, channel_session.as_mut(), msg, client_supports_chunks).await;
                        unsafe_debug_log!("[onion-merkle-tree-tops] db={} (data req) sent {} bytes", db_id, top.len());
                    }
                    REQ_ONIONPIR_MERKLE_INDEX_SIBLING if server.has_any_onionpir() => {
                        // round_id encoding: sibling_level * 100 + pbc_round_index
                        // Per-DB: the db_id trailer in the batch message selects the
                        // OnionPIR worker and its per-bin Merkle sibling levels.
                        if let Ok(batch) = OnionPirBatchQuery::decode(body) {
                            if server.onionpir_merkle_for(batch.db_id).is_none() {
                                let resp = Response::Error(format!(
                                    "OnionPIR Merkle not available for db_id={}",
                                    batch.db_id
                                ));
                                let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                                return;
                            }
                            let tx = match server.onionpir_tx_for(batch.db_id) {
                                Some(t) => t.clone(),
                                None => return,
                            };
                            let (reply_tx, reply_rx) = oneshot::channel();
                            let _ = tx.send(PirCommand::AnswerBatch {
                                client_id,
                                level: 10, // worker: INDEX per-group siblings
                                round_id: batch.round_id,
                                queries: batch.queries, reply: reply_tx,
                            }).await;
                            let results = reply_rx.await.unwrap();
                            let result_msg = OnionPirBatchResult { round_id: batch.round_id, results };
                            let _ = send_resp_chunked(sink, channel_session.as_mut(), result_msg.encode(RESP_ONIONPIR_MERKLE_INDEX_SIBLING), client_supports_chunks).await;
                        }
                    }
                    REQ_ONIONPIR_MERKLE_DATA_SIBLING if server.has_any_onionpir() && server.has_any_onionpir_merkle() => {
                        // round_id encoding: sibling_level * 100 + pbc_round_index
                        // Data siblings start after index siblings in the worker's server array.
                        if let Ok(batch) = OnionPirBatchQuery::decode(body) {
                            if server.onionpir_merkle_for(batch.db_id).is_none() {
                                let resp = Response::Error(format!(
                                    "OnionPIR Merkle not available for db_id={}",
                                    batch.db_id
                                ));
                                let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                                return;
                            }
                            let tx = match server.onionpir_tx_for(batch.db_id) {
                                Some(t) => t.clone(),
                                None => return,
                            };
                            let (reply_tx, reply_rx) = oneshot::channel();
                            let _ = tx.send(PirCommand::AnswerBatch {
                                client_id,
                                level: 11, // worker: DATA per-group siblings
                                round_id: batch.round_id,
                                queries: batch.queries, reply: reply_tx,
                            }).await;
                            let results = reply_rx.await.unwrap();
                            let result_msg = OnionPirBatchResult { round_id: batch.round_id, results };
                            let _ = send_resp_chunked(sink, channel_session.as_mut(), result_msg.encode(RESP_ONIONPIR_MERKLE_DATA_SIBLING), client_supports_chunks).await;
                        }
                    }

                    // ── Unsupported ──────────────────────────────────────
                    _ => {
                        let resp = Response::Error(format!("unsupported request 0x{:02x} for {} role", variant, role_name));
                        let _ = send_resp(sink, channel_session.as_mut(), resp.encode()).await;
                    }
                }
}
