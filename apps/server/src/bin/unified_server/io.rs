use crate::unsafe_debug_log;
use futures_util::SinkExt;
use runtime::protocol::*;
use runtime::table::{DatabaseDescriptor, MappedDatabase};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use zeroize::Zeroizing;

// ─── AMD VCEK chain loader ─────────────────────────────────────────────────
//
// Reads two PEM files from `--vcek-dir`:
//   - cert_chain.pem  — ASK + ARK as concatenated PEMs (the format AMD
//                       KDS returns from /vcek/v1/{Family}/cert_chain).
//                       ASK comes first, ARK second.
//   - vcek.pem        — the per-chip VCEK for the current TCB (fetched
//                       from /vcek/v1/{Family}/{ChipID}?TCB-params).
//
// Splits cert_chain.pem on the BEGIN/END boundaries so the AttestResult
// fields end up with separate `ark_pem` and `ask_pem`. (Splitting here
// rather than at the verifier matches the operator workflow: one curl
// per file from AMD KDS, then one cp into --vcek-dir.)
//
// Returns (ark, ask, vcek). Empty Vecs on any I/O or parse failure;
// caller logs and continues — AttestResult ships empty cert fields and
// the browser falls back to V2-binding-only mode.
pub(crate) fn load_vcek_chain(dir: &Path) -> std::io::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let chain_path = dir.join("cert_chain.pem");
    let vcek_path = dir.join("vcek.pem");
    let chain_bytes = std::fs::read(&chain_path)?;
    let vcek_bytes = std::fs::read(&vcek_path)?;

    let (ask, ark) = split_cert_chain_ask_then_ark(&chain_bytes).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "cert_chain.pem at {} did not contain two PEM blocks (expected ASK then ARK)",
                chain_path.display()
            ),
        )
    })?;
    Ok((ark, ask, vcek_bytes))
}

/// Split a concatenated PEM blob into (first_block, second_block) by
/// looking for `-----BEGIN` / `-----END` boundaries. AMD KDS returns
/// the chain endpoint as ASK + ARK (in that order); callers swap to
/// (ark, ask) at the call site.
pub(crate) fn split_cert_chain_ask_then_ark(bytes: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let s = std::str::from_utf8(bytes).ok()?;
    // Find the END of the first block, including its line.
    let first_end = s.find("-----END")?;
    let after_first_end = first_end + s[first_end..].find('\n')? + 1;
    let first_block = s.as_bytes()[..after_first_end].to_vec();
    // The remainder should start with the second BEGIN line.
    let rest = &s[after_first_end..];
    let second_begin = rest.find("-----BEGIN")?;
    let second_block = rest.as_bytes()[second_begin..].to_vec();
    if second_block.is_empty() {
        return None;
    }
    Some((first_block, second_block))
}

// ─── REQ_ANNOUNCE response builder ──────────────────────────────────────────
//
// Maps the startup-built `ServerState.announcement_bundle` to the wire
// reply: `Some` → `RESP_ANNOUNCE` carrying the operator-signed bundle
// verbatim; `None` → `RESP_ERROR` (the server was started without a
// consistent identity key + operator cert). Extracted so the REQ_ANNOUNCE
// dispatch arm and its unit test share one implementation — booting the
// full binary needs a multi-GB checkpoint, so this is the closest seam
// the production code path can be exercised at in-process.
pub(crate) fn build_announce_response(announcement_bundle: &Option<Vec<u8>>) -> Response {
    match announcement_bundle {
        Some(bytes) => Response::Announce(bytes.clone()),
        None => Response::Error(
            "announce not configured: server lacks identity key or operator cert".into(),
        ),
    }
}

pub(crate) fn read_regular_file_bounded_v1(
    path: &std::path::Path,
    maximum: usize,
    label: &str,
) -> Result<Vec<u8>, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect {label} {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!("{label} is not a regular file: {}", path.display()));
    }
    let maximum_u64 = u64::try_from(maximum).map_err(|_| format!("{label} limit overflow"))?;
    if metadata.len() > maximum_u64 {
        return Err(format!(
            "{label} is {} bytes, above the {} byte limit",
            metadata.len(),
            maximum
        ));
    }
    let file = File::open(path)
        .map_err(|error| format!("failed to open {label} {}: {error}", path.display()))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum_u64.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read {label} {}: {error}", path.display()))?;
    if bytes.len() > maximum {
        return Err(format!(
            "{label} changed while reading and exceeded its size limit"
        ));
    }
    Ok(bytes)
}

pub(crate) fn current_unix_seconds_v1() -> Result<u64, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_owned())?
        .as_secs();
    if now == 0 {
        return Err("system clock returned zero Unix time".to_owned());
    }
    Ok(now)
}

/// Like [`send_resp`], but when `allow_chunk` is set and the framed
/// message exceeds `CHUNK_SIZE`, splits it into chunk frames the client
/// reassembles. Used for the large OnionPIR result messages
/// (INDEX/CHUNK batches ~1–2 MB, Merkle tree-tops ~1 MB) sent to
/// chunk-capable clients. `allow_chunk` is the per-connection
/// `client_supports_chunks` flag — false for legacy / WASM DPF/Harmony
/// clients, which never receive a large enough OnionPIR message anyway.
pub(crate) async fn send_resp_chunked<S>(
    sink: &mut S,
    session: Option<&mut pir_runtime_core::channel::Session>,
    payload: Vec<u8>,
    allow_chunk: bool,
) -> tokio_tungstenite::tungstenite::Result<()>
where
    S: futures_util::Sink<
            tokio_tungstenite::tungstenite::Message,
            Error = tokio_tungstenite::tungstenite::Error,
        > + Unpin,
{
    use tokio_tungstenite::tungstenite::{Error as TungError, Message};
    // Frame (and optionally seal) exactly like send_resp.
    let to_send = match session {
        Some(s) => {
            if payload.len() < 4 {
                payload
            } else {
                let inner = &payload[4..];
                let sealed = s
                    .seal(pir_runtime_core::channel::Direction::ServerToClient, inner)
                    .map_err(|e| {
                        TungError::Io(std::io::Error::other(format!("channel seal: {}", e)))
                    })?;
                let mut framed = Vec::with_capacity(4 + sealed.len());
                framed.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
                framed.extend_from_slice(&sealed);
                framed
            }
        }
        None => payload,
    };
    if !allow_chunk || to_send.len() <= CHUNK_SIZE {
        return sink.send(Message::Binary(to_send)).await;
    }
    let total = to_send.len().div_ceil(CHUNK_SIZE);
    if total > u16::MAX as usize {
        return Err(TungError::Io(std::io::Error::other(format!(
            "response too large to chunk: {} bytes",
            to_send.len()
        ))));
    }
    let encoded_group_bytes = to_send
        .len()
        .checked_add(
            total
                .checked_mul(4 + CHUNK_HDR)
                .ok_or_else(|| TungError::Io(std::io::Error::other("chunk framing overflow")))?,
        )
        .ok_or_else(|| TungError::Io(std::io::Error::other("chunk response size overflow")))?;
    let _ = encoded_group_bytes;
    for seq in 0..total {
        let start = seq * CHUNK_SIZE;
        let end = (start + CHUNK_SIZE).min(to_send.len());
        let piece = &to_send[start..end];
        let mut frame = Vec::with_capacity(4 + CHUNK_HDR + piece.len());
        frame.extend_from_slice(&((CHUNK_HDR + piece.len()) as u32).to_le_bytes());
        frame.push(CHUNK_MAGIC);
        frame.extend_from_slice(&(seq as u16).to_le_bytes());
        frame.extend_from_slice(&(total as u16).to_le_bytes());
        frame.extend_from_slice(piece);
        sink.send(Message::Binary(frame)).await?;
    }
    Ok(())
}

pub(crate) async fn send_resp<S>(
    sink: &mut S,
    session: Option<&mut pir_runtime_core::channel::Session>,
    payload: Vec<u8>,
) -> tokio_tungstenite::tungstenite::Result<()>
where
    S: futures_util::SinkExt<
            tokio_tungstenite::tungstenite::Message,
            Error = tokio_tungstenite::tungstenite::Error,
        > + Unpin,
{
    use tokio_tungstenite::tungstenite::{Error as TungError, Message};
    let to_send = match session {
        Some(s) => {
            if payload.len() < 4 {
                // Defensive: malformed (no length prefix). Pass through —
                // the WS receiver will see a too-short frame and ignore it,
                // matching pre-Slice-B.2 behaviour.
                payload
            } else {
                let inner = &payload[4..];
                let sealed = s
                    .seal(pir_runtime_core::channel::Direction::ServerToClient, inner)
                    .map_err(|e| {
                        TungError::Io(std::io::Error::other(format!("channel seal: {}", e)))
                    })?;
                let mut framed = Vec::with_capacity(4 + sealed.len());
                framed.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
                framed.extend_from_slice(&sealed);
                framed
            }
        }
        None => payload,
    };
    sink.send(Message::Binary(to_send)).await
}

// `feed_resp` (a per-frame `sink.feed()` variant of `send_resp`) was
// removed when the V2 / V2-half hint paths switched from one
// `Message::Binary` per group to a coalesced ~768 KB batch — see
// `HINT_BATCH_BYTES` below. The coalesced path uses `send_resp_batch`,
// which seals each record individually (preserving per-record framing
// the client demuxes) and emits the concatenated buffer as one
// `Sink::send`-flushed Binary message per batch.

/// Send a batch of `[4B len][body]` records as ONE WebSocket Binary
/// message. Each record retains its own `[4B len][body_or_sealed]`
/// framing inside the buffer so the client's transport layer can demux
/// them one-by-one via [`WsConnection::recv`] (which peels one record
/// per call, buffering any tail).
///
/// When the channel session is active, each record is sealed
/// individually with a fresh sequence number — the seal pattern is
/// byte-identical to N back-to-back `send_resp` calls, just emitted as
/// one WS Binary message instead of N.
///
/// Used by the HarmonyPIR hint paths (V1, V2, V2-half) to coalesce the
/// per-group hint records into ~`HINT_BATCH_BYTES`-sized batches; see
/// the call sites for the surrounding loops.
pub(crate) async fn send_resp_batch<S>(
    sink: &mut S,
    mut session: Option<&mut pir_runtime_core::channel::Session>,
    records: Vec<Vec<u8>>,
) -> tokio_tungstenite::tungstenite::Result<()>
where
    S: futures_util::SinkExt<
            tokio_tungstenite::tungstenite::Message,
            Error = tokio_tungstenite::tungstenite::Error,
        > + Unpin,
{
    use tokio_tungstenite::tungstenite::{Error as TungError, Message};
    if records.is_empty() {
        return Ok(());
    }
    // Pre-size the output buffer. For the no-channel case we know the
    // exact size; for the channel case each sealed body is
    // `body.len() + 1 (magic) + 8 (seq) + 16 (tag) = body.len() + 25`,
    // so a tight upper-bound stays correct without re-allocating.
    let total_estimate: usize = records
        .iter()
        .map(|r| {
            if r.len() < 4 {
                r.len()
            } else {
                4 + (r.len() - 4) + 25
            }
        })
        .sum();
    let mut buf: Vec<u8> = Vec::with_capacity(total_estimate);
    for payload in records {
        match session.as_deref_mut() {
            Some(s) => {
                if payload.len() < 4 {
                    // Defensive: malformed (no length prefix). Pass
                    // through — matches `send_resp` behaviour.
                    buf.extend_from_slice(&payload);
                } else {
                    let inner = &payload[4..];
                    let sealed = s
                        .seal(pir_runtime_core::channel::Direction::ServerToClient, inner)
                        .map_err(|e| {
                            TungError::Io(std::io::Error::other(format!("channel seal: {}", e)))
                        })?;
                    buf.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
                    buf.extend_from_slice(&sealed);
                }
            }
            None => {
                buf.extend_from_slice(&payload);
            }
        }
    }

    sink.send(Message::Binary(buf)).await
}

// ─── Transport-level message chunking (Cloudflare large-message workaround) ──
//
// Cloudflare's WebSocket proxy silently corrupts single messages above
// ~1 MB (a 3.1 MB OnionPIR RegisterKeys upload arrives truncated — see
// docs/history/PIR1_REGISTER_KEYS_TRUNCATION.md). Messages over CHUNK_SIZE are
// split into `[4B len][CHUNK_MAGIC][seq:u16][total:u16][piece]` frames;
// the peer reassembles. These constants MUST stay in sync with
// `crates/sdk/client/src/connection.rs` (CHUNK_MAGIC / CHUNK_SIZE) and
// `web/src/onionpir_client.ts`.
pub(crate) const CHUNK_MAGIC: u8 = 0xc7;
pub(crate) const CHUNK_SIZE: usize = 256 * 1024;
pub(crate) const CHUNK_HDR: usize = 1 + 2 + 2; // magic + seq + total
pub(crate) const MAX_REASSEMBLED: usize = 16 * 1024 * 1024;
// Client uploads larger than this use BitcoinPIR's 256 KiB chunk envelope.
// Keeping the WebSocket parser itself small bounds memory before application
// admission logic sees the frame.
pub(crate) const MAX_WS_MESSAGE_BYTES: usize = 512 * 1024;

/// Production WebSocket transport limits, shared between the listener and
/// the regression tests that must prove responses survive them:
/// 512 KiB inbound message/frame caps plus a 2 MiB per-socket write-buffer
/// cap that bounds slow-consumer memory. Any single server→client message
/// above ~2 MiB (notably a live-scale Harmony batch response, ~4 MiB) must
/// therefore ride the shared CHUNK_MAGIC envelope — see
/// `harmony_batch_response_at_live_scale_crosses_production_ws_limits`.
#[allow(deprecated)]
pub(crate) fn production_ws_config_v1() -> WebSocketConfig {
    WebSocketConfig {
        max_send_queue: None,
        write_buffer_size: 128 * 1024,
        max_write_buffer_size: 2 * 1024 * 1024,
        max_message_size: Some(MAX_WS_MESSAGE_BYTES),
        max_frame_size: Some(MAX_WS_MESSAGE_BYTES),
        accept_unmasked_frames: false,
    }
}
// Process-wide cap across all partially/completely reassembled client
// requests.  This is independent of the connection count and signed grant
// limits so many slow clients cannot each retain a 16 MiB buffer.
pub(crate) const MAX_GLOBAL_REASSEMBLY_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_CHUNK_FRAMES: usize = MAX_REASSEMBLED.div_ceil(CHUNK_SIZE);

/// Target accumulation size before flushing a coalesced HarmonyPIR hint
/// batch as one WebSocket Binary message. Per-group hint records
/// (~74 KB each on the public deployment) are concatenated into a buffer
/// until the threshold is crossed, then flushed.
///
/// Wire-format inside the buffer is unchanged — each record is still the
/// pre-existing `[4B len][RESP_HARMONY_HINTS][group_id][n][t][m][hints]`
/// frame. Only WS message boundaries are reduced (a HarmonyPIR query that
/// previously emitted ~622 RX HARMONY_HINTS frames across two sockets now
/// emits ~32).
///
/// Sized below 1 MiB so the message survives the Cloudflare WebSocket
/// proxy (~1 MB ceiling — see docs/history/PIR1_REGISTER_KEYS_TRUNCATION.md).
/// Mirrors `HINT_BATCH_BYTES` in
/// `apps/server/src/bin/harmonypir_hint_server.rs`.
pub(crate) const HINT_BATCH_BYTES: usize = 768 * 1024;

pub(crate) fn read_exact_secret_v1<const N: usize>(
    path: &std::path::Path,
    label: &str,
) -> Result<[u8; N], String> {
    pir_private_files::read_exact_private_file_v1(path, label)
}

pub(crate) fn load_runtime_database_v1(
    db_id: u8,
    base_dir: &Path,
    descriptor: DatabaseDescriptor,
    direct_oram_db_ids: &BTreeSet<u8>,
) -> MappedDatabase {
    if direct_oram_db_ids.contains(&db_id) {
        MappedDatabase::load_for_direct_oram(base_dir, descriptor)
    } else {
        MappedDatabase::load(base_dir, descriptor)
    }
}
