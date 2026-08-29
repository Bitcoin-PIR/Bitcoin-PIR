use super::*;

// ─── Wire protocol constants ────────────────────────────────────────────────

pub(crate) const REQ_HARMONY_GET_INFO: u8 = 0x40;
pub(crate) const RESP_HARMONY_INFO: u8 = 0x40;

pub(crate) const REQ_HARMONY_HINTS: u8 = 0x41;
pub(crate) const RESP_HARMONY_HINTS: u8 = 0x41;

/// V2: server generates the PRP key. Request variant.
pub(crate) const REQ_HARMONY_HINTS_V2: u8 = 0x44;
/// V2: key preamble response variant.
pub(crate) const RESP_HARMONY_HINTS_KEY: u8 = 0x44;
pub(crate) const V2_HINT_POOL_UNAVAILABLE: &str = "V2 hint pool temporarily empty/unavailable";
#[cfg(not(test))]
pub(crate) const V2_HALF_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);
#[cfg(test)]
pub(crate) const V2_HALF_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(100);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum V2HintFetchOutcome {
    Loaded,
    PoolUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum V2KeyPreambleOutcome {
    Key { prp_backend: u8, prp_key: [u8; 16] },
    PoolUnavailable,
}

pub(crate) fn v2_record_body<'a>(frame: &'a [u8], label: &str) -> PirResult<&'a [u8]> {
    if frame.len() < 4 {
        return Err(PirError::Protocol(format!(
            "{}: truncated record length prefix",
            label
        )));
    }
    let declared = u32::from_le_bytes(frame[..4].try_into().expect("length checked")) as usize;
    let actual = frame.len() - 4;
    if declared != actual {
        return Err(PirError::Protocol(format!(
            "{}: record length mismatch (declared {}, actual {})",
            label, declared, actual
        )));
    }
    Ok(&frame[4..])
}

pub(crate) fn parse_v2_key_preamble(
    frame: &[u8],
    expected_total_groups: u8,
    label: &str,
) -> PirResult<V2KeyPreambleOutcome> {
    let body = v2_record_body(frame, label)?;
    let first = body
        .first()
        .copied()
        .ok_or_else(|| PirError::Protocol(format!("{}: empty response", label)))?;
    if first == RESP_ERROR {
        let reason =
            decode_error_response_message(body, label)?.expect("RESP_ERROR discriminator checked");
        return if is_v2_hint_pool_unavailable_message(reason) {
            Ok(V2KeyPreambleOutcome::PoolUnavailable)
        } else {
            Err(PirError::ServerError(format!("{label}: {reason}")))
        };
    }
    match first {
        RESP_HARMONY_HINTS_KEY => {
            // Exact layout: variant, backend, all-levels sentinel, total
            // groups, and the 16-byte server-generated PRP key.
            if body.len() != 20 {
                return Err(PirError::Protocol(format!(
                    "{}: key preamble has {} bytes, expected 20",
                    label,
                    body.len()
                )));
            }
            if body[2] != 0xFF {
                return Err(PirError::Protocol(format!(
                    "{}: key preamble level is 0x{:02x}, expected 0xff",
                    label, body[2]
                )));
            }
            if body[3] != expected_total_groups {
                return Err(PirError::Protocol(format!(
                    "{}: key preamble declares {} groups, expected {}",
                    label, body[3], expected_total_groups
                )));
            }
            let mut prp_key = [0u8; 16];
            prp_key.copy_from_slice(&body[4..20]);
            Ok(V2KeyPreambleOutcome::Key {
                prp_backend: body[1],
                prp_key,
            })
        }
        other => Err(PirError::Protocol(format!(
            "{}: expected key preamble (0x{:02x}), got 0x{:02x}",
            label, RESP_HARMONY_HINTS_KEY, other,
        ))),
    }
}

pub(crate) fn validate_v2_terminal(frame: &[u8], label: &str) -> PirResult<()> {
    let body = v2_record_body(frame, label)?;
    reject_error_response(body, label)?;
    if body != [RESP_HARMONY_HINTS, 0xFF] {
        return Err(PirError::Protocol(format!(
            "{}: invalid terminal sentinel (expected [0x{:02x}, 0xff], got {:02x?})",
            label, RESP_HARMONY_HINTS, body
        )));
    }
    Ok(())
}

/// The V2 hint pool serves the default database (db_id 0); other databases
/// fetch hints through the legacy V1 path.
pub(crate) fn should_use_v2_hint_pool(use_v2_protocol: bool, db_id: u8) -> bool {
    use_v2_protocol && db_id == 0
}

pub(crate) fn is_v2_hint_pool_unavailable_message(message: &str) -> bool {
    message == V2_HINT_POOL_UNAVAILABLE
}

/// V2 half-stream hint request — pairs with `REQ_HARMONY_HINTS_V2` but
/// splits the response into INDEX-only (side=0) or CHUNK-only (side=1)
/// halves. Two parallel requests carrying the same 16-byte session
/// token are matched server-side to the same pool entry, so both halves
/// expose the same PRP key. See
/// [`HarmonyClient::ensure_groups_ready_v2_half`] for the client-side
/// parallel fetch path.
pub(crate) const REQ_HARMONY_HINTS_V2_HALF: u8 = 0x46;

pub(crate) const REQ_HARMONY_BATCH_QUERY: u8 = 0x43;
pub(crate) const RESP_HARMONY_BATCH_QUERY: u8 = 0x43;

// `REQ_GET_DB_CATALOG` / `RESP_DB_CATALOG` / `RESP_ERROR` come from
// `crate::protocol` — shared with `DpfClient` and `OnionClient`.

/// PRP backends used on the HarmonyPIR wire.
pub use harmonypir::remote::{PRP_FASTPRP, PRP_HMR12};
// PRP_ALF (= 2) was removed 2026-05-12: ALF panicked on domain<65536
// (sibling Merkle tables hit this), causing pir-vpsbg crash loops.

pub(crate) fn new_harmony_group(
    n: u32,
    w: u32,
    t: u32,
    master_key: &[u8],
    group_id: u32,
    backend: u8,
) -> harmonypir::remote::Result<HarmonyGroup> {
    HarmonyGroup::new_with_backend(
        n,
        w,
        t,
        master_key,
        group_id,
        PrpBackend::try_from(backend)?,
    )
}

pub(crate) fn serialize_harmony_group(group: &HarmonyGroup) -> PirResult<Vec<u8>> {
    group
        .serialize_legacy_state()
        .map_err(|error| PirError::BackendState(format!("serialize HarmonyPIR group: {error}")))
}

/// Which group-map `fetch_and_load_hints_into` should write into.
///
/// Keeps the hint-loading plumbing single-purpose — the caller supplies
/// both the wire `level` byte and the matching local destination.
#[derive(Copy, Clone, Debug)]
pub(crate) enum HintTarget {
    /// Main INDEX groups keyed by `group_id` (0..index_k).
    Index,
    /// Main CHUNK groups keyed by `group_id` (0..chunk_k).
    Chunk,
    /// Bucket-Merkle INDEX sibling groups at `sib_level` L (0..).
    IndexSib(usize),
    /// Bucket-Merkle CHUNK sibling groups at `sib_level` L (0..).
    ChunkSib(usize),
}

// ─── Wire protocol helpers ──────────────────────────────────────────────────

pub(crate) struct BatchItem {
    pub(crate) group_id: u8,
    pub(crate) indices: Vec<u32>,
}

/// Wire format (matches `runtime::protocol::HarmonyBatchQuery::encode()`):
///
/// ```text
/// [4B msg_len LE]
/// [1B 0x43]
/// [1B level]
/// [2B round_id LE]
/// [2B num_groups LE]
/// [1B sub_queries_per_group = 1]
/// per group:
///   [1B group_id]
///   [4B count LE]
///   [count × 4B u32 LE]
/// [optional 1B db_id if db_id != 0]
/// ```
pub(crate) fn encode_batch_query(
    level: u8,
    round_id: u16,
    db_id: u8,
    items: &[BatchItem],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(level);
    payload.extend_from_slice(&round_id.to_le_bytes());
    payload.extend_from_slice(&(items.len() as u16).to_le_bytes());
    payload.push(1u8); // sub_queries_per_group

    for item in items {
        payload.push(item.group_id);
        payload.extend_from_slice(&(item.indices.len() as u32).to_le_bytes());
        for idx in &item.indices {
            payload.extend_from_slice(&idx.to_le_bytes());
        }
    }

    if db_id != 0 {
        payload.push(db_id);
    }

    encode_request(REQ_HARMONY_BATCH_QUERY, &payload)
}

/// Decode a `HarmonyBatchResult` response body after `roundtrip()` has
/// stripped the 4-byte record length. Returns a `group_id -> result` map.
///
/// Wire format:
/// ```text
/// [1B 0x43]
/// [1B level]
/// [2B round_id LE]
/// [2B num_groups LE]
/// [1B sub_results_per_group]
/// per group:
///   [1B group_id]
///   per sub-result:
///     [4B data_len LE]
///     [data_len bytes]
/// ```
pub(crate) fn decode_batch_response_body(
    body: &[u8],
    expected_level: u8,
    expected_round_id: u16,
    expected_groups: usize,
    context: &str,
) -> PirResult<HashMap<u8, Vec<u8>>> {
    if body.is_empty() {
        return Err(PirError::Decode(format!("{context}: empty batch response")));
    }
    reject_error_response(body, context)?;
    if body[0] != RESP_HARMONY_BATCH_QUERY {
        return Err(PirError::UnexpectedResponse {
            expected: "RESP_HARMONY_BATCH_QUERY",
            actual: format!("0x{:02x}", body[0]),
        });
    }
    if body.len() < 7 {
        return Err(PirError::Decode(format!(
            "{context}: batch response header truncated"
        )));
    }
    let mut pos = 1;
    let level = body[pos];
    pos += 1;
    if level != expected_level {
        return Err(PirError::Protocol(format!(
            "{context}: batch response level mismatch: expected {expected_level}, got {level}"
        )));
    }
    let round_id = u16::from_le_bytes(body[pos..pos + 2].try_into().unwrap());
    pos += 2;
    if round_id != expected_round_id {
        return Err(PirError::Protocol(format!(
            "{context}: batch response round_id mismatch: expected {expected_round_id}, got {round_id}"
        )));
    }
    let num_groups = u16::from_le_bytes(body[pos..pos + 2].try_into().unwrap()) as usize;
    pos += 2;
    if num_groups != expected_groups {
        return Err(PirError::Protocol(format!(
            "{context}: batch response group count mismatch: expected {expected_groups}, got {num_groups}"
        )));
    }
    let sub_per_group = body[pos] as usize;
    pos += 1;
    if sub_per_group != 1 {
        return Err(PirError::Protocol(format!(
            "{context}: expected exactly one sub-result per group, got {sub_per_group}"
        )));
    }

    let mut out: HashMap<u8, Vec<u8>> = HashMap::with_capacity(num_groups);

    for _ in 0..num_groups {
        if pos >= body.len() {
            return Err(PirError::Decode(format!("{context}: group id truncated")));
        }
        let gid = body[pos];
        pos += 1;
        if usize::from(gid) >= expected_groups {
            return Err(PirError::Protocol(format!(
                "{context}: out-of-range group id {gid} for {expected_groups} groups"
            )));
        }
        if out.contains_key(&gid) {
            return Err(PirError::Protocol(format!(
                "{context}: duplicate group id {gid}"
            )));
        }

        let mut first_sub: Option<Vec<u8>> = None;
        for s in 0..sub_per_group {
            let length_end = pos.checked_add(4).ok_or_else(|| {
                PirError::Decode(format!("{context}: sub-result length overflow"))
            })?;
            if length_end > body.len() {
                return Err(PirError::Decode(format!(
                    "{context}: sub-result length truncated"
                )));
            }
            let dlen = u32::from_le_bytes(body[pos..length_end].try_into().unwrap()) as usize;
            pos = length_end;
            let data_end = pos.checked_add(dlen).ok_or_else(|| {
                PirError::Decode(format!("{context}: sub-result data length overflow"))
            })?;
            if data_end > body.len() {
                return Err(PirError::Decode(format!(
                    "{context}: sub-result data truncated"
                )));
            }
            if s == 0 {
                first_sub = Some(body[pos..data_end].to_vec());
            }
            pos = data_end;
        }

        if let Some(d) = first_sub {
            out.insert(gid, d);
        }
    }

    if pos != body.len() {
        return Err(PirError::Decode(format!(
            "{context}: trailing bytes after batch response: {}",
            body.len() - pos
        )));
    }

    Ok(out)
}

/// Decode a full `recv()` record, independently validating its outer length.
pub(crate) fn decode_batch_response_frame(
    frame: &[u8],
    expected_level: u8,
    expected_round_id: u16,
    expected_groups: usize,
    context: &str,
) -> PirResult<HashMap<u8, Vec<u8>>> {
    if frame.len() < 4 {
        return Err(PirError::Decode(format!(
            "{context}: truncated batch response length prefix"
        )));
    }
    let body_len = u32::from_le_bytes(frame[..4].try_into().unwrap()) as usize;
    let expected_len = 4usize
        .checked_add(body_len)
        .ok_or_else(|| PirError::Decode(format!("{context}: response length overflow")))?;
    if frame.len() != expected_len {
        return Err(PirError::Decode(format!(
            "{context}: response length mismatch: prefix declares {body_len} body bytes, frame has {}",
            frame.len().saturating_sub(4)
        )));
    }
    decode_batch_response_body(
        &frame[4..],
        expected_level,
        expected_round_id,
        expected_groups,
        context,
    )
}

pub(crate) fn bytes_to_u32_vec(data: &[u8]) -> PirResult<Vec<u32>> {
    if !data.len().is_multiple_of(4) {
        return Err(PirError::Encode(format!(
            "request index bytes not a multiple of 4 (got {})",
            data.len()
        )));
    }
    Ok(data
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect())
}

// ─── PIR helpers ────────────────────────────────────────────────────────────

/// Scan the XOR-recovered INDEX bin for an entry matching `expected_tag`.
/// Returns `(start_chunk_id, num_chunks)` if found.
pub(crate) fn find_entry_in_index_result(result: &[u8], expected_tag: u64) -> Option<(u32, u8)> {
    for slot in 0..INDEX_SLOTS_PER_BIN {
        let base = slot * INDEX_SLOT_SIZE;
        if base + INDEX_SLOT_SIZE > result.len() {
            break;
        }
        let slot_tag = u64::from_le_bytes(result[base..base + TAG_SIZE].try_into().unwrap());
        if slot_tag == expected_tag {
            let start_chunk_id = u32::from_le_bytes(
                result[base + TAG_SIZE..base + TAG_SIZE + 4]
                    .try_into()
                    .unwrap(),
            );
            let num_chunks = result[base + TAG_SIZE + 4];
            return Some((start_chunk_id, num_chunks));
        }
    }
    None
}

/// Scan a CHUNK bin for the slot whose chunk_id matches `chunk_id`.
pub(crate) fn find_chunk_in_result(result: &[u8], chunk_id: u32) -> Option<&[u8]> {
    let target = chunk_id.to_le_bytes();
    for slot in 0..CHUNK_SLOTS_PER_BIN {
        let base = slot * CHUNK_SLOT_SIZE;
        if base + CHUNK_SLOT_SIZE > result.len() {
            break;
        }
        if result[base..base + 4] == target {
            return Some(&result[base + 4..base + CHUNK_SLOT_SIZE]);
        }
    }
    None
}

/// Decode concatenated UTXO chunk bytes into a `Vec<UtxoEntry>`.
/// Decode UTXO entries from assembled chunk bytes.
///
/// Wire format (matches the build pipeline at
/// `tools/db-builder/src/build_utxo_chunks.rs::serialize_group_sorted` and the
/// reference decoder at `pir_core::codec::parse_utxo_data`):
///
///   `[varint num_utxos][per entry: 32B txid | varint vout | varint amount]`
///
/// Padding bytes after the last entry (the assembled chunk_data is a
/// `N * CHUNK_SIZE`-byte buffer; the encoded entries usually don't fill
/// it exactly) are ignored.
///
/// **Bug history (2026-05-13).** The old in-file decoder here (and in
/// `dpf.rs`) assumed fixed 40-byte slots — `[32B txid | 4B vout LE |
/// 4B amount LE]` — which silently produced garbage `vout` / `amount`
/// values from byte ranges that actually held the varint stream's
/// continuation bytes. OnionPIR's decoder (`onion.rs:1892`) and
/// `pir_core::codec::parse_utxo_data` were always correct; the
/// regression only affected DPF + HarmonyPIR.
///
/// The chunk bytes are server-controlled and decoded *before* Merkle
/// verification, so a malformed varint is a `PirError::Decode`, never a
/// panic (C2, docs/history/CODE_REVIEW_2026-06.md).
pub(crate) fn decode_utxo_entries(data: &[u8]) -> PirResult<Vec<UtxoEntry>> {
    let mut entries = Vec::new();
    if data.is_empty() {
        return Ok(entries);
    }
    let (count, mut pos) = pir_core::codec::try_read_varint(data)
        .map_err(|e| PirError::Decode(format!("UTXO count varint: {}", e)))?;
    for _ in 0..count {
        if pos + 32 > data.len() {
            break;
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        if pos >= data.len() {
            break;
        }
        let (vout, vr) = pir_core::codec::try_read_varint(&data[pos..])
            .map_err(|e| PirError::Decode(format!("UTXO vout varint: {}", e)))?;
        pos += vr;
        if pos >= data.len() {
            break;
        }
        let (amount, ar) = pir_core::codec::try_read_varint(&data[pos..])
            .map_err(|e| PirError::Decode(format!("UTXO amount varint: {}", e)))?;
        pos += ar;
        entries.push(UtxoEntry {
            txid,
            vout: vout as u32,
            amount_sats: amount,
        });
    }
    Ok(entries)
}

/// Hex-format a 20-byte script hash as "aabbcc..eeff" (first and last 4 bytes).
/// Avoids pulling in the `hex` crate for one audit-log string; mirrors the
/// helper in `dpf.rs` so both clients log query traces identically.
#[allow(dead_code)]
pub(crate) fn format_hash_short(h: &[u8]) -> String {
    if h.len() <= 8 {
        let mut s = String::with_capacity(h.len() * 2);
        for b in h {
            s.push_str(&format!("{:02x}", b));
        }
        return s;
    }
    let mut s = String::with_capacity(22);
    for b in &h[..4] {
        s.push_str(&format!("{:02x}", b));
    }
    s.push_str("..");
    for b in &h[h.len() - 4..] {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
