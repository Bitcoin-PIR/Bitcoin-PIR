//! Shared wire-protocol helpers for PIR clients.
//!
//! All three native clients (`DpfClient`, `HarmonyClient`, `OnionClient`) speak
//! to the same `unified_server` binary and share a handful of primitives:
//!
//! * the `[4B len LE][1B variant][payload]` request frame,
//! * the `REQ_GET_DB_CATALOG` / `RESP_DB_CATALOG` shape defined by
//!   [`runtime::protocol`], and
//! * the generic `RESP_ERROR = 0xff` envelope the server uses for soft errors.
//!
//! Centralising them here keeps the clients in lock-step with the server's
//! wire format — previously each client maintained its own copy of
//! `decode_catalog`, and three separate off-by-one fixes had to be tracked
//! whenever the catalog layout changed.

use pir_sdk::{DatabaseCatalog, DatabaseInfo, DatabaseKind, PirError, PirResult};

// ─── Wire constants (mirror `runtime::protocol`) ────────────────────────────

/// Request-catalog variant byte. Supported by both Harmony roles
/// (hint + query) and the DPF/Onion `unified_server` builds — the match arm
/// in `unified_server.rs::REQ_GET_DB_CATALOG` runs before any role check.
pub(crate) const REQ_GET_DB_CATALOG: u8 = 0x02;

/// Successful catalog response variant.
pub(crate) const RESP_DB_CATALOG: u8 = 0x02;

/// Generic server-side error envelope: `[0xff][utf8 reason...]`. Clients must
/// short-circuit to a protocol error before attempting to decode the body.
pub(crate) const RESP_ERROR: u8 = 0xff;

// ─── Request framing ────────────────────────────────────────────────────────

/// Build a `[4B len LE][1B variant][payload]` request frame.
///
/// This is the wrapper the server expects on every WebSocket message —
/// `WsConnection::send` just writes the buffer through, and `roundtrip()`
/// strips the outer length prefix from the response before returning.
pub(crate) fn encode_request(variant: u8, payload: &[u8]) -> Vec<u8> {
    let total_len = 1 + payload.len();
    let mut buf = Vec::with_capacity(4 + total_len);
    buf.extend_from_slice(&(total_len as u32).to_le_bytes());
    buf.push(variant);
    buf.extend_from_slice(payload);
    buf
}

/// Parse the v2 trailing fields (index/chunk cuckoo master seed + chain
/// anchor) from a `RESP_INFO` / `RESP_HARMONY_INFO` response body.
///
/// `resp` includes the leading RESP byte at index 0; the legacy fields
/// occupy `[1..19]` and the v2 tail (if present) begins at offset 19:
/// `[8B index_master_seed][8B chunk_master_seed][1B anchor_kind][0/36/72B anchor]`.
/// Returns `(0, 0, 0, [])` when the tail is absent (pre-ext server).
pub(crate) fn parse_info_v2_tail(resp: &[u8]) -> (u64, u64, u8, Vec<u8>) {
    if resp.len() < 35 {
        return (0, 0, 0, Vec::new());
    }
    let ims = u64::from_le_bytes(resp[19..27].try_into().unwrap());
    let cms = u64::from_le_bytes(resp[27..35].try_into().unwrap());
    if resp.len() < 36 {
        return (ims, cms, 0, Vec::new());
    }
    let kind = resp[35];
    let n = match kind {
        1 => 36usize,
        2 => 72usize,
        _ => 0usize,
    };
    if n == 0 || resp.len() < 36 + n {
        return (ims, cms, if n == 0 { 0 } else { kind }, Vec::new());
    }
    (ims, cms, kind, resp[36..36 + n].to_vec())
}

// ─── Catalog decoding ───────────────────────────────────────────────────────

/// Decode a `DatabaseCatalog` from the body of a `RESP_DB_CATALOG` message.
///
/// `data` is expected to start at the first byte AFTER the `RESP_DB_CATALOG`
/// variant byte — callers slice off the leading byte before calling this.
///
/// Wire format matches `runtime::protocol::encode_db_catalog`:
/// `[1B num_dbs][entry...]*` where each entry is
/// `[1B db_id][1B db_type][1B name_len][name][29B fixed]`.
///
/// `num_dbs` is a single byte — a prior u16 read silently accepted
/// single-entry catalogs (since `db_id == 0x00` made the high byte zero)
/// but then pushed the cursor off-by-one into every subsequent field,
/// producing "truncated catalog name" against real servers.
pub(crate) fn decode_catalog(data: &[u8]) -> PirResult<DatabaseCatalog> {
    if data.is_empty() {
        return Err(PirError::Decode("catalog too short".into()));
    }
    let num_dbs = data[0] as usize;
    let mut pos = 1;
    let mut databases = Vec::with_capacity(num_dbs);

    for _ in 0..num_dbs {
        if pos + 3 > data.len() {
            return Err(PirError::Decode("truncated catalog entry header".into()));
        }
        let db_id = data[pos];
        pos += 1;
        let db_type = data[pos];
        pos += 1;
        let name_len = data[pos] as usize;
        pos += 1;
        if pos + name_len > data.len() {
            return Err(PirError::Decode("truncated catalog name".into()));
        }
        let name = String::from_utf8_lossy(&data[pos..pos + name_len]).into_owned();
        pos += name_len;

        // 29 fixed bytes: base_height(4) + height(4) + index_bins(4)
        // + chunk_bins(4) + index_k(1) + chunk_k(1) + tag_seed(8)
        // + dpf_n_index(1) + dpf_n_chunk(1) + has_bucket_merkle(1).
        if pos + 29 > data.len() {
            return Err(PirError::Decode("truncated catalog fields".into()));
        }
        let base_height = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let height = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let index_bins = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let chunk_bins = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let index_k = data[pos];
        pos += 1;
        let chunk_k = data[pos];
        pos += 1;
        let tag_seed = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let dpf_n_index = data[pos];
        pos += 1;
        let dpf_n_chunk = data[pos];
        pos += 1;
        let has_bucket_merkle = data[pos] != 0;
        pos += 1;

        let kind = if db_type == 1 {
            DatabaseKind::Delta { base_height }
        } else {
            DatabaseKind::Full
        };

        databases.push(DatabaseInfo {
            db_id,
            kind,
            name,
            height,
            index_bins,
            chunk_bins,
            index_k,
            chunk_k,
            tag_seed,
            dpf_n_index,
            dpf_n_chunk,
            has_bucket_merkle,
            // Patched from the trailing ext section below; defaults for a
            // legacy server that doesn't emit it.
            index_master_seed: 0,
            chunk_master_seed: 0,
            anchor_kind: 0,
            anchor_bytes: Vec::new(),
        });
    }

    // Trailing ext section (CATALOG_EXT_V1): per-entry master seeds + anchor.
    // Mirrors runtime::protocol::encode_db_catalog. Absent against a
    // pre-ext server — leave the defaults above.
    const CATALOG_EXT_V1: u8 = 0x01;
    if pos < data.len() && data[pos] == CATALOG_EXT_V1 {
        pos += 1;
        for db in databases.iter_mut() {
            if pos + 17 > data.len() {
                return Err(PirError::Decode("truncated catalog ext entry".into()));
            }
            db.index_master_seed = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
            pos += 8;
            db.chunk_master_seed = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
            pos += 8;
            let kind = data[pos];
            pos += 1;
            let n = match kind {
                0 => 0usize,
                1 => 36usize,
                2 => 72usize,
                other => {
                    return Err(PirError::Decode(format!(
                        "unknown catalog anchor kind {}",
                        other
                    )))
                }
            };
            if pos + n > data.len() {
                return Err(PirError::Decode("truncated catalog anchor bytes".into()));
            }
            db.anchor_kind = kind;
            db.anchor_bytes = data[pos..pos + n].to_vec();
            pos += n;
        }
    }

    // Refuse a database whose delivered seeds don't match its embedded
    // chain anchor (no-op for legacy DBs without an anchor).
    for db in &databases {
        validate_db_geometry(db)?;
        db.verify_anchor_seeds().map_err(|e| {
            PirError::Protocol(format!(
                "DB {} ({}) chain-anchor seed verification failed: {}",
                db.db_id, db.name, e
            ))
        })?;
    }
    Ok(DatabaseCatalog { databases })
}

/// Reject server-supplied database geometry that would wedge or crash
/// the client.
///
/// `index_k` / `chunk_k` feed the PBC planners (`derive_groups_3` /
/// `derive_int_groups_3`), which rejection-sample until they collect
/// 3 *distinct* groups mod k — with k < 3 that loop never terminates,
/// so a malicious or corrupted catalog could pin the client at 100 %
/// CPU forever (same trust boundary as the C2/C3 malicious-server
/// findings; production values are 75/80). Zero bins would turn the
/// downstream cuckoo bin hashing (`h % bins`) into a divide-by-zero
/// panic.
pub(crate) fn validate_db_geometry(db: &DatabaseInfo) -> PirResult<()> {
    if db.index_k < 3 || db.chunk_k < 3 {
        return Err(PirError::Decode(format!(
            "DB {} ({}) k out of range: index_k={} chunk_k={} (PBC planning needs k >= 3)",
            db.db_id, db.name, db.index_k, db.chunk_k
        )));
    }
    if db.index_bins == 0 || db.chunk_bins == 0 {
        return Err(PirError::Decode(format!(
            "DB {} ({}) has zero bins: index_bins={} chunk_bins={}",
            db.db_id, db.name, db.index_bins, db.chunk_bins
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip one full catalog entry through `decode_catalog`, mirroring
    /// the server encoder's exact byte layout.
    #[test]
    fn decode_catalog_single_entry() {
        // 1 num_dbs + entry(1 db_id + 1 db_type + 1 name_len + 4 name + 29 fixed)
        let mut buf = Vec::new();
        buf.push(1u8); // num_dbs
        buf.push(0u8); // db_id
        buf.push(0u8); // db_type (full)
        buf.push(4u8); // name_len
        buf.extend_from_slice(b"main");
        buf.extend_from_slice(&0u32.to_le_bytes()); // base_height
        buf.extend_from_slice(&900_000u32.to_le_bytes()); // height
        buf.extend_from_slice(&750_000u32.to_le_bytes()); // index_bins
        buf.extend_from_slice(&1_500_000u32.to_le_bytes()); // chunk_bins
        buf.push(75u8); // index_k
        buf.push(80u8); // chunk_k
        buf.extend_from_slice(&0xdead_beef_cafe_f00du64.to_le_bytes()); // tag_seed
        buf.push(17u8); // dpf_n_index
        buf.push(18u8); // dpf_n_chunk
        buf.push(1u8); // has_bucket_merkle

        let catalog = decode_catalog(&buf).expect("decode");
        assert_eq!(catalog.databases.len(), 1);
        let db = &catalog.databases[0];
        assert_eq!(db.db_id, 0);
        assert!(matches!(db.kind, DatabaseKind::Full));
        assert_eq!(db.name, "main");
        assert_eq!(db.height, 900_000);
        assert_eq!(db.index_bins, 750_000);
        assert_eq!(db.chunk_bins, 1_500_000);
        assert_eq!(db.index_k, 75);
        assert_eq!(db.chunk_k, 80);
        assert_eq!(db.tag_seed, 0xdead_beef_cafe_f00d);
        assert!(db.has_bucket_merkle);
    }

    #[test]
    fn decode_catalog_rejects_empty() {
        let err = decode_catalog(&[]).unwrap_err();
        assert!(matches!(err, PirError::Decode(_)));
    }

    /// Build the same well-formed single-entry catalog as
    /// `decode_catalog_single_entry`, with caller-chosen geometry.
    fn catalog_with_geometry(index_bins: u32, chunk_bins: u32, index_k: u8, chunk_k: u8) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(1u8); // num_dbs
        buf.push(0u8); // db_id
        buf.push(0u8); // db_type (full)
        buf.push(4u8); // name_len
        buf.extend_from_slice(b"main");
        buf.extend_from_slice(&0u32.to_le_bytes()); // base_height
        buf.extend_from_slice(&900_000u32.to_le_bytes()); // height
        buf.extend_from_slice(&index_bins.to_le_bytes());
        buf.extend_from_slice(&chunk_bins.to_le_bytes());
        buf.push(index_k);
        buf.push(chunk_k);
        buf.extend_from_slice(&0xdead_beef_cafe_f00du64.to_le_bytes()); // tag_seed
        buf.push(17u8); // dpf_n_index
        buf.push(18u8); // dpf_n_chunk
        buf.push(1u8); // has_bucket_merkle
        buf
    }

    /// A malicious catalog advertising k < 3 must be rejected at decode
    /// time: `derive_groups_3` / `derive_int_groups_3` rejection-sample
    /// 3 *distinct* groups mod k, so k = 2 would otherwise pin the
    /// client in an infinite 100 %-CPU loop on its first query.
    #[test]
    fn decode_catalog_rejects_k_below_pbc_minimum() {
        for (ik, ck) in [(2u8, 80u8), (75, 2), (0, 0), (1, 1)] {
            let err = decode_catalog(&catalog_with_geometry(750_000, 1_500_000, ik, ck))
                .unwrap_err();
            match err {
                PirError::Decode(msg) => assert!(
                    msg.contains("k out of range"),
                    "index_k={ik} chunk_k={ck}: unexpected message {msg:?}"
                ),
                other => panic!("index_k={ik} chunk_k={ck}: expected Decode, got {other:?}"),
            }
        }
        // k = 3 (the minimum) is accepted.
        decode_catalog(&catalog_with_geometry(750_000, 1_500_000, 3, 3)).expect("k = 3 is valid");
    }

    /// Zero bins would turn downstream cuckoo bin hashing (`h % bins`)
    /// into a divide-by-zero panic — rejected at decode time.
    #[test]
    fn decode_catalog_rejects_zero_bins() {
        for (ib, cb) in [(0u32, 1_500_000u32), (750_000, 0), (0, 0)] {
            let err = decode_catalog(&catalog_with_geometry(ib, cb, 75, 80)).unwrap_err();
            match err {
                PirError::Decode(msg) => assert!(
                    msg.contains("zero bins"),
                    "index_bins={ib} chunk_bins={cb}: unexpected message {msg:?}"
                ),
                other => panic!("index_bins={ib} chunk_bins={cb}: expected Decode, got {other:?}"),
            }
        }
    }

    #[test]
    fn decode_catalog_rejects_truncated_entry() {
        // num_dbs=1 but no entry bytes follow.
        let err = decode_catalog(&[1u8]).unwrap_err();
        assert!(matches!(err, PirError::Decode(_)));
    }

    #[test]
    fn encode_request_layout() {
        let r = encode_request(0x02, b"hi");
        // [len=3 LE][variant][payload]
        assert_eq!(&r[..4], &3u32.to_le_bytes());
        assert_eq!(r[4], 0x02);
        assert_eq!(&r[5..], b"hi");
    }
}
