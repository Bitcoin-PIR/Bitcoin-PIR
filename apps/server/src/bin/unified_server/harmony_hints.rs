use crate::oram::{CuckooTableAccess, MmapCuckooTable};
use harmonypir::params::Params;
use harmonypir::prp::hoang::HoangPrp;
use rayon::prelude::*;
use runtime::protocol::*;
use runtime::table::{MappedDatabase, MappedSubTable};

// ─── HarmonyPIR hint computation ────────────────────────────────────────────

pub(crate) fn derive_group_key(master_key: &[u8; 16], group_id: u32) -> [u8; 16] {
    let mut key = *master_key;
    let id_bytes = group_id.to_le_bytes();
    for i in 0..4 {
        key[12 + i] ^= id_bytes[i];
    }
    key
}

pub(crate) fn xor_into_hint(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

/// Resolve a HarmonyPIR level byte to its sub-table, entry size, and
/// hint-key group offset, or `None` if the level doesn't exist for this
/// DB.
///
/// Level mapping (shared by the hint and batch-query paths):
///   0 = INDEX, 1 = CHUNK
///   10..10+N = bucket Merkle INDEX sibling L0, L1, ...
///   20..20+N = bucket Merkle CHUNK sibling L0, L1, ...
///
/// The level byte arrives off the wire, so resolution must be total —
/// an unknown level is a `None` (mapped to `Response::Error` at the
/// call sites), never a panic: with the workspace-wide
/// `panic = 'abort'`, a panic here kills the whole server (S4).
pub(crate) fn harmony_level_table(
    db: &MappedDatabase,
    level: u8,
) -> Option<(&MappedSubTable, usize, u32)> {
    let index_k = db.index.params.k as u32;
    let chunk_k = db.chunk.params.k as u32;
    match level {
        0 => Some((&db.index, db.index.params.bin_size(), 0)),
        1 => Some((&db.chunk, db.chunk.params.bin_size(), index_k)),
        10..=19 => {
            let sib_level = (level - 10) as usize;
            let sib = db.bucket_merkle_index_siblings.get(sib_level)?;
            // k_offset: after INDEX (75) + CHUNK (80) = 155, plus level offset
            let offset = index_k + chunk_k + sib_level as u32 * index_k;
            Some((sib, sib.params.bin_size(), offset))
        }
        20..=29 => {
            let sib_level = (level - 20) as usize;
            let sib = db.bucket_merkle_chunk_siblings.get(sib_level)?;
            let index_sib_levels = db.bucket_merkle_index_siblings.len() as u32;
            let offset =
                index_k + chunk_k + index_sib_levels * index_k + sib_level as u32 * chunk_k;
            Some((sib, sib.params.bin_size(), offset))
        }
        _ => None,
    }
}
/// Reject a `REQ_HARMONY_HINTS` request whose level or group ids don't
/// exist for this DB *before* any blocking hint work is spawned. Both
/// fields are attacker-controlled. Pre-validating keeps the per-group
/// streaming contract intact for valid requests (every requested group
/// yields exactly one record) while turning invalid ones into a clean
/// `Response::Error` instead of a panic inside the rayon pool (S4) —
/// and caps the request at one hint per group, so a single frame cannot
/// queue unbounded PRP work (S5).
pub(crate) fn validate_harmony_hints_request(
    db: &MappedDatabase,
    level: u8,
    group_ids: &[u8],
) -> Result<(), String> {
    let (sub_table, _, _) =
        harmony_level_table(db, level).ok_or_else(|| format!("invalid hint level {}", level))?;
    let k = sub_table.params.k;
    if group_ids.len() > k {
        return Err(format!(
            "too many group_ids: {} > k {} for level {}",
            group_ids.len(),
            k,
            level
        ));
    }
    for &gid in group_ids {
        if gid as usize >= k {
            return Err(format!(
                "group_id {} out of range for level {} (k = {})",
                gid, level, k
            ));
        }
    }
    Ok(())
}

/// A pending V2Half session is bound to the database that supplied its first
/// half. The same client token must never splice halves from different pools.
pub(crate) fn validate_harmony_v2_half_database(
    bound_db_id: u8,
    requested_db_id: u8,
) -> Result<(), String> {
    if requested_db_id != bound_db_id {
        return Err(format!(
            "HarmonyPIR V2 half token is bound to db {}, not requested db {}",
            bound_db_id, requested_db_id
        ));
    }
    Ok(())
}

pub(crate) fn compute_hints_for_group(
    db: &MappedDatabase,
    prp_key: &[u8; 16],
    prp_backend: u8,
    level: u8,
    group_id: u8,
) -> Result<(u8, u32, u32, u32, Vec<u8>), String> {
    // Requests are pre-screened by validate_harmony_hints_request, but
    // stay total here too — an Err drops the group record, never the
    // process.
    let (sub_table, entry_size, k_offset) =
        harmony_level_table(db, level).ok_or_else(|| format!("invalid hint level {}", level))?;

    // S4: group_id comes off the wire — bounds-check before slicing the
    // mmap (group_id ≥ k would read past the table, and panic = 'abort'
    // turns that into a full-process kill). Checked before the PRP work
    // below so a rejected group costs nothing.
    let table_bytes = sub_table
        .try_group_bytes(group_id as usize)
        .ok_or_else(|| format!("group_id {} out of range for level {}", group_id, level))?;

    let real_n = sub_table.bins_per_table;
    let w = entry_size;

    let t_raw = harmonypir::remote::find_best_t(real_n as u32);
    let (padded_n, t_val) = harmonypir::remote::pad_n_for_t(real_n as u32, t_raw)
        .expect("validated non-zero HarmonyPIR table dimensions");
    let pn = padded_n as usize;
    let t = t_val as usize;

    let params = Params::new(pn, w, t).expect("valid params");
    let m = params.m;

    let derived_key = derive_group_key(prp_key, k_offset + group_id as u32);
    let domain = 2 * pn;
    let r = harmonypir::remote::compute_rounds(padded_n);

    use harmonypir::prp::BatchPrp;
    // PRP_ALF (= 2) is not part of the remote-client wire contract.
    // and crates/sdk/client/src/harmony/mod.rs for the rationale (panic on
    // domain<65536 crashed pir-vpsbg in a tight loop).
    let cell_of: Vec<usize> = match prp_backend {
        #[cfg(feature = "fastprp")]
        harmonypir::remote::PRP_FASTPRP => {
            use harmonypir::prp::fast::FastPrpWrapper;
            let prp = FastPrpWrapper::new(&derived_key, domain);
            prp.batch_forward()
        }
        harmonypir::remote::PRP_HMR12 => {
            let prp = HoangPrp::new(domain, r, &derived_key);
            prp.batch_forward()
        }
        #[cfg(not(feature = "fastprp"))]
        harmonypir::remote::PRP_FASTPRP => {
            return Err(
                "FastPRP requested, but runtime was built without the `fastprp` feature".into(),
            );
        }
        other => {
            return Err(format!("unsupported HarmonyPIR PRP backend {}", other));
        }
    };

    let mut hints: Vec<Vec<u8>> = (0..m).map(|_| vec![0u8; w]).collect();
    for k in 0..pn {
        let segment = cell_of[k] / t;
        if k < real_n {
            let entry = &table_bytes[k * entry_size..(k + 1) * entry_size];
            xor_into_hint(&mut hints[segment], entry);
        }
    }

    let flat: Vec<u8> = hints.into_iter().flat_map(|h| h.into_iter()).collect();
    Ok((group_id, padded_n, t_val, m as u32, flat))
}

/// Serve a single HarmonyPIR query against `db`. Free-function seam for
/// `UnifiedServerData::handle_harmony_query` so the S4/S5 guards are
/// unit-testable without booting the multi-GB server state (same
/// pattern as `build_announce_response`).
pub(crate) fn harmony_query_response(db: &MappedDatabase, query: &HarmonyQuery) -> Response {
    let (sub_table, entry_size) = match query.level {
        0 => (&db.index, db.index.params.bin_size()),
        1 => (&db.chunk, db.chunk.params.bin_size()),
        _ => return Response::Error("invalid level".into()),
    };
    let table = MmapCuckooTable::new(sub_table, entry_size);
    harmony_query_response_from_table(&table, query)
}

pub(crate) fn harmony_query_response_from_table<T: CuckooTableAccess>(
    table: &T,
    query: &HarmonyQuery,
) -> Response {
    // S4: group_id comes straight off the wire — bounds-check it before
    // slicing the mmap.
    let group_id = query.group_id as usize;
    if !table.group_exists(group_id) {
        return Response::Error(format!("group_id {} out of range", query.group_id));
    }

    // S5: validate the index count before allocating. A legitimate
    // query carries T − 1 distinct indices in [0, real_n), so more
    // indices than bins is invalid — reject it instead of reserving
    // indices.len() × entry_size bytes for an attacker-sized list.
    if query.indices.len() > table.bins_per_table() {
        return Response::Error(format!(
            "too many indices: {} > bins_per_table {}",
            query.indices.len(),
            table.bins_per_table()
        ));
    }

    let mut data = Vec::with_capacity(query.indices.len() * table.entry_size());
    if let Err(msg) = table.append_entries(group_id, &query.indices, false, &mut data) {
        table.abort_request(&msg);
        return Response::Error(msg);
    }
    if let Err(msg) = table.finish_request() {
        return Response::Error(msg);
    }

    Response::HarmonyQueryResult(HarmonyQueryResult {
        group_id: query.group_id,
        round_id: query.round_id,
        data,
    })
}

/// Serve a HarmonyPIR batch query against `db`. Free-function seam for
/// `UnifiedServerData::handle_harmony_batch_query` (see
/// `harmony_query_response`). Unlike the single-query path this also
/// serves the bucket-Merkle sibling levels, and zero-fills out-of-range
/// indices inside an accepted sub-query (pre-existing wire behavior of
/// this binary) rather than skipping them.
pub(crate) fn harmony_batch_response(db: &MappedDatabase, query: &HarmonyBatchQuery) -> Response {
    let (sub_table, entry_size, _) = match harmony_level_table(db, query.level) {
        Some(t) => t,
        None => return Response::Error(format!("invalid level {}", query.level)),
    };
    let table = MmapCuckooTable::new(sub_table, entry_size);
    harmony_batch_response_from_table(&table, query)
}

pub(crate) fn harmony_batch_response_from_table<T: CuckooTableAccess>(
    table: &T,
    query: &HarmonyBatchQuery,
) -> Response {
    let result_items: Result<Vec<HarmonyBatchResultItem>, String> = query
        .items
        .par_iter()
        .map(|item| {
            // S4: group_id comes straight off the wire — bounds-check
            // it before slicing the mmap.
            let group_id = item.group_id as usize;
            if !table.group_exists(group_id) {
                return Err(format!("group_id {} out of range", item.group_id));
            }
            let sub_results: Result<Vec<Vec<u8>>, String> = item
                .sub_queries
                .iter()
                .map(|indices| {
                    // S5: validate the index count before allocating (see
                    // harmony_query_response).
                    if indices.len() > table.bins_per_table() {
                        return Err(format!(
                            "too many indices: {} > bins_per_table {}",
                            indices.len(),
                            table.bins_per_table()
                        ));
                    }
                    let mut data = Vec::with_capacity(indices.len() * table.entry_size());
                    table.append_entries(group_id, indices, true, &mut data)?;
                    Ok(data)
                })
                .collect();
            Ok(HarmonyBatchResultItem {
                group_id: item.group_id,
                sub_results: sub_results?,
            })
        })
        .collect();

    let result_items = match result_items {
        Ok(items) => items,
        Err(msg) => {
            table.abort_request(&msg);
            return Response::Error(msg);
        }
    };

    if let Err(msg) = table.finish_request() {
        return Response::Error(msg);
    }

    Response::HarmonyBatchResult(HarmonyBatchResult {
        level: query.level,
        round_id: query.round_id,
        sub_results_per_group: query.sub_queries_per_group,
        items: result_items,
    })
}
