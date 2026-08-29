use super::*;

// ─── HarmonyPIR sibling querier for per-bucket Merkle ───────────────────────

/// HarmonyPIR-specific [`BucketMerkleSiblingQuerier`] impl.
///
/// One instance drives all sibling-level batches for one call to
/// `verify_bucket_merkle_batch_generic`. It borrows the query connection
/// and the sibling-group maps (owned by [`HarmonyClient`]) for the
/// duration of the verification, so the caller must `std::mem::take` them
/// out first to satisfy the borrow checker — see
/// `HarmonyClient::run_merkle_verification` for the pattern.
///
/// Each call to [`BucketMerkleSiblingQuerier::query_pass`] runs one
/// server round-trip on the query server:
///
/// * exactly K (INDEX) or K_CHUNK (CHUNK) sub-queries — one per PBC group —
///   matching `pass_targets.len()`;
/// * real slots use `HarmonyGroup::build_request` + `process_response`
///   to recover the 256-byte sibling row;
/// * padding slots use `HarmonyGroup::build_synthetic_dummy` so the server
///   cannot distinguish real from padding (see CLAUDE.md "Query Padding").
///
/// The `level` byte sent on the wire is `10 + merkle_level` for INDEX
/// sibling rounds and `20 + merkle_level` for CHUNK, matching the server
/// convention (see `runtime::protocol::HarmonyBatchQuery`).
pub(crate) struct HarmonySiblingQuerier<'a> {
    /// Query server transport — held mutably across the verification.
    /// Typed as `&mut dyn PirTransport` so the verifier works against
    /// any PirTransport impl (WsConnection in production; MockTransport
    /// in tests; a future WASM WebSocket impl without a code change).
    pub(crate) query_conn: &'a mut dyn PirTransport,
    /// INDEX sibling groups keyed by `(merkle_level, group_id)`.
    /// Populated by `HarmonyClient::ensure_sibling_groups_ready`.
    pub(crate) index_sib_groups: &'a mut HashMap<(usize, u8), HarmonyGroup>,
    /// CHUNK sibling groups keyed by `(merkle_level, group_id)`.
    pub(crate) chunk_sib_groups: &'a mut HashMap<(usize, u8), HarmonyGroup>,
    /// Merkle leakage rounds, buffered in this querier's own issue
    /// order — level 0 → N, and pass h0 → h1 within a level. Each pass
    /// appends one `IndexMerkleSiblings` / `ChunkMerkleSiblings` round
    /// tagged `server_id = 0` (HarmonyPIR Merkle has no per-server
    /// fan-out).
    ///
    /// Rounds are BUFFERED here, not recorded inline, because
    /// `verify_bucket_merkle_batch_parallel` drives two queriers
    /// concurrently on separate sockets. Recording inline would
    /// interleave INDEX- and CHUNK-Merkle rounds in wall-clock order —
    /// a timing artifact that varies run-to-run and, worse, correlates
    /// with found-vs-not-found (the CHUNK querier spends a hair more
    /// CPU building a real slot than a dummy). That makes a found
    /// query wire-distinguishable from a not-found one purely by
    /// Merkle-round order. `verify_merkle_items` drains the buffer(s)
    /// into the real recorder in a fixed INDEX-then-CHUNK sequence —
    /// matching the sequential DPF verifier — so the leakage profile
    /// stays deterministic and content-independent.
    pub(crate) recorded: &'a mut Vec<RoundProfile>,
}

pub(crate) struct PreparedHarmonySiblingLevel {
    pub(crate) table_type: u8,
    pub(crate) level: usize,
    pub(crate) db_id: u8,
    pub(crate) targets: Vec<Vec<Option<u32>>>,
    pub(crate) requests: Vec<Vec<u8>>,
    pub(crate) request_bytes: Vec<u64>,
    pub(crate) items_per_group: Vec<Vec<u32>>,
}

impl HarmonySiblingQuerier<'_> {
    fn sibling_group_mut(
        &mut self,
        table_type: u8,
        level: usize,
        group: u8,
    ) -> PirResult<&mut HarmonyGroup> {
        match table_type {
            0 => self.index_sib_groups.get_mut(&(level, group)),
            1 => self.chunk_sib_groups.get_mut(&(level, group)),
            other => {
                return Err(PirError::InvalidState(format!(
                    "unknown sibling table_type {}",
                    other
                )))
            }
        }
        .ok_or_else(|| {
            PirError::InvalidState(format!(
                "missing sibling group (table={}, level={}, group={})",
                table_type, level, group
            ))
        })
    }

    fn prepare_cross_level(
        &mut self,
        table_type: u8,
        level: usize,
        passes: &[Vec<Option<u32>>],
        db_id: u8,
    ) -> PirResult<PreparedHarmonySiblingLevel> {
        if passes.is_empty() || passes.len() > 2 {
            return Err(PirError::InvalidState(format!(
                "Harmony cross-level pipeline supports one or two passes, got {}",
                passes.len()
            )));
        }
        let table_k = passes[0].len();
        if passes.iter().any(|pass| pass.len() != table_k) {
            return Err(PirError::InvalidState(
                "Harmony cross-level pipeline received unequal pass widths".into(),
            ));
        }
        let wire_level = match table_type {
            0 => 10u8.checked_add(level as u8),
            1 => 20u8.checked_add(level as u8),
            _ => None,
        }
        .ok_or_else(|| {
            PirError::InvalidState(format!("sibling level {} does not fit in wire byte", level))
        })?;

        let mut bytes_by_pass: Vec<Vec<Vec<u8>>> = (0..passes.len())
            .map(|_| Vec::with_capacity(table_k))
            .collect();
        for group_idx in 0..table_k {
            let group_id = group_idx as u8;
            let group = self.sibling_group_mut(table_type, level, group_id)?;
            if passes.len() == 2 {
                if let (Some(target0), Some(target1)) = (passes[0][group_idx], passes[1][group_idx])
                {
                    let (request0, request1) = group
                        .build_request_pair(target0, target1)
                        .map_err(|error| {
                            PirError::BackendState(format!("sib build_request_pair: {:?}", error))
                        })?
                        .into_parts();
                    bytes_by_pass[0].push(request0.into_bytes());
                    bytes_by_pass[1].push(request1.into_bytes());
                    continue;
                }
            }
            for (pass_idx, pass) in passes.iter().enumerate() {
                let bytes = match pass[group_idx] {
                    Some(target) => group
                        .build_request(target)
                        .map_err(|error| {
                            PirError::BackendState(format!("sib build_request: {:?}", error))
                        })?
                        .into_bytes(),
                    None => group.build_synthetic_dummy(),
                };
                bytes_by_pass[pass_idx].push(bytes);
            }
        }

        let batch_items_by_pass: Vec<Vec<BatchItem>> = bytes_by_pass
            .iter()
            .map(|pass| {
                pass.iter()
                    .enumerate()
                    .map(|(group, bytes)| {
                        Ok(BatchItem {
                            group_id: group as u8,
                            indices: bytes_to_u32_vec(bytes)?,
                        })
                    })
                    .collect::<PirResult<Vec<_>>>()
            })
            .collect::<PirResult<Vec<_>>>()?;
        let mut requests = Vec::with_capacity(passes.len());
        for (pass_idx, items) in batch_items_by_pass.iter().enumerate() {
            let round_id = if passes.len() == 1 {
                (table_type as u16) * 100 + level as u16
            } else {
                (table_type as u16) * 1000 + (level as u16) * 10 + pass_idx as u16
            };
            requests.push(encode_batch_query(wire_level, round_id, db_id, items));
        }
        Ok(PreparedHarmonySiblingLevel {
            table_type,
            level,
            db_id,
            targets: passes.to_vec(),
            request_bytes: requests
                .iter()
                .map(|request| request.len() as u64)
                .collect(),
            items_per_group: batch_items_by_pass
                .iter()
                .map(|items| items.iter().map(|item| item.indices.len() as u32).collect())
                .collect(),
            requests,
        })
    }

    fn finish_cross_level(
        &mut self,
        prepared: &PreparedHarmonySiblingLevel,
        responses: &[Vec<u8>],
    ) -> PirResult<Vec<Vec<Option<Vec<u8>>>>> {
        if responses.len() != prepared.targets.len() {
            return Err(PirError::Protocol(format!(
                "Harmony sibling level {} returned malformed response count",
                prepared.level
            )));
        }
        let level = u8::try_from(prepared.level).map_err(|_| {
            PirError::InvalidState(format!(
                "Harmony sibling level {} does not fit in wire byte",
                prepared.level
            ))
        })?;
        let wire_level = match prepared.table_type {
            0 => 10u8.checked_add(level),
            1 => 20u8.checked_add(level),
            other => {
                return Err(PirError::InvalidState(format!(
                    "unknown sibling table_type {other}"
                )))
            }
        }
        .ok_or_else(|| PirError::InvalidState("Harmony sibling wire level overflow".into()))?;
        let table_k = prepared.targets[0].len();
        let decoded: Vec<_> = responses
            .iter()
            .enumerate()
            .map(|(pass_idx, response)| {
                let round_id = if prepared.targets.len() == 1 {
                    (prepared.table_type as u16) * 100 + level as u16
                } else {
                    (prepared.table_type as u16) * 1000 + (level as u16) * 10 + pass_idx as u16
                };
                decode_batch_response_frame(
                    response,
                    wire_level,
                    round_id,
                    table_k,
                    "Harmony sibling response",
                )
            })
            .collect::<PirResult<Vec<_>>>()?;
        let mut out = vec![vec![None; table_k]; prepared.targets.len()];

        for group_idx in 0..table_k {
            let group_id = group_idx as u8;
            let group = self.sibling_group_mut(prepared.table_type, prepared.level, group_id)?;
            if prepared.targets.len() == 2
                && prepared.targets[0][group_idx].is_some()
                && prepared.targets[1][group_idx].is_some()
            {
                let response0 = decoded[0].get(&group_id).ok_or_else(|| {
                    PirError::Protocol(format!("missing sibling h=0 group {}", group_id))
                })?;
                let response1 = decoded[1].get(&group_id).ok_or_else(|| {
                    PirError::Protocol(format!("missing sibling h=1 group {}", group_id))
                })?;
                let (row0, row1) =
                    group
                        .process_response_pair(response0, response1)
                        .map_err(|error| {
                            PirError::BackendState(format!(
                                "sib process_response_pair: {:?}",
                                error
                            ))
                        })?;
                if row0.len() != BUCKET_MERKLE_SIB_ROW_SIZE
                    || row1.len() != BUCKET_MERKLE_SIB_ROW_SIZE
                {
                    return Err(PirError::Protocol(
                        "pipelined sibling pair has wrong row size".into(),
                    ));
                }
                out[0][group_idx] = Some(row0);
                out[1][group_idx] = Some(row1);
                continue;
            }
            for pass_idx in 0..prepared.targets.len() {
                if prepared.targets[pass_idx][group_idx].is_none() {
                    continue;
                }
                let response = decoded[pass_idx].get(&group_id).ok_or_else(|| {
                    PirError::Protocol(format!(
                        "missing sibling response for pass {}, group {}",
                        pass_idx, group_id
                    ))
                })?;
                let row = group.process_response(response).map_err(|error| {
                    PirError::BackendState(format!("sib process_response: {:?}", error))
                })?;
                if row.len() != BUCKET_MERKLE_SIB_ROW_SIZE {
                    return Err(PirError::Protocol(format!(
                        "sibling row has {} bytes, expected {}",
                        row.len(),
                        BUCKET_MERKLE_SIB_ROW_SIZE
                    )));
                }
                out[pass_idx][group_idx] = Some(row);
            }
        }
        Ok(out)
    }
}

#[async_trait]
impl BucketMerkleSiblingQuerier for HarmonySiblingQuerier<'_> {
    async fn query_pass(
        &mut self,
        table_type: u8,
        level: usize,
        _level_bins_per_table: u32,
        pass_targets: &[Option<u32>],
        db_id: u8,
    ) -> PirResult<Vec<Option<Vec<u8>>>> {
        let table_k = pass_targets.len();

        // Wire `level` byte: 10+L for INDEX sib L, 20+L for CHUNK sib L.
        let wire_level: u8 = match table_type {
            0 => 10u8.checked_add(level as u8).ok_or_else(|| {
                PirError::InvalidState(format!(
                    "INDEX sib level {} does not fit in wire byte",
                    level
                ))
            })?,
            1 => 20u8.checked_add(level as u8).ok_or_else(|| {
                PirError::InvalidState(format!(
                    "CHUNK sib level {} does not fit in wire byte",
                    level
                ))
            })?,
            other => {
                return Err(PirError::InvalidState(format!(
                    "unknown sibling table_type {}",
                    other
                )))
            }
        };

        // Track which slots issued a real request so we can call
        // process_response on exactly those groups.
        let mut real_slots: Vec<u8> = Vec::new();
        let mut batch_items: Vec<BatchItem> = Vec::with_capacity(table_k);

        for (g_idx, target) in pass_targets.iter().enumerate() {
            let g = g_idx as u8;
            let group = match table_type {
                0 => self.index_sib_groups.get_mut(&(level, g)),
                1 => self.chunk_sib_groups.get_mut(&(level, g)),
                _ => None,
            };
            let group = group.ok_or_else(|| {
                PirError::InvalidState(format!(
                    "missing {} sib group ({}, {})",
                    if table_type == 0 { "INDEX" } else { "CHUNK" },
                    level,
                    g
                ))
            })?;

            let bytes = if let Some(t) = *target {
                real_slots.push(g);
                let req = group
                    .build_request(t)
                    .map_err(|e| PirError::BackendState(format!("sib build_request: {:?}", e)))?;
                req.into_bytes()
            } else {
                group.build_synthetic_dummy()
            };

            batch_items.push(BatchItem {
                group_id: g,
                indices: bytes_to_u32_vec(&bytes)?,
            });
        }

        // round_id mirrors the DPF querier's convention so audit logs align.
        let round_id = (table_type as u16) * 100 + level as u16;
        let request = encode_batch_query(wire_level, round_id, db_id, &batch_items);
        let request_bytes = request.len() as u64;
        // Per-group request shape — every Harmony query slot must send
        // exactly `T - 1` indices (CLAUDE.md "HarmonyPIR Per-Group
        // Request-Count Symmetry"). Capture the actual `indices.len()`
        // so a test can assert the invariant directly.
        let items_per_group: Vec<u32> = batch_items
            .iter()
            .map(|it| it.indices.len() as u32)
            .collect();
        let t_send = Instant::now();
        let response = self.query_conn.roundtrip(&request).await?;
        let dt_wire = t_send.elapsed();
        if std::env::var("HARMONY_BENCH").is_ok() {
            eprintln!(
                "[HARMONY_BENCH]   Merkle pass (table={}, level={}): wire RTT {:?} (req {}B resp {}B)",
                table_type, level, dt_wire, request_bytes, response.len() + 4,
            );
        }
        // Buffer this pass's leakage round; `verify_merkle_items` drains
        // the buffer in a fixed INDEX-then-CHUNK order once both Merkle
        // trees finish — see `HarmonySiblingQuerier.recorded` for why
        // inline recording would leak found-vs-not-found via round order.
        let kind = match table_type {
            1 => RoundKind::ChunkMerkleSiblings { level: level as u8 },
            _ => RoundKind::IndexMerkleSiblings { level: level as u8 },
        };
        self.recorded.push(RoundProfile {
            kind,
            server_id: 0,
            db_id: Some(db_id),
            request_bytes,
            response_bytes: (response.len() as u64).saturating_add(4),
            items: items_per_group,
        });
        let raw_results = decode_batch_response_body(
            &response,
            wire_level,
            round_id,
            table_k,
            "Harmony sibling response",
        )?;

        let mut out: Vec<Option<Vec<u8>>> = vec![None; table_k];
        for g in &real_slots {
            let data = raw_results.get(g).ok_or_else(|| {
                PirError::Protocol(format!(
                    "no sibling response for group {} at table_type={}, level={}",
                    g, table_type, level
                ))
            })?;
            let group = match table_type {
                0 => self.index_sib_groups.get_mut(&(level, *g)),
                1 => self.chunk_sib_groups.get_mut(&(level, *g)),
                _ => None,
            };
            let group = group.ok_or_else(|| {
                PirError::InvalidState(format!("sib group vanished mid-pass ({}, {})", level, g))
            })?;
            let row = group
                .process_response(data)
                .map_err(|e| PirError::BackendState(format!("sib process_response: {:?}", e)))?;
            if row.len() != BUCKET_MERKLE_SIB_ROW_SIZE {
                return Err(PirError::Protocol(format!(
                    "sib response has {} bytes, expected {}",
                    row.len(),
                    BUCKET_MERKLE_SIB_ROW_SIZE
                )));
            }
            out[*g as usize] = Some(row);
        }

        Ok(out)
    }

    /// Pipelined override for the same-level pass batch.
    ///
    /// Within a sibling level, different passes may hit the SAME PBC
    /// group with different items (e.g. INDEX Merkle at the INDEX
    /// Merkle Group-Symmetry collision case: two scripthashes whose
    /// cuckoo positions collide on the same PBC group). For those
    /// groups, the call pattern across passes is
    /// `build_request → build_request → process_response →
    /// process_response`, which corrupts the single-query `last_*`
    /// state slots inside `HarmonyGroup` (the second `build_request`
    /// overwrites the first's state before `process_response` ever
    /// reads it).
    ///
    /// To pipeline safely, we classify each group by its (pass0,
    /// pass1) Real/Dummy pattern and emit calls per-group:
    /// * **RealReal**  → `build_request_pair` + `process_response_pair`.
    ///   The pair API stashes both states in `pending_pair` and
    ///   consumes both atomically — exact equivalent of two sequential
    ///   `build_request`+`process_response` cycles given the same RNG
    ///   seed (verified by upstream `remote` pair-equivalence tests).
    /// * **RealDummy** → `build_request(t)` then `build_synthetic_dummy()`.
    ///   The dummy doesn't touch `last_*`, so pass 0's `process_response`
    ///   reads the real state correctly. Pass 1's dummy slot in
    ///   `pass_out` stays `None`.
    /// * **DummyReal** → `build_synthetic_dummy()` then `build_request(t)`.
    ///   Symmetric to the above; pass 0's slot is `None`, pass 1's is
    ///   the real row.
    /// * **DummyDummy** → two synthetic dummies, no `process_response`
    ///   at all. Both slots stay `None`.
    ///
    /// Currently specialised for `passes.len() == 2` (INDEX Merkle's
    /// `max_items_per_group_per_level = 2`). For other arities we fall
    /// back to the default serial implementation.
    async fn query_passes(
        &mut self,
        table_type: u8,
        level: usize,
        _level_bins_per_table: u32,
        passes: &[Vec<Option<u32>>],
        db_id: u8,
    ) -> PirResult<Vec<Vec<Option<Vec<u8>>>>> {
        if passes.is_empty() {
            return Ok(Vec::new());
        }
        if passes.len() == 1 {
            // Single-pass case: just call query_pass.
            let rows = self
                .query_pass(table_type, level, _level_bins_per_table, &passes[0], db_id)
                .await?;
            return Ok(vec![rows]);
        }
        if passes.len() != 2 {
            // Fallback for >2 passes — not exercised by current
            // production layouts. Default impl serialises.
            let mut out = Vec::with_capacity(passes.len());
            for p in passes {
                let rows = self
                    .query_pass(table_type, level, _level_bins_per_table, p, db_id)
                    .await?;
                out.push(rows);
            }
            return Ok(out);
        }

        let wire_level: u8 = match table_type {
            0 => 10u8.checked_add(level as u8).ok_or_else(|| {
                PirError::InvalidState(format!(
                    "INDEX sib level {} does not fit in wire byte",
                    level
                ))
            })?,
            1 => 20u8.checked_add(level as u8).ok_or_else(|| {
                PirError::InvalidState(format!(
                    "CHUNK sib level {} does not fit in wire byte",
                    level
                ))
            })?,
            other => {
                return Err(PirError::InvalidState(format!(
                    "unknown sibling table_type {}",
                    other
                )))
            }
        };

        let table_k = passes[0].len();
        if passes[1].len() != table_k {
            return Err(PirError::InvalidState(format!(
                "Merkle pipelined passes: pass 0 has {} targets but pass 1 has {}",
                table_k,
                passes[1].len()
            )));
        }

        // Per-group dispatch classification for the 2-pass case.
        #[derive(Clone, Copy)]
        enum PassPattern {
            RealReal(u32, u32),
            RealDummy(u32),
            DummyReal(u32),
            DummyDummy,
        }
        let mut patterns: Vec<PassPattern> = Vec::with_capacity(table_k);
        for g in 0..table_k {
            let p0 = passes[0][g];
            let p1 = passes[1][g];
            patterns.push(match (p0, p1) {
                (Some(t0), Some(t1)) => PassPattern::RealReal(t0, t1),
                (Some(t0), None) => PassPattern::RealDummy(t0),
                (None, Some(t1)) => PassPattern::DummyReal(t1),
                (None, None) => PassPattern::DummyDummy,
            });
        }

        // ── Build per-group request bytes for both passes ──
        let mut bytes_h0: Vec<Vec<u8>> = Vec::with_capacity(table_k);
        let mut bytes_h1: Vec<Vec<u8>> = Vec::with_capacity(table_k);

        for (g_idx, pat) in patterns.iter().enumerate() {
            let g = g_idx as u8;
            let group = match table_type {
                0 => self.index_sib_groups.get_mut(&(level, g)),
                1 => self.chunk_sib_groups.get_mut(&(level, g)),
                _ => None,
            };
            let group = group.ok_or_else(|| {
                PirError::InvalidState(format!(
                    "missing {} sib group ({}, {})",
                    if table_type == 0 { "INDEX" } else { "CHUNK" },
                    level,
                    g
                ))
            })?;

            match *pat {
                PassPattern::RealReal(t0, t1) => {
                    let pair = group.build_request_pair(t0, t1).map_err(|e| {
                        PirError::BackendState(format!("sib build_request_pair: {:?}", e))
                    })?;
                    let (req_1, req_2) = pair.into_parts();
                    bytes_h0.push(req_1.into_bytes());
                    bytes_h1.push(req_2.into_bytes());
                }
                PassPattern::RealDummy(t0) => {
                    let req = group.build_request(t0).map_err(|e| {
                        PirError::BackendState(format!("sib build_request: {:?}", e))
                    })?;
                    bytes_h0.push(req.into_bytes());
                    bytes_h1.push(group.build_synthetic_dummy());
                }
                PassPattern::DummyReal(t1) => {
                    bytes_h0.push(group.build_synthetic_dummy());
                    let req = group.build_request(t1).map_err(|e| {
                        PirError::BackendState(format!("sib build_request: {:?}", e))
                    })?;
                    bytes_h1.push(req.into_bytes());
                }
                PassPattern::DummyDummy => {
                    bytes_h0.push(group.build_synthetic_dummy());
                    bytes_h1.push(group.build_synthetic_dummy());
                }
            }
        }

        // Assemble BatchItem lists and encode both wire requests.
        let batch_items_h0: Vec<BatchItem> = bytes_h0
            .iter()
            .enumerate()
            .map(|(g_idx, b)| {
                Ok(BatchItem {
                    group_id: g_idx as u8,
                    indices: bytes_to_u32_vec(b)?,
                })
            })
            .collect::<PirResult<Vec<_>>>()?;
        let batch_items_h1: Vec<BatchItem> = bytes_h1
            .iter()
            .enumerate()
            .map(|(g_idx, b)| {
                Ok(BatchItem {
                    group_id: g_idx as u8,
                    indices: bytes_to_u32_vec(b)?,
                })
            })
            .collect::<PirResult<Vec<_>>>()?;

        // round_id encodes (table_type, level, pass_idx) so audit logs
        // can disambiguate the two passes.
        let round_id_h0 = (table_type as u16) * 1000 + (level as u16) * 10;
        let round_id_h1 = round_id_h0 + 1;
        let request_h0 = encode_batch_query(wire_level, round_id_h0, db_id, &batch_items_h0);
        let request_h1 = encode_batch_query(wire_level, round_id_h1, db_id, &batch_items_h1);
        let request_h0_bytes = request_h0.len() as u64;
        let request_h1_bytes = request_h1.len() as u64;
        let items_per_group_h0: Vec<u32> = batch_items_h0
            .iter()
            .map(|it| it.indices.len() as u32)
            .collect();
        let items_per_group_h1: Vec<u32> = batch_items_h1
            .iter()
            .map(|it| it.indices.len() as u32)
            .collect();

        // ── Pipelined send / recv ──
        let t_wire = Instant::now();
        self.query_conn.send(request_h0).await?;
        self.query_conn.send(request_h1).await?;
        let resp_h0_raw = self.query_conn.recv().await?;
        let resp_h1_raw = self.query_conn.recv().await?;
        let dt_wire = t_wire.elapsed();
        if std::env::var("HARMONY_BENCH").is_ok() {
            eprintln!(
                "[HARMONY_BENCH]   Merkle pipelined passes (table={}, level={}, n_passes=2): wire {:?} (req {}B+{}B, resp {}B+{}B)",
                table_type, level, dt_wire,
                request_h0_bytes, request_h1_bytes,
                resp_h0_raw.len(), resp_h1_raw.len(),
            );
        }
        // Buffer both passes' leakage rounds in pass order (h0 then h1);
        // `verify_merkle_items` drains the buffer in a fixed
        // INDEX-then-CHUNK order — see `HarmonySiblingQuerier.recorded`.
        let kind = match table_type {
            1 => RoundKind::ChunkMerkleSiblings { level: level as u8 },
            _ => RoundKind::IndexMerkleSiblings { level: level as u8 },
        };
        self.recorded.push(RoundProfile {
            kind,
            server_id: 0,
            db_id: Some(db_id),
            request_bytes: request_h0_bytes,
            response_bytes: resp_h0_raw.len() as u64,
            items: items_per_group_h0,
        });
        self.recorded.push(RoundProfile {
            kind,
            server_id: 0,
            db_id: Some(db_id),
            request_bytes: request_h1_bytes,
            response_bytes: resp_h1_raw.len() as u64,
            items: items_per_group_h1,
        });

        let raw_results_h0 = decode_batch_response_frame(
            &resp_h0_raw,
            wire_level,
            round_id_h0,
            table_k,
            "Harmony sibling h=0 response",
        )?;
        let raw_results_h1 = decode_batch_response_frame(
            &resp_h1_raw,
            wire_level,
            round_id_h1,
            table_k,
            "Harmony sibling h=1 response",
        )?;

        // ── Decode responses per-group via the matching API ──
        let mut out_h0: Vec<Option<Vec<u8>>> = vec![None; table_k];
        let mut out_h1: Vec<Option<Vec<u8>>> = vec![None; table_k];

        for (g_idx, pat) in patterns.iter().enumerate() {
            let g = g_idx as u8;
            let group = match table_type {
                0 => self.index_sib_groups.get_mut(&(level, g)),
                1 => self.chunk_sib_groups.get_mut(&(level, g)),
                _ => None,
            };
            let group = group.ok_or_else(|| {
                PirError::InvalidState(format!("sib group vanished mid-batch ({}, {})", level, g))
            })?;

            match *pat {
                PassPattern::RealReal(_, _) => {
                    let data_h0 = raw_results_h0.get(&g).ok_or_else(|| {
                        PirError::Protocol(format!(
                            "no pipelined sib h=0 response for group {} (table={}, level={})",
                            g, table_type, level
                        ))
                    })?;
                    let data_h1 = raw_results_h1.get(&g).ok_or_else(|| {
                        PirError::Protocol(format!(
                            "no pipelined sib h=1 response for group {} (table={}, level={})",
                            g, table_type, level
                        ))
                    })?;
                    let (row0, row1) =
                        group.process_response_pair(data_h0, data_h1).map_err(|e| {
                            PirError::BackendState(format!("sib process_response_pair: {:?}", e))
                        })?;
                    if row0.len() != BUCKET_MERKLE_SIB_ROW_SIZE
                        || row1.len() != BUCKET_MERKLE_SIB_ROW_SIZE
                    {
                        return Err(PirError::Protocol(format!(
                            "pipelined sib pair response has {}/{} bytes, expected {}",
                            row0.len(),
                            row1.len(),
                            BUCKET_MERKLE_SIB_ROW_SIZE
                        )));
                    }
                    out_h0[g_idx] = Some(row0);
                    out_h1[g_idx] = Some(row1);
                }
                PassPattern::RealDummy(_) => {
                    let data_h0 = raw_results_h0.get(&g).ok_or_else(|| {
                        PirError::Protocol(format!(
                            "no pipelined sib h=0 response for real-dummy group {} (table={}, level={})",
                            g, table_type, level
                        ))
                    })?;
                    let row = group.process_response(data_h0).map_err(|e| {
                        PirError::BackendState(format!(
                            "sib process_response (h=0 of real-dummy): {:?}",
                            e
                        ))
                    })?;
                    if row.len() != BUCKET_MERKLE_SIB_ROW_SIZE {
                        return Err(PirError::Protocol(format!(
                            "pipelined sib (real-dummy) response has {} bytes, expected {}",
                            row.len(),
                            BUCKET_MERKLE_SIB_ROW_SIZE
                        )));
                    }
                    out_h0[g_idx] = Some(row);
                    // out_h1 stays None.
                }
                PassPattern::DummyReal(_) => {
                    let data_h1 = raw_results_h1.get(&g).ok_or_else(|| {
                        PirError::Protocol(format!(
                            "no pipelined sib h=1 response for dummy-real group {} (table={}, level={})",
                            g, table_type, level
                        ))
                    })?;
                    let row = group.process_response(data_h1).map_err(|e| {
                        PirError::BackendState(format!(
                            "sib process_response (h=1 of dummy-real): {:?}",
                            e
                        ))
                    })?;
                    if row.len() != BUCKET_MERKLE_SIB_ROW_SIZE {
                        return Err(PirError::Protocol(format!(
                            "pipelined sib (dummy-real) response has {} bytes, expected {}",
                            row.len(),
                            BUCKET_MERKLE_SIB_ROW_SIZE
                        )));
                    }
                    out_h1[g_idx] = Some(row);
                    // out_h0 stays None.
                }
                PassPattern::DummyDummy => {
                    // Both slots stay None — caller treats this group as
                    // not participating at this level. The default
                    // implementation does the same thing.
                }
            }
        }

        Ok(vec![out_h0, out_h1])
    }

    async fn query_levels(
        &mut self,
        table_type: u8,
        levels: &[SiblingLevelPlan],
        db_id: u8,
    ) -> PirResult<Vec<Vec<Vec<Option<Vec<u8>>>>>> {
        if levels.iter().any(|level| level.passes.len() > 2) {
            let mut out = Vec::with_capacity(levels.len());
            for level in levels {
                out.push(
                    self.query_passes(
                        table_type,
                        level.level,
                        level.level_bins_per_table,
                        &level.passes,
                        db_id,
                    )
                    .await?,
                );
            }
            return Ok(out);
        }

        // State is disjoint across (level, group_id). Same-level collisions
        // still use HarmonyGroup's atomic pair API in prepare_cross_level.
        let mut prepared = Vec::with_capacity(levels.len());
        for level in levels {
            prepared.push(self.prepare_cross_level(
                table_type,
                level.level,
                &level.passes,
                db_id,
            )?);
        }
        for level in &mut prepared {
            if std::env::var("HARMONY_BENCH").is_ok() {
                let work_units: Vec<u64> = level
                    .items_per_group
                    .iter()
                    .map(|items| items.iter().map(|&count| u64::from(count)).sum())
                    .collect();
                eprintln!(
                    "[HARMONY_BENCH]   Merkle pipeline send (table={}, level={}): requests={:?} work_units={:?}",
                    level.table_type, level.level, level.request_bytes, work_units,
                );
            }
            for request in &mut level.requests {
                self.query_conn.send(std::mem::take(request)).await?;
            }
        }
        // One ordered recv stream: concurrent recv on a single WebSocket would
        // lose the protocol's implicit request/response correlation.
        let mut responses = Vec::with_capacity(prepared.len());
        for level in &prepared {
            let mut level_responses = Vec::with_capacity(level.requests.len());
            for _ in &level.requests {
                level_responses.push(self.query_conn.recv().await?);
            }
            if std::env::var("HARMONY_BENCH").is_ok() {
                let response_bytes: Vec<usize> = level_responses.iter().map(Vec::len).collect();
                eprintln!(
                    "[HARMONY_BENCH]   Merkle pipeline recv (table={}, level={}): responses={:?}",
                    level.table_type, level.level, response_bytes,
                );
            }
            responses.push(level_responses);
        }

        // Record all drained rounds before proof decoding, so malformed
        // evidence cannot truncate the observed leakage profile.
        for (level, level_responses) in prepared.iter().zip(&responses) {
            let kind = match level.table_type {
                1 => RoundKind::ChunkMerkleSiblings {
                    level: level.level as u8,
                },
                _ => RoundKind::IndexMerkleSiblings {
                    level: level.level as u8,
                },
            };
            for (pass, response) in level_responses.iter().enumerate() {
                self.recorded.push(RoundProfile {
                    kind,
                    server_id: 0,
                    db_id: Some(level.db_id),
                    request_bytes: level.request_bytes[pass],
                    response_bytes: response.len() as u64,
                    items: level.items_per_group[pass].clone(),
                });
            }
        }
        let mut out = Vec::with_capacity(prepared.len());
        for (level, level_responses) in prepared.iter().zip(&responses) {
            out.push(self.finish_cross_level(level, level_responses)?);
        }
        Ok(out)
    }
}
