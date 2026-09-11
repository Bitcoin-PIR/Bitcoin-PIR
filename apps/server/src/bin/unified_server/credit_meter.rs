//! Gas metering (docs/CREDITS.md): the gas table this server derives from
//! the databases it loaded, the classifier that reduces a request frame to
//! a `MeteredOp`, the hourly per-opcode report, and the process-CPU clock
//! behind it.
//!
//! Nothing here charges anyone yet. Without an issuer the table is
//! informational (`GET_INFO_JSON` "gas") and the hourly line is the
//! observability that checks the calibration against production; charging
//! a per-connection balance arrives with the issuer client.

use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures_util::Sink;
use pir_credit::gas::{
    dpf_sibling_round, CuckooGeometry, DatabaseGeometry, GasTable, MeteredOp, OnionGeometry,
    OramGeometry, SubTableGeometry, TableKind, GAS_UNIT,
};
use pir_credit::{Calibration, GasParams, MeterSample, MeterWindow};
use runtime::onionpir::{
    OnionPirBatchQuery, RegisterKeysMsg, REQ_ONIONPIR_CHUNK_QUERY, REQ_ONIONPIR_INDEX_QUERY,
    REQ_ONIONPIR_MERKLE_DATA_SIBLING, REQ_ONIONPIR_MERKLE_DATA_TREE_TOP,
    REQ_ONIONPIR_MERKLE_INDEX_SIBLING, REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP, REQ_REGISTER_KEYS,
};
use runtime::protocol::*;
use runtime::table::{MappedDatabase, MappedSubTable, ServerState};
use tokio_tungstenite::tungstenite::Message;

use crate::onion::OnionPirInfo;

/// How often the aggregate report is printed.
pub(crate) const METER_REPORT_INTERVAL: Duration = Duration::from_secs(3600);

fn sub_table_geometry(table: &MappedSubTable) -> SubTableGeometry {
    let groups = table.params.k as u64;
    SubTableGeometry {
        bins_per_group: table.bins_per_table as u64,
        groups,
        bytes: (table.table_byte_size as u64).saturating_mul(groups),
    }
}

/// The cuckoo tables DPF rounds scan and HarmonyPIR hint sets cover.
pub(crate) fn cuckoo_geometry(db: &MappedDatabase) -> CuckooGeometry {
    CuckooGeometry {
        index: sub_table_geometry(&db.index),
        chunk: sub_table_geometry(&db.chunk),
        index_siblings: db
            .bucket_merkle_index_siblings
            .iter()
            .map(sub_table_geometry)
            .collect(),
        chunk_siblings: db
            .bucket_merkle_chunk_siblings
            .iter()
            .map(sub_table_geometry)
            .collect(),
    }
}

/// Geometry of every loaded database: cuckoo tables from the server state,
/// OnionPIR NTT sizes from the loaded OnionPIR info, ORAM slots per lookup
/// from the direct ORAM tables (`db_id → padded slots`).
pub(crate) fn database_geometries(
    state: &ServerState,
    onionpir_infos: &[Option<OnionPirInfo>],
    oram_slots: &BTreeMap<u8, u64>,
) -> BTreeMap<u8, DatabaseGeometry> {
    let mut out = BTreeMap::new();
    for (index, db) in state.databases.iter().enumerate() {
        let db_id = index as u8;
        let onion = onionpir_infos
            .get(index)
            .and_then(|info| info.as_ref())
            .map(|info| OnionGeometry {
                index_ntt_bytes: info.index_ntt_bytes,
                chunk_ntt_bytes: info.chunk_ntt_bytes,
            });
        let oram = oram_slots.get(&db_id).map(|slots| OramGeometry {
            slots_per_lookup: *slots,
        });
        out.insert(
            db_id,
            DatabaseGeometry {
                cuckoo: Some(cuckoo_geometry(db)),
                onion,
                oram,
            },
        );
    }
    out
}

/// Reduce a request frame (`payload[0]` is the variant) to what its price
/// depends on, plus the database it addresses. `None` for unmetered
/// variants and for frames the decoder rejects (dispatch answers those
/// with the decode error).
pub(crate) fn metered_op_for_frame(variant: u8, payload: &[u8]) -> Option<(MeteredOp, u8)> {
    match variant {
        REQ_INDEX_BATCH
        | REQ_CHUNK_BATCH
        | REQ_BUCKET_MERKLE_SIB_BATCH
        | REQ_HARMONY_HINTS
        | REQ_HARMONY_HINTS_V2
        | REQ_HARMONY_HINTS_V2_HALF
        | REQ_HARMONY_QUERY
        | REQ_HARMONY_BATCH_QUERY
        | REQ_ORAM_LOOKUP => match Request::decode(payload).ok()? {
            Request::IndexBatch(q) => Some((MeteredOp::DpfIndexRound, q.db_id)),
            Request::ChunkBatch(q) => Some((MeteredOp::DpfChunkRound, q.db_id)),
            Request::BucketMerkleSibBatch(q) => {
                let (table, level) = dpf_sibling_round(q.round_id)?;
                Some((MeteredOp::DpfSiblingPass { table, level }, q.db_id))
            }
            Request::HarmonyHints(h) => {
                Some((MeteredOp::HarmonyHintSet { level: h.level }, h.db_id))
            }
            Request::HarmonyHintsV2(h) => Some((MeteredOp::HarmonyPoolEntry, h.db_id)),
            Request::HarmonyHintsV2Half(h) => Some((MeteredOp::HarmonyContinuation, h.db_id)),
            Request::HarmonyQuery(q) => Some((
                MeteredOp::HarmonyQuery {
                    level: q.level,
                    sub_queries: 1,
                },
                q.db_id,
            )),
            Request::HarmonyBatchQuery(q) => Some((
                MeteredOp::HarmonyQuery {
                    level: q.level,
                    sub_queries: u32::from(q.sub_queries_per_group),
                },
                q.db_id,
            )),
            Request::OramLookup(q) => Some((MeteredOp::OramLookup, q.db_id)),
            _ => None,
        },
        // Tree-top blobs carry an optional db_id byte after the variant.
        REQ_BUCKET_MERKLE_TREE_TOPS => {
            Some((MeteredOp::TreeTops, payload.get(1).copied().unwrap_or(0)))
        }
        REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP | REQ_ONIONPIR_MERKLE_DATA_TREE_TOP => Some((
            MeteredOp::OnionTreeTops,
            payload.get(1).copied().unwrap_or(0),
        )),
        REQ_REGISTER_KEYS => {
            let msg = RegisterKeysMsg::decode(payload.get(1..)?).ok()?;
            Some((MeteredOp::OnionRegisterKeys, msg.db_id))
        }
        REQ_ONIONPIR_INDEX_QUERY => {
            let q = OnionPirBatchQuery::decode(payload.get(1..)?).ok()?;
            Some((MeteredOp::OnionIndexQuery, q.db_id))
        }
        REQ_ONIONPIR_CHUNK_QUERY => {
            let q = OnionPirBatchQuery::decode(payload.get(1..)?).ok()?;
            Some((MeteredOp::OnionChunkQuery, q.db_id))
        }
        REQ_ONIONPIR_MERKLE_INDEX_SIBLING | REQ_ONIONPIR_MERKLE_DATA_SIBLING => {
            let q = OnionPirBatchQuery::decode(payload.get(1..)?).ok()?;
            let table = if variant == REQ_ONIONPIR_MERKLE_INDEX_SIBLING {
                TableKind::Index
            } else {
                TableKind::Chunk
            };
            Some((MeteredOp::OnionSiblingQuery { table }, q.db_id))
        }
        _ => None,
    }
}

/// Process CPU time (all threads) from the OS clock; zero where the clock
/// is unavailable so the meter degrades to wall time only.
pub(crate) fn process_cpu_time() -> Duration {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `clock_gettime` only writes the provided timespec.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut ts) };
    if rc != 0 {
        return Duration::ZERO;
    }
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

/// A request in flight: what [`CreditMeterV1::begin`] captured.
pub(crate) struct InFlightRequest {
    started: Instant,
    cpu_at_start: Duration,
    in_flight: usize,
}

/// The server's gas table, parameters, and hourly meter.
pub(crate) struct CreditMeterV1 {
    params: GasParams,
    table: GasTable,
    window: Mutex<MeterWindow>,
    in_flight: AtomicUsize,
}

impl CreditMeterV1 {
    pub(crate) fn new(params: GasParams, databases: BTreeMap<u8, DatabaseGeometry>) -> Self {
        Self {
            params,
            table: GasTable::new(Calibration::PIR1_2026_09, databases),
            window: Mutex::new(MeterWindow::new(METER_REPORT_INTERVAL, Instant::now())),
            in_flight: AtomicUsize::new(0),
        }
    }

    pub(crate) fn from_loaded(
        params: GasParams,
        state: &ServerState,
        onionpir_infos: &[Option<OnionPirInfo>],
        oram_slots: &BTreeMap<u8, u64>,
    ) -> Self {
        Self::new(
            params,
            database_geometries(state, onionpir_infos, oram_slots),
        )
    }

    #[cfg(test)]
    pub(crate) fn table(&self) -> &GasTable {
        &self.table
    }

    /// Gas a metered frame must cover before dispatch (work plus base fee);
    /// `None` for unmetered frames and backends this database does not
    /// serve, which the gate lets through.
    pub(crate) fn admission_gas(&self, op: Option<(MeteredOp, u8)>) -> Option<u64> {
        let (op, db_id) = op?;
        let work = self.table.work_gas(db_id, op)?;
        Some(self.params.frame_gas(work))
    }

    /// Gas `response_bytes` of egress cost under the current parameters.
    pub(crate) fn egress_gas(&self, response_bytes: u64) -> u64 {
        self.params.egress_gas(response_bytes)
    }

    /// Gas a frame is priced at: work plus base fee plus egress, or 0 for
    /// unmetered frames and backends this database does not serve.
    pub(crate) fn frame_gas(&self, op: Option<(MeteredOp, u8)>, egress_bytes: u64) -> u64 {
        let Some((op, db_id)) = op else { return 0 };
        let Some(work) = self.table.work_gas(db_id, op) else {
            return 0;
        };
        self.params
            .frame_gas(work)
            .saturating_add(self.params.egress_gas(egress_bytes))
    }

    pub(crate) fn begin(&self) -> InFlightRequest {
        let in_flight = self.in_flight.fetch_add(1, Ordering::Relaxed) + 1;
        InFlightRequest {
            started: Instant::now(),
            cpu_at_start: process_cpu_time(),
            in_flight,
        }
    }

    pub(crate) fn finish(
        &self,
        request: InFlightRequest,
        variant: u8,
        op: Option<(MeteredOp, u8)>,
        egress_bytes: u64,
    ) {
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
        let sample = MeterSample {
            variant,
            db_id: op.map(|(_, db_id)| db_id).unwrap_or(0),
            gas: self.frame_gas(op, egress_bytes),
            cpu: process_cpu_time().saturating_sub(request.cpu_at_start),
            wall: request.started.elapsed(),
            egress_bytes,
            in_flight: request.in_flight,
        };
        self.window.lock().unwrap().record(sample);
    }

    pub(crate) fn due_lines(&self, now: Instant) -> Option<Vec<String>> {
        self.window.lock().unwrap().due(now)
    }

    fn per_database_entries(&self, db_id: u8) -> Vec<(&'static str, String)> {
        let gas = |op| self.table.work_gas(db_id, op);
        let list = |values: Vec<Option<u64>>| -> Option<String> {
            let values: Option<Vec<u64>> = values.into_iter().collect();
            values.map(|v| {
                format!(
                    "[{}]",
                    v.iter()
                        .map(|g| g.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                )
            })
        };
        let cuckoo = self.table.geometry(db_id).and_then(|g| g.cuckoo.as_ref());
        let index_levels = cuckoo.map(|c| c.index_siblings.len()).unwrap_or(0);
        let chunk_levels = cuckoo.map(|c| c.chunk_siblings.len()).unwrap_or(0);
        let mut entries: Vec<(&'static str, Option<String>)> = vec![
            (
                "dpf_index_round",
                gas(MeteredOp::DpfIndexRound).map(|g| g.to_string()),
            ),
            (
                "dpf_chunk_round",
                gas(MeteredOp::DpfChunkRound).map(|g| g.to_string()),
            ),
            (
                "dpf_index_sibling_pass",
                list(
                    (0..index_levels)
                        .map(|level| {
                            gas(MeteredOp::DpfSiblingPass {
                                table: TableKind::Index,
                                level: level as u8,
                            })
                        })
                        .collect(),
                ),
            ),
            (
                "dpf_chunk_sibling_pass",
                list(
                    (0..chunk_levels)
                        .map(|level| {
                            gas(MeteredOp::DpfSiblingPass {
                                table: TableKind::Chunk,
                                level: level as u8,
                            })
                        })
                        .collect(),
                ),
            ),
            ("tree_tops", gas(MeteredOp::TreeTops).map(|g| g.to_string())),
            (
                "onion_register_keys",
                gas(MeteredOp::OnionRegisterKeys).map(|g| g.to_string()),
            ),
            (
                "onion_index_query",
                gas(MeteredOp::OnionIndexQuery).map(|g| g.to_string()),
            ),
            (
                "onion_chunk_query",
                gas(MeteredOp::OnionChunkQuery).map(|g| g.to_string()),
            ),
            (
                "onion_sibling_query",
                gas(MeteredOp::OnionSiblingQuery {
                    table: TableKind::Index,
                })
                .map(|g| g.to_string()),
            ),
            (
                "harmony_pool_entry",
                gas(MeteredOp::HarmonyPoolEntry).map(|g| g.to_string()),
            ),
            (
                "harmony_index_sibling_set",
                list(
                    (0..index_levels)
                        .map(|level| {
                            gas(MeteredOp::HarmonyHintSet {
                                level: 10 + level as u8,
                            })
                        })
                        .collect(),
                ),
            ),
            (
                "harmony_chunk_sibling_set",
                list(
                    (0..chunk_levels)
                        .map(|level| {
                            gas(MeteredOp::HarmonyHintSet {
                                level: 20 + level as u8,
                            })
                        })
                        .collect(),
                ),
            ),
            (
                "harmony_query_index",
                gas(MeteredOp::HarmonyQuery {
                    level: 0,
                    sub_queries: 1,
                })
                .map(|g| g.to_string()),
            ),
            (
                "harmony_query_chunk",
                gas(MeteredOp::HarmonyQuery {
                    level: 1,
                    sub_queries: 1,
                })
                .map(|g| g.to_string()),
            ),
            (
                "oram_lookup",
                gas(MeteredOp::OramLookup).map(|g| g.to_string()),
            ),
        ];
        entries
            .drain(..)
            .filter_map(|(name, value)| value.map(|v| (name, v)))
            .collect()
    }

    /// Startup log lines: the parameters, then one line per database.
    pub(crate) fn startup_lines(&self) -> Vec<String> {
        let p = &self.params;
        let mut lines = vec![format!(
            "Gas meter: unit={GAS_UNIT} credit_sat={} gas_per_credit={} base_gas_per_frame={} egress_gas_per_mb={} (report every {}s)",
            p.credit_sat,
            p.gas_per_credit,
            p.base_gas_per_frame,
            p.egress_gas_per_mb,
            METER_REPORT_INTERVAL.as_secs()
        )];
        for db_id in self.table.databases().keys() {
            let entries = self
                .per_database_entries(*db_id)
                .into_iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join(" ");
            lines.push(format!("[gas db={db_id}] {entries}"));
        }
        lines
    }

    /// `,"gas":{...}` for `GET_INFO_JSON`: unit, parameters, and the work gas
    /// of every metered request kind per database (all public geometry).
    pub(crate) fn info_json_fragment(&self) -> String {
        let p = &self.params;
        let mut json = format!(
            r#","gas":{{"unit":"{GAS_UNIT}","params":{{"credit_sat":{},"gas_per_credit":{},"base_gas_per_frame":{},"egress_gas_per_mb":{}}},"databases":{{"#,
            p.credit_sat, p.gas_per_credit, p.base_gas_per_frame, p.egress_gas_per_mb
        );
        for (i, db_id) in self.table.databases().keys().enumerate() {
            if i > 0 {
                json.push(',');
            }
            json.push_str(&format!(r#""{db_id}":{{"#));
            for (j, (name, value)) in self.per_database_entries(*db_id).into_iter().enumerate() {
                if j > 0 {
                    json.push(',');
                }
                json.push_str(&format!(r#""{name}":{value}"#));
            }
            json.push('}');
        }
        json.push_str("}}");
        json
    }
}

/// Counts the bytes of every WebSocket message written through it, so the
/// meter can attribute egress to the request being served.
pub(crate) struct CountingSink<S> {
    inner: S,
    bytes: Arc<AtomicU64>,
}

impl<S> CountingSink<S> {
    pub(crate) fn new(inner: S) -> Self {
        Self {
            inner,
            bytes: Arc::new(AtomicU64::new(0)),
        }
    }

    pub(crate) fn bytes_sent(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }
}

impl<S> Sink<Message> for CountingSink<S>
where
    S: Sink<Message> + Unpin,
{
    type Error = S::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        self.bytes.fetch_add(item.len() as u64, Ordering::Relaxed);
        Pin::new(&mut self.inner).start_send(item)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sub(bins: u64, groups: u64, bin_bytes: u64) -> SubTableGeometry {
        SubTableGeometry {
            bins_per_group: bins,
            groups,
            bytes: bins * groups * bin_bytes,
        }
    }

    fn checkpoint_948454() -> DatabaseGeometry {
        DatabaseGeometry {
            cuckoo: Some(CuckooGeometry {
                index: sub(567_558, 75, 52),
                chunk: sub(1_066_928, 80, 132),
                index_siblings: vec![
                    sub(70_945, 75, 256),
                    sub(8_869, 75, 256),
                    sub(1_109, 75, 256),
                ],
                chunk_siblings: vec![
                    sub(133_366, 80, 256),
                    sub(16_671, 80, 256),
                    sub(2_084, 80, 256),
                ],
            }),
            onion: Some(OnionGeometry {
                index_ntt_bytes: 12_580_000_000,
                chunk_ntt_bytes: 15_510_000_000,
            }),
            oram: None,
        }
    }

    fn meter() -> CreditMeterV1 {
        let mut databases = BTreeMap::new();
        databases.insert(0, checkpoint_948454());
        databases.insert(
            1,
            DatabaseGeometry {
                cuckoo: Some(CuckooGeometry {
                    index: sub(10_000, 75, 52),
                    chunk: sub(20_000, 80, 132),
                    index_siblings: vec![sub(1_250, 75, 256)],
                    chunk_siblings: vec![sub(2_500, 80, 256)],
                }),
                onion: None,
                oram: Some(OramGeometry {
                    slots_per_lookup: 256,
                }),
            },
        );
        CreditMeterV1::new(GasParams::PRODUCTION_2026_09, databases)
    }

    fn batch(level: u8, round_id: u16, db_id: u8) -> BatchQuery {
        // The decoder parses every DPF key, so the keys must be real ones.
        let key = libdpf::Dpf::with_default_key().gen(1, 8).0.to_bytes();
        BatchQuery {
            level,
            round_id,
            db_id,
            keys: vec![vec![key.clone(), key]; 3],
        }
    }

    #[test]
    fn classifies_dpf_frames_by_opcode_round_and_database() {
        let index = Request::IndexBatch(batch(0, 0, 1)).encode();
        assert_eq!(
            metered_op_for_frame(REQ_INDEX_BATCH, &index[4..]),
            Some((MeteredOp::DpfIndexRound, 1))
        );
        let chunk = Request::ChunkBatch(batch(1, 3, 0)).encode();
        assert_eq!(
            metered_op_for_frame(REQ_CHUNK_BATCH, &chunk[4..]),
            Some((MeteredOp::DpfChunkRound, 0))
        );
        let sib = Request::BucketMerkleSibBatch(batch(0, 102, 0)).encode();
        assert_eq!(
            metered_op_for_frame(REQ_BUCKET_MERKLE_SIB_BATCH, &sib[4..]),
            Some((
                MeteredOp::DpfSiblingPass {
                    table: TableKind::Chunk,
                    level: 2
                },
                0
            ))
        );
        assert_eq!(
            metered_op_for_frame(
                REQ_BUCKET_MERKLE_TREE_TOPS,
                &[REQ_BUCKET_MERKLE_TREE_TOPS, 1]
            ),
            Some((MeteredOp::TreeTops, 1))
        );
        assert_eq!(
            metered_op_for_frame(REQ_BUCKET_MERKLE_TREE_TOPS, &[REQ_BUCKET_MERKLE_TREE_TOPS]),
            Some((MeteredOp::TreeTops, 0))
        );
        // Undecodable frames are unmetered here; dispatch reports the error.
        assert_eq!(
            metered_op_for_frame(REQ_INDEX_BATCH, &[REQ_INDEX_BATCH, 0]),
            None
        );
        assert_eq!(metered_op_for_frame(REQ_PING, &[REQ_PING]), None);
        assert_eq!(
            metered_op_for_frame(REQ_SESSION_GRANT_PRESENT, &[REQ_SESSION_GRANT_PRESENT]),
            None
        );
    }

    #[test]
    fn classifies_harmony_oram_and_onion_frames() {
        let hints = Request::HarmonyHints(HarmonyHintRequest {
            prp_key: [1u8; 16],
            prp_backend: 1,
            level: 21,
            group_ids: vec![0, 1],
            db_id: 0,
        })
        .encode();
        assert_eq!(
            metered_op_for_frame(REQ_HARMONY_HINTS, &hints[4..]),
            Some((MeteredOp::HarmonyHintSet { level: 21 }, 0))
        );
        let query = Request::HarmonyQuery(HarmonyQuery {
            level: 1,
            group_id: 4,
            round_id: 0,
            indices: vec![1, 2, 3],
            db_id: 1,
        })
        .encode();
        assert_eq!(
            metered_op_for_frame(REQ_HARMONY_QUERY, &query[4..]),
            Some((
                MeteredOp::HarmonyQuery {
                    level: 1,
                    sub_queries: 1
                },
                1
            ))
        );
        let oram = Request::OramLookup(OramLookupRequest {
            db_id: 1,
            script_hashes: vec![[0u8; 20]],
            slot_present: vec![true],
        })
        .encode();
        assert_eq!(
            metered_op_for_frame(REQ_ORAM_LOOKUP, &oram[4..]),
            Some((MeteredOp::OramLookup, 1))
        );
        let keys = RegisterKeysMsg {
            galois_keys: vec![1, 2, 3],
            gsw_keys: vec![4],
            db_id: 1,
        }
        .encode();
        assert_eq!(
            metered_op_for_frame(REQ_REGISTER_KEYS, &keys[4..]),
            Some((MeteredOp::OnionRegisterKeys, 1))
        );
        let onion_query = OnionPirBatchQuery {
            round_id: 0,
            queries: vec![vec![9u8; 4]],
            db_id: 0,
        }
        .encode(REQ_ONIONPIR_CHUNK_QUERY);
        assert_eq!(
            metered_op_for_frame(REQ_ONIONPIR_CHUNK_QUERY, &onion_query[4..]),
            Some((MeteredOp::OnionChunkQuery, 0))
        );
        let sibling = OnionPirBatchQuery {
            round_id: 0,
            queries: vec![vec![9u8; 4]],
            db_id: 0,
        }
        .encode(REQ_ONIONPIR_MERKLE_DATA_SIBLING);
        assert_eq!(
            metered_op_for_frame(REQ_ONIONPIR_MERKLE_DATA_SIBLING, &sibling[4..]),
            Some((
                MeteredOp::OnionSiblingQuery {
                    table: TableKind::Chunk
                },
                0
            ))
        );
        assert_eq!(
            metered_op_for_frame(
                REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP,
                &[REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP]
            ),
            Some((MeteredOp::OnionTreeTops, 0))
        );
    }

    #[test]
    fn frame_gas_adds_base_fee_and_egress_and_ignores_unserved_backends() {
        let m = meter();
        let index = m.frame_gas(Some((MeteredOp::DpfIndexRound, 0)), 8_109);
        let work = m.table().work_gas(0, MeteredOp::DpfIndexRound).unwrap();
        assert_eq!(index, work + 20 + 8);
        assert_eq!(m.frame_gas(None, 1_000_000), 0);
        assert_eq!(m.frame_gas(Some((MeteredOp::OnionIndexQuery, 1)), 0), 0);
        assert_eq!(
            m.frame_gas(Some((MeteredOp::OramLookup, 1)), 0),
            256 * 2 + 20
        );
        assert_eq!(m.frame_gas(Some((MeteredOp::OramLookup, 0)), 0), 0);
    }

    #[test]
    fn startup_lines_and_info_json_list_only_served_backends() {
        let m = meter();
        let lines = m.startup_lines();
        assert_eq!(lines.len(), 3);
        assert!(
            lines[0].starts_with("Gas meter: unit=cpu_ms_pir1 credit_sat=10 gas_per_credit=72000")
        );
        assert!(lines[1].starts_with("[gas db=0] dpf_index_round="));
        assert!(lines[1].contains("onion_index_query="));
        assert!(!lines[1].contains("oram_lookup="));
        assert!(lines[2].contains("oram_lookup=512"));
        assert!(!lines[2].contains("onion_"));
        let json = m.info_json_fragment();
        assert!(json.starts_with(r#","gas":{"unit":"cpu_ms_pir1","params":{"credit_sat":10,"gas_per_credit":72000,"base_gas_per_frame":20,"egress_gas_per_mb":1000},"databases":{"0":{"dpf_index_round":"#));
        assert!(json.contains(r#""dpf_index_sibling_pass":["#));
        assert!(json.contains(r#""1":{"#));
        assert!(json.ends_with("}}"));
        // The fragment must splice into an object: balanced braces overall.
        let opens = json.matches('{').count();
        let closes = json.matches('}').count();
        assert_eq!(opens, closes);
    }

    #[test]
    fn meter_records_frames_and_reports_hourly() {
        let m = meter();
        let request = m.begin();
        assert_eq!(request.in_flight, 1);
        m.finish(
            request,
            REQ_INDEX_BATCH,
            Some((MeteredOp::DpfIndexRound, 0)),
            8_109,
        );
        assert_eq!(m.in_flight.load(Ordering::Relaxed), 0);
        assert!(m.due_lines(Instant::now()).is_none());
        let lines = m.due_lines(Instant::now() + METER_REPORT_INTERVAL).unwrap();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("[meter op=0x11 db=0] last 3600s: n=1 gas_mean="));
        assert!(lines[1].starts_with("[meter] last 3600s: frames=1 gas_total="));
    }

    /// The SDK's client-side classifier must price every frame the way this
    /// server does: encode each request kind with the real encoders and
    /// compare both classifiers (docs/CREDITS.md "Metering on the server").
    #[test]
    fn client_classifier_agrees_with_the_server_for_every_metered_request() {
        use pir_sdk_client::credit_frames::classify_frame;
        let key = libdpf::Dpf::with_default_key().gen(1, 8).0.to_bytes();
        let mut frames: Vec<Vec<u8>> = vec![
            Request::IndexBatch(BatchQuery {
                level: 0,
                round_id: 0,
                db_id: 0,
                keys: vec![vec![key.clone(), key.clone()]; 2],
            })
            .encode(),
            Request::ChunkBatch(BatchQuery {
                level: 1,
                round_id: 7,
                db_id: 2,
                keys: vec![vec![key.clone(), key.clone(), key.clone()]; 3],
            })
            .encode(),
            Request::BucketMerkleSibBatch(BatchQuery {
                level: 0,
                round_id: 101,
                db_id: 1,
                keys: vec![vec![key.clone()]; 4],
            })
            .encode(),
            Request::HarmonyHints(HarmonyHintRequest {
                prp_key: [3u8; 16],
                prp_backend: 1,
                level: 22,
                group_ids: vec![0, 5, 9],
                db_id: 0,
            })
            .encode(),
            Request::HarmonyHintsV2(HarmonyHintRequestV2 { db_id: 1 }).encode(),
            Request::HarmonyHintsV2Half(HarmonyHintRequestV2Half {
                session_token: [9u8; 16],
                side: 1,
                db_id: 0,
            })
            .encode(),
            Request::HarmonyQuery(HarmonyQuery {
                level: 0,
                group_id: 3,
                round_id: 2,
                indices: vec![1, 2, 3, 4],
                db_id: 1,
            })
            .encode(),
            Request::HarmonyBatchQuery(HarmonyBatchQuery {
                level: 11,
                round_id: 0,
                sub_queries_per_group: 2,
                items: vec![
                    HarmonyBatchItem {
                        group_id: 0,
                        sub_queries: vec![vec![1, 2], vec![3]],
                    },
                    HarmonyBatchItem {
                        group_id: 4,
                        sub_queries: vec![vec![], vec![7, 8, 9]],
                    },
                ],
                db_id: 0,
            })
            .encode(),
            Request::OramLookup(OramLookupRequest {
                db_id: 1,
                script_hashes: vec![[1u8; 20], [2u8; 20]],
                slot_present: vec![true, false],
            })
            .encode(),
            RegisterKeysMsg {
                galois_keys: vec![1, 2, 3],
                gsw_keys: vec![4, 5],
                db_id: 1,
            }
            .encode(),
        ];
        for variant in [
            REQ_ONIONPIR_INDEX_QUERY,
            REQ_ONIONPIR_CHUNK_QUERY,
            REQ_ONIONPIR_MERKLE_INDEX_SIBLING,
            REQ_ONIONPIR_MERKLE_DATA_SIBLING,
        ] {
            frames.push(
                OnionPirBatchQuery {
                    round_id: 1,
                    queries: vec![vec![8u8; 3], vec![]],
                    db_id: 2,
                }
                .encode(variant),
            );
        }
        // Tree-top requests carry an optional db_id byte after the variant.
        for variant in [
            REQ_BUCKET_MERKLE_TREE_TOPS,
            REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP,
            REQ_ONIONPIR_MERKLE_DATA_TREE_TOP,
        ] {
            frames.push(vec![1, 0, 0, 0, variant]);
            frames.push(vec![2, 0, 0, 0, variant, 1]);
        }
        // Unmetered requests must be unmetered on both sides.
        frames.push(Request::Ping.encode());
        frames.push(Request::GetInfo.encode());
        frames.push(Request::HarmonyGetInfo.encode());
        frames.push(Request::Announce.encode());
        frames.push(
            Request::CreditPresent {
                kind: 2,
                payload: vec![1, 2, 3],
            }
            .encode(),
        );
        assert!(frames.len() >= 20);
        for frame in &frames {
            let variant = frame[4];
            let server = metered_op_for_frame(variant, &frame[4..]);
            let client = classify_frame(frame);
            assert_eq!(client, server, "variant 0x{variant:02x}");
        }
        assert_eq!(
            frames
                .iter()
                .filter(|frame| classify_frame(frame).is_some())
                .count(),
            20
        );
    }

    #[test]
    fn process_cpu_clock_is_monotonic() {
        let a = process_cpu_time();
        let mut x = 0u64;
        for i in 0..200_000u64 {
            x = x.wrapping_mul(31).wrapping_add(i);
        }
        assert!(x != 1);
        let b = process_cpu_time();
        assert!(b >= a);
    }
}
