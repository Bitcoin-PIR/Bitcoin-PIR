//! The gas model: reference-CPU work per metered request, derived from
//! public database geometry and calibrated against measurements.
//!
//! One gas is one CPU-millisecond of work on the reference machine (pir1:
//! Intel i7-8700, six cores / twelve threads, CPU time summed over all
//! threads). Gas is *work*, not money: a provider on faster or slower
//! hardware changes only its price per gas, never the table. Every formula
//! takes public geometry (bins, groups, table bytes, NTT bytes, ORAM slots)
//! so a database of any size prices itself; the constants in
//! [`Calibration`] were fitted to measurements of the production databases
//! on 2026-09-09 (docs/CREDITS.md "Measurements").

use std::collections::BTreeMap;

/// Name of the gas unit as published in server info.
pub const GAS_UNIT: &str = "cpu_ms_pir1";

/// Per-primitive costs on the reference machine.
#[derive(Clone, Debug, PartialEq)]
pub struct Calibration {
    /// DPF evaluation: nanoseconds per (group, bin) pair evaluated.
    pub dpf_ns_per_bin: f64,
    /// DPF evaluation: milliseconds per 10^9 bytes of table scanned.
    pub dpf_ms_per_gb: f64,
    /// OnionPIR INDEX query: milliseconds per 10^9 bytes of NTT-form INDEX data.
    pub onion_index_ms_per_gb: f64,
    /// OnionPIR CHUNK query: milliseconds per 10^9 bytes of NTT-form CHUNK data.
    pub onion_chunk_ms_per_gb: f64,
    /// OnionPIR per-group Merkle sibling query: milliseconds per query
    /// (fixed-cost dominated; the sibling stores are small).
    pub onion_sibling_query_ms: f64,
    /// OnionPIR key registration: milliseconds per registration.
    pub onion_register_keys_ms: f64,
    /// HarmonyPIR hint-pool entry (INDEX + CHUNK): microseconds per cell.
    pub harmony_pool_us_per_cell: f64,
    /// HarmonyPIR on-demand sibling-level hint set: microseconds per cell.
    pub harmony_sibling_us_per_cell: f64,
    /// HarmonyPIR query: nanoseconds per random bin read.
    pub harmony_query_ns_per_read: f64,
    /// Direct ORAM lookup: milliseconds per request slot (provisional
    /// analytical figure; pir2 cannot be sampled from outside).
    pub oram_ms_per_slot: f64,
    /// Serving the per-bucket Merkle tree-top blob: milliseconds.
    pub tree_tops_ms: f64,
}

impl Calibration {
    /// Fitted on pir1 on 2026-09-09 against checkpoint 948454.
    pub const PIR1_2026_09: Calibration = Calibration {
        dpf_ns_per_bin: 18.9,
        dpf_ms_per_gb: 261.0,
        onion_index_ms_per_gb: 15_700.0,
        onion_chunk_ms_per_gb: 26_000.0,
        onion_sibling_query_ms: 21_000.0,
        onion_register_keys_ms: 200.0,
        harmony_pool_us_per_cell: 1.016,
        harmony_sibling_us_per_cell: 0.71,
        harmony_query_ns_per_read: 100.0,
        oram_ms_per_slot: 2.0,
        tree_tops_ms: 5.0,
    };
}

/// One PBC cuckoo sub-table family: `groups` groups of `bins_per_group`
/// bins, `bytes` bytes in total (what one full DPF round scans).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SubTableGeometry {
    pub bins_per_group: u64,
    pub groups: u64,
    pub bytes: u64,
}

impl SubTableGeometry {
    /// (group, bin) pairs one DPF round evaluates and one hint set covers.
    pub fn cells(&self) -> u64 {
        self.bins_per_group.saturating_mul(self.groups)
    }
}

/// The cuckoo tables DPF and HarmonyPIR share: INDEX, CHUNK, and the
/// per-bucket Merkle sibling tables per level.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CuckooGeometry {
    pub index: SubTableGeometry,
    pub chunk: SubTableGeometry,
    pub index_siblings: Vec<SubTableGeometry>,
    pub chunk_siblings: Vec<SubTableGeometry>,
}

/// OnionPIR NTT stores.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OnionGeometry {
    pub index_ntt_bytes: u64,
    pub chunk_ntt_bytes: u64,
}

/// Direct ORAM request shape.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OramGeometry {
    /// Script-hash slots one lookup frame carries after padding.
    pub slots_per_lookup: u64,
}

/// Everything a server knows about one database that prices its requests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DatabaseGeometry {
    pub cuckoo: Option<CuckooGeometry>,
    pub onion: Option<OnionGeometry>,
    pub oram: Option<OramGeometry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableKind {
    Index,
    Chunk,
}

/// A metered request, reduced to what its price depends on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeteredOp {
    /// `REQ_INDEX_BATCH`: one DPF round over the INDEX tables.
    DpfIndexRound,
    /// `REQ_CHUNK_BATCH`: one DPF round over the CHUNK tables.
    DpfChunkRound,
    /// `REQ_BUCKET_MERKLE_SIB_BATCH`: one DPF pass over one sibling level.
    DpfSiblingPass { table: TableKind, level: u8 },
    /// `REQ_BUCKET_MERKLE_TREE_TOPS`.
    TreeTops,
    /// `REQ_REGISTER_KEYS` (OnionPIR).
    OnionRegisterKeys,
    /// `REQ_ONIONPIR_INDEX_QUERY`.
    OnionIndexQuery,
    /// `REQ_ONIONPIR_CHUNK_QUERY`.
    OnionChunkQuery,
    /// `REQ_ONIONPIR_MERKLE_{INDEX,DATA}_SIBLING`.
    OnionSiblingQuery { table: TableKind },
    /// `REQ_ONIONPIR_MERKLE_{INDEX,DATA}_TREE_TOP`.
    OnionTreeTops,
    /// `REQ_HARMONY_HINTS` at a wire level (see [`harmony_level`]).
    HarmonyHintSet { level: u8 },
    /// `REQ_HARMONY_HINTS_V2`: one hint-pool entry (INDEX + CHUNK).
    HarmonyPoolEntry,
    /// `REQ_HARMONY_HINTS_V2_HALF`: the second half of a paid entry.
    HarmonyContinuation,
    /// `REQ_HARMONY_QUERY` / `REQ_HARMONY_BATCH_QUERY` at a wire level,
    /// `sub_queries` per group (1 for the single-query opcode).
    HarmonyQuery { level: u8, sub_queries: u32 },
    /// `REQ_ORAM_LOOKUP`.
    OramLookup,
}

/// HarmonyPIR wire levels: 0 = INDEX, 1 = CHUNK, `10 + l` = INDEX sibling
/// level `l`, `20 + l` = CHUNK sibling level `l`. Returns the table kind
/// and, for sibling levels, the level.
pub fn harmony_level(level: u8) -> Option<(TableKind, Option<u8>)> {
    match level {
        0 => Some((TableKind::Index, None)),
        1 => Some((TableKind::Chunk, None)),
        10..=19 => Some((TableKind::Index, Some(level - 10))),
        20..=29 => Some((TableKind::Chunk, Some(level - 20))),
        _ => None,
    }
}

/// DPF sibling batches encode the table and level in the round id as
/// `table_type * 100 + level` (0 = INDEX, 1 = CHUNK).
pub fn dpf_sibling_round(round_id: u16) -> Option<(TableKind, u8)> {
    let (table, level) = (round_id / 100, round_id % 100);
    let table = match table {
        0 => TableKind::Index,
        1 => TableKind::Chunk,
        _ => return None,
    };
    Some((table, level as u8))
}

/// HarmonyPIR segment size for a table of `bins` bins: `T = round(sqrt(2n))`,
/// the number of indices a query sends per group is `T - 1`.
pub fn harmony_segment(bins: u64) -> u64 {
    ((2.0 * bins as f64).sqrt().round()) as u64
}

/// Gas per metered request for every database a server serves.
#[derive(Clone, Debug, PartialEq)]
pub struct GasTable {
    calibration: Calibration,
    databases: BTreeMap<u8, DatabaseGeometry>,
}

impl GasTable {
    pub fn new(calibration: Calibration, databases: BTreeMap<u8, DatabaseGeometry>) -> Self {
        Self {
            calibration,
            databases,
        }
    }

    pub fn calibration(&self) -> &Calibration {
        &self.calibration
    }

    pub fn databases(&self) -> &BTreeMap<u8, DatabaseGeometry> {
        &self.databases
    }

    pub fn geometry(&self, db_id: u8) -> Option<&DatabaseGeometry> {
        self.databases.get(&db_id)
    }

    /// Gas the work of `op` on database `db_id` costs, without the base
    /// fee or egress. `None` when that database does not serve the backend
    /// the request needs (the request will be refused anyway).
    pub fn work_gas(&self, db_id: u8, op: MeteredOp) -> Option<u64> {
        let db = self.databases.get(&db_id)?;
        let c = &self.calibration;
        let ms = match op {
            MeteredOp::DpfIndexRound => self.dpf(&db.cuckoo.as_ref()?.index),
            MeteredOp::DpfChunkRound => self.dpf(&db.cuckoo.as_ref()?.chunk),
            MeteredOp::DpfSiblingPass { table, level } => {
                self.dpf(sibling(db.cuckoo.as_ref()?, table, level)?)
            }
            MeteredOp::TreeTops => {
                db.cuckoo.as_ref()?;
                c.tree_tops_ms
            }
            MeteredOp::OnionRegisterKeys => {
                db.onion.as_ref()?;
                c.onion_register_keys_ms
            }
            MeteredOp::OnionIndexQuery => {
                db.onion.as_ref()?.index_ntt_bytes as f64 / 1e9 * c.onion_index_ms_per_gb
            }
            MeteredOp::OnionChunkQuery => {
                db.onion.as_ref()?.chunk_ntt_bytes as f64 / 1e9 * c.onion_chunk_ms_per_gb
            }
            MeteredOp::OnionSiblingQuery { .. } => {
                db.onion.as_ref()?;
                c.onion_sibling_query_ms
            }
            MeteredOp::OnionTreeTops => {
                db.onion.as_ref()?;
                c.tree_tops_ms
            }
            MeteredOp::HarmonyHintSet { level } => {
                let cuckoo = db.cuckoo.as_ref()?;
                let (table, sibling_level) = harmony_level(level)?;
                match sibling_level {
                    None => {
                        let cells = match table {
                            TableKind::Index => cuckoo.index.cells(),
                            TableKind::Chunk => cuckoo.chunk.cells(),
                        };
                        cells as f64 * c.harmony_pool_us_per_cell / 1e3
                    }
                    Some(level) => {
                        sibling(cuckoo, table, level)?.cells() as f64
                            * c.harmony_sibling_us_per_cell
                            / 1e3
                    }
                }
            }
            MeteredOp::HarmonyPoolEntry => {
                let cuckoo = db.cuckoo.as_ref()?;
                (cuckoo.index.cells() + cuckoo.chunk.cells()) as f64 * c.harmony_pool_us_per_cell
                    / 1e3
            }
            MeteredOp::HarmonyContinuation => {
                db.cuckoo.as_ref()?;
                0.0
            }
            MeteredOp::HarmonyQuery { level, sub_queries } => {
                let cuckoo = db.cuckoo.as_ref()?;
                let (table, sibling_level) = harmony_level(level)?;
                let sub = match sibling_level {
                    None => match table {
                        TableKind::Index => &cuckoo.index,
                        TableKind::Chunk => &cuckoo.chunk,
                    },
                    Some(level) => sibling(cuckoo, table, level)?,
                };
                let reads = sub.groups as f64
                    * (harmony_segment(sub.bins_per_group).saturating_sub(1)) as f64
                    * sub_queries.max(1) as f64;
                reads * c.harmony_query_ns_per_read / 1e6
            }
            MeteredOp::OramLookup => db.oram.as_ref()?.slots_per_lookup as f64 * c.oram_ms_per_slot,
        };
        Some(ms.round().max(0.0) as u64)
    }

    fn dpf(&self, sub: &SubTableGeometry) -> f64 {
        let c = &self.calibration;
        sub.cells() as f64 * c.dpf_ns_per_bin / 1e6 + sub.bytes as f64 / 1e9 * c.dpf_ms_per_gb
    }
}

fn sibling(cuckoo: &CuckooGeometry, table: TableKind, level: u8) -> Option<&SubTableGeometry> {
    match table {
        TableKind::Index => cuckoo.index_siblings.get(usize::from(level)),
        TableKind::Chunk => cuckoo.chunk_siblings.get(usize::from(level)),
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;

    fn sub(bins: u64, groups: u64, bin_bytes: u64) -> SubTableGeometry {
        SubTableGeometry {
            bins_per_group: bins,
            groups,
            bytes: bins * groups * bin_bytes,
        }
    }

    /// The production checkpoint-948454 geometry from pir1's startup log
    /// (INDEX 4 × 13 B slots, CHUNK 3 × 44 B, sibling tables one 256 B slot).
    pub(crate) fn checkpoint_948454() -> DatabaseGeometry {
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
            oram: Some(OramGeometry {
                slots_per_lookup: 1,
            }),
        }
    }

    pub(crate) fn production_table() -> GasTable {
        let mut databases = BTreeMap::new();
        databases.insert(0, checkpoint_948454());
        GasTable::new(Calibration::PIR1_2026_09, databases)
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::production_table;
    use super::*;

    fn within(actual: u64, expected: u64, tolerance: f64) {
        let diff = (actual as f64 - expected as f64).abs() / expected as f64;
        assert!(
            diff <= tolerance,
            "expected about {expected}, got {actual} (off by {:.1}%)",
            diff * 100.0
        );
    }

    #[test]
    fn dpf_rounds_reproduce_the_2026_09_measurements() {
        let t = production_table();
        within(
            t.work_gas(0, MeteredOp::DpfIndexRound).unwrap(),
            1_380,
            0.02,
        );
        within(
            t.work_gas(0, MeteredOp::DpfChunkRound).unwrap(),
            4_550,
            0.02,
        );
        let siblings: u64 = [
            (TableKind::Index, 0),
            (TableKind::Index, 0),
            (TableKind::Index, 1),
            (TableKind::Index, 1),
            (TableKind::Index, 2),
            (TableKind::Index, 2),
            (TableKind::Chunk, 0),
            (TableKind::Chunk, 1),
            (TableKind::Chunk, 2),
        ]
        .into_iter()
        .map(|(table, level)| {
            t.work_gas(0, MeteredOp::DpfSiblingPass { table, level })
                .unwrap()
        })
        .sum();
        // Measured 1,770 ms for the nine sibling passes of one lookup; the
        // per-cell + per-byte fit lands 18% above it (docs/CREDITS.md).
        within(siblings, 1_770, 0.2);
        assert_eq!(t.work_gas(0, MeteredOp::TreeTops), Some(5));
    }

    #[test]
    fn onion_queries_reproduce_the_2026_09_measurements() {
        let t = production_table();
        within(
            t.work_gas(0, MeteredOp::OnionIndexQuery).unwrap(),
            197_500,
            0.01,
        );
        within(
            t.work_gas(0, MeteredOp::OnionChunkQuery).unwrap(),
            403_000,
            0.01,
        );
        assert_eq!(
            t.work_gas(
                0,
                MeteredOp::OnionSiblingQuery {
                    table: TableKind::Index
                }
            ),
            Some(21_000)
        );
        assert_eq!(t.work_gas(0, MeteredOp::OnionRegisterKeys), Some(200));
        assert_eq!(t.work_gas(0, MeteredOp::OnionTreeTops), Some(5));
    }

    #[test]
    fn harmony_hints_and_queries_follow_the_cell_and_read_models() {
        let t = production_table();
        within(
            t.work_gas(0, MeteredOp::HarmonyPoolEntry).unwrap(),
            130_000,
            0.01,
        );
        let index_set = t
            .work_gas(0, MeteredOp::HarmonyHintSet { level: 0 })
            .unwrap();
        let chunk_set = t
            .work_gas(0, MeteredOp::HarmonyHintSet { level: 1 })
            .unwrap();
        assert_eq!(
            index_set + chunk_set,
            t.work_gas(0, MeteredOp::HarmonyPoolEntry).unwrap()
        );
        let sibling_sets: u64 = [10u8, 11, 12, 20, 21, 22]
            .into_iter()
            .map(|level| t.work_gas(0, MeteredOp::HarmonyHintSet { level }).unwrap())
            .sum();
        within(sibling_sets, 13_000, 0.02);
        assert_eq!(t.work_gas(0, MeteredOp::HarmonyContinuation), Some(0));
        // INDEX: 75 groups × (round(sqrt(2·567558)) − 1) = 79,800 reads × 100 ns.
        assert_eq!(harmony_segment(567_558), 1_065);
        assert_eq!(
            t.work_gas(
                0,
                MeteredOp::HarmonyQuery {
                    level: 0,
                    sub_queries: 1
                }
            ),
            Some(8)
        );
        assert_eq!(
            t.work_gas(
                0,
                MeteredOp::HarmonyQuery {
                    level: 0,
                    sub_queries: 4
                }
            ),
            Some(32)
        );
        assert_eq!(t.work_gas(0, MeteredOp::HarmonyHintSet { level: 5 }), None);
        assert_eq!(t.work_gas(0, MeteredOp::HarmonyHintSet { level: 13 }), None);
    }

    #[test]
    fn oram_and_missing_backends() {
        let t = production_table();
        assert_eq!(t.work_gas(0, MeteredOp::OramLookup), Some(2));
        assert_eq!(t.work_gas(1, MeteredOp::OramLookup), None);
        let mut databases = BTreeMap::new();
        databases.insert(
            3,
            DatabaseGeometry {
                cuckoo: None,
                onion: None,
                oram: Some(OramGeometry {
                    slots_per_lookup: 256,
                }),
            },
        );
        let t = GasTable::new(Calibration::PIR1_2026_09, databases);
        assert_eq!(t.work_gas(3, MeteredOp::OramLookup), Some(512));
        assert_eq!(t.work_gas(3, MeteredOp::DpfIndexRound), None);
        assert_eq!(t.work_gas(3, MeteredOp::OnionIndexQuery), None);
        assert_eq!(t.work_gas(3, MeteredOp::TreeTops), None);
    }

    #[test]
    fn wire_level_helpers() {
        assert_eq!(harmony_level(0), Some((TableKind::Index, None)));
        assert_eq!(harmony_level(1), Some((TableKind::Chunk, None)));
        assert_eq!(harmony_level(12), Some((TableKind::Index, Some(2))));
        assert_eq!(harmony_level(20), Some((TableKind::Chunk, Some(0))));
        assert_eq!(harmony_level(2), None);
        assert_eq!(harmony_level(30), None);
        assert_eq!(dpf_sibling_round(0), Some((TableKind::Index, 0)));
        assert_eq!(dpf_sibling_round(102), Some((TableKind::Chunk, 2)));
        assert_eq!(dpf_sibling_round(200), None);
    }

    #[test]
    fn rate_card_2026_09_lands_on_ten_five_two_one() {
        use crate::params::GasParams;
        let p = GasParams::PRODUCTION_2026_09;
        let t = production_table();
        let gas = |op| t.work_gas(0, op).unwrap();
        let credits = |work: u64, frames: u64, egress_bytes: u64| {
            p.credits_to_cover(work + frames * p.base_gas_per_frame + p.egress_gas(egress_bytes))
        };
        // OnionPIR single-address lookup on a fresh client: register keys,
        // INDEX, CHUNK, two tree-top fetches, three sibling queries; 6.5 MB down.
        let onion = gas(MeteredOp::OnionRegisterKeys)
            + gas(MeteredOp::OnionIndexQuery)
            + gas(MeteredOp::OnionChunkQuery)
            + 2 * gas(MeteredOp::OnionTreeTops)
            + 3 * gas(MeteredOp::OnionSiblingQuery {
                table: TableKind::Index,
            });
        assert_eq!(credits(onion, 8, 6_500_000), 10);
        // HarmonyPIR fresh client: one pool entry plus six sibling sets on
        // the hint server (131 MB down), thirteen query frames on the query server.
        let hints = gas(MeteredOp::HarmonyPoolEntry)
            + [10u8, 11, 12, 20, 21, 22]
                .into_iter()
                .map(|level| gas(MeteredOp::HarmonyHintSet { level }))
                .sum::<u64>();
        assert_eq!(credits(hints, 8, 131_000_000), 4);
        let queries = 13 * 4 + gas(MeteredOp::TreeTops);
        assert_eq!(credits(queries, 13, 200_000), 1);
        // DPF single-address lookup, per server: INDEX, CHUNK, nine sibling
        // passes, tree tops; 4.8 MB down.
        let dpf = gas(MeteredOp::DpfIndexRound)
            + gas(MeteredOp::DpfChunkRound)
            + [
                (TableKind::Index, 0u8),
                (TableKind::Index, 0),
                (TableKind::Index, 1),
                (TableKind::Index, 1),
                (TableKind::Index, 2),
                (TableKind::Index, 2),
                (TableKind::Chunk, 0),
                (TableKind::Chunk, 1),
                (TableKind::Chunk, 2),
            ]
            .into_iter()
            .map(|(table, level)| gas(MeteredOp::DpfSiblingPass { table, level }))
            .sum::<u64>()
            + gas(MeteredOp::TreeTops);
        assert_eq!(credits(dpf, 11, 4_800_000), 1);
        // ORAM single-address lookup.
        assert_eq!(credits(gas(MeteredOp::OramLookup), 1, 50_000), 1);
    }
}
