//! Transport-free service-entitlement planning for PIR queries.
//!
//! The planner deliberately reports only counters that can be proven before
//! any private query is sent.  In particular, it shares the exact INDEX PBC
//! placement routine used by the live DPF and Harmony clients, and includes
//! the mandatory CHUNK-presence traffic.  It does not guess Merkle traffic,
//! response sizes, request bytes, or additional data-dependent CHUNK rounds.

use crate::dpf::plan_index_pbc_rounds_for_hashes;
use pir_core::params::{CHUNK_CUCKOO_NUM_HASHES, INDEX_CUCKOO_NUM_HASHES, NUM_HASHES};
use pir_sdk::{DatabaseInfo, PirError, PirResult, ScriptHash};
use pir_service_protocol::{BackendId, ServiceScopePolicyV1, WorkloadId};

/// Product-facing backend identifier. String labels match the signed service
/// scope and `web/src/service-entitlement.ts::ProductQueryShapeV1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductBackendV1 {
    /// Two-provider DPF-PIR.
    DpfPir,
    /// HarmonyPIR (separately priced hint/query roles).
    HarmonyPir,
}

impl ProductBackendV1 {
    /// Canonical signed-service label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DpfPir => "dpf-pir",
            Self::HarmonyPir => "harmony-pir",
        }
    }
}

/// Product-facing workload identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductWorkloadV1 {
    /// A DPF query job at one provider.
    DpfQuery,
    /// A Harmony query job at the query provider.
    HarmonyQuery,
    /// A Harmony cold-cache hint bundle at the hint provider.
    HarmonyHint,
}

impl ProductWorkloadV1 {
    /// Canonical signed-service label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DpfQuery => "dpf-query",
            Self::HarmonyQuery => "harmony-query",
            Self::HarmonyHint => "harmony-hint",
        }
    }
}

/// Counters that the real planner proves a provider must admit.
///
/// These are lower bounds for the complete provider transcript. `frames` and
/// `work_units` include mandatory CHUNK-presence traffic, but exclude Merkle
/// traffic and any additional CHUNK rounds selected after the private INDEX
/// response is decoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductQueryLowerBoundsV1 {
    /// Payment-V1 logical inputs charged by the backend gate.
    pub logical_inputs: u64,
    /// Minimum backend frames sent to this one provider.
    pub frames: u64,
    /// Minimum public backend work units, when derivable without I/O.
    pub work_units: Option<u64>,
    /// Minimum hint groups for a cold-cache hint workload.
    pub hint_groups: Option<u64>,
    /// Minimum simultaneous sockets needed by a valid fallback path.
    pub concurrent_sockets: Option<u8>,
}

/// Explicitly identifies counters intentionally absent from a plan.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProductQueryOmissionsV1 {
    /// Request bytes require real backend encoding/state and are not guessed.
    pub request_bytes: bool,
    /// Response sizes depend on the server/database and are not guessed.
    pub response_bytes: bool,
    /// Bucket-Merkle frame geometry is unavailable from `DatabaseInfo` alone.
    pub merkle_frames: bool,
    /// More real chunks may require more than the mandatory presence round(s).
    pub additional_chunk_frames: bool,
    /// A complete Harmony hint entitlement also includes authenticated sibling
    /// groups whose count is learned from verified tree-tops, not the catalog.
    pub sibling_hint_groups: bool,
}

/// Native transport-free result used by the WASM and TypeScript adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductQueryShapeV1 {
    /// Signed-service backend label.
    pub backend: ProductBackendV1,
    /// Signed-service workload label.
    pub workload: ProductWorkloadV1,
    /// Planner-proven provider-local admission lower bounds.
    pub lower_bounds: ProductQueryLowerBoundsV1,
    /// Exact number of PBC INDEX jobs, when this is a query workload.
    pub pbc_rounds: Option<u64>,
    /// Exact INDEX frames per provider (`R` for DPF, `2R` for Harmony).
    pub exact_index_frames: Option<u64>,
    /// Counters deliberately omitted instead of estimated.
    pub omitted: ProductQueryOmissionsV1,
}

/// Fail locally when a signed service scope cannot admit the planner-proven
/// lower bounds for a query. This deliberately checks only counters present in
/// [`ProductQueryLowerBoundsV1`]; omitted, data-dependent transcript costs
/// remain the operator's responsibility when sizing the signed scope.
pub fn assert_product_query_shape_fits_scope_v1(
    shape: &ProductQueryShapeV1,
    scope: &ServiceScopePolicyV1,
    label: &str,
) -> PirResult<()> {
    let (backend, workload) = match (shape.backend, shape.workload) {
        (ProductBackendV1::DpfPir, ProductWorkloadV1::DpfQuery) => {
            (BackendId::DpfPirV1, WorkloadId::DpfEvaluateJobV1)
        }
        (ProductBackendV1::HarmonyPir, ProductWorkloadV1::HarmonyQuery) => {
            (BackendId::HarmonyPirV2, WorkloadId::HarmonyQueryJobV1)
        }
        (ProductBackendV1::HarmonyPir, ProductWorkloadV1::HarmonyHint) => {
            (BackendId::HarmonyPirV2, WorkloadId::HarmonyHintBundleV1)
        }
        _ => {
            return Err(PirError::InvalidState(format!(
                "{label} has an unknown backend/workload"
            )))
        }
    };
    if scope.scope.backend != backend || scope.scope.workload != workload {
        return Err(PirError::InvalidState(format!(
            "{label} does not match the planned backend/workload"
        )));
    }

    let limits = &scope.limits;
    let required = &shape.lower_bounds;
    let comparisons = [
        (
            "logical inputs",
            Some(required.logical_inputs),
            u64::from(limits.max_logical_inputs),
        ),
        (
            "frames",
            Some(required.frames),
            u64::from(limits.max_frames),
        ),
        (
            "concurrent sockets",
            required.concurrent_sockets.map(u64::from),
            u64::from(limits.max_concurrent_sockets),
        ),
        (
            "hint groups",
            required.hint_groups,
            u64::from(limits.max_hint_groups),
        ),
        ("work units", required.work_units, limits.max_work_units),
    ];
    for (field, required, maximum) in comparisons {
        let Some(required) = required else {
            continue;
        };
        if required > maximum {
            return Err(PirError::InvalidState(format!(
                "{label} {field} limit is insufficient (requires {required}, signed maximum {maximum})"
            )));
        }
    }
    Ok(())
}

/// Plan a DPF query for one provider without opening a socket.
pub fn plan_dpf_service_query_v1(
    script_hashes: &[ScriptHash],
    db_info: &DatabaseInfo,
) -> PirResult<ProductQueryShapeV1> {
    validate_query_geometry(script_hashes, db_info)?;
    let (rounds, _) = plan_index_pbc_rounds_for_hashes(script_hashes, db_info.index_k as usize)?;
    let pbc_rounds = as_u64(rounds.len(), "DPF PBC round count")?;
    let logical_inputs = pbc_rounds;
    let mandatory_chunk_frames = as_u64(script_hashes.len(), "DPF query count")?;
    let frames = checked_add(pbc_rounds, mandatory_chunk_frames, "DPF frame lower bound")?;

    // The runtime charges one work unit per DPF key. Every INDEX frame has
    // index_k groups × two cuckoo keys; each per-query mandatory CHUNK frame
    // has chunk_k groups × two cuckoo keys.
    let index_work = checked_product(
        &[
            pbc_rounds,
            u64::from(db_info.index_k),
            INDEX_CUCKOO_NUM_HASHES as u64,
        ],
        "DPF INDEX work lower bound",
    )?;
    let chunk_work = checked_product(
        &[
            mandatory_chunk_frames,
            u64::from(db_info.chunk_k),
            CHUNK_CUCKOO_NUM_HASHES as u64,
        ],
        "DPF CHUNK work lower bound",
    )?;

    Ok(ProductQueryShapeV1 {
        backend: ProductBackendV1::DpfPir,
        workload: ProductWorkloadV1::DpfQuery,
        lower_bounds: ProductQueryLowerBoundsV1 {
            logical_inputs,
            frames,
            work_units: Some(checked_add(index_work, chunk_work, "DPF work lower bound")?),
            hint_groups: None,
            concurrent_sockets: Some(1),
        },
        pbc_rounds: Some(pbc_rounds),
        exact_index_frames: Some(pbc_rounds),
        omitted: ProductQueryOmissionsV1 {
            request_bytes: true,
            response_bytes: true,
            merkle_frames: db_info.has_bucket_merkle,
            additional_chunk_frames: true,
            sibling_hint_groups: false,
        },
    })
}

/// Plan a Harmony query-provider job without opening a socket or consuming a
/// cached hint. The exact INDEX shape is `R` PBC jobs × two cuckoo-position
/// frames. The batched CHUNK path always emits at least one two-frame dummy or
/// real presence round.
pub fn plan_harmony_service_query_v1(
    script_hashes: &[ScriptHash],
    db_info: &DatabaseInfo,
) -> PirResult<ProductQueryShapeV1> {
    validate_query_geometry(script_hashes, db_info)?;
    let (rounds, _) = plan_index_pbc_rounds_for_hashes(script_hashes, db_info.index_k as usize)?;
    let pbc_rounds = as_u64(rounds.len(), "Harmony PBC round count")?;
    let exact_index_frames = checked_product(
        &[pbc_rounds, INDEX_CUCKOO_NUM_HASHES as u64],
        "Harmony INDEX frame count",
    )?;
    let mandatory_chunk_frames = CHUNK_CUCKOO_NUM_HASHES as u64;
    let frames = checked_add(
        exact_index_frames,
        mandatory_chunk_frames,
        "Harmony frame lower bound",
    )?;

    // `HarmonyGroup::new(..., T=0, ...)` derives the same balanced T. A
    // fixed-shape request carries exactly T-1 indices for every group.
    let index_indices_per_group = harmony_indices_per_group(db_info.index_bins)?;
    let chunk_indices_per_group = harmony_indices_per_group(db_info.chunk_bins)?;
    let index_work = checked_product(
        &[
            exact_index_frames,
            u64::from(db_info.index_k),
            index_indices_per_group,
        ],
        "Harmony INDEX work lower bound",
    )?;
    let chunk_work = checked_product(
        &[
            mandatory_chunk_frames,
            u64::from(db_info.chunk_k),
            chunk_indices_per_group,
        ],
        "Harmony CHUNK work lower bound",
    )?;

    Ok(ProductQueryShapeV1 {
        backend: ProductBackendV1::HarmonyPir,
        workload: ProductWorkloadV1::HarmonyQuery,
        lower_bounds: ProductQueryLowerBoundsV1 {
            logical_inputs: pbc_rounds,
            frames,
            work_units: Some(checked_add(
                index_work,
                chunk_work,
                "Harmony work lower bound",
            )?),
            hint_groups: None,
            concurrent_sockets: Some(1),
        },
        pbc_rounds: Some(pbc_rounds),
        exact_index_frames: Some(exact_index_frames),
        omitted: ProductQueryOmissionsV1 {
            request_bytes: true,
            response_bytes: true,
            merkle_frames: db_info.has_bucket_merkle,
            additional_chunk_frames: true,
            sibling_hint_groups: false,
        },
    })
}

/// Plan the catalog-known lower bound for a cold Harmony hint workload.
///
/// The main V2 bundle contains every INDEX and CHUNK group. Authenticated
/// sibling hints are deliberately omitted because their count is learned only
/// after verified tree-top preflight.
pub fn plan_harmony_service_hint_v1(db_info: &DatabaseInfo) -> PirResult<ProductQueryShapeV1> {
    validate_database_geometry(db_info)?;
    let hint_groups = checked_add(
        u64::from(db_info.index_k),
        u64::from(db_info.chunk_k),
        "Harmony main hint-group count",
    )?;
    Ok(ProductQueryShapeV1 {
        backend: ProductBackendV1::HarmonyPir,
        workload: ProductWorkloadV1::HarmonyHint,
        lower_bounds: ProductQueryLowerBoundsV1 {
            logical_inputs: 0,
            frames: 1,
            work_units: Some(hint_groups),
            hint_groups: Some(hint_groups),
            concurrent_sockets: Some(1),
        },
        pbc_rounds: None,
        exact_index_frames: None,
        omitted: ProductQueryOmissionsV1 {
            request_bytes: true,
            response_bytes: true,
            merkle_frames: false,
            additional_chunk_frames: false,
            sibling_hint_groups: db_info.has_bucket_merkle,
        },
    })
}

fn validate_query_geometry(script_hashes: &[ScriptHash], db_info: &DatabaseInfo) -> PirResult<()> {
    if script_hashes.is_empty() {
        return Err(PirError::InvalidState(
            "service query planner requires at least one script hash".into(),
        ));
    }
    validate_database_geometry(db_info)
}

fn validate_database_geometry(db_info: &DatabaseInfo) -> PirResult<()> {
    if usize::from(db_info.index_k) < NUM_HASHES || usize::from(db_info.chunk_k) < NUM_HASHES {
        return Err(PirError::InvalidState(format!(
            "service query planner requires index_k and chunk_k >= {NUM_HASHES} (got {}/{})",
            db_info.index_k, db_info.chunk_k
        )));
    }
    if db_info.index_bins == 0 || db_info.chunk_bins == 0 {
        return Err(PirError::InvalidState(format!(
            "service query planner requires non-zero INDEX/CHUNK bins (got {}/{})",
            db_info.index_bins, db_info.chunk_bins
        )));
    }
    Ok(())
}

fn harmony_indices_per_group(real_n: u32) -> PirResult<u64> {
    let t = harmonypir::remote::find_best_t(real_n);
    let (_, padded_t) = harmonypir::remote::pad_n_for_t(real_n, t)
        .map_err(|error| PirError::InvalidState(format!("invalid Harmony geometry: {error}")))?;
    let indices = padded_t.checked_sub(1).ok_or_else(|| {
        PirError::InvalidState("Harmony balanced T cannot produce a fixed-count request".into())
    })?;
    if indices == 0 {
        return Err(PirError::InvalidState(
            "Harmony balanced T must be at least two".into(),
        ));
    }
    Ok(u64::from(indices))
}

fn as_u64(value: usize, label: &str) -> PirResult<u64> {
    u64::try_from(value).map_err(|_| PirError::InvalidState(format!("{label} does not fit u64")))
}

fn checked_add(left: u64, right: u64, label: &str) -> PirResult<u64> {
    left.checked_add(right)
        .ok_or_else(|| PirError::InvalidState(format!("{label} overflow")))
}

fn checked_product(values: &[u64], label: &str) -> PirResult<u64> {
    values.iter().try_fold(1_u64, |acc, value| {
        acc.checked_mul(*value)
            .ok_or_else(|| PirError::InvalidState(format!("{label} overflow")))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pir_sdk::DatabaseKind;
    use pir_service_protocol::{DatasetBindingV1, EntitlementLimitsV1, ServiceScopeV1};

    fn db(index_k: u8, chunk_k: u8) -> DatabaseInfo {
        DatabaseInfo {
            db_id: 7,
            kind: DatabaseKind::Full,
            name: "planner-fixture".into(),
            height: 1,
            index_bins: 1_024,
            chunk_bins: 2_048,
            index_k,
            chunk_k,
            tag_seed: 1,
            dpf_n_index: 10,
            dpf_n_chunk: 11,
            has_bucket_merkle: true,
            index_master_seed: 2,
            chunk_master_seed: 3,
            anchor_kind: 0,
            anchor_bytes: Vec::new(),
        }
    }

    fn colliding_first_groups(k: usize) -> (ScriptHash, ScriptHash) {
        let mut first = [[0_u8; 20]; 256];
        let mut seen = [false; 256];
        for byte in 0_u8..=u8::MAX {
            let hash = [byte; 20];
            let group = pir_core::hash::derive_groups_3(&hash, k)[0];
            if seen[group] {
                return (first[group], hash);
            }
            first[group] = hash;
            seen[group] = true;
        }
        panic!("pigeonhole principle requires a first-group collision");
    }

    #[test]
    fn collision_uses_real_pbc_alternates_without_adding_a_round() {
        let database = db(4, 4);
        let (a, b) = colliding_first_groups(database.index_k as usize);
        assert_eq!(
            pir_core::hash::derive_groups_3(&a, 4)[0],
            pir_core::hash::derive_groups_3(&b, 4)[0]
        );

        let dpf = plan_dpf_service_query_v1(&[a, b], &database).unwrap();
        assert_eq!(dpf.pbc_rounds, Some(1));
        assert_eq!(dpf.exact_index_frames, Some(1));
        assert_eq!(dpf.lower_bounds.logical_inputs, 1);
        assert_eq!(dpf.lower_bounds.frames, 3); // 1 INDEX + 2 CHUNK presence

        let harmony = plan_harmony_service_query_v1(&[a, b], &database).unwrap();
        assert_eq!(harmony.pbc_rounds, Some(1));
        assert_eq!(harmony.exact_index_frames, Some(2));
        assert_eq!(harmony.lower_bounds.logical_inputs, 1);
        assert_eq!(harmony.lower_bounds.frames, 4); // 2 INDEX + CHUNK pair
    }

    #[test]
    fn k_plus_one_inputs_produce_a_real_multi_round_plan() {
        let database = db(3, 3);
        let hashes = vec![[0_u8; 20], [1_u8; 20], [2_u8; 20], [3_u8; 20]];

        let dpf = plan_dpf_service_query_v1(&hashes, &database).unwrap();
        assert_eq!(dpf.pbc_rounds, Some(2));
        assert_eq!(dpf.lower_bounds.logical_inputs, 2);
        assert_eq!(dpf.lower_bounds.frames, 6); // 2 INDEX + 4 CHUNK presence
        assert_eq!(dpf.lower_bounds.work_units, Some(36));

        let harmony = plan_harmony_service_query_v1(&hashes, &database).unwrap();
        assert_eq!(harmony.pbc_rounds, Some(2));
        assert_eq!(harmony.exact_index_frames, Some(4));
        assert_eq!(harmony.lower_bounds.logical_inputs, 2);
        assert_eq!(harmony.lower_bounds.frames, 6); // 4 INDEX + CHUNK pair
        assert!(harmony.lower_bounds.work_units.unwrap() > 0);
    }

    #[test]
    fn hint_plan_is_main_groups_only_and_marks_siblings_omitted() {
        let plan = plan_harmony_service_hint_v1(&db(75, 80)).unwrap();
        assert_eq!(plan.backend, ProductBackendV1::HarmonyPir);
        assert_eq!(plan.workload, ProductWorkloadV1::HarmonyHint);
        assert_eq!(plan.lower_bounds.logical_inputs, 0);
        assert_eq!(plan.lower_bounds.frames, 1);
        assert_eq!(plan.lower_bounds.hint_groups, Some(155));
        assert_eq!(plan.lower_bounds.work_units, Some(155));
        assert!(plan.omitted.sibling_hint_groups);
    }

    #[test]
    fn empty_or_invalid_geometry_fails_before_pbc() {
        let valid = db(3, 3);
        assert!(plan_dpf_service_query_v1(&[], &valid).is_err());
        assert!(plan_harmony_service_query_v1(&[], &valid).is_err());
        assert!(plan_dpf_service_query_v1(&[[0; 20]], &db(2, 3)).is_err());
        assert!(plan_harmony_service_hint_v1(&db(3, 2)).is_err());
    }

    #[test]
    fn signed_scope_preflight_reports_the_exact_insufficient_counter() {
        let plan = plan_harmony_service_query_v1(&[[0; 20], [1; 20]], &db(75, 80)).unwrap();
        let required_work = plan.lower_bounds.work_units.unwrap();
        let scope = ServiceScopePolicyV1 {
            scope: ServiceScopeV1 {
                provider_id: [7; 32],
                backend: BackendId::HarmonyPirV2,
                workload: WorkloadId::HarmonyQueryJobV1,
                protocol_version: 2,
                dataset: DatasetBindingV1::ManifestRoot { root: [8; 32] },
                operation_profile: 1,
                entitlement_profile: 1,
            },
            limits: EntitlementLimitsV1 {
                max_logical_inputs: u16::MAX,
                max_frames: u32::MAX,
                max_request_bytes: u64::MAX,
                max_response_bytes: u64::MAX,
                max_wall_time_ms: u32::MAX,
                max_concurrent_sockets: u8::MAX,
                max_hint_groups: u16::MAX,
                max_work_units: required_work - 1,
            },
            offers: Vec::new(),
        };

        let error =
            assert_product_query_shape_fits_scope_v1(&plan, &scope, "selected Harmony query scope")
                .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "invalid state: selected Harmony query scope work units limit is insufficient \
                 (requires {required_work}, signed maximum {})",
                required_work - 1,
            )
        );
    }
}
