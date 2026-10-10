//! A plan that only carries changes (a delta chain, or the empty plan at the
//! tip) must run on the previous sync's results; `sync()` keeps none, so it
//! only accepts a full sync.

use pir_sdk::{
    compute_sync_plan, require_fresh_sync, require_sync_base, DatabaseCatalog, DatabaseInfo,
    DatabaseKind, PirError, PirResult, QueryResult, SyncPlan,
};

const BASE: u32 = 100;
const TIP: u32 = 110;

fn db(db_id: u8, kind: DatabaseKind, height: u32) -> DatabaseInfo {
    DatabaseInfo {
        db_id,
        kind,
        name: format!("db{db_id}"),
        height,
        index_bins: 128,
        chunk_bins: 128,
        index_k: 4,
        chunk_k: 4,
        tag_seed: 0,
        dpf_n_index: 7,
        dpf_n_chunk: 7,
        has_bucket_merkle: false,
        index_master_seed: 1,
        chunk_master_seed: 2,
        anchor_kind: 0,
        anchor_bytes: Vec::new(),
    }
}

/// Full snapshot at BASE (db 0) and one delta BASE -> TIP (db 1).
fn catalog() -> DatabaseCatalog {
    DatabaseCatalog {
        databases: vec![
            db(0, DatabaseKind::Full, BASE),
            db(1, DatabaseKind::Delta { base_height: BASE }, TIP),
        ],
    }
}

fn is_invalid_state(result: PirResult<()>) -> bool {
    matches!(result, Err(PirError::InvalidState(_)))
}

#[test]
fn sync_only_accepts_a_full_sync() {
    assert!(require_fresh_sync(None).is_ok());
    assert!(require_fresh_sync(Some(0)).is_ok());
    // 50 has no delta chain, so its plan would fall back to a fresh sync; it
    // is still refused, so whether a height works never depends on the catalog.
    for height in [50, BASE, TIP] {
        assert!(
            is_invalid_state(require_fresh_sync(Some(height))),
            "{height}"
        );
    }
}

#[test]
fn fresh_plan_runs_without_previous_results() {
    let plan = compute_sync_plan(&catalog(), None).unwrap();
    assert!(plan.is_fresh_sync);
    assert!(require_sync_base(&plan, 2, None).is_ok());
}

#[test]
fn delta_and_tip_plans_need_the_previous_results() {
    let delta = compute_sync_plan(&catalog(), Some(BASE)).unwrap();
    let at_tip = compute_sync_plan(&catalog(), Some(TIP)).unwrap();
    assert!(!delta.is_fresh_sync && !delta.is_empty());
    assert!(at_tip.is_empty());

    // `None` in a base slot means "absent at the previous height" and is valid.
    let previous = vec![Some(QueryResult::empty()), None];
    for plan in [&delta, &at_tip] {
        assert!(is_invalid_state(require_sync_base(plan, 2, None)));
        assert!(require_sync_base(plan, 2, Some(&previous)).is_ok());
    }
}

#[test]
fn previous_results_need_one_slot_per_script_hash() {
    let short = vec![None];
    for plan in [
        compute_sync_plan(&catalog(), None).unwrap(),
        compute_sync_plan(&catalog(), Some(BASE)).unwrap(),
        SyncPlan::empty(TIP),
    ] {
        assert!(is_invalid_state(require_sync_base(&plan, 2, Some(&short))));
    }
}
