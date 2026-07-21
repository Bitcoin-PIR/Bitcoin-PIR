//! Criterion benchmarks for `pir_sdk::compute_sync_plan`.
//!
//! `compute_sync_plan` is called once per `client.sync(...)` round and is
//! not on a tight inner loop. The benches here exist to (a) catch
//! algorithmic regressions when the BFS / adjacency-map code changes, and
//! (b) measure the win from the planned `SyncPlanner` reuse path
//! (pre-built adjacency map).
//!
//! Catalog sizes are calibrated to real Bitcoin PIR deployments:
//! - **Tiny** — 1 full snapshot + 5 chained deltas. Most realistic
//!   "small fleet" shape (one full + a few weekly deltas).
//! - **Realistic** — 1 full snapshot + 50 chained deltas. Typical
//!   long-running deployment (~50 weeks of 4000-block deltas off one
//!   anchor snapshot).
//! - **Stress** — 5 full snapshots + 200 chained deltas. Approaches
//!   the u8 `db_id` ceiling (255 entries hard cap).
//!
//! Query scenarios cover the full `compute_sync_plan` decision tree:
//! - `at_tip` — `last_height == latest_tip` (early exit, no work).
//! - `incremental_1step` — last sync one delta behind.
//! - `incremental_5step` — at the in-bound limit (`MAX_DELTA_CHAIN_LENGTH`).
//! - `incremental_6step` — forces fall-back to fresh sync (the BFS
//!   currently rebuilds the adjacency map twice; the refactor fixes
//!   this).
//! - `fresh_sync` — `last_height == None` (skips BFS for the
//!   start-from-best-full path, then BFS to chain deltas to tip).
//!
//! Run with:
//! ```bash
//! cargo bench -p pir-sdk --bench sync_plan
//! ```

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pir_sdk::{compute_sync_plan, DatabaseCatalog, DatabaseInfo, DatabaseKind, SyncPlanner};

/// Build a catalog with `num_full` full snapshots + `num_deltas` chained
/// deltas. Each full snapshot lives at `1_000_000 + i * delta_step *
/// num_deltas`, and each delta covers `delta_step` blocks chained off the
/// previous tip starting from the highest full snapshot.
///
/// Heights are picked to look like realistic Bitcoin block numbers
/// (~944k at time of writing), and `delta_step = 4000` matches the
/// `delta_940611_944000`-style naming the build pipeline emits.
fn build_catalog(num_full: u8, num_deltas: u8) -> DatabaseCatalog {
    const DELTA_STEP: u32 = 4_000;
    const BASE_HEIGHT: u32 = 1_000_000;

    let mut catalog = DatabaseCatalog::new();
    let mut next_db_id: u8 = 0;

    // Full snapshots, spaced (num_deltas * DELTA_STEP) apart so each
    // anchor has room for the delta chain.
    let mut full_heights: Vec<u32> = Vec::with_capacity(num_full as usize);
    for i in 0..num_full {
        let height = BASE_HEIGHT + (i as u32) * DELTA_STEP * (num_deltas.max(1) as u32);
        full_heights.push(height);
        catalog.databases.push(DatabaseInfo {
            db_id: next_db_id,
            kind: DatabaseKind::Full,
            name: format!("full_{}", height),
            height,
            index_bins: 1024,
            chunk_bins: 2048,
            index_k: 75,
            chunk_k: 80,
            tag_seed: 0,
            dpf_n_index: 10,
            dpf_n_chunk: 11,
            has_bucket_merkle: false,
        });
        next_db_id = next_db_id.checked_add(1).expect("catalog overflow (u8 db_id)");
    }

    // Chained deltas off the highest full snapshot.
    let anchor_height = *full_heights.last().expect("at least one full snapshot");
    let mut prev_tip = anchor_height;
    for _ in 0..num_deltas {
        let new_tip = prev_tip + DELTA_STEP;
        catalog.databases.push(DatabaseInfo {
            db_id: next_db_id,
            kind: DatabaseKind::Delta { base_height: prev_tip },
            name: format!("delta_{}_{}", prev_tip, new_tip),
            height: new_tip,
            index_bins: 256,
            chunk_bins: 512,
            index_k: 75,
            chunk_k: 80,
            tag_seed: 0,
            dpf_n_index: 8,
            dpf_n_chunk: 9,
            has_bucket_merkle: false,
        });
        next_db_id = next_db_id.checked_add(1).expect("catalog overflow (u8 db_id)");
        prev_tip = new_tip;
    }

    catalog
}

/// Pick a `last_height` that produces an N-step incremental chain
/// (counting from the catalog's highest full snapshot's anchor).
fn last_height_for_steps(catalog: &DatabaseCatalog, steps_back: u32) -> u32 {
    let tip = catalog.latest_tip().expect("non-empty catalog");
    tip.saturating_sub(steps_back * 4_000)
}

fn bench_compute_sync_plan(c: &mut Criterion) {
    // Three catalog shapes; benches cluster by shape so the user can
    // diff e.g. "tiny @ at_tip" against the same shape's other queries.
    let shapes: Vec<(&'static str, DatabaseCatalog)> = vec![
        ("tiny_1full_5delta", build_catalog(1, 5)),
        ("realistic_1full_50delta", build_catalog(1, 50)),
        ("stress_5full_200delta", build_catalog(5, 200)),
    ];

    for (label, catalog) in &shapes {
        let mut group = c.benchmark_group(format!("compute_sync_plan/{}", label));

        let tip = catalog.latest_tip().unwrap();
        let last_1 = last_height_for_steps(catalog, 1);
        let last_5 = last_height_for_steps(catalog, 5);
        let last_6 = last_height_for_steps(catalog, 6);

        // at_tip — early exit, no work.
        group.bench_function(BenchmarkId::from_parameter("at_tip"), |b| {
            b.iter(|| {
                let plan = compute_sync_plan(black_box(catalog), black_box(Some(tip)))
                    .expect("plan");
                black_box(plan);
            });
        });

        // 1-step incremental — shortest BFS.
        group.bench_function(BenchmarkId::from_parameter("incremental_1step"), |b| {
            b.iter(|| {
                let plan = compute_sync_plan(black_box(catalog), black_box(Some(last_1)))
                    .expect("plan");
                black_box(plan);
            });
        });

        // 5-step incremental — at MAX_DELTA_CHAIN_LENGTH bound.
        group.bench_function(BenchmarkId::from_parameter("incremental_5step"), |b| {
            b.iter(|| {
                let plan = compute_sync_plan(black_box(catalog), black_box(Some(last_5)))
                    .expect("plan");
                black_box(plan);
            });
        });

        // 6-step incremental — exceeds MAX_DELTA_CHAIN_LENGTH, forces
        // fall-back to compute_fresh_sync_plan (which currently
        // rebuilds the adjacency map a second time — the refactor
        // closes this).
        group.bench_function(BenchmarkId::from_parameter("incremental_6step_fallback"), |b| {
            b.iter(|| {
                let plan = compute_sync_plan(black_box(catalog), black_box(Some(last_6)))
                    .expect("plan");
                black_box(plan);
            });
        });

        // Fresh sync — last_height = None.
        group.bench_function(BenchmarkId::from_parameter("fresh_sync"), |b| {
            b.iter(|| {
                let plan = compute_sync_plan(black_box(catalog), black_box(None))
                    .expect("plan");
                black_box(plan);
            });
        });

        group.finish();
    }
}

/// Compare `compute_sync_plan` (rebuilds adjacency map each call) vs.
/// `SyncPlanner::plan` (one shared adjacency map across N plans). The
/// roadmap asked us to "consider caching chain computations"; this
/// bench is the visible signal.
///
/// Workload: compute 10 plans against the realistic catalog at varying
/// `last_height` values. The free-function path pays for 10 adjacency
/// maps; the planner path pays for 1.
fn bench_planner_reuse(c: &mut Criterion) {
    let catalog = build_catalog(1, 50);
    let tip = catalog.latest_tip().unwrap();

    // 10 distinct last_heights spaced one delta apart. We pick the
    // "near tip" range so each plan is a real BFS run, not an at-tip
    // early-exit.
    let last_heights: Vec<Option<u32>> = (1..=10)
        .map(|step_back: u32| Some(tip.saturating_sub(step_back * 4_000)))
        .collect();

    let mut group = c.benchmark_group("planner_reuse/realistic_1full_50delta_x10plans");

    group.bench_function(BenchmarkId::from_parameter("free_function_x10"), |b| {
        b.iter(|| {
            for last in &last_heights {
                let plan = compute_sync_plan(black_box(&catalog), black_box(*last))
                    .expect("plan");
                black_box(plan);
            }
        });
    });

    group.bench_function(BenchmarkId::from_parameter("planner_reuse_x10"), |b| {
        b.iter(|| {
            // SyncPlanner construction (adjacency-map build) is OUT
            // of the per-plan cost — it amortises across all 10
            // plans. This is the prescribed pattern for multi-plan
            // callers (multi-account wallets, polling dashboards).
            let planner = SyncPlanner::new(black_box(&catalog)).expect("planner");
            for last in &last_heights {
                let plan = planner.plan(black_box(*last)).expect("plan");
                black_box(plan);
            }
        });
    });

    group.finish();
}

criterion_group!(benches, bench_compute_sync_plan, bench_planner_reuse);
criterion_main!(benches);
