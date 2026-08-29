//! HarmonyPIR client implementation.
//!
//! HarmonyPIR is a two-server stateful PIR protocol:
//! - **Hint Server**: streams precomputed hint parities (one per group, per level)
//! - **Query Server**: answers per-group sorted-index queries against the cuckoo table
//!
//! The per-group state (relocation data structure + hints) is managed by
//! [`harmonypir::remote::RemoteClient`]. The SDK owns the transport and the
//! browser binding; the upstream library owns only protocol state and wire
//! request/response processing.
//!
//! ## Flow
//! 1. `connect()` opens WebSocket connections to both servers.
//! 2. `fetch_catalog()` sends [`REQ_HARMONY_GET_INFO`] and builds a
//!    single-entry catalog.
//! 3. `execute_step()` for each script hash:
//!    - Ensures per-group `HarmonyGroup` instances exist for this db
//!      (one per INDEX group and one per CHUNK group).
//!    - Fetches hints from the hint server once per db.
//!    - For each [`INDEX_CUCKOO_NUM_HASHES`] hash function, builds a
//!      padded batch request (real queries + synthetic dummies), sends
//!      it to the query server, and XORs hints with the response to
//!      recover the INDEX bin.
//!    - If an entry is found, runs the CHUNK rounds for the referenced
//!      chunk ids to recover UTXO bytes.
//!
//! The implementation mirrors the native reference
//! `apps/server/src/bin/harmonypir_batch_e2e.rs` but fetches hints over
//! the wire instead of computing them from a local mmap.

#[cfg(not(target_arch = "wasm32"))]
pub(crate) use crate::connection::WsConnection;
pub(crate) use crate::db_proof::{
    fetch_database_proof, verify_database_proof, DatabaseProofPolicy, VerifiedDatabaseRoots,
};
pub(crate) use crate::hint_cache;
pub(crate) use crate::merkle_verify::{
    fetch_tree_tops, verify_bucket_merkle_batch_generic, verify_bucket_merkle_batch_parallel,
    verify_tree_tops_super_root, BucketMerkleItem, BucketMerkleSiblingQuerier, SiblingLevelPlan,
    TreeTop, BUCKET_MERKLE_ARITY, BUCKET_MERKLE_SIB_ROW_SIZE,
};
pub(crate) use crate::protocol::{
    decode_catalog, decode_error_response_message, encode_request, ensure_catalog_query_compatible,
    reject_error_response, REQ_GET_DB_CATALOG, RESP_DB_CATALOG, RESP_ERROR,
};
pub(crate) use crate::transport::PirTransport;
pub(crate) use crate::verified_query::VerifiedQueryResult;
pub(crate) use crate::verified_roots::{RootPolicy, VerifiedRootState};
pub(crate) use async_trait::async_trait;
pub(crate) use harmonypir::remote::{PrpBackend, RemoteClient as HarmonyGroup};
pub(crate) use pir_core::params::{
    CHUNK_CUCKOO_NUM_HASHES, CHUNK_SIZE, CHUNK_SLOTS_PER_BIN, CHUNK_SLOT_SIZE,
    INDEX_CUCKOO_NUM_HASHES, INDEX_SLOTS_PER_BIN, INDEX_SLOT_SIZE, NUM_HASHES, TAG_SIZE,
};
pub(crate) use pir_sdk::{
    compute_sync_plan, merge_delta_batch, BucketRef, ConnectionState, DatabaseCatalog,
    DatabaseInfo, DatabaseKind, Instant, LeakageRecorder, PirBackendType, PirClient, PirError,
    PirMetrics, PirResult, QueryResult, RoundKind, RoundProfile, ScriptHash, StateListener,
    SyncPlan, SyncProgress, SyncResult, SyncStep, UtxoEntry,
};
pub(crate) use std::collections::HashMap;
pub(crate) use std::path::PathBuf;
pub(crate) use std::sync::Arc;

mod chunk;
mod hints;
mod merkle;
mod persist;
mod pir_client;
mod query;
mod session;
mod sibling;
mod traces;
mod wire;

use hints::*;
use sibling::*;
use traces::*;
use wire::*;

/// PRP backends used on the HarmonyPIR wire.
pub use harmonypir::remote::{PRP_FASTPRP, PRP_HMR12};
// PRP_ALF (= 2) was removed 2026-05-12: ALF panicked on domain<65536
// (sibling Merkle tables hit this), causing pir-vpsbg crash loops.

/// Per-group progress callback for the main-hint fetch path.
///
/// Fired once per group as its hint blob arrives over the wire and is
/// loaded into the local `HarmonyGroup`. `done` ranges from `1..=total`,
/// `total` is the constant `index_k + chunk_k` for the active database
/// (typically 75 + 80 = 155). `phase` is `"index"` while INDEX groups
/// stream in and `"chunk"` while CHUNK groups stream in.
///
/// Padding invariants are unaffected — the fetch wire shape is identical
/// to the no-callback path; this trait only observes when each per-group
/// response has been processed.
pub trait HintProgress: Send + Sync {
    /// Called after the `done`-th group's hints have been received and
    /// loaded into local state. See trait doc for argument contract.
    fn on_group_complete(&self, done: u32, total: u32, phase: &str);
}

// ─── HarmonyPIR Client ──────────────────────────────────────────────────────

/// HarmonyPIR client for two-server PIR queries.
///
/// HarmonyPIR is a stateful two-server PIR protocol that splits work
/// between a **hint server** (streams precomputed parities once per
/// database) and a **query server** (answers per-group cuckoo-bin
/// lookups). The per-client `HarmonyGroup` state must stay in sync
/// with the server's cuckoo table, so mid-session database switches
/// rebuild the groups from scratch; cross-session continuity is
/// provided by the hint cache (see [`with_hint_cache_dir`], plus
/// [`save_hints_bytes`] / [`load_hints_bytes`] for browser-side
/// IndexedDB mirrors).
///
/// # PRP backend selection
///
/// HarmonyPIR is parameterised by a pseudo-random permutation. The
/// default is HMR12 (portable, no extra deps); the `fastprp` cargo
/// feature enables FastPRP (2-3× faster per-group encode with a
/// precomputed cache). Select at runtime via [`set_prp_backend`] with
/// one of [`PRP_HMR12`] or [`PRP_FASTPRP`]. (PRP_ALF was removed
/// 2026-05-12 — see the V2_HALF_FETCH_TIMEOUT test override note.)
///
/// # Examples
///
/// Basic flow — create, connect, sync, use the results:
///
/// ```ignore
/// use pir_sdk_client::{HarmonyClient, PirClient, ScriptHash, PRP_HMR12};
///
/// #[tokio::main]
/// async fn main() {
///     let mut client = HarmonyClient::new(
///         "ws://hint-server:8091",
///         "ws://query-server:8092",
///     );
///     client.set_prp_backend(PRP_HMR12);
///     client.connect().await.unwrap();
///
///     let script_hash: ScriptHash = [0u8; 20]; // your HASH160 script hash
///     let result = client.sync(&[script_hash], None).await.unwrap();
///
///     if let Some(qr) = &result.results[0] {
///         println!("Balance: {} sats", qr.total_balance());
///     }
/// }
/// ```
///
/// Resuming from a cached hint blob (avoids a full hint re-fetch on
/// reconnect when the database fingerprint matches):
///
/// ```ignore
/// use pir_sdk_client::{HarmonyClient, PirClient};
///
/// #[tokio::main]
/// async fn main() {
///     let mut client = HarmonyClient::new(
///         "ws://hint-server:8091",
///         "ws://query-server:8092",
///     )
///     .with_hint_cache_dir("/var/cache/pir-sdk/hints");
///
///     // First sync populates the cache.
///     client.connect().await.unwrap();
///     let _ = client.sync(&[[0u8; 20]], None).await.unwrap();
///     client.disconnect().await.unwrap();
///
///     // Later reconnect: hint fetch short-circuits from the cache
///     // when the (key, backend, db_id, height, …) fingerprint matches.
///     client.connect().await.unwrap();
///     let _ = client.sync(&[[0u8; 20]], None).await.unwrap();
/// }
/// ```
///
/// [`with_hint_cache_dir`]: HarmonyClient::with_hint_cache_dir
/// [`save_hints_bytes`]: HarmonyClient::save_hints_bytes
/// [`load_hints_bytes`]: HarmonyClient::load_hints_bytes
/// [`set_prp_backend`]: HarmonyClient::set_prp_backend
pub struct HarmonyClient {
    hint_server_url: String,
    query_server_url: String,
    hint_conn: Option<Box<dyn PirTransport>>,
    /// Secondary hint-server WebSocket, used to split parallel sibling
    /// hint downloads (INDEX-tree levels on primary, CHUNK-tree levels
    /// on secondary) across two sockets. Same rationale as
    /// [`query_conn_secondary`] — the bandwidth-delay-product cap on
    /// one TCP stream is the bottleneck for the ~26 MB of sibling
    /// hints, so two streams cut wall time substantially.
    ///
    /// `None` means single-socket fallback (identical behaviour to
    /// pre-pool code). Set when `HARMONY_HINT_POOL_SIZE` env var is
    /// 2 (default) or higher.
    hint_conn_secondary: Option<Box<dyn PirTransport>>,
    query_conn: Option<Box<dyn PirTransport>>,
    /// Secondary query-server WebSocket, used to split parallel rounds
    /// (CHUNK h=0/h=1 pair, INDEX/CHUNK Merkle sub-trees) across two
    /// sockets so we can saturate the path's bandwidth-delay product
    /// instead of being capped by a single-TCP-stream limit. `None`
    /// means single-socket fallback (identical behaviour to pre-pool
    /// code).
    ///
    /// Opened in parallel with [`query_conn`] at [`connect`] time when
    /// the `HARMONY_QUERY_POOL_SIZE` env var is set to 2 (default) or
    /// higher. Pool size 1 leaves this `None` and all rounds run on
    /// `query_conn` alone.
    ///
    /// Privacy invariants are preserved per socket — the wire shape of
    /// each round is unchanged. The server can't distinguish a
    /// two-socket client from two single-socket clients running back
    /// to back: each socket is its own connection and gets its own
    /// stateless K-padded batch queries.
    query_conn_secondary: Option<Box<dyn PirTransport>>,
    catalog: Option<DatabaseCatalog>,
    prp_backend: u8,
    master_prp_key: [u8; 16],
    /// Groups are initialised lazily per db_id. When the id changes we
    /// drop existing groups and build a fresh set (hints are keyed on
    /// the db's cuckoo table).
    loaded_db_id: Option<u8>,
    index_groups: HashMap<u8, HarmonyGroup>,
    chunk_groups: HashMap<u8, HarmonyGroup>,
    /// Bucket-Merkle INDEX sibling groups, keyed by `(sib_level, local_group)`.
    /// Each level has exactly `index_k` groups; hints are fetched once per
    /// (db_id, level) and consumed during Merkle verification.
    index_sib_groups: HashMap<(usize, u8), HarmonyGroup>,
    /// Bucket-Merkle CHUNK sibling groups, keyed by `(sib_level, local_group)`.
    chunk_sib_groups: HashMap<(usize, u8), HarmonyGroup>,
    /// `Some(db_id)` when sibling groups + hints are loaded and fresh; reset
    /// whenever `loaded_db_id` changes or `master_prp_key`/`prp_backend`
    /// changes (via `invalidate_groups`).
    sibling_hints_loaded: Option<u8>,
    /// On-disk cache directory for hint blobs. `None` (the default) means
    /// "no filesystem cache" — `save_hints_bytes` / `load_hints_bytes`
    /// still work as explicit byte-level APIs, but nothing is read or
    /// written automatically. Set via
    /// [`HarmonyClient::with_hint_cache_dir`] or
    /// [`HarmonyClient::set_hint_cache_dir`].
    ///
    /// Session 5 will thread a wasm32-side IndexedDB wrapper through
    /// the same save/load byte APIs, so the filesystem path here only
    /// activates on native targets.
    hint_cache_dir: Option<PathBuf>,
    /// Optional observer invoked on every `ConnectionState` transition.
    /// Mirrors the DPF client's listener slot (see `dpf.rs` for the
    /// rationale behind `Arc<dyn StateListener>` over `Box`): sharing
    /// one sink between DPF + Harmony clients lets the WASM bindings
    /// plumb a single `Rc<RefCell<js_sys::Function>>` through both.
    state_listener: Option<Arc<dyn StateListener>>,
    /// Optional metrics recorder. When installed, fires
    /// `on_connect` / `on_disconnect` lifecycle events and
    /// `on_query_start` / `on_query_end` per-batch callbacks from the
    /// client layer, plus per-frame `on_bytes_sent` /
    /// `on_bytes_received` from the hint/query transports (wired on
    /// connect via `set_metrics_recorder`). Both transports are
    /// labelled `"harmony"` — a recorder can't tell which socket a
    /// byte count came from, but can split queries-vs-hints by
    /// observing the URL on `on_connect`.
    metrics_recorder: Option<Arc<dyn PirMetrics>>,
    /// Optional leakage recorder. When installed, every transport-level
    /// roundtrip (hint refresh, INDEX query, CHUNK query, Merkle
    /// tree-tops, Merkle sibling pass) emits a structured
    /// [`RoundProfile`] with the wire-observable shape. `server_id` is
    /// 0 for the query server and 1 for the hint server. Independent
    /// of `metrics_recorder` — install neither, either, or both.
    leakage_recorder: Option<Arc<dyn LeakageRecorder>>,
    verified_roots: VerifiedRootState,
    verified_tree_tops: HashMap<u8, Vec<TreeTop>>,
    /// If true, use V2 hint protocol: server generates the PRP key.
    /// Default: true for new clients. Set to false for V1 fallback
    /// (client generates key, sends in request) on ungated legacy sessions.
    /// A granted Payment V1 V2Full operation always follows its exact wire
    /// contract and does not consult this compatibility preference.
    use_v2_protocol: bool,
}

// ─── Kani harnesses ─────────────────────────────────────────────────────────
//
// Bounded model checking for the CHUNK Round-Presence Symmetry
// invariant (CLAUDE.md). The invariant says every HarmonyPIR INDEX
// query — found, not-found, or whale — emits a K_CHUNK-padded CHUNK
// PIR round on the wire. The structural witness lives in
// `classify_chunk_groups`: its result length is `k_chunk` regardless
// of how many real queries were passed in, and when no real queries
// are passed every entry is `Dummy`.
//
// `run_chunk_round_pair` consumes the role list directly, so verifying
// `classify_chunk_groups` lifts to verifying the wire-batch length:
// the dispatch loop pushes one `BatchItem` per role, so the resulting
// `Vec<BatchItem>` has exactly `k_chunk` elements. Every group either
// goes through `build_request` (real) or `build_synthetic_dummy`
// (dummy) — both produce T-1 sorted indices per the existing
// "HarmonyPIR Per-Group Request-Count Symmetry" invariant — so the
// wire bytes are shape-uniform.
//
// The harnesses live behind `#[cfg(kani)]` so a normal build doesn't
// compile them. Run with `cargo kani -p pir-sdk-client`.

#[cfg(kani)]
mod kani_harnesses {
    use super::*;

    /// **P1** — round-count uniformity. For any `(real_queries,
    /// k_chunk)`, the role list has length exactly `k_chunk`. The
    /// caller's dispatch loop in `run_chunk_round_pair` pushes one
    /// `BatchItem` per role, so the wire batch length equals
    /// `k_chunk` regardless of `real_queries.len()`. This is the
    /// structural witness that found / not-found / whale queries
    /// all emit `k_chunk` per-group sub-queries on the wire.
    ///
    /// Bound: `k_chunk ∈ {1, 2, 3, 4}`, `real_queries.len() ∈
    /// {0, 1, 2}` with each `(group_id < k_chunk)`. Bounds are
    /// small to keep CBMC tractable; the property is a length
    /// equality so the bound is illustrative — the proof
    /// generalises by symbolic execution on each concrete `k_chunk`.
    #[kani::proof]
    #[kani::unwind(5)]
    fn classify_chunk_groups_emits_k_chunk_entries() {
        let k_chunk: u8 = kani::any();
        kani::assume(k_chunk >= 1 && k_chunk <= 4);
        let n_real: usize = kani::any();
        kani::assume(n_real <= 2);
        let mut real_queries: Vec<(u32, u8)> = Vec::with_capacity(n_real);
        for _ in 0..n_real {
            let cid: u32 = kani::any();
            let group: u8 = kani::any();
            // Restrict group_ids to the valid range so we exercise
            // the in-range branch (out-of-range is silently dropped
            // — covered separately if a regression invents a panic).
            kani::assume(group < k_chunk);
            real_queries.push((cid, group));
        }

        let roles = classify_chunk_groups(&real_queries, k_chunk);

        assert_eq!(
            roles.len(),
            k_chunk as usize,
            "CHUNK Round-Presence Symmetry P1: role list length must \
             equal k_chunk so the dispatch loop emits exactly k_chunk \
             per-group sub-queries on the wire",
        );
    }

    /// **P2** — wire indistinguishability of the all-dummy round.
    /// When `real_queries` is empty (the not-found / whale path), the
    /// role list is `[Dummy, Dummy, …, Dummy]` of length `k_chunk`.
    /// `run_chunk_round_pair` then routes every group through
    /// `HarmonyGroup::build_synthetic_dummy`, which produces a
    /// shape-identical payload to a real `build_request` (per the
    /// existing per-group request-count symmetry). The result: a
    /// CHUNK round driven purely by dummies is byte-shape-identical
    /// to a CHUNK round with one or more real queries.
    #[kani::proof]
    #[kani::unwind(5)]
    fn classify_chunk_groups_all_dummy_when_no_real_queries() {
        let k_chunk: u8 = kani::any();
        kani::assume(k_chunk >= 1 && k_chunk <= 4);

        let roles = classify_chunk_groups(&[], k_chunk);

        assert_eq!(roles.len(), k_chunk as usize);
        for g in 0..k_chunk as usize {
            assert!(
                matches!(roles[g], ChunkGroupRole::Dummy),
                "CHUNK Round-Presence Symmetry P2: empty real_queries \
                 must produce all-Dummy roles so every group routes \
                 through build_synthetic_dummy on the wire",
            );
        }
    }

    /// Negative: a real query at a specific group must mark exactly
    /// that group as `Real`, leaving every other group as `Dummy`.
    /// Catches a hypothetical regression that mis-routes the role
    /// (e.g. off-by-one on the group index, or marking too many
    /// groups Real and shrinking the dummy padding).
    #[kani::proof]
    #[kani::unwind(5)]
    fn classify_chunk_groups_marks_only_specified_group_real() {
        let k_chunk: u8 = kani::any();
        kani::assume(k_chunk >= 1 && k_chunk <= 4);
        let target_group: u8 = kani::any();
        kani::assume(target_group < k_chunk);
        let cid: u32 = kani::any();

        let roles = classify_chunk_groups(&[(cid, target_group)], k_chunk);

        assert_eq!(roles.len(), k_chunk as usize);
        for g in 0..k_chunk as usize {
            if g == target_group as usize {
                assert!(
                    matches!(roles[g], ChunkGroupRole::Real(c) if c == cid),
                    "target group must carry the supplied chunk_id",
                );
            } else {
                assert!(
                    matches!(roles[g], ChunkGroupRole::Dummy),
                    "non-target groups must remain Dummy",
                );
            }
        }
    }

    /// Out-of-range `group_id`s are silently dropped — same
    /// observable behaviour as the pre-refactor
    /// `for g in 0..k_chunk` loop, which never queried groups
    /// `>= k_chunk` even if they were in the HashMap. Captured here
    /// so a future regression that panics or grows the role list
    /// fires loudly.
    #[kani::proof]
    #[kani::unwind(5)]
    fn classify_chunk_groups_drops_out_of_range_groups() {
        let k_chunk: u8 = kani::any();
        kani::assume(k_chunk >= 1 && k_chunk <= 3);
        let bad_group: u8 = kani::any();
        kani::assume(bad_group >= k_chunk);
        let cid: u32 = kani::any();

        let roles = classify_chunk_groups(&[(cid, bad_group)], k_chunk);

        assert_eq!(roles.len(), k_chunk as usize);
        for g in 0..k_chunk as usize {
            assert!(
                matches!(roles[g], ChunkGroupRole::Dummy),
                "out-of-range group_id must not poison any in-range \
                 role — every group stays Dummy",
            );
        }
    }
}

#[cfg(test)]
mod tests;
