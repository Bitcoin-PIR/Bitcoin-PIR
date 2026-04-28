//! Leakage profile capture for differential testing.
//!
//! This module is the foundation of the leakage-verification work
//! (see `PLAN_LEAKAGE_VERIFICATION.md`). It defines a
//! [`LeakageRecorder`] trait — analogous to [`PirMetrics`] but
//! orthogonal — that PIR clients invoke at every wire-observable
//! roundtrip with structured metadata about what the server can see.
//!
//! The output is a [`LeakageProfile`]: an ordered list of
//! [`RoundProfile`]s, one per (logical round × server). Tests assert:
//!
//! 1. **Per-message invariants** — every INDEX round has K groups, every
//!    INDEX Merkle round has `INDEX_CUCKOO_NUM_HASHES = 2` items per
//!    query, etc. (the "CRITICAL SECURITY REQUIREMENTS" in
//!    `CLAUDE.md`).
//! 2. **Simulator property** — for queries `q1`, `q2` with `L(q1) =
//!    L(q2)` (same admitted leakage), the resulting `LeakageProfile`s
//!    are structurally equal. This is the operational form of the
//!    statement "the wire transcript is a function only of the
//!    admitted leakage".
//!
//! [`PirMetrics`]: crate::PirMetrics
//!
//! # Why a separate trait from `PirMetrics`?
//!
//! `PirMetrics` is for production observability — it counts bytes,
//! latency, query lifecycle. Recorders shipped with apps don't care
//! about per-round structural details and shouldn't pay the cost of
//! capturing them.
//!
//! [`LeakageRecorder`] is for tests and audits — it captures the
//! per-round shape needed to characterise leakage. Recorders here
//! buffer events for offline inspection rather than aggregating into
//! counters.
//!
//! Both traits coexist on the same client: install whichever (or
//! both) you need. The default impls are no-ops, so when no recorder
//! is installed the entire path is optimised out.

use std::sync::Mutex;

// ─── RoundKind ──────────────────────────────────────────────────────────────

/// Categorisation of a single logical round in the PIR protocol.
///
/// The kind determines the semantics of [`RoundProfile::items`] — see
/// the field doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind", rename_all = "snake_case"))]
pub enum RoundKind {
    /// PIR INDEX query — one round per script-hash query, per server.
    /// `items` is per-group (length == K).
    Index,
    /// PIR CHUNK query — emitted only for queries that resolved to a
    /// match (reveals found vs not-found, an admitted leak). One round
    /// per CHUNK batch, per server. `items` is per-group (length ==
    /// K_CHUNK).
    Chunk,
    /// INDEX-tree Merkle sibling fetch at the given tree level.
    /// `items` is per-query (length == batch size). Invariant: every
    /// query contributes exactly `INDEX_CUCKOO_NUM_HASHES = 2` items.
    IndexMerkleSiblings { level: u8 },
    /// CHUNK-tree Merkle sibling fetch at the given tree level.
    /// `items` is per-query (length == batch size). Item count
    /// varies with UTXO count (admitted leak).
    ChunkMerkleSiblings { level: u8 },
    /// HarmonyPIR hint refresh — sent to the hint server when a
    /// per-group hint is exhausted. `items` is empty.
    HarmonyHintRefresh,
    /// OnionPIR FHE-key registration — client uploads Galois + GSW
    /// keys to the server before its first query against a given
    /// `db_id`. Issued at most once per (session × db_id) and the
    /// server responds with a single ACK byte. `items` is empty;
    /// `request_bytes` is dominated by the FHE key sizes which are
    /// public parameters (no admitted-leak privacy concern).
    OnionKeyRegister,
    /// Database catalog / info fetch. Issued once per session before
    /// any real query, so admitted to leak (every client does it).
    /// `items` is empty.
    Info,
    /// Merkle tree-tops fetch — public part of the Merkle tree, every
    /// client fetches the same bytes regardless of query. Admitted to
    /// leak. `items` is empty.
    MerkleTreeTops,
}

// ─── RoundProfile ───────────────────────────────────────────────────────────

/// Wire-observable shape of a single (logical round × server) pair.
///
/// One `RoundProfile` is emitted per transport-level roundtrip: a
/// single-server backend (OnionPIR) emits one per logical round, a
/// two-server backend (DPF, HarmonyPIR query+hint) emits two.
///
/// Equality is structural — two profiles compare equal iff every
/// field matches. The simulator-property tests rely on this: two
/// queries with the same admitted leakage should produce identical
/// `RoundProfile` sequences.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RoundProfile {
    /// Round category. Determines the semantics of [`Self::items`].
    ///
    /// Serialized via `#[serde(flatten)]` so the enum's `kind` tag
    /// merges into the struct's top-level keys (e.g.
    /// `{"kind": "index", ...}` rather than the nested
    /// `{"kind": {"kind": "index"}, ...}`). This keeps the JSON shape
    /// portable for the TypeScript cross-language diff (Phase 2.3) and
    /// matches the on-the-wire convention used by other tagged-enum
    /// payloads in the codebase.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub kind: RoundKind,
    /// Server identifier within the backend.
    ///
    /// - Single-server backends (Onion): always 0.
    /// - DPF: 0 for server0, 1 for server1.
    /// - HarmonyPIR: 0 for query server, 1 for hint server.
    ///
    /// Each server only sees its own messages, so a per-server
    /// breakdown is what the leakage threat model cares about.
    pub server_id: u8,
    /// Database identifier the round targets, if any. Catalog/info
    /// rounds carry `None`; PIR rounds always carry `Some`.
    pub db_id: Option<u8>,
    /// Wire payload size of the request, in bytes (excluding the
    /// 4-byte length prefix the framing layer prepends).
    pub request_bytes: u64,
    /// Wire payload size of the response, in bytes (excluding the
    /// 4-byte length prefix).
    pub response_bytes: u64,
    /// Item counts at the round's natural granularity. Semantics
    /// depend on [`Self::kind`]:
    ///
    /// - [`RoundKind::Index`] / [`RoundKind::Chunk`]: **per-group** —
    ///   length is K (INDEX) or K_CHUNK (CHUNK), and `items[g]` is the
    ///   number of cuckoo-hash items packed into group `g`. Per-message
    ///   invariant: `items.len() == K` and (for INDEX) every entry
    ///   equals `INDEX_CUCKOO_NUM_HASHES = 2`.
    /// - [`RoundKind::IndexMerkleSiblings`] /
    ///   [`RoundKind::ChunkMerkleSiblings`]: **per-query** — length is
    ///   the batch size, and `items[q]` is the number of sibling
    ///   fetches query `q` contributes at this level. Per-message
    ///   invariant: for INDEX, every entry equals
    ///   `INDEX_CUCKOO_NUM_HASHES = 2`.
    /// - [`RoundKind::HarmonyHintRefresh`] / [`RoundKind::Info`] /
    ///   [`RoundKind::MerkleTreeTops`] / [`RoundKind::OnionKeyRegister`]:
    ///   empty (or one entry per response frame for hint refresh).
    pub items: Vec<u32>,
}

impl RoundProfile {
    /// True if [`Self::items`] has exactly `expected_len` entries, each
    /// equal to `expected_value`. The standard per-message invariant
    /// shape: K-padded length plus uniform per-group item count
    /// (INDEX = 2 for DPF/Onion, T-1 for Harmony, etc.).
    pub fn items_uniform(&self, expected_len: usize, expected_value: u32) -> bool {
        self.items.len() == expected_len
            && self.items.iter().all(|&v| v == expected_value)
    }

    /// True if `kind` matches up to its enum variant, ignoring any
    /// inner fields like `level` for the Merkle variants. Useful for
    /// filtering profile rounds by category without caring about which
    /// Merkle level a sibling round targeted.
    pub fn kind_matches(&self, other: &RoundKind) -> bool {
        std::mem::discriminant(&self.kind) == std::mem::discriminant(other)
    }
}

// ─── LeakageProfile ─────────────────────────────────────────────────────────

/// Ordered sequence of [`RoundProfile`]s for a complete query (or test
/// run). Order matches emission order, which is the order the server
/// observes the rounds on the wire.
///
/// Two profiles compare equal iff their `rounds` Vecs are
/// element-wise equal. This is the structural equivalence relation
/// the simulator-property tests use.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LeakageProfile {
    /// Backend tag (`"dpf"`, `"harmony"`, `"onion"`).
    pub backend: String,
    /// Rounds in emission order.
    pub rounds: Vec<RoundProfile>,
}

impl LeakageProfile {
    /// New empty profile for the given backend.
    pub fn new(backend: impl Into<String>) -> Self {
        Self { backend: backend.into(), rounds: Vec::new() }
    }

    /// Iterator over rounds whose `kind` matches `kind` up to enum
    /// variant (ignoring any inner fields). Use to filter all
    /// `IndexMerkleSiblings { level: _ }` rounds in one call without
    /// matching a specific level.
    pub fn rounds_of_kind<'a>(
        &'a self,
        kind: &'a RoundKind,
    ) -> impl Iterator<Item = &'a RoundProfile> + 'a {
        self.rounds.iter().filter(move |r| r.kind_matches(kind))
    }

    /// Number of rounds whose `kind` matches `kind` up to enum variant.
    pub fn count_of_kind(&self, kind: &RoundKind) -> usize {
        self.rounds_of_kind(kind).count()
    }
}

// ─── Trait ──────────────────────────────────────────────────────────────────

/// Observer trait for per-round structural events.
///
/// Default callback is a no-op so installing no recorder costs
/// nothing. Implementations buffer or aggregate the events as needed.
///
/// `Send + Sync` because PIR clients are `Send + Sync` and recorders
/// are held behind `Arc<dyn LeakageRecorder>` across `.await` points.
pub trait LeakageRecorder: Send + Sync {
    /// Fired once per (logical round × server) — i.e. per
    /// transport-level roundtrip — with the round's wire-observable
    /// shape.
    ///
    /// `backend` is the same `&'static str` tag used by [`PirMetrics`]
    /// (`"dpf"`, `"harmony"`, `"onion"`) so a single process running
    /// multiple backends can demultiplex.
    ///
    /// [`PirMetrics`]: crate::PirMetrics
    fn record_round(&self, _backend: &'static str, _round: RoundProfile) {}
}

// ─── NoopLeakageRecorder ────────────────────────────────────────────────────

/// No-op leakage recorder. Functionally equivalent to not installing
/// one — the only reason to use this is API symmetry (e.g. a function
/// requires `Arc<dyn LeakageRecorder>` and you don't actually want to
/// record anything).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopLeakageRecorder;

impl LeakageRecorder for NoopLeakageRecorder {}

// ─── BufferingLeakageRecorder ───────────────────────────────────────────────

/// Recorder that buffers every emitted [`RoundProfile`] in a `Mutex`
/// behind a `Vec`. Designed for tests: install one, run a query, call
/// [`Self::take_profile`] (or [`Self::snapshot`]) to inspect.
///
/// This is the default test recorder. For high-throughput recording
/// you'd want a lock-free queue; for the typical test workload (one
/// query batch, hundreds of rounds at most) a `Mutex<Vec>` is fine
/// and keeps the implementation trivially correct.
#[derive(Debug, Default)]
pub struct BufferingLeakageRecorder {
    rounds: Mutex<Vec<RoundProfile>>,
}

impl BufferingLeakageRecorder {
    /// Create a new empty recorder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the current buffer (clone). The recorder retains its
    /// state — repeated snapshots see additional rounds appended.
    pub fn snapshot(&self) -> Vec<RoundProfile> {
        self.rounds.lock().expect("leakage recorder mutex poisoned").clone()
    }

    /// Drain the buffer into a [`LeakageProfile`] tagged with the
    /// given backend. After this call the recorder is empty — useful
    /// when running multiple queries through the same recorder and
    /// comparing per-query profiles.
    pub fn take_profile(&self, backend: impl Into<String>) -> LeakageProfile {
        let mut guard = self.rounds.lock().expect("leakage recorder mutex poisoned");
        let rounds = std::mem::take(&mut *guard);
        LeakageProfile { backend: backend.into(), rounds }
    }

    /// Drop every buffered round without producing a profile.
    pub fn clear(&self) {
        self.rounds.lock().expect("leakage recorder mutex poisoned").clear();
    }

    /// Number of rounds currently buffered.
    pub fn len(&self) -> usize {
        self.rounds.lock().expect("leakage recorder mutex poisoned").len()
    }

    /// `true` iff no rounds have been recorded since the last
    /// [`Self::take_profile`] / [`Self::clear`].
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl LeakageRecorder for BufferingLeakageRecorder {
    fn record_round(&self, _backend: &'static str, round: RoundProfile) {
        self.rounds
            .lock()
            .expect("leakage recorder mutex poisoned")
            .push(round);
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn round_index(server_id: u8, db_id: u8, k: usize, items_per_group: u32) -> RoundProfile {
        RoundProfile {
            kind: RoundKind::Index,
            server_id,
            db_id: Some(db_id),
            request_bytes: 0,
            response_bytes: 0,
            items: vec![items_per_group; k],
        }
    }

    fn round_index_merkle(level: u8, batch: usize, per_query: u32) -> RoundProfile {
        RoundProfile {
            kind: RoundKind::IndexMerkleSiblings { level },
            server_id: 0,
            db_id: Some(0),
            request_bytes: 0,
            response_bytes: 0,
            items: vec![per_query; batch],
        }
    }

    #[test]
    fn noop_recorder_is_silent() {
        let r = NoopLeakageRecorder;
        r.record_round("dpf", round_index(0, 0, 75, 2));
        // Nothing to assert — the point of NoopLeakageRecorder is that
        // it compiles, doesn't panic, and discards the round.
    }

    #[test]
    fn buffering_recorder_starts_empty() {
        let r = BufferingLeakageRecorder::new();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
        assert_eq!(r.snapshot(), Vec::<RoundProfile>::new());
    }

    #[test]
    fn buffering_recorder_appends_in_emission_order() {
        let r = BufferingLeakageRecorder::new();
        r.record_round("dpf", round_index(0, 0, 75, 2));
        r.record_round("dpf", round_index(1, 0, 75, 2));
        r.record_round("dpf", round_index_merkle(0, 1, 2));

        assert_eq!(r.len(), 3);
        let snap = r.snapshot();
        assert_eq!(snap[0].server_id, 0);
        assert_eq!(snap[1].server_id, 1);
        assert!(matches!(snap[2].kind, RoundKind::IndexMerkleSiblings { level: 0 }));
    }

    #[test]
    fn take_profile_drains_buffer() {
        let r = BufferingLeakageRecorder::new();
        r.record_round("dpf", round_index(0, 0, 75, 2));
        r.record_round("dpf", round_index(1, 0, 75, 2));

        let p = r.take_profile("dpf");
        assert_eq!(p.backend, "dpf");
        assert_eq!(p.rounds.len(), 2);
        // Buffer is now empty — the recorder is reusable for the next query.
        assert!(r.is_empty());
    }

    #[test]
    fn buffering_recorder_clear() {
        let r = BufferingLeakageRecorder::new();
        r.record_round("dpf", round_index(0, 0, 75, 2));
        assert_eq!(r.len(), 1);
        r.clear();
        assert!(r.is_empty());
    }

    /// The simulator-property test pattern: two queries with the same
    /// admitted leakage produce equal `LeakageProfile`s.
    #[test]
    fn structural_equality_of_two_identical_profiles() {
        let r1 = BufferingLeakageRecorder::new();
        let r2 = BufferingLeakageRecorder::new();
        // Imagine these are two different not-found queries — same
        // admitted leakage (no CHUNK round), identical INDEX +
        // INDEX-Merkle shape.
        for r in [&r1, &r2] {
            r.record_round("dpf", round_index(0, 0, 75, 2));
            r.record_round("dpf", round_index(1, 0, 75, 2));
            r.record_round("dpf", round_index_merkle(0, 1, 2));
        }
        assert_eq!(r1.take_profile("dpf"), r2.take_profile("dpf"));
    }

    /// Differing item counts at the per-message level produce unequal
    /// profiles — what would happen if one client's INDEX-Merkle
    /// emitted only 1 item per query (the leak the 2026 invariant
    /// closed).
    #[test]
    fn structural_inequality_when_index_merkle_count_drifts() {
        let good = BufferingLeakageRecorder::new();
        let bad = BufferingLeakageRecorder::new();
        good.record_round("dpf", round_index_merkle(0, 1, 2));
        bad.record_round("dpf", round_index_merkle(0, 1, 1));
        assert_ne!(good.take_profile("dpf"), bad.take_profile("dpf"));
    }

    /// Recorder works through `Arc<dyn LeakageRecorder>` — the actual
    /// usage shape, since clients hold trait objects.
    #[test]
    fn recorder_through_dyn_trait_object() {
        let r = Arc::new(BufferingLeakageRecorder::new());
        let dyn_r: Arc<dyn LeakageRecorder> = r.clone();
        dyn_r.record_round("harmony", round_index(0, 1, 75, 2));
        assert_eq!(r.len(), 1);
    }

    /// Multiple threads recording concurrently — the `Mutex<Vec>` is
    /// trivially correct but we verify the count.
    #[test]
    fn buffering_recorder_is_thread_safe() {
        use std::thread;
        let r = Arc::new(BufferingLeakageRecorder::new());
        let threads: Vec<_> = (0..8)
            .map(|tid| {
                let r = r.clone();
                thread::spawn(move || {
                    for _ in 0..100 {
                        r.record_round("dpf", round_index(tid as u8 % 2, 0, 75, 2));
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(r.len(), 800);
    }

    #[test]
    fn items_uniform_checks_length_and_value() {
        let r = round_index(0, 0, 75, 2);
        assert!(r.items_uniform(75, 2));
        // Wrong length.
        assert!(!r.items_uniform(74, 2));
        // Wrong value.
        assert!(!r.items_uniform(75, 3));
        // Empty profile vacuously satisfies length=0 / any value, but the
        // helper still requires the length match.
        let empty = RoundProfile {
            kind: RoundKind::Info,
            server_id: 0,
            db_id: None,
            request_bytes: 0,
            response_bytes: 0,
            items: Vec::new(),
        };
        assert!(empty.items_uniform(0, 99));
        assert!(!empty.items_uniform(1, 0));
    }

    #[test]
    fn items_uniform_rejects_one_outlier() {
        let mut r = round_index(0, 0, 75, 2);
        r.items[40] = 1;
        assert!(!r.items_uniform(75, 2));
    }

    #[test]
    fn kind_matches_ignores_inner_level() {
        let r = round_index_merkle(7, 1, 2);
        // Same variant, different level — should still match.
        assert!(r.kind_matches(&RoundKind::IndexMerkleSiblings { level: 0 }));
        // Different variant — should not match.
        assert!(!r.kind_matches(&RoundKind::ChunkMerkleSiblings { level: 7 }));
        assert!(!r.kind_matches(&RoundKind::Index));
    }

    #[test]
    fn rounds_of_kind_filters_across_levels() {
        let mut p = LeakageProfile::new("dpf");
        p.rounds.push(round_index(0, 0, 75, 2));
        p.rounds.push(round_index_merkle(0, 1, 2));
        p.rounds.push(round_index_merkle(1, 1, 2));
        p.rounds.push(round_index_merkle(2, 1, 2));

        let merkle_rounds: Vec<_> = p
            .rounds_of_kind(&RoundKind::IndexMerkleSiblings { level: 0 })
            .collect();
        // All three IndexMerkleSiblings rounds match, regardless of level.
        assert_eq!(merkle_rounds.len(), 3);
        assert_eq!(p.count_of_kind(&RoundKind::IndexMerkleSiblings { level: 0 }), 3);
        // Index variant is distinct.
        assert_eq!(p.count_of_kind(&RoundKind::Index), 1);
        // Variants not present in the profile return 0.
        assert_eq!(p.count_of_kind(&RoundKind::Chunk), 0);
        assert_eq!(p.count_of_kind(&RoundKind::OnionKeyRegister), 0);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn round_profile_json_roundtrips() {
        let r = round_index_merkle(0, 3, 2);
        let s = serde_json::to_string(&r).unwrap();
        let r2: RoundProfile = serde_json::from_str(&s).unwrap();
        assert_eq!(r, r2);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn leakage_profile_json_roundtrips() {
        let mut p = LeakageProfile::new("onion");
        p.rounds.push(round_index(0, 0, 75, 2));
        p.rounds.push(round_index_merkle(0, 1, 2));

        let s = serde_json::to_string(&p).unwrap();
        let p2: LeakageProfile = serde_json::from_str(&s).unwrap();
        assert_eq!(p, p2);
    }

    /// Pin the exact JSON shape so the TypeScript port (Phase 2.3) can
    /// match it. If this test fails, update `web/src/leakage.ts` and
    /// the cross-language diff fixture together.
    #[cfg(feature = "serde")]
    #[test]
    fn leakage_profile_json_shape_is_pinned() {
        let r1 = RoundProfile {
            kind: RoundKind::Index,
            server_id: 0,
            db_id: Some(3),
            request_bytes: 1024,
            response_bytes: 4096,
            items: vec![2, 2],
        };
        let r2 = RoundProfile {
            kind: RoundKind::IndexMerkleSiblings { level: 7 },
            server_id: 0,
            db_id: Some(3),
            request_bytes: 100,
            response_bytes: 200,
            items: vec![1, 1],
        };
        let r3 = RoundProfile {
            kind: RoundKind::Info,
            server_id: 0,
            db_id: None,
            request_bytes: 5,
            response_bytes: 23,
            items: vec![],
        };

        let s1 = serde_json::to_string(&r1).unwrap();
        let s2 = serde_json::to_string(&r2).unwrap();
        let s3 = serde_json::to_string(&r3).unwrap();

        // Goal of the pin: TypeScript can produce these exact strings.
        // `#[serde(flatten)]` on the `kind` field merges the enum's
        // tag into the struct keys; parametric variants like
        // `IndexMerkleSiblings { level }` add a sibling `level` key.
        assert_eq!(
            s1,
            r#"{"kind":"index","server_id":0,"db_id":3,"request_bytes":1024,"response_bytes":4096,"items":[2,2]}"#,
        );
        assert_eq!(
            s2,
            r#"{"kind":"index_merkle_siblings","level":7,"server_id":0,"db_id":3,"request_bytes":100,"response_bytes":200,"items":[1,1]}"#,
        );
        assert_eq!(
            s3,
            r#"{"kind":"info","server_id":0,"db_id":null,"request_bytes":5,"response_bytes":23,"items":[]}"#,
        );
    }
}
