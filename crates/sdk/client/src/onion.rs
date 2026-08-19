//! OnionPIR client implementation.
//!
//! OnionPIR is a single-server PIR protocol based on fully homomorphic
//! encryption (BFV, Microsoft SEAL). The client encrypts its query under
//! its own secret key; the server operates on the ciphertexts and returns
//! an encrypted response that only the client can decrypt.
//!
//! ## Feature gating
//!
//! The real implementation is gated behind the `onion` cargo feature because
//! the upstream [`onionpir`](https://github.com/Bitcoin-PIR/OnionPIRv2-fork)
//! crate has a heavy native build: CMake + the Microsoft SEAL C++ library
//! (pulled in as a submodule) and Homebrew GCC on macOS. Most SDK consumers
//! don't need OnionPIR and shouldn't pay that cost.
//!
//! ```toml
//! [dependencies]
//! pir-sdk-client = { version = "0.1", features = ["onion"] }
//! ```
//!
//! Without the feature, `OnionClient` compiles but every query logs a
//! warning and returns `None` — so the rest of the SDK (DPF, HarmonyPIR)
//! stays usable on systems without a C++ toolchain.
//!
//! ## Protocol flow
//!
//! 1. Fetch JSON server info (`0x03`) — gives per-database OnionPIR params
//!    (index_bins, chunk_bins, index_k, chunk_k, tag_seed, total_packed,
//!    index_slots_per_bin, index_slot_size).
//! 2. Create a per-client `onionpir::Client`, generate Galois + GSW keys,
//!    export the secret key.
//! 3. Send `REQ_REGISTER_KEYS (0x50)` once per database — await
//!    `RESP_KEYS_ACK (0x50)`.
//! 4. For each INDEX round: send `REQ_ONIONPIR_INDEX_QUERY (0x51)` with K
//!    encrypted queries (2 × K because INDEX uses 2-hash cuckoo — one query
//!    per hash position per group). Decrypt, scan the 256-slot × 15-byte
//!    bin for a matching tag.
//! 5. For each CHUNK round: build a 6-hash cuckoo table client-side to find
//!    each entry's exact bin, send `REQ_ONIONPIR_CHUNK_QUERY (0x52)` with
//!    K_CHUNK encrypted queries. Decrypt PACKED_ENTRY_SIZE=3840 bytes per
//!    entry.
//! 6. Assemble entries into raw UTXO bytes and decode with varint.
//!
//! ## Privacy-critical padding
//!
//! Every INDEX round sends **exactly K queries** (padded with random-bin
//! dummies), every CHUNK round sends **exactly K_CHUNK queries**. This is
//! mandatory per `CLAUDE.md` and is implemented identically to the DPF
//! client — never "optimize" it away.

#[cfg(not(target_arch = "wasm32"))]
use crate::connection::WsConnection;
use crate::db_proof::{
    fetch_database_proof, fetch_database_proof_v2, verify_database_proof, verify_database_proof_v2,
    DatabaseProofPolicy, VerifiedDatabaseRoots,
};
#[cfg(feature = "onion")]
use crate::protocol::reject_error_response;
use crate::protocol::{decode_catalog, encode_request, REQ_GET_DB_CATALOG, RESP_DB_CATALOG};
use crate::service::{
    authorize_bat_v2_redemption_v2, dangerous_unpaired_authorize_service_operation_v1,
    fetch_retained_bat_v2_policy_v2, fetch_verified_service_policy_v1, request_pow_challenge_v1,
    verify_service_policy_session_v1 as verify_policy_transport_session_v1,
    AcceptedRetainedBatV2PolicyV2, AcceptedServicePolicyV1, BatV2AdmissionOutcomeV2,
    ServicePolicyCheckpointV1, VerifiedBatV2RedemptionV2,
};
use crate::transport::PirTransport;
use crate::verified_roots::{RootPolicy, VerifiedRootState};
use async_trait::async_trait;
use ed25519_dalek::VerifyingKey;
use pir_sdk::{
    compute_sync_plan, merge_delta_batch, DatabaseCatalog, DatabaseInfo, DatabaseKind, Instant,
    LeakageRecorder, PirBackendType, PirClient, PirError, PirMetrics, PirResult, QueryResult,
    RoundKind, RoundProfile, ScriptHash, SyncPlan, SyncResult, SyncStep,
};
use pir_service_protocol::{AuthorizationProofV1, OperationStartV1, ProviderId};
use std::sync::Arc;

// ─── CHUNK Round-Presence Symmetry: per-slot classifier ────────────────────
//
// The classifier is feature-flag-free so its Kani harnesses can run
// in the default `cargo kani -p pir-sdk-client` invocation (the
// `onion` feature pulls in SEAL + onionpir, which Kani can't model).
//
// `ChunkSlotInput` is a small projection of the relevant fields of
// `IndexResult` (full struct gated on `feature = "onion"`); the
// caller projects `Option<&IndexResult>` onto this shape before
// invoking `classify_chunk_slots`.

/// Per-slot input to the OnionPIR CHUNK fetch-list classifier.
///
/// `num_entries == 0` represents both the not-found case (`None`
/// from the INDEX scan) and the whale case (`Some(ir)` with
/// `ir.num_entries == 0`). Both must produce a synthetic dummy
/// entry on the wire — the classifier collapses them into the
/// same `AppendDummy` action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(kani)]
pub(crate) struct ChunkSlotInput {
    pub entry_id: u32,
    pub num_entries: u8,
}

/// Per-slot action emitted by the classifier. The OnionPIR CHUNK
/// fetcher dispatches on this enum: `AppendReal` adds `num_entries`
/// real entry_ids to the unique-fetch list; `AppendDummy` injects
/// one uniformly random dummy entry_id (with up to 32 dedup retries).
///
/// Crucially, every input slot maps to *exactly one* action — there
/// is no "skip" branch. Pre-fix, not-found / whale slots silently
/// produced no action at all, leaking found-vs-not-found from CHUNK
/// round absence. The fix is captured by `classify_chunk_slots`
/// returning `slots.len()` actions for any input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(kani)]
pub(crate) enum ChunkSlotAction {
    AppendReal { entry_id: u32, num_entries: u8 },
    AppendDummy,
}

/// Classify each per-query slot for the OnionPIR CHUNK round.
///
/// Pure: no I/O, no allocation outside the result `Vec`, no RNG.
///
/// Postconditions (Kani-verified — see `kani_harnesses` in this file):
///
/// * **P1 (round-count uniformity)** —
///   `result.len() == slots.len()`. Combined with the call-site
///   loop `for action in &actions { … push to unique … }`, this
///   establishes that the OnionPIR CHUNK phase emits ≥ `slots.len()`
///   unique entry_ids on the wire (modulo dedup collisions on the
///   dummy path, which are probabilistically negligible with 32
///   retries against `total_packed ≫ batch_size`).
///
/// * **P2 (no-skip)** — every slot produces either an `AppendReal`
///   or an `AppendDummy`; there is no third "skip" branch. The
///   distinction maps to `num_entries > 0`: `Real` iff the INDEX
///   scan returned a non-whale match, `Dummy` otherwise (not-found
///   or whale).
#[cfg(kani)]
pub(crate) fn classify_chunk_slots(slots: &[ChunkSlotInput]) -> Vec<ChunkSlotAction> {
    slots
        .iter()
        .map(|s| {
            if s.num_entries > 0 {
                ChunkSlotAction::AppendReal {
                    entry_id: s.entry_id,
                    num_entries: s.num_entries,
                }
            } else {
                ChunkSlotAction::AppendDummy
            }
        })
        .collect()
}

// `UtxoEntry` is only constructed by the feature-gated decode path.
#[cfg(feature = "onion")]
use pir_sdk::UtxoEntry;

#[cfg(feature = "onion")]
use crate::onion_merkle::{
    parse_onionpir_merkle, verify_onion_merkle_batch, OnionMerkleInfo, OnionMerkleLeaf,
    OnionTreeKind,
};

#[cfg(feature = "onion")]
use pir_core::merkle::Hash256;

#[cfg(feature = "onion")]
use std::collections::{HashMap, HashSet};

// ─── Protocol wire codes ────────────────────────────────────────────────────

/// Request: fetch server info as JSON.
const REQ_GET_INFO_JSON: u8 = 0x03;
/// Response: JSON server info payload.
const RESP_GET_INFO_JSON: u8 = 0x03;
// `REQ_GET_DB_CATALOG` / `RESP_DB_CATALOG` come from `crate::protocol`.

/// Request: register FHE keys for a client.
#[cfg(feature = "onion")]
const REQ_REGISTER_KEYS: u8 = 0x50;
/// Response: FHE keys acknowledged.
#[cfg(feature = "onion")]
const RESP_KEYS_ACK: u8 = 0x50;
/// Request: batched encrypted INDEX queries.
#[cfg(feature = "onion")]
const REQ_ONIONPIR_INDEX_QUERY: u8 = 0x51;
/// Response: batched encrypted INDEX results.
#[cfg(feature = "onion")]
const RESP_ONIONPIR_INDEX_RESULT: u8 = 0x51;
/// Request: batched encrypted CHUNK queries.
#[cfg(feature = "onion")]
const REQ_ONIONPIR_CHUNK_QUERY: u8 = 0x52;
/// Response: batched encrypted CHUNK results.
#[cfg(feature = "onion")]
const RESP_ONIONPIR_CHUNK_RESULT: u8 = 0x52;

// ─── Layout constants ───────────────────────────────────────────────────────

/// Number of PBC hash functions (group assignment).
#[cfg(feature = "onion")]
const NUM_HASHES: usize = 3;

/// INDEX cuckoo hash functions (per-bin placement).
#[cfg(feature = "onion")]
const INDEX_CUCKOO_NUM_HASHES: usize = 2;

/// CHUNK cuckoo hash functions.
#[cfg(feature = "onion")]
const CHUNK_CUCKOO_NUM_HASHES: usize = 6;

/// Max kicks before declaring a cuckoo-build failure.
#[cfg(feature = "onion")]
const CHUNK_CUCKOO_MAX_KICKS: usize = 10000;

/// Master seed for CHUNK cuckoo derivation (must match server).
#[cfg(feature = "onion")]
const CHUNK_CUCKOO_SEED: u64 = 0xa3f7c2d918e4b065;

/// Sentinel for empty cuckoo slots.
#[cfg(feature = "onion")]
const EMPTY: u32 = u32::MAX;

/// Size of one packed entry bin in the CHUNK table.
///
/// Pre-port this was a hardcoded `3840` (CONFIG_N2048_K1 at PlainMod=15).
/// Post-port (`onionpir` rev `92fceb01`+) the value is dictated by the
/// compile-time OnionPIR config — `params_info(0).entry_size` — and is
/// 3328 for the default `CONFIG_N2048_K1`. Use [`packed_entry_size`]
/// at runtime instead of hardcoding.
#[cfg(feature = "onion")]
#[inline]
fn packed_entry_size() -> usize {
    onionpir::params_info(0).entry_size as usize
}

// ─── Per-DB OnionPIR parameters ─────────────────────────────────────────────

/// OnionPIR-specific parameters that aren't captured by [`DatabaseInfo`].
///
/// These come from the JSON `onionpir` sub-object in the server info
/// response. The SDK keeps a per-`db_id` table so the right numbers flow
/// into query generation when the client talks to deltas as well as the
/// main database.
///
/// The struct is always present (its values are parsed + stored regardless
/// of feature gate), but the fields are only *read* when the `onion` feature
/// is on. The `allow(dead_code)` silences the warning on default builds.
#[derive(Clone, Debug)]
#[cfg_attr(not(feature = "onion"), allow(dead_code))]
struct OnionDbParams {
    /// Total number of packed entries in the DB (for CHUNK reverse index).
    total_packed: usize,
    /// Number of slots in each decrypted INDEX bin (typically 256).
    index_slots_per_bin: usize,
    /// Byte size of each INDEX slot (typically 15).
    index_slot_size: usize,
}

// ─── Send + Sync wrapper around onionpir::Client ────────────────────────────
//
// `onionpir::Client` wraps an opaque C++ pointer via FFI and is `!Send + !Sync`
// by default. We need both marker traits because `OnionClient` has to satisfy
// `PirClient: Send + Sync` (see `crates/sdk/core/src/client.rs`), and `OnionClient`'s
// `FheState` transitively holds `HashMap<_, SendClient>`.
//
// ─── Audit: what Rust methods `SendClient` exposes ──────────────────────────
//
// The full public API of `onionpir::Client` (upstream
// `rust/onionpir/src/lib.rs` @ rev `92fceb01`, pinned in our Cargo.toml) is:
//
//     new(num_entries: u64) -> Self                                 [ctor]
//     from_secret_key(num_entries, client_id, sk) -> Option<Self>   [ctor]
//     export_secret_key(&self) -> Vec<u8>                           [&self]
//     id(&self) -> u64                                              [&self]
//     galois_keys(&self) -> Vec<u8>                                 [&self]
//     gsw_key(&self) -> Vec<u8>                                     [&self]
//     generate_query(&self, pt_idx: u64) -> Vec<u8>                 [&self]
//     decrypt_response(&self, response: &[u8]) -> Vec<u8>           [&self]
//     Drop::drop(&mut self)                                         [&mut]
//
// Note: post-port (92fceb01), the renames are `*_keys` → `_keys` /
// `_key` (galois plural, gsw singular), `new_from_secret_key` →
// `from_secret_key` (returns Option now), and `decrypt_response`
// dropped the entry-index argument and returns the *raw plaintext*
// (`[u32 N][u64 coeff_i]…`) — app code must bit-unpack with
// `bits_per_coeff = entry_size * 8 / poly_degree` to recover the
// original payload bytes.
//
// ─── Send safety ────────────────────────────────────────────────────────────
//
// `Send` is safe because:
// 1. `onionpir::Client` owns a unique C++ object via `ClientHandle`; no
//    internal sharing with other `onionpir::Client` instances.
// 2. All mutating entry points take `&mut self`, so an owned move across
//    threads cannot race with a concurrent `&mut` on the origin thread.
// 3. `Drop` takes `&mut self` and calls `onion_client_free`, a standard
//    per-instance `delete`.
//
// ─── Sync safety ────────────────────────────────────────────────────────────
//
// `Sync` means `&SendClient` is shareable across threads. Because the Rust
// borrow checker will only let a shared `&SendClient` invoke `&self` methods,
// the Sync safety argument only needs to cover `id` and `export_secret_key`.
//
// I audited the C++ side (upstream `src/ffi.cpp` + `src/ffi_c.cpp`) and
// confirmed:
// * `client_get_id(const OnionPirClient& client)` just reads an integer
//   field (`client.inner.get_client_id()`). No allocation, no mutation.
// * `client_export_secret_key(const OnionPirClient& client)` calls
//   SEAL's `SecretKey::save(stream)` into a *local* `stringstream`. SEAL's
//   `save` is a const member that only reads the secret-key polynomial.
//   Any SEAL-internal allocation goes through SEAL's default `MemoryPool`,
//   which is thread-safe by SEAL's contract.
//
// Neither function touches shared mutable state, global state, thread-local
// state, or OpenMP parallel regions — those all live on `Server::*`, which
// is explicitly documented as `!Send + !Sync` upstream and is not used here.
//
// ─── Practical note: `&self` paths are unused by the SDK ────────────────────
//
// In practice the OnionPIR SDK never actually invokes `&SendClient` methods
// concurrently. `FheState.level_clients` is only accessed via
// `get_level_client(&mut self, ...)` which takes `&mut self` on the
// `OnionClient`, and the per-query callers hold `&mut OnionClient`. So the
// Sync impl exists purely to satisfy the `PirClient: Send + Sync` trait
// bound — it is never exercised in parallel at runtime today.
//
// Keeping the Sync impl (instead of wrapping `SendClient` in a `Mutex`) is
// intentional: a `Mutex` would add lock overhead to every `get_level_client`
// call on the hot query path, and the guarantee it provides is no stronger
// than what the audit above already gives us.

#[cfg(feature = "onion")]
struct SendClient(onionpir::Client);

#[cfg(feature = "onion")]
// Safety: see the "Send + Sync wrapper around onionpir::Client" block above.
// Short version: `onionpir::Client` owns a unique C++ object via an opaque
// handle; all mutation is `&mut self`; there is no internal sharing.
unsafe impl Send for SendClient {}

#[cfg(feature = "onion")]
// Safety: see the "Send + Sync wrapper around onionpir::Client" block above.
// Short version: the only `&self` methods are `id` (integer read) and
// `export_secret_key` (const serialization into a local stringstream).
// Neither touches shared mutable state. No code path in the SDK actually
// shares `&SendClient` across threads today — the impl exists only to
// satisfy the `PirClient: Send + Sync` bound.
unsafe impl Sync for SendClient {}

// Compile-time assertion that `OnionClient` genuinely is `Send + Sync`. If
// somebody adds a new field that is `!Send` or `!Sync` (e.g. an `Rc`, a
// `RefCell`, or a raw pointer) without also wrapping it, this fails to
// compile rather than breaking the `PirClient` trait contract at a distant
// call site.
#[cfg(feature = "onion")]
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SendClient>();
    assert_send_sync::<FheState>();
    assert_send_sync::<OnionClient>();
};
// Same assertion for the stub (non-`onion`) build: `OnionClient` retains the
// API shape but fails queries closed, and still has to meet
// `PirClient: Send + Sync`.
#[cfg(not(feature = "onion"))]
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<OnionClient>();
};

// ─── FHE state (only when the `onion` feature is on) ────────────────────────

#[cfg(feature = "onion")]
struct FheState {
    /// Deterministic client ID (overridden from C++'s `rand()` default).
    client_id: u64,
    /// Exported secret key bytes; used to spawn per-level clients.
    secret_key: Vec<u8>,
    /// Serialized Galois key bytes; sent in the connection's one registration.
    galois_keys: Vec<u8>,
    /// Serialized GSW key bytes; sent in the connection's one registration.
    gsw_keys: Vec<u8>,
    /// Per-level clients, keyed by `(db_id, level)` where level 0=index, 1=chunk.
    ///
    /// Lazily populated on first query to each `(db_id, level)` combination.
    /// Keys are long-lived; per-level clients just adjust `num_entries` for
    /// query generation and response decryption.
    level_clients: HashMap<(u8, u8), SendClient>,
    /// Database IDs for which we've already registered keys on the server.
    registered: HashSet<u8>,
}

// ─── OnionClient ────────────────────────────────────────────────────────────

/// OnionPIR client for single-server FHE-based PIR queries.
///
/// OnionPIR uses Microsoft SEAL's BFV scheme to let a single server
/// operate on encrypted queries. The client generates Galois + GSW
/// relin keys once at connect time (the server caches them in a
/// per-client `KeyStore`), and every subsequent query is a ciphertext
/// the server can fold against the database without learning its contents.
/// If the server's FIFO key store evicts this connection, the SDK fails the
/// query with [`PirError::SessionEvicted`]. It deliberately does not register
/// again or replay a paid query: V1 admission permits exactly one registration
/// and treats a second registration as a terminal sequence violation.
///
/// # Feature gating
///
/// The real implementation is gated behind the `onion` cargo feature,
/// which pulls in the Microsoft SEAL C++ library via CMake + a recent
/// GCC on macOS. Without the feature, `OnionClient` compiles but every
/// query returns `None` and emits a warning — so the DPF and HarmonyPIR
/// paths stay usable on systems without a C++ toolchain. OnionPIR is
/// also native-only: SEAL's C++ build does not compile to
/// `wasm32-unknown-unknown`, so browsers must stay on the TypeScript
/// `onionpir_client.ts` reference implementation.
///
/// ```toml
/// [dependencies]
/// pir-sdk-client = { version = "0.1", features = ["onion"] }
/// ```
///
/// # Examples
///
/// ```ignore
/// use pir_sdk_client::{OnionClient, PirClient, ScriptHash};
///
/// #[tokio::main]
/// async fn main() {
///     let mut client = OnionClient::new("ws://onion-server:8093");
///     client.connect().await.unwrap();
///
///     let script_hash: ScriptHash = [0u8; 20]; // your HASH160 script hash
///     let result = client.sync(&[script_hash], None).await.unwrap();
///
///     if let Some(qr) = &result.results[0] {
///         for entry in &qr.entries {
///             println!("UTXO: {} sats at {}:{}",
///                 entry.amount_sats,
///                 hex::encode(entry.txid),
///                 entry.vout);
///         }
///     }
/// }
/// ```
///
/// [`PirError::SessionEvicted`]: pir_sdk::PirError::SessionEvicted
pub struct OnionClient {
    server_url: String,
    conn: Option<Box<dyn PirTransport>>,
    /// Onion query catalog. Its geometry comes from the JSON `onionpir`
    /// section, while heights and anchors are copied from the standard
    /// catalog when that catalog is available.
    catalog: Option<DatabaseCatalog>,
    /// Unmodified `REQ_GET_DB_CATALOG` response used exclusively to verify
    /// DB proof bundles. A v1 proof commits the DPF table geometry, not the
    /// OnionPIR query geometry, so substituting `catalog` here would reject
    /// every production proof (or, worse, validate against the wrong shape).
    proof_catalog: Option<DatabaseCatalog>,
    /// Per-DB OnionPIR-specific parameters. Keyed by db_id.
    onion_params: std::collections::HashMap<u8, OnionDbParams>,
    /// Per-DB OnionPIR per-bin Merkle info, populated during `fetch_server_info`
    /// when the server exposes an `onionpir_merkle` section. Absent entries
    /// mean the server has no Merkle commitment for that DB and queries run
    /// unverified (matching DpfClient's `has_bucket_merkle=false` path).
    #[cfg(feature = "onion")]
    onion_merkle: std::collections::HashMap<u8, OnionMerkleInfo>,
    /// Cached raw JSON info (so we can re-parse per-DB params on demand).
    info_json: Option<String>,
    #[cfg(feature = "onion")]
    fhe: Option<FheState>,
    /// Optional metrics recorder. When installed, fires
    /// `on_connect` / `on_disconnect` lifecycle events and
    /// `on_query_start` / `on_query_end` per-batch callbacks from the
    /// client layer, plus per-frame `on_bytes_sent` /
    /// `on_bytes_received` from the single transport below (wired on
    /// connect via `set_metrics_recorder`, labelled `"onion"`).
    metrics_recorder: Option<Arc<dyn PirMetrics>>,
    /// Optional leakage recorder. When installed, every transport-level
    /// roundtrip (info / catalog fetch, FHE key registration, INDEX +
    /// CHUNK FHE PIR queries, Merkle tree-tops + sibling rounds) emits
    /// a structured [`RoundProfile`] on `server_id = 0` (single-server
    /// backend).
    leakage_recorder: Option<Arc<dyn LeakageRecorder>>,
    verified_roots: VerifiedRootState,
    verified_tree_tops: std::collections::HashSet<u8>,
}

impl OnionClient {
    /// Create a new OnionPIR client.
    pub fn new(server_url: &str) -> Self {
        Self {
            server_url: server_url.to_string(),
            conn: None,
            catalog: None,
            proof_catalog: None,
            onion_params: std::collections::HashMap::new(),
            #[cfg(feature = "onion")]
            onion_merkle: std::collections::HashMap::new(),
            info_json: None,
            #[cfg(feature = "onion")]
            fhe: None,
            metrics_recorder: None,
            leakage_recorder: None,
            verified_roots: VerifiedRootState::default(),
            verified_tree_tops: std::collections::HashSet::new(),
        }
    }

    pub fn root_policy(&self) -> RootPolicy {
        self.verified_roots.policy()
    }

    pub fn set_root_policy(&mut self, policy: RootPolicy) {
        self.verified_roots.set_policy(policy);
    }

    pub async fn verify_database_proof(
        &mut self,
        db_id: u8,
        policy: &DatabaseProofPolicy,
    ) -> PirResult<VerifiedDatabaseRoots> {
        if !self.is_connected() {
            return Err(PirError::NotConnected);
        }
        let query_catalog = match &self.catalog {
            Some(c) => c.clone(),
            None => self.fetch_catalog().await?,
        };
        // The DB must exist in the catalog that drives this Onion session.
        // Merely finding it in the standard catalog is not enough to make it
        // queryable by OnionPIR.
        query_catalog
            .get(db_id)
            .ok_or(PirError::DatabaseNotFound(db_id))?;
        let db = self.proof_database_info(db_id)?;
        let conn = self.conn.as_mut().ok_or(PirError::NotConnected)?;
        let bundle = fetch_database_proof(conn.as_mut(), db_id).await?;
        verify_database_proof(&db, &bundle, policy)
    }

    /// Fetch and verify the staged v2 proof without falling back to v1.
    /// Production callers can opt in after v2 evidence and sidecars are
    /// deployed; the existing v1 method remains available during migration.
    pub async fn verify_database_proof_v2(
        &mut self,
        db_id: u8,
        policy: &DatabaseProofPolicy,
    ) -> PirResult<VerifiedDatabaseRoots> {
        if !self.is_connected() {
            return Err(PirError::NotConnected);
        }
        let query_catalog = match &self.catalog {
            Some(c) => c.clone(),
            None => self.fetch_catalog().await?,
        };
        query_catalog
            .get(db_id)
            .ok_or(PirError::DatabaseNotFound(db_id))?;
        let db = self.proof_database_info(db_id)?;
        let conn = self.conn.as_mut().ok_or(PirError::NotConnected)?;
        let bundle = fetch_database_proof_v2(conn.as_mut(), db_id).await?;
        verify_database_proof_v2(&db, &bundle, policy)
    }

    /// Select the unmodified standard-catalog entry for v1 DB-proof
    /// verification. JSON-only Onion servers may remain usable in advisory
    /// mode, but can never satisfy strict proof verification.
    fn proof_database_info(&self, db_id: u8) -> PirResult<DatabaseInfo> {
        let catalog = self.proof_catalog.as_ref().ok_or_else(|| {
            PirError::VerificationFailed(
                "OnionPIR strict verification requires REQ_GET_DB_CATALOG; \
                 server provided only OnionPIR query geometry"
                    .into(),
            )
        })?;
        catalog
            .get(db_id)
            .cloned()
            .ok_or(PirError::DatabaseNotFound(db_id))
    }

    pub fn install_verified_database_roots(
        &mut self,
        roots: VerifiedDatabaseRoots,
    ) -> PirResult<()> {
        let catalog = self
            .catalog
            .as_ref()
            .ok_or_else(|| PirError::InvalidState("no catalog".into()))?;
        let db_id = roots.db_id;
        let verified_layout = roots.onion_layout_v2;
        if let Some(layout) = verified_layout {
            let query_db = catalog
                .get(db_id)
                .ok_or(PirError::DatabaseNotFound(db_id))?;
            let proof_db = self
                .proof_catalog
                .as_ref()
                .and_then(|catalog| catalog.get(db_id))
                .ok_or_else(|| {
                    PirError::VerificationFailed(
                        "OnionPIR root installation requires the standard database catalog".into(),
                    )
                })?;
            if query_db.index_bins != layout.index_bins_per_table
                || query_db.chunk_bins != layout.chunk_bins_per_table
                || query_db.index_k != layout.index_k as u8
                || query_db.chunk_k != layout.chunk_k as u8
                || query_db.tag_seed != proof_db.tag_seed
            {
                return Err(PirError::VerificationFailed(format!(
                    "server Onion query geometry disagrees with proof v2 for db_id {db_id}"
                )));
            }
            #[cfg(feature = "onion")]
            {
                if packed_entry_size() != layout.entry_size as usize {
                    return Err(PirError::VerificationFailed(format!(
                        "local OnionPIR entry size {} disagrees with proof v2 {}",
                        packed_entry_size(),
                        layout.entry_size
                    )));
                }
                let merkle = self.onion_merkle.get(&db_id).ok_or_else(|| {
                    PirError::VerificationFailed(format!(
                        "db_id {db_id} has no OnionPIR Merkle metadata"
                    ))
                })?;
                let expected_index_rows =
                    (layout.index_bins_per_table as usize).div_ceil(layout.merkle_arity as usize);
                let expected_chunk_rows =
                    (layout.chunk_bins_per_table as usize).div_ceil(layout.merkle_arity as usize);
                if merkle.arity != layout.merkle_arity as usize
                    || merkle.index.k != layout.index_k as usize
                    || merkle.data.k != layout.chunk_k as usize
                    || merkle.index.num_pt != expected_index_rows
                    || merkle.data.num_pt != expected_chunk_rows
                {
                    return Err(PirError::VerificationFailed(format!(
                        "server Onion Merkle geometry disagrees with proof v2 for db_id {db_id}"
                    )));
                }
            }
        }
        self.verified_roots.install(catalog, roots)?;
        if let Some(layout) = verified_layout {
            self.onion_params.insert(
                db_id,
                OnionDbParams {
                    total_packed: layout.total_packed_entries as usize,
                    index_slots_per_bin: layout.index_slots_per_bin as usize,
                    index_slot_size: layout.index_slot_size as usize,
                },
            );
        }
        self.verified_tree_tops.remove(&db_id);
        Ok(())
    }

    pub fn clear_verified_database_roots(&mut self) {
        self.verified_roots.clear();
        self.verified_tree_tops.clear();
    }

    /// Clear every value whose authenticity or protocol state is bound to the
    /// current transport. Metrics/leakage recorders and the configured server
    /// URL are client configuration, so they deliberately survive.
    fn invalidate_session_bindings(&mut self) {
        self.catalog = None;
        self.proof_catalog = None;
        self.clear_verified_database_roots();
        self.onion_params.clear();
        self.info_json = None;
        #[cfg(feature = "onion")]
        {
            self.fhe = None;
            self.onion_merkle.clear();
        }
    }

    pub fn verified_database_roots(&self, db_id: u8) -> Option<&VerifiedDatabaseRoots> {
        self.verified_roots.get(db_id)
    }

    pub async fn fetch_service_policy_v1(
        &mut self,
        db_id: u8,
        expected_provider_id: ProviderId,
        policy_signing_key: &VerifyingKey,
        now_unix: u64,
        checkpoint: &ServicePolicyCheckpointV1,
    ) -> PirResult<AcceptedServicePolicyV1> {
        if self.verified_database_roots(db_id).is_none() {
            return Err(PirError::VerificationFailed(format!(
                "service policy requires installed database proof for db_id {db_id}"
            )));
        }
        let transport = self.conn.as_mut().ok_or(PirError::NotConnected)?;
        fetch_verified_service_policy_v1(
            transport.as_mut(),
            expected_provider_id,
            policy_signing_key,
            now_unix,
            checkpoint,
        )
        .await
    }

    /// Fetch one exact historical BAT V2 member after the Onion database root
    /// is installed. This path cannot select a provider-bound V1 credential.
    #[allow(clippy::too_many_arguments)]
    pub async fn fetch_retained_bat_v2_policy_v2(
        &mut self,
        db_id: u8,
        expected_provider_id: ProviderId,
        policy_signing_key: &VerifyingKey,
        expected_policy_digest: [u8; 32],
        scope_id: [u8; 32],
        offer_id: u32,
        now_unix: u64,
    ) -> PirResult<AcceptedRetainedBatV2PolicyV2> {
        if self.verified_database_roots(db_id).is_none() {
            return Err(PirError::VerificationFailed(format!(
                "retained BAT V2 policy requires installed database proof for db_id {db_id}"
            )));
        }
        let transport = self.conn.as_mut().ok_or(PirError::NotConnected)?;
        fetch_retained_bat_v2_policy_v2(
            transport.as_mut(),
            expected_provider_id,
            policy_signing_key,
            expected_policy_digest,
            scope_id,
            offer_id,
            now_unix,
        )
        .await
    }

    /// Verify that `accepted` belongs to this exact OnionPIR connection. Call
    /// immediately before retiring a one-shot capability.
    pub fn verify_service_policy_session_v1(
        &self,
        accepted: &AcceptedServicePolicyV1,
    ) -> PirResult<()> {
        let transport = self.conn.as_ref().ok_or(PirError::NotConnected)?;
        verify_policy_transport_session_v1(transport.as_ref(), accepted)
    }

    pub async fn authorize_service_v1(
        &mut self,
        db_id: u8,
        accepted: &AcceptedServicePolicyV1,
        scope_id: [u8; 32],
        offer_id: u32,
        proof: AuthorizationProofV1,
    ) -> PirResult<pir_service_protocol::AuthGrantedV1> {
        self.verify_service_policy_session_v1(accepted)?;
        if self.verified_database_roots(db_id).is_none() {
            return Err(PirError::VerificationFailed(format!(
                "service authorization requires installed database proof for db_id {db_id}"
            )));
        }
        let transport = self.conn.as_mut().ok_or(PirError::NotConnected)?;
        dangerous_unpaired_authorize_service_operation_v1(
            transport.as_mut(),
            accepted,
            scope_id,
            offer_id,
            OperationStartV1::OnionSession { db_id },
            proof,
        )
        .await
    }

    /// One-shot standalone OnionPIR BAT V2 admission with an exact verified
    /// member handle and conservative post-send disposition.
    pub async fn authorize_bat_v2_service_v2(
        &mut self,
        db_id: u8,
        verified: &VerifiedBatV2RedemptionV2,
        proof_bytes: &[u8],
        now_unix: u64,
    ) -> PirResult<BatV2AdmissionOutcomeV2> {
        if self.verified_database_roots(db_id).is_none() {
            return Err(PirError::VerificationFailed(format!(
                "BAT V2 authorization requires installed database proof for db_id {db_id}"
            )));
        }
        let transport = self.conn.as_mut().ok_or(PirError::NotConnected)?;
        authorize_bat_v2_redemption_v2(
            transport.as_mut(),
            verified,
            OperationStartV1::OnionSession { db_id },
            proof_bytes,
            now_unix,
        )
        .await
    }

    pub async fn request_service_pow_challenge_v1(
        &mut self,
        db_id: u8,
        accepted: &AcceptedServicePolicyV1,
        scope_id: [u8; 32],
        offer_id: u32,
        now_unix: u64,
    ) -> PirResult<pir_service_protocol::PowChallengeResponseV1> {
        if self.verified_database_roots(db_id).is_none() {
            return Err(PirError::VerificationFailed(format!(
                "proof-of-work challenge requires installed database proof for db_id {db_id}"
            )));
        }
        let transport = self.conn.as_mut().ok_or(PirError::NotConnected)?;
        request_pow_challenge_v1(
            transport.as_mut(),
            accepted,
            scope_id,
            offer_id,
            OperationStartV1::OnionSession { db_id },
            now_unix,
        )
        .await
    }

    /// Fetch and bind a database's OnionPIR Merkle tree-tops to an explicitly
    /// installed proof root before any address query is sent.
    ///
    /// This is the native OnionPIR counterpart of the DPF/Harmony preflight
    /// APIs. It is feature-gated because a build without `onion` has no FHE
    /// tree-top verifier and therefore cannot truthfully report a successful
    /// preflight.
    #[cfg(feature = "onion")]
    pub async fn preflight_verified_database(&mut self, db_id: u8) -> PirResult<()> {
        if self.verified_database_roots(db_id).is_none() {
            return Err(PirError::VerificationFailed(format!(
                "db_id {} has no installed database proof",
                db_id
            )));
        }
        if !self.is_connected() {
            return Err(PirError::NotConnected);
        }
        let catalog = match &self.catalog {
            Some(catalog) => catalog.clone(),
            None => self.fetch_catalog().await?,
        };
        if catalog.get(db_id).is_none() {
            return Err(PirError::DatabaseNotFound(db_id));
        }
        self.preflight_trusted_tree_tops(db_id).await
    }

    #[cfg(feature = "onion")]
    async fn preflight_trusted_tree_tops(&mut self, db_id: u8) -> PirResult<()> {
        let Some(roots) = self.verified_roots.get(db_id).cloned() else {
            return self.verified_roots.require_db(db_id);
        };
        if self.verified_tree_tops.contains(&db_id) {
            return Ok(());
        }
        let mut info = self.onion_merkle.get(&db_id).cloned().ok_or_else(|| {
            PirError::VerificationFailed(format!("db_id {} has no OnionPIR Merkle metadata", db_id))
        })?;
        info.super_root = roots.onion_super_root;
        let conn = self.conn.as_mut().ok_or(PirError::NotConnected)?;
        crate::onion_merkle::preflight_onion_tree_tops(conn.as_mut(), &info, db_id).await?;
        self.verified_tree_tops.insert(db_id);
        Ok(())
    }

    #[cfg(not(feature = "onion"))]
    async fn preflight_trusted_tree_tops(&mut self, _db_id: u8) -> PirResult<()> {
        Err(PirError::BackendState(
            "OnionPIR support is not compiled in; enable the `onion` cargo feature".into(),
        ))
    }

    /// Install (or replace) a metrics recorder.
    ///
    /// The recorder receives:
    /// * Per-frame `on_bytes_sent` / `on_bytes_received` callbacks from
    ///   the single transport, labelled `"onion"`.
    /// * Per-batch `on_query_start` / `on_query_end` callbacks at
    ///   [`query_batch`](PirClient::query_batch) entry / exit.
    /// * `on_connect` on successful `connect` and `on_disconnect` on
    ///   `disconnect`.
    ///
    /// If the client is already connected when the recorder is
    /// installed, the recorder is propagated to the transport
    /// immediately. Pass `None` to uninstall.
    pub fn set_metrics_recorder(&mut self, recorder: Option<Arc<dyn PirMetrics>>) {
        self.metrics_recorder = recorder.clone();
        if let Some(ref mut c) = self.conn {
            c.set_metrics_recorder(recorder, "onion");
        }
    }

    /// Fire `on_query_start` on the installed recorder, if any. Returns
    /// the `Instant` captured at start so a later
    /// [`fire_query_end`](Self::fire_query_end) can compute the
    /// wall-clock duration. `None` when no recorder is installed
    /// (preserves the zero-overhead no-recorder path).
    fn fire_query_start(&self, db_id: u8, num_queries: usize) -> Option<Instant> {
        if let Some(rec) = &self.metrics_recorder {
            rec.on_query_start("onion", db_id, num_queries);
            Some(Instant::now())
        } else {
            None
        }
    }

    /// Fire `on_query_end` on the installed recorder, if any. The
    /// `started_at` value comes from the matching
    /// [`fire_query_start`](Self::fire_query_start) call; `None`
    /// produces `Duration::ZERO` (best-effort observation per
    /// [`PirMetrics::on_query_end`] semantics).
    fn fire_query_end(
        &self,
        db_id: u8,
        num_queries: usize,
        success: bool,
        started_at: Option<Instant>,
    ) {
        if let Some(rec) = &self.metrics_recorder {
            let duration = started_at.map(|t| t.elapsed()).unwrap_or_default();
            rec.on_query_end("onion", db_id, num_queries, success, duration);
        }
    }

    /// Fire `on_connect` on the installed recorder, if any.
    fn fire_connect(&self, url: &str) {
        if let Some(rec) = &self.metrics_recorder {
            rec.on_connect("onion", url);
        }
    }

    /// Fire `on_disconnect` on the installed recorder, if any.
    fn fire_disconnect(&self) {
        if let Some(rec) = &self.metrics_recorder {
            rec.on_disconnect("onion");
        }
    }

    /// Install (or replace) a leakage recorder. Independent of
    /// [`set_metrics_recorder`](Self::set_metrics_recorder).
    /// All emissions tag `server_id = 0` (OnionPIR is single-server).
    /// Pass `None` to uninstall.
    pub fn set_leakage_recorder(&mut self, recorder: Option<Arc<dyn LeakageRecorder>>) {
        self.leakage_recorder = recorder;
    }

    /// Emit a [`RoundProfile`] to the installed leakage recorder, if any.
    fn record_round(&self, round: RoundProfile) {
        if let Some(rec) = &self.leakage_recorder {
            rec.record_round("onion", round);
        }
    }

    /// Install a pre-built transport directly, bypassing the URL-based
    /// [`PirClient::connect`] path.
    ///
    /// This is the test-injection escape hatch the `PirTransport` trait was
    /// designed around: state-machine tests can hand in a
    /// [`MockTransport`](crate::transport::MockTransport) (or any other
    /// impl) and drive the client without opening a real WebSocket.
    /// `PirClient::is_connected` returns `true` after this call.
    ///
    /// Note: with the `onion` feature, real queries also require FHE state
    /// Send REQ_ATTEST and verify the REPORT_DATA binding. See
    /// [`super::DpfClient::attest`] for the full semantics.
    pub async fn attest(
        &mut self,
        nonce: [u8; 32],
    ) -> PirResult<crate::attest::AttestVerification> {
        let conn = self
            .conn
            .as_mut()
            .ok_or_else(|| PirError::Protocol("attest: server not connected".into()))?;
        crate::attest::attest(conn.as_mut(), nonce).await
    }

    /// Send REQ_ANNOUNCE and parse the operator-signed identity bundle.
    /// See [`super::DpfClient::announce`] for full semantics.
    pub async fn announce(&mut self) -> PirResult<crate::announce::AnnounceVerification> {
        let conn = self
            .conn
            .as_mut()
            .ok_or_else(|| PirError::Protocol("announce: server not connected".into()))?;
        crate::announce::announce(conn.as_mut()).await
    }

    /// Replace the server connection with a secure-channel-wrapped
    /// version. See [`super::DpfClient::upgrade_to_secure_channel`]
    /// for the full semantics.
    pub async fn upgrade_to_secure_channel(
        &mut self,
        server_static_pub: [u8; 32],
    ) -> PirResult<()> {
        let mut eph = [0u8; 32];
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut eph)
            .map_err(|e| PirError::Protocol(format!("getrandom: {}", e)))?;
        getrandom::getrandom(&mut nonce)
            .map_err(|e| PirError::Protocol(format!("getrandom: {}", e)))?;
        self.upgrade_to_secure_channel_with_seeds(server_static_pub, eph, nonce)
            .await
    }

    /// Binding-friendly overload: thread the same `eph_seed` you
    /// passed to [`crate::attest::attest_with_eph_binding`] so the
    /// attestation covers this exact handshake. `hs_nonce` is the HKDF
    /// salt (CSPRNG-fresh per call).
    pub async fn upgrade_to_secure_channel_with_seeds(
        &mut self,
        server_static_pub: [u8; 32],
        eph_seed: [u8; 32],
        hs_nonce: [u8; 32],
    ) -> PirResult<()> {
        let raw = self
            .conn
            .take()
            .ok_or_else(|| PirError::Protocol("upgrade: server not connected".into()))?;
        let wrapped = crate::channel::establish(raw, server_static_pub, eph_seed, hs_nonce).await?;
        self.conn = Some(Box::new(wrapped));
        Ok(())
    }

    /// (Galois + GSW keys) which is populated during
    /// [`PirClient::fetch_catalog`]. Tests that want to bypass the wire
    /// entirely should drive query primitives directly, not through
    /// `sync_with_plan`.
    #[tracing::instrument(level = "debug", skip_all, fields(backend = "onion"))]
    pub fn connect_with_transport(&mut self, conn: Box<dyn PirTransport>) {
        // Replacing a transport starts a new session. Never carry a catalog,
        // verified root/tree-top binding, or FHE registration into it.
        self.invalidate_session_bindings();
        self.conn = Some(conn);
        // Propagate any installed recorder so per-frame byte counts flow
        // from this injected transport. OnionPIR only has one transport,
        // so no cloning game like DPF/Harmony — just forward directly.
        if let Some(rec) = self.metrics_recorder.clone() {
            if let Some(ref mut c) = self.conn {
                c.set_metrics_recorder(Some(rec), "onion");
            }
        }
        self.fire_connect(&self.server_url);
    }

    /// Fetch the JSON server info and (best-effort) the DPF-format catalog,
    /// merging into a unified [`DatabaseCatalog`] plus per-DB OnionPIR params.
    async fn fetch_server_info(&mut self) -> PirResult<()> {
        let conn = self.conn.as_mut().ok_or(PirError::NotConnected)?;

        // Request JSON info.
        let req = encode_request(REQ_GET_INFO_JSON, &[]);
        let request_bytes = req.len() as u64;
        let response = conn.roundtrip(&req).await?;
        // `roundtrip` strips the 4-byte length prefix; restore it for the
        // wire-observable byte count.
        self.record_round(RoundProfile {
            kind: RoundKind::Info,
            server_id: 0,
            db_id: None,
            request_bytes,
            response_bytes: (response.len() as u64).saturating_add(4),
            items: Vec::new(),
        });

        if response.is_empty() || response[0] != RESP_GET_INFO_JSON {
            return Err(PirError::Protocol(
                "expected 0x03 JSON info response".into(),
            ));
        }
        let json_bytes = &response[1..];
        let json = std::str::from_utf8(json_bytes)
            .map_err(|e| PirError::Protocol(format!("info JSON not UTF-8: {}", e)))?
            .to_string();

        self.onion_params = parse_onion_params_per_db(&json);
        if self.onion_params.is_empty() {
            return Err(PirError::Protocol(
                "server has no OnionPIR data — is this an OnionPIR-enabled server?".into(),
            ));
        }

        // Parse onionpir_merkle (optional). Populated per-DB so queries
        // against the main DB, deltas, and secondary DBs each pick up the
        // right root + sibling-level layout.
        #[cfg(feature = "onion")]
        {
            self.onion_merkle = parse_onion_merkle_per_db(&json);
        }

        // Best-effort standard catalog fetch for heights/names and proof
        // verification. Advisory Onion queries retain the JSON-only fallback,
        // but strict proof verification requires this exact, unmodified
        // catalog and never substitutes OnionPIR geometry.
        let dpf_catalog = self.try_fetch_dpf_catalog().await.ok();
        self.proof_catalog = dpf_catalog.clone();

        let catalog = build_catalog(&json, &self.onion_params, dpf_catalog.as_ref());
        self.catalog = Some(catalog);
        self.info_json = Some(json);
        Ok(())
    }

    async fn try_fetch_dpf_catalog(&mut self) -> PirResult<DatabaseCatalog> {
        let conn = self.conn.as_mut().ok_or(PirError::NotConnected)?;
        let req = encode_request(REQ_GET_DB_CATALOG, &[]);
        let request_bytes = req.len() as u64;
        let response = conn.roundtrip(&req).await?;
        self.record_round(RoundProfile {
            kind: RoundKind::Info,
            server_id: 0,
            db_id: None,
            request_bytes,
            response_bytes: (response.len() as u64).saturating_add(4),
            items: Vec::new(),
        });
        if response.is_empty() || response[0] != RESP_DB_CATALOG {
            return Err(PirError::Protocol("no DPF catalog available".into()));
        }
        decode_catalog(&response[1..])
    }

    /// Execute a single sync step for a batch of script hashes.
    #[cfg(feature = "onion")]
    #[tracing::instrument(level = "debug", skip_all, fields(backend = "onion", db_id = _step.db_id, step = %_step.name, height = _step.tip_height, num_queries = script_hashes.len()))]
    async fn execute_step(
        &mut self,
        script_hashes: &[ScriptHash],
        _step: &SyncStep,
        db_info: &DatabaseInfo,
    ) -> PirResult<Vec<Option<QueryResult>>> {
        // Strict sync has already required verified roots and preflighted the
        // Onion tree-tops. Empty input must not initialise FHE or register keys.
        if script_hashes.is_empty() {
            return Ok(Vec::new());
        }

        let params = self
            .onion_params
            .get(&db_info.db_id)
            .cloned()
            .ok_or_else(|| {
                PirError::InvalidState(format!("no OnionPIR params for db_id={}", db_info.db_id))
            })?;

        self.ensure_fhe_initialised()?;
        self.ensure_keys_registered(db_info).await?;

        log::info!(
            "[PIR-AUDIT] OnionPIR execute_step db_id={} ({}), {} scripthashes, K={}, K_CHUNK={}",
            db_info.db_id,
            db_info.name,
            script_hashes.len(),
            db_info.index_k,
            db_info.chunk_k
        );
        log::info!(
            "[PIR-AUDIT] OnionPIR padding: INDEX rounds send exactly K={} queries \
             (2*K cuckoo positions), CHUNK rounds send exactly K_CHUNK={} queries — \
             dummies fill empty groups.",
            db_info.index_k,
            db_info.chunk_k,
        );

        let (index_results, index_traces) = self
            .query_index_level(script_hashes, db_info, &params)
            .await?;

        let (chunk_data, data_merkle, chunk_owned_per_query) = self
            .query_chunk_level(&index_results, db_info, &params)
            .await?;

        // Decode per-scripthash UTXOs from assembled raw bytes.
        let mut results = Vec::with_capacity(script_hashes.len());
        for (idx, ir) in index_results.iter().enumerate() {
            let qr = match ir {
                None => {
                    log::info!(
                        "[PIR-AUDIT] OnionPIR scripthash {}: NOT FOUND",
                        hex_short(&script_hashes[idx])
                    );
                    None
                }
                Some(ir) if ir.num_entries == 0 => {
                    log::info!(
                        "[PIR-AUDIT] OnionPIR scripthash {}: WHALE (excluded)",
                        hex_short(&script_hashes[idx])
                    );
                    Some(QueryResult {
                        entries: Vec::new(),
                        is_whale: true,
                        // Optimistic default — `run_merkle_verification`
                        // flips this to `false` if the INDEX proof fails.
                        merkle_verified: true,
                        raw_chunk_data: None,
                        // OnionPIR inspector state isn't part of Session 2
                        // scope (DPF-only). Kept empty so the struct shape
                        // matches across backends; OnionPIR's per-bin
                        // Merkle trace lives inside `index_traces` /
                        // `data_merkle` which are consumed by
                        // `run_merkle_verification` directly.
                        index_bins: Vec::new(),
                        chunk_bins: Vec::new(),
                        matched_index_idx: None,
                    })
                }
                Some(ir) => {
                    let raw = assemble_entry_bytes(ir, &chunk_data, db_info.db_id)?;
                    let entries = decode_utxo_entries(&raw)?;
                    log::info!(
                        "[PIR-AUDIT] OnionPIR scripthash {}: FOUND {} UTXOs \
                         (entry_id={}, num_entries={}, byte_offset={})",
                        hex_short(&script_hashes[idx]),
                        entries.len(),
                        ir.entry_id,
                        ir.num_entries,
                        ir.byte_offset,
                    );
                    Some(QueryResult {
                        entries,
                        is_whale: false,
                        // Optimistic default — `run_merkle_verification`
                        // flips this to `false` (and empties `entries`) if
                        // INDEX or DATA proofs fail for this query.
                        merkle_verified: true,
                        raw_chunk_data: if db_info.kind.is_delta() {
                            Some(raw)
                        } else {
                            None
                        },
                        // See whale-case comment above — OnionPIR inspector
                        // state is out of scope for Session 2.
                        index_bins: Vec::new(),
                        chunk_bins: Vec::new(),
                        matched_index_idx: None,
                    })
                }
            };
            results.push(qr);
        }

        // Per-bin Merkle verification — same semantics as DpfClient: on any
        // leaf failing verification the corresponding result is coerced to
        // None so callers can't distinguish server lies from genuine absence.
        //
        // Only runs if the server exposed an `onionpir_merkle` section for
        // this DB (otherwise it's a silent skip, matching
        // `has_bucket_merkle=false` for DPF/Harmony).
        if self.onion_merkle.contains_key(&db_info.db_id) {
            self.run_merkle_verification(
                &mut results,
                &index_traces,
                &index_results,
                &data_merkle,
                &chunk_owned_per_query,
                db_info,
            )
            .await?;
        } else {
            log::info!(
                "[PIR-AUDIT] OnionPIR Merkle verification SKIPPED \
                 (db_id={} has no onionpir_merkle section)",
                db_info.db_id
            );
        }

        Ok(results)
    }

    /// Run OnionPIR per-bin Merkle verification on the traces collected
    /// during `query_index_level` / `query_chunk_level`.
    ///
    /// A query passes iff ALL of its INDEX leaves and (if found) DATA leaves
    /// verify to the respective sub-tree roots. On any failure, that query's
    /// result is set to `None` so untrusted data never reaches the caller.
    #[cfg(feature = "onion")]
    #[tracing::instrument(level = "debug", skip_all, fields(backend = "onion", db_id = db_info.db_id))]
    async fn run_merkle_verification(
        &mut self,
        results: &mut [Option<QueryResult>],
        index_traces: &[IndexBinMerkle],
        _index_results: &[Option<IndexResult>],
        data_merkle: &HashMap<u32, (Hash256, usize, u32)>,
        chunk_owned_per_query: &[Vec<u32>],
        db_info: &DatabaseInfo,
    ) -> PirResult<()> {
        let mut info = match self.onion_merkle.get(&db_info.db_id).cloned() {
            Some(m) => m,
            None => return Ok(()),
        };
        if let Some(roots) = self.verified_roots.get(db_info.db_id) {
            info.super_root = roots.onion_super_root;
        }

        // Build the flat leaf list (both INDEX and DATA).
        let mut leaves: Vec<OnionMerkleLeaf> =
            Vec::with_capacity(index_traces.len() + data_merkle.len());

        for it in index_traces {
            leaves.push(OnionMerkleLeaf {
                tree: OnionTreeKind::Index,
                pbc_group: it.pbc_group,
                bin: it.bin,
                hash: it.bin_hash,
                result_idx: it.sh_idx,
            });
        }

        // DATA leaves: post-M=16-removal (Phase 3 / WS-A) every query owns
        // its *real* chunk entry_ids in `chunk_owned_per_query[idx]` — N
        // for a found-with-N query, 0 for not-found / whale. A query
        // "passes" iff ALL of its real DATA leaves verify to the per-group
        // root. The same entry_id may be owned by multiple queries when
        // their real chunk ranges overlap; tracking every owner in
        // `entry_id_to_result` ensures a failure propagates to each owning
        // query. (Found-vs-not-found is not leaked by the now-variable DATA
        // leaf count: the per-group verifier still issues ≥1 all-dummy
        // CHUNK-Merkle pass for a 0-leaf DATA tree — round-presence.)
        let mut entry_id_to_result: HashMap<u32, Vec<usize>> = HashMap::new();
        for (idx, owned) in chunk_owned_per_query.iter().enumerate() {
            for &eid in owned {
                entry_id_to_result.entry(eid).or_default().push(idx);
            }
        }

        for (eid, &(hash, pbc_group, bin)) in data_merkle {
            let owners = match entry_id_to_result.get(eid) {
                Some(o) => o,
                None => continue, // entry fetched but no owning query — shouldn't happen
            };
            for &owner in owners {
                leaves.push(OnionMerkleLeaf {
                    tree: OnionTreeKind::Data,
                    pbc_group,
                    bin,
                    hash,
                    result_idx: owner,
                });
            }
        }

        if leaves.is_empty() {
            log::info!(
                "[PIR-AUDIT] OnionPIR Merkle: no leaves to verify for db_id={}",
                db_info.db_id
            );
            return Ok(());
        }

        log::info!(
            "[PIR-AUDIT] OnionPIR Merkle: verifying db_id={} ({} INDEX + {} DATA leaves across {} queries)",
            db_info.db_id,
            index_traces.len(),
            data_merkle.len(),
            results.len(),
        );

        let (client_id, secret_key) = {
            let fhe = self
                .fhe
                .as_ref()
                .ok_or_else(|| PirError::InvalidState("FHE not initialised".into()))?;
            (fhe.client_id, fhe.secret_key.clone())
        };
        let leakage = self.leakage_recorder.clone();
        let conn = self.conn.as_mut().ok_or(PirError::NotConnected)?;
        let verdicts = verify_onion_merkle_batch(
            conn,
            &info,
            &leaves,
            client_id,
            &secret_key,
            db_info.db_id,
            leakage,
        )
        .await?;

        // Aggregate: a result passes iff ALL of its leaves' verdicts are true.
        let mut per_query_ok = vec![true; results.len()];
        let mut per_query_touched = vec![false; results.len()];
        for leaf in &leaves {
            per_query_touched[leaf.result_idx] = true;
            let ok = verdicts
                .get(&(leaf.tree, leaf.pbc_group, leaf.bin))
                .copied()
                .unwrap_or(false);
            if !ok {
                per_query_ok[leaf.result_idx] = false;
            }
        }

        for qi in 0..results.len() {
            if !per_query_touched[qi] {
                continue;
            }
            if per_query_ok[qi] {
                log::info!("[PIR-AUDIT] OnionPIR Merkle PASSED for query #{}", qi);
                // merkle_verified is already true by construction above.
            } else {
                log::warn!(
                    "[PIR-AUDIT] OnionPIR Merkle FAILED for query #{}: \
                     emitting QueryResult {{ merkle_verified: false, entries: [] }} (untrusted)",
                    qi
                );
                // Surface the failure as a distinct signal from "not found"
                // (the old behaviour collapsed both to `None`). Entries are
                // wiped so downstream callers cannot accidentally trust
                // unverified data even if they ignore `merkle_verified`.
                results[qi] = Some(QueryResult::merkle_failed());
            }
        }

        Ok(())
    }

    /// Fail-closed fallback when the `onion` feature is disabled.
    #[cfg(not(feature = "onion"))]
    #[tracing::instrument(level = "debug", skip_all, fields(backend = "onion", db_id = _step.db_id, step = %_step.name, height = _step.tip_height, num_queries = script_hashes.len()))]
    async fn execute_step(
        &mut self,
        script_hashes: &[ScriptHash],
        _step: &SyncStep,
        _db_info: &DatabaseInfo,
    ) -> PirResult<Vec<Option<QueryResult>>> {
        Err(PirError::BackendState(format!(
            "OnionPIR support is not compiled in; cannot query {} script hash(es). \
             Enable the `onion` cargo feature (requires a C++ toolchain + cmake + SEAL)",
            script_hashes.len()
        )))
    }

    // ─── FHE helpers (onion feature only) ───────────────────────────────────

    #[cfg(feature = "onion")]
    fn ensure_fhe_initialised(&mut self) -> PirResult<()> {
        if self.fhe.is_some() {
            return Ok(());
        }
        // Pick an arbitrary DB for key generation — keys are independent of
        // num_entries, so we just need something to instantiate the client.
        let any_db_id = *self
            .onion_params
            .keys()
            .next()
            .ok_or_else(|| PirError::InvalidState("no OnionPIR databases known".into()))?;
        let num_entries = self.num_entries_for_level(any_db_id, /* chunk */ false);

        // Override client_id with a cryptographic-quality random u64 — the
        // C++ default uses rand() which is non-crypto and can collide.
        let client_id: u64 = rand::random();

        // Allocate a temporary `Client` just for keygen + secret-key export,
        // then drop it. Per-level clients are created lazily from the exported
        // secret key as queries come in.
        // OnionPIRv2 port (commit 1, 2026-05-14):
        //   * renamed `new_from_secret_key` → `from_secret_key`
        //   * return type changed from `Self` to `Option<Self>` (size/format check).
        // `.expect()` is fine here because we just generated the secret key via
        // `Client::new(...).export_secret_key()` on the line below — it cannot
        // be malformed.
        let mut keygen = onionpir::Client::from_secret_key(
            num_entries as u64,
            client_id,
            &onionpir::Client::new(num_entries as u64).export_secret_key(),
        )
        .expect("freshly-exported secret key must round-trip");
        // The above pattern (new + export + new_from_sk) is what the reference
        // onionpir_client does to decouple key ownership from num_entries.
        // We create one keygen client with our client_id bound to the newly
        // generated secret key, then pull keys + sk out of it.
        // OnionPIRv2 port: renamed `generate_galois_keys` → `galois_keys`,
        // `generate_gsw_keys` → `gsw_key` (singular).
        let galois_keys = keygen.galois_keys();
        let gsw_keys = keygen.gsw_key();
        let secret_key = keygen.export_secret_key();

        self.fhe = Some(FheState {
            client_id,
            secret_key,
            galois_keys,
            gsw_keys,
            level_clients: HashMap::new(),
            registered: HashSet::new(),
        });
        log::info!(
            "[PIR-AUDIT] OnionPIR generated FHE keys (client_id=0x{:016x})",
            client_id
        );
        Ok(())
    }

    /// Register keys for a given database if we haven't already on this
    /// connection. V1 admission permits this transition exactly once.
    #[cfg(feature = "onion")]
    async fn ensure_keys_registered(&mut self, db_info: &DatabaseInfo) -> PirResult<()> {
        let already = self
            .fhe
            .as_ref()
            .map(|f| f.registered.contains(&db_info.db_id))
            .unwrap_or(false);
        if already {
            return Ok(());
        }
        self.register_keys(db_info.db_id).await
    }

    #[cfg(feature = "onion")]
    async fn register_keys(&mut self, db_id: u8) -> PirResult<()> {
        let (galois_keys, gsw_keys) = {
            let fhe = self
                .fhe
                .as_ref()
                .ok_or_else(|| PirError::InvalidState("FHE not initialised".into()))?;
            (fhe.galois_keys.clone(), fhe.gsw_keys.clone())
        };

        let payload = encode_register_keys(&galois_keys, &gsw_keys, db_id);
        let request_bytes = payload.len() as u64;
        let conn = self.conn.as_mut().ok_or(PirError::NotConnected)?;
        let response = conn.roundtrip(&payload).await?;
        self.record_round(RoundProfile {
            kind: RoundKind::OnionKeyRegister,
            server_id: 0,
            db_id: Some(db_id),
            request_bytes,
            response_bytes: (response.len() as u64).saturating_add(4),
            items: Vec::new(),
        });

        decode_register_keys_ack(&response)?;

        self.fhe
            .as_mut()
            .expect("fhe present")
            .registered
            .insert(db_id);
        log::info!("[PIR-AUDIT] OnionPIR registered keys for db_id={}", db_id);
        Ok(())
    }

    /// Number of packed entries in a DB at a particular level (false=index, true=chunk).
    #[cfg(feature = "onion")]
    fn num_entries_for_level(&self, db_id: u8, chunk: bool) -> usize {
        let db = self.catalog.as_ref().and_then(|c| c.get(db_id));
        match db {
            Some(d) if chunk => d.chunk_bins as usize,
            Some(d) => d.index_bins as usize,
            None => 1,
        }
    }

    /// Send one OnionPIR batch and parse its response. An all-empty batch is
    /// the server's key-eviction signal. It fails closed immediately: replaying
    /// would consume a second backend frame, and re-registration is forbidden
    /// by the V1 register-once admission DFA.
    ///
    /// [`ErrorKind::SessionEvicted`]: pir_sdk::ErrorKind::SessionEvicted
    /// [`ErrorKind::ServerError`]: pir_sdk::ErrorKind::ServerError
    ///
    /// This is the single chokepoint for INDEX and CHUNK. The Merkle path
    /// independently fails verification on an empty ciphertext result.
    #[cfg(feature = "onion")]
    async fn onionpir_batch_rpc(
        &mut self,
        msg: &[u8],
        expected_variant: u8,
        expected_round_id: u16,
        db_id: u8,
        variant_name: &'static str,
        round_kind: RoundKind,
        items_per_group: &[u32],
    ) -> PirResult<Vec<Vec<u8>>> {
        let batch = self
            .onionpir_batch_rpc_once(
                msg,
                expected_variant,
                expected_round_id,
                variant_name,
                round_kind,
                items_per_group,
                db_id,
            )
            .await?;
        if batch_looks_evicted(&batch) {
            return Err(PirError::SessionEvicted(format!(
                "OnionPIR {} returned all-empty batch for db_id={} \
                 — server keys were evicted or FHE parameters drifted; \
                 V1 did not re-register or replay the query",
                variant_name, db_id,
            )));
        }
        Ok(batch)
    }

    /// One-shot sender for `onionpir_batch_rpc`: single roundtrip, no retry.
    /// Emits exactly one `RoundProfile` for the one actual roundtrip.
    #[cfg(feature = "onion")]
    async fn onionpir_batch_rpc_once(
        &mut self,
        msg: &[u8],
        expected_variant: u8,
        expected_round_id: u16,
        variant_name: &'static str,
        round_kind: RoundKind,
        items_per_group: &[u32],
        db_id: u8,
    ) -> PirResult<Vec<Vec<u8>>> {
        let expected_results = items_per_group.iter().try_fold(0usize, |total, count| {
            total.checked_add(*count as usize).ok_or_else(|| {
                PirError::Protocol(format!("{variant_name}: expected result count overflow"))
            })
        })?;
        let request_bytes = msg.len() as u64;
        let conn = self.conn.as_mut().ok_or(PirError::NotConnected)?;
        let response = conn.roundtrip(msg).await?;
        self.record_round(RoundProfile {
            kind: round_kind,
            server_id: 0,
            db_id: Some(db_id),
            request_bytes,
            response_bytes: (response.len() as u64).saturating_add(4),
            items: items_per_group.to_vec(),
        });
        decode_onionpir_batch_response(
            &response,
            expected_variant,
            expected_round_id,
            expected_results,
            variant_name,
        )
    }

    /// Get or create a per-level `onionpir::Client` for (db_id, level).
    #[cfg(feature = "onion")]
    fn get_level_client(&mut self, db_id: u8, chunk: bool) -> PirResult<&mut onionpir::Client> {
        let key = (db_id, if chunk { 1u8 } else { 0u8 });
        let num_entries = self.num_entries_for_level(db_id, chunk) as u64;
        let fhe = self
            .fhe
            .as_mut()
            .ok_or_else(|| PirError::InvalidState("FHE not initialised".into()))?;

        if !fhe.level_clients.contains_key(&key) {
            // OnionPIRv2 port: rename + return type changed to `Option<Self>`.
            // The secret key in `fhe.secret_key` was generated by
            // `Client::new(...).export_secret_key()` earlier in this same
            // session (see `init_fhe_state` / `generate_keys`), so
            // `from_secret_key` returning None here would indicate one of:
            //   1. CONFIG drift — the secret key was produced under a
            //      different `ACTIVE_CONFIG` than the current binary
            //      (`onionpir` rev vs. its compile-time DB shape).
            //   2. Truncation — `fhe.secret_key.len()` got clipped after
            //      generation (memory corruption / bad serialization on
            //      a future persistence layer).
            //   3. Stale persisted key from the pre-port SEAL build —
            //      not currently a concern since pir-sdk-client doesn't
            //      persist keys across process boundaries, but listed
            //      here so a future persistence layer remembers to
            //      version-tag the blob.
            // None of these are recoverable without re-generating the
            // session keys; surface a typed PirError so the caller can
            // tear down the session and retry from scratch.
            let client =
                onionpir::Client::from_secret_key(num_entries, fhe.client_id, &fhe.secret_key)
                    .ok_or_else(|| {
                        PirError::InvalidState(format!(
                            "OnionPIR Client::from_secret_key returned None for \
                     (num_entries={}, client_id={}, sk_len={}). \
                     Most likely cause: the secret key was generated under \
                     a different onionpir rev / ACTIVE_CONFIG than the \
                     currently-loaded library, or a future persistence \
                     layer wrote a pre-port SEAL-serialized key. \
                     Recovery: drop the FheState and call keygen fresh.",
                            num_entries,
                            fhe.client_id,
                            fhe.secret_key.len()
                        ))
                    })?;
            fhe.level_clients.insert(key, SendClient(client));
        }
        Ok(&mut fhe.level_clients.get_mut(&key).unwrap().0)
    }

    #[cfg(feature = "onion")]
    #[tracing::instrument(level = "trace", skip_all, fields(backend = "onion", db_id = db_info.db_id, num_queries = script_hashes.len()))]
    async fn query_index_level(
        &mut self,
        script_hashes: &[ScriptHash],
        db_info: &DatabaseInfo,
        params: &OnionDbParams,
    ) -> PirResult<(Vec<Option<IndexResult>>, Vec<IndexBinMerkle>)> {
        let k = db_info.index_k as usize;
        let bins = db_info.index_bins as usize;
        let tag_seed = db_info.tag_seed;
        let master_seed = db_info.index_master_seed;

        // Plan PBC rounds.
        let groups_per_sh: Vec<[usize; NUM_HASHES]> = script_hashes
            .iter()
            .map(|sh| pir_core::hash::derive_groups_3(sh, k))
            .collect();
        let rounds = pir_core::pbc::pbc_plan_rounds(&groups_per_sh, k, NUM_HASHES, 500);

        let mut results: Vec<Option<IndexResult>> =
            (0..script_hashes.len()).map(|_| None).collect();
        // INDEX Merkle traces: always `INDEX_CUCKOO_NUM_HASHES = 2` entries
        // per scripthash so Merkle item-count is uniform across found /
        // not-found / whale (CLAUDE.md: "Merkle INDEX Item-Count Symmetry").
        let mut index_traces: Vec<IndexBinMerkle> =
            Vec::with_capacity(script_hashes.len() * INDEX_CUCKOO_NUM_HASHES);
        let mut rng = SimpleRng::new();

        for (round_id, round) in rounds.iter().enumerate() {
            let mut group_to_sh: HashMap<usize, usize> = HashMap::new();
            for &(sh_idx, group) in round {
                group_to_sh.insert(group, sh_idx);
            }

            // Generate 2*K queries: [g0_h0, g0_h1, g1_h0, g1_h1, ...]
            let mut query_bins: Vec<u64> = Vec::with_capacity(2 * k);
            for g in 0..k {
                for h in 0..INDEX_CUCKOO_NUM_HASHES {
                    let bin = if let Some(&sh_idx) = group_to_sh.get(&g) {
                        let key = pir_core::hash::derive_cuckoo_key(master_seed, g, h);
                        pir_core::hash::cuckoo_hash(&script_hashes[sh_idx], key, bins) as u64
                    } else {
                        rng.next_u64() % bins as u64
                    };
                    query_bins.push(bin);
                }
            }

            // Encrypt queries.
            let index_client = self.get_level_client(db_info.db_id, false)?;
            let mut queries = Vec::with_capacity(2 * k);
            for &bin in &query_bins {
                queries.push(index_client.generate_query(bin));
            }

            // Send and receive exactly once. An LRU eviction fails the V1
            // session closed; register/replay would violate the paid grant's
            // register-once monotonic DFA.
            let msg = encode_onionpir_batch_query(
                REQ_ONIONPIR_INDEX_QUERY,
                round_id as u16,
                &queries,
                db_info.db_id,
            );
            // Per-group item count: every group sends exactly
            // INDEX_CUCKOO_NUM_HASHES queries (the same Merkle INDEX
            // Item-Count Symmetry invariant DPF / Harmony preserve).
            let items_per_group: Vec<u32> =
                (0..k).map(|_| INDEX_CUCKOO_NUM_HASHES as u32).collect();
            let batch = self
                .onionpir_batch_rpc(
                    &msg,
                    RESP_ONIONPIR_INDEX_RESULT,
                    round_id as u16,
                    db_info.db_id,
                    "RESP_ONIONPIR_INDEX_RESULT",
                    RoundKind::Index,
                    &items_per_group,
                )
                .await?;

            // Decrypt both cuckoo positions for every real scripthash in this
            // round. We DO NOT early-exit on match — both bins must be tracked
            // so the INDEX Merkle leaf count is 2 per query regardless of
            // outcome (see CLAUDE.md "Merkle INDEX Item-Count Symmetry"). The
            // second decrypt costs ~100ms FHE but closes the side channel
            // where sibling-round pass counts would otherwise leak
            // found-vs-not-found and h-position.
            let index_client = self.get_level_client(db_info.db_id, false)?;
            for &(sh_idx, group) in round {
                let tag = pir_core::hash::compute_tag(tag_seed, &script_hashes[sh_idx]);
                for h in 0..INDEX_CUCKOO_NUM_HASHES {
                    let qi = group * INDEX_CUCKOO_NUM_HASHES + h;
                    if qi >= batch.len() {
                        return Err(PirError::Protocol(format!(
                            "result batch truncated: qi={} len={}",
                            qi,
                            batch.len()
                        )));
                    }
                    let bin = query_bins[qi];
                    // OnionPIRv2 port (commit 2): unpack the raw plaintext
                    // returned by `decrypt_response`. Replaces the
                    // pre-port API which returned entry bytes for the
                    // given bin index directly. `entry` is now
                    // `params.entry_size` bytes (3328 with the default
                    // post-port config; was 3840 pre-port). Downstream
                    // PACKED_ENTRY_SIZE-based slicing remains until
                    // commit 5 sweeps capacity math.
                    let _ = bin;
                    let raw_pt = index_client.decrypt_response(&batch[qi]);
                    let pinfo = onionpir::params_info(bins as u64);
                    let entry = pir_core::onion_unpack::unpack_onion_plaintext(
                        &raw_pt,
                        pinfo.poly_degree as usize,
                        pinfo.entry_size as usize,
                    )
                    .ok_or_else(|| {
                        PirError::Protocol(format!(
                            "onion_unpack rejected INDEX plaintext (len={} N={} es={})",
                            raw_pt.len(),
                            pinfo.poly_degree,
                            pinfo.entry_size
                        ))
                    })?;

                    // Emit a Merkle trace for EVERY probed bin (not just the
                    // matching one). The Phase-3 per-group OnionPIR Merkle
                    // keys leaves by `(pbc_group, bin)`: `group` selects the
                    // per-group INDEX tree, `bin` is the leaf index in it.
                    //
                    // OnionPIRv2 port (commit 5): the bin is exactly
                    // `pinfo.entry_size` bytes after `onion_unpack`, so
                    // the pre-port `if len >= PACKED_ENTRY_SIZE { trim }
                    // else { full }` guard collapses to just the full
                    // slice. We hash the full bin unconditionally.
                    let entry_for_hash: &[u8] = &entry;
                    index_traces.push(IndexBinMerkle {
                        sh_idx,
                        pbc_group: group,
                        bin: bin as u32,
                        bin_hash: pir_core::merkle::sha256(entry_for_hash),
                    });

                    // Only record the first matching index result — the
                    // second probe is tracking-only for Merkle symmetry.
                    if results[sh_idx].is_none() {
                        if let Some(ir) = scan_index_bin(
                            &entry,
                            tag,
                            params.index_slots_per_bin,
                            params.index_slot_size,
                        ) {
                            results[sh_idx] = Some(ir);
                        }
                    }
                }
            }
        }

        Ok((results, index_traces))
    }

    #[cfg(feature = "onion")]
    #[tracing::instrument(level = "trace", skip_all, fields(backend = "onion", db_id = db_info.db_id))]
    async fn query_chunk_level(
        &mut self,
        index_results: &[Option<IndexResult>],
        db_info: &DatabaseInfo,
        params: &OnionDbParams,
    ) -> PirResult<(
        HashMap<u32, Vec<u8>>,
        HashMap<u32, (Hash256, usize, u32)>,
        Vec<Vec<u32>>,
    )> {
        // Collect each query's *real* chunk entry_ids. Phase 3 / WS-A
        // removed the M=16 chunk-Merkle padding (see docs/VERIFICATION_OVERVIEW.md):
        // a query now fetches its real chunk count — found-with-N → N
        // reals, not-found / whale → 0. The newly-admitted leak (per-query
        // real chunk count becomes observable) is intended and tracked in
        // the leakage spec; ~99% of addresses have exactly 1 chunk.
        //
        // Round-presence is preserved *separately* from M-padding:
        //   - CHUNK PIR round-presence — kept below: every non-empty batch
        //     issues ≥1 K_CHUNK CHUNK PIR round even when all-not-found.
        //   - CHUNK-Merkle round-presence — kept by the per-group verifier
        //     (`onion_merkle::verify_sub_tree` always issues ≥1 all-dummy
        //     sibling pass for the DATA tree).
        // Together they keep found-vs-not-found hidden without M=16.
        let total_packed = params.total_packed.max(1) as u32;

        let mut unique: Vec<u32> = Vec::new();
        let mut seen: HashSet<u32> = HashSet::new();
        let mut owned_per_query: Vec<Vec<u32>> = Vec::with_capacity(index_results.len());

        for ir_opt in index_results.iter() {
            let real_chunks: Vec<u32> = match ir_opt {
                Some(ir) if ir.num_entries > 0 => (0..ir.num_entries as u32)
                    .map(|i| ir.entry_id + i)
                    .collect(),
                _ => Vec::new(),
            };
            for &eid in &real_chunks {
                if eid < total_packed && seen.insert(eid) {
                    unique.push(eid);
                }
            }
            owned_per_query.push(real_chunks);
        }

        log::info!(
            "[PIR-AUDIT] OnionPIR CHUNK: {} queries, {} unique real chunk entry_ids",
            index_results.len(),
            unique.len(),
        );

        let mut decrypted: HashMap<u32, Vec<u8>> = HashMap::new();
        // entry_id → (SHA256(decrypted_bin), pbc_group, bin) — the per-group
        // OnionPIR Merkle leaf key. Populated per DATA bin fetched; later
        // fed to the per-group Merkle verifier.
        let mut data_merkle: HashMap<u32, (Hash256, usize, u32)> = HashMap::new();

        // 🔒 CHUNK Round-Presence Symmetry (CLAUDE.md / docs/VERIFICATION_OVERVIEW.md
        // cross-cutting invariant C.1). A genuinely empty batch (no
        // scripthashes) has nothing to hide → no CHUNK round. But a batch
        // whose scripthashes are *all* not-found / whale (`unique` empty)
        // MUST still issue exactly one all-dummy K_CHUNK CHUNK PIR round —
        // skipping it would leak found-vs-not-found via CHUNK round absence.
        if index_results.is_empty() {
            return Ok((decrypted, data_merkle, owned_per_query));
        }

        let chunk_k = db_info.chunk_k as usize;
        let chunk_bins = db_info.chunk_bins as usize;

        // Plan PBC rounds over the real chunk entry_ids. An all-not-found
        // batch has `unique` empty → no real PBC rounds; substitute a single
        // empty round so exactly one all-dummy K_CHUNK CHUNK PIR round still
        // goes out (round-presence, above). The round body handles an empty
        // `round` natively — every group falls through to a random dummy.
        let rounds: Vec<Vec<(usize, usize)>> = if unique.is_empty() {
            vec![Vec::new()]
        } else {
            let entry_groups: Vec<[usize; NUM_HASHES]> = unique
                .iter()
                .map(|&eid| pir_core::hash::derive_int_groups_3(eid, chunk_k))
                .collect();
            pir_core::pbc::pbc_plan_rounds(&entry_groups, chunk_k, NUM_HASHES, 500)
        };

        // The reverse index only locates *real* entries; an all-not-found
        // batch never indexes it, so skip the (total-entries-scale) build.
        let reverse_index: Vec<Vec<u32>> = if unique.is_empty() {
            Vec::new()
        } else {
            build_chunk_reverse_index(params.total_packed, chunk_k)
        };

        let mut cuckoo_cache: HashMap<usize, Vec<u32>> = HashMap::new();
        let mut rng = SimpleRng::new();

        for (round_id, round) in rounds.iter().enumerate() {
            struct Q {
                entry_id: u32,
                group: usize,
                bin: usize,
            }
            let mut round_queries: Vec<Q> = Vec::new();
            let mut group_bin: HashMap<usize, usize> = HashMap::new();

            for &(ei, group) in round {
                let eid = unique[ei];
                cuckoo_cache.entry(group).or_insert_with(|| {
                    build_chunk_cuckoo_for_group(group, &reverse_index, chunk_bins)
                });

                let keys = chunk_derive_keys(group);
                let bin =
                    find_in_chunk_cuckoo(cuckoo_cache.get(&group).unwrap(), eid, &keys, chunk_bins)
                        .ok_or_else(|| {
                            PirError::InvalidState(format!(
                                "entry_id {} not in chunk cuckoo for group {}",
                                eid, group
                            ))
                        })?;

                round_queries.push(Q {
                    entry_id: eid,
                    group,
                    bin,
                });
                group_bin.insert(group, bin);
            }

            // Generate K_CHUNK queries with dummies in empty groups.
            let chunk_client = self.get_level_client(db_info.db_id, true)?;
            let mut queries = Vec::with_capacity(chunk_k);
            for g in 0..chunk_k {
                let bin = if let Some(&b) = group_bin.get(&g) {
                    b as u64
                } else {
                    rng.next_u64() % chunk_bins as u64
                };
                queries.push(chunk_client.generate_query(bin));
            }

            // Same one-shot eviction behavior as the INDEX round — see
            // `onionpir_batch_rpc` for the reasoning.
            let msg = encode_onionpir_batch_query(
                REQ_ONIONPIR_CHUNK_QUERY,
                round_id as u16,
                &queries,
                db_info.db_id,
            );
            // OnionPIR CHUNK sends one query per group (different from
            // DPF / Harmony which send `CHUNK_CUCKOO_NUM_HASHES = 2`
            // per group); items[g] = 1 captures that wire shape.
            let items_per_group: Vec<u32> = (0..chunk_k).map(|_| 1u32).collect();
            let batch = self
                .onionpir_batch_rpc(
                    &msg,
                    RESP_ONIONPIR_CHUNK_RESULT,
                    round_id as u16,
                    db_info.db_id,
                    "RESP_ONIONPIR_CHUNK_RESULT",
                    RoundKind::Chunk,
                    &items_per_group,
                )
                .await?;

            let chunk_client = self.get_level_client(db_info.db_id, true)?;
            for q in &round_queries {
                if q.group >= batch.len() {
                    return Err(PirError::Protocol(format!(
                        "chunk result truncated: group={} len={}",
                        q.group,
                        batch.len()
                    )));
                }
                // OnionPIRv2 port (commit 2): see INDEX block above —
                // unpack the raw plaintext.
                let _ = q.bin;
                let raw_pt = chunk_client.decrypt_response(&batch[q.group]);
                let pinfo = onionpir::params_info(chunk_bins as u64);
                let bytes = pir_core::onion_unpack::unpack_onion_plaintext(
                    &raw_pt,
                    pinfo.poly_degree as usize,
                    pinfo.entry_size as usize,
                )
                .ok_or_else(|| {
                    PirError::Protocol(format!(
                        "onion_unpack rejected CHUNK plaintext (len={} N={} es={})",
                        raw_pt.len(),
                        pinfo.poly_degree,
                        pinfo.entry_size
                    ))
                })?;
                // OnionPIRv2 port (commit 5): after `onion_unpack`,
                // `bytes.len() == pinfo.entry_size` exactly, so the
                // pre-port short-bytes guard collapses to a redundant
                // equality. We keep an assertion for defensive sanity
                // — a server bug returning a wrong-shape plaintext
                // would otherwise propagate silently into the Merkle
                // hashes.
                debug_assert_eq!(
                    bytes.len(),
                    pinfo.entry_size as usize,
                    "CHUNK decrypt produced {} bytes, expected entry_size={}",
                    bytes.len(),
                    pinfo.entry_size
                );
                let packed: &[u8] = &bytes;
                decrypted.insert(q.entry_id, packed.to_vec());
                // DATA Merkle trace: one leaf per fetched entry_id, keyed by
                // `(pbc_group, bin)` for the per-group OnionPIR Merkle —
                // `q.group` selects the per-group DATA tree, `q.bin` is the
                // leaf index within it.
                data_merkle.insert(
                    q.entry_id,
                    (pir_core::merkle::sha256(packed), q.group, q.bin as u32),
                );
            }
        }

        Ok((decrypted, data_merkle, owned_per_query))
    }
}

// ─── PirClient trait impl ───────────────────────────────────────────────────

#[async_trait]
impl PirClient for OnionClient {
    fn backend_type(&self) -> PirBackendType {
        PirBackendType::Onion
    }

    #[tracing::instrument(level = "info", skip_all, fields(backend = "onion", server = %self.server_url))]
    async fn connect(&mut self) -> PirResult<()> {
        // Match DPF/Harmony semantics: duplicate connect on a complete live
        // session is idempotent, not an implicit transport replacement.
        if self.is_connected() {
            return Ok(());
        }
        self.invalidate_session_bindings();

        log::info!("Connecting to OnionPIR server: {}", self.server_url);

        // Native → tokio-tungstenite; WASM → web-sys WebSocket. OnionPIR
        // has a single server so no try_join is needed.
        #[cfg(not(target_arch = "wasm32"))]
        let conn: Box<dyn PirTransport> =
            { Box::new(WsConnection::connect(&self.server_url).await?) };
        #[cfg(target_arch = "wasm32")]
        let conn: Box<dyn PirTransport> = {
            use crate::wasm_transport::WasmWebSocketTransport;
            Box::new(WasmWebSocketTransport::connect(&self.server_url).await?)
        };

        self.conn = Some(conn);
        // Propagate any installed recorder to the fresh transport so
        // per-frame byte counts start flowing immediately.
        if let Some(rec) = self.metrics_recorder.clone() {
            if let Some(ref mut c) = self.conn {
                c.set_metrics_recorder(Some(rec), "onion");
            }
        }
        self.fire_connect(&self.server_url);
        #[cfg(not(feature = "onion"))]
        log::warn!(
            "OnionPIR client connected without the `onion` cargo feature — \
             queries will fail closed."
        );
        Ok(())
    }

    #[tracing::instrument(level = "info", skip_all, fields(backend = "onion"))]
    async fn disconnect(&mut self) -> PirResult<()> {
        if let Some(ref mut conn) = self.conn {
            let _ = conn.close().await;
        }
        self.conn = None;
        self.invalidate_session_bindings();
        self.fire_disconnect();
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.conn.is_some()
    }

    #[tracing::instrument(level = "debug", skip_all, fields(backend = "onion"))]
    async fn fetch_catalog(&mut self) -> PirResult<DatabaseCatalog> {
        if !self.is_connected() {
            return Err(PirError::NotConnected);
        }
        self.fetch_server_info().await?;
        let catalog = self
            .catalog
            .clone()
            .expect("fetch_server_info populates catalog");
        self.verified_roots.reconcile_catalog(&catalog);
        self.verified_tree_tops
            .retain(|db_id| self.verified_roots.get(*db_id).is_some());
        Ok(catalog)
    }

    fn cached_catalog(&self) -> Option<&DatabaseCatalog> {
        self.catalog.as_ref()
    }

    fn compute_sync_plan(
        &self,
        catalog: &DatabaseCatalog,
        last_height: Option<u32>,
    ) -> PirResult<SyncPlan> {
        compute_sync_plan(catalog, last_height)
    }

    #[tracing::instrument(level = "info", skip_all, fields(backend = "onion", num_queries = script_hashes.len(), last_height = ?last_height))]
    async fn sync(
        &mut self,
        script_hashes: &[ScriptHash],
        last_height: Option<u32>,
    ) -> PirResult<SyncResult> {
        if !self.is_connected() {
            self.connect().await?;
        }
        let catalog = match &self.catalog {
            Some(c) => c.clone(),
            None => self.fetch_catalog().await?,
        };
        let plan = self.compute_sync_plan(&catalog, last_height)?;
        self.sync_with_plan(script_hashes, &plan, None).await
    }

    #[tracing::instrument(level = "debug", skip_all, fields(backend = "onion", num_queries = script_hashes.len(), num_steps = plan.steps.len(), target_height = plan.target_height, is_fresh_sync = plan.is_fresh_sync))]
    async fn sync_with_plan(
        &mut self,
        script_hashes: &[ScriptHash],
        plan: &SyncPlan,
        cached_results: Option<&[Option<QueryResult>]>,
    ) -> PirResult<SyncResult> {
        if plan.is_empty() {
            return Ok(SyncResult {
                results: cached_results
                    .map(|r| r.to_vec())
                    .unwrap_or_else(|| vec![None; script_hashes.len()]),
                synced_height: plan.target_height,
                was_fresh_sync: false,
            });
        }

        self.verified_roots.require_plan(plan)?;

        let catalog = self
            .catalog
            .clone()
            .ok_or_else(|| PirError::InvalidState("no catalog".into()))?;
        let mut merged: Vec<Option<QueryResult>> = cached_results
            .map(|r| r.to_vec())
            .unwrap_or_else(|| vec![None; script_hashes.len()]);

        for step in &plan.steps {
            self.preflight_trusted_tree_tops(step.db_id).await?;
        }

        for (step_idx, step) in plan.steps.iter().enumerate() {
            log::info!(
                "[{}/{}] OnionPIR querying {} (db_id={}, height={})",
                step_idx + 1,
                plan.steps.len(),
                step.name,
                step.db_id,
                step.tip_height
            );

            let db_info = catalog
                .get(step.db_id)
                .ok_or(PirError::DatabaseNotFound(step.db_id))?
                .clone();

            let step_results = self.execute_step(script_hashes, step, &db_info).await?;

            if step.is_full() {
                merged = step_results;
            } else {
                merged = merge_delta_batch(&merged, &step_results)?;
            }
        }

        Ok(SyncResult {
            results: merged,
            synced_height: plan.target_height,
            was_fresh_sync: plan.is_fresh_sync,
        })
    }

    #[tracing::instrument(level = "debug", skip_all, fields(backend = "onion", db_id, num_queries = script_hashes.len()))]
    async fn query_batch(
        &mut self,
        script_hashes: &[ScriptHash],
        db_id: u8,
    ) -> PirResult<Vec<Option<QueryResult>>> {
        if !self.is_connected() {
            return Err(PirError::NotConnected);
        }
        let catalog = self
            .catalog
            .clone()
            .ok_or_else(|| PirError::InvalidState("no catalog".into()))?;
        let db_info = catalog
            .get(db_id)
            .ok_or(PirError::DatabaseNotFound(db_id))?
            .clone();
        self.verified_roots.require_db(db_id)?;
        self.preflight_trusted_tree_tops(db_id).await?;
        // Fire the query lifecycle callbacks so a recorder can time
        // the end-to-end round. `fire_*` is a no-op absent a recorder;
        // the `Option<Instant>` returned by `fire_query_start` carries
        // the start moment when a recorder is installed and is `None`
        // otherwise (zero-overhead no-recorder path).
        let num_queries = script_hashes.len();
        let started_at = self.fire_query_start(db_id, num_queries);
        let step = SyncStep::from_db_info(&db_info);
        let result = self.execute_step(script_hashes, &step, &db_info).await;
        self.fire_query_end(db_id, num_queries, result.is_ok(), started_at);
        result
    }
}

// ─── INDEX-level scan result ────────────────────────────────────────────────

#[cfg(feature = "onion")]
#[derive(Clone, Debug)]
struct IndexResult {
    entry_id: u32,
    byte_offset: u16,
    num_entries: u8,
}

/// Per-group INDEX Merkle trace entry.
///
/// Emitted for **every** probed cuckoo bin so the INDEX leaf count is uniform
/// across found / not-found / whale — see CLAUDE.md's
/// "Merkle INDEX Item-Count Symmetry" invariant. One of these is pushed per
/// INDEX bin we inspect.
///
/// Keyed by `(pbc_group, bin)` for the Phase-3 per-group OnionPIR Merkle: the
/// PBC group selects the per-group tree, `bin` is the leaf index within it.
#[cfg(feature = "onion")]
#[derive(Clone, Debug)]
struct IndexBinMerkle {
    /// Back-reference to which scripthash (query index) this bin belongs to.
    sh_idx: usize,
    /// PBC group index (`0..index_k`) — selects the per-group INDEX tree.
    pbc_group: usize,
    /// Cuckoo bin within the group = leaf index in that group's per-group tree.
    bin: u32,
    /// `SHA256(decrypted_bin)` — OnionPIR's no-prefix leaf hash (§2e).
    bin_hash: Hash256,
}

/// Scan a decrypted INDEX bin (slots_per_bin × slot_size bytes) for a tag.
/// OnionPIR slot layout: `tag(8) | entry_id(4) | byte_offset(2) | num_entries(1)`.
#[cfg(feature = "onion")]
fn scan_index_bin(
    entry_bytes: &[u8],
    tag: u64,
    slots_per_bin: usize,
    slot_size: usize,
) -> Option<IndexResult> {
    for slot in 0..slots_per_bin {
        let off = slot * slot_size;
        if off + slot_size > entry_bytes.len() {
            break;
        }
        let slot_tag = u64::from_le_bytes(entry_bytes[off..off + 8].try_into().ok()?);
        if slot_tag == tag && slot_tag != 0 {
            let entry_id = u32::from_le_bytes(entry_bytes[off + 8..off + 12].try_into().ok()?);
            let byte_offset = u16::from_le_bytes(entry_bytes[off + 12..off + 14].try_into().ok()?);
            let num_entries = entry_bytes[off + 14];
            return Some(IndexResult {
                entry_id,
                byte_offset,
                num_entries,
            });
        }
    }
    None
}

/// Stitch raw entry bytes into a single UTXO data blob starting at byte_offset.
#[cfg(feature = "onion")]
fn assemble_entry_bytes(
    ir: &IndexResult,
    chunk_data: &HashMap<u32, Vec<u8>>,
    db_id: u8,
) -> PirResult<Vec<u8>> {
    // OnionPIRv2 port (commit 5): capacity hint derived from runtime
    // params instead of the pre-port `PACKED_ENTRY_SIZE = 3840` constant.
    let mut out = Vec::with_capacity(ir.num_entries as usize * packed_entry_size());
    for i in 0..ir.num_entries as u32 {
        let eid = ir.entry_id + i;
        let entry = chunk_data.get(&eid).ok_or_else(|| {
            PirError::InvalidState(format!(
                "missing decrypted entry_id {} (db_id={})",
                eid, db_id
            ))
        })?;
        if i == 0 {
            let start = ir.byte_offset as usize;
            if start > entry.len() {
                return Err(PirError::Protocol(format!(
                    "byte_offset {} exceeds entry size {}",
                    start,
                    entry.len()
                )));
            }
            out.extend_from_slice(&entry[start..]);
        } else {
            out.extend_from_slice(entry);
        }
    }
    Ok(out)
}

/// Decode UTXO entries from assembled entry bytes (varint-encoded).
///
/// Layout: `varint(num_utxos) | [txid(32) | varint(vout) | varint(amount)] * N`.
///
/// The entry bytes are server-controlled and decoded *before* Merkle
/// verification, so a malformed varint is a `PirError::Decode`, never a
/// panic (C2, docs/CODE_REVIEW_2026-06.md).
#[cfg(feature = "onion")]
fn decode_utxo_entries(data: &[u8]) -> PirResult<Vec<UtxoEntry>> {
    let mut entries = Vec::new();
    if data.is_empty() {
        return Ok(entries);
    }
    let mut pos = 0;
    let (num_utxos, vr) = pir_core::codec::try_read_varint(&data[pos..])
        .map_err(|e| PirError::Decode(format!("UTXO count varint: {}", e)))?;
    pos += vr;

    for _ in 0..num_utxos {
        if pos + 32 > data.len() {
            break;
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        if pos >= data.len() {
            break;
        }
        let (vout, vr) = pir_core::codec::try_read_varint(&data[pos..])
            .map_err(|e| PirError::Decode(format!("UTXO vout varint: {}", e)))?;
        pos += vr;
        if pos >= data.len() {
            break;
        }
        let (amount, ar) = pir_core::codec::try_read_varint(&data[pos..])
            .map_err(|e| PirError::Decode(format!("UTXO amount varint: {}", e)))?;
        pos += ar;

        entries.push(UtxoEntry {
            txid,
            vout: vout as u32,
            amount_sats: amount,
        });
    }

    Ok(entries)
}

// ─── Client-side CHUNK cuckoo (6-hash, slots_per_bin=1) ─────────────────────

#[cfg(feature = "onion")]
fn chunk_derive_keys(group_id: usize) -> [u64; CHUNK_CUCKOO_NUM_HASHES] {
    let mut keys = [0u64; CHUNK_CUCKOO_NUM_HASHES];
    for (h, k) in keys.iter_mut().enumerate() {
        *k = pir_core::hash::splitmix64(
            CHUNK_CUCKOO_SEED
                .wrapping_add((group_id as u64).wrapping_mul(pir_core::hash::GOLDEN_RATIO))
                .wrapping_add((h as u64).wrapping_mul(pir_core::hash::CUCKOO_KEY_MIX)),
        );
    }
    keys
}

#[cfg(feature = "onion")]
#[inline]
fn chunk_cuckoo_hash(entry_id: u32, key: u64, num_bins: usize) -> usize {
    (pir_core::hash::splitmix64((entry_id as u64) ^ key) % num_bins as u64) as usize
}

#[cfg(feature = "onion")]
fn build_chunk_reverse_index(total_entries: usize, k_chunk: usize) -> Vec<Vec<u32>> {
    let mut index: Vec<Vec<u32>> = (0..k_chunk).map(|_| Vec::new()).collect();
    for eid in 0..total_entries as u32 {
        let groups = pir_core::hash::derive_int_groups_3(eid, k_chunk);
        for &g in &groups {
            index[g].push(eid);
        }
    }
    index
}

#[cfg(feature = "onion")]
fn build_chunk_cuckoo_for_group(
    group_id: usize,
    reverse_index: &[Vec<u32>],
    bins_per_table: usize,
) -> Vec<u32> {
    let entries = &reverse_index[group_id];
    let keys = chunk_derive_keys(group_id);
    let mut table = vec![EMPTY; bins_per_table];

    for &entry_id in entries {
        // Try primary placements.
        let mut placed = false;
        for &key in keys.iter() {
            let bin = chunk_cuckoo_hash(entry_id, key, bins_per_table);
            if table[bin] == EMPTY {
                table[bin] = entry_id;
                placed = true;
                break;
            }
        }
        if placed {
            continue;
        }

        // Kick loop — mirrors reference implementation exactly so bin
        // assignments match the server.
        let mut current_id = entry_id;
        let mut current_hash_fn = 0;
        let mut current_bin = chunk_cuckoo_hash(entry_id, keys[0], bins_per_table);
        let mut success = false;

        for kick in 0..CHUNK_CUCKOO_MAX_KICKS {
            let evicted = table[current_bin];
            table[current_bin] = current_id;

            for h in 0..CHUNK_CUCKOO_NUM_HASHES {
                let try_h = (current_hash_fn + 1 + h) % CHUNK_CUCKOO_NUM_HASHES;
                let bin = chunk_cuckoo_hash(evicted, keys[try_h], bins_per_table);
                if bin == current_bin {
                    continue;
                }
                if table[bin] == EMPTY {
                    table[bin] = evicted;
                    success = true;
                    break;
                }
            }
            if success {
                break;
            }

            let alt_h = (current_hash_fn + 1 + kick % (CHUNK_CUCKOO_NUM_HASHES - 1))
                % CHUNK_CUCKOO_NUM_HASHES;
            let alt_bin = chunk_cuckoo_hash(evicted, keys[alt_h], bins_per_table);
            let final_bin = if alt_bin == current_bin {
                let h2 = (alt_h + 1) % CHUNK_CUCKOO_NUM_HASHES;
                chunk_cuckoo_hash(evicted, keys[h2], bins_per_table)
            } else {
                alt_bin
            };

            current_id = evicted;
            current_hash_fn = alt_h;
            current_bin = final_bin;
        }

        if !success {
            // Don't panic — let the caller surface this as a protocol error.
            log::error!(
                "OnionPIR client-side cuckoo failed for entry_id={} group={}",
                entry_id,
                group_id
            );
        }
    }

    table
}

#[cfg(feature = "onion")]
fn find_in_chunk_cuckoo(
    table: &[u32],
    entry_id: u32,
    keys: &[u64; CHUNK_CUCKOO_NUM_HASHES],
    bins_per_table: usize,
) -> Option<usize> {
    for &key in keys.iter() {
        let bin = chunk_cuckoo_hash(entry_id, key, bins_per_table);
        if table[bin] == entry_id {
            return Some(bin);
        }
    }
    None
}

// ─── Wire encoding / decoding ──────────────────────────────────────────────

/// Encode a `RegisterKeysMsg`.
#[cfg(feature = "onion")]
fn encode_register_keys(galois: &[u8], gsw: &[u8], db_id: u8) -> Vec<u8> {
    let trailing = if db_id != 0 { 1 } else { 0 };
    let payload_len = 1 + 4 + galois.len() + 4 + gsw.len() + trailing;
    let mut buf = Vec::with_capacity(4 + payload_len);
    buf.extend_from_slice(&(payload_len as u32).to_le_bytes());
    buf.push(REQ_REGISTER_KEYS);
    buf.extend_from_slice(&(galois.len() as u32).to_le_bytes());
    buf.extend_from_slice(galois);
    buf.extend_from_slice(&(gsw.len() as u32).to_le_bytes());
    buf.extend_from_slice(gsw);
    if db_id != 0 {
        buf.push(db_id);
    }
    buf
}

/// Encode an `OnionPirBatchQuery` for INDEX (0x51) or CHUNK (0x52) variants.
#[cfg(feature = "onion")]
fn encode_onionpir_batch_query(
    variant: u8,
    round_id: u16,
    queries: &[Vec<u8>],
    db_id: u8,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(variant);
    payload.extend_from_slice(&round_id.to_le_bytes());
    payload.push(queries.len() as u8);
    for q in queries {
        payload.extend_from_slice(&(q.len() as u32).to_le_bytes());
        payload.extend_from_slice(q);
    }
    if db_id != 0 {
        payload.push(db_id);
    }
    let mut msg = Vec::with_capacity(4 + payload.len());
    msg.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    msg.extend_from_slice(&payload);
    msg
}

/// Detect whether an OnionPIR batch response signals that the server
/// has lost our keys.
///
/// The server-side `unified_server` loop wraps each `answer_query`
/// call in `catch_unwind` and returns `Vec::new()` on panic. When the
/// SEAL `KeyStore` has evicted our `client_id` (after 100 concurrent
/// clients, FIFO), every `answer_query` for us throws inside SEAL →
/// panics → returns empty. Since all queries in one batch share a
/// `client_id`, either every slot is empty (we've been evicted) or
/// every slot carries a real ciphertext. An all-empty batch with ≥1
/// slot is therefore an unambiguous eviction signal; an empty-length
/// batch is not (it would indicate a decode error in the outer frame,
/// which is handled elsewhere).
///
/// Kept as a free-standing function (rather than `impl OnionClient`)
/// so it can be unit-tested without the `onion` cargo feature.
/// The function itself has no FHE dependencies; the `#[allow(dead_code)]`
/// attribute below silences the spurious "never used" warning on
/// non-onion builds, where the only call sites are cfg-gated out.
#[cfg_attr(not(feature = "onion"), allow(dead_code))]
pub(crate) fn batch_looks_evicted(batch: &[Vec<u8>]) -> bool {
    !batch.is_empty() && batch.iter().all(|r| r.is_empty())
}

#[cfg(feature = "onion")]
fn decode_register_keys_ack(body: &[u8]) -> PirResult<()> {
    const CONTEXT: &str = "OnionPIR key registration";
    if body.is_empty() {
        return Err(PirError::Decode(format!("{CONTEXT}: empty response body")));
    }
    reject_error_response(body, CONTEXT)?;
    if body[0] != RESP_KEYS_ACK {
        return Err(PirError::UnexpectedResponse {
            expected: "RESP_KEYS_ACK",
            actual: format!("0x{:02x}", body[0]),
        });
    }
    if body.len() != 1 {
        return Err(PirError::Decode(format!(
            "{CONTEXT}: trailing bytes after ACK: {}",
            body.len() - 1
        )));
    }
    Ok(())
}

/// Decode an `OnionPirBatchResult` payload (after the variant byte).
///
/// Wire format: `[2B round_id][1B num_groups]({ [4B len][bytes] })*`.
#[cfg(feature = "onion")]
fn decode_onionpir_batch_result(
    data: &[u8],
    expected_round_id: u16,
    context: &str,
) -> PirResult<Vec<Vec<u8>>> {
    if data.len() < 3 {
        return Err(PirError::Decode(format!(
            "{context}: result batch too short"
        )));
    }
    let round_id = u16::from_le_bytes(data[..2].try_into().unwrap());
    if round_id != expected_round_id {
        return Err(PirError::Protocol(format!(
            "{context}: result round_id mismatch: expected {expected_round_id}, got {round_id}"
        )));
    }
    let mut pos = 2;
    let num_groups = data[pos] as usize;
    pos += 1;
    let mut results = Vec::with_capacity(num_groups);
    for _ in 0..num_groups {
        let length_end = pos
            .checked_add(4)
            .ok_or_else(|| PirError::Decode(format!("{context}: result length overflow")))?;
        if length_end > data.len() {
            return Err(PirError::Decode(format!("{context}: truncated result len")));
        }
        let len = u32::from_le_bytes(data[pos..length_end].try_into().unwrap()) as usize;
        pos = length_end;
        let result_end = pos
            .checked_add(len)
            .ok_or_else(|| PirError::Decode(format!("{context}: result data length overflow")))?;
        if result_end > data.len() {
            return Err(PirError::Decode(format!(
                "{context}: truncated result bytes"
            )));
        }
        results.push(data[pos..result_end].to_vec());
        pos = result_end;
    }
    if pos != data.len() {
        return Err(PirError::Decode(format!(
            "{context}: trailing bytes after result batch: {}",
            data.len() - pos
        )));
    }
    Ok(results)
}

#[cfg(feature = "onion")]
fn decode_onionpir_batch_response(
    body: &[u8],
    expected_variant: u8,
    expected_round_id: u16,
    expected_results: usize,
    context: &'static str,
) -> PirResult<Vec<Vec<u8>>> {
    if body.is_empty() {
        return Err(PirError::Decode(format!("{context}: empty response body")));
    }
    reject_error_response(body, context)?;
    if body[0] != expected_variant {
        return Err(PirError::UnexpectedResponse {
            expected: context,
            actual: format!("0x{:02x}", body[0]),
        });
    }
    let results = decode_onionpir_batch_result(&body[1..], expected_round_id, context)?;
    if results.len() != expected_results {
        return Err(PirError::Protocol(format!(
            "{context}: result count mismatch: expected {expected_results}, got {}",
            results.len()
        )));
    }
    Ok(results)
}

// ─── JSON parsing (minimal, no serde) ───────────────────────────────────────

/// Parse `"key":<number>` or `"key":"0xHEX"` out of a JSON string.
fn json_u64(json: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{}\":", key);
    let pos = json.find(&needle)?;
    let start = pos + needle.len();
    let rest = json[start..].trim_start();
    if let Some(rest) = rest.strip_prefix('"') {
        let end = rest.find('"')?;
        let hex = &rest[..end];
        u64::from_str_radix(hex.trim_start_matches("0x"), 16).ok()
    } else {
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        rest[..end].parse().ok()
    }
}

/// Find a JSON sub-object `"key":{ ... }` and return its inner slice.
fn extract_json_object<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{}\":", key);
    let start = json.find(&needle)?;
    let brace = json[start..].find('{')? + start;
    let mut depth = 0;
    let mut end = brace;
    for (i, c) in json[brace..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = brace + i + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    Some(&json[brace..end])
}

/// Parse per-DB OnionPIR params from the JSON info response.
///
/// Looks at the top-level `"onionpir"` (main DB, db_id=0) and each entry in
/// `"databases":[ ... ]` with a nested `"onionpir"` object.
fn parse_onion_params_per_db(json: &str) -> std::collections::HashMap<u8, OnionDbParams> {
    let mut out = std::collections::HashMap::new();

    // Main DB (db_id=0) — only if top-level has an onionpir sub-object.
    if let Some(opi) = extract_json_object(json, "onionpir") {
        if let Some(p) = parse_onion_params_from_opi(opi) {
            out.insert(0u8, p);
        }
    }

    // Per-DB entries. The regex-free path: scan "databases":[...] and find
    // each { db_id:.., onionpir:{...} } block.
    if let Some(dbs) = extract_json_object_array(json, "databases") {
        for entry in dbs {
            let id = match json_u64(entry, "db_id") {
                Some(v) => v as u8,
                None => continue,
            };
            if let Some(opi) = extract_json_object(entry, "onionpir") {
                if let Some(p) = parse_onion_params_from_opi(opi) {
                    out.insert(id, p);
                }
            }
        }
    }

    out
}

fn parse_onion_params_from_opi(opi: &str) -> Option<OnionDbParams> {
    Some(OnionDbParams {
        total_packed: json_u64(opi, "total_packed_entries")? as usize,
        index_slots_per_bin: json_u64(opi, "index_slots_per_bin")? as usize,
        index_slot_size: json_u64(opi, "index_slot_size")? as usize,
    })
}

/// Parse per-DB OnionPIR per-bin Merkle info from the JSON info response.
///
/// Looks for a top-level `"onionpir_merkle"` sub-object (main DB, db_id=0)
/// and each entry in `"databases":[ ... ]` with a nested `"onionpir_merkle"`
/// object. Returns an empty map if the server has no Merkle commitment at
/// all — callers treat that as "skip verification" (analogous to
/// `DatabaseInfo::has_bucket_merkle=false`).
#[cfg(feature = "onion")]
fn parse_onion_merkle_per_db(json: &str) -> std::collections::HashMap<u8, OnionMerkleInfo> {
    let mut out = std::collections::HashMap::new();

    // Main DB (db_id=0) — top-level onionpir_merkle.
    if let Some(info) = parse_onionpir_merkle(json) {
        out.insert(0u8, info);
    }

    // Per-DB entries. Each element is a full JSON object so
    // parse_onionpir_merkle can locate the nested "onionpir_merkle" sub-object
    // on its own.
    if let Some(dbs) = extract_json_object_array(json, "databases") {
        for entry in dbs {
            let id = match json_u64(entry, "db_id") {
                Some(v) => v as u8,
                None => continue,
            };
            if let Some(info) = parse_onionpir_merkle(entry) {
                out.insert(id, info);
            }
        }
    }

    out
}

/// Extract array elements of a top-level `"key":[{...},{...},...]` JSON field.
/// Returns each object (including braces) as a `&str`.
fn extract_json_object_array<'a>(json: &'a str, key: &str) -> Option<Vec<&'a str>> {
    let needle = format!("\"{}\":", key);
    let pos = json.find(&needle)?;
    let start = pos + needle.len();
    let rest = json[start..].trim_start();
    let rest = rest.strip_prefix('[')?;
    let arr_start = json.len() - rest.len();

    let mut depth = 0i32;
    let mut objs = Vec::new();
    let mut current_start: Option<usize> = None;
    for (i, c) in rest.char_indices() {
        let abs = arr_start + i;
        match c {
            '{' => {
                if depth == 0 {
                    current_start = Some(abs);
                }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    if let Some(s) = current_start.take() {
                        objs.push(&json[s..abs + 1]);
                    }
                }
            }
            ']' if depth == 0 => return Some(objs),
            _ => {}
        }
    }
    Some(objs)
}

/// Build a [`DatabaseCatalog`] from JSON info + optional DPF catalog.
///
/// Prefers DPF catalog data when present (gives real names and heights);
/// otherwise synthesizes a single full-snapshot entry per OnionPIR DB.
fn build_catalog(
    json: &str,
    onion_params: &std::collections::HashMap<u8, OnionDbParams>,
    dpf: Option<&DatabaseCatalog>,
) -> DatabaseCatalog {
    // Index OnionPIR-level params (index_bins, chunk_bins, index_k, chunk_k,
    // tag_seed) by db_id. Falls back to top-level fields if per-DB missing.
    let top_index_bins = json_u64(json, "index_bins_per_table").unwrap_or(0) as u32;
    let top_chunk_bins = json_u64(json, "chunk_bins_per_table").unwrap_or(0) as u32;
    let top_index_k = json_u64(json, "index_k").unwrap_or(75) as u8;
    let top_chunk_k = json_u64(json, "chunk_k").unwrap_or(80) as u8;
    let top_tag_seed = json_u64(json, "tag_seed").unwrap_or(0);
    let top_opi = extract_json_object(json, "onionpir");

    // Prefer DPF-catalog heights when available.
    if let Some(dc) = dpf {
        let mut dbs = Vec::with_capacity(dc.databases.len());
        for d in &dc.databases {
            if !onion_params.contains_key(&d.db_id) {
                // Skip DBs that don't have OnionPIR data on this server.
                continue;
            }
            // Override index/chunk bins with OnionPIR-specific values if present.
            let (opi_bins_idx, opi_bins_chunk, opi_index_k, opi_chunk_k, opi_tag_seed) =
                onion_level_params(
                    json,
                    d.db_id,
                    top_index_bins,
                    top_chunk_bins,
                    top_index_k,
                    top_chunk_k,
                    top_tag_seed,
                );
            dbs.push(DatabaseInfo {
                db_id: d.db_id,
                kind: d.kind,
                name: d.name.clone(),
                height: d.height,
                index_bins: opi_bins_idx,
                chunk_bins: opi_bins_chunk,
                index_k: opi_index_k,
                chunk_k: opi_chunk_k,
                tag_seed: opi_tag_seed,
                dpf_n_index: pir_core::params::compute_dpf_n(opi_bins_idx as usize),
                dpf_n_chunk: pir_core::params::compute_dpf_n(opi_bins_chunk as usize),
                has_bucket_merkle: false,
                // OnionPIR INDEX cuckoo uses the same INDEX_CUCKOO_MASTER
                // domain + anchor as the main DB, so the catalog entry's
                // master seed + anchor carry through unchanged.
                index_master_seed: d.index_master_seed,
                chunk_master_seed: d.chunk_master_seed,
                anchor_kind: d.anchor_kind,
                anchor_bytes: d.anchor_bytes.clone(),
            });
        }
        if !dbs.is_empty() {
            return DatabaseCatalog { databases: dbs };
        }
    }

    // Fallback: synthesize from OnionPIR JSON alone.
    let mut dbs = Vec::new();
    let mut ids: Vec<u8> = onion_params.keys().copied().collect();
    ids.sort();
    for id in ids {
        let (bins_idx, bins_chunk, index_k, chunk_k, tag_seed) = onion_level_params(
            json,
            id,
            top_index_bins,
            top_chunk_bins,
            top_index_k,
            top_chunk_k,
            top_tag_seed,
        );
        dbs.push(DatabaseInfo {
            db_id: id,
            kind: DatabaseKind::Full,
            name: if id == 0 {
                "main".into()
            } else {
                format!("db{}", id)
            },
            height: 0,
            index_bins: bins_idx,
            chunk_bins: bins_chunk,
            index_k,
            chunk_k,
            tag_seed,
            dpf_n_index: pir_core::params::compute_dpf_n(bins_idx as usize),
            dpf_n_chunk: pir_core::params::compute_dpf_n(bins_chunk as usize),
            has_bucket_merkle: false,
            // JSON-only fallback (no server catalog) — no wire master seed
            // or anchor available. Queries on this degraded path require a
            // real catalog; left zero/none here.
            index_master_seed: 0,
            chunk_master_seed: 0,
            anchor_kind: 0,
            anchor_bytes: Vec::new(),
        });
    }

    // Silence unused-warning when DPF branch didn't run but we built from JSON only.
    let _ = top_opi;

    DatabaseCatalog { databases: dbs }
}

/// Pick OnionPIR level params for a db_id, falling back to top-level defaults.
fn onion_level_params(
    json: &str,
    db_id: u8,
    fallback_index_bins: u32,
    fallback_chunk_bins: u32,
    fallback_index_k: u8,
    fallback_chunk_k: u8,
    fallback_tag_seed: u64,
) -> (u32, u32, u8, u8, u64) {
    let opi_section = if db_id == 0 {
        extract_json_object(json, "onionpir")
    } else {
        // Look for the matching entry in the databases array.
        extract_json_object_array(json, "databases")
            .and_then(|entries| {
                entries
                    .into_iter()
                    .find(|e| json_u64(e, "db_id") == Some(db_id as u64))
            })
            .and_then(|e| extract_json_object(e, "onionpir"))
    };
    if let Some(opi) = opi_section {
        let ib = json_u64(opi, "index_bins_per_table").unwrap_or(fallback_index_bins as u64) as u32;
        let cb = json_u64(opi, "chunk_bins_per_table").unwrap_or(fallback_chunk_bins as u64) as u32;
        let ik = json_u64(opi, "index_k").unwrap_or(fallback_index_k as u64) as u8;
        let ck = json_u64(opi, "chunk_k").unwrap_or(fallback_chunk_k as u64) as u8;
        let ts = json_u64(opi, "tag_seed").unwrap_or(fallback_tag_seed);
        (ib, cb, ik, ck, ts)
    } else {
        (
            fallback_index_bins,
            fallback_chunk_bins,
            fallback_index_k,
            fallback_chunk_k,
            fallback_tag_seed,
        )
    }
}

// ─── Misc helpers ──────────────────────────────────────────────────────────

/// First 8 hex chars of a script hash — for concise audit logs.
#[cfg(feature = "onion")]
fn hex_short(sh: &[u8]) -> String {
    let mut s = String::with_capacity(16 + 3);
    for b in sh.iter().take(8) {
        s.push_str(&format!("{:02x}", b));
    }
    s.push('.');
    s.push('.');
    s.push('.');
    s
}

/// Tiny deterministic PRNG (seeded from wall clock) for dummy query bins.
#[cfg(feature = "onion")]
struct SimpleRng {
    state: u64,
}

#[cfg(feature = "onion")]
impl SimpleRng {
    fn new() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0xcafebabedeadbeef);
        Self {
            state: pir_core::hash::splitmix64(seed),
        }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(pir_core::hash::GOLDEN_RATIO);
        pir_core::hash::splitmix64(self.state)
    }
}

// ─── Kani harnesses ─────────────────────────────────────────────────────────
//
// CHUNK Round-Presence Symmetry (CLAUDE.md): the OnionPIR client
// must never skip the CHUNK PIR phase for not-found / whale queries
// — every batch must produce exactly one entry_id per slot in the
// unique-fetch list (real or dummy), so CHUNK round count is a
// function only of batch size, not of which queries matched.
//
// The decision tree lives in `classify_chunk_slots`, which is
// feature-flag-free (the full `IndexResult` is gated on
// `feature = "onion"`, but the projection `ChunkSlotInput` is not),
// so these harnesses run via the default `cargo kani -p pir-sdk-client`
// invocation without pulling SEAL or onionpir into the build.

#[cfg(kani)]
mod kani_harnesses {
    use super::*;

    /// Pick a per-slot shape from a 2-bit symbolic. Mirrors the
    /// pattern from `dpf::kani_harnesses::symbolic_matched_idx` —
    /// keeps the symbolic state space small enough for CBMC.
    fn symbolic_slot() -> ChunkSlotInput {
        let raw: u8 = kani::any();
        kani::assume(raw < 4);
        match raw {
            0 => ChunkSlotInput {
                entry_id: 0,
                num_entries: 0,
            }, // not-found sentinel
            1 => ChunkSlotInput {
                entry_id: kani::any(),
                num_entries: 0,
            }, // whale
            2 => ChunkSlotInput {
                entry_id: kani::any(),
                num_entries: 1,
            }, // small-found
            _ => ChunkSlotInput {
                entry_id: kani::any(),
                num_entries: kani::any(),
            }, // generic-found
        }
    }

    /// **P1** — round-count uniformity. For any input list of slots,
    /// the classifier returns exactly `slots.len()` actions. Combined
    /// with the call-site loop in `query_chunk_level` that pushes
    /// ≥1 entry_id per action, this establishes that the unique-fetch
    /// list (and therefore the CHUNK PIR round count) is a function
    /// only of batch size — not of which queries matched.
    ///
    /// Bound: `slots.len() ∈ {0, 1, 2, 3, 4}`. Each slot's
    /// `num_entries` is drawn from a 4-way symbolic via
    /// `symbolic_slot` to cover the not-found / whale / small-found /
    /// generic-found shapes that the classifier dispatches on.
    #[kani::proof]
    #[kani::unwind(6)]
    fn classify_chunk_slots_emits_one_action_per_slot() {
        let n: usize = kani::any();
        kani::assume(n <= 4);
        let mut slots: Vec<ChunkSlotInput> = Vec::with_capacity(n);
        for _ in 0..n {
            slots.push(symbolic_slot());
        }

        let actions = classify_chunk_slots(&slots);

        assert_eq!(
            actions.len(),
            slots.len(),
            "CHUNK Round-Presence Symmetry P1: classifier must emit \
             one action per slot. The pre-fix bug skipped not-found \
             / whale slots entirely — exactly the leak this property \
             rules out.",
        );
    }

    /// **P2** — every action is `AppendReal` iff `num_entries > 0`,
    /// `AppendDummy` otherwise. There is no third "skip" branch.
    /// Captures the structural decision the classifier makes: the
    /// dispatch is purely on `num_entries` and the resulting action
    /// covers every input.
    #[kani::proof]
    #[kani::unwind(4)]
    fn classify_chunk_slots_no_skip_branch() {
        let slot = symbolic_slot();
        let actions = classify_chunk_slots(&[slot]);

        assert_eq!(actions.len(), 1);
        match (slot.num_entries, &actions[0]) {
            (0, ChunkSlotAction::AppendDummy) => {}
            (
                n,
                ChunkSlotAction::AppendReal {
                    num_entries,
                    entry_id,
                },
            ) if n > 0 && *num_entries == n && *entry_id == slot.entry_id => {}
            _ => panic!(
                "CHUNK Round-Presence Symmetry P2: action must be \
                 AppendReal iff num_entries > 0, AppendDummy iff == 0. \
                 No skip branch."
            ),
        }
    }

    /// **P2 corollary** — the classifier's action carries the
    /// correct `entry_id` and `num_entries` through to the wire:
    /// `AppendReal { entry_id, num_entries }` matches the input
    /// slot exactly. Catches a hypothetical regression that
    /// truncates or reorders fields between the projection and the
    /// classifier.
    #[kani::proof]
    #[kani::unwind(4)]
    fn classify_chunk_slots_preserves_real_fields() {
        let entry_id: u32 = kani::any();
        let num_entries: u8 = kani::any();
        kani::assume(num_entries > 0);
        let slot = ChunkSlotInput {
            entry_id,
            num_entries,
        };

        let actions = classify_chunk_slots(&[slot]);

        assert_eq!(actions.len(), 1);
        match actions[0] {
            ChunkSlotAction::AppendReal {
                entry_id: e,
                num_entries: n,
            } => {
                assert_eq!(
                    e, entry_id,
                    "entry_id must round-trip through the classifier"
                );
                assert_eq!(
                    n, num_entries,
                    "num_entries must round-trip through the classifier"
                );
            }
            ChunkSlotAction::AppendDummy => panic!(
                "num_entries > 0 must produce AppendReal — Dummy on a \
                 real slot would shrink the wire fetch list and break \
                 the FOUND path"
            ),
        }
    }

    /// **P2 corollary** — `num_entries == 0` is the universal
    /// dummy-trigger condition, regardless of `entry_id` value.
    /// Covers both not-found (sentinel `entry_id == 0`) and whale
    /// (arbitrary `entry_id`, but `num_entries == 0`) inputs in a
    /// single proof.
    #[kani::proof]
    #[kani::unwind(4)]
    fn classify_chunk_slots_zero_entries_means_dummy() {
        let entry_id: u32 = kani::any();
        let slot = ChunkSlotInput {
            entry_id,
            num_entries: 0,
        };

        let actions = classify_chunk_slots(&[slot]);

        assert_eq!(actions.len(), 1);
        assert!(
            matches!(actions[0], ChunkSlotAction::AppendDummy),
            "num_entries == 0 must trigger AppendDummy — the wire-level \
             fix for CHUNK Round-Presence Symmetry"
        );
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn proof_test_db(index_bins: u32, chunk_bins: u32, height: u32) -> DatabaseInfo {
        DatabaseInfo {
            db_id: 0,
            kind: DatabaseKind::Full,
            name: "main".into(),
            height,
            index_bins,
            chunk_bins,
            index_k: 75,
            chunk_k: 80,
            tag_seed: 7,
            dpf_n_index: pir_core::params::compute_dpf_n(index_bins as usize),
            dpf_n_chunk: pir_core::params::compute_dpf_n(chunk_bins as usize),
            has_bucket_merkle: true,
            index_master_seed: 0,
            chunk_master_seed: 0,
            anchor_kind: 0,
            anchor_bytes: Vec::new(),
        }
    }

    fn framed_response(payload: Vec<u8>) -> Vec<u8> {
        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&payload);
        frame
    }

    fn onion_info_response(index_bins: u32, chunk_bins: u32) -> Vec<u8> {
        let index_num_pt = index_bins.div_ceil(104);
        let chunk_num_pt = chunk_bins.div_ceil(104);
        let json = format!(
            r#"{{"index_bins_per_table":{index_bins},"chunk_bins_per_table":{chunk_bins},"index_k":75,"chunk_k":80,"tag_seed":7,"onionpir":{{"total_packed_entries":1000,"index_bins_per_table":{index_bins},"chunk_bins_per_table":{chunk_bins},"index_k":75,"chunk_k":80,"tag_seed":7,"index_slots_per_bin":221,"index_slot_size":15}},"onionpir_merkle":{{"arity":104,"super_root":"{root}","tree_tops_hash":"{tops}","tree_tops_size":1,"index":{{"k":75,"num_pt":{index_num_pt}}},"data":{{"k":80,"num_pt":{chunk_num_pt}}}}}}}"#,
            root = "00".repeat(32),
            tops = "11".repeat(32),
        );
        let mut payload = Vec::with_capacity(1 + json.len());
        payload.push(RESP_GET_INFO_JSON);
        payload.extend_from_slice(json.as_bytes());
        framed_response(payload)
    }

    fn standard_catalog_response(db: &DatabaseInfo) -> Vec<u8> {
        let mut payload = vec![RESP_DB_CATALOG, 1, db.db_id, 0, db.name.len() as u8];
        payload.extend_from_slice(db.name.as_bytes());
        payload.extend_from_slice(&db.base_height().to_le_bytes());
        payload.extend_from_slice(&db.height.to_le_bytes());
        payload.extend_from_slice(&db.index_bins.to_le_bytes());
        payload.extend_from_slice(&db.chunk_bins.to_le_bytes());
        payload.push(db.index_k);
        payload.push(db.chunk_k);
        payload.extend_from_slice(&db.tag_seed.to_le_bytes());
        payload.push(db.dpf_n_index);
        payload.push(db.dpf_n_chunk);
        payload.push(u8::from(db.has_bucket_merkle));
        framed_response(payload)
    }

    fn proof_test_roots(height: u32) -> VerifiedDatabaseRoots {
        VerifiedDatabaseRoots {
            db_id: 0,
            manifest_root: [0; 32],
            build_kind: pir_db_attest::BuildKind::Snapshot,
            from_height: 0,
            from_block_hash: [0; 32],
            height,
            block_hash: [1; 32],
            muhash: [2; 32],
            bucket_super_root: [3; 32],
            onion_super_root: [4; 32],
            onion_entry_size: 3328,
            onion_layout_v2: Some(pir_db_attest::OnionQueryLayoutV2::current(
                1_000, 10_273, 20_547, 3_328,
            )),
            params_hash: [5; 32],
            network_magic: [0xf9, 0xbe, 0xb4, 0xd9],
            builder_binary_sha256: [6; 32],
            builder_git_commit: "test".into(),
        }
    }

    fn seed_test_session_bindings(client: &mut OnionClient, db: &DatabaseInfo) {
        let catalog = DatabaseCatalog {
            databases: vec![db.clone()],
        };
        client.catalog = Some(catalog.clone());
        client.proof_catalog = Some(catalog);
        client.onion_params.insert(
            db.db_id,
            OnionDbParams {
                total_packed: 1000,
                index_slots_per_bin: 221,
                index_slot_size: 15,
            },
        );
        client.info_json = Some("{\"session\":\"old\"}".into());
        client.set_root_policy(RootPolicy::RequireVerified);
        #[cfg(feature = "onion")]
        {
            let merkle_json = r#"{
                "onionpir_merkle": {
                    "arity": 104,
                    "super_root": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                    "tree_tops_hash": "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
                    "tree_tops_size": 1245184,
                    "index": {"k": 75, "num_pt": 99},
                    "data": {"k": 80, "num_pt": 198}
                }
            }"#;
            client.onion_merkle = parse_onion_merkle_per_db(merkle_json);
        }
        client
            .install_verified_database_roots(proof_test_roots(db.height))
            .unwrap();
        client.verified_tree_tops.insert(db.db_id);

        #[cfg(feature = "onion")]
        {
            let merkle_json = r#"{
                "onionpir_merkle": {
                    "arity": 104,
                    "super_root": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                    "tree_tops_hash": "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
                    "tree_tops_size": 1245184,
                    "index": {"k": 75, "num_pt": 99},
                    "data": {"k": 80, "num_pt": 198}
                }
            }"#;
            client.onion_merkle = parse_onion_merkle_per_db(merkle_json);
            client.fhe = Some(FheState {
                client_id: 7,
                secret_key: vec![1],
                galois_keys: vec![2],
                gsw_keys: vec![3],
                level_clients: HashMap::new(),
                registered: [db.db_id].into_iter().collect(),
            });
        }
    }

    #[test]
    fn test_encode_request_simple() {
        let buf = encode_request(0x03, &[]);
        assert_eq!(buf, vec![1, 0, 0, 0, 0x03]);
    }

    #[test]
    fn test_json_u64_decimal() {
        assert_eq!(json_u64(r#"{"k":42,"x":0}"#, "k"), Some(42));
        assert_eq!(json_u64(r#"{"foo":null,"k":7}"#, "k"), Some(7));
    }

    #[test]
    fn test_json_u64_hex() {
        assert_eq!(
            json_u64(r#"{"tag_seed":"0x71a2ef38b4c90d15"}"#, "tag_seed"),
            Some(0x71a2ef38b4c90d15),
        );
    }

    #[test]
    fn test_extract_json_object_nested() {
        let j = r#"{"outer":{"inner":{"a":1}},"x":2}"#;
        assert_eq!(
            extract_json_object(j, "outer"),
            Some(r#"{"inner":{"a":1}}"#)
        );
        assert_eq!(extract_json_object(j, "inner"), Some(r#"{"a":1}"#));
    }

    #[test]
    fn test_parse_onion_params_main_only() {
        let j = r#"{"onionpir":{"total_packed_entries":1000,"index_bins_per_table":100,"chunk_bins_per_table":200,"tag_seed":"0x1","index_k":75,"chunk_k":80,"index_slots_per_bin":256,"index_slot_size":15,"chunk_slots_per_bin":1,"chunk_slot_size":3840}}"#;
        let params = parse_onion_params_per_db(j);
        assert_eq!(params.len(), 1);
        let p = params.get(&0).unwrap();
        assert_eq!(p.total_packed, 1000);
        assert_eq!(p.index_slots_per_bin, 256);
        assert_eq!(p.index_slot_size, 15);
    }

    #[test]
    fn test_parse_onion_params_multi_db() {
        let j = r#"{"onionpir":{"total_packed_entries":1000,"index_slots_per_bin":256,"index_slot_size":15},"databases":[{"db_id":0,"onionpir":{"total_packed_entries":1000,"index_slots_per_bin":256,"index_slot_size":15}},{"db_id":1,"onionpir":{"total_packed_entries":50,"index_slots_per_bin":128,"index_slot_size":15}}]}"#;
        let params = parse_onion_params_per_db(j);
        assert_eq!(params.len(), 2);
        assert_eq!(params.get(&0).unwrap().total_packed, 1000);
        assert_eq!(params.get(&1).unwrap().total_packed, 50);
        assert_eq!(params.get(&1).unwrap().index_slots_per_bin, 128);
    }

    #[test]
    fn test_parse_onion_params_no_onionpir() {
        let j = r#"{"index_bins_per_table":100,"chunk_bins_per_table":200}"#;
        assert!(parse_onion_params_per_db(j).is_empty());
    }

    #[test]
    fn test_build_catalog_from_json_only() {
        let j = r#"{"onionpir":{"total_packed_entries":1000,"index_bins_per_table":100,"chunk_bins_per_table":200,"tag_seed":"0xdeadbeef","index_k":75,"chunk_k":80,"index_slots_per_bin":256,"index_slot_size":15,"chunk_slots_per_bin":1,"chunk_slot_size":3840}}"#;
        let params = parse_onion_params_per_db(j);
        let catalog = build_catalog(j, &params, None);
        assert_eq!(catalog.databases.len(), 1);
        let db = &catalog.databases[0];
        assert_eq!(db.db_id, 0);
        assert_eq!(db.index_bins, 100);
        assert_eq!(db.chunk_bins, 200);
        assert_eq!(db.tag_seed, 0xdeadbeef);
        assert!(matches!(db.kind, DatabaseKind::Full));
    }

    #[tokio::test]
    async fn proof_verification_uses_standard_catalog_not_onion_query_geometry() {
        use crate::transport::mock::MockTransport;

        let proof_db = proof_test_db(567_558, 1_135_116, 948_454);
        let mut mock = MockTransport::new("wss://mock-onion");
        mock.enqueue_response(onion_info_response(10_273, 20_547));
        mock.enqueue_response(standard_catalog_response(&proof_db));

        let mut client = OnionClient::new("wss://mock-onion");
        client.connect_with_transport(Box::new(mock));
        let query_catalog = client.fetch_catalog().await.unwrap();

        let query_db = query_catalog.get(0).unwrap();
        assert_eq!(query_db.index_bins, 10_273);
        assert_eq!(query_db.chunk_bins, 20_547);
        assert_eq!(query_db.height, proof_db.height);

        let selected_for_proof = client.proof_database_info(0).unwrap();
        assert_eq!(selected_for_proof.index_bins, proof_db.index_bins);
        assert_eq!(selected_for_proof.chunk_bins, proof_db.chunk_bins);
        assert_ne!(selected_for_proof.index_bins, query_db.index_bins);
    }

    #[test]
    fn v1_roots_remain_installable_during_staged_v2_migration() {
        let db = proof_test_db(10_273, 20_547, 948_454);
        let mut client = OnionClient::new("wss://mock-onion");
        client.catalog = Some(DatabaseCatalog {
            databases: vec![db.clone()],
        });
        client.proof_catalog = client.catalog.clone();
        client.onion_params.insert(
            db.db_id,
            OnionDbParams {
                total_packed: 777,
                index_slots_per_bin: 221,
                index_slot_size: 15,
            },
        );
        let mut roots = proof_test_roots(db.height);
        roots.onion_layout_v2 = None;

        client.install_verified_database_roots(roots).unwrap();

        assert!(client.verified_database_roots(db.db_id).is_some());
        assert_eq!(
            client.onion_params.get(&db.db_id).unwrap().total_packed,
            777
        );
    }

    #[tokio::test]
    async fn proof_verification_fails_closed_without_standard_catalog() {
        use crate::transport::mock::MockTransport;

        let mut mock = MockTransport::new("wss://mock-onion");
        mock.enqueue_response(onion_info_response(10_273, 20_547));
        mock.enqueue_response(framed_response(vec![0xff, b'n', b'o']));

        let mut client = OnionClient::new("wss://mock-onion");
        client.connect_with_transport(Box::new(mock));
        let query_catalog = client.fetch_catalog().await.unwrap();
        assert_eq!(query_catalog.get(0).unwrap().index_bins, 10_273);

        let err = client
            .verify_database_proof(0, &DatabaseProofPolicy::mainnet())
            .await
            .unwrap_err();
        assert!(matches!(err, PirError::VerificationFailed(_)));
        assert!(err.to_string().contains("requires REQ_GET_DB_CATALOG"));
    }

    #[tokio::test]
    async fn onion_query_catalog_rotation_invalidates_installed_roots() {
        use crate::transport::mock::MockTransport;

        let proof_db = proof_test_db(567_558, 1_135_116, 948_454);
        let mut mock = MockTransport::new("wss://mock-onion");
        mock.enqueue_response(onion_info_response(10_273, 20_547));
        mock.enqueue_response(standard_catalog_response(&proof_db));
        mock.enqueue_response(onion_info_response(10_274, 20_547));
        mock.enqueue_response(standard_catalog_response(&proof_db));

        let mut client = OnionClient::new("wss://mock-onion");
        client.connect_with_transport(Box::new(mock));
        client.fetch_catalog().await.unwrap();
        let err = client
            .install_verified_database_roots(proof_test_roots(proof_db.height + 1))
            .unwrap_err();
        assert!(matches!(err, PirError::VerificationFailed(_)));
        assert!(client.verified_database_roots(0).is_none());
        client
            .install_verified_database_roots(proof_test_roots(proof_db.height))
            .unwrap();
        assert!(client.verified_database_roots(0).is_some());

        let rotated_query_catalog = client.fetch_catalog().await.unwrap();
        assert_eq!(rotated_query_catalog.get(0).unwrap().index_bins, 10_274);
        assert_eq!(
            client.proof_database_info(0).unwrap().index_bins,
            proof_db.index_bins
        );
        assert!(
            client.verified_database_roots(0).is_none(),
            "Onion query-catalog rotation must clear roots bound to the old session geometry"
        );
    }

    #[test]
    fn test_onion_client_new_uninitialised() {
        let c = OnionClient::new("ws://localhost:8091");
        assert_eq!(c.backend_type(), PirBackendType::Onion);
        assert!(!c.is_connected());
        assert!(c.cached_catalog().is_none());
    }

    #[cfg(feature = "onion")]
    #[tokio::test]
    async fn empty_execute_step_skips_onion_backend_work() {
        let db = proof_test_db(10_273, 20_547, 948_454);
        let step = SyncStep::from_db_info(&db);
        let mut client = OnionClient::new("wss://mock-onion");

        // No transport, query parameters, FHE state, or registered keys are
        // present. The outer empty-input guard must avoid every Onion backend
        // side effect after strict sync preflight has succeeded.
        let results = client.execute_step(&[], &step, &db).await.unwrap();
        assert!(results.is_empty());
        assert!(!client.is_connected());
    }

    #[cfg(not(feature = "onion"))]
    #[tokio::test]
    async fn empty_execute_step_fails_closed_without_onion_feature() {
        let db = proof_test_db(10_273, 20_547, 948_454);
        let step = SyncStep::from_db_info(&db);
        let mut client = OnionClient::new("wss://mock-onion");

        let error = client.execute_step(&[], &step, &db).await.unwrap_err();
        assert!(matches!(error, PirError::BackendState(_)));
        assert!(error.to_string().contains("not compiled in"));
    }

    #[tokio::test]
    async fn empty_onion_sync_still_requires_verified_roots() {
        use crate::transport::mock::MockTransport;

        let db = proof_test_db(10_273, 20_547, 948_454);
        let mut client = OnionClient::new("wss://mock-onion");
        client.connect_with_transport(Box::new(MockTransport::new("wss://mock-onion")));
        client.catalog = Some(DatabaseCatalog {
            databases: vec![db],
        });
        client.set_root_policy(RootPolicy::RequireVerified);

        let error = client.sync(&[], None).await.unwrap_err();
        assert!(matches!(error, PirError::VerificationFailed(_)));
    }

    #[cfg(feature = "onion")]
    #[tokio::test]
    async fn empty_onion_sync_succeeds_after_verified_preflight_without_fhe_or_network() {
        use crate::transport::mock::MockTransport;

        let db = proof_test_db(10_273, 20_547, 948_454);
        let mut client = OnionClient::new("wss://mock-onion");
        client.connect_with_transport(Box::new(MockTransport::new("wss://mock-onion")));
        seed_test_session_bindings(&mut client, &db);
        client.fhe = None;
        client.verified_tree_tops.remove(&db.db_id);

        let preflight_error = client.sync(&[], None).await.unwrap_err();
        assert!(
            preflight_error
                .to_string()
                .contains("mock: no enqueued response"),
            "installed roots must not let empty Onion sync bypass tree-top preflight: \
             {preflight_error}"
        );
        client.verified_tree_tops.insert(db.db_id);

        // The trusted tree-top marker is already bound to the verified roots,
        // so no response is queued. Success proves empty sync reaches strict
        // preflight but does not initialise FHE, register keys, or query.
        let result = client.sync(&[], None).await.unwrap();
        assert!(result.results.is_empty());
        assert_eq!(result.synced_height, db.height);
        assert!(result.was_fresh_sync);
        assert!(client.fhe.is_none());
    }

    #[cfg(not(feature = "onion"))]
    #[tokio::test]
    async fn query_fails_closed_without_onion_feature_for_every_root_policy() {
        use crate::transport::mock::MockTransport;

        let db = proof_test_db(10_273, 20_547, 948_454);
        let script_hashes = [[0u8; 20]];

        for policy in [RootPolicy::Advisory, RootPolicy::RequireVerified] {
            let mut client = OnionClient::new("wss://mock-onion");
            client.connect_with_transport(Box::new(MockTransport::new("wss://mock-onion")));
            client.catalog = Some(DatabaseCatalog {
                databases: vec![db.clone()],
            });
            client.proof_catalog = client.catalog.clone();
            client.set_root_policy(policy);
            if policy == RootPolicy::RequireVerified {
                client
                    .install_verified_database_roots(proof_test_roots(db.height))
                    .unwrap();
            }

            let query_err = client
                .query_batch(&script_hashes, db.db_id)
                .await
                .unwrap_err();
            assert!(matches!(query_err, PirError::BackendState(_)));
            assert!(query_err.to_string().contains("not compiled in"));

            let step = SyncStep::from_db_info(&db);
            let execute_err = client
                .execute_step(&script_hashes, &step, &db)
                .await
                .unwrap_err();
            assert!(matches!(execute_err, PirError::BackendState(_)));
            assert!(execute_err.to_string().contains("not compiled in"));
        }
    }

    /// `batch_looks_evicted` must fire on an all-empty batch of ≥1 slot,
    /// which is the server's signal that our `client_id` has been
    /// LRU-evicted from SEAL's `KeyStore`. A legit response has at
    /// least one non-empty ciphertext, so the function must return
    /// `false` in that case.
    #[test]
    fn test_batch_looks_evicted_all_empty() {
        // All-empty batch of 3 slots: eviction.
        let batch = vec![Vec::<u8>::new(), Vec::<u8>::new(), Vec::<u8>::new()];
        assert!(batch_looks_evicted(&batch));
        // Single empty slot: eviction.
        let batch = vec![Vec::<u8>::new()];
        assert!(batch_looks_evicted(&batch));
    }

    #[test]
    fn test_batch_looks_evicted_mixed_and_full() {
        // Mixed: at least one non-empty → NOT eviction.
        let batch = vec![Vec::<u8>::new(), vec![0x01, 0x02]];
        assert!(!batch_looks_evicted(&batch));
        // All non-empty: clearly not eviction.
        let batch = vec![vec![0xaa], vec![0xbb], vec![0xcc]];
        assert!(!batch_looks_evicted(&batch));
    }

    #[test]
    fn test_batch_looks_evicted_zero_length() {
        // Zero-slot batch: NOT eviction — that would be a decode
        // error (num_groups=0 payload), handled upstream. This test
        // pins the contract so a future `.all(...)` simplification
        // (which returns true on an empty iterator) doesn't silently
        // start reporting "eviction" on decode bugs.
        let batch: Vec<Vec<u8>> = Vec::new();
        assert!(!batch_looks_evicted(&batch));
    }

    #[cfg(feature = "onion")]
    #[test]
    fn test_encode_register_keys_no_db_id() {
        let buf = encode_register_keys(&[1, 2, 3], &[9, 8], 0);
        // 4B len, variant, 4B galois_len=3, galois=[1,2,3], 4B gsw_len=2, gsw=[9,8]
        // payload_len = 1 + 4 + 3 + 4 + 2 = 14
        assert_eq!(&buf[0..4], &14u32.to_le_bytes());
        assert_eq!(buf[4], REQ_REGISTER_KEYS);
    }

    #[cfg(feature = "onion")]
    #[test]
    fn test_encode_register_keys_with_db_id() {
        let buf = encode_register_keys(&[1], &[2], 3);
        // payload_len = 1 + 4 + 1 + 4 + 1 + 1 = 12 (trailing db_id byte)
        assert_eq!(&buf[0..4], &12u32.to_le_bytes());
        assert_eq!(*buf.last().unwrap(), 3);
    }

    #[cfg(feature = "onion")]
    #[test]
    fn test_register_keys_ack_is_exact_and_errors_are_canonical() {
        assert!(decode_register_keys_ack(&[RESP_KEYS_ACK]).is_ok());
        assert!(matches!(
            decode_register_keys_ack(&[RESP_KEYS_ACK, 0]),
            Err(PirError::Decode(ref text)) if text.contains("trailing bytes")
        ));
        assert!(matches!(
            decode_register_keys_ack(&[0x91]),
            Err(PirError::UnexpectedResponse { .. })
        ));

        let message = b"authorization required";
        let mut error = vec![crate::protocol::RESP_ERROR];
        error.extend_from_slice(&(message.len() as u32).to_le_bytes());
        error.extend_from_slice(message);
        assert!(matches!(
            decode_register_keys_ack(&error),
            Err(PirError::ServerError(ref text)) if text.contains("authorization required")
        ));
    }

    #[cfg(feature = "onion")]
    #[test]
    fn test_encode_onionpir_batch_query() {
        let qs = vec![vec![0xaau8, 0xbb], vec![0xcc]];
        let buf = encode_onionpir_batch_query(REQ_ONIONPIR_INDEX_QUERY, 7, &qs, 0);
        // payload: variant(1) + round_id(2) + num_groups(1) + [len(4)+bytes]*
        let expected_payload_len = 1 + 2 + 1 + (4 + 2) + (4 + 1);
        assert_eq!(&buf[0..4], &(expected_payload_len as u32).to_le_bytes());
        assert_eq!(buf[4], REQ_ONIONPIR_INDEX_QUERY);
    }

    #[cfg(feature = "onion")]
    #[test]
    fn test_decode_onionpir_batch_result_roundtrip() {
        let qs = vec![vec![0x11, 0x22], vec![0x33]];
        let buf = encode_onionpir_batch_query(RESP_ONIONPIR_INDEX_RESULT, 7, &qs, 0);
        // Skip length prefix + variant byte.
        let decoded = decode_onionpir_batch_result(&buf[5..], 7, "test").unwrap();
        assert_eq!(decoded, qs);
    }

    #[cfg(feature = "onion")]
    #[test]
    fn test_decode_onionpir_batch_result_rejects_round_truncation_and_trailing() {
        let qs = vec![vec![0x11, 0x22], vec![0x33]];
        let buf = encode_onionpir_batch_query(RESP_ONIONPIR_INDEX_RESULT, 7, &qs, 0);
        assert!(matches!(
            decode_onionpir_batch_result(&buf[5..], 8, "test"),
            Err(PirError::Protocol(ref text)) if text.contains("round_id mismatch")
        ));

        let mut truncated = buf[5..].to_vec();
        truncated.pop();
        assert!(matches!(
            decode_onionpir_batch_result(&truncated, 7, "test"),
            Err(PirError::Decode(_))
        ));

        let mut trailing = buf[5..].to_vec();
        trailing.push(0xaa);
        assert!(matches!(
            decode_onionpir_batch_result(&trailing, 7, "test"),
            Err(PirError::Decode(ref text)) if text.contains("trailing bytes")
        ));

        let mut wrong_opcode = buf[4..].to_vec();
        wrong_opcode[0] = 0x91;
        assert!(matches!(
            decode_onionpir_batch_response(
                &wrong_opcode,
                RESP_ONIONPIR_INDEX_RESULT,
                7,
                2,
                "RESP_ONIONPIR_INDEX_RESULT",
            ),
            Err(PirError::UnexpectedResponse { .. })
        ));

        let message = b"authorization required";
        let mut error = vec![crate::protocol::RESP_ERROR];
        error.extend_from_slice(&(message.len() as u32).to_le_bytes());
        error.extend_from_slice(message);
        assert!(matches!(
            decode_onionpir_batch_response(
                &error,
                RESP_ONIONPIR_INDEX_RESULT,
                7,
                2,
                "RESP_ONIONPIR_INDEX_RESULT",
            ),
            Err(PirError::ServerError(ref text)) if text.contains("authorization required")
        ));

        assert!(matches!(
            decode_onionpir_batch_response(
                &buf[4..],
                RESP_ONIONPIR_INDEX_RESULT,
                7,
                1,
                "RESP_ONIONPIR_INDEX_RESULT",
            ),
            Err(PirError::Protocol(ref text)) if text.contains("result count mismatch")
        ));
    }

    #[cfg(feature = "onion")]
    #[test]
    fn test_scan_index_bin_hit() {
        // Single slot: tag=0x42, entry_id=7, byte_offset=100, num_entries=3
        let mut entry = vec![0u8; 15];
        entry[0..8].copy_from_slice(&0x42u64.to_le_bytes());
        entry[8..12].copy_from_slice(&7u32.to_le_bytes());
        entry[12..14].copy_from_slice(&100u16.to_le_bytes());
        entry[14] = 3;
        let ir = scan_index_bin(&entry, 0x42, 1, 15).expect("should find");
        assert_eq!(ir.entry_id, 7);
        assert_eq!(ir.byte_offset, 100);
        assert_eq!(ir.num_entries, 3);
    }

    #[cfg(feature = "onion")]
    #[test]
    fn test_scan_index_bin_miss() {
        let entry = vec![0u8; 15];
        assert!(scan_index_bin(&entry, 0x42, 1, 15).is_none());
    }

    #[cfg(feature = "onion")]
    #[test]
    fn test_chunk_cuckoo_roundtrip() {
        // Build a reverse index and cuckoo table, then verify every assigned
        // entry is findable. Load factor must be comfortably below 1.0 for
        // cuckoo to succeed — with total=200 and k_chunk=10 each group gets
        // ~60 entries (3 PBC hashes), so 256 bins gives ~23% load.
        let total = 200usize;
        let k_chunk = 10usize;
        let bins = 256usize;
        let rev = build_chunk_reverse_index(total, k_chunk);
        // Check all non-empty groups, not just the first — catches
        // regressions that only show up at higher loads.
        for (group, entries) in rev.iter().enumerate() {
            if entries.is_empty() {
                continue;
            }
            let table = build_chunk_cuckoo_for_group(group, &rev, bins);
            let keys = chunk_derive_keys(group);
            for &eid in entries {
                let bin = find_in_chunk_cuckoo(&table, eid, &keys, bins);
                assert!(
                    bin.is_some(),
                    "entry_id {} not found in group {} ({} entries, {} bins)",
                    eid,
                    group,
                    entries.len(),
                    bins
                );
            }
        }
    }

    /// Concurrency smoke test for the `unsafe impl Sync for SendClient`.
    ///
    /// The Sync claim only covers the two `&self` methods on
    /// `onionpir::Client`: `id` and `export_secret_key`. This test
    /// exercises both from multiple threads sharing a single
    /// `Arc<SendClient>`. If the `&self` FFI path touches any internal
    /// mutable state that isn't protected by a lock (a
    /// `mutable`-declared member, a non-thread-safe SEAL MemoryPool
    /// operation, a static cache, etc.), we expect this to either
    /// produce mismatched results, hang, or trip ASAN in CI.
    ///
    /// The test is a smoke test, not a proof — data races in SEAL
    /// could be demonic enough to only show up under load or with a
    /// particular allocator state. CI runs under tsan would make this
    /// considerably stronger, but the full SEAL stack is not tsan-clean
    /// (OpenMP is already tsan-unfriendly), so the lightweight check is
    /// the best we can do in-tree.
    ///
    /// Gated behind `feature = "onion"` because it constructs a real
    /// `onionpir::Client`, which requires the SEAL C++ toolchain.
    #[cfg(feature = "onion")]
    #[test]
    fn test_send_client_sync_smoke() {
        use std::sync::Arc;
        use std::thread;

        // Tiny num_entries so this is cheap. We only call `&self` methods.
        let client = onionpir::Client::new(1 << 10);
        let expected_id = client.id();
        let expected_sk = client.export_secret_key();
        let shared = Arc::new(SendClient(client));

        let handles: Vec<_> = (0..8)
            .map(|t| {
                let s = Arc::clone(&shared);
                let exp_id = expected_id;
                let exp_sk = expected_sk.clone();
                thread::spawn(move || {
                    // Alternate between `id` and `export_secret_key` across
                    // threads so both `&self` FFI entry points are hit.
                    for i in 0..50 {
                        if (t + i) % 2 == 0 {
                            assert_eq!(s.0.id(), exp_id, "id() disagrees across threads");
                        } else {
                            let sk = s.0.export_secret_key();
                            assert_eq!(sk, exp_sk, "export_secret_key() disagrees across threads");
                        }
                    }
                })
            })
            .collect();
        for h in handles {
            h.join()
                .expect("thread panicked — possible data race in &self FFI path");
        }
    }

    /// C2 (docs/CODE_REVIEW_2026-06.md): malformed varints in
    /// server-controlled entry bytes must surface as `PirError::Decode`,
    /// never a panic — mirrors the equivalent tests in `dpf.rs` /
    /// `harmony.rs`.
    #[cfg(feature = "onion")]
    #[test]
    fn test_decode_utxo_entries_malformed_varint_is_decode_error() {
        // Count varint runs past 64 bits (previously panicked).
        let err = decode_utxo_entries(&[0xFF; 16]).unwrap_err();
        assert!(matches!(err, PirError::Decode(_)), "got {err:?}");

        // Count varint never terminates before the data ends.
        let err = decode_utxo_entries(&[0x80]).unwrap_err();
        assert!(matches!(err, PirError::Decode(_)), "got {err:?}");

        // Valid count + txid, then a vout varint cut mid-stream.
        let mut data = Vec::new();
        pir_core::codec::write_varint(1, &mut data);
        data.extend_from_slice(&[0xAB; 32]);
        data.push(0x80); // dangling continuation bit
        let err = decode_utxo_entries(&data).unwrap_err();
        assert!(matches!(err, PirError::Decode(_)), "got {err:?}");

        // Honest data still decodes.
        let mut data = Vec::new();
        pir_core::codec::write_varint(1, &mut data);
        data.extend_from_slice(&[0x44; 32]);
        pir_core::codec::write_varint(2, &mut data); // vout
        pir_core::codec::write_varint(31_337, &mut data); // amount
        let entries = decode_utxo_entries(&data).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].vout, 2);
        assert_eq!(entries[0].amount_sats, 31_337);
        assert!(decode_utxo_entries(&[]).unwrap().is_empty());
    }

    /// Demonstrates the test-injection escape hatch: a client built with a
    /// [`MockTransport`](crate::transport::mock::MockTransport) reports
    /// `is_connected()` without ever opening a real socket. This is the
    /// core value prop of the `PirTransport` trait.
    #[test]
    fn connect_with_transport_marks_connected() {
        use crate::transport::mock::MockTransport;
        let mut client = OnionClient::new("wss://mock-onion");
        assert!(!client.is_connected());
        client.connect_with_transport(Box::new(MockTransport::new("wss://mock-onion")));
        assert!(client.is_connected());
    }

    #[test]
    fn replacing_transport_invalidates_all_session_bindings() {
        use crate::transport::mock::MockTransport;

        let db = proof_test_db(10_273, 20_547, 948_454);
        let mut client = OnionClient::new("wss://mock-onion");
        client.connect_with_transport(Box::new(MockTransport::new("wss://old-session")));
        seed_test_session_bindings(&mut client, &db);

        assert!(client.catalog.is_some());
        assert!(client.proof_catalog.is_some());
        assert!(client.verified_database_roots(db.db_id).is_some());
        assert!(client.verified_tree_tops.contains(&db.db_id));
        assert!(!client.onion_params.is_empty());
        assert!(client.info_json.is_some());
        #[cfg(feature = "onion")]
        {
            assert!(!client.onion_merkle.is_empty());
            assert!(client.fhe.is_some());
        }

        client.connect_with_transport(Box::new(MockTransport::new("wss://new-session")));

        assert!(client.is_connected());
        assert!(client.catalog.is_none());
        assert!(client.proof_catalog.is_none());
        assert!(client.verified_database_roots(db.db_id).is_none());
        assert!(client.verified_tree_tops.is_empty());
        assert!(client.onion_params.is_empty());
        assert!(client.info_json.is_none());
        assert_eq!(client.root_policy(), RootPolicy::RequireVerified);
        #[cfg(feature = "onion")]
        {
            assert!(client.onion_merkle.is_empty());
            assert!(client.fhe.is_none());
        }
    }

    #[tokio::test]
    async fn duplicate_connect_is_idempotent_and_preserves_live_session() {
        use crate::transport::mock::MockTransport;

        let db = proof_test_db(10_273, 20_547, 948_454);
        let mut client = OnionClient::new("wss://must-not-be-dialed");
        client.connect_with_transport(Box::new(MockTransport::new("wss://live-session")));
        seed_test_session_bindings(&mut client, &db);

        client.connect().await.unwrap();

        assert!(client.is_connected());
        assert!(client.catalog.is_some());
        assert!(client.proof_catalog.is_some());
        assert!(client.verified_database_roots(db.db_id).is_some());
        assert!(client.verified_tree_tops.contains(&db.db_id));
        #[cfg(feature = "onion")]
        {
            assert!(!client.onion_merkle.is_empty());
            assert!(client.fhe.is_some());
        }
    }

    // ─── Tracing smoke test ──────────────────────────────────────────────
    //
    // Companion to `tracing_instrument_emits_backend_field_for_dpf` in
    // `dpf.rs` — proves the OnionClient span carries `backend="onion"`
    // so future maintainers can find OnionPIR-specific traces via a
    // single `backend=onion` filter.

    #[derive(Clone)]
    struct BufferWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for BufferWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BufferWriter {
        type Writer = BufferWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn tracing_instrument_emits_backend_field_for_onion() {
        use crate::transport::mock::MockTransport;
        use tracing_subscriber::fmt;

        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = fmt::Subscriber::builder()
            .with_span_events(fmt::format::FmtSpan::CLOSE)
            .with_writer(BufferWriter(buf.clone()))
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let mut client = OnionClient::new("wss://mock-onion");
            client.connect_with_transport(Box::new(MockTransport::new("wss://mock-onion")));
        });

        let captured = String::from_utf8(buf.lock().unwrap().clone())
            .expect("tracing writer produced valid UTF-8");
        assert!(
            captured.contains("connect_with_transport"),
            "expected span name in captured output, got: {}",
            captured
        );
        assert!(
            captured.contains("backend=\"onion\""),
            "expected backend=\"onion\" field in captured output, got: {}",
            captured
        );
    }

    // ─── Metrics recorder tests ─────────────────────────────────────────────
    //
    // Companion to the DPF/Harmony metrics tests. OnionClient has a
    // single transport (no hint/query split), so the `connects`
    // counter tops out at 1 here where DPF/Harmony top out at 2.

    /// Installing a recorder *before* `connect_with_transport` must
    /// fire exactly one `on_connect` callback for OnionClient's single
    /// transport, and must propagate the recorder to that transport so
    /// subsequent per-frame byte callbacks flow through.
    #[test]
    fn metrics_recorder_fires_on_connect_via_inject_onion() {
        use crate::transport::mock::MockTransport;
        use pir_sdk::AtomicMetrics;

        let recorder = Arc::new(AtomicMetrics::new());
        let mut client = OnionClient::new("wss://mock-onion");
        client.set_metrics_recorder(Some(recorder.clone()));

        client.connect_with_transport(Box::new(MockTransport::new("wss://mock-onion")));

        let snap = recorder.snapshot();
        assert_eq!(
            snap.connects, 1,
            "expected one on_connect for OnionClient's single transport"
        );
        assert_eq!(snap.disconnects, 0);
    }

    /// `disconnect` fires a single `on_disconnect` — same semantic as
    /// DPF/Harmony, the signal is "client left the connected state".
    #[tokio::test]
    async fn metrics_recorder_fires_on_disconnect_onion() {
        use crate::transport::mock::MockTransport;
        use pir_sdk::AtomicMetrics;

        let recorder = Arc::new(AtomicMetrics::new());
        let mut client = OnionClient::new("wss://mock-onion");
        client.set_metrics_recorder(Some(recorder.clone()));

        client.connect_with_transport(Box::new(MockTransport::new("wss://mock-onion")));
        client.disconnect().await.unwrap();

        let snap = recorder.snapshot();
        assert_eq!(snap.connects, 1);
        assert_eq!(snap.disconnects, 1);
    }

    /// Installing the recorder *after* `connect_with_transport` still
    /// propagates the handle to the transport. Drive a `send` through
    /// the conn directly — it must fire `on_bytes_sent("onion", N)`
    /// on the recorder even though it was installed post-connect.
    #[tokio::test]
    async fn metrics_recorder_propagates_to_transport_after_connect_onion() {
        use crate::transport::mock::MockTransport;
        use crate::transport::PirTransport;
        use pir_sdk::AtomicMetrics;

        let mut client = OnionClient::new("wss://mock-onion");
        client.connect_with_transport(Box::new(MockTransport::new("wss://mock-onion")));

        // Install the recorder post-connect.
        let recorder = Arc::new(AtomicMetrics::new());
        client.set_metrics_recorder(Some(recorder.clone()));

        // Drive one send through the transport directly.
        client
            .conn
            .as_mut()
            .unwrap()
            .send(vec![1, 2, 3, 4, 5, 6, 7])
            .await
            .unwrap();

        let snap = recorder.snapshot();
        assert_eq!(snap.bytes_sent, 7);
        assert_eq!(snap.frames_sent, 1);
    }

    /// `set_metrics_recorder(None)` silences both the client-level and
    /// transport-level callbacks.
    #[tokio::test]
    async fn metrics_recorder_uninstall_silences_everything_onion() {
        use crate::transport::mock::MockTransport;
        use crate::transport::PirTransport;
        use pir_sdk::AtomicMetrics;

        let recorder = Arc::new(AtomicMetrics::new());
        let mut client = OnionClient::new("wss://mock-onion");
        client.set_metrics_recorder(Some(recorder.clone()));
        client.connect_with_transport(Box::new(MockTransport::new("wss://mock-onion")));

        // Uninstall mid-session.
        client.set_metrics_recorder(None);
        // Neither the client-level disconnect callback nor the
        // transport-level send callback should fire now.
        client
            .conn
            .as_mut()
            .unwrap()
            .send(vec![9; 42])
            .await
            .unwrap();
        client.disconnect().await.unwrap();

        let snap = recorder.snapshot();
        // Only the pre-uninstall connect tick survives.
        assert_eq!(snap.connects, 1);
        assert_eq!(snap.disconnects, 0);
        assert_eq!(snap.bytes_sent, 0);
        assert_eq!(snap.frames_sent, 0);
    }

    /// `fire_query_start` returns `Some(Instant)` only when a recorder
    /// is installed — keeps the no-recorder path at zero overhead.
    #[test]
    fn fire_query_start_returns_instant_only_when_recorder_installed_onion() {
        use pir_sdk::AtomicMetrics;

        let mut client = OnionClient::new("wss://mock-onion");
        assert!(client.fire_query_start(0, 10).is_none());

        let recorder = Arc::new(AtomicMetrics::new());
        client.set_metrics_recorder(Some(recorder));
        assert!(client.fire_query_start(0, 10).is_some());
    }

    /// `fire_query_end` records non-zero duration when threading the
    /// captured `Instant`. We sleep a few ms to make the measured
    /// duration distinguishable from clock jitter.
    #[test]
    fn fire_query_end_records_non_zero_duration_with_recorder_onion() {
        use pir_sdk::AtomicMetrics;
        use std::thread::sleep;
        use std::time::Duration as StdDuration;

        let recorder = Arc::new(AtomicMetrics::new());
        let mut client = OnionClient::new("wss://mock-onion");
        client.set_metrics_recorder(Some(recorder.clone()));

        let started = client.fire_query_start(0, 10);
        assert!(started.is_some());
        sleep(StdDuration::from_millis(5));
        client.fire_query_end(0, 10, true, started);

        let snap = recorder.snapshot();
        assert_eq!(snap.queries_started, 1);
        assert_eq!(snap.queries_completed, 1);
        assert!(
            snap.min_query_latency_micros >= 1_000,
            "expected min_query_latency_micros >= 1000, got {}",
            snap.min_query_latency_micros
        );
    }

    /// `fire_query_end` with `started_at = None` records `Duration::ZERO`
    /// — best-effort observation per [`PirMetrics::on_query_end`].
    #[test]
    fn fire_query_end_with_none_start_records_zero_duration_onion() {
        use pir_sdk::AtomicMetrics;

        let recorder = Arc::new(AtomicMetrics::new());
        let mut client = OnionClient::new("wss://mock-onion");

        let started = client.fire_query_start(0, 10); // None (no recorder yet)
        client.set_metrics_recorder(Some(recorder.clone()));
        client.fire_query_end(0, 10, true, started);

        let snap = recorder.snapshot();
        assert_eq!(snap.queries_completed, 1);
        assert_eq!(snap.min_query_latency_micros, 0);
        assert_eq!(snap.max_query_latency_micros, 0);
    }

    // ─── Leakage recorder wiring ────────────────────────────────────────────

    /// `record_round` emits to an installed buffering recorder.
    #[test]
    fn leakage_recorder_records_via_helper_onion() {
        use pir_sdk::BufferingLeakageRecorder;

        let rec = Arc::new(BufferingLeakageRecorder::new());
        let mut client = OnionClient::new("wss://mock-onion");
        client.set_leakage_recorder(Some(rec.clone()));

        // OnionPIR INDEX shape: items[g] = INDEX_CUCKOO_NUM_HASHES = 2
        // (matches DPF) — captures the Merkle INDEX item-count symmetry
        // invariant in profile form.
        client.record_round(RoundProfile {
            kind: RoundKind::Index,
            server_id: 0,
            db_id: Some(0),
            request_bytes: 1024,
            response_bytes: 4096,
            items: vec![2; 75],
        });

        let snap = rec.snapshot();
        assert_eq!(snap.len(), 1);
        assert!(matches!(snap[0].kind, RoundKind::Index));
        assert_eq!(snap[0].server_id, 0); // Onion is single-server
        assert_eq!(snap[0].items.len(), 75);
        assert!(snap[0].items.iter().all(|&x| x == 2));
    }

    /// `set_leakage_recorder(None)` silences subsequent emissions.
    #[test]
    fn leakage_recorder_uninstall_silences_onion() {
        use pir_sdk::BufferingLeakageRecorder;

        let rec = Arc::new(BufferingLeakageRecorder::new());
        let mut client = OnionClient::new("wss://mock-onion");
        client.set_leakage_recorder(Some(rec.clone()));
        client.set_leakage_recorder(None);

        client.record_round(RoundProfile {
            kind: RoundKind::OnionKeyRegister,
            server_id: 0,
            db_id: Some(0),
            request_bytes: 100_000,
            response_bytes: 5,
            items: Vec::new(),
        });

        assert!(rec.is_empty());
    }

    /// Driving a real `fetch_server_info` through `MockTransport` emits
    /// exactly one `Info` round on server 0. Proves the wiring at the
    /// actual emission site.
    #[tokio::test]
    async fn leakage_recorder_captures_info_round_end_to_end_onion() {
        use crate::transport::mock::MockTransport;
        use pir_sdk::BufferingLeakageRecorder;

        let rec = Arc::new(BufferingLeakageRecorder::new());
        let mut client = OnionClient::new("wss://mock-onion");
        client.set_leakage_recorder(Some(rec.clone()));

        // Construct a minimal valid REQ_GET_INFO_JSON response. The
        // payload is a JSON blob; `fetch_server_info` parses it via
        // `parse_onion_params_per_db`. We need at least one valid DB
        // entry, otherwise the function errors out before recording the
        // round. To keep the test focused on the leakage-recorder wiring
        // (which fires regardless of parse outcome), build a JSON that
        // has at least one OnionPIR entry.
        let json = r#"{"main":{"backend":"onionpir","index_bins":1024,"chunk_bins":2048,"index_k":75,"chunk_k":80,"tag_seed":0,"index_slots_per_bin":4,"index_slot_size":13,"chunk_slot_size":44,"total_packed":1000}}"#;
        let payload_len = (1 + json.len()) as u32;
        let mut info_resp = Vec::with_capacity(4 + 1 + json.len());
        info_resp.extend_from_slice(&payload_len.to_le_bytes());
        info_resp.push(0x03); // RESP_GET_INFO_JSON
        info_resp.extend_from_slice(json.as_bytes());
        let total_response_size = info_resp.len() as u64;

        let mut mock = MockTransport::new("wss://mock-onion");
        mock.enqueue_response(info_resp);

        client.connect_with_transport(Box::new(mock));
        // `fetch_server_info` may or may not succeed depending on whether
        // the JSON triggers the catalog fallback path; we only care that
        // the Info round was recorded before any failure.
        let _ = client.fetch_server_info().await;

        let snap = rec.snapshot();
        assert!(!snap.is_empty(), "expected at least one Info round");
        let r = &snap[0];
        assert!(matches!(r.kind, RoundKind::Info));
        assert_eq!(r.server_id, 0); // Onion single-server
        assert_eq!(r.db_id, None);
        // request: REQ_GET_INFO_JSON is `[4B len=1][1B 0x03]` = 5 bytes.
        assert_eq!(r.request_bytes, 5);
        // response: full wire frame = 4 (length prefix) + 1 (variant) + json.
        assert_eq!(r.response_bytes, total_response_size);
        assert!(r.items.is_empty());
    }

    /// Leakage and metrics recorders coexist independently.
    #[tokio::test]
    async fn leakage_and_metrics_recorders_are_independent_onion() {
        use crate::transport::mock::MockTransport;
        use pir_sdk::{AtomicMetrics, BufferingLeakageRecorder};

        let leakage = Arc::new(BufferingLeakageRecorder::new());
        let metrics = Arc::new(AtomicMetrics::new());
        let mut client = OnionClient::new("wss://mock-onion");
        client.set_leakage_recorder(Some(leakage.clone()));
        client.set_metrics_recorder(Some(metrics.clone()));

        let json = r#"{"main":{"backend":"onionpir","index_bins":1024,"chunk_bins":2048,"index_k":75,"chunk_k":80,"tag_seed":0,"index_slots_per_bin":4,"index_slot_size":13,"chunk_slot_size":44,"total_packed":1000}}"#;
        let payload_len = (1 + json.len()) as u32;
        let mut info_resp = Vec::with_capacity(4 + 1 + json.len());
        info_resp.extend_from_slice(&payload_len.to_le_bytes());
        info_resp.push(0x03);
        info_resp.extend_from_slice(json.as_bytes());

        let mut mock = MockTransport::new("wss://mock-onion");
        mock.enqueue_response(info_resp);

        client.connect_with_transport(Box::new(mock));
        let _ = client.fetch_server_info().await;

        // Leakage saw the Info round.
        assert!(!leakage.is_empty());
        // Metrics saw byte counts via the transport.
        let snap = metrics.snapshot();
        assert!(snap.bytes_sent > 0);
        assert!(snap.bytes_received > 0);
    }
}
