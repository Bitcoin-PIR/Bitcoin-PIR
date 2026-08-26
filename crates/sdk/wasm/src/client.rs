//! Async PIR clients exposed to JavaScript via `wasm-bindgen`.
//!
//! Wraps the native [`DpfClient`] and [`HarmonyClient`] from
//! `pir-sdk-client` so browser callers get the same query orchestration,
//! Merkle verification, and padding invariants the native clients provide
//! — with the only differences being:
//!
//! * **Transport**: the wrapped clients auto-select
//!   [`WasmWebSocketTransport`] at connect time on `wasm32-unknown-unknown`
//!   (via the `cfg(target_arch = "wasm32")` branch inside
//!   `pir-sdk-client::DpfClient::connect` / `HarmonyClient::connect`), so
//!   JS callers never touch the transport layer directly.
//! * **Types on the JS boundary**: `ScriptHash` (`[u8; 20]`) is passed as
//!   a packed `Uint8Array` whose `length` is a multiple of 20, and
//!   `QueryResult`/`SyncResult` are returned as plain JS objects
//!   (`JsValue` built via `serde_wasm_bindgen::to_value(...)`) rather
//!   than typed classes, because the TypeScript side of the web app
//!   already deals with the JSON-shape UTXO entries that match the
//!   native [`QueryResult::to_json`](crate::WasmQueryResult) output.
//!
//! 🔒 Padding invariants (K=75 INDEX / K_CHUNK=80 CHUNK / 25-MERKLE) are
//! enforced inside the native clients — this wrapper is a thin translation
//! layer and must not bypass them. See `CLAUDE.md` → "Query Padding".
//!
//! # Not wrapped: `OnionClient`
//!
//! `pir-sdk-client::OnionClient` is a pass-through to the upstream
//! `onionpir` crate, which depends on a C++ SEAL build. SEAL does not
//! compile to `wasm32-unknown-unknown`, so there is no `WasmOnionClient`
//! for now — browsers that need OnionPIR must keep the existing
//! TypeScript path (`web/src/onionpir_client.ts`) until a WASM-compatible
//! FHE backend is available.

use js_sys::{Array, Uint8Array};
use pir_sdk::{PirClient, QueryResult, ScriptHash, SyncResult};
use pir_sdk_client::attest::{AttestVerification, SevStatus};
#[cfg(target_arch = "wasm32")]
use pir_sdk_client::HintProgress;
use pir_sdk_client::{
    verify_database_proof_response as verify_database_proof_response_payload,
    verify_database_proof_v2_response as verify_database_proof_v2_response_payload,
    DatabaseProofPolicy, DpfClient, HarmonyClient, OramClient, RootPolicy, VerifiedDatabaseRoots,
    ProductQueryShapeV1, PRP_FASTPRP, PRP_HMR12,
};
use wasm_bindgen::prelude::*;

use crate::service::{
    bat_v2_outcome_json_v2, build_proof_v1, build_retained_proof_v1, grant_json_v1,
    parse_digest_v1, parse_provider_and_key_v1, parse_scope_id_v1, parse_service_trust_v1,
    WasmAcceptedRetainedBatV2PolicyV2, WasmAcceptedRetainedServiceRedemptionV1,
    WasmAcceptedServicePolicyV1, WasmServicePowChallengeV1, WasmVerifiedBatV2RedemptionV2,
};
use crate::{to_js_object, WasmAtomicMetrics, WasmDatabaseCatalog, WasmQueryResult};

// These symbols are only referenced from wasm32-gated bridges below, so
// keep their imports gated too — on native we only compile recorder-impl
// unit tests that use native types directly.
#[cfg(target_arch = "wasm32")]
use pir_sdk::{ConnectionState, StateListener, SyncProgress};
#[cfg(target_arch = "wasm32")]
use send_wrapper::SendWrapper;
#[cfg(target_arch = "wasm32")]
use std::sync::Arc;

// ─── Helpers ────────────────────────────────────────────────────────────────

/// The input `Uint8Array` is a packed concatenation of 20-byte script
/// hashes; split it into `Vec<[u8; 20]>` with strict length validation so
/// a caller who forgot the padding (e.g. passed 19 bytes) gets a clear
/// error rather than a silently truncated query.
///
/// Returns a plain `String` on failure so the helper is callable from
/// native unit tests; the `#[wasm_bindgen]` methods wrap the error in
/// `JsError` at their boundary (`JsError::new` is a wasm-bindgen import
/// and panics when called on non-wasm targets).
fn unpack_script_hashes(packed: &[u8]) -> Result<Vec<ScriptHash>, String> {
    const SH_LEN: usize = 20;
    if packed.len() % SH_LEN != 0 {
        return Err(format!(
            "scriptHashes length must be a multiple of {} (got {})",
            SH_LEN,
            packed.len()
        ));
    }
    let n = packed.len() / SH_LEN;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let mut sh = [0u8; SH_LEN];
        sh.copy_from_slice(&packed[i * SH_LEN..(i + 1) * SH_LEN]);
        out.push(sh);
    }
    Ok(out)
}

/// Same one-byte PRP backend validation the `#[wasm_bindgen]` setters
/// use, factored out so unit tests can exercise it without constructing
/// a `JsError` (which panics on native).
fn validate_prp_backend(backend: u8) -> Result<(), String> {
    if backend != PRP_HMR12 && backend != PRP_FASTPRP {
        return Err(format!(
            "unknown PRP backend: {} (use PRP_HMR12={} or PRP_FASTPRP={}; \
             PRP_ALF=2 was removed 2026-05-12)",
            backend, PRP_HMR12, PRP_FASTPRP
        ));
    }
    Ok(())
}

/// Same 16-byte master-key validation the `#[wasm_bindgen]` setter
/// uses, factored out for native-side unit tests (see
/// `validate_prp_backend` for the `JsError`-panic rationale).
fn validate_master_key_len(len: usize) -> Result<(), String> {
    if len != 16 {
        return Err(format!("masterKey must be 16 bytes (got {})", len));
    }
    Ok(())
}

type AttestSeedSlots = [Option<[u8; 32]>; 2];

/// Invalidate the previous attestation/handshake binding before any fallible
/// part of a new attestation attempt. If the request fails, no stale seed can
/// be reused by a later secure-channel upgrade.
fn begin_attest_attempt(slots: &mut AttestSeedSlots, server_index: usize) {
    slots[server_index] = None;
}

/// Consume the binding before the fallible handshake starts. A failed
/// handshake therefore requires a fresh attestation instead of permitting a
/// replay with the same ephemeral key.
fn take_attest_seed(slots: &mut AttestSeedSlots, server_index: usize) -> Option<[u8; 32]> {
    slots[server_index].take()
}

/// Pretty-print a `PirError` for the JS side. We stringify via
/// `Display` (the `thiserror` output) — callers can still distinguish
/// kinds downstream by inspecting the message prefix, matching the
/// error-taxonomy placeholder in the SDK roadmap.
fn err_to_js(e: pir_sdk::PirError) -> JsError {
    JsError::new(&e.to_string())
}

/// Serialize a native transport-free service plan to the JS diagnostic shape.
/// Optional lower-bound counters are omitted, never emitted as `null`, so the
/// strict TypeScript canonicalizer cannot confuse "unknown" with zero.
fn product_query_plan_json(plan: &ProductQueryShapeV1) -> serde_json::Value {
    let mut lower_bounds = serde_json::Map::new();
    lower_bounds.insert(
        "logicalInputs".into(),
        serde_json::Value::from(plan.lower_bounds.logical_inputs),
    );
    lower_bounds.insert(
        "frames".into(),
        serde_json::Value::from(plan.lower_bounds.frames),
    );
    if let Some(request_bytes) = plan.lower_bounds.request_bytes {
        lower_bounds.insert(
            "requestBytes".into(),
            serde_json::Value::String(request_bytes.to_string()),
        );
    }
    if let Some(work_units) = plan.lower_bounds.work_units {
        // ProductQueryShapeV1 represents u64 counters as canonical decimal
        // strings so JavaScript never loses integer precision.
        lower_bounds.insert(
            "workUnits".into(),
            serde_json::Value::String(work_units.to_string()),
        );
    }
    if let Some(hint_groups) = plan.lower_bounds.hint_groups {
        lower_bounds.insert(
            "hintGroups".into(),
            serde_json::Value::from(hint_groups),
        );
    }
    if let Some(concurrent_sockets) = plan.lower_bounds.concurrent_sockets {
        lower_bounds.insert(
            "concurrentSockets".into(),
            serde_json::Value::from(concurrent_sockets),
        );
    }

    let mut root = serde_json::Map::new();
    root.insert(
        "backend".into(),
        serde_json::Value::String(plan.backend.as_str().into()),
    );
    root.insert(
        "workload".into(),
        serde_json::Value::String(plan.workload.as_str().into()),
    );
    root.insert(
        "lowerBounds".into(),
        serde_json::Value::Object(lower_bounds),
    );
    if let Some(pbc_rounds) = plan.pbc_rounds {
        root.insert("pbcRounds".into(), serde_json::Value::from(pbc_rounds));
    }
    if let Some(exact_index_frames) = plan.exact_index_frames {
        root.insert(
            "exactIndexFrames".into(),
            serde_json::Value::from(exact_index_frames),
        );
    }

    let omitted = [
        (plan.omitted.request_bytes, "requestBytes"),
        (plan.omitted.response_bytes, "responseBytes"),
        (plan.omitted.merkle_frames, "merkleFrames"),
        (
            plan.omitted.additional_chunk_frames,
            "dataDependentAdditionalChunkFrames",
        ),
        (plan.omitted.sibling_hint_groups, "siblingHintGroups"),
    ]
    .into_iter()
    .filter_map(|(is_omitted, label)| {
        is_omitted.then_some(serde_json::Value::String(label.into()))
    })
    .collect();
    root.insert("omitted".into(), serde_json::Value::Array(omitted));
    serde_json::Value::Object(root)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn parse_optional_hex_array<const N: usize>(
    field: &str,
    value: Option<String>,
) -> Result<Option<[u8; N]>, JsError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let bytes =
        hex::decode(value).map_err(|e| JsError::new(&format!("{field}: invalid hex: {e}")))?;
    let arr: [u8; N] = bytes.as_slice().try_into().map_err(|_| {
        JsError::new(&format!(
            "{field}: expected {} bytes ({} hex chars), got {} bytes",
            N,
            N * 2,
            bytes.len()
        ))
    })?;
    Ok(Some(arr))
}

fn database_proof_policy(
    expected_params_hash_hex: Option<String>,
    allowed_builder_binary_sha256_hex: Option<String>,
    allowed_builder_git_commit: Option<String>,
) -> Result<DatabaseProofPolicy, JsError> {
    let mut policy = DatabaseProofPolicy::mainnet();
    policy.expected_params_hash =
        parse_optional_hex_array::<32>("expectedParamsHashHex", expected_params_hash_hex)?;
    if let Some(hash) = parse_optional_hex_array::<32>(
        "allowedBuilderBinarySha256Hex",
        allowed_builder_binary_sha256_hex,
    )? {
        policy.allowed_builder_binary_sha256.push(hash);
    }
    if let Some(commit) = allowed_builder_git_commit {
        let commit = commit.trim();
        if !commit.is_empty() {
            policy.allowed_builder_git_commits.push(commit.to_owned());
        }
    }
    Ok(policy)
}

fn database_proof_json(roots: &VerifiedDatabaseRoots) -> serde_json::Value {
    let onion = roots.onion_layout_v2;
    serde_json::json!({
        "dbId": roots.db_id,
        "manifestRootHex": roots.manifest_root_hex(),
        "buildKind": pir_db_attest::build_kind_label(roots.build_kind),
        "fromHeight": roots.from_height,
        "fromBlockHashHex": roots.from_block_hash_hex(),
        "height": roots.height,
        "blockHashHex": roots.block_hash_hex(),
        "muhashHex": roots.muhash_hex(),
        "bucketSuperRootHex": roots.bucket_super_root_hex(),
        "onionSuperRootHex": roots.onion_super_root_hex(),
        "onionEntrySize": roots.onion_entry_size,
        "proofVersion": if onion.is_some() { 2 } else { 1 },
        "onionTotalPackedEntries": onion.map(|layout| layout.total_packed_entries),
        "onionIndexBinsPerTable": onion.map(|layout| layout.index_bins_per_table),
        "onionChunkBinsPerTable": onion.map(|layout| layout.chunk_bins_per_table),
        "onionIndexSlotsPerBin": onion.map(|layout| layout.index_slots_per_bin),
        "onionIndexSlotSize": onion.map(|layout| layout.index_slot_size),
        "paramsHashHex": hex_encode(&roots.params_hash),
        "networkMagicHex": hex_encode(&roots.network_magic),
        "builderBinarySha256Hex": hex_encode(&roots.builder_binary_sha256),
        "builderGitCommit": roots.builder_git_commit,
    })
}

/// Validate and strip one complete length-prefixed PIR response frame.
///
/// The standalone TypeScript transport returns `[u32 len LE][payload]`,
/// whereas `pir-sdk-client` proof decoders intentionally accept only the
/// variant-first payload returned by `PirTransport::roundtrip`.  Keep this
/// framing boundary explicit and reject truncated or concatenated records
/// instead of guessing which shape the caller supplied.
fn database_proof_payload_from_frame(frame: &[u8]) -> Result<&[u8], String> {
    if frame.len() < 5 {
        return Err(format!(
            "database proof response frame too short: expected at least 5 bytes, got {}",
            frame.len()
        ));
    }
    let declared = u32::from_le_bytes(frame[0..4].try_into().unwrap()) as usize;
    let actual = frame.len() - 4;
    if declared != actual {
        return Err(format!(
            "database proof response frame length mismatch: declared {}, got {}",
            declared, actual
        ));
    }
    Ok(&frame[4..])
}

/// Build the JS-facing data-only JSON shape of a `SyncResult`.
///
/// Plain objects cannot retain the private provenance carried by a
/// [`WasmQueryResult`](crate::WasmQueryResult), so `merkleVerified` is always
/// false. Callers that need native provenance must use `getResult()` and keep
/// the returned opaque handle.
fn sync_result_to_json(sync: &SyncResult) -> serde_json::Value {
    let results: Vec<serde_json::Value> = sync
        .results
        .iter()
        .map(query_result_option_to_json)
        .collect();

    serde_json::json!({
        "results": results,
        "syncedHeight": sync.synced_height,
        "wasFreshSync": sync.was_fresh_sync,
    })
}

fn query_result_option_to_json(result: &Option<QueryResult>) -> serde_json::Value {
    match result {
        None => serde_json::Value::Null,
        Some(qr) => {
            let entries: Vec<serde_json::Value> = qr
                .entries
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "txid": hex_encode(&e.txid),
                        "vout": e.vout,
                        "amountSats": e.amount_sats,
                    })
                })
                .collect();
            serde_json::json!({
                "entries": entries,
                "isWhale": qr.is_whale,
                "totalBalance": qr.total_balance(),
                "merkleVerified": false,
            })
        }
    }
}

fn query_results_to_json(results: &[Option<QueryResult>]) -> Vec<serde_json::Value> {
    results.iter().map(query_result_option_to_json).collect()
}

// ─── JS callback bridges (wasm32-only) ─────────────────────────────────────
//
// These wrap a `js_sys::Function` so it can be handed to the native
// `DpfClient` through the `StateListener` / `SyncProgress` traits.
//
// `js_sys::Function` is `!Send + !Sync` — it's a handle into the browser's
// single-threaded event loop — but both traits require `Send + Sync`.
// `send_wrapper::SendWrapper<T>` lies about the bound (`unsafe impl Send +
// Sync`) and panics on cross-thread access. This is sound on wasm32 since
// `wasm-bindgen-futures` runs everything on the single JS event loop; on
// native the wrapper doesn't exist and these bridges aren't compiled.

/// `StateListener` adapter that forwards each transition to a JS
/// function as a single `string` argument matching
/// [`ConnectionState::as_str`].
#[cfg(target_arch = "wasm32")]
struct JsStateListener {
    cb: SendWrapper<js_sys::Function>,
}

#[cfg(target_arch = "wasm32")]
impl StateListener for JsStateListener {
    fn on_state_change(&self, state: ConnectionState) {
        // Best-effort — a throwing JS callback shouldn't take the client
        // down, so we drop the Result.
        let _ = (*self.cb).call1(&JsValue::NULL, &JsValue::from_str(state.as_str()));
    }
}

/// `SyncProgress` adapter that serialises each event as a plain JSON
/// object and invokes the JS function with one argument.
///
/// Event shapes (`type` discriminates):
/// * `{ type: "step_start", stepIndex, totalSteps, description }`
/// * `{ type: "step_progress", stepIndex, progress }`
/// * `{ type: "step_complete", stepIndex }`
/// * `{ type: "complete", syncedHeight }`
/// * `{ type: "error", message }`
#[cfg(target_arch = "wasm32")]
struct JsSyncProgress {
    cb: SendWrapper<js_sys::Function>,
}

#[cfg(target_arch = "wasm32")]
impl JsSyncProgress {
    fn emit(&self, event: serde_json::Value) {
        let val = to_js_object(&event);
        let _ = (*self.cb).call1(&JsValue::NULL, &val);
    }
}

#[cfg(target_arch = "wasm32")]
impl SyncProgress for JsSyncProgress {
    fn on_step_start(&self, step_index: usize, total_steps: usize, description: &str) {
        self.emit(serde_json::json!({
            "type": "step_start",
            "stepIndex": step_index,
            "totalSteps": total_steps,
            "description": description,
        }));
    }

    fn on_step_progress(&self, step_index: usize, progress: f32) {
        self.emit(serde_json::json!({
            "type": "step_progress",
            "stepIndex": step_index,
            "progress": progress,
        }));
    }

    fn on_step_complete(&self, step_index: usize) {
        self.emit(serde_json::json!({
            "type": "step_complete",
            "stepIndex": step_index,
        }));
    }

    fn on_complete(&self, synced_height: u32) {
        self.emit(serde_json::json!({
            "type": "complete",
            "syncedHeight": synced_height,
        }));
    }

    fn on_error(&self, error: &pir_sdk::PirError) {
        self.emit(serde_json::json!({
            "type": "error",
            "message": error.to_string(),
        }));
    }
}

/// `HintProgress` adapter that serialises each per-group event as a
/// plain JSON object and invokes the JS function with one argument.
///
/// Event shape: `{ done: number, total: number, phase: "index" | "chunk" }`.
/// `done` is the running count of groups whose hints have been loaded;
/// `total` is the constant `index_k + chunk_k` (typically 155 for the
/// production HarmonyPIR config). The callback fires once per main
/// group on a fresh fetch, or once with `done === total` on a cache
/// hit / already-loaded state.
#[cfg(target_arch = "wasm32")]
struct JsHintProgress {
    cb: SendWrapper<js_sys::Function>,
}

#[cfg(target_arch = "wasm32")]
impl HintProgress for JsHintProgress {
    fn on_group_complete(&self, done: u32, total: u32, phase: &str) {
        let event = serde_json::json!({
            "done": done,
            "total": total,
            "phase": phase,
        });
        let val = to_js_object(&event);
        // Best-effort — a throwing JS callback shouldn't take the hint
        // fetch down, so we drop the Result.
        let _ = (*self.cb).call1(&JsValue::NULL, &val);
    }
}

// ─── WasmSyncResult ─────────────────────────────────────────────────────────

/// WASM wrapper for [`SyncResult`].
///
/// Exposes the merged per-script-hash results plus sync metadata
/// (`syncedHeight`, `wasFreshSync`). Entries are surfaced both as
/// individual [`WasmQueryResult`] objects (so callers that already use
/// the typed class get the same API) and as a JSON blob (so callers that
/// just want to splat the result into a UI get a plain object).
#[wasm_bindgen]
pub struct WasmSyncResult {
    inner: SyncResult,
}

#[wasm_bindgen]
impl WasmSyncResult {
    /// Number of per-script-hash result slots (= length of the input
    /// `scriptHashes` array passed to `sync`).
    #[wasm_bindgen(getter, js_name = resultCount)]
    pub fn result_count(&self) -> usize {
        self.inner.results.len()
    }

    /// Synced height — the tip height the final merged result reflects.
    ///
    /// For servers that don't publish a height (legacy Harmony without
    /// `REQ_GET_DB_CATALOG`), this is `0`. See `CLAUDE.md` →
    /// "HarmonyClient REQ_GET_DB_CATALOG with legacy fallback" for the
    /// upgrade path.
    #[wasm_bindgen(getter, js_name = syncedHeight)]
    pub fn synced_height(&self) -> u32 {
        self.inner.synced_height
    }

    /// Whether the sync started from a fresh snapshot (vs an incremental
    /// delta chain from a previous height).
    #[wasm_bindgen(getter, js_name = wasFreshSync)]
    pub fn was_fresh_sync(&self) -> bool {
        self.inner.was_fresh_sync
    }

    /// Get the per-script-hash [`WasmQueryResult`] at `index`, or `null`
    /// if the script hash was not found (and Merkle-verified absent when
    /// the DB publishes commitments).
    ///
    /// Mirrors the `results: Vec<Option<QueryResult>>` shape of the
    /// underlying sync: `None` = verified absent, `Some(qr)` with
    /// `merkleVerified = false` = untrusted/tainted result.
    #[wasm_bindgen(js_name = getResult)]
    pub fn get_result(&self, index: usize) -> Option<WasmQueryResult> {
        self.inner
            .results
            .get(index)
            .and_then(|r| r.as_ref())
            .cloned()
            .map(WasmQueryResult::from_native)
    }

    /// Convert the full sync result to a data-only plain JSON object.
    /// Verification provenance cannot survive conversion to caller-mutable
    /// JSON, so every `merkleVerified` property is false. Use `getResult()`
    /// to retain the opaque native provenance marker.
    ///
    /// Shape:
    /// ```json
    /// {
    ///   "results": [
    ///     null,
    ///     { "entries": [...], "isWhale": false,
    ///       "totalBalance": 0, "merkleVerified": false }
    ///   ],
    ///   "syncedHeight": 900000,
    ///   "wasFreshSync": true
    /// }
    /// ```
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> JsValue {
        to_js_object(&sync_result_to_json(&self.inner))
    }
}

// ─── WasmAttestVerification ────────────────────────────────────────────────

/// JS-visible result of a `WasmDpfClient.attest()` (or
/// `WasmHarmonyClient.attest()`) call.
///
/// Carries the server's self-reported binary hash + git rev + per-DB
/// manifest roots + V2 channel pubkey, plus the SEV-SNP report binding
/// status. The raw `sevSnpReport` bytes are also exposed so a future
/// browser-side AMD VCEK chain verifier (Slice D) can authenticate the
/// signature without re-fetching the report.
///
/// Caller workflow:
/// 1. `await client.attest(serverIndex)` → this object.
/// 2. Read `sevStatus` — if `"reportDataMatch"`, the server's
///    self-reported state is internally consistent with the chip-
///    signed REPORT_DATA. Anything else means "do not trust the
///    self-reported fields".
/// 3. (Slice D) Verify `sevSnpReport` against AMD's VCEK chain to
///    prove the report itself is signed by real silicon.
/// 4. `await client.upgradeToSecureChannel(attest0.serverStaticPub,
///    attest1.serverStaticPub)` — wraps both connections with the
///    AEAD frame layer.
#[wasm_bindgen]
pub struct WasmAttestVerification {
    inner: AttestVerification,
}

impl WasmAttestVerification {
    pub(crate) fn from_inner(inner: AttestVerification) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
impl WasmAttestVerification {
    /// 32-byte client nonce sent in REQ_ATTEST. Hex-encoded.
    #[wasm_bindgen(getter, js_name = nonceHex)]
    pub fn nonce_hex(&self) -> String {
        hex_encode(&self.inner.nonce)
    }

    /// SEV-SNP REPORT_DATA binding status as a string. One of:
    /// `"noSevHost"`, `"reportDataMatch"`, `"reportDataMismatch"`,
    /// `"malformedReport"`. Use this to decide whether the
    /// self-reported fields below are trustworthy.
    #[wasm_bindgen(getter, js_name = sevStatus)]
    pub fn sev_status(&self) -> String {
        match self.inner.sev_status {
            SevStatus::NoSevHost => "noSevHost",
            SevStatus::ReportDataMatch => "reportDataMatch",
            SevStatus::ReportDataMismatch => "reportDataMismatch",
            SevStatus::MalformedReport => "malformedReport",
        }
        .to_string()
    }

    /// SHA-256 of the running `unified_server` binary (server-side
    /// self-report). Hex-encoded. Trusted only if `sevStatus` is
    /// `"reportDataMatch"`.
    #[wasm_bindgen(getter, js_name = binarySha256Hex)]
    pub fn binary_sha256_hex(&self) -> String {
        hex_encode(&self.inner.response.binary_sha256)
    }

    /// X25519 public key the server uses for the encrypted channel.
    /// Returns the raw 32 bytes — pass directly to
    /// [`WasmDpfClient::upgrade_to_secure_channel`]. All-zero if the
    /// server doesn't yet have a channel key.
    #[wasm_bindgen(getter, js_name = serverStaticPub)]
    pub fn server_static_pub(&self) -> Uint8Array {
        Uint8Array::from(&self.inner.response.server_static_pub[..])
    }

    /// Same data as [`Self::server_static_pub`] but hex-encoded (for
    /// display / logging / cross-check against operator-published
    /// values).
    #[wasm_bindgen(getter, js_name = serverStaticPubHex)]
    pub fn server_static_pub_hex(&self) -> String {
        hex_encode(&self.inner.response.server_static_pub)
    }

    /// Git commit baked into the running server binary. May be
    /// suffixed with `-dirty` or be the literal `"unknown"`.
    #[wasm_bindgen(getter, js_name = gitRev)]
    pub fn git_rev(&self) -> String {
        self.inner.response.git_rev.clone()
    }

    /// Per-DB manifest roots in db_id order. Each entry is a 64-char
    /// hex string. The all-zero hash means that DB has no
    /// `MANIFEST.toml` (legacy / un-verified state).
    #[wasm_bindgen(getter, js_name = manifestRootsHex)]
    pub fn manifest_roots_hex(&self) -> Array {
        let arr = Array::new();
        for r in &self.inner.response.manifest_roots {
            arr.push(&JsValue::from_str(&hex_encode(r)));
        }
        arr
    }

    /// Raw signed SEV-SNP attestation report bytes (~1184 for v5).
    /// Empty if the server isn't on a SEV-SNP host. Slice D's AMD VCEK
    /// chain verifier consumes this directly.
    #[wasm_bindgen(getter, js_name = sevSnpReport)]
    pub fn sev_snp_report(&self) -> Uint8Array {
        Uint8Array::from(&self.inner.response.sev_snp_report[..])
    }

    /// Hex-encoded REPORT_DATA preimage hash the client recomputed
    /// locally. For comparison against the SEV report's REPORT_DATA[..32]
    /// when manually inspecting an attestation.
    #[wasm_bindgen(getter, js_name = expectedReportDataHashHex)]
    pub fn expected_report_data_hash_hex(&self) -> String {
        hex_encode(&self.inner.expected_report_data_hash)
    }

    /// Hex-encoded launch MEASUREMENT — the 48-byte hash that AMD's
    /// PSP signs into every SEV-SNP report, covering OVMF + the loaded
    /// UKI bytes (kernel + initramfs + cmdline). For Tier 3 deployments
    /// this is the operator-published value that pins the running
    /// software stack: any change to the binary inside the initramfs
    /// flips the MEASUREMENT, so a verifier comparing against a pinned
    /// value can detect substitution.
    ///
    /// Returns the empty string when the server is not on a SEV-SNP
    /// host (i.e. `sev_snp_report` is empty) — there's no MEASUREMENT
    /// to extract from a non-existent report.
    ///
    /// Offset 0x90, length 48 within the SEV-SNP attestation report
    /// (matches `bpir-admin attest`'s `MEASUREMENT_OFFSET` constant).
    #[wasm_bindgen(getter, js_name = launchMeasurementHex)]
    pub fn launch_measurement_hex(&self) -> String {
        const MEASUREMENT_OFFSET: usize = 0x90;
        const MEASUREMENT_LEN: usize = 48;
        let report = &self.inner.response.sev_snp_report;
        if report.len() < MEASUREMENT_OFFSET + MEASUREMENT_LEN {
            return String::new();
        }
        hex_encode(&report[MEASUREMENT_OFFSET..MEASUREMENT_OFFSET + MEASUREMENT_LEN])
    }

    // ── Slice D.2 cert chain accessors ──────────────────────────────
    //
    // PEM-encoded ARK / ASK / VCEK certs the server bundled in its
    // AttestResult. Empty Uint8Arrays if the server didn't have a
    // VCEK chain loaded (--vcek-dir unset, or reading failed). Use
    // `verifyVcekChain` below for the one-shot validation rather
    // than fetching these and feeding them to a separate verifier.

    /// Raw PEM bytes of the AMD ARK (Root Key) cert. Empty when not
    /// bundled by the server.
    #[wasm_bindgen(getter, js_name = arkPem)]
    pub fn ark_pem(&self) -> Uint8Array {
        Uint8Array::from(&self.inner.response.ark_pem[..])
    }

    /// Raw PEM bytes of the AMD ASK (SEV Signing Key) cert. Empty
    /// when not bundled.
    #[wasm_bindgen(getter, js_name = askPem)]
    pub fn ask_pem(&self) -> Uint8Array {
        Uint8Array::from(&self.inner.response.ask_pem[..])
    }

    /// Raw PEM bytes of the per-chip VCEK cert. Empty when not
    /// bundled.
    #[wasm_bindgen(getter, js_name = vcekPem)]
    pub fn vcek_pem(&self) -> Uint8Array {
        Uint8Array::from(&self.inner.response.vcek_pem[..])
    }

    /// True when all three cert PEMs are non-empty. Cheap pre-check
    /// before calling `verifyVcekChain` — saves a WASM round-trip
    /// when the server hasn't loaded a chain.
    #[wasm_bindgen(getter, js_name = hasVcekChain)]
    pub fn has_vcek_chain(&self) -> bool {
        !self.inner.response.ark_pem.is_empty()
            && !self.inner.response.ask_pem.is_empty()
            && !self.inner.response.vcek_pem.is_empty()
    }

    // ── Slice D.3 verifier ──────────────────────────────────────────

    /// One-shot AMD VCEK chain validation. Verifies:
    ///   1. The ARK PEM's SHA-256 fingerprint matches
    ///      `expectedArkFingerprint` (a 32-byte operator-pinned value
    ///      — typically baked into the web bundle at build time so a
    ///      malicious server can't substitute a forged root).
    ///   2. ARK is self-signed; ARK signs ASK (RSA-PSS-SHA384).
    ///   3. ASK signs the VCEK (RSA-PSS-SHA384).
    ///   4. The SEV-SNP report's ECDSA-P384-SHA384 signature
    ///      verifies against the VCEK's pubkey.
    ///
    /// On success returns nothing (resolves the Promise). On failure
    /// throws a `JsError` whose message is a single-line diagnostic
    /// from `pir_attest_verify::VerifyError`.
    ///
    /// `expectedArkFingerprint` MUST be exactly 32 bytes (SHA-256 of
    /// the ARK's DER-encoded certificate). Pass `null` to skip the
    /// pinning check (NOT recommended for production — without a
    /// pinned root, a malicious server could supply a self-signed
    /// "ARK" that doesn't actually belong to AMD).
    #[wasm_bindgen(js_name = verifyVcekChain)]
    pub fn verify_vcek_chain(
        &self,
        expected_ark_fingerprint: Option<Box<[u8]>>,
    ) -> Result<(), JsError> {
        if !self.has_vcek_chain() {
            return Err(JsError::new(
                "verifyVcekChain: server didn't bundle a VCEK chain (arkPem/askPem/vcekPem empty)",
            ));
        }
        let pin = match expected_ark_fingerprint {
            None => None,
            Some(bytes) => {
                if bytes.len() != 32 {
                    return Err(JsError::new(&format!(
                        "expectedArkFingerprint must be exactly 32 bytes, got {}",
                        bytes.len()
                    )));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(arr)
            }
        };
        // Step 1+2+3: chain + pinned ARK
        pir_attest_verify::verify_chain(
            &self.inner.response.ark_pem,
            &self.inner.response.ask_pem,
            &self.inner.response.vcek_pem,
            pin,
        )
        .map_err(|e| JsError::new(&format!("{}", e)))?;
        // Step 4: report sig against VCEK
        pir_attest_verify::verify_report_against_vcek(
            &self.inner.response.sev_snp_report,
            &self.inner.response.vcek_pem,
        )
        .map_err(|e| JsError::new(&format!("{}", e)))?;
        Ok(())
    }

    /// Highest-level SEV-SNP check: runs `verifyVcekChain`'s four
    /// steps AND the policy assertions described below — in a single
    /// call. On success, the report is fully trustworthy
    /// (signature-anchored AND content-acceptable).
    ///
    /// `expectedArkFingerprint`: same as `verifyVcekChain`. Pass the
    /// `AMD_TURIN_ARK_FINGERPRINT` constant from `attest-pin.ts` for
    /// production.
    ///
    /// `policy` is a `WasmPolicyRequirements` (constructed via its
    /// JS-visible constructor + setters). Defaults to the strictest
    /// production policy: VMPL 0, no debug, no migration, TCB
    /// monotonic. Override individual fields for tests / non-strict
    /// deployments.
    ///
    /// Throws a single-line JsError on the FIRST failing step (chain
    /// → report sig → policy). Use `verifyVcekChain` directly if you
    /// want to surface the chain / sig failure separately from a
    /// policy failure.
    #[wasm_bindgen(js_name = verifyFull)]
    pub fn verify_full(
        &self,
        expected_ark_fingerprint: Option<Box<[u8]>>,
        policy: &WasmPolicyRequirements,
    ) -> Result<(), JsError> {
        if !self.has_vcek_chain() {
            return Err(JsError::new(
                "verifyFull: server didn't bundle a VCEK chain (arkPem/askPem/vcekPem empty)",
            ));
        }
        let pin = match expected_ark_fingerprint {
            None => None,
            Some(bytes) => {
                if bytes.len() != 32 {
                    return Err(JsError::new(&format!(
                        "expectedArkFingerprint must be exactly 32 bytes, got {}",
                        bytes.len()
                    )));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(arr)
            }
        };
        pir_attest_verify::verify_full(
            &self.inner.response.sev_snp_report,
            &self.inner.response.ark_pem,
            &self.inner.response.ask_pem,
            &self.inner.response.vcek_pem,
            pin,
            &policy.inner,
        )
        .map_err(|e| JsError::new(&format!("{}", e)))?;
        Ok(())
    }
}

/// JS-visible policy requirements for [`WasmAttestVerification::verify_full`].
/// Constructed with sensible production defaults (strict). Mutate
/// individual fields via the setters to relax.
#[wasm_bindgen]
pub struct WasmPolicyRequirements {
    inner: pir_attest_verify::policy::PolicyRequirements,
}

#[wasm_bindgen]
impl WasmPolicyRequirements {
    /// Construct the strictest production policy: VMPL 0, no debug,
    /// no MA migration, TCB-monotonic. No measurement / family /
    /// image pin (set via the corresponding setters if you want them).
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: pir_attest_verify::policy::PolicyRequirements::default(),
        }
    }

    /// Raise the VMPL ceiling. Production: leave at 0.
    #[wasm_bindgen(js_name = setMaxVmpl)]
    pub fn set_max_vmpl(&mut self, v: u32) {
        self.inner.max_vmpl = v;
    }

    /// Permit guests with `policy.debug_allowed` set. Production: leave false.
    #[wasm_bindgen(js_name = setAllowDebug)]
    pub fn set_allow_debug(&mut self, v: bool) {
        self.inner.allow_debug = v;
    }

    /// Permit guests with `policy.migrate_ma_allowed` set. Production: leave false.
    #[wasm_bindgen(js_name = setAllowMigrateMa)]
    pub fn set_allow_migrate_ma(&mut self, v: bool) {
        self.inner.allow_migrate_ma = v;
    }

    /// Require guests to have `policy.single_socket_required`. Off by default.
    #[wasm_bindgen(js_name = setRequireSingleSocket)]
    pub fn set_require_single_socket(&mut self, v: bool) {
        self.inner.require_single_socket = v;
    }

    /// Pin the expected MEASUREMENT (48 bytes). Must be exactly 48
    /// bytes or a JsError is thrown. Set to the operator-published
    /// value for your Tier 3 UKI.
    #[wasm_bindgen(js_name = setExpectedMeasurement)]
    pub fn set_expected_measurement(&mut self, bytes: &[u8]) -> Result<(), JsError> {
        if bytes.len() != 48 {
            return Err(JsError::new(&format!(
                "expectedMeasurement must be exactly 48 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 48];
        arr.copy_from_slice(bytes);
        self.inner.expected_measurement = Some(arr);
        Ok(())
    }

    /// Pin the expected family_id (16 bytes).
    #[wasm_bindgen(js_name = setExpectedFamilyId)]
    pub fn set_expected_family_id(&mut self, bytes: &[u8]) -> Result<(), JsError> {
        if bytes.len() != 16 {
            return Err(JsError::new(&format!(
                "expectedFamilyId must be exactly 16 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(bytes);
        self.inner.expected_family_id = Some(arr);
        Ok(())
    }

    /// Pin the expected image_id (16 bytes).
    #[wasm_bindgen(js_name = setExpectedImageId)]
    pub fn set_expected_image_id(&mut self, bytes: &[u8]) -> Result<(), JsError> {
        if bytes.len() != 16 {
            return Err(JsError::new(&format!(
                "expectedImageId must be exactly 16 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(bytes);
        self.inner.expected_image_id = Some(arr);
        Ok(())
    }
}

impl Default for WasmPolicyRequirements {
    fn default() -> Self {
        Self::new()
    }
}

/// JS-visible accessor for the Turin ARK fingerprint pinned in
/// pir-attest-verify (matches `web/src/attest-pin.ts`). Returns the
/// 32-byte SHA-256 as a Uint8Array. Pass directly to
/// [`WasmAttestVerification::verify_full`] /
/// [`WasmAttestVerification::verify_vcek_chain`] for Turin servers.
#[wasm_bindgen(js_name = turinArkFingerprint)]
pub fn turin_ark_fingerprint() -> Uint8Array {
    Uint8Array::from(&pir_attest_verify::TURIN_ARK_FINGERPRINT_SHA256[..])
}

/// Verify a standalone SEV-SNP report and PEM certificate chain.
///
/// This is the static-artifact companion to
/// [`WasmAttestVerification::verify_full`]. Live runtime attestation gets
/// its report and VCEK chain from the server response; database-authenticity
/// proof pages load the same shape from `/proofs/...` static files instead.
#[wasm_bindgen(js_name = verifyRawSnpReport)]
pub fn verify_raw_snp_report(
    report_bytes: &[u8],
    ark_pem: &str,
    ask_pem: &str,
    vcek_pem: &str,
    expected_ark_fingerprint: Option<Box<[u8]>>,
    policy: &WasmPolicyRequirements,
) -> Result<(), JsError> {
    let pin = match expected_ark_fingerprint {
        None => None,
        Some(bytes) => {
            if bytes.len() != 32 {
                return Err(JsError::new(&format!(
                    "expectedArkFingerprint must be exactly 32 bytes, got {}",
                    bytes.len()
                )));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Some(arr)
        }
    };
    pir_attest_verify::verify_full(
        report_bytes,
        ark_pem.as_bytes(),
        ask_pem.as_bytes(),
        vcek_pem.as_bytes(),
        pin,
        &policy.inner,
    )
    .map_err(|e| JsError::new(&format!("{}", e)))?;
    Ok(())
}

// ─── WasmDatabaseProof ─────────────────────────────────────────────────────

/// JS-visible summary of a verified attested-builder database proof.
///
/// The Rust side has already checked the proof bundle against the database
/// catalog and policy before constructing this object. Hex values are display
/// oriented: block hashes and MuHash use Bitcoin Core display order; Merkle
/// roots and SHA-256 values are raw hex.
#[wasm_bindgen]
pub struct WasmDatabaseProof {
    inner: VerifiedDatabaseRoots,
}

#[wasm_bindgen]
impl WasmDatabaseProof {
    #[wasm_bindgen(getter, js_name = dbId)]
    pub fn db_id(&self) -> u8 {
        self.inner.db_id
    }

    #[wasm_bindgen(getter, js_name = manifestRootHex)]
    pub fn manifest_root_hex(&self) -> String {
        self.inner.manifest_root_hex()
    }

    #[wasm_bindgen(getter, js_name = buildKind)]
    pub fn build_kind(&self) -> String {
        pir_db_attest::build_kind_label(self.inner.build_kind).to_owned()
    }

    #[wasm_bindgen(getter, js_name = fromHeight)]
    pub fn from_height(&self) -> u32 {
        self.inner.from_height
    }

    #[wasm_bindgen(getter, js_name = fromBlockHashHex)]
    pub fn from_block_hash_hex(&self) -> String {
        self.inner.from_block_hash_hex()
    }

    #[wasm_bindgen(getter)]
    pub fn height(&self) -> u32 {
        self.inner.height
    }

    #[wasm_bindgen(getter, js_name = blockHashHex)]
    pub fn block_hash_hex(&self) -> String {
        self.inner.block_hash_hex()
    }

    #[wasm_bindgen(getter, js_name = muhashHex)]
    pub fn muhash_hex(&self) -> String {
        self.inner.muhash_hex()
    }

    #[wasm_bindgen(getter, js_name = bucketSuperRootHex)]
    pub fn bucket_super_root_hex(&self) -> String {
        self.inner.bucket_super_root_hex()
    }

    #[wasm_bindgen(getter, js_name = onionSuperRootHex)]
    pub fn onion_super_root_hex(&self) -> String {
        self.inner.onion_super_root_hex()
    }

    #[wasm_bindgen(getter, js_name = onionEntrySize)]
    pub fn onion_entry_size(&self) -> u32 {
        self.inner.onion_entry_size
    }

    #[wasm_bindgen(getter, js_name = proofVersion)]
    pub fn proof_version(&self) -> u8 {
        if self.inner.onion_layout_v2.is_some() {
            2
        } else {
            1
        }
    }

    #[wasm_bindgen(getter, js_name = onionTotalPackedEntries)]
    pub fn onion_total_packed_entries(&self) -> Option<u32> {
        self.inner
            .onion_layout_v2
            .map(|layout| layout.total_packed_entries)
    }

    #[wasm_bindgen(getter, js_name = onionIndexBinsPerTable)]
    pub fn onion_index_bins_per_table(&self) -> Option<u32> {
        self.inner
            .onion_layout_v2
            .map(|layout| layout.index_bins_per_table)
    }

    #[wasm_bindgen(getter, js_name = onionChunkBinsPerTable)]
    pub fn onion_chunk_bins_per_table(&self) -> Option<u32> {
        self.inner
            .onion_layout_v2
            .map(|layout| layout.chunk_bins_per_table)
    }

    #[wasm_bindgen(getter, js_name = onionIndexSlotsPerBin)]
    pub fn onion_index_slots_per_bin(&self) -> Option<u16> {
        self.inner
            .onion_layout_v2
            .map(|layout| layout.index_slots_per_bin)
    }

    #[wasm_bindgen(getter, js_name = onionIndexSlotSize)]
    pub fn onion_index_slot_size(&self) -> Option<u16> {
        self.inner
            .onion_layout_v2
            .map(|layout| layout.index_slot_size)
    }

    #[wasm_bindgen(getter, js_name = paramsHashHex)]
    pub fn params_hash_hex(&self) -> String {
        hex_encode(&self.inner.params_hash)
    }

    #[wasm_bindgen(getter, js_name = networkMagicHex)]
    pub fn network_magic_hex(&self) -> String {
        hex_encode(&self.inner.network_magic)
    }

    #[wasm_bindgen(getter, js_name = builderBinarySha256Hex)]
    pub fn builder_binary_sha256_hex(&self) -> String {
        hex_encode(&self.inner.builder_binary_sha256)
    }

    #[wasm_bindgen(getter, js_name = builderGitCommit)]
    pub fn builder_git_commit(&self) -> String {
        self.inner.builder_git_commit.clone()
    }

    /// Convert to a plain JS object for UI state and callbacks.
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> JsValue {
        to_js_object(&database_proof_json(&self.inner))
    }
}

/// Verify a complete, length-prefixed `RESP_DB_PROOF` frame without owning a
/// WebSocket or PIR client.
///
/// This is the authoritative verifier for transports that remain in
/// JavaScript, notably the standalone OnionPIR browser client.  `responseFrame`
/// must be exactly one record in the shape returned by that client's
/// `ManagedWebSocket.sendRaw`: `[u32 payload_len LE][opcode][body...]`.
/// The outer length, response opcode, requested database ID, catalog anchors,
/// attested-builder proof, and supplied policy pins are all checked before an
/// opaque [`WasmDatabaseProof`] is returned.
///
/// The function is stateless and does not install roots.  JavaScript must
/// compare every exposed field with its production pin and then explicitly
/// transfer the same handle into its OnionPIR session root store.
#[wasm_bindgen(js_name = verifyDatabaseProofResponse)]
pub fn verify_database_proof_response(
    response_frame: &[u8],
    catalog: &WasmDatabaseCatalog,
    expected_db_id: u8,
    expected_params_hash_hex: Option<String>,
    allowed_builder_binary_sha256_hex: Option<String>,
    allowed_builder_git_commit: Option<String>,
) -> Result<WasmDatabaseProof, JsError> {
    let response_payload =
        database_proof_payload_from_frame(response_frame).map_err(|e| JsError::new(&e))?;
    let db_info = catalog.inner().get(expected_db_id).ok_or_else(|| {
        JsError::new(&format!("database {} not found in catalog", expected_db_id))
    })?;
    let policy = database_proof_policy(
        expected_params_hash_hex,
        allowed_builder_binary_sha256_hex,
        allowed_builder_git_commit,
    )?;
    let roots = verify_database_proof_response_payload(db_info, response_payload, &policy)
        .map_err(err_to_js)?;
    Ok(WasmDatabaseProof { inner: roots })
}

/// Strict OnionPIR verifier. It accepts only the v2 opcode/bundle/evidence
/// stack and therefore cannot silently fall back to a v1 proof.
#[wasm_bindgen(js_name = verifyDatabaseProofV2Response)]
pub fn verify_database_proof_v2_response(
    response_frame: &[u8],
    catalog: &WasmDatabaseCatalog,
    expected_db_id: u8,
    expected_params_hash_hex: Option<String>,
    allowed_builder_binary_sha256_hex: Option<String>,
    allowed_builder_git_commit: Option<String>,
) -> Result<WasmDatabaseProof, JsError> {
    let response_payload =
        database_proof_payload_from_frame(response_frame).map_err(|e| JsError::new(&e))?;
    let db_info = catalog.inner().get(expected_db_id).ok_or_else(|| {
        JsError::new(&format!("database {} not found in catalog", expected_db_id))
    })?;
    let policy = database_proof_policy(
        expected_params_hash_hex,
        allowed_builder_binary_sha256_hex,
        allowed_builder_git_commit,
    )?;
    let roots = verify_database_proof_v2_response_payload(db_info, response_payload, &policy)
        .map_err(err_to_js)?;
    Ok(WasmDatabaseProof { inner: roots })
}

// ─── WasmAnnounceVerification ──────────────────────────────────────────────

/// JS-visible result of a `WasmDpfClient.announce()` (or
/// `WasmHarmonyClient.announce()`) call.
///
/// Carries the parsed operator-signed bundle:
/// - `IdentityCert` (Tier 1): operator's offline Ed25519 key endorses
///   the server's identity_pubkey for a given server_id + validity
///   window.
/// - `ChannelManifest` (Tier 2): server's per-boot Ed25519 key signs
///   the current channel_pub + build metadata.
///
/// `chainVerified` tells you whether the two layers cross-check
/// (manifest signature + identity_pubkey + server_id agreement).
/// Pinning the operator pubkey is a separate, caller-driven step:
/// compare `operatorPubkeyHex` against your pinned value, then call
/// the IdentityCert's verify yourself if you want defense-in-depth on
/// top of `chainVerified` — but `chainVerified` already runs the
/// manifest signature check internally.
#[wasm_bindgen]
pub struct WasmAnnounceVerification {
    inner: pir_sdk_client::announce::AnnounceVerification,
}

#[wasm_bindgen]
impl WasmAnnounceVerification {
    /// Server identifier the cert was endorsed for (e.g. "pir1").
    #[wasm_bindgen(getter, js_name = serverId)]
    pub fn server_id(&self) -> String {
        self.inner.bundle.cert.server_id.clone()
    }

    /// Hex-encoded operator pubkey (the Tier-1 signer). Compare this
    /// against the value the operator published out-of-band (e.g. via
    /// Nostr) before trusting any of the bundle's fields.
    #[wasm_bindgen(getter, js_name = operatorPubkeyHex)]
    pub fn operator_pubkey_hex(&self) -> String {
        hex_encode(&self.inner.bundle.cert.operator_pubkey)
    }

    /// Hex-encoded identity pubkey the operator endorsed for this
    /// server. The Tier-2 manifest signature chains back to this key.
    #[wasm_bindgen(getter, js_name = identityPubkeyHex)]
    pub fn identity_pubkey_hex(&self) -> String {
        hex_encode(&self.inner.bundle.cert.identity_pubkey)
    }

    /// X25519 channel pubkey the manifest endorses. Cross-check
    /// against the value you'll handshake with (e.g.
    /// `attestVerification.serverStaticPub`). Returns the raw 32 bytes.
    #[wasm_bindgen(getter, js_name = channelPub)]
    pub fn channel_pub(&self) -> Uint8Array {
        Uint8Array::from(&self.inner.bundle.manifest.channel_pub[..])
    }

    /// Same data as [`Self::channel_pub`] but hex-encoded for display.
    #[wasm_bindgen(getter, js_name = channelPubHex)]
    pub fn channel_pub_hex(&self) -> String {
        hex_encode(&self.inner.bundle.manifest.channel_pub)
    }

    /// Verify the bundle against a pinned operator pubkey: operator
    /// pubkey match + the cert's operator **signature** (`cert.verify()`)
    /// + validity window (skipped when `nowUnixSeconds == 0`) + the
    /// in-bundle chain check. Throws on any failure or a non-32-byte
    /// argument. A bare `operatorPubkeyHex` string-compare would miss
    /// the signature check, so use this. Mirrors the Rust
    /// `AnnounceVerification::check_pinned_operator`.
    #[wasm_bindgen(js_name = checkPinnedOperator)]
    pub fn check_pinned_operator(
        &self,
        pinned_operator_pubkey: &[u8],
        now_unix_seconds: i64,
    ) -> Result<(), JsError> {
        let arr: [u8; 32] = pinned_operator_pubkey.try_into().map_err(|_| {
            JsError::new(&format!(
                "checkPinnedOperator: expected a 32-byte operator pubkey, got {} bytes",
                pinned_operator_pubkey.len()
            ))
        })?;
        self.inner
            .check_pinned_operator(&arr, now_unix_seconds)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Bind the bundle to the encrypted session: verify that the
    /// manifest's `channelPub` equals the X25519 key the channel
    /// actually handshook against. Pass the *attested* key — i.e.
    /// `attestVerification.serverStaticPub`, which the SEV-SNP report /
    /// VCEK chain already vouches for. Throws on mismatch (the bundle
    /// describes a different channel than the live session) or on a
    /// non-32-byte argument. Mirrors the Rust
    /// `AnnounceVerification::check_channel_binding` so web and native
    /// share one implementation and error message.
    #[wasm_bindgen(js_name = checkChannelBinding)]
    pub fn check_channel_binding(&self, expected_channel_pub: &[u8]) -> Result<(), JsError> {
        let arr: [u8; 32] = expected_channel_pub.try_into().map_err(|_| {
            JsError::new(&format!(
                "checkChannelBinding: expected a 32-byte channel pubkey, got {} bytes",
                expected_channel_pub.len()
            ))
        })?;
        self.inner
            .check_channel_binding(&arr)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Replay / staleness guard on `manifest.issued_at`. Throws if the
    /// bundle is older than `maxAgeSeconds` before `nowUnixSeconds`
    /// (stale) or more than 300s after it (future-dated). NOTE:
    /// `issued_at` is the server's boot time, so pick `maxAgeSeconds`
    /// generously (≥ expected uptime); pass `0n` to skip the staleness
    /// arm, or `nowUnixSeconds === 0n` to skip entirely. Mirrors the Rust
    /// `AnnounceVerification::check_freshness`.
    #[wasm_bindgen(js_name = checkFreshness)]
    pub fn check_freshness(
        &self,
        now_unix_seconds: i64,
        max_age_seconds: i64,
    ) -> Result<(), JsError> {
        self.inner
            .check_freshness(now_unix_seconds, max_age_seconds)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Hex-encoded binary SHA-256 the manifest claims (self-reported,
    /// trustworthy iff the chain check passed).
    #[wasm_bindgen(getter, js_name = binarySha256Hex)]
    pub fn binary_sha256_hex(&self) -> String {
        hex_encode(&self.inner.bundle.manifest.binary_sha256)
    }

    /// Server-self-reported git rev (string).
    #[wasm_bindgen(getter, js_name = gitRev)]
    pub fn git_rev(&self) -> String {
        self.inner.bundle.manifest.git_rev.clone()
    }

    /// Cert validity lower bound (unix-seconds). 0 = no lower bound.
    #[wasm_bindgen(getter, js_name = validFrom)]
    pub fn valid_from(&self) -> i64 {
        self.inner.bundle.cert.valid_from
    }

    /// Cert validity upper bound (unix-seconds). 0 = indefinite.
    #[wasm_bindgen(getter, js_name = validUntil)]
    pub fn valid_until(&self) -> i64 {
        self.inner.bundle.cert.valid_until
    }

    /// Manifest's `issued_at` timestamp (unix-seconds). Use this to
    /// apply a freshness policy if you want one.
    #[wasm_bindgen(getter, js_name = issuedAt)]
    pub fn issued_at(&self) -> i64 {
        self.inner.bundle.manifest.issued_at
    }

    /// Whether the in-bundle chain check passed: manifest signature
    /// valid against `identityPubkey`, and `cert.server_id` ==
    /// `manifest.server_id`, and `cert.identity_pubkey` ==
    /// `manifest.identity_pubkey`. Does NOT include cert-vs-pinned-
    /// operator verification (caller-driven).
    #[wasm_bindgen(getter, js_name = chainVerified)]
    pub fn chain_verified(&self) -> bool {
        self.inner.chain_verified
    }

    /// Diagnostic string describing why `chainVerified` is false.
    /// Empty when verified.
    #[wasm_bindgen(getter, js_name = chainError)]
    pub fn chain_error(&self) -> String {
        self.inner
            .chain_error
            .as_ref()
            .map(|e| e.to_string())
            .unwrap_or_default()
    }
}

/// Parse + verify a raw RESP_ANNOUNCE wire payload (the response frame
/// starting at the variant byte) into a [`WasmAnnounceVerification`],
/// running the in-bundle chain check. Throws on a wire-format violation
/// or a server `RESP_ERROR` envelope (e.g. "announce not configured").
///
/// This is for transports that don't go through `WasmDpfClient` — the
/// standalone TS `OnionPirWebClient` does its own REQ_ANNOUNCE
/// round-trip over its WebSocket and hands the response bytes here, so
/// it reuses the exact same Rust parsing + chain verification (and the
/// `checkPinnedOperator` / `checkChannelBinding` methods on the result)
/// instead of reimplementing Ed25519 verification in TS. Mirrors the
/// Rust `pir_sdk_client::announce::parse_announce_response`.
#[wasm_bindgen(js_name = verifyAnnounceResponse)]
pub fn verify_announce_response(resp_payload: &[u8]) -> Result<WasmAnnounceVerification, JsError> {
    let inner = pir_sdk_client::announce::parse_announce_response(resp_payload)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(WasmAnnounceVerification { inner })
}

// ─── WasmDpfClient ──────────────────────────────────────────────────────────

/// Two-server DPF-PIR client exposed to JavaScript.
///
/// On the browser this is the recommended backend: stateless per query,
/// no FHE keys to register, and the fastest query round-trip of the
/// three backends. Construct with two `ws://` / `wss://` URLs, `connect`,
/// then call `sync` / `queryBatch`.
///
/// ```javascript
/// import init, { WasmDpfClient } from 'pir-sdk-wasm';
/// await init();
/// const client = new WasmDpfClient('wss://pir1...', 'wss://pir2...');
/// await client.connect();
/// const res = await client.sync(scriptHashesU8, null);
/// ```
#[wasm_bindgen]
pub struct WasmDpfClient {
    inner: DpfClient,
    /// Per-server cache of the handshake-eph seed committed-to in the
    /// most recent `attest()` call's REPORT_DATA. Threaded into
    /// `upgradeToSecureChannel` so the chip-signed report binds the
    /// exact eph_pub used in the handshake. Cleared after a successful
    /// upgrade. JS callers never see these bytes.
    attest_eph_seeds: [Option<[u8; 32]>; 2],
}

#[wasm_bindgen]
impl WasmDpfClient {
    /// Create a new DPF client. No network I/O happens until `connect` is
    /// called.
    #[wasm_bindgen(constructor)]
    pub fn new(server0_url: &str, server1_url: &str) -> Self {
        Self {
            inner: DpfClient::new(server0_url, server1_url),
            attest_eph_seeds: [None, None],
        }
    }

    /// Open WebSocket connections to both servers and run the PIR
    /// handshake. Idempotent — calling twice is safe (the second call
    /// returns early via `PirClient::is_connected`).
    ///
    /// Rejects on malformed URL, CORS violation, or server refusal.
    #[wasm_bindgen(js_name = connect)]
    pub async fn connect(&mut self) -> Result<(), JsError> {
        self.inner.connect().await.map_err(err_to_js)
    }

    /// Set one staged provider URL before that leg is connected.
    #[wasm_bindgen(js_name = setServerUrl)]
    pub fn set_server_url(&mut self, server_index: u8, url: &str) -> Result<(), JsError> {
        self.inner
            .set_server_url(server_index, url)
            .map_err(err_to_js)
    }

    /// Connect one provider without selecting or dialing its peer.
    #[wasm_bindgen(js_name = connectServer)]
    pub async fn connect_server(&mut self, server_index: u8) -> Result<(), JsError> {
        self.inner
            .connect_server(server_index)
            .await
            .map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = disconnectServer)]
    pub async fn disconnect_server(&mut self, server_index: u8) -> Result<(), JsError> {
        if server_index < 2 {
            self.attest_eph_seeds[server_index as usize] = None;
        }
        self.inner
            .disconnect_server(server_index)
            .await
            .map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = isServerConnected)]
    pub fn is_server_connected(&self, server_index: u8) -> Result<bool, JsError> {
        self.inner
            .is_server_connected(server_index)
            .map_err(err_to_js)
    }

    /// Close both WebSocket connections. After this the client returns
    /// `isConnected === false` and `connect` must be called before the
    /// next query.
    #[wasm_bindgen(js_name = disconnect)]
    pub async fn disconnect(&mut self) -> Result<(), JsError> {
        self.attest_eph_seeds = [None, None];
        self.inner.disconnect().await.map_err(err_to_js)
    }

    /// True while both `conn0` and `conn1` are live.
    #[wasm_bindgen(getter, js_name = isConnected)]
    pub fn is_connected(&self) -> bool {
        self.inner.is_connected()
    }

    /// Fetch the database catalog from the server.
    ///
    /// Returns a [`WasmDatabaseCatalog`] wrapping the native catalog —
    /// the same class returned by
    /// `WasmDatabaseCatalog.fromJson(...)` for the TS fallback path, so
    /// downstream sync-planning code works on both surfaces.
    #[wasm_bindgen(js_name = fetchCatalog)]
    pub async fn fetch_catalog(&mut self) -> Result<WasmDatabaseCatalog, JsError> {
        let catalog = self.inner.fetch_catalog().await.map_err(err_to_js)?;
        Ok(WasmDatabaseCatalog::from_native(catalog))
    }

    /// Fetch and verify the attested-builder proof bundle for `dbId`.
    ///
    /// The proof is checked against the database catalog plus the supplied
    /// production policy pins. `expectedParamsHashHex`,
    /// `allowedBuilderBinarySha256Hex`, and `allowedBuilderGitCommit` may be
    /// `undefined` / empty to skip that particular policy check. Mainnet
    /// network magic is always enforced.
    #[wasm_bindgen(js_name = verifyDatabaseProof)]
    pub async fn verify_database_proof(
        &mut self,
        db_id: u8,
        expected_params_hash_hex: Option<String>,
        allowed_builder_binary_sha256_hex: Option<String>,
        allowed_builder_git_commit: Option<String>,
    ) -> Result<WasmDatabaseProof, JsError> {
        let policy = database_proof_policy(
            expected_params_hash_hex,
            allowed_builder_binary_sha256_hex,
            allowed_builder_git_commit,
        )?;
        let roots = self
            .inner
            .verify_database_proof(db_id, &policy)
            .await
            .map_err(err_to_js)?;
        Ok(WasmDatabaseProof { inner: roots })
    }

    /// Verify the proof returned by one exact staged provider.
    #[wasm_bindgen(js_name = verifyDatabaseProofFromServer)]
    pub async fn verify_database_proof_from_server(
        &mut self,
        server_index: u8,
        db_id: u8,
        expected_params_hash_hex: Option<String>,
        allowed_builder_binary_sha256_hex: Option<String>,
        allowed_builder_git_commit: Option<String>,
    ) -> Result<WasmDatabaseProof, JsError> {
        let policy = database_proof_policy(
            expected_params_hash_hex,
            allowed_builder_binary_sha256_hex,
            allowed_builder_git_commit,
        )?;
        let roots = self
            .inner
            .verify_database_proof_from_server(server_index, db_id, &policy)
            .await
            .map_err(err_to_js)?;
        Ok(WasmDatabaseProof { inner: roots })
    }

    /// Fetch and install-or-compare one staged provider's catalog.
    #[wasm_bindgen(js_name = fetchCatalogFromServer)]
    pub async fn fetch_catalog_from_server(
        &mut self,
        server_index: u8,
    ) -> Result<WasmDatabaseCatalog, JsError> {
        let catalog = self
            .inner
            .fetch_catalog_from_server(server_index)
            .await
            .map_err(err_to_js)?;
        Ok(WasmDatabaseCatalog::from_native(catalog))
    }

    /// Select whether every query must be bound to proof-verified database
    /// roots installed during the current connection.
    #[wasm_bindgen(js_name = setRequireVerifiedDatabaseRoots)]
    pub fn set_require_verified_database_roots(&mut self, require_verified: bool) {
        self.inner.set_root_policy(if require_verified {
            RootPolicy::RequireVerified
        } else {
            RootPolicy::Advisory
        });
    }

    /// Consume and install the exact proof handle returned by
    /// `verifyDatabaseProof`. JavaScript must perform its production-pin
    /// comparison before transferring ownership here.
    #[wasm_bindgen(js_name = installVerifiedDatabaseProof)]
    pub fn install_verified_database_proof(
        &mut self,
        proof: WasmDatabaseProof,
    ) -> Result<(), JsError> {
        self.inner
            .install_verified_database_roots(proof.inner)
            .map_err(err_to_js)
    }

    /// Fetch and authenticate the bucket Merkle tree-tops before any private
    /// address query is allowed to run.
    #[wasm_bindgen(js_name = preflightDatabase)]
    pub async fn preflight_database(&mut self, db_id: u8) -> Result<(), JsError> {
        self.inner
            .preflight_verified_database(db_id)
            .await
            .map_err(err_to_js)
    }

    /// Fetch and verify one provider's service policy on its authenticated
    /// secure connection. `checkpointBytes` must be the opaque checkpoint for
    /// this exact provider (empty only on first use).
    #[wasm_bindgen(js_name = fetchServicePolicy)]
    pub async fn fetch_service_policy_v1(
        &mut self,
        server_index: u8,
        db_id: u8,
        expected_provider_id: &[u8],
        policy_signing_key: &[u8],
        now_unix: u64,
        checkpoint_bytes: &[u8],
    ) -> Result<WasmAcceptedServicePolicyV1, JsError> {
        let (provider_id, signing_key, checkpoint) =
            parse_service_trust_v1(expected_provider_id, policy_signing_key, checkpoint_bytes)?;
        let accepted = self
            .inner
            .fetch_service_policy_v1(
                server_index,
                db_id,
                provider_id,
                &signing_key,
                now_unix,
                &checkpoint,
            )
            .await
            .map_err(err_to_js)?;
        Ok(WasmAcceptedServicePolicyV1::from_native(accepted))
    }

    /// Fetch one exact historical policy for already-issued credential
    /// redemption only. This handle exposes no acquisition or PoW API.
    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = fetchRetainedServiceRedemption)]
    pub async fn fetch_retained_service_redemption_v1(
        &mut self,
        server_index: u8,
        db_id: u8,
        expected_provider_id: &[u8],
        policy_signing_key: &[u8],
        expected_policy_digest: &[u8],
        scope_id: &[u8],
        offer_id: u32,
        now_unix: u64,
    ) -> Result<WasmAcceptedRetainedServiceRedemptionV1, JsError> {
        let (provider_id, signing_key) =
            parse_provider_and_key_v1(expected_provider_id, policy_signing_key)?;
        let accepted = self
            .inner
            .fetch_retained_service_redemption_v1(
                server_index,
                db_id,
                provider_id,
                &signing_key,
                parse_digest_v1("expectedPolicyDigest", expected_policy_digest)?,
                parse_scope_id_v1(scope_id)?,
                offer_id,
                now_unix,
            )
            .await
            .map_err(err_to_js)?;
        Ok(WasmAcceptedRetainedServiceRedemptionV1 { inner: accepted })
    }

    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = fetchRetainedBatV2Policy)]
    pub async fn fetch_retained_bat_v2_policy_v2(
        &mut self,
        server_index: u8,
        db_id: u8,
        expected_provider_id: &[u8],
        policy_signing_key: &[u8],
        expected_policy_digest: &[u8],
        scope_id: &[u8],
        offer_id: u32,
        now_unix: u64,
    ) -> Result<WasmAcceptedRetainedBatV2PolicyV2, JsError> {
        let (provider_id, signing_key) =
            parse_provider_and_key_v1(expected_provider_id, policy_signing_key)?;
        let accepted = self
            .inner
            .fetch_retained_bat_v2_policy_v2(
                server_index,
                db_id,
                provider_id,
                &signing_key,
                parse_digest_v1("expectedPolicyDigest", expected_policy_digest)?,
                parse_scope_id_v1(scope_id)?,
                offer_id,
                now_unix,
            )
            .await
            .map_err(err_to_js)?;
        Ok(WasmAcceptedRetainedBatV2PolicyV2 { inner: accepted })
    }

    /// Fail before capability retirement unless the accepted policy belongs to
    /// the currently connected DPF side.
    #[wasm_bindgen(js_name = verifyServicePolicySession)]
    pub fn verify_service_policy_session_v1(
        &self,
        server_index: u8,
        accepted: &WasmAcceptedServicePolicyV1,
    ) -> Result<(), JsError> {
        self.inner
            .verify_service_policy_session_v1(server_index, &accepted.inner)
            .map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = verifyRetainedServiceSession)]
    pub fn verify_retained_service_session_v1(
        &self,
        server_index: u8,
        accepted: &WasmAcceptedRetainedServiceRedemptionV1,
        now_unix: u64,
    ) -> Result<(), JsError> {
        self.inner
            .verify_retained_service_session_v1(server_index, &accepted.inner)
            .and_then(|_| accepted.inner.verify_redemption_ready_v1(now_unix))
            .map_err(err_to_js)
    }

    /// Consume one provider-specific capability for this DPF connection.
    /// The method/key are derived from the verified offer; JavaScript cannot
    /// override them. This call is deliberately one-shot and never retries.
    #[wasm_bindgen(js_name = authorizeService)]
    pub async fn authorize_service_v1(
        &mut self,
        server_index: u8,
        db_id: u8,
        accepted: &WasmAcceptedServicePolicyV1,
        scope_id: &[u8],
        offer_id: u32,
        proof_bytes: &[u8],
    ) -> Result<JsValue, JsError> {
        let scope_id = parse_scope_id_v1(scope_id)?;
        let proof = build_proof_v1(accepted, &scope_id, offer_id, proof_bytes)?;
        let grant = self
            .inner
            .dangerous_unpaired_authorize_service_v1(
                server_index,
                db_id,
                &accepted.inner,
                scope_id,
                offer_id,
                proof,
            )
            .await
            .map_err(err_to_js)?;
        Ok(grant_json_v1(&grant))
    }

    /// Dangerous one-sided DPF scheme-6 admission. This accepts only the
    /// verified-member handle but does not prove a strict provider pair.
    #[wasm_bindgen(js_name = dangerousUnpairedAuthorizeBatV2Service)]
    pub async fn dangerous_unpaired_authorize_bat_v2_service_v2(
        &mut self,
        server_index: u8,
        db_id: u8,
        verified: &WasmVerifiedBatV2RedemptionV2,
        proof_bytes: &[u8],
        now_unix: u64,
    ) -> Result<JsValue, JsError> {
        let outcome = self
            .inner
            .dangerous_unpaired_authorize_bat_v2_service_v2(
                server_index,
                db_id,
                &verified.inner,
                proof_bytes,
                now_unix,
            )
            .await
            .map_err(err_to_js)?;
        Ok(bat_v2_outcome_json_v2(&outcome))
    }

    /// Low-level one-sided DPF retained redemption. The JavaScript name is
    /// intentionally explicit because this method does not verify the other
    /// provider's payment context.
    #[wasm_bindgen(js_name = dangerousUnpairedAuthorizeRetainedService)]
    pub async fn dangerous_unpaired_authorize_retained_service_v1(
        &mut self,
        server_index: u8,
        db_id: u8,
        accepted: &WasmAcceptedRetainedServiceRedemptionV1,
        proof_bytes: &[u8],
        now_unix: u64,
    ) -> Result<JsValue, JsError> {
        let proof = build_retained_proof_v1(accepted, proof_bytes, now_unix)?;
        let grant = self
            .inner
            .dangerous_unpaired_authorize_retained_service_redemption_v1(
                server_index,
                db_id,
                &accepted.inner,
                proof,
                now_unix,
            )
            .await
            .map_err(err_to_js)?;
        Ok(grant_json_v1(&grant))
    }

    /// Request a verified secure-channel-bound PoW challenge. The browser
    /// solves it in bounded chunks through `WasmServicePowChallengeV1`.
    #[wasm_bindgen(js_name = requestServicePowChallenge)]
    pub async fn request_service_pow_challenge_v1(
        &mut self,
        server_index: u8,
        db_id: u8,
        accepted: &WasmAcceptedServicePolicyV1,
        scope_id: &[u8],
        offer_id: u32,
        now_unix: u64,
    ) -> Result<WasmServicePowChallengeV1, JsError> {
        accepted.require_checkpoint_persisted()?;
        let scope_id = parse_scope_id_v1(scope_id)?;
        let challenge = self
            .inner
            .request_service_pow_challenge_v1(
                server_index,
                db_id,
                &accepted.inner,
                scope_id,
                offer_id,
                now_unix,
            )
            .await
            .map_err(err_to_js)?;
        Ok(WasmServicePowChallengeV1::from_native(challenge))
    }

    /// End-to-end sync: fetch catalog, plan, execute all steps, merge
    /// deltas. Returns a [`WasmSyncResult`] whose `results[i]`
    /// corresponds to the i-th script hash in the packed input.
    ///
    /// # Arguments
    /// * `script_hashes` — packed `Uint8Array` of length `20 * N`
    /// * `last_height` — `null`/`undefined` for fresh sync, otherwise the
    ///   last-synced height to compute a delta chain from
    #[wasm_bindgen(js_name = sync)]
    pub async fn sync(
        &mut self,
        script_hashes: &Uint8Array,
        last_height: Option<u32>,
    ) -> Result<WasmSyncResult, JsError> {
        let packed = script_hashes.to_vec();
        let script_hashes = unpack_script_hashes(&packed).map_err(|e| JsError::new(&e))?;
        let result = self
            .inner
            .sync(&script_hashes, last_height)
            .await
            .map_err(err_to_js)?;
        Ok(WasmSyncResult { inner: result })
    }

    /// Low-level: query a single database by `db_id` without the
    /// catalog/plan orchestration. Matches
    /// `PirClient::query_batch`.
    ///
    /// Returns a JSON array of length `N`, each element either `null`
    /// (not found) or a `QueryResult` JSON object (see
    /// `WasmQueryResult.toJson()` for the shape).
    #[wasm_bindgen(js_name = queryBatch)]
    pub async fn query_batch(
        &mut self,
        script_hashes: &Uint8Array,
        db_id: u8,
    ) -> Result<JsValue, JsError> {
        let packed = script_hashes.to_vec();
        let script_hashes = unpack_script_hashes(&packed).map_err(|e| JsError::new(&e))?;
        let results = self
            .inner
            .query_batch(&script_hashes, db_id)
            .await
            .map_err(err_to_js)?;
        Ok(to_js_object(&query_results_to_json(&results)))
    }

    /// Return the two server URLs this client is connected to as a
    /// `[string, string]` array (order matches the constructor:
    /// `[server0_url, server1_url]`).
    ///
    /// Safe to call at any time — no network I/O, no connection state
    /// needed.
    #[wasm_bindgen(js_name = serverUrls)]
    pub fn server_urls(&self) -> JsValue {
        let (a, b) = self.inner.server_urls();
        let arr = Array::new();
        arr.push(&JsValue::from_str(a));
        arr.push(&JsValue::from_str(b));
        arr.into()
    }

    /// Send REQ_ATTEST to one of the connected servers and return a
    /// [`WasmAttestVerification`] handle covering the response.
    ///
    /// `serverIndex` selects 0 (first URL) or 1 (second URL). Internally
    /// the 32-byte nonce is *bound* to the X25519 handshake ephemeral
    /// the client will use in the subsequent `upgradeToSecureChannel`:
    ///
    /// ```text
    /// eph_seed       = OsRng()                                  (cached per-server)
    /// client_eph_pub = X25519(eph_seed)
    /// random_32      = OsRng()
    /// nonce          = sha256("BPIR-ATTEST-NONCE-V1" || client_eph_pub || random_32)
    /// ```
    ///
    /// Caching the `eph_seed` here lets `upgradeToSecureChannel` reuse
    /// the same pubkey the report committed to, so the chip-signed
    /// REPORT_DATA covers *this* handshake — not a stale or replayed
    /// one. The `eph_seed` is never exposed to JS.
    ///
    /// Calling `attest(serverIndex)` twice for the same server rotates
    /// the cached seed (the prior eph is dropped). Callers should call
    /// `attest` for *both* servers before `upgradeToSecureChannel`.
    #[wasm_bindgen(js_name = attest)]
    pub async fn attest(&mut self, server_index: u8) -> Result<WasmAttestVerification, JsError> {
        if server_index >= 2 {
            return Err(JsError::new(&format!(
                "attest: serverIndex must be 0 or 1, got {}",
                server_index
            )));
        }
        begin_attest_attempt(&mut self.attest_eph_seeds, server_index as usize);
        let mut eph_seed = [0u8; 32];
        let mut random_32 = [0u8; 32];
        getrandom::getrandom(&mut eph_seed)
            .map_err(|e| JsError::new(&format!("getrandom: {}", e)))?;
        getrandom::getrandom(&mut random_32)
            .map_err(|e| JsError::new(&format!("getrandom: {}", e)))?;
        let client_eph_pub = pir_channel::eph_pub_from_seed(eph_seed);
        let nonce = pir_core::attest::derive_attest_nonce(client_eph_pub, random_32);
        let v = self
            .inner
            .attest(server_index, nonce)
            .await
            .map_err(err_to_js)?;
        // Only cache on a successful attest call so a network failure
        // doesn't leave a stale seed behind that a subsequent upgrade
        // would silently use.
        self.attest_eph_seeds[server_index as usize] = Some(eph_seed);
        Ok(WasmAttestVerification { inner: v })
    }

    /// Send REQ_ANNOUNCE to one of the connected servers and return a
    /// [`WasmAnnounceVerification`] with the parsed operator-signed
    /// identity bundle.
    ///
    /// Errors with the server's RESP_ERROR text ("announce not
    /// configured") if the server doesn't have an identity key + cert
    /// installed. That's a soft state — attest / handshake / queries
    /// still work as normal.
    #[wasm_bindgen(js_name = announce)]
    pub async fn announce(
        &mut self,
        server_index: u8,
    ) -> Result<WasmAnnounceVerification, JsError> {
        if server_index >= 2 {
            return Err(JsError::new(&format!(
                "announce: serverIndex must be 0 or 1, got {}",
                server_index
            )));
        }
        let v = self.inner.announce(server_index).await.map_err(err_to_js)?;
        Ok(WasmAnnounceVerification { inner: v })
    }

    /// Wrap both server connections with the encrypted-channel
    /// transport.
    ///
    /// `serverStaticPub0` and `serverStaticPub1` are the X25519 pubkeys
    /// the caller obtained (and verified) via [`Self::attest`]. Each
    /// must be exactly 32 bytes; shorter or longer rejects with a
    /// JsError. After this returns, every subsequent query through
    /// this client is AEAD-sealed via `pir_channel`'s ChaCha20-Poly1305
    /// frame format — cloudflared (or any other transport-layer
    /// intermediary) sees only ciphertext.
    ///
    /// Uses the eph_seeds cached by [`Self::attest`] so the handshake's
    /// `client_eph_pub` matches the one the SEV-SNP REPORT_DATA
    /// committed to. **You MUST call `attest(0)` and `attest(1)` before
    /// this method**, otherwise it rejects with a JsError. On success
    /// the cached seeds are cleared (one-shot per attest call).
    ///
    /// Errors if either connection isn't established, either cached
    /// eph_seed is missing, or either handshake fails. On error, the
    /// connections are dropped — call [`Self::connect`] to re-establish.
    #[wasm_bindgen(js_name = upgradeToSecureChannel)]
    pub async fn upgrade_to_secure_channel(
        &mut self,
        server_static_pub_0: &[u8],
        server_static_pub_1: &[u8],
    ) -> Result<(), JsError> {
        let pub0: [u8; 32] = server_static_pub_0
            .try_into()
            .map_err(|_| JsError::new("serverStaticPub0 must be exactly 32 bytes"))?;
        let pub1: [u8; 32] = server_static_pub_1
            .try_into()
            .map_err(|_| JsError::new("serverStaticPub1 must be exactly 32 bytes"))?;
        let eph_seed_0 = take_attest_seed(&mut self.attest_eph_seeds, 0).ok_or_else(|| {
            JsError::new(
                "upgradeToSecureChannel: must call attest(0) first (eph_seed binding required)",
            )
        })?;
        let eph_seed_1 = take_attest_seed(&mut self.attest_eph_seeds, 1).ok_or_else(|| {
            JsError::new(
                "upgradeToSecureChannel: must call attest(1) first (eph_seed binding required)",
            )
        })?;
        let mut hs_nonce_0 = [0u8; 32];
        let mut hs_nonce_1 = [0u8; 32];
        getrandom::getrandom(&mut hs_nonce_0)
            .map_err(|e| JsError::new(&format!("getrandom: {}", e)))?;
        getrandom::getrandom(&mut hs_nonce_1)
            .map_err(|e| JsError::new(&format!("getrandom: {}", e)))?;
        self.inner
            .upgrade_to_secure_channel_with_seeds(
                pub0, eph_seed_0, hs_nonce_0, pub1, eph_seed_1, hs_nonce_1,
            )
            .await
            .map_err(err_to_js)?;
        // One-shot: consume the cached seeds so a follow-up reconnect
        // is forced to re-attest before another upgrade.
        Ok(())
    }

    /// Upgrade one staged provider using only that leg's attestation-bound
    /// ephemeral seed. No peer transport is inspected or modified.
    #[wasm_bindgen(js_name = upgradeServerToSecureChannel)]
    pub async fn upgrade_server_to_secure_channel(
        &mut self,
        server_index: u8,
        server_static_pub: &[u8],
    ) -> Result<(), JsError> {
        if server_index >= 2 {
            return Err(JsError::new("serverIndex must be 0 or 1"));
        }
        let server_static_pub: [u8; 32] = server_static_pub
            .try_into()
            .map_err(|_| JsError::new("serverStaticPub must be exactly 32 bytes"))?;
        let eph_seed = take_attest_seed(&mut self.attest_eph_seeds, server_index as usize)
            .ok_or_else(|| {
                JsError::new("upgradeServerToSecureChannel requires attest(serverIndex) first")
            })?;
        let mut hs_nonce = [0u8; 32];
        getrandom::getrandom(&mut hs_nonce)
            .map_err(|e| JsError::new(&format!("getrandom: {}", e)))?;
        self.inner
            .upgrade_server_to_secure_channel_with_seed(
                server_index,
                server_static_pub,
                eph_seed,
                hs_nonce,
            )
            .await
            .map_err(err_to_js)?;
        Ok(())
    }

    /// Release-safe inspector batch query. Native Rust retains every raw
    /// INDEX/CHUNK bin, re-derives coordinates and decoded payloads from the
    /// exact input order, and completes Merkle verification before this
    /// promise resolves. A single failed slot rejects the whole batch; JS
    /// never receives an unverified entry or an independently forgeable JSON
    /// proof object.
    ///
    /// Returns a JS `Array` of length `N` (the input scripthash count).
    /// Every slot is a non-null [`WasmQueryResult`] — not-found queries
    /// are synthesised as empty inspector-populated results so the
    /// absence-proof bins are preserved for verification.
    /// Empty input or a database without bucket-Merkle commitments fails
    /// before the private query phase.
    ///
    /// 🔒 Padding invariants are preserved (K=75 INDEX / K_CHUNK=80
    /// CHUNK groups), including when most queries are not-found — the
    /// wire-level batch is unchanged.
    #[wasm_bindgen(js_name = queryBatchVerified)]
    pub async fn query_batch_verified(
        &mut self,
        script_hashes: &Uint8Array,
        db_id: u8,
    ) -> Result<JsValue, JsError> {
        let packed = script_hashes.to_vec();
        let script_hashes = unpack_script_hashes(&packed).map_err(|e| JsError::new(&e))?;
        let results = self
            .inner
            .query_batch_verified_with_inspector(&script_hashes, db_id)
            .await
            .map_err(err_to_js)?;
        let arr = Array::new();
        for result in results {
            arr.push(&JsValue::from(WasmQueryResult::from_verified(result)));
        }
        Ok(arr.into())
    }

    /// Plan the complete provider-local query transcript lower bound without
    /// opening a socket or emitting a PIR frame. The cached verified catalog
    /// supplies `dbId` geometry; the INDEX round count comes from the same PBC
    /// planner as `queryBatchVerified`.
    #[wasm_bindgen(js_name = planServiceQuery)]
    pub fn plan_service_query(
        &self,
        script_hashes: &Uint8Array,
        db_id: u8,
    ) -> Result<JsValue, JsError> {
        let packed = script_hashes.to_vec();
        let script_hashes = unpack_script_hashes(&packed).map_err(|e| JsError::new(&e))?;
        let plan = self
            .inner
            .plan_service_query(&script_hashes, db_id)
            .map_err(err_to_js)?;
        Ok(to_js_object(&product_query_plan_json(&plan)))
    }

    /// Install a [`WasmAtomicMetrics`] recorder. All subsequent
    /// connect / disconnect / byte / query-lifecycle events are
    /// recorded on the shared atomic counters.
    ///
    /// Pre- and post-connect installs both work: if the client is
    /// already connected, the recorder is pushed to both transports
    /// immediately so it starts seeing byte traffic on the very next
    /// frame; otherwise the handle is held until `connect` wires up
    /// the fresh transports.
    ///
    /// The recorder is held behind an `Arc`, so installing the same
    /// [`WasmAtomicMetrics`] on multiple clients aggregates counters
    /// across all of them. Call [`clearMetricsRecorder`](Self::clear_metrics_recorder)
    /// to uninstall.
    ///
    /// 🔒 Padding invariants unaffected — the metrics surface is
    /// observational only and cannot influence the number or content
    /// of padding queries sent.
    #[wasm_bindgen(js_name = setMetricsRecorder)]
    pub fn set_metrics_recorder(&mut self, metrics: &WasmAtomicMetrics) {
        self.inner
            .set_metrics_recorder(Some(metrics.recorder_handle()));
    }

    /// Uninstall the currently-registered metrics recorder. Subsequent
    /// events are silenced on this client — any previously-shared
    /// [`WasmAtomicMetrics`] handle held by JS continues to reflect
    /// the last observed state and can still be installed on other
    /// clients.
    #[wasm_bindgen(js_name = clearMetricsRecorder)]
    pub fn clear_metrics_recorder(&mut self) {
        self.inner.set_metrics_recorder(None);
    }
}

/// wasm32-only: progress-aware sync and state-change observer.
///
/// These take `js_sys::Function` arguments and install wasm32-only
/// bridges ([`JsSyncProgress`] / [`JsStateListener`]) into the native
/// client. Both bridges rely on `send_wrapper::SendWrapper`, which is
/// sound only on single-threaded wasm32; that's why the whole block is
/// cfg-gated. Native callers use `DpfClient::set_state_listener` /
/// `DpfClient::sync_with_progress` directly.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
impl WasmDpfClient {
    /// Run an end-to-end sync, firing progress events to the given JS
    /// callback for every step transition.
    ///
    /// The callback receives a single argument — a plain JS object —
    /// whose `type` discriminates: `"step_start"`, `"step_progress"`,
    /// `"step_complete"`, `"complete"`, or `"error"`. See
    /// [`JsSyncProgress`] for the exact field set per event type.
    ///
    /// Argument semantics match [`sync`](Self::sync) otherwise.
    /// Callback exceptions are swallowed — a broken progress sink must
    /// not take the sync down.
    #[wasm_bindgen(js_name = syncWithProgress)]
    pub async fn sync_with_progress(
        &mut self,
        script_hashes: &Uint8Array,
        last_height: Option<u32>,
        progress: js_sys::Function,
    ) -> Result<WasmSyncResult, JsError> {
        let packed = script_hashes.to_vec();
        let script_hashes = unpack_script_hashes(&packed).map_err(|e| JsError::new(&e))?;
        let prog = JsSyncProgress {
            cb: SendWrapper::new(progress),
        };
        let result = self
            .inner
            .sync_with_progress(&script_hashes, last_height, &prog)
            .await
            .map_err(err_to_js)?;
        Ok(WasmSyncResult { inner: result })
    }

    /// Register a JS callback to be invoked on every
    /// [`ConnectionState`](pir_sdk::ConnectionState) transition.
    ///
    /// The callback receives a single `string` argument: one of
    /// `"connecting"`, `"connected"`, `"disconnected"` (see
    /// [`ConnectionState::as_str`](pir_sdk::ConnectionState::as_str)).
    /// Replaces any previously registered callback — only one listener
    /// per client. Pass-through behaviour matches the underlying
    /// [`DpfClient::set_state_listener`].
    ///
    /// Callback exceptions are swallowed.
    #[wasm_bindgen(js_name = onStateChange)]
    pub fn on_state_change(&mut self, cb: js_sys::Function) {
        let listener = Arc::new(JsStateListener {
            cb: SendWrapper::new(cb),
        });
        self.inner.set_state_listener(Some(listener));
    }
}

// ─── WasmHarmonyClient ──────────────────────────────────────────────────────

/// Two-server HarmonyPIR client (hint server + query server) exposed to
/// JavaScript.
///
/// HarmonyPIR has a stateful hint phase — hints are fetched from the
/// hint server once per `(db_id, level)` and replayed against the query
/// server for each query. The wrapper preserves this: a single
/// `WasmHarmonyClient` reuses hints across multiple `sync` calls on the
/// same database, so amortised cost drops after the first query.
///
/// ```javascript
/// import init, { WasmHarmonyClient } from 'pir-sdk-wasm';
/// await init();
/// const client = new WasmHarmonyClient('wss://hint...', 'wss://query...');
/// await client.connect();
/// const res = await client.sync(scriptHashesU8, null);
/// ```
#[wasm_bindgen]
pub struct WasmHarmonyClient {
    inner: HarmonyClient,
    /// Per-server cache of the handshake-eph seed committed-to in the
    /// most recent `attest()` call's REPORT_DATA. Index 0 = hint
    /// server, index 1 = query server. See
    /// [`WasmDpfClient::attest_eph_seeds`].
    attest_eph_seeds: [Option<[u8; 32]>; 2],
}

#[wasm_bindgen]
impl WasmHarmonyClient {
    /// Create a new HarmonyPIR client. Generates a random master PRP key
    /// from `performance.now()`-ish entropy (see `HarmonyClient::new`).
    /// Callers that want a stable key (e.g. to reuse cached hints across
    /// sessions) must call `setMasterKey`.
    #[wasm_bindgen(constructor)]
    pub fn new(hint_server_url: &str, query_server_url: &str) -> Self {
        Self {
            inner: HarmonyClient::new(hint_server_url, query_server_url),
            attest_eph_seeds: [None, None],
        }
    }

    /// Override the 16-byte master PRP key. Invalidates any previously
    /// loaded hints — the next `sync`/`queryBatch` call will re-fetch.
    ///
    /// Rejects if `key` is not exactly 16 bytes.
    #[wasm_bindgen(js_name = setMasterKey)]
    pub fn set_master_key(&mut self, key: &[u8]) -> Result<(), JsError> {
        validate_master_key_len(key.len()).map_err(|e| JsError::new(&e))?;
        let mut arr = [0u8; 16];
        arr.copy_from_slice(key);
        self.inner.set_master_key(arr);
        Ok(())
    }

    /// Return the effective 16-byte master key used by the loaded hint state.
    /// V2 hint setup replaces the initial client key with a server-assigned
    /// value, so browser persistence must read this value after hint download.
    #[wasm_bindgen(js_name = cacheMasterKey)]
    pub fn cache_master_key(&self) -> Uint8Array {
        Uint8Array::from(&self.inner.cache_master_key()[..])
    }

    /// Return the effective PRP backend selected by V2 hint setup.
    #[wasm_bindgen(js_name = cachePrpBackend)]
    pub fn cache_prp_backend(&self) -> u8 {
        self.inner.cache_prp_backend()
    }

    /// Select the PRP backend.
    ///
    /// Accepts [`PRP_HMR12`] or [`PRP_FASTPRP`].
    /// [`PRP_HMR12`] is the reference backend (always
    /// available); the faster backends require the corresponding cargo
    /// features on the enclosing build.
    #[wasm_bindgen(js_name = setPrpBackend)]
    pub fn set_prp_backend(&mut self, backend: u8) -> Result<(), JsError> {
        validate_prp_backend(backend).map_err(|e| JsError::new(&e))?;
        self.inner.set_prp_backend(backend);
        Ok(())
    }

    /// Open WebSocket connections to both hint and query servers.
    #[wasm_bindgen(js_name = connect)]
    pub async fn connect(&mut self) -> Result<(), JsError> {
        self.inner.connect().await.map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = setProviderUrl)]
    pub fn set_provider_url(&mut self, provider_index: u8, url: &str) -> Result<(), JsError> {
        self.inner
            .set_provider_url(provider_index, url)
            .map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = connectProvider)]
    pub async fn connect_provider(&mut self, provider_index: u8) -> Result<(), JsError> {
        self.inner
            .connect_provider(provider_index)
            .await
            .map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = disconnectProvider)]
    pub async fn disconnect_provider(&mut self, provider_index: u8) -> Result<(), JsError> {
        if provider_index < 2 {
            self.attest_eph_seeds[provider_index as usize] = None;
        }
        self.inner
            .disconnect_provider(provider_index)
            .await
            .map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = isProviderConnected)]
    pub fn is_provider_connected(&self, provider_index: u8) -> Result<bool, JsError> {
        self.inner
            .is_provider_connected(provider_index)
            .map_err(err_to_js)
    }

    /// Close both WebSocket connections.
    #[wasm_bindgen(js_name = disconnect)]
    pub async fn disconnect(&mut self) -> Result<(), JsError> {
        self.attest_eph_seeds = [None, None];
        self.inner.disconnect().await.map_err(err_to_js)
    }

    /// True while both connections are live.
    #[wasm_bindgen(getter, js_name = isConnected)]
    pub fn is_connected(&self) -> bool {
        self.inner.is_connected()
    }

    /// Fetch the database catalog from the hint server.
    #[wasm_bindgen(js_name = fetchCatalog)]
    pub async fn fetch_catalog(&mut self) -> Result<WasmDatabaseCatalog, JsError> {
        let catalog = self.inner.fetch_catalog().await.map_err(err_to_js)?;
        Ok(WasmDatabaseCatalog::from_native(catalog))
    }

    /// Fetch and verify the attested-builder proof bundle for `dbId`.
    ///
    /// See [`WasmDpfClient::verify_database_proof`] for policy argument
    /// semantics. Mainnet network magic is always enforced.
    #[wasm_bindgen(js_name = verifyDatabaseProof)]
    pub async fn verify_database_proof(
        &mut self,
        db_id: u8,
        expected_params_hash_hex: Option<String>,
        allowed_builder_binary_sha256_hex: Option<String>,
        allowed_builder_git_commit: Option<String>,
    ) -> Result<WasmDatabaseProof, JsError> {
        let policy = database_proof_policy(
            expected_params_hash_hex,
            allowed_builder_binary_sha256_hex,
            allowed_builder_git_commit,
        )?;
        let roots = self
            .inner
            .verify_database_proof(db_id, &policy)
            .await
            .map_err(err_to_js)?;
        Ok(WasmDatabaseProof { inner: roots })
    }

    #[wasm_bindgen(js_name = verifyDatabaseProofFromProvider)]
    pub async fn verify_database_proof_from_provider(
        &mut self,
        provider_index: u8,
        db_id: u8,
        expected_params_hash_hex: Option<String>,
        allowed_builder_binary_sha256_hex: Option<String>,
        allowed_builder_git_commit: Option<String>,
    ) -> Result<WasmDatabaseProof, JsError> {
        let policy = database_proof_policy(
            expected_params_hash_hex,
            allowed_builder_binary_sha256_hex,
            allowed_builder_git_commit,
        )?;
        let roots = self
            .inner
            .verify_database_proof_from_provider(provider_index, db_id, &policy)
            .await
            .map_err(err_to_js)?;
        Ok(WasmDatabaseProof { inner: roots })
    }

    #[wasm_bindgen(js_name = fetchCatalogFromProvider)]
    pub async fn fetch_catalog_from_provider(
        &mut self,
        provider_index: u8,
    ) -> Result<WasmDatabaseCatalog, JsError> {
        let catalog = self
            .inner
            .fetch_catalog_from_provider(provider_index)
            .await
            .map_err(err_to_js)?;
        Ok(WasmDatabaseCatalog::from_native(catalog))
    }

    /// Select whether every query must be bound to proof-verified database
    /// roots installed during the current connection.
    #[wasm_bindgen(js_name = setRequireVerifiedDatabaseRoots)]
    pub fn set_require_verified_database_roots(&mut self, require_verified: bool) {
        self.inner.set_root_policy(if require_verified {
            RootPolicy::RequireVerified
        } else {
            RootPolicy::Advisory
        });
    }

    /// Consume and install the exact proof handle returned by
    /// `verifyDatabaseProof` after the browser's production-pin comparison.
    #[wasm_bindgen(js_name = installVerifiedDatabaseProof)]
    pub fn install_verified_database_proof(
        &mut self,
        proof: WasmDatabaseProof,
    ) -> Result<(), JsError> {
        self.inner
            .install_verified_database_roots(proof.inner)
            .map_err(err_to_js)
    }

    /// Fetch and authenticate the bucket Merkle tree-tops before any private
    /// address query is allowed to run.
    #[wasm_bindgen(js_name = preflightDatabase)]
    pub async fn preflight_database(&mut self, db_id: u8) -> Result<(), JsError> {
        self.inner
            .preflight_verified_database(db_id)
            .await
            .map_err(err_to_js)
    }

    /// Fetch an independently pinned Harmony provider policy (`0 = hint`,
    /// `1 = query`). Provider checkpoints and capabilities are never shared.
    #[wasm_bindgen(js_name = fetchServicePolicy)]
    pub async fn fetch_service_policy_v1(
        &mut self,
        provider_index: u8,
        db_id: u8,
        expected_provider_id: &[u8],
        policy_signing_key: &[u8],
        now_unix: u64,
        checkpoint_bytes: &[u8],
    ) -> Result<WasmAcceptedServicePolicyV1, JsError> {
        let (provider_id, signing_key, checkpoint) =
            parse_service_trust_v1(expected_provider_id, policy_signing_key, checkpoint_bytes)?;
        let accepted = self
            .inner
            .fetch_service_policy_v1(
                provider_index,
                db_id,
                provider_id,
                &signing_key,
                now_unix,
                &checkpoint,
            )
            .await
            .map_err(err_to_js)?;
        Ok(WasmAcceptedServicePolicyV1::from_native(accepted))
    }

    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = fetchRetainedServiceRedemption)]
    pub async fn fetch_retained_service_redemption_v1(
        &mut self,
        provider_index: u8,
        db_id: u8,
        expected_provider_id: &[u8],
        policy_signing_key: &[u8],
        expected_policy_digest: &[u8],
        scope_id: &[u8],
        offer_id: u32,
        now_unix: u64,
    ) -> Result<WasmAcceptedRetainedServiceRedemptionV1, JsError> {
        let (provider_id, signing_key) =
            parse_provider_and_key_v1(expected_provider_id, policy_signing_key)?;
        let accepted = self
            .inner
            .fetch_retained_service_redemption_v1(
                provider_index,
                db_id,
                provider_id,
                &signing_key,
                parse_digest_v1("expectedPolicyDigest", expected_policy_digest)?,
                parse_scope_id_v1(scope_id)?,
                offer_id,
                now_unix,
            )
            .await
            .map_err(err_to_js)?;
        Ok(WasmAcceptedRetainedServiceRedemptionV1 { inner: accepted })
    }

    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = fetchRetainedBatV2Policy)]
    pub async fn fetch_retained_bat_v2_policy_v2(
        &mut self,
        provider_index: u8,
        db_id: u8,
        expected_provider_id: &[u8],
        policy_signing_key: &[u8],
        expected_policy_digest: &[u8],
        scope_id: &[u8],
        offer_id: u32,
        now_unix: u64,
    ) -> Result<WasmAcceptedRetainedBatV2PolicyV2, JsError> {
        let (provider_id, signing_key) =
            parse_provider_and_key_v1(expected_provider_id, policy_signing_key)?;
        let accepted = self
            .inner
            .fetch_retained_bat_v2_policy_v2(
                provider_index,
                db_id,
                provider_id,
                &signing_key,
                parse_digest_v1("expectedPolicyDigest", expected_policy_digest)?,
                parse_scope_id_v1(scope_id)?,
                offer_id,
                now_unix,
            )
            .await
            .map_err(err_to_js)?;
        Ok(WasmAcceptedRetainedBatV2PolicyV2 { inner: accepted })
    }

    /// Fail before capability retirement unless the accepted policy belongs to
    /// the currently connected Harmony provider side.
    #[wasm_bindgen(js_name = verifyServicePolicySession)]
    pub fn verify_service_policy_session_v1(
        &self,
        provider_index: u8,
        accepted: &WasmAcceptedServicePolicyV1,
    ) -> Result<(), JsError> {
        self.inner
            .verify_service_policy_session_v1(provider_index, &accepted.inner)
            .map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = verifyRetainedServiceSession)]
    pub fn verify_retained_service_session_v1(
        &self,
        provider_index: u8,
        accepted: &WasmAcceptedRetainedServiceRedemptionV1,
        now_unix: u64,
    ) -> Result<(), JsError> {
        self.inner
            .verify_retained_service_session_v1(provider_index, &accepted.inner)
            .and_then(|_| accepted.inner.verify_redemption_ready_v1(now_unix))
            .map_err(err_to_js)
    }

    /// Consume the hint provider's capability for the full V2 hint bundle.
    /// Hint and query offers/prices are separate signed scopes.
    #[wasm_bindgen(js_name = authorizeHintService)]
    pub async fn authorize_hint_service_v1(
        &mut self,
        db_id: u8,
        accepted: &WasmAcceptedServicePolicyV1,
        scope_id: &[u8],
        offer_id: u32,
        proof_bytes: &[u8],
    ) -> Result<JsValue, JsError> {
        let scope_id = parse_scope_id_v1(scope_id)?;
        let proof = build_proof_v1(accepted, &scope_id, offer_id, proof_bytes)?;
        let grant = self
            .inner
            .dangerous_unpaired_authorize_hint_service_v1(
                db_id,
                &accepted.inner,
                scope_id,
                offer_id,
                proof,
                pir_service_protocol::HintTransport::V2Full,
                None,
                None,
            )
            .await
            .map_err(err_to_js)?;
        Ok(grant_json_v1(&grant))
    }

    /// Dangerous one-sided Harmony hint admission without a verified strict
    /// hint/query provider pair.
    #[wasm_bindgen(js_name = dangerousUnpairedAuthorizeBatV2HintService)]
    pub async fn dangerous_unpaired_authorize_bat_v2_hint_service_v2(
        &mut self,
        db_id: u8,
        verified: &WasmVerifiedBatV2RedemptionV2,
        proof_bytes: &[u8],
        now_unix: u64,
    ) -> Result<JsValue, JsError> {
        let outcome = self
            .inner
            .dangerous_unpaired_authorize_bat_v2_hint_service_v2(
                db_id,
                &verified.inner,
                proof_bytes,
                now_unix,
                pir_service_protocol::HintTransport::V2Full,
                None,
                None,
            )
            .await
            .map_err(err_to_js)?;
        Ok(bat_v2_outcome_json_v2(&outcome))
    }

    /// Low-level retained hint redemption without a verified hint/query
    /// payment context.
    #[wasm_bindgen(js_name = dangerousUnpairedAuthorizeRetainedHintService)]
    pub async fn dangerous_unpaired_authorize_retained_hint_service_v1(
        &mut self,
        db_id: u8,
        accepted: &WasmAcceptedRetainedServiceRedemptionV1,
        proof_bytes: &[u8],
        now_unix: u64,
    ) -> Result<JsValue, JsError> {
        let proof = build_retained_proof_v1(accepted, proof_bytes, now_unix)?;
        let grant = self
            .inner
            .dangerous_unpaired_authorize_retained_hint_service_v1(
                db_id,
                &accepted.inner,
                proof,
                now_unix,
            )
            .await
            .map_err(err_to_js)?;
        Ok(grant_json_v1(&grant))
    }

    /// Consume a different capability for the independently selected query
    /// provider. No hint-provider field is sent on this connection.
    #[wasm_bindgen(js_name = authorizeQueryService)]
    pub async fn authorize_query_service_v1(
        &mut self,
        db_id: u8,
        accepted: &WasmAcceptedServicePolicyV1,
        scope_id: &[u8],
        offer_id: u32,
        proof_bytes: &[u8],
    ) -> Result<JsValue, JsError> {
        let scope_id = parse_scope_id_v1(scope_id)?;
        let proof = build_proof_v1(accepted, &scope_id, offer_id, proof_bytes)?;
        let grant = self
            .inner
            .dangerous_unpaired_authorize_query_service_v1(
                db_id,
                &accepted.inner,
                scope_id,
                offer_id,
                proof,
            )
            .await
            .map_err(err_to_js)?;
        Ok(grant_json_v1(&grant))
    }

    /// Dangerous one-sided Harmony query admission without a verified strict
    /// hint/query provider pair.
    #[wasm_bindgen(js_name = dangerousUnpairedAuthorizeBatV2QueryService)]
    pub async fn dangerous_unpaired_authorize_bat_v2_query_service_v2(
        &mut self,
        db_id: u8,
        verified: &WasmVerifiedBatV2RedemptionV2,
        proof_bytes: &[u8],
        now_unix: u64,
    ) -> Result<JsValue, JsError> {
        let outcome = self
            .inner
            .dangerous_unpaired_authorize_bat_v2_query_service_v2(
                db_id,
                &verified.inner,
                proof_bytes,
                now_unix,
            )
            .await
            .map_err(err_to_js)?;
        Ok(bat_v2_outcome_json_v2(&outcome))
    }

    /// Low-level retained query redemption without a verified hint/query
    /// payment context.
    #[wasm_bindgen(js_name = dangerousUnpairedAuthorizeRetainedQueryService)]
    pub async fn dangerous_unpaired_authorize_retained_query_service_v1(
        &mut self,
        db_id: u8,
        accepted: &WasmAcceptedRetainedServiceRedemptionV1,
        proof_bytes: &[u8],
        now_unix: u64,
    ) -> Result<JsValue, JsError> {
        let proof = build_retained_proof_v1(accepted, proof_bytes, now_unix)?;
        let grant = self
            .inner
            .dangerous_unpaired_authorize_retained_query_service_v1(
                db_id,
                &accepted.inner,
                proof,
                now_unix,
            )
            .await
            .map_err(err_to_js)?;
        Ok(grant_json_v1(&grant))
    }

    #[wasm_bindgen(js_name = requestHintPowChallenge)]
    pub async fn request_hint_pow_challenge_v1(
        &mut self,
        db_id: u8,
        accepted: &WasmAcceptedServicePolicyV1,
        scope_id: &[u8],
        offer_id: u32,
        now_unix: u64,
    ) -> Result<WasmServicePowChallengeV1, JsError> {
        accepted.require_checkpoint_persisted()?;
        let scope_id = parse_scope_id_v1(scope_id)?;
        let challenge = self
            .inner
            .request_hint_pow_challenge_v1(db_id, &accepted.inner, scope_id, offer_id, now_unix)
            .await
            .map_err(err_to_js)?;
        Ok(WasmServicePowChallengeV1::from_native(challenge))
    }

    #[wasm_bindgen(js_name = requestQueryPowChallenge)]
    pub async fn request_query_pow_challenge_v1(
        &mut self,
        db_id: u8,
        accepted: &WasmAcceptedServicePolicyV1,
        scope_id: &[u8],
        offer_id: u32,
        now_unix: u64,
    ) -> Result<WasmServicePowChallengeV1, JsError> {
        accepted.require_checkpoint_persisted()?;
        let scope_id = parse_scope_id_v1(scope_id)?;
        let challenge = self
            .inner
            .request_query_pow_challenge_v1(db_id, &accepted.inner, scope_id, offer_id, now_unix)
            .await
            .map_err(err_to_js)?;
        Ok(WasmServicePowChallengeV1::from_native(challenge))
    }

    /// End-to-end sync. See [`WasmDpfClient::sync`] for argument
    /// semantics — the wire path differs but the JS-facing shape is
    /// identical.
    #[wasm_bindgen(js_name = sync)]
    pub async fn sync(
        &mut self,
        script_hashes: &Uint8Array,
        last_height: Option<u32>,
    ) -> Result<WasmSyncResult, JsError> {
        let packed = script_hashes.to_vec();
        let script_hashes = unpack_script_hashes(&packed).map_err(|e| JsError::new(&e))?;
        let result = self
            .inner
            .sync(&script_hashes, last_height)
            .await
            .map_err(err_to_js)?;
        Ok(WasmSyncResult { inner: result })
    }

    /// Low-level: query a single database by `db_id`. See
    /// [`WasmDpfClient::query_batch`].
    #[wasm_bindgen(js_name = queryBatch)]
    pub async fn query_batch(
        &mut self,
        script_hashes: &Uint8Array,
        db_id: u8,
    ) -> Result<JsValue, JsError> {
        let packed = script_hashes.to_vec();
        let script_hashes = unpack_script_hashes(&packed).map_err(|e| JsError::new(&e))?;
        let results = self
            .inner
            .query_batch(&script_hashes, db_id)
            .await
            .map_err(err_to_js)?;
        Ok(to_js_object(&query_results_to_json(&results)))
    }

    // ─── Session 5: inspector / verify / DB-switch / hint-cache surface ─────

    /// Return the two server URLs this client is connected to as a
    /// `[string, string]` array (order matches the constructor:
    /// `[hint_server_url, query_server_url]`).
    ///
    /// Safe to call at any time — no network I/O, no connection state
    /// needed. Mirrors [`WasmDpfClient::server_urls`].
    #[wasm_bindgen(js_name = serverUrls)]
    pub fn server_urls(&self) -> JsValue {
        let (h, q) = self.inner.server_urls();
        let arr = Array::new();
        arr.push(&JsValue::from_str(h));
        arr.push(&JsValue::from_str(q));
        arr.into()
    }

    /// Send REQ_ATTEST to the hint (`serverIndex=0`) or query
    /// (`serverIndex=1`) server and return the verification result.
    /// See [`WasmDpfClient::attest`] for the full semantics (including
    /// the bound-nonce derivation that ties this attestation to the
    /// subsequent handshake).
    #[wasm_bindgen(js_name = attest)]
    pub async fn attest(&mut self, server_index: u8) -> Result<WasmAttestVerification, JsError> {
        if server_index >= 2 {
            return Err(JsError::new(&format!(
                "attest: serverIndex must be 0 or 1, got {}",
                server_index
            )));
        }
        begin_attest_attempt(&mut self.attest_eph_seeds, server_index as usize);
        let mut eph_seed = [0u8; 32];
        let mut random_32 = [0u8; 32];
        getrandom::getrandom(&mut eph_seed)
            .map_err(|e| JsError::new(&format!("getrandom: {}", e)))?;
        getrandom::getrandom(&mut random_32)
            .map_err(|e| JsError::new(&format!("getrandom: {}", e)))?;
        let client_eph_pub = pir_channel::eph_pub_from_seed(eph_seed);
        let nonce = pir_core::attest::derive_attest_nonce(client_eph_pub, random_32);
        let v = self
            .inner
            .attest(server_index, nonce)
            .await
            .map_err(err_to_js)?;
        self.attest_eph_seeds[server_index as usize] = Some(eph_seed);
        Ok(WasmAttestVerification { inner: v })
    }

    /// Send REQ_ANNOUNCE to the hint (`serverIndex=0`) or query
    /// (`serverIndex=1`) server. See [`WasmDpfClient::announce`] for
    /// full semantics.
    #[wasm_bindgen(js_name = announce)]
    pub async fn announce(
        &mut self,
        server_index: u8,
    ) -> Result<WasmAnnounceVerification, JsError> {
        if server_index >= 2 {
            return Err(JsError::new(&format!(
                "announce: serverIndex must be 0 or 1, got {}",
                server_index
            )));
        }
        let v = self.inner.announce(server_index).await.map_err(err_to_js)?;
        Ok(WasmAnnounceVerification { inner: v })
    }

    /// Wrap both server connections (hint + query) with the encrypted
    /// channel transport. See [`WasmDpfClient::upgrade_to_secure_channel`]
    /// — same eph_seed caching + binding flow. Argument order matches
    /// `serverUrls()` — `(hint, query)`.
    #[wasm_bindgen(js_name = upgradeToSecureChannel)]
    pub async fn upgrade_to_secure_channel(
        &mut self,
        hint_server_static_pub: &[u8],
        query_server_static_pub: &[u8],
    ) -> Result<(), JsError> {
        let hint_pub: [u8; 32] = hint_server_static_pub
            .try_into()
            .map_err(|_| JsError::new("hintServerStaticPub must be exactly 32 bytes"))?;
        let query_pub: [u8; 32] = query_server_static_pub
            .try_into()
            .map_err(|_| JsError::new("queryServerStaticPub must be exactly 32 bytes"))?;
        let eph_seed_hint = take_attest_seed(&mut self.attest_eph_seeds, 0).ok_or_else(|| {
            JsError::new(
                "upgradeToSecureChannel: must call attest(0) on the hint server first \
                 (eph_seed binding required)",
            )
        })?;
        let eph_seed_query = take_attest_seed(&mut self.attest_eph_seeds, 1).ok_or_else(|| {
            JsError::new(
                "upgradeToSecureChannel: must call attest(1) on the query server first \
                 (eph_seed binding required)",
            )
        })?;
        let mut hs_nonce_hint = [0u8; 32];
        let mut hs_nonce_query = [0u8; 32];
        getrandom::getrandom(&mut hs_nonce_hint)
            .map_err(|e| JsError::new(&format!("getrandom: {}", e)))?;
        getrandom::getrandom(&mut hs_nonce_query)
            .map_err(|e| JsError::new(&format!("getrandom: {}", e)))?;
        self.inner
            .upgrade_to_secure_channel_with_seeds(
                hint_pub,
                eph_seed_hint,
                hs_nonce_hint,
                query_pub,
                eph_seed_query,
                hs_nonce_query,
            )
            .await
            .map_err(err_to_js)?;
        Ok(())
    }

    #[wasm_bindgen(js_name = upgradeProviderToSecureChannel)]
    pub async fn upgrade_provider_to_secure_channel(
        &mut self,
        provider_index: u8,
        server_static_pub: &[u8],
    ) -> Result<(), JsError> {
        if provider_index >= 2 {
            return Err(JsError::new("providerIndex must be 0 or 1"));
        }
        let server_static_pub: [u8; 32] = server_static_pub
            .try_into()
            .map_err(|_| JsError::new("serverStaticPub must be exactly 32 bytes"))?;
        let eph_seed = take_attest_seed(&mut self.attest_eph_seeds, provider_index as usize)
            .ok_or_else(|| {
                JsError::new("upgradeProviderToSecureChannel requires attest(providerIndex) first")
            })?;
        let mut hs_nonce = [0u8; 32];
        getrandom::getrandom(&mut hs_nonce)
            .map_err(|e| JsError::new(&format!("getrandom: {}", e)))?;
        self.inner
            .upgrade_provider_to_secure_channel_with_seed(
                provider_index,
                server_static_pub,
                eph_seed,
                hs_nonce,
            )
            .await
            .map_err(err_to_js)?;
        Ok(())
    }

    /// Release-safe inspector batch query. See
    /// [`WasmDpfClient::query_batch_verified`] for the all-or-nothing
    /// verification and JS-boundary contract.
    /// Empty input or a database without bucket-Merkle commitments fails
    /// before the private query phase.
    ///
    /// 🔒 Padding invariants are preserved (K=75 INDEX / K_CHUNK=80
    /// CHUNK groups) — padding lives in the native `HarmonyClient` query
    /// path that this wrapper delegates to.
    #[wasm_bindgen(js_name = queryBatchVerified)]
    pub async fn query_batch_verified(
        &mut self,
        script_hashes: &Uint8Array,
        db_id: u8,
    ) -> Result<JsValue, JsError> {
        let packed = script_hashes.to_vec();
        let script_hashes = unpack_script_hashes(&packed).map_err(|e| JsError::new(&e))?;
        let results = self
            .inner
            .query_batch_verified_with_inspector(&script_hashes, db_id)
            .await
            .map_err(err_to_js)?;
        let arr = Array::new();
        for result in results {
            arr.push(&JsValue::from(WasmQueryResult::from_verified(result)));
        }
        Ok(arr.into())
    }

    /// Query-provider counterpart of `WasmDpfClient.planServiceQuery`.
    /// Reports `2R` exact INDEX frames plus the mandatory two-frame batched
    /// CHUNK-presence round; Merkle and extra real-chunk rounds remain omitted.
    #[wasm_bindgen(js_name = planServiceQuery)]
    pub fn plan_service_query(
        &self,
        script_hashes: &Uint8Array,
        db_id: u8,
    ) -> Result<JsValue, JsError> {
        let packed = script_hashes.to_vec();
        let script_hashes = unpack_script_hashes(&packed).map_err(|e| JsError::new(&e))?;
        let plan = self
            .inner
            .plan_service_query(&script_hashes, db_id)
            .map_err(err_to_js)?;
        Ok(to_js_object(&product_query_plan_json(&plan)))
    }

    /// Plan the catalog-known cold-cache hint lower bound. This is a separate
    /// provider/workload from the query plan and never inspects query inputs.
    #[wasm_bindgen(js_name = planServiceHint)]
    pub fn plan_service_hint(&self, db_id: u8) -> Result<JsValue, JsError> {
        let plan = self.inner.plan_service_hint(db_id).map_err(err_to_js)?;
        Ok(to_js_object(&product_query_plan_json(&plan)))
    }

    /// Get the currently-loaded `db_id`, or `null` if no hints are
    /// loaded. See [`HarmonyClient::db_id`] for semantics.
    #[wasm_bindgen(js_name = dbId)]
    pub fn db_id(&self) -> Option<u8> {
        self.inner.db_id()
    }

    /// Pin this client's hint state to `db_id`. If hints for a different
    /// db are currently loaded, invalidates them — the next
    /// `sync`/`queryBatch`/`queryBatchVerified` will re-fetch (or restore
    /// from the hint cache if configured).
    ///
    /// Idempotent when `db_id` already matches the loaded state.
    #[wasm_bindgen(js_name = setDbId)]
    pub fn set_db_id(&mut self, db_id: u8) {
        self.inner.set_db_id(db_id);
    }

    /// Minimum remaining per-group query budget across every loaded
    /// `HarmonyGroup`. Returns `null` when nothing is loaded — callers
    /// should treat that as "unknown, call `sync` or `queryBatch` first".
    ///
    /// UI surfaces use this to decide when to proactively refresh hints.
    #[wasm_bindgen(js_name = minQueriesRemaining)]
    pub fn min_queries_remaining(&self) -> Option<u32> {
        self.inner.min_queries_remaining()
    }

    /// Byte size the blob [`save_hints`](Self::save_hints) would produce
    /// right now. Returns `0` when no state is loaded or the client is
    /// in an inconsistent state (e.g. catalog missing).
    ///
    /// O(total hint bytes); fine for UI-polling cadence but not for
    /// the hot query path.
    #[wasm_bindgen(js_name = estimateHintSizeBytes)]
    pub fn estimate_hint_size_bytes(&self) -> u32 {
        // `usize` is 32-bit on wasm32; on native unit tests we truncate.
        // Hints are capped far below u32::MAX in practice so this is
        // always accurate in realistic deployments.
        self.inner.estimate_hint_size_bytes() as u32
    }

    /// 16-byte fingerprint of the cache key for the given catalog +
    /// `db_id`, under this client's current master key and PRP backend.
    /// Returns a fresh `Uint8Array` of length 16 on success.
    ///
    /// Rejects with `JsError` when the catalog doesn't carry `db_id`.
    /// The fingerprint matches the one embedded in the `saveHints` blob
    /// header and the on-disk cache filename stem, so the JS-side
    /// IndexedDB bridge can key cache entries on it directly.
    #[wasm_bindgen(js_name = fingerprint)]
    pub fn fingerprint(
        &self,
        catalog: &WasmDatabaseCatalog,
        db_id: u8,
    ) -> Result<Uint8Array, JsError> {
        let db_info = catalog
            .inner()
            .get(db_id)
            .ok_or_else(|| JsError::new(&format!("no database with db_id={}", db_id)))?;
        let fp = self.inner.cache_fingerprint(db_info);
        Ok(Uint8Array::from(&fp[..]))
    }

    /// Serialise the currently-loaded hint state to a self-describing
    /// binary blob. Returns a fresh `Uint8Array`, or `null` if no hints
    /// are loaded.
    ///
    /// The blob embeds a 16-byte fingerprint (see
    /// [`fingerprint`](Self::fingerprint)) so a later `loadHints` call
    /// against a mismatched database or master key fails cleanly
    /// instead of returning corrupted state. Safe to persist to
    /// IndexedDB as an opaque byte array.
    #[wasm_bindgen(js_name = saveHints)]
    pub fn save_hints(&self) -> Result<JsValue, JsError> {
        match self.inner.save_hints_bytes().map_err(err_to_js)? {
            Some(bytes) => Ok(Uint8Array::from(&bytes[..]).into()),
            None => Ok(JsValue::NULL),
        }
    }

    /// Restore hint state from a blob previously produced by
    /// [`saveHints`](Self::save_hints).
    ///
    /// The blob's embedded fingerprint is cross-checked against
    /// `(masterKey, prpBackend, catalog.get(db_id))`: a mismatch (wrong
    /// db shape, different master key, etc.) rejects with `JsError`
    /// rather than silently loading stale hints. Rejects with `JsError`
    /// when the catalog doesn't carry `db_id`.
    ///
    /// On success the client transitions into the same state it would
    /// be in after a fresh `sync` / `queryBatch` against `db_id` — i.e.
    /// `dbId() === db_id`, main `HarmonyGroup`s are populated, and the
    /// next query skips the hint-fetch network roundtrips.
    #[wasm_bindgen(js_name = loadHints)]
    pub fn load_hints(
        &mut self,
        bytes: &[u8],
        catalog: &WasmDatabaseCatalog,
        db_id: u8,
    ) -> Result<(), JsError> {
        let db_info = catalog
            .inner()
            .get(db_id)
            .ok_or_else(|| JsError::new(&format!("no database with db_id={}", db_id)))?;
        self.inner
            .load_hints_bytes(bytes, db_info)
            .map_err(err_to_js)
    }

    /// Restore only a complete paid hint resource. The native client requires
    /// proof-verified tree tops for `dbId` and rejects main-only or malformed
    /// sibling state, clearing the partial in-memory bundle on failure.
    #[wasm_bindgen(js_name = loadCompleteHints)]
    pub fn load_complete_hints(
        &mut self,
        bytes: &[u8],
        catalog: &WasmDatabaseCatalog,
        db_id: u8,
    ) -> Result<(), JsError> {
        let db_info = catalog
            .inner()
            .get(db_id)
            .ok_or_else(|| JsError::new(&format!("no database with db_id={}", db_id)))?;
        self.inner
            .load_complete_hints_bytes(bytes, db_info)
            .map_err(err_to_js)
    }

    /// True only when every main and authenticated sibling hint group for the
    /// proof-verified database is present in memory.
    #[wasm_bindgen(js_name = hasCompleteHints)]
    pub fn has_complete_hints(
        &self,
        catalog: &WasmDatabaseCatalog,
        db_id: u8,
    ) -> Result<bool, JsError> {
        let db_info = catalog
            .inner()
            .get(db_id)
            .ok_or_else(|| JsError::new(&format!("no database with db_id={}", db_id)))?;
        self.inner
            .has_complete_hints_for_verified_database(db_info)
            .map_err(err_to_js)
    }

    /// Install a [`WasmAtomicMetrics`] recorder.
    ///
    /// See [`WasmDpfClient::set_metrics_recorder`] for the full
    /// install + aggregation contract — the Harmony implementation
    /// propagates the handle to both transports (hint + query) with
    /// the `"harmony"` backend label, so a single
    /// [`WasmAtomicMetrics`] installed on a DPF and a Harmony client
    /// simultaneously can aggregate counters across both backends.
    ///
    /// 🔒 Padding invariants unaffected.
    #[wasm_bindgen(js_name = setMetricsRecorder)]
    pub fn set_metrics_recorder(&mut self, metrics: &WasmAtomicMetrics) {
        self.inner
            .set_metrics_recorder(Some(metrics.recorder_handle()));
    }

    /// Uninstall the currently-registered metrics recorder. See
    /// [`WasmDpfClient::clear_metrics_recorder`].
    #[wasm_bindgen(js_name = clearMetricsRecorder)]
    pub fn clear_metrics_recorder(&mut self) {
        self.inner.set_metrics_recorder(None);
    }
}

/// wasm32-only: progress-aware sync and state-change observer for
/// HarmonyPIR. Mirrors [`WasmDpfClient`]'s wasm32 extension block —
/// same [`JsSyncProgress`] / [`JsStateListener`] bridges, same callback
/// contract. See the DPF version for the full event shape reference.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
impl WasmHarmonyClient {
    /// Run an end-to-end sync, firing progress events to the given JS
    /// callback for every step transition. See
    /// [`WasmDpfClient::sync_with_progress`] for the full argument +
    /// event-shape contract.
    #[wasm_bindgen(js_name = syncWithProgress)]
    pub async fn sync_with_progress(
        &mut self,
        script_hashes: &Uint8Array,
        last_height: Option<u32>,
        progress: js_sys::Function,
    ) -> Result<WasmSyncResult, JsError> {
        let packed = script_hashes.to_vec();
        let script_hashes = unpack_script_hashes(&packed).map_err(|e| JsError::new(&e))?;
        let prog = JsSyncProgress {
            cb: SendWrapper::new(progress),
        };
        let result = self
            .inner
            .sync_with_progress(&script_hashes, last_height, &prog)
            .await
            .map_err(err_to_js)?;
        Ok(WasmSyncResult { inner: result })
    }

    /// Register a JS callback to be invoked on every
    /// [`ConnectionState`](pir_sdk::ConnectionState) transition. See
    /// [`WasmDpfClient::on_state_change`].
    #[wasm_bindgen(js_name = onStateChange)]
    pub fn on_state_change(&mut self, cb: js_sys::Function) {
        let listener = Arc::new(JsStateListener {
            cb: SendWrapper::new(cb),
        });
        self.inner.set_state_listener(Some(listener));
    }

    /// Pre-fetch the main hint state for `dbId`, firing `progress` after
    /// each per-group response is loaded. Replaces the legacy "issue a
    /// dummy query to warm hints" pattern with a dedicated entry point
    /// that surfaces per-group progress directly.
    ///
    /// `progress` is invoked with one argument:
    /// `{ done, total, phase }` (see `JsHintProgress` for the contract).
    /// `total` equals `index_k + chunk_k` for the active database
    /// (typically 75 + 80 = 155). On a cache hit / already-loaded
    /// state, `progress` fires once with `done === total`.
    ///
    /// Rejects with `JsError` if the catalog doesn't carry `dbId` or
    /// the client isn't connected.
    ///
    /// 🔒 Padding invariants are unaffected — wire shape matches the
    /// no-progress hint-fetch path.
    #[wasm_bindgen(js_name = fetchHintsWithProgress)]
    pub async fn fetch_hints_with_progress(
        &mut self,
        catalog: &WasmDatabaseCatalog,
        db_id: u8,
        progress: js_sys::Function,
    ) -> Result<(), JsError> {
        let db_info = catalog
            .inner()
            .get(db_id)
            .ok_or_else(|| JsError::new(&format!("no database with db_id={}", db_id)))?
            .clone();
        let prog = JsHintProgress {
            cb: SendWrapper::new(progress),
        };
        self.inner
            .fetch_hints_with_progress(&db_info, &prog)
            .await
            .map_err(err_to_js)
    }

    /// Pre-fetch every main and Merkle-sibling hint group needed to restore a
    /// paid hint entitlement across page reloads. Requires proof-verified tree
    /// tops to have been installed through `preflightDatabase` first.
    #[wasm_bindgen(js_name = fetchCompleteHintsWithProgress)]
    pub async fn fetch_complete_hints_with_progress(
        &mut self,
        catalog: &WasmDatabaseCatalog,
        db_id: u8,
        progress: js_sys::Function,
    ) -> Result<(), JsError> {
        let db_info = catalog
            .inner()
            .get(db_id)
            .ok_or_else(|| JsError::new(&format!("no database with db_id={}", db_id)))?
            .clone();
        let prog = JsHintProgress {
            cb: SendWrapper::new(progress),
        };
        self.inner
            .fetch_complete_hints_with_progress(&db_info, &prog)
            .await
            .map_err(err_to_js)
    }
}

// ─── WasmOramClient ─────────────────────────────────────────────────────────

/// Single-server ORAM client exposed to JavaScript.
///
/// This is the TEE backend path: JavaScript authenticates one attested server,
/// upgrades that WebSocket to the encrypted channel, then sends plaintext
/// script hashes inside the channel. Server-side ORAM hides the INDEX and
/// CHUNK address trace. Unlike DPF/Harmony, this path does not use the PBC
/// cuckoo-bucket layout on the client boundary; `queryBatch` returns decoded
/// direct-entry CHUNK results.
#[wasm_bindgen]
pub struct WasmOramClient {
    inner: OramClient,
    attest_eph_seed: Option<[u8; 32]>,
}

#[wasm_bindgen]
impl WasmOramClient {
    /// Create a new ORAM client. No network I/O happens until `connect`.
    #[wasm_bindgen(constructor)]
    pub fn new(server_url: &str) -> Self {
        Self {
            inner: OramClient::new(server_url),
            attest_eph_seed: None,
        }
    }

    /// Open the WebSocket connection.
    #[wasm_bindgen(js_name = connect)]
    pub async fn connect(&mut self) -> Result<(), JsError> {
        self.inner.connect().await.map_err(err_to_js)
    }

    /// Close the WebSocket connection and clear cached catalog state.
    #[wasm_bindgen(js_name = disconnect)]
    pub async fn disconnect(&mut self) -> Result<(), JsError> {
        self.inner.disconnect().await.map_err(err_to_js)
    }

    /// True while the single ORAM server connection is live.
    #[wasm_bindgen(getter, js_name = isConnected)]
    pub fn is_connected(&self) -> bool {
        self.inner.is_connected()
    }

    /// Fetch the database catalog from the ORAM server.
    #[wasm_bindgen(js_name = fetchCatalog)]
    pub async fn fetch_catalog(&mut self) -> Result<WasmDatabaseCatalog, JsError> {
        let catalog = self.inner.fetch_catalog().await.map_err(err_to_js)?;
        Ok(WasmDatabaseCatalog::from_native(catalog))
    }

    /// Fetch and verify the attested-builder proof bundle for `dbId`.
    ///
    /// Uses the same production policy pins and catalog cross-check as
    /// `WasmDpfClient.verifyDatabaseProof` and
    /// `WasmHarmonyClient.verifyDatabaseProof`.
    #[wasm_bindgen(js_name = verifyDatabaseProof)]
    pub async fn verify_database_proof(
        &mut self,
        db_id: u8,
        expected_params_hash_hex: Option<String>,
        allowed_builder_binary_sha256_hex: Option<String>,
        allowed_builder_git_commit: Option<String>,
    ) -> Result<WasmDatabaseProof, JsError> {
        let policy = database_proof_policy(
            expected_params_hash_hex,
            allowed_builder_binary_sha256_hex,
            allowed_builder_git_commit,
        )?;
        let roots = self
            .inner
            .verify_database_proof(db_id, &policy)
            .await
            .map_err(err_to_js)?;
        Ok(WasmDatabaseProof { inner: roots })
    }

    /// Require proof-root installation before ORAM query/admission.
    #[wasm_bindgen(js_name = setRequireVerifiedDatabaseRoots)]
    pub fn set_require_verified_database_roots(&mut self, require_verified: bool) {
        self.inner.set_root_policy(if require_verified {
            RootPolicy::RequireVerified
        } else {
            RootPolicy::Advisory
        });
    }

    /// Install a proof only after JavaScript has checked production pins.
    #[wasm_bindgen(js_name = installVerifiedDatabaseProof)]
    pub fn install_verified_database_proof(
        &mut self,
        proof: WasmDatabaseProof,
    ) -> Result<(), JsError> {
        self.inner
            .install_verified_database_roots(proof.inner)
            .map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = fetchServicePolicy)]
    pub async fn fetch_service_policy_v1(
        &mut self,
        db_id: u8,
        expected_provider_id: &[u8],
        policy_signing_key: &[u8],
        now_unix: u64,
        checkpoint_bytes: &[u8],
    ) -> Result<WasmAcceptedServicePolicyV1, JsError> {
        let (provider_id, signing_key, checkpoint) =
            parse_service_trust_v1(expected_provider_id, policy_signing_key, checkpoint_bytes)?;
        let accepted = self
            .inner
            .fetch_service_policy_v1(db_id, provider_id, &signing_key, now_unix, &checkpoint)
            .await
            .map_err(err_to_js)?;
        Ok(WasmAcceptedServicePolicyV1::from_native(accepted))
    }

    /// Fetch one exact historical ORAM policy for redemption only. The
    /// returned handle cannot create quotes, solve PoW, or select another
    /// offer.
    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = fetchRetainedServiceRedemption)]
    pub async fn fetch_retained_service_redemption_v1(
        &mut self,
        db_id: u8,
        expected_provider_id: &[u8],
        policy_signing_key: &[u8],
        expected_policy_digest: &[u8],
        scope_id: &[u8],
        offer_id: u32,
        now_unix: u64,
    ) -> Result<WasmAcceptedRetainedServiceRedemptionV1, JsError> {
        let (provider_id, signing_key) =
            parse_provider_and_key_v1(expected_provider_id, policy_signing_key)?;
        let accepted = self
            .inner
            .fetch_retained_service_redemption_v1(
                db_id,
                provider_id,
                &signing_key,
                parse_digest_v1("expectedPolicyDigest", expected_policy_digest)?,
                parse_scope_id_v1(scope_id)?,
                offer_id,
                now_unix,
            )
            .await
            .map_err(err_to_js)?;
        Ok(WasmAcceptedRetainedServiceRedemptionV1 { inner: accepted })
    }

    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = fetchRetainedBatV2Policy)]
    pub async fn fetch_retained_bat_v2_policy_v2(
        &mut self,
        db_id: u8,
        expected_provider_id: &[u8],
        policy_signing_key: &[u8],
        expected_policy_digest: &[u8],
        scope_id: &[u8],
        offer_id: u32,
        now_unix: u64,
    ) -> Result<WasmAcceptedRetainedBatV2PolicyV2, JsError> {
        let (provider_id, signing_key) =
            parse_provider_and_key_v1(expected_provider_id, policy_signing_key)?;
        let accepted = self
            .inner
            .fetch_retained_bat_v2_policy_v2(
                db_id,
                provider_id,
                &signing_key,
                parse_digest_v1("expectedPolicyDigest", expected_policy_digest)?,
                parse_scope_id_v1(scope_id)?,
                offer_id,
                now_unix,
            )
            .await
            .map_err(err_to_js)?;
        Ok(WasmAcceptedRetainedBatV2PolicyV2 { inner: accepted })
    }

    /// Fail before capability retirement unless the accepted policy belongs to
    /// the currently connected ORAM session.
    #[wasm_bindgen(js_name = verifyServicePolicySession)]
    pub fn verify_service_policy_session_v1(
        &self,
        accepted: &WasmAcceptedServicePolicyV1,
    ) -> Result<(), JsError> {
        self.inner
            .verify_service_policy_session_v1(&accepted.inner)
            .map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = verifyRetainedServiceSession)]
    pub fn verify_retained_service_session_v1(
        &self,
        accepted: &WasmAcceptedRetainedServiceRedemptionV1,
        now_unix: u64,
    ) -> Result<(), JsError> {
        self.inner
            .verify_retained_service_session_v1(&accepted.inner)
            .and_then(|_| accepted.inner.verify_redemption_ready_v1(now_unix))
            .map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = authorizeService)]
    pub async fn authorize_service_v1(
        &mut self,
        db_id: u8,
        accepted: &WasmAcceptedServicePolicyV1,
        scope_id: &[u8],
        offer_id: u32,
        proof_bytes: &[u8],
    ) -> Result<JsValue, JsError> {
        let scope_id = parse_scope_id_v1(scope_id)?;
        let proof = build_proof_v1(accepted, &scope_id, offer_id, proof_bytes)?;
        let grant = self
            .inner
            .authorize_service_v1(db_id, &accepted.inner, scope_id, offer_id, proof)
            .await
            .map_err(err_to_js)?;
        Ok(grant_json_v1(&grant))
    }

    #[wasm_bindgen(js_name = authorizeBatV2Service)]
    pub async fn authorize_bat_v2_service_v2(
        &mut self,
        db_id: u8,
        verified: &WasmVerifiedBatV2RedemptionV2,
        proof_bytes: &[u8],
        now_unix: u64,
    ) -> Result<JsValue, JsError> {
        let outcome = self
            .inner
            .authorize_bat_v2_service_v2(db_id, &verified.inner, proof_bytes, now_unix)
            .await
            .map_err(err_to_js)?;
        Ok(bat_v2_outcome_json_v2(&outcome))
    }

    #[wasm_bindgen(js_name = authorizeRetainedService)]
    pub async fn authorize_retained_service_v1(
        &mut self,
        db_id: u8,
        accepted: &WasmAcceptedRetainedServiceRedemptionV1,
        proof_bytes: &[u8],
        now_unix: u64,
    ) -> Result<JsValue, JsError> {
        let proof = build_retained_proof_v1(accepted, proof_bytes, now_unix)?;
        let grant = self
            .inner
            .authorize_retained_service_redemption_v1(db_id, &accepted.inner, proof, now_unix)
            .await
            .map_err(err_to_js)?;
        Ok(grant_json_v1(&grant))
    }

    #[wasm_bindgen(js_name = requestServicePowChallenge)]
    pub async fn request_service_pow_challenge_v1(
        &mut self,
        db_id: u8,
        accepted: &WasmAcceptedServicePolicyV1,
        scope_id: &[u8],
        offer_id: u32,
        now_unix: u64,
    ) -> Result<WasmServicePowChallengeV1, JsError> {
        accepted.require_checkpoint_persisted()?;
        let scope_id = parse_scope_id_v1(scope_id)?;
        let challenge = self
            .inner
            .request_service_pow_challenge_v1(db_id, &accepted.inner, scope_id, offer_id, now_unix)
            .await
            .map_err(err_to_js)?;
        Ok(WasmServicePowChallengeV1::from_native(challenge))
    }

    /// Low-level ORAM batch query against one database.
    ///
    /// Returns a JSON array of length `N`, each element either `null`
    /// (not found) or the same `QueryResult` JSON object returned by the
    /// DPF/Harmony wrappers.
    #[wasm_bindgen(js_name = queryBatch)]
    pub async fn query_batch(
        &mut self,
        script_hashes: &Uint8Array,
        db_id: u8,
    ) -> Result<JsValue, JsError> {
        let packed = script_hashes.to_vec();
        let script_hashes = unpack_script_hashes(&packed).map_err(|e| JsError::new(&e))?;
        let results = self
            .inner
            .query_batch(&script_hashes, db_id)
            .await
            .map_err(err_to_js)?;
        Ok(to_js_object(&query_results_to_json(&results)))
    }

    /// Low-level ORAM batch query padded to `paddedSlots`.
    ///
    /// The JS input contains only real script hashes. The native ORAM client
    /// appends explicit empty slots before sending `REQ_ORAM_LOOKUP`, so the
    /// TEE spends the same INDEX schedule without treating padding as keys.
    /// The returned JSON array contains only the real input results.
    #[wasm_bindgen(js_name = queryBatchPadded)]
    pub async fn query_batch_padded(
        &mut self,
        script_hashes: &Uint8Array,
        db_id: u8,
        padded_slots: usize,
    ) -> Result<JsValue, JsError> {
        let packed = script_hashes.to_vec();
        let script_hashes = unpack_script_hashes(&packed).map_err(|e| JsError::new(&e))?;
        let results = self
            .inner
            .query_batch_padded(&script_hashes, padded_slots, db_id)
            .await
            .map_err(err_to_js)?;
        Ok(to_js_object(&query_results_to_json(&results)))
    }

    /// Return the configured server URL.
    #[wasm_bindgen(js_name = serverUrl)]
    pub fn server_url(&self) -> String {
        self.inner.server_url().to_owned()
    }

    /// Send REQ_ATTEST and return the parsed verification result.
    ///
    /// The nonce is bound to the X25519 ephemeral public key that
    /// `upgradeToSecureChannel` will use next, matching the DPF/Harmony
    /// bound-attestation flow.
    #[wasm_bindgen(js_name = attest)]
    pub async fn attest(&mut self) -> Result<WasmAttestVerification, JsError> {
        let mut eph_seed = [0u8; 32];
        let mut random_32 = [0u8; 32];
        getrandom::getrandom(&mut eph_seed)
            .map_err(|e| JsError::new(&format!("getrandom: {}", e)))?;
        getrandom::getrandom(&mut random_32)
            .map_err(|e| JsError::new(&format!("getrandom: {}", e)))?;
        let client_eph_pub = pir_channel::eph_pub_from_seed(eph_seed);
        let nonce = pir_core::attest::derive_attest_nonce(client_eph_pub, random_32);
        let v = self.inner.attest(nonce).await.map_err(err_to_js)?;
        self.attest_eph_seed = Some(eph_seed);
        Ok(WasmAttestVerification { inner: v })
    }

    /// Send REQ_ANNOUNCE and return the parsed operator-signed identity
    /// bundle.
    #[wasm_bindgen(js_name = announce)]
    pub async fn announce(&mut self) -> Result<WasmAnnounceVerification, JsError> {
        let v = self.inner.announce().await.map_err(err_to_js)?;
        Ok(WasmAnnounceVerification { inner: v })
    }

    /// Wrap the single server connection with the encrypted-channel transport.
    ///
    /// `serverStaticPub` must be the 32-byte key from a verified attestation
    /// or announcement. `attest()` must be called first so the channel
    /// ephemeral key is bound into the SEV-SNP report nonce.
    #[wasm_bindgen(js_name = upgradeToSecureChannel)]
    pub async fn upgrade_to_secure_channel(
        &mut self,
        server_static_pub: &[u8],
    ) -> Result<(), JsError> {
        let server_pub: [u8; 32] = server_static_pub
            .try_into()
            .map_err(|_| JsError::new("serverStaticPub must be exactly 32 bytes"))?;
        let eph_seed = self.attest_eph_seed.ok_or_else(|| {
            JsError::new(
                "upgradeToSecureChannel: must call attest() first (eph_seed binding required)",
            )
        })?;
        let mut hs_nonce = [0u8; 32];
        getrandom::getrandom(&mut hs_nonce)
            .map_err(|e| JsError::new(&format!("getrandom: {}", e)))?;
        self.inner
            .upgrade_to_secure_channel_with_seeds(server_pub, eph_seed, hs_nonce)
            .await
            .map_err(err_to_js)?;
        self.attest_eph_seed = None;
        Ok(())
    }

    /// Install a [`WasmAtomicMetrics`] recorder.
    #[wasm_bindgen(js_name = setMetricsRecorder)]
    pub fn set_metrics_recorder(&mut self, metrics: &WasmAtomicMetrics) {
        self.inner
            .set_metrics_recorder(Some(metrics.recorder_handle()));
    }

    /// Uninstall the currently-registered metrics recorder.
    #[wasm_bindgen(js_name = clearMetricsRecorder)]
    pub fn clear_metrics_recorder(&mut self) {
        self.inner.set_metrics_recorder(None);
    }
}

// ─── PRP backend constants (re-exported as JS number constants) ─────────────

/// PRP backend constant for the reference `HMR12` implementation.
/// Always available.
#[wasm_bindgen(js_name = PRP_HMR12)]
pub fn prp_hmr12() -> u8 {
    PRP_HMR12
}

/// PRP backend constant for `FastPRP`. Requires the `fastprp` cargo
/// feature on the enclosing build.
#[wasm_bindgen(js_name = PRP_FASTPRP)]
pub fn prp_fastprp() -> u8 {
    PRP_FASTPRP
}

// PRP_ALF (= 2) was removed 2026-05-12 — see crates/sdk/client/src/harmony.rs:81.
// The JS-side `PRP_ALF` accessor is intentionally removed. JS callers that
// pass `2` will hit `validate_prp_backend` and get a clean error.

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn planner_db(index_k: u8, chunk_k: u8) -> pir_sdk::DatabaseInfo {
        pir_sdk::DatabaseInfo {
            db_id: 0,
            kind: pir_sdk::DatabaseKind::Full,
            name: "wasm-planner".into(),
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

    #[test]
    fn failed_reattest_clears_the_previous_handshake_seed() {
        let mut slots: AttestSeedSlots = [Some([0x11; 32]), Some([0x22; 32])];

        // `begin_attest_attempt` runs before randomness or network I/O. A
        // failure after this point leaves no older binding available.
        begin_attest_attempt(&mut slots, 0);

        assert_eq!(slots[0], None);
        assert_eq!(slots[1], Some([0x22; 32]));
    }

    #[test]
    fn failed_handshake_cannot_reuse_a_consumed_attestation_seed() {
        let mut slots: AttestSeedSlots = [Some([0x31; 32]), Some([0x32; 32])];

        // The real handshake starts only after this one-shot take. Simulate a
        // later transport failure by deliberately not putting it back.
        assert_eq!(take_attest_seed(&mut slots, 1), Some([0x32; 32]));

        assert_eq!(take_attest_seed(&mut slots, 1), None);
        assert_eq!(slots[0], Some([0x31; 32]));
    }

    #[test]
    fn database_proof_frame_requires_exact_length_prefix() {
        let frame = [2, 0, 0, 0, 0x0a, 0x01];
        assert_eq!(
            database_proof_payload_from_frame(&frame).unwrap(),
            &[0x0a, 0x01]
        );

        assert!(database_proof_payload_from_frame(&[]).is_err());
        assert!(database_proof_payload_from_frame(&[0x0a]).is_err());
        assert!(database_proof_payload_from_frame(&[1, 0, 0, 0]).is_err());

        let truncated = [2, 0, 0, 0, 0x0a];
        assert!(database_proof_payload_from_frame(&truncated)
            .unwrap_err()
            .contains("length mismatch"));

        let concatenated = [1, 0, 0, 0, 0x0a, 1, 0, 0, 0, 0x0a];
        assert!(database_proof_payload_from_frame(&concatenated)
            .unwrap_err()
            .contains("length mismatch"));
    }

    #[test]
    fn database_proof_exposes_onion_entry_size() {
        let roots = VerifiedDatabaseRoots {
            db_id: 1,
            manifest_root: [9; 32],
            build_kind: pir_db_attest::BuildKind::Snapshot,
            from_height: 0,
            from_block_hash: [0; 32],
            height: 940_611,
            block_hash: [1; 32],
            muhash: [2; 32],
            bucket_super_root: [3; 32],
            onion_super_root: [4; 32],
            onion_entry_size: 3328,
            onion_layout_v2: None,
            params_hash: [5; 32],
            network_magic: [0xf9, 0xbe, 0xb4, 0xd9],
            builder_binary_sha256: [6; 32],
            builder_git_commit: "test".into(),
        };

        let json = database_proof_json(&roots);
        assert_eq!(json["manifestRootHex"], "09".repeat(32));
        assert_eq!(json["onionEntrySize"], 3328);
        let proof = WasmDatabaseProof { inner: roots };
        assert_eq!(proof.manifest_root_hex(), "09".repeat(32));
        assert_eq!(proof.onion_entry_size(), 3328);
    }

    #[test]
    fn database_proof_v2_exposes_typed_onion_layout() {
        let layout = pir_db_attest::OnionQueryLayoutV2::current(948_640, 10_273, 37_954, 3_328);
        let roots = VerifiedDatabaseRoots {
            db_id: 0,
            manifest_root: [9; 32],
            build_kind: pir_db_attest::BuildKind::Snapshot,
            from_height: 0,
            from_block_hash: [0; 32],
            height: 948_454,
            block_hash: [1; 32],
            muhash: [2; 32],
            bucket_super_root: [3; 32],
            onion_super_root: [4; 32],
            onion_entry_size: 3328,
            onion_layout_v2: Some(layout),
            params_hash: [5; 32],
            network_magic: [0xf9, 0xbe, 0xb4, 0xd9],
            builder_binary_sha256: [6; 32],
            builder_git_commit: "test-v2".into(),
        };

        let json = database_proof_json(&roots);
        assert_eq!(json["proofVersion"], 2);
        assert_eq!(json["onionTotalPackedEntries"], 948_640);
        let proof = WasmDatabaseProof { inner: roots };
        assert_eq!(proof.proof_version(), 2);
        assert_eq!(proof.onion_index_bins_per_table(), Some(10_273));
        assert_eq!(proof.onion_chunk_bins_per_table(), Some(37_954));
    }

    #[test]
    fn unpack_script_hashes_empty_input_ok() {
        let out = unpack_script_hashes(&[]).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn unpack_script_hashes_multiple_of_20_ok() {
        let mut buf = Vec::new();
        for i in 0..3u8 {
            buf.extend(std::iter::repeat(i).take(20));
        }
        let out = unpack_script_hashes(&buf).unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(out[0], [0u8; 20]);
        assert_eq!(out[1], [1u8; 20]);
        assert_eq!(out[2], [2u8; 20]);
    }

    #[test]
    fn unpack_script_hashes_non_multiple_errors() {
        let buf = vec![0u8; 19];
        assert!(unpack_script_hashes(&buf).is_err());
        let buf = vec![0u8; 21];
        assert!(unpack_script_hashes(&buf).is_err());
        let buf = vec![0u8; 41];
        assert!(unpack_script_hashes(&buf).is_err());
    }

    #[test]
    fn service_query_plan_json_preserves_u64_and_omission_semantics() {
        let hashes = vec![[0_u8; 20], [1_u8; 20], [2_u8; 20], [3_u8; 20]];
        let plan = pir_sdk_client::plan_dpf_service_query_v1(&hashes, &planner_db(3, 3))
            .expect("transport-free DPF plan");
        let json = product_query_plan_json(&plan);

        assert_eq!(json["backend"], "dpf-pir");
        assert_eq!(json["workload"], "dpf-query");
        assert_eq!(json["lowerBounds"]["logicalInputs"], 2);
        assert_eq!(json["lowerBounds"]["frames"], 6);
        assert_eq!(json["lowerBounds"]["workUnits"], "36");
        assert_eq!(json["lowerBounds"]["concurrentSockets"], 1);
        assert!(json["lowerBounds"].get("hintGroups").is_none());
        assert_eq!(json["pbcRounds"], 2);
        assert_eq!(json["exactIndexFrames"], 2);
        assert!(json["omitted"]
            .as_array()
            .unwrap()
            .contains(&serde_json::Value::String("merkleFrames".into())));
        assert!(json.get("requestBytes").is_none());
    }

    #[test]
    fn harmony_hint_plan_json_is_a_separate_product_workload() {
        let plan = pir_sdk_client::plan_harmony_service_hint_v1(&planner_db(75, 80))
            .expect("transport-free hint plan");
        let json = product_query_plan_json(&plan);

        assert_eq!(json["backend"], "harmony-pir");
        assert_eq!(json["workload"], "harmony-hint");
        assert_eq!(json["lowerBounds"]["logicalInputs"], 0);
        assert_eq!(json["lowerBounds"]["frames"], 1);
        assert_eq!(json["lowerBounds"]["hintGroups"], 155);
        assert_eq!(json["lowerBounds"]["workUnits"], "155");
        assert!(json.get("pbcRounds").is_none());
        assert!(json["omitted"]
            .as_array()
            .unwrap()
            .contains(&serde_json::Value::String("siblingHintGroups".into())));
    }

    #[test]
    fn wasm_dpf_client_construct_and_introspect() {
        let client = WasmDpfClient::new("ws://a:1", "ws://b:2");
        assert!(!client.is_connected());
    }

    #[test]
    fn wasm_harmony_client_construct_and_introspect() {
        let client = WasmHarmonyClient::new("ws://hint:1", "ws://query:2");
        assert!(!client.is_connected());
    }

    #[test]
    fn wasm_oram_client_construct_and_introspect() {
        let client = WasmOramClient::new("ws://oram:1");
        assert!(!client.is_connected());
        assert_eq!(client.inner.server_url(), "ws://oram:1");
    }

    // ─── Session 5: WasmHarmonyClient surface tests (native-safe only) ──────
    //
    // Methods that return `JsValue` / `Uint8Array` / `JsError` can't run
    // on native because those wasm-bindgen imports panic outside wasm32.
    // The tests below cover the native-typed slice of the Session 5
    // surface (dbId / setDbId / minQueriesRemaining /
    // estimateHintSizeBytes + loadHints error paths where the error
    // comes from a `String`-returning helper before hitting `JsError`).

    /// Fresh `WasmHarmonyClient` reports `dbId() === None`, and
    /// `setDbId(0)` stays no-op when no hints are loaded.
    #[test]
    fn wasm_harmony_db_id_defaults_to_none() {
        let mut client = WasmHarmonyClient::new("ws://h:1", "ws://q:2");
        assert_eq!(client.db_id(), None);
        client.set_db_id(0);
        // `set_db_id` only invalidates if the id differs from
        // `loaded_db_id`; with nothing loaded the transition is inert.
        assert_eq!(client.db_id(), None);
    }

    /// `min_queries_remaining()` returns None before any hints are
    /// loaded — mirrors the native accessor.
    #[test]
    fn wasm_harmony_min_queries_remaining_none_when_empty() {
        let client = WasmHarmonyClient::new("ws://h:1", "ws://q:2");
        assert_eq!(client.min_queries_remaining(), None);
    }

    /// `estimate_hint_size_bytes()` is 0 before any hints are loaded.
    #[test]
    fn wasm_harmony_estimate_hint_size_zero_when_empty() {
        let client = WasmHarmonyClient::new("ws://h:1", "ws://q:2");
        assert_eq!(client.estimate_hint_size_bytes(), 0);
    }

    /// Sanity: `serverUrls` returns a 2-element JS array; we can't
    /// inspect the JS side natively but we can assert the native
    /// `inner.server_urls()` returns the constructor arguments
    /// verbatim (what `serverUrls` wraps).
    #[test]
    fn wasm_harmony_inner_server_urls_match_constructor() {
        let client = WasmHarmonyClient::new("wss://h.example", "wss://q.example");
        let (h, q) = client.inner.server_urls();
        assert_eq!(h, "wss://h.example");
        assert_eq!(q, "wss://q.example");
    }

    #[test]
    fn validate_master_key_len_accepts_only_16() {
        assert!(validate_master_key_len(15).is_err());
        assert!(validate_master_key_len(17).is_err());
        assert!(validate_master_key_len(0).is_err());
        assert!(validate_master_key_len(16).is_ok());
    }

    #[test]
    fn validate_prp_backend_matches_constants() {
        assert!(validate_prp_backend(PRP_HMR12).is_ok());
        assert!(validate_prp_backend(PRP_FASTPRP).is_ok());
        // PRP_ALF (= 2) was removed 2026-05-12 and now errors.
        assert!(validate_prp_backend(2).is_err());
        assert!(validate_prp_backend(99).is_err());
        assert!(validate_prp_backend(255).is_err());
    }

    #[test]
    fn prp_constants_reachable() {
        assert_eq!(prp_hmr12(), PRP_HMR12);
        assert_eq!(prp_fastprp(), PRP_FASTPRP);
        // Exercise the uniqueness invariant — the set_prp_backend guard
        // above relies on these two being distinct.
        assert_ne!(PRP_HMR12, PRP_FASTPRP);
    }

    #[test]
    fn sync_result_to_json_drops_raw_verification_metadata() {
        use pir_sdk::{QueryResult, SyncResult, UtxoEntry};

        let mut txid = [0u8; 32];
        txid[31] = 0xab;

        let mut raw = QueryResult::with_entries(vec![UtxoEntry {
            txid,
            vout: 7,
            amount_sats: 12345,
        }]);
        raw.merkle_verified = true;
        let sync = SyncResult {
            results: vec![None, Some(raw)],
            synced_height: 900_000,
            was_fresh_sync: true,
        };

        let json = sync_result_to_json(&sync);
        assert_eq!(json["syncedHeight"], 900_000);
        assert_eq!(json["wasFreshSync"], true);
        let results = json["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0].is_null());
        let entries = results[1]["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["vout"], 7);
        assert_eq!(entries[0]["amountSats"], 12345);
        // Even positive native diagnostic metadata is stripped from mutable
        // plain JSON. Only an opaque WasmQueryResult handle preserves it.
        assert_eq!(results[1]["merkleVerified"], false);
    }

    #[test]
    fn sync_result_to_json_merkle_failed_propagates() {
        use pir_sdk::{QueryResult, SyncResult};

        let sync = SyncResult {
            results: vec![Some(QueryResult::merkle_failed())],
            synced_height: 0,
            was_fresh_sync: false,
        };

        let json = sync_result_to_json(&sync);
        assert_eq!(json["results"][0]["merkleVerified"], false);
        assert_eq!(json["results"][0]["entries"].as_array().unwrap().len(), 0);
    }

    // Note: we deliberately don't have a unit test that calls `err_to_js`
    // directly — `JsError::new` is a wasm-bindgen imported function and
    // panics on non-wasm targets. The conversion's correctness is
    // verified at compile time (every `#[wasm_bindgen]` method using
    // `.map_err(err_to_js)` has to type-check).
}
