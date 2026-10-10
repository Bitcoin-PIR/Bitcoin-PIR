//! Client-side trait for PIR protocols.
//!
//! This module defines the `PirClient` trait that abstracts over different PIR
//! backends (DPF, HarmonyPIR, OnionPIR), providing a unified interface for:
//!
//! - Connecting to PIR servers
//! - Fetching database catalogs
//! - Computing sync plans
//! - Executing queries with automatic delta chaining

use async_trait::async_trait;

use crate::error::PirResult;
use crate::sync::SyncPlan;
use crate::types::{DatabaseCatalog, PirBackendType, QueryResult, ScriptHash, SyncResult};

/// Client-side interface for PIR queries.
///
/// This trait provides both high-level (sync) and low-level (query_batch) APIs
/// for querying PIR servers.
///
/// # High-Level API
///
/// For most use cases, use `sync()` which handles:
/// - Fetching the database catalog
/// - Computing an optimal sync plan (snapshot + deltas)
/// - Executing all query steps
/// - Merging delta results into snapshots
///
/// # Low-Level API
///
/// For advanced use cases (e.g., custom Merkle verification), use:
/// - `fetch_catalog()` to get available databases
/// - `compute_sync_plan()` to plan the sync steps
/// - `query_batch()` to execute individual queries
///
/// # Backend Differences
///
/// - **DPF**: Requires two servers, stateless per-query
/// - **HarmonyPIR**: Requires two servers (hint + query), stateful hints per-group
/// - **OnionPIR**: Single server, requires FHE key registration at connect time
#[async_trait]
pub trait PirClient: Send + Sync {
    /// Returns the backend type.
    fn backend_type(&self) -> PirBackendType;

    /// Connect to PIR server(s).
    ///
    /// For two-server protocols (DPF, HarmonyPIR), both URLs must be configured.
    /// For single-server protocols (OnionPIR), only the primary URL is used.
    ///
    /// # Errors
    ///
    /// Returns an error if connection fails or required servers are not configured.
    async fn connect(&mut self) -> PirResult<()>;

    /// Disconnect from all servers.
    async fn disconnect(&mut self) -> PirResult<()>;

    /// Returns true if connected to all required servers.
    fn is_connected(&self) -> bool;

    /// Fetch the database catalog from the primary server.
    ///
    /// The catalog contains information about all available databases:
    /// - Full UTXO snapshots at various heights
    /// - Delta databases between heights
    /// - PIR parameters for each database
    async fn fetch_catalog(&mut self) -> PirResult<DatabaseCatalog>;

    /// Get the cached catalog (if previously fetched).
    fn cached_catalog(&self) -> Option<&DatabaseCatalog>;

    /// Compute an optimal sync plan from `last_height` toward the catalog tip.
    ///
    /// # Arguments
    ///
    /// * `catalog` - Database catalog from `fetch_catalog()`
    /// * `last_height` - Last synced height, or `None` for fresh sync
    ///
    /// # Returns
    ///
    /// A sync plan with steps to execute (full snapshot and/or deltas).
    ///
    /// # Algorithm
    ///
    /// 1. **Fresh sync** (`last_height` is `None`): Start from best full snapshot,
    ///    then chain deltas to reach the tip.
    /// 2. **Incremental sync**: Try to find a delta chain from `last_height` to tip.
    ///    Falls back to full snapshot if chain is too long (> 5 steps) or doesn't exist.
    fn compute_sync_plan(
        &self,
        catalog: &DatabaseCatalog,
        last_height: Option<u32>,
    ) -> PirResult<SyncPlan>;

    /// Execute a full sync: connect, fetch catalog, compute plan, execute all steps.
    ///
    /// This is the primary high-level entry point for most callers.
    ///
    /// # Arguments
    ///
    /// * `script_hashes` - Script hashes to query
    /// * `last_height` - Must be `None` (or `Some(0)`). `sync` keeps no
    ///   results between calls, so it always syncs from the best full
    ///   snapshot. A height is rejected with `PirError::InvalidState` before
    ///   any network I/O: to resume from a previous sync, compute the plan
    ///   from its `synced_height` and pass its `results` to
    ///   [`sync_with_plan`](Self::sync_with_plan).
    ///
    /// # Returns
    ///
    /// Merged results for all script hashes, with the final synced height.
    async fn sync(
        &mut self,
        script_hashes: &[ScriptHash],
        last_height: Option<u32>,
    ) -> PirResult<SyncResult>;

    /// Execute a sync using an existing plan.
    ///
    /// Use this when you want to compute the plan separately (e.g., to show
    /// progress to the user before starting).
    ///
    /// # Arguments
    ///
    /// * `script_hashes` - Script hashes to query
    /// * `plan` - Pre-computed sync plan
    /// * `cached_results` - The `results` of the sync the plan starts from, one
    ///   per script hash in the same order. Required unless the plan is fresh:
    ///   a delta chain (or the empty plan at the tip) only carries changes, so
    ///   without the previous results it is rejected with
    ///   `PirError::InvalidState`. A fresh plan ignores them.
    async fn sync_with_plan(
        &mut self,
        script_hashes: &[ScriptHash],
        plan: &SyncPlan,
        cached_results: Option<&[Option<QueryResult>]>,
    ) -> PirResult<SyncResult>;

    /// Low-level: Query a specific database for a batch of script hashes.
    ///
    /// This bypasses the sync orchestration. Use for:
    /// - Step-by-step control over sync execution
    /// - Custom Merkle verification per step
    /// - Debugging and testing
    ///
    /// # Arguments
    ///
    /// * `script_hashes` - Script hashes to query
    /// * `db_id` - Database ID to query
    ///
    /// # Returns
    ///
    /// Results for each script hash (in same order as input).
    /// `None` entries indicate the script hash was not found.
    async fn query_batch(
        &mut self,
        script_hashes: &[ScriptHash],
        db_id: u8,
    ) -> PirResult<Vec<Option<QueryResult>>>;
}

/// Progress callback for sync operations.
pub trait SyncProgress: Send + Sync {
    /// Called when a sync step starts.
    fn on_step_start(&self, step_index: usize, total_steps: usize, description: &str);

    /// Called with progress within a step (0.0 to 1.0).
    fn on_step_progress(&self, step_index: usize, progress: f32);

    /// Called when a sync step completes.
    fn on_step_complete(&self, step_index: usize);

    /// Called when sync completes.
    fn on_complete(&self, synced_height: u32);

    /// Called on error.
    fn on_error(&self, error: &crate::error::PirError);
}

/// A no-op progress callback.
pub struct NoProgress;

impl SyncProgress for NoProgress {
    fn on_step_start(&self, _: usize, _: usize, _: &str) {}
    fn on_step_progress(&self, _: usize, _: f32) {}
    fn on_step_complete(&self, _: usize) {}
    fn on_complete(&self, _: u32) {}
    fn on_error(&self, _: &crate::error::PirError) {}
}

/// A simple progress callback that prints to stdout.
pub struct PrintProgress;

impl SyncProgress for PrintProgress {
    fn on_step_start(&self, step_index: usize, total_steps: usize, description: &str) {
        println!(
            "[{}/{}] Starting: {}",
            step_index + 1,
            total_steps,
            description
        );
    }

    fn on_step_progress(&self, step_index: usize, progress: f32) {
        println!("[{}] Progress: {:.0}%", step_index + 1, progress * 100.0);
    }

    fn on_step_complete(&self, step_index: usize) {
        println!("[{}] Complete", step_index + 1);
    }

    fn on_complete(&self, synced_height: u32) {
        println!("Sync complete at height {}", synced_height);
    }

    fn on_error(&self, error: &crate::error::PirError) {
        eprintln!("Sync error: {}", error);
    }
}

/// Connection-level state transitions emitted through
/// [`StateListener::on_state_change`].
///
/// The exact set of values is intentionally narrow so the WASM
/// bindings can stringify a value to a stable JS-side contract (see
/// [`Self::as_str`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConnectionState {
    /// `connect()` has been called and the underlying transport is
    /// mid-handshake — the client is not yet usable.
    Connecting,
    /// Handshake completed, transport is up, catalog has been fetched.
    /// The client is ready to accept queries.
    Connected,
    /// `disconnect()` has completed, or a connect attempt failed.
    /// Callers must call `connect()` (or inject new transports) before
    /// further queries.
    Disconnected,
}

impl ConnectionState {
    /// Stable string label used by the WASM bindings' `onStateChange`
    /// surface. Must match the strings `web/src/` TypeScript callers
    /// switch on — bump the TS consumers if you add a variant.
    pub fn as_str(&self) -> &'static str {
        match self {
            ConnectionState::Connecting => "connecting",
            ConnectionState::Connected => "connected",
            ConnectionState::Disconnected => "disconnected",
        }
    }
}

/// Observer callback invoked whenever a client moves between
/// [`ConnectionState`] values.
///
/// Wired into the WASM side's `onStateChange(cb)` by wrapping the JS
/// `Function` in a `send_wrapper::SendWrapper<Rc<RefCell<Function>>>`
/// bridge (see `crates/sdk/wasm/src/client.rs`). On native, callers
/// typically implement this with a channel sender or a simple `Arc<Mutex<_>>`.
pub trait StateListener: Send + Sync {
    /// Invoked on every transition. Will be called from the async
    /// task that drives the client — implementations MUST NOT block.
    fn on_state_change(&self, state: ConnectionState);
}
