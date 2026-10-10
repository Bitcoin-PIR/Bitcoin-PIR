//! PIR SDK: core types and traits for Private Information Retrieval clients.
//!
//! - **Types**: common data structures like `UtxoEntry`, `DatabaseInfo`, `SyncPlan`
//! - **Error**: a unified error type for all PIR operations
//! - **Client trait**: the interface every backend client implements
//! - **Sync**: delta synchronization planning and merging
//!
//! # Architecture
//!
//! The SDK supports three PIR backends:
//! - **DPF-PIR**: Two-server, stateless, uses Distributed Point Functions
//! - **HarmonyPIR**: Two-server (hint + query), stateful per-group hints
//! - **OnionPIR**: Single-server, FHE-based, requires key registration
//!
//! All backends share the same two-level (INDEX + CHUNK) cuckoo table structure
//! and support chained delta synchronization (snapshot A -> delta A->B -> delta B->C -> ...).
//!
//! The backend clients (`DpfClient`, `HarmonyClient`, `OnionClient`,
//! `OramClient`) live in `pir-sdk-client`.

pub mod client;
pub mod error;
pub mod leakage;
pub mod metrics;
pub mod sync;
pub mod types;

// Re-export main types at crate root
pub use client::{
    ConnectionState, NoProgress, PirClient, PrintProgress, StateListener, SyncProgress,
};
pub use error::{ErrorKind, PirError, PirResult};
pub use leakage::{
    BufferingLeakageRecorder, LeakageProfile, LeakageRecorder, NoopLeakageRecorder, RoundKind,
    RoundProfile,
};
pub use metrics::{
    AtomicMetrics, AtomicMetricsSnapshot, Duration, Instant, NoopMetrics, PirMetrics,
};
pub use sync::{
    compute_sync_plan, decode_delta_data, merge_delta, merge_delta_batch, require_fresh_sync,
    require_sync_base, DeltaData, SyncPlan, SyncPlanner, SyncStep, MAX_DELTA_CHAIN_LENGTH,
};
pub use types::*;

// Re-export pir-core for convenience
pub use pir_core;
