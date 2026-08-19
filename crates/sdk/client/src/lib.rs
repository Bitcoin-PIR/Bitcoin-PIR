//! PIR SDK Client: Native Rust client for PIR queries.
//!
//! This crate provides PIR client implementations for supported backends:
//!
//! - **DPF** (`DpfClient`): Two-server client using Distributed Point Functions.
//!   This is the recommended backend for production use.
//! - **HarmonyPIR** (`HarmonyClient`): Two-server client with offline hint phase.
//!   Connects to a separate hint server and query server; enable the `fastprp` or
//!   `alf` cargo feature to select a faster PRP backend.
//! - **OnionPIR** (`OnionClient`): Single-server FHE-based client.
//!   Currently a placeholder - requires FHE library integration.
//!
//! # Quick Start
//!
//! ```ignore
//! use pir_sdk_client::{DpfClient, PirClient, ScriptHash};
//!
//! #[tokio::main]
//! async fn main() {
//!     // Create client with two server URLs
//!     let mut client = DpfClient::new("ws://server0:8091", "ws://server1:8092");
//!     client.connect().await.unwrap();
//!
//!     // Query for a script hash
//!     let script_hash: ScriptHash = [0u8; 20]; // your HASH160 script hash
//!     let result = client.sync(&[script_hash], None).await.unwrap();
//!
//!     // Process results
//!     if let Some(query_result) = &result.results[0] {
//!         for entry in &query_result.entries {
//!             println!("UTXO: {} sats at {}:{}", entry.amount_sats, hex::encode(entry.txid), entry.vout);
//!         }
//!         println!("Total balance: {} sats", query_result.total_balance());
//!     }
//! }
//! ```
//!
//! # Delta Synchronization
//!
//! The SDK supports efficient delta sync - if you have results from a previous
//! height, you only need to query the changes:
//!
//! ```ignore
//! // First sync
//! let result = client.sync(&script_hashes, None).await?;
//! let height = result.synced_height;
//!
//! // Later: only query changes since last sync
//! let updated = client.sync(&script_hashes, Some(height)).await?;
//! ```

// `connection` hosts the tokio-tungstenite + rustls native WebSocket client.
// It is native-only: its deps (`tokio::net::TcpStream`, `rustls`,
// `tokio_tungstenite::connect_async`) don't compile to
// `wasm32-unknown-unknown`. On wasm32 the equivalent role is played by
// [`wasm_transport::WasmWebSocketTransport`], which wraps `web_sys::WebSocket`
// and bridges its callback-driven API to `async/.await` via an mpsc channel.
pub mod admin;
pub mod announce;
pub mod attest;
pub mod bat_v2;
pub mod bolt11;
pub mod channel;
#[cfg(not(target_arch = "wasm32"))]
mod connection;
pub mod db_proof;
mod dpf;
mod harmony;
pub mod hint_cache;
mod merkle_verify;
mod onion;
#[cfg(feature = "onion")]
mod onion_merkle;
mod oram;
mod platform_time;
mod protocol;
mod query_plan;
pub mod service;
pub mod strict_pair;
mod transport;
mod verified_query;
mod verified_roots;
#[cfg(any(target_arch = "wasm32", test))]
mod wasm_chunk;
#[cfg(target_arch = "wasm32")]
mod wasm_transport;

pub use bat_v2::{
    AcceptedBolt11BatV2QuoteV2, PreparedBolt11BatV2ClaimV2, PreparedBolt11BatV2QuoteV2,
    VerifiedCurrentBatV2OfferV2,
};
pub use bolt11::{
    AcceptedBolt11QuoteV1, Bolt11QuoteKeyCheckpointV1, PreparedBolt11ClaimV1, PreparedBolt11QuoteV1,
};
#[cfg(not(target_arch = "wasm32"))]
pub use connection::{
    RetryPolicy, WsConnection, DEFAULT_CONNECT_TIMEOUT, DEFAULT_INITIAL_BACKOFF_DELAY,
    DEFAULT_MAX_BACKOFF_DELAY, DEFAULT_MAX_CONNECT_ATTEMPTS, DEFAULT_REQUEST_TIMEOUT,
};
pub use db_proof::{
    fetch_database_proof, fetch_database_proof_v2, verify_database_proof,
    verify_database_proof_response, verify_database_proof_v2, verify_database_proof_v2_response,
    DatabaseProofBundle, DatabaseProofPolicy, VerifiedDatabaseRoots,
};
pub use dpf::DpfClient;
pub use harmony::{HarmonyClient, HintProgress, PRP_FASTPRP, PRP_HMR12};
pub use onion::OnionClient;
pub use oram::{OramClient, OramLookupItem, OramLookupResult, OramLookupSlot};
pub use query_plan::{
    plan_dpf_service_query_v1, plan_harmony_service_hint_v1, plan_harmony_service_query_v1,
    ProductBackendV1, ProductQueryLowerBoundsV1, ProductQueryOmissionsV1, ProductQueryShapeV1,
    ProductWorkloadV1,
};
pub use service::{
    accept_bat_v2_authorization_response_v2, accept_pow_challenge_response_v1,
    accept_retained_bat_v2_policy_response_v2, accept_retained_service_policy_response_v1,
    accept_service_policy_response_v1, dangerous_unpaired_authorize_bat_v2_redemption_v2,
    build_pow_challenge_request_v1, build_retained_service_policy_request_v1,
    build_service_policy_request_v1,
    dangerous_unpaired_accept_retained_service_authorization_response_v1,
    dangerous_unpaired_accept_service_authorization_response_v1,
    dangerous_unpaired_authorize_retained_service_redemption_v1,
    dangerous_unpaired_authorize_service_operation_v1,
    dangerous_unpaired_build_authorization_proof_v1,
    dangerous_unpaired_build_retained_authorization_proof_v1,
    dangerous_unpaired_build_retained_service_authorization_request_v1,
    dangerous_unpaired_build_service_authorization_request_v1, fetch_retained_bat_v2_policy_v2,
    fetch_retained_service_redemption_v1, fetch_verified_service_policy_v1,
    request_pow_challenge_v1, verify_service_policy_session_v1, AcceptedRetainedBatV2PolicyV2,
    AcceptedRetiredServiceRedemptionV1, AcceptedServicePolicyV1, BatV2AdmissionOutcomeV2,
    ServicePolicyCheckpointV1, VerifiedBatV2RedemptionV2,
};
pub use strict_pair::{
    select_strict_bat_v2_offer_v2, select_strict_provider_offer_v1,
    verify_strict_two_provider_bat_v2_offer_pair_v2, verify_strict_two_provider_offer_pair_v1,
    StrictBatV2OfferSelectionV2, StrictProviderOfferSelectionV1, StrictProviderPairOptionsV1,
    StrictProviderPaymentContextInputV1, VerifiedDistinctBatV2ProofPairV2,
    VerifiedStrictTwoProviderBatV2OfferPairV2, VerifiedStrictTwoProviderOfferPairV1,
    VerifiedStrictTwoProviderPaymentContextV1,
};
pub use transport::PirTransport;
pub use verified_query::VerifiedQueryResult;
pub use verified_roots::RootPolicy;
#[cfg(target_arch = "wasm32")]
pub use wasm_transport::WasmWebSocketTransport;

// Re-export SDK types
pub use pir_sdk::{
    compute_sync_plan, merge_delta, merge_delta_batch, DatabaseCatalog, DatabaseInfo,
    PirBackendType, PirClient, PirClientConfig, PirError, PirResult, QueryResult, ScriptHash,
    SyncPlan, SyncResult,
};
