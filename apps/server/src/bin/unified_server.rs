//! Unified PIR WebSocket server — serves all 3 protocols from one process.
//!
//! Roles:
//!   --role primary   (default): DPF + OnionPIR + HarmonyPIR (hint + query)
//!   --role secondary:           DPF only (2nd server for 2-server DPF protocol)
//!
//! Uses pir-core's MappedDatabase for table loading instead of legacy CuckooTablePair.
//!
//! Usage:
//!   unified_server --port 8091 [--data-dir /path/to/checkpoint] [--role primary|secondary]
//!     [--checkpoint /path/to/checkpoint <height>]...
//!     [--delta /path/to/delta <base_height> <tip_height>]...

use pir_runtime_core::free_admission::{
    FreeAdmissionCommitterV1, FreeIpSubjectKeyV1, FreeRateLimitStateV1,
};
use pir_runtime_core::harmony_attach_runtime::HarmonyAttachRegistryV1;
use pir_runtime_core::service_admission::{
    encode_auth_result_response_v1, encode_harmony_attach_result_response_v1,
    encode_pow_challenge_response_v1, encode_service_policy_response_v1, AdmissionEnforcementV1,
    AdmissionMethodRouteV1, BackendFrameKindV1, BackendFramePermitV1, BackendFrameV1,
    CompositeAdmissionMethodCommitterV1, ConnectionAdmissionGateV1, ProviderStoreBearerCommitterV1,
    ServiceWireRequestV1,
};
use pir_runtime_core::service_policy_runtime::{
    activate_exact_storeless_free_pow_policy_v1, activate_retained_service_policy_v1,
    activate_service_policy_v1, validate_policy_method_coverage_v1,
    validate_retained_policy_method_coverage_v1, ActivatedRetainedServicePolicyV1,
    ActivatedServicePolicyV1,
};
use runtime::config::ServerConfig;
use runtime::db_proof::load_database_proof_bundle;
use runtime::eval::{self, GroupTiming};
use runtime::hint_pool;
use runtime::onionpir::*;
use runtime::protocol::*;
use runtime::table::{
    DatabaseDescriptor, DatabaseType, MappedDatabase, MappedSubTable, ServerState,
};

use ed25519_dalek::VerifyingKey;
use futures_util::{SinkExt, StreamExt};
use libdpf::DpfKey;
use pir_core::params::{self, CHUNK_PARAMS, INDEX_PARAMS};
use rayon::prelude::*;
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore, SemaphorePermit};
use tokio_tungstenite::accept_async_with_config;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;

use pir_arc_adapter::{
    ArcPresentationCanonicalizerV1 as ExperimentalArcPresentationCanonicalizerV1, ArcSecretKeyV1,
    ArcSecretKeyringV1,
};
use pir_payment_crypto::K256CashuMintKeyringV1;
use pir_rollback_authority_client::load_remote_rollback_authority_deployment_for_business_domain_v1;
use pir_service_protocol::{
    bind_auth_begin_v1, BackendId as ServiceBackendIdV1, DatasetBindingV1,
    HarmonyAttachRejectCodeV1, HarmonyAttachResultV1, HarmonyAttachTransitionErrorV1,
    IssuerClearingApprovalV1, OperationStartV1, ProviderClearingAuthorizationV1,
    ProviderRedeemEnvelopeV1, ServicePolicyRequestV1, ServicePolicyResponseV1, ServicePolicyV1,
    ServiceProtocolError, TrustedCatalogResolutionV1, VerifiedServiceOfferV1,
    WorkloadId as ServiceWorkloadIdV1,
};
use pir_service_store::{
    CashuCustodyInventoryV1, ProviderStore, RemoteProviderRollbackFloorAuthorityV1,
    RollbackFloorAuthorityV1, SqliteRollbackFloorAuthorityV1, StoreOptions,
};
use zeroize::{Zeroize, Zeroizing};

use pir_cashu_client::{
    CashuCustodyExposureLimitsV1, CashuMintRouteV1, CashuMintTransportFailureKindV1,
    CashuMintTransportFailureV1, CashuMintTransportV1, CashuMintTrustV1,
    ChaCha20Poly1305CustodyCipherV1, ChaCha20Poly1305RecoveryCipherV1,
    StandardCashuAdmissionCommitterV1, StandardCashuClientV1,
};
use pir_provider_clearing_client::{
    ProviderRedeemIdempotencyKeyV1, SharedIssuerAdmissionCommitterV1, SharedIssuerRedeemEnvelopeV1,
    SharedIssuerRedeemTransportV1, SharedIssuerTransportErrorV1,
};
use pir_strict_https::{HttpsPostErrorV1, StrictHttpsClientV1};

/// Detailed per-connection/per-query logging is a privacy-dangerous local
/// diagnostic mode. Production/default logging must never depend on request
/// identity, shape, selected database, byte count, or elapsed time.
#[cfg(any(test, feature = "test-only-unsafe-query-logging"))]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(any(test, feature = "test-only-unsafe-query-logging"))]
static UNSAFE_DEBUG_QUERY_LOGGING: AtomicBool = AtomicBool::new(false);

#[cfg(any(test, feature = "test-only-unsafe-query-logging"))]
macro_rules! unsafe_debug_log {
    ($($arg:tt)*) => {
        if UNSAFE_DEBUG_QUERY_LOGGING.load(Ordering::Relaxed) {
            eprintln!($($arg)*);
        }
    };
}

/// Build a query-derived ORAM diagnostic only in an explicitly unsafe local
/// diagnostic build *and* only when its runtime switch is enabled. In normal
/// artifacts the formatting expression (including bin/chunk identifiers and
/// backend error text) is not compiled at all.
#[cfg(all(
    feature = "cuckoo-oram",
    any(test, feature = "test-only-unsafe-query-logging")
))]
macro_rules! unsafe_oram_detail {
    ($($arg:tt)*) => {{
        if UNSAFE_DEBUG_QUERY_LOGGING.load(Ordering::Relaxed) {
            Some(format!($($arg)*))
        } else {
            None
        }
    }};
}

#[cfg(all(
    feature = "cuckoo-oram",
    not(any(test, feature = "test-only-unsafe-query-logging"))
))]
macro_rules! unsafe_oram_detail {
    ($($arg:tt)*) => {{
        None::<String>
    }};
}

// Keep call sites type-checked and their timing variables non-unused without
// compiling an output path or runtime switch into normal binaries.
#[cfg(not(any(test, feature = "test-only-unsafe-query-logging")))]
macro_rules! unsafe_debug_log {
    ($($arg:tt)*) => {
        if false {
            let _ = format_args!($($arg)*);
        }
    };
}

// HarmonyPIR imports
use harmonypir::params::Params;
use harmonypir::prp::hoang::HoangPrp;

// OnionPIR imports
use memmap2::Mmap;
use onionpir::{self, KeyStore, Server as PirServer};

#[cfg(feature = "cuckoo-oram")]
use bitcoinpir_oram::{
    circuit_meta_page_bytes, circuit_payload_page_bytes, AeadPageStore, CircuitCuckooBinReader,
    CircuitDirectChunkReader, CircuitDirectIndexReader, CircuitOram, CircuitOramState,
    CircuitStoreAuthLayout, CircuitStoreAuthState, CuckooLevel, CuckooTableInfo, DirectLevel,
    DirectOramDatasetBindingV1, DirectTableMetadata, EmbeddedTreePageStore, FilePageStore,
    FrontCachedPageStore, OramParams, PageStore, PathPageStore, Result as OramResult,
    TieredMerklePageStore, TieredMerkleState, AEAD_OVERHEAD, DIRECT_CHUNK_RECORD_SIZE,
    EMBEDDED_TREE_AUTH_BYTES_PER_PAGE,
};

#[cfg(all(feature = "cuckoo-oram", test))]
use bitcoinpir_oram::{
    CuckooPackedBlockReader, DirectChunkPackedBlockReader, DirectIndexPackedBlockReader,
    DirectTableInfo, DIRECT_INDEX_INPUT_RECORD_SIZE,
};

// ─── CLI ────────────────────────────────────────────────────────────────────

/// Loosely-coupled flag controlling **only OnionPIR loading** at startup.
///
/// History: `Primary` and `Secondary` originally bundled three
/// independent decisions — OnionPIR loading, HarmonyPIR query
/// dispatch, HarmonyPIR hint dispatch. That bundling pinned operators
/// into "primary host = full stack, secondary host = hint-only" which
/// made it awkward to allocate workload to where the hardware fits.
///
/// Today the role flag controls only one thing: whether to attempt
/// loading OnionPIR data files at startup. Both roles handle every
/// DPF and HarmonyPIR opcode (hint, query, batch query, info). The
/// CLIENT chooses which endpoint to send hint vs query requests to —
/// the two-server non-collusion property of HarmonyPIR comes from
/// picking independent operators/hardware, not from server-side
/// dispatch gating.
///
/// `--disable-onion` overrides the OnionPIR-loading default for a
/// primary-role instance that doesn't have the data files (e.g., the
/// VPSBG host, which is OnionPIR-free by design).
///
/// (The variant names are kept for back-compat with existing systemd
/// units and CLI invocations; semantically they could just as well be
/// `WithOnion`/`NoOnion`.)
#[derive(Clone, Copy, PartialEq)]
enum ServerRole {
    /// Tries to load OnionPIR data at startup unless `--disable-onion`
    /// is set. Both Hetzner (which has OnionPIR data) and VPSBG (which
    /// doesn't, hence `--disable-onion`) can run as Primary safely;
    /// the loader gracefully skips on missing files.
    Primary,
    /// Skips OnionPIR loading entirely. Useful when the operator
    /// wants to be explicit about "this server is intentionally
    /// OnionPIR-free" without relying on file-presence detection.
    Secondary,
}

struct CliArgs {
    /// IP address to bind. The production-compatible default remains the
    /// dual-stack wildcard; local integration harnesses can explicitly bind
    /// 127.0.0.1 so the test listener is never exposed off-host.
    bind_address: IpAddr,
    port: u16,
    data_dir: PathBuf,
    role: ServerRole,
    /// Path to databases.toml config file (overrides --checkpoint/--delta).
    config_path: Option<PathBuf>,
    /// Checkpoint databases: (path, height).
    checkpoints: Vec<(PathBuf, u32)>,
    /// Delta databases: (path, base_height, tip_height).
    deltas: Vec<(PathBuf, u32, u32)>,
    /// Hex-encoded ed25519 admin pubkey (64 chars). When set, REQ_ADMIN_*
    /// requests are accepted and gated by challenge/response auth against
    /// this key. When unset, all REQ_ADMIN_* requests return an error
    /// envelope.
    admin_pubkey_hex: Option<String>,
    /// Skip OnionPIR loading even if files are present and this is a
    /// primary-role instance. Used on hosts that are intentionally
    /// OnionPIR-free (e.g., the VPSBG non-collusion partner where
    /// OnionPIR data is not synced from Hetzner). Primary role
    /// otherwise auto-loads OnionPIR if files exist.
    disable_onion: bool,
    /// Directory containing the AMD VCEK chain PEMs. Expected files:
    ///   - cert_chain.pem  (ASK + ARK concatenated, as AMD KDS returns)
    ///   - vcek.pem        (the per-chip VCEK for the current TCB)
    ///
    /// If unset (or files missing), the AttestResult ships empty cert
    /// fields and the browser-side verifier falls back to V2-binding-
    /// only mode. Operator's responsibility to refresh after TCB
    /// changes (kernel update, microcode update) — see
    /// docs/PHASE3_ROADMAP.md.
    vcek_dir: Option<PathBuf>,
    /// HarmonyPIR V2 hint pool size (0 = pool disabled, use V1 on-demand).
    pool_size: usize,
    /// Database ID whose immutable tables back this process's single V2 hint
    /// pool. One process deliberately owns one pool/database binding.
    pool_db_id: u8,
    /// Directory for pool file persistence.
    pool_dir: Option<PathBuf>,
    /// Require ARC credential presentation before serving PIR queries.
    require_arc: bool,
    /// Path to the 128-byte ARC private key (`arc_key.bin`) shared with the
    /// issuer. When set with `--require-arc`, the verifier loads this key so
    /// externally-issued credentials verify. Without it, a random key is
    /// generated (no external credential can verify — dev/test only).
    arc_key_path: Option<PathBuf>,
    require_cashu: bool,
    cashu_keysets: Vec<(String, String)>,
    /// Enforce the production V1 service admission state machine. This first
    /// integration slice is deliberately fail-closed until a verified policy
    /// source and all advertised method adapters are configured.
    require_service_auth_v1: bool,
    /// Canonical operator-signed ServicePolicyV1 bytes. Required with strict
    /// V1 admission; never fetched from an untrusted network location.
    service_policy_path: Option<PathBuf>,
    /// Canonical, older signed policies retained solely for redeeming already
    /// issued credentials during each offer's bounded grace period.
    service_retained_policy_paths: Vec<PathBuf>,
    /// Trusted provider audience and the single V1 policy verification key.
    /// This key must remain stable while any retained policy grace window is
    /// live; V1 deliberately has no unauthenticated historical-key list.
    service_provider_id_hex: Option<String>,
    service_policy_key_hex: Option<String>,
    /// Exact canonical ServicePolicyV1 digest for the measured, storeless
    /// Free-PoW-only deployment mode. The pin must be part of the measured
    /// launch configuration; it replaces durable policy rollback state only
    /// for this deliberately narrow policy shape.
    service_storeless_free_pow_policy_digest_hex: Option<String>,
    /// Existing provider spend database. The rollback authority must be exactly
    /// one local development/test SQLite file or one production remote config;
    /// startup never creates or silently substitutes either.
    service_store_path: Option<PathBuf>,
    service_rollback_authority_path: Option<PathBuf>,
    service_remote_rollback_authority_config_path: Option<PathBuf>,
    /// Explicit acknowledgement that the selected local SQLite rollback floor
    /// is development/test-only and not an independent production authority.
    allow_local_service_rollback_authority_dev: bool,
    /// Secret HMAC key for provider-local durable IP quota cohorts.
    service_free_ip_key_path: Option<PathBuf>,
    /// Assert that the TCP peer address is the real client address. This is
    /// deliberately separate from the HMAC key because a local reverse proxy
    /// would otherwise collapse every user into one free-rate bucket.
    service_trust_direct_peer_ip: bool,
    /// Raw 32-byte provider-local Cashu BAT denomination secrets. Repeatable.
    service_bat_key_paths: Vec<PathBuf>,
    /// Experimental provider-local ARC private keys, each encoded as
    /// `<hex-key-id>=<raw-128-byte-key-path>`.
    service_arc_key_specs: Vec<String>,
    /// Explicit acknowledgement required before any current/retained V1 policy
    /// may advertise experimental ARC or any provider-local ARC key is loaded.
    allow_experimental_arc: bool,
    /// Standard Cashu merchant recovery keys as `<epoch>=<raw-32-byte-path>`.
    service_cashu_recovery_key_specs: Vec<String>,
    service_cashu_recovery_active_epoch: Option<u64>,
    /// Separately keyed standard Cashu note-custody encryption. Recovery and
    /// custody key material are intentionally not interchangeable.
    service_cashu_custody_key_specs: Vec<String>,
    service_cashu_custody_active_epoch: Option<u64>,
    /// Finite exposure caps as
    /// `<mint-id-hex>:<unit>:<max-unsettled-value>:<max-unsettled-notes>`.
    service_cashu_exposure_limit_specs: Vec<String>,
    /// Test-only private WebPKI root for deterministic Standard Cashu process
    /// E2E. Leaf-SPKI pins are still authenticated signed-manifest data.
    #[cfg(feature = "standard-cashu-process-e2e")]
    test_only_service_https_root_pem: Option<PathBuf>,
    /// One shared issuer clearing relationship for this provider runtime.
    service_shared_authorization_path: Option<PathBuf>,
    service_shared_issuer_approval_path: Option<PathBuf>,
    service_shared_operator_key_hex: Option<String>,
    service_shared_issuer_settlement_key_hex: Option<String>,
    service_shared_clearing_key_path: Option<PathBuf>,
    service_shared_idempotency_key_path: Option<PathBuf>,
    service_shared_minimum_authorization_epoch: Option<u64>,
    /// Hard cap on live TCP/WebSocket tasks. Connections over the cap are
    /// dropped before allocating a WebSocket parser.
    max_connections: usize,
    /// Hard cap on concurrent service AUTH commits, including blocking
    /// external Cashu/shared-issuer calls.
    service_max_concurrent_auth: usize,
    /// Sub-cap for Harmony V2Full authorizations whose authoritative verifier
    /// is online. It must leave at least one global AUTH permit and one ready
    /// pool entry available to provider-local methods.
    service_max_concurrent_online_v2full_auth: Option<usize>,
    websocket_handshake_timeout_ms: u64,
    connection_idle_timeout_ms: u64,
    /// Absolute lifetime of an enforced-mode connection through successful
    /// write+flush of its granted AUTH result. Unlike the idle timeout,
    /// WebSocket Ping/control traffic cannot extend this deadline. A durable
    /// commit already in progress is not cancelled, but the remaining fixed
    /// budget covers its result delivery; expiry closes before any PIR work.
    service_pre_auth_timeout_ms: u64,
    /// Explicitly enables privacy-dangerous per-connection/per-query logs.
    #[cfg(any(test, feature = "test-only-unsafe-query-logging"))]
    unsafe_debug_query_logging: bool,
    /// Whether this server accepts HarmonyPIR hint requests
    /// (`REQ_HARMONY_HINTS` / `REQ_HARMONY_HINTS_V2`). Default `false`;
    /// must be explicitly enabled via `--serve-hints`. Combined with
    /// `--serve-queries` to pin the role: pir1 (Hetzner, no-SEV) runs
    /// `--serve-hints --serve-queries` (HarmonyPIR hint pool + DPF
    /// server-0 + OnionPIR); pir2 (VPSBG, SEV-SNP Tier 3) runs
    /// `--serve-queries` only (DPF server-1 + HarmonyPIR query phase).
    /// Misconfiguration (client hits the wrong role) becomes a
    /// wire-level rejection instead of silently falling through to
    /// the legacy V1-on-demand path or producing confusing errors.
    serve_hints: bool,
    /// Whether this server accepts PIR query requests (DPF batches,
    /// OnionPIR queries, HarmonyPIR query phase, Merkle siblings,
    /// tree-tops). Default `false`; must be explicitly enabled via
    /// `--serve-queries`. See `serve_hints` for the deployment
    /// topology rationale.
    serve_queries: bool,
    /// Path to the server's long-lived Ed25519 identity key (raw 32-byte
    /// seed). Combined with `--identity-cert-path` to build the
    /// REQ_ANNOUNCE bundle. If either is missing or fails to load,
    /// REQ_ANNOUNCE is disabled but the rest of the protocol runs
    /// normally. Generate one with `bpir-admin generate-identity`.
    identity_key_path: Option<PathBuf>,
    /// Path to the operator-signed IdentityCert (raw bytes produced by
    /// `bpir-admin sign-identity`, encoded per
    /// `pir_identity::IdentityCert::encode`).
    identity_cert_path: Option<PathBuf>,
    /// Human-readable server identifier (e.g. "pir1", "pir2"). Bound
    /// into the announcement bundle; cross-checked against the cert
    /// loaded from `--identity-cert-path`. Required if either of the
    /// identity flags is set.
    identity_server_id: Option<String>,
    /// Optional Circuit ORAM image directory for the two-level cuckoo tables
    /// (legacy alias for db_id=0, levels 0/1 only). Built by `oramctl build-circuit`.
    cuckoo_oram_dir: Option<PathBuf>,
    /// Optional per-database Circuit ORAM image directories.
    /// Repeatable as `--cuckoo-oram-db <db_id>=<dir>`.
    cuckoo_oram_dbs: Vec<(u8, PathBuf)>,
    /// Consecutive cuckoo bins packed into one ORAM logical block.
    cuckoo_oram_pack: usize,
    /// Public deterministic evictions drained after each ORAM bin read.
    cuckoo_oram_drain_per_access: u64,
    /// Whether ORAM metadata/payload page files are AEAD wrapped.
    cuckoo_oram_encrypted: bool,
    /// 32-byte hex key for encrypted ORAM page files.
    cuckoo_oram_key_hex: Option<String>,
    /// 32-byte hex key for encrypted ORAM controller state.
    cuckoo_oram_state_key_hex: Option<String>,
    /// Public top-tree levels cached in trusted memory.
    cuckoo_oram_cache_levels: usize,
    /// Authenticate disk-backed ORAM page images with split Merkle stores.
    cuckoo_oram_auth_store: bool,
    /// Do not persist trusted ORAM state after query responses.
    cuckoo_oram_no_save: bool,
    /// Optional direct-entry ORAM image directory for db_id=0.
    direct_oram_dir: Option<PathBuf>,
    /// Optional per-database direct-entry ORAM image directories.
    /// Repeatable as `--direct-oram-db <db_id>=<dir>`.
    direct_oram_dbs: Vec<(u8, PathBuf)>,
    /// Optional per-database trusted controller/auth state directories.
    /// Repeatable as `--direct-oram-trusted-state-db <db_id>=<dir>`.
    direct_oram_trusted_state_dbs: Vec<(u8, PathBuf)>,
    /// Development/test-only escape hatch for trusted state outside the
    /// measured `/run/bitcoinpir-oram-state` tmpfs.
    #[cfg_attr(not(feature = "cuckoo-oram"), allow(dead_code))]
    direct_oram_allow_trusted_state_outside_run_dev: bool,
    /// Public deterministic evictions drained after each direct ORAM read.
    direct_oram_drain_per_access: u64,
    /// Fixed direct ORAM access budget per ORAM lookup request.
    direct_oram_access_budget: usize,
    /// Whether direct ORAM metadata/payload page files are AEAD wrapped.
    direct_oram_encrypted: bool,
    /// 32-byte hex key for encrypted direct ORAM page files.
    direct_oram_key_hex: Option<String>,
    /// 32-byte hex key for encrypted direct ORAM controller state.
    direct_oram_state_key_hex: Option<String>,
    /// Public top-tree levels cached in trusted memory.
    direct_oram_cache_levels: usize,
    /// Authenticate disk-backed direct ORAM page images with split Merkle stores.
    direct_oram_auth_store: bool,
    /// Do not persist trusted direct ORAM state after query responses.
    direct_oram_no_save: bool,
}

fn parse_cuckoo_oram_db_arg(spec: &str) -> Result<(u8, PathBuf), String> {
    let Some((db_id_raw, dir_raw)) = spec.split_once('=') else {
        return Err(
            "--cuckoo-oram-db expects <db_id>=<dir> (legacy alias: --harmony-oram-db)".into(),
        );
    };
    let db_id = db_id_raw
        .parse::<u8>()
        .map_err(|e| format!("invalid --cuckoo-oram-db db_id `{}`: {}", db_id_raw, e))?;
    if dir_raw.is_empty() {
        return Err("--cuckoo-oram-db requires a non-empty directory".into());
    }
    Ok((db_id, PathBuf::from(dir_raw)))
}

fn parse_direct_oram_db_arg(spec: &str) -> Result<(u8, PathBuf), String> {
    let Some((db_id_raw, dir_raw)) = spec.split_once('=') else {
        return Err("--direct-oram-db expects <db_id>=<dir>".into());
    };
    let db_id = db_id_raw
        .parse::<u8>()
        .map_err(|e| format!("invalid --direct-oram-db db_id `{}`: {}", db_id_raw, e))?;
    if dir_raw.is_empty() {
        return Err("--direct-oram-db requires a non-empty directory".into());
    }
    Ok((db_id, PathBuf::from(dir_raw)))
}

fn parse_direct_oram_trusted_state_db_arg(spec: &str) -> Result<(u8, PathBuf), String> {
    let Some((db_id_raw, dir_raw)) = spec.split_once('=') else {
        return Err("--direct-oram-trusted-state-db expects <db_id>=<dir>".into());
    };
    let db_id = db_id_raw.parse::<u8>().map_err(|e| {
        format!(
            "invalid --direct-oram-trusted-state-db db_id `{}`: {}",
            db_id_raw, e
        )
    })?;
    if dir_raw.is_empty() {
        return Err("--direct-oram-trusted-state-db requires a non-empty directory".into());
    }
    Ok((db_id, PathBuf::from(dir_raw)))
}

fn fatal_cli(msg: impl AsRef<str>) -> ! {
    eprintln!("ERROR: {}", msg.as_ref());
    std::process::exit(2);
}

fn parse_args() -> CliArgs {
    parse_args_from(std::env::args().collect())
}

/// Bound online-authority V2Full authorization below both configured resources.
/// The runtime additionally enforces a floor against the current cross-process
/// set of lockable ready entries; the target-size calculation alone is not a
/// sufficient availability boundary while a pool is refilling.
fn online_v2full_auth_limit_v1(
    pool_size: usize,
    service_max_concurrent_auth: usize,
    configured: Option<usize>,
) -> Result<usize, String> {
    let safe_max = pool_size
        .saturating_sub(1)
        .min(service_max_concurrent_auth.saturating_sub(1));
    let limit = configured.unwrap_or_else(|| safe_max.min(8));
    if limit > safe_max {
        return Err(format!(
            "--service-max-concurrent-online-v2full-auth={limit} must be less than both --pool-size={pool_size} and --service-max-concurrent-auth={service_max_concurrent_auth}"
        ));
    }
    Ok(limit)
}

/// Acquire the narrower online-authority permit before the global AUTH permit.
/// This ordering prevents rejected online overflow from repeatedly stealing the
/// final global slot that provider-local verification is intended to retain.
fn try_acquire_auth_capacity_v1<'a>(
    global: &'a Semaphore,
    online: &Arc<Semaphore>,
    requires_online: bool,
) -> Option<(Option<OwnedSemaphorePermit>, SemaphorePermit<'a>)> {
    let online_permit = if requires_online {
        Some(Arc::clone(online).try_acquire_owned().ok()?)
    } else {
        None
    };
    let global_permit = global.try_acquire().ok()?;
    Some((online_permit, global_permit))
}

fn parse_args_from(args: Vec<String>) -> CliArgs {
    let mut bind_address = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
    let mut port = 8091u16;
    let mut data_dir = PathBuf::from("/Volumes/Bitcoin/data/checkpoints/940611");
    let mut role = ServerRole::Primary;
    let mut config_path: Option<PathBuf> = None;
    let mut checkpoints: Vec<(PathBuf, u32)> = Vec::new();
    let mut deltas: Vec<(PathBuf, u32, u32)> = Vec::new();
    let mut admin_pubkey_hex: Option<String> = None;
    let mut disable_onion = false;
    let mut vcek_dir: Option<PathBuf> = None;
    let mut pool_size: usize = 0; // 0 = pool disabled
    let mut pool_db_id: u8 = 0;
    let mut pool_dir: Option<PathBuf> = None;
    let mut require_arc = false;
    let mut arc_key_path: Option<PathBuf> = None;
    let mut require_cashu = false;
    let mut cashu_keysets: Vec<(String, String)> = Vec::new();
    let mut require_service_auth_v1 = false;
    let mut service_policy_path: Option<PathBuf> = None;
    let mut service_retained_policy_paths: Vec<PathBuf> = Vec::new();
    let mut service_provider_id_hex: Option<String> = None;
    let mut service_policy_key_hex: Option<String> = None;
    let mut service_storeless_free_pow_policy_digest_hex: Option<String> = None;
    let mut service_store_path: Option<PathBuf> = None;
    let mut service_rollback_authority_path: Option<PathBuf> = None;
    let mut service_remote_rollback_authority_config_path: Option<PathBuf> = None;
    let mut allow_local_service_rollback_authority_dev = false;
    let mut service_free_ip_key_path: Option<PathBuf> = None;
    let mut service_trust_direct_peer_ip = false;
    let mut service_bat_key_paths: Vec<PathBuf> = Vec::new();
    let mut service_arc_key_specs: Vec<String> = Vec::new();
    let mut allow_experimental_arc = false;
    let mut service_cashu_recovery_key_specs: Vec<String> = Vec::new();
    let mut service_cashu_recovery_active_epoch: Option<u64> = None;
    let mut service_cashu_custody_key_specs: Vec<String> = Vec::new();
    let mut service_cashu_custody_active_epoch: Option<u64> = None;
    let mut service_cashu_exposure_limit_specs: Vec<String> = Vec::new();
    #[cfg(feature = "standard-cashu-process-e2e")]
    let mut test_only_service_https_root_pem: Option<PathBuf> = None;
    let mut service_shared_authorization_path: Option<PathBuf> = None;
    let mut service_shared_issuer_approval_path: Option<PathBuf> = None;
    let mut service_shared_operator_key_hex: Option<String> = None;
    let mut service_shared_issuer_settlement_key_hex: Option<String> = None;
    let mut service_shared_clearing_key_path: Option<PathBuf> = None;
    let mut service_shared_idempotency_key_path: Option<PathBuf> = None;
    let mut service_shared_minimum_authorization_epoch: Option<u64> = None;
    let mut max_connections: usize = 128;
    let mut service_max_concurrent_auth: usize = 32;
    let mut service_max_concurrent_online_v2full_auth: Option<usize> = None;
    let mut websocket_handshake_timeout_ms: u64 = 10_000;
    let mut connection_idle_timeout_ms: u64 = 30_000;
    let mut service_pre_auth_timeout_ms: u64 = 120_000;
    #[cfg(any(test, feature = "test-only-unsafe-query-logging"))]
    let mut unsafe_debug_query_logging = false;
    let mut serve_hints = false;
    let mut serve_queries = false;
    let mut identity_key_path: Option<PathBuf> = None;
    let mut identity_cert_path: Option<PathBuf> = None;
    let mut identity_server_id: Option<String> = None;
    let mut cuckoo_oram_dir: Option<PathBuf> = None;
    let mut cuckoo_oram_dbs: Vec<(u8, PathBuf)> = Vec::new();
    let mut cuckoo_oram_pack: usize = 16;
    let mut cuckoo_oram_drain_per_access: u64 = 2;
    let mut cuckoo_oram_encrypted = false;
    let mut cuckoo_oram_key_hex: Option<String> = None;
    let mut cuckoo_oram_state_key_hex: Option<String> = None;
    let mut cuckoo_oram_cache_levels: usize = 0;
    let mut cuckoo_oram_auth_store = false;
    let mut cuckoo_oram_no_save = false;
    let mut direct_oram_dir: Option<PathBuf> = None;
    let mut direct_oram_dbs: Vec<(u8, PathBuf)> = Vec::new();
    let mut direct_oram_trusted_state_dbs: Vec<(u8, PathBuf)> = Vec::new();
    let mut direct_oram_allow_trusted_state_outside_run_dev = false;
    let mut direct_oram_drain_per_access: u64 = 2;
    let mut direct_oram_access_budget: usize = 75;
    let mut direct_oram_encrypted = false;
    let mut direct_oram_key_hex: Option<String> = None;
    let mut direct_oram_state_key_hex: Option<String> = None;
    let mut direct_oram_cache_levels: usize = 0;
    let mut direct_oram_auth_store = false;
    let mut direct_oram_no_save = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--bind-address" => {
                bind_address = args
                    .get(i + 1)
                    .unwrap_or_else(|| fatal_cli("--bind-address requires an IP address"))
                    .parse::<IpAddr>()
                    .unwrap_or_else(|_| fatal_cli("--bind-address requires a valid IP address"));
                i += 1;
            }
            "--port" | "-p" => {
                port = args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(8091);
                i += 1;
            }
            "--data-dir" | "-d" => {
                if let Some(dir) = args.get(i + 1) {
                    data_dir = PathBuf::from(dir);
                }
                i += 1;
            }
            "--role" | "-r" => {
                if let Some(r) = args.get(i + 1) {
                    role = match r.as_str() {
                        "secondary" | "s" | "2" => ServerRole::Secondary,
                        _ => ServerRole::Primary,
                    };
                }
                i += 1;
            }
            "--config" | "-c" => {
                if let Some(path) = args.get(i + 1) {
                    config_path = Some(PathBuf::from(path));
                }
                i += 1;
            }
            "--checkpoint" => {
                // --checkpoint <path> <height>
                if let (Some(path), Some(height)) = (
                    args.get(i + 1),
                    args.get(i + 2).and_then(|s| s.parse::<u32>().ok()),
                ) {
                    checkpoints.push((PathBuf::from(path), height));
                    i += 2;
                }
            }
            "--delta" => {
                // --delta <path> <base_height> <tip_height>
                if let (Some(path), Some(base), Some(tip)) = (
                    args.get(i + 1),
                    args.get(i + 2).and_then(|s| s.parse::<u32>().ok()),
                    args.get(i + 3).and_then(|s| s.parse::<u32>().ok()),
                ) {
                    deltas.push((PathBuf::from(path), base, tip));
                    i += 3;
                }
            }
            "--admin-pubkey-hex" => {
                if let Some(hex) = args.get(i + 1) {
                    admin_pubkey_hex = Some(hex.clone());
                }
                i += 1;
            }
            "--disable-onion" => {
                disable_onion = true;
            }
            "--vcek-dir" => {
                if let Some(dir) = args.get(i + 1) {
                    vcek_dir = Some(PathBuf::from(dir));
                }
                i += 1;
            }
            "--pool-size" => {
                pool_size = args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(0);
                i += 1;
            }
            "--pool-db-id" => {
                let value = args
                    .get(i + 1)
                    .unwrap_or_else(|| fatal_cli("--pool-db-id requires a u8 database ID"));
                pool_db_id = value.parse::<u8>().unwrap_or_else(|_| {
                    fatal_cli(format!(
                        "--pool-db-id must be a u8 database ID, got {value}"
                    ))
                });
                i += 1;
            }
            "--pool-dir" => {
                if let Some(dir) = args.get(i + 1) {
                    pool_dir = Some(PathBuf::from(dir));
                }
                i += 1;
            }
            "--require-arc" => {
                require_arc = true;
            }
            "--arc-key" => {
                if let Some(p) = args.get(i + 1) {
                    arc_key_path = Some(PathBuf::from(p));
                }
                i += 1;
            }
            "--require-cashu" => {
                require_cashu = true;
            }
            "--cashu-keyset" => {
                // Format: --cashu-keyset <id>:<hex_secret_key>
                // Can be repeated for multiple keysets.
                if let Some(kv) = args.get(i + 1) {
                    if let Some((id, sk_hex)) = kv.split_once(':') {
                        cashu_keysets.push((id.to_string(), sk_hex.to_string()));
                    }
                }
                i += 1;
            }
            "--require-service-auth-v1" => {
                require_service_auth_v1 = true;
            }
            "--service-policy" => {
                service_policy_path = args.get(i + 1).map(PathBuf::from);
                i += 1;
            }
            "--service-retained-policy" => {
                if let Some(path) = args.get(i + 1) {
                    service_retained_policy_paths.push(PathBuf::from(path));
                }
                i += 1;
            }
            "--service-provider-id-hex" => {
                service_provider_id_hex = args.get(i + 1).cloned();
                i += 1;
            }
            "--service-policy-key-hex" => {
                service_policy_key_hex = args.get(i + 1).cloned();
                i += 1;
            }
            "--service-storeless-free-pow-policy-digest-hex" => {
                if service_storeless_free_pow_policy_digest_hex.is_some() {
                    fatal_cli(
                        "--service-storeless-free-pow-policy-digest-hex must not be repeated",
                    );
                }
                service_storeless_free_pow_policy_digest_hex = Some(
                    args.get(i + 1)
                        .unwrap_or_else(|| {
                            fatal_cli(
                                "--service-storeless-free-pow-policy-digest-hex requires a digest",
                            )
                        })
                        .clone(),
                );
                i += 1;
            }
            "--service-store" => {
                service_store_path = args.get(i + 1).map(PathBuf::from);
                i += 1;
            }
            "--service-rollback-authority" => {
                if service_rollback_authority_path.is_some() {
                    fatal_cli("--service-rollback-authority must not be repeated");
                }
                let path = args.get(i + 1).unwrap_or_else(|| {
                    fatal_cli("--service-rollback-authority requires a path");
                });
                service_rollback_authority_path = Some(PathBuf::from(path));
                i += 1;
            }
            "--service-remote-rollback-authority-config" => {
                if service_remote_rollback_authority_config_path.is_some() {
                    fatal_cli("--service-remote-rollback-authority-config must not be repeated");
                }
                let path = args.get(i + 1).unwrap_or_else(|| {
                    fatal_cli("--service-remote-rollback-authority-config requires a path");
                });
                service_remote_rollback_authority_config_path = Some(PathBuf::from(path));
                i += 1;
            }
            "--allow-local-service-rollback-authority-dev" => {
                allow_local_service_rollback_authority_dev = true;
            }
            "--service-free-ip-key" => {
                service_free_ip_key_path = args.get(i + 1).map(PathBuf::from);
                i += 1;
            }
            "--service-trust-direct-peer-ip" => {
                service_trust_direct_peer_ip = true;
            }
            "--service-bat-key" => {
                if let Some(path) = args.get(i + 1) {
                    service_bat_key_paths.push(PathBuf::from(path));
                }
                i += 1;
            }
            "--service-arc-key" => {
                if let Some(spec) = args.get(i + 1) {
                    service_arc_key_specs.push(spec.clone());
                }
                i += 1;
            }
            "--allow-experimental-arc" => {
                allow_experimental_arc = true;
            }
            "--service-cashu-recovery-key" => {
                if let Some(spec) = args.get(i + 1) {
                    service_cashu_recovery_key_specs.push(spec.clone());
                }
                i += 1;
            }
            "--service-cashu-recovery-active-epoch" => {
                service_cashu_recovery_active_epoch =
                    args.get(i + 1).and_then(|value| value.parse().ok());
                i += 1;
            }
            "--service-cashu-custody-key" => {
                if let Some(spec) = args.get(i + 1) {
                    service_cashu_custody_key_specs.push(spec.clone());
                }
                i += 1;
            }
            "--service-cashu-custody-active-epoch" => {
                service_cashu_custody_active_epoch =
                    args.get(i + 1).and_then(|value| value.parse().ok());
                i += 1;
            }
            "--service-cashu-exposure-limit" => {
                if let Some(spec) = args.get(i + 1) {
                    service_cashu_exposure_limit_specs.push(spec.clone());
                }
                i += 1;
            }
            #[cfg(feature = "standard-cashu-process-e2e")]
            "--test-only-service-https-root-pem" => {
                if test_only_service_https_root_pem.is_some() {
                    fatal_cli("--test-only-service-https-root-pem must not be repeated");
                }
                let path = args.get(i + 1).unwrap_or_else(|| {
                    fatal_cli("--test-only-service-https-root-pem requires a path");
                });
                test_only_service_https_root_pem = Some(PathBuf::from(path));
                i += 1;
            }
            "--service-shared-authorization" => {
                service_shared_authorization_path = args.get(i + 1).map(PathBuf::from);
                i += 1;
            }
            "--service-shared-issuer-approval" => {
                service_shared_issuer_approval_path = args.get(i + 1).map(PathBuf::from);
                i += 1;
            }
            "--service-shared-operator-key-hex" => {
                service_shared_operator_key_hex = args.get(i + 1).cloned();
                i += 1;
            }
            "--service-shared-issuer-settlement-key-hex" => {
                service_shared_issuer_settlement_key_hex = args.get(i + 1).cloned();
                i += 1;
            }
            "--service-shared-clearing-key" => {
                service_shared_clearing_key_path = args.get(i + 1).map(PathBuf::from);
                i += 1;
            }
            "--service-shared-idempotency-key" => {
                service_shared_idempotency_key_path = args.get(i + 1).map(PathBuf::from);
                i += 1;
            }
            "--service-shared-minimum-authorization-epoch" => {
                service_shared_minimum_authorization_epoch =
                    args.get(i + 1).and_then(|value| value.parse().ok());
                i += 1;
            }
            "--max-connections" => {
                max_connections = args
                    .get(i + 1)
                    .and_then(|value| value.parse().ok())
                    .unwrap_or_else(|| fatal_cli("--max-connections requires an integer"));
                i += 1;
            }
            "--service-max-concurrent-auth" => {
                service_max_concurrent_auth = args
                    .get(i + 1)
                    .and_then(|value| value.parse().ok())
                    .unwrap_or_else(|| {
                        fatal_cli("--service-max-concurrent-auth requires an integer")
                    });
                i += 1;
            }
            "--service-max-concurrent-online-v2full-auth" => {
                service_max_concurrent_online_v2full_auth = Some(
                    args.get(i + 1)
                        .and_then(|value| value.parse().ok())
                        .unwrap_or_else(|| {
                            fatal_cli(
                                "--service-max-concurrent-online-v2full-auth requires an integer",
                            )
                        }),
                );
                i += 1;
            }
            "--websocket-handshake-timeout-ms" => {
                websocket_handshake_timeout_ms = args
                    .get(i + 1)
                    .and_then(|value| value.parse().ok())
                    .unwrap_or_else(|| {
                        fatal_cli("--websocket-handshake-timeout-ms requires an integer")
                    });
                i += 1;
            }
            "--connection-idle-timeout-ms" => {
                connection_idle_timeout_ms = args
                    .get(i + 1)
                    .and_then(|value| value.parse().ok())
                    .unwrap_or_else(|| {
                        fatal_cli("--connection-idle-timeout-ms requires an integer")
                    });
                i += 1;
            }
            "--service-pre-auth-timeout-ms" => {
                service_pre_auth_timeout_ms = args
                    .get(i + 1)
                    .and_then(|value| value.parse().ok())
                    .unwrap_or_else(|| {
                        fatal_cli("--service-pre-auth-timeout-ms requires an integer")
                    });
                i += 1;
            }
            #[cfg(any(test, feature = "test-only-unsafe-query-logging"))]
            "--unsafe-debug-query-logging" => {
                unsafe_debug_query_logging = true;
            }
            "--serve-hints" => {
                serve_hints = true;
            }
            "--serve-queries" => {
                serve_queries = true;
            }
            "--identity-key-path" => {
                if let Some(p) = args.get(i + 1) {
                    identity_key_path = Some(PathBuf::from(p));
                }
                i += 1;
            }
            "--identity-cert-path" => {
                if let Some(p) = args.get(i + 1) {
                    identity_cert_path = Some(PathBuf::from(p));
                }
                i += 1;
            }
            "--identity-server-id" => {
                if let Some(s) = args.get(i + 1) {
                    identity_server_id = Some(s.clone());
                }
                i += 1;
            }
            "--cuckoo-oram-dir" | "--harmony-oram-dir" => {
                if let Some(p) = args.get(i + 1) {
                    cuckoo_oram_dir = Some(PathBuf::from(p));
                }
                i += 1;
            }
            "--cuckoo-oram-db" | "--harmony-oram-db" => {
                let spec = args.get(i + 1).unwrap_or_else(|| {
                    fatal_cli("--cuckoo-oram-db requires <db_id>=<dir>");
                });
                let parsed = parse_cuckoo_oram_db_arg(spec).unwrap_or_else(|e| fatal_cli(e));
                cuckoo_oram_dbs.push(parsed);
                i += 1;
            }
            "--cuckoo-oram-pack" | "--harmony-oram-pack" => {
                cuckoo_oram_pack = args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(16);
                i += 1;
            }
            "--cuckoo-oram-drain-per-access" | "--harmony-oram-drain-per-access" => {
                cuckoo_oram_drain_per_access =
                    args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(2);
                i += 1;
            }
            "--cuckoo-oram-encrypted" | "--harmony-oram-encrypted" => {
                cuckoo_oram_encrypted = true;
            }
            "--cuckoo-oram-key-hex" | "--harmony-oram-key-hex" => {
                if let Some(hex) = args.get(i + 1) {
                    cuckoo_oram_key_hex = Some(hex.clone());
                }
                i += 1;
            }
            "--cuckoo-oram-state-key-hex" | "--harmony-oram-state-key-hex" => {
                if let Some(hex) = args.get(i + 1) {
                    cuckoo_oram_state_key_hex = Some(hex.clone());
                }
                i += 1;
            }
            "--cuckoo-oram-cache-levels" | "--harmony-oram-cache-levels" => {
                cuckoo_oram_cache_levels =
                    args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(0);
                i += 1;
            }
            "--cuckoo-oram-auth-store" | "--harmony-oram-auth-store" => {
                cuckoo_oram_auth_store = true;
            }
            "--cuckoo-oram-no-save" | "--harmony-oram-no-save" => {
                cuckoo_oram_no_save = true;
            }
            "--direct-oram-dir" => {
                if let Some(p) = args.get(i + 1) {
                    direct_oram_dir = Some(PathBuf::from(p));
                }
                i += 1;
            }
            "--direct-oram-db" => {
                let spec = args.get(i + 1).unwrap_or_else(|| {
                    fatal_cli("--direct-oram-db requires <db_id>=<dir>");
                });
                let parsed = parse_direct_oram_db_arg(spec).unwrap_or_else(|e| fatal_cli(e));
                direct_oram_dbs.push(parsed);
                i += 1;
            }
            "--direct-oram-trusted-state-db" => {
                let spec = args.get(i + 1).unwrap_or_else(|| {
                    fatal_cli("--direct-oram-trusted-state-db requires <db_id>=<dir>");
                });
                let parsed =
                    parse_direct_oram_trusted_state_db_arg(spec).unwrap_or_else(|e| fatal_cli(e));
                direct_oram_trusted_state_dbs.push(parsed);
                i += 1;
            }
            "--allow-direct-oram-trusted-state-outside-run-dev" => {
                direct_oram_allow_trusted_state_outside_run_dev = true;
            }
            "--direct-oram-drain-per-access" => {
                direct_oram_drain_per_access =
                    args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(2);
                i += 1;
            }
            "--direct-oram-access-budget" => {
                direct_oram_access_budget =
                    args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(75);
                i += 1;
            }
            "--direct-oram-encrypted" => {
                direct_oram_encrypted = true;
            }
            "--direct-oram-key-hex" => {
                if let Some(hex) = args.get(i + 1) {
                    direct_oram_key_hex = Some(hex.clone());
                }
                i += 1;
            }
            "--direct-oram-state-key-hex" => {
                if let Some(hex) = args.get(i + 1) {
                    direct_oram_state_key_hex = Some(hex.clone());
                }
                i += 1;
            }
            "--direct-oram-cache-levels" => {
                direct_oram_cache_levels =
                    args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(0);
                i += 1;
            }
            "--direct-oram-auth-store" => {
                direct_oram_auth_store = true;
            }
            "--direct-oram-no-save" => {
                direct_oram_no_save = true;
            }
            unknown => fatal_cli(unknown_cli_argument_v1(unknown)),
        }
        i += 1;
    }

    if !(1..=4_096).contains(&max_connections) {
        fatal_cli("--max-connections must be in 1..=4096");
    }
    if !(1..=1_024).contains(&service_max_concurrent_auth) {
        fatal_cli("--service-max-concurrent-auth must be in 1..=1024");
    }
    if service_max_concurrent_online_v2full_auth.is_some_and(|limit| limit > 1_023) {
        fatal_cli("--service-max-concurrent-online-v2full-auth must be in 0..=1023");
    }
    if !(1_000..=60_000).contains(&websocket_handshake_timeout_ms) {
        fatal_cli("--websocket-handshake-timeout-ms must be in 1000..=60000");
    }
    if !(10_000..=600_000).contains(&connection_idle_timeout_ms) {
        fatal_cli("--connection-idle-timeout-ms must be in 10000..=600000");
    }
    if !(10_000..=600_000).contains(&service_pre_auth_timeout_ms) {
        fatal_cli("--service-pre-auth-timeout-ms must be in 10000..=600000");
    }

    CliArgs {
        bind_address,
        port,
        data_dir,
        role,
        config_path,
        checkpoints,
        deltas,
        admin_pubkey_hex,
        disable_onion,
        vcek_dir,
        pool_size,
        pool_db_id,
        pool_dir,
        require_arc,
        arc_key_path,
        require_cashu,
        cashu_keysets,
        require_service_auth_v1,
        service_policy_path,
        service_retained_policy_paths,
        service_provider_id_hex,
        service_policy_key_hex,
        service_storeless_free_pow_policy_digest_hex,
        service_store_path,
        service_rollback_authority_path,
        service_remote_rollback_authority_config_path,
        allow_local_service_rollback_authority_dev,
        service_free_ip_key_path,
        service_trust_direct_peer_ip,
        service_bat_key_paths,
        service_arc_key_specs,
        allow_experimental_arc,
        service_cashu_recovery_key_specs,
        service_cashu_recovery_active_epoch,
        service_cashu_custody_key_specs,
        service_cashu_custody_active_epoch,
        service_cashu_exposure_limit_specs,
        #[cfg(feature = "standard-cashu-process-e2e")]
        test_only_service_https_root_pem,
        service_shared_authorization_path,
        service_shared_issuer_approval_path,
        service_shared_operator_key_hex,
        service_shared_issuer_settlement_key_hex,
        service_shared_clearing_key_path,
        service_shared_idempotency_key_path,
        service_shared_minimum_authorization_epoch,
        max_connections,
        service_max_concurrent_auth,
        service_max_concurrent_online_v2full_auth,
        websocket_handshake_timeout_ms,
        connection_idle_timeout_ms,
        service_pre_auth_timeout_ms,
        #[cfg(any(test, feature = "test-only-unsafe-query-logging"))]
        unsafe_debug_query_logging,
        serve_hints,
        serve_queries,
        identity_key_path,
        identity_cert_path,
        identity_server_id,
        cuckoo_oram_dir,
        cuckoo_oram_dbs,
        cuckoo_oram_pack,
        cuckoo_oram_drain_per_access,
        cuckoo_oram_encrypted,
        cuckoo_oram_key_hex,
        cuckoo_oram_state_key_hex,
        cuckoo_oram_cache_levels,
        cuckoo_oram_auth_store,
        cuckoo_oram_no_save,
        direct_oram_dir,
        direct_oram_dbs,
        direct_oram_trusted_state_dbs,
        direct_oram_allow_trusted_state_outside_run_dev,
        direct_oram_drain_per_access,
        direct_oram_access_budget,
        direct_oram_encrypted,
        direct_oram_key_hex,
        direct_oram_state_key_hex,
        direct_oram_cache_levels,
        direct_oram_auth_store,
        direct_oram_no_save,
    }
}

fn unknown_cli_argument_v1(argument: &str) -> String {
    format!("unknown argument: {argument}")
}

// ─── OnionPIR worker thread ─────────────────────────────────────────────────

enum PirCommand {
    RegisterKeys {
        client_id: u64,
        galois_keys: Vec<u8>,
        gsw_keys: Vec<u8>,
        reply: oneshot::Sender<()>,
    },
    AnswerBatch {
        client_id: u64,
        level: u8,
        round_id: u16,
        queries: Vec<Vec<u8>>,
        reply: oneshot::Sender<Vec<Vec<u8>>>,
    },
}

// ─── OnionPIR file paths + headers ──────────────────────────────────────────

const ONION_NTT_FILE: &str = "onion_shared_ntt.bin";
const ONION_CHUNK_CUCKOO_FILE: &str = "onion_chunk_cuckoo.bin";
// Consolidated INDEX file produced by gen_3_onion. Replaces the legacy
// onion_index_pir/group_{0..K-1}.bin directory layout. Layout:
//   [master header 32B: magic u64 | K u64 | per_group_bytes u64 | reserved u64]
//   [group_0: per_group_bytes] [group_1: per_group_bytes] ... [group_{K-1}]
// Each per-group slice is exactly what OnionPIR's save_db_to_file produced
// (standard preproc header + NTT-form data) and is passed into
// PirServer::load_db_from_bytes — zero-copy via one outer mmap.
const ONION_INDEX_ALL_FILE: &str = "onion_index_all.bin";
const ONION_INDEX_META_FILE: &str = "onion_index_meta.bin";

const ONION_CHUNK_MAGIC: u64 = 0xBA7C_0010_0000_0001;
const ONION_INDEX_META_MAGIC: u64 = 0xBA7C_0010_0000_0002;
const ONION_INDEX_ALL_MAGIC: u64 = 0xBA7C_0010_0000_0003;
const ONION_INDEX_ALL_HEADER_BYTES: usize = 32;

/// XOR markers re-used from pir-core::cuckoo so v1 (legacy, no anchor)
/// vs v2 (snapshot/delta anchor appended) are discriminated by the
/// same bit pattern across all BitcoinPIR file formats.
const ONION_MAGIC_SNAPSHOT_XOR: u64 = pir_core::cuckoo::ANCHOR_MAGIC_SNAPSHOT_XOR;
const ONION_MAGIC_DELTA_XOR: u64 = pir_core::cuckoo::ANCHOR_MAGIC_DELTA_XOR;

/// Recognise legacy + v2 magics for an onion file header. Returns the
/// matched legacy magic (for downstream offset parsing) on success.
/// `Err` if the magic is unrecognised.
fn check_onion_magic(magic: u64, legacy: u64, file_label: &str) -> u64 {
    let snap = legacy ^ ONION_MAGIC_SNAPSHOT_XOR;
    let delta = legacy ^ ONION_MAGIC_DELTA_XOR;
    if magic == legacy || magic == snap || magic == delta {
        legacy
    } else {
        panic!(
            "Bad {} magic: expected 0x{:016x} (legacy), 0x{:016x} (v2 snapshot), or 0x{:016x} (v2 delta); got 0x{:016x}",
            file_label, legacy, snap, delta, magic
        );
    }
}

/// Parse the chain anchor appended after an onion file's `header_size`-byte
/// legacy header, when the magic indicates a v2 (snapshot/delta) layout.
/// `None` for a legacy (pre-anchor) file.
fn parse_onion_anchor(
    data: &[u8],
    legacy_magic: u64,
    header_size: usize,
) -> Option<pir_core::cuckoo::HeaderAnchor> {
    use pir_core::seeds::{ChainAnchor, DeltaAnchor, CHAIN_ANCHOR_BYTES, DELTA_ANCHOR_BYTES};
    let magic = u64::from_le_bytes(data[0..8].try_into().unwrap());
    if magic == legacy_magic ^ ONION_MAGIC_SNAPSHOT_XOR {
        let end = header_size + CHAIN_ANCHOR_BYTES;
        ChainAnchor::from_bytes(data.get(header_size..end)?)
            .ok()
            .map(pir_core::cuckoo::HeaderAnchor::Snapshot)
    } else if magic == legacy_magic ^ ONION_MAGIC_DELTA_XOR {
        let end = header_size + DELTA_ANCHOR_BYTES;
        DeltaAnchor::from_bytes(data.get(header_size..end)?)
            .ok()
            .map(pir_core::cuckoo::HeaderAnchor::Delta)
    } else {
        None
    }
}

/// Self-verify that the onion INDEX/CHUNK seeds were honestly derived
/// from the embedded chain anchor. Panics (refuse-to-serve) on mismatch;
/// no-op for a legacy (anchor-less) onion DB. Mirrors the DPF/HarmonyPIR
/// `MappedSubTable::verify_anchor_consistency` defense-in-depth check.
fn verify_onion_anchor_seeds(
    anchor: &pir_core::cuckoo::HeaderAnchor,
    im_master: u64,
    im_tag: u64,
    ch_master: u64,
    label: &str,
) {
    fn check<C: pir_core::seeds::SeedContext>(
        a: &C,
        im_master: u64,
        im_tag: u64,
        ch_master: u64,
        label: &str,
    ) {
        use pir_core::seeds::{derive_seed_u64, domain};
        let dm = derive_seed_u64(domain::INDEX_CUCKOO_MASTER, a);
        assert_eq!(
            dm, im_master,
            "[anchor] {} onion INDEX master_seed mismatch: derived 0x{:016x} vs header 0x{:016x} — refusing to serve",
            label, dm, im_master
        );
        let dt = derive_seed_u64(domain::INDEX_TAG_FINGERPRINT, a);
        assert_eq!(
            dt, im_tag,
            "[anchor] {} onion INDEX tag_seed mismatch — refusing to serve",
            label
        );
        let dc = derive_seed_u64(domain::CHUNK_CUCKOO_MASTER, a);
        assert_eq!(
            dc, ch_master,
            "[anchor] {} onion CHUNK master_seed mismatch — refusing to serve",
            label
        );
    }
    match anchor {
        pir_core::cuckoo::HeaderAnchor::Snapshot(a) => {
            check(a, im_master, im_tag, ch_master, label)
        }
        pir_core::cuckoo::HeaderAnchor::Delta(a) => check(a, im_master, im_tag, ch_master, label),
    }
}

struct OnionChunkHeader {
    k_chunk: usize,
    bins_per_table: usize,
    num_packed_entries: usize,
    /// CHUNK cuckoo master seed (chain-derived for v2 DBs). Layout:
    /// magic(8) k_chunk(4) cuckoo_hashes(4) bins(4) master_seed(8) ...
    master_seed: u64,
    /// Byte offset where the per-group bin→entry-id tables begin. For a
    /// v2 (chain-anchored) file the anchor is written BETWEEN the 36-byte
    /// header and the tables (same convention as the DPF cuckoo files),
    /// so the tables shift by the anchor length. The table reader MUST use
    /// this — a hardcoded 36 reads the anchor bytes as entry-ids, which
    /// then index out-of-bounds into the NTT store and segfault the query.
    data_offset: usize,
}

/// Legacy onion chunk-cuckoo header size (before any v2 anchor).
const ONION_CHUNK_HEADER_BYTES: usize = 36;

fn read_onion_chunk_header(data: &[u8]) -> OnionChunkHeader {
    let magic = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let _ = check_onion_magic(magic, ONION_CHUNK_MAGIC, "onion chunk cuckoo");
    // The v2 anchor (if any) sits between the legacy header and the
    // per-group tables — so the table data offset must skip it too.
    let anchor_len = if magic == ONION_CHUNK_MAGIC ^ ONION_MAGIC_SNAPSHOT_XOR {
        pir_core::seeds::CHAIN_ANCHOR_BYTES
    } else if magic == ONION_CHUNK_MAGIC ^ ONION_MAGIC_DELTA_XOR {
        pir_core::seeds::DELTA_ANCHOR_BYTES
    } else {
        0
    };
    OnionChunkHeader {
        k_chunk: u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize,
        bins_per_table: u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize,
        master_seed: u64::from_le_bytes(data[20..28].try_into().unwrap()),
        num_packed_entries: u32::from_le_bytes(data[28..32].try_into().unwrap()) as usize,
        data_offset: ONION_CHUNK_HEADER_BYTES + anchor_len,
    }
}

struct OnionIndexMeta {
    k: usize,
    bins_per_table: usize,
    slots_per_bin: usize,
    tag_seed: u64,
    slot_size: usize,
    /// INDEX cuckoo master seed (chain-derived for v2 DBs). Layout:
    /// magic(8) k(4) cuckoo_hashes(4) slots_per_bin(4) bins(4) master_seed(8) tag_seed(8) slot_size(4)
    master_seed: u64,
    /// Chain anchor appended after the 44-byte legacy header in v2 files.
    anchor: Option<pir_core::cuckoo::HeaderAnchor>,
}

/// Legacy (pre-anchor) byte size of the onion index meta header.
const ONION_INDEX_META_HEADER_BYTES: usize = 44;

fn read_onion_index_meta(data: &[u8]) -> OnionIndexMeta {
    let magic = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let _ = check_onion_magic(magic, ONION_INDEX_META_MAGIC, "onion index meta");
    OnionIndexMeta {
        k: u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize,
        bins_per_table: u32::from_le_bytes(data[20..24].try_into().unwrap()) as usize,
        slots_per_bin: u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize,
        master_seed: u64::from_le_bytes(data[24..32].try_into().unwrap()),
        tag_seed: u64::from_le_bytes(data[32..40].try_into().unwrap()),
        slot_size: u32::from_le_bytes(data[40..44].try_into().unwrap()) as usize,
        anchor: parse_onion_anchor(data, ONION_INDEX_META_MAGIC, ONION_INDEX_META_HEADER_BYTES),
    }
}

// ─── HarmonyPIR hint computation ────────────────────────────────────────────

fn derive_group_key(master_key: &[u8; 16], group_id: u32) -> [u8; 16] {
    let mut key = *master_key;
    let id_bytes = group_id.to_le_bytes();
    for i in 0..4 {
        key[12 + i] ^= id_bytes[i];
    }
    key
}

fn xor_into_hint(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

/// Resolve a HarmonyPIR level byte to its sub-table, entry size, and
/// hint-key group offset, or `None` if the level doesn't exist for this
/// DB.
///
/// Level mapping (shared by the hint and batch-query paths):
///   0 = INDEX, 1 = CHUNK
///   10..10+N = bucket Merkle INDEX sibling L0, L1, ...
///   20..20+N = bucket Merkle CHUNK sibling L0, L1, ...
///
/// The level byte arrives off the wire, so resolution must be total —
/// an unknown level is a `None` (mapped to `Response::Error` at the
/// call sites), never a panic: with the workspace-wide
/// `panic = 'abort'`, a panic here kills the whole server (S4).
fn harmony_level_table(db: &MappedDatabase, level: u8) -> Option<(&MappedSubTable, usize, u32)> {
    let index_k = db.index.params.k as u32;
    let chunk_k = db.chunk.params.k as u32;
    match level {
        0 => Some((&db.index, db.index.params.bin_size(), 0)),
        1 => Some((&db.chunk, db.chunk.params.bin_size(), index_k)),
        10..=19 => {
            let sib_level = (level - 10) as usize;
            let sib = db.bucket_merkle_index_siblings.get(sib_level)?;
            // k_offset: after INDEX (75) + CHUNK (80) = 155, plus level offset
            let offset = index_k + chunk_k + sib_level as u32 * index_k;
            Some((sib, sib.params.bin_size(), offset))
        }
        20..=29 => {
            let sib_level = (level - 20) as usize;
            let sib = db.bucket_merkle_chunk_siblings.get(sib_level)?;
            let index_sib_levels = db.bucket_merkle_index_siblings.len() as u32;
            let offset =
                index_k + chunk_k + index_sib_levels * index_k + sib_level as u32 * chunk_k;
            Some((sib, sib.params.bin_size(), offset))
        }
        _ => None,
    }
}

/// Narrow read interface for BitcoinPIR cuckoo-table rows.
///
/// The mmap implementation below preserves the current behavior exactly. The
/// shape is intentionally smaller than `MappedSubTable` so an ORAM-backed table
/// can serve the same `group_id + index` requests without exposing full group
/// slices. HarmonyPIR is the first caller because its query protocol already
/// sends explicit bin indices; a native ORAM backend can reuse the same layer.
trait CuckooTableAccess: Sync {
    fn bins_per_table(&self) -> usize;
    fn entry_size(&self) -> usize;
    fn group_exists(&self, group_id: usize) -> bool;
    fn append_entry(&self, group_id: usize, idx: usize, dst: &mut Vec<u8>) -> Result<(), String>;

    fn append_entries(
        &self,
        group_id: usize,
        indices: &[u32],
        zero_fill_oob: bool,
        dst: &mut Vec<u8>,
    ) -> Result<(), String> {
        for &idx in indices {
            let idx_usize = idx as usize;
            if idx_usize < self.bins_per_table() {
                self.append_entry(group_id, idx_usize, dst)?;
            } else if zero_fill_oob {
                dst.extend(std::iter::repeat_n(0u8, self.entry_size()));
            } else {
                return Err(format!("index {} out of range", idx));
            }
        }
        Ok(())
    }

    fn finish_request(&self) -> Result<(), String> {
        Ok(())
    }

    fn abort_request(&self, _reason: &str) {}
}

struct MmapCuckooTable<'a> {
    sub_table: &'a MappedSubTable,
    entry_size: usize,
}

impl<'a> MmapCuckooTable<'a> {
    const fn new(sub_table: &'a MappedSubTable, entry_size: usize) -> Self {
        Self {
            sub_table,
            entry_size,
        }
    }
}

impl CuckooTableAccess for MmapCuckooTable<'_> {
    fn bins_per_table(&self) -> usize {
        self.sub_table.bins_per_table
    }

    fn entry_size(&self) -> usize {
        self.entry_size
    }

    fn group_exists(&self, group_id: usize) -> bool {
        self.sub_table.try_group_bytes(group_id).is_some()
    }

    fn append_entry(&self, group_id: usize, idx: usize, dst: &mut Vec<u8>) -> Result<(), String> {
        let table_bytes = self
            .sub_table
            .try_group_bytes(group_id)
            .ok_or_else(|| format!("group_id {} out of range", group_id))?;
        if idx >= self.sub_table.bins_per_table {
            return Err(format!("index {} out of range", idx));
        }
        let offset = idx * self.entry_size;
        dst.extend_from_slice(&table_bytes[offset..offset + self.entry_size]);
        Ok(())
    }
}

#[cfg(feature = "cuckoo-oram")]
type CuckooRawPageStore = Box<dyn PageStore + Send>;

#[cfg(feature = "cuckoo-oram")]
enum CuckooOramStore {
    Plain(CuckooRawPageStore),
    Sidecar(TieredMerklePageStore<CuckooRawPageStore, CuckooRawPageStore>),
    Embedded(EmbeddedTreePageStore<CuckooRawPageStore>),
}

#[cfg(feature = "cuckoo-oram")]
impl PathPageStore for CuckooOramStore {
    fn page_size(&self) -> usize {
        match self {
            Self::Plain(store) => PageStore::page_size(&**store),
            Self::Sidecar(store) => PageStore::page_size(store),
            Self::Embedded(store) => PathPageStore::page_size(store),
        }
    }

    fn page_count(&self) -> usize {
        match self {
            Self::Plain(store) => PageStore::page_count(&**store),
            Self::Sidecar(store) => PageStore::page_count(store),
            Self::Embedded(store) => PathPageStore::page_count(store),
        }
    }

    fn read_path_pages(&mut self, path: &[usize]) -> OramResult<Vec<Vec<u8>>> {
        match self {
            Self::Plain(store) => PageStore::read_pages(&mut **store, path),
            Self::Sidecar(store) => PathPageStore::read_path_pages(store, path),
            Self::Embedded(store) => store.read_path_pages(path),
        }
    }

    fn write_path_pages(&mut self, path: &[usize], pages: &[Vec<u8>]) -> OramResult<()> {
        match self {
            Self::Plain(store) => PageStore::write_pages(&mut **store, path, pages),
            Self::Sidecar(store) => PathPageStore::write_path_pages(store, path, pages),
            Self::Embedded(store) => store.write_path_pages(path, pages),
        }
    }

    fn read_paths_pages(&mut self, paths: &[Vec<usize>]) -> OramResult<Vec<Vec<Vec<u8>>>> {
        match self {
            Self::Plain(store) => PathPageStore::read_paths_pages(&mut **store, paths),
            Self::Sidecar(store) => PathPageStore::read_paths_pages(store, paths),
            Self::Embedded(store) => PathPageStore::read_paths_pages(store, paths),
        }
    }

    fn write_paths_pages(
        &mut self,
        paths: &[Vec<usize>],
        pages: &[Vec<Vec<u8>>],
    ) -> OramResult<()> {
        match self {
            Self::Plain(store) => PathPageStore::write_paths_pages(&mut **store, paths, pages),
            Self::Sidecar(store) => PathPageStore::write_paths_pages(store, paths, pages),
            Self::Embedded(store) => PathPageStore::write_paths_pages(store, paths, pages),
        }
    }

    fn flush(&mut self) -> OramResult<()> {
        match self {
            Self::Plain(store) => PageStore::flush(&mut **store),
            Self::Sidecar(store) => PageStore::flush(store),
            Self::Embedded(store) => PathPageStore::flush(store),
        }
    }

    fn tiered_merkle_state(&self) -> Option<TieredMerkleState> {
        match self {
            Self::Plain(store) => PageStore::tiered_merkle_state(&**store),
            Self::Sidecar(store) => Some(store.trusted_state()),
            Self::Embedded(_) => None,
        }
    }

    fn embedded_tree_state(&self) -> Option<bitcoinpir_oram::EmbeddedTreeState> {
        match self {
            Self::Embedded(store) => Some(store.state()),
            Self::Plain(_) | Self::Sidecar(_) => None,
        }
    }
}

#[cfg(feature = "cuckoo-oram")]
type CuckooOramBinReader = CircuitCuckooBinReader<CuckooOramStore, CuckooOramStore>;

#[cfg(feature = "cuckoo-oram")]
struct CuckooOramTable {
    reader: std::sync::Mutex<CuckooOramBinReader>,
    poisoned: std::sync::Mutex<Option<String>>,
    dirty: std::sync::atomic::AtomicBool,
    level: CuckooLevel,
    k: usize,
    bins_per_table: usize,
    entry_size: usize,
    state_path: PathBuf,
    auth_state_path: Option<PathBuf>,
    state_key: Option<[u8; 32]>,
    drain_per_access: u64,
    save_state: bool,
}

#[cfg(feature = "cuckoo-oram")]
impl CuckooOramTable {
    #[allow(clippy::too_many_arguments)]
    fn open(
        db_dir: &std::path::Path,
        oram_dir: &std::path::Path,
        level: CuckooLevel,
        pack: usize,
        drain_per_access: u64,
        encrypted: bool,
        key_hex: Option<&str>,
        state_key_hex: Option<&str>,
        cache_levels: usize,
        auth_store: bool,
        save_state: bool,
    ) -> Result<Self, String> {
        if pack == 0 {
            return Err("--cuckoo-oram-pack must be > 0".into());
        }
        let table = CuckooTableInfo::from_file(level, db_dir.join(level.filename()))
            .map_err(|e| e.to_string())?;
        let paths = CuckooOramPaths::new(oram_dir, level);
        let state_key = parse_optional_32_hex(state_key_hex)?;
        let loaded = match state_key {
            Some(key) => {
                CircuitOramState::load_encrypted(&paths.state, key).map_err(|e| e.to_string())?
            }
            None => CircuitOramState::load(&paths.state).map_err(|e| e.to_string())?,
        };
        let bound_auth = loaded.auth.clone();
        let params = loaded.params.clone();
        let cached_pages = cached_pages_for_oram_levels(&params, cache_levels)?;
        let (meta_store, payload_store) = open_existing_circuit_oram_stores(
            &paths,
            level,
            &params,
            encrypted,
            key_hex,
            cached_pages,
            auth_store,
            bound_auth.as_ref(),
            state_key,
        )?;
        let oram = CircuitOram::from_state(meta_store, payload_store, loaded)
            .map_err(|e| e.to_string())?;
        let reader = CircuitCuckooBinReader::new(&table, pack, oram).map_err(|e| e.to_string())?;

        println!(
            "  Cuckoo ORAM {}: dir={}, pack={}, bins={}, bin_size={}, logical_blocks={}, cache_levels={}, auth_store={}, save_state={}",
            level,
            oram_dir.display(),
            pack,
            table.total_bins(),
            table.bin_size(),
            reader.oram().params().logical_blocks,
            cache_levels,
            auth_store,
            save_state,
        );

        Ok(Self {
            reader: std::sync::Mutex::new(reader),
            poisoned: std::sync::Mutex::new(None),
            dirty: std::sync::atomic::AtomicBool::new(false),
            level,
            k: table.k,
            bins_per_table: table.bins_per_table,
            entry_size: table.bin_size(),
            state_path: paths.state,
            auth_state_path: auth_store.then_some(paths.auth_state),
            state_key,
            drain_per_access,
            save_state,
        })
    }

    fn check_not_poisoned(&self) -> Result<(), String> {
        let poisoned = self
            .poisoned
            .lock()
            .map_err(|_| format!("Cuckoo ORAM {} poison mutex poisoned", self.level))?;
        if let Some(reason) = poisoned.as_ref() {
            Err(format!(
                "Cuckoo ORAM {} table is poisoned: {}",
                self.level, reason
            ))
        } else {
            Ok(())
        }
    }

    fn poison(&self, coarse_reason: &'static str, unsafe_detail: Option<String>) -> String {
        eprintln!(
            "Cuckoo ORAM {} table poisoned: {}",
            self.level, coarse_reason
        );
        if let Some(detail) = unsafe_detail.as_ref() {
            unsafe_debug_log!("Cuckoo ORAM {} poison detail: {}", self.level, detail);
        }
        let retained_reason = unsafe_detail.unwrap_or_else(|| coarse_reason.to_string());
        if let Ok(mut poisoned) = self.poisoned.lock() {
            if poisoned.is_none() {
                *poisoned = Some(retained_reason.clone());
            }
        }
        retained_reason
    }

    fn poison_after_dirty(&self, coarse_reason: &'static str, unsafe_detail: Option<String>) {
        if self.dirty.load(std::sync::atomic::Ordering::SeqCst) {
            self.poison(coarse_reason, unsafe_detail);
        }
    }
}

#[cfg(feature = "cuckoo-oram")]
impl CuckooTableAccess for CuckooOramTable {
    fn bins_per_table(&self) -> usize {
        self.bins_per_table
    }

    fn entry_size(&self) -> usize {
        self.entry_size
    }

    fn group_exists(&self, group_id: usize) -> bool {
        group_id < self.k
    }

    fn append_entry(&self, group_id: usize, idx: usize, dst: &mut Vec<u8>) -> Result<(), String> {
        self.append_entries(group_id, &[idx as u32], false, dst)
    }

    fn append_entries(
        &self,
        group_id: usize,
        indices: &[u32],
        zero_fill_oob: bool,
        dst: &mut Vec<u8>,
    ) -> Result<(), String> {
        self.check_not_poisoned()?;
        if !self.group_exists(group_id) {
            return Err(format!("group_id {} out of range", group_id));
        }
        for &idx in indices {
            let idx_usize = idx as usize;
            if idx_usize >= self.bins_per_table && !zero_fill_oob {
                return Err(format!("index {} out of range", idx));
            }
        }

        let mut reader = self
            .reader
            .lock()
            .map_err(|_| "Cuckoo ORAM reader mutex poisoned".to_string())?;
        for &idx in indices {
            let idx_usize = idx as usize;
            if idx_usize >= self.bins_per_table {
                dst.extend(std::iter::repeat_n(0u8, self.entry_size));
                continue;
            }
            let bin_id = group_id
                .checked_mul(self.bins_per_table)
                .and_then(|base| base.checked_add(idx_usize))
                .ok_or_else(|| "global ORAM bin id overflow".to_string())?;
            self.dirty.store(true, std::sync::atomic::Ordering::SeqCst);
            let got = match reader.read_bin(bin_id, self.drain_per_access) {
                Ok(got) => got,
                Err(_error) => {
                    let msg = self.poison(
                        "Cuckoo ORAM read failed after mutation",
                        unsafe_oram_detail!(
                            "ORAM bin {} read failed after mutation: {}",
                            bin_id,
                            _error
                        ),
                    );
                    return Err(msg);
                }
            };
            if got.payload.len() != self.entry_size {
                let msg = self.poison(
                    "Cuckoo ORAM read returned an invalid payload length",
                    unsafe_oram_detail!(
                        "ORAM bin {} returned {} bytes, expected {}",
                        bin_id,
                        got.payload.len(),
                        self.entry_size
                    ),
                );
                return Err(msg);
            }
            dst.extend_from_slice(&got.payload);
        }
        Ok(())
    }

    fn finish_request(&self) -> Result<(), String> {
        self.check_not_poisoned()?;
        if !self.dirty.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(());
        }
        if !self.save_state {
            self.dirty.store(false, std::sync::atomic::Ordering::SeqCst);
            return Ok(());
        }
        let mut reader = self
            .reader
            .lock()
            .map_err(|_| "Cuckoo ORAM reader mutex poisoned".to_string())?;
        if let Err(_error) = reader.oram_mut().flush() {
            drop(reader);
            let msg = self.poison(
                "Cuckoo ORAM flush failed after mutation",
                unsafe_oram_detail!("ORAM flush failed after mutation: {}", _error),
            );
            return Err(msg);
        }
        let snapshot = reader.oram().snapshot();
        let auth_snapshot = match self.auth_state_path.as_ref() {
            Some(_) => match reader.oram().store_auth_state() {
                Some(state) => Some(state),
                None => {
                    drop(reader);
                    let msg = self.poison(
                        "Cuckoo ORAM auth-store state unavailable after mutation",
                        None,
                    );
                    return Err(msg);
                }
            },
            None => None,
        };
        drop(reader);
        let saved = match self.state_key {
            Some(key) => snapshot
                .save_encrypted_atomic(&self.state_path, key)
                .map_err(|e| e.to_string()),
            None => snapshot
                .save_atomic(&self.state_path)
                .map_err(|e| e.to_string()),
        };
        if let Err(_error) = saved {
            let msg = self.poison(
                "Cuckoo ORAM state save failed after mutation",
                unsafe_oram_detail!("ORAM state save failed after mutation: {}", _error),
            );
            return Err(msg);
        }
        if let (Some(path), Some(auth_snapshot)) =
            (self.auth_state_path.as_ref(), auth_snapshot.as_ref())
        {
            if let Err(_error) = save_circuit_store_auth(auth_snapshot, path, self.state_key) {
                let msg = self.poison(
                    "Cuckoo ORAM auth-state save failed after mutation",
                    unsafe_oram_detail!("ORAM auth state save failed after mutation: {}", _error),
                );
                return Err(msg);
            }
        }
        self.dirty.store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn abort_request(&self, _reason: &str) {
        self.poison_after_dirty(
            "Cuckoo ORAM request aborted after mutation",
            unsafe_oram_detail!("request aborted after ORAM mutation: {}", _reason),
        );
    }
}

#[cfg(feature = "cuckoo-oram")]
struct CuckooOramTables {
    index: CuckooOramTable,
    chunk: CuckooOramTable,
    /// Serializes the complete legacy lookup transaction for this database,
    /// including both table mutations and both controller/auth-state commits.
    request_transaction: std::sync::Mutex<()>,
}

#[cfg(feature = "cuckoo-oram")]
impl CuckooOramTables {
    #[allow(clippy::too_many_arguments)]
    fn open(
        db_dir: &std::path::Path,
        oram_dir: &std::path::Path,
        pack: usize,
        drain_per_access: u64,
        encrypted: bool,
        key_hex: Option<&str>,
        state_key_hex: Option<&str>,
        cache_levels: usize,
        auth_store: bool,
        save_state: bool,
    ) -> Result<Self, String> {
        Ok(Self {
            index: CuckooOramTable::open(
                db_dir,
                oram_dir,
                CuckooLevel::Index,
                pack,
                drain_per_access,
                encrypted,
                key_hex,
                state_key_hex,
                cache_levels,
                auth_store,
                save_state,
            )?,
            chunk: CuckooOramTable::open(
                db_dir,
                oram_dir,
                CuckooLevel::Chunk,
                pack,
                drain_per_access,
                encrypted,
                key_hex,
                state_key_hex,
                cache_levels,
                auth_store,
                save_state,
            )?,
            request_transaction: std::sync::Mutex::new(()),
        })
    }

    fn lookup_batch(
        &self,
        config: CuckooNativeLookupConfig,
        script_hashes: &[[u8; pir_core::params::SCRIPT_HASH_SIZE]],
    ) -> Result<Vec<CuckooNativeLookupResult>, String> {
        let _transaction = self.request_transaction.lock().map_err(|_| {
            "Cuckoo ORAM request transaction mutex poisoned; refusing further mutations".to_string()
        })?;
        self.index.check_not_poisoned()?;
        self.chunk.check_not_poisoned()?;
        cuckoo_native_lookup_batch_from_tables(&self.index, &self.chunk, config, script_hashes)
    }
}

#[cfg(feature = "cuckoo-oram")]
type DirectOramIndexReader = CircuitDirectIndexReader<CuckooOramStore, CuckooOramStore>;

#[cfg(feature = "cuckoo-oram")]
type DirectOramChunkReader = CircuitDirectChunkReader<CuckooOramStore, CuckooOramStore>;

#[cfg(feature = "cuckoo-oram")]
struct DirectOramIndexTable {
    reader: std::sync::Mutex<DirectOramIndexReader>,
    poisoned: std::sync::Mutex<Option<String>>,
    dirty: std::sync::atomic::AtomicBool,
    hash_fns: usize,
    metadata: DirectTableMetadata,
    state_path: PathBuf,
    auth_state_path: Option<PathBuf>,
    state_key: Option<[u8; 32]>,
    drain_per_access: u64,
    save_state: bool,
}

#[cfg(feature = "cuckoo-oram")]
struct DirectOramChunkTable {
    reader: std::sync::Mutex<DirectOramChunkReader>,
    poisoned: std::sync::Mutex<Option<String>>,
    dirty: std::sync::atomic::AtomicBool,
    total_chunks: usize,
    metadata: DirectTableMetadata,
    state_path: PathBuf,
    auth_state_path: Option<PathBuf>,
    state_key: Option<[u8; 32]>,
    drain_per_access: u64,
    save_state: bool,
}

#[cfg(feature = "cuckoo-oram")]
struct DirectOramTables {
    index: DirectOramIndexTable,
    chunk: DirectOramChunkTable,
    access_budget: usize,
    /// Serializes the complete mutating lookup transaction for this database.
    ///
    /// The index and chunk reader mutexes only protect individual in-memory
    /// ORAM operations.  A request also flushes both readers and atomically
    /// replaces their controller/auth-state files, whose save helpers use
    /// fixed `.tmp` paths.  Without this outer per-DB mutex, two requests can
    /// interleave those phases and race the same temp files (or persist an
    /// index state from one request with a chunk state from another).
    request_transaction: std::sync::Mutex<()>,
}

#[cfg(feature = "cuckoo-oram")]
impl DirectOramTables {
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn open(
        oram_dir: &std::path::Path,
        drain_per_access: u64,
        access_budget: usize,
        encrypted: bool,
        key_hex: Option<&str>,
        state_key_hex: Option<&str>,
        cache_levels: usize,
        auth_store: bool,
        save_state: bool,
    ) -> Result<Self, String> {
        Self::open_with_trusted_state(
            oram_dir,
            None,
            drain_per_access,
            access_budget,
            encrypted,
            key_hex,
            state_key_hex,
            cache_levels,
            auth_store,
            save_state,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn open_with_trusted_state(
        oram_dir: &std::path::Path,
        trusted_state_dir: Option<&std::path::Path>,
        drain_per_access: u64,
        access_budget: usize,
        encrypted: bool,
        key_hex: Option<&str>,
        state_key_hex: Option<&str>,
        cache_levels: usize,
        auth_store: bool,
        save_state: bool,
    ) -> Result<Self, String> {
        if access_budget == 0 {
            return Err("--direct-oram-access-budget must be > 0".into());
        }
        Ok(Self {
            index: DirectOramIndexTable::open(
                oram_dir,
                trusted_state_dir,
                drain_per_access,
                encrypted,
                key_hex,
                state_key_hex,
                cache_levels,
                auth_store,
                save_state,
            )?,
            chunk: DirectOramChunkTable::open(
                oram_dir,
                trusted_state_dir,
                drain_per_access,
                encrypted,
                key_hex,
                state_key_hex,
                cache_levels,
                auth_store,
                save_state,
            )?,
            access_budget,
            request_transaction: std::sync::Mutex::new(()),
        })
    }

    fn lookup_batch(
        &self,
        script_hashes: &[[u8; pir_core::params::SCRIPT_HASH_SIZE]],
        slot_present: &[bool],
    ) -> Result<Vec<DirectNativeLookupResult>, String> {
        direct_native_lookup_slots(self, script_hashes, slot_present)
    }

    fn validate_dataset_binding(&self, database: &MappedDatabase) -> Result<(), String> {
        let manifest_root = database.manifest_root.ok_or_else(|| {
            "production Direct ORAM requires an exact verified server DB manifest root".to_owned()
        })?;
        let direct = database
            .manifest
            .as_ref()
            .and_then(|manifest| manifest.direct_oram.as_ref())
            .ok_or_else(|| {
                "production Direct ORAM requires typed [direct_oram] data in MANIFEST.toml"
                    .to_owned()
            })?
            .validate()
            .map_err(|error| error.to_string())?;
        let expected = DirectOramDatasetBindingV1 {
            server_db_manifest_sha256: manifest_root,
            index_sha256: direct.index_sha256,
            index_bytes: direct.index_bytes,
            index_records: direct.index_records,
            chunk_sha256: direct.chunk_sha256,
            chunk_bytes: direct.chunk_bytes,
            chunk_records: direct.chunk_records,
            index_slots_per_bin: direct.index_slots_per_bin,
            index_hash_fns: direct.index_hash_fns,
            index_load_factor_ppb: direct.index_load_factor_ppb,
            index_seed: direct.index_seed,
        };
        expected.validate().map_err(|error| error.to_string())?;
        let index = *self
            .index
            .metadata
            .require_dataset_binding()
            .map_err(|error| error.to_string())?;
        let chunk = *self
            .chunk
            .metadata
            .require_dataset_binding()
            .map_err(|error| error.to_string())?;
        if index != chunk {
            return Err(
                "Direct ORAM INDEX and CHUNK metadata have different dataset bindings".into(),
            );
        }
        if index != expected || index.digest() != expected.digest() {
            return Err(format!(
                "Direct ORAM metadata does not match verified DB manifest binding {}",
                hex::encode(expected.digest())
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "cuckoo-oram")]
impl DirectOramIndexTable {
    #[allow(clippy::too_many_arguments)]
    fn open(
        oram_dir: &std::path::Path,
        trusted_state_dir: Option<&std::path::Path>,
        drain_per_access: u64,
        encrypted: bool,
        key_hex: Option<&str>,
        state_key_hex: Option<&str>,
        cache_levels: usize,
        auth_store: bool,
        save_state: bool,
    ) -> Result<Self, String> {
        let paths = DirectOramPaths::new_with_trusted_state(
            oram_dir,
            trusted_state_dir,
            DirectLevel::Index,
        );
        let metadata = DirectTableMetadata::load(&paths.metadata).map_err(|e| e.to_string())?;
        if metadata.level != DirectLevel::Index {
            return Err(format!(
                "direct index metadata {} has level {}",
                paths.metadata.display(),
                metadata.level
            ));
        }
        let state_key = parse_optional_32_hex(state_key_hex)?;
        let loaded = load_circuit_oram_state(&paths.state, state_key)?;
        let bound_auth = loaded.auth.clone();
        let params = loaded.params.clone();
        let cached_pages = cached_pages_for_oram_levels(&params, cache_levels)?;
        let (meta_store, payload_store) = open_existing_direct_oram_stores(
            &paths,
            DirectLevel::Index,
            &params,
            encrypted,
            key_hex,
            cached_pages,
            auth_store,
            bound_auth.as_ref(),
            state_key,
        )?;
        let oram = CircuitOram::from_state(meta_store, payload_store, loaded)
            .map_err(|e| e.to_string())?;
        let reader =
            CircuitDirectIndexReader::new(metadata.clone(), oram).map_err(|e| e.to_string())?;

        println!(
            "  Direct ORAM index: dir={}, items={}, pack={}, logical_blocks={}, hash_fns={}, cache_levels={}, auth_store={}, save_state={}",
            oram_dir.display(),
            metadata.total_items,
            metadata.items_per_block,
            reader.oram().params().logical_blocks,
            metadata.hash_fns,
            cache_levels,
            auth_store,
            save_state,
        );

        Ok(Self {
            reader: std::sync::Mutex::new(reader),
            poisoned: std::sync::Mutex::new(None),
            dirty: std::sync::atomic::AtomicBool::new(false),
            hash_fns: metadata.hash_fns,
            metadata,
            state_path: paths.state,
            auth_state_path: auth_store.then_some(paths.auth_state),
            state_key,
            drain_per_access,
            save_state,
        })
    }

    fn lookup_many(
        &self,
        script_hashes: &[[u8; pir_core::params::SCRIPT_HASH_SIZE]],
    ) -> Result<Vec<bitcoinpir_oram::DirectIndexLookup>, String> {
        if script_hashes.is_empty() {
            return Ok(Vec::new());
        }
        self.check_not_poisoned()?;
        let mut reader = self
            .reader
            .lock()
            .map_err(|_| "Direct ORAM index reader mutex poisoned".to_string())?;
        self.dirty.store(true, std::sync::atomic::Ordering::SeqCst);
        match reader.lookup_many_batched(script_hashes, self.drain_per_access) {
            Ok(got) => Ok(got.lookups),
            Err(_error) => {
                let msg = self.poison(
                    "Direct ORAM index lookup failed after mutation",
                    unsafe_oram_detail!(
                        "Direct ORAM index batch lookup failed after mutation: {}",
                        _error
                    ),
                );
                Err(msg)
            }
        }
    }

    fn finish_request(&self) -> Result<(), String> {
        finish_direct_oram_request(
            "index",
            &self.reader,
            &self.dirty,
            &self.poisoned,
            &self.state_path,
            self.auth_state_path.as_deref(),
            self.state_key,
            self.save_state,
        )
    }

    fn abort_request(&self, _reason: &str) {
        self.poison_after_dirty(
            "Direct ORAM index request aborted after mutation",
            unsafe_oram_detail!("request aborted after direct index mutation: {}", _reason),
        );
    }

    fn check_not_poisoned(&self) -> Result<(), String> {
        check_direct_poisoned("index", &self.poisoned)
    }

    fn poison(&self, coarse_reason: &'static str, unsafe_detail: Option<String>) -> String {
        poison_direct("index", &self.poisoned, coarse_reason, unsafe_detail)
    }

    fn poison_after_dirty(&self, coarse_reason: &'static str, unsafe_detail: Option<String>) {
        if self.dirty.load(std::sync::atomic::Ordering::SeqCst) {
            self.poison(coarse_reason, unsafe_detail);
        }
    }
}

#[cfg(feature = "cuckoo-oram")]
impl DirectOramChunkTable {
    #[allow(clippy::too_many_arguments)]
    fn open(
        oram_dir: &std::path::Path,
        trusted_state_dir: Option<&std::path::Path>,
        drain_per_access: u64,
        encrypted: bool,
        key_hex: Option<&str>,
        state_key_hex: Option<&str>,
        cache_levels: usize,
        auth_store: bool,
        save_state: bool,
    ) -> Result<Self, String> {
        let paths = DirectOramPaths::new_with_trusted_state(
            oram_dir,
            trusted_state_dir,
            DirectLevel::Chunk,
        );
        let metadata = DirectTableMetadata::load(&paths.metadata).map_err(|e| e.to_string())?;
        if metadata.level != DirectLevel::Chunk {
            return Err(format!(
                "direct chunk metadata {} has level {}",
                paths.metadata.display(),
                metadata.level
            ));
        }
        let state_key = parse_optional_32_hex(state_key_hex)?;
        let loaded = load_circuit_oram_state(&paths.state, state_key)?;
        let bound_auth = loaded.auth.clone();
        let params = loaded.params.clone();
        let cached_pages = cached_pages_for_oram_levels(&params, cache_levels)?;
        let (meta_store, payload_store) = open_existing_direct_oram_stores(
            &paths,
            DirectLevel::Chunk,
            &params,
            encrypted,
            key_hex,
            cached_pages,
            auth_store,
            bound_auth.as_ref(),
            state_key,
        )?;
        let oram = CircuitOram::from_state(meta_store, payload_store, loaded)
            .map_err(|e| e.to_string())?;
        let reader =
            CircuitDirectChunkReader::new(metadata.clone(), oram).map_err(|e| e.to_string())?;

        println!(
            "  Direct ORAM chunk: dir={}, chunks={}, pack={}, logical_blocks={}, cache_levels={}, auth_store={}, save_state={}",
            oram_dir.display(),
            metadata.total_items,
            metadata.items_per_block,
            reader.oram().params().logical_blocks,
            cache_levels,
            auth_store,
            save_state,
        );

        Ok(Self {
            reader: std::sync::Mutex::new(reader),
            poisoned: std::sync::Mutex::new(None),
            dirty: std::sync::atomic::AtomicBool::new(false),
            total_chunks: metadata.total_items,
            metadata,
            state_path: paths.state,
            auth_state_path: auth_store.then_some(paths.auth_state),
            state_key,
            drain_per_access,
            save_state,
        })
    }

    fn read_chunks(&self, chunk_ids: &[usize]) -> Result<Vec<Vec<u8>>, String> {
        if chunk_ids.is_empty() {
            return Ok(Vec::new());
        }
        self.check_not_poisoned()?;
        let mut reader = self
            .reader
            .lock()
            .map_err(|_| "Direct ORAM chunk reader mutex poisoned".to_string())?;
        self.dirty.store(true, std::sync::atomic::Ordering::SeqCst);
        let got = match reader.read_chunks(chunk_ids, self.drain_per_access) {
            Ok(got) => got,
            Err(_error) => {
                let msg = self.poison(
                    "Direct ORAM chunk read failed after mutation",
                    unsafe_oram_detail!(
                        "Direct ORAM chunk batch read failed after mutation: {}",
                        _error
                    ),
                );
                return Err(msg);
            }
        };

        let mut payloads = Vec::with_capacity(got.reads.len());
        for read in got.reads {
            if read.payload.len() != DIRECT_CHUNK_RECORD_SIZE {
                let msg = self.poison(
                    "Direct ORAM chunk read returned an invalid payload length",
                    unsafe_oram_detail!(
                        "Direct ORAM chunk {} returned {} bytes, expected {}",
                        read.chunk_id,
                        read.payload.len(),
                        DIRECT_CHUNK_RECORD_SIZE
                    ),
                );
                return Err(msg);
            }
            payloads.push(read.payload);
        }
        Ok(payloads)
    }

    fn read_dummy_many(&self, count: usize) -> Result<(), String> {
        if count == 0 {
            return Ok(());
        }
        if self.total_chunks == 0 {
            return Err("direct ORAM chunk table is empty; cannot issue dummy read".into());
        }
        self.check_not_poisoned()?;
        let mut reader = self
            .reader
            .lock()
            .map_err(|_| "Direct ORAM chunk reader mutex poisoned".to_string())?;
        self.dirty.store(true, std::sync::atomic::Ordering::SeqCst);
        match reader.read_dummy_many(count, self.drain_per_access) {
            Ok(_) => Ok(()),
            Err(_error) => {
                let msg = self.poison(
                    "Direct ORAM dummy chunk read failed after mutation",
                    unsafe_oram_detail!(
                        "Direct ORAM chunk dummy batch read failed after mutation: {}",
                        _error
                    ),
                );
                Err(msg)
            }
        }
    }

    fn finish_request(&self) -> Result<(), String> {
        finish_direct_oram_request(
            "chunk",
            &self.reader,
            &self.dirty,
            &self.poisoned,
            &self.state_path,
            self.auth_state_path.as_deref(),
            self.state_key,
            self.save_state,
        )
    }

    fn abort_request(&self, _reason: &str) {
        self.poison_after_dirty(
            "Direct ORAM chunk request aborted after mutation",
            unsafe_oram_detail!("request aborted after direct chunk mutation: {}", _reason),
        );
    }

    fn check_not_poisoned(&self) -> Result<(), String> {
        check_direct_poisoned("chunk", &self.poisoned)
    }

    fn poison(&self, coarse_reason: &'static str, unsafe_detail: Option<String>) -> String {
        poison_direct("chunk", &self.poisoned, coarse_reason, unsafe_detail)
    }

    fn poison_after_dirty(&self, coarse_reason: &'static str, unsafe_detail: Option<String>) {
        if self.dirty.load(std::sync::atomic::Ordering::SeqCst) {
            self.poison(coarse_reason, unsafe_detail);
        }
    }
}

#[cfg(feature = "cuckoo-oram")]
trait DirectReaderState {
    fn flush_oram(&mut self) -> Result<(), String>;
    fn snapshot_oram(&self) -> CircuitOramState;
    fn auth_state(&self) -> Option<CircuitStoreAuthState>;
}

#[cfg(feature = "cuckoo-oram")]
impl DirectReaderState for DirectOramIndexReader {
    fn flush_oram(&mut self) -> Result<(), String> {
        self.oram_mut().flush().map_err(|e| e.to_string())
    }

    fn snapshot_oram(&self) -> CircuitOramState {
        self.oram().snapshot()
    }

    fn auth_state(&self) -> Option<CircuitStoreAuthState> {
        self.oram().store_auth_state()
    }
}

#[cfg(feature = "cuckoo-oram")]
impl DirectReaderState for DirectOramChunkReader {
    fn flush_oram(&mut self) -> Result<(), String> {
        self.oram_mut().flush().map_err(|e| e.to_string())
    }

    fn snapshot_oram(&self) -> CircuitOramState {
        self.oram().snapshot()
    }

    fn auth_state(&self) -> Option<CircuitStoreAuthState> {
        self.oram().store_auth_state()
    }
}

#[cfg(feature = "cuckoo-oram")]
#[allow(clippy::too_many_arguments)]
fn finish_direct_oram_request<R: DirectReaderState>(
    label: &str,
    reader: &std::sync::Mutex<R>,
    dirty: &std::sync::atomic::AtomicBool,
    poisoned: &std::sync::Mutex<Option<String>>,
    state_path: &std::path::Path,
    auth_state_path: Option<&std::path::Path>,
    state_key: Option<[u8; 32]>,
    save_state: bool,
) -> Result<(), String> {
    check_direct_poisoned(label, poisoned)?;
    if !dirty.load(std::sync::atomic::Ordering::SeqCst) {
        return Ok(());
    }
    if !save_state {
        dirty.store(false, std::sync::atomic::Ordering::SeqCst);
        return Ok(());
    }

    let mut reader = reader
        .lock()
        .map_err(|_| format!("Direct ORAM {label} reader mutex poisoned"))?;
    if let Err(_error) = reader.flush_oram() {
        drop(reader);
        let msg = poison_direct(
            label,
            poisoned,
            "Direct ORAM flush failed after mutation",
            unsafe_oram_detail!("Direct ORAM {label} flush failed after mutation: {_error}"),
        );
        return Err(msg);
    }
    let snapshot = reader.snapshot_oram();
    let auth_snapshot = match auth_state_path {
        Some(_) => match reader.auth_state() {
            Some(state) => Some(state),
            None => {
                drop(reader);
                let msg = poison_direct(
                    label,
                    poisoned,
                    "Direct ORAM auth-store state unavailable after mutation",
                    unsafe_oram_detail!(
                        "Direct ORAM {label} auth-store state unavailable after mutation"
                    ),
                );
                return Err(msg);
            }
        },
        None => None,
    };
    drop(reader);

    if let Err(_error) = save_circuit_oram_state(&snapshot, state_path, state_key) {
        let msg = poison_direct(
            label,
            poisoned,
            "Direct ORAM state save failed after mutation",
            unsafe_oram_detail!("Direct ORAM {label} state save failed after mutation: {_error}"),
        );
        return Err(msg);
    }
    if let (Some(path), Some(auth_snapshot)) = (auth_state_path, auth_snapshot.as_ref()) {
        if let Err(_error) = save_circuit_store_auth(auth_snapshot, path, state_key) {
            let msg = poison_direct(
                label,
                poisoned,
                "Direct ORAM auth-state save failed after mutation",
                unsafe_oram_detail!(
                    "Direct ORAM {label} auth state save failed after mutation: {_error}"
                ),
            );
            return Err(msg);
        }
    }
    dirty.store(false, std::sync::atomic::Ordering::SeqCst);
    Ok(())
}

#[cfg(feature = "cuckoo-oram")]
fn check_direct_poisoned(
    label: &str,
    poisoned: &std::sync::Mutex<Option<String>>,
) -> Result<(), String> {
    let poisoned = poisoned
        .lock()
        .map_err(|_| format!("Direct ORAM {label} poison mutex poisoned"))?;
    if let Some(reason) = poisoned.as_ref() {
        Err(format!("Direct ORAM {label} table is poisoned: {reason}"))
    } else {
        Ok(())
    }
}

#[cfg(feature = "cuckoo-oram")]
fn poison_direct(
    label: &str,
    poisoned: &std::sync::Mutex<Option<String>>,
    coarse_reason: &'static str,
    unsafe_detail: Option<String>,
) -> String {
    eprintln!("Direct ORAM {label} table poisoned: {coarse_reason}");
    if let Some(detail) = unsafe_detail.as_ref() {
        unsafe_debug_log!("Direct ORAM {label} poison detail: {detail}");
    }
    let retained_reason = unsafe_detail.unwrap_or_else(|| coarse_reason.to_string());
    if let Ok(mut poisoned) = poisoned.lock() {
        if poisoned.is_none() {
            *poisoned = Some(retained_reason.clone());
        }
    }
    retained_reason
}

#[cfg(feature = "cuckoo-oram")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct DirectNativeLookupResult {
    found: bool,
    whale: bool,
    start_chunk_id: Option<u32>,
    num_chunks: u8,
    raw_chunk_data: Vec<u8>,
}

#[cfg(feature = "cuckoo-oram")]
#[cfg(test)]
fn direct_native_lookup_batch(
    tables: &DirectOramTables,
    script_hashes: &[[u8; pir_core::params::SCRIPT_HASH_SIZE]],
) -> Result<Vec<DirectNativeLookupResult>, String> {
    let slot_present = vec![true; script_hashes.len()];
    tables.lookup_batch(script_hashes, &slot_present)
}

#[cfg(feature = "cuckoo-oram")]
fn direct_native_lookup_slots(
    tables: &DirectOramTables,
    script_hashes: &[[u8; pir_core::params::SCRIPT_HASH_SIZE]],
    slot_present: &[bool],
) -> Result<Vec<DirectNativeLookupResult>, String> {
    let _transaction = tables.request_transaction.lock().map_err(|_| {
        "Direct ORAM request transaction mutex poisoned; refusing further mutations".to_string()
    })?;
    if slot_present.len() != script_hashes.len() {
        return Err(format!(
            "direct ORAM slot-present length {} does not match script hash count {}",
            slot_present.len(),
            script_hashes.len(),
        ));
    }
    let index_budget = tables
        .index
        .hash_fns
        .checked_mul(script_hashes.len())
        .ok_or_else(|| "direct ORAM index budget overflow".to_string())?;
    if index_budget > tables.access_budget {
        return Err(format!(
            "direct ORAM access budget {} too small for {} script hashes and {} index reads each",
            tables.access_budget,
            script_hashes.len(),
            tables.index.hash_fns,
        ));
    }
    let chunk_budget = tables.access_budget - index_budget;

    // Fail before mutating either half if a prior request already made the
    // paired database unusable. The transaction lock keeps this preflight
    // valid until both tables have committed or the request fails closed.
    tables.index.check_not_poisoned()?;
    tables.chunk.check_not_poisoned()?;

    let lookups = match tables.index.lookup_many(script_hashes) {
        Ok(batch) => {
            if batch.len() != script_hashes.len() {
                let msg = format!(
                    "direct ORAM index batch returned {} lookup(s), expected {}",
                    batch.len(),
                    script_hashes.len()
                );
                tables.index.abort_request(&msg);
                tables.chunk.abort_request(&msg);
                return Err(msg);
            }
            batch
        }
        Err(e) => {
            tables.index.abort_request(&e);
            tables.chunk.abort_request(&e);
            return Err(e);
        }
    };

    let mut chunk_plan: Vec<(usize, u32)> = Vec::new();
    let mut out = Vec::with_capacity(lookups.len());
    for (lookup, present) in lookups.iter().zip(slot_present) {
        if !*present {
            out.push(DirectNativeLookupResult {
                found: false,
                whale: false,
                start_chunk_id: None,
                num_chunks: 0,
                raw_chunk_data: Vec::new(),
            });
            continue;
        }

        let found = lookup.found;
        let whale = found && lookup.num_chunks == 0;
        if found && lookup.num_chunks > 0 {
            let end = match lookup.start_chunk_id.checked_add(lookup.num_chunks as u32) {
                Some(end) => end,
                None => {
                    let msg = "direct INDEX entry chunk range overflows u32".to_string();
                    tables.index.abort_request(&msg);
                    tables.chunk.abort_request(&msg);
                    return Err(msg);
                }
            };
            for chunk_id in lookup.start_chunk_id..end {
                chunk_plan.push((out.len(), chunk_id));
            }
        }
        out.push(DirectNativeLookupResult {
            found,
            whale,
            start_chunk_id: found.then_some(lookup.start_chunk_id),
            num_chunks: lookup.num_chunks,
            raw_chunk_data: Vec::new(),
        });
    }

    if chunk_plan.len() > chunk_budget {
        if let Err(e) = tables.chunk.read_dummy_many(chunk_budget) {
            tables.index.abort_request(&e);
            tables.chunk.abort_request(&e);
            return Err(e);
        }
        let msg = format!(
            "direct ORAM chunk demand {} exceeds remaining access budget {}",
            chunk_plan.len(),
            chunk_budget,
        );
        if let Err(e) = tables.index.finish_request() {
            tables.chunk.abort_request(&e);
            return Err(e);
        }
        tables.chunk.finish_request()?;
        return Err(msg);
    }

    let real_reads = chunk_plan.len();
    let chunk_ids = chunk_plan
        .iter()
        .map(|(_, chunk_id)| *chunk_id as usize)
        .collect::<Vec<_>>();
    let payloads = match tables.chunk.read_chunks(&chunk_ids) {
        Ok(payloads) => payloads,
        Err(e) => {
            tables.index.abort_request(&e);
            tables.chunk.abort_request(&e);
            return Err(e);
        }
    };
    for ((result_idx, _), payload) in chunk_plan.iter().zip(payloads) {
        out[*result_idx].raw_chunk_data.extend_from_slice(&payload);
    }
    if let Err(e) = tables.chunk.read_dummy_many(chunk_budget - real_reads) {
        tables.index.abort_request(&e);
        tables.chunk.abort_request(&e);
        return Err(e);
    }

    if let Err(e) = tables.index.finish_request() {
        tables.chunk.abort_request(&e);
        return Err(e);
    }
    tables.chunk.finish_request()?;
    Ok(out)
}

#[cfg(feature = "cuckoo-oram")]
fn direct_oram_response_padding_bytes(
    access_budget: usize,
    slots: usize,
    hash_fns: usize,
    actual_chunk_bytes: usize,
) -> Result<usize, String> {
    let index_budget = hash_fns
        .checked_mul(slots)
        .ok_or_else(|| "direct ORAM response index budget overflow".to_string())?;
    if index_budget > access_budget {
        return Err(format!(
            "direct ORAM access budget {} too small for {} slots and {} index reads each",
            access_budget, slots, hash_fns,
        ));
    }
    let max_chunk_bytes = (access_budget - index_budget)
        .checked_mul(DIRECT_CHUNK_RECORD_SIZE)
        .ok_or_else(|| "direct ORAM response padding byte count overflow".to_string())?;
    if actual_chunk_bytes > max_chunk_bytes {
        return Err(format!(
            "direct ORAM response has {} chunk bytes, exceeding public budget {}",
            actual_chunk_bytes, max_chunk_bytes,
        ));
    }
    Ok(max_chunk_bytes - actual_chunk_bytes)
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
struct CuckooNativeLookupConfig {
    index_k: usize,
    chunk_k: usize,
    index_master_seed: u64,
    chunk_master_seed: u64,
    tag_seed: u64,
}

#[allow(dead_code)]
impl CuckooNativeLookupConfig {
    const fn from_db(db: &MappedDatabase) -> Self {
        Self {
            index_k: db.index.params.k,
            chunk_k: db.chunk.params.k,
            index_master_seed: db.index.master_seed,
            chunk_master_seed: db.chunk.master_seed,
            tag_seed: db.index.tag_seed,
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct CuckooBinRead {
    pbc_group: u32,
    bin_index: u32,
    bin_content: Vec<u8>,
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct CuckooNativeLookupResult {
    found: bool,
    whale: bool,
    start_chunk_id: Option<u32>,
    num_chunks: u8,
    raw_chunk_data: Vec<u8>,
    index_bin_reads: Vec<CuckooBinRead>,
    chunk_bin_reads: Vec<CuckooBinRead>,
}

#[allow(dead_code)]
fn cuckoo_native_lookup_batch_mmap(
    db: &MappedDatabase,
    script_hashes: &[[u8; pir_core::params::SCRIPT_HASH_SIZE]],
) -> Result<Vec<CuckooNativeLookupResult>, String> {
    let index_table = MmapCuckooTable::new(&db.index, db.index.params.bin_size());
    let chunk_table = MmapCuckooTable::new(&db.chunk, db.chunk.params.bin_size());
    cuckoo_native_lookup_batch_from_tables(
        &index_table,
        &chunk_table,
        CuckooNativeLookupConfig::from_db(db),
        script_hashes,
    )
}

#[allow(dead_code)]
fn cuckoo_native_lookup_batch_from_tables<I, C>(
    index_table: &I,
    chunk_table: &C,
    config: CuckooNativeLookupConfig,
    script_hashes: &[[u8; pir_core::params::SCRIPT_HASH_SIZE]],
) -> Result<Vec<CuckooNativeLookupResult>, String>
where
    I: CuckooTableAccess,
    C: CuckooTableAccess,
{
    cuckoo_native_lookup_batch_from_tables_with_dummy(
        index_table,
        chunk_table,
        config,
        script_hashes,
        rand::random::<u32>,
    )
}

#[allow(dead_code)]
fn cuckoo_native_lookup_batch_from_tables_with_dummy<I, C>(
    index_table: &I,
    chunk_table: &C,
    config: CuckooNativeLookupConfig,
    script_hashes: &[[u8; pir_core::params::SCRIPT_HASH_SIZE]],
    mut next_dummy_chunk_id: impl FnMut() -> u32,
) -> Result<Vec<CuckooNativeLookupResult>, String>
where
    I: CuckooTableAccess,
    C: CuckooTableAccess,
{
    if config.index_k < pir_core::params::NUM_HASHES
        || config.chunk_k < pir_core::params::NUM_HASHES
    {
        return Err(format!(
            "invalid cuckoo lookup geometry: index_k={}, chunk_k={} (need >= {})",
            config.index_k,
            config.chunk_k,
            pir_core::params::NUM_HASHES,
        ));
    }
    if index_table.bins_per_table() == 0 || chunk_table.bins_per_table() == 0 {
        return Err("cuckoo lookup table has zero bins".into());
    }

    let mut out = Vec::with_capacity(script_hashes.len());
    for script_hash in script_hashes {
        match cuckoo_native_lookup_one(
            index_table,
            chunk_table,
            config,
            script_hash,
            &mut next_dummy_chunk_id,
        ) {
            Ok(item) => out.push(item),
            Err(e) => {
                index_table.abort_request(&e);
                chunk_table.abort_request(&e);
                return Err(e);
            }
        }
    }

    if let Err(e) = index_table.finish_request() {
        chunk_table.abort_request(&e);
        return Err(e);
    }
    chunk_table.finish_request()?;
    Ok(out)
}

fn cuckoo_native_lookup_one<I, C>(
    index_table: &I,
    chunk_table: &C,
    config: CuckooNativeLookupConfig,
    script_hash: &[u8; pir_core::params::SCRIPT_HASH_SIZE],
    next_dummy_chunk_id: &mut impl FnMut() -> u32,
) -> Result<CuckooNativeLookupResult, String>
where
    I: CuckooTableAccess,
    C: CuckooTableAccess,
{
    let index_group = pir_core::hash::derive_groups_3(script_hash, config.index_k)[0];
    let expected_tag = pir_core::hash::compute_tag(config.tag_seed, script_hash);
    let mut index_bin_reads = Vec::with_capacity(INDEX_PARAMS.cuckoo_num_hashes);
    let mut found_entry: Option<(u32, u8)> = None;

    for h in 0..INDEX_PARAMS.cuckoo_num_hashes {
        let key = pir_core::hash::derive_cuckoo_key(config.index_master_seed, index_group, h);
        let bin = pir_core::hash::cuckoo_hash(script_hash, key, index_table.bins_per_table());
        let bin_content = read_cuckoo_bin(index_table, index_group, bin)?;
        if found_entry.is_none() {
            found_entry = find_entry_in_index_bin(&bin_content, expected_tag);
        }
        index_bin_reads.push(CuckooBinRead {
            pbc_group: checked_u32(index_group, "index group")?,
            bin_index: checked_u32(bin, "index bin")?,
            bin_content,
        });
    }

    let (start_chunk_id, num_chunks) = found_entry.unwrap_or((0, 0));
    let found = found_entry.is_some();
    let whale = found && num_chunks == 0;
    let mut real_chunk_ids = Vec::new();
    if found && num_chunks > 0 {
        let end = start_chunk_id
            .checked_add(num_chunks as u32)
            .ok_or_else(|| "INDEX entry chunk range overflows u32".to_string())?;
        real_chunk_ids.extend(start_chunk_id..end);
    }

    // CHUNK round-presence analogue for TEE/ORAM: even not-found and
    // whale results issue one full two-position dummy chunk probe, so the
    // host does not learn found-vs-not-found from zero CHUNK ORAM reads.
    let (probe_ids, dummy_probe) = if real_chunk_ids.is_empty() {
        (vec![next_dummy_chunk_id()], true)
    } else {
        (real_chunk_ids.clone(), false)
    };

    let mut chunk_bin_reads = Vec::with_capacity(probe_ids.len() * CHUNK_PARAMS.cuckoo_num_hashes);
    let mut raw_chunk_data =
        Vec::with_capacity(real_chunk_ids.len() * pir_core::params::CHUNK_SIZE);
    for chunk_id in probe_ids {
        let chunk_group = pir_core::hash::derive_int_groups_3(chunk_id, config.chunk_k)[0];
        let mut recovered: Option<Vec<u8>> = None;
        for h in 0..CHUNK_PARAMS.cuckoo_num_hashes {
            let key = pir_core::hash::derive_cuckoo_key(config.chunk_master_seed, chunk_group, h);
            let bin = pir_core::hash::cuckoo_hash_int(chunk_id, key, chunk_table.bins_per_table());
            let bin_content = read_cuckoo_bin(chunk_table, chunk_group, bin)?;
            if !dummy_probe && recovered.is_none() {
                if let Some(data) = find_chunk_in_bin(&bin_content, chunk_id) {
                    recovered = Some(data.to_vec());
                }
            }
            chunk_bin_reads.push(CuckooBinRead {
                pbc_group: checked_u32(chunk_group, "chunk group")?,
                bin_index: checked_u32(bin, "chunk bin")?,
                bin_content,
            });
        }
        if !dummy_probe {
            let data = recovered
                .ok_or_else(|| format!("chunk_id {} missing from cuckoo table", chunk_id))?;
            raw_chunk_data.extend_from_slice(&data);
        }
    }

    Ok(CuckooNativeLookupResult {
        found,
        whale,
        start_chunk_id: found.then_some(start_chunk_id),
        num_chunks,
        raw_chunk_data,
        index_bin_reads,
        chunk_bin_reads,
    })
}

fn checked_u32(value: usize, label: &str) -> Result<u32, String> {
    u32::try_from(value).map_err(|_| format!("{label} {} does not fit in u32", value))
}

fn read_cuckoo_bin<T: CuckooTableAccess>(
    table: &T,
    group_id: usize,
    bin_index: usize,
) -> Result<Vec<u8>, String> {
    let mut bin = Vec::with_capacity(table.entry_size());
    table.append_entry(group_id, bin_index, &mut bin)?;
    if bin.len() != table.entry_size() {
        return Err(format!(
            "cuckoo bin read returned {} bytes, expected {}",
            bin.len(),
            table.entry_size(),
        ));
    }
    Ok(bin)
}

fn find_entry_in_index_bin(result: &[u8], expected_tag: u64) -> Option<(u32, u8)> {
    for slot in 0..INDEX_PARAMS.slots_per_bin {
        let base = slot * INDEX_PARAMS.slot_size;
        if base + INDEX_PARAMS.slot_size > result.len() {
            break;
        }
        let slot_tag = u64::from_le_bytes(
            result[base..base + pir_core::params::TAG_SIZE]
                .try_into()
                .ok()?,
        );
        if slot_tag == expected_tag {
            let start = base + pir_core::params::TAG_SIZE;
            let start_chunk_id = u32::from_le_bytes(result[start..start + 4].try_into().ok()?);
            let num_chunks = result[start + 4];
            return Some((start_chunk_id, num_chunks));
        }
    }
    None
}

fn find_chunk_in_bin(result: &[u8], chunk_id: u32) -> Option<&[u8]> {
    let target = chunk_id.to_le_bytes();
    for slot in 0..CHUNK_PARAMS.slots_per_bin {
        let base = slot * CHUNK_PARAMS.slot_size;
        if base + CHUNK_PARAMS.slot_size > result.len() {
            break;
        }
        if result[base..base + 4] == target {
            return Some(&result[base + 4..base + CHUNK_PARAMS.slot_size]);
        }
    }
    None
}

#[cfg(feature = "cuckoo-oram")]
struct CuckooOramPaths {
    meta_image: PathBuf,
    payload_image: PathBuf,
    meta_hash_image: PathBuf,
    payload_hash_image: PathBuf,
    state: PathBuf,
    auth_state: PathBuf,
}

#[cfg(feature = "cuckoo-oram")]
impl CuckooOramPaths {
    fn new(oram_dir: &std::path::Path, level: CuckooLevel) -> Self {
        let label = level.label();
        Self {
            meta_image: oram_dir.join(format!("{label}.meta.oram")),
            payload_image: oram_dir.join(format!("{label}.payload.oram")),
            meta_hash_image: oram_dir.join(format!("{label}.meta.hash.oram")),
            payload_hash_image: oram_dir.join(format!("{label}.payload.hash.oram")),
            state: oram_dir.join(format!("{label}.state")),
            auth_state: oram_dir.join(format!("{label}.auth.state")),
        }
    }
}

#[cfg(feature = "cuckoo-oram")]
struct DirectOramPaths {
    meta_image: PathBuf,
    payload_image: PathBuf,
    meta_hash_image: PathBuf,
    payload_hash_image: PathBuf,
    state: PathBuf,
    auth_state: PathBuf,
    metadata: PathBuf,
}

#[cfg(feature = "cuckoo-oram")]
impl DirectOramPaths {
    #[cfg(test)]
    fn new(oram_dir: &std::path::Path, level: DirectLevel) -> Self {
        Self::new_with_trusted_state(oram_dir, None, level)
    }

    fn new_with_trusted_state(
        oram_dir: &std::path::Path,
        trusted_state_dir: Option<&std::path::Path>,
        level: DirectLevel,
    ) -> Self {
        let label = format!("direct-{}", level.label());
        let trusted_state_dir = trusted_state_dir.unwrap_or(oram_dir);
        Self {
            meta_image: oram_dir.join(format!("{label}.meta.oram")),
            payload_image: oram_dir.join(format!("{label}.payload.oram")),
            meta_hash_image: oram_dir.join(format!("{label}.meta.hash.oram")),
            payload_hash_image: oram_dir.join(format!("{label}.payload.hash.oram")),
            state: trusted_state_dir.join(format!("{label}.state")),
            auth_state: trusted_state_dir.join(format!("{label}.auth.state")),
            metadata: trusted_state_dir.join(format!("{label}.metadata")),
        }
    }
}

#[cfg(feature = "cuckoo-oram")]
fn open_existing_oram_store(
    path: &std::path::Path,
    page_count: usize,
    plaintext_page_size: usize,
    encrypted: bool,
    key_hex: Option<&str>,
    key_flag: &str,
    cached_pages: usize,
) -> Result<CuckooRawPageStore, String> {
    let backing_page_size = plaintext_page_size + if encrypted { AEAD_OVERHEAD } else { 0 };
    let expected_len = page_count
        .checked_mul(backing_page_size)
        .ok_or_else(|| "ORAM image length overflow".to_string())?;
    let actual_len = std::fs::metadata(path)
        .map_err(|e| format!("open ORAM image {}: {}", path.display(), e))?
        .len() as usize;
    if actual_len != expected_len {
        return Err(format!(
            "ORAM image {} has {} bytes, expected {}",
            path.display(),
            actual_len,
            expected_len
        ));
    }

    let store: CuckooRawPageStore = if encrypted {
        let key = parse_required_32_hex(key_hex, key_flag)?;
        let file =
            FilePageStore::open(path, page_count, backing_page_size).map_err(|e| e.to_string())?;
        Box::new(AeadPageStore::new(file, key, plaintext_page_size).map_err(|e| e.to_string())?)
    } else {
        Box::new(
            FilePageStore::open(path, page_count, plaintext_page_size)
                .map_err(|e| e.to_string())?,
        )
    };

    if cached_pages == 0 {
        Ok(store)
    } else {
        Ok(Box::new(
            FrontCachedPageStore::new(store, cached_pages).map_err(|e| e.to_string())?,
        ))
    }
}

#[cfg(feature = "cuckoo-oram")]
#[allow(clippy::too_many_arguments)]
fn open_existing_circuit_oram_stores(
    paths: &CuckooOramPaths,
    level: CuckooLevel,
    params: &OramParams,
    encrypted: bool,
    key_hex: Option<&str>,
    cached_pages: usize,
    auth_store: bool,
    bound_auth: Option<&CircuitStoreAuthState>,
    state_key: Option<[u8; 32]>,
) -> Result<(CuckooOramStore, CuckooOramStore), String> {
    if !auth_store {
        let meta_store = open_existing_oram_store(
            &paths.meta_image,
            params.bucket_count(),
            circuit_meta_page_bytes(params.bucket_size),
            encrypted,
            key_hex,
            "--cuckoo-oram-key-hex",
            cached_pages,
        )?;
        let payload_store = open_existing_oram_store(
            &paths.payload_image,
            params.bucket_count(),
            circuit_payload_page_bytes(params.bucket_size, params.block_size),
            encrypted,
            key_hex,
            "--cuckoo-oram-key-hex",
            cached_pages,
        )?;
        return Ok((
            CuckooOramStore::Plain(meta_store),
            CuckooOramStore::Plain(payload_store),
        ));
    }

    let auth = match bound_auth {
        Some(auth) => auth.clone(),
        None => load_circuit_store_auth(&paths.auth_state, state_key)?,
    };
    match auth.layout {
        CircuitStoreAuthLayout::TieredMerkle { meta, payload } => {
            let expected_meta_id = circuit_auth_store_id(level, CircuitAuthStoreKind::Meta);
            let expected_payload_id = circuit_auth_store_id(level, CircuitAuthStoreKind::Payload);
            if meta.store_id != expected_meta_id || payload.store_id != expected_payload_id {
                return Err(format!(
                    "Cuckoo ORAM {} auth sidecar store_id does not match expected level/store domains",
                    level
                ));
            }

            let meta_store = open_existing_oram_store(
                &paths.meta_image,
                params.bucket_count(),
                circuit_meta_page_bytes(params.bucket_size),
                encrypted,
                key_hex,
                "--cuckoo-oram-key-hex",
                cached_pages,
            )?;
            let payload_store = open_existing_oram_store(
                &paths.payload_image,
                params.bucket_count(),
                circuit_payload_page_bytes(params.bucket_size, params.block_size),
                encrypted,
                key_hex,
                "--cuckoo-oram-key-hex",
                cached_pages,
            )?;
            let meta_hash_store = open_existing_hash_store(
                &paths.meta_hash_image,
                &meta,
                encrypted,
                key_hex,
                "--cuckoo-oram-key-hex",
            )?;
            let payload_hash_store = open_existing_hash_store(
                &paths.payload_hash_image,
                &payload,
                encrypted,
                key_hex,
                "--cuckoo-oram-key-hex",
            )?;
            let meta = TieredMerklePageStore::from_trusted_state(meta_store, meta_hash_store, meta)
                .map_err(|e| e.to_string())?;
            let payload = TieredMerklePageStore::from_trusted_state(
                payload_store,
                payload_hash_store,
                payload,
            )
            .map_err(|e| e.to_string())?;
            Ok((
                CuckooOramStore::Sidecar(meta),
                CuckooOramStore::Sidecar(payload),
            ))
        }
        CircuitStoreAuthLayout::EmbeddedTree { meta, payload } => {
            let expected_meta_id = circuit_auth_store_id(level, CircuitAuthStoreKind::Meta);
            let expected_payload_id = circuit_auth_store_id(level, CircuitAuthStoreKind::Payload);
            if meta.store_id != expected_meta_id || payload.store_id != expected_payload_id {
                return Err(format!(
                    "Cuckoo ORAM {} embedded auth store_id does not match expected level/store domains",
                    level
                ));
            }

            let meta_store = open_existing_oram_store(
                &paths.meta_image,
                params.bucket_count(),
                circuit_meta_page_bytes(params.bucket_size) + EMBEDDED_TREE_AUTH_BYTES_PER_PAGE,
                encrypted,
                key_hex,
                "--cuckoo-oram-key-hex",
                cached_pages,
            )?;
            let payload_store = open_existing_oram_store(
                &paths.payload_image,
                params.bucket_count(),
                circuit_payload_page_bytes(params.bucket_size, params.block_size)
                    + EMBEDDED_TREE_AUTH_BYTES_PER_PAGE,
                encrypted,
                key_hex,
                "--cuckoo-oram-key-hex",
                cached_pages,
            )?;
            let meta =
                EmbeddedTreePageStore::from_state(meta_store, meta).map_err(|e| e.to_string())?;
            let payload = EmbeddedTreePageStore::from_state(payload_store, payload)
                .map_err(|e| e.to_string())?;
            Ok((
                CuckooOramStore::Embedded(meta),
                CuckooOramStore::Embedded(payload),
            ))
        }
    }
}

#[cfg(feature = "cuckoo-oram")]
#[allow(clippy::too_many_arguments)]
fn open_existing_direct_oram_stores(
    paths: &DirectOramPaths,
    level: DirectLevel,
    params: &OramParams,
    encrypted: bool,
    key_hex: Option<&str>,
    cached_pages: usize,
    auth_store: bool,
    bound_auth: Option<&CircuitStoreAuthState>,
    state_key: Option<[u8; 32]>,
) -> Result<(CuckooOramStore, CuckooOramStore), String> {
    if !auth_store {
        let meta_store = open_existing_oram_store(
            &paths.meta_image,
            params.bucket_count(),
            circuit_meta_page_bytes(params.bucket_size),
            encrypted,
            key_hex,
            "--direct-oram-key-hex",
            cached_pages,
        )?;
        let payload_store = open_existing_oram_store(
            &paths.payload_image,
            params.bucket_count(),
            circuit_payload_page_bytes(params.bucket_size, params.block_size),
            encrypted,
            key_hex,
            "--direct-oram-key-hex",
            cached_pages,
        )?;
        return Ok((
            CuckooOramStore::Plain(meta_store),
            CuckooOramStore::Plain(payload_store),
        ));
    }

    let auth = match bound_auth {
        Some(auth) => auth.clone(),
        None => load_circuit_store_auth(&paths.auth_state, state_key)?,
    };
    match auth.layout {
        CircuitStoreAuthLayout::TieredMerkle { meta, payload } => {
            let expected_meta_id = direct_auth_store_id(level, CircuitAuthStoreKind::Meta);
            let expected_payload_id = direct_auth_store_id(level, CircuitAuthStoreKind::Payload);
            if meta.store_id != expected_meta_id || payload.store_id != expected_payload_id {
                return Err(format!(
                    "Direct ORAM {} auth sidecar store_id does not match expected level/store domains",
                    level
                ));
            }

            let meta_store = open_existing_oram_store(
                &paths.meta_image,
                params.bucket_count(),
                circuit_meta_page_bytes(params.bucket_size),
                encrypted,
                key_hex,
                "--direct-oram-key-hex",
                cached_pages,
            )?;
            let payload_store = open_existing_oram_store(
                &paths.payload_image,
                params.bucket_count(),
                circuit_payload_page_bytes(params.bucket_size, params.block_size),
                encrypted,
                key_hex,
                "--direct-oram-key-hex",
                cached_pages,
            )?;
            let meta_hash_store = open_existing_hash_store(
                &paths.meta_hash_image,
                &meta,
                encrypted,
                key_hex,
                "--direct-oram-key-hex",
            )?;
            let payload_hash_store = open_existing_hash_store(
                &paths.payload_hash_image,
                &payload,
                encrypted,
                key_hex,
                "--direct-oram-key-hex",
            )?;
            let meta = TieredMerklePageStore::from_trusted_state(meta_store, meta_hash_store, meta)
                .map_err(|e| e.to_string())?;
            let payload = TieredMerklePageStore::from_trusted_state(
                payload_store,
                payload_hash_store,
                payload,
            )
            .map_err(|e| e.to_string())?;
            Ok((
                CuckooOramStore::Sidecar(meta),
                CuckooOramStore::Sidecar(payload),
            ))
        }
        CircuitStoreAuthLayout::EmbeddedTree { meta, payload } => {
            let expected_meta_id = direct_auth_store_id(level, CircuitAuthStoreKind::Meta);
            let expected_payload_id = direct_auth_store_id(level, CircuitAuthStoreKind::Payload);
            if meta.store_id != expected_meta_id || payload.store_id != expected_payload_id {
                return Err(format!(
                    "Direct ORAM {} embedded auth store_id does not match expected level/store domains",
                    level
                ));
            }

            let meta_store = open_existing_oram_store(
                &paths.meta_image,
                params.bucket_count(),
                circuit_meta_page_bytes(params.bucket_size) + EMBEDDED_TREE_AUTH_BYTES_PER_PAGE,
                encrypted,
                key_hex,
                "--direct-oram-key-hex",
                cached_pages,
            )?;
            let payload_store = open_existing_oram_store(
                &paths.payload_image,
                params.bucket_count(),
                circuit_payload_page_bytes(params.bucket_size, params.block_size)
                    + EMBEDDED_TREE_AUTH_BYTES_PER_PAGE,
                encrypted,
                key_hex,
                "--direct-oram-key-hex",
                cached_pages,
            )?;
            let meta =
                EmbeddedTreePageStore::from_state(meta_store, meta).map_err(|e| e.to_string())?;
            let payload = EmbeddedTreePageStore::from_state(payload_store, payload)
                .map_err(|e| e.to_string())?;
            Ok((
                CuckooOramStore::Embedded(meta),
                CuckooOramStore::Embedded(payload),
            ))
        }
    }
}

#[cfg(feature = "cuckoo-oram")]
fn open_existing_hash_store(
    path: &std::path::Path,
    auth: &TieredMerkleState,
    encrypted: bool,
    key_hex: Option<&str>,
    key_flag: &str,
) -> Result<CuckooRawPageStore, String> {
    let hash_pages = tiered_hash_pages(auth.page_count, auth.hash_page_size, auth.trusted_levels)?;
    open_existing_oram_store(
        path,
        hash_pages,
        auth.hash_page_size,
        encrypted,
        key_hex,
        key_flag,
        0,
    )
}

#[cfg(feature = "cuckoo-oram")]
fn tiered_hash_pages(
    data_pages: usize,
    hash_page_size: usize,
    trusted_levels: usize,
) -> Result<usize, String> {
    TieredMerklePageStore::<CuckooRawPageStore, CuckooRawPageStore>::required_hash_pages(
        data_pages,
        hash_page_size,
        trusted_levels,
    )
    .map_err(|e| e.to_string())
}

#[cfg(feature = "cuckoo-oram")]
fn load_circuit_store_auth(
    path: &std::path::Path,
    state_key: Option<[u8; 32]>,
) -> Result<CircuitStoreAuthState, String> {
    match state_key {
        Some(key) => CircuitStoreAuthState::load_encrypted(path, key).map_err(|e| e.to_string()),
        None => CircuitStoreAuthState::load(path).map_err(|e| e.to_string()),
    }
}

#[cfg(feature = "cuckoo-oram")]
fn load_circuit_oram_state(
    path: &std::path::Path,
    state_key: Option<[u8; 32]>,
) -> Result<CircuitOramState, String> {
    match state_key {
        Some(key) => CircuitOramState::load_encrypted(path, key).map_err(|e| e.to_string()),
        None => CircuitOramState::load(path).map_err(|e| e.to_string()),
    }
}

#[cfg(feature = "cuckoo-oram")]
fn save_circuit_oram_state(
    state: &CircuitOramState,
    path: &std::path::Path,
    state_key: Option<[u8; 32]>,
) -> Result<(), String> {
    match state_key {
        Some(key) => state
            .save_encrypted_atomic(path, key)
            .map_err(|e| e.to_string()),
        None => state.save_atomic(path).map_err(|e| e.to_string()),
    }
}

#[cfg(feature = "cuckoo-oram")]
fn save_circuit_store_auth(
    state: &CircuitStoreAuthState,
    path: &std::path::Path,
    state_key: Option<[u8; 32]>,
) -> Result<(), String> {
    match state_key {
        Some(key) => state
            .save_encrypted_atomic(path, key)
            .map_err(|e| e.to_string()),
        None => state.save_atomic(path).map_err(|e| e.to_string()),
    }
}

#[cfg(feature = "cuckoo-oram")]
#[derive(Clone, Copy)]
enum CircuitAuthStoreKind {
    Meta,
    Payload,
}

#[cfg(feature = "cuckoo-oram")]
fn circuit_auth_store_id(level: CuckooLevel, kind: CircuitAuthStoreKind) -> [u8; 16] {
    match (level, kind) {
        (CuckooLevel::Index, CircuitAuthStoreKind::Meta) => *b"bpir-idx-meta-v1",
        (CuckooLevel::Index, CircuitAuthStoreKind::Payload) => *b"bpir-idx-data-v1",
        (CuckooLevel::Chunk, CircuitAuthStoreKind::Meta) => *b"bpir-chk-meta-v1",
        (CuckooLevel::Chunk, CircuitAuthStoreKind::Payload) => *b"bpir-chk-data-v1",
    }
}

#[cfg(feature = "cuckoo-oram")]
fn direct_auth_store_id(level: DirectLevel, kind: CircuitAuthStoreKind) -> [u8; 16] {
    match (level, kind) {
        (DirectLevel::Index, CircuitAuthStoreKind::Meta) => *b"bpir-diridx-meta",
        (DirectLevel::Index, CircuitAuthStoreKind::Payload) => *b"bpir-diridx-data",
        (DirectLevel::Chunk, CircuitAuthStoreKind::Meta) => *b"bpir-dirchk-meta",
        (DirectLevel::Chunk, CircuitAuthStoreKind::Payload) => *b"bpir-dirchk-data",
    }
}

#[cfg(feature = "cuckoo-oram")]
fn cached_pages_for_oram_levels(params: &OramParams, cache_levels: usize) -> Result<usize, String> {
    if cache_levels == 0 {
        return Ok(0);
    }
    if cache_levels > params.height() {
        return Err(format!(
            "--cuckoo-oram-cache-levels {} > ORAM tree height {}",
            cache_levels,
            params.height()
        ));
    }
    Ok((1usize << cache_levels) - 1)
}

#[cfg(feature = "cuckoo-oram")]
fn parse_optional_32_hex(input: Option<&str>) -> Result<Option<[u8; 32]>, String> {
    match input {
        Some(input) => parse_32_hex(input).map(Some),
        None => Ok(None),
    }
}

#[cfg(feature = "cuckoo-oram")]
fn parse_required_32_hex(input: Option<&str>, flag: &str) -> Result<[u8; 32], String> {
    let input = input.ok_or_else(|| format!("{flag} is required"))?;
    parse_32_hex(input)
}

#[cfg(feature = "cuckoo-oram")]
fn parse_32_hex(input: &str) -> Result<[u8; 32], String> {
    if input.len() != 64 {
        return Err(format!(
            "expected 32-byte hex string (64 chars), got {} chars",
            input.len()
        ));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let start = i * 2;
        *byte = u8::from_str_radix(&input[start..start + 2], 16)
            .map_err(|_| format!("invalid hex byte at offset {}", start))?;
    }
    Ok(out)
}

/// Reject a `REQ_HARMONY_HINTS` request whose level or group ids don't
/// exist for this DB *before* any blocking hint work is spawned. Both
/// fields are attacker-controlled. Pre-validating keeps the per-group
/// streaming contract intact for valid requests (every requested group
/// yields exactly one record) while turning invalid ones into a clean
/// `Response::Error` instead of a panic inside the rayon pool (S4) —
/// and caps the request at one hint per group, so a single frame cannot
/// queue unbounded PRP work (S5).
fn validate_harmony_hints_request(
    db: &MappedDatabase,
    level: u8,
    group_ids: &[u8],
) -> Result<(), String> {
    let (sub_table, _, _) =
        harmony_level_table(db, level).ok_or_else(|| format!("invalid hint level {}", level))?;
    let k = sub_table.params.k;
    if group_ids.len() > k {
        return Err(format!(
            "too many group_ids: {} > k {} for level {}",
            group_ids.len(),
            k,
            level
        ));
    }
    for &gid in group_ids {
        if gid as usize >= k {
            return Err(format!(
                "group_id {} out of range for level {} (k = {})",
                gid, level, k
            ));
        }
    }
    Ok(())
}

/// A V2 hint pool is precomputed against exactly one immutable database.
/// Never serve those hints for another catalog entry, even when that db_id is
/// otherwise valid and loaded by the server.
fn validate_harmony_v2_pool_database(bound_db_id: u8, requested_db_id: u8) -> Result<(), String> {
    if requested_db_id != bound_db_id {
        return Err(format!(
            "HarmonyPIR V2 hint pool is bound to db {}, not requested db {}",
            bound_db_id, requested_db_id
        ));
    }
    Ok(())
}

/// Connection-local V2Full reservation. Its durable ready inode remains
/// exclusively locked across credential verification and grant delivery.
/// Rejection, lost grant, timeout, or disconnect before the first main dispatch
/// simply drops the lock and returns the unexposed entry. The first authorized
/// dispatch unlinks+fsyncs it before exposing the PRP key.
struct PendingHarmonyV2FullEntryV1 {
    db_id: u8,
    reservation: hint_pool::PoolReservation,
    /// Online authority concurrency remains charged until the reserved inode
    /// is consumed or restored, not merely until AUTH_GRANTED is delivered.
    _online_authority_permit: Option<OwnedSemaphorePermit>,
    /// Absolute post-grant deadline; Ping and unrelated frames cannot extend
    /// how long scarce capacity remains connection-bound.
    dispatch_deadline: Option<Instant>,
}

fn harmony_v2_full_reservation_db_v1(operation: &OperationStartV1) -> Option<u8> {
    match operation {
        OperationStartV1::HarmonyHint {
            db_id,
            transport: pir_service_protocol::HintTransport::V2Full,
            ..
        } => Some(*db_id),
        _ => None,
    }
}

fn is_exact_pending_v2full_dispatch_v1(
    pending_db_id: u8,
    request_was_encrypted: bool,
    payload: &[u8],
) -> bool {
    request_was_encrypted
        && matches!(
            Request::decode(payload),
            Ok(Request::HarmonyHintsV2(request)) if request.db_id == pending_db_id
        )
}

fn compute_hints_for_group(
    db: &MappedDatabase,
    prp_key: &[u8; 16],
    prp_backend: u8,
    level: u8,
    group_id: u8,
) -> Result<(u8, u32, u32, u32, Vec<u8>), String> {
    // Requests are pre-screened by validate_harmony_hints_request, but
    // stay total here too — an Err drops the group record, never the
    // process.
    let (sub_table, entry_size, k_offset) =
        harmony_level_table(db, level).ok_or_else(|| format!("invalid hint level {}", level))?;

    // S4: group_id comes off the wire — bounds-check before slicing the
    // mmap (group_id ≥ k would read past the table, and panic = 'abort'
    // turns that into a full-process kill). Checked before the PRP work
    // below so a rejected group costs nothing.
    let table_bytes = sub_table
        .try_group_bytes(group_id as usize)
        .ok_or_else(|| format!("group_id {} out of range for level {}", group_id, level))?;

    let real_n = sub_table.bins_per_table;
    let w = entry_size;

    let t_raw = harmonypir::remote::find_best_t(real_n as u32);
    let (padded_n, t_val) = harmonypir::remote::pad_n_for_t(real_n as u32, t_raw)
        .expect("validated non-zero HarmonyPIR table dimensions");
    let pn = padded_n as usize;
    let t = t_val as usize;

    let params = Params::new(pn, w, t).expect("valid params");
    let m = params.m;

    let derived_key = derive_group_key(prp_key, k_offset + group_id as u32);
    let domain = 2 * pn;
    let r = harmonypir::remote::compute_rounds(padded_n);

    use harmonypir::prp::BatchPrp;
    // PRP_ALF (= 2) is not part of the remote-client wire contract.
    // and crates/sdk/client/src/harmony.rs:81 for the rationale (panic on
    // domain<65536 crashed pir-vpsbg in a tight loop).
    let cell_of: Vec<usize> = match prp_backend {
        #[cfg(feature = "fastprp")]
        harmonypir::remote::PRP_FASTPRP => {
            use harmonypir::prp::fast::FastPrpWrapper;
            let prp = FastPrpWrapper::new(&derived_key, domain);
            prp.batch_forward()
        }
        harmonypir::remote::PRP_HMR12 => {
            let prp = HoangPrp::new(domain, r, &derived_key);
            prp.batch_forward()
        }
        #[cfg(not(feature = "fastprp"))]
        harmonypir::remote::PRP_FASTPRP => {
            return Err(
                "FastPRP requested, but runtime was built without the `fastprp` feature".into(),
            );
        }
        other => {
            return Err(format!("unsupported HarmonyPIR PRP backend {}", other));
        }
    };

    let mut hints: Vec<Vec<u8>> = (0..m).map(|_| vec![0u8; w]).collect();
    for k in 0..pn {
        let segment = cell_of[k] / t;
        if k < real_n {
            let entry = &table_bytes[k * entry_size..(k + 1) * entry_size];
            xor_into_hint(&mut hints[segment], entry);
        }
    }

    let flat: Vec<u8> = hints.into_iter().flat_map(|h| h.into_iter()).collect();
    Ok((group_id, padded_n, t_val, m as u32, flat))
}

/// Serve a single HarmonyPIR query against `db`. Free-function seam for
/// `UnifiedServerData::handle_harmony_query` so the S4/S5 guards are
/// unit-testable without booting the multi-GB server state (same
/// pattern as `build_announce_response`).
fn harmony_query_response(db: &MappedDatabase, query: &HarmonyQuery) -> Response {
    let (sub_table, entry_size) = match query.level {
        0 => (&db.index, db.index.params.bin_size()),
        1 => (&db.chunk, db.chunk.params.bin_size()),
        _ => return Response::Error("invalid level".into()),
    };
    let table = MmapCuckooTable::new(sub_table, entry_size);
    harmony_query_response_from_table(&table, query)
}

fn harmony_query_response_from_table<T: CuckooTableAccess>(
    table: &T,
    query: &HarmonyQuery,
) -> Response {
    // S4: group_id comes straight off the wire — bounds-check it before
    // slicing the mmap.
    let group_id = query.group_id as usize;
    if !table.group_exists(group_id) {
        return Response::Error(format!("group_id {} out of range", query.group_id));
    }

    // S5: validate the index count before allocating. A legitimate
    // query carries T − 1 distinct indices in [0, real_n), so more
    // indices than bins is invalid — reject it instead of reserving
    // indices.len() × entry_size bytes for an attacker-sized list.
    if query.indices.len() > table.bins_per_table() {
        return Response::Error(format!(
            "too many indices: {} > bins_per_table {}",
            query.indices.len(),
            table.bins_per_table()
        ));
    }

    let mut data = Vec::with_capacity(query.indices.len() * table.entry_size());
    if let Err(msg) = table.append_entries(group_id, &query.indices, false, &mut data) {
        table.abort_request(&msg);
        return Response::Error(msg);
    }
    if let Err(msg) = table.finish_request() {
        return Response::Error(msg);
    }

    Response::HarmonyQueryResult(HarmonyQueryResult {
        group_id: query.group_id,
        round_id: query.round_id,
        data,
    })
}

/// Serve a HarmonyPIR batch query against `db`. Free-function seam for
/// `UnifiedServerData::handle_harmony_batch_query` (see
/// `harmony_query_response`). Unlike the single-query path this also
/// serves the bucket-Merkle sibling levels, and zero-fills out-of-range
/// indices inside an accepted sub-query (pre-existing wire behavior of
/// this binary) rather than skipping them.
fn harmony_batch_response(db: &MappedDatabase, query: &HarmonyBatchQuery) -> Response {
    let (sub_table, entry_size, _) = match harmony_level_table(db, query.level) {
        Some(t) => t,
        None => return Response::Error(format!("invalid level {}", query.level)),
    };
    let table = MmapCuckooTable::new(sub_table, entry_size);
    harmony_batch_response_from_table(&table, query)
}

fn harmony_batch_response_from_table<T: CuckooTableAccess>(
    table: &T,
    query: &HarmonyBatchQuery,
) -> Response {
    let result_items: Result<Vec<HarmonyBatchResultItem>, String> = query
        .items
        .par_iter()
        .map(|item| {
            // S4: group_id comes straight off the wire — bounds-check
            // it before slicing the mmap.
            let group_id = item.group_id as usize;
            if !table.group_exists(group_id) {
                return Err(format!("group_id {} out of range", item.group_id));
            }
            let sub_results: Result<Vec<Vec<u8>>, String> = item
                .sub_queries
                .iter()
                .map(|indices| {
                    // S5: validate the index count before allocating (see
                    // harmony_query_response).
                    if indices.len() > table.bins_per_table() {
                        return Err(format!(
                            "too many indices: {} > bins_per_table {}",
                            indices.len(),
                            table.bins_per_table()
                        ));
                    }
                    let mut data = Vec::with_capacity(indices.len() * table.entry_size());
                    table.append_entries(group_id, indices, true, &mut data)?;
                    Ok(data)
                })
                .collect();
            Ok(HarmonyBatchResultItem {
                group_id: item.group_id,
                sub_results: sub_results?,
            })
        })
        .collect();

    let result_items = match result_items {
        Ok(items) => items,
        Err(msg) => {
            table.abort_request(&msg);
            return Response::Error(msg);
        }
    };

    if let Err(msg) = table.finish_request() {
        return Response::Error(msg);
    }

    Response::HarmonyBatchResult(HarmonyBatchResult {
        level: query.level,
        round_id: query.round_id,
        sub_results_per_group: query.sub_queries_per_group,
        items: result_items,
    })
}

// ─── Server state ───────────────────────────────────────────────────────────

/// A pool entry that has been "claimed" by one half of a V2-half session
/// and is waiting for the matching second half. Stored under the
/// client-supplied 16-byte `session_token` in
/// [`UnifiedServerData::v2_half_pending`].
///
/// The entry is held shared (`Arc`) because the half-stream serve loop
/// only reads from it; once both halves have been served, the entry is
/// simply dropped (the pool refills lazily).
struct V2HalfPending {
    /// The pool entry feeding both halves of this session. Shared so
    /// the second half's serve loop can read its frames without
    /// having to coordinate with the first half's lifetime.
    entry: Arc<hint_pool::PoolEntry>,
    /// Bitmask of sides already served (bit 0 = side 0 / INDEX,
    /// bit 1 = side 1 / CHUNK). Used to reject duplicate requests
    /// for the same side on the same token, and to determine when
    /// the entry can be evicted.
    sides_served: u8,
    /// When this token was first seen. Used by the cleanup task to
    /// expire lone entries.
    created_at: Instant,
}

/// TTL for a lone V2-half pending entry. Generous enough to absorb a
/// straggling second-half request from a flaky client, short enough
/// that orphaned entries don't deplete the pool. The pool fills at a
/// rate roughly determined by `--pool-size` × the generator's hint
/// computation throughput (a few entries / sec on the i7-8700), so
/// 30 s × that rate ≈ 100 entries is a safe steady-state bound on
/// the pending map.
const V2_HALF_PENDING_TTL_SECS: u64 = 30;
/// A granted V2Full connection must issue its first main request promptly.
/// This absolute cap is independent of Ping/control traffic and is further
/// reduced when the configured connection-idle timeout is shorter.
const V2_FULL_POST_GRANT_RESERVATION_MAX: Duration = Duration::from_secs(30);

struct UnifiedServerData {
    state: ServerState,
    role: ServerRole,
    /// OnionPIR worker channels indexed by db_id.
    /// Each entry is `None` if that DB has no OnionPIR data (or if secondary role).
    /// Length matches `state.databases.len()`.
    onionpir_txs: Vec<Option<Arc<mpsc::Sender<PirCommand>>>>,
    /// Per-DB OnionPIR parameters (None if that DB has no OnionPIR data).
    /// Length matches `state.databases.len()`.
    onionpir_infos: Vec<Option<OnionPirInfo>>,
    /// OnionPIR per-bin Merkle info indexed by db_id.
    /// Each entry is `None` if that DB has no OnionPIR Merkle data (no
    /// `merkle_onion_*` sibling / root / tree-top files on disk).
    /// Length matches `state.databases.len()`.
    onionpir_merkle: Vec<Option<OnionPirMerkleInfo>>,
    /// Admin auth config — `Some` when the operator started the server with
    /// `--admin-pubkey-hex <hex>`. `None` means REQ_ADMIN_* requests fail.
    admin_config: Option<pir_runtime_core::admin::AdminConfig>,
    /// Data root for admin DB uploads: the directory `databases.toml`
    /// lives in (or `data_dir` for legacy invocations). Staging dirs
    /// land at `<data_root>/.staging/<name>/` and ACTIVATE renames into
    /// `<data_root>/<target_path>/`.
    data_root: PathBuf,
    /// Long-lived X25519 keypair for the inner encrypted channel
    /// (cloudflared-blind WSS frames). Generated inside the SEV-SNP
    /// guest at startup; the public half is committed to REPORT_DATA
    /// via `pir_core::attest::build_report_data` (V2). The secret half
    /// is consumed by per-connection handshakes via
    /// `channel_keypair.new_handshake()` in the dispatch loop's
    /// REQ_HANDSHAKE branch.
    channel_keypair: pir_runtime_core::channel::ChannelKeypair,
    /// Pre-computed HarmonyPIR V2 hint pool (None if pool_size=0).
    hint_pool: Option<hint_pool::HintPool>,
    /// Optional legacy ORAM-backed INDEX/CHUNK cuckoo-table access indexed by
    /// db_id. This is kept only as a compatibility fallback for
    /// REQ_ORAM_LOOKUP; HarmonyPIR queries stay mmap-backed so ORAM state
    /// mutation cannot interfere with the ordinary PBC service path.
    #[cfg(feature = "cuckoo-oram")]
    cuckoo_oram: HashMap<u8, CuckooOramTables>,
    /// Optional direct-entry ORAM lookup tables indexed by db_id. These bypass
    /// the PBC-expanded cuckoo DB entirely and are used only by REQ_ORAM_LOOKUP.
    #[cfg(feature = "cuckoo-oram")]
    direct_oram: HashMap<u8, DirectOramTables>,
    /// Pending half-stream pool entries, keyed by client-supplied
    /// session token. The first arriving half of a logical V2-half
    /// session allocates a pool entry into this map; the second
    /// arriving half consumes the matching slot and clears the entry.
    /// Lone entries (one half arrives, the other never does) are
    /// garbage-collected by a background tokio task after 30 s.
    ///
    /// Wrapped in `tokio::sync::Mutex` because both the per-connection
    /// dispatch loop (under `tokio::main`) and the cleanup task touch
    /// it. The map itself is small (typically <16 pending entries at
    /// any moment), so lock contention is negligible vs the network
    /// IO it gates.
    v2_half_pending: Arc<tokio::sync::Mutex<HashMap<[u8; 16], V2HalfPending>>>,
    /// ARC presentation verifier + seen-tag set. Wrapped in a Mutex because
    /// `verify()` mutates the per-context tag set. `None` if ARC is disabled
    /// (server started without --require-arc).
    arc_verifier: Option<std::sync::Mutex<pir_runtime_core::arc_verifier::ArcVerifier>>,
    /// Whether ARC credential presentation is required for PIR queries.
    require_arc: bool,
    /// Cashu blind auth verifier.
    cashu_verifier: Option<std::sync::Mutex<pir_runtime_core::cashu_verifier::CashuVerifier>>,
    /// Whether Cashu BAT presentation is required for PIR queries.
    require_cashu: bool,
    /// Enforce the V1 policy/auth/grant gate for every expensive backend
    /// frame. Legacy 0x08/0x09 success bits never modify this gate.
    service_admission_enforcement: AdmissionEnforcementV1,
    /// Present exactly when strict V1 admission activated a canonical signed
    /// policy and all its advertised method routes at startup.
    service_admission: Option<StrictServiceAdmissionRuntimeV1>,
    /// Whether this server accepts `REQ_HARMONY_HINTS` /
    /// `REQ_HARMONY_HINTS_V2` opcodes (set via `--serve-hints`).
    /// Mirrors `CliArgs::serve_hints`. Gated in the dispatch loop.
    serve_hints: bool,
    /// Whether this server accepts PIR query opcodes (DPF + OnionPIR +
    /// HarmonyPIR query phase). Mirrors `CliArgs::serve_queries`.
    serve_queries: bool,
}

struct StrictServiceAdmissionRuntimeV1 {
    policy: ActivatedServicePolicyV1,
    retained_policies: BTreeMap<[u8; 32], ActivatedRetainedServicePolicyV1>,
    /// Absent only for the exact-digest-pinned, Free-PoW-only measured mode.
    /// Every durable quota, credential, payment, Cashu, ARC, retained-policy,
    /// or shared-issuer route requires this store at startup.
    provider_store: Option<ProviderStore>,
    free_rate_limits: Arc<FreeRateLimitStateV1>,
    free_ip_subject_key: Option<FreeIpSubjectKeyV1>,
    trust_direct_peer_ip: bool,
    bat_keyring: Option<K256CashuMintKeyringV1>,
    experimental_arc_keyring: Option<ArcSecretKeyringV1>,
    cashu_recovery_cipher: Option<ChaCha20Poly1305RecoveryCipherV1>,
    cashu_custody_cipher: Option<ChaCha20Poly1305CustodyCipherV1>,
    cashu_exposure_limits: BTreeMap<([u8; 32], String), CashuCustodyExposureLimitsV1>,
    shared_issuer: Option<SharedIssuerRuntimeConfigV1>,
    http_transport: ProviderAdmissionHttpsTransportV1,
    harmony_attach_registry: Arc<HarmonyAttachRegistryV1>,
    monotonic_origin: Instant,
}

struct SharedIssuerRuntimeConfigV1 {
    authorization: ProviderClearingAuthorizationV1,
    issuer_approval: IssuerClearingApprovalV1,
    operator_verifying_key: VerifyingKey,
    issuer_settlement_verifying_key: VerifyingKey,
    clearing_signing_key: ed25519_dalek::SigningKey,
    minimum_authorization_epoch: u64,
    idempotency_key: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for SharedIssuerRuntimeConfigV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SharedIssuerRuntimeConfigV1")
            .field("provider_id", &self.authorization.claims.provider_id)
            .field("issuer_id", &self.authorization.claims.issuer_id)
            .field(
                "minimum_authorization_epoch",
                &self.minimum_authorization_epoch,
            )
            .field("clearing_signing_key", &"[REDACTED]")
            .field("idempotency_key", &"[REDACTED]")
            .finish()
    }
}

impl SharedIssuerRuntimeConfigV1 {
    fn committer<'a>(
        &self,
        provider_store: &ProviderStore,
        transport: &'a dyn SharedIssuerRedeemTransportV1,
    ) -> Result<SharedIssuerAdmissionCommitterV1<'a>, pir_service_protocol::ServiceProtocolError>
    {
        SharedIssuerAdmissionCommitterV1::new(
            self.authorization.clone(),
            self.issuer_approval.clone(),
            self.operator_verifying_key,
            self.issuer_settlement_verifying_key,
            self.clearing_signing_key.clone(),
            self.minimum_authorization_epoch,
            ProviderRedeemIdempotencyKeyV1::from_bytes(*self.idempotency_key)?,
            provider_store.clone(),
            transport,
        )
    }
}

#[derive(Clone)]
struct ProviderAdmissionHttpsTransportV1 {
    connect_timeout: Duration,
    io_timeout: Duration,
    #[cfg(feature = "standard-cashu-process-e2e")]
    test_only_webpki_root_pem: Option<Arc<[u8]>>,
}

impl core::fmt::Debug for ProviderAdmissionHttpsTransportV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProviderAdmissionHttpsTransportV1")
            .field("connect_timeout", &self.connect_timeout)
            .field("io_timeout", &self.io_timeout)
            .field("test_only_webpki_root_pem", &"[REDACTED]")
            .finish()
    }
}

impl ProviderAdmissionHttpsTransportV1 {
    fn client_for_pins(
        &self,
        leaf_spki_sha256_pins: &[[u8; 32]],
    ) -> Result<StrictHttpsClientV1, String> {
        #[cfg(feature = "standard-cashu-process-e2e")]
        if let Some(root) = self.test_only_webpki_root_pem.as_deref() {
            return StrictHttpsClientV1::new_with_leaf_spki_sha256_pins_and_test_only_webpki_root_pem(
                self.connect_timeout,
                self.io_timeout,
                leaf_spki_sha256_pins,
                root,
            );
        }
        StrictHttpsClientV1::new_with_leaf_spki_sha256_pins(
            self.connect_timeout,
            self.io_timeout,
            leaf_spki_sha256_pins,
        )
    }

    fn validate_trust(
        &self,
        endpoint: &str,
        leaf_spki_sha256_pins: &[[u8; 32]],
    ) -> Result<(), String> {
        StrictHttpsClientV1::validate_base_endpoint(endpoint)?;
        self.client_for_pins(leaf_spki_sha256_pins).map(|_| ())
    }
}

impl CashuMintTransportV1 for ProviderAdmissionHttpsTransportV1 {
    fn post_json(
        &self,
        trust: CashuMintTrustV1<'_>,
        route: CashuMintRouteV1,
        request_json: &[u8],
        max_response_bytes: usize,
    ) -> Result<Vec<u8>, CashuMintTransportFailureV1> {
        self.client_for_pins(trust.leaf_spki_sha256_pins())
            .map_err(|_| {
                CashuMintTransportFailureV1::ambiguous(
                    CashuMintTransportFailureKindV1::Network,
                    None,
                )
            })?
            .post(
                trust.mint_endpoint(),
                route.path(),
                "application/json",
                "application/json",
                request_json,
                max_response_bytes,
            )
            .map_err(|error| match error {
                HttpsPostErrorV1::DefinitelyNotSent => CashuMintTransportFailureV1::ambiguous(
                    CashuMintTransportFailureKindV1::Network,
                    None,
                ),
                HttpsPostErrorV1::OutcomeUnknown => CashuMintTransportFailureV1::ambiguous(
                    CashuMintTransportFailureKindV1::Timeout,
                    None,
                ),
                HttpsPostErrorV1::HttpStatus { status, body } => {
                    CashuMintTransportFailureV1::from_http_status(status, body.as_slice())
                }
                HttpsPostErrorV1::InvalidResponse => CashuMintTransportFailureV1::ambiguous(
                    CashuMintTransportFailureKindV1::InvalidContentType,
                    None,
                ),
            })
    }
}

impl SharedIssuerRedeemTransportV1 for ProviderAdmissionHttpsTransportV1 {
    fn redeem(
        &self,
        envelope: SharedIssuerRedeemEnvelopeV1<'_>,
        max_response_bytes: usize,
    ) -> Result<Vec<u8>, SharedIssuerTransportErrorV1> {
        let mut request = ProviderRedeemEnvelopeV1 {
            request: envelope.request.clone(),
            request_auth: envelope.request_auth.clone(),
            credential_binding: envelope.credential_binding.clone(),
            canonical_credential: envelope.canonical_credential.to_vec(),
        };
        let encoded = request.encode();
        request.canonical_credential.zeroize();
        let body =
            Zeroizing::new(encoded.map_err(|_| SharedIssuerTransportErrorV1::ScopeUnavailable)?);
        self.client_for_pins(envelope.redeem_leaf_spki_sha256_pins)
            .map_err(|_| SharedIssuerTransportErrorV1::ScopeUnavailable)?
            .post_with_error_content_type(
                envelope.redeem_endpoint,
                "/v1/redeems",
                "application/vnd.bitcoinpir.redeem-v1",
                "application/vnd.bitcoinpir.redeem-result-v1",
                "application/problem+json",
                &body,
                max_response_bytes,
            )
            .map_err(|error| match error {
                HttpsPostErrorV1::DefinitelyNotSent => SharedIssuerTransportErrorV1::NotSent {
                    retry_after_ms: 1_000,
                },
                HttpsPostErrorV1::HttpStatus {
                    status: 400 | 409 | 410 | 422,
                    ..
                } => SharedIssuerTransportErrorV1::InvalidOrSpent,
                HttpsPostErrorV1::HttpStatus {
                    status: 401 | 403 | 404,
                    ..
                } => SharedIssuerTransportErrorV1::ScopeUnavailable,
                HttpsPostErrorV1::OutcomeUnknown | HttpsPostErrorV1::HttpStatus { .. } => {
                    SharedIssuerTransportErrorV1::OutcomeUnknown
                }
                HttpsPostErrorV1::InvalidResponse => SharedIssuerTransportErrorV1::InvalidResponse,
            })
    }
}

impl StrictServiceAdmissionRuntimeV1 {
    fn all_policies(&self) -> impl Iterator<Item = &ServicePolicyV1> {
        std::iter::once(self.policy.policy()).chain(
            self.retained_policies
                .values()
                .map(ActivatedRetainedServicePolicyV1::policy),
        )
    }

    fn response_for_policy_request(
        &self,
        request: ServicePolicyRequestV1,
        now_unix: u64,
    ) -> Option<(ServicePolicyResponseV1, [u8; 32])> {
        match request {
            ServicePolicyRequestV1::Current => {
                self.policy.verify_current(now_unix).ok()?;
                Some((self.policy.response(), self.policy.policy_digest()))
            }
            ServicePolicyRequestV1::Retained { policy_digest } => {
                let retained = self.retained_policies.get(&policy_digest)?;
                retained
                    .has_live_redemption(now_unix)
                    .then(|| (retained.response(), policy_digest))
            }
        }
    }

    fn policy_for_digest(&self, policy_digest: &[u8; 32]) -> Option<&ServicePolicyV1> {
        if policy_digest == &self.policy.policy_digest() {
            Some(self.policy.policy())
        } else {
            self.retained_policies
                .get(policy_digest)
                .map(ActivatedRetainedServicePolicyV1::policy)
        }
    }

    fn verified_offer_for_authorization(
        &self,
        policy_digest: &[u8; 32],
        scope_id: &[u8; 32],
        offer_id: u32,
        now_unix: u64,
    ) -> Result<Option<VerifiedServiceOfferV1<'_>>, ServiceProtocolError> {
        if policy_digest == &self.policy.policy_digest() {
            return self
                .policy
                .verified_offer(scope_id, offer_id, now_unix)
                .map(Some);
        }
        let Some(retained) = self.retained_policies.get(policy_digest) else {
            return Ok(None);
        };
        retained
            .verified_offer_for_redemption(scope_id, offer_id, now_unix)
            .map(Some)
    }

    fn is_current_policy_digest(&self, policy_digest: &[u8; 32]) -> bool {
        policy_digest == &self.policy.policy_digest()
    }

    fn supports(&self, route: AdmissionMethodRouteV1) -> bool {
        match route {
            AdmissionMethodRouteV1::FreeOpenBestEffort => self.provider_store.is_some(),
            AdmissionMethodRouteV1::FreeProofOfWork => true,
            AdmissionMethodRouteV1::FreeAnonymousTicketProviderLocal
            | AdmissionMethodRouteV1::Bolt11DirectReceiptProviderLocal => {
                self.provider_store.is_some()
            }
            AdmissionMethodRouteV1::FreeIpRateLimited => {
                self.free_ip_subject_key.is_some()
                    && self.trust_direct_peer_ip
                    && self.free_rate_limits.is_persistent()
            }
            AdmissionMethodRouteV1::BitcoinPirCashuBatProviderLocal => {
                self.provider_store.is_some() && self.bat_keyring.is_some()
            }
            AdmissionMethodRouteV1::ArcProviderLocalExperimental => {
                self.provider_store.is_some() && self.experimental_arc_keyring.is_some()
            }
            AdmissionMethodRouteV1::StandardCashuMintOnline => {
                self.provider_store.is_some()
                    && self.cashu_recovery_cipher.is_some()
                    && self.cashu_custody_cipher.is_some()
                    && !self.cashu_exposure_limits.is_empty()
            }
            AdmissionMethodRouteV1::FreeAnonymousTicketSharedIssuerOnline
            | AdmissionMethodRouteV1::BitcoinPirCashuBatSharedIssuerOnline
            | AdmissionMethodRouteV1::ArcSharedIssuerOnlineExperimental => {
                self.provider_store.is_some() && self.shared_issuer.is_some()
            }
        }
    }
}

impl UnifiedServerData {
    /// Main UTXO database (db_id=0). Always present.
    fn main_db(&self) -> &MappedDatabase {
        self.state.get_db(0).expect("main database must be loaded")
    }

    /// Whether ANY database has OnionPIR data loaded (used as a request guard).
    fn has_any_onionpir(&self) -> bool {
        self.onionpir_txs.iter().any(|t| t.is_some())
    }

    /// Look up the OnionPIR worker channel for a specific db_id.
    /// Returns `None` if the db_id is out of range or if that DB has no OnionPIR data.
    fn onionpir_tx_for(&self, db_id: u8) -> Option<&Arc<mpsc::Sender<PirCommand>>> {
        self.onionpir_txs
            .get(db_id as usize)
            .and_then(|o| o.as_ref())
    }

    /// Look up the OnionPIR per-bin Merkle info for a specific db_id.
    /// Returns `None` if the db_id is out of range or if that DB has no Merkle data.
    fn onionpir_merkle_for(&self, db_id: u8) -> Option<&OnionPirMerkleInfo> {
        self.onionpir_merkle
            .get(db_id as usize)
            .and_then(|o| o.as_ref())
    }

    /// Whether ANY database has OnionPIR Merkle data loaded.
    fn has_any_onionpir_merkle(&self) -> bool {
        self.onionpir_merkle.iter().any(|m| m.is_some())
    }

    #[cfg(feature = "cuckoo-oram")]
    fn has_oram_for(&self, db_id: u8) -> bool {
        // Payment V1 TEE-ORAM scopes are production catalog entries. Legacy
        // Cuckoo ORAM has no exact attested source binding and must never make
        // such a scope locally serviceable.
        self.direct_oram.contains_key(&db_id)
    }

    #[cfg(not(feature = "cuckoo-oram"))]
    fn has_oram_for(&self, _db_id: u8) -> bool {
        false
    }

    fn service_operation_is_local_v1(&self, operation: &OperationStartV1) -> bool {
        let db_id = match operation {
            OperationStartV1::DpfQuery { db_id }
            | OperationStartV1::HarmonyHint { db_id, .. }
            | OperationStartV1::HarmonyQuery { db_id }
            | OperationStartV1::OnionSession { db_id }
            | OperationStartV1::TeeOramQuery { db_id } => *db_id,
        };
        if self.state.get_db(db_id).is_none() {
            return false;
        }
        match operation {
            OperationStartV1::DpfQuery { .. } | OperationStartV1::HarmonyQuery { .. } => {
                self.serve_queries
            }
            OperationStartV1::HarmonyHint { .. } => {
                self.serve_hints
                    && self
                        .hint_pool
                        .as_ref()
                        .is_some_and(|pool| pool.database_id() == db_id)
            }
            OperationStartV1::OnionSession { .. } => {
                self.serve_queries && self.onionpir_tx_for(db_id).is_some()
            }
            OperationStartV1::TeeOramQuery { .. } => self.serve_queries && self.has_oram_for(db_id),
        }
    }

    /// Resolve an untrusted operation from actual loaded state plus the exact
    /// activated provider policy. Multiple matching scopes fail closed: the
    /// wire request is not allowed to choose an operation profile indirectly.
    fn resolve_service_operation_for_policy_v1(
        &self,
        policy: &ServicePolicyV1,
        operation: &OperationStartV1,
    ) -> Option<TrustedCatalogResolutionV1> {
        if !self.service_operation_is_local_v1(operation) {
            return None;
        }
        let db_id = match operation {
            OperationStartV1::DpfQuery { db_id }
            | OperationStartV1::HarmonyHint { db_id, .. }
            | OperationStartV1::HarmonyQuery { db_id }
            | OperationStartV1::OnionSession { db_id }
            | OperationStartV1::TeeOramQuery { db_id } => *db_id,
        };
        let database = self.state.get_db(db_id)?;
        let root = database.manifest_root?;
        let (backend, workload) = operation.required_service();
        let protocol_version = match backend {
            ServiceBackendIdV1::HarmonyPirV2 => 2,
            ServiceBackendIdV1::DpfPirV1
            | ServiceBackendIdV1::OnionPirV1
            | ServiceBackendIdV1::TeeOramV1 => 1,
        };
        let mut matching = policy.scopes.iter().filter(|scope_policy| {
            let scope = &scope_policy.scope;
            scope.provider_id == policy.provider_id
                && scope.backend == backend
                && scope.workload == workload
                && scope.protocol_version == protocol_version
                && scope.dataset == DatasetBindingV1::ManifestRoot { root }
        });
        let scope = &matching.next()?.scope;
        if matching.next().is_some() {
            return None;
        }
        Some(TrustedCatalogResolutionV1::new(
            db_id,
            backend,
            workload,
            protocol_version,
            DatasetBindingV1::ManifestRoot { root },
            scope.operation_profile,
        ))
    }

    fn validate_service_policy_catalog_v1(&self) -> Result<(), String> {
        let Some(runtime) = self.service_admission.as_ref() else {
            return Ok(());
        };
        for policy in runtime.all_policies() {
            let policy_digest = policy
                .policy_digest()
                .map_err(|error| format!("invalid activated service policy: {error}"))?;
            for scope_policy in &policy.scopes {
                let scope = &scope_policy.scope;
                let DatasetBindingV1::ManifestRoot { root } = &scope.dataset else {
                    return Err(format!(
                        "strict service scope {} in policy {} is not bound to an exact database manifest root",
                        hex::encode(scope.scope_id()),
                        hex::encode(policy_digest),
                    ));
                };
                let root = *root;
                let locally_served =
                    self.state
                        .databases
                        .iter()
                        .enumerate()
                        .any(|(index, database)| {
                            let Ok(db_id) = u8::try_from(index) else {
                                return false;
                            };
                            if database.manifest_root != Some(root) {
                                return false;
                            }
                            match (scope.backend, scope.workload) {
                                (
                                    ServiceBackendIdV1::DpfPirV1,
                                    ServiceWorkloadIdV1::DpfEvaluateJobV1,
                                ) => self.service_operation_is_local_v1(
                                    &OperationStartV1::DpfQuery { db_id },
                                ),
                                (
                                    ServiceBackendIdV1::HarmonyPirV2,
                                    ServiceWorkloadIdV1::HarmonyHintBundleV1,
                                ) => self.service_operation_is_local_v1(
                                    &OperationStartV1::HarmonyHint {
                                        db_id,
                                        transport: pir_service_protocol::HintTransport::V2Full,
                                        session_token: None,
                                        primary_side: None,
                                    },
                                ),
                                (
                                    ServiceBackendIdV1::HarmonyPirV2,
                                    ServiceWorkloadIdV1::HarmonyQueryJobV1,
                                ) => self.service_operation_is_local_v1(
                                    &OperationStartV1::HarmonyQuery { db_id },
                                ),
                                (
                                    ServiceBackendIdV1::OnionPirV1,
                                    ServiceWorkloadIdV1::OnionEvaluateJobV1,
                                ) => self.service_operation_is_local_v1(
                                    &OperationStartV1::OnionSession { db_id },
                                ),
                                (
                                    ServiceBackendIdV1::TeeOramV1,
                                    ServiceWorkloadIdV1::TeeOramQueryV1,
                                ) => self.service_operation_is_local_v1(
                                    &OperationStartV1::TeeOramQuery { db_id },
                                ),
                                _ => false,
                            }
                        });
                if !locally_served {
                    return Err(format!(
                        "strict service scope {} in policy {} is not backed by a loaded database and enabled workload",
                        hex::encode(scope.scope_id()),
                        hex::encode(policy_digest),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Derive admission accounting from one decoded DPF backend frame.
///
/// `query.keys` is the public K-padded server workload (normally 75 INDEX or
/// 80 CHUNK groups), not the number of user-selected Bitcoin inputs. Charging
/// it as `logical_inputs` made a signed one-job entitlement reject the first
/// honest request and would couple commercial semantics to privacy padding.
/// One INDEX batch therefore starts one logical padded job; its CHUNK and
/// Merkle follow-ups add no new logical job. All three still charge their
/// exact public work units, bytes, and frame count.
fn dpf_backend_frame_for_service_gate(payload: &[u8]) -> Result<BackendFrameV1, String> {
    let request_bytes = u64::try_from(payload.len())
        .map_err(|_| "request length does not fit admission counter".to_owned())?;
    let request = Request::decode(payload).map_err(|error| error.to_string())?;
    let (kind, query) = match request {
        Request::IndexBatch(query) => (BackendFrameKindV1::DpfIndexBatch, query),
        Request::ChunkBatch(query) => (BackendFrameKindV1::DpfChunkBatch, query),
        Request::BucketMerkleSibBatch(query) => (BackendFrameKindV1::DpfMerkleSiblingBatch, query),
        _ => return Err("runtime decoder returned a mismatched DPF request".into()),
    };
    let logical_inputs = u64::from(matches!(&kind, BackendFrameKindV1::DpfIndexBatch));
    let work_units = query
        .keys
        .iter()
        .map(Vec::len)
        .try_fold(0usize, usize::checked_add)
        .ok_or_else(|| "DPF work-unit count overflow".to_owned())?;
    Ok(BackendFrameV1 {
        kind,
        db_id: query.db_id,
        logical_inputs,
        hint_groups: 0,
        request_bytes,
        work_units: u64::try_from(work_units.max(1))
            .map_err(|_| "work-unit count overflow".to_owned())?,
    })
}

fn backend_frame_for_service_gate(
    server: &UnifiedServerData,
    payload: &[u8],
) -> Result<Option<BackendFrameV1>, String> {
    let Some((&variant, body)) = payload.split_first() else {
        return Ok(None);
    };
    let request_bytes = u64::try_from(payload.len())
        .map_err(|_| "request length does not fit admission counter".to_owned())?;
    let counted = |kind, db_id, logical_inputs: usize, hint_groups: usize, work_units: usize| {
        Ok(Some(BackendFrameV1 {
            kind,
            db_id,
            logical_inputs: u64::try_from(logical_inputs)
                .map_err(|_| "logical input count overflow".to_owned())?,
            hint_groups: u64::try_from(hint_groups)
                .map_err(|_| "hint group count overflow".to_owned())?,
            request_bytes,
            work_units: u64::try_from(work_units.max(1))
                .map_err(|_| "work-unit count overflow".to_owned())?,
        }))
    };

    match variant {
        REQ_INDEX_BATCH | REQ_CHUNK_BATCH | REQ_BUCKET_MERKLE_SIB_BATCH => {
            Ok(Some(dpf_backend_frame_for_service_gate(payload)?))
        }
        REQ_HARMONY_HINTS => {
            let Request::HarmonyHints(request) =
                Request::decode(payload).map_err(|error| error.to_string())?
            else {
                return Err("runtime decoder returned a mismatched Harmony hint request".into());
            };
            let database = server
                .state
                .get_db(request.db_id)
                .ok_or_else(|| format!("unknown db_id {}", request.db_id))?;
            let (sub_table, _, _) = harmony_level_table(database, request.level)
                .ok_or_else(|| format!("invalid Harmony hint level {}", request.level))?;
            let expected_groups = sub_table.params.k;
            if request.group_ids.len() != expected_groups
                || request
                    .group_ids
                    .iter()
                    .copied()
                    .enumerate()
                    .any(|(expected, actual)| usize::from(actual) != expected)
            {
                return Err(format!(
                    "service-gated Harmony sibling hint L{} must contain every group exactly once in canonical order (expected {}, got {})",
                    request.level,
                    expected_groups,
                    request.group_ids.len(),
                ));
            }
            let index_sibling_levels = u8::try_from(database.bucket_merkle_index_siblings.len())
                .map_err(|_| "Harmony INDEX sibling level count overflow".to_owned())?;
            let chunk_sibling_levels = u8::try_from(database.bucket_merkle_chunk_siblings.len())
                .map_err(|_| "Harmony CHUNK sibling level count overflow".to_owned())?;
            counted(
                BackendFrameKindV1::HarmonyHintLegacyV1 {
                    level: request.level,
                    index_sibling_levels,
                    chunk_sibling_levels,
                    expected_groups: u8::try_from(expected_groups)
                        .map_err(|_| "Harmony hint group count overflow".to_owned())?,
                },
                request.db_id,
                0,
                request.group_ids.len(),
                request.group_ids.len(),
            )
        }
        REQ_HARMONY_HINTS_V2 => {
            let Request::HarmonyHintsV2(request) =
                Request::decode(payload).map_err(|error| error.to_string())?
            else {
                return Err("runtime decoder returned a mismatched Harmony V2 request".into());
            };
            let database = server
                .state
                .get_db(request.db_id)
                .ok_or_else(|| format!("unknown db_id {}", request.db_id))?;
            let groups = database
                .index
                .params
                .k
                .checked_add(database.chunk.params.k)
                .ok_or_else(|| "Harmony group count overflow".to_owned())?;
            counted(
                BackendFrameKindV1::HarmonyHintV2Full,
                request.db_id,
                0,
                groups,
                groups,
            )
        }
        REQ_HARMONY_HINTS_V2_HALF => {
            let Request::HarmonyHintsV2Half(request) =
                Request::decode(payload).map_err(|error| error.to_string())?
            else {
                return Err("runtime decoder returned a mismatched Harmony V2-half request".into());
            };
            let database = server
                .state
                .get_db(request.db_id)
                .ok_or_else(|| format!("unknown db_id {}", request.db_id))?;
            let (side, groups) = match request.side {
                0 => (
                    pir_service_protocol::HarmonyHintSideV1::Index,
                    database.index.params.k,
                ),
                1 => (
                    pir_service_protocol::HarmonyHintSideV1::Chunk,
                    database.chunk.params.k,
                ),
                value => return Err(format!("invalid Harmony V2-half side {}", value)),
            };
            counted(
                BackendFrameKindV1::HarmonyHintV2Half {
                    session_token: request.session_token,
                    side,
                },
                request.db_id,
                0,
                groups,
                groups,
            )
        }
        REQ_HARMONY_QUERY => {
            let Request::HarmonyQuery(request) =
                Request::decode(payload).map_err(|error| error.to_string())?
            else {
                return Err("runtime decoder returned a mismatched Harmony query".into());
            };
            counted(
                BackendFrameKindV1::HarmonyLegacySingleQuery,
                request.db_id,
                request.indices.len(),
                0,
                request.indices.len(),
            )
        }
        REQ_HARMONY_BATCH_QUERY => {
            let Request::HarmonyBatchQuery(request) =
                Request::decode(payload).map_err(|error| error.to_string())?
            else {
                return Err("runtime decoder returned a mismatched Harmony batch query".into());
            };
            let database = server
                .state
                .get_db(request.db_id)
                .ok_or_else(|| format!("unknown db_id {}", request.db_id))?;
            let (sub_table, _, _) = harmony_level_table(database, request.level)
                .ok_or_else(|| format!("invalid Harmony batch level {}", request.level))?;
            if request.items.len() != sub_table.params.k
                || request.sub_queries_per_group != 1
                || request.items.iter().enumerate().any(|(expected, item)| {
                    usize::from(item.group_id) != expected || item.sub_queries.len() != 1
                })
            {
                return Err(format!(
                    "service-gated Harmony batch L{} must be K-padded with one sub-query per canonical group",
                    request.level
                ));
            }
            let work_units = request
                .items
                .iter()
                .flat_map(|item| item.sub_queries.iter())
                .map(Vec::len)
                .try_fold(0usize, usize::checked_add)
                .ok_or_else(|| "Harmony work-unit count overflow".to_owned())?;
            let index_sibling_levels = u8::try_from(database.bucket_merkle_index_siblings.len())
                .map_err(|_| "Harmony INDEX sibling level count overflow".to_owned())?;
            let chunk_sibling_levels = u8::try_from(database.bucket_merkle_chunk_siblings.len())
                .map_err(|_| "Harmony CHUNK sibling level count overflow".to_owned())?;
            let logical_inputs = usize::from(request.level == 0 && request.round_id % 2 == 0);
            counted(
                BackendFrameKindV1::HarmonyBatchQuery {
                    level: request.level,
                    round_id: request.round_id,
                    index_sibling_levels,
                    chunk_sibling_levels,
                },
                request.db_id,
                logical_inputs,
                0,
                work_units,
            )
        }
        REQ_ORAM_LOOKUP => {
            let Request::OramLookup(request) =
                Request::decode(payload).map_err(|error| error.to_string())?
            else {
                return Err("runtime decoder returned a mismatched ORAM query".into());
            };
            counted(
                BackendFrameKindV1::TeeOramQuery,
                request.db_id,
                request.script_hashes.len(),
                0,
                request.script_hashes.len(),
            )
        }
        REQ_REGISTER_KEYS => {
            let request = RegisterKeysMsg::decode(body).map_err(|error| error.to_string())?;
            counted(
                BackendFrameKindV1::OnionRegisterKeys,
                request.db_id,
                0,
                0,
                1,
            )
        }
        REQ_ONIONPIR_INDEX_QUERY
        | REQ_ONIONPIR_CHUNK_QUERY
        | REQ_ONIONPIR_MERKLE_INDEX_SIBLING
        | REQ_ONIONPIR_MERKLE_DATA_SIBLING => {
            let request = OnionPirBatchQuery::decode(body).map_err(|error| error.to_string())?;
            let (kind, expected_queries) = match variant {
                REQ_ONIONPIR_INDEX_QUERY => {
                    let info = server
                        .onionpir_infos
                        .get(request.db_id as usize)
                        .and_then(Option::as_ref)
                        .ok_or_else(|| {
                            format!("OnionPIR not available for db_id={}", request.db_id)
                        })?;
                    (
                        BackendFrameKindV1::OnionIndexQuery {
                            round_id: request.round_id,
                        },
                        usize::from(info.index_k)
                            .checked_mul(pir_core::params::INDEX_CUCKOO_NUM_HASHES)
                            .ok_or_else(|| "OnionPIR INDEX query count overflow".to_owned())?,
                    )
                }
                REQ_ONIONPIR_CHUNK_QUERY => {
                    let info = server
                        .onionpir_infos
                        .get(request.db_id as usize)
                        .and_then(Option::as_ref)
                        .ok_or_else(|| {
                            format!("OnionPIR not available for db_id={}", request.db_id)
                        })?;
                    (
                        BackendFrameKindV1::OnionChunkQuery {
                            round_id: request.round_id,
                        },
                        usize::from(info.chunk_k),
                    )
                }
                REQ_ONIONPIR_MERKLE_INDEX_SIBLING => {
                    let info = server.onionpir_merkle_for(request.db_id).ok_or_else(|| {
                        format!("OnionPIR Merkle not available for db_id={}", request.db_id)
                    })?;
                    (
                        BackendFrameKindV1::OnionMerkleIndexSibling {
                            round_id: request.round_id,
                        },
                        info.index_k,
                    )
                }
                REQ_ONIONPIR_MERKLE_DATA_SIBLING => {
                    let info = server.onionpir_merkle_for(request.db_id).ok_or_else(|| {
                        format!("OnionPIR Merkle not available for db_id={}", request.db_id)
                    })?;
                    (
                        BackendFrameKindV1::OnionMerkleDataSibling {
                            round_id: request.round_id,
                        },
                        info.data_k,
                    )
                }
                _ => unreachable!("matched exact OnionPIR opcode set"),
            };
            if request.queries.len() != expected_queries {
                return Err(format!(
                    "service-gated OnionPIR opcode 0x{variant:02x} requires {expected_queries} padded ciphertexts, got {}",
                    request.queries.len()
                ));
            }
            let logical_inputs = usize::from(variant == REQ_ONIONPIR_INDEX_QUERY);
            counted(
                kind,
                request.db_id,
                logical_inputs,
                0,
                request.queries.len(),
            )
        }
        _ => Ok(None),
    }
}

fn service_gate_is_backend_opcode_v1(variant: u8) -> bool {
    matches!(
        variant,
        REQ_INDEX_BATCH
            | REQ_CHUNK_BATCH
            | REQ_BUCKET_MERKLE_SIB_BATCH
            | REQ_HARMONY_HINTS
            | REQ_HARMONY_HINTS_V2
            | REQ_HARMONY_HINTS_V2_HALF
            | REQ_HARMONY_QUERY
            | REQ_HARMONY_BATCH_QUERY
            | REQ_ORAM_LOOKUP
            | REQ_REGISTER_KEYS
            | REQ_ONIONPIR_INDEX_QUERY
            | REQ_ONIONPIR_CHUNK_QUERY
            | REQ_ONIONPIR_MERKLE_INDEX_SIBLING
            | REQ_ONIONPIR_MERKLE_DATA_SIBLING
    )
}

fn service_gate_allows_ungranted_opcode(variant: u8) -> bool {
    matches!(
        variant,
        REQ_PING
            | REQ_GET_INFO
            | 0x03 // REQ_GET_INFO_JSON
            | REQ_GET_DB_CATALOG
            | REQ_GET_DB_PROOF
            | REQ_GET_DB_PROOF_V2
            | REQ_ATTEST
            | REQ_ANNOUNCE
            | REQ_HANDSHAKE
            | REQ_SERVICE_POLICY_V1
            | REQ_AUTH_BEGIN_V1
            | REQ_POW_CHALLENGE_V1
            | REQ_HARMONY_ATTACH_V1
            | REQ_ADMIN_AUTH_CHALLENGE
            | REQ_ADMIN_AUTH_RESPONSE
            | REQ_ADMIN_DB_UPLOAD_BEGIN
            | REQ_ADMIN_DB_UPLOAD_CHUNK
            | REQ_ADMIN_DB_UPLOAD_FINALIZE
            | REQ_ADMIN_DB_ACTIVATE
            | REQ_BUCKET_MERKLE_TREE_TOPS
            | REQ_HARMONY_GET_INFO
            | REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP
            | REQ_ONIONPIR_MERKLE_DATA_TREE_TOP
    )
}

/// Per-group OnionPIR Merkle metadata for one DB (Phase 3 per-group
/// redesign). The 155-tree tree-top blob `merkle_onion_tree_tops.bin`
/// is served whole to clients on either TREE_TOP request; the per-group
/// sibling FHE-PIR DBs (one OnionPIR `Server` per group) live in the
/// OnionPIR worker thread.
#[derive(Clone)]
struct OnionPirMerkleInfo {
    arity: usize,
    /// SHA256 of the concatenated 155 per-group roots — the §2f trust anchor.
    super_root_hex: String,
    /// `merkle_onion_tree_tops.bin` verbatim (75 INDEX + 80 DATA per-group
    /// tree-tops); served whole on either INDEX/DATA TREE_TOP request.
    tree_tops: Vec<u8>,
    /// Number of INDEX per-group sibling trees (= INDEX PBC group count).
    index_k: usize,
    /// Plaintexts in each INDEX per-group sibling DB.
    index_num_pt: usize,
    /// Number of DATA per-group sibling trees (= CHUNK PBC group count).
    data_k: usize,
    /// Plaintexts in each DATA per-group sibling DB.
    data_num_pt: usize,
}

#[derive(Clone)]
struct OnionPirInfo {
    total_packed_entries: u32,
    index_bins_per_table: u32,
    chunk_bins_per_table: u32,
    index_k: u8,
    chunk_k: u8,
    tag_seed: u64,
    index_slots_per_bin: u16,
    index_slot_size: u8,
    /// INDEX/CHUNK cuckoo master seeds (chain-derived for v2 DBs),
    /// delivered to the standalone OnionPIR TS client so it computes
    /// placements with the server's seed instead of a hardcoded const.
    index_master_seed: u64,
    chunk_master_seed: u64,
}

impl UnifiedServerData {
    /// Append a single `OnionPirMerkleInfo` object to `json` preceded by
    /// `prefix`. Per-group schema (Phase 3): `arity`, `super_root`, the
    /// shared 155-tree tree-top blob's hash/size, and per-kind `{k,num_pt}`
    /// for the INDEX and DATA per-group sibling DBs.
    fn append_onionpir_merkle_json(json: &mut String, prefix: &str, om: &OnionPirMerkleInfo) {
        json.push_str(prefix);
        let top_hash = pir_core::merkle::sha256(&om.tree_tops);
        json.push_str(&format!(
            r#"{{"arity":{},"super_root":"{}","tree_tops_hash":"{}","tree_tops_size":{}"#,
            om.arity,
            om.super_root_hex,
            top_hash
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),
            om.tree_tops.len(),
        ));
        json.push_str(&format!(
            r#","index":{{"k":{},"num_pt":{}}},"data":{{"k":{},"num_pt":{}}}}}"#,
            om.index_k, om.index_num_pt, om.data_k, om.data_num_pt,
        ));
    }

    fn server_info(&self) -> ServerInfo {
        ServerInfo {
            index_bins_per_table: self.main_db().index.bins_per_table as u32,
            chunk_bins_per_table: self.main_db().chunk.bins_per_table as u32,
            index_k: self.main_db().index.params.k as u8,
            chunk_k: self.main_db().chunk.params.k as u8,
            tag_seed: self.main_db().index.tag_seed,
            index_master_seed: self.main_db().index.master_seed,
            chunk_master_seed: self.main_db().chunk.master_seed,
            anchor: self.main_db().index.anchor,
        }
    }

    /// Build a JSON server info string covering all protocols.
    fn server_info_json(&self) -> String {
        let mut json = format!(
            r#"{{"index_bins_per_table":{},"chunk_bins_per_table":{},"index_k":{},"chunk_k":{},"tag_seed":"0x{:016x}","index_dpf_n":{},"chunk_dpf_n":{},"index_slots_per_bin":{},"index_slot_size":{},"chunk_slots_per_bin":{},"chunk_slot_size":{},"role":"{}""#,
            self.main_db().index.bins_per_table,
            self.main_db().chunk.bins_per_table,
            self.main_db().index.params.k,
            self.main_db().chunk.params.k,
            self.main_db().index.tag_seed,
            params::compute_dpf_n(self.main_db().index.bins_per_table),
            params::compute_dpf_n(self.main_db().chunk.bins_per_table),
            self.main_db().index.params.slots_per_bin,
            self.main_db().index.params.slot_size,
            self.main_db().chunk.params.slots_per_bin,
            self.main_db().chunk.params.slot_size,
            match self.role {
                ServerRole::Primary => "primary",
                ServerRole::Secondary => "secondary",
            },
        );

        if let Some(Some(ref opi)) = self.onionpir_infos.first() {
            json.push_str(&format!(
                r#","onionpir":{{"total_packed_entries":{},"index_bins_per_table":{},"chunk_bins_per_table":{},"tag_seed":"0x{:016x}","index_master_seed":"0x{:016x}","chunk_master_seed":"0x{:016x}","index_k":{},"chunk_k":{},"index_slots_per_bin":{},"index_slot_size":{},"chunk_slots_per_bin":1,"chunk_slot_size":{}}}"#,
                opi.total_packed_entries, opi.index_bins_per_table, opi.chunk_bins_per_table,
                opi.tag_seed, opi.index_master_seed, opi.chunk_master_seed,
                opi.index_k, opi.chunk_k,
                opi.index_slots_per_bin, opi.index_slot_size,
                3840, // PACKED_ENTRY_SIZE = 3.75KB fixed bin size for OnionPIR chunks
            ));
        }

        // Top-level `onionpir_merkle` reflects the main DB (db_id=0) for
        // backward compatibility with clients that only look at the main
        // entry. Per-DB Merkle is also emitted under `databases[]` below.
        if let Some(om) = self.onionpir_merkle_for(0) {
            Self::append_onionpir_merkle_json(&mut json, ",\"onionpir_merkle\":", om);
        }

        // Legacy global N-ary tree Merkle ("merkle":{…}) removed — the
        // per-bucket bin Merkle below ("merkle_bucket":{…}) is the active
        // scheme. No DB carries N-ary Merkle data anymore.

        // Per-bucket bin Merkle info
        if self.main_db().has_bucket_merkle() {
            json.push_str(r#","merkle_bucket":{"arity":8,"#);

            // INDEX sibling levels
            json.push_str(r#""index_levels":["#);
            for (i, sib) in self
                .main_db()
                .bucket_merkle_index_siblings
                .iter()
                .enumerate()
            {
                if i > 0 {
                    json.push(',');
                }
                json.push_str(&format!(
                    r#"{{"dpf_n":{},"bins_per_table":{}}}"#,
                    params::compute_dpf_n(sib.bins_per_table),
                    sib.bins_per_table,
                ));
            }
            json.push_str("],");

            // CHUNK sibling levels
            json.push_str(r#""chunk_levels":["#);
            for (i, sib) in self
                .main_db()
                .bucket_merkle_chunk_siblings
                .iter()
                .enumerate()
            {
                if i > 0 {
                    json.push(',');
                }
                json.push_str(&format!(
                    r#"{{"dpf_n":{},"bins_per_table":{}}}"#,
                    params::compute_dpf_n(sib.bins_per_table),
                    sib.bins_per_table,
                ));
            }
            json.push_str("],");

            // Per-group roots as hex arrays
            if let Some(ref roots_data) = self.main_db().bucket_merkle_roots {
                let index_k = self.main_db().index.params.k;
                let chunk_k = self.main_db().chunk.params.k;

                json.push_str(r#""index_roots":["#);
                for g in 0..index_k {
                    if g > 0 {
                        json.push(',');
                    }
                    let root = &roots_data[g * 32..(g + 1) * 32];
                    json.push('"');
                    for b in root {
                        json.push_str(&format!("{:02x}", b));
                    }
                    json.push('"');
                }
                json.push_str("],");

                json.push_str(r#""chunk_roots":["#);
                for g in 0..chunk_k {
                    if g > 0 {
                        json.push(',');
                    }
                    let root = &roots_data[(index_k + g) * 32..(index_k + g + 1) * 32];
                    json.push('"');
                    for b in root {
                        json.push_str(&format!("{:02x}", b));
                    }
                    json.push('"');
                }
                json.push_str("],");
            }

            // Super-root
            if let Some(ref sr) = self.main_db().bucket_merkle_root {
                json.push_str(&format!(
                    r#""super_root":"{}","#,
                    sr.iter().map(|b| format!("{:02x}", b)).collect::<String>()
                ));
            }

            // Tree-tops hash and size
            if let Some(ref tops) = self.main_db().bucket_merkle_tree_tops {
                let tops_hash = pir_core::merkle::sha256(tops);
                json.push_str(&format!(
                    r#""tree_tops_hash":"{}","tree_tops_size":{}"#,
                    tops_hash
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<String>(),
                    tops.len()
                ));
            }

            json.push('}');
        }

        // Per-database info array (Merkle availability + params for each DB)
        if self.state.databases.len() > 1
            || self.state.databases.iter().any(|db| db.has_bucket_merkle())
            || self.has_any_onionpir_merkle()
        {
            json.push_str(r#","databases":["#);
            for (i, db) in self.state.databases.iter().enumerate() {
                if i > 0 {
                    json.push(',');
                }
                let has_onionpir_merkle = self.onionpir_merkle_for(i as u8).is_some();
                let has_onionpir = self
                    .onionpir_txs
                    .get(i)
                    .map(|o| o.is_some())
                    .unwrap_or(false);
                json.push_str(&format!(
                    r#"{{"db_id":{},"has_bucket_merkle":{},"has_onionpir":{},"has_onionpir_merkle":{}"#,
                    i, db.has_bucket_merkle(), has_onionpir, has_onionpir_merkle
                ));

                // Per-DB OnionPIR parameters (so the web client can switch BFV
                // params when querying a delta with different bins_per_table).
                if let Some(Some(ref opi)) = self.onionpir_infos.get(i) {
                    json.push_str(&format!(
                        r#","onionpir":{{"total_packed_entries":{},"index_bins_per_table":{},"chunk_bins_per_table":{},"tag_seed":"0x{:016x}","index_k":{},"chunk_k":{},"index_slots_per_bin":{},"index_slot_size":{},"chunk_slots_per_bin":1,"chunk_slot_size":{}}}"#,
                        opi.total_packed_entries, opi.index_bins_per_table, opi.chunk_bins_per_table,
                        opi.tag_seed, opi.index_k, opi.chunk_k,
                        opi.index_slots_per_bin, opi.index_slot_size,
                        3840, // PACKED_ENTRY_SIZE
                    ));
                }

                if db.has_bucket_merkle() {
                    json.push_str(r#","merkle_bucket":{"arity":8,"#);

                    // INDEX sibling levels
                    json.push_str(r#""index_levels":["#);
                    for (li, sib) in db.bucket_merkle_index_siblings.iter().enumerate() {
                        if li > 0 {
                            json.push(',');
                        }
                        json.push_str(&format!(
                            r#"{{"dpf_n":{},"bins_per_table":{}}}"#,
                            params::compute_dpf_n(sib.bins_per_table),
                            sib.bins_per_table,
                        ));
                    }
                    json.push_str("],");

                    // CHUNK sibling levels
                    json.push_str(r#""chunk_levels":["#);
                    for (li, sib) in db.bucket_merkle_chunk_siblings.iter().enumerate() {
                        if li > 0 {
                            json.push(',');
                        }
                        json.push_str(&format!(
                            r#"{{"dpf_n":{},"bins_per_table":{}}}"#,
                            params::compute_dpf_n(sib.bins_per_table),
                            sib.bins_per_table,
                        ));
                    }
                    json.push_str("],");

                    // Per-group roots
                    if let Some(ref roots_data) = db.bucket_merkle_roots {
                        let index_k = db.index.params.k;
                        let chunk_k = db.chunk.params.k;

                        json.push_str(r#""index_roots":["#);
                        for g in 0..index_k {
                            if g > 0 {
                                json.push(',');
                            }
                            let root = &roots_data[g * 32..(g + 1) * 32];
                            json.push('"');
                            for b in root {
                                json.push_str(&format!("{:02x}", b));
                            }
                            json.push('"');
                        }
                        json.push_str("],");

                        json.push_str(r#""chunk_roots":["#);
                        for g in 0..chunk_k {
                            if g > 0 {
                                json.push(',');
                            }
                            let root = &roots_data[(index_k + g) * 32..(index_k + g + 1) * 32];
                            json.push('"');
                            for b in root {
                                json.push_str(&format!("{:02x}", b));
                            }
                            json.push('"');
                        }
                        json.push_str("],");
                    }

                    if let Some(ref sr) = db.bucket_merkle_root {
                        json.push_str(&format!(
                            r#""super_root":"{}","#,
                            sr.iter().map(|b| format!("{:02x}", b)).collect::<String>()
                        ));
                    }

                    if let Some(ref tops) = db.bucket_merkle_tree_tops {
                        let tops_hash = pir_core::merkle::sha256(tops);
                        json.push_str(&format!(
                            r#""tree_tops_hash":"{}","tree_tops_size":{}"#,
                            tops_hash
                                .iter()
                                .map(|b| format!("{:02x}", b))
                                .collect::<String>(),
                            tops.len()
                        ));
                    }

                    json.push('}'); // close merkle_bucket
                }

                // Per-DB OnionPIR per-bin Merkle, when this DB has it
                if let Some(om) = self.onionpir_merkle_for(i as u8) {
                    Self::append_onionpir_merkle_json(&mut json, ",\"onionpir_merkle\":", om);
                }

                json.push('}'); // close database entry
            }
            json.push(']'); // close databases array
        }

        json.push('}');
        json
    }

    /// Encode a JSON info response as a length-prefixed binary message.
    fn encode_info_json_response(&self, variant: u8) -> Vec<u8> {
        let json = self.server_info_json();
        let json_bytes = json.as_bytes();
        // Wire: [4B length LE][1B variant][json bytes]
        let payload_len = 1 + json_bytes.len();
        let mut msg = Vec::with_capacity(4 + payload_len);
        msg.extend_from_slice(&(payload_len as u32).to_le_bytes());
        msg.push(variant);
        msg.extend_from_slice(json_bytes);
        msg
    }

    fn build_catalog(&self) -> DatabaseCatalog {
        DatabaseCatalog {
            databases: self
                .state
                .databases
                .iter()
                .enumerate()
                .map(|(i, db)| DatabaseCatalogEntry {
                    db_id: i as u8,
                    db_type: match db.descriptor.db_type {
                        DatabaseType::Full => 0,
                        DatabaseType::Delta => 1,
                    },
                    name: db.descriptor.name.clone(),
                    base_height: db.descriptor.base_height,
                    height: db.descriptor.height,
                    index_bins_per_table: db.index.bins_per_table as u32,
                    chunk_bins_per_table: db.chunk.bins_per_table as u32,
                    index_k: db.index.params.k as u8,
                    chunk_k: db.chunk.params.k as u8,
                    tag_seed: db.index.tag_seed,
                    dpf_n_index: params::compute_dpf_n(db.index.bins_per_table),
                    dpf_n_chunk: params::compute_dpf_n(db.chunk.bins_per_table),
                    has_bucket_merkle: db.has_bucket_merkle(),
                    index_master_seed: db.index.master_seed,
                    chunk_master_seed: db.chunk.master_seed,
                    anchor: db.index.anchor,
                })
                .collect(),
        }
    }

    fn process_index_batch(
        &self,
        query: &BatchQuery,
        db: &MappedDatabase,
    ) -> (BatchResult, std::time::Duration, std::time::Duration) {
        let k = db.index.params.k;
        let num_groups = query.keys.len().min(k);
        let group_results: Vec<(Vec<Vec<u8>>, GroupTiming)> = (0..num_groups)
            .into_par_iter()
            .map(|b| {
                let dpf_keys: Vec<DpfKey> = query.keys[b]
                    .iter()
                    .map(|k| DpfKey::from_bytes(k).expect("bad dpf key"))
                    .collect();
                let key_refs: Vec<&DpfKey> = dpf_keys.iter().collect();
                let table_bytes = db.index.group_bytes(b);
                let (r0, r1, timing) = eval::process_index_group(
                    key_refs[0],
                    key_refs[1],
                    table_bytes,
                    db.index.bins_per_table,
                );
                (vec![r0, r1], timing)
            })
            .collect();

        let mut total_dpf = std::time::Duration::ZERO;
        let mut total_fetch = std::time::Duration::ZERO;
        let mut results = Vec::with_capacity(num_groups);
        for (r, t) in group_results {
            total_dpf += t.dpf_eval;
            total_fetch += t.fetch_xor;
            results.push(r);
        }
        (
            BatchResult {
                level: 0,
                round_id: 0,
                results,
            },
            total_dpf,
            total_fetch,
        )
    }

    fn process_chunk_batch(
        &self,
        query: &BatchQuery,
        db: &MappedDatabase,
    ) -> (BatchResult, std::time::Duration, std::time::Duration) {
        let k = db.chunk.params.k;
        let num_groups = query.keys.len().min(k);
        let group_results: Vec<(Vec<Vec<u8>>, GroupTiming)> = (0..num_groups)
            .into_par_iter()
            .map(|b| {
                let dpf_keys: Vec<DpfKey> = query.keys[b]
                    .iter()
                    .map(|k| DpfKey::from_bytes(k).expect("bad dpf key"))
                    .collect();
                let key_refs: Vec<&DpfKey> = dpf_keys.iter().collect();
                let table_bytes = db.chunk.group_bytes(b);
                let (r, timing) =
                    eval::process_chunk_group(&key_refs, table_bytes, db.chunk.bins_per_table);
                (r, timing)
            })
            .collect();

        let mut total_dpf = std::time::Duration::ZERO;
        let mut total_fetch = std::time::Duration::ZERO;
        let mut results = Vec::with_capacity(num_groups);
        for (r, t) in group_results {
            total_dpf += t.dpf_eval;
            total_fetch += t.fetch_xor;
            results.push(r);
        }
        (
            BatchResult {
                level: 1,
                round_id: query.round_id,
                results,
            },
            total_dpf,
            total_fetch,
        )
    }

    /// Generic DPF batch evaluation against any MappedSubTable.
    fn process_generic_batch(
        &self,
        query: &BatchQuery,
        table: &MappedSubTable,
    ) -> (BatchResult, std::time::Duration, std::time::Duration) {
        let k = table.params.k;
        let result_size = table.params.bin_size();
        let num_groups = query.keys.len().min(k);

        let group_results: Vec<(Vec<Vec<u8>>, GroupTiming)> = (0..num_groups)
            .into_par_iter()
            .map(|b| {
                let dpf_keys: Vec<DpfKey> = query.keys[b]
                    .iter()
                    .map(|k| DpfKey::from_bytes(k).expect("bad dpf key"))
                    .collect();
                let key_refs: Vec<&DpfKey> = dpf_keys.iter().collect();
                let table_bytes = table.group_bytes(b);
                let (r, timing) = eval::process_merkle_sibling_group(
                    &key_refs,
                    table_bytes,
                    table.bins_per_table,
                    result_size,
                );
                (r, timing)
            })
            .collect();

        let mut total_dpf = std::time::Duration::ZERO;
        let mut total_fetch = std::time::Duration::ZERO;
        let mut results = Vec::with_capacity(num_groups);
        for (r, t) in group_results {
            total_dpf += t.dpf_eval;
            total_fetch += t.fetch_xor;
            results.push(r);
        }
        (
            BatchResult {
                level: query.level,
                round_id: query.round_id,
                results,
            },
            total_dpf,
            total_fetch,
        )
    }

    fn handle_harmony_query(&self, query: &HarmonyQuery) -> Response {
        let db = match self.state.get_db(query.db_id) {
            Some(d) => d,
            None => return Response::Error(format!("unknown db_id {}", query.db_id)),
        };
        harmony_query_response(db, query)
    }

    fn handle_harmony_batch_query(&self, query: &HarmonyBatchQuery) -> Response {
        let db = match self.state.get_db(query.db_id) {
            Some(d) => d,
            None => return Response::Error(format!("unknown db_id {}", query.db_id)),
        };
        harmony_batch_response(db, query)
    }

    fn handle_oram_lookup(&self, query: &OramLookupRequest) -> Response {
        #[cfg(feature = "cuckoo-oram")]
        {
            if self.state.get_db(query.db_id).is_none() {
                return Response::Error(format!("unknown db_id {}", query.db_id));
            }
            if let Some(tables) = self.direct_oram.get(&query.db_id) {
                let t = Instant::now();
                let lookup = match tables.lookup_batch(&query.script_hashes, &query.slot_present) {
                    Ok(v) => v,
                    Err(e) => return Response::Error(format!("Direct ORAM lookup failed: {}", e)),
                };
                unsafe_debug_log!(
                    "[direct-oram-lookup] db={} slots={}, budget={} in {:.2?}",
                    query.db_id,
                    query.script_hashes.len(),
                    tables.access_budget,
                    t.elapsed(),
                );
                let actual_chunk_bytes = lookup.iter().try_fold(0usize, |acc, item| {
                    acc.checked_add(item.raw_chunk_data.len())
                        .ok_or_else(|| "direct ORAM response chunk byte count overflow".to_string())
                });
                let actual_chunk_bytes = match actual_chunk_bytes {
                    Ok(bytes) => bytes,
                    Err(e) => return Response::Error(e),
                };
                let trailing_padding_bytes = match direct_oram_response_padding_bytes(
                    tables.access_budget,
                    query.script_hashes.len(),
                    tables.index.hash_fns,
                    actual_chunk_bytes,
                ) {
                    Ok(bytes) => bytes,
                    Err(e) => return Response::Error(e),
                };
                return Response::OramLookupResult(OramLookupResult {
                    db_id: query.db_id,
                    items: lookup
                        .into_iter()
                        .map(|item| OramLookupItem {
                            found: item.found,
                            whale: item.whale,
                            start_chunk_id: item.start_chunk_id.unwrap_or(0),
                            num_chunks: item.num_chunks,
                            raw_chunk_data: item.raw_chunk_data,
                        })
                        .collect(),
                    trailing_padding_bytes,
                });
            }
            let db = self
                .state
                .get_db(query.db_id)
                .expect("unknown db_id checked above");
            let Some(tables) = self.cuckoo_oram.get(&query.db_id) else {
                return Response::Error(format!(
                    "ORAM not configured for db_id {}; start with --direct-oram-db {}=<dir> or --cuckoo-oram-db {}=<dir>",
                    query.db_id,
                    query.db_id, query.db_id
                ));
            };
            let t = Instant::now();
            if query.present_count() != query.script_hashes.len() {
                return Response::Error(
                    "padded empty ORAM slots require --direct-oram-db; legacy cuckoo ORAM fallback does not support explicit empty slots".into(),
                );
            }
            let lookup = match tables
                .lookup_batch(CuckooNativeLookupConfig::from_db(db), &query.script_hashes)
            {
                Ok(v) => v,
                Err(e) => return Response::Error(format!("ORAM lookup failed: {}", e)),
            };
            unsafe_debug_log!(
                "[oram-lookup] db={} {} scripthash(es) in {:.2?}",
                query.db_id,
                query.script_hashes.len(),
                t.elapsed(),
            );
            Response::OramLookupResult(OramLookupResult {
                db_id: query.db_id,
                items: lookup
                    .into_iter()
                    .map(|item| OramLookupItem {
                        found: item.found,
                        whale: item.whale,
                        start_chunk_id: item.start_chunk_id.unwrap_or(0),
                        num_chunks: item.num_chunks,
                        raw_chunk_data: item.raw_chunk_data,
                    })
                    .collect(),
                trailing_padding_bytes: 0,
            })
        }
        #[cfg(not(feature = "cuckoo-oram"))]
        {
            let _ = query;
            Response::Error(
                "ORAM lookup requires building unified_server with --features cuckoo-oram".into(),
            )
        }
    }
}

// ─── AMD VCEK chain loader ─────────────────────────────────────────────────
//
// Reads two PEM files from `--vcek-dir`:
//   - cert_chain.pem  — ASK + ARK as concatenated PEMs (the format AMD
//                       KDS returns from /vcek/v1/{Family}/cert_chain).
//                       ASK comes first, ARK second.
//   - vcek.pem        — the per-chip VCEK for the current TCB (fetched
//                       from /vcek/v1/{Family}/{ChipID}?TCB-params).
//
// Splits cert_chain.pem on the BEGIN/END boundaries so the AttestResult
// fields end up with separate `ark_pem` and `ask_pem`. (Splitting here
// rather than at the verifier matches the operator workflow: one curl
// per file from AMD KDS, then one cp into --vcek-dir.)
//
// Returns (ark, ask, vcek). Empty Vecs on any I/O or parse failure;
// caller logs and continues — AttestResult ships empty cert fields and
// the browser falls back to V2-binding-only mode.
fn load_vcek_chain(dir: &Path) -> std::io::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let chain_path = dir.join("cert_chain.pem");
    let vcek_path = dir.join("vcek.pem");
    let chain_bytes = std::fs::read(&chain_path)?;
    let vcek_bytes = std::fs::read(&vcek_path)?;

    let (ask, ark) = split_cert_chain_ask_then_ark(&chain_bytes).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "cert_chain.pem at {} did not contain two PEM blocks (expected ASK then ARK)",
                chain_path.display()
            ),
        )
    })?;
    Ok((ark, ask, vcek_bytes))
}

/// Split a concatenated PEM blob into (first_block, second_block) by
/// looking for `-----BEGIN` / `-----END` boundaries. AMD KDS returns
/// the chain endpoint as ASK + ARK (in that order); callers swap to
/// (ark, ask) at the call site.
fn split_cert_chain_ask_then_ark(bytes: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let s = std::str::from_utf8(bytes).ok()?;
    // Find the END of the first block, including its line.
    let first_end = s.find("-----END")?;
    let after_first_end = first_end + s[first_end..].find('\n')? + 1;
    let first_block = s.as_bytes()[..after_first_end].to_vec();
    // The remainder should start with the second BEGIN line.
    let rest = &s[after_first_end..];
    let second_begin = rest.find("-----BEGIN")?;
    let second_block = rest.as_bytes()[second_begin..].to_vec();
    if second_block.is_empty() {
        return None;
    }
    Some((first_block, second_block))
}

// ─── REQ_ANNOUNCE response builder ──────────────────────────────────────────
//
// Maps the startup-built `ServerState.announcement_bundle` to the wire
// reply: `Some` → `RESP_ANNOUNCE` carrying the operator-signed bundle
// verbatim; `None` → `RESP_ERROR` (the server was started without a
// consistent identity key + operator cert). Extracted so the REQ_ANNOUNCE
// dispatch arm and its unit test share one implementation — booting the
// full binary needs a multi-GB checkpoint, so this is the closest seam
// the production code path can be exercised at in-process.
fn build_announce_response(announcement_bundle: &Option<Vec<u8>>) -> Response {
    match announcement_bundle {
        Some(bytes) => Response::Announce(bytes.clone()),
        None => Response::Error(
            "announce not configured: server lacks identity key or operator cert".into(),
        ),
    }
}

/// Private response-budget seam used by the connection sink. Production uses
/// the connection's signed admission grant; tests use a tiny deterministic
/// budget to prove no encoded response can bypass this layer.
trait ServiceResponseBudgetV1 {
    fn reserve_service_response_bytes_v1(&mut self, bytes: u64) -> Result<(), String>;
}

const MAX_PRE_AUTH_EGRESS_MESSAGES_V1: u32 = 32;
const MAX_PRE_AUTH_EGRESS_BYTES_V1: u64 = 16 * 1024 * 1024;
type PreAuthDeadlineFutureV1 =
    std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>;

#[derive(Clone, Copy, Debug)]
struct PreAuthEgressBudgetV1 {
    message_limit: u32,
    byte_limit: u64,
    messages_used: u32,
    bytes_used: u64,
    terminal: bool,
}

impl PreAuthEgressBudgetV1 {
    const fn production() -> Self {
        Self {
            message_limit: MAX_PRE_AUTH_EGRESS_MESSAGES_V1,
            byte_limit: MAX_PRE_AUTH_EGRESS_BYTES_V1,
            messages_used: 0,
            bytes_used: 0,
            terminal: false,
        }
    }

    #[cfg(test)]
    const fn with_limits(message_limit: u32, byte_limit: u64) -> Self {
        Self {
            message_limit,
            byte_limit,
            messages_used: 0,
            bytes_used: 0,
            terminal: false,
        }
    }

    fn reserve(&mut self, messages: u32, bytes: u64) -> Result<(), String> {
        if self.terminal {
            return Err("pre-authorization egress budget is terminal".into());
        }
        if messages == 0 || bytes == 0 {
            self.terminal = true;
            return Err("pre-authorization egress reservation is empty".into());
        }
        let Some(next_messages) = self.messages_used.checked_add(messages) else {
            self.terminal = true;
            return Err("pre-authorization message counter overflow".into());
        };
        let Some(next_bytes) = self.bytes_used.checked_add(bytes) else {
            self.terminal = true;
            return Err("pre-authorization byte counter overflow".into());
        };
        if next_messages > self.message_limit || next_bytes > self.byte_limit {
            self.terminal = true;
            return Err("pre-authorization egress budget exceeded".into());
        }
        self.messages_used = next_messages;
        self.bytes_used = next_bytes;
        Ok(())
    }
}

fn is_pre_auth_egress_opcode_v1(variant: u8) -> bool {
    matches!(
        variant,
        REQ_PING
            | REQ_GET_INFO
            | 0x03 // REQ_GET_INFO_JSON
            | REQ_GET_DB_CATALOG
            | REQ_GET_DB_PROOF
            | REQ_GET_DB_PROOF_V2
            | REQ_ATTEST
            | REQ_ANNOUNCE
            | REQ_HANDSHAKE
            | REQ_SERVICE_POLICY_V1
            | REQ_POW_CHALLENGE_V1
            | REQ_BUCKET_MERKLE_TREE_TOPS
            | REQ_HARMONY_GET_INFO
            | REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP
            | REQ_ONIONPIR_MERKLE_DATA_TREE_TOP
    )
}

impl ServiceResponseBudgetV1 for ConnectionAdmissionGateV1 {
    fn reserve_service_response_bytes_v1(&mut self, bytes: u64) -> Result<(), String> {
        self.reserve_response_bytes(bytes)
            .map_err(|error| error.to_string())
    }
}

/// Sink wrapper that accounts the actual application-encoded WebSocket Binary
/// bytes after secure-channel sealing and outer framing, immediately before
/// they reach the underlying socket. Signed backend grants use their policy
/// response limit; ungated verification/preflight opcodes use a separate
/// fixed per-connection message+byte budget. Exhausting either fails closed.
struct ServiceAdmissionSink<S, B = ConnectionAdmissionGateV1> {
    inner: S,
    response_budget: B,
    meter_current_response: bool,
    meter_current_pre_auth_response: bool,
    pre_reserved_response_bytes: u64,
    pre_reserved_response_messages: u32,
    pre_auth_egress_budget: PreAuthEgressBudgetV1,
    /// Fixed at connection setup. The future remains armed until a granted
    /// AUTH result has been successfully written *and flushed* to the peer.
    /// Keeping this separate from the admission gate is essential: a durable
    /// commit may move the gate to `Granted` while its response is still
    /// blocked behind WebSocket/TCP backpressure.
    pre_auth_deadline_at: Option<Instant>,
    pre_auth_deadline: Option<PreAuthDeadlineFutureV1>,
    auth_result_delivered: bool,
    pre_auth_deadline_expired: bool,
}

impl<S> ServiceAdmissionSink<S, ConnectionAdmissionGateV1> {
    fn new(
        inner: S,
        enforcement: AdmissionEnforcementV1,
        pre_auth_started: Instant,
        pre_auth_timeout: Duration,
    ) -> Self {
        let pre_auth_deadline_at = if enforcement == AdmissionEnforcementV1::Enforced {
            Some(
                pre_auth_started
                    .checked_add(pre_auth_timeout)
                    .expect("bounded service pre-auth timeout cannot overflow Instant"),
            )
        } else {
            None
        };
        let pre_auth_deadline = pre_auth_deadline_at.map(|deadline| {
            Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(
                deadline,
            ))) as PreAuthDeadlineFutureV1
        });
        Self {
            inner,
            response_budget: ConnectionAdmissionGateV1::new(enforcement),
            meter_current_response: false,
            meter_current_pre_auth_response: false,
            pre_reserved_response_bytes: 0,
            pre_reserved_response_messages: 0,
            pre_auth_egress_budget: PreAuthEgressBudgetV1::production(),
            pre_auth_deadline_at,
            pre_auth_deadline,
            auth_result_delivered: false,
            pre_auth_deadline_expired: false,
        }
    }

    fn admission_gate_mut(&mut self) -> &mut ConnectionAdmissionGateV1 {
        &mut self.response_budget
    }

    fn active_chunk_request_limit(&self) -> Option<usize> {
        self.response_budget
            .active_request_byte_limit()
            .and_then(|limit| usize::try_from(limit).ok())
            // Outer length plus encrypted-channel magic/sequence/tag. Keep a
            // little versioning headroom while the plaintext limit remains
            // authoritative after decryption.
            .map(|limit| limit.saturating_add(64).min(MAX_REASSEMBLED))
    }

    fn meter_backend_response(&mut self, _permit: BackendFramePermitV1) {
        self.meter_current_response = true;
    }
}

/// Return the next socket-read budget and whether expiry means the absolute
/// pre-authorization deadline fired. Only enforced admission uses that
/// deadline; the ordinary idle timeout applies only after a granted AUTH
/// result has been successfully written and flushed. A durable authorization
/// commit alone is deliberately insufficient. In particular, repeatedly
/// receiving Ping frames cannot reset `pre_auth_elapsed`.
fn connection_read_timeout_v1(
    enforcement: AdmissionEnforcementV1,
    auth_result_delivered: bool,
    pre_auth_elapsed: Duration,
    pre_auth_timeout: Duration,
    idle_timeout: Duration,
) -> Option<(Duration, bool)> {
    if enforcement != AdmissionEnforcementV1::Enforced || auth_result_delivered {
        return Some((idle_timeout, false));
    }
    let remaining = pre_auth_timeout.checked_sub(pre_auth_elapsed)?;
    if remaining.is_zero() {
        return None;
    }
    if remaining <= idle_timeout {
        Some((remaining, true))
    } else {
        Some((idle_timeout, false))
    }
}

/// Apply an absolute post-grant V2Full dispatch deadline to the next socket
/// read. The caller stores the original `deadline`; control frames can trigger
/// another call but can never create a fresh interval.
fn cap_read_timeout_by_dispatch_deadline_v1(
    read_timeout: Duration,
    dispatch_deadline: Option<Instant>,
    now: Instant,
) -> Option<(Duration, bool)> {
    let Some(deadline) = dispatch_deadline else {
        return Some((read_timeout, false));
    };
    let remaining = deadline.checked_duration_since(now)?;
    if remaining.is_zero() {
        return None;
    }
    if remaining <= read_timeout {
        Some((remaining, true))
    } else {
        Some((read_timeout, false))
    }
}

/// Arm the post-grant window only after AUTH_GRANTED has been flushed. Repeated
/// calls are idempotent so no later frame can extend an existing deadline.
fn arm_v2full_dispatch_deadline_v1(
    deadline: &mut Option<Instant>,
    grant_flushed_at: Instant,
    timeout: Duration,
) {
    if deadline.is_none() {
        *deadline = Some(grant_flushed_at + timeout);
    }
}

/// Recheck the absolute connection deadline after a potentially blocking,
/// durable authorization commit. Equality is expired. The commit itself is not
/// cancelled: doing so could strand an unknown outcome or corrupt its exact
/// retry semantics. The caller must close without sending the auth result or
/// permitting backend work when this returns true.
fn post_authorization_deadline_expired_v1(
    enforcement: AdmissionEnforcementV1,
    pre_auth_elapsed: Duration,
    pre_auth_timeout: Duration,
) -> bool {
    enforcement == AdmissionEnforcementV1::Enforced && pre_auth_elapsed >= pre_auth_timeout
}

#[cfg(test)]
mod connection_resource_deadline_tests {
    use super::*;

    #[test]
    fn enforced_pre_auth_deadline_is_absolute_and_not_an_idle_reset() {
        let pre_auth = Duration::from_secs(120);
        let idle = Duration::from_secs(30);
        assert_eq!(
            connection_read_timeout_v1(
                AdmissionEnforcementV1::Enforced,
                false,
                Duration::from_secs(0),
                pre_auth,
                idle,
            ),
            Some((idle, false))
        );
        // A Ping may cause another call, but elapsed time comes from the
        // unchanged connection origin, so only ten seconds remain.
        assert_eq!(
            connection_read_timeout_v1(
                AdmissionEnforcementV1::Enforced,
                false,
                Duration::from_secs(110),
                pre_auth,
                idle,
            ),
            Some((Duration::from_secs(10), true))
        );
        assert_eq!(
            connection_read_timeout_v1(
                AdmissionEnforcementV1::Enforced,
                false,
                pre_auth,
                pre_auth,
                idle,
            ),
            None
        );
    }

    #[test]
    fn delivered_grant_or_explicit_legacy_connections_use_idle_timeout() {
        let idle = Duration::from_secs(30);
        for (enforcement, delivered) in [
            (AdmissionEnforcementV1::Enforced, true),
            (AdmissionEnforcementV1::ExplicitLegacyMode, false),
        ] {
            assert_eq!(
                connection_read_timeout_v1(
                    enforcement,
                    delivered,
                    Duration::from_secs(600),
                    Duration::from_secs(120),
                    idle,
                ),
                Some((idle, false))
            );
        }
    }

    #[test]
    fn durable_commit_without_result_delivery_remains_on_pre_auth_deadline() {
        let pre_auth = Duration::from_secs(120);
        let idle = Duration::from_secs(30);
        assert_eq!(
            connection_read_timeout_v1(
                AdmissionEnforcementV1::Enforced,
                false,
                Duration::from_secs(119),
                pre_auth,
                idle,
            ),
            Some((Duration::from_secs(1), true))
        );
    }

    #[test]
    fn post_authorization_commit_rechecks_the_absolute_deadline() {
        let timeout = Duration::from_secs(120);
        assert!(!post_authorization_deadline_expired_v1(
            AdmissionEnforcementV1::Enforced,
            timeout - Duration::from_nanos(1),
            timeout,
        ));
        assert!(post_authorization_deadline_expired_v1(
            AdmissionEnforcementV1::Enforced,
            timeout,
            timeout,
        ));
        assert!(post_authorization_deadline_expired_v1(
            AdmissionEnforcementV1::Enforced,
            timeout + Duration::from_secs(1),
            timeout,
        ));
        assert!(!post_authorization_deadline_expired_v1(
            AdmissionEnforcementV1::ExplicitLegacyMode,
            timeout + Duration::from_secs(1),
            timeout,
        ));
    }

    #[test]
    fn post_grant_v2full_deadline_is_absolute_across_control_frames() {
        let origin = Instant::now();
        let deadline = origin + Duration::from_secs(30);
        assert_eq!(
            cap_read_timeout_by_dispatch_deadline_v1(
                Duration::from_secs(120),
                Some(deadline),
                origin,
            ),
            Some((Duration::from_secs(30), true))
        );
        // Model a Ping ten seconds later: the unchanged deadline leaves twenty
        // seconds, rather than resetting a new thirty-second window.
        assert_eq!(
            cap_read_timeout_by_dispatch_deadline_v1(
                Duration::from_secs(120),
                Some(deadline),
                origin + Duration::from_secs(10),
            ),
            Some((Duration::from_secs(20), true))
        );
        assert_eq!(
            cap_read_timeout_by_dispatch_deadline_v1(
                Duration::from_secs(120),
                Some(deadline),
                deadline,
            ),
            None
        );
    }

    #[test]
    fn v2full_dispatch_window_starts_after_grant_flush_and_never_resets() {
        let authorization_finished = Instant::now();
        let grant_flushed = authorization_finished + Duration::from_secs(20);
        let mut deadline = None;
        arm_v2full_dispatch_deadline_v1(&mut deadline, grant_flushed, Duration::from_secs(30));
        assert_eq!(deadline, Some(grant_flushed + Duration::from_secs(30)));
        arm_v2full_dispatch_deadline_v1(
            &mut deadline,
            grant_flushed + Duration::from_secs(10),
            Duration::from_secs(30),
        );
        assert_eq!(deadline, Some(grant_flushed + Duration::from_secs(30)));
    }
}

impl<S, B> ServiceAdmissionSink<S, B> {
    /// Start one inbound application request. Any unused group reservation
    /// remains charged (there are no refunds after a partial/network failure),
    /// but must never be applied to a later request.
    fn begin_request(&mut self) {
        self.meter_current_response = false;
        self.meter_current_pre_auth_response = false;
        self.pre_reserved_response_bytes = 0;
        self.pre_reserved_response_messages = 0;
    }

    fn meter_pre_auth_response_for_opcode(&mut self, variant: u8) {
        self.meter_current_pre_auth_response = is_pre_auth_egress_opcode_v1(variant);
    }

    fn pre_auth_egress_is_terminal(&self) -> bool {
        self.pre_auth_egress_budget.terminal
    }

    fn auth_result_delivered(&self) -> bool {
        self.auth_result_delivered
    }

    /// Backend work is never authorized by gate state alone. A grant may have
    /// committed durably, or a complementary Harmony grant may have been
    /// installed, while its result is still queued behind transport
    /// backpressure. Only a completely flushed grant result crosses this
    /// connection-local delivery boundary.
    fn require_auth_result_delivered_for_backend(&self) -> Result<(), &'static str> {
        if self.auth_result_delivered {
            Ok(())
        } else {
            Err("authorization grant result has not been delivered")
        }
    }

    /// Disable the pre-auth write deadline only after `SinkExt::send` has
    /// completed, which includes the underlying sink's flush.
    fn mark_auth_result_delivered(&mut self) {
        self.auth_result_delivered = true;
        self.pre_auth_deadline_at = None;
        self.pre_auth_deadline = None;
    }

    fn pre_auth_deadline_has_expired(&self) -> bool {
        self.pre_auth_deadline_expired
    }

    fn expire_pre_auth_deadline(&mut self) {
        self.pre_auth_deadline_expired = true;
        // Make every subsequent application send fail closed even if its
        // caller historically ignored a transport error before returning to
        // the connection-loop terminal check.
        self.pre_auth_egress_budget.terminal = true;
        self.pre_auth_deadline_at = None;
        self.pre_auth_deadline = None;
    }

    fn pre_auth_timeout_error() -> tokio_tungstenite::tungstenite::Error {
        tokio_tungstenite::tungstenite::Error::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "absolute pre-authorization write deadline expired",
        ))
    }

    #[allow(clippy::result_large_err)] // Must return the underlying Sink::Error shape.
    fn enforce_pre_auth_deadline_now(&mut self) -> tokio_tungstenite::tungstenite::Result<()> {
        if self.pre_auth_deadline_expired {
            return Err(Self::pre_auth_timeout_error());
        }
        if !self.auth_result_delivered {
            if let Some(deadline) = self.pre_auth_deadline_at {
                if Instant::now() >= deadline {
                    self.expire_pre_auth_deadline();
                    return Err(Self::pre_auth_timeout_error());
                }
            }
        }
        Ok(())
    }

    /// Poll the same fixed deadline alongside every write/flush operation.
    /// Returning `Ok(())` while the timer is pending lets the underlying sink
    /// make progress, while polling the timer registers a wakeup even for an
    /// underlying sink that remains permanently `Pending`.
    #[allow(clippy::result_large_err)] // Must return the underlying Sink::Error shape.
    fn poll_pre_auth_deadline(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> tokio_tungstenite::tungstenite::Result<()> {
        self.enforce_pre_auth_deadline_now()?;
        if self.auth_result_delivered {
            return Ok(());
        }
        let expired = self
            .pre_auth_deadline
            .as_mut()
            .is_some_and(|deadline| std::future::Future::poll(deadline.as_mut(), cx).is_ready());
        if expired {
            self.expire_pre_auth_deadline();
            return Err(Self::pre_auth_timeout_error());
        }
        Ok(())
    }

    #[cfg(test)]
    fn with_test_budget(inner: S, response_budget: B) -> Self {
        Self {
            inner,
            response_budget,
            meter_current_response: false,
            meter_current_pre_auth_response: false,
            pre_reserved_response_bytes: 0,
            pre_reserved_response_messages: 0,
            pre_auth_egress_budget: PreAuthEgressBudgetV1::production(),
            pre_auth_deadline_at: None,
            pre_auth_deadline: None,
            auth_result_delivered: false,
            pre_auth_deadline_expired: false,
        }
    }

    #[cfg(test)]
    fn set_test_pre_auth_deadline<F>(&mut self, deadline: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        self.pre_auth_deadline_at = None;
        self.pre_auth_deadline = Some(Box::pin(deadline));
        self.auth_result_delivered = false;
        self.pre_auth_deadline_expired = false;
    }

    #[cfg(test)]
    fn set_test_pre_auth_egress_limits(&mut self, messages: u32, bytes: u64) {
        self.pre_auth_egress_budget = PreAuthEgressBudgetV1::with_limits(messages, bytes);
    }

    #[cfg(test)]
    fn meter_response_for_test(&mut self) {
        self.meter_current_response = true;
    }
}

impl<S, B> ServiceAdmissionSink<S, B>
where
    B: ServiceResponseBudgetV1,
{
    fn budget_error(reason: impl Into<String>) -> tokio_tungstenite::tungstenite::Error {
        tokio_tungstenite::tungstenite::Error::Io(std::io::Error::other(reason.into()))
    }

    #[allow(clippy::result_large_err)] // Must return the underlying Sink::Error unchanged.
    fn reserve_encoded_bytes(
        &mut self,
        bytes: usize,
    ) -> tokio_tungstenite::tungstenite::Result<()> {
        if self.pre_auth_egress_budget.terminal {
            return Err(Self::budget_error(
                "pre-authorization egress budget is terminal",
            ));
        }
        if !self.meter_current_response && !self.meter_current_pre_auth_response {
            return Ok(());
        }
        let bytes = u64::try_from(bytes)
            .map_err(|_| Self::budget_error("encoded response length exceeds u64"))?;
        if self.pre_reserved_response_bytes != 0 {
            if bytes > self.pre_reserved_response_bytes || self.pre_reserved_response_messages == 0
            {
                return Err(Self::budget_error(
                    "encoded response exceeded its atomic group reservation",
                ));
            }
            self.pre_reserved_response_bytes -= bytes;
            self.pre_reserved_response_messages -= 1;
            return Ok(());
        }
        if self.meter_current_response {
            self.response_budget
                .reserve_service_response_bytes_v1(bytes)
                .map_err(|error| {
                    Self::budget_error(format!("service response budget rejected send: {error}"))
                })?;
        }
        if self.meter_current_pre_auth_response {
            self.pre_auth_egress_budget
                .reserve(1, bytes)
                .map_err(Self::budget_error)?;
        }
        Ok(())
    }

    /// Reserve a multi-message encoded response before its first byte is sent.
    /// If the signed limit is too small the gate becomes terminal and the
    /// underlying sink observes no partial result.
    #[allow(clippy::result_large_err)] // Must return the underlying Sink::Error unchanged.
    fn reserve_response_group(
        &mut self,
        messages: usize,
        bytes: usize,
    ) -> tokio_tungstenite::tungstenite::Result<()> {
        if self.pre_auth_egress_budget.terminal {
            return Err(Self::budget_error(
                "pre-authorization egress budget is terminal",
            ));
        }
        if !self.meter_current_response && !self.meter_current_pre_auth_response {
            return Ok(());
        }
        let messages = u32::try_from(messages)
            .map_err(|_| Self::budget_error("encoded response group message count exceeds u32"))?;
        let bytes = u64::try_from(bytes)
            .map_err(|_| Self::budget_error("encoded response group length exceeds u64"))?;
        if messages == 0 || bytes == 0 {
            return Err(Self::budget_error("encoded response group is empty"));
        }
        if self.meter_current_response {
            self.response_budget
                .reserve_service_response_bytes_v1(bytes)
                .map_err(|error| {
                    Self::budget_error(format!("service response budget rejected group: {error}"))
                })?;
        }
        if self.meter_current_pre_auth_response {
            self.pre_auth_egress_budget
                .reserve(messages, bytes)
                .map_err(Self::budget_error)?;
        }
        self.pre_reserved_response_bytes = self
            .pre_reserved_response_bytes
            .checked_add(bytes)
            .ok_or_else(|| Self::budget_error("response group reservation overflow"))?;
        self.pre_reserved_response_messages = self
            .pre_reserved_response_messages
            .checked_add(messages)
            .ok_or_else(|| Self::budget_error("response group message reservation overflow"))?;
        Ok(())
    }
}

impl<S, B> futures_util::Sink<tokio_tungstenite::tungstenite::Message>
    for ServiceAdmissionSink<S, B>
where
    S: futures_util::Sink<
            tokio_tungstenite::tungstenite::Message,
            Error = tokio_tungstenite::tungstenite::Error,
        > + Unpin,
    B: ServiceResponseBudgetV1 + Unpin,
{
    type Error = tokio_tungstenite::tungstenite::Error;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        if let Err(error) = this.poll_pre_auth_deadline(cx) {
            return std::task::Poll::Ready(Err(error));
        }
        std::pin::Pin::new(&mut this.inner).poll_ready(cx)
    }

    fn start_send(
        self: std::pin::Pin<&mut Self>,
        item: tokio_tungstenite::tungstenite::Message,
    ) -> Result<(), Self::Error> {
        let this = self.get_mut();
        this.enforce_pre_auth_deadline_now()?;
        if let tokio_tungstenite::tungstenite::Message::Binary(bytes) = &item {
            this.reserve_encoded_bytes(bytes.len())?;
        }
        std::pin::Pin::new(&mut this.inner).start_send(item)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        if let Err(error) = this.poll_pre_auth_deadline(cx) {
            return std::task::Poll::Ready(Err(error));
        }
        match std::pin::Pin::new(&mut this.inner).poll_flush(cx) {
            std::task::Poll::Ready(Ok(())) => match this.enforce_pre_auth_deadline_now() {
                Ok(()) => std::task::Poll::Ready(Ok(())),
                Err(error) => std::task::Poll::Ready(Err(error)),
            },
            other => other,
        }
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.inner).poll_close(cx)
    }
}

// ─── Encrypted-channel send helper ─────────────────────────────────────────
//
// Wraps the raw `sink.send(Message::Binary(...))` pattern so that, if a
// session is established for this connection, the outgoing payload gets
// AEAD-sealed via pir_channel before going on the wire. Cleartext callers
// pass `None` and the function is a thin pass-through.
//
// `payload` is the full outgoing wire blob: `[4B len LE][1B variant][body]`.
// When sealing, we strip the 4-byte length, seal the rest, then re-frame
// with a fresh outer length around the sealed bytes. The result still
// satisfies the WS receiver's `[4B len][payload]` expectation; the
// payload's first byte is now `pir_channel::ENCRYPTED_FRAME_MAGIC` (0xfe)
// instead of the raw variant byte.
//
// Errors from sealing (sequence-counter exhaustion, AEAD backend failure)
// are surfaced as `tungstenite::Error::Io(..)` so the caller can use the
// same `if let Err(e) = ...` shape it already uses for raw send errors.
async fn send_resp<S>(
    sink: &mut S,
    session: Option<&mut pir_runtime_core::channel::Session>,
    payload: Vec<u8>,
) -> tokio_tungstenite::tungstenite::Result<()>
where
    S: futures_util::SinkExt<
            tokio_tungstenite::tungstenite::Message,
            Error = tokio_tungstenite::tungstenite::Error,
        > + Unpin,
{
    use tokio_tungstenite::tungstenite::{Error as TungError, Message};
    let to_send = match session {
        Some(s) => {
            if payload.len() < 4 {
                // Defensive: malformed (no length prefix). Pass through —
                // the WS receiver will see a too-short frame and ignore it,
                // matching pre-Slice-B.2 behaviour.
                payload
            } else {
                let inner = &payload[4..];
                let sealed = s
                    .seal(pir_runtime_core::channel::Direction::ServerToClient, inner)
                    .map_err(|e| {
                        TungError::Io(std::io::Error::other(format!("channel seal: {}", e)))
                    })?;
                let mut framed = Vec::with_capacity(4 + sealed.len());
                framed.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
                framed.extend_from_slice(&sealed);
                framed
            }
        }
        None => payload,
    };
    sink.send(Message::Binary(to_send)).await
}

/// Deliver one AUTH result and record a grant as usable only after the
/// WebSocket sink has accepted and flushed the complete response. The
/// `ServiceAdmissionSink` keeps its fixed pre-auth deadline armed throughout
/// this await, including when a durable admission commit has already moved the
/// gate to `Granted`.
async fn deliver_auth_result_response_v1<S, B>(
    sink: &mut ServiceAdmissionSink<S, B>,
    session: Option<&mut pir_runtime_core::channel::Session>,
    result: &pir_service_protocol::AuthResultV1,
) -> tokio_tungstenite::tungstenite::Result<()>
where
    S: futures_util::Sink<
            tokio_tungstenite::tungstenite::Message,
            Error = tokio_tungstenite::tungstenite::Error,
        > + Unpin,
    B: ServiceResponseBudgetV1 + Unpin,
{
    let granted = matches!(result, pir_service_protocol::AuthResultV1::Granted(_));
    let response = encode_auth_result_response_v1(result).map_err(|error| {
        tokio_tungstenite::tungstenite::Error::Io(std::io::Error::other(format!(
            "failed to encode RESP_AUTH_RESULT_V1: {error}"
        )))
    })?;
    send_resp(sink, session, response).await?;
    if granted {
        sink.mark_auth_result_delivered();
    }
    Ok(())
}

/// Deliver a complementary Harmony attach result under the same fixed
/// pre-authorization write deadline as a primary AUTH result. Installing the
/// attached gate is not enough: only a fully flushed `Attached` response makes
/// backend work usable on this socket. Rejections leave the deadline armed so
/// a client may attempt a fresh, independently valid attach while time remains.
async fn deliver_harmony_attach_result_response_v1<S, B>(
    sink: &mut ServiceAdmissionSink<S, B>,
    session: Option<&mut pir_runtime_core::channel::Session>,
    result: &HarmonyAttachResultV1,
) -> tokio_tungstenite::tungstenite::Result<()>
where
    S: futures_util::Sink<
            tokio_tungstenite::tungstenite::Message,
            Error = tokio_tungstenite::tungstenite::Error,
        > + Unpin,
    B: ServiceResponseBudgetV1 + Unpin,
{
    let attached = matches!(result, HarmonyAttachResultV1::Attached { .. });
    let response = encode_harmony_attach_result_response_v1(result).map_err(|error| {
        tokio_tungstenite::tungstenite::Error::Io(std::io::Error::other(format!(
            "failed to encode RESP_HARMONY_ATTACH_V1: {error}"
        )))
    })?;
    send_resp(sink, session, response).await?;
    if attached {
        sink.mark_auth_result_delivered();
    }
    Ok(())
}

// `feed_resp` (a per-frame `sink.feed()` variant of `send_resp`) was
// removed when the V2 / V2-half hint paths switched from one
// `Message::Binary` per group to a coalesced ~768 KB batch — see
// `HINT_BATCH_BYTES` below. The coalesced path uses `send_resp_batch`,
// which seals each record individually (preserving per-record framing
// the client demuxes) and emits the concatenated buffer as one
// `Sink::send`-flushed Binary message per batch.

/// Send a batch of `[4B len][body]` records as ONE WebSocket Binary
/// message. Each record retains its own `[4B len][body_or_sealed]`
/// framing inside the buffer so the client's transport layer can demux
/// them one-by-one via [`WsConnection::recv`] (which peels one record
/// per call, buffering any tail).
///
/// When the channel session is active, each record is sealed
/// individually with a fresh sequence number — the seal pattern is
/// byte-identical to N back-to-back `send_resp` calls, just emitted as
/// one WS Binary message instead of N.
///
/// Used by the HarmonyPIR hint paths (V1, V2, V2-half) to coalesce the
/// per-group hint records into ~`HINT_BATCH_BYTES`-sized batches; see
/// the call sites for the surrounding loops.
async fn send_resp_batch<S>(
    sink: &mut S,
    mut session: Option<&mut pir_runtime_core::channel::Session>,
    records: Vec<Vec<u8>>,
) -> tokio_tungstenite::tungstenite::Result<()>
where
    S: futures_util::SinkExt<
            tokio_tungstenite::tungstenite::Message,
            Error = tokio_tungstenite::tungstenite::Error,
        > + Unpin,
{
    use tokio_tungstenite::tungstenite::{Error as TungError, Message};
    if records.is_empty() {
        return Ok(());
    }
    // Pre-size the output buffer. For the no-channel case we know the
    // exact size; for the channel case each sealed body is
    // `body.len() + 1 (magic) + 8 (seq) + 16 (tag) = body.len() + 25`,
    // so a tight upper-bound stays correct without re-allocating.
    let total_estimate: usize = records
        .iter()
        .map(|r| {
            if r.len() < 4 {
                r.len()
            } else {
                4 + (r.len() - 4) + 25
            }
        })
        .sum();
    let mut buf: Vec<u8> = Vec::with_capacity(total_estimate);
    for payload in records {
        match session.as_deref_mut() {
            Some(s) => {
                if payload.len() < 4 {
                    // Defensive: malformed (no length prefix). Pass
                    // through — matches `send_resp` behaviour.
                    buf.extend_from_slice(&payload);
                } else {
                    let inner = &payload[4..];
                    let sealed = s
                        .seal(pir_runtime_core::channel::Direction::ServerToClient, inner)
                        .map_err(|e| {
                            TungError::Io(std::io::Error::other(format!("channel seal: {}", e)))
                        })?;
                    buf.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
                    buf.extend_from_slice(&sealed);
                }
            }
            None => {
                buf.extend_from_slice(&payload);
            }
        }
    }

    sink.send(Message::Binary(buf)).await
}

// ─── Transport-level message chunking (Cloudflare large-message workaround) ──
//
// Cloudflare's WebSocket proxy silently corrupts single messages above
// ~1 MB (a 3.1 MB OnionPIR RegisterKeys upload arrives truncated — see
// docs/PIR1_REGISTER_KEYS_TRUNCATION.md). Messages over CHUNK_SIZE are
// split into `[4B len][CHUNK_MAGIC][seq:u16][total:u16][piece]` frames;
// the peer reassembles. These constants MUST stay in sync with
// `crates/sdk/client/src/connection.rs` (CHUNK_MAGIC / CHUNK_SIZE) and
// `web/src/onionpir_client.ts`.
const CHUNK_MAGIC: u8 = 0xc7;
const CHUNK_SIZE: usize = 256 * 1024;
const CHUNK_HDR: usize = 1 + 2 + 2; // magic + seq + total
const MAX_REASSEMBLED: usize = 16 * 1024 * 1024;
// Client uploads larger than this use BitcoinPIR's 256 KiB chunk envelope.
// Keeping the WebSocket parser itself small bounds memory before application
// admission logic sees the frame.
const MAX_WS_MESSAGE_BYTES: usize = 512 * 1024;
// Process-wide cap across all partially/completely reassembled client
// requests.  This is independent of the connection count and signed grant
// limits so many slow clients cannot each retain a 16 MiB buffer.
const MAX_GLOBAL_REASSEMBLY_BYTES: usize = 64 * 1024 * 1024;
const MAX_CHUNK_FRAMES: usize = MAX_REASSEMBLED.div_ceil(CHUNK_SIZE);

/// Target accumulation size before flushing a coalesced HarmonyPIR hint
/// batch as one WebSocket Binary message. Per-group hint records
/// (~74 KB each on the public deployment) are concatenated into a buffer
/// until the threshold is crossed, then flushed.
///
/// Wire-format inside the buffer is unchanged — each record is still the
/// pre-existing `[4B len][RESP_HARMONY_HINTS][group_id][n][t][m][hints]`
/// frame. Only WS message boundaries are reduced (a HarmonyPIR query that
/// previously emitted ~622 RX HARMONY_HINTS frames across two sockets now
/// emits ~32).
///
/// Sized below 1 MiB so the message survives the Cloudflare WebSocket
/// proxy (~1 MB ceiling — see docs/PIR1_REGISTER_KEYS_TRUNCATION.md).
/// Mirrors `HINT_BATCH_BYTES` in
/// `apps/server/src/bin/harmonypir_hint_server.rs`.
const HINT_BATCH_BYTES: usize = 768 * 1024;

/// Like [`send_resp`], but when `allow_chunk` is set and the framed
/// message exceeds `CHUNK_SIZE`, splits it into chunk frames the client
/// reassembles. Used for the large OnionPIR result messages
/// (INDEX/CHUNK batches ~1–2 MB, Merkle tree-tops ~1 MB) sent to
/// chunk-capable clients. `allow_chunk` is the per-connection
/// `client_supports_chunks` flag — false for legacy / WASM DPF/Harmony
/// clients, which never receive a large enough OnionPIR message anyway.
async fn send_resp_chunked<S, B>(
    sink: &mut ServiceAdmissionSink<S, B>,
    session: Option<&mut pir_runtime_core::channel::Session>,
    payload: Vec<u8>,
    allow_chunk: bool,
) -> tokio_tungstenite::tungstenite::Result<()>
where
    S: futures_util::Sink<
            tokio_tungstenite::tungstenite::Message,
            Error = tokio_tungstenite::tungstenite::Error,
        > + Unpin,
    B: ServiceResponseBudgetV1 + Unpin,
{
    use tokio_tungstenite::tungstenite::{Error as TungError, Message};
    // Frame (and optionally seal) exactly like send_resp.
    let to_send = match session {
        Some(s) => {
            if payload.len() < 4 {
                payload
            } else {
                let inner = &payload[4..];
                let sealed = s
                    .seal(pir_runtime_core::channel::Direction::ServerToClient, inner)
                    .map_err(|e| {
                        TungError::Io(std::io::Error::other(format!("channel seal: {}", e)))
                    })?;
                let mut framed = Vec::with_capacity(4 + sealed.len());
                framed.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
                framed.extend_from_slice(&sealed);
                framed
            }
        }
        None => payload,
    };
    if !allow_chunk || to_send.len() <= CHUNK_SIZE {
        return sink.send(Message::Binary(to_send)).await;
    }
    let total = to_send.len().div_ceil(CHUNK_SIZE);
    if total > u16::MAX as usize {
        return Err(TungError::Io(std::io::Error::other(format!(
            "response too large to chunk: {} bytes",
            to_send.len()
        ))));
    }
    let encoded_group_bytes = to_send
        .len()
        .checked_add(
            total
                .checked_mul(4 + CHUNK_HDR)
                .ok_or_else(|| TungError::Io(std::io::Error::other("chunk framing overflow")))?,
        )
        .ok_or_else(|| TungError::Io(std::io::Error::other("chunk response size overflow")))?;
    sink.reserve_response_group(total, encoded_group_bytes)?;
    for seq in 0..total {
        let start = seq * CHUNK_SIZE;
        let end = (start + CHUNK_SIZE).min(to_send.len());
        let piece = &to_send[start..end];
        let mut frame = Vec::with_capacity(4 + CHUNK_HDR + piece.len());
        frame.extend_from_slice(&((CHUNK_HDR + piece.len()) as u32).to_le_bytes());
        frame.push(CHUNK_MAGIC);
        frame.extend_from_slice(&(seq as u16).to_le_bytes());
        frame.extend_from_slice(&(total as u16).to_le_bytes());
        frame.extend_from_slice(piece);
        sink.send(Message::Binary(frame)).await?;
    }
    Ok(())
}

const SERVICE_CONFIG_FILE_LIMIT_V1: usize = 64 * 1024;

fn current_unix_seconds_v1() -> Result<u64, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_owned())?
        .as_secs();
    if now == 0 {
        return Err("system clock returned zero Unix time".to_owned());
    }
    Ok(now)
}

fn read_regular_file_bounded_v1(
    path: &std::path::Path,
    maximum: usize,
    label: &str,
) -> Result<Vec<u8>, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect {label} {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!("{label} is not a regular file: {}", path.display()));
    }
    let maximum_u64 = u64::try_from(maximum).map_err(|_| format!("{label} limit overflow"))?;
    if metadata.len() > maximum_u64 {
        return Err(format!(
            "{label} is {} bytes, above the {} byte limit",
            metadata.len(),
            maximum
        ));
    }
    let file = File::open(path)
        .map_err(|error| format!("failed to open {label} {}: {error}", path.display()))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum_u64.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read {label} {}: {error}", path.display()))?;
    if bytes.len() > maximum {
        return Err(format!(
            "{label} changed while reading and exceeded its size limit"
        ));
    }
    Ok(bytes)
}

fn decode_fixed_hex_v1<const N: usize>(input: &str, label: &str) -> Result<[u8; N], String> {
    if input.len() != N.saturating_mul(2) {
        return Err(format!(
            "{label} must be exactly {} lowercase or uppercase hex characters",
            N.saturating_mul(2)
        ));
    }
    let bytes = hex::decode(input).map_err(|_| format!("{label} is not valid hex"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{label} is not exactly {N} bytes"))
}

fn read_exact_secret_v1<const N: usize>(
    path: &std::path::Path,
    label: &str,
) -> Result<[u8; N], String> {
    pir_private_files::read_exact_private_file_v1(path, label)
}

type CashuEpochKeysV1 = (u64, Vec<(u64, [u8; 32])>);

fn load_cashu_epoch_keys_v1(
    active_epoch: Option<u64>,
    specs: &[String],
    active_flag: &str,
    key_flag: &str,
    key_label: &str,
) -> Result<Option<CashuEpochKeysV1>, String> {
    match (active_epoch, specs.is_empty()) {
        (None, true) => Ok(None),
        (Some(active_epoch), false) if active_epoch != 0 => {
            let mut keys: Vec<(u64, [u8; 32])> = Vec::with_capacity(specs.len());
            let mut epochs = std::collections::BTreeSet::new();
            for spec in specs {
                let (epoch, path) = spec
                    .split_once('=')
                    .ok_or_else(|| format!("{key_flag} must be <epoch>=<raw-32-byte-path>"))?;
                let epoch = epoch
                    .parse::<u64>()
                    .map_err(|_| format!("{key_flag} epoch must be a non-zero u64"))?;
                if epoch == 0 || path.is_empty() || !epochs.insert(epoch) {
                    for (_, key) in &mut keys {
                        key.zeroize();
                    }
                    return Err(format!(
                        "{key_flag} epochs and paths must be non-empty, non-zero, and unique"
                    ));
                }
                match read_exact_secret_v1::<32>(std::path::Path::new(path), key_label) {
                    Ok(mut key) => {
                        if keys.iter().any(|(_, existing)| existing == &key) {
                            key.zeroize();
                            for (_, loaded_key) in &mut keys {
                                loaded_key.zeroize();
                            }
                            return Err(format!(
                                "{key_flag} must not reuse the same key bytes across epochs"
                            ));
                        }
                        keys.push((epoch, key));
                    }
                    Err(error) => {
                        for (_, key) in &mut keys {
                            key.zeroize();
                        }
                        return Err(error);
                    }
                }
            }
            if !epochs.contains(&active_epoch) {
                for (_, key) in &mut keys {
                    key.zeroize();
                }
                return Err(format!(
                    "{active_flag} must select an epoch loaded by {key_flag}"
                ));
            }
            Ok(Some((active_epoch, keys)))
        }
        _ => Err(format!(
            "standard Cashu requires {active_flag} together with at least one {key_flag}"
        )),
    }
}

fn zeroize_cashu_epoch_keys_v1(material: &mut Option<CashuEpochKeysV1>) {
    if let Some((_, keys)) = material {
        for (_, key) in keys {
            key.zeroize();
        }
    }
}

fn parse_cashu_exposure_limits_v1(
    specs: &[String],
) -> Result<BTreeMap<([u8; 32], String), CashuCustodyExposureLimitsV1>, String> {
    let mut limits = BTreeMap::new();
    for spec in specs {
        let fields = spec.split(':').collect::<Vec<_>>();
        if fields.len() != 4 {
            return Err(
                "--service-cashu-exposure-limit must be <mint-id-hex>:<unit>:<max-unsettled-value>:<max-unsettled-notes>"
                    .to_owned(),
            );
        }
        let mint_id =
            decode_fixed_hex_v1::<32>(fields[0], "--service-cashu-exposure-limit mint ID")?;
        if mint_id.iter().all(|byte| *byte == 0) {
            return Err("--service-cashu-exposure-limit mint ID must not be all zero".to_owned());
        }
        let unit = fields[1];
        if unit.is_empty()
            || unit.len() > pir_service_protocol::MAX_PRICE_UNIT_LEN
            || !unit.is_ascii()
            || !unit
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(
                "--service-cashu-exposure-limit unit must be bounded lowercase ASCII".to_owned(),
            );
        }
        let max_value = fields[2]
            .parse::<u64>()
            .map_err(|_| "Cashu max-unsettled-value must be a finite non-zero u64".to_owned())?;
        let max_notes = fields[3]
            .parse::<u64>()
            .map_err(|_| "Cashu max-unsettled-notes must be a finite non-zero u64".to_owned())?;
        let value = CashuCustodyExposureLimitsV1::new(max_value, max_notes)
            .map_err(|_| "Cashu exposure limits must be finite and non-zero".to_owned())?;
        if limits.insert((mint_id, unit.to_owned()), value).is_some() {
            return Err("duplicate standard Cashu exposure limit for one mint/unit".to_owned());
        }
    }
    Ok(limits)
}

/// Resolve one sensitive SQLite database through a pinned, symlink-free parent
/// walk. The final 0700 directory is the local single-user boundary protecting
/// both the main file and SQLite's runtime `-wal`/`-shm` sidecars; the final
/// component must independently be a single-link euid-owned mode-0600 file.
fn validate_existing_private_sqlite_path_v1(
    path: &std::path::Path,
    label: &str,
) -> Result<PathBuf, String> {
    pir_private_files::checked_existing_private_file_v1(
        path,
        pir_private_files::PrivateFileModeV1::ReadWrite,
        label,
    )
    .map(|checked| checked.path().to_path_buf())
}

fn private_sqlite_paths_alias_v1(
    first: &std::path::Path,
    second: &std::path::Path,
) -> Result<bool, String> {
    if first == second {
        return Ok(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let first_metadata = std::fs::symlink_metadata(first)
            .map_err(|error| format!("failed to inspect {}: {error}", first.display()))?;
        let second_metadata = std::fs::symlink_metadata(second)
            .map_err(|error| format!("failed to inspect {}: {error}", second.display()))?;
        Ok(first_metadata.dev() == second_metadata.dev()
            && first_metadata.ino() == second_metadata.ino())
    }
    #[cfg(not(unix))]
    {
        Err("sensitive SQLite path alias checks are unsupported on non-Unix platforms".to_owned())
    }
}

#[cfg(all(test, unix))]
mod secret_loader_tests_v1 {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use tempfile::tempdir;

    fn write_secret(path: &std::path::Path, bytes: &[u8], mode: u32) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn private_tempdir() -> tempfile::TempDir {
        let dir = tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[test]
    fn exact_secret_loader_rejects_symlink() {
        let dir = private_tempdir();
        let target = dir.path().join("target.key");
        let link = dir.path().join("link.key");
        write_secret(&target, &[0x11; 32], 0o600);
        symlink(&target, &link).unwrap();

        assert!(read_exact_secret_v1::<32>(&link, "test key").is_err());
    }

    #[test]
    fn exact_secret_loader_rejects_group_or_world_access() {
        let dir = private_tempdir();
        let path = dir.path().join("wide.key");
        write_secret(&path, &[0x22; 32], 0o640);

        assert!(read_exact_secret_v1::<32>(&path, "test key").is_err());
    }

    #[test]
    fn exact_secret_loader_rejects_wrong_length() {
        let dir = private_tempdir();
        let short = dir.path().join("short.key");
        let long = dir.path().join("long.key");
        write_secret(&short, &[0x33; 31], 0o600);
        write_secret(&long, &[0x44; 33], 0o600);

        assert!(read_exact_secret_v1::<32>(&short, "test key").is_err());
        assert!(read_exact_secret_v1::<32>(&long, "test key").is_err());
    }

    #[test]
    fn exact_secret_loader_rejects_hardlink_and_fifo() {
        use std::process::Command;

        let dir = private_tempdir();
        let path = dir.path().join("secret.key");
        let hard = dir.path().join("hard.key");
        write_secret(&path, &[0x45; 32], 0o600);
        fs::hard_link(&path, &hard).unwrap();
        assert!(read_exact_secret_v1::<32>(&path, "test key").is_err());
        fs::remove_file(&hard).unwrap();

        let fifo = dir.path().join("fifo.key");
        assert!(Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        fs::set_permissions(&fifo, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_exact_secret_v1::<32>(&fifo, "test key").is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn exact_secret_loader_rejects_extended_acl() {
        use std::process::Command;

        let dir = private_tempdir();
        let path = dir.path().join("secret.key");
        write_secret(&path, &[0x46; 32], 0o600);
        assert!(Command::new("chmod")
            .args(["+a", "everyone allow read"])
            .arg(&path)
            .status()
            .unwrap()
            .success());
        assert!(read_exact_secret_v1::<32>(&path, "test key").is_err());
    }

    #[test]
    fn cashu_epoch_key_loader_requires_exact_paired_unique_configuration() {
        let dir = private_tempdir();
        let first = dir.path().join("first.key");
        let second = dir.path().join("second.key");
        write_secret(&first, &[0x31; 32], 0o600);
        write_secret(&second, &[0x32; 32], 0o600);
        let specs = vec![
            format!("1={}", first.display()),
            format!("2={}", second.display()),
        ];
        let mut loaded =
            load_cashu_epoch_keys_v1(Some(2), &specs, "--active", "--key", "test Cashu key")
                .unwrap();
        assert_eq!(loaded.as_ref().unwrap().0, 2);
        assert_eq!(loaded.as_ref().unwrap().1.len(), 2);
        zeroize_cashu_epoch_keys_v1(&mut loaded);

        assert!(
            load_cashu_epoch_keys_v1(None, &specs, "--active", "--key", "test Cashu key",).is_err()
        );
        assert!(
            load_cashu_epoch_keys_v1(Some(3), &specs, "--active", "--key", "test Cashu key",)
                .is_err()
        );
        let duplicate = vec![
            format!("1={}", first.display()),
            format!("1={}", second.display()),
        ];
        assert!(load_cashu_epoch_keys_v1(
            Some(1),
            &duplicate,
            "--active",
            "--key",
            "test Cashu key",
        )
        .is_err());

        write_secret(&second, &[0x31; 32], 0o600);
        let reused_bytes = vec![
            format!("1={}", first.display()),
            format!("2={}", second.display()),
        ];
        assert!(load_cashu_epoch_keys_v1(
            Some(2),
            &reused_bytes,
            "--active",
            "--key",
            "test Cashu key",
        )
        .is_err());
    }

    #[test]
    fn cashu_exposure_limit_parser_rejects_unbounded_and_duplicate_entries() {
        let mint = hex::encode([0x42; 32]);
        let parsed = parse_cashu_exposure_limits_v1(&[format!("{mint}:sat:1000:64")])
            .expect("finite Cashu cap");
        let cap = parsed.get(&([0x42; 32], "sat".to_owned())).unwrap();
        assert_eq!(cap.max_unsettled_value(), 1_000);
        assert_eq!(cap.max_unsettled_notes(), 64);

        assert!(parse_cashu_exposure_limits_v1(&[format!("{mint}:sat:0:64")]).is_err());
        assert!(parse_cashu_exposure_limits_v1(&[format!("{mint}:sat:{}:64", u64::MAX)]).is_err());
        assert!(parse_cashu_exposure_limits_v1(&[
            format!("{mint}:sat:1000:64"),
            format!("{mint}:sat:2000:128"),
        ])
        .is_err());
    }

    #[test]
    fn cashu_startup_inventory_must_fit_the_exact_finite_cap() {
        let limits = CashuCustodyExposureLimitsV1::new(100, 10).unwrap();
        let mut inventory = CashuCustodyInventoryV1 {
            pending_intent_value: 20,
            pending_intent_notes: 2,
            available_lot_count: 1,
            available_value: 30,
            available_notes: 3,
            reserved_lot_count: 1,
            reserved_value: 40,
            reserved_notes: 4,
            acknowledged_lot_count: 1,
            acknowledged_value: 10,
            acknowledged_notes: 1,
            spent_confirmed_lot_count: 1,
            spent_confirmed_value: u64::MAX,
            spent_confirmed_notes: u64::MAX,
            reserved_export_count: 1,
            materialized_export_count: 0,
            acknowledged_export_count: 1,
            spent_confirmed_export_count: 1,
        };
        assert_eq!(
            cashu_inventory_within_limits_v1(&inventory, limits),
            Ok(true),
            "delivery-acknowledged custody remains exposure; only spent-confirmed custody is excluded"
        );
        inventory.acknowledged_value += 1;
        assert_eq!(
            cashu_inventory_within_limits_v1(&inventory, limits),
            Ok(false)
        );
        inventory.acknowledged_value -= 1;
        inventory.acknowledged_notes += 1;
        assert_eq!(
            cashu_inventory_within_limits_v1(&inventory, limits),
            Ok(false)
        );
        inventory.acknowledged_value = u64::MAX;
        assert!(cashu_inventory_within_limits_v1(&inventory, limits).is_err());
    }

    fn private_directory(path: &std::path::Path) {
        fs::create_dir_all(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn sensitive_sqlite_path_requires_private_parent_owner_mode_and_no_symlink() {
        let dir = private_tempdir();
        let private = dir.path().join("private");
        private_directory(&private);
        let database = private.join("provider.sqlite3");
        fs::write(&database, b"state").unwrap();
        fs::set_permissions(&database, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(
            validate_existing_private_sqlite_path_v1(&database, "provider store")
                .unwrap_err()
                .contains("mode 0600")
        );

        fs::set_permissions(&database, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            validate_existing_private_sqlite_path_v1(&database, "provider store").unwrap(),
            private.canonicalize().unwrap().join("provider.sqlite3")
        );
        let link = private.join("provider-link.sqlite3");
        symlink(&database, &link).unwrap();
        assert!(validate_existing_private_sqlite_path_v1(&link, "provider store").is_err());

        let public = dir.path().join("public");
        fs::create_dir(&public).unwrap();
        fs::set_permissions(&public, fs::Permissions::from_mode(0o755)).unwrap();
        let public_database = public.join("provider.sqlite3");
        fs::write(&public_database, b"state").unwrap();
        fs::set_permissions(&public_database, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            validate_existing_private_sqlite_path_v1(&public_database, "provider store").is_err()
        );
    }

    #[test]
    fn sensitive_sqlite_path_rejects_same_inode_hardlinks() {
        let dir = private_tempdir();
        let private = dir.path().join("private");
        private_directory(&private);
        let store = private.join("provider.sqlite3");
        let authority = private.join("authority.sqlite3");
        fs::write(&store, b"state").unwrap();
        fs::set_permissions(&store, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&store, &authority).unwrap();
        assert!(validate_existing_private_sqlite_path_v1(&store, "provider store").is_err());
        assert!(validate_existing_private_sqlite_path_v1(
            &authority,
            "provider rollback authority"
        )
        .is_err());
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ExperimentalArcPolicyUsageV1 {
    any: bool,
    provider_local: bool,
}

impl ExperimentalArcPolicyUsageV1 {
    fn include(&mut self, other: Self) {
        self.any |= other.any;
        self.provider_local |= other.provider_local;
    }
}

fn experimental_arc_policy_usage_v1(policy: &ServicePolicyV1) -> ExperimentalArcPolicyUsageV1 {
    let mut usage = ExperimentalArcPolicyUsageV1::default();
    for scope in &policy.scopes {
        for offer in &scope.offers {
            if offer.authorization == pir_service_protocol::AuthScheme::ArcV1Experimental {
                usage.any = true;
                usage.provider_local |=
                    offer.verification == pir_service_protocol::VerificationMode::ProviderLocal;
            }
        }
    }
    usage
}

fn inspect_experimental_arc_policy_v1(
    canonical_signed_policy: &[u8],
    label: &str,
) -> Result<ExperimentalArcPolicyUsageV1, String> {
    let policy = ServicePolicyV1::decode(canonical_signed_policy)
        .map_err(|error| format!("{label} is not a canonical V1 service policy: {error}"))?;
    if policy
        .encode()
        .map_err(|error| format!("failed to re-encode {label}: {error}"))?
        .as_slice()
        != canonical_signed_policy
    {
        return Err(format!("{label} is not canonically encoded"));
    }
    Ok(experimental_arc_policy_usage_v1(&policy))
}

fn validate_experimental_arc_opt_in_v1(
    allow_experimental_arc: bool,
    policy_usage: ExperimentalArcPolicyUsageV1,
    provider_local_keys_configured: bool,
) -> Result<(), String> {
    let configured = policy_usage.any || provider_local_keys_configured;
    if !allow_experimental_arc && configured {
        return Err(
            "experimental ARC policy/key configuration requires explicit --allow-experimental-arc; ARC is unaudited and production-disabled"
                .to_owned(),
        );
    }
    if allow_experimental_arc && !configured {
        return Err(
            "--allow-experimental-arc was supplied but no current/retained ARC policy or provider-local ARC key is configured"
                .to_owned(),
        );
    }
    if provider_local_keys_configured && !policy_usage.provider_local {
        return Err(
            "--service-arc-key was supplied but no current/retained provider-local ARC policy uses it"
                .to_owned(),
        );
    }
    if policy_usage.provider_local && !provider_local_keys_configured {
        return Err(
            "current/retained provider-local ARC policy requires at least one --service-arc-key"
                .to_owned(),
        );
    }
    Ok(())
}

fn validate_legacy_experimental_arc_cli_v1(
    allow_experimental_arc: bool,
    require_arc: bool,
    arc_key_configured: bool,
    service_admission_v1_enabled: bool,
) -> Result<(), String> {
    let legacy_arc_configured = require_arc || arc_key_configured;
    if legacy_arc_configured && !allow_experimental_arc {
        return Err(
            "legacy experimental ARC configuration requires explicit --allow-experimental-arc; ARC is unaudited and production-disabled"
                .to_owned(),
        );
    }
    if arc_key_configured && !require_arc {
        return Err(
            "--arc-key requires --require-arc; refusing to ignore ARC key material".to_owned(),
        );
    }
    if allow_experimental_arc && !legacy_arc_configured && !service_admission_v1_enabled {
        return Err(
            "--allow-experimental-arc was supplied but neither legacy ARC nor service admission V1 is configured"
                .to_owned(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod experimental_arc_opt_in_tests_v1 {
    use super::{
        validate_experimental_arc_opt_in_v1, validate_legacy_experimental_arc_cli_v1,
        ExperimentalArcPolicyUsageV1,
    };

    #[test]
    fn acknowledgement_and_arc_configuration_must_be_exactly_paired() {
        let none = ExperimentalArcPolicyUsageV1::default();
        let shared = ExperimentalArcPolicyUsageV1 {
            any: true,
            provider_local: false,
        };
        let provider_local = ExperimentalArcPolicyUsageV1 {
            any: true,
            provider_local: true,
        };

        assert!(validate_experimental_arc_opt_in_v1(false, none, false).is_ok());
        assert!(validate_experimental_arc_opt_in_v1(true, none, false).is_err());
        assert!(validate_experimental_arc_opt_in_v1(false, shared, false).is_err());
        assert!(validate_experimental_arc_opt_in_v1(false, none, true).is_err());
        assert!(validate_experimental_arc_opt_in_v1(true, none, true).is_err());
        assert!(validate_experimental_arc_opt_in_v1(true, shared, false).is_ok());
        assert!(validate_experimental_arc_opt_in_v1(true, shared, true).is_err());
        assert!(validate_experimental_arc_opt_in_v1(true, provider_local, false).is_err());
        assert!(validate_experimental_arc_opt_in_v1(true, provider_local, true).is_ok());
    }

    #[test]
    fn legacy_arc_requires_the_same_explicit_acknowledgement() {
        assert!(validate_legacy_experimental_arc_cli_v1(false, false, false, false).is_ok());
        assert!(validate_legacy_experimental_arc_cli_v1(false, true, false, false).is_err());
        assert!(validate_legacy_experimental_arc_cli_v1(true, true, false, false).is_ok());
        assert!(validate_legacy_experimental_arc_cli_v1(true, false, true, false).is_err());
        assert!(validate_legacy_experimental_arc_cli_v1(true, false, false, false).is_err());
        assert!(validate_legacy_experimental_arc_cli_v1(true, false, false, true).is_ok());
    }
}

#[derive(Clone, Copy)]
enum ServiceRollbackAuthoritySourceV1<'a> {
    LocalSqlite(&'a Path),
    RemoteConfig(&'a Path),
}

fn service_rollback_authority_source_v1<'a>(
    local_sqlite: Option<&'a Path>,
    remote_config: Option<&'a Path>,
    allow_local_dev: bool,
) -> Result<ServiceRollbackAuthoritySourceV1<'a>, String> {
    match (local_sqlite, remote_config, allow_local_dev) {
        (Some(path), None, true) => Ok(ServiceRollbackAuthoritySourceV1::LocalSqlite(path)),
        (Some(_), None, false) => Err(
            "--service-rollback-authority is development/test-only and requires --allow-local-service-rollback-authority-dev"
                .to_owned(),
        ),
        (None, Some(path), false) => Ok(ServiceRollbackAuthoritySourceV1::RemoteConfig(path)),
        (None, Some(_), true) => Err(
            "--allow-local-service-rollback-authority-dev is valid only with --service-rollback-authority"
                .to_owned(),
        ),
        (None, None, true) => Err(
            "--allow-local-service-rollback-authority-dev requires --service-rollback-authority"
                .to_owned(),
        ),
        (None, None, false) => Err(
            "exactly one of --service-rollback-authority or --service-remote-rollback-authority-config is required"
                .to_owned(),
        ),
        (Some(_), Some(_), _) => Err(
            "--service-rollback-authority and --service-remote-rollback-authority-config are mutually exclusive"
                .to_owned(),
        ),
    }
}

fn open_remote_service_rollback_authority_v1(
    provider_id: [u8; 32],
    config_path: &Path,
) -> Result<Arc<dyn RollbackFloorAuthorityV1>, String> {
    let configured =
        load_remote_rollback_authority_deployment_for_business_domain_v1(config_path, provider_id)
            .map_err(|error| {
                format!("failed to load remote rollback-authority configuration: {error}")
            })?;
    let (client, codec, operation_timeout) = configured.into_parts();
    let authority =
        RemoteProviderRollbackFloorAuthorityV1::new(provider_id, client, codec, operation_timeout)
            .map_err(|error| format!("failed to construct remote rollback authority: {error}"))?;
    Ok(Arc::new(authority))
}

fn provider_store_startup_log_line_v1(elapsed_ms: u128) -> String {
    format!("  Provider store startup_check=ok elapsed_ms={elapsed_ms}")
}

#[cfg(test)]
mod service_rollback_authority_source_tests_v1 {
    use super::{
        provider_store_startup_log_line_v1, service_rollback_authority_source_v1,
        ServiceRollbackAuthoritySourceV1,
    };
    use std::path::Path;

    #[test]
    fn local_and_remote_sources_are_strictly_exclusive() {
        let local = Path::new("/local.sqlite3");
        let remote = Path::new("/remote.toml");
        assert!(matches!(
            service_rollback_authority_source_v1(Some(local), None, true).unwrap(),
            ServiceRollbackAuthoritySourceV1::LocalSqlite(path) if path == local
        ));
        assert!(matches!(
            service_rollback_authority_source_v1(None, Some(remote), false).unwrap(),
            ServiceRollbackAuthoritySourceV1::RemoteConfig(path) if path == remote
        ));
        assert!(service_rollback_authority_source_v1(Some(local), None, false).is_err());
        assert!(service_rollback_authority_source_v1(None, Some(remote), true).is_err());
        assert!(service_rollback_authority_source_v1(None, None, false).is_err());
        assert!(service_rollback_authority_source_v1(None, None, true).is_err());
        assert!(service_rollback_authority_source_v1(Some(local), Some(remote), false).is_err());
        assert!(service_rollback_authority_source_v1(Some(local), Some(remote), true).is_err());
    }

    #[test]
    fn serving_startup_log_omits_exact_business_inventory() {
        let line = provider_store_startup_log_line_v1(17);
        assert_eq!(line, "  Provider store startup_check=ok elapsed_ms=17");
        for forbidden in [
            "store_generation",
            "spend_commit_seq",
            "namespace_rows",
            "spent_capability_rows",
            "free_rate_limit_bucket_rows",
            "cashu_swap_intent_rows",
            "cashu_custody_lot_rows",
            "cashu_custody_note_rows",
            "cashu_custody_export_batch_rows",
        ] {
            assert!(!line.contains(forbidden), "leaked {forbidden}");
        }
    }
}

fn load_strict_service_admission_v1(
    args: &CliArgs,
    now_unix: u64,
) -> Result<Option<StrictServiceAdmissionRuntimeV1>, String> {
    #[cfg(feature = "standard-cashu-process-e2e")]
    let test_only_service_https_configured = args.test_only_service_https_root_pem.is_some();
    let has_partial_configuration = args.service_policy_path.is_some()
        || !args.service_retained_policy_paths.is_empty()
        || args.service_provider_id_hex.is_some()
        || args.service_policy_key_hex.is_some()
        || args.service_storeless_free_pow_policy_digest_hex.is_some()
        || args.service_store_path.is_some()
        || args.service_rollback_authority_path.is_some()
        || args.service_remote_rollback_authority_config_path.is_some()
        || args.allow_local_service_rollback_authority_dev
        || args.service_free_ip_key_path.is_some()
        || args.service_trust_direct_peer_ip
        || !args.service_bat_key_paths.is_empty()
        || !args.service_arc_key_specs.is_empty()
        || !args.service_cashu_recovery_key_specs.is_empty()
        || args.service_cashu_recovery_active_epoch.is_some()
        || !args.service_cashu_custody_key_specs.is_empty()
        || args.service_cashu_custody_active_epoch.is_some()
        || !args.service_cashu_exposure_limit_specs.is_empty()
        || args.service_shared_authorization_path.is_some()
        || args.service_shared_issuer_approval_path.is_some()
        || args.service_shared_operator_key_hex.is_some()
        || args.service_shared_issuer_settlement_key_hex.is_some()
        || args.service_shared_clearing_key_path.is_some()
        || args.service_shared_idempotency_key_path.is_some()
        || args.service_shared_minimum_authorization_epoch.is_some()
        || {
            #[cfg(feature = "standard-cashu-process-e2e")]
            {
                test_only_service_https_configured
            }
            #[cfg(not(feature = "standard-cashu-process-e2e"))]
            {
                false
            }
        };
    if !args.require_service_auth_v1 {
        if has_partial_configuration {
            return Err(
                "service-admission configuration requires --require-service-auth-v1; refusing to ignore security-sensitive flags"
                    .to_owned(),
            );
        }
        return Ok(None);
    }
    if args.require_arc || args.require_cashu {
        return Err(
            "--require-service-auth-v1 cannot be combined with legacy --require-arc/--require-cashu gates"
                .to_owned(),
        );
    }

    let policy_path = args
        .service_policy_path
        .as_deref()
        .ok_or_else(|| "--service-policy is required".to_owned())?;
    let provider_id = decode_fixed_hex_v1::<32>(
        args.service_provider_id_hex
            .as_deref()
            .ok_or_else(|| "--service-provider-id-hex is required".to_owned())?,
        "--service-provider-id-hex",
    )?;
    if provider_id.iter().all(|byte| *byte == 0) {
        return Err("--service-provider-id-hex must not be all zero".to_owned());
    }
    let verifying_key_bytes = decode_fixed_hex_v1::<32>(
        args.service_policy_key_hex
            .as_deref()
            .ok_or_else(|| "--service-policy-key-hex is required".to_owned())?,
        "--service-policy-key-hex",
    )?;
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
        .map_err(|_| "--service-policy-key-hex is not a valid Ed25519 public key".to_owned())?;
    let signed_policy = read_regular_file_bounded_v1(
        policy_path,
        SERVICE_CONFIG_FILE_LIMIT_V1,
        "signed service policy",
    )?;
    let storeless_free_pow_policy_digest = args
        .service_storeless_free_pow_policy_digest_hex
        .as_deref()
        .map(|value| {
            decode_fixed_hex_v1::<32>(value, "--service-storeless-free-pow-policy-digest-hex")
        })
        .transpose()?;
    if storeless_free_pow_policy_digest.is_some()
        && (!args.service_retained_policy_paths.is_empty()
            || args.arc_key_path.is_some()
            || !args.cashu_keysets.is_empty()
            || args.service_store_path.is_some()
            || args.service_rollback_authority_path.is_some()
            || args.service_remote_rollback_authority_config_path.is_some()
            || args.allow_local_service_rollback_authority_dev
            || args.service_free_ip_key_path.is_some()
            || args.service_trust_direct_peer_ip
            || !args.service_bat_key_paths.is_empty()
            || !args.service_arc_key_specs.is_empty()
            || args.allow_experimental_arc
            || !args.service_cashu_recovery_key_specs.is_empty()
            || args.service_cashu_recovery_active_epoch.is_some()
            || !args.service_cashu_custody_key_specs.is_empty()
            || args.service_cashu_custody_active_epoch.is_some()
            || !args.service_cashu_exposure_limit_specs.is_empty()
            || args.service_shared_authorization_path.is_some()
            || args.service_shared_issuer_approval_path.is_some()
            || args.service_shared_operator_key_hex.is_some()
            || args.service_shared_issuer_settlement_key_hex.is_some()
            || args.service_shared_clearing_key_path.is_some()
            || args.service_shared_idempotency_key_path.is_some()
            || args.service_shared_minimum_authorization_epoch.is_some()
            || {
                #[cfg(feature = "standard-cashu-process-e2e")]
                {
                    test_only_service_https_configured
                }
                #[cfg(not(feature = "standard-cashu-process-e2e"))]
                {
                    false
                }
            })
    {
        return Err(
            "storeless Free-PoW mode forbids retained policies, stores, rollback authorities, Free IP quota, credential/payment keys, legacy or V1 Cashu/ARC, shared issuer, and test HTTPS configuration"
                .to_owned(),
        );
    }
    let mut experimental_arc_usage =
        inspect_experimental_arc_policy_v1(&signed_policy, "signed service policy")?;
    let mut retained_policy_inputs = Vec::with_capacity(args.service_retained_policy_paths.len());
    for retained_path in &args.service_retained_policy_paths {
        let retained_bytes = read_regular_file_bounded_v1(
            retained_path,
            SERVICE_CONFIG_FILE_LIMIT_V1,
            "retained signed service policy",
        )?;
        experimental_arc_usage.include(inspect_experimental_arc_policy_v1(
            &retained_bytes,
            &format!("retained signed service policy {}", retained_path.display()),
        )?);
        retained_policy_inputs.push((retained_path.clone(), retained_bytes));
    }
    validate_experimental_arc_opt_in_v1(
        args.allow_experimental_arc,
        experimental_arc_usage,
        !args.service_arc_key_specs.is_empty(),
    )?;
    if experimental_arc_usage.any {
        eprintln!(
            "!!! WARNING: EXPERIMENTAL ARC ENABLED FOR THIS PIR SERVER; THE PINNED DRAFT-01 IMPLEMENTATION IS UNAUDITED AND MUST NOT BE USED IN PRODUCTION !!!"
        );
    }
    let provider_store = if storeless_free_pow_policy_digest.is_some() {
        None
    } else {
        let provider_store_path = args
            .service_store_path
            .as_deref()
            .ok_or_else(|| "--service-store is required".to_owned())?;
        let rollback_source = service_rollback_authority_source_v1(
            args.service_rollback_authority_path.as_deref(),
            args.service_remote_rollback_authority_config_path
                .as_deref(),
            args.allow_local_service_rollback_authority_dev,
        )?;
        let canonical_store =
            validate_existing_private_sqlite_path_v1(provider_store_path, "provider spend store")?;

        let options = StoreOptions::default();
        let store_startup_check_started = Instant::now();
        let rollback_authority: Arc<dyn RollbackFloorAuthorityV1> = match rollback_source {
            ServiceRollbackAuthoritySourceV1::LocalSqlite(path) => {
                let canonical_rollback =
                    validate_existing_private_sqlite_path_v1(path, "provider rollback authority")?;
                if private_sqlite_paths_alias_v1(&canonical_store, &canonical_rollback)? {
                    return Err(
                        "provider store and rollback authority must be different files/inodes"
                            .to_owned(),
                    );
                }
                eprintln!(
                    "!!! WARNING: LOCAL SQLITE SERVICE ROLLBACK AUTHORITY IS DEVELOPMENT/TEST ONLY; USE --service-remote-rollback-authority-config FOR PRODUCTION !!!"
                );
                Arc::new(
                    SqliteRollbackFloorAuthorityV1::open_existing(
                        &canonical_rollback,
                        options.busy_timeout,
                    )
                    .map_err(|error| format!("failed to open rollback authority: {error}"))?,
                )
            }
            ServiceRollbackAuthoritySourceV1::RemoteConfig(path) => {
                open_remote_service_rollback_authority_v1(provider_id, path)?
            }
        };
        let store = ProviderStore::open_existing(
            &canonical_store,
            provider_id,
            options,
            rollback_authority,
        )
        .map_err(|error| format!("failed to open provider spend store: {error}"))?;
        let _store_inventory = store.operational_inventory().map_err(|error| {
            format!("failed to read provider store operational inventory: {error}")
        })?;
        let startup_line =
            provider_store_startup_log_line_v1(store_startup_check_started.elapsed().as_millis());
        println!("{startup_line}");
        Some(store)
    };

    let free_ip_subject_key = match args.service_free_ip_key_path.as_deref() {
        Some(path) => Some(
            FreeIpSubjectKeyV1::from_bytes(read_exact_secret_v1::<32>(
                path,
                "service Free IP HMAC key",
            )?)
            .map_err(|error| format!("invalid service Free IP HMAC key: {error}"))?,
        ),
        None => None,
    };
    if args.service_trust_direct_peer_ip && free_ip_subject_key.is_none() {
        return Err("--service-trust-direct-peer-ip requires --service-free-ip-key".to_owned());
    }

    let bat_keyring = if args.service_bat_key_paths.is_empty() {
        None
    } else {
        let mut secret_keys = Vec::with_capacity(args.service_bat_key_paths.len());
        for path in &args.service_bat_key_paths {
            secret_keys.push(read_exact_secret_v1::<32>(path, "service Cashu BAT key")?);
        }
        let result = K256CashuMintKeyringV1::from_secret_keys(secret_keys.iter().copied())
            .map_err(|error| format!("invalid service Cashu BAT keyring: {error}"));
        secret_keys.zeroize();
        Some(result?)
    };

    let experimental_arc_keyring = if args.service_arc_key_specs.is_empty() {
        None
    } else {
        let mut keys = Vec::with_capacity(args.service_arc_key_specs.len());
        for spec in &args.service_arc_key_specs {
            let (key_id_hex, path) = spec.split_once('=').ok_or_else(|| {
                "--service-arc-key must be <hex-key-id>=<raw-128-byte-key-path>".to_owned()
            })?;
            let key_id = hex::decode(key_id_hex)
                .map_err(|_| "--service-arc-key key ID is not valid hex".to_owned())?;
            if key_id.is_empty() || key_id.len() > pir_service_protocol::MAX_CREDENTIAL_KEY_ID_LEN {
                return Err(format!(
                    "--service-arc-key key ID must contain 1..={} bytes",
                    pir_service_protocol::MAX_CREDENTIAL_KEY_ID_LEN
                ));
            }
            if path.is_empty() {
                return Err("--service-arc-key path is empty".to_owned());
            }
            let secret = Zeroizing::new(read_exact_secret_v1::<
                { pir_arc_adapter::ARC_SECRET_KEY_LEN_V1 },
            >(
                std::path::Path::new(path),
                "experimental ARC private key",
            )?);
            keys.push(
                ArcSecretKeyV1::from_zeroizing_bytes(key_id, secret)
                    .map_err(|error| format!("invalid experimental ARC private key: {error}"))?,
            );
        }
        Some(
            ArcSecretKeyringV1::new(keys)
                .map_err(|error| format!("invalid experimental ARC keyring: {error}"))?,
        )
    };

    let mut cashu_recovery_key_material = load_cashu_epoch_keys_v1(
        args.service_cashu_recovery_active_epoch,
        &args.service_cashu_recovery_key_specs,
        "--service-cashu-recovery-active-epoch",
        "--service-cashu-recovery-key",
        "standard Cashu recovery key",
    )?;
    let mut cashu_custody_key_material = match load_cashu_epoch_keys_v1(
        args.service_cashu_custody_active_epoch,
        &args.service_cashu_custody_key_specs,
        "--service-cashu-custody-active-epoch",
        "--service-cashu-custody-key",
        "standard Cashu custody key",
    ) {
        Ok(material) => material,
        Err(error) => {
            zeroize_cashu_epoch_keys_v1(&mut cashu_recovery_key_material);
            return Err(error);
        }
    };
    if let (Some((_, recovery_keys)), Some((_, custody_keys))) = (
        cashu_recovery_key_material.as_ref(),
        cashu_custody_key_material.as_ref(),
    ) {
        if recovery_keys.iter().any(|(_, recovery_key)| {
            custody_keys
                .iter()
                .any(|(_, custody_key)| recovery_key == custody_key)
        }) {
            zeroize_cashu_epoch_keys_v1(&mut cashu_recovery_key_material);
            zeroize_cashu_epoch_keys_v1(&mut cashu_custody_key_material);
            return Err(
                "standard Cashu recovery and custody keyrings must use distinct key material"
                    .to_owned(),
            );
        }
    }
    let cashu_recovery_cipher =
        match cashu_recovery_key_material.take() {
            None => None,
            Some((active_epoch, mut keys)) => {
                let result = ChaCha20Poly1305RecoveryCipherV1::new(
                    active_epoch,
                    keys.iter().map(|(epoch, key)| (*epoch, *key)),
                );
                for (_, key) in &mut keys {
                    key.zeroize();
                }
                Some(result.map_err(|error| {
                    format!("invalid standard Cashu recovery keyring: {error:?}")
                })?)
            }
        };
    let cashu_custody_cipher =
        match cashu_custody_key_material.take() {
            None => None,
            Some((active_epoch, mut keys)) => {
                let result = ChaCha20Poly1305CustodyCipherV1::new(
                    active_epoch,
                    keys.iter().map(|(epoch, key)| (*epoch, *key)),
                );
                for (_, key) in &mut keys {
                    key.zeroize();
                }
                Some(result.map_err(|error| {
                    format!("invalid standard Cashu custody keyring: {error:?}")
                })?)
            }
        };
    let cashu_exposure_limits =
        parse_cashu_exposure_limits_v1(&args.service_cashu_exposure_limit_specs)?;

    let shared_field_count = [
        args.service_shared_authorization_path.is_some(),
        args.service_shared_issuer_approval_path.is_some(),
        args.service_shared_operator_key_hex.is_some(),
        args.service_shared_issuer_settlement_key_hex.is_some(),
        args.service_shared_clearing_key_path.is_some(),
        args.service_shared_idempotency_key_path.is_some(),
        args.service_shared_minimum_authorization_epoch.is_some(),
    ]
    .into_iter()
    .filter(|configured| *configured)
    .count();
    let shared_issuer = if shared_field_count == 0 {
        None
    } else if shared_field_count != 7 {
        return Err(
            "shared issuer clearing requires all --service-shared-* authorization, approval, operator key, issuer settlement key, clearing key, idempotency key and minimum epoch fields"
                .to_owned(),
        );
    } else {
        let authorization_bytes = read_regular_file_bounded_v1(
            args.service_shared_authorization_path
                .as_deref()
                .expect("count checked"),
            SERVICE_CONFIG_FILE_LIMIT_V1,
            "provider clearing authorization",
        )?;
        let authorization = ProviderClearingAuthorizationV1::decode(&authorization_bytes)
            .map_err(|error| format!("invalid provider clearing authorization: {error}"))?;
        if authorization
            .encode()
            .map_err(|error| format!("invalid provider clearing authorization: {error}"))?
            != authorization_bytes
        {
            return Err("provider clearing authorization is not canonical".to_owned());
        }
        let approval_bytes = read_regular_file_bounded_v1(
            args.service_shared_issuer_approval_path
                .as_deref()
                .expect("count checked"),
            SERVICE_CONFIG_FILE_LIMIT_V1,
            "issuer clearing approval",
        )?;
        let issuer_approval = IssuerClearingApprovalV1::decode(&approval_bytes)
            .map_err(|error| format!("invalid issuer clearing approval: {error}"))?;
        if issuer_approval.encode() != approval_bytes {
            return Err("issuer clearing approval is not canonical".to_owned());
        }
        let operator_verifying_key = VerifyingKey::from_bytes(&decode_fixed_hex_v1::<32>(
            args.service_shared_operator_key_hex
                .as_deref()
                .expect("count checked"),
            "--service-shared-operator-key-hex",
        )?)
        .map_err(|_| "shared operator key is not valid Ed25519".to_owned())?;
        let issuer_settlement_verifying_key = VerifyingKey::from_bytes(&decode_fixed_hex_v1::<32>(
            args.service_shared_issuer_settlement_key_hex
                .as_deref()
                .expect("count checked"),
            "--service-shared-issuer-settlement-key-hex",
        )?)
        .map_err(|_| "shared issuer settlement key is not valid Ed25519".to_owned())?;
        let mut clearing_key_bytes = read_exact_secret_v1::<32>(
            args.service_shared_clearing_key_path
                .as_deref()
                .expect("count checked"),
            "provider clearing signing key",
        )?;
        let clearing_signing_key = ed25519_dalek::SigningKey::from_bytes(&clearing_key_bytes);
        clearing_key_bytes.zeroize();
        let idempotency_key = Zeroizing::new(read_exact_secret_v1::<32>(
            args.service_shared_idempotency_key_path
                .as_deref()
                .expect("count checked"),
            "provider clearing idempotency key",
        )?);
        let minimum_authorization_epoch = args
            .service_shared_minimum_authorization_epoch
            .expect("count checked");
        if minimum_authorization_epoch == 0 {
            return Err("shared minimum authorization epoch must be non-zero".to_owned());
        }
        Some(SharedIssuerRuntimeConfigV1 {
            authorization,
            issuer_approval,
            operator_verifying_key,
            issuer_settlement_verifying_key,
            clearing_signing_key,
            minimum_authorization_epoch,
            idempotency_key,
        })
    };

    #[cfg(feature = "standard-cashu-process-e2e")]
    let test_only_webpki_root_pem = args
        .test_only_service_https_root_pem
        .as_deref()
        .map(|path| {
            pir_private_files::read_private_file_bounded_v1(
                path,
                16 * 1024,
                pir_private_files::PrivateFileModeV1::ReadOnlyOrReadWrite,
                "test-only service WebPKI root",
            )
            .map(|bytes| Arc::<[u8]>::from(bytes.as_slice()))
        })
        .transpose()?;
    let http_transport = ProviderAdmissionHttpsTransportV1 {
        connect_timeout: Duration::from_secs(5),
        io_timeout: Duration::from_secs(15),
        #[cfg(feature = "standard-cashu-process-e2e")]
        test_only_webpki_root_pem,
    };
    if let Some(shared) = shared_issuer.as_ref() {
        http_transport
            .validate_trust(
                &shared.authorization.claims.redeem_endpoint,
                &shared.authorization.claims.redeem_leaf_spki_sha256_pins,
            )
            .map_err(|error| format!("shared issuer HTTPS trust is invalid: {error}"))?;
        shared
            .committer(
                provider_store.as_ref().ok_or_else(|| {
                    "shared issuer configuration requires a provider store".to_owned()
                })?,
                &http_transport,
            )
            .map_err(|error| format!("shared issuer clearing configuration is invalid: {error}"))?;
        shared
            .authorization
            .verify_for(
                &provider_id,
                &shared.authorization.claims.issuer_id,
                &shared.operator_verifying_key,
                now_unix,
                shared.minimum_authorization_epoch,
            )
            .map_err(|error| format!("provider clearing authorization is not current: {error}"))?;
        shared
            .issuer_approval
            .verify_for(
                &shared.authorization,
                &shared.issuer_settlement_verifying_key,
                now_unix,
                shared.minimum_authorization_epoch,
            )
            .map_err(|error| format!("issuer clearing approval is not current: {error}"))?;
    }

    let policy = match storeless_free_pow_policy_digest {
        Some(expected_digest) => activate_exact_storeless_free_pow_policy_v1(
            &signed_policy,
            provider_id,
            verifying_key,
            expected_digest,
            now_unix,
        ),
        None => activate_service_policy_v1(
            &signed_policy,
            provider_id,
            verifying_key,
            provider_store
                .as_ref()
                .ok_or_else(|| "provider store is unavailable".to_owned())?,
            now_unix,
            experimental_arc_keyring
                .as_ref()
                .map(|keyring| keyring as &dyn pir_service_store::ArcExclusiveKeyLineageVerifierV1),
        ),
    }
    .map_err(|error| format!("failed to activate signed service policy: {error}"))?;
    let mut retained_policies = BTreeMap::new();
    for (retained_path, retained_bytes) in retained_policy_inputs {
        let retained =
            activate_retained_service_policy_v1(&retained_bytes, &policy).map_err(|error| {
                format!(
                    "failed to activate retained service policy {}: {error} \
                     (V1 requires every retained policy to verify under the current \
                     --service-policy-key-hex)",
                    retained_path.display()
                )
            })?;
        let digest = retained.policy_digest();
        if retained_policies.insert(digest, retained).is_some() {
            return Err(format!(
                "duplicate retained service policy digest {}",
                hex::encode(digest)
            ));
        }
    }
    let free_rate_limits = Arc::new(match provider_store.as_ref() {
        Some(store) => FreeRateLimitStateV1::provider_store(
            store.clone(),
            pir_runtime_core::free_admission::DEFAULT_MAX_FREE_RATE_LIMIT_BUCKETS_V1,
        ),
        None => FreeRateLimitStateV1::new(
            pir_runtime_core::free_admission::DEFAULT_MAX_FREE_RATE_LIMIT_BUCKETS_V1,
        ),
    });
    let runtime = StrictServiceAdmissionRuntimeV1 {
        policy,
        retained_policies,
        provider_store,
        free_rate_limits,
        free_ip_subject_key,
        trust_direct_peer_ip: args.service_trust_direct_peer_ip,
        bat_keyring,
        experimental_arc_keyring,
        cashu_recovery_cipher,
        cashu_custody_cipher,
        cashu_exposure_limits,
        shared_issuer,
        http_transport,
        harmony_attach_registry: Arc::new(HarmonyAttachRegistryV1::default()),
        monotonic_origin: Instant::now(),
    };
    validate_cashu_runtime_configuration_v1(&runtime)?;
    validate_policy_method_coverage_v1(runtime.policy.policy(), |route| runtime.supports(route))
        .map_err(|error| format!("incomplete service admission configuration: {error}"))?;
    for retained in runtime.retained_policies.values() {
        validate_retained_policy_method_coverage_v1(retained.policy(), |route| {
            runtime.supports(route)
        })
        .map_err(|error| {
            format!(
                "incomplete retained-policy redemption configuration for {}: {error}",
                hex::encode(retained.policy_digest())
            )
        })?;
        for scope_policy in &retained.policy().scopes {
            let scope_id = scope_policy.scope.scope_id();
            for offer in &scope_policy.offers {
                if offer.credential_binding.is_none() {
                    continue;
                }
                let verified_offer = retained
                    .verified_offer_for_redemption(
                        &scope_id,
                        offer.offer_id,
                        retained.policy().issued_at,
                    )
                    .map_err(|error| {
                        format!(
                            "retained policy {} has an invalid redemption offer: {error}",
                            hex::encode(retained.policy_digest())
                        )
                    })?;
                let readiness = runtime
                    .provider_store
                    .as_ref()
                    .ok_or_else(|| "retained policy requires a provider store".to_owned())?
                    .verify_existing_verified_offer_namespace_v1(
                        &verified_offer,
                        retained.policy().issued_at,
                        runtime.experimental_arc_keyring.as_ref().map(|keyring| {
                            keyring as &dyn pir_service_store::ArcExclusiveKeyLineageVerifierV1
                        }),
                    )
                    .map_err(|error| {
                        format!(
                            "retained policy {} is missing exact durable redemption state: {error}",
                            hex::encode(retained.policy_digest())
                        )
                    })?;
                if readiness
                    == pir_service_store::VerifiedOfferNamespaceReadinessV1::UnsupportedExperimental
                {
                    return Err(format!(
                        "retained policy {} requires an unavailable experimental ARC adapter",
                        hex::encode(retained.policy_digest())
                    ));
                }
            }
        }
    }

    for configured_policy in runtime.all_policies() {
        for scope in &configured_policy.scopes {
            for offer in &scope.offers {
                if offer.credential_binding.is_none() {
                    continue;
                }
                if offer.verification == pir_service_protocol::VerificationMode::SharedIssuerOnline
                {
                    let shared = runtime.shared_issuer.as_ref().ok_or_else(|| {
                        "policy advertises shared issuer redemption without clearing configuration"
                            .to_owned()
                    })?;
                    let binding = offer.credential_binding.as_ref().ok_or_else(|| {
                        "shared issuer offer is missing its credential binding".to_owned()
                    })?;
                    let digest = binding
                        .binding_digest()
                        .map_err(|error| format!("invalid shared issuer binding: {error}"))?;
                    shared
                        .authorization
                        .rule_for_binding(&digest)
                        .ok_or_else(|| {
                            "shared issuer clearing authorization has no rule for an advertised offer"
                                .to_owned()
                        })?;
                    if offer.issuer_id != shared.authorization.claims.issuer_id
                        || scope.scope.provider_id != shared.authorization.claims.provider_id
                        || offer.endpoint != shared.authorization.claims.redeem_endpoint
                    {
                        return Err(
                            "shared issuer offer audience or endpoint does not match clearing authorization"
                                .to_owned(),
                        );
                    }
                }
            }
        }
    }

    if let Some(keyring) = runtime.bat_keyring.as_ref() {
        let retained = keyring.denomination_public_keys();
        for configured_policy in runtime.all_policies() {
            for scope in &configured_policy.scopes {
                for offer in &scope.offers {
                    if offer.credential_binding.is_none() {
                        continue;
                    }
                    if offer.authorization == pir_service_protocol::AuthScheme::BitcoinPirCashuBatV1
                        && offer.verification
                            == pir_service_protocol::VerificationMode::ProviderLocal
                    {
                        let verification_key = offer
                            .credential_binding
                            .as_ref()
                            .and_then(|binding| {
                                <[u8; 33]>::try_from(binding.claims.verification_key.as_slice())
                                    .ok()
                            })
                            .ok_or_else(|| {
                                "provider-local BAT offer has no exact 33-byte verification key"
                                    .to_owned()
                            })?;
                        if !retained.contains(&verification_key) {
                            return Err(
                                "provider-local BAT offer references a key not retained by this server"
                                    .to_owned(),
                            );
                        }
                    }
                }
            }
        }
    }
    Ok(Some(runtime))
}

fn validate_cashu_runtime_configuration_v1(
    runtime: &StrictServiceAdmissionRuntimeV1,
) -> Result<(), String> {
    let mut required = std::collections::BTreeSet::new();
    for policy in runtime.all_policies() {
        for scope in &policy.scopes {
            for offer in &scope.offers {
                if let Some(manifest) = offer.cashu_mint_manifest.as_ref() {
                    runtime
                        .http_transport
                        .validate_trust(&manifest.mint_endpoint, &manifest.leaf_spki_sha256_pins)
                        .map_err(|error| {
                            format!("standard Cashu mint HTTPS trust is invalid: {error}")
                        })?;
                    required.insert((manifest.mint_id(), manifest.unit.clone()));
                }
            }
        }
    }

    if required.is_empty() {
        if runtime.cashu_recovery_cipher.is_some()
            || runtime.cashu_custody_cipher.is_some()
            || !runtime.cashu_exposure_limits.is_empty()
        {
            return Err(
                "standard Cashu keys or limits were configured but no current/retained policy advertises standard Cashu"
                    .to_owned(),
            );
        }
        return Ok(());
    }
    if runtime.cashu_recovery_cipher.is_none() || runtime.cashu_custody_cipher.is_none() {
        return Err(
            "every standard Cashu offer requires separate recovery and custody keyrings".to_owned(),
        );
    }
    for (mint_id, unit) in &required {
        let limits = runtime
            .cashu_exposure_limits
            .get(&(*mint_id, unit.clone()))
            .ok_or_else(|| {
                format!(
                    "standard Cashu offer for mint {} unit {} has no exact finite exposure limit",
                    hex::encode(mint_id),
                    unit,
                )
            })?;
        let inventory = runtime
            .provider_store
            .as_ref()
            .ok_or_else(|| "standard Cashu requires a provider store".to_owned())?
            .cashu_custody_inventory_v1(mint_id, unit)
            .map_err(|error| {
                format!(
                    "failed to validate standard Cashu exposure for mint {} unit {}: {error}",
                    hex::encode(mint_id),
                    unit,
                )
            })?;
        if !cashu_inventory_within_limits_v1(&inventory, *limits)? {
            return Err(format!(
                "existing standard Cashu exposure for mint {} unit {} exceeds its configured finite cap",
                hex::encode(mint_id),
                unit,
            ));
        }
    }
    for (mint_id, unit) in runtime.cashu_exposure_limits.keys() {
        if !required.contains(&(*mint_id, unit.clone())) {
            return Err(format!(
                "standard Cashu exposure limit for mint {} unit {} is not referenced by any current/retained policy",
                hex::encode(mint_id),
                unit,
            ));
        }
    }
    Ok(())
}

fn cashu_inventory_within_limits_v1(
    inventory: &CashuCustodyInventoryV1,
    limits: CashuCustodyExposureLimitsV1,
) -> Result<bool, String> {
    let unsettled_value = inventory
        .pending_intent_value
        .checked_add(inventory.available_value)
        .and_then(|value| value.checked_add(inventory.reserved_value))
        .and_then(|value| value.checked_add(inventory.acknowledged_value))
        .ok_or_else(|| {
            "standard Cashu startup exposure value overflowed; refusing activation".to_owned()
        })?;
    let unsettled_notes = inventory
        .pending_intent_notes
        .checked_add(inventory.available_notes)
        .and_then(|value| value.checked_add(inventory.reserved_notes))
        .and_then(|value| value.checked_add(inventory.acknowledged_notes))
        .ok_or_else(|| {
            "standard Cashu startup exposure note count overflowed; refusing activation".to_owned()
        })?;
    Ok(unsettled_value <= limits.max_unsettled_value()
        && unsettled_notes <= limits.max_unsettled_notes())
}

// ─── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let args = parse_args();
    let online_v2full_auth_limit = online_v2full_auth_limit_v1(
        args.pool_size,
        args.service_max_concurrent_auth,
        args.service_max_concurrent_online_v2full_auth,
    )
    .unwrap_or_else(|error| fatal_cli(error));
    validate_legacy_experimental_arc_cli_v1(
        args.allow_experimental_arc,
        args.require_arc,
        args.arc_key_path.is_some(),
        args.require_service_auth_v1,
    )
    .unwrap_or_else(|error| fatal_cli(error));
    if args.require_arc {
        eprintln!(
            "!!! WARNING: EXPERIMENTAL ARC ENABLED FOR THIS PIR SERVER; THE IMPLEMENTATION IS UNAUDITED AND MUST NOT BE USED IN PRODUCTION !!!"
        );
    }
    #[cfg(any(test, feature = "test-only-unsafe-query-logging"))]
    {
        UNSAFE_DEBUG_QUERY_LOGGING.store(args.unsafe_debug_query_logging, Ordering::Relaxed);
        if args.unsafe_debug_query_logging {
            eprintln!(
                "!!! UNSAFE DEBUG QUERY LOGGING ENABLED: logs may expose peer IPs, client IDs, request timing, database/group selections and byte sizes; never enable in production !!!"
            );
        }
    }
    let role_name = match args.role {
        ServerRole::Primary => "primary",
        ServerRole::Secondary => "secondary",
    };

    // ── Mode validation ────────────────────────────────────────────────
    // The server's accepted-opcode set is gated by two independent flags:
    //   --serve-hints   → REQ_HARMONY_HINTS / REQ_HARMONY_HINTS_V2
    //   --serve-queries → all PIR query opcodes (DPF batches, OnionPIR
    //                      queries, HarmonyPIR query phase, Merkle siblings,
    //                      tree-tops, batched index/chunk)
    // At least one must be enabled, else the server has no useful role.
    // Run-mode logged below; configure on each unit file (see
    // `deploy/systemd/pir-primary.service` and
    // `deploy/systemd/pir-secondary.service`).
    if !args.serve_hints && !args.serve_queries {
        eprintln!(
            "ERROR: must enable at least one of --serve-hints / --serve-queries.\n  \
             Hint-only deployment (HarmonyPIR V2 pool):  --serve-hints --pool-size N [--pool-db-id ID]\n  \
             Query-only deployment (DPF / OnionPIR / HarmonyPIR query): --serve-queries\n  \
             Both (legacy single-host or pir1 Hetzner topology):       --serve-hints --serve-queries"
        );
        std::process::exit(2);
    }

    println!("=== Unified PIR Server ({}) ===", role_name);
    println!("  Bind:     {}:{}", args.bind_address, args.port);
    println!(
        "  Mode:     hints={}, queries={}",
        if args.serve_hints { "yes" } else { "no" },
        if args.serve_queries { "yes" } else { "no" },
    );
    if let Some(ref config_path) = args.config_path {
        println!("  Config:   {}", config_path.display());
    } else {
        println!("  Data dir: {}", args.data_dir.display());
        for (path, height) in &args.checkpoints {
            println!("  Checkpoint: {} (height={})", path.display(), height);
        }
        for (path, base, tip) in &args.deltas {
            println!("  Delta:      {} ({}→{})", path.display(), base, tip);
        }
    }
    println!();

    let total_start = Instant::now();

    // ── Load databases ─────────────────────────────────────────────────
    let mut all_databases: Vec<MappedDatabase> = Vec::new();
    // Per-DB source directories for OnionPIR loading (db_id, label, path).
    // Populated alongside `all_databases` so OnionPIR setup can iterate over
    // every loaded DB and look for its OnionPIR files.
    let mut db_paths: Vec<(u8, String, PathBuf)> = Vec::new();

    if let Some(ref config_path) = args.config_path {
        let config = ServerConfig::load(config_path);
        println!(
            "[config] Loaded {} databases from {}",
            config.databases.len(),
            config_path.display()
        );

        for (i, db_cfg) in config.databases.iter().enumerate() {
            let db_type = match db_cfg.db_type.as_str() {
                "delta" => DatabaseType::Delta,
                _ => DatabaseType::Full,
            };
            let db_path = config.db_path(i);
            let mut db = MappedDatabase::load(
                &db_path,
                DatabaseDescriptor {
                    name: db_cfg.name.clone(),
                    db_type,
                    base_height: db_cfg.base_height,
                    height: db_cfg.height,
                    index_params: INDEX_PARAMS,
                    chunk_params: CHUNK_PARAMS,
                },
            );
            if let Some(proof_dir) = db_cfg.proof_dir.as_ref() {
                db.db_proof = Some(
                    load_database_proof_bundle(i as u8, proof_dir).unwrap_or_else(|e| {
                        panic!(
                            "[config] failed to load proof_dir for db {} from {}: {}",
                            db_cfg.name,
                            proof_dir.display(),
                            e
                        )
                    }),
                );
                println!(
                    "[config] DB proof loaded for db_id={} name={} from {}",
                    i,
                    db_cfg.name,
                    proof_dir.display()
                );
            }
            if let Some(proof_dir) = db_cfg.proof_v2_dir.as_ref() {
                db.db_proof_v2 = Some(
                    load_database_proof_bundle(i as u8, proof_dir).unwrap_or_else(|e| {
                        panic!(
                            "[config] failed to load proof_v2_dir for db {} from {}: {}",
                            db_cfg.name,
                            proof_dir.display(),
                            e
                        )
                    }),
                );
                println!(
                    "[config] DB proof v2 loaded for db_id={} name={} from {}",
                    i,
                    db_cfg.name,
                    proof_dir.display()
                );
            }
            let type_label = if db_type == DatabaseType::Delta {
                format!("Delta:{}→{}", db_cfg.base_height, db_cfg.height)
            } else {
                format!("Full:{}", db_cfg.height)
            };
            println!(
                "[{}] INDEX bins={}, CHUNK bins={}, dpf_n_index={}, dpf_n_chunk={}",
                type_label,
                db.index.bins_per_table,
                db.chunk.bins_per_table,
                params::compute_dpf_n(db.index.bins_per_table),
                params::compute_dpf_n(db.chunk.bins_per_table)
            );
            db_paths.push((i as u8, db_cfg.name.clone(), db_path));
            all_databases.push(db);
        }
    } else {
        // Legacy CLI mode: --data-dir + --checkpoint + --delta

        let main_db = MappedDatabase::load(
            &args.data_dir,
            DatabaseDescriptor {
                name: "main".to_string(),
                db_type: DatabaseType::Full,
                base_height: 0,
                height: 0,
                index_params: INDEX_PARAMS,
                chunk_params: CHUNK_PARAMS,
            },
        );

        db_paths.push((0u8, "main".to_string(), args.data_dir.clone()));
        all_databases.push(main_db);

        for (path, height) in &args.checkpoints {
            let name = format!("checkpoint_{}", height);
            let db = MappedDatabase::load(
                path,
                DatabaseDescriptor {
                    name: name.clone(),
                    db_type: DatabaseType::Full,
                    base_height: 0,
                    height: *height,
                    index_params: INDEX_PARAMS,
                    chunk_params: CHUNK_PARAMS,
                },
            );
            println!(
                "[Checkpoint:{}] INDEX bins={}, CHUNK bins={}, dpf_n_index={}, dpf_n_chunk={}",
                height,
                db.index.bins_per_table,
                db.chunk.bins_per_table,
                params::compute_dpf_n(db.index.bins_per_table),
                params::compute_dpf_n(db.chunk.bins_per_table)
            );
            db_paths.push((all_databases.len() as u8, name, path.clone()));
            all_databases.push(db);
        }

        for (path, base, tip) in &args.deltas {
            let name = format!("delta_{}_{}", base, tip);
            let db = MappedDatabase::load(
                path,
                DatabaseDescriptor {
                    name: name.clone(),
                    db_type: DatabaseType::Delta,
                    base_height: *base,
                    height: *tip,
                    index_params: INDEX_PARAMS,
                    chunk_params: CHUNK_PARAMS,
                },
            );
            println!(
                "[Delta:{}→{}] INDEX bins={}, CHUNK bins={}, dpf_n_index={}, dpf_n_chunk={}",
                base,
                tip,
                db.index.bins_per_table,
                db.chunk.bins_per_table,
                params::compute_dpf_n(db.index.bins_per_table),
                params::compute_dpf_n(db.chunk.bins_per_table)
            );
            db_paths.push((all_databases.len() as u8, name, path.clone()));
            all_databases.push(db);
        }
    }

    let main_db = &all_databases[0];
    let index_k = main_db.index.params.k;
    let chunk_k = main_db.chunk.params.k;

    #[cfg(not(feature = "cuckoo-oram"))]
    {
        let _ = (
            args.cuckoo_oram_pack,
            args.cuckoo_oram_drain_per_access,
            args.cuckoo_oram_encrypted,
            args.cuckoo_oram_key_hex.as_ref(),
            args.cuckoo_oram_state_key_hex.as_ref(),
            args.cuckoo_oram_cache_levels,
            args.cuckoo_oram_auth_store,
            args.cuckoo_oram_no_save,
            args.direct_oram_drain_per_access,
            args.direct_oram_access_budget,
            args.direct_oram_encrypted,
            args.direct_oram_key_hex.as_ref(),
            args.direct_oram_state_key_hex.as_ref(),
            args.direct_oram_cache_levels,
            args.direct_oram_auth_store,
            args.direct_oram_no_save,
            args.direct_oram_trusted_state_dbs.as_slice(),
        );
        if args.cuckoo_oram_dir.is_some()
            || !args.cuckoo_oram_dbs.is_empty()
            || args.direct_oram_dir.is_some()
            || !args.direct_oram_dbs.is_empty()
            || !args.direct_oram_trusted_state_dbs.is_empty()
        {
            eprintln!(
                "ERROR: ORAM flags require building unified_server with --features cuckoo-oram \
                 (legacy alias: --features harmony-oram)"
            );
            std::process::exit(2);
        }
    }

    #[cfg(feature = "cuckoo-oram")]
    let cuckoo_oram = {
        let mut requested: BTreeMap<u8, PathBuf> = BTreeMap::new();
        if let Some(oram_dir) = args.cuckoo_oram_dir.as_ref() {
            requested.insert(0, oram_dir.clone());
        }
        for (db_id, oram_dir) in &args.cuckoo_oram_dbs {
            if requested.insert(*db_id, oram_dir.clone()).is_some() {
                eprintln!(
                    "ERROR: duplicate Cuckoo ORAM configuration for db_id={}",
                    db_id
                );
                std::process::exit(2);
            }
        }

        if requested.is_empty() {
            println!("  Cuckoo ORAM: disabled (use --cuckoo-oram-db <db_id>=<dir> to enable)");
            HashMap::new()
        } else {
            let mut opened = HashMap::new();
            for (db_id, oram_dir) in requested {
                let Some((_, db_label, db_path)) = db_paths
                    .iter()
                    .find(|(candidate, _, _)| *candidate == db_id)
                else {
                    eprintln!(
                        "ERROR: Cuckoo ORAM configured for unknown db_id={} (loaded db_ids: {:?})",
                        db_id,
                        db_paths.iter().map(|(id, _, _)| *id).collect::<Vec<_>>()
                    );
                    std::process::exit(2);
                };

                println!(
                    "  Cuckoo ORAM: enabled for db_id={} name={}, dir={}, pack={}, drain_per_access={}, encrypted={}, cache_levels={}, auth_store={}",
                    db_id,
                    db_label,
                    oram_dir.display(),
                    args.cuckoo_oram_pack,
                    args.cuckoo_oram_drain_per_access,
                    args.cuckoo_oram_encrypted,
                    args.cuckoo_oram_cache_levels,
                    args.cuckoo_oram_auth_store,
                );
                let tables = CuckooOramTables::open(
                    db_path,
                    &oram_dir,
                    args.cuckoo_oram_pack,
                    args.cuckoo_oram_drain_per_access,
                    args.cuckoo_oram_encrypted,
                    args.cuckoo_oram_key_hex.as_deref(),
                    args.cuckoo_oram_state_key_hex.as_deref(),
                    args.cuckoo_oram_cache_levels,
                    args.cuckoo_oram_auth_store,
                    !args.cuckoo_oram_no_save,
                )
                .unwrap_or_else(|e| {
                    panic!(
                        "failed to open Cuckoo ORAM for db_id={} ({}): {}",
                        db_id, db_label, e
                    )
                });
                opened.insert(db_id, tables);
            }

            let mmap_fallbacks: Vec<String> = db_paths
                .iter()
                .filter(|(db_id, _, _)| !opened.contains_key(db_id))
                .map(|(db_id, label, _)| format!("{}:{}", db_id, label))
                .collect();
            if !mmap_fallbacks.is_empty() {
                eprintln!(
                    "  Cuckoo ORAM: WARNING — DB(s) without ORAM config remain mmap-backed for Harmony queries: {}",
                    mmap_fallbacks.join(", ")
                );
            }
            opened
        }
    };

    #[cfg(feature = "cuckoo-oram")]
    let direct_oram = {
        let mut requested: BTreeMap<u8, PathBuf> = BTreeMap::new();
        let mut trusted_state_requested: BTreeMap<u8, PathBuf> = BTreeMap::new();
        if let Some(oram_dir) = args.direct_oram_dir.as_ref() {
            requested.insert(0, oram_dir.clone());
        }
        for (db_id, oram_dir) in &args.direct_oram_dbs {
            if requested.insert(*db_id, oram_dir.clone()).is_some() {
                eprintln!(
                    "ERROR: duplicate Direct ORAM configuration for db_id={}",
                    db_id
                );
                std::process::exit(2);
            }
        }
        for (db_id, trusted_state_dir) in &args.direct_oram_trusted_state_dbs {
            if trusted_state_requested
                .insert(*db_id, trusted_state_dir.clone())
                .is_some()
            {
                eprintln!(
                    "ERROR: duplicate Direct ORAM trusted-state configuration for db_id={}",
                    db_id
                );
                std::process::exit(2);
            }
        }
        for db_id in trusted_state_requested.keys() {
            if !requested.contains_key(db_id) {
                eprintln!(
                    "ERROR: Direct ORAM trusted-state configured without an image directory for db_id={}",
                    db_id
                );
                std::process::exit(2);
            }
        }

        if requested.is_empty() {
            println!("  Direct ORAM: disabled (use --direct-oram-db <db_id>=<dir> to enable)");
            HashMap::new()
        } else {
            let mut opened = HashMap::new();
            for (db_id, oram_dir) in requested {
                let trusted_state_dir = trusted_state_requested.remove(&db_id);
                let Some((_, db_label, _db_path)) = db_paths
                    .iter()
                    .find(|(candidate, _, _)| *candidate == db_id)
                else {
                    eprintln!(
                        "ERROR: Direct ORAM configured for unknown db_id={} (loaded db_ids: {:?})",
                        db_id,
                        db_paths.iter().map(|(id, _, _)| *id).collect::<Vec<_>>()
                    );
                    std::process::exit(2);
                };
                let database = all_databases.get(db_id as usize).unwrap_or_else(|| {
                    panic!("loaded DB vector is missing configured db_id={db_id}")
                });
                if !args.direct_oram_auth_store {
                    eprintln!(
                        "ERROR: production Direct ORAM for db_id={} requires --direct-oram-auth-store",
                        db_id
                    );
                    std::process::exit(2);
                }
                if !args.direct_oram_encrypted {
                    eprintln!(
                        "ERROR: production Direct ORAM for db_id={} requires --direct-oram-encrypted so the host cannot track plaintext block relocation",
                        db_id
                    );
                    std::process::exit(2);
                }
                if args.direct_oram_no_save {
                    eprintln!(
                        "ERROR: production Direct ORAM for db_id={} rejects --direct-oram-no-save because mutable controller/auth state must commit",
                        db_id
                    );
                    std::process::exit(2);
                }
                if trusted_state_dir.is_none() {
                    eprintln!(
                        "ERROR: production Direct ORAM for db_id={} requires a separate --direct-oram-trusted-state-db",
                        db_id
                    );
                    std::process::exit(2);
                }
                let trusted_state_dir = trusted_state_dir
                    .as_deref()
                    .expect("production Direct ORAM checked trusted-state directory");
                if !args.direct_oram_allow_trusted_state_outside_run_dev {
                    let trusted_state_dir = std::fs::canonicalize(trusted_state_dir)
                        .unwrap_or_else(|error| {
                            panic!(
                                "failed to resolve Direct ORAM trusted-state directory for db_id={} ({}): {}",
                                db_id,
                                trusted_state_dir.display(),
                                error
                            )
                        });
                    if !trusted_state_dir.starts_with("/run/bitcoinpir-oram-state") {
                        eprintln!(
                            "ERROR: production Direct ORAM for db_id={} requires trusted state under measured /run/bitcoinpir-oram-state; got {}",
                            db_id,
                            trusted_state_dir.display()
                        );
                        std::process::exit(2);
                    }
                    let bulk_dir = std::fs::canonicalize(&oram_dir).unwrap_or_else(|error| {
                        panic!(
                            "failed to resolve Direct ORAM bulk directory for db_id={} ({}): {}",
                            db_id,
                            oram_dir.display(),
                            error
                        )
                    });
                    if bulk_dir.starts_with(&trusted_state_dir)
                        || trusted_state_dir.starts_with(&bulk_dir)
                    {
                        eprintln!(
                            "ERROR: production Direct ORAM for db_id={} requires disjoint bulk and trusted-state directories",
                            db_id
                        );
                        std::process::exit(2);
                    }
                } else {
                    eprintln!(
                        "WARNING: Direct ORAM trusted state outside measured /run explicitly allowed for development/testing (db_id={})",
                        db_id
                    );
                }

                println!(
                    "  Direct ORAM: enabled for db_id={} name={}, dir={}, trusted_state_dir={}, access_budget={}, drain_per_access={}, encrypted={}, cache_levels={}, auth_store={}",
                    db_id,
                    db_label,
                    oram_dir.display(),
                    trusted_state_dir.display(),
                    args.direct_oram_access_budget,
                    args.direct_oram_drain_per_access,
                    args.direct_oram_encrypted,
                    args.direct_oram_cache_levels,
                    args.direct_oram_auth_store,
                );
                let tables = DirectOramTables::open_with_trusted_state(
                    &oram_dir,
                    Some(trusted_state_dir),
                    args.direct_oram_drain_per_access,
                    args.direct_oram_access_budget,
                    args.direct_oram_encrypted,
                    args.direct_oram_key_hex.as_deref(),
                    args.direct_oram_state_key_hex.as_deref(),
                    args.direct_oram_cache_levels,
                    args.direct_oram_auth_store,
                    !args.direct_oram_no_save,
                )
                .unwrap_or_else(|e| {
                    panic!(
                        "failed to open Direct ORAM for db_id={} ({}): {}",
                        db_id, db_label, e
                    )
                });
                tables
                    .validate_dataset_binding(database)
                    .unwrap_or_else(|error| {
                        panic!(
                            "failed to bind Direct ORAM to verified DB for db_id={} ({}): {}",
                            db_id, db_label, error
                        )
                    });
                opened.insert(db_id, tables);
            }
            opened
        }
    };

    // ── Set up OnionPIR per-DB (primary only, if data available) ──────────
    //
    // Each database can have its own OnionPIR data. Loading is per-DB:
    //   onionpir_txs[db_id]    = Some(channel) if db has OnionPIR data
    //   onionpir_infos[db_id]  = Some(info)    if db has OnionPIR data
    //   onionpir_merkle[db_id] = Some(info)    if db has OnionPIR Merkle data
    //
    // db_paths was already populated alongside `all_databases` above; it's
    // a list of (db_id, label, source_dir) for every loaded database.

    let num_total_dbs = db_paths.len();
    let mut onionpir_txs: Vec<Option<Arc<mpsc::Sender<PirCommand>>>> = vec![None; num_total_dbs];
    let mut onionpir_infos: Vec<Option<OnionPirInfo>> = (0..num_total_dbs).map(|_| None).collect();
    let mut onionpir_merkle_per_db: Vec<Option<OnionPirMerkleInfo>> =
        (0..num_total_dbs).map(|_| None).collect();

    // Per-group OnionPIR Merkle (Phase 3): one consolidated sibling file
    // per kind, loaded per-DB alongside the OnionPIR worker setup.
    struct OnionSibFile {
        /// Number of per-group sibling DBs (= PBC group count).
        k: usize,
        /// Plaintexts per per-group sibling DB.
        num_pt: usize,
        /// Byte length of one per-group `save_db` blob.
        blob_len: usize,
        /// `merkle_onion_sib_{index,data}.bin` mmap: `[24B header][K blobs]`.
        mmap: Mmap,
    }

    /// Load one consolidated per-group sibling file (Phase 3). Returns
    /// `None` if the file is absent (DB has no per-group OnionPIR Merkle).
    fn load_onion_sib_file(
        data_dir: &std::path::Path,
        db_label: &str,
        tree_kind: &str,
    ) -> Option<OnionSibFile> {
        let path = data_dir.join(format!("merkle_onion_sib_{}.bin", tree_kind));
        if !path.exists() {
            return None;
        }
        let file = std::fs::File::open(&path).expect("open onion sibling file");
        let mmap = unsafe { Mmap::map(&file) }.expect("mmap onion sibling file");
        assert!(
            mmap.len() >= 24,
            "{}: too small ({} B) for the 24-byte header",
            path.display(),
            mmap.len(),
        );
        // Header: [8B magic][4B K][4B arity][4B num_pt][4B blob_len].
        let k = u32::from_le_bytes(mmap[8..12].try_into().unwrap()) as usize;
        let num_pt = u32::from_le_bytes(mmap[16..20].try_into().unwrap()) as usize;
        let blob_len = u32::from_le_bytes(mmap[20..24].try_into().unwrap()) as usize;
        let expected = 24 + k * blob_len;
        assert_eq!(
            mmap.len(),
            expected,
            "{}: size mismatch (header K={} blob_len={} → {} B, file is {} B)",
            path.display(),
            k,
            blob_len,
            expected,
            mmap.len(),
        );
        println!(
            "  [{}] onion sibling '{}': K={}, num_pt={}, blob={:.2} MB, total={:.2} MB",
            db_label,
            tree_kind,
            k,
            num_pt,
            blob_len as f64 / 1e6,
            mmap.len() as f64 / 1e6,
        );
        Some(OnionSibFile {
            k,
            num_pt,
            blob_len,
            mmap,
        })
    }

    if args.role == ServerRole::Primary && !args.disable_onion {
        for (db_id, db_label, db_dir) in &db_paths {
            let ntt_path = db_dir.join(ONION_NTT_FILE);
            if !ntt_path.exists() {
                println!(
                    "[OnionPIR:{}] Not available (no {} in {})",
                    db_label,
                    ONION_NTT_FILE,
                    db_dir.display()
                );
                continue;
            }
            println!("[OnionPIR:{}] Loading data...", db_label);

            let chunk_cuckoo_path = db_dir.join(ONION_CHUNK_CUCKOO_FILE);
            let index_all_path = db_dir.join(ONION_INDEX_ALL_FILE);
            let index_meta_path = db_dir.join(ONION_INDEX_META_FILE);

            if !index_all_path.exists() {
                println!(
                    "[OnionPIR:{}] Skipping — {} missing in {}. Re-run scripts/build_delta_onion.sh (or gen_3_onion) to regenerate the consolidated INDEX layout.",
                    db_label, ONION_INDEX_ALL_FILE, db_dir.display(),
                );
                continue;
            }

            // Read OnionPIR-specific headers
            let cuckoo_data = std::fs::read(&chunk_cuckoo_path).expect("read onion chunk cuckoo");
            let ch = read_onion_chunk_header(&cuckoo_data);
            let meta_data = std::fs::read(&index_meta_path).expect("read onion index meta");
            let im = read_onion_index_meta(&meta_data);

            println!(
                "  Chunk: K={}, bins={}, packed={}",
                ch.k_chunk, ch.bins_per_table, ch.num_packed_entries
            );
            println!(
                "  Index: K={}, bins={}, slots_per_bin={}",
                im.k, im.bins_per_table, im.slots_per_bin
            );

            // Phase: self-verify onion seeds against the chain anchor embedded
            // in onion_index_meta.bin (v2 header). No-op for legacy onion DBs.
            if let Some(anchor) = im.anchor {
                verify_onion_anchor_seeds(
                    &anchor,
                    im.master_seed,
                    im.tag_seed,
                    ch.master_seed,
                    db_label,
                );
                println!("  anchor verified: onion INDEX/CHUNK seeds match chain-derived values");
            }

            onionpir_infos[*db_id as usize] = Some(OnionPirInfo {
                total_packed_entries: ch.num_packed_entries as u32,
                index_bins_per_table: im.bins_per_table as u32,
                chunk_bins_per_table: ch.bins_per_table as u32,
                index_k: im.k as u8,
                chunk_k: ch.k_chunk as u8,
                tag_seed: im.tag_seed,
                index_slots_per_bin: im.slots_per_bin as u16,
                index_slot_size: im.slot_size as u8,
                index_master_seed: im.master_seed,
                chunk_master_seed: ch.master_seed,
            });

            // Parse chunk cuckoo tables. ch.data_offset accounts for the v2
            // chain-anchor that sits between the header and the tables —
            // hardcoding 36 here read the anchor bytes as entry-ids and
            // segfaulted the onion query path (see OnionChunkHeader).
            let header_size = ch.data_offset;
            let mut chunk_tables: Vec<Vec<u32>> = Vec::with_capacity(ch.k_chunk);
            for g in 0..ch.k_chunk {
                let offset = header_size + g * ch.bins_per_table * 4;
                let mut table = Vec::with_capacity(ch.bins_per_table);
                for b in 0..ch.bins_per_table {
                    let pos = offset + b * 4;
                    let eid = u32::from_le_bytes(cuckoo_data[pos..pos + 4].try_into().unwrap());
                    table.push(eid);
                }
                chunk_tables.push(table);
            }

            // Load NTT store
            let ntt_file = std::fs::File::open(&ntt_path).expect("open NTT store");
            let ntt_mmap = unsafe { Mmap::map(&ntt_file) }.expect("mmap NTT store");
            println!("  NTT store: {:.2} GB", ntt_mmap.len() as f64 / 1e9);
            // Load consolidated INDEX file (onion_index_all.bin). Single mmap;
            // we parse the 32-byte master header here and hand per-group slices
            // to the PIR worker thread, which in turn feeds each slice into
            // `PirServer::load_db_from_bytes` (zero-copy aliased pointer).
            let index_all_file = std::fs::File::open(&index_all_path)
                .unwrap_or_else(|e| panic!("open {}: {}", index_all_path.display(), e));
            let index_all_mmap =
                unsafe { Mmap::map(&index_all_file) }.expect("mmap onion_index_all.bin");
            {
                if index_all_mmap.len() < ONION_INDEX_ALL_HEADER_BYTES {
                    panic!(
                        "{}: file too small ({} bytes) for index_all master header",
                        index_all_path.display(),
                        index_all_mmap.len(),
                    );
                }
                let magic = u64::from_le_bytes(index_all_mmap[0..8].try_into().unwrap());
                let file_k = u64::from_le_bytes(index_all_mmap[8..16].try_into().unwrap()) as usize;
                let file_per_group =
                    u64::from_le_bytes(index_all_mmap[16..24].try_into().unwrap()) as usize;
                // Accept legacy + v2 (anchor trailer) magic.
                let _ = check_onion_magic(magic, ONION_INDEX_ALL_MAGIC, "onion index-all master");
                assert_eq!(
                    file_k,
                    im.k,
                    "{}: K mismatch (file says {}, meta says {})",
                    index_all_path.display(),
                    file_k,
                    im.k,
                );
                // The K per-group payloads occupy [HEADER .. HEADER + K*per_group);
                // a v2 file then appends the chain anchor as a trailer.
                let data_len = ONION_INDEX_ALL_HEADER_BYTES + file_k * file_per_group;
                let all_anchor =
                    parse_onion_anchor(&index_all_mmap, ONION_INDEX_ALL_MAGIC, data_len);
                let expected_len = data_len
                    + match all_anchor {
                        None => 0,
                        Some(pir_core::cuckoo::HeaderAnchor::Snapshot(_)) => {
                            pir_core::seeds::CHAIN_ANCHOR_BYTES
                        }
                        Some(pir_core::cuckoo::HeaderAnchor::Delta(_)) => {
                            pir_core::seeds::DELTA_ANCHOR_BYTES
                        }
                    };
                assert_eq!(
                    index_all_mmap.len(),
                    expected_len,
                    "{}: total size mismatch (expected {}, got {})",
                    index_all_path.display(),
                    expected_len,
                    index_all_mmap.len(),
                );
                // Cross-file consistency: onion_index_all's trailer anchor must
                // match the one embedded in onion_index_meta.bin — catches a
                // mixed build where the two files came from different anchors.
                if let (Some(a), Some(m)) = (all_anchor, im.anchor) {
                    assert_eq!(
                        a, m,
                        "{}: index-all anchor disagrees with index-meta anchor — mixed build, refusing to serve",
                        index_all_path.display(),
                    );
                }
                println!(
                    "  Index-all: K={}, per_group={:.2} MB, total={:.2} MB",
                    file_k,
                    file_per_group as f64 / 1e6,
                    index_all_mmap.len() as f64 / 1e6,
                );
            }
            let index_all_per_group =
                u64::from_le_bytes(index_all_mmap[16..24].try_into().unwrap()) as usize;

            // Load the per-group OnionPIR Merkle sidecars (Phase 3
            // per-group redesign). A DB ships these only if
            // `gen_4_build_merkle_onion` has been run for it.
            let index_sib_file = load_onion_sib_file(db_dir, db_label, "index");
            let data_sib_file = load_onion_sib_file(db_dir, db_label, "data");

            let merkle_tree_tops: Option<Vec<u8>> = {
                let p = db_dir.join("merkle_onion_tree_tops.bin");
                if p.exists() {
                    Some(std::fs::read(&p).expect("read merkle_onion_tree_tops.bin"))
                } else {
                    None
                }
            };
            let merkle_super_root: Option<Vec<u8>> = {
                let p = db_dir.join("merkle_onion_root.bin");
                if p.exists() {
                    Some(std::fs::read(&p).expect("read merkle_onion_root.bin"))
                } else {
                    None
                }
            };

            // A DB has OnionPIR Merkle iff the full per-group set is on
            // disk: both consolidated sibling files plus the tree-top blob.
            let has_merkle_data =
                index_sib_file.is_some() && data_sib_file.is_some() && merkle_tree_tops.is_some();
            if has_merkle_data {
                let idx = index_sib_file.as_ref().unwrap();
                let dat = data_sib_file.as_ref().unwrap();
                let arity = onionpir::params_info(0).entry_size as usize / 32;
                let super_root_hex = merkle_super_root
                    .as_ref()
                    .map(|r| r.iter().map(|b| format!("{:02x}", b)).collect::<String>())
                    .unwrap_or_default();
                onionpir_merkle_per_db[*db_id as usize] = Some(OnionPirMerkleInfo {
                    arity,
                    super_root_hex,
                    tree_tops: merkle_tree_tops.unwrap_or_default(),
                    index_k: idx.k,
                    index_num_pt: idx.num_pt,
                    data_k: dat.k,
                    data_num_pt: dat.num_pt,
                });
            }

            let k_index = im.k;
            let k_chunk = ch.k_chunk;
            let index_bins = im.bins_per_table;
            let chunk_bins = ch.bins_per_table;
            let index_all_per_group_for_worker = index_all_per_group;
            let worker_label = db_label.clone();

            let (tx, mut pir_rx) = mpsc::channel::<PirCommand>(64);
            onionpir_txs[*db_id as usize] = Some(Arc::new(tx));

            // Spawn PIR worker thread (one per DB)
            std::thread::spawn(move || {
                // OnionPIRv2 port: KeyStore::new() takes no args now.
                let key_store = Box::new(KeyStore::new());

                // Set up chunk servers.
                //
                // OnionPIRv2 port (commit 6 / runtime-num_pt update): post the
                // upstream `target_num_pt` refactor (`fb14f4e447b...`),
                // `params_info(chunk_bins)` returns the LOCAL per-instance
                // shape (small server sized for `chunk_bins` ~37K plaintexts).
                // That's what each chunk worker's PirServer needs.
                let p_chunk = onionpir::params_info(chunk_bins as u64);
                let padded_chunk = p_chunk.num_entries as usize;
                // OnionPIRv2 port: `set_shared_database` now takes
                // `&[u64]` rather than a raw `*const u64` + count. The
                // unsafe slice construction below is sound for the same
                // reason the old raw-pointer call was: `ntt_mmap` is
                // captured by-move into this worker-thread closure and
                // outlives every `PirServer` we attach to it.
                //
                // SAFETY: `ntt_mmap` is a `&[u8]` with `len() % 8 == 0`
                // (preprocessed_db.bin payload is u64-aligned by build).
                let ntt_u64_slice: &[u64] = unsafe {
                    std::slice::from_raw_parts(ntt_mmap.as_ptr() as *const u64, ntt_mmap.len() / 8)
                };

                // Shared store's `num_pt` — what gen_2_onion's builder
                // `PirServer::new(num_packed_entries)` was created with,
                // which is what `set_shared_database`'s `shared_num_entries`
                // argument wants. Pre-`fb14f4e` we passed
                // `p_chunk.num_plaintexts` (the local per-instance value);
                // post-refactor those are different numbers and the local
                // one is wrong here. Derive from the NTT store file size
                // instead — `len() / 8 / coeff_val_cnt` is the count of
                // plaintext slots the builder saved.
                let coeff_val_cnt = onionpir::params_info(0).coeff_val_cnt as usize;
                assert!(
                    coeff_val_cnt > 0 && ntt_u64_slice.len().is_multiple_of(coeff_val_cnt),
                    "chunk NTT store len ({} u64s) not divisible by \
                     coeff_val_cnt ({}); file is the wrong shape",
                    ntt_u64_slice.len(),
                    coeff_val_cnt,
                );
                let chunk_shared_num_entries = (ntt_u64_slice.len() / coeff_val_cnt) as u64;

                let mut chunk_index_tables: Vec<Vec<u32>> = Vec::with_capacity(k_chunk);
                let mut chunk_servers: Vec<PirServer> = Vec::with_capacity(k_chunk);
                for (g, chunk_table) in chunk_tables.iter().enumerate().take(k_chunk) {
                    let mut server = PirServer::new(chunk_bins as u64);
                    let mut index_table = vec![0u32; padded_chunk];
                    for bin in 0..chunk_bins {
                        let eid = chunk_table[bin];
                        if eid != u32::MAX {
                            index_table[bin] = eid;
                        }
                    }
                    unsafe {
                        // OnionPIRv2 port: `set_shared_database` returns
                        // bool now (false on validation failure). Wrap in
                        // assert! so silent failures don't ship.
                        // OnionPIRv2 port (commit 3a): pass
                        // `num_plaintexts` (compile-time DB shape) as
                        // `shared_num_entries`, not the pre-port
                        // `num_packed_entries` (dataset size). The NTT
                        // store from gen_2_onion's post-port save_db
                        // payload is sized for the full num_plaintexts
                        // slot count; passing the smaller
                        // num_packed_entries would lie about the layout.
                        // Cuckoo placement only assigns to
                        // [0, num_packed_entries) so empty slots beyond
                        // that range are never queried.
                        assert!(
                            server.set_shared_database(
                                ntt_u64_slice,
                                chunk_shared_num_entries,
                                &index_table,
                            ),
                            "set_shared_database failed (chunk worker {} \
                             group {}; chunk_shared_num_entries={}, \
                             index_table.len={}, local_num_pt={})",
                            worker_label,
                            g,
                            chunk_shared_num_entries,
                            index_table.len(),
                            p_chunk.num_plaintexts,
                        );
                        // OnionPIRv2 port: `set_key_store` takes Option now.
                        server.set_key_store(Some(&key_store));
                    }
                    chunk_index_tables.push(index_table);
                    chunk_servers.push(server);
                }
                println!(
                    "  [OnionPIR:{}] {} chunk servers ready",
                    worker_label, k_chunk
                );

                // Set up index servers — each slices into the consolidated
                // onion_index_all.bin mmap via load_db_from_bytes (zero-copy).
                // The mmap handle must outlive every PirServer that aliases
                // it, which is satisfied by moving `index_all_mmap` into this
                // worker thread closure — the mmap drops only when the
                // thread exits, which happens on process shutdown.
                let mut index_servers: Vec<PirServer> = Vec::with_capacity(k_index);
                for b in 0..k_index {
                    let off = ONION_INDEX_ALL_HEADER_BYTES + b * index_all_per_group_for_worker;
                    let end = off + index_all_per_group_for_worker;
                    let slice = &index_all_mmap[off..end];
                    let mut server = PirServer::new(index_bins as u64);
                    // SAFETY: `index_all_mmap` is owned by this worker thread
                    // and lives as long as `server`. The PirServer will NOT
                    // munmap the borrowed buffer on drop (fd = -1 path inside
                    // load_db_from_borrowed).
                    assert!(
                        unsafe { server.load_db_from_borrowed(slice) },
                        "Failed to load index group {} from consolidated index_all (offset {}, len {})",
                        b, off, slice.len(),
                    );
                    // OnionPIRv2 port: `set_key_store` takes Option now.
                    unsafe {
                        server.set_key_store(Some(&key_store));
                    }
                    index_servers.push(server);
                }
                println!(
                    "  [OnionPIR:{}] {} index servers ready (via onion_index_all.bin mmap)",
                    worker_label, k_index
                );

                // Set up per-group OnionPIR Merkle sibling servers — one
                // PirServer per group, each zero-copy aliasing its
                // 24-byte-header sub-slice of merkle_onion_sib_*.bin.
                // Mirrors the index_servers block above.
                let build_sib_servers = |sib: &OnionSibFile, kind: &str| -> Vec<PirServer> {
                    let mut servers = Vec::with_capacity(sib.k);
                    for g in 0..sib.k {
                        let off = 24 + g * sib.blob_len;
                        let slice = &sib.mmap[off..off + sib.blob_len];
                        let mut server = PirServer::new(sib.num_pt as u64);
                        // SAFETY: `sib.mmap` is owned by this worker thread
                        // (moved into the closure) and outlives `server`.
                        assert!(
                            unsafe { server.load_db_from_borrowed(slice) },
                            "[OnionPIR:{}] load_db_from_borrowed failed for {} \
                             sibling group {} (offset {}, len {})",
                            worker_label,
                            kind,
                            g,
                            off,
                            slice.len(),
                        );
                        // OnionPIRv2 port: `set_key_store` takes Option now.
                        unsafe {
                            server.set_key_store(Some(&key_store));
                        }
                        servers.push(server);
                    }
                    println!(
                        "  [OnionPIR:{}] {} sibling servers ready ({} groups, num_pt={})",
                        worker_label, kind, sib.k, sib.num_pt,
                    );
                    servers
                };
                let mut index_sib_servers: Vec<PirServer> = match &index_sib_file {
                    Some(sib) => build_sib_servers(sib, "index"),
                    None => Vec::new(),
                };
                let mut data_sib_servers: Vec<PirServer> = match &data_sib_file {
                    Some(sib) => build_sib_servers(sib, "data"),
                    None => Vec::new(),
                };

                // Event loop
                while let Some(cmd) = pir_rx.blocking_recv() {
                    match cmd {
                        PirCommand::RegisterKeys {
                            client_id,
                            galois_keys,
                            gsw_keys,
                            reply,
                        } => {
                            let t = Instant::now();
                            key_store.set_galois_keys(client_id, &galois_keys);
                            key_store.set_gsw_key(client_id, &gsw_keys);
                            unsafe_debug_log!(
                                "  [OnionPIR:{}] client {} keys registered in {:.2?}",
                                worker_label,
                                client_id,
                                t.elapsed()
                            );
                            let _ = reply.send(());
                        }
                        PirCommand::AnswerBatch {
                            client_id,
                            level,
                            round_id,
                            queries,
                            reply,
                        } => {
                            let t = Instant::now();
                            // OnionPIRv2 port (2402b16): rayon-parallel `answer_query`
                            // across the per-group PirServer Vec. Safe after upstream
                            // 2402b16 made g_scratch / NTT cache / TimerLogger
                            // thread_local + added a mutex to SharedKeyStore. Each
                            // rayon worker gets one exclusive `&mut PirServer`
                            // (Send-but-not-Sync), so per-server state is single-
                            // threaded; the shared SharedKeyStore is mutex-guarded.
                            //
                            // The bd1a2928 attempt to ship this was reverted after a
                            // pir1 deploy showed 60 s registrations + empty
                            // answer_query. That turned out NOT to be a 2402b16 bug —
                            // it was a contaminated incremental libonionpir.a build
                            // from flipping the onionpir git rev repeatedly without a
                            // clean rebuild (see docs/PIR1_REGISTER_KEYS_TRUNCATION.md).
                            // With a clean build, 2402b16 registers keys in ~1 ms and
                            // the parallel path is sound.
                            //
                            // Wall-time projection (i7-8700, 6 cores):
                            //   INDEX 142 s → ~25 s ; CHUNK 157 s → ~25 s. Total batch
                            //   ≈ 60 s — under Cloudflare's ~100 s WS idle timeout.
                            let worker_label = &worker_label;
                            let queries_ref = &queries;
                            let (name, results): (&str, Vec<Vec<u8>>) = if level == 0 {
                                let results: Vec<Vec<u8>> = index_servers
                                    .par_iter_mut()
                                    .enumerate()
                                    .flat_map_iter(|(g, server)| {
                                        let q0 = &queries_ref[2 * g];
                                        let q1 = &queries_ref[2 * g + 1];
                                        // The workspace uses panic=abort, so an OnionPIR panic
                                        // terminates the process; there is no in-process isolation.
                                        // A process boundary is required if that policy changes.
                                        let r0 = server.answer_query(client_id, q0);
                                        let r1 = server.answer_query(client_id, q1);
                                        std::iter::once(r0).chain(std::iter::once(r1))
                                    })
                                    .collect();
                                ("index", results)
                            } else if level == 1 {
                                let results: Vec<Vec<u8>> = chunk_servers
                                    .par_iter_mut()
                                    .enumerate()
                                    .map(|(b, server)| {
                                        server.answer_query(client_id, &queries_ref[b])
                                    })
                                    .collect();
                                ("chunk", results)
                            } else if level == 10 || level == 11 {
                                // Per-group OnionPIR Merkle siblings:
                                // level 10 = INDEX trees, level 11 = DATA trees.
                                let (servers, kind): (&mut Vec<PirServer>, &str) = if level == 10 {
                                    (&mut index_sib_servers, "index-sibling")
                                } else {
                                    (&mut data_sib_servers, "data-sibling")
                                };
                                let results: Vec<Vec<u8>> = servers
                                    .par_iter_mut()
                                    .enumerate()
                                    .map(|(b, server)| {
                                        server.answer_query(client_id, &queries_ref[b])
                                    })
                                    .collect();
                                (kind, results)
                            } else {
                                unsafe_debug_log!(
                                    "[OnionPIR:{}] unknown level {}",
                                    worker_label,
                                    level
                                );
                                ("unknown", Vec::new())
                            };
                            // OnionPIRv2 port: report empty/nonempty result split
                            // alongside the existing wall-clock log so a future
                            // "all-empty batch" client-side report (see
                            // `crates/sdk/client/src/onion.rs::batch_looks_evicted`)
                            // can be triaged from server logs alone — either
                            // answer_query returned an all-empty batch quickly
                            // (empty=N/N → keystore drift or query malformed) or the
                            // matmul completed (empty=0/N, full wall time →
                            // client decode / decryption-noise bug).
                            let empty_count = results.iter().filter(|r| r.is_empty()).count();
                            let nonempty_bytes: usize = results
                                .iter()
                                .filter(|r| !r.is_empty())
                                .map(|r| r.len())
                                .sum();
                            let first_resp_len = results
                                .iter()
                                .find(|r| !r.is_empty())
                                .map(|r| r.len())
                                .unwrap_or(0);
                            unsafe_debug_log!(
                                "  [OnionPIR:{}] {} r{} {} queries in {:.2?} (empty={}/{}, nonempty_total={}B, resp_len={}B, client_id={})",
                                worker_label, name, round_id, queries.len(), t.elapsed(),
                                empty_count, results.len(), nonempty_bytes, first_resp_len, client_id,
                            );
                            let _ = reply.send(results);
                        }
                    }
                }
            });
        }
    }

    // ── Build server state ──────────────────────────────────────────────
    // (OnionPIR per-bin Merkle info was built per-DB inside the loading
    // loop above; it's stored in `onionpir_merkle_per_db`.)

    println!();
    println!("Data loaded in {:.2?}", total_start.elapsed());
    println!();

    // ── Generate the long-lived channel keypair ─────────────────────────
    // This is the X25519 key the future encrypted channel handshakes
    // ECDH against. We generate it inside the SEV-SNP guest at startup
    // (before any client traffic), commit the pubkey to REPORT_DATA via
    // build_report_data's V2 layout, and stash both halves on the
    // server. The secret never touches disk; on reboot a new key is
    // generated, which automatically bumps MEASUREMENT (because the
    // pubkey-in-cmdline path doesn't apply yet — see Slice B).
    //
    // Why on a non-SEV host (Hetzner) too? The channel layer is hosted
    // identically; only the attestation backing differs. Clients still
    // get an encrypted channel against pir1; they just don't get the
    // chip-signed binding.
    let channel_keypair = pir_runtime_core::channel::ChannelKeypair::generate();
    let channel_pubkey = channel_keypair.public_bytes();
    println!(
        "  Channel pubkey: {}",
        channel_pubkey
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );

    // ── Load AMD VCEK chain (optional) ───────────────────────────────────
    // Operator places ARK + ASK + VCEK PEMs at --vcek-dir; server reads
    // once at startup and ships them in every AttestResult so the
    // browser can chain-validate the SNP report's signature back to
    // AMD's known root without talking to kdsintf.amd.com directly
    // (CORS-blocked from the browser).
    let (ark_pem, ask_pem, vcek_pem) = match args.vcek_dir.as_ref() {
        Some(dir) => match load_vcek_chain(dir) {
            Ok((ark, ask, vcek)) => {
                println!(
                    "  VCEK chain: loaded from {} (ark={}B ask={}B vcek={}B)",
                    dir.display(),
                    ark.len(),
                    ask.len(),
                    vcek.len(),
                );
                (ark, ask, vcek)
            }
            Err(e) => {
                eprintln!(
                    "  VCEK chain: failed to load from {}: {} — AttestResult will ship empty cert fields, browser falls back to V2-binding-only verification",
                    dir.display(),
                    e
                );
                (Vec::new(), Vec::new(), Vec::new())
            }
        },
        None => {
            println!("  VCEK chain: not configured (--vcek-dir unset) — AttestResult ships empty cert fields");
            (Vec::new(), Vec::new(), Vec::new())
        }
    };

    // ── Build the operator-signed announcement bundle, if configured ─
    // [HUMAN-decided 2026-05-21] When either file is missing or the
    // cert / key disagree, log a warning and serve without announce
    // (REQ_ANNOUNCE returns RESP_ERROR). Existing attest / handshake
    // / query paths are unaffected.
    let announcement_bundle: Option<Vec<u8>> = match (
        args.identity_key_path.as_ref(),
        args.identity_cert_path.as_ref(),
        args.identity_server_id.as_deref(),
    ) {
        (Some(key_path), Some(cert_path), Some(server_id)) => {
            let identity_key =
                read_exact_secret_v1::<32>(key_path, "identity signing key").map(|mut seed| {
                    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
                    seed.zeroize();
                    key
                });
            match identity_key.and_then(|sk| {
                pir_runtime_core::identity::load_identity_cert(cert_path)
                    .map(|cert| (sk, cert))
                    .map_err(|error| error.to_string())
            }) {
                Ok((sk, cert)) => {
                    // Manifest roots in db_id order — same as the V2
                    // attest layout, so the bundle and the SEV report
                    // commit to the same set.
                    let manifest_roots: Vec<[u8; 32]> = all_databases
                        .iter()
                        .map(|db| db.manifest_root.unwrap_or([0u8; 32]))
                        .collect();
                    let binary_sha256 = pir_runtime_core::attest::self_exe_sha256();
                    let git_rev = pir_runtime_core::attest::GIT_REV;
                    let issued_at = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    match pir_runtime_core::identity::build_announcement_bundle(
                        &sk,
                        cert,
                        server_id,
                        channel_pubkey,
                        binary_sha256,
                        git_rev,
                        manifest_roots,
                        issued_at,
                    ) {
                        Ok(id) => {
                            let id_short: String = id.cert.identity_pubkey[..8]
                                .iter()
                                .map(|b| format!("{:02x}", b))
                                .collect();
                            println!(
                                "  Identity announce: enabled (server_id={}, identity_pub={}…, issued_at={})",
                                server_id, id_short, issued_at
                            );
                            Some(id.encoded_bundle)
                        }
                        Err(e) => {
                            eprintln!(
                                "  Identity announce: DISABLED — failed to build bundle: {}. REQ_ANNOUNCE will return RESP_ERROR; attest/handshake/queries still serve normally.",
                                e
                            );
                            None
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        "  Identity announce: DISABLED — {}. REQ_ANNOUNCE will return RESP_ERROR; attest/handshake/queries still serve normally.",
                        e
                    );
                    None
                }
            }
        }
        (None, None, None) => {
            println!(
                "  Identity announce: not configured (--identity-key-path / --identity-cert-path / --identity-server-id unset)"
            );
            None
        }
        _ => {
            eprintln!(
                "  Identity announce: DISABLED — all three of --identity-key-path, --identity-cert-path, --identity-server-id must be set together (or none of them)."
            );
            None
        }
    };

    // ── Assemble ServerState ────────────────────────────────────────────
    let num_databases = all_databases.len();
    let state = ServerState {
        databases: all_databases,
        server_static_pub: channel_pubkey,
        ark_pem,
        ask_pem,
        vcek_pem,
        announcement_bundle,
    };

    let admin_config = match args.admin_pubkey_hex.as_deref() {
        None => None,
        Some(hex) => match pir_runtime_core::admin::AdminConfig::from_hex(hex) {
            Ok(c) => {
                println!("  Admin auth: enabled (pubkey={})", &hex[..16]);
                Some(c)
            }
            Err(e) => panic!("invalid --admin-pubkey-hex: {}", e),
        },
    };

    // data_root = directory of databases.toml (where DB subdirs live)
    // when --config is given; otherwise fall back to --data-dir.
    let data_root = match args.config_path.as_ref() {
        Some(p) => p
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(".")),
        None => args.data_dir.clone(),
    };
    println!("  Data root: {}", data_root.display());
    let service_admission = load_strict_service_admission_v1(
        &args,
        current_unix_seconds_v1().unwrap_or_else(|error| fatal_cli(error)),
    )
    .unwrap_or_else(|error| fatal_cli(format!("service admission V1: {error}")));
    let service_admission_enforcement = if let Some(runtime) = service_admission.as_ref() {
        if args.pool_size > 0
            && online_v2full_auth_limit == 0
            && runtime.all_policies().any(|policy| {
                policy.scopes.iter().any(|scope| {
                    scope.scope.backend == ServiceBackendIdV1::HarmonyPirV2
                        && scope.scope.workload == ServiceWorkloadIdV1::HarmonyHintBundleV1
                        && scope.offers.iter().any(|offer| {
                            offer.verification
                                != pir_service_protocol::VerificationMode::ProviderLocal
                        })
                })
            })
        {
            fatal_cli(
                "online-authority Harmony hint offers require --pool-size and --service-max-concurrent-auth to leave at least one provider-local slot",
            );
        }
        println!(
            "  Service admission V1: enforced (policy epoch={}, digest={})",
            runtime.policy.policy().policy_epoch,
            hex::encode(runtime.policy.policy_digest())
        );
        if !runtime.retained_policies.is_empty() {
            println!(
                "  Retained policies: {} redemption-only (the single V1 policy key must remain stable through every live grace window)",
                runtime.retained_policies.len()
            );
        }
        if runtime.trust_direct_peer_ip {
            println!("  Free IP quotas: direct TCP peer explicitly trusted");
        }
        if runtime.provider_store.is_none() {
            println!(
                "  Storeless Free-PoW: exact measured policy digest; no provider store or rollback authority"
            );
        }
        AdmissionEnforcementV1::Enforced
    } else {
        println!(
            "  Service admission V1: explicit legacy migration mode (0x0d/0x0e never unlock backend work)"
        );
        AdmissionEnforcementV1::ExplicitLegacyMode
    };

    // ── Initialize HarmonyPIR V2 hint pool (if enabled) ──────────────────
    let (arc_verifier, require_arc) = if args.require_arc {
        let verifier = match &args.arc_key_path {
            Some(path) => {
                let mut secret = read_exact_secret_v1::<128>(path, "ARC key").unwrap_or_else(|e| {
                    panic!("failed to load ARC key from {}: {e}", path.display())
                });
                let v = pir_runtime_core::arc_verifier::ArcVerifier::from_secret_key_bytes(&secret)
                    .unwrap_or_else(|e| {
                        panic!("failed to load ARC key from {}: {e}", path.display())
                    });
                secret.zeroize();
                println!(
                    "  ARC: enabled — verification required (shared key loaded from {})",
                    path.display()
                );
                v
            }
            None => {
                let v = pir_runtime_core::arc_verifier::ArcVerifier::generate();
                eprintln!(
                    "  ARC: WARNING — --require-arc set without --arc-key; generated a random \
                     key. No externally-issued credential will verify. Pass --arc-key <arc_key.bin> \
                     to share the issuer's key."
                );
                v
            }
        };
        (Some(std::sync::Mutex::new(verifier)), true)
    } else {
        println!("  ARC: disabled (use --require-arc to enable)");
        (None, false)
    };

    let (cashu_verifier, require_cashu) = if args.require_cashu {
        if args.cashu_keysets.is_empty() {
            panic!("--require-cashu requires at least one --cashu-keyset <id>:<hex_sk>");
        }
        let verifier =
            pir_runtime_core::cashu_verifier::CashuVerifier::from_keys(&args.cashu_keysets)
                .expect("valid Cashu keysets");
        println!(
            "  Cashu: enabled — {} keyset(s) loaded",
            verifier.keyset_count()
        );
        (Some(std::sync::Mutex::new(verifier)), true)
    } else {
        println!("  Cashu: disabled (use --require-cashu to enable)");
        (None, false)
    };

    let hint_pool = if args.pool_size > 0 {
        let pool_config = hint_pool::HintPoolConfig {
            pool_size: args.pool_size,
            // Advertise exactly the backend compiled into this runtime:
            // FastPRP with the feature, HMR12 otherwise.
            prp_backend: hint_pool::default_prp_backend(),
            pool_dir: args.pool_dir.clone(),
        };
        let pool_db_id = args.pool_db_id;
        let pool_db = state.get_db(pool_db_id).unwrap_or_else(|| {
            panic!(
                "HarmonyPIR hint pool database db_id {} must be loaded",
                pool_db_id
            )
        });
        let backend_name = match pool_config.prp_backend {
            harmonypir::remote::PRP_HMR12 => "HMR12",
            harmonypir::remote::PRP_FASTPRP => "FastPRP",
            _ => "unknown",
        };
        println!(
            "  HarmonyPIR V2 hint pool: db_id={}, size={}, backend={}, dir={}",
            pool_db_id,
            pool_config.pool_size,
            backend_name,
            pool_config
                .pool_dir
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "memory-only".into())
        );
        println!(
            "  HarmonyPIR V2 online-authority AUTH limit: {} (provider-local headroom reserved)",
            online_v2full_auth_limit
        );
        Some(
            hint_pool::HintPool::new(pool_config, pool_db_id, pool_db)
                .unwrap_or_else(|e| panic!("HarmonyPIR hint pool init failed: {}", e)),
        )
    } else {
        println!("  HarmonyPIR V2 hint pool: disabled (use --pool-size to enable)");
        None
    };

    let server = Arc::new(UnifiedServerData {
        state,
        role: args.role,
        onionpir_txs,
        onionpir_infos,
        onionpir_merkle: onionpir_merkle_per_db,
        admin_config,
        data_root,
        channel_keypair,
        hint_pool,
        #[cfg(feature = "cuckoo-oram")]
        cuckoo_oram,
        #[cfg(feature = "cuckoo-oram")]
        direct_oram,
        v2_half_pending: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        arc_verifier,
        require_arc,
        cashu_verifier,
        require_cashu,
        service_admission_enforcement,
        service_admission,
        serve_hints: args.serve_hints,
        serve_queries: args.serve_queries,
    });
    server
        .validate_service_policy_catalog_v1()
        .unwrap_or_else(|error| fatal_cli(format!("service admission V1 catalog: {error}")));

    // Background task: garbage-collect V2-half pending entries whose
    // matching second half never arrived. Runs every 10 s; entries
    // older than `V2_HALF_PENDING_TTL_SECS` are evicted (their pool
    // entry is dropped — the pool generator will refill).
    {
        let pending = Arc::clone(&server.v2_half_pending);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                let cutoff =
                    Instant::now().checked_sub(Duration::from_secs(V2_HALF_PENDING_TTL_SECS));
                let Some(cutoff) = cutoff else { continue };
                let mut map = pending.lock().await;
                let before = map.len();
                map.retain(|_token, pend| pend.created_at >= cutoff);
                let evicted = before.saturating_sub(map.len());
                if evicted > 0 {
                    unsafe_debug_log!(
                        "[v2-half-pending] evicted {} stale entr(ies), {} remaining",
                        evicted,
                        map.len()
                    );
                }
            }
        });
    }

    // ── Accept WebSocket connections ────────────────────────────────────

    // The default `[::]:port` preserves the production dual-stack behavior:
    // it accepts IPv6 and (where IPV6_V6ONLY=0) IPv4-mapped connections. An
    // explicit --bind-address lets operators and deterministic local tests
    // narrow the listener to one interface without a proxy or firewall trick.
    let addr = SocketAddr::new(args.bind_address, args.port);
    let listener = TcpListener::bind(addr).await.expect("bind");
    println!("Listening on ws://{}", addr);
    println!("  Role: {}", role_name);
    println!(
        "  Index: K={}, bins_per_table={}",
        index_k,
        server.main_db().index.bins_per_table
    );
    println!(
        "  Chunk: K={}, bins_per_table={}",
        chunk_k,
        server.main_db().chunk.bins_per_table
    );
    println!("  Databases: {}", num_databases);
    println!(
        "  OnionPIR: {}",
        if server.has_any_onionpir() {
            "enabled"
        } else if args.disable_onion {
            "disabled (--disable-onion)"
        } else if args.role == ServerRole::Secondary {
            "disabled (secondary role never loads OnionPIR)"
        } else {
            "disabled (no onion_*.bin files in any DB dir)"
        }
    );
    match args.role {
        ServerRole::Primary => println!("  HarmonyPIR: query server"),
        ServerRole::Secondary => println!("  HarmonyPIR: hint server"),
    }
    if server.main_db().has_bucket_merkle() {
        println!("  Merkle: available (per-bucket)");
    }
    println!();

    let client_counter = std::sync::atomic::AtomicU64::new(1);
    let connection_limiter = Arc::new(Semaphore::new(args.max_connections));
    let service_auth_limiter = Arc::new(Semaphore::new(args.service_max_concurrent_auth));
    let online_v2full_auth_limiter = Arc::new(Semaphore::new(online_v2full_auth_limit));
    let reassembly_limiter = Arc::new(Semaphore::new(MAX_GLOBAL_REASSEMBLY_BYTES));
    let websocket_handshake_timeout = Duration::from_millis(args.websocket_handshake_timeout_ms);
    let connection_idle_timeout = Duration::from_millis(args.connection_idle_timeout_ms);
    let v2full_dispatch_timeout = connection_idle_timeout.min(V2_FULL_POST_GRANT_RESERVATION_MAX);
    let service_pre_auth_timeout = Duration::from_millis(args.service_pre_auth_timeout_ms);

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("Accept error: {}", e);
                continue;
            }
        };
        let connection_permit = match Arc::clone(&connection_limiter).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                // Drop before WebSocket parsing. The reverse proxy/edge is
                // expected to convert saturation into its normal retry path.
                drop(stream);
                continue;
            }
        };

        let client_id = client_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let server = Arc::clone(&server);
        let service_auth_limiter = Arc::clone(&service_auth_limiter);
        let online_v2full_auth_limiter = Arc::clone(&online_v2full_auth_limiter);
        let reassembly_limiter = Arc::clone(&reassembly_limiter);

        tokio::spawn(async move {
            let _connection_permit = connection_permit;
            #[allow(deprecated)]
            let ws_config = WebSocketConfig {
                max_send_queue: None,
                write_buffer_size: 128 * 1024,
                max_write_buffer_size: 2 * 1024 * 1024,
                max_message_size: Some(MAX_WS_MESSAGE_BYTES),
                max_frame_size: Some(MAX_WS_MESSAGE_BYTES),
                accept_unmasked_frames: false,
            };
            let ws = match tokio::time::timeout(
                websocket_handshake_timeout,
                accept_async_with_config(stream, Some(ws_config)),
            )
            .await
            {
                Ok(Ok(ws)) => ws,
                Ok(Err(e)) => {
                    unsafe_debug_log!("[{}] Handshake failed: {}", peer, e);
                    return;
                }
                Err(_) => {
                    unsafe_debug_log!("[{}] Handshake timed out", peer);
                    return;
                }
            };
            unsafe_debug_log!("[{}] Connected (id={})", peer, client_id);
            let (raw_sink, mut ws_stream) = ws.split();
            let pre_auth_started = Instant::now();
            let mut sink = ServiceAdmissionSink::new(
                raw_sink,
                server.service_admission_enforcement,
                pre_auth_started,
                service_pre_auth_timeout,
            );

            // Per-connection admin auth state. Lives until the connection
            // drops; disconnecting is logging out.
            let mut admin_state = pir_runtime_core::admin::AdminConnectionState::default();

            // Per-connection encrypted-channel session. `None` until the
            // client sends REQ_HANDSHAKE; `Some` after we've derived the
            // session key. While Some, every outgoing response is sealed
            // (via send_resp below), and incoming frames whose first byte
            // is `pir_channel::ENCRYPTED_FRAME_MAGIC` are decrypted at the
            // top of the dispatch loop.
            //
            // We KEEP cleartext support per-frame even after the session
            // is established — a client can mix cleartext probes (e.g.
            // REQ_PING) with encrypted PIR queries on the same socket.
            // Privacy-conscious clients (the browser SDK) wrap every
            // application frame; legacy clients keep working.
            let mut channel_session: Option<pir_runtime_core::channel::Session> = None;
            let mut free_admission: Option<FreeAdmissionCommitterV1> = None;
            // A Payment V1 V2Full authorization reserves one durable pool file
            // before credential verification and keeps its inode lock here
            // after credential commit. Only the first main dispatch durably
            // consumes it; lost grants and pre-dispatch disconnects return it.
            let mut reserved_harmony_v2_full: Option<PendingHarmonyV2FullEntryV1> = None;

            // Per-connection ARC state: set to true after the first valid
            // REQ_CREDENTIAL_PRESENT. The presentation_context for this
            // connection is the client-supplied bytes (typically a random
            // session nonce). Tags are scoped to this context.
            let mut arc_ok: bool = false;
            let mut arc_pres_ctx: Option<Vec<u8>> = None;
            let mut cashu_ok: bool = false;

            // Per-connection transport-level chunk reassembly state. A
            // client that sends a multi-MB message (OnionPIR RegisterKeys
            // / query batches) splits it into CHUNK_MAGIC frames; we
            // reassemble before dispatch. `client_supports_chunks` flips
            // true on the first chunk frame seen and gates whether the
            // server chunks its (large) responses back.
            let mut chunk_acc: Vec<u8> = Vec::new();
            let mut chunk_expected: u16 = 0;
            let mut chunk_total: u16 = 0;
            let mut chunk_permits = Vec::new();
            let mut client_supports_chunks = false;

            loop {
                if reserved_harmony_v2_full
                    .as_ref()
                    .and_then(|pending| pending.dispatch_deadline)
                    .is_some_and(|deadline| Instant::now() >= deadline)
                {
                    unsafe_debug_log!("[{}] post-grant V2Full dispatch deadline expired", peer);
                    break;
                }
                if sink.pre_auth_deadline_has_expired() {
                    unsafe_debug_log!("[{}] pre-authorization write deadline expired", peer);
                    break;
                }
                if sink.pre_auth_egress_is_terminal() {
                    unsafe_debug_log!("[{}] pre-authorization egress budget exhausted", peer);
                    break;
                }
                let Some((read_timeout, pre_auth_deadline_is_limiting)) =
                    connection_read_timeout_v1(
                        server.service_admission_enforcement,
                        sink.auth_result_delivered(),
                        pre_auth_started.elapsed(),
                        service_pre_auth_timeout,
                        connection_idle_timeout,
                    )
                else {
                    unsafe_debug_log!("[{}] pre-authorization deadline expired", peer);
                    break;
                };
                let Some((read_timeout, v2full_dispatch_deadline_is_limiting)) =
                    cap_read_timeout_by_dispatch_deadline_v1(
                        read_timeout,
                        reserved_harmony_v2_full
                            .as_ref()
                            .and_then(|pending| pending.dispatch_deadline),
                        Instant::now(),
                    )
                else {
                    unsafe_debug_log!("[{}] post-grant V2Full dispatch deadline expired", peer);
                    break;
                };
                let Some(msg) = (match tokio::time::timeout(read_timeout, ws_stream.next()).await {
                    Ok(message) => message,
                    Err(_) => {
                        if v2full_dispatch_deadline_is_limiting {
                            unsafe_debug_log!(
                                "[{}] post-grant V2Full dispatch deadline expired",
                                peer
                            );
                        } else if pre_auth_deadline_is_limiting {
                            unsafe_debug_log!("[{}] pre-authorization deadline expired", peer);
                        } else {
                            unsafe_debug_log!("[{}] idle timeout", peer);
                        }
                        break;
                    }
                }) else {
                    break;
                };
                let msg = match msg {
                    Ok(m) => m,
                    Err(e) => {
                        unsafe_debug_log!("[{}] Read error: {}", peer, e);
                        break;
                    }
                };
                // Response accounting is scoped to exactly one inbound
                // application request. A typed backend permit below is the
                // only production path that turns it on again.
                sink.begin_request();

                let raw_bin = match msg {
                    Message::Binary(b) => b,
                    Message::Ping(p) => {
                        // Control traffic cannot keep a partial upload alive.
                        chunk_acc.clear();
                        chunk_permits.clear();
                        chunk_expected = 0;
                        if let Some(deadline) = reserved_harmony_v2_full
                            .as_ref()
                            .and_then(|pending| pending.dispatch_deadline)
                        {
                            match tokio::time::timeout_at(
                                tokio::time::Instant::from_std(deadline),
                                sink.send(Message::Pong(p)),
                            )
                            .await
                            {
                                Ok(Ok(())) => {}
                                Ok(Err(_)) | Err(_) => break,
                            }
                        } else {
                            let _ = sink.send(Message::Pong(p)).await;
                        }
                        continue;
                    }
                    Message::Close(_) => break,
                    _ => {
                        chunk_acc.clear();
                        chunk_permits.clear();
                        chunk_expected = 0;
                        continue;
                    }
                };

                // Transport-level chunk reassembly. A chunk frame is
                // `[4B len][CHUNK_MAGIC][seq:u16][total:u16][piece]`; a
                // normal message never carries CHUNK_MAGIC at offset 4.
                let mut completed_chunk_permits = Vec::new();
                let bin: Vec<u8> = if raw_bin.len() >= 4 + CHUNK_HDR && raw_bin[4] == CHUNK_MAGIC {
                    client_supports_chunks = true;
                    let seq = u16::from_le_bytes([raw_bin[5], raw_bin[6]]);
                    let total = u16::from_le_bytes([raw_bin[7], raw_bin[8]]);
                    let declared = usize::try_from(u32::from_le_bytes([
                        raw_bin[0], raw_bin[1], raw_bin[2], raw_bin[3],
                    ]))
                    .unwrap_or(usize::MAX);
                    let allowed_reassembled = if server.service_admission_enforcement
                        == AdmissionEnforcementV1::Enforced
                    {
                        let Some(limit) = sink.active_chunk_request_limit() else {
                            unsafe_debug_log!("[{}] pre-authorization chunk upload rejected", peer);
                            break;
                        };
                        limit
                    } else {
                        MAX_REASSEMBLED
                    };
                    if declared != raw_bin.len().saturating_sub(4)
                        || total == 0
                        || usize::from(total) > MAX_CHUNK_FRAMES
                        || seq >= total
                        || seq != chunk_expected
                    {
                        unsafe_debug_log!(
                            "[{}] bad chunk frame (seq={} total={} expected={}) — closing",
                            peer,
                            seq,
                            total,
                            chunk_expected
                        );
                        break;
                    }
                    if seq == 0 {
                        chunk_total = total;
                        chunk_acc.clear();
                        chunk_permits.clear();
                    } else if total != chunk_total {
                        unsafe_debug_log!("[{}] chunk total changed mid-stream — closing", peer);
                        break;
                    }
                    let piece = &raw_bin[4 + CHUNK_HDR..];
                    let Some(next_len) = chunk_acc.len().checked_add(piece.len()) else {
                        break;
                    };
                    if piece.is_empty() || next_len > allowed_reassembled {
                        unsafe_debug_log!(
                            "[{}] reassembled message exceeds active cap — closing",
                            peer
                        );
                        break;
                    }
                    let Ok(piece_permits) = u32::try_from(piece.len()) else {
                        break;
                    };
                    let permit = match Arc::clone(&reassembly_limiter)
                        .try_acquire_many_owned(piece_permits)
                    {
                        Ok(permit) => permit,
                        Err(_) => {
                            unsafe_debug_log!("[{}] global reassembly budget exhausted", peer);
                            break;
                        }
                    };
                    if chunk_acc.try_reserve(piece.len()).is_err() {
                        unsafe_debug_log!("[{}] reassembly allocation failed", peer);
                        break;
                    }
                    chunk_acc.extend_from_slice(piece);
                    chunk_permits.push(permit);
                    chunk_expected += 1;
                    if chunk_expected < chunk_total {
                        continue; // wait for the next chunk frame
                    }
                    chunk_expected = 0;
                    completed_chunk_permits = std::mem::take(&mut chunk_permits);
                    std::mem::take(&mut chunk_acc)
                } else {
                    if !chunk_acc.is_empty() {
                        unsafe_debug_log!("[{}] non-chunk frame interrupted chunk upload", peer);
                        break;
                    }
                    raw_bin
                };
                // Hold process-wide permits until this request has completed
                // decoding and backend dispatch; early `continue` paths drop
                // them automatically.
                let _completed_chunk_permits = completed_chunk_permits;

                if bin.len() < 5 {
                    continue;
                }
                let outer_payload = &bin[4..];

                // Encrypted-frame demux. If the first byte is the channel
                // magic AND we have an established session, open the frame
                // and dispatch the inner request as if it were cleartext.
                // If the magic appears but no session is established, that's
                // a protocol error (clients must REQ_HANDSHAKE first).
                let decrypted: Zeroizing<Vec<u8>>;
                let request_was_encrypted = outer_payload.first()
                    == Some(&pir_runtime_core::channel::ENCRYPTED_FRAME_MAGIC);
                let payload: &[u8] = if request_was_encrypted {
                    match channel_session.as_mut() {
                        Some(s) => {
                            match s.open(
                                pir_runtime_core::channel::Direction::ClientToServer,
                                outer_payload,
                            ) {
                                Ok(buf) => {
                                    decrypted = Zeroizing::new(buf);
                                    decrypted.as_slice()
                                }
                                Err(e) => {
                                    unsafe_debug_log!("[{}] channel open failed: {}", peer, e);
                                    if reserved_harmony_v2_full.is_some() {
                                        break;
                                    }
                                    let err =
                                        Response::Error(format!("channel open failed: {}", e));
                                    let _ = send_resp(
                                        &mut sink,
                                        channel_session.as_mut(),
                                        err.encode(),
                                    )
                                    .await;
                                    continue;
                                }
                            }
                        }
                        None => {
                            unsafe_debug_log!(
                                "[{}] received encrypted frame without established session",
                                peer
                            );
                            let err = Response::Error("encrypted frame received but no session established (run REQ_HANDSHAKE first)".into());
                            let _ =
                                send_resp(&mut sink, channel_session.as_mut(), err.encode()).await;
                            continue;
                        }
                    }
                } else {
                    outer_payload
                };

                if payload.is_empty() {
                    continue;
                }
                let variant = payload[0];
                let body = &payload[1..];
                sink.meter_pre_auth_response_for_opcode(variant);

                // After a V2Full grant, the hint provider accepts exactly the
                // bound, encrypted main-dispatch frame. Preflight belongs on
                // the independent query-provider connection and
                // should already be complete. This keeps arbitrary handler
                // awaits out of the scarce reservation's absolute deadline.
                if let Some(pending) = reserved_harmony_v2_full.as_ref() {
                    if pending
                        .dispatch_deadline
                        .is_some_and(|deadline| Instant::now() >= deadline)
                        || !is_exact_pending_v2full_dispatch_v1(
                            pending.db_id,
                            request_was_encrypted,
                            payload,
                        )
                    {
                        break;
                    }
                }

                // Production V1 admission gate. This check runs before every
                // legacy credential/mode gate and before any blocking PIR,
                // hint, OnionPIR, or ORAM work. Therefore a successful legacy
                // 0x08/0x09 presentation cannot unlock an enforced V1 server.
                if server.service_admission_enforcement == AdmissionEnforcementV1::Enforced {
                    // Reject a cleartext expensive opcode before parsing its
                    // backend body. This preserves secure-channel-first error
                    // ordering and avoids spending unauthenticated CPU on a
                    // potentially large request. The gate call also
                    // terminalizes any already-active paid grant.
                    if !request_was_encrypted && service_gate_is_backend_opcode_v1(variant) {
                        let gate_error = sink
                            .admission_gate_mut()
                            .reject_malformed_backend_frame(false);
                        let response = Response::Error(format!(
                            "service authorization required: {gate_error}"
                        ));
                        if let Err(send_error) =
                            send_resp(&mut sink, channel_session.as_mut(), response.encode()).await
                        {
                            unsafe_debug_log!(
                                "[{}] failed to deliver secure-channel rejection: {}",
                                peer,
                                send_error
                            );
                            break;
                        }
                        continue;
                    }
                    let backend_frame = match backend_frame_for_service_gate(&server, payload) {
                        Ok(frame) => frame,
                        Err(error) => {
                            if reserved_harmony_v2_full.is_some() {
                                break;
                            }
                            let gate_error = sink
                                .admission_gate_mut()
                                .reject_malformed_backend_frame(request_was_encrypted);
                            let response = Response::Error(format!(
                                "service admission rejected malformed backend frame ({gate_error}): {error}"
                            ));
                            let _ =
                                send_resp(&mut sink, channel_session.as_mut(), response.encode())
                                    .await;
                            continue;
                        }
                    };
                    if let Some(backend_frame) = backend_frame {
                        let now_monotonic_ms = u64::try_from(
                            server
                                .service_admission
                                .as_ref()
                                .expect("enforced service runtime")
                                .monotonic_origin
                                .elapsed()
                                .as_millis(),
                        )
                        .unwrap_or(u64::MAX);
                        // Preserve the gate's security-first error ordering.
                        // In particular, an unencrypted expensive frame must
                        // be rejected as a secure-channel violation even when
                        // no AUTH result has yet been delivered. Calling the
                        // gate also retains its terminal-after-spend behavior
                        // if a granted client later attempts plaintext.
                        if !request_was_encrypted {
                            let rejection = match sink.admission_gate_mut().permit_backend_frame(
                                false,
                                &backend_frame,
                                now_monotonic_ms,
                            ) {
                                Err(error) => error.to_string(),
                                Ok(_) => "secure encrypted channel is required".to_owned(),
                            };
                            let response = Response::Error(format!(
                                "service authorization required: {rejection}"
                            ));
                            if let Err(send_error) =
                                send_resp(&mut sink, channel_session.as_mut(), response.encode())
                                    .await
                            {
                                unsafe_debug_log!(
                                    "[{}] failed to deliver secure-channel rejection: {}",
                                    peer,
                                    send_error
                                );
                                break;
                            }
                            continue;
                        }
                        if let Err(error) = sink.require_auth_result_delivered_for_backend() {
                            let response =
                                Response::Error(format!("service authorization required: {error}"));
                            if let Err(send_error) =
                                send_resp(&mut sink, channel_session.as_mut(), response.encode())
                                    .await
                            {
                                unsafe_debug_log!(
                                    "[{}] failed to deliver service authorization rejection: {}",
                                    peer,
                                    send_error
                                );
                                break;
                            }
                            continue;
                        }
                        match sink.admission_gate_mut().permit_backend_frame(
                            true,
                            &backend_frame,
                            now_monotonic_ms,
                        ) {
                            Ok(permit) => sink.meter_backend_response(permit),
                            Err(error) => {
                                if reserved_harmony_v2_full.is_some() {
                                    break;
                                }
                                let response = Response::Error(format!(
                                    "service authorization required: {}",
                                    error
                                ));
                                let _ = send_resp(
                                    &mut sink,
                                    channel_session.as_mut(),
                                    response.encode(),
                                )
                                .await;
                                continue;
                            }
                        }
                    } else if !service_gate_allows_ungranted_opcode(variant) {
                        // Unknown/new opcodes and legacy credential frames are
                        // denied by default. Adding a future expensive backend
                        // requires an explicit BackendFrameV1 mapping and DFA
                        // rule; it cannot inherit an existing grant by
                        // omission.
                        let response = Response::Error(format!(
                            "opcode 0x{:02x} is not admitted by service authorization V1",
                            variant
                        ));
                        let _ =
                            send_resp(&mut sink, channel_session.as_mut(), response.encode()).await;
                        continue;
                    }
                }

                // ARC gate: if --require-arc is set and no valid credential
                // presented yet, reject PIR-bearing request variants. Whitelisted
                // variants (info, ping, auth, attest, handshake, hints, and the
                // credential presentation itself) pass through.
                if (server.require_arc || server.require_cashu) && !arc_ok && !cashu_ok {
                    match variant {
                        REQ_INDEX_BATCH
                        | REQ_CHUNK_BATCH
                        | REQ_BUCKET_MERKLE_SIB_BATCH
                        | REQ_BUCKET_MERKLE_TREE_TOPS
                        | REQ_HARMONY_QUERY
                        | REQ_HARMONY_BATCH_QUERY
                        | REQ_ORAM_LOOKUP
                        | REQ_REGISTER_KEYS
                        | REQ_ONIONPIR_INDEX_QUERY
                        | REQ_ONIONPIR_CHUNK_QUERY
                        | REQ_ONIONPIR_MERKLE_INDEX_SIBLING
                        | REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP
                        | REQ_ONIONPIR_MERKLE_DATA_SIBLING
                        | REQ_ONIONPIR_MERKLE_DATA_TREE_TOP => {
                            let resp = Response::Error(
                                "ARC credential required — send REQ_CREDENTIAL_PRESENT first"
                                    .into(),
                            );
                            let _ =
                                send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            continue;
                        }
                        _ => {}
                    }
                }

                // Mode gate: reject hint or query requests this server isn't
                // configured for (`--serve-hints` / `--serve-queries` flags).
                // Whitelisted opcodes (info / ping / attest / handshake /
                // credential / admin / db-catalog) always pass —
                // they don't expose hint or query content, only metadata
                // needed for clients to discover the server's capabilities.
                if !server.serve_hints {
                    match variant {
                        REQ_HARMONY_HINTS | REQ_HARMONY_HINTS_V2 | REQ_HARMONY_HINTS_V2_HALF => {
                            let resp = Response::Error(
                                "server not configured to serve hints — start with --serve-hints (see deploy/systemd/*.service)".into(),
                            );
                            let _ =
                                send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            continue;
                        }
                        _ => {}
                    }
                }
                if !server.serve_queries {
                    match variant {
                        REQ_INDEX_BATCH
                        | REQ_CHUNK_BATCH
                        | REQ_BUCKET_MERKLE_SIB_BATCH
                        | REQ_BUCKET_MERKLE_TREE_TOPS
                        | REQ_HARMONY_QUERY
                        | REQ_HARMONY_BATCH_QUERY
                        | REQ_ORAM_LOOKUP
                        | REQ_REGISTER_KEYS
                        | REQ_ONIONPIR_INDEX_QUERY
                        | REQ_ONIONPIR_CHUNK_QUERY
                        | REQ_ONIONPIR_MERKLE_INDEX_SIBLING
                        | REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP
                        | REQ_ONIONPIR_MERKLE_DATA_SIBLING
                        | REQ_ONIONPIR_MERKLE_DATA_TREE_TOP => {
                            let resp = Response::Error(
                                "server not configured to answer queries — start with --serve-queries (see deploy/systemd/*.service)".into(),
                            );
                            let _ =
                                send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            continue;
                        }
                        _ => {}
                    }
                }

                // Route by variant byte
                match variant {
                    // ── Shared: info / ping ──────────────────────────────
                    REQ_PING => {
                        let _ = send_resp(&mut sink, channel_session.as_mut(), Response::Pong.encode()).await;
                    }
                    REQ_GET_INFO => {
                        let _ = send_resp(&mut sink, channel_session.as_mut(), Response::Info(server.server_info()).encode()).await;
                    }
                    0x03 /* REQ_GET_INFO_JSON */ => {
                        let _ = send_resp(&mut sink, channel_session.as_mut(), server.encode_info_json_response(0x03)).await;
                    }
                    // 0x33 was REQ_ONIONPIR_GET_INFO (binary ServerInfoV2), now removed.
                    // All clients should use 0x03 (JSON) instead.
                    REQ_GET_DB_CATALOG => {
                        let _ = send_resp(&mut sink, channel_session.as_mut(), Response::DbCatalog(server.build_catalog()).encode()).await;
                    }
                    REQ_GET_DB_PROOF => {
                        if body.len() != 1 {
                            let resp = Response::Error(
                                "malformed REQ_GET_DB_PROOF: expected one db_id byte".into(),
                            );
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            continue;
                        }
                        let db_id = body[0];
                        let resp = match server
                            .state
                            .get_db(db_id)
                            .and_then(|db| db.db_proof.as_ref())
                        {
                            Some(bundle) => Response::DbProof(bundle.clone()),
                            None => Response::Error(format!(
                                "db proof not configured for db_id {}",
                                db_id
                            )),
                        };
                        let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                    }
                    REQ_GET_DB_PROOF_V2 => {
                        if body.len() != 1 {
                            let resp = Response::Error(
                                "malformed REQ_GET_DB_PROOF_V2: expected one db_id byte".into(),
                            );
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            continue;
                        }
                        let db_id = body[0];
                        let resp = match server
                            .state
                            .get_db(db_id)
                            .and_then(|db| db.db_proof_v2.as_ref())
                        {
                            Some(bundle) => Response::DbProofV2(bundle.clone()),
                            None => Response::Error(format!(
                                "db proof v2 not configured for db_id {}",
                                db_id
                            )),
                        };
                        let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                    }
                    REQ_SERVICE_POLICY_V1 => {
                        if !request_was_encrypted {
                            let response = Response::Error(
                                "REQ_SERVICE_POLICY_V1 requires the authenticated encrypted channel"
                                    .into(),
                            );
                            let _ = send_resp(
                                &mut sink,
                                channel_session.as_mut(),
                                response.encode(),
                            )
                            .await;
                            continue;
                        }
                        match ServiceWireRequestV1::decode_inner_payload(payload) {
                            Ok(Some(ServiceWireRequestV1::Policy(request))) => {
                                let Some(runtime) = server.service_admission.as_ref() else {
                                    let response = Response::Error(
                                        "server is in explicit legacy migration mode; V1 policy/auth never falls back to legacy credentials"
                                            .into(),
                                    );
                                    let _ = send_resp(
                                        &mut sink,
                                        channel_session.as_mut(),
                                        response.encode(),
                                    )
                                    .await;
                                    continue;
                                };
                                let now_unix = match current_unix_seconds_v1() {
                                    Ok(now) => now,
                                    Err(_) => {
                                        let response = Response::Error(
                                            "service policy unavailable: system clock invalid"
                                                .into(),
                                        );
                                        let _ = send_resp(
                                            &mut sink,
                                            channel_session.as_mut(),
                                            response.encode(),
                                        )
                                        .await;
                                        continue;
                                    }
                                };
                                let Some((policy_response, served_policy_digest)) =
                                    runtime.response_for_policy_request(request, now_unix)
                                else {
                                    let response = Response::Error(
                                        "requested service policy unavailable or outside redemption grace"
                                            .into(),
                                    );
                                    let _ = send_resp(
                                        &mut sink,
                                        channel_session.as_mut(),
                                        response.encode(),
                                    )
                                    .await;
                                    continue;
                                };
                                let encoded = match encode_service_policy_response_v1(
                                    &policy_response,
                                ) {
                                    Ok(encoded) => encoded,
                                    Err(error) => {
                                        unsafe_debug_log!(
                                            "[{}] activated service policy encoding failed: {}",
                                            peer, error
                                        );
                                        let response = Response::Error(
                                            "service policy encoding failed".into(),
                                        );
                                        let _ = send_resp(
                                            &mut sink,
                                            channel_session.as_mut(),
                                            response.encode(),
                                        )
                                        .await;
                                        continue;
                                    }
                                };
                                if let Err(error) = send_resp(
                                    &mut sink,
                                    channel_session.as_mut(),
                                    encoded,
                                )
                                .await
                                {
                                    unsafe_debug_log!(
                                        "[{}] service policy send failed: {}",
                                        peer,
                                        error
                                    );
                                    break;
                                }
                                if let Err(error) = sink.admission_gate_mut().policy_served(
                                    true,
                                    served_policy_digest,
                                ) {
                                    unsafe_debug_log!(
                                        "[{}] service policy gate transition failed after send: {}",
                                        peer, error
                                    );
                                    break;
                                }
                            }
                            Ok(_) => unreachable!("matched service-policy opcode"),
                            Err(error) => {
                                let response = Response::Error(format!(
                                    "malformed REQ_SERVICE_POLICY_V1: {}",
                                    error
                                ));
                                let _ = send_resp(
                                    &mut sink,
                                    channel_session.as_mut(),
                                    response.encode(),
                                )
                                .await;
                            }
                        }
                    }
                    REQ_AUTH_BEGIN_V1 => {
                        let result = if !request_was_encrypted {
                            pir_service_protocol::AuthResultV1::Rejected(
                                pir_service_protocol::AuthRejectedV1 {
                                    code: pir_service_protocol::AuthRejectCode::SecureChannelRequired,
                                    retry_after_ms: 0,
                                },
                            )
                        } else {
                            match ServiceWireRequestV1::decode_inner_payload(payload) {
                                Ok(Some(ServiceWireRequestV1::Auth(request))) => {
                                    let Some(runtime) = server.service_admission.as_ref() else {
                                        let unavailable = pir_service_protocol::AuthResultV1::Rejected(
                                            pir_service_protocol::AuthRejectedV1 {
                                                code: pir_service_protocol::AuthRejectCode::ScopeUnavailable,
                                                retry_after_ms: 0,
                                            },
                                        );
                                        let response = encode_auth_result_response_v1(&unavailable)
                                            .expect("bounded rejection encoding");
                                        let _ = send_resp(
                                            &mut sink,
                                            channel_session.as_mut(),
                                            response,
                                        )
                                        .await;
                                        continue;
                                    };
                                    let now_unix = match current_unix_seconds_v1() {
                                        Ok(now) => now,
                                        Err(_) => {
                                            let unavailable = pir_service_protocol::AuthResultV1::Rejected(
                                                pir_service_protocol::AuthRejectedV1 {
                                                    code: pir_service_protocol::AuthRejectCode::ScopeUnavailable,
                                                    retry_after_ms: 0,
                                                },
                                            );
                                            let response = encode_auth_result_response_v1(&unavailable)
                                                .expect("bounded rejection encoding");
                                            let _ = send_resp(
                                                &mut sink,
                                                channel_session.as_mut(),
                                                response,
                                            )
                                            .await;
                                            continue;
                                        }
                                    };
                                    match (
                                        runtime.policy_for_digest(&request.policy_digest),
                                        runtime.verified_offer_for_authorization(
                                            &request.policy_digest,
                                            &request.scope_id,
                                            request.offer_id,
                                            now_unix,
                                        ),
                                    ) {
                                        (Some(selected_policy), Ok(Some(verified_offer))) => {
                                            let arc_canonicalizer = if verified_offer
                                                .offer()
                                                .authorization
                                                == pir_service_protocol::AuthScheme::ArcV1Experimental
                                            {
                                                ExperimentalArcPresentationCanonicalizerV1::from_verified_offer_v1(
                                                    &verified_offer,
                                                    now_unix,
                                                )
                                                .ok()
                                            } else {
                                                None
                                            };
                                            let trusted_catalog = |operation: &OperationStartV1| {
                                                server.resolve_service_operation_for_policy_v1(
                                                    selected_policy,
                                                    operation,
                                                )
                                            };
                                            let arc_canonicalizer_ref = arc_canonicalizer.as_ref().map(
                                                |canonicalizer| {
                                                    canonicalizer
                                                        as &dyn pir_service_protocol::ArcPresentationCanonicalizerV1
                                                },
                                            );
                                            // This first bind is structural and
                                            // non-consuming. It is intentionally
                                            // repeated inside the admission gate:
                                            // only an exact locally bound V2Full
                                            // attempt may reserve scarce capacity,
                                            // while the gate remains the sole path
                                            // to proof verification and commit.
                                            let v2_full_reservation_db_id =
                                                bind_auth_begin_v1(
                                                    &request,
                                                    verified_offer,
                                                    &trusted_catalog,
                                                    arc_canonicalizer_ref,
                                                )
                                                .ok()
                                                .and_then(|attempt| {
                                                    harmony_v2_full_reservation_db_v1(
                                                        attempt.operation(),
                                                    )
                                                });
                                            let requires_v2_full_reservation =
                                                v2_full_reservation_db_id.is_some();
                                            let requires_online_v2full_authority =
                                                requires_v2_full_reservation
                                                    && verified_offer.offer().verification
                                                        != pir_service_protocol::VerificationMode::ProviderLocal;
                                            // Online V2Full first acquires its narrower class
                                            // permit. Only then may it compete for the global
                                            // AUTH permit, so rejected overflow cannot steal the
                                            // slot reserved for provider-local verification.
                                            let mut auth_capacity = try_acquire_auth_capacity_v1(
                                                &service_auth_limiter,
                                                &online_v2full_auth_limiter,
                                                requires_online_v2full_authority,
                                            );
                                            let auth_capacity_saturated = auth_capacity.is_none();
                                            let mut attempt_reservation = if auth_capacity_saturated {
                                                None
                                            } else {
                                                v2_full_reservation_db_id.and_then(|db_id| {
                                                    server
                                                        .hint_pool
                                                        .as_ref()
                                                        .filter(|pool| {
                                                            pool.database_id() == db_id
                                                        })
                                                        .and_then(|pool| {
                                                            if requires_online_v2full_authority {
                                                                pool.try_reserve_preserving_ready_floor(1)
                                                            } else {
                                                                pool.try_reserve()
                                                            }
                                                        })
                                                        .map(|reservation| {
                                                            PendingHarmonyV2FullEntryV1 {
                                                                db_id,
                                                                reservation,
                                                                _online_authority_permit: None,
                                                                dispatch_deadline: None,
                                                            }
                                                        })
                                                })
                                            };
                                            if auth_capacity_saturated
                                                || (requires_v2_full_reservation
                                                    && attempt_reservation.is_none())
                                            {
                                                pir_service_protocol::AuthResultV1::Rejected(
                                                    pir_service_protocol::AuthRejectedV1 {
                                                        code: pir_service_protocol::AuthRejectCode::ServerBusy,
                                                        retry_after_ms: 1_000,
                                                    },
                                                )
                                            } else {
                                                let provider_local = runtime.provider_store.as_ref().map(|store| {
                                                    let committer = ProviderStoreBearerCommitterV1::new(
                                                        store,
                                                        runtime
                                                            .bat_keyring
                                                            .as_ref()
                                                            .map(|keyring| keyring as &dyn pir_service_store::CashuBatProofVerifierV1),
                                                    );
                                                    match runtime.experimental_arc_keyring.as_ref() {
                                                        Some(keyring) => committer.with_arc_adapter_v1(keyring),
                                                        None => committer,
                                                    }
                                                });
                                                let mut composite =
                                                    CompositeAdmissionMethodCommitterV1::new();
                                                if let Some(committer) = provider_local.as_ref() {
                                                    composite = composite.with_provider_local(committer);
                                                }
                                                if let Some(free) = free_admission.as_ref() {
                                                    composite = composite.with_free(free);
                                                }
                                                let standard_cashu = match (
                                                    runtime.provider_store.as_ref(),
                                                    runtime.cashu_recovery_cipher.as_ref(),
                                                    runtime.cashu_custody_cipher.as_ref(),
                                                    verified_offer
                                                        .offer()
                                                        .cashu_mint_manifest
                                                        .as_ref(),
                                                ) {
                                                    (
                                                        Some(store),
                                                        Some(recovery),
                                                        Some(custody),
                                                        Some(manifest),
                                                    ) => runtime
                                                        .cashu_exposure_limits
                                                        .get(&(
                                                            manifest.mint_id(),
                                                            manifest.unit.clone(),
                                                        ))
                                                        .copied()
                                                        .map(|limits| {
                                                            StandardCashuAdmissionCommitterV1::new(
                                                                StandardCashuClientV1::new(
                                                                    store,
                                                                    &runtime.http_transport,
                                                                    recovery,
                                                                    custody,
                                                                    limits,
                                                                ),
                                                            )
                                                        }),
                                                    _ => None,
                                                };
                                                if let Some(committer) = standard_cashu.as_ref() {
                                                    composite =
                                                        composite.with_standard_cashu(committer);
                                                }
                                                let shared_issuer = runtime
                                                    .shared_issuer
                                                    .as_ref()
                                                    .zip(runtime.provider_store.as_ref())
                                                    .and_then(|(config, store)| {
                                                        config
                                                            .committer(
                                                                store,
                                                                &runtime.http_transport,
                                                            )
                                                            .ok()
                                                    });
                                                if let Some(committer) = shared_issuer.as_ref() {
                                                    composite =
                                                        composite.with_shared_issuer(committer);
                                                }
                                                let monotonic_now_ms = || {
                                                    u64::try_from(
                                                        runtime
                                                            .monotonic_origin
                                                            .elapsed()
                                                            .as_millis(),
                                                    )
                                                    .unwrap_or(u64::MAX)
                                                };
                                                let result = tokio::task::block_in_place(|| {
                                                    sink.admission_gate_mut().authorize_and_commit_with_harmony_registry(
                                                        true,
                                                        &request,
                                                        verified_offer,
                                                        &trusted_catalog,
                                                        arc_canonicalizer_ref,
                                                        &composite,
                                                        Some(&runtime.harmony_attach_registry),
                                                        now_unix,
                                                        &monotonic_now_ms,
                                                    )
                                                });
                                                let granted = matches!(
                                                    &result,
                                                    pir_service_protocol::AuthResultV1::Granted(_)
                                                );
                                                let mut missing_reservation_after_grant = false;
                                                if granted && requires_v2_full_reservation {
                                                    match attempt_reservation.take() {
                                                        Some(mut reservation)
                                                            if reserved_harmony_v2_full.is_none() =>
                                                        {
                                                            // Keep the inode lock until the first
                                                            // main dispatch. A lost/expired grant
                                                            // response must not burn an unexposed,
                                                            // expensive precomputed hint.
                                                            reservation._online_authority_permit =
                                                                auth_capacity
                                                                    .as_mut()
                                                                    .and_then(|(online, _global)| {
                                                                        online.take()
                                                                    });
                                                            reserved_harmony_v2_full = Some(reservation);
                                                        }
                                                        Some(reservation) => {
                                                            if let Err(error) =
                                                                reservation.reservation.restore()
                                                            {
                                                                eprintln!(
                                                                    "[hint-pool] Failed to restore a duplicate pre-credential reservation"
                                                                );
                                                                unsafe_debug_log!(
                                                                    "[hint-pool] duplicate reservation restore detail: {}",
                                                                    error
                                                                );
                                                            }
                                                            missing_reservation_after_grant = true;
                                                        }
                                                        None => {
                                                            missing_reservation_after_grant = true;
                                                        }
                                                    }
                                                } else if let Some(reservation) =
                                                    attempt_reservation.take()
                                                {
                                                    if let Err(error) =
                                                        reservation.reservation.restore()
                                                    {
                                                        eprintln!(
                                                            "[hint-pool] Failed to restore a rejected pre-credential reservation"
                                                        );
                                                        unsafe_debug_log!(
                                                            "[hint-pool] rejected reservation restore detail: {}",
                                                            error
                                                        );
                                                    }
                                                }
                                                if missing_reservation_after_grant {
                                                    pir_service_protocol::AuthResultV1::Rejected(
                                                        pir_service_protocol::AuthRejectedV1 {
                                                            code: pir_service_protocol::AuthRejectCode::InternalAfterSpend,
                                                            retry_after_ms: 0,
                                                        },
                                                    )
                                                } else {
                                                    result
                                                }
                                            }
                                        }
                                        _ => pir_service_protocol::AuthResultV1::Rejected(
                                            pir_service_protocol::AuthRejectedV1 {
                                                code: pir_service_protocol::AuthRejectCode::PolicyChanged,
                                                retry_after_ms: 0,
                                            },
                                        ),
                                    }
                                }
                                Ok(_) => unreachable!("matched auth-begin opcode"),
                                Err(error) => {
                                    let response = Response::Error(format!(
                                        "malformed REQ_AUTH_BEGIN_V1: {}",
                                        error
                                    ));
                                    let _ = send_resp(
                                        &mut sink,
                                        channel_session.as_mut(),
                                        response.encode(),
                                    )
                                    .await;
                                    continue;
                                }
                            }
                        };
                        // A Cashu/shared-issuer/remote-authority commit may be
                        // durable even when its bounded blocking call outlives
                        // this connection's absolute pre-auth deadline. Never
                        // cancel that call into an unknown outcome. Once it
                        // returns, fail closed before revealing the result or
                        // allowing any PIR work on the expired connection.
                        if post_authorization_deadline_expired_v1(
                            server.service_admission_enforcement,
                            pre_auth_started.elapsed(),
                            service_pre_auth_timeout,
                        ) {
                            unsafe_debug_log!(
                                "[{}] pre-authorization deadline expired after authorization commit; closing without a grant response",
                                peer
                            );
                            break;
                        }
                        // The sink's still-armed fixed deadline supplies the
                        // remaining absolute budget to both write and flush.
                        // Only a fully flushed Granted response changes the
                        // connection to ordinary idle-timeout handling.
                        let granted = matches!(
                            &result,
                            pir_service_protocol::AuthResultV1::Granted(_)
                        );
                        if let Err(error) = deliver_auth_result_response_v1(
                            &mut sink,
                            channel_session.as_mut(),
                            &result,
                        )
                        .await
                        {
                            unsafe_debug_log!(
                                "[{}] failed to deliver authorization result before deadline: {}",
                                peer,
                                error
                            );
                            break;
                        }
                        if granted {
                            if let Some(pending) = reserved_harmony_v2_full.as_mut() {
                                // Arm only after the complete AUTH_GRANTED frame
                                // has been flushed. A slow but successful flush
                                // cannot consume the client's dispatch window,
                                // and a later frame can never reset this value.
                                arm_v2full_dispatch_deadline_v1(
                                    &mut pending.dispatch_deadline,
                                    Instant::now(),
                                    v2full_dispatch_timeout,
                                );
                            }
                        }
                    }
                    REQ_POW_CHALLENGE_V1 => {
                        if !request_was_encrypted {
                            let response = Response::Error(
                                "PoW challenge requires the authenticated encrypted channel"
                                    .into(),
                            );
                            let _ = send_resp(
                                &mut sink,
                                channel_session.as_mut(),
                                response.encode(),
                            )
                            .await;
                            continue;
                        }
                        let request = match ServiceWireRequestV1::decode_inner_payload(payload) {
                            Ok(Some(ServiceWireRequestV1::PowChallenge(request))) => request,
                            Ok(_) => unreachable!("matched PoW challenge opcode"),
                            Err(error) => {
                                let response = Response::Error(format!(
                                    "malformed REQ_POW_CHALLENGE_V1: {error}"
                                ));
                                let _ = send_resp(
                                    &mut sink,
                                    channel_session.as_mut(),
                                    response.encode(),
                                )
                                .await;
                                continue;
                            }
                        };
                        let Some(runtime) = server.service_admission.as_ref() else {
                            let response = Response::Error(
                                "service admission V1 is not enabled".into(),
                            );
                            let _ = send_resp(
                                &mut sink,
                                channel_session.as_mut(),
                                response.encode(),
                            )
                            .await;
                            continue;
                        };
                        let Some(free) = free_admission.as_ref() else {
                            let response = Response::Error(
                                "Free admission is not bound to this secure channel".into(),
                            );
                            let _ = send_resp(
                                &mut sink,
                                channel_session.as_mut(),
                                response.encode(),
                            )
                            .await;
                            continue;
                        };
                        let now_unix = match current_unix_seconds_v1() {
                            Ok(now) => now,
                            Err(_) => {
                                let response =
                                    Response::Error("service clock unavailable".into());
                                let _ = send_resp(
                                    &mut sink,
                                    channel_session.as_mut(),
                                    response.encode(),
                                )
                                .await;
                                continue;
                            }
                        };
                        if !runtime.is_current_policy_digest(&request.policy_digest) {
                            let response = Response::Error(
                                "PoW challenges are available only under the current policy"
                                    .into(),
                            );
                            let _ = send_resp(
                                &mut sink,
                                channel_session.as_mut(),
                                response.encode(),
                            )
                            .await;
                            continue;
                        }
                        let verified_offer = match runtime.policy.verified_offer(
                            &request.scope_id,
                            request.offer_id,
                            now_unix,
                        ) {
                            Ok(offer) => offer,
                            Err(_) => {
                                let response =
                                    Response::Error("service offer unavailable".into());
                                let _ = send_resp(
                                    &mut sink,
                                    channel_session.as_mut(),
                                    response.encode(),
                                )
                                .await;
                                continue;
                            }
                        };
                        let catalog_matches = server
                            .resolve_service_operation_for_policy_v1(
                                runtime.policy.policy(),
                                &request.operation,
                            )
                            .is_some_and(|resolution| {
                                let scope = verified_offer.scope();
                                resolution.backend() == scope.backend
                                    && resolution.workload() == scope.workload
                                    && resolution.protocol_version() == scope.protocol_version
                                    && resolution.dataset() == &scope.dataset
                                    && resolution.operation_profile() == scope.operation_profile
                            });
                        if !catalog_matches
                            || sink
                                .admission_gate_mut()
                                .permit_pow_challenge(true, &request.policy_digest)
                                .is_err()
                        {
                            let response =
                                Response::Error("PoW challenge scope unavailable".into());
                            let _ = send_resp(
                                &mut sink,
                                channel_session.as_mut(),
                                response.encode(),
                            )
                            .await;
                            continue;
                        }
                        let challenge = match free.issue_pow_challenge(
                            *request,
                            verified_offer,
                            now_unix,
                            60,
                        ) {
                            Ok(challenge) => challenge,
                            Err(_) => {
                                let response =
                                    Response::Error("PoW challenge unavailable".into());
                                let _ = send_resp(
                                    &mut sink,
                                    channel_session.as_mut(),
                                    response.encode(),
                                )
                                .await;
                                continue;
                            }
                        };
                        let encoded = match encode_pow_challenge_response_v1(&challenge) {
                            Ok(encoded) => encoded,
                            Err(_) => {
                                let response =
                                    Response::Error("PoW challenge encoding failed".into());
                                let _ = send_resp(
                                    &mut sink,
                                    channel_session.as_mut(),
                                    response.encode(),
                                )
                                .await;
                                continue;
                            }
                        };
                        let _ = send_resp(
                            &mut sink,
                            channel_session.as_mut(),
                            encoded,
                        )
                        .await;
                    }
                    REQ_HARMONY_ATTACH_V1 => {
                        let result = if !request_was_encrypted {
                            HarmonyAttachResultV1::Rejected {
                                code: HarmonyAttachRejectCodeV1::SecureChannelRequired,
                            }
                        } else {
                            let request = match ServiceWireRequestV1::decode_inner_payload(payload) {
                                Ok(Some(ServiceWireRequestV1::HarmonyAttach(request))) => request,
                                Ok(_) => unreachable!("matched Harmony attach opcode"),
                                Err(error) => {
                                    let response = Response::Error(format!(
                                        "malformed REQ_HARMONY_ATTACH_V1: {error}"
                                    ));
                                    if let Err(send_error) = send_resp(
                                        &mut sink,
                                        channel_session.as_mut(),
                                        response.encode(),
                                    )
                                    .await
                                    {
                                        unsafe_debug_log!(
                                            "[{}] failed to deliver malformed Harmony attach rejection: {}",
                                            peer,
                                            send_error
                                        );
                                        break;
                                    }
                                    continue;
                                }
                            };
                            let Some(runtime) = server.service_admission.as_ref() else {
                                let result = HarmonyAttachResultV1::Rejected {
                                    code: HarmonyAttachRejectCodeV1::NoWaitingOperation,
                                };
                                if let Err(error) = deliver_harmony_attach_result_response_v1(
                                    &mut sink,
                                    channel_session.as_mut(),
                                    &result,
                                )
                                .await
                                {
                                    unsafe_debug_log!(
                                        "[{}] failed to deliver Harmony attach result before deadline: {}",
                                        peer,
                                        error
                                    );
                                    break;
                                }
                                continue;
                            };
                            if sink
                                .admission_gate_mut()
                                .permit_harmony_attach(true, &request.policy_digest)
                                .is_err()
                            {
                                HarmonyAttachResultV1::Rejected {
                                    code: HarmonyAttachRejectCodeV1::WrongBinding,
                                }
                            } else {
                                let now_monotonic_ms = u64::try_from(
                                    runtime.monotonic_origin.elapsed().as_millis(),
                                )
                                .unwrap_or(u64::MAX);
                                match runtime
                                    .harmony_attach_registry
                                    .try_attach_v1(&request, now_monotonic_ms)
                                {
                                    Ok(attached) => {
                                        let operation_id = *attached.operation_id();
                                        match sink
                                            .admission_gate_mut()
                                            .install_attached_harmony_grant_v1(
                                                true,
                                                attached,
                                                now_monotonic_ms,
                                            ) {
                                            Ok(()) => HarmonyAttachResultV1::Attached {
                                                operation_id,
                                            },
                                            Err(_) => HarmonyAttachResultV1::Rejected {
                                                code: HarmonyAttachRejectCodeV1::WrongBinding,
                                            },
                                        }
                                    }
                                    Err(error) => HarmonyAttachResultV1::Rejected {
                                        code: match error {
                                            HarmonyAttachTransitionErrorV1::NoWaitingOperation => {
                                                HarmonyAttachRejectCodeV1::NoWaitingOperation
                                            }
                                            HarmonyAttachTransitionErrorV1::Expired => {
                                                HarmonyAttachRejectCodeV1::Expired
                                            }
                                            HarmonyAttachTransitionErrorV1::WrongBinding => {
                                                HarmonyAttachRejectCodeV1::WrongBinding
                                            }
                                            HarmonyAttachTransitionErrorV1::WrongSide => {
                                                HarmonyAttachRejectCodeV1::WrongSide
                                            }
                                            HarmonyAttachTransitionErrorV1::AlreadyAttached => {
                                                HarmonyAttachRejectCodeV1::AlreadyAttached
                                            }
                                        },
                                    },
                                }
                            }
                        };
                        if let Err(error) = deliver_harmony_attach_result_response_v1(
                            &mut sink,
                            channel_session.as_mut(),
                            &result,
                        )
                        .await
                        {
                            unsafe_debug_log!(
                                "[{}] failed to deliver Harmony attach result before deadline: {}",
                                peer,
                                error
                            );
                            break;
                        }
                    }
                    REQ_CREDENTIAL_PRESENT => {
                        // Wire format:
                        //   [1B variant=0x08]
                        //   [1B request_context_len][request_context]
                        //   [1B presentation_context_len][presentation_context]
                        //   [8B presentation_limit LE]
                        //   [presentation_bytes...]
                        if body.len() < 11 {
                            let resp = Response::Error("malformed REQ_CREDENTIAL_PRESENT: too short".into());
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            continue;
                        }
                        let req_ctx_len = body[0] as usize;
                        if body.len() < 1 + req_ctx_len + 1 {
                            let resp = Response::Error("malformed REQ_CREDENTIAL_PRESENT: truncated".into());
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            continue;
                        }
                        let req_ctx = &body[1..1 + req_ctx_len];
                        let off = 1 + req_ctx_len;
                        let pres_ctx_len = body[off] as usize;
                        if body.len() < off + 1 + pres_ctx_len + 8 {
                            let resp = Response::Error("malformed REQ_CREDENTIAL_PRESENT: truncated".into());
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            continue;
                        }
                        let pres_ctx = &body[off + 1..off + 1 + pres_ctx_len];
                        let limit_off = off + 1 + pres_ctx_len;
                        let limit = u64::from_le_bytes(
                            body[limit_off..limit_off + 8].try_into().unwrap()
                        );
                        let pres_bytes = &body[limit_off + 8..];

                        let result = match &server.arc_verifier {
                            None => Err(pir_runtime_core::arc_verifier::ArcVerifyError::InvalidProof(
                                "ARC disabled on this server".into()
                            )),
                            Some(verifier) => {
                                let mut v = verifier.lock().unwrap();
                                v.verify(req_ctx, pres_ctx, pres_bytes, limit)
                            }
                        };

                        match result {
                            Ok(()) => {
                                arc_ok = true;
                                arc_pres_ctx = Some(pres_ctx.to_vec());
                                let resp = Response::ArcCredentialOk;
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            }
                            Err(e) => {
                                arc_ok = false;
                                let resp = Response::Error(format!("ARC: {}", e));
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            }
                        }
                    }
                    REQ_CASHU_BAT_PRESENT => {
                        // Wire format: [1B variant=0x09][bat_base64url bytes...]
                        let bat_str = match std::str::from_utf8(body) {
                            Ok(s) => s,
                            Err(_) => {
                                let resp = Response::Error("invalid UTF-8 in Cashu BAT".into());
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                        };
                        let result = match &server.cashu_verifier {
                            None => Err(pir_runtime_core::cashu_verifier::CashuVerifyError::InvalidFormat(
                                "Cashu disabled on this server".into(),
                            )),
                            Some(v) => v.lock().unwrap().verify(bat_str),
                        };
                        match result {
                            Ok(()) => {
                                cashu_ok = true;
                                let resp = Response::CashuBatOk;
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            }
                            Err(e) => {
                                cashu_ok = false;
                                let resp = Response::Error(format!("Cashu: {}", e));
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            }
                        }
                    }
                    REQ_ADMIN_AUTH_CHALLENGE => {
                        match server.admin_config {
                            None => {
                                let resp = Response::Error("admin auth disabled (server started without --admin-pubkey-hex)".into());
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            }
                            Some(_) => {
                                let nonce = admin_state.issue_challenge();
                                let resp = Response::AdminAuthChallenge(
                                    pir_runtime_core::protocol::AdminAuthChallenge { nonce },
                                );
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            }
                        }
                    }
                    REQ_ADMIN_AUTH_RESPONSE => {
                        let cfg = match server.admin_config.as_ref() {
                            Some(c) => c,
                            None => {
                                let resp = Response::Error("admin auth disabled".into());
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                        };
                        let signature = if let Ok(Request::AdminAuthResponse { signature }) = Request::decode(payload) {
                            signature
                        } else {
                            let resp = Response::Error("malformed REQ_ADMIN_AUTH_RESPONSE".into());
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            continue;
                        };
                        let result = match admin_state.verify_response(&signature, cfg) {
                            Ok(()) => {
                                println!("admin authenticated");
                                pir_runtime_core::protocol::AdminAuthResult { ok: true, msg: "ok".into() }
                            }
                            Err(e) => {
                                eprintln!("admin auth failed: {}", e);
                                pir_runtime_core::protocol::AdminAuthResult { ok: false, msg: e.to_string() }
                            }
                        };
                        let _ = send_resp(&mut sink, channel_session.as_mut(), Response::AdminAuthResponse(result).encode()).await;
                    }
                    REQ_ADMIN_DB_UPLOAD_BEGIN | REQ_ADMIN_DB_UPLOAD_CHUNK
                    | REQ_ADMIN_DB_UPLOAD_FINALIZE | REQ_ADMIN_DB_ACTIVATE => {
                        if !admin_state.authenticated {
                            let resp = Response::Error("not authenticated; complete REQ_ADMIN_AUTH_* first".into());
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            continue;
                        }
                        let req = match Request::decode(payload) {
                            Ok(r) => r,
                            Err(e) => {
                                let resp = Response::Error(format!("decode admin request: {}", e));
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                        };
                        let resp = match req {
                            Request::AdminDbUploadBegin { name, manifest_toml } => {
                                let r = match admin_state.begin_upload(name.clone(), manifest_toml, &server.data_root) {
                                    Ok(()) => {
                                        println!("admin upload BEGIN {:?}", name);
                                        pir_runtime_core::protocol::AdminAck { ok: true, msg: "ok".into() }
                                    }
                                    Err(e) => {
                                        eprintln!("admin upload BEGIN failed: {}", e);
                                        pir_runtime_core::protocol::AdminAck { ok: false, msg: e.to_string() }
                                    }
                                };
                                Response::AdminDbUploadBegin(r)
                            }
                            Request::AdminDbUploadChunk { name, file_path, offset, data } => {
                                let r = match admin_state.write_chunk(&name, &file_path, offset, &data) {
                                    Ok(()) => pir_runtime_core::protocol::AdminAck { ok: true, msg: "ok".into() },
                                    Err(e) => pir_runtime_core::protocol::AdminAck { ok: false, msg: e.to_string() },
                                };
                                Response::AdminDbUploadChunk(r)
                            }
                            Request::AdminDbUploadFinalize { name } => {
                                let r = match admin_state.finalize_upload(&name) {
                                    Ok(root) => pir_runtime_core::protocol::AdminFinalizeResult {
                                        ok: true,
                                        msg: "verified".into(),
                                        manifest_root: root,
                                    },
                                    Err(e) => pir_runtime_core::protocol::AdminFinalizeResult {
                                        ok: false,
                                        msg: e.to_string(),
                                        manifest_root: [0u8; 32],
                                    },
                                };
                                Response::AdminDbUploadFinalize(r)
                            }
                            Request::AdminDbActivate { name, target_path } => {
                                let r = match admin_state.activate(&name, &target_path, &server.data_root) {
                                    Ok(()) => {
                                        println!(
                                            "admin ACTIVATE {:?} → {:?} (restart server to load)",
                                            name, target_path
                                        );
                                        pir_runtime_core::protocol::AdminAck {
                                            ok: true,
                                            msg: "activated; restart server to load".into(),
                                        }
                                    }
                                    Err(e) => pir_runtime_core::protocol::AdminAck { ok: false, msg: e.to_string() },
                                };
                                Response::AdminDbActivate(r)
                            }
                            _ => unreachable!("variant byte already filtered"),
                        };
                        let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                    }
                    REQ_ATTEST => {
                        if let Ok(Request::Attest { nonce }) = Request::decode(payload) {
                            let s = Arc::clone(&server);
                            let resp = tokio::task::spawn_blocking(move || {
                                use pir_runtime_core::attest;
                                let manifest_roots: Vec<[u8; 32]> = s.state.databases.iter()
                                    .map(|db| db.manifest_root.unwrap_or([0u8; 32]))
                                    .collect();
                                let binary_sha256 = attest::self_exe_sha256();
                                let server_static_pub = s.state.server_static_pub;
                                let git_rev = attest::GIT_REV;
                                let report_data = attest::build_report_data(
                                    nonce,
                                    &manifest_roots,
                                    binary_sha256,
                                    server_static_pub,
                                    git_rev,
                                );
                                let sev_snp_report = attest::fetch_report(report_data)
                                    .ok().flatten().unwrap_or_default();
                                Response::Attest(pir_runtime_core::protocol::AttestResult {
                                    sev_snp_report,
                                    manifest_roots,
                                    binary_sha256,
                                    server_static_pub,
                                    git_rev: git_rev.to_string(),
                                    ark_pem: s.state.ark_pem.clone(),
                                    ask_pem: s.state.ask_pem.clone(),
                                    vcek_pem: s.state.vcek_pem.clone(),
                                })
                            }).await.unwrap();
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                        }
                    }
                    REQ_ANNOUNCE => {
                        // Operator-signed identity bundle, built at startup
                        // into `ServerState.announcement_bundle` when the
                        // --identity-* flags are set. `None` means the server
                        // lacks an identity key / operator cert.
                        let resp = build_announce_response(&server.state.announcement_bundle);
                        let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                    }
                    REQ_HANDSHAKE => {
                        // Encrypted-channel handshake. The reply MUST go out
                        // in cleartext — the client doesn't have the session
                        // key until it processes RESP_HANDSHAKE. So we mint
                        // the Session AFTER the send, and the next inbound
                        // frame the client sends will be encrypted.
                        if channel_session.is_some() {
                            let err = Response::Error(
                                "secure channel is already established on this connection".into(),
                            );
                            let _ = send_resp(
                                &mut sink,
                                channel_session.as_mut(),
                                err.encode(),
                            )
                            .await;
                            break;
                        }
                        if let Ok(Request::Handshake { client_eph_pub, nonce }) = Request::decode(payload) {
                            let server_hs = server.channel_keypair.new_handshake();
                            let server_eph_pub = server_hs.server_eph_pub();
                            let new_session = server_hs.complete_handshake(&client_eph_pub, &nonce);
                            let new_free_admission = match server.service_admission.as_ref() {
                                Some(runtime) => {
                                    let ip_subject = if runtime.trust_direct_peer_ip {
                                        runtime
                                            .free_ip_subject_key
                                            .as_ref()
                                            .map(|key| key.subject(&runtime.policy.policy().provider_id, peer.ip()))
                                    } else {
                                        None
                                    };
                                    match FreeAdmissionCommitterV1::new(
                                        runtime.policy.policy().provider_id,
                                        new_session.service_authorization_exporter_v1(),
                                        ip_subject,
                                        Arc::clone(&runtime.free_rate_limits),
                                    ) {
                                        Ok(committer) => Some(committer),
                                        Err(error) => {
                                            unsafe_debug_log!(
                                                "[{}] failed to bind Free admission to secure channel: {}",
                                                peer, error
                                            );
                                            let err = Response::Error(
                                                "secure-channel service binding failed".into(),
                                            );
                                            let _ = send_resp(&mut sink, None, err.encode()).await;
                                            break;
                                        }
                                    }
                                }
                                None => None,
                            };
                            let resp = Response::Handshake(
                                pir_runtime_core::protocol::HandshakeResult { server_eph_pub },
                            );
                            // Cleartext send (force `None` so send_resp doesn't seal).
                            if let Err(error) = send_resp(&mut sink, None, resp.encode()).await {
                                unsafe_debug_log!(
                                    "[{}] handshake response send failed: {}",
                                    peer,
                                    error
                                );
                                break;
                            }
                            // Now switch the connection into encrypted mode for
                            // all subsequent client→server and server→client
                            // frames.
                            channel_session = Some(new_session);
                            free_admission = new_free_admission;
                            sink.admission_gate_mut().secure_channel_established();
                        } else {
                            let err = Response::Error(
                                "malformed REQ_HANDSHAKE (expected client_eph_pub:32 + nonce:32)".into(),
                            );
                            let _ = send_resp(&mut sink, channel_session.as_mut(), err.encode()).await;
                        }
                    }
                    // ── DPF batch queries (both roles) ──────────────────
                    REQ_INDEX_BATCH => {
                        if let Ok(Request::IndexBatch(q)) = Request::decode(payload) {
                            let s = Arc::clone(&server);
                            let resp = tokio::task::spawn_blocking(move || {
                                let db = match s.state.get_db(q.db_id) {
                                    Some(db) => db,
                                    None => return Response::Error(format!("unknown db_id {}", q.db_id)),
                                };
                                let t = Instant::now();
                                let n = q.keys.len();
                                let (batch, dpf_sum, fetch_sum) = s.process_index_batch(&q, db);
                                let wall = t.elapsed();
                                unsafe_debug_log!("[index] db={} {} groups {:.2?} | dpf {:.2?} fetch+xor {:.2?}", q.db_id, n, wall, dpf_sum, fetch_sum);
                                Response::IndexBatch(batch)
                            }).await.unwrap();
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                        }
                    }
                    REQ_CHUNK_BATCH => {
                        if let Ok(Request::ChunkBatch(q)) = Request::decode(payload) {
                            let s = Arc::clone(&server);
                            let resp = tokio::task::spawn_blocking(move || {
                                let db = match s.state.get_db(q.db_id) {
                                    Some(db) => db,
                                    None => return Response::Error(format!("unknown db_id {}", q.db_id)),
                                };
                                let t = Instant::now();
                                let n = q.keys.len();
                                let round = q.round_id;
                                let (batch, dpf_sum, fetch_sum) = s.process_chunk_batch(&q, db);
                                let wall = t.elapsed();
                                unsafe_debug_log!("[chunk] db={} r{} {} groups {:.2?} | dpf {:.2?} fetch+xor {:.2?}", q.db_id, round, n, wall, dpf_sum, fetch_sum);
                                Response::ChunkBatch(batch)
                            }).await.unwrap();
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                        }
                    }

                    // (0x31 REQ_MERKLE_SIBLING_BATCH / 0x32 REQ_MERKLE_TREE_TOP
                    //  retired — legacy global N-ary tree Merkle. The per-bucket
                    //  bin Merkle arms below are the active scheme.)

                    // ── Per-bucket bin Merkle sibling batch queries ──────
                    REQ_BUCKET_MERKLE_SIB_BATCH => {
                        if let Ok(Request::BucketMerkleSibBatch(q)) = Request::decode(payload) {
                            let s = Arc::clone(&server);
                            let resp = tokio::task::spawn_blocking(move || {
                                let db = match s.state.get_db(q.db_id) {
                                    Some(db) if db.has_bucket_merkle() => db,
                                    _ => return Response::Error(format!("db {} has no bucket merkle", q.db_id)),
                                };
                                let t = Instant::now();
                                let n = q.keys.len();
                                // round_id encodes: table_type * 100 + level
                                let table_type = q.round_id / 100;
                                let level = (q.round_id % 100) as usize;
                                let sib_tables = if table_type == 0 {
                                    &db.bucket_merkle_index_siblings
                                } else {
                                    &db.bucket_merkle_chunk_siblings
                                };
                                if level >= sib_tables.len() {
                                    return Response::Error(format!("bucket merkle: invalid level {}", level));
                                }
                                let sib = &sib_tables[level];
                                let (batch, dpf_sum, fetch_sum) = s.process_generic_batch(&q, sib);
                                let wall = t.elapsed();
                                unsafe_debug_log!("[bkt-merkle-sib] db={} T{} L{} {} groups {:.2?} | dpf {:.2?} fetch {:.2?}",
                                    q.db_id, table_type, level, n, wall, dpf_sum, fetch_sum);
                                Response::BucketMerkleSibBatch(batch)
                            }).await.unwrap();
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                        }
                    }

                    // ── Per-bucket Merkle tree-tops fetch ────────────────
                    REQ_BUCKET_MERKLE_TREE_TOPS => {
                        // Optional db_id byte: payload[1] if present, else 0.
                        let db_id = if payload.len() > 1 { payload[1] } else { 0 };
                        let db = server.state.get_db(db_id);
                        let tops = db.and_then(|d| d.bucket_merkle_tree_tops.as_ref());
                        if let Some(tops) = tops {
                            let payload_len = 1 + tops.len();
                            let mut msg = Vec::with_capacity(4 + payload_len);
                            msg.extend_from_slice(&(payload_len as u32).to_le_bytes());
                            msg.push(RESP_BUCKET_MERKLE_TREE_TOPS);
                            msg.extend_from_slice(tops);
                            let _ = send_resp(&mut sink, channel_session.as_mut(), msg).await;
                            unsafe_debug_log!("[bkt-merkle-tops] db={} sent {} bytes", db_id, tops.len());
                        } else {
                            let err = Response::Error(format!("db {} has no bucket merkle tree-tops", db_id));
                            let _ = send_resp(&mut sink, channel_session.as_mut(), err.encode()).await;
                        }
                    }

                    // ── HarmonyPIR ────────────────────────────────────────
                    // Both roles respond to ALL HarmonyPIR ops. The
                    // role flag controls only OnionPIR loading at startup
                    // (and `--disable-onion` overrides even that). The
                    // CLIENT decides which server to send hint requests
                    // vs query requests to — the protocol's two-server
                    // non-collusion guarantee comes from picking
                    // independent endpoints, not from server-side dispatch
                    // gating. This decoupling lets operators allocate
                    // workload (hint is ~6× CPU of query per Hetzner
                    // production stats) to whichever endpoint has the
                    // matching hardware capacity, without re-rolling the
                    // role flag and the systemd unit.
                    REQ_HARMONY_GET_INFO => {
                        let _ = send_resp(
                            &mut sink,
                            channel_session.as_mut(),
                            Response::HarmonyInfo(server.server_info()).encode(),
                        ).await;
                    }
                    REQ_HARMONY_HINTS => {
                        if let Ok(Request::HarmonyHints(hint_req)) = Request::decode(payload) {
                            let t_start = Instant::now();
                            let level = hint_req.level;
                            let num = hint_req.group_ids.len();
                            let prp_key: [u8; 16] = hint_req.prp_key;
                            let prp_backend = hint_req.prp_backend;
                            let group_ids = hint_req.group_ids.clone();
                            let db_id = hint_req.db_id;
                            if let Err(msg) = hint_pool::validate_prp_backend(prp_backend) {
                                let resp = Response::Error(msg);
                                let _ = send_resp(
                                    &mut sink,
                                    channel_session.as_mut(),
                                    resp.encode(),
                                )
                                .await;
                                continue;
                            }
                            // Validate backend, db_id, level, and group_ids before
                            // spawning blocking work — all four come off
                            // the wire (S4: an out-of-range group_id or
                            // unknown level previously panicked inside the
                            // rayon pool, aborting the whole server).
                            match server.state.get_db(db_id) {
                                None => {
                                    let resp = Response::Error(format!("unknown db_id {}", db_id));
                                    let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                    continue;
                                }
                                Some(db) => {
                                    if let Err(msg) = validate_harmony_hints_request(db, level, &group_ids) {
                                        let resp = Response::Error(msg);
                                        let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                        continue;
                                    }
                                }
                            }
                            let s = Arc::clone(&server);

                            let (tx, mut rx) = tokio::sync::mpsc::channel::<(u8, u32, u32, u32, Vec<u8>)>(4);
                            tokio::task::spawn_blocking(move || {
                                let db = s.state.get_db(db_id).expect("db_id checked before spawn");
                                group_ids.par_iter().for_each_with(tx, |tx, &bid| {
                                    // Validated above; an Err here would only
                                    // drop this group's record, not the process.
                                    if let Ok(result) = compute_hints_for_group(db, &prp_key, prp_backend, level, bid) {
                                        let _ = tx.blocking_send(result);
                                    }
                                });
                            });

                            // Coalesce per-group records into ~HINT_BATCH_BYTES
                            // WS messages so the browser sees ~30 onmessage
                            // events instead of `num` (~155). Each record
                            // retains its per-record `[4B len][body]`
                            // framing inside the buffer (sealed
                            // individually if the channel is active) so
                            // the client's existing one-record-per-recv()
                            // contract holds — see `send_resp_batch` and
                            // `WsConnection::recv` for the demux.
                            let mut sent = 0;
                            let mut batches = 0usize;
                            let mut pending: Vec<Vec<u8>> = Vec::new();
                            let mut pending_bytes = 0usize;
                            while let Some((group_id, n, t, m, flat_hints)) = rx.recv().await {
                                let hint_len = 1 + 1 + 4 + 4 + 4 + flat_hints.len();
                                let mut record = Vec::with_capacity(4 + hint_len);
                                record.extend_from_slice(&(hint_len as u32).to_le_bytes());
                                record.push(RESP_HARMONY_HINTS);
                                record.push(group_id);
                                record.extend_from_slice(&n.to_le_bytes());
                                record.extend_from_slice(&t.to_le_bytes());
                                record.extend_from_slice(&m.to_le_bytes());
                                record.extend_from_slice(&flat_hints);
                                pending_bytes += record.len();
                                pending.push(record);
                                if pending_bytes >= HINT_BATCH_BYTES {
                                    let batch = std::mem::take(&mut pending);
                                    pending_bytes = 0;
                                    if let Err(e) = send_resp_batch(&mut sink, channel_session.as_mut(), batch).await {
                                        unsafe_debug_log!("[{}] Send error: {}", peer, e);
                                        break;
                                    }
                                    batches += 1;
                                }
                                sent += 1;
                            }
                            if !pending.is_empty() {
                                if let Err(e) = send_resp_batch(&mut sink, channel_session.as_mut(), pending).await {
                                    unsafe_debug_log!("[{}] Final-batch send error: {}", peer, e);
                                } else {
                                    batches += 1;
                                }
                            }
                            unsafe_debug_log!("[harmony-hint] db={} L{} {}/{} groups in {:.2?} ({} WS batches)",
                                db_id, level, sent, num, t_start.elapsed(), batches);
                        }
                    }
                    REQ_HARMONY_HINTS_V2 => {
                        // V2: server generates PRP key, serves pre-computed frames from pool.
                        let t_start = Instant::now();
                        let v2_req = match Request::decode(payload) {
                            Ok(Request::HarmonyHintsV2(h)) => h,
                            Ok(other) => {
                                let resp = Response::Error(format!("unexpected request type for V2 hints: {:?}", other));
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                            Err(e) => {
                                let resp = Response::Error(format!("V2 hint request decode error: {}", e));
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                        };
                        let db_id = v2_req.db_id;
                        if server.state.get_db(db_id).is_none() {
                            let resp = Response::Error(format!("unknown db_id {}", db_id));
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            continue;
                        }

                        let pool = match &server.hint_pool {
                            Some(p) => p,
                            None => {
                                let resp = Response::Error(
                                    "V2 hints not available: start server with --pool-size to enable".into()
                                );
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                        };
                        if let Err(message) = validate_harmony_v2_pool_database(
                            pool.database_id(),
                            db_id,
                        ) {
                            let resp = Response::Error(message);
                            let _ = send_resp(
                                &mut sink,
                                channel_session.as_mut(),
                                resp.encode(),
                            )
                            .await;
                            continue;
                        }

                        let entry = if server.service_admission_enforcement
                            == AdmissionEnforcementV1::Enforced
                        {
                            let Some(reservation) = reserved_harmony_v2_full.take() else {
                                let resp = Response::Error(
                                    "authorized V2Full hint reservation is unavailable".into(),
                                );
                                let _ = send_resp(
                                    &mut sink,
                                    channel_session.as_mut(),
                                    resp.encode(),
                                )
                                .await;
                                break;
                            };
                            if reservation.db_id != db_id {
                                let reserved_db_id = reservation.db_id;
                                drop(reservation);
                                let resp = Response::Error(format!(
                                    "authorized V2Full hint reservation is bound to db {}, not requested db {}",
                                    reserved_db_id, db_id
                                ));
                                let _ = send_resp(
                                    &mut sink,
                                    channel_session.as_mut(),
                                    resp.encode(),
                                )
                                .await;
                                break;
                            }
                            match reservation.reservation.commit_consume() {
                                Ok(entry) => entry,
                                Err(error) => {
                                    eprintln!(
                                        "[hint-pool] Durable consume failed at authorized dispatch"
                                    );
                                    unsafe_debug_log!(
                                        "[hint-pool] authorized dispatch consume detail: {}",
                                        error
                                    );
                                    let resp = Response::Error(
                                        "authorized V2Full hint became unavailable before dispatch"
                                            .into(),
                                    );
                                    let _ = send_resp(
                                        &mut sink,
                                        channel_session.as_mut(),
                                        resp.encode(),
                                    )
                                    .await;
                                    break;
                                }
                            }
                        } else {
                            match pool.try_take() {
                                Some(entry) => entry,
                                None => {
                                    let resp = Response::Error(
                                        "V2 hint pool temporarily empty/unavailable".into(),
                                    );
                                    let _ = send_resp(
                                        &mut sink,
                                        channel_session.as_mut(),
                                        resp.encode(),
                                    )
                                    .await;
                                    continue;
                                }
                            }
                        };

                        // 1. Send key preamble as its own (small) WS Binary
                        //    message — keeps the existing wire shape for the
                        //    preamble + makes the client's first recv()
                        //    return just the preamble. (The client picks the
                        //    PRP key out of it before building HarmonyGroup
                        //    instances.)
                        if let Err(e) = send_resp(&mut sink, channel_session.as_mut(), entry.key_preamble.clone()).await {
                            unsafe_debug_log!("[{}] V2 preamble send error: {}", peer, e);
                            continue;
                        }

                        // 2. Coalesce INDEX + CHUNK frames into
                        //    ~HINT_BATCH_BYTES WS messages. Each record
                        //    retains its per-record `[4B len][body]`
                        //    framing (sealed individually if the channel
                        //    is on) so the client's
                        //    one-record-per-recv() contract holds — see
                        //    `send_resp_batch` + `WsConnection::recv`
                        //    for the demux. A typical pool entry's ~155
                        //    frames now flush as ~10 WS messages
                        //    instead of 155.
                        let mut sent = 0usize;
                        let mut batches = 0usize;
                        let mut pending: Vec<Vec<u8>> = Vec::new();
                        let mut pending_bytes = 0usize;
                        let frame_iter = entry.index_frames.iter().chain(entry.chunk_frames.iter());
                        for frame in frame_iter {
                            pending_bytes += frame.len();
                            pending.push(frame.clone());
                            if pending_bytes >= HINT_BATCH_BYTES {
                                let batch = std::mem::take(&mut pending);
                                pending_bytes = 0;
                                if let Err(e) = send_resp_batch(&mut sink, channel_session.as_mut(), batch).await {
                                    unsafe_debug_log!("[{}] V2 frame batch send error: {}", peer, e);
                                    break;
                                }
                                batches += 1;
                            }
                            sent += 1;
                        }
                        if !pending.is_empty() {
                            if let Err(e) = send_resp_batch(&mut sink, channel_session.as_mut(), pending).await {
                                unsafe_debug_log!("[{}] V2 final-batch send error: {}", peer, e);
                            } else {
                                batches += 1;
                            }
                        }

                        // 3. Terminal sentinel: group_id=0xFF signals
                        //    end-of-stream. Sent as its own (small) message
                        //    so the client's last recv() returns just the
                        //    sentinel, matching the legacy unbatched shape.
                        let terminal_len: u32 = 1 + 1; // variant + group_id
                        let mut terminal = Vec::with_capacity(4 + terminal_len as usize);
                        terminal.extend_from_slice(&terminal_len.to_le_bytes());
                        terminal.push(RESP_HARMONY_HINTS);
                        terminal.push(0xFFu8);
                        let _ = send_resp(&mut sink, channel_session.as_mut(), terminal).await;

                        let elapsed = t_start.elapsed();
                        unsafe_debug_log!(
                            "[harmony-hint-v2] db={} {} groups served from pool ({} WS batches) in {:.2?}",
                            db_id, sent, batches, elapsed,
                        );
                    }
                    REQ_HARMONY_HINTS_V2_HALF => {
                        // Half-stream V2: serve INDEX (side=0) or CHUNK
                        // (side=1) frames from a pool entry shared with
                        // a matching session_token request.
                        let t_start = Instant::now();
                        let v2half_req = match Request::decode(payload) {
                            Ok(Request::HarmonyHintsV2Half(h)) => h,
                            Ok(other) => {
                                let resp = Response::Error(format!(
                                    "unexpected request type for V2 half hints: {:?}",
                                    other
                                ));
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                            Err(e) => {
                                let resp = Response::Error(format!(
                                    "V2 half hint request decode error: {}",
                                    e
                                ));
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                        };
                        let db_id = v2half_req.db_id;
                        if server.state.get_db(db_id).is_none() {
                            let resp =
                                Response::Error(format!("unknown db_id {}", db_id));
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            continue;
                        }

                        let pool = match &server.hint_pool {
                            Some(p) => p,
                            None => {
                                let resp = Response::Error(
                                    "V2 half hints not available: start server with --pool-size to enable"
                                        .into(),
                                );
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                        };
                        if let Err(message) = validate_harmony_v2_pool_database(
                            pool.database_id(),
                            db_id,
                        ) {
                            let resp = Response::Error(message);
                            let _ = send_resp(
                                &mut sink,
                                channel_session.as_mut(),
                                resp.encode(),
                            )
                            .await;
                            continue;
                        }

                        let token = v2half_req.session_token;
                        let side = v2half_req.side;
                        let side_bit: u8 = 1 << side;

                        // Look up (or allocate) the pending entry for
                        // this token. Held under one short critical
                        // section — we drop the lock before serving
                        // frames because send/feed yield the task.
                        let entry_arc: Arc<hint_pool::PoolEntry> = {
                            let mut map = server.v2_half_pending.lock().await;
                            match map.get_mut(&token) {
                                Some(pend) => {
                                    if pend.sides_served & side_bit != 0 {
                                        // Same side already served on
                                        // this token — protocol error.
                                        drop(map);
                                        let resp = Response::Error(format!(
                                            "V2 half: side {} already served for this token",
                                            side
                                        ));
                                        let _ = send_resp(
                                            &mut sink,
                                            channel_session.as_mut(),
                                            resp.encode(),
                                        )
                                        .await;
                                        continue;
                                    }
                                    let arc = Arc::clone(&pend.entry);
                                    pend.sides_served |= side_bit;
                                    // If both sides now served, the
                                    // entry is no longer pending — drop
                                    // it from the map (the Arc keeps
                                    // the data alive in our local
                                    // `entry_arc` for the remainder of
                                    // this serve loop).
                                    if pend.sides_served == 0b11 {
                                        map.remove(&token);
                                    }
                                    arc
                                }
                                None => {
                                    // First half to arrive — allocate a
                                    // fresh pool entry.
                                    let entry = match pool.try_take() {
                                        Some(e) => e,
                                        None => {
                                            drop(map);
                                            let resp = Response::Error(
                                                "V2 hint pool temporarily empty/unavailable"
                                                    .into(),
                                            );
                                            let _ = send_resp(
                                                &mut sink,
                                                channel_session.as_mut(),
                                                resp.encode(),
                                            )
                                            .await;
                                            continue;
                                        }
                                    };
                                    let arc = Arc::new(entry);
                                    map.insert(
                                        token,
                                        V2HalfPending {
                                            entry: Arc::clone(&arc),
                                            sides_served: side_bit,
                                            created_at: Instant::now(),
                                        },
                                    );
                                    arc
                                }
                            }
                        };

                        // 1. Send key preamble (same for both halves
                        //    since they share the entry). Kept as its own
                        //    small WS Binary message so the client's first
                        //    recv() returns just the preamble.
                        if let Err(e) = send_resp(
                            &mut sink,
                            channel_session.as_mut(),
                            entry_arc.key_preamble.clone(),
                        )
                        .await
                        {
                            unsafe_debug_log!(
                                "[{}] V2-half preamble send error: {}",
                                peer, e
                            );
                            continue;
                        }

                        // 2. Coalesce the selected half's frames into
                        //    ~HINT_BATCH_BYTES WS messages. Each record
                        //    retains its per-record `[4B len][body]`
                        //    framing (sealed individually if the
                        //    channel is on) so the client's
                        //    one-record-per-recv() contract holds. A
                        //    typical half (~78 INDEX or ~77 CHUNK
                        //    frames @ ~74 KB) now flushes as ~5 WS
                        //    messages instead of ~78.
                        let frames: &[Vec<u8>] = if side == 0 {
                            &entry_arc.index_frames
                        } else {
                            &entry_arc.chunk_frames
                        };
                        let mut sent = 0usize;
                        let mut batches = 0usize;
                        let mut pending: Vec<Vec<u8>> = Vec::new();
                        let mut pending_bytes = 0usize;
                        for frame in frames {
                            pending_bytes += frame.len();
                            pending.push(frame.clone());
                            if pending_bytes >= HINT_BATCH_BYTES {
                                let batch = std::mem::take(&mut pending);
                                pending_bytes = 0;
                                if let Err(e) = send_resp_batch(
                                    &mut sink,
                                    channel_session.as_mut(),
                                    batch,
                                )
                                .await
                                {
                                    unsafe_debug_log!(
                                        "[{}] V2-half frame batch send error (side={}, group={}): {}",
                                        peer, side, sent, e
                                    );
                                    break;
                                }
                                batches += 1;
                            }
                            sent += 1;
                        }
                        if !pending.is_empty() {
                            if let Err(e) = send_resp_batch(
                                &mut sink,
                                channel_session.as_mut(),
                                pending,
                            )
                            .await
                            {
                                unsafe_debug_log!(
                                    "[{}] V2-half final-batch send error (side={}): {}",
                                    peer, side, e
                                );
                            } else {
                                batches += 1;
                            }
                        }

                        // 3. Send terminal sentinel.
                        let terminal_len: u32 = 1 + 1;
                        let mut terminal = Vec::with_capacity(4 + terminal_len as usize);
                        terminal.extend_from_slice(&terminal_len.to_le_bytes());
                        terminal.push(RESP_HARMONY_HINTS);
                        terminal.push(0xFFu8);
                        let _ = send_resp(
                            &mut sink,
                            channel_session.as_mut(),
                            terminal,
                        )
                        .await;

                        let elapsed = t_start.elapsed();
                        let side_name = if side == 0 { "INDEX" } else { "CHUNK" };
                        unsafe_debug_log!(
                            "[harmony-hint-v2-half] db={} side={} {} groups served from pool ({} WS batches) in {:.2?}",
                            db_id, side_name, sent, batches, elapsed,
                        );
                    }
                    REQ_HARMONY_QUERY => {
                        if let Ok(Request::HarmonyQuery(q)) = Request::decode(payload) {
                            // Validate db_id before dispatching to a worker.
                            if server.state.get_db(q.db_id).is_none() {
                                let resp = Response::Error(format!("unknown db_id {}", q.db_id));
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                            let s = Arc::clone(&server);
                            let resp = tokio::task::spawn_blocking(move || s.handle_harmony_query(&q)).await.unwrap();
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                        }
                    }
                    REQ_HARMONY_BATCH_QUERY => {
                        if let Ok(Request::HarmonyBatchQuery(q)) = Request::decode(payload) {
                            // Validate db_id before dispatching to a worker.
                            if server.state.get_db(q.db_id).is_none() {
                                let resp = Response::Error(format!("unknown db_id {}", q.db_id));
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                            let t = Instant::now();
                            let n = q.items.len();
                            let level = q.level;
                            let db_id = q.db_id;
                            let s = Arc::clone(&server);
                            let resp = tokio::task::spawn_blocking(move || s.handle_harmony_batch_query(&q)).await.unwrap();
                            unsafe_debug_log!("[harmony-batch] db={} L{} {} groups in {:.2?}", db_id, level, n, t.elapsed());
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                        }
                    }
                    REQ_ORAM_LOOKUP => {
                        if !request_was_encrypted {
                            let resp = Response::Error(
                                "REQ_ORAM_LOOKUP must be sent inside the encrypted channel".into(),
                            );
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            continue;
                        }
                        match Request::decode(payload) {
                            Ok(Request::OramLookup(q)) => {
                                let s = Arc::clone(&server);
                                let resp = tokio::task::spawn_blocking(move || {
                                    s.handle_oram_lookup(&q)
                                })
                                .await
                                .unwrap();
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            }
                            Ok(other) => {
                                let resp = Response::Error(format!(
                                    "unexpected request type for ORAM lookup: {:?}",
                                    other
                                ));
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            }
                            Err(e) => {
                                let resp =
                                    Response::Error(format!("ORAM lookup decode error: {}", e));
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            }
                        }
                    }

                    // ── OnionPIR (primary only, if available) ────────────
                    REQ_REGISTER_KEYS if server.has_any_onionpir() => {
                        match RegisterKeysMsg::decode(body) {
                            Ok(keys_msg) => {
                                let db_id = keys_msg.db_id;
                                let tx = match server.onionpir_tx_for(db_id) {
                                    Some(t) => t.clone(),
                                    None => {
                                        let resp = Response::Error(format!("OnionPIR not available for db_id={}", db_id));
                                        let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                        continue;
                                    }
                                };
                                let (reply_tx, reply_rx) = oneshot::channel();
                                let _ = tx.send(PirCommand::RegisterKeys {
                                    client_id,
                                    galois_keys: keys_msg.galois_keys,
                                    gsw_keys: keys_msg.gsw_keys,
                                    reply: reply_tx,
                                }).await;
                                let _ = reply_rx.await;
                                let mut resp = Vec::with_capacity(5);
                                resp.extend_from_slice(&1u32.to_le_bytes());
                                resp.push(RESP_KEYS_ACK);
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp).await;
                            }
                            Err(error) => {
                                let response = Response::Error(format!(
                                    "OnionPIR key registration decode error: {error}"
                                ));
                                let _ = send_resp(
                                    &mut sink,
                                    channel_session.as_mut(),
                                    response.encode(),
                                )
                                .await;
                            }
                        }
                    }
                    REQ_ONIONPIR_INDEX_QUERY if server.has_any_onionpir() => {
                        if let Ok(batch) = OnionPirBatchQuery::decode(body) {
                            let tx = match server.onionpir_tx_for(batch.db_id) {
                                Some(t) => t.clone(),
                                None => {
                                    let resp = Response::Error(format!("OnionPIR not available for db_id={}", batch.db_id));
                                    let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                    continue;
                                }
                            };
                            let (reply_tx, reply_rx) = oneshot::channel();
                            let _ = tx.send(PirCommand::AnswerBatch {
                                client_id, level: 0,
                                round_id: batch.round_id,
                                queries: batch.queries, reply: reply_tx,
                            }).await;
                            let results = reply_rx.await.unwrap();
                            let result_msg = OnionPirBatchResult { round_id: batch.round_id, results };
                            let _ = send_resp_chunked(&mut sink, channel_session.as_mut(), result_msg.encode(RESP_ONIONPIR_INDEX_RESULT), client_supports_chunks).await;
                        }
                    }
                    REQ_ONIONPIR_CHUNK_QUERY if server.has_any_onionpir() => {
                        if let Ok(batch) = OnionPirBatchQuery::decode(body) {
                            let tx = match server.onionpir_tx_for(batch.db_id) {
                                Some(t) => t.clone(),
                                None => {
                                    let resp = Response::Error(format!("OnionPIR not available for db_id={}", batch.db_id));
                                    let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                    continue;
                                }
                            };
                            let (reply_tx, reply_rx) = oneshot::channel();
                            let _ = tx.send(PirCommand::AnswerBatch {
                                client_id, level: 1,
                                round_id: batch.round_id,
                                queries: batch.queries, reply: reply_tx,
                            }).await;
                            let results = reply_rx.await.unwrap();
                            let result_msg = OnionPirBatchResult { round_id: batch.round_id, results };
                            let _ = send_resp_chunked(&mut sink, channel_session.as_mut(), result_msg.encode(RESP_ONIONPIR_CHUNK_RESULT), client_supports_chunks).await;
                        }
                    }
                    REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP if server.has_any_onionpir_merkle() => {
                        // Optional db_id byte: payload[1] if present, else 0.
                        let db_id = if payload.len() > 1 { payload[1] } else { 0 };
                        let om = match server.onionpir_merkle_for(db_id) {
                            Some(om) => om,
                            None => {
                                let resp = Response::Error(format!("OnionPIR Merkle not available for db_id={}", db_id));
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                        };
                        // Per-group redesign: one consolidated 155-tree
                        // tree-top blob, served whole on either request.
                        let top = &om.tree_tops;
                        let payload_len = 1 + top.len();
                        let mut msg = Vec::with_capacity(4 + payload_len);
                        msg.extend_from_slice(&(payload_len as u32).to_le_bytes());
                        msg.push(RESP_ONIONPIR_MERKLE_INDEX_TREE_TOP);
                        msg.extend_from_slice(top);
                        let _ = send_resp_chunked(&mut sink, channel_session.as_mut(), msg, client_supports_chunks).await;
                        unsafe_debug_log!("[onion-merkle-tree-tops] db={} (index req) sent {} bytes", db_id, top.len());
                    }
                    REQ_ONIONPIR_MERKLE_DATA_TREE_TOP if server.has_any_onionpir_merkle() => {
                        // Optional db_id byte: payload[1] if present, else 0.
                        let db_id = if payload.len() > 1 { payload[1] } else { 0 };
                        let om = match server.onionpir_merkle_for(db_id) {
                            Some(om) => om,
                            None => {
                                let resp = Response::Error(format!("OnionPIR Merkle not available for db_id={}", db_id));
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                        };
                        // Per-group redesign: one consolidated 155-tree
                        // tree-top blob, served whole on either request.
                        let top = &om.tree_tops;
                        let payload_len = 1 + top.len();
                        let mut msg = Vec::with_capacity(4 + payload_len);
                        msg.extend_from_slice(&(payload_len as u32).to_le_bytes());
                        msg.push(RESP_ONIONPIR_MERKLE_DATA_TREE_TOP);
                        msg.extend_from_slice(top);
                        let _ = send_resp_chunked(&mut sink, channel_session.as_mut(), msg, client_supports_chunks).await;
                        unsafe_debug_log!("[onion-merkle-tree-tops] db={} (data req) sent {} bytes", db_id, top.len());
                    }
                    REQ_ONIONPIR_MERKLE_INDEX_SIBLING if server.has_any_onionpir() => {
                        // round_id encoding: sibling_level * 100 + pbc_round_index
                        // Per-DB: the db_id trailer in the batch message selects the
                        // OnionPIR worker and its per-bin Merkle sibling levels.
                        if let Ok(batch) = OnionPirBatchQuery::decode(body) {
                            if server.onionpir_merkle_for(batch.db_id).is_none() {
                                let resp = Response::Error(format!(
                                    "OnionPIR Merkle not available for db_id={}",
                                    batch.db_id
                                ));
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                            let tx = match server.onionpir_tx_for(batch.db_id) {
                                Some(t) => t.clone(),
                                None => continue,
                            };
                            let (reply_tx, reply_rx) = oneshot::channel();
                            let _ = tx.send(PirCommand::AnswerBatch {
                                client_id,
                                level: 10, // worker: INDEX per-group siblings
                                round_id: batch.round_id,
                                queries: batch.queries, reply: reply_tx,
                            }).await;
                            let results = reply_rx.await.unwrap();
                            let result_msg = OnionPirBatchResult { round_id: batch.round_id, results };
                            let _ = send_resp_chunked(&mut sink, channel_session.as_mut(), result_msg.encode(RESP_ONIONPIR_MERKLE_INDEX_SIBLING), client_supports_chunks).await;
                        }
                    }
                    REQ_ONIONPIR_MERKLE_DATA_SIBLING if server.has_any_onionpir() && server.has_any_onionpir_merkle() => {
                        // round_id encoding: sibling_level * 100 + pbc_round_index
                        // Data siblings start after index siblings in the worker's server array.
                        if let Ok(batch) = OnionPirBatchQuery::decode(body) {
                            if server.onionpir_merkle_for(batch.db_id).is_none() {
                                let resp = Response::Error(format!(
                                    "OnionPIR Merkle not available for db_id={}",
                                    batch.db_id
                                ));
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                            let tx = match server.onionpir_tx_for(batch.db_id) {
                                Some(t) => t.clone(),
                                None => continue,
                            };
                            let (reply_tx, reply_rx) = oneshot::channel();
                            let _ = tx.send(PirCommand::AnswerBatch {
                                client_id,
                                level: 11, // worker: DATA per-group siblings
                                round_id: batch.round_id,
                                queries: batch.queries, reply: reply_tx,
                            }).await;
                            let results = reply_rx.await.unwrap();
                            let result_msg = OnionPirBatchResult { round_id: batch.round_id, results };
                            let _ = send_resp_chunked(&mut sink, channel_session.as_mut(), result_msg.encode(RESP_ONIONPIR_MERKLE_DATA_SIBLING), client_supports_chunks).await;
                        }
                    }

                    // ── Unsupported ──────────────────────────────────────
                    _ => {
                        let resp = Response::Error(format!("unsupported request 0x{:02x} for {} role", variant, role_name));
                        let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                    }
                }
            }

            // A leftover post-credential V2Full reservation never reached its
            // first main dispatch. Dropping it releases the inode lock and
            // returns the unexposed durable entry without filesystem writes.
            drop(reserved_harmony_v2_full.take());

            // ARC cleanup: remove the seen-tag set for this connection's
            // presentation context so memory doesn't grow unboundedly.
            if let (Some(ctx), Some(verifier)) = (arc_pres_ctx, &server.arc_verifier) {
                verifier.lock().unwrap().remove_context(&ctx);
            }

            unsafe_debug_log!("[{}] Disconnected (id={})", peer, client_id);
        });
    }
}

#[cfg(test)]
mod service_admission_dispatch_tests {
    use super::*;

    #[test]
    fn real_k_padded_dpf_frames_charge_one_index_job_not_padding_groups() {
        use libdpf::Dpf;

        let dpf = Dpf::with_default_key();
        let (key0, key1) = dpf.gen(0, 7);
        let pair = vec![key0.to_bytes(), key1.to_bytes()];

        let index_wire = Request::IndexBatch(BatchQuery {
            level: 0,
            round_id: 0,
            db_id: 0,
            keys: vec![pair.clone(); INDEX_PARAMS.k],
        })
        .encode();
        let index = dpf_backend_frame_for_service_gate(&index_wire[4..]).unwrap();
        assert_eq!(index.kind, BackendFrameKindV1::DpfIndexBatch);
        assert_eq!(index.logical_inputs, 1);
        assert_eq!(index.work_units, (INDEX_PARAMS.k * 2) as u64);

        let chunk_wire = Request::ChunkBatch(BatchQuery {
            level: 1,
            round_id: 0,
            db_id: 0,
            keys: vec![pair; CHUNK_PARAMS.k],
        })
        .encode();
        let chunk = dpf_backend_frame_for_service_gate(&chunk_wire[4..]).unwrap();
        assert_eq!(chunk.kind, BackendFrameKindV1::DpfChunkBatch);
        assert_eq!(chunk.logical_inputs, 0);
        assert_eq!(chunk.work_units, (CHUNK_PARAMS.k * 2) as u64);
    }

    #[derive(Default)]
    struct RecordingSink {
        messages: Vec<Message>,
    }

    impl futures_util::Sink<Message> for RecordingSink {
        type Error = tokio_tungstenite::tungstenite::Error;

        fn poll_ready(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn start_send(self: std::pin::Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
            self.get_mut().messages.push(item);
            Ok(())
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// Adversarial transport: accepts a frame into its local queue, then
    /// never completes or wakes the flush. The pre-auth timer must be the
    /// future that wakes and terminates `SinkExt::send`.
    #[derive(Default)]
    struct PermanentlyPendingFlushSink {
        messages: Vec<Message>,
        flush_polls: usize,
    }

    impl futures_util::Sink<Message> for PermanentlyPendingFlushSink {
        type Error = tokio_tungstenite::tungstenite::Error;

        fn poll_ready(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn start_send(self: std::pin::Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
            self.get_mut().messages.push(item);
            Ok(())
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            self.get_mut().flush_polls += 1;
            std::task::Poll::Pending
        }

        fn poll_close(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Pending
        }
    }

    /// Adversarial transport: never becomes ready and never wakes by itself.
    /// The wrapper's fixed deadline must provide the wakeup, and `start_send`
    /// must remain unreachable.
    #[derive(Default)]
    struct PermanentlyPendingReadySink {
        ready_polls: usize,
        start_send_calls: usize,
    }

    impl futures_util::Sink<Message> for PermanentlyPendingReadySink {
        type Error = tokio_tungstenite::tungstenite::Error;

        fn poll_ready(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            self.get_mut().ready_polls += 1;
            std::task::Poll::Pending
        }

        fn start_send(self: std::pin::Pin<&mut Self>, _item: Message) -> Result<(), Self::Error> {
            self.get_mut().start_send_calls += 1;
            Ok(())
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Pending
        }

        fn poll_close(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Pending
        }
    }

    /// Adversarial transport: accepts a queued frame but fails its first flush.
    /// A grant must remain unusable after this non-timeout write failure.
    #[derive(Default)]
    struct FailingFlushSink {
        messages: Vec<Message>,
        flush_polls: usize,
    }

    impl futures_util::Sink<Message> for FailingFlushSink {
        type Error = tokio_tungstenite::tungstenite::Error;

        fn poll_ready(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn start_send(self: std::pin::Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
            self.get_mut().messages.push(item);
            Ok(())
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            self.get_mut().flush_polls += 1;
            std::task::Poll::Ready(Err(tokio_tungstenite::tungstenite::Error::Io(
                std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "injected flush failure",
                ),
            )))
        }

        fn poll_close(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    struct TestResponseBudget {
        limit: u64,
        used: u64,
        terminal: bool,
    }

    impl ServiceResponseBudgetV1 for TestResponseBudget {
        fn reserve_service_response_bytes_v1(&mut self, bytes: u64) -> Result<(), String> {
            if self.terminal {
                return Err("terminal response budget".into());
            }
            let next = self
                .used
                .checked_add(bytes)
                .ok_or_else(|| "test response counter overflow".to_owned())?;
            if next > self.limit {
                self.terminal = true;
                return Err("test response budget exceeded".into());
            }
            self.used = next;
            Ok(())
        }
    }

    fn test_sink(limit: u64) -> ServiceAdmissionSink<RecordingSink, TestResponseBudget> {
        ServiceAdmissionSink::with_test_budget(
            RecordingSink::default(),
            TestResponseBudget {
                limit,
                used: 0,
                terminal: false,
            },
        )
    }

    fn permanently_pending_test_sink(
        limit: u64,
    ) -> ServiceAdmissionSink<PermanentlyPendingFlushSink, TestResponseBudget> {
        ServiceAdmissionSink::with_test_budget(
            PermanentlyPendingFlushSink::default(),
            TestResponseBudget {
                limit,
                used: 0,
                terminal: false,
            },
        )
    }

    fn permanently_pending_ready_test_sink(
        limit: u64,
    ) -> ServiceAdmissionSink<PermanentlyPendingReadySink, TestResponseBudget> {
        ServiceAdmissionSink::with_test_budget(
            PermanentlyPendingReadySink::default(),
            TestResponseBudget {
                limit,
                used: 0,
                terminal: false,
            },
        )
    }

    fn failing_flush_test_sink(
        limit: u64,
    ) -> ServiceAdmissionSink<FailingFlushSink, TestResponseBudget> {
        ServiceAdmissionSink::with_test_budget(
            FailingFlushSink::default(),
            TestResponseBudget {
                limit,
                used: 0,
                terminal: false,
            },
        )
    }

    async fn assert_future_is_pending_once<F>(future: std::pin::Pin<&mut F>)
    where
        F: std::future::Future + ?Sized,
    {
        let mut future = future;
        std::future::poll_fn(|cx| match std::future::Future::poll(future.as_mut(), cx) {
            std::task::Poll::Pending => std::task::Poll::Ready(()),
            std::task::Poll::Ready(_) => {
                panic!("permanently blocked sink unexpectedly completed before deadline")
            }
        })
        .await;
    }

    #[test]
    fn every_known_expensive_opcode_requires_a_typed_grant() {
        for opcode in [
            REQ_INDEX_BATCH,
            REQ_CHUNK_BATCH,
            REQ_BUCKET_MERKLE_SIB_BATCH,
            REQ_HARMONY_HINTS,
            REQ_HARMONY_HINTS_V2,
            REQ_HARMONY_HINTS_V2_HALF,
            REQ_HARMONY_QUERY,
            REQ_HARMONY_BATCH_QUERY,
            REQ_ORAM_LOOKUP,
            REQ_REGISTER_KEYS,
            REQ_ONIONPIR_INDEX_QUERY,
            REQ_ONIONPIR_CHUNK_QUERY,
            REQ_ONIONPIR_MERKLE_INDEX_SIBLING,
            REQ_ONIONPIR_MERKLE_DATA_SIBLING,
        ] {
            assert!(
                !service_gate_allows_ungranted_opcode(opcode),
                "expensive opcode 0x{opcode:02x} bypasses the V1 grant"
            );
            assert!(
                service_gate_is_backend_opcode_v1(opcode),
                "expensive opcode 0x{opcode:02x} is parsed before the plaintext transport gate"
            );
        }
    }

    #[test]
    fn legacy_credentials_cannot_unlock_v1_and_preflight_remains_available() {
        assert!(!service_gate_allows_ungranted_opcode(
            REQ_CREDENTIAL_PRESENT
        ));
        assert!(!service_gate_allows_ungranted_opcode(REQ_CASHU_BAT_PRESENT));
        for opcode in [
            REQ_SERVICE_POLICY_V1,
            REQ_AUTH_BEGIN_V1,
            REQ_BUCKET_MERKLE_TREE_TOPS,
            REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP,
            REQ_ONIONPIR_MERKLE_DATA_TREE_TOP,
        ] {
            assert!(service_gate_allows_ungranted_opcode(opcode));
        }
    }

    #[tokio::test]
    async fn metered_response_counts_actual_encoded_bytes_and_blocks_overflow() {
        let mut sink = test_sink(8);
        sink.begin_request();
        sink.meter_response_for_test();

        send_resp(&mut sink, None, vec![0; 8]).await.unwrap();
        assert_eq!(sink.response_budget.used, 8);
        assert_eq!(sink.inner.messages.len(), 1);

        assert!(send_resp(&mut sink, None, vec![0]).await.is_err());
        assert!(sink.response_budget.terminal);
        assert_eq!(
            sink.inner.messages.len(),
            1,
            "the over-limit result must not reach the underlying socket"
        );
    }

    #[tokio::test]
    async fn chunked_response_reserves_the_whole_encoded_group_before_first_send() {
        let first_chunk_wire_bytes = CHUNK_SIZE + 4 + CHUNK_HDR;
        let mut sink = test_sink(u64::try_from(first_chunk_wire_bytes).unwrap());
        sink.begin_request();
        sink.meter_response_for_test();

        let response = vec![0; CHUNK_SIZE + 1];
        assert!(send_resp_chunked(&mut sink, None, response, true)
            .await
            .is_err());
        assert!(sink.response_budget.terminal);
        assert!(
            sink.inner.messages.is_empty(),
            "an oversized multi-chunk result must fail atomically"
        );
    }

    #[tokio::test]
    async fn preflight_egress_has_independent_message_and_byte_limits() {
        let mut sink = test_sink(0);
        sink.set_test_pre_auth_egress_limits(2, 64);

        sink.begin_request();
        sink.meter_pre_auth_response_for_opcode(REQ_BUCKET_MERKLE_TREE_TOPS);
        send_resp(&mut sink, None, vec![0; 32]).await.unwrap();
        assert_eq!(sink.response_budget.used, 0);
        assert_eq!(sink.pre_auth_egress_budget.messages_used, 1);
        assert_eq!(sink.pre_auth_egress_budget.bytes_used, 32);

        sink.begin_request();
        sink.meter_pre_auth_response_for_opcode(REQ_GET_DB_PROOF_V2);
        send_resp(&mut sink, None, vec![0; 32]).await.unwrap();
        assert_eq!(sink.pre_auth_egress_budget.messages_used, 2);
        assert_eq!(sink.pre_auth_egress_budget.bytes_used, 64);

        sink.begin_request();
        sink.meter_pre_auth_response_for_opcode(REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP);
        assert!(send_resp(&mut sink, None, vec![0]).await.is_err());
        assert!(sink.pre_auth_egress_is_terminal());
        assert_eq!(sink.inner.messages.len(), 2);

        // Terminal is connection-wide: changing to an unmetered opcode cannot
        // recover or send an authorization response on this connection.
        sink.begin_request();
        sink.meter_pre_auth_response_for_opcode(REQ_AUTH_BEGIN_V1);
        assert!(send_resp(&mut sink, None, vec![0]).await.is_err());
        assert_eq!(sink.inner.messages.len(), 2);
    }

    #[tokio::test]
    async fn preflight_chunk_group_reserves_messages_and_bytes_before_first_send() {
        let mut sink = test_sink(0);
        sink.set_test_pre_auth_egress_limits(1, u64::MAX);
        sink.begin_request();
        sink.meter_pre_auth_response_for_opcode(REQ_ONIONPIR_MERKLE_DATA_TREE_TOP);

        assert!(
            send_resp_chunked(&mut sink, None, vec![0; CHUNK_SIZE + 1], true)
                .await
                .is_err()
        );
        assert!(sink.pre_auth_egress_is_terminal());
        assert!(sink.inner.messages.is_empty());
    }

    #[tokio::test]
    async fn absolute_deadline_interrupts_permanently_pending_preflight_group_flush() {
        let mut sink = permanently_pending_test_sink(0);
        sink.set_test_pre_auth_egress_limits(4, u64::MAX);
        let (deadline_tx, deadline_rx) = tokio::sync::oneshot::channel();
        sink.set_test_pre_auth_deadline(async move {
            let _ = deadline_rx.await;
        });
        sink.begin_request();
        sink.meter_pre_auth_response_for_opcode(REQ_ONIONPIR_MERKLE_DATA_TREE_TOP);

        let mut write = Box::pin(send_resp_chunked(
            &mut sink,
            None,
            vec![0; CHUNK_SIZE + 1],
            true,
        ));
        assert_future_is_pending_once(write.as_mut()).await;
        deadline_tx.send(()).unwrap();
        let error = write.await.unwrap_err();
        match error {
            tokio_tungstenite::tungstenite::Error::Io(error) => {
                assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
            }
            other => panic!("unexpected pre-auth deadline error: {other}"),
        }

        assert!(sink.pre_auth_deadline_has_expired());
        assert!(!sink.auth_result_delivered());
        assert_eq!(sink.inner.messages.len(), 1);
        assert!(sink.inner.flush_polls >= 1);
    }

    #[tokio::test]
    async fn committed_grant_result_cannot_escape_deadline_via_pending_flush() {
        let mut sink = permanently_pending_test_sink(u64::MAX);
        let (deadline_tx, deadline_rx) = tokio::sync::oneshot::channel();
        sink.set_test_pre_auth_deadline(async move {
            let _ = deadline_rx.await;
        });
        sink.begin_request();
        sink.meter_pre_auth_response_for_opcode(REQ_AUTH_BEGIN_V1);
        // Model the value returned by a completed, non-cancellable durable
        // commit. Delivery, rather than gate state, controls the transition.
        let durably_committed_result =
            pir_service_protocol::AuthResultV1::Granted(pir_service_protocol::AuthGrantedV1 {
                scope_id: [7; 32],
                enforced_profile: 1,
                expires_in_ms: 10_000,
                harmony_attach: None,
            });

        let mut delivery = Box::pin(deliver_auth_result_response_v1(
            &mut sink,
            None,
            &durably_committed_result,
        ));
        assert_future_is_pending_once(delivery.as_mut()).await;
        deadline_tx.send(()).unwrap();
        let error = delivery.await.unwrap_err();
        match error {
            tokio_tungstenite::tungstenite::Error::Io(error) => {
                assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
            }
            other => panic!("unexpected auth-result deadline error: {other}"),
        }

        assert!(sink.pre_auth_deadline_has_expired());
        assert!(!sink.auth_result_delivered());
        assert_eq!(sink.inner.messages.len(), 1);
        assert!(sink.inner.flush_polls >= 1);
    }

    #[tokio::test]
    async fn absolute_deadline_interrupts_permanently_pending_poll_ready() {
        let mut sink = permanently_pending_ready_test_sink(u64::MAX);
        let (deadline_tx, deadline_rx) = tokio::sync::oneshot::channel();
        sink.set_test_pre_auth_deadline(async move {
            let _ = deadline_rx.await;
        });
        let result =
            pir_service_protocol::AuthResultV1::Granted(pir_service_protocol::AuthGrantedV1 {
                scope_id: [9; 32],
                enforced_profile: 1,
                expires_in_ms: 10_000,
                harmony_attach: None,
            });

        let mut delivery = Box::pin(deliver_auth_result_response_v1(&mut sink, None, &result));
        assert_future_is_pending_once(delivery.as_mut()).await;
        deadline_tx.send(()).unwrap();
        let error = delivery.await.unwrap_err();
        match error {
            tokio_tungstenite::tungstenite::Error::Io(error) => {
                assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
            }
            other => panic!("unexpected poll-ready deadline error: {other}"),
        }

        assert!(sink.pre_auth_deadline_has_expired());
        assert!(!sink.auth_result_delivered());
        assert!(sink.require_auth_result_delivered_for_backend().is_err());
        assert!(sink.inner.ready_polls >= 1);
        assert_eq!(sink.inner.start_send_calls, 0);
    }

    #[tokio::test]
    async fn harmony_attached_marks_delivery_only_after_successful_flush() {
        let mut attached_sink = test_sink(u64::MAX);
        let (attached_deadline_tx, attached_deadline_rx) = tokio::sync::oneshot::channel();
        attached_sink.set_test_pre_auth_deadline(async move {
            let _ = attached_deadline_rx.await;
        });
        let attached = HarmonyAttachResultV1::Attached {
            operation_id: [10; 32],
        };

        deliver_harmony_attach_result_response_v1(&mut attached_sink, None, &attached)
            .await
            .unwrap();
        assert!(attached_sink.auth_result_delivered());
        assert!(attached_sink
            .require_auth_result_delivered_for_backend()
            .is_ok());
        assert_eq!(attached_sink.inner.messages.len(), 1);
        assert!(
            attached_deadline_tx.send(()).is_err(),
            "successful Attached flush did not disarm its deadline"
        );

        let mut rejected_sink = test_sink(u64::MAX);
        let (rejected_deadline_tx, rejected_deadline_rx) = tokio::sync::oneshot::channel();
        rejected_sink.set_test_pre_auth_deadline(async move {
            let _ = rejected_deadline_rx.await;
        });
        let rejected = HarmonyAttachResultV1::Rejected {
            code: HarmonyAttachRejectCodeV1::NoWaitingOperation,
        };

        deliver_harmony_attach_result_response_v1(&mut rejected_sink, None, &rejected)
            .await
            .unwrap();
        assert!(!rejected_sink.auth_result_delivered());
        assert!(rejected_sink
            .require_auth_result_delivered_for_backend()
            .is_err());
        assert_eq!(rejected_sink.inner.messages.len(), 1);
        assert!(
            rejected_deadline_tx.send(()).is_ok(),
            "a rejected attach must leave its deadline armed"
        );
    }

    #[tokio::test]
    async fn harmony_attached_cannot_escape_deadline_via_pending_flush() {
        let mut sink = permanently_pending_test_sink(u64::MAX);
        let (deadline_tx, deadline_rx) = tokio::sync::oneshot::channel();
        sink.set_test_pre_auth_deadline(async move {
            let _ = deadline_rx.await;
        });
        let attached = HarmonyAttachResultV1::Attached {
            operation_id: [11; 32],
        };

        let mut delivery = Box::pin(deliver_harmony_attach_result_response_v1(
            &mut sink, None, &attached,
        ));
        assert_future_is_pending_once(delivery.as_mut()).await;
        deadline_tx.send(()).unwrap();
        let error = delivery.await.unwrap_err();
        match error {
            tokio_tungstenite::tungstenite::Error::Io(error) => {
                assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
            }
            other => panic!("unexpected Harmony attach deadline error: {other}"),
        }

        assert!(sink.pre_auth_deadline_has_expired());
        assert!(!sink.auth_result_delivered());
        assert!(sink.require_auth_result_delivered_for_backend().is_err());
        assert_eq!(sink.inner.messages.len(), 1);
        assert!(sink.inner.flush_polls >= 1);
    }

    #[tokio::test]
    async fn harmony_attach_write_or_encoding_error_keeps_backend_guard_closed() {
        let mut flush_sink = failing_flush_test_sink(u64::MAX);
        let attached = HarmonyAttachResultV1::Attached {
            operation_id: [12; 32],
        };
        let error = deliver_harmony_attach_result_response_v1(&mut flush_sink, None, &attached)
            .await
            .unwrap_err();
        match error {
            tokio_tungstenite::tungstenite::Error::Io(error) => {
                assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
            }
            other => panic!("unexpected Harmony attach flush error: {other}"),
        }
        assert!(!flush_sink.auth_result_delivered());
        assert!(flush_sink
            .require_auth_result_delivered_for_backend()
            .is_err());
        assert_eq!(flush_sink.inner.messages.len(), 1);
        assert_eq!(flush_sink.inner.flush_polls, 1);

        let mut encode_sink = test_sink(u64::MAX);
        let invalid = HarmonyAttachResultV1::Attached {
            operation_id: [0; 32],
        };
        assert!(
            deliver_harmony_attach_result_response_v1(&mut encode_sink, None, &invalid)
                .await
                .is_err()
        );
        assert!(!encode_sink.auth_result_delivered());
        assert!(encode_sink
            .require_auth_result_delivered_for_backend()
            .is_err());
        assert!(encode_sink.inner.messages.is_empty());
    }

    #[tokio::test]
    async fn invalid_granted_result_encoding_fails_closed_without_diagnostic_send() {
        let mut sink = test_sink(u64::MAX);
        let invalid =
            pir_service_protocol::AuthResultV1::Granted(pir_service_protocol::AuthGrantedV1 {
                scope_id: [13; 32],
                enforced_profile: 1,
                expires_in_ms: 0,
                harmony_attach: None,
            });

        assert!(deliver_auth_result_response_v1(&mut sink, None, &invalid)
            .await
            .is_err());
        assert!(!sink.auth_result_delivered());
        assert!(sink.require_auth_result_delivered_for_backend().is_err());
        assert!(sink.inner.messages.is_empty());
    }

    #[tokio::test]
    async fn start_send_rechecks_an_expired_absolute_deadline() {
        let mut sink = ServiceAdmissionSink::new(
            RecordingSink::default(),
            AdmissionEnforcementV1::Enforced,
            Instant::now(),
            Duration::ZERO,
        );

        let error =
            futures_util::Sink::start_send(std::pin::Pin::new(&mut sink), Message::Binary(vec![1]))
                .unwrap_err();
        match error {
            tokio_tungstenite::tungstenite::Error::Io(error) => {
                assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
            }
            other => panic!("unexpected start-send deadline error: {other}"),
        }
        assert!(sink.pre_auth_deadline_has_expired());
        assert!(!sink.auth_result_delivered());
        assert!(sink.require_auth_result_delivered_for_backend().is_err());
        assert!(sink.inner.messages.is_empty());
    }

    #[tokio::test]
    async fn granted_result_switches_to_idle_only_after_successful_flush() {
        let mut sink = test_sink(u64::MAX);
        let (deadline_tx, deadline_rx) = tokio::sync::oneshot::channel();
        sink.set_test_pre_auth_deadline(async move {
            let _ = deadline_rx.await;
        });
        let result =
            pir_service_protocol::AuthResultV1::Granted(pir_service_protocol::AuthGrantedV1 {
                scope_id: [8; 32],
                enforced_profile: 1,
                expires_in_ms: 10_000,
                harmony_attach: None,
            });

        deliver_auth_result_response_v1(&mut sink, None, &result)
            .await
            .unwrap();
        assert!(sink.auth_result_delivered());
        assert_eq!(sink.inner.messages.len(), 1);
        assert!(
            deadline_tx.send(()).is_err(),
            "deadline future was not disarmed"
        );
        send_resp(&mut sink, None, vec![0; 1]).await.unwrap();
        assert_eq!(sink.inner.messages.len(), 2);
    }

    #[test]
    fn exact_verification_and_tree_top_opcodes_are_bounded_but_auth_is_not() {
        for opcode in [
            REQ_ATTEST,
            REQ_ANNOUNCE,
            REQ_HANDSHAKE,
            REQ_GET_DB_PROOF,
            REQ_GET_DB_PROOF_V2,
            REQ_SERVICE_POLICY_V1,
            REQ_BUCKET_MERKLE_TREE_TOPS,
            REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP,
            REQ_ONIONPIR_MERKLE_DATA_TREE_TOP,
        ] {
            assert!(is_pre_auth_egress_opcode_v1(opcode));
        }
        assert!(!is_pre_auth_egress_opcode_v1(REQ_AUTH_BEGIN_V1));
        assert!(!is_pre_auth_egress_opcode_v1(REQ_HARMONY_ATTACH_V1));
    }

    #[test]
    fn default_runtime_logging_forbidden_field_scan() {
        fn direct_log_calls<'a>(source: &'a str, needle: &str) -> Vec<&'a str> {
            let mut calls = Vec::new();
            let mut offset = 0;
            while let Some(relative) = source[offset..].find(needle) {
                let start = offset + relative;
                if needle == "println!(" && start != 0 && source.as_bytes()[start - 1] == b'e' {
                    offset = start + needle.len();
                    continue;
                }
                let tail = &source[start..];
                let end = tail.find(");").map(|end| end + 2).unwrap_or(tail.len());
                calls.push(&tail[..end]);
                offset = start + end;
            }
            calls
        }

        assert!(!UNSAFE_DEBUG_QUERY_LOGGING.load(Ordering::Relaxed));
        let source = include_str!("unified_server.rs");
        let runtime = source
            .split_once("let client_counter =")
            .expect("runtime logging scan start marker")
            .1
            .split_once("#[cfg(test)]\nmod service_admission_dispatch_tests")
            .expect("runtime logging scan end marker")
            .0;
        let compact: String = runtime
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();

        // Detailed calls must use `unsafe_debug_log!`; direct default log
        // macros in the live connection loop may contain only aggregate/admin
        // operational events.
        for forbidden in [
            "println!(\"[{}]",
            "eprintln!(\"[{}]",
            "println!(\"[index]",
            "println!(\"[chunk]",
            "println!(\"[harmony-",
            "println!(\"[bkt-merkle",
            "println!(\"[onion-merkle",
            "eprintln!(\"[OnionPIR:",
        ] {
            assert!(
                !compact.contains(forbidden),
                "default runtime log contains forbidden correlation field: {forbidden}"
            );
        }
        for call in direct_log_calls(runtime, "println!(")
            .into_iter()
            .chain(direct_log_calls(runtime, "eprintln!("))
        {
            for forbidden_field in [
                "peer",
                "client_id",
                "elapsed",
                "q.db_id",
                "db_id",
                "group_ids",
                "groups",
                ".len()",
                "bytes",
                "seq",
                "round_id",
            ] {
                assert!(
                    !call.contains(forbidden_field),
                    "default runtime log contains `{forbidden_field}`: {call}"
                );
            }
        }

        // Scan the complete non-test server source, not only the connection
        // loop. ORAM poison paths live above `main` and retain their first
        // reason across requests, so a detailed direct log there is also a
        // cross-request correlation sink.
        let non_test_source = source
            .split_once("#[cfg(test)]\nmod service_admission_dispatch_tests")
            .expect("non-test source boundary")
            .0;
        for call in direct_log_calls(non_test_source, "println!(")
            .into_iter()
            .chain(direct_log_calls(non_test_source, "eprintln!("))
        {
            for query_derived_field in [
                "bin_id",
                "chunk_id",
                "group_id",
                "round_id",
                "script_hash",
                "client_id",
                "prp_key",
                "hex_prefix",
                "[v2-half-pending]",
                "evicted",
            ] {
                assert!(
                    !call.contains(query_derived_field),
                    "default server log contains query-derived `{query_derived_field}`: {call}"
                );
            }
            if call.contains("table poisoned") {
                assert!(call.contains("coarse_reason"));
                assert!(!call.contains("unsafe_detail"));
            }
        }
        assert!(source.contains("macro_rules! unsafe_oram_detail"));
        assert!(source.contains("not(any(test, feature = \"test-only-unsafe-query-logging\"))"));
        assert!(source.contains("--unsafe-debug-query-logging"));
        assert!(source.contains("UNSAFE DEBUG QUERY LOGGING ENABLED"));
    }

    #[cfg(feature = "cuckoo-oram")]
    #[test]
    fn default_oram_poison_reason_discards_query_derived_detail() {
        UNSAFE_DEBUG_QUERY_LOGGING.store(false, Ordering::SeqCst);
        let poisoned = std::sync::Mutex::new(None);
        let returned = poison_direct(
            "chunk",
            &poisoned,
            "Direct ORAM chunk read failed after mutation",
            unsafe_oram_detail!(
                "Direct ORAM chunk {} returned bytes for request {}",
                424_242,
                919_191
            ),
        );
        assert_eq!(returned, "Direct ORAM chunk read failed after mutation");
        assert_eq!(
            poisoned.lock().unwrap().as_deref(),
            Some("Direct ORAM chunk read failed after mutation")
        );
        assert!(!returned.contains("424242"));
        assert!(!returned.contains("919191"));

        let later = poison_direct(
            "chunk",
            &poisoned,
            "Direct ORAM later request failed",
            unsafe_oram_detail!("later request chunk {}", 777_777),
        );
        assert_eq!(later, "Direct ORAM later request failed");
        assert_eq!(
            poisoned.lock().unwrap().as_deref(),
            Some("Direct ORAM chunk read failed after mutation"),
            "cross-request poison state must retain only the first coarse reason"
        );
    }

    #[cfg(not(feature = "test-only-unsafe-query-logging"))]
    #[test]
    fn default_non_feature_binary_gates_unsafe_logging_flag_to_unknown_cli_fallback() {
        let source = include_str!("unified_server.rs");
        let arm = source
            .find("\"--unsafe-debug-query-logging\" =>")
            .expect("unsafe logging CLI arm remains available to test builds");
        let gate = &source[arm.saturating_sub(128)..arm];
        assert!(gate.contains("#[cfg(any(test, feature = \"test-only-unsafe-query-logging\"))]"));
        assert_eq!(
            unknown_cli_argument_v1("--unsafe-debug-query-logging"),
            "unknown argument: --unsafe-debug-query-logging"
        );
    }

    #[test]
    fn cfg_test_cli_parser_recognizes_unsafe_logging_flag() {
        let args = parse_args_from(vec![
            "unified_server".to_owned(),
            "--unsafe-debug-query-logging".to_owned(),
        ]);
        assert!(args.unsafe_debug_query_logging);
    }

    #[test]
    fn online_v2full_limit_preserves_local_auth_and_pool_headroom() {
        assert_eq!(online_v2full_auth_limit_v1(0, 32, None).unwrap(), 0);
        assert_eq!(online_v2full_auth_limit_v1(1, 32, None).unwrap(), 0);
        assert_eq!(online_v2full_auth_limit_v1(2, 32, None).unwrap(), 1);
        assert_eq!(online_v2full_auth_limit_v1(20, 32, None).unwrap(), 8);
        assert_eq!(online_v2full_auth_limit_v1(100, 4, None).unwrap(), 3);
        assert_eq!(online_v2full_auth_limit_v1(4, 8, Some(2)).unwrap(), 2);
        assert!(online_v2full_auth_limit_v1(4, 8, Some(4)).is_err());
        assert!(online_v2full_auth_limit_v1(8, 4, Some(4)).is_err());
    }

    #[test]
    fn online_v2full_capacity_is_acquired_before_global_and_retained_after_auth() {
        let global = Semaphore::new(2);
        let online = Arc::new(Semaphore::new(1));

        let mut first = try_acquire_auth_capacity_v1(&global, &online, true)
            .expect("first online authorization has both permits");
        assert_eq!(global.available_permits(), 1);
        assert_eq!(online.available_permits(), 0);

        // Transfer the narrower permit into the post-grant reservation while
        // allowing the AUTH-only global permit to return.
        let retained_online = first.0.take().expect("online permit is owned");
        drop(first);
        assert_eq!(global.available_permits(), 2);
        assert_eq!(online.available_permits(), 0);

        // Overflow fails at the online class and therefore leaves every global
        // permit untouched; provider-local work can still acquire one.
        assert!(try_acquire_auth_capacity_v1(&global, &online, true).is_none());
        assert_eq!(global.available_permits(), 2);
        let local = try_acquire_auth_capacity_v1(&global, &online, false)
            .expect("provider-local authorization keeps global headroom");
        assert_eq!(global.available_permits(), 1);
        drop(local);

        drop(retained_online);
        assert_eq!(online.available_permits(), 1);
    }

    #[test]
    fn pending_v2full_accepts_only_its_bound_encrypted_main_dispatch() {
        let exact = Request::HarmonyHintsV2(HarmonyHintRequestV2 { db_id: 7 }).encode();
        let payload = &exact[4..];
        assert!(is_exact_pending_v2full_dispatch_v1(7, true, payload));
        assert!(!is_exact_pending_v2full_dispatch_v1(7, false, payload));
        assert!(!is_exact_pending_v2full_dispatch_v1(8, true, payload));
        assert!(!is_exact_pending_v2full_dispatch_v1(7, true, &[REQ_PING]));
    }

    #[test]
    fn cli_parser_accepts_explicit_online_v2full_limit() {
        let args = parse_args_from(vec![
            "unified_server".to_owned(),
            "--service-max-concurrent-online-v2full-auth".to_owned(),
            "3".to_owned(),
        ]);
        assert_eq!(args.service_max_concurrent_online_v2full_auth, Some(3));
    }

    #[test]
    fn cli_parser_accepts_exact_storeless_free_pow_policy_digest() {
        let digest = "42".repeat(32);
        let args = parse_args_from(vec![
            "unified_server".to_owned(),
            "--service-storeless-free-pow-policy-digest-hex".to_owned(),
            digest.clone(),
        ]);
        assert_eq!(
            args.service_storeless_free_pow_policy_digest_hex.as_deref(),
            Some(digest.as_str())
        );
    }

    #[cfg(feature = "test-only-unsafe-query-logging")]
    #[test]
    fn explicit_debug_feature_cli_parser_recognizes_unsafe_logging_flag() {
        let args = parse_args_from(vec![
            "unified_server".to_owned(),
            "--unsafe-debug-query-logging".to_owned(),
        ]);
        assert!(args.unsafe_debug_query_logging);
    }
}

#[cfg(test)]
mod announce_dispatch_tests {
    //! Tests for the REQ_ANNOUNCE response builder used by the
    //! production dispatch loop. The full per-connection match lives
    //! inline in `main` and needs a multi-GB checkpoint to boot, so we
    //! exercise the shared `build_announce_response` seam directly.
    //! Routing (opcode 0x07 reaching this arm rather than the catch-all
    //! "unsupported request" arm) is verified live by the operator-
    //! identity end-to-end check, since it can only be observed against
    //! a running binary.
    use super::*;

    #[test]
    fn announce_response_configured_returns_bundle_verbatim() {
        let bundle = vec![0xDEu8, 0xAD, 0xBE, 0xEF, 0x07];
        match build_announce_response(&Some(bundle.clone())) {
            Response::Announce(b) => assert_eq!(b, bundle),
            other => panic!("expected Announce, got {:?}", other),
        }
    }

    #[test]
    fn announce_response_configured_wire_roundtrips_to_same_bundle() {
        // The arm sends `resp.encode()` on the wire; a client decodes it
        // back to identical bundle bytes — proving the dispatch arm emits
        // a well-formed RESP_ANNOUNCE frame the SDK `announce()` parses.
        let bundle = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let wire = build_announce_response(&Some(bundle.clone())).encode();
        // Wire layout: [u32 LE outer len][RESP_ANNOUNCE][u32 LE blen][bundle];
        // `Response::decode` consumes everything after the outer length.
        match Response::decode(&wire[4..]).expect("decode RESP_ANNOUNCE") {
            Response::Announce(b) => assert_eq!(b, bundle),
            other => panic!("expected Announce after round-trip, got {:?}", other),
        }
    }

    #[test]
    fn announce_response_unconfigured_returns_error() {
        // None (server started without --identity-* flags, or with an
        // inconsistent key/cert pair) must surface as RESP_ERROR carrying
        // the documented "announce not configured" message — the client's
        // `announce()` maps this to PirError::ServerError.
        match build_announce_response(&None) {
            Response::Error(msg) => assert!(
                msg.contains("announce not configured"),
                "unexpected error message: {msg}"
            ),
            other => panic!("expected Error, got {:?}", other),
        }
    }
}

#[cfg(test)]
mod harmony_dos_guard_tests {
    //! S4/S5 guards for this binary's own inline Harmony handlers —
    //! the duplicates of `pir-runtime-core`'s `RequestHandler` paths
    //! (whose twins live in that crate's `dos_guard_tests`), plus the
    //! binary-only `REQ_HARMONY_HINTS` path. With the workspace-wide
    //! `panic = 'abort'`, each unguarded path was a single-frame
    //! unauthenticated full-process kill.
    //!
    //! Exercised through the free-function seams
    //! (`harmony_query_response`, `harmony_batch_response`,
    //! `validate_harmony_hints_request`, `compute_hints_for_group`)
    //! because the full `UnifiedServerData` needs a multi-GB
    //! checkpoint to boot — same pattern as `announce_dispatch_tests`.
    use super::*;
    use pir_core::cuckoo::write_header_with_anchor;
    use std::io::Write as _;

    /// bins_per_table for the synthetic test DB (mirrors the
    /// pir-runtime-core dos_guard_tests geometry).
    const TEST_BINS: usize = 256;

    static TEMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn temp_suffix() -> String {
        let n = TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!(
            "{}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            n,
        )
    }

    fn temp_path(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("unified_dos_{}_{}.bin", tag, temp_suffix()));
        p
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("unified_dos_{}_{}", tag, temp_suffix()));
        p
    }

    fn write_subtable_file(
        path: &std::path::Path,
        params: &pir_core::params::TableParams,
        bins_per_table: usize,
    ) {
        let bin_size = params.bin_size();
        let mut bytes = write_header_with_anchor(params, bins_per_table, 0, None);
        for g in 0..params.k {
            for bin in 0..bins_per_table {
                let marker = (g as u8) ^ (bin as u8);
                bytes.extend(std::iter::repeat(marker).take(bin_size));
            }
        }
        std::fs::File::create(path)
            .unwrap()
            .write_all(&bytes)
            .unwrap();
    }

    #[derive(Clone)]
    struct LookupFixture {
        found_sh: [u8; pir_core::params::SCRIPT_HASH_SIZE],
        whale_sh: [u8; pir_core::params::SCRIPT_HASH_SIZE],
        missing_sh: [u8; pir_core::params::SCRIPT_HASH_SIZE],
        chunk_payloads: Vec<Vec<u8>>,
    }

    const LOOKUP_TEST_BINS: usize = 64;
    const LOOKUP_INDEX_MASTER_SEED: u64 = 0x1111_2222_3333_4444;
    const LOOKUP_CHUNK_MASTER_SEED: u64 = 0x5555_6666_7777_8888;
    const LOOKUP_TAG_SEED: u64 = 0x9999_aaaa_bbbb_cccc;
    const LOOKUP_START_CHUNK_ID: u32 = 7;
    const LOOKUP_WHALE_START_CHUNK_ID: u32 = 900;

    fn deterministic_dummy(mut next: u32) -> impl FnMut() -> u32 {
        move || {
            let out = next;
            next = next.wrapping_add(1);
            out
        }
    }

    fn lookup_index_params() -> pir_core::params::TableParams {
        INDEX_PARAMS.with_master_seed(LOOKUP_INDEX_MASTER_SEED)
    }

    fn lookup_chunk_params() -> pir_core::params::TableParams {
        CHUNK_PARAMS.with_master_seed(LOOKUP_CHUNK_MASTER_SEED)
    }

    fn empty_lookup_table_bytes(
        params: &pir_core::params::TableParams,
        bins_per_table: usize,
        tag_seed: u64,
    ) -> Vec<u8> {
        let mut bytes = write_header_with_anchor(params, bins_per_table, tag_seed, None);
        bytes.resize(
            bytes.len() + params.k * params.table_byte_size(bins_per_table),
            0,
        );
        bytes
    }

    fn slot_offset(
        header_len: usize,
        params: &pir_core::params::TableParams,
        bins_per_table: usize,
        group_id: usize,
        bin_index: usize,
        slot: usize,
    ) -> usize {
        header_len
            + group_id * params.table_byte_size(bins_per_table)
            + bin_index * params.bin_size()
            + slot * params.slot_size
    }

    fn insert_slot(
        table: &mut [u8],
        header_len: usize,
        params: &pir_core::params::TableParams,
        bins_per_table: usize,
        group_id: usize,
        bin_index: usize,
        slot_bytes: &[u8],
    ) {
        assert_eq!(slot_bytes.len(), params.slot_size);
        for slot in 0..params.slots_per_bin {
            let off = slot_offset(
                header_len,
                params,
                bins_per_table,
                group_id,
                bin_index,
                slot,
            );
            if table[off..off + params.slot_size].iter().all(|&b| b == 0) {
                table[off..off + params.slot_size].copy_from_slice(slot_bytes);
                return;
            }
        }
        panic!("test cuckoo bin is full: group={group_id}, bin={bin_index}");
    }

    fn insert_index_record(
        table: &mut [u8],
        params: &pir_core::params::TableParams,
        bins_per_table: usize,
        script_hash: &[u8; pir_core::params::SCRIPT_HASH_SIZE],
        start_chunk_id: u32,
        num_chunks: u8,
    ) {
        let tag = pir_core::hash::compute_tag(LOOKUP_TAG_SEED, script_hash);
        let mut slot = Vec::with_capacity(params.slot_size);
        slot.extend_from_slice(&tag.to_le_bytes());
        slot.extend_from_slice(&start_chunk_id.to_le_bytes());
        slot.push(num_chunks);
        let header_len = params.header_size;
        for group_id in pir_core::hash::derive_groups_3(script_hash, params.k) {
            let key = pir_core::hash::derive_cuckoo_key(params.master_seed, group_id, 0);
            let bin_index = pir_core::hash::cuckoo_hash(script_hash, key, bins_per_table);
            insert_slot(
                table,
                header_len,
                params,
                bins_per_table,
                group_id,
                bin_index,
                &slot,
            );
        }
    }

    fn insert_chunk_record(
        table: &mut [u8],
        params: &pir_core::params::TableParams,
        bins_per_table: usize,
        chunk_id: u32,
        payload: &[u8],
    ) {
        assert_eq!(payload.len(), pir_core::params::CHUNK_SIZE);
        let mut slot = Vec::with_capacity(params.slot_size);
        slot.extend_from_slice(&chunk_id.to_le_bytes());
        slot.extend_from_slice(payload);
        let header_len = params.header_size;
        for group_id in pir_core::hash::derive_int_groups_3(chunk_id, params.k) {
            let key = pir_core::hash::derive_cuckoo_key(params.master_seed, group_id, 0);
            let bin_index = pir_core::hash::cuckoo_hash_int(chunk_id, key, bins_per_table);
            insert_slot(
                table,
                header_len,
                params,
                bins_per_table,
                group_id,
                bin_index,
                &slot,
            );
        }
    }

    fn write_lookup_db_files(db_dir: &std::path::Path) -> LookupFixture {
        std::fs::create_dir_all(db_dir).unwrap();
        let index_params = lookup_index_params();
        let chunk_params = lookup_chunk_params();
        let found_sh = [0x42u8; pir_core::params::SCRIPT_HASH_SIZE];
        let whale_sh = [0x24u8; pir_core::params::SCRIPT_HASH_SIZE];
        let missing_sh = [0x99u8; pir_core::params::SCRIPT_HASH_SIZE];
        let chunk_payloads = vec![
            vec![0xA7u8; pir_core::params::CHUNK_SIZE],
            vec![0xB8u8; pir_core::params::CHUNK_SIZE],
        ];

        let mut index_bytes =
            empty_lookup_table_bytes(&index_params, LOOKUP_TEST_BINS, LOOKUP_TAG_SEED);
        insert_index_record(
            &mut index_bytes,
            &index_params,
            LOOKUP_TEST_BINS,
            &found_sh,
            LOOKUP_START_CHUNK_ID,
            chunk_payloads.len() as u8,
        );
        insert_index_record(
            &mut index_bytes,
            &index_params,
            LOOKUP_TEST_BINS,
            &whale_sh,
            LOOKUP_WHALE_START_CHUNK_ID,
            0,
        );

        let mut chunk_bytes = empty_lookup_table_bytes(&chunk_params, LOOKUP_TEST_BINS, 0);
        for (i, payload) in chunk_payloads.iter().enumerate() {
            insert_chunk_record(
                &mut chunk_bytes,
                &chunk_params,
                LOOKUP_TEST_BINS,
                LOOKUP_START_CHUNK_ID + i as u32,
                payload,
            );
        }

        std::fs::write(db_dir.join("batch_pir_cuckoo.bin"), index_bytes).unwrap();
        std::fs::write(db_dir.join("chunk_pir_cuckoo.bin"), chunk_bytes).unwrap();

        LookupFixture {
            found_sh,
            whale_sh,
            missing_sh,
            chunk_payloads,
        }
    }

    fn load_lookup_db(db_dir: &std::path::Path) -> MappedDatabase {
        MappedDatabase {
            descriptor: DatabaseDescriptor {
                name: "lookup-test".into(),
                db_type: DatabaseType::Full,
                base_height: 0,
                height: 0,
                index_params: lookup_index_params(),
                chunk_params: lookup_chunk_params(),
            },
            index: MappedSubTable::load(
                &db_dir.join("batch_pir_cuckoo.bin"),
                lookup_index_params(),
            ),
            chunk: MappedSubTable::load(
                &db_dir.join("chunk_pir_cuckoo.bin"),
                lookup_chunk_params(),
            ),
            bucket_merkle_index_siblings: Vec::new(),
            bucket_merkle_chunk_siblings: Vec::new(),
            bucket_merkle_tree_tops: None,
            bucket_merkle_roots: None,
            bucket_merkle_root: None,
            manifest_root: None,
            manifest: None,
            db_proof: None,
            db_proof_v2: None,
        }
    }

    /// Write a legacy (anchor-less) cuckoo file with k groups of
    /// TEST_BINS bins, every byte of bin `b` in group `g` set to
    /// `g ^ b`, then mmap it.
    fn make_subtable(tag: &str, params: pir_core::params::TableParams) -> MappedSubTable {
        let path = temp_path(tag);
        write_subtable_file(&path, &params, TEST_BINS);
        let st = MappedSubTable::load(&path, params);
        // mmap keeps the inode alive; unlink immediately so failing
        // tests don't leak temp files.
        std::fs::remove_file(&path).ok();
        st
    }

    /// Synthetic DB with one bucket-Merkle INDEX sibling level so the
    /// sibling branches of `harmony_level_table` are reachable.
    fn make_db() -> MappedDatabase {
        MappedDatabase {
            descriptor: DatabaseDescriptor {
                name: "dos-test".into(),
                db_type: DatabaseType::Full,
                base_height: 0,
                height: 0,
                index_params: INDEX_PARAMS.clone(),
                chunk_params: CHUNK_PARAMS.clone(),
            },
            index: make_subtable("idx", INDEX_PARAMS.clone()),
            chunk: make_subtable("chk", CHUNK_PARAMS.clone()),
            bucket_merkle_index_siblings: vec![make_subtable("isib0", INDEX_PARAMS.clone())],
            bucket_merkle_chunk_siblings: Vec::new(),
            bucket_merkle_tree_tops: None,
            bucket_merkle_roots: None,
            bucket_merkle_root: None,
            manifest_root: None,
            manifest: None,
            db_proof: None,
            db_proof_v2: None,
        }
    }

    fn expect_error(resp: Response, needle: &str) {
        match resp {
            Response::Error(msg) => {
                assert!(msg.contains(needle), "error {:?} missing {:?}", msg, needle)
            }
            other => panic!("expected Error, got {:?}", other),
        }
    }

    #[test]
    fn mmap_table_access_matches_direct_group_slice() {
        let db = make_db();
        let access = MmapCuckooTable::new(&db.chunk, db.chunk.params.bin_size());
        let group_id = 4usize;
        let indices = [0usize, 17, TEST_BINS - 1];

        let mut via_access = Vec::new();
        for idx in indices {
            access.append_entry(group_id, idx, &mut via_access).unwrap();
        }

        let entry_size = db.chunk.params.bin_size();
        let group_bytes = db.chunk.group_bytes(group_id);
        let mut direct = Vec::new();
        for idx in indices {
            let off = idx * entry_size;
            direct.extend_from_slice(&group_bytes[off..off + entry_size]);
        }

        assert_eq!(via_access, direct);
    }

    #[test]
    fn native_lookup_mmap_reads_expected_data_and_presence_padding() {
        let db_dir = temp_dir("lookup_mmap");
        let fixture = write_lookup_db_files(&db_dir);
        let db = load_lookup_db(&db_dir);
        let script_hashes = [fixture.found_sh, fixture.missing_sh, fixture.whale_sh];

        let index_table = MmapCuckooTable::new(&db.index, db.index.params.bin_size());
        let chunk_table = MmapCuckooTable::new(&db.chunk, db.chunk.params.bin_size());
        let got = cuckoo_native_lookup_batch_from_tables_with_dummy(
            &index_table,
            &chunk_table,
            CuckooNativeLookupConfig::from_db(&db),
            &script_hashes,
            deterministic_dummy(1_000),
        )
        .unwrap();

        assert_eq!(got.len(), 3);

        let mut expected_payload = Vec::new();
        expected_payload.extend_from_slice(&fixture.chunk_payloads[0]);
        expected_payload.extend_from_slice(&fixture.chunk_payloads[1]);
        assert!(got[0].found);
        assert!(!got[0].whale);
        assert_eq!(got[0].start_chunk_id, Some(LOOKUP_START_CHUNK_ID));
        assert_eq!(got[0].num_chunks, 2);
        assert_eq!(got[0].raw_chunk_data, expected_payload);
        assert_eq!(got[0].index_bin_reads.len(), INDEX_PARAMS.cuckoo_num_hashes);
        assert_eq!(
            got[0].chunk_bin_reads.len(),
            CHUNK_PARAMS.cuckoo_num_hashes * got[0].num_chunks as usize,
        );

        assert!(!got[1].found);
        assert!(!got[1].whale);
        assert_eq!(got[1].start_chunk_id, None);
        assert_eq!(got[1].raw_chunk_data.len(), 0);
        assert_eq!(got[1].index_bin_reads.len(), INDEX_PARAMS.cuckoo_num_hashes);
        assert_eq!(got[1].chunk_bin_reads.len(), CHUNK_PARAMS.cuckoo_num_hashes);

        assert!(got[2].found);
        assert!(got[2].whale);
        assert_eq!(got[2].start_chunk_id, Some(LOOKUP_WHALE_START_CHUNK_ID));
        assert_eq!(got[2].raw_chunk_data.len(), 0);
        assert_eq!(got[2].index_bin_reads.len(), INDEX_PARAMS.cuckoo_num_hashes);
        assert_eq!(got[2].chunk_bin_reads.len(), CHUNK_PARAMS.cuckoo_num_hashes);

        std::fs::remove_dir_all(&db_dir).ok();
    }

    #[cfg(feature = "cuckoo-oram")]
    #[test]
    fn oram_table_access_matches_direct_group_slice() {
        let db_dir = temp_dir("oram_db");
        let oram_dir = temp_dir("oram_img");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&oram_dir).unwrap();

        let bins_per_table = 16usize;
        let chunk_path = db_dir.join(CuckooLevel::Chunk.filename());
        write_subtable_file(&chunk_path, &CHUNK_PARAMS, bins_per_table);
        let table = CuckooTableInfo::from_file(CuckooLevel::Chunk, &chunk_path).unwrap();
        let pack = 4usize;
        let source = CuckooPackedBlockReader::open(table.clone(), pack).unwrap();
        let params = OramParams::with_leaves(
            source.logical_blocks(),
            source.block_payload_bytes(),
            source.logical_blocks().max(2).next_power_of_two(),
        )
        .unwrap()
        .with_bucket_size(2)
        .unwrap()
        .with_stash_capacity(128)
        .unwrap();
        let meta_path = oram_dir.join("chunk.meta.oram");
        let payload_path = oram_dir.join("chunk.payload.oram");
        let state_path = oram_dir.join("chunk.state");
        let meta_store = FilePageStore::open(
            &meta_path,
            params.bucket_count(),
            circuit_meta_page_bytes(params.bucket_size),
        )
        .unwrap();
        let payload_store = FilePageStore::open(
            &payload_path,
            params.bucket_count(),
            circuit_payload_page_bytes(params.bucket_size, params.block_size),
        )
        .unwrap();
        let mut oram = CircuitOram::build_trusted_from_source(
            params,
            meta_store,
            payload_store,
            source,
            [9; 32],
        )
        .unwrap();
        oram.flush().unwrap();
        oram.snapshot().save_atomic(&state_path).unwrap();
        drop(oram);

        let access = CuckooOramTable::open(
            &db_dir,
            &oram_dir,
            CuckooLevel::Chunk,
            pack,
            2,
            false,
            None,
            None,
            0,
            false,
            true,
        )
        .unwrap();

        let group_id = 3usize;
        let indices = [0u32, 5, (bins_per_table - 1) as u32];
        let mut via_oram = Vec::new();
        access
            .append_entries(group_id, &indices, false, &mut via_oram)
            .unwrap();
        access.finish_request().unwrap();

        let mut direct_reader = CuckooPackedBlockReader::open(table, pack).unwrap();
        let mut direct = Vec::new();
        for idx in indices {
            direct.extend_from_slice(
                &direct_reader
                    .read_bin(group_id * bins_per_table + idx as usize)
                    .unwrap(),
            );
        }

        assert_eq!(via_oram, direct);

        std::fs::remove_dir_all(&db_dir).ok();
        std::fs::remove_dir_all(&oram_dir).ok();
    }

    #[cfg(feature = "cuckoo-oram")]
    #[test]
    fn oram_table_poisoned_after_failed_state_save() {
        let db_dir = temp_dir("oram_poison_db");
        let oram_dir = temp_dir("oram_poison_img");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&oram_dir).unwrap();

        let bins_per_table = 16usize;
        let chunk_path = db_dir.join(CuckooLevel::Chunk.filename());
        write_subtable_file(&chunk_path, &CHUNK_PARAMS, bins_per_table);
        let pack = 4usize;
        build_test_oram_image(&db_dir, &oram_dir, CuckooLevel::Chunk, pack);

        let access = CuckooOramTable::open(
            &db_dir,
            &oram_dir,
            CuckooLevel::Chunk,
            pack,
            2,
            false,
            None,
            None,
            0,
            false,
            true,
        )
        .unwrap();

        let mut first = Vec::new();
        access.append_entries(3, &[0], false, &mut first).unwrap();

        // Keep opened page-image descriptors alive, but make the state-file
        // commit impossible. A failed commit after mutation must poison the
        // table instead of allowing later reads to continue.
        std::fs::remove_dir_all(&oram_dir).unwrap();
        let err = access.finish_request().unwrap_err();
        assert!(
            err.contains("state save failed"),
            "unexpected finish_request error: {err}"
        );

        let mut second = Vec::new();
        let err = access
            .append_entries(3, &[1], false, &mut second)
            .unwrap_err();
        assert!(err.contains("poisoned"), "unexpected poisoned error: {err}");

        std::fs::remove_dir_all(&db_dir).ok();
    }

    #[cfg(feature = "cuckoo-oram")]
    fn build_test_oram_image(
        db_dir: &std::path::Path,
        oram_dir: &std::path::Path,
        level: CuckooLevel,
        pack: usize,
    ) {
        let table = CuckooTableInfo::from_file(level, db_dir.join(level.filename())).unwrap();
        let source = CuckooPackedBlockReader::open(table, pack).unwrap();
        let params = OramParams::with_leaves(
            source.logical_blocks(),
            source.block_payload_bytes(),
            source.logical_blocks().max(2).next_power_of_two(),
        )
        .unwrap()
        .with_bucket_size(2)
        .unwrap()
        .with_stash_capacity(128)
        .unwrap();
        let paths = CuckooOramPaths::new(oram_dir, level);
        let meta_store = FilePageStore::open(
            &paths.meta_image,
            params.bucket_count(),
            circuit_meta_page_bytes(params.bucket_size),
        )
        .unwrap();
        let payload_store = FilePageStore::open(
            &paths.payload_image,
            params.bucket_count(),
            circuit_payload_page_bytes(params.bucket_size, params.block_size),
        )
        .unwrap();
        let mut oram = CircuitOram::build_trusted_from_source(
            params,
            meta_store,
            payload_store,
            source,
            [3; 32],
        )
        .unwrap();
        oram.flush().unwrap();
        oram.snapshot().save_atomic(&paths.state).unwrap();
    }

    #[cfg(feature = "cuckoo-oram")]
    struct DirectLookupFixture {
        found_sh: [u8; pir_core::params::SCRIPT_HASH_SIZE],
        whale_sh: [u8; pir_core::params::SCRIPT_HASH_SIZE],
        missing_sh: [u8; pir_core::params::SCRIPT_HASH_SIZE],
        chunks: Vec<Vec<u8>>,
    }

    #[cfg(feature = "cuckoo-oram")]
    fn direct_chunk_record(txid_byte: u8, vout: u32, amount: u64) -> Vec<u8> {
        let mut raw = pir_core::codec::serialize_utxo_data(&[pir_core::codec::UtxoEntry {
            txid: [txid_byte; 32],
            vout,
            amount,
        }]);
        assert!(raw.len() <= DIRECT_CHUNK_RECORD_SIZE);
        raw.resize(DIRECT_CHUNK_RECORD_SIZE, 0);
        raw
    }

    #[cfg(feature = "cuckoo-oram")]
    #[test]
    fn direct_oram_response_padding_fills_public_chunk_budget() {
        let access_budget = 8usize;
        let slots = 3usize;
        let hash_fns = 2usize;
        let actual_chunk_bytes = DIRECT_CHUNK_RECORD_SIZE;

        assert_eq!(
            direct_oram_response_padding_bytes(access_budget, slots, hash_fns, actual_chunk_bytes)
                .unwrap(),
            DIRECT_CHUNK_RECORD_SIZE,
        );
        assert!(direct_oram_response_padding_bytes(
            access_budget,
            slots,
            hash_fns,
            3 * DIRECT_CHUNK_RECORD_SIZE,
        )
        .is_err());
    }

    #[cfg(feature = "cuckoo-oram")]
    fn write_direct_lookup_files(db_dir: &std::path::Path) -> DirectLookupFixture {
        std::fs::create_dir_all(db_dir).unwrap();

        let found_sh = [0x51u8; pir_core::params::SCRIPT_HASH_SIZE];
        let whale_sh = [0x52u8; pir_core::params::SCRIPT_HASH_SIZE];
        let missing_sh = [0x53u8; pir_core::params::SCRIPT_HASH_SIZE];

        let mut index_bytes = Vec::new();
        index_bytes.extend_from_slice(&found_sh);
        index_bytes.extend_from_slice(&3u32.to_le_bytes());
        index_bytes.push(2);
        index_bytes.extend_from_slice(&whale_sh);
        index_bytes.extend_from_slice(&1u32.to_le_bytes());
        index_bytes.push(0);
        assert_eq!(index_bytes.len(), 2 * DIRECT_INDEX_INPUT_RECORD_SIZE);

        let chunks = vec![
            vec![0u8; DIRECT_CHUNK_RECORD_SIZE],
            vec![0u8; DIRECT_CHUNK_RECORD_SIZE],
            vec![0u8; DIRECT_CHUNK_RECORD_SIZE],
            direct_chunk_record(0xA1, 1, 42),
            direct_chunk_record(0xB2, 2, 77),
            vec![0u8; DIRECT_CHUNK_RECORD_SIZE],
        ];
        let mut chunk_bytes = Vec::new();
        for chunk in &chunks {
            chunk_bytes.extend_from_slice(chunk);
        }

        std::fs::write(db_dir.join("utxo_chunks_index_nodust.bin"), index_bytes).unwrap();
        std::fs::write(db_dir.join("utxo_chunks_nodust.bin"), chunk_bytes).unwrap();

        DirectLookupFixture {
            found_sh,
            whale_sh,
            missing_sh,
            chunks,
        }
    }

    #[cfg(feature = "cuckoo-oram")]
    fn build_test_direct_oram_image(
        db_dir: &std::path::Path,
        oram_dir: &std::path::Path,
        level: DirectLevel,
        pack: usize,
    ) {
        match level {
            DirectLevel::Index => {
                let info = DirectTableInfo::from_index_file(
                    db_dir.join("utxo_chunks_index_nodust.bin"),
                    4,
                    2,
                    0.20,
                    0x6469_7265_6374_0001,
                )
                .unwrap();
                let source = DirectIndexPackedBlockReader::build(info, pack).unwrap();
                let metadata = source.metadata().clone();
                build_test_direct_oram_from_source(oram_dir, level, metadata, source);
            }
            DirectLevel::Chunk => {
                let info = DirectTableInfo::from_chunks_file(db_dir.join("utxo_chunks_nodust.bin"))
                    .unwrap();
                let source = DirectChunkPackedBlockReader::open(info, pack).unwrap();
                let metadata = source.metadata().clone();
                build_test_direct_oram_from_source(oram_dir, level, metadata, source);
            }
        }
    }

    #[cfg(feature = "cuckoo-oram")]
    fn build_test_direct_oram_from_source<S: bitcoinpir_oram::TrustedBlockSource>(
        oram_dir: &std::path::Path,
        level: DirectLevel,
        metadata: DirectTableMetadata,
        source: S,
    ) {
        let params = OramParams::with_leaves(
            source.logical_blocks(),
            source.block_size(),
            source.logical_blocks().max(2).next_power_of_two(),
        )
        .unwrap()
        .with_bucket_size(2)
        .unwrap()
        .with_stash_capacity(128)
        .unwrap();
        let paths = DirectOramPaths::new(oram_dir, level);
        let meta_store = FilePageStore::open(
            &paths.meta_image,
            params.bucket_count(),
            circuit_meta_page_bytes(params.bucket_size),
        )
        .unwrap();
        let payload_store = FilePageStore::open(
            &paths.payload_image,
            params.bucket_count(),
            circuit_payload_page_bytes(params.bucket_size, params.block_size),
        )
        .unwrap();
        let mut oram = CircuitOram::build_trusted_from_source(
            params,
            meta_store,
            payload_store,
            source,
            [5; 32],
        )
        .unwrap();
        oram.flush().unwrap();
        oram.snapshot().save_atomic(&paths.state).unwrap();
        metadata.save(&paths.metadata).unwrap();
    }

    #[cfg(feature = "cuckoo-oram")]
    fn build_test_direct_oram_auth_store(
        oram_dir: &std::path::Path,
        level: DirectLevel,
        trusted_levels: usize,
    ) {
        let paths = DirectOramPaths::new(oram_dir, level);
        let state = CircuitOramState::load(&paths.state).unwrap();
        let params = state.params.clone();
        let hash_page_size = 4096usize;
        let meta_store = FilePageStore::open(
            &paths.meta_image,
            params.bucket_count(),
            circuit_meta_page_bytes(params.bucket_size),
        )
        .unwrap();
        let payload_store = FilePageStore::open(
            &paths.payload_image,
            params.bucket_count(),
            circuit_payload_page_bytes(params.bucket_size, params.block_size),
        )
        .unwrap();
        let meta_hash_store = FilePageStore::open(
            &paths.meta_hash_image,
            tiered_hash_pages(params.bucket_count(), hash_page_size, trusted_levels).unwrap(),
            hash_page_size,
        )
        .unwrap();
        let payload_hash_store = FilePageStore::open(
            &paths.payload_hash_image,
            tiered_hash_pages(params.bucket_count(), hash_page_size, trusted_levels).unwrap(),
            hash_page_size,
        )
        .unwrap();
        let mut meta = TieredMerklePageStore::build(
            meta_store,
            meta_hash_store,
            direct_auth_store_id(level, CircuitAuthStoreKind::Meta),
            trusted_levels,
        )
        .unwrap();
        let mut payload = TieredMerklePageStore::build(
            payload_store,
            payload_hash_store,
            direct_auth_store_id(level, CircuitAuthStoreKind::Payload),
            trusted_levels,
        )
        .unwrap();
        PageStore::flush(&mut meta).unwrap();
        PageStore::flush(&mut payload).unwrap();
        CircuitStoreAuthState::new(meta.trusted_state(), payload.trusted_state())
            .save_atomic(&paths.auth_state)
            .unwrap();
    }

    #[cfg(feature = "cuckoo-oram")]
    #[test]
    fn direct_oram_lookup_reads_direct_entries_without_pbc() {
        let db_dir = temp_dir("direct_lookup_db");
        let oram_dir = temp_dir("direct_lookup_img");
        std::fs::create_dir_all(&oram_dir).unwrap();
        let fixture = write_direct_lookup_files(&db_dir);

        let pack = 2usize;
        build_test_direct_oram_image(&db_dir, &oram_dir, DirectLevel::Index, pack);
        build_test_direct_oram_image(&db_dir, &oram_dir, DirectLevel::Chunk, pack);

        let tables =
            DirectOramTables::open(&oram_dir, 2, 8, false, None, None, 0, false, true).unwrap();
        let got = direct_native_lookup_batch(
            &tables,
            &[fixture.found_sh, fixture.missing_sh, fixture.whale_sh],
        )
        .unwrap();

        let mut expected_payload = Vec::new();
        expected_payload.extend_from_slice(&fixture.chunks[3]);
        expected_payload.extend_from_slice(&fixture.chunks[4]);

        assert_eq!(got.len(), 3);
        assert!(got[0].found);
        assert!(!got[0].whale);
        assert_eq!(got[0].start_chunk_id, Some(3));
        assert_eq!(got[0].num_chunks, 2);
        assert_eq!(got[0].raw_chunk_data, expected_payload);

        assert!(!got[1].found);
        assert!(!got[1].whale);
        assert_eq!(got[1].raw_chunk_data.len(), 0);

        assert!(got[2].found);
        assert!(got[2].whale);
        assert_eq!(got[2].start_chunk_id, Some(1));
        assert_eq!(got[2].num_chunks, 0);
        assert_eq!(got[2].raw_chunk_data.len(), 0);

        std::fs::remove_dir_all(&db_dir).ok();
        std::fs::remove_dir_all(&oram_dir).ok();
    }

    #[cfg(feature = "cuckoo-oram")]
    #[test]
    fn direct_oram_opens_controller_state_and_metadata_from_trusted_directory() {
        let db_dir = temp_dir("direct_lookup_trusted_db");
        let oram_dir = temp_dir("direct_lookup_trusted_img");
        let trusted_state_dir = temp_dir("direct_lookup_trusted_state");
        std::fs::create_dir_all(&oram_dir).unwrap();
        std::fs::create_dir_all(&trusted_state_dir).unwrap();
        let fixture = write_direct_lookup_files(&db_dir);

        let pack = 2usize;
        for level in [DirectLevel::Index, DirectLevel::Chunk] {
            build_test_direct_oram_image(&db_dir, &oram_dir, level, pack);
            let disk_paths = DirectOramPaths::new(&oram_dir, level);
            let trusted_paths =
                DirectOramPaths::new_with_trusted_state(&oram_dir, Some(&trusted_state_dir), level);
            std::fs::rename(&disk_paths.state, &trusted_paths.state).unwrap();
            std::fs::rename(&disk_paths.metadata, &trusted_paths.metadata).unwrap();
        }

        let tables = DirectOramTables::open_with_trusted_state(
            &oram_dir,
            Some(&trusted_state_dir),
            2,
            8,
            false,
            None,
            None,
            0,
            false,
            true,
        )
        .unwrap();
        let got = direct_native_lookup_batch(&tables, &[fixture.found_sh]).unwrap();
        assert!(got[0].found);
        assert!(trusted_state_dir.join("direct-index.state").exists());
        assert!(trusted_state_dir.join("direct-chunk.state").exists());
        assert!(!oram_dir.join("direct-index.state").exists());
        assert!(!oram_dir.join("direct-chunk.state").exists());

        std::fs::remove_dir_all(&db_dir).ok();
        std::fs::remove_dir_all(&oram_dir).ok();
        std::fs::remove_dir_all(&trusted_state_dir).ok();
    }

    #[cfg(feature = "cuckoo-oram")]
    #[test]
    fn direct_oram_lookup_spends_dummy_index_reads_for_empty_slots() {
        let db_dir = temp_dir("direct_lookup_padded_db");
        let oram_dir = temp_dir("direct_lookup_padded_img");
        std::fs::create_dir_all(&oram_dir).unwrap();
        let fixture = write_direct_lookup_files(&db_dir);

        let pack = 2usize;
        build_test_direct_oram_image(&db_dir, &oram_dir, DirectLevel::Index, pack);
        build_test_direct_oram_image(&db_dir, &oram_dir, DirectLevel::Chunk, pack);

        let tables =
            DirectOramTables::open(&oram_dir, 2, 8, false, None, None, 0, false, true).unwrap();
        let got = tables
            .lookup_batch(
                &[
                    fixture.found_sh,
                    [0u8; pir_core::params::SCRIPT_HASH_SIZE],
                    fixture.missing_sh,
                ],
                &[true, false, true],
            )
            .unwrap();

        let mut expected_payload = Vec::new();
        expected_payload.extend_from_slice(&fixture.chunks[3]);
        expected_payload.extend_from_slice(&fixture.chunks[4]);

        assert_eq!(got.len(), 3);
        assert!(got[0].found);
        assert_eq!(got[0].raw_chunk_data, expected_payload);
        assert!(!got[1].found);
        assert_eq!(got[1].num_chunks, 0);
        assert_eq!(got[1].raw_chunk_data.len(), 0);
        assert!(!got[2].found);

        std::fs::remove_dir_all(&db_dir).ok();
        std::fs::remove_dir_all(&oram_dir).ok();
    }

    #[cfg(feature = "cuckoo-oram")]
    #[test]
    fn direct_oram_same_db_requests_serialize_complete_state_commits() {
        use std::sync::{mpsc, Arc};
        use std::time::Duration;

        let db_dir = temp_dir("direct_lookup_serial_db");
        let oram_dir = temp_dir("direct_lookup_serial_img");
        std::fs::create_dir_all(&oram_dir).unwrap();
        let fixture = write_direct_lookup_files(&db_dir);

        let pack = 2usize;
        build_test_direct_oram_image(&db_dir, &oram_dir, DirectLevel::Index, pack);
        build_test_direct_oram_image(&db_dir, &oram_dir, DirectLevel::Chunk, pack);
        build_test_direct_oram_auth_store(&oram_dir, DirectLevel::Index, 2);
        build_test_direct_oram_auth_store(&oram_dir, DirectLevel::Chunk, 2);

        let tables = Arc::new(
            DirectOramTables::open(&oram_dir, 2, 8, false, None, None, 0, true, true).unwrap(),
        );

        // Hold the per-DB transaction gate while both workers reach the
        // production lookup entrypoint. Neither request may complete until
        // the gate is released; afterwards both must commit cleanly in turn.
        let gate = tables.request_transaction.lock().unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let mut workers = Vec::new();
        for _ in 0..2 {
            let tables = Arc::clone(&tables);
            let ready_tx = ready_tx.clone();
            let done_tx = done_tx.clone();
            let script_hash = fixture.found_sh;
            workers.push(std::thread::spawn(move || {
                ready_tx.send(()).unwrap();
                done_tx
                    .send(tables.lookup_batch(&[script_hash], &[true]))
                    .unwrap();
            }));
        }
        drop(ready_tx);
        drop(done_tx);
        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(
            done_rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));

        drop(gate);
        for _ in 0..2 {
            let got = done_rx
                .recv_timeout(Duration::from_secs(15))
                .expect("serialized direct ORAM request did not finish")
                .expect("serialized direct ORAM request failed");
            assert_eq!(got.len(), 1);
            assert!(got[0].found);
        }
        for worker in workers {
            worker.join().unwrap();
        }

        tables.index.check_not_poisoned().unwrap();
        tables.chunk.check_not_poisoned().unwrap();
        for name in [
            "direct-index.state.tmp",
            "direct-index.auth.state.tmp",
            "direct-chunk.state.tmp",
            "direct-chunk.auth.state.tmp",
        ] {
            assert!(
                !oram_dir.join(name).exists(),
                "serialized save left temporary file {name}"
            );
        }

        // Reopening validates that state and authenticated roots were saved as
        // one coherent sequence, not merely that neither worker saw ENOENT.
        drop(tables);
        let reopened =
            DirectOramTables::open(&oram_dir, 2, 8, false, None, None, 0, true, true).unwrap();
        let got = reopened.lookup_batch(&[fixture.found_sh], &[true]).unwrap();
        assert!(got[0].found);

        std::fs::remove_dir_all(&db_dir).ok();
        std::fs::remove_dir_all(&oram_dir).ok();
    }

    #[cfg(feature = "cuckoo-oram")]
    #[test]
    fn direct_oram_different_databases_keep_independent_transaction_gates() {
        use std::sync::{mpsc, Arc};
        use std::time::Duration;

        let db_dir = temp_dir("direct_lookup_parallel_db");
        let oram_dir_0 = temp_dir("direct_lookup_parallel_img_0");
        let oram_dir_1 = temp_dir("direct_lookup_parallel_img_1");
        let fixture = write_direct_lookup_files(&db_dir);

        let pack = 2usize;
        for oram_dir in [&oram_dir_0, &oram_dir_1] {
            std::fs::create_dir_all(oram_dir).unwrap();
            build_test_direct_oram_image(&db_dir, oram_dir, DirectLevel::Index, pack);
            build_test_direct_oram_image(&db_dir, oram_dir, DirectLevel::Chunk, pack);
        }

        let db0 =
            DirectOramTables::open(&oram_dir_0, 2, 8, false, None, None, 0, false, true).unwrap();
        let db1 = Arc::new(
            DirectOramTables::open(&oram_dir_1, 2, 8, false, None, None, 0, false, true).unwrap(),
        );

        let db0_gate = db0.request_transaction.lock().unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        let worker_db1 = Arc::clone(&db1);
        let script_hash = fixture.found_sh;
        let worker = std::thread::spawn(move || {
            done_tx
                .send(worker_db1.lookup_batch(&[script_hash], &[true]))
                .unwrap();
        });

        let got = done_rx
            .recv_timeout(Duration::from_secs(15))
            .expect("DB1 request was incorrectly blocked by DB0 transaction")
            .expect("DB1 request failed while DB0 transaction was held");
        assert!(got[0].found);
        worker.join().unwrap();
        drop(db0_gate);

        std::fs::remove_dir_all(&db_dir).ok();
        std::fs::remove_dir_all(&oram_dir_0).ok();
        std::fs::remove_dir_all(&oram_dir_1).ok();
    }

    #[cfg(feature = "cuckoo-oram")]
    #[test]
    fn direct_oram_lookup_rejects_when_index_reads_exceed_budget() {
        let db_dir = temp_dir("direct_lookup_db");
        let oram_dir = temp_dir("direct_lookup_img");
        std::fs::create_dir_all(&oram_dir).unwrap();
        let fixture = write_direct_lookup_files(&db_dir);

        let pack = 2usize;
        build_test_direct_oram_image(&db_dir, &oram_dir, DirectLevel::Index, pack);
        build_test_direct_oram_image(&db_dir, &oram_dir, DirectLevel::Chunk, pack);

        let tables =
            DirectOramTables::open(&oram_dir, 2, 1, false, None, None, 0, false, true).unwrap();
        let err = direct_native_lookup_batch(&tables, &[fixture.found_sh]).unwrap_err();
        assert!(err.contains("access budget 1 too small"));

        std::fs::remove_dir_all(&db_dir).ok();
        std::fs::remove_dir_all(&oram_dir).ok();
    }

    #[cfg(feature = "cuckoo-oram")]
    #[test]
    fn direct_oram_lookup_rejects_when_chunk_demand_exceeds_remaining_budget() {
        let db_dir = temp_dir("direct_lookup_db");
        let oram_dir = temp_dir("direct_lookup_img");
        std::fs::create_dir_all(&oram_dir).unwrap();
        let fixture = write_direct_lookup_files(&db_dir);

        let pack = 2usize;
        build_test_direct_oram_image(&db_dir, &oram_dir, DirectLevel::Index, pack);
        build_test_direct_oram_image(&db_dir, &oram_dir, DirectLevel::Chunk, pack);

        let tables =
            DirectOramTables::open(&oram_dir, 2, 3, false, None, None, 0, false, true).unwrap();
        let err = direct_native_lookup_batch(&tables, &[fixture.found_sh]).unwrap_err();
        assert!(err.contains("chunk demand 2 exceeds remaining access budget 1"));

        std::fs::remove_dir_all(&db_dir).ok();
        std::fs::remove_dir_all(&oram_dir).ok();
    }

    #[cfg(feature = "cuckoo-oram")]
    fn build_test_oram_auth_store(
        oram_dir: &std::path::Path,
        level: CuckooLevel,
        trusted_levels: usize,
    ) {
        let paths = CuckooOramPaths::new(oram_dir, level);
        let state = CircuitOramState::load(&paths.state).unwrap();
        let params = state.params.clone();
        let hash_page_size = 4096usize;
        let meta_store = FilePageStore::open(
            &paths.meta_image,
            params.bucket_count(),
            circuit_meta_page_bytes(params.bucket_size),
        )
        .unwrap();
        let payload_store = FilePageStore::open(
            &paths.payload_image,
            params.bucket_count(),
            circuit_payload_page_bytes(params.bucket_size, params.block_size),
        )
        .unwrap();
        let meta_hash_store = FilePageStore::open(
            &paths.meta_hash_image,
            tiered_hash_pages(params.bucket_count(), hash_page_size, trusted_levels).unwrap(),
            hash_page_size,
        )
        .unwrap();
        let payload_hash_store = FilePageStore::open(
            &paths.payload_hash_image,
            tiered_hash_pages(params.bucket_count(), hash_page_size, trusted_levels).unwrap(),
            hash_page_size,
        )
        .unwrap();
        let mut meta = TieredMerklePageStore::build(
            meta_store,
            meta_hash_store,
            circuit_auth_store_id(level, CircuitAuthStoreKind::Meta),
            trusted_levels,
        )
        .unwrap();
        let mut payload = TieredMerklePageStore::build(
            payload_store,
            payload_hash_store,
            circuit_auth_store_id(level, CircuitAuthStoreKind::Payload),
            trusted_levels,
        )
        .unwrap();
        PageStore::flush(&mut meta).unwrap();
        PageStore::flush(&mut payload).unwrap();
        CircuitStoreAuthState::new(meta.trusted_state(), payload.trusted_state())
            .save_atomic(&paths.auth_state)
            .unwrap();
    }

    #[cfg(feature = "cuckoo-oram")]
    #[test]
    fn oram_table_auth_store_reopens_after_mutating_read() {
        let db_dir = temp_dir("oram_auth_db");
        let oram_dir = temp_dir("oram_auth_img");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&oram_dir).unwrap();

        let bins_per_table = 16usize;
        let chunk_path = db_dir.join(CuckooLevel::Chunk.filename());
        write_subtable_file(&chunk_path, &CHUNK_PARAMS, bins_per_table);
        let pack = 4usize;
        build_test_oram_image(&db_dir, &oram_dir, CuckooLevel::Chunk, pack);
        build_test_oram_auth_store(&oram_dir, CuckooLevel::Chunk, 2);

        let group_id = 3usize;
        let indices = [0u32, 5, (bins_per_table - 1) as u32];
        let direct_table = CuckooTableInfo::from_file(
            CuckooLevel::Chunk,
            db_dir.join(CuckooLevel::Chunk.filename()),
        )
        .unwrap();
        let mut direct_reader = CuckooPackedBlockReader::open(direct_table, pack).unwrap();
        let mut expected = Vec::new();
        for idx in indices {
            expected.extend_from_slice(
                &direct_reader
                    .read_bin(group_id * bins_per_table + idx as usize)
                    .unwrap(),
            );
        }

        {
            let access = CuckooOramTable::open(
                &db_dir,
                &oram_dir,
                CuckooLevel::Chunk,
                pack,
                2,
                false,
                None,
                None,
                0,
                true,
                true,
            )
            .unwrap();
            let mut via_oram = Vec::new();
            access
                .append_entries(group_id, &indices, false, &mut via_oram)
                .unwrap();
            access.finish_request().unwrap();
            assert_eq!(via_oram, expected);
        }

        {
            let reopened = CuckooOramTable::open(
                &db_dir,
                &oram_dir,
                CuckooLevel::Chunk,
                pack,
                2,
                false,
                None,
                None,
                0,
                true,
                true,
            )
            .unwrap();
            let mut via_oram = Vec::new();
            reopened
                .append_entries(group_id, &indices, false, &mut via_oram)
                .unwrap();
            reopened.finish_request().unwrap();
            assert_eq!(via_oram, expected);
        }

        std::fs::remove_dir_all(&db_dir).ok();
        std::fs::remove_dir_all(&oram_dir).ok();
    }

    #[cfg(feature = "cuckoo-oram")]
    #[test]
    fn legacy_oram_same_db_requests_serialize_complete_state_commits() {
        use std::sync::{mpsc, Arc};
        use std::time::Duration;

        let db_dir = temp_dir("legacy_lookup_serial_db");
        let oram_dir = temp_dir("legacy_lookup_serial_img");
        std::fs::create_dir_all(&oram_dir).unwrap();
        let fixture = write_lookup_db_files(&db_dir);
        let db = load_lookup_db(&db_dir);
        let config = CuckooNativeLookupConfig::from_db(&db);

        let pack = 4usize;
        build_test_oram_image(&db_dir, &oram_dir, CuckooLevel::Index, pack);
        build_test_oram_image(&db_dir, &oram_dir, CuckooLevel::Chunk, pack);
        build_test_oram_auth_store(&oram_dir, CuckooLevel::Index, 2);
        build_test_oram_auth_store(&oram_dir, CuckooLevel::Chunk, 2);

        let tables = Arc::new(
            CuckooOramTables::open(
                &db_dir, &oram_dir, pack, 2, false, None, None, 0, true, true,
            )
            .unwrap(),
        );

        let gate = tables.request_transaction.lock().unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let mut workers = Vec::new();
        for _ in 0..2 {
            let tables = Arc::clone(&tables);
            let ready_tx = ready_tx.clone();
            let done_tx = done_tx.clone();
            let script_hash = fixture.found_sh;
            workers.push(std::thread::spawn(move || {
                ready_tx.send(()).unwrap();
                done_tx
                    .send(tables.lookup_batch(config, &[script_hash]))
                    .unwrap();
            }));
        }
        drop(ready_tx);
        drop(done_tx);
        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(
            done_rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));

        drop(gate);
        for _ in 0..2 {
            let got = done_rx
                .recv_timeout(Duration::from_secs(15))
                .expect("serialized legacy ORAM request did not finish")
                .expect("serialized legacy ORAM request failed");
            assert_eq!(got.len(), 1);
            assert!(got[0].found);
        }
        for worker in workers {
            worker.join().unwrap();
        }

        tables.index.check_not_poisoned().unwrap();
        tables.chunk.check_not_poisoned().unwrap();
        for name in [
            "index.state.tmp",
            "index.auth.state.tmp",
            "chunk.state.tmp",
            "chunk.auth.state.tmp",
        ] {
            assert!(
                !oram_dir.join(name).exists(),
                "serialized legacy save left temporary file {name}"
            );
        }

        drop(tables);
        let reopened = CuckooOramTables::open(
            &db_dir, &oram_dir, pack, 2, false, None, None, 0, true, true,
        )
        .unwrap();
        let got = reopened.lookup_batch(config, &[fixture.found_sh]).unwrap();
        assert!(got[0].found);

        std::fs::remove_dir_all(&db_dir).ok();
        std::fs::remove_dir_all(&oram_dir).ok();
    }

    #[cfg(feature = "cuckoo-oram")]
    #[test]
    fn native_lookup_oram_matches_mmap_lookup() {
        let db_dir = temp_dir("lookup_oram_db");
        let oram_dir = temp_dir("lookup_oram_img");
        std::fs::create_dir_all(&oram_dir).unwrap();
        let fixture = write_lookup_db_files(&db_dir);
        let db = load_lookup_db(&db_dir);
        let script_hashes = [fixture.found_sh, fixture.missing_sh, fixture.whale_sh];
        let pack = 4usize;
        build_test_oram_image(&db_dir, &oram_dir, CuckooLevel::Index, pack);
        build_test_oram_image(&db_dir, &oram_dir, CuckooLevel::Chunk, pack);

        let mmap_index = MmapCuckooTable::new(&db.index, db.index.params.bin_size());
        let mmap_chunk = MmapCuckooTable::new(&db.chunk, db.chunk.params.bin_size());
        let expected = cuckoo_native_lookup_batch_from_tables_with_dummy(
            &mmap_index,
            &mmap_chunk,
            CuckooNativeLookupConfig::from_db(&db),
            &script_hashes,
            deterministic_dummy(2_000),
        )
        .unwrap();

        let oram_tables = CuckooOramTables::open(
            &db_dir, &oram_dir, pack, 2, false, None, None, 0, false, true,
        )
        .unwrap();
        let actual = cuckoo_native_lookup_batch_from_tables_with_dummy(
            &oram_tables.index,
            &oram_tables.chunk,
            CuckooNativeLookupConfig::from_db(&db),
            &script_hashes,
            deterministic_dummy(2_000),
        )
        .unwrap();

        assert_eq!(actual, expected);

        std::fs::remove_dir_all(&db_dir).ok();
        std::fs::remove_dir_all(&oram_dir).ok();
    }

    // ─── S4: wire group_id slices the mmap ──────────────────────────────

    #[test]
    fn single_query_group_id_out_of_range_returns_error() {
        // k = 75 for INDEX; group_id 250 previously sliced ~175 groups
        // past the mmap end → panic → abort.
        let db = make_db();
        let q = HarmonyQuery {
            level: 0,
            group_id: 250,
            round_id: 0,
            indices: vec![0],
            db_id: 0,
        };
        expect_error(harmony_query_response(&db, &q), "out of range");
    }

    #[test]
    fn batch_query_group_id_out_of_range_returns_error() {
        let db = make_db();
        let q = HarmonyBatchQuery {
            level: 1,
            round_id: 7,
            sub_queries_per_group: 1,
            items: vec![HarmonyBatchItem {
                group_id: 250,
                sub_queries: vec![vec![0]],
            }],
            db_id: 0,
        };
        expect_error(harmony_batch_response(&db, &q), "out of range");
    }

    #[test]
    fn batch_query_unknown_level_returns_error() {
        // Sibling levels that don't exist for this DB (INDEX sib L1,
        // any CHUNK sib) and junk levels all map to a clean error.
        let db = make_db();
        for level in [2u8, 11, 19, 20, 29, 42, 255] {
            let q = HarmonyBatchQuery {
                level,
                round_id: 0,
                sub_queries_per_group: 1,
                items: vec![HarmonyBatchItem {
                    group_id: 0,
                    sub_queries: vec![vec![0]],
                }],
                db_id: 0,
            };
            expect_error(harmony_batch_response(&db, &q), "invalid level");
        }
    }

    // ─── S5: index count drives the pre-allocation ───────────────────────

    #[test]
    fn single_query_too_many_indices_returns_error() {
        // A legitimate query sends T − 1 < bins_per_table indices; an
        // attacker-sized list previously reserved len × entry_size
        // bytes before any range check ran.
        let db = make_db();
        let q = HarmonyQuery {
            level: 0,
            group_id: 0,
            round_id: 0,
            indices: vec![0; TEST_BINS + 1],
            db_id: 0,
        };
        expect_error(harmony_query_response(&db, &q), "too many indices");
    }

    #[test]
    fn batch_query_too_many_indices_returns_error() {
        let db = make_db();
        let q = HarmonyBatchQuery {
            level: 0,
            round_id: 0,
            sub_queries_per_group: 1,
            items: vec![HarmonyBatchItem {
                group_id: 0,
                sub_queries: vec![vec![0; TEST_BINS + 1]],
            }],
            db_id: 0,
        };
        expect_error(harmony_batch_response(&db, &q), "too many indices");
    }

    // ─── Happy paths: legitimate traffic is byte-identical ───────────────

    #[test]
    fn single_query_returns_requested_bins() {
        let db = make_db();
        let bin_size = db.index.params.bin_size();
        let q = HarmonyQuery {
            level: 0,
            group_id: 3,
            round_id: 9,
            indices: vec![0, 5, 7],
            db_id: 0,
        };
        match harmony_query_response(&db, &q) {
            Response::HarmonyQueryResult(r) => {
                assert_eq!(r.group_id, 3);
                assert_eq!(r.round_id, 9);
                assert_eq!(r.data.len(), 3 * bin_size);
                for (i, &bin) in [0u8, 5, 7].iter().enumerate() {
                    let expect = 3u8 ^ bin;
                    assert!(
                        r.data[i * bin_size..(i + 1) * bin_size]
                            .iter()
                            .all(|&b| b == expect),
                        "bin {} contents wrong",
                        bin
                    );
                }
            }
            other => panic!("expected HarmonyQueryResult, got {:?}", other),
        }
    }

    #[test]
    fn single_query_index_out_of_range_returns_error() {
        // Pre-existing behavior of the single-query path: an
        // out-of-range index *value* is an error (the batch path
        // zero-fills instead).
        let db = make_db();
        let q = HarmonyQuery {
            level: 0,
            group_id: 0,
            round_id: 0,
            indices: vec![TEST_BINS as u32],
            db_id: 0,
        };
        expect_error(harmony_query_response(&db, &q), "out of range");
    }

    #[test]
    fn batch_query_serves_main_and_sibling_levels_and_zero_fills() {
        let db = make_db();
        // level 10 = INDEX sibling L0 — exists in make_db.
        for level in [0u8, 1, 10] {
            let (sub_table, bin_size, _) = harmony_level_table(&db, level).unwrap();
            assert_eq!(sub_table.bins_per_table, TEST_BINS);
            let q = HarmonyBatchQuery {
                level,
                round_id: 4,
                sub_queries_per_group: 1,
                // One in-range index and one out-of-range *value*
                // (zero-filled — pre-existing wire behavior).
                items: vec![HarmonyBatchItem {
                    group_id: 2,
                    sub_queries: vec![vec![1, TEST_BINS as u32]],
                }],
                db_id: 0,
            };
            match harmony_batch_response(&db, &q) {
                Response::HarmonyBatchResult(r) => {
                    assert_eq!(r.level, level);
                    assert_eq!(r.items.len(), 1);
                    let data = &r.items[0].sub_results[0];
                    assert_eq!(data.len(), 2 * bin_size);
                    assert!(data[..bin_size].iter().all(|&b| b == 2u8 ^ 1u8));
                    assert!(data[bin_size..].iter().all(|&b| b == 0));
                }
                other => panic!(
                    "level {}: expected HarmonyBatchResult, got {:?}",
                    level, other
                ),
            }
        }
    }

    // ─── REQ_HARMONY_HINTS pre-validation + total hint computation ──────

    #[test]
    fn hints_validation_rejects_bad_level_group_and_count() {
        let db = make_db();
        // Unknown levels (11 = INDEX sib L1 doesn't exist, 20 = no
        // CHUNK sibs at all).
        for level in [2u8, 11, 20, 42] {
            assert!(validate_harmony_hints_request(&db, level, &[0]).is_err());
        }
        // group_id ≥ k (k = 75 for INDEX).
        assert!(validate_harmony_hints_request(&db, 0, &[0, 74]).is_ok());
        assert!(validate_harmony_hints_request(&db, 0, &[75]).is_err());
        assert!(validate_harmony_hints_request(&db, 0, &[250]).is_err());
        // More group_ids than groups (duplicate-amplification cap).
        let too_many = vec![0u8; INDEX_PARAMS.k + 1];
        assert!(validate_harmony_hints_request(&db, 0, &too_many).is_err());
        // The full legitimate sweep 0..k is accepted for every level
        // that exists.
        for (level, k) in [
            (0u8, INDEX_PARAMS.k),
            (1, CHUNK_PARAMS.k),
            (10, INDEX_PARAMS.k),
        ] {
            let all: Vec<u8> = (0..k as u8).collect();
            assert!(validate_harmony_hints_request(&db, level, &all).is_ok());
        }
    }

    #[test]
    fn compute_hints_invalid_level_returns_err_not_panic() {
        // Previously `panic!("invalid hint level {}")` inside the rayon
        // pool → abort.
        let db = make_db();
        let key = [7u8; 16];
        let backend = hint_pool::default_prp_backend();
        assert!(compute_hints_for_group(&db, &key, backend, 42, 0).is_err());
        assert!(compute_hints_for_group(&db, &key, backend, 11, 0).is_err());
    }

    #[test]
    fn compute_hints_group_out_of_range_returns_err_not_panic() {
        // Previously sliced the mmap at group 250 of 75 → panic → abort.
        let db = make_db();
        let key = [7u8; 16];
        assert!(
            compute_hints_for_group(&db, &key, hint_pool::default_prp_backend(), 0, 250).is_err()
        );
    }

    #[test]
    fn compute_hints_happy_path_still_serves() {
        let db = make_db();
        let key = [7u8; 16];
        let (group_id, n, t, m, flat) =
            compute_hints_for_group(&db, &key, hint_pool::default_prp_backend(), 0, 3)
                .expect("legitimate hint request must still be served");
        assert_eq!(group_id, 3);
        assert!(n as usize >= TEST_BINS);
        assert!(t > 0 && m > 0);
        assert_eq!(flat.len(), m as usize * db.index.params.bin_size());
    }

    #[test]
    fn compute_hints_unsupported_backend_returns_err() {
        let db = make_db();
        let error = compute_hints_for_group(&db, &[7u8; 16], 0xfe, 0, 3).unwrap_err();
        assert!(error.contains("unsupported"));
    }

    #[test]
    fn v2_hint_pool_rejects_a_different_database_id() {
        assert!(validate_harmony_v2_pool_database(0, 0).is_ok());
        assert!(validate_harmony_v2_pool_database(7, 7).is_ok());
        let error = validate_harmony_v2_pool_database(0, 1).unwrap_err();
        assert!(error.contains("bound to db 0"));
        assert!(error.contains("requested db 1"));
    }

    #[test]
    fn only_v2_full_hint_operations_reserve_their_exact_database_pool() {
        let full = OperationStartV1::HarmonyHint {
            db_id: 7,
            transport: pir_service_protocol::HintTransport::V2Full,
            session_token: None,
            primary_side: None,
        };
        assert_eq!(harmony_v2_full_reservation_db_v1(&full), Some(7));

        let half = OperationStartV1::HarmonyHint {
            db_id: 7,
            transport: pir_service_protocol::HintTransport::V2Half,
            session_token: Some([3; 16]),
            primary_side: Some(pir_service_protocol::HarmonyHintSideV1::Index),
        };
        assert_eq!(harmony_v2_full_reservation_db_v1(&half), None);
        assert_eq!(
            harmony_v2_full_reservation_db_v1(&OperationStartV1::HarmonyQuery { db_id: 7 }),
            None
        );
    }

    #[test]
    fn v2_full_durable_consume_occurs_only_at_first_main_dispatch() {
        let source = include_str!("unified_server.rs");
        let auth = source
            .split_once("REQ_AUTH_BEGIN_V1 =>")
            .unwrap()
            .1
            .split_once("REQ_POW_CHALLENGE_V1 =>")
            .unwrap()
            .0;
        assert!(auth.contains("reserved_harmony_v2_full ="));
        assert!(
            !auth.contains(".commit_consume()"),
            "grant creation/delivery loss must return an unexposed hint"
        );

        let dispatch = source
            .split_once("// V2: server generates PRP key, serves pre-computed frames from pool.")
            .unwrap()
            .1
            .split_once("REQ_HARMONY_HINTS_V2_HALF =>")
            .unwrap()
            .0;
        assert!(dispatch.contains(".commit_consume()"));
        assert!(
            dispatch.find("commit_consume()").unwrap()
                < dispatch.find("entry.key_preamble.clone()").unwrap(),
            "durable unlink+fsync must precede PRP key exposure"
        );
    }
}
