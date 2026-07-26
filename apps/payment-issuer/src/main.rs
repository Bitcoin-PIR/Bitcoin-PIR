//! BitcoinPIR payment issuer executable.
//!
//! Both serving modes bind only to loopback. `serve-fake` is a deterministic
//! integration harness; `serve-cln` uses a locally owned Core Lightning Unix
//! RPC socket and is intended to sit behind a separately managed TLS edge.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand, ValueEnum};
use ed25519_dalek::{SigningKey, VerifyingKey};
use pir_arc_adapter::{
    ArcIssuanceCanonicalizerV1, ArcSecretKeyV1, ArcSecretKeyringV1, ARC_SECRET_KEY_LEN_V1,
};
use pir_issuer_clearing::RedeemResponseDerivationKeyV1;
use pir_issuer_core::{QuoteIdSourceErrorV1, QuoteIdSourceV1};
use pir_issuer_credentials::IssuerCredentialDerivationKeyV1;
use pir_issuer_service::{
    ensure_shared_clearing_binding_material_v1, IssuerAcquisitionServiceV1, IssuerServiceErrorV1,
    QuoteSigningMaterialV1, ReceiptSigningMaterialV1, SharedIssuerClearingServiceV1,
    TrustedClearingProviderV1,
};
use pir_issuer_store::{
    BatKeyLineageRegistration, IssuerStore, ProviderSettlementRegistrationWriteV1, QuoteCapacityV1,
    SqliteIssuerRollbackFloorAuthorityV1, StoreOptions, MAX_EXACT_CLEARING_APPROVAL_BYTES,
    MAX_EXACT_CLEARING_AUTHORIZATION_BYTES, MAX_QUOTE_RECONCILIATION_BATCH_V1,
    SCHEMA_VERSION as ISSUER_STORE_SCHEMA_VERSION,
};
#[cfg(unix)]
use pir_lightning_backend::{
    CoreLightningBackendV1, UnixClnRpcSocketPolicyV1, UnixClnRpcTransportV1,
};
use pir_lightning_backend::{
    CreateInvoiceRequestV1, CreatedInvoiceV1, FakeLightningNodeV1, InvoiceObservationV1,
    LightningBackendErrorV1, LightningInvoiceBackendV1,
};
use pir_payment_crypto::K256CashuMintKeyringV1;
use pir_service_protocol::{
    AuthScheme, Bolt11QuoteClaimEnvelopeV1, Bolt11QuoteIntentV1, Bolt11QuoteKeyDelegationV1,
    IssuerClearingApprovalV1, LightningNetworkV1, ProviderClearingAuthorizationV1,
    ProviderRedeemEnvelopeV1, ServicePolicyV1, SettlementModesV1, SettlementUnitV1,
    MAX_BOLT11_QUOTE_CLAIM_ENVELOPE_LEN_V1, MAX_BOLT11_QUOTE_INTENT_LEN,
    MAX_BOLT11_QUOTE_KEY_DELEGATION_LEN, MAX_BOLT11_QUOTE_STATUS_REQUEST_LEN,
    MAX_CREDENTIAL_ISSUANCE_RESPONSE_LEN_V1, MAX_PROVIDER_REDEEM_ENVELOPE_LEN_V1,
};
use zeroize::{Zeroize, Zeroizing};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_HTTP_BODY_BYTES: usize = MAX_BOLT11_QUOTE_CLAIM_ENVELOPE_LEN_V1;
const MAX_HTTP_RESPONSE_BYTES: usize = MAX_CREDENTIAL_ISSUANCE_RESPONSE_LEN_V1;
const DEFAULT_MAX_CONNECTIONS: usize = 64;
const DEFAULT_MAX_OUTSTANDING_QUOTES: u64 = 256;
const DEFAULT_MAX_TOTAL_QUOTES: u64 = 100_000;
const DEFAULT_QUOTE_RATE_PER_MINUTE: u32 = 60;
const DEFAULT_STATUS_RATE_PER_MINUTE: u32 = 600;
const DEFAULT_MUTATION_RATE_PER_MINUTE: u32 = 120;
const DEFAULT_RECONCILIATION_RATE_PER_MINUTE: u32 = 120;
const DEFAULT_RECONCILIATION_BATCH_SIZE: u32 = 16;
const DEFAULT_RECONCILIATION_INTERVAL_SECONDS: u64 = 5;
const DEFAULT_RECONCILIATION_TICK_BUDGET_MS: u64 = 5_000;
const MAX_CONFIGURED_RATE_PER_MINUTE: u32 = 60_000;
const IO_TIMEOUT: Duration = Duration::from_secs(10);

const CT_QUOTE_INTENT: &str = "application/vnd.bitcoinpir.bolt11-quote-intent-v1";
const CT_QUOTE: &str = "application/vnd.bitcoinpir.bolt11-quote-v1";
const CT_QUOTE_KEY_DELEGATION: &str = "application/vnd.bitcoinpir.bolt11-quote-key-delegation-v1";
const CT_STATUS_REQUEST: &str = "application/vnd.bitcoinpir.bolt11-quote-status-request-v1";
const CT_CLAIM_ENVELOPE: &str = "application/vnd.bitcoinpir.bolt11-quote-claim-envelope-v1";
const CT_ISSUANCE_RESPONSE: &str = "application/vnd.bitcoinpir.credential-issuance-response-v1";
const CT_REDEEM: &str = "application/vnd.bitcoinpir.redeem-v1";
const CT_REDEEM_RESULT: &str = "application/vnd.bitcoinpir.redeem-result-v1";
const CT_FAKE_SETTLEMENT: &str = "application/vnd.bitcoinpir.fake-settlement-v1";

#[derive(Parser, Debug)]
#[command(name = "payment-issuer", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create a fresh issuer store and its separate rollback authority.
    InitStore(InitStoreArgs),
    /// Run the local-only fake-Lightning HTTP integration service.
    ServeFake(ServeFakeArgs),
    /// Run the loopback HTTP service backed by a local Core Lightning node.
    #[cfg(unix)]
    ServeCln(ServeClnArgs),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum NetworkArg {
    Bitcoin,
    Testnet,
    Signet,
    Regtest,
}

impl From<NetworkArg> for LightningNetworkV1 {
    fn from(value: NetworkArg) -> Self {
        match value {
            NetworkArg::Bitcoin => Self::Bitcoin,
            NetworkArg::Testnet => Self::Testnet,
            NetworkArg::Signet => Self::Signet,
            NetworkArg::Regtest => Self::Regtest,
        }
    }
}

#[derive(Args, Debug)]
struct InitStoreArgs {
    #[arg(long)]
    store: PathBuf,
    #[arg(long)]
    rollback_authority: PathBuf,
    #[arg(long)]
    issuer_id_hex: String,
    #[arg(long, value_enum)]
    network: NetworkArg,
}

#[derive(Args, Debug)]
struct ServeCommonArgs {
    #[arg(long, default_value = "127.0.0.1:5610")]
    bind: SocketAddr,
    #[arg(long, default_value_t = DEFAULT_MAX_CONNECTIONS)]
    max_connections: usize,
    /// Process-wide new-invoice rate. Only a canonical request whose exact
    /// digest matches the durable intent bypasses this limiter.
    #[arg(long, default_value_t = DEFAULT_QUOTE_RATE_PER_MINUTE)]
    quote_rate_per_minute: u32,
    /// Process-wide budget for authenticated status polling. This bounds the
    /// durable nonce/CAS work while remaining separate from mutation traffic.
    #[arg(long, default_value_t = DEFAULT_STATUS_RATE_PER_MINUTE)]
    status_rate_per_minute: u32,
    /// Process-wide budget shared by claim and provider-redeem mutations.
    #[arg(long, default_value_t = DEFAULT_MUTATION_RATE_PER_MINUTE)]
    mutation_rate_per_minute: u32,
    /// Process-wide backend reconciliation observations per minute.
    #[arg(long, default_value_t = DEFAULT_RECONCILIATION_RATE_PER_MINUTE)]
    reconciliation_rate_per_minute: u32,
    #[arg(long, default_value_t = DEFAULT_RECONCILIATION_BATCH_SIZE)]
    reconciliation_batch_size: u32,
    #[arg(long, default_value_t = DEFAULT_RECONCILIATION_INTERVAL_SECONDS)]
    reconciliation_interval_seconds: u64,
    /// Soft per-tick scheduler budget. One already-started backend RPC may run
    /// until its independently bounded socket timeout.
    #[arg(long, default_value_t = DEFAULT_RECONCILIATION_TICK_BUDGET_MS)]
    reconciliation_tick_budget_ms: u64,
    #[arg(long, default_value_t = DEFAULT_MAX_OUTSTANDING_QUOTES)]
    max_outstanding_quotes: u64,
    /// Maximum active quote workflows. Open and expired-pending-reconcile
    /// quotes count through their immutable recovery horizon. Paid, claimed,
    /// horizon-expired, and bounded failed reservations remain durably
    /// auditable but release this capacity.
    #[arg(long, default_value_t = DEFAULT_MAX_TOTAL_QUOTES)]
    max_total_quotes: u64,
    #[arg(long)]
    allow_origin: Option<String>,
    #[arg(long)]
    store: PathBuf,
    #[arg(long)]
    rollback_authority: PathBuf,
    #[arg(long)]
    quote_delegation: PathBuf,
    #[arg(long)]
    quote_signing_key: PathBuf,
    /// Repeat `<delegation-path>=<signing-key-path>` for exact recovery of
    /// quotes created before the current quote-key rotation.
    #[arg(long = "retained-quote-material")]
    retained_quote_materials: Vec<String>,
    #[arg(long)]
    credential_derivation_key: PathBuf,
    /// Repeat `<signed-policy-path>=<ed25519-policy-public-key-hex>`.
    #[arg(long = "service-policy")]
    service_policies: Vec<String>,
    /// Repeat for every retained direct-receipt Ed25519 signing key.
    #[arg(long = "receipt-signing-key")]
    receipt_signing_keys: Vec<PathBuf>,
    /// Repeat for every retained BitcoinPIR Cashu BAT scalar.
    #[arg(long = "bat-key")]
    bat_keys: Vec<PathBuf>,
    /// Repeat `<credential-key-id-hex>=<raw-128-byte-arc-key-path>`.
    #[arg(long = "arc-key")]
    arc_keys: Vec<String>,
    /// Repeat one canonical operator-signed provider clearing authorization.
    #[arg(long = "clearing-authorization")]
    clearing_authorizations: Vec<PathBuf>,
    /// Repeat one matching issuer approval, in the same order as authorization.
    #[arg(long = "clearing-approval")]
    clearing_approvals: Vec<PathBuf>,
    /// Repeat `<provider-id-hex>=<issuer-local-payout-target-id-hex>`.
    #[arg(long = "clearing-payout-target")]
    clearing_payout_targets: Vec<String>,
    /// Issuer Ed25519 settlement signing key; required when clearing is enabled.
    #[arg(long)]
    issuer_settlement_signing_key: Option<PathBuf>,
    /// Independent deterministic redeem-response derivation key.
    #[arg(long)]
    redeem_response_derivation_key: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct ServeFakeArgs {
    #[command(flatten)]
    common: ServeCommonArgs,
    #[arg(long)]
    fake_lightning_signing_key: PathBuf,
    #[arg(long)]
    fake_lightning_derivation_seed: PathBuf,
}

#[cfg(unix)]
#[derive(Args, Debug)]
struct ServeClnArgs {
    #[command(flatten)]
    common: ServeCommonArgs,
    /// Absolute path to Core Lightning's local JSON-RPC Unix socket.
    #[arg(long)]
    cln_rpc_socket: PathBuf,
    /// Effective UID that must own the Core Lightning RPC socket.
    #[arg(long)]
    cln_rpc_expected_uid: u32,
    /// Optional exact group owner. When omitted, the socket must be owner-only.
    #[arg(long)]
    cln_rpc_expected_gid: Option<u32>,
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..=30))]
    cln_rpc_timeout_seconds: u64,
}

#[derive(Debug, Default)]
struct OsQuoteIdSourceV1;

impl QuoteIdSourceV1 for OsQuoteIdSourceV1 {
    fn next_quote_id(&self) -> Result<[u8; 32], QuoteIdSourceErrorV1> {
        for _ in 0..8 {
            let mut value = [0u8; 32];
            getrandom::getrandom(&mut value).map_err(|_| QuoteIdSourceErrorV1::Unavailable)?;
            if value.iter().any(|byte| *byte != 0) {
                return Ok(value);
            }
        }
        Err(QuoteIdSourceErrorV1::Exhausted)
    }
}

enum RuntimeLightningBackendV1 {
    Fake(Arc<FakeLightningNodeV1>),
    #[cfg(unix)]
    CoreLightning(CoreLightningBackendV1<UnixClnRpcTransportV1>),
}

impl core::fmt::Debug for RuntimeLightningBackendV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RuntimeLightningBackendV1")
            .field("mode", &self.mode_name())
            .field("backend", &"[redacted]")
            .finish()
    }
}

impl RuntimeLightningBackendV1 {
    const fn mode_name(&self) -> &'static str {
        match self {
            Self::Fake(_) => "fake",
            #[cfg(unix)]
            Self::CoreLightning(_) => "cln",
        }
    }
}

impl LightningInvoiceBackendV1 for RuntimeLightningBackendV1 {
    fn create_or_get_invoice(
        &self,
        request: &CreateInvoiceRequestV1,
    ) -> Result<CreatedInvoiceV1, LightningBackendErrorV1> {
        match self {
            Self::Fake(backend) => backend.create_or_get_invoice(request),
            #[cfg(unix)]
            Self::CoreLightning(backend) => backend.create_or_get_invoice(request),
        }
    }

    fn lookup_invoice(
        &self,
        backend_label: &str,
        observed_at: u64,
    ) -> Result<InvoiceObservationV1, LightningBackendErrorV1> {
        match self {
            Self::Fake(backend) => backend.lookup_invoice(backend_label, observed_at),
            #[cfg(unix)]
            Self::CoreLightning(backend) => backend.lookup_invoice(backend_label, observed_at),
        }
    }

    fn existing_invoice(
        &self,
        backend_label: &str,
    ) -> Result<Option<CreatedInvoiceV1>, LightningBackendErrorV1> {
        match self {
            Self::Fake(backend) => backend.existing_invoice(backend_label),
            #[cfg(unix)]
            Self::CoreLightning(backend) => backend.existing_invoice(backend_label),
        }
    }
}

type AcquisitionService = IssuerAcquisitionServiceV1<RuntimeLightningBackendV1, OsQuoteIdSourceV1>;

struct ServerState {
    acquisition: AcquisitionService,
    current_quote_delegation: Vec<u8>,
    quote_delegations: BTreeMap<[u8; 16], Vec<u8>>,
    clearing: Option<SharedIssuerClearingServiceV1>,
    store: IssuerStore,
    fake_lightning: Option<Arc<FakeLightningNodeV1>>,
    allow_origin: Option<String>,
    quote_rate: FixedWindowRateLimiterV1,
    status_rate: FixedWindowRateLimiterV1,
    mutation_rate: FixedWindowRateLimiterV1,
}

impl core::fmt::Debug for ServerState {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ServerState")
            .field("acquisition", &"[redacted]")
            .field("quote_delegation_count", &self.quote_delegations.len())
            .field("clearing", &self.clearing.is_some())
            .field("store", &"[redacted]")
            .field("fake_settlement_route", &self.fake_lightning.is_some())
            .field("allow_origin", &self.allow_origin)
            .field("quote_rate", &self.quote_rate)
            .field("status_rate", &self.status_rate)
            .field("mutation_rate", &self.mutation_rate)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct FixedWindowRateLimiterV1 {
    per_minute: u32,
    window: Mutex<QuoteRateWindowV1>,
}

#[derive(Debug)]
struct QuoteRateWindowV1 {
    started: Instant,
    used: u32,
}

struct ReconciliationWorkerConfigV1 {
    interval: Duration,
    batch_size: u32,
    tick_budget: Duration,
    rate: FixedWindowRateLimiterV1,
}

#[derive(Default)]
struct ReconciliationTickTotalsV1 {
    examined: u32,
    transitioned: u32,
    unchanged: u32,
    retryable_failures: u32,
    permanent_failures: u32,
    service_failures: u32,
}

fn spawn_reconciliation_worker(
    state: Arc<ServerState>,
    config: ReconciliationWorkerConfigV1,
) -> Result<(), String> {
    thread::Builder::new()
        .name("issuer-reconciliation-v1".to_owned())
        .spawn(move || {
            let mut cursor = None;
            loop {
                let tick_started = Instant::now();
                let mut totals = ReconciliationTickTotalsV1::default();
                while totals.examined < config.batch_size
                    && tick_started.elapsed() < config.tick_budget
                    && config.rate.try_acquire(Instant::now())
                {
                    let now_unix = match system_time_unix() {
                        Ok(now) => now,
                        Err(_) => {
                            totals.service_failures = totals.service_failures.saturating_add(1);
                            break;
                        }
                    };
                    match state
                        .acquisition
                        .reconcile_quote_batch(cursor.as_ref(), 1, now_unix)
                    {
                        Ok(report) if report.examined == 0 => {
                            cursor = None;
                            break;
                        }
                        Ok(report) => {
                            cursor = report.next_cursor();
                            totals.examined = totals.examined.saturating_add(report.examined);
                            totals.transitioned =
                                totals.transitioned.saturating_add(report.transitioned);
                            totals.unchanged = totals.unchanged.saturating_add(report.unchanged);
                            totals.retryable_failures = totals
                                .retryable_failures
                                .saturating_add(report.retryable_failures);
                            totals.permanent_failures = totals
                                .permanent_failures
                                .saturating_add(report.permanent_failures);
                        }
                        Err(_) => {
                            totals.service_failures = totals.service_failures.saturating_add(1);
                            break;
                        }
                    }
                }
                if totals.transitioned != 0
                    || totals.retryable_failures != 0
                    || totals.permanent_failures != 0
                    || totals.service_failures != 0
                {
                    eprintln!(
                        "payment-issuer reconciliation: examined={} transitioned={} unchanged={} retryable_failures={} permanent_failures={} service_failures={}",
                        totals.examined,
                        totals.transitioned,
                        totals.unchanged,
                        totals.retryable_failures,
                        totals.permanent_failures,
                        totals.service_failures,
                    );
                }
                thread::sleep(config.interval);
            }
        })
        .map(|_| ())
        .map_err(|error| format!("spawn reconciliation worker failed: {error}"))
}

impl FixedWindowRateLimiterV1 {
    fn new(per_minute: u32, option_name: &'static str) -> Result<Self, String> {
        if per_minute == 0 || per_minute > MAX_CONFIGURED_RATE_PER_MINUTE {
            return Err(format!(
                "{option_name} must be in 1..={MAX_CONFIGURED_RATE_PER_MINUTE}"
            ));
        }
        Ok(Self {
            per_minute,
            window: Mutex::new(QuoteRateWindowV1 {
                started: Instant::now(),
                used: 0,
            }),
        })
    }

    fn try_acquire(&self, now: Instant) -> bool {
        let Ok(mut window) = self.window.lock() else {
            return false;
        };
        if now.duration_since(window.started) >= Duration::from_secs(60) {
            window.started = now;
            window.used = 0;
        }
        if window.used >= self.per_minute {
            return false;
        }
        window.used += 1;
        true
    }
}

fn exact_intent_replay(stored_intent_digest: Option<[u8; 32]>, request_digest: [u8; 32]) -> bool {
    stored_intent_digest == Some(request_digest)
}

fn validate_loopback_bind(bind: SocketAddr) -> Result<(), String> {
    if bind.ip().is_loopback() {
        Ok(())
    } else {
        Err("issuer serving modes refuse every non-loopback bind address".to_owned())
    }
}

fn require_fake_settlement_backend(
    fake_lightning: Option<&Arc<FakeLightningNodeV1>>,
) -> Result<&Arc<FakeLightningNodeV1>, IssuerServiceErrorV1> {
    fake_lightning.ok_or(IssuerServiceErrorV1::NotFound)
}

/// A claim may bypass the mutation budget only when its raw idempotency key
/// resolves to a durable record and both exact request digests still match.
/// The service repeats this check and authenticates the signed request before
/// returning the stored response.
fn is_exact_claim_replay(
    store: &IssuerStore,
    route_quote_id: &[u8; 32],
    canonical_envelope: &[u8],
) -> bool {
    let arc_codec = ArcIssuanceCanonicalizerV1;
    let Ok(envelope) = Bolt11QuoteClaimEnvelopeV1::decode(canonical_envelope, Some(&arc_codec))
    else {
        return false;
    };
    if &envelope.claim.quote_id != route_quote_id {
        return false;
    }
    let Ok(Some(existing)) = store.claim_by_idempotency_key(&envelope.claim.idempotency_key) else {
        return false;
    };
    let Ok(claim_digest) = envelope.claim.claim_request_digest() else {
        return false;
    };
    let Ok(exact_credential_request) = envelope.credential_request.encode() else {
        return false;
    };
    existing.quote_id == envelope.claim.quote_id
        && existing.claim_request_digest == claim_digest
        && existing.exact_credential_request == exact_credential_request
}

/// Shared-issuer redeem recovery is defined by the store's privacy-preserving
/// request replay image. The service still verifies the provider signature
/// and historical authorization before releasing the durable response.
fn is_exact_redeem_replay(store: &IssuerStore, canonical_envelope: &[u8]) -> bool {
    let Ok(envelope) = ProviderRedeemEnvelopeV1::decode(canonical_envelope) else {
        return false;
    };
    if envelope.encode().ok().as_deref() != Some(canonical_envelope) {
        return false;
    }
    store
        .redeem_by_idempotency(&envelope.request)
        .is_ok_and(|existing| existing.is_some())
}

fn main() {
    let result = match Cli::parse().command {
        Command::InitStore(args) => init_store(args),
        Command::ServeFake(args) => serve_fake(args),
        #[cfg(unix)]
        Command::ServeCln(args) => serve_cln(args),
    };
    if let Err(error) = result {
        eprintln!("payment-issuer: {error}");
        std::process::exit(1);
    }
}

fn init_store(args: InitStoreArgs) -> Result<(), String> {
    let issuer_id = decode_fixed_hex::<32>(&args.issuer_id_hex, "issuer ID")?;
    if issuer_id.iter().all(|byte| *byte == 0) {
        return Err("issuer ID must not be all zero".to_owned());
    }
    let mut store_instance_id = [0u8; 16];
    getrandom::getrandom(&mut store_instance_id)
        .map_err(|_| "operating-system randomness is unavailable".to_owned())?;
    if store_instance_id.iter().all(|byte| *byte == 0) {
        return Err("operating-system randomness returned an invalid store ID".to_owned());
    }
    let store_path = prepare_new_private_database_path(&args.store, "issuer store")?;
    let authority_path =
        prepare_new_private_database_path(&args.rollback_authority, "issuer rollback authority")?;
    if store_path == authority_path {
        return Err("store and rollback authority resolve to the same canonical target".to_owned());
    }
    if store_path.parent() == authority_path.parent() {
        eprintln!(
            "warning: issuer store and rollback authority share one private directory; use independent backup/restore domains in production"
        );
    }
    let options = StoreOptions::default();
    let authority = Arc::new(
        SqliteIssuerRollbackFloorAuthorityV1::create(&authority_path, options.busy_timeout)
            .map_err(|error| {
                incomplete_init_error_v1(
                    "create rollback authority",
                    &store_path,
                    &authority_path,
                    &error.to_string(),
                )
            })?,
    );
    set_owner_only_database_file_v1(&authority_path).map_err(|error| {
        incomplete_init_error_v1(
            "secure rollback authority permissions",
            &store_path,
            &authority_path,
            &error,
        )
    })?;
    validate_existing_private_database_path(&authority_path, "issuer rollback authority").map_err(
        |error| {
            incomplete_init_error_v1(
                "self-check rollback authority ownership/path",
                &store_path,
                &authority_path,
                &error,
            )
        },
    )?;
    let store = IssuerStore::create(
        &store_path,
        store_instance_id,
        issuer_id,
        args.network.into(),
        options,
        authority.clone(),
    )
    .map_err(|error| {
        incomplete_init_error_v1(
            "create issuer store",
            &store_path,
            &authority_path,
            &error.to_string(),
        )
    })?;
    set_owner_only_database_file_v1(&store_path).map_err(|error| {
        incomplete_init_error_v1(
            "secure issuer store permissions",
            &store_path,
            &authority_path,
            &error,
        )
    })?;
    validate_existing_private_database_path(&store_path, "issuer store").map_err(|error| {
        incomplete_init_error_v1(
            "self-check issuer store ownership/path",
            &store_path,
            &authority_path,
            &error,
        )
    })?;
    if private_database_paths_alias_v1(&store_path, &authority_path).map_err(|error| {
        incomplete_init_error_v1(
            "self-check store/authority aliases",
            &store_path,
            &authority_path,
            &error,
        )
    })? {
        return Err(incomplete_init_error_v1(
            "self-check store/authority aliases",
            &store_path,
            &authority_path,
            "store and rollback authority resolve to the same file/inode",
        ));
    }

    let identity = store.identity().map_err(|error| {
        incomplete_init_error_v1(
            "read back issuer store identity",
            &store_path,
            &authority_path,
            &error.to_string(),
        )
    })?;
    if identity.store_instance_id != store_instance_id
        || identity.issuer_id != issuer_id
        || identity.network != args.network.into()
        || identity.commit_seq != 0
        || identity.rollback_parent_commitment != [0; 32]
        || identity.status_time_floor != 0
        || identity.schema_version != ISSUER_STORE_SCHEMA_VERSION
    {
        return Err(incomplete_init_error_v1(
            "exact new-store identity self-check",
            &store_path,
            &authority_path,
            "new issuer store identity is not the expected generation-zero state",
        ));
    }
    drop(store);
    drop(authority);

    // Initialization succeeds only when the same production open-existing
    // path accepts both exact files after every creation handle is dropped.
    let reopened_authority = Arc::new(
        SqliteIssuerRollbackFloorAuthorityV1::open_existing(&authority_path, options.busy_timeout)
            .map_err(|error| {
                incomplete_init_error_v1(
                    "reopen rollback authority",
                    &store_path,
                    &authority_path,
                    &error.to_string(),
                )
            })?,
    );
    let reopened = IssuerStore::open_existing(
        &store_path,
        issuer_id,
        args.network.into(),
        options,
        reopened_authority,
    )
    .map_err(|error| {
        incomplete_init_error_v1(
            "reopen issuer store",
            &store_path,
            &authority_path,
            &error.to_string(),
        )
    })?;
    if reopened.identity().map_err(|error| {
        incomplete_init_error_v1(
            "read reopened issuer store identity",
            &store_path,
            &authority_path,
            &error.to_string(),
        )
    })? != identity
    {
        return Err(incomplete_init_error_v1(
            "reopened identity self-check",
            &store_path,
            &authority_path,
            "issuer store identity changed across reopen",
        ));
    }

    println!("issuer_id={}", hex::encode(issuer_id));
    println!("store_instance_id={}", hex::encode(store_instance_id));
    println!("schema_version={ISSUER_STORE_SCHEMA_VERSION}");
    println!("store={}", store_path.display());
    println!("rollback_authority={}", authority_path.display());
    Ok(())
}

enum BackendConfigV1 {
    Fake {
        signing_key: PathBuf,
        derivation_seed: PathBuf,
    },
    #[cfg(unix)]
    CoreLightning {
        socket_path: PathBuf,
        socket_policy: UnixClnRpcSocketPolicyV1,
        timeout: Duration,
    },
}

impl BackendConfigV1 {
    const fn mode_name(&self) -> &'static str {
        match self {
            Self::Fake { .. } => "fake",
            #[cfg(unix)]
            Self::CoreLightning { .. } => "cln",
        }
    }
}

fn serve_fake(args: ServeFakeArgs) -> Result<(), String> {
    serve_with_backend(
        args.common,
        BackendConfigV1::Fake {
            signing_key: args.fake_lightning_signing_key,
            derivation_seed: args.fake_lightning_derivation_seed,
        },
    )
}

#[cfg(unix)]
fn serve_cln(args: ServeClnArgs) -> Result<(), String> {
    serve_with_backend(
        args.common,
        BackendConfigV1::CoreLightning {
            socket_path: args.cln_rpc_socket,
            socket_policy: UnixClnRpcSocketPolicyV1 {
                expected_uid: args.cln_rpc_expected_uid,
                expected_gid: args.cln_rpc_expected_gid,
            },
            timeout: Duration::from_secs(args.cln_rpc_timeout_seconds),
        },
    )
}

fn serve_with_backend(
    args: ServeCommonArgs,
    backend_config: BackendConfigV1,
) -> Result<(), String> {
    validate_loopback_bind(args.bind)?;
    if args.max_connections == 0 || args.max_connections > 4_096 {
        return Err("--max-connections must be in 1..=4096".to_owned());
    }
    let quote_capacity = QuoteCapacityV1::new(args.max_outstanding_quotes, args.max_total_quotes)
        .ok_or_else(|| {
        "quote capacities must be non-zero and outstanding must not exceed active total".to_owned()
    })?;
    let quote_rate =
        FixedWindowRateLimiterV1::new(args.quote_rate_per_minute, "--quote-rate-per-minute")?;
    let status_rate =
        FixedWindowRateLimiterV1::new(args.status_rate_per_minute, "--status-rate-per-minute")?;
    let mutation_rate =
        FixedWindowRateLimiterV1::new(args.mutation_rate_per_minute, "--mutation-rate-per-minute")?;
    let reconciliation_rate = FixedWindowRateLimiterV1::new(
        args.reconciliation_rate_per_minute,
        "--reconciliation-rate-per-minute",
    )?;
    if args.reconciliation_batch_size == 0
        || args.reconciliation_batch_size > MAX_QUOTE_RECONCILIATION_BATCH_V1
    {
        return Err(format!(
            "--reconciliation-batch-size must be in 1..={MAX_QUOTE_RECONCILIATION_BATCH_V1}"
        ));
    }
    if !(1..=300).contains(&args.reconciliation_interval_seconds) {
        return Err("--reconciliation-interval-seconds must be in 1..=300".to_owned());
    }
    if !(10..=60_000).contains(&args.reconciliation_tick_budget_ms) {
        return Err("--reconciliation-tick-budget-ms must be in 10..=60000".to_owned());
    }
    let reconciliation_config = ReconciliationWorkerConfigV1 {
        interval: Duration::from_secs(args.reconciliation_interval_seconds),
        batch_size: args.reconciliation_batch_size,
        tick_budget: Duration::from_millis(args.reconciliation_tick_budget_ms),
        rate: reconciliation_rate,
    };
    if args.service_policies.is_empty() {
        return Err("at least one --service-policy is required".to_owned());
    }
    if let Some(origin) = &args.allow_origin {
        validate_origin(origin)?;
    }

    let (delegation, delegation_bytes, current_quote_material) = load_quote_material(
        &args.quote_delegation,
        &args.quote_signing_key,
        "current quote material",
    )?;
    let mut retained_quote_materials = Vec::new();
    let mut quote_delegations = BTreeMap::new();
    quote_delegations.insert(delegation.quote_key_id, delegation_bytes.clone());
    let mut quote_epochs = BTreeMap::new();
    quote_epochs.insert(delegation.key_epoch, delegation.quote_key_id);
    let mut quote_digests = BTreeMap::new();
    quote_digests.insert(
        delegation
            .delegation_digest()
            .map_err(|_| "current quote delegation digest failed".to_owned())?,
        delegation.quote_key_id,
    );
    for spec in &args.retained_quote_materials {
        let (delegation_path, signing_key_path) = spec.split_once('=').ok_or_else(|| {
            "--retained-quote-material must be <delegation-path>=<signing-key-path>".to_owned()
        })?;
        let (retained, exact, material) = load_quote_material(
            Path::new(delegation_path),
            Path::new(signing_key_path),
            "retained quote material",
        )?;
        if retained.issuer_id != delegation.issuer_id
            || retained.issuer_verifying_key != delegation.issuer_verifying_key
            || retained.network != delegation.network
            || retained.expected_payee_pubkey != delegation.expected_payee_pubkey
            || retained.key_epoch >= delegation.key_epoch
        {
            return Err(
                "retained quote delegation must share the current root/network/payee and have an older epoch"
                    .to_owned(),
            );
        }
        let digest = retained
            .delegation_digest()
            .map_err(|_| "retained quote delegation digest failed".to_owned())?;
        if quote_delegations
            .insert(retained.quote_key_id, exact)
            .is_some()
            || quote_epochs
                .insert(retained.key_epoch, retained.quote_key_id)
                .is_some()
            || quote_digests
                .insert(digest, retained.quote_key_id)
                .is_some()
        {
            return Err("duplicate quote key ID, epoch, or delegation digest".to_owned());
        }
        retained_quote_materials.push(material);
    }
    let options = StoreOptions::default();
    let canonical_store = validate_existing_private_database_path(&args.store, "issuer store")?;
    let canonical_authority = validate_existing_private_database_path(
        &args.rollback_authority,
        "issuer rollback authority",
    )?;
    if private_database_paths_alias_v1(&canonical_store, &canonical_authority)? {
        return Err("store and rollback authority resolve to the same file/inode".to_owned());
    }
    let authority = Arc::new(
        SqliteIssuerRollbackFloorAuthorityV1::open_existing(
            &canonical_authority,
            options.busy_timeout,
        )
        .map_err(|error| format!("open rollback authority failed: {error}"))?,
    );
    let store = IssuerStore::open_existing(
        &canonical_store,
        delegation.issuer_id,
        delegation.network,
        options,
        authority,
    )
    .map_err(|error| format!("open issuer store failed: {error}"))?;

    let now_unix = system_time_unix()?;
    delegation
        .verify_for(
            &delegation.issuer_id,
            delegation.network,
            &delegation.expected_payee_pubkey,
            delegation.key_epoch,
            now_unix,
        )
        .map_err(|_| "current quote delegation is not authentic and live".to_owned())?;
    let mut policies = Vec::with_capacity(args.service_policies.len());
    for spec in &args.service_policies {
        let (path, key_hex) = spec.rsplit_once('=').ok_or_else(|| {
            "--service-policy must be <signed-policy-path>=<ed25519-public-key-hex>".to_owned()
        })?;
        let bytes = read_public_file(
            Path::new(path),
            pir_service_protocol::MAX_SIGNED_POLICY_LEN,
            "service policy",
        )?;
        let policy = ServicePolicyV1::decode(&bytes)
            .map_err(|_| format!("service policy {} is not canonical V1", path))?;
        if policy
            .encode()
            .map_err(|_| "service policy encode failed".to_owned())?
            != bytes
        {
            return Err(format!("service policy {} is non-canonical", path));
        }
        let key_bytes = decode_fixed_hex::<32>(key_hex, "service policy public key")?;
        let key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| "service policy public key is invalid".to_owned())?;
        let _registration = store
            .register_service_policy(&policy, &key, now_unix)
            .map_err(|error| format!("register service policy failed: {error}"))?;
        register_policy_key_lineages(&store, &policy, now_unix)?;
        policies.push(policy);
    }

    let backend_mode = backend_config.mode_name();
    let (lightning, fake_lightning) = match backend_config {
        BackendConfigV1::Fake {
            signing_key,
            derivation_seed,
        } => {
            let mut lightning_secret =
                read_secret_exact::<32>(&signing_key, "fake Lightning signing key")?;
            let mut lightning_seed =
                read_secret_exact::<32>(&derivation_seed, "fake Lightning derivation seed")?;
            let created = FakeLightningNodeV1::new(
                delegation.network,
                lightning_secret,
                lightning_seed,
                now_unix,
            );
            lightning_secret.zeroize();
            lightning_seed.zeroize();
            let fake =
                Arc::new(created.map_err(|_| "fake Lightning key or seed is invalid".to_owned())?);
            if fake.payee_pubkey() != delegation.expected_payee_pubkey {
                return Err("fake Lightning payee does not match quote delegation".to_owned());
            }
            (
                Arc::new(RuntimeLightningBackendV1::Fake(Arc::clone(&fake))),
                Some(fake),
            )
        }
        #[cfg(unix)]
        BackendConfigV1::CoreLightning {
            socket_path,
            socket_policy,
            timeout,
        } => {
            let transport = UnixClnRpcTransportV1::new(socket_path, socket_policy, timeout)
                .map_err(|_| "Core Lightning RPC socket configuration is invalid".to_owned())?;
            let backend = CoreLightningBackendV1::new(transport);
            backend
                .verify_node_identity(&delegation.expected_payee_pubkey, delegation.network)
                .map_err(|error| {
                    format!(
                        "Core Lightning RPC node identity or network does not match quote delegation: {error}"
                    )
                })?;
            (
                Arc::new(RuntimeLightningBackendV1::CoreLightning(backend)),
                None,
            )
        }
    };

    let mut receipt_keys = Vec::with_capacity(args.receipt_signing_keys.len());
    for path in &args.receipt_signing_keys {
        let mut bytes = read_secret_exact::<32>(path, "receipt signing key")?;
        receipt_keys.push(ReceiptSigningMaterialV1::new(SigningKey::from_bytes(
            &bytes,
        )));
        bytes.zeroize();
    }
    let bat_keyring = load_bat_keyring(&args.bat_keys)?;
    let arc_keyring = load_arc_keyring(&args.arc_keys)?;
    let mut derivation_bytes =
        read_secret_exact::<32>(&args.credential_derivation_key, "credential derivation key")?;
    let credential_derivation_key =
        IssuerCredentialDerivationKeyV1::from_bytes(derivation_bytes)
            .map_err(|_| "credential derivation key is invalid".to_owned())?;
    derivation_bytes.zeroize();

    let acquisition = IssuerAcquisitionServiceV1::new_with_quote_capacity(
        store.clone(),
        Arc::clone(&lightning),
        Arc::new(OsQuoteIdSourceV1),
        current_quote_material,
        retained_quote_materials,
        receipt_keys,
        bat_keyring.clone(),
        arc_keyring.clone(),
        credential_derivation_key,
        quote_capacity,
        now_unix,
    )
    .map_err(|error| format!("build acquisition service failed: {error}"))?;
    let clearing = load_ledger_clearing(&args, &store, bat_keyring, arc_keyring, now_unix)?;
    drop(policies);

    let listener = TcpListener::bind(args.bind)
        .map_err(|error| format!("bind {backend_mode} issuer listener failed: {error}"))?;
    let state = Arc::new(ServerState {
        acquisition,
        current_quote_delegation: delegation_bytes,
        quote_delegations,
        clearing,
        store,
        fake_lightning,
        allow_origin: args.allow_origin,
        quote_rate,
        status_rate,
        mutation_rate,
    });
    let active = Arc::new(AtomicUsize::new(0));
    spawn_reconciliation_worker(Arc::clone(&state), reconciliation_config)?;
    println!(
        "payment-issuer {backend_mode} service listening on http://{} (loopback only)",
        args.bind,
    );
    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(stream) => stream,
            Err(_) => continue,
        };
        if active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < args.max_connections).then_some(count + 1)
            })
            .is_err()
        {
            continue;
        }
        let state = Arc::clone(&state);
        let active = Arc::clone(&active);
        thread::spawn(move || {
            let _guard = ConnectionCountGuard(active);
            handle_connection(stream, &state);
        });
    }
    Ok(())
}

fn load_quote_material(
    delegation_path: &Path,
    signing_key_path: &Path,
    label: &str,
) -> Result<(Bolt11QuoteKeyDelegationV1, Vec<u8>, QuoteSigningMaterialV1), String> {
    let exact = read_public_file(delegation_path, MAX_BOLT11_QUOTE_KEY_DELEGATION_LEN, label)?;
    let delegation = Bolt11QuoteKeyDelegationV1::decode(&exact)
        .map_err(|_| format!("{label} delegation is not canonical V1"))?;
    if delegation
        .encode()
        .map_err(|_| format!("{label} delegation cannot be encoded"))?
        != exact
    {
        return Err(format!("{label} delegation is non-canonical"));
    }
    // Verify the root signature at a time known to be inside the signed
    // window. Retained keys may legitimately be expired at process startup.
    delegation
        .verify_for(
            &delegation.issuer_id,
            delegation.network,
            &delegation.expected_payee_pubkey,
            delegation.key_epoch,
            delegation.not_before,
        )
        .map_err(|_| format!("{label} delegation signature or binding is invalid"))?;
    let mut secret = read_secret_exact::<32>(signing_key_path, label)?;
    let signing_key = SigningKey::from_bytes(&secret);
    secret.zeroize();
    let material = QuoteSigningMaterialV1::new(delegation.clone(), signing_key)
        .map_err(|_| format!("{label} signing key does not match its delegation"))?;
    Ok((delegation, exact, material))
}

fn register_policy_key_lineages(
    store: &IssuerStore,
    policy: &ServicePolicyV1,
    now_unix: u64,
) -> Result<(), String> {
    let identity = store
        .identity()
        .map_err(|error| format!("read issuer identity failed: {error}"))?;
    for scope_policy in &policy.scopes {
        let scope_id = scope_policy.scope.scope_id();
        for offer in &scope_policy.offers {
            if offer.issuer_id != identity.issuer_id {
                continue;
            }
            let Some(binding) = &offer.credential_binding else {
                continue;
            };
            match offer.authorization {
                AuthScheme::BitcoinPirCashuBatV1 => {
                    let raw_public_key: [u8; 33] = binding
                        .claims
                        .verification_key
                        .as_slice()
                        .try_into()
                        .map_err(|_| "BAT binding key is not 33 bytes".to_owned())?;
                    let credential_key_id: [u8; 32] = binding
                        .claims
                        .credential_key_id
                        .as_slice()
                        .try_into()
                        .map_err(|_| "BAT binding key ID is not 32 bytes".to_owned())?;
                    let _registration = store
                        .register_bat_key_lineage(&BatKeyLineageRegistration {
                            raw_public_key,
                            provider_id: policy.provider_id,
                            scope_id,
                            offer_id: offer.offer_id,
                            entitlement_profile: scope_policy.scope.entitlement_profile,
                            keyset_epoch: binding.claims.keyset_epoch,
                            credential_key_id,
                        })
                        .map_err(|error| format!("register BAT key lineage failed: {error}"))?;
                }
                AuthScheme::ArcV1Experimental => {
                    let _registration = store
                        .register_arc_key_lineage_experimental(binding, now_unix)
                        .map_err(|error| format!("register ARC key lineage failed: {error}"))?;
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn load_bat_keyring(paths: &[PathBuf]) -> Result<Option<Arc<K256CashuMintKeyringV1>>, String> {
    if paths.is_empty() {
        return Ok(None);
    }
    let mut keys = Vec::with_capacity(paths.len());
    for path in paths {
        keys.push(read_secret_exact::<32>(path, "Cashu BAT key")?);
    }
    let result = K256CashuMintKeyringV1::from_secret_keys(keys.iter().copied())
        .map(Arc::new)
        .map_err(|_| "Cashu BAT keyring is invalid".to_owned());
    keys.zeroize();
    result.map(Some)
}

fn load_arc_keyring(specs: &[String]) -> Result<Option<Arc<ArcSecretKeyringV1>>, String> {
    if specs.is_empty() {
        return Ok(None);
    }
    let mut keys = Vec::with_capacity(specs.len());
    for spec in specs {
        let (key_id_hex, path) = spec
            .split_once('=')
            .ok_or_else(|| "--arc-key must be <key-id-hex>=<key-path>".to_owned())?;
        let key_id = hex::decode(key_id_hex).map_err(|_| "ARC key ID is invalid hex".to_owned())?;
        let secret = Zeroizing::new(read_secret_exact::<ARC_SECRET_KEY_LEN_V1>(
            Path::new(path),
            "experimental ARC key",
        )?);
        keys.push(
            ArcSecretKeyV1::from_zeroizing_bytes(key_id, secret)
                .map_err(|_| "experimental ARC key is invalid".to_owned())?,
        );
    }
    ArcSecretKeyringV1::new(keys)
        .map(Arc::new)
        .map(Some)
        .map_err(|_| "experimental ARC keyring is invalid".to_owned())
}

/// Installs the local trust configuration for the shared issuer route used by
/// provider servers.  The first executable surface deliberately supports only
/// identified ledger credit.  Anonymous blind settlement is implemented in
/// the transport-neutral service, but requires a separate retained-keyset
/// operations ceremony before it can be enabled here.
fn load_ledger_clearing(
    args: &ServeCommonArgs,
    store: &IssuerStore,
    bat_keyring: Option<Arc<K256CashuMintKeyringV1>>,
    arc_keyring: Option<Arc<ArcSecretKeyringV1>>,
    now_unix: u64,
) -> Result<Option<SharedIssuerClearingServiceV1>, String> {
    let any_configured = !args.clearing_authorizations.is_empty()
        || !args.clearing_approvals.is_empty()
        || !args.clearing_payout_targets.is_empty()
        || args.issuer_settlement_signing_key.is_some()
        || args.redeem_response_derivation_key.is_some();
    if !any_configured {
        return Ok(None);
    }
    if args.clearing_authorizations.is_empty()
        || args.clearing_authorizations.len() != args.clearing_approvals.len()
    {
        return Err(
            "clearing requires the same non-zero number of --clearing-authorization and --clearing-approval files"
                .to_owned(),
        );
    }
    let settlement_key_path = args
        .issuer_settlement_signing_key
        .as_deref()
        .ok_or_else(|| "clearing requires --issuer-settlement-signing-key".to_owned())?;
    let derivation_key_path = args
        .redeem_response_derivation_key
        .as_deref()
        .ok_or_else(|| "clearing requires --redeem-response-derivation-key".to_owned())?;

    let mut settlement_key_bytes =
        read_secret_exact::<32>(settlement_key_path, "issuer settlement signing key")?;
    let issuer_settlement_signing_key = SigningKey::from_bytes(&settlement_key_bytes);
    settlement_key_bytes.zeroize();
    let settlement_verifying_key = issuer_settlement_signing_key.verifying_key();

    let mut derivation_key_bytes =
        read_secret_exact::<32>(derivation_key_path, "redeem response derivation key")?;
    let response_derivation_key =
        RedeemResponseDerivationKeyV1::from_bytes(derivation_key_bytes)
            .map_err(|_| "redeem response derivation key is invalid".to_owned())?;
    derivation_key_bytes.zeroize();

    let mut payout_targets = BTreeMap::new();
    for spec in &args.clearing_payout_targets {
        let (provider_hex, target_hex) = spec.split_once('=').ok_or_else(|| {
            "--clearing-payout-target must be <provider-id-hex>=<payout-target-id-hex>".to_owned()
        })?;
        let provider_id = decode_fixed_hex::<32>(provider_hex, "clearing provider ID")?;
        let payout_target_id = decode_fixed_hex::<32>(target_hex, "clearing payout target ID")?;
        if provider_id.iter().all(|byte| *byte == 0)
            || payout_target_id.iter().all(|byte| *byte == 0)
            || payout_targets
                .insert(provider_id, payout_target_id)
                .is_some()
        {
            return Err(
                "clearing payout targets must be non-zero and unique per provider".to_owned(),
            );
        }
    }

    struct PreparedClearingProvider {
        authorization: ProviderClearingAuthorizationV1,
        approval: IssuerClearingApprovalV1,
        operator_key: VerifyingKey,
        payout_target_id: [u8; 32],
    }

    let identity = store
        .identity()
        .map_err(|error| format!("read issuer identity failed: {error}"))?;
    let mut prepared = Vec::with_capacity(args.clearing_authorizations.len());
    let mut seen_providers = BTreeMap::new();
    for (authorization_path, approval_path) in args
        .clearing_authorizations
        .iter()
        .zip(&args.clearing_approvals)
    {
        let authorization_bytes = read_public_file(
            authorization_path,
            MAX_EXACT_CLEARING_AUTHORIZATION_BYTES,
            "provider clearing authorization",
        )?;
        let authorization = ProviderClearingAuthorizationV1::decode(&authorization_bytes)
            .map_err(|_| "provider clearing authorization is not canonical V1".to_owned())?;
        if authorization
            .encode()
            .map_err(|_| "provider clearing authorization cannot be encoded".to_owned())?
            != authorization_bytes
        {
            return Err("provider clearing authorization is non-canonical".to_owned());
        }
        let approval_bytes = read_public_file(
            approval_path,
            MAX_EXACT_CLEARING_APPROVAL_BYTES,
            "issuer clearing approval",
        )?;
        let approval = IssuerClearingApprovalV1::decode(&approval_bytes)
            .map_err(|_| "issuer clearing approval is not canonical V1".to_owned())?;
        if approval.encode() != approval_bytes {
            return Err("issuer clearing approval is non-canonical".to_owned());
        }
        if authorization.claims.issuer_id != identity.issuer_id {
            return Err("clearing authorization targets a different issuer".to_owned());
        }
        if authorization.claims.rules.iter().any(|rule| {
            rule.unit != SettlementUnitV1::AuthCredit
                || !rule
                    .settlement_modes
                    .allows(SettlementModesV1::LEDGER_CREDIT)
                || rule
                    .settlement_modes
                    .allows(SettlementModesV1::BLIND_OUTPUTS)
        }) {
            return Err(
                "payment issuer clearing currently requires auth-credit ledger-only settlement rules"
                    .to_owned(),
            );
        }
        let operator_key = VerifyingKey::from_bytes(&authorization.operator_verifying_key)
            .map_err(|_| "provider operator key is invalid".to_owned())?;
        authorization
            .verify_for(
                &authorization.claims.provider_id,
                &identity.issuer_id,
                &operator_key,
                now_unix,
                authorization.claims.authorization_epoch,
            )
            .map_err(|_| {
                "provider clearing authorization is not current or authentic".to_owned()
            })?;
        approval
            .verify_for(
                &authorization,
                &settlement_verifying_key,
                now_unix,
                authorization.claims.authorization_epoch,
            )
            .map_err(|_| "issuer clearing approval is not current or authentic".to_owned())?;
        for binding in store
            .credential_bindings_for_clearing_authorization(&authorization, now_unix)
            .map_err(|error| {
                format!("resolve clearing credential binding and lineage failed: {error}")
            })?
        {
            ensure_shared_clearing_binding_material_v1(
                &binding,
                now_unix,
                bat_keyring.as_deref(),
                arc_keyring.as_deref(),
            )
            .map_err(|_| {
                "current clearing authorization requires unavailable BAT/ARC private material"
                    .to_owned()
            })?;
        }
        let provider_id = authorization.claims.provider_id;
        if seen_providers.insert(provider_id, ()).is_some() {
            return Err(
                "only one current clearing authorization per provider is allowed".to_owned(),
            );
        }
        let payout_target_id = payout_targets
            .remove(&provider_id)
            .ok_or_else(|| "clearing provider has no configured payout target".to_owned())?;
        prepared.push(PreparedClearingProvider {
            authorization,
            approval,
            operator_key,
            payout_target_id,
        });
    }
    if !payout_targets.is_empty() {
        return Err("clearing payout target has no matching authorization".to_owned());
    }

    let mut trusted = Vec::with_capacity(prepared.len());
    for provider in prepared {
        let claims = &provider.authorization.claims;
        let _registration = store
            .register_provider_settlement(&ProviderSettlementRegistrationWriteV1 {
                registration_epoch: claims.authorization_epoch,
                provider_id: claims.provider_id,
                settlement_account_id: claims.settlement_account_id,
                provider_request_verifying_key: claims.clearing_verifying_key,
                payout_target_id: provider.payout_target_id,
                not_before: claims.not_before,
                not_after: claims.not_after,
            })
            .map_err(|error| format!("register provider settlement failed: {error}"))?;
        let _authorization = store
            .register_clearing_authorization(
                &provider.authorization,
                &provider.approval,
                &provider.operator_key,
                &settlement_verifying_key,
                now_unix,
            )
            .map_err(|error| format!("register clearing authorization failed: {error}"))?;
        trusted.push(TrustedClearingProviderV1 {
            provider_id: claims.provider_id,
            operator_key: provider.operator_key,
            minimum_authorization_epoch: claims.authorization_epoch,
        });
    }

    SharedIssuerClearingServiceV1::new(
        store.clone(),
        trusted,
        bat_keyring,
        arc_keyring,
        issuer_settlement_signing_key,
        None,
        Vec::new(),
        response_derivation_key,
    )
    .map(Some)
    .map_err(|error| format!("build shared issuer clearing service failed: {error}"))
}

struct ConnectionCountGuard(Arc<AtomicUsize>);

impl Drop for ConnectionCountGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct ParsedRequest {
    method: String,
    path: String,
    content_type: Option<String>,
    origin: Option<String>,
    body: Vec<u8>,
}

fn handle_connection(mut stream: TcpStream, state: &ServerState) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let request = match read_request(&mut stream) {
        Ok(request) => request,
        Err(error) => {
            let _ = write_error(&mut stream, error, state.allow_origin.as_deref());
            return;
        }
    };
    if request.method == "OPTIONS" {
        let allowed = state
            .allow_origin
            .as_deref()
            .zip(request.origin.as_deref())
            .is_some_and(|(expected, actual)| expected == actual);
        let result = if allowed {
            write_response(
                &mut stream,
                204,
                "text/plain",
                &[],
                state.allow_origin.as_deref(),
            )
        } else {
            write_error(&mut stream, IssuerServiceErrorV1::Unauthorized, None)
        };
        let _ = result;
        return;
    }
    if let (Some(expected), Some(actual)) =
        (state.allow_origin.as_deref(), request.origin.as_deref())
    {
        if expected != actual {
            let _ = write_error(&mut stream, IssuerServiceErrorV1::Unauthorized, None);
            return;
        }
    }

    if request.method == "GET" {
        let response = route_get_request(state, &request);
        match response {
            Ok((content_type, body)) => {
                let _ = write_response(
                    &mut stream,
                    200,
                    content_type,
                    &body,
                    state.allow_origin.as_deref(),
                );
            }
            Err(error) => {
                let _ = write_error(&mut stream, error, state.allow_origin.as_deref());
            }
        }
        return;
    }
    if request.method != "POST" {
        let _ = write_status(&mut stream, 405, "method_not_allowed", None);
        return;
    }

    let response = route_request(state, &request);
    match response {
        Ok((content_type, body)) => {
            let _ = write_response(
                &mut stream,
                200,
                content_type,
                &body,
                state.allow_origin.as_deref(),
            );
        }
        Err(error) => {
            let _ = write_error(&mut stream, error, state.allow_origin.as_deref());
        }
    }
}

fn route_get_request(
    state: &ServerState,
    request: &ParsedRequest,
) -> Result<(&'static str, Vec<u8>), IssuerServiceErrorV1> {
    if !request.body.is_empty() || request.content_type.is_some() {
        return Err(IssuerServiceErrorV1::InvalidRequest);
    }
    if request.path == "/v1/quote-keys/current" {
        return Ok((
            CT_QUOTE_KEY_DELEGATION,
            state.current_quote_delegation.clone(),
        ));
    }
    let key_id = parse_quote_key_path(&request.path).ok_or(IssuerServiceErrorV1::NotFound)?;
    state
        .quote_delegations
        .get(&key_id)
        .cloned()
        .map(|body| (CT_QUOTE_KEY_DELEGATION, body))
        .ok_or(IssuerServiceErrorV1::NotFound)
}

fn route_request(
    state: &ServerState,
    request: &ParsedRequest,
) -> Result<(&'static str, Vec<u8>), IssuerServiceErrorV1> {
    let now_unix = system_time_unix().map_err(|_| IssuerServiceErrorV1::Internal)?;
    match request.path.as_str() {
        "/v1/quotes/bolt11" => {
            require_content_type(request, CT_QUOTE_INTENT)?;
            if request.body.len() > MAX_BOLT11_QUOTE_INTENT_LEN {
                return Err(IssuerServiceErrorV1::InvalidRequest);
            }
            let intent = Bolt11QuoteIntentV1::decode(&request.body)
                .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?;
            if intent.encode().ok().as_deref() != Some(request.body.as_slice()) {
                return Err(IssuerServiceErrorV1::InvalidRequest);
            }
            let request_digest = intent
                .request_digest()
                .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?;
            let stored = state
                .store
                .quote_by_creation_idempotency_key(&intent.idempotency_key)
                .map_err(|_| IssuerServiceErrorV1::RetryableUnavailable)?;
            let exact_replay = exact_intent_replay(
                stored.as_ref().map(|quote| quote.intent_digest),
                request_digest,
            );
            if !exact_replay && !state.quote_rate.try_acquire(Instant::now()) {
                return Err(IssuerServiceErrorV1::RetryableUnavailable);
            }
            state
                .acquisition
                .create_quote(&request.body, now_unix)
                .map(|body| (CT_QUOTE, body))
        }
        "/v1/redeems" => {
            require_content_type(request, CT_REDEEM)?;
            if request.body.len() > MAX_PROVIDER_REDEEM_ENVELOPE_LEN_V1 {
                return Err(IssuerServiceErrorV1::InvalidRequest);
            }
            if !is_exact_redeem_replay(&state.store, &request.body)
                && !state.mutation_rate.try_acquire(Instant::now())
            {
                return Err(IssuerServiceErrorV1::RetryableUnavailable);
            }
            state
                .clearing
                .as_ref()
                .ok_or(IssuerServiceErrorV1::NotFound)?
                .redeem(&request.body, now_unix)
                .map(|body| (CT_REDEEM_RESULT, body))
        }
        "/__test/fake/settle" => {
            // This route must be indistinguishable from an unknown path in
            // production mode, before validating any test-only payload.
            let fake_lightning = require_fake_settlement_backend(state.fake_lightning.as_ref())?;
            require_content_type(request, CT_FAKE_SETTLEMENT)?;
            if request.body.len() != 48 {
                return Err(IssuerServiceErrorV1::InvalidRequest);
            }
            let quote_id: [u8; 32] = request.body[0..32]
                .try_into()
                .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?;
            let amount = u64::from_le_bytes(
                request.body[32..40]
                    .try_into()
                    .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?,
            );
            let settled_at = u64::from_le_bytes(
                request.body[40..48]
                    .try_into()
                    .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?,
            );
            let quote = state
                .store
                .quote(&quote_id)
                .map_err(|_| IssuerServiceErrorV1::Internal)?
                .ok_or(IssuerServiceErrorV1::NotFound)?;
            fake_lightning
                .observe_settlement(&quote.backend_label, amount, settled_at)
                .map_err(|_| IssuerServiceErrorV1::Conflict)?;
            Ok(("application/octet-stream", Vec::new()))
        }
        path => {
            let (quote_id, action) =
                parse_quote_action_path(path).ok_or(IssuerServiceErrorV1::NotFound)?;
            match action {
                "status" => {
                    require_content_type(request, CT_STATUS_REQUEST)?;
                    if request.body.len() > MAX_BOLT11_QUOTE_STATUS_REQUEST_LEN {
                        return Err(IssuerServiceErrorV1::InvalidRequest);
                    }
                    if !state.status_rate.try_acquire(Instant::now()) {
                        return Err(IssuerServiceErrorV1::RetryableUnavailable);
                    }
                    state
                        .acquisition
                        .quote_status(&quote_id, &request.body, now_unix)
                        .map(|body| (CT_QUOTE, body))
                }
                "claim" => {
                    require_content_type(request, CT_CLAIM_ENVELOPE)?;
                    if request.body.len() > MAX_BOLT11_QUOTE_CLAIM_ENVELOPE_LEN_V1 {
                        return Err(IssuerServiceErrorV1::InvalidRequest);
                    }
                    if !is_exact_claim_replay(&state.store, &quote_id, &request.body)
                        && !state.mutation_rate.try_acquire(Instant::now())
                    {
                        return Err(IssuerServiceErrorV1::RetryableUnavailable);
                    }
                    state
                        .acquisition
                        .claim_quote(&quote_id, &request.body, now_unix)
                        .map(|body| (CT_ISSUANCE_RESPONSE, body))
                }
                _ => Err(IssuerServiceErrorV1::NotFound),
            }
        }
    }
}

fn require_content_type(
    request: &ParsedRequest,
    expected: &str,
) -> Result<(), IssuerServiceErrorV1> {
    if request.content_type.as_deref() == Some(expected) {
        Ok(())
    } else {
        Err(IssuerServiceErrorV1::InvalidRequest)
    }
}

fn parse_quote_action_path(path: &str) -> Option<([u8; 32], &str)> {
    let rest = path.strip_prefix("/v1/quotes/")?;
    let (quote_hex, action) = rest.split_once('/')?;
    if quote_hex.len() != 64
        || !quote_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !matches!(action, "status" | "claim")
    {
        return None;
    }
    let decoded = hex::decode(quote_hex).ok()?;
    Some((decoded.try_into().ok()?, action))
}

fn parse_quote_key_path(path: &str) -> Option<[u8; 16]> {
    let key_hex = path.strip_prefix("/v1/quote-keys/")?;
    if key_hex.len() != 32
        || !key_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    hex::decode(key_hex).ok()?.try_into().ok()
}

fn read_request(stream: &mut TcpStream) -> Result<ParsedRequest, IssuerServiceErrorV1> {
    let mut bytes = Vec::with_capacity(2048);
    let header_end = loop {
        if bytes.len() >= MAX_HEADER_BYTES {
            return Err(IssuerServiceErrorV1::InvalidRequest);
        }
        let mut chunk = [0u8; 2048];
        let read = stream
            .read(&mut chunk)
            .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?;
        if read == 0 {
            return Err(IssuerServiceErrorV1::InvalidRequest);
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let end = position + 4;
            if end > MAX_HEADER_BYTES {
                return Err(IssuerServiceErrorV1::InvalidRequest);
            }
            break end;
        }
    };
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Request::new(&mut headers);
    let parsed_len = match parsed
        .parse(&bytes[..header_end])
        .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?
    {
        httparse::Status::Complete(length) if length == header_end => length,
        _ => return Err(IssuerServiceErrorV1::InvalidRequest),
    };
    if parsed.version != Some(1) || parsed_len != header_end {
        return Err(IssuerServiceErrorV1::InvalidRequest);
    }
    let method = parsed
        .method
        .filter(|value| matches!(*value, "GET" | "POST" | "OPTIONS"))
        .ok_or(IssuerServiceErrorV1::InvalidRequest)?
        .to_owned();
    let path = parsed
        .path
        .filter(|value| value.starts_with('/') && !value.contains('?') && value.is_ascii())
        .ok_or(IssuerServiceErrorV1::InvalidRequest)?
        .to_owned();
    let mut content_length = None;
    let mut content_type = None;
    let mut origin = None;
    let mut host_count = 0usize;
    for header in parsed.headers.iter() {
        let name = header.name.to_ascii_lowercase();
        let value = std::str::from_utf8(header.value)
            .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?
            .trim();
        match name.as_str() {
            "host" => host_count += 1,
            "content-length" if content_length.is_none() => {
                content_length = Some(
                    value
                        .parse::<usize>()
                        .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?,
                );
            }
            "content-length" => return Err(IssuerServiceErrorV1::InvalidRequest),
            "content-type" if content_type.is_none() => content_type = Some(value.to_owned()),
            "content-type" => return Err(IssuerServiceErrorV1::InvalidRequest),
            "origin" if origin.is_none() => origin = Some(value.to_owned()),
            "origin" | "transfer-encoding" | "expect" => {
                return Err(IssuerServiceErrorV1::InvalidRequest)
            }
            _ => {}
        }
    }
    if host_count != 1 {
        return Err(IssuerServiceErrorV1::InvalidRequest);
    }
    let body_len = content_length.unwrap_or(0);
    if body_len > MAX_HTTP_BODY_BYTES
        || (method == "POST" && content_length.is_none())
        || (method == "GET" && body_len != 0)
    {
        return Err(IssuerServiceErrorV1::InvalidRequest);
    }
    let already = bytes.len().saturating_sub(header_end);
    if already > body_len {
        return Err(IssuerServiceErrorV1::InvalidRequest);
    }
    let mut body = Vec::with_capacity(body_len);
    body.extend_from_slice(&bytes[header_end..]);
    body.resize(body_len, 0);
    if already < body_len {
        stream
            .read_exact(&mut body[already..])
            .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?;
    }
    Ok(ParsedRequest {
        method,
        path,
        content_type,
        origin,
        body,
    })
}

fn write_error(
    stream: &mut TcpStream,
    error: IssuerServiceErrorV1,
    allow_origin: Option<&str>,
) -> std::io::Result<()> {
    write_status(
        stream,
        error.http_status(),
        error.public_code(),
        allow_origin,
    )
}

fn write_status(
    stream: &mut TcpStream,
    status: u16,
    code: &str,
    allow_origin: Option<&str>,
) -> std::io::Result<()> {
    let body = format!("{{\"code\":\"{code}\"}}");
    write_response(
        stream,
        status,
        "application/problem+json",
        body.as_bytes(),
        allow_origin,
    )
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
    allow_origin: Option<&str>,
) -> std::io::Result<()> {
    if body.len() > MAX_HTTP_RESPONSE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "response exceeds configured bound",
        ));
    }
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n",
        body.len()
    );
    if let Some(origin) = allow_origin {
        head.push_str("Access-Control-Allow-Origin: ");
        head.push_str(origin);
        head.push_str("\r\nVary: Origin\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn system_time_unix() -> Result<u64, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before Unix epoch".to_owned())?
        .as_secs();
    if now == 0 {
        Err("system clock is zero".to_owned())
    } else {
        Ok(now)
    }
}

fn validate_origin(origin: &str) -> Result<(), String> {
    let invalid = || {
        "--allow-origin must be one canonical exact origin (HTTPS, or HTTP localhost), with no userinfo/path/query/fragment/whitespace".to_owned()
    };
    if origin.is_empty()
        || origin.len() > 512
        || !origin.is_ascii()
        || origin
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(invalid());
    }
    let (scheme, authority) = origin.split_once("://").ok_or_else(&invalid)?;
    if authority.is_empty() || authority.contains(['/', '?', '#', '@']) || authority.contains("://")
    {
        return Err(invalid());
    }
    let (host, port) = parse_canonical_origin_authority_v1(authority).ok_or_else(&invalid)?;
    match scheme {
        "https" => {
            if port == Some(443) {
                return Err(invalid());
            }
        }
        "http" => {
            if host != "localhost" && host != "127.0.0.1" && host != "[::1]" {
                return Err(invalid());
            }
            if port == Some(80) {
                return Err(invalid());
            }
        }
        _ => return Err(invalid()),
    }
    Ok(())
}

fn parse_canonical_origin_authority_v1(authority: &str) -> Option<(&str, Option<u16>)> {
    let (host, port_text) = if authority.starts_with('[') {
        let close = authority.find(']')?;
        let host = &authority[..=close];
        let suffix = &authority[close + 1..];
        let port = if suffix.is_empty() {
            None
        } else {
            Some(suffix.strip_prefix(':')?)
        };
        (host, port)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if host.contains(':') {
            return None;
        }
        (host, Some(port))
    } else {
        (authority, None)
    };
    if !is_canonical_origin_host_v1(host) {
        return None;
    }
    let port = match port_text {
        None => None,
        Some(value)
            if !value.is_empty()
                && value.bytes().all(|byte| byte.is_ascii_digit())
                && !value.starts_with('0') =>
        {
            let parsed = value.parse::<u16>().ok()?;
            if parsed == 0 || parsed.to_string() != value {
                return None;
            }
            Some(parsed)
        }
        Some(_) => return None,
    };
    Some((host, port))
}

fn is_canonical_origin_host_v1(host: &str) -> bool {
    if let Some(inner) = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    {
        let address = match inner.parse::<std::net::Ipv6Addr>() {
            Ok(address) => address,
            Err(_) => return false,
        };
        return format!("[{address}]") == host;
    }
    if host.is_empty() || host.len() > 253 || host.ends_with('.') {
        return false;
    }
    if host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|address| address.to_string() == host);
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    })
}

fn incomplete_init_error_v1(
    stage: &str,
    store_path: &Path,
    authority_path: &Path,
    error: &str,
) -> String {
    format!(
        "{stage} failed: {error}; issuer-store initialization is incomplete and neither {} nor {} may be used as live state; inspect both paths and manually remove only files known to belong to this failed ceremony before retrying (payment-issuer never auto-deletes or adopts partial state)",
        store_path.display(),
        authority_path.display()
    )
}

/// Resolve a not-yet-created SQLite path through its canonical parent. The
/// private parent is the single-user mutation boundary protecting the main DB
/// and SQLite's `-wal`/`-shm` sidecars from path replacement or disclosure.
fn prepare_new_private_database_path(path: &Path, label: &str) -> Result<PathBuf, String> {
    let file_name = path
        .file_name()
        .ok_or_else(|| format!("{label} path is not a file path: {}", path.display()))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_was_missing = match fs::symlink_metadata(parent) {
        Ok(_) => false,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => {
            return Err(format!(
                "inspect {label} parent {} failed: {error}",
                parent.display()
            ))
        }
    };
    fs::create_dir_all(parent)
        .map_err(|error| format!("create {label} parent {} failed: {error}", parent.display()))?;
    if parent_was_missing {
        set_private_database_directory_v1(parent, label)?;
    }
    let canonical_parent = parent.canonicalize().map_err(|error| {
        format!(
            "resolve {label} parent {} failed: {error}",
            parent.display()
        )
    })?;
    ensure_private_database_directory_v1(&canonical_parent, label)?;
    let canonical = canonical_parent.join(file_name);
    match fs::symlink_metadata(&canonical) {
        Ok(_) => Err(format!(
            "{label} {} already exists; init-store never overwrites or adopts files",
            canonical.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(canonical),
        Err(error) => Err(format!(
            "inspect {label} {} failed: {error}",
            canonical.display()
        )),
    }
}

/// Validate an existing sensitive SQLite file and return a canonical-parent
/// path. Requiring an owner-only parent makes the subsequent SQLite open and
/// sidecar creation safe against other local users; the final component is
/// independently required to be a real owner-only file.
fn validate_existing_private_database_path(path: &Path, label: &str) -> Result<PathBuf, String> {
    let configured = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "inspect configured {label} {} failed: {error}",
            path.display()
        )
    })?;
    if configured.file_type().is_symlink() || !configured.file_type().is_file() {
        return Err(format!(
            "configured {label} must be a non-symlink regular file: {}",
            path.display()
        ));
    }
    let file_name = path
        .file_name()
        .ok_or_else(|| format!("{label} path is not a file path: {}", path.display()))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let canonical_parent = parent.canonicalize().map_err(|error| {
        format!(
            "resolve {label} parent {} failed: {error}",
            parent.display()
        )
    })?;
    ensure_private_database_directory_v1(&canonical_parent, label)?;
    let canonical = canonical_parent.join(file_name);
    let resolved = fs::symlink_metadata(&canonical).map_err(|error| {
        format!(
            "inspect resolved {label} {} failed: {error}",
            canonical.display()
        )
    })?;
    if resolved.file_type().is_symlink() || !resolved.file_type().is_file() {
        return Err(format!(
            "resolved {label} must be a non-symlink regular file: {}",
            canonical.display()
        ));
    }
    ensure_private_database_file_metadata_v1(&resolved, &canonical, label)?;
    ensure_same_resolved_file_v1(&configured, &resolved, label)?;
    Ok(canonical)
}

#[cfg(unix)]
fn set_private_database_directory_v1(path: &Path, label: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
        format!(
            "set private {label} parent permissions on {} failed: {error}",
            path.display()
        )
    })
}

#[cfg(not(unix))]
fn set_private_database_directory_v1(_path: &Path, label: &str) -> Result<(), String> {
    Err(format!(
        "{label} is unsupported on non-Unix platforms because owner-only SQLite directory permissions cannot be enforced"
    ))
}

#[cfg(unix)]
fn ensure_private_database_directory_v1(path: &Path, label: &str) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {label} parent {} failed: {error}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(format!(
            "{label} parent must be a real directory owned by the effective user with mode 0700: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_database_directory_v1(path: &Path, label: &str) -> Result<(), String> {
    Err(format!(
        "{label} parent {} is unsupported on non-Unix platforms because owner and mode checks cannot be enforced",
        path.display()
    ))
}

#[cfg(unix)]
fn set_owner_only_database_file_v1(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|error| {
        format!(
            "set owner-only database permissions on {} failed: {error}",
            path.display()
        )
    })
}

#[cfg(not(unix))]
fn set_owner_only_database_file_v1(path: &Path) -> Result<(), String> {
    Err(format!(
        "sensitive SQLite file {} is unsupported on non-Unix platforms because mode 0600 cannot be enforced",
        path.display()
    ))
}

#[cfg(unix)]
fn ensure_private_database_file_metadata_v1(
    metadata: &fs::Metadata,
    path: &Path,
    label: &str,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(format!(
            "{label} must be owned by the effective user: {}",
            path.display()
        ));
    }
    if metadata.mode() & 0o777 != 0o600 {
        return Err(format!(
            "{label} must have mode 0600 (invoice/payment and rollback state is sensitive): {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_database_file_metadata_v1(
    _metadata: &fs::Metadata,
    path: &Path,
    label: &str,
) -> Result<(), String> {
    Err(format!(
        "{label} {} is unsupported on non-Unix platforms because owner and mode checks cannot be enforced",
        path.display()
    ))
}

#[cfg(unix)]
fn ensure_same_resolved_file_v1(
    configured: &fs::Metadata,
    resolved: &fs::Metadata,
    label: &str,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    if configured.dev() != resolved.dev() || configured.ino() != resolved.ino() {
        return Err(format!(
            "configured {label} changed while its canonical parent was resolved"
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_same_resolved_file_v1(
    _configured: &fs::Metadata,
    _resolved: &fs::Metadata,
    label: &str,
) -> Result<(), String> {
    Err(format!(
        "{label} is unsupported on non-Unix platforms because file identity checks cannot be enforced"
    ))
}

fn private_database_paths_alias_v1(first: &Path, second: &Path) -> Result<bool, String> {
    if first == second {
        return Ok(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let first_metadata = fs::symlink_metadata(first)
            .map_err(|error| format!("inspect {} failed: {error}", first.display()))?;
        let second_metadata = fs::symlink_metadata(second)
            .map_err(|error| format!("inspect {} failed: {error}", second.display()))?;
        Ok(first_metadata.dev() == second_metadata.dev()
            && first_metadata.ino() == second_metadata.ino())
    }
    #[cfg(not(unix))]
    {
        Err("sensitive SQLite path alias checks are unsupported on non-Unix platforms".to_owned())
    }
}

fn decode_fixed_hex<const N: usize>(input: &str, label: &str) -> Result<[u8; N], String> {
    if input.len() != N * 2 {
        return Err(format!(
            "{label} must contain exactly {} hex characters",
            N * 2
        ));
    }
    hex::decode(input)
        .map_err(|_| format!("{label} is invalid hex"))?
        .try_into()
        .map_err(|_| format!("{label} is not exactly {N} bytes"))
}

fn read_public_file(path: &Path, max: usize, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("read {label} metadata failed: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(format!("{label} must be a non-symlink regular file"));
    }
    let len = usize::try_from(metadata.len()).map_err(|_| format!("{label} is too large"))?;
    if len == 0 || len > max {
        return Err(format!("{label} size is outside 1..={max}"));
    }
    let bytes = fs::read(path).map_err(|error| format!("read {label} failed: {error}"))?;
    if bytes.len() != len {
        return Err(format!("{label} changed while it was read"));
    }
    Ok(bytes)
}

fn read_secret_exact<const N: usize>(path: &Path, label: &str) -> Result<[u8; N], String> {
    #[cfg(unix)]
    {
        read_secret_exact_unix(path, label)
    }

    #[cfg(not(unix))]
    {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("read {label} metadata failed: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(format!("{label} must be a non-symlink regular file"));
        }
        if metadata.len() != N as u64 {
            return Err(format!("{label} must contain exactly {N} raw bytes"));
        }
        let mut bytes = fs::read(path).map_err(|error| format!("read {label} failed: {error}"))?;
        if bytes.len() != N {
            bytes.zeroize();
            return Err(format!("{label} changed while it was read"));
        }
        let result = bytes
            .as_slice()
            .try_into()
            .map_err(|_| format!("{label} is not exactly {N} bytes"));
        bytes.zeroize();
        result
    }
}

#[cfg(unix)]
fn read_secret_exact_unix<const N: usize>(path: &Path, label: &str) -> Result<[u8; N], String> {
    use rustix::fs::{self, FileType, Mode, OFlags};

    // O_NOFOLLOW makes the single open reject a symlink. fstat below and both
    // reads operate on this exact descriptor, never on the path again.
    let fd = fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| format!("read {label} failed: {error}"))?;
    let stat = fs::fstat(&fd).map_err(|error| format!("inspect open {label} failed: {error}"))?;
    if !FileType::from_raw_mode(stat.st_mode).is_file() {
        return Err(format!("{label} must be a regular file"));
    }
    if stat.st_uid != rustix::process::geteuid().as_raw() {
        return Err(format!("{label} must be owned by the effective user"));
    }
    if stat.st_mode & 0o077 != 0 {
        return Err(format!("{label} must not be group/world accessible"));
    }
    if u64::try_from(stat.st_size).ok() != Some(N as u64) {
        return Err(format!("{label} must contain exactly {N} raw bytes"));
    }

    let mut file = std::fs::File::from(fd);
    let mut bytes = [0u8; N];
    if let Err(error) = file.read_exact(&mut bytes) {
        bytes.zeroize();
        return Err(format!("read {label} failed: {error}"));
    }
    let mut extra = [0u8; 1];
    match file.read(&mut extra) {
        Ok(0) => Ok(bytes),
        Ok(_) => {
            bytes.zeroize();
            Err(format!("{label} changed while it was read"))
        }
        Err(error) => {
            bytes.zeroize();
            Err(format!("read {label} failed: {error}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_quote_ids_require_lowercase_exact_hex() {
        let id = "ab".repeat(32);
        assert_eq!(
            parse_quote_action_path(&format!("/v1/quotes/{id}/status"))
                .unwrap()
                .1,
            "status"
        );
        assert!(
            parse_quote_action_path(&format!("/v1/quotes/{}/status", id.to_uppercase())).is_none()
        );
        assert!(parse_quote_action_path(&format!("/v1/quotes/{id}/status?x=1")).is_none());
    }

    #[test]
    fn quote_key_routes_require_lowercase_exact_hex() {
        let id = "ab".repeat(16);
        assert_eq!(
            parse_quote_key_path(&format!("/v1/quote-keys/{id}")),
            Some([0xab; 16])
        );
        assert!(parse_quote_key_path(&format!("/v1/quote-keys/{}", id.to_uppercase())).is_none());
        assert!(parse_quote_key_path("/v1/quote-keys/current").is_none());
    }

    #[test]
    fn fake_server_refuses_non_loopback() {
        assert!(validate_loopback_bind("127.0.0.1:5610".parse().unwrap()).is_ok());
        assert!(validate_loopback_bind("[::1]:5610".parse().unwrap()).is_ok());
        assert!(validate_loopback_bind("0.0.0.0:5610".parse().unwrap()).is_err());
    }

    #[test]
    fn cors_origin_requires_one_canonical_exact_origin() {
        for accepted in [
            "https://bitcoinpir.org",
            "https://issuer.bitcoinpir.org:8443",
            "http://localhost:5173",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
        ] {
            assert!(validate_origin(accepted).is_ok(), "rejected {accepted}");
        }
        for rejected in [
            "https://bitcoinpir.org/",
            "https://bitcoinpir.org/path",
            "https://bitcoinpir.org?query",
            "https://bitcoinpir.org#fragment",
            "https://user@bitcoinpir.org",
            "https://bitcoinpir.org:443",
            "https://BITCOINPIR.ORG",
            "https://bitcoinpir.org.",
            "https://bitcoinpir.org:0443",
            "https://bitcoinpir.org:0",
            "http://example.com:8080",
            "http://localhost:80",
            "ftp://bitcoinpir.org",
            " https://bitcoinpir.org",
            "https://bitcoinpir.org\t",
            "https://bitcoinpir.org\r\nX-Evil: yes",
            "https://bitcoinpir.org https://evil.example",
        ] {
            assert!(validate_origin(rejected).is_err(), "accepted {rejected:?}");
        }
    }

    #[test]
    fn quote_rate_limiter_exhausts_and_resets_at_the_window_boundary() {
        let limiter = FixedWindowRateLimiterV1::new(2, "--test-rate").unwrap();
        let start = Instant::now();
        assert!(limiter.try_acquire(start));
        assert!(limiter.try_acquire(start + Duration::from_secs(59)));
        assert!(!limiter.try_acquire(start + Duration::from_secs(59)));
        assert!(limiter.try_acquire(start + Duration::from_secs(60)));
        assert!(FixedWindowRateLimiterV1::new(0, "--test-rate").is_err());
        assert!(
            FixedWindowRateLimiterV1::new(MAX_CONFIGURED_RATE_PER_MINUTE + 1, "--test-rate")
                .is_err()
        );
    }

    #[test]
    fn only_an_exact_durable_intent_digest_bypasses_quote_rate() {
        let exact = [0x11; 32];
        assert!(exact_intent_replay(Some(exact), exact));
        assert!(!exact_intent_replay(Some(exact), [0x12; 32]));
        assert!(!exact_intent_replay(None, exact));
    }

    #[test]
    fn production_mode_has_no_fake_settlement_backend() {
        let error = require_fake_settlement_backend(None).unwrap_err();
        assert_eq!(error.http_status(), 404);
        assert_eq!(error.public_code(), "not_found");
    }

    #[cfg(unix)]
    #[test]
    fn cli_exposes_cln_mode_without_fake_secret_arguments() {
        let cli = Cli::try_parse_from([
            "payment-issuer",
            "serve-cln",
            "--store",
            "/tmp/issuer.sqlite",
            "--rollback-authority",
            "/tmp/rollback.sqlite",
            "--quote-delegation",
            "/tmp/delegation.bin",
            "--quote-signing-key",
            "/tmp/quote.key",
            "--credential-derivation-key",
            "/tmp/credential.key",
            "--cln-rpc-socket",
            "/tmp/lightning-rpc",
            "--cln-rpc-expected-uid",
            "501",
        ])
        .unwrap();
        let Command::ServeCln(args) = cli.command else {
            panic!("expected serve-cln command");
        };
        assert_eq!(args.common.bind, "127.0.0.1:5610".parse().unwrap());
        assert_eq!(args.cln_rpc_expected_uid, 501);
        assert_eq!(args.cln_rpc_timeout_seconds, 10);
        assert_eq!(
            args.common.status_rate_per_minute,
            DEFAULT_STATUS_RATE_PER_MINUTE
        );
        assert_eq!(
            args.common.mutation_rate_per_minute,
            DEFAULT_MUTATION_RATE_PER_MINUTE
        );
        assert_eq!(
            args.common.reconciliation_rate_per_minute,
            DEFAULT_RECONCILIATION_RATE_PER_MINUTE
        );
        assert_eq!(
            args.common.reconciliation_batch_size,
            DEFAULT_RECONCILIATION_BATCH_SIZE
        );
    }

    #[cfg(unix)]
    fn write_secret(path: &Path, bytes: &[u8], mode: u32) {
        use std::os::unix::fs::PermissionsExt;

        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn secret_loader_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.key");
        let link = dir.path().join("link.key");
        write_secret(&target, &[0x11; 32], 0o600);
        symlink(&target, &link).unwrap();

        assert!(read_secret_exact::<32>(&link, "test key").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn secret_loader_rejects_group_or_world_access() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wide.key");
        write_secret(&path, &[0x22; 32], 0o640);

        let error = read_secret_exact::<32>(&path, "test key").unwrap_err();
        assert!(error.contains("group/world"));
    }

    #[cfg(unix)]
    #[test]
    fn secret_loader_rejects_wrong_length() {
        let dir = tempfile::tempdir().unwrap();
        let short = dir.path().join("short.key");
        let long = dir.path().join("long.key");
        write_secret(&short, &[0x33; 31], 0o600);
        write_secret(&long, &[0x44; 33], 0o600);

        assert!(read_secret_exact::<32>(&short, "test key").is_err());
        assert!(read_secret_exact::<32>(&long, "test key").is_err());
    }

    #[cfg(unix)]
    fn private_directory(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::create_dir_all(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[cfg(unix)]
    fn init_args(root: &Path) -> InitStoreArgs {
        let store_parent = root.join("issuer-domain");
        let authority_parent = root.join("rollback-domain");
        private_directory(&store_parent);
        private_directory(&authority_parent);
        InitStoreArgs {
            store: store_parent.join("issuer.sqlite3"),
            rollback_authority: authority_parent.join("floor.sqlite3"),
            issuer_id_hex: hex::encode([0x55; 32]),
            network: NetworkArg::Regtest,
        }
    }

    #[cfg(unix)]
    #[test]
    fn init_store_creates_owner_only_files_and_reopens_exact_state() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let args = init_args(directory.path());
        let store = args.store.clone();
        let authority = args.rollback_authority.clone();
        init_store(args).unwrap();

        for path in [&store, &authority] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let rollback = Arc::new(
            SqliteIssuerRollbackFloorAuthorityV1::open_existing(
                &authority,
                StoreOptions::default().busy_timeout,
            )
            .unwrap(),
        );
        let reopened = IssuerStore::open_existing(
            &store,
            [0x55; 32],
            LightningNetworkV1::Regtest,
            StoreOptions::default(),
            rollback,
        )
        .unwrap();
        let identity = reopened.identity().unwrap();
        assert_eq!(identity.issuer_id, [0x55; 32]);
        assert_eq!(identity.network, LightningNetworkV1::Regtest);
        assert_eq!(identity.commit_seq, 0);
        assert_eq!(identity.schema_version, ISSUER_STORE_SCHEMA_VERSION);
    }

    #[cfg(unix)]
    #[test]
    fn init_store_rejects_overwrite_public_parent_and_canonical_alias() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = tempfile::tempdir().unwrap();
        let args = init_args(directory.path());
        fs::write(&args.store, b"existing").unwrap();
        assert!(init_store(args).unwrap_err().contains("never overwrites"));

        let public_root = tempfile::tempdir().unwrap();
        let mut public = init_args(public_root.path());
        let public_parent = public_root.path().join("public");
        fs::create_dir(&public_parent).unwrap();
        fs::set_permissions(&public_parent, fs::Permissions::from_mode(0o755)).unwrap();
        public.store = public_parent.join("issuer.sqlite3");
        assert!(init_store(public).unwrap_err().contains("mode 0700"));

        let alias_root = tempfile::tempdir().unwrap();
        let real_parent = alias_root.path().join("real");
        private_directory(&real_parent);
        let alias_parent = alias_root.path().join("alias");
        symlink(&real_parent, &alias_parent).unwrap();
        let alias = InitStoreArgs {
            store: real_parent.join("same.sqlite3"),
            rollback_authority: alias_parent.join("same.sqlite3"),
            issuer_id_hex: hex::encode([0x66; 32]),
            network: NetworkArg::Regtest,
        };
        assert!(init_store(alias)
            .unwrap_err()
            .contains("same canonical target"));
    }

    #[cfg(unix)]
    #[test]
    fn serve_path_validation_rejects_symlink_public_mode_and_same_inode() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = tempfile::tempdir().unwrap();
        let private = directory.path().join("private");
        private_directory(&private);
        let file = private.join("issuer.sqlite3");
        fs::write(&file, b"state").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(
            validate_existing_private_database_path(&file, "issuer store")
                .unwrap_err()
                .contains("mode 0600")
        );

        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let link = private.join("issuer-link.sqlite3");
        symlink(&file, &link).unwrap();
        assert!(
            validate_existing_private_database_path(&link, "issuer store")
                .unwrap_err()
                .contains("non-symlink")
        );

        let public = directory.path().join("public");
        fs::create_dir(&public).unwrap();
        fs::set_permissions(&public, fs::Permissions::from_mode(0o755)).unwrap();
        let public_file = public.join("issuer.sqlite3");
        fs::write(&public_file, b"state").unwrap();
        fs::set_permissions(&public_file, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            validate_existing_private_database_path(&public_file, "issuer store")
                .unwrap_err()
                .contains("mode 0700")
        );

        let hard_link = private.join("authority.sqlite3");
        fs::hard_link(&file, &hard_link).unwrap();
        let canonical_file =
            validate_existing_private_database_path(&file, "issuer store").unwrap();
        let canonical_hard =
            validate_existing_private_database_path(&hard_link, "issuer rollback authority")
                .unwrap();
        assert!(private_database_paths_alias_v1(&canonical_file, &canonical_hard).unwrap());
    }
}
