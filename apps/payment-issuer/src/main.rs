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
    QuoteSigningMaterialV1, ReceiptSigningMaterialV1, SettlementPayoutPolicyV1,
    SharedIssuerClearingServiceV1, TrustedClearingProviderV1,
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
    ProviderPayoutEnvelopeV1, ProviderPayoutIntentEnvelopeV1, ProviderPayoutStatusEnvelopeV1,
    ProviderRedeemEnvelopeV1, ServicePolicyV1, SettlementModesV1, SettlementUnitV1,
    MAX_BOLT11_QUOTE_CLAIM_ENVELOPE_LEN_V1, MAX_BOLT11_QUOTE_INTENT_LEN,
    MAX_BOLT11_QUOTE_KEY_DELEGATION_LEN, MAX_BOLT11_QUOTE_STATUS_REQUEST_LEN,
    MAX_CREDENTIAL_ISSUANCE_RESPONSE_LEN_V1, MAX_EXECUTABLE_SETTLEMENT_HTTP_ENVELOPE_LEN_V1,
    MAX_PROVIDER_REDEEM_ENVELOPE_LEN_V1,
};
use zeroize::{Zeroize, Zeroizing};

const MAX_HEADER_BYTES: usize = 16 * 1024;
// The only 320 KiB settlement envelope is the 64-note deposit model, which
// this executable does not serve. Keep the public listener capped by the
// larger of the actually executable claim/redeem/ledger-only surfaces.
const MAX_HTTP_BODY_BYTES: usize = MAX_BOLT11_QUOTE_CLAIM_ENVELOPE_LEN_V1;
const _: () = assert!(MAX_PROVIDER_REDEEM_ENVELOPE_LEN_V1 <= MAX_HTTP_BODY_BYTES);
const _: () = assert!(MAX_EXECUTABLE_SETTLEMENT_HTTP_ENVELOPE_LEN_V1 <= MAX_HTTP_BODY_BYTES);
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
const CT_BALANCE_ENVELOPE: &str = "application/vnd.bitcoinpir.provider-balance-envelope-v1";
const CT_BALANCE_RESPONSE: &str = "application/vnd.bitcoinpir.issuer-balance-response-v1";
const CT_PAYOUT_INTENT_ENVELOPE: &str =
    "application/vnd.bitcoinpir.provider-payout-intent-envelope-v1";
const CT_PAYOUT_INTENT_RESPONSE: &str =
    "application/vnd.bitcoinpir.issuer-payout-intent-response-v1";
const CT_PAYOUT_ENVELOPE: &str = "application/vnd.bitcoinpir.provider-payout-envelope-v1";
const CT_PAYOUT_RESPONSE: &str = "application/vnd.bitcoinpir.issuer-payout-response-v1";
const CT_PAYOUT_STATUS_ENVELOPE: &str =
    "application/vnd.bitcoinpir.provider-payout-status-envelope-v1";
const CT_PAYOUT_STATUS_RESPONSE: &str =
    "application/vnd.bitcoinpir.issuer-payout-status-response-v1";

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
    /// Run the production issuer-store open/integrity path without a listener.
    /// May reconcile one legitimate unanchored successor, like serving startup.
    CheckStore(StoreCheckArgs),
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
struct StoreCheckArgs {
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
    /// Repeat one retained raw Ed25519 settlement verifying key for recovery
    /// of payouts accepted before a signing-key rotation.
    #[arg(long = "retained-issuer-settlement-verifying-key")]
    retained_issuer_settlement_verifying_keys: Vec<PathBuf>,
    /// Independent deterministic redeem-response derivation key.
    #[arg(long)]
    redeem_response_derivation_key: Option<PathBuf>,
    /// Commercial issuer fee, in the authorization's settlement unit, quoted
    /// only in newly signed provider payout intents.
    #[arg(long)]
    clearing_payout_fee: Option<u64>,
    /// Validity of a newly signed payout intent. Required explicitly so
    /// commercial policy is never inferred from credential entitlement.
    #[arg(long)]
    clearing_payout_intent_ttl_seconds: Option<u64>,
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
    #[cfg(test)]
    now_unix_override: Option<u64>,
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

fn is_exact_payout_intent_replay(store: &IssuerStore, canonical_envelope: &[u8]) -> bool {
    let Ok(envelope) = ProviderPayoutIntentEnvelopeV1::decode(canonical_envelope) else {
        return false;
    };
    store
        .payout_intent_by_idempotency(&envelope.request)
        .is_ok_and(|existing| existing.is_some())
}

fn is_exact_payout_replay(store: &IssuerStore, canonical_envelope: &[u8]) -> bool {
    let Ok(envelope) = ProviderPayoutEnvelopeV1::decode(canonical_envelope) else {
        return false;
    };
    store
        .payout_by_idempotency(&envelope.request)
        .is_ok_and(|existing| existing.is_some())
}

fn is_exact_payout_status_replay(store: &IssuerStore, canonical_envelope: &[u8]) -> bool {
    let Ok(envelope) = ProviderPayoutStatusEnvelopeV1::decode(canonical_envelope) else {
        return false;
    };
    let Ok(request_digest) = envelope.request.request_digest() else {
        return false;
    };
    let Ok(Some(record)) = store.payout_by_id(&envelope.request.payout_id) else {
        return false;
    };
    let Some(exact) = record.exact_latest_status_response else {
        return false;
    };
    pir_service_protocol::IssuerPayoutStatusResponseV1::decode(&exact)
        .is_ok_and(|response| response.request_digest == request_digest)
}

fn main() {
    let result = match Cli::parse().command {
        Command::InitStore(args) => init_store(args),
        Command::CheckStore(args) => check_store(args),
        Command::ServeFake(args) => serve_fake(args),
        #[cfg(unix)]
        Command::ServeCln(args) => serve_cln(args),
    };
    if let Err(error) = result {
        eprintln!("payment-issuer: {error}");
        std::process::exit(1);
    }
}

fn check_store(args: StoreCheckArgs) -> Result<(), String> {
    let issuer_id = decode_fixed_hex::<32>(&args.issuer_id_hex, "issuer ID")?;
    if issuer_id.iter().all(|byte| *byte == 0) {
        return Err("issuer ID must not be all zero".to_owned());
    }
    let store_path = validate_existing_private_database_path(&args.store, "issuer store")?;
    let authority_path = validate_existing_private_database_path(
        &args.rollback_authority,
        "issuer rollback authority",
    )?;
    if private_database_paths_alias_v1(&store_path, &authority_path)? {
        return Err("store and rollback authority resolve to the same file/inode".to_owned());
    }

    let options = StoreOptions::default();
    let started = Instant::now();
    let authority =
        SqliteIssuerRollbackFloorAuthorityV1::open_existing(&authority_path, options.busy_timeout)
            .map_err(|error| format!("open issuer rollback authority: {error}"))?;
    let store = IssuerStore::open_existing(
        &store_path,
        issuer_id,
        args.network.into(),
        options,
        Arc::new(authority),
    )
    .map_err(|error| format!("open issuer store: {error}"))?;
    let identity = store
        .identity()
        .map_err(|error| format!("read issuer store identity: {error}"))?;
    let inventory = store
        .operational_inventory()
        .map_err(|error| format!("read issuer store inventory: {error}"))?;

    println!("issuer_id={}", hex::encode(identity.issuer_id));
    println!(
        "store_instance_id={}",
        hex::encode(identity.store_instance_id)
    );
    println!("schema_version={}", identity.schema_version);
    println!("commit_seq={}", inventory.observed_commit_seq);
    println!("startup_check_ms={}", started.elapsed().as_millis());
    println!("quote_rows={}", inventory.quote_rows);
    println!("claim_rows={}", inventory.claim_rows);
    println!("retained_policy_rows={}", inventory.retained_policy_rows);
    println!("redemption_rows={}", inventory.redemption_rows);
    println!("payout_rows={}", inventory.payout_rows);
    Ok(())
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
    let store_startup_check_started = Instant::now();
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
    let store_inventory = store
        .operational_inventory()
        .map_err(|error| format!("read issuer store operational inventory failed: {error}"))?;
    println!(
        "issuer_store_startup_check_ms={} commit_seq={} quote_rows={} claim_rows={} retained_policy_rows={} redemption_rows={} payout_rows={}",
        store_startup_check_started.elapsed().as_millis(),
        store_inventory.observed_commit_seq,
        store_inventory.quote_rows,
        store_inventory.claim_rows,
        store_inventory.retained_policy_rows,
        store_inventory.redemption_rows,
        store_inventory.payout_rows,
    );

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
        #[cfg(test)]
        now_unix_override: None,
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
        || !args.retained_issuer_settlement_verifying_keys.is_empty()
        || args.redeem_response_derivation_key.is_some()
        || args.clearing_payout_fee.is_some()
        || args.clearing_payout_intent_ttl_seconds.is_some();
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
    let payout_fee = args
        .clearing_payout_fee
        .ok_or_else(|| "clearing requires explicit --clearing-payout-fee".to_owned())?;
    let payout_intent_ttl_seconds = args.clearing_payout_intent_ttl_seconds.ok_or_else(|| {
        "clearing requires explicit --clearing-payout-intent-ttl-seconds".to_owned()
    })?;
    let payout_policy = SettlementPayoutPolicyV1::new(payout_fee, payout_intent_ttl_seconds)
        .map_err(|_| "clearing payout fee or intent TTL is outside V1 bounds".to_owned())?;

    let mut settlement_key_bytes =
        read_secret_exact::<32>(settlement_key_path, "issuer settlement signing key")?;
    let issuer_settlement_signing_key = SigningKey::from_bytes(&settlement_key_bytes);
    settlement_key_bytes.zeroize();
    let settlement_verifying_key = issuer_settlement_signing_key.verifying_key();
    let mut retained_settlement_verifying_keys =
        Vec::with_capacity(args.retained_issuer_settlement_verifying_keys.len());
    for path in &args.retained_issuer_settlement_verifying_keys {
        let exact = read_public_file(path, 32, "retained issuer settlement verifying key")?;
        let bytes: [u8; 32] = exact
            .try_into()
            .map_err(|_| "retained issuer settlement verifying key must be 32 bytes".to_owned())?;
        retained_settlement_verifying_keys.push(
            VerifyingKey::from_bytes(&bytes)
                .map_err(|_| "retained issuer settlement verifying key is invalid".to_owned())?,
        );
    }

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
        retained_settlement_verifying_keys,
        None,
        Vec::new(),
        response_derivation_key,
        payout_policy,
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
    #[cfg(test)]
    let now_unix = state
        .now_unix_override
        .map(Ok)
        .unwrap_or_else(system_time_unix)
        .map_err(|_| IssuerServiceErrorV1::Internal)?;
    #[cfg(not(test))]
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
        "/v1/settlement/balance" => {
            require_executable_settlement_request(request, CT_BALANCE_ENVELOPE)?;
            if !state.status_rate.try_acquire(Instant::now()) {
                return Err(IssuerServiceErrorV1::RetryableUnavailable);
            }
            state
                .clearing
                .as_ref()
                .ok_or(IssuerServiceErrorV1::NotFound)?
                .balance(&request.body, now_unix)
                .map(|body| (CT_BALANCE_RESPONSE, body))
        }
        "/v1/settlement/payout-intents" => {
            require_executable_settlement_request(request, CT_PAYOUT_INTENT_ENVELOPE)?;
            if !is_exact_payout_intent_replay(&state.store, &request.body)
                && !state.mutation_rate.try_acquire(Instant::now())
            {
                return Err(IssuerServiceErrorV1::RetryableUnavailable);
            }
            state
                .clearing
                .as_ref()
                .ok_or(IssuerServiceErrorV1::NotFound)?
                .payout_intent(&request.body, now_unix)
                .map(|body| (CT_PAYOUT_INTENT_RESPONSE, body))
        }
        "/v1/settlement/payouts" => {
            require_executable_settlement_request(request, CT_PAYOUT_ENVELOPE)?;
            if !is_exact_payout_replay(&state.store, &request.body)
                && !state.mutation_rate.try_acquire(Instant::now())
            {
                return Err(IssuerServiceErrorV1::RetryableUnavailable);
            }
            state
                .clearing
                .as_ref()
                .ok_or(IssuerServiceErrorV1::NotFound)?
                .payout(&request.body, now_unix)
                .map(|body| (CT_PAYOUT_RESPONSE, body))
        }
        "/v1/settlement/payout-status" => {
            require_executable_settlement_request(request, CT_PAYOUT_STATUS_ENVELOPE)?;
            if !is_exact_payout_status_replay(&state.store, &request.body)
                && !state.status_rate.try_acquire(Instant::now())
            {
                return Err(IssuerServiceErrorV1::RetryableUnavailable);
            }
            state
                .clearing
                .as_ref()
                .ok_or(IssuerServiceErrorV1::NotFound)?
                .payout_status(&request.body, now_unix)
                .map(|body| (CT_PAYOUT_STATUS_RESPONSE, body))
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

fn require_executable_settlement_request(
    request: &ParsedRequest,
    expected_content_type: &str,
) -> Result<(), IssuerServiceErrorV1> {
    require_content_type(request, expected_content_type)?;
    if request.body.len() > MAX_EXECUTABLE_SETTLEMENT_HTTP_ENVELOPE_LEN_V1 {
        return Err(IssuerServiceErrorV1::InvalidRequest);
    }
    Ok(())
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
    use pir_payment_crypto::{cashu_hash_to_curve_v1, sign_bip340_prehash_v1};
    use pir_service_protocol::{
        bind_auth_begin_v1, credential_presentation_digest, derive_bat_key_id_v1, derive_issuer_id,
        paid_receipt_key_id, AcquisitionMethod, AuthBeginV1, AuthPaddingClassV1, BackendId,
        BitcoinPirCashuBatProofV1, Bolt11QuoteClaimV1, Bolt11QuoteKeyRollbackGuardV1,
        Bolt11QuoteStatusRequestV1, Bolt11QuoteStatusV1, Bolt11QuoteV1,
        CheckedCredentialIssuanceResponseV1, CredentialIssuanceRequestItemsV1,
        CredentialIssuanceRequestV1, CredentialIssuanceResponseV1, CredentialKeyBindingClaimsV1,
        CredentialKeyBindingV1, CredentialUnitV1, DatasetBindingV1, DeploymentStatus,
        EntitlementLimitsV1, FreeModeV1, IssuerBalanceResponseV1, IssuerPayoutIntentResponseV1,
        IssuerPayoutResponseV1, IssuerPayoutStatusResponseV1, OperationStartV1,
        ParsedBolt11InvoiceV1, PayoutStateV1, PolicyRollbackGuardV1, PriceV1, PrivacyLeakageV1,
        ProviderBalanceEnvelopeV1, ProviderBalanceRequestV1, ProviderClearingAuthorizationClaimsV1,
        ProviderClearingRequestAuthV1, ProviderPayoutIntentRequestV1, ProviderPayoutRequestV1,
        ProviderPayoutStatusRequestV1, ProviderRedeemRequestV1, ProviderSettlementRequestAuthV1,
        ServiceOfferV1, ServicePolicyEpochFloorsV1, ServiceScopePolicyV1, ServiceScopeV1,
        SettlementDestinationV1, SettlementRuleV1, TrustedCatalogResolutionV1, VerificationMode,
        WorkloadId,
    };
    use pir_service_store::{
        verify_provider_local_bearer_spend_v1, ProviderStore, SqliteRollbackFloorAuthorityV1,
        StoreError as ProviderStoreError, StoreOptions as ProviderStoreOptions,
    };

    fn http_exchange(
        state: Arc<ServerState>,
        method: &str,
        path: &str,
        request_content_type: Option<&str>,
        accept: &str,
        body: &[u8],
    ) -> (u16, String, Vec<u8>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test issuer listener");
        let address = listener.local_addr().expect("test issuer address");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept test issuer request");
            handle_connection(stream, &state);
        });

        let mut stream = TcpStream::connect(address).expect("connect test issuer");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set client read timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .expect("set client write timeout");
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {address}\r\nAccept: {accept}\r\nConnection: close\r\nContent-Length: {}\r\n",
            body.len()
        );
        if let Some(content_type) = request_content_type {
            request.push_str(&format!("Content-Type: {content_type}\r\n"));
        }
        request.push_str("\r\n");
        stream
            .write_all(request.as_bytes())
            .expect("write test issuer headers");
        stream.write_all(body).expect("write test issuer body");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .expect("read test issuer response");
        server.join().expect("test issuer server thread");

        let header_end = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
            .expect("HTTP response header terminator");
        let header = std::str::from_utf8(&response[..header_end]).expect("ASCII HTTP response");
        let mut lines = header.split("\r\n");
        let status = lines
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse::<u16>().ok())
            .expect("HTTP response status");
        let mut content_type = None;
        let mut content_length = None;
        for line in lines {
            if let Some(value) = line.strip_prefix("Content-Type: ") {
                content_type = Some(value.to_owned());
            }
            if let Some(value) = line.strip_prefix("Content-Length: ") {
                content_length = value.parse::<usize>().ok();
            }
        }
        let response_body = response[header_end..].to_vec();
        assert_eq!(content_length, Some(response_body.len()));
        (
            status,
            content_type.expect("HTTP response content type"),
            response_body,
        )
    }

    fn wait_until_after(timestamp: u64) -> u64 {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let now = system_time_unix().expect("system clock");
            if now > timestamp {
                return now;
            }
            assert!(Instant::now() < deadline, "system clock did not advance");
            thread::sleep(Duration::from_millis(10));
        }
    }

    const SETTLEMENT_HTTP_PROVIDER_ID: [u8; 32] = [0x71; 32];
    const SETTLEMENT_HTTP_SCOPE_ID: [u8; 32] = [0x72; 32];
    const SETTLEMENT_HTTP_ACCOUNT_ID: [u8; 32] = [0x73; 32];
    const SETTLEMENT_HTTP_PAYOUT_TARGET_ID: [u8; 32] = [0x74; 32];
    const SETTLEMENT_HTTP_ISSUER_ROOT: [u8; 32] = [0x75; 32];
    const SETTLEMENT_HTTP_QUOTE_KEY: [u8; 32] = [0x76; 32];
    const SETTLEMENT_HTTP_OPERATOR_KEY: [u8; 32] = [0x77; 32];
    const SETTLEMENT_HTTP_CLEARING_KEY: [u8; 32] = [0x78; 32];
    const SETTLEMENT_HTTP_PROVIDER_REQUEST_KEY: [u8; 32] = [0x79; 32];
    const SETTLEMENT_HTTP_SIGNING_KEY: [u8; 32] = [0x7a; 32];
    const SETTLEMENT_HTTP_BAT_KEY: [u8; 32] = [0x7b; 32];

    struct SettlementHttpFixture {
        _directory: tempfile::TempDir,
        store_path: PathBuf,
        rollback_path: PathBuf,
        issuer_id: [u8; 32],
        binding: CredentialKeyBindingV1,
        authorization: ProviderClearingAuthorizationV1,
        now_unix: u64,
        registration_not_after: u64,
    }

    impl SettlementHttpFixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("settlement HTTP directory");
            let store_path = directory.path().join("issuer.sqlite3");
            let rollback_path = directory.path().join("issuer-floor.sqlite3");
            let now_unix = system_time_unix().expect("system clock");
            let not_before = now_unix.saturating_sub(60);
            let registration_not_after = now_unix + 120;
            let issuer_root = SigningKey::from_bytes(&SETTLEMENT_HTTP_ISSUER_ROOT);
            let issuer_id = derive_issuer_id(&issuer_root.verifying_key().to_bytes());
            let rollback = Arc::new(
                SqliteIssuerRollbackFloorAuthorityV1::create(
                    &rollback_path,
                    StoreOptions::default().busy_timeout,
                )
                .expect("settlement HTTP rollback floor"),
            );
            let store = IssuerStore::create(
                &store_path,
                [0x31; 16],
                issuer_id,
                LightningNetworkV1::Regtest,
                StoreOptions::default(),
                rollback,
            )
            .expect("settlement HTTP issuer store");
            let provider_request = SigningKey::from_bytes(&SETTLEMENT_HTTP_PROVIDER_REQUEST_KEY);
            let _ = store
                .register_provider_settlement(&ProviderSettlementRegistrationWriteV1 {
                    registration_epoch: 1,
                    provider_id: SETTLEMENT_HTTP_PROVIDER_ID,
                    settlement_account_id: SETTLEMENT_HTTP_ACCOUNT_ID,
                    provider_request_verifying_key: provider_request.verifying_key().to_bytes(),
                    payout_target_id: SETTLEMENT_HTTP_PAYOUT_TARGET_ID,
                    not_before,
                    not_after: registration_not_after,
                })
                .expect("register settlement HTTP provider");

            let bat_keyring = Self::bat_keyring();
            let bat_public_key = bat_keyring.denomination_public_keys()[0];
            let credential_key_id = derive_bat_key_id_v1(
                &SETTLEMENT_HTTP_PROVIDER_ID,
                &SETTLEMENT_HTTP_SCOPE_ID,
                7,
                9,
                1,
                &bat_public_key,
            );
            let binding = CredentialKeyBindingV1::sign(
                CredentialKeyBindingClaimsV1 {
                    provider_id: SETTLEMENT_HTTP_PROVIDER_ID,
                    scope_id: SETTLEMENT_HTTP_SCOPE_ID,
                    offer_id: 7,
                    scheme: AuthScheme::BitcoinPirCashuBatV1,
                    keyset_epoch: 1,
                    entitlement_profile: 9,
                    unit: CredentialUnitV1::Auth,
                    amount: 1,
                    presentation_limit: 1,
                    not_before,
                    not_after: registration_not_after,
                    credential_key_id: credential_key_id.to_vec(),
                    verification_key: bat_public_key.to_vec(),
                },
                &issuer_root,
            )
            .expect("settlement HTTP BAT binding");
            let _ = store
                .register_bat_key_lineage(&BatKeyLineageRegistration {
                    raw_public_key: bat_public_key,
                    provider_id: SETTLEMENT_HTTP_PROVIDER_ID,
                    scope_id: SETTLEMENT_HTTP_SCOPE_ID,
                    offer_id: 7,
                    entitlement_profile: 9,
                    keyset_epoch: 1,
                    credential_key_id,
                })
                .expect("register settlement HTTP BAT lineage");

            let operator = SigningKey::from_bytes(&SETTLEMENT_HTTP_OPERATOR_KEY);
            let clearing = SigningKey::from_bytes(&SETTLEMENT_HTTP_CLEARING_KEY);
            let settlement = SigningKey::from_bytes(&SETTLEMENT_HTTP_SIGNING_KEY);
            let authorization = ProviderClearingAuthorizationV1::sign(
                ProviderClearingAuthorizationClaimsV1 {
                    authorization_id: [0x7c; 16],
                    authorization_epoch: 1,
                    provider_id: SETTLEMENT_HTTP_PROVIDER_ID,
                    issuer_id,
                    settlement_account_id: SETTLEMENT_HTTP_ACCOUNT_ID,
                    clearing_verifying_key: clearing.verifying_key().to_bytes(),
                    not_before,
                    not_after: registration_not_after,
                    rules: vec![SettlementRuleV1 {
                        credential_binding_digest: binding
                            .binding_digest()
                            .expect("settlement HTTP binding digest"),
                        unit: SettlementUnitV1::AuthCredit,
                        accepted_value: 10,
                        provider_credit: 9,
                        issuer_fee: 1,
                        denomination_profile: 1,
                        settlement_modes: SettlementModesV1::from_bits(
                            SettlementModesV1::LEDGER_CREDIT,
                        )
                        .expect("ledger-only settlement mode"),
                        blind_output_minimum_validity_seconds: 0,
                        blind_output_keyset: None,
                    }],
                },
                &operator,
            )
            .expect("settlement HTTP authorization");
            let approval = IssuerClearingApprovalV1::sign(
                &authorization,
                not_before,
                registration_not_after,
                &settlement,
            )
            .expect("settlement HTTP approval");
            let _ = store
                .register_clearing_authorization(
                    &authorization,
                    &approval,
                    &operator.verifying_key(),
                    &settlement.verifying_key(),
                    now_unix,
                )
                .expect("register settlement HTTP authorization");
            drop(store);

            Self {
                _directory: directory,
                store_path,
                rollback_path,
                issuer_id,
                binding,
                authorization,
                now_unix,
                registration_not_after,
            }
        }

        fn bat_keyring() -> Arc<K256CashuMintKeyringV1> {
            Arc::new(
                K256CashuMintKeyringV1::from_secret_keys([SETTLEMENT_HTTP_BAT_KEY])
                    .expect("settlement HTTP BAT keyring"),
            )
        }

        fn credential(&self) -> Vec<u8> {
            let secret_raw = [0x7d; 32];
            let hashed = cashu_hash_to_curve_v1(&secret_raw).expect("hash settlement HTTP BAT");
            let keyring = Self::bat_keyring();
            let signed = keyring
                .blind_sign_with_dleq_v1(
                    &keyring.denomination_public_keys()[0],
                    &hashed,
                    &[0x7e; 32],
                )
                .expect("sign settlement HTTP BAT");
            BitcoinPirCashuBatProofV1 {
                secret_raw,
                c: *signed.blinded_signature(),
            }
            .encode()
            .expect("encode settlement HTTP BAT")
            .to_vec()
        }

        fn state(&self, now_unix_override: u64) -> Arc<ServerState> {
            let rollback = Arc::new(
                SqliteIssuerRollbackFloorAuthorityV1::open_existing(
                    &self.rollback_path,
                    StoreOptions::default().busy_timeout,
                )
                .expect("reopen settlement HTTP rollback floor"),
            );
            let store = IssuerStore::open_existing(
                &self.store_path,
                self.issuer_id,
                LightningNetworkV1::Regtest,
                StoreOptions::default(),
                rollback,
            )
            .expect("reopen settlement HTTP issuer store");
            let fake_lightning = Arc::new(
                FakeLightningNodeV1::new(
                    LightningNetworkV1::Regtest,
                    [0x13; 32],
                    [0x14; 32],
                    self.now_unix.saturating_sub(10),
                )
                .expect("settlement HTTP fake Lightning"),
            );
            let issuer_root = SigningKey::from_bytes(&SETTLEMENT_HTTP_ISSUER_ROOT);
            let quote_signing_key = SigningKey::from_bytes(&SETTLEMENT_HTTP_QUOTE_KEY);
            let delegation = Bolt11QuoteKeyDelegationV1::sign(
                LightningNetworkV1::Regtest,
                fake_lightning.payee_pubkey(),
                1,
                self.now_unix.saturating_sub(60),
                self.now_unix + 3_600,
                quote_signing_key.verifying_key().to_bytes(),
                &issuer_root,
            )
            .expect("settlement HTTP quote delegation");
            let delegation_bytes = delegation.encode().expect("encode quote delegation");
            let bat_keyring = Self::bat_keyring();
            let acquisition = IssuerAcquisitionServiceV1::new_with_quote_capacity(
                store.clone(),
                Arc::new(RuntimeLightningBackendV1::Fake(fake_lightning)),
                Arc::new(OsQuoteIdSourceV1),
                QuoteSigningMaterialV1::new(delegation.clone(), quote_signing_key)
                    .expect("settlement HTTP quote material"),
                Vec::new(),
                Vec::new(),
                Some(Arc::clone(&bat_keyring)),
                None,
                IssuerCredentialDerivationKeyV1::from_bytes([0x15; 32])
                    .expect("settlement HTTP credential derivation"),
                QuoteCapacityV1::new(16, 128).expect("settlement HTTP quote capacity"),
                self.now_unix,
            )
            .expect("settlement HTTP acquisition service");
            let clearing = SharedIssuerClearingServiceV1::new(
                store.clone(),
                vec![TrustedClearingProviderV1 {
                    provider_id: SETTLEMENT_HTTP_PROVIDER_ID,
                    operator_key: SigningKey::from_bytes(&SETTLEMENT_HTTP_OPERATOR_KEY)
                        .verifying_key(),
                    minimum_authorization_epoch: 1,
                }],
                Some(bat_keyring),
                None,
                SigningKey::from_bytes(&SETTLEMENT_HTTP_SIGNING_KEY),
                Vec::new(),
                None,
                Vec::new(),
                RedeemResponseDerivationKeyV1::from_bytes([0x16; 32])
                    .expect("settlement HTTP response derivation"),
                SettlementPayoutPolicyV1::new(2, 100).expect("settlement HTTP payout policy"),
            )
            .expect("settlement HTTP clearing service");
            Arc::new(ServerState {
                acquisition,
                current_quote_delegation: delegation_bytes.clone(),
                quote_delegations: BTreeMap::from([(delegation.quote_key_id, delegation_bytes)]),
                clearing: Some(clearing),
                store,
                fake_lightning: None,
                allow_origin: None,
                quote_rate: FixedWindowRateLimiterV1::new(100, "settlement HTTP quote rate")
                    .expect("settlement HTTP quote rate"),
                status_rate: FixedWindowRateLimiterV1::new(100, "settlement HTTP status rate")
                    .expect("settlement HTTP status rate"),
                mutation_rate: FixedWindowRateLimiterV1::new(100, "settlement HTTP mutation rate")
                    .expect("settlement HTTP mutation rate"),
                now_unix_override: Some(now_unix_override),
            })
        }
    }

    #[test]
    fn shared_issuer_settlement_http_roundtrip_restarts_and_replays_after_expiry() {
        let fixture = SettlementHttpFixture::new();
        let state = fixture.state(fixture.now_unix);
        let oversized_ledger_envelope = [0; MAX_EXECUTABLE_SETTLEMENT_HTTP_ENVELOPE_LEN_V1 + 1];
        let (status, _, _) = http_exchange(
            Arc::clone(&state),
            "POST",
            "/v1/settlement/balance",
            Some(CT_BALANCE_ENVELOPE),
            CT_BALANCE_RESPONSE,
            &oversized_ledger_envelope,
        );
        assert_eq!(status, 400, "ledger-only route enforces its 8 KiB cap");
        let (status, _, _) = http_exchange(
            Arc::clone(&state),
            "GET",
            "/v1/settlement/keysets",
            None,
            "application/octet-stream",
            &[],
        );
        assert_eq!(status, 404, "settlement keysets are not executable");
        let (status, _, _) = http_exchange(
            Arc::clone(&state),
            "POST",
            "/v1/settlement/deposits",
            Some("application/vnd.bitcoinpir.provider-settlement-deposit-envelope-v1"),
            "application/octet-stream",
            &[],
        );
        assert_eq!(status, 404, "settlement deposits are not executable");
        let authorization_digest = fixture
            .authorization
            .authorization_digest()
            .expect("settlement HTTP authorization digest");
        let clearing = SigningKey::from_bytes(&SETTLEMENT_HTTP_CLEARING_KEY);
        let provider_request = SigningKey::from_bytes(&SETTLEMENT_HTTP_PROVIDER_REQUEST_KEY);

        let credential = fixture.credential();
        let redeem_request = ProviderRedeemRequestV1 {
            authorization_digest,
            issuer_id: fixture.issuer_id,
            provider_id: SETTLEMENT_HTTP_PROVIDER_ID,
            scope_id: SETTLEMENT_HTTP_SCOPE_ID,
            offer_id: 7,
            credential_binding_digest: fixture
                .binding
                .binding_digest()
                .expect("settlement HTTP binding digest"),
            scheme: AuthScheme::BitcoinPirCashuBatV1,
            credential_digest: credential_presentation_digest(
                AuthScheme::BitcoinPirCashuBatV1,
                &credential,
            )
            .expect("settlement HTTP credential digest"),
            accepted_value: 10,
            denomination_profile: 1,
            idempotency_key: [0x81; 32],
            destination: SettlementDestinationV1::LedgerCredit {
                account_id: SETTLEMENT_HTTP_ACCOUNT_ID,
            },
        };
        let redeem_envelope = ProviderRedeemEnvelopeV1 {
            request_auth: ProviderClearingRequestAuthV1::sign(
                authorization_digest,
                redeem_request
                    .request_digest()
                    .expect("settlement HTTP redeem digest"),
                &clearing,
            ),
            request: redeem_request,
            credential_binding: fixture.binding.clone(),
            canonical_credential: credential.clone(),
        }
        .encode()
        .expect("settlement HTTP redeem envelope");
        let (status, content_type, redeem_response) = http_exchange(
            Arc::clone(&state),
            "POST",
            "/v1/redeems",
            Some(CT_REDEEM),
            CT_REDEEM_RESULT,
            &redeem_envelope,
        );
        assert_eq!((status, content_type.as_str()), (200, CT_REDEEM_RESULT));
        assert!(
            !redeem_response
                .windows(credential.len())
                .any(|window| window == credential.as_slice()),
            "issuer response must not echo the bearer credential"
        );
        let (status, content_type, replayed_redeem) = http_exchange(
            Arc::clone(&state),
            "POST",
            "/v1/redeems",
            Some(CT_REDEEM),
            CT_REDEEM_RESULT,
            &redeem_envelope,
        );
        assert_eq!((status, content_type.as_str()), (200, CT_REDEEM_RESULT));
        assert_eq!(replayed_redeem, redeem_response);

        let balance_request = ProviderBalanceRequestV1 {
            authorization_digest,
            issuer_id: fixture.issuer_id,
            provider_id: SETTLEMENT_HTTP_PROVIDER_ID,
            account_id: SETTLEMENT_HTTP_ACCOUNT_ID,
            unit: SettlementUnitV1::AuthCredit,
            idempotency_key: [0x82; 32],
        };
        let balance_envelope = ProviderBalanceEnvelopeV1 {
            request_auth: ProviderClearingRequestAuthV1::sign(
                authorization_digest,
                balance_request
                    .request_digest()
                    .expect("settlement HTTP balance digest"),
                &clearing,
            ),
            request: balance_request.clone(),
        }
        .encode()
        .expect("settlement HTTP balance envelope");
        let (status, content_type, balance_response) = http_exchange(
            Arc::clone(&state),
            "POST",
            "/v1/settlement/balance",
            Some(CT_BALANCE_ENVELOPE),
            CT_BALANCE_RESPONSE,
            &balance_envelope,
        );
        assert_eq!((status, content_type.as_str()), (200, CT_BALANCE_RESPONSE));
        let balance = IssuerBalanceResponseV1::decode(&balance_response)
            .expect("decode settlement HTTP balance");
        assert_eq!((balance.available_value, balance.reserved_value), (9, 0));

        let intent_request = ProviderPayoutIntentRequestV1 {
            authorization_digest,
            issuer_id: fixture.issuer_id,
            provider_id: SETTLEMENT_HTTP_PROVIDER_ID,
            account_id: SETTLEMENT_HTTP_ACCOUNT_ID,
            payout_target_id: SETTLEMENT_HTTP_PAYOUT_TARGET_ID,
            unit: SettlementUnitV1::AuthCredit,
            payout_value: 7,
            idempotency_key: [0x83; 32],
        };
        let intent_envelope = ProviderPayoutIntentEnvelopeV1 {
            request_auth: ProviderClearingRequestAuthV1::sign(
                authorization_digest,
                intent_request
                    .request_digest()
                    .expect("settlement HTTP intent digest"),
                &clearing,
            ),
            request: intent_request.clone(),
        }
        .encode()
        .expect("settlement HTTP payout-intent envelope");
        let (status, content_type, intent_response_bytes) = http_exchange(
            Arc::clone(&state),
            "POST",
            "/v1/settlement/payout-intents",
            Some(CT_PAYOUT_INTENT_ENVELOPE),
            CT_PAYOUT_INTENT_RESPONSE,
            &intent_envelope,
        );
        assert_eq!(
            (status, content_type.as_str()),
            (200, CT_PAYOUT_INTENT_RESPONSE)
        );
        let intent_response = IssuerPayoutIntentResponseV1::decode(&intent_response_bytes)
            .expect("decode settlement HTTP payout intent");
        assert_eq!(
            (intent_response.issuer_fee, intent_response.total_debit),
            (2, 9)
        );
        let (status, _, replayed_intent) = http_exchange(
            Arc::clone(&state),
            "POST",
            "/v1/settlement/payout-intents",
            Some(CT_PAYOUT_INTENT_ENVELOPE),
            CT_PAYOUT_INTENT_RESPONSE,
            &intent_envelope,
        );
        assert_eq!(status, 200);
        assert_eq!(replayed_intent, intent_response_bytes);

        let payout_request = ProviderPayoutRequestV1 {
            authorization_digest,
            issuer_id: fixture.issuer_id,
            provider_id: SETTLEMENT_HTTP_PROVIDER_ID,
            account_id: SETTLEMENT_HTTP_ACCOUNT_ID,
            payout_target_id: SETTLEMENT_HTTP_PAYOUT_TARGET_ID,
            payout_intent_id: intent_response.payout_intent_id,
            payout_intent_digest: intent_response
                .payout_intent_digest()
                .expect("settlement HTTP signed intent digest"),
            unit: SettlementUnitV1::AuthCredit,
            payout_value: 7,
            total_debit: 9,
            idempotency_key: [0x84; 32],
        };
        let payout_envelope = ProviderPayoutEnvelopeV1 {
            request_auth: ProviderClearingRequestAuthV1::sign(
                authorization_digest,
                payout_request
                    .request_digest()
                    .expect("settlement HTTP payout digest"),
                &clearing,
            ),
            request: payout_request.clone(),
            intent_request: intent_request.clone(),
            intent_response: intent_response.clone(),
        }
        .encode()
        .expect("settlement HTTP payout envelope");
        let (status, content_type, payout_response_bytes) = http_exchange(
            Arc::clone(&state),
            "POST",
            "/v1/settlement/payouts",
            Some(CT_PAYOUT_ENVELOPE),
            CT_PAYOUT_RESPONSE,
            &payout_envelope,
        );
        assert_eq!((status, content_type.as_str()), (200, CT_PAYOUT_RESPONSE));
        let payout_response = IssuerPayoutResponseV1::decode(&payout_response_bytes)
            .expect("decode settlement HTTP payout");
        assert_eq!(payout_response.state, PayoutStateV1::Accepted);
        let (status, _, replayed_payout) = http_exchange(
            Arc::clone(&state),
            "POST",
            "/v1/settlement/payouts",
            Some(CT_PAYOUT_ENVELOPE),
            CT_PAYOUT_RESPONSE,
            &payout_envelope,
        );
        assert_eq!(status, 200);
        assert_eq!(replayed_payout, payout_response_bytes);
        drop(state);

        // Reopen every service/store handle before the first status request.
        // This exercises the executable restart path rather than retaining an
        // in-memory payout typestate.
        let restarted = fixture.state(fixture.now_unix + 5);
        let registration = restarted
            .store
            .provider_settlement_registration(&SETTLEMENT_HTTP_PROVIDER_ID)
            .expect("read settlement HTTP registration")
            .expect("settlement HTTP registration exists");
        let status_request = ProviderPayoutStatusRequestV1 {
            registration_digest: registration.registration_digest,
            issuer_id: fixture.issuer_id,
            provider_id: SETTLEMENT_HTTP_PROVIDER_ID,
            account_id: SETTLEMENT_HTTP_ACCOUNT_ID,
            payout_id: payout_response.payout_id,
            payout_request_digest: payout_request
                .request_digest()
                .expect("settlement HTTP payout request digest"),
            request_nonce: [0x85; 32],
        };
        let status_auth = ProviderSettlementRequestAuthV1::sign(
            registration.registration_digest,
            status_request
                .request_digest()
                .expect("settlement HTTP status digest"),
            &provider_request,
        );
        let status_envelope_value = ProviderPayoutStatusEnvelopeV1 {
            request: status_request.clone(),
            request_auth: status_auth.clone(),
            payout_request: payout_request.clone(),
            initial_payout_response: payout_response.clone(),
        };
        let status_envelope = status_envelope_value
            .encode()
            .expect("settlement HTTP status envelope");
        let (status, content_type, status_response_bytes) = http_exchange(
            Arc::clone(&restarted),
            "POST",
            "/v1/settlement/payout-status",
            Some(CT_PAYOUT_STATUS_ENVELOPE),
            CT_PAYOUT_STATUS_RESPONSE,
            &status_envelope,
        );
        assert_eq!(
            (status, content_type.as_str()),
            (200, CT_PAYOUT_STATUS_RESPONSE)
        );
        let status_response = IssuerPayoutStatusResponseV1::decode(&status_response_bytes)
            .expect("decode settlement HTTP payout status");
        assert_eq!(status_response.state_version, 2);
        let (status, _, replayed_status) = http_exchange(
            Arc::clone(&restarted),
            "POST",
            "/v1/settlement/payout-status",
            Some(CT_PAYOUT_STATUS_ENVELOPE),
            CT_PAYOUT_STATUS_RESPONSE,
            &status_envelope,
        );
        assert_eq!(status, 200);
        assert_eq!(replayed_status, status_response_bytes);
        drop(restarted);

        // Exact durable bytes remain recoverable after authorization and
        // registration expiry; fresh reads/mutations remain fail-closed.
        let expired = fixture.state(fixture.registration_not_after + 1);
        for (path, request_type, accept, body, expected) in [
            (
                "/v1/redeems",
                CT_REDEEM,
                CT_REDEEM_RESULT,
                redeem_envelope.as_slice(),
                redeem_response.as_slice(),
            ),
            (
                "/v1/settlement/payout-intents",
                CT_PAYOUT_INTENT_ENVELOPE,
                CT_PAYOUT_INTENT_RESPONSE,
                intent_envelope.as_slice(),
                intent_response_bytes.as_slice(),
            ),
            (
                "/v1/settlement/payouts",
                CT_PAYOUT_ENVELOPE,
                CT_PAYOUT_RESPONSE,
                payout_envelope.as_slice(),
                payout_response_bytes.as_slice(),
            ),
            (
                "/v1/settlement/payout-status",
                CT_PAYOUT_STATUS_ENVELOPE,
                CT_PAYOUT_STATUS_RESPONSE,
                status_envelope.as_slice(),
                status_response_bytes.as_slice(),
            ),
        ] {
            let (status, content_type, replayed) = http_exchange(
                Arc::clone(&expired),
                "POST",
                path,
                Some(request_type),
                accept,
                body,
            );
            assert_eq!((status, content_type.as_str()), (200, accept));
            assert_eq!(replayed, expected);
        }

        let mut tampered_status = status_envelope_value.clone();
        tampered_status.request_auth.signature[0] ^= 1;
        let (status, _, _) = http_exchange(
            Arc::clone(&expired),
            "POST",
            "/v1/settlement/payout-status",
            Some(CT_PAYOUT_STATUS_ENVELOPE),
            CT_PAYOUT_STATUS_RESPONSE,
            &tampered_status
                .encode()
                .expect("tampered settlement HTTP status envelope"),
        );
        assert_eq!(status, 401, "exact replay still requires provider auth");

        let mut fresh_status_request = status_request;
        fresh_status_request.request_nonce = [0x86; 32];
        let fresh_status_envelope = ProviderPayoutStatusEnvelopeV1 {
            request_auth: ProviderSettlementRequestAuthV1::sign(
                registration.registration_digest,
                fresh_status_request
                    .request_digest()
                    .expect("fresh expired status digest"),
                &provider_request,
            ),
            request: fresh_status_request,
            payout_request,
            initial_payout_response: payout_response,
        }
        .encode()
        .expect("fresh expired status envelope");
        let (status, _, _) = http_exchange(
            Arc::clone(&expired),
            "POST",
            "/v1/settlement/payout-status",
            Some(CT_PAYOUT_STATUS_ENVELOPE),
            CT_PAYOUT_STATUS_RESPONSE,
            &fresh_status_envelope,
        );
        assert_eq!(
            status, 401,
            "expired registration cannot create a successor"
        );
        let (status, _, _) = http_exchange(
            expired,
            "POST",
            "/v1/settlement/balance",
            Some(CT_BALANCE_ENVELOPE),
            CT_BALANCE_RESPONSE,
            &balance_envelope,
        );
        assert_eq!(
            status, 401,
            "expired clearing auth cannot read a fresh balance"
        );
    }

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

    #[test]
    fn cli_exposes_offline_store_check() {
        let cli = Cli::try_parse_from([
            "payment-issuer",
            "check-store",
            "--store",
            "/private/issuer.sqlite3",
            "--rollback-authority",
            "/independent/floor.sqlite3",
            "--issuer-id-hex",
            &hex::encode([0x11_u8; 32]),
            "--network",
            "regtest",
        ])
        .unwrap();
        assert!(matches!(cli.command, Command::CheckStore(_)));
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

        check_store(StoreCheckArgs {
            store: store.clone(),
            rollback_authority: authority.clone(),
            issuer_id_hex: hex::encode([0x55; 32]),
            network: NetworkArg::Regtest,
        })
        .unwrap();
        assert!(check_store(StoreCheckArgs {
            store,
            rollback_authority: authority,
            issuer_id_hex: hex::encode([0x56; 32]),
            network: NetworkArg::Regtest,
        })
        .unwrap_err()
        .contains("identity mismatch"));
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

    #[test]
    fn fake_http_quote_claim_issues_one_provider_spendable_receipt() {
        let now = system_time_unix().expect("system clock");
        let directory = tempfile::tempdir().expect("temporary directory");
        let fake_lightning = Arc::new(
            FakeLightningNodeV1::new(
                LightningNetworkV1::Regtest,
                [0x03; 32],
                [0x07; 32],
                now.saturating_sub(10),
            )
            .expect("fake Lightning node"),
        );

        let issuer_root = SigningKey::from_bytes(&[0x41; 32]);
        let issuer_id = derive_issuer_id(&issuer_root.verifying_key().to_bytes());
        let provider_id = [0x51; 32];
        let scope = ServiceScopeV1 {
            provider_id,
            backend: BackendId::DpfPirV1,
            workload: WorkloadId::DpfEvaluateJobV1,
            protocol_version: 1,
            dataset: DatasetBindingV1::Class { class_id: 7 },
            operation_profile: 11,
            entitlement_profile: 101,
        };
        let scope_id = scope.scope_id();
        let receipt_key = SigningKey::from_bytes(&[0x42; 32]);
        let receipt_key_id = paid_receipt_key_id(&receipt_key.verifying_key()).to_vec();
        let credential_binding = CredentialKeyBindingV1::sign(
            CredentialKeyBindingClaimsV1 {
                provider_id,
                scope_id,
                offer_id: 9,
                scheme: AuthScheme::Bolt11DirectReceiptV1,
                keyset_epoch: 1,
                entitlement_profile: scope.entitlement_profile,
                unit: CredentialUnitV1::Entitlement,
                amount: 1,
                presentation_limit: 1,
                not_before: now.saturating_sub(60),
                not_after: now + 3_600,
                credential_key_id: receipt_key_id.clone(),
                verification_key: receipt_key.verifying_key().to_bytes().to_vec(),
            },
            &issuer_root,
        )
        .expect("direct-receipt binding");
        let offer = ServiceOfferV1 {
            offer_id: 9,
            acquisition: AcquisitionMethod::Bolt11V1,
            free_mode: FreeModeV1::NotFree,
            free_quota: 0,
            free_window_seconds: 0,
            free_pow_difficulty_bits: 0,
            priority_class: 1,
            authorization: AuthScheme::Bolt11DirectReceiptV1,
            verification: VerificationMode::ProviderLocal,
            deployment_status: DeploymentStatus::Stable,
            price: PriceV1::MilliSatoshi(1_000),
            issuer_id,
            key_id: receipt_key_id,
            credential_binding: Some(credential_binding),
            cashu_mint_manifest: None,
            endpoint: "https://issuer.test.invalid".to_owned(),
            invoice_expiry_seconds: 60,
            claim_window_seconds: 120,
            minimum_credential_validity_seconds: 300,
            retired_policy_grace_seconds: 1_000,
            credential_count: 1,
            credential_presentation_limit: 1,
            privacy_leakage: PrivacyLeakageV1::from_bits(PrivacyLeakageV1::DIRECT_PAYMENT_TO_SPEND)
                .expect("direct-receipt privacy leakage"),
        };
        let policy_key = SigningKey::from_bytes(&[0x43; 32]);
        let policy = ServicePolicyV1::sign(
            provider_id,
            1,
            now.saturating_sub(60),
            now + 3_000,
            AuthPaddingClassV1::Class16KiB,
            vec![ServiceScopePolicyV1 {
                scope: scope.clone(),
                limits: EntitlementLimitsV1 {
                    max_logical_inputs: 1,
                    max_frames: 64,
                    max_request_bytes: 2 * 1024 * 1024,
                    max_response_bytes: 2 * 1024 * 1024,
                    max_wall_time_ms: 20_000,
                    max_concurrent_sockets: 1,
                    max_hint_groups: 0,
                    max_work_units: 10_000,
                },
                offers: vec![offer],
            }],
            &policy_key,
        )
        .expect("signed service policy");
        let verified_policy = policy
            .verify_current_for_acquisition(
                &provider_id,
                now,
                &PolicyRollbackGuardV1::initial(),
                &ServicePolicyEpochFloorsV1::initial(),
                &policy_key.verifying_key(),
            )
            .expect("verified service policy");
        let verified_offer = verified_policy.offer(&scope_id, 9).expect("verified offer");

        let quote_key = SigningKey::from_bytes(&[0x44; 32]);
        let delegation = Bolt11QuoteKeyDelegationV1::sign(
            LightningNetworkV1::Regtest,
            fake_lightning.payee_pubkey(),
            1,
            now.saturating_sub(60),
            now + 3_600,
            quote_key.verifying_key().to_bytes(),
            &issuer_root,
        )
        .expect("quote-key delegation");
        let claim_secret = [0x05; 32];
        let (claim_pubkey_xonly, _) =
            sign_bip340_prehash_v1(&claim_secret, &[0x11; 32], &[0; 32]).expect("claim public key");
        let quote_guard = Bolt11QuoteKeyRollbackGuardV1::initial(
            issuer_id,
            LightningNetworkV1::Regtest,
            fake_lightning.payee_pubkey(),
        )
        .expect("initial quote guard");
        let (intent, _) = Bolt11QuoteIntentV1::from_verified_offer_guarded(
            &verified_offer,
            &delegation,
            &quote_guard,
            now,
            claim_pubkey_xonly,
            [0x61; 32],
        )
        .expect("verified quote intent");

        let issuer_floor = Arc::new(
            SqliteIssuerRollbackFloorAuthorityV1::create(
                directory.path().join("issuer-floor.sqlite3"),
                StoreOptions::default().busy_timeout,
            )
            .expect("issuer rollback floor"),
        );
        let issuer_store = IssuerStore::create(
            directory.path().join("issuer.sqlite3"),
            [0x11; 16],
            issuer_id,
            LightningNetworkV1::Regtest,
            StoreOptions::default(),
            issuer_floor,
        )
        .expect("issuer store");
        let _ = issuer_store
            .register_service_policy(&policy, &policy_key.verifying_key(), now)
            .expect("register service policy");
        let runtime_lightning =
            Arc::new(RuntimeLightningBackendV1::Fake(Arc::clone(&fake_lightning)));
        let acquisition = IssuerAcquisitionServiceV1::new_with_quote_capacity(
            issuer_store.clone(),
            runtime_lightning,
            Arc::new(OsQuoteIdSourceV1),
            QuoteSigningMaterialV1::new(delegation.clone(), quote_key)
                .expect("quote signing material"),
            Vec::new(),
            vec![ReceiptSigningMaterialV1::new(receipt_key)],
            None,
            None,
            IssuerCredentialDerivationKeyV1::from_bytes([0x09; 32])
                .expect("credential derivation key"),
            QuoteCapacityV1::new(16, 128).expect("quote capacity"),
            now,
        )
        .expect("issuer acquisition service");
        let delegation_bytes = delegation.encode().expect("delegation encoding");
        let state = Arc::new(ServerState {
            acquisition,
            current_quote_delegation: delegation_bytes.clone(),
            quote_delegations: BTreeMap::from([(delegation.quote_key_id, delegation_bytes)]),
            clearing: None,
            store: issuer_store,
            fake_lightning: Some(Arc::clone(&fake_lightning)),
            allow_origin: None,
            quote_rate: FixedWindowRateLimiterV1::new(100, "test quote rate").expect("quote rate"),
            status_rate: FixedWindowRateLimiterV1::new(100, "test status rate")
                .expect("status rate"),
            mutation_rate: FixedWindowRateLimiterV1::new(100, "test mutation rate")
                .expect("mutation rate"),
            now_unix_override: None,
        });

        let (status, content_type, current_delegation) = http_exchange(
            Arc::clone(&state),
            "GET",
            "/v1/quote-keys/current",
            None,
            CT_QUOTE_KEY_DELEGATION,
            &[],
        );
        assert_eq!(status, 200);
        assert_eq!(content_type, CT_QUOTE_KEY_DELEGATION);
        assert_eq!(
            Bolt11QuoteKeyDelegationV1::decode(&current_delegation)
                .expect("HTTP delegation")
                .quote_key_id,
            delegation.quote_key_id
        );

        let intent_bytes = intent.encode().expect("intent encoding");
        let (status, content_type, initial_bytes) = http_exchange(
            Arc::clone(&state),
            "POST",
            "/v1/quotes/bolt11",
            Some(CT_QUOTE_INTENT),
            CT_QUOTE,
            &intent_bytes,
        );
        assert_eq!(status, 200);
        assert_eq!(content_type, CT_QUOTE);
        let initial = Bolt11QuoteV1::decode(&initial_bytes).expect("initial HTTP quote");
        let parsed_initial =
            ParsedBolt11InvoiceV1::parse(&initial.invoice).expect("parse fake BOLT11 invoice");
        initial
            .verify_for_payment(
                &intent,
                &delegation,
                &parsed_initial,
                system_time_unix().unwrap(),
            )
            .expect("payable HTTP quote");

        let settled_at = wait_until_after(initial.status_updated_at);
        let mut settlement = Vec::with_capacity(48);
        settlement.extend_from_slice(&initial.quote_id);
        settlement.extend_from_slice(&initial.amount_msat.to_le_bytes());
        settlement.extend_from_slice(&settled_at.to_le_bytes());
        let (status, content_type, response) = http_exchange(
            Arc::clone(&state),
            "POST",
            "/__test/fake/settle",
            Some(CT_FAKE_SETTLEMENT),
            "application/octet-stream",
            &settlement,
        );
        assert_eq!(status, 200);
        assert_eq!(content_type, "application/octet-stream");
        assert!(response.is_empty());

        let mut status_request = Bolt11QuoteStatusRequestV1 {
            issuer_id,
            quote_id: initial.quote_id,
            quote_request_digest: intent.request_digest().expect("intent digest"),
            claim_pubkey_xonly,
            requested_at: system_time_unix().expect("status request time"),
            request_nonce: [0x62; 32],
            signature: [1; 64],
        };
        let status_digest = status_request
            .bip340_signing_digest()
            .expect("status signing digest");
        let (signed_pubkey, status_signature) =
            sign_bip340_prehash_v1(&claim_secret, &status_digest, &[0x63; 32])
                .expect("status signature");
        assert_eq!(signed_pubkey, claim_pubkey_xonly);
        status_request.signature = status_signature;
        let status_path = format!("/v1/quotes/{}/status", hex::encode(initial.quote_id));
        let (status, content_type, settled_bytes) = http_exchange(
            Arc::clone(&state),
            "POST",
            &status_path,
            Some(CT_STATUS_REQUEST),
            CT_QUOTE,
            &status_request.encode().expect("status request encoding"),
        );
        assert_eq!(status, 200);
        assert_eq!(content_type, CT_QUOTE);
        let settled = Bolt11QuoteV1::decode(&settled_bytes).expect("settled HTTP quote");
        assert_eq!(settled.status, Bolt11QuoteStatusV1::PaymentSettled);

        let claim_now = wait_until_after(settled.status_updated_at);
        let parsed_settled =
            ParsedBolt11InvoiceV1::parse(&settled.invoice).expect("parse settled invoice");
        let verified_quote = settled
            .verify_for_claim_submission(&intent, &delegation, &parsed_settled, claim_now)
            .expect("claimable settled quote");
        let issuance_request = CredentialIssuanceRequestV1 {
            issuer_id,
            quote_id: settled.quote_id,
            quote_request_digest: settled.request_digest,
            authorization: AuthScheme::Bolt11DirectReceiptV1,
            credential_binding_digest: intent.credential_binding_digest,
            credential_key_id: intent.credential_key_id.clone(),
            items: CredentialIssuanceRequestItemsV1::DirectPaidReceipt,
        };
        let mut claim = Bolt11QuoteClaimV1 {
            issuer_id,
            quote_id: settled.quote_id,
            quote_request_digest: settled.request_digest,
            credential_request_digest: issuance_request
                .request_digest()
                .expect("issuance request digest"),
            claim_pubkey_xonly,
            idempotency_key: intent.idempotency_key,
            signature: [1; 64],
        };
        let claim_digest = claim.bip340_signing_digest().expect("claim signing digest");
        let (signed_pubkey, claim_signature) =
            sign_bip340_prehash_v1(&claim_secret, &claim_digest, &[0x64; 32])
                .expect("claim signature");
        assert_eq!(signed_pubkey, claim_pubkey_xonly);
        claim.signature = claim_signature;
        let envelope = Bolt11QuoteClaimEnvelopeV1 {
            quote_intent: intent.clone(),
            claim,
            credential_request: issuance_request.clone(),
        }
        .encode()
        .expect("claim envelope encoding");
        let claim_path = format!("/v1/quotes/{}/claim", hex::encode(settled.quote_id));
        let (status, content_type, issuance_bytes) = http_exchange(
            Arc::clone(&state),
            "POST",
            &claim_path,
            Some(CT_CLAIM_ENVELOPE),
            CT_ISSUANCE_RESPONSE,
            &envelope,
        );
        assert_eq!(status, 200);
        assert_eq!(content_type, CT_ISSUANCE_RESPONSE);
        let (replay_status, replay_content_type, replay_bytes) = http_exchange(
            Arc::clone(&state),
            "POST",
            &claim_path,
            Some(CT_CLAIM_ENVELOPE),
            CT_ISSUANCE_RESPONSE,
            &envelope,
        );
        assert_eq!(replay_status, 200);
        assert_eq!(replay_content_type, CT_ISSUANCE_RESPONSE);
        assert_eq!(replay_bytes, issuance_bytes);

        let issuance = CredentialIssuanceResponseV1::decode(&issuance_bytes, None)
            .expect("issuance response encoding");
        let receipt = match issuance
            .verify_for_verified_quote(
                &issuance_request,
                &verified_quote,
                verified_offer
                    .offer()
                    .credential_binding
                    .as_ref()
                    .expect("receipt binding"),
            )
            .expect("verified issuance response")
        {
            CheckedCredentialIssuanceResponseV1::DirectPaidReceipts(receipts) => {
                assert_eq!(receipts.len(), 1);
                receipts.into_iter().next().expect("issued receipt")
            }
            _ => panic!("direct-receipt quote returned another credential scheme"),
        };

        let provider_floor = Arc::new(
            SqliteRollbackFloorAuthorityV1::create(
                directory.path().join("provider-floor.sqlite3"),
                ProviderStoreOptions::default().busy_timeout,
            )
            .expect("provider rollback floor"),
        );
        let provider_store = ProviderStore::create(
            directory.path().join("provider.sqlite3"),
            [0x21; 16],
            provider_id,
            ProviderStoreOptions::default(),
            provider_floor.clone(),
        )
        .expect("provider store");
        let _ = provider_store
            .install_verified_offer_namespace_v1(&verified_offer, claim_now, None)
            .expect("install receipt namespace");
        let operation = OperationStartV1::DpfQuery { db_id: 0 };
        let auth = AuthBeginV1 {
            policy_digest: verified_offer.policy_digest(),
            scope_id,
            offer_id: 9,
            scheme: AuthScheme::Bolt11DirectReceiptV1,
            key_id: verified_offer.offer().key_id.clone(),
            operation: operation.clone(),
            proof: receipt.encode().expect("receipt proof encoding"),
        };
        let auth = AuthBeginV1::decode_padded_for(
            &auth
                .encode_padded_for(policy.auth_padding_class)
                .expect("padded authorization"),
            policy.auth_padding_class,
        )
        .expect("canonical authorization frame");
        let catalog = |candidate: &OperationStartV1| {
            (candidate == &operation).then(|| {
                TrustedCatalogResolutionV1::new(
                    0,
                    scope.backend,
                    scope.workload,
                    scope.protocol_version,
                    scope.dataset.clone(),
                    scope.operation_profile,
                )
            })
        };
        let attempt = bind_auth_begin_v1(&auth, verified_offer, &catalog, None)
            .expect("bind issued receipt to provider operation");
        let spend = verify_provider_local_bearer_spend_v1(&attempt, claim_now, None)
            .expect("verify issued provider receipt");
        provider_store
            .spend_verified_provider_local_v1(spend)
            .expect("commit issued provider receipt");

        let reopened = ProviderStore::open_existing(
            directory.path().join("provider.sqlite3"),
            provider_id,
            ProviderStoreOptions::default(),
            provider_floor,
        )
        .expect("reopen provider store");
        let replay_attempt = bind_auth_begin_v1(&auth, verified_offer, &catalog, None)
            .expect("rebind exact receipt after restart");
        let replay_spend = verify_provider_local_bearer_spend_v1(&replay_attempt, claim_now, None)
            .expect("reverify exact receipt after restart");
        assert!(matches!(
            reopened.spend_verified_provider_local_v1(replay_spend),
            Err(ProviderStoreError::AlreadySpent)
        ));
    }
}
