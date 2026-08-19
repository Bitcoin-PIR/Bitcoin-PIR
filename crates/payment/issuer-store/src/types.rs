use pir_service_protocol::{
    AuthScheme, BatV2IssuanceResponseV2, Bolt11BatV2ClaimEnvelopeV2, Bolt11QuoteClaimV1,
    CheckedBatV2IssuanceResponseV2, CredentialIssuanceRequestV1, CredentialIssuanceResponseV1,
    CredentialKeyBindingV1, IssuerAccountingApprovalV2, IssuerClearingApprovalV1,
    LightningNetworkV1, PayoutStateV1, ProviderAccountingAuthorizationV2,
    ProviderClearingAuthorizationV1, ProviderRedeemRequestV1, ProviderRedeemResponseV1,
    ServiceProtocolError, SettlementUnitV1,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// On-disk schema version. This crate never performs an implicit migration.
/// Version 8 is a fresh-schema boundary for issuer-global BAT V2 redemption
/// and protocol-neutral provider-account bindings. This crate never upgrades
/// a version-7 store implicitly; deployment must isolate a fresh v8 store or
/// use an explicit, separately reviewed migration.
pub const SCHEMA_VERSION: u32 = 8;

pub const MAX_EXACT_INTENT_BYTES: usize = 64 * 1024;
pub const MAX_EXACT_DELEGATION_BYTES: usize = 64 * 1024;
pub const MAX_SIGNED_QUOTE_BYTES: usize = 64 * 1024;
pub const MAX_INVOICE_BYTES: usize = 8 * 1024;
pub const MAX_EXACT_CLAIM_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_EXACT_CLAIM_RESPONSE_BYTES: usize = 128 * 1024;
pub const MAX_EXACT_CLEARING_AUTHORIZATION_BYTES: usize = 128 * 1024;
pub const MAX_EXACT_CLEARING_APPROVAL_BYTES: usize = 4 * 1024;
pub const MAX_EXACT_REDEEM_REQUEST_BYTES: usize = 128 * 1024;
pub const MAX_EXACT_REDEEM_RESPONSE_BYTES: usize = 256 * 1024;
pub const MAX_EXACT_SETTLEMENT_DEPOSIT_REQUEST_BYTES: usize = 256 * 1024;
pub const MAX_EXACT_SETTLEMENT_DEPOSIT_RESPONSE_BYTES: usize = 16 * 1024;
pub const MAX_EXACT_PAYOUT_INTENT_REQUEST_BYTES: usize = 16 * 1024;
pub const MAX_EXACT_PAYOUT_INTENT_RESPONSE_BYTES: usize = 16 * 1024;
pub const MAX_EXACT_PAYOUT_REQUEST_BYTES: usize = 16 * 1024;
pub const MAX_EXACT_PAYOUT_RESPONSE_BYTES: usize = 16 * 1024;
pub const MAX_EXACT_PAYOUT_STATUS_RESPONSE_BYTES: usize = 16 * 1024;
pub const MAX_EXACT_SERVICE_POLICY_BYTES: usize = pir_service_protocol::MAX_SIGNED_POLICY_LEN;
/// Durable upper bound for one canonical signed BAT V2 class artifact. The
/// protocol codec has its own equal-or-smaller bound; this store never accepts
/// an artifact that the protocol layer cannot decode and re-encode exactly.
pub const MAX_EXACT_BAT_V2_CLASS_BYTES: usize =
    pir_service_protocol::MAX_BAT_ACCEPTANCE_CLASS_LEN_V2;
pub const MAX_EXACT_BAT_V2_ACCOUNTING_AUTHORIZATION_BYTES: usize =
    pir_service_protocol::MAX_BAT_V2_PROVIDER_ACCOUNTING_AUTHORIZATION_LEN_V2;
pub const MAX_EXACT_BAT_V2_ACCOUNTING_APPROVAL_BYTES: usize =
    pir_service_protocol::BAT_V2_ISSUER_ACCOUNTING_APPROVAL_LEN_V2;
pub const MAX_EXACT_BAT_V2_REDEEM_SUCCESS_BYTES: usize =
    pir_service_protocol::MAX_BAT_V2_PROVIDER_REDEEM_RESPONSE_LEN_V2;
/// V1 protocol acquisition cap. Store limits may not exceed the wire cap.
pub const MAX_RECEIPT_SERIALS_PER_CLAIM: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreOptions {
    pub busy_timeout: Duration,
}

impl Default for StoreOptions {
    fn default() -> Self {
        Self {
            busy_timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreIdentity {
    pub store_instance_id: [u8; 16],
    pub issuer_id: [u8; 32],
    pub network: LightningNetworkV1,
    pub commit_seq: u64,
    /// Zero only at generation zero; otherwise the exact previous externally
    /// anchored rolling commitment.
    pub rollback_parent_commitment: [u8; 32],
    pub rollback_commitment: [u8; 32],
    /// Highest trusted status-service wall-clock observation. The rolling
    /// commitment and mandatory external rollback authority protect it against
    /// stale database restore.
    pub status_time_floor: u64,
    pub schema_version: u32,
}

/// Aggregate, non-secret row counts for startup-capacity observation.
///
/// These counters deliberately expose no quote IDs, invoices, payment hashes,
/// credentials, provider pairings, or timestamps. Operators can combine them
/// with the measured `open_existing` latency to define a staging activation
/// SLO for the store's full retained-history integrity check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IssuerStoreOperationalInventoryV1 {
    pub observed_commit_seq: u64,
    pub quote_rows: u64,
    pub claim_rows: u64,
    pub retained_policy_rows: u64,
    pub bat_v2_class_rows: u64,
    pub bat_v2_class_head_rows: u64,
    pub bat_v2_class_member_rows: u64,
    pub provider_account_binding_rows: u64,
    pub bat_v2_accounting_authorization_rows: u64,
    pub redemption_rows: u64,
    pub bat_v2_redemption_rows: u64,
    pub payout_rows: u64,
}

/// One exact provider-policy member retained under one signed BAT V2 class
/// artifact. The redemption deadline is derived from the registered exact
/// policy and signed offer at registration time; it is not caller supplied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatAcceptanceClassMemberRecordV2 {
    pub member_index: u16,
    pub provider_id: [u8; 32],
    pub policy_digest: [u8; 32],
    pub scope_id: [u8; 32],
    pub offer_id: u32,
    pub redemption_deadline: u64,
}

/// Append-only issuer BAT V2 class/key-epoch snapshot. `exact_artifact`
/// remains the canonical signed protocol object; the duplicated fixed-width
/// columns are checked readback indexes, not a second source of truth.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatAcceptanceClassRecordV2 {
    pub class_id: [u8; 32],
    pub key_epoch: u64,
    pub artifact_digest: [u8; 32],
    pub common_terms_digest: [u8; 32],
    pub issuer_verifying_key: [u8; 32],
    pub raw_public_key: [u8; 33],
    pub key_fingerprint: [u8; 32],
    pub bat_key_id: [u8; 32],
    pub key_not_before: u64,
    pub key_not_after: u64,
    pub exact_artifact: Vec<u8>,
    pub members: Vec<BatAcceptanceClassMemberRecordV2>,
    pub commit: CommitMarker,
}

/// One provider policy retained by the issuer for current acquisition and
/// later paid-claim recovery. The exact signed policy and its verifying key
/// are durable issuer-local trust state; neither is accepted from a claim
/// request.
#[derive(Clone, Eq, PartialEq)]
pub struct IssuerServicePolicyRecordV1 {
    pub provider_id: [u8; 32],
    pub policy_epoch: u64,
    pub policy_digest: [u8; 32],
    pub policy_verifying_key: [u8; 32],
    pub exact_policy: Vec<u8>,
    pub expires_at: u64,
    pub commit: CommitMarker,
}

/// Exact BIP340 inputs for an authenticated private quote-status read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuoteStatusBip340Input<'a> {
    pub claim_pubkey_xonly: &'a [u8; 32],
    pub message_digest: &'a [u8; 32],
    pub signature: &'a [u8; 64],
}

/// Adapter boundary for a reviewed BIP340 verifier.
pub trait QuoteStatusBip340Verifier {
    fn verify(&self, input: QuoteStatusBip340Input<'_>) -> bool;
}

/// Exact parsed objects a claim verifier must authenticate before the store
/// can commit issuance. The verifier is responsible for BIP340 and
/// scheme-specific credential cryptography (receipt signatures, BAT signing
/// correctness, or experimental ARC issuance/finalization constraints).
#[derive(Clone, Copy)]
pub struct ClaimCryptographicVerificationInput<'a> {
    pub claim: &'a Bolt11QuoteClaimV1,
    pub issuance_request: &'a CredentialIssuanceRequestV1,
    pub issuance_response: &'a CredentialIssuanceResponseV1,
    pub bip340_message_digest: &'a [u8; 32],
}

pub trait ClaimCryptographicVerifier {
    fn verify(&self, input: ClaimCryptographicVerificationInput<'_>) -> bool;
}

impl<F> ClaimCryptographicVerifier for F
where
    F: Fn(ClaimCryptographicVerificationInput<'_>) -> bool,
{
    fn verify(&self, input: ClaimCryptographicVerificationInput<'_>) -> bool {
        self(input)
    }
}

impl<F> QuoteStatusBip340Verifier for F
where
    F: Fn(QuoteStatusBip340Input<'_>) -> bool,
{
    fn verify(&self, input: QuoteStatusBip340Input<'_>) -> bool {
        self(input)
    }
}

/// Store-specific durable write marker.
///
/// A method constructs this value only after SQLite reports a successful
/// commit and the external rollback authority confirms the new generation, or
/// when replaying an already-anchored row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitMarker {
    pub store_instance_id: [u8; 16],
    pub commit_seq: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteDisposition {
    Committed,
    ExactReplay,
}

#[must_use = "durable issuer writes and exact replays must be handled explicitly"]
pub struct DurableWrite<T> {
    pub disposition: WriteDisposition,
    pub commit: CommitMarker,
    pub value: T,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub enum QuoteState {
    Reserved = 0,
    InvoiceOpen = 1,
    PaymentSettled = 2,
    CredentialClaimed = 3,
    InvoiceExpiredPendingReconcile = 4,
    LateSettledReconcile = 5,
}

impl QuoteState {
    pub(crate) fn from_db(value: i64) -> Option<Self> {
        match value {
            0 => Some(Self::Reserved),
            1 => Some(Self::InvoiceOpen),
            2 => Some(Self::PaymentSettled),
            3 => Some(Self::CredentialClaimed),
            4 => Some(Self::InvoiceExpiredPendingReconcile),
            5 => Some(Self::LateSettledReconcile),
            _ => None,
        }
    }
}

/// Bounded background-reconciliation cursor item. It deliberately has no
/// `Debug` implementation because the backend label is issuer-confidential.
#[derive(Clone, Eq, PartialEq)]
pub struct QuoteReconciliationCandidateV1 {
    pub(crate) quote_id: [u8; 32],
    pub(crate) backend_label: String,
    pub(crate) delegation_digest: [u8; 32],
}

impl QuoteReconciliationCandidateV1 {
    pub const fn quote_id(&self) -> &[u8; 32] {
        &self.quote_id
    }

    pub fn backend_label(&self) -> &str {
        &self.backend_label
    }

    pub const fn delegation_digest(&self) -> &[u8; 32] {
        &self.delegation_digest
    }
}

/// Durable admission limits applied atomically when reserving a new quote.
/// Exact idempotent replay is always allowed even when either limit is full.
/// Paid/claimed rows and expired rows past their immutable recovery horizon
/// remain in the audit log but do not consume `max_active_records`; an
/// abandoned reservation consumes capacity only through its signed
/// invoice-creation window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuoteCapacityV1 {
    pub max_outstanding_unpaid: u64,
    pub max_active_records: u64,
}

impl QuoteCapacityV1 {
    pub const fn unbounded() -> Self {
        Self {
            max_outstanding_unpaid: u64::MAX,
            max_active_records: u64::MAX,
        }
    }

    pub const fn new(max_outstanding_unpaid: u64, max_active_records: u64) -> Option<Self> {
        if max_outstanding_unpaid == 0
            || max_active_records == 0
            || max_outstanding_unpaid > max_active_records
        {
            None
        } else {
            Some(Self {
                max_outstanding_unpaid,
                max_active_records,
            })
        }
    }
}

/// First durable step in quote creation.
///
/// The protocol layer must verify `exact_intent` against the selected offer
/// and verify `exact_delegation` under the issuer root before this call. The
/// store repeats issuer/network/payee/epoch/digest and delegation signature
/// checks, then atomically advances the rollback guard and reserves the quote.
#[derive(Clone)]
pub struct QuoteReservation {
    pub quote_id: [u8; 32],
    pub creation_idempotency_key: [u8; 32],
    pub intent_digest: [u8; 32],
    pub exact_intent: Vec<u8>,
    pub payee_pubkey: [u8; 33],
    pub delegation_epoch: u64,
    pub delegation_digest: [u8; 32],
    pub exact_delegation: Vec<u8>,
    pub exact_amount_msat: u64,
    /// Earliest acceptable node-assigned BOLT11 creation timestamp. This is
    /// immutable recovery state, not the caller's current wall clock.
    pub invoice_created_not_before: u64,
    /// Latest acceptable node-assigned BOLT11 creation timestamp. Persisting
    /// the bounded window makes a `Reserved` replay safe after restart while
    /// remaining compatible with LND/CLN assigning the invoice timestamp.
    pub invoice_created_not_after: u64,
    /// Used only to recheck delegation validity for a new reservation. It is
    /// not persisted and is ignored for an exact replay.
    pub now_unix: u64,
}

/// Minimal durable input for one issuer-wide BAT V2 quote reservation.
/// Commercial, class, delegation, and idempotency fields are decoded from
/// the two exact canonical protocol objects rather than repeated here.
#[derive(Clone)]
pub struct BatV2QuoteReservation {
    pub quote_id: [u8; 32],
    pub exact_intent: Vec<u8>,
    pub exact_delegation: Vec<u8>,
    pub invoice_created_not_before: u64,
    pub invoice_created_not_after: u64,
    pub now_unix: u64,
}

/// Exact BOLT11 invoice and first signed quote snapshot.
#[derive(Clone)]
pub struct QuoteFinalization {
    pub quote_id: [u8; 32],
    pub invoice: String,
    pub payment_hash: [u8; 32],
    pub invoice_created_at: u64,
    pub invoice_expires_at: u64,
    pub claim_deadline: u64,
    pub credential_not_after: u64,
    pub exact_signed_quote_response: Vec<u8>,
}

#[derive(Clone)]
pub struct QuoteExpiry {
    pub quote_id: [u8; 32],
    pub observed_at: u64,
    pub exact_signed_quote_response: Vec<u8>,
}

#[derive(Clone)]
pub struct QuoteSettlement {
    pub quote_id: [u8; 32],
    pub settled_at: u64,
    /// Signed quote lifecycle transition time. This may be later than the
    /// Lightning backend's actual settlement time during reconciliation.
    pub observed_at: u64,
    pub settled_amount_msat: u64,
    pub settlement_evidence_digest: [u8; 32],
    pub exact_signed_quote_response: Vec<u8>,
}

/// Full durable quote recovery record.
///
/// The invoice is issuer-confidential data. This type does not implement
/// `Debug` so an accidental structured log cannot print it.
#[derive(Clone, Eq, PartialEq)]
pub struct QuoteRecord {
    pub quote_id: [u8; 32],
    /// Endpoint-domain-separated digest. The raw idempotency key is never
    /// persisted or returned by this crate.
    pub creation_idempotency_digest: [u8; 32],
    pub backend_label: String,
    pub intent_digest: [u8; 32],
    /// Canonical intent with the raw idempotency field replaced by its
    /// endpoint-domain digest. `intent_digest` still commits to the exact
    /// original wire request.
    pub intent_replay_image: Vec<u8>,
    pub payee_pubkey: [u8; 33],
    pub delegation_epoch: u64,
    pub delegation_digest: [u8; 32],
    pub exact_delegation: Vec<u8>,
    pub exact_amount_msat: u64,
    pub invoice_created_not_before: u64,
    pub invoice_created_not_after: u64,
    /// Latest possible claim-recovery deadline if invoice creation completes
    /// at the upper edge of its immutable creation window.
    pub reservation_recovery_deadline: u64,
    pub state: QuoteState,
    /// Monotonic per-quote state revision. Reservation is version 0; every
    /// committed lifecycle transition increments it exactly once.
    pub state_version: u64,
    pub invoice: Option<String>,
    pub payment_hash: Option<[u8; 32]>,
    pub invoice_created_at: Option<u64>,
    pub invoice_expires_at: Option<u64>,
    pub claim_deadline: Option<u64>,
    pub credential_not_after: Option<u64>,
    pub initial_signed_quote_response: Option<Vec<u8>>,
    pub expiry_observed_at: Option<u64>,
    pub expired_signed_quote_response: Option<Vec<u8>>,
    pub settled_at: Option<u64>,
    pub settlement_observed_at: Option<u64>,
    pub settled_amount_msat: Option<u64>,
    pub settlement_evidence_digest: Option<[u8; 32]>,
    pub settled_signed_quote_response: Option<Vec<u8>>,
    pub reservation_commit: CommitMarker,
    pub finalization_commit: Option<CommitMarker>,
    pub expiry_commit: Option<CommitMarker>,
    pub settlement_commit: Option<CommitMarker>,
}

/// Narrow response for one authenticated quote-status read. The exact signed
/// snapshot contains the invoice, so this type intentionally does not
/// implement `Debug`. Internal backend labels, payment hashes, replay images,
/// and settlement evidence never cross this boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticatedQuoteStatus {
    pub quote_id: [u8; 32],
    pub state: QuoteState,
    pub state_version: u64,
    pub exact_signed_quote_response: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ReceiptSerial {
    pub key_id: [u8; 16],
    pub serial: [u8; 32],
}

#[derive(Clone)]
pub struct ClaimWrite {
    pub quote_id: [u8; 32],
    pub claim_idempotency_key: [u8; 32],
    pub claim_request_digest: [u8; 32],
    pub exact_claim_request: Vec<u8>,
    pub exact_credential_request: Vec<u8>,
    pub exact_claim_response: Vec<u8>,
    pub exact_signed_quote_response: Vec<u8>,
    /// Authoritative lifecycle transition time for a new claim. It is
    /// persisted as `claimed_at`; an exact replay ignores a later supplied
    /// value and remains available after the deadline.
    pub now_unix: u64,
}

/// Exact BAT V2 claim envelope and issuer response to commit atomically. The
/// quote ID and both endpoint idempotency keys are decoded from the canonical
/// envelope; raw keys are never copied into durable replay images.
#[derive(Clone)]
pub struct BatV2ClaimWrite {
    pub exact_claim_envelope: Vec<u8>,
    pub exact_claim_response: Vec<u8>,
    pub exact_signed_quote_response: Vec<u8>,
    pub now_unix: u64,
}

pub struct BatV2ClaimCryptographicVerificationInputV2<'a> {
    pub claim_envelope: &'a Bolt11BatV2ClaimEnvelopeV2,
    pub issuance_response: &'a BatV2IssuanceResponseV2,
    pub checked_response: &'a CheckedBatV2IssuanceResponseV2,
    pub bip340_message_digest: &'a [u8; 32],
}

pub trait BatV2ClaimCryptographicVerifierV2 {
    fn verify(&self, input: BatV2ClaimCryptographicVerificationInputV2<'_>) -> bool;
}

impl<F> BatV2ClaimCryptographicVerifierV2 for F
where
    F: Fn(BatV2ClaimCryptographicVerificationInputV2<'_>) -> bool,
{
    fn verify(&self, input: BatV2ClaimCryptographicVerificationInputV2<'_>) -> bool {
        self(input)
    }
}

/// One retained BAT key epoch whose private mint scalar must remain loaded.
///
/// `raw_public_key` is only the exact compressed-public-key locator used to
/// select that scalar from an in-memory keyring. It is not the scalar itself;
/// issuer-store never persists or returns BAT private key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct BatV2CredentialMaterialRequirementV2 {
    pub class_id: [u8; 32],
    pub class_key_epoch: u64,
    /// Exact compressed BAT verification key identifying the required scalar.
    pub raw_public_key: [u8; 33],
    pub bat_key_id: [u8; 32],
}

/// Exact claim recovery record. Exact request/response bytes are intentionally
/// not `Debug`-printable through this type.
#[derive(Clone, Eq, PartialEq)]
pub struct ClaimRecord {
    pub quote_id: [u8; 32],
    /// Endpoint-domain-separated digest. The raw claim idempotency key is
    /// never persisted or returned.
    pub claim_idempotency_digest: [u8; 32],
    pub claim_request_digest: [u8; 32],
    /// Canonical claim with its raw idempotency field replaced by the
    /// endpoint-domain digest. `claim_request_digest` commits to the exact
    /// original signed request.
    pub claim_request_replay_image: Vec<u8>,
    pub exact_credential_request: Vec<u8>,
    pub exact_claim_response: Vec<u8>,
    pub exact_signed_quote_response: Vec<u8>,
    pub claimed_at: u64,
    pub receipt_serials: Vec<ReceiptSerial>,
    pub claim_commit: CommitMarker,
}

/// A root-signed quote-key delegation accepted independently of quote
/// creation. Exact replay is allowed; lower epochs and same-epoch forks fail.
#[derive(Clone)]
pub struct DelegationAdvance {
    pub payee_pubkey: [u8; 33],
    pub delegation_epoch: u64,
    pub delegation_digest: [u8; 32],
    pub exact_delegation: Vec<u8>,
    pub now_unix: u64,
}

#[derive(Clone, Eq, PartialEq)]
pub struct DelegationHead {
    pub payee_pubkey: [u8; 33],
    pub highest_epoch: u64,
    pub delegation_digest: [u8; 32],
    pub exact_delegation: Vec<u8>,
    pub commit: CommitMarker,
}

#[derive(Clone)]
pub struct BatKeyLineageRegistration {
    pub raw_public_key: [u8; 33],
    pub provider_id: [u8; 32],
    pub scope_id: [u8; 32],
    pub offer_id: u32,
    pub entitlement_profile: u16,
    pub keyset_epoch: u64,
    pub credential_key_id: [u8; 32],
}

#[derive(Clone, Eq, PartialEq)]
pub struct BatKeyLineage {
    pub key_fingerprint: [u8; 32],
    pub raw_public_key: [u8; 33],
    pub provider_id: [u8; 32],
    pub scope_id: [u8; 32],
    pub offer_id: u32,
    pub entitlement_profile: u16,
    pub keyset_epoch: u64,
    pub credential_key_id: [u8; 32],
    pub lineage_digest: [u8; 32],
    pub commit: CommitMarker,
}

#[derive(Clone)]
pub struct SettlementKeyLineageRegistration {
    pub raw_public_key: [u8; 33],
    pub keyset_id: String,
    pub unit: String,
    pub keyset_epoch: u64,
    pub denomination: u64,
    pub manifest_digest: [u8; 32],
    pub final_expiry: Option<u64>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ArcKeyLineageV1 {
    pub key_fingerprint: [u8; 32],
    pub raw_public_key: [u8; 99],
    pub binding_digest: [u8; 32],
    pub provider_id: [u8; 32],
    pub scope_id: [u8; 32],
    pub offer_id: u32,
    pub entitlement_profile: u16,
    pub keyset_epoch: u64,
    pub credential_key_id: Vec<u8>,
    pub exact_binding: Vec<u8>,
    pub lineage_digest: [u8; 32],
    pub commit: CommitMarker,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SettlementKeyLineage {
    pub key_fingerprint: [u8; 32],
    pub raw_public_key: [u8; 33],
    pub keyset_id: String,
    pub unit: String,
    pub keyset_epoch: u64,
    pub denomination: u64,
    pub manifest_digest: [u8; 32],
    pub final_expiry: Option<u64>,
    pub lineage_digest: [u8; 32],
    pub commit: CommitMarker,
}

/// Trusted issuer-local provider registration. This is operational
/// configuration, not a directory assertion and not request-supplied data.
#[derive(Clone)]
pub struct ProviderSettlementRegistrationWriteV1 {
    pub registration_epoch: u64,
    pub provider_id: [u8; 32],
    pub settlement_account_id: [u8; 32],
    pub provider_request_verifying_key: [u8; 32],
    pub payout_target_id: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProviderSettlementRegistrationRecordV1 {
    pub registration_epoch: u64,
    pub registration_digest: [u8; 32],
    pub provider_id: [u8; 32],
    pub settlement_account_id: [u8; 32],
    pub provider_request_verifying_key: [u8; 32],
    pub payout_target_id: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
    pub commit: CommitMarker,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ClearingAuthorizationRecordV1 {
    pub authorization_digest: [u8; 32],
    pub provider_id: [u8; 32],
    pub authorization_epoch: u64,
    pub exact_authorization: Vec<u8>,
    pub exact_approval: Vec<u8>,
    pub not_after: u64,
    pub commit: CommitMarker,
}

/// Protocol-neutral immutable binding between one provider and the one issuer
/// ledger account into which both V1 and V2 clearing may post.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderAccountBindingRecordV2 {
    pub provider_id: [u8; 32],
    pub settlement_account_id: [u8; 32],
    pub unit: SettlementUnitV1,
    pub commit: CommitMarker,
}

/// Append-only, issuer-verified BAT V2 accounting authority. Exact encoded
/// artifacts remain the only truth; duplicated columns are checked indexes.
#[derive(Clone, Eq, PartialEq)]
pub struct BatV2AccountingAuthorizationRecordV2 {
    pub authorization_digest: [u8; 32],
    pub authorization_id: [u8; 16],
    pub authorization_epoch: u64,
    pub provider_id: [u8; 32],
    pub settlement_account_id: [u8; 32],
    pub operator_verifying_key: [u8; 32],
    pub issuer_settlement_verifying_key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
    pub exact_authorization: Vec<u8>,
    pub exact_approval: Vec<u8>,
    pub commit: CommitMarker,
}

impl BatV2AccountingAuthorizationRecordV2 {
    pub fn decode_exact(
        &self,
    ) -> Result<
        (
            ProviderAccountingAuthorizationV2,
            IssuerAccountingApprovalV2,
        ),
        ServiceProtocolError,
    > {
        Ok((
            ProviderAccountingAuthorizationV2::decode(&self.exact_authorization)?,
            IssuerAccountingApprovalV2::decode(&self.exact_approval)?,
        ))
    }
}

/// Exact inputs a reviewed shared-credential adapter must authenticate. The
/// adapter returns its private cryptographic result only through the sink.
pub struct SharedCredentialVerificationInputV1<'a> {
    pub request: &'a ProviderRedeemRequestV1,
    pub canonical_credential: &'a [u8],
    pub credential_binding: &'a CredentialKeyBindingV1,
    pub now_unix: u64,
}

pub trait SharedCredentialSpendSinkV1 {
    fn accept_verified_spend_v1(
        &mut self,
        scheme: AuthScheme,
        credential_binding_digest: &[u8; 32],
        spend_key: &[u8; 32],
    ) -> Result<(), ServiceProtocolError>;
}

/// Reviewed cryptographic boundary for shared-issuer Free tickets, Cashu BAT,
/// and experimental ARC. Implementations must canonical-decode the exact
/// credential and call the sink exactly once with a verifier-derived global
/// spend key.
pub trait SharedCredentialCryptographicVerifierV1: Send + Sync {
    fn verify_shared_credential_v1(
        &self,
        input: SharedCredentialVerificationInputV1<'_>,
        sink: &mut dyn SharedCredentialSpendSinkV1,
    ) -> Result<(), ServiceProtocolError>;
}

/// Move-only evidence combining current clearing authorization verification
/// with method-specific credential verification. Fields are private so raw
/// spend keys cannot be asserted by an HTTP handler.
#[must_use = "a verified shared credential must be atomically redeemed before granting"]
pub struct VerifiedSharedIssuerRedeemV1<'a> {
    pub(crate) request: &'a ProviderRedeemRequestV1,
    pub(crate) credential_binding: &'a CredentialKeyBindingV1,
    pub(crate) authorization: &'a ProviderClearingAuthorizationV1,
    pub(crate) issuer_approval: &'a IssuerClearingApprovalV1,
    pub(crate) spend_key: [u8; 32],
    pub(crate) unit: SettlementUnitV1,
    pub(crate) provider_credit: u64,
    pub(crate) issuer_fee: u64,
    pub(crate) now_unix: u64,
}

impl<'a> VerifiedSharedIssuerRedeemV1<'a> {
    pub fn request(&self) -> &'a ProviderRedeemRequestV1 {
        self.request
    }

    pub fn authorization(&self) -> &'a ProviderClearingAuthorizationV1 {
        self.authorization
    }

    pub fn credential_binding(&self) -> &'a CredentialKeyBindingV1 {
        self.credential_binding
    }

    pub fn issuer_approval(&self) -> &'a IssuerClearingApprovalV1 {
        self.issuer_approval
    }

    pub fn unit(&self) -> SettlementUnitV1 {
        self.unit
    }

    pub fn provider_credit(&self) -> u64 {
        self.provider_credit
    }

    pub fn issuer_fee(&self) -> u64 {
        self.issuer_fee
    }

    pub fn now_unix(&self) -> u64 {
        self.now_unix
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub enum LedgerTransactionKindV1 {
    RedeemLedgerCredit = 1,
    RedeemBlindLiability = 2,
    BlindSettlementDeposit = 3,
    PayoutDebit = 4,
    PayoutSucceeded = 5,
    PayoutFailed = 6,
    BatV2RedeemLedgerCredit = 7,
}

#[derive(Clone, Eq, PartialEq)]
pub struct RedeemRecordV1 {
    pub idempotency_digest: [u8; 32],
    pub request_digest: [u8; 32],
    pub provider_id: [u8; 32],
    pub authorization_digest: [u8; 32],
    pub credential_binding_digest: [u8; 32],
    pub scheme: AuthScheme,
    pub credential_digest: [u8; 32],
    pub accepted_value: u64,
    pub provider_credit: u64,
    pub issuer_fee: u64,
    pub unit: SettlementUnitV1,
    pub ledger_transaction_id: [u8; 32],
    pub exact_request_replay_image: Vec<u8>,
    pub exact_response: Vec<u8>,
    pub redeemed_at: u64,
    pub commit: CommitMarker,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderLedgerBalanceV1 {
    pub provider_id: [u8; 32],
    pub account_id: [u8; 32],
    pub unit: SettlementUnitV1,
    pub available_value: u64,
    pub reserved_value: u64,
    pub ledger_sequence: u64,
    pub commit: CommitMarker,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SettlementDepositRecordV1 {
    pub idempotency_digest: [u8; 32],
    pub request_digest: [u8; 32],
    pub registration_digest: [u8; 32],
    pub provider_id: [u8; 32],
    pub account_id: [u8; 32],
    pub unit: SettlementUnitV1,
    pub settlement_keyset_id: String,
    pub total_value: u64,
    pub ledger_transaction_id: [u8; 32],
    pub ledger_sequence: u64,
    pub exact_request_replay_image: Vec<u8>,
    pub exact_response: Vec<u8>,
    pub deposited_at: u64,
    pub commit: CommitMarker,
}

#[derive(Clone, Eq, PartialEq)]
pub struct PayoutIntentRecordV1 {
    pub idempotency_digest: [u8; 32],
    pub request_digest: [u8; 32],
    pub provider_id: [u8; 32],
    pub account_id: [u8; 32],
    pub payout_target_id: [u8; 32],
    pub unit: SettlementUnitV1,
    pub payout_value: u64,
    pub issuer_fee: u64,
    pub total_debit: u64,
    pub payout_intent_id: [u8; 32],
    pub expires_at: u64,
    pub consumed_by_payout_id: Option<[u8; 32]>,
    pub exact_request_replay_image: Vec<u8>,
    pub exact_response: Vec<u8>,
    pub commit: CommitMarker,
}

#[derive(Clone, Eq, PartialEq)]
pub struct PayoutRecordV1 {
    pub idempotency_digest: [u8; 32],
    pub request_digest: [u8; 32],
    pub provider_id: [u8; 32],
    pub account_id: [u8; 32],
    pub payout_target_id: [u8; 32],
    pub payout_intent_id: [u8; 32],
    pub payout_id: [u8; 32],
    pub unit: SettlementUnitV1,
    pub payout_value: u64,
    pub total_debit: u64,
    pub state: PayoutStateV1,
    pub ledger_transaction_id: [u8; 32],
    pub terminal_ledger_transaction_id: Option<[u8; 32]>,
    pub state_version: u64,
    pub updated_at: u64,
    pub exact_request_replay_image: Vec<u8>,
    pub exact_initial_response: Vec<u8>,
    pub exact_latest_status_response: Option<Vec<u8>>,
    pub commit: CommitMarker,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub enum PayoutOutboxStateV1 {
    Pending = 1,
    Leased = 2,
    Complete = 3,
}

#[derive(Clone, Eq, PartialEq)]
pub struct PayoutOutboxCommandV1 {
    pub command_id: [u8; 32],
    pub payout_id: [u8; 32],
    pub payout_target_id: [u8; 32],
    pub unit: SettlementUnitV1,
    pub payout_value: u64,
    pub state: PayoutOutboxStateV1,
    pub attempt_count: u32,
    pub lease_owner_digest: Option<[u8; 32]>,
    pub lease_until: Option<u64>,
    pub commit: CommitMarker,
}

/// Pair of protocol typestates required by the atomic persistence boundary.
/// The response typestate separately proves the issuer signature, exact echo,
/// and any returned NUT-12 promises.
pub struct VerifiedRedeemCommitV1<'a, 'response> {
    pub redeem: VerifiedSharedIssuerRedeemV1<'a>,
    pub response: pir_service_protocol::VerifiedProviderRedeemResponseV1<'response>,
}

impl VerifiedRedeemCommitV1<'_, '_> {
    pub fn response(&self) -> &ProviderRedeemResponseV1 {
        self.response.response()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct StoreHandle {
    pub path: PathBuf,
    pub expected_store_instance_id: [u8; 16],
    pub expected_issuer_id: [u8; 32],
    pub expected_network: LightningNetworkV1,
    pub rollback_authority: Arc<dyn crate::IssuerRollbackFloorAuthorityV1>,
    pub options: StoreOptions,
}
