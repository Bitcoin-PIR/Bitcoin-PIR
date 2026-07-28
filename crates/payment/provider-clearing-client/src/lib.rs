//! Provider-side online redemption for shared Free, Cashu BAT, and
//! experimental ARC credentials.
//!
//! The provider uses a key distinct from its service-policy and Nostr keys.
//! The issuer owns the global spent set and ledger.  This crate never accepts
//! an invoice, payment hash, preimage, payer identity, peer-provider identity,
//! or PIR result.

#![forbid(unsafe_code)]

mod https_transport;
mod remote_floor;
mod sqlite_store;

pub use https_transport::StrictHttpsProviderSettlementTransportV1;
pub use remote_floor::RemoteProviderSettlementFloorAuthorityV1;
pub use sqlite_store::{
    AuthenticatedProviderSettlementFloorTransitionV1, LocalTestSqliteProviderSettlementFloorV1,
    ProviderSettlementFloorAuthorityErrorV1, ProviderSettlementFloorAuthorityV1,
    ProviderSettlementFloorPhaseV1, ProviderSettlementFloorV1,
    ProviderSettlementRecoveryTransitionKindV2, ProviderSettlementRecoveryV1,
    ProviderSettlementSqliteStoreErrorV1, SqliteProviderSettlementStateStoreV1,
    UnverifiedProviderSettlementRecoveryV2, VerifiedProviderSettlementRecoveryV2,
};

use core::fmt;

use ed25519_dalek::{SigningKey, VerifyingKey};
use pir_runtime_core::service_admission::{
    AdmissionCommitErrorV1, AdmissionMethodCommitterV1, AdmissionMethodRouteV1,
};
use pir_service_protocol::{
    credential_presentation_digest, verify_committed_clearing_request_auth_v1,
    verify_new_payout_request_for, verify_new_payout_status_request_for,
    verify_new_payout_status_response_for, verify_payout_initial_response_for_exact_request,
    verify_persisted_payout_snapshot_for_store_v1, verify_shared_issuer_local_grant_claim_v1,
    AuthScheme, AuthorizationProofV1, BoundAuthAttemptV1, CommittedRedeemReplayExpectationV1,
    FreeAuthorizationProofV1, IssuerBalanceResponseV1, IssuerClearingApprovalV1,
    IssuerPayoutIntentResponseV1, IssuerPayoutResponseV1, IssuerPayoutStatusResponseV1,
    IssuerSettlementKeyringExpectationV1, PayoutExecutionContextV1, PayoutStateV1,
    PayoutStatusContextV1, PayoutTargetIdV1, ProviderBalanceEnvelopeV1, ProviderBalanceRequestV1,
    ProviderClearingAuthorizationV1, ProviderClearingExpectationV1, ProviderClearingRequestAuthV1,
    ProviderId, ProviderPayoutEnvelopeV1, ProviderPayoutIntentEnvelopeV1,
    ProviderPayoutIntentRequestV1, ProviderPayoutRequestV1, ProviderPayoutStatusEnvelopeV1,
    ProviderPayoutStatusRequestV1, ProviderRedeemRequestV1,
    ProviderSettlementRegistrationExpectationV1, ProviderSettlementRequestAuthV1,
    ServiceProtocolError, SettlementDestinationV1, SettlementUnitV1, SharedIssuerProviderSecretV1,
    VerificationMode, VerifiedPayoutSnapshotV1, MAX_EXECUTABLE_SETTLEMENT_HTTP_ENVELOPE_LEN_V1,
};
use pir_service_store::{ProviderStore, StoreError};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const PENDING_PAYOUT_FLOOR_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/provider-settlement/pending-payout-floor/v1";
const DURABLE_PAYOUT_STATE_COMMITMENT_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/provider-settlement/durable-payout-state/v1";
pub const MAX_SHARED_ISSUER_RESPONSE_BYTES_V1: usize = 64 * 1024;

pub const PROVIDER_BALANCE_ENDPOINT_V1: &str = "/v1/settlement/balance";
pub const PROVIDER_PAYOUT_INTENT_ENDPOINT_V1: &str = "/v1/settlement/payout-intents";
pub const PROVIDER_PAYOUT_ENDPOINT_V1: &str = "/v1/settlement/payouts";
pub const PROVIDER_PAYOUT_STATUS_ENDPOINT_V1: &str = "/v1/settlement/payout-status";

/// Settlement HTTP response ceiling. V1 settlement responses are fixed-size,
/// so accepting the much larger note-deposit envelope ceiling here would only
/// increase pre-authentication allocation risk.
pub const MAX_PROVIDER_SETTLEMENT_RESPONSE_BYTES_V1: usize =
    MAX_EXECUTABLE_SETTLEMENT_HTTP_ENVELOPE_LEN_V1;

/// Exact canonical body passed to a transport adapter. Adapters must disable
/// redirects and request/response-body logging. No body accepted by this
/// client contains invoices, payment hashes, preimages, PIR queries, or a peer
/// provider identifier.
pub struct ProviderSettlementHttpRequestV1<'a> {
    pub endpoint: &'static str,
    pub canonical_body: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderSettlementTransportErrorV1 {
    /// The adapter proves that no request bytes reached the issuer.
    NotSent,
    /// The issuer returned an authenticated HTTP rejection.
    Rejected { status: u16 },
    /// The request may have committed but its response was not received.
    /// Retry the exact operation with the exact idempotency key/nonce.
    OutcomeUnknown,
}

/// Transport-neutral boundary for a provider settlement client. A concrete
/// HTTP adapter owns TLS, redirect policy, timeouts, and status-code mapping.
pub trait ProviderSettlementTransportV1: Send + Sync {
    fn post(
        &self,
        request: ProviderSettlementHttpRequestV1<'_>,
        max_response_bytes: usize,
    ) -> Result<Vec<u8>, ProviderSettlementTransportErrorV1>;
}

#[derive(Debug)]
pub enum ProviderSettlementClientErrorV1 {
    Protocol(ServiceProtocolError),
    Transport(ProviderSettlementTransportErrorV1),
    ResponseTooLarge { len: usize, max: usize },
    Rollback,
}

impl fmt::Display for ProviderSettlementClientErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(formatter, "settlement protocol error: {error}"),
            Self::Transport(error) => write!(formatter, "settlement transport error: {error:?}"),
            Self::ResponseTooLarge { len, max } => {
                write!(
                    formatter,
                    "settlement response is {len} bytes (maximum {max})"
                )
            }
            Self::Rollback => formatter.write_str("settlement payout snapshot rollback"),
        }
    }
}

impl std::error::Error for ProviderSettlementClientErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ServiceProtocolError> for ProviderSettlementClientErrorV1 {
    fn from(error: ServiceProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<ProviderSettlementTransportErrorV1> for ProviderSettlementClientErrorV1 {
    fn from(error: ProviderSettlementTransportErrorV1) -> Self {
        Self::Transport(error)
    }
}

/// Provider-side copy of the issuer's authenticated settlement registration.
/// The digest is an opaque issuer-store handle (its store-instance domain is
/// intentionally not reproduced by this protocol client), and it plus the
/// validity interval/key come from trusted operator provisioning, never from
/// a settlement HTTP response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderSettlementRegistrationV1 {
    pub registration_digest: [u8; 32],
    pub provider_id: ProviderId,
    pub issuer_id: [u8; 32],
    pub settlement_account_id: [u8; 32],
    pub provider_request_verifying_key: [u8; 32],
    pub payout_target_id: PayoutTargetIdV1,
    pub not_before: u64,
    pub not_after: u64,
}

/// Issuer/operator trust material for provider settlement. The current key is
/// used for fresh registration-authenticated status reads. Retained keys are
/// verification-only and allow exact historical issuer responses to survive
/// settlement-key rotation.
pub struct ProviderSettlementTrustV1 {
    pub authorization: ProviderClearingAuthorizationV1,
    pub issuer_approval: IssuerClearingApprovalV1,
    pub operator_verifying_key: VerifyingKey,
    pub minimum_authorization_epoch: u64,
    pub registration: ProviderSettlementRegistrationV1,
    pub current_issuer_settlement_key: VerifyingKey,
    pub retained_issuer_settlement_keys: Vec<VerifyingKey>,
    /// Trusted historical registrations accepted only while restoring local
    /// issuer-signed state or verifying a persisted response. They never
    /// authorize preparation of a fresh request. Issuer-side historical lookup
    /// is additionally limited to an exact already-committed request digest;
    /// merely retaining a provider-side registration cannot authorize a new
    /// operation after registration rotation.
    pub retained_registrations: Vec<ProviderSettlementRegistrationV1>,
}

impl fmt::Debug for ProviderSettlementTrustV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderSettlementTrustV1")
            .field("provider_id", &self.registration.provider_id)
            .field("issuer_id", &self.registration.issuer_id)
            .field(
                "minimum_authorization_epoch",
                &self.minimum_authorization_epoch,
            )
            .field(
                "retained_issuer_settlement_key_count",
                &self.retained_issuer_settlement_keys.len(),
            )
            .field(
                "retained_registration_count",
                &self.retained_registrations.len(),
            )
            .finish_non_exhaustive()
    }
}

/// Verified signed payout intent. Persist both exact nested objects before
/// attempting payout execution; a lost payout response must be retried with
/// this exact intent and the same payout idempotency key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedProviderPayoutIntentV1 {
    request: ProviderPayoutIntentRequestV1,
    response: IssuerPayoutIntentResponseV1,
}

impl VerifiedProviderPayoutIntentV1 {
    pub fn request(&self) -> &ProviderPayoutIntentRequestV1 {
        &self.request
    }

    pub fn response(&self) -> &IssuerPayoutIntentResponseV1 {
        &self.response
    }
}

/// Independent-authority value for one exact payout preparation. The value
/// is domain-separated over the complete canonical pending record. It must be
/// stored outside the detailed provider payout database so rolling that
/// database back cannot silently authorize a different idempotency key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderPayoutPendingFloorV1 {
    pending_digest: [u8; 32],
}

impl ProviderPayoutPendingFloorV1 {
    /// Reconstructs an independently persisted pending authority. A zero value
    /// is never a valid floor and usually indicates an uninitialized or torn
    /// external-authority record.
    pub fn from_digest(pending_digest: [u8; 32]) -> Result<Self, ServiceProtocolError> {
        if pending_digest.iter().all(|byte| *byte == 0) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderPayoutPendingFloorV1.pending_digest",
                reason: "pending digest must be non-zero",
            });
        }
        Ok(Self { pending_digest })
    }

    pub fn pending_digest(&self) -> &[u8; 32] {
        &self.pending_digest
    }
}

/// Exact initial payout request durably recorded before any request byte is
/// sent. Redundant canonical intent fields make store and restore binding
/// explicit; they must exactly equal the nested objects in the envelope.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderPayoutPendingV1 {
    pub canonical_envelope: Vec<u8>,
    pub payout_request_digest: [u8; 32],
    pub idempotency_key: [u8; 32],
    pub intent_request: Vec<u8>,
    pub intent_response: Vec<u8>,
    pub registration: ProviderSettlementRegistrationV1,
    /// `None` only for the first payout in a provider workflow store. Later
    /// payouts must name the exact independently protected terminal floor they
    /// advance from, forming a rollback-detecting payout chain.
    pub predecessor_floor: Option<ProviderPayoutRollbackFloorV1>,
    pub pending_floor: ProviderPayoutPendingFloorV1,
}

impl fmt::Debug for ProviderPayoutPendingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderPayoutPendingV1")
            .field("canonical_envelope_len", &self.canonical_envelope.len())
            .field("payout_request", &"[REDACTED]")
            .field("idempotency_key", &"[REDACTED]")
            .field("has_predecessor", &self.predecessor_floor.is_some())
            .finish_non_exhaustive()
    }
}

impl Drop for ProviderPayoutPendingV1 {
    fn drop(&mut self) {
        self.canonical_envelope.zeroize();
        self.payout_request_digest.zeroize();
        self.idempotency_key.zeroize();
        self.intent_request.zeroize();
        self.intent_response.zeroize();
    }
}

/// Small anti-rollback floor value. The value itself is not an authority:
/// persist it in a store whose rollback boundary is independent from the
/// detailed payout record. Keeping it only inside the record cannot detect
/// rollback of the whole record or restoration of an old backup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderPayoutRollbackFloorV1 {
    payout_id: [u8; 32],
    payout_request_digest: [u8; 32],
    ledger_transaction_id: [u8; 32],
    state: PayoutStateV1,
    state_version: u64,
    updated_at: u64,
}

impl ProviderPayoutRollbackFloorV1 {
    pub fn from_parts(
        payout_id: [u8; 32],
        payout_request_digest: [u8; 32],
        ledger_transaction_id: [u8; 32],
        state: PayoutStateV1,
        state_version: u64,
        updated_at: u64,
    ) -> Result<Self, ServiceProtocolError> {
        if payout_id.iter().all(|byte| *byte == 0)
            || payout_request_digest.iter().all(|byte| *byte == 0)
            || ledger_transaction_id.iter().all(|byte| *byte == 0)
            || state_version == 0
            || updated_at == 0
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderPayoutRollbackFloorV1",
                reason: "payout identity, state version, and update time must be non-zero",
            });
        }
        Ok(Self {
            payout_id,
            payout_request_digest,
            ledger_transaction_id,
            state,
            state_version,
            updated_at,
        })
    }

    fn from_snapshot(snapshot: &VerifiedPayoutSnapshotV1) -> Self {
        Self::from_parts(
            *snapshot.payout_id(),
            *snapshot.payout_request_digest(),
            *snapshot.ledger_transaction_id(),
            snapshot.state(),
            snapshot.state_version(),
            snapshot.updated_at(),
        )
        .expect("verified payout snapshot has canonical non-zero floor fields")
    }

    pub fn payout_id(&self) -> &[u8; 32] {
        &self.payout_id
    }

    pub fn payout_request_digest(&self) -> &[u8; 32] {
        &self.payout_request_digest
    }

    pub fn ledger_transaction_id(&self) -> &[u8; 32] {
        &self.ledger_transaction_id
    }

    pub fn state(&self) -> PayoutStateV1 {
        self.state
    }

    pub fn state_version(&self) -> u64 {
        self.state_version
    }

    pub fn updated_at(&self) -> u64 {
        self.updated_at
    }
}

/// Canonical provider payout state that must be durably stored. It contains
/// the exact intent request/response, payout request/initial response, latest
/// accepted status response, and the matching rollback floor. It contains no
/// wallet destination or Lightning/PIR material.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderPayoutDurableStateV1 {
    pub intent_request: Vec<u8>,
    pub intent_response: Vec<u8>,
    pub payout_request: Vec<u8>,
    pub initial_payout_response: Vec<u8>,
    pub latest_status_response: Option<Vec<u8>>,
    pub rollback_floor: ProviderPayoutRollbackFloorV1,
}

impl fmt::Debug for ProviderPayoutDurableStateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderPayoutDurableStateV1")
            .field("state", &self.rollback_floor.state())
            .field("state_version", &self.rollback_floor.state_version())
            .field("updated_at", &self.rollback_floor.updated_at())
            .field("exact_protocol_bytes", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl Drop for ProviderPayoutDurableStateV1 {
    fn drop(&mut self) {
        self.intent_request.zeroize();
        self.intent_response.zeroize();
        self.payout_request.zeroize();
        self.initial_payout_response.zeroize();
        self.latest_status_response.zeroize();
    }
}

/// Exact status request durably recorded before any request byte is sent.
/// The historical registration is included so an exact response remains
/// client-verifiable after trust rotation. End-to-end replay after ordinary
/// expiry or registration replacement additionally requires the issuer's
/// exact committed-request replay path and retained registration history.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderPayoutStatusPendingV1 {
    pub canonical_envelope: Vec<u8>,
    pub request_digest: [u8; 32],
    pub registration: ProviderSettlementRegistrationV1,
    pub previous_floor: ProviderPayoutRollbackFloorV1,
    /// Exact content commitment of the authenticated durable payout state from
    /// which this status request was prepared. This lets a crash-recovery
    /// journal reconstruct the authority's pre-status commitment even after a
    /// signed successor has replaced the detailed current-state bytes.
    pub previous_state_commitment: [u8; 32],
}

impl fmt::Debug for ProviderPayoutStatusPendingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderPayoutStatusPendingV1")
            .field("canonical_envelope_len", &self.canonical_envelope.len())
            .field("request", &"[REDACTED]")
            .field("previous_state", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl Drop for ProviderPayoutStatusPendingV1 {
    fn drop(&mut self) {
        self.canonical_envelope.zeroize();
        self.request_digest.zeroize();
        self.previous_state_commitment.zeroize();
    }
}

/// Client-authenticated capability for installing one exact pending payout.
/// Fields are private so callers cannot bypass canonical/trust verification and
/// invoke a durable store directly with a hand-built record.
#[derive(Clone)]
pub struct VerifiedProviderPayoutPendingWriteV1 {
    pub(crate) pending: ProviderPayoutPendingV1,
}

impl VerifiedProviderPayoutPendingWriteV1 {
    pub fn pending(&self) -> &ProviderPayoutPendingV1 {
        &self.pending
    }
}

impl fmt::Debug for VerifiedProviderPayoutPendingWriteV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedProviderPayoutPendingWriteV1")
            .field("payout_request_digest", &self.pending.payout_request_digest)
            .finish_non_exhaustive()
    }
}

/// Client-authenticated capability for replacing an exact pending payout with
/// its issuer-signed initial `Accepted/v1` state.
#[derive(Clone)]
pub struct VerifiedProviderPayoutInitialWriteV1 {
    pub(crate) pending: ProviderPayoutPendingV1,
    pub(crate) state: ProviderPayoutDurableStateV1,
}

impl VerifiedProviderPayoutInitialWriteV1 {
    pub fn pending(&self) -> &ProviderPayoutPendingV1 {
        &self.pending
    }

    pub fn state(&self) -> &ProviderPayoutDurableStateV1 {
        &self.state
    }
}

impl fmt::Debug for VerifiedProviderPayoutInitialWriteV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedProviderPayoutInitialWriteV1")
            .field("payout_request_digest", &self.pending.payout_request_digest)
            .field("state", &self.state.rollback_floor.state())
            .field("state_version", &self.state.rollback_floor.state_version())
            .finish_non_exhaustive()
    }
}

/// Client-authenticated capability for installing one exact read-only payout
/// status request before any request byte leaves the provider.
#[derive(Clone)]
pub struct VerifiedProviderPayoutStatusPendingWriteV1 {
    pub(crate) pending: ProviderPayoutStatusPendingV1,
}

impl VerifiedProviderPayoutStatusPendingWriteV1 {
    pub fn pending(&self) -> &ProviderPayoutStatusPendingV1 {
        &self.pending
    }
}

impl fmt::Debug for VerifiedProviderPayoutStatusPendingWriteV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedProviderPayoutStatusPendingWriteV1")
            .field("request_digest", &self.pending.request_digest)
            .finish_non_exhaustive()
    }
}

/// Client-authenticated capability for committing one exact issuer-signed
/// payout status successor from its exact pending status request.
#[derive(Clone)]
pub struct VerifiedProviderPayoutStatusWriteV1 {
    pub(crate) pending: ProviderPayoutStatusPendingV1,
    pub(crate) state: ProviderPayoutDurableStateV1,
}

impl VerifiedProviderPayoutStatusWriteV1 {
    pub fn pending(&self) -> &ProviderPayoutStatusPendingV1 {
        &self.pending
    }

    pub fn state(&self) -> &ProviderPayoutDurableStateV1 {
        &self.state
    }
}

impl fmt::Debug for VerifiedProviderPayoutStatusWriteV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedProviderPayoutStatusWriteV1")
            .field("request_digest", &self.pending.request_digest)
            .field("state", &self.state.rollback_floor.state())
            .field("state_version", &self.state.rollback_floor.state_version())
            .finish_non_exhaustive()
    }
}

/// Durable provider settlement state boundary. Implementations must update
/// the detailed state and their independent monotonic rollback authority in
/// one transaction (or a crash-safe equivalent).
pub trait ProviderSettlementStateStoreV1 {
    type Error;

    /// Atomically install one exact pending payout and CAS an independently
    /// durable authority to `pending.pending_floor`. The same provider store
    /// must serialize active workflows. A first payout requires empty state;
    /// a later payout requires `predecessor_floor` to exactly equal the
    /// current terminal payout and independent floor. The transition must
    /// preserve/archive that predecessor before advancing the authority. A
    /// different pending digest is a conflict; an exact pending replay may
    /// return true. If detailed state is missing while the external authority
    /// already names a pending digest, this must fail closed rather than
    /// creating a replacement payout.
    fn persist_pending_payout(
        &mut self,
        write: &VerifiedProviderPayoutPendingWriteV1,
    ) -> Result<bool, Self::Error>;

    /// Atomically require the exact pending row/floor, replace it with the
    /// verified initial payout state, and advance the independent authority
    /// from the pending digest to `state.rollback_floor`. A concurrent exact
    /// replay may return true only when the already durable state is byte-for-
    /// byte equal; no second economic payout may be represented. The committed
    /// workflow metadata must durably retain the origin pending digest and its
    /// optional predecessor link even after the active pending row is removed,
    /// so history/audit and exact-concurrency checks do not lose the chain.
    fn commit_initial_payout_from_pending(
        &mut self,
        write: &VerifiedProviderPayoutInitialWriteV1,
    ) -> Result<bool, Self::Error>;

    /// Persist a pending exact status request before network submission. The
    /// store must compare `previous_floor` against its independent authority.
    fn persist_pending_status(
        &mut self,
        write: &VerifiedProviderPayoutStatusPendingWriteV1,
    ) -> Result<bool, Self::Error>;

    /// Atomically CAS the previous floor, store the exact signed successor,
    /// advance the independent floor, and remove the matching pending request.
    fn commit_status_update(
        &mut self,
        write: &VerifiedProviderPayoutStatusWriteV1,
    ) -> Result<bool, Self::Error>;
}

#[derive(Debug)]
pub enum ProviderSettlementStateErrorV1<E> {
    Client(ProviderSettlementClientErrorV1),
    Store(E),
    Conflict { operation: &'static str },
}

impl<E: fmt::Display> fmt::Display for ProviderSettlementStateErrorV1<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client(error) => error.fmt(formatter),
            Self::Store(error) => write!(formatter, "provider settlement store error: {error}"),
            Self::Conflict { operation } => {
                write!(formatter, "provider settlement state conflict: {operation}")
            }
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for ProviderSettlementStateErrorV1<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Client(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::Conflict { .. } => None,
        }
    }
}

impl<E> From<ProviderSettlementClientErrorV1> for ProviderSettlementStateErrorV1<E> {
    fn from(error: ProviderSettlementClientErrorV1) -> Self {
        Self::Client(error)
    }
}

/// Marker whose private field proves the pending request was either committed
/// through [`ProviderSettlementStateStoreV1`] or loaded and revalidated from a
/// trusted provider store.
#[derive(Clone)]
pub struct PersistedProviderPayoutStatusV1 {
    pending: ProviderPayoutStatusPendingV1,
}

/// Marker whose private field proves an exact initial payout was persisted
/// before network submission, or restored only after matching an independent
/// pending floor and revalidating all canonical trust bindings.
#[derive(Clone)]
pub struct PersistedProviderPayoutV1 {
    pending: ProviderPayoutPendingV1,
}

impl fmt::Debug for PersistedProviderPayoutV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistedProviderPayoutV1")
            .field("pending", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for PersistedProviderPayoutStatusV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistedProviderPayoutStatusV1")
            .field("pending", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl PersistedProviderPayoutV1 {
    pub fn pending(&self) -> &ProviderPayoutPendingV1 {
        &self.pending
    }
}

impl PersistedProviderPayoutStatusV1 {
    pub fn pending(&self) -> &ProviderPayoutStatusPendingV1 {
        &self.pending
    }
}

/// In-memory, issuer-authenticated payout state. Every successful status call
/// returns a new value; callers must atomically persist its durable form and
/// advance the independent rollback floor before replacing the old value.
#[derive(Clone)]
pub struct VerifiedProviderPayoutStateV1 {
    intent: VerifiedProviderPayoutIntentV1,
    payout_request: ProviderPayoutRequestV1,
    initial_response: IssuerPayoutResponseV1,
    latest_status_response: Option<IssuerPayoutStatusResponseV1>,
    snapshot: VerifiedPayoutSnapshotV1,
}

impl fmt::Debug for VerifiedProviderPayoutStateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedProviderPayoutStateV1")
            .field("state", &self.snapshot.state())
            .field("state_version", &self.snapshot.state_version())
            .field("updated_at", &self.snapshot.updated_at())
            .finish_non_exhaustive()
    }
}

impl VerifiedProviderPayoutStateV1 {
    pub fn intent(&self) -> &VerifiedProviderPayoutIntentV1 {
        &self.intent
    }

    pub fn payout_request(&self) -> &ProviderPayoutRequestV1 {
        &self.payout_request
    }

    pub fn initial_response(&self) -> &IssuerPayoutResponseV1 {
        &self.initial_response
    }

    pub fn snapshot(&self) -> &VerifiedPayoutSnapshotV1 {
        &self.snapshot
    }

    pub fn rollback_floor(&self) -> ProviderPayoutRollbackFloorV1 {
        ProviderPayoutRollbackFloorV1::from_snapshot(&self.snapshot)
    }

    pub fn durable_state(
        &self,
    ) -> Result<ProviderPayoutDurableStateV1, ProviderSettlementClientErrorV1> {
        Ok(ProviderPayoutDurableStateV1 {
            intent_request: self.intent.request.encode()?,
            intent_response: self.intent.response.encode()?,
            payout_request: self.payout_request.encode()?,
            initial_payout_response: self.initial_response.encode()?,
            latest_status_response: self
                .latest_status_response
                .as_ref()
                .map(IssuerPayoutStatusResponseV1::encode)
                .transpose()?,
            rollback_floor: self.rollback_floor(),
        })
    }
}

/// Provider settlement client. The clearing key signs debt-related operations;
/// the distinct provider-request key signs only recovery/read-only status.
pub struct ProviderSettlementClientV1<'a> {
    trust: ProviderSettlementTrustV1,
    clearing_signing_key: SigningKey,
    provider_request_signing_key: SigningKey,
    transport: &'a dyn ProviderSettlementTransportV1,
}

impl fmt::Debug for ProviderSettlementClientV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderSettlementClientV1")
            .field("trust", &self.trust)
            .finish_non_exhaustive()
    }
}

impl<'a> ProviderSettlementClientV1<'a> {
    pub fn new(
        trust: ProviderSettlementTrustV1,
        clearing_signing_key: SigningKey,
        provider_request_signing_key: SigningKey,
        transport: &'a dyn ProviderSettlementTransportV1,
    ) -> Result<Self, ProviderSettlementClientErrorV1> {
        let registration = &trust.registration;
        if registration
            .registration_digest
            .iter()
            .all(|byte| *byte == 0)
            || registration.payout_target_id.iter().all(|byte| *byte == 0)
            || registration.not_before == 0
            || registration.not_after < registration.not_before
            || registration.provider_id != trust.authorization.claims.provider_id
            || registration.issuer_id != trust.authorization.claims.issuer_id
            || registration.settlement_account_id
                != trust.authorization.claims.settlement_account_id
            || trust.authorization.claims.clearing_verifying_key
                != clearing_signing_key.verifying_key().to_bytes()
            || registration.provider_request_verifying_key
                != provider_request_signing_key.verifying_key().to_bytes()
            || clearing_signing_key.verifying_key().to_bytes()
                == provider_request_signing_key.verifying_key().to_bytes()
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderSettlementClientV1.trust",
                reason: "registration audience, validity, payout target, or distinct provider keys mismatch",
            }
            .into());
        }
        if trust.retained_registrations.iter().any(|retained| {
            retained.registration_digest.iter().all(|byte| *byte == 0)
                || retained.payout_target_id.iter().all(|byte| *byte == 0)
                || retained.not_before == 0
                || retained.not_after < retained.not_before
                || VerifyingKey::from_bytes(&retained.provider_request_verifying_key).is_err()
                || retained.registration_digest == registration.registration_digest
                || retained.provider_id != registration.provider_id
                || retained.issuer_id != registration.issuer_id
                || retained.settlement_account_id != registration.settlement_account_id
        }) || trust
            .retained_registrations
            .iter()
            .enumerate()
            .any(|(index, retained)| {
                trust.retained_registrations[index + 1..]
                    .iter()
                    .any(|other| other.registration_digest == retained.registration_digest)
            })
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderSettlementTrustV1.retained_registrations",
                reason: "retained registrations must be non-zero, unique, historical, and provider-bound",
            }
            .into());
        }
        let keyring = IssuerSettlementKeyringExpectationV1 {
            issuer_id: &registration.issuer_id,
            current_key: &trust.current_issuer_settlement_key,
            retained_keys: &trust.retained_issuer_settlement_keys,
        };
        let approval_key = keyring.resolve_for_issuer(
            &registration.issuer_id,
            &trust.issuer_approval.issuer_settlement_key_id,
        )?;
        let validation_time = trust
            .authorization
            .claims
            .not_before
            .max(trust.issuer_approval.approved_at);
        trust.authorization.verify_for(
            &registration.provider_id,
            &registration.issuer_id,
            &trust.operator_verifying_key,
            validation_time,
            trust.minimum_authorization_epoch,
        )?;
        trust.issuer_approval.verify_for(
            &trust.authorization,
            approval_key,
            validation_time,
            trust.minimum_authorization_epoch,
        )?;
        Ok(Self {
            trust,
            clearing_signing_key,
            provider_request_signing_key,
            transport,
        })
    }

    pub fn balance(
        &self,
        unit: SettlementUnitV1,
        fresh_request_nonce: [u8; 32],
    ) -> Result<IssuerBalanceResponseV1, ProviderSettlementClientErrorV1> {
        let request = ProviderBalanceRequestV1 {
            authorization_digest: self.authorization_digest()?,
            issuer_id: self.trust.registration.issuer_id,
            provider_id: self.trust.registration.provider_id,
            account_id: self.trust.registration.settlement_account_id,
            unit,
            idempotency_key: fresh_request_nonce,
        };
        let request_auth = self.clearing_auth(request.request_digest()?);
        let body = ProviderBalanceEnvelopeV1 {
            request: request.clone(),
            request_auth,
        }
        .encode()?;
        let bytes = self.post(PROVIDER_BALANCE_ENDPOINT_V1, &body)?;
        let response = decode_canonical_response(
            &bytes,
            IssuerBalanceResponseV1::decode,
            IssuerBalanceResponseV1::encode,
        )?;
        let response_key = self.response_key(&response.issuer_settlement_key_id)?;
        response.verify_for_exact_request(&request, &response_key)?;
        Ok(response)
    }

    pub fn payout_intent(
        &self,
        unit: SettlementUnitV1,
        payout_value: u64,
        idempotency_key: [u8; 32],
    ) -> Result<VerifiedProviderPayoutIntentV1, ProviderSettlementClientErrorV1> {
        let request = ProviderPayoutIntentRequestV1 {
            authorization_digest: self.authorization_digest()?,
            issuer_id: self.trust.registration.issuer_id,
            provider_id: self.trust.registration.provider_id,
            account_id: self.trust.registration.settlement_account_id,
            payout_target_id: self.trust.registration.payout_target_id,
            unit,
            payout_value,
            idempotency_key,
        };
        let request_auth = self.clearing_auth(request.request_digest()?);
        let body = ProviderPayoutIntentEnvelopeV1 {
            request: request.clone(),
            request_auth,
        }
        .encode()?;
        let bytes = self.post(PROVIDER_PAYOUT_INTENT_ENDPOINT_V1, &body)?;
        let response = decode_canonical_response(
            &bytes,
            IssuerPayoutIntentResponseV1::decode,
            IssuerPayoutIntentResponseV1::encode,
        )?;
        self.verify_intent_response(&request, &response)?;
        Ok(VerifiedProviderPayoutIntentV1 { request, response })
    }

    /// Builds and validates one fresh payout request, then persists its exact
    /// bytes and independent pending floor before returning a submit-capable
    /// marker. `now_unix` is used only on this fresh path; historical restore
    /// never substitutes a registration's `not_before` for current time.
    pub fn prepare_payout<Store: ProviderSettlementStateStoreV1>(
        &self,
        intent: &VerifiedProviderPayoutIntentV1,
        idempotency_key: [u8; 32],
        now_unix: u64,
        store: &mut Store,
    ) -> Result<PersistedProviderPayoutV1, ProviderSettlementStateErrorV1<Store::Error>> {
        self.prepare_payout_from_predecessor(intent, idempotency_key, now_unix, None, store)
    }

    /// Prepares a later payout by atomically advancing from an already
    /// verified terminal payout floor. This explicit API prevents a provider
    /// store from becoming a one-lifetime-payout slot while retaining a
    /// monotonic chain across independent-authority and detailed-store backup
    /// boundaries.
    pub fn prepare_next_payout<Store: ProviderSettlementStateStoreV1>(
        &self,
        intent: &VerifiedProviderPayoutIntentV1,
        idempotency_key: [u8; 32],
        now_unix: u64,
        predecessor: &VerifiedProviderPayoutStateV1,
        store: &mut Store,
    ) -> Result<PersistedProviderPayoutV1, ProviderSettlementStateErrorV1<Store::Error>> {
        let predecessor_floor = predecessor.rollback_floor();
        if !matches!(
            predecessor_floor.state(),
            PayoutStateV1::Succeeded | PayoutStateV1::Failed
        ) {
            return Err(ProviderSettlementClientErrorV1::Protocol(
                ServiceProtocolError::InvalidValue {
                    field: "ProviderPayoutPendingV1.predecessor_floor",
                    reason: "a later payout requires an exact terminal predecessor",
                },
            )
            .into());
        }
        self.prepare_payout_from_predecessor(
            intent,
            idempotency_key,
            now_unix,
            Some(predecessor_floor),
            store,
        )
    }

    fn prepare_payout_from_predecessor<Store: ProviderSettlementStateStoreV1>(
        &self,
        intent: &VerifiedProviderPayoutIntentV1,
        idempotency_key: [u8; 32],
        now_unix: u64,
        predecessor_floor: Option<ProviderPayoutRollbackFloorV1>,
        store: &mut Store,
    ) -> Result<PersistedProviderPayoutV1, ProviderSettlementStateErrorV1<Store::Error>> {
        let pending =
            self.build_pending_payout(intent, idempotency_key, now_unix, predecessor_floor)?;
        let write = VerifiedProviderPayoutPendingWriteV1 {
            pending: pending.clone(),
        };
        let committed = store
            .persist_pending_payout(&write)
            .map_err(ProviderSettlementStateErrorV1::Store)?;
        if !committed {
            return Err(ProviderSettlementStateErrorV1::Conflict {
                operation: "pending_initial_payout_and_floor_commit",
            });
        }
        Ok(PersistedProviderPayoutV1 { pending })
    }

    /// Reconstructs a submit-capable marker from exact durable bytes only
    /// after the independently loaded authority equals the pending digest.
    /// This API receives no nonce, signing key, or idempotency input and cannot
    /// manufacture a replacement payout after detailed-store rollback.
    pub fn restore_persisted_payout(
        &self,
        pending: ProviderPayoutPendingV1,
        trusted_pending_floor: &ProviderPayoutPendingFloorV1,
    ) -> Result<PersistedProviderPayoutV1, ProviderSettlementClientErrorV1> {
        if &pending.pending_floor != trusted_pending_floor {
            return Err(ProviderSettlementClientErrorV1::Rollback);
        }
        self.decode_and_verify_pending_payout(&pending)?;
        Ok(PersistedProviderPayoutV1 { pending })
    }

    /// Reconfirms and sends one already persisted exact payout. An unknown
    /// network outcome leaves the pending marker untouched; retrying this
    /// method posts byte-identical request data. A verified issuer response is
    /// returned only after the store atomically transitions pending state and
    /// its independent authority to the initial payout rollback floor.
    pub fn submit_payout<Store: ProviderSettlementStateStoreV1>(
        &self,
        persisted: &PersistedProviderPayoutV1,
        store: &mut Store,
    ) -> Result<VerifiedProviderPayoutStateV1, ProviderSettlementStateErrorV1<Store::Error>> {
        let pending = &persisted.pending;
        self.decode_and_verify_pending_payout(pending)?;
        let pending_write = VerifiedProviderPayoutPendingWriteV1 {
            pending: pending.clone(),
        };
        let still_persisted = store
            .persist_pending_payout(&pending_write)
            .map_err(ProviderSettlementStateErrorV1::Store)?;
        if !still_persisted {
            return Err(ProviderSettlementStateErrorV1::Conflict {
                operation: "pending_initial_payout_recheck",
            });
        }
        let envelope = self.decode_and_verify_pending_payout(pending)?;
        let bytes = self.post(PROVIDER_PAYOUT_ENDPOINT_V1, &pending.canonical_envelope)?;
        let response = decode_canonical_response(
            &bytes,
            IssuerPayoutResponseV1::decode,
            IssuerPayoutResponseV1::encode,
        )?;
        let snapshot = verify_payout_initial_response_for_exact_request(
            &response,
            &envelope.request,
            &self.issuer_keyring(),
        )
        .map_err(ProviderSettlementClientErrorV1::from)?;
        let state = VerifiedProviderPayoutStateV1 {
            intent: VerifiedProviderPayoutIntentV1 {
                request: envelope.intent_request,
                response: envelope.intent_response,
            },
            payout_request: envelope.request,
            initial_response: response,
            latest_status_response: None,
            snapshot,
        };
        let durable = state.durable_state()?;
        let write = VerifiedProviderPayoutInitialWriteV1 {
            pending: pending.clone(),
            state: durable,
        };
        let committed = store
            .commit_initial_payout_from_pending(&write)
            .map_err(ProviderSettlementStateErrorV1::Store)?;
        if !committed {
            return Err(ProviderSettlementStateErrorV1::Conflict {
                operation: "pending_to_initial_payout_and_floor_commit",
            });
        }
        Ok(state)
    }

    fn build_pending_payout(
        &self,
        intent: &VerifiedProviderPayoutIntentV1,
        idempotency_key: [u8; 32],
        now_unix: u64,
        predecessor_floor: Option<ProviderPayoutRollbackFloorV1>,
    ) -> Result<ProviderPayoutPendingV1, ProviderSettlementClientErrorV1> {
        let request = self.payout_request(intent, idempotency_key)?;
        let request_auth = self.clearing_auth(request.request_digest()?);
        let envelope = ProviderPayoutEnvelopeV1 {
            request: request.clone(),
            request_auth: request_auth.clone(),
            intent_request: intent.request.clone(),
            intent_response: intent.response.clone(),
        };
        let canonical_envelope = envelope.encode()?;
        let intent_request = intent.request.encode()?;
        let intent_response = intent.response.encode()?;
        let payout_request_digest = request.request_digest()?;
        let registration = self.trust.registration.clone();
        let pending_floor = pending_payout_floor_v1(
            &canonical_envelope,
            &payout_request_digest,
            &idempotency_key,
            &intent_request,
            &intent_response,
            &registration,
            predecessor_floor.as_ref(),
        )?;
        let pending = ProviderPayoutPendingV1 {
            canonical_envelope,
            payout_request_digest,
            idempotency_key,
            intent_request,
            intent_response,
            registration,
            predecessor_floor,
            pending_floor,
        };

        // First establish that the exact pending record is internally
        // canonical and historically authenticated. Then apply all *fresh*
        // authorities with the caller-supplied real clock. In particular, a
        // retained registration or key can never be smuggled into this path.
        let verified = self.decode_and_verify_pending_payout(&pending)?;
        if pending.registration != self.trust.registration
            || now_unix < self.trust.registration.not_before
            || now_unix > self.trust.registration.not_after
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderPayoutPendingV1.fresh_registration",
                reason: "fresh payout preparation requires the current registration and real-time validity",
            }
            .into());
        }
        let execution_context = PayoutExecutionContextV1 {
            intent_request: &verified.intent_request,
            intent_response: &verified.intent_response,
            registered_payout_target_id: &self.trust.registration.payout_target_id,
        };
        verify_new_payout_request_for(
            &verified.request,
            &execution_context,
            &self.trust.authorization,
            &self.trust.issuer_approval,
            &verified.request_auth,
            &ProviderClearingExpectationV1 {
                provider_id: &self.trust.registration.provider_id,
                issuer_id: &self.trust.registration.issuer_id,
                operator_key: &self.trust.operator_verifying_key,
                issuer_settlement_key: &self.trust.current_issuer_settlement_key,
                now_unix,
                minimum_authorization_epoch: self.trust.minimum_authorization_epoch,
            },
        )?;
        Ok(pending)
    }

    /// Creates and durably records a fresh status request before any network
    /// submission. `request_nonce` must be fresh relative to every accepted or
    /// pending request. An outcome-unknown submission is retried through the
    /// returned persisted marker, never by preparing a new nonce.
    pub fn prepare_payout_status<Store: ProviderSettlementStateStoreV1>(
        &self,
        payout: &VerifiedProviderPayoutStateV1,
        request_nonce: [u8; 32],
        now_unix: u64,
        store: &mut Store,
    ) -> Result<PersistedProviderPayoutStatusV1, ProviderSettlementStateErrorV1<Store::Error>> {
        let pending = self.build_pending_status(payout, request_nonce, now_unix)?;
        let write = VerifiedProviderPayoutStatusPendingWriteV1 {
            pending: pending.clone(),
        };
        let committed = store
            .persist_pending_status(&write)
            .map_err(ProviderSettlementStateErrorV1::Store)?;
        if !committed {
            return Err(ProviderSettlementStateErrorV1::Conflict {
                operation: "pending_payout_status_commit",
            });
        }
        Ok(PersistedProviderPayoutStatusV1 { pending })
    }

    /// Revalidates an exact pending status request loaded from trusted durable
    /// provider state. Historical registration/key trust is allowed only on
    /// this recovery path, never while preparing a fresh request.
    pub fn restore_persisted_payout_status(
        &self,
        payout: &VerifiedProviderPayoutStateV1,
        pending: ProviderPayoutStatusPendingV1,
    ) -> Result<PersistedProviderPayoutStatusV1, ProviderSettlementClientErrorV1> {
        self.decode_and_verify_pending_status(payout, &pending, pending.registration.not_before)?;
        Ok(PersistedProviderPayoutStatusV1 { pending })
    }

    /// Sends an already persisted exact status request, verifies strict
    /// monotonic progression, then atomically commits the signed successor and
    /// floor before returning it. Exact retries remain valid after ordinary
    /// registration expiry because the persisted historical registration and
    /// request signature are revalidated at their original validity window.
    pub fn submit_payout_status<Store: ProviderSettlementStateStoreV1>(
        &self,
        payout: &VerifiedProviderPayoutStateV1,
        persisted: &PersistedProviderPayoutStatusV1,
        store: &mut Store,
    ) -> Result<VerifiedProviderPayoutStateV1, ProviderSettlementStateErrorV1<Store::Error>> {
        let pending = &persisted.pending;
        let envelope = self.decode_and_verify_pending_status(
            payout,
            pending,
            pending.registration.not_before,
        )?;
        let bytes = self.post(
            PROVIDER_PAYOUT_STATUS_ENDPOINT_V1,
            &pending.canonical_envelope,
        )?;
        let response = decode_canonical_response(
            &bytes,
            IssuerPayoutStatusResponseV1::decode,
            IssuerPayoutStatusResponseV1::encode,
        )?;
        let snapshot =
            self.verify_historical_status_response(payout, pending, &envelope, &response)?;
        let mut next = payout.clone();
        next.latest_status_response = Some(response);
        next.snapshot = snapshot;
        let durable = next.durable_state()?;
        let write = VerifiedProviderPayoutStatusWriteV1 {
            pending: pending.clone(),
            state: durable,
        };
        let committed = store
            .commit_status_update(&write)
            .map_err(ProviderSettlementStateErrorV1::Store)?;
        if !committed {
            return Err(ProviderSettlementStateErrorV1::Conflict {
                operation: "payout_status_and_floor_cas",
            });
        }
        Ok(next)
    }

    fn build_pending_status(
        &self,
        payout: &VerifiedProviderPayoutStateV1,
        request_nonce: [u8; 32],
        now_unix: u64,
    ) -> Result<ProviderPayoutStatusPendingV1, ProviderSettlementClientErrorV1> {
        let request = ProviderPayoutStatusRequestV1 {
            registration_digest: self.trust.registration.registration_digest,
            issuer_id: self.trust.registration.issuer_id,
            provider_id: self.trust.registration.provider_id,
            account_id: self.trust.registration.settlement_account_id,
            payout_id: *payout.snapshot.payout_id(),
            payout_request_digest: *payout.snapshot.payout_request_digest(),
            request_nonce,
        };
        let request_auth = ProviderSettlementRequestAuthV1::sign(
            self.trust.registration.registration_digest,
            request.request_digest()?,
            &self.provider_request_signing_key,
        );
        let body = ProviderPayoutStatusEnvelopeV1 {
            request: request.clone(),
            request_auth: request_auth.clone(),
            payout_request: payout.payout_request.clone(),
            initial_payout_response: payout.initial_response.clone(),
        }
        .encode()?;
        let previous_state_commitment =
            provider_payout_durable_state_commitment_v1(&payout.durable_state()?)?;
        let pending = ProviderPayoutStatusPendingV1 {
            canonical_envelope: body,
            request_digest: request.request_digest()?,
            registration: self.trust.registration.clone(),
            previous_floor: payout.rollback_floor(),
            previous_state_commitment,
        };
        self.decode_and_verify_pending_status(payout, &pending, now_unix)?;
        Ok(pending)
    }

    /// Authenticates every protocol object needed to complete one interrupted
    /// SQLite journal. Inspection itself is deliberately pure read and does not
    /// grant the store authority to advance its independent floor.
    pub fn authenticate_settlement_recovery_v2(
        &self,
        unverified: &UnverifiedProviderSettlementRecoveryV2,
    ) -> Result<VerifiedProviderSettlementRecoveryV2, ProviderSettlementClientErrorV1> {
        if unverified.desired_floor.provider_id() != &self.trust.registration.provider_id
            || unverified
                .expected_floor
                .as_ref()
                .is_some_and(|floor| floor.provider_id() != unverified.desired_floor.provider_id())
            || (unverified.authority_at_inspection != unverified.expected_floor
                && unverified.authority_at_inspection != Some(unverified.desired_floor))
        {
            return Err(ProviderSettlementClientErrorV1::Rollback);
        }

        let workflow = &unverified.workflow;
        let verify_origin_for = |origin: &ProviderPayoutPendingV1,
                                 state: &ProviderPayoutDurableStateV1|
         -> Result<(), ProviderSettlementClientErrorV1> {
            self.decode_and_verify_pending_payout(origin)?;
            if state.rollback_floor.payout_request_digest() != &origin.payout_request_digest {
                return Err(ProviderSettlementClientErrorV1::Rollback);
            }
            Ok(())
        };

        match unverified.transition_kind {
            ProviderSettlementRecoveryTransitionKindV2::PendingPayout => {
                let pending = workflow.active_pending_payout.as_ref().ok_or(
                    ServiceProtocolError::InvalidValue {
                        field: "UnverifiedProviderSettlementRecoveryV2.active_pending_payout",
                        reason: "pending-payout recovery is missing its exact request",
                    },
                )?;
                self.decode_and_verify_pending_payout(pending)?;
                if unverified.transition_previous_state.is_some() {
                    return Err(ProviderSettlementClientErrorV1::Rollback);
                }
                match pending.predecessor_floor {
                    None => {
                        if workflow.payout_state.is_some()
                            || workflow.committed_payout_origin.is_some()
                        {
                            return Err(ProviderSettlementClientErrorV1::Rollback);
                        }
                    }
                    Some(predecessor) => {
                        let state = workflow
                            .payout_state
                            .as_ref()
                            .ok_or(ProviderSettlementClientErrorV1::Rollback)?;
                        let origin = workflow
                            .committed_payout_origin
                            .as_ref()
                            .ok_or(ProviderSettlementClientErrorV1::Rollback)?;
                        self.restore_payout(state, &predecessor)?;
                        verify_origin_for(origin, state)?;
                        if state.rollback_floor != predecessor
                            || !matches!(
                                predecessor.state(),
                                PayoutStateV1::Succeeded | PayoutStateV1::Failed
                            )
                        {
                            return Err(ProviderSettlementClientErrorV1::Rollback);
                        }
                    }
                }
            }
            ProviderSettlementRecoveryTransitionKindV2::InitialPayout => {
                let pending = workflow.active_pending_payout.as_ref().ok_or(
                    ServiceProtocolError::InvalidValue {
                        field: "UnverifiedProviderSettlementRecoveryV2.active_pending_payout",
                        reason: "initial-payout recovery is missing its exact request",
                    },
                )?;
                let origin = workflow
                    .committed_payout_origin
                    .as_ref()
                    .ok_or(ProviderSettlementClientErrorV1::Rollback)?;
                let state = workflow
                    .payout_state
                    .as_ref()
                    .ok_or(ProviderSettlementClientErrorV1::Rollback)?;
                self.decode_and_verify_pending_payout(pending)?;
                self.restore_payout(state, &state.rollback_floor)?;
                verify_origin_for(origin, state)?;
                if origin != pending
                    || unverified.transition_previous_state.is_some()
                    || state.rollback_floor.state() != PayoutStateV1::Accepted
                    || state.rollback_floor.state_version() != 1
                {
                    return Err(ProviderSettlementClientErrorV1::Rollback);
                }
            }
            ProviderSettlementRecoveryTransitionKindV2::StatusPending => {
                let state = workflow
                    .payout_state
                    .as_ref()
                    .ok_or(ProviderSettlementClientErrorV1::Rollback)?;
                let origin = workflow
                    .committed_payout_origin
                    .as_ref()
                    .ok_or(ProviderSettlementClientErrorV1::Rollback)?;
                let pending = workflow
                    .pending_status
                    .as_ref()
                    .ok_or(ProviderSettlementClientErrorV1::Rollback)?;
                let verified_state = self.restore_payout(state, &pending.previous_floor)?;
                verify_origin_for(origin, state)?;
                self.decode_and_verify_pending_status(
                    &verified_state,
                    pending,
                    pending.registration.not_before,
                )?;
                if workflow.active_pending_payout.is_some()
                    || unverified.transition_previous_state.is_some()
                {
                    return Err(ProviderSettlementClientErrorV1::Rollback);
                }
            }
            ProviderSettlementRecoveryTransitionKindV2::StatusCommit => {
                let previous = unverified
                    .transition_previous_state
                    .as_ref()
                    .ok_or(ProviderSettlementClientErrorV1::Rollback)?;
                let successor = workflow
                    .payout_state
                    .as_ref()
                    .ok_or(ProviderSettlementClientErrorV1::Rollback)?;
                let origin = workflow
                    .committed_payout_origin
                    .as_ref()
                    .ok_or(ProviderSettlementClientErrorV1::Rollback)?;
                let pending = workflow
                    .pending_status
                    .as_ref()
                    .ok_or(ProviderSettlementClientErrorV1::Rollback)?;
                let verified_previous = self.restore_payout(previous, &pending.previous_floor)?;
                self.restore_payout(successor, &pending.previous_floor)?;
                verify_origin_for(origin, successor)?;
                let envelope = self.decode_and_verify_pending_status(
                    &verified_previous,
                    pending,
                    pending.registration.not_before,
                )?;
                let response_bytes = successor.latest_status_response.as_ref().ok_or(
                    ServiceProtocolError::InvalidValue {
                        field: "ProviderPayoutDurableStateV1.latest_status_response",
                        reason: "status-commit recovery is missing its exact signed response",
                    },
                )?;
                let response = decode_canonical_response(
                    response_bytes,
                    IssuerPayoutStatusResponseV1::decode,
                    IssuerPayoutStatusResponseV1::encode,
                )?;
                let exact_snapshot = self.verify_historical_status_response(
                    &verified_previous,
                    pending,
                    &envelope,
                    &response,
                )?;
                if workflow.active_pending_payout.is_some()
                    || !floor_is_satisfied(&pending.previous_floor, &successor.rollback_floor)
                    || ProviderPayoutRollbackFloorV1::from_snapshot(&exact_snapshot)
                        != successor.rollback_floor
                {
                    return Err(ProviderSettlementClientErrorV1::Rollback);
                }
            }
        }

        Ok(VerifiedProviderSettlementRecoveryV2 {
            snapshot_digest: unverified.snapshot_digest,
            transition_kind: unverified.transition_kind,
            expected_floor: unverified.expected_floor,
            desired_floor: unverified.desired_floor,
        })
    }

    /// Restores a payout only from a rollback-protected provider store. The
    /// `minimum_floor` must come from an independent monotonic store;
    /// passing the floor embedded in `durable` provides no backup-rollback
    /// protection by itself.
    pub fn restore_payout(
        &self,
        durable: &ProviderPayoutDurableStateV1,
        minimum_floor: &ProviderPayoutRollbackFloorV1,
    ) -> Result<VerifiedProviderPayoutStateV1, ProviderSettlementClientErrorV1> {
        let intent_request = decode_canonical_response(
            &durable.intent_request,
            ProviderPayoutIntentRequestV1::decode,
            ProviderPayoutIntentRequestV1::encode,
        )?;
        let intent_response = decode_canonical_response(
            &durable.intent_response,
            IssuerPayoutIntentResponseV1::decode,
            IssuerPayoutIntentResponseV1::encode,
        )?;
        let payout_request = decode_canonical_response(
            &durable.payout_request,
            ProviderPayoutRequestV1::decode,
            ProviderPayoutRequestV1::encode,
        )?;
        let trusted_registration = core::iter::once(&self.trust.registration)
            .chain(self.trust.retained_registrations.iter())
            .find(|registration| {
                intent_request.issuer_id == registration.issuer_id
                    && intent_request.provider_id == registration.provider_id
                    && intent_request.account_id == registration.settlement_account_id
                    && intent_request.payout_target_id == registration.payout_target_id
                    && payout_request.issuer_id == registration.issuer_id
                    && payout_request.provider_id == registration.provider_id
                    && payout_request.account_id == registration.settlement_account_id
                    && payout_request.payout_target_id == registration.payout_target_id
            })
            .ok_or(ServiceProtocolError::InvalidValue {
                field: "ProviderPayoutDurableStateV1.registration",
                reason:
                    "persisted payout is not in the trusted current/retained registration lineage",
            })?;
        self.verify_intent_response_for_registration(
            &intent_request,
            &intent_response,
            trusted_registration,
        )?;
        let intent = VerifiedProviderPayoutIntentV1 {
            request: intent_request,
            response: intent_response,
        };
        if payout_request
            != self.payout_request_for_registration(
                &intent,
                payout_request.idempotency_key,
                trusted_registration,
            )?
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderPayoutDurableStateV1.payout_request",
                reason: "payout request is not derived from the verified intent",
            }
            .into());
        }
        let initial_response = decode_canonical_response(
            &durable.initial_payout_response,
            IssuerPayoutResponseV1::decode,
            IssuerPayoutResponseV1::encode,
        )?;
        let latest_status_response = durable
            .latest_status_response
            .as_ref()
            .map(|bytes| {
                decode_canonical_response(
                    bytes,
                    IssuerPayoutStatusResponseV1::decode,
                    IssuerPayoutStatusResponseV1::encode,
                )
            })
            .transpose()?;
        let snapshot = verify_persisted_payout_snapshot_for_store_v1(
            &payout_request,
            &initial_response,
            latest_status_response.as_ref(),
            &self.issuer_keyring(),
        )?;
        let actual_floor = ProviderPayoutRollbackFloorV1::from_snapshot(&snapshot);
        if actual_floor != durable.rollback_floor
            || !floor_is_satisfied(minimum_floor, &actual_floor)
        {
            return Err(ProviderSettlementClientErrorV1::Rollback);
        }
        if let Some(status) = &latest_status_response {
            if status.registration_digest != self.trust.registration.registration_digest
                && !self
                    .trust
                    .retained_registrations
                    .iter()
                    .any(|registration| {
                        registration.registration_digest == status.registration_digest
                    })
            {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "ProviderPayoutDurableStateV1.latest_status_response",
                    reason: "latest status belongs to another provider registration",
                }
                .into());
            }
        }
        Ok(VerifiedProviderPayoutStateV1 {
            intent,
            payout_request,
            initial_response,
            latest_status_response,
            snapshot,
        })
    }

    fn authorization_digest(&self) -> Result<[u8; 32], ProviderSettlementClientErrorV1> {
        Ok(self.trust.authorization.authorization_digest()?)
    }

    fn clearing_auth(&self, request_digest: [u8; 32]) -> ProviderClearingRequestAuthV1 {
        ProviderClearingRequestAuthV1::sign(
            self.trust
                .authorization
                .authorization_digest()
                .expect("constructor validated canonical authorization"),
            request_digest,
            &self.clearing_signing_key,
        )
    }

    fn issuer_keyring(&self) -> IssuerSettlementKeyringExpectationV1<'_> {
        IssuerSettlementKeyringExpectationV1 {
            issuer_id: &self.trust.registration.issuer_id,
            current_key: &self.trust.current_issuer_settlement_key,
            retained_keys: &self.trust.retained_issuer_settlement_keys,
        }
    }

    /// Verifies a persisted initial payout without granting fresh authority.
    /// Callers must have matched an independent pending floor before reaching
    /// this historical verifier. Expiry is deliberately not re-evaluated: the
    /// exact authenticated request may already have committed at the issuer.
    fn decode_and_verify_pending_payout(
        &self,
        pending: &ProviderPayoutPendingV1,
    ) -> Result<ProviderPayoutEnvelopeV1, ProviderSettlementClientErrorV1> {
        let expected_floor = pending_payout_floor_v1(
            &pending.canonical_envelope,
            &pending.payout_request_digest,
            &pending.idempotency_key,
            &pending.intent_request,
            &pending.intent_response,
            &pending.registration,
            pending.predecessor_floor.as_ref(),
        )?;
        if expected_floor != pending.pending_floor {
            return Err(ProviderSettlementClientErrorV1::Rollback);
        }

        let trusted_registration = if pending.registration == self.trust.registration {
            Some(&self.trust.registration)
        } else {
            self.trust
                .retained_registrations
                .iter()
                .find(|registration| **registration == pending.registration)
        }
        .ok_or(ServiceProtocolError::InvalidValue {
            field: "ProviderPayoutPendingV1.registration",
            reason: "pending payout registration is not in the trusted current/retained lineage",
        })?;

        let envelope = ProviderPayoutEnvelopeV1::decode(&pending.canonical_envelope)?;
        let stored_intent_request = decode_canonical_response(
            &pending.intent_request,
            ProviderPayoutIntentRequestV1::decode,
            ProviderPayoutIntentRequestV1::encode,
        )?;
        let stored_intent_response = decode_canonical_response(
            &pending.intent_response,
            IssuerPayoutIntentResponseV1::decode,
            IssuerPayoutIntentResponseV1::encode,
        )?;
        let canonical_envelope = Zeroizing::new(envelope.encode()?);
        if canonical_envelope.as_slice() != pending.canonical_envelope
            || envelope.intent_request != stored_intent_request
            || envelope.intent_response != stored_intent_response
            || envelope.request.request_digest()? != pending.payout_request_digest
            || envelope.request.idempotency_key != pending.idempotency_key
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderPayoutPendingV1.binding",
                reason: "pending bytes, digest, idempotency key, or exact intent binding mismatch",
            }
            .into());
        }

        self.verify_intent_response_for_registration(
            &envelope.intent_request,
            &envelope.intent_response,
            trusted_registration,
        )?;
        let intent = VerifiedProviderPayoutIntentV1 {
            request: envelope.intent_request.clone(),
            response: envelope.intent_response.clone(),
        };
        if envelope.request
            != self.payout_request_for_registration(
                &intent,
                pending.idempotency_key,
                trusted_registration,
            )?
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderPayoutPendingV1.payout_request",
                reason:
                    "payout request is not derived from the exact verified intent and registration",
            }
            .into());
        }

        let approval_key =
            self.response_key(&self.trust.issuer_approval.issuer_settlement_key_id)?;
        verify_committed_clearing_request_auth_v1(
            &envelope.request.authorization_digest,
            &pending.payout_request_digest,
            &self.trust.authorization,
            &self.trust.issuer_approval,
            &envelope.request_auth,
            &CommittedRedeemReplayExpectationV1 {
                provider_id: &trusted_registration.provider_id,
                issuer_id: &trusted_registration.issuer_id,
                operator_key: &self.trust.operator_verifying_key,
                issuer_settlement_key: &approval_key,
            },
        )?;
        Ok(envelope)
    }

    fn decode_and_verify_pending_status(
        &self,
        payout: &VerifiedProviderPayoutStateV1,
        pending: &ProviderPayoutStatusPendingV1,
        verification_time: u64,
    ) -> Result<ProviderPayoutStatusEnvelopeV1, ProviderSettlementClientErrorV1> {
        if pending.previous_floor != payout.rollback_floor()
            || provider_payout_durable_state_commitment_v1(&payout.durable_state()?)?
                != pending.previous_state_commitment
        {
            return Err(ProviderSettlementClientErrorV1::Rollback);
        }
        let trusted_registration = if pending.registration == self.trust.registration {
            Some(&self.trust.registration)
        } else {
            self.trust
                .retained_registrations
                .iter()
                .find(|registration| **registration == pending.registration)
        }
        .ok_or(ServiceProtocolError::InvalidValue {
            field: "ProviderPayoutStatusPendingV1.registration",
            reason: "pending status registration is not in the trusted current/retained lineage",
        })?;
        let envelope = ProviderPayoutStatusEnvelopeV1::decode(&pending.canonical_envelope)?;
        let canonical_envelope = Zeroizing::new(envelope.encode()?);
        if canonical_envelope.as_slice() != pending.canonical_envelope
            || envelope.request.request_digest()? != pending.request_digest
            || envelope.payout_request != payout.payout_request
            || envelope.initial_payout_response != payout.initial_response
            || envelope.request.registration_digest != trusted_registration.registration_digest
            || envelope.request.issuer_id != trusted_registration.issuer_id
            || envelope.request.provider_id != trusted_registration.provider_id
            || envelope.request.account_id != trusted_registration.settlement_account_id
            || envelope.request.payout_id != *pending.previous_floor.payout_id()
            || envelope.request.payout_request_digest
                != *pending.previous_floor.payout_request_digest()
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderPayoutStatusPendingV1.binding",
                reason: "pending status bytes, digest, payout, or registration binding mismatch",
            }
            .into());
        }
        let provider_request_key =
            VerifyingKey::from_bytes(&trusted_registration.provider_request_verifying_key)
                .map_err(|_| ServiceProtocolError::BadPublicKey)?;
        let registration = ProviderSettlementRegistrationExpectationV1 {
            registration_digest: &trusted_registration.registration_digest,
            provider_id: &trusted_registration.provider_id,
            issuer_id: &trusted_registration.issuer_id,
            settlement_account_id: &trusted_registration.settlement_account_id,
            provider_request_key: &provider_request_key,
            issuer_settlement_key: &self.trust.current_issuer_settlement_key,
            not_before: trusted_registration.not_before,
            not_after: trusted_registration.not_after,
            now_unix: verification_time,
        };
        let keyring = self.issuer_keyring();
        let context = PayoutStatusContextV1 {
            payout_request: &payout.payout_request,
            initial_payout_response: &payout.initial_response,
        };
        verify_new_payout_status_request_for(
            &envelope.request,
            &context,
            &envelope.request_auth,
            &registration,
            &keyring,
        )?;
        Ok(envelope)
    }

    fn verify_historical_status_response(
        &self,
        payout: &VerifiedProviderPayoutStateV1,
        pending: &ProviderPayoutStatusPendingV1,
        envelope: &ProviderPayoutStatusEnvelopeV1,
        response: &IssuerPayoutStatusResponseV1,
    ) -> Result<VerifiedPayoutSnapshotV1, ProviderSettlementClientErrorV1> {
        let provider_request_key =
            VerifyingKey::from_bytes(&pending.registration.provider_request_verifying_key)
                .map_err(|_| ServiceProtocolError::BadPublicKey)?;
        let registration = ProviderSettlementRegistrationExpectationV1 {
            registration_digest: &pending.registration.registration_digest,
            provider_id: &pending.registration.provider_id,
            issuer_id: &pending.registration.issuer_id,
            settlement_account_id: &pending.registration.settlement_account_id,
            provider_request_key: &provider_request_key,
            issuer_settlement_key: &self.trust.current_issuer_settlement_key,
            not_before: pending.registration.not_before,
            not_after: pending.registration.not_after,
            now_unix: pending.registration.not_before,
        };
        let keyring = self.issuer_keyring();
        let context = PayoutStatusContextV1 {
            payout_request: &payout.payout_request,
            initial_payout_response: &payout.initial_response,
        };
        Ok(verify_new_payout_status_response_for(
            response,
            &envelope.request,
            &context,
            &payout.snapshot,
            &envelope.request_auth,
            &registration,
            &keyring,
        )?)
    }

    fn response_key(
        &self,
        key_id: &[u8; 16],
    ) -> Result<VerifyingKey, ProviderSettlementClientErrorV1> {
        Ok(self
            .issuer_keyring()
            .resolve_for_issuer(&self.trust.registration.issuer_id, key_id)?
            .to_owned())
    }

    fn verify_intent_response(
        &self,
        request: &ProviderPayoutIntentRequestV1,
        response: &IssuerPayoutIntentResponseV1,
    ) -> Result<(), ProviderSettlementClientErrorV1> {
        self.verify_intent_response_for_registration(request, response, &self.trust.registration)
    }

    fn verify_intent_response_for_registration(
        &self,
        request: &ProviderPayoutIntentRequestV1,
        response: &IssuerPayoutIntentResponseV1,
        registration: &ProviderSettlementRegistrationV1,
    ) -> Result<(), ProviderSettlementClientErrorV1> {
        if request.authorization_digest != self.authorization_digest()?
            || request.issuer_id != registration.issuer_id
            || request.provider_id != registration.provider_id
            || request.account_id != registration.settlement_account_id
            || request.payout_target_id != registration.payout_target_id
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "VerifiedProviderPayoutIntentV1.request",
                reason: "intent request does not match configured provider settlement audience",
            }
            .into());
        }
        response.verify_for_exact_request(
            request,
            &self.response_key(&response.issuer_settlement_key_id)?,
        )?;
        Ok(())
    }

    fn payout_request(
        &self,
        intent: &VerifiedProviderPayoutIntentV1,
        idempotency_key: [u8; 32],
    ) -> Result<ProviderPayoutRequestV1, ProviderSettlementClientErrorV1> {
        self.payout_request_for_registration(intent, idempotency_key, &self.trust.registration)
    }

    fn payout_request_for_registration(
        &self,
        intent: &VerifiedProviderPayoutIntentV1,
        idempotency_key: [u8; 32],
        registration: &ProviderSettlementRegistrationV1,
    ) -> Result<ProviderPayoutRequestV1, ProviderSettlementClientErrorV1> {
        Ok(ProviderPayoutRequestV1 {
            authorization_digest: self.authorization_digest()?,
            issuer_id: registration.issuer_id,
            provider_id: registration.provider_id,
            account_id: registration.settlement_account_id,
            payout_target_id: registration.payout_target_id,
            payout_intent_id: intent.response.payout_intent_id,
            payout_intent_digest: intent.response.payout_intent_digest()?,
            unit: intent.response.unit,
            payout_value: intent.response.payout_value,
            total_debit: intent.response.total_debit,
            idempotency_key,
        })
    }

    fn post(
        &self,
        endpoint: &'static str,
        canonical_body: &[u8],
    ) -> Result<Vec<u8>, ProviderSettlementClientErrorV1> {
        let response = self.transport.post(
            ProviderSettlementHttpRequestV1 {
                endpoint,
                canonical_body,
            },
            MAX_PROVIDER_SETTLEMENT_RESPONSE_BYTES_V1,
        )?;
        if response.len() > MAX_PROVIDER_SETTLEMENT_RESPONSE_BYTES_V1 {
            return Err(ProviderSettlementClientErrorV1::ResponseTooLarge {
                len: response.len(),
                max: MAX_PROVIDER_SETTLEMENT_RESPONSE_BYTES_V1,
            });
        }
        Ok(response)
    }
}

/// Domain-separated commitment to every exact byte of one durable provider
/// payout state plus its rollback coordinates. This is content-only; a store
/// authority additionally binds it to its random instance ID and revision.
pub fn provider_payout_durable_state_commitment_v1(
    state: &ProviderPayoutDurableStateV1,
) -> Result<[u8; 32], ServiceProtocolError> {
    fn hash_len_prefixed(
        hasher: &mut Sha256,
        bytes: &[u8],
        field: &'static str,
    ) -> Result<(), ServiceProtocolError> {
        let len = u64::try_from(bytes.len()).map_err(|_| ServiceProtocolError::InvalidValue {
            field,
            reason: "durable payout canonical field length does not fit u64",
        })?;
        hasher.update(len.to_le_bytes());
        hasher.update(bytes);
        Ok(())
    }

    let mut hasher = Sha256::new();
    hasher.update(DURABLE_PAYOUT_STATE_COMMITMENT_DOMAIN_V1);
    hash_len_prefixed(
        &mut hasher,
        &state.intent_request,
        "ProviderPayoutDurableStateV1.intent_request",
    )?;
    hash_len_prefixed(
        &mut hasher,
        &state.intent_response,
        "ProviderPayoutDurableStateV1.intent_response",
    )?;
    hash_len_prefixed(
        &mut hasher,
        &state.payout_request,
        "ProviderPayoutDurableStateV1.payout_request",
    )?;
    hash_len_prefixed(
        &mut hasher,
        &state.initial_payout_response,
        "ProviderPayoutDurableStateV1.initial_payout_response",
    )?;
    match state.latest_status_response.as_ref() {
        None => hasher.update([0]),
        Some(status) => {
            hasher.update([1]);
            hash_len_prefixed(
                &mut hasher,
                status,
                "ProviderPayoutDurableStateV1.latest_status_response",
            )?;
        }
    }
    hasher.update(state.rollback_floor.payout_id);
    hasher.update(state.rollback_floor.payout_request_digest);
    hasher.update(state.rollback_floor.ledger_transaction_id);
    hasher.update([state.rollback_floor.state as u8]);
    hasher.update(state.rollback_floor.state_version.to_le_bytes());
    hasher.update(state.rollback_floor.updated_at.to_le_bytes());
    Ok(hasher.finalize().into())
}

fn pending_payout_floor_v1(
    canonical_envelope: &[u8],
    payout_request_digest: &[u8; 32],
    idempotency_key: &[u8; 32],
    intent_request: &[u8],
    intent_response: &[u8],
    registration: &ProviderSettlementRegistrationV1,
    predecessor_floor: Option<&ProviderPayoutRollbackFloorV1>,
) -> Result<ProviderPayoutPendingFloorV1, ServiceProtocolError> {
    fn hash_len_prefixed(
        hasher: &mut Sha256,
        bytes: &[u8],
        field: &'static str,
    ) -> Result<(), ServiceProtocolError> {
        let len = u64::try_from(bytes.len()).map_err(|_| ServiceProtocolError::InvalidValue {
            field,
            reason: "pending payout canonical field length does not fit u64",
        })?;
        hasher.update(len.to_le_bytes());
        hasher.update(bytes);
        Ok(())
    }

    let mut hasher = Sha256::new();
    hasher.update(PENDING_PAYOUT_FLOOR_DOMAIN_V1);
    hasher.update(registration.registration_digest);
    hasher.update(registration.provider_id);
    hasher.update(registration.issuer_id);
    hasher.update(registration.settlement_account_id);
    hasher.update(registration.provider_request_verifying_key);
    hasher.update(registration.payout_target_id);
    hasher.update(registration.not_before.to_le_bytes());
    hasher.update(registration.not_after.to_le_bytes());
    match predecessor_floor {
        None => hasher.update([0]),
        Some(floor) => {
            hasher.update([1]);
            hasher.update(floor.payout_id);
            hasher.update(floor.payout_request_digest);
            hasher.update(floor.ledger_transaction_id);
            hasher.update([floor.state as u8]);
            hasher.update(floor.state_version.to_le_bytes());
            hasher.update(floor.updated_at.to_le_bytes());
        }
    }
    hasher.update(payout_request_digest);
    hasher.update(idempotency_key);
    hash_len_prefixed(
        &mut hasher,
        canonical_envelope,
        "ProviderPayoutPendingV1.canonical_envelope",
    )?;
    hash_len_prefixed(
        &mut hasher,
        intent_request,
        "ProviderPayoutPendingV1.intent_request",
    )?;
    hash_len_prefixed(
        &mut hasher,
        intent_response,
        "ProviderPayoutPendingV1.intent_response",
    )?;
    ProviderPayoutPendingFloorV1::from_digest(hasher.finalize().into())
}

fn decode_canonical_response<T>(
    bytes: &[u8],
    decode: impl FnOnce(&[u8]) -> Result<T, ServiceProtocolError>,
    encode: impl FnOnce(&T) -> Result<Vec<u8>, ServiceProtocolError>,
) -> Result<T, ProviderSettlementClientErrorV1> {
    if bytes.len() > MAX_PROVIDER_SETTLEMENT_RESPONSE_BYTES_V1 {
        return Err(ProviderSettlementClientErrorV1::ResponseTooLarge {
            len: bytes.len(),
            max: MAX_PROVIDER_SETTLEMENT_RESPONSE_BYTES_V1,
        });
    }
    let value = decode(bytes)?;
    if encode(&value)?.as_slice() != bytes {
        return Err(ServiceProtocolError::InvalidValue {
            field: "ProviderSettlementClientV1.response",
            reason: "issuer response is not canonical",
        }
        .into());
    }
    Ok(value)
}

fn floor_is_satisfied(
    minimum: &ProviderPayoutRollbackFloorV1,
    actual: &ProviderPayoutRollbackFloorV1,
) -> bool {
    if minimum.payout_id != actual.payout_id
        || minimum.payout_request_digest != actual.payout_request_digest
        || minimum.ledger_transaction_id != actual.ledger_transaction_id
        || actual.state_version < minimum.state_version
        || actual.updated_at < minimum.updated_at
    {
        return false;
    }
    if actual.state_version == minimum.state_version {
        return actual == minimum;
    }
    match minimum.state {
        PayoutStateV1::Accepted => true,
        PayoutStateV1::InFlight => matches!(
            actual.state,
            PayoutStateV1::InFlight | PayoutStateV1::Succeeded | PayoutStateV1::Failed
        ),
        PayoutStateV1::Succeeded => actual.state == PayoutStateV1::Succeeded,
        PayoutStateV1::Failed => actual.state == PayoutStateV1::Failed,
    }
}

/// Typed transport input. The endpoint and pins come only from the verified,
/// operator-authorized and issuer-approved clearing claims. Concrete HTTP
/// adapters encode these exact canonical objects, require WebPKI plus a pin,
/// and disable redirects and request/response body logging.
pub struct SharedIssuerRedeemEnvelopeV1<'a> {
    pub redeem_endpoint: &'a str,
    pub redeem_leaf_spki_sha256_pins: &'a [[u8; 32]],
    pub request: &'a ProviderRedeemRequestV1,
    pub request_auth: &'a ProviderClearingRequestAuthV1,
    pub credential_binding: &'a pir_service_protocol::CredentialKeyBindingV1,
    pub canonical_credential: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharedIssuerTransportErrorV1 {
    /// No request bytes could have reached the issuer. A later user-initiated
    /// retry is safe and uses the same deterministic idempotency key.
    NotSent { retry_after_ms: u32 },
    /// Issuer authoritatively rejected the credential as invalid or spent.
    InvalidOrSpent,
    /// Issuer no longer serves the configured authorization/rule.
    ScopeUnavailable,
    /// Bytes may have reached an issuer that may have committed the redeem.
    OutcomeUnknown,
    /// A response arrived but was too large or not the canonical signed V1
    /// success form. The issuer may already have committed.
    InvalidResponse,
}

pub trait SharedIssuerRedeemTransportV1: Send + Sync {
    fn redeem(
        &self,
        envelope: SharedIssuerRedeemEnvelopeV1<'_>,
        max_response_bytes: usize,
    ) -> Result<Vec<u8>, SharedIssuerTransportErrorV1>;
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ProviderRedeemIdempotencyKeyV1(SharedIssuerProviderSecretV1);

impl fmt::Debug for ProviderRedeemIdempotencyKeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ProviderRedeemIdempotencyKeyV1")
            .field(&"[REDACTED]")
            .finish()
    }
}

impl ProviderRedeemIdempotencyKeyV1 {
    pub fn from_bytes(key: [u8; 32]) -> Result<Self, ServiceProtocolError> {
        SharedIssuerProviderSecretV1::from_bytes(key).map(Self)
    }

    fn derive(
        &self,
        authorization_digest: &[u8; 32],
        binding_digest: &[u8; 32],
        credential_digest: &[u8; 32],
    ) -> [u8; 32] {
        self.0
            .derive_wire_idempotency_v1(authorization_digest, binding_digest, credential_digest)
    }
}

/// Immutable, operator/issuer-approved clearing configuration for one
/// provider. The transport may be shared by many providers, but every runtime
/// has its own authorization, clearing signing key, and idempotency secret.
pub struct SharedIssuerAdmissionCommitterV1<'a> {
    authorization: ProviderClearingAuthorizationV1,
    issuer_approval: IssuerClearingApprovalV1,
    operator_verifying_key: VerifyingKey,
    issuer_settlement_verifying_key: VerifyingKey,
    clearing_signing_key: SigningKey,
    minimum_authorization_epoch: u64,
    idempotency_key: ProviderRedeemIdempotencyKeyV1,
    provider_store: ProviderStore,
    transport: &'a dyn SharedIssuerRedeemTransportV1,
}

impl fmt::Debug for SharedIssuerAdmissionCommitterV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedIssuerAdmissionCommitterV1")
            .field("provider_id", &self.authorization.claims.provider_id)
            .field("issuer_id", &self.authorization.claims.issuer_id)
            .field(
                "authorization_epoch",
                &self.authorization.claims.authorization_epoch,
            )
            .field(
                "minimum_authorization_epoch",
                &self.minimum_authorization_epoch,
            )
            .finish_non_exhaustive()
    }
}

impl<'a> SharedIssuerAdmissionCommitterV1<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authorization: ProviderClearingAuthorizationV1,
        issuer_approval: IssuerClearingApprovalV1,
        operator_verifying_key: VerifyingKey,
        issuer_settlement_verifying_key: VerifyingKey,
        clearing_signing_key: SigningKey,
        minimum_authorization_epoch: u64,
        idempotency_key: ProviderRedeemIdempotencyKeyV1,
        provider_store: ProviderStore,
        transport: &'a dyn SharedIssuerRedeemTransportV1,
    ) -> Result<Self, ServiceProtocolError> {
        if authorization.claims.authorization_epoch < minimum_authorization_epoch
            || authorization.claims.clearing_verifying_key
                != clearing_signing_key.verifying_key().to_bytes()
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "SharedIssuerAdmissionCommitterV1.authorization",
                reason: "authorization epoch or provider clearing key mismatch",
            });
        }
        let store_identity =
            provider_store
                .identity()
                .map_err(|_| ServiceProtocolError::InvalidValue {
                    field: "SharedIssuerAdmissionCommitterV1.provider_store",
                    reason: "provider store is unavailable",
                })?;
        if store_identity.provider_id != authorization.claims.provider_id {
            return Err(ServiceProtocolError::InvalidValue {
                field: "SharedIssuerAdmissionCommitterV1.provider_store",
                reason: "provider store belongs to another provider",
            });
        }
        Ok(Self {
            authorization,
            issuer_approval,
            operator_verifying_key,
            issuer_settlement_verifying_key,
            clearing_signing_key,
            minimum_authorization_epoch,
            idempotency_key,
            provider_store,
            transport,
        })
    }

    fn verify_and_redeem(
        &self,
        attempt: &BoundAuthAttemptV1<'_>,
        now_unix: u64,
    ) -> Result<(), AdmissionCommitErrorV1> {
        let offer = attempt.offer();
        let binding = offer
            .credential_binding
            .as_ref()
            .ok_or(AdmissionCommitErrorV1::ScopeUnavailable)?;
        let expectation = ProviderClearingExpectationV1 {
            provider_id: &attempt.scope().provider_id,
            issuer_id: &offer.issuer_id,
            operator_key: &self.operator_verifying_key,
            issuer_settlement_key: &self.issuer_settlement_verifying_key,
            now_unix,
            minimum_authorization_epoch: self.minimum_authorization_epoch,
        };
        self.authorization
            .verify_for(
                expectation.provider_id,
                expectation.issuer_id,
                expectation.operator_key,
                expectation.now_unix,
                expectation.minimum_authorization_epoch,
            )
            .map_err(|_| AdmissionCommitErrorV1::ScopeUnavailable)?;
        self.issuer_approval
            .verify_for(
                &self.authorization,
                expectation.issuer_settlement_key,
                expectation.now_unix,
                expectation.minimum_authorization_epoch,
            )
            .map_err(|_| AdmissionCommitErrorV1::ScopeUnavailable)?;
        if offer.verification != VerificationMode::SharedIssuerOnline
            || offer.issuer_id != self.authorization.claims.issuer_id
            || attempt.scope().provider_id != self.authorization.claims.provider_id
            || offer.endpoint != self.authorization.claims.redeem_endpoint
        {
            return Err(AdmissionCommitErrorV1::ScopeUnavailable);
        }

        let canonical_credential = Zeroizing::new(
            canonical_shared_credential_v1(attempt)
                .map_err(|_| AdmissionCommitErrorV1::InvalidOrSpent)?,
        );
        let binding_digest = binding
            .binding_digest()
            .map_err(|_| AdmissionCommitErrorV1::ScopeUnavailable)?;
        let authorization_digest = self
            .authorization
            .authorization_digest()
            .map_err(|_| AdmissionCommitErrorV1::ScopeUnavailable)?;
        let rule = self
            .authorization
            .rule_for_binding(&binding_digest)
            .ok_or(AdmissionCommitErrorV1::ScopeUnavailable)?;
        let credential_digest =
            credential_presentation_digest(offer.authorization, &canonical_credential)
                .map_err(|_| AdmissionCommitErrorV1::InvalidOrSpent)?;
        let request = ProviderRedeemRequestV1 {
            authorization_digest,
            issuer_id: offer.issuer_id,
            provider_id: attempt.scope().provider_id,
            scope_id: attempt.scope().scope_id(),
            offer_id: offer.offer_id,
            credential_binding_digest: binding_digest,
            scheme: offer.authorization,
            credential_digest,
            accepted_value: rule.accepted_value,
            denomination_profile: rule.denomination_profile,
            idempotency_key: self.idempotency_key.derive(
                &authorization_digest,
                &binding_digest,
                &credential_digest,
            ),
            destination: SettlementDestinationV1::LedgerCredit {
                account_id: self.authorization.claims.settlement_account_id,
            },
        };
        let request_digest = request
            .request_digest()
            .map_err(|_| AdmissionCommitErrorV1::ScopeUnavailable)?;
        let request_auth = ProviderClearingRequestAuthV1::sign(
            authorization_digest,
            request_digest,
            &self.clearing_signing_key,
        );

        let response_bytes = Zeroizing::new(
            self.transport
                .redeem(
                    SharedIssuerRedeemEnvelopeV1 {
                        redeem_endpoint: &self.authorization.claims.redeem_endpoint,
                        redeem_leaf_spki_sha256_pins: &self
                            .authorization
                            .claims
                            .redeem_leaf_spki_sha256_pins,
                        request: &request,
                        request_auth: &request_auth,
                        credential_binding: binding,
                        canonical_credential: &canonical_credential,
                    },
                    MAX_SHARED_ISSUER_RESPONSE_BYTES_V1,
                )
                .map_err(map_transport_error)?,
        );
        if response_bytes.len() > MAX_SHARED_ISSUER_RESPONSE_BYTES_V1 {
            return Err(AdmissionCommitErrorV1::InternalAfterSpend);
        }
        let local_claim = verify_shared_issuer_local_grant_claim_v1(
            &response_bytes,
            &request,
            &self.authorization,
            &self.issuer_settlement_verifying_key,
            attempt.verified_offer(),
            &self.idempotency_key.0,
            now_unix,
        )
        .map_err(|_| AdmissionCommitErrorV1::InternalAfterSpend)?;
        self.provider_store
            .claim_verified_shared_issuer_local_grant_v1(local_claim)
            .map_err(map_post_issuer_local_claim_error)?;
        Ok(())
    }
}

impl AdmissionMethodCommitterV1 for SharedIssuerAdmissionCommitterV1<'_> {
    fn verify_and_commit_v1(
        &self,
        route: AdmissionMethodRouteV1,
        attempt: &BoundAuthAttemptV1<'_>,
        now_unix_seconds: u64,
    ) -> Result<(), AdmissionCommitErrorV1> {
        let expected = match route {
            AdmissionMethodRouteV1::FreeAnonymousTicketSharedIssuerOnline => AuthScheme::FreeV1,
            AdmissionMethodRouteV1::BitcoinPirCashuBatSharedIssuerOnline => {
                AuthScheme::BitcoinPirCashuBatV1
            }
            AdmissionMethodRouteV1::ArcSharedIssuerOnlineExperimental => {
                AuthScheme::ArcV1Experimental
            }
            _ => return Err(AdmissionCommitErrorV1::UnsupportedScheme),
        };
        if attempt.offer().authorization != expected {
            return Err(AdmissionCommitErrorV1::InvalidOrSpent);
        }
        self.verify_and_redeem(attempt, now_unix_seconds)
    }
}

fn canonical_shared_credential_v1(
    attempt: &BoundAuthAttemptV1<'_>,
) -> Result<Vec<u8>, ServiceProtocolError> {
    match attempt.proof() {
        AuthorizationProofV1::Free(FreeAuthorizationProofV1::AnonymousTicket(ticket)) => {
            ticket.encode()
        }
        AuthorizationProofV1::BitcoinPirCashuBat(proof) => Ok(proof.encode_zeroizing()?.to_vec()),
        AuthorizationProofV1::ArcExperimental(presentation) => presentation.encode(),
        _ => Err(ServiceProtocolError::InvalidValue {
            field: "AuthorizationProofV1",
            reason: "proof is not a shared-issuer credential",
        }),
    }
}

fn map_transport_error(error: SharedIssuerTransportErrorV1) -> AdmissionCommitErrorV1 {
    match error {
        SharedIssuerTransportErrorV1::NotSent { retry_after_ms } => {
            AdmissionCommitErrorV1::ServerBusy { retry_after_ms }
        }
        SharedIssuerTransportErrorV1::InvalidOrSpent => AdmissionCommitErrorV1::InvalidOrSpent,
        SharedIssuerTransportErrorV1::ScopeUnavailable => AdmissionCommitErrorV1::ScopeUnavailable,
        SharedIssuerTransportErrorV1::OutcomeUnknown
        | SharedIssuerTransportErrorV1::InvalidResponse => {
            // Intentionally not retryable: the issuer may already have spent
            // the proof. Only a caller that explicitly retained the identical
            // proof can exercise the server-side exact-replay safety path; the
            // Web flow deletes before send and does not auto-recover. Likewise,
            // losing AUTH_GRANTED after a committed local claim burns the grant.
            AdmissionCommitErrorV1::InternalAfterSpend
        }
    }
}

fn map_post_issuer_local_claim_error(error: StoreError) -> AdmissionCommitErrorV1 {
    match error {
        StoreError::AlreadySpent => AdmissionCommitErrorV1::InvalidOrSpent,
        // The issuer may already have invalidated the credential and credited
        // this provider. No other local failure is safe to expose as retryable
        // or to turn into a connection grant.
        _ => AdmissionCommitErrorV1::InternalAfterSpend,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idempotency_is_deterministic_and_provider_secret_specific() {
        let first = ProviderRedeemIdempotencyKeyV1::from_bytes([1; 32]).unwrap();
        let second = ProviderRedeemIdempotencyKeyV1::from_bytes([2; 32]).unwrap();
        let a = first.derive(&[3; 32], &[4; 32], &[5; 32]);
        assert_eq!(a, first.derive(&[3; 32], &[4; 32], &[5; 32]));
        assert_ne!(a, second.derive(&[3; 32], &[4; 32], &[5; 32]));
        assert_ne!(a, first.derive(&[3; 32], &[4; 32], &[6; 32]));
    }

    #[test]
    fn transport_failures_have_conservative_spend_semantics() {
        assert_eq!(
            map_transport_error(SharedIssuerTransportErrorV1::NotSent {
                retry_after_ms: 750,
            }),
            AdmissionCommitErrorV1::ServerBusy {
                retry_after_ms: 750,
            }
        );
        assert_eq!(
            map_transport_error(SharedIssuerTransportErrorV1::OutcomeUnknown),
            AdmissionCommitErrorV1::InternalAfterSpend
        );
        assert_eq!(
            map_transport_error(SharedIssuerTransportErrorV1::InvalidResponse),
            AdmissionCommitErrorV1::InternalAfterSpend
        );
    }
}

#[cfg(test)]
mod settlement_client_tests;

#[cfg(test)]
mod shared_grant_tests;
