//! Transport-neutral BOLT11 quote lifecycle orchestration.
//!
//! This crate intentionally stops at a durably settled quote. Credential
//! issuance, HTTP, production Lightning RPC, payout accounting, and PIR server
//! admission belong to separate layers.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signer as _, SigningKey};
use pir_issuer_store::{
    IssuerStore, QuoteCapacityV1, QuoteExpiry, QuoteFinalization, QuoteRecord, QuoteReservation,
    QuoteSettlement, QuoteState, StoreError, WriteDisposition,
};
use pir_lightning_backend::{
    anonymous_invoice_description_hash_v1, CreateInvoiceRequestV1, InvoiceObservationStateV1,
    LightningBackendErrorV1, LightningInvoiceBackendV1,
};
use pir_service_protocol::{
    bolt11_invoice_text_digest_v1, Bolt11QuoteIntentV1, Bolt11QuoteKeyDelegationV1,
    Bolt11QuoteStatusV1, Bolt11QuoteV1, ParsedBolt11InvoiceV1, PersistedBolt11QuoteExpectationV1,
    VerifiedBolt11QuoteIntentV1, BOLT11_QUOTE_SIGNATURE_DOMAIN,
};
use std::fmt;
use std::sync::Arc;

/// Maximum tolerated difference between the issuer clock used for a new
/// reservation and the Lightning node's signed BOLT11 timestamp.
///
/// The resulting lower/upper bounds are durably persisted by `IssuerStore`.
/// A restart therefore validates against the original window, never against a
/// later retry's wall clock.
pub const INVOICE_CREATION_CLOCK_SKEW_SECONDS_V1: u64 = 30;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuoteIdSourceErrorV1 {
    Unavailable,
    Exhausted,
}

impl fmt::Display for QuoteIdSourceErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "quote ID source unavailable",
            Self::Exhausted => "quote ID source exhausted",
        })
    }
}

impl std::error::Error for QuoteIdSourceErrorV1 {}

/// Injected source for unpredictable, non-zero quote identifiers.
pub trait QuoteIdSourceV1: fmt::Debug + Send + Sync + 'static {
    fn next_quote_id(&self) -> Result<[u8; 32], QuoteIdSourceErrorV1>;
}

/// Coarse failure classes suitable for transport mapping and structured logs.
///
/// No variant retains an invoice, payment hash, backend label, database path,
/// or backend/store error string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssuerCoreErrorV1 {
    InvalidInput,
    RetryableUnavailable,
    OutcomeUnknown,
    PermanentMismatch,
    StoreUnanchored,
    NotFound,
    InvalidState,
}

impl fmt::Display for IssuerCoreErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "invalid issuer lifecycle input",
            Self::RetryableUnavailable => "issuer dependency temporarily unavailable",
            Self::OutcomeUnknown => "durable operation outcome unknown; retry exact request",
            Self::PermanentMismatch => "issuer lifecycle evidence mismatch",
            Self::StoreUnanchored => "issuer durable state is not externally anchored",
            Self::NotFound => "issuer lifecycle record not found",
            Self::InvalidState => "issuer lifecycle state does not permit this operation",
        })
    }
}

impl std::error::Error for IssuerCoreErrorV1 {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuoteCreateDispositionV1 {
    Created,
    RecoveredReserved,
    ExactReplay,
}

/// Exact signed quote bytes for a create/recovery response.
///
/// This type deliberately has no `Debug` implementation: the encoded quote
/// contains the BOLT11 invoice. Payment hash, preimage, and backend label are
/// never fields of this result.
#[derive(Clone, Eq, PartialEq)]
pub struct QuoteCreateResultV1 {
    disposition: QuoteCreateDispositionV1,
    exact_signed_quote_response: Vec<u8>,
}

impl QuoteCreateResultV1 {
    pub const fn disposition(&self) -> QuoteCreateDispositionV1 {
        self.disposition
    }

    pub fn exact_signed_quote_response(&self) -> &[u8] {
        &self.exact_signed_quote_response
    }

    pub fn into_exact_signed_quote_response(self) -> Vec<u8> {
        self.exact_signed_quote_response
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuoteReconcileDispositionV1 {
    Unchanged,
    Transitioned,
}

/// Exact current signed quote snapshot after reconciliation.
///
/// This type deliberately has no `Debug` implementation because the bytes
/// contain the invoice. It does not carry a payment hash, preimage, or backend
/// label.
#[derive(Clone, Eq, PartialEq)]
pub struct QuoteReconcileResultV1 {
    durable_state: QuoteState,
    disposition: QuoteReconcileDispositionV1,
    exact_signed_quote_response: Vec<u8>,
}

impl QuoteReconcileResultV1 {
    pub const fn durable_state(&self) -> QuoteState {
        self.durable_state
    }

    pub const fn disposition(&self) -> QuoteReconcileDispositionV1 {
        self.disposition
    }

    pub fn exact_signed_quote_response(&self) -> &[u8] {
        &self.exact_signed_quote_response
    }

    pub fn into_exact_signed_quote_response(self) -> Vec<u8> {
        self.exact_signed_quote_response
    }
}

/// BOLT11 orchestration over one durable issuer store and one Lightning
/// backend. The backend and quote-ID source are shared so independent core
/// instances can model process restarts in tests and production adapters.
pub struct Bolt11IssuerCoreV1<B, Q> {
    store: IssuerStore,
    backend: Arc<B>,
    quote_ids: Arc<Q>,
    quote_capacity: QuoteCapacityV1,
}

impl<B, Q> fmt::Debug for Bolt11IssuerCoreV1<B, Q> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Bolt11IssuerCoreV1")
            .field("store", &"[redacted]")
            .field("backend", &"[redacted]")
            .field("quote_ids", &"[redacted]")
            .field("quote_capacity", &self.quote_capacity)
            .finish()
    }
}

impl<B, Q> Bolt11IssuerCoreV1<B, Q>
where
    B: LightningInvoiceBackendV1,
    Q: QuoteIdSourceV1,
{
    pub fn new(store: IssuerStore, backend: Arc<B>, quote_ids: Arc<Q>) -> Self {
        Self {
            store,
            backend,
            quote_ids,
            quote_capacity: QuoteCapacityV1::unbounded(),
        }
    }

    pub fn new_with_quote_capacity(
        store: IssuerStore,
        backend: Arc<B>,
        quote_ids: Arc<Q>,
        quote_capacity: QuoteCapacityV1,
    ) -> Result<Self, IssuerCoreErrorV1> {
        if quote_capacity.max_outstanding_unpaid == 0
            || quote_capacity.max_active_records == 0
            || quote_capacity.max_outstanding_unpaid > quote_capacity.max_active_records
        {
            return Err(IssuerCoreErrorV1::InvalidInput);
        }
        Ok(Self {
            store,
            backend,
            quote_ids,
            quote_capacity,
        })
    }

    /// Reserve before Lightning, then create or recover exactly one invoice.
    /// An exact replay first queries durable state using the raw idempotency
    /// key and returns the byte-identical initial signed snapshot.
    pub fn create_or_recover_quote(
        &self,
        verified_intent: &VerifiedBolt11QuoteIntentV1<'_>,
        quote_signing_key: &SigningKey,
        now_unix: u64,
    ) -> Result<QuoteCreateResultV1, IssuerCoreErrorV1> {
        validate_now(now_unix)?;
        validate_signer(verified_intent.delegation(), quote_signing_key)?;
        let intent = verified_intent.intent();

        if let Some(record) = self
            .store
            .quote_by_creation_idempotency_key(&intent.idempotency_key)
            .map_err(map_store_error)?
        {
            return self.recover_record(
                record,
                verified_intent,
                quote_signing_key,
                now_unix,
                false,
            );
        }

        let quote_id = self
            .quote_ids
            .next_quote_id()
            .map_err(|error| match error {
                QuoteIdSourceErrorV1::Unavailable => IssuerCoreErrorV1::RetryableUnavailable,
                QuoteIdSourceErrorV1::Exhausted => IssuerCoreErrorV1::PermanentMismatch,
            })?;
        if quote_id.iter().all(|byte| *byte == 0) {
            return Err(IssuerCoreErrorV1::PermanentMismatch);
        }
        let invoice_created_not_before = now_unix
            .checked_sub(INVOICE_CREATION_CLOCK_SKEW_SECONDS_V1)
            .ok_or(IssuerCoreErrorV1::InvalidInput)?;
        let invoice_created_not_after = now_unix
            .checked_add(INVOICE_CREATION_CLOCK_SKEW_SECONDS_V1)
            .ok_or(IssuerCoreErrorV1::InvalidInput)?;
        if invoice_created_not_before == 0 {
            return Err(IssuerCoreErrorV1::InvalidInput);
        }
        let exact_intent = intent
            .encode()
            .map_err(|_| IssuerCoreErrorV1::PermanentMismatch)?;
        let exact_delegation = verified_intent
            .delegation()
            .encode()
            .map_err(|_| IssuerCoreErrorV1::PermanentMismatch)?;
        let reservation = QuoteReservation {
            quote_id,
            creation_idempotency_key: intent.idempotency_key,
            intent_digest: intent
                .request_digest()
                .map_err(|_| IssuerCoreErrorV1::PermanentMismatch)?,
            exact_intent,
            payee_pubkey: intent.expected_payee_pubkey,
            delegation_epoch: verified_intent.delegation().key_epoch,
            delegation_digest: verified_intent
                .delegation()
                .delegation_digest()
                .map_err(|_| IssuerCoreErrorV1::PermanentMismatch)?,
            exact_delegation,
            exact_amount_msat: intent.exact_amount_msat,
            invoice_created_not_before,
            invoice_created_not_after,
            now_unix,
        };

        let (record, newly_reserved) = match self
            .store
            .reserve_quote_with_capacity(&reservation, self.quote_capacity)
        {
            Ok(write) => (
                write.value,
                write.disposition == WriteDisposition::Committed,
            ),
            Err(StoreError::CreationIdempotencyConflict) => {
                let existing = self
                    .store
                    .quote_by_creation_idempotency_key(&intent.idempotency_key)
                    .map_err(map_store_error)?
                    .ok_or(IssuerCoreErrorV1::OutcomeUnknown)?;
                (existing, false)
            }
            Err(error) => return Err(map_store_error(error)),
        };
        self.recover_record(
            record,
            verified_intent,
            quote_signing_key,
            now_unix,
            newly_reserved,
        )
    }

    /// Reconcile one issuer-confidential backend label against durable quote
    /// state. Callers must never place this label in PIR protocol messages.
    pub fn reconcile_by_backend_label(
        &self,
        backend_label: &str,
        quote_signing_key: &SigningKey,
        now_unix: u64,
    ) -> Result<QuoteReconcileResultV1, IssuerCoreErrorV1> {
        validate_now(now_unix)?;
        if backend_label.is_empty() {
            return Err(IssuerCoreErrorV1::InvalidInput);
        }
        let record = self
            .store
            .quote_by_backend_label(backend_label)
            .map_err(map_store_error)?
            .ok_or(IssuerCoreErrorV1::NotFound)?;
        if record.backend_label != backend_label {
            return Err(IssuerCoreErrorV1::PermanentMismatch);
        }
        if record.state == QuoteState::Reserved {
            return self.recover_reserved_for_reconciliation(record, quote_signing_key, now_unix);
        }
        let current_exact = current_snapshot_bytes(&record)?.to_vec();
        verify_persisted_snapshot(
            &record,
            &current_exact,
            quote_signing_key,
            now_unix,
            expected_status_for_state(record.state)?,
        )?;

        let observation = self
            .backend
            .lookup_invoice(&record.backend_label, now_unix)
            .map_err(map_backend_error)?;
        if observation.observed_at != now_unix {
            return Err(IssuerCoreErrorV1::PermanentMismatch);
        }

        match observation.state {
            InvoiceObservationStateV1::Open => {
                if record.state != QuoteState::InvoiceOpen
                    || now_unix >= required_time(record.invoice_expires_at)?
                {
                    return Err(IssuerCoreErrorV1::PermanentMismatch);
                }
                Ok(reconcile_result(
                    &record,
                    QuoteReconcileDispositionV1::Unchanged,
                    current_exact,
                ))
            }
            InvoiceObservationStateV1::Expired => self.reconcile_expired(
                record,
                current_exact,
                quote_signing_key,
                observation.observed_at,
            ),
            InvoiceObservationStateV1::Settled {
                settled_at,
                amount_received_msat,
                settlement_evidence_digest,
            } => self.reconcile_settled(
                record,
                current_exact,
                quote_signing_key,
                observation.observed_at,
                settled_at,
                amount_received_msat,
                settlement_evidence_digest,
            ),
        }
    }

    fn recover_reserved_for_reconciliation(
        &self,
        record: QuoteRecord,
        quote_signing_key: &SigningKey,
        now_unix: u64,
    ) -> Result<QuoteReconcileResultV1, IssuerCoreErrorV1> {
        let intent = Bolt11QuoteIntentV1::decode(&record.intent_replay_image)
            .map_err(|_| IssuerCoreErrorV1::PermanentMismatch)?;
        if intent
            .encode()
            .map_err(|_| IssuerCoreErrorV1::PermanentMismatch)?
            != record.intent_replay_image
            || intent.idempotency_key != record.creation_idempotency_digest
            || intent.expected_payee_pubkey != record.payee_pubkey
            || intent.minimum_quote_key_epoch != record.delegation_epoch
            || intent.quote_delegation_digest != record.delegation_digest
            || intent.exact_amount_msat != record.exact_amount_msat
        {
            return Err(IssuerCoreErrorV1::PermanentMismatch);
        }
        let identity = self.store.identity().map_err(map_store_error)?;
        if intent.issuer_id != identity.issuer_id || intent.network != identity.network {
            return Err(IssuerCoreErrorV1::PermanentMismatch);
        }
        let delegation = Bolt11QuoteKeyDelegationV1::decode(&record.exact_delegation)
            .map_err(|_| IssuerCoreErrorV1::PermanentMismatch)?;
        if delegation
            .encode()
            .map_err(|_| IssuerCoreErrorV1::PermanentMismatch)?
            != record.exact_delegation
            || delegation.delegation_digest().ok() != Some(record.delegation_digest)
            || delegation.issuer_id != identity.issuer_id
            || delegation.network != identity.network
            || delegation.expected_payee_pubkey != record.payee_pubkey
            || delegation.key_epoch != record.delegation_epoch
        {
            return Err(IssuerCoreErrorV1::PermanentMismatch);
        }
        validate_signer(&delegation, quote_signing_key)?;
        let request = CreateInvoiceRequestV1 {
            backend_label: record.backend_label.clone(),
            network: intent.network,
            expected_payee_pubkey: record.payee_pubkey,
            amount_msat: record.exact_amount_msat,
            expiry_seconds: intent.invoice_expiry_seconds,
            description_hash: anonymous_invoice_description_hash_v1(),
        };
        let created = match self
            .backend
            .existing_invoice(&record.backend_label)
            .map_err(map_backend_error)?
        {
            Some(created) => created,
            None if now_unix <= record.invoice_created_not_after => self
                .backend
                .create_or_get_invoice(&request)
                .map_err(map_backend_error)?,
            None => return Err(IssuerCoreErrorV1::InvalidState),
        };
        let created = created
            .verify_for_request(&request)
            .map_err(map_backend_error)?
            .created();
        if created.created_at < record.invoice_created_not_before
            || created.created_at > record.invoice_created_not_after
            || created.created_at > now_unix.saturating_add(INVOICE_CREATION_CLOCK_SKEW_SECONDS_V1)
        {
            return Err(IssuerCoreErrorV1::PermanentMismatch);
        }
        let parsed = ParsedBolt11InvoiceV1::parse(&created.invoice)
            .map_err(|_| IssuerCoreErrorV1::PermanentMismatch)?;
        let exact = sign_recovered_initial_quote(
            &record,
            &intent,
            &delegation,
            &created.invoice,
            &parsed,
            quote_signing_key,
        )?;
        let write = self
            .store
            .finalize_quote(&QuoteFinalization {
                quote_id: record.quote_id,
                invoice: created.invoice.clone(),
                payment_hash: created.payment_hash,
                invoice_created_at: created.created_at,
                invoice_expires_at: created.expires_at,
                claim_deadline: intent
                    .derived_horizons(created.created_at)
                    .map_err(|_| IssuerCoreErrorV1::PermanentMismatch)?
                    .claim_deadline,
                credential_not_after: intent
                    .derived_horizons(created.created_at)
                    .map_err(|_| IssuerCoreErrorV1::PermanentMismatch)?
                    .credential_not_after,
                exact_signed_quote_response: exact,
            })
            .map_err(map_store_error)?;
        let persisted = write
            .value
            .initial_signed_quote_response
            .clone()
            .ok_or(IssuerCoreErrorV1::PermanentMismatch)?;
        verify_persisted_snapshot(
            &write.value,
            &persisted,
            quote_signing_key,
            now_unix,
            Bolt11QuoteStatusV1::InvoiceOpen,
        )?;
        Ok(reconcile_result(
            &write.value,
            QuoteReconcileDispositionV1::Transitioned,
            persisted,
        ))
    }

    fn recover_record(
        &self,
        record: QuoteRecord,
        verified_intent: &VerifiedBolt11QuoteIntentV1<'_>,
        quote_signing_key: &SigningKey,
        now_unix: u64,
        newly_reserved: bool,
    ) -> Result<QuoteCreateResultV1, IssuerCoreErrorV1> {
        validate_record_for_intent(&record, verified_intent)?;
        if record.state != QuoteState::Reserved {
            let exact = record
                .initial_signed_quote_response
                .as_deref()
                .ok_or(IssuerCoreErrorV1::PermanentMismatch)?;
            verify_persisted_snapshot(
                &record,
                exact,
                quote_signing_key,
                now_unix,
                Bolt11QuoteStatusV1::InvoiceOpen,
            )?;
            return Ok(QuoteCreateResultV1 {
                disposition: QuoteCreateDispositionV1::ExactReplay,
                exact_signed_quote_response: exact.to_vec(),
            });
        }

        let intent = verified_intent.intent();
        let request = CreateInvoiceRequestV1 {
            backend_label: record.backend_label.clone(),
            network: intent.network,
            expected_payee_pubkey: record.payee_pubkey,
            amount_msat: record.exact_amount_msat,
            expiry_seconds: intent.invoice_expiry_seconds,
            description_hash: anonymous_invoice_description_hash_v1(),
        };
        let created = match self
            .backend
            .existing_invoice(&record.backend_label)
            .map_err(map_backend_error)?
        {
            Some(created) => created,
            None if now_unix <= record.invoice_created_not_after => self
                .backend
                .create_or_get_invoice(&request)
                .map_err(map_backend_error)?,
            None => return Err(IssuerCoreErrorV1::InvalidState),
        };
        let verified_created = created
            .verify_for_request(&request)
            .map_err(map_backend_error)?;
        let created = verified_created.created();
        if created.created_at < record.invoice_created_not_before
            || created.created_at > record.invoice_created_not_after
            || created.created_at > now_unix.saturating_add(INVOICE_CREATION_CLOCK_SKEW_SECONDS_V1)
        {
            return Err(IssuerCoreErrorV1::PermanentMismatch);
        }
        let parsed = ParsedBolt11InvoiceV1::parse(&created.invoice)
            .map_err(|_| IssuerCoreErrorV1::PermanentMismatch)?;
        let quote = Bolt11QuoteV1::sign_for_verified_intent(
            verified_intent,
            record.quote_id,
            created.invoice.clone(),
            &parsed,
            Bolt11QuoteStatusV1::InvoiceOpen,
            created.created_at,
            quote_signing_key,
        )
        .map_err(|_| IssuerCoreErrorV1::PermanentMismatch)?;
        let exact = quote
            .encode()
            .map_err(|_| IssuerCoreErrorV1::PermanentMismatch)?;
        let write = self
            .store
            .finalize_quote(&QuoteFinalization {
                quote_id: record.quote_id,
                invoice: created.invoice.clone(),
                payment_hash: created.payment_hash,
                invoice_created_at: quote.invoice_created_at,
                invoice_expires_at: quote.invoice_expires_at,
                claim_deadline: quote.claim_deadline,
                credential_not_after: quote.credential_not_after,
                exact_signed_quote_response: exact,
            })
            .map_err(map_store_error)?;
        let persisted = write
            .value
            .initial_signed_quote_response
            .clone()
            .ok_or(IssuerCoreErrorV1::PermanentMismatch)?;
        verify_persisted_snapshot(
            &write.value,
            &persisted,
            quote_signing_key,
            now_unix,
            Bolt11QuoteStatusV1::InvoiceOpen,
        )?;
        Ok(QuoteCreateResultV1 {
            disposition: if newly_reserved {
                QuoteCreateDispositionV1::Created
            } else {
                QuoteCreateDispositionV1::RecoveredReserved
            },
            exact_signed_quote_response: persisted,
        })
    }

    fn reconcile_expired(
        &self,
        record: QuoteRecord,
        current_exact: Vec<u8>,
        quote_signing_key: &SigningKey,
        observed_at: u64,
    ) -> Result<QuoteReconcileResultV1, IssuerCoreErrorV1> {
        let expires_at = required_time(record.invoice_expires_at)?;
        if observed_at < expires_at {
            return Err(IssuerCoreErrorV1::PermanentMismatch);
        }
        match record.state {
            QuoteState::InvoiceOpen => {
                // Expiry is a deterministic invoice fact, not the wall-clock
                // time at which this process happened to observe it. Signing
                // at `expires_at` keeps restart recovery possible after a long
                // issuer outage without extending the delegated quote key's
                // validity or manufacturing a later lifecycle timestamp.
                let next = sign_persisted_transition(
                    &record,
                    &current_exact,
                    quote_signing_key,
                    observed_at,
                    Bolt11QuoteStatusV1::InvoiceExpiredPendingReconcile,
                    expires_at,
                )?;
                let write = self
                    .store
                    .mark_invoice_expired(&QuoteExpiry {
                        quote_id: record.quote_id,
                        observed_at: expires_at,
                        exact_signed_quote_response: next,
                    })
                    .map_err(map_store_error)?;
                let exact = write
                    .value
                    .expired_signed_quote_response
                    .clone()
                    .ok_or(IssuerCoreErrorV1::PermanentMismatch)?;
                Ok(reconcile_result(
                    &write.value,
                    QuoteReconcileDispositionV1::Transitioned,
                    exact,
                ))
            }
            QuoteState::InvoiceExpiredPendingReconcile => Ok(reconcile_result(
                &record,
                QuoteReconcileDispositionV1::Unchanged,
                current_exact,
            )),
            QuoteState::PaymentSettled | QuoteState::LateSettledReconcile => {
                Err(IssuerCoreErrorV1::PermanentMismatch)
            }
            QuoteState::Reserved | QuoteState::CredentialClaimed => {
                Err(IssuerCoreErrorV1::InvalidState)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn reconcile_settled(
        &self,
        record: QuoteRecord,
        current_exact: Vec<u8>,
        quote_signing_key: &SigningKey,
        observed_at: u64,
        settled_at: u64,
        amount_received_msat: u64,
        settlement_evidence_digest: [u8; 32],
    ) -> Result<QuoteReconcileResultV1, IssuerCoreErrorV1> {
        let created_at = required_time(record.invoice_created_at)?;
        let expires_at = required_time(record.invoice_expires_at)?;
        if settled_at < created_at
            || settled_at > observed_at
            || amount_received_msat < record.exact_amount_msat
            || settlement_evidence_digest.iter().all(|byte| *byte == 0)
        {
            return Err(IssuerCoreErrorV1::PermanentMismatch);
        }

        match record.state {
            QuoteState::InvoiceOpen if settled_at <= expires_at => self.commit_settlement(
                record,
                current_exact,
                quote_signing_key,
                observed_at,
                settled_at,
                amount_received_msat,
                settlement_evidence_digest,
                Bolt11QuoteStatusV1::PaymentSettled,
            ),
            QuoteState::InvoiceOpen => {
                let expired_exact = sign_persisted_transition(
                    &record,
                    &current_exact,
                    quote_signing_key,
                    observed_at,
                    Bolt11QuoteStatusV1::InvoiceExpiredPendingReconcile,
                    expires_at,
                )?;
                let expired_write = self
                    .store
                    .mark_invoice_expired(&QuoteExpiry {
                        quote_id: record.quote_id,
                        observed_at: expires_at,
                        exact_signed_quote_response: expired_exact,
                    })
                    .map_err(map_store_error)?;
                let expired_record = expired_write.value;
                let expired_snapshot = expired_record
                    .expired_signed_quote_response
                    .clone()
                    .ok_or(IssuerCoreErrorV1::PermanentMismatch)?;
                self.commit_settlement(
                    expired_record,
                    expired_snapshot,
                    quote_signing_key,
                    observed_at,
                    settled_at,
                    amount_received_msat,
                    settlement_evidence_digest,
                    Bolt11QuoteStatusV1::LateSettledReconcile,
                )
            }
            QuoteState::InvoiceExpiredPendingReconcile => {
                let expired_observed_at = required_time(record.expiry_observed_at)?;
                if settled_at <= expires_at || settled_at <= expired_observed_at {
                    return Err(IssuerCoreErrorV1::PermanentMismatch);
                }
                self.commit_settlement(
                    record,
                    current_exact,
                    quote_signing_key,
                    observed_at,
                    settled_at,
                    amount_received_msat,
                    settlement_evidence_digest,
                    Bolt11QuoteStatusV1::LateSettledReconcile,
                )
            }
            QuoteState::PaymentSettled | QuoteState::LateSettledReconcile => {
                if record.settled_at != Some(settled_at)
                    || record.settled_amount_msat != Some(amount_received_msat)
                    || record.settlement_evidence_digest != Some(settlement_evidence_digest)
                {
                    return Err(IssuerCoreErrorV1::PermanentMismatch);
                }
                Ok(reconcile_result(
                    &record,
                    QuoteReconcileDispositionV1::Unchanged,
                    current_exact,
                ))
            }
            QuoteState::Reserved | QuoteState::CredentialClaimed => {
                Err(IssuerCoreErrorV1::InvalidState)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_settlement(
        &self,
        record: QuoteRecord,
        current_exact: Vec<u8>,
        quote_signing_key: &SigningKey,
        observed_at: u64,
        settled_at: u64,
        amount_received_msat: u64,
        settlement_evidence_digest: [u8; 32],
        next_status: Bolt11QuoteStatusV1,
    ) -> Result<QuoteReconcileResultV1, IssuerCoreErrorV1> {
        let current = Bolt11QuoteV1::decode(&current_exact)
            .map_err(|_| IssuerCoreErrorV1::PermanentMismatch)?;
        // Backend settlement timestamps are authoritative payment evidence,
        // while issuer observation time is only local bookkeeping.  Sign the
        // earliest strictly monotonic lifecycle time justified by that
        // evidence.  In particular, an on-time payment first observed after
        // invoice expiry must remain PaymentSettled instead of being assigned
        // a post-expiry status timestamp and rejected by the wire protocol.
        let transition_time = settled_at.max(
            current
                .status_updated_at
                .checked_add(1)
                .ok_or(IssuerCoreErrorV1::PermanentMismatch)?,
        );
        if transition_time > observed_at {
            return Err(IssuerCoreErrorV1::RetryableUnavailable);
        }
        let next = sign_persisted_transition(
            &record,
            &current_exact,
            quote_signing_key,
            observed_at,
            next_status,
            transition_time,
        )?;
        let write = self
            .store
            .record_settlement(&QuoteSettlement {
                quote_id: record.quote_id,
                settled_at,
                observed_at: transition_time,
                settled_amount_msat: amount_received_msat,
                settlement_evidence_digest,
                exact_signed_quote_response: next,
            })
            .map_err(map_store_error)?;
        let exact = write
            .value
            .settled_signed_quote_response
            .clone()
            .ok_or(IssuerCoreErrorV1::PermanentMismatch)?;
        Ok(reconcile_result(
            &write.value,
            QuoteReconcileDispositionV1::Transitioned,
            exact,
        ))
    }
}

fn validate_now(now_unix: u64) -> Result<(), IssuerCoreErrorV1> {
    if now_unix == 0 {
        Err(IssuerCoreErrorV1::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_signer(
    delegation: &Bolt11QuoteKeyDelegationV1,
    quote_signing_key: &SigningKey,
) -> Result<(), IssuerCoreErrorV1> {
    if quote_signing_key.verifying_key().to_bytes() != delegation.quote_verifying_key {
        return Err(IssuerCoreErrorV1::PermanentMismatch);
    }
    Ok(())
}

fn validate_record_for_intent(
    record: &QuoteRecord,
    verified_intent: &VerifiedBolt11QuoteIntentV1<'_>,
) -> Result<(), IssuerCoreErrorV1> {
    let intent = verified_intent.intent();
    let exact_delegation = verified_intent
        .delegation()
        .encode()
        .map_err(|_| IssuerCoreErrorV1::PermanentMismatch)?;
    if record.intent_digest
        != intent
            .request_digest()
            .map_err(|_| IssuerCoreErrorV1::PermanentMismatch)?
        || record.payee_pubkey != intent.expected_payee_pubkey
        || record.delegation_epoch != verified_intent.delegation().key_epoch
        || record.delegation_digest != intent.quote_delegation_digest
        || record.exact_delegation != exact_delegation
        || record.exact_amount_msat != intent.exact_amount_msat
        || record.invoice_created_not_before == 0
        || record.invoice_created_not_after < record.invoice_created_not_before
    {
        return Err(IssuerCoreErrorV1::PermanentMismatch);
    }
    Ok(())
}

fn sign_recovered_initial_quote(
    record: &QuoteRecord,
    sanitized_intent: &Bolt11QuoteIntentV1,
    delegation: &Bolt11QuoteKeyDelegationV1,
    invoice: &str,
    parsed_invoice: &ParsedBolt11InvoiceV1,
    quote_signing_key: &SigningKey,
) -> Result<Vec<u8>, IssuerCoreErrorV1> {
    let horizons = sanitized_intent
        .derived_horizons(parsed_invoice.created_at())
        .map_err(|_| IssuerCoreErrorV1::PermanentMismatch)?;
    if parsed_invoice.invoice_text_digest() != bolt11_invoice_text_digest_v1(invoice)
        || parsed_invoice.network() != sanitized_intent.network
        || parsed_invoice.payee_pubkey() != record.payee_pubkey
        || parsed_invoice.amount_msat() != record.exact_amount_msat
        || parsed_invoice.expiry_seconds() != sanitized_intent.invoice_expiry_seconds
        || parsed_invoice
            .expires_at()
            .map_err(|_| IssuerCoreErrorV1::PermanentMismatch)?
            != horizons.invoice_expires_at
    {
        return Err(IssuerCoreErrorV1::PermanentMismatch);
    }
    delegation
        .verify_for(
            &sanitized_intent.issuer_id,
            sanitized_intent.network,
            &record.payee_pubkey,
            record.delegation_epoch,
            parsed_invoice.created_at(),
        )
        .and_then(|_| {
            delegation.verify_for(
                &sanitized_intent.issuer_id,
                sanitized_intent.network,
                &record.payee_pubkey,
                record.delegation_epoch,
                horizons.claim_deadline,
            )
        })
        .map_err(|_| IssuerCoreErrorV1::PermanentMismatch)?;
    validate_signer(delegation, quote_signing_key)?;
    let mut quote = Bolt11QuoteV1 {
        request_digest: record.intent_digest,
        quote_id: record.quote_id,
        quote_key_id: delegation.quote_key_id,
        invoice: invoice.to_owned(),
        network: sanitized_intent.network,
        payee_pubkey: record.payee_pubkey,
        amount_msat: record.exact_amount_msat,
        invoice_created_at: parsed_invoice.created_at(),
        invoice_expires_at: horizons.invoice_expires_at,
        claim_deadline: horizons.claim_deadline,
        credential_not_after: horizons.credential_not_after,
        status: Bolt11QuoteStatusV1::InvoiceOpen,
        state_version: 1,
        status_updated_at: parsed_invoice.created_at(),
        signature: [0; 64],
    };
    let unsigned_with_placeholder = quote
        .encode()
        .map_err(|_| IssuerCoreErrorV1::PermanentMismatch)?;
    let unsigned_len = unsigned_with_placeholder
        .len()
        .checked_sub(quote.signature.len())
        .ok_or(IssuerCoreErrorV1::PermanentMismatch)?;
    let mut signing_preimage =
        Vec::with_capacity(BOLT11_QUOTE_SIGNATURE_DOMAIN.len() + unsigned_len);
    signing_preimage.extend_from_slice(BOLT11_QUOTE_SIGNATURE_DOMAIN);
    signing_preimage.extend_from_slice(&unsigned_with_placeholder[..unsigned_len]);
    quote.signature = quote_signing_key.sign(&signing_preimage).to_bytes();
    quote
        .encode()
        .map_err(|_| IssuerCoreErrorV1::PermanentMismatch)
}

fn required_time(value: Option<u64>) -> Result<u64, IssuerCoreErrorV1> {
    value.ok_or(IssuerCoreErrorV1::PermanentMismatch)
}

fn current_snapshot_bytes(record: &QuoteRecord) -> Result<&[u8], IssuerCoreErrorV1> {
    match record.state {
        QuoteState::InvoiceOpen => record.initial_signed_quote_response.as_deref(),
        QuoteState::PaymentSettled | QuoteState::LateSettledReconcile => {
            record.settled_signed_quote_response.as_deref()
        }
        QuoteState::InvoiceExpiredPendingReconcile => {
            record.expired_signed_quote_response.as_deref()
        }
        QuoteState::Reserved | QuoteState::CredentialClaimed => {
            return Err(IssuerCoreErrorV1::InvalidState)
        }
    }
    .ok_or(IssuerCoreErrorV1::PermanentMismatch)
}

fn expected_status_for_state(state: QuoteState) -> Result<Bolt11QuoteStatusV1, IssuerCoreErrorV1> {
    match state {
        QuoteState::InvoiceOpen => Ok(Bolt11QuoteStatusV1::InvoiceOpen),
        QuoteState::PaymentSettled => Ok(Bolt11QuoteStatusV1::PaymentSettled),
        QuoteState::InvoiceExpiredPendingReconcile => {
            Ok(Bolt11QuoteStatusV1::InvoiceExpiredPendingReconcile)
        }
        QuoteState::LateSettledReconcile => Ok(Bolt11QuoteStatusV1::LateSettledReconcile),
        QuoteState::Reserved | QuoteState::CredentialClaimed => {
            Err(IssuerCoreErrorV1::InvalidState)
        }
    }
}

fn decode_persisted_material(
    record: &QuoteRecord,
    exact: &[u8],
    quote_signing_key: &SigningKey,
    expected_status: Bolt11QuoteStatusV1,
) -> Result<(Bolt11QuoteV1, Bolt11QuoteKeyDelegationV1), IssuerCoreErrorV1> {
    let quote = Bolt11QuoteV1::decode(exact).map_err(|_| IssuerCoreErrorV1::PermanentMismatch)?;
    if quote
        .encode()
        .map_err(|_| IssuerCoreErrorV1::PermanentMismatch)?
        != exact
        || quote.status != expected_status
    {
        return Err(IssuerCoreErrorV1::PermanentMismatch);
    }
    let delegation = Bolt11QuoteKeyDelegationV1::decode(&record.exact_delegation)
        .map_err(|_| IssuerCoreErrorV1::PermanentMismatch)?;
    if delegation
        .encode()
        .map_err(|_| IssuerCoreErrorV1::PermanentMismatch)?
        != record.exact_delegation
        || delegation.delegation_digest().ok() != Some(record.delegation_digest)
    {
        return Err(IssuerCoreErrorV1::PermanentMismatch);
    }
    validate_signer(&delegation, quote_signing_key)?;
    Ok((quote, delegation))
}

fn persisted_expectation<'a>(
    record: &'a QuoteRecord,
    delegation: &'a Bolt11QuoteKeyDelegationV1,
) -> Result<PersistedBolt11QuoteExpectationV1<'a>, IssuerCoreErrorV1> {
    Ok(PersistedBolt11QuoteExpectationV1 {
        issuer_id: &delegation.issuer_id,
        network: delegation.network,
        payee_pubkey: &record.payee_pubkey,
        minimum_quote_key_epoch: record.delegation_epoch,
        quote_delegation_digest: &record.delegation_digest,
        request_digest: &record.intent_digest,
        quote_id: &record.quote_id,
        invoice: record
            .invoice
            .as_deref()
            .ok_or(IssuerCoreErrorV1::PermanentMismatch)?,
        amount_msat: record.exact_amount_msat,
        invoice_created_at: required_time(record.invoice_created_at)?,
        invoice_expires_at: required_time(record.invoice_expires_at)?,
        claim_deadline: required_time(record.claim_deadline)?,
        credential_not_after: required_time(record.credential_not_after)?,
    })
}

fn verify_persisted_snapshot(
    record: &QuoteRecord,
    exact: &[u8],
    quote_signing_key: &SigningKey,
    now_unix: u64,
    expected_status: Bolt11QuoteStatusV1,
) -> Result<(), IssuerCoreErrorV1> {
    let (quote, delegation) =
        decode_persisted_material(record, exact, quote_signing_key, expected_status)?;
    let latest_signed_time = quote.invoice_created_at.max(quote.status_updated_at);
    if latest_signed_time > now_unix.saturating_add(INVOICE_CREATION_CLOCK_SKEW_SECONDS_V1) {
        return Err(IssuerCoreErrorV1::PermanentMismatch);
    }
    let verification_time = now_unix.max(latest_signed_time);
    let expected = persisted_expectation(record, &delegation)?;
    quote
        .verify_persisted_for_transition(expected, &delegation, verification_time)
        .map_err(|_| IssuerCoreErrorV1::PermanentMismatch)?;
    Ok(())
}

fn sign_persisted_transition(
    record: &QuoteRecord,
    current_exact: &[u8],
    quote_signing_key: &SigningKey,
    verification_time: u64,
    next_status: Bolt11QuoteStatusV1,
    transition_time: u64,
) -> Result<Vec<u8>, IssuerCoreErrorV1> {
    let (quote, delegation) = decode_persisted_material(
        record,
        current_exact,
        quote_signing_key,
        expected_status_for_state(record.state)?,
    )?;
    // Lightning backends such as Core Lightning report both invoice creation
    // and settlement at whole-second precision.  A valid payment can therefore
    // settle in the same second as the signed InvoiceOpen snapshot.  Keep the
    // backend's exact settlement time as evidence, but wait for a later issuer
    // observation before signing the lifecycle successor so the wire-level
    // transition time remains strictly monotonic.
    if transition_time <= quote.status_updated_at {
        return Err(IssuerCoreErrorV1::RetryableUnavailable);
    }
    let expected = persisted_expectation(record, &delegation)?;
    let verified = quote
        .verify_persisted_for_transition(expected, &delegation, verification_time)
        .map_err(|_| IssuerCoreErrorV1::PermanentMismatch)?;
    let next = Bolt11QuoteV1::with_status_from_verified_persisted_snapshot(
        &verified,
        next_status,
        transition_time,
        &delegation,
        quote_signing_key,
    )
    .map_err(|_| IssuerCoreErrorV1::PermanentMismatch)?;
    next.encode()
        .map_err(|_| IssuerCoreErrorV1::PermanentMismatch)
}

fn reconcile_result(
    record: &QuoteRecord,
    disposition: QuoteReconcileDispositionV1,
    exact_signed_quote_response: Vec<u8>,
) -> QuoteReconcileResultV1 {
    QuoteReconcileResultV1 {
        durable_state: record.state,
        disposition,
        exact_signed_quote_response,
    }
}

fn map_backend_error(error: LightningBackendErrorV1) -> IssuerCoreErrorV1 {
    match error {
        LightningBackendErrorV1::BackendUnavailable | LightningBackendErrorV1::LockPoisoned => {
            IssuerCoreErrorV1::RetryableUnavailable
        }
        LightningBackendErrorV1::OutcomeUnknown => IssuerCoreErrorV1::OutcomeUnknown,
        LightningBackendErrorV1::InvalidRequest
        | LightningBackendErrorV1::RequestConflict
        | LightningBackendErrorV1::InvoiceNotFound
        | LightningBackendErrorV1::InvoiceCreationFailed => IssuerCoreErrorV1::PermanentMismatch,
    }
}

fn map_store_error(error: StoreError) -> IssuerCoreErrorV1 {
    match error {
        StoreError::RollbackFloorMissing
        | StoreError::RollbackFloorIdentityMismatch
        | StoreError::RollbackDetected { .. }
        | StoreError::RollbackFork
        | StoreError::RollbackAuthorityProtocol(_)
        | StoreError::RollbackAuthorityUnavailable(_)
        | StoreError::UnanchoredCommit { .. } => IssuerCoreErrorV1::StoreUnanchored,
        StoreError::CommitOutcomeUnknown(_) => IssuerCoreErrorV1::OutcomeUnknown,
        StoreError::QuoteMissing => IssuerCoreErrorV1::NotFound,
        StoreError::InvalidQuoteState
        | StoreError::QuoteNotSettled
        | StoreError::PayoutIntentAlreadyConsumed
        | StoreError::InsufficientProviderBalance => IssuerCoreErrorV1::InvalidState,
        StoreError::Io(_)
        | StoreError::Sqlite(_)
        | StoreError::PayoutOutboxUnavailable
        | StoreError::QuoteCapacityExceeded
        | StoreError::StatusNonceCapacityExceeded => IssuerCoreErrorV1::RetryableUnavailable,
        StoreError::MissingDatabase(_)
        | StoreError::NotRegularDatabase(_)
        | StoreError::SchemaMismatch(_)
        | StoreError::IntegrityCheckFailed(_)
        | StoreError::StoreInstanceMismatch
        | StoreError::IssuerMismatch
        | StoreError::NetworkMismatch
        | StoreError::InvalidInput(_)
        | StoreError::QuoteConflict
        | StoreError::CreationIdempotencyConflict
        | StoreError::InvoiceConflict
        | StoreError::PaymentHashConflict
        | StoreError::RequiresExpiryReconcile
        | StoreError::SettlementConflict
        | StoreError::SignedQuoteMismatch
        | StoreError::ClaimIdempotencyConflict
        | StoreError::QuoteAlreadyClaimed
        | StoreError::ClaimDeadlineExpired
        | StoreError::ClaimProtocolMismatch
        | StoreError::BadClaimCryptography
        | StoreError::StatusRequestBindingMismatch
        | StoreError::StatusRequestStale
        | StoreError::StatusTimeRollback
        | StoreError::BadStatusRequestSignature
        | StoreError::StatusNonceReplay
        | StoreError::ReceiptSerialConflict
        | StoreError::DelegationRollback
        | StoreError::DelegationFork
        | StoreError::ServicePolicyRollback
        | StoreError::ServicePolicyFork
        | StoreError::ServicePolicySigningKeyConflict
        | StoreError::BatKeyLineageConflict
        | StoreError::BatV2ClassRollback
        | StoreError::BatV2ClassFork
        | StoreError::BatV2ClassTermsConflict
        | StoreError::BatV2ClassMemberMismatch
        | StoreError::BatV2RawKeyConflict
        | StoreError::ArcKeyLineageConflict
        | StoreError::SettlementKeyLineageConflict
        | StoreError::ProviderRegistrationRollback
        | StoreError::ProviderRegistrationFork
        | StoreError::ClearingAuthorizationRollback
        | StoreError::ClearingAuthorizationFork
        | StoreError::RedeemIdempotencyConflict
        | StoreError::CredentialAlreadySpent
        | StoreError::LedgerBalanceOverflow
        | StoreError::SettlementDepositIdempotencyConflict
        | StoreError::SettlementNoteAlreadySpent
        | StoreError::SettlementLedgerSequenceConflict
        | StoreError::PayoutIntentIdempotencyConflict
        | StoreError::PayoutIdempotencyConflict
        | StoreError::PayoutStatusConflict
        | StoreError::Protocol(_)
        | StoreError::CommitSequenceExhausted => IssuerCoreErrorV1::PermanentMismatch,
    }
}

#[cfg(test)]
mod tests;
