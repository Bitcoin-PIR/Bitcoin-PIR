//! Transport-neutral issuer request handlers.
//!
//! No type in this crate is a PIR wire message. Invoice, payment hash,
//! backend label, and claim recovery state terminate at this boundary.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey};
use pir_arc_adapter::{ArcIssuanceCanonicalizerV1, ArcSecretKeyringV1};
use pir_issuer_clearing::{
    prepare_payout_intent_response_v1, prepare_redeem_response_v1,
    sign_and_commit_payout_execution_v1, sign_and_commit_payout_status_v1,
    RedeemResponseDerivationKeyV1, SharedIssuerCredentialVerifierV1,
};
use pir_issuer_core::{
    Bolt11IssuerCoreV1, IssuerCoreErrorV1, QuoteIdSourceV1, QuoteReconcileDispositionV1,
    INVOICE_CREATION_CLOCK_SKEW_SECONDS_V1,
};
use pir_issuer_credentials::{
    prepare_arc_issuance_v1, prepare_cashu_bat_issuance_v1, prepare_direct_receipt_issuance_v1,
    IssuerCredentialDerivationKeyV1, PreparedCredentialIssuanceV1,
};
use pir_issuer_store::{
    ClaimCryptographicVerificationInput, ClaimWrite, IssuerStore,
    ProviderSettlementRegistrationRecordV1, QuoteCapacityV1, QuoteState, QuoteStatusBip340Input,
    StoreError, VerifiedRedeemCommitV1,
};
use pir_lightning_backend::LightningInvoiceBackendV1;
use pir_payment_crypto::{
    K256Bip340PrehashVerifierV1, K256CashuDleqVerifierV1, K256CashuMintKeyringV1,
};
use pir_service_protocol::{
    verify_committed_clearing_request_auth_v1, verify_committed_payout_status_replay_auth_v1,
    verify_committed_redeem_replay_auth_v1, verify_ledger_redeem_response_for_exact_request_v1,
    verify_new_balance_request_for, verify_new_payout_request_for,
    verify_new_payout_status_request_for, verify_payout_initial_response_for_exact_request,
    verify_persisted_payout_snapshot_for_store_v1, verify_redeem_response_for_exact_request,
    AcquisitionMethod, AuthScheme, Bolt11QuoteClaimEnvelopeV1, Bolt11QuoteIntentV1,
    Bolt11QuoteKeyDelegationV1, Bolt11QuoteKeyRollbackGuardV1, Bolt11QuoteStatusRequestV1,
    Bolt11QuoteStatusV1, Bolt11QuoteV1, CashuKeysetBindingV1, CommittedRedeemReplayExpectationV1,
    IssuerBalanceResponseV1, IssuerClearingApprovalV1, IssuerPayoutIntentResponseV1,
    IssuerPayoutResponseV1, IssuerPayoutStatusResponseV1, IssuerSettlementKeyringExpectationV1,
    ParsedBolt11InvoiceV1, PayoutCommitErrorV1, PayoutExecutionContextV1, PayoutStatusContextV1,
    PolicyRollbackGuardV1, ProviderBalanceEnvelopeV1, ProviderClearingAuthorizationV1,
    ProviderClearingExpectationV1, ProviderPayoutEnvelopeV1, ProviderPayoutIntentEnvelopeV1,
    ProviderPayoutStatusEnvelopeV1, ProviderRedeemEnvelopeV1,
    ProviderSettlementRegistrationExpectationV1, RetainedSettlementKeysetExpectationV1,
    ServicePolicyEpochFloorsV1, ServicePolicyV1, SettlementDestinationV1, MAX_SERVICE_VALUE_V1,
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssuerServiceErrorV1 {
    InvalidRequest,
    Unauthorized,
    NotFound,
    Conflict,
    RetryableUnavailable,
    OutcomeUnknown,
    Internal,
}

/// Aggregate-only background reconciliation result. The cursor is available
/// to the scheduler but omitted from `Debug` because quote IDs and backend
/// labels must never enter logs.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct IssuerReconciliationBatchV1 {
    next_cursor: Option<[u8; 32]>,
    pub examined: u32,
    pub transitioned: u32,
    pub unchanged: u32,
    pub retryable_failures: u32,
    pub permanent_failures: u32,
}

impl IssuerReconciliationBatchV1 {
    pub const fn next_cursor(&self) -> Option<[u8; 32]> {
        self.next_cursor
    }
}

impl fmt::Debug for IssuerReconciliationBatchV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuerReconciliationBatchV1")
            .field("cursor", &"[redacted]")
            .field("examined", &self.examined)
            .field("transitioned", &self.transitioned)
            .field("unchanged", &self.unchanged)
            .field("retryable_failures", &self.retryable_failures)
            .field("permanent_failures", &self.permanent_failures)
            .finish()
    }
}

impl IssuerServiceErrorV1 {
    pub const fn http_status(self) -> u16 {
        match self {
            Self::InvalidRequest => 400,
            Self::Unauthorized => 401,
            Self::NotFound => 404,
            Self::Conflict => 409,
            Self::RetryableUnavailable => 503,
            Self::OutcomeUnknown => 503,
            Self::Internal => 500,
        }
    }

    pub const fn public_code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::Unauthorized => "unauthorized",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::RetryableUnavailable => "retryable_unavailable",
            Self::OutcomeUnknown => "outcome_unknown_retry_exact_request",
            Self::Internal => "internal_error",
        }
    }
}

impl fmt::Display for IssuerServiceErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.public_code())
    }
}

impl std::error::Error for IssuerServiceErrorV1 {}

/// One root-signed quote-key delegation and the matching online signing key.
/// The constructor proves the private key cannot be paired with a different
/// public delegation.
pub struct QuoteSigningMaterialV1 {
    delegation: Bolt11QuoteKeyDelegationV1,
    signing_key: SigningKey,
    delegation_digest: [u8; 32],
}

impl QuoteSigningMaterialV1 {
    pub fn new(
        delegation: Bolt11QuoteKeyDelegationV1,
        signing_key: SigningKey,
    ) -> Result<Self, IssuerServiceErrorV1> {
        if delegation.quote_verifying_key != signing_key.verifying_key().to_bytes() {
            return Err(IssuerServiceErrorV1::InvalidRequest);
        }
        let delegation_digest = delegation
            .delegation_digest()
            .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?;
        Ok(Self {
            delegation,
            signing_key,
            delegation_digest,
        })
    }
}

impl fmt::Debug for QuoteSigningMaterialV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QuoteSigningMaterialV1")
            .field("delegation_digest", &self.delegation_digest)
            .field("signing_key", &"[redacted]")
            .finish_non_exhaustive()
    }
}

/// Retained receipt signer. Keys are selected only by the exact issuer-signed
/// credential binding's verification key.
pub struct ReceiptSigningMaterialV1 {
    signing_key: SigningKey,
}

impl ReceiptSigningMaterialV1 {
    pub fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }
}

impl fmt::Debug for ReceiptSigningMaterialV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReceiptSigningMaterialV1")
            .field("signing_key", &"[redacted]")
            .finish()
    }
}

/// Fully configured quote/claim service. Shared clearing is added through a
/// separate adapter so a deployment can run acquisition without an online
/// redeem trust dependency.
pub struct IssuerAcquisitionServiceV1<B, Q> {
    store: IssuerStore,
    core: Bolt11IssuerCoreV1<B, Q>,
    current_quote_key: QuoteSigningMaterialV1,
    retained_quote_keys: Vec<QuoteSigningMaterialV1>,
    receipt_keys: Vec<ReceiptSigningMaterialV1>,
    bat_keyring: Option<Arc<K256CashuMintKeyringV1>>,
    arc_keyring_experimental: Option<Arc<ArcSecretKeyringV1>>,
    credential_derivation_key: IssuerCredentialDerivationKeyV1,
}

impl<B, Q> fmt::Debug for IssuerAcquisitionServiceV1<B, Q> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuerAcquisitionServiceV1")
            .field("store", &"[redacted]")
            .field("core", &"[redacted]")
            .field(
                "quote_key_count",
                &self.retained_quote_keys.len().saturating_add(1),
            )
            .field("receipt_key_count", &self.receipt_keys.len())
            .field("bat", &self.bat_keyring.is_some())
            .field("arc_experimental", &self.arc_keyring_experimental.is_some())
            .finish_non_exhaustive()
    }
}

impl<B, Q> IssuerAcquisitionServiceV1<B, Q>
where
    B: LightningInvoiceBackendV1,
    Q: QuoteIdSourceV1,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: IssuerStore,
        backend: Arc<B>,
        quote_ids: Arc<Q>,
        current_quote_key: QuoteSigningMaterialV1,
        retained_quote_keys: Vec<QuoteSigningMaterialV1>,
        receipt_keys: Vec<ReceiptSigningMaterialV1>,
        bat_keyring: Option<Arc<K256CashuMintKeyringV1>>,
        arc_keyring_experimental: Option<Arc<ArcSecretKeyringV1>>,
        credential_derivation_key: IssuerCredentialDerivationKeyV1,
        now_unix: u64,
    ) -> Result<Self, IssuerServiceErrorV1> {
        Self::new_with_quote_capacity(
            store,
            backend,
            quote_ids,
            current_quote_key,
            retained_quote_keys,
            receipt_keys,
            bat_keyring,
            arc_keyring_experimental,
            credential_derivation_key,
            QuoteCapacityV1::unbounded(),
            now_unix,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_quote_capacity(
        store: IssuerStore,
        backend: Arc<B>,
        quote_ids: Arc<Q>,
        current_quote_key: QuoteSigningMaterialV1,
        retained_quote_keys: Vec<QuoteSigningMaterialV1>,
        receipt_keys: Vec<ReceiptSigningMaterialV1>,
        bat_keyring: Option<Arc<K256CashuMintKeyringV1>>,
        arc_keyring_experimental: Option<Arc<ArcSecretKeyringV1>>,
        credential_derivation_key: IssuerCredentialDerivationKeyV1,
        quote_capacity: QuoteCapacityV1,
        now_unix: u64,
    ) -> Result<Self, IssuerServiceErrorV1> {
        if now_unix == 0 {
            return Err(IssuerServiceErrorV1::InvalidRequest);
        }
        let identity = store.identity().map_err(map_store_error)?;
        let mut delegation_digests = BTreeSet::new();
        let mut quote_key_ids = BTreeSet::new();
        let mut stream_epochs = BTreeSet::new();
        for (position, material) in std::iter::once(&current_quote_key)
            .chain(retained_quote_keys.iter())
            .enumerate()
        {
            let delegation = &material.delegation;
            if delegation.issuer_id != identity.issuer_id
                || delegation.network != identity.network
                || !delegation_digests.insert(material.delegation_digest)
                || !quote_key_ids.insert(delegation.quote_key_id)
                || !stream_epochs.insert((delegation.expected_payee_pubkey, delegation.key_epoch))
                || delegation
                    .verify_for(
                        &identity.issuer_id,
                        identity.network,
                        &delegation.expected_payee_pubkey,
                        delegation.key_epoch,
                        delegation.not_before,
                    )
                    .is_err()
                || (position == 0
                    && delegation
                        .verify_for(
                            &identity.issuer_id,
                            identity.network,
                            &delegation.expected_payee_pubkey,
                            delegation.key_epoch,
                            now_unix,
                        )
                        .is_err())
                || (position != 0
                    && (delegation.issuer_verifying_key
                        != current_quote_key.delegation.issuer_verifying_key
                        || delegation.expected_payee_pubkey
                            != current_quote_key.delegation.expected_payee_pubkey
                        || delegation.key_epoch >= current_quote_key.delegation.key_epoch))
            {
                return Err(IssuerServiceErrorV1::InvalidRequest);
            }
        }
        for required_digest in store
            .quote_delegation_digests_requiring_signing_material(now_unix)
            .map_err(map_store_error)?
        {
            if !delegation_digests.contains(&required_digest) {
                return Err(IssuerServiceErrorV1::InvalidRequest);
            }
        }
        for record in store
            .service_policies_requiring_credential_material(now_unix)
            .map_err(map_store_error)?
        {
            let policy = decode_retained_policy(&record)?;
            ensure_policy_credential_material_v1(
                &policy,
                &identity.issuer_id,
                &receipt_keys,
                bat_keyring.as_deref(),
                arc_keyring_experimental.as_deref(),
            )?;
        }
        Ok(Self {
            core: Bolt11IssuerCoreV1::new_with_quote_capacity(
                store.clone(),
                backend,
                quote_ids,
                quote_capacity,
            )
            .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?,
            store,
            current_quote_key,
            retained_quote_keys,
            receipt_keys,
            bat_keyring,
            arc_keyring_experimental,
            credential_derivation_key,
        })
    }

    /// `POST /v1/quotes/bolt11` body handler.
    pub fn create_quote(
        &self,
        canonical_intent: &[u8],
        now_unix: u64,
    ) -> Result<Vec<u8>, IssuerServiceErrorV1> {
        let intent = Bolt11QuoteIntentV1::decode(canonical_intent)
            .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?;
        if intent
            .encode()
            .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?
            .as_slice()
            != canonical_intent
        {
            return Err(IssuerServiceErrorV1::InvalidRequest);
        }
        if let Some(existing) = self
            .store
            .quote_by_creation_idempotency_key(&intent.idempotency_key)
            .map_err(map_store_error)?
        {
            if existing.intent_digest
                != intent
                    .request_digest()
                    .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?
            {
                return Err(IssuerServiceErrorV1::Conflict);
            }
            let policy_record = self
                .store
                .service_policy(&intent.provider_id, &intent.policy_digest)
                .map_err(map_store_error)?
                .ok_or(IssuerServiceErrorV1::Internal)?;
            let policy = decode_retained_policy(&policy_record)?;
            let policy_key = decode_policy_key(&policy_record.policy_verifying_key)?;
            let reservation_time = existing
                .invoice_created_not_before
                .checked_add(INVOICE_CREATION_CLOCK_SKEW_SECONDS_V1)
                .ok_or(IssuerServiceErrorV1::Internal)?;
            if reservation_time.checked_add(INVOICE_CREATION_CLOCK_SKEW_SECONDS_V1)
                != Some(existing.invoice_created_not_after)
            {
                return Err(IssuerServiceErrorV1::Internal);
            }
            let verified_offer = policy
                .verify_historical_for_exact_quote_recovery(
                    &intent.provider_id,
                    &intent.policy_digest,
                    &intent.scope_id,
                    intent.offer_id,
                    reservation_time,
                    &policy_key,
                )
                .map_err(|_| IssuerServiceErrorV1::Unauthorized)?;
            self.ensure_offer_credential_material(verified_offer.offer())?;
            let delegation = Bolt11QuoteKeyDelegationV1::decode(&existing.exact_delegation)
                .map_err(|_| IssuerServiceErrorV1::Internal)?;
            let quote_material = self
                .quote_material(&existing.delegation_digest)
                .ok_or(IssuerServiceErrorV1::Internal)?;
            let delegation_guard = Bolt11QuoteKeyRollbackGuardV1::from_persisted(
                intent.issuer_id,
                intent.network,
                intent.expected_payee_pubkey,
                existing.delegation_epoch,
                existing.delegation_digest,
            )
            .map_err(|_| IssuerServiceErrorV1::Internal)?;
            let verified_intent = intent
                .verify_for_offer_guarded(
                    &verified_offer,
                    &delegation,
                    &delegation_guard,
                    reservation_time,
                )
                .map_err(|_| IssuerServiceErrorV1::Unauthorized)?;
            return self
                .core
                .create_or_recover_quote(&verified_intent, &quote_material.signing_key, now_unix)
                .map(|result| result.into_exact_signed_quote_response())
                .map_err(map_core_error);
        }
        let record = self
            .store
            .current_service_policy(&intent.provider_id)
            .map_err(map_store_error)?
            .ok_or(IssuerServiceErrorV1::Unauthorized)?;
        if record.policy_digest != intent.policy_digest {
            return Err(IssuerServiceErrorV1::Unauthorized);
        }
        let policy = decode_retained_policy(&record)?;
        let policy_key = decode_policy_key(&record.policy_verifying_key)?;
        let verified_policy = policy
            .verify_current_for_acquisition(
                &record.provider_id,
                now_unix,
                &PolicyRollbackGuardV1 {
                    highest_epoch: record.policy_epoch,
                    digest_at_highest_epoch: record.policy_digest,
                },
                &ServicePolicyEpochFloorsV1::initial(),
                &policy_key,
            )
            .map_err(|_| IssuerServiceErrorV1::Unauthorized)?;
        let verified_offer = verified_policy
            .offer(&intent.scope_id, intent.offer_id)
            .map_err(|_| IssuerServiceErrorV1::Unauthorized)?;
        self.ensure_offer_credential_material(verified_offer.offer())?;
        if intent.quote_delegation_digest != self.current_quote_key.delegation_digest {
            return Err(IssuerServiceErrorV1::Unauthorized);
        }
        let quote_material = self
            .quote_material(&intent.quote_delegation_digest)
            .ok_or(IssuerServiceErrorV1::Unauthorized)?;
        let delegation_guard = match self
            .store
            .delegation_head(&intent.expected_payee_pubkey)
            .map_err(map_store_error)?
        {
            Some(head) => Bolt11QuoteKeyRollbackGuardV1::from_persisted(
                intent.issuer_id,
                intent.network,
                intent.expected_payee_pubkey,
                head.highest_epoch,
                head.delegation_digest,
            ),
            None => Bolt11QuoteKeyRollbackGuardV1::initial(
                intent.issuer_id,
                intent.network,
                intent.expected_payee_pubkey,
            ),
        }
        .map_err(|_| IssuerServiceErrorV1::Unauthorized)?;
        let verified_intent = intent
            .verify_for_offer_guarded(
                &verified_offer,
                &quote_material.delegation,
                &delegation_guard,
                now_unix,
            )
            .map_err(|_| IssuerServiceErrorV1::Unauthorized)?;
        self.core
            .create_or_recover_quote(&verified_intent, &quote_material.signing_key, now_unix)
            .map(|result| result.into_exact_signed_quote_response())
            .map_err(map_core_error)
    }

    /// Reconcile one bounded cursor page without any browser status nonce.
    /// Individual backend failures are reduced to aggregate counters so no
    /// invoice, label, payment hash, or quote ID can reach logs.
    pub fn reconcile_quote_batch(
        &self,
        after_quote_id: Option<&[u8; 32]>,
        limit: u32,
        now_unix: u64,
    ) -> Result<IssuerReconciliationBatchV1, IssuerServiceErrorV1> {
        if now_unix == 0 {
            return Err(IssuerServiceErrorV1::InvalidRequest);
        }
        let candidates = self
            .store
            .quote_reconciliation_candidates_after(after_quote_id, limit, now_unix)
            .map_err(map_store_error)?;
        let mut report = IssuerReconciliationBatchV1 {
            next_cursor: None,
            examined: 0,
            transitioned: 0,
            unchanged: 0,
            retryable_failures: 0,
            permanent_failures: 0,
        };
        for candidate in &candidates {
            report.examined = report.examined.saturating_add(1);
            let Some(material) = self.quote_material(candidate.delegation_digest()) else {
                report.permanent_failures = report.permanent_failures.saturating_add(1);
                continue;
            };
            match self.core.reconcile_by_backend_label(
                candidate.backend_label(),
                &material.signing_key,
                now_unix,
            ) {
                Ok(result) => match result.disposition() {
                    QuoteReconcileDispositionV1::Transitioned => {
                        report.transitioned = report.transitioned.saturating_add(1)
                    }
                    QuoteReconcileDispositionV1::Unchanged => {
                        report.unchanged = report.unchanged.saturating_add(1)
                    }
                },
                Err(
                    IssuerCoreErrorV1::RetryableUnavailable
                    | IssuerCoreErrorV1::OutcomeUnknown
                    | IssuerCoreErrorV1::StoreUnanchored,
                ) => report.retryable_failures = report.retryable_failures.saturating_add(1),
                Err(_) => report.permanent_failures = report.permanent_failures.saturating_add(1),
            }
        }
        if candidates.len() == limit as usize {
            report.next_cursor = candidates.last().map(|candidate| *candidate.quote_id());
        }
        Ok(report)
    }

    /// `POST /v1/quotes/{quote_id}/status` body handler. The URL id is checked
    /// before the fresh signed nonce is durably consumed.
    pub fn quote_status(
        &self,
        route_quote_id: &[u8; 32],
        canonical_request: &[u8],
        now_unix: u64,
    ) -> Result<Vec<u8>, IssuerServiceErrorV1> {
        let request = Bolt11QuoteStatusRequestV1::decode(canonical_request)
            .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?;
        if &request.quote_id != route_quote_id
            || request
                .encode()
                .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?
                .as_slice()
                != canonical_request
        {
            return Err(IssuerServiceErrorV1::InvalidRequest);
        }
        let bip340 = K256Bip340PrehashVerifierV1;
        let authenticated = self
            .store
            .consume_quote_status_request(&request, now_unix, &|input: QuoteStatusBip340Input<
                '_,
            >| {
                bip340
                    .verify(
                        input.claim_pubkey_xonly,
                        input.message_digest,
                        input.signature,
                    )
                    .is_ok()
            })
            .map_err(map_store_error)?
            .value;
        if authenticated.state == QuoteState::CredentialClaimed {
            return Ok(authenticated.exact_signed_quote_response);
        }
        let record = self
            .store
            .quote(route_quote_id)
            .map_err(map_store_error)?
            .ok_or(IssuerServiceErrorV1::NotFound)?;
        let quote_material = self
            .quote_material(&record.delegation_digest)
            .ok_or(IssuerServiceErrorV1::Internal)?;
        self.core
            .reconcile_by_backend_label(
                &record.backend_label,
                &quote_material.signing_key,
                now_unix,
            )
            .map(|result| result.into_exact_signed_quote_response())
            .map_err(map_core_error)
    }

    /// `POST /v1/quotes/{quote_id}/claim` body handler.
    pub fn claim_quote(
        &self,
        route_quote_id: &[u8; 32],
        canonical_envelope: &[u8],
        now_unix: u64,
    ) -> Result<Vec<u8>, IssuerServiceErrorV1> {
        let arc_codec = ArcIssuanceCanonicalizerV1;
        let envelope = Bolt11QuoteClaimEnvelopeV1::decode(canonical_envelope, Some(&arc_codec))
            .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?;
        if &envelope.claim.quote_id != route_quote_id {
            return Err(IssuerServiceErrorV1::InvalidRequest);
        }
        let arc_for_store = (envelope.credential_request.authorization
            == AuthScheme::ArcV1Experimental)
            .then_some(&arc_codec as &dyn pir_service_protocol::ArcIssuanceCanonicalizerV1);

        // Exact committed recovery is authenticated by record_claim's
        // idempotency/request replay comparison and does not require a live
        // signer, policy window, or Lightning lookup.
        if let Some(existing) = self
            .store
            .claim_by_idempotency_key(&envelope.claim.idempotency_key)
            .map_err(map_store_error)?
        {
            let claim_write = ClaimWrite {
                quote_id: envelope.claim.quote_id,
                claim_idempotency_key: envelope.claim.idempotency_key,
                claim_request_digest: envelope
                    .claim
                    .claim_request_digest()
                    .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?,
                exact_claim_request: envelope
                    .claim
                    .encode()
                    .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?,
                exact_credential_request: envelope
                    .credential_request
                    .encode()
                    .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?,
                exact_claim_response: existing.exact_claim_response.clone(),
                exact_signed_quote_response: existing.exact_signed_quote_response.clone(),
                now_unix,
            };
            let replay = self
                .store
                .record_claim(
                    &claim_write,
                    &|_: ClaimCryptographicVerificationInput<'_>| false,
                    arc_for_store,
                )
                .map_err(map_store_error)?;
            return Ok(replay.value.exact_claim_response);
        }

        let quote_record = self
            .store
            .quote(route_quote_id)
            .map_err(map_store_error)?
            .ok_or(IssuerServiceErrorV1::NotFound)?;
        if envelope
            .quote_intent
            .request_digest()
            .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?
            != quote_record.intent_digest
        {
            return Err(IssuerServiceErrorV1::Unauthorized);
        }
        let policy_record = self
            .store
            .service_policy(
                &envelope.quote_intent.provider_id,
                &envelope.quote_intent.policy_digest,
            )
            .map_err(map_store_error)?
            .ok_or(IssuerServiceErrorV1::Unauthorized)?;
        let policy = decode_retained_policy(&policy_record)?;
        let policy_key = decode_policy_key(&policy_record.policy_verifying_key)?;
        let verified_offer = policy
            .verify_retired_for_redemption(
                &envelope.quote_intent.provider_id,
                &envelope.quote_intent.policy_digest,
                &envelope.quote_intent.scope_id,
                envelope.quote_intent.offer_id,
                now_unix,
                &policy_key,
            )
            .map_err(|_| IssuerServiceErrorV1::Unauthorized)?;
        let binding = verified_offer
            .offer()
            .credential_binding
            .as_ref()
            .ok_or(IssuerServiceErrorV1::Unauthorized)?;
        let delegation = Bolt11QuoteKeyDelegationV1::decode(&quote_record.exact_delegation)
            .map_err(|_| IssuerServiceErrorV1::Internal)?;
        let quote_material = self
            .quote_material(&quote_record.delegation_digest)
            .ok_or(IssuerServiceErrorV1::Internal)?;
        let invoice = quote_record
            .invoice
            .as_deref()
            .ok_or(IssuerServiceErrorV1::Internal)?;
        let parsed_invoice =
            ParsedBolt11InvoiceV1::parse(invoice).map_err(|_| IssuerServiceErrorV1::Internal)?;
        let exact_settled = quote_record
            .settled_signed_quote_response
            .as_deref()
            .ok_or(IssuerServiceErrorV1::Conflict)?;
        let quote =
            Bolt11QuoteV1::decode(exact_settled).map_err(|_| IssuerServiceErrorV1::Internal)?;
        if !matches!(
            quote.status,
            Bolt11QuoteStatusV1::PaymentSettled | Bolt11QuoteStatusV1::LateSettledReconcile
        ) {
            return Err(IssuerServiceErrorV1::Conflict);
        }
        // Quote lifecycle timestamps are whole seconds.  If the settled
        // lifecycle transition has this same timestamp, a CredentialClaimed
        // successor cannot yet satisfy the strict monotonic-time invariant. The
        // exact claim body is already replay-stable, so tell the client to
        // retry instead of misclassifying this normal clock boundary as an
        // internal error.
        if now_unix <= quote.status_updated_at {
            return Err(IssuerServiceErrorV1::RetryableUnavailable);
        }
        let delegation_guard = Bolt11QuoteKeyRollbackGuardV1::from_persisted(
            envelope.quote_intent.issuer_id,
            envelope.quote_intent.network,
            envelope.quote_intent.expected_payee_pubkey,
            delegation.key_epoch,
            quote_record.delegation_digest,
        )
        .map_err(|_| IssuerServiceErrorV1::Internal)?;
        envelope
            .quote_intent
            .verify_for_offer_guarded(
                &verified_offer,
                &delegation,
                &delegation_guard,
                quote.invoice_created_at,
            )
            .map_err(|_| IssuerServiceErrorV1::Unauthorized)?;
        let verified_quote = quote
            .verify_for_claim_submission(
                &envelope.quote_intent,
                &delegation,
                &parsed_invoice,
                now_unix,
            )
            .map_err(|_| IssuerServiceErrorV1::Unauthorized)?;
        let prepared = self.prepare_credential(&envelope, &verified_quote, binding, now_unix)?;
        let exact_response = prepared
            .encode_response()
            .map_err(|_| IssuerServiceErrorV1::Internal)?;
        let claimed_quote = Bolt11QuoteV1::with_status_from_verified_snapshot(
            &verified_quote,
            Bolt11QuoteStatusV1::CredentialClaimed,
            now_unix,
            &delegation,
            &quote_material.signing_key,
        )
        .map_err(|_| IssuerServiceErrorV1::Internal)?
        .encode()
        .map_err(|_| IssuerServiceErrorV1::Internal)?;
        let exact_claim = envelope
            .claim
            .encode()
            .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?;
        let exact_request = envelope
            .credential_request
            .encode()
            .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?;
        let expected_bip340_digest = *prepared.verified_claim().bip340_message_digest();
        let expected_response = prepared.response().clone();
        let verifier = |input: ClaimCryptographicVerificationInput<'_>| {
            input.bip340_message_digest == &expected_bip340_digest
                && input.issuance_response == &expected_response
                && input.claim == &envelope.claim
                && input.issuance_request == &envelope.credential_request
        };
        let write = self
            .store
            .record_claim(
                &ClaimWrite {
                    quote_id: envelope.claim.quote_id,
                    claim_idempotency_key: envelope.claim.idempotency_key,
                    claim_request_digest: envelope
                        .claim
                        .claim_request_digest()
                        .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?,
                    exact_claim_request: exact_claim,
                    exact_credential_request: exact_request,
                    exact_claim_response: exact_response,
                    exact_signed_quote_response: claimed_quote,
                    now_unix,
                },
                &verifier,
                arc_for_store,
            )
            .map_err(map_store_error)?;
        Ok(write.value.exact_claim_response)
    }

    fn prepare_credential(
        &self,
        envelope: &Bolt11QuoteClaimEnvelopeV1,
        verified_quote: &pir_service_protocol::VerifiedBolt11QuoteV1<'_>,
        binding: &pir_service_protocol::CredentialKeyBindingV1,
        now_unix: u64,
    ) -> Result<PreparedCredentialIssuanceV1, IssuerServiceErrorV1> {
        match envelope.credential_request.authorization {
            AuthScheme::Bolt11DirectReceiptV1 => {
                let verification_key: [u8; 32] = binding
                    .claims
                    .verification_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| IssuerServiceErrorV1::Unauthorized)?;
                let key = self
                    .receipt_keys
                    .iter()
                    .find(|key| key.signing_key.verifying_key().to_bytes() == verification_key)
                    .ok_or(IssuerServiceErrorV1::Internal)?;
                prepare_direct_receipt_issuance_v1(
                    &envelope.credential_request,
                    &envelope.claim,
                    verified_quote,
                    binding,
                    &key.signing_key,
                    &self.credential_derivation_key,
                    now_unix,
                )
                .map_err(|_| IssuerServiceErrorV1::Unauthorized)
            }
            AuthScheme::BitcoinPirCashuBatV1 => prepare_cashu_bat_issuance_v1(
                &envelope.credential_request,
                &envelope.claim,
                verified_quote,
                binding,
                self.bat_keyring
                    .as_ref()
                    .ok_or(IssuerServiceErrorV1::Internal)?,
                &self.credential_derivation_key,
                now_unix,
            )
            .map_err(|_| IssuerServiceErrorV1::Unauthorized),
            AuthScheme::ArcV1Experimental => prepare_arc_issuance_v1(
                &envelope.credential_request,
                &envelope.claim,
                verified_quote,
                binding,
                self.arc_keyring_experimental
                    .as_ref()
                    .ok_or(IssuerServiceErrorV1::Internal)?,
                &self.credential_derivation_key,
                now_unix,
            )
            .map_err(|_| IssuerServiceErrorV1::Unauthorized),
            AuthScheme::BitcoinPirCashuBatV2 => Err(IssuerServiceErrorV1::InvalidRequest),
            AuthScheme::FreeV1 | AuthScheme::CashuEcashV1 => {
                Err(IssuerServiceErrorV1::InvalidRequest)
            }
        }
    }

    fn quote_material(&self, digest: &[u8; 32]) -> Option<&QuoteSigningMaterialV1> {
        std::iter::once(&self.current_quote_key)
            .chain(self.retained_quote_keys.iter())
            .find(|material| &material.delegation_digest == digest)
    }

    fn ensure_offer_credential_material(
        &self,
        offer: &pir_service_protocol::ServiceOfferV1,
    ) -> Result<(), IssuerServiceErrorV1> {
        let identity = self.store.identity().map_err(map_store_error)?;
        ensure_offer_credential_material_v1(
            offer,
            &identity.issuer_id,
            &self.receipt_keys,
            self.bat_keyring.as_deref(),
            self.arc_keyring_experimental.as_deref(),
        )
    }
}

/// Verifies that an exact issuer-retained shared-clearing binding still has
/// its matching online BAT or experimental ARC private material. Expired
/// bindings remain auditable through the store lineage but deliberately do
/// not pin obsolete private keys online forever.
pub fn ensure_shared_clearing_binding_material_v1(
    binding: &pir_service_protocol::CredentialKeyBindingV1,
    now_unix: u64,
    bat_keyring: Option<&K256CashuMintKeyringV1>,
    arc_keyring: Option<&ArcSecretKeyringV1>,
) -> Result<(), IssuerServiceErrorV1> {
    if now_unix == 0 {
        return Err(IssuerServiceErrorV1::InvalidRequest);
    }
    if now_unix > binding.claims.not_after {
        return Ok(());
    }
    let covered = match binding.claims.scheme {
        AuthScheme::FreeV1 => true,
        AuthScheme::BitcoinPirCashuBatV1 => binding
            .claims
            .verification_key
            .as_slice()
            .try_into()
            .ok()
            .is_some_and(|expected: [u8; 33]| {
                bat_keyring.is_some_and(|keys| keys.denomination_public_keys().contains(&expected))
            }),
        AuthScheme::ArcV1Experimental => arc_keyring.is_some_and(|keys| {
            keys.contains_credential_key(
                &binding.claims.credential_key_id,
                &binding.claims.verification_key,
            )
        }),
        AuthScheme::BitcoinPirCashuBatV2 => false,
        AuthScheme::Bolt11DirectReceiptV1 | AuthScheme::CashuEcashV1 => false,
    };
    if covered {
        Ok(())
    } else {
        Err(IssuerServiceErrorV1::InvalidRequest)
    }
}

fn ensure_policy_credential_material_v1(
    policy: &ServicePolicyV1,
    issuer_id: &[u8; 32],
    receipt_keys: &[ReceiptSigningMaterialV1],
    bat_keyring: Option<&K256CashuMintKeyringV1>,
    arc_keyring: Option<&ArcSecretKeyringV1>,
) -> Result<(), IssuerServiceErrorV1> {
    for scope in &policy.scopes {
        for offer in &scope.offers {
            ensure_offer_credential_material_v1(
                offer,
                issuer_id,
                receipt_keys,
                bat_keyring,
                arc_keyring,
            )?;
        }
    }
    Ok(())
}

fn ensure_offer_credential_material_v1(
    offer: &pir_service_protocol::ServiceOfferV1,
    issuer_id: &[u8; 32],
    receipt_keys: &[ReceiptSigningMaterialV1],
    bat_keyring: Option<&K256CashuMintKeyringV1>,
    arc_keyring: Option<&ArcSecretKeyringV1>,
) -> Result<(), IssuerServiceErrorV1> {
    // Free and standard Cashu acquisition never ask this issuer to create a
    // BOLT11 invoice or mint the provider authorization capability.
    if offer.acquisition != AcquisitionMethod::Bolt11V1 || &offer.issuer_id != issuer_id {
        return Ok(());
    }
    if offer.authorization == AuthScheme::BitcoinPirCashuBatV2 {
        return Err(IssuerServiceErrorV1::InvalidRequest);
    }
    let binding = offer
        .credential_binding
        .as_ref()
        .ok_or(IssuerServiceErrorV1::InvalidRequest)?;
    let covered = match offer.authorization {
        AuthScheme::Bolt11DirectReceiptV1 => binding
            .claims
            .verification_key
            .as_slice()
            .try_into()
            .ok()
            .is_some_and(|expected: [u8; 32]| {
                receipt_keys
                    .iter()
                    .any(|key| key.signing_key.verifying_key().to_bytes() == expected)
            }),
        AuthScheme::BitcoinPirCashuBatV1 => binding
            .claims
            .verification_key
            .as_slice()
            .try_into()
            .ok()
            .is_some_and(|expected: [u8; 33]| {
                bat_keyring.is_some_and(|keys| keys.denomination_public_keys().contains(&expected))
            }),
        AuthScheme::ArcV1Experimental => arc_keyring.is_some_and(|keys| {
            keys.contains_credential_key(
                &binding.claims.credential_key_id,
                &binding.claims.verification_key,
            )
        }),
        AuthScheme::BitcoinPirCashuBatV2 => false,
        AuthScheme::FreeV1 | AuthScheme::CashuEcashV1 => false,
    };
    if covered {
        Ok(())
    } else {
        Err(IssuerServiceErrorV1::InvalidRequest)
    }
}

#[cfg(test)]
mod credential_material_tests_v1 {
    use super::*;
    use pir_arc_adapter::{ArcSecretKeyV1, ARC_SECRET_KEY_LEN_V1};
    use pir_service_protocol::{
        CredentialKeyBindingClaimsV1, CredentialKeyBindingV1, CredentialUnitV1, DeploymentStatus,
        FreeModeV1, PriceV1, PrivacyLeakageV1, ServiceOfferV1, VerificationMode,
    };
    use zeroize::Zeroizing;

    const ISSUER_ID: [u8; 32] = [0x51; 32];

    fn scalar_bytes(multiplier: u8) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[31] = multiplier;
        bytes
    }

    fn offer(scheme: AuthScheme, key_id: Vec<u8>, verification_key: Vec<u8>) -> ServiceOfferV1 {
        let presentation_limit = if scheme == AuthScheme::ArcV1Experimental {
            2
        } else {
            1
        };
        ServiceOfferV1 {
            offer_id: 1,
            acquisition: AcquisitionMethod::Bolt11V1,
            free_mode: FreeModeV1::NotFree,
            free_quota: 0,
            free_window_seconds: 0,
            free_pow_difficulty_bits: 0,
            priority_class: 1,
            authorization: scheme,
            verification: VerificationMode::ProviderLocal,
            deployment_status: if scheme == AuthScheme::ArcV1Experimental {
                DeploymentStatus::Experimental
            } else {
                DeploymentStatus::Stable
            },
            price: PriceV1::MilliSatoshi(1_000),
            issuer_id: ISSUER_ID,
            key_id: key_id.clone(),
            credential_binding: Some(CredentialKeyBindingV1 {
                issuer_id: ISSUER_ID,
                issuer_verifying_key: [0x52; 32],
                claims: CredentialKeyBindingClaimsV1 {
                    provider_id: [0x53; 32],
                    scope_id: [0x54; 32],
                    offer_id: 1,
                    scheme,
                    keyset_epoch: 1,
                    entitlement_profile: 1,
                    unit: CredentialUnitV1::Auth,
                    amount: 1,
                    presentation_limit,
                    not_before: 1,
                    not_after: 10_000,
                    credential_key_id: key_id,
                    verification_key,
                },
                signature: [0x55; 64],
            }),
            cashu_mint_manifest: None,
            endpoint: "https://issuer.invalid".to_owned(),
            invoice_expiry_seconds: 60,
            claim_window_seconds: 120,
            minimum_credential_validity_seconds: 300,
            retired_policy_grace_seconds: 480,
            credential_count: 1,
            credential_presentation_limit: presentation_limit,
            privacy_leakage: PrivacyLeakageV1::NONE,
        }
    }

    #[test]
    fn direct_receipt_material_must_be_present_and_match_public_binding() {
        let correct = SigningKey::from_bytes(&[0x61; 32]);
        let wrong = SigningKey::from_bytes(&[0x62; 32]);
        let offer = offer(
            AuthScheme::Bolt11DirectReceiptV1,
            vec![1; 16],
            correct.verifying_key().to_bytes().to_vec(),
        );
        assert!(ensure_offer_credential_material_v1(&offer, &ISSUER_ID, &[], None, None).is_err());
        assert!(ensure_offer_credential_material_v1(
            &offer,
            &ISSUER_ID,
            &[ReceiptSigningMaterialV1::new(wrong)],
            None,
            None,
        )
        .is_err());
        assert!(ensure_offer_credential_material_v1(
            &offer,
            &ISSUER_ID,
            &[ReceiptSigningMaterialV1::new(correct)],
            None,
            None,
        )
        .is_ok());
    }

    #[test]
    fn bat_material_must_be_present_and_match_public_binding() {
        let correct = K256CashuMintKeyringV1::from_secret_keys([scalar_bytes(11)]).unwrap();
        let wrong = K256CashuMintKeyringV1::from_secret_keys([scalar_bytes(12)]).unwrap();
        let public = correct.denomination_public_keys()[0];
        let offer = offer(
            AuthScheme::BitcoinPirCashuBatV1,
            vec![2; 32],
            public.to_vec(),
        );
        assert!(ensure_offer_credential_material_v1(&offer, &ISSUER_ID, &[], None, None).is_err());
        assert!(
            ensure_offer_credential_material_v1(&offer, &ISSUER_ID, &[], Some(&wrong), None,)
                .is_err()
        );
        assert!(
            ensure_offer_credential_material_v1(&offer, &ISSUER_ID, &[], Some(&correct), None,)
                .is_ok()
        );
    }

    fn arc_key(fill: u8, key_id: Vec<u8>) -> ArcSecretKeyV1 {
        ArcSecretKeyV1::from_zeroizing_bytes(key_id, Zeroizing::new([fill; ARC_SECRET_KEY_LEN_V1]))
            .expect("test ARC scalar encoding")
    }

    #[test]
    fn experimental_arc_material_must_be_present_and_match_public_binding() {
        let key_id = vec![3; 16];
        let correct_key = arc_key(1, key_id.clone());
        let public = correct_key.public_key_bytes().to_vec();
        let correct = ArcSecretKeyringV1::new(vec![correct_key]).unwrap();
        let wrong = ArcSecretKeyringV1::new(vec![arc_key(2, key_id.clone())]).unwrap();
        let offer = offer(AuthScheme::ArcV1Experimental, key_id, public);
        assert!(ensure_offer_credential_material_v1(&offer, &ISSUER_ID, &[], None, None).is_err());
        assert!(
            ensure_offer_credential_material_v1(&offer, &ISSUER_ID, &[], None, Some(&wrong),)
                .is_err()
        );
        assert!(
            ensure_offer_credential_material_v1(&offer, &ISSUER_ID, &[], None, Some(&correct),)
                .is_ok()
        );
    }

    #[test]
    fn standard_cashu_does_not_require_issuer_credential_private_material() {
        let mut offer = offer(AuthScheme::BitcoinPirCashuBatV1, vec![4; 32], vec![5; 33]);
        offer.acquisition = AcquisitionMethod::CashuEcashV1;
        offer.authorization = AuthScheme::CashuEcashV1;
        assert!(ensure_offer_credential_material_v1(&offer, &ISSUER_ID, &[], None, None).is_ok());
    }
}

/// Issuer-local trust root for one participating provider. This is configured
/// out of band and is never inferred from a redeem request.
#[derive(Clone)]
pub struct TrustedClearingProviderV1 {
    pub provider_id: [u8; 32],
    pub operator_key: VerifyingKey,
    pub minimum_authorization_epoch: u64,
}

/// Operator-selected commercial policy for provider payouts. It is kept out
/// of signed credential and PIR authorization semantics: changing this value
/// changes only newly issued payout intents, never ticket value or query
/// entitlement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SettlementPayoutPolicyV1 {
    pub issuer_fee: u64,
    pub intent_ttl_seconds: u64,
}

/// Schema filler used when a provider registration belongs to a ledger-only
/// issuer. This is SHA-256 of the ASCII domain
/// `BitcoinPIR/issuer-service/v1/ledger-only-disabled-payout-target`.
///
/// The first byte is deliberately non-zero because the V1 store schema rejects
/// an all-zero payout target. Production code installs this value directly; it
/// is not accepted from an HTTP request or command-line option. It is not a
/// payout destination and must never be interpreted as one.
pub const LEDGER_ONLY_DISABLED_PAYOUT_TARGET_ID_V1: [u8; 32] = [
    0x85, 0x28, 0x4b, 0xc7, 0xed, 0xff, 0x9a, 0x30, 0x2f, 0xfb, 0x2c, 0xf6, 0x2c, 0xdb, 0x82, 0xe8,
    0x7d, 0x14, 0x6b, 0xe3, 0x77, 0xa0, 0x7e, 0x2b, 0x60, 0xd7, 0xb3, 0x90, 0xfc, 0xa2, 0x53, 0x73,
];

impl SettlementPayoutPolicyV1 {
    pub fn new(issuer_fee: u64, intent_ttl_seconds: u64) -> Result<Self, IssuerServiceErrorV1> {
        if issuer_fee > MAX_SERVICE_VALUE_V1 || !(1..=86_400).contains(&intent_ttl_seconds) {
            return Err(IssuerServiceErrorV1::InvalidRequest);
        }
        Ok(Self {
            issuer_fee,
            intent_ttl_seconds,
        })
    }
}

impl fmt::Debug for TrustedClearingProviderV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedClearingProviderV1")
            .field("provider_id", &self.provider_id)
            .field(
                "minimum_authorization_epoch",
                &self.minimum_authorization_epoch,
            )
            .finish_non_exhaustive()
    }
}

/// Shared-issuer online redemption. It has one issuer-global spent set and
/// ledger, but no peer-provider or PIR-query input.
pub struct SharedIssuerClearingServiceV1 {
    store: IssuerStore,
    providers: Vec<TrustedClearingProviderV1>,
    bat_keyring: Option<Arc<K256CashuMintKeyringV1>>,
    arc_keyring_experimental: Option<Arc<ArcSecretKeyringV1>>,
    issuer_settlement_signing_key: SigningKey,
    retained_issuer_settlement_keys: Vec<VerifyingKey>,
    settlement_keyring: Option<Arc<K256CashuMintKeyringV1>>,
    retained_settlement_keysets: Vec<CashuKeysetBindingV1>,
    response_derivation_key: RedeemResponseDerivationKeyV1,
    payout_policy: Option<SettlementPayoutPolicyV1>,
}

struct LoadedClearingContextV1 {
    authorization: ProviderClearingAuthorizationV1,
    approval: IssuerClearingApprovalV1,
    operator_key: VerifyingKey,
    minimum_authorization_epoch: u64,
    registration: ProviderSettlementRegistrationRecordV1,
}

impl fmt::Debug for SharedIssuerClearingServiceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedIssuerClearingServiceV1")
            .field("store", &"[redacted]")
            .field("provider_count", &self.providers.len())
            .field("bat", &self.bat_keyring.is_some())
            .field("arc_experimental", &self.arc_keyring_experimental.is_some())
            .field(
                "settlement_keyset_count",
                &self.retained_settlement_keysets.len(),
            )
            .field(
                "retained_settlement_signing_key_count",
                &self.retained_issuer_settlement_keys.len(),
            )
            .field("ledger_only", &self.payout_policy.is_none())
            .finish_non_exhaustive()
    }
}

impl SharedIssuerClearingServiceV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: IssuerStore,
        providers: Vec<TrustedClearingProviderV1>,
        bat_keyring: Option<Arc<K256CashuMintKeyringV1>>,
        arc_keyring_experimental: Option<Arc<ArcSecretKeyringV1>>,
        issuer_settlement_signing_key: SigningKey,
        retained_issuer_settlement_keys: Vec<VerifyingKey>,
        settlement_keyring: Option<Arc<K256CashuMintKeyringV1>>,
        retained_settlement_keysets: Vec<CashuKeysetBindingV1>,
        response_derivation_key: RedeemResponseDerivationKeyV1,
        payout_policy: SettlementPayoutPolicyV1,
    ) -> Result<Self, IssuerServiceErrorV1> {
        Self::new_with_payout_mode(
            store,
            providers,
            bat_keyring,
            arc_keyring_experimental,
            issuer_settlement_signing_key,
            retained_issuer_settlement_keys,
            settlement_keyring,
            retained_settlement_keysets,
            response_derivation_key,
            Some(payout_policy),
        )
    }

    /// Builds the production V1 ledger-accrual service. Payout intent,
    /// execution and status methods are disabled and return `NotFound` before
    /// decoding input or reading/mutating the store.
    #[allow(clippy::too_many_arguments)]
    pub fn new_ledger_only(
        store: IssuerStore,
        providers: Vec<TrustedClearingProviderV1>,
        bat_keyring: Option<Arc<K256CashuMintKeyringV1>>,
        arc_keyring_experimental: Option<Arc<ArcSecretKeyringV1>>,
        issuer_settlement_signing_key: SigningKey,
        retained_issuer_settlement_keys: Vec<VerifyingKey>,
        settlement_keyring: Option<Arc<K256CashuMintKeyringV1>>,
        retained_settlement_keysets: Vec<CashuKeysetBindingV1>,
        response_derivation_key: RedeemResponseDerivationKeyV1,
    ) -> Result<Self, IssuerServiceErrorV1> {
        Self::new_with_payout_mode(
            store,
            providers,
            bat_keyring,
            arc_keyring_experimental,
            issuer_settlement_signing_key,
            retained_issuer_settlement_keys,
            settlement_keyring,
            retained_settlement_keysets,
            response_derivation_key,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_payout_mode(
        store: IssuerStore,
        mut providers: Vec<TrustedClearingProviderV1>,
        bat_keyring: Option<Arc<K256CashuMintKeyringV1>>,
        arc_keyring_experimental: Option<Arc<ArcSecretKeyringV1>>,
        issuer_settlement_signing_key: SigningKey,
        retained_issuer_settlement_keys: Vec<VerifyingKey>,
        settlement_keyring: Option<Arc<K256CashuMintKeyringV1>>,
        retained_settlement_keysets: Vec<CashuKeysetBindingV1>,
        response_derivation_key: RedeemResponseDerivationKeyV1,
        payout_policy: Option<SettlementPayoutPolicyV1>,
    ) -> Result<Self, IssuerServiceErrorV1> {
        providers.sort_by_key(|provider| provider.provider_id);
        if providers.is_empty()
            || providers.iter().any(|provider| {
                provider.provider_id.iter().all(|byte| *byte == 0)
                    || provider.minimum_authorization_epoch == 0
            })
            || providers
                .windows(2)
                .any(|pair| pair[0].provider_id == pair[1].provider_id)
        {
            return Err(IssuerServiceErrorV1::InvalidRequest);
        }
        let current_settlement_key = issuer_settlement_signing_key.verifying_key();
        let mut retained_key_bytes = BTreeSet::new();
        if retained_issuer_settlement_keys.iter().any(|key| {
            key.to_bytes() == current_settlement_key.to_bytes()
                || !retained_key_bytes.insert(key.to_bytes())
        }) {
            return Err(IssuerServiceErrorV1::InvalidRequest);
        }
        Ok(Self {
            store,
            providers,
            bat_keyring,
            arc_keyring_experimental,
            issuer_settlement_signing_key,
            retained_issuer_settlement_keys,
            settlement_keyring,
            retained_settlement_keysets,
            response_derivation_key,
            payout_policy,
        })
    }

    pub const fn is_ledger_only(&self) -> bool {
        self.payout_policy.is_none()
    }

    /// `POST /v1/redeems` body handler. A committed exact replay authenticates
    /// the provider signature but does not spend or credit twice.
    pub fn redeem(
        &self,
        canonical_envelope: &[u8],
        now_unix: u64,
    ) -> Result<Vec<u8>, IssuerServiceErrorV1> {
        let envelope = ProviderRedeemEnvelopeV1::decode(canonical_envelope)
            .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?;
        let exact_reencoding = Zeroizing::new(
            envelope
                .encode()
                .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?,
        );
        if exact_reencoding.as_slice() != canonical_envelope {
            return Err(IssuerServiceErrorV1::InvalidRequest);
        }
        let provider = self
            .providers
            .binary_search_by_key(&envelope.request.provider_id, |provider| {
                provider.provider_id
            })
            .ok()
            .map(|index| &self.providers[index])
            .ok_or(IssuerServiceErrorV1::Unauthorized)?;
        let identity = self.store.identity().map_err(map_store_error)?;
        if envelope.request.issuer_id != identity.issuer_id {
            return Err(IssuerServiceErrorV1::Unauthorized);
        }
        let authorization_record = self
            .store
            .clearing_authorization(&envelope.request.authorization_digest)
            .map_err(map_store_error)?
            .ok_or(IssuerServiceErrorV1::Unauthorized)?;
        let authorization =
            ProviderClearingAuthorizationV1::decode(&authorization_record.exact_authorization)
                .map_err(|_| IssuerServiceErrorV1::Internal)?;
        let approval = IssuerClearingApprovalV1::decode(&authorization_record.exact_approval)
            .map_err(|_| IssuerServiceErrorV1::Internal)?;
        let settlement_verifying_key = self.issuer_settlement_signing_key.verifying_key();

        if let Some(existing) = self
            .store
            .redeem_by_idempotency(&envelope.request)
            .map_err(map_store_error)?
        {
            // The issuer approval countersigned the exact historical
            // authorization, including this operator key.  Exact committed
            // replay must therefore authenticate with that retained key,
            // rather than the provider's current rotation key; otherwise a
            // routine key rotation would destroy recovery of a response whose
            // debit and credit are already durable.
            let historical_operator_key =
                VerifyingKey::from_bytes(&authorization.operator_verifying_key)
                    .map_err(|_| IssuerServiceErrorV1::Internal)?;
            let keyring =
                self.issuer_settlement_keyring(&identity.issuer_id, &settlement_verifying_key);
            let historical_approval_key = keyring
                .resolve_for_issuer(&identity.issuer_id, &approval.issuer_settlement_key_id)
                .map_err(|_| IssuerServiceErrorV1::Internal)?;
            verify_committed_redeem_replay_auth_v1(
                &envelope.request,
                &authorization,
                &approval,
                &envelope.request_auth,
                &CommittedRedeemReplayExpectationV1 {
                    provider_id: &provider.provider_id,
                    issuer_id: &identity.issuer_id,
                    operator_key: &historical_operator_key,
                    issuer_settlement_key: historical_approval_key,
                },
            )
            .map_err(|_| IssuerServiceErrorV1::Unauthorized)?;
            let response =
                pir_service_protocol::ProviderRedeemResponseV1::decode(&existing.exact_response)
                    .map_err(|_| IssuerServiceErrorV1::Internal)?;
            let historical_response_key = keyring
                .resolve_for_issuer(&identity.issuer_id, &response.issuer_settlement_key_id)
                .map_err(|_| IssuerServiceErrorV1::Internal)?;
            self.verify_redeem_response(
                &response,
                &envelope.request,
                &authorization,
                historical_response_key,
                now_unix,
            )?;
            return Ok(existing.exact_response);
        }

        let expectation = ProviderClearingExpectationV1 {
            provider_id: &provider.provider_id,
            issuer_id: &identity.issuer_id,
            operator_key: &provider.operator_key,
            issuer_settlement_key: &settlement_verifying_key,
            now_unix,
            minimum_authorization_epoch: provider.minimum_authorization_epoch,
        };
        let credential_verifier = SharedIssuerCredentialVerifierV1::new(
            self.bat_keyring.as_deref(),
            self.arc_keyring_experimental.as_deref(),
        );
        let verified_redeem = pir_issuer_store::verify_shared_issuer_redeem_v1(
            &envelope.request,
            &envelope.canonical_credential,
            &envelope.credential_binding,
            &authorization,
            &approval,
            &envelope.request_auth,
            &expectation,
            &credential_verifier,
        )
        .map_err(map_store_error)?;
        let response = prepare_redeem_response_v1(
            &verified_redeem,
            &self.issuer_settlement_signing_key,
            self.settlement_keyring.as_deref(),
            &self.response_derivation_key,
        )
        .map_err(|_| IssuerServiceErrorV1::Unauthorized)?;
        let verified_response = self.verify_redeem_response(
            &response,
            &envelope.request,
            &authorization,
            &settlement_verifying_key,
            now_unix,
        )?;
        let committed = self
            .store
            .commit_redeem(&VerifiedRedeemCommitV1 {
                redeem: verified_redeem,
                response: verified_response,
            })
            .map_err(map_store_error)?;
        Ok(committed.value.exact_response)
    }

    /// `POST /v1/settlement/balance` body handler. This is a live signed read;
    /// its request nonce is authenticated but not persisted as an economic
    /// idempotency key.
    pub fn balance(
        &self,
        canonical_envelope: &[u8],
        now_unix: u64,
    ) -> Result<Vec<u8>, IssuerServiceErrorV1> {
        let envelope = ProviderBalanceEnvelopeV1::decode(canonical_envelope)
            .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?;
        let context = self.load_clearing_context(
            &envelope.request.provider_id,
            &envelope.request.authorization_digest,
        )?;
        let settlement_key = self.issuer_settlement_signing_key.verifying_key();
        let expectation = self.clearing_expectation(&context, &settlement_key, now_unix);
        verify_new_balance_request_for(
            &envelope.request,
            &context.authorization,
            &context.approval,
            &envelope.request_auth,
            &expectation,
        )
        .map_err(|_| IssuerServiceErrorV1::Unauthorized)?;
        let balance = self
            .store
            .provider_ledger_balance(&envelope.request.provider_id)
            .map_err(map_store_error)?
            .ok_or(IssuerServiceErrorV1::NotFound)?;
        if balance.account_id != envelope.request.account_id
            || balance.unit != envelope.request.unit
        {
            return Err(IssuerServiceErrorV1::Unauthorized);
        }
        IssuerBalanceResponseV1::sign(
            IssuerBalanceResponseV1 {
                issuer_settlement_key_id: [0; 16],
                request_digest: envelope
                    .request
                    .request_digest()
                    .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?,
                authorization_digest: envelope.request.authorization_digest,
                issuer_id: envelope.request.issuer_id,
                provider_id: envelope.request.provider_id,
                account_id: envelope.request.account_id,
                unit: envelope.request.unit,
                available_value: balance.available_value,
                reserved_value: balance.reserved_value,
                ledger_sequence: balance.ledger_sequence,
                as_of_unix: now_unix,
                signature: [0; 64],
            },
            &self.issuer_settlement_signing_key,
        )
        .and_then(|response| response.encode())
        .map_err(|_| IssuerServiceErrorV1::Internal)
    }

    /// `POST /v1/settlement/payout-intents` body handler. Commercial fee and
    /// expiry policy are supplied by operator configuration and snapshotted in
    /// the signed, durably idempotent response.
    pub fn payout_intent(
        &self,
        canonical_envelope: &[u8],
        now_unix: u64,
    ) -> Result<Vec<u8>, IssuerServiceErrorV1> {
        let payout_policy = self.payout_policy.ok_or(IssuerServiceErrorV1::NotFound)?;
        let envelope = ProviderPayoutIntentEnvelopeV1::decode(canonical_envelope)
            .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?;
        let context = self.load_clearing_context(
            &envelope.request.provider_id,
            &envelope.request.authorization_digest,
        )?;
        let settlement_key = self.issuer_settlement_signing_key.verifying_key();
        let expectation = self.clearing_expectation(&context, &settlement_key, now_unix);
        if let Some(existing) = self
            .store
            .payout_intent_by_idempotency(&envelope.request)
            .map_err(map_store_error)?
        {
            self.verify_committed_clearing_auth(
                &envelope.request.authorization_digest,
                &envelope
                    .request
                    .request_digest()
                    .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?,
                &context,
                &envelope.request_auth,
            )?;
            let response = IssuerPayoutIntentResponseV1::decode(&existing.exact_response)
                .map_err(|_| IssuerServiceErrorV1::Internal)?;
            let keyring = self.issuer_settlement_keyring(
                &context.authorization.claims.issuer_id,
                &settlement_key,
            );
            let signing_key = keyring
                .resolve_for_issuer(
                    &envelope.request.issuer_id,
                    &response.issuer_settlement_key_id,
                )
                .map_err(|_| IssuerServiceErrorV1::Internal)?;
            response
                .verify_for_exact_request(&envelope.request, signing_key)
                .map_err(|_| IssuerServiceErrorV1::Internal)?;
            return Ok(existing.exact_response);
        }
        pir_service_protocol::verify_new_payout_intent_request_for(
            &envelope.request,
            &context.registration.payout_target_id,
            &context.authorization,
            &context.approval,
            &envelope.request_auth,
            &expectation,
        )
        .map_err(|_| IssuerServiceErrorV1::Unauthorized)?;
        let expires_at = now_unix
            .checked_add(payout_policy.intent_ttl_seconds)
            .ok_or(IssuerServiceErrorV1::InvalidRequest)?;
        let response = prepare_payout_intent_response_v1(
            &envelope.request,
            payout_policy.issuer_fee,
            expires_at,
            &self.issuer_settlement_signing_key,
        )
        .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?;
        match self.store.commit_payout_intent(
            &envelope.request,
            &response,
            &context.authorization,
            &context.approval,
            &envelope.request_auth,
            &expectation,
        ) {
            Ok(committed) => Ok(committed.value.exact_response),
            Err(StoreError::PayoutIntentIdempotencyConflict) => self
                .store
                .payout_intent_by_idempotency(&envelope.request)
                .map_err(map_store_error)?
                .map(|record| record.exact_response)
                .ok_or(IssuerServiceErrorV1::Conflict),
            Err(error) => Err(map_store_error(error)),
        }
    }

    /// `POST /v1/settlement/payouts` body handler. A success response cannot
    /// escape until intent consumption, balance reservation, payout record and
    /// outbox command commit atomically.
    pub fn payout(
        &self,
        canonical_envelope: &[u8],
        now_unix: u64,
    ) -> Result<Vec<u8>, IssuerServiceErrorV1> {
        if self.payout_policy.is_none() {
            return Err(IssuerServiceErrorV1::NotFound);
        }
        let envelope = ProviderPayoutEnvelopeV1::decode(canonical_envelope)
            .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?;
        let context = self.load_clearing_context(
            &envelope.request.provider_id,
            &envelope.request.authorization_digest,
        )?;
        let settlement_key = self.issuer_settlement_signing_key.verifying_key();
        let expectation = self.clearing_expectation(&context, &settlement_key, now_unix);
        let stored_intent = self
            .store
            .payout_intent_by_idempotency(&envelope.intent_request)
            .map_err(map_store_error)?
            .ok_or(IssuerServiceErrorV1::NotFound)?;
        if stored_intent.exact_response
            != envelope
                .intent_response
                .encode()
                .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?
        {
            return Err(IssuerServiceErrorV1::Conflict);
        }
        let payout_context = PayoutExecutionContextV1 {
            intent_request: &envelope.intent_request,
            intent_response: &envelope.intent_response,
            registered_payout_target_id: &context.registration.payout_target_id,
        };
        if let Some(existing) = self
            .store
            .payout_by_idempotency(&envelope.request)
            .map_err(map_store_error)?
        {
            self.verify_committed_clearing_auth(
                &envelope.request.authorization_digest,
                &envelope
                    .request
                    .request_digest()
                    .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?,
                &context,
                &envelope.request_auth,
            )?;
            let response = IssuerPayoutResponseV1::decode(&existing.exact_initial_response)
                .map_err(|_| IssuerServiceErrorV1::Internal)?;
            let keyring =
                self.issuer_settlement_keyring(&envelope.request.issuer_id, &settlement_key);
            verify_payout_initial_response_for_exact_request(
                &response,
                &envelope.request,
                &keyring,
            )
            .map_err(|_| IssuerServiceErrorV1::Internal)?;
            return Ok(existing.exact_initial_response);
        }
        let execution = verify_new_payout_request_for(
            &envelope.request,
            &payout_context,
            &context.authorization,
            &context.approval,
            &envelope.request_auth,
            &expectation,
        )
        .map_err(|_| IssuerServiceErrorV1::Unauthorized)?;
        let mut committer = self.store.payout_execution_committer(&settlement_key);
        match sign_and_commit_payout_execution_v1(
            &execution,
            now_unix,
            &self.issuer_settlement_signing_key,
            &mut committer,
        ) {
            Ok(response) => response
                .encode()
                .map_err(|_| IssuerServiceErrorV1::Internal),
            Err(PayoutCommitErrorV1::Conflict { .. }) => self
                .store
                .payout_by_idempotency(&envelope.request)
                .map_err(map_store_error)?
                .map(|record| record.exact_initial_response)
                .ok_or(IssuerServiceErrorV1::Conflict),
            Err(PayoutCommitErrorV1::Store(error)) => Err(map_store_error(error)),
            Err(PayoutCommitErrorV1::Protocol(_)) => Err(IssuerServiceErrorV1::InvalidRequest),
        }
    }

    /// `POST /v1/settlement/payout-status` body handler. Exact retries return
    /// the already committed response and may use the request's retained
    /// provider registration after rotation. Fresh nonces use only the current
    /// registration and produce a same-state signed successor through the
    /// store's exact-predecessor CAS.
    pub fn payout_status(
        &self,
        canonical_envelope: &[u8],
        now_unix: u64,
    ) -> Result<Vec<u8>, IssuerServiceErrorV1> {
        if self.payout_policy.is_none() {
            return Err(IssuerServiceErrorV1::NotFound);
        }
        let envelope = ProviderPayoutStatusEnvelopeV1::decode(canonical_envelope)
            .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?;
        let identity = self.store.identity().map_err(map_store_error)?;
        let current_settlement_key = self.issuer_settlement_signing_key.verifying_key();
        let issuer_keyring = IssuerSettlementKeyringExpectationV1 {
            issuer_id: &identity.issuer_id,
            current_key: &current_settlement_key,
            retained_keys: &self.retained_issuer_settlement_keys,
        };
        let payout_context = PayoutStatusContextV1 {
            payout_request: &envelope.payout_request,
            initial_payout_response: &envelope.initial_payout_response,
        };
        let record = self
            .store
            .payout_by_id(&envelope.request.payout_id)
            .map_err(map_store_error)?;
        let status_request_digest = envelope
            .request
            .request_digest()
            .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?;
        let exact_replay = record
            .as_ref()
            .filter(|record| record.provider_id == envelope.request.provider_id)
            .and_then(|record| record.exact_latest_status_response.as_deref())
            .and_then(|exact| IssuerPayoutStatusResponseV1::decode(exact).ok())
            .is_some_and(|response| response.request_digest == status_request_digest);
        let current_registration = self
            .store
            .provider_settlement_registration(&envelope.request.provider_id)
            .map_err(map_store_error)?
            .ok_or(IssuerServiceErrorV1::Unauthorized)?;
        let registration = if exact_replay
            && current_registration.registration_digest != envelope.request.registration_digest
        {
            self.store
                .historical_provider_settlement_registration(
                    &envelope.request.provider_id,
                    &envelope.request.registration_digest,
                )
                .map_err(map_store_error)?
                .ok_or(IssuerServiceErrorV1::Unauthorized)?
        } else {
            current_registration
        };
        let provider_request_key =
            VerifyingKey::from_bytes(&registration.provider_request_verifying_key)
                .map_err(|_| IssuerServiceErrorV1::Internal)?;
        let registration_expectation = ProviderSettlementRegistrationExpectationV1 {
            registration_digest: &registration.registration_digest,
            provider_id: &registration.provider_id,
            issuer_id: &identity.issuer_id,
            settlement_account_id: &registration.settlement_account_id,
            provider_request_key: &provider_request_key,
            issuer_settlement_key: &current_settlement_key,
            not_before: registration.not_before,
            not_after: registration.not_after,
            now_unix,
        };
        if exact_replay {
            verify_committed_payout_status_replay_auth_v1(
                &envelope.request,
                &payout_context,
                &envelope.request_auth,
                &registration_expectation,
                &issuer_keyring,
            )
            .map_err(|_| IssuerServiceErrorV1::Unauthorized)?;
        } else {
            verify_new_payout_status_request_for(
                &envelope.request,
                &payout_context,
                &envelope.request_auth,
                &registration_expectation,
                &issuer_keyring,
            )
            .map_err(|_| IssuerServiceErrorV1::Unauthorized)?;
        }
        let record = record.ok_or(IssuerServiceErrorV1::NotFound)?;
        let exact_initial = envelope
            .initial_payout_response
            .encode()
            .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?;
        if record.exact_initial_response != exact_initial
            || record.request_digest
                != envelope
                    .payout_request
                    .request_digest()
                    .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?
        {
            return Err(IssuerServiceErrorV1::Conflict);
        }
        let latest = record
            .exact_latest_status_response
            .as_deref()
            .map(IssuerPayoutStatusResponseV1::decode)
            .transpose()
            .map_err(|_| IssuerServiceErrorV1::Internal)?;
        let current = verify_persisted_payout_snapshot_for_store_v1(
            &envelope.payout_request,
            &envelope.initial_payout_response,
            latest.as_ref(),
            &issuer_keyring,
        )
        .map_err(|_| IssuerServiceErrorV1::Internal)?;
        if current.payout_id() != &record.payout_id
            || current.payout_request_digest() != &record.request_digest
            || current.ledger_transaction_id() != &record.ledger_transaction_id
            || current.state() != record.state
            || current.state_version() != record.state_version
            || current.updated_at() != record.updated_at
        {
            return Err(IssuerServiceErrorV1::Internal);
        }
        if let (Some(latest), Some(exact)) = (
            latest.as_ref(),
            record.exact_latest_status_response.as_ref(),
        ) {
            if latest.request_digest == status_request_digest {
                return Ok(exact.clone());
            }
        }
        if now_unix <= current.updated_at() {
            return Err(IssuerServiceErrorV1::RetryableUnavailable);
        }
        let mut committer = self.store.payout_status_committer(&current_settlement_key);
        match sign_and_commit_payout_status_v1(
            &envelope.request,
            &envelope.initial_payout_response,
            &current,
            current.state(),
            now_unix,
            &self.issuer_settlement_signing_key,
            &mut committer,
        ) {
            Ok(response) => response
                .encode()
                .map_err(|_| IssuerServiceErrorV1::Internal),
            Err(PayoutCommitErrorV1::Conflict { .. }) => {
                let raced = self
                    .store
                    .payout_by_id(&envelope.request.payout_id)
                    .map_err(map_store_error)?
                    .ok_or(IssuerServiceErrorV1::NotFound)?;
                let Some(exact) = raced.exact_latest_status_response else {
                    return Err(IssuerServiceErrorV1::RetryableUnavailable);
                };
                let response = IssuerPayoutStatusResponseV1::decode(&exact)
                    .map_err(|_| IssuerServiceErrorV1::Internal)?;
                if response.request_digest == status_request_digest {
                    Ok(exact)
                } else {
                    Err(IssuerServiceErrorV1::RetryableUnavailable)
                }
            }
            Err(PayoutCommitErrorV1::Store(error)) => Err(map_store_error(error)),
            Err(PayoutCommitErrorV1::Protocol(_)) => Err(IssuerServiceErrorV1::Internal),
        }
    }

    fn load_clearing_context(
        &self,
        provider_id: &[u8; 32],
        authorization_digest: &[u8; 32],
    ) -> Result<LoadedClearingContextV1, IssuerServiceErrorV1> {
        let provider = self
            .providers
            .binary_search_by_key(provider_id, |provider| provider.provider_id)
            .ok()
            .map(|index| &self.providers[index])
            .ok_or(IssuerServiceErrorV1::Unauthorized)?;
        let authorization_record = self
            .store
            .clearing_authorization(authorization_digest)
            .map_err(map_store_error)?
            .ok_or(IssuerServiceErrorV1::Unauthorized)?;
        let authorization =
            ProviderClearingAuthorizationV1::decode(&authorization_record.exact_authorization)
                .map_err(|_| IssuerServiceErrorV1::Internal)?;
        let approval = IssuerClearingApprovalV1::decode(&authorization_record.exact_approval)
            .map_err(|_| IssuerServiceErrorV1::Internal)?;
        let registration = self
            .store
            .provider_settlement_registration(provider_id)
            .map_err(map_store_error)?
            .ok_or(IssuerServiceErrorV1::Unauthorized)?;
        if &authorization.claims.provider_id != provider_id
            || authorization
                .authorization_digest()
                .map_err(|_| IssuerServiceErrorV1::Internal)?
                != *authorization_digest
            || registration.provider_id != *provider_id
        {
            return Err(IssuerServiceErrorV1::Unauthorized);
        }
        Ok(LoadedClearingContextV1 {
            authorization,
            approval,
            operator_key: provider.operator_key,
            minimum_authorization_epoch: provider.minimum_authorization_epoch,
            registration,
        })
    }

    fn clearing_expectation<'a>(
        &'a self,
        context: &'a LoadedClearingContextV1,
        settlement_key: &'a VerifyingKey,
        now_unix: u64,
    ) -> ProviderClearingExpectationV1<'a> {
        ProviderClearingExpectationV1 {
            provider_id: &context.authorization.claims.provider_id,
            issuer_id: &context.authorization.claims.issuer_id,
            operator_key: &context.operator_key,
            issuer_settlement_key: settlement_key,
            now_unix,
            minimum_authorization_epoch: context.minimum_authorization_epoch,
        }
    }

    fn issuer_settlement_keyring<'a>(
        &'a self,
        issuer_id: &'a [u8; 32],
        current_key: &'a VerifyingKey,
    ) -> IssuerSettlementKeyringExpectationV1<'a> {
        IssuerSettlementKeyringExpectationV1 {
            issuer_id,
            current_key,
            retained_keys: &self.retained_issuer_settlement_keys,
        }
    }

    fn verify_committed_clearing_auth(
        &self,
        authorization_digest: &[u8; 32],
        request_digest: &[u8; 32],
        context: &LoadedClearingContextV1,
        request_auth: &pir_service_protocol::ProviderClearingRequestAuthV1,
    ) -> Result<(), IssuerServiceErrorV1> {
        let historical_operator_key =
            VerifyingKey::from_bytes(&context.authorization.operator_verifying_key)
                .map_err(|_| IssuerServiceErrorV1::Internal)?;
        let current_settlement_key = self.issuer_settlement_signing_key.verifying_key();
        let keyring = self.issuer_settlement_keyring(
            &context.authorization.claims.issuer_id,
            &current_settlement_key,
        );
        let historical_settlement_key = keyring
            .resolve_for_issuer(
                &context.authorization.claims.issuer_id,
                &context.approval.issuer_settlement_key_id,
            )
            .map_err(|_| IssuerServiceErrorV1::Internal)?;
        verify_committed_clearing_request_auth_v1(
            authorization_digest,
            request_digest,
            &context.authorization,
            &context.approval,
            request_auth,
            &CommittedRedeemReplayExpectationV1 {
                provider_id: &context.authorization.claims.provider_id,
                issuer_id: &context.authorization.claims.issuer_id,
                operator_key: &historical_operator_key,
                issuer_settlement_key: historical_settlement_key,
            },
        )
        .map_err(|_| IssuerServiceErrorV1::Unauthorized)
    }

    fn verify_redeem_response<'a>(
        &self,
        response: &'a pir_service_protocol::ProviderRedeemResponseV1,
        request: &pir_service_protocol::ProviderRedeemRequestV1,
        authorization: &ProviderClearingAuthorizationV1,
        settlement_verifying_key: &VerifyingKey,
        now_unix: u64,
    ) -> Result<pir_service_protocol::VerifiedProviderRedeemResponseV1<'a>, IssuerServiceErrorV1>
    {
        match &request.destination {
            SettlementDestinationV1::LedgerCredit { .. } => {
                verify_ledger_redeem_response_for_exact_request_v1(
                    response,
                    request,
                    authorization,
                    settlement_verifying_key,
                )
                .map_err(|_| IssuerServiceErrorV1::Internal)
            }
            SettlementDestinationV1::BlindOutputs { .. } => {
                verify_redeem_response_for_exact_request(
                    response,
                    request,
                    authorization,
                    settlement_verifying_key,
                    &RetainedSettlementKeysetExpectationV1 {
                        issuer_id: &request.issuer_id,
                        retained_keysets: &self.retained_settlement_keysets,
                        now_unix,
                    },
                    &K256CashuDleqVerifierV1,
                )
                .map_err(|_| IssuerServiceErrorV1::Internal)
            }
        }
    }
}

fn decode_retained_policy(
    record: &pir_issuer_store::IssuerServicePolicyRecordV1,
) -> Result<ServicePolicyV1, IssuerServiceErrorV1> {
    let policy = ServicePolicyV1::decode(&record.exact_policy)
        .map_err(|_| IssuerServiceErrorV1::Internal)?;
    if policy
        .encode()
        .map_err(|_| IssuerServiceErrorV1::Internal)?
        != record.exact_policy
        || policy
            .policy_digest()
            .map_err(|_| IssuerServiceErrorV1::Internal)?
            != record.policy_digest
    {
        return Err(IssuerServiceErrorV1::Internal);
    }
    Ok(policy)
}

fn decode_policy_key(bytes: &[u8; 32]) -> Result<VerifyingKey, IssuerServiceErrorV1> {
    VerifyingKey::from_bytes(bytes).map_err(|_| IssuerServiceErrorV1::Internal)
}

fn map_core_error(error: IssuerCoreErrorV1) -> IssuerServiceErrorV1 {
    match error {
        IssuerCoreErrorV1::InvalidInput => IssuerServiceErrorV1::InvalidRequest,
        IssuerCoreErrorV1::RetryableUnavailable => IssuerServiceErrorV1::RetryableUnavailable,
        IssuerCoreErrorV1::OutcomeUnknown => IssuerServiceErrorV1::OutcomeUnknown,
        IssuerCoreErrorV1::NotFound => IssuerServiceErrorV1::NotFound,
        IssuerCoreErrorV1::InvalidState => IssuerServiceErrorV1::Conflict,
        IssuerCoreErrorV1::PermanentMismatch | IssuerCoreErrorV1::StoreUnanchored => {
            IssuerServiceErrorV1::Internal
        }
    }
}

fn map_store_error(error: StoreError) -> IssuerServiceErrorV1 {
    match error {
        StoreError::QuoteMissing => IssuerServiceErrorV1::NotFound,
        StoreError::StatusRequestBindingMismatch
        | StoreError::StatusRequestStale
        | StoreError::BadStatusRequestSignature => IssuerServiceErrorV1::Unauthorized,
        StoreError::CreationIdempotencyConflict
        | StoreError::ClaimIdempotencyConflict
        | StoreError::QuoteAlreadyClaimed
        | StoreError::QuoteNotSettled
        | StoreError::ClaimDeadlineExpired
        | StoreError::StatusNonceReplay
        | StoreError::RedeemIdempotencyConflict
        | StoreError::CredentialAlreadySpent
        | StoreError::SettlementDepositIdempotencyConflict
        | StoreError::SettlementNoteAlreadySpent
        | StoreError::SettlementLedgerSequenceConflict
        | StoreError::PayoutIntentIdempotencyConflict
        | StoreError::PayoutIntentAlreadyConsumed
        | StoreError::PayoutIdempotencyConflict
        | StoreError::InsufficientProviderBalance
        | StoreError::PayoutStatusConflict => IssuerServiceErrorV1::Conflict,
        StoreError::Io(_)
        | StoreError::Sqlite(_)
        | StoreError::PayoutOutboxUnavailable
        | StoreError::QuoteCapacityExceeded
        | StoreError::StatusNonceCapacityExceeded => IssuerServiceErrorV1::RetryableUnavailable,
        StoreError::CommitOutcomeUnknown(_) | StoreError::UnanchoredCommit { .. } => {
            IssuerServiceErrorV1::OutcomeUnknown
        }
        StoreError::InvalidInput(_) | StoreError::Protocol(_) => {
            IssuerServiceErrorV1::InvalidRequest
        }
        _ => IssuerServiceErrorV1::Internal,
    }
}

#[cfg(test)]
mod settlement_service_tests;
