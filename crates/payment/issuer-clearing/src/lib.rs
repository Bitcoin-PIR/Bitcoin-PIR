//! Shared-issuer credential verification and settlement response preparation.

#![forbid(unsafe_code)]

use ed25519_dalek::{SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use pir_arc_adapter::{ArcPresentationCanonicalizerV1, ArcSecretKeyringV1};
use pir_issuer_store::{
    issuer_payout_id_v1, issuer_payout_intent_id_v1, issuer_payout_ledger_transaction_id_v1,
    issuer_redeem_ledger_transaction_id_v1, issuer_settlement_deposit_transaction_id_v1,
    SharedCredentialCryptographicVerifierV1, SharedCredentialSpendSinkV1,
    SharedCredentialVerificationInputV1, VerifiedSharedIssuerRedeemV1,
};
use pir_payment_crypto::{K256CashuMintKeyringV1, PaymentCryptoError};
use pir_service_protocol::{
    AuthScheme, BitcoinPirCashuBatProofV1, BlindSettlementSignatureV1,
    CredentialKeyBindingExpectationV1, FreeAnonymousTicketExpectationV1, FreeAnonymousTicketV1,
    IssuerPayoutIntentResponseV1, IssuerPayoutResponseV1, IssuerPayoutStatusResponseV1,
    PayoutCommitErrorV1, PayoutExecutionCommitStoreV1, PayoutStateV1,
    PayoutStatusCompareAndSwapStoreV1, ProviderPayoutIntentRequestV1,
    ProviderPayoutStatusRequestV1, ProviderRedeemResponseV1, ProviderSettlementDepositResponseV1,
    RedeemSettlementResultV1, ServiceProtocolError, SettlementDestinationV1,
    VerifiedPayoutExecutionV1, VerifiedPayoutSnapshotV1, VerifiedSettlementDepositV1,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

mod payout_worker;

pub use payout_worker::{
    ExternalPayoutCallResultV1, ExternalPayoutCommandV1, ExternalPayoutExecutionContextV1,
    ExternalPayoutExecutorV1, ExternalPayoutOutcomeV1, ExternalPayoutReadinessV1,
    IssuerPayoutOutboxWorkerV1, NoFundsPayoutExecutorV1, PayoutOutboxWorkerErrorV1,
    PayoutOutboxWorkerProgressV1, PayoutWorkerClockV1, SystemPayoutWorkerClockV1,
    MAX_PAYOUT_WORKER_LEASE_SECONDS_V1,
};

const BLIND_SETTLEMENT_NONCE_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-clearing/blind-settlement-dleq-nonce/v1";

#[derive(Debug)]
pub enum IssuerClearingErrorV1 {
    Protocol(ServiceProtocolError),
    Crypto(PaymentCryptoError),
    MethodUnavailable(AuthScheme),
    NonceDerivationExhausted,
}

impl core::fmt::Display for IssuerClearingErrorV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Protocol(error) => write!(formatter, "issuer clearing protocol error: {error}"),
            Self::Crypto(error) => write!(formatter, "issuer clearing crypto error: {error}"),
            Self::MethodUnavailable(scheme) => {
                write!(
                    formatter,
                    "shared credential method is unavailable: {scheme:?}"
                )
            }
            Self::NonceDerivationExhausted => {
                formatter.write_str("could not derive a valid deterministic DLEQ nonce")
            }
        }
    }
}

impl std::error::Error for IssuerClearingErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Crypto(error) => Some(error),
            Self::MethodUnavailable(_) | Self::NonceDerivationExhausted => None,
        }
    }
}

impl From<ServiceProtocolError> for IssuerClearingErrorV1 {
    fn from(value: ServiceProtocolError) -> Self {
        Self::Protocol(value)
    }
}

impl From<PaymentCryptoError> for IssuerClearingErrorV1 {
    fn from(value: PaymentCryptoError) -> Self {
        Self::Crypto(value)
    }
}

/// Reviewed credential adapters available to one shared issuer process. The
/// ARC keyring is optional and remains explicitly experimental.
pub struct SharedIssuerCredentialVerifierV1<'a> {
    bat_keyring: Option<&'a K256CashuMintKeyringV1>,
    arc_keyring_experimental: Option<&'a ArcSecretKeyringV1>,
}

impl<'a> SharedIssuerCredentialVerifierV1<'a> {
    pub const fn new(
        bat_keyring: Option<&'a K256CashuMintKeyringV1>,
        arc_keyring_experimental: Option<&'a ArcSecretKeyringV1>,
    ) -> Self {
        Self {
            bat_keyring,
            arc_keyring_experimental,
        }
    }
}

impl SharedCredentialCryptographicVerifierV1 for SharedIssuerCredentialVerifierV1<'_> {
    fn verify_shared_credential_v1(
        &self,
        input: SharedCredentialVerificationInputV1<'_>,
        sink: &mut dyn SharedCredentialSpendSinkV1,
    ) -> Result<(), ServiceProtocolError> {
        let binding_digest = input.credential_binding.binding_digest()?;
        if binding_digest != input.request.credential_binding_digest
            || input.credential_binding.issuer_id != input.request.issuer_id
            || input.credential_binding.claims.provider_id != input.request.provider_id
            || input.credential_binding.claims.scope_id != input.request.scope_id
            || input.credential_binding.claims.offer_id != input.request.offer_id
            || input.credential_binding.claims.scheme != input.request.scheme
        {
            return Err(invalid_credential(
                "credential binding does not match redeem request",
            ));
        }
        match input.request.scheme {
            AuthScheme::FreeV1 => verify_free(input, &binding_digest, sink),
            AuthScheme::BitcoinPirCashuBatV1 => {
                let keyring = self
                    .bat_keyring
                    .ok_or_else(|| invalid_credential("Cashu BAT verifier is unavailable"))?;
                verify_bat(input, &binding_digest, keyring, sink)
            }
            AuthScheme::ArcV1Experimental => {
                let keyring = self.arc_keyring_experimental.ok_or_else(|| {
                    invalid_credential("experimental ARC verifier is unavailable")
                })?;
                verify_arc_experimental(input, &binding_digest, keyring, sink)
            }
            _ => Err(invalid_credential(
                "credential scheme is not shared-issuer redeemable",
            )),
        }
    }
}

fn verify_free(
    input: SharedCredentialVerificationInputV1<'_>,
    binding_digest: &[u8; 32],
    sink: &mut dyn SharedCredentialSpendSinkV1,
) -> Result<(), ServiceProtocolError> {
    let ticket = FreeAnonymousTicketV1::decode(input.canonical_credential)?;
    let exact_ticket = Zeroizing::new(ticket.encode()?);
    if exact_ticket.as_slice() != input.canonical_credential
        || ticket.not_before < input.credential_binding.claims.not_before
        || ticket.not_after > input.credential_binding.claims.not_after
    {
        return Err(invalid_credential(
            "free ticket is non-canonical or outlives its delegated key",
        ));
    }
    let key_bytes: [u8; 32] = input
        .credential_binding
        .claims
        .verification_key
        .as_slice()
        .try_into()
        .map_err(|_| invalid_credential("free ticket key is not Ed25519"))?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| invalid_credential("free ticket key is malformed"))?;
    ticket.verify(
        &key,
        &FreeAnonymousTicketExpectationV1 {
            provider_id: input.request.provider_id,
            scope_id: input.request.scope_id,
            offer_id: input.request.offer_id,
            policy_digest: ticket.policy_digest,
            entitlement_profile: input.credential_binding.claims.entitlement_profile,
            issuer_id: input.request.issuer_id,
        },
        input.now_unix,
    )?;
    sink.accept_verified_spend_v1(AuthScheme::FreeV1, binding_digest, &ticket.spend_key())
}

fn verify_bat(
    input: SharedCredentialVerificationInputV1<'_>,
    binding_digest: &[u8; 32],
    keyring: &K256CashuMintKeyringV1,
    sink: &mut dyn SharedCredentialSpendSinkV1,
) -> Result<(), ServiceProtocolError> {
    let proof = BitcoinPirCashuBatProofV1::decode(input.canonical_credential)?;
    if proof.encode_zeroizing()?.as_slice() != input.canonical_credential {
        return Err(invalid_credential("Cashu BAT proof is not canonical"));
    }
    let public_key: [u8; 33] = input
        .credential_binding
        .claims
        .verification_key
        .as_slice()
        .try_into()
        .map_err(|_| invalid_credential("Cashu BAT key is not a compressed point"))?;
    keyring
        .verify_raw_cashu_signature(&public_key, &proof.secret_raw, &proof.c)
        .map_err(|_| invalid_credential("Cashu BAT signature is invalid"))?;
    let spend_key = proof.spend_key(&public_key)?;
    sink.accept_verified_spend_v1(AuthScheme::BitcoinPirCashuBatV1, binding_digest, &spend_key)
}

fn verify_arc_experimental(
    input: SharedCredentialVerificationInputV1<'_>,
    binding_digest: &[u8; 32],
    keyring: &ArcSecretKeyringV1,
    sink: &mut dyn SharedCredentialSpendSinkV1,
) -> Result<(), ServiceProtocolError> {
    let claims = &input.credential_binding.claims;
    let expected = CredentialKeyBindingExpectationV1 {
        issuer_id: &input.request.issuer_id,
        provider_id: &input.request.provider_id,
        scope_id: &input.request.scope_id,
        offer_id: input.request.offer_id,
        scheme: AuthScheme::ArcV1Experimental,
        minimum_keyset_epoch: claims.keyset_epoch,
        entitlement_profile: claims.entitlement_profile,
        presentation_limit: claims.presentation_limit,
        credential_key_id: &claims.credential_key_id,
    };
    let canonicalizer = ArcPresentationCanonicalizerV1::from_verified_binding(
        input.credential_binding,
        &expected,
        input.now_unix,
    )
    .map_err(|_| invalid_credential("experimental ARC binding is invalid"))?;
    if canonicalizer.binding_digest() != binding_digest {
        return Err(invalid_credential(
            "experimental ARC canonicalizer binding mismatch",
        ));
    }
    let presentation = pir_service_protocol::ArcPresentationV1::decode_canonical(
        input.canonical_credential,
        &canonicalizer,
    )?;
    let verified = keyring
        .verify_presentation(
            input.credential_binding,
            &expected,
            input.now_unix,
            &presentation,
        )
        .map_err(|_| invalid_credential("experimental ARC presentation is invalid"))?;
    if verified.binding_digest() != binding_digest {
        return Err(invalid_credential(
            "experimental ARC verified binding mismatch",
        ));
    }
    sink.accept_verified_spend_v1(
        AuthScheme::ArcV1Experimental,
        binding_digest,
        verified.spend_key(),
    )
}

/// Secret used only to derive deterministic NUT-12 proof nonces for exact
/// redeem-response recovery. It is independent of Cashu denomination keys and
/// never persisted by the issuer store.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RedeemResponseDerivationKeyV1([u8; 32]);

impl core::fmt::Debug for RedeemResponseDerivationKeyV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("RedeemResponseDerivationKeyV1")
            .field(&"[REDACTED]")
            .finish()
    }
}

impl RedeemResponseDerivationKeyV1 {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, IssuerClearingErrorV1> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(IssuerClearingErrorV1::Protocol(invalid_credential(
                "redeem response derivation key is all zero",
            )));
        }
        Ok(Self(bytes))
    }
}

/// Builds a deterministic candidate success response. The caller must obtain
/// a verified response typestate and atomically commit it before release.
pub fn prepare_redeem_response_v1(
    verified: &VerifiedSharedIssuerRedeemV1<'_>,
    issuer_settlement_signing_key: &SigningKey,
    settlement_keyring: Option<&K256CashuMintKeyringV1>,
    derivation_key: &RedeemResponseDerivationKeyV1,
) -> Result<ProviderRedeemResponseV1, IssuerClearingErrorV1> {
    let request = verified.request();
    let request_digest = request.request_digest()?;
    let result = match &request.destination {
        SettlementDestinationV1::LedgerCredit { account_id } => {
            RedeemSettlementResultV1::LedgerCredit {
                account_id: *account_id,
                ledger_transaction_id: issuer_redeem_ledger_transaction_id_v1(
                    &request.issuer_id,
                    &request_digest,
                ),
            }
        }
        SettlementDestinationV1::BlindOutputs {
            settlement_keyset_id,
            outputs,
        } => {
            let keyring = settlement_keyring
                .ok_or(IssuerClearingErrorV1::MethodUnavailable(request.scheme))?;
            let rule = verified
                .authorization()
                .rule_for_binding(&request.credential_binding_digest)
                .ok_or_else(|| invalid_credential("settlement rule disappeared"))?;
            let keyset = rule
                .blind_output_keyset
                .as_ref()
                .ok_or_else(|| invalid_credential("blind settlement keyset is missing"))?;
            if keyset.keyset_id != *settlement_keyset_id {
                return Err(invalid_credential("blind settlement keyset mismatch").into());
            }
            let mut signatures = Vec::with_capacity(outputs.len());
            for (index, output) in outputs.iter().enumerate() {
                let public_key = keyset
                    .keys
                    .iter()
                    .find(|key| key.amount == output.denomination)
                    .map(|key| key.public_key)
                    .ok_or_else(|| invalid_credential("blind settlement denomination missing"))?;
                let signed = blind_sign_deterministic(
                    keyring,
                    &public_key,
                    &output.blinded_message,
                    derivation_key,
                    &request_digest,
                    index,
                )?;
                signatures.push(BlindSettlementSignatureV1 {
                    denomination: output.denomination,
                    blinded_message: output.blinded_message,
                    blinded_signature: *signed.blinded_signature(),
                    dleq_e: *signed.dleq_e(),
                    dleq_s: *signed.dleq_s(),
                });
            }
            RedeemSettlementResultV1::BlindOutputs {
                settlement_keyset_id: settlement_keyset_id.clone(),
                signatures,
            }
        }
    };
    ProviderRedeemResponseV1::sign(
        ProviderRedeemResponseV1 {
            issuer_settlement_key_id: [1; 16],
            request_digest,
            authorization_digest: request.authorization_digest,
            issuer_id: request.issuer_id,
            provider_id: request.provider_id,
            unit: verified.unit(),
            accepted_value: request.accepted_value,
            provider_credit: verified.provider_credit(),
            issuer_fee: verified.issuer_fee(),
            result,
            signature: [0; 64],
        },
        issuer_settlement_signing_key,
    )
    .map_err(Into::into)
}

/// Constructs the signed candidate response for an already verified blind
/// settlement deposit. `next_ledger_sequence` must come from the current
/// durable provider balance; the store compare-and-sets it during commit.
pub fn prepare_settlement_deposit_response_v1(
    verified: &VerifiedSettlementDepositV1<'_>,
    next_ledger_sequence: u64,
    issuer_settlement_signing_key: &SigningKey,
) -> Result<ProviderSettlementDepositResponseV1, IssuerClearingErrorV1> {
    if next_ledger_sequence == 0 {
        return Err(invalid_credential("next ledger sequence is zero").into());
    }
    let request = verified.request();
    let request_digest = request.request_digest()?;
    ProviderSettlementDepositResponseV1::sign(
        ProviderSettlementDepositResponseV1 {
            issuer_settlement_key_id: [1; 16],
            request_digest,
            registration_digest: request.registration_digest,
            issuer_id: request.issuer_id,
            provider_id: request.provider_id,
            account_id: request.account_id,
            unit: request.unit,
            settlement_keyset_id: verified.keyset_id().to_owned(),
            total_value: request.total_value,
            ledger_transaction_id: issuer_settlement_deposit_transaction_id_v1(
                &request.issuer_id,
                &request_digest,
            ),
            ledger_sequence: next_ledger_sequence,
            signature: [0; 64],
        },
        issuer_settlement_signing_key,
    )
    .map_err(Into::into)
}

/// Constructs the issuer-signed, idempotently persistable payout quote. The
/// intent only quotes a fee and expiry; it does not reserve provider funds.
pub fn prepare_payout_intent_response_v1(
    request: &ProviderPayoutIntentRequestV1,
    issuer_fee: u64,
    expires_at: u64,
    issuer_settlement_signing_key: &SigningKey,
) -> Result<IssuerPayoutIntentResponseV1, IssuerClearingErrorV1> {
    let request_digest = request.request_digest()?;
    let total_debit = request
        .payout_value
        .checked_add(issuer_fee)
        .ok_or_else(|| invalid_credential("payout debit overflows"))?;
    IssuerPayoutIntentResponseV1::sign(
        IssuerPayoutIntentResponseV1 {
            issuer_settlement_key_id: [0; 16],
            request_digest,
            authorization_digest: request.authorization_digest,
            issuer_id: request.issuer_id,
            provider_id: request.provider_id,
            account_id: request.account_id,
            payout_target_id: request.payout_target_id,
            unit: request.unit,
            payout_value: request.payout_value,
            issuer_fee,
            total_debit,
            payout_intent_id: issuer_payout_intent_id_v1(&request.issuer_id, &request_digest),
            expires_at,
            signature: [0; 64],
        },
        issuer_settlement_signing_key,
    )
    .map_err(Into::into)
}

/// Signs and atomically commits the initial Accepted payout plus its durable
/// outbox command. The signed response is never returned after a lost store
/// race or failed persistence boundary.
pub fn sign_and_commit_payout_execution_v1<Store: PayoutExecutionCommitStoreV1>(
    execution: &VerifiedPayoutExecutionV1<'_>,
    updated_at: u64,
    issuer_settlement_signing_key: &SigningKey,
    store: &mut Store,
) -> Result<IssuerPayoutResponseV1, PayoutCommitErrorV1<Store::Error>> {
    let request = execution.request();
    let request_digest = request
        .request_digest()
        .map_err(PayoutCommitErrorV1::Protocol)?;
    IssuerPayoutResponseV1::sign_and_commit_execution(
        IssuerPayoutResponseV1 {
            issuer_settlement_key_id: [0; 16],
            request_digest,
            authorization_digest: request.authorization_digest,
            issuer_id: request.issuer_id,
            provider_id: request.provider_id,
            account_id: request.account_id,
            payout_target_id: request.payout_target_id,
            payout_intent_id: request.payout_intent_id,
            payout_id: issuer_payout_id_v1(&request.issuer_id, &request.payout_intent_id),
            unit: request.unit,
            payout_value: request.payout_value,
            total_debit: request.total_debit,
            state: PayoutStateV1::Accepted,
            ledger_transaction_id: issuer_payout_ledger_transaction_id_v1(
                &request.issuer_id,
                &request_digest,
            ),
            state_version: 1,
            updated_at,
            signature: [0; 64],
        },
        execution,
        issuer_settlement_signing_key,
        store,
    )
}

/// Signs and atomically commits one exact payout-status successor. A worker
/// uses this for Accepted -> InFlight -> terminal; status reads may use the
/// protocol-permitted same-state successor with a fresh request nonce.
#[allow(clippy::too_many_arguments)]
pub fn sign_and_commit_payout_status_v1<Store: PayoutStatusCompareAndSwapStoreV1>(
    status_request: &ProviderPayoutStatusRequestV1,
    initial_response: &IssuerPayoutResponseV1,
    previous: &VerifiedPayoutSnapshotV1,
    next_state: PayoutStateV1,
    updated_at: u64,
    issuer_settlement_signing_key: &SigningKey,
    store: &mut Store,
) -> Result<IssuerPayoutStatusResponseV1, PayoutCommitErrorV1<Store::Error>> {
    IssuerPayoutStatusResponseV1::sign_and_commit_successor(
        IssuerPayoutStatusResponseV1 {
            issuer_settlement_key_id: [0; 16],
            request_digest: status_request
                .request_digest()
                .map_err(PayoutCommitErrorV1::Protocol)?,
            registration_digest: status_request.registration_digest,
            issuer_id: initial_response.issuer_id,
            provider_id: initial_response.provider_id,
            account_id: initial_response.account_id,
            payout_id: initial_response.payout_id,
            payout_request_digest: initial_response.request_digest,
            payout_target_id: initial_response.payout_target_id,
            unit: initial_response.unit,
            payout_value: initial_response.payout_value,
            total_debit: initial_response.total_debit,
            state: next_state,
            ledger_transaction_id: initial_response.ledger_transaction_id,
            state_version: previous.state_version().checked_add(1).ok_or_else(|| {
                PayoutCommitErrorV1::Protocol(invalid_credential("payout state version overflows"))
            })?,
            updated_at,
            signature: [0; 64],
        },
        previous,
        issuer_settlement_signing_key,
        store,
    )
}

fn blind_sign_deterministic(
    keyring: &K256CashuMintKeyringV1,
    public_key: &[u8; 33],
    blinded_message: &[u8; 33],
    derivation_key: &RedeemResponseDerivationKeyV1,
    request_digest: &[u8; 32],
    index: usize,
) -> Result<pir_payment_crypto::CashuBlindSignatureWithDleqV1, IssuerClearingErrorV1> {
    for counter in 0u16..=u16::MAX {
        let mut mac = Hmac::<Sha256>::new_from_slice(&derivation_key.0)
            .expect("HMAC accepts every 32-byte key");
        mac.update(BLIND_SETTLEMENT_NONCE_DOMAIN_V1);
        mac.update(request_digest);
        mac.update(&(index as u64).to_le_bytes());
        mac.update(blinded_message);
        mac.update(&counter.to_le_bytes());
        let nonce: [u8; 32] = mac.finalize().into_bytes().into();
        match keyring.blind_sign_with_dleq_v1(public_key, blinded_message, &nonce) {
            Ok(value) => return Ok(value),
            Err(PaymentCryptoError::InvalidCashuScalar)
            | Err(PaymentCryptoError::CashuDleqResponseScalarInvalid) => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(IssuerClearingErrorV1::NonceDerivationExhausted)
}

fn invalid_credential(reason: &'static str) -> ServiceProtocolError {
    ServiceProtocolError::InvalidValue {
        field: "shared issuer credential",
        reason,
    }
}

/// Digest-only helper used in tests and diagnostics; never log credential
/// bytes themselves.
pub fn credential_debug_digest_v1(canonical_credential: &[u8]) -> [u8; 32] {
    Sha256::digest(canonical_credential).into()
}

#[cfg(test)]
mod tests;
