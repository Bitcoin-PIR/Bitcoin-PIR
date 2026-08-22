use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey};
use pir_issuer_store::{
    BatAcceptanceClassMemberRecordV2, BatAcceptanceClassRecordV2,
    BatV2AccountingAuthorizationRecordV2, IssuerStore,
};
use pir_payment_crypto::{K256CashuMintKeyringV1, PaymentCryptoError};
use pir_service_protocol::{
    bat_acceptance_member_from_retained_policy_v2, precheck_bat_v2_redeem_v2,
    sign_and_commit_grantable_success_v2, sign_retry_safe_non_consuming_v2,
    sign_terminal_if_attempt_committed_v2, sign_terminal_invalid_or_spent_v2,
    verify_bat_v2_credential_for_commit_v2, BatAcceptanceClassV2, BatV2CredentialCheckV2,
    BatV2ProofVerificationInputV2, BatV2RedeemCommitResultV2, BatV2RedeemPrecheckV2,
    ProviderAccountingAuthorizationV2, ProviderAccountingExpectationV2, ProviderRedeemEnvelopeV2,
    ProviderRedeemRequestV2, ProviderRedeemResponseV2, VerifiedBatAcceptanceMemberV2,
};

use super::{decode_policy_key, decode_retained_policy, IssuerServiceErrorV1};

/// Transport-neutral issuer-global BAT V2 redemption service.
///
/// This service has no provider-local idempotency key, delivery claim, or
/// ProviderStore. The issuer store is the sole durable spend and ledger
/// authority; only the request that wins the fresh commit may receive a
/// grantable success.
pub struct BatV2IssuerRedemptionServiceV2 {
    store: IssuerStore,
    bat_keyring: Arc<K256CashuMintKeyringV1>,
    issuer_settlement_signing_key: SigningKey,
}

impl fmt::Debug for BatV2IssuerRedemptionServiceV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BatV2IssuerRedemptionServiceV2")
            .field("store", &"[redacted]")
            .field("bat_keyring", &"[redacted]")
            .field("issuer_settlement_signing_key", &"[redacted]")
            .finish()
    }
}

impl BatV2IssuerRedemptionServiceV2 {
    pub fn new(
        store: IssuerStore,
        bat_keyring: Arc<K256CashuMintKeyringV1>,
        issuer_settlement_signing_key: SigningKey,
        now_unix: u64,
    ) -> Result<Self, IssuerServiceErrorV1> {
        if now_unix == 0 {
            return Err(IssuerServiceErrorV1::InvalidRequest);
        }
        let loaded: BTreeSet<[u8; 33]> =
            bat_keyring.denomination_public_keys().into_iter().collect();
        let required = store
            .bat_v2_credential_material_requirements(now_unix)
            .map_err(|_| IssuerServiceErrorV1::Internal)?;
        if required
            .iter()
            .any(|requirement| !loaded.contains(&requirement.raw_public_key))
        {
            return Err(IssuerServiceErrorV1::InvalidRequest);
        }
        Ok(Self {
            store,
            bat_keyring,
            issuer_settlement_signing_key,
        })
    }

    /// Read-only mutation-budget classification. Only a canonical request
    /// whose provider/attempt pair is already durable may bypass the new-write
    /// budget, and the later handler will return a non-granting terminal.
    pub fn committed_attempt_for_canonical_envelope(
        &self,
        canonical_envelope: &[u8],
    ) -> Result<bool, IssuerServiceErrorV1> {
        let envelope = decode_canonical_envelope(canonical_envelope)?;
        self.store
            .bat_v2_attempt_is_committed(
                &envelope.request.provider_id,
                &envelope.request.attempt_id,
            )
            .map_err(|_| IssuerServiceErrorV1::OutcomeUnknownCredentialBurned)
    }

    /// `POST /v2/redeems` body handler. Any operational error after canonical
    /// decode is explicit burn-on-ambiguity and never asks the caller to retry
    /// the credential.
    pub fn redeem_v2(
        &self,
        canonical_envelope: &[u8],
        now_unix: u64,
    ) -> Result<Vec<u8>, IssuerServiceErrorV1> {
        if now_unix == 0 {
            return Err(IssuerServiceErrorV1::InvalidRequest);
        }
        let envelope = decode_canonical_envelope(canonical_envelope)?;
        let request = envelope.request.clone();
        let mut committer = self
            .store
            .bat_v2_redeem_committer(now_unix)
            .map_err(|_| IssuerServiceErrorV1::OutcomeUnknownCredentialBurned)?;

        if let Some(terminal) = sign_terminal_if_attempt_committed_v2(
            &request,
            &self.issuer_settlement_signing_key,
            &committer,
        )
        .map_err(|_| IssuerServiceErrorV1::OutcomeUnknownCredentialBurned)?
        {
            return encode_response(terminal);
        }

        let authorization_record = self
            .store
            .current_bat_v2_accounting_authorization(&request.provider_id)
            .map_err(|_| IssuerServiceErrorV1::OutcomeUnknownCredentialBurned)?
            .ok_or(IssuerServiceErrorV1::OutcomeUnknownCredentialBurned)?;
        let (authorization, approval) = authorization_record
            .decode_exact()
            .map_err(|_| IssuerServiceErrorV1::OutcomeUnknownCredentialBurned)?;
        let operator_key = VerifyingKey::from_bytes(&authorization_record.operator_verifying_key)
            .map_err(|_| IssuerServiceErrorV1::OutcomeUnknownCredentialBurned)?;
        let settlement_key =
            VerifyingKey::from_bytes(&authorization_record.issuer_settlement_verifying_key)
                .map_err(|_| IssuerServiceErrorV1::OutcomeUnknownCredentialBurned)?;
        if settlement_key != self.issuer_settlement_signing_key.verifying_key() {
            return Err(IssuerServiceErrorV1::OutcomeUnknownCredentialBurned);
        }

        let class_record = self
            .store
            .bat_acceptance_class_v2(&request.class_id, request.class_key_epoch)
            .map_err(|_| IssuerServiceErrorV1::OutcomeUnknownCredentialBurned)?
            .ok_or(IssuerServiceErrorV1::OutcomeUnknownCredentialBurned)?;
        let class = decode_exact_class(&class_record)?;
        let member = self.verified_member_for_request(
            &request,
            &authorization_record,
            &authorization,
            &class_record,
            &class,
        )?;

        let expectation = ProviderAccountingExpectationV2 {
            provider_id: authorization_record.provider_id,
            issuer_id: authorization.claims.issuer_id,
            operator_verifying_key: &operator_key,
            issuer_settlement_verifying_key: &settlement_key,
            now_unix,
            minimum_authorization_epoch: authorization_record.authorization_epoch,
        };
        let authorized = match precheck_bat_v2_redeem_v2(
            envelope,
            &authorization,
            &approval,
            &class,
            &member,
            expectation,
        )
        .map_err(|_| IssuerServiceErrorV1::OutcomeUnknownCredentialBurned)?
        {
            BatV2RedeemPrecheckV2::Authorized(value) => *value,
            BatV2RedeemPrecheckV2::RetrySafeNonConsuming(value) => {
                return encode_response(
                    sign_retry_safe_non_consuming_v2(value, &self.issuer_settlement_signing_key)
                        .map_err(|_| IssuerServiceErrorV1::OutcomeUnknownCredentialBurned)?,
                )
            }
            BatV2RedeemPrecheckV2::TerminalInvalidOrSpent(value) => {
                return encode_response(
                    sign_terminal_invalid_or_spent_v2(value, &self.issuer_settlement_signing_key)
                        .map_err(|_| IssuerServiceErrorV1::OutcomeUnknownCredentialBurned)?,
                )
            }
        };

        let verifier = |input: BatV2ProofVerificationInputV2<'_>| match self
            .bat_keyring
            .verify_raw_cashu_signature(input.bat_verification_key, input.secret_raw, input.c)
        {
            Ok(_) => Ok(true),
            Err(PaymentCryptoError::CashuMintKeyNotFound) => Err(()),
            Err(_) => Ok(false),
        };
        let verified = match verify_bat_v2_credential_for_commit_v2(authorized, &verifier)
            .map_err(|_| IssuerServiceErrorV1::OutcomeUnknownCredentialBurned)?
        {
            BatV2CredentialCheckV2::Verified(value) => value,
            BatV2CredentialCheckV2::TerminalInvalidOrSpent(value) => {
                return encode_response(
                    sign_terminal_invalid_or_spent_v2(value, &self.issuer_settlement_signing_key)
                        .map_err(|_| IssuerServiceErrorV1::OutcomeUnknownCredentialBurned)?,
                )
            }
        };

        match sign_and_commit_grantable_success_v2(
            verified,
            &self.issuer_settlement_signing_key,
            &mut committer,
        )
        .map_err(|_| IssuerServiceErrorV1::OutcomeUnknownCredentialBurned)?
        {
            BatV2RedeemCommitResultV2::FreshCommitted(value) => {
                encode_response(value.into_response())
            }
            BatV2RedeemCommitResultV2::TerminalInvalidOrSpent(value) => encode_response(value),
        }
    }

    fn verified_member_for_request(
        &self,
        request: &ProviderRedeemRequestV2,
        authorization_record: &BatV2AccountingAuthorizationRecordV2,
        authorization: &ProviderAccountingAuthorizationV2,
        class_record: &BatAcceptanceClassRecordV2,
        class: &BatAcceptanceClassV2,
    ) -> Result<VerifiedBatAcceptanceMemberV2, IssuerServiceErrorV1> {
        let exact = class_record.members.iter().find(|member| {
            member.provider_id == request.provider_id
                && member.policy_digest == request.policy_digest
                && member.scope_id == request.scope_id
                && member.offer_id == request.offer_id
        });
        if let Some(member) = exact {
            return self.load_verified_member(member, class_record, class);
        }

        let fallback = class_record
            .members
            .iter()
            .find(|member| {
                if member.provider_id != authorization_record.provider_id {
                    return false;
                }
                let tuple = member_tuple(member);
                authorization
                    .rule_for_member(&tuple, &class.class_id)
                    .is_some()
            })
            .or_else(|| {
                class_record
                    .members
                    .iter()
                    .find(|member| member.provider_id == authorization_record.provider_id)
            })
            .or_else(|| class_record.members.first());
        let fallback = fallback.ok_or(IssuerServiceErrorV1::OutcomeUnknownCredentialBurned)?;
        self.load_verified_member(fallback, class_record, class)
    }

    fn load_verified_member(
        &self,
        member: &BatAcceptanceClassMemberRecordV2,
        class_record: &BatAcceptanceClassRecordV2,
        class: &BatAcceptanceClassV2,
    ) -> Result<VerifiedBatAcceptanceMemberV2, IssuerServiceErrorV1> {
        let policy_record = self
            .store
            .service_policy(&member.provider_id, &member.policy_digest)
            .map_err(|_| IssuerServiceErrorV1::OutcomeUnknownCredentialBurned)?
            .ok_or(IssuerServiceErrorV1::OutcomeUnknownCredentialBurned)?;
        let policy = decode_retained_policy(&policy_record)
            .map_err(|_| IssuerServiceErrorV1::OutcomeUnknownCredentialBurned)?;
        let policy_key = decode_policy_key(&policy_record.policy_verifying_key)
            .map_err(|_| IssuerServiceErrorV1::OutcomeUnknownCredentialBurned)?;
        let verified = bat_acceptance_member_from_retained_policy_v2(
            &policy,
            &member.provider_id,
            &member.policy_digest,
            &member.scope_id,
            member.offer_id,
            &policy_key,
        )
        .map_err(|_| IssuerServiceErrorV1::OutcomeUnknownCredentialBurned)?;
        if verified.class_id != class_record.class_id
            || !verified
                .common_terms
                .commercially_equivalent_to(&class.common_terms)
            || verified.redemption_deadline != member.redemption_deadline
            || verified.member != member_tuple(member)
            || !class.members.contains(&verified.member)
        {
            return Err(IssuerServiceErrorV1::OutcomeUnknownCredentialBurned);
        }
        Ok(verified)
    }
}

fn decode_canonical_envelope(
    canonical_envelope: &[u8],
) -> Result<ProviderRedeemEnvelopeV2, IssuerServiceErrorV1> {
    let envelope = ProviderRedeemEnvelopeV2::decode(canonical_envelope)
        .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?;
    if envelope
        .encode()
        .map_err(|_| IssuerServiceErrorV1::InvalidRequest)?
        .as_slice()
        != canonical_envelope
    {
        return Err(IssuerServiceErrorV1::InvalidRequest);
    }
    Ok(envelope)
}

fn decode_exact_class(
    record: &BatAcceptanceClassRecordV2,
) -> Result<BatAcceptanceClassV2, IssuerServiceErrorV1> {
    let class = BatAcceptanceClassV2::decode(&record.exact_artifact)
        .map_err(|_| IssuerServiceErrorV1::OutcomeUnknownCredentialBurned)?;
    if class
        .encode()
        .map_err(|_| IssuerServiceErrorV1::OutcomeUnknownCredentialBurned)?
        != record.exact_artifact
        || class
            .class_digest()
            .map_err(|_| IssuerServiceErrorV1::OutcomeUnknownCredentialBurned)?
            != record.artifact_digest
    {
        return Err(IssuerServiceErrorV1::OutcomeUnknownCredentialBurned);
    }
    Ok(class)
}

fn member_tuple(
    member: &BatAcceptanceClassMemberRecordV2,
) -> pir_service_protocol::BatAcceptanceMemberV2 {
    pir_service_protocol::BatAcceptanceMemberV2 {
        provider_id: member.provider_id,
        policy_digest: member.policy_digest,
        scope_id: member.scope_id,
        offer_id: member.offer_id,
    }
}

fn encode_response(response: ProviderRedeemResponseV2) -> Result<Vec<u8>, IssuerServiceErrorV1> {
    response
        .encode()
        .map_err(|_| IssuerServiceErrorV1::OutcomeUnknownCredentialBurned)
}
