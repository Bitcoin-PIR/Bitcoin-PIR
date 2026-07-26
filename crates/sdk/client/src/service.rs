//! Strict client-side service admission for one independently selected provider.
//!
//! This module deliberately knows nothing about a second PIR provider.  A
//! caller keeps a separate [`ServicePolicyCheckpointV1`] and capability pool
//! for every provider and invokes the same functions on that provider's
//! already authenticated secure transport.
//!
//! The capability is consumed at the server during `REQ_AUTH_BEGIN_V1`.
//! Therefore a transport error after the request is sent has an ambiguous
//! spend outcome and must not be retried with the same capability.

use ed25519_dalek::VerifyingKey;
use pir_sdk::{PirError, PirResult};
use pir_service_protocol::{
    check_standard_cashu_spend_for_offer, ArcPresentationV1, AuthBeginV1, AuthRejectCode,
    AuthResultV1, AuthScheme, AuthorizationProofV1, BitcoinPirCashuBatProofV1,
    CashuManifestEpochFloorV1, CredentialKeysetEpochFloorV1, DeploymentStatus,
    FreeAnonymousTicketV1, FreeAuthorizationProofV1, FreeModeV1, FreePowProofV1, OperationStartV1,
    PaidReceiptV1, PolicyRollbackGuardV1, PowChallengeRequestV1, PowChallengeResponseV1,
    ProviderId, ServicePolicyEpochFloorsV1, ServicePolicyRequestV1, ServicePolicyResponseV1,
    ServicePolicyV1, StandardCashuSpendV1, REQ_AUTH_BEGIN_V1, REQ_POW_CHALLENGE_V1,
    REQ_SERVICE_POLICY_V1, RESP_AUTH_RESULT_V1, RESP_POW_CHALLENGE_V1, RESP_SERVICE_POLICY_V1,
};

use crate::protocol::encode_request;
use crate::transport::PirTransport;

const CHECKPOINT_VERSION_V1: u8 = 1;
const MAX_CHECKPOINT_CREDENTIAL_FLOORS_V1: usize = 1_024;
const MAX_CHECKPOINT_CASHU_FLOORS_V1: usize = 1_024;
const MAX_CHECKPOINT_UNIT_LEN_V1: usize = 16;

/// Durable client-side rollback checkpoint for one provider.
///
/// Persist this independently for every `provider_id`.  The checkpoint never
/// contains an invoice, payment hash, credential, query, peer provider, or
/// server-pair identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServicePolicyCheckpointV1 {
    rollback_guard: PolicyRollbackGuardV1,
    epoch_floors: ServicePolicyEpochFloorsV1,
}

impl Default for ServicePolicyCheckpointV1 {
    fn default() -> Self {
        Self::initial()
    }
}

impl ServicePolicyCheckpointV1 {
    pub const fn initial() -> Self {
        Self {
            rollback_guard: PolicyRollbackGuardV1::initial(),
            epoch_floors: ServicePolicyEpochFloorsV1::initial(),
        }
    }

    pub const fn rollback_guard(&self) -> &PolicyRollbackGuardV1 {
        &self.rollback_guard
    }

    pub const fn epoch_floors(&self) -> &ServicePolicyEpochFloorsV1 {
        &self.epoch_floors
    }

    /// Canonical opaque bytes suitable for an encrypted client vault.
    pub fn encode(&self) -> PirResult<Vec<u8>> {
        if self.epoch_floors.credential_keysets.len() > MAX_CHECKPOINT_CREDENTIAL_FLOORS_V1
            || self.epoch_floors.cashu_manifests.len() > MAX_CHECKPOINT_CASHU_FLOORS_V1
        {
            return Err(PirError::Encode(
                "service policy checkpoint has too many epoch floors".into(),
            ));
        }
        let mut out = Vec::new();
        out.push(CHECKPOINT_VERSION_V1);
        out.extend_from_slice(&self.rollback_guard.highest_epoch.to_le_bytes());
        out.extend_from_slice(&self.rollback_guard.digest_at_highest_epoch);
        out.extend_from_slice(&(self.epoch_floors.credential_keysets.len() as u16).to_le_bytes());
        for floor in &self.epoch_floors.credential_keysets {
            out.extend_from_slice(&floor.scope_id);
            out.push(floor.scheme as u8);
            out.extend_from_slice(&floor.issuer_id);
            out.extend_from_slice(&floor.minimum_epoch.to_le_bytes());
        }
        out.extend_from_slice(&(self.epoch_floors.cashu_manifests.len() as u16).to_le_bytes());
        for floor in &self.epoch_floors.cashu_manifests {
            if floor.unit.is_empty()
                || floor.unit.len() > MAX_CHECKPOINT_UNIT_LEN_V1
                || !floor.unit.is_ascii()
            {
                return Err(PirError::Encode(
                    "service policy checkpoint contains an invalid Cashu unit".into(),
                ));
            }
            out.extend_from_slice(&floor.mint_id);
            out.push(floor.unit.len() as u8);
            out.extend_from_slice(floor.unit.as_bytes());
            out.extend_from_slice(&floor.minimum_epoch.to_le_bytes());
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> PirResult<Self> {
        let mut decoder = CheckpointDecoder::new(bytes);
        if decoder.u8()? != CHECKPOINT_VERSION_V1 {
            return Err(PirError::Decode(
                "unsupported service policy checkpoint version".into(),
            ));
        }
        let rollback_guard = PolicyRollbackGuardV1 {
            highest_epoch: decoder.u64()?,
            digest_at_highest_epoch: decoder.fixed()?,
        };
        let credential_count = decoder.u16()? as usize;
        if credential_count > MAX_CHECKPOINT_CREDENTIAL_FLOORS_V1 {
            return Err(PirError::Decode(
                "service policy checkpoint has too many credential floors".into(),
            ));
        }
        let mut credential_keysets = Vec::with_capacity(credential_count);
        for _ in 0..credential_count {
            let scope_id = decoder.fixed()?;
            let scheme = decode_auth_scheme(decoder.u8()?)?;
            let issuer_id = decoder.fixed()?;
            let minimum_epoch = decoder.u64()?;
            credential_keysets.push(CredentialKeysetEpochFloorV1 {
                scope_id,
                scheme,
                issuer_id,
                minimum_epoch,
            });
        }
        let cashu_count = decoder.u16()? as usize;
        if cashu_count > MAX_CHECKPOINT_CASHU_FLOORS_V1 {
            return Err(PirError::Decode(
                "service policy checkpoint has too many Cashu floors".into(),
            ));
        }
        let mut cashu_manifests = Vec::with_capacity(cashu_count);
        for _ in 0..cashu_count {
            let mint_id = decoder.fixed()?;
            let unit_len = decoder.u8()? as usize;
            if unit_len == 0 || unit_len > MAX_CHECKPOINT_UNIT_LEN_V1 {
                return Err(PirError::Decode(
                    "service policy checkpoint has an invalid Cashu unit length".into(),
                ));
            }
            let unit = std::str::from_utf8(decoder.take(unit_len)?)
                .map_err(|_| PirError::Decode("Cashu checkpoint unit is not UTF-8".into()))?
                .to_owned();
            if !unit.is_ascii() {
                return Err(PirError::Decode(
                    "Cashu checkpoint unit is not ASCII".into(),
                ));
            }
            cashu_manifests.push(CashuManifestEpochFloorV1 {
                mint_id,
                unit,
                minimum_epoch: decoder.u64()?,
            });
        }
        decoder.finish()?;
        let checkpoint = Self {
            rollback_guard,
            epoch_floors: ServicePolicyEpochFloorsV1 {
                credential_keysets,
                cashu_manifests,
            },
        };
        // Delegate consistency and duplicate-floor validation to the protocol
        // verifier without trusting a policy from the wire. The initial guard
        // representation is additionally checked here.
        if (checkpoint.rollback_guard.highest_epoch == 0)
            != checkpoint
                .rollback_guard
                .digest_at_highest_epoch
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(PirError::Decode(
                "service policy checkpoint rollback guard is inconsistent".into(),
            ));
        }
        Ok(checkpoint)
    }
}

/// A policy accepted against one provider's identity/key and rollback state.
#[derive(Clone)]
pub struct AcceptedServicePolicyV1 {
    policy: ServicePolicyV1,
    policy_digest: [u8; 32],
    checkpoint: ServicePolicyCheckpointV1,
    policy_signing_key: VerifyingKey,
    // Session-local channel binding. It is intentionally absent from every
    // checkpoint/wire encoding and from Debug output.
    service_authorization_exporter: [u8; 32],
}

impl core::fmt::Debug for AcceptedServicePolicyV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AcceptedServicePolicyV1")
            .field("policy", &self.policy)
            .field("policy_digest", &self.policy_digest)
            .field("checkpoint", &self.checkpoint)
            .field("policy_signing_key", &self.policy_signing_key)
            .field("service_authorization_exporter", &"[redacted]")
            .finish()
    }
}

impl AcceptedServicePolicyV1 {
    pub const fn policy(&self) -> &ServicePolicyV1 {
        &self.policy
    }

    pub const fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }

    pub const fn checkpoint(&self) -> &ServicePolicyCheckpointV1 {
        &self.checkpoint
    }

    /// Exact Ed25519 key that authenticated this policy.
    ///
    /// Strict two-provider selection compares this already-verified value
    /// locally. It never asks either provider about its peer.
    pub fn policy_signing_key_ed25519(&self) -> [u8; 32] {
        self.policy_signing_key.to_bytes()
    }

    /// Verify that this accepted policy belongs to the exact authenticated
    /// secure-channel session about to carry an authorization. The exporter is
    /// never returned, serialized, or logged.
    pub fn verify_service_authorization_exporter_v1(
        &self,
        current_exporter: &[u8; 32],
    ) -> PirResult<()> {
        if current_exporter.iter().all(|byte| *byte == 0)
            || current_exporter != &self.service_authorization_exporter
        {
            return Err(PirError::VerificationFailed(
                "accepted service policy belongs to a different secure-channel session".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn verify_current_offer_for_pair_v1(
        &self,
        scope_id: &[u8; 32],
        offer_id: u32,
        now_unix: u64,
    ) -> PirResult<pir_service_protocol::VerifiedServiceOfferV1<'_>> {
        if now_unix == 0 {
            return Err(PirError::InvalidState(
                "trusted wall clock is required for strict provider-pair selection".into(),
            ));
        }
        let verified = self
            .policy
            .verify_current_for_acquisition(
                &self.policy.provider_id,
                now_unix,
                self.checkpoint.rollback_guard(),
                self.checkpoint.epoch_floors(),
                &self.policy_signing_key,
            )
            .map_err(protocol_verification_error)?;
        if verified.policy_digest() != self.policy_digest {
            return Err(PirError::VerificationFailed(
                "accepted service-policy digest changed during strict provider-pair selection"
                    .into(),
            ));
        }
        verified
            .offer(scope_id, offer_id)
            .map_err(protocol_verification_error)
    }

    /// Dangerous unpaired primitive: build a BOLT11 quote intent from one
    /// exact verified signed offer without proving that a second provider
    /// selection passed the strict independence checks.
    ///
    /// Native two-provider callers must acquire through
    /// `VerifiedStrictTwoProviderOfferPairV1`. Single-provider backends and the
    /// browser's separately pair-gated WASM orchestrator may use this explicit
    /// low-level entry point.
    ///
    /// `quote_key_checkpoint` is an independently persisted issuer/network/
    /// payee rollback stream. The returned advanced checkpoint must be made
    /// durable before the intent is posted to an issuer, and therefore before
    /// any invoice can be displayed or paid.
    #[allow(clippy::too_many_arguments)]
    pub fn dangerous_unpaired_prepare_bolt11_quote_v1(
        &self,
        scope_id: &[u8; 32],
        offer_id: u32,
        quote_delegation_bytes: &[u8],
        quote_key_checkpoint: &crate::bolt11::Bolt11QuoteKeyCheckpointV1,
        now_unix: u64,
        claim_pubkey_xonly: [u8; 32],
        idempotency_key: [u8; 32],
    ) -> PirResult<crate::bolt11::PreparedBolt11QuoteV1> {
        if now_unix == 0 {
            return Err(PirError::InvalidState(
                "trusted wall clock is required for BOLT11 quote preparation".into(),
            ));
        }
        let verified = self
            .policy
            .verify_current_for_acquisition(
                &self.policy.provider_id,
                now_unix,
                self.checkpoint.rollback_guard(),
                self.checkpoint.epoch_floors(),
                &self.policy_signing_key,
            )
            .map_err(protocol_verification_error)?;
        if verified.policy_digest() != self.policy_digest {
            return Err(PirError::VerificationFailed(
                "accepted service-policy digest changed during quote preparation".into(),
            ));
        }
        let verified_offer = verified
            .offer(scope_id, offer_id)
            .map_err(protocol_verification_error)?;
        crate::bolt11::PreparedBolt11QuoteV1::from_verified_offer(
            &verified_offer,
            quote_delegation_bytes,
            quote_key_checkpoint,
            now_unix,
            claim_pubkey_xonly,
            idempotency_key,
        )
    }

    /// Dangerous unpaired primitive: normalize a wallet-supplied standard
    /// Cashu spend only after closing it against this exact current signed
    /// offer, including the embedded mint manifest, unit, accepted keysets,
    /// denominations, NUT-02 fees, amount, and redemption deadline.
    ///
    /// This does not contact the mint or verify Cashu signatures/spent state;
    /// the provider's authoritative NUT-03 adapter remains responsible for
    /// that online commit. Native two-provider callers should expose this only
    /// through an already verified provider-pair typestate.
    pub fn dangerous_unpaired_prepare_standard_cashu_spend_v1(
        &self,
        scope_id: &[u8; 32],
        offer_id: u32,
        spend: &StandardCashuSpendV1,
        now_unix: u64,
    ) -> PirResult<Vec<u8>> {
        let verified_offer = self.verify_current_offer_for_pair_v1(scope_id, offer_id, now_unix)?;
        check_standard_cashu_spend_for_offer(spend, &verified_offer, now_unix)
            .map_err(protocol_verification_error)?;
        spend.encode().map_err(protocol_decode_error)
    }
}

/// One exact historical policy/offer accepted solely to redeem an already
/// issued provider-bound credential during its signed grace period.
///
/// This is intentionally a distinct type from [`AcceptedServicePolicyV1`]: it
/// carries no rollback checkpoint and exposes no quote, Cashu acquisition, or
/// proof-of-work APIs. The exact digest, scope and offer are fixed at fetch.
#[derive(Clone)]
pub struct AcceptedRetiredServiceRedemptionV1 {
    policy: ServicePolicyV1,
    policy_digest: [u8; 32],
    scope_id: [u8; 32],
    offer_id: u32,
    policy_signing_key: VerifyingKey,
    service_authorization_exporter: [u8; 32],
}

impl core::fmt::Debug for AcceptedRetiredServiceRedemptionV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AcceptedRetiredServiceRedemptionV1")
            .field("policy_digest", &self.policy_digest)
            .field("scope_id", &self.scope_id)
            .field("offer_id", &self.offer_id)
            .field("policy_signing_key", &self.policy_signing_key)
            .field("service_authorization_exporter", &"[redacted]")
            .finish()
    }
}

impl AcceptedRetiredServiceRedemptionV1 {
    pub const fn policy(&self) -> &ServicePolicyV1 {
        &self.policy
    }

    pub const fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }

    pub const fn scope_id(&self) -> [u8; 32] {
        self.scope_id
    }

    pub const fn offer_id(&self) -> u32 {
        self.offer_id
    }

    pub fn verify_service_authorization_exporter_v1(
        &self,
        current_exporter: &[u8; 32],
    ) -> PirResult<()> {
        if current_exporter.iter().all(|byte| *byte == 0)
            || current_exporter != &self.service_authorization_exporter
        {
            return Err(PirError::VerificationFailed(
                "accepted retained redemption belongs to a different secure-channel session".into(),
            ));
        }
        Ok(())
    }

    /// Re-verify and expose the exact historical scope/limits/offer typestate
    /// for trusted client-side preflight. This remains redemption-only: it
    /// cannot create a quote, PoW challenge, or select a different offer.
    pub fn verified_offer_for_redemption_v1(
        &self,
        now_unix: u64,
    ) -> PirResult<pir_service_protocol::VerifiedRetiredOfferV1<'_>> {
        if now_unix == 0 {
            return Err(PirError::InvalidState(
                "trusted wall clock is required for retained-policy redemption".into(),
            ));
        }
        self.policy
            .verify_retired_for_redemption(
                &self.policy.provider_id,
                &self.policy_digest,
                &self.scope_id,
                self.offer_id,
                now_unix,
                &self.policy_signing_key,
            )
            .map_err(protocol_verification_error)
    }

    /// Recheck signed grace and credential binding immediately before a
    /// caller irreversibly retires local proof bytes.
    pub fn verify_redemption_ready_v1(&self, now_unix: u64) -> PirResult<()> {
        self.verified_offer_for_redemption_v1(now_unix).map(|_| ())
    }
}

/// Fetch and verify one provider's policy on an authenticated encrypted
/// channel. No capability is presented or consumed by this function.
pub async fn fetch_verified_service_policy_v1(
    transport: &mut dyn PirTransport,
    expected_provider_id: ProviderId,
    policy_signing_key: &VerifyingKey,
    now_unix: u64,
    checkpoint: &ServicePolicyCheckpointV1,
) -> PirResult<AcceptedServicePolicyV1> {
    let exporter = require_secure_service_channel(transport)?;
    let request = build_service_policy_request_v1();
    let response = transport.roundtrip(&request).await?;
    accept_service_policy_response_v1(
        &response,
        expected_provider_id,
        policy_signing_key,
        now_unix,
        checkpoint,
        exporter,
    )
}

/// Fetch one exact retained policy and accept only the requested
/// provider-bound scope/offer for redemption. This never advances the current
/// policy checkpoint and cannot be used to acquire a new credential.
#[allow(clippy::too_many_arguments)]
pub async fn fetch_retained_service_redemption_v1(
    transport: &mut dyn PirTransport,
    expected_provider_id: ProviderId,
    policy_signing_key: &VerifyingKey,
    expected_policy_digest: [u8; 32],
    scope_id: [u8; 32],
    offer_id: u32,
    now_unix: u64,
) -> PirResult<AcceptedRetiredServiceRedemptionV1> {
    let exporter = require_secure_service_channel(transport)?;
    let request = build_retained_service_policy_request_v1(expected_policy_digest)?;
    let response = transport.roundtrip(&request).await?;
    accept_retained_service_policy_response_v1(
        &response,
        expected_provider_id,
        policy_signing_key,
        expected_policy_digest,
        scope_id,
        offer_id,
        now_unix,
        exporter,
    )
}

/// Fail closed unless `accepted` was fetched over this exact authenticated
/// secure-channel session. Callers which retire capabilities outside this crate
/// should invoke this immediately before that durable transition; send helpers
/// repeat the same check before network I/O.
pub fn verify_service_policy_session_v1(
    transport: &dyn PirTransport,
    accepted: &AcceptedServicePolicyV1,
) -> PirResult<()> {
    let exporter = require_secure_service_channel(transport)?;
    accepted.verify_service_authorization_exporter_v1(&exporter)
}

/// Build the transport-independent policy request used by standalone browser
/// clients which already own an authenticated secure record channel.
pub fn build_service_policy_request_v1() -> Vec<u8> {
    encode_request(
        REQ_SERVICE_POLICY_V1,
        &ServicePolicyRequestV1::Current.encode(),
    )
}

/// Build the same policy opcode with an exact retained digest selector. There
/// is no request form for "any" or "latest" historical policy.
pub fn build_retained_service_policy_request_v1(policy_digest: [u8; 32]) -> PirResult<Vec<u8>> {
    let request = ServicePolicyRequestV1::retained(policy_digest).map_err(protocol_decode_error)?;
    Ok(encode_request(REQ_SERVICE_POLICY_V1, &request.encode()))
}

/// Verify a policy response payload (`opcode || body`) without owning the
/// transport. This is the same verification path used by native clients.
pub fn accept_service_policy_response_v1(
    response: &[u8],
    expected_provider_id: ProviderId,
    policy_signing_key: &VerifyingKey,
    now_unix: u64,
    checkpoint: &ServicePolicyCheckpointV1,
    service_authorization_exporter: [u8; 32],
) -> PirResult<AcceptedServicePolicyV1> {
    if now_unix == 0 {
        return Err(PirError::InvalidState(
            "trusted wall clock is required for service policy verification".into(),
        ));
    }
    if service_authorization_exporter.iter().all(|byte| *byte == 0) {
        return Err(PirError::VerificationFailed(
            "service policy acceptance requires a non-zero secure-channel exporter".into(),
        ));
    }
    let body = expect_response_opcode(&response, RESP_SERVICE_POLICY_V1, "service policy")?;
    let response = ServicePolicyResponseV1::decode(body).map_err(protocol_decode_error)?;
    let policy = response.policy;
    let (policy_digest, next_checkpoint) = {
        let verified = policy
            .verify_current_for_acquisition(
                &expected_provider_id,
                now_unix,
                checkpoint.rollback_guard(),
                checkpoint.epoch_floors(),
                policy_signing_key,
            )
            .map_err(protocol_verification_error)?;
        let policy_digest = verified.policy_digest();
        let next_checkpoint = ServicePolicyCheckpointV1 {
            rollback_guard: PolicyRollbackGuardV1::from_verified(&verified),
            epoch_floors: checkpoint
                .epoch_floors()
                .updated_from_verified(&verified)
                .map_err(protocol_verification_error)?,
        };
        (policy_digest, next_checkpoint)
    };
    Ok(AcceptedServicePolicyV1 {
        policy,
        policy_digest,
        checkpoint: next_checkpoint,
        policy_signing_key: *policy_signing_key,
        service_authorization_exporter,
    })
}

/// Verify a retained-policy response against the exact digest, provider,
/// signing key, scope, offer and current grace deadline. No current-policy
/// rollback state is changed.
#[allow(clippy::too_many_arguments)]
pub fn accept_retained_service_policy_response_v1(
    response: &[u8],
    expected_provider_id: ProviderId,
    policy_signing_key: &VerifyingKey,
    expected_policy_digest: [u8; 32],
    scope_id: [u8; 32],
    offer_id: u32,
    now_unix: u64,
    service_authorization_exporter: [u8; 32],
) -> PirResult<AcceptedRetiredServiceRedemptionV1> {
    if now_unix == 0 {
        return Err(PirError::InvalidState(
            "trusted wall clock is required for retained-policy verification".into(),
        ));
    }
    ServicePolicyRequestV1::retained(expected_policy_digest).map_err(protocol_decode_error)?;
    if service_authorization_exporter.iter().all(|byte| *byte == 0) {
        return Err(PirError::VerificationFailed(
            "retained-policy acceptance requires a non-zero secure-channel exporter".into(),
        ));
    }
    let body = expect_response_opcode(&response, RESP_SERVICE_POLICY_V1, "retained policy")?;
    let policy = ServicePolicyResponseV1::decode(body)
        .map_err(protocol_decode_error)?
        .policy;
    policy
        .verify_retired_for_redemption(
            &expected_provider_id,
            &expected_policy_digest,
            &scope_id,
            offer_id,
            now_unix,
            policy_signing_key,
        )
        .map_err(protocol_verification_error)?;
    Ok(AcceptedRetiredServiceRedemptionV1 {
        policy,
        policy_digest: expected_policy_digest,
        scope_id,
        offer_id,
        policy_signing_key: *policy_signing_key,
        service_authorization_exporter,
    })
}

/// Dangerous unpaired primitive: convert provider-vault bytes into the proof
/// type selected by one signed offer, without checking the peer provider.
/// Native strict two-provider callers should decode through
/// `VerifiedStrictTwoProviderOfferPairV1` instead.
///
/// `proof_bytes` is the canonical method payload, not an old `0x08`/`0x09`
/// presentation frame. ARC accepts only locally emitted canonical
/// presentation bytes and remains experimental.
pub fn dangerous_unpaired_build_authorization_proof_v1(
    accepted: &AcceptedServicePolicyV1,
    scope_id: &[u8; 32],
    offer_id: u32,
    proof_bytes: &[u8],
) -> PirResult<AuthorizationProofV1> {
    let scope_policy = accepted
        .policy
        .scopes
        .iter()
        .find(|entry| &entry.scope.scope_id() == scope_id)
        .ok_or_else(|| PirError::InvalidState("selected service scope is not in policy".into()))?;
    let offer = scope_policy
        .offers
        .iter()
        .find(|offer| offer.offer_id == offer_id)
        .ok_or_else(|| PirError::InvalidState("selected service offer is not in policy".into()))?;

    build_authorization_proof_for_offer_v1(offer, proof_bytes)
}

/// Decode proof bytes for the exact credential-bound offer fixed in a
/// retained redemption handle. The handle cannot select another scope/offer.
pub fn dangerous_unpaired_build_retained_authorization_proof_v1(
    accepted: &AcceptedRetiredServiceRedemptionV1,
    proof_bytes: &[u8],
) -> PirResult<AuthorizationProofV1> {
    let scope_policy = accepted
        .policy
        .scopes
        .iter()
        .find(|entry| entry.scope.scope_id() == accepted.scope_id)
        .ok_or_else(|| PirError::InvalidState("retained service scope is not in policy".into()))?;
    let offer = scope_policy
        .offers
        .iter()
        .find(|offer| offer.offer_id == accepted.offer_id)
        .ok_or_else(|| PirError::InvalidState("retained service offer is not in policy".into()))?;
    if offer.credential_binding.is_none() {
        return Err(PirError::VerificationFailed(
            "retained policy cannot authorize a non-credential offer".into(),
        ));
    }
    build_authorization_proof_for_offer_v1(offer, proof_bytes)
}

fn build_authorization_proof_for_offer_v1(
    offer: &pir_service_protocol::ServiceOfferV1,
    proof_bytes: &[u8],
) -> PirResult<AuthorizationProofV1> {
    let proof = match (offer.authorization, offer.free_mode) {
        (AuthScheme::FreeV1, FreeModeV1::OpenBestEffort) => {
            require_empty_proof(proof_bytes)?;
            AuthorizationProofV1::Free(FreeAuthorizationProofV1::OpenBestEffort)
        }
        (AuthScheme::FreeV1, FreeModeV1::IpRateLimited) => {
            require_empty_proof(proof_bytes)?;
            AuthorizationProofV1::Free(FreeAuthorizationProofV1::IpRateLimited)
        }
        (AuthScheme::FreeV1, FreeModeV1::ProofOfWork) => {
            AuthorizationProofV1::Free(FreeAuthorizationProofV1::ProofOfWork(
                FreePowProofV1::decode(proof_bytes).map_err(protocol_decode_error)?,
            ))
        }
        (AuthScheme::FreeV1, FreeModeV1::AnonymousTicket) => {
            AuthorizationProofV1::Free(FreeAuthorizationProofV1::AnonymousTicket(Box::new(
                FreeAnonymousTicketV1::decode(proof_bytes).map_err(protocol_decode_error)?,
            )))
        }
        (AuthScheme::Bolt11DirectReceiptV1, FreeModeV1::NotFree) => {
            AuthorizationProofV1::Bolt11DirectReceipt(Box::new(
                PaidReceiptV1::decode(proof_bytes).map_err(protocol_decode_error)?,
            ))
        }
        (AuthScheme::CashuEcashV1, FreeModeV1::NotFree) => AuthorizationProofV1::StandardCashu(
            StandardCashuSpendV1::decode(proof_bytes).map_err(protocol_decode_error)?,
        ),
        (AuthScheme::BitcoinPirCashuBatV1, FreeModeV1::NotFree) => {
            AuthorizationProofV1::BitcoinPirCashuBat(
                BitcoinPirCashuBatProofV1::decode(proof_bytes).map_err(protocol_decode_error)?,
            )
        }
        (AuthScheme::ArcV1Experimental, FreeModeV1::NotFree) => {
            if offer.deployment_status != DeploymentStatus::Experimental {
                return Err(PirError::VerificationFailed(
                    "ARC offer is not explicitly marked experimental".into(),
                ));
            }
            AuthorizationProofV1::ArcExperimental(
                ArcPresentationV1::from_canonical_bytes(proof_bytes.to_vec())
                    .map_err(protocol_decode_error)?,
            )
        }
        _ => {
            return Err(PirError::InvalidState(
                "selected offer has an unsupported scheme/free-mode combination".into(),
            ))
        }
    };
    // Run the protocol's exact offer/scheme compatibility check now. This
    // catches malformed or out-of-family inputs before a bearer is exposed to
    // the network.
    proof
        .encode_for(offer.authorization, offer.free_mode)
        .map_err(protocol_decode_error)?;
    Ok(proof)
}

/// Request one server-fresh, secure-channel-bound free proof-of-work
/// challenge for an exact operation.  The returned challenge is verified
/// against the signed offer, provider, policy, operation and channel exporter.
pub async fn request_pow_challenge_v1(
    transport: &mut dyn PirTransport,
    accepted: &AcceptedServicePolicyV1,
    scope_id: [u8; 32],
    offer_id: u32,
    operation: OperationStartV1,
    now_unix: u64,
) -> PirResult<PowChallengeResponseV1> {
    let exporter = require_secure_service_channel(transport)?;
    accepted.verify_service_authorization_exporter_v1(&exporter)?;
    let frame = build_pow_challenge_request_v1(accepted, scope_id, offer_id, operation.clone())?;
    let response = transport.roundtrip(&frame).await?;
    accept_pow_challenge_response_v1(
        &response, accepted, scope_id, offer_id, operation, &exporter, now_unix,
    )
}

/// Build a canonical secure-channel PoW request without sending it.
pub fn build_pow_challenge_request_v1(
    accepted: &AcceptedServicePolicyV1,
    scope_id: [u8; 32],
    offer_id: u32,
    operation: OperationStartV1,
) -> PirResult<Vec<u8>> {
    let (scope_policy, offer) =
        service_offer_for_operation_v1(accepted, &scope_id, offer_id, &operation)?;
    if offer.authorization != AuthScheme::FreeV1 || offer.free_mode != FreeModeV1::ProofOfWork {
        return Err(PirError::InvalidState(
            "selected service offer is not proof-of-work".into(),
        ));
    }
    debug_assert_eq!(scope_policy.scope.provider_id, accepted.policy.provider_id);
    let request = PowChallengeRequestV1 {
        policy_digest: accepted.policy_digest,
        scope_id,
        offer_id,
        operation,
    };
    Ok(encode_request(
        REQ_POW_CHALLENGE_V1,
        &request.encode_padded().map_err(protocol_decode_error)?,
    ))
}

/// Verify a PoW response payload against the exact signed offer, operation,
/// secure-channel exporter and trusted wall clock.
pub fn accept_pow_challenge_response_v1(
    response: &[u8],
    accepted: &AcceptedServicePolicyV1,
    scope_id: [u8; 32],
    offer_id: u32,
    operation: OperationStartV1,
    exporter: &[u8; 32],
    now_unix: u64,
) -> PirResult<PowChallengeResponseV1> {
    if now_unix == 0 {
        return Err(PirError::InvalidState(
            "trusted wall clock is required for proof-of-work challenge verification".into(),
        ));
    }
    let (_scope_policy, offer) =
        service_offer_for_operation_v1(accepted, &scope_id, offer_id, &operation)?;
    if offer.authorization != AuthScheme::FreeV1 || offer.free_mode != FreeModeV1::ProofOfWork {
        return Err(PirError::InvalidState(
            "selected service offer is not proof-of-work".into(),
        ));
    }
    let request = PowChallengeRequestV1 {
        policy_digest: accepted.policy_digest,
        scope_id,
        offer_id,
        operation,
    };
    let body = expect_response_opcode(response, RESP_POW_CHALLENGE_V1, "proof-of-work challenge")?;
    let challenge = PowChallengeResponseV1::decode_padded(body).map_err(protocol_decode_error)?;
    challenge
        .verify_for_request(&accepted.policy.provider_id, &request, exporter)
        .map_err(protocol_verification_error)?;
    if challenge.difficulty_bits != offer.free_pow_difficulty_bits {
        return Err(PirError::VerificationFailed(
            "proof-of-work challenge difficulty does not match signed offer".into(),
        ));
    }
    if now_unix < challenge.issued_at_unix || now_unix > challenge.expires_at_unix {
        return Err(PirError::VerificationFailed(
            "proof-of-work challenge is outside its validity window".into(),
        ));
    }
    Ok(challenge)
}

/// Dangerous unpaired primitive: present one provider-local capability without
/// proving that the peer provider selection passed strict independence checks.
///
/// The caller must retire a single-use credential (or durably advance ARC
/// state) before entering this function. Any transport/protocol error after
/// entry is an ambiguous spend outcome; this function never retries.
pub async fn dangerous_unpaired_authorize_service_operation_v1(
    transport: &mut dyn PirTransport,
    accepted: &AcceptedServicePolicyV1,
    scope_id: [u8; 32],
    offer_id: u32,
    operation: OperationStartV1,
    proof: AuthorizationProofV1,
) -> PirResult<pir_service_protocol::AuthGrantedV1> {
    let exporter = require_secure_service_channel(transport)?;
    accepted.verify_service_authorization_exporter_v1(&exporter)?;
    let request = dangerous_unpaired_build_service_authorization_request_v1(
        accepted, scope_id, offer_id, operation, proof,
    )?;
    let response = transport.roundtrip(&request).await?;
    dangerous_unpaired_accept_service_authorization_response_v1(&response, accepted, scope_id)
}

/// Present the exact already-issued credential selected by a retained
/// redemption handle. The grace deadline and secure-channel exporter are
/// rechecked immediately before the one-shot network request; this function
/// never retries an ambiguous spend.
pub async fn dangerous_unpaired_authorize_retained_service_redemption_v1(
    transport: &mut dyn PirTransport,
    accepted: &AcceptedRetiredServiceRedemptionV1,
    operation: OperationStartV1,
    proof: AuthorizationProofV1,
    now_unix: u64,
) -> PirResult<pir_service_protocol::AuthGrantedV1> {
    let exporter = require_secure_service_channel(transport)?;
    accepted.verify_service_authorization_exporter_v1(&exporter)?;
    let request = dangerous_unpaired_build_retained_service_authorization_request_v1(
        accepted, operation, proof, now_unix,
    )?;
    let response = transport.roundtrip(&request).await?;
    dangerous_unpaired_accept_retained_service_authorization_response_v1(&response, accepted)
}

/// Build the one-shot AuthBegin for the exact retained digest/scope/offer.
/// There is no parameter with which a caller could substitute any of them.
pub fn dangerous_unpaired_build_retained_service_authorization_request_v1(
    accepted: &AcceptedRetiredServiceRedemptionV1,
    operation: OperationStartV1,
    proof: AuthorizationProofV1,
    now_unix: u64,
) -> PirResult<Vec<u8>> {
    let verified_offer = accepted.verified_offer_for_redemption_v1(now_unix)?;
    let scope = verified_offer.scope();
    let (required_backend, required_workload) = operation.required_service();
    if scope.backend != required_backend || scope.workload != required_workload {
        return Err(PirError::InvalidState(
            "retained service scope does not authorize this backend workload".into(),
        ));
    }
    let offer = verified_offer.offer();
    let proof = proof
        .encode_for(offer.authorization, offer.free_mode)
        .map_err(protocol_decode_error)?;
    let auth = AuthBeginV1 {
        policy_digest: accepted.policy_digest,
        scope_id: accepted.scope_id,
        offer_id: accepted.offer_id,
        scheme: offer.authorization,
        key_id: offer.key_id.clone(),
        operation,
        proof,
    };
    Ok(encode_request(
        REQ_AUTH_BEGIN_V1,
        &auth.encode_padded().map_err(protocol_decode_error)?,
    ))
}

/// Dangerous unpaired primitive: build a one-shot authorization request
/// without checking the peer provider. The caller is responsible for
/// retiring/advancing the proof before releasing these bytes to the network.
pub fn dangerous_unpaired_build_service_authorization_request_v1(
    accepted: &AcceptedServicePolicyV1,
    scope_id: [u8; 32],
    offer_id: u32,
    operation: OperationStartV1,
    proof: AuthorizationProofV1,
) -> PirResult<Vec<u8>> {
    let (_scope_policy, offer) =
        service_offer_for_operation_v1(accepted, &scope_id, offer_id, &operation)?;
    let proof = proof
        .encode_for(offer.authorization, offer.free_mode)
        .map_err(protocol_decode_error)?;
    let auth = AuthBeginV1 {
        policy_digest: accepted.policy_digest,
        scope_id,
        offer_id,
        scheme: offer.authorization,
        key_id: offer.key_id.clone(),
        operation,
        proof,
    };
    Ok(encode_request(
        REQ_AUTH_BEGIN_V1,
        &auth.encode_padded().map_err(protocol_decode_error)?,
    ))
}

/// Dangerous unpaired primitive: verify one provider's authorization response
/// without checking the peer provider. A rejected or malformed result never
/// creates a grant and must not cause the caller to replay its proof.
pub fn dangerous_unpaired_accept_service_authorization_response_v1(
    response: &[u8],
    accepted: &AcceptedServicePolicyV1,
    scope_id: [u8; 32],
) -> PirResult<pir_service_protocol::AuthGrantedV1> {
    let scope_policy = accepted
        .policy
        .scopes
        .iter()
        .find(|entry| entry.scope.scope_id() == scope_id)
        .ok_or_else(|| PirError::InvalidState("selected service scope is not in policy".into()))?;
    let body = expect_response_opcode(response, RESP_AUTH_RESULT_V1, "service authorization")?;
    match AuthResultV1::decode(body).map_err(protocol_decode_error)? {
        AuthResultV1::Granted(grant) => {
            if grant.scope_id != scope_id
                || grant.enforced_profile != scope_policy.scope.entitlement_profile
            {
                return Err(PirError::VerificationFailed(
                    "service authorization grant does not match selected scope/profile".into(),
                ));
            }
            Ok(grant)
        }
        AuthResultV1::Rejected(rejected) => {
            Err(auth_rejection(rejected.code, rejected.retry_after_ms))
        }
    }
}

/// Verify an authorization result against the exact scope/profile fixed by a
/// retained redemption handle.
pub fn dangerous_unpaired_accept_retained_service_authorization_response_v1(
    response: &[u8],
    accepted: &AcceptedRetiredServiceRedemptionV1,
) -> PirResult<pir_service_protocol::AuthGrantedV1> {
    let scope_policy = accepted
        .policy
        .scopes
        .iter()
        .find(|entry| entry.scope.scope_id() == accepted.scope_id)
        .ok_or_else(|| PirError::InvalidState("retained service scope is not in policy".into()))?;
    let body = expect_response_opcode(
        response,
        RESP_AUTH_RESULT_V1,
        "retained service authorization",
    )?;
    match AuthResultV1::decode(body).map_err(protocol_decode_error)? {
        AuthResultV1::Granted(grant) => {
            if grant.scope_id != accepted.scope_id
                || grant.enforced_profile != scope_policy.scope.entitlement_profile
            {
                return Err(PirError::VerificationFailed(
                    "retained authorization grant does not match selected scope/profile".into(),
                ));
            }
            Ok(grant)
        }
        AuthResultV1::Rejected(rejected) => {
            Err(auth_rejection(rejected.code, rejected.retry_after_ms))
        }
    }
}

fn service_offer_for_operation_v1<'a>(
    accepted: &'a AcceptedServicePolicyV1,
    scope_id: &[u8; 32],
    offer_id: u32,
    operation: &OperationStartV1,
) -> PirResult<(
    &'a pir_service_protocol::ServiceScopePolicyV1,
    &'a pir_service_protocol::ServiceOfferV1,
)> {
    let scope_policy = accepted
        .policy
        .scopes
        .iter()
        .find(|entry| &entry.scope.scope_id() == scope_id)
        .ok_or_else(|| PirError::InvalidState("selected service scope is not in policy".into()))?;
    let offer = scope_policy
        .offers
        .iter()
        .find(|offer| offer.offer_id == offer_id)
        .ok_or_else(|| PirError::InvalidState("selected service offer is not in policy".into()))?;
    let (required_backend, required_workload) = operation.required_service();
    if scope_policy.scope.provider_id != accepted.policy.provider_id
        || scope_policy.scope.backend != required_backend
        || scope_policy.scope.workload != required_workload
    {
        return Err(PirError::InvalidState(
            "selected service scope does not authorize this backend workload".into(),
        ));
    }
    Ok((scope_policy, offer))
}

fn require_secure_service_channel(transport: &dyn PirTransport) -> PirResult<[u8; 32]> {
    transport
        .service_authorization_exporter_v1()
        .ok_or_else(|| {
            PirError::VerificationFailed(
                "service admission requires an authenticated secure-channel upgrade".into(),
            )
        })
}

fn require_empty_proof(bytes: &[u8]) -> PirResult<()> {
    if bytes.is_empty() {
        Ok(())
    } else {
        Err(PirError::Encode(
            "selected free offer requires an empty authorization proof".into(),
        ))
    }
}

fn expect_response_opcode<'a>(
    response: &'a [u8],
    expected: u8,
    label: &'static str,
) -> PirResult<&'a [u8]> {
    let Some((&opcode, body)) = response.split_first() else {
        return Err(PirError::Protocol(format!("empty {label} response")));
    };
    if opcode == 0xff {
        return Err(PirError::ServerError(format!("{label} rejected")));
    }
    if opcode != expected {
        return Err(PirError::UnexpectedResponse {
            expected: label,
            actual: format!("opcode 0x{opcode:02x}"),
        });
    }
    Ok(body)
}

fn auth_rejection(code: AuthRejectCode, retry_after_ms: u32) -> PirError {
    // Keep wire-facing proof failures coarse. In particular, do not echo
    // credential bytes or server implementation detail into logs/UI.
    let reason = match code {
        AuthRejectCode::UnsupportedVersion => "unsupported-version",
        AuthRejectCode::UnsupportedScheme => "unsupported-scheme",
        AuthRejectCode::ScopeUnavailable => "scope-unavailable",
        AuthRejectCode::WrongScope => "wrong-scope",
        AuthRejectCode::InvalidOrSpent => "invalid-or-spent",
        AuthRejectCode::ServerBusy => "server-busy",
        AuthRejectCode::SecureChannelRequired => "secure-channel-required",
        AuthRejectCode::PolicyChanged => "policy-changed",
        AuthRejectCode::InternalAfterSpend => "internal-after-spend",
    };
    PirError::ServerError(format!(
        "service authorization rejected: {reason}; retry_after_ms={retry_after_ms}"
    ))
}

fn protocol_decode_error(error: pir_service_protocol::ServiceProtocolError) -> PirError {
    PirError::Decode(format!("service protocol: {error}"))
}

fn protocol_verification_error(error: pir_service_protocol::ServiceProtocolError) -> PirError {
    PirError::VerificationFailed(format!("service policy: {error}"))
}

fn decode_auth_scheme(value: u8) -> PirResult<AuthScheme> {
    match value {
        1 => Ok(AuthScheme::FreeV1),
        2 => Ok(AuthScheme::Bolt11DirectReceiptV1),
        3 => Ok(AuthScheme::CashuEcashV1),
        4 => Ok(AuthScheme::BitcoinPirCashuBatV1),
        5 => Ok(AuthScheme::ArcV1Experimental),
        _ => Err(PirError::Decode(
            "service policy checkpoint contains an unknown authorization scheme".into(),
        )),
    }
}

struct CheckpointDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CheckpointDecoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> PirResult<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| PirError::Decode("truncated service policy checkpoint".into()))?;
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> PirResult<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> PirResult<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> PirResult<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn fixed<const N: usize>(&mut self) -> PirResult<[u8; N]> {
        Ok(self.take(N)?.try_into().unwrap())
    }

    fn finish(self) -> PirResult<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(PirError::Decode(
                "service policy checkpoint has trailing bytes".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use pir_sdk::PirMetrics;
    use pir_service_protocol::{
        paid_receipt_key_id, AcquisitionMethod, AuthGrantedV1, AuthPaddingClassV1, BackendId,
        CredentialKeyBindingClaimsV1, CredentialKeyBindingV1, CredentialUnitV1, DatasetBindingV1,
        EntitlementLimitsV1, PaidReceiptBindingV1, PriceV1, PrivacyLeakageV1, ServiceOfferV1,
        ServiceScopePolicyV1, ServiceScopeV1, VerificationMode, WorkloadId,
    };
    use std::sync::Arc;

    struct ScriptedSecureTransport {
        responses: std::collections::VecDeque<Vec<u8>>,
        sent: Vec<Vec<u8>>,
        exporter: [u8; 32],
    }

    #[async_trait]
    impl PirTransport for ScriptedSecureTransport {
        async fn send(&mut self, _: Vec<u8>) -> PirResult<()> {
            unimplemented!()
        }
        async fn recv(&mut self) -> PirResult<Vec<u8>> {
            unimplemented!()
        }
        async fn roundtrip(&mut self, request: &[u8]) -> PirResult<Vec<u8>> {
            self.sent.push(request.to_vec());
            self.responses
                .pop_front()
                .ok_or_else(|| PirError::ConnectionClosed("script exhausted".into()))
        }
        async fn close(&mut self) -> PirResult<()> {
            Ok(())
        }
        fn url(&self) -> &str {
            "mock://service"
        }
        fn service_authorization_exporter_v1(&self) -> Option<[u8; 32]> {
            Some(self.exporter)
        }
        fn set_metrics_recorder(&mut self, _: Option<Arc<dyn PirMetrics>>, _: &'static str) {}
    }

    fn policy() -> (ServicePolicyV1, VerifyingKey, [u8; 32], [u8; 32]) {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let provider_id = [4; 32];
        let scope = ServiceScopeV1 {
            provider_id,
            backend: BackendId::DpfPirV1,
            workload: WorkloadId::DpfEvaluateJobV1,
            protocol_version: 1,
            dataset: DatasetBindingV1::Class { class_id: 1 },
            operation_profile: 1,
            entitlement_profile: 1,
        };
        let scope_id = scope.scope_id();
        let policy = ServicePolicyV1::sign(
            provider_id,
            1,
            100,
            200,
            AuthPaddingClassV1::Class16KiB,
            vec![ServiceScopePolicyV1 {
                scope,
                limits: EntitlementLimitsV1 {
                    max_logical_inputs: 10,
                    max_frames: 10,
                    max_request_bytes: 1_000_000,
                    max_response_bytes: 1_000_000,
                    max_wall_time_ms: 10_000,
                    max_concurrent_sockets: 1,
                    max_hint_groups: 0,
                    max_work_units: 1_000,
                },
                offers: vec![ServiceOfferV1 {
                    offer_id: 7,
                    acquisition: AcquisitionMethod::FreeV1,
                    free_mode: FreeModeV1::OpenBestEffort,
                    free_quota: 0,
                    free_window_seconds: 0,
                    free_pow_difficulty_bits: 0,
                    priority_class: 1,
                    authorization: AuthScheme::FreeV1,
                    verification: VerificationMode::ProviderLocal,
                    deployment_status: DeploymentStatus::Stable,
                    price: PriceV1::Free,
                    issuer_id: [0; 32],
                    key_id: Vec::new(),
                    credential_binding: None,
                    cashu_mint_manifest: None,
                    endpoint: String::new(),
                    invoice_expiry_seconds: 0,
                    claim_window_seconds: 0,
                    minimum_credential_validity_seconds: 60,
                    retired_policy_grace_seconds: 0,
                    credential_count: 1,
                    credential_presentation_limit: 1,
                    privacy_leakage: PrivacyLeakageV1::NONE,
                }],
            }],
            &signing,
        )
        .unwrap();
        (policy, signing.verifying_key(), provider_id, scope_id)
    }

    fn retained_policy() -> (
        ServicePolicyV1,
        VerifyingKey,
        [u8; 32],
        [u8; 32],
        ed25519_dalek::SigningKey,
    ) {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let provider_id = [4; 32];
        let scope = ServiceScopeV1 {
            provider_id,
            backend: BackendId::DpfPirV1,
            workload: WorkloadId::DpfEvaluateJobV1,
            protocol_version: 1,
            dataset: DatasetBindingV1::Class { class_id: 1 },
            operation_profile: 1,
            entitlement_profile: 3,
        };
        let scope_id = scope.scope_id();
        let receipt_key = ed25519_dalek::SigningKey::from_bytes(&[5; 32]);
        let credential_key_id = paid_receipt_key_id(&receipt_key.verifying_key()).to_vec();
        let binding = CredentialKeyBindingV1::sign(
            CredentialKeyBindingClaimsV1 {
                provider_id,
                scope_id,
                offer_id: 9,
                scheme: AuthScheme::Bolt11DirectReceiptV1,
                keyset_epoch: 1,
                entitlement_profile: 3,
                unit: CredentialUnitV1::Entitlement,
                amount: 1,
                presentation_limit: 1,
                not_before: 50,
                not_after: 1_500,
                credential_key_id: credential_key_id.clone(),
                verification_key: receipt_key.verifying_key().to_bytes().to_vec(),
            },
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
        )
        .unwrap();
        let policy = ServicePolicyV1::sign(
            provider_id,
            1,
            100,
            200,
            AuthPaddingClassV1::Class16KiB,
            vec![ServiceScopePolicyV1 {
                scope,
                limits: EntitlementLimitsV1 {
                    max_logical_inputs: 10,
                    max_frames: 10,
                    max_request_bytes: 1_000_000,
                    max_response_bytes: 1_000_000,
                    max_wall_time_ms: 10_000,
                    max_concurrent_sockets: 1,
                    max_hint_groups: 0,
                    max_work_units: 1_000,
                },
                offers: vec![ServiceOfferV1 {
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
                    issuer_id: binding.issuer_id,
                    key_id: credential_key_id,
                    credential_binding: Some(binding),
                    cashu_mint_manifest: None,
                    endpoint: "https://issuer.invalid".into(),
                    invoice_expiry_seconds: 600,
                    claim_window_seconds: 600,
                    minimum_credential_validity_seconds: 100,
                    retired_policy_grace_seconds: 1_300,
                    credential_count: 1,
                    credential_presentation_limit: 1,
                    privacy_leakage: PrivacyLeakageV1::from_bits(
                        PrivacyLeakageV1::DIRECT_PAYMENT_TO_SPEND,
                    )
                    .unwrap(),
                }],
            }],
            &signing,
        )
        .unwrap();
        (
            policy,
            signing.verifying_key(),
            provider_id,
            scope_id,
            receipt_key,
        )
    }

    fn policy_wire_response(policy: ServicePolicyV1) -> Vec<u8> {
        let body = ServicePolicyResponseV1 { policy }.encode().unwrap();
        let mut response = vec![RESP_SERVICE_POLICY_V1];
        response.extend_from_slice(&body);
        response
    }

    #[test]
    fn checkpoint_roundtrip_is_canonical_and_provider_local() {
        let checkpoint = ServicePolicyCheckpointV1 {
            rollback_guard: PolicyRollbackGuardV1 {
                highest_epoch: 8,
                digest_at_highest_epoch: [1; 32],
            },
            epoch_floors: ServicePolicyEpochFloorsV1 {
                credential_keysets: vec![CredentialKeysetEpochFloorV1 {
                    scope_id: [2; 32],
                    scheme: AuthScheme::BitcoinPirCashuBatV1,
                    issuer_id: [3; 32],
                    minimum_epoch: 4,
                }],
                cashu_manifests: vec![CashuManifestEpochFloorV1 {
                    mint_id: [5; 32],
                    unit: "sat".into(),
                    minimum_epoch: 6,
                }],
            },
        };
        let encoded = checkpoint.encode().unwrap();
        assert_eq!(
            ServicePolicyCheckpointV1::decode(&encoded).unwrap(),
            checkpoint
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert!(ServicePolicyCheckpointV1::decode(&trailing).is_err());
    }

    #[tokio::test]
    async fn policy_then_free_authorization_uses_signed_offer_fields() {
        let (policy, verifying_key, provider_id, scope_id) = policy();
        let policy_body = ServicePolicyResponseV1 { policy }.encode().unwrap();
        let mut policy_response = vec![RESP_SERVICE_POLICY_V1];
        policy_response.extend_from_slice(&policy_body);
        let granted = AuthResultV1::Granted(AuthGrantedV1 {
            scope_id,
            enforced_profile: 1,
            expires_in_ms: 10_000,
            harmony_attach: None,
        })
        .encode()
        .unwrap();
        let mut auth_response = vec![RESP_AUTH_RESULT_V1];
        auth_response.extend_from_slice(&granted);
        let mut transport = ScriptedSecureTransport {
            responses: [policy_response, auth_response].into(),
            sent: Vec::new(),
            exporter: [9; 32],
        };

        let accepted = fetch_verified_service_policy_v1(
            &mut transport,
            provider_id,
            &verifying_key,
            150,
            &ServicePolicyCheckpointV1::initial(),
        )
        .await
        .unwrap();
        let proof =
            dangerous_unpaired_build_authorization_proof_v1(&accepted, &scope_id, 7, &[]).unwrap();
        dangerous_unpaired_authorize_service_operation_v1(
            &mut transport,
            &accepted,
            scope_id,
            7,
            OperationStartV1::DpfQuery { db_id: 0 },
            proof,
        )
        .await
        .unwrap();

        assert_eq!(transport.sent[0][4], REQ_SERVICE_POLICY_V1);
        assert_eq!(transport.sent[1][4], REQ_AUTH_BEGIN_V1);
        let decoded = AuthBeginV1::decode_padded(&transport.sent[1][5..]).unwrap();
        assert_eq!(decoded.scheme, AuthScheme::FreeV1);
        assert!(decoded.key_id.is_empty());
        assert!(decoded.proof.is_empty());
    }

    #[tokio::test]
    async fn authorization_rejects_policy_from_a_previous_secure_channel_before_send() {
        let (policy, verifying_key, provider_id, scope_id) = policy();
        let policy_body = ServicePolicyResponseV1 { policy }.encode().unwrap();
        let mut policy_response = vec![RESP_SERVICE_POLICY_V1];
        policy_response.extend_from_slice(&policy_body);
        let mut transport = ScriptedSecureTransport {
            responses: [policy_response].into(),
            sent: Vec::new(),
            exporter: [9; 32],
        };
        let accepted = fetch_verified_service_policy_v1(
            &mut transport,
            provider_id,
            &verifying_key,
            150,
            &ServicePolicyCheckpointV1::initial(),
        )
        .await
        .unwrap();
        let proof =
            dangerous_unpaired_build_authorization_proof_v1(&accepted, &scope_id, 7, &[]).unwrap();
        transport.exporter = [8; 32];
        let sent_before = transport.sent.len();
        let error = dangerous_unpaired_authorize_service_operation_v1(
            &mut transport,
            &accepted,
            scope_id,
            7,
            OperationStartV1::DpfQuery { db_id: 0 },
            proof,
        )
        .await
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("different secure-channel session"));
        assert_eq!(transport.sent.len(), sent_before, "no auth bytes escaped");
    }

    #[tokio::test]
    async fn retained_redemption_fetches_exact_digest_and_binds_auth_request() {
        let (policy, verifying_key, provider_id, scope_id, receipt_key) = retained_policy();
        let policy_digest = policy.policy_digest().unwrap();
        let policy_response = policy_wire_response(policy);
        let granted = AuthResultV1::Granted(AuthGrantedV1 {
            scope_id,
            enforced_profile: 3,
            expires_in_ms: 10_000,
            harmony_attach: None,
        })
        .encode()
        .unwrap();
        let mut auth_response = vec![RESP_AUTH_RESULT_V1];
        auth_response.extend_from_slice(&granted);
        let mut transport = ScriptedSecureTransport {
            responses: [policy_response, auth_response].into(),
            sent: Vec::new(),
            exporter: [9; 32],
        };

        let accepted = fetch_retained_service_redemption_v1(
            &mut transport,
            provider_id,
            &verifying_key,
            policy_digest,
            scope_id,
            9,
            250,
        )
        .await
        .unwrap();
        assert_eq!(accepted.policy_digest(), policy_digest);
        assert_eq!(accepted.scope_id(), scope_id);
        assert_eq!(accepted.offer_id(), 9);
        assert_eq!(transport.sent[0].len(), 4 + 1 + 34);
        assert_eq!(transport.sent[0][4], REQ_SERVICE_POLICY_V1);
        assert_eq!(transport.sent[0][5..7], [1, 1]);
        assert_eq!(&transport.sent[0][7..39], &policy_digest);

        let receipt = PaidReceiptV1::sign(
            accepted.policy.scopes[0].offers[0].issuer_id,
            [8; 32],
            PaidReceiptBindingV1 {
                scope_id,
                offer_id: 9,
                policy_digest,
                entitlement_profile: 3,
            },
            100,
            1_500,
            &receipt_key,
        )
        .unwrap();
        let proof = dangerous_unpaired_build_retained_authorization_proof_v1(
            &accepted,
            &receipt.encode().unwrap(),
        )
        .unwrap();
        dangerous_unpaired_authorize_retained_service_redemption_v1(
            &mut transport,
            &accepted,
            OperationStartV1::DpfQuery { db_id: 0 },
            proof,
            250,
        )
        .await
        .unwrap();

        let auth = AuthBeginV1::decode_padded(&transport.sent[1][5..]).unwrap();
        assert_eq!(auth.policy_digest, policy_digest);
        assert_eq!(auth.scope_id, scope_id);
        assert_eq!(auth.offer_id, 9);
        assert_eq!(auth.scheme, AuthScheme::Bolt11DirectReceiptV1);
    }

    #[test]
    fn retained_acceptance_rejects_wrong_digest_expiry_and_free_policy() {
        let (retired_policy, verifying_key, provider_id, scope_id, _) = retained_policy();
        let policy_digest = retired_policy.policy_digest().unwrap();
        let response = policy_wire_response(retired_policy);
        assert!(accept_retained_service_policy_response_v1(
            &response,
            provider_id,
            &verifying_key,
            [6; 32],
            scope_id,
            9,
            250,
            [9; 32],
        )
        .is_err());
        assert!(accept_retained_service_policy_response_v1(
            &response,
            provider_id,
            &verifying_key,
            policy_digest,
            scope_id,
            9,
            1_501,
            [9; 32],
        )
        .is_err());

        let (free_policy, free_key, free_provider, free_scope) = policy();
        let free_digest = free_policy.policy_digest().unwrap();
        assert!(accept_retained_service_policy_response_v1(
            &policy_wire_response(free_policy),
            free_provider,
            &free_key,
            free_digest,
            free_scope,
            7,
            150,
            [9; 32],
        )
        .is_err());
    }

    #[tokio::test]
    async fn retained_authorization_rejects_exporter_change_before_send() {
        let (policy, verifying_key, provider_id, scope_id, receipt_key) = retained_policy();
        let policy_digest = policy.policy_digest().unwrap();
        let mut transport = ScriptedSecureTransport {
            responses: [policy_wire_response(policy)].into(),
            sent: Vec::new(),
            exporter: [9; 32],
        };
        let accepted = fetch_retained_service_redemption_v1(
            &mut transport,
            provider_id,
            &verifying_key,
            policy_digest,
            scope_id,
            9,
            250,
        )
        .await
        .unwrap();
        let receipt = PaidReceiptV1::sign(
            accepted.policy.scopes[0].offers[0].issuer_id,
            [8; 32],
            PaidReceiptBindingV1 {
                scope_id,
                offer_id: 9,
                policy_digest,
                entitlement_profile: 3,
            },
            100,
            1_500,
            &receipt_key,
        )
        .unwrap();
        let proof = dangerous_unpaired_build_retained_authorization_proof_v1(
            &accepted,
            &receipt.encode().unwrap(),
        )
        .unwrap();
        transport.exporter = [8; 32];
        let sent_before = transport.sent.len();
        let error = dangerous_unpaired_authorize_retained_service_redemption_v1(
            &mut transport,
            &accepted,
            OperationStartV1::DpfQuery { db_id: 0 },
            proof,
            250,
        )
        .await
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("different secure-channel session"));
        assert_eq!(transport.sent.len(), sent_before);
    }

    #[test]
    fn current_policy_request_remains_the_legacy_one_byte_body() {
        let request = build_service_policy_request_v1();
        assert_eq!(request.len(), 6);
        assert_eq!(u32::from_le_bytes(request[..4].try_into().unwrap()), 2);
        assert_eq!(request[4], REQ_SERVICE_POLICY_V1);
        assert_eq!(request[5], 1);
    }

    #[tokio::test]
    async fn policy_fetch_fails_closed_on_raw_transport() {
        let (_, verifying_key, provider_id, _) = policy();
        struct Raw;
        #[async_trait]
        impl PirTransport for Raw {
            async fn send(&mut self, _: Vec<u8>) -> PirResult<()> {
                Ok(())
            }
            async fn recv(&mut self) -> PirResult<Vec<u8>> {
                Ok(Vec::new())
            }
            async fn roundtrip(&mut self, _: &[u8]) -> PirResult<Vec<u8>> {
                panic!("must not send")
            }
            async fn close(&mut self) -> PirResult<()> {
                Ok(())
            }
            fn url(&self) -> &str {
                "mock://raw"
            }
        }
        let error = fetch_verified_service_policy_v1(
            &mut Raw,
            provider_id,
            &verifying_key,
            150,
            &ServicePolicyCheckpointV1::initial(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("secure-channel"));
    }
}
