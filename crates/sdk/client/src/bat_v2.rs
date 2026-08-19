//! Class-bound, restart-safe BOLT11 acquisition for issuer-wide BAT V2.
//!
//! HTTP remains caller-owned.  This module accepts a provider offer only long
//! enough to prove membership in one exact issuer-signed class; every durable
//! acquisition object thereafter contains class coordinates, never provider,
//! policy, scope, or offer coordinates.

use core::fmt;

use pir_payment_crypto::{sign_bip340_prehash_v1, verify_quote_claim_v1};
use pir_sdk::{PirError, PirResult};
use pir_service_protocol::{
    BatAcceptanceClassV2, BatV2IssuanceRequestV2, BatV2IssuanceResponseV2,
    BitcoinPirCashuBatIssuanceRequestItemV1, Bolt11BatV2ClaimEnvelopeV2, Bolt11BatV2QuoteIntentV2,
    Bolt11QuoteClaimV1, Bolt11QuoteKeyDelegationV1, Bolt11QuoteStatusRequestV1,
    Bolt11QuoteStatusV1, Bolt11QuoteV1, CheckedBatV2IssuanceResponseV2, ParsedBolt11InvoiceV1,
    VerifiedBatAcceptanceMemberV2,
};
use zeroize::{Zeroize, Zeroizing};

use crate::bolt11::Bolt11QuoteKeyCheckpointV1;

/// A current provider policy offer proven to be an exact member of one
/// issuer-signed BAT V2 acceptance class.
///
/// The member is retained only until the class-only quote intent is prepared;
/// it is intentionally absent from [`PreparedBolt11BatV2QuoteV2`] and every
/// recovery record derived from that type.
#[derive(Clone, Debug)]
pub struct VerifiedCurrentBatV2OfferV2 {
    class: BatAcceptanceClassV2,
    member: VerifiedBatAcceptanceMemberV2,
}

impl VerifiedCurrentBatV2OfferV2 {
    pub(crate) const fn new(
        class: BatAcceptanceClassV2,
        member: VerifiedBatAcceptanceMemberV2,
    ) -> Self {
        Self { class, member }
    }

    pub const fn class(&self) -> &BatAcceptanceClassV2 {
        &self.class
    }

    pub const fn member(&self) -> &VerifiedBatAcceptanceMemberV2 {
        &self.member
    }

    pub fn class_bytes(&self) -> PirResult<Vec<u8>> {
        self.class.encode().map_err(protocol_encode_error)
    }

    pub fn class_digest(&self) -> PirResult<[u8; 32]> {
        self.class
            .class_digest()
            .map_err(protocol_verification_error)
    }

    pub const fn class_id(&self) -> [u8; 32] {
        self.class.class_id
    }

    pub const fn class_key_epoch(&self) -> u64 {
        self.class.key_epoch
    }

    pub fn bat_key_id(&self) -> [u8; 32] {
        self.class.bat_key_id()
    }
}

/// A class-only quote intent whose signed class, selected current member,
/// quote-key delegation, and durable rollback stream have all been checked.
#[derive(Clone, Debug)]
pub struct PreparedBolt11BatV2QuoteV2 {
    intent: Bolt11BatV2QuoteIntentV2,
    class: BatAcceptanceClassV2,
    delegation: Bolt11QuoteKeyDelegationV1,
    advanced_checkpoint: Bolt11QuoteKeyCheckpointV1,
}

impl PreparedBolt11BatV2QuoteV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_current_offer(
        verified: &VerifiedCurrentBatV2OfferV2,
        delegation_bytes: &[u8],
        checkpoint: &Bolt11QuoteKeyCheckpointV1,
        now_unix: u64,
        claim_pubkey_xonly: [u8; 32],
        idempotency_key: [u8; 32],
    ) -> PirResult<Self> {
        let delegation =
            Bolt11QuoteKeyDelegationV1::decode(delegation_bytes).map_err(protocol_decode_error)?;
        let (intent, advanced_guard) =
            Bolt11BatV2QuoteIntentV2::from_verified_class_member_guarded(
                verified.member(),
                verified.class(),
                &delegation,
                checkpoint.rollback_guard_v1(),
                now_unix,
                claim_pubkey_xonly,
                idempotency_key,
            )
            .map_err(protocol_verification_error)?;
        Ok(Self {
            intent,
            class: verified.class.clone(),
            delegation,
            advanced_checkpoint: Bolt11QuoteKeyCheckpointV1::from_rollback_guard_v1(advanced_guard),
        })
    }

    pub fn restore(
        intent_bytes: &[u8],
        class_bytes: &[u8],
        delegation_bytes: &[u8],
        checkpoint_bytes: &[u8],
        now_unix: u64,
    ) -> PirResult<Self> {
        let intent =
            Bolt11BatV2QuoteIntentV2::decode(intent_bytes).map_err(protocol_decode_error)?;
        let class = BatAcceptanceClassV2::decode(class_bytes).map_err(protocol_decode_error)?;
        let delegation =
            Bolt11QuoteKeyDelegationV1::decode(delegation_bytes).map_err(protocol_decode_error)?;
        let advanced_checkpoint = Bolt11QuoteKeyCheckpointV1::decode(checkpoint_bytes)?;
        let verified = intent
            .verify_for_class_guarded(
                &class,
                &delegation,
                advanced_checkpoint.rollback_guard_v1(),
                now_unix,
            )
            .map_err(protocol_verification_error)?;
        if verified.advanced_guard() != *advanced_checkpoint.rollback_guard_v1() {
            return Err(PirError::VerificationFailed(
                "restored BAT V2 quote-key checkpoint differs from the intent".into(),
            ));
        }
        Ok(Self {
            intent,
            class,
            delegation,
            advanced_checkpoint,
        })
    }

    pub const fn intent(&self) -> &Bolt11BatV2QuoteIntentV2 {
        &self.intent
    }

    pub const fn class(&self) -> &BatAcceptanceClassV2 {
        &self.class
    }

    pub const fn delegation(&self) -> &Bolt11QuoteKeyDelegationV1 {
        &self.delegation
    }

    pub fn intent_bytes(&self) -> PirResult<Vec<u8>> {
        self.intent.encode().map_err(protocol_encode_error)
    }

    pub fn class_bytes(&self) -> PirResult<Vec<u8>> {
        self.class.encode().map_err(protocol_encode_error)
    }

    pub fn delegation_bytes(&self) -> PirResult<Vec<u8>> {
        self.delegation.encode().map_err(protocol_encode_error)
    }

    pub fn quote_key_checkpoint_bytes(&self) -> Vec<u8> {
        self.advanced_checkpoint.encode()
    }

    pub fn accept_initial_quote_for_payment(
        &self,
        quote_bytes: &[u8],
        now_unix: u64,
    ) -> PirResult<AcceptedBolt11BatV2QuoteV2> {
        let quote = Bolt11QuoteV1::decode(quote_bytes).map_err(protocol_decode_error)?;
        let parsed =
            ParsedBolt11InvoiceV1::parse(&quote.invoice).map_err(protocol_verification_error)?;
        quote
            .verify_bat_v2_for_payment(
                &self.intent,
                &self.class,
                &self.delegation,
                &parsed,
                now_unix,
            )
            .map_err(protocol_verification_error)?;
        Ok(AcceptedBolt11BatV2QuoteV2 { quote })
    }

    pub fn restore_quote_snapshot(
        &self,
        quote_bytes: &[u8],
        now_unix: u64,
    ) -> PirResult<AcceptedBolt11BatV2QuoteV2> {
        let quote = Bolt11QuoteV1::decode(quote_bytes).map_err(protocol_decode_error)?;
        let parsed =
            ParsedBolt11InvoiceV1::parse(&quote.invoice).map_err(protocol_verification_error)?;
        quote
            .verify_bat_v2_snapshot(
                &self.intent,
                &self.class,
                &self.delegation,
                &parsed,
                now_unix,
            )
            .map_err(protocol_verification_error)?;
        Ok(AcceptedBolt11BatV2QuoteV2 { quote })
    }

    pub fn build_status_request(
        &self,
        quote: &AcceptedBolt11BatV2QuoteV2,
        claim_secret_key: &[u8; 32],
        requested_at: u64,
        request_nonce: [u8; 32],
        auxiliary_randomness: [u8; 32],
    ) -> PirResult<Vec<u8>> {
        let mut request = Bolt11QuoteStatusRequestV1 {
            issuer_id: self.intent.issuer_id,
            quote_id: quote.quote.quote_id,
            quote_request_digest: self
                .intent
                .request_digest()
                .map_err(protocol_encode_error)?,
            claim_pubkey_xonly: self.intent.claim_pubkey_xonly,
            requested_at,
            request_nonce,
            signature: [1; 64],
        };
        let digest = request
            .bip340_signing_digest()
            .map_err(protocol_encode_error)?;
        let (public_key, signature) =
            sign_bip340_prehash_v1(claim_secret_key, &digest, &auxiliary_randomness)
                .map_err(payment_crypto_error)?;
        if public_key != self.intent.claim_pubkey_xonly {
            return Err(PirError::VerificationFailed(
                "claim secret does not match the BAT V2 quote intent".into(),
            ));
        }
        request.signature = signature;
        request.encode().map_err(protocol_encode_error)
    }

    pub fn prepare_claim(
        &self,
        quote: &AcceptedBolt11BatV2QuoteV2,
        items: Vec<BitcoinPirCashuBatIssuanceRequestItemV1>,
        claim_secret_key: &[u8; 32],
        auxiliary_randomness: [u8; 32],
        now_unix: u64,
    ) -> PirResult<PreparedBolt11BatV2ClaimV2> {
        let parsed = ParsedBolt11InvoiceV1::parse(&quote.quote.invoice)
            .map_err(protocol_verification_error)?;
        let verified_quote = quote
            .quote
            .verify_bat_v2_for_claim_submission(
                &self.intent,
                &self.class,
                &self.delegation,
                &parsed,
                now_unix,
            )
            .map_err(protocol_verification_error)?;
        let request = BatV2IssuanceRequestV2 {
            issuer_id: self.intent.issuer_id,
            quote_id: quote.quote.quote_id,
            quote_request_digest: quote.quote.request_digest,
            class_id: self.intent.class_id,
            class_digest: self.intent.class_digest,
            class_key_epoch: self.intent.class_key_epoch,
            bat_key_id: self.intent.bat_key_id,
            items,
        };
        let credential_request_digest = request.request_digest().map_err(protocol_encode_error)?;
        let mut claim = Bolt11QuoteClaimV1 {
            issuer_id: self.intent.issuer_id,
            quote_id: quote.quote.quote_id,
            quote_request_digest: quote.quote.request_digest,
            credential_request_digest,
            claim_pubkey_xonly: self.intent.claim_pubkey_xonly,
            idempotency_key: self.intent.idempotency_key,
            signature: [1; 64],
        };
        let digest = claim
            .bip340_signing_digest()
            .map_err(protocol_encode_error)?;
        let (public_key, signature) =
            sign_bip340_prehash_v1(claim_secret_key, &digest, &auxiliary_randomness)
                .map_err(payment_crypto_error)?;
        if public_key != self.intent.claim_pubkey_xonly {
            return Err(PirError::VerificationFailed(
                "claim secret does not match the BAT V2 quote intent".into(),
            ));
        }
        claim.signature = signature;
        let unverified = request
            .verify_for_verified_quote(&claim, &verified_quote, now_unix)
            .map_err(protocol_verification_error)?;
        verify_quote_claim_v1(&unverified).map_err(payment_crypto_error)?;
        let envelope = Bolt11BatV2ClaimEnvelopeV2 {
            quote_intent: self.intent.clone(),
            claim,
            credential_request: request.clone(),
        };
        let mut envelope_bytes = Zeroizing::new(envelope.encode().map_err(protocol_encode_error)?);
        Ok(PreparedBolt11BatV2ClaimV2 {
            request,
            envelope_bytes: core::mem::take(&mut *envelope_bytes),
        })
    }

    pub fn restore_claim(&self, envelope_bytes: &[u8]) -> PirResult<PreparedBolt11BatV2ClaimV2> {
        let envelope =
            Bolt11BatV2ClaimEnvelopeV2::decode(envelope_bytes).map_err(protocol_decode_error)?;
        if envelope.quote_intent != self.intent
            || envelope.claim.issuer_id != self.intent.issuer_id
            || envelope.claim.quote_request_digest
                != self
                    .intent
                    .request_digest()
                    .map_err(protocol_encode_error)?
            || envelope.claim.claim_pubkey_xonly != self.intent.claim_pubkey_xonly
            || envelope.claim.idempotency_key != self.intent.idempotency_key
        {
            return Err(PirError::VerificationFailed(
                "restored BAT V2 claim differs from the verified class-only intent".into(),
            ));
        }
        let mut canonical = Zeroizing::new(envelope.encode().map_err(protocol_encode_error)?);
        if canonical.as_slice() != envelope_bytes {
            return Err(PirError::Decode(
                "restored BAT V2 claim envelope is non-canonical".into(),
            ));
        }
        Ok(PreparedBolt11BatV2ClaimV2 {
            request: envelope.credential_request,
            envelope_bytes: core::mem::take(&mut *canonical),
        })
    }

    pub fn verify_issuance_response(
        &self,
        quote: &AcceptedBolt11BatV2QuoteV2,
        claim: &PreparedBolt11BatV2ClaimV2,
        response_bytes: &[u8],
        now_unix: u64,
    ) -> PirResult<CheckedBatV2IssuanceResponseV2> {
        let parsed = ParsedBolt11InvoiceV1::parse(&quote.quote.invoice)
            .map_err(protocol_verification_error)?;
        let verified_quote = quote
            .quote
            .verify_bat_v2_snapshot(
                &self.intent,
                &self.class,
                &self.delegation,
                &parsed,
                now_unix,
            )
            .map_err(protocol_verification_error)?;
        let response =
            BatV2IssuanceResponseV2::decode(response_bytes).map_err(protocol_decode_error)?;
        response
            .verify_for_verified_quote(&claim.request, &verified_quote)
            .map_err(protocol_verification_error)
    }
}

#[derive(Clone, Debug)]
pub struct AcceptedBolt11BatV2QuoteV2 {
    quote: Bolt11QuoteV1,
}

impl AcceptedBolt11BatV2QuoteV2 {
    pub fn bytes(&self) -> PirResult<Vec<u8>> {
        self.quote.encode().map_err(protocol_encode_error)
    }

    pub fn invoice(&self) -> &str {
        &self.quote.invoice
    }

    pub const fn quote_id(&self) -> [u8; 32] {
        self.quote.quote_id
    }

    pub const fn status(&self) -> Bolt11QuoteStatusV1 {
        self.quote.status
    }

    pub const fn state_version(&self) -> u64 {
        self.quote.state_version
    }

    pub const fn invoice_expires_at(&self) -> u64 {
        self.quote.invoice_expires_at
    }

    pub const fn invoice_created_at(&self) -> u64 {
        self.quote.invoice_created_at
    }

    pub const fn claim_deadline(&self) -> u64 {
        self.quote.claim_deadline
    }

    pub fn accept_latest_after(
        &self,
        prepared: &PreparedBolt11BatV2QuoteV2,
        response_bytes: &[u8],
        now_unix: u64,
    ) -> PirResult<Self> {
        let next = Bolt11QuoteV1::decode(response_bytes).map_err(protocol_decode_error)?;
        let parsed =
            ParsedBolt11InvoiceV1::parse(&next.invoice).map_err(protocol_verification_error)?;
        next.verify_latest_bat_v2_after(
            &self.quote,
            &prepared.intent,
            &prepared.class,
            &prepared.delegation,
            &parsed,
            now_unix,
        )
        .map_err(protocol_verification_error)?;
        Ok(Self { quote: next })
    }
}

#[derive(Clone)]
pub struct PreparedBolt11BatV2ClaimV2 {
    request: BatV2IssuanceRequestV2,
    envelope_bytes: Vec<u8>,
}

impl fmt::Debug for PreparedBolt11BatV2ClaimV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedBolt11BatV2ClaimV2")
            .field("claim_envelope", &"[REDACTED]")
            .finish()
    }
}

impl Drop for PreparedBolt11BatV2ClaimV2 {
    fn drop(&mut self) {
        self.envelope_bytes.zeroize();
    }
}

impl PreparedBolt11BatV2ClaimV2 {
    pub fn envelope_bytes(&self) -> &[u8] {
        &self.envelope_bytes
    }

    pub fn credential_request_bytes(&self) -> PirResult<Vec<u8>> {
        self.request.encode().map_err(protocol_encode_error)
    }

    pub const fn credential_request(&self) -> &BatV2IssuanceRequestV2 {
        &self.request
    }
}

fn protocol_decode_error(error: impl core::fmt::Display) -> PirError {
    PirError::Decode(format!("BAT V2 protocol decode failed: {error}"))
}

fn protocol_encode_error(error: impl core::fmt::Display) -> PirError {
    PirError::Encode(format!("BAT V2 protocol encode failed: {error}"))
}

fn protocol_verification_error(error: impl core::fmt::Display) -> PirError {
    PirError::VerificationFailed(format!("BAT V2 verification failed: {error}"))
}

fn payment_crypto_error(error: impl core::fmt::Display) -> PirError {
    PirError::VerificationFailed(format!("BAT V2 client cryptography failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use pir_service_protocol::{
        AuthPaddingClassV1, BackendId, BatAcceptanceMemberV2, BatAcceptanceTermsV2,
        DatasetBindingV1, DeploymentStatus, EntitlementLimitsV1, LightningNetworkV1,
        PrivacyLeakageV1, VerifiedBatAcceptanceMemberV2, WorkloadId,
    };

    const GENERATOR_COMPRESSED: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];
    const GENERATOR_XONLY: [u8; 32] = [
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
        0x17, 0x98,
    ];

    fn terms() -> BatAcceptanceTermsV2 {
        BatAcceptanceTermsV2 {
            auth_padding_class: AuthPaddingClassV1::Class16KiB,
            backend: BackendId::DpfPirV1,
            workload: WorkloadId::DpfEvaluateJobV1,
            protocol_version: 1,
            dataset: DatasetBindingV1::Class { class_id: 1 },
            operation_profile: 2,
            entitlement_profile: 3,
            limits: EntitlementLimitsV1 {
                max_logical_inputs: 1,
                max_frames: 10,
                max_request_bytes: 10_000,
                max_response_bytes: 20_000,
                max_wall_time_ms: 1_000,
                max_concurrent_sockets: 1,
                max_hint_groups: 0,
                max_work_units: 100,
            },
            priority_class: 1,
            deployment_status: DeploymentStatus::Stable,
            price_msat: 1_000,
            issuer_endpoint: "https://issuer.invalid".into(),
            invoice_expiry_seconds: 10,
            claim_window_seconds: 10,
            minimum_credential_validity_seconds: 10,
            retired_policy_grace_seconds: 30,
            credential_count: 2,
            credential_presentation_limit: 1,
            privacy_leakage: PrivacyLeakageV1::from_bits(
                PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING
                    | PrivacyLeakageV1::ISSUER_REDEMPTION_TIMING
                    | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER,
            )
            .unwrap(),
        }
    }

    fn class_and_members() -> (
        BatAcceptanceClassV2,
        VerifiedBatAcceptanceMemberV2,
        VerifiedBatAcceptanceMemberV2,
        SigningKey,
    ) {
        let issuer_key = SigningKey::from_bytes(&[31; 32]);
        let first = BatAcceptanceMemberV2 {
            provider_id: [0xa1; 32],
            policy_digest: [0xa2; 32],
            scope_id: [0xa3; 32],
            offer_id: 0xa4a4_a4a4,
        };
        let second = BatAcceptanceMemberV2 {
            provider_id: [0xb1; 32],
            policy_digest: [0xb2; 32],
            scope_id: [0xb3; 32],
            offer_id: 0xb4b4_b4b4,
        };
        let common_terms = terms();
        let class = BatAcceptanceClassV2::sign(
            [0xc1; 32],
            7,
            100,
            10_030,
            GENERATOR_COMPRESSED,
            common_terms.clone(),
            vec![first.clone(), second.clone()],
            &issuer_key,
        )
        .unwrap();
        let issuer_id = class.issuer_id;
        let class_id = class.class_id;
        let project = |member| VerifiedBatAcceptanceMemberV2 {
            issuer_id,
            class_id,
            member,
            common_terms: common_terms.clone(),
            policy_issued_at: 100,
            policy_expires_at: 10_000,
            redemption_deadline: 10_030,
        };
        (class, project(first), project(second), issuer_key)
    }

    #[test]
    fn recovery_domains_do_not_accept_v1_intents_as_v2() {
        assert!(Bolt11BatV2QuoteIntentV2::decode(&[1; 64]).is_err());
    }

    #[test]
    fn prepared_claim_debug_redacts_envelope() {
        let claim = PreparedBolt11BatV2ClaimV2 {
            request: BatV2IssuanceRequestV2 {
                issuer_id: [1; 32],
                quote_id: [2; 32],
                quote_request_digest: [3; 32],
                class_id: [4; 32],
                class_digest: [5; 32],
                class_key_epoch: 6,
                bat_key_id: [7; 32],
                items: Vec::new(),
            },
            envelope_bytes: b"secret-canary".to_vec(),
        };
        let rendered = format!("{claim:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("secret-canary"));
    }

    #[test]
    fn two_provider_members_produce_identical_class_only_intent() {
        let (class, first_member, second_member, issuer_key) = class_and_members();
        let quote_key = SigningKey::from_bytes(&[32; 32]);
        let delegation = Bolt11QuoteKeyDelegationV1::sign(
            LightningNetworkV1::Bitcoin,
            GENERATOR_COMPRESSED,
            9,
            100,
            10_030,
            quote_key.verifying_key().to_bytes(),
            &issuer_key,
        )
        .unwrap();
        let checkpoint = Bolt11QuoteKeyCheckpointV1::initial(
            class.issuer_id,
            LightningNetworkV1::Bitcoin,
            GENERATOR_COMPRESSED,
        )
        .unwrap();
        let prepare = |member| {
            PreparedBolt11BatV2QuoteV2::from_verified_current_offer(
                &VerifiedCurrentBatV2OfferV2::new(class.clone(), member),
                &delegation.encode().unwrap(),
                &checkpoint,
                1_000,
                GENERATOR_XONLY,
                [0xd1; 32],
            )
            .unwrap()
        };
        let first = prepare(first_member);
        let second = prepare(second_member);
        let first_bytes = first.intent_bytes().unwrap();
        assert_eq!(first_bytes, second.intent_bytes().unwrap());
        for provider_bound_canary in [
            [0xa1; 32], [0xa2; 32], [0xa3; 32], [0xb1; 32], [0xb2; 32], [0xb3; 32],
        ] {
            assert!(!first_bytes
                .windows(provider_bound_canary.len())
                .any(|window| window == provider_bound_canary));
        }

        let restored = PreparedBolt11BatV2QuoteV2::restore(
            &first.intent_bytes().unwrap(),
            &first.class_bytes().unwrap(),
            &first.delegation_bytes().unwrap(),
            &first.quote_key_checkpoint_bytes(),
            1_000,
        )
        .unwrap();
        assert_eq!(restored.intent_bytes().unwrap(), first_bytes);
    }

    #[test]
    fn nonmember_cannot_prepare_a_class_only_intent() {
        let (class, mut member, _, issuer_key) = class_and_members();
        member.member.provider_id = [0xee; 32];
        let quote_key = SigningKey::from_bytes(&[33; 32]);
        let delegation = Bolt11QuoteKeyDelegationV1::sign(
            LightningNetworkV1::Bitcoin,
            GENERATOR_COMPRESSED,
            9,
            100,
            10_030,
            quote_key.verifying_key().to_bytes(),
            &issuer_key,
        )
        .unwrap();
        let checkpoint = Bolt11QuoteKeyCheckpointV1::initial(
            class.issuer_id,
            LightningNetworkV1::Bitcoin,
            GENERATOR_COMPRESSED,
        )
        .unwrap();
        assert!(PreparedBolt11BatV2QuoteV2::from_verified_current_offer(
            &VerifiedCurrentBatV2OfferV2::new(class, member),
            &delegation.encode().unwrap(),
            &checkpoint,
            1_000,
            GENERATOR_XONLY,
            [0xd1; 32],
        )
        .is_err());
    }
}
