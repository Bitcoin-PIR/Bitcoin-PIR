use core::fmt;

use ed25519_dalek::{SigningKey, VerifyingKey};
use pir_runtime_core::service_admission::{
    AdmissionCommitErrorV1, AdmissionMethodCommitterV1, AdmissionMethodRouteV1,
};
use pir_service_protocol::{
    verify_grantable_success_for_inflight_attempt_v2, BatAcceptanceClassV2,
    BitcoinPirCashuBatProofV2, IssuerAccountingApprovalV2, ProviderAccountingAuthorizationV2,
    ProviderId, ProviderRedeemEnvelopeV2, ProviderRedeemOutcomeV2, ProviderRedeemRequestAuthV2,
    ProviderRedeemRequestV2, ProviderRedeemResponseV2, RetrySafeNonConsumingReasonV2,
    ServiceProtocolError, VerifiedBatAcceptanceMemberV2, VerifiedGrantableProviderRedeemSuccessV2,
    MAX_BAT_V2_PROVIDER_REDEEM_RESPONSE_LEN_V2,
};
use zeroize::Zeroizing;

pub const BAT_V2_REDEEM_ENDPOINT_V2: &str = "/v2/redeems";
pub const BAT_V2_REDEEM_REQUEST_CONTENT_TYPE_V2: &str =
    "application/vnd.bitcoinpir.bat-v2-provider-redeem-envelope-v2";
pub const BAT_V2_REDEEM_RESPONSE_CONTENT_TYPE_V2: &str =
    "application/vnd.bitcoinpir.bat-v2-provider-redeem-response-v2";

/// Exact canonical request handed to a concrete HTTPS adapter. The origin and
/// leaf pins come only from the signed accounting authorization; adapters must
/// require WebPKI in addition to the pins, disable redirects, and never log the
/// body.
pub struct BatV2RedeemHttpRequestV2<'a> {
    pub issuer_origin: &'a str,
    pub leaf_spki_sha256_pins: &'a [[u8; 32]],
    pub endpoint: &'static str,
    pub request_content_type: &'static str,
    pub response_content_type: &'static str,
    pub canonical_envelope: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatV2RedeemTransportErrorV2 {
    /// The adapter proves that no HTTP application byte reached the issuer.
    DefinitelyNotSent { retry_after_ms: u32 },
    /// Request delivery or issuer commit may have occurred. This burns the BAT.
    OutcomeUnknown,
}

/// Transport-neutral, single-attempt BAT V2 redemption boundary.
pub trait BatV2RedeemTransportV2: Send + Sync {
    fn redeem_v2(
        &self,
        request: BatV2RedeemHttpRequestV2<'_>,
        max_response_bytes: usize,
    ) -> Result<Vec<u8>, BatV2RedeemTransportErrorV2>;
}

pub struct BatV2ProviderRedeemTrustV2 {
    pub expected_provider_id: ProviderId,
    pub expected_issuer_id: [u8; 32],
    pub authorization: ProviderAccountingAuthorizationV2,
    pub issuer_approval: IssuerAccountingApprovalV2,
    pub operator_verifying_key: VerifyingKey,
    pub issuer_settlement_verifying_key: VerifyingKey,
    pub minimum_authorization_epoch: u64,
}

impl fmt::Debug for BatV2ProviderRedeemTrustV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BatV2ProviderRedeemTrustV2")
            .field("expected_provider_id", &self.expected_provider_id)
            .field("expected_issuer_id", &self.expected_issuer_id)
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

/// Opaque, non-clone proof that the issuer freshly committed this exact
/// in-flight attempt. It intentionally exposes neither response bytes nor a
/// recovery constructor.
pub struct FreshBatV2ConnectionGrantV2 {
    _verified: VerifiedGrantableProviderRedeemSuccessV2,
}

impl fmt::Debug for FreshBatV2ConnectionGrantV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshBatV2ConnectionGrantV2")
            .finish_non_exhaustive()
    }
}

pub enum StorelessBatV2RedeemDecisionV2 {
    FreshGrant(Box<FreshBatV2ConnectionGrantV2>),
    RetrySafeNonConsuming(RetrySafeNonConsumingReasonV2),
    DefinitelyNotSent { retry_after_ms: u32 },
    TerminalInvalidOrSpent,
}

impl fmt::Debug for StorelessBatV2RedeemDecisionV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FreshGrant(_) => formatter.write_str("FreshGrant([VERIFIED])"),
            Self::RetrySafeNonConsuming(reason) => formatter
                .debug_tuple("RetrySafeNonConsuming")
                .field(reason)
                .finish(),
            Self::DefinitelyNotSent { retry_after_ms } => formatter
                .debug_struct("DefinitelyNotSent")
                .field("retry_after_ms", retry_after_ms)
                .finish(),
            Self::TerminalInvalidOrSpent => formatter.write_str("TerminalInvalidOrSpent"),
        }
    }
}

#[derive(Debug)]
pub enum StorelessBatV2RedeemErrorV2 {
    /// Local validation or encoding failed before any request byte was sent.
    PreSend(ServiceProtocolError),
    /// OS randomness failed before any request byte was sent.
    EntropyUnavailable,
    /// Delivery, response validity, or issuer commit is uncertain. The caller
    /// must burn the credential and must not automatically retry it.
    OutcomeUnknownCredentialBurned,
}

impl fmt::Display for StorelessBatV2RedeemErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PreSend(error) => write!(formatter, "BAT V2 pre-send validation failed: {error}"),
            Self::EntropyUnavailable => {
                formatter.write_str("BAT V2 attempt entropy is unavailable before send")
            }
            Self::OutcomeUnknownCredentialBurned => formatter.write_str(
                "BAT V2 outcome is unknown; the credential is burned and must not be retried",
            ),
        }
    }
}

impl std::error::Error for StorelessBatV2RedeemErrorV2 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PreSend(error) => Some(error),
            _ => None,
        }
    }
}

/// Stateless provider client for issuer-wide BAT V2 admission. It owns no
/// ProviderStore, idempotency/HMAC secret, rollback client, or replay state.
pub struct StorelessBatV2ProviderRedeemClientV2<'a> {
    trust: BatV2ProviderRedeemTrustV2,
    clearing_signing_key: SigningKey,
    transport: &'a dyn BatV2RedeemTransportV2,
}

impl fmt::Debug for StorelessBatV2ProviderRedeemClientV2<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StorelessBatV2ProviderRedeemClientV2")
            .field("trust", &self.trust)
            .field("clearing_signing_key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl<'a> StorelessBatV2ProviderRedeemClientV2<'a> {
    pub fn new(
        trust: BatV2ProviderRedeemTrustV2,
        clearing_signing_key: SigningKey,
        transport: &'a dyn BatV2RedeemTransportV2,
    ) -> Result<Self, ServiceProtocolError> {
        if trust.minimum_authorization_epoch == 0
            || trust.authorization.claims.provider_id != trust.expected_provider_id
            || trust.authorization.claims.issuer_id != trust.expected_issuer_id
            || trust.authorization.claims.authorization_epoch < trust.minimum_authorization_epoch
            || trust.authorization.claims.clearing_verifying_key
                != clearing_signing_key.verifying_key().to_bytes()
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "StorelessBatV2ProviderRedeemClientV2.trust",
                reason: "provider, issuer, epoch, or clearing key does not match pinned trust",
            });
        }
        let operator = trust.operator_verifying_key.to_bytes();
        let settlement = trust.issuer_settlement_verifying_key.to_bytes();
        let clearing = clearing_signing_key.verifying_key().to_bytes();
        if operator == settlement || operator == clearing || settlement == clearing {
            return Err(ServiceProtocolError::InvalidValue {
                field: "StorelessBatV2ProviderRedeemClientV2.role_keys",
                reason: "operator, issuer settlement, and provider clearing keys must be distinct",
            });
        }
        // Prove that the two public artifacts share at least one valid instant
        // before accepting them as a durable trust configuration. Current-time
        // validity is checked again for every attempt.
        let overlap_start = trust
            .authorization
            .claims
            .not_before
            .max(trust.issuer_approval.approved_at);
        let overlap_end = trust
            .authorization
            .claims
            .not_after
            .min(trust.issuer_approval.not_after);
        if overlap_start > overlap_end {
            return Err(ServiceProtocolError::InvalidValue {
                field: "StorelessBatV2ProviderRedeemClientV2.validity",
                reason: "authorization and issuer approval have no common validity instant",
            });
        }
        trust.authorization.verify_for(
            &trust.expected_provider_id,
            &trust.expected_issuer_id,
            &trust.operator_verifying_key,
            overlap_start,
            trust.minimum_authorization_epoch,
        )?;
        trust.issuer_approval.verify_for(
            &trust.authorization,
            &trust.issuer_settlement_verifying_key,
            overlap_start,
            trust.minimum_authorization_epoch,
        )?;
        Ok(Self {
            trust,
            clearing_signing_key,
            transport,
        })
    }

    pub fn redeem_once(
        &self,
        member: &VerifiedBatAcceptanceMemberV2,
        class: &BatAcceptanceClassV2,
        proof: &BitcoinPirCashuBatProofV2,
        now_unix: u64,
    ) -> Result<StorelessBatV2RedeemDecisionV2, StorelessBatV2RedeemErrorV2> {
        self.verify_attempt_inputs(member, class, now_unix)
            .map_err(StorelessBatV2RedeemErrorV2::PreSend)?;
        let attempt_id = fresh_nonzero_attempt_id_v2()?;
        let prepared = ProviderRedeemRequestV2::prepare(
            &self.trust.authorization,
            member,
            class,
            proof,
            attempt_id,
        )
        .map_err(StorelessBatV2RedeemErrorV2::PreSend)?;
        let (request, in_flight) = prepared.into_parts();
        let request_auth = ProviderRedeemRequestAuthV2::sign(&request, &self.clearing_signing_key)
            .map_err(StorelessBatV2RedeemErrorV2::PreSend)?;
        let canonical_envelope = Zeroizing::new(
            ProviderRedeemEnvelopeV2 {
                request: request.clone(),
                request_auth,
                credential: proof.clone(),
            }
            .encode()
            .map_err(StorelessBatV2RedeemErrorV2::PreSend)?,
        );

        let response_bytes = match self.transport.redeem_v2(
            BatV2RedeemHttpRequestV2 {
                issuer_origin: &self.trust.authorization.claims.redeem_endpoint,
                leaf_spki_sha256_pins: &self
                    .trust
                    .authorization
                    .claims
                    .redeem_leaf_spki_sha256_pins,
                endpoint: BAT_V2_REDEEM_ENDPOINT_V2,
                request_content_type: BAT_V2_REDEEM_REQUEST_CONTENT_TYPE_V2,
                response_content_type: BAT_V2_REDEEM_RESPONSE_CONTENT_TYPE_V2,
                canonical_envelope: canonical_envelope.as_slice(),
            },
            MAX_BAT_V2_PROVIDER_REDEEM_RESPONSE_LEN_V2,
        ) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(BatV2RedeemTransportErrorV2::DefinitelyNotSent { retry_after_ms }) => {
                return Ok(StorelessBatV2RedeemDecisionV2::DefinitelyNotSent { retry_after_ms });
            }
            Err(BatV2RedeemTransportErrorV2::OutcomeUnknown) => {
                return Err(StorelessBatV2RedeemErrorV2::OutcomeUnknownCredentialBurned);
            }
        };
        if response_bytes.len() > MAX_BAT_V2_PROVIDER_REDEEM_RESPONSE_LEN_V2 {
            return Err(StorelessBatV2RedeemErrorV2::OutcomeUnknownCredentialBurned);
        }
        let response = ProviderRedeemResponseV2::decode(&response_bytes)
            .map_err(|_| StorelessBatV2RedeemErrorV2::OutcomeUnknownCredentialBurned)?;
        if response
            .encode()
            .map_err(|_| StorelessBatV2RedeemErrorV2::OutcomeUnknownCredentialBurned)?
            != response_bytes.as_slice()
        {
            return Err(StorelessBatV2RedeemErrorV2::OutcomeUnknownCredentialBurned);
        }
        response
            .verify_for_exact_request(&request, &self.trust.issuer_settlement_verifying_key)
            .map_err(|_| StorelessBatV2RedeemErrorV2::OutcomeUnknownCredentialBurned)?;

        match response.outcome {
            ProviderRedeemOutcomeV2::GrantableSuccess { .. } => {
                let verified = verify_grantable_success_for_inflight_attempt_v2(
                    response,
                    &request,
                    in_flight,
                    &self.trust.issuer_settlement_verifying_key,
                )
                .map_err(|_| StorelessBatV2RedeemErrorV2::OutcomeUnknownCredentialBurned)?;
                Ok(StorelessBatV2RedeemDecisionV2::FreshGrant(Box::new(
                    FreshBatV2ConnectionGrantV2 {
                        _verified: verified,
                    },
                )))
            }
            ProviderRedeemOutcomeV2::RetrySafeNonConsuming { reason } => Ok(
                StorelessBatV2RedeemDecisionV2::RetrySafeNonConsuming(reason),
            ),
            ProviderRedeemOutcomeV2::TerminalInvalidOrSpent => {
                Ok(StorelessBatV2RedeemDecisionV2::TerminalInvalidOrSpent)
            }
        }
    }

    fn verify_attempt_inputs(
        &self,
        member: &VerifiedBatAcceptanceMemberV2,
        class: &BatAcceptanceClassV2,
        now_unix: u64,
    ) -> Result<(), ServiceProtocolError> {
        self.trust.authorization.verify_for(
            &self.trust.expected_provider_id,
            &self.trust.expected_issuer_id,
            &self.trust.operator_verifying_key,
            now_unix,
            self.trust.minimum_authorization_epoch,
        )?;
        self.trust.issuer_approval.verify_for(
            &self.trust.authorization,
            &self.trust.issuer_settlement_verifying_key,
            now_unix,
            self.trust.minimum_authorization_epoch,
        )?;
        if now_unix < class.key_not_before
            || now_unix > class.key_not_after
            || now_unix < member.policy_issued_at
            || now_unix > member.redemption_deadline
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "StorelessBatV2ProviderRedeemClientV2.member_validity",
                reason: "class key or exact policy member is outside its redemption window",
            });
        }
        Ok(())
    }
}

fn fresh_nonzero_attempt_id_v2() -> Result<[u8; 32], StorelessBatV2RedeemErrorV2> {
    for _ in 0..2 {
        let mut attempt_id = [0u8; 32];
        getrandom::getrandom(&mut attempt_id)
            .map_err(|_| StorelessBatV2RedeemErrorV2::EntropyUnavailable)?;
        if attempt_id.iter().any(|byte| *byte != 0) {
            return Ok(attempt_id);
        }
    }
    Err(StorelessBatV2RedeemErrorV2::EntropyUnavailable)
}

/// Admission adapter bound to one exact verified policy member, its signed
/// acceptance class, and the storeless issuer client. It owns no ProviderStore
/// and cannot be used for a V1 shared-issuer route.
pub struct StorelessBatV2AdmissionCommitterV2<'a> {
    member: &'a VerifiedBatAcceptanceMemberV2,
    class: &'a BatAcceptanceClassV2,
    client: &'a StorelessBatV2ProviderRedeemClientV2<'a>,
}

impl fmt::Debug for StorelessBatV2AdmissionCommitterV2<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StorelessBatV2AdmissionCommitterV2")
            .field("member", &self.member.member)
            .field("class_id", &self.class.class_id)
            .finish_non_exhaustive()
    }
}

impl<'a> StorelessBatV2AdmissionCommitterV2<'a> {
    pub fn new(
        member: &'a VerifiedBatAcceptanceMemberV2,
        class: &'a BatAcceptanceClassV2,
        client: &'a StorelessBatV2ProviderRedeemClientV2<'a>,
    ) -> Result<Self, ServiceProtocolError> {
        class.verify_for(&member.issuer_id, &member.class_id)?;
        let expected_deadline = member
            .policy_expires_at
            .checked_add(class.common_terms.retired_policy_grace_seconds as u64);
        if member.common_terms != class.common_terms
            || !class.members.contains(&member.member)
            || member.policy_issued_at > member.policy_expires_at
            || expected_deadline != Some(member.redemption_deadline)
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "StorelessBatV2AdmissionCommitterV2.member",
                reason: "verified member is not an exact member of the signed BAT V2 class",
            });
        }
        Ok(Self {
            member,
            class,
            client,
        })
    }

    fn attempt_matches_exact_member(
        &self,
        attempt: &pir_service_protocol::BoundAuthAttemptV1<'_>,
    ) -> bool {
        let offer = attempt.offer();
        let scope = attempt.scope();
        attempt.verified_offer().policy_digest() == self.member.member.policy_digest
            && attempt.verified_offer().redemption_deadline() == self.member.redemption_deadline
            && scope.provider_id == self.member.member.provider_id
            && scope.scope_id() == self.member.member.scope_id
            && offer.offer_id == self.member.member.offer_id
            && offer.issuer_id == self.member.issuer_id
            && offer.key_id.as_slice() == self.member.class_id
    }
}

impl AdmissionMethodCommitterV1 for StorelessBatV2AdmissionCommitterV2<'_> {
    fn verify_and_commit_v1(
        &self,
        route: AdmissionMethodRouteV1,
        attempt: &pir_service_protocol::BoundAuthAttemptV1<'_>,
        now_unix_seconds: u64,
    ) -> Result<(), AdmissionCommitErrorV1> {
        if route != AdmissionMethodRouteV1::BitcoinPirCashuBatV2SharedIssuerOnline {
            return Err(AdmissionCommitErrorV1::UnsupportedScheme);
        }
        let pir_service_protocol::AuthorizationProofV1::BitcoinPirCashuBatV2(proof) =
            attempt.proof()
        else {
            return Err(AdmissionCommitErrorV1::ScopeUnavailable);
        };
        if !self.attempt_matches_exact_member(attempt) {
            return Err(AdmissionCommitErrorV1::ScopeUnavailable);
        }

        map_storeless_bat_v2_admission_result(self.client.redeem_once(
            self.member,
            self.class,
            proof,
            now_unix_seconds,
        ))
    }
}

fn map_storeless_bat_v2_admission_result(
    result: Result<StorelessBatV2RedeemDecisionV2, StorelessBatV2RedeemErrorV2>,
) -> Result<(), AdmissionCommitErrorV1> {
    match result {
        Ok(StorelessBatV2RedeemDecisionV2::FreshGrant(_)) => Ok(()),
        Ok(StorelessBatV2RedeemDecisionV2::DefinitelyNotSent { retry_after_ms }) => {
            Err(AdmissionCommitErrorV1::ServerBusy { retry_after_ms })
        }
        Ok(StorelessBatV2RedeemDecisionV2::RetrySafeNonConsuming(_)) => {
            Err(AdmissionCommitErrorV1::ScopeUnavailable)
        }
        Ok(StorelessBatV2RedeemDecisionV2::TerminalInvalidOrSpent) => {
            Err(AdmissionCommitErrorV1::InvalidOrSpent)
        }
        Err(StorelessBatV2RedeemErrorV2::PreSend(_)) => {
            Err(AdmissionCommitErrorV1::ScopeUnavailable)
        }
        Err(StorelessBatV2RedeemErrorV2::EntropyUnavailable) => {
            Err(AdmissionCommitErrorV1::ServerBusy {
                retry_after_ms: 1_000,
            })
        }
        Err(StorelessBatV2RedeemErrorV2::OutcomeUnknownCredentialBurned) => {
            Err(AdmissionCommitErrorV1::InternalAfterSpend)
        }
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    #[test]
    fn admission_mapping_preserves_safe_vs_burned_outcomes() {
        assert_eq!(
            map_storeless_bat_v2_admission_result(Ok(
                StorelessBatV2RedeemDecisionV2::DefinitelyNotSent { retry_after_ms: 17 }
            )),
            Err(AdmissionCommitErrorV1::ServerBusy { retry_after_ms: 17 })
        );
        assert_eq!(
            map_storeless_bat_v2_admission_result(Ok(
                StorelessBatV2RedeemDecisionV2::RetrySafeNonConsuming(
                    RetrySafeNonConsumingReasonV2::ClassCompatibility,
                )
            )),
            Err(AdmissionCommitErrorV1::ScopeUnavailable)
        );
        assert_eq!(
            map_storeless_bat_v2_admission_result(Ok(
                StorelessBatV2RedeemDecisionV2::TerminalInvalidOrSpent,
            )),
            Err(AdmissionCommitErrorV1::InvalidOrSpent)
        );
        assert_eq!(
            map_storeless_bat_v2_admission_result(Err(
                StorelessBatV2RedeemErrorV2::EntropyUnavailable,
            )),
            Err(AdmissionCommitErrorV1::ServerBusy {
                retry_after_ms: 1_000,
            })
        );
        assert_eq!(
            map_storeless_bat_v2_admission_result(Err(StorelessBatV2RedeemErrorV2::PreSend(
                ServiceProtocolError::InvalidValue {
                    field: "test",
                    reason: "not sent",
                }
            ),)),
            Err(AdmissionCommitErrorV1::ScopeUnavailable)
        );
        assert_eq!(
            map_storeless_bat_v2_admission_result(Err(
                StorelessBatV2RedeemErrorV2::OutcomeUnknownCredentialBurned,
            )),
            Err(AdmissionCommitErrorV1::InternalAfterSpend)
        );
    }
}
