//! Provider-side online redemption for shared Free, Cashu BAT, and
//! experimental ARC credentials.
//!
//! The provider uses a key distinct from its service-policy and Nostr keys.
//! The issuer owns the global spent set and ledger.  This crate never accepts
//! an invoice, payment hash, preimage, payer identity, peer-provider identity,
//! or PIR result.

#![forbid(unsafe_code)]

use core::fmt;

use ed25519_dalek::{SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use pir_runtime_core::service_admission::{
    AdmissionCommitErrorV1, AdmissionMethodCommitterV1, AdmissionMethodRouteV1,
};
use pir_service_protocol::{
    credential_presentation_digest, verify_ledger_redeem_response_for_exact_request_v1, AuthScheme,
    AuthorizationProofV1, BoundAuthAttemptV1, FreeAuthorizationProofV1, IssuerClearingApprovalV1,
    ProviderClearingAuthorizationV1, ProviderClearingExpectationV1, ProviderClearingRequestAuthV1,
    ProviderRedeemRequestV1, ProviderRedeemResponseV1, ServiceProtocolError,
    SettlementDestinationV1, VerificationMode,
};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

const IDEMPOTENCY_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/provider-shared-redeem-idempotency/POST-/v1/redeems/v1";
pub const MAX_SHARED_ISSUER_RESPONSE_BYTES_V1: usize = 64 * 1024;

/// Typed transport input. Concrete HTTP adapters encode these exact canonical
/// objects and must disable redirects and request/response body logging.
pub struct SharedIssuerRedeemEnvelopeV1<'a> {
    pub endpoint: &'a str,
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
pub struct ProviderRedeemIdempotencyKeyV1([u8; 32]);

impl fmt::Debug for ProviderRedeemIdempotencyKeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ProviderRedeemIdempotencyKeyV1")
            .field(&"[REDACTED]")
            .finish()
    }
}

impl ProviderRedeemIdempotencyKeyV1 {
    pub fn from_bytes(mut key: [u8; 32]) -> Result<Self, ServiceProtocolError> {
        if key.iter().all(|byte| *byte == 0) {
            key.zeroize();
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderRedeemIdempotencyKeyV1",
                reason: "must be non-zero",
            });
        }
        Ok(Self(key))
    }

    fn derive(
        &self,
        authorization_digest: &[u8; 32],
        binding_digest: &[u8; 32],
        credential_digest: &[u8; 32],
    ) -> [u8; 32] {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC-SHA256 accepts every key length");
        mac.update(IDEMPOTENCY_DOMAIN_V1);
        mac.update(authorization_digest);
        mac.update(binding_digest);
        mac.update(credential_digest);
        mac.finalize().into_bytes().into()
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
        Ok(Self {
            authorization,
            issuer_approval,
            operator_verifying_key,
            issuer_settlement_verifying_key,
            clearing_signing_key,
            minimum_authorization_epoch,
            idempotency_key,
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
        {
            return Err(AdmissionCommitErrorV1::ScopeUnavailable);
        }

        let canonical_credential = canonical_shared_credential_v1(attempt)
            .map_err(|_| AdmissionCommitErrorV1::InvalidOrSpent)?;
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

        let response_bytes = self
            .transport
            .redeem(
                SharedIssuerRedeemEnvelopeV1 {
                    endpoint: &offer.endpoint,
                    request: &request,
                    request_auth: &request_auth,
                    credential_binding: binding,
                    canonical_credential: &canonical_credential,
                },
                MAX_SHARED_ISSUER_RESPONSE_BYTES_V1,
            )
            .map_err(map_transport_error)?;
        if response_bytes.len() > MAX_SHARED_ISSUER_RESPONSE_BYTES_V1 {
            return Err(AdmissionCommitErrorV1::InternalAfterSpend);
        }
        let response = ProviderRedeemResponseV1::decode(&response_bytes)
            .map_err(|_| AdmissionCommitErrorV1::InternalAfterSpend)?;
        if response
            .encode()
            .map_err(|_| AdmissionCommitErrorV1::InternalAfterSpend)?
            != response_bytes
        {
            return Err(AdmissionCommitErrorV1::InternalAfterSpend);
        }
        verify_ledger_redeem_response_for_exact_request_v1(
            &response,
            &request,
            &self.authorization,
            &self.issuer_settlement_verifying_key,
        )
        .map_err(|_| AdmissionCommitErrorV1::InternalAfterSpend)?;
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
        AuthorizationProofV1::BitcoinPirCashuBat(proof) => Ok(proof.encode()?.to_vec()),
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
            AdmissionCommitErrorV1::InternalAfterSpend
        }
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
