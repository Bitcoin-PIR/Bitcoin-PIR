//! Sealed provider-local bearer admission typestate.
//!
//! Runtime handlers cannot call the raw spent-set primitive. They first bind
//! an untrusted authorization request to a verified policy and trusted local
//! operation with `pir-service-protocol`, then pass that bound attempt here for
//! method-specific cryptographic verification and spend-key derivation.

pub use pir_service_protocol::{
    arc_provider_global_spend_key_v1, ARC_CANONICAL_TAG_LEN_V1,
    ARC_PROVIDER_GLOBAL_SPEND_KEY_DOMAIN_V1,
};
use pir_service_protocol::{
    verify_free_anonymous_ticket_for_offer, verify_paid_receipt_for_offer, AuthScheme,
    AuthorizationProofV1, BitcoinPirCashuBatProofV1, BoundAuthAttemptV1, DeploymentStatus,
    FreeAuthorizationProofV1, ServiceProtocolError, VerificationMode,
    VerifiedSharedIssuerLocalGrantClaimV1,
};
use std::fmt;

use crate::offer_namespace::{
    derive_verified_offer_namespace_v1, ArcExclusiveKeyLineageVerifierV1, DerivedOfferNamespaceV1,
};
use crate::{SpendRequest, StoreError, StoreResult};

/// Reviewed adapter for BitcoinPIR Cashu BAT's exact DHKE verification.
///
/// Implementations must verify `C == k * H_to_curve(secret_raw)` (using the
/// protocol's canonical hash-to-curve suite) against the supplied raw key.
/// Merely parsing points or comparing a policy key ID does not satisfy this
/// contract.
pub trait CashuBatProofVerifierV1: Send + Sync {
    fn verify_cashu_bat_proof_v1(
        &self,
        proof: &BitcoinPirCashuBatProofV1,
        raw_verification_key: &[u8; 33],
    ) -> Result<(), ServiceProtocolError>;
}

/// Store-owned callback accepting the complete output of one cryptographically
/// verified ARC presentation. Callers never receive a constructor for the
/// sealed spend typestate and cannot pass these fields to the commit API.
///
/// The reviewed adapter must source all four values from its private verified
/// result. The store checks the exact credential binding, raw-key lineage, and
/// recomputed provider-global spend key before retaining anything.
pub trait ArcVerifiedSpendSinkV1 {
    fn accept_verified_arc_spend_v1(
        &mut self,
        canonical_tag: &[u8; ARC_CANONICAL_TAG_LEN_V1],
        public_key_fingerprint: &[u8; 32],
        credential_binding_digest: &[u8; 32],
        provider_global_spend_key: &[u8; 32],
    ) -> Result<(), ServiceProtocolError>;
}

/// Reviewed ARC presentation verifier boundary. A successful implementation
/// must call `sink` exactly once with fields taken from its private
/// cryptographic `VerifiedArcSpendV1` value.
pub trait ArcPresentationSpendVerifierV1: Send + Sync {
    fn verify_arc_presentation_spend_v1(
        &self,
        attempt: &BoundAuthAttemptV1<'_>,
        now_unix_seconds: u64,
        sink: &mut dyn ArcVerifiedSpendSinkV1,
    ) -> Result<(), ServiceProtocolError>;
}

/// One reviewed provider-local ARC adapter must supply both namespace lineage
/// and presentation verification. Shared-issuer ARC intentionally uses a
/// different online authority and never enters this trait boundary.
pub trait ArcProviderLocalAdapterV1:
    ArcExclusiveKeyLineageVerifierV1 + ArcPresentationSpendVerifierV1 + Send + Sync
{
}

impl<T> ArcProviderLocalAdapterV1 for T where
    T: ArcExclusiveKeyLineageVerifierV1 + ArcPresentationSpendVerifierV1 + Send + Sync
{
}

/// Private-field marker proving outer request/operation binding and the
/// selected provider-local bearer's method-specific verification completed.
#[derive(Clone, Copy, Eq, PartialEq)]
#[must_use = "a verified provider-local spend must be atomically committed before granting"]
pub struct VerifiedProviderLocalSpendV1 {
    pub(crate) namespace_id: [u8; 32],
    pub(crate) spend_key: [u8; 32],
    pub(crate) now_unix_seconds: u64,
}

impl fmt::Debug for VerifiedProviderLocalSpendV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedProviderLocalSpendV1")
            .field("namespace_id", &"[REDACTED]")
            .field("spend_key", &"[REDACTED]")
            .field("now_unix_seconds", &"[REDACTED]")
            .finish()
    }
}

/// Sealed provider-local ARC spend typestate. It is deliberately move-only,
/// has no public constructor, and redacts the durable nullifier from `Debug`.
#[must_use = "a verified ARC spend must be atomically committed before granting"]
pub struct VerifiedArcProviderLocalSpendV1 {
    pub(crate) namespace_id: [u8; 32],
    pub(crate) spend_key: [u8; 32],
    pub(crate) now_unix_seconds: u64,
}

impl fmt::Debug for VerifiedArcProviderLocalSpendV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedArcProviderLocalSpendV1")
            .field("namespace_id", &"[REDACTED]")
            .field("spend_key", &"[REDACTED]")
            .field("now_unix_seconds", &"[REDACTED]")
            .finish()
    }
}

/// Verify one provider-local bearer attempt and derive its sealed durable
/// spend marker. Standard Cashu/shared-issuer methods are authoritative
/// elsewhere; non-bearer Free modes have no local serial; ARC remains blocked
/// until its reviewed verifier/nullifier adapter exists.
pub fn verify_provider_local_bearer_spend_v1(
    attempt: &BoundAuthAttemptV1<'_>,
    now_unix_seconds: u64,
    cashu_bat_verifier: Option<&dyn CashuBatProofVerifierV1>,
) -> StoreResult<VerifiedProviderLocalSpendV1> {
    if now_unix_seconds == 0 {
        return Err(StoreError::InvalidInput("verification time is zero"));
    }
    let verified_offer = attempt.verified_offer();
    let offer = verified_offer.offer();
    if offer.verification != VerificationMode::ProviderLocal {
        return Err(protocol_value_error(
            "ServiceOfferV1.verification",
            "provider-local spent state is not authoritative for this offer",
        ));
    }

    let spend_key = match (offer.authorization, attempt.proof()) {
        (
            AuthScheme::FreeV1,
            AuthorizationProofV1::Free(FreeAuthorizationProofV1::AnonymousTicket(ticket)),
        ) => verify_free_anonymous_ticket_for_offer(ticket, verified_offer, now_unix_seconds)?,
        (AuthScheme::Bolt11DirectReceiptV1, AuthorizationProofV1::Bolt11DirectReceipt(receipt)) => {
            verify_paid_receipt_for_offer(receipt, verified_offer, now_unix_seconds)?
        }
        (AuthScheme::BitcoinPirCashuBatV1, AuthorizationProofV1::BitcoinPirCashuBat(proof)) => {
            if now_unix_seconds > verified_offer.redemption_deadline() {
                return Err(protocol_value_error(
                    "VerifiedServiceOfferV1.redemption_deadline",
                    "BAT redemption is outside the retained-policy grace",
                ));
            }
            let binding = offer.credential_binding.as_ref().ok_or_else(|| {
                protocol_value_error(
                    "ServiceOfferV1.credential_binding",
                    "BAT offer has no delegated verification key",
                )
            })?;
            if now_unix_seconds < binding.claims.not_before
                || now_unix_seconds > binding.claims.not_after
            {
                return Err(protocol_value_error(
                    "CredentialKeyBindingV1.validity",
                    "BAT delegated key is not currently valid",
                ));
            }
            let raw_verification_key: [u8; 33] = binding
                .claims
                .verification_key
                .as_slice()
                .try_into()
                .map_err(|_| {
                    protocol_value_error(
                        "CredentialKeyBindingV1.verification_key",
                        "BAT verification key is not exactly 33 bytes",
                    )
                })?;
            cashu_bat_verifier
                .ok_or(StoreError::InvalidInput(
                    "reviewed Cashu BAT verifier is required",
                ))?
                .verify_cashu_bat_proof_v1(proof, &raw_verification_key)?;
            proof.spend_key(&raw_verification_key)?
        }
        (AuthScheme::ArcV1Experimental, _) => {
            return Err(StoreError::InvalidInput(
                "provider-local ARC is blocked pending reviewed nullifier support",
            ))
        }
        _ => {
            return Err(protocol_value_error(
                "AuthorizationProofV1",
                "attempt is not a provider-local single-use bearer proof",
            ))
        }
    };

    let namespace = match derive_verified_offer_namespace_v1(
        verified_offer,
        now_unix_seconds,
        None::<&dyn ArcExclusiveKeyLineageVerifierV1>,
    )? {
        DerivedOfferNamespaceV1::Namespace(namespace) => namespace,
        DerivedOfferNamespaceV1::NotApplicable(_) => {
            return Err(protocol_value_error(
                "ServiceOfferV1.verification",
                "offer does not use provider-local bearer persistence",
            ))
        }
        DerivedOfferNamespaceV1::UnsupportedExperimental => {
            return Err(StoreError::InvalidInput(
                "experimental provider-local namespace is unsupported",
            ))
        }
    };

    Ok(VerifiedProviderLocalSpendV1 {
        namespace_id: namespace.namespace_id,
        spend_key,
        now_unix_seconds,
    })
}

/// Verify one experimental provider-local ARC presentation into a sealed
/// durable-spend typestate. This API never accepts a raw fingerprint, binding
/// digest, tag, or nullifier from its caller.
pub fn verify_provider_local_arc_spend_v1(
    attempt: &BoundAuthAttemptV1<'_>,
    now_unix_seconds: u64,
    arc_adapter: &dyn ArcProviderLocalAdapterV1,
) -> StoreResult<VerifiedArcProviderLocalSpendV1> {
    if now_unix_seconds == 0 {
        return Err(StoreError::InvalidInput("verification time is zero"));
    }
    let verified_offer = attempt.verified_offer();
    let offer = verified_offer.offer();
    if offer.authorization != AuthScheme::ArcV1Experimental
        || offer.verification != VerificationMode::ProviderLocal
        || offer.deployment_status != DeploymentStatus::Experimental
        || !matches!(attempt.proof(), AuthorizationProofV1::ArcExperimental(_))
    {
        return Err(protocol_value_error(
            "AuthorizationProofV1",
            "attempt is not experimental provider-local ARC",
        ));
    }
    if now_unix_seconds > verified_offer.redemption_deadline() {
        return Err(protocol_value_error(
            "VerifiedServiceOfferV1.redemption_deadline",
            "ARC redemption is outside the retained-policy grace",
        ));
    }
    let binding = offer.credential_binding.as_ref().ok_or_else(|| {
        protocol_value_error(
            "ServiceOfferV1.credential_binding",
            "ARC offer has no delegated verification key",
        )
    })?;
    let credential_binding_digest = binding.binding_digest()?;

    let namespace = match derive_verified_offer_namespace_v1(
        verified_offer,
        now_unix_seconds,
        Some(arc_adapter),
    )? {
        DerivedOfferNamespaceV1::Namespace(namespace) => namespace,
        DerivedOfferNamespaceV1::NotApplicable(_) => {
            return Err(protocol_value_error(
                "ServiceOfferV1.verification",
                "ARC offer does not use provider-local bearer persistence",
            ))
        }
        DerivedOfferNamespaceV1::UnsupportedExperimental => {
            return Err(StoreError::InvalidInput(
                "reviewed provider-local ARC adapter is required",
            ))
        }
    };
    let lineage = namespace
        .exclusive_key_lineage
        .ok_or(StoreError::InvalidInput(
            "ARC namespace is missing its exclusive raw-key lineage",
        ))?;
    let mut sink = CheckedArcSpendSinkV1 {
        expected_public_key_fingerprint: lineage.key_fingerprint,
        expected_credential_binding_digest: credential_binding_digest,
        accepted_spend_key: None,
    };
    arc_adapter.verify_arc_presentation_spend_v1(attempt, now_unix_seconds, &mut sink)?;
    let spend_key = sink.accepted_spend_key.ok_or_else(|| {
        protocol_value_error(
            "ArcPresentationSpendVerifierV1",
            "ARC verifier returned success without one verified spend",
        )
    })?;

    Ok(VerifiedArcProviderLocalSpendV1 {
        namespace_id: namespace.namespace_id,
        spend_key,
        now_unix_seconds,
    })
}

struct CheckedArcSpendSinkV1 {
    expected_public_key_fingerprint: [u8; 32],
    expected_credential_binding_digest: [u8; 32],
    accepted_spend_key: Option<[u8; 32]>,
}

impl ArcVerifiedSpendSinkV1 for CheckedArcSpendSinkV1 {
    fn accept_verified_arc_spend_v1(
        &mut self,
        canonical_tag: &[u8; ARC_CANONICAL_TAG_LEN_V1],
        public_key_fingerprint: &[u8; 32],
        credential_binding_digest: &[u8; 32],
        provider_global_spend_key: &[u8; 32],
    ) -> Result<(), ServiceProtocolError> {
        if self.accepted_spend_key.is_some() {
            return Err(invalid_protocol_value(
                "ArcPresentationSpendVerifierV1",
                "ARC verifier emitted more than one verified spend",
            ));
        }
        if public_key_fingerprint != &self.expected_public_key_fingerprint {
            return Err(invalid_protocol_value(
                "VerifiedArcSpendV1.public_key_fingerprint",
                "does not match the exact installed ARC raw-key lineage",
            ));
        }
        if credential_binding_digest != &self.expected_credential_binding_digest {
            return Err(invalid_protocol_value(
                "VerifiedArcSpendV1.binding_digest",
                "does not match the exact namespace credential binding",
            ));
        }
        let expected_spend_key = arc_provider_global_spend_key_v1(
            public_key_fingerprint,
            credential_binding_digest,
            canonical_tag,
        );
        if provider_global_spend_key != &expected_spend_key || expected_spend_key == [0; 32] {
            return Err(invalid_protocol_value(
                "VerifiedArcSpendV1.spend_key",
                "does not match the provider-global ARC spend-key derivation",
            ));
        }
        self.accepted_spend_key = Some(expected_spend_key);
        Ok(())
    }
}

fn protocol_value_error(field: &'static str, reason: &'static str) -> StoreError {
    StoreError::ServiceProtocol(invalid_protocol_value(field, reason))
}

fn invalid_protocol_value(field: &'static str, reason: &'static str) -> ServiceProtocolError {
    ServiceProtocolError::InvalidValue { field, reason }
}

impl From<VerifiedProviderLocalSpendV1> for SpendRequest {
    fn from(value: VerifiedProviderLocalSpendV1) -> Self {
        Self {
            namespace_id: value.namespace_id,
            spend_key: value.spend_key,
            now_unix_seconds: value.now_unix_seconds,
        }
    }
}

impl From<VerifiedArcProviderLocalSpendV1> for SpendRequest {
    fn from(value: VerifiedArcProviderLocalSpendV1) -> Self {
        Self {
            namespace_id: value.namespace_id,
            spend_key: value.spend_key,
            now_unix_seconds: value.now_unix_seconds,
        }
    }
}

impl From<VerifiedSharedIssuerLocalGrantClaimV1> for SpendRequest {
    fn from(value: VerifiedSharedIssuerLocalGrantClaimV1) -> Self {
        Self {
            namespace_id: value.namespace_id(),
            spend_key: value.local_claim_key(),
            now_unix_seconds: value.now_unix_seconds(),
        }
    }
}

#[cfg(test)]
mod sensitive_debug_tests {
    use super::*;

    #[test]
    fn verified_provider_local_markers_redact_every_coordinate_and_exact_time() {
        let bearer = VerifiedProviderLocalSpendV1 {
            namespace_id: [0x61; 32],
            spend_key: [0x62; 32],
            now_unix_seconds: 7,
        };
        let arc = VerifiedArcProviderLocalSpendV1 {
            namespace_id: [0x63; 32],
            spend_key: [0x64; 32],
            now_unix_seconds: 8,
        };
        for rendered in [format!("{bearer:?}"), format!("{arc:?}")] {
            assert!(rendered.contains("[REDACTED]"));
            assert!(!rendered.contains("61616161"));
            assert!(!rendered.contains("62626262"));
            assert!(!rendered.contains("63636363"));
            assert!(!rendered.contains("64646464"));
            assert!(!rendered.contains(": 7"));
            assert!(!rendered.contains(": 8"));
        }
    }
}
