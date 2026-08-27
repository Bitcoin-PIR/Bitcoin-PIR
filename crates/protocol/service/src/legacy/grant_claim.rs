//! Provider-local delivery claims for shared-issuer redemptions.
//!
//! The issuer remains authoritative for credential redemption and provider
//! settlement.  This module derives a separate provider-local capability used
//! only to ensure that one exact, issuer-signed success can install at most one
//! connection-local service grant.  Neither the issuer idempotency key nor the
//! credential nullifier is persisted in the provider store.

use core::fmt;

use ed25519_dalek::VerifyingKey;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    verify_ledger_redeem_response_for_exact_request_v1, AuthScheme,
    ProviderClearingAuthorizationV1, ProviderRedeemRequestV1, ProviderRedeemResponseV1,
    ServiceProtocolError, VerificationMode, VerifiedServiceOfferV1,
};

/// Purpose tag stored in `spend_namespaces.scheme` for provider-local delivery
/// claims. It is deliberately outside the wire [`AuthScheme`] discriminants:
/// this state is not an issuer credential nullifier or a second verifier for
/// the credential.
pub const SHARED_ISSUER_LOCAL_GRANT_NAMESPACE_SCHEME_V1: u16 = 0x8001;

pub const SHARED_ISSUER_LOCAL_GRANT_BINDING_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/shared-issuer-local-grant-binding/v1";
pub const SHARED_ISSUER_LOCAL_GRANT_KEY_ID_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/shared-issuer-local-grant-key-id/v1";
pub const SHARED_ISSUER_LOCAL_GRANT_NAMESPACE_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/shared-issuer-local-grant-namespace/v1";
pub const SHARED_ISSUER_WIRE_IDEMPOTENCY_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/provider-shared-redeem-idempotency/POST-/v1/redeems/v1";
pub const SHARED_ISSUER_LOCAL_GRANT_CLAIM_KEY_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/shared-issuer-local-grant-claim-key/v1";

/// One provider's root secret for shared-issuer request idempotency and local
/// grant-claim derivation. The two outputs use independent HMAC domains.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedIssuerProviderSecretV1([u8; 32]);

impl fmt::Debug for SharedIssuerProviderSecretV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SharedIssuerProviderSecretV1")
            .field(&"[REDACTED]")
            .finish()
    }
}

impl SharedIssuerProviderSecretV1 {
    pub fn from_bytes(mut secret: [u8; 32]) -> Result<Self, ServiceProtocolError> {
        if secret.iter().all(|byte| *byte == 0) {
            secret.zeroize();
            return Err(ServiceProtocolError::InvalidValue {
                field: "SharedIssuerProviderSecretV1",
                reason: "must be non-zero",
            });
        }
        Ok(Self(secret))
    }

    /// Deterministic wire idempotency for one exact credential coordinate.
    /// This value is disclosed to the issuer and must never be used directly
    /// as the provider-local spent key.
    pub fn derive_wire_idempotency_v1(
        &self,
        authorization_digest: &[u8; 32],
        binding_digest: &[u8; 32],
        credential_digest: &[u8; 32],
    ) -> [u8; 32] {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC-SHA256 accepts every key length");
        mac.update(SHARED_ISSUER_WIRE_IDEMPOTENCY_DOMAIN_V1);
        mac.update(authorization_digest);
        mac.update(binding_digest);
        mac.update(credential_digest);
        mac.finalize().into_bytes().into()
    }

    fn derive_local_claim_key_v1(
        &self,
        request: &ProviderRedeemRequestV1,
        request_digest: &[u8; 32],
        namespace_id: &[u8; 32],
    ) -> [u8; 32] {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC-SHA256 accepts every key length");
        mac.update(SHARED_ISSUER_LOCAL_GRANT_CLAIM_KEY_DOMAIN_V1);
        // The issuer knows both values below, but not this provider secret.
        // Re-keying them under a separate domain prevents a persisted local
        // claim from becoming an invoice/issuer correlation handle.
        mac.update(&request.idempotency_key);
        mac.update(request_digest);
        mac.update(namespace_id);
        mac.finalize().into_bytes().into()
    }
}

/// Public, non-secret coordinates for the synthetic provider-local namespace
/// belonging to one shared-issuer offer purpose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedIssuerLocalGrantNamespaceV1 {
    namespace_id: [u8; 32],
    key_id: [u8; 32],
    binding_digest: [u8; 32],
    issuer_id: [u8; 32],
    not_after: u64,
}

impl SharedIssuerLocalGrantNamespaceV1 {
    pub const fn namespace_id(&self) -> [u8; 32] {
        self.namespace_id
    }

    pub const fn key_id(&self) -> [u8; 32] {
        self.key_id
    }

    pub const fn binding_digest(&self) -> [u8; 32] {
        self.binding_digest
    }

    pub const fn issuer_id(&self) -> [u8; 32] {
        self.issuer_id
    }

    pub const fn not_after(&self) -> u64 {
        self.not_after
    }
}

/// Derive the stable, purpose-tagged provider namespace for a verified
/// shared-issuer offer. This namespace records only local delivery claims; the
/// shared issuer remains the credential spend and settlement authority.
pub fn derive_shared_issuer_local_grant_namespace_v1(
    verified_offer: &VerifiedServiceOfferV1<'_>,
) -> Result<SharedIssuerLocalGrantNamespaceV1, ServiceProtocolError> {
    let offer = verified_offer.offer();
    let scope = verified_offer.scope();
    let binding = offer
        .credential_binding
        .as_ref()
        .ok_or(ServiceProtocolError::InvalidValue {
            field: "ServiceOfferV1.credential_binding",
            reason: "shared-issuer offer is missing its credential binding",
        })?;
    if offer.verification != VerificationMode::SharedIssuerOnline
        || !matches!(
            offer.authorization,
            AuthScheme::FreeV1 | AuthScheme::BitcoinPirCashuBatV1 | AuthScheme::ArcV1Experimental
        )
        || offer.issuer_id != binding.issuer_id
        || scope.provider_id != binding.claims.provider_id
        || scope.scope_id() != binding.claims.scope_id
        || offer.offer_id != binding.claims.offer_id
        || offer.authorization != binding.claims.scheme
        || scope.entitlement_profile != binding.claims.entitlement_profile
        || binding.claims.not_after > verified_offer.redemption_deadline()
    {
        return Err(ServiceProtocolError::InvalidValue {
            field: "VerifiedServiceOfferV1",
            reason: "shared-issuer offer purpose is not exactly bound",
        });
    }

    let credential_binding_digest = binding.binding_digest()?;
    let mut binding_hasher = Sha256::new();
    binding_hasher.update(SHARED_ISSUER_LOCAL_GRANT_BINDING_DOMAIN_V1);
    binding_hasher.update(scope.provider_id);
    binding_hasher.update(scope.scope_id());
    binding_hasher.update(offer.offer_id.to_le_bytes());
    binding_hasher.update((offer.authorization as u16).to_le_bytes());
    binding_hasher.update(offer.issuer_id);
    binding_hasher.update(scope.entitlement_profile.to_le_bytes());
    binding_hasher.update(credential_binding_digest);
    let binding_digest: [u8; 32] = binding_hasher.finalize().into();

    let mut key_hasher = Sha256::new();
    key_hasher.update(SHARED_ISSUER_LOCAL_GRANT_KEY_ID_DOMAIN_V1);
    key_hasher.update(binding_digest);
    let key_id: [u8; 32] = key_hasher.finalize().into();

    let mut namespace_hasher = Sha256::new();
    namespace_hasher.update(SHARED_ISSUER_LOCAL_GRANT_NAMESPACE_DOMAIN_V1);
    namespace_hasher.update(scope.provider_id);
    namespace_hasher.update(SHARED_ISSUER_LOCAL_GRANT_NAMESPACE_SCHEME_V1.to_le_bytes());
    namespace_hasher.update(offer.issuer_id);
    namespace_hasher.update(key_id);
    namespace_hasher.update(binding_digest);
    let namespace_id = namespace_hasher.finalize().into();

    Ok(SharedIssuerLocalGrantNamespaceV1 {
        namespace_id,
        key_id,
        binding_digest,
        issuer_id: offer.issuer_id,
        not_after: binding
            .claims
            .not_after
            .min(verified_offer.redemption_deadline()),
    })
}

/// Sealed proof that one canonical issuer-signed response matches the exact
/// redeem request and verified service offer. It authorizes only a
/// provider-local grant-delivery claim, never issuer settlement or credential
/// validation.
#[must_use = "a verified shared-issuer local grant claim must be durably claimed before granting"]
pub struct VerifiedSharedIssuerLocalGrantClaimV1 {
    namespace_id: [u8; 32],
    local_claim_key: [u8; 32],
    now_unix_seconds: u64,
}

impl fmt::Debug for VerifiedSharedIssuerLocalGrantClaimV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedSharedIssuerLocalGrantClaimV1")
            .field("namespace_id", &"[REDACTED]")
            .field("local_claim_key", &"[REDACTED]")
            .field("now_unix_seconds", &"[REDACTED]")
            .finish()
    }
}

impl Drop for VerifiedSharedIssuerLocalGrantClaimV1 {
    fn drop(&mut self) {
        self.local_claim_key.zeroize();
    }
}

impl VerifiedSharedIssuerLocalGrantClaimV1 {
    pub const fn namespace_id(&self) -> [u8; 32] {
        self.namespace_id
    }

    pub const fn local_claim_key(&self) -> [u8; 32] {
        self.local_claim_key
    }

    pub const fn now_unix_seconds(&self) -> u64 {
        self.now_unix_seconds
    }
}

/// Decode a canonical response, verify its issuer signature and exact request,
/// bind it again to the verified offer, and derive the provider-only claim.
/// A caller cannot construct the returned typestate from raw store keys.
#[allow(clippy::too_many_arguments)]
pub fn verify_shared_issuer_local_grant_claim_v1(
    canonical_response: &[u8],
    request: &ProviderRedeemRequestV1,
    authorization: &ProviderClearingAuthorizationV1,
    expected_issuer_settlement_key: &VerifyingKey,
    verified_offer: &VerifiedServiceOfferV1<'_>,
    provider_secret: &SharedIssuerProviderSecretV1,
    now_unix_seconds: u64,
) -> Result<VerifiedSharedIssuerLocalGrantClaimV1, ServiceProtocolError> {
    if now_unix_seconds == 0 || now_unix_seconds > verified_offer.redemption_deadline() {
        return Err(ServiceProtocolError::InvalidValue {
            field: "VerifiedSharedIssuerLocalGrantClaimV1.now_unix_seconds",
            reason: "claim time is zero or outside the verified redemption deadline",
        });
    }
    let response = ProviderRedeemResponseV1::decode(canonical_response)?;
    if response.encode()?.as_slice() != canonical_response {
        return Err(ServiceProtocolError::InvalidValue {
            field: "ProviderRedeemResponseV1",
            reason: "response is not canonical",
        });
    }
    verify_ledger_redeem_response_for_exact_request_v1(
        &response,
        request,
        authorization,
        expected_issuer_settlement_key,
    )?;

    let namespace = derive_shared_issuer_local_grant_namespace_v1(verified_offer)?;
    let offer = verified_offer.offer();
    let binding = offer
        .credential_binding
        .as_ref()
        .expect("namespace derivation proved a credential binding");
    if request.provider_id != verified_offer.scope().provider_id
        || request.scope_id != verified_offer.scope().scope_id()
        || request.offer_id != offer.offer_id
        || request.scheme != offer.authorization
        || request.issuer_id != offer.issuer_id
        || request.credential_binding_digest != binding.binding_digest()?
    {
        return Err(ServiceProtocolError::InvalidValue {
            field: "ProviderRedeemRequestV1.offer",
            reason: "exact redeem request does not match the verified offer",
        });
    }
    let request_digest = request.request_digest()?;
    let local_claim_key = provider_secret.derive_local_claim_key_v1(
        request,
        &request_digest,
        &namespace.namespace_id,
    );
    if local_claim_key.iter().all(|byte| *byte == 0) {
        return Err(ServiceProtocolError::InvalidValue {
            field: "VerifiedSharedIssuerLocalGrantClaimV1.local_claim_key",
            reason: "derived local claim key is all zero",
        });
    }
    Ok(VerifiedSharedIssuerLocalGrantClaimV1 {
        namespace_id: namespace.namespace_id,
        local_claim_key,
        now_unix_seconds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_secret_and_verified_claim_debug_are_redacted() {
        let secret = SharedIssuerProviderSecretV1::from_bytes([0x5a; 32]).unwrap();
        assert_eq!(
            format!("{secret:?}"),
            "SharedIssuerProviderSecretV1(\"[REDACTED]\")"
        );
        let claim = VerifiedSharedIssuerLocalGrantClaimV1 {
            namespace_id: [0x61; 32],
            local_claim_key: [0x62; 32],
            now_unix_seconds: 7,
        };
        let rendered = format!("{claim:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("61616161"));
        assert!(!rendered.contains("62626262"));
        assert!(!rendered.contains(": 7"));
    }

    #[test]
    fn wire_and_local_domains_are_distinct_and_secret_specific() {
        let first = SharedIssuerProviderSecretV1::from_bytes([1; 32]).unwrap();
        let second = SharedIssuerProviderSecretV1::from_bytes([2; 32]).unwrap();
        let wire = first.derive_wire_idempotency_v1(&[3; 32], &[4; 32], &[5; 32]);
        let request = ProviderRedeemRequestV1 {
            authorization_digest: [3; 32],
            issuer_id: [6; 32],
            provider_id: [7; 32],
            scope_id: [8; 32],
            offer_id: 1,
            credential_binding_digest: [4; 32],
            scheme: AuthScheme::FreeV1,
            credential_digest: [5; 32],
            accepted_value: 1,
            denomination_profile: 1,
            idempotency_key: wire,
            destination: crate::SettlementDestinationV1::LedgerCredit {
                account_id: [9; 32],
            },
        };
        let digest = request.request_digest().unwrap();
        assert_eq!(
            format!("{request:?}"),
            "ProviderRedeemRequestV1 { request: \"[REDACTED]\" }"
        );
        let first_local = first.derive_local_claim_key_v1(&request, &digest, &[10; 32]);
        let second_local = second.derive_local_claim_key_v1(&request, &digest, &[10; 32]);
        assert_ne!(wire, first_local);
        assert_ne!(first_local, second_local);
        assert_eq!(
            first_local,
            first.derive_local_claim_key_v1(&request, &digest, &[10; 32])
        );
    }
}
