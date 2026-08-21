//! Verified, rollback-aware service-policy activation for a PIR provider.
//!
//! This module owns no payment secrets and performs no network access.  It
//! converts one canonical operator-signed policy plus provider-local durable
//! rollback state into the only policy object that the WebSocket runtime may
//! serve or use for admission.  A policy that cannot install every required
//! provider-local namespace is never activated in memory.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ed25519_dalek::VerifyingKey;
use pir_service_protocol::{
    bat_acceptance_member_from_retained_policy_v2, bat_acceptance_member_from_verified_policy_v2,
    AcquisitionMethod, AuthScheme, CashuManifestEpochFloorV1, CredentialKeysetEpochFloorV1,
    FreeModeV1, PolicyRollbackGuardV1, PriceV1, ProviderId, ServiceOfferV1,
    ServicePolicyEpochFloorsV1, ServicePolicyResponseV1, ServicePolicyV1, ServiceProtocolError,
    VerificationMode, VerifiedBatAcceptanceMemberV2, VerifiedCurrentPolicyV1,
    VerifiedRetiredOfferV1, VerifiedServiceOfferV1,
};
use pir_service_store::{
    ArcExclusiveKeyLineageVerifierV1, ProviderStore, StoreError,
    VerifiedOfferNamespaceInstallOutcomeV1, MAX_SIGNED_POLICY_BYTES,
};

use crate::service_admission::AdmissionMethodRouteV1;

#[derive(Debug)]
pub enum ServicePolicyActivationErrorV1 {
    EmptyPolicy,
    PolicyTooLarge { len: usize },
    NonCanonicalPolicy,
    Protocol(ServiceProtocolError),
    Store(StoreError),
    ArcProviderLocalUnavailable,
    RetainedPolicyIsCurrent,
    RetainedPolicyIsNotOlder,
    RetainedPolicyHasNoCredentialOffers,
    ExactPolicyDigestMismatch,
    StorelessPolicyIsNotFreeProofOfWorkOnly,
    StorelessBatV2PolicyShape,
    StorelessRetainedBatV2PolicyExpired,
    MissingMethodAdapter(AdmissionMethodRouteV1),
}

impl fmt::Display for ServicePolicyActivationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPolicy => formatter.write_str("signed service policy is empty"),
            Self::PolicyTooLarge { len } => write!(
                formatter,
                "signed service policy is {len} bytes, above the durable limit"
            ),
            Self::NonCanonicalPolicy => {
                formatter.write_str("signed service policy is not the canonical V1 encoding")
            }
            Self::Protocol(error) => {
                write!(formatter, "service policy verification failed: {error}")
            }
            Self::Store(error) => write!(formatter, "service policy store failed: {error}"),
            Self::ArcProviderLocalUnavailable => formatter.write_str(
                "policy advertises provider-local experimental ARC without a reviewed adapter",
            ),
            Self::RetainedPolicyIsCurrent => {
                formatter.write_str("retained service policy is the current policy")
            }
            Self::RetainedPolicyIsNotOlder => formatter.write_str(
                "retained service policy epoch must be lower than the current policy epoch",
            ),
            Self::RetainedPolicyHasNoCredentialOffers => formatter
                .write_str("retained service policy has no provider-bound credential offers"),
            Self::ExactPolicyDigestMismatch => formatter
                .write_str("service policy does not match the exact storeless policy digest pin"),
            Self::StorelessPolicyIsNotFreeProofOfWorkOnly => formatter.write_str(
                "storeless service policy must contain only provider-local Free proof-of-work offers",
            ),
            Self::StorelessBatV2PolicyShape => formatter.write_str(
                "payment-storeless BAT V2 policy must contain scheme 6 and only provider-local Free proof-of-work or shared-issuer BAT V2 offers",
            ),
            Self::StorelessRetainedBatV2PolicyExpired => formatter.write_str(
                "retained payment-storeless BAT V2 policy has no member inside its redemption horizon",
            ),
            Self::MissingMethodAdapter(route) => {
                write!(
                    formatter,
                    "policy advertises an unconfigured admission route: {route:?}"
                )
            }
        }
    }
}

impl std::error::Error for ServicePolicyActivationErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::EmptyPolicy
            | Self::PolicyTooLarge { .. }
            | Self::NonCanonicalPolicy
            | Self::ArcProviderLocalUnavailable
            | Self::RetainedPolicyIsCurrent
            | Self::RetainedPolicyIsNotOlder
            | Self::RetainedPolicyHasNoCredentialOffers
            | Self::ExactPolicyDigestMismatch
            | Self::StorelessPolicyIsNotFreeProofOfWorkOnly
            | Self::StorelessBatV2PolicyShape
            | Self::StorelessRetainedBatV2PolicyExpired
            | Self::MissingMethodAdapter(_) => None,
        }
    }
}

/// Exact method routes required by a fully verified policy. This is used at
/// startup to reject partial deployments before the policy can be served.
pub fn required_admission_routes_v1(policy: &ServicePolicyV1) -> BTreeSet<AdmissionMethodRouteV1> {
    let mut routes = BTreeSet::new();
    for scope_policy in &policy.scopes {
        for offer in &scope_policy.offers {
            if let Some(route) = admission_method_route_v1(offer) {
                routes.insert(route);
            }
        }
    }
    routes
}

/// Exact adapters needed to redeem credentials issued under a retained
/// policy. Offers without a signed credential binding are intentionally
/// excluded: a retained policy is never an acquisition/free/PoW surface.
pub fn required_retained_redemption_routes_v1(
    policy: &ServicePolicyV1,
) -> BTreeSet<AdmissionMethodRouteV1> {
    let mut routes = BTreeSet::new();
    for scope_policy in &policy.scopes {
        for offer in &scope_policy.offers {
            if offer.credential_binding.is_none()
                && offer.authorization != AuthScheme::BitcoinPirCashuBatV2
            {
                continue;
            }
            if let Some(route) = admission_method_route_v1(offer) {
                routes.insert(route);
            }
        }
    }
    routes
}

fn admission_method_route_v1(offer: &ServiceOfferV1) -> Option<AdmissionMethodRouteV1> {
    let route = match (offer.authorization, offer.free_mode, offer.verification) {
        (AuthScheme::FreeV1, FreeModeV1::OpenBestEffort, _) => {
            AdmissionMethodRouteV1::FreeOpenBestEffort
        }
        (AuthScheme::FreeV1, FreeModeV1::IpRateLimited, _) => {
            AdmissionMethodRouteV1::FreeIpRateLimited
        }
        (AuthScheme::FreeV1, FreeModeV1::ProofOfWork, _) => AdmissionMethodRouteV1::FreeProofOfWork,
        (
            AuthScheme::FreeV1,
            FreeModeV1::AnonymousTicket,
            pir_service_protocol::VerificationMode::ProviderLocal,
        ) => AdmissionMethodRouteV1::FreeAnonymousTicketProviderLocal,
        (
            AuthScheme::FreeV1,
            FreeModeV1::AnonymousTicket,
            pir_service_protocol::VerificationMode::SharedIssuerOnline,
        ) => AdmissionMethodRouteV1::FreeAnonymousTicketSharedIssuerOnline,
        (AuthScheme::Bolt11DirectReceiptV1, _, _) => {
            AdmissionMethodRouteV1::Bolt11DirectReceiptProviderLocal
        }
        (AuthScheme::CashuEcashV1, _, _) => AdmissionMethodRouteV1::StandardCashuMintOnline,
        (
            AuthScheme::BitcoinPirCashuBatV1,
            _,
            pir_service_protocol::VerificationMode::ProviderLocal,
        ) => AdmissionMethodRouteV1::BitcoinPirCashuBatProviderLocal,
        (
            AuthScheme::BitcoinPirCashuBatV1,
            _,
            pir_service_protocol::VerificationMode::SharedIssuerOnline,
        ) => AdmissionMethodRouteV1::BitcoinPirCashuBatSharedIssuerOnline,
        (
            AuthScheme::BitcoinPirCashuBatV2,
            _,
            pir_service_protocol::VerificationMode::SharedIssuerOnline,
        ) => AdmissionMethodRouteV1::BitcoinPirCashuBatV2SharedIssuerOnline,
        (
            AuthScheme::ArcV1Experimental,
            _,
            pir_service_protocol::VerificationMode::ProviderLocal,
        ) => AdmissionMethodRouteV1::ArcProviderLocalExperimental,
        (
            AuthScheme::ArcV1Experimental,
            _,
            pir_service_protocol::VerificationMode::SharedIssuerOnline,
        ) => AdmissionMethodRouteV1::ArcSharedIssuerOnlineExperimental,
        _ => return None,
    };
    Some(route)
}

pub fn validate_policy_method_coverage_v1(
    policy: &ServicePolicyV1,
    supports: impl Fn(AdmissionMethodRouteV1) -> bool,
) -> Result<(), ServicePolicyActivationErrorV1> {
    for route in required_admission_routes_v1(policy) {
        if !supports(route) {
            return Err(ServicePolicyActivationErrorV1::MissingMethodAdapter(route));
        }
    }
    Ok(())
}

pub fn validate_retained_policy_method_coverage_v1(
    policy: &ServicePolicyV1,
    supports: impl Fn(AdmissionMethodRouteV1) -> bool,
) -> Result<(), ServicePolicyActivationErrorV1> {
    for route in required_retained_redemption_routes_v1(policy) {
        if !supports(route) {
            return Err(ServicePolicyActivationErrorV1::MissingMethodAdapter(route));
        }
    }
    Ok(())
}

impl From<ServiceProtocolError> for ServicePolicyActivationErrorV1 {
    fn from(value: ServiceProtocolError) -> Self {
        Self::Protocol(value)
    }
}

impl From<StoreError> for ServicePolicyActivationErrorV1 {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

/// In-memory policy state produced only by [`activate_service_policy_v1`].
/// The durable store remains authoritative for epoch floors; these cached
/// values are an immutable snapshot for the lifetime of this server process.
#[derive(Clone, Debug)]
pub struct ActivatedServicePolicyV1 {
    policy: ServicePolicyV1,
    provider_id: ProviderId,
    verifying_key: VerifyingKey,
    rollback_guard: PolicyRollbackGuardV1,
    epoch_floors: ServicePolicyEpochFloorsV1,
    policy_digest: [u8; 32],
}

impl ActivatedServicePolicyV1 {
    pub const fn policy(&self) -> &ServicePolicyV1 {
        &self.policy
    }

    pub const fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }

    pub fn response(&self) -> ServicePolicyResponseV1 {
        ServicePolicyResponseV1 {
            policy: self.policy.clone(),
        }
    }

    /// Recheck absolute validity at the time of each acquisition.  This keeps
    /// a long-running process from accepting an offer after policy expiry.
    pub fn verify_current(
        &self,
        now_unix: u64,
    ) -> Result<VerifiedCurrentPolicyV1<'_>, ServiceProtocolError> {
        self.policy.verify_current_for_acquisition(
            &self.provider_id,
            now_unix,
            &self.rollback_guard,
            &self.epoch_floors,
            &self.verifying_key,
        )
    }

    pub fn verified_offer(
        &self,
        scope_id: &[u8; 32],
        offer_id: u32,
        now_unix: u64,
    ) -> Result<VerifiedServiceOfferV1<'_>, ServiceProtocolError> {
        self.verify_current(now_unix)?.offer(scope_id, offer_id)
    }

    pub fn verified_bat_v2_member_for_admission(
        &self,
        scope_id: &[u8; 32],
        offer_id: u32,
        now_unix: u64,
    ) -> Result<VerifiedBatAcceptanceMemberV2, ServiceProtocolError> {
        let verified = self.verify_current(now_unix)?;
        bat_acceptance_member_from_verified_policy_v2(&verified, scope_id, offer_id)
    }
}

/// One exact, operator-configured historical policy.  This type deliberately
/// exposes only credential redemption; it cannot verify current acquisition,
/// issue a quote, install a namespace, or advance rollback state.
#[derive(Clone, Debug)]
pub struct ActivatedRetainedServicePolicyV1 {
    policy: ServicePolicyV1,
    provider_id: ProviderId,
    verifying_key: VerifyingKey,
    policy_digest: [u8; 32],
}

impl ActivatedRetainedServicePolicyV1 {
    pub const fn policy(&self) -> &ServicePolicyV1 {
        &self.policy
    }

    pub const fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }

    pub fn response(&self) -> ServicePolicyResponseV1 {
        ServicePolicyResponseV1 {
            policy: self.policy.clone(),
        }
    }

    pub fn verified_offer_for_redemption(
        &self,
        scope_id: &[u8; 32],
        offer_id: u32,
        now_unix: u64,
    ) -> Result<VerifiedRetiredOfferV1<'_>, ServiceProtocolError> {
        self.policy.verify_retired_for_redemption(
            &self.provider_id,
            &self.policy_digest,
            scope_id,
            offer_id,
            now_unix,
            &self.verifying_key,
        )
    }

    pub fn has_live_redemption(&self, now_unix: u64) -> bool {
        self.policy.scopes.iter().any(|scope_policy| {
            let scope_id = scope_policy.scope.scope_id();
            scope_policy.offers.iter().any(|offer| {
                offer.credential_binding.as_ref().is_some_and(|binding| {
                    now_unix >= binding.claims.not_before && now_unix <= binding.claims.not_after
                }) && self
                    .verified_offer_for_redemption(&scope_id, offer.offer_id, now_unix)
                    .is_ok()
            })
        })
    }

    pub fn verified_bat_v2_member_for_redemption(
        &self,
        scope_id: &[u8; 32],
        offer_id: u32,
        now_unix: u64,
    ) -> Result<VerifiedBatAcceptanceMemberV2, ServiceProtocolError> {
        self.verified_bat_v2_offer_for_redemption(scope_id, offer_id, now_unix)?;
        let member = bat_acceptance_member_from_retained_policy_v2(
            &self.policy,
            &self.provider_id,
            &self.policy_digest,
            scope_id,
            offer_id,
            &self.verifying_key,
        )?;
        Ok(member)
    }

    /// Exact verified offer for binding a retained scheme-6 `AuthBeginV1`.
    /// Unlike the provider-bound V1 accessor, this accepts no credential
    /// binding and closes validity at the signed BAT V2 redemption deadline.
    pub fn verified_bat_v2_offer_for_redemption(
        &self,
        scope_id: &[u8; 32],
        offer_id: u32,
        now_unix: u64,
    ) -> Result<VerifiedServiceOfferV1<'_>, ServiceProtocolError> {
        let verified = self.policy.verify_retained_bat_v2_offer(
            &self.provider_id,
            &self.policy_digest,
            scope_id,
            offer_id,
            &self.verifying_key,
        )?;
        if now_unix < self.policy.issued_at || now_unix > verified.redemption_deadline() {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ActivatedRetainedServicePolicyV1.bat_v2_offer",
                reason: "retained BAT V2 member is outside its signed redemption horizon",
            });
        }
        Ok(verified)
    }

    pub fn has_live_bat_v2_redemption(&self, now_unix: u64) -> bool {
        self.policy.scopes.iter().any(|scope_policy| {
            let scope_id = scope_policy.scope.scope_id();
            scope_policy.offers.iter().any(|offer| {
                offer.authorization == AuthScheme::BitcoinPirCashuBatV2
                    && self
                        .verified_bat_v2_member_for_redemption(&scope_id, offer.offer_id, now_unix)
                        .is_ok()
            })
        })
    }
}

/// Verify one exact historical policy without mutating any durable state.
/// Its digest must be explicitly configured by the operator and its epoch
/// must precede the already activated current policy.
pub fn activate_retained_service_policy_v1(
    canonical_signed_policy: &[u8],
    current: &ActivatedServicePolicyV1,
) -> Result<ActivatedRetainedServicePolicyV1, ServicePolicyActivationErrorV1> {
    if canonical_signed_policy.is_empty() {
        return Err(ServicePolicyActivationErrorV1::EmptyPolicy);
    }
    if canonical_signed_policy.len() > MAX_SIGNED_POLICY_BYTES {
        return Err(ServicePolicyActivationErrorV1::PolicyTooLarge {
            len: canonical_signed_policy.len(),
        });
    }
    let policy = ServicePolicyV1::decode(canonical_signed_policy)?;
    if policy.encode()?.as_slice() != canonical_signed_policy {
        return Err(ServicePolicyActivationErrorV1::NonCanonicalPolicy);
    }
    policy.verify_signature_and_identity(&current.provider_id, &current.verifying_key)?;
    let policy_digest = policy.policy_digest()?;
    if policy_digest == current.policy_digest {
        return Err(ServicePolicyActivationErrorV1::RetainedPolicyIsCurrent);
    }
    if policy.policy_epoch >= current.policy.policy_epoch {
        return Err(ServicePolicyActivationErrorV1::RetainedPolicyIsNotOlder);
    }
    if !policy.scopes.iter().any(|scope_policy| {
        scope_policy
            .offers
            .iter()
            .any(|offer| offer.credential_binding.is_some())
    }) {
        return Err(ServicePolicyActivationErrorV1::RetainedPolicyHasNoCredentialOffers);
    }

    Ok(ActivatedRetainedServicePolicyV1 {
        policy,
        provider_id: current.provider_id,
        verifying_key: current.verifying_key,
        policy_digest,
    })
}

/// Activate one exact, signed, provider-local Free proof-of-work policy without
/// opening a ProviderStore.
///
/// This deliberately narrow mode exists for measured, immutable deployments
/// whose command line pins the exact canonical policy digest. The digest pin is
/// the rollback/fork boundary: accepting an operator key, epoch floor, or
/// mutable policy path alone would let a hostile host replay an older signed
/// free policy. Paid methods, durable IP quota, anonymous tickets, retained
/// policies, and every credential-bearing offer still require the ordinary
/// rollback-aware [`activate_service_policy_v1`] path.
pub fn activate_exact_storeless_free_pow_policy_v1(
    canonical_signed_policy: &[u8],
    expected_provider_id: ProviderId,
    verifying_key: VerifyingKey,
    expected_policy_digest: [u8; 32],
    now_unix: u64,
) -> Result<ActivatedServicePolicyV1, ServicePolicyActivationErrorV1> {
    if canonical_signed_policy.is_empty() {
        return Err(ServicePolicyActivationErrorV1::EmptyPolicy);
    }
    if canonical_signed_policy.len() > MAX_SIGNED_POLICY_BYTES {
        return Err(ServicePolicyActivationErrorV1::PolicyTooLarge {
            len: canonical_signed_policy.len(),
        });
    }

    let policy = ServicePolicyV1::decode(canonical_signed_policy)?;
    if policy.encode()?.as_slice() != canonical_signed_policy {
        return Err(ServicePolicyActivationErrorV1::NonCanonicalPolicy);
    }
    let policy_digest = policy.policy_digest()?;
    if expected_policy_digest.iter().all(|byte| *byte == 0)
        || policy_digest != expected_policy_digest
    {
        return Err(ServicePolicyActivationErrorV1::ExactPolicyDigestMismatch);
    }
    if policy.scopes.is_empty()
        || policy.scopes.iter().any(|scope| scope.offers.is_empty())
        || policy
            .scopes
            .iter()
            .flat_map(|scope| &scope.offers)
            .any(|offer| {
                offer.acquisition != AcquisitionMethod::FreeV1
                    || offer.authorization != AuthScheme::FreeV1
                    || offer.free_mode != FreeModeV1::ProofOfWork
                    || offer.verification != VerificationMode::ProviderLocal
                    || offer.price != PriceV1::Free
                    || offer.issuer_id != [0; 32]
                    || !offer.key_id.is_empty()
                    || offer.credential_binding.is_some()
                    || offer.cashu_mint_manifest.is_some()
                    || !offer.endpoint.is_empty()
                    || offer.invoice_expiry_seconds != 0
                    || offer.claim_window_seconds != 0
                    || offer.minimum_credential_validity_seconds != 1
                    || offer.retired_policy_grace_seconds != 0
                    || offer.credential_count != 1
                    || offer.credential_presentation_limit != 1
                    || offer.privacy_leakage != pir_service_protocol::PrivacyLeakageV1::NONE
            })
    {
        return Err(ServicePolicyActivationErrorV1::StorelessPolicyIsNotFreeProofOfWorkOnly);
    }

    // The exact digest pin supplies both the epoch and same-epoch fork guard.
    // Credential/mint floors are empty because the policy shape above forbids
    // all credential and Cashu material.
    let rollback_guard = PolicyRollbackGuardV1 {
        highest_epoch: policy.policy_epoch,
        digest_at_highest_epoch: policy_digest,
    };
    let epoch_floors = ServicePolicyEpochFloorsV1::initial();
    policy.verify_current_for_acquisition(
        &expected_provider_id,
        now_unix,
        &rollback_guard,
        &epoch_floors,
        &verifying_key,
    )?;

    Ok(ActivatedServicePolicyV1 {
        policy,
        provider_id: expected_provider_id,
        verifying_key,
        rollback_guard,
        epoch_floors,
        policy_digest,
    })
}

/// Activate one exact, payment-storeless policy whose only admission methods
/// are provider-local Free-PoW and issuer-wide BAT V2. The exact digest is the
/// immutable rollback/fork boundary; no ProviderStore or payment rollback
/// authority participates in this mode.
pub fn activate_exact_storeless_bat_v2_policy_v1(
    canonical_signed_policy: &[u8],
    expected_provider_id: ProviderId,
    verifying_key: VerifyingKey,
    expected_policy_digest: [u8; 32],
    now_unix: u64,
) -> Result<ActivatedServicePolicyV1, ServicePolicyActivationErrorV1> {
    let policy = decode_exact_storeless_policy_v1(canonical_signed_policy, expected_policy_digest)?;
    if !is_closed_storeless_bat_v2_policy_v1(&policy) {
        return Err(ServicePolicyActivationErrorV1::StorelessBatV2PolicyShape);
    }

    let rollback_guard = PolicyRollbackGuardV1 {
        highest_epoch: policy.policy_epoch,
        digest_at_highest_epoch: expected_policy_digest,
    };
    let epoch_floors = ServicePolicyEpochFloorsV1::initial();
    let verified = policy.verify_current_for_acquisition(
        &expected_provider_id,
        now_unix,
        &rollback_guard,
        &epoch_floors,
        &verifying_key,
    )?;
    for scope_policy in &policy.scopes {
        let scope_id = scope_policy.scope.scope_id();
        for offer in &scope_policy.offers {
            if offer.authorization == AuthScheme::BitcoinPirCashuBatV2 {
                bat_acceptance_member_from_verified_policy_v2(
                    &verified,
                    &scope_id,
                    offer.offer_id,
                )?;
            }
        }
    }

    Ok(ActivatedServicePolicyV1 {
        policy,
        provider_id: expected_provider_id,
        verifying_key,
        rollback_guard,
        epoch_floors,
        policy_digest: expected_policy_digest,
    })
}

/// Activate one exact older payment-storeless BAT V2 policy only while at
/// least one of its scheme-6 members remains inside the signed redemption
/// horizon. Free-PoW offers in the immutable bytes are never redemption
/// methods. The caller must pin each retained digest explicitly.
pub fn activate_exact_storeless_retained_bat_v2_policy_v1(
    canonical_signed_policy: &[u8],
    expected_policy_digest: [u8; 32],
    current: &ActivatedServicePolicyV1,
    now_unix: u64,
) -> Result<ActivatedRetainedServicePolicyV1, ServicePolicyActivationErrorV1> {
    let policy = decode_exact_storeless_policy_v1(canonical_signed_policy, expected_policy_digest)?;
    policy.verify_signature_and_identity(&current.provider_id, &current.verifying_key)?;
    if expected_policy_digest == current.policy_digest {
        return Err(ServicePolicyActivationErrorV1::RetainedPolicyIsCurrent);
    }
    if policy.policy_epoch >= current.policy.policy_epoch {
        return Err(ServicePolicyActivationErrorV1::RetainedPolicyIsNotOlder);
    }
    if !is_closed_storeless_bat_v2_policy_v1(&policy) {
        return Err(ServicePolicyActivationErrorV1::StorelessBatV2PolicyShape);
    }

    let retained = ActivatedRetainedServicePolicyV1 {
        policy,
        provider_id: current.provider_id,
        verifying_key: current.verifying_key,
        policy_digest: expected_policy_digest,
    };
    if !retained.has_live_bat_v2_redemption(now_unix) {
        return Err(ServicePolicyActivationErrorV1::StorelessRetainedBatV2PolicyExpired);
    }
    Ok(retained)
}

fn decode_exact_storeless_policy_v1(
    canonical_signed_policy: &[u8],
    expected_policy_digest: [u8; 32],
) -> Result<ServicePolicyV1, ServicePolicyActivationErrorV1> {
    if canonical_signed_policy.is_empty() {
        return Err(ServicePolicyActivationErrorV1::EmptyPolicy);
    }
    if canonical_signed_policy.len() > MAX_SIGNED_POLICY_BYTES {
        return Err(ServicePolicyActivationErrorV1::PolicyTooLarge {
            len: canonical_signed_policy.len(),
        });
    }
    let policy = ServicePolicyV1::decode(canonical_signed_policy)?;
    if policy.encode()?.as_slice() != canonical_signed_policy {
        return Err(ServicePolicyActivationErrorV1::NonCanonicalPolicy);
    }
    let policy_digest = policy.policy_digest()?;
    if expected_policy_digest.iter().all(|byte| *byte == 0)
        || policy_digest != expected_policy_digest
    {
        return Err(ServicePolicyActivationErrorV1::ExactPolicyDigestMismatch);
    }
    Ok(policy)
}

fn is_closed_storeless_bat_v2_policy_v1(policy: &ServicePolicyV1) -> bool {
    if policy.scopes.is_empty() {
        return false;
    }
    for scope in &policy.scopes {
        if scope.offers.len() != 2 {
            return false;
        }
        let mut free_pow_count = 0;
        let mut bat_v2_count = 0;
        for offer in &scope.offers {
            if offer.authorization == AuthScheme::BitcoinPirCashuBatV2 {
                bat_v2_count += 1;
                if offer.acquisition != AcquisitionMethod::Bolt11V1
                    || offer.free_mode != FreeModeV1::NotFree
                    || offer.verification != VerificationMode::SharedIssuerOnline
                    || !matches!(offer.price, PriceV1::MilliSatoshi(_))
                    || offer.issuer_id.iter().all(|byte| *byte == 0)
                    || offer.key_id.len() != 32
                    || offer.key_id.iter().all(|byte| *byte == 0)
                    || offer.credential_binding.is_some()
                    || offer.cashu_mint_manifest.is_some()
                {
                    return false;
                }
            } else {
                free_pow_count += 1;
                if offer.acquisition != AcquisitionMethod::FreeV1
                    || offer.authorization != AuthScheme::FreeV1
                    || offer.free_mode != FreeModeV1::ProofOfWork
                    || offer.verification != VerificationMode::ProviderLocal
                    || offer.price != PriceV1::Free
                    || offer.issuer_id != [0; 32]
                    || !offer.key_id.is_empty()
                    || offer.credential_binding.is_some()
                    || offer.cashu_mint_manifest.is_some()
                    || !offer.endpoint.is_empty()
                    || offer.invoice_expiry_seconds != 0
                    || offer.claim_window_seconds != 0
                    || offer.minimum_credential_validity_seconds != 1
                    || offer.retired_policy_grace_seconds != 0
                    || offer.credential_count != 1
                    || offer.credential_presentation_limit != 1
                    || offer.privacy_leakage != pir_service_protocol::PrivacyLeakageV1::NONE
                {
                    return false;
                }
            }
        }
        if free_pow_count != 1 || bat_v2_count != 1 {
            return false;
        }
    }
    true
}

/// Decode, verify, durably advance rollback state, install provider-local
/// bearer namespaces, and only then return an activatable policy.
pub fn activate_service_policy_v1(
    canonical_signed_policy: &[u8],
    expected_provider_id: ProviderId,
    verifying_key: VerifyingKey,
    store: &ProviderStore,
    now_unix: u64,
    arc_lineage_verifier: Option<&dyn ArcExclusiveKeyLineageVerifierV1>,
) -> Result<ActivatedServicePolicyV1, ServicePolicyActivationErrorV1> {
    if canonical_signed_policy.is_empty() {
        return Err(ServicePolicyActivationErrorV1::EmptyPolicy);
    }
    if canonical_signed_policy.len() > MAX_SIGNED_POLICY_BYTES {
        return Err(ServicePolicyActivationErrorV1::PolicyTooLarge {
            len: canonical_signed_policy.len(),
        });
    }
    if store.identity()?.provider_id != expected_provider_id {
        return Err(StoreError::ProviderMismatch.into());
    }

    let policy = ServicePolicyV1::decode(canonical_signed_policy)?;
    if policy.encode()?.as_slice() != canonical_signed_policy {
        return Err(ServicePolicyActivationErrorV1::NonCanonicalPolicy);
    }

    let rollback_guard = match store.policy_head()? {
        Some(head) => PolicyRollbackGuardV1 {
            highest_epoch: head.highest_policy_epoch,
            digest_at_highest_epoch: head.policy_digest,
        },
        None => PolicyRollbackGuardV1::initial(),
    };
    let prior_floors = policy_epoch_floors_for_candidate(store, &policy)?;
    let verified = policy.verify_current_for_acquisition(
        &expected_provider_id,
        now_unix,
        &rollback_guard,
        &prior_floors,
        &verifying_key,
    )?;

    // Persist the verified head and every monotonic floor before a response
    // containing this policy can escape the process.
    store.apply_verified_policy_state_v1(&verified)?;

    for scope_policy in &policy.scopes {
        let scope_id = scope_policy.scope.scope_id();
        for offer in &scope_policy.offers {
            let verified_offer = verified.offer(&scope_id, offer.offer_id)?;
            let outcome = store.install_verified_offer_namespace_v1(
                &verified_offer,
                now_unix,
                arc_lineage_verifier,
            )?;
            if outcome == VerifiedOfferNamespaceInstallOutcomeV1::UnsupportedExperimental {
                return Err(ServicePolicyActivationErrorV1::ArcProviderLocalUnavailable);
            }
        }
    }

    let policy_digest = verified.policy_digest();
    let rollback_guard = PolicyRollbackGuardV1::from_verified(&verified);
    let epoch_floors = policy_epoch_floors_for_candidate(store, &policy)?;
    // Reverify against the exact post-commit snapshot.  This catches store
    // adapter bugs or a concurrently advanced floor before activation.
    policy.verify_current_for_acquisition(
        &expected_provider_id,
        now_unix,
        &rollback_guard,
        &epoch_floors,
        &verifying_key,
    )?;

    Ok(ActivatedServicePolicyV1 {
        policy,
        provider_id: expected_provider_id,
        verifying_key,
        rollback_guard,
        epoch_floors,
        policy_digest,
    })
}

fn policy_epoch_floors_for_candidate(
    store: &ProviderStore,
    policy: &ServicePolicyV1,
) -> Result<ServicePolicyEpochFloorsV1, StoreError> {
    let mut credential_keysets = BTreeMap::new();
    let mut cashu_manifests = BTreeMap::new();
    for scope_policy in &policy.scopes {
        let scope_id = scope_policy.scope.scope_id();
        for offer in &scope_policy.offers {
            if offer.credential_binding.is_some() {
                if let Some(minimum_epoch) = store.credential_epoch_floor(
                    &scope_id,
                    offer.authorization as u16,
                    &offer.issuer_id,
                )? {
                    credential_keysets.insert(
                        (scope_id, offer.authorization as u8, offer.issuer_id),
                        CredentialKeysetEpochFloorV1 {
                            scope_id,
                            scheme: offer.authorization,
                            issuer_id: offer.issuer_id,
                            minimum_epoch,
                        },
                    );
                }
            }
            if let Some(manifest) = &offer.cashu_mint_manifest {
                if let Some(minimum_epoch) =
                    store.cashu_manifest_epoch_floor(&offer.issuer_id, &manifest.unit)?
                {
                    cashu_manifests.insert(
                        (offer.issuer_id, manifest.unit.clone()),
                        CashuManifestEpochFloorV1 {
                            mint_id: offer.issuer_id,
                            unit: manifest.unit.clone(),
                            minimum_epoch,
                        },
                    );
                }
            }
        }
    }
    Ok(ServicePolicyEpochFloorsV1 {
        credential_keysets: credential_keysets.into_values().collect(),
        cashu_manifests: cashu_manifests.into_values().collect(),
    })
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use ed25519_dalek::SigningKey;
    use pir_service_protocol::{
        paid_receipt_key_id, AcquisitionMethod, AuthPaddingClassV1, AuthScheme, BackendId,
        CredentialKeyBindingClaimsV1, CredentialKeyBindingV1, CredentialUnitV1, DatasetBindingV1,
        DeploymentStatus, EntitlementLimitsV1, FreeModeV1, PriceV1, PrivacyLeakageV1,
        ServiceOfferV1, ServiceScopePolicyV1, ServiceScopeV1, VerificationMode, WorkloadId,
    };
    use pir_service_store::StoreOptions;
    use tempfile::{tempdir, TempDir};

    use super::*;

    fn private_tempdir() -> TempDir {
        let directory = tempdir().unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn free_policy(signing: &SigningKey, provider_id: ProviderId, epoch: u64) -> ServicePolicyV1 {
        let scope = ServiceScopeV1 {
            provider_id,
            backend: BackendId::DpfPirV1,
            workload: WorkloadId::DpfEvaluateJobV1,
            protocol_version: 1,
            dataset: DatasetBindingV1::Class { class_id: 7 },
            operation_profile: 8,
            entitlement_profile: 9,
        };
        ServicePolicyV1::sign(
            provider_id,
            epoch,
            100,
            200,
            AuthPaddingClassV1::Class16KiB,
            vec![ServiceScopePolicyV1 {
                scope,
                limits: EntitlementLimitsV1 {
                    max_logical_inputs: 1,
                    max_frames: 1,
                    max_request_bytes: 1024,
                    max_response_bytes: 2048,
                    max_wall_time_ms: 5_000,
                    max_concurrent_sockets: 1,
                    max_hint_groups: 0,
                    max_work_units: 1,
                },
                offers: vec![ServiceOfferV1 {
                    offer_id: 1,
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
                    minimum_credential_validity_seconds: 1,
                    retired_policy_grace_seconds: 0,
                    credential_count: 1,
                    credential_presentation_limit: 1,
                    privacy_leakage: PrivacyLeakageV1::NONE,
                }],
            }],
            signing,
        )
        .unwrap()
    }

    fn free_pow_policy(
        signing: &SigningKey,
        provider_id: ProviderId,
        epoch: u64,
    ) -> ServicePolicyV1 {
        let template = free_policy(signing, provider_id, epoch);
        let mut scopes = template.scopes;
        let offer = &mut scopes[0].offers[0];
        offer.free_mode = FreeModeV1::ProofOfWork;
        offer.free_pow_difficulty_bits = 8;
        ServicePolicyV1::sign(
            provider_id,
            epoch,
            template.issued_at,
            template.expires_at,
            template.auth_padding_class,
            scopes,
            signing,
        )
        .unwrap()
    }

    fn storeless_bat_v2_policy(
        signing: &SigningKey,
        provider_id: ProviderId,
        epoch: u64,
    ) -> (ServicePolicyV1, [u8; 32]) {
        let template = free_pow_policy(signing, provider_id, epoch);
        let mut scopes = template.scopes;
        let scope_id = scopes[0].scope.scope_id();
        scopes[0].offers.push(ServiceOfferV1 {
            offer_id: 2,
            acquisition: AcquisitionMethod::Bolt11V1,
            free_mode: FreeModeV1::NotFree,
            free_quota: 0,
            free_window_seconds: 0,
            free_pow_difficulty_bits: 0,
            priority_class: 1,
            authorization: AuthScheme::BitcoinPirCashuBatV2,
            verification: VerificationMode::SharedIssuerOnline,
            deployment_status: DeploymentStatus::Stable,
            price: PriceV1::MilliSatoshi(1_000),
            issuer_id: [7; 32],
            key_id: vec![8; 32],
            credential_binding: None,
            cashu_mint_manifest: None,
            endpoint: "https://issuer.invalid".into(),
            invoice_expiry_seconds: 10,
            claim_window_seconds: 10,
            minimum_credential_validity_seconds: 100,
            retired_policy_grace_seconds: 120,
            credential_count: 1,
            credential_presentation_limit: 1,
            privacy_leakage: PrivacyLeakageV1::from_bits(
                PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING
                    | PrivacyLeakageV1::ISSUER_REDEMPTION_TIMING
                    | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER,
            )
            .unwrap(),
        });
        (
            ServicePolicyV1::sign(
                provider_id,
                epoch,
                template.issued_at,
                template.expires_at,
                template.auth_padding_class,
                scopes,
                signing,
            )
            .unwrap(),
            scope_id,
        )
    }

    fn retained_receipt_policy(
        signing: &SigningKey,
        provider_id: ProviderId,
        epoch: u64,
    ) -> (ServicePolicyV1, [u8; 32]) {
        let scope = ServiceScopeV1 {
            provider_id,
            backend: BackendId::DpfPirV1,
            workload: WorkloadId::DpfEvaluateJobV1,
            protocol_version: 1,
            dataset: DatasetBindingV1::Class { class_id: 7 },
            operation_profile: 8,
            entitlement_profile: 9,
        };
        let scope_id = scope.scope_id();
        let receipt_key = SigningKey::from_bytes(&[5; 32]);
        let credential_key_id = paid_receipt_key_id(&receipt_key.verifying_key()).to_vec();
        let binding = CredentialKeyBindingV1::sign(
            CredentialKeyBindingClaimsV1 {
                provider_id,
                scope_id,
                offer_id: 7,
                scheme: AuthScheme::Bolt11DirectReceiptV1,
                keyset_epoch: 1,
                entitlement_profile: 9,
                unit: CredentialUnitV1::Entitlement,
                amount: 1,
                presentation_limit: 1,
                not_before: 50,
                not_after: 1_120,
                credential_key_id: credential_key_id.clone(),
                verification_key: receipt_key.verifying_key().to_bytes().to_vec(),
            },
            &SigningKey::from_bytes(&[7; 32]),
        )
        .unwrap();
        let policy = ServicePolicyV1::sign(
            provider_id,
            epoch,
            100,
            120,
            AuthPaddingClassV1::Class16KiB,
            vec![ServiceScopePolicyV1 {
                scope,
                limits: EntitlementLimitsV1 {
                    max_logical_inputs: 1,
                    max_frames: 1,
                    max_request_bytes: 1024,
                    max_response_bytes: 2048,
                    max_wall_time_ms: 5_000,
                    max_concurrent_sockets: 1,
                    max_hint_groups: 0,
                    max_work_units: 1,
                },
                offers: vec![ServiceOfferV1 {
                    offer_id: 7,
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
                    invoice_expiry_seconds: 10,
                    claim_window_seconds: 10,
                    minimum_credential_validity_seconds: 100,
                    retired_policy_grace_seconds: 1_000,
                    credential_count: 1,
                    credential_presentation_limit: 1,
                    privacy_leakage: PrivacyLeakageV1::from_bits(
                        PrivacyLeakageV1::DIRECT_PAYMENT_TO_SPEND,
                    )
                    .unwrap(),
                }],
            }],
            signing,
        )
        .unwrap();
        (policy, scope_id)
    }

    #[test]
    fn activation_persists_head_and_rejects_rollback_or_noncanonical_bytes() {
        let dir = private_tempdir();
        let provider_id = [9; 32];
        let store = ProviderStore::create(
            dir.path().join("provider.sqlite"),
            [1; 16],
            provider_id,
            StoreOptions {
                busy_timeout: Duration::from_secs(1),
            },
        )
        .unwrap();
        let signing = SigningKey::from_bytes(&[3; 32]);
        let policy = free_policy(&signing, provider_id, 2);
        let bytes = policy.encode().unwrap();
        let activated = activate_service_policy_v1(
            &bytes,
            provider_id,
            signing.verifying_key(),
            &store,
            150,
            None,
        )
        .unwrap();
        assert_eq!(activated.policy_digest(), policy.policy_digest().unwrap());
        assert!(activated.verify_current(150).is_ok());
        assert_eq!(store.policy_head().unwrap().unwrap().signed_policy, bytes);

        let old = free_policy(&signing, provider_id, 1).encode().unwrap();
        assert!(activate_service_policy_v1(
            &old,
            provider_id,
            signing.verifying_key(),
            &store,
            150,
            None,
        )
        .is_err());

        let mut trailing = policy.encode().unwrap();
        trailing.push(0);
        assert!(activate_service_policy_v1(
            &trailing,
            provider_id,
            signing.verifying_key(),
            &store,
            150,
            None,
        )
        .is_err());
    }

    #[test]
    fn exact_storeless_free_pow_activation_needs_no_store_and_keeps_exact_pin() {
        let provider_id = [9; 32];
        let signing = SigningKey::from_bytes(&[3; 32]);
        let policy = free_pow_policy(&signing, provider_id, 2);
        let bytes = policy.encode().unwrap();
        let digest = policy.policy_digest().unwrap();

        let activated = activate_exact_storeless_free_pow_policy_v1(
            &bytes,
            provider_id,
            signing.verifying_key(),
            digest,
            150,
        )
        .unwrap();
        assert_eq!(activated.policy_digest(), digest);
        assert!(activated.verify_current(150).is_ok());

        let wrong_digest = [0x42; 32];
        assert!(matches!(
            activate_exact_storeless_free_pow_policy_v1(
                &bytes,
                provider_id,
                signing.verifying_key(),
                wrong_digest,
                150,
            ),
            Err(ServicePolicyActivationErrorV1::ExactPolicyDigestMismatch)
        ));
        assert!(matches!(
            activate_exact_storeless_free_pow_policy_v1(
                &bytes,
                provider_id,
                signing.verifying_key(),
                [0; 32],
                150,
            ),
            Err(ServicePolicyActivationErrorV1::ExactPolicyDigestMismatch)
        ));
    }

    #[test]
    fn exact_storeless_free_pow_rejects_every_broader_policy_shape() {
        let provider_id = [9; 32];
        let signing = SigningKey::from_bytes(&[3; 32]);

        let open = free_policy(&signing, provider_id, 2);
        let open_bytes = open.encode().unwrap();
        assert!(matches!(
            activate_exact_storeless_free_pow_policy_v1(
                &open_bytes,
                provider_id,
                signing.verifying_key(),
                open.policy_digest().unwrap(),
                150,
            ),
            Err(ServicePolicyActivationErrorV1::StorelessPolicyIsNotFreeProofOfWorkOnly)
        ));

        let paid = retained_receipt_policy(&signing, provider_id, 2).0;
        let paid_bytes = paid.encode().unwrap();
        assert!(matches!(
            activate_exact_storeless_free_pow_policy_v1(
                &paid_bytes,
                provider_id,
                signing.verifying_key(),
                paid.policy_digest().unwrap(),
                110,
            ),
            Err(ServicePolicyActivationErrorV1::StorelessPolicyIsNotFreeProofOfWorkOnly)
        ));

        let policy = free_pow_policy(&signing, provider_id, 2);
        let mut trailing = policy.encode().unwrap();
        trailing.push(0);
        assert!(activate_exact_storeless_free_pow_policy_v1(
            &trailing,
            provider_id,
            signing.verifying_key(),
            policy.policy_digest().unwrap(),
            150,
        )
        .is_err());
        assert!(activate_exact_storeless_free_pow_policy_v1(
            &policy.encode().unwrap(),
            [8; 32],
            signing.verifying_key(),
            policy.policy_digest().unwrap(),
            150,
        )
        .is_err());
        assert!(activate_exact_storeless_free_pow_policy_v1(
            &policy.encode().unwrap(),
            provider_id,
            SigningKey::from_bytes(&[4; 32]).verifying_key(),
            policy.policy_digest().unwrap(),
            150,
        )
        .is_err());

        let empty = ServicePolicyV1::sign(
            provider_id,
            2,
            100,
            200,
            AuthPaddingClassV1::Class16KiB,
            Vec::new(),
            &signing,
        )
        .unwrap();
        assert!(matches!(
            activate_exact_storeless_free_pow_policy_v1(
                &empty.encode().unwrap(),
                provider_id,
                signing.verifying_key(),
                empty.policy_digest().unwrap(),
                150,
            ),
            Err(ServicePolicyActivationErrorV1::StorelessPolicyIsNotFreeProofOfWorkOnly)
        ));

        let template = free_pow_policy(&signing, provider_id, 2);
        let mut empty_offer_scopes = template.scopes;
        empty_offer_scopes[0].offers.clear();
        let empty_offer_scope = ServicePolicyV1::sign(
            provider_id,
            2,
            template.issued_at,
            template.expires_at,
            template.auth_padding_class,
            empty_offer_scopes,
            &signing,
        )
        .unwrap();
        assert!(matches!(
            activate_exact_storeless_free_pow_policy_v1(
                &empty_offer_scope.encode().unwrap(),
                provider_id,
                signing.verifying_key(),
                empty_offer_scope.policy_digest().unwrap(),
                150,
            ),
            Err(ServicePolicyActivationErrorV1::StorelessPolicyIsNotFreeProofOfWorkOnly)
        ));

        for mutate in [
            |offer: &mut ServiceOfferV1| offer.endpoint = "https://issuer.invalid".to_owned(),
            |offer: &mut ServiceOfferV1| offer.minimum_credential_validity_seconds = 2,
            |offer: &mut ServiceOfferV1| offer.retired_policy_grace_seconds = 1,
            |offer: &mut ServiceOfferV1| {
                offer.privacy_leakage =
                    PrivacyLeakageV1::from_bits(PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING).unwrap()
            },
        ] {
            let template = free_pow_policy(&signing, provider_id, 2);
            let mut scopes = template.scopes;
            mutate(&mut scopes[0].offers[0]);
            let decorated = ServicePolicyV1::sign(
                provider_id,
                2,
                template.issued_at,
                template.expires_at,
                template.auth_padding_class,
                scopes,
                &signing,
            )
            .unwrap();
            assert!(matches!(
                activate_exact_storeless_free_pow_policy_v1(
                    &decorated.encode().unwrap(),
                    provider_id,
                    signing.verifying_key(),
                    decorated.policy_digest().unwrap(),
                    150,
                ),
                Err(ServicePolicyActivationErrorV1::StorelessPolicyIsNotFreeProofOfWorkOnly)
            ));
        }
    }

    #[test]
    fn exact_storeless_bat_v2_activation_is_closed_and_uses_its_own_route() {
        let provider_id = [9; 32];
        let signing = SigningKey::from_bytes(&[3; 32]);
        let (policy, scope_id) = storeless_bat_v2_policy(&signing, provider_id, 2);
        let bytes = policy.encode().unwrap();
        let digest = policy.policy_digest().unwrap();

        let activated = activate_exact_storeless_bat_v2_policy_v1(
            &bytes,
            provider_id,
            signing.verifying_key(),
            digest,
            150,
        )
        .unwrap();
        let member = activated
            .verified_bat_v2_member_for_admission(&scope_id, 2, 150)
            .unwrap();
        assert_eq!(member.member.policy_digest, digest);
        assert_eq!(member.member.scope_id, scope_id);
        assert_eq!(member.class_id, [8; 32]);
        assert_eq!(
            required_admission_routes_v1(activated.policy()),
            BTreeSet::from([
                AdmissionMethodRouteV1::FreeProofOfWork,
                AdmissionMethodRouteV1::BitcoinPirCashuBatV2SharedIssuerOnline,
            ])
        );

        assert!(matches!(
            activate_exact_storeless_free_pow_policy_v1(
                &bytes,
                provider_id,
                signing.verifying_key(),
                digest,
                150,
            ),
            Err(ServicePolicyActivationErrorV1::StorelessPolicyIsNotFreeProofOfWorkOnly)
        ));
        let free_only = free_pow_policy(&signing, provider_id, 2);
        assert!(matches!(
            activate_exact_storeless_bat_v2_policy_v1(
                &free_only.encode().unwrap(),
                provider_id,
                signing.verifying_key(),
                free_only.policy_digest().unwrap(),
                150,
            ),
            Err(ServicePolicyActivationErrorV1::StorelessBatV2PolicyShape)
        ));

        let resign = |template: &ServicePolicyV1, scopes: Vec<ServiceScopePolicyV1>| {
            ServicePolicyV1::sign(
                provider_id,
                template.policy_epoch,
                template.issued_at,
                template.expires_at,
                template.auth_padding_class,
                scopes,
                &signing,
            )
            .unwrap()
        };
        let rejects_closed_shape = |candidate: &ServicePolicyV1| {
            matches!(
                activate_exact_storeless_bat_v2_policy_v1(
                    &candidate.encode().unwrap(),
                    provider_id,
                    signing.verifying_key(),
                    candidate.policy_digest().unwrap(),
                    150,
                ),
                Err(ServicePolicyActivationErrorV1::StorelessBatV2PolicyShape)
            )
        };

        let (template, _) = storeless_bat_v2_policy(&signing, provider_id, 2);
        let free_offer = template.scopes[0].offers[0].clone();
        let bat_offer = template.scopes[0].offers[1].clone();

        let mut only_bat_scopes = template.scopes.clone();
        only_bat_scopes[0].offers = vec![bat_offer.clone()];
        assert!(rejects_closed_shape(&resign(&template, only_bat_scopes)));

        let mut duplicate_bat = bat_offer.clone();
        duplicate_bat.offer_id = 3;
        let mut duplicate_bat_scopes = template.scopes.clone();
        duplicate_bat_scopes[0].offers = vec![bat_offer.clone(), duplicate_bat];
        assert!(rejects_closed_shape(&resign(
            &template,
            duplicate_bat_scopes,
        )));

        let mut duplicate_free = free_offer.clone();
        duplicate_free.offer_id = 3;
        let mut duplicate_free_scopes = template.scopes.clone();
        duplicate_free_scopes[0].offers = vec![free_offer.clone(), duplicate_free];
        assert!(rejects_closed_shape(&resign(
            &template,
            duplicate_free_scopes,
        )));

        let mut bat_only_scope = template.scopes[0].clone();
        bat_only_scope.offers = vec![bat_offer];
        let mut free_only_scope = template.scopes[0].clone();
        free_only_scope.scope.dataset = DatasetBindingV1::Class { class_id: 12 };
        free_only_scope.offers = vec![free_offer];
        let mut split_method_scopes = vec![bat_only_scope, free_only_scope];
        split_method_scopes.sort_by_key(|scope| scope.scope.scope_id());
        assert!(rejects_closed_shape(&resign(
            &template,
            split_method_scopes,
        )));
    }

    #[test]
    fn exact_storeless_retained_bat_v2_is_digest_pinned_and_horizon_closed() {
        let provider_id = [9; 32];
        let signing = SigningKey::from_bytes(&[3; 32]);
        let (current_policy, _) = storeless_bat_v2_policy(&signing, provider_id, 2);
        let current = activate_exact_storeless_bat_v2_policy_v1(
            &current_policy.encode().unwrap(),
            provider_id,
            signing.verifying_key(),
            current_policy.policy_digest().unwrap(),
            150,
        )
        .unwrap();
        let (old_policy, old_scope_id) = storeless_bat_v2_policy(&signing, provider_id, 1);
        let old_bytes = old_policy.encode().unwrap();
        let old_digest = old_policy.policy_digest().unwrap();

        let retained = activate_exact_storeless_retained_bat_v2_policy_v1(
            &old_bytes, old_digest, &current, 250,
        )
        .unwrap();
        assert!(retained.has_live_bat_v2_redemption(320));
        assert!(retained
            .verified_bat_v2_member_for_redemption(&old_scope_id, 2, 320)
            .is_ok());
        assert!(retained
            .verified_bat_v2_offer_for_redemption(&old_scope_id, 2, 320)
            .is_ok());
        assert!(retained
            .verified_bat_v2_member_for_redemption(&old_scope_id, 2, 321)
            .is_err());
        assert!(retained
            .verified_bat_v2_offer_for_redemption(&old_scope_id, 2, 321)
            .is_err());
        assert!(matches!(
            activate_exact_storeless_retained_bat_v2_policy_v1(
                &old_bytes, old_digest, &current, 321,
            ),
            Err(ServicePolicyActivationErrorV1::StorelessRetainedBatV2PolicyExpired)
        ));
        assert!(matches!(
            activate_exact_storeless_retained_bat_v2_policy_v1(&old_bytes, [42; 32], &current, 250,),
            Err(ServicePolicyActivationErrorV1::ExactPolicyDigestMismatch)
        ));
    }

    #[test]
    fn retained_activation_is_exact_redemption_only_and_restart_safe() {
        let dir = private_tempdir();
        let provider_id = [9; 32];
        let store_path = dir.path().join("provider.sqlite");
        let options = StoreOptions {
            busy_timeout: Duration::from_secs(1),
        };
        let store = ProviderStore::create(
            &store_path,
            [1; 16],
            provider_id,
            options,
        )
        .unwrap();
        let signing = SigningKey::from_bytes(&[3; 32]);
        let (old_policy, scope_id) = retained_receipt_policy(&signing, provider_id, 1);
        let old_bytes = old_policy.encode().unwrap();

        // Install the old provider-local spend namespace while the policy is
        // current, then advance to a newer current policy.
        activate_service_policy_v1(
            &old_bytes,
            provider_id,
            signing.verifying_key(),
            &store,
            110,
            None,
        )
        .unwrap();
        let current_bytes = free_policy(&signing, provider_id, 2).encode().unwrap();
        let current = activate_service_policy_v1(
            &current_bytes,
            provider_id,
            signing.verifying_key(),
            &store,
            150,
            None,
        )
        .unwrap();
        let head_before = store.policy_head().unwrap().unwrap();

        let retained = activate_retained_service_policy_v1(&old_bytes, &current).unwrap();
        assert_ne!(retained.policy_digest(), current.policy_digest());
        assert!(retained.has_live_redemption(150));
        assert!(retained
            .verified_offer_for_redemption(&scope_id, 7, 1_120)
            .is_ok());
        assert!(retained
            .verified_offer_for_redemption(&scope_id, 7, 1_121)
            .is_err());
        let verified_offer = retained
            .verified_offer_for_redemption(&scope_id, 7, 100)
            .unwrap();
        assert!(matches!(
            store
                .verify_existing_verified_offer_namespace_v1(&verified_offer, 100, None)
                .unwrap(),
            pir_service_store::VerifiedOfferNamespaceReadinessV1::Ready
        ));
        assert_eq!(store.policy_head().unwrap().unwrap(), head_before);

        assert!(matches!(
            activate_retained_service_policy_v1(&current_bytes, &current),
            Err(ServicePolicyActivationErrorV1::RetainedPolicyIsCurrent)
        ));
        let future = free_policy(&signing, provider_id, 3).encode().unwrap();
        assert!(matches!(
            activate_retained_service_policy_v1(&future, &current),
            Err(ServicePolicyActivationErrorV1::RetainedPolicyIsNotOlder)
        ));

        drop(store);
        let reopened =
            ProviderStore::open_existing(&store_path, provider_id, options).unwrap();
        let current_after_restart = activate_service_policy_v1(
            &current_bytes,
            provider_id,
            signing.verifying_key(),
            &reopened,
            150,
            None,
        )
        .unwrap();
        let retained_after_restart =
            activate_retained_service_policy_v1(&old_bytes, &current_after_restart).unwrap();
        assert!(retained_after_restart.has_live_redemption(150));
    }

    #[test]
    fn retained_activation_rejects_free_only_and_wrong_identity_or_key() {
        let dir = private_tempdir();
        let provider_id = [9; 32];
        let store = ProviderStore::create(
            dir.path().join("provider.sqlite"),
            [1; 16],
            provider_id,
            StoreOptions {
                busy_timeout: Duration::from_secs(1),
            },
        )
        .unwrap();
        let signing = SigningKey::from_bytes(&[3; 32]);
        let current_bytes = free_policy(&signing, provider_id, 2).encode().unwrap();
        let current = activate_service_policy_v1(
            &current_bytes,
            provider_id,
            signing.verifying_key(),
            &store,
            150,
            None,
        )
        .unwrap();

        let free_old = free_policy(&signing, provider_id, 1).encode().unwrap();
        assert!(matches!(
            activate_retained_service_policy_v1(&free_old, &current),
            Err(ServicePolicyActivationErrorV1::RetainedPolicyHasNoCredentialOffers)
        ));
        let wrong_provider = retained_receipt_policy(&signing, [8; 32], 1)
            .0
            .encode()
            .unwrap();
        assert!(activate_retained_service_policy_v1(&wrong_provider, &current).is_err());
        let wrong_key = SigningKey::from_bytes(&[4; 32]);
        let wrong_key_policy = retained_receipt_policy(&wrong_key, provider_id, 1)
            .0
            .encode()
            .unwrap();
        assert!(activate_retained_service_policy_v1(&wrong_key_policy, &current).is_err());

        let (never_current, scope_id) = retained_receipt_policy(&signing, provider_id, 1);
        let never_current =
            activate_retained_service_policy_v1(&never_current.encode().unwrap(), &current)
                .unwrap();
        let verified_offer = never_current
            .verified_offer_for_redemption(&scope_id, 7, 100)
            .unwrap();
        assert!(matches!(
            store.verify_existing_verified_offer_namespace_v1(&verified_offer, 100, None),
            Err(StoreError::NamespaceMissing)
        ));
    }
}
