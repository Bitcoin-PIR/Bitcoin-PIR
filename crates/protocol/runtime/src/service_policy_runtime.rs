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
    AuthScheme, CashuManifestEpochFloorV1, CredentialKeysetEpochFloorV1, FreeModeV1,
    PolicyRollbackGuardV1, ProviderId, ServiceOfferV1, ServicePolicyEpochFloorsV1,
    ServicePolicyResponseV1, ServicePolicyV1, ServiceProtocolError, VerifiedCurrentPolicyV1,
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
            if offer.credential_binding.is_none() {
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
/// The durable store remains authoritative for rollback floors; these cached
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
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use ed25519_dalek::SigningKey;
    use pir_service_protocol::{
        paid_receipt_key_id, AcquisitionMethod, AuthPaddingClassV1, AuthScheme, BackendId,
        CredentialKeyBindingClaimsV1, CredentialKeyBindingV1, CredentialUnitV1, DatasetBindingV1,
        DeploymentStatus, EntitlementLimitsV1, FreeModeV1, PriceV1, PrivacyLeakageV1,
        ServiceOfferV1, ServiceScopePolicyV1, ServiceScopeV1, VerificationMode, WorkloadId,
    };
    use pir_service_store::{
        RollbackFloorAuthorityErrorV1, RollbackFloorAuthorityV1, RollbackFloorV1, StoreOptions,
    };
    use tempfile::tempdir;

    use super::*;

    #[derive(Debug, Default)]
    struct MemoryFloor(Mutex<Option<RollbackFloorV1>>);

    impl RollbackFloorAuthorityV1 for MemoryFloor {
        fn initialize(
            &self,
            initial: &RollbackFloorV1,
        ) -> Result<RollbackFloorV1, RollbackFloorAuthorityErrorV1> {
            let mut guard = self.0.lock().unwrap();
            match *guard {
                Some(current) if current != *initial => Err(RollbackFloorAuthorityErrorV1::new(
                    "conflicting initial floor",
                )),
                Some(current) => Ok(current),
                None => {
                    *guard = Some(*initial);
                    Ok(*initial)
                }
            }
        }

        fn load(
            &self,
            _provider_id: &[u8; 32],
        ) -> Result<Option<RollbackFloorV1>, RollbackFloorAuthorityErrorV1> {
            Ok(*self.0.lock().unwrap())
        }

        fn compare_and_advance(
            &self,
            expected: &RollbackFloorV1,
            next: &RollbackFloorV1,
        ) -> Result<RollbackFloorV1, RollbackFloorAuthorityErrorV1> {
            let mut guard = self.0.lock().unwrap();
            if guard.as_ref() != Some(expected) {
                return Err(RollbackFloorAuthorityErrorV1::new("floor CAS conflict"));
            }
            *guard = Some(*next);
            Ok(*next)
        }
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
        let dir = tempdir().unwrap();
        let provider_id = [9; 32];
        let authority = Arc::new(MemoryFloor::default());
        let store = ProviderStore::create(
            dir.path().join("provider.sqlite"),
            [1; 16],
            provider_id,
            StoreOptions {
                busy_timeout: Duration::from_secs(1),
            },
            authority,
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
    fn retained_activation_is_exact_redemption_only_and_restart_safe() {
        let dir = tempdir().unwrap();
        let provider_id = [9; 32];
        let authority = Arc::new(MemoryFloor::default());
        let store_path = dir.path().join("provider.sqlite");
        let options = StoreOptions {
            busy_timeout: Duration::from_secs(1),
        };
        let store = ProviderStore::create(
            &store_path,
            [1; 16],
            provider_id,
            options,
            authority.clone(),
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
            ProviderStore::open_existing(&store_path, provider_id, options, authority).unwrap();
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
        let dir = tempdir().unwrap();
        let provider_id = [9; 32];
        let store = ProviderStore::create(
            dir.path().join("provider.sqlite"),
            [1; 16],
            provider_id,
            StoreOptions {
                busy_timeout: Duration::from_secs(1),
            },
            Arc::new(MemoryFloor::default()),
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
