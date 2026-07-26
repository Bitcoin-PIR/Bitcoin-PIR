//! Provider-side policy and operation binding for `AuthBeginV1`.
//!
//! [`bind_auth_begin_v1`] is the single public entry point for turning an
//! untrusted authorization request into a typed proof attached to one exact
//! verified offer and one exact provider-local operation.  The local catalog
//! is trusted configuration: it must resolve the complete operation, including
//! its database ID and transport-specific fields, to the backend, workload,
//! protocol version, dataset binding, and operation profile that the provider
//! will actually execute.
//!
//! A [`BoundAuthAttemptV1`] is **not** authorization to run a PIR operation. It
//! proves only structural canonicality and signed-policy/local-catalog binding.
//! A runtime gate must first establish the required secure channel, then carry
//! out the selected method's cryptographic verification and atomic spend (or
//! free-admission) transition before granting the operation.

use crate::proof::decode_authorization_proof_v1;
use crate::{
    ArcPresentationCanonicalizerV1, AuthBeginV1, AuthorizationProofV1, BackendId, DatasetBindingV1,
    EntitlementLimitsV1, OperationStartV1, ServiceOfferV1, ServiceProtocolError, ServiceScopeV1,
    VerifiedServiceOfferV1, WorkloadId,
};

/// Trusted provider-local resolution of the exact operation that will run.
///
/// Fields are private so an untrusted wire request cannot be reinterpreted as
/// a resource budget. Providers construct this value only from local catalog
/// state via [`TrustedCatalogResolutionV1::new`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedCatalogResolutionV1 {
    database_id: u8,
    backend: BackendId,
    workload: WorkloadId,
    protocol_version: u16,
    dataset: DatasetBindingV1,
    operation_profile: u16,
}

impl TrustedCatalogResolutionV1 {
    pub const fn new(
        database_id: u8,
        backend: BackendId,
        workload: WorkloadId,
        protocol_version: u16,
        dataset: DatasetBindingV1,
        operation_profile: u16,
    ) -> Self {
        Self {
            database_id,
            backend,
            workload,
            protocol_version,
            dataset,
            operation_profile,
        }
    }

    pub const fn database_id(&self) -> u8 {
        self.database_id
    }

    pub const fn backend(&self) -> BackendId {
        self.backend
    }

    pub const fn workload(&self) -> WorkloadId {
        self.workload
    }

    pub const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub const fn dataset(&self) -> &DatasetBindingV1 {
        &self.dataset
    }

    pub const fn operation_profile(&self) -> u16 {
        self.operation_profile
    }
}

/// Read-only adapter over the provider's trusted database/service catalog.
///
/// Implementations must use every operation field that changes the actual
/// service, including `db_id`, Harmony hint transport, session form, and side.
/// Returning `None` means the exact operation is not locally configured and
/// therefore fails closed.
pub trait TrustedServiceCatalogV1 {
    fn resolve_operation(&self, operation: &OperationStartV1)
        -> Option<TrustedCatalogResolutionV1>;
}

impl<F> TrustedServiceCatalogV1 for F
where
    F: Fn(&OperationStartV1) -> Option<TrustedCatalogResolutionV1>,
{
    fn resolve_operation(
        &self,
        operation: &OperationStartV1,
    ) -> Option<TrustedCatalogResolutionV1> {
        self(operation)
    }
}

/// Structurally decoded proof bound to one exact verified policy offer and one
/// exact trusted local operation.
///
/// All fields are private. Callers can inspect the immutable bound values but
/// cannot substitute request-controlled limits, scope, or offer data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundAuthAttemptV1<'policy> {
    verified_offer: VerifiedServiceOfferV1<'policy>,
    catalog_resolution: TrustedCatalogResolutionV1,
    operation: OperationStartV1,
    proof: AuthorizationProofV1,
}

impl<'policy> BoundAuthAttemptV1<'policy> {
    pub const fn verified_offer(&self) -> &VerifiedServiceOfferV1<'policy> {
        &self.verified_offer
    }

    pub const fn scope(&self) -> &'policy ServiceScopeV1 {
        self.verified_offer.scope()
    }

    pub const fn limits(&self) -> &'policy EntitlementLimitsV1 {
        self.verified_offer.limits()
    }

    pub const fn offer(&self) -> &'policy ServiceOfferV1 {
        self.verified_offer.offer()
    }

    pub const fn catalog_resolution(&self) -> &TrustedCatalogResolutionV1 {
        &self.catalog_resolution
    }

    pub const fn operation(&self) -> &OperationStartV1 {
        &self.operation
    }

    /// Typed, canonical proof only. Method-specific signatures, nullifiers,
    /// online redemption, and durable consumption are intentionally unchecked.
    pub const fn proof(&self) -> &AuthorizationProofV1 {
        &self.proof
    }
}

/// Bind one untrusted `AuthBeginV1` to a verified signed offer and the exact
/// operation resolved from trusted provider-local configuration.
///
/// This function verifies every outer selector against `verified_offer`,
/// verifies the operation's inherent service and its complete local catalog
/// binding, and only then dispatches proof decoding from the signed offer's
/// authorization scheme/free mode. The raw request never selects a budget or
/// proof decoder. ARC additionally requires a reviewed typed canonicalizer.
///
/// This function does not establish a secure channel, verify cryptographic
/// proof validity, check freshness/nullifiers, or consume anything. Those are
/// mandatory subsequent runtime-gate transitions.
pub fn bind_auth_begin_v1<'policy>(
    request: &AuthBeginV1,
    verified_offer: VerifiedServiceOfferV1<'policy>,
    trusted_catalog: &dyn TrustedServiceCatalogV1,
    arc_canonicalizer: Option<&dyn ArcPresentationCanonicalizerV1>,
) -> Result<BoundAuthAttemptV1<'policy>, ServiceProtocolError> {
    let scope = verified_offer.scope();
    let offer = verified_offer.offer();

    if request.policy_digest != verified_offer.policy_digest() {
        return Err(ServiceProtocolError::InvalidValue {
            field: "AuthBeginV1.policy_digest",
            reason: "does not match the exact verified offer policy",
        });
    }
    if request.scope_id != scope.scope_id() {
        return Err(ServiceProtocolError::InvalidValue {
            field: "AuthBeginV1.scope_id",
            reason: "does not match the exact verified offer scope",
        });
    }
    if request.offer_id != offer.offer_id {
        return Err(ServiceProtocolError::InvalidValue {
            field: "AuthBeginV1.offer_id",
            reason: "does not match the exact verified offer",
        });
    }
    if request.scheme != offer.authorization {
        return Err(ServiceProtocolError::InvalidValue {
            field: "AuthBeginV1.scheme",
            reason: "does not match the signed offer authorization scheme",
        });
    }
    if request.key_id != offer.key_id {
        return Err(ServiceProtocolError::InvalidValue {
            field: "AuthBeginV1.key_id",
            reason: "does not match the signed offer key ID",
        });
    }

    // Validate even directly constructed values; network callers normally
    // arrive through AuthBeginV1::decode_padded, which already enforces this.
    request.operation.encode()?;
    let required_service = request.operation.required_service();
    if required_service != (scope.backend, scope.workload) {
        return Err(ServiceProtocolError::InvalidValue {
            field: "OperationStartV1.required_service",
            reason: "operation does not belong to the verified offer scope",
        });
    }

    let catalog_resolution = trusted_catalog
        .resolve_operation(&request.operation)
        .ok_or(ServiceProtocolError::InvalidValue {
            field: "TrustedServiceCatalogV1.operation",
            reason: "operation or database is not present in the trusted local catalog",
        })?;
    if catalog_resolution.database_id != operation_database_id(&request.operation) {
        return Err(ServiceProtocolError::InvalidValue {
            field: "TrustedCatalogResolutionV1.database_id",
            reason: "does not match the requested local database",
        });
    }
    if catalog_resolution.backend != scope.backend {
        return Err(ServiceProtocolError::InvalidValue {
            field: "TrustedCatalogResolutionV1.backend",
            reason: "does not match the verified offer scope",
        });
    }
    if catalog_resolution.workload != scope.workload {
        return Err(ServiceProtocolError::InvalidValue {
            field: "TrustedCatalogResolutionV1.workload",
            reason: "does not match the verified offer scope",
        });
    }
    if catalog_resolution.protocol_version != scope.protocol_version {
        return Err(ServiceProtocolError::InvalidValue {
            field: "TrustedCatalogResolutionV1.protocol_version",
            reason: "does not match the verified offer scope",
        });
    }
    if catalog_resolution.dataset != scope.dataset {
        return Err(ServiceProtocolError::InvalidValue {
            field: "TrustedCatalogResolutionV1.dataset",
            reason: "database dataset does not match the verified offer scope",
        });
    }
    if catalog_resolution.operation_profile != scope.operation_profile {
        return Err(ServiceProtocolError::InvalidValue {
            field: "TrustedCatalogResolutionV1.operation_profile",
            reason: "does not match the verified offer scope",
        });
    }

    let proof = decode_authorization_proof_v1(
        offer.authorization,
        offer.free_mode,
        &request.proof,
        arc_canonicalizer,
    )?;

    Ok(BoundAuthAttemptV1 {
        verified_offer,
        catalog_resolution,
        operation: request.operation.clone(),
        proof,
    })
}

const fn operation_database_id(operation: &OperationStartV1) -> u8 {
    match operation {
        OperationStartV1::DpfQuery { db_id }
        | OperationStartV1::HarmonyHint { db_id, .. }
        | OperationStartV1::HarmonyQuery { db_id }
        | OperationStartV1::OnionSession { db_id }
        | OperationStartV1::TeeOramQuery { db_id } => *db_id,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use ed25519_dalek::{SigningKey, VerifyingKey};

    use super::*;
    use crate::{
        AcquisitionMethod, ArcPresentationV1, AuthPaddingClassV1, CredentialKeyBindingClaimsV1,
        CredentialKeyBindingV1, CredentialUnitV1, DeploymentStatus, FreeAuthorizationProofV1,
        FreeModeV1, PolicyRollbackGuardV1, PriceV1, PrivacyLeakageV1, ServicePolicyEpochFloorsV1,
        ServicePolicyV1, ServiceScopePolicyV1, VerificationMode,
    };

    const NOW: u64 = 150;

    fn limits(seed: u32) -> EntitlementLimitsV1 {
        EntitlementLimitsV1 {
            max_logical_inputs: seed as u16,
            max_frames: seed,
            max_request_bytes: u64::from(seed) * 10,
            max_response_bytes: u64::from(seed) * 20,
            max_wall_time_ms: seed,
            max_concurrent_sockets: 1,
            max_hint_groups: 0,
            max_work_units: u64::from(seed) * 30,
        }
    }

    fn dpf_scope(dataset: DatasetBindingV1, operation_profile: u16) -> ServiceScopeV1 {
        ServiceScopeV1 {
            provider_id: [9; 32],
            backend: BackendId::DpfPirV1,
            workload: WorkloadId::DpfEvaluateJobV1,
            protocol_version: 1,
            dataset,
            operation_profile,
            entitlement_profile: operation_profile + 100,
        }
    }

    fn free_offer(offer_id: u32) -> ServiceOfferV1 {
        ServiceOfferV1 {
            offer_id,
            acquisition: AcquisitionMethod::FreeV1,
            free_mode: FreeModeV1::OpenBestEffort,
            free_quota: 0,
            free_window_seconds: 0,
            free_pow_difficulty_bits: 0,
            priority_class: 1,
            authorization: crate::AuthScheme::FreeV1,
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
        }
    }

    fn arc_offer(scope: &ServiceScopeV1, offer_id: u32) -> ServiceOfferV1 {
        let credential_key_id = vec![0xa5; 32];
        let issuer_key = SigningKey::from_bytes(&[8; 32]);
        let binding = CredentialKeyBindingV1::sign(
            CredentialKeyBindingClaimsV1 {
                provider_id: scope.provider_id,
                scope_id: scope.scope_id(),
                offer_id,
                scheme: crate::AuthScheme::ArcV1Experimental,
                keyset_epoch: 1,
                entitlement_profile: scope.entitlement_profile,
                unit: CredentialUnitV1::Auth,
                amount: 1,
                presentation_limit: 2,
                not_before: 50,
                not_after: 270,
                credential_key_id: credential_key_id.clone(),
                verification_key: vec![0x5a; 99],
            },
            &issuer_key,
        )
        .unwrap();
        ServiceOfferV1 {
            offer_id,
            acquisition: AcquisitionMethod::Bolt11V1,
            free_mode: FreeModeV1::NotFree,
            free_quota: 0,
            free_window_seconds: 0,
            free_pow_difficulty_bits: 0,
            priority_class: 2,
            authorization: crate::AuthScheme::ArcV1Experimental,
            verification: VerificationMode::ProviderLocal,
            deployment_status: DeploymentStatus::Experimental,
            price: PriceV1::MilliSatoshi(1_000),
            issuer_id: binding.issuer_id,
            key_id: credential_key_id,
            credential_binding: Some(binding),
            cashu_mint_manifest: None,
            endpoint: "https://issuer.invalid".into(),
            invoice_expiry_seconds: 10,
            claim_window_seconds: 10,
            minimum_credential_validity_seconds: 50,
            retired_policy_grace_seconds: 70,
            credential_count: 2,
            credential_presentation_limit: 2,
            privacy_leakage: PrivacyLeakageV1::from_bits(
                PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING
                    | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER
                    | PrivacyLeakageV1::PROVIDER_LOCAL_BEARER,
            )
            .unwrap(),
        }
    }

    fn signed_policy() -> (ServicePolicyV1, VerifyingKey) {
        let first = dpf_scope(DatasetBindingV1::Class { class_id: 11 }, 21);
        let second = dpf_scope(DatasetBindingV1::Class { class_id: 12 }, 22);
        let signing_key = SigningKey::from_bytes(&[3; 32]);
        let policy = ServicePolicyV1::sign(
            first.provider_id,
            8,
            100,
            200,
            AuthPaddingClassV1::Class16KiB,
            vec![
                ServiceScopePolicyV1 {
                    scope: first.clone(),
                    limits: limits(101),
                    offers: vec![free_offer(1), arc_offer(&first, 2)],
                },
                ServiceScopePolicyV1 {
                    scope: second,
                    limits: limits(202),
                    offers: vec![free_offer(3)],
                },
            ],
            &signing_key,
        )
        .unwrap();
        (policy, signing_key.verifying_key())
    }

    fn verified_policy<'a>(
        policy: &'a ServicePolicyV1,
        key: &VerifyingKey,
    ) -> crate::VerifiedCurrentPolicyV1<'a> {
        policy
            .verify_current_for_acquisition(
                &policy.provider_id,
                NOW,
                &PolicyRollbackGuardV1::initial(),
                &ServicePolicyEpochFloorsV1::initial(),
                key,
            )
            .unwrap()
    }

    fn request_for(
        verified_offer: &VerifiedServiceOfferV1<'_>,
        operation: OperationStartV1,
        proof: Vec<u8>,
    ) -> AuthBeginV1 {
        AuthBeginV1 {
            policy_digest: verified_offer.policy_digest(),
            scope_id: verified_offer.scope().scope_id(),
            offer_id: verified_offer.offer().offer_id,
            scheme: verified_offer.offer().authorization,
            key_id: verified_offer.offer().key_id.clone(),
            operation,
            proof,
        }
    }

    fn resolution_for(database_id: u8, scope: &ServiceScopeV1) -> TrustedCatalogResolutionV1 {
        TrustedCatalogResolutionV1::new(
            database_id,
            scope.backend,
            scope.workload,
            scope.protocol_version,
            scope.dataset.clone(),
            scope.operation_profile,
        )
    }

    fn catalog_for_db(
        expected_db: u8,
        resolution: TrustedCatalogResolutionV1,
    ) -> impl TrustedServiceCatalogV1 {
        move |operation: &OperationStartV1| match operation {
            OperationStartV1::DpfQuery { db_id } if *db_id == expected_db => {
                Some(resolution.clone())
            }
            _ => None,
        }
    }

    fn assert_invalid_field<T>(
        result: Result<T, ServiceProtocolError>,
        expected_field: &'static str,
    ) {
        assert!(matches!(
            result,
            Err(ServiceProtocolError::InvalidValue { field, .. }) if field == expected_field
        ));
    }

    #[test]
    fn binds_exact_offer_scope_limits_operation_and_typed_proof() {
        let (policy, key) = signed_policy();
        let verified_policy = verified_policy(&policy, &key);
        let scope_id = policy.scopes[0].scope.scope_id();
        let offer = verified_policy.offer(&scope_id, 1).unwrap();
        let request = request_for(&offer, OperationStartV1::DpfQuery { db_id: 7 }, Vec::new());
        let resolution = resolution_for(7, offer.scope());
        let catalog = catalog_for_db(7, resolution.clone());

        let bound = bind_auth_begin_v1(&request, offer, &catalog, None).unwrap();

        assert_eq!(bound.scope(), &policy.scopes[0].scope);
        assert_eq!(bound.limits(), &policy.scopes[0].limits);
        assert_eq!(bound.offer(), &policy.scopes[0].offers[0]);
        assert!(core::ptr::eq(bound.scope(), &policy.scopes[0].scope));
        assert!(core::ptr::eq(bound.limits(), &policy.scopes[0].limits));
        assert!(core::ptr::eq(bound.offer(), &policy.scopes[0].offers[0]));
        assert_eq!(bound.catalog_resolution(), &resolution);
        assert_eq!(bound.operation(), &request.operation);
        assert!(matches!(
            bound.proof(),
            AuthorizationProofV1::Free(FreeAuthorizationProofV1::OpenBestEffort)
        ));
    }

    #[test]
    fn rejects_every_untrusted_outer_selector_before_proof_dispatch() {
        let (policy, key) = signed_policy();
        let verified_policy = verified_policy(&policy, &key);
        let scope_id = policy.scopes[0].scope.scope_id();
        let offer = verified_policy.offer(&scope_id, 1).unwrap();
        let catalog = catalog_for_db(7, resolution_for(7, offer.scope()));
        let base = request_for(&offer, OperationStartV1::DpfQuery { db_id: 7 }, Vec::new());

        let mut wrong_policy = base.clone();
        wrong_policy.policy_digest[0] ^= 1;
        assert_invalid_field(
            bind_auth_begin_v1(&wrong_policy, offer, &catalog, None),
            "AuthBeginV1.policy_digest",
        );

        let mut wrong_scope = base.clone();
        wrong_scope.scope_id = policy.scopes[1].scope.scope_id();
        assert_invalid_field(
            bind_auth_begin_v1(&wrong_scope, offer, &catalog, None),
            "AuthBeginV1.scope_id",
        );

        let mut wrong_offer = base.clone();
        wrong_offer.offer_id = 2;
        assert_invalid_field(
            bind_auth_begin_v1(&wrong_offer, offer, &catalog, None),
            "AuthBeginV1.offer_id",
        );

        // A paid outer tag/proof cannot turn a signed free offer into a paid
        // request, nor choose the paid decoder.
        let mut paid_to_free = base.clone();
        paid_to_free.scheme = crate::AuthScheme::Bolt11DirectReceiptV1;
        paid_to_free.proof = vec![0xff; 32];
        assert_invalid_field(
            bind_auth_begin_v1(&paid_to_free, offer, &catalog, None),
            "AuthBeginV1.scheme",
        );

        let mut wrong_key = base;
        wrong_key.key_id = vec![1];
        assert_invalid_field(
            bind_auth_begin_v1(&wrong_key, offer, &catalog, None),
            "AuthBeginV1.key_id",
        );
    }

    #[test]
    fn rejects_cross_offer_and_cross_scope_even_with_valid_policy_objects() {
        let (policy, key) = signed_policy();
        let verified_policy = verified_policy(&policy, &key);
        let first_scope_id = policy.scopes[0].scope.scope_id();
        let second_scope_id = policy.scopes[1].scope.scope_id();
        let free = verified_policy.offer(&first_scope_id, 1).unwrap();
        let arc = verified_policy.offer(&first_scope_id, 2).unwrap();
        let other_scope = verified_policy.offer(&second_scope_id, 3).unwrap();
        let catalog = catalog_for_db(7, resolution_for(7, free.scope()));

        let request_from_arc = request_for(&arc, OperationStartV1::DpfQuery { db_id: 7 }, vec![1]);
        assert_invalid_field(
            bind_auth_begin_v1(&request_from_arc, free, &catalog, None),
            "AuthBeginV1.offer_id",
        );

        let request_from_other_scope = request_for(
            &other_scope,
            OperationStartV1::DpfQuery { db_id: 7 },
            Vec::new(),
        );
        assert_invalid_field(
            bind_auth_begin_v1(&request_from_other_scope, free, &catalog, None),
            "AuthBeginV1.scope_id",
        );
    }

    #[test]
    fn rejects_wrong_database_and_every_catalog_binding_dimension() {
        let (policy, key) = signed_policy();
        let verified_policy = verified_policy(&policy, &key);
        let scope_id = policy.scopes[0].scope.scope_id();
        let offer = verified_policy.offer(&scope_id, 1).unwrap();
        let request = request_for(&offer, OperationStartV1::DpfQuery { db_id: 8 }, Vec::new());

        let wrong_db_catalog = catalog_for_db(7, resolution_for(7, offer.scope()));
        assert_invalid_field(
            bind_auth_begin_v1(&request, offer, &wrong_db_catalog, None),
            "TrustedServiceCatalogV1.operation",
        );

        let mismatched_db_catalog = catalog_for_db(8, resolution_for(7, offer.scope()));
        assert_invalid_field(
            bind_auth_begin_v1(&request, offer, &mismatched_db_catalog, None),
            "TrustedCatalogResolutionV1.database_id",
        );

        let request = request_for(&offer, OperationStartV1::DpfQuery { db_id: 7 }, Vec::new());
        let mut wrong = resolution_for(7, offer.scope());
        wrong.backend = BackendId::HarmonyPirV2;
        let catalog = catalog_for_db(7, wrong);
        assert_invalid_field(
            bind_auth_begin_v1(&request, offer, &catalog, None),
            "TrustedCatalogResolutionV1.backend",
        );

        let mut wrong = resolution_for(7, offer.scope());
        wrong.workload = WorkloadId::HarmonyQueryJobV1;
        let catalog = catalog_for_db(7, wrong);
        assert_invalid_field(
            bind_auth_begin_v1(&request, offer, &catalog, None),
            "TrustedCatalogResolutionV1.workload",
        );

        let mut wrong = resolution_for(7, offer.scope());
        wrong.protocol_version = 2;
        let catalog = catalog_for_db(7, wrong);
        assert_invalid_field(
            bind_auth_begin_v1(&request, offer, &catalog, None),
            "TrustedCatalogResolutionV1.protocol_version",
        );

        let mut wrong = resolution_for(7, offer.scope());
        wrong.dataset = DatasetBindingV1::Class { class_id: 99 };
        let catalog = catalog_for_db(7, wrong);
        assert_invalid_field(
            bind_auth_begin_v1(&request, offer, &catalog, None),
            "TrustedCatalogResolutionV1.dataset",
        );

        let mut wrong = resolution_for(7, offer.scope());
        wrong.operation_profile += 1;
        let catalog = catalog_for_db(7, wrong);
        assert_invalid_field(
            bind_auth_begin_v1(&request, offer, &catalog, None),
            "TrustedCatalogResolutionV1.operation_profile",
        );
    }

    #[test]
    fn rejects_operation_service_before_catalog_or_proof_processing() {
        let (policy, key) = signed_policy();
        let verified_policy = verified_policy(&policy, &key);
        let scope_id = policy.scopes[0].scope.scope_id();
        let offer = verified_policy.offer(&scope_id, 1).unwrap();
        let request = request_for(&offer, OperationStartV1::HarmonyQuery { db_id: 7 }, vec![1]);
        let calls = Cell::new(0u8);
        let catalog = |_operation: &OperationStartV1| {
            calls.set(calls.get() + 1);
            Some(resolution_for(7, offer.scope()))
        };

        assert_invalid_field(
            bind_auth_begin_v1(&request, offer, &catalog, None),
            "OperationStartV1.required_service",
        );
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn paid_offer_cannot_be_retagged_free_and_arc_requires_typed_adapter() {
        let (policy, key) = signed_policy();
        let verified_policy = verified_policy(&policy, &key);
        let scope_id = policy.scopes[0].scope.scope_id();
        let offer = verified_policy.offer(&scope_id, 2).unwrap();
        let catalog = catalog_for_db(7, resolution_for(7, offer.scope()));
        let presentation = ArcPresentationV1::from_canonical_bytes(vec![1, 2, 3])
            .unwrap()
            .encode()
            .unwrap();
        let request = request_for(
            &offer,
            OperationStartV1::DpfQuery { db_id: 7 },
            presentation,
        );

        let mut retagged_free = request.clone();
        retagged_free.scheme = crate::AuthScheme::FreeV1;
        retagged_free.key_id.clear();
        retagged_free.proof.clear();
        assert_invalid_field(
            bind_auth_begin_v1(&retagged_free, offer, &catalog, None),
            "AuthBeginV1.scheme",
        );

        assert_invalid_field(
            bind_auth_begin_v1(&request, offer, &catalog, None),
            "ArcPresentationV1.presentation",
        );

        let typed_canonicalizer = |bytes: &[u8]| Ok(bytes.to_vec());
        let bound =
            bind_auth_begin_v1(&request, offer, &catalog, Some(&typed_canonicalizer)).unwrap();
        assert!(matches!(
            bound.proof(),
            AuthorizationProofV1::ArcExperimental(presentation)
                if presentation.presentation_bytes() == [1, 2, 3]
        ));
    }

    #[test]
    fn directly_constructed_noncanonical_operation_fails_before_catalog() {
        let (policy, key) = signed_policy();
        let verified_policy = verified_policy(&policy, &key);
        let scope_id = policy.scopes[0].scope.scope_id();
        let offer = verified_policy.offer(&scope_id, 1).unwrap();
        let operation = OperationStartV1::HarmonyHint {
            db_id: 7,
            transport: crate::HintTransport::V2Full,
            session_token: Some([1; 16]),
            primary_side: Some(crate::HarmonyHintSideV1::Index),
        };
        let request = request_for(&offer, operation, Vec::new());
        let calls = Cell::new(0u8);
        let catalog = |_operation: &OperationStartV1| {
            calls.set(calls.get() + 1);
            Some(resolution_for(7, offer.scope()))
        };

        assert!(bind_auth_begin_v1(&request, offer, &catalog, None).is_err());
        assert_eq!(calls.get(), 0);
    }
}
