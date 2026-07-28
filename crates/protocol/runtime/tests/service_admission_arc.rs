use std::sync::{Arc, Mutex};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use ed25519_dalek::SigningKey;
use pir_runtime_core::service_admission::{
    AdmissionCommitErrorV1, AdmissionMethodCommitterV1, AdmissionMethodRouteV1,
    ProviderStoreBearerCommitterV1,
};
use pir_service_protocol::{
    arc_provider_global_spend_key_v1, bind_auth_begin_v1, AcquisitionMethod, ArcPresentationV1,
    AuthBeginV1, AuthPaddingClassV1, AuthScheme, AuthorizationProofV1, BackendId,
    BoundAuthAttemptV1, CredentialKeyBindingClaimsV1, CredentialKeyBindingV1, CredentialUnitV1,
    DatasetBindingV1, DeploymentStatus, EntitlementLimitsV1, FreeModeV1, OperationStartV1,
    PolicyRollbackGuardV1, PriceV1, PrivacyLeakageV1, ServiceOfferV1, ServicePolicyEpochFloorsV1,
    ServicePolicyV1, ServiceProtocolError, ServiceScopePolicyV1, ServiceScopeV1,
    TrustedCatalogResolutionV1, VerificationMode, VerifiedServiceOfferV1, WorkloadId,
};
use pir_service_store::{
    ArcExclusiveKeyLineageVerifierV1, ArcPresentationSpendVerifierV1, ArcVerifiedSpendSinkV1,
    ExclusiveKeyLineage, ProviderStore, RollbackFloorAuthorityErrorV1, RollbackFloorAuthorityV1,
    RollbackFloorV1, StoreOptions, VerifiedOfferNamespaceInstallOutcomeV1,
};
use sha2::{Digest, Sha256};

const PROVIDER: [u8; 32] = [0x19; 32];

#[derive(Debug, Default)]
struct MemoryRollbackAuthorityV1 {
    floor: Mutex<Option<RollbackFloorV1>>,
}

impl RollbackFloorAuthorityV1 for MemoryRollbackAuthorityV1 {
    fn load(
        &self,
        _provider_id: &[u8; 32],
    ) -> Result<Option<RollbackFloorV1>, RollbackFloorAuthorityErrorV1> {
        Ok(*self.floor.lock().unwrap())
    }

    fn initialize(
        &self,
        initial: &RollbackFloorV1,
    ) -> Result<RollbackFloorV1, RollbackFloorAuthorityErrorV1> {
        let mut floor = self.floor.lock().unwrap();
        if floor.is_none() {
            *floor = Some(*initial);
        }
        floor.ok_or_else(|| RollbackFloorAuthorityErrorV1::new("floor initialization failed"))
    }

    fn compare_and_advance(
        &self,
        expected: &RollbackFloorV1,
        next: &RollbackFloorV1,
    ) -> Result<RollbackFloorV1, RollbackFloorAuthorityErrorV1> {
        let mut floor = self.floor.lock().unwrap();
        if floor.as_ref() == Some(expected) {
            *floor = Some(*next);
        }
        floor.ok_or_else(|| RollbackFloorAuthorityErrorV1::new("floor disappeared"))
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct FakeReviewedArcAdapterV1;

impl ArcExclusiveKeyLineageVerifierV1 for FakeReviewedArcAdapterV1 {
    fn verify_arc_exclusive_key_lineage_v1(
        &self,
        verified_offer: &VerifiedServiceOfferV1<'_>,
        binding: &CredentialKeyBindingV1,
        now_unix_seconds: u64,
    ) -> Result<ExclusiveKeyLineage, ServiceProtocolError> {
        if verified_offer.offer().credential_binding.as_ref() != Some(binding)
            || now_unix_seconds < binding.claims.not_before
            || now_unix_seconds > binding.claims.not_after
        {
            return Err(protocol_error("ARC lineage binding/time mismatch"));
        }
        let fingerprint = fingerprint(binding);
        let mut hasher = Sha256::new();
        hasher.update(b"BitcoinPIR/runtime-test-arc-lineage/v1");
        hasher.update(fingerprint);
        hasher.update(binding.binding_digest()?);
        Ok(ExclusiveKeyLineage {
            key_fingerprint: fingerprint,
            lineage_digest: hasher.finalize().into(),
        })
    }
}

impl ArcPresentationSpendVerifierV1 for FakeReviewedArcAdapterV1 {
    fn verify_arc_presentation_spend_v1(
        &self,
        attempt: &BoundAuthAttemptV1<'_>,
        _now_unix_seconds: u64,
        sink: &mut dyn ArcVerifiedSpendSinkV1,
    ) -> Result<(), ServiceProtocolError> {
        if !matches!(attempt.proof(), AuthorizationProofV1::ArcExperimental(_)) {
            return Err(protocol_error("ARC proof type mismatch"));
        }
        let binding = attempt
            .offer()
            .credential_binding
            .as_ref()
            .ok_or_else(|| protocol_error("ARC binding missing"))?;
        let fingerprint = fingerprint(binding);
        let binding_digest = binding.binding_digest()?;
        let tag = [0x74; 33];
        let spend_key = arc_provider_global_spend_key_v1(&fingerprint, &binding_digest, &tag);
        sink.accept_verified_arc_spend_v1(&tag, &fingerprint, &binding_digest, &spend_key)
    }
}

fn fingerprint(binding: &CredentialKeyBindingV1) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BitcoinPIR/runtime-test-arc-fingerprint/v1");
    hasher.update(&binding.claims.verification_key);
    hasher.finalize().into()
}

fn protocol_error(reason: &'static str) -> ServiceProtocolError {
    ServiceProtocolError::InvalidValue {
        field: "FakeReviewedArcAdapterV1",
        reason,
    }
}

fn scope() -> ServiceScopeV1 {
    ServiceScopeV1 {
        provider_id: PROVIDER,
        backend: BackendId::DpfPirV1,
        workload: WorkloadId::DpfEvaluateJobV1,
        protocol_version: 1,
        dataset: DatasetBindingV1::Class { class_id: 7 },
        operation_profile: 9,
        entitlement_profile: 2,
    }
}

fn limits() -> EntitlementLimitsV1 {
    EntitlementLimitsV1 {
        max_logical_inputs: 1,
        max_frames: 8,
        max_request_bytes: 1_000_000,
        max_response_bytes: 2_000_000,
        max_wall_time_ms: 60_000,
        max_concurrent_sockets: 1,
        max_hint_groups: 0,
        max_work_units: 9_000,
    }
}

fn signed_arc_policy() -> (ServicePolicyV1, ed25519_dalek::VerifyingKey) {
    let scope = scope();
    let issuer_key = SigningKey::from_bytes(&[0x31; 32]);
    let key_id = vec![0xa6; 16];
    let binding = CredentialKeyBindingV1::sign(
        CredentialKeyBindingClaimsV1 {
            provider_id: PROVIDER,
            scope_id: scope.scope_id(),
            offer_id: 9,
            scheme: AuthScheme::ArcV1Experimental,
            keyset_epoch: 1,
            entitlement_profile: scope.entitlement_profile,
            unit: CredentialUnitV1::Auth,
            amount: 1,
            presentation_limit: 2,
            not_before: 50,
            not_after: 300,
            credential_key_id: key_id.clone(),
            verification_key: vec![0xa5; 99],
        },
        &issuer_key,
    )
    .unwrap();
    let offer = ServiceOfferV1 {
        offer_id: 9,
        acquisition: AcquisitionMethod::Bolt11V1,
        free_mode: FreeModeV1::NotFree,
        free_quota: 0,
        free_window_seconds: 0,
        free_pow_difficulty_bits: 0,
        priority_class: 1,
        authorization: AuthScheme::ArcV1Experimental,
        verification: VerificationMode::ProviderLocal,
        deployment_status: DeploymentStatus::Experimental,
        price: PriceV1::MilliSatoshi(2_000),
        issuer_id: binding.issuer_id,
        key_id,
        credential_binding: Some(binding),
        cashu_mint_manifest: None,
        endpoint: "https://issuer.invalid".into(),
        invoice_expiry_seconds: 10,
        claim_window_seconds: 20,
        minimum_credential_validity_seconds: 30,
        retired_policy_grace_seconds: 100,
        credential_count: 1,
        credential_presentation_limit: 2,
        privacy_leakage: PrivacyLeakageV1::from_bits(PrivacyLeakageV1::KNOWN_MASK).unwrap(),
    };
    let policy_key = SigningKey::from_bytes(&[0x21; 32]);
    let verifying_key = policy_key.verifying_key();
    let policy = ServicePolicyV1::sign(
        PROVIDER,
        1,
        100,
        200,
        AuthPaddingClassV1::Class16KiB,
        vec![ServiceScopePolicyV1 {
            scope,
            limits: limits(),
            offers: vec![offer],
        }],
        &policy_key,
    )
    .unwrap();
    (policy, verifying_key)
}

#[test]
fn provider_store_committer_routes_only_provider_local_experimental_arc() {
    let (policy, policy_key) = signed_arc_policy();
    let verified_policy = policy
        .verify_current_for_acquisition(
            &PROVIDER,
            150,
            &PolicyRollbackGuardV1::initial(),
            &ServicePolicyEpochFloorsV1::default(),
            &policy_key,
        )
        .unwrap();
    let service_scope = scope();
    let verified_offer = verified_policy.offer(&service_scope.scope_id(), 9).unwrap();
    let presentation = ArcPresentationV1::from_canonical_bytes(vec![1, 2, 3]).unwrap();
    let request = AuthBeginV1 {
        policy_digest: verified_offer.policy_digest(),
        scope_id: service_scope.scope_id(),
        offer_id: 9,
        scheme: AuthScheme::ArcV1Experimental,
        key_id: verified_offer.offer().key_id.clone(),
        operation: OperationStartV1::DpfQuery { db_id: 7 },
        proof: presentation.encode().unwrap(),
    };
    let catalog = |_operation: &OperationStartV1| {
        Some(TrustedCatalogResolutionV1::new(
            7,
            service_scope.backend,
            service_scope.workload,
            service_scope.protocol_version,
            service_scope.dataset.clone(),
            service_scope.operation_profile,
        ))
    };
    let canonicalizer = |bytes: &[u8]| Ok(bytes.to_vec());
    let bound =
        bind_auth_begin_v1(&request, verified_offer, &catalog, Some(&canonicalizer)).unwrap();

    let directory = tempfile::Builder::new()
        .prefix("bitcoinpir-runtime-arc-route-")
        .tempdir()
        .unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let store = ProviderStore::create(
        directory.path().join("provider.sqlite3"),
        [0x44; 16],
        PROVIDER,
        StoreOptions::default(),
        Arc::new(MemoryRollbackAuthorityV1::default()),
    )
    .unwrap();
    let adapter = FakeReviewedArcAdapterV1;
    assert!(matches!(
        store
            .install_verified_offer_namespace_v1(bound.verified_offer(), 150, Some(&adapter),)
            .unwrap(),
        VerifiedOfferNamespaceInstallOutcomeV1::Namespace { .. }
    ));

    let disabled = ProviderStoreBearerCommitterV1::new(&store, None);
    assert_eq!(
        disabled.verify_and_commit_v1(
            AdmissionMethodRouteV1::ArcProviderLocalExperimental,
            &bound,
            150,
        ),
        Err(AdmissionCommitErrorV1::ScopeUnavailable)
    );

    let enabled = disabled.with_arc_adapter_v1(&adapter);
    assert_eq!(
        enabled.verify_and_commit_v1(
            AdmissionMethodRouteV1::ArcSharedIssuerOnlineExperimental,
            &bound,
            150,
        ),
        Err(AdmissionCommitErrorV1::UnsupportedScheme)
    );
    assert_eq!(
        enabled.verify_and_commit_v1(
            AdmissionMethodRouteV1::ArcProviderLocalExperimental,
            &bound,
            150,
        ),
        Ok(())
    );
    assert_eq!(
        enabled.verify_and_commit_v1(
            AdmissionMethodRouteV1::ArcProviderLocalExperimental,
            &bound,
            150,
        ),
        Err(AdmissionCommitErrorV1::InvalidOrSpent)
    );
}
