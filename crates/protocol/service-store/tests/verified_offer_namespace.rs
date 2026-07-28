use ed25519_dalek::{SigningKey, VerifyingKey};
use pir_service_protocol::{
    arc_provider_global_spend_key_v1, bat_verification_key_fingerprint_v1, bind_auth_begin_v1,
    derive_bat_key_id_v1, derive_cashu_keyset_id_v2, derive_cashu_mint_id,
    derive_shared_issuer_local_grant_namespace_v1,
    free_anonymous_ticket_key_id, paid_receipt_key_id, AcquisitionMethod, ArcPresentationV1,
    AuthBeginV1, AuthPaddingClassV1, AuthScheme, AuthorizationProofV1, BackendId,
    BoundAuthAttemptV1, CashuDenominationKeyV1, CashuKeysetBindingV1, CashuRequiredNutsV1,
    CredentialKeyBindingClaimsV1, CredentialKeyBindingV1, CredentialUnitV1, DatasetBindingV1,
    DeploymentStatus, EntitlementLimitsV1, FreeAnonymousTicketV1, FreeModeV1, OperationStartV1,
    PolicyRollbackGuardV1, PriceV1, PrivacyLeakageV1, ServiceOfferV1, ServicePolicyEpochFloorsV1,
    ServicePolicyV1, ServiceProtocolError, ServiceScopePolicyV1, ServiceScopeV1,
    StandardCashuMintManifestV1, TrustedCatalogResolutionV1, VerificationMode,
    VerifiedServiceOfferV1, WorkloadId,
};
use pir_service_store::{
    verify_provider_local_arc_spend_v1, verify_provider_local_bearer_spend_v1,
    ArcExclusiveKeyLineageVerifierV1, ArcPresentationSpendVerifierV1, ArcVerifiedSpendSinkV1,
    ExclusiveKeyLineage, NamespaceInstallOutcome, NewSpendNamespace, ProviderStore, StoreError,
    StoreOptions, VerifiedOfferNamespaceInstallOutcomeV1, VerifiedOfferNamespaceNotApplicableV1,
    VerifiedOfferNamespaceReadinessV1,
};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tempfile::{Builder, TempDir};

const PROVIDER: [u8; 32] = [0x11; 32];
const POLICY_SIGNING_SEED: [u8; 32] = [0x21; 32];
const ISSUER_SIGNING_SEED: [u8; 32] = [0x31; 32];
const CREDENTIAL_SIGNING_SEED: [u8; 32] = [0x41; 32];
const SECP256K1_GENERATOR: [u8; 33] = [
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98,
];

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum FakeArcSpendFaultV1 {
    #[default]
    None,
    WrongBinding,
    WrongFingerprint,
    WrongSpendKey,
    NoVerifiedSpend,
    DuplicateVerifiedSpend,
}

#[derive(Clone, Copy, Debug, Default)]
struct FakeReviewedArcAdapterV1 {
    fault: FakeArcSpendFaultV1,
}

impl ArcExclusiveKeyLineageVerifierV1 for FakeReviewedArcAdapterV1 {
    fn verify_arc_exclusive_key_lineage_v1(
        &self,
        verified_offer: &VerifiedServiceOfferV1<'_>,
        binding: &CredentialKeyBindingV1,
        now_unix_seconds: u64,
    ) -> Result<ExclusiveKeyLineage, ServiceProtocolError> {
        let offer = verified_offer.offer();
        if offer.authorization != AuthScheme::ArcV1Experimental
            || offer.verification != VerificationMode::ProviderLocal
            || offer.deployment_status != DeploymentStatus::Experimental
            || offer.credential_binding.as_ref() != Some(binding)
            || now_unix_seconds < binding.claims.not_before
            || now_unix_seconds > binding.claims.not_after
        {
            return Err(arc_test_protocol_error(
                "fake reviewed ARC lineage adapter rejected the binding",
            ));
        }
        let key_fingerprint = fake_arc_key_fingerprint(binding);
        let mut hasher = Sha256::new();
        hasher.update(b"BitcoinPIR/test-arc-exclusive-lineage/v1");
        hasher.update(key_fingerprint);
        hasher.update(binding.binding_digest()?);
        Ok(ExclusiveKeyLineage {
            key_fingerprint,
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
            return Err(arc_test_protocol_error("fake ARC proof type mismatch"));
        }
        if self.fault == FakeArcSpendFaultV1::NoVerifiedSpend {
            return Ok(());
        }
        let binding = attempt
            .offer()
            .credential_binding
            .as_ref()
            .ok_or_else(|| arc_test_protocol_error("fake ARC binding missing"))?;
        let mut public_key_fingerprint = fake_arc_key_fingerprint(binding);
        let mut credential_binding_digest = binding.binding_digest()?;
        let canonical_tag = [0x54; 33];
        match self.fault {
            FakeArcSpendFaultV1::WrongBinding => credential_binding_digest[0] ^= 1,
            FakeArcSpendFaultV1::WrongFingerprint => public_key_fingerprint[0] ^= 1,
            _ => {}
        }
        let mut spend_key = arc_provider_global_spend_key_v1(
            &public_key_fingerprint,
            &credential_binding_digest,
            &canonical_tag,
        );
        if self.fault == FakeArcSpendFaultV1::WrongSpendKey {
            spend_key[0] ^= 1;
        }
        sink.accept_verified_arc_spend_v1(
            &canonical_tag,
            &public_key_fingerprint,
            &credential_binding_digest,
            &spend_key,
        )?;
        if self.fault == FakeArcSpendFaultV1::DuplicateVerifiedSpend {
            sink.accept_verified_arc_spend_v1(
                &canonical_tag,
                &public_key_fingerprint,
                &credential_binding_digest,
                &spend_key,
            )?;
        }
        Ok(())
    }
}

fn fake_arc_key_fingerprint(binding: &CredentialKeyBindingV1) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BitcoinPIR/test-arc-key-fingerprint/v1");
    hasher.update(&binding.claims.verification_key);
    hasher.finalize().into()
}

fn arc_test_protocol_error(reason: &'static str) -> ServiceProtocolError {
    ServiceProtocolError::InvalidValue {
        field: "FakeReviewedArcAdapterV1",
        reason,
    }
}

struct TestPath {
    _directory: TempDir,
    database: PathBuf,
}

impl TestPath {
    fn new() -> Self {
        let directory = Builder::new()
            .prefix("bitcoinpir-verified-offer-store-test-")
            .tempdir()
            .expect("create task-specific temporary directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .expect("restrict verified-offer test directory permissions");
        }
        let database = directory.path().join("provider.sqlite3");
        Self {
            _directory: directory,
            database,
        }
    }
}

fn create_store(path: &Path, instance_byte: u8) -> ProviderStore {
    ProviderStore::create_unprotected_for_tests(
        path,
        [instance_byte; 16],
        PROVIDER,
        StoreOptions::default(),
    )
    .expect("create provider store")
}

fn scope(operation_profile: u16) -> ServiceScopeV1 {
    ServiceScopeV1 {
        provider_id: PROVIDER,
        backend: BackendId::DpfPirV1,
        workload: WorkloadId::DpfEvaluateJobV1,
        protocol_version: 1,
        dataset: DatasetBindingV1::Class { class_id: 7 },
        operation_profile,
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

fn credential_binding(
    scope: &ServiceScopeV1,
    offer_id: u32,
    scheme: AuthScheme,
    keyset_epoch: u64,
    presentation_limit: u32,
) -> (CredentialKeyBindingV1, Vec<u8>) {
    let credential_signing_key = SigningKey::from_bytes(&CREDENTIAL_SIGNING_SEED);
    let (unit, verification_key, key_id) = match scheme {
        AuthScheme::FreeV1 => {
            let key = credential_signing_key.verifying_key();
            (
                CredentialUnitV1::Entitlement,
                key.to_bytes().to_vec(),
                free_anonymous_ticket_key_id(&key).to_vec(),
            )
        }
        AuthScheme::Bolt11DirectReceiptV1 => {
            let key = credential_signing_key.verifying_key();
            (
                CredentialUnitV1::Entitlement,
                key.to_bytes().to_vec(),
                paid_receipt_key_id(&key).to_vec(),
            )
        }
        AuthScheme::BitcoinPirCashuBatV1 => (
            CredentialUnitV1::Auth,
            SECP256K1_GENERATOR.to_vec(),
            derive_bat_key_id_v1(
                &scope.provider_id,
                &scope.scope_id(),
                offer_id,
                scope.entitlement_profile,
                keyset_epoch,
                &SECP256K1_GENERATOR,
            )
            .to_vec(),
        ),
        AuthScheme::ArcV1Experimental => (CredentialUnitV1::Auth, vec![0xa5; 99], vec![0xa6; 16]),
        AuthScheme::CashuEcashV1 => panic!("standard Cashu has no credential binding"),
    };
    let issuer_signing_key = SigningKey::from_bytes(&ISSUER_SIGNING_SEED);
    let binding = CredentialKeyBindingV1::sign(
        CredentialKeyBindingClaimsV1 {
            provider_id: scope.provider_id,
            scope_id: scope.scope_id(),
            offer_id,
            scheme,
            keyset_epoch,
            entitlement_profile: scope.entitlement_profile,
            unit,
            amount: 1,
            presentation_limit,
            not_before: 50,
            not_after: 300,
            credential_key_id: key_id.clone(),
            verification_key,
        },
        &issuer_signing_key,
    )
    .unwrap();
    (binding, key_id)
}

fn bearer_offer(
    scope: &ServiceScopeV1,
    offer_id: u32,
    scheme: AuthScheme,
    verification: VerificationMode,
    keyset_epoch: u64,
) -> ServiceOfferV1 {
    let presentation_limit = if scheme == AuthScheme::ArcV1Experimental {
        2
    } else {
        1
    };
    let (binding, key_id) =
        credential_binding(scope, offer_id, scheme, keyset_epoch, presentation_limit);
    let is_free = scheme == AuthScheme::FreeV1;
    ServiceOfferV1 {
        offer_id,
        acquisition: if is_free {
            AcquisitionMethod::FreeV1
        } else {
            AcquisitionMethod::Bolt11V1
        },
        free_mode: if is_free {
            FreeModeV1::AnonymousTicket
        } else {
            FreeModeV1::NotFree
        },
        free_quota: 0,
        free_window_seconds: 0,
        free_pow_difficulty_bits: 0,
        priority_class: 1,
        authorization: scheme,
        verification,
        deployment_status: if scheme == AuthScheme::ArcV1Experimental {
            DeploymentStatus::Experimental
        } else {
            DeploymentStatus::Stable
        },
        price: if is_free {
            PriceV1::Free
        } else {
            PriceV1::MilliSatoshi(2_000)
        },
        issuer_id: binding.issuer_id,
        key_id,
        credential_binding: Some(binding),
        cashu_mint_manifest: None,
        endpoint: "https://issuer.invalid".into(),
        invoice_expiry_seconds: if is_free { 0 } else { 10 },
        claim_window_seconds: if is_free { 0 } else { 20 },
        minimum_credential_validity_seconds: 30,
        retired_policy_grace_seconds: 100,
        credential_count: 1,
        credential_presentation_limit: presentation_limit,
        privacy_leakage: PrivacyLeakageV1::from_bits(PrivacyLeakageV1::KNOWN_MASK).unwrap(),
    }
}

fn non_bearer_free_offer(mode: FreeModeV1, offer_id: u32) -> ServiceOfferV1 {
    let (free_quota, free_window_seconds, free_pow_difficulty_bits) = match mode {
        FreeModeV1::OpenBestEffort => (0, 0, 0),
        FreeModeV1::IpRateLimited => (5, 60, 0),
        FreeModeV1::ProofOfWork => (0, 0, 8),
        _ => panic!("helper only accepts non-bearer Free modes"),
    };
    ServiceOfferV1 {
        offer_id,
        acquisition: AcquisitionMethod::FreeV1,
        free_mode: mode,
        free_quota,
        free_window_seconds,
        free_pow_difficulty_bits,
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
        minimum_credential_validity_seconds: 30,
        retired_policy_grace_seconds: 0,
        credential_count: 1,
        credential_presentation_limit: 1,
        privacy_leakage: PrivacyLeakageV1::from_bits(PrivacyLeakageV1::KNOWN_MASK).unwrap(),
    }
}

fn standard_cashu_offer(offer_id: u32) -> ServiceOfferV1 {
    let keys = vec![CashuDenominationKeyV1 {
        amount: 1,
        public_key: SECP256K1_GENERATOR,
    }];
    let keyset = CashuKeysetBindingV1 {
        keyset_id: derive_cashu_keyset_id_v2(&keys, "sat", 0, Some(1_000)).unwrap(),
        unit: "sat".into(),
        input_fee_ppk: 0,
        final_expiry: Some(1_000),
        keys,
    };
    let manifest = StandardCashuMintManifestV1 {
        manifest_epoch: 1,
        mint_endpoint: "https://mint.example".into(),
        leaf_spki_sha256_pins: vec![[0x31; 32]],
        unit: "sat".into(),
        required_nuts: CashuRequiredNutsV1::required_v1(),
        accepted_input_keysets: vec![keyset.clone()],
        active_output_keyset: keyset,
    };
    ServiceOfferV1 {
        offer_id,
        acquisition: AcquisitionMethod::CashuEcashV1,
        free_mode: FreeModeV1::NotFree,
        free_quota: 0,
        free_window_seconds: 0,
        free_pow_difficulty_bits: 0,
        priority_class: 1,
        authorization: AuthScheme::CashuEcashV1,
        verification: VerificationMode::StandardCashuMintOnline,
        deployment_status: DeploymentStatus::Stable,
        price: PriceV1::Cashu {
            unit: "sat".into(),
            amount: 1,
        },
        issuer_id: derive_cashu_mint_id("https://mint.example"),
        key_id: manifest.manifest_digest().unwrap().to_vec(),
        credential_binding: None,
        cashu_mint_manifest: Some(manifest),
        endpoint: "https://mint.example".into(),
        invoice_expiry_seconds: 0,
        claim_window_seconds: 0,
        minimum_credential_validity_seconds: 30,
        retired_policy_grace_seconds: 0,
        credential_count: 1,
        credential_presentation_limit: 1,
        privacy_leakage: PrivacyLeakageV1::from_bits(PrivacyLeakageV1::KNOWN_MASK).unwrap(),
    }
}

fn signed_policy(
    scope: ServiceScopeV1,
    offer: ServiceOfferV1,
    policy_epoch: u64,
) -> (ServicePolicyV1, VerifyingKey) {
    let signing_key = SigningKey::from_bytes(&POLICY_SIGNING_SEED);
    let verifying_key = signing_key.verifying_key();
    let policy = ServicePolicyV1::sign(
        scope.provider_id,
        policy_epoch,
        100,
        200,
        AuthPaddingClassV1::Class16KiB,
        vec![ServiceScopePolicyV1 {
            scope,
            limits: limits(),
            offers: vec![offer],
        }],
        &signing_key,
    )
    .unwrap();
    (policy, verifying_key)
}

fn verified_offer<'a>(
    policy: &'a ServicePolicyV1,
    verifying_key: &VerifyingKey,
) -> VerifiedServiceOfferV1<'a> {
    let verified_policy = policy
        .verify_current_for_acquisition(
            &policy.provider_id,
            150,
            &PolicyRollbackGuardV1::initial(),
            &ServicePolicyEpochFloorsV1::default(),
            verifying_key,
        )
        .unwrap();
    let scope_id = policy.scopes[0].scope.scope_id();
    verified_policy
        .offer(&scope_id, policy.scopes[0].offers[0].offer_id)
        .unwrap()
}

fn bound_arc_attempt<'a>(verified_offer: VerifiedServiceOfferV1<'a>) -> BoundAuthAttemptV1<'a> {
    let offer = verified_offer.offer();
    let scope = verified_offer.scope().clone();
    let presentation = ArcPresentationV1::from_canonical_bytes(vec![0x51, 0x52, 0x53]).unwrap();
    let request = AuthBeginV1 {
        policy_digest: verified_offer.policy_digest(),
        scope_id: scope.scope_id(),
        offer_id: offer.offer_id,
        scheme: AuthScheme::ArcV1Experimental,
        key_id: offer.key_id.clone(),
        operation: OperationStartV1::DpfQuery { db_id: 7 },
        proof: presentation.encode().unwrap(),
    };
    let catalog = |_operation: &OperationStartV1| {
        Some(TrustedCatalogResolutionV1::new(
            7,
            scope.backend,
            scope.workload,
            scope.protocol_version,
            scope.dataset.clone(),
            scope.operation_profile,
        ))
    };
    let canonicalizer = |bytes: &[u8]| Ok(bytes.to_vec());
    bind_auth_begin_v1(&request, verified_offer, &catalog, Some(&canonicalizer)).unwrap()
}

fn install_offer(
    store: &ProviderStore,
    scope: ServiceScopeV1,
    offer: ServiceOfferV1,
    policy_epoch: u64,
) -> Result<VerifiedOfferNamespaceInstallOutcomeV1, StoreError> {
    let (policy, verifying_key) = signed_policy(scope, offer, policy_epoch);
    let verified = verified_offer(&policy, &verifying_key);
    store.install_verified_offer_namespace_v1(&verified, 150, None)
}

fn expect_namespace(
    outcome: VerifiedOfferNamespaceInstallOutcomeV1,
) -> (NewSpendNamespace, NamespaceInstallOutcome) {
    match outcome {
        VerifiedOfferNamespaceInstallOutcomeV1::Namespace {
            namespace,
            install_outcome,
        } => (*namespace, install_outcome),
        other => panic!("expected a durable namespace, got {other:?}"),
    }
}

#[test]
fn arc_raw_key_lineage_is_permanent_across_scope_offer_keyset_and_binding_changes() {
    let first_scope = scope(1);
    let first_offer = bearer_offer(
        &first_scope,
        60,
        AuthScheme::ArcV1Experimental,
        VerificationMode::ProviderLocal,
        1,
    );

    let changed_scope = scope(2);
    let changed_scope_offer = bearer_offer(
        &changed_scope,
        60,
        AuthScheme::ArcV1Experimental,
        VerificationMode::ProviderLocal,
        1,
    );
    let changed_offer_id = bearer_offer(
        &first_scope,
        61,
        AuthScheme::ArcV1Experimental,
        VerificationMode::ProviderLocal,
        1,
    );
    let changed_keyset = bearer_offer(
        &first_scope,
        60,
        AuthScheme::ArcV1Experimental,
        VerificationMode::ProviderLocal,
        2,
    );
    let mut changed_binding = first_offer.clone();
    let mut changed_claims = changed_binding
        .credential_binding
        .as_ref()
        .unwrap()
        .claims
        .clone();
    changed_claims.not_before = 40;
    let changed_signed_binding = CredentialKeyBindingV1::sign(
        changed_claims,
        &SigningKey::from_bytes(&ISSUER_SIGNING_SEED),
    )
    .unwrap();
    changed_binding.issuer_id = changed_signed_binding.issuer_id;
    changed_binding.credential_binding = Some(changed_signed_binding);

    let variants = vec![
        (changed_scope, changed_scope_offer),
        (first_scope.clone(), changed_offer_id),
        (first_scope.clone(), changed_keyset),
        (first_scope.clone(), changed_binding),
    ];
    let adapter = FakeReviewedArcAdapterV1::default();
    for (index, (second_scope, second_offer)) in variants.into_iter().enumerate() {
        let test_path = TestPath::new();
        let store = create_store(&test_path.database, 30 + index as u8);
        let (first_policy, first_policy_key) =
            signed_policy(first_scope.clone(), first_offer.clone(), 1);
        let first_verified = verified_offer(&first_policy, &first_policy_key);
        let (first_namespace, first_outcome) = expect_namespace(
            store
                .install_verified_offer_namespace_v1(&first_verified, 150, Some(&adapter))
                .unwrap(),
        );
        assert_eq!(first_outcome, NamespaceInstallOutcome::Installed);
        store
            .close_namespace(&first_namespace.namespace_id)
            .expect("close old ARC namespace");

        let (second_policy, second_policy_key) = signed_policy(second_scope, second_offer, 2);
        let second_verified = verified_offer(&second_policy, &second_policy_key);
        assert!(matches!(
            store.install_verified_offer_namespace_v1(&second_verified, 150, Some(&adapter)),
            Err(StoreError::ExclusiveKeyLineageConflict)
        ));

        let connection = Connection::open(&test_path.database).unwrap();
        let lineage_rows: i64 = connection
            .query_row("SELECT COUNT(*) FROM exclusive_key_lineages", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(lineage_rows, 1);
    }
}

#[test]
fn arc_exact_namespace_replay_is_idempotent_but_expired_binding_fails_closed() {
    let test_path = TestPath::new();
    let store = create_store(&test_path.database, 40);
    let service_scope = scope(3);
    let offer = bearer_offer(
        &service_scope,
        70,
        AuthScheme::ArcV1Experimental,
        VerificationMode::ProviderLocal,
        1,
    );
    let (policy, key) = signed_policy(service_scope, offer, 1);
    let verified = verified_offer(&policy, &key);
    let adapter = FakeReviewedArcAdapterV1::default();
    let (namespace, first) = expect_namespace(
        store
            .install_verified_offer_namespace_v1(&verified, 150, Some(&adapter))
            .unwrap(),
    );
    let (replayed, second) = expect_namespace(
        store
            .install_verified_offer_namespace_v1(&verified, 150, Some(&adapter))
            .unwrap(),
    );
    assert_eq!(namespace, replayed);
    assert_eq!(first, NamespaceInstallOutcome::Installed);
    assert_eq!(
        second,
        NamespaceInstallOutcome::AlreadyPresent(pir_service_store::NamespaceStatus::Active)
    );

    let bound = bound_arc_attempt(verified);
    assert!(matches!(
        verify_provider_local_arc_spend_v1(&bound, 301, &adapter),
        Err(StoreError::ServiceProtocol(_))
    ));
}

#[test]
fn arc_retained_readiness_rejects_missing_exclusive_key_lineage() {
    let test_path = TestPath::new();
    let store = create_store(&test_path.database, 44);
    let service_scope = scope(7);
    let offer = bearer_offer(
        &service_scope,
        74,
        AuthScheme::ArcV1Experimental,
        VerificationMode::ProviderLocal,
        1,
    );
    let (policy, key) = signed_policy(service_scope, offer, 1);
    let verified = verified_offer(&policy, &key);
    let adapter = FakeReviewedArcAdapterV1::default();
    let _ = store
        .install_verified_offer_namespace_v1(&verified, 150, Some(&adapter))
        .unwrap();
    assert_eq!(
        store
            .verify_existing_verified_offer_namespace_v1(&verified, 150, Some(&adapter))
            .unwrap(),
        VerifiedOfferNamespaceReadinessV1::Ready
    );

    Connection::open(&test_path.database)
        .unwrap()
        .execute("DELETE FROM exclusive_key_lineages", [])
        .unwrap();
    assert!(matches!(
        store.verify_existing_verified_offer_namespace_v1(&verified, 150, Some(&adapter)),
        Err(StoreError::SchemaMismatch(message))
            if message == "namespace is missing its exclusive key lineage"
    ));
}

#[test]
fn arc_retained_readiness_rejects_tampered_exclusive_key_lineage() {
    let test_path = TestPath::new();
    let store = create_store(&test_path.database, 45);
    let service_scope = scope(8);
    let offer = bearer_offer(
        &service_scope,
        75,
        AuthScheme::ArcV1Experimental,
        VerificationMode::ProviderLocal,
        1,
    );
    let (policy, key) = signed_policy(service_scope, offer, 1);
    let verified = verified_offer(&policy, &key);
    let adapter = FakeReviewedArcAdapterV1::default();
    let _ = store
        .install_verified_offer_namespace_v1(&verified, 150, Some(&adapter))
        .unwrap();

    Connection::open(&test_path.database)
        .unwrap()
        .execute(
            "UPDATE exclusive_key_lineages SET lineage_digest = ?1",
            params![[0xee_u8; 32].as_slice()],
        )
        .unwrap();
    assert!(matches!(
        store.verify_existing_verified_offer_namespace_v1(&verified, 150, Some(&adapter)),
        Err(StoreError::ExclusiveKeyLineageConflict)
    ));
}

#[test]
fn arc_spend_exact_replay_and_concurrency_have_one_durable_winner() {
    let test_path = TestPath::new();
    let store = create_store(&test_path.database, 41);
    let service_scope = scope(4);
    let offer = bearer_offer(
        &service_scope,
        71,
        AuthScheme::ArcV1Experimental,
        VerificationMode::ProviderLocal,
        1,
    );
    let (policy, key) = signed_policy(service_scope, offer, 1);
    let verified = verified_offer(&policy, &key);
    let adapter = FakeReviewedArcAdapterV1::default();
    let _ = store
        .install_verified_offer_namespace_v1(&verified, 150, Some(&adapter))
        .unwrap();
    let bound = bound_arc_attempt(verified);

    let first = verify_provider_local_arc_spend_v1(&bound, 150, &adapter).unwrap();
    assert_eq!(
        store
            .spend_verified_arc_provider_local_v1(first)
            .unwrap()
            .spend_commit_seq,
        1
    );
    let replay = verify_provider_local_arc_spend_v1(&bound, 150, &adapter).unwrap();
    assert!(matches!(
        store.spend_verified_arc_provider_local_v1(replay),
        Err(StoreError::AlreadySpent)
    ));

    let concurrent_path = TestPath::new();
    let concurrent_store = create_store(&concurrent_path.database, 42);
    let service_scope = scope(5);
    let offer = bearer_offer(
        &service_scope,
        72,
        AuthScheme::ArcV1Experimental,
        VerificationMode::ProviderLocal,
        1,
    );
    let (policy, key) = signed_policy(service_scope, offer, 1);
    let verified = verified_offer(&policy, &key);
    let _ = concurrent_store
        .install_verified_offer_namespace_v1(&verified, 150, Some(&adapter))
        .unwrap();
    let bound = bound_arc_attempt(verified);
    let results = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..8 {
            let store = concurrent_store.clone();
            let bound = &bound;
            let adapter = &adapter;
            handles.push(scope.spawn(move || {
                let verified = verify_provider_local_arc_spend_v1(bound, 150, adapter)?;
                store.spend_verified_arc_provider_local_v1(verified)
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(StoreError::AlreadySpent)))
            .count(),
        7
    );
}

#[test]
fn arc_sealed_spend_rejects_wrong_binding_fingerprint_key_and_adapter_protocol() {
    let test_path = TestPath::new();
    let store = create_store(&test_path.database, 43);
    let service_scope = scope(6);
    let offer = bearer_offer(
        &service_scope,
        73,
        AuthScheme::ArcV1Experimental,
        VerificationMode::ProviderLocal,
        1,
    );
    let (policy, key) = signed_policy(service_scope, offer, 1);
    let verified = verified_offer(&policy, &key);
    let good = FakeReviewedArcAdapterV1::default();
    let _ = store
        .install_verified_offer_namespace_v1(&verified, 150, Some(&good))
        .unwrap();
    let bound = bound_arc_attempt(verified);

    for fault in [
        FakeArcSpendFaultV1::WrongBinding,
        FakeArcSpendFaultV1::WrongFingerprint,
        FakeArcSpendFaultV1::WrongSpendKey,
        FakeArcSpendFaultV1::NoVerifiedSpend,
        FakeArcSpendFaultV1::DuplicateVerifiedSpend,
    ] {
        let faulty = FakeReviewedArcAdapterV1 { fault };
        assert!(matches!(
            verify_provider_local_arc_spend_v1(&bound, 150, &faulty),
            Err(StoreError::ServiceProtocol(_))
        ));
    }

    let verified = verify_provider_local_arc_spend_v1(&bound, 150, &good).unwrap();
    assert_eq!(
        store
            .spend_verified_arc_provider_local_v1(verified)
            .unwrap()
            .spend_commit_seq,
        1
    );
}

fn assert_no_namespace_rows(path: &Path) {
    let connection = Connection::open(path).unwrap();
    let namespaces: i64 = connection
        .query_row("SELECT COUNT(*) FROM spend_namespaces", [], |row| {
            row.get(0)
        })
        .unwrap();
    let lineages: i64 = connection
        .query_row("SELECT COUNT(*) FROM exclusive_key_lineages", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!((namespaces, lineages), (0, 0));
}

#[test]
fn all_authorization_schemes_route_to_their_authoritative_state() {
    for (index, mode) in [
        FreeModeV1::OpenBestEffort,
        FreeModeV1::IpRateLimited,
        FreeModeV1::ProofOfWork,
    ]
    .into_iter()
    .enumerate()
    {
        let test_path = TestPath::new();
        let store = create_store(&test_path.database, index as u8 + 1);
        assert_eq!(
            install_offer(
                &store,
                scope(1),
                non_bearer_free_offer(mode, index as u32 + 1),
                1,
            )
            .unwrap(),
            VerifiedOfferNamespaceInstallOutcomeV1::NotApplicable(
                VerifiedOfferNamespaceNotApplicableV1::NonBearerFree
            )
        );
        assert_no_namespace_rows(&test_path.database);
    }

    let free_path = TestPath::new();
    let free_store = create_store(&free_path.database, 4);
    let (free_namespace, free_outcome) = expect_namespace(
        install_offer(
            &free_store,
            scope(1),
            bearer_offer(
                &scope(1),
                4,
                AuthScheme::FreeV1,
                VerificationMode::ProviderLocal,
                1,
            ),
            1,
        )
        .unwrap(),
    );
    assert_eq!(free_outcome, NamespaceInstallOutcome::Installed);
    assert!(free_namespace.exclusive_key_lineage.is_none());

    let shared_free_path = TestPath::new();
    let shared_free_store = create_store(&shared_free_path.database, 10);
    let (shared_free_namespace, shared_free_outcome) = expect_namespace(
        install_offer(
            &shared_free_store,
            scope(1),
            bearer_offer(
                &scope(1),
                10,
                AuthScheme::FreeV1,
                VerificationMode::SharedIssuerOnline,
                1,
            ),
            1,
        )
        .unwrap(),
    );
    assert_eq!(shared_free_outcome, NamespaceInstallOutcome::Installed);
    assert_eq!(
        shared_free_namespace.scheme,
        pir_service_protocol::SHARED_ISSUER_LOCAL_GRANT_NAMESPACE_SCHEME_V1
    );
    assert!(shared_free_namespace.exclusive_key_lineage.is_none());

    let receipt_path = TestPath::new();
    let receipt_store = create_store(&receipt_path.database, 5);
    let (receipt_namespace, receipt_outcome) = expect_namespace(
        install_offer(
            &receipt_store,
            scope(1),
            bearer_offer(
                &scope(1),
                5,
                AuthScheme::Bolt11DirectReceiptV1,
                VerificationMode::ProviderLocal,
                1,
            ),
            1,
        )
        .unwrap(),
    );
    assert_eq!(receipt_outcome, NamespaceInstallOutcome::Installed);
    assert!(receipt_namespace.exclusive_key_lineage.is_none());

    let cashu_path = TestPath::new();
    let cashu_store = create_store(&cashu_path.database, 6);
    assert_eq!(
        install_offer(&cashu_store, scope(1), standard_cashu_offer(6), 1).unwrap(),
        VerifiedOfferNamespaceInstallOutcomeV1::NotApplicable(
            VerifiedOfferNamespaceNotApplicableV1::StandardCashuMintOnline
        )
    );
    assert_no_namespace_rows(&cashu_path.database);

    let bat_path = TestPath::new();
    let bat_store = create_store(&bat_path.database, 7);
    let (bat_namespace, bat_outcome) = expect_namespace(
        install_offer(
            &bat_store,
            scope(1),
            bearer_offer(
                &scope(1),
                7,
                AuthScheme::BitcoinPirCashuBatV1,
                VerificationMode::ProviderLocal,
                1,
            ),
            1,
        )
        .unwrap(),
    );
    assert_eq!(bat_outcome, NamespaceInstallOutcome::Installed);
    assert_eq!(bat_namespace.not_after, 300);
    assert_eq!(
        bat_namespace
            .exclusive_key_lineage
            .expect("BAT lineage")
            .key_fingerprint,
        bat_verification_key_fingerprint_v1(&SECP256K1_GENERATOR).unwrap()
    );

    let arc_path = TestPath::new();
    let arc_store = create_store(&arc_path.database, 8);
    assert_eq!(
        install_offer(
            &arc_store,
            scope(1),
            bearer_offer(
                &scope(1),
                8,
                AuthScheme::ArcV1Experimental,
                VerificationMode::ProviderLocal,
                1,
            ),
            1,
        )
        .unwrap(),
        VerifiedOfferNamespaceInstallOutcomeV1::UnsupportedExperimental
    );
    assert_no_namespace_rows(&arc_path.database);

    let shared_path = TestPath::new();
    let shared_store = create_store(&shared_path.database, 9);
    let (shared_namespace, shared_outcome) = expect_namespace(
        install_offer(
            &shared_store,
            scope(1),
            bearer_offer(
                &scope(1),
                9,
                AuthScheme::BitcoinPirCashuBatV1,
                VerificationMode::SharedIssuerOnline,
                1,
            ),
            1,
        )
        .unwrap(),
    );
    assert_eq!(shared_outcome, NamespaceInstallOutcome::Installed);
    assert_eq!(
        shared_namespace.scheme,
        pir_service_protocol::SHARED_ISSUER_LOCAL_GRANT_NAMESPACE_SCHEME_V1
    );
    assert!(shared_namespace.exclusive_key_lineage.is_none());
}

#[test]
fn shared_issuer_synthetic_namespace_is_unique_per_complete_offer_purpose() {
    let base_scope = scope(1);
    let mut other_provider_scope = base_scope.clone();
    other_provider_scope.provider_id = [0x12; 32];
    let other_scope = scope(2);
    let mut other_entitlement_scope = base_scope.clone();
    other_entitlement_scope.entitlement_profile += 1;

    let purposes = [
        (base_scope.clone(), 70),
        (other_provider_scope, 70),
        (other_scope, 70),
        (base_scope.clone(), 71),
        (other_entitlement_scope, 70),
    ];
    let namespaces = purposes
        .into_iter()
        .enumerate()
        .map(|(index, (service_scope, offer_id))| {
            let offer = bearer_offer(
                &service_scope,
                offer_id,
                AuthScheme::FreeV1,
                VerificationMode::SharedIssuerOnline,
                1,
            );
            let (policy, key) = signed_policy(service_scope, offer, index as u64 + 1);
            derive_shared_issuer_local_grant_namespace_v1(&verified_offer(&policy, &key))
                .expect("derive shared-issuer synthetic namespace")
        })
        .collect::<Vec<_>>();

    for (index, first) in namespaces.iter().enumerate() {
        for second in &namespaces[index + 1..] {
            assert_ne!(first.namespace_id(), second.namespace_id());
            assert_ne!(first.key_id(), second.key_id());
            assert_ne!(
                (first.namespace_id(), first.key_id()),
                (second.namespace_id(), second.key_id())
            );
            // All variants deliberately reuse the same issuer root/key.
            assert_eq!(first.issuer_id(), second.issuer_id());
        }
    }
}

#[test]
fn exact_binding_is_deterministic_and_idempotent_across_signed_policies() {
    let test_path = TestPath::new();
    let store = create_store(&test_path.database, 1);
    let service_scope = scope(1);
    let offer = bearer_offer(
        &service_scope,
        10,
        AuthScheme::BitcoinPirCashuBatV1,
        VerificationMode::ProviderLocal,
        7,
    );
    let (first_policy, first_key) = signed_policy(service_scope.clone(), offer.clone(), 1);
    let (second_policy, second_key) = signed_policy(service_scope, offer, 2);
    assert_ne!(
        first_policy.policy_digest().unwrap(),
        second_policy.policy_digest().unwrap()
    );

    let (first_namespace, first_outcome) = expect_namespace(
        store
            .install_verified_offer_namespace_v1(
                &verified_offer(&first_policy, &first_key),
                150,
                None,
            )
            .unwrap(),
    );
    let (second_namespace, second_outcome) = expect_namespace(
        store
            .install_verified_offer_namespace_v1(
                &verified_offer(&second_policy, &second_key),
                150,
                None,
            )
            .unwrap(),
    );
    assert_eq!(first_outcome, NamespaceInstallOutcome::Installed);
    assert_eq!(
        first_namespace.namespace_id,
        [
            0xde, 0x3d, 0xee, 0xb1, 0x8a, 0x7e, 0xbe, 0xca, 0xb8, 0xcd, 0xac, 0x16, 0x4e, 0x8d,
            0x83, 0x36, 0x4e, 0x60, 0x66, 0x2a, 0x28, 0x73, 0xfa, 0x58, 0xbd, 0x56, 0x7d, 0xdd,
            0xd6, 0x5f, 0x4a, 0x0e,
        ]
    );
    assert_eq!(
        first_namespace.binding_digest,
        [
            0x3b, 0xe4, 0xe6, 0x35, 0x12, 0xb2, 0x81, 0xf0, 0xb1, 0xe5, 0x4f, 0x95, 0x3b, 0x5d,
            0x5c, 0xa6, 0x99, 0xe1, 0x25, 0xda, 0xbc, 0xcf, 0x97, 0x2d, 0x57, 0x38, 0x24, 0x70,
            0xe7, 0xde, 0xa7, 0x7f,
        ]
    );
    assert_eq!(
        first_namespace
            .exclusive_key_lineage
            .expect("BAT lineage")
            .lineage_digest,
        [
            0x1c, 0x12, 0x4d, 0xd2, 0x0a, 0xaa, 0xba, 0x5c, 0xb5, 0x8b, 0x2a, 0xc9, 0xd3, 0x26,
            0x7b, 0xc7, 0x7c, 0xb5, 0xeb, 0xf8, 0x0b, 0x70, 0x88, 0xa5, 0xe5, 0x57, 0x4c, 0xdd,
            0x7e, 0x06, 0xc9, 0x22,
        ]
    );
    assert_eq!(
        second_outcome,
        NamespaceInstallOutcome::AlreadyPresent(pir_service_store::NamespaceStatus::Active)
    );
    assert_eq!(first_namespace, second_namespace);
    assert_eq!(first_namespace.not_after, 300);
}

#[test]
fn same_raw_bat_key_cannot_cross_scope_offer_or_keyset_epoch() {
    let test_path = TestPath::new();
    let store = create_store(&test_path.database, 1);
    let initial_scope = scope(1);
    let initial_offer = bearer_offer(
        &initial_scope,
        20,
        AuthScheme::BitcoinPirCashuBatV1,
        VerificationMode::ProviderLocal,
        1,
    );
    expect_namespace(install_offer(&store, initial_scope, initial_offer, 1).unwrap());

    let changed_scope = scope(2);
    let changed_scope_offer = bearer_offer(
        &changed_scope,
        20,
        AuthScheme::BitcoinPirCashuBatV1,
        VerificationMode::ProviderLocal,
        1,
    );
    assert!(matches!(
        install_offer(&store, changed_scope, changed_scope_offer, 2),
        Err(StoreError::ExclusiveKeyLineageConflict)
    ));

    let mut changed_profile_scope = scope(1);
    changed_profile_scope.entitlement_profile = 3;
    let changed_profile_offer = bearer_offer(
        &changed_profile_scope,
        20,
        AuthScheme::BitcoinPirCashuBatV1,
        VerificationMode::ProviderLocal,
        1,
    );
    assert!(matches!(
        install_offer(&store, changed_profile_scope, changed_profile_offer, 3),
        Err(StoreError::ExclusiveKeyLineageConflict)
    ));

    let changed_offer_scope = scope(1);
    let changed_offer = bearer_offer(
        &changed_offer_scope,
        21,
        AuthScheme::BitcoinPirCashuBatV1,
        VerificationMode::ProviderLocal,
        1,
    );
    assert!(matches!(
        install_offer(&store, changed_offer_scope, changed_offer, 4),
        Err(StoreError::ExclusiveKeyLineageConflict)
    ));

    let changed_epoch_scope = scope(1);
    let changed_epoch = bearer_offer(
        &changed_epoch_scope,
        20,
        AuthScheme::BitcoinPirCashuBatV1,
        VerificationMode::ProviderLocal,
        2,
    );
    assert!(matches!(
        install_offer(&store, changed_epoch_scope, changed_epoch, 5),
        Err(StoreError::ExclusiveKeyLineageConflict)
    ));
}

#[test]
fn derived_namespace_is_deterministic_across_independent_stores_and_restart() {
    let first_path = TestPath::new();
    let second_path = TestPath::new();
    let first_store = create_store(&first_path.database, 1);
    let second_store = create_store(&second_path.database, 2);
    let service_scope = scope(1);
    let offer = bearer_offer(
        &service_scope,
        30,
        AuthScheme::Bolt11DirectReceiptV1,
        VerificationMode::ProviderLocal,
        3,
    );
    let (policy, key) = signed_policy(service_scope, offer, 1);
    let verified = verified_offer(&policy, &key);

    let (first_namespace, first_outcome) = expect_namespace(
        first_store
            .install_verified_offer_namespace_v1(&verified, 150, None)
            .unwrap(),
    );
    let (second_namespace, second_outcome) = expect_namespace(
        second_store
            .install_verified_offer_namespace_v1(&verified, 150, None)
            .unwrap(),
    );
    assert_eq!(first_outcome, NamespaceInstallOutcome::Installed);
    assert_eq!(second_outcome, NamespaceInstallOutcome::Installed);
    assert_eq!(first_namespace, second_namespace);
    drop(first_store);

    let reopened = ProviderStore::open_existing_unprotected_for_tests(
        &first_path.database,
        PROVIDER,
        StoreOptions::default(),
    )
    .unwrap();
    let (restarted_namespace, restarted_outcome) = expect_namespace(
        reopened
            .install_verified_offer_namespace_v1(&verified, 150, None)
            .unwrap(),
    );
    assert_eq!(restarted_namespace, first_namespace);
    assert_eq!(
        restarted_outcome,
        NamespaceInstallOutcome::AlreadyPresent(pir_service_store::NamespaceStatus::Active)
    );
}

#[test]
fn verified_offer_must_match_the_store_provider() {
    let test_path = TestPath::new();
    let store = create_store(&test_path.database, 1);
    let mut foreign_scope = scope(1);
    foreign_scope.provider_id = [0x99; 32];
    let foreign_offer = bearer_offer(
        &foreign_scope,
        40,
        AuthScheme::Bolt11DirectReceiptV1,
        VerificationMode::ProviderLocal,
        1,
    );
    let (policy, key) = signed_policy(foreign_scope, foreign_offer, 1);
    let verified = verified_offer(&policy, &key);
    assert!(matches!(
        store.install_verified_offer_namespace_v1(&verified, 150, None),
        Err(StoreError::ProviderMismatch)
    ));
    assert_no_namespace_rows(&test_path.database);
}

#[test]
fn runtime_spend_entry_requires_bound_and_cryptographically_verified_typestate() {
    let test_path = TestPath::new();
    let store = create_store(&test_path.database, 1);
    let service_scope = scope(9);
    let offer = bearer_offer(
        &service_scope,
        50,
        AuthScheme::FreeV1,
        VerificationMode::ProviderLocal,
        1,
    );
    let (policy, policy_key) = signed_policy(service_scope.clone(), offer, 1);
    let verified_offer = verified_offer(&policy, &policy_key);
    let _ = store
        .install_verified_offer_namespace_v1(&verified_offer, 150, None)
        .unwrap();

    let credential_key = SigningKey::from_bytes(&CREDENTIAL_SIGNING_SEED);
    let ticket = FreeAnonymousTicketV1::sign(
        PROVIDER,
        service_scope.scope_id(),
        50,
        verified_offer.policy_digest(),
        service_scope.entitlement_profile,
        verified_offer.offer().issuer_id,
        [0xd1; 32],
        100,
        200,
        &credential_key,
    )
    .unwrap();
    let request = AuthBeginV1 {
        policy_digest: verified_offer.policy_digest(),
        scope_id: service_scope.scope_id(),
        offer_id: 50,
        scheme: AuthScheme::FreeV1,
        key_id: verified_offer.offer().key_id.clone(),
        operation: OperationStartV1::DpfQuery { db_id: 7 },
        proof: ticket.encode().unwrap(),
    };
    let catalog = |_operation: &OperationStartV1| {
        Some(TrustedCatalogResolutionV1::new(
            7,
            BackendId::DpfPirV1,
            WorkloadId::DpfEvaluateJobV1,
            1,
            DatasetBindingV1::Class { class_id: 7 },
            9,
        ))
    };
    let bound = bind_auth_begin_v1(&request, verified_offer, &catalog, None).unwrap();
    let verified_spend = verify_provider_local_bearer_spend_v1(&bound, 150, None).unwrap();
    assert_eq!(
        store
            .spend_verified_provider_local_v1(verified_spend)
            .unwrap()
            .spend_commit_seq,
        1
    );
    assert!(matches!(
        store.spend_verified_provider_local_v1(verified_spend),
        Err(StoreError::AlreadySpent)
    ));
}
