use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};
use pir_issuer_core::{QuoteIdSourceErrorV1, QuoteIdSourceV1};
use pir_issuer_credentials::IssuerCredentialDerivationKeyV1;
use pir_issuer_service::{
    ensure_shared_clearing_binding_material_v1, IssuerAcquisitionServiceV1, IssuerServiceErrorV1,
    QuoteSigningMaterialV1,
};
use pir_issuer_store::{
    BatKeyLineageRegistration, IssuerStore, QuoteState, SqliteIssuerRollbackFloorAuthorityV1,
    StoreOptions,
};
use pir_lightning_backend::FakeLightningNodeV1;
use pir_payment_crypto::{blind_cashu_message_v1, sign_bip340_prehash_v1, K256CashuMintKeyringV1};
use pir_service_protocol::{
    derive_bat_key_id_v1, derive_issuer_id, AcquisitionMethod, AuthPaddingClassV1, AuthScheme,
    BackendId, BitcoinPirCashuBatIssuanceRequestItemV1, Bolt11QuoteClaimEnvelopeV1,
    Bolt11QuoteClaimV1, Bolt11QuoteIntentV1, Bolt11QuoteKeyDelegationV1,
    Bolt11QuoteKeyRollbackGuardV1, Bolt11QuoteStatusV1, Bolt11QuoteV1,
    CredentialIssuanceRequestItemsV1, CredentialIssuanceRequestV1, CredentialKeyBindingClaimsV1,
    CredentialKeyBindingV1, CredentialUnitV1, DatasetBindingV1, DeploymentStatus,
    EntitlementLimitsV1, FreeModeV1, LightningNetworkV1, PolicyRollbackGuardV1, PriceV1,
    PrivacyLeakageV1, ProviderClearingAuthorizationClaimsV1, ProviderClearingAuthorizationV1,
    ServiceOfferV1, ServicePolicyEpochFloorsV1, ServicePolicyV1, ServiceScopePolicyV1,
    ServiceScopeV1, SettlementModesV1, SettlementRuleV1, SettlementUnitV1, VerificationMode,
    WorkloadId,
};
use tempfile::Builder;

const NOW: u64 = 1_700_000_000;

#[derive(Debug)]
struct SequentialIds(AtomicU8);

impl QuoteIdSourceV1 for SequentialIds {
    fn next_quote_id(&self) -> Result<[u8; 32], QuoteIdSourceErrorV1> {
        let value = self.0.fetch_add(1, Ordering::SeqCst);
        if value == 0 || value == u8::MAX {
            Err(QuoteIdSourceErrorV1::Exhausted)
        } else {
            Ok([value; 32])
        }
    }
}

fn point(multiplier: u64) -> [u8; 33] {
    let encoded = (ProjectivePoint::GENERATOR * Scalar::from(multiplier))
        .to_affine()
        .to_encoded_point(true);
    encoded.as_bytes().try_into().expect("compressed point")
}

fn xonly(multiplier: u64) -> [u8; 32] {
    point(multiplier)[1..].try_into().expect("x-only point")
}

fn scalar_bytes(multiplier: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[31] = multiplier;
    bytes
}

fn bat_keyring(multipliers: &[u8]) -> Arc<K256CashuMintKeyringV1> {
    Arc::new(
        K256CashuMintKeyringV1::from_secret_keys(multipliers.iter().copied().map(scalar_bytes))
            .expect("BAT keyring"),
    )
}

struct Fixture {
    issuer_id: [u8; 32],
    provider_id: [u8; 32],
    scope_id: [u8; 32],
    policy_key: SigningKey,
    policy: ServicePolicyV1,
    delegation: Bolt11QuoteKeyDelegationV1,
    quote_key: SigningKey,
    intent: Bolt11QuoteIntentV1,
}

fn fixture(payee_pubkey: [u8; 33]) -> Fixture {
    let issuer_root = SigningKey::from_bytes(&[0x41; 32]);
    let issuer_id = derive_issuer_id(&issuer_root.verifying_key().to_bytes());
    let provider_id = [0x42; 32];
    let scope = ServiceScopeV1 {
        provider_id,
        backend: BackendId::DpfPirV1,
        workload: WorkloadId::DpfEvaluateJobV1,
        protocol_version: 1,
        dataset: DatasetBindingV1::Class { class_id: 1 },
        operation_profile: 2,
        entitlement_profile: 3,
    };
    let scope_id = scope.scope_id();
    let raw_bat_key = point(11);
    let credential_key_id = derive_bat_key_id_v1(
        &provider_id,
        &scope_id,
        9,
        scope.entitlement_profile,
        1,
        &raw_bat_key,
    )
    .to_vec();
    let credential_binding = CredentialKeyBindingV1::sign(
        CredentialKeyBindingClaimsV1 {
            provider_id,
            scope_id,
            offer_id: 9,
            scheme: AuthScheme::BitcoinPirCashuBatV1,
            keyset_epoch: 1,
            entitlement_profile: scope.entitlement_profile,
            unit: CredentialUnitV1::Auth,
            amount: 1,
            presentation_limit: 1,
            not_before: NOW - 100,
            not_after: NOW + 3_500,
            credential_key_id: credential_key_id.clone(),
            verification_key: raw_bat_key.to_vec(),
        },
        &issuer_root,
    )
    .expect("credential binding");
    let offer = ServiceOfferV1 {
        offer_id: 9,
        acquisition: AcquisitionMethod::Bolt11V1,
        free_mode: FreeModeV1::NotFree,
        free_quota: 0,
        free_window_seconds: 0,
        free_pow_difficulty_bits: 0,
        priority_class: 1,
        authorization: AuthScheme::BitcoinPirCashuBatV1,
        verification: VerificationMode::SharedIssuerOnline,
        deployment_status: DeploymentStatus::Stable,
        price: PriceV1::MilliSatoshi(100_000),
        issuer_id,
        key_id: credential_key_id,
        credential_binding: Some(credential_binding),
        cashu_mint_manifest: None,
        endpoint: "https://issuer.invalid".into(),
        invoice_expiry_seconds: 60,
        claim_window_seconds: 120,
        minimum_credential_validity_seconds: 300,
        retired_policy_grace_seconds: 1_000,
        credential_count: 4,
        credential_presentation_limit: 1,
        privacy_leakage: PrivacyLeakageV1::from_bits(
            PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING
                | PrivacyLeakageV1::ISSUER_REDEMPTION_TIMING
                | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER,
        )
        .expect("privacy leakage"),
    };
    let policy_key = SigningKey::from_bytes(&[0x43; 32]);
    let policy = ServicePolicyV1::sign(
        provider_id,
        1,
        NOW - 100,
        NOW + 3_000,
        AuthPaddingClassV1::Class16KiB,
        vec![ServiceScopePolicyV1 {
            scope,
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
            offers: vec![offer],
        }],
        &policy_key,
    )
    .expect("policy");
    let quote_key = SigningKey::from_bytes(&[0x44; 32]);
    let delegation = Bolt11QuoteKeyDelegationV1::sign(
        LightningNetworkV1::Regtest,
        payee_pubkey,
        4,
        NOW - 100,
        NOW + 3_500,
        quote_key.verifying_key().to_bytes(),
        &issuer_root,
    )
    .expect("delegation");
    let verified_policy = policy
        .verify_current_for_acquisition(
            &provider_id,
            NOW,
            &PolicyRollbackGuardV1::initial(),
            &ServicePolicyEpochFloorsV1::initial(),
            &policy_key.verifying_key(),
        )
        .expect("verified policy");
    let verified_offer = verified_policy.offer(&scope_id, 9).expect("offer");
    let guard = Bolt11QuoteKeyRollbackGuardV1::initial(
        issuer_id,
        LightningNetworkV1::Regtest,
        payee_pubkey,
    )
    .expect("delegation guard");
    let (intent, _) = Bolt11QuoteIntentV1::from_verified_offer_guarded(
        &verified_offer,
        &delegation,
        &guard,
        NOW,
        xonly(5),
        [0x45; 32],
    )
    .expect("intent");
    Fixture {
        issuer_id,
        provider_id,
        scope_id,
        policy_key,
        policy,
        delegation,
        quote_key,
        intent,
    }
}

fn rotated_bat_policy(fixture: &Fixture, epoch: u64, bat_multiplier: u8) -> ServicePolicyV1 {
    let issuer_root = SigningKey::from_bytes(&[0x41; 32]);
    let mut scopes = fixture.policy.scopes.clone();
    let entitlement_profile = scopes[0].scope.entitlement_profile;
    let offer = &mut scopes[0].offers[0];
    let public_key = point(u64::from(bat_multiplier));
    let key_id = derive_bat_key_id_v1(
        &fixture.provider_id,
        &fixture.scope_id,
        offer.offer_id,
        entitlement_profile,
        epoch,
        &public_key,
    )
    .to_vec();
    offer.key_id = key_id.clone();
    offer.credential_binding = Some(
        CredentialKeyBindingV1::sign(
            CredentialKeyBindingClaimsV1 {
                provider_id: fixture.provider_id,
                scope_id: fixture.scope_id,
                offer_id: offer.offer_id,
                scheme: AuthScheme::BitcoinPirCashuBatV1,
                keyset_epoch: epoch,
                entitlement_profile,
                unit: CredentialUnitV1::Auth,
                amount: 1,
                presentation_limit: 1,
                not_before: NOW - 100,
                not_after: NOW + 3_500,
                credential_key_id: key_id,
                verification_key: public_key.to_vec(),
            },
            &issuer_root,
        )
        .expect("rotated BAT binding"),
    );
    ServicePolicyV1::sign(
        fixture.provider_id,
        epoch,
        NOW - 50,
        NOW + 3_000,
        fixture.policy.auth_padding_class,
        scopes,
        &fixture.policy_key,
    )
    .expect("rotated BAT policy")
}

#[test]
fn startup_rejects_missing_wrong_and_retained_bat_private_material() {
    let directory = Builder::new()
        .prefix("bitcoinpir-issuer-key-coverage-test-")
        .tempdir()
        .expect("temporary directory");
    let authority = Arc::new(
        SqliteIssuerRollbackFloorAuthorityV1::create(
            directory.path().join("floor.sqlite3"),
            StoreOptions::default().busy_timeout,
        )
        .expect("rollback authority"),
    );
    let lightning = Arc::new(
        FakeLightningNodeV1::new(LightningNetworkV1::Regtest, [3; 32], [7; 32], NOW)
            .expect("fake Lightning"),
    );
    let fixture = fixture(lightning.payee_pubkey());
    let store = IssuerStore::create(
        directory.path().join("issuer.sqlite3"),
        [0x35; 16],
        fixture.issuer_id,
        LightningNetworkV1::Regtest,
        StoreOptions::default(),
        authority,
    )
    .expect("issuer store");
    let _ = store
        .register_service_policy(&fixture.policy, &fixture.policy_key.verifying_key(), NOW)
        .expect("install first policy");

    let build = |keys: Option<Arc<K256CashuMintKeyringV1>>, observed_at: u64| {
        IssuerAcquisitionServiceV1::new(
            store.clone(),
            Arc::clone(&lightning),
            Arc::new(SequentialIds(AtomicU8::new(0x71))),
            QuoteSigningMaterialV1::new(
                fixture.delegation.clone(),
                SigningKey::from_bytes(&[0x44; 32]),
            )
            .expect("quote material"),
            Vec::new(),
            Vec::new(),
            keys,
            None,
            IssuerCredentialDerivationKeyV1::from_bytes([9; 32]).expect("derivation key"),
            observed_at,
        )
    };
    assert_eq!(
        build(None, NOW).unwrap_err(),
        IssuerServiceErrorV1::InvalidRequest
    );
    assert_eq!(
        build(Some(bat_keyring(&[12])), NOW).unwrap_err(),
        IssuerServiceErrorV1::InvalidRequest
    );
    let old_service = build(Some(bat_keyring(&[11])), NOW).expect("old-key service");
    old_service
        .create_quote(&fixture.intent.encode().expect("intent"), NOW)
        .expect("create old-policy quote");
    drop(old_service);

    let rotated = rotated_bat_policy(&fixture, 2, 12);
    let _ = store
        .register_service_policy(&rotated, &fixture.policy_key.verifying_key(), NOW)
        .expect("install rotated policy");
    assert_eq!(
        build(Some(bat_keyring(&[12])), NOW + 1).unwrap_err(),
        IssuerServiceErrorV1::InvalidRequest,
        "current key alone must not strand a claim under the retained policy"
    );
    assert!(build(Some(bat_keyring(&[11, 12])), NOW + 1).is_ok());
    assert!(
        build(Some(bat_keyring(&[12])), NOW + 181).is_ok(),
        "an expired historical quote must not pin its credential private key forever"
    );
}

#[test]
fn startup_requires_quote_signer_only_through_recovery_horizon() {
    let directory = Builder::new()
        .prefix("bitcoinpir-issuer-quote-key-coverage-test-")
        .tempdir()
        .expect("temporary directory");
    let authority = Arc::new(
        SqliteIssuerRollbackFloorAuthorityV1::create(
            directory.path().join("floor.sqlite3"),
            StoreOptions::default().busy_timeout,
        )
        .expect("rollback authority"),
    );
    let lightning = Arc::new(
        FakeLightningNodeV1::new(LightningNetworkV1::Regtest, [3; 32], [7; 32], NOW)
            .expect("fake Lightning"),
    );
    let fixture = fixture(lightning.payee_pubkey());
    let store = IssuerStore::create(
        directory.path().join("issuer.sqlite3"),
        [0x36; 16],
        fixture.issuer_id,
        LightningNetworkV1::Regtest,
        StoreOptions::default(),
        authority,
    )
    .expect("issuer store");
    let _ = store
        .register_service_policy(&fixture.policy, &fixture.policy_key.verifying_key(), NOW)
        .expect("install policy");

    let old_material = || {
        QuoteSigningMaterialV1::new(
            fixture.delegation.clone(),
            SigningKey::from_bytes(&[0x44; 32]),
        )
        .expect("old quote material")
    };
    let issuer_root = SigningKey::from_bytes(&[0x41; 32]);
    let new_quote_key = SigningKey::from_bytes(&[0x45; 32]);
    let new_delegation = Bolt11QuoteKeyDelegationV1::sign(
        LightningNetworkV1::Regtest,
        fixture.delegation.expected_payee_pubkey,
        fixture.delegation.key_epoch + 1,
        NOW - 100,
        NOW + 3_500,
        new_quote_key.verifying_key().to_bytes(),
        &issuer_root,
    )
    .expect("new delegation");
    let new_material = || {
        QuoteSigningMaterialV1::new(new_delegation.clone(), new_quote_key.clone())
            .expect("new quote material")
    };
    let pre_head_service = IssuerAcquisitionServiceV1::new(
        store.clone(),
        Arc::clone(&lightning),
        Arc::new(SequentialIds(AtomicU8::new(0x70))),
        new_material(),
        vec![old_material()],
        Vec::new(),
        Some(bat_keyring(&[11])),
        None,
        IssuerCredentialDerivationKeyV1::from_bytes([9; 32]).expect("derivation key"),
        NOW,
    )
    .expect("rotated service before any delegation head");
    let mut fresh_old_before_head = fixture.intent.clone();
    fresh_old_before_head.idempotency_key = [0x70; 32];
    assert_eq!(
        pre_head_service.create_quote(
            &fresh_old_before_head
                .encode()
                .expect("fresh retained intent"),
            NOW,
        ),
        Err(IssuerServiceErrorV1::Unauthorized),
        "a retained delegation must not create a fresh quote even before a head exists"
    );
    drop(pre_head_service);

    let old_service = IssuerAcquisitionServiceV1::new(
        store.clone(),
        Arc::clone(&lightning),
        Arc::new(SequentialIds(AtomicU8::new(0x72))),
        old_material(),
        Vec::new(),
        Vec::new(),
        Some(bat_keyring(&[11])),
        None,
        IssuerCredentialDerivationKeyV1::from_bytes([9; 32]).expect("derivation key"),
        NOW,
    )
    .expect("old service");
    let old_response = old_service
        .create_quote(&fixture.intent.encode().expect("intent"), NOW)
        .expect("create old quote");
    drop(old_service);
    let build = |current: QuoteSigningMaterialV1,
                 retained: Vec<QuoteSigningMaterialV1>,
                 observed_at: u64| {
        IssuerAcquisitionServiceV1::new(
            store.clone(),
            Arc::clone(&lightning),
            Arc::new(SequentialIds(AtomicU8::new(0x73))),
            current,
            retained,
            Vec::new(),
            Some(bat_keyring(&[11])),
            None,
            IssuerCredentialDerivationKeyV1::from_bytes([9; 32]).expect("derivation key"),
            observed_at,
        )
    };
    assert_eq!(
        build(new_material(), Vec::new(), NOW + 1).unwrap_err(),
        IssuerServiceErrorV1::InvalidRequest,
        "a still-recoverable durable quote must pin its exact retained signer"
    );
    let rotated_service =
        build(new_material(), vec![old_material()], NOW + 1).expect("rotated service");
    assert_eq!(
        rotated_service
            .create_quote(&fixture.intent.encode().expect("exact old intent"), NOW + 1)
            .expect("recover exact retained quote"),
        old_response
    );
    let mut fresh_old_after_head = fixture.intent.clone();
    fresh_old_after_head.idempotency_key = [0x74; 32];
    assert_eq!(
        rotated_service.create_quote(
            &fresh_old_after_head.encode().expect("fresh old intent"),
            NOW + 1,
        ),
        Err(IssuerServiceErrorV1::Unauthorized),
        "a retained delegation must not create a fresh quote after restart"
    );
    let mut fresh_current = fixture.intent.clone();
    fresh_current.minimum_quote_key_epoch = new_delegation.key_epoch;
    fresh_current.quote_delegation_digest = new_delegation
        .delegation_digest()
        .expect("new delegation digest");
    fresh_current.idempotency_key = [0x75; 32];
    rotated_service
        .create_quote(
            &fresh_current.encode().expect("fresh current intent"),
            NOW + 1,
        )
        .expect("fresh current quote");
    drop(rotated_service);
    assert!(
        build(new_material(), Vec::new(), NOW + 181).is_ok(),
        "an expired historical quote must release its signer without deleting its row"
    );
}

#[test]
fn clearing_readiness_requires_live_binding_key_and_immutable_lineage() {
    let directory = Builder::new()
        .prefix("bitcoinpir-issuer-clearing-key-readiness-test-")
        .tempdir()
        .expect("temporary directory");
    let authority = Arc::new(
        SqliteIssuerRollbackFloorAuthorityV1::create(
            directory.path().join("floor.sqlite3"),
            StoreOptions::default().busy_timeout,
        )
        .expect("rollback authority"),
    );
    let lightning = FakeLightningNodeV1::new(LightningNetworkV1::Regtest, [3; 32], [7; 32], NOW)
        .expect("fake Lightning");
    let fixture = fixture(lightning.payee_pubkey());
    let store = IssuerStore::create(
        directory.path().join("issuer.sqlite3"),
        [0x37; 16],
        fixture.issuer_id,
        LightningNetworkV1::Regtest,
        StoreOptions::default(),
        authority,
    )
    .expect("issuer store");
    let _ = store
        .register_service_policy(&fixture.policy, &fixture.policy_key.verifying_key(), NOW)
        .expect("install policy");
    let binding = fixture.policy.scopes[0].offers[0]
        .credential_binding
        .as_ref()
        .expect("BAT binding")
        .clone();
    let operator = SigningKey::from_bytes(&[0x61; 32]);
    let clearing_key = SigningKey::from_bytes(&[0x62; 32]);
    let authorization = ProviderClearingAuthorizationV1::sign(
        ProviderClearingAuthorizationClaimsV1 {
            authorization_id: [0x63; 16],
            authorization_epoch: 1,
            provider_id: fixture.provider_id,
            issuer_id: fixture.issuer_id,
            settlement_account_id: [0x64; 32],
            clearing_verifying_key: clearing_key.verifying_key().to_bytes(),
            not_before: NOW - 100,
            not_after: binding.claims.not_after + 100,
            rules: vec![SettlementRuleV1 {
                credential_binding_digest: binding.binding_digest().expect("binding digest"),
                unit: SettlementUnitV1::AuthCredit,
                accepted_value: 1,
                provider_credit: 1,
                issuer_fee: 0,
                denomination_profile: 1,
                settlement_modes: SettlementModesV1::from_bits(SettlementModesV1::LEDGER_CREDIT)
                    .expect("ledger mode"),
                blind_output_minimum_validity_seconds: 0,
                blind_output_keyset: None,
            }],
        },
        &operator,
    )
    .expect("clearing authorization");

    assert!(
        store
            .credential_bindings_for_clearing_authorization(&authorization, NOW)
            .is_err(),
        "an authorization rule must not activate before immutable lineage registration"
    );
    let raw_public_key: [u8; 33] = binding
        .claims
        .verification_key
        .as_slice()
        .try_into()
        .expect("BAT public key");
    let credential_key_id: [u8; 32] = binding
        .claims
        .credential_key_id
        .as_slice()
        .try_into()
        .expect("BAT key ID");
    let _ = store
        .register_bat_key_lineage(&BatKeyLineageRegistration {
            raw_public_key,
            provider_id: binding.claims.provider_id,
            scope_id: binding.claims.scope_id,
            offer_id: binding.claims.offer_id,
            entitlement_profile: binding.claims.entitlement_profile,
            keyset_epoch: binding.claims.keyset_epoch,
            credential_key_id,
        })
        .expect("register BAT lineage");
    let resolved = store
        .credential_bindings_for_clearing_authorization(&authorization, NOW)
        .expect("resolve clearing binding");
    assert_eq!(resolved, vec![binding.clone()]);
    assert_eq!(
        ensure_shared_clearing_binding_material_v1(&binding, NOW, Some(&bat_keyring(&[12])), None,),
        Err(IssuerServiceErrorV1::InvalidRequest),
        "a rotated current key alone must not strand a live K1 capability"
    );
    assert!(ensure_shared_clearing_binding_material_v1(
        &binding,
        NOW,
        Some(&bat_keyring(&[11])),
        None,
    )
    .is_ok());
    let after_binding = binding.claims.not_after + 1;
    let expired = store
        .credential_bindings_for_clearing_authorization(&authorization, after_binding)
        .expect("expired binding remains lineage-auditable");
    assert_eq!(expired, vec![binding.clone()]);
    assert!(
        ensure_shared_clearing_binding_material_v1(
            &binding,
            after_binding,
            Some(&bat_keyring(&[12])),
            None,
        )
        .is_ok(),
        "expired K1 private material must be retireable"
    );
}

#[test]
fn exact_quote_create_recovers_after_policy_rotation_and_conflicts_on_changed_body() {
    let directory = Builder::new()
        .prefix("bitcoinpir-issuer-service-test-")
        .tempdir()
        .expect("temporary directory");
    let authority = Arc::new(
        SqliteIssuerRollbackFloorAuthorityV1::create(
            directory.path().join("floor.sqlite3"),
            StoreOptions::default().busy_timeout,
        )
        .expect("rollback authority"),
    );
    let lightning = Arc::new(
        FakeLightningNodeV1::new(LightningNetworkV1::Regtest, [3; 32], [7; 32], NOW)
            .expect("fake Lightning"),
    );
    let fixture = fixture(lightning.payee_pubkey());
    let store = IssuerStore::create(
        directory.path().join("issuer.sqlite3"),
        [0x31; 16],
        fixture.issuer_id,
        LightningNetworkV1::Regtest,
        StoreOptions::default(),
        authority,
    )
    .expect("issuer store");
    let _installed = store
        .register_service_policy(&fixture.policy, &fixture.policy_key.verifying_key(), NOW)
        .expect("install policy");
    let service = IssuerAcquisitionServiceV1::new(
        store.clone(),
        lightning,
        Arc::new(SequentialIds(AtomicU8::new(0x51))),
        QuoteSigningMaterialV1::new(fixture.delegation.clone(), fixture.quote_key)
            .expect("quote material"),
        Vec::new(),
        Vec::new(),
        Some(bat_keyring(&[11])),
        None,
        IssuerCredentialDerivationKeyV1::from_bytes([9; 32]).expect("derivation key"),
        NOW,
    )
    .expect("acquisition service");
    let intent_bytes = fixture.intent.encode().expect("intent encoding");
    let first = service
        .create_quote(&intent_bytes, NOW)
        .expect("create quote");

    let rotated = ServicePolicyV1::sign(
        fixture.provider_id,
        2,
        NOW,
        NOW + 3_000,
        fixture.policy.auth_padding_class,
        fixture.policy.scopes.clone(),
        &fixture.policy_key,
    )
    .expect("rotated policy");
    let _rotated = store
        .register_service_policy(&rotated, &fixture.policy_key.verifying_key(), NOW)
        .expect("install rotated policy");

    assert_eq!(
        service
            .create_quote(&intent_bytes, NOW + 1)
            .expect("recover exact old request"),
        first
    );

    let mut changed = fixture.intent.clone();
    changed.exact_amount_msat += 1;
    assert_eq!(
        service.create_quote(&changed.encode().expect("changed encoding"), NOW + 1),
        Err(IssuerServiceErrorV1::Conflict)
    );
    assert_eq!(fixture.scope_id, fixture.intent.scope_id);
}

#[test]
fn same_second_settlement_claim_retries_without_write_then_replays_exactly() {
    let directory = Builder::new()
        .prefix("bitcoinpir-issuer-same-second-claim-test-")
        .tempdir()
        .expect("temporary directory");
    let authority = Arc::new(
        SqliteIssuerRollbackFloorAuthorityV1::create(
            directory.path().join("floor.sqlite3"),
            StoreOptions::default().busy_timeout,
        )
        .expect("rollback authority"),
    );
    let lightning = Arc::new(
        FakeLightningNodeV1::new(LightningNetworkV1::Regtest, [3; 32], [7; 32], NOW)
            .expect("fake Lightning"),
    );
    let fixture = fixture(lightning.payee_pubkey());
    let store = IssuerStore::create(
        directory.path().join("issuer.sqlite3"),
        [0x38; 16],
        fixture.issuer_id,
        LightningNetworkV1::Regtest,
        StoreOptions::default(),
        authority,
    )
    .expect("issuer store");
    let _installed = store
        .register_service_policy(&fixture.policy, &fixture.policy_key.verifying_key(), NOW)
        .expect("install policy");
    let service = IssuerAcquisitionServiceV1::new(
        store.clone(),
        Arc::clone(&lightning),
        Arc::new(SequentialIds(AtomicU8::new(0x76))),
        QuoteSigningMaterialV1::new(fixture.delegation.clone(), fixture.quote_key.clone())
            .expect("quote material"),
        Vec::new(),
        Vec::new(),
        Some(bat_keyring(&[11])),
        None,
        IssuerCredentialDerivationKeyV1::from_bytes([9; 32]).expect("derivation key"),
        NOW,
    )
    .expect("acquisition service");

    let initial = Bolt11QuoteV1::decode(
        &service
            .create_quote(&fixture.intent.encode().expect("intent encoding"), NOW)
            .expect("create quote"),
    )
    .expect("decode initial quote");
    let open_record = store
        .quote(&initial.quote_id)
        .expect("read open quote")
        .expect("open quote");
    let settled_at = NOW + 1;
    lightning
        .set_time(settled_at)
        .expect("advance fake Lightning clock");
    lightning
        .observe_settlement(&open_record.backend_label, initial.amount_msat, settled_at)
        .expect("observe settlement");
    let report = service
        .reconcile_quote_batch(None, 16, settled_at)
        .expect("reconcile settlement");
    assert_eq!(report.transitioned, 1);

    let settled_record = store
        .quote(&initial.quote_id)
        .expect("read settled quote")
        .expect("settled quote");
    assert_eq!(settled_record.state, QuoteState::PaymentSettled);
    let settled = Bolt11QuoteV1::decode(
        settled_record
            .settled_signed_quote_response
            .as_deref()
            .expect("settled signed quote"),
    )
    .expect("decode settled quote");
    assert_eq!(settled.status, Bolt11QuoteStatusV1::PaymentSettled);
    assert_eq!(settled.status_updated_at, settled_at);

    let items = (0..fixture.intent.credential_count)
        .map(|index| {
            let byte = u8::try_from(index + 1).expect("small credential count");
            BitcoinPirCashuBatIssuanceRequestItemV1 {
                blinded_message: blind_cashu_message_v1(&[byte; 32], &scalar_bytes(byte + 16))
                    .expect("blind BAT request"),
            }
        })
        .collect();
    let credential_request = CredentialIssuanceRequestV1 {
        issuer_id: fixture.issuer_id,
        quote_id: settled.quote_id,
        quote_request_digest: settled.request_digest,
        authorization: AuthScheme::BitcoinPirCashuBatV1,
        credential_binding_digest: fixture.intent.credential_binding_digest,
        credential_key_id: fixture.intent.credential_key_id.clone(),
        items: CredentialIssuanceRequestItemsV1::BitcoinPirCashuBat(items),
    };
    let mut claim = Bolt11QuoteClaimV1 {
        issuer_id: fixture.issuer_id,
        quote_id: settled.quote_id,
        quote_request_digest: settled.request_digest,
        credential_request_digest: credential_request
            .request_digest()
            .expect("credential request digest"),
        claim_pubkey_xonly: fixture.intent.claim_pubkey_xonly,
        idempotency_key: fixture.intent.idempotency_key,
        signature: [1; 64],
    };
    let claim_digest = claim.bip340_signing_digest().expect("claim digest");
    let (claim_pubkey, signature) =
        sign_bip340_prehash_v1(&scalar_bytes(5), &claim_digest, &[0x78; 32]).expect("sign claim");
    assert_eq!(claim_pubkey, fixture.intent.claim_pubkey_xonly);
    claim.signature = signature;
    let canonical_envelope = Bolt11QuoteClaimEnvelopeV1 {
        quote_intent: fixture.intent.clone(),
        claim,
        credential_request,
    }
    .encode()
    .expect("claim envelope encoding");

    let first_error = service
        .claim_quote(&settled.quote_id, &canonical_envelope, settled_at)
        .expect_err("same-second claim must be retryable");
    assert_eq!(first_error, IssuerServiceErrorV1::RetryableUnavailable);
    assert_eq!(first_error.http_status(), 503);
    assert!(store
        .claim(&settled.quote_id)
        .expect("read absent claim")
        .is_none());
    assert_eq!(
        store
            .operational_inventory()
            .expect("inventory after retryable claim")
            .claim_rows,
        0
    );
    assert_eq!(
        store
            .quote(&settled.quote_id)
            .expect("read quote after retryable claim")
            .expect("quote after retryable claim")
            .state,
        QuoteState::PaymentSettled
    );

    let issued = service
        .claim_quote(&settled.quote_id, &canonical_envelope, settled_at + 1)
        .expect("next-second claim succeeds");
    assert!(!issued.is_empty());
    assert_eq!(
        store
            .quote(&settled.quote_id)
            .expect("read claimed quote")
            .expect("claimed quote")
            .state,
        QuoteState::CredentialClaimed
    );
    assert_eq!(
        store
            .operational_inventory()
            .expect("inventory after successful claim")
            .claim_rows,
        1
    );
    let replay = service
        .claim_quote(&settled.quote_id, &canonical_envelope, settled_at + 2)
        .expect("exact claim replay succeeds");
    assert_eq!(replay, issued);
}

#[test]
fn background_batch_expires_open_invoice_without_status_nonce() {
    let directory = Builder::new()
        .prefix("bitcoinpir-issuer-reconcile-test-")
        .tempdir()
        .expect("temporary directory");
    let authority = Arc::new(
        SqliteIssuerRollbackFloorAuthorityV1::create(
            directory.path().join("floor.sqlite3"),
            StoreOptions::default().busy_timeout,
        )
        .expect("rollback authority"),
    );
    let lightning = Arc::new(
        FakeLightningNodeV1::new(LightningNetworkV1::Regtest, [3; 32], [7; 32], NOW)
            .expect("fake Lightning"),
    );
    let fixture = fixture(lightning.payee_pubkey());
    let store = IssuerStore::create(
        directory.path().join("issuer.sqlite3"),
        [0x32; 16],
        fixture.issuer_id,
        LightningNetworkV1::Regtest,
        StoreOptions::default(),
        authority,
    )
    .expect("issuer store");
    let _installed = store
        .register_service_policy(&fixture.policy, &fixture.policy_key.verifying_key(), NOW)
        .expect("install policy");
    let service = IssuerAcquisitionServiceV1::new(
        store.clone(),
        Arc::clone(&lightning),
        Arc::new(SequentialIds(AtomicU8::new(0x61))),
        QuoteSigningMaterialV1::new(fixture.delegation.clone(), fixture.quote_key)
            .expect("quote material"),
        Vec::new(),
        Vec::new(),
        Some(bat_keyring(&[11])),
        None,
        IssuerCredentialDerivationKeyV1::from_bytes([9; 32]).expect("derivation key"),
        NOW,
    )
    .expect("acquisition service");
    service
        .create_quote(&fixture.intent.encode().expect("intent encoding"), NOW)
        .expect("create quote");
    lightning.set_time(NOW + 61).expect("advance fake clock");

    let report = service
        .reconcile_quote_batch(None, 16, NOW + 61)
        .expect("background reconciliation");
    assert_eq!(report.examined, 1);
    assert_eq!(report.transitioned, 1);
    assert_eq!(report.retryable_failures, 0);
    assert!(report.next_cursor().is_none());
    assert!(!format!("{report:?}").contains(&"61".repeat(32)));
    assert_eq!(
        store.quote(&[0x61; 32]).unwrap().unwrap().state,
        QuoteState::InvoiceExpiredPendingReconcile
    );
}
