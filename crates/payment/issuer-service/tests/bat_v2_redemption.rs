use std::path::PathBuf;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};
use pir_issuer_service::{BatV2IssuerRedemptionServiceV2, IssuerServiceErrorV1};
use pir_issuer_store::{BatV2ClearingEpochReservationV2, IssuerStore, StoreOptions};
use pir_payment_crypto::{
    blind_cashu_message_v1, verify_and_unblind_cashu_promise_v1, K256CashuMintKeyringV1,
};
use pir_service_protocol::{
    bat_acceptance_member_from_verified_policy_v2, derive_issuer_id, AcquisitionMethod,
    AuthPaddingClassV1, AuthScheme, BackendId, BatAcceptanceClassV2, BitcoinPirCashuBatProofV2,
    DatasetBindingV1, DeploymentStatus, EntitlementLimitsV1, FreeModeV1,
    IssuerAccountingApprovalV2, LightningNetworkV1, PolicyRollbackGuardV1, PriceV1,
    PrivacyLeakageV1, ProviderAccountingAuthorizationClaimsV2, ProviderAccountingAuthorizationV2,
    ProviderAccountingRuleV2, ProviderRedeemEnvelopeV2, ProviderRedeemOutcomeV2,
    ProviderRedeemRequestAuthV2, ProviderRedeemRequestV2, ProviderRedeemResponseV2,
    RetrySafeNonConsumingReasonV2, ServiceOfferV1, ServicePolicyEpochFloorsV1, ServicePolicyV1,
    ServiceScopePolicyV1, ServiceScopeV1, SettlementUnitV1, VerificationMode,
    VerifiedBatAcceptanceMemberV2, WorkloadId,
};
use tempfile::{Builder, TempDir};

const NOW: u64 = 400;
const BAT_KEY_MULTIPLIER: u64 = 101;

struct TestPath {
    _directory: TempDir,
    database: PathBuf,
}

impl TestPath {
    fn new() -> Self {
        let directory = Builder::new()
            .prefix("bitcoinpir-issuer-service-bat-v2-redemption-test-")
            .tempdir()
            .expect("create task-specific temporary directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .expect("restrict task-specific temporary directory permissions");
        }
        Self {
            database: directory.path().join("issuer.sqlite3"),
            _directory: directory,
        }
    }

    fn create_store(&self, issuer_id: [u8; 32]) -> IssuerStore {
        IssuerStore::create(
            &self.database,
            [0x11; 16],
            issuer_id,
            LightningNetworkV1::Regtest,
            StoreOptions::default(),
        )
        .expect("create issuer store")
    }

    fn reopen_store(&self, issuer_id: [u8; 32]) -> IssuerStore {
        IssuerStore::open_existing(
            &self.database,
            issuer_id,
            LightningNetworkV1::Regtest,
            StoreOptions::default(),
        )
        .expect("reopen issuer store")
    }
}

struct Fixture {
    path: TestPath,
    store: IssuerStore,
    issuer_id: [u8; 32],
    class: BatAcceptanceClassV2,
    member: VerifiedBatAcceptanceMemberV2,
    authorization: ProviderAccountingAuthorizationV2,
    clearing_key: SigningKey,
    settlement_key: SigningKey,
    keyring: Arc<K256CashuMintKeyringV1>,
}

impl Fixture {
    fn new() -> Self {
        let issuer_root = SigningKey::from_bytes(&[0x21; 32]);
        let issuer_id = derive_issuer_id(&issuer_root.verifying_key().to_bytes());
        let provider_id = [0xa1; 32];
        let class_id = [0x81; 32];
        let scope = ServiceScopeV1 {
            provider_id,
            backend: BackendId::DpfPirV1,
            workload: WorkloadId::DpfEvaluateJobV1,
            protocol_version: 1,
            dataset: DatasetBindingV1::Class { class_id: 1 },
            operation_profile: 1,
            entitlement_profile: 2,
        };
        let scope_id = scope.scope_id();
        let limits = EntitlementLimitsV1 {
            max_logical_inputs: 4,
            max_frames: 200,
            max_request_bytes: 1_000_000,
            max_response_bytes: 2_000_000,
            max_wall_time_ms: 60_000,
            max_concurrent_sockets: 1,
            max_hint_groups: 0,
            max_work_units: 9_000,
        };
        let privacy_leakage = PrivacyLeakageV1::from_bits(
            PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING
                | PrivacyLeakageV1::ISSUER_REDEMPTION_TIMING
                | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER,
        )
        .expect("BAT V2 privacy flags");
        let offer = ServiceOfferV1 {
            offer_id: 7,
            acquisition: AcquisitionMethod::Bolt11V1,
            free_mode: FreeModeV1::NotFree,
            free_quota: 0,
            free_window_seconds: 0,
            free_pow_difficulty_bits: 0,
            priority_class: 1,
            authorization: AuthScheme::BitcoinPirCashuBatV2,
            verification: VerificationMode::SharedIssuerOnline,
            deployment_status: DeploymentStatus::Stable,
            price: PriceV1::MilliSatoshi(2_000),
            issuer_id,
            key_id: class_id.to_vec(),
            credential_binding: None,
            cashu_mint_manifest: None,
            endpoint: "https://issuer.invalid".to_owned(),
            invoice_expiry_seconds: 60,
            claim_window_seconds: 120,
            minimum_credential_validity_seconds: 300,
            retired_policy_grace_seconds: 480,
            credential_count: 2,
            credential_presentation_limit: 1,
            privacy_leakage,
        };
        let policy_key = SigningKey::from_bytes(&[0xb1; 32]);
        let policy = ServicePolicyV1::sign(
            provider_id,
            1,
            100,
            1_000,
            AuthPaddingClassV1::Class16KiB,
            vec![ServiceScopePolicyV1 {
                scope,
                limits,
                offers: vec![offer],
            }],
            &policy_key,
        )
        .expect("sign BAT V2 member policy");
        let verified_policy = policy
            .verify_current_for_acquisition(
                &provider_id,
                200,
                &PolicyRollbackGuardV1::initial(),
                &ServicePolicyEpochFloorsV1::initial(),
                &policy_key.verifying_key(),
            )
            .expect("verify BAT V2 member policy");
        let member = bat_acceptance_member_from_verified_policy_v2(&verified_policy, &scope_id, 7)
            .expect("project verified BAT V2 member");
        let class = BatAcceptanceClassV2::sign(
            class_id,
            1,
            100,
            1_480,
            point(BAT_KEY_MULTIPLIER),
            member.common_terms.clone(),
            vec![member.member.clone()],
            &issuer_root,
        )
        .expect("sign BAT V2 class");

        let path = TestPath::new();
        let store = path.create_store(issuer_id);
        let _ = store
            .register_service_policy(&policy, &policy_key.verifying_key(), 200)
            .expect("register BAT V2 member policy");
        let _ = store
            .register_bat_acceptance_class_v2(&class, 200)
            .expect("register BAT V2 class");

        let operator_key = SigningKey::from_bytes(&[0xc1; 32]);
        let clearing_key = SigningKey::from_bytes(&[0xc2; 32]);
        let settlement_key = SigningKey::from_bytes(&[0xd1; 32]);
        let authorization = ProviderAccountingAuthorizationV2::sign(
            ProviderAccountingAuthorizationClaimsV2 {
                authorization_id: [0xc3; 16],
                authorization_epoch: 1,
                provider_id,
                issuer_id,
                redeem_endpoint: "https://issuer.invalid".to_owned(),
                redeem_leaf_spki_sha256_pins: vec![[0xc4; 32]],
                settlement_account_id: [0xc5; 32],
                clearing_verifying_key: clearing_key.verifying_key().to_bytes(),
                not_before: 100,
                not_after: 2_000,
                rules: vec![ProviderAccountingRuleV2 {
                    class_id,
                    policy_digest: member.member.policy_digest,
                    scope_id,
                    offer_id: 7,
                    unit: SettlementUnitV1::AuthCredit,
                    accepted_value: 10,
                    provider_credit: 7,
                    issuer_fee: 3,
                }],
            },
            &operator_key,
        )
        .expect("sign BAT V2 accounting authorization");
        let approval =
            IssuerAccountingApprovalV2::sign(&authorization, 200, 2_000, &settlement_key)
                .expect("sign BAT V2 issuer accounting approval");
        let _ = store
            .reserve_bat_v2_clearing_epoch(BatV2ClearingEpochReservationV2 {
                provider_id,
                authorization_epoch: authorization.claims.authorization_epoch,
            })
            .expect("reserve BAT V2 clearing epoch");
        let _ = store
            .register_bat_v2_accounting_authorization(
                &authorization,
                &approval,
                &operator_key.verifying_key(),
                &settlement_key.verifying_key(),
                200,
            )
            .expect("register BAT V2 accounting authorization");
        let keyring = Arc::new(
            K256CashuMintKeyringV1::from_secret_keys([scalar(BAT_KEY_MULTIPLIER)])
                .expect("construct BAT V2 keyring"),
        );

        Self {
            path,
            store,
            issuer_id,
            class,
            member,
            authorization,
            clearing_key,
            settlement_key,
            keyring,
        }
    }

    fn service(&self) -> BatV2IssuerRedemptionServiceV2 {
        BatV2IssuerRedemptionServiceV2::new(
            self.store.clone(),
            Arc::clone(&self.keyring),
            self.settlement_key.clone(),
            NOW,
        )
        .expect("construct BAT V2 redemption service")
    }

    fn proof(&self, secret_byte: u8) -> BitcoinPirCashuBatProofV2 {
        let secret_raw = [secret_byte; 32];
        let blinding_scalar = scalar(u64::from(secret_byte) + 17);
        let blinded_message = blind_cashu_message_v1(&secret_raw, &blinding_scalar)
            .expect("blind BAT V2 Cashu message");
        let promise = self
            .keyring
            .blind_sign_with_dleq_v1(
                &self.class.bat_verification_key,
                &blinded_message,
                &scalar(u64::from(secret_byte) + 37),
            )
            .expect("blind-sign BAT V2 Cashu message");
        let unblinded = verify_and_unblind_cashu_promise_v1(
            &secret_raw,
            &blinding_scalar,
            &self.class.bat_verification_key,
            &blinded_message,
            promise.blinded_signature(),
            promise.dleq_e(),
            promise.dleq_s(),
        )
        .expect("DLEQ-check and unblind BAT V2 Cashu promise");
        BitcoinPirCashuBatProofV2::from_class(
            &self.class,
            secret_raw,
            *unblinded.unblinded_signature(),
        )
        .expect("construct class-bound BAT V2 proof")
    }

    fn envelope(
        &self,
        proof: &BitcoinPirCashuBatProofV2,
        attempt_byte: u8,
        request_signing_key: &SigningKey,
    ) -> ProviderRedeemEnvelopeV2 {
        let (request, _) = ProviderRedeemRequestV2::prepare(
            &self.authorization,
            &self.member,
            &self.class,
            proof,
            [attempt_byte; 32],
        )
        .expect("prepare BAT V2 redeem request")
        .into_parts();
        let request_auth = ProviderRedeemRequestAuthV2::sign(&request, request_signing_key)
            .expect("sign BAT V2 redeem request");
        ProviderRedeemEnvelopeV2 {
            request,
            request_auth,
            credential: proof.clone(),
        }
    }
}

fn point(multiplier: u64) -> [u8; 33] {
    let encoded = (ProjectivePoint::GENERATOR * Scalar::from(multiplier))
        .to_affine()
        .to_encoded_point(true);
    encoded.as_bytes().try_into().expect("compressed point")
}

fn scalar(multiplier: u64) -> [u8; 32] {
    Scalar::from(multiplier).to_bytes().into()
}

fn decode_response(bytes: &[u8]) -> ProviderRedeemResponseV2 {
    ProviderRedeemResponseV2::decode(bytes).expect("decode canonical BAT V2 redeem response")
}

#[test]
fn startup_rejects_missing_required_class_scalar() {
    let fixture = Fixture::new();
    let wrong_keyring = Arc::new(
        K256CashuMintKeyringV1::from_secret_keys([scalar(BAT_KEY_MULTIPLIER + 1)])
            .expect("construct wrong BAT V2 keyring"),
    );

    assert_eq!(
        BatV2IssuerRedemptionServiceV2::new(
            fixture.store,
            wrong_keyring,
            fixture.settlement_key,
            NOW,
        )
        .unwrap_err(),
        IssuerServiceErrorV1::InvalidRequest,
        "a live redemption class must pin its exact Cashu scalar at startup"
    );
}

#[test]
fn fresh_success_and_all_same_proof_replays_are_terminal_across_restart() {
    let fixture = Fixture::new();
    let proof = fixture.proof(0x41);
    let initial = fixture.envelope(&proof, 0x51, &fixture.clearing_key);
    let initial_request = initial.request.clone();
    let initial_wire = initial.encode().expect("encode initial BAT V2 redeem");
    let service = fixture.service();

    let success_wire = service
        .redeem_v2(&initial_wire, NOW)
        .expect("fresh BAT V2 redeem succeeds");
    let success = decode_response(&success_wire);
    success
        .verify_for_exact_request(&initial_request, &fixture.settlement_key.verifying_key())
        .expect("verify signed fresh success");
    assert!(matches!(
        success.outcome,
        ProviderRedeemOutcomeV2::GrantableSuccess { .. }
    ));
    assert_eq!(
        fixture
            .store
            .operational_inventory()
            .expect("inventory after fresh redeem")
            .bat_v2_redemption_rows,
        1
    );

    let exact_replay_wire = service
        .redeem_v2(&initial_wire, NOW)
        .expect("exact attempt replay is classified");
    let exact_replay = decode_response(&exact_replay_wire);
    exact_replay
        .verify_for_exact_request(&initial_request, &fixture.settlement_key.verifying_key())
        .expect("verify signed exact-attempt terminal");
    assert_eq!(
        exact_replay.outcome,
        ProviderRedeemOutcomeV2::TerminalInvalidOrSpent
    );
    assert_ne!(
        exact_replay_wire, success_wire,
        "the issuer must never replay the retained initial success"
    );

    let later = fixture.envelope(&proof, 0x52, &fixture.clearing_key);
    let later_request = later.request.clone();
    let later_wire = later.encode().expect("encode later BAT V2 attempt");
    let later_response = decode_response(
        &service
            .redeem_v2(&later_wire, NOW)
            .expect("same proof under a later attempt is classified"),
    );
    later_response
        .verify_for_exact_request(&later_request, &fixture.settlement_key.verifying_key())
        .expect("verify signed later-attempt terminal");
    assert_eq!(
        later_response.outcome,
        ProviderRedeemOutcomeV2::TerminalInvalidOrSpent
    );
    assert_eq!(
        fixture
            .store
            .operational_inventory()
            .expect("inventory after replay classifications")
            .bat_v2_redemption_rows,
        1
    );

    drop(service);
    let reopened = fixture.path.reopen_store(fixture.issuer_id);
    let restarted = BatV2IssuerRedemptionServiceV2::new(
        reopened,
        Arc::clone(&fixture.keyring),
        fixture.settlement_key.clone(),
        NOW,
    )
    .expect("rebuild BAT V2 redemption service");
    let restarted_replay_wire = restarted
        .redeem_v2(&initial_wire, NOW)
        .expect("restart replay is classified");
    let restarted_replay = decode_response(&restarted_replay_wire);
    restarted_replay
        .verify_for_exact_request(&initial_request, &fixture.settlement_key.verifying_key())
        .expect("verify restart terminal");
    assert_eq!(
        restarted_replay.outcome,
        ProviderRedeemOutcomeV2::TerminalInvalidOrSpent
    );
    assert_eq!(
        restarted_replay_wire, exact_replay_wire,
        "service rebuild must preserve the same unified terminal result"
    );
}

#[test]
fn signed_retry_safe_is_zero_mutation_then_the_same_proof_can_succeed() {
    let fixture = Fixture::new();
    let foreign_provider_id = [0xe2; 32];
    let foreign_operator = SigningKey::from_bytes(&[0xe3; 32]);
    let foreign_clearing = SigningKey::from_bytes(&[0xe4; 32]);
    let foreign_account_id = [0xe5; 32];
    let foreign_authorization = ProviderAccountingAuthorizationV2::sign(
        ProviderAccountingAuthorizationClaimsV2 {
            authorization_id: [0xe6; 16],
            authorization_epoch: 1,
            provider_id: foreign_provider_id,
            issuer_id: fixture.issuer_id,
            redeem_endpoint: "https://issuer.invalid".to_owned(),
            redeem_leaf_spki_sha256_pins: vec![[0xe7; 32]],
            settlement_account_id: foreign_account_id,
            clearing_verifying_key: foreign_clearing.verifying_key().to_bytes(),
            not_before: 100,
            not_after: 2_000,
            rules: vec![ProviderAccountingRuleV2 {
                class_id: fixture.class.class_id,
                policy_digest: fixture.member.member.policy_digest,
                scope_id: fixture.member.member.scope_id,
                offer_id: fixture.member.member.offer_id,
                unit: SettlementUnitV1::AuthCredit,
                accepted_value: 10,
                provider_credit: 7,
                issuer_fee: 3,
            }],
        },
        &foreign_operator,
    )
    .expect("sign foreign-provider accounting authorization");
    let foreign_approval = IssuerAccountingApprovalV2::sign(
        &foreign_authorization,
        200,
        2_000,
        &fixture.settlement_key,
    )
    .expect("sign foreign-provider issuer approval");
    let _ = fixture
        .store
        .reserve_bat_v2_clearing_epoch(BatV2ClearingEpochReservationV2 {
            provider_id: foreign_provider_id,
            authorization_epoch: foreign_authorization.claims.authorization_epoch,
        })
        .expect("reserve foreign-provider BAT V2 clearing epoch");
    let _ = fixture
        .store
        .register_bat_v2_accounting_authorization(
            &foreign_authorization,
            &foreign_approval,
            &foreign_operator.verifying_key(),
            &fixture.settlement_key.verifying_key(),
            200,
        )
        .expect("register foreign-provider accounting authorization");
    let service = fixture.service();
    let proof = fixture.proof(0x61);
    let wrong_clearing_key = SigningKey::from_bytes(&[0xe1; 32]);
    let rejected = fixture.envelope(&proof, 0x62, &wrong_clearing_key);
    let rejected_request = rejected.request.clone();
    let baseline = fixture
        .store
        .identity()
        .expect("identity before retry-safe rejection")
        .commit_seq;

    let rejection = decode_response(
        &service
            .redeem_v2(
                &rejected.encode().expect("encode unauthenticated redeem"),
                NOW,
            )
            .expect("pre-consumption rejection is signed"),
    );
    rejection
        .verify_for_exact_request(&rejected_request, &fixture.settlement_key.verifying_key())
        .expect("verify signed retry-safe response");
    assert_eq!(
        rejection.outcome,
        ProviderRedeemOutcomeV2::RetrySafeNonConsuming {
            reason: RetrySafeNonConsumingReasonV2::ProviderAuthentication,
        }
    );
    assert_eq!(
        fixture
            .store
            .identity()
            .expect("identity after retry-safe rejection")
            .commit_seq,
        baseline,
        "RetrySafeNonConsuming must not mutate the issuer store"
    );
    assert_eq!(
        fixture
            .store
            .operational_inventory()
            .expect("inventory after retry-safe rejection")
            .bat_v2_redemption_rows,
        0
    );

    let mut incompatible = fixture.envelope(&proof, 0x63, &fixture.clearing_key);
    incompatible.request.provider_id = foreign_provider_id;
    incompatible.request.accounting_authorization_digest = foreign_authorization
        .authorization_digest()
        .expect("foreign authorization digest");
    incompatible.request.settlement_account_id = foreign_account_id;
    incompatible.request_auth =
        ProviderRedeemRequestAuthV2::sign(&incompatible.request, &foreign_clearing)
            .expect("sign incompatible foreign-provider request");
    let incompatible_request = incompatible.request.clone();
    let class_rejection = decode_response(
        &service
            .redeem_v2(
                &incompatible
                    .encode()
                    .expect("encode incompatible foreign-provider redeem"),
                NOW,
            )
            .expect("class incompatibility is signed"),
    );
    class_rejection
        .verify_for_exact_request(
            &incompatible_request,
            &fixture.settlement_key.verifying_key(),
        )
        .expect("verify signed class-compatibility response");
    assert_eq!(
        class_rejection.outcome,
        ProviderRedeemOutcomeV2::RetrySafeNonConsuming {
            reason: RetrySafeNonConsumingReasonV2::ClassCompatibility,
        }
    );
    assert_eq!(
        fixture
            .store
            .identity()
            .expect("identity after class-compatibility rejection")
            .commit_seq,
        baseline,
        "class compatibility rejection must not mutate the issuer store"
    );
    assert_eq!(
        fixture
            .store
            .operational_inventory()
            .expect("inventory after class-compatibility rejection")
            .bat_v2_redemption_rows,
        0
    );

    let accepted = fixture.envelope(&proof, 0x62, &fixture.clearing_key);
    let accepted_request = accepted.request.clone();
    let success = decode_response(
        &service
            .redeem_v2(
                &accepted.encode().expect("encode authenticated redeem"),
                NOW,
            )
            .expect("same proof succeeds after retry-safe rejection"),
    );
    success
        .verify_for_exact_request(&accepted_request, &fixture.settlement_key.verifying_key())
        .expect("verify signed success after retry-safe rejection");
    assert!(matches!(
        success.outcome,
        ProviderRedeemOutcomeV2::GrantableSuccess { .. }
    ));
    assert_eq!(
        fixture
            .store
            .operational_inventory()
            .expect("inventory after successful redeem")
            .bat_v2_redemption_rows,
        1
    );
}
