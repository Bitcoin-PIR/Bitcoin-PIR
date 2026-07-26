use super::*;
use pir_issuer_store::{
    BatKeyLineageRegistration, ProviderSettlementRegistrationWriteV1,
    SqliteIssuerRollbackFloorAuthorityV1, StoreOptions,
};
use pir_payment_crypto::{cashu_hash_to_curve_v1, K256CashuMintKeyringV1};
use pir_service_protocol::{
    credential_presentation_digest, derive_bat_key_id_v1, derive_issuer_id,
    verify_new_payout_response_for, verify_new_payout_status_response_for, AuthScheme,
    BitcoinPirCashuBatProofV1, CredentialKeyBindingClaimsV1, CredentialKeyBindingV1,
    CredentialUnitV1, IssuerBalanceResponseV1, IssuerClearingApprovalV1,
    IssuerPayoutIntentResponseV1, IssuerPayoutResponseV1, IssuerPayoutStatusResponseV1,
    IssuerSettlementKeyringExpectationV1, LightningNetworkV1, PayoutExecutionContextV1,
    PayoutStateV1, PayoutStatusContextV1, ProviderBalanceEnvelopeV1, ProviderBalanceRequestV1,
    ProviderClearingAuthorizationClaimsV1, ProviderClearingAuthorizationV1,
    ProviderClearingExpectationV1, ProviderClearingRequestAuthV1, ProviderPayoutEnvelopeV1,
    ProviderPayoutIntentEnvelopeV1, ProviderPayoutIntentRequestV1, ProviderPayoutRequestV1,
    ProviderPayoutStatusEnvelopeV1, ProviderPayoutStatusRequestV1, ProviderRedeemEnvelopeV1,
    ProviderRedeemRequestV1, ProviderSettlementRegistrationExpectationV1,
    ProviderSettlementRequestAuthV1, SettlementDestinationV1, SettlementModesV1, SettlementRuleV1,
    SettlementUnitV1,
};
use std::sync::Arc;

const ISSUER_ROOT_SEED: [u8; 32] = [0x21; 32];
const SETTLEMENT_SIGNING_SEED: [u8; 32] = [0x25; 32];
const PROVIDER_ID: [u8; 32] = [0x31; 32];
const SCOPE_ID: [u8; 32] = [0x32; 32];
const ACCOUNT_ID: [u8; 32] = [0x33; 32];
const PAYOUT_TARGET_ID: [u8; 32] = [0x34; 32];
const NOW: u64 = 1_500;

struct Fixture {
    _directory: tempfile::TempDir,
    store: IssuerStore,
    bat_keyring: Arc<K256CashuMintKeyringV1>,
    operator: SigningKey,
    clearing: SigningKey,
    provider_request: SigningKey,
    binding: CredentialKeyBindingV1,
    authorization: ProviderClearingAuthorizationV1,
    approval: IssuerClearingApprovalV1,
    issuer_id: [u8; 32],
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("test directory");
        let issuer_root = SigningKey::from_bytes(&ISSUER_ROOT_SEED);
        let issuer_id = derive_issuer_id(&issuer_root.verifying_key().to_bytes());
        let rollback = Arc::new(
            SqliteIssuerRollbackFloorAuthorityV1::create(
                directory.path().join("issuer-floor.sqlite3"),
                StoreOptions::default().busy_timeout,
            )
            .expect("rollback floor"),
        );
        let store = IssuerStore::create(
            directory.path().join("issuer.sqlite3"),
            [0x11; 16],
            issuer_id,
            LightningNetworkV1::Regtest,
            StoreOptions::default(),
            rollback,
        )
        .expect("issuer store");
        let provider_request = SigningKey::from_bytes(&[0x22; 32]);
        let _ = store
            .register_provider_settlement(&ProviderSettlementRegistrationWriteV1 {
                registration_epoch: 1,
                provider_id: PROVIDER_ID,
                settlement_account_id: ACCOUNT_ID,
                provider_request_verifying_key: provider_request.verifying_key().to_bytes(),
                payout_target_id: PAYOUT_TARGET_ID,
                not_before: 1_000,
                not_after: 5_000,
            })
            .expect("provider registration");

        let bat_keyring =
            Arc::new(K256CashuMintKeyringV1::from_secret_keys([[0x07; 32]]).expect("BAT keyring"));
        let bat_public_key = bat_keyring.denomination_public_keys()[0];
        let credential_key_id =
            derive_bat_key_id_v1(&PROVIDER_ID, &SCOPE_ID, 7, 9, 1, &bat_public_key);
        let binding = CredentialKeyBindingV1::sign(
            CredentialKeyBindingClaimsV1 {
                provider_id: PROVIDER_ID,
                scope_id: SCOPE_ID,
                offer_id: 7,
                scheme: AuthScheme::BitcoinPirCashuBatV1,
                keyset_epoch: 1,
                entitlement_profile: 9,
                unit: CredentialUnitV1::Auth,
                amount: 1,
                presentation_limit: 1,
                not_before: 1_000,
                not_after: 5_000,
                credential_key_id: credential_key_id.to_vec(),
                verification_key: bat_public_key.to_vec(),
            },
            &issuer_root,
        )
        .expect("BAT binding");
        let _ = store
            .register_bat_key_lineage(&BatKeyLineageRegistration {
                raw_public_key: bat_public_key,
                provider_id: PROVIDER_ID,
                scope_id: SCOPE_ID,
                offer_id: 7,
                entitlement_profile: 9,
                keyset_epoch: 1,
                credential_key_id,
            })
            .expect("BAT key lineage");

        let operator = SigningKey::from_bytes(&[0x23; 32]);
        let clearing = SigningKey::from_bytes(&[0x24; 32]);
        let settlement_signing = SigningKey::from_bytes(&SETTLEMENT_SIGNING_SEED);
        let authorization = ProviderClearingAuthorizationV1::sign(
            ProviderClearingAuthorizationClaimsV1 {
                authorization_id: [0x35; 16],
                authorization_epoch: 1,
                provider_id: PROVIDER_ID,
                issuer_id,
                settlement_account_id: ACCOUNT_ID,
                clearing_verifying_key: clearing.verifying_key().to_bytes(),
                not_before: 1_000,
                not_after: 5_000,
                rules: vec![SettlementRuleV1 {
                    credential_binding_digest: binding.binding_digest().expect("binding digest"),
                    unit: SettlementUnitV1::AuthCredit,
                    accepted_value: 10,
                    provider_credit: 9,
                    issuer_fee: 1,
                    denomination_profile: 1,
                    settlement_modes: SettlementModesV1::from_bits(
                        SettlementModesV1::LEDGER_CREDIT,
                    )
                    .expect("ledger settlement mode"),
                    blind_output_minimum_validity_seconds: 0,
                    blind_output_keyset: None,
                }],
            },
            &operator,
        )
        .expect("clearing authorization");
        let approval =
            IssuerClearingApprovalV1::sign(&authorization, 1_000, 5_000, &settlement_signing)
                .expect("issuer approval");
        let _ = store
            .register_clearing_authorization(
                &authorization,
                &approval,
                &operator.verifying_key(),
                &settlement_signing.verifying_key(),
                NOW,
            )
            .expect("register clearing authorization");
        Self {
            _directory: directory,
            store,
            bat_keyring,
            operator,
            clearing,
            provider_request,
            binding,
            authorization,
            approval,
            issuer_id,
        }
    }

    fn service(&self) -> SharedIssuerClearingServiceV1 {
        self.service_with_settlement_lineage(SETTLEMENT_SIGNING_SEED, Vec::new())
    }

    fn service_with_settlement_lineage(
        &self,
        current_seed: [u8; 32],
        retained_keys: Vec<ed25519_dalek::VerifyingKey>,
    ) -> SharedIssuerClearingServiceV1 {
        SharedIssuerClearingServiceV1::new(
            self.store.clone(),
            vec![TrustedClearingProviderV1 {
                provider_id: PROVIDER_ID,
                operator_key: self.operator.verifying_key(),
                minimum_authorization_epoch: 1,
            }],
            Some(Arc::clone(&self.bat_keyring)),
            None,
            SigningKey::from_bytes(&current_seed),
            retained_keys,
            None,
            Vec::new(),
            RedeemResponseDerivationKeyV1::from_bytes([0x46; 32]).expect("redeem derivation key"),
            SettlementPayoutPolicyV1::new(2, 100).expect("payout policy"),
        )
        .expect("clearing service")
    }

    fn credential(&self) -> Vec<u8> {
        let secret_raw = [0x44; 32];
        let hashed = cashu_hash_to_curve_v1(&secret_raw).expect("hash BAT secret");
        let signed = self
            .bat_keyring
            .blind_sign_with_dleq_v1(
                &self.bat_keyring.denomination_public_keys()[0],
                &hashed,
                &[0x45; 32],
            )
            .expect("sign BAT proof");
        BitcoinPirCashuBatProofV1 {
            secret_raw,
            c: *signed.blinded_signature(),
        }
        .encode()
        .expect("BAT proof encoding")
        .to_vec()
    }
}

#[test]
fn shared_issuer_redeem_balance_payout_and_restart_status_are_executable() {
    let fixture = Fixture::new();
    let service = fixture.service();
    let authorization_digest = fixture
        .authorization
        .authorization_digest()
        .expect("authorization digest");

    let credential = fixture.credential();
    let redeem_request = ProviderRedeemRequestV1 {
        authorization_digest,
        issuer_id: fixture.issuer_id,
        provider_id: PROVIDER_ID,
        scope_id: SCOPE_ID,
        offer_id: 7,
        credential_binding_digest: fixture.binding.binding_digest().expect("binding digest"),
        scheme: AuthScheme::BitcoinPirCashuBatV1,
        credential_digest: credential_presentation_digest(
            AuthScheme::BitcoinPirCashuBatV1,
            &credential,
        )
        .expect("credential digest"),
        accepted_value: 10,
        denomination_profile: 1,
        idempotency_key: [0x50; 32],
        destination: SettlementDestinationV1::LedgerCredit {
            account_id: ACCOUNT_ID,
        },
    };
    let redeem_auth = ProviderClearingRequestAuthV1::sign(
        authorization_digest,
        redeem_request.request_digest().expect("redeem digest"),
        &fixture.clearing,
    );
    let redeem_envelope = ProviderRedeemEnvelopeV1 {
        request: redeem_request,
        request_auth: redeem_auth,
        credential_binding: fixture.binding.clone(),
        canonical_credential: credential,
    }
    .encode()
    .expect("redeem envelope");
    let redeem_response = service.redeem(&redeem_envelope, NOW).expect("redeem BAT");
    assert_eq!(
        service
            .redeem(&redeem_envelope, NOW)
            .expect("redeem replay"),
        redeem_response
    );
    let rotated = fixture.service_with_settlement_lineage(
        [0x26; 32],
        vec![SigningKey::from_bytes(&SETTLEMENT_SIGNING_SEED).verifying_key()],
    );
    assert_eq!(
        rotated
            .redeem(&redeem_envelope, 6_000)
            .expect("redeem replay after auth expiry and issuer key rotation"),
        redeem_response
    );

    let balance_request = ProviderBalanceRequestV1 {
        authorization_digest,
        issuer_id: fixture.issuer_id,
        provider_id: PROVIDER_ID,
        account_id: ACCOUNT_ID,
        unit: SettlementUnitV1::AuthCredit,
        idempotency_key: [0x51; 32],
    };
    let balance_auth = ProviderClearingRequestAuthV1::sign(
        authorization_digest,
        balance_request.request_digest().expect("balance digest"),
        &fixture.clearing,
    );
    let balance_bytes = service
        .balance(
            &ProviderBalanceEnvelopeV1 {
                request: balance_request.clone(),
                request_auth: balance_auth,
            }
            .encode()
            .expect("balance envelope"),
            NOW + 1,
        )
        .expect("balance response");
    let balance = IssuerBalanceResponseV1::decode(&balance_bytes).expect("decode balance");
    balance
        .verify_for_exact_request(
            &balance_request,
            &SigningKey::from_bytes(&SETTLEMENT_SIGNING_SEED).verifying_key(),
        )
        .expect("verify balance");
    assert_eq!((balance.available_value, balance.reserved_value), (9, 0));

    let intent_request = ProviderPayoutIntentRequestV1 {
        authorization_digest,
        issuer_id: fixture.issuer_id,
        provider_id: PROVIDER_ID,
        account_id: ACCOUNT_ID,
        payout_target_id: PAYOUT_TARGET_ID,
        unit: SettlementUnitV1::AuthCredit,
        payout_value: 7,
        idempotency_key: [0x52; 32],
    };
    let intent_auth = ProviderClearingRequestAuthV1::sign(
        authorization_digest,
        intent_request.request_digest().expect("intent digest"),
        &fixture.clearing,
    );
    let intent_envelope = ProviderPayoutIntentEnvelopeV1 {
        request: intent_request.clone(),
        request_auth: intent_auth,
    }
    .encode()
    .expect("intent envelope");
    let intent_bytes = service
        .payout_intent(&intent_envelope, NOW + 2)
        .expect("payout intent");
    assert_eq!(
        service
            .payout_intent(&intent_envelope, 6_000)
            .expect("historical intent replay"),
        intent_bytes
    );
    let intent_response =
        IssuerPayoutIntentResponseV1::decode(&intent_bytes).expect("decode intent");
    assert_eq!(
        (intent_response.issuer_fee, intent_response.total_debit),
        (2, 9)
    );

    let payout_request = ProviderPayoutRequestV1 {
        authorization_digest,
        issuer_id: fixture.issuer_id,
        provider_id: PROVIDER_ID,
        account_id: ACCOUNT_ID,
        payout_target_id: PAYOUT_TARGET_ID,
        payout_intent_id: intent_response.payout_intent_id,
        payout_intent_digest: intent_response
            .payout_intent_digest()
            .expect("intent response digest"),
        unit: SettlementUnitV1::AuthCredit,
        payout_value: 7,
        total_debit: 9,
        idempotency_key: [0x53; 32],
    };
    let payout_auth = ProviderClearingRequestAuthV1::sign(
        authorization_digest,
        payout_request.request_digest().expect("payout digest"),
        &fixture.clearing,
    );
    let payout_envelope = ProviderPayoutEnvelopeV1 {
        request: payout_request.clone(),
        request_auth: payout_auth.clone(),
        intent_request: intent_request.clone(),
        intent_response: intent_response.clone(),
    }
    .encode()
    .expect("payout envelope");
    let payout_bytes = service
        .payout(&payout_envelope, NOW + 4)
        .expect("execute payout");
    assert_eq!(
        service
            .payout(&payout_envelope, 6_000)
            .expect("historical payout replay"),
        payout_bytes
    );
    let payout_response =
        IssuerPayoutResponseV1::decode(&payout_bytes).expect("decode payout response");
    assert_eq!(payout_response.state, PayoutStateV1::Accepted);

    let settlement_key = SigningKey::from_bytes(&SETTLEMENT_SIGNING_SEED).verifying_key();
    let operator_key = fixture.operator.verifying_key();
    let clearing_expectation = ProviderClearingExpectationV1 {
        provider_id: &PROVIDER_ID,
        issuer_id: &fixture.issuer_id,
        operator_key: &operator_key,
        issuer_settlement_key: &settlement_key,
        now_unix: NOW + 4,
        minimum_authorization_epoch: 1,
    };
    let payout_context = PayoutExecutionContextV1 {
        intent_request: &intent_request,
        intent_response: &intent_response,
        registered_payout_target_id: &PAYOUT_TARGET_ID,
    };
    let initial_snapshot = verify_new_payout_response_for(
        &payout_response,
        &payout_request,
        &payout_context,
        &fixture.authorization,
        &fixture.approval,
        &payout_auth,
        &clearing_expectation,
    )
    .expect("verify initial payout");

    let registration = fixture
        .store
        .provider_settlement_registration(&PROVIDER_ID)
        .expect("read registration")
        .expect("registration exists");
    let status_request = ProviderPayoutStatusRequestV1 {
        registration_digest: registration.registration_digest,
        issuer_id: fixture.issuer_id,
        provider_id: PROVIDER_ID,
        account_id: ACCOUNT_ID,
        payout_id: payout_response.payout_id,
        payout_request_digest: payout_request.request_digest().expect("payout digest"),
        request_nonce: [0x54; 32],
    };
    let status_auth = ProviderSettlementRequestAuthV1::sign(
        registration.registration_digest,
        status_request.request_digest().expect("status digest"),
        &fixture.provider_request,
    );
    let status_envelope = ProviderPayoutStatusEnvelopeV1 {
        request: status_request.clone(),
        request_auth: status_auth.clone(),
        payout_request: payout_request.clone(),
        initial_payout_response: payout_response.clone(),
    }
    .encode()
    .expect("status envelope");
    // A new service instance proves status reconstruction does not depend on
    // in-memory typestate from the payout execution.
    let restarted = fixture.service();
    let status_bytes = restarted
        .payout_status(&status_envelope, NOW + 5)
        .expect("payout status");
    assert_eq!(
        restarted
            .payout_status(&status_envelope, NOW + 5)
            .expect("status exact replay"),
        status_bytes
    );
    let rotated_provider_request = SigningKey::from_bytes(&[0x27; 32]);
    let rotated_registration = fixture
        .store
        .register_provider_settlement(&ProviderSettlementRegistrationWriteV1 {
            registration_epoch: 2,
            provider_id: PROVIDER_ID,
            settlement_account_id: ACCOUNT_ID,
            provider_request_verifying_key: rotated_provider_request.verifying_key().to_bytes(),
            payout_target_id: PAYOUT_TARGET_ID,
            not_before: NOW + 6,
            not_after: 7_000,
        })
        .expect("rotate provider settlement request key");
    assert!(
        fixture
            .store
            .historical_provider_settlement_registration(
                &PROVIDER_ID,
                &registration.registration_digest,
            )
            .expect("read retained provider registration")
            == Some(registration.clone())
    );
    assert_eq!(
        fixture
            .store
            .provider_settlement_registration(&PROVIDER_ID)
            .expect("read rotated registration")
            .expect("rotated registration exists")
            .registration_digest,
        rotated_registration.value.registration_digest
    );
    assert_eq!(
        restarted
            .payout_status(&status_envelope, NOW + 7)
            .expect("old exact status replay after provider key rotation"),
        status_bytes
    );
    assert_eq!(
        restarted
            .payout_status(&status_envelope, 6_000)
            .expect("old exact status replay after rotation and registration expiry"),
        status_bytes
    );
    let mut old_fresh_request = status_request.clone();
    old_fresh_request.request_nonce = [0x55; 32];
    let old_fresh_auth = ProviderSettlementRequestAuthV1::sign(
        registration.registration_digest,
        old_fresh_request
            .request_digest()
            .expect("old fresh status digest"),
        &fixture.provider_request,
    );
    let old_fresh_envelope = ProviderPayoutStatusEnvelopeV1 {
        request: old_fresh_request,
        request_auth: old_fresh_auth,
        payout_request: payout_request.clone(),
        initial_payout_response: payout_response.clone(),
    }
    .encode()
    .expect("old fresh status envelope");
    assert_eq!(
        restarted.payout_status(&old_fresh_envelope, NOW + 7),
        Err(IssuerServiceErrorV1::Unauthorized)
    );
    let mut tampered_auth = status_auth.clone();
    tampered_auth.signature[0] ^= 0x01;
    let tampered_envelope = ProviderPayoutStatusEnvelopeV1 {
        request: status_request.clone(),
        request_auth: tampered_auth,
        payout_request: payout_request.clone(),
        initial_payout_response: payout_response.clone(),
    }
    .encode()
    .expect("tampered status envelope");
    assert_eq!(
        restarted.payout_status(&tampered_envelope, NOW + 7),
        Err(IssuerServiceErrorV1::Unauthorized)
    );
    let mut wrong_provider_request = status_request.clone();
    wrong_provider_request.provider_id = [0x41; 32];
    let wrong_provider_envelope = ProviderPayoutStatusEnvelopeV1 {
        request: wrong_provider_request,
        request_auth: status_auth.clone(),
        payout_request: payout_request.clone(),
        initial_payout_response: payout_response.clone(),
    }
    .encode()
    .expect("wrong-provider status envelope");
    assert_eq!(
        restarted.payout_status(&wrong_provider_envelope, NOW + 7),
        Err(IssuerServiceErrorV1::Unauthorized)
    );
    let status_response =
        IssuerPayoutStatusResponseV1::decode(&status_bytes).expect("decode status");
    let provider_request_key = fixture.provider_request.verifying_key();
    let registration_expectation = ProviderSettlementRegistrationExpectationV1 {
        registration_digest: &registration.registration_digest,
        provider_id: &PROVIDER_ID,
        issuer_id: &fixture.issuer_id,
        settlement_account_id: &ACCOUNT_ID,
        provider_request_key: &provider_request_key,
        issuer_settlement_key: &settlement_key,
        not_before: registration.not_before,
        not_after: registration.not_after,
        now_unix: NOW + 5,
    };
    let issuer_keyring = IssuerSettlementKeyringExpectationV1 {
        issuer_id: &fixture.issuer_id,
        current_key: &settlement_key,
        retained_keys: &[],
    };
    let status_context = PayoutStatusContextV1 {
        payout_request: &payout_request,
        initial_payout_response: &payout_response,
    };
    let verified_status = verify_new_payout_status_response_for(
        &status_response,
        &status_request,
        &status_context,
        &initial_snapshot,
        &status_auth,
        &registration_expectation,
        &issuer_keyring,
    )
    .expect("verify status response");
    assert_eq!(verified_status.state_version(), 2);

    let current_status_request = ProviderPayoutStatusRequestV1 {
        registration_digest: rotated_registration.value.registration_digest,
        issuer_id: fixture.issuer_id,
        provider_id: PROVIDER_ID,
        account_id: ACCOUNT_ID,
        payout_id: payout_response.payout_id,
        payout_request_digest: payout_request.request_digest().expect("payout digest"),
        request_nonce: [0x56; 32],
    };
    let current_status_auth = ProviderSettlementRequestAuthV1::sign(
        rotated_registration.value.registration_digest,
        current_status_request
            .request_digest()
            .expect("current status digest"),
        &rotated_provider_request,
    );
    let current_status_envelope = ProviderPayoutStatusEnvelopeV1 {
        request: current_status_request,
        request_auth: current_status_auth,
        payout_request: payout_request.clone(),
        initial_payout_response: payout_response.clone(),
    }
    .encode()
    .expect("current status envelope");
    let current_status_bytes = restarted
        .payout_status(&current_status_envelope, NOW + 8)
        .expect("fresh status under current provider registration");
    assert_ne!(current_status_bytes, status_bytes);
    assert_eq!(
        restarted.payout_status(&status_envelope, NOW + 9),
        Err(IssuerServiceErrorV1::Unauthorized)
    );
}
