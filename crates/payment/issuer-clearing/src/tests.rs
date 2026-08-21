use super::*;
use pir_arc_adapter::{ArcSecretKeyV1, ArcSecretKeyringV1, ARC_SECRET_KEY_LEN_V1};
use pir_issuer_store::{
    issuer_payout_outbox_command_id_v1, verify_shared_issuer_redeem_v1, BatKeyLineageRegistration,
    IssuerStore, ProviderSettlementRegistrationWriteV1, SettlementKeyLineageRegistration,
    StoreError, StoreOptions, VerifiedRedeemCommitV1, WriteDisposition,
};
use pir_payment_crypto::{
    blind_cashu_message_v1, cashu_hash_to_curve_v1, verify_and_unblind_cashu_promise_v1,
    K256CashuDleqVerifierV1,
};
use pir_service_protocol::{
    credential_presentation_digest, derive_bat_key_id_v1, derive_cashu_keyset_id_v2,
    derive_issuer_id, verify_new_payout_request_for, verify_new_payout_response_for,
    verify_new_payout_status_response_for, verify_new_settlement_deposit_request_for,
    verify_persisted_payout_snapshot_from_store_record_v1,
    verify_redeem_response_for_exact_request, ArcPresentationV1, CashuDenominationKeyV1,
    CashuKeysetBindingV1, CredentialKeyBindingClaimsV1, CredentialKeyBindingExpectationV1,
    CredentialKeyBindingV1, CredentialUnitV1, IssuerClearingApprovalV1,
    IssuerPayoutIntentResponseV1, IssuerPayoutResponseV1, IssuerPayoutStatusResponseV1,
    IssuerSettlementKeyringExpectationV1, LightningNetworkV1, PayoutCommitErrorV1,
    PayoutExecutionContextV1, PayoutStateV1, PayoutStatusContextV1,
    ProviderClearingAuthorizationClaimsV1, ProviderClearingAuthorizationV1,
    ProviderClearingExpectationV1, ProviderClearingRequestAuthV1, ProviderPayoutIntentRequestV1,
    ProviderPayoutRequestV1, ProviderPayoutStatusRequestV1, ProviderRedeemRequestV1,
    ProviderSettlementRegistrationExpectationV1, ProviderSettlementRequestAuthV1,
    RetainedSettlementKeysetExpectationV1, SettlementModesV1, SettlementNoteV1, SettlementRuleV1,
    SettlementUnitV1, VerifiedPayoutSnapshotV1,
};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use tempfile::TempDir;
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

const NOW: u64 = 1_500;
const PROVIDER_ID: [u8; 32] = [0x31; 32];
const SCOPE_ID: [u8; 32] = [0x32; 32];
const ACCOUNT_ID: [u8; 32] = [0x33; 32];

struct Fixture {
    _directory: TempDir,
    database: PathBuf,
    store: IssuerStore,
    issuer_root: SigningKey,
    operator: SigningKey,
    clearing: SigningKey,
    settlement_signing: SigningKey,
    provider_request: SigningKey,
    bat_keyring: K256CashuMintKeyringV1,
    settlement_keyring: K256CashuMintKeyringV1,
    settlement_keyset: CashuKeysetBindingV1,
    binding: CredentialKeyBindingV1,
    authorization: ProviderClearingAuthorizationV1,
    approval: IssuerClearingApprovalV1,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::Builder::new()
            .prefix("bitcoinpir-issuer-clearing-test-")
            .tempdir()
            .expect("create test directory");
        #[cfg(unix)]
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("restrict test directory permissions");
        let database = directory.path().join("issuer.sqlite3");
        let issuer_root = SigningKey::from_bytes(&[0x21; 32]);
        let issuer_id = derive_issuer_id(&issuer_root.verifying_key().to_bytes());
        let store = IssuerStore::create(
            &database,
            [0x11; 16],
            issuer_id,
            LightningNetworkV1::Regtest,
            StoreOptions::default(),
        )
        .expect("create issuer store");

        let provider_request = SigningKey::from_bytes(&[0x22; 32]);
        let _provider_registration = store
            .register_provider_settlement(&ProviderSettlementRegistrationWriteV1 {
                registration_epoch: 1,
                provider_id: PROVIDER_ID,
                settlement_account_id: ACCOUNT_ID,
                provider_request_verifying_key: provider_request.verifying_key().to_bytes(),
                payout_target_id: [0x34; 32],
                not_before: 1_000,
                not_after: 5_000,
            })
            .expect("register provider settlement");

        let bat_keyring =
            K256CashuMintKeyringV1::from_secret_keys([[0x07; 32]]).expect("create BAT keyring");
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
        .expect("sign BAT binding");
        let _bat_lineage = store
            .register_bat_key_lineage(&BatKeyLineageRegistration {
                raw_public_key: bat_public_key,
                provider_id: PROVIDER_ID,
                scope_id: SCOPE_ID,
                offer_id: 7,
                entitlement_profile: 9,
                keyset_epoch: 1,
                credential_key_id,
            })
            .expect("register BAT lineage");

        let settlement_keyring = K256CashuMintKeyringV1::from_secret_keys([[0x09; 32]])
            .expect("create settlement keyring");
        let settlement_keys = vec![CashuDenominationKeyV1 {
            amount: 9,
            public_key: settlement_keyring.denomination_public_keys()[0],
        }];
        let settlement_keyset = CashuKeysetBindingV1 {
            keyset_id: derive_cashu_keyset_id_v2(&settlement_keys, "auth", 0, Some(7_000))
                .expect("derive keyset id"),
            unit: "auth".to_owned(),
            input_fee_ppk: 0,
            final_expiry: Some(7_000),
            keys: settlement_keys,
        };
        let _settlement_lineage = store
            .register_settlement_key_lineage(&SettlementKeyLineageRegistration {
                raw_public_key: settlement_keyset.keys[0].public_key,
                keyset_id: settlement_keyset.keyset_id.clone(),
                unit: settlement_keyset.unit.clone(),
                keyset_epoch: 1,
                denomination: settlement_keyset.keys[0].amount,
                manifest_digest: [0x36; 32],
                final_expiry: settlement_keyset.final_expiry,
            })
            .expect("register settlement key lineage");
        let operator = SigningKey::from_bytes(&[0x23; 32]);
        let clearing = SigningKey::from_bytes(&[0x24; 32]);
        let settlement_signing = SigningKey::from_bytes(&[0x25; 32]);
        let authorization = ProviderClearingAuthorizationV1::sign(
            ProviderClearingAuthorizationClaimsV1 {
                authorization_id: [0x35; 16],
                authorization_epoch: 1,
                provider_id: PROVIDER_ID,
                issuer_id,
                redeem_endpoint: "https://issuer.example".to_owned(),
                redeem_leaf_spki_sha256_pins: vec![[0x41; 32]],
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
                        SettlementModesV1::LEDGER_CREDIT | SettlementModesV1::BLIND_OUTPUTS,
                    )
                    .expect("settlement modes"),
                    blind_output_minimum_validity_seconds: 1_000,
                    blind_output_keyset: Some(settlement_keyset.clone()),
                }],
            },
            &operator,
        )
        .expect("sign clearing authorization");
        let approval =
            IssuerClearingApprovalV1::sign(&authorization, 1_000, 5_000, &settlement_signing)
                .expect("sign issuer approval");
        let _clearing_authorization = store
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
            database,
            store,
            issuer_root,
            operator,
            clearing,
            settlement_signing,
            provider_request,
            bat_keyring,
            settlement_keyring,
            settlement_keyset,
            binding,
            authorization,
            approval,
        }
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
        .expect("encode BAT proof")
        .to_vec()
    }

    fn request(
        &self,
        idempotency_byte: u8,
        destination: SettlementDestinationV1,
    ) -> ProviderRedeemRequestV1 {
        let credential = self.credential();
        ProviderRedeemRequestV1 {
            authorization_digest: self
                .authorization
                .authorization_digest()
                .expect("authorization digest"),
            issuer_id: self.binding.issuer_id,
            provider_id: PROVIDER_ID,
            scope_id: SCOPE_ID,
            offer_id: 7,
            credential_binding_digest: self.binding.binding_digest().expect("binding digest"),
            scheme: AuthScheme::BitcoinPirCashuBatV1,
            credential_digest: credential_presentation_digest(
                AuthScheme::BitcoinPirCashuBatV1,
                &credential,
            )
            .expect("credential digest"),
            accepted_value: 10,
            denomination_profile: 1,
            idempotency_key: [idempotency_byte; 32],
            destination,
        }
    }

    fn verify_redeem<'a>(
        &'a self,
        request: &'a ProviderRedeemRequestV1,
    ) -> pir_issuer_store::VerifiedSharedIssuerRedeemV1<'a> {
        let credential = self.credential();
        let request_auth = ProviderClearingRequestAuthV1::sign(
            request.authorization_digest,
            request.request_digest().expect("request digest"),
            &self.clearing,
        );
        let verifier = SharedIssuerCredentialVerifierV1::new(Some(&self.bat_keyring), None);
        let operator_key = self.operator.verifying_key();
        let settlement_key = self.settlement_signing.verifying_key();
        let expectation = ProviderClearingExpectationV1 {
            provider_id: &PROVIDER_ID,
            issuer_id: &self.binding.issuer_id,
            operator_key: &operator_key,
            issuer_settlement_key: &settlement_key,
            now_unix: NOW,
            minimum_authorization_epoch: 1,
        };
        verify_shared_issuer_redeem_v1(
            request,
            &credential,
            &self.binding,
            &self.authorization,
            &self.approval,
            &request_auth,
            &expectation,
            &verifier,
        )
        .expect("verify shared issuer redeem")
    }

    fn commit(
        &self,
        request: &ProviderRedeemRequestV1,
    ) -> Result<pir_issuer_store::DurableWrite<pir_issuer_store::RedeemRecordV1>, StoreError> {
        let verified = self.verify_redeem(request);
        let response = prepare_redeem_response_v1(
            &verified,
            &self.settlement_signing,
            Some(&self.settlement_keyring),
            &RedeemResponseDerivationKeyV1::from_bytes([0x46; 32])
                .expect("response derivation key"),
        )
        .expect("prepare response");
        let retained_keysets = [self.settlement_keyset.clone()];
        let retained = RetainedSettlementKeysetExpectationV1 {
            issuer_id: &self.binding.issuer_id,
            retained_keysets: &retained_keysets,
            now_unix: NOW,
        };
        let verified_response = verify_redeem_response_for_exact_request(
            &response,
            request,
            &self.authorization,
            &self.settlement_signing.verifying_key(),
            &retained,
            &K256CashuDleqVerifierV1,
        )
        .expect("verify prepared response");
        self.store.commit_redeem(&VerifiedRedeemCommitV1 {
            redeem: verified,
            response: verified_response,
        })
    }
}

struct AcceptedPayout {
    intent_request: ProviderPayoutIntentRequestV1,
    intent_response: IssuerPayoutIntentResponseV1,
    request: ProviderPayoutRequestV1,
    response: IssuerPayoutResponseV1,
    snapshot: VerifiedPayoutSnapshotV1,
}

fn accept_funded_payout(fixture: &Fixture, idempotency_byte: u8) -> AcceptedPayout {
    let funding_request = fixture.request(
        idempotency_byte,
        SettlementDestinationV1::LedgerCredit {
            account_id: ACCOUNT_ID,
        },
    );
    let _funding = fixture
        .commit(&funding_request)
        .expect("fund provider payout balance");
    let authorization_digest = fixture
        .authorization
        .authorization_digest()
        .expect("authorization digest");
    let intent_request = ProviderPayoutIntentRequestV1 {
        authorization_digest,
        issuer_id: fixture.binding.issuer_id,
        provider_id: PROVIDER_ID,
        account_id: ACCOUNT_ID,
        payout_target_id: [0x34; 32],
        unit: SettlementUnitV1::AuthCredit,
        payout_value: 7,
        idempotency_key: [idempotency_byte.wrapping_add(1); 32],
    };
    let intent_auth = ProviderClearingRequestAuthV1::sign(
        authorization_digest,
        intent_request.request_digest().expect("intent digest"),
        &fixture.clearing,
    );
    let operator_key = fixture.operator.verifying_key();
    let settlement_key = fixture.settlement_signing.verifying_key();
    let expectation = ProviderClearingExpectationV1 {
        provider_id: &PROVIDER_ID,
        issuer_id: &fixture.binding.issuer_id,
        operator_key: &operator_key,
        issuer_settlement_key: &settlement_key,
        now_unix: NOW,
        minimum_authorization_epoch: 1,
    };
    let intent_response = prepare_payout_intent_response_v1(
        &intent_request,
        2,
        NOW + 100,
        &fixture.settlement_signing,
    )
    .expect("prepare payout intent");
    let committed_intent = fixture
        .store
        .commit_payout_intent(
            &intent_request,
            &intent_response,
            &fixture.authorization,
            &fixture.approval,
            &intent_auth,
            &expectation,
        )
        .expect("commit payout intent");
    assert_eq!(committed_intent.disposition, WriteDisposition::Committed);

    let request = ProviderPayoutRequestV1 {
        authorization_digest,
        issuer_id: fixture.binding.issuer_id,
        provider_id: PROVIDER_ID,
        account_id: ACCOUNT_ID,
        payout_target_id: [0x34; 32],
        payout_intent_id: intent_response.payout_intent_id,
        payout_intent_digest: intent_response
            .payout_intent_digest()
            .expect("payout intent digest"),
        unit: SettlementUnitV1::AuthCredit,
        payout_value: 7,
        total_debit: 9,
        idempotency_key: [idempotency_byte.wrapping_add(2); 32],
    };
    let request_auth = ProviderClearingRequestAuthV1::sign(
        authorization_digest,
        request.request_digest().expect("payout request digest"),
        &fixture.clearing,
    );
    let context = PayoutExecutionContextV1 {
        intent_request: &intent_request,
        intent_response: &intent_response,
        registered_payout_target_id: &[0x34; 32],
    };
    let execution = verify_new_payout_request_for(
        &request,
        &context,
        &fixture.authorization,
        &fixture.approval,
        &request_auth,
        &expectation,
    )
    .expect("verify payout request");
    let mut committer = fixture.store.payout_execution_committer(&settlement_key);
    let response = sign_and_commit_payout_execution_v1(
        &execution,
        NOW + 1,
        &fixture.settlement_signing,
        &mut committer,
    )
    .expect("sign and commit payout");
    let snapshot = verify_new_payout_response_for(
        &response,
        &request,
        &context,
        &fixture.authorization,
        &fixture.approval,
        &request_auth,
        &expectation,
    )
    .expect("verify initial payout response");
    AcceptedPayout {
        intent_request,
        intent_response,
        request,
        response,
        snapshot,
    }
}

fn advance_payout_status(
    fixture: &Fixture,
    store: &IssuerStore,
    payout: &AcceptedPayout,
    previous: &VerifiedPayoutSnapshotV1,
    next_state: PayoutStateV1,
    nonce: u8,
    updated_at: u64,
) -> (IssuerPayoutStatusResponseV1, VerifiedPayoutSnapshotV1) {
    let registration = store
        .provider_settlement_registration(&PROVIDER_ID)
        .expect("read provider registration")
        .expect("provider registration exists");
    let request = ProviderPayoutStatusRequestV1 {
        registration_digest: registration.registration_digest,
        issuer_id: fixture.binding.issuer_id,
        provider_id: PROVIDER_ID,
        account_id: ACCOUNT_ID,
        payout_id: payout.response.payout_id,
        payout_request_digest: payout.request.request_digest().expect("payout digest"),
        request_nonce: [nonce; 32],
    };
    let request_auth = ProviderSettlementRequestAuthV1::sign(
        registration.registration_digest,
        request.request_digest().expect("status request digest"),
        &fixture.provider_request,
    );
    let settlement_key = fixture.settlement_signing.verifying_key();
    let provider_key = fixture.provider_request.verifying_key();
    let registration_expectation = ProviderSettlementRegistrationExpectationV1 {
        registration_digest: &registration.registration_digest,
        provider_id: &PROVIDER_ID,
        issuer_id: &fixture.binding.issuer_id,
        settlement_account_id: &ACCOUNT_ID,
        provider_request_key: &provider_key,
        issuer_settlement_key: &settlement_key,
        not_before: registration.not_before,
        not_after: registration.not_after,
        now_unix: updated_at,
    };
    let keyring = IssuerSettlementKeyringExpectationV1 {
        issuer_id: &fixture.binding.issuer_id,
        current_key: &settlement_key,
        retained_keys: &[],
    };
    let mut committer = store.payout_status_committer(&settlement_key);
    let response = sign_and_commit_payout_status_v1(
        &request,
        &payout.response,
        previous,
        next_state,
        updated_at,
        &fixture.settlement_signing,
        &mut committer,
    )
    .expect("commit payout status");
    let context = PayoutStatusContextV1 {
        payout_request: &payout.request,
        initial_payout_response: &payout.response,
    };
    let snapshot = verify_new_payout_status_response_for(
        &response,
        &request,
        &context,
        previous,
        &request_auth,
        &registration_expectation,
        &keyring,
    )
    .expect("verify payout status");
    (response, snapshot)
}

#[test]
fn bat_ledger_redeem_is_atomic_idempotent_and_restart_safe() {
    let fixture = Fixture::new();
    let request = fixture.request(
        0x51,
        SettlementDestinationV1::LedgerCredit {
            account_id: ACCOUNT_ID,
        },
    );
    let first = fixture.commit(&request).expect("commit ledger redeem");
    assert_eq!(first.disposition, WriteDisposition::Committed);
    assert_eq!(first.value.provider_credit, 9);
    let recovered = fixture
        .store
        .redeem_by_idempotency(&request)
        .expect("recover redeem")
        .expect("redeem exists");
    assert_eq!(recovered.exact_response, first.value.exact_response);
    let replay = fixture.commit(&request).expect("exact replay");
    assert_eq!(replay.disposition, WriteDisposition::ExactReplay);
    assert_eq!(replay.value.exact_response, first.value.exact_response);
    let balance = fixture
        .store
        .provider_ledger_balance(&PROVIDER_ID)
        .expect("read balance")
        .expect("balance exists");
    assert_eq!(balance.available_value, 9);
    assert_eq!(balance.reserved_value, 0);
    assert_eq!(balance.ledger_sequence, 1);

    let reopened = IssuerStore::open_existing(
        &fixture.database,
        fixture.binding.issuer_id,
        LightningNetworkV1::Regtest,
        StoreOptions::default(),
    )
    .expect("reopen issuer store");
    assert_eq!(
        reopened
            .redeem_by_idempotency(&request)
            .expect("restart recovery")
            .expect("restart redeem")
            .exact_response,
        first.value.exact_response,
    );
}

#[test]
fn same_bat_under_new_idempotency_is_spent_and_parallel_race_has_one_winner() {
    let fixture = Arc::new(Fixture::new());
    let barrier = Arc::new(Barrier::new(8));
    let mut threads = Vec::new();
    for index in 0..8u8 {
        let fixture = fixture.clone();
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || {
            let request = fixture.request(
                0x60 + index,
                SettlementDestinationV1::LedgerCredit {
                    account_id: ACCOUNT_ID,
                },
            );
            barrier.wait();
            fixture.commit(&request)
        }));
    }
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().expect("join redeem thread"))
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(StoreError::CredentialAlreadySpent)))
            .count(),
        7,
    );
    let balance = fixture
        .store
        .provider_ledger_balance(&PROVIDER_ID)
        .expect("read balance")
        .expect("balance exists");
    assert_eq!(balance.available_value, 9);
    assert_eq!(balance.ledger_sequence, 1);
}

#[test]
fn blind_settlement_response_is_deterministic_and_ledger_conserves_value() {
    let fixture = Fixture::new();
    let blinded_message = blind_cashu_message_v1(b"provider settlement", &[0x52; 32])
        .expect("blind settlement message");
    let request = fixture.request(
        0x53,
        SettlementDestinationV1::BlindOutputs {
            settlement_keyset_id: fixture.settlement_keyset.keyset_id.clone(),
            outputs: vec![pir_service_protocol::BlindSettlementOutputV1 {
                denomination: 9,
                blinded_message,
            }],
        },
    );
    let verified = fixture.verify_redeem(&request);
    let derivation =
        RedeemResponseDerivationKeyV1::from_bytes([0x46; 32]).expect("response derivation key");
    let first = prepare_redeem_response_v1(
        &verified,
        &fixture.settlement_signing,
        Some(&fixture.settlement_keyring),
        &derivation,
    )
    .expect("first blind response");
    let second = prepare_redeem_response_v1(
        &verified,
        &fixture.settlement_signing,
        Some(&fixture.settlement_keyring),
        &derivation,
    )
    .expect("second blind response");
    assert_eq!(first, second);
    let committed = fixture.commit(&request).expect("commit blind redeem");
    assert_eq!(committed.disposition, WriteDisposition::Committed);
    let balance = fixture
        .store
        .provider_ledger_balance(&PROVIDER_ID)
        .expect("read balance")
        .expect("balance exists");
    assert_eq!(balance.available_value, 0);
    assert_eq!(balance.ledger_sequence, 0);

    let connection = rusqlite::Connection::open(&fixture.database).expect("open ledger database");
    let unbalanced: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM (SELECT transaction_id, SUM(signed_amount) AS total \
             FROM ledger_postings GROUP BY transaction_id HAVING total != 0)",
            [],
            |row| row.get(0),
        )
        .expect("query ledger conservation");
    assert_eq!(unbalanced, 0);
}

#[test]
fn blind_note_deposit_is_atomic_idempotent_and_cannot_be_credited_twice() {
    let fixture = Fixture::new();
    let note_secret = "provider settlement note".to_owned();
    let blinding_scalar = [0x52; 32];
    let blinded_message = blind_cashu_message_v1(note_secret.as_bytes(), &blinding_scalar)
        .expect("blind settlement message");
    let redeem_request = fixture.request(
        0x72,
        SettlementDestinationV1::BlindOutputs {
            settlement_keyset_id: fixture.settlement_keyset.keyset_id.clone(),
            outputs: vec![pir_service_protocol::BlindSettlementOutputV1 {
                denomination: 9,
                blinded_message,
            }],
        },
    );
    let redeemed = fixture
        .commit(&redeem_request)
        .expect("commit blind settlement redeem");
    let redeem_response = ProviderRedeemResponseV1::decode(&redeemed.value.exact_response)
        .expect("decode blind settlement response");
    let promise = match &redeem_response.result {
        RedeemSettlementResultV1::BlindOutputs { signatures, .. } => &signatures[0],
        RedeemSettlementResultV1::LedgerCredit { .. } => panic!("expected blind response"),
    };
    let denomination_public_key = fixture.settlement_keyset.keys[0].public_key;
    let unblinded = verify_and_unblind_cashu_promise_v1(
        note_secret.as_bytes(),
        &blinding_scalar,
        &denomination_public_key,
        &promise.blinded_message,
        &promise.blinded_signature,
        &promise.dleq_e,
        &promise.dleq_s,
    )
    .expect("verify and unblind settlement promise");
    let note = SettlementNoteV1::new(
        &fixture.settlement_keyset.keyset_id,
        9,
        note_secret,
        *unblinded.unblinded_signature(),
        None,
    )
    .expect("construct settlement note");
    let registration = fixture
        .store
        .provider_settlement_registration(&PROVIDER_ID)
        .expect("read provider registration")
        .expect("provider registration exists");
    let make_request =
        |idempotency_byte| pir_service_protocol::ProviderSettlementDepositRequestV1 {
            registration_digest: registration.registration_digest,
            issuer_id: fixture.binding.issuer_id,
            provider_id: PROVIDER_ID,
            account_id: ACCOUNT_ID,
            unit: SettlementUnitV1::AuthCredit,
            settlement_keyset_id: fixture.settlement_keyset.keyset_id.clone(),
            notes: vec![note.clone()],
            total_value: 9,
            idempotency_key: [idempotency_byte; 32],
        };
    let request = make_request(0x73);
    let request_auth = ProviderSettlementRequestAuthV1::sign(
        registration.registration_digest,
        request.request_digest().expect("deposit request digest"),
        &fixture.provider_request,
    );
    let provider_request_key = fixture.provider_request.verifying_key();
    let issuer_settlement_key = fixture.settlement_signing.verifying_key();
    let registration_expectation = ProviderSettlementRegistrationExpectationV1 {
        registration_digest: &registration.registration_digest,
        provider_id: &PROVIDER_ID,
        issuer_id: &fixture.binding.issuer_id,
        settlement_account_id: &ACCOUNT_ID,
        provider_request_key: &provider_request_key,
        issuer_settlement_key: &issuer_settlement_key,
        not_before: registration.not_before,
        not_after: registration.not_after,
        now_unix: NOW,
    };
    let retained_keysets = [fixture.settlement_keyset.clone()];
    let retained = RetainedSettlementKeysetExpectationV1 {
        issuer_id: &fixture.binding.issuer_id,
        retained_keysets: &retained_keysets,
        now_unix: NOW,
    };
    let verified = verify_new_settlement_deposit_request_for(
        &request,
        &request_auth,
        &registration_expectation,
        &retained,
        &fixture.settlement_keyring,
    )
    .expect("verify settlement deposit");
    let response =
        prepare_settlement_deposit_response_v1(&verified, 1, &fixture.settlement_signing)
            .expect("prepare deposit response");
    let first = fixture
        .store
        .commit_settlement_deposit(&verified, &response, &issuer_settlement_key, NOW)
        .expect("commit settlement deposit");
    assert_eq!(first.disposition, WriteDisposition::Committed);
    let replay = fixture
        .store
        .commit_settlement_deposit(&verified, &response, &issuer_settlement_key, NOW + 1)
        .expect("replay settlement deposit");
    assert_eq!(replay.disposition, WriteDisposition::ExactReplay);
    assert_eq!(replay.value.exact_response, first.value.exact_response);

    let second_request = make_request(0x74);
    let second_auth = ProviderSettlementRequestAuthV1::sign(
        registration.registration_digest,
        second_request
            .request_digest()
            .expect("second deposit request digest"),
        &fixture.provider_request,
    );
    let second_verified = verify_new_settlement_deposit_request_for(
        &second_request,
        &second_auth,
        &registration_expectation,
        &retained,
        &fixture.settlement_keyring,
    )
    .expect("verify repeated settlement note");
    let second_response =
        prepare_settlement_deposit_response_v1(&second_verified, 2, &fixture.settlement_signing)
            .expect("prepare repeated deposit response");
    assert!(matches!(
        fixture.store.commit_settlement_deposit(
            &second_verified,
            &second_response,
            &issuer_settlement_key,
            NOW + 1,
        ),
        Err(StoreError::SettlementNoteAlreadySpent)
    ));
    let balance = fixture
        .store
        .provider_ledger_balance(&PROVIDER_ID)
        .expect("read balance")
        .expect("balance exists");
    assert_eq!(balance.available_value, 9);
    assert_eq!(balance.ledger_sequence, 1);
}

#[test]
fn invalid_bat_fails_before_any_store_mutation() {
    let fixture = Fixture::new();
    let request = fixture.request(
        0x71,
        SettlementDestinationV1::LedgerCredit {
            account_id: ACCOUNT_ID,
        },
    );
    let before = fixture
        .store
        .identity()
        .expect("identity before")
        .commit_seq;
    let mut credential = fixture.credential();
    let last = credential.len() - 1;
    credential[last] ^= 1;
    let request_auth = ProviderClearingRequestAuthV1::sign(
        request.authorization_digest,
        request.request_digest().expect("request digest"),
        &fixture.clearing,
    );
    let verifier = SharedIssuerCredentialVerifierV1::new(Some(&fixture.bat_keyring), None);
    let operator_key = fixture.operator.verifying_key();
    let settlement_key = fixture.settlement_signing.verifying_key();
    let expectation = ProviderClearingExpectationV1 {
        provider_id: &PROVIDER_ID,
        issuer_id: &fixture.binding.issuer_id,
        operator_key: &operator_key,
        issuer_settlement_key: &settlement_key,
        now_unix: NOW,
        minimum_authorization_epoch: 1,
    };
    assert!(verify_shared_issuer_redeem_v1(
        &request,
        &credential,
        &fixture.binding,
        &fixture.authorization,
        &fixture.approval,
        &request_auth,
        &expectation,
        &verifier,
    )
    .is_err());
    assert_eq!(
        fixture.store.identity().expect("identity after").commit_seq,
        before,
    );
}

#[test]
fn payout_reservation_outbox_restart_and_success_are_atomic() {
    let fixture = Fixture::new();
    let payout = accept_funded_payout(&fixture, 0x80);
    assert_eq!(
        payout.intent_response.payout_intent_id,
        payout.request.payout_intent_id
    );
    assert_eq!(
        fixture
            .store
            .payout_intent_by_idempotency(&payout.intent_request)
            .expect("recover payout intent")
            .expect("payout intent exists")
            .consumed_by_payout_id,
        Some(payout.response.payout_id)
    );
    let reserved = fixture
        .store
        .provider_ledger_balance(&PROVIDER_ID)
        .expect("read reserved balance")
        .expect("balance exists");
    assert_eq!((reserved.available_value, reserved.reserved_value), (0, 9));

    let reopened = IssuerStore::open_existing(
        &fixture.database,
        fixture.binding.issuer_id,
        LightningNetworkV1::Regtest,
        StoreOptions::default(),
    )
    .expect("reopen issuer before outbox claim");
    let first_claim = reopened
        .claim_next_payout_outbox(&[0x81; 32], NOW + 2, 10)
        .expect("claim payout outbox")
        .expect("outbox command exists");
    assert_eq!(first_claim.value.payout_id, payout.response.payout_id);
    assert_eq!(first_claim.value.attempt_count, 1);
    assert!(reopened
        .claim_next_payout_outbox(&[0x82; 32], NOW + 5, 10)
        .expect("unexpired lease check")
        .is_none());
    let recovered_claim = reopened
        .claim_next_payout_outbox(&[0x82; 32], NOW + 13, 10)
        .expect("reclaim expired lease")
        .expect("expired lease is recoverable");
    assert_eq!(recovered_claim.value.attempt_count, 2);

    let (_, in_flight) = advance_payout_status(
        &fixture,
        &reopened,
        &payout,
        &payout.snapshot,
        PayoutStateV1::InFlight,
        0x83,
        NOW + 14,
    );
    let (_, succeeded) = advance_payout_status(
        &fixture,
        &reopened,
        &payout,
        &in_flight,
        PayoutStateV1::Succeeded,
        0x84,
        NOW + 15,
    );
    assert_eq!(succeeded.state(), PayoutStateV1::Succeeded);
    let balance = reopened
        .provider_ledger_balance(&PROVIDER_ID)
        .expect("read settled balance")
        .expect("balance exists");
    assert_eq!((balance.available_value, balance.reserved_value), (0, 0));
    assert!(reopened
        .claim_next_payout_outbox(&[0x85; 32], NOW + 30, 10)
        .expect("completed outbox check")
        .is_none());
    let record = reopened
        .payout_by_id(&payout.response.payout_id)
        .expect("read payout")
        .expect("payout exists");
    assert_eq!(record.state, PayoutStateV1::Succeeded);
    assert!(record.terminal_ledger_transaction_id.is_some());

    let connection = rusqlite::Connection::open(&fixture.database).expect("open payout ledger");
    let unbalanced: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM (SELECT transaction_id, SUM(signed_amount) AS total \
             FROM ledger_postings GROUP BY transaction_id HAVING total != 0)",
            [],
            |row| row.get(0),
        )
        .expect("check payout ledger conservation");
    assert_eq!(unbalanced, 0);
}

#[test]
fn failed_payout_restores_balance_and_terminal_cas_has_one_winner() {
    let fixture = Fixture::new();
    let payout = accept_funded_payout(&fixture, 0x90);
    let _claim = fixture
        .store
        .claim_next_payout_outbox(&[0x91; 32], NOW + 2, 20)
        .expect("claim payout outbox")
        .expect("outbox command exists");
    let (_, in_flight) = advance_payout_status(
        &fixture,
        &fixture.store,
        &payout,
        &payout.snapshot,
        PayoutStateV1::InFlight,
        0x92,
        NOW + 3,
    );

    let registration = fixture
        .store
        .provider_settlement_registration(&PROVIDER_ID)
        .expect("read provider registration")
        .expect("provider registration exists");
    let loser_request = ProviderPayoutStatusRequestV1 {
        registration_digest: registration.registration_digest,
        issuer_id: fixture.binding.issuer_id,
        provider_id: PROVIDER_ID,
        account_id: ACCOUNT_ID,
        payout_id: payout.response.payout_id,
        payout_request_digest: payout.request.request_digest().expect("payout digest"),
        request_nonce: [0x93; 32],
    };
    let (_, failed) = advance_payout_status(
        &fixture,
        &fixture.store,
        &payout,
        &in_flight,
        PayoutStateV1::Failed,
        0x94,
        NOW + 4,
    );
    assert_eq!(failed.state(), PayoutStateV1::Failed);

    let settlement_key = fixture.settlement_signing.verifying_key();
    let mut losing_committer = fixture.store.payout_status_committer(&settlement_key);
    let losing = sign_and_commit_payout_status_v1(
        &loser_request,
        &payout.response,
        &in_flight,
        PayoutStateV1::Succeeded,
        NOW + 5,
        &fixture.settlement_signing,
        &mut losing_committer,
    );
    assert!(matches!(
        losing,
        Err(PayoutCommitErrorV1::Conflict {
            operation: "payout_status_compare_and_swap"
        })
    ));
    let balance = fixture
        .store
        .provider_ledger_balance(&PROVIDER_ID)
        .expect("read restored balance")
        .expect("balance exists");
    assert_eq!((balance.available_value, balance.reserved_value), (9, 0));
    let payout_record = fixture
        .store
        .payout_by_id(&payout.response.payout_id)
        .expect("read failed payout")
        .expect("failed payout exists");
    assert_eq!(payout_record.state, PayoutStateV1::Failed);
}

#[derive(Debug)]
struct ScriptedPayoutExecutorV1 {
    readiness: ExternalPayoutReadinessV1,
    submit_results: VecDeque<ExternalPayoutCallResultV1>,
    reconcile_results: VecDeque<ExternalPayoutCallResultV1>,
    submit_calls: usize,
    reconcile_calls: usize,
    command_ids: Vec<[u8; 32]>,
    execution_contexts: Vec<ExternalPayoutExecutionContextV1>,
}

impl ScriptedPayoutExecutorV1 {
    fn ready(
        submit_outcomes: impl IntoIterator<Item = ExternalPayoutOutcomeV1>,
        reconcile_outcomes: impl IntoIterator<Item = ExternalPayoutOutcomeV1>,
    ) -> Self {
        Self {
            readiness: ExternalPayoutReadinessV1::Ready,
            submit_results: submit_outcomes
                .into_iter()
                .map(ExternalPayoutCallResultV1::Completed)
                .collect(),
            reconcile_results: reconcile_outcomes
                .into_iter()
                .map(ExternalPayoutCallResultV1::Completed)
                .collect(),
            submit_calls: 0,
            reconcile_calls: 0,
            command_ids: Vec::new(),
            execution_contexts: Vec::new(),
        }
    }

    fn ready_call_results(
        submit_results: impl IntoIterator<Item = ExternalPayoutCallResultV1>,
        reconcile_results: impl IntoIterator<Item = ExternalPayoutCallResultV1>,
    ) -> Self {
        Self {
            readiness: ExternalPayoutReadinessV1::Ready,
            submit_results: submit_results.into_iter().collect(),
            reconcile_results: reconcile_results.into_iter().collect(),
            submit_calls: 0,
            reconcile_calls: 0,
            command_ids: Vec::new(),
            execution_contexts: Vec::new(),
        }
    }
}

impl ExternalPayoutExecutorV1 for ScriptedPayoutExecutorV1 {
    fn readiness(&self) -> ExternalPayoutReadinessV1 {
        self.readiness
    }

    fn submit_once(
        &mut self,
        command: &ExternalPayoutCommandV1,
        context: ExternalPayoutExecutionContextV1,
    ) -> ExternalPayoutCallResultV1 {
        self.submit_calls += 1;
        self.command_ids.push(command.command_id);
        self.execution_contexts.push(context);
        self.submit_results
            .pop_front()
            .unwrap_or(ExternalPayoutCallResultV1::TimedOut)
    }

    fn reconcile(
        &mut self,
        command: &ExternalPayoutCommandV1,
        context: ExternalPayoutExecutionContextV1,
    ) -> ExternalPayoutCallResultV1 {
        self.reconcile_calls += 1;
        self.command_ids.push(command.command_id);
        self.execution_contexts.push(context);
        self.reconcile_results
            .pop_front()
            .unwrap_or(ExternalPayoutCallResultV1::TimedOut)
    }
}

#[derive(Debug)]
struct ScriptedPayoutClockV1(VecDeque<u64>);

impl ScriptedPayoutClockV1 {
    fn new(values: impl IntoIterator<Item = u64>) -> Self {
        Self(values.into_iter().collect())
    }
}

impl PayoutWorkerClockV1 for ScriptedPayoutClockV1 {
    fn now_unix(&mut self) -> Option<u64> {
        self.0.pop_front()
    }
}

fn persisted_payout_snapshot(
    fixture: &Fixture,
    payout: &AcceptedPayout,
) -> VerifiedPayoutSnapshotV1 {
    let record = fixture
        .store
        .payout_by_id(&payout.response.payout_id)
        .expect("read payout snapshot")
        .expect("payout exists");
    let initial = IssuerPayoutResponseV1::decode(&record.exact_initial_response)
        .expect("decode initial payout snapshot");
    let latest = record
        .exact_latest_status_response
        .as_deref()
        .map(IssuerPayoutStatusResponseV1::decode)
        .transpose()
        .expect("decode latest payout snapshot");
    let settlement_key = fixture.settlement_signing.verifying_key();
    verify_persisted_payout_snapshot_from_store_record_v1(
        &record.request_digest,
        &initial,
        latest.as_ref(),
        &IssuerSettlementKeyringExpectationV1 {
            issuer_id: &fixture.binding.issuer_id,
            current_key: &settlement_key,
            retained_keys: &[],
        },
    )
    .expect("verify persisted payout snapshot")
}

struct TerminalCasRaceClockV1<'a> {
    fixture: &'a Fixture,
    payout: &'a AcceptedPayout,
    previous: VerifiedPayoutSnapshotV1,
    winner: PayoutStateV1,
    tamper_winner_signature: bool,
    calls: u8,
}

impl PayoutWorkerClockV1 for TerminalCasRaceClockV1<'_> {
    fn now_unix(&mut self) -> Option<u64> {
        self.calls = self.calls.saturating_add(1);
        match self.calls {
            1 => Some(NOW + 20),
            2 => {
                let (_, winner) = advance_payout_status(
                    self.fixture,
                    &self.fixture.store,
                    self.payout,
                    &self.previous,
                    self.winner,
                    0xd1,
                    NOW + 21,
                );
                assert_eq!(winner.state(), self.winner);
                if self.tamper_winner_signature {
                    tamper_latest_payout_signature(self.fixture, self.payout);
                }
                Some(NOW + 22)
            }
            _ => None,
        }
    }
}

fn tamper_initial_payout_signature(fixture: &Fixture, payout: &AcceptedPayout) {
    let connection = rusqlite::Connection::open(&fixture.database).expect("open payout database");
    let exact: Vec<u8> = connection
        .query_row(
            "SELECT exact_initial_response FROM payouts WHERE payout_id = ?1",
            rusqlite::params![payout.response.payout_id.as_slice()],
            |row| row.get(0),
        )
        .expect("read exact initial payout response");
    let mut response =
        IssuerPayoutResponseV1::decode(&exact).expect("decode exact initial payout response");
    response.signature[0] ^= 1;
    let tampered = response
        .encode()
        .expect("encode tampered initial payout response");
    assert_eq!(
        connection
            .execute(
                "UPDATE payouts SET exact_initial_response = ?1 WHERE payout_id = ?2",
                rusqlite::params![tampered, payout.response.payout_id.as_slice()],
            )
            .expect("tamper initial payout signature"),
        1
    );
}

fn tamper_latest_payout_signature(fixture: &Fixture, payout: &AcceptedPayout) {
    let connection = rusqlite::Connection::open(&fixture.database).expect("open payout database");
    let exact: Vec<u8> = connection
        .query_row(
            "SELECT exact_latest_status_response FROM payouts WHERE payout_id = ?1",
            rusqlite::params![payout.response.payout_id.as_slice()],
            |row| row.get(0),
        )
        .expect("read exact latest payout response");
    let mut response =
        IssuerPayoutStatusResponseV1::decode(&exact).expect("decode exact latest payout response");
    response.signature[0] ^= 1;
    let tampered = response
        .encode()
        .expect("encode tampered latest payout response");
    assert_eq!(
        connection
            .execute(
                "UPDATE payouts SET exact_latest_status_response = ?1 WHERE payout_id = ?2",
                rusqlite::params![tampered, payout.response.payout_id.as_slice()],
            )
            .expect("tamper latest payout signature"),
        1
    );
}

struct TamperingTerminalPayoutExecutorV1<'a> {
    fixture: &'a Fixture,
    payout: &'a AcceptedPayout,
    previous: VerifiedPayoutSnapshotV1,
    submit_calls: usize,
    reconcile_calls: usize,
}

impl ExternalPayoutExecutorV1 for TamperingTerminalPayoutExecutorV1<'_> {
    fn readiness(&self) -> ExternalPayoutReadinessV1 {
        ExternalPayoutReadinessV1::Ready
    }

    fn submit_once(
        &mut self,
        _command: &ExternalPayoutCommandV1,
        _context: ExternalPayoutExecutionContextV1,
    ) -> ExternalPayoutCallResultV1 {
        self.submit_calls += 1;
        ExternalPayoutCallResultV1::Completed(ExternalPayoutOutcomeV1::Succeeded)
    }

    fn reconcile(
        &mut self,
        _command: &ExternalPayoutCommandV1,
        _context: ExternalPayoutExecutionContextV1,
    ) -> ExternalPayoutCallResultV1 {
        self.reconcile_calls += 1;
        let (_, terminal) = advance_payout_status(
            self.fixture,
            &self.fixture.store,
            self.payout,
            &self.previous,
            PayoutStateV1::Succeeded,
            0xce,
            NOW + 21,
        );
        assert_eq!(terminal.state(), PayoutStateV1::Succeeded);
        tamper_latest_payout_signature(self.fixture, self.payout);
        ExternalPayoutCallResultV1::Completed(ExternalPayoutOutcomeV1::Succeeded)
    }
}

fn submit_payout_with_unknown_outcome(
    fixture: &Fixture,
    payout: &AcceptedPayout,
) -> VerifiedPayoutSnapshotV1 {
    let executor = ScriptedPayoutExecutorV1::ready(
        [ExternalPayoutOutcomeV1::OutcomeUnknown],
        std::iter::empty(),
    );
    let mut worker = IssuerPayoutOutboxWorkerV1::new(
        &fixture.store,
        &fixture.settlement_signing,
        &[],
        executor,
        [0xd2; 32],
        10,
        8,
    )
    .expect("construct unknown-outcome worker");
    let mut clock = ScriptedPayoutClockV1::new([NOW + 2, NOW + 3]);
    assert_eq!(
        worker.run_once(&mut clock).expect("submit payout once"),
        PayoutOutboxWorkerProgressV1::OutcomeUnknown {
            payout_id: payout.response.payout_id,
        }
    );
    assert_eq!(worker.executor().submit_calls, 1);
    persisted_payout_snapshot(fixture, payout)
}

#[test]
fn no_funds_payout_executor_is_disabled_before_claim_or_clock_read() {
    let fixture = Fixture::new();
    let payout = accept_funded_payout(&fixture, 0xa0);
    assert!(matches!(
        IssuerPayoutOutboxWorkerV1::new(
            &fixture.store,
            &fixture.settlement_signing,
            &[],
            NoFundsPayoutExecutorV1,
            [0xa1; 32],
            MAX_PAYOUT_WORKER_LEASE_SECONDS_V1 + 1,
            1,
        ),
        Err(PayoutOutboxWorkerErrorV1::InvalidConfiguration(_))
    ));
    let mut worker = IssuerPayoutOutboxWorkerV1::new(
        &fixture.store,
        &fixture.settlement_signing,
        &[],
        NoFundsPayoutExecutorV1,
        [0xa1; 32],
        10,
        8,
    )
    .expect("construct disabled payout worker");
    let mut empty_clock = ScriptedPayoutClockV1::new([]);
    assert_eq!(
        worker.run_once(&mut empty_clock).expect("disabled worker"),
        PayoutOutboxWorkerProgressV1::ExecutorDisabled
    );
    let record = fixture
        .store
        .payout_by_id(&payout.response.payout_id)
        .expect("read untouched payout")
        .expect("payout exists");
    assert_eq!(record.state, PayoutStateV1::Accepted);
    let first_claim = fixture
        .store
        .claim_next_payout_outbox(&[0xa2; 32], NOW + 2, 10)
        .expect("claim after disabled worker")
        .expect("disabled worker did not claim");
    assert_eq!(first_claim.value.attempt_count, 1);
}

#[test]
fn payout_worker_rejects_deadline_outside_durable_lease() {
    let fixture = Fixture::new();
    for (lease_seconds, external_call_timeout_seconds) in [(10, 0), (10, 10), (10, 11)] {
        assert!(matches!(
            IssuerPayoutOutboxWorkerV1::new(
                &fixture.store,
                &fixture.settlement_signing,
                &[],
                NoFundsPayoutExecutorV1,
                [0xe1; 32],
                lease_seconds,
                external_call_timeout_seconds,
            ),
            Err(PayoutOutboxWorkerErrorV1::InvalidConfiguration(_))
        ));
    }
    assert!(IssuerPayoutOutboxWorkerV1::new(
        &fixture.store,
        &fixture.settlement_signing,
        &[],
        NoFundsPayoutExecutorV1,
        [0xe1; 32],
        2,
        1,
    )
    .is_ok());
}

#[test]
fn payout_worker_commits_in_flight_before_one_successful_submission() {
    let fixture = Fixture::new();
    let payout = accept_funded_payout(&fixture, 0xa3);
    let executor =
        ScriptedPayoutExecutorV1::ready([ExternalPayoutOutcomeV1::Succeeded], std::iter::empty());
    let mut worker = IssuerPayoutOutboxWorkerV1::new(
        &fixture.store,
        &fixture.settlement_signing,
        &[],
        executor,
        [0xa4; 32],
        10,
        8,
    )
    .expect("construct payout worker");
    let mut clock = ScriptedPayoutClockV1::new([NOW + 2, NOW + 3, NOW + 4]);
    assert_eq!(
        worker.run_once(&mut clock).expect("run successful payout"),
        PayoutOutboxWorkerProgressV1::Succeeded {
            payout_id: payout.response.payout_id
        }
    );
    assert_eq!(worker.executor().submit_calls, 1);
    assert_eq!(worker.executor().reconcile_calls, 0);
    assert_eq!(worker.executor().command_ids.len(), 1);
    assert_eq!(worker.executor().execution_contexts.len(), 1);
    let absolute_deadline = worker.executor().execution_contexts[0].absolute_deadline_unix();
    assert_eq!(absolute_deadline, NOW + 10);
    assert!(
        absolute_deadline < NOW + 12,
        "deadline must precede lease expiry"
    );
    let record = fixture
        .store
        .payout_by_id(&payout.response.payout_id)
        .expect("read completed payout")
        .expect("payout exists");
    assert_eq!(record.state, PayoutStateV1::Succeeded);
    assert!(fixture
        .store
        .claim_next_payout_outbox(&[0xa5; 32], NOW + 30, 10)
        .expect("check completed outbox")
        .is_none());
}

#[test]
fn timeout_and_cancellation_are_always_outcome_unknown() {
    let fixture = Fixture::new();
    let payout = accept_funded_payout(&fixture, 0xe2);
    let executor = ScriptedPayoutExecutorV1::ready_call_results(
        [ExternalPayoutCallResultV1::TimedOut],
        [ExternalPayoutCallResultV1::Cancelled],
    );
    let mut worker = IssuerPayoutOutboxWorkerV1::new(
        &fixture.store,
        &fixture.settlement_signing,
        &[],
        executor,
        [0xe3; 32],
        10,
        8,
    )
    .expect("construct timeout worker");

    let mut submit_clock = ScriptedPayoutClockV1::new([NOW + 2, NOW + 3]);
    assert_eq!(
        worker
            .run_once(&mut submit_clock)
            .expect("time out submission"),
        PayoutOutboxWorkerProgressV1::OutcomeUnknown {
            payout_id: payout.response.payout_id,
        }
    );
    let mut reconcile_clock = ScriptedPayoutClockV1::new([NOW + 20]);
    assert_eq!(
        worker
            .run_once(&mut reconcile_clock)
            .expect("cancel reconciliation"),
        PayoutOutboxWorkerProgressV1::OutcomeUnknown {
            payout_id: payout.response.payout_id,
        }
    );
    assert_eq!(worker.executor().submit_calls, 1);
    assert_eq!(worker.executor().reconcile_calls, 1);
    assert_eq!(
        worker
            .executor()
            .execution_contexts
            .iter()
            .map(|context| context.absolute_deadline_unix())
            .collect::<Vec<_>>(),
        [NOW + 10, NOW + 28]
    );
    assert_eq!(
        fixture
            .store
            .payout_by_id(&payout.response.payout_id)
            .expect("read ambiguous payout")
            .expect("payout exists")
            .state,
        PayoutStateV1::InFlight
    );
}

#[test]
fn payout_worker_progress_debug_redacts_payout_id() {
    let payout_id = [0xe4; 32];
    let cases = [
        (
            PayoutOutboxWorkerProgressV1::DeferredForClock {
                payout_id,
                state: PayoutStateV1::Accepted,
            },
            "DeferredForClock(Accepted)",
        ),
        (
            PayoutOutboxWorkerProgressV1::OutcomeUnknown { payout_id },
            "OutcomeUnknown",
        ),
        (
            PayoutOutboxWorkerProgressV1::TerminalCommitDeferred {
                payout_id,
                outcome: ExternalPayoutOutcomeV1::Succeeded,
            },
            "TerminalCommitDeferred(Succeeded)",
        ),
        (
            PayoutOutboxWorkerProgressV1::Succeeded { payout_id },
            "Succeeded",
        ),
        (PayoutOutboxWorkerProgressV1::Failed { payout_id }, "Failed"),
        (
            PayoutOutboxWorkerProgressV1::ConcurrentAdvance { payout_id },
            "ConcurrentAdvance",
        ),
        (
            PayoutOutboxWorkerProgressV1::TerminalCommitRaced {
                payout_id,
                outcome: ExternalPayoutOutcomeV1::DefinitelyFailed,
            },
            "TerminalCommitRaced(DefinitelyFailed)",
        ),
    ];
    for (progress, expected) in cases {
        let rendered = format!("{progress:?}");
        assert_eq!(rendered, expected);
        assert!(!rendered.contains("payout_id"));
        assert!(!rendered.contains("228"));
    }
}

#[test]
fn ambiguous_submission_is_only_reconciled_and_never_submitted_twice() {
    let fixture = Fixture::new();
    let payout = accept_funded_payout(&fixture, 0xa6);
    let executor = ScriptedPayoutExecutorV1::ready(
        [ExternalPayoutOutcomeV1::OutcomeUnknown],
        std::iter::empty(),
    );
    let mut worker = IssuerPayoutOutboxWorkerV1::new(
        &fixture.store,
        &fixture.settlement_signing,
        &[],
        executor,
        [0xa7; 32],
        10,
        8,
    )
    .expect("construct payout worker");

    let mut first_clock = ScriptedPayoutClockV1::new([NOW + 2, NOW + 3]);
    assert_eq!(
        worker
            .run_once(&mut first_clock)
            .expect("run ambiguous submission"),
        PayoutOutboxWorkerProgressV1::OutcomeUnknown {
            payout_id: payout.response.payout_id
        }
    );
    assert_eq!(
        fixture
            .store
            .payout_by_id(&payout.response.payout_id)
            .expect("read in-flight payout")
            .expect("payout exists")
            .state,
        PayoutStateV1::InFlight
    );
    assert_eq!(worker.executor().submit_calls, 1);
    let submitted_command_id = worker.executor().command_ids[0];
    drop(worker);

    let reopened = IssuerStore::open_existing(
        &fixture.database,
        fixture.binding.issuer_id,
        LightningNetworkV1::Regtest,
        StoreOptions::default(),
    )
    .expect("reopen issuer after ambiguous submission");
    let recovery_executor = ScriptedPayoutExecutorV1::ready(
        [ExternalPayoutOutcomeV1::DefinitelyFailed],
        [
            ExternalPayoutOutcomeV1::OutcomeUnknown,
            ExternalPayoutOutcomeV1::Succeeded,
        ],
    );
    let mut recovery_worker = IssuerPayoutOutboxWorkerV1::new(
        &reopened,
        &fixture.settlement_signing,
        &[],
        recovery_executor,
        [0xac; 32],
        10,
        8,
    )
    .expect("construct restarted payout worker");

    let mut unexpired_clock = ScriptedPayoutClockV1::new([NOW + 5]);
    assert_eq!(
        recovery_worker
            .run_once(&mut unexpired_clock)
            .expect("respect unexpired lease"),
        PayoutOutboxWorkerProgressV1::Idle
    );
    assert_eq!(recovery_worker.executor().submit_calls, 0);
    assert_eq!(recovery_worker.executor().reconcile_calls, 0);

    let mut second_clock = ScriptedPayoutClockV1::new([NOW + 20]);
    assert_eq!(
        recovery_worker
            .run_once(&mut second_clock)
            .expect("run ambiguous reconciliation"),
        PayoutOutboxWorkerProgressV1::OutcomeUnknown {
            payout_id: payout.response.payout_id
        }
    );
    let mut third_clock = ScriptedPayoutClockV1::new([NOW + 40, NOW + 41]);
    assert_eq!(
        recovery_worker
            .run_once(&mut third_clock)
            .expect("run successful reconciliation"),
        PayoutOutboxWorkerProgressV1::Succeeded {
            payout_id: payout.response.payout_id
        }
    );
    assert_eq!(recovery_worker.executor().submit_calls, 0);
    assert_eq!(recovery_worker.executor().reconcile_calls, 2);
    assert!(recovery_worker
        .executor()
        .command_ids
        .iter()
        .all(|command_id| *command_id == submitted_command_id));
}

#[test]
fn terminal_cas_race_reloads_a_matching_signed_winner() {
    let fixture = Fixture::new();
    let payout = accept_funded_payout(&fixture, 0xd3);
    let previous = submit_payout_with_unknown_outcome(&fixture, &payout);
    assert_eq!(previous.state(), PayoutStateV1::InFlight);

    let executor =
        ScriptedPayoutExecutorV1::ready(std::iter::empty(), [ExternalPayoutOutcomeV1::Succeeded]);
    let mut worker = IssuerPayoutOutboxWorkerV1::new(
        &fixture.store,
        &fixture.settlement_signing,
        &[],
        executor,
        [0xd4; 32],
        10,
        8,
    )
    .expect("construct matching-race worker");
    let mut clock = TerminalCasRaceClockV1 {
        fixture: &fixture,
        payout: &payout,
        previous,
        winner: PayoutStateV1::Succeeded,
        tamper_winner_signature: false,
        calls: 0,
    };
    assert_eq!(
        worker
            .run_once(&mut clock)
            .expect("reload matching terminal winner"),
        PayoutOutboxWorkerProgressV1::ConcurrentAdvance {
            payout_id: payout.response.payout_id,
        }
    );
    assert_eq!(worker.executor().submit_calls, 0);
    assert_eq!(worker.executor().reconcile_calls, 1);
    assert_eq!(
        fixture
            .store
            .payout_by_id(&payout.response.payout_id)
            .expect("read matching winner")
            .expect("payout exists")
            .state,
        PayoutStateV1::Succeeded
    );
}

#[test]
fn terminal_cas_race_fails_closed_on_a_conflicting_signed_winner() {
    let fixture = Fixture::new();
    let payout = accept_funded_payout(&fixture, 0xd5);
    let previous = submit_payout_with_unknown_outcome(&fixture, &payout);
    assert_eq!(previous.state(), PayoutStateV1::InFlight);

    let executor =
        ScriptedPayoutExecutorV1::ready(std::iter::empty(), [ExternalPayoutOutcomeV1::Succeeded]);
    let mut worker = IssuerPayoutOutboxWorkerV1::new(
        &fixture.store,
        &fixture.settlement_signing,
        &[],
        executor,
        [0xd6; 32],
        10,
        8,
    )
    .expect("construct conflicting-race worker");
    let mut clock = TerminalCasRaceClockV1 {
        fixture: &fixture,
        payout: &payout,
        previous,
        winner: PayoutStateV1::Failed,
        tamper_winner_signature: false,
        calls: 0,
    };
    assert!(matches!(
        worker.run_once(&mut clock),
        Err(PayoutOutboxWorkerErrorV1::StoreInvariant(
            "terminal payout winner conflicts with external outcome"
        ))
    ));
    assert_eq!(worker.executor().submit_calls, 0);
    assert_eq!(worker.executor().reconcile_calls, 1);
    assert_eq!(
        fixture
            .store
            .payout_by_id(&payout.response.payout_id)
            .expect("read conflicting winner")
            .expect("payout exists")
            .state,
        PayoutStateV1::Failed
    );
}

#[test]
fn terminal_cas_race_fails_closed_on_a_tampered_winner_signature() {
    let fixture = Fixture::new();
    let payout = accept_funded_payout(&fixture, 0xd7);
    let previous = submit_payout_with_unknown_outcome(&fixture, &payout);
    assert_eq!(previous.state(), PayoutStateV1::InFlight);

    let executor =
        ScriptedPayoutExecutorV1::ready(std::iter::empty(), [ExternalPayoutOutcomeV1::Succeeded]);
    let mut worker = IssuerPayoutOutboxWorkerV1::new(
        &fixture.store,
        &fixture.settlement_signing,
        &[],
        executor,
        [0xd8; 32],
        10,
        8,
    )
    .expect("construct tampered-race worker");
    let mut clock = TerminalCasRaceClockV1 {
        fixture: &fixture,
        payout: &payout,
        previous,
        winner: PayoutStateV1::Succeeded,
        tamper_winner_signature: true,
        calls: 0,
    };
    assert!(matches!(
        worker.run_once(&mut clock),
        Err(PayoutOutboxWorkerErrorV1::Protocol(_))
    ));
    assert_eq!(worker.executor().submit_calls, 0);
    assert_eq!(worker.executor().reconcile_calls, 1);
}

#[test]
fn terminal_fast_path_fails_closed_on_a_tampered_signed_snapshot() {
    let fixture = Fixture::new();
    let payout = accept_funded_payout(&fixture, 0xcf);
    let previous = submit_payout_with_unknown_outcome(&fixture, &payout);
    assert_eq!(previous.state(), PayoutStateV1::InFlight);

    let executor = TamperingTerminalPayoutExecutorV1 {
        fixture: &fixture,
        payout: &payout,
        previous,
        submit_calls: 0,
        reconcile_calls: 0,
    };
    let mut worker = IssuerPayoutOutboxWorkerV1::new(
        &fixture.store,
        &fixture.settlement_signing,
        &[],
        executor,
        [0xd0; 32],
        10,
        8,
    )
    .expect("construct terminal-fast-path worker");
    let mut clock = ScriptedPayoutClockV1::new([NOW + 20]);
    assert!(matches!(
        worker.run_once(&mut clock),
        Err(PayoutOutboxWorkerErrorV1::Protocol(_))
    ));
    assert_eq!(worker.executor().submit_calls, 0);
    assert_eq!(worker.executor().reconcile_calls, 1);
}

#[test]
fn definite_external_failure_restores_reserved_provider_balance() {
    let fixture = Fixture::new();
    let payout = accept_funded_payout(&fixture, 0xa8);
    let executor = ScriptedPayoutExecutorV1::ready(
        [ExternalPayoutOutcomeV1::DefinitelyFailed],
        std::iter::empty(),
    );
    let mut worker = IssuerPayoutOutboxWorkerV1::new(
        &fixture.store,
        &fixture.settlement_signing,
        &[],
        executor,
        [0xa9; 32],
        10,
        8,
    )
    .expect("construct payout worker");
    let mut clock = ScriptedPayoutClockV1::new([NOW + 2, NOW + 3, NOW + 4]);
    assert_eq!(
        worker.run_once(&mut clock).expect("run failed payout"),
        PayoutOutboxWorkerProgressV1::Failed {
            payout_id: payout.response.payout_id
        }
    );
    let balance = fixture
        .store
        .provider_ledger_balance(&PROVIDER_ID)
        .expect("read restored payout balance")
        .expect("provider balance exists");
    assert_eq!((balance.available_value, balance.reserved_value), (9, 0));
    assert_eq!(worker.executor().submit_calls, 1);
}

#[test]
fn terminal_clock_deferral_recovers_by_reconciliation_without_resubmit() {
    let fixture = Fixture::new();
    let payout = accept_funded_payout(&fixture, 0xba);
    let executor =
        ScriptedPayoutExecutorV1::ready([ExternalPayoutOutcomeV1::Succeeded], std::iter::empty());
    let mut worker = IssuerPayoutOutboxWorkerV1::new(
        &fixture.store,
        &fixture.settlement_signing,
        &[],
        executor,
        [0xbb; 32],
        10,
        8,
    )
    .expect("construct terminal-deferral worker");
    let mut clock = ScriptedPayoutClockV1::new([NOW + 2, NOW + 3, NOW + 3]);
    assert_eq!(
        worker
            .run_once(&mut clock)
            .expect("defer non-monotonic terminal commit"),
        PayoutOutboxWorkerProgressV1::TerminalCommitDeferred {
            payout_id: payout.response.payout_id,
            outcome: ExternalPayoutOutcomeV1::Succeeded,
        }
    );
    assert_eq!(worker.executor().submit_calls, 1);
    drop(worker);

    let reopened = IssuerStore::open_existing(
        &fixture.database,
        fixture.binding.issuer_id,
        LightningNetworkV1::Regtest,
        StoreOptions::default(),
    )
    .expect("reopen terminal-deferral store");
    let executor = ScriptedPayoutExecutorV1::ready(
        [ExternalPayoutOutcomeV1::DefinitelyFailed],
        [ExternalPayoutOutcomeV1::Succeeded],
    );
    let mut recovery_worker = IssuerPayoutOutboxWorkerV1::new(
        &reopened,
        &fixture.settlement_signing,
        &[],
        executor,
        [0xbc; 32],
        10,
        8,
    )
    .expect("construct terminal recovery worker");
    let mut recovery_clock = ScriptedPayoutClockV1::new([NOW + 20, NOW + 21]);
    assert_eq!(
        recovery_worker
            .run_once(&mut recovery_clock)
            .expect("reconcile terminal outcome"),
        PayoutOutboxWorkerProgressV1::Succeeded {
            payout_id: payout.response.payout_id
        }
    );
    assert_eq!(recovery_worker.executor().submit_calls, 0);
    assert_eq!(recovery_worker.executor().reconcile_calls, 1);
}

#[test]
fn non_monotonic_worker_clock_never_calls_external_executor() {
    let fixture = Fixture::new();
    let payout = accept_funded_payout(&fixture, 0xaa);
    let executor =
        ScriptedPayoutExecutorV1::ready([ExternalPayoutOutcomeV1::Succeeded], std::iter::empty());
    let mut worker = IssuerPayoutOutboxWorkerV1::new(
        &fixture.store,
        &fixture.settlement_signing,
        &[],
        executor,
        [0xab; 32],
        10,
        8,
    )
    .expect("construct payout worker");
    let mut clock = ScriptedPayoutClockV1::new([NOW + 2, NOW + 1]);
    assert_eq!(
        worker.run_once(&mut clock).expect("defer stale clock"),
        PayoutOutboxWorkerProgressV1::DeferredForClock {
            payout_id: payout.response.payout_id,
            state: PayoutStateV1::Accepted,
        }
    );
    assert_eq!(worker.executor().submit_calls, 0);
    assert_eq!(worker.executor().reconcile_calls, 0);
}

#[test]
fn tampered_outbox_command_id_never_reaches_external_executor() {
    let fixture = Fixture::new();
    let payout = accept_funded_payout(&fixture, 0xb7);
    let mut tampered_command_id =
        issuer_payout_outbox_command_id_v1(&fixture.binding.issuer_id, &payout.response.payout_id);
    tampered_command_id[0] ^= 1;
    let connection = rusqlite::Connection::open(&fixture.database).expect("open payout database");
    assert_eq!(
        connection
            .execute(
                "UPDATE payout_outbox SET command_id = ?1 WHERE payout_id = ?2",
                rusqlite::params![
                    tampered_command_id.as_slice(),
                    payout.response.payout_id.as_slice()
                ],
            )
            .expect("tamper outbox command id"),
        1
    );
    drop(connection);

    let executor = ScriptedPayoutExecutorV1::ready(
        [ExternalPayoutOutcomeV1::Succeeded],
        [ExternalPayoutOutcomeV1::Succeeded],
    );
    let mut worker = IssuerPayoutOutboxWorkerV1::new(
        &fixture.store,
        &fixture.settlement_signing,
        &[],
        executor,
        [0xb9; 32],
        10,
        8,
    )
    .expect("construct command-binding worker");
    let mut clock = ScriptedPayoutClockV1::new([NOW + 2]);
    assert!(matches!(
        worker.run_once(&mut clock),
        Err(PayoutOutboxWorkerErrorV1::StoreInvariant(
            "outbox command id is not derived from issuer and payout"
        ))
    ));
    assert_eq!(worker.executor().submit_calls, 0);
    assert_eq!(worker.executor().reconcile_calls, 0);
}

#[test]
fn tampered_accepted_initial_signature_never_reaches_external_executor() {
    let fixture = Fixture::new();
    let payout = accept_funded_payout(&fixture, 0xc1);
    tamper_initial_payout_signature(&fixture, &payout);
    let executor = ScriptedPayoutExecutorV1::ready(
        [ExternalPayoutOutcomeV1::Succeeded],
        [ExternalPayoutOutcomeV1::Succeeded],
    );
    let mut worker = IssuerPayoutOutboxWorkerV1::new(
        &fixture.store,
        &fixture.settlement_signing,
        &[],
        executor,
        [0xc2; 32],
        10,
        8,
    )
    .expect("construct initial-signature worker");
    let mut clock = ScriptedPayoutClockV1::new([NOW + 2]);
    assert!(matches!(
        worker.run_once(&mut clock),
        Err(PayoutOutboxWorkerErrorV1::Protocol(_))
    ));
    assert_eq!(worker.executor().submit_calls, 0);
    assert_eq!(worker.executor().reconcile_calls, 0);
}

#[test]
fn tampered_in_flight_latest_signature_never_reaches_external_executor() {
    let fixture = Fixture::new();
    let payout = accept_funded_payout(&fixture, 0xc3);
    let previous = submit_payout_with_unknown_outcome(&fixture, &payout);
    assert_eq!(previous.state(), PayoutStateV1::InFlight);
    tamper_latest_payout_signature(&fixture, &payout);

    let executor = ScriptedPayoutExecutorV1::ready(
        [ExternalPayoutOutcomeV1::Succeeded],
        [ExternalPayoutOutcomeV1::Succeeded],
    );
    let mut worker = IssuerPayoutOutboxWorkerV1::new(
        &fixture.store,
        &fixture.settlement_signing,
        &[],
        executor,
        [0xc4; 32],
        10,
        8,
    )
    .expect("construct latest-signature worker");
    let mut clock = ScriptedPayoutClockV1::new([NOW + 20]);
    assert!(matches!(
        worker.run_once(&mut clock),
        Err(PayoutOutboxWorkerErrorV1::Protocol(_))
    ));
    assert_eq!(worker.executor().submit_calls, 0);
    assert_eq!(worker.executor().reconcile_calls, 0);
}

#[test]
fn invalid_retained_keyring_never_reaches_external_executor() {
    let fixture = Fixture::new();
    let _payout = accept_funded_payout(&fixture, 0xc5);
    let executor = ScriptedPayoutExecutorV1::ready(
        [ExternalPayoutOutcomeV1::Succeeded],
        [ExternalPayoutOutcomeV1::Succeeded],
    );
    let current_key = fixture.settlement_signing.verifying_key();
    let retained_keys = [current_key];
    let mut worker = IssuerPayoutOutboxWorkerV1::new(
        &fixture.store,
        &fixture.settlement_signing,
        &retained_keys,
        executor,
        [0xc6; 32],
        10,
        8,
    )
    .expect("construct invalid-keyring worker");
    let mut clock = ScriptedPayoutClockV1::new([NOW + 2]);
    assert!(matches!(
        worker.run_once(&mut clock),
        Err(PayoutOutboxWorkerErrorV1::Protocol(_))
    ));
    assert_eq!(worker.executor().submit_calls, 0);
    assert_eq!(worker.executor().reconcile_calls, 0);
}

#[derive(Debug)]
struct CrashBeforeExternalSubmitV1;

impl ExternalPayoutExecutorV1 for CrashBeforeExternalSubmitV1 {
    fn readiness(&self) -> ExternalPayoutReadinessV1 {
        ExternalPayoutReadinessV1::Ready
    }

    fn submit_once(
        &mut self,
        _command: &ExternalPayoutCommandV1,
        _context: ExternalPayoutExecutionContextV1,
    ) -> ExternalPayoutCallResultV1 {
        panic!("simulated process crash before external adapter submission");
    }

    fn reconcile(
        &mut self,
        _command: &ExternalPayoutCommandV1,
        _context: ExternalPayoutExecutionContextV1,
    ) -> ExternalPayoutCallResultV1 {
        panic!("crashing worker must not reconcile");
    }
}

#[test]
fn crash_after_in_flight_commit_restarts_in_reconcile_only_mode() {
    let fixture = Fixture::new();
    let payout = accept_funded_payout(&fixture, 0xad);
    {
        let mut crashing_worker = IssuerPayoutOutboxWorkerV1::new(
            &fixture.store,
            &fixture.settlement_signing,
            &[],
            CrashBeforeExternalSubmitV1,
            [0xae; 32],
            10,
            8,
        )
        .expect("construct crashing worker");
        let mut first_clock = ScriptedPayoutClockV1::new([NOW + 2, NOW + 3]);
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = crashing_worker.run_once(&mut first_clock);
        }));
        assert!(crashed.is_err());
    }
    assert_eq!(
        fixture
            .store
            .payout_by_id(&payout.response.payout_id)
            .expect("read payout after simulated crash")
            .expect("payout exists")
            .state,
        PayoutStateV1::InFlight
    );

    let reopened = IssuerStore::open_existing(
        &fixture.database,
        fixture.binding.issuer_id,
        LightningNetworkV1::Regtest,
        StoreOptions::default(),
    )
    .expect("reopen after simulated worker crash");
    // A submit outcome is deliberately configured, so the assertion proves
    // the restarted worker never consumes it for an InFlight payout.
    let recovery_executor = ScriptedPayoutExecutorV1::ready(
        [ExternalPayoutOutcomeV1::Succeeded],
        [ExternalPayoutOutcomeV1::OutcomeUnknown],
    );
    let mut recovery_worker = IssuerPayoutOutboxWorkerV1::new(
        &reopened,
        &fixture.settlement_signing,
        &[],
        recovery_executor,
        [0xaf; 32],
        10,
        8,
    )
    .expect("construct recovery worker");
    let mut recovery_clock = ScriptedPayoutClockV1::new([NOW + 20]);
    assert_eq!(
        recovery_worker
            .run_once(&mut recovery_clock)
            .expect("reconcile after crash"),
        PayoutOutboxWorkerProgressV1::OutcomeUnknown {
            payout_id: payout.response.payout_id
        }
    );
    assert_eq!(recovery_worker.executor().submit_calls, 0);
    assert_eq!(recovery_worker.executor().reconcile_calls, 1);
}

#[test]
fn store_record_snapshot_verification_rejects_digest_and_signature_tampering() {
    let fixture = Fixture::new();
    let payout = accept_funded_payout(&fixture, 0xb0);
    let record = fixture
        .store
        .payout_by_id(&payout.response.payout_id)
        .expect("read payout for tamper test")
        .expect("payout exists");
    let initial = IssuerPayoutResponseV1::decode(&record.exact_initial_response)
        .expect("decode durable initial response");
    let settlement_key = fixture.settlement_signing.verifying_key();
    let keyring = IssuerSettlementKeyringExpectationV1 {
        issuer_id: &fixture.binding.issuer_id,
        current_key: &settlement_key,
        retained_keys: &[],
    };
    assert!(verify_persisted_payout_snapshot_from_store_record_v1(
        &[0xb1; 32],
        &initial,
        None,
        &keyring,
    )
    .is_err());
    let mut forged = initial;
    forged.signature[0] ^= 1;
    assert!(verify_persisted_payout_snapshot_from_store_record_v1(
        &record.request_digest,
        &forged,
        None,
        &keyring,
    )
    .is_err());

    let _claim = fixture
        .store
        .claim_next_payout_outbox(&[0xb5; 32], NOW + 2, 10)
        .expect("claim payout for status tamper test")
        .expect("payout command exists");
    let _ = advance_payout_status(
        &fixture,
        &fixture.store,
        &payout,
        &payout.snapshot,
        PayoutStateV1::InFlight,
        0xb6,
        NOW + 3,
    );
    let advanced = fixture
        .store
        .payout_by_id(&payout.response.payout_id)
        .expect("read advanced payout")
        .expect("advanced payout exists");
    let advanced_initial = IssuerPayoutResponseV1::decode(&advanced.exact_initial_response)
        .expect("decode advanced initial response");
    let mut forged_latest = IssuerPayoutStatusResponseV1::decode(
        advanced
            .exact_latest_status_response
            .as_deref()
            .expect("advanced status exists"),
    )
    .expect("decode advanced status");
    forged_latest.signature[0] ^= 1;
    assert!(verify_persisted_payout_snapshot_from_store_record_v1(
        &advanced.request_digest,
        &advanced_initial,
        Some(&forged_latest),
        &keyring,
    )
    .is_err());
}

#[derive(Debug)]
struct SharedCountingPayoutExecutorV1 {
    submit_calls: Arc<AtomicUsize>,
    reconcile_calls: Arc<AtomicUsize>,
    deadlines: Arc<Mutex<Vec<u64>>>,
}

impl ExternalPayoutExecutorV1 for SharedCountingPayoutExecutorV1 {
    fn readiness(&self) -> ExternalPayoutReadinessV1 {
        ExternalPayoutReadinessV1::Ready
    }

    fn submit_once(
        &mut self,
        _command: &ExternalPayoutCommandV1,
        context: ExternalPayoutExecutionContextV1,
    ) -> ExternalPayoutCallResultV1 {
        self.submit_calls.fetch_add(1, Ordering::SeqCst);
        self.deadlines
            .lock()
            .expect("deadline mutex")
            .push(context.absolute_deadline_unix());
        ExternalPayoutCallResultV1::Completed(ExternalPayoutOutcomeV1::Succeeded)
    }

    fn reconcile(
        &mut self,
        _command: &ExternalPayoutCommandV1,
        context: ExternalPayoutExecutionContextV1,
    ) -> ExternalPayoutCallResultV1 {
        self.reconcile_calls.fetch_add(1, Ordering::SeqCst);
        self.deadlines
            .lock()
            .expect("deadline mutex")
            .push(context.absolute_deadline_unix());
        ExternalPayoutCallResultV1::Completed(ExternalPayoutOutcomeV1::Succeeded)
    }
}

#[test]
fn two_concurrent_workers_submit_at_most_once() {
    let fixture = Fixture::new();
    let payout = accept_funded_payout(&fixture, 0xb2);
    let barrier = Arc::new(Barrier::new(2));
    let submit_calls = Arc::new(AtomicUsize::new(0));
    let reconcile_calls = Arc::new(AtomicUsize::new(0));
    let deadlines = Arc::new(Mutex::new(Vec::new()));
    let mut joins = Vec::new();
    for worker_byte in [0xb3, 0xb4] {
        let database = fixture.database.clone();
        let issuer_id = fixture.binding.issuer_id;
        let barrier = barrier.clone();
        let submit_calls = submit_calls.clone();
        let reconcile_calls = reconcile_calls.clone();
        let deadlines = deadlines.clone();
        joins.push(std::thread::spawn(move || {
            let store = IssuerStore::open_existing(
                &database,
                issuer_id,
                LightningNetworkV1::Regtest,
                StoreOptions::default(),
            )
            .expect("open concurrent worker store");
            let signing_key = SigningKey::from_bytes(&[0x25; 32]);
            let executor = SharedCountingPayoutExecutorV1 {
                submit_calls,
                reconcile_calls,
                deadlines,
            };
            let mut worker = IssuerPayoutOutboxWorkerV1::new(
                &store,
                &signing_key,
                &[],
                executor,
                [worker_byte; 32],
                10,
                8,
            )
            .expect("construct concurrent worker");
            let mut clock = ScriptedPayoutClockV1::new([NOW + 2, NOW + 3, NOW + 4]);
            barrier.wait();
            worker.run_once(&mut clock)
        }));
    }
    let outcomes: Vec<_> = joins
        .into_iter()
        .map(|join| join.join().expect("concurrent worker thread"))
        .collect();
    // A loser may fail closed while observing the store's commit-then-floor-CAS
    // window. The economic invariant is that exactly one submission occurs
    // and the durable payout reaches one terminal state.
    assert!(outcomes.iter().any(Result::is_ok));
    assert_eq!(submit_calls.load(Ordering::SeqCst), 1);
    assert_eq!(reconcile_calls.load(Ordering::SeqCst), 0);
    let observed_deadlines = deadlines.lock().expect("deadline mutex");
    assert_eq!(
        *observed_deadlines,
        [NOW + 10],
        "the sole concurrent submission uses claim time plus the configured timeout"
    );
    assert!(
        observed_deadlines[0] < NOW + 12,
        "deadline must precede lease expiry"
    );
    assert_eq!(
        fixture
            .store
            .payout_by_id(&payout.response.payout_id)
            .expect("read concurrent payout")
            .expect("payout exists")
            .state,
        PayoutStateV1::Succeeded
    );
}

#[test]
fn shared_issuer_arc_requires_registered_exclusive_lineage_experimental() {
    use arc::group::serialize_scalar;

    let fixture = Fixture::new();
    let mut rng = ChaCha20Rng::from_seed([0xa1; 32]);
    let (arc_secret, arc_public) = arc::setup_server(&mut rng);
    let mut secret_bytes = Zeroizing::new([0u8; ARC_SECRET_KEY_LEN_V1]);
    secret_bytes[0..32].copy_from_slice(&serialize_scalar(&arc_secret.x0));
    secret_bytes[32..64].copy_from_slice(&serialize_scalar(&arc_secret.x1));
    secret_bytes[64..96].copy_from_slice(&serialize_scalar(&arc_secret.x2));
    secret_bytes[96..128].copy_from_slice(&serialize_scalar(&arc_secret.x0_blinding));
    let key_id = vec![0xa2; 16];
    let arc_key = ArcSecretKeyV1::from_zeroizing_bytes(key_id.clone(), secret_bytes)
        .expect("construct ARC adapter key");
    let arc_keyring = ArcSecretKeyringV1::new(vec![arc_key]).expect("construct ARC keyring");
    let binding = CredentialKeyBindingV1::sign(
        CredentialKeyBindingClaimsV1 {
            provider_id: PROVIDER_ID,
            scope_id: SCOPE_ID,
            offer_id: 8,
            scheme: AuthScheme::ArcV1Experimental,
            keyset_epoch: 1,
            entitlement_profile: 10,
            unit: CredentialUnitV1::Auth,
            amount: 1,
            presentation_limit: 2,
            not_before: 1_000,
            not_after: 5_000,
            credential_key_id: key_id.clone(),
            verification_key: arc_public.to_bytes().to_vec(),
        },
        &fixture.issuer_root,
    )
    .expect("sign ARC binding");
    let authorization = ProviderClearingAuthorizationV1::sign(
        ProviderClearingAuthorizationClaimsV1 {
            authorization_id: [0xa3; 16],
            authorization_epoch: 2,
            provider_id: PROVIDER_ID,
            issuer_id: fixture.binding.issuer_id,
            redeem_endpoint: "https://issuer.example".to_owned(),
            redeem_leaf_spki_sha256_pins: vec![[0x41; 32]],
            settlement_account_id: ACCOUNT_ID,
            clearing_verifying_key: fixture.clearing.verifying_key().to_bytes(),
            not_before: 1_000,
            not_after: 5_000,
            rules: vec![SettlementRuleV1 {
                credential_binding_digest: binding.binding_digest().expect("ARC binding digest"),
                unit: SettlementUnitV1::AuthCredit,
                accepted_value: 10,
                provider_credit: 9,
                issuer_fee: 1,
                denomination_profile: 1,
                settlement_modes: SettlementModesV1::from_bits(SettlementModesV1::LEDGER_CREDIT)
                    .expect("ledger settlement mode"),
                blind_output_minimum_validity_seconds: 0,
                blind_output_keyset: None,
            }],
        },
        &fixture.operator,
    )
    .expect("sign ARC clearing authorization");
    let approval =
        IssuerClearingApprovalV1::sign(&authorization, 1_000, 5_000, &fixture.settlement_signing)
            .expect("sign ARC clearing approval");
    let _registered_authorization = fixture
        .store
        .register_clearing_authorization(
            &authorization,
            &approval,
            &fixture.operator.verifying_key(),
            &fixture.settlement_signing.verifying_key(),
            NOW,
        )
        .expect("register ARC clearing authorization");

    let expected = CredentialKeyBindingExpectationV1 {
        issuer_id: &binding.issuer_id,
        provider_id: &PROVIDER_ID,
        scope_id: &SCOPE_ID,
        offer_id: 8,
        scheme: AuthScheme::ArcV1Experimental,
        minimum_keyset_epoch: 1,
        entitlement_profile: 10,
        presentation_limit: 2,
        credential_key_id: &key_id,
    };
    binding
        .verify_for(&expected, NOW)
        .expect("verify ARC binding");
    let request_context = binding
        .request_context_digest()
        .expect("ARC request context");
    let presentation_context = binding
        .presentation_context_digest()
        .expect("ARC presentation context");
    let (client_secrets, credential_request) =
        arc::create_credential_request(&request_context, &mut rng).expect("create ARC request");
    let credential_response =
        arc::create_credential_response(&arc_secret, &arc_public, &credential_request, &mut rng)
            .expect("create ARC response");
    let credential = arc::finalize_credential(
        &client_secrets,
        &arc_public,
        &credential_request,
        &credential_response,
    )
    .expect("finalize ARC credential");
    let presentation_state = arc::make_presentation_state(credential, &presentation_context, 2);
    let (_, _, typed_presentation) =
        arc::present(&presentation_state, &mut rng).expect("present ARC credential");
    let credential = ArcPresentationV1::from_canonical_bytes(typed_presentation.to_bytes())
        .expect("wrap ARC presentation")
        .encode()
        .expect("encode ARC presentation");
    let request = ProviderRedeemRequestV1 {
        authorization_digest: authorization
            .authorization_digest()
            .expect("ARC authorization digest"),
        issuer_id: binding.issuer_id,
        provider_id: PROVIDER_ID,
        scope_id: SCOPE_ID,
        offer_id: 8,
        credential_binding_digest: binding.binding_digest().expect("ARC binding digest"),
        scheme: AuthScheme::ArcV1Experimental,
        credential_digest: credential_presentation_digest(
            AuthScheme::ArcV1Experimental,
            &credential,
        )
        .expect("ARC credential digest"),
        accepted_value: 10,
        denomination_profile: 1,
        idempotency_key: [0xa4; 32],
        destination: SettlementDestinationV1::LedgerCredit {
            account_id: ACCOUNT_ID,
        },
    };
    let request_auth = ProviderClearingRequestAuthV1::sign(
        request.authorization_digest,
        request.request_digest().expect("ARC redeem request digest"),
        &fixture.clearing,
    );
    let operator_key = fixture.operator.verifying_key();
    let settlement_key = fixture.settlement_signing.verifying_key();
    let clearing_expectation = ProviderClearingExpectationV1 {
        provider_id: &PROVIDER_ID,
        issuer_id: &binding.issuer_id,
        operator_key: &operator_key,
        issuer_settlement_key: &settlement_key,
        now_unix: NOW,
        minimum_authorization_epoch: 2,
    };
    let credential_verifier = SharedIssuerCredentialVerifierV1::new(None, Some(&arc_keyring));
    let verify = || {
        verify_shared_issuer_redeem_v1(
            &request,
            &credential,
            &binding,
            &authorization,
            &approval,
            &request_auth,
            &clearing_expectation,
            &credential_verifier,
        )
        .expect("verify shared ARC redeem")
    };
    let commit_verified = |verified| {
        let response = prepare_redeem_response_v1(
            &verified,
            &fixture.settlement_signing,
            None,
            &RedeemResponseDerivationKeyV1::from_bytes([0xa5; 32]).expect("response key"),
        )
        .expect("prepare ARC redeem response");
        let retained_keysets = [fixture.settlement_keyset.clone()];
        let retained = RetainedSettlementKeysetExpectationV1 {
            issuer_id: &binding.issuer_id,
            retained_keysets: &retained_keysets,
            now_unix: NOW,
        };
        let verified_response = verify_redeem_response_for_exact_request(
            &response,
            &request,
            &authorization,
            &settlement_key,
            &retained,
            &K256CashuDleqVerifierV1,
        )
        .expect("verify ARC redeem response");
        fixture.store.commit_redeem(&VerifiedRedeemCommitV1 {
            redeem: verified,
            response: verified_response,
        })
    };
    assert!(matches!(
        commit_verified(verify()),
        Err(StoreError::InvalidInput(
            "experimental ARC key lineage is not issuer-registered"
        ))
    ));
    let registered = fixture
        .store
        .register_arc_key_lineage_experimental(&binding, NOW)
        .expect("register experimental ARC lineage");
    assert_eq!(registered.disposition, WriteDisposition::Committed);
    let committed = commit_verified(verify()).expect("commit shared ARC redeem");
    assert_eq!(committed.disposition, WriteDisposition::Committed);
    let balance = fixture
        .store
        .provider_ledger_balance(&PROVIDER_ID)
        .expect("read ARC credited balance")
        .expect("balance exists");
    assert_eq!(balance.available_value, 9);
}
