use super::*;
use pir_arc_adapter::{ArcSecretKeyV1, ArcSecretKeyringV1, ARC_SECRET_KEY_LEN_V1};
use pir_issuer_store::{
    verify_shared_issuer_redeem_v1, BatKeyLineageRegistration, IssuerRollbackFloorAuthorityErrorV1,
    IssuerRollbackFloorAuthorityV1, IssuerRollbackFloorV1, IssuerStore,
    ProviderSettlementRegistrationWriteV1, SettlementKeyLineageRegistration, StoreError,
    StoreOptions, VerifiedRedeemCommitV1, WriteDisposition,
};
use pir_payment_crypto::{
    blind_cashu_message_v1, cashu_hash_to_curve_v1, verify_and_unblind_cashu_promise_v1,
    K256CashuDleqVerifierV1,
};
use pir_service_protocol::{
    credential_presentation_digest, derive_bat_key_id_v1, derive_cashu_keyset_id_v2,
    derive_issuer_id, verify_new_payout_request_for, verify_new_payout_response_for,
    verify_new_payout_status_response_for, verify_new_settlement_deposit_request_for,
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
use std::path::PathBuf;
use std::sync::{Arc, Barrier, Mutex};
use tempfile::TempDir;
use zeroize::Zeroizing;

const NOW: u64 = 1_500;
const PROVIDER_ID: [u8; 32] = [0x31; 32];
const SCOPE_ID: [u8; 32] = [0x32; 32];
const ACCOUNT_ID: [u8; 32] = [0x33; 32];

#[derive(Debug, Default)]
struct MemoryRollbackAuthorityV1 {
    floor: Mutex<Option<IssuerRollbackFloorV1>>,
}

impl IssuerRollbackFloorAuthorityV1 for MemoryRollbackAuthorityV1 {
    fn load(
        &self,
        _issuer_id: &[u8; 32],
        _network: LightningNetworkV1,
    ) -> Result<Option<IssuerRollbackFloorV1>, IssuerRollbackFloorAuthorityErrorV1> {
        Ok(*self.floor.lock().expect("rollback floor mutex"))
    }

    fn initialize(
        &self,
        initial: &IssuerRollbackFloorV1,
    ) -> Result<IssuerRollbackFloorV1, IssuerRollbackFloorAuthorityErrorV1> {
        let mut floor = self.floor.lock().expect("rollback floor mutex");
        if floor.is_none() {
            *floor = Some(*initial);
        }
        floor.ok_or_else(|| IssuerRollbackFloorAuthorityErrorV1::new("missing test floor"))
    }

    fn compare_and_advance(
        &self,
        expected: &IssuerRollbackFloorV1,
        next: &IssuerRollbackFloorV1,
    ) -> Result<IssuerRollbackFloorV1, IssuerRollbackFloorAuthorityErrorV1> {
        let mut floor = self.floor.lock().expect("rollback floor mutex");
        if floor.as_ref() == Some(expected) {
            *floor = Some(*next);
        }
        floor.ok_or_else(|| IssuerRollbackFloorAuthorityErrorV1::new("missing test floor"))
    }
}

struct Fixture {
    _directory: TempDir,
    database: PathBuf,
    rollback: Arc<MemoryRollbackAuthorityV1>,
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
        let database = directory.path().join("issuer.sqlite3");
        let rollback = Arc::new(MemoryRollbackAuthorityV1::default());
        let issuer_root = SigningKey::from_bytes(&[0x21; 32]);
        let issuer_id = derive_issuer_id(&issuer_root.verifying_key().to_bytes());
        let store = IssuerStore::create(
            &database,
            [0x11; 16],
            issuer_id,
            LightningNetworkV1::Regtest,
            StoreOptions::default(),
            rollback.clone(),
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
            rollback,
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
        fixture.rollback.clone(),
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
        fixture.rollback.clone(),
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
