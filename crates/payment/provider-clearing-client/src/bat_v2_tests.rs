use std::collections::HashSet;
use std::sync::Mutex;

use ed25519_dalek::SigningKey;
use pir_service_protocol::{
    precheck_bat_v2_redeem_v2, sign_and_commit_grantable_success_v2,
    sign_retry_safe_non_consuming_v2, sign_terminal_invalid_or_spent_v2,
    verify_bat_v2_credential_for_commit_v2, AuthPaddingClassV1, BackendId, BatAcceptanceClassV2,
    BatAcceptanceMemberV2, BatAcceptanceTermsV2, BatV2CredentialCheckV2,
    BatV2ProofVerificationInputV2, BatV2ProofVerifierV2, BatV2RedeemCommitResultV2,
    BatV2RedeemCommitStoreV2, BatV2RedeemPrecheckV2, BitcoinPirCashuBatProofV2, DatasetBindingV1,
    DeploymentStatus, EntitlementLimitsV1, IssuerAccountingApprovalV2, PrivacyLeakageV1,
    ProviderAccountingAuthorizationClaimsV2, ProviderAccountingAuthorizationV2,
    ProviderAccountingExpectationV2, ProviderAccountingRuleV2, ProviderRedeemEnvelopeV2,
    ProviderRedeemResponseV2, RetrySafeNonConsumingReasonV2, ServiceProtocolError,
    SettlementUnitV1, VerifiedBatAcceptanceMemberV2, VerifiedBatV2RedeemCommitV2, WorkloadId,
    MAX_BAT_V2_PROVIDER_REDEEM_RESPONSE_LEN_V2,
};

use crate::{
    BatV2ProviderRedeemTrustV2, BatV2RedeemHttpRequestV2, BatV2RedeemTransportErrorV2,
    BatV2RedeemTransportV2, StorelessBatV2AdmissionCommitterV2,
    StorelessBatV2ProviderRedeemClientV2, StorelessBatV2RedeemDecisionV2,
    StorelessBatV2RedeemErrorV2, BAT_V2_REDEEM_ENDPOINT_V2, BAT_V2_REDEEM_REQUEST_CONTENT_TYPE_V2,
    BAT_V2_REDEEM_RESPONSE_CONTENT_TYPE_V2,
};

const NOW: u64 = 200;
const SECP_GENERATOR: [u8; 33] = [
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98,
];

fn terms() -> BatAcceptanceTermsV2 {
    BatAcceptanceTermsV2 {
        auth_padding_class: AuthPaddingClassV1::Class16KiB,
        backend: BackendId::DpfPirV1,
        workload: WorkloadId::DpfEvaluateJobV1,
        protocol_version: 1,
        dataset: DatasetBindingV1::Class { class_id: 1 },
        operation_profile: 1,
        entitlement_profile: 2,
        limits: EntitlementLimitsV1 {
            max_logical_inputs: 4,
            max_frames: 200,
            max_request_bytes: 1_000_000,
            max_response_bytes: 2_000_000,
            max_wall_time_ms: 60_000,
            max_concurrent_sockets: 1,
            max_hint_groups: 0,
            max_work_units: 9_000,
        },
        priority_class: 1,
        deployment_status: DeploymentStatus::Stable,
        price_msat: 2_000,
        issuer_endpoint: "https://issuer.invalid".into(),
        invoice_expiry_seconds: 60,
        claim_window_seconds: 120,
        minimum_credential_validity_seconds: 300,
        retired_policy_grace_seconds: 480,
        credential_count: 2,
        credential_presentation_limit: 1,
        privacy_leakage: PrivacyLeakageV1::from_bits(
            PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING
                | PrivacyLeakageV1::ISSUER_REDEMPTION_TIMING
                | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER,
        )
        .unwrap(),
    }
}

fn member(policy_byte: u8, scope_byte: u8, offer_id: u32) -> BatAcceptanceMemberV2 {
    BatAcceptanceMemberV2 {
        provider_id: [2; 32],
        policy_digest: [policy_byte; 32],
        scope_id: [scope_byte; 32],
        offer_id,
    }
}

struct Fixture {
    class: BatAcceptanceClassV2,
    selected: VerifiedBatAcceptanceMemberV2,
    class_only: VerifiedBatAcceptanceMemberV2,
    authorization: ProviderAccountingAuthorizationV2,
    approval: IssuerAccountingApprovalV2,
    operator_key: SigningKey,
    settlement_key: SigningKey,
    clearing_key: SigningKey,
}

impl Fixture {
    fn new() -> Self {
        let class_signing_key = SigningKey::from_bytes(&[8; 32]);
        let operator_key = SigningKey::from_bytes(&[11; 32]);
        let settlement_key = SigningKey::from_bytes(&[24; 32]);
        let clearing_key = SigningKey::from_bytes(&[6; 32]);
        let members = vec![member(8, 9, 10), member(18, 19, 20)];
        let class = BatAcceptanceClassV2::sign(
            [7; 32],
            13,
            100,
            1_480,
            SECP_GENERATOR,
            terms(),
            members.clone(),
            &class_signing_key,
        )
        .unwrap();
        let issuer_id = class.issuer_id;
        let class_id = class.class_id;
        let common_terms = class.common_terms.clone();
        let verified = |member: BatAcceptanceMemberV2| VerifiedBatAcceptanceMemberV2 {
            issuer_id,
            class_id,
            member,
            common_terms: common_terms.clone(),
            policy_issued_at: 100,
            policy_expires_at: 1_000,
            redemption_deadline: 1_480,
        };
        let authorization = ProviderAccountingAuthorizationV2::sign(
            ProviderAccountingAuthorizationClaimsV2 {
                authorization_id: [1; 16],
                authorization_epoch: 7,
                provider_id: [2; 32],
                issuer_id: class.issuer_id,
                redeem_endpoint: "https://issuer.invalid".into(),
                redeem_leaf_spki_sha256_pins: vec![[4; 32]],
                settlement_account_id: [5; 32],
                clearing_verifying_key: clearing_key.verifying_key().to_bytes(),
                not_before: 100,
                not_after: 1_000,
                rules: vec![
                    ProviderAccountingRuleV2 {
                        class_id: class.class_id,
                        policy_digest: members[0].policy_digest,
                        scope_id: members[0].scope_id,
                        offer_id: members[0].offer_id,
                        unit: SettlementUnitV1::AuthCredit,
                        accepted_value: 10,
                        provider_credit: 8,
                        issuer_fee: 2,
                    },
                    ProviderAccountingRuleV2 {
                        class_id: class.class_id,
                        policy_digest: members[1].policy_digest,
                        scope_id: members[1].scope_id,
                        offer_id: members[1].offer_id,
                        unit: SettlementUnitV1::AuthCredit,
                        accepted_value: 10,
                        provider_credit: 8,
                        issuer_fee: 2,
                    },
                ],
            },
            &operator_key,
        )
        .unwrap();
        let approval =
            IssuerAccountingApprovalV2::sign(&authorization, 150, 900, &settlement_key).unwrap();
        Self {
            class,
            selected: verified(members[0].clone()),
            class_only: verified(members[1].clone()),
            authorization,
            approval,
            operator_key,
            settlement_key,
            clearing_key,
        }
    }

    fn proof(&self) -> BitcoinPirCashuBatProofV2 {
        BitcoinPirCashuBatProofV2::from_class(&self.class, [15; 32], SECP_GENERATOR).unwrap()
    }

    fn trust(&self) -> BatV2ProviderRedeemTrustV2 {
        BatV2ProviderRedeemTrustV2 {
            expected_provider_id: [2; 32],
            expected_issuer_id: self.class.issuer_id,
            authorization: self.authorization.clone(),
            issuer_approval: self.approval.clone(),
            operator_verifying_key: self.operator_key.verifying_key(),
            issuer_settlement_verifying_key: self.settlement_key.verifying_key(),
            minimum_authorization_epoch: 7,
        }
    }

    fn class_with_validity(&self, key_not_before: u64, key_not_after: u64) -> BatAcceptanceClassV2 {
        BatAcceptanceClassV2::sign(
            self.class.class_id,
            self.class.key_epoch,
            key_not_before,
            key_not_after,
            self.class.bat_verification_key,
            self.class.common_terms.clone(),
            self.class.members.clone(),
            &SigningKey::from_bytes(&[8; 32]),
        )
        .unwrap()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Normal,
    DefinitelyNotSent,
    OutcomeUnknown,
    InvalidBody,
    Oversize,
    ReplayPrevious,
    BadSignature,
    RetryProviderAuthentication,
    RetryClassCompatibility,
}

#[derive(Debug)]
struct Observation {
    attempt_id: [u8; 32],
    endpoint: &'static str,
    request_content_type: &'static str,
    response_content_type: &'static str,
    max_response_bytes: usize,
}

#[derive(Default)]
struct MemoryCommitStore {
    attempts: HashSet<([u8; 32], [u8; 32])>,
    spends: HashSet<[u8; 32]>,
}

impl BatV2RedeemCommitStoreV2 for MemoryCommitStore {
    type Error = ();

    fn attempt_is_committed(
        &self,
        request: &pir_service_protocol::ProviderRedeemRequestV2,
    ) -> Result<bool, Self::Error> {
        Ok(self
            .attempts
            .contains(&(request.provider_id, request.attempt_id)))
    }

    fn commit_fresh(
        &mut self,
        verified: &VerifiedBatV2RedeemCommitV2,
        _signed_initial_success: &ProviderRedeemResponseV2,
    ) -> Result<bool, Self::Error> {
        let attempt = (
            verified.request().provider_id,
            verified.request().attempt_id,
        );
        if self.attempts.contains(&attempt) || self.spends.contains(verified.global_spend_key()) {
            return Ok(false);
        }
        self.attempts.insert(attempt);
        self.spends.insert(*verified.global_spend_key());
        Ok(true)
    }
}

struct TestIssuerTransport {
    fixture: Fixture,
    mode: Mutex<Mode>,
    store: Mutex<MemoryCommitStore>,
    observations: Mutex<Vec<Observation>>,
    previous_response: Mutex<Option<Vec<u8>>>,
}

struct AlwaysValidProof;

impl BatV2ProofVerifierV2 for AlwaysValidProof {
    type Error = ();

    fn verify_bat_v2_proof(
        &self,
        _input: BatV2ProofVerificationInputV2<'_>,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

impl TestIssuerTransport {
    fn new() -> Self {
        Self {
            fixture: Fixture::new(),
            mode: Mutex::new(Mode::Normal),
            store: Mutex::new(MemoryCommitStore::default()),
            observations: Mutex::new(Vec::new()),
            previous_response: Mutex::new(None),
        }
    }

    fn set_mode(&self, mode: Mode) {
        *self.mode.lock().unwrap() = mode;
    }

    fn response_for(
        &self,
        envelope: ProviderRedeemEnvelopeV2,
        mode: Mode,
    ) -> ProviderRedeemResponseV2 {
        let (member, now_unix) = match mode {
            Mode::RetryProviderAuthentication => (&self.fixture.selected, 1_001),
            Mode::RetryClassCompatibility => (&self.fixture.class_only, NOW),
            _ => (&self.fixture.selected, NOW),
        };
        let precheck = precheck_bat_v2_redeem_v2(
            envelope,
            &self.fixture.authorization,
            &self.fixture.approval,
            &self.fixture.class,
            member,
            ProviderAccountingExpectationV2 {
                provider_id: [2; 32],
                issuer_id: self.fixture.class.issuer_id,
                operator_verifying_key: &self.fixture.operator_key.verifying_key(),
                issuer_settlement_verifying_key: &self.fixture.settlement_key.verifying_key(),
                now_unix,
                minimum_authorization_epoch: 7,
            },
        )
        .unwrap();
        match precheck {
            BatV2RedeemPrecheckV2::RetrySafeNonConsuming(retry) => {
                sign_retry_safe_non_consuming_v2(retry, &self.fixture.settlement_key).unwrap()
            }
            BatV2RedeemPrecheckV2::TerminalInvalidOrSpent(terminal) => {
                sign_terminal_invalid_or_spent_v2(terminal, &self.fixture.settlement_key).unwrap()
            }
            BatV2RedeemPrecheckV2::Authorized(authorized) => {
                let checked =
                    verify_bat_v2_credential_for_commit_v2(*authorized, &AlwaysValidProof).unwrap();
                match checked {
                    BatV2CredentialCheckV2::Verified(verified) => {
                        let mut store = self.store.lock().unwrap();
                        match sign_and_commit_grantable_success_v2(
                            verified,
                            &self.fixture.settlement_key,
                            &mut *store,
                        )
                        .unwrap()
                        {
                            BatV2RedeemCommitResultV2::FreshCommitted(fresh) => {
                                fresh.into_response()
                            }
                            BatV2RedeemCommitResultV2::TerminalInvalidOrSpent(response) => response,
                        }
                    }
                    BatV2CredentialCheckV2::TerminalInvalidOrSpent(terminal) => {
                        sign_terminal_invalid_or_spent_v2(terminal, &self.fixture.settlement_key)
                            .unwrap()
                    }
                }
            }
        }
    }
}

impl BatV2RedeemTransportV2 for TestIssuerTransport {
    fn redeem_v2(
        &self,
        request: BatV2RedeemHttpRequestV2<'_>,
        max_response_bytes: usize,
    ) -> Result<Vec<u8>, BatV2RedeemTransportErrorV2> {
        assert_eq!(request.issuer_origin, "https://issuer.invalid");
        assert_eq!(request.leaf_spki_sha256_pins, &[[4; 32]]);
        let envelope = ProviderRedeemEnvelopeV2::decode(request.canonical_envelope).unwrap();
        self.observations.lock().unwrap().push(Observation {
            attempt_id: envelope.request.attempt_id,
            endpoint: request.endpoint,
            request_content_type: request.request_content_type,
            response_content_type: request.response_content_type,
            max_response_bytes,
        });
        let mode = *self.mode.lock().unwrap();
        match mode {
            Mode::DefinitelyNotSent => {
                return Err(BatV2RedeemTransportErrorV2::DefinitelyNotSent { retry_after_ms: 17 })
            }
            Mode::OutcomeUnknown => return Err(BatV2RedeemTransportErrorV2::OutcomeUnknown),
            Mode::InvalidBody => return Ok(vec![0x55; 32]),
            Mode::Oversize => return Ok(vec![0; max_response_bytes + 1]),
            Mode::ReplayPrevious => {
                return Ok(self
                    .previous_response
                    .lock()
                    .unwrap()
                    .clone()
                    .expect("previous signed response"))
            }
            _ => {}
        }
        envelope
            .request_auth
            .verify_for(
                &envelope.request,
                &self.fixture.clearing_key.verifying_key(),
            )
            .unwrap();
        let response = self.response_for(envelope, mode);
        let mut encoded = response.encode().unwrap();
        if mode == Mode::BadSignature {
            *encoded.last_mut().unwrap() ^= 1;
        } else {
            *self.previous_response.lock().unwrap() = Some(encoded.clone());
        }
        Ok(encoded)
    }
}

fn client<'a>(transport: &'a TestIssuerTransport) -> StorelessBatV2ProviderRedeemClientV2<'a> {
    StorelessBatV2ProviderRedeemClientV2::new(
        transport.fixture.trust(),
        transport.fixture.clearing_key.clone(),
        transport,
    )
    .unwrap()
}

#[test]
fn bat_v2_storeless_fresh_grant_once_then_global_spend_is_terminal() {
    let transport = TestIssuerTransport::new();
    let client = client(&transport);
    let proof = transport.fixture.proof();
    assert!(matches!(
        client
            .redeem_once(
                &transport.fixture.selected,
                &transport.fixture.class,
                &proof,
                NOW,
            )
            .unwrap(),
        StorelessBatV2RedeemDecisionV2::FreshGrant(_)
    ));
    assert!(matches!(
        client
            .redeem_once(
                &transport.fixture.selected,
                &transport.fixture.class,
                &proof,
                NOW,
            )
            .unwrap(),
        StorelessBatV2RedeemDecisionV2::TerminalInvalidOrSpent
    ));
    let observations = transport.observations.lock().unwrap();
    assert_eq!(observations.len(), 2);
    assert_ne!(observations[0].attempt_id, [0; 32]);
    assert_ne!(observations[0].attempt_id, observations[1].attempt_id);
    for observation in observations.iter() {
        assert_eq!(observation.endpoint, BAT_V2_REDEEM_ENDPOINT_V2);
        assert_eq!(
            observation.request_content_type,
            BAT_V2_REDEEM_REQUEST_CONTENT_TYPE_V2
        );
        assert_eq!(
            observation.response_content_type,
            BAT_V2_REDEEM_RESPONSE_CONTENT_TYPE_V2
        );
        assert_eq!(
            observation.max_response_bytes,
            MAX_BAT_V2_PROVIDER_REDEEM_RESPONSE_LEN_V2
        );
    }
}

#[test]
fn bat_v2_storeless_definitely_not_sent_never_retries_automatically() {
    let transport = TestIssuerTransport::new();
    let client = client(&transport);
    let proof = transport.fixture.proof();
    transport.set_mode(Mode::DefinitelyNotSent);
    assert!(matches!(
        client
            .redeem_once(
                &transport.fixture.selected,
                &transport.fixture.class,
                &proof,
                NOW,
            )
            .unwrap(),
        StorelessBatV2RedeemDecisionV2::DefinitelyNotSent { retry_after_ms: 17 }
    ));
    assert_eq!(transport.observations.lock().unwrap().len(), 1);
    transport.set_mode(Mode::Normal);
    assert!(matches!(
        client
            .redeem_once(
                &transport.fixture.selected,
                &transport.fixture.class,
                &proof,
                NOW,
            )
            .unwrap(),
        StorelessBatV2RedeemDecisionV2::FreshGrant(_)
    ));
    let observations = transport.observations.lock().unwrap();
    assert_ne!(observations[0].attempt_id, observations[1].attempt_id);
}

#[test]
fn bat_v2_storeless_signed_retry_safe_reasons_preserve_the_proof() {
    for (mode, expected) in [
        (
            Mode::RetryProviderAuthentication,
            RetrySafeNonConsumingReasonV2::ProviderAuthentication,
        ),
        (
            Mode::RetryClassCompatibility,
            RetrySafeNonConsumingReasonV2::ClassCompatibility,
        ),
    ] {
        let transport = TestIssuerTransport::new();
        let client = client(&transport);
        let proof = transport.fixture.proof();
        transport.set_mode(mode);
        let decision = client
            .redeem_once(
                &transport.fixture.selected,
                &transport.fixture.class,
                &proof,
                NOW,
            )
            .unwrap();
        assert!(
            matches!(
                &decision,
                StorelessBatV2RedeemDecisionV2::RetrySafeNonConsuming(reason)
                    if *reason == expected
            ),
            "mode {mode:?} returned {decision:?}"
        );
        assert_eq!(transport.observations.lock().unwrap().len(), 1);
        transport.set_mode(Mode::Normal);
        assert!(matches!(
            client
                .redeem_once(
                    &transport.fixture.selected,
                    &transport.fixture.class,
                    &proof,
                    NOW,
                )
                .unwrap(),
            StorelessBatV2RedeemDecisionV2::FreshGrant(_)
        ));
    }
}

#[test]
fn bat_v2_storeless_unsigned_or_stale_responses_burn_and_never_grant() {
    for mode in [
        Mode::OutcomeUnknown,
        Mode::InvalidBody,
        Mode::Oversize,
        Mode::BadSignature,
    ] {
        let transport = TestIssuerTransport::new();
        let client = client(&transport);
        transport.set_mode(mode);
        assert!(matches!(
            client.redeem_once(
                &transport.fixture.selected,
                &transport.fixture.class,
                &transport.fixture.proof(),
                NOW,
            ),
            Err(StorelessBatV2RedeemErrorV2::OutcomeUnknownCredentialBurned)
        ));
        assert_eq!(transport.observations.lock().unwrap().len(), 1);
    }

    let transport = TestIssuerTransport::new();
    let client = client(&transport);
    let first_proof = transport.fixture.proof();
    assert!(matches!(
        client
            .redeem_once(
                &transport.fixture.selected,
                &transport.fixture.class,
                &first_proof,
                NOW,
            )
            .unwrap(),
        StorelessBatV2RedeemDecisionV2::FreshGrant(_)
    ));
    transport.set_mode(Mode::ReplayPrevious);
    assert!(matches!(
        client.redeem_once(
            &transport.fixture.selected,
            &transport.fixture.class,
            &transport.fixture.proof(),
            NOW,
        ),
        Err(StorelessBatV2RedeemErrorV2::OutcomeUnknownCredentialBurned)
    ));
}

#[test]
fn bat_v2_storeless_constructor_and_presend_checks_fail_closed() {
    let transport = TestIssuerTransport::new();
    let mut wrong_provider = transport.fixture.trust();
    wrong_provider.expected_provider_id = [99; 32];
    assert!(StorelessBatV2ProviderRedeemClientV2::new(
        wrong_provider,
        transport.fixture.clearing_key.clone(),
        &transport,
    )
    .is_err());

    let mut rollback = transport.fixture.trust();
    rollback.minimum_authorization_epoch = 8;
    assert!(StorelessBatV2ProviderRedeemClientV2::new(
        rollback,
        transport.fixture.clearing_key.clone(),
        &transport,
    )
    .is_err());

    assert!(StorelessBatV2ProviderRedeemClientV2::new(
        transport.fixture.trust(),
        SigningKey::from_bytes(&[77; 32]),
        &transport,
    )
    .is_err());

    let mut reused_role = transport.fixture.trust();
    reused_role.issuer_settlement_verifying_key = transport.fixture.clearing_key.verifying_key();
    assert!(StorelessBatV2ProviderRedeemClientV2::new(
        reused_role,
        transport.fixture.clearing_key.clone(),
        &transport,
    )
    .is_err());

    let client = client(&transport);
    assert!(StorelessBatV2AdmissionCommitterV2::new(
        &transport.fixture.selected,
        &transport.fixture.class,
        &client,
    )
    .is_ok());
    let mut wrong_member = transport.fixture.selected.clone();
    wrong_member.member.offer_id += 1;
    assert!(StorelessBatV2AdmissionCommitterV2::new(
        &wrong_member,
        &transport.fixture.class,
        &client,
    )
    .is_err());
    let mut extended_deadline = transport.fixture.selected.clone();
    extended_deadline.redemption_deadline += 1;
    assert!(StorelessBatV2AdmissionCommitterV2::new(
        &extended_deadline,
        &transport.fixture.class,
        &client,
    )
    .is_err());
    let starts_after_policy = transport.fixture.class_with_validity(101, 1_480);
    assert!(StorelessBatV2AdmissionCommitterV2::new(
        &transport.fixture.selected,
        &starts_after_policy,
        &client,
    )
    .is_err());
    let short_by_one = transport.fixture.class_with_validity(100, 1_479);
    assert!(StorelessBatV2AdmissionCommitterV2::new(
        &transport.fixture.selected,
        &short_by_one,
        &client,
    )
    .is_err());
    let extends_past_redemption = transport.fixture.class_with_validity(100, 1_481);
    assert!(StorelessBatV2AdmissionCommitterV2::new(
        &transport.fixture.selected,
        &extends_past_redemption,
        &client,
    )
    .is_err());
    let overflow_class = transport.fixture.class_with_validity(100, u64::MAX);
    let mut overflow_member = transport.fixture.selected.clone();
    overflow_member.policy_expires_at = u64::MAX - 100;
    overflow_member.redemption_deadline = u64::MAX;
    assert!(matches!(
        StorelessBatV2AdmissionCommitterV2::new(&overflow_member, &overflow_class, &client),
        Err(ServiceProtocolError::InvalidValue {
            field: "VerifiedBatAcceptanceMemberV2.class_projection",
            reason: "minimum class validity horizon overflows",
        })
    ));
    assert!(matches!(
        client.redeem_once(
            &transport.fixture.selected,
            &transport.fixture.class,
            &transport.fixture.proof(),
            1_001,
        ),
        Err(StorelessBatV2RedeemErrorV2::PreSend(_))
    ));
    assert!(transport.observations.lock().unwrap().is_empty());
    let debug = format!("{client:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains(&format!("{:?}", [6u8; 32])));
}
