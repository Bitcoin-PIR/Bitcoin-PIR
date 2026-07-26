use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use pir_service_protocol::{
    derive_cashu_keyset_id_v2, AcquisitionMethod, AuthPaddingClassV1, AuthScheme, BackendId,
    CashuDenominationKeyV1, CashuKeysetBindingV1, CashuRequiredNutsV1, DatasetBindingV1,
    DeploymentStatus, EntitlementLimitsV1, FreeModeV1, PolicyRollbackGuardV1, PriceV1,
    PrivacyLeakageV1, ServiceOfferV1, ServicePolicyEpochFloorsV1, ServicePolicyV1,
    ServiceScopePolicyV1, ServiceScopeV1, StandardCashuMintManifestV1, StandardCashuProofV1,
    VerificationMode, VerifiedServiceOfferV1, WorkloadId,
};
use pir_service_store::{
    ProviderStore, RollbackFloorAuthorityErrorV1, RollbackFloorAuthorityV1, RollbackFloorV1,
    StoreOptions,
};

use super::*;
use crate::dto::{
    CashuBlindSignatureJsonV1, CashuDleqJsonV1, CashuPostCheckStateResponseJsonV1,
    CashuProofStateEntryJsonV1,
};

#[derive(Debug, Default)]
struct ProviderStoreTestAuthorityV1 {
    floor: Mutex<Option<RollbackFloorV1>>,
    lose_response_at_generation: AtomicU64,
}

impl ProviderStoreTestAuthorityV1 {
    fn lose_response_at(&self, generation: u64) {
        self.lose_response_at_generation
            .store(generation, Ordering::SeqCst);
    }

    fn floor(&self) -> RollbackFloorV1 {
        self.floor.lock().unwrap().unwrap()
    }
}

impl RollbackFloorAuthorityV1 for ProviderStoreTestAuthorityV1 {
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
        Ok(floor.unwrap())
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
        let current = floor
            .ok_or_else(|| RollbackFloorAuthorityErrorV1::new("rollback floor disappeared"))?;
        if next.store_generation != 0
            && self
                .lose_response_at_generation
                .compare_exchange(next.store_generation, 0, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            return Err(RollbackFloorAuthorityErrorV1::new(
                "injected lost CAS response",
            ));
        }
        Ok(current)
    }
}

fn create_provider_store_for_fixture(
    path: &std::path::Path,
    provider_id: [u8; 32],
    authority: Arc<ProviderStoreTestAuthorityV1>,
) -> ProviderStore {
    ProviderStore::create(
        path,
        [0xd1; 16],
        provider_id,
        StoreOptions::default(),
        authority,
    )
    .unwrap()
}

#[derive(Debug)]
struct TestRecoveryCipherV1 {
    nonce: AtomicU64,
    key: [u8; 32],
}

impl Default for TestRecoveryCipherV1 {
    fn default() -> Self {
        Self {
            nonce: AtomicU64::new(1),
            key: [0xa5; 32],
        }
    }
}

impl CashuRecoveryCipherV1 for TestRecoveryCipherV1 {
    fn seal(
        &self,
        aad: &CashuRecoveryAadV1,
        plaintext: &[u8],
    ) -> Result<CashuSealedRecoveryV1, CashuRecoveryCipherErrorV1> {
        let nonce = self.nonce.fetch_add(1, Ordering::SeqCst).to_le_bytes();
        let mut ciphertext = plaintext
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ self.key[index % self.key.len()])
            .collect::<Vec<_>>();
        let tag = test_cipher_tag(&self.key, &aad.encode(), &nonce, &ciphertext);
        ciphertext.extend_from_slice(&tag);
        Ok(CashuSealedRecoveryV1 {
            key_epoch: 1,
            nonce: nonce.to_vec(),
            ciphertext,
        })
    }

    fn open(
        &self,
        aad: &CashuRecoveryAadV1,
        sealed: &CashuSealedRecoveryV1,
    ) -> Result<Vec<u8>, CashuRecoveryCipherErrorV1> {
        if sealed.key_epoch != 1 || sealed.ciphertext.len() < 32 {
            return Err(CashuRecoveryCipherErrorV1::UnknownKeyEpoch);
        }
        let split = sealed.ciphertext.len() - 32;
        let (ciphertext, tag) = sealed.ciphertext.split_at(split);
        let expected = test_cipher_tag(&self.key, &aad.encode(), &sealed.nonce, ciphertext);
        if tag != expected {
            return Err(CashuRecoveryCipherErrorV1::AuthenticationFailed);
        }
        Ok(ciphertext
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ self.key[index % self.key.len()])
            .collect())
    }
}

fn test_cipher_tag(key: &[u8; 32], aad: &[u8], nonce: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BitcoinPIR/test-only-cashu-recovery-cipher/v1");
    hasher.update(key);
    hasher.update(aad);
    hasher.update(nonce);
    hasher.update(ciphertext);
    hasher.finalize().into()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SwapReply {
    Normal,
    TimeoutCommitted,
    TimeoutUncommitted,
    NotFoundUncommitted,
    InvalidJsonCommitted,
    BadDleqCommitted,
    WrongOrderCommitted,
    WrongAmountCommitted,
    WrongKeysetCommitted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RestoreReply {
    Stored,
    Empty,
    Partial,
    Timeout,
    NotFound,
    InvalidJson,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CheckReply {
    Uniform(CashuProofStateJsonV1),
    Exact(Vec<CashuProofStateJsonV1>),
    Timeout,
    InvalidJson,
}

struct FakeMintState {
    swap_reply: SwapReply,
    restore_reply: RestoreReply,
    check_reply: CheckReply,
    submitted_request: Option<CashuPostSwapRequestJsonV1>,
    stored_response: Option<CashuPostSwapResponseJsonV1>,
    last_restore_outputs: Option<Vec<CashuBlindedMessageJsonV1>>,
    swap_calls: usize,
    restore_calls: usize,
    check_calls: usize,
}

struct FakeMintTransportV1 {
    state: Mutex<FakeMintState>,
}

impl FakeMintTransportV1 {
    fn new(swap_reply: SwapReply, restore_reply: RestoreReply, check_reply: CheckReply) -> Self {
        Self {
            state: Mutex::new(FakeMintState {
                swap_reply,
                restore_reply,
                check_reply,
                submitted_request: None,
                stored_response: None,
                last_restore_outputs: None,
                swap_calls: 0,
                restore_calls: 0,
                check_calls: 0,
            }),
        }
    }

    fn calls(&self) -> (usize, usize, usize) {
        let state = self.state.lock().unwrap();
        (state.swap_calls, state.restore_calls, state.check_calls)
    }

    fn submitted_and_restored_outputs_match(&self) -> bool {
        let state = self.state.lock().unwrap();
        state
            .submitted_request
            .as_ref()
            .map(|request| &request.outputs)
            == state.last_restore_outputs.as_ref()
    }

    fn set_restore_reply(&self, reply: RestoreReply) {
        self.state.lock().unwrap().restore_reply = reply;
    }

    fn commit_pending(&self) {
        let mut state = self.state.lock().unwrap();
        let request = state.submitted_request.clone().unwrap();
        state.stored_response = Some(valid_mint_response(&request));
        state.check_reply = CheckReply::Uniform(CashuProofStateJsonV1::Spent);
    }
}

impl CashuMintTransportV1 for FakeMintTransportV1 {
    fn post_json(
        &self,
        mint_endpoint: &str,
        route: CashuMintRouteV1,
        request_json: &[u8],
        max_response_bytes: usize,
    ) -> Result<Vec<u8>, CashuMintTransportFailureV1> {
        assert_eq!(mint_endpoint, "https://mint.example");
        assert_eq!(max_response_bytes, MAX_CASHU_MINT_JSON_BYTES_V1);
        let mut state = self.state.lock().unwrap();
        match route {
            CashuMintRouteV1::Swap => {
                state.swap_calls += 1;
                let request: CashuPostSwapRequestJsonV1 = decode_json_v1(request_json).unwrap();
                let mut response = valid_mint_response(&request);
                match state.swap_reply {
                    SwapReply::BadDleqCommitted => {
                        response.signatures[0].dleq.s.replace_range(62..64, "00");
                    }
                    SwapReply::WrongOrderCommitted => response.signatures.reverse(),
                    SwapReply::WrongAmountCommitted => response.signatures[0].amount += 1,
                    SwapReply::WrongKeysetCommitted => {
                        response.signatures[0].id.replace_range(2..4, "ff");
                    }
                    _ => {}
                }
                state.submitted_request = Some(request);
                match state.swap_reply {
                    SwapReply::Normal
                    | SwapReply::TimeoutCommitted
                    | SwapReply::InvalidJsonCommitted
                    | SwapReply::BadDleqCommitted
                    | SwapReply::WrongOrderCommitted
                    | SwapReply::WrongAmountCommitted
                    | SwapReply::WrongKeysetCommitted => {
                        state.stored_response = Some(response.clone());
                        state.check_reply = CheckReply::Uniform(CashuProofStateJsonV1::Spent);
                    }
                    SwapReply::TimeoutUncommitted | SwapReply::NotFoundUncommitted => {}
                }
                match state.swap_reply {
                    SwapReply::Normal
                    | SwapReply::BadDleqCommitted
                    | SwapReply::WrongOrderCommitted
                    | SwapReply::WrongAmountCommitted
                    | SwapReply::WrongKeysetCommitted => Ok(encode_json_v1(&response).unwrap()),
                    SwapReply::InvalidJsonCommitted => Ok(b"{".to_vec()),
                    SwapReply::TimeoutCommitted | SwapReply::TimeoutUncommitted => {
                        Err(transport_failure(CashuMintTransportFailureKindV1::Timeout))
                    }
                    SwapReply::NotFoundUncommitted => Err(CashuMintTransportFailureV1 {
                        kind: CashuMintTransportFailureKindV1::NotFound,
                        http_status: Some(404),
                    }),
                }
            }
            CashuMintRouteV1::Restore => {
                state.restore_calls += 1;
                let request: CashuPostRestoreRequestJsonV1 = decode_json_v1(request_json).unwrap();
                state.last_restore_outputs = Some(request.outputs.clone());
                match state.restore_reply {
                    RestoreReply::Stored => {
                        let Some(response) = state.stored_response.clone() else {
                            return Ok(encode_json_v1(&CashuPostRestoreResponseJsonV1 {
                                outputs: Vec::new(),
                                signatures: Vec::new(),
                            })
                            .unwrap());
                        };
                        let outputs = state.submitted_request.as_ref().unwrap().outputs.clone();
                        Ok(encode_json_v1(&CashuPostRestoreResponseJsonV1 {
                            outputs,
                            signatures: response.signatures,
                        })
                        .unwrap())
                    }
                    RestoreReply::Empty => Ok(encode_json_v1(&CashuPostRestoreResponseJsonV1 {
                        outputs: Vec::new(),
                        signatures: Vec::new(),
                    })
                    .unwrap()),
                    RestoreReply::Partial => {
                        let response = state.stored_response.as_ref().unwrap();
                        let output = state
                            .submitted_request
                            .as_ref()
                            .unwrap()
                            .outputs
                            .first()
                            .unwrap()
                            .clone();
                        Ok(encode_json_v1(&CashuPostRestoreResponseJsonV1 {
                            outputs: vec![output],
                            signatures: vec![response.signatures[0].clone()],
                        })
                        .unwrap())
                    }
                    RestoreReply::Timeout => {
                        Err(transport_failure(CashuMintTransportFailureKindV1::Timeout))
                    }
                    RestoreReply::NotFound => Err(CashuMintTransportFailureV1 {
                        kind: CashuMintTransportFailureKindV1::NotFound,
                        http_status: Some(404),
                    }),
                    RestoreReply::InvalidJson => Ok(b"not-json".to_vec()),
                }
            }
            CashuMintRouteV1::CheckState => {
                state.check_calls += 1;
                let request: CashuPostCheckStateRequestJsonV1 =
                    decode_json_v1(request_json).unwrap();
                let states = match &state.check_reply {
                    CheckReply::Uniform(proof_state) => {
                        vec![*proof_state; request.ys.len()]
                    }
                    CheckReply::Exact(proof_states) => proof_states.clone(),
                    CheckReply::Timeout => {
                        return Err(transport_failure(CashuMintTransportFailureKindV1::Timeout))
                    }
                    CheckReply::InvalidJson => return Ok(b"[]".to_vec()),
                };
                Ok(encode_json_v1(&CashuPostCheckStateResponseJsonV1 {
                    states: request
                        .ys
                        .into_iter()
                        .zip(states)
                        .map(|(y, proof_state)| CashuProofStateEntryJsonV1 {
                            y,
                            state: proof_state,
                            witness: None,
                        })
                        .collect(),
                })
                .unwrap())
            }
        }
    }
}

fn transport_failure(kind: CashuMintTransportFailureKindV1) -> CashuMintTransportFailureV1 {
    CashuMintTransportFailureV1 {
        kind,
        http_status: None,
    }
}

struct Fixture {
    spend: StandardCashuSpendV1,
    checked: StandardCashuSpendCheckV1,
    manifest: StandardCashuMintManifestV1,
    policy: ServicePolicyV1,
    policy_key: SigningKey,
}

impl Fixture {
    fn verified_offer(&self) -> VerifiedServiceOfferV1<'_> {
        let verified_policy = self
            .policy
            .verify_current_for_acquisition(
                &self.policy.provider_id,
                100,
                &PolicyRollbackGuardV1::initial(),
                &ServicePolicyEpochFloorsV1::initial(),
                &self.policy_key.verifying_key(),
            )
            .unwrap();
        verified_policy
            .offer(&self.policy.scopes[0].scope.scope_id(), 17)
            .unwrap()
    }
}

fn fixture(price: u64) -> Fixture {
    assert!((1..=3).contains(&price));
    let keys = [1u64, 2, 4]
        .into_iter()
        .map(|amount| CashuDenominationKeyV1 {
            amount,
            public_key: mint_public_key(amount),
        })
        .collect::<Vec<_>>();
    let keyset = CashuKeysetBindingV1 {
        keyset_id: derive_cashu_keyset_id_v2(&keys, "sat", 0, Some(100_000)).unwrap(),
        unit: "sat".to_owned(),
        input_fee_ppk: 0,
        final_expiry: Some(100_000),
        keys,
    };
    let manifest = StandardCashuMintManifestV1 {
        manifest_epoch: 1,
        mint_endpoint: "https://mint.example".to_owned(),
        unit: "sat".to_owned(),
        required_nuts: CashuRequiredNutsV1::required_v1(),
        accepted_input_keysets: vec![keyset.clone()],
        active_output_keyset: keyset.clone(),
    };
    manifest.encode().unwrap();
    let mut proofs = Vec::new();
    if price & 1 != 0 {
        proofs.push(StandardCashuProofV1 {
            keyset_id: keyset.keyset_id.clone(),
            amount: 1,
            secret: "input-secret-one".to_owned(),
            c: compressed_point(&(ProjectivePoint::GENERATOR * Scalar::from(51u64))),
        });
    }
    if price & 2 != 0 {
        proofs.push(StandardCashuProofV1 {
            keyset_id: keyset.keyset_id,
            amount: 2,
            secret: "input-secret-two".to_owned(),
            c: compressed_point(&(ProjectivePoint::GENERATOR * Scalar::from(52u64))),
        });
    }
    let spend = StandardCashuSpendV1::new_canonical(proofs).unwrap();
    let provider_id = [0x51; 32];
    let scope = ServiceScopeV1 {
        provider_id,
        backend: BackendId::DpfPirV1,
        workload: WorkloadId::DpfEvaluateJobV1,
        protocol_version: 1,
        dataset: DatasetBindingV1::Class { class_id: 2 },
        operation_profile: 1,
        entitlement_profile: 8,
    };
    let offer = ServiceOfferV1 {
        offer_id: 17,
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
            unit: "sat".to_owned(),
            amount: price,
        },
        issuer_id: manifest.mint_id(),
        key_id: manifest.manifest_digest().unwrap().to_vec(),
        credential_binding: None,
        cashu_mint_manifest: Some(manifest.clone()),
        endpoint: manifest.mint_endpoint.clone(),
        invoice_expiry_seconds: 0,
        claim_window_seconds: 0,
        minimum_credential_validity_seconds: 100,
        retired_policy_grace_seconds: 100,
        credential_count: 1,
        credential_presentation_limit: 1,
        privacy_leakage: PrivacyLeakageV1::from_bits(
            PrivacyLeakageV1::ISSUER_REDEMPTION_TIMING | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER,
        )
        .unwrap(),
    };
    let policy_key = SigningKey::from_bytes(&[0x52; 32]);
    let policy = ServicePolicyV1::sign(
        provider_id,
        1,
        100,
        10_000,
        AuthPaddingClassV1::Class16KiB,
        vec![ServiceScopePolicyV1 {
            scope,
            limits: EntitlementLimitsV1 {
                max_logical_inputs: 1,
                max_frames: 10,
                max_request_bytes: 1_000,
                max_response_bytes: 2_000,
                max_wall_time_ms: 1_000,
                max_concurrent_sockets: 1,
                max_hint_groups: 0,
                max_work_units: 100,
            },
            offers: vec![offer],
        }],
        &policy_key,
    )
    .unwrap();
    let verified_policy = policy
        .verify_current_for_acquisition(
            &provider_id,
            100,
            &PolicyRollbackGuardV1::initial(),
            &ServicePolicyEpochFloorsV1::initial(),
            &policy_key.verifying_key(),
        )
        .unwrap();
    let verified_offer = verified_policy
        .offer(&policy.scopes[0].scope.scope_id(), 17)
        .unwrap();
    let checked = check_standard_cashu_spend_for_offer(&spend, &verified_offer, 100).unwrap();
    Fixture {
        spend,
        checked,
        manifest,
        policy,
        policy_key,
    }
}

fn output_materials(price: u64, tweak: u8) -> Vec<CashuOutputMaterialV1> {
    let mut outputs = Vec::new();
    if price & 1 != 0 {
        outputs.push(CashuOutputMaterialV1::new(
            1,
            [tweak.wrapping_add(1); 32],
            scalar_bytes(u64::from(tweak) + 7),
        ));
    }
    if price & 2 != 0 {
        outputs.push(CashuOutputMaterialV1::new(
            2,
            [tweak.wrapping_add(2); 32],
            scalar_bytes(u64::from(tweak) + 11),
        ));
    }
    outputs
}

fn client<'a>(
    store: &'a InsecureDevSqliteCashuSwapStoreV1,
    mint: &'a FakeMintTransportV1,
    cipher: &'a TestRecoveryCipherV1,
) -> StandardCashuClientV1<'a> {
    StandardCashuClientV1::new(store, mint, cipher)
}

fn mint_public_key(amount: u64) -> [u8; 33] {
    compressed_point(&(ProjectivePoint::GENERATOR * mint_scalar(amount)))
}

fn mint_scalar(amount: u64) -> Scalar {
    Scalar::from(amount + 20)
}

fn scalar_bytes(value: u64) -> [u8; 32] {
    Scalar::from(value).to_bytes().into()
}

fn valid_mint_response(request: &CashuPostSwapRequestJsonV1) -> CashuPostSwapResponseJsonV1 {
    CashuPostSwapResponseJsonV1 {
        signatures: request.outputs.iter().map(valid_blind_signature).collect(),
    }
}

fn valid_blind_signature(output: &CashuBlindedMessageJsonV1) -> CashuBlindSignatureJsonV1 {
    let blinded_message_bytes = decode_lower_hex::<33>(
        &output.blinded_message,
        CashuClientErrorV1::InvalidMintPoint,
    )
    .unwrap();
    let encoded = EncodedPoint::from_bytes(blinded_message_bytes).unwrap();
    let blinded_message = ProjectivePoint::from(
        Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded)).unwrap(),
    );
    let a = mint_scalar(output.amount);
    let public_key = ProjectivePoint::GENERATOR * a;
    let blinded_signature = blinded_message * a;

    let (e_bytes, e, nonce) = (1u64..)
        .find_map(|nonce_value| {
            let nonce = Scalar::from(nonce_value + 100);
            let r1 = ProjectivePoint::GENERATOR * nonce;
            let r2 = blinded_message * nonce;
            let challenge = cashu_challenge(&r1, &r2, &public_key, &blinded_signature);
            Option::<Scalar>::from(Scalar::from_repr(challenge.into()))
                .filter(|scalar| !bool::from(scalar.is_zero()))
                .map(|e| (challenge, e, nonce))
        })
        .unwrap();
    let s = nonce + e * a;
    CashuBlindSignatureJsonV1 {
        amount: output.amount,
        id: output.id.clone(),
        blinded_signature: lower_hex(&compressed_point(&blinded_signature)),
        dleq: CashuDleqJsonV1 {
            e: lower_hex(&e_bytes),
            s: lower_hex(&<[u8; 32]>::from(s.to_bytes())),
        },
    }
}

fn cashu_challenge(
    r1: &ProjectivePoint,
    r2: &ProjectivePoint,
    public_key: &ProjectivePoint,
    blinded_signature: &ProjectivePoint,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for point in [r1, r2, public_key, blinded_signature] {
        hasher.update(lower_hex(
            point.to_affine().to_encoded_point(false).as_bytes(),
        ));
    }
    hasher.finalize().into()
}

fn compressed_point(point: &ProjectivePoint) -> [u8; 33] {
    point
        .to_affine()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap()
}

#[test]
fn normal_swap_is_durable_at_most_once_and_never_locally_respent() {
    let fixture = fixture(3);
    let store = InsecureDevSqliteCashuSwapStoreV1::open_in_memory().unwrap();
    let mint = FakeMintTransportV1::new(
        SwapReply::Normal,
        RestoreReply::Stored,
        CheckReply::Uniform(CashuProofStateJsonV1::Unspent),
    );
    let cipher = TestRecoveryCipherV1::default();
    let first = client(&store, &mint, &cipher)
        .start_swap(
            &fixture.spend,
            &fixture.checked,
            &fixture.verified_offer(),
            &fixture.manifest,
            output_materials(3, 0),
            100,
        )
        .unwrap();
    let CashuSwapProgressV1::Grant(grant) = first else {
        panic!("expected grant")
    };
    assert_eq!(grant.settlement_value(), 3);
    assert_eq!(grant.received_note_count(), 2);

    let duplicate = client(&store, &mint, &cipher)
        .start_swap(
            &fixture.spend,
            &fixture.checked,
            &fixture.verified_offer(),
            &fixture.manifest,
            output_materials(3, 9),
            101,
        )
        .unwrap();
    assert_eq!(
        duplicate,
        CashuSwapProgressV1::AlreadyGranted {
            intent_id: *grant.intent_id()
        }
    );
    assert_eq!(mint.calls(), (1, 0, 0));
}

#[test]
fn lost_swap_response_restores_the_identical_ordered_outputs() {
    let fixture = fixture(3);
    let store = InsecureDevSqliteCashuSwapStoreV1::open_in_memory().unwrap();
    let mint = FakeMintTransportV1::new(
        SwapReply::TimeoutCommitted,
        RestoreReply::Stored,
        CheckReply::Uniform(CashuProofStateJsonV1::Spent),
    );
    let cipher = TestRecoveryCipherV1::default();
    assert!(matches!(
        client(&store, &mint, &cipher)
            .start_swap(
                &fixture.spend,
                &fixture.checked,
                &fixture.verified_offer(),
                &fixture.manifest,
                output_materials(3, 0),
                100,
            )
            .unwrap(),
        CashuSwapProgressV1::Grant(_)
    ));
    assert_eq!(mint.calls(), (1, 1, 0));
    assert!(mint.submitted_and_restored_outputs_match());
}

#[test]
fn invalid_swap_json_can_only_recover_through_nut09() {
    let fixture = fixture(1);
    let store = InsecureDevSqliteCashuSwapStoreV1::open_in_memory().unwrap();
    let mint = FakeMintTransportV1::new(
        SwapReply::InvalidJsonCommitted,
        RestoreReply::Stored,
        CheckReply::Uniform(CashuProofStateJsonV1::Spent),
    );
    let cipher = TestRecoveryCipherV1::default();
    assert!(matches!(
        client(&store, &mint, &cipher)
            .start_swap(
                &fixture.spend,
                &fixture.checked,
                &fixture.verified_offer(),
                &fixture.manifest,
                output_materials(1, 0),
                100,
            )
            .unwrap(),
        CashuSwapProgressV1::Grant(_)
    ));
    assert_eq!(mint.calls(), (1, 1, 0));
}

#[test]
fn timeout_or_404_with_unspent_inputs_never_submits_new_outputs() {
    for swap_reply in [
        SwapReply::TimeoutUncommitted,
        SwapReply::NotFoundUncommitted,
    ] {
        let fixture = fixture(1);
        let store = InsecureDevSqliteCashuSwapStoreV1::open_in_memory().unwrap();
        let mint = FakeMintTransportV1::new(
            swap_reply,
            RestoreReply::NotFound,
            CheckReply::Uniform(CashuProofStateJsonV1::Unspent),
        );
        let cipher = TestRecoveryCipherV1::default();
        let first = client(&store, &mint, &cipher)
            .start_swap(
                &fixture.spend,
                &fixture.checked,
                &fixture.verified_offer(),
                &fixture.manifest,
                output_materials(1, 0),
                100,
            )
            .unwrap();
        assert!(matches!(
            first,
            CashuSwapProgressV1::RecoveryPending {
                observation: CashuRecoveryObservationV1::InputsUnspentObserved,
                ..
            }
        ));
        let second = client(&store, &mint, &cipher)
            .start_swap(
                &fixture.spend,
                &fixture.checked,
                &fixture.verified_offer(),
                &fixture.manifest,
                output_materials(1, 20),
                101,
            )
            .unwrap();
        assert!(matches!(
            second,
            CashuSwapProgressV1::RecoveryPending { .. }
        ));
        assert_eq!(mint.calls().0, 1);
        assert!(mint.submitted_and_restored_outputs_match());
    }
}

#[test]
fn partial_restore_and_spent_inputs_requires_attention() {
    let fixture = fixture(3);
    let store = InsecureDevSqliteCashuSwapStoreV1::open_in_memory().unwrap();
    let mint = FakeMintTransportV1::new(
        SwapReply::TimeoutCommitted,
        RestoreReply::Partial,
        CheckReply::Uniform(CashuProofStateJsonV1::Spent),
    );
    let cipher = TestRecoveryCipherV1::default();
    assert!(matches!(
        client(&store, &mint, &cipher)
            .start_swap(
                &fixture.spend,
                &fixture.checked,
                &fixture.verified_offer(),
                &fixture.manifest,
                output_materials(3, 0),
                100,
            )
            .unwrap(),
        CashuSwapProgressV1::AttentionRequired {
            observation: CashuRecoveryObservationV1::InputsSpentButPromisesMissing,
            ..
        }
    ));
    assert_eq!(mint.calls(), (1, 1, 1));
}

#[test]
fn wrong_amount_keyset_order_and_bad_dleq_fail_closed() {
    for reply in [
        SwapReply::WrongOrderCommitted,
        SwapReply::WrongAmountCommitted,
        SwapReply::WrongKeysetCommitted,
        SwapReply::BadDleqCommitted,
    ] {
        let fixture = fixture(3);
        let store = InsecureDevSqliteCashuSwapStoreV1::open_in_memory().unwrap();
        let mint = FakeMintTransportV1::new(
            reply,
            RestoreReply::Stored,
            CheckReply::Uniform(CashuProofStateJsonV1::Spent),
        );
        let cipher = TestRecoveryCipherV1::default();
        assert!(matches!(
            client(&store, &mint, &cipher)
                .start_swap(
                    &fixture.spend,
                    &fixture.checked,
                    &fixture.verified_offer(),
                    &fixture.manifest,
                    output_materials(3, 0),
                    100,
                )
                .unwrap(),
            CashuSwapProgressV1::AttentionRequired {
                observation: CashuRecoveryObservationV1::BadMintResponse,
                ..
            }
        ));
        assert_eq!(mint.calls().0, 1);
    }
}

#[test]
fn exact_output_value_and_unconditional_inputs_are_enforced_pre_transport() {
    let exact_fixture = fixture(2);
    let store = InsecureDevSqliteCashuSwapStoreV1::open_in_memory().unwrap();
    let mint = FakeMintTransportV1::new(
        SwapReply::Normal,
        RestoreReply::Stored,
        CheckReply::Uniform(CashuProofStateJsonV1::Unspent),
    );
    let cipher = TestRecoveryCipherV1::default();
    assert_eq!(
        client(&store, &mint, &cipher).start_swap(
            &exact_fixture.spend,
            &exact_fixture.checked,
            &exact_fixture.verified_offer(),
            &exact_fixture.manifest,
            output_materials(1, 0),
            100,
        ),
        Err(CashuClientErrorV1::Underpayment)
    );
    assert_eq!(
        client(&store, &mint, &cipher).start_swap(
            &exact_fixture.spend,
            &exact_fixture.checked,
            &exact_fixture.verified_offer(),
            &exact_fixture.manifest,
            output_materials(3, 0),
            100,
        ),
        Err(CashuClientErrorV1::Overpayment)
    );

    let mut conditional = fixture(1);
    conditional.spend.proofs[0].secret = r#"["P2PK",{"nonce":"x","data":"02aa"}]"#.to_owned();
    assert_eq!(
        client(&store, &mint, &cipher).start_swap(
            &conditional.spend,
            &conditional.checked,
            &conditional.verified_offer(),
            &conditional.manifest,
            output_materials(1, 0),
            100,
        ),
        Err(CashuClientErrorV1::ConditionalTokenUnsupported)
    );
    assert_eq!(mint.calls(), (0, 0, 0));
}

#[test]
fn caller_cannot_forge_the_public_policy_check_result() {
    let mut forged = fixture(2);
    forged.checked.policy_price = 1;
    forged.checked.net_amount = 1;
    let store = InsecureDevSqliteCashuSwapStoreV1::open_in_memory().unwrap();
    let mint = FakeMintTransportV1::new(
        SwapReply::Normal,
        RestoreReply::Stored,
        CheckReply::Uniform(CashuProofStateJsonV1::Unspent),
    );
    let cipher = TestRecoveryCipherV1::default();
    assert_eq!(
        client(&store, &mint, &cipher).start_swap(
            &forged.spend,
            &forged.checked,
            &forged.verified_offer(),
            &forged.manifest,
            output_materials(1, 0),
            100,
        ),
        Err(CashuClientErrorV1::InvalidCheckedSpend)
    );
    assert_eq!(mint.calls(), (0, 0, 0));
}

#[test]
fn pending_mint_and_invalid_json_never_grant() {
    for (restore, check) in [
        (RestoreReply::Timeout, CheckReply::Timeout),
        (RestoreReply::InvalidJson, CheckReply::InvalidJson),
    ] {
        let fixture = fixture(1);
        let store = InsecureDevSqliteCashuSwapStoreV1::open_in_memory().unwrap();
        let mint = FakeMintTransportV1::new(SwapReply::TimeoutUncommitted, restore, check);
        let cipher = TestRecoveryCipherV1::default();
        assert!(matches!(
            client(&store, &mint, &cipher)
                .start_swap(
                    &fixture.spend,
                    &fixture.checked,
                    &fixture.verified_offer(),
                    &fixture.manifest,
                    output_materials(1, 0),
                    100,
                )
                .unwrap(),
            CashuSwapProgressV1::RecoveryPending {
                observation: CashuRecoveryObservationV1::MintUnavailable,
                ..
            }
        ));
        assert_eq!(mint.calls().0, 1);
    }
}

#[test]
fn mixed_input_states_are_never_treated_as_payment() {
    let fixture = fixture(3);
    let store = InsecureDevSqliteCashuSwapStoreV1::open_in_memory().unwrap();
    let mint = FakeMintTransportV1::new(
        SwapReply::TimeoutUncommitted,
        RestoreReply::Empty,
        CheckReply::Exact(vec![
            CashuProofStateJsonV1::Spent,
            CashuProofStateJsonV1::Unspent,
        ]),
    );
    let cipher = TestRecoveryCipherV1::default();
    assert!(matches!(
        client(&store, &mint, &cipher)
            .start_swap(
                &fixture.spend,
                &fixture.checked,
                &fixture.verified_offer(),
                &fixture.manifest,
                output_materials(3, 0),
                100,
            )
            .unwrap(),
        CashuSwapProgressV1::AttentionRequired {
            observation: CashuRecoveryObservationV1::InconsistentInputStates,
            ..
        }
    ));
}

#[test]
fn concurrent_callers_issue_one_swap_and_one_grant() {
    let fixture = Arc::new(fixture(3));
    let store = Arc::new(InsecureDevSqliteCashuSwapStoreV1::open_in_memory().unwrap());
    let mint = Arc::new(FakeMintTransportV1::new(
        SwapReply::Normal,
        RestoreReply::Stored,
        CheckReply::Uniform(CashuProofStateJsonV1::Unspent),
    ));
    let cipher = Arc::new(TestRecoveryCipherV1::default());
    let mut threads = Vec::new();
    for index in 0..8u8 {
        let fixture = Arc::clone(&fixture);
        let store = Arc::clone(&store);
        let mint = Arc::clone(&mint);
        let cipher = Arc::clone(&cipher);
        threads.push(std::thread::spawn(move || {
            client(&store, &mint, &cipher).start_swap(
                &fixture.spend,
                &fixture.checked,
                &fixture.verified_offer(),
                &fixture.manifest,
                output_materials(3, index.wrapping_mul(3)),
                100 + u64::from(index),
            )
        }));
    }
    let results = threads
        .into_iter()
        .map(|thread| thread.join().unwrap().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, CashuSwapProgressV1::Grant(_)))
            .count(),
        1
    );
    assert!(results.iter().all(|result| matches!(
        result,
        CashuSwapProgressV1::Grant(_) | CashuSwapProgressV1::AlreadyGranted { .. }
    )));
    assert_eq!(mint.calls().0, 1);
}

#[test]
fn restart_recovers_late_commit_without_resubmitting_swap() {
    let fixture = fixture(1);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cashu.sqlite");
    let mint = FakeMintTransportV1::new(
        SwapReply::TimeoutUncommitted,
        RestoreReply::Empty,
        CheckReply::Uniform(CashuProofStateJsonV1::Unspent),
    );
    let cipher = TestRecoveryCipherV1::default();
    {
        let store = InsecureDevSqliteCashuSwapStoreV1::open(&path).unwrap();
        assert!(matches!(
            client(&store, &mint, &cipher)
                .start_swap(
                    &fixture.spend,
                    &fixture.checked,
                    &fixture.verified_offer(),
                    &fixture.manifest,
                    output_materials(1, 0),
                    100,
                )
                .unwrap(),
            CashuSwapProgressV1::RecoveryPending { .. }
        ));
    }
    mint.commit_pending();
    mint.set_restore_reply(RestoreReply::Stored);
    let store = InsecureDevSqliteCashuSwapStoreV1::open(&path).unwrap();
    assert!(matches!(
        client(&store, &mint, &cipher)
            .resume_swap(
                &fixture.spend,
                &fixture.checked,
                &fixture.verified_offer(),
                &fixture.manifest,
                101,
            )
            .unwrap(),
        CashuSwapProgressV1::Grant(_)
    ));
    assert_eq!(mint.calls().0, 1);
}

#[test]
fn sqlite_contains_no_plaintext_proof_or_output_secret() {
    let fixture = fixture(1);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cashu.sqlite");
    let mint = FakeMintTransportV1::new(
        SwapReply::TimeoutUncommitted,
        RestoreReply::Timeout,
        CheckReply::Timeout,
    );
    let cipher = TestRecoveryCipherV1::default();
    {
        let store = InsecureDevSqliteCashuSwapStoreV1::open(&path).unwrap();
        let _ = client(&store, &mint, &cipher)
            .start_swap(
                &fixture.spend,
                &fixture.checked,
                &fixture.verified_offer(),
                &fixture.manifest,
                output_materials(1, 0),
                100,
            )
            .unwrap();
    }
    let database = std::fs::read(path).unwrap();
    assert!(!database
        .windows(b"input-secret-one".len())
        .any(|window| window == b"input-secret-one"));
    let output_secret = lower_hex(&[1; 32]);
    assert!(!database
        .windows(output_secret.len())
        .any(|window| window == output_secret.as_bytes()));
}

#[test]
fn production_provider_store_adapter_completes_once_and_survives_restart() {
    let fixture = fixture(3);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("provider.sqlite3");
    let authority = Arc::new(ProviderStoreTestAuthorityV1::default());
    let mint = FakeMintTransportV1::new(
        SwapReply::Normal,
        RestoreReply::Stored,
        CheckReply::Uniform(CashuProofStateJsonV1::Unspent),
    );
    let cipher = TestRecoveryCipherV1::default();
    {
        let store = create_provider_store_for_fixture(
            &path,
            fixture.policy.provider_id,
            Arc::clone(&authority),
        );
        let progress = StandardCashuClientV1::new(&store, &mint, &cipher)
            .start_swap(
                &fixture.spend,
                &fixture.checked,
                &fixture.verified_offer(),
                &fixture.manifest,
                output_materials(3, 0),
                100,
            )
            .unwrap();
        assert!(matches!(progress, CashuSwapProgressV1::Grant(_)));
        let identity = store.identity().unwrap();
        assert_eq!(identity.store_generation, 4);
        assert_eq!(identity.spend_commit_seq, 1);
    }

    let reopened = ProviderStore::open_existing(
        &path,
        fixture.policy.provider_id,
        StoreOptions::default(),
        Arc::clone(&authority) as Arc<dyn RollbackFloorAuthorityV1>,
    )
    .unwrap();
    let replay = StandardCashuClientV1::new(&reopened, &mint, &cipher)
        .start_swap(
            &fixture.spend,
            &fixture.checked,
            &fixture.verified_offer(),
            &fixture.manifest,
            output_materials(3, 40),
            200,
        )
        .unwrap();
    assert!(matches!(replay, CashuSwapProgressV1::AlreadyGranted { .. }));
    assert_eq!(mint.calls(), (1, 0, 0));
    assert_eq!(authority.floor().store_generation, 4);
    assert_eq!(authority.floor().spend_commit_seq, 1);
}

#[test]
fn lost_submit_anchor_response_never_causes_nut03_side_effect_or_retry() {
    let fixture = fixture(1);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("provider.sqlite3");
    let authority = Arc::new(ProviderStoreTestAuthorityV1::default());
    let mint = FakeMintTransportV1::new(
        SwapReply::Normal,
        RestoreReply::Empty,
        CheckReply::Uniform(CashuProofStateJsonV1::Unspent),
    );
    let cipher = TestRecoveryCipherV1::default();
    {
        let store = create_provider_store_for_fixture(
            &path,
            fixture.policy.provider_id,
            Arc::clone(&authority),
        );
        // PREPARED is generation 1. The authority durably accepts generation
        // 2 (SUBMITTED) but the caller loses that CAS response. The adapter
        // must treat the error as a hard prohibition on sending NUT-03.
        authority.lose_response_at(2);
        assert_eq!(
            StandardCashuClientV1::new(&store, &mint, &cipher).start_swap(
                &fixture.spend,
                &fixture.checked,
                &fixture.verified_offer(),
                &fixture.manifest,
                output_materials(1, 0),
                100,
            ),
            Err(CashuClientErrorV1::StoreUnavailable)
        );
        assert_eq!(mint.calls(), (0, 0, 0));
        assert_eq!(authority.floor().store_generation, 2);
    }

    let reopened = ProviderStore::open_existing(
        &path,
        fixture.policy.provider_id,
        StoreOptions::default(),
        Arc::clone(&authority) as Arc<dyn RollbackFloorAuthorityV1>,
    )
    .unwrap();
    let progress = StandardCashuClientV1::new(&reopened, &mint, &cipher)
        .start_swap(
            &fixture.spend,
            &fixture.checked,
            &fixture.verified_offer(),
            &fixture.manifest,
            output_materials(1, 40),
            200,
        )
        .unwrap();
    assert!(matches!(
        progress,
        CashuSwapProgressV1::RecoveryPending {
            observation: CashuRecoveryObservationV1::InputsUnspentObserved,
            ..
        }
    ));
    // Recovery uses only NUT-09 then NUT-07. NUT-03 stays at zero forever.
    assert_eq!(mint.calls(), (0, 1, 1));
    assert_eq!(reopened.identity().unwrap().store_generation, 2);
}

#[test]
fn lost_wallet_commit_anchor_response_recovers_notes_without_second_nut03() {
    let fixture = fixture(1);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("provider.sqlite3");
    let authority = Arc::new(ProviderStoreTestAuthorityV1::default());
    let mint = FakeMintTransportV1::new(
        SwapReply::Normal,
        RestoreReply::Stored,
        CheckReply::Uniform(CashuProofStateJsonV1::Spent),
    );
    let cipher = TestRecoveryCipherV1::default();
    {
        let store = create_provider_store_for_fixture(
            &path,
            fixture.policy.provider_id,
            Arc::clone(&authority),
        );
        // Generation 3 stores the fully verified/unblinded provider notes.
        authority.lose_response_at(3);
        assert_eq!(
            StandardCashuClientV1::new(&store, &mint, &cipher).start_swap(
                &fixture.spend,
                &fixture.checked,
                &fixture.verified_offer(),
                &fixture.manifest,
                output_materials(1, 0),
                100,
            ),
            Err(CashuClientErrorV1::StoreUnavailable)
        );
        assert_eq!(mint.calls(), (1, 0, 0));
        assert_eq!(authority.floor().store_generation, 3);
    }

    let reopened = ProviderStore::open_existing(
        &path,
        fixture.policy.provider_id,
        StoreOptions::default(),
        Arc::clone(&authority) as Arc<dyn RollbackFloorAuthorityV1>,
    )
    .unwrap();
    let progress = StandardCashuClientV1::new(&reopened, &mint, &cipher)
        .resume_swap(
            &fixture.spend,
            &fixture.checked,
            &fixture.verified_offer(),
            &fixture.manifest,
            200,
        )
        .unwrap();
    assert!(matches!(progress, CashuSwapProgressV1::Grant(_)));
    assert_eq!(mint.calls(), (1, 0, 0));
    let identity = reopened.identity().unwrap();
    assert_eq!(identity.store_generation, 4);
    assert_eq!(identity.spend_commit_seq, 1);
}

#[test]
fn lost_grant_claim_anchor_response_never_reissues_grant_or_nut03() {
    let fixture = fixture(1);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("provider.sqlite3");
    let authority = Arc::new(ProviderStoreTestAuthorityV1::default());
    let mint = FakeMintTransportV1::new(
        SwapReply::Normal,
        RestoreReply::Stored,
        CheckReply::Uniform(CashuProofStateJsonV1::Spent),
    );
    let cipher = TestRecoveryCipherV1::default();
    {
        let store = create_provider_store_for_fixture(
            &path,
            fixture.policy.provider_id,
            Arc::clone(&authority),
        );
        // The grant claim is generation 4 and the only Cashu mutation which
        // also advances spend_commit_seq. A lost response must return no grant.
        authority.lose_response_at(4);
        assert_eq!(
            StandardCashuClientV1::new(&store, &mint, &cipher).start_swap(
                &fixture.spend,
                &fixture.checked,
                &fixture.verified_offer(),
                &fixture.manifest,
                output_materials(1, 0),
                100,
            ),
            Err(CashuClientErrorV1::StoreUnavailable)
        );
        assert_eq!(mint.calls(), (1, 0, 0));
        assert_eq!(authority.floor().store_generation, 4);
        assert_eq!(authority.floor().spend_commit_seq, 1);
    }

    let reopened = ProviderStore::open_existing(
        &path,
        fixture.policy.provider_id,
        StoreOptions::default(),
        Arc::clone(&authority) as Arc<dyn RollbackFloorAuthorityV1>,
    )
    .unwrap();
    let replay = StandardCashuClientV1::new(&reopened, &mint, &cipher)
        .resume_swap(
            &fixture.spend,
            &fixture.checked,
            &fixture.verified_offer(),
            &fixture.manifest,
            200,
        )
        .unwrap();
    assert!(matches!(replay, CashuSwapProgressV1::AlreadyGranted { .. }));
    assert_eq!(mint.calls(), (1, 0, 0));
    let identity = reopened.identity().unwrap();
    assert_eq!(identity.store_generation, 4);
    assert_eq!(identity.spend_commit_seq, 1);
}
