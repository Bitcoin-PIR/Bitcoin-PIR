use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use pir_runtime_core::service_admission::{AdmissionEnforcementV1, ConnectionAdmissionGateV1};
use pir_service_protocol::{
    derive_cashu_keyset_id_v2, AcquisitionMethod, AuthBeginV1, AuthPaddingClassV1, AuthRejectCode,
    AuthResultV1, AuthScheme, AuthorizationProofV1, BackendId, CashuDenominationKeyV1,
    CashuKeysetBindingV1, CashuRequiredNutsV1, DatasetBindingV1, DeploymentStatus,
    EntitlementLimitsV1, FreeModeV1, OperationStartV1, PolicyRollbackGuardV1, PriceV1,
    PrivacyLeakageV1, ServiceOfferV1, ServicePolicyEpochFloorsV1, ServicePolicyV1,
    ServiceScopePolicyV1, ServiceScopeV1, StandardCashuMintManifestV1, StandardCashuProofV1,
    TrustedCatalogResolutionV1, VerificationMode, VerifiedServiceOfferV1, WorkloadId,
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

fn private_provider_store_tempdir_v1() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("create provider-store test directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("restrict provider-store test directory permissions");
    }
    directory
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

impl CashuCustodyCipherV1 for TestRecoveryCipherV1 {
    fn seal(
        &self,
        aad: &CashuCustodyAadV1,
        plaintext: &[u8],
    ) -> Result<CashuSealedCustodyV1, CashuCustodyCipherErrorV1> {
        let nonce = self.nonce.fetch_add(1, Ordering::SeqCst).to_le_bytes();
        let mut ciphertext = plaintext
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ self.key[index % self.key.len()])
            .collect::<Vec<_>>();
        let tag = test_cipher_tag_domain(
            b"BitcoinPIR/test-only-cashu-custody-cipher/v1",
            &self.key,
            &aad.encode(),
            &nonce,
            &ciphertext,
        );
        ciphertext.extend_from_slice(&tag);
        Ok(CashuSealedCustodyV1 {
            key_epoch: 1,
            nonce: nonce.to_vec(),
            ciphertext,
        })
    }

    fn open(
        &self,
        aad: &CashuCustodyAadV1,
        sealed: &CashuSealedCustodyV1,
    ) -> Result<Vec<u8>, CashuCustodyCipherErrorV1> {
        if sealed.key_epoch != 1 || sealed.ciphertext.len() < 32 {
            return Err(CashuCustodyCipherErrorV1::UnknownKeyEpoch);
        }
        let split = sealed.ciphertext.len() - 32;
        let (ciphertext, tag) = sealed.ciphertext.split_at(split);
        let expected = test_cipher_tag_domain(
            b"BitcoinPIR/test-only-cashu-custody-cipher/v1",
            &self.key,
            &aad.encode(),
            &sealed.nonce,
            ciphertext,
        );
        if tag != expected {
            return Err(CashuCustodyCipherErrorV1::AuthenticationFailed);
        }
        Ok(ciphertext
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ self.key[index % self.key.len()])
            .collect())
    }
}

fn test_cipher_tag(key: &[u8; 32], aad: &[u8], nonce: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    test_cipher_tag_domain(
        b"BitcoinPIR/test-only-cashu-recovery-cipher/v1",
        key,
        aad,
        nonce,
        ciphertext,
    )
}

fn test_cipher_tag_domain(
    domain: &[u8],
    key: &[u8; 32],
    aad: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
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
    InvalidJsonUncommitted,
    BadDleqCommitted,
    WrongOrderCommitted,
    WrongAmountCommitted,
    WrongKeysetCommitted,
    Nut00Http400Uncommitted,
    Malformed400,
    Http408Nut00,
    Http425Nut00,
    Http429Nut00,
    Http500Nut00,
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
        trust: CashuMintTrustV1<'_>,
        route: CashuMintRouteV1,
        request_json: &[u8],
        max_response_bytes: usize,
    ) -> Result<Vec<u8>, CashuMintTransportFailureV1> {
        assert_eq!(trust.mint_endpoint(), "https://mint.example");
        assert_eq!(trust.leaf_spki_sha256_pins(), &[[0x31; 32]]);
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
                    SwapReply::TimeoutUncommitted
                    | SwapReply::NotFoundUncommitted
                    | SwapReply::Nut00Http400Uncommitted
                    | SwapReply::InvalidJsonUncommitted
                    | SwapReply::Malformed400
                    | SwapReply::Http408Nut00
                    | SwapReply::Http425Nut00
                    | SwapReply::Http429Nut00
                    | SwapReply::Http500Nut00 => {}
                }
                match state.swap_reply {
                    SwapReply::Normal
                    | SwapReply::BadDleqCommitted
                    | SwapReply::WrongOrderCommitted
                    | SwapReply::WrongAmountCommitted
                    | SwapReply::WrongKeysetCommitted => Ok(encode_json_v1(&response).unwrap()),
                    SwapReply::InvalidJsonCommitted => Ok(b"{".to_vec()),
                    SwapReply::InvalidJsonUncommitted => Ok(b"{".to_vec()),
                    SwapReply::TimeoutCommitted | SwapReply::TimeoutUncommitted => {
                        Err(transport_failure(CashuMintTransportFailureKindV1::Timeout))
                    }
                    SwapReply::NotFoundUncommitted => Err(CashuMintTransportFailureV1::ambiguous(
                        CashuMintTransportFailureKindV1::NotFound,
                        Some(404),
                    )),
                    SwapReply::Nut00Http400Uncommitted => {
                        Err(CashuMintTransportFailureV1::from_http_status(
                            400,
                            br#"{"code":10001,"detail":"proof verification failed"}"#,
                        ))
                    }
                    SwapReply::Malformed400 => Err(CashuMintTransportFailureV1::from_http_status(
                        400,
                        b"not-json",
                    )),
                    SwapReply::Http408Nut00 => Err(nut00_http_failure(408)),
                    SwapReply::Http425Nut00 => Err(nut00_http_failure(425)),
                    SwapReply::Http429Nut00 => Err(nut00_http_failure(429)),
                    SwapReply::Http500Nut00 => Err(nut00_http_failure(500)),
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
                    RestoreReply::NotFound => Err(CashuMintTransportFailureV1::ambiguous(
                        CashuMintTransportFailureKindV1::NotFound,
                        Some(404),
                    )),
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
                        .iter()
                        .cloned()
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
    CashuMintTransportFailureV1::ambiguous(kind, None)
}

fn nut00_http_failure(status: u16) -> CashuMintTransportFailureV1 {
    CashuMintTransportFailureV1::from_http_status(
        status,
        br#"{"code":10001,"detail":"proof verification failed"}"#,
    )
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
    fixture_with_unit(price, "sat")
}

fn fixture_with_unit(price: u64, unit: &str) -> Fixture {
    assert!((1..=3).contains(&price));
    let keys = [1u64, 2, 4]
        .into_iter()
        .map(|amount| CashuDenominationKeyV1 {
            amount,
            public_key: mint_public_key(amount),
        })
        .collect::<Vec<_>>();
    let keyset = CashuKeysetBindingV1 {
        keyset_id: derive_cashu_keyset_id_v2(&keys, unit, 0, Some(100_000)).unwrap(),
        unit: unit.to_owned(),
        input_fee_ppk: 0,
        final_expiry: Some(100_000),
        keys,
    };
    let manifest = StandardCashuMintManifestV1 {
        manifest_epoch: 1,
        mint_endpoint: "https://mint.example".to_owned(),
        leaf_spki_sha256_pins: vec![[0x31; 32]],
        unit: unit.to_owned(),
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
            unit: unit.to_owned(),
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
    store: &'a dyn CashuSwapStoreV1,
    mint: &'a FakeMintTransportV1,
    cipher: &'a TestRecoveryCipherV1,
) -> StandardCashuClientV1<'a> {
    client_with_limits(
        store,
        mint,
        cipher,
        CashuCustodyExposureLimitsV1::new(1_000_000, 1_000_000).unwrap(),
    )
}

fn client_with_limits<'a>(
    store: &'a dyn CashuSwapStoreV1,
    mint: &'a FakeMintTransportV1,
    cipher: &'a TestRecoveryCipherV1,
    limits: CashuCustodyExposureLimitsV1,
) -> StandardCashuClientV1<'a> {
    StandardCashuClientV1::new(store, mint, cipher, cipher, limits)
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
fn mint_transport_trust_is_manifest_derived_and_debug_redacted() {
    let fixture = fixture(1);
    let trust = CashuMintTrustV1::from_manifest(&fixture.manifest).unwrap();
    assert_eq!(trust.mint_endpoint(), "https://mint.example");
    assert_eq!(trust.leaf_spki_sha256_pins(), &[[0x31; 32]]);
    let debug = format!("{trust:?}");
    assert!(!debug.contains("mint.example"));
    assert!(!debug.contains(&hex::encode([0x31; 32])));

    let mut invalid = fixture.manifest;
    invalid.leaf_spki_sha256_pins = vec![[0x32; 32], [0x31; 32]];
    assert_eq!(
        CashuMintTrustV1::from_manifest(&invalid),
        Err(CashuClientErrorV1::InvalidManifest)
    );
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
            client(store.as_ref(), &mint, &cipher).start_swap(
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
    // The durable PREPARED -> SUBMITTED transition intentionally happens
    // before the sole NUT-03 call. A concurrent observer may therefore reach
    // NUT-09/NUT-07 before the winning call has committed at the mint and get
    // a transient, fail-closed RecoveryPending result. A second valid ordering
    // is NUT-09 observing no promises immediately before the winner commits,
    // followed by NUT-07 observing the now-spent inputs. That observer must
    // report the exact spent-without-promises attention state; it still must
    // never submit a second output set, and the shared persisted intent
    // converges after the winner completes.
    assert!(results.iter().all(|result| matches!(
        result,
        CashuSwapProgressV1::Grant(_)
            | CashuSwapProgressV1::AlreadyGranted { .. }
            | CashuSwapProgressV1::RecoveryPending { .. }
            | CashuSwapProgressV1::AttentionRequired {
                observation: CashuRecoveryObservationV1::InputsSpentButPromisesMissing,
                ..
            }
    )));
    assert_eq!(mint.calls().0, 1);
    assert!(matches!(
        client(store.as_ref(), &mint, &cipher)
            .resume_swap(
                &fixture.spend,
                &fixture.checked,
                &fixture.verified_offer(),
                &fixture.manifest,
                200,
            )
            .unwrap(),
        CashuSwapProgressV1::AlreadyGranted { .. }
    ));
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
    let directory = private_provider_store_tempdir_v1();
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
        let progress = client(&store, &mint, &cipher)
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
    let replay = client(&reopened, &mint, &cipher)
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
fn runtime_admission_committer_consumes_a_bound_standard_cashu_attempt_once() {
    let fixture = fixture(3);
    let scope = &fixture.policy.scopes[0].scope;
    let offer = &fixture.policy.scopes[0].offers[0];
    let operation = OperationStartV1::DpfQuery { db_id: 7 };
    let request = AuthBeginV1 {
        policy_digest: fixture.policy.policy_digest().unwrap(),
        scope_id: scope.scope_id(),
        offer_id: offer.offer_id,
        scheme: offer.authorization,
        key_id: offer.key_id.clone(),
        operation: operation.clone(),
        proof: AuthorizationProofV1::StandardCashu(fixture.spend.clone())
            .encode_for(offer.authorization, offer.free_mode)
            .unwrap(),
    };
    let request = AuthBeginV1::decode_padded(&request.encode_padded().unwrap()).unwrap();
    let resolution = TrustedCatalogResolutionV1::new(
        7,
        scope.backend,
        scope.workload,
        scope.protocol_version,
        scope.dataset.clone(),
        scope.operation_profile,
    );
    let catalog =
        |candidate: &OperationStartV1| (candidate == &operation).then(|| resolution.clone());

    let directory = private_provider_store_tempdir_v1();
    let path = directory.path().join("provider.sqlite3");
    let authority = Arc::new(ProviderStoreTestAuthorityV1::default());
    let store = create_provider_store_for_fixture(
        &path,
        fixture.policy.provider_id,
        Arc::clone(&authority),
    );
    let mint = FakeMintTransportV1::new(
        SwapReply::Normal,
        RestoreReply::Stored,
        CheckReply::Uniform(CashuProofStateJsonV1::Unspent),
    );
    let cipher = TestRecoveryCipherV1::default();
    let committer = StandardCashuAdmissionCommitterV1::new(client(&store, &mint, &cipher));

    let mut first_gate = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
    first_gate.secure_channel_established();
    first_gate
        .policy_served(true, request.policy_digest)
        .unwrap();
    assert!(matches!(
        first_gate.authorize_and_commit(
            true,
            &request,
            fixture.verified_offer(),
            &catalog,
            None,
            &committer,
            100,
            1_000,
        ),
        AuthResultV1::Granted(_)
    ));

    let mut replay_gate = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
    replay_gate.secure_channel_established();
    replay_gate
        .policy_served(true, request.policy_digest)
        .unwrap();
    assert!(matches!(
        replay_gate.authorize_and_commit(
            true,
            &request,
            fixture.verified_offer(),
            &catalog,
            None,
            &committer,
            101,
            2_000,
        ),
        AuthResultV1::Rejected(rejected) if rejected.code == AuthRejectCode::InvalidOrSpent
    ));
    assert_eq!(mint.calls(), (1, 0, 0));
}

#[test]
fn lost_submit_anchor_response_never_causes_nut03_side_effect_or_retry() {
    let fixture = fixture(1);
    let directory = private_provider_store_tempdir_v1();
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
            client(&store, &mint, &cipher).start_swap(
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
    let progress = client(&reopened, &mint, &cipher)
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
    let directory = private_provider_store_tempdir_v1();
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
            client(&store, &mint, &cipher).start_swap(
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
    let progress = client(&reopened, &mint, &cipher)
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
    let directory = private_provider_store_tempdir_v1();
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
            client(&store, &mint, &cipher).start_swap(
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
    let replay = client(&reopened, &mint, &cipher)
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

#[test]
fn finite_exposure_limits_are_mandatory_and_enforced_before_nut03() {
    assert_eq!(
        CashuCustodyExposureLimitsV1::new(0, 1),
        Err(CashuClientErrorV1::InvalidExposureLimits)
    );
    assert_eq!(
        CashuCustodyExposureLimitsV1::new(1, u64::MAX - 1),
        Err(CashuClientErrorV1::InvalidExposureLimits)
    );
    let fixture = fixture(3);
    let store = InsecureDevSqliteCashuSwapStoreV1::open_in_memory().unwrap();
    let mint = FakeMintTransportV1::new(
        SwapReply::Normal,
        RestoreReply::Stored,
        CheckReply::Uniform(CashuProofStateJsonV1::Unspent),
    );
    let cipher = TestRecoveryCipherV1::default();
    assert_eq!(
        client_with_limits(
            &store,
            &mint,
            &cipher,
            CashuCustodyExposureLimitsV1::new(2, 10).unwrap(),
        )
        .start_swap(
            &fixture.spend,
            &fixture.checked,
            &fixture.verified_offer(),
            &fixture.manifest,
            output_materials(3, 0),
            100,
        ),
        Err(CashuClientErrorV1::ExposureLimitExceeded)
    );
    assert_eq!(mint.calls(), (0, 0, 0));
}

#[test]
fn every_http_error_remains_an_ambiguous_swap_outcome() {
    let valid = br#"{"code":10001,"detail":"proof verification failed"}"#;
    let http_400 = CashuMintTransportFailureV1::from_http_status(400, valid);
    assert_eq!(http_400.kind(), CashuMintTransportFailureKindV1::HttpError);
    assert_eq!(http_400.http_status(), Some(400));

    for (status, body) in [
        (400, b"not-json".as_slice()),
        (400, br#"{"code":10001}"#.as_slice()),
        (
            400,
            br#"{"code":10001,"detail":"x","extra":true}"#.as_slice(),
        ),
        (400, br#"{"code":0,"detail":"x"}"#.as_slice()),
        (408, valid.as_slice()),
        (425, valid.as_slice()),
        (429, valid.as_slice()),
        (500, valid.as_slice()),
        (503, valid.as_slice()),
    ] {
        assert!(
            matches!(
                CashuMintTransportFailureV1::from_http_status(status, body).kind(),
                CashuMintTransportFailureKindV1::HttpError
                    | CashuMintTransportFailureKindV1::NotFound
            ),
            "status {status} and body {body:?} must remain ambiguous"
        );
    }
    let oversized = format!(r#"{{"code":10001,"detail":"{}"}}"#, "x".repeat(4_096));
    assert_eq!(
        CashuMintTransportFailureV1::from_http_status(400, oversized.as_bytes()).kind(),
        CashuMintTransportFailureKindV1::HttpError
    );
}

#[test]
fn nut00_http_400_retains_recovery_and_never_resubmits() {
    let fixture = fixture(1);
    let store = InsecureDevSqliteCashuSwapStoreV1::open_in_memory().unwrap();
    let mint = FakeMintTransportV1::new(
        SwapReply::Nut00Http400Uncommitted,
        RestoreReply::Empty,
        CheckReply::Uniform(CashuProofStateJsonV1::Unspent),
    );
    let cipher = TestRecoveryCipherV1::default();
    let context = CheckedContextV1::new(
        &fixture.spend,
        &fixture.checked,
        &fixture.verified_offer(),
        &fixture.manifest,
        100,
    )
    .unwrap();
    for now in [100, 101] {
        assert!(matches!(
            client(&store, &mint, &cipher).start_swap(
                &fixture.spend,
                &fixture.checked,
                &fixture.verified_offer(),
                &fixture.manifest,
                output_materials(1, now as u8),
                now,
            ),
            Ok(CashuSwapProgressV1::RecoveryPending {
                observation: CashuRecoveryObservationV1::InputsUnspentObserved,
                ..
            })
        ));
    }
    assert_eq!(mint.calls(), (1, 2, 2));
    assert_eq!(
        store
            .load_by_input(&fixture.checked.mint_id, &context.input_set_digest)
            .unwrap()
            .unwrap()
            .state,
        CashuSwapStateV1::Submitted
    );
}

#[test]
fn ambiguous_http_errors_never_release_or_resubmit() {
    for reply in [
        SwapReply::Nut00Http400Uncommitted,
        SwapReply::Malformed400,
        SwapReply::NotFoundUncommitted,
        SwapReply::InvalidJsonUncommitted,
        SwapReply::Http408Nut00,
        SwapReply::Http425Nut00,
        SwapReply::Http429Nut00,
        SwapReply::Http500Nut00,
    ] {
        let fixture = fixture(1);
        let store = InsecureDevSqliteCashuSwapStoreV1::open_in_memory().unwrap();
        let mint = FakeMintTransportV1::new(
            reply,
            RestoreReply::Empty,
            CheckReply::Uniform(CashuProofStateJsonV1::Unspent),
        );
        let cipher = TestRecoveryCipherV1::default();
        let context = CheckedContextV1::new(
            &fixture.spend,
            &fixture.checked,
            &fixture.verified_offer(),
            &fixture.manifest,
            100,
        )
        .unwrap();
        let first = client(&store, &mint, &cipher)
            .start_swap(
                &fixture.spend,
                &fixture.checked,
                &fixture.verified_offer(),
                &fixture.manifest,
                output_materials(1, 1),
                100,
            )
            .unwrap();
        assert!(matches!(first, CashuSwapProgressV1::RecoveryPending { .. }));
        let second = client(&store, &mint, &cipher)
            .start_swap(
                &fixture.spend,
                &fixture.checked,
                &fixture.verified_offer(),
                &fixture.manifest,
                output_materials(1, 2),
                101,
            )
            .unwrap();
        assert!(matches!(
            second,
            CashuSwapProgressV1::RecoveryPending { .. }
        ));
        assert_eq!(mint.calls().0, 1);
        assert_eq!(
            store
                .load_by_input(&fixture.checked.mint_id, &context.input_set_digest)
                .unwrap()
                .unwrap()
                .state,
            CashuSwapStateV1::Submitted
        );
    }
}

#[test]
fn canonical_units_with_digits_and_underscores_complete_custody_grant() {
    for unit in ["usd1", "usd_1"] {
        let fixture = fixture_with_unit(1, unit);
        let store = InsecureDevSqliteCashuSwapStoreV1::open_in_memory().unwrap();
        let mint = FakeMintTransportV1::new(
            SwapReply::Normal,
            RestoreReply::Stored,
            CheckReply::Uniform(CashuProofStateJsonV1::Unspent),
        );
        let cipher = TestRecoveryCipherV1::default();
        assert!(matches!(
            client(&store, &mint, &cipher).start_swap(
                &fixture.spend,
                &fixture.checked,
                &fixture.verified_offer(),
                &fixture.manifest,
                output_materials(1, 1),
                100,
            ),
            Ok(CashuSwapProgressV1::Grant(_))
        ));
    }
}

#[test]
fn repeated_output_rng_across_swaps_cannot_duplicate_y_or_create_a_second_grant() {
    let first = fixture(1);
    let mut second = fixture(1);
    second.spend.proofs[0].secret = "different-input-secret".to_owned();
    second.checked = {
        let verified = second.verified_offer();
        check_standard_cashu_spend_for_offer(&second.spend, &verified, 100).unwrap()
    };
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cashu.sqlite");
    let store = InsecureDevSqliteCashuSwapStoreV1::open(&path).unwrap();
    let mint = FakeMintTransportV1::new(
        SwapReply::Normal,
        RestoreReply::Stored,
        CheckReply::Uniform(CashuProofStateJsonV1::Unspent),
    );
    let cipher = TestRecoveryCipherV1::default();
    assert!(matches!(
        client(&store, &mint, &cipher).start_swap(
            &first.spend,
            &first.checked,
            &first.verified_offer(),
            &first.manifest,
            output_materials(1, 0),
            100,
        ),
        Ok(CashuSwapProgressV1::Grant(_))
    ));
    assert_eq!(
        client(&store, &mint, &cipher).start_swap(
            &second.spend,
            &second.checked,
            &second.verified_offer(),
            &second.manifest,
            output_materials(1, 0),
            101,
        ),
        Err(CashuClientErrorV1::StoreConflict)
    );
    drop(store);
    let connection = rusqlite::Connection::open(path).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM cashu_custody_lots", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM cashu_custody_notes", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM cashu_swap_intents WHERE state = 3",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM cashu_swap_intents WHERE state = 2",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
}

fn recovery_codec_fixture(
    output_count: usize,
    with_response: bool,
) -> CashuSwapRecoveryPlaintextV1 {
    let outputs = (0..output_count)
        .map(|index| CashuOutputRecoveryV1 {
            amount: u64::try_from(index + 1).unwrap(),
            secret_bytes: SensitiveBytes32V1::new([0x11u8.wrapping_add(index as u8); 32]),
            blinding_scalar: SensitiveBytes32V1::new([0x41u8.wrapping_add(index as u8); 32]),
        })
        .collect::<Vec<_>>();
    let received_notes = if with_response {
        (0..output_count)
            .map(|index| {
                let mut signature = [0x61u8.wrapping_add(index as u8); 33];
                signature[0] = if index & 1 == 0 { 0x02 } else { 0x03 };
                CashuReceivedNoteRecoveryV1 {
                    amount: u64::try_from(index + 1).unwrap(),
                    secret_bytes: SensitiveBytes32V1::new([0x21u8.wrapping_add(index as u8); 32]),
                    unblinded_signature: SensitiveRecoveryBytesV1::new(signature),
                }
            })
            .collect()
    } else {
        Vec::new()
    };
    CashuSwapRecoveryPlaintextV1 {
        version: CASHU_RECOVERY_CODEC_VERSION_V1,
        request_json: SensitiveRecoveryStringV1::new(
            r#"{"inputs":["recovery-secret"],"outputs":["blinded-output"]}"#.to_owned(),
        ),
        outputs,
        response_json: with_response.then(|| {
            SensitiveRecoveryStringV1::new(
                r#"{"signatures":["mint-controlled-response"]}"#.to_owned(),
            )
        }),
        received_notes,
    }
}

fn recovery_codec_zeroized_drop_count() -> usize {
    RECOVERY_CODEC_ZEROIZED_DROPS_V1.with(std::cell::Cell::get)
}

#[test]
fn sealed_recovery_and_custody_envelopes_redact_debug_and_zeroize_on_drop() {
    assert!(std::mem::needs_drop::<CashuSealedRecoveryV1>());
    assert!(std::mem::needs_drop::<CashuSealedCustodyV1>());

    let recovery = CashuSealedRecoveryV1 {
        key_epoch: 6,
        nonce: b"sensitive-recovery-nonce".to_vec(),
        ciphertext: b"sensitive-recovery-ciphertext".to_vec(),
    };
    assert_eq!(
        format!("{recovery:?}"),
        "CashuSealedRecoveryV1 { envelope: \"[REDACTED]\" }"
    );

    let custody = CashuSealedCustodyV1 {
        key_epoch: 7,
        nonce: b"sensitive-custody-nonce".to_vec(),
        ciphertext: b"sensitive-custody-ciphertext".to_vec(),
    };
    assert_eq!(
        format!("{custody:?}"),
        "CashuSealedCustodyV1 { envelope: \"[REDACTED]\" }"
    );
}

#[test]
fn recovery_binary_codec_roundtrips_canonically_without_reallocation() {
    for with_response in [false, true] {
        let recovery = recovery_codec_fixture(2, with_response);
        let plaintext = encode_recovery_plaintext_v1(&recovery).unwrap();
        assert_eq!(
            &plaintext[..CASHU_RECOVERY_MAGIC_V1.len()],
            CASHU_RECOVERY_MAGIC_V1
        );
        assert_eq!(plaintext[8], CASHU_RECOVERY_CODEC_VERSION_V1);
        assert_eq!(plaintext[9], u8::from(with_response));
        assert!(plaintext.capacity() >= MAX_CASHU_RECOVERY_PLAINTEXT_BYTES_V1);

        let decoded = decode_recovery_plaintext_v1(&plaintext).unwrap();
        assert_eq!(decoded.version, CASHU_RECOVERY_CODEC_VERSION_V1);
        assert_eq!(
            decoded.request_json.as_bytes(),
            recovery.request_json.as_bytes()
        );
        assert!(decoded.request_json.capacity() >= decoded.request_json.as_bytes().len());
        assert_eq!(decoded.outputs.len(), recovery.outputs.len());
        assert!(decoded.outputs.capacity() >= decoded.outputs.len());
        for (actual, expected) in decoded.outputs.iter().zip(&recovery.outputs) {
            assert_eq!(actual.amount, expected.amount);
            assert_eq!(
                actual.secret_bytes.as_array(),
                expected.secret_bytes.as_array()
            );
            assert_eq!(
                actual.blinding_scalar.as_array(),
                expected.blinding_scalar.as_array()
            );
        }
        assert_eq!(
            decoded.response_json.as_ref().map(|value| value.as_bytes()),
            recovery
                .response_json
                .as_ref()
                .map(|value| value.as_bytes())
        );
        assert!(decoded.received_notes == recovery.received_notes);
        assert!(decoded.received_notes.capacity() >= decoded.received_notes.len());

        let reencoded = encode_recovery_plaintext_v1(&decoded).unwrap();
        assert_eq!(reencoded.as_slice(), plaintext.as_slice());
    }
}

#[test]
fn recovery_binary_codec_rejects_tamper_truncation_trailing_and_oversize() {
    let recovery = recovery_codec_fixture(1, true);
    let plaintext = encode_recovery_plaintext_v1(&recovery).unwrap();

    for (offset, value) in [(0usize, b'X'), (8, 2), (9, 0x80), (10, 1)] {
        let mut tampered = Zeroizing::new(plaintext.as_slice().to_vec());
        tampered[offset] = value;
        assert!(matches!(
            decode_recovery_plaintext_v1(&tampered),
            Err(CashuClientErrorV1::RecoveryPlaintextInvalid)
        ));
    }
    for truncated_len in 0..plaintext.len() {
        assert!(matches!(
            decode_recovery_plaintext_v1(&plaintext[..truncated_len]),
            Err(CashuClientErrorV1::RecoveryPlaintextInvalid)
        ));
    }

    let mut trailing = encode_recovery_plaintext_v1(&recovery).unwrap();
    let original_capacity = trailing.capacity();
    trailing.push(0);
    assert_eq!(trailing.capacity(), original_capacity);
    assert!(matches!(
        decode_recovery_plaintext_v1(&trailing),
        Err(CashuClientErrorV1::RecoveryPlaintextInvalid)
    ));

    let mut impossible_count = Zeroizing::new(plaintext.as_slice().to_vec());
    impossible_count[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        decode_recovery_plaintext_v1(&impossible_count),
        Err(CashuClientErrorV1::RecoveryPlaintextInvalid)
    ));

    let mut oversized_recovery = recovery_codec_fixture(1, false);
    oversized_recovery.request_json =
        SensitiveRecoveryStringV1::new("x".repeat(MAX_CASHU_MINT_JSON_BYTES_V1 + 1));
    assert!(matches!(
        encode_recovery_plaintext_v1(&oversized_recovery),
        Err(CashuClientErrorV1::RecoveryPlaintextInvalid)
    ));
    let oversized_plaintext = Zeroizing::new(vec![0u8; MAX_CASHU_RECOVERY_PLAINTEXT_BYTES_V1 + 1]);
    assert!(matches!(
        decode_recovery_plaintext_v1(&oversized_plaintext),
        Err(CashuClientErrorV1::RecoveryPlaintextInvalid)
    ));
}

#[test]
fn recovery_binary_codec_failure_drops_every_constructed_sensitive_field() {
    let recovery = recovery_codec_fixture(2, false);
    let mut plaintext = encode_recovery_plaintext_v1(&recovery).unwrap();
    let request_len =
        usize::try_from(u32::from_le_bytes(plaintext[16..20].try_into().unwrap())).unwrap();
    let second_amount_offset =
        CASHU_RECOVERY_HEADER_BYTES_V1 + request_len + CASHU_OUTPUT_RECOVERY_BYTES_V1;
    plaintext[second_amount_offset..second_amount_offset + 8].fill(0);

    let before = recovery_codec_zeroized_drop_count();
    assert!(matches!(
        decode_recovery_plaintext_v1(&plaintext),
        Err(CashuClientErrorV1::RecoveryPlaintextInvalid)
    ));
    // The request and both 32-byte fields in the first completed output were
    // owned before the second output failed, and all three were wiped.
    assert_eq!(recovery_codec_zeroized_drop_count() - before, 3);
}

#[test]
fn custody_cipher_is_domain_bound_and_offline_decryptor_validates_the_bundle() {
    let fixture = fixture(3);
    let store = InsecureDevSqliteCashuSwapStoreV1::open_in_memory().unwrap();
    let mint = FakeMintTransportV1::new(
        SwapReply::Normal,
        RestoreReply::Stored,
        CheckReply::Uniform(CashuProofStateJsonV1::Unspent),
    );
    let test_cipher = TestRecoveryCipherV1::default();
    let test_client = client(&store, &mint, &test_cipher);
    let context = CheckedContextV1::new(
        &fixture.spend,
        &fixture.checked,
        &fixture.verified_offer(),
        &fixture.manifest,
        100,
    )
    .unwrap();
    let (new_intent, recovery) = test_client
        .prepare_intent(&context, output_materials(3, 0))
        .unwrap();
    let request: CashuPostSwapRequestJsonV1 =
        decode_json_v1(recovery.request_json.as_bytes()).unwrap();
    let response = encode_json_v1(&valid_mint_response(&request)).unwrap();
    let notes = verify_mint_response_v1(&recovery, &context, &response).unwrap();
    let record = StoredCashuSwapIntentV1 {
        intent_id: new_intent.intent_id,
        mint_id: new_intent.mint_id,
        manifest_digest: new_intent.manifest_digest,
        unit: new_intent.unit,
        input_set_digest: new_intent.input_set_digest,
        request_digest: new_intent.request_digest,
        output_set_digest: new_intent.output_set_digest,
        offer_binding_digest: new_intent.offer_binding_digest,
        settlement_value: new_intent.settlement_value,
        expected_output_count: new_intent.expected_output_count,
        state: CashuSwapStateV1::WalletStored,
        sealed_recovery: new_intent.sealed_recovery,
        created_bucket: new_intent.created_bucket,
        updated_bucket: new_intent.created_bucket,
    };
    let built = build_custody_lot_v1(&record, &context, &notes).unwrap();
    let plaintext = built.bundle.encode_canonical().unwrap();
    assert!(!plaintext
        .windows(b"input-secret-one".len())
        .any(|window| window == b"input-secret-one"));
    for forbidden in [
        b"intent".as_slice(),
        b"offer",
        b"request",
        b"response",
        b"query",
    ] {
        assert!(!plaintext
            .windows(forbidden.len())
            .any(|window| window == forbidden));
    }

    let cipher = ChaCha20Poly1305CustodyCipherV1::new(7, [(7, [0x41; 32])]).unwrap();
    let sealed = cipher.seal(&built.aad, &plaintext).unwrap();
    let decryptor = ChaCha20Poly1305CustodyDecryptorV1::new([(7, [0x41; 32])]).unwrap();
    let opened = decryptor.open_bundle(&built.aad, &sealed).unwrap();
    assert_eq!(opened.note_set_digest(), built.bundle.note_set_digest());
    assert_eq!(opened.manifest_digest(), &fixture.checked.manifest_digest);
    assert_eq!(
        opened.leaf_spki_sha256_pins(),
        fixture.manifest.leaf_spki_sha256_pins.as_slice()
    );

    let mut wrong_aad = built.aad;
    wrong_aad.settlement_value += 1;
    assert_eq!(
        decryptor.open_bundle(&wrong_aad, &sealed),
        Err(CashuClientErrorV1::CustodyAuthenticationFailed)
    );
    let mut tampered = sealed;
    tampered.ciphertext[0] ^= 1;
    assert_eq!(
        decryptor.open_bundle(&built.aad, &tampered),
        Err(CashuClientErrorV1::CustodyAuthenticationFailed)
    );
    let debug = format!("{:?}", tampered);
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains(&hex::encode(&tampered.ciphertext)));
}

#[test]
fn official_cashub_v4_vector_round_trips_semantically_and_debug_redacts_secrets() {
    const OFFICIAL: &str = "cashuBo2F0gqJhaUgA_9SLj17PgGFwgaNhYQFhc3hAYWNjMTI0MzVlN2I4NDg0YzNjZjE4NTAxNDkyMThhZjkwZjcxNmE1MmJmNGE1ZWQzNDdlNDhlY2MxM2Y3NzM4OGFjWCECRFODGd5IXVW-07KaZCvuWHk3WrnnpiDhHki6SCQh88-iYWlIAK0mjE0fWCZhcIKjYWECYXN4QDEzMjNkM2Q0NzA3YTU4YWQyZTIzYWRhNGU5ZjFmNDlmNWE1YjRhYzdiNzA4ZWIwZDYxZjczOGY0ODMwN2U4ZWVhY1ghAjRWqhENhLSsdHrr2Cw7AFrKUL9Ffr1XN6RBT6w659lNo2FhAWFzeEA1NmJjYmNiYjdjYzY0MDZiM2ZhNWQ1N2QyMTc0ZjRlZmY4YjQ0MDJiMTc2OTI2ZDNhNTdkM2MzZGNiYjU5ZDU3YWNYIQJzEpxXGeWZN5qXSmJjY8MzxWyvwObQGr5G1YCCgHicY2FtdWh0dHA6Ly9sb2NhbGhvc3Q6MzMzOGF1Y3NhdA";
    let token = CashuTokenV4V1::decode_cashub(OFFICIAL).unwrap();
    let encoded = token.encode_cashub().unwrap();
    assert_eq!(CashuTokenV4V1::decode_cashub(&encoded).unwrap(), token);
    assert_ne!(encoded.as_str(), OFFICIAL);
    let debug = format!("{token:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("acc12435e7b8484c3cf1850149218af90f716a52bf4a5ed347e48ecc13f77388"));
}

#[test]
fn custody_export_groups_keyset_rotations_and_uses_full_ids_on_short_collision() {
    fn bundle(keyset_id: String, secret_byte: u8, digest_byte: u8) -> CashuCustodyBundleV1 {
        CashuCustodyBundleV1::new(
            "https://mint.example".into(),
            [0x52; 32],
            vec![[0x31; 32]],
            "sat".into(),
            keyset_id,
            [digest_byte.wrapping_add(30); 32],
            vec![CashuCustodyNoteV1::new(
                1,
                lower_hex(&[secret_byte; 32]),
                compressed_point(&ProjectivePoint::GENERATOR),
                [digest_byte; 32],
            )
            .unwrap()],
        )
        .unwrap()
    }

    let shared_prefix = "0102030405060708";
    let first_id = format!("{shared_prefix}{}", "11".repeat(25));
    let second_id = format!("{shared_prefix}{}", "22".repeat(25));
    let encoded =
        encode_cashub_from_custody_bundles_v1(&[bundle(second_id, 2, 2), bundle(first_id, 1, 1)])
            .unwrap();
    let decoded = CashuTokenV4V1::decode_cashub(&encoded).unwrap();
    assert_eq!(decoded.groups().len(), 2);
    assert!(decoded
        .groups()
        .iter()
        .all(|group| group.keyset_id().len() == 33));
    assert_eq!(
        decoded
            .groups()
            .iter()
            .map(|group| group.proofs().len())
            .sum::<usize>(),
        2
    );
    assert!(
        cashub_encoded_upper_bound_v1(512, 16, 2_048, 16).unwrap()
            <= MAX_CASHUB_SERIALIZED_CHARS_V1
    );
}

#[test]
fn custody_note_and_bundle_debug_redact_stable_linkage_markers() {
    let endpoint = "https://stable-debug-mint.example";
    let keyset_id = format!("01{}", "ab".repeat(32));
    let secret = lower_hex(&[0x44; 32]);
    let c = compressed_point(&ProjectivePoint::GENERATOR);
    let y_digest = [0x55; 32];
    let note_set_digest = [0x66; 32];
    let amount = 987_654_321_u64;
    let bundle = CashuCustodyBundleV1::new(
        endpoint.to_owned(),
        [0x52; 32],
        vec![[0x31; 32]],
        "sat".to_owned(),
        keyset_id.clone(),
        note_set_digest,
        vec![CashuCustodyNoteV1::new(amount, secret.clone(), c, y_digest).unwrap()],
    )
    .unwrap();

    let note_debug = format!("{:?}", bundle.notes()[0]);
    let bundle_debug = format!("{bundle:?}");
    let combined = format!("{note_debug}\n{bundle_debug}");
    for stable_marker in [
        endpoint.to_owned(),
        keyset_id,
        secret,
        hex::encode(c),
        hex::encode(y_digest),
        hex::encode(note_set_digest),
        amount.to_string(),
    ] {
        assert!(
            !combined.contains(&stable_marker),
            "custody Debug leaked a stable linkage marker"
        );
    }
    assert!(combined.contains("[REDACTED"));
}

#[test]
fn custody_export_limits_keyset_groups_not_custody_lots() {
    fn bundle(keyset_id: String, marker: u8) -> CashuCustodyBundleV1 {
        CashuCustodyBundleV1::new(
            "https://mint.example".into(),
            [0x52; 32],
            vec![[0x31; 32]],
            "sat".into(),
            keyset_id,
            [marker.wrapping_add(30); 32],
            vec![CashuCustodyNoteV1::new(
                1,
                lower_hex(&[marker; 32]),
                compressed_point(&ProjectivePoint::GENERATOR),
                [marker; 32],
            )
            .unwrap()],
        )
        .unwrap()
    }

    let shared_keyset = "11".repeat(33);
    let same_keyset_lots = (1..=17)
        .map(|marker| bundle(shared_keyset.clone(), marker))
        .collect::<Vec<_>>();
    let encoded = encode_cashub_from_custody_bundles_v1(&same_keyset_lots).unwrap();
    let decoded = CashuTokenV4V1::decode_cashub(&encoded).unwrap();
    assert_eq!(decoded.groups().len(), 1);
    assert_eq!(decoded.groups()[0].proofs().len(), 17);

    let distinct_keysets = (1..=17)
        .map(|marker| bundle(format!("{marker:02x}{}", "ab".repeat(32)), marker))
        .collect::<Vec<_>>();
    assert_eq!(
        encode_cashub_from_custody_bundles_v1(&distinct_keysets),
        Err(CashuClientErrorV1::InvalidItemCount)
    );
}

#[test]
fn cdk_style_padded_cashub_dleq_is_accepted_but_never_reexported() {
    use base64::{engine::general_purpose::URL_SAFE, Engine as _};
    use ciborium::value::Value;

    let proof = Value::Map(vec![
        (Value::Text("a".into()), Value::Integer(1u64.into())),
        (Value::Text("s".into()), Value::Text("11".repeat(32))),
        (
            Value::Text("c".into()),
            Value::Bytes(compressed_point(&ProjectivePoint::GENERATOR).to_vec()),
        ),
        (
            Value::Text("d".into()),
            Value::Map(vec![
                (Value::Text("e".into()), Value::Bytes(vec![1; 32])),
                (Value::Text("s".into()), Value::Bytes(vec![2; 32])),
                (Value::Text("r".into()), Value::Bytes(vec![3; 32])),
            ]),
        ),
    ]);
    let root = Value::Map(vec![
        (
            Value::Text("m".into()),
            Value::Text("https://mint.example".into()),
        ),
        (Value::Text("u".into()), Value::Text("sat".into())),
        (
            Value::Text("t".into()),
            Value::Array(vec![Value::Map(vec![
                (Value::Text("i".into()), Value::Bytes(vec![1; 8])),
                (Value::Text("p".into()), Value::Array(vec![proof])),
            ])]),
        ),
    ]);
    let mut bytes = Vec::new();
    ciborium::into_writer(&root, &mut bytes).unwrap();
    let padded = format!("cashuB{}", URL_SAFE.encode(bytes));
    let decoded = CashuTokenV4V1::decode_cashub(&padded).unwrap();
    let clean = decoded.encode_cashub().unwrap();
    assert!(!clean.ends_with('='));
    assert_eq!(CashuTokenV4V1::decode_cashub(&clean).unwrap(), decoded);
}

#[test]
#[ignore = "requires BITCOINPIR_CDK_CASHUB_TOKEN from the disposable CDK interop runner"]
fn cdk_cashub_token_strict_semantic_round_trip() {
    let serialized = std::env::var("BITCOINPIR_CDK_CASHUB_TOKEN")
        .expect("the ignored CDK interop test requires BITCOINPIR_CDK_CASHUB_TOKEN");
    let decoded = CashuTokenV4V1::decode_cashub(&serialized)
        .expect("CDK token must be strict canonical Cashu V4");
    let reencoded = decoded.encode_cashub().unwrap();
    let reparsed = CashuTokenV4V1::decode_cashub(&reencoded).unwrap();
    assert_eq!(decoded, reparsed);
}
