//! Cross-product coverage for the service-admission control plane.
//!
//! These tests deliberately use an authoritative-committer test double. They
//! prove that a canonical encrypted AUTH_BEGIN frame is bound to the signed
//! policy/catalog, dispatched to the exact payment-method route, committed
//! before a grant is installed, and then constrained by the selected backend
//! state machine. Method-specific cryptography and crash-durable transitions
//! remain covered by each production adapter's own integration tests; this is
//! not a socket-level or external-mint E2E test.

use std::collections::HashSet;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::sync::Mutex;

use ed25519_dalek::SigningKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};
use pir_channel::{ClientHandshake, Direction, ServerHandshake};
use pir_runtime_core::service_admission::{
    AdmissionCommitErrorV1, AdmissionEnforcementV1, AdmissionMethodCommitterV1,
    AdmissionMethodRouteV1, BackendFrameKindV1, BackendFrameV1, ConnectionAdmissionGateV1,
    GateErrorV1, ProviderStoreBearerCommitterV1, ServiceWireRequestV1,
};
use pir_service_protocol::{
    derive_bat_key_id_v1, derive_cashu_keyset_id_v2, paid_receipt_key_id, AcquisitionMethod,
    ArcPresentationCanonicalizerV1, ArcPresentationV1, AuthBeginV1, AuthPaddingClassV1,
    AuthResultV1, AuthScheme, AuthorizationProofV1, BackendId, BitcoinPirCashuBatProofV1,
    CashuDenominationKeyV1, CashuKeysetBindingV1, CashuRequiredNutsV1,
    CredentialKeyBindingClaimsV1, CredentialKeyBindingV1, CredentialUnitV1, DatasetBindingV1,
    DeploymentStatus, EntitlementLimitsV1, FreeAuthorizationProofV1, FreeModeV1, HintTransport,
    OperationStartV1, PaidReceiptBindingV1, PaidReceiptV1, PolicyRollbackGuardV1, PriceV1,
    PrivacyLeakageV1, ServiceOfferV1, ServicePolicyEpochFloorsV1, ServicePolicyV1,
    ServiceProtocolError, ServiceScopePolicyV1, ServiceScopeV1, StandardCashuMintManifestV1,
    StandardCashuProofV1, StandardCashuSpendV1, TrustedCatalogResolutionV1, VerificationMode,
    WorkloadId, REQ_AUTH_BEGIN_V1,
};
use sha2::{Digest, Sha256};
use x25519_dalek::StaticSecret;

use pir_service_store::{ProviderStore, StoreOptions, VerifiedOfferNamespaceInstallOutcomeV1};

const PROVIDER: [u8; 32] = [0x42; 32];
const DB_ID: u8 = 7;
const NOW_UNIX: u64 = 150;
const NOW_MONOTONIC_MS: u64 = 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MethodCase {
    Free,
    Bolt11Receipt,
    StandardCashu,
    CashuBat,
    ArcExperimental,
}

impl MethodCase {
    const ALL: [Self; 5] = [
        Self::Free,
        Self::Bolt11Receipt,
        Self::StandardCashu,
        Self::CashuBat,
        Self::ArcExperimental,
    ];

    fn expected_route(self) -> AdmissionMethodRouteV1 {
        match self {
            Self::Free => AdmissionMethodRouteV1::FreeOpenBestEffort,
            Self::Bolt11Receipt => AdmissionMethodRouteV1::Bolt11DirectReceiptProviderLocal,
            Self::StandardCashu => AdmissionMethodRouteV1::StandardCashuMintOnline,
            Self::CashuBat => AdmissionMethodRouteV1::BitcoinPirCashuBatProviderLocal,
            Self::ArcExperimental => AdmissionMethodRouteV1::ArcProviderLocalExperimental,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BackendCase {
    Dpf,
    HarmonyHint,
    HarmonyQuery,
    Onion,
    Oram,
}

impl BackendCase {
    const ALL: [Self; 5] = [
        Self::Dpf,
        Self::HarmonyHint,
        Self::HarmonyQuery,
        Self::Onion,
        Self::Oram,
    ];

    fn scope(self) -> ServiceScopeV1 {
        let (backend, workload, protocol_version) = match self {
            Self::Dpf => (BackendId::DpfPirV1, WorkloadId::DpfEvaluateJobV1, 1),
            Self::HarmonyHint => (BackendId::HarmonyPirV2, WorkloadId::HarmonyHintBundleV1, 2),
            Self::HarmonyQuery => (BackendId::HarmonyPirV2, WorkloadId::HarmonyQueryJobV1, 2),
            Self::Onion => (BackendId::OnionPirV1, WorkloadId::OnionEvaluateJobV1, 1),
            Self::Oram => (BackendId::TeeOramV1, WorkloadId::TeeOramQueryV1, 1),
        };
        ServiceScopeV1 {
            provider_id: PROVIDER,
            backend,
            workload,
            protocol_version,
            dataset: DatasetBindingV1::Class { class_id: 23 },
            operation_profile: 31,
            entitlement_profile: 41,
        }
    }

    fn operation(self) -> OperationStartV1 {
        match self {
            Self::Dpf => OperationStartV1::DpfQuery { db_id: DB_ID },
            Self::HarmonyHint => OperationStartV1::HarmonyHint {
                db_id: DB_ID,
                transport: HintTransport::V2Full,
                session_token: None,
                primary_side: None,
            },
            Self::HarmonyQuery => OperationStartV1::HarmonyQuery { db_id: DB_ID },
            Self::Onion => OperationStartV1::OnionSession { db_id: DB_ID },
            Self::Oram => OperationStartV1::TeeOramQuery { db_id: DB_ID },
        }
    }
}

#[derive(Debug, Default)]
struct AuthoritativeCommitterDouble {
    routes: Mutex<Vec<AdmissionMethodRouteV1>>,
    spent: Mutex<HashSet<[u8; 32]>>,
}

impl AdmissionMethodCommitterV1 for AuthoritativeCommitterDouble {
    fn verify_and_commit_v1(
        &self,
        route: AdmissionMethodRouteV1,
        attempt: &pir_service_protocol::BoundAuthAttemptV1<'_>,
        _now_unix_seconds: u64,
    ) -> Result<(), AdmissionCommitErrorV1> {
        let mut hasher = Sha256::new();
        hasher.update(b"BitcoinPIR/admission-matrix-spend-double/v1");
        hasher.update([route as u8]);
        hasher.update(attempt.scope().scope_id());
        hasher.update(
            attempt
                .operation()
                .digest()
                .map_err(|_| AdmissionCommitErrorV1::InvalidOrSpent)?,
        );
        hasher.update(
            attempt
                .proof()
                .encode_for(attempt.offer().authorization, attempt.offer().free_mode)
                .map_err(|_| AdmissionCommitErrorV1::InvalidOrSpent)?,
        );
        let spend_key: [u8; 32] = hasher.finalize().into();
        if !self.spent.lock().unwrap().insert(spend_key) {
            return Err(AdmissionCommitErrorV1::InvalidOrSpent);
        }
        self.routes.lock().unwrap().push(route);
        Ok(())
    }
}

fn point(multiplier: u64) -> [u8; 33] {
    (ProjectivePoint::GENERATOR * Scalar::from(multiplier))
        .to_affine()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap()
}

fn limits() -> EntitlementLimitsV1 {
    EntitlementLimitsV1 {
        max_logical_inputs: 8,
        max_frames: 8,
        max_request_bytes: 16_384,
        max_response_bytes: 32_768,
        max_wall_time_ms: 5_000,
        max_concurrent_sockets: 1,
        max_hint_groups: 8,
        max_work_units: 100,
    }
}

fn credential_binding(
    scope: &ServiceScopeV1,
    offer_id: u32,
    method: MethodCase,
) -> CredentialKeyBindingV1 {
    let issuer_key = SigningKey::from_bytes(&[0x61; 32]);
    let (scheme, unit, presentation_limit, verification_key, credential_key_id) = match method {
        MethodCase::Bolt11Receipt => {
            let receipt_key = SigningKey::from_bytes(&[0x62; 32]);
            let verification_key = receipt_key.verifying_key().to_bytes().to_vec();
            (
                AuthScheme::Bolt11DirectReceiptV1,
                CredentialUnitV1::Entitlement,
                1,
                verification_key,
                paid_receipt_key_id(&receipt_key.verifying_key()).to_vec(),
            )
        }
        MethodCase::CashuBat => {
            let verification_key = point(17);
            let key_id = derive_bat_key_id_v1(
                &scope.provider_id,
                &scope.scope_id(),
                offer_id,
                scope.entitlement_profile,
                1,
                &verification_key,
            )
            .to_vec();
            (
                AuthScheme::BitcoinPirCashuBatV1,
                CredentialUnitV1::Auth,
                1,
                verification_key.to_vec(),
                key_id,
            )
        }
        MethodCase::ArcExperimental => (
            AuthScheme::ArcV1Experimental,
            CredentialUnitV1::Auth,
            2,
            vec![0xa5; 99],
            vec![0xa6; 16],
        ),
        MethodCase::Free | MethodCase::StandardCashu => {
            panic!("method does not use a credential binding")
        }
    };
    CredentialKeyBindingV1::sign(
        CredentialKeyBindingClaimsV1 {
            provider_id: scope.provider_id,
            scope_id: scope.scope_id(),
            offer_id,
            scheme,
            keyset_epoch: 1,
            entitlement_profile: scope.entitlement_profile,
            unit,
            amount: 1,
            presentation_limit,
            not_before: 50,
            not_after: 300,
            credential_key_id,
            verification_key,
        },
        &issuer_key,
    )
    .unwrap()
}

fn cashu_manifest() -> StandardCashuMintManifestV1 {
    let keys = vec![CashuDenominationKeyV1 {
        amount: 1,
        public_key: point(21),
    }];
    let keyset = CashuKeysetBindingV1 {
        keyset_id: derive_cashu_keyset_id_v2(&keys, "sat", 0, None).unwrap(),
        unit: "sat".into(),
        input_fee_ppk: 0,
        final_expiry: None,
        keys,
    };
    StandardCashuMintManifestV1 {
        manifest_epoch: 1,
        mint_endpoint: "https://mint.example".into(),
        leaf_spki_sha256_pins: vec![[0x31; 32]],
        unit: "sat".into(),
        required_nuts: CashuRequiredNutsV1::required_v1(),
        accepted_input_keysets: vec![keyset.clone()],
        active_output_keyset: keyset,
    }
}

fn offer(scope: &ServiceScopeV1, method: MethodCase) -> ServiceOfferV1 {
    let offer_id = 9;
    let mut offer = ServiceOfferV1 {
        offer_id,
        acquisition: AcquisitionMethod::FreeV1,
        free_mode: FreeModeV1::OpenBestEffort,
        free_quota: 0,
        free_window_seconds: 0,
        free_pow_difficulty_bits: 0,
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
        retired_policy_grace_seconds: 100,
        credential_count: 1,
        credential_presentation_limit: 1,
        privacy_leakage: PrivacyLeakageV1::NONE,
    };
    match method {
        MethodCase::Free => {}
        MethodCase::Bolt11Receipt | MethodCase::CashuBat | MethodCase::ArcExperimental => {
            let binding = credential_binding(scope, offer_id, method);
            offer.acquisition = AcquisitionMethod::Bolt11V1;
            offer.free_mode = FreeModeV1::NotFree;
            offer.authorization = match method {
                MethodCase::Bolt11Receipt => AuthScheme::Bolt11DirectReceiptV1,
                MethodCase::CashuBat => AuthScheme::BitcoinPirCashuBatV1,
                MethodCase::ArcExperimental => AuthScheme::ArcV1Experimental,
                _ => unreachable!(),
            };
            offer.deployment_status = if method == MethodCase::ArcExperimental {
                DeploymentStatus::Experimental
            } else {
                DeploymentStatus::Stable
            };
            offer.price = PriceV1::MilliSatoshi(2_000);
            offer.issuer_id = binding.issuer_id;
            offer.key_id = binding.claims.credential_key_id.clone();
            offer.credential_binding = Some(binding);
            offer.endpoint = "https://issuer.example".into();
            offer.invoice_expiry_seconds = 10;
            offer.claim_window_seconds = 20;
            offer.credential_presentation_limit = if method == MethodCase::ArcExperimental {
                2
            } else {
                1
            };
            offer.privacy_leakage = PrivacyLeakageV1::from_bits(match method {
                MethodCase::Bolt11Receipt => PrivacyLeakageV1::DIRECT_PAYMENT_TO_SPEND,
                MethodCase::CashuBat | MethodCase::ArcExperimental => {
                    PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING
                        | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER
                        | PrivacyLeakageV1::PROVIDER_LOCAL_BEARER
                }
                _ => unreachable!(),
            })
            .unwrap();
        }
        MethodCase::StandardCashu => {
            let manifest = cashu_manifest();
            offer.acquisition = AcquisitionMethod::CashuEcashV1;
            offer.free_mode = FreeModeV1::NotFree;
            offer.authorization = AuthScheme::CashuEcashV1;
            offer.verification = VerificationMode::StandardCashuMintOnline;
            offer.price = PriceV1::Cashu {
                unit: "sat".into(),
                amount: 1,
            };
            offer.issuer_id = manifest.mint_id();
            offer.key_id = manifest.manifest_digest().unwrap().to_vec();
            offer.cashu_mint_manifest = Some(manifest);
            offer.endpoint = "https://mint.example".into();
            offer.privacy_leakage = PrivacyLeakageV1::from_bits(
                PrivacyLeakageV1::ISSUER_REDEMPTION_TIMING
                    | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER,
            )
            .unwrap();
        }
    }
    offer
}

fn proof(
    method: MethodCase,
    policy: &ServicePolicyV1,
    scope: &ServiceScopeV1,
    offer: &ServiceOfferV1,
) -> AuthorizationProofV1 {
    match method {
        MethodCase::Free => AuthorizationProofV1::Free(FreeAuthorizationProofV1::OpenBestEffort),
        MethodCase::Bolt11Receipt => {
            let signing_key = SigningKey::from_bytes(&[0x62; 32]);
            AuthorizationProofV1::Bolt11DirectReceipt(Box::new(
                PaidReceiptV1::sign(
                    offer.issuer_id,
                    [0x63; 32],
                    PaidReceiptBindingV1 {
                        scope_id: scope.scope_id(),
                        offer_id: offer.offer_id,
                        policy_digest: policy.policy_digest().unwrap(),
                        entitlement_profile: scope.entitlement_profile,
                    },
                    100,
                    250,
                    &signing_key,
                )
                .unwrap(),
            ))
        }
        MethodCase::StandardCashu => {
            let manifest = offer.cashu_mint_manifest.as_ref().unwrap();
            AuthorizationProofV1::StandardCashu(
                StandardCashuSpendV1::new_canonical(vec![StandardCashuProofV1 {
                    keyset_id: manifest.active_output_keyset.keyset_id.clone(),
                    amount: 1,
                    secret: "matrix-standard-cashu-proof".into(),
                    c: point(22),
                }])
                .unwrap(),
            )
        }
        MethodCase::CashuBat => {
            AuthorizationProofV1::BitcoinPirCashuBat(BitcoinPirCashuBatProofV1 {
                secret_raw: [0x64; 32],
                c: point(23),
            })
        }
        MethodCase::ArcExperimental => AuthorizationProofV1::ArcExperimental(
            ArcPresentationV1::from_canonical_bytes(vec![0x65; 32]).unwrap(),
        ),
    }
}

fn signed_fixture(
    method: MethodCase,
    backend: BackendCase,
) -> (ServicePolicyV1, AuthBeginV1, TrustedCatalogResolutionV1) {
    let scope = backend.scope();
    let offer = offer(&scope, method);
    let policy_key = SigningKey::from_bytes(&[0x51; 32]);
    let policy = ServicePolicyV1::sign(
        PROVIDER,
        1,
        100,
        200,
        AuthPaddingClassV1::Class16KiB,
        vec![ServiceScopePolicyV1 {
            scope: scope.clone(),
            limits: limits(),
            offers: vec![offer],
        }],
        &policy_key,
    )
    .unwrap();
    let verified = policy
        .verify_current_for_acquisition(
            &PROVIDER,
            NOW_UNIX,
            &PolicyRollbackGuardV1::initial(),
            &ServicePolicyEpochFloorsV1::initial(),
            &policy_key.verifying_key(),
        )
        .unwrap();
    let verified_offer = verified.offer(&scope.scope_id(), 9).unwrap();
    let typed_proof = proof(method, &policy, &scope, verified_offer.offer());
    let request = AuthBeginV1 {
        policy_digest: policy.policy_digest().unwrap(),
        scope_id: scope.scope_id(),
        offer_id: 9,
        scheme: verified_offer.offer().authorization,
        key_id: verified_offer.offer().key_id.clone(),
        operation: backend.operation(),
        proof: typed_proof
            .encode_for(
                verified_offer.offer().authorization,
                verified_offer.offer().free_mode,
            )
            .unwrap(),
    };
    let resolution = TrustedCatalogResolutionV1::new(
        DB_ID,
        scope.backend,
        scope.workload,
        scope.protocol_version,
        scope.dataset,
        scope.operation_profile,
    );
    (policy, request, resolution)
}

fn decode_auth_wire(request: &AuthBeginV1) -> AuthBeginV1 {
    let mut inner = Vec::with_capacity(1 + 16_384);
    inner.push(REQ_AUTH_BEGIN_V1);
    inner.extend_from_slice(&request.encode_padded().unwrap());

    // Exercise the real post-upgrade wire boundary rather than treating an
    // inner payload as though it had already crossed the secure channel. The
    // fixed seeds are test-only; production callers generate fresh entropy and
    // bind the client ephemeral key into the verified attestation report.
    let server_static = StaticSecret::from([0x31; 32]);
    let client_handshake = ClientHandshake::new([0x32; 32], [0x33; 32]);
    let server_handshake = ServerHandshake::new(&server_static, [0x34; 32]);
    let client_eph_pub = client_handshake.client_eph_pub();
    let nonce = client_handshake.nonce();
    let server_eph_pub = server_handshake.server_eph_pub();
    let server_static_pub = x25519_dalek::PublicKey::from(&server_static);
    let mut client_session =
        client_handshake.complete_handshake(server_static_pub.as_bytes(), &server_eph_pub);
    let mut server_session = server_handshake.complete_handshake(&client_eph_pub, &nonce);
    let encrypted = client_session
        .seal(Direction::ClientToServer, &inner)
        .unwrap();
    assert_ne!(encrypted.as_slice(), inner.as_slice());
    let decrypted = server_session
        .open(Direction::ClientToServer, &encrypted)
        .unwrap();
    assert!(
        server_session
            .open(Direction::ClientToServer, &encrypted)
            .is_err(),
        "the secure channel must reject an authorization-frame replay"
    );

    let Some(ServiceWireRequestV1::Auth(decoded)) =
        ServiceWireRequestV1::decode_inner_payload(&decrypted).unwrap()
    else {
        panic!("canonical AUTH_BEGIN must decode as a service auth frame")
    };
    *decoded
}

fn authorize(
    policy: &ServicePolicyV1,
    request: &AuthBeginV1,
    resolution: &TrustedCatalogResolutionV1,
    committer: &dyn AdmissionMethodCommitterV1,
) -> (ConnectionAdmissionGateV1, AuthResultV1) {
    let policy_key = SigningKey::from_bytes(&[0x51; 32]);
    let verified = policy
        .verify_current_for_acquisition(
            &PROVIDER,
            NOW_UNIX,
            &PolicyRollbackGuardV1::initial(),
            &ServicePolicyEpochFloorsV1::initial(),
            &policy_key.verifying_key(),
        )
        .unwrap();
    let verified_offer = verified.offer(&request.scope_id, request.offer_id).unwrap();
    let catalog = |operation: &OperationStartV1| {
        if operation == &request.operation {
            Some(resolution.clone())
        } else {
            None
        }
    };
    let canonicalizer =
        |bytes: &[u8]| -> Result<Vec<u8>, ServiceProtocolError> { Ok(bytes.to_vec()) };
    let arc_canonicalizer: Option<&dyn ArcPresentationCanonicalizerV1> = Some(&canonicalizer);
    let mut gate = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
    gate.secure_channel_established();
    gate.policy_served(true, request.policy_digest).unwrap();
    let result = gate.authorize_and_commit(
        true,
        request,
        verified_offer,
        &catalog,
        arc_canonicalizer,
        committer,
        NOW_UNIX,
        NOW_MONOTONIC_MS,
    );
    (gate, result)
}

#[test]
fn direct_receipt_production_committer_spend_survives_store_restart() {
    let method = MethodCase::Bolt11Receipt;
    let backend = BackendCase::Dpf;
    let (policy, request, resolution) = signed_fixture(method, backend);
    let decoded = decode_auth_wire(&request);
    let policy_key = SigningKey::from_bytes(&[0x51; 32]);
    let verified = policy
        .verify_current_for_acquisition(
            &PROVIDER,
            NOW_UNIX,
            &PolicyRollbackGuardV1::initial(),
            &ServicePolicyEpochFloorsV1::initial(),
            &policy_key.verifying_key(),
        )
        .unwrap();
    let verified_offer = verified.offer(&request.scope_id, request.offer_id).unwrap();

    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let store_path = directory.path().join("provider.sqlite3");
    let store = ProviderStore::create(&store_path, [0x71; 16], PROVIDER, StoreOptions::default())
        .unwrap();
    assert!(matches!(
        store
            .install_verified_offer_namespace_v1(&verified_offer, NOW_UNIX, None)
            .unwrap(),
        VerifiedOfferNamespaceInstallOutcomeV1::Namespace { .. }
    ));

    {
        let committer = ProviderStoreBearerCommitterV1::new(&store, None);
        let (mut gate, first) = authorize(&policy, &decoded, &resolution, &committer);
        assert!(matches!(first, AuthResultV1::Granted(_)));
        let _permit = gate
            .permit_backend_frame(
                true,
                &frame(BackendFrameKindV1::DpfIndexBatch),
                NOW_MONOTONIC_MS + 1,
            )
            .unwrap();
    }
    drop(store);

    let reopened =
        ProviderStore::open_existing(&store_path, PROVIDER, StoreOptions::default()).unwrap();
    let committer = ProviderStoreBearerCommitterV1::new(&reopened, None);
    let (mut replay_gate, replay) = authorize(&policy, &decoded, &resolution, &committer);
    assert!(matches!(
        replay,
        AuthResultV1::Rejected(ref rejected)
            if rejected.code == pir_service_protocol::AuthRejectCode::InvalidOrSpent
    ));
    assert_eq!(
        replay_gate.permit_backend_frame(
            true,
            &frame(BackendFrameKindV1::DpfIndexBatch),
            NOW_MONOTONIC_MS + 1,
        ),
        Err(GateErrorV1::TerminalAfterSpend)
    );
}

fn frame(kind: BackendFrameKindV1) -> BackendFrameV1 {
    BackendFrameV1 {
        kind,
        db_id: DB_ID,
        logical_inputs: 1,
        hint_groups: 0,
        request_bytes: 128,
        work_units: 2,
    }
}

fn exercise_backend(gate: &mut ConnectionAdmissionGateV1, backend: BackendCase) {
    match backend {
        BackendCase::Dpf => {
            let _permit = gate
                .permit_backend_frame(
                    true,
                    &frame(BackendFrameKindV1::DpfIndexBatch),
                    NOW_MONOTONIC_MS + 1,
                )
                .unwrap();
            let _permit = gate
                .permit_backend_frame(
                    true,
                    &BackendFrameV1 {
                        logical_inputs: 0,
                        ..frame(BackendFrameKindV1::DpfChunkBatch)
                    },
                    NOW_MONOTONIC_MS + 2,
                )
                .unwrap();
            let _permit = gate
                .permit_backend_frame(
                    true,
                    &BackendFrameV1 {
                        logical_inputs: 0,
                        ..frame(BackendFrameKindV1::DpfMerkleSiblingBatch)
                    },
                    NOW_MONOTONIC_MS + 3,
                )
                .unwrap();
        }
        BackendCase::HarmonyHint => {
            let mut hint = frame(BackendFrameKindV1::HarmonyHintV2Full);
            hint.logical_inputs = 0;
            hint.hint_groups = 1;
            let _permit = gate
                .permit_backend_frame(true, &hint, NOW_MONOTONIC_MS + 1)
                .unwrap();
        }
        BackendCase::HarmonyQuery => {
            let _permit = gate
                .permit_backend_frame(
                    true,
                    &frame(BackendFrameKindV1::HarmonyBatchQuery {
                        level: 0,
                        round_id: 0,
                        index_sibling_levels: 1,
                        chunk_sibling_levels: 1,
                    }),
                    NOW_MONOTONIC_MS + 1,
                )
                .unwrap();
        }
        BackendCase::Onion => {
            let mut register = frame(BackendFrameKindV1::OnionRegisterKeys);
            register.logical_inputs = 0;
            let _permit = gate
                .permit_backend_frame(true, &register, NOW_MONOTONIC_MS + 1)
                .unwrap();
            let _permit = gate
                .permit_backend_frame(
                    true,
                    &frame(BackendFrameKindV1::OnionIndexQuery { round_id: 0 }),
                    NOW_MONOTONIC_MS + 2,
                )
                .unwrap();
            let mut chunk = frame(BackendFrameKindV1::OnionChunkQuery { round_id: 0 });
            chunk.logical_inputs = 0;
            let _permit = gate
                .permit_backend_frame(true, &chunk, NOW_MONOTONIC_MS + 3)
                .unwrap();
            let mut merkle = frame(BackendFrameKindV1::OnionMerkleIndexSibling { round_id: 0 });
            merkle.logical_inputs = 0;
            let _permit = gate
                .permit_backend_frame(true, &merkle, NOW_MONOTONIC_MS + 4)
                .unwrap();
        }
        BackendCase::Oram => {
            let _permit = gate
                .permit_backend_frame(
                    true,
                    &frame(BackendFrameKindV1::TeeOramQuery),
                    NOW_MONOTONIC_MS + 1,
                )
                .unwrap();
        }
    }
    gate.reserve_response_bytes(256).unwrap();
    let usage = gate
        .usage()
        .expect("successful grant exposes bounded usage");
    assert!(usage.frames >= 1);
    assert_eq!(usage.response_bytes, 256);
}

#[test]
fn every_v1_payment_method_reaches_every_v1_backend_gate() {
    for method in MethodCase::ALL {
        for backend in BackendCase::ALL {
            let (policy, request, resolution) = signed_fixture(method, backend);
            let decoded = decode_auth_wire(&request);
            assert_eq!(decoded, request, "wire mismatch for {method:?}/{backend:?}");
            let committer = AuthoritativeCommitterDouble::default();
            let (mut gate, result) = authorize(&policy, &decoded, &resolution, &committer);
            assert!(
                matches!(result, AuthResultV1::Granted(_)),
                "authorization failed for {method:?}/{backend:?}: {result:?}"
            );
            assert_eq!(
                committer.routes.lock().unwrap().as_slice(),
                &[method.expected_route()],
                "wrong route for {method:?}/{backend:?}"
            );
            exercise_backend(&mut gate, backend);
        }
    }
}

#[test]
fn each_matrix_cell_commits_before_work_and_replay_stays_terminal() {
    for method in MethodCase::ALL {
        for backend in BackendCase::ALL {
            let (policy, request, resolution) = signed_fixture(method, backend);
            let decoded = decode_auth_wire(&request);
            let committer = AuthoritativeCommitterDouble::default();

            let (mut first_gate, first) = authorize(&policy, &decoded, &resolution, &committer);
            assert!(matches!(first, AuthResultV1::Granted(_)));
            exercise_backend(&mut first_gate, backend);

            let (mut replay_gate, replay) = authorize(&policy, &decoded, &resolution, &committer);
            assert!(
                matches!(replay, AuthResultV1::Rejected(ref rejected) if rejected.code == pir_service_protocol::AuthRejectCode::InvalidOrSpent),
                "replay was not rejected for {method:?}/{backend:?}: {replay:?}"
            );
            assert_eq!(
                replay_gate.permit_backend_frame(
                    true,
                    &frame(BackendFrameKindV1::DpfIndexBatch),
                    NOW_MONOTONIC_MS + 1,
                ),
                Err(GateErrorV1::TerminalAfterSpend),
                "rejected replay left backend work reachable for {method:?}/{backend:?}"
            );
        }
    }
}
