//! Loopback-only Payment V1 to TEE-ORAM process integration test.
//!
//! The fixture builds a tiny direct INDEX/CHUNK Circuit ORAM with the same
//! public `bitcoinpir-oram` API used by `oramctl build-direct`. Bulk images,
//! authenticated sidecars and controller/trusted state are real on-disk
//! artifacts. The test then starts the production `unified_server` binary and
//! crosses its real WebSocket, secure-channel, Payment V1 admission and direct
//! ORAM handler boundaries.
//!
//! All keys and data are deterministic public test fixtures. This deliberately
//! observes `NoSevHost` and uses the SDK's `dangerous_unpaired_*` primitives;
//! it is not evidence of production attestation, binary pinning, DB proof,
//! external rollback authority, wallet operation or real funds.

#![cfg(all(unix, feature = "cuckoo-oram"))]

use bitcoinpir_oram::{
    circuit_meta_page_bytes, circuit_payload_page_bytes, CircuitOram, CircuitStoreAuthState,
    DirectChunkPackedBlockReader, DirectIndexPackedBlockReader, DirectLevel, DirectTableInfo,
    DirectTableMetadata, FilePageStore, OramParams, PageStore, TieredMerklePageStore,
    TrustedBlockSource, DIRECT_CHUNK_RECORD_SIZE, DIRECT_INDEX_INPUT_RECORD_SIZE,
};
use ed25519_dalek::SigningKey;
use pir_core::cuckoo::write_header_with_anchor;
use pir_core::merkle::sha256;
use pir_core::params::{CHUNK_PARAMS, INDEX_PARAMS, SCRIPT_HASH_SIZE};
use pir_runtime_core::protocol::{OramLookupRequest, Request, Response};
use pir_sdk_client::attest::{attest_with_eph_binding, SevStatus};
use pir_sdk_client::channel::{establish, SecureChannelTransport};
use pir_sdk_client::{
    dangerous_unpaired_accept_service_authorization_response_v1,
    dangerous_unpaired_authorize_service_operation_v1,
    dangerous_unpaired_build_authorization_proof_v1, fetch_verified_service_policy_v1,
    AcceptedServicePolicyV1, PirTransport, ServicePolicyCheckpointV1, WsConnection,
};
use pir_service_protocol::{
    derive_provider_id, paid_receipt_key_id, AcquisitionMethod, AuthBeginV1, AuthPaddingClassV1,
    AuthScheme, AuthorizationProofV1, BackendId, CredentialKeyBindingClaimsV1,
    CredentialKeyBindingV1, CredentialUnitV1, DatasetBindingV1, DeploymentStatus,
    EntitlementLimitsV1, FreeModeV1, OperationStartV1, PaidReceiptBindingV1, PaidReceiptV1,
    PriceV1, PrivacyLeakageV1, ServiceOfferV1, ServicePolicyV1, ServiceScopePolicyV1,
    ServiceScopeV1, VerificationMode, WorkloadId, REQ_AUTH_BEGIN_V1,
};
use pir_service_store::{ProviderStore, SqliteRollbackFloorAuthorityV1, StoreOptions};
use std::fs::{self, File};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const OFFER_ID: u32 = 41;
const OPERATION_PROFILE: u16 = 44;
const ENTITLEMENT_PROFILE: u16 = 144;
const DIRECT_ORAM_PACK: usize = 2;
const DIRECT_ORAM_ACCESS_BUDGET: usize = 8;
const TINY_BINS_PER_TABLE: usize = 128;
static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
struct ProviderFixture {
    provider_id: [u8; 32],
    policy_signing_key: SigningKey,
    receipt_signing_key: SigningKey,
    issuer_id: [u8; 32],
    policy_path: PathBuf,
    store_path: PathBuf,
    rollback_path: PathBuf,
    tee_scope_id: [u8; 32],
    dpf_scope_id: [u8; 32],
    other_provider_tee_scope_id: [u8; 32],
    policy_digest: [u8; 32],
    issued_at: u64,
    receipt_not_after: u64,
}

impl ProviderFixture {
    fn receipt(&self, scope_id: [u8; 32], serial_byte: u8) -> PaidReceiptV1 {
        PaidReceiptV1::sign(
            self.issuer_id,
            [serial_byte; 32],
            PaidReceiptBindingV1 {
                scope_id,
                offer_id: OFFER_ID,
                policy_digest: self.policy_digest,
                entitlement_profile: ENTITLEMENT_PROFILE,
            },
            self.issued_at,
            self.receipt_not_after,
            &self.receipt_signing_key,
        )
        .expect("deterministic receipt fixture must be valid")
    }
}

struct DirectOramFixture {
    image_dir: PathBuf,
    trusted_state_dir: PathBuf,
    found_script_hash: [u8; SCRIPT_HASH_SIZE],
    expected_chunk_data: Vec<u8>,
}

struct ServerProcess {
    child: Child,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

impl ServerProcess {
    fn spawn(
        root: &Path,
        db_path: &Path,
        oram: &DirectOramFixture,
        fixture: &ProviderFixture,
        port: u16,
        generation: u8,
    ) -> Self {
        let stdout_path = root.join(format!("tee-oram-generation-{generation}-stdout.log"));
        let stderr_path = root.join(format!("tee-oram-generation-{generation}-stderr.log"));
        let stdout = File::create(&stdout_path).expect("create server stdout log");
        let stderr = File::create(&stderr_path).expect("create server stderr log");
        let direct_oram = format!("0={}", oram.image_dir.display());
        let trusted_state = format!("0={}", oram.trusted_state_dir.display());
        let child = Command::new(env!("CARGO_BIN_EXE_unified_server"))
            .args([
                "--bind-address",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--data-dir",
                db_path.to_str().expect("UTF-8 test path"),
                "--role",
                "secondary",
                "--disable-onion",
                "--serve-queries",
                "--direct-oram-db",
                &direct_oram,
                "--direct-oram-trusted-state-db",
                &trusted_state,
                "--direct-oram-drain-per-access",
                "2",
                "--direct-oram-access-budget",
                &DIRECT_ORAM_ACCESS_BUDGET.to_string(),
                "--direct-oram-auth-store",
                "--require-service-auth-v1",
                "--service-policy",
                fixture.policy_path.to_str().expect("UTF-8 test path"),
                "--service-provider-id-hex",
                &hex::encode(fixture.provider_id),
                "--service-policy-key-hex",
                &hex::encode(fixture.policy_signing_key.verifying_key().to_bytes()),
                "--service-store",
                fixture.store_path.to_str().expect("UTF-8 test path"),
                "--service-rollback-authority",
                fixture.rollback_path.to_str().expect("UTF-8 test path"),
                "--allow-local-service-rollback-authority-dev",
                "--max-connections",
                "16",
                "--service-max-concurrent-auth",
                "4",
                "--websocket-handshake-timeout-ms",
                "1000",
                "--connection-idle-timeout-ms",
                "60000",
                "--service-pre-auth-timeout-ms",
                "60000",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("spawn ORAM-enabled unified_server");
        let mut server = Self {
            child,
            stdout_path,
            stderr_path,
        };
        server.wait_until_listening(port);
        server
    }

    fn wait_until_listening(&mut self, port: u16) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.child.try_wait().expect("poll unified_server") {
                panic!(
                    "unified_server exited before listening ({status})\nstdout:\n{}\nstderr:\n{}",
                    read_log(&self.stdout_path),
                    read_log(&self.stderr_path),
                );
            }
            if TcpStream::connect_timeout(
                &format!("127.0.0.1:{port}").parse().unwrap(),
                Duration::from_millis(100),
            )
            .is_ok()
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for loopback unified_server\nstdout:\n{}\nstderr:\n{}",
                read_log(&self.stdout_path),
                read_log(&self.stderr_path),
            );
            thread::sleep(Duration::from_millis(50));
        }
    }

    fn stop(mut self) -> (String, String) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        (read_log(&self.stdout_path), read_log(&self.stderr_path))
    }
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if thread::panicking() {
            eprintln!(
                "unified_server logs after test failure\nstdout:\n{}\nstderr:\n{}",
                read_log(&self.stdout_path),
                read_log(&self.stderr_path),
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paid_gate_reaches_real_direct_tee_oram_handler_and_replay_survives_restart() {
    let root = tempfile::tempdir().expect("test root");
    chmod(root.path(), 0o700);
    let (db_path, manifest_root) = write_tiny_manifest_database(root.path());
    let oram = build_direct_oram_fixture(root.path());
    let provider = build_provider(root.path(), manifest_root, unix_now());
    let port = unused_loopback_port();
    let server = ServerProcess::spawn(root.path(), &db_path, &oram, &provider, port, 0);
    let request =
        Request::OramLookup(OramLookupRequest::compact(0, vec![oram.found_script_hash])).encode();

    assert_ne!(provider.tee_scope_id, provider.dpf_scope_id);
    assert_ne!(provider.tee_scope_id, provider.other_provider_tee_scope_id);

    // The same issuer key cannot turn a capability bound to another provider
    // audience into value at this provider.
    reject_wrong_receipt_scope(
        port,
        &provider,
        manifest_root,
        &request,
        &provider.receipt(provider.other_provider_tee_scope_id, 0x61),
    )
    .await;

    // Backend and workload are part of the scope digest. A correctly signed
    // DPF-scoped receipt cannot authorize the TEE-ORAM offer.
    reject_wrong_receipt_scope(
        port,
        &provider,
        manifest_root,
        &request,
        &provider.receipt(provider.dpf_scope_id, 0x62),
    )
    .await;

    let receipt = provider.receipt(provider.tee_scope_id, 0x70);
    let (mut secure, accepted) =
        open_verified_session(port, &provider, manifest_root, &request).await;
    let proof = dangerous_unpaired_build_authorization_proof_v1(
        &accepted,
        &provider.tee_scope_id,
        OFFER_ID,
        &receipt.encode().unwrap(),
    )
    .unwrap();

    // Send a deliberately raw request because the SDK correctly refuses to
    // construct an operation/scope mismatch. The server rejects this before
    // proof verification/commit; the exact receipt is then still accepted for
    // its signed TEE-ORAM workload.
    let wrong_operation = raw_authorization_request(
        &accepted,
        provider.tee_scope_id,
        OperationStartV1::DpfQuery { db_id: 0 },
        proof.clone(),
    );
    let wrong_operation_response = secure.roundtrip(&wrong_operation).await.unwrap();
    let wrong_operation_error = dangerous_unpaired_accept_service_authorization_response_v1(
        &wrong_operation_response,
        &accepted,
        provider.tee_scope_id,
    )
    .unwrap_err();
    assert!(
        wrong_operation_error.to_string().contains("wrong-scope"),
        "{wrong_operation_error}"
    );

    let grant = dangerous_unpaired_authorize_service_operation_v1(
        &mut secure,
        &accepted,
        provider.tee_scope_id,
        OFFER_ID,
        OperationStartV1::TeeOramQuery { db_id: 0 },
        proof,
    )
    .await
    .expect("TEE-ORAM receipt must authorize its exact provider/backend/workload");
    assert_eq!(grant.scope_id, provider.tee_scope_id);
    assert_eq!(grant.enforced_profile, ENTITLEMENT_PROFILE);

    assert_real_oram_result(
        &secure.roundtrip(&request).await.unwrap(),
        &oram.expected_chunk_data,
    );
    expect_error_response(
        &secure.roundtrip(&request).await.unwrap(),
        "already used an authorization",
    );
    secure.close().await.unwrap();

    let (stdout_first, stderr_first) = server.stop();
    assert_oram_listener(port, &stdout_first, &stderr_first, &oram);

    // Reopen the same authenticated ORAM state and provider spend domain. The
    // spent receipt stays terminal across the process boundary.
    let server = ServerProcess::spawn(root.path(), &db_path, &oram, &provider, port, 1);
    let (mut replay_session, replay_policy) =
        open_verified_session(port, &provider, manifest_root, &request).await;
    let replay_proof = dangerous_unpaired_build_authorization_proof_v1(
        &replay_policy,
        &provider.tee_scope_id,
        OFFER_ID,
        &receipt.encode().unwrap(),
    )
    .unwrap();
    let replay = dangerous_unpaired_authorize_service_operation_v1(
        &mut replay_session,
        &replay_policy,
        provider.tee_scope_id,
        OFFER_ID,
        OperationStartV1::TeeOramQuery { db_id: 0 },
        replay_proof,
    )
    .await
    .unwrap_err();
    assert!(replay.to_string().contains("invalid-or-spent"), "{replay}");
    replay_session.close().await.unwrap();

    // A fresh capability proves that restart recovered usable ORAM controller
    // and authentication state, rather than only recovering the spent set.
    let fresh = provider.receipt(provider.tee_scope_id, 0x71);
    exercise_fresh_oram_grant(
        port,
        &provider,
        manifest_root,
        &request,
        &fresh,
        &oram.expected_chunk_data,
    )
    .await;

    let (stdout_second, stderr_second) = server.stop();
    assert_oram_listener(port, &stdout_second, &stderr_second, &oram);
}

async fn reject_wrong_receipt_scope(
    port: u16,
    fixture: &ProviderFixture,
    manifest_root: [u8; 32],
    request: &[u8],
    receipt: &PaidReceiptV1,
) {
    let (mut secure, accepted) = open_verified_session(port, fixture, manifest_root, request).await;
    let proof = dangerous_unpaired_build_authorization_proof_v1(
        &accepted,
        &fixture.tee_scope_id,
        OFFER_ID,
        &receipt.encode().unwrap(),
    )
    .unwrap();
    let error = dangerous_unpaired_authorize_service_operation_v1(
        &mut secure,
        &accepted,
        fixture.tee_scope_id,
        OFFER_ID,
        OperationStartV1::TeeOramQuery { db_id: 0 },
        proof,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("invalid-or-spent"), "{error}");
    secure.close().await.unwrap();
}

async fn exercise_fresh_oram_grant(
    port: u16,
    fixture: &ProviderFixture,
    manifest_root: [u8; 32],
    request: &[u8],
    receipt: &PaidReceiptV1,
    expected_chunk_data: &[u8],
) {
    let (mut secure, accepted) = open_verified_session(port, fixture, manifest_root, request).await;
    let proof = dangerous_unpaired_build_authorization_proof_v1(
        &accepted,
        &fixture.tee_scope_id,
        OFFER_ID,
        &receipt.encode().unwrap(),
    )
    .unwrap();
    dangerous_unpaired_authorize_service_operation_v1(
        &mut secure,
        &accepted,
        fixture.tee_scope_id,
        OFFER_ID,
        OperationStartV1::TeeOramQuery { db_id: 0 },
        proof,
    )
    .await
    .expect("fresh post-restart TEE-ORAM receipt must authorize");
    assert_real_oram_result(
        &secure.roundtrip(request).await.unwrap(),
        expected_chunk_data,
    );
    secure.close().await.unwrap();
}

fn raw_authorization_request(
    accepted: &AcceptedServicePolicyV1,
    scope_id: [u8; 32],
    operation: OperationStartV1,
    proof: AuthorizationProofV1,
) -> Vec<u8> {
    let scope_policy = accepted
        .policy()
        .scopes
        .iter()
        .find(|entry| entry.scope.scope_id() == scope_id)
        .unwrap();
    let offer = scope_policy
        .offers
        .iter()
        .find(|offer| offer.offer_id == OFFER_ID)
        .unwrap();
    let request = AuthBeginV1 {
        policy_digest: accepted.policy_digest(),
        scope_id,
        offer_id: OFFER_ID,
        scheme: offer.authorization,
        key_id: offer.key_id.clone(),
        operation,
        proof: proof
            .encode_for(offer.authorization, offer.free_mode)
            .unwrap(),
    };
    encode_request(REQ_AUTH_BEGIN_V1, &request.encode_padded().unwrap())
}

fn encode_request(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let total_len = 1usize.checked_add(payload.len()).unwrap();
    let mut request = Vec::with_capacity(4 + total_len);
    request.extend_from_slice(&u32::try_from(total_len).unwrap().to_le_bytes());
    request.push(opcode);
    request.extend_from_slice(payload);
    request
}

async fn open_verified_session(
    port: u16,
    fixture: &ProviderFixture,
    manifest_root: [u8; 32],
    backend_request: &[u8],
) -> (
    SecureChannelTransport<WsConnection>,
    AcceptedServicePolicyV1,
) {
    let url = format!("ws://127.0.0.1:{port}");
    let mut raw = WsConnection::connect_once(&url)
        .await
        .expect("connect loopback WebSocket");

    let local_reject = fetch_verified_service_policy_v1(
        &mut raw,
        fixture.provider_id,
        &fixture.policy_signing_key.verifying_key(),
        unix_now(),
        &ServicePolicyCheckpointV1::initial(),
    )
    .await
    .unwrap_err();
    assert!(local_reject.to_string().contains("secure-channel"));
    expect_error_response(
        &raw.roundtrip(backend_request).await.unwrap(),
        "secure encrypted channel is required",
    );

    let session_id = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut eph_seed = [0x21; 32];
    let mut random = [0x41; 32];
    let mut handshake_nonce = [0x61; 32];
    eph_seed[..8].copy_from_slice(&session_id.to_le_bytes());
    random[..8].copy_from_slice(&session_id.wrapping_add(0x1000).to_le_bytes());
    handshake_nonce[..8].copy_from_slice(&session_id.wrapping_add(0x2000).to_le_bytes());
    let attestation = attest_with_eph_binding(&mut raw, eph_seed, random)
        .await
        .expect("attestation-bound channel key");
    assert_eq!(attestation.sev_status, SevStatus::NoSevHost);
    assert_eq!(attestation.response.manifest_roots, vec![manifest_root]);
    assert!(attestation
        .response
        .server_static_pub
        .iter()
        .any(|byte| *byte != 0));

    let mut secure = establish(
        raw,
        attestation.response.server_static_pub,
        eph_seed,
        handshake_nonce,
    )
    .await
    .expect("secure-channel upgrade");
    let accepted = fetch_verified_service_policy_v1(
        &mut secure,
        fixture.provider_id,
        &fixture.policy_signing_key.verifying_key(),
        unix_now(),
        &ServicePolicyCheckpointV1::initial(),
    )
    .await
    .expect("verify exact signed provider policy");
    assert_eq!(accepted.policy_digest(), fixture.policy_digest);
    expect_error_response(
        &secure.roundtrip(backend_request).await.unwrap(),
        "authorization required",
    );
    (secure, accepted)
}

fn assert_real_oram_result(response: &[u8], expected_chunk_data: &[u8]) {
    match Response::decode(response).unwrap() {
        Response::OramLookupResult(result) => {
            assert_eq!(result.db_id, 0);
            assert_eq!(result.items.len(), 1);
            let item = &result.items[0];
            assert!(item.found);
            assert!(!item.whale);
            assert_eq!(item.start_chunk_id, 3);
            assert_eq!(item.num_chunks, 2);
            assert_eq!(item.raw_chunk_data, expected_chunk_data);
            // The decoder intentionally discards indistinguishable trailing
            // response padding. Compare the observed encrypted response body
            // length with the canonical unpadded re-encoding instead.
            let unpadded_len = Response::OramLookupResult(result.clone()).encode().len() - 4;
            assert_eq!(
                response.len() - unpadded_len,
                (DIRECT_ORAM_ACCESS_BUDGET - 2) * DIRECT_CHUNK_RECORD_SIZE
                    - expected_chunk_data.len()
            );
        }
        other => panic!("authorized TEE-ORAM frame did not reach real handler: {other:?}"),
    }
}

fn assert_oram_listener(port: u16, stdout: &str, stderr: &str, oram: &DirectOramFixture) {
    assert!(stdout.contains(&format!("Listening on ws://127.0.0.1:{port}")));
    assert!(stdout.contains("Service admission V1: enforced"));
    assert!(stdout.contains("Direct ORAM: enabled for db_id=0"));
    assert!(stdout.contains("auth_store=true"));
    assert!(stdout.contains(&format!(
        "trusted_state_dir={}",
        oram.trusted_state_dir.display()
    )));
    assert!(!stderr.contains("UNSAFE DEBUG QUERY LOGGING ENABLED"));
    assert!(!stdout.contains(&hex::encode(oram.found_script_hash)));
    assert!(!stderr.contains(&hex::encode(oram.found_script_hash)));
}

fn build_provider(root: &Path, manifest_root: [u8; 32], now: u64) -> ProviderFixture {
    let provider_root = root.join("tee-oram-provider");
    let store_dir = provider_root.join("store-domain");
    let rollback_dir = provider_root.join("rollback-domain");
    fs::create_dir_all(&store_dir).unwrap();
    fs::create_dir_all(&rollback_dir).unwrap();
    chmod(&provider_root, 0o700);
    chmod(&store_dir, 0o700);
    chmod(&rollback_dir, 0o700);

    let operator_key = SigningKey::from_bytes(&[0x11; 32]);
    let policy_signing_key = SigningKey::from_bytes(&[0x22; 32]);
    let issuer_root_key = SigningKey::from_bytes(&[0x33; 32]);
    let receipt_signing_key = SigningKey::from_bytes(&[0x44; 32]);
    let provider_id = derive_provider_id(
        &operator_key.verifying_key().to_bytes(),
        "payment-v1-process-tee-oram-provider",
    );
    let other_provider_id = derive_provider_id(
        &SigningKey::from_bytes(&[0x12; 32])
            .verifying_key()
            .to_bytes(),
        "payment-v1-process-other-provider",
    );
    let issued_at = now.saturating_sub(60);
    let expires_at = now.checked_add(3_600).unwrap();
    let receipt_not_after = now.checked_add(600).unwrap();
    let tee_scope = service_scope(
        provider_id,
        BackendId::TeeOramV1,
        WorkloadId::TeeOramQueryV1,
        1,
        manifest_root,
    );
    let tee_scope_id = tee_scope.scope_id();
    let dpf_scope_id = service_scope(
        provider_id,
        BackendId::DpfPirV1,
        WorkloadId::DpfEvaluateJobV1,
        1,
        manifest_root,
    )
    .scope_id();
    let other_provider_tee_scope_id = service_scope(
        other_provider_id,
        BackendId::TeeOramV1,
        WorkloadId::TeeOramQueryV1,
        1,
        manifest_root,
    )
    .scope_id();
    let receipt_key_id = paid_receipt_key_id(&receipt_signing_key.verifying_key()).to_vec();
    let retired_policy_grace_seconds = 1_800;
    let binding = CredentialKeyBindingV1::sign(
        CredentialKeyBindingClaimsV1 {
            provider_id,
            scope_id: tee_scope_id,
            offer_id: OFFER_ID,
            scheme: AuthScheme::Bolt11DirectReceiptV1,
            keyset_epoch: 1,
            entitlement_profile: ENTITLEMENT_PROFILE,
            unit: CredentialUnitV1::Entitlement,
            amount: 1,
            presentation_limit: 1,
            not_before: issued_at.saturating_sub(60),
            not_after: expires_at + u64::from(retired_policy_grace_seconds),
            credential_key_id: receipt_key_id.clone(),
            verification_key: receipt_signing_key.verifying_key().to_bytes().to_vec(),
        },
        &issuer_root_key,
    )
    .unwrap();
    let offer = ServiceOfferV1 {
        offer_id: OFFER_ID,
        acquisition: AcquisitionMethod::Bolt11V1,
        free_mode: FreeModeV1::NotFree,
        free_quota: 0,
        free_window_seconds: 0,
        free_pow_difficulty_bits: 0,
        priority_class: 10,
        authorization: AuthScheme::Bolt11DirectReceiptV1,
        verification: VerificationMode::ProviderLocal,
        deployment_status: DeploymentStatus::Stable,
        price: PriceV1::MilliSatoshi(2_000),
        issuer_id: binding.issuer_id,
        key_id: receipt_key_id,
        credential_binding: Some(binding.clone()),
        cashu_mint_manifest: None,
        endpoint: "https://tee-oram-issuer.fixture.invalid".into(),
        invoice_expiry_seconds: 600,
        claim_window_seconds: 600,
        minimum_credential_validity_seconds: 600,
        retired_policy_grace_seconds,
        credential_count: 1,
        credential_presentation_limit: 1,
        privacy_leakage: PrivacyLeakageV1::from_bits(PrivacyLeakageV1::DIRECT_PAYMENT_TO_SPEND)
            .unwrap(),
    };
    let policy = ServicePolicyV1::sign(
        provider_id,
        1,
        issued_at,
        expires_at,
        AuthPaddingClassV1::Class16KiB,
        vec![ServiceScopePolicyV1 {
            scope: tee_scope,
            limits: EntitlementLimitsV1 {
                max_logical_inputs: 1,
                max_frames: 1,
                max_request_bytes: 16 * 1024,
                max_response_bytes: 4 * 1024,
                max_wall_time_ms: 10_000,
                max_concurrent_sockets: 1,
                max_hint_groups: 0,
                max_work_units: 1,
            },
            offers: vec![offer],
        }],
        &policy_signing_key,
    )
    .unwrap();
    let policy_digest = policy.policy_digest().unwrap();
    let policy_path = provider_root.join("service-policy-v1.bin");
    fs::write(&policy_path, policy.encode().unwrap()).unwrap();
    chmod(&policy_path, 0o644);

    let store_path = store_dir.join("provider.sqlite3");
    let rollback_path = rollback_dir.join("floor.sqlite3");
    let authority =
        SqliteRollbackFloorAuthorityV1::create(&rollback_path, Duration::from_secs(1)).unwrap();
    let store = ProviderStore::create(
        &store_path,
        [0x55; 16],
        provider_id,
        StoreOptions {
            busy_timeout: Duration::from_secs(1),
        },
        Arc::new(authority),
    )
    .unwrap();
    drop(store);
    chmod(&store_path, 0o600);
    chmod(&rollback_path, 0o600);

    ProviderFixture {
        provider_id,
        policy_signing_key,
        receipt_signing_key,
        issuer_id: binding.issuer_id,
        policy_path,
        store_path,
        rollback_path,
        tee_scope_id,
        dpf_scope_id,
        other_provider_tee_scope_id,
        policy_digest,
        issued_at,
        receipt_not_after,
    }
}

fn service_scope(
    provider_id: [u8; 32],
    backend: BackendId,
    workload: WorkloadId,
    protocol_version: u16,
    manifest_root: [u8; 32],
) -> ServiceScopeV1 {
    ServiceScopeV1 {
        provider_id,
        backend,
        workload,
        protocol_version,
        dataset: DatasetBindingV1::ManifestRoot {
            root: manifest_root,
        },
        operation_profile: OPERATION_PROFILE,
        entitlement_profile: ENTITLEMENT_PROFILE,
    }
}

fn build_direct_oram_fixture(root: &Path) -> DirectOramFixture {
    let source_dir = root.join("direct-oram-source");
    let image_dir = root.join("direct-oram-images");
    let trusted_state_dir = root.join("direct-oram-trusted-state");
    fs::create_dir_all(&source_dir).unwrap();
    fs::create_dir_all(&image_dir).unwrap();
    fs::create_dir_all(&trusted_state_dir).unwrap();
    chmod(&source_dir, 0o700);
    chmod(&image_dir, 0o700);
    chmod(&trusted_state_dir, 0o700);

    let found_script_hash = [0x51; SCRIPT_HASH_SIZE];
    let whale_script_hash = [0x52; SCRIPT_HASH_SIZE];
    let mut index = Vec::new();
    index.extend_from_slice(&found_script_hash);
    index.extend_from_slice(&3u32.to_le_bytes());
    index.push(2);
    index.extend_from_slice(&whale_script_hash);
    index.extend_from_slice(&1u32.to_le_bytes());
    index.push(0);
    assert_eq!(index.len(), 2 * DIRECT_INDEX_INPUT_RECORD_SIZE);
    fs::write(source_dir.join("utxo_chunks_index_nodust.bin"), index).unwrap();

    let chunks = vec![
        vec![0; DIRECT_CHUNK_RECORD_SIZE],
        vec![0; DIRECT_CHUNK_RECORD_SIZE],
        vec![0; DIRECT_CHUNK_RECORD_SIZE],
        direct_chunk_record(0xA1, 1, 42),
        direct_chunk_record(0xB2, 2, 77),
        vec![0; DIRECT_CHUNK_RECORD_SIZE],
    ];
    let mut chunk_bytes = Vec::new();
    for chunk in &chunks {
        chunk_bytes.extend_from_slice(chunk);
    }
    fs::write(source_dir.join("utxo_chunks_nodust.bin"), chunk_bytes).unwrap();

    build_direct_oram_level(
        &source_dir,
        &image_dir,
        &trusted_state_dir,
        DirectLevel::Index,
    );
    build_direct_oram_level(
        &source_dir,
        &image_dir,
        &trusted_state_dir,
        DirectLevel::Chunk,
    );

    let mut expected_chunk_data = chunks[3].clone();
    expected_chunk_data.extend_from_slice(&chunks[4]);
    DirectOramFixture {
        image_dir,
        trusted_state_dir,
        found_script_hash,
        expected_chunk_data,
    }
}

fn direct_chunk_record(txid_byte: u8, vout: u32, amount: u64) -> Vec<u8> {
    let mut raw = pir_core::codec::serialize_utxo_data(&[pir_core::codec::UtxoEntry {
        txid: [txid_byte; 32],
        vout,
        amount,
    }]);
    assert!(raw.len() <= DIRECT_CHUNK_RECORD_SIZE);
    raw.resize(DIRECT_CHUNK_RECORD_SIZE, 0);
    raw
}

fn build_direct_oram_level(
    source_dir: &Path,
    image_dir: &Path,
    trusted_state_dir: &Path,
    level: DirectLevel,
) {
    match level {
        DirectLevel::Index => {
            let info = DirectTableInfo::from_index_file(
                source_dir.join("utxo_chunks_index_nodust.bin"),
                4,
                2,
                0.20,
                0x6469_7265_6374_0001,
            )
            .unwrap();
            let source = DirectIndexPackedBlockReader::build(info, DIRECT_ORAM_PACK).unwrap();
            let metadata = source.metadata().clone();
            build_direct_oram_from_source(image_dir, trusted_state_dir, level, metadata, source);
        }
        DirectLevel::Chunk => {
            let info = DirectTableInfo::from_chunks_file(source_dir.join("utxo_chunks_nodust.bin"))
                .unwrap();
            let source = DirectChunkPackedBlockReader::open(info, DIRECT_ORAM_PACK).unwrap();
            let metadata = source.metadata().clone();
            build_direct_oram_from_source(image_dir, trusted_state_dir, level, metadata, source);
        }
    }
}

fn build_direct_oram_from_source<S: TrustedBlockSource>(
    image_dir: &Path,
    trusted_state_dir: &Path,
    level: DirectLevel,
    metadata: DirectTableMetadata,
    source: S,
) {
    let params = OramParams::with_leaves(
        source.logical_blocks(),
        source.block_size(),
        source.logical_blocks().max(2).next_power_of_two(),
    )
    .unwrap()
    .with_bucket_size(2)
    .unwrap()
    .with_stash_capacity(128)
    .unwrap();
    let paths = direct_oram_paths(image_dir, trusted_state_dir, level);
    let meta_store = FilePageStore::open(
        &paths.meta_image,
        params.bucket_count(),
        circuit_meta_page_bytes(params.bucket_size),
    )
    .unwrap();
    let payload_store = FilePageStore::open(
        &paths.payload_image,
        params.bucket_count(),
        circuit_payload_page_bytes(params.bucket_size, params.block_size),
    )
    .unwrap();
    let mut oram = CircuitOram::build_trusted_from_source(
        params.clone(),
        meta_store,
        payload_store,
        source,
        [0x5A; 32],
    )
    .unwrap();
    oram.flush().unwrap();
    oram.snapshot().save_atomic(&paths.state).unwrap();
    drop(oram);
    metadata.save(&paths.metadata).unwrap();
    build_direct_oram_auth_store(&paths, level, &params);
}

fn build_direct_oram_auth_store(paths: &DirectOramPaths, level: DirectLevel, params: &OramParams) {
    let trusted_levels = 1usize;
    let hash_page_size = 4096usize;
    let meta_store = FilePageStore::open(
        &paths.meta_image,
        params.bucket_count(),
        circuit_meta_page_bytes(params.bucket_size),
    )
    .unwrap();
    let payload_store = FilePageStore::open(
        &paths.payload_image,
        params.bucket_count(),
        circuit_payload_page_bytes(params.bucket_size, params.block_size),
    )
    .unwrap();
    let hash_pages = TieredMerklePageStore::<FilePageStore, FilePageStore>::required_hash_pages(
        params.bucket_count(),
        hash_page_size,
        trusted_levels,
    )
    .unwrap();
    let meta_hash_store =
        FilePageStore::open(&paths.meta_hash_image, hash_pages, hash_page_size).unwrap();
    let payload_hash_store =
        FilePageStore::open(&paths.payload_hash_image, hash_pages, hash_page_size).unwrap();
    let (meta_store_id, payload_store_id) = direct_auth_store_ids(level);
    let mut meta =
        TieredMerklePageStore::build(meta_store, meta_hash_store, meta_store_id, trusted_levels)
            .unwrap();
    let mut payload = TieredMerklePageStore::build(
        payload_store,
        payload_hash_store,
        payload_store_id,
        trusted_levels,
    )
    .unwrap();
    PageStore::flush(&mut meta).unwrap();
    PageStore::flush(&mut payload).unwrap();
    CircuitStoreAuthState::new(meta.trusted_state(), payload.trusted_state())
        .save_atomic(&paths.auth_state)
        .unwrap();
}

struct DirectOramPaths {
    meta_image: PathBuf,
    payload_image: PathBuf,
    meta_hash_image: PathBuf,
    payload_hash_image: PathBuf,
    state: PathBuf,
    auth_state: PathBuf,
    metadata: PathBuf,
}

fn direct_oram_paths(
    image_dir: &Path,
    trusted_state_dir: &Path,
    level: DirectLevel,
) -> DirectOramPaths {
    let label = format!("direct-{}", level.label());
    DirectOramPaths {
        meta_image: image_dir.join(format!("{label}.meta.oram")),
        payload_image: image_dir.join(format!("{label}.payload.oram")),
        meta_hash_image: image_dir.join(format!("{label}.meta.hash.oram")),
        payload_hash_image: image_dir.join(format!("{label}.payload.hash.oram")),
        state: trusted_state_dir.join(format!("{label}.state")),
        auth_state: trusted_state_dir.join(format!("{label}.auth.state")),
        metadata: trusted_state_dir.join(format!("{label}.metadata")),
    }
}

fn direct_auth_store_ids(level: DirectLevel) -> ([u8; 16], [u8; 16]) {
    match level {
        DirectLevel::Index => (*b"bpir-diridx-meta", *b"bpir-diridx-data"),
        DirectLevel::Chunk => (*b"bpir-dirchk-meta", *b"bpir-dirchk-data"),
    }
}

fn write_tiny_manifest_database(root: &Path) -> (PathBuf, [u8; 32]) {
    let db = root.join("tiny-db");
    fs::create_dir(&db).unwrap();
    write_tiny_table(
        &db.join("batch_pir_cuckoo.bin"),
        &INDEX_PARAMS.with_master_seed(0x1111_2222_3333_4444),
        0x9999_aaaa_bbbb_cccc,
    );
    write_tiny_table(
        &db.join("chunk_pir_cuckoo.bin"),
        &CHUNK_PARAMS.with_master_seed(0x5555_6666_7777_8888),
        0,
    );
    let zero_hash = "0".repeat(64);
    let manifest = format!(
        "[manifest]\nversion = 1\ngenerated_at = \"2026-07-29T00:00:00Z\"\n\n[files]\n\"batch_pir_cuckoo.bin\" = \"{zero_hash}\"\n\"chunk_pir_cuckoo.bin\" = \"{zero_hash}\"\n"
    );
    fs::write(db.join("MANIFEST.toml"), manifest.as_bytes()).unwrap();
    (db, sha256(manifest.as_bytes()))
}

fn write_tiny_table(path: &Path, params: &pir_core::params::TableParams, tag_seed: u64) {
    let mut bytes = write_header_with_anchor(params, TINY_BINS_PER_TABLE, tag_seed, None);
    bytes.resize(
        bytes.len() + params.k * params.table_byte_size(TINY_BINS_PER_TABLE),
        0,
    );
    fs::write(path, bytes).unwrap();
}

fn expect_error_response(response: &[u8], needle: &str) {
    match Response::decode(response).unwrap() {
        Response::Error(message) => assert!(
            message.contains(needle),
            "expected error containing {needle:?}, got {message:?}"
        ),
        other => panic!("expected server error containing {needle:?}, got {other:?}"),
    }
}

fn unused_loopback_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn read_log(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| format!("<read log failed: {error}>"))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs()
}
