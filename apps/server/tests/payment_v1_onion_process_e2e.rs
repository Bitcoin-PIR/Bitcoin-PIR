//! Real-process Payment V1 admission in front of the production OnionPIR handler.
//!
//! This no-funds test builds a one-row OnionPIR database exclusively through
//! the public `onionpir` API, launches two independent `unified_server`
//! processes, and decrypts the ciphertext responses emitted by the production
//! INDEX, CHUNK, and per-group Merkle-sibling workers.  It deliberately keeps
//! INDEX and CHUNK inside one `OnionEvaluateJobV1` authorization: they are DFA
//! phases of one paid job, not independently purchasable workloads.
//!
//! Ordinary CI hosts report `NoSevHost`, so this uses the SDK's explicitly
//! dangerous unpaired helpers after the real attestation-bound channel
//! handshake.  It proves the local encrypted wire, signed policy, provider
//! capability, durable spend, admission DFA, and C++ OnionPIR dispatch
//! boundaries.  It is not production hardware-attestation evidence and never
//! contacts an issuer, Lightning node, mint, relay, or external service.

#![cfg(unix)]

#[path = "support/payment_v1_method_matrix.rs"]
mod payment_v1_method_matrix;

use ed25519_dalek::SigningKey;
use onionpir::{Client as OnionPirClient, Server as OnionPirServer};
#[cfg(feature = "standard-cashu-process-e2e")]
use payment_v1_method_matrix::MatrixMethod;
use payment_v1_method_matrix::{MethodMatrixFixture, TestCashuMint};
use pir_core::cuckoo::write_header_with_anchor;
use pir_core::merkle::sha256;
use pir_core::params::{CHUNK_PARAMS, INDEX_PARAMS};
use pir_runtime_core::protocol::Response;
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
    AuthScheme, BackendId, CredentialKeyBindingClaimsV1, CredentialKeyBindingV1, CredentialUnitV1,
    DatasetBindingV1, DeploymentStatus, EntitlementLimitsV1, FreeModeV1, OperationStartV1,
    PaidReceiptBindingV1, PaidReceiptV1, PriceV1, PrivacyLeakageV1, ServiceOfferV1,
    ServicePolicyV1, ServiceScopePolicyV1, ServiceScopeV1, VerificationMode, WorkloadId,
    REQ_AUTH_BEGIN_V1,
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

const OFFER_ID: u32 = 2;
const OPERATION_PROFILE: u16 = 14;
const ENTITLEMENT_PROFILE: u16 = 104;
const TINY_DPF_BINS_PER_TABLE: usize = 128;
const TINY_ONION_BINS_PER_TABLE: u32 = 1;

const REQ_REGISTER_KEYS: u8 = 0x50;
const REQ_ONIONPIR_INDEX_QUERY: u8 = 0x51;
const REQ_ONIONPIR_CHUNK_QUERY: u8 = 0x52;
const REQ_ONIONPIR_MERKLE_INDEX_SIBLING: u8 = 0x53;
const REQ_ONIONPIR_MERKLE_DATA_SIBLING: u8 = 0x55;

const RESP_KEYS_ACK: u8 = 0x50;
const RESP_ONIONPIR_INDEX_RESULT: u8 = 0x51;
const RESP_ONIONPIR_CHUNK_RESULT: u8 = 0x52;
const RESP_ONIONPIR_MERKLE_INDEX_SIBLING: u8 = 0x53;
const RESP_ONIONPIR_MERKLE_DATA_SIBLING: u8 = 0x55;

const ONION_CHUNK_MAGIC: u64 = 0xBA7C_0010_0000_0001;
const ONION_INDEX_META_MAGIC: u64 = 0xBA7C_0010_0000_0002;
const ONION_INDEX_ALL_MAGIC: u64 = 0xBA7C_0010_0000_0003;
const ONION_INDEX_SIBLING_MAGIC: u64 = 0xBA7C_0E51_0000_0000;
const ONION_DATA_SIBLING_MAGIC: u64 = 0xBA7C_0E51_0000_0001;

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
struct ProviderFixture {
    index: u8,
    provider_id: [u8; 32],
    policy_signing_key: SigningKey,
    receipt_signing_key: SigningKey,
    issuer_id: [u8; 32],
    receipt_key_id: Vec<u8>,
    policy_path: PathBuf,
    store_path: PathBuf,
    rollback_path: PathBuf,
    scope_id: [u8; 32],
    policy_digest: [u8; 32],
    issued_at: u64,
    receipt_not_after: u64,
    method_matrix: Option<MethodMatrixFixture>,
}

impl ProviderFixture {
    fn receipt(&self, serial_byte: u8) -> PaidReceiptV1 {
        PaidReceiptV1::sign(
            self.issuer_id,
            [serial_byte; 32],
            PaidReceiptBindingV1 {
                scope_id: self.scope_id,
                offer_id: OFFER_ID,
                policy_digest: self.policy_digest,
                entitlement_profile: ENTITLEMENT_PROFILE,
            },
            self.issued_at,
            self.receipt_not_after,
            &self.receipt_signing_key,
        )
        .expect("deterministic Onion receipt fixture must be valid")
    }
}

struct OnionWireFixture {
    client: OnionPirClient,
    expected_plaintext: Vec<u8>,
    register: Vec<u8>,
    query: Vec<u8>,
}

impl OnionWireFixture {
    fn index(&self, round_id: u16) -> Vec<u8> {
        encode_onion_batch(
            REQ_ONIONPIR_INDEX_QUERY,
            round_id,
            &[self.query.clone(), self.query.clone()],
        )
    }

    fn chunk(&self, round_id: u16) -> Vec<u8> {
        encode_onion_batch(
            REQ_ONIONPIR_CHUNK_QUERY,
            round_id,
            std::slice::from_ref(&self.query),
        )
    }

    fn merkle_index(&self) -> Vec<u8> {
        encode_onion_batch(
            REQ_ONIONPIR_MERKLE_INDEX_SIBLING,
            0,
            std::slice::from_ref(&self.query),
        )
    }

    fn merkle_data(&self) -> Vec<u8> {
        encode_onion_batch(
            REQ_ONIONPIR_MERKLE_DATA_SIBLING,
            0,
            std::slice::from_ref(&self.query),
        )
    }
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
        fixture: &ProviderFixture,
        port: u16,
        generation: u8,
    ) -> Self {
        let stdout_path = root.join(format!(
            "onion-provider-{}-generation-{generation}-stdout.log",
            fixture.index
        ));
        let stderr_path = root.join(format!(
            "onion-provider-{}-generation-{generation}-stderr.log",
            fixture.index
        ));
        let stdout = File::create(&stdout_path).expect("create Onion server stdout log");
        let stderr = File::create(&stderr_path).expect("create Onion server stderr log");
        let mut args = vec![
            "--bind-address".to_owned(),
            "127.0.0.1".to_owned(),
            "--port".to_owned(),
            port.to_string(),
            "--data-dir".to_owned(),
            db_path.display().to_string(),
            "--role".to_owned(),
            "primary".to_owned(),
            "--serve-queries".to_owned(),
            "--require-service-auth-v1".to_owned(),
            "--service-policy".to_owned(),
            fixture.policy_path.display().to_string(),
            "--service-provider-id-hex".to_owned(),
            hex::encode(fixture.provider_id),
            "--service-policy-key-hex".to_owned(),
            hex::encode(fixture.policy_signing_key.verifying_key().to_bytes()),
            "--service-store".to_owned(),
            fixture.store_path.display().to_string(),
            "--service-rollback-authority".to_owned(),
            fixture.rollback_path.display().to_string(),
            "--allow-local-service-rollback-authority-dev".to_owned(),
            "--max-connections".to_owned(),
            "32".to_owned(),
            "--service-max-concurrent-auth".to_owned(),
            "4".to_owned(),
            "--websocket-handshake-timeout-ms".to_owned(),
            "1000".to_owned(),
            "--connection-idle-timeout-ms".to_owned(),
            "300000".to_owned(),
            "--service-pre-auth-timeout-ms".to_owned(),
            "120000".to_owned(),
        ];
        if let Some(matrix) = &fixture.method_matrix {
            matrix.extend_server_args(&mut args);
        }
        let child = Command::new(env!("CARGO_BIN_EXE_unified_server"))
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("spawn Onion unified_server");
        let mut server = Self {
            child,
            stdout_path,
            stderr_path,
        };
        server.wait_until_listening(port);
        server
    }

    fn wait_until_listening(&mut self, port: u16) {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = self.child.try_wait().expect("poll Onion unified_server") {
                panic!(
                    "Onion unified_server exited before listening ({status})\nstdout:\n{}\nstderr:\n{}",
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
                "timed out waiting for Onion unified_server\nstdout:\n{}\nstderr:\n{}",
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
                "Onion unified_server logs after test failure\nstdout:\n{}\nstderr:\n{}",
                read_log(&self.stdout_path),
                read_log(&self.stderr_path),
            );
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn paid_onion_scope_reaches_real_handler_and_enforces_durable_session_dfa() {
    let root = tempfile::tempdir().expect("Onion process test root");
    chmod(root.path(), 0o700);
    let db_path = write_tiny_manifest_database(root.path());
    let onion = write_real_onion_artifacts(&db_path);
    let manifest_root = write_complete_manifest(&db_path);
    let now = unix_now();
    let provider0 = build_provider(root.path(), 0, manifest_root, now, None);
    let provider1 = build_provider(root.path(), 1, manifest_root, now, None);

    assert_ne!(provider0.provider_id, provider1.provider_id);
    assert_ne!(provider0.scope_id, provider1.scope_id);
    assert_ne!(provider0.issuer_id, provider1.issuer_id);
    assert_ne!(provider0.store_path, provider1.store_path);

    let port0 = unused_loopback_port();
    let mut port1 = unused_loopback_port();
    while port1 == port0 {
        port1 = unused_loopback_port();
    }
    let server0 = ServerProcess::spawn(root.path(), &db_path, &provider0, port0, 0);
    let server1 = ServerProcess::spawn(root.path(), &db_path, &provider1, port1, 0);

    // Structurally valid empty-key registration probes are rejected at the
    // cleartext and encrypted-but-unauthorized boundaries before the C++ key
    // store.  The later authorized registration uses the real large payload,
    // exercising transport chunking (current Onion keys exceed 256 KiB).
    let unauthorized_register_probe = encode_register_keys(&[], &[]);
    let provider1_receipt = provider1.receipt(0x71);
    let (mut wrong_provider, accepted0) = open_verified_session(
        port0,
        &provider0,
        manifest_root,
        Some(&unauthorized_register_probe),
    )
    .await;
    let wrong_provider_proof = dangerous_unpaired_build_authorization_proof_v1(
        &accepted0,
        &provider0.scope_id,
        OFFER_ID,
        &provider1_receipt.encode().unwrap(),
    )
    .unwrap();
    let rejected = dangerous_unpaired_authorize_service_operation_v1(
        &mut wrong_provider,
        &accepted0,
        provider0.scope_id,
        OFFER_ID,
        OperationStartV1::OnionSession { db_id: 0 },
        wrong_provider_proof,
    )
    .await
    .unwrap_err();
    assert!(
        rejected.to_string().contains("invalid-or-spent"),
        "{rejected}"
    );
    wrong_provider.close().await.unwrap();

    // Provider 0 did not burn provider 1's credential.  Its intended provider
    // accepts it, performs one genuine INDEX query, and rejects INDEX round 1
    // as a second logical paid job before it reaches the handler.
    exercise_second_job_limit(port1, &provider1, manifest_root, &provider1_receipt, &onion).await;

    // A structurally wrong same-provider backend/workload selection is bound
    // before the durable receipt commit.  The exact receipt remains usable on
    // a fresh connection for the correct complete OnionEvaluateJob scope.
    let main_receipt = provider0.receipt(0x80);
    exercise_wrong_operation_non_consuming(port0, &provider0, manifest_root, &main_receipt).await;
    exercise_complete_real_onion_job(port0, &provider0, manifest_root, &main_receipt, &onion).await;

    // Once AUTH_GRANTED is committed, a bad phase is an after-spend protocol
    // failure, not a refundable/non-consuming authorization error.  Each case
    // is isolated under a distinct capability and must terminalize its grant.
    exercise_extra_registration_fails_closed(
        port0,
        &provider0,
        manifest_root,
        &provider0.receipt(0x81),
        &onion,
    )
    .await;
    exercise_chunk_before_index_fails_closed(
        port0,
        &provider0,
        manifest_root,
        &provider0.receipt(0x82),
        &onion,
    )
    .await;
    exercise_wrong_round_fails_closed(
        port0,
        &provider0,
        manifest_root,
        &provider0.receipt(0x83),
        &onion,
    )
    .await;

    let (stdout0_first, stderr0_first) = server0.stop();
    assert_real_onion_listener(0, port0, &stdout0_first, &stderr0_first);
    let server0 = ServerProcess::spawn(root.path(), &db_path, &provider0, port0, 1);

    // The complete job's direct receipt remains spent after both the process
    // and C++ worker state are recreated from disk.
    let (mut replay, replay_policy) =
        open_verified_session(port0, &provider0, manifest_root, None).await;
    let replay_proof = dangerous_unpaired_build_authorization_proof_v1(
        &replay_policy,
        &provider0.scope_id,
        OFFER_ID,
        &main_receipt.encode().unwrap(),
    )
    .unwrap();
    let replay_error = dangerous_unpaired_authorize_service_operation_v1(
        &mut replay,
        &replay_policy,
        provider0.scope_id,
        OFFER_ID,
        OperationStartV1::OnionSession { db_id: 0 },
        replay_proof,
    )
    .await
    .unwrap_err();
    assert!(
        replay_error.to_string().contains("invalid-or-spent"),
        "{replay_error}"
    );
    replay.close().await.unwrap();

    let (stdout0, stderr0) = server0.stop();
    let (stdout1, stderr1) = server1.stop();
    assert_real_onion_listener(0, port0, &stdout0, &stderr0);
    assert_real_onion_listener(1, port1, &stdout1, &stderr1);
}

#[cfg(feature = "standard-cashu-process-e2e")]
#[tokio::test(flavor = "current_thread")]
async fn all_non_receipt_methods_commit_before_real_onion_job_and_replay_after_restart() {
    let root = tempfile::tempdir().expect("Onion matrix test root");
    chmod(root.path(), 0o700);
    let mint = TestCashuMint::spawn(root.path());
    let db_path = write_tiny_manifest_database(root.path());
    let onion = write_real_onion_artifacts(&db_path);
    let manifest_root = write_complete_manifest(&db_path);
    let provider = build_provider(root.path(), 0, manifest_root, unix_now(), Some(&mint));
    let port = unused_loopback_port();
    let server = ServerProcess::spawn(root.path(), &db_path, &provider, port, 0);
    let matrix = provider.method_matrix.as_ref().unwrap();

    for method in MatrixMethod::ALL {
        let fixture = matrix.method(method);
        let (mut secure, accepted) =
            open_verified_session(port, &provider, manifest_root, None).await;
        let scope = accepted
            .policy()
            .scopes
            .iter()
            .find(|entry| entry.scope.scope_id() == provider.scope_id)
            .unwrap();
        assert_eq!(scope.scope.backend, BackendId::OnionPirV1);
        assert_eq!(scope.scope.workload, WorkloadId::OnionEvaluateJobV1);
        let proof = dangerous_unpaired_build_authorization_proof_v1(
            &accepted,
            &provider.scope_id,
            fixture.offer_id(),
            fixture.proof(0),
        )
        .unwrap();
        let attempts_before_wrong_scope = mint.attempt_count();
        let wrong = raw_authorization_request(
            &accepted,
            provider.scope_id,
            fixture.offer_id(),
            OperationStartV1::DpfQuery { db_id: 0 },
            proof.clone(),
        );
        let response = secure.roundtrip(&wrong).await.unwrap();
        let error = dangerous_unpaired_accept_service_authorization_response_v1(
            &response,
            &accepted,
            provider.scope_id,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("wrong-scope"),
            "{method:?}: {error}"
        );
        assert_eq!(mint.attempt_count(), attempts_before_wrong_scope);
        let grant = dangerous_unpaired_authorize_service_operation_v1(
            &mut secure,
            &accepted,
            provider.scope_id,
            fixture.offer_id(),
            OperationStartV1::OnionSession { db_id: 0 },
            proof,
        )
        .await
        .unwrap_or_else(|error| panic!("{method:?} failed exact Onion auth: {error}"));
        assert_eq!(grant.scope_id, provider.scope_id);
        assert_eq!(grant.enforced_profile, ENTITLEMENT_PROFILE);
        exercise_complete_onion_frames(&mut secure, &onion).await;
        secure.close().await.unwrap();
    }
    assert_eq!(
        mint.attempt_count(),
        1,
        "only Standard Cashu reaches the mint"
    );

    let (stdout_first, stderr_first) = server.stop();
    assert_real_onion_listener(0, port, &stdout_first, &stderr_first);
    let server = ServerProcess::spawn(root.path(), &db_path, &provider, port, 1);
    for method in MatrixMethod::ALL {
        let fixture = matrix.method(method);
        let (mut secure, accepted) =
            open_verified_session(port, &provider, manifest_root, None).await;
        let proof = dangerous_unpaired_build_authorization_proof_v1(
            &accepted,
            &provider.scope_id,
            fixture.offer_id(),
            fixture.proof(0),
        )
        .unwrap();
        let error = dangerous_unpaired_authorize_service_operation_v1(
            &mut secure,
            &accepted,
            provider.scope_id,
            fixture.offer_id(),
            OperationStartV1::OnionSession { db_id: 0 },
            proof,
        )
        .await
        .expect_err("matrix capability replay must stay terminal after restart");
        assert!(
            error.to_string().contains(method.replay_rejection()),
            "{method:?}: {error}"
        );
        secure.close().await.unwrap();
    }
    assert_eq!(mint.attempt_count(), 1, "Cashu replay reached the mint");
    let (stdout, stderr) = server.stop();
    assert_real_onion_listener(0, port, &stdout, &stderr);
}

async fn exercise_second_job_limit(
    port: u16,
    fixture: &ProviderFixture,
    manifest_root: [u8; 32],
    receipt: &PaidReceiptV1,
    onion: &OnionWireFixture,
) {
    let (mut secure, accepted) = open_verified_session(port, fixture, manifest_root, None).await;
    authorize_onion(&mut secure, &accepted, fixture, receipt).await;
    register_keys(&mut secure, &onion.register).await;
    let first = secure.roundtrip(&onion.index(0)).await.unwrap();
    assert_real_onion_result(&first, RESP_ONIONPIR_INDEX_RESULT, 0, 2, onion);
    expect_error_response(
        &secure.roundtrip(&onion.index(1)).await.unwrap(),
        "service entitlement limit exceeded",
    );
    expect_error_response(
        &secure.roundtrip(&onion.chunk(0)).await.unwrap(),
        "connection is terminal after capability consumption",
    );
    secure.close().await.unwrap();
}

async fn exercise_wrong_operation_non_consuming(
    port: u16,
    fixture: &ProviderFixture,
    manifest_root: [u8; 32],
    receipt: &PaidReceiptV1,
) {
    let (mut secure, accepted) = open_verified_session(port, fixture, manifest_root, None).await;
    let wrong = AuthBeginV1 {
        policy_digest: fixture.policy_digest,
        scope_id: fixture.scope_id,
        offer_id: OFFER_ID,
        scheme: AuthScheme::Bolt11DirectReceiptV1,
        key_id: fixture.receipt_key_id.clone(),
        operation: OperationStartV1::DpfQuery { db_id: 0 },
        proof: receipt.encode().unwrap(),
    };
    let response = secure
        .roundtrip(&encode_service_request(
            REQ_AUTH_BEGIN_V1,
            &wrong.encode_padded().unwrap(),
        ))
        .await
        .unwrap();
    let rejected = dangerous_unpaired_accept_service_authorization_response_v1(
        &response,
        &accepted,
        fixture.scope_id,
    )
    .unwrap_err();
    assert!(rejected.to_string().contains("wrong-scope"), "{rejected}");
    secure.close().await.unwrap();
}

async fn exercise_complete_real_onion_job(
    port: u16,
    fixture: &ProviderFixture,
    manifest_root: [u8; 32],
    receipt: &PaidReceiptV1,
    onion: &OnionWireFixture,
) {
    let (mut secure, accepted) = open_verified_session(port, fixture, manifest_root, None).await;
    authorize_onion(&mut secure, &accepted, fixture, receipt).await;
    exercise_complete_onion_frames(&mut secure, onion).await;
    secure.close().await.unwrap();
}

async fn exercise_complete_onion_frames(
    secure: &mut SecureChannelTransport<WsConnection>,
    onion: &OnionWireFixture,
) {
    register_keys(secure, &onion.register).await;

    let index = secure.roundtrip(&onion.index(0)).await.unwrap();
    assert_real_onion_result(&index, RESP_ONIONPIR_INDEX_RESULT, 0, 2, onion);
    let chunk = secure.roundtrip(&onion.chunk(0)).await.unwrap();
    assert_real_onion_result(&chunk, RESP_ONIONPIR_CHUNK_RESULT, 0, 1, onion);
    let index_sibling = secure.roundtrip(&onion.merkle_index()).await.unwrap();
    assert_real_onion_result(
        &index_sibling,
        RESP_ONIONPIR_MERKLE_INDEX_SIBLING,
        0,
        1,
        onion,
    );
    let data_sibling = secure.roundtrip(&onion.merkle_data()).await.unwrap();
    assert_real_onion_result(
        &data_sibling,
        RESP_ONIONPIR_MERKLE_DATA_SIBLING,
        0,
        1,
        onion,
    );
}

async fn exercise_extra_registration_fails_closed(
    port: u16,
    fixture: &ProviderFixture,
    manifest_root: [u8; 32],
    receipt: &PaidReceiptV1,
    onion: &OnionWireFixture,
) {
    let (mut secure, accepted) = open_verified_session(port, fixture, manifest_root, None).await;
    authorize_onion(&mut secure, &accepted, fixture, receipt).await;
    register_keys(&mut secure, &onion.register).await;
    expect_error_response(
        &secure.roundtrip(&onion.register).await.unwrap(),
        "backend frame violates the operation sequence",
    );
    expect_error_response(
        &secure.roundtrip(&onion.index(0)).await.unwrap(),
        "connection is terminal after capability consumption",
    );
    secure.close().await.unwrap();
}

async fn exercise_chunk_before_index_fails_closed(
    port: u16,
    fixture: &ProviderFixture,
    manifest_root: [u8; 32],
    receipt: &PaidReceiptV1,
    onion: &OnionWireFixture,
) {
    let (mut secure, accepted) = open_verified_session(port, fixture, manifest_root, None).await;
    authorize_onion(&mut secure, &accepted, fixture, receipt).await;
    register_keys(&mut secure, &onion.register).await;
    expect_error_response(
        &secure.roundtrip(&onion.chunk(0)).await.unwrap(),
        "backend frame violates the operation sequence",
    );
    expect_error_response(
        &secure.roundtrip(&onion.index(0)).await.unwrap(),
        "connection is terminal after capability consumption",
    );
    secure.close().await.unwrap();
}

async fn exercise_wrong_round_fails_closed(
    port: u16,
    fixture: &ProviderFixture,
    manifest_root: [u8; 32],
    receipt: &PaidReceiptV1,
    onion: &OnionWireFixture,
) {
    let (mut secure, accepted) = open_verified_session(port, fixture, manifest_root, None).await;
    authorize_onion(&mut secure, &accepted, fixture, receipt).await;
    register_keys(&mut secure, &onion.register).await;
    expect_error_response(
        &secure.roundtrip(&onion.index(1)).await.unwrap(),
        "backend frame violates the operation sequence",
    );
    expect_error_response(
        &secure.roundtrip(&onion.index(0)).await.unwrap(),
        "connection is terminal after capability consumption",
    );
    secure.close().await.unwrap();
}

async fn authorize_onion(
    secure: &mut SecureChannelTransport<WsConnection>,
    accepted: &AcceptedServicePolicyV1,
    fixture: &ProviderFixture,
    receipt: &PaidReceiptV1,
) {
    let proof = dangerous_unpaired_build_authorization_proof_v1(
        accepted,
        &fixture.scope_id,
        OFFER_ID,
        &receipt.encode().unwrap(),
    )
    .unwrap();
    let grant = dangerous_unpaired_authorize_service_operation_v1(
        secure,
        accepted,
        fixture.scope_id,
        OFFER_ID,
        OperationStartV1::OnionSession { db_id: 0 },
        proof,
    )
    .await
    .expect("provider-specific Onion receipt must authorize");
    assert_eq!(grant.scope_id, fixture.scope_id);
    assert_eq!(grant.enforced_profile, ENTITLEMENT_PROFILE);
}

async fn register_keys(secure: &mut SecureChannelTransport<WsConnection>, request: &[u8]) {
    let response = secure.roundtrip(request).await.unwrap();
    assert_eq!(response, [RESP_KEYS_ACK]);
}

async fn open_verified_session(
    port: u16,
    fixture: &ProviderFixture,
    manifest_root: [u8; 32],
    boundary_probe: Option<&[u8]>,
) -> (
    SecureChannelTransport<WsConnection>,
    AcceptedServicePolicyV1,
) {
    let url = format!("ws://127.0.0.1:{port}");
    let mut raw = WsConnection::connect_once(&url)
        .await
        .expect("connect loopback Onion WebSocket");

    if let Some(probe) = boundary_probe {
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
            &raw.roundtrip(probe).await.unwrap(),
            "secure encrypted channel is required",
        );
    }

    let session_id = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut eph_seed = [0x20u8.wrapping_add(fixture.index); 32];
    let mut random = [0x40u8.wrapping_add(fixture.index); 32];
    let mut handshake_nonce = [0x60u8.wrapping_add(fixture.index); 32];
    eph_seed[..8].copy_from_slice(&session_id.to_le_bytes());
    random[..8].copy_from_slice(&session_id.wrapping_add(0x1000).to_le_bytes());
    handshake_nonce[..8].copy_from_slice(&session_id.wrapping_add(0x2000).to_le_bytes());
    let attestation = attest_with_eph_binding(&mut raw, eph_seed, random)
        .await
        .expect("attestation-bound Onion channel key");
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
    .expect("verify exact signed Onion provider policy");
    assert_eq!(accepted.policy_digest(), fixture.policy_digest);
    assert_eq!(accepted.checkpoint().rollback_guard().highest_epoch, 1);

    if let Some(probe) = boundary_probe {
        expect_error_response(
            &secure.roundtrip(probe).await.unwrap(),
            "authorization required",
        );
    }
    (secure, accepted)
}

fn build_provider(
    root: &Path,
    index: u8,
    manifest_root: [u8; 32],
    now: u64,
    matrix_mint: Option<&TestCashuMint>,
) -> ProviderFixture {
    let provider_root = root.join(format!("onion-provider-{index}"));
    let store_dir = provider_root.join("store-domain");
    let rollback_dir = provider_root.join("rollback-domain");
    fs::create_dir_all(&store_dir).unwrap();
    fs::create_dir_all(&rollback_dir).unwrap();
    chmod(&provider_root, 0o700);
    chmod(&store_dir, 0o700);
    chmod(&rollback_dir, 0o700);

    let operator_key = SigningKey::from_bytes(&[0x11u8.wrapping_add(index); 32]);
    let policy_signing_key = SigningKey::from_bytes(&[0x21u8.wrapping_add(index); 32]);
    let issuer_root_key = SigningKey::from_bytes(&[0x31u8.wrapping_add(index); 32]);
    let receipt_signing_key = SigningKey::from_bytes(&[0x41u8.wrapping_add(index); 32]);
    let stable_server_id = format!("payment-v1-onion-process-provider-{index}");
    let provider_id =
        derive_provider_id(&operator_key.verifying_key().to_bytes(), &stable_server_id);
    let issued_at = now.saturating_sub(60);
    let expires_at = now.checked_add(3_600).unwrap();
    let receipt_not_after = now.checked_add(600).unwrap();
    let scope = ServiceScopeV1 {
        provider_id,
        backend: BackendId::OnionPirV1,
        workload: WorkloadId::OnionEvaluateJobV1,
        protocol_version: 1,
        dataset: DatasetBindingV1::ManifestRoot {
            root: manifest_root,
        },
        operation_profile: OPERATION_PROFILE,
        entitlement_profile: ENTITLEMENT_PROFILE,
    };
    let scope_id = scope.scope_id();
    let receipt_key_id = paid_receipt_key_id(&receipt_signing_key.verifying_key()).to_vec();
    let retired_policy_grace_seconds = 1_800;
    let binding = CredentialKeyBindingV1::sign(
        CredentialKeyBindingClaimsV1 {
            provider_id,
            scope_id,
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
        price: PriceV1::MilliSatoshi(1_000),
        issuer_id: binding.issuer_id,
        key_id: receipt_key_id.clone(),
        credential_binding: Some(binding.clone()),
        cashu_mint_manifest: None,
        endpoint: format!("https://onion-issuer-{index}.fixture.invalid"),
        invoice_expiry_seconds: 600,
        claim_window_seconds: 600,
        minimum_credential_validity_seconds: 600,
        retired_policy_grace_seconds,
        credential_count: 1,
        credential_presentation_limit: 1,
        privacy_leakage: PrivacyLeakageV1::from_bits(PrivacyLeakageV1::DIRECT_PAYMENT_TO_SPEND)
            .unwrap(),
    };
    let method_matrix = matrix_mint.map(|mint| {
        MethodMatrixFixture::build(
            &provider_root,
            provider_id,
            scope_id,
            ENTITLEMENT_PROFILE,
            issued_at,
            expires_at,
            1,
            0x51u8.wrapping_add(index),
            mint,
        )
    });
    let mut offers = vec![offer];
    if let Some(matrix) = &method_matrix {
        offers.extend(matrix.offers().iter().cloned());
    }
    let policy = ServicePolicyV1::sign(
        provider_id,
        1,
        issued_at,
        expires_at,
        AuthPaddingClassV1::Class16KiB,
        vec![ServiceScopePolicyV1 {
            scope,
            limits: EntitlementLimitsV1 {
                max_logical_inputs: 1,
                max_frames: 8,
                max_request_bytes: 64 * 1024 * 1024,
                max_response_bytes: 64 * 1024 * 1024,
                max_wall_time_ms: 300_000,
                max_concurrent_sockets: 1,
                max_hint_groups: 0,
                max_work_units: 16,
            },
            offers,
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
        [0x51u8.wrapping_add(index); 16],
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
        index,
        provider_id,
        policy_signing_key,
        receipt_signing_key,
        issuer_id: binding.issuer_id,
        receipt_key_id,
        policy_path,
        store_path,
        rollback_path,
        scope_id,
        policy_digest,
        issued_at,
        receipt_not_after,
        method_matrix,
    }
}

fn write_tiny_manifest_database(root: &Path) -> PathBuf {
    let db = root.join("tiny-onion-db");
    fs::create_dir(&db).unwrap();
    let index_path = db.join("batch_pir_cuckoo.bin");
    let chunk_path = db.join("chunk_pir_cuckoo.bin");
    write_tiny_dpf_table(
        &index_path,
        &INDEX_PARAMS.with_master_seed(0x1111_2222_3333_4444),
        0x9999_aaaa_bbbb_cccc,
    );
    write_tiny_dpf_table(
        &chunk_path,
        &CHUNK_PARAMS.with_master_seed(0x5555_6666_7777_8888),
        0,
    );
    db
}

fn write_complete_manifest(db: &Path) -> [u8; 32] {
    let mut files = fs::read_dir(db)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_file() && path.file_name().unwrap() != "MANIFEST.toml")
        .collect::<Vec<_>>();
    files.sort();

    let mut manifest = String::from(
        "[manifest]\nversion = 1\ngenerated_at = \"2026-07-29T00:00:00Z\"\n\n[files]\n",
    );
    for path in files {
        let name = path.file_name().unwrap().to_str().unwrap();
        manifest.push_str(&format!(
            "\"{name}\" = \"{}\"\n",
            hex::encode(sha256(&fs::read(&path).unwrap()))
        ));
    }
    fs::write(db.join("MANIFEST.toml"), manifest.as_bytes()).unwrap();
    sha256(manifest.as_bytes())
}

fn write_tiny_dpf_table(path: &Path, params: &pir_core::params::TableParams, tag_seed: u64) {
    let mut bytes = write_header_with_anchor(params, TINY_DPF_BINS_PER_TABLE, tag_seed, None);
    bytes.resize(
        bytes.len() + params.k * params.table_byte_size(TINY_DPF_BINS_PER_TABLE),
        0,
    );
    fs::write(path, bytes).unwrap();
}

fn write_real_onion_artifacts(db: &Path) -> OnionWireFixture {
    let params = onionpir::params_info(u64::from(TINY_ONION_BINS_PER_TABLE));
    assert_eq!(params.num_plaintexts, 1);
    assert_eq!(params.num_entries, 1);

    let save_path = db.join("tiny-onion-save.bin");
    let mut server = OnionPirServer::new(u64::from(TINY_ONION_BINS_PER_TABLE));
    server.gen_data(&[0]);
    let expected_plaintext = server.get_original_plaintext(0);
    assert!(!expected_plaintext.is_empty());
    assert!(server.save_db(save_path.to_str().unwrap()));
    let saved = fs::read(&save_path).unwrap();
    fs::remove_file(&save_path).unwrap();
    assert!(saved.len() > 48);
    assert_eq!(
        saved.len() - 48,
        params.coeff_val_cnt as usize * params.num_plaintexts as usize * 8,
    );

    fs::write(db.join("onion_shared_ntt.bin"), &saved[48..]).unwrap();

    let mut chunk = Vec::with_capacity(40);
    chunk.extend_from_slice(&ONION_CHUNK_MAGIC.to_le_bytes());
    chunk.extend_from_slice(&1u32.to_le_bytes());
    chunk.extend_from_slice(&2u32.to_le_bytes());
    chunk.extend_from_slice(&TINY_ONION_BINS_PER_TABLE.to_le_bytes());
    chunk.extend_from_slice(&0x5152_5354_5556_5758u64.to_le_bytes());
    chunk.extend_from_slice(&1u32.to_le_bytes());
    chunk.extend_from_slice(&0u32.to_le_bytes());
    chunk.extend_from_slice(&0u32.to_le_bytes());
    fs::write(db.join("onion_chunk_cuckoo.bin"), chunk).unwrap();

    let mut index_meta = Vec::with_capacity(44);
    index_meta.extend_from_slice(&ONION_INDEX_META_MAGIC.to_le_bytes());
    index_meta.extend_from_slice(&1u32.to_le_bytes());
    index_meta.extend_from_slice(&2u32.to_le_bytes());
    index_meta.extend_from_slice(&1u32.to_le_bytes());
    index_meta.extend_from_slice(&TINY_ONION_BINS_PER_TABLE.to_le_bytes());
    index_meta.extend_from_slice(&0x6162_6364_6566_6768u64.to_le_bytes());
    index_meta.extend_from_slice(&0x7172_7374_7576_7778u64.to_le_bytes());
    index_meta.extend_from_slice(&15u32.to_le_bytes());
    assert_eq!(index_meta.len(), 44);
    fs::write(db.join("onion_index_meta.bin"), index_meta).unwrap();

    let mut index_all = Vec::with_capacity(32 + saved.len());
    index_all.extend_from_slice(&ONION_INDEX_ALL_MAGIC.to_le_bytes());
    index_all.extend_from_slice(&1u64.to_le_bytes());
    index_all.extend_from_slice(&(saved.len() as u64).to_le_bytes());
    index_all.extend_from_slice(&0u64.to_le_bytes());
    index_all.extend_from_slice(&saved);
    fs::write(db.join("onion_index_all.bin"), index_all).unwrap();

    write_onion_sibling_file(
        &db.join("merkle_onion_sib_index.bin"),
        ONION_INDEX_SIBLING_MAGIC,
        params.entry_size as u32 / 32,
        &saved,
    );
    write_onion_sibling_file(
        &db.join("merkle_onion_sib_data.bin"),
        ONION_DATA_SIBLING_MAGIC,
        params.entry_size as u32 / 32,
        &saved,
    );
    fs::write(db.join("merkle_onion_tree_tops.bin"), [0x5au8; 32]).unwrap();
    fs::write(db.join("merkle_onion_root.bin"), [0x6bu8; 32]).unwrap();

    let client = OnionPirClient::new(u64::from(TINY_ONION_BINS_PER_TABLE));
    let register = encode_register_keys(&client.galois_keys(), &client.gsw_key());
    assert!(
        register.len() > 256 * 1024,
        "fixture must exercise real client request chunking"
    );
    let query = client.generate_query(0);
    OnionWireFixture {
        client,
        expected_plaintext,
        register,
        query,
    }
}

fn write_onion_sibling_file(path: &Path, magic: u64, arity: u32, saved: &[u8]) {
    let mut bytes = Vec::with_capacity(24 + saved.len());
    bytes.extend_from_slice(&magic.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&arity.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&(saved.len() as u32).to_le_bytes());
    bytes.extend_from_slice(saved);
    fs::write(path, bytes).unwrap();
}

fn encode_register_keys(galois: &[u8], gsw: &[u8]) -> Vec<u8> {
    let payload_len = 1 + 4 + galois.len() + 4 + gsw.len();
    let mut request = Vec::with_capacity(4 + payload_len);
    request.extend_from_slice(&(payload_len as u32).to_le_bytes());
    request.push(REQ_REGISTER_KEYS);
    request.extend_from_slice(&(galois.len() as u32).to_le_bytes());
    request.extend_from_slice(galois);
    request.extend_from_slice(&(gsw.len() as u32).to_le_bytes());
    request.extend_from_slice(gsw);
    request
}

fn encode_onion_batch(variant: u8, round_id: u16, queries: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(variant);
    payload.extend_from_slice(&round_id.to_le_bytes());
    payload.push(queries.len() as u8);
    for query in queries {
        payload.extend_from_slice(&(query.len() as u32).to_le_bytes());
        payload.extend_from_slice(query);
    }
    let mut request = Vec::with_capacity(4 + payload.len());
    request.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    request.extend_from_slice(&payload);
    request
}

#[cfg(feature = "standard-cashu-process-e2e")]
fn raw_authorization_request(
    accepted: &AcceptedServicePolicyV1,
    scope_id: [u8; 32],
    offer_id: u32,
    operation: OperationStartV1,
    proof: pir_service_protocol::AuthorizationProofV1,
) -> Vec<u8> {
    let offer = accepted
        .policy()
        .scopes
        .iter()
        .find(|entry| entry.scope.scope_id() == scope_id)
        .and_then(|entry| entry.offers.iter().find(|offer| offer.offer_id == offer_id))
        .unwrap();
    let request = AuthBeginV1 {
        policy_digest: accepted.policy_digest(),
        scope_id,
        offer_id,
        scheme: offer.authorization,
        key_id: offer.key_id.clone(),
        operation,
        proof: proof
            .encode_for(offer.authorization, offer.free_mode)
            .unwrap(),
    };
    encode_service_request(REQ_AUTH_BEGIN_V1, &request.encode_padded().unwrap())
}

fn encode_service_request(opcode: u8, body: &[u8]) -> Vec<u8> {
    let payload_len = 1 + body.len();
    let mut request = Vec::with_capacity(4 + payload_len);
    request.extend_from_slice(&(payload_len as u32).to_le_bytes());
    request.push(opcode);
    request.extend_from_slice(body);
    request
}

fn assert_real_onion_result(
    response: &[u8],
    expected_variant: u8,
    expected_round: u16,
    expected_results: usize,
    onion: &OnionWireFixture,
) {
    assert_eq!(response.first().copied(), Some(expected_variant));
    let body = &response[1..];
    assert!(body.len() >= 3);
    assert_eq!(
        u16::from_le_bytes(body[..2].try_into().unwrap()),
        expected_round
    );
    assert_eq!(body[2] as usize, expected_results);
    let mut offset = 3;
    for result_index in 0..expected_results {
        assert!(offset + 4 <= body.len());
        let len = u32::from_le_bytes(body[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        assert!(len > 0, "real Onion result {result_index} was empty");
        assert!(offset + len <= body.len());
        let decrypted = onion.client.decrypt_response(&body[offset..offset + len]);
        assert_eq!(
            decrypted, onion.expected_plaintext,
            "real Onion result {result_index} did not decrypt to fixture plaintext"
        );
        offset += len;
    }
    assert_eq!(offset, body.len(), "Onion response has trailing bytes");
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

fn assert_real_onion_listener(index: u8, port: u16, stdout: &str, stderr: &str) {
    assert!(
        stdout.contains(&format!("Listening on ws://127.0.0.1:{port}")),
        "provider {index} was not loopback-bound\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );
    assert!(stdout.contains("Service admission V1: enforced"));
    assert!(stdout.contains("1 index servers ready"));
    assert!(stdout.contains("1 chunk servers ready"));
    assert!(stdout.contains("index sibling servers ready (1 groups"));
    assert!(stdout.contains("data sibling servers ready (1 groups"));
    assert!(!stderr.contains("UNSAFE DEBUG QUERY LOGGING ENABLED"));
}

fn unused_loopback_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn chmod(path: &Path, mode: u32) {
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions).unwrap();
}

fn read_log(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| format!("<read {}: {error}>", path.display()))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
