//! Loopback-only Payment V1 process/wire integration test.
//!
//! This test deliberately uses a tiny, manifest-bound DPF/Harmony database and
//! public deterministic test keys. It starts two independent `unified_server`
//! processes and exercises the real WebSocket, attestation-bound secure
//! channel, signed per-workload policy and keys, direct-receipt authorization,
//! DPF and four-frame K-padded Harmony query handlers, backend gate, and durable
//! replay boundary. It never starts an issuer or hint server, contacts a
//! Lightning node/mint/relay, or moves funds.
//!
//! On ordinary CI hosts this deliberately observes `NoSevHost` and uses the
//! SDK's `dangerous_unpaired_*` helpers. That covers the local wire and gate
//! boundaries only; it is not evidence of production identity, binary-pin, or
//! hardware-attestation verification.

#![cfg(unix)]

#[path = "support/payment_v1_method_matrix.rs"]
mod payment_v1_method_matrix;

use ed25519_dalek::SigningKey;
use libdpf::Dpf;
#[cfg(feature = "standard-cashu-process-e2e")]
use payment_v1_method_matrix::MatrixMethod;
use payment_v1_method_matrix::{MethodMatrixFixture, TestCashuMint};
use pir_core::cuckoo::write_header_with_anchor;
use pir_core::merkle::sha256;
use pir_core::params::{CHUNK_PARAMS, INDEX_PARAMS};
use pir_runtime_core::protocol::{
    BatchQuery, HarmonyBatchItem, HarmonyBatchQuery, Request, Response,
};
use pir_sdk_client::attest::{attest_with_eph_binding, SevStatus};
use pir_sdk_client::channel::{establish, SecureChannelTransport};
#[cfg(feature = "standard-cashu-process-e2e")]
use pir_sdk_client::dangerous_unpaired_accept_service_authorization_response_v1;
use pir_sdk_client::{
    dangerous_unpaired_authorize_service_operation_v1,
    dangerous_unpaired_build_authorization_proof_v1, fetch_verified_service_policy_v1,
    AcceptedServicePolicyV1, PirTransport, ServicePolicyCheckpointV1,
    WsConnection,
};
use pir_service_protocol::{
    derive_provider_id, paid_receipt_key_id, AcquisitionMethod,
    AuthPaddingClassV1, AuthScheme, BackendId, CredentialKeyBindingClaimsV1,
    CredentialKeyBindingV1, CredentialUnitV1, DatasetBindingV1, DeploymentStatus,
    EntitlementLimitsV1, FreeModeV1, OperationStartV1, PaidReceiptBindingV1,
    PaidReceiptV1, PriceV1, PrivacyLeakageV1, ServiceOfferV1,
    ServicePolicyV1, ServiceScopePolicyV1, ServiceScopeV1, VerificationMode, WorkloadId,
};
#[cfg(feature = "standard-cashu-process-e2e")]
use pir_service_protocol::{AuthBeginV1, AuthorizationProofV1, REQ_AUTH_BEGIN_V1};
use pir_service_store::{ProviderStore, StoreOptions};
use std::fs::{self, File};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DPF_OFFER_ID: u32 = 2;
const HARMONY_OFFER_ID: u32 = 3;
const OPERATION_PROFILE: u16 = 11;
const ENTITLEMENT_PROFILE: u16 = 101;
const TINY_BINS_PER_TABLE: usize = 128;
static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
struct ProviderFixture {
    index: u8,
    provider_id: [u8; 32],
    policy_signing_key: SigningKey,
    dpf_receipt_signing_key: SigningKey,
    harmony_receipt_signing_key: SigningKey,
    issuer_id: [u8; 32],
    policy_path: PathBuf,
    store_path: PathBuf,
    dpf_scope_id: [u8; 32],
    harmony_scope_id: [u8; 32],
    policy_digest: [u8; 32],
    issued_at: u64,
    receipt_not_after: u64,
    harmony_method_matrix: Option<MethodMatrixFixture>,
}

impl ProviderFixture {
    fn receipt(&self, scope_id: [u8; 32], offer_id: u32, serial_byte: u8) -> PaidReceiptV1 {
        let receipt_signing_key = if scope_id == self.dpf_scope_id {
            &self.dpf_receipt_signing_key
        } else if scope_id == self.harmony_scope_id {
            &self.harmony_receipt_signing_key
        } else {
            panic!("receipt fixture requested for an unknown scope")
        };
        PaidReceiptV1::sign(
            self.issuer_id,
            [serial_byte; 32],
            PaidReceiptBindingV1 {
                scope_id,
                offer_id,
                policy_digest: self.policy_digest,
                entitlement_profile: ENTITLEMENT_PROFILE,
            },
            self.issued_at,
            self.receipt_not_after,
            receipt_signing_key,
        )
        .expect("deterministic receipt fixture must be valid")
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
            "provider-{}-generation-{generation}-stdout.log",
            fixture.index
        ));
        let stderr_path = root.join(format!(
            "provider-{}-generation-{generation}-stderr.log",
            fixture.index
        ));
        let stdout = File::create(&stdout_path).expect("create server stdout log");
        let stderr = File::create(&stderr_path).expect("create server stderr log");
        let mut args = vec![
            "--bind-address".to_owned(),
            "127.0.0.1".to_owned(),
            "--port".to_owned(),
            port.to_string(),
            "--data-dir".to_owned(),
            db_path.display().to_string(),
            "--role".to_owned(),
            "secondary".to_owned(),
            "--disable-onion".to_owned(),
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
            "--max-connections".to_owned(),
            "16".to_owned(),
            "--service-max-concurrent-auth".to_owned(),
            "4".to_owned(),
            "--websocket-handshake-timeout-ms".to_owned(),
            "1000".to_owned(),
            "--connection-idle-timeout-ms".to_owned(),
            "60000".to_owned(),
            "--service-pre-auth-timeout-ms".to_owned(),
            "60000".to_owned(),
        ];
        if let Some(matrix) = &fixture.harmony_method_matrix {
            matrix.extend_server_args(&mut args);
        }
        let child = Command::new(env!("CARGO_BIN_EXE_unified_server"))
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("spawn unified_server");
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
async fn two_independent_providers_enforce_secure_paid_capabilities_over_real_sockets() {
    let root = tempfile::tempdir().expect("test root");
    chmod(root.path(), 0o700);
    let (db_path, manifest_root) = write_tiny_manifest_database(root.path());
    let now = unix_now();
    let provider0 = build_provider(root.path(), 0, manifest_root, now, None);
    let provider1 = build_provider(root.path(), 1, manifest_root, now, None);

    assert_ne!(provider0.provider_id, provider1.provider_id);
    assert_ne!(
        provider0.policy_signing_key.verifying_key(),
        provider1.policy_signing_key.verifying_key()
    );
    assert_ne!(provider0.issuer_id, provider1.issuer_id);
    assert_ne!(
        paid_receipt_key_id(&provider0.dpf_receipt_signing_key.verifying_key()),
        paid_receipt_key_id(&provider1.dpf_receipt_signing_key.verifying_key())
    );
    assert_ne!(
        paid_receipt_key_id(&provider0.harmony_receipt_signing_key.verifying_key()),
        paid_receipt_key_id(&provider1.harmony_receipt_signing_key.verifying_key())
    );
    assert_ne!(
        paid_receipt_key_id(&provider0.dpf_receipt_signing_key.verifying_key()),
        paid_receipt_key_id(&provider0.harmony_receipt_signing_key.verifying_key())
    );
    assert_ne!(provider0.store_path, provider1.store_path);

    let port0 = unused_loopback_port();
    let mut port1 = unused_loopback_port();
    while port1 == port0 {
        port1 = unused_loopback_port();
    }
    let server0 = ServerProcess::spawn(root.path(), &db_path, &provider0, port0, 0);
    let server1 = ServerProcess::spawn(root.path(), &db_path, &provider1, port1, 0);
    let request = valid_tiny_dpf_request();

    // A capability issued for provider 1 cannot authorize provider 0. This is
    // a real server rejection, not a client-side pair simulation.
    let (mut wrong_target, accepted0) =
        open_verified_session(port0, &provider0, manifest_root, &request).await;
    let provider1_receipt = provider1.receipt(provider1.dpf_scope_id, DPF_OFFER_ID, 0x71);
    let wrong_proof = dangerous_unpaired_build_authorization_proof_v1(
        &accepted0,
        &provider0.dpf_scope_id,
        DPF_OFFER_ID,
        &provider1_receipt.encode().unwrap(),
    )
    .unwrap();
    let error = dangerous_unpaired_authorize_service_operation_v1(
        &mut wrong_target,
        &accepted0,
        provider0.dpf_scope_id,
        DPF_OFFER_ID,
        OperationStartV1::DpfQuery { db_id: 0 },
        wrong_proof,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("invalid-or-spent"), "{error}");
    wrong_target.close().await.unwrap();

    // Provider 0's rejection does not burn provider 1's capability or consult
    // a cross-provider spent set: the exact same receipt succeeds at its
    // intended provider.
    exercise_paid_grant(
        port1,
        &provider1,
        manifest_root,
        &request,
        &provider1_receipt,
    )
    .await;

    // Provider 0 independently accepts only its own capability, then lets one
    // bounded PBC frame carrying two address placements reach the real DPF
    // handler. Payment V1 charges the packed INDEX frame as one logical job,
    // not two raw user inputs or the public padding width.
    let receipt0 = provider0.receipt(provider0.dpf_scope_id, DPF_OFFER_ID, 0x80);
    exercise_paid_grant(port0, &provider0, manifest_root, &request, &receipt0).await;

    let harmony_requests = valid_tiny_harmony_query_requests();

    // Entitlements are backend/workload-specific. A fresh DPF receipt cannot
    // authorize a Harmony query scope, and the rejected mismatch must not burn
    // the receipt at its intended DPF scope.
    let dpf_only_receipt = provider0.receipt(provider0.dpf_scope_id, DPF_OFFER_ID, 0x81);
    let (mut wrong_scope, wrong_scope_policy) =
        open_verified_session(port0, &provider0, manifest_root, &harmony_requests[0]).await;
    let wrong_scope_proof = dangerous_unpaired_build_authorization_proof_v1(
        &wrong_scope_policy,
        &provider0.harmony_scope_id,
        HARMONY_OFFER_ID,
        &dpf_only_receipt.encode().unwrap(),
    )
    .unwrap();
    let wrong_scope_error = dangerous_unpaired_authorize_service_operation_v1(
        &mut wrong_scope,
        &wrong_scope_policy,
        provider0.harmony_scope_id,
        HARMONY_OFFER_ID,
        OperationStartV1::HarmonyQuery { db_id: 0 },
        wrong_scope_proof,
    )
    .await
    .unwrap_err();
    assert!(
        wrong_scope_error.to_string().contains("invalid-or-spent"),
        "{wrong_scope_error}"
    );
    wrong_scope.close().await.unwrap();
    exercise_paid_grant(
        port0,
        &provider0,
        manifest_root,
        &request,
        &dpf_only_receipt,
    )
    .await;

    // Each provider independently prices and spends its Harmony query scope.
    // The four accepted frames execute real INDEX/CHUNK K-padded queries in
    // the production process without configuring or naming any hint server.
    let harmony_receipt0 = provider0.receipt(provider0.harmony_scope_id, HARMONY_OFFER_ID, 0x90);
    let harmony_receipt1 = provider1.receipt(provider1.harmony_scope_id, HARMONY_OFFER_ID, 0x91);
    exercise_harmony_query_grant(
        port0,
        &provider0,
        manifest_root,
        &harmony_requests,
        &harmony_receipt0,
    )
    .await;
    exercise_harmony_query_grant(
        port1,
        &provider1,
        manifest_root,
        &harmony_requests,
        &harmony_receipt1,
    )
    .await;

    // Stop and restart provider 0 against the same SQLite domain. Its durable
    // store must reject the same receipt on a fresh process and secure session.
    let (stdout0_first, stderr0_first) = server0.stop();
    assert_loopback_listener(0, port0, &stdout0_first, &stderr0_first);
    let server0 = ServerProcess::spawn(root.path(), &db_path, &provider0, port0, 1);
    let (mut replay_session, replay_policy) =
        open_verified_session(port0, &provider0, manifest_root, &request).await;
    let replay_proof = dangerous_unpaired_build_authorization_proof_v1(
        &replay_policy,
        &provider0.dpf_scope_id,
        DPF_OFFER_ID,
        &receipt0.encode().unwrap(),
    )
    .unwrap();
    let replay = dangerous_unpaired_authorize_service_operation_v1(
        &mut replay_session,
        &replay_policy,
        provider0.dpf_scope_id,
        DPF_OFFER_ID,
        OperationStartV1::DpfQuery { db_id: 0 },
        replay_proof,
    )
    .await
    .unwrap_err();
    assert!(replay.to_string().contains("invalid-or-spent"), "{replay}");
    replay_session.close().await.unwrap();

    let (mut harmony_replay_session, harmony_replay_policy) =
        open_verified_session(port0, &provider0, manifest_root, &harmony_requests[0]).await;
    let harmony_replay_proof = dangerous_unpaired_build_authorization_proof_v1(
        &harmony_replay_policy,
        &provider0.harmony_scope_id,
        HARMONY_OFFER_ID,
        &harmony_receipt0.encode().unwrap(),
    )
    .unwrap();
    let harmony_replay = dangerous_unpaired_authorize_service_operation_v1(
        &mut harmony_replay_session,
        &harmony_replay_policy,
        provider0.harmony_scope_id,
        HARMONY_OFFER_ID,
        OperationStartV1::HarmonyQuery { db_id: 0 },
        harmony_replay_proof,
    )
    .await
    .unwrap_err();
    assert!(
        harmony_replay.to_string().contains("invalid-or-spent"),
        "{harmony_replay}"
    );
    harmony_replay_session.close().await.unwrap();

    let (stdout0, stderr0) = server0.stop();
    let (stdout1, stderr1) = server1.stop();
    for (index, stdout, stderr) in [(0, stdout0, stderr0), (1, stdout1, stderr1)] {
        let port = if index == 0 { port0 } else { port1 };
        assert_loopback_listener(index, port, &stdout, &stderr);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn harmony_work_limit_rejection_returns_an_encrypted_error_response() {
    let root = tempfile::tempdir().expect("test root");
    chmod(root.path(), 0o700);
    let (db_path, manifest_root) = write_tiny_manifest_database(root.path());
    let first_index_frame_work = u64::try_from(INDEX_PARAMS.k).unwrap();
    let provider = build_provider_with_harmony_work_limit(
        root.path(),
        0,
        manifest_root,
        unix_now(),
        None,
        first_index_frame_work - 1,
    );
    let port = unused_loopback_port();
    let server = ServerProcess::spawn(root.path(), &db_path, &provider, port, 0);
    let requests = valid_tiny_harmony_query_requests();
    let receipt = provider.receipt(provider.harmony_scope_id, HARMONY_OFFER_ID, 0xa0);
    let (mut secure, accepted) =
        open_verified_session(port, &provider, manifest_root, &requests[0]).await;
    let proof = dangerous_unpaired_build_authorization_proof_v1(
        &accepted,
        &provider.harmony_scope_id,
        HARMONY_OFFER_ID,
        &receipt.encode().unwrap(),
    )
    .unwrap();
    dangerous_unpaired_authorize_service_operation_v1(
        &mut secure,
        &accepted,
        provider.harmony_scope_id,
        HARMONY_OFFER_ID,
        OperationStartV1::HarmonyQuery { db_id: 0 },
        proof,
    )
    .await
    .expect("undersized scope must still authorize before the backend frame is counted");

    let response = secure
        .roundtrip(&requests[0])
        .await
        .expect("resource-limit rejection must remain an encrypted response");
    expect_error_response(&response, "service entitlement limit exceeded");
    secure.close().await.unwrap();

    let (stdout, stderr) = server.stop();
    assert_loopback_listener(0, port, &stdout, &stderr);
}

#[cfg(feature = "standard-cashu-process-e2e")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_non_receipt_methods_commit_before_real_harmony_query_and_replay_after_restart() {
    let root = tempfile::tempdir().expect("test root");
    chmod(root.path(), 0o700);
    let mint = TestCashuMint::spawn(root.path());
    let (db_path, manifest_root) = write_tiny_manifest_database(root.path());
    let provider = build_provider(root.path(), 0, manifest_root, unix_now(), Some(&mint));
    let port = unused_loopback_port();
    let server = ServerProcess::spawn(root.path(), &db_path, &provider, port, 0);
    let requests = valid_tiny_harmony_query_requests();
    let matrix = provider.harmony_method_matrix.as_ref().unwrap();

    for method in MatrixMethod::ALL {
        let fixture = matrix.method(method);
        let (mut secure, accepted) =
            open_verified_session(port, &provider, manifest_root, &requests[0]).await;
        let scope = accepted
            .policy()
            .scopes
            .iter()
            .find(|entry| entry.scope.scope_id() == provider.harmony_scope_id)
            .unwrap();
        assert_eq!(scope.scope.backend, BackendId::HarmonyPirV2);
        assert_eq!(scope.scope.workload, WorkloadId::HarmonyQueryJobV1);
        let proof = dangerous_unpaired_build_authorization_proof_v1(
            &accepted,
            &provider.harmony_scope_id,
            fixture.offer_id(),
            fixture.proof(0),
        )
        .unwrap();
        let attempts_before_wrong_scope = mint.attempt_count();
        let wrong = raw_authorization_request(
            &accepted,
            provider.harmony_scope_id,
            fixture.offer_id(),
            OperationStartV1::DpfQuery { db_id: 0 },
            proof.clone(),
        );
        let response = secure.roundtrip(&wrong).await.unwrap();
        let error = dangerous_unpaired_accept_service_authorization_response_v1(
            &response,
            &accepted,
            provider.harmony_scope_id,
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
            provider.harmony_scope_id,
            fixture.offer_id(),
            OperationStartV1::HarmonyQuery { db_id: 0 },
            proof,
        )
        .await
        .unwrap_or_else(|error| panic!("{method:?} failed exact Harmony auth: {error}"));
        assert_eq!(grant.scope_id, provider.harmony_scope_id);
        assert_eq!(grant.enforced_profile, ENTITLEMENT_PROFILE);
        assert_harmony_query_results(&mut secure, &requests).await;
        secure.close().await.unwrap();
    }
    assert_eq!(
        mint.attempt_count(),
        1,
        "only Standard Cashu reaches the mint"
    );

    let (stdout_first, stderr_first) = server.stop();
    assert_loopback_listener(0, port, &stdout_first, &stderr_first);
    let server = ServerProcess::spawn(root.path(), &db_path, &provider, port, 1);
    for method in MatrixMethod::ALL {
        let fixture = matrix.method(method);
        let (mut secure, accepted) =
            open_verified_session(port, &provider, manifest_root, &requests[0]).await;
        let proof = dangerous_unpaired_build_authorization_proof_v1(
            &accepted,
            &provider.harmony_scope_id,
            fixture.offer_id(),
            fixture.proof(0),
        )
        .unwrap();
        let error = dangerous_unpaired_authorize_service_operation_v1(
            &mut secure,
            &accepted,
            provider.harmony_scope_id,
            fixture.offer_id(),
            OperationStartV1::HarmonyQuery { db_id: 0 },
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
    assert_loopback_listener(0, port, &stdout, &stderr);
}

#[test]
fn misspelled_bind_flag_fails_closed_before_listening() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_unified_server"))
        .args(["--bind-addres", "127.0.0.1"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run unified_server with misspelled bind flag");
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if child.try_wait().expect("poll typo process").is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("unknown CLI argument did not fail within two seconds");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = child
        .wait_with_output()
        .expect("collect typo process output");

    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown argument: --bind-addres"),
        "{stderr}"
    );
}

fn assert_loopback_listener(index: u8, port: u16, stdout: &str, stderr: &str) {
    let expected = format!("Listening on ws://127.0.0.1:{port}");
    assert!(
        stdout.contains(&expected),
        "provider {index} was not loopback-bound\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );
    assert!(stdout.contains("Service admission V1: enforced"));
    assert!(!stderr.contains("UNSAFE DEBUG QUERY LOGGING ENABLED"));
}

async fn exercise_paid_grant(
    port: u16,
    fixture: &ProviderFixture,
    manifest_root: [u8; 32],
    request: &[u8],
    receipt: &PaidReceiptV1,
) {
    let (mut secure, accepted) = open_verified_session(port, fixture, manifest_root, request).await;
    let proof = dangerous_unpaired_build_authorization_proof_v1(
        &accepted,
        &fixture.dpf_scope_id,
        DPF_OFFER_ID,
        &receipt.encode().unwrap(),
    )
    .unwrap();
    let grant = dangerous_unpaired_authorize_service_operation_v1(
        &mut secure,
        &accepted,
        fixture.dpf_scope_id,
        DPF_OFFER_ID,
        OperationStartV1::DpfQuery { db_id: 0 },
        proof,
    )
    .await
    .expect("provider-specific direct receipt must authorize");
    assert_eq!(grant.scope_id, fixture.dpf_scope_id);
    assert_eq!(grant.enforced_profile, ENTITLEMENT_PROFILE);

    let response = secure.roundtrip(request).await.unwrap();
    match Response::decode(&response).unwrap() {
        Response::IndexBatch(result) => {
            assert_eq!(result.results.len(), 2);
            assert!(result.results.iter().all(|group| group.len() == 2));
            assert!(result.results.iter().flatten().all(|item| item.len() == 52));
        }
        other => panic!("authorized DPF frame did not reach handler: {other:?}"),
    }

    // The signed entitlement permits only one backend frame. A second frame
    // is rejected by the gate instead of silently creating extra value.
    expect_error_response(
        &secure.roundtrip(request).await.unwrap(),
        "service entitlement limit exceeded",
    );
    secure.close().await.unwrap();
}

async fn exercise_harmony_query_grant(
    port: u16,
    fixture: &ProviderFixture,
    manifest_root: [u8; 32],
    requests: &[Vec<u8>],
    receipt: &PaidReceiptV1,
) {
    assert_eq!(requests.len(), 4);
    let (mut secure, accepted) =
        open_verified_session(port, fixture, manifest_root, &requests[0]).await;
    let proof = dangerous_unpaired_build_authorization_proof_v1(
        &accepted,
        &fixture.harmony_scope_id,
        HARMONY_OFFER_ID,
        &receipt.encode().unwrap(),
    )
    .unwrap();
    let grant = dangerous_unpaired_authorize_service_operation_v1(
        &mut secure,
        &accepted,
        fixture.harmony_scope_id,
        HARMONY_OFFER_ID,
        OperationStartV1::HarmonyQuery { db_id: 0 },
        proof,
    )
    .await
    .expect("provider-specific Harmony receipt must authorize");
    assert_eq!(grant.scope_id, fixture.harmony_scope_id);
    assert_eq!(grant.enforced_profile, ENTITLEMENT_PROFILE);

    assert_harmony_query_results(&mut secure, requests).await;

    // The price applies to one signed four-frame query job. The completed DFA
    // is terminal: a second job cannot reopen or extend the consumed grant,
    // even though the first repeated frame would fit an individual frame
    // shape.
    expect_error_response(
        &secure.roundtrip(&requests[0]).await.unwrap(),
        "backend frame violates the operation sequence",
    );
    secure.close().await.unwrap();
}

async fn assert_harmony_query_results(
    secure: &mut SecureChannelTransport<WsConnection>,
    requests: &[Vec<u8>],
) {
    assert_eq!(requests.len(), 4);
    for (request, (expected_level, expected_round)) in
        requests.iter().zip([(0u8, 0u16), (0, 1), (1, 0), (1, 1)])
    {
        let response = secure.roundtrip(request).await.unwrap();
        match Response::decode(&response).unwrap() {
            Response::HarmonyBatchResult(result) => {
                assert_eq!(result.level, expected_level);
                assert_eq!(result.round_id, expected_round);
                assert_eq!(result.sub_results_per_group, 1);
                let expected_groups = if expected_level == 0 {
                    INDEX_PARAMS.k
                } else {
                    CHUNK_PARAMS.k
                };
                let expected_bin_size = if expected_level == 0 {
                    INDEX_PARAMS.bin_size()
                } else {
                    CHUNK_PARAMS.bin_size()
                };
                assert_eq!(result.items.len(), expected_groups);
                for (group, item) in result.items.iter().enumerate() {
                    assert_eq!(usize::from(item.group_id), group);
                    assert_eq!(item.sub_results.len(), 1);
                    assert_eq!(item.sub_results[0].len(), expected_bin_size);
                    assert!(item.sub_results[0].iter().all(|byte| *byte == 0));
                }
            }
            other => panic!("authorized Harmony frame did not reach handler: {other:?}"),
        }
    }
}

#[cfg(feature = "standard-cashu-process-e2e")]
fn raw_authorization_request(
    accepted: &AcceptedServicePolicyV1,
    scope_id: [u8; 32],
    offer_id: u32,
    operation: OperationStartV1,
    proof: AuthorizationProofV1,
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

#[cfg(feature = "standard-cashu-process-e2e")]
fn encode_service_request(opcode: u8, payload: &[u8]) -> Vec<u8> {
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
    open_verified_session_exact(
        port,
        fixture.provider_id,
        &fixture.policy_signing_key,
        fixture.policy_digest,
        fixture.index,
        manifest_root,
        backend_request,
    )
    .await
}

async fn open_verified_session_exact(
    port: u16,
    provider_id: [u8; 32],
    policy_signing_key: &SigningKey,
    policy_digest: [u8; 32],
    provider_index: u8,
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

    // The SDK refuses a policy fetch before the secure-channel upgrade, and
    // the server independently rejects a cleartext expensive backend frame.
    let local_reject = fetch_verified_service_policy_v1(
        &mut raw,
        provider_id,
        &policy_signing_key.verifying_key(),
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

    // Keep deterministic fixtures without reusing client ephemeral material
    // across the multiple real connections opened by this test.
    let session_id = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut eph_seed = [0x20u8.wrapping_add(provider_index); 32];
    let mut random = [0x40u8.wrapping_add(provider_index); 32];
    let mut handshake_nonce = [0x60u8.wrapping_add(provider_index); 32];
    eph_seed[..8].copy_from_slice(&session_id.to_le_bytes());
    random[..8].copy_from_slice(&session_id.wrapping_add(0x1000).to_le_bytes());
    handshake_nonce[..8].copy_from_slice(&session_id.wrapping_add(0x2000).to_le_bytes());
    let attestation = attest_with_eph_binding(&mut raw, eph_seed, random)
        .await
        .expect("attestation-bound channel key");
    assert_eq!(attestation.sev_status, SevStatus::NoSevHost);
    assert_eq!(attestation.response.manifest_roots, vec![manifest_root]);
    // This local binary is not produced by the attested-builder pipeline, so
    // its binary_sha256 may be the all-zero sentinel. Production binary-pin
    // verification is deliberately outside this wire/gate test.
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
        provider_id,
        &policy_signing_key.verifying_key(),
        unix_now(),
        &ServicePolicyCheckpointV1::initial(),
    )
    .await
    .expect("verify exact signed provider policy");
    assert_eq!(accepted.policy_digest(), policy_digest);
    assert_eq!(accepted.checkpoint().rollback_guard().highest_epoch, 1);

    expect_error_response(
        &secure.roundtrip(backend_request).await.unwrap(),
        "authorization required",
    );
    (secure, accepted)
}

fn build_provider(
    root: &Path,
    index: u8,
    manifest_root: [u8; 32],
    now: u64,
    matrix_mint: Option<&TestCashuMint>,
) -> ProviderFixture {
    build_provider_with_harmony_work_limit(root, index, manifest_root, now, matrix_mint, 320)
}

fn build_provider_with_harmony_work_limit(
    root: &Path,
    index: u8,
    manifest_root: [u8; 32],
    now: u64,
    matrix_mint: Option<&TestCashuMint>,
    harmony_max_work_units: u64,
) -> ProviderFixture {
    let provider_root = root.join(format!("provider-{index}"));
    let store_dir = provider_root.join("store-domain");
    fs::create_dir_all(&store_dir).unwrap();
    chmod(&provider_root, 0o700);
    chmod(&store_dir, 0o700);

    let operator_key = SigningKey::from_bytes(&[0x10u8.wrapping_add(index); 32]);
    let policy_signing_key = SigningKey::from_bytes(&[0x20u8.wrapping_add(index); 32]);
    let issuer_root_key = SigningKey::from_bytes(&[0x30u8.wrapping_add(index); 32]);
    let dpf_receipt_signing_key = SigningKey::from_bytes(&[0x40u8.wrapping_add(index); 32]);
    let harmony_receipt_signing_key = SigningKey::from_bytes(&[0x60u8.wrapping_add(index); 32]);
    let stable_server_id = format!("payment-v1-process-provider-{index}");
    let provider_id =
        derive_provider_id(&operator_key.verifying_key().to_bytes(), &stable_server_id);
    let issued_at = now.saturating_sub(60);
    let expires_at = now.checked_add(3_600).unwrap();
    let receipt_not_after = now.checked_add(600).unwrap();
    let dpf_scope = ServiceScopeV1 {
        provider_id,
        backend: BackendId::DpfPirV1,
        workload: WorkloadId::DpfEvaluateJobV1,
        protocol_version: 1,
        dataset: DatasetBindingV1::ManifestRoot {
            root: manifest_root,
        },
        operation_profile: OPERATION_PROFILE,
        entitlement_profile: ENTITLEMENT_PROFILE,
    };
    let harmony_scope = ServiceScopeV1 {
        provider_id,
        backend: BackendId::HarmonyPirV2,
        workload: WorkloadId::HarmonyQueryJobV1,
        protocol_version: 2,
        dataset: DatasetBindingV1::ManifestRoot {
            root: manifest_root,
        },
        operation_profile: OPERATION_PROFILE,
        entitlement_profile: ENTITLEMENT_PROFILE,
    };
    let dpf_scope_id = dpf_scope.scope_id();
    let harmony_scope_id = harmony_scope.scope_id();
    let dpf_receipt_key_id = paid_receipt_key_id(&dpf_receipt_signing_key.verifying_key()).to_vec();
    let harmony_receipt_key_id =
        paid_receipt_key_id(&harmony_receipt_signing_key.verifying_key()).to_vec();
    let retired_policy_grace_seconds = 1_800;
    let make_binding =
        |scope_id, offer_id, receipt_signing_key: &SigningKey, receipt_key_id: &[u8]| {
            CredentialKeyBindingV1::sign(
                CredentialKeyBindingClaimsV1 {
                    provider_id,
                    scope_id,
                    offer_id,
                    scheme: AuthScheme::Bolt11DirectReceiptV1,
                    keyset_epoch: 1,
                    entitlement_profile: ENTITLEMENT_PROFILE,
                    unit: CredentialUnitV1::Entitlement,
                    amount: 1,
                    presentation_limit: 1,
                    not_before: issued_at.saturating_sub(60),
                    not_after: expires_at + u64::from(retired_policy_grace_seconds),
                    credential_key_id: receipt_key_id.to_vec(),
                    verification_key: receipt_signing_key.verifying_key().to_bytes().to_vec(),
                },
                &issuer_root_key,
            )
            .unwrap()
        };
    let dpf_binding = make_binding(
        dpf_scope_id,
        DPF_OFFER_ID,
        &dpf_receipt_signing_key,
        &dpf_receipt_key_id,
    );
    let harmony_binding = make_binding(
        harmony_scope_id,
        HARMONY_OFFER_ID,
        &harmony_receipt_signing_key,
        &harmony_receipt_key_id,
    );
    let issuer_id = dpf_binding.issuer_id;
    assert_eq!(issuer_id, harmony_binding.issuer_id);
    let make_offer = |offer_id, key_id: Vec<u8>, binding: CredentialKeyBindingV1| ServiceOfferV1 {
        offer_id,
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
        key_id,
        credential_binding: Some(binding),
        cashu_mint_manifest: None,
        endpoint: format!("https://issuer-{index}.fixture.invalid"),
        invoice_expiry_seconds: 600,
        claim_window_seconds: 600,
        minimum_credential_validity_seconds: 600,
        retired_policy_grace_seconds,
        credential_count: 1,
        credential_presentation_limit: 1,
        privacy_leakage: PrivacyLeakageV1::from_bits(PrivacyLeakageV1::DIRECT_PAYMENT_TO_SPEND)
            .unwrap(),
    };
    let harmony_method_matrix = matrix_mint.map(|mint| {
        MethodMatrixFixture::build(
            &provider_root,
            provider_id,
            harmony_scope_id,
            ENTITLEMENT_PROFILE,
            issued_at,
            expires_at,
            1,
            0x41u8.wrapping_add(index),
            mint,
        )
    });
    let mut harmony_offers = vec![make_offer(
        HARMONY_OFFER_ID,
        harmony_receipt_key_id,
        harmony_binding,
    )];
    if let Some(matrix) = &harmony_method_matrix {
        harmony_offers.extend(matrix.offers().iter().cloned());
    }
    let policy = ServicePolicyV1::sign(
        provider_id,
        1,
        issued_at,
        expires_at,
        AuthPaddingClassV1::Class16KiB,
        vec![
            ServiceScopePolicyV1 {
                scope: dpf_scope,
                limits: EntitlementLimitsV1 {
                    max_logical_inputs: 1,
                    max_frames: 1,
                    max_request_bytes: 16 * 1024,
                    max_response_bytes: 4 * 1024,
                    max_wall_time_ms: 10_000,
                    max_concurrent_sockets: 1,
                    max_hint_groups: 0,
                    max_work_units: 4,
                },
                offers: vec![make_offer(DPF_OFFER_ID, dpf_receipt_key_id, dpf_binding)],
            },
            ServiceScopePolicyV1 {
                scope: harmony_scope,
                limits: EntitlementLimitsV1 {
                    max_logical_inputs: 1,
                    max_frames: 4,
                    max_request_bytes: 64 * 1024,
                    max_response_bytes: 64 * 1024,
                    max_wall_time_ms: 10_000,
                    max_concurrent_sockets: 1,
                    max_hint_groups: 0,
                    max_work_units: harmony_max_work_units,
                },
                offers: harmony_offers,
            },
        ],
        &policy_signing_key,
    )
    .unwrap();
    let policy_digest = policy.policy_digest().unwrap();
    let policy_path = provider_root.join("service-policy-v1.bin");
    fs::write(&policy_path, policy.encode().unwrap()).unwrap();
    chmod(&policy_path, 0o644);

    let store_path = store_dir.join("provider.sqlite3");
    let store = ProviderStore::create(
        &store_path,
        [0x50u8.wrapping_add(index); 16],
        provider_id,
        StoreOptions {
            busy_timeout: Duration::from_secs(1),
        },
    )
    .unwrap();
    drop(store);
    chmod(&store_path, 0o600);

    ProviderFixture {
        index,
        provider_id,
        policy_signing_key,
        dpf_receipt_signing_key,
        harmony_receipt_signing_key,
        issuer_id,
        policy_path,
        store_path,
        dpf_scope_id,
        harmony_scope_id,
        policy_digest,
        issued_at,
        receipt_not_after,
        harmony_method_matrix,
    }
}

fn write_tiny_manifest_database(root: &Path) -> (PathBuf, [u8; 32]) {
    let db = root.join("tiny-db");
    fs::create_dir(&db).unwrap();
    let index_path = db.join("batch_pir_cuckoo.bin");
    let chunk_path = db.join("chunk_pir_cuckoo.bin");
    write_tiny_table(
        &index_path,
        &INDEX_PARAMS.with_master_seed(0x1111_2222_3333_4444),
        0x9999_aaaa_bbbb_cccc,
    );
    write_tiny_table(
        &chunk_path,
        &CHUNK_PARAMS.with_master_seed(0x5555_6666_7777_8888),
        0,
    );
    let zero_hash = "0".repeat(64);
    let manifest = format!(
        "[manifest]\nversion = 1\ngenerated_at = \"2026-07-26T00:00:00Z\"\n\n[files]\n\"batch_pir_cuckoo.bin\" = \"{zero_hash}\"\n\"chunk_pir_cuckoo.bin\" = \"{zero_hash}\"\n"
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

fn valid_tiny_dpf_request() -> Vec<u8> {
    let dpf = Dpf::with_default_key();
    // Two real PBC groups model N=2 addresses that fit one packed INDEX
    // round. Each group still carries the two cuckoo-position DPF keys.
    let (first0, first1) = dpf.gen(0, 7);
    let (second0, second1) = dpf.gen(1, 7);
    Request::IndexBatch(BatchQuery {
        level: 0,
        round_id: 0,
        db_id: 0,
        keys: vec![
            vec![first0.to_bytes(), first1.to_bytes()],
            vec![second0.to_bytes(), second1.to_bytes()],
        ],
    })
    .encode()
}

fn valid_tiny_harmony_query_requests() -> Vec<Vec<u8>> {
    [(0u8, 0u16), (0, 1), (1, 0), (1, 1)]
        .into_iter()
        .map(|(level, round_id)| {
            let group_count = if level == 0 {
                INDEX_PARAMS.k
            } else {
                CHUNK_PARAMS.k
            };
            let items = (0..group_count)
                .map(|group_id| HarmonyBatchItem {
                    group_id: u8::try_from(group_id).expect("fixture K fits u8"),
                    sub_queries: vec![vec![0]],
                })
                .collect();
            Request::HarmonyBatchQuery(HarmonyBatchQuery {
                level,
                round_id,
                sub_queries_per_group: 1,
                items,
                db_id: 0,
            })
            .encode()
        })
        .collect()
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
