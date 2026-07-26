//! Loopback-only Payment V1 process/wire integration test.
//!
//! This test deliberately uses a tiny, manifest-bound DPF database and public
//! deterministic test keys. It starts two independent `unified_server`
//! processes and exercises the real WebSocket, attestation-bound secure
//! channel, signed policy, direct-receipt authorization, backend gate, and
//! durable replay boundary. It never starts an issuer, contacts a Lightning
//! node/mint/relay, or moves funds.
//!
//! On ordinary CI hosts this deliberately observes `NoSevHost` and uses the
//! SDK's `dangerous_unpaired_*` helpers. That covers the local wire and gate
//! boundaries only; it is not evidence of production identity, binary-pin, or
//! hardware-attestation verification.

#![cfg(unix)]

use ed25519_dalek::SigningKey;
use libdpf::Dpf;
use pir_core::cuckoo::write_header_with_anchor;
use pir_core::merkle::sha256;
use pir_core::params::{CHUNK_PARAMS, INDEX_PARAMS};
use pir_runtime_core::protocol::{BatchQuery, Request, Response};
use pir_sdk_client::attest::{attest_with_eph_binding, SevStatus};
use pir_sdk_client::channel::{establish, SecureChannelTransport};
use pir_sdk_client::{
    dangerous_unpaired_authorize_service_operation_v1,
    dangerous_unpaired_build_authorization_proof_v1, fetch_verified_service_policy_v1,
    AcceptedServicePolicyV1, PirTransport, ServicePolicyCheckpointV1, WsConnection,
};
use pir_service_protocol::{
    derive_provider_id, paid_receipt_key_id, AcquisitionMethod, AuthPaddingClassV1, AuthScheme,
    BackendId, CredentialKeyBindingClaimsV1, CredentialKeyBindingV1, CredentialUnitV1,
    DatasetBindingV1, DeploymentStatus, EntitlementLimitsV1, FreeModeV1, OperationStartV1,
    PaidReceiptBindingV1, PaidReceiptV1, PriceV1, PrivacyLeakageV1, ServiceOfferV1,
    ServicePolicyV1, ServiceScopePolicyV1, ServiceScopeV1, VerificationMode, WorkloadId,
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
const OPERATION_PROFILE: u16 = 11;
const ENTITLEMENT_PROFILE: u16 = 101;
const TINY_BINS_PER_TABLE: usize = 128;
static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
struct ProviderFixture {
    index: u8,
    provider_id: [u8; 32],
    policy_signing_key: SigningKey,
    receipt_signing_key: SigningKey,
    issuer_id: [u8; 32],
    policy_path: PathBuf,
    store_path: PathBuf,
    rollback_path: PathBuf,
    scope_id: [u8; 32],
    policy_digest: [u8; 32],
    issued_at: u64,
    receipt_not_after: u64,
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
    let provider0 = build_provider(root.path(), 0, manifest_root, now);
    let provider1 = build_provider(root.path(), 1, manifest_root, now);

    assert_ne!(provider0.provider_id, provider1.provider_id);
    assert_ne!(
        provider0.policy_signing_key.verifying_key(),
        provider1.policy_signing_key.verifying_key()
    );
    assert_ne!(provider0.issuer_id, provider1.issuer_id);
    assert_ne!(
        paid_receipt_key_id(&provider0.receipt_signing_key.verifying_key()),
        paid_receipt_key_id(&provider1.receipt_signing_key.verifying_key())
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
    let provider1_receipt = provider1.receipt(0x71);
    let wrong_proof = dangerous_unpaired_build_authorization_proof_v1(
        &accepted0,
        &provider0.scope_id,
        OFFER_ID,
        &provider1_receipt.encode().unwrap(),
    )
    .unwrap();
    let error = dangerous_unpaired_authorize_service_operation_v1(
        &mut wrong_target,
        &accepted0,
        provider0.scope_id,
        OFFER_ID,
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

    // Provider 0 independently accepts only its own capability, then lets
    // exactly one bounded backend frame reach the real DPF handler.
    let receipt0 = provider0.receipt(0x80);
    exercise_paid_grant(port0, &provider0, manifest_root, &request, &receipt0).await;

    // Stop and restart provider 0 against the same SQLite domain. Its durable
    // store must reject the same receipt on a fresh process and secure session.
    let (stdout0_first, stderr0_first) = server0.stop();
    assert_loopback_listener(0, port0, &stdout0_first, &stderr0_first);
    let server0 = ServerProcess::spawn(root.path(), &db_path, &provider0, port0, 1);
    let (mut replay_session, replay_policy) =
        open_verified_session(port0, &provider0, manifest_root, &request).await;
    let replay_proof = dangerous_unpaired_build_authorization_proof_v1(
        &replay_policy,
        &provider0.scope_id,
        OFFER_ID,
        &receipt0.encode().unwrap(),
    )
    .unwrap();
    let replay = dangerous_unpaired_authorize_service_operation_v1(
        &mut replay_session,
        &replay_policy,
        provider0.scope_id,
        OFFER_ID,
        OperationStartV1::DpfQuery { db_id: 0 },
        replay_proof,
    )
    .await
    .unwrap_err();
    assert!(replay.to_string().contains("invalid-or-spent"), "{replay}");
    replay_session.close().await.unwrap();

    let (stdout0, stderr0) = server0.stop();
    let (stdout1, stderr1) = server1.stop();
    for (index, stdout, stderr) in [(0, stdout0, stderr0), (1, stdout1, stderr1)] {
        let port = if index == 0 { port0 } else { port1 };
        assert_loopback_listener(index, port, &stdout, &stderr);
    }
}

#[test]
fn misspelled_bind_flag_fails_closed_before_listening() {
    let port = unused_loopback_port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_unified_server"))
        .args(["--bind-addres", "127.0.0.1", "--port", &port.to_string()])
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
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown argument: --bind-addres"),
        "{stderr}"
    );
    assert!(
        TcpStream::connect(("127.0.0.1", port)).is_err(),
        "misspelled bind flag must fail before a listener is opened"
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
        &fixture.scope_id,
        OFFER_ID,
        &receipt.encode().unwrap(),
    )
    .unwrap();
    let grant = dangerous_unpaired_authorize_service_operation_v1(
        &mut secure,
        &accepted,
        fixture.scope_id,
        OFFER_ID,
        OperationStartV1::DpfQuery { db_id: 0 },
        proof,
    )
    .await
    .expect("provider-specific direct receipt must authorize");
    assert_eq!(grant.scope_id, fixture.scope_id);
    assert_eq!(grant.enforced_profile, ENTITLEMENT_PROFILE);

    let response = secure.roundtrip(request).await.unwrap();
    match Response::decode(&response).unwrap() {
        Response::IndexBatch(result) => {
            assert_eq!(result.results.len(), 1);
            assert_eq!(result.results[0].len(), 2);
            assert!(result.results[0].iter().all(|item| item.len() == 52));
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

    // The SDK refuses a policy fetch before the secure-channel upgrade, and
    // the server independently rejects a cleartext expensive backend frame.
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

    // Keep deterministic fixtures without reusing client ephemeral material
    // across the multiple real connections opened by this test.
    let session_id = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut eph_seed = [0x20u8.wrapping_add(fixture.index); 32];
    let mut random = [0x40u8.wrapping_add(fixture.index); 32];
    let mut handshake_nonce = [0x60u8.wrapping_add(fixture.index); 32];
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
        fixture.provider_id,
        &fixture.policy_signing_key.verifying_key(),
        unix_now(),
        &ServicePolicyCheckpointV1::initial(),
    )
    .await
    .expect("verify exact signed provider policy");
    assert_eq!(accepted.policy_digest(), fixture.policy_digest);
    assert_eq!(accepted.checkpoint().rollback_guard().highest_epoch, 1);

    expect_error_response(
        &secure.roundtrip(backend_request).await.unwrap(),
        "authorization required",
    );
    (secure, accepted)
}

fn build_provider(root: &Path, index: u8, manifest_root: [u8; 32], now: u64) -> ProviderFixture {
    let provider_root = root.join(format!("provider-{index}"));
    let store_dir = provider_root.join("store-domain");
    let rollback_dir = provider_root.join("rollback-domain");
    fs::create_dir_all(&store_dir).unwrap();
    fs::create_dir_all(&rollback_dir).unwrap();
    chmod(&provider_root, 0o700);
    chmod(&store_dir, 0o700);
    chmod(&rollback_dir, 0o700);

    let operator_key = SigningKey::from_bytes(&[0x10u8.wrapping_add(index); 32]);
    let policy_signing_key = SigningKey::from_bytes(&[0x20u8.wrapping_add(index); 32]);
    let issuer_root_key = SigningKey::from_bytes(&[0x30u8.wrapping_add(index); 32]);
    let receipt_signing_key = SigningKey::from_bytes(&[0x40u8.wrapping_add(index); 32]);
    let stable_server_id = format!("payment-v1-process-provider-{index}");
    let provider_id =
        derive_provider_id(&operator_key.verifying_key().to_bytes(), &stable_server_id);
    let issued_at = now.saturating_sub(60);
    let expires_at = now.checked_add(3_600).unwrap();
    let receipt_not_after = now.checked_add(600).unwrap();
    let scope = ServiceScopeV1 {
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
        key_id: receipt_key_id,
        credential_binding: Some(binding.clone()),
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
                max_frames: 1,
                max_request_bytes: 16 * 1024,
                max_response_bytes: 4 * 1024,
                max_wall_time_ms: 10_000,
                max_concurrent_sockets: 1,
                max_hint_groups: 0,
                max_work_units: 2,
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
        [0x50u8.wrapping_add(index); 16],
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
        policy_path,
        store_path,
        rollback_path,
        scope_id,
        policy_digest,
        issued_at,
        receipt_not_after,
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
    let (key0, key1) = dpf.gen(0, 7);
    Request::IndexBatch(BatchQuery {
        level: 0,
        round_id: 0,
        db_id: 0,
        keys: vec![vec![key0.to_bytes(), key1.to_bytes()]],
    })
    .encode()
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
