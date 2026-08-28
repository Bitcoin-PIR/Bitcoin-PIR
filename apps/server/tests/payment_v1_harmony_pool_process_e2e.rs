//! Real-process Payment V1 coverage for the durable HarmonyPIR V2Full pool.
//!
//! The fixture uses a tiny manifest-bound database, deterministic public test
//! keys, one loopback `unified_server`, and a private on-disk hint pool. It
//! exercises the reservation boundary across a real process and WebSocket:
//! invalid credentials restore the ready inode, a granted-but-disconnected
//! session returns its reservation, the first V2Full dispatch consumes the
//! exact ready file before exposing its PRP key, restart reuses the bound pool,
//! and an externally replaced ready name makes dispatch fail closed.
//!
//! Ordinary CI hosts report `NoSevHost`, so this uses the SDK's explicitly
//! dangerous unpaired authorization helpers after completing the real
//! attestation-bound secure-channel upgrade. It is wire/lifecycle evidence,
//! not production hardware-attestation evidence.

#![cfg(unix)]

#[path = "support/payment_v1_method_matrix.rs"]
mod payment_v1_method_matrix;

use ed25519_dalek::SigningKey;
#[cfg(feature = "standard-cashu-process-e2e")]
use payment_v1_method_matrix::MatrixMethod;
use payment_v1_method_matrix::{MethodMatrixFixture, TestCashuMint};
use pir_core::cuckoo::write_header_with_anchor;
use pir_core::merkle::{compute_bin_leaf_hash, compute_parent_n, sha256, Hash256, ZERO_HASH};
use pir_core::params::{CHUNK_PARAMS, INDEX_PARAMS};
use pir_runtime_core::protocol::{HarmonyHintRequestV2, Request, Response};
use pir_sdk_client::attest::{attest_with_eph_binding, SevStatus};
use pir_sdk_client::channel::{establish, SecureChannelTransport};
#[cfg(feature = "standard-cashu-process-e2e")]
use pir_sdk_client::dangerous_unpaired_accept_service_authorization_response_v1;
use pir_sdk_client::{
    dangerous_unpaired_authorize_service_operation_v1,
    dangerous_unpaired_build_authorization_proof_v1, fetch_verified_service_policy_v1,
    AcceptedServicePolicyV1, PirTransport, ServicePolicyCheckpointV1, WsConnection,
};
use pir_service_protocol::{
    derive_provider_id, paid_receipt_key_id, AcquisitionMethod, AuthPaddingClassV1, AuthScheme,
    BackendId, CredentialKeyBindingClaimsV1, CredentialKeyBindingV1, CredentialUnitV1,
    DatasetBindingV1, DeploymentStatus, EntitlementLimitsV1, FreeModeV1, HintTransport,
    OperationStartV1, PaidReceiptBindingV1, PaidReceiptV1, PriceV1, PrivacyLeakageV1,
    ServiceOfferV1, ServicePolicyV1, ServiceScopePolicyV1, ServiceScopeV1, VerificationMode,
    WorkloadId,
};
#[cfg(feature = "standard-cashu-process-e2e")]
use pir_service_protocol::{AuthBeginV1, AuthorizationProofV1, REQ_AUTH_BEGIN_V1};
use pir_service_store::{ProviderStore, StoreOptions};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::future::Future;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const OFFER_ID: u32 = 61;
const OPERATION_PROFILE: u16 = 41;
const ENTITLEMENT_PROFILE: u16 = 401;
const TINY_BINS_PER_TABLE: usize = 128;
const BUCKET_MERKLE_ARITY: usize = 8;
const PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(15);
const BINDING_MARKER: &str = ".hmpool-binding-v1";
const RESP_HARMONY_HINTS_KEY: u8 = 0x44;
static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

struct ProviderFixture {
    provider_id: [u8; 32],
    policy_signing_key: SigningKey,
    receipt_signing_key: SigningKey,
    issuer_id: [u8; 32],
    policy_path: PathBuf,
    store_path: PathBuf,
    scope_id: [u8; 32],
    policy_digest: [u8; 32],
    issued_at: u64,
    receipt_not_after: u64,
    method_matrix: Option<MethodMatrixFixture>,
}

impl ProviderFixture {
    fn receipt(&self, serial_byte: u8) -> PaidReceiptV1 {
        self.receipt_signed_by(serial_byte, &self.receipt_signing_key)
    }

    fn receipt_signed_by(&self, serial_byte: u8, key: &SigningKey) -> PaidReceiptV1 {
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
            key,
        )
        .expect("deterministic direct-receipt fixture")
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
        pool_dir: &Path,
        fixture: &ProviderFixture,
        port: u16,
        generation: u8,
    ) -> Self {
        // The method matrix includes Standard Cashu (online authority). Keep
        // one pool entry reserved for provider-local methods while the online
        // authorization limiter owns the other; the receipt-only baseline
        // intentionally retains its historical single-entry pool.
        let pool_size = if fixture.method_matrix.is_some() {
            "2"
        } else {
            "1"
        };
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
            "--serve-hints".to_owned(),
            "--pool-size".to_owned(),
            pool_size.to_owned(),
            "--pool-db-id".to_owned(),
            "0".to_owned(),
            "--pool-dir".to_owned(),
            pool_dir.display().to_string(),
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
            "30000".to_owned(),
            "--service-pre-auth-timeout-ms".to_owned(),
            "30000".to_owned(),
        ];
        if let Some(matrix) = &fixture.method_matrix {
            matrix.extend_server_args(&mut args);
        }
        Self::spawn_with_args(root, port, generation, args)
    }

    fn spawn_with_args(root: &Path, port: u16, generation: u8, args: Vec<String>) -> Self {
        let stdout_path = root.join(format!("harmony-pool-generation-{generation}-stdout.log"));
        let stderr_path = root.join(format!("harmony-pool-generation-{generation}-stderr.log"));
        let stdout = File::create(&stdout_path).expect("create server stdout log");
        let stderr = File::create(&stderr_path).expect("create server stderr log");
        let child = Command::new(env!("CARGO_BIN_EXE_unified_server"))
            .args(&args)
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
        let deadline = Instant::now() + PROCESS_TIMEOUT;
        loop {
            self.assert_running("waiting for listener");
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
                "timed out waiting for unified_server\nstdout:\n{}\nstderr:\n{}",
                read_log(&self.stdout_path),
                read_log(&self.stderr_path),
            );
            thread::sleep(Duration::from_millis(25));
        }
    }

    fn assert_running(&mut self, context: &str) {
        if let Some(status) = self.child.try_wait().expect("poll unified_server") {
            panic!(
                "unified_server exited while {context} ({status})\nstdout:\n{}\nstderr:\n{}",
                read_log(&self.stdout_path),
                read_log(&self.stderr_path),
            );
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

#[test]
fn complete_two_database_policy_starts_with_two_exact_hint_pools() {
    let root = tempfile::tempdir().expect("test root");
    chmod(root.path(), 0o700);
    let (db0_path, db0_root) = write_merkle_database_named(root.path(), "tiny-merkle-db0", 0);
    let (db1_path, db1_root) = write_merkle_database_named(root.path(), "tiny-merkle-db1", 1);
    let config_path = root.path().join("databases.toml");
    fs::write(
        &config_path,
        format!(
            "[[database]]\nname = \"db0\"\ntype = \"full\"\npath = \"{}\"\nbase_height = 0\nheight = 1\n\n[[database]]\nname = \"db1\"\ntype = \"delta\"\npath = \"{}\"\nbase_height = 1\nheight = 2\n",
            db0_path.display(),
            db1_path.display(),
        ),
    )
    .unwrap();

    let mut fixture = build_provider(root.path(), db0_root, unix_now(), None);
    install_two_database_free_pow_policy(&mut fixture, [db0_root, db1_root], unix_now());
    let pool0 = root.path().join("harmony-pool-db0");
    let pool1 = root.path().join("harmony-pool-db1");
    for pool in [&pool0, &pool1] {
        fs::create_dir(pool).unwrap();
        chmod(pool, 0o700);
    }

    let port = unused_loopback_port();
    let args = vec![
        "--bind-address".to_owned(),
        "127.0.0.1".to_owned(),
        "--port".to_owned(),
        port.to_string(),
        "--config".to_owned(),
        config_path.display().to_string(),
        "--role".to_owned(),
        "secondary".to_owned(),
        "--disable-onion".to_owned(),
        "--serve-hints".to_owned(),
        "--pool-size".to_owned(),
        "1".to_owned(),
        "--harmony-pool-db".to_owned(),
        format!("0={}", pool0.display()),
        "--harmony-pool-db".to_owned(),
        format!("1={}", pool1.display()),
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
        "30000".to_owned(),
        "--service-pre-auth-timeout-ms".to_owned(),
        "30000".to_owned(),
    ];
    let mut server = ServerProcess::spawn_with_args(root.path(), port, 9, args);
    wait_for_path(
        &mut server,
        &pool0.join(BINDING_MARKER),
        "db0 pool binding marker",
    );
    wait_for_path(
        &mut server,
        &pool1.join(BINDING_MARKER),
        "db1 pool binding marker",
    );
    let (stdout, stderr) = server.stop();
    assert_server_log(&stdout, &stderr, port);
    assert!(stdout.contains("HarmonyPIR V2 hint pool: db_id=0"));
    assert!(stdout.contains("HarmonyPIR V2 hint pool: db_id=1"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn harmony_v2_full_pool_reserves_consumes_recovers_and_fails_closed_over_real_process() {
    let root = tempfile::tempdir().expect("test root");
    chmod(root.path(), 0o700);
    let (db_path, manifest_root) = write_merkle_database(root.path());
    let pool_dir = root.path().join("harmony-pool");
    fs::create_dir(&pool_dir).unwrap();
    chmod(&pool_dir, 0o700);
    let fixture = build_provider(root.path(), manifest_root, unix_now(), None);
    let port = unused_loopback_port();
    let mut server = ServerProcess::spawn(root.path(), &db_path, &pool_dir, &fixture, port, 0);

    let marker_path = pool_dir.join(BINDING_MARKER);
    wait_for_path(&mut server, &marker_path, "durable pool binding marker");
    let marker_before = fs::read(&marker_path).expect("read initial pool binding marker");
    assert_private_single_link_file(&marker_path);
    let initial_ready = wait_for_ready_file(&mut server, &pool_dir, None);
    assert_private_single_link_file(&initial_ready);
    let initial_metadata = fs::metadata(&initial_ready).unwrap();

    // Structurally valid receipt bytes with the correct issuer/binding but a
    // signature from the wrong key must be rejected without consuming or
    // replacing the reserved ready inode.
    let wrong_key = SigningKey::from_bytes(&[0x7e; 32]);
    let invalid_receipt = fixture.receipt_signed_by(0x11, &wrong_key);
    let (mut invalid_session, invalid_policy) = within(
        "open invalid-credential session",
        open_verified_session(port, &fixture, manifest_root),
    )
    .await;
    let invalid_proof = dangerous_unpaired_build_authorization_proof_v1(
        &invalid_policy,
        &fixture.scope_id,
        OFFER_ID,
        &invalid_receipt.encode().unwrap(),
    )
    .unwrap();
    let invalid = within(
        "reject invalid direct receipt",
        dangerous_unpaired_authorize_service_operation_v1(
            &mut invalid_session,
            &invalid_policy,
            fixture.scope_id,
            OFFER_ID,
            v2_full_operation(),
            invalid_proof,
        ),
    )
    .await
    .expect_err("wrong receipt signature must fail");
    assert!(
        invalid.to_string().contains("invalid-or-spent"),
        "{invalid}"
    );
    let after_invalid = fs::metadata(&initial_ready).expect("ready file survived rejection");
    assert_eq!(initial_metadata.dev(), after_invalid.dev());
    assert_eq!(initial_metadata.ino(), after_invalid.ino());
    wait_until_unlocked(&mut server, &initial_ready);
    within("close invalid session", invalid_session.close())
        .await
        .unwrap();

    // A valid grant reserves the exact ready inode, but does not remove its
    // name. Closing before the first backend frame releases that reservation.
    let disconnect_receipt = fixture.receipt(0x22);
    let (mut disconnect_session, disconnect_policy) = within(
        "open disconnect session",
        open_verified_session(port, &fixture, manifest_root),
    )
    .await;
    let disconnect_proof = dangerous_unpaired_build_authorization_proof_v1(
        &disconnect_policy,
        &fixture.scope_id,
        OFFER_ID,
        &disconnect_receipt.encode().unwrap(),
    )
    .unwrap();
    within(
        "grant disconnect receipt",
        dangerous_unpaired_authorize_service_operation_v1(
            &mut disconnect_session,
            &disconnect_policy,
            fixture.scope_id,
            OFFER_ID,
            v2_full_operation(),
            disconnect_proof,
        ),
    )
    .await
    .expect("valid direct receipt must grant");
    assert!(
        initial_ready.exists(),
        "AUTH grant must not unlink ready file"
    );
    assert_locked_by_server(&initial_ready);
    within(
        "disconnect before V2Full dispatch",
        disconnect_session.close(),
    )
    .await
    .unwrap();
    wait_until_unlocked(&mut server, &initial_ready);

    // A second valid receipt can reserve the returned capacity. Its first
    // V2Full dispatch must unlink the exact ready name before the PRP preamble
    // is observable.
    let dispatch_receipt = fixture.receipt(0x33);
    let (mut dispatch_session, dispatch_policy) = within(
        "open dispatch session",
        open_verified_session(port, &fixture, manifest_root),
    )
    .await;
    let dispatch_proof = dangerous_unpaired_build_authorization_proof_v1(
        &dispatch_policy,
        &fixture.scope_id,
        OFFER_ID,
        &dispatch_receipt.encode().unwrap(),
    )
    .unwrap();
    within(
        "grant dispatch receipt",
        dangerous_unpaired_authorize_service_operation_v1(
            &mut dispatch_session,
            &dispatch_policy,
            fixture.scope_id,
            OFFER_ID,
            v2_full_operation(),
            dispatch_proof,
        ),
    )
    .await
    .expect("second valid receipt must grant");
    assert!(initial_ready.exists());
    assert_locked_by_server(&initial_ready);
    let expected_prp = ready_file_prp_key(&initial_ready);
    within(
        "send first V2Full frame",
        dispatch_session.send(v2_full_request()),
    )
    .await
    .unwrap();
    let preamble = within("receive V2Full PRP preamble", dispatch_session.recv())
        .await
        .unwrap();
    assert_eq!(parse_v2_full_preamble(&preamble), expected_prp);
    assert!(
        !initial_ready.exists(),
        "the ready name matching the exposed PRP must already be consumed"
    );
    let _ = within("close dispatched session", dispatch_session.close()).await;

    let replenished_ready =
        wait_for_ready_file(&mut server, &pool_dir, Some(initial_ready.as_path()));
    assert_ne!(replenished_ready, initial_ready);
    assert_private_single_link_file(&replenished_ready);
    assert_eq!(fs::read(&marker_path).unwrap(), marker_before);

    let (stdout_first, stderr_first) = server.stop();
    assert_server_log(&stdout_first, &stderr_first, port);
    let mut server = ServerProcess::spawn(root.path(), &db_path, &pool_dir, &fixture, port, 1);
    let restarted_ready = wait_for_ready_file(&mut server, &pool_dir, None);
    assert_eq!(restarted_ready, replenished_ready);
    assert_eq!(fs::read(&marker_path).unwrap(), marker_before);

    // Hold a valid post-restart reservation, then replace its ready namespace
    // entry with a different locked inode. The commit identity check must emit
    // only a generic error response and never expose the reserved PRP.
    let failure_receipt = fixture.receipt(0x44);
    let (mut failure_session, failure_policy) = within(
        "open commit-failure session",
        open_verified_session(port, &fixture, manifest_root),
    )
    .await;
    let failure_proof = dangerous_unpaired_build_authorization_proof_v1(
        &failure_policy,
        &fixture.scope_id,
        OFFER_ID,
        &failure_receipt.encode().unwrap(),
    )
    .unwrap();
    within(
        "grant commit-failure receipt",
        dangerous_unpaired_authorize_service_operation_v1(
            &mut failure_session,
            &failure_policy,
            fixture.scope_id,
            OFFER_ID,
            v2_full_operation(),
            failure_proof,
        ),
    )
    .await
    .expect("post-restart receipt must grant");
    assert_locked_by_server(&restarted_ready);
    let reserved_prp = ready_file_prp_key(&restarted_ready);
    fs::remove_file(&restarted_ready).expect("unlink reserved ready name externally");
    let replacement = create_locked_replacement(&restarted_ready);
    within(
        "send V2Full frame after inode replacement",
        failure_session.send(v2_full_request()),
    )
    .await
    .unwrap();
    let failure_frame = within(
        "receive fail-closed dispatch response",
        failure_session.recv(),
    )
    .await
    .unwrap();
    expect_full_frame_error(
        &failure_frame,
        "authorized V2Full hint became unavailable before dispatch",
    );
    assert!(
        !failure_frame
            .windows(reserved_prp.len())
            .any(|window| window == reserved_prp),
        "commit failure response must not contain the reserved PRP key"
    );
    drop(replacement);
    drop(failure_session);

    let (stdout_restart, stderr_restart) = server.stop();
    assert_server_log(&stdout_restart, &stderr_restart, port);
    assert!(
        stdout_restart.contains("[hint-pool] Loaded 1 entries from disk, target pool size 1"),
        "restart did not load the remaining durable ready entry\n{stdout_restart}"
    );
}

#[cfg(feature = "standard-cashu-process-e2e")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_non_receipt_methods_restore_pre_dispatch_and_burn_on_real_hint_dispatch() {
    let root = tempfile::tempdir().expect("test root");
    chmod(root.path(), 0o700);
    let mint = TestCashuMint::spawn(root.path());
    let (db_path, manifest_root) = write_merkle_database(root.path());
    let pool_dir = root.path().join("harmony-matrix-pool");
    fs::create_dir(&pool_dir).unwrap();
    chmod(&pool_dir, 0o700);
    let fixture = build_provider(root.path(), manifest_root, unix_now(), Some(&mint));
    let port = unused_loopback_port();
    let mut server = ServerProcess::spawn(root.path(), &db_path, &pool_dir, &fixture, port, 0);
    let marker_path = pool_dir.join(BINDING_MARKER);
    wait_for_path(
        &mut server,
        &marker_path,
        "durable matrix pool binding marker",
    );
    let matrix = fixture.method_matrix.as_ref().unwrap();
    wait_for_ready_pool_size(&mut server, &pool_dir, 2);

    for method in MatrixMethod::ALL {
        let method_fixture = matrix.method(method);
        assert_eq!(method_fixture.proof_count(), 2);

        // AUTH reserves pool capacity. A disconnect before the first hint
        // dispatch returns that exact inode, while the method-specific
        // capability itself remains durably consumed.
        let (mut disconnect, accepted) = within(
            "open matrix pre-dispatch session",
            open_verified_session(port, &fixture, manifest_root),
        )
        .await;
        let scope = accepted
            .policy()
            .scopes
            .iter()
            .find(|entry| entry.scope.scope_id() == fixture.scope_id)
            .unwrap();
        assert_eq!(scope.scope.backend, BackendId::HarmonyPirV2);
        assert_eq!(scope.scope.workload, WorkloadId::HarmonyHintBundleV1);
        let proof0 = dangerous_unpaired_build_authorization_proof_v1(
            &accepted,
            &fixture.scope_id,
            method_fixture.offer_id(),
            method_fixture.proof(0),
        )
        .unwrap();
        let attempts_before_wrong_scope = mint.attempt_count();
        let wrong = raw_authorization_request(
            &accepted,
            fixture.scope_id,
            method_fixture.offer_id(),
            OperationStartV1::DpfQuery { db_id: 0 },
            proof0.clone(),
        );
        let response = within(
            "reject wrong matrix hint operation",
            disconnect.roundtrip(&wrong),
        )
        .await
        .unwrap();
        let error = dangerous_unpaired_accept_service_authorization_response_v1(
            &response,
            &accepted,
            fixture.scope_id,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("wrong-scope"),
            "{method:?}: {error}"
        );
        assert_eq!(mint.attempt_count(), attempts_before_wrong_scope);
        within(
            "grant matrix pre-dispatch capability",
            dangerous_unpaired_authorize_service_operation_v1(
                &mut disconnect,
                &accepted,
                fixture.scope_id,
                method_fixture.offer_id(),
                v2_full_operation(),
                proof0,
            ),
        )
        .await
        .unwrap_or_else(|error| panic!("{method:?} pre-dispatch auth failed: {error}"));
        let reserved_ready = wait_for_locked_ready(&mut server, &pool_dir);
        let ready_metadata = fs::metadata(&reserved_ready).unwrap();
        within("disconnect matrix reservation", disconnect.close())
            .await
            .unwrap();
        wait_until_unlocked(&mut server, &reserved_ready);
        let restored_metadata = fs::metadata(&reserved_ready).unwrap();
        assert_eq!(ready_metadata.dev(), restored_metadata.dev());
        assert_eq!(ready_metadata.ino(), restored_metadata.ino());

        // A second independent capability reaches the real V2Full handler.
        // First dispatch unlinks its exact ready name before exposing the PRP.
        let (mut dispatch, accepted) = within(
            "open matrix dispatch session",
            open_verified_session(port, &fixture, manifest_root),
        )
        .await;
        let proof1 = dangerous_unpaired_build_authorization_proof_v1(
            &accepted,
            &fixture.scope_id,
            method_fixture.offer_id(),
            method_fixture.proof(1),
        )
        .unwrap();
        within(
            "grant matrix dispatch capability",
            dangerous_unpaired_authorize_service_operation_v1(
                &mut dispatch,
                &accepted,
                fixture.scope_id,
                method_fixture.offer_id(),
                v2_full_operation(),
                proof1,
            ),
        )
        .await
        .unwrap_or_else(|error| panic!("{method:?} dispatch auth failed: {error}"));
        let dispatched_ready = wait_for_locked_ready(&mut server, &pool_dir);
        let expected_prp = ready_file_prp_key(&dispatched_ready);
        within(
            "send matrix V2Full dispatch",
            dispatch.send(v2_full_request()),
        )
        .await
        .unwrap();
        let preamble = within("receive matrix V2Full preamble", dispatch.recv())
            .await
            .unwrap();
        assert_eq!(parse_v2_full_preamble(&preamble), expected_prp);
        assert!(
            !dispatched_ready.exists(),
            "{method:?} dispatch did not burn ready name"
        );
        let _ = within("close matrix dispatch", dispatch.close()).await;
        wait_for_ready_pool_size(&mut server, &pool_dir, 2);
    }
    assert_eq!(
        mint.attempt_count(),
        2,
        "two Cashu capabilities reach the mint"
    );

    let (stdout_first, stderr_first) = server.stop();
    assert_server_log(&stdout_first, &stderr_first, port);
    let mut server = ServerProcess::spawn(root.path(), &db_path, &pool_dir, &fixture, port, 1);
    let restarted_ready = wait_for_ready_pool_size(&mut server, &pool_dir, 2)
        .into_iter()
        .next()
        .unwrap();
    for method in MatrixMethod::ALL {
        let method_fixture = matrix.method(method);
        for proof_index in 0..method_fixture.proof_count() {
            let (mut replay, accepted) = within(
                "open matrix replay session",
                open_verified_session(port, &fixture, manifest_root),
            )
            .await;
            let proof = dangerous_unpaired_build_authorization_proof_v1(
                &accepted,
                &fixture.scope_id,
                method_fixture.offer_id(),
                method_fixture.proof(proof_index),
            )
            .unwrap();
            let error = within(
                "reject matrix replay",
                dangerous_unpaired_authorize_service_operation_v1(
                    &mut replay,
                    &accepted,
                    fixture.scope_id,
                    method_fixture.offer_id(),
                    v2_full_operation(),
                    proof,
                ),
            )
            .await
            .expect_err("matrix capability replay must stay terminal after restart");
            assert!(
                error.to_string().contains(method.replay_rejection()),
                "{method:?}/{proof_index}: {error}"
            );
            replay.close().await.unwrap();
        }
    }
    assert_eq!(mint.attempt_count(), 2, "Cashu replay reached the mint");
    assert!(restarted_ready.exists());
    wait_until_unlocked(&mut server, &restarted_ready);
    let (stdout, stderr) = server.stop();
    assert_server_log(&stdout, &stderr, port);
}

async fn within<T>(label: &str, future: impl Future<Output = T>) -> T {
    tokio::time::timeout(IO_TIMEOUT, future)
        .await
        .unwrap_or_else(|_| panic!("timed out while {label}"))
}

fn v2_full_operation() -> OperationStartV1 {
    OperationStartV1::HarmonyHint {
        db_id: 0,
        transport: HintTransport::V2Full,
        session_token: None,
        primary_side: None,
    }
}

fn v2_full_request() -> Vec<u8> {
    Request::HarmonyHintsV2(HarmonyHintRequestV2 { db_id: 0 }).encode()
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
) -> (
    SecureChannelTransport<WsConnection>,
    AcceptedServicePolicyV1,
) {
    let url = format!("ws://127.0.0.1:{port}");
    let mut raw = WsConnection::connect_once(&url)
        .await
        .expect("connect loopback WebSocket");
    let request = v2_full_request();

    let local_reject = fetch_verified_service_policy_v1(
        &mut raw,
        fixture.provider_id,
        &fixture.policy_signing_key.verifying_key(),
        unix_now(),
        &ServicePolicyCheckpointV1::initial(),
    )
    .await
    .expect_err("policy fetch before secure channel must fail");
    assert!(local_reject.to_string().contains("secure-channel"));
    expect_payload_error(
        &raw.roundtrip(&request).await.unwrap(),
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
    expect_payload_error(
        &secure.roundtrip(&request).await.unwrap(),
        "authorization required",
    );
    (secure, accepted)
}

fn build_provider(
    root: &Path,
    manifest_root: [u8; 32],
    now: u64,
    matrix_mint: Option<&TestCashuMint>,
) -> ProviderFixture {
    let provider_root = root.join("provider");
    let store_dir = provider_root.join("store-domain");
    fs::create_dir_all(&store_dir).unwrap();
    chmod(&provider_root, 0o700);
    chmod(&store_dir, 0o700);

    let operator_key = SigningKey::from_bytes(&[0x10; 32]);
    let policy_signing_key = SigningKey::from_bytes(&[0x20; 32]);
    let issuer_root_key = SigningKey::from_bytes(&[0x30; 32]);
    let receipt_signing_key = SigningKey::from_bytes(&[0x40; 32]);
    let provider_id = derive_provider_id(
        &operator_key.verifying_key().to_bytes(),
        "harmony-pool-process-provider",
    );
    let issued_at = now.saturating_sub(60);
    let expires_at = now.checked_add(3_600).unwrap();
    let receipt_not_after = now.checked_add(1_200).unwrap();
    let scope = ServiceScopeV1 {
        provider_id,
        backend: BackendId::HarmonyPirV2,
        workload: WorkloadId::HarmonyHintBundleV1,
        protocol_version: 2,
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
        endpoint: "https://issuer.fixture.invalid".to_owned(),
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
            2,
            0x61,
            mint,
        )
    });
    let mut offers = vec![offer];
    if let Some(matrix) = &method_matrix {
        offers.extend(matrix.offers().iter().cloned());
    }
    let total_groups = u16::try_from(INDEX_PARAMS.k + CHUNK_PARAMS.k).unwrap();
    let policy = ServicePolicyV1::sign(
        provider_id,
        1,
        issued_at,
        expires_at,
        AuthPaddingClassV1::Class16KiB,
        vec![ServiceScopePolicyV1 {
            scope,
            limits: EntitlementLimitsV1 {
                max_logical_inputs: 0,
                max_frames: 1,
                max_request_bytes: 1_024,
                max_response_bytes: 64 * 1024 * 1024,
                max_wall_time_ms: 30_000,
                max_concurrent_sockets: 1,
                max_hint_groups: total_groups,
                max_work_units: u64::from(total_groups),
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
    let store = ProviderStore::create(
        &store_path,
        [0x50; 16],
        provider_id,
        StoreOptions {
            busy_timeout: Duration::from_secs(1),
        },
    )
    .unwrap();
    drop(store);
    chmod(&store_path, 0o600);

    ProviderFixture {
        provider_id,
        policy_signing_key,
        receipt_signing_key,
        issuer_id: binding.issuer_id,
        policy_path,
        store_path,
        scope_id,
        policy_digest,
        issued_at,
        receipt_not_after,
        method_matrix,
    }
}

fn install_two_database_free_pow_policy(
    fixture: &mut ProviderFixture,
    manifest_roots: [[u8; 32]; 2],
    now: u64,
) {
    let total_groups = u16::try_from(INDEX_PARAMS.k + CHUNK_PARAMS.k).unwrap();
    let scopes = manifest_roots
        .into_iter()
        .enumerate()
        .map(|(db_id, root)| ServiceScopePolicyV1 {
            scope: ServiceScopeV1 {
                provider_id: fixture.provider_id,
                backend: BackendId::HarmonyPirV2,
                workload: WorkloadId::HarmonyHintBundleV1,
                protocol_version: 2,
                dataset: DatasetBindingV1::ManifestRoot { root },
                operation_profile: OPERATION_PROFILE,
                entitlement_profile: ENTITLEMENT_PROFILE,
            },
            limits: EntitlementLimitsV1 {
                max_logical_inputs: 0,
                max_frames: 1,
                max_request_bytes: 1_024,
                max_response_bytes: 64 * 1024 * 1024,
                max_wall_time_ms: 30_000,
                max_concurrent_sockets: 1,
                max_hint_groups: total_groups,
                max_work_units: u64::from(total_groups),
            },
            offers: vec![ServiceOfferV1 {
                offer_id: 70 + u32::try_from(db_id).unwrap(),
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
                minimum_credential_validity_seconds: 60,
                retired_policy_grace_seconds: 0,
                credential_count: 1,
                credential_presentation_limit: 1,
                privacy_leakage: PrivacyLeakageV1::NONE,
            }],
        })
        .collect();
    let policy = ServicePolicyV1::sign(
        fixture.provider_id,
        1,
        now.saturating_sub(60),
        now.checked_add(3_600).unwrap(),
        AuthPaddingClassV1::Class16KiB,
        scopes,
        &fixture.policy_signing_key,
    )
    .unwrap();
    fixture.policy_digest = policy.policy_digest().unwrap();
    fs::write(&fixture.policy_path, policy.encode().unwrap()).unwrap();
}

struct BucketMerkleArtifacts {
    super_root: [u8; 32],
    tree_tops: Vec<u8>,
    roots: Vec<u8>,
}

fn write_merkle_database(root: &Path) -> (PathBuf, [u8; 32]) {
    write_merkle_database_named(root, "tiny-merkle-db", 0)
}

fn write_merkle_database_named(
    root: &Path,
    name: &str,
    database_variant: u64,
) -> (PathBuf, [u8; 32]) {
    let db = root.join(name);
    fs::create_dir(&db).unwrap();
    let mut index = write_header_with_anchor(
        &INDEX_PARAMS.with_master_seed(0x1111_2222_3333_4444 ^ database_variant),
        TINY_BINS_PER_TABLE,
        0x9999_aaaa_bbbb_cccc ^ database_variant,
        None,
    );
    index.resize(
        index.len() + INDEX_PARAMS.k * INDEX_PARAMS.table_byte_size(TINY_BINS_PER_TABLE),
        0,
    );
    let mut chunk = write_header_with_anchor(
        &CHUNK_PARAMS.with_master_seed(0x5555_6666_7777_8888 ^ database_variant),
        TINY_BINS_PER_TABLE,
        database_variant,
        None,
    );
    chunk.resize(
        chunk.len() + CHUNK_PARAMS.k * CHUNK_PARAMS.table_byte_size(TINY_BINS_PER_TABLE),
        0,
    );
    let merkle = build_bucket_merkle_artifacts(&index, &chunk);
    let manifest = format!(
        "[manifest]\nversion = 1\ngenerated_at = \"2026-07-28T00:00:00Z\"\n\n[files]\n\"batch_pir_cuckoo.bin\" = \"{}\"\n\"chunk_pir_cuckoo.bin\" = \"{}\"\n\"merkle_bucket_root.bin\" = \"{}\"\n\"merkle_bucket_roots.bin\" = \"{}\"\n\"merkle_bucket_tree_tops.bin\" = \"{}\"\n",
        hex::encode(sha256(&index)),
        hex::encode(sha256(&chunk)),
        hex::encode(sha256(&merkle.super_root)),
        hex::encode(sha256(&merkle.roots)),
        hex::encode(sha256(&merkle.tree_tops)),
    );
    for (name, bytes) in [
        ("batch_pir_cuckoo.bin", index.as_slice()),
        ("chunk_pir_cuckoo.bin", chunk.as_slice()),
        ("merkle_bucket_root.bin", merkle.super_root.as_slice()),
        ("merkle_bucket_roots.bin", merkle.roots.as_slice()),
        ("merkle_bucket_tree_tops.bin", merkle.tree_tops.as_slice()),
        ("MANIFEST.toml", manifest.as_bytes()),
    ] {
        fs::write(db.join(name), bytes).unwrap();
    }
    (db, sha256(manifest.as_bytes()))
}

fn build_bucket_merkle_artifacts(index: &[u8], chunk: &[u8]) -> BucketMerkleArtifacts {
    let tree_count = INDEX_PARAMS.k + CHUNK_PARAMS.k;
    let mut tree_tops = Vec::new();
    tree_tops.extend_from_slice(&(tree_count as u32).to_le_bytes());
    let mut roots = Vec::with_capacity(tree_count * 32);
    append_bucket_merkle_table(index, &INDEX_PARAMS, &mut tree_tops, &mut roots);
    append_bucket_merkle_table(chunk, &CHUNK_PARAMS, &mut tree_tops, &mut roots);
    BucketMerkleArtifacts {
        super_root: sha256(&roots),
        tree_tops,
        roots,
    }
}

fn append_bucket_merkle_table(
    table: &[u8],
    params: &pir_core::params::TableParams,
    tree_tops: &mut Vec<u8>,
    roots: &mut Vec<u8>,
) {
    let header = pir_core::cuckoo::read_cuckoo_header_with_anchor(table, params).unwrap();
    let group_size = params.table_byte_size(header.bins_per_table);
    for group in 0..params.k {
        let start = header.header_size + group * group_size;
        let group_bytes = &table[start..start + group_size];
        let mut levels: Vec<Vec<Hash256>> = vec![(0..header.bins_per_table)
            .map(|bin_index| {
                let offset = bin_index * params.bin_size();
                compute_bin_leaf_hash(
                    bin_index as u32,
                    &group_bytes[offset..offset + params.bin_size()],
                )
            })
            .collect()];
        while levels.last().unwrap().len() > 1 {
            let previous = levels.last().unwrap();
            let mut next = Vec::with_capacity(previous.len().div_ceil(BUCKET_MERKLE_ARITY));
            for offset in (0..previous.len()).step_by(BUCKET_MERKLE_ARITY) {
                let mut children = [ZERO_HASH; BUCKET_MERKLE_ARITY];
                let available = (previous.len() - offset).min(BUCKET_MERKLE_ARITY);
                children[..available].copy_from_slice(&previous[offset..offset + available]);
                next.push(compute_parent_n(&children));
            }
            levels.push(next);
        }
        roots.extend_from_slice(&levels.last().unwrap()[0]);
        tree_tops.push(0);
        let total_nodes: usize = levels.iter().map(Vec::len).sum();
        tree_tops.extend_from_slice(&(total_nodes as u32).to_le_bytes());
        tree_tops.extend_from_slice(&(BUCKET_MERKLE_ARITY as u16).to_le_bytes());
        tree_tops.push(levels.len() as u8);
        for level in levels {
            tree_tops.extend_from_slice(&(level.len() as u32).to_le_bytes());
            for hash in level {
                tree_tops.extend_from_slice(&hash);
            }
        }
    }
}

fn wait_for_path(server: &mut ServerProcess, path: &Path, label: &str) {
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    while !path.exists() {
        server.assert_running(label);
        assert!(Instant::now() < deadline, "timed out waiting for {label}");
        thread::sleep(Duration::from_millis(25));
    }
}

fn wait_for_ready_file(
    server: &mut ServerProcess,
    pool_dir: &Path,
    excluded: Option<&Path>,
) -> PathBuf {
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    loop {
        server.assert_running("waiting for HarmonyPIR ready pool file");
        let mut ready = ready_files(pool_dir);
        if let Some(excluded) = excluded {
            ready.retain(|path| path != excluded);
        }
        if let Some(path) = ready
            .into_iter()
            .find(|path| ready_file_publish_is_complete(path))
        {
            // Publication drops the staging inode lock immediately after the
            // final link becomes single-link. Give the worker one scheduling
            // turn to enqueue that same entry before AUTH probes the pool.
            thread::sleep(Duration::from_millis(25));
            return path;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for HarmonyPIR ready pool file\nstdout:\n{}\nstderr:\n{}",
            read_log(&server.stdout_path),
            read_log(&server.stderr_path),
        );
        thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(feature = "standard-cashu-process-e2e")]
fn wait_for_ready_pool_size(
    server: &mut ServerProcess,
    pool_dir: &Path,
    minimum: usize,
) -> Vec<PathBuf> {
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    loop {
        server.assert_running("waiting for HarmonyPIR ready pool capacity");
        let ready: Vec<_> = ready_files(pool_dir)
            .into_iter()
            .filter(|path| ready_file_publish_is_complete(path))
            .collect();
        if ready.len() >= minimum {
            // Publication drops the staging inode lock immediately after the
            // final link becomes single-link. Give the worker one scheduling
            // turn to enqueue every observed entry before AUTH probes the pool.
            thread::sleep(Duration::from_millis(25));
            return ready;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {minimum} HarmonyPIR ready pool files\nstdout:\n{}\nstderr:\n{}",
            read_log(&server.stdout_path),
            read_log(&server.stderr_path),
        );
        thread::sleep(Duration::from_millis(25));
    }
}

fn ready_file_publish_is_complete(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.file_type().is_file()
            && metadata.permissions().mode() & 0o7777 == 0o600
            && metadata.nlink() == 1
    })
}

fn ready_files(pool_dir: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<_> = fs::read_dir(pool_dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_prefix("pool_"))
                .and_then(|name| name.strip_suffix(".hints"))
                .is_some_and(|encoded| {
                    encoded.len() == 32 && encoded.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
        })
        .collect();
    paths.sort();
    paths
}

fn wait_until_unlocked(server: &mut ServerProcess, path: &Path) {
    let deadline = Instant::now() + IO_TIMEOUT;
    loop {
        server.assert_running("waiting for reservation rollback");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        match file.try_lock() {
            Ok(()) => {
                file.unlock().unwrap();
                return;
            }
            Err(TryLockError::WouldBlock) => {}
            Err(TryLockError::Error(error)) => panic!("reservation lock probe failed: {error}"),
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for server reservation to release"
        );
        thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(feature = "standard-cashu-process-e2e")]
fn wait_for_locked_ready(server: &mut ServerProcess, pool_dir: &Path) -> PathBuf {
    let deadline = Instant::now() + IO_TIMEOUT;
    loop {
        server.assert_running("waiting for the reserved HarmonyPIR ready inode");
        for path in ready_files(pool_dir) {
            let Ok(file) = OpenOptions::new().read(true).write(true).open(&path) else {
                continue;
            };
            match file.try_lock() {
                Err(TryLockError::WouldBlock) => return path,
                Ok(()) => file.unlock().unwrap(),
                Err(TryLockError::Error(error)) => {
                    panic!("reservation lock probe failed: {error}")
                }
            }
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for the server-owned ready inode reservation"
        );
        thread::sleep(Duration::from_millis(25));
    }
}

fn assert_locked_by_server(path: &Path) {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    match file.try_lock() {
        Err(TryLockError::WouldBlock) => {}
        Ok(()) => {
            file.unlock().unwrap();
            panic!("server grant did not retain the ready inode reservation lock");
        }
        Err(TryLockError::Error(error)) => panic!("reservation lock probe failed: {error}"),
    }
}

fn create_locked_replacement(path: &Path) -> File {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("create private replacement ready inode");
    file.write_all(b"replacement-inode").unwrap();
    file.sync_all().unwrap();
    File::open(path.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
    file.try_lock()
        .expect("lock replacement against background cleanup");
    file
}

fn ready_file_prp_key(path: &Path) -> [u8; 16] {
    let name = path.file_name().unwrap().to_str().unwrap();
    let encoded = name
        .strip_prefix("pool_")
        .and_then(|name| name.strip_suffix(".hints"))
        .expect("canonical ready pool filename");
    let mut key = [0u8; 16];
    hex::decode_to_slice(encoded, &mut key).unwrap();
    key
}

fn parse_v2_full_preamble(frame: &[u8]) -> [u8; 16] {
    assert_eq!(
        u32::from_le_bytes(frame[..4].try_into().unwrap()) as usize,
        frame.len() - 4
    );
    assert_eq!(frame.len(), 24);
    assert_eq!(frame[4], RESP_HARMONY_HINTS_KEY);
    assert_eq!(frame[6], 0xff);
    assert_eq!(usize::from(frame[7]), INDEX_PARAMS.k + CHUNK_PARAMS.k);
    let mut key = [0u8; 16];
    key.copy_from_slice(&frame[8..24]);
    key
}

fn expect_payload_error(response: &[u8], needle: &str) {
    match Response::decode(response).unwrap() {
        Response::Error(message) => assert!(message.contains(needle), "{message}"),
        other => panic!("expected server error containing {needle:?}, got {other:?}"),
    }
}

fn expect_full_frame_error(frame: &[u8], needle: &str) {
    assert!(frame.len() >= 5);
    assert_eq!(
        u32::from_le_bytes(frame[..4].try_into().unwrap()) as usize,
        frame.len() - 4
    );
    expect_payload_error(&frame[4..], needle);
}

fn assert_private_single_link_file(path: &Path) {
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.file_type().is_file());
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
    assert_eq!(metadata.nlink(), 1);
}

fn assert_server_log(stdout: &str, stderr: &str, port: u16) {
    assert!(stdout.contains(&format!("Listening on ws://127.0.0.1:{port}")));
    assert!(stdout.contains("Service admission V1: enforced"));
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
