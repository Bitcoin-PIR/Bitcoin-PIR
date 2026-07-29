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
    circuit_meta_page_bytes, circuit_payload_page_bytes, AeadPageStore, CircuitOram,
    CircuitStoreAuthState, DirectChunkPackedBlockReader, DirectIndexPackedBlockReader, DirectLevel,
    DirectOramDatasetBindingV1, DirectTableInfo, DirectTableMetadata, FilePageStore, OramParams,
    PageStore, TieredMerklePageStore, TrustedBlockSource, AEAD_OVERHEAD, DIRECT_CHUNK_RECORD_SIZE,
    DIRECT_INDEX_INPUT_RECORD_SIZE,
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
const DIRECT_ORAM_PAGE_KEY: [u8; 32] = [0x77; 32];
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

#[derive(Clone, Copy)]
struct ServerSecurityMode {
    encrypted: bool,
    auth_store: bool,
    trusted_state: bool,
    no_save: bool,
    allow_trusted_state_outside_run_dev: bool,
}

impl Default for ServerSecurityMode {
    fn default() -> Self {
        Self {
            encrypted: true,
            auth_store: true,
            trusted_state: true,
            no_save: false,
            allow_trusted_state_outside_run_dev: true,
        }
    }
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
        let mut server = Self::spawn_unchecked(
            root,
            db_path,
            oram,
            fixture,
            port,
            generation,
            ServerSecurityMode::default(),
        );
        server.wait_until_listening(port);
        server
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_unchecked(
        root: &Path,
        db_path: &Path,
        oram: &DirectOramFixture,
        fixture: &ProviderFixture,
        port: u16,
        generation: u8,
        mode: ServerSecurityMode,
    ) -> Self {
        let stdout_path = root.join(format!("tee-oram-generation-{generation}-stdout.log"));
        let stderr_path = root.join(format!("tee-oram-generation-{generation}-stderr.log"));
        let stdout = File::create(&stdout_path).expect("create server stdout log");
        let stderr = File::create(&stderr_path).expect("create server stderr log");
        let direct_oram = format!("0={}", oram.image_dir.display());
        let trusted_state = format!("0={}", oram.trusted_state_dir.display());
        let page_key_hex = hex::encode(DIRECT_ORAM_PAGE_KEY);
        let mut args = vec![
            "--bind-address".to_owned(),
            "127.0.0.1".to_owned(),
            "--port".to_owned(),
            port.to_string(),
            "--data-dir".to_owned(),
            db_path.to_string_lossy().into_owned(),
            "--role".to_owned(),
            "secondary".to_owned(),
            "--disable-onion".to_owned(),
            "--serve-queries".to_owned(),
            "--direct-oram-db".to_owned(),
            direct_oram,
            "--direct-oram-drain-per-access".to_owned(),
            "2".to_owned(),
            "--direct-oram-access-budget".to_owned(),
            DIRECT_ORAM_ACCESS_BUDGET.to_string(),
        ];
        if mode.trusted_state {
            args.extend(["--direct-oram-trusted-state-db".to_owned(), trusted_state]);
        }
        if mode.encrypted {
            args.extend([
                "--direct-oram-encrypted".to_owned(),
                "--direct-oram-key-hex".to_owned(),
                page_key_hex,
            ]);
        }
        if mode.auth_store {
            args.push("--direct-oram-auth-store".to_owned());
        }
        if mode.no_save {
            args.push("--direct-oram-no-save".to_owned());
        }
        if mode.allow_trusted_state_outside_run_dev {
            args.push("--allow-direct-oram-trusted-state-outside-run-dev".to_owned());
        }
        args.extend([
            "--require-service-auth-v1".to_owned(),
            "--service-policy".to_owned(),
            fixture.policy_path.to_string_lossy().into_owned(),
            "--service-provider-id-hex".to_owned(),
            hex::encode(fixture.provider_id),
            "--service-policy-key-hex".to_owned(),
            hex::encode(fixture.policy_signing_key.verifying_key().to_bytes()),
            "--service-store".to_owned(),
            fixture.store_path.to_string_lossy().into_owned(),
            "--service-rollback-authority".to_owned(),
            fixture.rollback_path.to_string_lossy().into_owned(),
            "--allow-local-service-rollback-authority-dev".to_owned(),
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
        ]);
        let child = Command::new(env!("CARGO_BIN_EXE_unified_server"))
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("spawn ORAM-enabled unified_server");
        Self {
            child,
            stdout_path,
            stderr_path,
        }
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

    fn assert_startup_rejected(mut self, port: u16, needle: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().expect("poll rejected server") {
                let stdout = read_log(&self.stdout_path);
                let stderr = read_log(&self.stderr_path);
                assert!(
                    !status.success(),
                    "unsafe server unexpectedly exited successfully"
                );
                assert!(
                    stdout.contains(needle) || stderr.contains(needle),
                    "startup rejection did not contain {needle:?}\nstdout:\n{stdout}\nstderr:\n{stderr}"
                );
                return;
            }
            assert!(
                TcpStream::connect_timeout(
                    &format!("127.0.0.1:{port}").parse().unwrap(),
                    Duration::from_millis(50),
                )
                .is_err(),
                "unsafe server reached its listener before rejection"
            );
            assert!(
                Instant::now() < deadline,
                "unsafe server did not reject startup"
            );
            thread::sleep(Duration::from_millis(25));
        }
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
    let (db_path, manifest_root, oram) = build_direct_oram_fixture(root.path());
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

#[test]
fn production_direct_oram_startup_rejects_unbound_or_unsafe_configurations() {
    let root = tempfile::tempdir().expect("test root");
    chmod(root.path(), 0o700);
    let (db_path, manifest_root, oram) = build_direct_oram_fixture(root.path());
    let provider = build_provider(root.path(), manifest_root, unix_now());
    let reject = |generation: u8, mode: ServerSecurityMode, needle: &str| {
        let port = unused_loopback_port();
        ServerProcess::spawn_unchecked(
            root.path(),
            &db_path,
            &oram,
            &provider,
            port,
            generation,
            mode,
        )
        .assert_startup_rejected(port, needle);
    };

    reject(
        10,
        ServerSecurityMode {
            auth_store: false,
            ..ServerSecurityMode::default()
        },
        "requires --direct-oram-auth-store",
    );
    reject(
        11,
        ServerSecurityMode {
            encrypted: false,
            ..ServerSecurityMode::default()
        },
        "requires --direct-oram-encrypted",
    );
    reject(
        12,
        ServerSecurityMode {
            trusted_state: false,
            ..ServerSecurityMode::default()
        },
        "requires a separate --direct-oram-trusted-state-db",
    );
    reject(
        13,
        ServerSecurityMode {
            no_save: true,
            ..ServerSecurityMode::default()
        },
        "rejects --direct-oram-no-save",
    );
    reject(
        19,
        ServerSecurityMode {
            allow_trusted_state_outside_run_dev: false,
            ..ServerSecurityMode::default()
        },
        "requires trusted state under measured /run/bitcoinpir-oram-state",
    );

    let index_metadata_path = oram.trusted_state_dir.join("direct-index.metadata");
    let chunk_metadata_path = oram.trusted_state_dir.join("direct-chunk.metadata");
    let original_index_metadata = fs::read(&index_metadata_path).unwrap();
    let original_chunk_metadata = fs::read(&chunk_metadata_path).unwrap();
    let mut tampered = DirectTableMetadata::load(&index_metadata_path).unwrap();
    let mut binding = *tampered.require_dataset_binding().unwrap();
    binding.index_sha256[0] ^= 0x80;
    tampered.dataset_binding = Some(binding);
    tampered.save(&index_metadata_path).unwrap();
    reject(
        14,
        ServerSecurityMode::default(),
        "different dataset bindings",
    );
    fs::write(&index_metadata_path, &original_index_metadata).unwrap();

    fs::write(&chunk_metadata_path, &original_index_metadata).unwrap();
    reject(15, ServerSecurityMode::default(), "has level index");
    fs::write(&chunk_metadata_path, &original_chunk_metadata).unwrap();

    let mut legacy = DirectTableMetadata::load(&index_metadata_path).unwrap();
    legacy.version = 1;
    legacy.dataset_binding = None;
    legacy.save(&index_metadata_path).unwrap();
    reject(16, ServerSecurityMode::default(), "legacy");
    fs::write(&index_metadata_path, &original_index_metadata).unwrap();

    let manifest_path = db_path.join("MANIFEST.toml");
    let original_manifest = fs::read(&manifest_path).unwrap();
    let manifest_text = std::str::from_utf8(&original_manifest).unwrap();
    let tampered_manifest = manifest_text.replacen(
        &hex::encode(sha256(
            &fs::read(
                root.path()
                    .join("direct-oram-source/utxo_chunks_index_nodust.bin"),
            )
            .unwrap(),
        )),
        &"9".repeat(64),
        1,
    );
    fs::write(&manifest_path, tampered_manifest).unwrap();
    reject(
        17,
        ServerSecurityMode::default(),
        "does not match verified DB manifest",
    );
    fs::write(&manifest_path, &original_manifest).unwrap();

    fs::remove_file(&manifest_path).unwrap();
    reject(
        18,
        ServerSecurityMode::default(),
        "requires an exact verified server DB manifest root",
    );
    fs::write(&manifest_path, &original_manifest).unwrap();
}

#[test]
fn measured_boot_copies_exact_manifest_and_sources_before_strict_build() {
    let script = include_str!("../../../scripts/dracut/97bpir-tier3-init/unified-server-run.sh");
    assert!(script.contains("server-db/MANIFEST.toml missing"));
    assert!(script.contains("$trusted_input_dir/server-db-MANIFEST.toml"));
    assert_eq!(
        script
            .matches("--server-db-manifest \"$db_manifest\"")
            .count(),
        2
    );
    assert!(script.contains("trusted tmpfs index copy hash mismatch"));
    assert!(script.contains("trusted tmpfs chunks copy hash mismatch"));
    assert!(script.contains("--strict-source-binding"));
    assert!(script.contains("ORAM_PAGE_KEY_HEX=\"$(random_seed_hex)\""));
    assert!(script.contains("TRUSTED_STATE_ROOT=/run/bitcoinpir-oram-state"));
    assert!(!script.contains("--seed-hex"));
    assert!(!script.contains("set -x"));
    assert!(!script.contains("echo \"$ORAM_PAGE_KEY_HEX\""));
    assert_eq!(script.matches("--encrypted").count(), 2);
    assert!(script.contains("--direct-oram-encrypted"));
    assert!(script.contains("--direct-oram-auth-store"));
    assert!(!script.contains("--direct-oram-no-save"));
    assert!(!script.contains("--allow-direct-oram-trusted-state-outside-run-dev"));

    let copy = script
        .find("$trusted_input_dir/server-db-MANIFEST.toml")
        .unwrap();
    let trusted_rebind = script
        .find("db_manifest=\"$trusted_input_dir/server-db-MANIFEST.toml\"")
        .unwrap();
    let strict_build = script
        .find("--server-db-manifest \"$db_manifest\"")
        .unwrap();
    assert!(copy < trusted_rebind && trusted_rebind < strict_build);
}

#[test]
fn measured_builder_binds_direct_sources_before_evidence_and_quote() {
    let script =
        include_str!("../../../scripts/dracut/97bpir-builder-tier3-init/bpir-builder-run.sh");
    assert!(script.contains("export ROOTS_ONLY=0"));
    assert!(script.contains("export STAGE_SERVER_DB=1"));
    assert!(script.contains("export WRITE_BUILD_EVIDENCE=0"));
    assert!(script.contains("export EMIT_SEV_SNP_QUOTE=0"));
    assert!(script
        .contains("PIPELINE=/usr/local/lib/attested-builder/scripts/build-snapshot-database.sh"));
    assert!(script.contains("direct_oram_eligible=no"));
    assert!(script.contains(
        "direct_oram_blocker=requires-new-measured-snapshot-or-delta-build-with-typed-manifest-before-evidence"
    ));
    assert!(script.contains("direct_oram_blocker=attested-builder-full-build-v2-required"));
    assert!(script.contains("direct_oram_eligible=yes"));
    assert!(script.contains("augment_server_db_manifest_with_direct_oram"));
    assert!(script.contains("Direct ORAM INDEX source size must be a positive multiple of 25"));
    assert!(script.contains("Direct ORAM CHUNK source size must be a positive multiple of 40"));

    let pipeline = script.find("/bin/bash \"$PIPELINE\"").unwrap();
    let bind = script
        .rfind("augment_server_db_manifest_with_direct_oram \\")
        .unwrap();
    let evidence = script.rfind("\"$BIN\" write-build-evidence \\").unwrap();
    let report_data = script.rfind("\"$BIN\" write-tee-report-data \\").unwrap();
    let quote = script.rfind("\"$BIN\" emit-sev-snp-quote \\").unwrap();
    let version_gate = script
        .rfind("evidence_version=$(verified_evidence_field")
        .unwrap();
    let blocker = script
        .rfind("direct_oram_blocker=attested-builder-full-build-v2-required")
        .unwrap();
    let publish = script
        .rfind("ln -sfn \"$OUT_DIR\" \"$OUT_BASE/latest\"")
        .unwrap();
    let eligible = script.rfind("direct_oram_eligible=yes").unwrap();
    assert!(pipeline < bind && bind < evidence && evidence < report_data && report_data < quote);
    assert!(
        quote < version_gate && version_gate < blocker && blocker < publish && publish < eligible
    );
    assert!(script.contains("\"$evidence_version\" != 2"));
    assert!(script.contains("\"$evidence_mode\" != full_build"));
    assert!(script.contains("\"$predecessor_evidence\" != none"));
    assert!(script.contains("\"$predecessor_report\" != none"));
}

#[test]
fn production_manifest_generator_commits_exact_direct_sources_and_layout() {
    let root = tempfile::tempdir().unwrap();
    let db = root.path().join("db");
    fs::create_dir(&db).unwrap();
    fs::write(db.join("batch_pir_cuckoo.bin"), b"index-db").unwrap();
    fs::write(db.join("chunk_pir_cuckoo.bin"), b"chunk-db").unwrap();
    let index = root.path().join("utxo_chunks_index_nodust.bin");
    let chunks = root.path().join("utxo_chunks_nodust.bin");
    fs::write(&index, [0x11; 50]).unwrap();
    fs::write(&chunks, [0x22; 120]).unwrap();
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/build_db_manifest.sh");
    let status = Command::new("bash")
        .arg(&script)
        .arg(&db)
        .args([
            "--direct-oram-index",
            index.to_str().unwrap(),
            "--direct-oram-chunks",
            chunks.to_str().unwrap(),
            "--direct-index-slots-per-bin",
            "4",
            "--direct-index-hash-fns",
            "2",
            "--direct-index-load-factor-ppb",
            "950000000",
            "--direct-index-seed",
            "8030603977422561841",
        ])
        .status()
        .unwrap();
    assert!(status.success());
    let (manifest, _) = pir_runtime_core::manifest::DbManifest::load_and_verify(&db)
        .unwrap()
        .unwrap();
    let direct = manifest.direct_oram.unwrap().validate().unwrap();
    assert_eq!(direct.index_sha256, sha256(&[0x11; 50]));
    assert_eq!(direct.index_bytes, 50);
    assert_eq!(direct.index_records, 2);
    assert_eq!(direct.chunk_sha256, sha256(&[0x22; 120]));
    assert_eq!(direct.chunk_bytes, 120);
    assert_eq!(direct.chunk_records, 3);
    assert_eq!(direct.index_slots_per_bin, 4);
    assert_eq!(direct.index_hash_fns, 2);
    assert_eq!(direct.index_load_factor_ppb, 950_000_000);
    assert_eq!(direct.index_seed, 8_030_603_977_422_561_841);

    let partial = Command::new("bash")
        .arg(&script)
        .arg(&db)
        .args(["--direct-oram-index", index.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(
        !partial.success(),
        "partial direct binding arguments must fail"
    );
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

fn build_direct_oram_fixture(root: &Path) -> (PathBuf, [u8; 32], DirectOramFixture) {
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
    let index_sha256 = sha256(&index);
    fs::write(source_dir.join("utxo_chunks_index_nodust.bin"), &index).unwrap();

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
    let chunk_sha256 = sha256(&chunk_bytes);
    fs::write(source_dir.join("utxo_chunks_nodust.bin"), &chunk_bytes).unwrap();

    let (db_path, manifest_root) = write_tiny_manifest_database(
        root,
        index_sha256,
        index.len() as u64,
        2,
        chunk_sha256,
        chunk_bytes.len() as u64,
        chunks.len() as u64,
    );
    let binding = DirectOramDatasetBindingV1 {
        server_db_manifest_sha256: manifest_root,
        index_sha256,
        index_bytes: index.len() as u64,
        index_records: 2,
        chunk_sha256,
        chunk_bytes: chunk_bytes.len() as u64,
        chunk_records: chunks.len() as u64,
        index_slots_per_bin: 4,
        index_hash_fns: 2,
        index_load_factor_ppb: 200_000_000,
        index_seed: 0x6469_7265_6374_0001,
    };

    build_direct_oram_level(
        &source_dir,
        &image_dir,
        &trusted_state_dir,
        DirectLevel::Index,
        binding,
    );
    build_direct_oram_level(
        &source_dir,
        &image_dir,
        &trusted_state_dir,
        DirectLevel::Chunk,
        binding,
    );

    let mut expected_chunk_data = chunks[3].clone();
    expected_chunk_data.extend_from_slice(&chunks[4]);
    (
        db_path,
        manifest_root,
        DirectOramFixture {
            image_dir,
            trusted_state_dir,
            found_script_hash,
            expected_chunk_data,
        },
    )
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
    binding: DirectOramDatasetBindingV1,
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
            let metadata = source.metadata().clone().bind_dataset(binding).unwrap();
            build_direct_oram_from_source(image_dir, trusted_state_dir, level, metadata, source);
        }
        DirectLevel::Chunk => {
            let info = DirectTableInfo::from_chunks_file(source_dir.join("utxo_chunks_nodust.bin"))
                .unwrap();
            let source = DirectChunkPackedBlockReader::open(info, DIRECT_ORAM_PACK).unwrap();
            let metadata = source.metadata().clone().bind_dataset(binding).unwrap();
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
    let meta_plaintext_bytes = circuit_meta_page_bytes(params.bucket_size);
    let payload_plaintext_bytes = circuit_payload_page_bytes(params.bucket_size, params.block_size);
    let meta_file = FilePageStore::open(
        &paths.meta_image,
        params.bucket_count(),
        meta_plaintext_bytes + AEAD_OVERHEAD,
    )
    .unwrap();
    let payload_file = FilePageStore::open(
        &paths.payload_image,
        params.bucket_count(),
        payload_plaintext_bytes + AEAD_OVERHEAD,
    )
    .unwrap();
    let meta_store =
        AeadPageStore::new(meta_file, DIRECT_ORAM_PAGE_KEY, meta_plaintext_bytes).unwrap();
    let payload_store =
        AeadPageStore::new(payload_file, DIRECT_ORAM_PAGE_KEY, payload_plaintext_bytes).unwrap();
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
    let meta_plaintext_bytes = circuit_meta_page_bytes(params.bucket_size);
    let payload_plaintext_bytes = circuit_payload_page_bytes(params.bucket_size, params.block_size);
    let meta_file = FilePageStore::open(
        &paths.meta_image,
        params.bucket_count(),
        meta_plaintext_bytes + AEAD_OVERHEAD,
    )
    .unwrap();
    let payload_file = FilePageStore::open(
        &paths.payload_image,
        params.bucket_count(),
        payload_plaintext_bytes + AEAD_OVERHEAD,
    )
    .unwrap();
    let meta_store =
        AeadPageStore::new(meta_file, DIRECT_ORAM_PAGE_KEY, meta_plaintext_bytes).unwrap();
    let payload_store =
        AeadPageStore::new(payload_file, DIRECT_ORAM_PAGE_KEY, payload_plaintext_bytes).unwrap();
    let hash_pages = TieredMerklePageStore::<FilePageStore, FilePageStore>::required_hash_pages(
        params.bucket_count(),
        hash_page_size,
        trusted_levels,
    )
    .unwrap();
    let meta_hash_file = FilePageStore::open(
        &paths.meta_hash_image,
        hash_pages,
        hash_page_size + AEAD_OVERHEAD,
    )
    .unwrap();
    let payload_hash_file = FilePageStore::open(
        &paths.payload_hash_image,
        hash_pages,
        hash_page_size + AEAD_OVERHEAD,
    )
    .unwrap();
    let mut meta_hash_store =
        AeadPageStore::new(meta_hash_file, DIRECT_ORAM_PAGE_KEY, hash_page_size).unwrap();
    let mut payload_hash_store =
        AeadPageStore::new(payload_hash_file, DIRECT_ORAM_PAGE_KEY, hash_page_size).unwrap();
    let zero_hash_page = vec![0u8; hash_page_size];
    for page in 0..hash_pages {
        meta_hash_store.write_page(page, &zero_hash_page).unwrap();
        payload_hash_store
            .write_page(page, &zero_hash_page)
            .unwrap();
    }
    PageStore::flush(&mut meta_hash_store).unwrap();
    PageStore::flush(&mut payload_hash_store).unwrap();
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

#[allow(clippy::too_many_arguments)]
fn write_tiny_manifest_database(
    root: &Path,
    index_sha256: [u8; 32],
    index_bytes: u64,
    index_records: u64,
    chunk_sha256: [u8; 32],
    chunk_bytes: u64,
    chunk_records: u64,
) -> (PathBuf, [u8; 32]) {
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
        "[manifest]\nversion = 1\ngenerated_at = \"2026-07-29T00:00:00Z\"\n\n[direct_oram]\nversion = 1\nindex_sha256 = \"{}\"\nindex_bytes = {index_bytes}\nindex_records = {index_records}\nchunk_sha256 = \"{}\"\nchunk_bytes = {chunk_bytes}\nchunk_records = {chunk_records}\nindex_slots_per_bin = 4\nindex_hash_fns = 2\nindex_load_factor_ppb = 200000000\nindex_seed = 7235440056133222401\n\n[files]\n\"batch_pir_cuckoo.bin\" = \"{zero_hash}\"\n\"chunk_pir_cuckoo.bin\" = \"{zero_hash}\"\n",
        hex::encode(index_sha256),
        hex::encode(chunk_sha256),
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
