//! Deterministic Standard Cashu real-process coverage.
//!
//! This non-default test starts two independent `unified_server` processes and
//! a third OS process that serves a tiny HTTPS NUT-03 mint. The Cashu provider
//! reaches the mint through the production strict-HTTPS transport (normal
//! hostname/time/WebPKI validation plus a mandatory leaf-SPKI pin), while the
//! peer provider independently selects Free/OpenBestEffort. The client uses
//! attestation-bound secure channels, proof-bound bucket-Merkle preflight, a
//! real two-server DPF query, and explicit Merkle absence verification.
//!
//! The CA, provider keys, accepted input bearer and mint signing key are public
//! deterministic fixtures; provider output secrets still come from the real OS
//! randomness path. No Lightning node, public mint, relay, wallet, or funds are
//! involved. The private CA trust hook is feature-gated and `pir-strict-https`
//! rejects that feature in release builds.

#![cfg(all(unix, feature = "standard-cashu-process-e2e"))]

use ed25519_dalek::{SigningKey, VerifyingKey};
use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use pir_core::cuckoo::write_header_with_anchor;
use pir_core::merkle::{compute_bin_leaf_hash, compute_parent_n, sha256, Hash256, ZERO_HASH};
use pir_core::params::{CHUNK_PARAMS, INDEX_PARAMS};
use pir_db_attest::BuildKind;
use pir_sdk::{BufferingLeakageRecorder, RoundKind};
use pir_sdk_client::attest::{bound_nonce_for, SevStatus};
use pir_sdk_client::{
    AcceptedServicePolicyV1, DpfClient, PirClient, RootPolicy, ServicePolicyCheckpointV1,
    VerifiedDatabaseRoots,
};
use pir_service_protocol::{
    check_standard_cashu_spend_for_offer, derive_cashu_keyset_id_v2, derive_provider_id,
    AcquisitionMethod, AuthPaddingClassV1, AuthScheme, AuthorizationProofV1, BackendId,
    CashuDenominationKeyV1, CashuKeysetBindingV1, CashuRequiredNutsV1, DatasetBindingV1,
    DeploymentStatus, EntitlementLimitsV1, FreeAuthorizationProofV1, FreeModeV1,
    PolicyRollbackGuardV1, PriceV1, PrivacyLeakageV1, ServiceOfferV1, ServicePolicyEpochFloorsV1,
    ServicePolicyV1, ServiceScopePolicyV1, ServiceScopeV1, StandardCashuMintManifestV1,
    StandardCashuProofV1, StandardCashuSpendV1, VerificationMode, WorkloadId,
};
use pir_service_store::{ProviderStore, SqliteRollbackFloorAuthorityV1, StoreOptions};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CASHU_OFFER_ID: u32 = 41;
const FREE_OFFER_ID: u32 = 42;
const OPERATION_PROFILE: u16 = 31;
const ENTITLEMENT_PROFILE: u16 = 301;
const TINY_BINS_PER_TABLE: usize = 128;
const BUCKET_MERKLE_ARITY: usize = 8;
const CASHU_PRICE_SAT: u64 = 1;
const CASHU_UNIT: &str = "sat";
const CASHU_INPUT_SECRET: &str = "cashu-process-input-v1";
const MINT_SCALAR_OFFSET: u64 = 20;
const TEST_LEAF_SPKI_SHA256_HEX: &str =
    "e91550521f8e17b21d99f7e00b99c08be1b1f31fe57772ac8f904ea50c6a609b";
const MINT_HELPER_MARKER: &str = "BITCOINPIR_TEST_ONLY_CASHU_MINT_HELPER_V1";
const CDK_PROXY_HELPER_MARKER: &str = "BITCOINPIR_TEST_ONLY_CDK_TLS_PROXY_HELPER_V1";
const PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const TLS_IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HTTP_REQUEST_BYTES: usize = 64 * 1024;
const PREPARED_DATABASE_FILES: [&str; 6] = [
    "MANIFEST.toml",
    "batch_pir_cuckoo.bin",
    "chunk_pir_cuckoo.bin",
    "merkle_bucket_root.bin",
    "merkle_bucket_roots.bin",
    "merkle_bucket_tree_tops.bin",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProviderMethod {
    StandardCashu,
    FreeOpen,
}

#[derive(Debug)]
struct ProviderFixture {
    index: u8,
    method: ProviderMethod,
    provider_id: [u8; 32],
    policy_verifying_key: VerifyingKey,
    policy_path: PathBuf,
    store_path: PathBuf,
    rollback_path: PathBuf,
    recovery_key_path: Option<PathBuf>,
    custody_key_path: Option<PathBuf>,
    scope_id: [u8; 32],
    offer_id: u32,
    spend: Option<StandardCashuSpendV1>,
    mint_id: Option<[u8; 32]>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PreparedDatabaseFixtureV1 {
    database_path: PathBuf,
    manifest_root_hex: String,
    bucket_super_root_hex: String,
}

impl PreparedDatabaseFixtureV1 {
    fn manifest_root(&self) -> [u8; 32] {
        decode_exact_hex32("prepared manifest root", &self.manifest_root_hex)
    }

    fn bucket_super_root(&self) -> [u8; 32] {
        decode_exact_hex32("prepared bucket super-root", &self.bucket_super_root_hex)
    }
}

struct ChildProcess {
    label: String,
    child: Child,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

impl ChildProcess {
    fn wait_until_listening(&mut self, port: u16) {
        let deadline = Instant::now() + PROCESS_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().expect("poll child process") {
                panic!(
                    "{} exited before listening ({status})\nstdout:\n{}\nstderr:\n{}",
                    self.label,
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
                "timed out waiting for {}\nstdout:\n{}\nstderr:\n{}",
                self.label,
                read_log(&self.stdout_path),
                read_log(&self.stderr_path),
            );
            thread::sleep(Duration::from_millis(25));
        }
    }

    fn stop(mut self) -> (String, String) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        (read_log(&self.stdout_path), read_log(&self.stderr_path))
    }
}

impl Drop for ChildProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if thread::panicking() {
            eprintln!(
                "{} logs after test failure\nstdout:\n{}\nstderr:\n{}",
                self.label,
                read_log(&self.stdout_path),
                read_log(&self.stderr_path),
            );
        }
    }
}

#[test]
#[ignore = "spawned only by standard_cashu_real_process_tls_two_provider_e2e"]
fn standard_cashu_tls_mint_subprocess() {
    if env::var_os(MINT_HELPER_MARKER).is_none() {
        return;
    }
    let bind = required_env("BITCOINPIR_TEST_CASHU_MINT_BIND")
        .parse()
        .expect("mint helper bind address");
    let certificate = fs::read(required_env("BITCOINPIR_TEST_CASHU_MINT_CERT"))
        .expect("read test mint certificate");
    let private_key =
        fs::read(required_env("BITCOINPIR_TEST_CASHU_MINT_KEY")).expect("read test mint key");
    let state_path = PathBuf::from(required_env("BITCOINPIR_TEST_CASHU_MINT_STATE"));
    serve_cashu_mint(bind, &certificate, &private_key, &state_path)
        .expect("serve deterministic TLS Cashu mint");
}

#[test]
#[ignore = "spawned only by the pinned CDK runner"]
fn standard_cashu_cdk_tls_proxy_subprocess() {
    if env::var_os(CDK_PROXY_HELPER_MARKER).is_none() {
        return;
    }
    let bind = required_env("BITCOINPIR_TEST_CDK_PROXY_BIND")
        .parse()
        .expect("CDK TLS proxy bind address");
    let upstream = required_env("BITCOINPIR_TEST_CDK_PROXY_UPSTREAM")
        .parse()
        .expect("CDK TLS proxy upstream address");
    let certificate = fs::read(required_env("BITCOINPIR_TEST_CDK_PROXY_CERT"))
        .expect("read CDK TLS proxy certificate");
    let private_key = fs::read(required_env("BITCOINPIR_TEST_CDK_PROXY_KEY"))
        .expect("read CDK TLS proxy private key");
    let state_path = PathBuf::from(required_env("BITCOINPIR_TEST_CDK_PROXY_STATE"));
    serve_cdk_tls_proxy(bind, upstream, &certificate, &private_key, &state_path)
        .expect("serve test-only CDK TLS proxy");
}

#[test]
#[ignore = "spawned only by the pinned CDK runner"]
fn standard_cashu_prepare_real_cdk_database_fixture() {
    let fixture_root = PathBuf::from(required_env("BITCOINPIR_CDK_DATABASE_FIXTURE_ROOT"));
    let metadata_path = PathBuf::from(required_env("BITCOINPIR_CDK_DATABASE_FIXTURE_METADATA"));
    assert!(fixture_root.is_absolute());
    assert_eq!(metadata_path.parent(), Some(fixture_root.as_path()));
    let root_metadata = fs::symlink_metadata(&fixture_root).expect("inspect fixture root");
    assert!(root_metadata.file_type().is_dir());
    assert_eq!(root_metadata.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(root_metadata.mode() & 0o7777, 0o700);

    let (database_path, manifest_root, bucket_super_root) = write_merkle_database(&fixture_root);
    chmod(&database_path, 0o700);
    for name in PREPARED_DATABASE_FILES {
        chmod(&database_path.join(name), 0o600);
    }
    let metadata = PreparedDatabaseFixtureV1 {
        database_path,
        manifest_root_hex: hex::encode(manifest_root),
        bucket_super_root_hex: hex::encode(bucket_super_root),
    };
    write_private_file(
        &metadata_path,
        &serde_json::to_vec(&metadata).expect("encode prepared database metadata"),
    );
    assert_private_regular_file(&metadata_path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn standard_cashu_real_process_tls_two_provider_e2e() {
    let root = tempfile::tempdir().expect("test root");
    chmod(root.path(), 0o700);
    let (db_path, manifest_root, bucket_super_root) = write_merkle_database(root.path());
    let material = install_tls_material(root.path());
    let mint_port = unused_loopback_port();
    let mint_endpoint = format!("https://localhost:{mint_port}");
    let mint_state = root.path().join("mint-swap-attempts.log");
    let mint = spawn_mint_helper(root.path(), mint_port, &material, &mint_state);

    let now = unix_now();
    let provider0 = build_provider(
        root.path(),
        0,
        ProviderMethod::StandardCashu,
        manifest_root,
        &mint_endpoint,
        vec![test_leaf_spki_sha256()],
        now,
    );
    let provider1 = build_provider(
        root.path(),
        1,
        ProviderMethod::FreeOpen,
        manifest_root,
        "",
        Vec::new(),
        now,
    );
    assert_ne!(provider0.provider_id, provider1.provider_id);
    assert_ne!(provider0.store_path, provider1.store_path);
    assert_ne!(
        provider0.policy_verifying_key,
        provider1.policy_verifying_key
    );

    let port0 = distinct_unused_port(&[mint_port]);
    let port1 = distinct_unused_port(&[mint_port, port0]);
    let server0 = spawn_server(
        root.path(),
        &db_path,
        &provider0,
        port0,
        0,
        Some(&material.root),
    );
    let server1 = spawn_server(root.path(), &db_path, &provider1, port1, 0, None);

    let mut client = open_strict_dpf_pair(
        port0,
        port1,
        manifest_root,
        bucket_super_root,
        &provider0,
        &provider1,
        now,
    )
    .await;
    let accepted0 = client
        .fetch_service_policy_v1(
            0,
            0,
            provider0.provider_id,
            &provider0.policy_verifying_key,
            now,
            &ServicePolicyCheckpointV1::initial(),
        )
        .await
        .expect("fetch Cashu provider policy");
    let accepted1 = client
        .fetch_service_policy_v1(
            1,
            0,
            provider1.provider_id,
            &provider1.policy_verifying_key,
            now,
            &ServicePolicyCheckpointV1::initial(),
        )
        .await
        .expect("fetch independent Free provider policy");
    authorize_cashu(&mut client, 0, &provider0, &accepted0)
        .await
        .expect("Standard Cashu must authorize through real HTTPS NUT-03");
    client
        .dangerous_unpaired_authorize_service_v1(
            1,
            0,
            &accepted1,
            provider1.scope_id,
            provider1.offer_id,
            AuthorizationProofV1::Free(FreeAuthorizationProofV1::OpenBestEffort),
        )
        .await
        .expect("peer provider independently accepts Free/OpenBestEffort");

    client
        .preflight_verified_database(0)
        .await
        .expect("proof-bound bucket-Merkle tree-top preflight");
    let leakage = Arc::new(BufferingLeakageRecorder::new());
    client.set_leakage_recorder(Some(leakage.clone()));
    let mut results = client
        .query_batch_with_inspector(&[[0x39; 20], [0x3a; 20]], 0)
        .await
        .expect("one paid two-address DPF inspector batch");

    // Payment V1 grants one logical job per INDEX frame, not per address.
    // The N=2 inspector call must therefore use one packed PBC INDEX round
    // (one transcript entry per server).  The old sequential implementation
    // emitted two INDEX rounds and the second was rejected by the strict
    // max_logical_inputs=1 grant below.
    let raw_profile = leakage.take_profile("dpf");
    assert_eq!(raw_profile.count_of_kind(&RoundKind::Index), 2);
    assert_eq!(raw_profile.count_of_kind(&RoundKind::Chunk), 4);
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|result| result
        .as_ref()
        .is_some_and(|result| !result.merkle_verified)));
    assert_ne!(
        results[0].as_ref().unwrap().index_bins[0].pbc_group,
        results[1].as_ref().unwrap().index_bins[0].pbc_group,
        "fixed N=2 vectors must occupy independent PBC groups",
    );

    // Exercise one real standalone batch verifier call with a deliberately
    // bad first proof.  Per-query folding must preserve the independent
    // positive verdict for query 1; it must never promote either raw result's
    // embedded flag (the immutable return value remains quarantined).
    results[0]
        .as_mut()
        .and_then(|result| result.index_bins.first_mut())
        .and_then(|bin| bin.bin_content.first_mut())
        .map(|byte| *byte ^= 1)
        .expect("first inspector result has a Merkle-covered INDEX bin");
    let verdicts = client
        .verify_merkle_batch_for_results(&results, 0)
        .await
        .expect("single real bucket-Merkle batch verification");
    assert_eq!(verdicts, vec![false, true]);
    assert!(results
        .iter()
        .all(|result| result.as_ref().is_some_and(|result| {
            result.entries.is_empty()
                && result.matched_index_idx.is_none()
                && !result.merkle_verified
        })));
    client.disconnect().await.unwrap();

    let (stdout0_first, stderr0_first) = server0.stop();
    let (stdout1_first, stderr1_first) = server1.stop();
    assert_server_log(&stdout0_first, &stderr0_first, port0);
    assert_server_log(&stdout1_first, &stderr1_first, port1);
    assert_eq!(mint_swap_attempt_count(&mint_state), 1);
    assert_private_regular_file(&mint_state);

    // Reopen both processes against their original independent durable stores.
    // Provider 0 must reject the same bearer locally before a second NUT-03.
    let server0 = spawn_server(
        root.path(),
        &db_path,
        &provider0,
        port0,
        1,
        Some(&material.root),
    );
    let server1 = spawn_server(root.path(), &db_path, &provider1, port1, 1, None);
    let mut restarted = open_strict_dpf_pair(
        port0,
        port1,
        manifest_root,
        bucket_super_root,
        &provider0,
        &provider1,
        now + 1,
    )
    .await;
    let accepted0 = restarted
        .fetch_service_policy_v1(
            0,
            0,
            provider0.provider_id,
            &provider0.policy_verifying_key,
            now + 1,
            &ServicePolicyCheckpointV1::initial(),
        )
        .await
        .unwrap();
    let replay = authorize_cashu(&mut restarted, 0, &provider0, &accepted0)
        .await
        .unwrap_err();
    assert!(replay.to_string().contains("invalid-or-spent"), "{replay}");
    assert_eq!(mint_swap_attempt_count(&mint_state), 1);
    restarted.disconnect().await.unwrap();
    let (stdout0, stderr0) = server0.stop();
    let (stdout1, stderr1) = server1.stop();
    assert_server_log(&stdout0, &stderr0, port0);
    assert_server_log(&stdout1, &stderr1, port1);

    // TLS trust failures are exercised through fresh real provider processes.
    // None can grant, reach the DPF backend, or add a mint request attempt.
    exercise_tls_failure_matrix(
        root.path(),
        &db_path,
        manifest_root,
        &mint_endpoint,
        &material,
        mint_port,
        now,
    )
    .await;
    assert_eq!(mint_swap_attempt_count(&mint_state), 1);

    let (mint_stdout, mint_stderr) = mint.stop();
    for forbidden in ["cashu-process-input", "payment_hash", "preimage", "invoice"] {
        assert!(!mint_stdout.contains(forbidden));
        assert!(!mint_stderr.contains(forbidden));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires scripts/payment-v1-cdk-regtest-e2e.sh and disposable CDK 0.17.3"]
async fn standard_cashu_real_cdk_browser_provider_two_server_e2e() {
    let root = tempfile::tempdir().expect("real CDK provider test root");
    chmod(root.path(), 0o700);
    let database = load_prepared_database_fixture();
    let signed_mint_endpoint = required_env("BITCOINPIR_CDK_SIGNED_MINT_ENDPOINT");
    let proxy_port = parse_signed_localhost_endpoint(&signed_mint_endpoint);
    let actual_mint_endpoint = required_env("BITCOINPIR_CDK_MINT_ENDPOINT");
    let upstream = parse_actual_loopback_endpoint(&actual_mint_endpoint);
    let material = install_tls_material(root.path());
    let proxy_state = root.path().join("cdk-proxy-forwarded.log");
    let proxy = spawn_cdk_tls_proxy(root.path(), proxy_port, upstream, &material, &proxy_state);

    let now = unix_now();
    let provider0 = build_real_cdk_provider(root.path(), 0, database.manifest_root(), now);
    let provider1 = build_provider(
        root.path(),
        1,
        ProviderMethod::FreeOpen,
        database.manifest_root(),
        "",
        Vec::new(),
        now,
    );
    assert_ne!(provider0.provider_id, provider1.provider_id);
    assert_ne!(provider0.store_path, provider1.store_path);
    assert_ne!(
        provider0.policy_verifying_key,
        provider1.policy_verifying_key
    );

    let port0 = distinct_unused_port(&[proxy_port]);
    let port1 = distinct_unused_port(&[proxy_port, port0]);
    let server0 = spawn_server(
        root.path(),
        &database.database_path,
        &provider0,
        port0,
        0,
        Some(&material.root),
    );
    let server1 = spawn_server(
        root.path(),
        &database.database_path,
        &provider1,
        port1,
        0,
        None,
    );

    let mut client = open_strict_dpf_pair(
        port0,
        port1,
        database.manifest_root(),
        database.bucket_super_root(),
        &provider0,
        &provider1,
        now,
    )
    .await;
    let accepted0 = client
        .fetch_service_policy_v1(
            0,
            0,
            provider0.provider_id,
            &provider0.policy_verifying_key,
            now,
            &ServicePolicyCheckpointV1::initial(),
        )
        .await
        .expect("fetch browser-selected real-CDK provider policy");
    let accepted1 = client
        .fetch_service_policy_v1(
            1,
            0,
            provider1.provider_id,
            &provider1.policy_verifying_key,
            now,
            &ServicePolicyCheckpointV1::initial(),
        )
        .await
        .expect("fetch independent Free provider policy");
    authorize_cashu(&mut client, 0, &provider0, &accepted0)
        .await
        .expect("Chromium canonical spend must authorize at the real provider through CDK");
    client
        .dangerous_unpaired_authorize_service_v1(
            1,
            0,
            &accepted1,
            provider1.scope_id,
            provider1.offer_id,
            AuthorizationProofV1::Free(FreeAuthorizationProofV1::OpenBestEffort),
        )
        .await
        .expect("peer provider independently accepts Free/OpenBestEffort");
    assert_eq!(mint_swap_attempt_count(&proxy_state), 1);
    assert_private_regular_file(&proxy_state);

    client
        .preflight_verified_database(0)
        .await
        .expect("proof-bound bucket-Merkle tree-top preflight");
    let results = client
        .query_batch_with_inspector(&[[0x39; 20]], 0)
        .await
        .expect("real two-server DPF query after browser Cashu admission");
    let verdicts = client
        .verify_merkle_batch_for_results(&results, 0)
        .await
        .expect("real bucket-Merkle absence verification");
    assert_eq!(verdicts, vec![true]);
    assert!(results[0]
        .as_ref()
        .is_some_and(|result| result.entries.is_empty() && result.matched_index_idx.is_none()));
    client.disconnect().await.unwrap();

    let (stdout0_first, stderr0_first) = server0.stop();
    let (stdout1_first, stderr1_first) = server1.stop();
    assert_server_log(&stdout0_first, &stderr0_first, port0);
    assert_server_log(&stdout1_first, &stderr1_first, port1);

    let server0 = spawn_server(
        root.path(),
        &database.database_path,
        &provider0,
        port0,
        1,
        Some(&material.root),
    );
    let server1 = spawn_server(
        root.path(),
        &database.database_path,
        &provider1,
        port1,
        1,
        None,
    );
    let mut restarted = open_strict_dpf_pair(
        port0,
        port1,
        database.manifest_root(),
        database.bucket_super_root(),
        &provider0,
        &provider1,
        now + 1,
    )
    .await;
    let accepted0 = restarted
        .fetch_service_policy_v1(
            0,
            0,
            provider0.provider_id,
            &provider0.policy_verifying_key,
            now + 1,
            &ServicePolicyCheckpointV1::initial(),
        )
        .await
        .expect("fetch policy after provider restart");
    let replay = authorize_cashu(&mut restarted, 0, &provider0, &accepted0)
        .await
        .expect_err("provider-local replay must fail before a second CDK request");
    assert!(replay.to_string().contains("invalid-or-spent"), "{replay}");
    assert_eq!(
        mint_swap_attempt_count(&proxy_state),
        1,
        "provider-local replay rejection must not touch the CDK proxy"
    );
    restarted.disconnect().await.unwrap();
    let (stdout0_restart, stderr0_restart) = server0.stop();
    let (stdout1_restart, stderr1_restart) = server1.stop();
    assert_server_log(&stdout0_restart, &stderr0_restart, port0);
    assert_server_log(&stdout1_restart, &stderr1_restart, port1);

    let (proxy_stdout, proxy_stderr) = proxy.stop();
    let spend = provider0.spend.as_ref().expect("browser Cashu spend");
    assert_no_cashu_bearer_or_proof_log(
        spend,
        [
            stdout0_first.as_str(),
            stderr0_first.as_str(),
            stdout1_first.as_str(),
            stderr1_first.as_str(),
            stdout0_restart.as_str(),
            stderr0_restart.as_str(),
            stdout1_restart.as_str(),
            stderr1_restart.as_str(),
            proxy_stdout.as_str(),
            proxy_stderr.as_str(),
        ],
    );
}

async fn authorize_cashu(
    client: &mut DpfClient,
    server_index: u8,
    fixture: &ProviderFixture,
    accepted: &AcceptedServicePolicyV1,
) -> pir_sdk_client::PirResult<pir_service_protocol::AuthGrantedV1> {
    client
        .dangerous_unpaired_authorize_service_v1(
            server_index,
            0,
            accepted,
            fixture.scope_id,
            fixture.offer_id,
            AuthorizationProofV1::StandardCashu(
                fixture
                    .spend
                    .as_ref()
                    .expect("Cashu provider spend")
                    .clone(),
            ),
        )
        .await
}

async fn open_strict_dpf_pair(
    port0: u16,
    port1: u16,
    manifest_root: [u8; 32],
    bucket_super_root: [u8; 32],
    provider0: &ProviderFixture,
    provider1: &ProviderFixture,
    now: u64,
) -> DpfClient {
    let mut client = DpfClient::new(
        &format!("ws://127.0.0.1:{port0}"),
        &format!("ws://127.0.0.1:{port1}"),
    );
    client.connect().await.expect("connect real provider pair");

    let eph0 = deterministic_32(0x20, provider0.index, now);
    let random0 = deterministic_32(0x30, provider0.index, now);
    let eph1 = deterministic_32(0x40, provider1.index, now);
    let random1 = deterministic_32(0x50, provider1.index, now);
    let attest0 = client
        .attest(0, bound_nonce_for(eph0, random0))
        .await
        .expect("provider 0 bound runtime attestation");
    let attest1 = client
        .attest(1, bound_nonce_for(eph1, random1))
        .await
        .expect("provider 1 bound runtime attestation");
    for attestation in [&attest0, &attest1] {
        assert_eq!(attestation.sev_status, SevStatus::NoSevHost);
        assert_eq!(attestation.response.manifest_roots, vec![manifest_root]);
        assert!(attestation
            .response
            .server_static_pub
            .iter()
            .any(|byte| *byte != 0));
    }
    client
        .upgrade_to_secure_channel_with_seeds(
            attest0.response.server_static_pub,
            eph0,
            deterministic_32(0x60, provider0.index, now),
            attest1.response.server_static_pub,
            eph1,
            deterministic_32(0x70, provider1.index, now),
        )
        .await
        .expect("mandatory secure-channel upgrade for both providers");

    let catalog = client
        .fetch_catalog()
        .await
        .expect("fetch catalog inside secure channel");
    let db = catalog.get(0).expect("fixture db 0");
    assert_eq!(db.height, 0);
    assert!(db.has_bucket_merkle);
    client.set_root_policy(RootPolicy::RequireVerified);
    client
        .install_verified_database_roots(VerifiedDatabaseRoots {
            db_id: 0,
            manifest_root: [0; 32],
            build_kind: BuildKind::Snapshot,
            from_height: 0,
            from_block_hash: [0; 32],
            height: 0,
            block_hash: [0x81; 32],
            muhash: [0x82; 32],
            bucket_super_root,
            onion_super_root: [0x83; 32],
            onion_entry_size: 3_328,
            onion_layout_v2: None,
            params_hash: [0x84; 32],
            network_magic: [0xfa, 0xbf, 0xb5, 0xda],
            builder_binary_sha256: [0x85; 32],
            builder_git_commit: "standard-cashu-process-fixture".to_owned(),
        })
        .expect("install explicit proof-verified fixture roots");
    client
}

fn load_prepared_database_fixture() -> PreparedDatabaseFixtureV1 {
    let fixture_root = PathBuf::from(required_env("BITCOINPIR_CDK_DATABASE_FIXTURE_ROOT"));
    let metadata_path = PathBuf::from(required_env("BITCOINPIR_CDK_DATABASE_FIXTURE_METADATA"));
    assert!(fixture_root.is_absolute());
    assert_eq!(metadata_path.parent(), Some(fixture_root.as_path()));
    let root_metadata = fs::symlink_metadata(&fixture_root).expect("inspect prepared fixture root");
    assert!(root_metadata.file_type().is_dir());
    assert_eq!(root_metadata.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(root_metadata.mode() & 0o7777, 0o700);
    assert_private_regular_file(&metadata_path);
    let fixture: PreparedDatabaseFixtureV1 =
        serde_json::from_slice(&fs::read(&metadata_path).expect("read prepared database metadata"))
            .expect("decode prepared database metadata");
    assert!(fixture.database_path.is_absolute());
    assert_eq!(fixture.database_path.parent(), Some(fixture_root.as_path()));
    assert_eq!(
        fixture
            .database_path
            .file_name()
            .and_then(|name| name.to_str()),
        Some("tiny-merkle-db")
    );
    let database_metadata =
        fs::symlink_metadata(&fixture.database_path).expect("inspect prepared database directory");
    assert!(database_metadata.file_type().is_dir());
    assert_eq!(database_metadata.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(database_metadata.mode() & 0o7777, 0o700);

    let mut actual_files = fs::read_dir(&fixture.database_path)
        .expect("read prepared database directory")
        .map(|entry| {
            entry
                .expect("read prepared database entry")
                .file_name()
                .into_string()
                .expect("prepared database file names must be UTF-8")
        })
        .collect::<Vec<_>>();
    actual_files.sort();
    let mut expected_files = PREPARED_DATABASE_FILES.map(str::to_owned).to_vec();
    expected_files.sort();
    assert_eq!(actual_files, expected_files);
    for name in PREPARED_DATABASE_FILES {
        assert_private_regular_file(&fixture.database_path.join(name));
    }

    let manifest_path = fixture.database_path.join("MANIFEST.toml");
    let bucket_root_path = fixture.database_path.join("merkle_bucket_root.bin");
    assert_eq!(
        sha256(&fs::read(&manifest_path).expect("read prepared manifest")),
        fixture.manifest_root()
    );
    let bucket_root: [u8; 32] = fs::read(&bucket_root_path)
        .expect("read prepared bucket super-root")
        .try_into()
        .expect("prepared bucket super-root length");
    assert_eq!(bucket_root, fixture.bucket_super_root());
    fixture
}

fn build_real_cdk_provider(
    root: &Path,
    index: u8,
    manifest_root: [u8; 32],
    now: u64,
) -> ProviderFixture {
    let policy_path = PathBuf::from(required_env("BITCOINPIR_CDK_POLICY_FILE"));
    let spend_path = PathBuf::from(required_env("BITCOINPIR_CDK_BROWSER_SPEND_FILE"));
    assert_private_regular_file(&policy_path);
    assert_private_regular_file(&spend_path);
    let policy_bytes = fs::read(&policy_path).expect("read browser-selected provider policy");
    let policy = ServicePolicyV1::decode(&policy_bytes).expect("decode browser provider policy");
    assert_eq!(
        policy.encode().expect("re-encode browser provider policy"),
        policy_bytes,
        "browser provider policy must be canonical"
    );
    let provider_id = required_hex32_env("BITCOINPIR_CDK_PROVIDER_ID_HEX");
    let policy_key_bytes = required_hex32_env("BITCOINPIR_CDK_POLICY_SIGNING_PUBKEY_HEX");
    let policy_verifying_key =
        VerifyingKey::from_bytes(&policy_key_bytes).expect("valid provider policy Ed25519 key");
    assert_eq!(policy.provider_id, provider_id);
    let verified = policy
        .verify_current_for_acquisition(
            &provider_id,
            now,
            &PolicyRollbackGuardV1::initial(),
            &ServicePolicyEpochFloorsV1::initial(),
            &policy_verifying_key,
        )
        .expect("verify browser-selected provider policy");
    assert_eq!(policy.scopes.len(), 1);
    let scope_policy = &policy.scopes[0];
    assert_eq!(scope_policy.scope.provider_id, provider_id);
    assert_eq!(scope_policy.scope.backend, BackendId::DpfPirV1);
    assert_eq!(scope_policy.scope.workload, WorkloadId::DpfEvaluateJobV1);
    assert_eq!(scope_policy.scope.protocol_version, 1);
    assert_eq!(
        scope_policy.scope.dataset,
        DatasetBindingV1::ManifestRoot {
            root: manifest_root
        },
        "provider policy must bind the exact prepared database manifest root"
    );
    assert_eq!(scope_policy.offers.len(), 1);
    let offer_id = scope_policy.offers[0].offer_id;
    let scope_id = scope_policy.scope.scope_id();
    let verified_offer = verified
        .offer(&scope_id, offer_id)
        .expect("verified real-CDK offer");
    let offer = verified_offer.offer();
    assert_eq!(offer.acquisition, AcquisitionMethod::CashuEcashV1);
    assert_eq!(offer.authorization, AuthScheme::CashuEcashV1);
    assert_eq!(
        offer.verification,
        VerificationMode::StandardCashuMintOnline
    );
    let expected_amount = required_env("BITCOINPIR_CDK_EXPECTED_AMOUNT")
        .parse::<u64>()
        .expect("BITCOINPIR_CDK_EXPECTED_AMOUNT must be u64");
    assert_eq!(
        offer.price,
        PriceV1::Cashu {
            unit: CASHU_UNIT.to_owned(),
            amount: expected_amount,
        }
    );
    let signed_endpoint = required_env("BITCOINPIR_CDK_SIGNED_MINT_ENDPOINT");
    assert_eq!(offer.endpoint, signed_endpoint);
    let manifest = offer
        .cashu_mint_manifest
        .as_ref()
        .expect("real-CDK offer carries signed manifest");
    assert_eq!(manifest.mint_endpoint, signed_endpoint);
    assert_eq!(
        manifest.leaf_spki_sha256_pins,
        vec![test_leaf_spki_sha256()]
    );
    let spend_bytes = fs::read(&spend_path).expect("read Chromium canonical Cashu spend");
    let spend =
        StandardCashuSpendV1::decode(&spend_bytes).expect("decode Chromium canonical Cashu spend");
    assert_eq!(
        spend.encode().expect("re-encode Chromium Cashu spend"),
        spend_bytes,
        "Chromium spend must be exact canonical provider wire bytes"
    );
    assert_eq!(spend.total_amount().unwrap(), expected_amount);
    check_standard_cashu_spend_for_offer(&spend, &verified_offer, now)
        .expect("Chromium spend matches exact real provider offer");

    let provider_root = root.join(format!("provider-{index}"));
    let store_dir = provider_root.join("store-domain");
    let rollback_dir = provider_root.join("rollback-domain");
    fs::create_dir_all(&store_dir).unwrap();
    fs::create_dir_all(&rollback_dir).unwrap();
    chmod(&provider_root, 0o700);
    chmod(&store_dir, 0o700);
    chmod(&rollback_dir, 0o700);
    let recovery_key_path = provider_root.join("cashu-recovery.key");
    let custody_key_path = provider_root.join("cashu-custody.key");
    write_private_file(&recovery_key_path, &[0x91u8.wrapping_add(index); 32]);
    write_private_file(&custody_key_path, &[0xa1u8.wrapping_add(index); 32]);
    let store_path = store_dir.join("provider.sqlite3");
    let rollback_path = rollback_dir.join("floor.sqlite3");
    let rollback =
        SqliteRollbackFloorAuthorityV1::create(&rollback_path, Duration::from_secs(1)).unwrap();
    let store = ProviderStore::create(
        &store_path,
        [0xc1u8.wrapping_add(index); 16],
        provider_id,
        StoreOptions {
            busy_timeout: Duration::from_secs(1),
        },
        Arc::new(rollback),
    )
    .unwrap();
    drop(store);
    chmod(&store_path, 0o600);
    chmod(&rollback_path, 0o600);

    ProviderFixture {
        index,
        method: ProviderMethod::StandardCashu,
        provider_id,
        policy_verifying_key,
        policy_path,
        store_path,
        rollback_path,
        recovery_key_path: Some(recovery_key_path),
        custody_key_path: Some(custody_key_path),
        scope_id,
        offer_id,
        spend: Some(spend),
        mint_id: Some(manifest.mint_id()),
    }
}

fn build_provider(
    root: &Path,
    index: u8,
    method: ProviderMethod,
    manifest_root: [u8; 32],
    mint_endpoint: &str,
    mint_leaf_spki_sha256_pins: Vec<[u8; 32]>,
    now: u64,
) -> ProviderFixture {
    let provider_root = root.join(format!("provider-{index}"));
    let store_dir = provider_root.join("store-domain");
    let rollback_dir = provider_root.join("rollback-domain");
    fs::create_dir_all(&store_dir).unwrap();
    fs::create_dir_all(&rollback_dir).unwrap();
    chmod(&provider_root, 0o700);
    chmod(&store_dir, 0o700);
    chmod(&rollback_dir, 0o700);

    let operator_key = SigningKey::from_bytes(&[0x10u8.wrapping_add(index); 32]);
    let policy_signing_key = SigningKey::from_bytes(&[0x30u8.wrapping_add(index); 32]);
    let provider_id = derive_provider_id(
        &operator_key.verifying_key().to_bytes(),
        &format!("standard-cashu-process-provider-{index}"),
    );
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
    let (offer, spend, mint_id, recovery_key_path, custody_key_path) = match method {
        ProviderMethod::StandardCashu => {
            assert!(mint_endpoint.starts_with("https://localhost:"));
            assert!(!mint_leaf_spki_sha256_pins.is_empty());
            let keyset = deterministic_cashu_keyset(now + 86_400);
            let manifest = StandardCashuMintManifestV1 {
                manifest_epoch: 1,
                mint_endpoint: mint_endpoint.to_owned(),
                leaf_spki_sha256_pins: mint_leaf_spki_sha256_pins,
                unit: CASHU_UNIT.to_owned(),
                required_nuts: CashuRequiredNutsV1::required_v1(),
                accepted_input_keysets: vec![keyset.clone()],
                active_output_keyset: keyset.clone(),
            };
            let mint_id = manifest.mint_id();
            let spend = StandardCashuSpendV1::new_canonical(vec![StandardCashuProofV1 {
                keyset_id: keyset.keyset_id,
                amount: CASHU_PRICE_SAT,
                secret: CASHU_INPUT_SECRET.to_owned(),
                c: compressed_point(&(ProjectivePoint::GENERATOR * Scalar::from(51u64))),
            }])
            .unwrap();
            let offer = ServiceOfferV1 {
                offer_id: CASHU_OFFER_ID,
                acquisition: AcquisitionMethod::CashuEcashV1,
                free_mode: FreeModeV1::NotFree,
                free_quota: 0,
                free_window_seconds: 0,
                free_pow_difficulty_bits: 0,
                priority_class: 10,
                authorization: AuthScheme::CashuEcashV1,
                verification: VerificationMode::StandardCashuMintOnline,
                deployment_status: DeploymentStatus::Stable,
                price: PriceV1::Cashu {
                    unit: CASHU_UNIT.to_owned(),
                    amount: CASHU_PRICE_SAT,
                },
                issuer_id: mint_id,
                key_id: manifest.manifest_digest().unwrap().to_vec(),
                credential_binding: None,
                cashu_mint_manifest: Some(manifest),
                endpoint: mint_endpoint.to_owned(),
                invoice_expiry_seconds: 0,
                claim_window_seconds: 0,
                minimum_credential_validity_seconds: 600,
                retired_policy_grace_seconds: 600,
                credential_count: 1,
                credential_presentation_limit: 1,
                privacy_leakage: PrivacyLeakageV1::from_bits(
                    PrivacyLeakageV1::ISSUER_REDEMPTION_TIMING
                        | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER,
                )
                .unwrap(),
            };
            let recovery_key_path = provider_root.join("cashu-recovery.key");
            let custody_key_path = provider_root.join("cashu-custody.key");
            write_private_file(&recovery_key_path, &[0x91u8.wrapping_add(index); 32]);
            write_private_file(&custody_key_path, &[0xa1u8.wrapping_add(index); 32]);
            (
                offer,
                Some(spend),
                Some(mint_id),
                Some(recovery_key_path),
                Some(custody_key_path),
            )
        }
        ProviderMethod::FreeOpen => {
            assert!(mint_leaf_spki_sha256_pins.is_empty());
            (
                ServiceOfferV1 {
                    offer_id: FREE_OFFER_ID,
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
                    privacy_leakage: PrivacyLeakageV1::from_bits(PrivacyLeakageV1::KNOWN_MASK)
                        .unwrap(),
                },
                None,
                None,
                None,
                None,
            )
        }
    };
    let policy = ServicePolicyV1::sign(
        provider_id,
        1,
        now.saturating_sub(60),
        now + 3_600,
        AuthPaddingClassV1::Class16KiB,
        vec![ServiceScopePolicyV1 {
            scope,
            limits: EntitlementLimitsV1 {
                max_logical_inputs: 1,
                // This fixed all-not-found N=2 fixture emits exactly one
                // K=75x2 INDEX frame and two K_CHUNK=80x2 presence frames per
                // provider.  Merkle paths are served from the authenticated
                // full tree-top cache, so no sibling frame is needed.
                max_frames: 3,
                max_request_bytes: 2 * 1024 * 1024,
                max_response_bytes: 2 * 1024 * 1024,
                max_wall_time_ms: 20_000,
                max_concurrent_sockets: 1,
                max_hint_groups: 0,
                max_work_units: (INDEX_PARAMS.k * 2 + CHUNK_PARAMS.k * 2 * 2) as u64,
            },
            offers: vec![offer],
        }],
        &policy_signing_key,
    )
    .expect("sign deterministic provider policy");
    let policy_path = provider_root.join("service-policy-v1.bin");
    fs::write(&policy_path, policy.encode().unwrap()).unwrap();
    chmod(&policy_path, 0o644);

    let store_path = store_dir.join("provider.sqlite3");
    let rollback_path = rollback_dir.join("floor.sqlite3");
    let rollback =
        SqliteRollbackFloorAuthorityV1::create(&rollback_path, Duration::from_secs(1)).unwrap();
    let store = ProviderStore::create(
        &store_path,
        [0xb1u8.wrapping_add(index); 16],
        provider_id,
        StoreOptions {
            busy_timeout: Duration::from_secs(1),
        },
        Arc::new(rollback),
    )
    .unwrap();
    drop(store);
    chmod(&store_path, 0o600);
    chmod(&rollback_path, 0o600);

    ProviderFixture {
        index,
        method,
        provider_id,
        policy_verifying_key: policy_signing_key.verifying_key(),
        policy_path,
        store_path,
        rollback_path,
        recovery_key_path,
        custody_key_path,
        scope_id,
        offer_id: match method {
            ProviderMethod::StandardCashu => CASHU_OFFER_ID,
            ProviderMethod::FreeOpen => FREE_OFFER_ID,
        },
        spend,
        mint_id,
    }
}

fn deterministic_cashu_keyset(final_expiry: u64) -> CashuKeysetBindingV1 {
    let keys = vec![CashuDenominationKeyV1 {
        amount: CASHU_PRICE_SAT,
        public_key: mint_public_key(CASHU_PRICE_SAT),
    }];
    CashuKeysetBindingV1 {
        keyset_id: derive_cashu_keyset_id_v2(&keys, CASHU_UNIT, 0, Some(final_expiry)).unwrap(),
        unit: CASHU_UNIT.to_owned(),
        input_fee_ppk: 0,
        final_expiry: Some(final_expiry),
        keys,
    }
}

fn test_leaf_spki_sha256() -> [u8; 32] {
    let decoded = hex::decode(TEST_LEAF_SPKI_SHA256_HEX).unwrap();
    decoded.try_into().unwrap()
}

fn spawn_server(
    root: &Path,
    db_path: &Path,
    fixture: &ProviderFixture,
    port: u16,
    generation: u8,
    test_root: Option<&Path>,
) -> ChildProcess {
    let label = format!("provider-{}-generation-{generation}", fixture.index);
    let stdout_path = root.join(format!("{label}-stdout.log"));
    let stderr_path = root.join(format!("{label}-stderr.log"));
    let stdout = File::create(&stdout_path).unwrap();
    let stderr = File::create(&stderr_path).unwrap();
    let mut args = vec![
        "--bind-address".to_owned(),
        "127.0.0.1".to_owned(),
        "--port".to_owned(),
        port.to_string(),
        "--data-dir".to_owned(),
        db_path.to_str().unwrap().to_owned(),
        "--role".to_owned(),
        "secondary".to_owned(),
        "--disable-onion".to_owned(),
        "--serve-queries".to_owned(),
        "--require-service-auth-v1".to_owned(),
        "--service-policy".to_owned(),
        fixture.policy_path.to_str().unwrap().to_owned(),
        "--service-provider-id-hex".to_owned(),
        hex::encode(fixture.provider_id),
        "--service-policy-key-hex".to_owned(),
        hex::encode(fixture.policy_verifying_key.to_bytes()),
        "--service-store".to_owned(),
        fixture.store_path.to_str().unwrap().to_owned(),
        "--service-rollback-authority".to_owned(),
        fixture.rollback_path.to_str().unwrap().to_owned(),
        "--allow-local-service-rollback-authority-dev".to_owned(),
        "--max-connections".to_owned(),
        "24".to_owned(),
        "--service-max-concurrent-auth".to_owned(),
        "4".to_owned(),
        "--websocket-handshake-timeout-ms".to_owned(),
        "1000".to_owned(),
        "--connection-idle-timeout-ms".to_owned(),
        "60000".to_owned(),
        "--service-pre-auth-timeout-ms".to_owned(),
        "60000".to_owned(),
    ];
    if fixture.method == ProviderMethod::StandardCashu {
        let recovery = fixture.recovery_key_path.as_ref().unwrap();
        let custody = fixture.custody_key_path.as_ref().unwrap();
        args.extend([
            "--service-cashu-recovery-key".to_owned(),
            format!("1={}", recovery.display()),
            "--service-cashu-recovery-active-epoch".to_owned(),
            "1".to_owned(),
            "--service-cashu-custody-key".to_owned(),
            format!("1={}", custody.display()),
            "--service-cashu-custody-active-epoch".to_owned(),
            "1".to_owned(),
            "--service-cashu-exposure-limit".to_owned(),
            format!(
                "{}:{CASHU_UNIT}:16:16",
                hex::encode(fixture.mint_id.expect("Cashu mint ID"))
            ),
        ]);
        if let Some(test_root) = test_root {
            args.extend([
                "--test-only-service-https-root-pem".to_owned(),
                test_root.to_str().unwrap().to_owned(),
            ]);
        }
    } else {
        assert!(test_root.is_none());
    }
    let child = Command::new(env!("CARGO_BIN_EXE_unified_server"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("spawn unified_server");
    let mut process = ChildProcess {
        label,
        child,
        stdout_path,
        stderr_path,
    };
    process.wait_until_listening(port);
    process
}

struct TlsMaterial {
    root: PathBuf,
    wrong_root: PathBuf,
    certificate: PathBuf,
    private_key: PathBuf,
}

fn install_tls_material(root: &Path) -> TlsMaterial {
    let material = TlsMaterial {
        root: root.join("cashu-test-root.pem"),
        wrong_root: root.join("cashu-wrong-root.pem"),
        certificate: root.join("cashu-test-leaf.pem"),
        private_key: root.join("cashu-test-leaf.key"),
    };
    for (path, bytes) in [
        (
            &material.root,
            include_bytes!("testdata/remote-authority-process-root.pem").as_slice(),
        ),
        (
            &material.wrong_root,
            include_bytes!("../../../crates/net/strict-https/src/testdata/wrong-root.pem")
                .as_slice(),
        ),
        (
            &material.certificate,
            include_bytes!("testdata/remote-authority-process-leaf.pem").as_slice(),
        ),
        (
            &material.private_key,
            include_bytes!("testdata/remote-authority-process-leaf.key").as_slice(),
        ),
    ] {
        write_private_file(path, bytes);
        assert_private_regular_file(path);
    }
    material
}

fn spawn_mint_helper(
    root: &Path,
    port: u16,
    material: &TlsMaterial,
    state_path: &Path,
) -> ChildProcess {
    let label = "cashu-tls-mint".to_owned();
    let stdout_path = root.join("cashu-tls-mint-stdout.log");
    let stderr_path = root.join("cashu-tls-mint-stderr.log");
    let stdout = File::create(&stdout_path).unwrap();
    let stderr = File::create(&stderr_path).unwrap();
    let child = Command::new(env::current_exe().expect("current integration test executable"))
        .args([
            "--ignored",
            "--exact",
            "standard_cashu_tls_mint_subprocess",
            "--nocapture",
        ])
        .env(MINT_HELPER_MARKER, "1")
        .env(
            "BITCOINPIR_TEST_CASHU_MINT_BIND",
            format!("127.0.0.1:{port}"),
        )
        .env("BITCOINPIR_TEST_CASHU_MINT_CERT", &material.certificate)
        .env("BITCOINPIR_TEST_CASHU_MINT_KEY", &material.private_key)
        .env("BITCOINPIR_TEST_CASHU_MINT_STATE", state_path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("spawn deterministic Cashu mint helper process");
    let mut process = ChildProcess {
        label,
        child,
        stdout_path,
        stderr_path,
    };
    process.wait_until_listening(port);
    process
}

fn spawn_cdk_tls_proxy(
    root: &Path,
    port: u16,
    upstream: std::net::SocketAddr,
    material: &TlsMaterial,
    state_path: &Path,
) -> ChildProcess {
    assert!(upstream.ip().is_loopback());
    let label = "real-cdk-tls-proxy".to_owned();
    let stdout_path = root.join("real-cdk-tls-proxy-stdout.log");
    let stderr_path = root.join("real-cdk-tls-proxy-stderr.log");
    let stdout = File::create(&stdout_path).unwrap();
    let stderr = File::create(&stderr_path).unwrap();
    let child = Command::new(env::current_exe().expect("current integration test executable"))
        .args([
            "--ignored",
            "--exact",
            "standard_cashu_cdk_tls_proxy_subprocess",
            "--nocapture",
        ])
        .env(CDK_PROXY_HELPER_MARKER, "1")
        .env(
            "BITCOINPIR_TEST_CDK_PROXY_BIND",
            format!("127.0.0.1:{port}"),
        )
        .env("BITCOINPIR_TEST_CDK_PROXY_UPSTREAM", upstream.to_string())
        .env("BITCOINPIR_TEST_CDK_PROXY_CERT", &material.certificate)
        .env("BITCOINPIR_TEST_CDK_PROXY_KEY", &material.private_key)
        .env("BITCOINPIR_TEST_CDK_PROXY_STATE", state_path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("spawn test-only real-CDK TLS proxy");
    let mut process = ChildProcess {
        label,
        child,
        stdout_path,
        stderr_path,
    };
    process.wait_until_listening(port);
    process
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MintSwapRequest {
    inputs: Vec<MintProof>,
    outputs: Vec<MintBlindedMessage>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MintProof {
    amount: u64,
    id: String,
    secret: String,
    #[serde(rename = "C")]
    c: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MintBlindedMessage {
    amount: u64,
    id: String,
    #[serde(rename = "B_")]
    blinded_message: String,
}

#[derive(Serialize)]
struct MintSwapResponse {
    signatures: Vec<MintBlindSignature>,
}

#[derive(Serialize)]
struct MintBlindSignature {
    amount: u64,
    id: String,
    #[serde(rename = "C_")]
    blinded_signature: String,
    dleq: MintDleq,
}

#[derive(Serialize)]
struct MintDleq {
    e: String,
    s: String,
}

fn serve_cashu_mint(
    bind: std::net::SocketAddr,
    certificate_pem: &[u8],
    private_key_pem: &[u8],
    state_path: &Path,
) -> io::Result<()> {
    if !bind.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "test Cashu mint must bind loopback",
        ));
    }
    let certificate = CertificateDer::from_pem_slice(certificate_pem)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid test certificate"))?;
    let private_key = PrivateKeyDer::from_pem_slice(private_key_pem)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid test private key"))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| io::Error::other("configure TLS versions"))?
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)
        .map_err(|_| io::Error::other("configure TLS identity"))?;
    let config = Arc::new(config);
    let listener = TcpListener::bind(bind)?;
    loop {
        let (socket, _) = listener.accept()?;
        if serve_one_mint_request(socket, Arc::clone(&config), state_path).is_err() {
            // TCP readiness probes and malformed TLS handshakes are silent.
            // The helper never logs peer, note, timing, or query information.
        }
    }
}

fn serve_cdk_tls_proxy(
    bind: std::net::SocketAddr,
    upstream: std::net::SocketAddr,
    certificate_pem: &[u8],
    private_key_pem: &[u8],
    state_path: &Path,
) -> io::Result<()> {
    if !bind.ip().is_loopback() || !upstream.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "test CDK TLS proxy endpoints must be loopback",
        ));
    }
    let certificate = CertificateDer::from_pem_slice(certificate_pem)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid test certificate"))?;
    let private_key = PrivateKeyDer::from_pem_slice(private_key_pem)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid test private key"))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| io::Error::other("configure TLS versions"))?
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)
        .map_err(|_| io::Error::other("configure TLS identity"))?;
    let config = Arc::new(config);
    let listener = TcpListener::bind(bind)?;
    loop {
        let (socket, _) = listener.accept()?;
        if serve_one_cdk_tls_proxy_request(socket, Arc::clone(&config), upstream, state_path)
            .is_err()
        {
            // Readiness probes, malformed TLS and invalid HTTP remain silent;
            // the helper never logs a token, proof, peer, query or response.
        }
    }
}

fn serve_one_cdk_tls_proxy_request(
    socket: TcpStream,
    config: Arc<ServerConfig>,
    upstream: std::net::SocketAddr,
    state_path: &Path,
) -> io::Result<()> {
    let expected_host = format!("host: localhost:{}", socket.local_addr()?.port());
    socket.set_read_timeout(Some(TLS_IO_TIMEOUT))?;
    socket.set_write_timeout(Some(TLS_IO_TIMEOUT))?;
    let connection = ServerConnection::new(config).map_err(io::Error::other)?;
    let mut tls = StreamOwned::new(connection, socket);
    let request = read_bounded_http_request(&mut tls)?;
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP header end"))?;
    let header = std::str::from_utf8(&request[..header_end])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-ASCII HTTP header"))?;
    let mut lines = header.split("\r\n");
    if lines.next() != Some("POST /v1/swap HTTP/1.1")
        || !lines
            .clone()
            .any(|line| line.eq_ignore_ascii_case(&expected_host))
        || !lines.any(|line| line.eq_ignore_ascii_case("content-type: application/json"))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected CDK proxy request",
        ));
    }
    let body = &request[header_end..];
    let mut upstream_socket = TcpStream::connect_timeout(&upstream, TLS_IO_TIMEOUT)?;
    upstream_socket.set_read_timeout(Some(TLS_IO_TIMEOUT))?;
    upstream_socket.set_write_timeout(Some(TLS_IO_TIMEOUT))?;
    let forwarded_header = format!(
        "POST /v1/swap HTTP/1.1\r\nHost: {upstream}\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    record_mint_swap_attempt(state_path)?;
    upstream_socket.write_all(forwarded_header.as_bytes())?;
    upstream_socket.write_all(body)?;
    upstream_socket.flush()?;
    let response = read_bounded_http_request(&mut upstream_socket)?;
    if !response.starts_with(b"HTTP/1.1 200 ") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "real CDK swap did not return HTTP 200",
        ));
    }
    tls.write_all(&response)?;
    tls.flush()?;
    tls.conn.send_close_notify();
    let _ = tls.flush();
    Ok(())
}

fn serve_one_mint_request(
    socket: TcpStream,
    config: Arc<ServerConfig>,
    state_path: &Path,
) -> io::Result<()> {
    socket.set_read_timeout(Some(TLS_IO_TIMEOUT))?;
    socket.set_write_timeout(Some(TLS_IO_TIMEOUT))?;
    let connection = ServerConnection::new(config).map_err(io::Error::other)?;
    let mut tls = StreamOwned::new(connection, socket);
    let request = read_bounded_http_request(&mut tls)?;
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP header end"))?;
    let header = std::str::from_utf8(&request[..header_end])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-ASCII HTTP header"))?;
    let mut lines = header.split("\r\n");
    let request_target_ok = lines.next() == Some("POST /v1/swap HTTP/1.1");
    let host_ok = lines.any(|line| {
        line.eq_ignore_ascii_case("Host: localhost")
            || line.to_ascii_lowercase().starts_with("host: localhost:")
    });
    if !request_target_ok || !host_ok {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected Cashu HTTP target",
        ));
    }
    let parsed: MintSwapRequest = serde_json::from_slice(&request[header_end..])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid Cashu swap JSON"))?;
    validate_mint_swap_request(&parsed)?;

    // Persist one anonymous attempt marker before any application response.
    // This lets the parent test distinguish a real local replay short-circuit
    // from a replay that incorrectly reached the mint and merely received 400.
    if record_mint_swap_attempt(state_path)? > 0 {
        return write_json_response(
            &mut tls,
            400,
            br#"{"code":10001,"detail":"proof verification failed"}"#,
        );
    }
    let response = MintSwapResponse {
        signatures: parsed.outputs.iter().map(sign_blinded_message).collect(),
    };
    let response = serde_json::to_vec(&response).map_err(io::Error::other)?;
    write_json_response(&mut tls, 200, &response)
}

fn record_mint_swap_attempt(path: &Path) -> io::Result<u64> {
    let prior = read_mint_swap_attempt_count(path)?;
    let mut options = fs::OpenOptions::new();
    options.append(true).mode(0o600);
    if prior == 0 {
        options.create_new(true);
    }
    let mut file = options.open(path)?;
    file.write_all(b"1\n")?;
    file.sync_all()?;
    Ok(prior)
}

fn read_mint_swap_attempt_count(path: &Path) -> io::Result<u64> {
    let value = match fs::read_to_string(path) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    if value.is_empty() || value.lines().any(|line| line != "1") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid test mint attempt journal",
        ));
    }
    u64::try_from(value.lines().count())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "test mint attempt overflow"))
}

fn validate_mint_swap_request(request: &MintSwapRequest) -> io::Result<()> {
    if request.inputs.len() != 1 || request.outputs.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture expects one Cashu input and output",
        ));
    }
    let input = &request.inputs[0];
    let expected_c = hex::encode(compressed_point(
        &(ProjectivePoint::GENERATOR * Scalar::from(51u64)),
    ));
    if input.amount != CASHU_PRICE_SAT
        || input.secret != CASHU_INPUT_SECRET
        || input.c != expected_c
        || input.id.len() != 66
        || !is_lower_hex(&input.id)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected deterministic Cashu input",
        ));
    }
    let output = &request.outputs[0];
    if output.amount != CASHU_PRICE_SAT
        || output.id != input.id
        || output.blinded_message.len() != 66
        || !is_lower_hex(&output.blinded_message)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected deterministic Cashu output",
        ));
    }
    Ok(())
}

fn sign_blinded_message(output: &MintBlindedMessage) -> MintBlindSignature {
    let encoded = hex::decode(&output.blinded_message).unwrap();
    let encoded = EncodedPoint::from_bytes(&encoded).unwrap();
    let blinded_message = ProjectivePoint::from(
        Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded)).unwrap(),
    );
    let mint_scalar = mint_scalar(output.amount);
    let public_key = ProjectivePoint::GENERATOR * mint_scalar;
    let blinded_signature = blinded_message * mint_scalar;
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
    let s = nonce + e * mint_scalar;
    MintBlindSignature {
        amount: output.amount,
        id: output.id.clone(),
        blinded_signature: hex::encode(compressed_point(&blinded_signature)),
        dleq: MintDleq {
            e: hex::encode(e_bytes),
            s: hex::encode(<[u8; 32]>::from(s.to_bytes())),
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
        hasher.update(hex::encode(
            point.to_affine().to_encoded_point(false).as_bytes(),
        ));
    }
    hasher.finalize().into()
}

fn write_json_response(
    tls: &mut StreamOwned<ServerConnection, TcpStream>,
    status: u16,
    body: &[u8],
) -> io::Result<()> {
    let reason = if status == 200 { "OK" } else { "Bad Request" };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    tls.write_all(header.as_bytes())?;
    tls.write_all(body)?;
    tls.flush()?;
    tls.conn.send_close_notify();
    let _ = tls.flush();
    Ok(())
}

fn read_bounded_http_request(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut request = Vec::new();
    let mut total_length = None;
    loop {
        if request.len() >= MAX_HTTP_REQUEST_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Cashu request exceeded bound",
            ));
        }
        let mut chunk = [0u8; 2048];
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Cashu request ended early",
            ));
        }
        request.extend_from_slice(&chunk[..read]);
        if total_length.is_none() {
            if let Some(header_end) = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|position| position + 4)
            {
                let header = std::str::from_utf8(&request[..header_end]).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "non-ASCII Cashu headers")
                })?;
                let content_length = header
                    .split("\r\n")
                    .find_map(|line| {
                        line.split_once(':').and_then(|(name, value)| {
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                    })
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "missing content length")
                    })?;
                let total = header_end.checked_add(content_length).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "Cashu request overflow")
                })?;
                if total > MAX_HTTP_REQUEST_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Cashu request exceeded bound",
                    ));
                }
                total_length = Some(total);
            }
        }
        if let Some(total) = total_length.filter(|total| request.len() >= *total) {
            if request.len() != total {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Cashu request contained trailing bytes",
                ));
            }
            return Ok(request);
        }
    }
}

struct BucketMerkleArtifacts {
    super_root: [u8; 32],
    tree_tops: Vec<u8>,
    roots: Vec<u8>,
}

fn write_merkle_database(root: &Path) -> (PathBuf, [u8; 32], [u8; 32]) {
    let db = root.join("tiny-merkle-db");
    fs::create_dir(&db).unwrap();
    let mut index = write_header_with_anchor(
        &INDEX_PARAMS.with_master_seed(0x1111_2222_3333_4444),
        TINY_BINS_PER_TABLE,
        0x9999_aaaa_bbbb_cccc,
        None,
    );
    index.resize(
        index.len() + INDEX_PARAMS.k * INDEX_PARAMS.table_byte_size(TINY_BINS_PER_TABLE),
        0,
    );
    let mut chunk = write_header_with_anchor(
        &CHUNK_PARAMS.with_master_seed(0x5555_6666_7777_8888),
        TINY_BINS_PER_TABLE,
        0,
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
    let manifest_root = sha256(manifest.as_bytes());
    (db, manifest_root, merkle.super_root)
}

fn build_bucket_merkle_artifacts(index: &[u8], chunk: &[u8]) -> BucketMerkleArtifacts {
    let tree_count = INDEX_PARAMS.k + CHUNK_PARAMS.k;
    let mut tree_tops = Vec::new();
    tree_tops.extend_from_slice(&(tree_count as u32).to_le_bytes());
    let mut roots = Vec::with_capacity(tree_count * 32);
    append_bucket_merkle_table(index, &INDEX_PARAMS, &mut tree_tops, &mut roots);
    append_bucket_merkle_table(chunk, &CHUNK_PARAMS, &mut tree_tops, &mut roots);
    assert_eq!(roots.len(), tree_count * 32);
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
    assert_eq!(header.bins_per_table, TINY_BINS_PER_TABLE);
    let group_size = params.table_byte_size(header.bins_per_table);
    assert_eq!(table.len(), header.header_size + params.k * group_size);
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

        // All levels of this deliberately tiny tree fit in the public cache,
        // so no sibling-PIR fixture is needed for the Merkle round.
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

fn mint_scalar(amount: u64) -> Scalar {
    Scalar::from(amount + MINT_SCALAR_OFFSET)
}

fn mint_public_key(amount: u64) -> [u8; 33] {
    compressed_point(&(ProjectivePoint::GENERATOR * mint_scalar(amount)))
}

fn compressed_point(point: &ProjectivePoint) -> [u8; 33] {
    point
        .to_affine()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap()
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn deterministic_32(domain: u8, provider: u8, counter: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BitcoinPIR/standard-cashu-process-e2e/v1");
    hasher.update([domain, provider]);
    hasher.update(counter.to_le_bytes());
    hasher.finalize().into()
}

fn assert_server_log(stdout: &str, stderr: &str, port: u16) {
    assert!(stdout.contains(&format!("Listening on ws://127.0.0.1:{port}")));
    assert!(stdout.contains("Service admission V1: enforced"));
    assert!(!stderr.contains("UNSAFE DEBUG QUERY LOGGING ENABLED"));
    for forbidden in [CASHU_INPUT_SECRET, "payment_hash", "preimage", "invoice"] {
        assert!(!stdout.contains(forbidden));
        assert!(!stderr.contains(forbidden));
    }
}

fn mint_swap_attempt_count(path: &Path) -> u64 {
    read_mint_swap_attempt_count(path).expect("read mint attempt journal")
}

fn write_private_file(path: &Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap_or_else(|error| panic!("create private file {}: {error}", path.display()));
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn assert_private_regular_file(path: &Path) {
    let parent = fs::symlink_metadata(path.parent().expect("private test file parent")).unwrap();
    assert!(parent.file_type().is_dir());
    assert_eq!(parent.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(parent.mode() & 0o7777, 0o700);
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.file_type().is_file());
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_eq!(metadata.nlink(), 1);
}

fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("missing {name}"))
}

fn required_hex32_env(name: &str) -> [u8; 32] {
    decode_exact_hex32(name, &required_env(name))
}

fn decode_exact_hex32(field: &str, value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64, "{field} must be 32-byte hex");
    assert!(is_lower_hex(value), "{field} must be lowercase hex");
    let decoded: [u8; 32] = hex::decode(value)
        .expect("decode exact hex")
        .try_into()
        .expect("exact 32-byte hex length");
    assert!(
        decoded.iter().any(|byte| *byte != 0),
        "{field} must be nonzero"
    );
    decoded
}

fn parse_signed_localhost_endpoint(endpoint: &str) -> u16 {
    let port = endpoint
        .strip_prefix("https://localhost:")
        .filter(|value| !value.is_empty() && !value.contains('/'))
        .unwrap_or_else(|| {
            panic!("signed CDK endpoint is not canonical localhost HTTPS: {endpoint}")
        })
        .parse::<u16>()
        .expect("signed CDK endpoint port");
    assert!(port >= 1024);
    port
}

fn parse_actual_loopback_endpoint(endpoint: &str) -> std::net::SocketAddr {
    let port = endpoint
        .strip_prefix("http://127.0.0.1:")
        .filter(|value| !value.is_empty() && !value.contains('/'))
        .unwrap_or_else(|| {
            panic!("actual CDK endpoint is not exact IPv4 loopback HTTP: {endpoint}")
        })
        .parse::<u16>()
        .expect("actual CDK endpoint port");
    assert!(port >= 1024);
    format!("127.0.0.1:{port}")
        .parse()
        .expect("actual CDK loopback socket")
}

fn assert_no_cashu_bearer_or_proof_log<'a>(
    spend: &StandardCashuSpendV1,
    logs: impl IntoIterator<Item = &'a str>,
) {
    for log in logs {
        for forbidden in ["cashuB", "payment_hash", "preimage", "invoice"] {
            assert!(
                !log.contains(forbidden),
                "sensitive Cashu marker reached a process log"
            );
        }
        for proof in &spend.proofs {
            assert!(
                !log.contains(&proof.secret),
                "a Cashu proof secret reached a process log"
            );
        }
    }
}

fn distinct_unused_port(excluded: &[u16]) -> u16 {
    loop {
        let port = unused_loopback_port();
        if !excluded.contains(&port) {
            return port;
        }
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

async fn exercise_tls_failure_matrix(
    root: &Path,
    db_path: &Path,
    manifest_root: [u8; 32],
    mint_endpoint: &str,
    material: &TlsMaterial,
    mint_port: u16,
    now: u64,
) {
    #[derive(Clone, Copy)]
    enum FailureCase {
        WrongCa,
        WrongSignedPin,
        Offline,
    }

    for (case_index, case) in [
        FailureCase::WrongCa,
        FailureCase::WrongSignedPin,
        FailureCase::Offline,
    ]
    .into_iter()
    .enumerate()
    {
        let provider_index = 10 + u8::try_from(case_index * 2).unwrap();
        let peer_index = provider_index + 1;
        let offline_port = distinct_unused_port(&[mint_port]);
        let endpoint = match case {
            FailureCase::Offline => format!("https://localhost:{offline_port}"),
            _ => mint_endpoint.to_owned(),
        };
        let pins = match case {
            FailureCase::WrongSignedPin => vec![[0x5a; 32]],
            _ => vec![test_leaf_spki_sha256()],
        };
        let cashu = build_provider(
            root,
            provider_index,
            ProviderMethod::StandardCashu,
            manifest_root,
            &endpoint,
            pins,
            now,
        );
        let free = build_provider(
            root,
            peer_index,
            ProviderMethod::FreeOpen,
            manifest_root,
            "",
            Vec::new(),
            now,
        );
        let provider_port = distinct_unused_port(&[mint_port, offline_port]);
        let peer_port = distinct_unused_port(&[mint_port, offline_port, provider_port]);
        let test_root = match case {
            FailureCase::WrongCa => &material.wrong_root,
            _ => &material.root,
        };
        let server0 = spawn_server(root, db_path, &cashu, provider_port, 0, Some(test_root));
        let server1 = spawn_server(root, db_path, &free, peer_port, 0, None);
        let mut client = open_strict_dpf_pair(
            provider_port,
            peer_port,
            manifest_root,
            fs::read(db_path.join("merkle_bucket_root.bin"))
                .unwrap()
                .try_into()
                .unwrap(),
            &cashu,
            &free,
            now + u64::try_from(case_index).unwrap() + 10,
        )
        .await;
        let accepted = client
            .fetch_service_policy_v1(
                0,
                0,
                cashu.provider_id,
                &cashu.policy_verifying_key,
                now,
                &ServicePolicyCheckpointV1::initial(),
            )
            .await
            .unwrap();
        let rejection = authorize_cashu(&mut client, 0, &cashu, &accepted)
            .await
            .expect_err("TLS trust/offline failure must never grant Cashu admission");
        assert!(
            rejection.to_string().contains("internal-after-spend"),
            "unexpected fail-closed Cashu rejection: {rejection}"
        );
        client.disconnect().await.unwrap();
        let (stdout0, stderr0) = server0.stop();
        let (stdout1, stderr1) = server1.stop();
        assert_server_log(&stdout0, &stderr0, provider_port);
        assert_server_log(&stdout1, &stderr1, peer_port);
    }
}
