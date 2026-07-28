//! Non-default real-process E2E for the production remote rollback-authority
//! path. The authority application, loopback TLS edge, and `unified_server`
//! each run in a distinct OS process. The private test CA is accepted only by
//! the explicit Cargo feature that includes this module.

use super::*;

use std::env;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::process::ExitStatus;

use clap::Parser as _;
use pir_rollback_authority_client::load_remote_rollback_authority_deployment_for_business_domain_v1;
use pir_service_store::RemoteProviderRollbackFloorAuthorityV1;
use rollback_authority::{run as run_rollback_authority, Cli as RollbackAuthorityCli};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

const AUTHORITY_HELPER_MARKER: &str = "BITCOINPIR_TEST_ONLY_AUTHORITY_HELPER_V1";
const TLS_HELPER_MARKER: &str = "BITCOINPIR_TEST_ONLY_AUTHORITY_TLS_HELPER_V1";
const TEST_LEAF_SPKI_SHA256_HEX: &str =
    "e91550521f8e17b21d99f7e00b99c08be1b1f31fe57772ac8f904ea50c6a609b";
const PROCESS_START_TIMEOUT: Duration = Duration::from_secs(30);
const PROCESS_EXIT_TIMEOUT: Duration = Duration::from_secs(12);
const TLS_IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PROXY_REQUEST_BYTES: usize = 64 * 1024;
const MAX_PROXY_RESPONSE_BYTES: usize = 256 * 1024;

struct AuthorityMaterial {
    authority_secret: PathBuf,
    authority_metadata: PathBuf,
    authority_store: PathBuf,
    remote_config: PathBuf,
    wrong_pin_config: PathBuf,
    wrong_ca_config: PathBuf,
    test_root: PathBuf,
    leaf_certificate: PathBuf,
    leaf_private_key: PathBuf,
    authority_instance_id_hex: String,
    authority_verifying_key_hex: String,
    namespace_hex: String,
    client_verifying_key_hex: String,
}

struct HelperProcess {
    label: &'static str,
    child: Child,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

impl HelperProcess {
    fn spawn(
        root: &Path,
        label: &'static str,
        generation: u8,
        test_name: &str,
        environment: &[(&str, String)],
    ) -> Self {
        let stdout_path = root.join(format!("{label}-{generation}-stdout.log"));
        let stderr_path = root.join(format!("{label}-{generation}-stderr.log"));
        let stdout = File::create(&stdout_path).expect("create helper stdout log");
        let stderr = File::create(&stderr_path).expect("create helper stderr log");
        let mut command = Command::new(env::current_exe().expect("current test executable"));
        command
            .args(["--ignored", "--exact", test_name, "--nocapture"])
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        for (key, value) in environment {
            command.env(key, value);
        }
        let child = command.spawn().expect("spawn real helper process");
        Self {
            label,
            child,
            stdout_path,
            stderr_path,
        }
    }

    fn wait_until_listening(&mut self, port: u16) {
        let deadline = Instant::now() + PROCESS_START_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().expect("poll helper process") {
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

impl Drop for HelperProcess {
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
#[ignore = "spawned only by remote_authority_real_process_tls_provider_e2e"]
fn rollback_authority_subprocess() {
    if env::var_os(AUTHORITY_HELPER_MARKER).is_none() {
        return;
    }
    let bind = required_env("BITCOINPIR_TEST_AUTHORITY_BIND");
    let store = required_env("BITCOINPIR_TEST_AUTHORITY_STORE");
    let secret = required_env("BITCOINPIR_TEST_AUTHORITY_SECRET");
    let metadata = required_env("BITCOINPIR_TEST_AUTHORITY_METADATA");
    let public_key = required_env("BITCOINPIR_TEST_AUTHORITY_PUBLIC_KEY");
    let cli = RollbackAuthorityCli::try_parse_from([
        "rollback-authority",
        "serve",
        "--bind",
        bind.as_str(),
        "--store",
        store.as_str(),
        "--authority-secret",
        secret.as_str(),
        "--authority-metadata",
        metadata.as_str(),
        "--expected-authority-pubkey-hex",
        public_key.as_str(),
        "--busy-timeout-ms",
        "1000",
        "--io-timeout-ms",
        "2000",
        "--max-connections",
        "8",
    ])
    .expect("parse authority helper CLI");
    run_rollback_authority(cli).expect("serve real rollback-authority process");
}

#[test]
#[ignore = "spawned only by remote_authority_real_process_tls_provider_e2e"]
fn rollback_authority_tls_edge_subprocess() {
    if env::var_os(TLS_HELPER_MARKER).is_none() {
        return;
    }
    let bind: std::net::SocketAddr = required_env("BITCOINPIR_TEST_TLS_BIND")
        .parse()
        .expect("TLS helper bind address");
    assert!(
        bind.ip().is_loopback(),
        "TLS helper must bind loopback only"
    );
    let backend: std::net::SocketAddr = required_env("BITCOINPIR_TEST_TLS_BACKEND")
        .parse()
        .expect("TLS helper backend address");
    assert!(
        backend.ip().is_loopback(),
        "TLS helper backend must be loopback only"
    );
    let certificate =
        fs::read(required_env("BITCOINPIR_TEST_TLS_CERT")).expect("read TLS helper certificate");
    let private_key =
        fs::read(required_env("BITCOINPIR_TEST_TLS_KEY")).expect("read TLS helper key");
    serve_test_tls_edge(bind, backend, &certificate, &private_key)
        .expect("serve test-only TLS edge");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_authority_real_process_tls_provider_e2e() {
    let root = tempfile::tempdir().expect("remote authority process test root");
    chmod(root.path(), 0o700);
    let (db_path, manifest_root) = write_tiny_manifest_database(root.path());
    let provider = build_provider(root.path(), 7, manifest_root, unix_now());
    remove_local_provider_store_fixture(&provider);

    let authority_port = distinct_unused_port(&[]);
    let tls_port = distinct_unused_port(&[authority_port]);
    let provider_port = distinct_unused_port(&[authority_port, tls_port]);
    let material = prepare_authority_material(root.path(), tls_port);

    let mut authority = spawn_authority(root.path(), &material, authority_port, 0);
    authority.wait_until_listening(authority_port);
    let mut tls = spawn_tls_edge(root.path(), &material, tls_port, authority_port, 0);
    tls.wait_until_listening(tls_port);

    create_remote_provider_store(&provider, &material.remote_config);

    // A correct pin cannot rescue a chain signed by an untrusted CA, and a
    // trusted test CA cannot rescue the wrong SPKI pin. Both provider
    // processes must exit before opening their WebSocket listeners.
    assert_remote_server_startup_fails_closed(
        root.path(),
        &db_path,
        &provider,
        provider_port,
        &material.wrong_ca_config,
        "wrong-ca",
    );
    assert_remote_server_startup_fails_closed(
        root.path(),
        &db_path,
        &provider,
        provider_port,
        &material.wrong_pin_config,
        "wrong-pin",
    );

    let server = spawn_remote_server(
        root.path(),
        &db_path,
        &provider,
        provider_port,
        &material.remote_config,
        0,
    );
    let request = valid_tiny_dpf_request();
    let receipt = provider.receipt(0xd7);
    exercise_remote_paid_grant(provider_port, &provider, manifest_root, &request, &receipt).await;

    let (server_stdout, server_stderr) = server.stop();
    assert_remote_server_log(&server_stdout, &server_stderr, provider_port);

    // Restart both the independent authority and the provider against their
    // durable stores. The exact paid receipt remains spent.
    let (authority_stdout0, authority_stderr0) = authority.stop();
    assert_authority_log_is_coarse(&material, &authority_stdout0, &authority_stderr0);
    authority = spawn_authority(root.path(), &material, authority_port, 1);
    authority.wait_until_listening(authority_port);
    let restarted = spawn_remote_server(
        root.path(),
        &db_path,
        &provider,
        provider_port,
        &material.remote_config,
        1,
    );
    let (mut replay_session, replay_policy) =
        open_remote_verified_session(provider_port, &provider, manifest_root, &request).await;
    let replay_proof = dangerous_unpaired_build_authorization_proof_v1(
        &replay_policy,
        &provider.scope_id,
        OFFER_ID,
        &receipt.encode().unwrap(),
    )
    .unwrap();
    let replay = dangerous_unpaired_authorize_service_operation_v1(
        &mut replay_session,
        &replay_policy,
        provider.scope_id,
        OFFER_ID,
        OperationStartV1::DpfQuery { db_id: 0 },
        replay_proof,
    )
    .await
    .unwrap_err();
    assert!(replay.to_string().contains("invalid-or-spent"), "{replay}");
    replay_session.close().await.unwrap();
    let (restart_stdout, restart_stderr) = restarted.stop();
    assert_remote_server_log(&restart_stdout, &restart_stderr, provider_port);

    let (authority_stdout1, authority_stderr1) = authority.stop();
    assert_authority_log_is_coarse(&material, &authority_stdout1, &authority_stderr1);
    let (tls_stdout, tls_stderr) = tls.stop();
    assert!(!tls_stdout.contains("invoice"));
    assert!(!tls_stdout.contains(&material.namespace_hex));
    assert!(
        tls_stderr.trim().is_empty(),
        "TLS edge logged stderr: {tls_stderr}"
    );

    // With the authority/TLS edge unavailable, the detailed store is not used
    // as a fallback source of truth and startup remains fail closed.
    assert_remote_server_startup_fails_closed(
        root.path(),
        &db_path,
        &provider,
        provider_port,
        &material.remote_config,
        "authority-offline",
    );
}

async fn exercise_remote_paid_grant(
    port: u16,
    fixture: &ProviderFixture,
    manifest_root: [u8; 32],
    request: &[u8],
    receipt: &PaidReceiptV1,
) {
    let (mut secure, accepted) =
        open_remote_verified_session(port, fixture, manifest_root, request).await;
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
    .expect("remote-authority paid receipt must authorize");
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
    expect_error_response(
        &secure.roundtrip(request).await.unwrap(),
        "service entitlement limit exceeded",
    );
    secure.close().await.unwrap();
}

async fn open_remote_verified_session(
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
        .expect("connect remote-authority provider WebSocket");
    let session_id = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut eph_seed = [0x97; 32];
    let mut random = [0xa7; 32];
    let mut handshake_nonce = [0xb7; 32];
    eph_seed[..8].copy_from_slice(&session_id.to_le_bytes());
    random[..8].copy_from_slice(&session_id.wrapping_add(0x3000).to_le_bytes());
    handshake_nonce[..8].copy_from_slice(&session_id.wrapping_add(0x4000).to_le_bytes());
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
    .expect("verify signed remote-authority provider policy");
    assert_eq!(accepted.policy_digest(), fixture.policy_digest);
    assert_eq!(accepted.checkpoint().rollback_guard().highest_epoch, 1);
    expect_error_response(
        &secure.roundtrip(backend_request).await.unwrap(),
        "authorization",
    );
    (secure, accepted)
}

fn prepare_authority_material(root: &Path, tls_port: u16) -> AuthorityMaterial {
    let authority_dir = root.join("remote-authority-domain");
    let client_dir = root.join("remote-client-domain");
    let edge_dir = root.join("remote-tls-edge-domain");
    for directory in [&authority_dir, &client_dir, &edge_dir] {
        fs::create_dir(directory).unwrap();
        chmod(directory, 0o700);
    }

    let authority_secret = authority_dir.join("authority.seed");
    let authority_metadata = authority_dir.join("authority-public.txt");
    let authority_store = authority_dir.join("authority.sqlite3");
    let client_secret = client_dir.join("client.seed");
    let value_root = client_dir.join("value-root.raw");
    let client_metadata = client_dir.join("client-provisioning.txt");
    run_authority_cli(vec![
        "rollback-authority".to_owned(),
        "generate-authority".to_owned(),
        "--secret-out".to_owned(),
        authority_secret.display().to_string(),
        "--metadata-out".to_owned(),
        authority_metadata.display().to_string(),
    ]);
    run_authority_cli(vec![
        "rollback-authority".to_owned(),
        "generate-client".to_owned(),
        "--secret-out".to_owned(),
        client_secret.display().to_string(),
        "--value-root-key-out".to_owned(),
        value_root.display().to_string(),
        "--metadata-out".to_owned(),
        client_metadata.display().to_string(),
    ]);
    run_authority_cli(vec![
        "rollback-authority".to_owned(),
        "init-store".to_owned(),
        "--store".to_owned(),
        authority_store.display().to_string(),
        "--authority-metadata".to_owned(),
        authority_metadata.display().to_string(),
        "--busy-timeout-ms".to_owned(),
        "1000".to_owned(),
    ]);
    run_authority_cli(vec![
        "rollback-authority".to_owned(),
        "provision".to_owned(),
        "--store".to_owned(),
        authority_store.display().to_string(),
        "--authority-metadata".to_owned(),
        authority_metadata.display().to_string(),
        "--client-metadata".to_owned(),
        client_metadata.display().to_string(),
        "--max-operation-rows".to_owned(),
        "128".to_owned(),
        "--max-call-rows".to_owned(),
        "1024".to_owned(),
    ]);

    let authority_instance_id_hex = metadata_field(&authority_metadata, "authority_instance_id");
    let authority_verifying_key_hex =
        metadata_field(&authority_metadata, "authority_verifying_key");
    let namespace_hex = metadata_field(&client_metadata, "namespace");
    let client_verifying_key_hex = metadata_field(&client_metadata, "client_verifying_key");

    let test_root = client_dir.join("test-only-root.pem");
    let wrong_root = client_dir.join("test-only-wrong-root.pem");
    let leaf_certificate = edge_dir.join("localhost-leaf.pem");
    let leaf_private_key = edge_dir.join("localhost-leaf.key");
    write_private_file(
        &test_root,
        include_bytes!("../testdata/remote-authority-process-root.pem"),
    );
    write_private_file(
        &wrong_root,
        include_bytes!("../../../../crates/net/strict-https/src/testdata/wrong-root.pem"),
    );
    write_private_file(
        &leaf_certificate,
        include_bytes!("../testdata/remote-authority-process-leaf.pem"),
    );
    write_private_file(
        &leaf_private_key,
        include_bytes!("../testdata/remote-authority-process-leaf.key"),
    );

    let remote_config = client_dir.join("remote-authority.toml");
    let wrong_pin_config = client_dir.join("remote-authority-wrong-pin.toml");
    let wrong_ca_config = client_dir.join("remote-authority-wrong-ca.toml");
    let public = RemoteConfigPublicFields {
        endpoint: format!("https://localhost:{tls_port}"),
        authority_instance_id_hex: &authority_instance_id_hex,
        authority_verifying_key_hex: &authority_verifying_key_hex,
        namespace_hex: &namespace_hex,
        client_verifying_key_hex: &client_verifying_key_hex,
        client_secret: &client_secret,
        value_root: &value_root,
    };
    write_private_file(
        &remote_config,
        remote_config_text(&public, TEST_LEAF_SPKI_SHA256_HEX, &test_root).as_bytes(),
    );
    write_private_file(
        &wrong_pin_config,
        remote_config_text(&public, &"55".repeat(32), &test_root).as_bytes(),
    );
    write_private_file(
        &wrong_ca_config,
        remote_config_text(&public, TEST_LEAF_SPKI_SHA256_HEX, &wrong_root).as_bytes(),
    );

    AuthorityMaterial {
        authority_secret,
        authority_metadata,
        authority_store,
        remote_config,
        wrong_pin_config,
        wrong_ca_config,
        test_root,
        leaf_certificate,
        leaf_private_key,
        authority_instance_id_hex,
        authority_verifying_key_hex,
        namespace_hex,
        client_verifying_key_hex,
    }
}

struct RemoteConfigPublicFields<'a> {
    endpoint: String,
    authority_instance_id_hex: &'a str,
    authority_verifying_key_hex: &'a str,
    namespace_hex: &'a str,
    client_verifying_key_hex: &'a str,
    client_secret: &'a Path,
    value_root: &'a Path,
}

fn remote_config_text(public: &RemoteConfigPublicFields<'_>, pin: &str, root: &Path) -> String {
    format!(
        "schema = \"bitcoinpir_remote_rollback_authority_v1\"\nendpoint = {:?}\nauthority_instance_id_hex = {:?}\nauthority_verifying_key_hex = {:?}\nnamespace_hex = {:?}\nclient_verifying_key_hex = {:?}\nclient_signing_seed_path = {:?}\nvalue_root_key_path = {:?}\nleaf_spki_sha256_pins_hex = [{pin:?}]\nconnect_timeout_ms = 500\nio_timeout_ms = 1000\nattempt_timeout_ms = 1500\noperation_timeout_ms = 4500\ntest_only_webpki_root_pem_path = {:?}\n",
        public.endpoint,
        public.authority_instance_id_hex,
        public.authority_verifying_key_hex,
        public.namespace_hex,
        public.client_verifying_key_hex,
        public.client_secret.display().to_string(),
        public.value_root.display().to_string(),
        root.display().to_string(),
    )
}

fn create_remote_provider_store(provider: &ProviderFixture, config: &Path) {
    let configured = load_remote_rollback_authority_deployment_for_business_domain_v1(
        config,
        provider.provider_id,
    )
    .expect("load strict remote rollback authority config");
    let (client, codec, timeout) = configured.into_parts();
    let authority =
        RemoteProviderRollbackFloorAuthorityV1::new(provider.provider_id, client, codec, timeout)
            .expect("bind remote provider rollback authority");
    let store = ProviderStore::create(
        &provider.store_path,
        [0x57; 16],
        provider.provider_id,
        StoreOptions {
            busy_timeout: Duration::from_secs(1),
        },
        Arc::new(authority),
    )
    .expect("create provider store through remote authority");
    drop(store);
    chmod(&provider.store_path, 0o600);
}

fn remove_local_provider_store_fixture(provider: &ProviderFixture) {
    fs::remove_file(&provider.store_path).expect("remove disposable local provider store");
    fs::remove_file(&provider.rollback_path).expect("remove disposable local rollback floor");
}

fn spawn_authority(
    root: &Path,
    material: &AuthorityMaterial,
    port: u16,
    generation: u8,
) -> HelperProcess {
    HelperProcess::spawn(
        root,
        "rollback-authority-process",
        generation,
        "remote_authority_process::rollback_authority_subprocess",
        &[
            (AUTHORITY_HELPER_MARKER, "1".to_owned()),
            (
                "BITCOINPIR_TEST_AUTHORITY_BIND",
                format!("127.0.0.1:{port}"),
            ),
            (
                "BITCOINPIR_TEST_AUTHORITY_STORE",
                material.authority_store.display().to_string(),
            ),
            (
                "BITCOINPIR_TEST_AUTHORITY_SECRET",
                material.authority_secret.display().to_string(),
            ),
            (
                "BITCOINPIR_TEST_AUTHORITY_METADATA",
                material.authority_metadata.display().to_string(),
            ),
            (
                "BITCOINPIR_TEST_AUTHORITY_PUBLIC_KEY",
                material.authority_verifying_key_hex.clone(),
            ),
        ],
    )
}

fn spawn_tls_edge(
    root: &Path,
    material: &AuthorityMaterial,
    tls_port: u16,
    authority_port: u16,
    generation: u8,
) -> HelperProcess {
    HelperProcess::spawn(
        root,
        "rollback-authority-tls-edge-process",
        generation,
        "remote_authority_process::rollback_authority_tls_edge_subprocess",
        &[
            (TLS_HELPER_MARKER, "1".to_owned()),
            ("BITCOINPIR_TEST_TLS_BIND", format!("127.0.0.1:{tls_port}")),
            (
                "BITCOINPIR_TEST_TLS_BACKEND",
                format!("127.0.0.1:{authority_port}"),
            ),
            (
                "BITCOINPIR_TEST_TLS_CERT",
                material.leaf_certificate.display().to_string(),
            ),
            (
                "BITCOINPIR_TEST_TLS_KEY",
                material.leaf_private_key.display().to_string(),
            ),
        ],
    )
}

fn spawn_remote_server(
    root: &Path,
    db_path: &Path,
    provider: &ProviderFixture,
    port: u16,
    config: &Path,
    generation: u8,
) -> ServerProcess {
    let stdout_path = root.join(format!("remote-provider-{generation}-stdout.log"));
    let stderr_path = root.join(format!("remote-provider-{generation}-stderr.log"));
    let stdout = File::create(&stdout_path).expect("create remote provider stdout log");
    let stderr = File::create(&stderr_path).expect("create remote provider stderr log");
    let child = remote_server_command(db_path, provider, port, config)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("spawn remote-authority unified_server");
    let mut server = ServerProcess {
        child,
        stdout_path,
        stderr_path,
    };
    server.wait_until_listening(port);
    server
}

fn assert_remote_server_startup_fails_closed(
    root: &Path,
    db_path: &Path,
    provider: &ProviderFixture,
    port: u16,
    config: &Path,
    label: &str,
) {
    let mut child = remote_server_command(db_path, provider, port, config)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn expected-failure remote provider");
    let deadline = Instant::now() + PROCESS_EXIT_TIMEOUT;
    let status = loop {
        assert!(
            TcpStream::connect(("127.0.0.1", port)).is_err(),
            "{label} provider opened a listener before remote authority validation"
        );
        if let Some(status) = child.try_wait().expect("poll expected-failure provider") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{label} provider did not fail closed before timeout");
        }
        thread::sleep(Duration::from_millis(25));
    };
    let output = child
        .wait_with_output()
        .expect("collect expected-failure provider output");
    assert_failed_remote_startup(label, status, &output.stdout, &output.stderr);
    let evidence = root.join(format!("remote-provider-{label}-failure.log"));
    write_private_file(&evidence, &output.stderr);
}

fn remote_server_command(
    db_path: &Path,
    provider: &ProviderFixture,
    port: u16,
    config: &Path,
) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_unified_server"));
    command.args([
        "--bind-address",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--data-dir",
        db_path.to_str().expect("UTF-8 database path"),
        "--role",
        "secondary",
        "--disable-onion",
        "--serve-queries",
        "--require-service-auth-v1",
        "--service-policy",
        provider.policy_path.to_str().expect("UTF-8 policy path"),
        "--service-provider-id-hex",
        &hex::encode(provider.provider_id),
        "--service-policy-key-hex",
        &hex::encode(provider.policy_signing_key.verifying_key().to_bytes()),
        "--service-store",
        provider.store_path.to_str().expect("UTF-8 store path"),
        "--service-remote-rollback-authority-config",
        config.to_str().expect("UTF-8 remote authority config"),
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
    ]);
    command
}

fn assert_failed_remote_startup(label: &str, status: ExitStatus, stdout: &[u8], stderr: &[u8]) {
    let stdout = String::from_utf8_lossy(stdout);
    let stderr = String::from_utf8_lossy(stderr);
    assert!(!status.success(), "{label} provider unexpectedly succeeded");
    assert!(
        !stdout.contains("Listening on ws://"),
        "{label} provider listened before failure: {stdout}"
    );
    assert!(
        stderr.to_ascii_lowercase().contains("rollback"),
        "{label} failure did not identify the remote authority boundary: {stderr}"
    );
    assert!(
        !stderr.contains("LOCAL SQLITE SERVICE ROLLBACK AUTHORITY"),
        "{label} failure used the forbidden local fallback: {stderr}"
    );
}

fn assert_remote_server_log(stdout: &str, stderr: &str, port: u16) {
    assert!(stdout.contains(&format!("Listening on ws://127.0.0.1:{port}")));
    assert!(stdout.contains("Provider store startup_check=ok"));
    assert!(stdout.contains("Service admission V1: enforced"));
    assert!(!stderr.contains("LOCAL SQLITE SERVICE ROLLBACK AUTHORITY"));
    assert!(!stderr.contains("UNSAFE DEBUG QUERY LOGGING ENABLED"));
}

fn assert_authority_log_is_coarse(material: &AuthorityMaterial, stdout: &str, stderr: &str) {
    assert!(stdout.contains("rollback-authority-listening=127.0.0.1:"));
    assert!(
        stderr.trim().is_empty(),
        "authority emitted stderr: {stderr}"
    );
    for forbidden in [
        material.authority_instance_id_hex.as_str(),
        material.authority_verifying_key_hex.as_str(),
        material.namespace_hex.as_str(),
        material.client_verifying_key_hex.as_str(),
        material.test_root.to_str().unwrap(),
        "invoice",
        "payment_hash",
        "preimage",
    ] {
        assert!(
            !stdout.contains(forbidden) && !stderr.contains(forbidden),
            "authority process log exposed forbidden material"
        );
    }
}

fn serve_test_tls_edge(
    bind: std::net::SocketAddr,
    backend: std::net::SocketAddr,
    certificate_pem: &[u8],
    private_key_pem: &[u8],
) -> io::Result<()> {
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
    let local = listener.local_addr()?;
    if !local.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "test TLS edge resolved outside loopback",
        ));
    }
    loop {
        let (socket, _) = listener.accept()?;
        let config = Arc::clone(&config);
        if let Err(_error) = proxy_one_tls_request(socket, backend, config) {
            // Readiness probes and malformed handshakes are deliberately
            // silent. The edge emits no peer, request, or authority metadata.
        }
    }
}

fn proxy_one_tls_request(
    socket: TcpStream,
    backend: std::net::SocketAddr,
    config: Arc<ServerConfig>,
) -> io::Result<()> {
    socket.set_read_timeout(Some(TLS_IO_TIMEOUT))?;
    socket.set_write_timeout(Some(TLS_IO_TIMEOUT))?;
    let connection = ServerConnection::new(config).map_err(io::Error::other)?;
    let mut tls = StreamOwned::new(connection, socket);
    let request = read_bounded_http_request(&mut tls)?;

    let mut upstream = TcpStream::connect_timeout(&backend, TLS_IO_TIMEOUT)?;
    upstream.set_read_timeout(Some(TLS_IO_TIMEOUT))?;
    upstream.set_write_timeout(Some(TLS_IO_TIMEOUT))?;
    upstream.write_all(&request)?;
    upstream.shutdown(Shutdown::Write)?;
    let mut response = Vec::new();
    upstream
        .take((MAX_PROXY_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut response)?;
    if response.len() > MAX_PROXY_RESPONSE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "authority response exceeded proxy bound",
        ));
    }
    tls.write_all(&response)?;
    tls.flush()?;
    tls.conn.send_close_notify();
    let _ = tls.flush();
    Ok(())
}

fn read_bounded_http_request(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut request = Vec::new();
    let mut total_length = None;
    loop {
        if request.len() >= MAX_PROXY_REQUEST_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "authority request exceeded proxy bound",
            ));
        }
        let mut chunk = [0_u8; 2048];
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "authority request ended early",
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
                    io::Error::new(io::ErrorKind::InvalidData, "non-ASCII authority headers")
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
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "missing authority content length",
                        )
                    })?;
                let total = header_end.checked_add(content_length).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "authority request overflow")
                })?;
                if total > MAX_PROXY_REQUEST_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "authority request exceeded proxy bound",
                    ));
                }
                total_length = Some(total);
            }
        }
        if total_length.is_some_and(|total| request.len() >= total) {
            if request.len() != total_length.unwrap() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "authority request contained trailing bytes",
                ));
            }
            return Ok(request);
        }
    }
}

fn run_authority_cli(arguments: Vec<String>) {
    let cli = RollbackAuthorityCli::try_parse_from(arguments).expect("parse authority ceremony");
    run_rollback_authority(cli).expect("complete authority ceremony");
}

fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("missing {name}"))
}

fn metadata_field(path: &Path, name: &str) -> String {
    let text = fs::read_to_string(path).expect("read public authority metadata");
    text.lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")))
        .unwrap_or_else(|| panic!("missing metadata field {name}"))
        .to_owned()
}

fn write_private_file(path: &Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .expect("create private test file");
    file.write_all(bytes).expect("write private test file");
    file.sync_all().expect("sync private test file");
    chmod(path, 0o600);
}

fn distinct_unused_port(excluded: &[u16]) -> u16 {
    loop {
        let port = unused_loopback_port();
        if !excluded.contains(&port) {
            return port;
        }
    }
}
