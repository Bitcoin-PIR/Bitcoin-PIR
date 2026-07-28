//! Non-default real-process E2E for the payment-issuer remote rollback floor.
//!
//! The issuer binary, rollback-authority application, and loopback TLS edge
//! execute in distinct OS processes. Private-CA trust exists only behind the
//! explicit test feature; release builds with that feature fail to compile.

#![cfg(all(unix, feature = "remote-authority-process-e2e"))]

use clap::Parser as _;
use rollback_authority::{run as run_rollback_authority, Cli as RollbackAuthorityCli};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const AUTHORITY_HELPER_MARKER: &str = "BITCOINPIR_TEST_ONLY_ISSUER_AUTHORITY_HELPER_V1";
const TLS_HELPER_MARKER: &str = "BITCOINPIR_TEST_ONLY_ISSUER_AUTHORITY_TLS_HELPER_V1";
const TEST_LEAF_SPKI_SHA256_HEX: &str =
    "e91550521f8e17b21d99f7e00b99c08be1b1f31fe57772ac8f904ea50c6a609b";
const PROCESS_START_TIMEOUT: Duration = Duration::from_secs(30);
const PROCESS_EXIT_TIMEOUT: Duration = Duration::from_secs(15);
const TLS_IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PROXY_REQUEST_BYTES: usize = 64 * 1024;
const MAX_PROXY_RESPONSE_BYTES: usize = 256 * 1024;

struct AuthorityMaterial {
    authority_secret: PathBuf,
    authority_metadata: PathBuf,
    authority_store: PathBuf,
    client_secret: PathBuf,
    value_root: PathBuf,
    remote_config: PathBuf,
    wrong_pin_config: PathBuf,
    wrong_ca_config: PathBuf,
    test_root: PathBuf,
    wrong_root: PathBuf,
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
        let address: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
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
            if TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
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

    fn stop(&mut self) -> (String, String) {
        if self
            .child
            .try_wait()
            .expect("poll helper before stop")
            .is_none()
        {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        (read_log(&self.stdout_path), read_log(&self.stderr_path))
    }
}

impl Drop for HelperProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
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

struct ProcessOutput {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

#[test]
#[ignore = "spawned only by payment_issuer_remote_authority_real_process_tls_e2e"]
fn rollback_authority_subprocess() {
    if env::var_os(AUTHORITY_HELPER_MARKER).is_none() {
        return;
    }
    let bind = required_env("BITCOINPIR_TEST_ISSUER_AUTHORITY_BIND");
    let store = required_env("BITCOINPIR_TEST_ISSUER_AUTHORITY_STORE");
    let secret = required_env("BITCOINPIR_TEST_ISSUER_AUTHORITY_SECRET");
    let metadata = required_env("BITCOINPIR_TEST_ISSUER_AUTHORITY_METADATA");
    let public_key = required_env("BITCOINPIR_TEST_ISSUER_AUTHORITY_PUBLIC_KEY");
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
        "32",
    ])
    .expect("parse authority helper CLI");
    run_rollback_authority(cli).expect("serve real rollback-authority process");
}

#[test]
#[ignore = "spawned only by payment_issuer_remote_authority_real_process_tls_e2e"]
fn rollback_authority_tls_edge_subprocess() {
    if env::var_os(TLS_HELPER_MARKER).is_none() {
        return;
    }
    let bind: SocketAddr = required_env("BITCOINPIR_TEST_ISSUER_TLS_BIND")
        .parse()
        .expect("TLS helper bind address");
    let backend: SocketAddr = required_env("BITCOINPIR_TEST_ISSUER_TLS_BACKEND")
        .parse()
        .expect("TLS helper backend address");
    assert!(bind.ip().is_loopback() && backend.ip().is_loopback());
    let certificate = fs::read(required_env("BITCOINPIR_TEST_ISSUER_TLS_CERT"))
        .expect("read TLS helper certificate");
    let private_key =
        fs::read(required_env("BITCOINPIR_TEST_ISSUER_TLS_KEY")).expect("read TLS helper key");
    serve_test_tls_edge(bind, backend, &certificate, &private_key)
        .expect("serve test-only TLS edge");
}

#[test]
fn payment_issuer_remote_authority_real_process_tls_e2e() {
    let root = tempfile::tempdir().expect("remote issuer process test root");
    chmod(root.path(), 0o700);
    let authority_port = distinct_unused_port(&[]);
    let tls_port = distinct_unused_port(&[authority_port]);
    let material = prepare_authority_material(root.path(), tls_port);

    let issuer_dir = root.path().join("issuer-domain");
    fs::create_dir(&issuer_dir).expect("create issuer domain");
    chmod(&issuer_dir, 0o700);
    let issuer_store = issuer_dir.join("issuer.sqlite3");
    let issuer_id_hex = hex::encode([0x91; 32]);
    let store_instance_id_hex = hex::encode([0x42; 16]);

    let mut authority = spawn_authority(root.path(), &material, authority_port, 0);
    authority.wait_until_listening(authority_port);
    let mut tls = spawn_tls_edge(root.path(), &material, tls_port, authority_port, 0);
    tls.wait_until_listening(tls_port);

    let init = run_issuer_bounded(
        root.path(),
        "issuer-init",
        issuer_init_command(
            &issuer_store,
            &material.remote_config,
            &issuer_id_hex,
            &store_instance_id_hex,
        ),
    );
    assert_issuer_success("init-store", &init, &issuer_id_hex, &store_instance_id_hex);
    assert!(init.stdout.contains("rollback_authority_mode=remote"));
    assert!(init
        .stdout
        .contains("rollback_authority_reference=[remote-config-redacted]"));
    assert!(issuer_store.is_file(), "issuer store was not created");
    assert_no_sensitive_logs(&material, "issuer init", &init.stdout, &init.stderr);

    for (label, config) in [
        ("wrong-ca", material.wrong_ca_config.as_path()),
        ("wrong-pin", material.wrong_pin_config.as_path()),
    ] {
        let failed = run_issuer_bounded(
            root.path(),
            label,
            issuer_check_command(&issuer_store, config, &issuer_id_hex),
        );
        assert_issuer_fail_closed(label, &failed);
        assert_no_sensitive_logs(&material, label, &failed.stdout, &failed.stderr);
    }

    // Stopping only the authority leaves the TLS listener reachable. The
    // issuer must still fail rather than trusting its detailed SQLite store.
    let (authority_stdout0, authority_stderr0) = authority.stop();
    assert_authority_log_is_coarse(&material, &authority_stdout0, &authority_stderr0);
    let offline = run_issuer_bounded(
        root.path(),
        "authority-offline",
        issuer_check_command(&issuer_store, &material.remote_config, &issuer_id_hex),
    );
    assert_issuer_fail_closed("authority-offline", &offline);
    assert_no_sensitive_logs(
        &material,
        "authority-offline",
        &offline.stdout,
        &offline.stderr,
    );

    // Restart the authority against the original durable store. A fresh issuer
    // process must reopen the detailed store and accept the preserved floor.
    authority = spawn_authority(root.path(), &material, authority_port, 1);
    authority.wait_until_listening(authority_port);
    let restarted = run_issuer_bounded(
        root.path(),
        "issuer-restarted-check",
        issuer_check_command(&issuer_store, &material.remote_config, &issuer_id_hex),
    );
    assert_issuer_success(
        "restart check-store",
        &restarted,
        &issuer_id_hex,
        &store_instance_id_hex,
    );
    assert!(restarted.stdout.contains("commit_seq=0"));
    assert_no_sensitive_logs(
        &material,
        "issuer restarted check",
        &restarted.stdout,
        &restarted.stderr,
    );

    let (authority_stdout1, authority_stderr1) = authority.stop();
    assert_authority_log_is_coarse(&material, &authority_stdout1, &authority_stderr1);
    let (tls_stdout, tls_stderr) = tls.stop();
    assert_no_sensitive_logs(&material, "TLS edge", &tls_stdout, &tls_stderr);
    assert!(
        tls_stderr.trim().is_empty(),
        "TLS edge emitted stderr: {tls_stderr}"
    );
}

fn issuer_init_command(
    store: &Path,
    config: &Path,
    issuer_id_hex: &str,
    store_instance_id_hex: &str,
) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_payment-issuer"));
    command.args([
        "init-store",
        "--store",
        store.to_str().expect("UTF-8 issuer store path"),
        "--remote-rollback-authority-config",
        config.to_str().expect("UTF-8 authority config path"),
        "--store-instance-id-hex",
        store_instance_id_hex,
        "--issuer-id-hex",
        issuer_id_hex,
        "--network",
        "regtest",
    ]);
    command
}

fn issuer_check_command(store: &Path, config: &Path, issuer_id_hex: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_payment-issuer"));
    command.args([
        "check-store",
        "--store",
        store.to_str().expect("UTF-8 issuer store path"),
        "--remote-rollback-authority-config",
        config.to_str().expect("UTF-8 authority config path"),
        "--issuer-id-hex",
        issuer_id_hex,
        "--network",
        "regtest",
    ]);
    command
}

fn run_issuer_bounded(root: &Path, label: &str, mut command: Command) -> ProcessOutput {
    let stdout_path = root.join(format!("{label}-stdout.log"));
    let stderr_path = root.join(format!("{label}-stderr.log"));
    let stdout = File::create(&stdout_path).expect("create issuer stdout log");
    let stderr = File::create(&stderr_path).expect("create issuer stderr log");
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("spawn payment-issuer binary");
    let deadline = Instant::now() + PROCESS_EXIT_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll payment-issuer") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{label} payment-issuer did not exit before timeout");
        }
        thread::sleep(Duration::from_millis(25));
    };
    ProcessOutput {
        status,
        stdout: read_log(&stdout_path),
        stderr: read_log(&stderr_path),
    }
}

fn assert_issuer_success(
    label: &str,
    output: &ProcessOutput,
    issuer_id_hex: &str,
    store_instance_id_hex: &str,
) {
    assert!(
        output.status.success(),
        "{label} failed\nstdout:\n{}\nstderr:\n{}",
        output.stdout,
        output.stderr
    );
    assert!(output
        .stdout
        .contains(&format!("issuer_id={issuer_id_hex}")));
    assert!(output
        .stdout
        .contains(&format!("store_instance_id={store_instance_id_hex}")));
    assert!(
        output.stderr.trim().is_empty(),
        "{label} emitted stderr: {}",
        output.stderr
    );
}

fn assert_issuer_fail_closed(label: &str, output: &ProcessOutput) {
    assert!(
        !output.status.success(),
        "{label} unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        output.stdout,
        output.stderr
    );
    assert!(
        output.stderr.to_ascii_lowercase().contains("rollback"),
        "{label} did not identify the rollback boundary: {}",
        output.stderr
    );
    assert!(
        !output
            .stderr
            .contains("local SQLite issuer rollback authority"),
        "{label} used a local rollback fallback: {}",
        output.stderr
    );
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
        include_bytes!("../../server/tests/testdata/remote-authority-process-root.pem"),
    );
    write_private_file(
        &wrong_root,
        include_bytes!("../../../crates/net/strict-https/src/testdata/wrong-root.pem"),
    );
    write_private_file(
        &leaf_certificate,
        include_bytes!("../../server/tests/testdata/remote-authority-process-leaf.pem"),
    );
    write_private_file(
        &leaf_private_key,
        include_bytes!("../../server/tests/testdata/remote-authority-process-leaf.key"),
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
        client_secret,
        value_root,
        remote_config,
        wrong_pin_config,
        wrong_ca_config,
        test_root,
        wrong_root,
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

fn spawn_authority(
    root: &Path,
    material: &AuthorityMaterial,
    port: u16,
    generation: u8,
) -> HelperProcess {
    HelperProcess::spawn(
        root,
        "issuer-rollback-authority-process",
        generation,
        "rollback_authority_subprocess",
        &[
            (AUTHORITY_HELPER_MARKER, "1".to_owned()),
            (
                "BITCOINPIR_TEST_ISSUER_AUTHORITY_BIND",
                format!("127.0.0.1:{port}"),
            ),
            (
                "BITCOINPIR_TEST_ISSUER_AUTHORITY_STORE",
                material.authority_store.display().to_string(),
            ),
            (
                "BITCOINPIR_TEST_ISSUER_AUTHORITY_SECRET",
                material.authority_secret.display().to_string(),
            ),
            (
                "BITCOINPIR_TEST_ISSUER_AUTHORITY_METADATA",
                material.authority_metadata.display().to_string(),
            ),
            (
                "BITCOINPIR_TEST_ISSUER_AUTHORITY_PUBLIC_KEY",
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
        "issuer-rollback-authority-tls-edge-process",
        generation,
        "rollback_authority_tls_edge_subprocess",
        &[
            (TLS_HELPER_MARKER, "1".to_owned()),
            (
                "BITCOINPIR_TEST_ISSUER_TLS_BIND",
                format!("127.0.0.1:{tls_port}"),
            ),
            (
                "BITCOINPIR_TEST_ISSUER_TLS_BACKEND",
                format!("127.0.0.1:{authority_port}"),
            ),
            (
                "BITCOINPIR_TEST_ISSUER_TLS_CERT",
                material.leaf_certificate.display().to_string(),
            ),
            (
                "BITCOINPIR_TEST_ISSUER_TLS_KEY",
                material.leaf_private_key.display().to_string(),
            ),
        ],
    )
}

fn assert_authority_log_is_coarse(material: &AuthorityMaterial, stdout: &str, stderr: &str) {
    assert!(stdout.contains("rollback-authority-listening=127.0.0.1:"));
    assert!(
        stderr.trim().is_empty(),
        "authority emitted stderr: {stderr}"
    );
    assert_no_sensitive_logs(material, "authority", stdout, stderr);
}

fn assert_no_sensitive_logs(material: &AuthorityMaterial, label: &str, stdout: &str, stderr: &str) {
    let combined = format!("{stdout}\n{stderr}");
    let secret_hex = [
        hex::encode(fs::read(&material.authority_secret).expect("read authority seed")),
        hex::encode(fs::read(&material.client_secret).expect("read client seed")),
        hex::encode(fs::read(&material.value_root).expect("read value root")),
    ];
    let config_paths = [
        material.remote_config.display().to_string(),
        material.wrong_pin_config.display().to_string(),
        material.wrong_ca_config.display().to_string(),
        material.test_root.display().to_string(),
        material.wrong_root.display().to_string(),
    ];
    for forbidden in [
        material.authority_instance_id_hex.as_str(),
        material.authority_verifying_key_hex.as_str(),
        material.namespace_hex.as_str(),
        material.client_verifying_key_hex.as_str(),
        secret_hex[0].as_str(),
        secret_hex[1].as_str(),
        secret_hex[2].as_str(),
        config_paths[0].as_str(),
        config_paths[1].as_str(),
        config_paths[2].as_str(),
        config_paths[3].as_str(),
        config_paths[4].as_str(),
        "remote-authority.toml",
        "remote-authority-wrong-pin.toml",
        "remote-authority-wrong-ca.toml",
    ] {
        assert!(
            !combined.contains(forbidden),
            "{label} log exposed forbidden material"
        );
    }
    let lowercase = combined.to_ascii_lowercase();
    for forbidden in ["invoice", "payment_hash", "payment hash", "preimage"] {
        assert!(
            !lowercase.contains(forbidden),
            "{label} log exposed {forbidden}"
        );
    }
}

fn serve_test_tls_edge(
    bind: SocketAddr,
    backend: SocketAddr,
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
    if !listener.local_addr()?.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "test TLS edge resolved outside loopback",
        ));
    }
    loop {
        let (socket, _) = listener.accept()?;
        if let Err(_error) = proxy_one_tls_request(socket, backend, Arc::clone(&config)) {
            // Readiness probes, rejected TLS clients, and unavailable backends
            // are deliberately silent and reveal no request metadata.
        }
    }
}

fn proxy_one_tls_request(
    socket: TcpStream,
    backend: SocketAddr,
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

fn read_log(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| format!("<failed to read log: {error}>"))
}

fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set private permissions");
}

fn unused_loopback_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .expect("bind ephemeral loopback port")
        .local_addr()
        .expect("read ephemeral loopback address")
        .port()
}

fn distinct_unused_port(excluded: &[u16]) -> u16 {
    loop {
        let port = unused_loopback_port();
        if !excluded.contains(&port) {
            return port;
        }
    }
}
