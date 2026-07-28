#![cfg(unix)]

use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use clap::Parser;
use ed25519_dalek::SigningKey;
use pir_rollback_authority_protocol::{
    authority_client_key_id_v1, verify_authority_read_response_v1, verify_authority_response_v1,
    AuthorityCallV1, AuthorityClientSignerV1, AuthorityServerSignerV1, AuthorityValueCodecV1,
    AuthorityValueRootKeyV1, VerifiedAuthorityCasOutcomeV1, VerifiedAuthorityResponseBodyRefV1,
};
use pir_rollback_authority_store::{
    RollbackAuthorityStoreErrorV1, SqliteRollbackAuthorityProvisionerV1,
    SqliteRollbackAuthorityStoreV1, MAX_OPERATION_ROWS_PER_NAMESPACE_V1,
};
use tempfile::TempDir;
use zeroize::Zeroize;

use super::http::{
    worker_count_for_limit_v1, AuthorityHttpStateV1, ConnectionLimiterV1,
    AUTHORITY_ACCEPT_VALUE_V1, MAX_ADMITTED_CONNECTIONS_V1, MAX_WORKER_THREADS_V1,
    STRICT_CLIENT_USER_AGENT_V1,
};
use super::material::{self, AuthorityPublicMetadataV1, ClientProvisioningMetadataV1};
use super::{
    generated_material_summary_v1, init_store_error_v1, operation_capacity_summary_v1, run,
    serve_v1, Cli, ServeArgs,
};
use crate::{
    AUTHORITY_CALL_MEDIA_TYPE_V1, AUTHORITY_CALL_PATH_V1, AUTHORITY_RESPONSE_MEDIA_TYPE_V1,
};

const TIMEOUT: Duration = Duration::from_secs(3);
const TEST_OPERATION_ROWS: u64 = 32;

struct FixtureV1 {
    _directory: TempDir,
    authority_secret_path: PathBuf,
    store_path: PathBuf,
    authority: AuthorityPublicMetadataV1,
    client_signer: AuthorityClientSignerV1,
    codec: AuthorityValueCodecV1,
    state: Option<AuthorityHttpStateV1>,
}

impl FixtureV1 {
    fn new() -> Self {
        let directory = private_tempdir_v1();
        let authority_secret_path = directory.path().join("authority.seed");
        let authority_metadata_path = directory.path().join("authority-public.txt");
        let client_secret_path = directory.path().join("client.seed");
        let value_root_key_path = directory.path().join("value-root-key.raw");
        let client_metadata_path = directory.path().join("client-provisioning.txt");
        let store_path = directory.path().join("authority.sqlite3");

        let authority =
            material::generate_authority_v1(&authority_secret_path, &authority_metadata_path)
                .expect("generate authority material");
        let client = material::generate_client_v1(
            &client_secret_path,
            &value_root_key_path,
            &client_metadata_path,
        )
        .expect("generate client material");
        let provisioner = SqliteRollbackAuthorityProvisionerV1::create(
            &store_path,
            authority.authority_instance_id,
            TIMEOUT,
        )
        .expect("create store");
        provisioner
            .provision_namespace(
                client.namespace,
                &client.client_verifying_key,
                TEST_OPERATION_ROWS,
                TEST_OPERATION_ROWS * 4,
            )
            .expect("provision namespace");
        let store = provisioner.into_online();

        let mut authority_secret =
            material::read_secret_seed_v1(&authority_secret_path).expect("authority secret");
        let authority_signing_key = SigningKey::from_bytes(&authority_secret);
        authority_secret.zeroize();
        let authority_signer =
            AuthorityServerSignerV1::new(authority.authority_instance_id, authority_signing_key)
                .expect("authority signer");

        let mut client_secret =
            material::read_secret_seed_v1(&client_secret_path).expect("client secret");
        let client_signing_key = SigningKey::from_bytes(&client_secret);
        client_secret.zeroize();
        let client_signer = AuthorityClientSignerV1::new(
            authority.authority_instance_id,
            client.namespace,
            client_signing_key,
        )
        .expect("client signer");
        let mut value_root = material::read_value_root_key_for_tests_v1(&value_root_key_path)
            .expect("value root key");
        let root = AuthorityValueRootKeyV1::from_bytes(*value_root).expect("root key");
        value_root.zeroize();
        let codec = AuthorityValueCodecV1::derive(
            &root,
            authority.authority_instance_id,
            client.namespace,
            &client.client_verifying_key,
        )
        .expect("value codec");
        let state = AuthorityHttpStateV1::new(store, authority_signer, TIMEOUT);

        Self {
            _directory: directory,
            authority_secret_path,
            store_path,
            authority,
            client_signer,
            codec,
            state: Some(state),
        }
    }

    fn exchange(&self, request: &[u8]) -> Vec<u8> {
        exchange_v1(self.state.as_ref().expect("online state"), request)
    }

    fn restart(&mut self) {
        drop(self.state.take());
        let store = SqliteRollbackAuthorityStoreV1::open_existing(
            &self.store_path,
            self.authority.authority_instance_id,
            TIMEOUT,
        )
        .expect("reopen store");
        let mut seed = material::read_secret_seed_v1(&self.authority_secret_path)
            .expect("reopen authority secret");
        let signer = AuthorityServerSignerV1::new(
            self.authority.authority_instance_id,
            SigningKey::from_bytes(&seed),
        )
        .expect("reopen signer");
        seed.zeroize();
        self.state = Some(AuthorityHttpStateV1::new(store, signer, TIMEOUT));
    }
}

fn private_tempdir_v1() -> TempDir {
    let directory = tempfile::Builder::new()
        .prefix("bpir-rollback-authority-app-")
        .tempdir()
        .expect("temporary directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("private temporary directory");
    directory
}

fn canonical_request_v1(body: &[u8]) -> Vec<u8> {
    request_v1(
        "POST",
        AUTHORITY_CALL_PATH_V1,
        AUTHORITY_CALL_MEDIA_TYPE_V1,
        AUTHORITY_ACCEPT_VALUE_V1,
        &body.len().to_string(),
        "",
        body,
    )
}

#[allow(clippy::too_many_arguments)]
fn request_v1(
    method: &str,
    path: &str,
    content_type: &str,
    accept: &str,
    content_length: &str,
    extra_headers: &str,
    body: &[u8],
) -> Vec<u8> {
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: authority.invalid\r\nContent-Type: {content_type}\r\nAccept: {accept}\r\nContent-Length: {content_length}\r\nConnection: close\r\nUser-Agent: {STRICT_CLIENT_USER_AGENT_V1}\r\n{extra_headers}\r\n"
    )
    .into_bytes();
    request.extend_from_slice(body);
    request
}

fn exchange_v1(state: &AuthorityHttpStateV1, request: &[u8]) -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").expect("test listener");
    let address = listener.local_addr().expect("listener address");
    thread::scope(|scope| {
        let mut client = TcpStream::connect(address).expect("connect request");
        client.write_all(request).expect("write request");
        client.shutdown(Shutdown::Write).expect("finish request");
        let handler = scope.spawn(|| {
            let (stream, _) = listener.accept().expect("accept request");
            super::http::handle_connection_v1(stream, state);
        });
        client
            .set_read_timeout(Some(TIMEOUT))
            .expect("response timeout");
        let mut response = Vec::new();
        client.read_to_end(&mut response).expect("read response");
        handler.join().expect("request handler");
        response
    })
}

fn split_response_v1(response: &[u8]) -> (&str, &[u8]) {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .expect("response headers");
    (
        std::str::from_utf8(&response[..header_end]).expect("ASCII response headers"),
        &response[header_end..],
    )
}

fn generation_error_v1<T>(result: Result<T, String>) -> String {
    match result {
        Ok(_) => panic!("generation unexpectedly succeeded"),
        Err(error) => error,
    }
}

#[test]
fn signed_read_initialize_and_restart_round_trip_over_http() {
    let mut fixture = FixtureV1::new();

    let empty_attempt = fixture
        .client_signer
        .sign_fresh_read()
        .expect("read attempt");
    let empty_response = fixture.exchange(&canonical_request_v1(empty_attempt.as_bytes()));
    let (empty_headers, empty_body) = split_response_v1(&empty_response);
    assert!(empty_headers.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(empty_headers.contains(&format!(
        "Content-Type: {AUTHORITY_RESPONSE_MEDIA_TYPE_V1}\r\n"
    )));
    assert!(empty_headers.contains("Connection: close\r\n"));
    assert!(empty_headers.contains("Cache-Control: no-store\r\n"));
    assert!(empty_headers.contains("X-Content-Type-Options: nosniff\r\n"));
    assert!(!empty_headers.to_ascii_lowercase().contains("set-cookie"));
    assert!(!empty_headers
        .to_ascii_lowercase()
        .contains("access-control"));
    let verified_empty = verify_authority_read_response_v1(
        empty_body,
        empty_attempt,
        &fixture.authority.authority_verifying_key,
    )
    .expect("verify empty read");
    assert!(matches!(
        verified_empty.body(),
        VerifiedAuthorityResponseBodyRefV1::Read { current: None }
    ));

    let desired = fixture.codec.seal(0, b"durable-floor").expect("seal floor");
    let call = AuthorityCallV1::from_parts([0x61; 32], [0x71; 32]).expect("CAS call");
    let initialize = fixture
        .client_signer
        .sign_compare_and_swap(&call, None, &desired)
        .expect("sign initialize");
    let initialize_response = fixture.exchange(&canonical_request_v1(initialize.as_bytes()));
    let (_, initialize_body) = split_response_v1(&initialize_response);
    let verified_initialize = verify_authority_response_v1(
        initialize_body,
        &initialize,
        &fixture.authority.authority_verifying_key,
    )
    .expect("verify initialize");
    assert!(matches!(
        verified_initialize.body(),
        VerifiedAuthorityResponseBodyRefV1::CompareAndSwap(VerifiedAuthorityCasOutcomeV1::Applied(
            _
        ))
    ));

    fixture.restart();
    let current_attempt = fixture
        .client_signer
        .sign_fresh_read()
        .expect("restart read");
    let current_response = fixture.exchange(&canonical_request_v1(current_attempt.as_bytes()));
    let (_, current_body) = split_response_v1(&current_response);
    let verified_current = verify_authority_read_response_v1(
        current_body,
        current_attempt,
        &fixture.authority.authority_verifying_key,
    )
    .expect("verify restart read");
    match verified_current.body() {
        VerifiedAuthorityResponseBodyRefV1::Read {
            current: Some(record),
        } => assert_eq!(record.revision(), 0),
        other => panic!("unexpected restart response: {other:?}"),
    }
}

#[test]
fn strict_http_rejects_method_path_media_length_and_pipelining() {
    let fixture = FixtureV1::new();
    let cases = [
        request_v1(
            "GET",
            AUTHORITY_CALL_PATH_V1,
            AUTHORITY_CALL_MEDIA_TYPE_V1,
            AUTHORITY_ACCEPT_VALUE_V1,
            "0",
            "",
            &[],
        ),
        request_v1(
            "POST",
            "/v1/rollback-authority/calls?query=1",
            AUTHORITY_CALL_MEDIA_TYPE_V1,
            AUTHORITY_ACCEPT_VALUE_V1,
            "0",
            "",
            &[],
        ),
        request_v1(
            "POST",
            AUTHORITY_CALL_PATH_V1,
            "application/octet-stream",
            AUTHORITY_ACCEPT_VALUE_V1,
            "0",
            "",
            &[],
        ),
        request_v1(
            "POST",
            AUTHORITY_CALL_PATH_V1,
            AUTHORITY_CALL_MEDIA_TYPE_V1,
            "*/*",
            "0",
            "",
            &[],
        ),
        request_v1(
            "POST",
            AUTHORITY_CALL_PATH_V1,
            AUTHORITY_CALL_MEDIA_TYPE_V1,
            AUTHORITY_ACCEPT_VALUE_V1,
            "01",
            "",
            &[0],
        ),
        request_v1(
            "POST",
            AUTHORITY_CALL_PATH_V1,
            AUTHORITY_CALL_MEDIA_TYPE_V1,
            AUTHORITY_ACCEPT_VALUE_V1,
            "0",
            "Transfer-Encoding: chunked\r\n",
            &[],
        ),
    ];
    for request in cases {
        let response = fixture.exchange(&request);
        let (headers, _) = split_response_v1(&response);
        assert!(!headers.starts_with("HTTP/1.1 200"), "{headers}");
        assert!(headers.contains("Connection: close\r\n"));
    }

    let attempt = fixture.client_signer.sign_fresh_read().expect("read");
    let mut pipelined = canonical_request_v1(attempt.as_bytes());
    pipelined.extend_from_slice(&canonical_request_v1(attempt.as_bytes()));
    let response = fixture.exchange(&pipelined);
    assert!(split_response_v1(&response)
        .0
        .starts_with("HTTP/1.1 400 Bad Request\r\n"));
}

#[test]
fn unknown_namespace_and_bad_signature_have_identical_http_response() {
    let fixture = FixtureV1::new();
    let mut bad_signature = fixture
        .client_signer
        .sign_fresh_read()
        .expect("bad-signature read")
        .into_bytes();
    let final_byte = bad_signature.len() - 1;
    bad_signature[final_byte] ^= 1;
    let bad_signature_response = fixture.exchange(&canonical_request_v1(&bad_signature));

    let unknown = AuthorityClientSignerV1::new(
        fixture.authority.authority_instance_id,
        [0xA7; 32],
        SigningKey::from_bytes(&[0xB7; 32]),
    )
    .expect("unknown signer")
    .sign_fresh_read()
    .expect("unknown read");
    let unknown_response = fixture.exchange(&canonical_request_v1(unknown.as_bytes()));
    assert_eq!(bad_signature_response, unknown_response);

    let first_desired = fixture.codec.seal(0, b"first").expect("first floor");
    let first_call = AuthorityCallV1::from_parts([0x41; 32], [0x51; 32]).expect("first call");
    let first_request = fixture
        .client_signer
        .sign_compare_and_swap(&first_call, None, &first_desired)
        .expect("first CAS");
    assert!(
        split_response_v1(&fixture.exchange(&canonical_request_v1(first_request.as_bytes())))
            .0
            .starts_with("HTTP/1.1 200 OK\r\n")
    );
    let divergent_desired = fixture
        .codec
        .seal(0, b"divergent")
        .expect("divergent floor");
    let divergent_call =
        AuthorityCallV1::from_parts([0x42; 32], [0x51; 32]).expect("divergent call");
    let divergent_request = fixture
        .client_signer
        .sign_compare_and_swap(&divergent_call, None, &divergent_desired)
        .expect("divergent CAS");
    let replay_response = fixture.exchange(&canonical_request_v1(divergent_request.as_bytes()));
    assert_eq!(bad_signature_response, replay_response);

    let (headers, body) = split_response_v1(&unknown_response);
    assert!(headers.starts_with("HTTP/1.1 401 Unauthorized\r\n"));
    assert_eq!(body, br#"{"code":"request_rejected"}"#);
}

#[test]
fn fixed_worker_pool_and_total_admission_are_conservatively_bounded() {
    assert_eq!(worker_count_for_limit_v1(1), 1);
    assert_eq!(
        worker_count_for_limit_v1(MAX_WORKER_THREADS_V1),
        MAX_WORKER_THREADS_V1
    );
    assert_eq!(
        worker_count_for_limit_v1(MAX_ADMITTED_CONNECTIONS_V1),
        MAX_WORKER_THREADS_V1
    );

    let limiter = Arc::new(ConnectionLimiterV1::new(3));
    let first = limiter.try_acquire().expect("first permit");
    let second = limiter.try_acquire().expect("second permit");
    let third = limiter.try_acquire().expect("third permit");
    assert!(limiter.try_acquire().is_none());
    drop(second);
    let replacement = limiter.try_acquire().expect("released permit reused");
    assert!(limiter.try_acquire().is_none());
    drop((first, third, replacement));
}

#[test]
fn generation_creates_three_distinct_private_client_files_without_secret_metadata() {
    let directory = private_tempdir_v1();
    let secret_path = directory.path().join("client.seed");
    let root_path = directory.path().join("value-root-key.raw");
    let metadata_path = directory.path().join("client.txt");
    let metadata = material::generate_client_v1(&secret_path, &root_path, &metadata_path)
        .expect("generate client");
    let secret = material::read_secret_seed_v1(&secret_path).expect("client secret");
    let root = material::read_value_root_key_for_tests_v1(&root_path).expect("value root");
    assert!(secret.iter().any(|byte| *byte != 0));
    assert!(root.iter().any(|byte| *byte != 0));
    let encoded = fs::read_to_string(&metadata_path).expect("metadata text");
    assert_eq!(encoded, metadata.encode());
    let fields: Vec<&str> = encoded.lines().collect();
    assert_eq!(fields.len(), 4);
    assert_eq!(fields[0], "bitcoinpir_rollback_authority_client_v1");
    assert!(fields[1].starts_with("namespace="));
    assert!(fields[2].starts_with("client_key_id="));
    assert!(fields[3].starts_with("client_verifying_key="));
    assert!(!encoded.contains("secret"));
    assert!(!encoded.contains("value_root"));

    for path in [&secret_path, &root_path, &metadata_path] {
        let file = fs::metadata(path).expect("private file");
        assert_eq!(file.mode() & 0o777, 0o600);
        assert_eq!(file.nlink(), 1);
    }
}

#[test]
fn generation_preflight_rejects_aliases_and_existing_outputs_without_writes() {
    let directory = private_tempdir_v1();
    let alias = directory.path().join("same.raw");
    let alias_with_dot = directory.path().join(".").join("same.raw");
    let metadata = directory.path().join("client.txt");
    let error = generation_error_v1(material::generate_client_v1(
        &alias,
        &alias_with_dot,
        &metadata,
    ));
    assert!(error.contains("distinct"));
    assert!(!alias.exists());
    assert!(!metadata.exists());

    fs::write(&metadata, b"existing").expect("existing metadata");
    fs::set_permissions(&metadata, fs::Permissions::from_mode(0o600))
        .expect("metadata permissions");
    let secret = directory.path().join("new.seed");
    let root = directory.path().join("new-root.raw");
    let before = fs::read(&metadata).expect("existing bytes");
    assert!(material::generate_client_v1(&secret, &root, &metadata).is_err());
    assert!(!secret.exists());
    assert!(!root.exists());
    assert_eq!(fs::read(&metadata).expect("unchanged bytes"), before);
}

#[test]
fn partial_client_ceremony_keeps_created_files_and_reports_exact_stage() {
    let directory = private_tempdir_v1();
    let secret = directory.path().join("client.seed");
    let root = directory.path().join("value-root-key.raw");
    let metadata = directory.path().join("client.txt");
    let error = generation_error_v1(material::generate_client_failing_at_stage_for_tests_v1(
        &secret, &root, &metadata, 3,
    ));
    assert!(error.contains("partial client generation"));
    assert!(error.contains("signing secret and value root key were created"));
    assert!(secret.exists());
    assert!(root.exists());
    assert!(!metadata.exists());
    assert_eq!(fs::metadata(&secret).expect("secret").len(), 32);
    assert_eq!(fs::metadata(&root).expect("root").len(), 32);
}

#[test]
fn private_material_reads_reject_symlinks_hardlinks_and_bad_modes() {
    let directory = private_tempdir_v1();
    let authority_secret = directory.path().join("authority.seed");
    let authority_metadata = directory.path().join("authority.txt");
    material::generate_authority_v1(&authority_secret, &authority_metadata)
        .expect("authority material");

    let symlink_path = directory.path().join("secret-link");
    symlink(&authority_secret, &symlink_path).expect("secret symlink");
    assert!(material::read_secret_seed_v1(&symlink_path).is_err());

    let hardlink_path = directory.path().join("secret-hardlink");
    fs::hard_link(&authority_secret, &hardlink_path).expect("secret hard link");
    assert!(material::read_secret_seed_v1(&authority_secret).is_err());
    assert!(material::read_secret_seed_v1(&hardlink_path).is_err());
    fs::remove_file(&hardlink_path).expect("remove hard link");

    fs::set_permissions(&authority_metadata, fs::Permissions::from_mode(0o640))
        .expect("weaken metadata permissions");
    assert!(material::read_authority_metadata_v1(&authority_metadata).is_err());

    let public_parent = private_tempdir_v1();
    fs::set_permissions(public_parent.path(), fs::Permissions::from_mode(0o755))
        .expect("public parent permissions");
    let unsafe_secret = public_parent.path().join("unsafe.seed");
    let unsafe_metadata = public_parent.path().join("unsafe.txt");
    assert!(material::generate_authority_v1(&unsafe_secret, &unsafe_metadata).is_err());
    assert!(!unsafe_secret.exists());
    assert!(!unsafe_metadata.exists());
}

#[cfg(target_os = "macos")]
#[test]
fn private_material_rejects_parent_and_file_extended_acls() {
    use std::process::Command;

    let parent_acl = private_tempdir_v1();
    assert!(Command::new("chmod")
        .args(["+a", "everyone allow read,readattr,file_inherit"])
        .arg(parent_acl.path())
        .status()
        .unwrap()
        .success());
    let secret = parent_acl.path().join("authority.seed");
    let metadata = parent_acl.path().join("authority.txt");
    assert!(material::generate_authority_v1(&secret, &metadata).is_err());
    assert!(!secret.exists());
    assert!(!metadata.exists());

    let file_acl = private_tempdir_v1();
    let secret = file_acl.path().join("authority.seed");
    let metadata = file_acl.path().join("authority.txt");
    material::generate_authority_v1(&secret, &metadata).unwrap();
    assert!(Command::new("chmod")
        .args(["+a", "everyone allow read"])
        .arg(&secret)
        .status()
        .unwrap()
        .success());
    assert!(material::read_secret_seed_v1(&secret).is_err());
}

#[test]
fn serve_requires_loopback_and_exact_authority_pin_before_listening() {
    let non_loopback = ServeArgs {
        bind: "0.0.0.0:8099".parse::<SocketAddr>().expect("socket"),
        store: PathBuf::from("unused"),
        authority_secret: PathBuf::from("unused"),
        authority_metadata: PathBuf::from("unused"),
        expected_authority_pubkey_hex: "00".repeat(32),
        busy_timeout_ms: 1_000,
        io_timeout_ms: 1_000,
        max_connections: 1,
    };
    assert!(serve_v1(non_loopback)
        .expect_err("remote bind rejected")
        .contains("loopback"));

    let directory = private_tempdir_v1();
    let authority_secret = directory.path().join("authority.seed");
    let authority_metadata = directory.path().join("authority.txt");
    let store = directory.path().join("authority.sqlite3");
    let metadata = material::generate_authority_v1(&authority_secret, &authority_metadata)
        .expect("authority material");
    SqliteRollbackAuthorityProvisionerV1::create(&store, metadata.authority_instance_id, TIMEOUT)
        .expect("authority store");
    let wrong_pin = if metadata.authority_verifying_key.as_bytes() == &[0xFF; 32] {
        "00".repeat(32)
    } else {
        "ff".repeat(32)
    };
    let mismatched = ServeArgs {
        bind: "127.0.0.1:0".parse().expect("socket"),
        store,
        authority_secret,
        authority_metadata,
        expected_authority_pubkey_hex: wrong_pin,
        busy_timeout_ms: 1_000,
        io_timeout_ms: 1_000,
        max_connections: 1,
    };
    assert!(serve_v1(mismatched)
        .expect_err("pin mismatch rejected")
        .contains("expected public-key pin"));
}

#[test]
fn generate_client_cli_requires_value_root_key_output() {
    assert!(Cli::try_parse_from([
        "rollback-authority",
        "generate-client",
        "--secret-out",
        "/tmp/client.seed",
        "--metadata-out",
        "/tmp/client.txt",
    ])
    .is_err());
}

#[test]
fn provision_rejects_authority_key_reused_as_client_key() {
    let directory = private_tempdir_v1();
    let authority_secret = directory.path().join("authority.seed");
    let authority_metadata = directory.path().join("authority.txt");
    let authority = material::generate_authority_v1(&authority_secret, &authority_metadata)
        .expect("authority material");
    let client_metadata_path = directory.path().join("client.txt");
    let client_metadata = ClientProvisioningMetadataV1 {
        namespace: [0xA5; 32],
        client_key_id: authority_client_key_id_v1(&authority.authority_verifying_key),
        client_verifying_key: authority.authority_verifying_key,
    };
    fs::write(&client_metadata_path, client_metadata.encode()).expect("client metadata");
    fs::set_permissions(&client_metadata_path, fs::Permissions::from_mode(0o600))
        .expect("client metadata permissions");

    let cli = Cli::try_parse_from([
        "rollback-authority",
        "provision",
        "--store",
        directory.path().join("missing.sqlite3").to_str().unwrap(),
        "--authority-metadata",
        authority_metadata.to_str().unwrap(),
        "--client-metadata",
        client_metadata_path.to_str().unwrap(),
        "--max-operation-rows",
        "1000",
        "--max-call-rows",
        "4000",
    ])
    .expect("provision CLI");
    assert!(run(cli)
        .expect_err("role collision rejected")
        .contains("must be independent"));
}

#[test]
fn provision_cli_requires_explicit_operation_capacity() {
    assert!(Cli::try_parse_from([
        "rollback-authority",
        "provision",
        "--store",
        "/tmp/authority.sqlite3",
        "--authority-metadata",
        "/tmp/authority.txt",
        "--client-metadata",
        "/tmp/client.txt",
        "--max-call-rows",
        "1000",
    ])
    .is_err());
}

#[test]
fn provision_cli_requires_explicit_call_capacity() {
    assert!(Cli::try_parse_from([
        "rollback-authority",
        "provision",
        "--store",
        "/tmp/authority.sqlite3",
        "--authority-metadata",
        "/tmp/authority.txt",
        "--client-metadata",
        "/tmp/client.txt",
        "--max-operation-rows",
        "1000",
    ])
    .is_err());
}

#[test]
fn provision_cli_rejects_operation_capacity_outside_finite_v1_range_before_io() {
    for invalid in [0, MAX_OPERATION_ROWS_PER_NAMESPACE_V1 + 1] {
        let invalid = invalid.to_string();
        let cli = Cli::try_parse_from([
            "rollback-authority",
            "provision",
            "--store",
            "/does/not/exist/authority.sqlite3",
            "--authority-metadata",
            "/does/not/exist/authority.txt",
            "--client-metadata",
            "/does/not/exist/client.txt",
            "--max-operation-rows",
            invalid.as_str(),
            "--max-call-rows",
            "1000",
        ])
        .expect("syntactically valid provision CLI");
        let error = run(cli).expect_err("capacity outside V1 range rejected");
        assert!(error.contains("--max-operation-rows must be in"));
        assert!(!error.contains("file"));
    }
}

#[test]
fn provision_cli_rejects_call_capacity_outside_finite_v1_range_before_io() {
    for invalid in [
        0,
        pir_rollback_authority_store::MAX_CALL_ROWS_PER_NAMESPACE_V1 + 1,
    ] {
        let invalid = invalid.to_string();
        let cli = Cli::try_parse_from([
            "rollback-authority",
            "provision",
            "--store",
            "/does/not/exist/authority.sqlite3",
            "--authority-metadata",
            "/does/not/exist/authority.txt",
            "--client-metadata",
            "/does/not/exist/client.txt",
            "--max-operation-rows",
            "1000",
            "--max-call-rows",
            invalid.as_str(),
        ])
        .expect("syntactically valid provision CLI");
        let error = run(cli).expect_err("capacity outside V1 range rejected");
        assert!(error.contains("--max-call-rows must be in"));
        assert!(!error.contains("file"));
    }
}

#[test]
fn check_store_fails_when_unprovisioned_and_reports_exact_private_capacity() {
    let directory = private_tempdir_v1();
    let authority_secret = directory.path().join("authority.seed");
    let authority_metadata = directory.path().join("authority.txt");
    let store = directory.path().join("authority.sqlite3");
    let authority = material::generate_authority_v1(&authority_secret, &authority_metadata)
        .expect("authority material");
    let provisioner = SqliteRollbackAuthorityProvisionerV1::create(
        &store,
        authority.authority_instance_id,
        TIMEOUT,
    )
    .expect("authority store");

    let check_cli = || {
        Cli::try_parse_from([
            "rollback-authority",
            "check-store",
            "--store",
            store.to_str().unwrap(),
            "--authority-metadata",
            authority_metadata.to_str().unwrap(),
        ])
        .expect("check-store CLI")
    };
    assert!(run(check_cli())
        .expect_err("unprovisioned store rejected")
        .contains("namespace is unprovisioned"));

    let client = SigningKey::from_bytes(&[0xB5; 32]);
    provisioner
        .provision_namespace([0xC5; 32], &client.verifying_key(), 7, 11)
        .unwrap();
    let inventory = provisioner.operation_capacity_inventory().unwrap();
    assert_eq!(
        operation_capacity_summary_v1(&inventory).unwrap(),
        "result=ok\nnamespace_status=provisioned\noperation_rows_used=0\noperation_rows_max=7\ncall_rows_used=0\ncall_rows_max=11\n"
    );
    run(check_cli()).expect("provisioned check-store");
}

#[test]
fn generation_summary_contains_no_linkable_public_metadata() {
    let path = PathBuf::from("/private/operator/client-provisioning.txt");
    let summary = generated_material_summary_v1("client", &path);
    assert!(summary.contains("result=ok"));
    assert!(summary.contains("metadata_path="));
    assert!(!summary.contains("namespace="));
    assert!(!summary.contains("client_key_id="));
    assert!(!summary.contains("client_verifying_key="));
}

#[test]
fn init_store_failure_warns_only_when_partial_output_may_exist() {
    let path = PathBuf::from("/private/operator/authority.sqlite3");
    let partial = init_store_error_v1(&path, RollbackAuthorityStoreErrorV1::StorageFailure);
    assert!(partial.contains("partial initialization may remain"));
    assert!(partial.contains("do not delete, overwrite, or rerun automatically"));
    assert!(partial.contains("check-store"));

    let preflight =
        init_store_error_v1(&path, RollbackAuthorityStoreErrorV1::DatabaseAlreadyExists);
    assert!(!preflight.contains("partial initialization may remain"));
}

#[test]
fn canonical_metadata_parsers_reject_modified_key_ids_and_noncanonical_hex() {
    let directory = private_tempdir_v1();
    let secret = directory.path().join("client.seed");
    let root = directory.path().join("root.raw");
    let metadata_path = directory.path().join("client.txt");
    let metadata =
        material::generate_client_v1(&secret, &root, &metadata_path).expect("client material");
    let namespace_hex = hex::encode(metadata.namespace);
    let uppercase_namespace = format!("A{}", &namespace_hex[1..]);
    let uppercase = metadata
        .encode()
        .replacen(&namespace_hex, &uppercase_namespace, 1);
    fs::write(&metadata_path, uppercase).expect("rewrite metadata");
    assert!(material::read_client_metadata_v1(&metadata_path).is_err());

    let wrong_id_path = directory.path().join("wrong-client.txt");
    let key_id_hex = hex::encode(metadata.client_key_id);
    let replacement_prefix = if key_id_hex.starts_with('0') {
        "1"
    } else {
        "0"
    };
    let wrong_key_id = format!("{replacement_prefix}{}", &key_id_hex[1..]);
    let wrong = metadata.encode().replace(&key_id_hex, &wrong_key_id);
    fs::write(&wrong_id_path, wrong).expect("wrong metadata");
    fs::set_permissions(&wrong_id_path, fs::Permissions::from_mode(0o600))
        .expect("wrong metadata permissions");
    assert!(material::read_client_metadata_v1(&wrong_id_path).is_err());
}
