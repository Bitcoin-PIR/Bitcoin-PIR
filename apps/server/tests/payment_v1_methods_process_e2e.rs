//! Real-process coverage for the provider-local Payment V1 method adapters.
//!
//! The fixtures use public deterministic keys, a tiny manifest-bound DPF
//! database, and loopback sockets only.  Each provider owns a different
//! policy key, provider ID, Free-IP HMAC key, BAT scalar, experimental ARC
//! key, provider store, and rollback authority.  There is intentionally no
//! pair identifier or peer-provider configuration.
//!
//! This is local wire/admission evidence, not production-attestation
//! evidence: ordinary CI hosts return `NoSevHost`, so the SDK's explicitly
//! dangerous unpaired helpers are used after the attestation-bound secure
//! channel is established.

#![cfg(unix)]

use arc::group::serialize_scalar;
use arc::{
    create_credential_request, create_credential_response, finalize_credential,
    make_presentation_state, present, setup_server,
};
use ed25519_dalek::SigningKey;
use libdpf::Dpf;
use pir_arc_adapter::{ArcSecretKeyV1, ARC_SECRET_KEY_LEN_V1};
use pir_core::cuckoo::write_header_with_anchor;
use pir_core::merkle::sha256;
use pir_core::params::{CHUNK_PARAMS, INDEX_PARAMS};
use pir_payment_crypto::{
    blind_cashu_message_v1, verify_and_unblind_cashu_promise_v1, K256CashuMintKeyringV1,
};
use pir_runtime_core::protocol::{BatchQuery, Request, Response};
use pir_sdk_client::attest::{attest_with_eph_binding, SevStatus};
use pir_sdk_client::channel::{establish, SecureChannelTransport};
use pir_sdk_client::{
    dangerous_unpaired_authorize_service_operation_v1,
    dangerous_unpaired_build_authorization_proof_v1, fetch_verified_service_policy_v1,
    AcceptedServicePolicyV1, PirTransport, ServicePolicyCheckpointV1, WsConnection,
};
use pir_service_protocol::{
    derive_bat_key_id_v1, derive_provider_id, AcquisitionMethod, ArcPresentationV1,
    AuthPaddingClassV1, AuthScheme, BackendId, BitcoinPirCashuBatProofV1,
    CredentialKeyBindingClaimsV1, CredentialKeyBindingExpectationV1, CredentialKeyBindingV1,
    CredentialUnitV1, DatasetBindingV1, DeploymentStatus, EntitlementLimitsV1, FreeModeV1,
    OperationStartV1, PriceV1, PrivacyLeakageV1, ServiceOfferV1, ServicePolicyV1,
    ServiceScopePolicyV1, ServiceScopeV1, VerificationMode, WorkloadId,
};
use pir_service_store::{ProviderStore, SqliteRollbackFloorAuthorityV1, StoreOptions};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use std::fs::{self, File};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const FREE_OPEN_OFFER_ID: u32 = 10;
const FREE_IP_OFFER_ID: u32 = 11;
const BAT_OFFER_ID: u32 = 12;
const ARC_OFFER_ID: u32 = 13;
const OPERATION_PROFILE: u16 = 21;
const ENTITLEMENT_PROFILE: u16 = 201;
const TINY_BINS_PER_TABLE: usize = 128;
const ARC_PRESENTATION_LIMIT: u32 = 2;
static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

struct ProviderFixture {
    index: u8,
    provider_id: [u8; 32],
    policy_signing_key: SigningKey,
    policy_path: PathBuf,
    store_path: PathBuf,
    rollback_path: PathBuf,
    free_ip_key_path: PathBuf,
    bat_key_path: PathBuf,
    arc_key_path: PathBuf,
    arc_key_id: Vec<u8>,
    scope_id: [u8; 32],
    policy_digest: [u8; 32],
    bat_proof: Vec<u8>,
    arc_presentation: Vec<u8>,
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
            "payment-methods-provider-{}-generation-{generation}-stdout.log",
            fixture.index
        ));
        let stderr_path = root.join(format!(
            "payment-methods-provider-{}-generation-{generation}-stderr.log",
            fixture.index
        ));
        let stdout = File::create(&stdout_path).expect("create server stdout log");
        let stderr = File::create(&stderr_path).expect("create server stderr log");
        let arc_key_spec = format!(
            "{}={}",
            hex::encode(&fixture.arc_key_id),
            fixture.arc_key_path.to_str().expect("UTF-8 test path")
        );
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
                "--allow-experimental-arc",
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
                "--service-free-ip-key",
                fixture.free_ip_key_path.to_str().expect("UTF-8 test path"),
                "--service-trust-direct-peer-ip",
                "--service-bat-key",
                fixture.bat_key_path.to_str().expect("UTF-8 test path"),
                "--service-arc-key",
                &arc_key_spec,
                "--max-connections",
                "24",
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
async fn independent_providers_enforce_free_bat_and_experimental_arc_over_real_sockets() {
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
    assert_ne!(provider0.free_ip_key_path, provider1.free_ip_key_path);
    assert_ne!(provider0.bat_key_path, provider1.bat_key_path);
    assert_ne!(provider0.arc_key_path, provider1.arc_key_path);
    assert_ne!(provider0.arc_key_id, provider1.arc_key_id);
    assert_ne!(provider0.store_path, provider1.store_path);
    assert_ne!(provider0.rollback_path, provider1.rollback_path);

    let port0 = unused_loopback_port();
    let mut port1 = unused_loopback_port();
    while port1 == port0 {
        port1 = unused_loopback_port();
    }
    let server0 = ServerProcess::spawn(root.path(), &db_path, &provider0, port0, 0);
    let server1 = ServerProcess::spawn(root.path(), &db_path, &provider1, port1, 0);
    let request = valid_tiny_dpf_request();

    // Open best effort has no bearer or durable quota, but still requires the
    // real secure channel, signed policy, AUTH opcode, and bounded grant.
    authorize_and_query(
        port0,
        &provider0,
        manifest_root,
        &request,
        FREE_OPEN_OFFER_ID,
        &[],
    )
    .await;

    // The direct-IP quota is provider-local and durable.  Consuming provider
    // 0's one-slot bucket does not consume provider 1's independent bucket.
    authorize_and_query(
        port0,
        &provider0,
        manifest_root,
        &request,
        FREE_IP_OFFER_ID,
        &[],
    )
    .await;
    expect_authorization_rejected(
        port0,
        &provider0,
        manifest_root,
        &request,
        FREE_IP_OFFER_ID,
        &[],
        "server-busy",
    )
    .await;
    authorize_and_query(
        port1,
        &provider1,
        manifest_root,
        &request,
        FREE_IP_OFFER_ID,
        &[],
    )
    .await;

    // A provider-0 BAT is rejected by provider 1's independent key before
    // provider 1 accepts and commits its own capability.
    authorize_and_query(
        port0,
        &provider0,
        manifest_root,
        &request,
        BAT_OFFER_ID,
        &provider0.bat_proof,
    )
    .await;
    expect_authorization_rejected(
        port0,
        &provider0,
        manifest_root,
        &request,
        BAT_OFFER_ID,
        &provider0.bat_proof,
        "invalid-or-spent",
    )
    .await;
    expect_authorization_rejected(
        port1,
        &provider1,
        manifest_root,
        &request,
        BAT_OFFER_ID,
        &provider0.bat_proof,
        "invalid-or-spent",
    )
    .await;
    authorize_and_query(
        port1,
        &provider1,
        manifest_root,
        &request,
        BAT_OFFER_ID,
        &provider1.bat_proof,
    )
    .await;

    // Experimental ARC follows the same provider-local separation.  The
    // server derives the durable nullifier only after real ARC verification;
    // resending the exact canonical presentation cannot create a second grant.
    authorize_and_query(
        port0,
        &provider0,
        manifest_root,
        &request,
        ARC_OFFER_ID,
        &provider0.arc_presentation,
    )
    .await;
    expect_authorization_rejected(
        port0,
        &provider0,
        manifest_root,
        &request,
        ARC_OFFER_ID,
        &provider0.arc_presentation,
        "invalid-or-spent",
    )
    .await;
    expect_authorization_rejected(
        port1,
        &provider1,
        manifest_root,
        &request,
        ARC_OFFER_ID,
        &provider0.arc_presentation,
        "invalid-or-spent",
    )
    .await;
    authorize_and_query(
        port1,
        &provider1,
        manifest_root,
        &request,
        ARC_OFFER_ID,
        &provider1.arc_presentation,
    )
    .await;

    let (stdout0_first, stderr0_first) = server0.stop();
    let (stdout1_first, stderr1_first) = server1.stop();
    assert_loopback_listener(0, port0, &stdout0_first, &stderr0_first);
    assert_loopback_listener(1, port1, &stdout1_first, &stderr1_first);

    // A fresh process using the same independent SQLite domains observes all
    // three durable boundaries: Free-IP quota, BAT spent key, and ARC tag.
    let server0 = ServerProcess::spawn(root.path(), &db_path, &provider0, port0, 1);
    let server1 = ServerProcess::spawn(root.path(), &db_path, &provider1, port1, 1);
    for (port, fixture) in [(port0, &provider0), (port1, &provider1)] {
        expect_authorization_rejected(
            port,
            fixture,
            manifest_root,
            &request,
            FREE_IP_OFFER_ID,
            &[],
            "server-busy",
        )
        .await;
        expect_authorization_rejected(
            port,
            fixture,
            manifest_root,
            &request,
            BAT_OFFER_ID,
            &fixture.bat_proof,
            "invalid-or-spent",
        )
        .await;
        expect_authorization_rejected(
            port,
            fixture,
            manifest_root,
            &request,
            ARC_OFFER_ID,
            &fixture.arc_presentation,
            "invalid-or-spent",
        )
        .await;
    }

    let (stdout0, stderr0) = server0.stop();
    let (stdout1, stderr1) = server1.stop();
    assert_loopback_listener(0, port0, &stdout0, &stderr0);
    assert_loopback_listener(1, port1, &stdout1, &stderr1);
}

async fn authorize_and_query(
    port: u16,
    fixture: &ProviderFixture,
    manifest_root: [u8; 32],
    backend_request: &[u8],
    offer_id: u32,
    proof_bytes: &[u8],
) {
    let (mut secure, accepted) =
        open_verified_session(port, fixture, manifest_root, backend_request).await;
    let proof = dangerous_unpaired_build_authorization_proof_v1(
        &accepted,
        &fixture.scope_id,
        offer_id,
        proof_bytes,
    )
    .expect("construct exact offer proof");
    let grant = dangerous_unpaired_authorize_service_operation_v1(
        &mut secure,
        &accepted,
        fixture.scope_id,
        offer_id,
        OperationStartV1::DpfQuery { db_id: 0 },
        proof,
    )
    .await
    .expect("provider-local method must authorize");
    assert_eq!(grant.scope_id, fixture.scope_id);
    assert_eq!(grant.enforced_profile, ENTITLEMENT_PROFILE);

    let response = secure.roundtrip(backend_request).await.unwrap();
    match Response::decode(&response).unwrap() {
        Response::IndexBatch(result) => {
            assert_eq!(result.results.len(), 1);
            assert_eq!(result.results[0].len(), 2);
            assert!(result.results[0].iter().all(|item| item.len() == 52));
        }
        other => panic!("authorized DPF frame did not reach handler: {other:?}"),
    }
    expect_error_response(
        &secure.roundtrip(backend_request).await.unwrap(),
        "service entitlement limit exceeded",
    );
    secure.close().await.unwrap();
}

async fn expect_authorization_rejected(
    port: u16,
    fixture: &ProviderFixture,
    manifest_root: [u8; 32],
    backend_request: &[u8],
    offer_id: u32,
    proof_bytes: &[u8],
    needle: &str,
) {
    let (mut secure, accepted) =
        open_verified_session(port, fixture, manifest_root, backend_request).await;
    let proof = dangerous_unpaired_build_authorization_proof_v1(
        &accepted,
        &fixture.scope_id,
        offer_id,
        proof_bytes,
    )
    .expect("construct exact offer proof");
    let error = dangerous_unpaired_authorize_service_operation_v1(
        &mut secure,
        &accepted,
        fixture.scope_id,
        offer_id,
        OperationStartV1::DpfQuery { db_id: 0 },
        proof,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains(needle), "{error}");
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
    let mut eph_seed = [0x70u8.wrapping_add(fixture.index); 32];
    let mut random = [0x90u8.wrapping_add(fixture.index); 32];
    let mut handshake_nonce = [0xb0u8.wrapping_add(fixture.index); 32];
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
    assert_eq!(accepted.checkpoint().rollback_guard().highest_epoch, 1);
    expect_error_response(
        &secure.roundtrip(backend_request).await.unwrap(),
        "authorization required",
    );
    (secure, accepted)
}

fn build_provider(root: &Path, index: u8, manifest_root: [u8; 32], now: u64) -> ProviderFixture {
    let provider_root = root.join(format!("payment-methods-provider-{index}"));
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
    let stable_server_id = format!("payment-methods-process-provider-{index}");
    let provider_id =
        derive_provider_id(&operator_key.verifying_key().to_bytes(), &stable_server_id);
    let issued_at = now.saturating_sub(60);
    let expires_at = now.checked_add(3_600).unwrap();
    let retired_policy_grace_seconds = 1_800u32;
    let binding_not_after = expires_at + u64::from(retired_policy_grace_seconds);
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

    let free_ip_key_path = provider_root.join("free-ip-hmac.key");
    fs::write(&free_ip_key_path, [0x41u8.wrapping_add(index); 32]).unwrap();
    chmod(&free_ip_key_path, 0o600);

    let bat_secret = [0x51u8.wrapping_add(index); 32];
    let bat_key_path = provider_root.join("bat.key");
    fs::write(&bat_key_path, bat_secret).unwrap();
    chmod(&bat_key_path, 0o600);
    let bat_keyring = K256CashuMintKeyringV1::from_secret_keys([bat_secret]).unwrap();
    let bat_public_key = bat_keyring.denomination_public_keys()[0];
    let bat_key_id = derive_bat_key_id_v1(
        &provider_id,
        &scope_id,
        BAT_OFFER_ID,
        ENTITLEMENT_PROFILE,
        1,
        &bat_public_key,
    )
    .to_vec();
    let bat_binding = credential_binding(
        provider_id,
        scope_id,
        BAT_OFFER_ID,
        AuthScheme::BitcoinPirCashuBatV1,
        ENTITLEMENT_PROFILE,
        1,
        bat_key_id.clone(),
        bat_public_key.to_vec(),
        issued_at,
        binding_not_after,
        &issuer_root_key,
    );
    let bat_secret_raw = [0x61u8.wrapping_add(index); 32];
    let bat_blinding = [0x07u8.wrapping_add(index); 32];
    let blinded = blind_cashu_message_v1(&bat_secret_raw, &bat_blinding).unwrap();
    let promise = bat_keyring
        .blind_sign_with_dleq_v1(&bat_public_key, &blinded, &[0x17u8.wrapping_add(index); 32])
        .unwrap();
    let unblinded = verify_and_unblind_cashu_promise_v1(
        &bat_secret_raw,
        &bat_blinding,
        &bat_public_key,
        &blinded,
        promise.blinded_signature(),
        promise.dleq_e(),
        promise.dleq_s(),
    )
    .unwrap();
    let bat_proof = BitcoinPirCashuBatProofV1 {
        secret_raw: bat_secret_raw,
        c: *unblinded.unblinded_signature(),
    }
    .encode()
    .unwrap()
    .to_vec();

    let mut arc_rng = ChaCha20Rng::from_seed([0x71u8.wrapping_add(index); 32]);
    let (arc_secret, arc_public) = setup_server(&mut arc_rng);
    let arc_key_id = vec![0x81u8.wrapping_add(index); 16];
    let mut arc_secret_bytes = [0u8; ARC_SECRET_KEY_LEN_V1];
    arc_secret_bytes[0..32].copy_from_slice(&serialize_scalar(&arc_secret.x0));
    arc_secret_bytes[32..64].copy_from_slice(&serialize_scalar(&arc_secret.x1));
    arc_secret_bytes[64..96].copy_from_slice(&serialize_scalar(&arc_secret.x2));
    arc_secret_bytes[96..128].copy_from_slice(&serialize_scalar(&arc_secret.x0_blinding));
    let arc_key_path = provider_root.join("arc.key");
    fs::write(&arc_key_path, arc_secret_bytes).unwrap();
    chmod(&arc_key_path, 0o600);
    let parsed_arc_secret =
        ArcSecretKeyV1::from_zeroizing_bytes(arc_key_id.clone(), Zeroizing::new(arc_secret_bytes))
            .unwrap();
    assert_eq!(parsed_arc_secret.public_key_bytes(), &arc_public.to_bytes());
    let arc_binding = credential_binding(
        provider_id,
        scope_id,
        ARC_OFFER_ID,
        AuthScheme::ArcV1Experimental,
        ENTITLEMENT_PROFILE,
        ARC_PRESENTATION_LIMIT,
        arc_key_id.clone(),
        arc_public.to_bytes().to_vec(),
        issued_at,
        binding_not_after,
        &issuer_root_key,
    );
    let arc_expectation = CredentialKeyBindingExpectationV1 {
        issuer_id: &arc_binding.issuer_id,
        provider_id: &provider_id,
        scope_id: &scope_id,
        offer_id: ARC_OFFER_ID,
        scheme: AuthScheme::ArcV1Experimental,
        minimum_keyset_epoch: 1,
        entitlement_profile: ENTITLEMENT_PROFILE,
        presentation_limit: ARC_PRESENTATION_LIMIT,
        credential_key_id: &arc_key_id,
    };
    arc_binding
        .verify_for(&arc_expectation, now)
        .expect("ARC binding fixture");
    let request_context = arc_binding.request_context_digest().unwrap();
    let presentation_context = arc_binding.presentation_context_digest().unwrap();
    let (client_secrets, credential_request) =
        create_credential_request(&request_context, &mut arc_rng).unwrap();
    let credential_response =
        create_credential_response(&arc_secret, &arc_public, &credential_request, &mut arc_rng)
            .unwrap();
    let credential = finalize_credential(
        &client_secrets,
        &arc_public,
        &credential_request,
        &credential_response,
    )
    .unwrap();
    let initial_state = make_presentation_state(
        credential,
        &presentation_context,
        u64::from(ARC_PRESENTATION_LIMIT),
    );
    let (_successor, _nonce, presentation) = present(&initial_state, &mut arc_rng).unwrap();
    let arc_presentation =
        ArcPresentationV1::from_canonical_bytes(presentation.to_bytes()).unwrap();

    let offers = vec![
        free_offer(FREE_OPEN_OFFER_ID, FreeModeV1::OpenBestEffort),
        free_offer(FREE_IP_OFFER_ID, FreeModeV1::IpRateLimited),
        paid_offer(
            BAT_OFFER_ID,
            AuthScheme::BitcoinPirCashuBatV1,
            DeploymentStatus::Stable,
            bat_key_id,
            bat_binding,
            1,
        ),
        paid_offer(
            ARC_OFFER_ID,
            AuthScheme::ArcV1Experimental,
            DeploymentStatus::Experimental,
            arc_key_id.clone(),
            arc_binding,
            ARC_PRESENTATION_LIMIT,
        ),
    ];
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
        [0x91u8.wrapping_add(index); 16],
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
        policy_path,
        store_path,
        rollback_path,
        free_ip_key_path,
        bat_key_path,
        arc_key_path,
        arc_key_id,
        scope_id,
        policy_digest,
        bat_proof,
        arc_presentation: arc_presentation.presentation_bytes().to_vec(),
    }
}

#[allow(clippy::too_many_arguments)]
fn credential_binding(
    provider_id: [u8; 32],
    scope_id: [u8; 32],
    offer_id: u32,
    scheme: AuthScheme,
    entitlement_profile: u16,
    presentation_limit: u32,
    credential_key_id: Vec<u8>,
    verification_key: Vec<u8>,
    issued_at: u64,
    not_after: u64,
    issuer_root_key: &SigningKey,
) -> CredentialKeyBindingV1 {
    CredentialKeyBindingV1::sign(
        CredentialKeyBindingClaimsV1 {
            provider_id,
            scope_id,
            offer_id,
            scheme,
            keyset_epoch: 1,
            entitlement_profile,
            unit: CredentialUnitV1::Auth,
            amount: 1,
            presentation_limit,
            not_before: issued_at.saturating_sub(60),
            not_after,
            credential_key_id,
            verification_key,
        },
        issuer_root_key,
    )
    .unwrap()
}

fn free_offer(offer_id: u32, mode: FreeModeV1) -> ServiceOfferV1 {
    let (free_quota, free_window_seconds) = match mode {
        FreeModeV1::OpenBestEffort => (0, 0),
        FreeModeV1::IpRateLimited => (1, 3_600),
        _ => panic!("test helper supports only open and IP Free modes"),
    };
    ServiceOfferV1 {
        offer_id,
        acquisition: AcquisitionMethod::FreeV1,
        free_mode: mode,
        free_quota,
        free_window_seconds,
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
        privacy_leakage: PrivacyLeakageV1::from_bits(PrivacyLeakageV1::KNOWN_MASK).unwrap(),
    }
}

fn paid_offer(
    offer_id: u32,
    scheme: AuthScheme,
    deployment_status: DeploymentStatus,
    key_id: Vec<u8>,
    binding: CredentialKeyBindingV1,
    presentation_limit: u32,
) -> ServiceOfferV1 {
    ServiceOfferV1 {
        offer_id,
        acquisition: AcquisitionMethod::Bolt11V1,
        free_mode: FreeModeV1::NotFree,
        free_quota: 0,
        free_window_seconds: 0,
        free_pow_difficulty_bits: 0,
        priority_class: 10,
        authorization: scheme,
        verification: VerificationMode::ProviderLocal,
        deployment_status,
        price: PriceV1::MilliSatoshi(1_000),
        issuer_id: binding.issuer_id,
        key_id,
        credential_binding: Some(binding),
        cashu_mint_manifest: None,
        endpoint: format!("https://issuer-{offer_id}.fixture.invalid"),
        invoice_expiry_seconds: 600,
        claim_window_seconds: 600,
        minimum_credential_validity_seconds: 600,
        retired_policy_grace_seconds: 1_800,
        credential_count: 1,
        credential_presentation_limit: presentation_limit,
        privacy_leakage: PrivacyLeakageV1::from_bits(PrivacyLeakageV1::KNOWN_MASK).unwrap(),
    }
}

fn write_tiny_manifest_database(root: &Path) -> (PathBuf, [u8; 32]) {
    let db = root.join("payment-methods-tiny-db");
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

fn assert_loopback_listener(index: u8, port: u16, stdout: &str, stderr: &str) {
    let expected = format!("Listening on ws://127.0.0.1:{port}");
    assert!(
        stdout.contains(&expected),
        "provider {index} was not loopback-bound\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );
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
