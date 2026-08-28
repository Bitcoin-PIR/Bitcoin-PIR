//! Shared-issuer real-process admission coverage.
//!
//! The paid provider is a real `unified_server` subprocess. Its signed clearing
//! authorization selects a normal WebPKI HTTPS origin and an additional signed
//! leaf-SPKI pin. A separate TLS-edge subprocess forwards only `/v1/redeems` to
//! a real `payment-issuer` subprocess. The issuer's test-only fake Lightning
//! backend is used only to satisfy no-funds startup; this test never creates or
//! settles an invoice. The peer provider independently selects Free/Open.
//!
//! The TLS edge also drops one complete, successful redeem response after the
//! issuer commits it. The provider must fail closed without a delivery claim,
//! then recover by replaying the exact request after the issuer and provider
//! restart against their original stores.
//!
//! The private test CA hook is inherited from `standard-cashu-process-e2e`, so
//! there is one test-only WebPKI injection surface and `pir-strict-https` keeps
//! its release compile guard. All bearer/key fixtures are deterministic public
//! test material. No public service, Lightning node, wallet, relay, or funds are
//! contacted.

#![cfg(all(unix, feature = "shared-issuer-process-e2e"))]

use ed25519_dalek::{SigningKey, VerifyingKey};
use libdpf::Dpf;
use pir_core::cuckoo::write_header_with_anchor;
use pir_core::merkle::sha256;
use pir_core::params::{CHUNK_PARAMS, INDEX_PARAMS};
use pir_issuer_store::{IssuerStore, StoreOptions as IssuerStoreOptions};
use pir_lightning_backend::FakeLightningNodeV1;
use pir_payment_crypto::{cashu_hash_to_curve_v1, K256CashuMintKeyringV1};
use pir_provider_clearing_client::{
    ProviderLedgerBalanceClientV1, ProviderLedgerBalanceTrustV1,
    StrictHttpsProviderSettlementTransportV1,
};
use pir_runtime_core::protocol::{BatchQuery, Request, Response};
use pir_sdk_client::attest::{attest_with_eph_binding, SevStatus};
use pir_sdk_client::channel::{establish, SecureChannelTransport};
use pir_sdk_client::{
    dangerous_unpaired_authorize_service_operation_v1,
    dangerous_unpaired_build_authorization_proof_v1, fetch_verified_service_policy_v1,
    request_pow_challenge_v1, AcceptedServicePolicyV1, PirTransport, ServicePolicyCheckpointV1,
    WsConnection,
};
use pir_service_protocol::{
    derive_bat_key_id_v1, derive_issuer_id, derive_provider_id, pow_solution_meets_difficulty_v1,
    AcquisitionMethod, AuthPaddingClassV1, AuthScheme, AuthorizationProofV1, BackendId,
    BitcoinPirCashuBatProofV1, Bolt11QuoteKeyDelegationV1, CredentialKeyBindingClaimsV1,
    CredentialKeyBindingV1, CredentialUnitV1, DatasetBindingV1, DeploymentStatus,
    EntitlementLimitsV1, FreeAuthorizationProofV1, FreeModeV1, FreePowProofV1,
    IssuerClearingApprovalV1, LightningNetworkV1, OperationStartV1, PowChallengeResponseV1,
    PriceV1, PrivacyLeakageV1, ProviderClearingAuthorizationV1, ProviderRedeemEnvelopeV1,
    ProviderRedeemResponseV1, ServiceOfferV1, ServicePolicyV1, ServiceScopePolicyV1,
    ServiceScopeV1, SettlementUnitV1, VerificationMode, WorkloadId,
};
use pir_service_store::{ProviderStore, StoreOptions as ProviderStoreOptions};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::env;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const SHARED_OFFER_ID: u32 = 61;
const FREE_OFFER_ID: u32 = 62;
const FREE_POW_OFFER_ID: u32 = 63;
const FREE_POW_DIFFICULTY_BITS: u8 = 4;
const OPERATION_PROFILE: u16 = 41;
const ENTITLEMENT_PROFILE: u16 = 401;
const TINY_BINS_PER_TABLE: usize = 128;
const TEST_LEAF_SPKI_SHA256_HEX: &str =
    "e91550521f8e17b21d99f7e00b99c08be1b1f31fe57772ac8f904ea50c6a609b";
const TLS_EDGE_HELPER_MARKER: &str = "BITCOINPIR_TEST_ONLY_SHARED_ISSUER_TLS_EDGE_V1";
const TLS_EDGE_TRANSCRIPT_PATH: &str = "BITCOINPIR_TEST_SHARED_ISSUER_TRANSCRIPTS";
const TLS_EDGE_DROP_SUCCESS_ONCE_PATH: &str = "BITCOINPIR_TEST_SHARED_ISSUER_DROP_SUCCESS_ONCE";
const REDEEM_CONTENT_TYPE: &str = "application/vnd.bitcoinpir.redeem-v1";
const REDEEM_RESULT_CONTENT_TYPE: &str = "application/vnd.bitcoinpir.redeem-result-v1";
const REDEEM_TRANSCRIPT_DIGEST_BYTES: usize = 3 * 32;
const PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const TLS_IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PROXY_HTTP_BYTES: usize = 128 * 1024;
static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProviderMethod {
    SharedIssuerBat,
    SharedIssuerBatWithFreePow,
    FreeOpen,
}

struct SharedProviderConfig {
    authorization_epoch: u64,
    authorization_path: PathBuf,
    approval_path: PathBuf,
    operator_key_path: PathBuf,
    operator_verifying_key: VerifyingKey,
    issuer_settlement_verifying_key: VerifyingKey,
    clearing_key_path: PathBuf,
    provider_request_verifying_key_path: PathBuf,
    idempotency_key_path: PathBuf,
    proof: BitcoinPirCashuBatProofV1,
    account_id: [u8; 32],
}

struct ProviderFixture {
    index: u8,
    method: ProviderMethod,
    provider_id: [u8; 32],
    policy_signing_key: SigningKey,
    policy_path: PathBuf,
    store_path: PathBuf,
    scope_id: [u8; 32],
    policy_digest: [u8; 32],
    shared: Option<SharedProviderConfig>,
}

impl ProviderFixture {
    fn proof(&self) -> AuthorizationProofV1 {
        match self.method {
            ProviderMethod::SharedIssuerBat | ProviderMethod::SharedIssuerBatWithFreePow => {
                AuthorizationProofV1::BitcoinPirCashuBat(
                    self.shared
                        .as_ref()
                        .expect("shared provider config")
                        .proof
                        .clone(),
                )
            }
            ProviderMethod::FreeOpen => {
                AuthorizationProofV1::Free(FreeAuthorizationProofV1::OpenBestEffort)
            }
        }
    }

    fn offer_id(&self) -> u32 {
        match self.method {
            ProviderMethod::SharedIssuerBat | ProviderMethod::SharedIssuerBatWithFreePow => {
                SHARED_OFFER_ID
            }
            ProviderMethod::FreeOpen => FREE_OFFER_ID,
        }
    }
}

struct IssuerMaterial {
    binary: PathBuf,
    admin_binary: PathBuf,
    issuer_id: [u8; 32],
    issuer_root: SigningKey,
    settlement_signing_key: SigningKey,
    store_path: PathBuf,
    quote_delegation_path: PathBuf,
    quote_signing_key_path: PathBuf,
    credential_derivation_key_path: PathBuf,
    bat_key_path: PathBuf,
    fake_lightning_signing_key_path: PathBuf,
    fake_lightning_derivation_seed_path: PathBuf,
    issuer_settlement_signing_key_path: PathBuf,
    retained_issuer_settlement_verifying_key_paths: Vec<PathBuf>,
    redeem_response_derivation_key_path: PathBuf,
    bat_keyring: Arc<K256CashuMintKeyringV1>,
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

struct TlsMaterial {
    root: PathBuf,
    wrong_root: PathBuf,
    certificate: PathBuf,
    private_key: PathBuf,
}

/// Fixed-size, test-local replay evidence. No envelope, credential, raw
/// idempotency key, HTTP metadata, peer address, or timing is persisted.
#[derive(Clone, Copy)]
struct RedeemTranscriptDigests {
    canonical_body: [u8; 32],
    request_digest: [u8; 32],
    idempotency_key_digest: [u8; 32],
}

impl RedeemTranscriptDigests {
    fn encode(self) -> [u8; REDEEM_TRANSCRIPT_DIGEST_BYTES] {
        let mut encoded = [0u8; REDEEM_TRANSCRIPT_DIGEST_BYTES];
        encoded[..32].copy_from_slice(&self.canonical_body);
        encoded[32..64].copy_from_slice(&self.request_digest);
        encoded[64..].copy_from_slice(&self.idempotency_key_digest);
        encoded
    }
}

#[test]
#[ignore = "spawned only by shared-issuer process E2E tests"]
fn shared_issuer_tls_edge_subprocess() {
    if env::var_os(TLS_EDGE_HELPER_MARKER).is_none() {
        return;
    }
    let bind = required_env("BITCOINPIR_TEST_SHARED_ISSUER_EDGE_BIND")
        .parse()
        .expect("TLS edge bind address");
    let upstream = required_env("BITCOINPIR_TEST_SHARED_ISSUER_UPSTREAM")
        .parse()
        .expect("TLS edge upstream address");
    let certificate = fs::read(required_env("BITCOINPIR_TEST_SHARED_ISSUER_CERT"))
        .expect("read TLS edge certificate");
    let private_key = fs::read(required_env("BITCOINPIR_TEST_SHARED_ISSUER_KEY"))
        .expect("read TLS edge private key");
    let counter_path = PathBuf::from(required_env(
        "BITCOINPIR_TEST_SHARED_ISSUER_FORWARD_COUNTER",
    ));
    let transcript_path = PathBuf::from(required_env(TLS_EDGE_TRANSCRIPT_PATH));
    let drop_success_once_path = env::var_os(TLS_EDGE_DROP_SUCCESS_ONCE_PATH).map(PathBuf::from);
    serve_tls_edge(
        bind,
        upstream,
        &certificate,
        &private_key,
        &counter_path,
        &transcript_path,
        drop_success_once_path.as_deref(),
    )
    .expect("serve shared-issuer TLS edge");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_issuer_real_process_tls_e2e() {
    let root = tempfile::tempdir().expect("shared-issuer process test root");
    chmod(root.path(), 0o700);
    let (db_path, manifest_root) = write_tiny_manifest_database(root.path());
    let tls = install_tls_material(root.path());

    let issuer_port = unused_loopback_port();
    let edge_port = distinct_unused_port(&[issuer_port]);
    let offline_port = distinct_unused_port(&[issuer_port, edge_port]);
    let redeem_endpoint = format!("https://localhost:{edge_port}");
    let mut issuer = build_issuer_material(root.path(), unix_now());
    let now = unix_now();

    let mut paid = build_provider(
        root.path(),
        0,
        ProviderMethod::SharedIssuerBat,
        manifest_root,
        &issuer,
        &redeem_endpoint,
        vec![test_leaf_spki_sha256()],
        now,
    );
    let free = build_provider(
        root.path(),
        1,
        ProviderMethod::FreeOpen,
        manifest_root,
        &issuer,
        "",
        Vec::new(),
        now,
    );
    let wrong_ca = build_provider(
        root.path(),
        10,
        ProviderMethod::SharedIssuerBat,
        manifest_root,
        &issuer,
        &redeem_endpoint,
        vec![test_leaf_spki_sha256()],
        now,
    );
    let wrong_pin = build_provider(
        root.path(),
        11,
        ProviderMethod::SharedIssuerBat,
        manifest_root,
        &issuer,
        &redeem_endpoint,
        vec![[0x5a; 32]],
        now,
    );
    let offline = build_provider(
        root.path(),
        12,
        ProviderMethod::SharedIssuerBat,
        manifest_root,
        &issuer,
        &format!("https://localhost:{offline_port}"),
        vec![test_leaf_spki_sha256()],
        now,
    );
    // The negative providers must fail at TLS trust or connect time before an
    // issuer request exists, so the real issuer registers only the paid
    // provider that can reach `/v1/redeems`. This also preserves the issuer
    // store invariant that one BAT public key has one immutable lineage.
    let shared_providers = [&paid];
    init_issuer_store(&issuer);
    let payment_issuer = spawn_payment_issuer(root.path(), issuer_port, &issuer, &shared_providers);
    let forward_counter = root.path().join("tls-edge-forwarded.log");
    let transcript_path = root.path().join("tls-edge-transcript-digests.bin");
    let drop_success_once_path = root.path().join("tls-edge-drop-success-once.marker");
    write_private_file(&forward_counter, b"");
    write_private_file(&transcript_path, b"");
    assert!(!drop_success_once_path.exists());
    let tls_edge = spawn_tls_edge(
        root.path(),
        edge_port,
        issuer_port,
        &tls,
        &forward_counter,
        &transcript_path,
        Some(&drop_success_once_path),
    );

    assert_ne!(paid.provider_id, free.provider_id);
    assert_ne!(paid.store_path, free.store_path);
    let paid_port = distinct_unused_port(&[issuer_port, edge_port, offline_port]);
    let free_port = distinct_unused_port(&[issuer_port, edge_port, offline_port, paid_port]);
    let paid_server = spawn_provider(root.path(), &db_path, &paid, paid_port, 0, Some(&tls.root));
    let free_server = spawn_provider(root.path(), &db_path, &free, free_port, 0, None);

    // The edge reads a complete HTTP 200 from the real issuer, proving that the
    // ledger commit completed, then drops that one downstream response. The
    // provider must fail closed and must not create a local delivery claim.
    let lost_response = authorize_only(paid_port, &paid, manifest_root)
        .await
        .expect_err("committed issuer response loss must not grant locally");
    assert!(
        lost_response.contains("internal-after-spend"),
        "unexpected outcome-unknown rejection: {lost_response}"
    );
    assert_payment_material_absent(&lost_response, "", &[&paid]);
    let (paid_loss_stdout, paid_loss_stderr) = paid_server.stop();
    assert_server_log(&paid_loss_stdout, &paid_loss_stderr, paid_port, &paid);
    assert_provider_spend_inventory(&paid, 0);
    assert_eq!(forwarded_request_count(&forward_counter), 1);
    assert_private_regular_file(&drop_success_once_path);
    let response_loss_marker =
        fs::read(&drop_success_once_path).expect("read response-loss marker");
    assert_eq!(
        response_loss_marker.as_slice(),
        b"committed-response-dropped\n"
    );

    // Kill and reopen the actual issuer against the same durable store. The
    // provider is also reopened to prove recovery does not depend on volatile
    // client state.
    let (issuer_loss_stdout, issuer_loss_stderr) = payment_issuer.stop();
    assert_issuer_log(&issuer_loss_stdout, &issuer_loss_stderr, &paid);
    assert_issuer_ledger(&issuer, &paid, &[&wrong_ca, &wrong_pin, &offline]);
    let payment_issuer = spawn_payment_issuer(root.path(), issuer_port, &issuer, &shared_providers);
    let paid_server = spawn_provider(root.path(), &db_path, &paid, paid_port, 1, Some(&tls.root));
    exercise_grant_and_dpf(paid_port, &paid, manifest_root)
        .await
        .expect("exact redeem replay after issuer restart must recover one grant");
    exercise_grant_and_dpf(free_port, &free, manifest_root)
        .await
        .expect("peer provider must independently accept Free/Open");

    let initial_balance = read_signed_ledger_balance(&paid, &tls.root, [0x11; 32], Vec::new());
    assert_eq!(
        (
            initial_balance.available_value,
            initial_balance.reserved_value
        ),
        (9, 0)
    );

    // A real issuer restart reopens the same durable store and the
    // independently generated authorization/approval/request-key artifacts.
    // The next balance is freshly signed and revalidated; no payout fixture or
    // in-memory registration is accepted as a substitute.
    let (issuer_stdout_first, issuer_stderr_first) = payment_issuer.stop();
    assert!(issuer_stdout_first.contains("payment-issuer fake service listening"));
    assert!(issuer_stdout_first.contains("issuer_store_startup_check=ok"));
    assert!(!issuer_stderr_first.contains("secret_raw"));
    let payment_issuer = spawn_payment_issuer(root.path(), issuer_port, &issuer, &[&paid]);
    let restarted_balance = read_signed_ledger_balance(&paid, &tls.root, [0x12; 32], Vec::new());
    assert_eq!(
        (
            restarted_balance.available_value,
            restarted_balance.reserved_value
        ),
        (9, 0)
    );

    let (paid_stdout_first, paid_stderr_first) = paid_server.stop();
    let (free_stdout, free_stderr) = free_server.stop();
    assert_server_log(&paid_stdout_first, &paid_stderr_first, paid_port, &paid);
    assert_server_log(&free_stdout, &free_stderr, free_port, &free);
    assert_provider_spend_inventory(&paid, 1);
    assert_eq!(
        forwarded_request_count(&forward_counter),
        4,
        "two recovery redeems and two signed balance reads must reach the issuer"
    );
    assert_private_regular_file(&transcript_path);
    assert_first_two_forwarded_requests_are_identical(&transcript_path);

    // Reopen the paid provider against the same local store. The issuer may
    // return its exact durable redeem response, but the provider-local claim is
    // already committed and a second connection grant is forbidden.
    let paid_server = spawn_provider(root.path(), &db_path, &paid, paid_port, 2, Some(&tls.root));
    let replay = authorize_only(paid_port, &paid, manifest_root)
        .await
        .expect_err("replayed shared-issuer proof must not grant after restart");
    assert!(
        replay.contains("invalid-or-spent"),
        "unexpected replay: {replay}"
    );
    let (paid_stdout, paid_stderr) = paid_server.stop();
    assert_server_log(&paid_stdout, &paid_stderr, paid_port, &paid);
    assert_provider_spend_inventory(&paid, 1);

    let forwarded_after_replay = forwarded_request_count(&forward_counter);
    assert!(
        (4..=5).contains(&forwarded_after_replay),
        "two identical recovery redeems and two signed balance reads must be forwarded; the later spent replay may be rejected locally or replayed at the issuer"
    );

    // Rotate both the authorization epoch and issuer settlement signing key.
    // The issuer retains the old public key only for historical recovery, while
    // the newly generated approval is bound to epoch 2 and the new key. The
    // real provider restarts on those files; its already-spent credential
    // remains spent and the signed ledger balance survives unchanged.
    let (issuer_stdout_restart, issuer_stderr_restart) = payment_issuer.stop();
    assert!(issuer_stdout_restart.contains("issuer_store_startup_check=ok"));
    assert!(!issuer_stderr_restart.contains("secret_raw"));
    let old_settlement_key = rotate_shared_clearing_artifacts(&mut issuer, &mut paid, unix_now());
    let payment_issuer = spawn_payment_issuer(root.path(), issuer_port, &issuer, &[&paid]);
    let rotated_balance =
        read_signed_ledger_balance(&paid, &tls.root, [0x13; 32], vec![old_settlement_key]);
    assert_eq!(
        (
            rotated_balance.available_value,
            rotated_balance.reserved_value
        ),
        (9, 0)
    );
    assert_ne!(
        initial_balance.issuer_settlement_key_id,
        rotated_balance.issuer_settlement_key_id
    );
    let rotated_provider =
        spawn_provider(root.path(), &db_path, &paid, paid_port, 2, Some(&tls.root));
    let rotated_replay = authorize_only(paid_port, &paid, manifest_root)
        .await
        .expect_err("credential spent before clearing rotation must remain spent");
    assert!(
        rotated_replay.contains("invalid-or-spent"),
        "unexpected rotated replay: {rotated_replay}"
    );
    let (rotated_stdout, rotated_stderr) = rotated_provider.stop();
    assert_server_log(&rotated_stdout, &rotated_stderr, paid_port, &paid);
    assert_provider_spend_inventory(&paid, 1);
    let forwarded_after_rotation = forwarded_request_count(&forward_counter);
    assert!(
        (forwarded_after_replay + 1..=forwarded_after_replay + 2)
            .contains(&forwarded_after_rotation),
        "rotated signed balance must be forwarded once; rotated spent proof may be rejected locally or by the issuer"
    );

    // Every trust failure uses a fresh provider process/store. The signed
    // authorization is otherwise valid, so only WebPKI, the signed pin, or the
    // offline origin can account for the fail-closed result.
    for (fixture, test_root) in [
        (&wrong_ca, &tls.wrong_root),
        (&wrong_pin, &tls.root),
        (&offline, &tls.root),
    ] {
        let port =
            distinct_unused_port(&[issuer_port, edge_port, offline_port, paid_port, free_port]);
        let server = spawn_provider(root.path(), &db_path, fixture, port, 0, Some(test_root));
        authorize_only(port, fixture, manifest_root)
            .await
            .expect_err("wrong CA/pin/offline issuer must fail closed");
        let (stdout, stderr) = server.stop();
        assert_server_log(&stdout, &stderr, port, fixture);
        assert_provider_spend_inventory(fixture, 0);
        assert_eq!(
            forwarded_request_count(&forward_counter),
            forwarded_after_rotation,
            "TLS trust/offline failure must not reach the issuer HTTP application"
        );
    }

    let (edge_stdout, edge_stderr) = tls_edge.stop();
    let (issuer_stdout, issuer_stderr) = payment_issuer.stop();
    assert_payment_material_absent(&edge_stdout, &edge_stderr, &[&paid]);
    assert_issuer_log(&issuer_stdout, &issuer_stderr, &paid);

    assert_issuer_ledger(&issuer, &paid, &[&wrong_ca, &wrong_pin, &offline]);
}

/// A provider may publish a local Free-PoW offer alongside a shared-issuer
/// Cashu BAT offer for the exact same DPF scope.  The former must never call
/// the issuer; the latter must still redeem through the issuer even though the
/// provider has no provider-local BAT or ARC key material.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_issuer_free_pow_and_bat_share_one_strict_policy_scope_e2e() {
    let root = tempfile::tempdir().expect("shared-issuer plus Free-PoW process test root");
    chmod(root.path(), 0o700);
    let (db_path, manifest_root) = write_tiny_manifest_database(root.path());
    let tls = install_tls_material(root.path());

    let issuer_port = unused_loopback_port();
    let edge_port = distinct_unused_port(&[issuer_port]);
    let redeem_endpoint = format!("https://localhost:{edge_port}");
    let issuer = build_issuer_material(root.path(), unix_now());
    let provider = build_provider(
        root.path(),
        20,
        ProviderMethod::SharedIssuerBatWithFreePow,
        manifest_root,
        &issuer,
        &redeem_endpoint,
        vec![test_leaf_spki_sha256()],
        unix_now(),
    );

    let policy_bytes = fs::read(&provider.policy_path).expect("read combined provider policy");
    let policy = ServicePolicyV1::decode(&policy_bytes).expect("decode combined provider policy");
    assert_eq!(
        policy.scopes.len(),
        1,
        "combined policy must have one scope"
    );
    assert_eq!(policy.scopes[0].scope.scope_id(), provider.scope_id);
    assert_eq!(
        policy.scopes[0]
            .offers
            .iter()
            .map(|offer| offer.offer_id)
            .collect::<Vec<_>>(),
        vec![SHARED_OFFER_ID, FREE_POW_OFFER_ID],
        "the same signed scope must offer both premium BAT and Free-PoW"
    );

    init_issuer_store(&issuer);
    let payment_issuer = spawn_payment_issuer(root.path(), issuer_port, &issuer, &[&provider]);
    let forward_counter = root.path().join("combined-tls-edge-forwarded.log");
    let transcript_path = root.path().join("combined-tls-edge-transcript-digests.bin");
    write_private_file(&forward_counter, b"");
    write_private_file(&transcript_path, b"");
    let tls_edge = spawn_tls_edge(
        root.path(),
        edge_port,
        issuer_port,
        &tls,
        &forward_counter,
        &transcript_path,
        None,
    );
    let provider_port = distinct_unused_port(&[issuer_port, edge_port]);
    let provider_server = spawn_provider(
        root.path(),
        &db_path,
        &provider,
        provider_port,
        0,
        Some(&tls.root),
    );

    exercise_free_pow_grant_and_dpf(provider_port, &provider, manifest_root)
        .await
        .expect("Free-PoW offer in the combined policy must authorize one real DPF query");
    assert_eq!(
        forwarded_request_count(&forward_counter),
        0,
        "Free-PoW must not contact the shared issuer"
    );

    // Stop only the issuer to inspect its durable inventory, then restart it
    // against the same store before presenting the premium BAT on the already
    // running strict provider.
    let (free_issuer_stdout, free_issuer_stderr) = payment_issuer.stop();
    assert_issuer_log(&free_issuer_stdout, &free_issuer_stderr, &provider);
    assert_issuer_redemption_inventory(&issuer, 0);
    let payment_issuer = spawn_payment_issuer(root.path(), issuer_port, &issuer, &[&provider]);

    exercise_grant_and_dpf(provider_port, &provider, manifest_root)
        .await
        .expect("shared-issuer BAT in the combined policy must authorize one real DPF query");
    assert_eq!(
        forwarded_request_count(&forward_counter),
        1,
        "only the premium BAT must reach the issuer redeem endpoint"
    );

    let (provider_stdout, provider_stderr) = provider_server.stop();
    assert_server_log(&provider_stdout, &provider_stderr, provider_port, &provider);
    assert_provider_spend_inventory(&provider, 1);
    let (edge_stdout, edge_stderr) = tls_edge.stop();
    let (issuer_stdout, issuer_stderr) = payment_issuer.stop();
    assert_payment_material_absent(&edge_stdout, &edge_stderr, &[&provider]);
    assert_issuer_log(&issuer_stdout, &issuer_stderr, &provider);
    assert_issuer_ledger(&issuer, &provider, &[]);
}

fn build_issuer_material(root: &Path, now: u64) -> IssuerMaterial {
    let binary = required_payment_issuer_binary();
    let admin_binary = required_bpir_admin_binary();
    let issuer_root_dir = root.join("payment-issuer");
    let store_dir = issuer_root_dir.join("store-domain");
    fs::create_dir_all(&store_dir).unwrap();
    chmod(&issuer_root_dir, 0o700);
    chmod(&store_dir, 0o700);

    let issuer_root = SigningKey::from_bytes(&[0x31; 32]);
    let quote_signing_key = SigningKey::from_bytes(&[0x32; 32]);
    let settlement_signing_key = SigningKey::from_bytes(&[0x33; 32]);
    let fake_lightning_signing_key = [0x34; 32];
    let fake_lightning_derivation_seed = [0x35; 32];
    let bat_key = [0x36; 32];
    let credential_derivation_key = [0x37; 32];
    let redeem_response_derivation_key = [0x38; 32];
    let issuer_id = derive_issuer_id(&issuer_root.verifying_key().to_bytes());
    let fake_lightning = FakeLightningNodeV1::new(
        LightningNetworkV1::Regtest,
        fake_lightning_signing_key,
        fake_lightning_derivation_seed,
        now,
    )
    .expect("construct no-funds fake Lightning identity");
    let delegation = Bolt11QuoteKeyDelegationV1::sign(
        LightningNetworkV1::Regtest,
        fake_lightning.payee_pubkey(),
        1,
        now.saturating_sub(60),
        now + 3_600,
        quote_signing_key.verifying_key().to_bytes(),
        &issuer_root,
    )
    .expect("sign issuer quote delegation");

    let quote_delegation_path = issuer_root_dir.join("quote-delegation.bin");
    let quote_signing_key_path = issuer_root_dir.join("quote-signing.key");
    let credential_derivation_key_path = issuer_root_dir.join("credential-derivation.key");
    let bat_key_path = issuer_root_dir.join("bat.key");
    let fake_lightning_signing_key_path = issuer_root_dir.join("fake-lightning-signing.key");
    let fake_lightning_derivation_seed_path = issuer_root_dir.join("fake-lightning-seed.key");
    let issuer_settlement_signing_key_path = issuer_root_dir.join("settlement-signing.key");
    let redeem_response_derivation_key_path = issuer_root_dir.join("redeem-response.key");
    write_public_file(
        &quote_delegation_path,
        &delegation.encode().expect("encode quote delegation"),
    );
    write_private_file(&quote_signing_key_path, &quote_signing_key.to_bytes());
    write_private_file(&credential_derivation_key_path, &credential_derivation_key);
    write_private_file(&bat_key_path, &bat_key);
    write_private_file(
        &fake_lightning_signing_key_path,
        &fake_lightning_signing_key,
    );
    write_private_file(
        &fake_lightning_derivation_seed_path,
        &fake_lightning_derivation_seed,
    );
    write_private_file(
        &issuer_settlement_signing_key_path,
        &settlement_signing_key.to_bytes(),
    );
    write_private_file(
        &redeem_response_derivation_key_path,
        &redeem_response_derivation_key,
    );

    IssuerMaterial {
        binary,
        admin_binary,
        issuer_id,
        issuer_root,
        settlement_signing_key,
        store_path: store_dir.join("issuer.sqlite3"),
        quote_delegation_path,
        quote_signing_key_path,
        credential_derivation_key_path,
        bat_key_path,
        fake_lightning_signing_key_path,
        fake_lightning_derivation_seed_path,
        issuer_settlement_signing_key_path,
        retained_issuer_settlement_verifying_key_paths: Vec::new(),
        redeem_response_derivation_key_path,
        bat_keyring: Arc::new(
            K256CashuMintKeyringV1::from_secret_keys([bat_key])
                .expect("construct deterministic BAT keyring"),
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_provider(
    root: &Path,
    index: u8,
    method: ProviderMethod,
    manifest_root: [u8; 32],
    issuer: &IssuerMaterial,
    redeem_endpoint: &str,
    redeem_pins: Vec<[u8; 32]>,
    now: u64,
) -> ProviderFixture {
    let provider_root = root.join(format!("provider-{index}"));
    let store_dir = provider_root.join("store-domain");
    fs::create_dir_all(&store_dir).unwrap();
    chmod(&provider_root, 0o700);
    chmod(&store_dir, 0o700);

    let operator = SigningKey::from_bytes(&[0x40u8.wrapping_add(index); 32]);
    let policy_signing_key = SigningKey::from_bytes(&[0x60u8.wrapping_add(index); 32]);
    let provider_id = derive_provider_id(
        &operator.verifying_key().to_bytes(),
        &format!("shared-issuer-process-provider-{index}"),
    );
    let issued_at = now.saturating_sub(60);
    let expires_at = now + 3_600;
    let retired_grace = 1_800u32;
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

    let (mut offers, shared) = match method {
        ProviderMethod::SharedIssuerBat | ProviderMethod::SharedIssuerBatWithFreePow => {
            assert!(redeem_endpoint.starts_with("https://localhost:"));
            assert!(!redeem_pins.is_empty());
            let denomination_public_key = issuer.bat_keyring.denomination_public_keys()[0];
            let credential_key_id = derive_bat_key_id_v1(
                &provider_id,
                &scope_id,
                SHARED_OFFER_ID,
                ENTITLEMENT_PROFILE,
                1,
                &denomination_public_key,
            );
            let binding = CredentialKeyBindingV1::sign(
                CredentialKeyBindingClaimsV1 {
                    provider_id,
                    scope_id,
                    offer_id: SHARED_OFFER_ID,
                    scheme: AuthScheme::BitcoinPirCashuBatV1,
                    keyset_epoch: 1,
                    entitlement_profile: ENTITLEMENT_PROFILE,
                    unit: CredentialUnitV1::Auth,
                    amount: 1,
                    presentation_limit: 1,
                    not_before: issued_at,
                    not_after: expires_at + u64::from(retired_grace),
                    credential_key_id: credential_key_id.to_vec(),
                    verification_key: denomination_public_key.to_vec(),
                },
                &issuer.issuer_root,
            )
            .expect("sign shared BAT binding");
            let offer = ServiceOfferV1 {
                offer_id: SHARED_OFFER_ID,
                acquisition: AcquisitionMethod::Bolt11V1,
                free_mode: FreeModeV1::NotFree,
                free_quota: 0,
                free_window_seconds: 0,
                free_pow_difficulty_bits: 0,
                priority_class: 10,
                authorization: AuthScheme::BitcoinPirCashuBatV1,
                verification: VerificationMode::SharedIssuerOnline,
                deployment_status: DeploymentStatus::Stable,
                price: PriceV1::MilliSatoshi(1_000),
                issuer_id: issuer.issuer_id,
                key_id: credential_key_id.to_vec(),
                credential_binding: Some(binding.clone()),
                cashu_mint_manifest: None,
                endpoint: redeem_endpoint.to_owned(),
                invoice_expiry_seconds: 600,
                claim_window_seconds: 600,
                minimum_credential_validity_seconds: 60,
                retired_policy_grace_seconds: retired_grace,
                credential_count: 1,
                credential_presentation_limit: 1,
                privacy_leakage: PrivacyLeakageV1::from_bits(
                    PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING
                        | PrivacyLeakageV1::ISSUER_REDEMPTION_TIMING
                        | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER,
                )
                .expect("known shared-issuer privacy flags"),
            };
            let clearing = SigningKey::from_bytes(&[0x80u8.wrapping_add(index); 32]);
            let provider_request = SigningKey::from_bytes(&[0x90u8.wrapping_add(index); 32]);
            let idempotency_key = [0xa0u8.wrapping_add(index); 32];
            let account_id = [0xb0u8.wrapping_add(index); 32];
            let secret_raw = [0xe0u8.wrapping_add(index); 32];
            let hashed = cashu_hash_to_curve_v1(&secret_raw).expect("hash BAT secret to curve");
            let signed = issuer
                .bat_keyring
                .blind_sign_with_dleq_v1(
                    &denomination_public_key,
                    &hashed,
                    &[0xf0u8.wrapping_add(index); 32],
                )
                .expect("sign deterministic BAT proof");
            let proof = BitcoinPirCashuBatProofV1 {
                secret_raw,
                c: *signed.blinded_signature(),
            };

            let authorization_path = provider_root.join("clearing-authorization.bin");
            let approval_path = provider_root.join("issuer-approval.bin");
            let operator_key_path = provider_root.join("operator.key");
            let authorization_config_path = provider_root.join("clearing-authorization.toml");
            let clearing_key_path = provider_root.join("clearing.key");
            let provider_request_verifying_key_path =
                provider_root.join("provider-request-verifying.key");
            let idempotency_key_path = provider_root.join("redeem-idempotency.key");
            write_private_file(&operator_key_path, &operator.to_bytes());
            write_private_file(&clearing_key_path, &clearing.to_bytes());
            write_public_file(
                &provider_request_verifying_key_path,
                &provider_request.verifying_key().to_bytes(),
            );
            write_private_file(&idempotency_key_path, &idempotency_key);
            let authorization_config = format!(
                "authorization_id_hex = \"{}\"\n\
                 authorization_epoch = 1\n\
                 provider_id_hex = \"{}\"\n\
                 issuer_id_hex = \"{}\"\n\
                 redeem_endpoint = \"{}\"\n\
                 redeem_leaf_spki_sha256_pins_hex = [{}]\n\
                 settlement_account_id_hex = \"{}\"\n\
                 clearing_verifying_key_hex = \"{}\"\n\
                 not_before = {}\n\
                 not_after = {}\n\
                 [[rules]]\n\
                 credential_binding_digest_hex = \"{}\"\n\
                 accepted_value = 10\n\
                 provider_credit = 9\n\
                 issuer_fee = 1\n\
                 denomination_profile = 1\n",
                hex::encode([0xd0u8.wrapping_add(index); 16]),
                hex::encode(provider_id),
                hex::encode(issuer.issuer_id),
                redeem_endpoint,
                redeem_pins
                    .iter()
                    .map(|pin| format!("\"{}\"", hex::encode(pin)))
                    .collect::<Vec<_>>()
                    .join(", "),
                hex::encode(account_id),
                hex::encode(clearing.verifying_key().to_bytes()),
                issued_at,
                expires_at,
                hex::encode(binding.binding_digest().expect("shared BAT binding digest")),
            );
            write_public_file(&authorization_config_path, authorization_config.as_bytes());
            let authorization_output = Command::new(&issuer.admin_binary)
                .args([
                    OsString::from("payment-artifact"),
                    OsString::from("clearing-authorization"),
                    OsString::from("--operator-signing-key"),
                    operator_key_path.as_os_str().to_owned(),
                    OsString::from("--config"),
                    authorization_config_path.as_os_str().to_owned(),
                    OsString::from("--out"),
                    authorization_path.as_os_str().to_owned(),
                ])
                .stdin(Stdio::null())
                .output()
                .expect("run bpir-admin clearing-authorization");
            assert_command_success("bpir-admin clearing-authorization", &authorization_output);
            let authorization = ProviderClearingAuthorizationV1::decode(
                &fs::read(&authorization_path).expect("read generated clearing authorization"),
            )
            .expect("decode generated clearing authorization");
            let approval_output = Command::new(&issuer.admin_binary)
                .args([
                    OsString::from("payment-artifact"),
                    OsString::from("clearing-approval"),
                    OsString::from("--authorization"),
                    authorization_path.as_os_str().to_owned(),
                    OsString::from("--issuer-settlement-signing-key"),
                    issuer
                        .issuer_settlement_signing_key_path
                        .as_os_str()
                        .to_owned(),
                    OsString::from("--expected-authorization-digest-hex"),
                    OsString::from(hex::encode(
                        authorization
                            .authorization_digest()
                            .expect("generated authorization digest"),
                    )),
                    OsString::from("--expected-provider-id-hex"),
                    OsString::from(hex::encode(provider_id)),
                    OsString::from("--expected-issuer-id-hex"),
                    OsString::from(hex::encode(issuer.issuer_id)),
                    OsString::from("--expected-operator-key-hex"),
                    OsString::from(hex::encode(operator.verifying_key().to_bytes())),
                    OsString::from("--minimum-authorization-epoch"),
                    OsString::from("1"),
                    OsString::from("--approved-at"),
                    OsString::from(issued_at.to_string()),
                    OsString::from("--not-after"),
                    OsString::from(expires_at.to_string()),
                    OsString::from("--out"),
                    approval_path.as_os_str().to_owned(),
                ])
                .stdin(Stdio::null())
                .output()
                .expect("run bpir-admin clearing-approval");
            assert_command_success("bpir-admin clearing-approval", &approval_output);
            IssuerClearingApprovalV1::decode(
                &fs::read(&approval_path).expect("read generated clearing approval"),
            )
            .expect("decode generated clearing approval")
            .verify_for(
                &authorization,
                &issuer.settlement_signing_key.verifying_key(),
                issued_at,
                1,
            )
            .expect("self-verified CLI clearing approval");
            (
                vec![offer],
                Some(SharedProviderConfig {
                    authorization_epoch: 1,
                    authorization_path,
                    approval_path,
                    operator_key_path,
                    operator_verifying_key: operator.verifying_key(),
                    issuer_settlement_verifying_key: issuer.settlement_signing_key.verifying_key(),
                    clearing_key_path,
                    provider_request_verifying_key_path,
                    idempotency_key_path,
                    proof,
                    account_id,
                }),
            )
        }
        ProviderMethod::FreeOpen => {
            assert!(redeem_endpoint.is_empty());
            assert!(redeem_pins.is_empty());
            (
                vec![ServiceOfferV1 {
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
                        .expect("known Free privacy flags"),
                }],
                None,
            )
        }
    };

    if method == ProviderMethod::SharedIssuerBatWithFreePow {
        offers.push(ServiceOfferV1 {
            offer_id: FREE_POW_OFFER_ID,
            acquisition: AcquisitionMethod::FreeV1,
            free_mode: FreeModeV1::OpenBestEffort,
            free_quota: 0,
            free_window_seconds: 0,
            free_pow_difficulty_bits: FREE_POW_DIFFICULTY_BITS,
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
        });
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
    .expect("sign provider policy");
    let policy_digest = policy.policy_digest().expect("provider policy digest");
    let policy_path = provider_root.join("service-policy-v1.bin");
    write_public_file(
        &policy_path,
        &policy.encode().expect("encode provider policy"),
    );

    let store_path = store_dir.join("provider.sqlite3");
    let store = ProviderStore::create(
        &store_path,
        [0x20u8.wrapping_add(index); 16],
        provider_id,
        ProviderStoreOptions::default(),
    )
    .expect("create provider store");
    drop(store);

    ProviderFixture {
        index,
        method,
        provider_id,
        policy_signing_key,
        policy_path,
        store_path,
        scope_id,
        policy_digest,
        shared,
    }
}

fn rotate_shared_clearing_artifacts(
    issuer: &mut IssuerMaterial,
    fixture: &mut ProviderFixture,
    now: u64,
) -> VerifyingKey {
    let shared = fixture.shared.as_mut().expect("shared provider config");
    let old_settlement_key = issuer.settlement_signing_key.verifying_key();
    assert_eq!(old_settlement_key, shared.issuer_settlement_verifying_key);
    let old_authorization = ProviderClearingAuthorizationV1::decode(
        &fs::read(&shared.authorization_path).expect("read old clearing authorization"),
    )
    .expect("decode old clearing authorization");
    assert_eq!(old_authorization.claims.rules.len(), 1);
    let old_rule = &old_authorization.claims.rules[0];

    let issuer_root = issuer
        .issuer_settlement_signing_key_path
        .parent()
        .expect("issuer settlement key parent");
    let retained_path = issuer_root.join("settlement-verifying-v1.pub");
    write_public_file(&retained_path, &old_settlement_key.to_bytes());
    issuer
        .retained_issuer_settlement_verifying_key_paths
        .push(retained_path);
    let rotated_settlement = SigningKey::from_bytes(&[0x39; 32]);
    assert_ne!(
        rotated_settlement.verifying_key().to_bytes(),
        old_settlement_key.to_bytes()
    );
    let rotated_settlement_path = issuer_root.join("settlement-signing-v2.key");
    write_private_file(&rotated_settlement_path, &rotated_settlement.to_bytes());

    let provider_root = shared
        .authorization_path
        .parent()
        .expect("provider authorization parent");
    let config_path = provider_root.join("clearing-authorization-v2.toml");
    let authorization_path = provider_root.join("clearing-authorization-v2.bin");
    let approval_path = provider_root.join("issuer-approval-v2.bin");
    let issued_at = now.saturating_sub(1);
    let not_after = old_authorization.claims.not_after;
    let config = format!(
        "authorization_id_hex = \"{}\"\n\
         authorization_epoch = 2\n\
         provider_id_hex = \"{}\"\n\
         issuer_id_hex = \"{}\"\n\
         redeem_endpoint = \"{}\"\n\
         redeem_leaf_spki_sha256_pins_hex = [{}]\n\
         settlement_account_id_hex = \"{}\"\n\
         clearing_verifying_key_hex = \"{}\"\n\
         not_before = {}\n\
         not_after = {}\n\
         [[rules]]\n\
         credential_binding_digest_hex = \"{}\"\n\
         accepted_value = {}\n\
         provider_credit = {}\n\
         issuer_fee = {}\n\
         denomination_profile = {}\n",
        hex::encode([0xd2; 16]),
        hex::encode(old_authorization.claims.provider_id),
        hex::encode(old_authorization.claims.issuer_id),
        old_authorization.claims.redeem_endpoint,
        old_authorization
            .claims
            .redeem_leaf_spki_sha256_pins
            .iter()
            .map(|pin| format!("\"{}\"", hex::encode(pin)))
            .collect::<Vec<_>>()
            .join(", "),
        hex::encode(old_authorization.claims.settlement_account_id),
        hex::encode(old_authorization.claims.clearing_verifying_key),
        issued_at,
        not_after,
        hex::encode(old_rule.credential_binding_digest),
        old_rule.accepted_value,
        old_rule.provider_credit,
        old_rule.issuer_fee,
        old_rule.denomination_profile,
    );
    write_public_file(&config_path, config.as_bytes());
    let authorization_output = Command::new(&issuer.admin_binary)
        .args([
            OsString::from("payment-artifact"),
            OsString::from("clearing-authorization"),
            OsString::from("--operator-signing-key"),
            shared.operator_key_path.as_os_str().to_owned(),
            OsString::from("--config"),
            config_path.as_os_str().to_owned(),
            OsString::from("--out"),
            authorization_path.as_os_str().to_owned(),
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run rotated bpir-admin clearing-authorization");
    assert_command_success(
        "bpir-admin rotated clearing-authorization",
        &authorization_output,
    );
    let authorization = ProviderClearingAuthorizationV1::decode(
        &fs::read(&authorization_path).expect("read rotated clearing authorization"),
    )
    .expect("decode rotated clearing authorization");
    let approval_output = Command::new(&issuer.admin_binary)
        .args([
            OsString::from("payment-artifact"),
            OsString::from("clearing-approval"),
            OsString::from("--authorization"),
            authorization_path.as_os_str().to_owned(),
            OsString::from("--issuer-settlement-signing-key"),
            rotated_settlement_path.as_os_str().to_owned(),
            OsString::from("--expected-authorization-digest-hex"),
            OsString::from(hex::encode(
                authorization
                    .authorization_digest()
                    .expect("rotated authorization digest"),
            )),
            OsString::from("--expected-provider-id-hex"),
            OsString::from(hex::encode(fixture.provider_id)),
            OsString::from("--expected-issuer-id-hex"),
            OsString::from(hex::encode(issuer.issuer_id)),
            OsString::from("--expected-operator-key-hex"),
            OsString::from(hex::encode(shared.operator_verifying_key.to_bytes())),
            OsString::from("--minimum-authorization-epoch"),
            OsString::from("2"),
            OsString::from("--approved-at"),
            OsString::from(issued_at.to_string()),
            OsString::from("--not-after"),
            OsString::from(not_after.to_string()),
            OsString::from("--out"),
            approval_path.as_os_str().to_owned(),
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run rotated bpir-admin clearing-approval");
    assert_command_success("bpir-admin rotated clearing-approval", &approval_output);
    let approval = IssuerClearingApprovalV1::decode(
        &fs::read(&approval_path).expect("read rotated issuer clearing approval"),
    )
    .expect("decode rotated issuer clearing approval");
    approval
        .verify_for(
            &authorization,
            &rotated_settlement.verifying_key(),
            issued_at,
            2,
        )
        .expect("verify rotated issuer clearing approval");

    issuer.settlement_signing_key = rotated_settlement;
    issuer.issuer_settlement_signing_key_path = rotated_settlement_path;
    shared.authorization_epoch = 2;
    shared.authorization_path = authorization_path;
    shared.approval_path = approval_path;
    shared.issuer_settlement_verifying_key = issuer.settlement_signing_key.verifying_key();
    old_settlement_key
}

fn init_issuer_store(issuer: &IssuerMaterial) {
    let output = Command::new(&issuer.binary)
        .args([
            OsString::from("init-store"),
            OsString::from("--store"),
            issuer.store_path.as_os_str().to_owned(),
            OsString::from("--issuer-id-hex"),
            OsString::from(hex::encode(issuer.issuer_id)),
            OsString::from("--network"),
            OsString::from("regtest"),
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run payment-issuer init-store");
    assert_command_success("payment-issuer init-store", &output);
    assert_private_regular_file(&issuer.store_path);
}

fn spawn_payment_issuer(
    root: &Path,
    port: u16,
    issuer: &IssuerMaterial,
    providers: &[&ProviderFixture],
) -> ChildProcess {
    let label = "payment-issuer-fake".to_owned();
    let stdout_path = root.join("payment-issuer-stdout.log");
    let stderr_path = root.join("payment-issuer-stderr.log");
    let stdout = File::create(&stdout_path).expect("create payment-issuer stdout log");
    let stderr = File::create(&stderr_path).expect("create payment-issuer stderr log");
    let mut args = vec![
        OsString::from("serve-fake"),
        OsString::from("--bind"),
        OsString::from(format!("127.0.0.1:{port}")),
        OsString::from("--store"),
        issuer.store_path.as_os_str().to_owned(),
        OsString::from("--quote-delegation"),
        issuer.quote_delegation_path.as_os_str().to_owned(),
        OsString::from("--quote-signing-key"),
        issuer.quote_signing_key_path.as_os_str().to_owned(),
        OsString::from("--credential-derivation-key"),
        issuer.credential_derivation_key_path.as_os_str().to_owned(),
        OsString::from("--bat-key"),
        issuer.bat_key_path.as_os_str().to_owned(),
        OsString::from("--issuer-settlement-signing-key"),
        issuer
            .issuer_settlement_signing_key_path
            .as_os_str()
            .to_owned(),
        OsString::from("--redeem-response-derivation-key"),
        issuer
            .redeem_response_derivation_key_path
            .as_os_str()
            .to_owned(),
        OsString::from("--fake-lightning-signing-key"),
        issuer
            .fake_lightning_signing_key_path
            .as_os_str()
            .to_owned(),
        OsString::from("--fake-lightning-derivation-seed"),
        issuer
            .fake_lightning_derivation_seed_path
            .as_os_str()
            .to_owned(),
        OsString::from("--max-connections"),
        OsString::from("32"),
        OsString::from("--mutation-rate-per-minute"),
        OsString::from("1000"),
    ];
    for retained_key_path in &issuer.retained_issuer_settlement_verifying_key_paths {
        args.extend([
            OsString::from("--retained-issuer-settlement-verifying-key"),
            retained_key_path.as_os_str().to_owned(),
        ]);
    }
    for fixture in providers {
        let shared = fixture.shared.as_ref().expect("shared issuer provider");
        args.extend([
            OsString::from("--service-policy"),
            OsString::from(format!(
                "{}={}",
                fixture.policy_path.display(),
                hex::encode(fixture.policy_signing_key.verifying_key().to_bytes())
            )),
            OsString::from("--clearing-authorization"),
            shared.authorization_path.as_os_str().to_owned(),
            OsString::from("--clearing-approval"),
            shared.approval_path.as_os_str().to_owned(),
            OsString::from("--clearing-provider-request-verifying-key"),
            shared
                .provider_request_verifying_key_path
                .as_os_str()
                .to_owned(),
        ]);
    }

    let child = Command::new(&issuer.binary)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("spawn real payment-issuer binary from BITCOINPIR_PAYMENT_ISSUER_BIN");
    let mut process = ChildProcess {
        label,
        child,
        stdout_path,
        stderr_path,
    };
    process.wait_until_listening(port);
    process
}

fn spawn_provider(
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
    let stdout = File::create(&stdout_path).expect("create provider stdout log");
    let stderr = File::create(&stderr_path).expect("create provider stderr log");
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
        "--require-service-auth-v1".to_owned(),
        "--service-policy".to_owned(),
        fixture.policy_path.to_string_lossy().into_owned(),
        "--service-provider-id-hex".to_owned(),
        hex::encode(fixture.provider_id),
        "--service-policy-key-hex".to_owned(),
        hex::encode(fixture.policy_signing_key.verifying_key().to_bytes()),
        "--service-store".to_owned(),
        fixture.store_path.to_string_lossy().into_owned(),
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
    if let Some(shared) = &fixture.shared {
        let test_root = test_root.expect("shared issuer provider requires a WebPKI root");
        args.extend([
            "--service-shared-authorization".to_owned(),
            shared.authorization_path.to_string_lossy().into_owned(),
            "--service-shared-issuer-approval".to_owned(),
            shared.approval_path.to_string_lossy().into_owned(),
            "--service-shared-operator-key-hex".to_owned(),
            hex::encode(shared.operator_verifying_key.to_bytes()),
            "--service-shared-issuer-settlement-key-hex".to_owned(),
            hex::encode(shared.issuer_settlement_verifying_key.to_bytes()),
            "--service-shared-clearing-key".to_owned(),
            shared.clearing_key_path.to_string_lossy().into_owned(),
            "--service-shared-idempotency-key".to_owned(),
            shared.idempotency_key_path.to_string_lossy().into_owned(),
            "--service-shared-minimum-authorization-epoch".to_owned(),
            shared.authorization_epoch.to_string(),
            "--test-only-service-https-root-pem".to_owned(),
            test_root.to_string_lossy().into_owned(),
        ]);
    } else {
        assert!(test_root.is_none());
    }
    if fixture.method == ProviderMethod::SharedIssuerBatWithFreePow {
        assert!(
            !args.iter().any(|arg| {
                arg == "--service-bat-key" || arg == "--service-arc-key"
            }),
            "combined shared-issuer/Free-PoW process test must not pass provider-local BAT or ARC keys"
        );
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

fn spawn_tls_edge(
    root: &Path,
    port: u16,
    issuer_port: u16,
    material: &TlsMaterial,
    counter_path: &Path,
    transcript_path: &Path,
    drop_success_once_path: Option<&Path>,
) -> ChildProcess {
    let label = "shared-issuer-tls-edge".to_owned();
    let stdout_path = root.join("shared-issuer-tls-edge-stdout.log");
    let stderr_path = root.join("shared-issuer-tls-edge-stderr.log");
    let stdout = File::create(&stdout_path).expect("create TLS edge stdout log");
    let stderr = File::create(&stderr_path).expect("create TLS edge stderr log");
    let mut command =
        Command::new(env::current_exe().expect("current integration test executable"));
    command
        .args([
            "--ignored",
            "--exact",
            "shared_issuer_tls_edge_subprocess",
            "--nocapture",
        ])
        .env(TLS_EDGE_HELPER_MARKER, "1")
        .env(
            "BITCOINPIR_TEST_SHARED_ISSUER_EDGE_BIND",
            format!("127.0.0.1:{port}"),
        )
        .env(
            "BITCOINPIR_TEST_SHARED_ISSUER_UPSTREAM",
            format!("127.0.0.1:{issuer_port}"),
        )
        .env("BITCOINPIR_TEST_SHARED_ISSUER_CERT", &material.certificate)
        .env("BITCOINPIR_TEST_SHARED_ISSUER_KEY", &material.private_key)
        .env(
            "BITCOINPIR_TEST_SHARED_ISSUER_FORWARD_COUNTER",
            counter_path,
        )
        .env(TLS_EDGE_TRANSCRIPT_PATH, transcript_path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    if let Some(path) = drop_success_once_path {
        command.env(TLS_EDGE_DROP_SUCCESS_ONCE_PATH, path);
    }
    let child = command
        .spawn()
        .expect("spawn shared-issuer TLS edge process");
    let mut process = ChildProcess {
        label,
        child,
        stdout_path,
        stderr_path,
    };
    process.wait_until_listening(port);
    process
}

async fn exercise_grant_and_dpf(
    port: u16,
    fixture: &ProviderFixture,
    manifest_root: [u8; 32],
) -> Result<(), String> {
    let request = valid_tiny_dpf_request();
    let (mut secure, accepted) =
        open_verified_session(port, fixture, manifest_root, &request).await;
    let grant = dangerous_unpaired_authorize_service_operation_v1(
        &mut secure,
        &accepted,
        fixture.scope_id,
        fixture.offer_id(),
        OperationStartV1::DpfQuery { db_id: 0 },
        fixture.proof(),
    )
    .await
    .map_err(|error| error.to_string())?;
    if grant.scope_id != fixture.scope_id || grant.enforced_profile != ENTITLEMENT_PROFILE {
        return Err("AUTH grant did not bind the selected scope/profile".to_owned());
    }
    let response = secure
        .roundtrip(&request)
        .await
        .map_err(|error| error.to_string())?;
    match Response::decode(&response).map_err(|error| error.to_string())? {
        Response::IndexBatch(result)
            if result.results.len() == 1
                && result.results[0].len() == 2
                && result.results[0].iter().all(|item| item.len() == 52) => {}
        other => {
            return Err(format!(
                "authorized DPF frame did not reach handler: {other:?}"
            ))
        }
    }
    secure.close().await.map_err(|error| error.to_string())?;
    Ok(())
}

async fn exercise_free_pow_grant_and_dpf(
    port: u16,
    fixture: &ProviderFixture,
    manifest_root: [u8; 32],
) -> Result<(), String> {
    let request = valid_tiny_dpf_request();
    let (mut secure, accepted) =
        open_verified_session(port, fixture, manifest_root, &request).await;
    let operation = OperationStartV1::DpfQuery { db_id: 0 };
    let challenge = request_pow_challenge_v1(
        &mut secure,
        &accepted,
        fixture.scope_id,
        FREE_POW_OFFER_ID,
        operation.clone(),
        unix_now(),
    )
    .await
    .map_err(|error| error.to_string())?;
    if challenge.difficulty_bits != FREE_POW_DIFFICULTY_BITS {
        return Err(format!(
            "combined Free-PoW challenge used {} bits instead of {FREE_POW_DIFFICULTY_BITS}",
            challenge.difficulty_bits
        ));
    }
    let solution = solve_pow(&challenge);
    let proof = dangerous_unpaired_build_authorization_proof_v1(
        &accepted,
        &fixture.scope_id,
        FREE_POW_OFFER_ID,
        &solution.encode().map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let grant = dangerous_unpaired_authorize_service_operation_v1(
        &mut secure,
        &accepted,
        fixture.scope_id,
        FREE_POW_OFFER_ID,
        operation,
        proof,
    )
    .await
    .map_err(|error| error.to_string())?;
    if grant.scope_id != fixture.scope_id || grant.enforced_profile != ENTITLEMENT_PROFILE {
        return Err("Free-PoW AUTH grant did not bind the selected scope/profile".to_owned());
    }
    let response = secure
        .roundtrip(&request)
        .await
        .map_err(|error| error.to_string())?;
    match Response::decode(&response).map_err(|error| error.to_string())? {
        Response::IndexBatch(result)
            if result.results.len() == 1
                && result.results[0].len() == 2
                && result.results[0].iter().all(|item| item.len() == 52) => {}
        other => {
            return Err(format!(
                "Free-PoW authorized DPF frame did not reach handler: {other:?}"
            ))
        }
    }
    secure.close().await.map_err(|error| error.to_string())?;
    Ok(())
}

async fn authorize_only(
    port: u16,
    fixture: &ProviderFixture,
    manifest_root: [u8; 32],
) -> Result<(), String> {
    let request = valid_tiny_dpf_request();
    let (mut secure, accepted) =
        open_verified_session(port, fixture, manifest_root, &request).await;
    let result = dangerous_unpaired_authorize_service_operation_v1(
        &mut secure,
        &accepted,
        fixture.scope_id,
        fixture.offer_id(),
        OperationStartV1::DpfQuery { db_id: 0 },
        fixture.proof(),
    )
    .await
    .map(|_| ())
    .map_err(|error| error.to_string());
    let _ = secure.close().await;
    result
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
    let mut raw = WsConnection::connect_once(&format!("ws://127.0.0.1:{port}"))
        .await
        .expect("connect real provider WebSocket");

    let pre_secure_policy = fetch_verified_service_policy_v1(
        &mut raw,
        fixture.provider_id,
        &fixture.policy_signing_key.verifying_key(),
        unix_now(),
        &ServicePolicyCheckpointV1::initial(),
    )
    .await
    .expect_err("policy fetch before secure-channel upgrade must fail");
    assert!(pre_secure_policy.to_string().contains("secure-channel"));
    expect_error_response(
        &raw.roundtrip(backend_request)
            .await
            .expect("cleartext backend rejection"),
        "secure encrypted channel is required",
    );

    let session_id = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut eph_seed = [0x21u8.wrapping_add(fixture.index); 32];
    let mut random = [0x41u8.wrapping_add(fixture.index); 32];
    let mut handshake_nonce = [0x61u8.wrapping_add(fixture.index); 32];
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
    .expect("mandatory secure-channel upgrade");
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
        &secure
            .roundtrip(backend_request)
            .await
            .expect("pre-AUTH backend rejection"),
        "authorization required",
    );
    (secure, accepted)
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

fn solve_pow(challenge: &PowChallengeResponseV1) -> FreePowProofV1 {
    for nonce in 0..=u64::MAX {
        let solution = FreePowProofV1 {
            challenge_id: challenge.challenge_id,
            nonce,
        };
        if pow_solution_meets_difficulty_v1(challenge, &solution)
            .expect("test Free-PoW challenge must be valid")
        {
            return solution;
        }
    }
    unreachable!("bounded test Free-PoW difficulty has a solution")
}

fn expect_error_response(response: &[u8], needle: &str) {
    match Response::decode(response).expect("decode runtime response") {
        Response::Error(message) => assert!(
            message.contains(needle),
            "expected error containing {needle:?}, got {message:?}"
        ),
        other => panic!("expected server error containing {needle:?}, got {other:?}"),
    }
}

fn write_tiny_manifest_database(root: &Path) -> (PathBuf, [u8; 32]) {
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
        "[manifest]\nversion = 1\ngenerated_at = \"2026-07-29T00:00:00Z\"\n\n[files]\n\"batch_pir_cuckoo.bin\" = \"{zero_hash}\"\n\"chunk_pir_cuckoo.bin\" = \"{zero_hash}\"\n"
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

fn assert_provider_spend_inventory(fixture: &ProviderFixture, expected: u64) {
    let store = ProviderStore::open_existing(
        &fixture.store_path,
        fixture.provider_id,
        ProviderStoreOptions::default(),
    )
    .expect("open provider store for audit");
    let inventory = store
        .operational_inventory()
        .expect("provider operational inventory");
    assert_eq!(inventory.spent_capability_rows, expected);
    assert_eq!(inventory.observed_spend_commit_seq, expected);
}

fn assert_issuer_redemption_inventory(issuer: &IssuerMaterial, expected: u64) {
    let store = IssuerStore::open_existing(
        &issuer.store_path,
        issuer.issuer_id,
        LightningNetworkV1::Regtest,
        IssuerStoreOptions::default(),
    )
    .expect("open issuer store for redemption inventory");
    assert_eq!(
        store
            .operational_inventory()
            .expect("issuer operational inventory")
            .redemption_rows,
        expected
    );
}

fn assert_issuer_ledger(
    issuer: &IssuerMaterial,
    paid: &ProviderFixture,
    failed: &[&ProviderFixture],
) {
    let store = IssuerStore::open_existing(
        &issuer.store_path,
        issuer.issuer_id,
        LightningNetworkV1::Regtest,
        IssuerStoreOptions::default(),
    )
    .expect("open issuer store for audit");
    let paid_balance = store
        .provider_ledger_balance(&paid.provider_id)
        .expect("read paid provider ledger")
        .expect("paid provider ledger exists");
    assert_eq!(
        paid_balance.account_id,
        paid.shared.as_ref().unwrap().account_id
    );
    assert_eq!(paid_balance.unit, SettlementUnitV1::AuthCredit);
    assert_eq!(paid_balance.ledger_sequence, 1);
    assert_eq!(
        (paid_balance.available_value, paid_balance.reserved_value),
        (9, 0)
    );
    for fixture in failed {
        assert!(store
            .provider_ledger_balance(&fixture.provider_id)
            .expect("read failed provider ledger")
            .is_none());
    }
    let inventory = store
        .operational_inventory()
        .expect("issuer operational inventory");
    assert_eq!(inventory.redemption_rows, 1);
    assert_eq!(inventory.payout_rows, 0);
}

fn read_signed_ledger_balance(
    fixture: &ProviderFixture,
    test_root: &Path,
    nonce: [u8; 32],
    retained_issuer_settlement_keys: Vec<VerifyingKey>,
) -> pir_service_protocol::IssuerBalanceResponseV1 {
    let shared = fixture.shared.as_ref().expect("shared provider config");
    let authorization_bytes = fs::read(&shared.authorization_path)
        .expect("read generated provider clearing authorization");
    let authorization = ProviderClearingAuthorizationV1::decode(&authorization_bytes)
        .expect("decode generated provider clearing authorization");
    assert_eq!(authorization.encode().unwrap(), authorization_bytes);
    let approval_bytes =
        fs::read(&shared.approval_path).expect("read generated issuer clearing approval");
    let approval = IssuerClearingApprovalV1::decode(&approval_bytes)
        .expect("decode generated issuer clearing approval");
    assert_eq!(approval.encode(), approval_bytes);
    let clearing_bytes: [u8; 32] = fs::read(&shared.clearing_key_path)
        .expect("read provider clearing signing key")
        .try_into()
        .expect("provider clearing signing key length");
    let transport = StrictHttpsProviderSettlementTransportV1::new_with_test_only_webpki_root_pem(
        authorization.claims.redeem_endpoint.clone(),
        Duration::from_secs(2),
        Duration::from_secs(5),
        &authorization.claims.redeem_leaf_spki_sha256_pins,
        &fs::read(test_root).expect("read private test WebPKI root"),
    )
    .expect("construct pinned test-only ledger transport");
    let client = ProviderLedgerBalanceClientV1::new(
        ProviderLedgerBalanceTrustV1 {
            authorization,
            issuer_approval: approval,
            operator_verifying_key: shared.operator_verifying_key,
            minimum_authorization_epoch: shared.authorization_epoch,
            current_issuer_settlement_key: shared.issuer_settlement_verifying_key,
            retained_issuer_settlement_keys,
        },
        SigningKey::from_bytes(&clearing_bytes),
        &transport,
    )
    .expect("construct ledger-only balance client from generated artifacts");
    client
        .balance(nonce, unix_now())
        .expect("fetch and verify issuer-signed ledger balance")
}

fn assert_server_log(stdout: &str, stderr: &str, port: u16, fixture: &ProviderFixture) {
    assert!(stdout.contains(&format!("Listening on ws://127.0.0.1:{port}")));
    assert!(stdout.contains("Service admission V1: enforced"));
    assert!(!stderr.contains("UNSAFE DEBUG QUERY LOGGING ENABLED"));
    assert_payment_material_absent(stdout, stderr, &[fixture]);
}

fn assert_issuer_log(stdout: &str, stderr: &str, fixture: &ProviderFixture) {
    assert!(stdout.contains("payment-issuer fake service listening"));
    assert!(stdout.contains("issuer_store_startup_check=ok"));
    assert_payment_material_absent(stdout, stderr, &[fixture]);
}

fn assert_payment_material_absent(stdout: &str, stderr: &str, fixtures: &[&ProviderFixture]) {
    let stdout_lower = stdout.to_ascii_lowercase();
    let stderr_lower = stderr.to_ascii_lowercase();
    for forbidden in [
        "payment_hash",
        "payment hash",
        "paymenthash",
        "preimage",
        "invoice",
        "secret_raw",
    ] {
        assert!(!stdout_lower.contains(forbidden));
        assert!(!stderr_lower.contains(forbidden));
    }
    for fixture in fixtures {
        let Some(shared) = &fixture.shared else {
            continue;
        };
        let proof = shared
            .proof
            .encode()
            .expect("encode BAT proof for log audit");
        for forbidden in [
            hex::encode(shared.proof.secret_raw),
            hex::encode(shared.proof.c),
            hex::encode(proof),
            format!("{:?}", shared.proof.secret_raw),
            format!("{:?}", shared.proof.c),
        ] {
            assert!(!stdout_lower.contains(forbidden.as_str()));
            assert!(!stderr_lower.contains(forbidden.as_str()));
        }
    }
}

fn install_tls_material(root: &Path) -> TlsMaterial {
    let material = TlsMaterial {
        root: root.join("shared-issuer-test-root.pem"),
        wrong_root: root.join("shared-issuer-wrong-root.pem"),
        certificate: root.join("shared-issuer-test-leaf.pem"),
        private_key: root.join("shared-issuer-test-leaf.key"),
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

fn serve_tls_edge(
    bind: SocketAddr,
    upstream: SocketAddr,
    certificate_pem: &[u8],
    private_key_pem: &[u8],
    counter_path: &Path,
    transcript_path: &Path,
    drop_success_once_path: Option<&Path>,
) -> io::Result<()> {
    if !bind.ip().is_loopback() || !upstream.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "test TLS edge must remain loopback-only",
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
        if serve_one_tls_edge_request(
            socket,
            upstream,
            Arc::clone(&config),
            counter_path,
            transcript_path,
            drop_success_once_path,
        )
        .is_err()
        {
            // Readiness probes and malformed TLS/HTTP are deliberately silent.
            // Never log peer addresses, credential bytes, timing, or responses.
        }
    }
}

fn serve_one_tls_edge_request(
    socket: TcpStream,
    upstream_address: SocketAddr,
    config: Arc<ServerConfig>,
    counter_path: &Path,
    transcript_path: &Path,
    drop_success_once_path: Option<&Path>,
) -> io::Result<()> {
    socket.set_read_timeout(Some(TLS_IO_TIMEOUT))?;
    socket.set_write_timeout(Some(TLS_IO_TIMEOUT))?;
    let connection = ServerConnection::new(config).map_err(io::Error::other)?;
    let mut tls = StreamOwned::new(connection, socket);
    let request = read_bounded_http_request(&mut tls)?;
    let is_redeem = request.starts_with(b"POST /v1/redeems HTTP/1.1\r\n");
    let is_balance = request.starts_with(b"POST /v1/settlement/balance HTTP/1.1\r\n");
    if !is_redeem && !is_balance {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS edge accepts only issuer redeem and signed balance routes",
        ));
    }
    let transcript = is_redeem
        .then(|| validate_canonical_redeem_request(&request))
        .transpose()?;

    let mut upstream = TcpStream::connect_timeout(&upstream_address, TLS_IO_TIMEOUT)?;
    upstream.set_read_timeout(Some(TLS_IO_TIMEOUT))?;
    upstream.set_write_timeout(Some(TLS_IO_TIMEOUT))?;
    upstream.write_all(&request)?;
    upstream.flush()?;
    upstream.shutdown(std::net::Shutdown::Write)?;
    append_forward_counter(counter_path)?;

    let mut response = Vec::new();
    upstream
        .take((MAX_PROXY_HTTP_BYTES + 1) as u64)
        .read_to_end(&mut response)?;
    if response.is_empty() || response.len() > MAX_PROXY_HTTP_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "issuer response is empty or exceeded the proxy bound",
        ));
    }
    if let Some(transcript) = transcript {
        let canonical_success =
            validate_canonical_redeem_success_response(&response, &transcript.request_digest)?;
        append_redeem_transcript_digests(transcript_path, transcript)?;
        if canonical_success && mark_drop_success_response_once(drop_success_once_path)? {
            // The complete issuer success response proves the redeem commit escaped
            // the application boundary. Drop the downstream TLS stream without
            // forwarding one response, modeling an outcome-unknown network loss.
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "test-only committed issuer response loss",
            ));
        }
    }
    tls.write_all(&response)?;
    tls.flush()?;
    tls.conn.send_close_notify();
    let _ = tls.flush();
    Ok(())
}

fn validate_canonical_redeem_request(wire: &[u8]) -> io::Result<RedeemTranscriptDigests> {
    let body =
        exact_content_length_http_body(wire, "POST /v1/redeems HTTP/1.1", REDEEM_CONTENT_TYPE)?;
    let envelope = ProviderRedeemEnvelopeV1::decode(body).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "issuer request body is not a redeem envelope",
        )
    })?;
    let canonical = Zeroizing::new(envelope.encode().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "issuer redeem envelope cannot be canonically encoded",
        )
    })?);
    if canonical.as_slice() != body {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "issuer redeem envelope is not canonical",
        ));
    }
    let request_digest = envelope.request.request_digest().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "issuer redeem request digest is invalid",
        )
    })?;
    Ok(RedeemTranscriptDigests {
        canonical_body: sha256(body),
        request_digest,
        idempotency_key_digest: sha256(&envelope.request.idempotency_key),
    })
}

fn validate_canonical_redeem_success_response(
    wire: &[u8],
    expected_request_digest: &[u8; 32],
) -> io::Result<bool> {
    let (head, _) = split_http_wire(wire)?;
    if head.split("\r\n").next() != Some("HTTP/1.1 200 OK") {
        return Ok(false);
    }
    let body = exact_content_length_http_body(wire, "HTTP/1.1 200 OK", REDEEM_RESULT_CONTENT_TYPE)?;
    let response = ProviderRedeemResponseV1::decode(body).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "issuer success body is not a redeem response",
        )
    })?;
    let canonical = response.encode().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "issuer redeem response cannot be canonically encoded",
        )
    })?;
    if canonical.as_slice() != body || &response.request_digest != expected_request_digest {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "issuer redeem response is non-canonical or bound to another request",
        ));
    }
    Ok(true)
}

fn exact_content_length_http_body<'a>(
    wire: &'a [u8],
    expected_start_line: &str,
    expected_content_type: &str,
) -> io::Result<&'a [u8]> {
    let (head, body) = split_http_wire(wire)?;
    let mut lines = head.split("\r\n");
    if lines.next() != Some(expected_start_line) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected HTTP start line",
        ));
    }
    let mut content_type = None;
    let mut content_length = None;
    for line in lines {
        if !line.is_ascii() || line.bytes().any(|byte| matches!(byte, b'\r' | b'\n')) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "non-ASCII or folded HTTP header",
            ));
        }
        let (name, raw_value) = line
            .split_once(':')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed HTTP header"))?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed HTTP header name",
            ));
        }
        let value = raw_value.trim_matches(|character| matches!(character, ' ' | '\t'));
        if name.eq_ignore_ascii_case("content-type") {
            if content_type.replace(value).is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate HTTP content type",
                ));
            }
        } else if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some()
                || value.is_empty()
                || !value.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid or duplicate HTTP content length",
                ));
            }
            content_length = Some(value.parse::<usize>().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "HTTP content length overflow")
            })?);
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            || (name.eq_ignore_ascii_case("content-encoding")
                && !value.eq_ignore_ascii_case("identity"))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "encoded HTTP body is forbidden",
            ));
        }
    }
    if content_type != Some(expected_content_type) || content_length != Some(body.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP content type or body length is not exact",
        ));
    }
    Ok(body)
}

fn split_http_wire(wire: &[u8]) -> io::Result<(&str, &[u8])> {
    let head_end = wire
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing HTTP header terminator")
        })?;
    let head = std::str::from_utf8(&wire[..head_end])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-ASCII HTTP headers"))?;
    if head.is_empty() || !head.is_ascii() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty HTTP header block",
        ));
    }
    Ok((head, &wire[head_end + 4..]))
}

fn read_bounded_http_request(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut request = Vec::new();
    let mut total_length = None;
    loop {
        if request.len() >= MAX_PROXY_HTTP_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "issuer request exceeded TLS-edge bound",
            ));
        }
        let mut chunk = [0u8; 2048];
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "issuer request ended early",
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
                    io::Error::new(io::ErrorKind::InvalidData, "non-ASCII issuer headers")
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
                    io::Error::new(io::ErrorKind::InvalidData, "issuer request length overflow")
                })?;
                if total > MAX_PROXY_HTTP_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "issuer request exceeded TLS-edge bound",
                    ));
                }
                total_length = Some(total);
            }
        }
        if let Some(total) = total_length.filter(|total| request.len() >= *total) {
            if request.len() != total {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "issuer request contained trailing bytes",
                ));
            }
            return Ok(request);
        }
    }
}

fn append_forward_counter(path: &Path) -> io::Result<()> {
    let mut file = fs::OpenOptions::new().append(true).open(path)?;
    file.write_all(b"1\n")?;
    file.sync_data()
}

fn append_redeem_transcript_digests(
    path: &Path,
    transcript: RedeemTranscriptDigests,
) -> io::Result<()> {
    let mut file = fs::OpenOptions::new().append(true).open(path)?;
    file.write_all(&transcript.encode())?;
    file.sync_data()
}

fn mark_drop_success_response_once(path: Option<&Path>) -> io::Result<bool> {
    let Some(path) = path else {
        return Ok(false);
    };
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(mut file) => {
            file.write_all(b"committed-response-dropped\n")?;
            file.sync_all()?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(error),
    }
}

fn forwarded_request_count(path: &Path) -> u64 {
    u64::try_from(
        fs::read(path)
            .expect("read TLS edge forward counter")
            .into_iter()
            .filter(|byte| *byte == b'\n')
            .count(),
    )
    .expect("forward counter fits u64")
}

fn assert_first_two_forwarded_requests_are_identical(path: &Path) {
    let digests = fs::read(path).expect("read TLS edge transcript digests");
    assert_eq!(
        digests.len(),
        2 * REDEEM_TRANSCRIPT_DIGEST_BYTES,
        "response-loss recovery must make exactly two completed issuer requests"
    );
    for (label, start, end) in [
        ("canonical redeem envelope", 0, 32),
        ("request digest", 32, 64),
        ("idempotency key digest", 64, 96),
    ] {
        assert_eq!(
            &digests[start..end],
            &digests[REDEEM_TRANSCRIPT_DIGEST_BYTES + start..REDEEM_TRANSCRIPT_DIGEST_BYTES + end],
            "issuer restart recovery changed the {label}"
        );
    }
}

fn test_leaf_spki_sha256() -> [u8; 32] {
    hex::decode(TEST_LEAF_SPKI_SHA256_HEX)
        .expect("test leaf pin hex")
        .try_into()
        .expect("test leaf pin length")
}

fn required_payment_issuer_binary() -> PathBuf {
    let path = PathBuf::from(
        env::var_os("BITCOINPIR_PAYMENT_ISSUER_BIN")
            .expect("BITCOINPIR_PAYMENT_ISSUER_BIN must name a debug payment-issuer binary built with test-only-fake-lightning"),
    );
    assert!(
        path.is_absolute(),
        "BITCOINPIR_PAYMENT_ISSUER_BIN must be absolute"
    );
    let metadata = fs::symlink_metadata(&path).unwrap_or_else(|error| {
        panic!("inspect payment-issuer binary {}: {error}", path.display())
    });
    assert!(!metadata.file_type().is_symlink());
    assert!(metadata.file_type().is_file());
    assert_ne!(
        metadata.mode() & 0o111,
        0,
        "payment-issuer is not executable"
    );
    path
}

fn required_bpir_admin_binary() -> PathBuf {
    let path = PathBuf::from(
        env::var_os("BITCOINPIR_BPIR_ADMIN_BIN")
            .expect("BITCOINPIR_BPIR_ADMIN_BIN must name a debug bpir-admin binary"),
    );
    assert!(
        path.is_absolute(),
        "BITCOINPIR_BPIR_ADMIN_BIN must be absolute"
    );
    let metadata = fs::symlink_metadata(&path)
        .unwrap_or_else(|error| panic!("inspect bpir-admin binary {}: {error}", path.display()));
    assert!(!metadata.file_type().is_symlink());
    assert!(metadata.file_type().is_file());
    assert_ne!(metadata.mode() & 0o111, 0, "bpir-admin is not executable");
    path
}

fn assert_command_success(label: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{label} failed ({})\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
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

fn write_public_file(path: &Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)
        .unwrap_or_else(|error| panic!("create public file {}: {error}", path.display()));
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
