//! Shared-issuer real-process admission coverage.
//!
//! The paid provider is a real `unified_server` subprocess. Its signed clearing
//! authorization selects a normal WebPKI HTTPS origin and an additional signed
//! leaf-SPKI pin. A separate TLS-edge subprocess forwards only `/v1/redeems` to
//! a real `payment-issuer` subprocess. The issuer's test-only fake Lightning
//! backend is used only to satisfy no-funds startup; this test never creates or
//! settles an invoice. The peer provider independently selects Free/Open.
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
use pir_issuer_store::{
    IssuerStore, SqliteIssuerRollbackFloorAuthorityV1, StoreOptions as IssuerStoreOptions,
};
use pir_lightning_backend::FakeLightningNodeV1;
use pir_payment_crypto::{cashu_hash_to_curve_v1, K256CashuMintKeyringV1};
use pir_runtime_core::protocol::{BatchQuery, Request, Response};
use pir_sdk_client::attest::{attest_with_eph_binding, SevStatus};
use pir_sdk_client::channel::{establish, SecureChannelTransport};
use pir_sdk_client::{
    dangerous_unpaired_authorize_service_operation_v1, fetch_verified_service_policy_v1,
    AcceptedServicePolicyV1, PirTransport, ServicePolicyCheckpointV1, WsConnection,
};
use pir_service_protocol::{
    derive_bat_key_id_v1, derive_issuer_id, derive_provider_id, AcquisitionMethod,
    AuthPaddingClassV1, AuthScheme, AuthorizationProofV1, BackendId, BitcoinPirCashuBatProofV1,
    Bolt11QuoteKeyDelegationV1, CredentialKeyBindingClaimsV1, CredentialKeyBindingV1,
    CredentialUnitV1, DatasetBindingV1, DeploymentStatus, EntitlementLimitsV1,
    FreeAuthorizationProofV1, FreeModeV1, IssuerClearingApprovalV1, LightningNetworkV1,
    OperationStartV1, PriceV1, PrivacyLeakageV1, ProviderClearingAuthorizationClaimsV1,
    ProviderClearingAuthorizationV1, ServiceOfferV1, ServicePolicyV1, ServiceScopePolicyV1,
    ServiceScopeV1, SettlementModesV1, SettlementRuleV1, SettlementUnitV1, VerificationMode,
    WorkloadId,
};
use pir_service_store::{
    ProviderStore, SqliteRollbackFloorAuthorityV1, StoreOptions as ProviderStoreOptions,
};
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

const SHARED_OFFER_ID: u32 = 61;
const FREE_OFFER_ID: u32 = 62;
const OPERATION_PROFILE: u16 = 41;
const ENTITLEMENT_PROFILE: u16 = 401;
const TINY_BINS_PER_TABLE: usize = 128;
const TEST_LEAF_SPKI_SHA256_HEX: &str =
    "e91550521f8e17b21d99f7e00b99c08be1b1f31fe57772ac8f904ea50c6a609b";
const TLS_EDGE_HELPER_MARKER: &str = "BITCOINPIR_TEST_ONLY_SHARED_ISSUER_TLS_EDGE_V1";
const PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const TLS_IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PROXY_HTTP_BYTES: usize = 128 * 1024;
static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProviderMethod {
    SharedIssuerBat,
    FreeOpen,
}

struct SharedProviderConfig {
    authorization_path: PathBuf,
    approval_path: PathBuf,
    operator_verifying_key: VerifyingKey,
    issuer_settlement_verifying_key: VerifyingKey,
    clearing_key_path: PathBuf,
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
    rollback_path: PathBuf,
    scope_id: [u8; 32],
    policy_digest: [u8; 32],
    shared: Option<SharedProviderConfig>,
}

impl ProviderFixture {
    fn proof(&self) -> AuthorizationProofV1 {
        match self.method {
            ProviderMethod::SharedIssuerBat => AuthorizationProofV1::BitcoinPirCashuBat(
                self.shared
                    .as_ref()
                    .expect("shared provider config")
                    .proof
                    .clone(),
            ),
            ProviderMethod::FreeOpen => {
                AuthorizationProofV1::Free(FreeAuthorizationProofV1::OpenBestEffort)
            }
        }
    }

    fn offer_id(&self) -> u32 {
        match self.method {
            ProviderMethod::SharedIssuerBat => SHARED_OFFER_ID,
            ProviderMethod::FreeOpen => FREE_OFFER_ID,
        }
    }
}

struct IssuerMaterial {
    binary: PathBuf,
    issuer_id: [u8; 32],
    issuer_root: SigningKey,
    settlement_signing_key: SigningKey,
    store_path: PathBuf,
    rollback_path: PathBuf,
    quote_delegation_path: PathBuf,
    quote_signing_key_path: PathBuf,
    credential_derivation_key_path: PathBuf,
    bat_key_path: PathBuf,
    fake_lightning_signing_key_path: PathBuf,
    fake_lightning_derivation_seed_path: PathBuf,
    issuer_settlement_signing_key_path: PathBuf,
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

#[test]
#[ignore = "spawned only by shared_issuer_real_process_tls_e2e"]
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
    serve_tls_edge(bind, upstream, &certificate, &private_key, &counter_path)
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
    let issuer = build_issuer_material(root.path(), unix_now());
    let now = unix_now();

    let paid = build_provider(
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
    write_private_file(&forward_counter, b"");
    let tls_edge = spawn_tls_edge(root.path(), edge_port, issuer_port, &tls, &forward_counter);

    assert_ne!(paid.provider_id, free.provider_id);
    assert_ne!(paid.store_path, free.store_path);
    let paid_port = distinct_unused_port(&[issuer_port, edge_port, offline_port]);
    let free_port = distinct_unused_port(&[issuer_port, edge_port, offline_port, paid_port]);
    let paid_server = spawn_provider(root.path(), &db_path, &paid, paid_port, 0, Some(&tls.root));
    let free_server = spawn_provider(root.path(), &db_path, &free, free_port, 0, None);

    exercise_grant_and_dpf(paid_port, &paid, manifest_root)
        .await
        .expect("shared-issuer BAT must redeem and authorize");
    exercise_grant_and_dpf(free_port, &free, manifest_root)
        .await
        .expect("peer provider must independently accept Free/Open");

    let (paid_stdout_first, paid_stderr_first) = paid_server.stop();
    let (free_stdout, free_stderr) = free_server.stop();
    assert_server_log(&paid_stdout_first, &paid_stderr_first, paid_port, &paid);
    assert_server_log(&free_stdout, &free_stderr, free_port, &free);

    // Reopen the paid provider against the same local store. The issuer may
    // return its exact durable redeem response, but the provider-local claim is
    // already committed and a second connection grant is forbidden.
    let paid_server = spawn_provider(root.path(), &db_path, &paid, paid_port, 1, Some(&tls.root));
    let replay = authorize_only(paid_port, &paid, manifest_root)
        .await
        .expect_err("replayed shared-issuer proof must not grant after restart");
    assert!(
        replay.contains("invalid-or-spent"),
        "unexpected replay: {replay}"
    );
    let (paid_stdout, paid_stderr) = paid_server.stop();
    assert_server_log(&paid_stdout, &paid_stderr, paid_port, &paid);
    assert_eq!(provider_local_claim_count(&paid), 1);

    let forwarded_after_replay = forwarded_request_count(&forward_counter);
    assert!(
        (1..=2).contains(&forwarded_after_replay),
        "initial redeem must be forwarded once; exact replay may be rejected locally or replayed at the issuer"
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
        assert_eq!(provider_local_claim_count(fixture), 0);
        assert_eq!(
            forwarded_request_count(&forward_counter),
            forwarded_after_replay,
            "TLS trust/offline failure must not reach the issuer HTTP application"
        );
    }

    let (edge_stdout, edge_stderr) = tls_edge.stop();
    let (issuer_stdout, issuer_stderr) = payment_issuer.stop();
    for forbidden in ["payment_hash", "preimage", "invoice", "secret_raw"] {
        assert!(!edge_stdout.contains(forbidden));
        assert!(!edge_stderr.contains(forbidden));
    }
    assert!(issuer_stdout.contains("payment-issuer fake service listening"));
    assert!(issuer_stdout.contains("issuer_store_startup_check=ok"));
    for forbidden in ["payment_hash", "preimage", "invoice", "secret_raw"] {
        assert!(!issuer_stdout.contains(forbidden));
        assert!(!issuer_stderr.contains(forbidden));
    }

    assert_issuer_ledger(&issuer, &paid, &[&wrong_ca, &wrong_pin, &offline]);
}

fn build_issuer_material(root: &Path, now: u64) -> IssuerMaterial {
    let binary = required_payment_issuer_binary();
    let issuer_root_dir = root.join("payment-issuer");
    let store_dir = issuer_root_dir.join("store-domain");
    let rollback_dir = issuer_root_dir.join("rollback-domain");
    fs::create_dir_all(&store_dir).unwrap();
    fs::create_dir_all(&rollback_dir).unwrap();
    chmod(&issuer_root_dir, 0o700);
    chmod(&store_dir, 0o700);
    chmod(&rollback_dir, 0o700);

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
        issuer_id,
        issuer_root,
        settlement_signing_key,
        store_path: store_dir.join("issuer.sqlite3"),
        rollback_path: rollback_dir.join("floor.sqlite3"),
        quote_delegation_path,
        quote_signing_key_path,
        credential_derivation_key_path,
        bat_key_path,
        fake_lightning_signing_key_path,
        fake_lightning_derivation_seed_path,
        issuer_settlement_signing_key_path,
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
    let rollback_dir = provider_root.join("rollback-domain");
    fs::create_dir_all(&store_dir).unwrap();
    fs::create_dir_all(&rollback_dir).unwrap();
    chmod(&provider_root, 0o700);
    chmod(&store_dir, 0o700);
    chmod(&rollback_dir, 0o700);

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

    let (offer, shared) = match method {
        ProviderMethod::SharedIssuerBat => {
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
            let idempotency_key = [0xa0u8.wrapping_add(index); 32];
            let account_id = [0xb0u8.wrapping_add(index); 32];
            let authorization = ProviderClearingAuthorizationV1::sign(
                ProviderClearingAuthorizationClaimsV1 {
                    authorization_id: [0xd0u8.wrapping_add(index); 16],
                    authorization_epoch: 1,
                    provider_id,
                    issuer_id: issuer.issuer_id,
                    redeem_endpoint: redeem_endpoint.to_owned(),
                    redeem_leaf_spki_sha256_pins: redeem_pins,
                    settlement_account_id: account_id,
                    clearing_verifying_key: clearing.verifying_key().to_bytes(),
                    not_before: issued_at,
                    not_after: expires_at,
                    rules: vec![SettlementRuleV1 {
                        credential_binding_digest: binding
                            .binding_digest()
                            .expect("shared BAT binding digest"),
                        unit: SettlementUnitV1::AuthCredit,
                        accepted_value: 10,
                        provider_credit: 9,
                        issuer_fee: 1,
                        denomination_profile: 1,
                        settlement_modes: SettlementModesV1::from_bits(
                            SettlementModesV1::LEDGER_CREDIT,
                        )
                        .expect("ledger-credit-only settlement"),
                        blind_output_minimum_validity_seconds: 0,
                        blind_output_keyset: None,
                    }],
                },
                &operator,
            )
            .expect("sign provider clearing authorization");
            let approval = IssuerClearingApprovalV1::sign(
                &authorization,
                issued_at,
                expires_at,
                &issuer.settlement_signing_key,
            )
            .expect("sign issuer clearing approval");
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
            let clearing_key_path = provider_root.join("clearing.key");
            let idempotency_key_path = provider_root.join("redeem-idempotency.key");
            write_public_file(
                &authorization_path,
                &authorization
                    .encode()
                    .expect("encode clearing authorization"),
            );
            write_public_file(&approval_path, &approval.encode());
            write_private_file(&clearing_key_path, &clearing.to_bytes());
            write_private_file(&idempotency_key_path, &idempotency_key);
            (
                offer,
                Some(SharedProviderConfig {
                    authorization_path,
                    approval_path,
                    operator_verifying_key: operator.verifying_key(),
                    issuer_settlement_verifying_key: issuer.settlement_signing_key.verifying_key(),
                    clearing_key_path,
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
                        .expect("known Free privacy flags"),
                },
                None,
            )
        }
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
    .expect("sign provider policy");
    let policy_digest = policy.policy_digest().expect("provider policy digest");
    let policy_path = provider_root.join("service-policy-v1.bin");
    write_public_file(
        &policy_path,
        &policy.encode().expect("encode provider policy"),
    );

    let store_path = store_dir.join("provider.sqlite3");
    let rollback_path = rollback_dir.join("floor.sqlite3");
    let rollback = SqliteRollbackFloorAuthorityV1::create(
        &rollback_path,
        ProviderStoreOptions::default().busy_timeout,
    )
    .expect("create provider rollback floor");
    let store = ProviderStore::create(
        &store_path,
        [0x20u8.wrapping_add(index); 16],
        provider_id,
        ProviderStoreOptions::default(),
        Arc::new(rollback),
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
        rollback_path,
        scope_id,
        policy_digest,
        shared,
    }
}

fn init_issuer_store(issuer: &IssuerMaterial) {
    let output = Command::new(&issuer.binary)
        .args([
            OsString::from("init-store"),
            OsString::from("--store"),
            issuer.store_path.as_os_str().to_owned(),
            OsString::from("--rollback-authority"),
            issuer.rollback_path.as_os_str().to_owned(),
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
    assert_private_regular_file(&issuer.rollback_path);
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
        OsString::from("--rollback-authority"),
        issuer.rollback_path.as_os_str().to_owned(),
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
            "1".to_owned(),
            "--test-only-service-https-root-pem".to_owned(),
            test_root.to_string_lossy().into_owned(),
        ]);
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

fn spawn_tls_edge(
    root: &Path,
    port: u16,
    issuer_port: u16,
    material: &TlsMaterial,
    counter_path: &Path,
) -> ChildProcess {
    let label = "shared-issuer-tls-edge".to_owned();
    let stdout_path = root.join("shared-issuer-tls-edge-stdout.log");
    let stderr_path = root.join("shared-issuer-tls-edge-stderr.log");
    let stdout = File::create(&stdout_path).expect("create TLS edge stdout log");
    let stderr = File::create(&stderr_path).expect("create TLS edge stderr log");
    let child = Command::new(env::current_exe().expect("current integration test executable"))
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
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
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

fn provider_local_claim_count(fixture: &ProviderFixture) -> u64 {
    let rollback = SqliteRollbackFloorAuthorityV1::open_existing(
        &fixture.rollback_path,
        ProviderStoreOptions::default().busy_timeout,
    )
    .expect("open provider rollback floor for audit");
    let store = ProviderStore::open_existing(
        &fixture.store_path,
        fixture.provider_id,
        ProviderStoreOptions::default(),
        Arc::new(rollback),
    )
    .expect("open provider store for audit");
    store
        .operational_inventory()
        .expect("provider operational inventory")
        .spent_capability_rows
}

fn assert_issuer_ledger(
    issuer: &IssuerMaterial,
    paid: &ProviderFixture,
    failed: &[&ProviderFixture],
) {
    let rollback = SqliteIssuerRollbackFloorAuthorityV1::open_existing(
        &issuer.rollback_path,
        IssuerStoreOptions::default().busy_timeout,
    )
    .expect("open issuer rollback floor for audit");
    let store = IssuerStore::open_existing(
        &issuer.store_path,
        issuer.issuer_id,
        LightningNetworkV1::Regtest,
        IssuerStoreOptions::default(),
        Arc::new(rollback),
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

fn assert_server_log(stdout: &str, stderr: &str, port: u16, fixture: &ProviderFixture) {
    assert!(stdout.contains(&format!("Listening on ws://127.0.0.1:{port}")));
    assert!(stdout.contains("Service admission V1: enforced"));
    assert!(!stderr.contains("UNSAFE DEBUG QUERY LOGGING ENABLED"));
    for forbidden in ["payment_hash", "preimage", "invoice", "secret_raw"] {
        assert!(!stdout.contains(forbidden));
        assert!(!stderr.contains(forbidden));
    }
    if let Some(shared) = &fixture.shared {
        assert!(!stdout.contains(&hex::encode(shared.proof.secret_raw)));
        assert!(!stderr.contains(&hex::encode(shared.proof.secret_raw)));
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
        if serve_one_tls_edge_request(socket, upstream, Arc::clone(&config), counter_path).is_err()
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
) -> io::Result<()> {
    socket.set_read_timeout(Some(TLS_IO_TIMEOUT))?;
    socket.set_write_timeout(Some(TLS_IO_TIMEOUT))?;
    let connection = ServerConnection::new(config).map_err(io::Error::other)?;
    let mut tls = StreamOwned::new(connection, socket);
    let request = read_bounded_http_request(&mut tls)?;
    if !request.starts_with(b"POST /v1/redeems HTTP/1.1\r\n") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS edge accepts only the issuer redeem route",
        ));
    }

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
