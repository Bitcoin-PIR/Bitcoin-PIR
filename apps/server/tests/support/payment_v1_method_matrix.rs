//! Shared real-adapter fixtures for the Payment V1 provider-process matrix.
//!
//! This module deliberately contains no provider or backend test double. It
//! only prepares signed offers/proofs and the provider-local key material that
//! the production `unified_server` adapters consume. Standard Cashu crosses a
//! real loopback TLS/NUT-03 boundary; Free-IP, BAT and experimental ARC use the
//! same production committers and durable ProviderStore as deployment builds.

#![allow(dead_code)]

use arc::group::serialize_scalar;
use arc::{
    create_credential_request, create_credential_response, finalize_credential,
    make_presentation_state, present, setup_server,
};
use ed25519_dalek::SigningKey;
use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use pir_arc_adapter::{ArcSecretKeyV1, ARC_SECRET_KEY_LEN_V1};
use pir_payment_crypto::{
    blind_cashu_message_v1, verify_and_unblind_cashu_promise_v1, K256CashuMintKeyringV1,
};
use pir_service_protocol::{
    derive_bat_key_id_v1, derive_cashu_keyset_id_v2, AcquisitionMethod, ArcPresentationV1,
    AuthScheme, BitcoinPirCashuBatProofV1, CashuDenominationKeyV1, CashuKeysetBindingV1,
    CashuRequiredNutsV1, CredentialKeyBindingClaimsV1, CredentialKeyBindingExpectationV1,
    CredentialKeyBindingV1, CredentialUnitV1, DeploymentStatus, FreeModeV1, PriceV1,
    PrivacyLeakageV1, ServiceOfferV1, StandardCashuMintManifestV1, StandardCashuProofV1,
    StandardCashuSpendV1, VerificationMode,
};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use zeroize::Zeroizing;

pub const FREE_IP_OFFER_ID: u32 = 0x4d00_0001;
pub const CASHU_OFFER_ID: u32 = 0x4d00_0002;
pub const BAT_OFFER_ID: u32 = 0x4d00_0003;
pub const ARC_OFFER_ID: u32 = 0x4d00_0004;

const CASHU_PRICE_SAT: u64 = 1;
const CASHU_UNIT: &str = "sat";
const ARC_PRESENTATION_LIMIT_MAX: u32 = 8;
const TEST_LEAF_SPKI_SHA256_HEX: &str =
    "e91550521f8e17b21d99f7e00b99c08be1b1f31fe57772ac8f904ea50c6a609b";
const MAX_HTTP_REQUEST_BYTES: usize = 64 * 1024;
const TLS_IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatrixMethod {
    FreeIp,
    StandardCashu,
    CashuBat,
    ArcExperimental,
}

impl MatrixMethod {
    pub const ALL: [Self; 4] = [
        Self::FreeIp,
        Self::StandardCashu,
        Self::CashuBat,
        Self::ArcExperimental,
    ];

    pub fn offer_id(self) -> u32 {
        match self {
            Self::FreeIp => FREE_IP_OFFER_ID,
            Self::StandardCashu => CASHU_OFFER_ID,
            Self::CashuBat => BAT_OFFER_ID,
            Self::ArcExperimental => ARC_OFFER_ID,
        }
    }

    pub fn scheme(self) -> AuthScheme {
        match self {
            Self::FreeIp => AuthScheme::FreeV1,
            Self::StandardCashu => AuthScheme::CashuEcashV1,
            Self::CashuBat => AuthScheme::BitcoinPirCashuBatV1,
            Self::ArcExperimental => AuthScheme::ArcV1Experimental,
        }
    }

    pub fn replay_rejection(self) -> &'static str {
        match self {
            Self::FreeIp => "server-busy",
            Self::StandardCashu | Self::CashuBat | Self::ArcExperimental => "invalid-or-spent",
        }
    }
}

#[derive(Debug)]
pub struct MatrixMethodFixture {
    method: MatrixMethod,
    key_id: Vec<u8>,
    proofs: Vec<Vec<u8>>,
}

impl MatrixMethodFixture {
    pub fn method(&self) -> MatrixMethod {
        self.method
    }

    pub fn offer_id(&self) -> u32 {
        self.method.offer_id()
    }

    pub fn scheme(&self) -> AuthScheme {
        self.method.scheme()
    }

    pub fn key_id(&self) -> &[u8] {
        &self.key_id
    }

    pub fn proof(&self, index: usize) -> &[u8] {
        self.proofs
            .get(index)
            .unwrap_or_else(|| panic!("missing {:?} proof {index}", self.method))
    }

    pub fn proof_count(&self) -> usize {
        self.proofs.len()
    }
}

#[derive(Debug)]
pub struct MethodMatrixFixture {
    offers: Vec<ServiceOfferV1>,
    methods: Vec<MatrixMethodFixture>,
    free_ip_key_path: PathBuf,
    bat_key_path: PathBuf,
    arc_key_path: PathBuf,
    arc_key_id: Vec<u8>,
    cashu_recovery_key_path: PathBuf,
    cashu_custody_key_path: PathBuf,
    cashu_mint_id: [u8; 32],
    cashu_test_root_path: PathBuf,
}

impl MethodMatrixFixture {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        provider_root: &Path,
        provider_id: [u8; 32],
        scope_id: [u8; 32],
        entitlement_profile: u16,
        issued_at: u64,
        expires_at: u64,
        capability_count: usize,
        seed: u8,
        mint: &TestCashuMint,
    ) -> Self {
        assert!((1..=ARC_PRESENTATION_LIMIT_MAX as usize).contains(&capability_count));
        let binding_not_after = expires_at + 1_800;
        let issuer_root_key = SigningKey::from_bytes(&[0xa0u8.wrapping_add(seed); 32]);

        let free_ip_key_path = provider_root.join("matrix-free-ip-hmac.key");
        write_private_file(&free_ip_key_path, &[0xa1u8.wrapping_add(seed); 32]);

        let bat_secret = [0xa2u8.wrapping_add(seed); 32];
        let bat_key_path = provider_root.join("matrix-bat.key");
        write_private_file(&bat_key_path, &bat_secret);
        let bat_keyring = K256CashuMintKeyringV1::from_secret_keys([bat_secret]).unwrap();
        let bat_public_key = bat_keyring.denomination_public_keys()[0];
        let bat_key_id = derive_bat_key_id_v1(
            &provider_id,
            &scope_id,
            BAT_OFFER_ID,
            entitlement_profile,
            1,
            &bat_public_key,
        )
        .to_vec();
        let bat_binding = credential_binding(
            provider_id,
            scope_id,
            BAT_OFFER_ID,
            AuthScheme::BitcoinPirCashuBatV1,
            entitlement_profile,
            1,
            bat_key_id.clone(),
            bat_public_key.to_vec(),
            issued_at,
            binding_not_after,
            &issuer_root_key,
        );
        let bat_proofs = (0..capability_count)
            .map(|index| {
                let index = u8::try_from(index).unwrap();
                let secret_raw = [0xb0u8.wrapping_add(seed).wrapping_add(index); 32];
                let blinding = [0x11u8.wrapping_add(seed).wrapping_add(index); 32];
                let blinded = blind_cashu_message_v1(&secret_raw, &blinding).unwrap();
                let promise = bat_keyring
                    .blind_sign_with_dleq_v1(
                        &bat_public_key,
                        &blinded,
                        &[0x21u8.wrapping_add(seed).wrapping_add(index); 32],
                    )
                    .unwrap();
                let unblinded = verify_and_unblind_cashu_promise_v1(
                    &secret_raw,
                    &blinding,
                    &bat_public_key,
                    &blinded,
                    promise.blinded_signature(),
                    promise.dleq_e(),
                    promise.dleq_s(),
                )
                .unwrap();
                BitcoinPirCashuBatProofV1 {
                    secret_raw,
                    c: *unblinded.unblinded_signature(),
                }
                .encode()
                .unwrap()
                .to_vec()
            })
            .collect::<Vec<_>>();

        let mut arc_rng = ChaCha20Rng::from_seed([0xc0u8.wrapping_add(seed); 32]);
        let (arc_secret, arc_public) = setup_server(&mut arc_rng);
        let arc_key_id = vec![0xc1u8.wrapping_add(seed); 16];
        let mut arc_secret_bytes = [0u8; ARC_SECRET_KEY_LEN_V1];
        arc_secret_bytes[0..32].copy_from_slice(&serialize_scalar(&arc_secret.x0));
        arc_secret_bytes[32..64].copy_from_slice(&serialize_scalar(&arc_secret.x1));
        arc_secret_bytes[64..96].copy_from_slice(&serialize_scalar(&arc_secret.x2));
        arc_secret_bytes[96..128].copy_from_slice(&serialize_scalar(&arc_secret.x0_blinding));
        let arc_key_path = provider_root.join("matrix-arc.key");
        write_private_file(&arc_key_path, &arc_secret_bytes);
        let parsed_arc_secret = ArcSecretKeyV1::from_zeroizing_bytes(
            arc_key_id.clone(),
            Zeroizing::new(arc_secret_bytes),
        )
        .unwrap();
        assert_eq!(parsed_arc_secret.public_key_bytes(), &arc_public.to_bytes());
        let arc_presentation_limit = u32::try_from(capability_count).unwrap().max(2);
        let arc_binding = credential_binding(
            provider_id,
            scope_id,
            ARC_OFFER_ID,
            AuthScheme::ArcV1Experimental,
            entitlement_profile,
            arc_presentation_limit,
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
            entitlement_profile,
            presentation_limit: arc_presentation_limit,
            credential_key_id: &arc_key_id,
        };
        arc_binding.verify_for(&arc_expectation, issued_at).unwrap();
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
        let mut presentation_state = make_presentation_state(
            credential,
            &presentation_context,
            u64::from(arc_presentation_limit),
        );
        let mut arc_proofs = Vec::with_capacity(capability_count);
        for _ in 0..capability_count {
            let (successor, _nonce, presentation) =
                present(&presentation_state, &mut arc_rng).unwrap();
            presentation_state = successor;
            arc_proofs.push(
                ArcPresentationV1::from_canonical_bytes(presentation.to_bytes())
                    .unwrap()
                    .presentation_bytes()
                    .to_vec(),
            );
        }

        let keyset = deterministic_cashu_keyset(expires_at + 86_400);
        let cashu_manifest = StandardCashuMintManifestV1 {
            manifest_epoch: 1,
            mint_endpoint: mint.endpoint().to_owned(),
            leaf_spki_sha256_pins: vec![mint.leaf_spki_sha256()],
            unit: CASHU_UNIT.to_owned(),
            required_nuts: CashuRequiredNutsV1::required_v1(),
            accepted_input_keysets: vec![keyset.clone()],
            active_output_keyset: keyset.clone(),
        };
        let cashu_mint_id = cashu_manifest.mint_id();
        let cashu_key_id = cashu_manifest.manifest_digest().unwrap().to_vec();
        let cashu_proofs = (0..capability_count)
            .map(|index| {
                StandardCashuSpendV1::new_canonical(vec![StandardCashuProofV1 {
                    keyset_id: keyset.keyset_id.clone(),
                    amount: CASHU_PRICE_SAT,
                    secret: format!("matrix-cashu-{seed}-{index}"),
                    c: compressed_point(&(ProjectivePoint::GENERATOR * Scalar::from(51u64))),
                }])
                .unwrap()
                .encode()
                .unwrap()
            })
            .collect::<Vec<_>>();
        let cashu_recovery_key_path = provider_root.join("matrix-cashu-recovery.key");
        let cashu_custody_key_path = provider_root.join("matrix-cashu-custody.key");
        write_private_file(&cashu_recovery_key_path, &[0xd0u8.wrapping_add(seed); 32]);
        write_private_file(&cashu_custody_key_path, &[0xd1u8.wrapping_add(seed); 32]);

        let offers = vec![
            free_ip_offer(capability_count),
            standard_cashu_offer(cashu_manifest),
            paid_local_offer(
                BAT_OFFER_ID,
                AuthScheme::BitcoinPirCashuBatV1,
                DeploymentStatus::Stable,
                bat_key_id.clone(),
                bat_binding,
                1,
            ),
            paid_local_offer(
                ARC_OFFER_ID,
                AuthScheme::ArcV1Experimental,
                DeploymentStatus::Experimental,
                arc_key_id.clone(),
                arc_binding,
                arc_presentation_limit,
            ),
        ];
        let methods = vec![
            MatrixMethodFixture {
                method: MatrixMethod::FreeIp,
                key_id: Vec::new(),
                proofs: vec![Vec::new(); capability_count],
            },
            MatrixMethodFixture {
                method: MatrixMethod::StandardCashu,
                key_id: cashu_key_id,
                proofs: cashu_proofs,
            },
            MatrixMethodFixture {
                method: MatrixMethod::CashuBat,
                key_id: bat_key_id,
                proofs: bat_proofs,
            },
            MatrixMethodFixture {
                method: MatrixMethod::ArcExperimental,
                key_id: arc_key_id.clone(),
                proofs: arc_proofs,
            },
        ];

        Self {
            offers,
            methods,
            free_ip_key_path,
            bat_key_path,
            arc_key_path,
            arc_key_id,
            cashu_recovery_key_path,
            cashu_custody_key_path,
            cashu_mint_id,
            cashu_test_root_path: mint.root_path().to_owned(),
        }
    }

    pub fn offers(&self) -> &[ServiceOfferV1] {
        &self.offers
    }

    pub fn method(&self, method: MatrixMethod) -> &MatrixMethodFixture {
        self.methods
            .iter()
            .find(|fixture| fixture.method == method)
            .unwrap_or_else(|| panic!("missing {method:?} matrix fixture"))
    }

    pub fn methods(&self) -> impl Iterator<Item = &MatrixMethodFixture> {
        self.methods.iter()
    }

    pub fn extend_server_args(&self, args: &mut Vec<String>) {
        args.extend([
            "--allow-experimental-arc".to_owned(),
            "--service-free-ip-key".to_owned(),
            self.free_ip_key_path.display().to_string(),
            "--service-trust-direct-peer-ip".to_owned(),
            "--service-bat-key".to_owned(),
            self.bat_key_path.display().to_string(),
            "--service-arc-key".to_owned(),
            format!(
                "{}={}",
                hex::encode(&self.arc_key_id),
                self.arc_key_path.display()
            ),
            "--service-cashu-recovery-key".to_owned(),
            format!("1={}", self.cashu_recovery_key_path.display()),
            "--service-cashu-recovery-active-epoch".to_owned(),
            "1".to_owned(),
            "--service-cashu-custody-key".to_owned(),
            format!("1={}", self.cashu_custody_key_path.display()),
            "--service-cashu-custody-active-epoch".to_owned(),
            "1".to_owned(),
            "--service-cashu-exposure-limit".to_owned(),
            format!("{}:{CASHU_UNIT}:32:32", hex::encode(self.cashu_mint_id)),
            "--test-only-service-https-root-pem".to_owned(),
            self.cashu_test_root_path.display().to_string(),
        ]);
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

fn free_ip_offer(capability_count: usize) -> ServiceOfferV1 {
    ServiceOfferV1 {
        offer_id: FREE_IP_OFFER_ID,
        acquisition: AcquisitionMethod::FreeV1,
        free_mode: FreeModeV1::IpRateLimited,
        free_quota: u32::try_from(capability_count).unwrap(),
        free_window_seconds: 3_600,
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

fn standard_cashu_offer(manifest: StandardCashuMintManifestV1) -> ServiceOfferV1 {
    let mint_id = manifest.mint_id();
    ServiceOfferV1 {
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
        endpoint: manifest.mint_endpoint.clone(),
        cashu_mint_manifest: Some(manifest),
        invoice_expiry_seconds: 0,
        claim_window_seconds: 0,
        minimum_credential_validity_seconds: 600,
        retired_policy_grace_seconds: 600,
        credential_count: 1,
        credential_presentation_limit: 1,
        privacy_leakage: PrivacyLeakageV1::from_bits(
            PrivacyLeakageV1::ISSUER_REDEMPTION_TIMING | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER,
        )
        .unwrap(),
    }
}

fn paid_local_offer(
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
        endpoint: format!("https://matrix-issuer-{offer_id}.fixture.invalid"),
        invoice_expiry_seconds: 600,
        claim_window_seconds: 600,
        minimum_credential_validity_seconds: 600,
        retired_policy_grace_seconds: 1_800,
        credential_count: 1,
        credential_presentation_limit: presentation_limit,
        privacy_leakage: PrivacyLeakageV1::from_bits(PrivacyLeakageV1::KNOWN_MASK).unwrap(),
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

fn mint_scalar(amount: u64) -> Scalar {
    Scalar::from(20 + amount)
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

pub struct TestCashuMint {
    endpoint: String,
    root_path: PathBuf,
    attempts: Arc<AtomicU64>,
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl TestCashuMint {
    pub fn spawn(root: &Path) -> Self {
        let root_path = root.join("matrix-cashu-test-root.pem");
        let certificate_path = root.join("matrix-cashu-test-leaf.pem");
        let private_key_path = root.join("matrix-cashu-test-leaf.key");
        write_private_file(
            &root_path,
            include_bytes!("../testdata/remote-authority-process-root.pem"),
        );
        write_private_file(
            &certificate_path,
            include_bytes!("../testdata/remote-authority-process-leaf.pem"),
        );
        write_private_file(
            &private_key_path,
            include_bytes!("../testdata/remote-authority-process-leaf.key"),
        );
        let certificate_pem = fs::read(&certificate_path).unwrap();
        let private_key_pem = fs::read(&private_key_path).unwrap();
        let certificate = CertificateDer::from_pem_slice(&certificate_pem).unwrap();
        let private_key = PrivateKeyDer::from_pem_slice(&private_key_pem).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], private_key)
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let attempts = Arc::new(AtomicU64::new(0));
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_attempts = Arc::clone(&attempts);
        let thread_shutdown = Arc::clone(&shutdown);
        let seen_inputs = Arc::new(Mutex::new(HashSet::new()));
        let thread = thread::spawn(move || {
            let config = Arc::new(config);
            while !thread_shutdown.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((socket, _)) => {
                        let _ = serve_one_mint_request(
                            socket,
                            Arc::clone(&config),
                            &thread_attempts,
                            &seen_inputs,
                        );
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            endpoint: format!("https://localhost:{port}"),
            root_path,
            attempts,
            shutdown,
            thread: Some(thread),
        }
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn root_path(&self) -> &Path {
        &self.root_path
    }

    pub fn leaf_spki_sha256(&self) -> [u8; 32] {
        hex::decode(TEST_LEAF_SPKI_SHA256_HEX)
            .unwrap()
            .try_into()
            .unwrap()
    }

    pub fn attempt_count(&self) -> u64 {
        self.attempts.load(Ordering::Acquire)
    }
}

impl Drop for TestCashuMint {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(port) = self.endpoint.rsplit(':').next() {
            let _ = TcpStream::connect(format!("127.0.0.1:{port}"));
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
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

fn serve_one_mint_request(
    socket: TcpStream,
    config: Arc<ServerConfig>,
    attempts: &AtomicU64,
    seen_inputs: &Mutex<HashSet<String>>,
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
    attempts.fetch_add(1, Ordering::AcqRel);
    let secret = parsed.inputs[0].secret.clone();
    if !seen_inputs.lock().unwrap().insert(secret) {
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

fn validate_mint_swap_request(request: &MintSwapRequest) -> io::Result<()> {
    if request.inputs.len() != 1 || request.outputs.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture expects one Cashu input and output",
        ));
    }
    let input = &request.inputs[0];
    if input.amount != CASHU_PRICE_SAT
        || !input.secret.starts_with("matrix-cashu-")
        || input.id.len() != 66
        || !is_lower_hex(&input.id)
        || input.c.len() != 66
        || !is_lower_hex(&input.c)
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
    stream: &mut StreamOwned<ServerConnection, TcpStream>,
    status: u16,
    body: &[u8],
) -> io::Result<()> {
    let reason = if status == 200 { "OK" } else { "Bad Request" };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()?;
    stream.conn.send_close_notify();
    let _ = stream.flush();
    Ok(())
}

fn read_bounded_http_request(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut request = Vec::new();
    let mut buffer = [0u8; 4 * 1024];
    let mut expected_len = None;
    loop {
        if request.len() >= MAX_HTTP_REQUEST_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Cashu request exceeded bound",
            ));
        }
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Cashu request ended early",
            ));
        }
        request.extend_from_slice(&buffer[..read]);
        if expected_len.is_none() {
            if let Some(header_start) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                let header_end = header_start + 4;
                let header = std::str::from_utf8(&request[..header_end]).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "non-ASCII Cashu headers")
                })?;
                let content_length = header
                    .split("\r\n")
                    .find_map(|line| {
                        line.strip_prefix("Content-Length:")
                            .or_else(|| line.strip_prefix("content-length:"))
                    })
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "missing Content-Length")
                    })?
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "invalid Content-Length")
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
                expected_len = Some(total);
            }
        }
        if let Some(expected_len) = expected_len {
            if request.len() == expected_len {
                return Ok(request);
            }
            if request.len() > expected_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Cashu request contained trailing bytes",
                ));
            }
        }
    }
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn write_private_file(path: &Path, bytes: &[u8]) {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
