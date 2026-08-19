//! Deterministic, test-only Payment V1 fixture.
//!
//! The fixture contains no invoice and cannot move funds. Every secret is
//! deterministically derived and therefore public knowledge. It exists only
//! to make two-provider, five-method, five-workload integration tests
//! reproducible without a network listener or Lightning node.

use clap::Args;
use ed25519_dalek::SigningKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::schnorr::SigningKey as SchnorrSigningKey;
use k256::SecretKey as Secp256k1SecretKey;
use pir_arc_adapter::{ArcSecretKeyV1, ARC_SECRET_KEY_LEN_V1};
use pir_core::cuckoo::{write_header_with_anchor, HeaderAnchor};
use pir_core::merkle::{compute_bin_leaf_hash, compute_parent_n, sha256, Hash256, ZERO_HASH};
use pir_core::params::{CHUNK_PARAMS, INDEX_PARAMS};
use pir_core::seeds::{ChainAnchor as CoreChainAnchor, SnapshotSeeds};
use pir_db_attest::{
    display_hash_hex, BuildEvidence, BuildKind, BuildParamsV1, ChainAnchor as AttestedChainAnchor,
    EvidenceMode, NamedRoot, ProofBundle, RootBundlePayload, EVIDENCE_VERSION_V1,
    SEV_SNP_REPORT_DATA_LEN, SEV_SNP_REPORT_DATA_OFFSET,
};
use pir_service_protocol::{
    derive_bat_key_id_v1, derive_cashu_keyset_id_v2, derive_issuer_id, derive_provider_id,
    paid_receipt_key_id, AcquisitionMethod, AuthPaddingClassV1, AuthScheme, BackendId,
    Bolt11QuoteKeyDelegationV1, CashuDenominationKeyV1, CashuKeysetBindingV1, CashuRequiredNutsV1,
    CredentialKeyBindingClaimsV1, CredentialKeyBindingExpectationV1, CredentialKeyBindingV1,
    CredentialUnitV1, DatasetBindingV1, DeploymentStatus, EntitlementLimitsV1, FreeModeV1,
    LightningNetworkV1, PolicyRollbackGuardV1, PriceV1, PrivacyLeakageV1, ServiceOfferV1,
    ServicePolicyEpochFloorsV1, ServicePolicyV1, ServiceScopePolicyV1, ServiceScopeV1,
    StandardCashuMintExpectationV1, StandardCashuMintManifestV1, VerificationMode, WorkloadId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

const FIXTURE_ISSUED_AT: u64 = 1_700_000_000;
const FIXTURE_NOW: u64 = 1_800_000_000;
const FIXTURE_EXPIRES_AT: u64 = 2_000_000_000;
const INVOICE_EXPIRY_SECONDS: u32 = 600;
const CLAIM_WINDOW_SECONDS: u32 = 86_400;
const CREDENTIAL_VALIDITY_SECONDS: u32 = 604_800;
const RETIRED_POLICY_GRACE_SECONDS: u32 = 700_000;
const BINDING_NOT_AFTER: u64 = FIXTURE_EXPIRES_AT + RETIRED_POLICY_GRACE_SECONDS as u64;
const CASHU_FINAL_EXPIRY: u64 = FIXTURE_EXPIRES_AT + 1_000_000;
const ARC_PRESENTATION_LIMIT: u32 = 4;
const BROWSER_HARNESS_TINY_BINS_PER_TABLE: usize = 128;
const BROWSER_HARNESS_DB_ID: u8 = 0;
const BROWSER_HARNESS_DB_HEIGHT: u32 = 101;
const BROWSER_HARNESS_ONION_ENTRY_SIZE: u32 = 3_328;
const BROWSER_HARNESS_BUCKET_MERKLE_ARITY: usize = 8;
const BROWSER_HARNESS_BUILDER_GIT_COMMIT: &str =
    "bitcoinpir-payment-two-provider-synthetic-builder-v1";
const MAINNET_NETWORK_MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];

#[derive(Args, Debug)]
pub struct PaymentFixtureArgs {
    /// Output directory. Existing known files are overwritten only with --force.
    #[arg(long)]
    pub out: PathBuf,
    /// Required acknowledgement that all generated keys are public test vectors.
    #[arg(long)]
    pub acknowledge_deterministic_test_keys: bool,
    /// Overwrite only the fixture's known files; unrelated files are not removed.
    #[arg(long)]
    pub force: bool,
    /// Also emit a manifest-bound, DPF-only browser -> issuer -> two-provider
    /// loopback harness. This remains deterministic, test-only and unable to
    /// move funds. It includes a synthetic REPORT_DATA-bound database-proof
    /// fixture, but never represents a production SEV signature or attestation.
    #[arg(long)]
    pub include_browser_two_provider_harness: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct FixtureInventoryV1 {
    schema: String,
    schema_version: u8,
    test_only: bool,
    deterministic: bool,
    funds_capable: bool,
    network: String,
    warning: String,
    providers: Vec<FixtureProviderInventoryV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    browser_two_provider_harness: Option<BrowserTwoProviderHarnessInventoryV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct BrowserTwoProviderHarnessInventoryV1 {
    boundary: String,
    database_path: String,
    database_config_path: String,
    manifest_root: String,
    database_proof: BrowserDatabaseProofHarnessInventoryV1,
    public_files: Vec<String>,
    providers: Vec<BrowserProviderHarnessInventoryV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct BrowserDatabaseProofHarnessInventoryV1 {
    boundary: String,
    proof_path: String,
    db_id: u8,
    build_kind: String,
    from_height: u32,
    from_block_hash: String,
    height: u32,
    block_hash: String,
    anchor_hex: String,
    index_master_seed_hex: String,
    chunk_master_seed_hex: String,
    tag_seed_hex: String,
    muhash: String,
    bucket_super_root: String,
    onion_super_root: String,
    onion_entry_size: u32,
    params_hash: String,
    network_magic: String,
    builder_binary_sha256: String,
    builder_git_commit: String,
    proof_version: u8,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct BrowserProviderHarnessInventoryV1 {
    name: String,
    provider_id: String,
    policy_signing_pubkey: String,
    expected_payee_pubkey: String,
    issuer_id: String,
    policy_path: String,
    quote_delegation_path: String,
    scope_id: String,
    entitlement_profile: u16,
    offers: Vec<BrowserProviderOfferHarnessInventoryV1>,
    free_ip_key_path: Option<String>,
    bat_key_path: Option<String>,
    arc_key_path: Option<String>,
    arc_key_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct BrowserProviderOfferHarnessInventoryV1 {
    variant: String,
    offer_id: u32,
    method: String,
    free_mode: String,
    deployment_status: String,
}

struct BrowserBucketMerkleArtifactsV1 {
    tree_tops: Vec<u8>,
    roots: Vec<u8>,
    super_root: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct FixtureProviderInventoryV1 {
    name: String,
    stable_server_id: String,
    provider_id: String,
    operator_pubkey: String,
    policy_signing_pubkey: String,
    issuer_id: String,
    quote_key_id: String,
    quote_delegation_digest: String,
    expected_payee_pubkey: String,
    cashu_mint_id: String,
    cashu_manifest_digest: String,
    policy_path: String,
    quote_delegation_path: String,
    cashu_manifest_path: String,
    secret_files: Vec<String>,
    public_files: Vec<String>,
    scopes: Vec<FixtureScopeInventoryV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct FixtureScopeInventoryV1 {
    workload: String,
    scope_id: String,
    offers: Vec<FixtureOfferInventoryV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct FixtureOfferInventoryV1 {
    method: String,
    offer_id: u32,
    deployment_status: String,
    credential_binding_path: Option<String>,
    credential_key_id: Option<String>,
}

#[derive(Clone)]
struct WorkloadFixture {
    name: &'static str,
    backend: BackendId,
    workload: WorkloadId,
    protocol_version: u16,
    operation_profile: u16,
    entitlement_profile: u16,
    bolt11_unit_price_msat: u64,
    cashu_price_sat: u64,
    limits: EntitlementLimitsV1,
}

const WORKLOADS: [WorkloadFixture; 5] = [
    WorkloadFixture {
        name: "dpf-evaluate-job-v1",
        backend: BackendId::DpfPirV1,
        workload: WorkloadId::DpfEvaluateJobV1,
        protocol_version: 1,
        operation_profile: 11,
        entitlement_profile: 101,
        bolt11_unit_price_msat: 1_000,
        cashu_price_sat: 1,
        limits: EntitlementLimitsV1 {
            max_logical_inputs: 1,
            max_frames: 64,
            max_request_bytes: 2 * 1024 * 1024,
            max_response_bytes: 2 * 1024 * 1024,
            max_wall_time_ms: 20_000,
            max_concurrent_sockets: 1,
            max_hint_groups: 0,
            max_work_units: 10_000,
        },
    },
    WorkloadFixture {
        name: "harmony-hint-bundle-v1",
        backend: BackendId::HarmonyPirV2,
        workload: WorkloadId::HarmonyHintBundleV1,
        protocol_version: 2,
        operation_profile: 12,
        entitlement_profile: 102,
        bolt11_unit_price_msat: 5_000,
        cashu_price_sat: 5,
        // Integration-fixture capacity, not a commercial price profile. A
        // cold V2Full cache fill is one 155-group main bundle followed by up
        // to ten 75-group INDEX and ten 80-group CHUNK sibling levels.
        limits: EntitlementLimitsV1 {
            max_logical_inputs: 1,
            max_frames: 32,
            max_request_bytes: 4 * 1024 * 1024,
            max_response_bytes: 256 * 1024 * 1024,
            max_wall_time_ms: 300_000,
            max_concurrent_sockets: 1,
            max_hint_groups: 2_048,
            max_work_units: 2_048,
        },
    },
    WorkloadFixture {
        name: "harmony-query-job-v1",
        backend: BackendId::HarmonyPirV2,
        workload: WorkloadId::HarmonyQueryJobV1,
        protocol_version: 2,
        operation_profile: 13,
        entitlement_profile: 103,
        bolt11_unit_price_msat: 500,
        cashu_price_sat: 1,
        // Integration-fixture capacity, not a commercial price profile. One
        // logical input is one complete padded INDEX pair; K*(T-1) padding is
        // charged only to work/byte budgets and real CHUNK responses exceed
        // the old 2 MiB placeholder.
        limits: EntitlementLimitsV1 {
            max_logical_inputs: 1,
            max_frames: 32,
            max_request_bytes: 8 * 1024 * 1024,
            max_response_bytes: 64 * 1024 * 1024,
            max_wall_time_ms: 120_000,
            max_concurrent_sockets: 1,
            max_hint_groups: 0,
            max_work_units: 1_000_000,
        },
    },
    WorkloadFixture {
        name: "onion-evaluate-job-v1",
        backend: BackendId::OnionPirV1,
        workload: WorkloadId::OnionEvaluateJobV1,
        protocol_version: 1,
        operation_profile: 14,
        entitlement_profile: 104,
        bolt11_unit_price_msat: 3_000,
        cashu_price_sat: 3,
        limits: EntitlementLimitsV1 {
            max_logical_inputs: 1,
            max_frames: 256,
            max_request_bytes: 16 * 1024 * 1024,
            max_response_bytes: 16 * 1024 * 1024,
            max_wall_time_ms: 90_000,
            max_concurrent_sockets: 1,
            max_hint_groups: 0,
            max_work_units: 75_000,
        },
    },
    WorkloadFixture {
        name: "tee-oram-query-v1",
        backend: BackendId::TeeOramV1,
        workload: WorkloadId::TeeOramQueryV1,
        protocol_version: 1,
        operation_profile: 15,
        entitlement_profile: 105,
        bolt11_unit_price_msat: 2_000,
        cashu_price_sat: 2,
        limits: EntitlementLimitsV1 {
            // One capability authorizes one atomic REQ_ORAM_LOOKUP containing
            // up to the public 25-slot deployment profile. Multiple frames
            // would turn one entitlement into cross-query reuse.
            max_logical_inputs: 25,
            max_frames: 1,
            max_request_bytes: 4 * 1024 * 1024,
            max_response_bytes: 4 * 1024 * 1024,
            max_wall_time_ms: 45_000,
            max_concurrent_sockets: 1,
            max_hint_groups: 0,
            max_work_units: 30_000,
        },
    },
];

pub fn run(args: PaymentFixtureArgs) -> Result<(), String> {
    if !args.acknowledge_deterministic_test_keys {
        return Err(
            "refusing to emit public deterministic keys without --acknowledge-deterministic-test-keys"
                .to_owned(),
        );
    }
    let output_root = prepare_output_directory(&args.out, args.force)?;
    let mut providers = Vec::with_capacity(2);
    for provider_index in 0..2 {
        providers.push(build_provider_fixture(
            &output_root,
            provider_index,
            args.force,
        )?);
    }
    verify_provider_independence(&providers)?;
    let browser_two_provider_harness = if args.include_browser_two_provider_harness {
        Some(build_browser_two_provider_harness(
            &output_root,
            args.force,
            &mut providers,
        )?)
    } else {
        None
    };
    let inventory = FixtureInventoryV1 {
        schema: "BitcoinPIRPaymentV1NoFundsFixture".to_owned(),
        schema_version: 1,
        test_only: true,
        deterministic: true,
        funds_capable: false,
        network: "regtest".to_owned(),
        warning: "ALL KEYS ARE PUBLIC TEST VECTORS. NEVER USE WITH REAL FUNDS OR PRODUCTION DATA."
            .to_owned(),
        providers,
        browser_two_provider_harness,
    };
    let encoded = serde_json::to_vec_pretty(&inventory)
        .map_err(|error| format!("encode fixture inventory: {error}"))?;
    write_fixture_file(
        &output_root,
        &output_root.join("fixture.json"),
        &encoded,
        args.force,
        FixtureFileKind::Public,
    )?;
    let decoded: FixtureInventoryV1 = serde_json::from_slice(&encoded)
        .map_err(|error| format!("self-decode fixture inventory: {error}"))?;
    if decoded != inventory {
        return Err("fixture inventory did not roundtrip exactly".to_owned());
    }
    println!("fixture={}", output_root.display());
    println!("providers=2");
    println!("workloads_per_provider=5");
    println!("methods_per_workload=5");
    println!("funds_capable=false");
    if args.include_browser_two_provider_harness {
        println!("browser_two_provider_harness=yes");
    }
    Ok(())
}

fn prepare_output_directory(path: &Path, force: bool) -> Result<PathBuf, String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                return Err(format!("{} must be a real directory", path.display()));
            }
            if !force {
                return Err(format!("{} already exists; use --force", path.display()));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path)
                .map_err(|error| format!("create {}: {error}", path.display()))?;
        }
        Err(error) => return Err(format!("inspect {}: {error}", path.display())),
    }
    std::fs::canonicalize(path)
        .map_err(|error| format!("canonicalize fixture root {}: {error}", path.display()))
}

fn build_provider_fixture(
    root: &Path,
    provider_index: usize,
    force: bool,
) -> Result<FixtureProviderInventoryV1, String> {
    let name = format!("provider-{provider_index}");
    let stable_server_id = format!("payment-v1-fixture-{name}");
    let provider_root = root.join(&name);
    let secrets_root = provider_root.join("secrets");
    let public_root = provider_root.join("public");
    ensure_fixture_directory(root, &public_root)?;

    let mut secret_files = Vec::new();
    let mut public_files = Vec::new();

    let operator_seed = deterministic_ed25519_seed(&format!("{name}/operator"));
    let operator_key = SigningKey::from_bytes(&operator_seed);
    write_fixture_secret(
        root,
        &secrets_root.join("operator-ed25519.key"),
        &operator_seed,
        force,
        &mut secret_files,
    )?;
    let provider_id =
        derive_provider_id(&operator_key.verifying_key().to_bytes(), &stable_server_id);

    let policy_seed = deterministic_ed25519_seed(&format!("{name}/policy"));
    let policy_key = SigningKey::from_bytes(&policy_seed);
    write_fixture_secret(
        root,
        &secrets_root.join("policy-ed25519.key"),
        &policy_seed,
        force,
        &mut secret_files,
    )?;

    let issuer_seed = deterministic_ed25519_seed(&format!("{name}/issuer-root"));
    let issuer_key = SigningKey::from_bytes(&issuer_seed);
    write_fixture_secret(
        root,
        &secrets_root.join("issuer-root-ed25519.key"),
        &issuer_seed,
        force,
        &mut secret_files,
    )?;

    let quote_seed = deterministic_ed25519_seed(&format!("{name}/quote-signing"));
    let quote_key = SigningKey::from_bytes(&quote_seed);
    write_fixture_secret(
        root,
        &secrets_root.join("quote-ed25519.key"),
        &quote_seed,
        force,
        &mut secret_files,
    )?;

    for (file_name, label) in [
        ("credential-derivation.key", "credential-derivation"),
        ("redeem-derivation.key", "redeem-derivation"),
        ("fake-lightning-derivation.key", "fake-lightning-derivation"),
    ] {
        let key = deterministic_nonzero_32(&format!("{name}/{label}"));
        write_fixture_secret(
            root,
            &secrets_root.join(file_name),
            &key,
            force,
            &mut secret_files,
        )?;
    }

    let claim_seed = deterministic_k256_scalar(&format!("{name}/browser-claim"));
    let claim_key = SchnorrSigningKey::from_bytes(&claim_seed)
        .map_err(|_| "deterministic BIP340 fixture key was invalid".to_owned())?;
    write_fixture_secret(
        root,
        &provider_root.join("browser-test-only/claim-bip340.key"),
        &claim_seed,
        force,
        &mut secret_files,
    )?;
    let claim_public_path = public_root.join("browser-claim-pubkey.hex");
    write_fixture_public(
        root,
        &claim_public_path,
        hex::encode(claim_key.verifying_key().to_bytes()).as_bytes(),
        force,
        &mut public_files,
    )?;

    let fake_lightning_seed = deterministic_k256_scalar(&format!("{name}/fake-lightning"));
    let fake_lightning_key = Secp256k1SecretKey::from_slice(&fake_lightning_seed)
        .map_err(|_| "deterministic fake-Lightning key was invalid".to_owned())?;
    write_fixture_secret(
        root,
        &secrets_root.join("fake-lightning-secp256k1.key"),
        &fake_lightning_seed,
        force,
        &mut secret_files,
    )?;
    let payee: [u8; 33] = fake_lightning_key
        .public_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .map_err(|_| "fake-Lightning public key was not compressed".to_owned())?;
    let quote_delegation = Bolt11QuoteKeyDelegationV1::sign(
        LightningNetworkV1::Regtest,
        payee,
        1,
        FIXTURE_ISSUED_AT,
        FIXTURE_EXPIRES_AT,
        quote_key.verifying_key().to_bytes(),
        &issuer_key,
    )
    .map_err(|error| format!("construct {name} quote delegation: {error}"))?;
    quote_delegation
        .verify_for(
            &quote_delegation.issuer_id,
            LightningNetworkV1::Regtest,
            &payee,
            1,
            FIXTURE_NOW,
        )
        .map_err(|error| format!("self-verify {name} quote delegation: {error}"))?;
    let quote_path = public_root.join("quote-key-delegation-v1.bin");
    let quote_bytes = quote_delegation
        .encode()
        .map_err(|error| format!("encode {name} quote delegation: {error}"))?;
    if Bolt11QuoteKeyDelegationV1::decode(&quote_bytes)
        .map_err(|error| format!("roundtrip {name} quote delegation: {error}"))?
        != quote_delegation
    {
        return Err(format!("{name} quote delegation roundtrip mismatch"));
    }
    write_fixture_public(root, &quote_path, &quote_bytes, force, &mut public_files)?;

    let receipt_seed = deterministic_ed25519_seed(&format!("{name}/receipt"));
    let receipt_key = SigningKey::from_bytes(&receipt_seed);
    write_fixture_secret(
        root,
        &secrets_root.join("receipt-ed25519.key"),
        &receipt_seed,
        force,
        &mut secret_files,
    )?;

    let (cashu_manifest, cashu_manifest_path) = build_fixture_cashu_manifest(
        root,
        &name,
        &secrets_root,
        &public_root,
        force,
        &mut secret_files,
        &mut public_files,
    )?;
    let cashu_manifest_digest = cashu_manifest
        .manifest_digest()
        .map_err(|error| format!("digest {name} Cashu manifest: {error}"))?;
    let cashu_mint_id = cashu_manifest.mint_id();

    let issuer_endpoint = format!("https://issuer-{provider_index}.fixture.invalid");
    let mut scope_policies = Vec::with_capacity(WORKLOADS.len());
    let mut scope_inventory = Vec::with_capacity(WORKLOADS.len());
    for (workload_index, workload) in WORKLOADS.iter().enumerate() {
        let scope = ServiceScopeV1 {
            provider_id,
            backend: workload.backend,
            workload: workload.workload,
            protocol_version: workload.protocol_version,
            dataset: DatasetBindingV1::Class { class_id: 1 },
            operation_profile: workload.operation_profile,
            entitlement_profile: workload.entitlement_profile,
        };
        scope
            .validate()
            .map_err(|error| format!("validate {name}/{} scope: {error}", workload.name))?;
        let scope_id = scope.scope_id();
        let first_offer_id = (workload_index as u32 + 1) * 10;
        let bindings_dir = public_root.join("credential-bindings").join(workload.name);
        let secrets_dir = secrets_root.join("workloads").join(workload.name);

        let direct_offer_id = first_offer_id + 2;
        let direct_key_id = paid_receipt_key_id(&receipt_key.verifying_key()).to_vec();
        let direct_binding = fixture_binding(
            &issuer_key,
            provider_id,
            scope_id,
            direct_offer_id,
            AuthScheme::Bolt11DirectReceiptV1,
            workload.entitlement_profile,
            CredentialUnitV1::Entitlement,
            1,
            direct_key_id.clone(),
            receipt_key.verifying_key().to_bytes().to_vec(),
        )?;
        let direct_binding_path = bindings_dir.join("bolt11-direct-receipt-v1.bin");
        write_binding(
            root,
            &direct_binding_path,
            &direct_binding,
            force,
            &mut public_files,
        )?;

        let bat_offer_id = first_offer_id + 4;
        let bat_secret = deterministic_k256_scalar(&format!("{name}/{}/bat", workload.name));
        let bat_key = Secp256k1SecretKey::from_slice(&bat_secret)
            .map_err(|_| "deterministic BAT key was invalid".to_owned())?;
        let bat_public: [u8; 33] = bat_key
            .public_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .map_err(|_| "BAT public key was not compressed".to_owned())?;
        write_fixture_secret(
            root,
            &secrets_dir.join("cashu-bat.key"),
            &bat_secret,
            force,
            &mut secret_files,
        )?;
        let bat_key_id = derive_bat_key_id_v1(
            &provider_id,
            &scope_id,
            bat_offer_id,
            workload.entitlement_profile,
            1,
            &bat_public,
        )
        .to_vec();
        let bat_binding = fixture_binding(
            &issuer_key,
            provider_id,
            scope_id,
            bat_offer_id,
            AuthScheme::BitcoinPirCashuBatV1,
            workload.entitlement_profile,
            CredentialUnitV1::Auth,
            1,
            bat_key_id.clone(),
            bat_public.to_vec(),
        )?;
        let bat_binding_path = bindings_dir.join("cashu-bat-v1.bin");
        write_binding(
            root,
            &bat_binding_path,
            &bat_binding,
            force,
            &mut public_files,
        )?;

        let arc_offer_id = first_offer_id + 5;
        let mut arc_secret = deterministic_arc_secret(&format!("{name}/{}/arc", workload.name))?;
        let arc_key = ArcSecretKeyV1::from_zeroizing_bytes(vec![1], Zeroizing::new(arc_secret))
            .map_err(|error| format!("parse deterministic ARC key: {error}"))?;
        write_fixture_secret(
            root,
            &secrets_dir.join("arc-experimental.key"),
            &arc_secret,
            force,
            &mut secret_files,
        )?;
        arc_secret.zeroize();
        let arc_key_id = arc_key.public_key_fingerprint().to_vec();
        let arc_binding = fixture_binding_with_limit(
            &issuer_key,
            provider_id,
            scope_id,
            arc_offer_id,
            AuthScheme::ArcV1Experimental,
            workload.entitlement_profile,
            CredentialUnitV1::Auth,
            ARC_PRESENTATION_LIMIT,
            arc_key_id.clone(),
            arc_key.public_key_bytes().to_vec(),
        )?;
        let arc_binding_path = bindings_dir.join("arc-v1-experimental.bin");
        write_binding(
            root,
            &arc_binding_path,
            &arc_binding,
            force,
            &mut public_files,
        )?;

        let offers = vec![
            free_offer(first_offer_id + 1),
            direct_offer(
                direct_offer_id,
                workload.bolt11_unit_price_msat,
                quote_delegation.issuer_id,
                direct_key_id.clone(),
                direct_binding,
                issuer_endpoint.clone(),
            )?,
            cashu_ecash_offer(
                first_offer_id + 3,
                workload.cashu_price_sat,
                cashu_manifest.clone(),
            )?,
            bat_offer(
                bat_offer_id,
                workload.bolt11_unit_price_msat.saturating_mul(4),
                quote_delegation.issuer_id,
                bat_key_id.clone(),
                bat_binding,
                issuer_endpoint.clone(),
            )?,
            arc_offer(
                arc_offer_id,
                workload.bolt11_unit_price_msat.saturating_mul(4),
                quote_delegation.issuer_id,
                arc_key_id.clone(),
                arc_binding,
                issuer_endpoint.clone(),
            )?,
        ];
        scope_policies.push(ServiceScopePolicyV1 {
            scope,
            limits: workload.limits.clone(),
            offers,
        });
        scope_inventory.push(FixtureScopeInventoryV1 {
            workload: workload.name.to_owned(),
            scope_id: hex::encode(scope_id),
            offers: vec![
                fixture_offer("free", first_offer_id + 1, "stable", None, None, root),
                fixture_offer(
                    "bolt11",
                    direct_offer_id,
                    "stable",
                    Some(&direct_binding_path),
                    Some(&direct_key_id),
                    root,
                ),
                fixture_offer(
                    "cashu-ecash",
                    first_offer_id + 3,
                    "stable",
                    None,
                    Some(&cashu_manifest_digest),
                    root,
                ),
                fixture_offer(
                    "cashu-bat",
                    bat_offer_id,
                    "stable",
                    Some(&bat_binding_path),
                    Some(&bat_key_id),
                    root,
                ),
                fixture_offer(
                    "arc-experimental",
                    arc_offer_id,
                    "experimental",
                    Some(&arc_binding_path),
                    Some(&arc_key_id),
                    root,
                ),
            ],
        });
    }

    let policy = ServicePolicyV1::sign(
        provider_id,
        1,
        FIXTURE_ISSUED_AT,
        FIXTURE_EXPIRES_AT,
        AuthPaddingClassV1::Class16KiB,
        scope_policies,
        &policy_key,
    )
    .map_err(|error| format!("sign {name} service policy: {error}"))?;
    let policy_bytes = policy
        .encode()
        .map_err(|error| format!("encode {name} service policy: {error}"))?;
    let decoded_policy = ServicePolicyV1::decode(&policy_bytes)
        .map_err(|error| format!("decode {name} service policy: {error}"))?;
    if decoded_policy != policy {
        return Err(format!("{name} service policy roundtrip mismatch"));
    }
    let verified = decoded_policy
        .verify_current_for_acquisition(
            &provider_id,
            FIXTURE_NOW,
            &PolicyRollbackGuardV1::initial(),
            &ServicePolicyEpochFloorsV1::initial(),
            &policy_key.verifying_key(),
        )
        .map_err(|error| format!("self-verify {name} service policy: {error}"))?;
    for scope in &scope_inventory {
        let scope_id = crate::payment_artifact::parse_hex_exact::<32>("scope_id", &scope.scope_id)?;
        for offer in &scope.offers {
            verified
                .offer(&scope_id, offer.offer_id)
                .map_err(|error| format!("resolve {name} fixture offer: {error}"))?;
        }
    }
    let policy_path = public_root.join("service-policy-v1.bin");
    write_fixture_public(root, &policy_path, &policy_bytes, force, &mut public_files)?;

    secret_files.sort();
    public_files.sort();
    Ok(FixtureProviderInventoryV1 {
        name,
        stable_server_id,
        provider_id: hex::encode(provider_id),
        operator_pubkey: hex::encode(operator_key.verifying_key().to_bytes()),
        policy_signing_pubkey: hex::encode(policy_key.verifying_key().to_bytes()),
        issuer_id: hex::encode(quote_delegation.issuer_id),
        quote_key_id: hex::encode(quote_delegation.quote_key_id),
        quote_delegation_digest: hex::encode(
            quote_delegation
                .delegation_digest()
                .map_err(|error| format!("digest quote delegation: {error}"))?,
        ),
        expected_payee_pubkey: hex::encode(payee),
        cashu_mint_id: hex::encode(cashu_mint_id),
        cashu_manifest_digest: hex::encode(cashu_manifest_digest),
        policy_path: relative(root, &policy_path)?,
        quote_delegation_path: relative(root, &quote_path)?,
        cashu_manifest_path: relative(root, &cashu_manifest_path)?,
        secret_files,
        public_files,
        scopes: scope_inventory,
    })
}

fn build_browser_two_provider_harness(
    root: &Path,
    force: bool,
    providers: &mut [FixtureProviderInventoryV1],
) -> Result<BrowserTwoProviderHarnessInventoryV1, String> {
    if providers.len() != 2 {
        return Err("browser two-provider harness requires exactly two providers".to_owned());
    }
    let harness_root = root.join("browser-two-provider");
    let database = harness_root.join("tiny-dpf-db");
    ensure_fixture_directory(root, &database)?;
    let chain_anchor = CoreChainAnchor {
        block_hash: deterministic_nonzero_32("browser-two-provider/database-chain-anchor"),
        block_height: BROWSER_HARNESS_DB_HEIGHT,
    };
    let header_anchor = HeaderAnchor::Snapshot(chain_anchor);
    let seeds = SnapshotSeeds::derive(&chain_anchor);
    let index_path = database.join("batch_pir_cuckoo.bin");
    let chunk_path = database.join("chunk_pir_cuckoo.bin");
    let mut index_bytes = write_header_with_anchor(
        &INDEX_PARAMS.with_master_seed(seeds.index_master),
        BROWSER_HARNESS_TINY_BINS_PER_TABLE,
        seeds.index_tag,
        Some(&header_anchor),
    );
    index_bytes.resize(
        index_bytes.len()
            + INDEX_PARAMS.k * INDEX_PARAMS.table_byte_size(BROWSER_HARNESS_TINY_BINS_PER_TABLE),
        0,
    );
    let mut chunk_bytes = write_header_with_anchor(
        &CHUNK_PARAMS.with_master_seed(seeds.chunk_master),
        BROWSER_HARNESS_TINY_BINS_PER_TABLE,
        0,
        Some(&header_anchor),
    );
    chunk_bytes.resize(
        chunk_bytes.len()
            + CHUNK_PARAMS.k * CHUNK_PARAMS.table_byte_size(BROWSER_HARNESS_TINY_BINS_PER_TABLE),
        0,
    );
    let bucket_merkle = build_browser_bucket_merkle_artifacts(&index_bytes, &chunk_bytes)?;
    let tree_tops_path = database.join("merkle_bucket_tree_tops.bin");
    let roots_path = database.join("merkle_bucket_roots.bin");
    let super_root_path = database.join("merkle_bucket_root.bin");
    let index_hash = hex::encode(sha256(&index_bytes));
    let chunk_hash = hex::encode(sha256(&chunk_bytes));
    let tree_tops_hash = hex::encode(sha256(&bucket_merkle.tree_tops));
    let roots_hash = hex::encode(sha256(&bucket_merkle.roots));
    let super_root_hash = hex::encode(sha256(&bucket_merkle.super_root));
    let manifest = format!(
        "[manifest]\nversion = 1\ngenerated_at = \"2026-07-26T00:00:00Z\"\n\n[files]\n\"batch_pir_cuckoo.bin\" = \"{index_hash}\"\n\"chunk_pir_cuckoo.bin\" = \"{chunk_hash}\"\n\"merkle_bucket_root.bin\" = \"{super_root_hash}\"\n\"merkle_bucket_roots.bin\" = \"{roots_hash}\"\n\"merkle_bucket_tree_tops.bin\" = \"{tree_tops_hash}\"\n"
    );
    let manifest_path = database.join("MANIFEST.toml");
    for (path, bytes) in [
        (&index_path, index_bytes.as_slice()),
        (&chunk_path, chunk_bytes.as_slice()),
        (&tree_tops_path, bucket_merkle.tree_tops.as_slice()),
        (&roots_path, bucket_merkle.roots.as_slice()),
        (&super_root_path, bucket_merkle.super_root.as_slice()),
        (&manifest_path, manifest.as_bytes()),
    ] {
        write_fixture_file(root, path, bytes, force, FixtureFileKind::Public)?;
    }
    let manifest_root = sha256(manifest.as_bytes());
    let database_proof = build_browser_database_proof(
        root,
        &harness_root,
        force,
        &index_bytes,
        &chunk_bytes,
        &bucket_merkle,
        manifest.as_bytes(),
        manifest_root,
        chain_anchor,
        seeds,
    )?;
    let config_path = harness_root.join("databases.toml");
    let config = format!(
        "[[database]]\nname = \"payment-two-provider-tiny-snapshot\"\ntype = \"full\"\npath = \"tiny-dpf-db\"\nproof_dir = \"synthetic-db-proof\"\nbase_height = 0\nheight = {BROWSER_HARNESS_DB_HEIGHT}\n"
    );
    write_fixture_file(
        root,
        &config_path,
        config.as_bytes(),
        force,
        FixtureFileKind::Public,
    )?;

    let workload = &WORKLOADS[0];
    if workload.backend != BackendId::DpfPirV1 || workload.workload != WorkloadId::DpfEvaluateJobV1
    {
        return Err("browser harness DPF workload fixture changed unexpectedly".to_owned());
    }
    let mut harness_providers = Vec::with_capacity(2);
    for (provider_index, provider_inventory) in providers.iter_mut().enumerate() {
        let name = format!("provider-{provider_index}");
        if provider_inventory.name != name {
            return Err("browser harness provider inventory order changed".to_owned());
        }
        let operator_key =
            SigningKey::from_bytes(&deterministic_ed25519_seed(&format!("{name}/operator")));
        let provider_id = derive_provider_id(
            &operator_key.verifying_key().to_bytes(),
            &provider_inventory.stable_server_id,
        );
        if hex::encode(provider_id) != provider_inventory.provider_id {
            return Err(format!("{name} browser harness provider ID drifted"));
        }
        let policy_key =
            SigningKey::from_bytes(&deterministic_ed25519_seed(&format!("{name}/policy")));
        let issuer_key =
            SigningKey::from_bytes(&deterministic_ed25519_seed(&format!("{name}/issuer-root")));
        let expected_issuer_id = derive_issuer_id(&issuer_key.verifying_key().to_bytes());
        if hex::encode(expected_issuer_id) != provider_inventory.issuer_id {
            return Err(format!(
                "{name} browser harness issuer ID drifted from its fixture quote delegation"
            ));
        }
        let scope = ServiceScopeV1 {
            provider_id,
            backend: workload.backend,
            workload: workload.workload,
            protocol_version: workload.protocol_version,
            dataset: DatasetBindingV1::ManifestRoot {
                root: manifest_root,
            },
            operation_profile: workload.operation_profile,
            entitlement_profile: workload.entitlement_profile,
        };
        scope
            .validate()
            .map_err(|error| format!("validate {name} browser DPF scope: {error}"))?;
        let scope_id = scope.scope_id();
        let endpoint = format!("https://issuer-{provider_index}.fixture.invalid");
        let public_root = root.join(&name).join("public/browser-two-provider");

        let (
            offers,
            offer_inventory,
            issuer_id,
            free_ip_key_path,
            bat_key_path,
            arc_key_path,
            arc_key_id,
        ) = if provider_index == 0 {
            let mut free = free_offer(111);
            free.free_mode = FreeModeV1::IpRateLimited;
            free.free_quota = 1;
            free.free_window_seconds = 3_600;
            free.privacy_leakage = PrivacyLeakageV1::from_bits(PrivacyLeakageV1::IP_RATE_BUCKET)
                .map_err(|error| format!("build browser Free/IP leakage disclosure: {error}"))?;
            let mut free_ip_secret =
                deterministic_nonzero_32(&format!("{name}/browser-two-provider/free-ip"));
            let free_ip_secret_path = root
                .join(&name)
                .join("secrets/browser-two-provider/free-ip-hmac.key");
            write_fixture_secret(
                root,
                &free_ip_secret_path,
                &free_ip_secret,
                force,
                &mut provider_inventory.secret_files,
            )?;
            free_ip_secret.zeroize();
            let offer_id = 112;
            let receipt_key =
                SigningKey::from_bytes(&deterministic_ed25519_seed(&format!("{name}/receipt")));
            let key_id = paid_receipt_key_id(&receipt_key.verifying_key()).to_vec();
            let binding = fixture_binding(
                &issuer_key,
                provider_id,
                scope_id,
                offer_id,
                AuthScheme::Bolt11DirectReceiptV1,
                workload.entitlement_profile,
                CredentialUnitV1::Entitlement,
                1,
                key_id.clone(),
                receipt_key.verifying_key().to_bytes().to_vec(),
            )?;
            let binding_path = public_root.join("bolt11-direct-receipt-v1.bin");
            write_binding(
                root,
                &binding_path,
                &binding,
                force,
                &mut provider_inventory.public_files,
            )?;
            let direct = direct_offer(
                offer_id,
                workload.bolt11_unit_price_msat,
                binding.issuer_id,
                key_id,
                binding,
                endpoint.clone(),
            )?;
            (
                vec![free, direct],
                vec![
                    BrowserProviderOfferHarnessInventoryV1 {
                        variant: "direct-bat".to_owned(),
                        offer_id,
                        method: "bolt11-direct-receipt".to_owned(),
                        free_mode: "not-free".to_owned(),
                        deployment_status: "stable".to_owned(),
                    },
                    BrowserProviderOfferHarnessInventoryV1 {
                        variant: "free-arc-experimental".to_owned(),
                        offer_id: 111,
                        method: "free".to_owned(),
                        free_mode: "ip-rate-limited".to_owned(),
                        deployment_status: "stable".to_owned(),
                    },
                ],
                expected_issuer_id,
                Some(relative(root, &free_ip_secret_path)?),
                None,
                None,
                None,
            )
        } else {
            let offer_id = 214;
            let mut bat_secret =
                deterministic_k256_scalar(&format!("{name}/browser-two-provider/bat"));
            let bat_key = Secp256k1SecretKey::from_slice(&bat_secret)
                .map_err(|_| "deterministic browser BAT key was invalid".to_owned())?;
            let bat_public: [u8; 33] = bat_key
                .public_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .map_err(|_| "browser BAT public key was not compressed".to_owned())?;
            let bat_secret_path = root
                .join(&name)
                .join("secrets/browser-two-provider/cashu-bat.key");
            write_fixture_secret(
                root,
                &bat_secret_path,
                &bat_secret,
                force,
                &mut provider_inventory.secret_files,
            )?;
            bat_secret.zeroize();
            let key_id = derive_bat_key_id_v1(
                &provider_id,
                &scope_id,
                offer_id,
                workload.entitlement_profile,
                1,
                &bat_public,
            )
            .to_vec();
            let binding = fixture_binding(
                &issuer_key,
                provider_id,
                scope_id,
                offer_id,
                AuthScheme::BitcoinPirCashuBatV1,
                workload.entitlement_profile,
                CredentialUnitV1::Auth,
                1,
                key_id.clone(),
                bat_public.to_vec(),
            )?;
            let binding_path = public_root.join("cashu-bat-v1.bin");
            write_binding(
                root,
                &binding_path,
                &binding,
                force,
                &mut provider_inventory.public_files,
            )?;
            let mut bat = bat_offer(
                offer_id,
                workload.bolt11_unit_price_msat.saturating_mul(4),
                binding.issuer_id,
                key_id,
                binding,
                endpoint.clone(),
            )?;
            // This harness exercises one exact single-use capability on each
            // leg. The broader fixture still covers multi-capability batches.
            bat.credential_count = 1;

            let arc_offer_id = 215;
            let mut arc_secret =
                deterministic_arc_secret(&format!("{name}/browser-two-provider/arc"))?;
            let arc_key = ArcSecretKeyV1::from_zeroizing_bytes(vec![1], Zeroizing::new(arc_secret))
                .map_err(|error| format!("parse deterministic browser ARC key: {error}"))?;
            let arc_secret_path = root
                .join(&name)
                .join("secrets/browser-two-provider/arc-experimental.key");
            write_fixture_secret(
                root,
                &arc_secret_path,
                &arc_secret,
                force,
                &mut provider_inventory.secret_files,
            )?;
            arc_secret.zeroize();
            let arc_id = arc_key.public_key_fingerprint().to_vec();
            let arc_binding = fixture_binding_with_limit(
                &issuer_key,
                provider_id,
                scope_id,
                arc_offer_id,
                AuthScheme::ArcV1Experimental,
                workload.entitlement_profile,
                CredentialUnitV1::Auth,
                ARC_PRESENTATION_LIMIT,
                arc_id.clone(),
                arc_key.public_key_bytes().to_vec(),
            )?;
            let arc_binding_path = public_root.join("arc-v1-experimental.bin");
            write_binding(
                root,
                &arc_binding_path,
                &arc_binding,
                force,
                &mut provider_inventory.public_files,
            )?;
            let arc = arc_offer(
                arc_offer_id,
                workload.bolt11_unit_price_msat.saturating_mul(4),
                arc_binding.issuer_id,
                arc_id.clone(),
                arc_binding,
                endpoint.clone(),
            )?;
            (
                vec![bat, arc],
                vec![
                    BrowserProviderOfferHarnessInventoryV1 {
                        variant: "direct-bat".to_owned(),
                        offer_id,
                        method: "cashu-bat".to_owned(),
                        free_mode: "not-free".to_owned(),
                        deployment_status: "stable".to_owned(),
                    },
                    BrowserProviderOfferHarnessInventoryV1 {
                        variant: "free-arc-experimental".to_owned(),
                        offer_id: arc_offer_id,
                        method: "arc-experimental".to_owned(),
                        free_mode: "not-free".to_owned(),
                        deployment_status: "experimental".to_owned(),
                    },
                ],
                expected_issuer_id,
                None,
                Some(relative(root, &bat_secret_path)?),
                Some(relative(root, &arc_secret_path)?),
                Some(hex::encode(arc_id)),
            )
        };
        let policy = ServicePolicyV1::sign(
            provider_id,
            1,
            FIXTURE_ISSUED_AT,
            FIXTURE_EXPIRES_AT,
            AuthPaddingClassV1::Class16KiB,
            vec![ServiceScopePolicyV1 {
                scope,
                limits: workload.limits.clone(),
                offers,
            }],
            &policy_key,
        )
        .map_err(|error| format!("sign {name} browser DPF policy: {error}"))?;
        policy
            .verify_current_for_acquisition(
                &provider_id,
                FIXTURE_NOW,
                &PolicyRollbackGuardV1::initial(),
                &ServicePolicyEpochFloorsV1::initial(),
                &policy_key.verifying_key(),
            )
            .map_err(|error| format!("self-verify {name} browser DPF policy: {error}"))?;
        let policy_path = public_root.join("service-policy-v1.bin");
        let policy_bytes = policy
            .encode()
            .map_err(|error| format!("encode {name} browser DPF policy: {error}"))?;
        write_fixture_public(
            root,
            &policy_path,
            &policy_bytes,
            force,
            &mut provider_inventory.public_files,
        )?;
        provider_inventory.secret_files.sort();
        provider_inventory.secret_files.dedup();
        provider_inventory.public_files.sort();
        provider_inventory.public_files.dedup();
        harness_providers.push(BrowserProviderHarnessInventoryV1 {
            name,
            provider_id: hex::encode(provider_id),
            policy_signing_pubkey: hex::encode(policy_key.verifying_key().to_bytes()),
            expected_payee_pubkey: provider_inventory.expected_payee_pubkey.clone(),
            issuer_id: hex::encode(issuer_id),
            policy_path: relative(root, &policy_path)?,
            quote_delegation_path: provider_inventory.quote_delegation_path.clone(),
            scope_id: hex::encode(scope_id),
            entitlement_profile: workload.entitlement_profile,
            offers: offer_inventory,
            free_ip_key_path,
            bat_key_path,
            arc_key_path,
            arc_key_id,
        });
    }
    let proof_root = root.join(&database_proof.proof_path);
    let mut public_files = vec![
        index_path,
        chunk_path,
        tree_tops_path,
        roots_path,
        super_root_path,
        manifest_path,
        config_path,
    ];
    public_files.extend(
        [
            "build-evidence.bin",
            "root-bundle-payload.bin",
            "build-evidence.sev-snp-report.bin",
            "database.manifest.sha256",
            "all-artifacts.manifest.sha256",
            "server-db/MANIFEST.toml",
        ]
        .into_iter()
        .map(|relative_path| proof_root.join(relative_path)),
    );
    let public_files = public_files
        .iter()
        .map(|path| relative(root, path))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(BrowserTwoProviderHarnessInventoryV1 {
        boundary: "loopback-only no-funds DPF admission and query with explicit NoSEV runtime-attestation boundary; the synthetic DB report proves only REPORT_DATA byte binding (not an AMD signature or production builder); no production identity, AMD attestation, or production database, but the harness performs real secure-channel DPF query plus proof-bound bucket-Merkle preflight and inclusion/absence verification"
            .to_owned(),
        database_path: relative(root, &database)?,
        database_config_path: relative(root, &harness_root.join("databases.toml"))?,
        manifest_root: hex::encode(manifest_root),
        database_proof,
        public_files,
        providers: harness_providers,
    })
}

fn build_browser_bucket_merkle_artifacts(
    index_bytes: &[u8],
    chunk_bytes: &[u8],
) -> Result<BrowserBucketMerkleArtifactsV1, String> {
    let tree_count = INDEX_PARAMS
        .k
        .checked_add(CHUNK_PARAMS.k)
        .ok_or_else(|| "browser bucket-Merkle tree count overflow".to_owned())?;
    let mut tree_tops = Vec::new();
    tree_tops.extend_from_slice(
        &u32::try_from(tree_count)
            .map_err(|_| "browser bucket-Merkle tree count exceeds u32".to_owned())?
            .to_le_bytes(),
    );
    let mut roots = Vec::with_capacity(tree_count * 32);
    append_browser_bucket_merkle_table(
        "INDEX",
        index_bytes,
        &INDEX_PARAMS,
        &mut tree_tops,
        &mut roots,
    )?;
    append_browser_bucket_merkle_table(
        "CHUNK",
        chunk_bytes,
        &CHUNK_PARAMS,
        &mut tree_tops,
        &mut roots,
    )?;
    if roots.len() != tree_count * 32 {
        return Err("browser bucket-Merkle roots length drifted".to_owned());
    }
    Ok(BrowserBucketMerkleArtifactsV1 {
        super_root: sha256(&roots),
        tree_tops,
        roots,
    })
}

fn append_browser_bucket_merkle_table(
    label: &str,
    table_bytes: &[u8],
    params: &pir_core::params::TableParams,
    tree_tops: &mut Vec<u8>,
    roots: &mut Vec<u8>,
) -> Result<(), String> {
    let header = pir_core::cuckoo::read_cuckoo_header_with_anchor(table_bytes, params)
        .map_err(|error| format!("parse browser {label} table for bucket Merkle: {error}"))?;
    if header.bins_per_table != BROWSER_HARNESS_TINY_BINS_PER_TABLE {
        return Err(format!(
            "browser {label} table has {} bins instead of {}",
            header.bins_per_table, BROWSER_HARNESS_TINY_BINS_PER_TABLE
        ));
    }
    let group_size = params.table_byte_size(header.bins_per_table);
    let table_data_len = params
        .k
        .checked_mul(group_size)
        .ok_or_else(|| format!("browser {label} table length overflow"))?;
    let expected_len = header
        .header_size
        .checked_add(table_data_len)
        .ok_or_else(|| format!("browser {label} file length overflow"))?;
    if table_bytes.len() != expected_len {
        return Err(format!(
            "browser {label} table length {} does not equal expected {expected_len}",
            table_bytes.len()
        ));
    }

    for group in 0..params.k {
        let start = header.header_size + group * group_size;
        let group_bytes = &table_bytes[start..start + group_size];
        let mut levels: Vec<Vec<Hash256>> = vec![(0..header.bins_per_table)
            .map(|bin_index| {
                let bin_start = bin_index * params.bin_size();
                compute_bin_leaf_hash(
                    bin_index as u32,
                    &group_bytes[bin_start..bin_start + params.bin_size()],
                )
            })
            .collect()];
        while levels.last().map_or(0, Vec::len) > 1 {
            let previous = levels.last().expect("one leaf level exists");
            let mut next =
                Vec::with_capacity(previous.len().div_ceil(BROWSER_HARNESS_BUCKET_MERKLE_ARITY));
            for group_start in (0..previous.len()).step_by(BROWSER_HARNESS_BUCKET_MERKLE_ARITY) {
                let mut children = [ZERO_HASH; BROWSER_HARNESS_BUCKET_MERKLE_ARITY];
                let available =
                    (previous.len() - group_start).min(BROWSER_HARNESS_BUCKET_MERKLE_ARITY);
                children[..available]
                    .copy_from_slice(&previous[group_start..group_start + available]);
                next.push(compute_parent_n(&children));
            }
            levels.push(next);
        }
        let root = levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .ok_or_else(|| format!("browser {label} group {group} produced no Merkle root"))?;
        roots.extend_from_slice(&root);

        // With 128 leaves the complete arity-8 tree is small enough to cache,
        // so cache_from_level=0 and no sibling-PIR tables are required.
        tree_tops.push(0);
        let total_nodes = levels.iter().try_fold(0usize, |sum, level| {
            sum.checked_add(level.len())
                .ok_or_else(|| format!("browser {label} Merkle node count overflow"))
        })?;
        tree_tops.extend_from_slice(
            &u32::try_from(total_nodes)
                .map_err(|_| format!("browser {label} Merkle node count exceeds u32"))?
                .to_le_bytes(),
        );
        tree_tops.extend_from_slice(
            &u16::try_from(BROWSER_HARNESS_BUCKET_MERKLE_ARITY)
                .map_err(|_| "browser bucket-Merkle arity exceeds u16".to_owned())?
                .to_le_bytes(),
        );
        tree_tops.push(
            u8::try_from(levels.len())
                .map_err(|_| format!("browser {label} Merkle depth exceeds u8"))?,
        );
        for level in levels {
            tree_tops.extend_from_slice(
                &u32::try_from(level.len())
                    .map_err(|_| format!("browser {label} Merkle level exceeds u32"))?
                    .to_le_bytes(),
            );
            for hash in level {
                tree_tops.extend_from_slice(&hash);
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_browser_database_proof(
    root: &Path,
    harness_root: &Path,
    force: bool,
    index_bytes: &[u8],
    chunk_bytes: &[u8],
    bucket_merkle: &BrowserBucketMerkleArtifactsV1,
    server_db_manifest_toml: &[u8],
    manifest_root: [u8; 32],
    chain_anchor: CoreChainAnchor,
    seeds: SnapshotSeeds,
) -> Result<BrowserDatabaseProofHarnessInventoryV1, String> {
    let proof_root = harness_root.join("synthetic-db-proof");
    let attested_anchor = AttestedChainAnchor {
        block_hash: chain_anchor.block_hash,
        height: chain_anchor.block_height,
    };
    let from_anchor = AttestedChainAnchor {
        block_hash: [0; 32],
        height: 0,
    };
    let params_hash = BuildParamsV1::current_snapshot(
        BROWSER_HARNESS_TINY_BINS_PER_TABLE as u32,
        BROWSER_HARNESS_TINY_BINS_PER_TABLE as u32,
        BROWSER_HARNESS_ONION_ENTRY_SIZE,
    )
    .params_hash();
    let builder_binary_sha256 =
        deterministic_nonzero_32("browser-two-provider/db-proof/synthetic-builder-binary");
    let muhash = deterministic_nonzero_32("browser-two-provider/db-proof/synthetic-muhash");
    let bucket_super_root = bucket_merkle.super_root;
    let onion_super_root =
        deterministic_nonzero_32("browser-two-provider/db-proof/synthetic-onion-root");
    let root_bundle = RootBundlePayload {
        network_magic: MAINNET_NETWORK_MAGIC,
        build_kind: BuildKind::Snapshot,
        from_anchor,
        anchor: attested_anchor,
        utxo_muhash: muhash,
        dust_threshold_sats: 0,
        max_utxos_per_spk: 1,
        params_hash,
        issued_at: FIXTURE_ISSUED_AT as i64,
        roots: vec![
            NamedRoot {
                label: "merkle/bucket/super_root".to_owned(),
                root: bucket_super_root,
            },
            NamedRoot {
                label: "merkle/onion/super_root".to_owned(),
                root: onion_super_root,
            },
        ],
    };
    let root_bundle_payload = root_bundle
        .encode()
        .map_err(|error| format!("encode browser synthetic root bundle: {error}"))?;
    let database_manifest_sha256 = format!("{}\n", hex::encode(manifest_root)).into_bytes();
    let mut artifacts_hasher = Sha256::new();
    artifacts_hasher.update(index_bytes);
    artifacts_hasher.update(chunk_bytes);
    artifacts_hasher.update(&bucket_merkle.tree_tops);
    artifacts_hasher.update(&bucket_merkle.roots);
    artifacts_hasher.update(bucket_merkle.super_root);
    artifacts_hasher.update(server_db_manifest_toml);
    let all_artifacts_manifest_sha256 =
        format!("{}\n", hex::encode(artifacts_hasher.finalize())).into_bytes();
    let mut snapshot_hasher = Sha256::new();
    snapshot_hasher.update(index_bytes);
    snapshot_hasher.update(chunk_bytes);
    let snapshot_sha256: [u8; 32] = snapshot_hasher.finalize().into();
    let evidence = BuildEvidence {
        version: EVIDENCE_VERSION_V1,
        builder_git_commit: BROWSER_HARNESS_BUILDER_GIT_COMMIT.to_owned(),
        builder_binary_sha256,
        tee_platform: "synthetic-report-data-only".to_owned(),
        tee_image_measurement: Vec::new(),
        core_version: "synthetic-no-bitcoin-core".to_owned(),
        snapshot_sha256,
        snapshot_bytes: (index_bytes.len() + chunk_bytes.len()) as u64,
        network_magic: MAINNET_NETWORK_MAGIC,
        build_kind: BuildKind::Snapshot,
        from_anchor,
        anchor: attested_anchor,
        utxo_muhash: muhash,
        dust_threshold_sats: 0,
        max_utxos_per_spk: 1,
        params_hash,
        index_bins_per_table: BROWSER_HARNESS_TINY_BINS_PER_TABLE as u32,
        chunk_bins_per_table: BROWSER_HARNESS_TINY_BINS_PER_TABLE as u32,
        onion_entry_size: BROWSER_HARNESS_ONION_ENTRY_SIZE,
        bucket_super_root,
        onion_super_root,
        root_bundle_payload_sha256: sha256(&root_bundle_payload),
        signed_root_bundle_sha256: None,
        database_manifest_sha256: sha256(&database_manifest_sha256),
        all_artifacts_manifest_sha256: sha256(&all_artifacts_manifest_sha256),
        server_db_manifest_sha256: sha256(server_db_manifest_toml),
        evidence_mode: EvidenceMode::FullBuild,
        predecessor_evidence_sha256: None,
        predecessor_report_sha256: None,
        onion_layout_v2: None,
    };
    let build_evidence = evidence
        .encode()
        .map_err(|error| format!("encode browser synthetic build evidence: {error}"))?;
    let mut synthetic_report = vec![0; SEV_SNP_REPORT_DATA_OFFSET + SEV_SNP_REPORT_DATA_LEN];
    synthetic_report
        [SEV_SNP_REPORT_DATA_OFFSET..SEV_SNP_REPORT_DATA_OFFSET + SEV_SNP_REPORT_DATA_LEN]
        .copy_from_slice(
            &evidence
                .report_data()
                .map_err(|error| format!("bind browser synthetic REPORT_DATA: {error}"))?,
        );
    ProofBundle {
        build_evidence: build_evidence.clone(),
        root_bundle_payload: root_bundle_payload.clone(),
        sev_snp_report: synthetic_report.clone(),
        database_manifest_sha256: database_manifest_sha256.clone(),
        all_artifacts_manifest_sha256: all_artifacts_manifest_sha256.clone(),
        server_db_manifest_toml: server_db_manifest_toml.to_vec(),
    }
    .verify()
    .map_err(|error| format!("self-verify browser synthetic DB proof: {error}"))?;

    for (relative_path, bytes) in [
        ("build-evidence.bin", build_evidence.as_slice()),
        ("root-bundle-payload.bin", root_bundle_payload.as_slice()),
        (
            "build-evidence.sev-snp-report.bin",
            synthetic_report.as_slice(),
        ),
        (
            "database.manifest.sha256",
            database_manifest_sha256.as_slice(),
        ),
        (
            "all-artifacts.manifest.sha256",
            all_artifacts_manifest_sha256.as_slice(),
        ),
        ("server-db/MANIFEST.toml", server_db_manifest_toml),
    ] {
        write_fixture_file(
            root,
            &proof_root.join(relative_path),
            bytes,
            force,
            FixtureFileKind::Public,
        )?;
    }

    Ok(BrowserDatabaseProofHarnessInventoryV1 {
        boundary: "synthetic minimum-length report; verifier checks REPORT_DATA binding only, not AMD SEV-SNP signature, certificate chain, TCB, measurement, or production builder provenance"
            .to_owned(),
        proof_path: relative(root, &proof_root)?,
        db_id: BROWSER_HARNESS_DB_ID,
        build_kind: "snapshot".to_owned(),
        from_height: 0,
        from_block_hash: display_hash_hex(&from_anchor.block_hash),
        height: chain_anchor.block_height,
        block_hash: display_hash_hex(&chain_anchor.block_hash),
        anchor_hex: hex::encode(chain_anchor.to_bytes()),
        index_master_seed_hex: format!("{:016x}", seeds.index_master),
        chunk_master_seed_hex: format!("{:016x}", seeds.chunk_master),
        tag_seed_hex: format!("{:016x}", seeds.index_tag),
        muhash: display_hash_hex(&muhash),
        bucket_super_root: hex::encode(bucket_super_root),
        onion_super_root: hex::encode(onion_super_root),
        onion_entry_size: BROWSER_HARNESS_ONION_ENTRY_SIZE,
        params_hash: hex::encode(params_hash),
        network_magic: hex::encode(MAINNET_NETWORK_MAGIC),
        builder_binary_sha256: hex::encode(builder_binary_sha256),
        builder_git_commit: BROWSER_HARNESS_BUILDER_GIT_COMMIT.to_owned(),
        proof_version: 1,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_fixture_cashu_manifest(
    root: &Path,
    name: &str,
    secrets_root: &Path,
    public_root: &Path,
    force: bool,
    secret_files: &mut Vec<String>,
    public_files: &mut Vec<String>,
) -> Result<(StandardCashuMintManifestV1, PathBuf), String> {
    let mut keys = Vec::new();
    for amount in [1u64, 2, 4, 8, 16] {
        let secret = deterministic_k256_scalar(&format!("{name}/cashu-ecash/{amount}"));
        let parsed = Secp256k1SecretKey::from_slice(&secret)
            .map_err(|_| "deterministic standard Cashu key was invalid".to_owned())?;
        let public_key: [u8; 33] = parsed
            .public_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .map_err(|_| "standard Cashu public key was not compressed".to_owned())?;
        write_fixture_secret(
            root,
            &secrets_root.join(format!("cashu-ecash-denomination-{amount}.key")),
            &secret,
            force,
            secret_files,
        )?;
        keys.push(CashuDenominationKeyV1 { amount, public_key });
    }
    let unit = "sat".to_owned();
    let keyset_id = derive_cashu_keyset_id_v2(&keys, &unit, 0, Some(CASHU_FINAL_EXPIRY))
        .map_err(|error| format!("derive fixture Cashu keyset ID: {error}"))?;
    let keyset = CashuKeysetBindingV1 {
        keyset_id,
        unit: unit.clone(),
        input_fee_ppk: 0,
        final_expiry: Some(CASHU_FINAL_EXPIRY),
        keys,
    };
    let endpoint = if name == "provider-0" {
        "https://cashu-0.fixture.invalid"
    } else {
        "https://cashu-1.fixture.invalid"
    };
    let manifest = StandardCashuMintManifestV1 {
        manifest_epoch: 1,
        mint_endpoint: endpoint.to_owned(),
        leaf_spki_sha256_pins: vec![deterministic_nonzero_32(&format!(
            "{name}/cashu-ecash/leaf-spki-sha256"
        ))],
        unit,
        required_nuts: CashuRequiredNutsV1::required_v1(),
        accepted_input_keysets: vec![keyset.clone()],
        active_output_keyset: keyset,
    };
    let encoded = manifest
        .encode()
        .map_err(|error| format!("encode fixture Cashu manifest: {error}"))?;
    if StandardCashuMintManifestV1::decode(&encoded)
        .map_err(|error| format!("roundtrip fixture Cashu manifest: {error}"))?
        != manifest
    {
        return Err("fixture Cashu manifest roundtrip mismatch".to_owned());
    }
    let mint_id = manifest.mint_id();
    let digest = manifest
        .manifest_digest()
        .map_err(|error| format!("digest fixture Cashu manifest: {error}"))?;
    manifest
        .verify_for(
            &StandardCashuMintExpectationV1 {
                mint_id: &mint_id,
                manifest_digest: &digest,
                mint_endpoint: &manifest.mint_endpoint,
                unit: &manifest.unit,
                accepted_inputs_valid_through: FIXTURE_EXPIRES_AT,
                active_output_valid_through: FIXTURE_EXPIRES_AT
                    + CREDENTIAL_VALIDITY_SECONDS as u64,
            },
            1,
        )
        .map_err(|error| format!("self-verify fixture Cashu manifest: {error}"))?;
    let path = public_root.join("standard-cashu-mint-manifest-v1.bin");
    write_fixture_public(root, &path, &encoded, force, public_files)?;
    Ok((manifest, path))
}

#[allow(clippy::too_many_arguments)]
fn fixture_binding(
    issuer_key: &SigningKey,
    provider_id: [u8; 32],
    scope_id: [u8; 32],
    offer_id: u32,
    scheme: AuthScheme,
    entitlement_profile: u16,
    unit: CredentialUnitV1,
    presentation_limit: u32,
    credential_key_id: Vec<u8>,
    verification_key: Vec<u8>,
) -> Result<CredentialKeyBindingV1, String> {
    fixture_binding_with_limit(
        issuer_key,
        provider_id,
        scope_id,
        offer_id,
        scheme,
        entitlement_profile,
        unit,
        presentation_limit,
        credential_key_id,
        verification_key,
    )
}

#[allow(clippy::too_many_arguments)]
fn fixture_binding_with_limit(
    issuer_key: &SigningKey,
    provider_id: [u8; 32],
    scope_id: [u8; 32],
    offer_id: u32,
    scheme: AuthScheme,
    entitlement_profile: u16,
    unit: CredentialUnitV1,
    presentation_limit: u32,
    credential_key_id: Vec<u8>,
    verification_key: Vec<u8>,
) -> Result<CredentialKeyBindingV1, String> {
    let binding = CredentialKeyBindingV1::sign(
        CredentialKeyBindingClaimsV1 {
            provider_id,
            scope_id,
            offer_id,
            scheme,
            keyset_epoch: 1,
            entitlement_profile,
            unit,
            amount: 1,
            presentation_limit,
            not_before: FIXTURE_ISSUED_AT,
            not_after: BINDING_NOT_AFTER,
            credential_key_id: credential_key_id.clone(),
            verification_key,
        },
        issuer_key,
    )
    .map_err(|error| format!("sign fixture credential binding: {error}"))?;
    binding
        .verify_for(
            &CredentialKeyBindingExpectationV1 {
                issuer_id: &binding.issuer_id,
                provider_id: &provider_id,
                scope_id: &scope_id,
                offer_id,
                scheme,
                minimum_keyset_epoch: 1,
                entitlement_profile,
                presentation_limit,
                credential_key_id: &credential_key_id,
            },
            FIXTURE_NOW,
        )
        .map_err(|error| format!("self-verify fixture credential binding: {error}"))?;
    Ok(binding)
}

fn write_binding(
    root: &Path,
    path: &Path,
    binding: &CredentialKeyBindingV1,
    force: bool,
    public_files: &mut Vec<String>,
) -> Result<(), String> {
    let bytes = binding
        .encode()
        .map_err(|error| format!("encode fixture credential binding: {error}"))?;
    if CredentialKeyBindingV1::decode(&bytes)
        .map_err(|error| format!("roundtrip fixture credential binding: {error}"))?
        != *binding
    {
        return Err("fixture credential binding roundtrip mismatch".to_owned());
    }
    write_fixture_public(root, path, &bytes, force, public_files)
}

fn base_offer(offer_id: u32) -> ServiceOfferV1 {
    ServiceOfferV1 {
        offer_id,
        acquisition: AcquisitionMethod::FreeV1,
        free_mode: FreeModeV1::OpenBestEffort,
        free_quota: 0,
        free_window_seconds: 0,
        free_pow_difficulty_bits: 0,
        priority_class: 100,
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
        minimum_credential_validity_seconds: 1,
        retired_policy_grace_seconds: 0,
        credential_count: 1,
        credential_presentation_limit: 1,
        privacy_leakage: PrivacyLeakageV1::NONE,
    }
}

fn free_offer(offer_id: u32) -> ServiceOfferV1 {
    base_offer(offer_id)
}

fn direct_offer(
    offer_id: u32,
    price_msat: u64,
    issuer_id: [u8; 32],
    key_id: Vec<u8>,
    binding: CredentialKeyBindingV1,
    endpoint: String,
) -> Result<ServiceOfferV1, String> {
    let mut offer = base_offer(offer_id);
    offer.acquisition = AcquisitionMethod::Bolt11V1;
    offer.free_mode = FreeModeV1::NotFree;
    offer.priority_class = 10;
    offer.authorization = AuthScheme::Bolt11DirectReceiptV1;
    offer.price = PriceV1::MilliSatoshi(price_msat);
    offer.issuer_id = issuer_id;
    offer.key_id = key_id;
    offer.credential_binding = Some(binding);
    offer.endpoint = endpoint;
    offer.invoice_expiry_seconds = INVOICE_EXPIRY_SECONDS;
    offer.claim_window_seconds = CLAIM_WINDOW_SECONDS;
    offer.minimum_credential_validity_seconds = CREDENTIAL_VALIDITY_SECONDS;
    offer.retired_policy_grace_seconds = RETIRED_POLICY_GRACE_SECONDS;
    offer.privacy_leakage = PrivacyLeakageV1::from_bits(PrivacyLeakageV1::DIRECT_PAYMENT_TO_SPEND)
        .map_err(|error| format!("direct privacy flags: {error}"))?;
    Ok(offer)
}

fn cashu_ecash_offer(
    offer_id: u32,
    price_sat: u64,
    manifest: StandardCashuMintManifestV1,
) -> Result<ServiceOfferV1, String> {
    let mut offer = base_offer(offer_id);
    offer.acquisition = AcquisitionMethod::CashuEcashV1;
    offer.free_mode = FreeModeV1::NotFree;
    offer.priority_class = 20;
    offer.authorization = AuthScheme::CashuEcashV1;
    offer.verification = VerificationMode::StandardCashuMintOnline;
    offer.price = PriceV1::Cashu {
        unit: manifest.unit.clone(),
        amount: price_sat,
    };
    offer.issuer_id = manifest.mint_id();
    offer.key_id = manifest
        .manifest_digest()
        .map_err(|error| format!("Cashu manifest digest: {error}"))?
        .to_vec();
    offer.endpoint = manifest.mint_endpoint.clone();
    offer.cashu_mint_manifest = Some(manifest);
    offer.minimum_credential_validity_seconds = CREDENTIAL_VALIDITY_SECONDS;
    offer.privacy_leakage = PrivacyLeakageV1::from_bits(
        PrivacyLeakageV1::ISSUER_REDEMPTION_TIMING | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER,
    )
    .map_err(|error| format!("Cashu privacy flags: {error}"))?;
    Ok(offer)
}

fn bat_offer(
    offer_id: u32,
    price_msat: u64,
    issuer_id: [u8; 32],
    key_id: Vec<u8>,
    binding: CredentialKeyBindingV1,
    endpoint: String,
) -> Result<ServiceOfferV1, String> {
    let mut offer = base_offer(offer_id);
    offer.acquisition = AcquisitionMethod::Bolt11V1;
    offer.free_mode = FreeModeV1::NotFree;
    offer.priority_class = 15;
    offer.authorization = AuthScheme::BitcoinPirCashuBatV1;
    offer.price = PriceV1::MilliSatoshi(price_msat);
    offer.issuer_id = issuer_id;
    offer.key_id = key_id;
    offer.credential_binding = Some(binding);
    offer.endpoint = endpoint;
    offer.invoice_expiry_seconds = INVOICE_EXPIRY_SECONDS;
    offer.claim_window_seconds = CLAIM_WINDOW_SECONDS;
    offer.minimum_credential_validity_seconds = CREDENTIAL_VALIDITY_SECONDS;
    offer.retired_policy_grace_seconds = RETIRED_POLICY_GRACE_SECONDS;
    offer.credential_count = ARC_PRESENTATION_LIMIT;
    offer.privacy_leakage = PrivacyLeakageV1::from_bits(
        PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING
            | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER
            | PrivacyLeakageV1::PROVIDER_LOCAL_BEARER,
    )
    .map_err(|error| format!("BAT privacy flags: {error}"))?;
    Ok(offer)
}

fn arc_offer(
    offer_id: u32,
    price_msat: u64,
    issuer_id: [u8; 32],
    key_id: Vec<u8>,
    binding: CredentialKeyBindingV1,
    endpoint: String,
) -> Result<ServiceOfferV1, String> {
    let mut offer = base_offer(offer_id);
    offer.acquisition = AcquisitionMethod::Bolt11V1;
    offer.free_mode = FreeModeV1::NotFree;
    offer.priority_class = 15;
    offer.authorization = AuthScheme::ArcV1Experimental;
    offer.deployment_status = DeploymentStatus::Experimental;
    offer.price = PriceV1::MilliSatoshi(price_msat);
    offer.issuer_id = issuer_id;
    offer.key_id = key_id;
    offer.credential_binding = Some(binding);
    offer.endpoint = endpoint;
    offer.invoice_expiry_seconds = INVOICE_EXPIRY_SECONDS;
    offer.claim_window_seconds = CLAIM_WINDOW_SECONDS;
    offer.minimum_credential_validity_seconds = CREDENTIAL_VALIDITY_SECONDS;
    offer.retired_policy_grace_seconds = RETIRED_POLICY_GRACE_SECONDS;
    offer.credential_presentation_limit = ARC_PRESENTATION_LIMIT;
    offer.privacy_leakage = PrivacyLeakageV1::from_bits(
        PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING
            | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER
            | PrivacyLeakageV1::PROVIDER_LOCAL_BEARER,
    )
    .map_err(|error| format!("ARC privacy flags: {error}"))?;
    Ok(offer)
}

fn fixture_offer(
    method: &str,
    offer_id: u32,
    deployment_status: &str,
    binding_path: Option<&Path>,
    key_id: Option<&[u8]>,
    root: &Path,
) -> FixtureOfferInventoryV1 {
    FixtureOfferInventoryV1 {
        method: method.to_owned(),
        offer_id,
        deployment_status: deployment_status.to_owned(),
        credential_binding_path: binding_path.map(|path| {
            relative(root, path).expect("fixture paths are descendants of their output root")
        }),
        credential_key_id: key_id.map(hex::encode),
    }
}

fn write_fixture_secret(
    root: &Path,
    path: &Path,
    bytes: &[u8],
    force: bool,
    inventory: &mut Vec<String>,
) -> Result<(), String> {
    write_fixture_file(root, path, bytes, force, FixtureFileKind::Secret)?;
    inventory.push(relative(root, path)?);
    Ok(())
}

fn write_fixture_public(
    root: &Path,
    path: &Path,
    bytes: &[u8],
    force: bool,
    inventory: &mut Vec<String>,
) -> Result<(), String> {
    write_fixture_file(root, path, bytes, force, FixtureFileKind::Public)?;
    inventory.push(relative(root, path)?);
    Ok(())
}

#[derive(Clone, Copy)]
enum FixtureFileKind {
    Public,
    Secret,
}

fn write_fixture_file(
    root: &Path,
    path: &Path,
    bytes: &[u8],
    force: bool,
    kind: FixtureFileKind,
) -> Result<(), String> {
    if matches!(kind, FixtureFileKind::Secret) {
        // The shared secret writer requires the final parent to be exactly
        // 0700 and never chmods an existing directory behind the operator's
        // back. Let its descriptor-relative walker create missing secret
        // parents before the fixture's ordinary path inventory checks.
        crate::keygen::prepare_secret_key_parent(path)?;
    }
    prepare_fixture_file_path(root, path, force)?;
    match kind {
        FixtureFileKind::Public => {
            crate::payment_artifact::write_public_artifact(path, bytes, force)
        }
        FixtureFileKind::Secret => crate::keygen::write_secret_bytes_unix(path, bytes),
    }
}

/// Create and validate every directory below the canonical fixture root one
/// component at a time. `create_dir_all` would follow an attacker-controlled
/// symlink already present at an intermediate component.
fn ensure_fixture_directory(root: &Path, directory: &Path) -> Result<(), String> {
    let relative = directory.strip_prefix(root).map_err(|_| {
        format!(
            "{} is not inside canonical fixture root {}",
            directory.display(),
            root.display()
        )
    })?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(format!(
                "{} contains a non-normal fixture path component",
                directory.display()
            ));
        };
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                    return Err(format!(
                        "{} must be a real directory inside the fixture root; nested symlinks are forbidden",
                        current.display()
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&current)
                    .map_err(|error| format!("create {}: {error}", current.display()))?;
                let metadata = std::fs::symlink_metadata(&current)
                    .map_err(|error| format!("inspect {}: {error}", current.display()))?;
                if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                    return Err(format!(
                        "{} did not resolve to a real fixture directory",
                        current.display()
                    ));
                }
            }
            Err(error) => return Err(format!("inspect {}: {error}", current.display())),
        }
    }
    let canonical = std::fs::canonicalize(directory)
        .map_err(|error| format!("canonicalize {}: {error}", directory.display()))?;
    if canonical != directory || !canonical.starts_with(root) {
        return Err(format!(
            "{} escapes canonical fixture root {}",
            directory.display(),
            root.display()
        ));
    }
    Ok(())
}

fn prepare_fixture_file_path(root: &Path, path: &Path, force: bool) -> Result<(), String> {
    if path == root || !path.starts_with(root) {
        return Err(format!(
            "{} is not a file below fixture root {}",
            path.display(),
            root.display()
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no fixture parent directory", path.display()))?;
    ensure_fixture_directory(root, parent)?;
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !force {
                return Err(format!("{} already exists; use --force", path.display()));
            }
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(format!(
                    "{} must be a regular, non-symlink fixture file",
                    path.display()
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() != 1 {
                    return Err(format!(
                        "{} has multiple hard links; --force refuses to overwrite it",
                        path.display()
                    ));
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("inspect {}: {error}", path.display())),
    }
    Ok(())
}

fn relative(root: &Path, path: &Path) -> Result<String, String> {
    let relative = path.strip_prefix(root).map_err(|_| {
        format!(
            "{} is not inside fixture root {}",
            path.display(),
            root.display()
        )
    })?;
    Ok(relative.to_string_lossy().replace('\\', "/"))
}

fn deterministic_digest(label: &str, counter: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BitcoinPIR/payment-v1-no-funds-fixture/v1");
    hasher.update((label.len() as u32).to_le_bytes());
    hasher.update(label.as_bytes());
    hasher.update(counter.to_le_bytes());
    hasher.finalize().into()
}

fn deterministic_ed25519_seed(label: &str) -> [u8; 32] {
    deterministic_digest(label, 0)
}

fn deterministic_nonzero_32(label: &str) -> [u8; 32] {
    for counter in 0..u32::MAX {
        let candidate = deterministic_digest(label, counter);
        if candidate.iter().any(|byte| *byte != 0) {
            return candidate;
        }
    }
    unreachable!("SHA-256 deterministic derivation exhausted")
}

fn deterministic_k256_scalar(label: &str) -> [u8; 32] {
    for counter in 0..u32::MAX {
        let candidate = deterministic_digest(label, counter);
        if Secp256k1SecretKey::from_slice(&candidate).is_ok() {
            return candidate;
        }
    }
    unreachable!("secp256k1 deterministic derivation exhausted")
}

fn deterministic_arc_secret(label: &str) -> Result<[u8; ARC_SECRET_KEY_LEN_V1], String> {
    for attempt in 0..u32::MAX {
        let mut candidate = [0u8; ARC_SECRET_KEY_LEN_V1];
        for component in 0..4u32 {
            let digest = deterministic_digest(&format!("{label}/component-{component}"), attempt);
            let offset = component as usize * 32;
            candidate[offset..offset + 32].copy_from_slice(&digest);
        }
        if ArcSecretKeyV1::from_zeroizing_bytes(vec![1], Zeroizing::new(candidate)).is_ok() {
            return Ok(candidate);
        }
        candidate.zeroize();
    }
    Err("ARC deterministic derivation exhausted".to_owned())
}

fn verify_provider_independence(providers: &[FixtureProviderInventoryV1]) -> Result<(), String> {
    if providers.len() != 2 {
        return Err("fixture must contain exactly two providers".to_owned());
    }
    let left = &providers[0];
    let right = &providers[1];
    for (field, left, right) in [
        ("provider_id", &left.provider_id, &right.provider_id),
        (
            "operator_pubkey",
            &left.operator_pubkey,
            &right.operator_pubkey,
        ),
        (
            "policy_signing_pubkey",
            &left.policy_signing_pubkey,
            &right.policy_signing_pubkey,
        ),
        ("issuer_id", &left.issuer_id, &right.issuer_id),
        ("quote_key_id", &left.quote_key_id, &right.quote_key_id),
        (
            "expected_payee_pubkey",
            &left.expected_payee_pubkey,
            &right.expected_payee_pubkey,
        ),
        ("cashu_mint_id", &left.cashu_mint_id, &right.cashu_mint_id),
    ] {
        if left == right {
            return Err(format!("provider independence failure: shared {field}"));
        }
    }
    for provider in providers {
        if provider.scopes.len() != WORKLOADS.len() {
            return Err(format!("{} does not contain five workloads", provider.name));
        }
        let mut scope_ids = BTreeSet::new();
        let mut offer_ids = BTreeSet::new();
        for scope in &provider.scopes {
            if !scope_ids.insert(&scope.scope_id) || scope.offers.len() != 5 {
                return Err(format!(
                    "{} workload matrix is not independent",
                    provider.name
                ));
            }
            let methods: BTreeSet<_> = scope
                .offers
                .iter()
                .map(|offer| offer.method.as_str())
                .collect();
            if methods
                != BTreeSet::from([
                    "arc-experimental",
                    "bolt11",
                    "cashu-bat",
                    "cashu-ecash",
                    "free",
                ])
            {
                return Err(format!(
                    "{} workload is missing a payment method",
                    provider.name
                ));
            }
            for offer in &scope.offers {
                if !offer_ids.insert(offer.offer_id) {
                    return Err(format!("{} reuses an offer ID", provider.name));
                }
                if offer.method == "arc-experimental" && offer.deployment_status != "experimental" {
                    return Err("ARC fixture offer is not experimental".to_owned());
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::private_tempdir_v1 as private_tempdir;
    use pir_service_protocol::{
        bind_auth_begin_v1, check_standard_cashu_spend_for_offer, AuthBeginV1, Bolt11QuoteIntentV1,
        Bolt11QuoteKeyRollbackGuardV1, HintTransport, OperationStartV1, ServiceProtocolError,
        StandardCashuProofV1, StandardCashuSpendV1, TrustedCatalogResolutionV1,
    };

    fn generate(path: &Path) -> FixtureInventoryV1 {
        run(PaymentFixtureArgs {
            out: path.to_path_buf(),
            acknowledge_deterministic_test_keys: true,
            force: false,
            include_browser_two_provider_harness: false,
        })
        .unwrap();
        serde_json::from_slice(&std::fs::read(path.join("fixture.json")).unwrap()).unwrap()
    }

    fn generate_browser_harness(path: &Path) -> FixtureInventoryV1 {
        run(PaymentFixtureArgs {
            out: path.to_path_buf(),
            acknowledge_deterministic_test_keys: true,
            force: false,
            include_browser_two_provider_harness: true,
        })
        .unwrap();
        serde_json::from_slice(&std::fs::read(path.join("fixture.json")).unwrap()).unwrap()
    }

    fn fixture_cashu_spend(offer: &ServiceOfferV1, parts: &[(u64, &str)]) -> StandardCashuSpendV1 {
        let keyset = &offer
            .cashu_mint_manifest
            .as_ref()
            .expect("test fixture standard-Cashu offer has a signed manifest")
            .accepted_input_keysets[0];
        let proofs = parts
            .iter()
            .map(|(amount, secret)| {
                assert!(
                    keyset.keys.iter().any(|key| key.amount == *amount),
                    "test fixture Cashu amount has no signed denomination"
                );
                let point_secret = deterministic_k256_scalar(&format!(
                    "payment-v1-test-fixture/scope-price/{secret}/{amount}"
                ));
                let point_key = Secp256k1SecretKey::from_slice(&point_secret).unwrap();
                StandardCashuProofV1 {
                    keyset_id: keyset.keyset_id.clone(),
                    amount: *amount,
                    secret: (*secret).to_owned(),
                    c: point_key
                        .public_key()
                        .to_encoded_point(true)
                        .as_bytes()
                        .try_into()
                        .unwrap(),
                }
            })
            .collect();
        StandardCashuSpendV1::new_canonical(proofs).unwrap()
    }

    fn files_below(root: &Path, at: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        let mut entries: Vec<_> = std::fs::read_dir(at)
            .unwrap()
            .map(|entry| entry.unwrap())
            .collect();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                files_below(root, &path, out);
            } else {
                out.push((relative(root, &path).unwrap(), std::fs::read(path).unwrap()));
            }
        }
    }

    #[test]
    fn fixture_is_byte_for_byte_deterministic_and_independent() {
        let first = private_tempdir().unwrap();
        let second = private_tempdir().unwrap();
        let first_root = first.path().join("fixture");
        let second_root = second.path().join("fixture");
        let first_inventory = generate(&first_root);
        let second_inventory = generate(&second_root);
        assert_eq!(first_inventory, second_inventory);
        let mut first_files = Vec::new();
        let mut second_files = Vec::new();
        files_below(&first_root, &first_root, &mut first_files);
        files_below(&second_root, &second_root, &mut second_files);
        assert_eq!(first_files, second_files);
        verify_provider_independence(&first_inventory.providers).unwrap();
    }

    #[test]
    fn fixture_policies_and_all_artifacts_roundtrip() {
        let directory = private_tempdir().unwrap();
        let root = directory.path().join("fixture");
        let inventory = generate(&root);
        assert!(inventory.test_only);
        assert!(inventory.deterministic);
        assert!(!inventory.funds_capable);
        assert_eq!(inventory.network, "regtest");
        let mut all_scope_ids = BTreeSet::new();
        let mut all_bat_keys = BTreeSet::new();
        let mut all_arc_keys = BTreeSet::new();
        let mut provider_receipt_keys = BTreeSet::new();
        let mut all_cashu_denomination_keys = BTreeSet::new();
        for provider in &inventory.providers {
            let policy_bytes = std::fs::read(root.join(&provider.policy_path)).unwrap();
            let policy = ServicePolicyV1::decode(&policy_bytes).unwrap();
            assert_eq!(policy.encode().unwrap(), policy_bytes);
            assert_eq!(policy.scopes.len(), 5);
            assert!(policy.scopes.iter().all(|scope| scope.offers.len() == 5));
            for scope in &policy.scopes {
                assert!(all_scope_ids.insert(scope.scope.scope_id()));
                for offer in &scope.offers {
                    match offer.authorization {
                        AuthScheme::Bolt11DirectReceiptV1 => {
                            provider_receipt_keys.insert(
                                offer
                                    .credential_binding
                                    .as_ref()
                                    .unwrap()
                                    .claims
                                    .verification_key
                                    .clone(),
                            );
                        }
                        AuthScheme::BitcoinPirCashuBatV1 => {
                            assert!(all_bat_keys.insert(
                                offer
                                    .credential_binding
                                    .as_ref()
                                    .unwrap()
                                    .claims
                                    .verification_key
                                    .clone(),
                            ));
                        }
                        AuthScheme::ArcV1Experimental => {
                            assert!(all_arc_keys.insert(
                                offer
                                    .credential_binding
                                    .as_ref()
                                    .unwrap()
                                    .claims
                                    .verification_key
                                    .clone(),
                            ));
                        }
                        AuthScheme::CashuEcashV1 => {
                            for key in &offer
                                .cashu_mint_manifest
                                .as_ref()
                                .unwrap()
                                .active_output_keyset
                                .keys
                            {
                                all_cashu_denomination_keys.insert(key.public_key);
                            }
                        }
                        AuthScheme::FreeV1 => {}
                        AuthScheme::BitcoinPirCashuBatV2 => {
                            panic!("V1 payment fixture must not emit issuer-wide BAT V2 offers")
                        }
                    }
                }
            }

            let quote_bytes = std::fs::read(root.join(&provider.quote_delegation_path)).unwrap();
            assert_eq!(
                Bolt11QuoteKeyDelegationV1::decode(&quote_bytes)
                    .unwrap()
                    .encode()
                    .unwrap(),
                quote_bytes
            );
            let manifest_bytes = std::fs::read(root.join(&provider.cashu_manifest_path)).unwrap();
            assert_eq!(
                StandardCashuMintManifestV1::decode(&manifest_bytes)
                    .unwrap()
                    .encode()
                    .unwrap(),
                manifest_bytes
            );
            for scope in &provider.scopes {
                for offer in &scope.offers {
                    if let Some(path) = &offer.credential_binding_path {
                        let bytes = std::fs::read(root.join(path)).unwrap();
                        assert_eq!(
                            CredentialKeyBindingV1::decode(&bytes)
                                .unwrap()
                                .encode()
                                .unwrap(),
                            bytes
                        );
                    }
                }
            }
        }
        assert_eq!(all_scope_ids.len(), 10);
        assert_eq!(all_bat_keys.len(), 10);
        assert_eq!(all_arc_keys.len(), 10);
        // Receipt keys may be shared across workloads within one provider,
        // but never across independently selected providers.
        assert_eq!(provider_receipt_keys.len(), 2);
        assert_eq!(all_cashu_denomination_keys.len(), 10);
    }

    #[test]
    fn harmony_hint_and_query_use_distinct_test_fixture_scopes_and_exact_prices() {
        // These constants pin deterministic interoperability fixtures only.
        // They are not product pricing or a commercial-policy recommendation.
        const TEST_FIXTURE_HINT_BOLT11_MSAT: u64 = 5_000;
        const TEST_FIXTURE_QUERY_BOLT11_MSAT: u64 = 500;
        const TEST_FIXTURE_HINT_CASHU_SAT: u64 = 5;
        const TEST_FIXTURE_QUERY_CASHU_SAT: u64 = 1;

        let directory = private_tempdir().unwrap();
        let root = directory.path().join("fixture");
        let inventory = generate(&root);
        let provider = &inventory.providers[0];
        let policy =
            ServicePolicyV1::decode(&std::fs::read(root.join(&provider.policy_path)).unwrap())
                .unwrap();
        let provider_id = parse_hex32(&provider.provider_id);
        let policy_verifying_key =
            ed25519_dalek::VerifyingKey::from_bytes(&parse_hex32(&provider.policy_signing_pubkey))
                .unwrap();
        let verified_policy = policy
            .verify_current_for_acquisition(
                &provider_id,
                FIXTURE_NOW,
                &PolicyRollbackGuardV1::initial(),
                &ServicePolicyEpochFloorsV1::initial(),
                &policy_verifying_key,
            )
            .unwrap();

        let hint_scope = policy
            .scopes
            .iter()
            .find(|scope| scope.scope.workload == WorkloadId::HarmonyHintBundleV1)
            .unwrap();
        let query_scope = policy
            .scopes
            .iter()
            .find(|scope| scope.scope.workload == WorkloadId::HarmonyQueryJobV1)
            .unwrap();
        assert_eq!(hint_scope.scope.backend, BackendId::HarmonyPirV2);
        assert_eq!(query_scope.scope.backend, BackendId::HarmonyPirV2);
        assert_ne!(hint_scope.scope.workload, query_scope.scope.workload);
        assert_ne!(
            hint_scope.scope.entitlement_profile,
            query_scope.scope.entitlement_profile
        );
        assert_ne!(hint_scope.scope.scope_id(), query_scope.scope.scope_id());

        let hint_direct = hint_scope
            .offers
            .iter()
            .find(|offer| offer.authorization == AuthScheme::Bolt11DirectReceiptV1)
            .unwrap();
        let query_direct = query_scope
            .offers
            .iter()
            .find(|offer| offer.authorization == AuthScheme::Bolt11DirectReceiptV1)
            .unwrap();
        let hint_direct_verified = verified_policy
            .offer(&hint_scope.scope.scope_id(), hint_direct.offer_id)
            .unwrap();
        let query_direct_verified = verified_policy
            .offer(&query_scope.scope.scope_id(), query_direct.offer_id)
            .unwrap();
        let quote_delegation = Bolt11QuoteKeyDelegationV1::decode(
            &std::fs::read(root.join(&provider.quote_delegation_path)).unwrap(),
        )
        .unwrap();
        let quote_guard = Bolt11QuoteKeyRollbackGuardV1::initial(
            quote_delegation.issuer_id,
            LightningNetworkV1::Regtest,
            quote_delegation.expected_payee_pubkey,
        )
        .unwrap();
        let claim_key = SchnorrSigningKey::from_bytes(&deterministic_k256_scalar(
            "payment-v1-test-fixture/harmony-price/claim",
        ))
        .unwrap();
        let claim_pubkey_xonly: [u8; 32] = claim_key.verifying_key().to_bytes().into();
        let (hint_quote, _) = Bolt11QuoteIntentV1::from_verified_offer_guarded(
            &hint_direct_verified,
            &quote_delegation,
            &quote_guard,
            FIXTURE_NOW,
            claim_pubkey_xonly,
            [0x31; 32],
        )
        .unwrap();
        let (query_quote, _) = Bolt11QuoteIntentV1::from_verified_offer_guarded(
            &query_direct_verified,
            &quote_delegation,
            &quote_guard,
            FIXTURE_NOW,
            claim_pubkey_xonly,
            [0x32; 32],
        )
        .unwrap();
        assert_eq!(hint_quote.exact_amount_msat, TEST_FIXTURE_HINT_BOLT11_MSAT);
        assert_eq!(
            query_quote.exact_amount_msat,
            TEST_FIXTURE_QUERY_BOLT11_MSAT
        );
        assert_ne!(hint_quote.exact_amount_msat, query_quote.exact_amount_msat);
        assert_eq!(hint_quote.scope_id, hint_scope.scope.scope_id());
        assert_eq!(query_quote.scope_id, query_scope.scope.scope_id());
        assert_eq!(
            hint_quote.entitlement_profile,
            hint_scope.scope.entitlement_profile
        );
        assert_eq!(
            query_quote.entitlement_profile,
            query_scope.scope.entitlement_profile
        );
        assert!(hint_quote
            .verify_for_offer_guarded(
                &query_direct_verified,
                &quote_delegation,
                &quote_guard,
                FIXTURE_NOW,
            )
            .is_err());

        let hint_cashu = hint_scope
            .offers
            .iter()
            .find(|offer| offer.authorization == AuthScheme::CashuEcashV1)
            .unwrap();
        let query_cashu = query_scope
            .offers
            .iter()
            .find(|offer| offer.authorization == AuthScheme::CashuEcashV1)
            .unwrap();
        let hint_cashu_verified = verified_policy
            .offer(&hint_scope.scope.scope_id(), hint_cashu.offer_id)
            .unwrap();
        let query_cashu_verified = verified_policy
            .offer(&query_scope.scope.scope_id(), query_cashu.offer_id)
            .unwrap();
        let hint_spend = fixture_cashu_spend(hint_cashu, &[(1, "hint-one"), (4, "hint-four")]);
        let query_spend = fixture_cashu_spend(query_cashu, &[(1, "query-one")]);
        let hint_checked =
            check_standard_cashu_spend_for_offer(&hint_spend, &hint_cashu_verified, FIXTURE_NOW)
                .unwrap();
        let query_checked =
            check_standard_cashu_spend_for_offer(&query_spend, &query_cashu_verified, FIXTURE_NOW)
                .unwrap();
        assert_eq!(hint_checked.policy_price, TEST_FIXTURE_HINT_CASHU_SAT);
        assert_eq!(hint_checked.net_amount, TEST_FIXTURE_HINT_CASHU_SAT);
        assert_eq!(query_checked.policy_price, TEST_FIXTURE_QUERY_CASHU_SAT);
        assert_eq!(query_checked.net_amount, TEST_FIXTURE_QUERY_CASHU_SAT);
        assert_ne!(hint_checked.policy_price, query_checked.policy_price);

        let hint_operation = OperationStartV1::HarmonyHint {
            db_id: 7,
            transport: HintTransport::V2Full,
            session_token: None,
            primary_side: None,
        };
        let query_operation = OperationStartV1::HarmonyQuery { db_id: 7 };
        let hint_resolution = TrustedCatalogResolutionV1::new(
            7,
            hint_scope.scope.backend,
            hint_scope.scope.workload,
            hint_scope.scope.protocol_version,
            hint_scope.scope.dataset.clone(),
            hint_scope.scope.operation_profile,
        );
        let query_resolution = TrustedCatalogResolutionV1::new(
            7,
            query_scope.scope.backend,
            query_scope.scope.workload,
            query_scope.scope.protocol_version,
            query_scope.scope.dataset.clone(),
            query_scope.scope.operation_profile,
        );
        let hint_catalog = |candidate: &OperationStartV1| {
            (candidate == &hint_operation).then(|| hint_resolution.clone())
        };
        let query_catalog = |candidate: &OperationStartV1| {
            (candidate == &query_operation).then(|| query_resolution.clone())
        };
        let hint_capability = AuthBeginV1 {
            policy_digest: verified_policy.policy_digest(),
            scope_id: hint_scope.scope.scope_id(),
            offer_id: hint_cashu.offer_id,
            scheme: hint_cashu.authorization,
            key_id: hint_cashu.key_id.clone(),
            operation: hint_operation.clone(),
            proof: hint_spend.encode().unwrap(),
        };
        bind_auth_begin_v1(&hint_capability, hint_cashu_verified, &hint_catalog, None).unwrap();

        let mut wrong_operation = hint_capability.clone();
        wrong_operation.operation = query_operation.clone();
        assert!(matches!(
            bind_auth_begin_v1(&wrong_operation, hint_cashu_verified, &query_catalog, None,),
            Err(ServiceProtocolError::InvalidValue {
                field: "OperationStartV1.required_service",
                ..
            })
        ));
        assert!(matches!(
            bind_auth_begin_v1(&hint_capability, query_cashu_verified, &hint_catalog, None,),
            Err(ServiceProtocolError::InvalidValue {
                field: "AuthBeginV1.scope_id",
                ..
            })
        ));

        // Even if an attacker rewrites every outer selector, the unchanged
        // five-sat hint bearer is not a one-sat query capability: V1 has no
        // change path, so the method-specific exact-price guard rejects it.
        let mut retagged_hint_spend = hint_capability.clone();
        retagged_hint_spend.scope_id = query_scope.scope.scope_id();
        retagged_hint_spend.offer_id = query_cashu.offer_id;
        retagged_hint_spend.key_id.clone_from(&query_cashu.key_id);
        retagged_hint_spend.operation = query_operation.clone();
        bind_auth_begin_v1(
            &retagged_hint_spend,
            query_cashu_verified,
            &query_catalog,
            None,
        )
        .unwrap();
        assert!(matches!(
            check_standard_cashu_spend_for_offer(&hint_spend, &query_cashu_verified, FIXTURE_NOW,),
            Err(ServiceProtocolError::InvalidValue {
                field: "StandardCashuSpendV1.net_amount",
                reason: "overpayment is forbidden because V1 returns no change",
            })
        ));
    }

    #[test]
    fn optional_browser_harness_is_manifest_bound_and_method_independent() {
        let directory = private_tempdir().unwrap();
        let root = directory.path().join("fixture");
        let inventory = generate_browser_harness(&root);
        let harness = inventory.browser_two_provider_harness.unwrap();
        assert!(harness.boundary.contains("no production identity"));
        assert!(harness.boundary.contains("synthetic DB report"));
        assert!(harness.boundary.contains("real secure-channel DPF query"));
        assert!(harness.boundary.contains("bucket-Merkle preflight"));
        assert!(harness
            .database_proof
            .boundary
            .contains("not AMD SEV-SNP signature"));
        assert_eq!(harness.database_proof.db_id, 0);
        assert_eq!(harness.database_proof.build_kind, "snapshot");
        assert_eq!(harness.database_proof.from_height, 0);
        assert_eq!(harness.database_proof.from_block_hash, "0".repeat(64));
        assert_eq!(harness.database_proof.height, BROWSER_HARNESS_DB_HEIGHT);
        assert_eq!(harness.database_proof.network_magic, "f9beb4d9");
        assert_eq!(harness.database_proof.proof_version, 1);
        assert_eq!(harness.providers.len(), 2);
        assert_eq!(harness.providers[0].offers.len(), 2);
        assert_eq!(harness.providers[1].offers.len(), 2);
        assert_eq!(harness.providers[0].offers[0].variant, "direct-bat");
        assert_eq!(
            harness.providers[0].offers[0].method,
            "bolt11-direct-receipt"
        );
        assert_eq!(
            harness.providers[0].offers[1].variant,
            "free-arc-experimental"
        );
        assert_eq!(harness.providers[0].offers[1].method, "free");
        assert_eq!(harness.providers[0].offers[1].free_mode, "ip-rate-limited");
        assert_eq!(harness.providers[1].offers[0].variant, "direct-bat");
        assert_eq!(harness.providers[1].offers[0].method, "cashu-bat");
        assert_eq!(
            harness.providers[1].offers[1].variant,
            "free-arc-experimental"
        );
        assert_eq!(harness.providers[1].offers[1].method, "arc-experimental");
        assert_eq!(
            harness.providers[1].offers[1].deployment_status,
            "experimental"
        );
        assert_ne!(
            harness.providers[0].provider_id,
            harness.providers[1].provider_id
        );
        assert_ne!(
            harness.providers[0].policy_signing_pubkey,
            harness.providers[1].policy_signing_pubkey
        );
        assert_ne!(
            harness.providers[0].expected_payee_pubkey,
            harness.providers[1].expected_payee_pubkey
        );
        for (index, provider) in harness.providers.iter().enumerate() {
            assert_eq!(provider.issuer_id, inventory.providers[index].issuer_id);
            assert_ne!(provider.issuer_id, provider.provider_id);
            assert_ne!(provider.issuer_id, provider.policy_signing_pubkey);
            assert_ne!(provider.provider_id, provider.policy_signing_pubkey);
        }
        let manifest =
            std::fs::read(root.join(&harness.database_path).join("MANIFEST.toml")).unwrap();
        assert_eq!(hex::encode(sha256(&manifest)), harness.manifest_root);
        let proof = pir_db_attest::ProofDirectory::load_and_verify(
            root.join(&harness.database_proof.proof_path),
        )
        .unwrap();
        assert_eq!(
            std::fs::read(
                root.join(&harness.database_proof.proof_path)
                    .join("server-db/MANIFEST.toml")
            )
            .unwrap(),
            manifest
        );
        assert_eq!(proof.evidence.version, EVIDENCE_VERSION_V1);
        assert_eq!(proof.evidence.build_kind, BuildKind::Snapshot);
        assert_eq!(proof.evidence.anchor.height, BROWSER_HARNESS_DB_HEIGHT);
        let database_path = root.join(&harness.database_path);
        let tree_tops = std::fs::read(database_path.join("merkle_bucket_tree_tops.bin")).unwrap();
        let roots = std::fs::read(database_path.join("merkle_bucket_roots.bin")).unwrap();
        let super_root = std::fs::read(database_path.join("merkle_bucket_root.bin")).unwrap();
        assert_eq!(
            u32::from_le_bytes(tree_tops[..4].try_into().unwrap()) as usize,
            INDEX_PARAMS.k + CHUNK_PARAMS.k
        );
        assert_eq!(tree_tops[4], 0, "tiny fixture must cache the full tree");
        assert_eq!(roots.len(), (INDEX_PARAMS.k + CHUNK_PARAMS.k) * 32);
        assert_eq!(super_root.as_slice(), sha256(&roots).as_slice());
        assert_eq!(
            proof.evidence.bucket_super_root.as_slice(),
            super_root.as_slice()
        );
        let mapped = pir_runtime_core::table::MappedDatabase::load(
            &database_path,
            pir_runtime_core::table::DatabaseDescriptor {
                name: "payment-two-provider-test".to_owned(),
                db_type: pir_runtime_core::table::DatabaseType::Full,
                base_height: 0,
                height: BROWSER_HARNESS_DB_HEIGHT,
                index_params: INDEX_PARAMS,
                chunk_params: CHUNK_PARAMS,
            },
        );
        assert!(mapped.has_bucket_merkle());
        assert!(mapped.bucket_merkle_index_siblings.is_empty());
        assert!(mapped.bucket_merkle_chunk_siblings.is_empty());
        assert_eq!(
            hex::encode(proof.evidence.params_hash),
            harness.database_proof.params_hash
        );
        assert_eq!(
            hex::encode(proof.evidence.builder_binary_sha256),
            harness.database_proof.builder_binary_sha256
        );
        assert_eq!(
            proof.evidence.builder_git_commit,
            harness.database_proof.builder_git_commit
        );
        let config = std::fs::read_to_string(root.join(&harness.database_config_path)).unwrap();
        assert!(config.contains("proof_dir = \"synthetic-db-proof\""));
        assert!(config.contains(&format!("height = {BROWSER_HARNESS_DB_HEIGHT}")));
        for provider in &harness.providers {
            let policy =
                ServicePolicyV1::decode(&std::fs::read(root.join(&provider.policy_path)).unwrap())
                    .unwrap();
            assert_eq!(policy.scopes.len(), 1);
            assert_eq!(policy.scopes[0].offers.len(), 2);
            assert_eq!(
                policy.scopes[0].scope.scope_id(),
                parse_hex32(&provider.scope_id)
            );
            assert_eq!(
                policy.scopes[0]
                    .offers
                    .iter()
                    .map(|offer| offer.offer_id)
                    .collect::<BTreeSet<_>>(),
                provider
                    .offers
                    .iter()
                    .map(|offer| offer.offer_id)
                    .collect::<BTreeSet<_>>()
            );
            assert_eq!(
                policy.scopes[0].scope.dataset,
                DatasetBindingV1::ManifestRoot {
                    root: parse_hex32(&harness.manifest_root),
                }
            );
            if provider.name == "provider-0" {
                let free = policy.scopes[0]
                    .offers
                    .iter()
                    .find(|offer| offer.offer_id == 111)
                    .unwrap();
                assert_eq!(free.free_mode, FreeModeV1::IpRateLimited);
                assert_eq!(free.free_quota, 1);
                assert_eq!(free.free_window_seconds, 3_600);
                assert_eq!(
                    free.privacy_leakage.bits(),
                    PrivacyLeakageV1::IP_RATE_BUCKET
                );
            }
        }
        assert!(harness.providers[0].free_ip_key_path.is_some());
        assert!(harness.providers[0].bat_key_path.is_none());
        assert!(harness.providers[0].arc_key_path.is_none());
        assert!(harness.providers[0].arc_key_id.is_none());
        assert!(harness.providers[1].free_ip_key_path.is_none());
        assert!(harness.providers[1].bat_key_path.is_some());
        assert!(harness.providers[1].arc_key_path.is_some());
        assert!(harness.providers[1].arc_key_id.is_some());
        let free_ip_key =
            std::fs::read(root.join(harness.providers[0].free_ip_key_path.as_ref().unwrap()))
                .unwrap();
        assert_eq!(free_ip_key.len(), 32);
        assert!(free_ip_key.iter().any(|byte| *byte != 0));
        for issuer_key_path in [
            "provider-0/secrets/issuer-root-ed25519.key",
            "provider-0/secrets/quote-ed25519.key",
            "provider-0/secrets/credential-derivation.key",
            "provider-0/secrets/receipt-ed25519.key",
        ] {
            assert_ne!(
                free_ip_key,
                std::fs::read(root.join(issuer_key_path)).unwrap()
            );
        }
        assert_ne!(
            free_ip_key,
            std::fs::read(root.join(harness.providers[1].bat_key_path.as_ref().unwrap())).unwrap()
        );
        assert_ne!(
            free_ip_key,
            std::fs::read(root.join(harness.providers[1].arc_key_path.as_ref().unwrap())).unwrap()
        );
        assert_ne!(
            std::fs::read(root.join(harness.providers[1].bat_key_path.as_ref().unwrap())).unwrap(),
            std::fs::read(
                root.join("provider-1/secrets/workloads/dpf-evaluate-job-v1/cashu-bat.key")
            )
            .unwrap()
        );
        assert_ne!(
            std::fs::read(root.join(harness.providers[1].arc_key_path.as_ref().unwrap())).unwrap(),
            std::fs::read(
                root.join("provider-1/secrets/workloads/dpf-evaluate-job-v1/arc-experimental.key")
            )
            .unwrap()
        );
        assert_ne!(
            harness.providers[1].offers[0].offer_id,
            harness.providers[1].offers[1].offer_id
        );
    }

    fn parse_hex32(value: &str) -> [u8; 32] {
        hex::decode(value).unwrap().try_into().unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn fixture_secret_and_public_permissions_are_strict() {
        use std::os::unix::fs::PermissionsExt;
        let directory = private_tempdir().unwrap();
        let root = directory.path().join("fixture");
        let inventory = generate(&root);
        for provider in &inventory.providers {
            for path in &provider.secret_files {
                let mode = std::fs::metadata(root.join(path))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(mode, 0o600, "secret {path}");
            }
            for path in &provider.public_files {
                let mode = std::fs::metadata(root.join(path))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(mode, 0o644, "public artifact {path}");
            }
        }
        assert_eq!(
            std::fs::metadata(root.join("fixture.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }

    #[test]
    fn fixture_requires_acknowledgement_and_overwrite_flag() {
        let directory = private_tempdir().unwrap();
        let root = directory.path().join("fixture");
        assert!(run(PaymentFixtureArgs {
            out: root.clone(),
            acknowledge_deterministic_test_keys: false,
            force: false,
            include_browser_two_provider_harness: false,
        })
        .unwrap_err()
        .contains("acknowledge"));
        generate(&root);
        assert!(run(PaymentFixtureArgs {
            out: root.clone(),
            acknowledge_deterministic_test_keys: true,
            force: false,
            include_browser_two_provider_harness: false,
        })
        .unwrap_err()
        .contains("already exists"));
        run(PaymentFixtureArgs {
            out: root,
            acknowledge_deterministic_test_keys: true,
            force: true,
            include_browser_two_provider_harness: false,
        })
        .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn force_rejects_nested_directory_symlink_without_writing_outside_root() {
        use std::os::unix::fs::symlink;

        let directory = private_tempdir().unwrap();
        let root = directory.path().join("fixture");
        let outside = directory.path().join("outside");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(root.join("provider-0")).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("sentinel"), b"unchanged").unwrap();
        symlink(&outside, root.join("provider-0/secrets")).unwrap();

        let error = run(PaymentFixtureArgs {
            out: root,
            acknowledge_deterministic_test_keys: true,
            force: true,
            include_browser_two_provider_harness: false,
        })
        .unwrap_err();
        assert!(error.contains("without following symlinks"), "{error}");
        assert_eq!(
            std::fs::read(outside.join("sentinel")).unwrap(),
            b"unchanged"
        );
        assert!(!outside.join("operator-ed25519.key").exists());
    }

    #[cfg(unix)]
    #[test]
    fn force_rejects_hard_link_without_truncating_external_inode() {
        let directory = private_tempdir().unwrap();
        let root = directory.path().join("fixture");
        generate(&root);
        let fixture_secret = root.join("provider-0/secrets/operator-ed25519.key");
        let outside = directory.path().join("outside.key");
        std::fs::write(&outside, b"external sentinel").unwrap();
        std::fs::remove_file(&fixture_secret).unwrap();
        std::fs::hard_link(&outside, &fixture_secret).unwrap();

        let error = run(PaymentFixtureArgs {
            out: root,
            acknowledge_deterministic_test_keys: true,
            force: true,
            include_browser_two_provider_harness: false,
        })
        .unwrap_err();
        assert!(error.contains("multiple hard links"), "{error}");
        assert_eq!(std::fs::read(&outside).unwrap(), b"external sentinel");
    }
}
