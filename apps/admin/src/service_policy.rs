//! Offline service-policy signer and verifier.
//!
//! Pricing is supplied by an explicit TOML file. This tool only translates
//! that policy into the canonical signed V1 wire shape and verifies the exact
//! result before writing it.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use ed25519_dalek::VerifyingKey;
use pir_service_protocol::{
    derive_provider_id, AcquisitionMethod, AuthPaddingClassV1, AuthScheme, BackendId,
    CredentialKeyBindingV1, DatasetBindingV1, DeploymentStatus, EntitlementLimitsV1, FreeModeV1,
    PolicyRollbackGuardV1, PriceV1, PrivacyLeakageV1, ServiceOfferV1, ServicePolicyEpochFloorsV1,
    ServicePolicyV1, ServiceScopePolicyV1, ServiceScopeV1, StandardCashuMintManifestV1,
    VerificationMode, WorkloadId, MAX_CASHU_MINT_MANIFEST_LEN, MAX_CREDENTIAL_BINDING_LEN,
    MAX_SIGNED_POLICY_LEN,
};
use serde::Deserialize;

#[derive(Args, Debug)]
pub struct ServicePolicyArgs {
    #[command(subcommand)]
    command: ServicePolicyCommand,
}

#[derive(Subcommand, Debug)]
enum ServicePolicyCommand {
    /// Sign a declarative TOML policy with a dedicated Ed25519 policy key.
    Sign(SignArgs),
    /// Verify and summarize one exact canonical signed policy.
    Verify(VerifyArgs),
}

#[derive(Args, Debug)]
struct SignArgs {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    policy_signing_key: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    force: bool,
}

#[derive(Args, Debug)]
struct VerifyArgs {
    #[arg(long)]
    policy: PathBuf,
    #[arg(long)]
    policy_signing_key_hex: String,
    #[arg(long)]
    operator_pubkey_hex: String,
    #[arg(long)]
    stable_server_id: String,
    #[arg(long)]
    now_unix: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyConfig {
    operator_pubkey_hex: String,
    stable_server_id: String,
    policy_epoch: u64,
    issued_at: u64,
    expires_at: u64,
    auth_padding_class: String,
    scopes: Vec<ScopeConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeConfig {
    backend: String,
    workload: String,
    protocol_version: u16,
    dataset: DatasetConfig,
    operation_profile: u16,
    entitlement_profile: u16,
    limits: LimitsConfig,
    offers: Vec<OfferConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum DatasetConfig {
    Class { class_id: u16 },
    CatalogEpoch { epoch: u64 },
    ManifestRoot { root_hex: String },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsConfig {
    max_logical_inputs: u16,
    max_frames: u32,
    max_request_bytes: u64,
    max_response_bytes: u64,
    max_wall_time_ms: u32,
    max_concurrent_sockets: u8,
    max_hint_groups: u16,
    max_work_units: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OfferConfig {
    offer_id: u32,
    acquisition: String,
    free_mode: String,
    #[serde(default)]
    free_quota: u32,
    #[serde(default)]
    free_window_seconds: u32,
    #[serde(default)]
    free_pow_difficulty_bits: u8,
    priority_class: u16,
    authorization: String,
    verification: String,
    deployment_status: String,
    price: PriceConfig,
    #[serde(default)]
    issuer_id_hex: Option<String>,
    #[serde(default)]
    key_id_hex: Option<String>,
    #[serde(default)]
    credential_binding_path: Option<PathBuf>,
    #[serde(default)]
    cashu_mint_manifest_path: Option<PathBuf>,
    #[serde(default)]
    endpoint: String,
    #[serde(default)]
    invoice_expiry_seconds: u32,
    #[serde(default)]
    claim_window_seconds: u32,
    minimum_credential_validity_seconds: u32,
    retired_policy_grace_seconds: u32,
    credential_count: u32,
    credential_presentation_limit: u32,
    privacy_leakage_bits: u16,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum PriceConfig {
    Free,
    Msat { amount: u64 },
    Cashu { unit: String, amount: u64 },
}

pub fn run(args: ServicePolicyArgs) -> Result<(), String> {
    match args.command {
        ServicePolicyCommand::Sign(args) => sign(args),
        ServicePolicyCommand::Verify(args) => verify(args),
    }
}

fn sign(args: SignArgs) -> Result<(), String> {
    let config_text = read_utf8_bounded(&args.config, MAX_SIGNED_POLICY_LEN, "policy config")?;
    let config: PolicyConfig = toml::from_str(&config_text)
        .map_err(|error| format!("invalid service-policy TOML: {error}"))?;
    let operator_key = decode_fixed_hex::<32>(&config.operator_pubkey_hex, "operator public key")?;
    VerifyingKey::from_bytes(&operator_key)
        .map_err(|_| "operator public key is not valid Ed25519".to_owned())?;
    validate_stable_server_id(&config.stable_server_id)?;
    let provider_id = derive_provider_id(&operator_key, &config.stable_server_id);
    let policy_key = crate::keygen::read_secret_key(&args.policy_signing_key)?;
    if policy_key.verifying_key().to_bytes() == operator_key {
        return Err(
            "service policy key must be distinct from the operator identity key".to_owned(),
        );
    }
    let base = args.config.parent().unwrap_or_else(|| Path::new("."));
    let scopes = config
        .scopes
        .into_iter()
        .map(|scope| build_scope(scope, provider_id, base))
        .collect::<Result<Vec<_>, _>>()?;
    let padding = match config.auth_padding_class.as_str() {
        "16-kib" => AuthPaddingClassV1::Class16KiB,
        _ => return Err("auth_padding_class must be `16-kib`".to_owned()),
    };
    let policy = ServicePolicyV1::sign(
        provider_id,
        config.policy_epoch,
        config.issued_at,
        config.expires_at,
        padding,
        scopes,
        &policy_key,
    )
    .map_err(|error| format!("service policy validation/signing failed: {error}"))?;
    // Self-verify at the signed start of the window before releasing bytes.
    policy
        .verify_current_for_acquisition(
            &provider_id,
            config.issued_at,
            &PolicyRollbackGuardV1::initial(),
            &ServicePolicyEpochFloorsV1::initial(),
            &policy_key.verifying_key(),
        )
        .map_err(|error| format!("signed service policy did not self-verify: {error}"))?;
    let bytes = policy
        .encode()
        .map_err(|error| format!("service policy encoding failed: {error}"))?;
    write_public_exact(&args.out, &bytes, args.force)?;
    println!("provider_id={}", hex::encode(provider_id));
    println!(
        "policy_signing_key_ed25519={}",
        hex::encode(policy_key.verifying_key().to_bytes())
    );
    println!(
        "policy_digest={}",
        hex::encode(policy.policy_digest().map_err(|error| error.to_string())?)
    );
    println!("policy_epoch={}", policy.policy_epoch);
    Ok(())
}

fn verify(args: VerifyArgs) -> Result<(), String> {
    if args.now_unix == 0 {
        return Err("--now-unix must be non-zero".to_owned());
    }
    validate_stable_server_id(&args.stable_server_id)?;
    let operator_key = decode_fixed_hex::<32>(&args.operator_pubkey_hex, "operator public key")?;
    let policy_key =
        decode_fixed_hex::<32>(&args.policy_signing_key_hex, "service policy public key")?;
    if operator_key == policy_key {
        return Err(
            "service policy key must be distinct from the operator identity key".to_owned(),
        );
    }
    let verifying_key = VerifyingKey::from_bytes(&policy_key)
        .map_err(|_| "service policy public key is not valid Ed25519".to_owned())?;
    let provider_id = derive_provider_id(&operator_key, &args.stable_server_id);
    let bytes = read_public_bounded(&args.policy, MAX_SIGNED_POLICY_LEN, "signed service policy")?;
    let policy = ServicePolicyV1::decode(&bytes)
        .map_err(|error| format!("invalid signed service policy: {error}"))?;
    if policy.encode().map_err(|error| error.to_string())? != bytes {
        return Err("signed service policy is not canonical".to_owned());
    }
    policy
        .verify_current_for_acquisition(
            &provider_id,
            args.now_unix,
            &PolicyRollbackGuardV1::initial(),
            &ServicePolicyEpochFloorsV1::initial(),
            &verifying_key,
        )
        .map_err(|error| format!("service policy verification failed: {error}"))?;
    println!("provider_id={}", hex::encode(provider_id));
    println!("policy_epoch={}", policy.policy_epoch);
    println!(
        "policy_digest={}",
        hex::encode(policy.policy_digest().map_err(|error| error.to_string())?)
    );
    println!("scope_count={}", policy.scopes.len());
    for scope in &policy.scopes {
        println!(
            "scope={} backend={:?} workload={:?} offers={}",
            hex::encode(scope.scope.scope_id()),
            scope.scope.backend,
            scope.scope.workload,
            scope.offers.len()
        );
    }
    Ok(())
}

fn build_scope(
    config: ScopeConfig,
    provider_id: [u8; 32],
    base: &Path,
) -> Result<ServiceScopePolicyV1, String> {
    let backend = parse_backend(&config.backend)?;
    let workload = parse_workload(&config.workload)?;
    let dataset = match config.dataset {
        DatasetConfig::Class { class_id } => DatasetBindingV1::Class { class_id },
        DatasetConfig::CatalogEpoch { epoch } => DatasetBindingV1::CatalogEpoch { epoch },
        DatasetConfig::ManifestRoot { root_hex } => DatasetBindingV1::ManifestRoot {
            root: decode_fixed_hex::<32>(&root_hex, "dataset manifest root")?,
        },
    };
    let scope = ServiceScopeV1 {
        provider_id,
        backend,
        workload,
        protocol_version: config.protocol_version,
        dataset,
        operation_profile: config.operation_profile,
        entitlement_profile: config.entitlement_profile,
    };
    scope
        .validate()
        .map_err(|error| format!("invalid service scope: {error}"))?;
    let offers = config
        .offers
        .into_iter()
        .map(|offer| build_offer(offer, base))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ServiceScopePolicyV1 {
        scope,
        limits: EntitlementLimitsV1 {
            max_logical_inputs: config.limits.max_logical_inputs,
            max_frames: config.limits.max_frames,
            max_request_bytes: config.limits.max_request_bytes,
            max_response_bytes: config.limits.max_response_bytes,
            max_wall_time_ms: config.limits.max_wall_time_ms,
            max_concurrent_sockets: config.limits.max_concurrent_sockets,
            max_hint_groups: config.limits.max_hint_groups,
            max_work_units: config.limits.max_work_units,
        },
        offers,
    })
}

fn build_offer(config: OfferConfig, base: &Path) -> Result<ServiceOfferV1, String> {
    let credential_binding = config
        .credential_binding_path
        .as_ref()
        .map(|path| {
            let bytes = read_public_bounded(
                &resolve_relative(base, path),
                MAX_CREDENTIAL_BINDING_LEN,
                "credential binding",
            )?;
            let value = CredentialKeyBindingV1::decode(&bytes)
                .map_err(|error| format!("invalid credential binding: {error}"))?;
            if value.encode().map_err(|error| error.to_string())? != bytes {
                return Err("credential binding is not canonical".to_owned());
            }
            Ok(value)
        })
        .transpose()?;
    let cashu_mint_manifest = config
        .cashu_mint_manifest_path
        .as_ref()
        .map(|path| {
            let bytes = read_public_bounded(
                &resolve_relative(base, path),
                MAX_CASHU_MINT_MANIFEST_LEN,
                "Cashu mint manifest",
            )?;
            let value = StandardCashuMintManifestV1::decode(&bytes)
                .map_err(|error| format!("invalid Cashu mint manifest: {error}"))?;
            if value.encode().map_err(|error| error.to_string())? != bytes {
                return Err("Cashu mint manifest is not canonical".to_owned());
            }
            Ok(value)
        })
        .transpose()?;
    Ok(ServiceOfferV1 {
        offer_id: config.offer_id,
        acquisition: parse_acquisition(&config.acquisition)?,
        free_mode: parse_free_mode(&config.free_mode)?,
        free_quota: config.free_quota,
        free_window_seconds: config.free_window_seconds,
        free_pow_difficulty_bits: config.free_pow_difficulty_bits,
        priority_class: config.priority_class,
        authorization: parse_authorization(&config.authorization)?,
        verification: parse_verification(&config.verification)?,
        deployment_status: parse_deployment(&config.deployment_status)?,
        price: match config.price {
            PriceConfig::Free => PriceV1::Free,
            PriceConfig::Msat { amount } => PriceV1::MilliSatoshi(amount),
            PriceConfig::Cashu { unit, amount } => PriceV1::Cashu { unit, amount },
        },
        issuer_id: config
            .issuer_id_hex
            .as_deref()
            .map(|value| decode_fixed_hex::<32>(value, "issuer ID"))
            .transpose()?
            .unwrap_or([0; 32]),
        key_id: config
            .key_id_hex
            .as_deref()
            .map(|value| decode_hex(value, "credential key ID"))
            .transpose()?
            .unwrap_or_default(),
        credential_binding,
        cashu_mint_manifest,
        endpoint: config.endpoint,
        invoice_expiry_seconds: config.invoice_expiry_seconds,
        claim_window_seconds: config.claim_window_seconds,
        minimum_credential_validity_seconds: config.minimum_credential_validity_seconds,
        retired_policy_grace_seconds: config.retired_policy_grace_seconds,
        credential_count: config.credential_count,
        credential_presentation_limit: config.credential_presentation_limit,
        privacy_leakage: PrivacyLeakageV1::from_bits(config.privacy_leakage_bits)
            .map_err(|error| format!("invalid privacy leakage flags: {error}"))?,
    })
}

fn parse_backend(value: &str) -> Result<BackendId, String> {
    match value {
        "dpf-pir-v1" => Ok(BackendId::DpfPirV1),
        "harmony-pir-v2" => Ok(BackendId::HarmonyPirV2),
        "onion-pir-v1" => Ok(BackendId::OnionPirV1),
        "tee-oram-v1" => Ok(BackendId::TeeOramV1),
        _ => Err(format!("unknown backend `{value}`")),
    }
}

fn parse_workload(value: &str) -> Result<WorkloadId, String> {
    match value {
        "dpf-evaluate-job-v1" => Ok(WorkloadId::DpfEvaluateJobV1),
        "harmony-hint-bundle-v1" => Ok(WorkloadId::HarmonyHintBundleV1),
        "harmony-query-job-v1" => Ok(WorkloadId::HarmonyQueryJobV1),
        "onion-evaluate-job-v1" => Ok(WorkloadId::OnionEvaluateJobV1),
        "tee-oram-query-v1" => Ok(WorkloadId::TeeOramQueryV1),
        _ => Err(format!("unknown workload `{value}`")),
    }
}

fn parse_acquisition(value: &str) -> Result<AcquisitionMethod, String> {
    match value {
        "free" => Ok(AcquisitionMethod::FreeV1),
        "bolt11" => Ok(AcquisitionMethod::Bolt11V1),
        "cashu-ecash" => Ok(AcquisitionMethod::CashuEcashV1),
        _ => Err(format!("unknown acquisition method `{value}`")),
    }
}

fn parse_free_mode(value: &str) -> Result<FreeModeV1, String> {
    match value {
        "not-free" => Ok(FreeModeV1::NotFree),
        "open-best-effort" => Ok(FreeModeV1::OpenBestEffort),
        "ip-rate-limited" => Ok(FreeModeV1::IpRateLimited),
        "proof-of-work" => Ok(FreeModeV1::ProofOfWork),
        "anonymous-ticket" => Ok(FreeModeV1::AnonymousTicket),
        _ => Err(format!("unknown free mode `{value}`")),
    }
}

fn parse_authorization(value: &str) -> Result<AuthScheme, String> {
    match value {
        "free" => Ok(AuthScheme::FreeV1),
        "bolt11-direct-receipt" => Ok(AuthScheme::Bolt11DirectReceiptV1),
        "cashu-ecash" => Ok(AuthScheme::CashuEcashV1),
        "cashu-bat" => Ok(AuthScheme::BitcoinPirCashuBatV1),
        "arc-experimental" => Ok(AuthScheme::ArcV1Experimental),
        _ => Err(format!("unknown authorization scheme `{value}`")),
    }
}

fn parse_verification(value: &str) -> Result<VerificationMode, String> {
    match value {
        "provider-local" => Ok(VerificationMode::ProviderLocal),
        "shared-issuer-online" => Ok(VerificationMode::SharedIssuerOnline),
        "standard-cashu-mint-online" => Ok(VerificationMode::StandardCashuMintOnline),
        _ => Err(format!("unknown verification mode `{value}`")),
    }
}

fn parse_deployment(value: &str) -> Result<DeploymentStatus, String> {
    match value {
        "stable" => Ok(DeploymentStatus::Stable),
        "experimental" => Ok(DeploymentStatus::Experimental),
        _ => Err(format!("unknown deployment status `{value}`")),
    }
}

fn resolve_relative(base: &Path, value: &Path) -> PathBuf {
    if value.is_absolute() {
        value.to_owned()
    } else {
        base.join(value)
    }
}

fn read_utf8_bounded(path: &Path, max: usize, label: &str) -> Result<String, String> {
    let bytes = read_public_bounded(path, max, label)?;
    String::from_utf8(bytes).map_err(|_| format!("{label} must be UTF-8"))
}

fn read_public_bounded(path: &Path, max: usize, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("read {label} metadata failed: {error}"))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{label} must be a non-symlink regular file"));
    }
    let len = usize::try_from(metadata.len()).map_err(|_| format!("{label} is too large"))?;
    if len == 0 || len > max {
        return Err(format!("{label} size must be within 1..={max}"));
    }
    let bytes = fs::read(path).map_err(|error| format!("read {label} failed: {error}"))?;
    if bytes.len() != len {
        return Err(format!("{label} changed while it was read"));
    }
    Ok(bytes)
}

fn write_public_exact(path: &Path, bytes: &[u8], force: bool) -> Result<(), String> {
    if bytes.is_empty() {
        return Err("refusing to write an empty service policy".to_owned());
    }
    let mut options = fs::OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("open {} failed: {error}", path.display()))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("write {} failed: {error}", path.display()))
}

fn validate_stable_server_id(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        Err("stable server ID must be non-empty, bounded, and contain no controls".to_owned())
    } else {
        Ok(())
    }
}

fn decode_hex(value: &str, label: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{label} must be even-length hex"));
    }
    hex::decode(value).map_err(|_| format!("{label} is invalid hex"))
}

fn decode_fixed_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    let bytes = decode_hex(value, label)?;
    bytes
        .try_into()
        .map_err(|_| format!("{label} must be exactly {N} bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::private_tempdir_v1 as private_tempdir;
    use ed25519_dalek::SigningKey;

    #[test]
    fn free_policy_toml_signs_and_verifies() {
        let directory = private_tempdir().unwrap();
        let key_path = directory.path().join("policy.key");
        let config_path = directory.path().join("policy.toml");
        let output = directory.path().join("policy.bin");
        let policy_key = SigningKey::from_bytes(&[3; 32]);
        crate::keygen::write_secret_key_unix(&key_path, &policy_key.to_bytes()).unwrap();
        let operator = SigningKey::from_bytes(&[4; 32]);
        let config = format!(
            r#"operator_pubkey_hex = "{}"
stable_server_id = "pir-a"
policy_epoch = 1
issued_at = 100
expires_at = 200
auth_padding_class = "16-kib"

[[scopes]]
backend = "dpf-pir-v1"
workload = "dpf-evaluate-job-v1"
protocol_version = 1
operation_profile = 1
entitlement_profile = 2

[scopes.dataset]
kind = "class"
class_id = 1

[scopes.limits]
max_logical_inputs = 1
max_frames = 4
max_request_bytes = 1000
max_response_bytes = 2000
max_wall_time_ms = 1000
max_concurrent_sockets = 1
max_hint_groups = 0
max_work_units = 10

[[scopes.offers]]
offer_id = 1
acquisition = "free"
free_mode = "open-best-effort"
priority_class = 1
authorization = "free"
verification = "provider-local"
deployment_status = "stable"
minimum_credential_validity_seconds = 1
retired_policy_grace_seconds = 0
credential_count = 1
credential_presentation_limit = 1
privacy_leakage_bits = 0

[scopes.offers.price]
kind = "free"
"#,
            hex::encode(operator.verifying_key().to_bytes())
        );
        fs::write(&config_path, config).unwrap();
        sign(SignArgs {
            config: config_path,
            policy_signing_key: key_path,
            out: output.clone(),
            force: false,
        })
        .unwrap();
        let bytes = fs::read(output).unwrap();
        let policy = ServicePolicyV1::decode(&bytes).unwrap();
        assert_eq!(policy.policy_epoch, 1);
        assert_eq!(policy.scopes.len(), 1);
    }
}
