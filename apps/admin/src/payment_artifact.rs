//! Offline Payment V1 protocol-artifact builders.
//!
//! These commands never open a socket or invoke a Lightning backend. They
//! construct canonical protocol objects, decode the exact encoded bytes, and
//! verify the decoded object against the operator-supplied expectations before
//! writing anything to disk.

use clap::{Args, Subcommand, ValueEnum};
use ed25519_dalek::VerifyingKey;
use pir_arc_adapter::{arc_public_key_fingerprint_v1, ARC_PUBLIC_KEY_LEN_V1};
use pir_service_protocol::{
    derive_bat_key_id_v1, derive_cashu_keyset_id_v2, free_anonymous_ticket_key_id,
    paid_receipt_key_id, AuthScheme, Bolt11QuoteKeyDelegationV1, CashuDenominationKeyV1,
    CashuKeysetBindingV1, CashuRequiredNutsV1, CredentialKeyBindingClaimsV1,
    CredentialKeyBindingExpectationV1, CredentialKeyBindingV1, CredentialUnitV1,
    IssuerClearingApprovalV1, LightningNetworkV1, ProviderClearingAuthorizationClaimsV1,
    ProviderClearingAuthorizationV1, SettlementModesV1, SettlementRuleV1, SettlementUnitV1,
    StandardCashuMintExpectationV1, StandardCashuMintManifestV1, MAX_CREDENTIAL_KEY_ID_LEN,
};
use serde::Deserialize;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const MAX_MANIFEST_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_CLEARING_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_CLEARING_AUTHORIZATION_BYTES: u64 = 64 * 1024;

#[derive(Args, Debug)]
pub struct PaymentArtifactArgs {
    #[command(subcommand)]
    command: PaymentArtifactCommand,
}

#[derive(Subcommand, Debug)]
enum PaymentArtifactCommand {
    /// Root-sign and self-verify an online BOLT11 quote-key delegation.
    #[command(name = "quote-delegation")]
    QuoteDelegation(QuoteDelegationArgs),
    /// Root-sign and self-verify one provider/scope credential-key binding.
    #[command(name = "credential-binding")]
    CredentialBinding(CredentialBindingArgs),
    /// Build and self-verify a canonical standard Cashu mint manifest.
    #[command(name = "cashu-manifest")]
    CashuManifest(CashuManifestArgs),
    /// Operator-sign and self-verify one production ledger-only provider authorization.
    #[command(name = "clearing-authorization")]
    ClearingAuthorization(ClearingAuthorizationArgs),
    /// Issuer-sign and self-verify one exact provider clearing authorization.
    #[command(name = "clearing-approval")]
    ClearingApproval(ClearingApprovalArgs),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum LightningNetworkArg {
    Bitcoin,
    Testnet,
    Signet,
    Regtest,
}

impl From<LightningNetworkArg> for LightningNetworkV1 {
    fn from(value: LightningNetworkArg) -> Self {
        match value {
            LightningNetworkArg::Bitcoin => Self::Bitcoin,
            LightningNetworkArg::Testnet => Self::Testnet,
            LightningNetworkArg::Signet => Self::Signet,
            LightningNetworkArg::Regtest => Self::Regtest,
        }
    }
}

#[derive(Args, Debug)]
struct QuoteDelegationArgs {
    /// Owner-only 32-byte issuer-root Ed25519 seed.
    #[arg(long)]
    issuer_root_key: PathBuf,
    /// Owner-only 32-byte online quote-signing Ed25519 seed.
    #[arg(long)]
    quote_signing_key: PathBuf,
    #[arg(long, value_enum)]
    network: LightningNetworkArg,
    /// Compressed secp256k1 Lightning payee public key (66 lowercase hex chars).
    #[arg(long)]
    expected_payee_pubkey_hex: String,
    #[arg(long)]
    key_epoch: u64,
    #[arg(long)]
    not_before: u64,
    #[arg(long)]
    not_after: u64,
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    force: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CredentialBindingSchemeArg {
    /// A FreeV1 AnonymousTicket binding. Open free admission has no binding.
    FreeAnonymousTicket,
    Bolt11DirectReceipt,
    CashuBat,
    ArcExperimental,
}

impl CredentialBindingSchemeArg {
    const fn protocol(self) -> AuthScheme {
        match self {
            Self::FreeAnonymousTicket => AuthScheme::FreeV1,
            Self::Bolt11DirectReceipt => AuthScheme::Bolt11DirectReceiptV1,
            Self::CashuBat => AuthScheme::BitcoinPirCashuBatV1,
            Self::ArcExperimental => AuthScheme::ArcV1Experimental,
        }
    }

    const fn unit(self) -> CredentialUnitV1 {
        match self {
            Self::FreeAnonymousTicket | Self::Bolt11DirectReceipt => CredentialUnitV1::Entitlement,
            Self::CashuBat | Self::ArcExperimental => CredentialUnitV1::Auth,
        }
    }
}

#[derive(Args, Debug)]
struct CredentialBindingArgs {
    /// Owner-only 32-byte issuer-root Ed25519 seed.
    #[arg(long)]
    issuer_root_key: PathBuf,
    #[arg(long)]
    provider_id_hex: String,
    #[arg(long)]
    scope_id_hex: String,
    #[arg(long)]
    offer_id: u32,
    #[arg(long, value_enum)]
    scheme: CredentialBindingSchemeArg,
    #[arg(long)]
    keyset_epoch: u64,
    #[arg(long)]
    entitlement_profile: u16,
    /// Defaults to 1, or 4 for experimental ARC.
    #[arg(long)]
    presentation_limit: Option<u32>,
    #[arg(long)]
    not_before: u64,
    #[arg(long)]
    not_after: u64,
    /// Ed25519 (32), compressed secp256k1 (33), or ARC draft-01 (99) bytes.
    #[arg(long)]
    verification_key_hex: String,
    /// Optional ARC key ID. ARC defaults to its public-key fingerprint.
    /// Other schemes always use their protocol-mandated canonical key ID.
    #[arg(long)]
    credential_key_id_hex: Option<String>,
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    force: bool,
}

#[derive(Args, Debug)]
struct CashuManifestArgs {
    /// Strict TOML manifest source. Keyset IDs are always derived, never read.
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    force: bool,
}

#[derive(Args, Debug)]
struct ClearingAuthorizationArgs {
    /// Owner-only 32-byte provider-operator Ed25519 seed.
    #[arg(long)]
    operator_signing_key: PathBuf,
    /// Strict TOML source for one auth-credit, ledger-only authorization.
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    force: bool,
}

#[derive(Args, Debug)]
struct ClearingApprovalArgs {
    /// Canonical operator-signed ProviderClearingAuthorizationV1 bytes.
    #[arg(long)]
    authorization: PathBuf,
    /// Owner-only 32-byte issuer-settlement Ed25519 seed.
    #[arg(long)]
    issuer_settlement_signing_key: PathBuf,
    /// Digest printed by the independently run clearing-authorization ceremony.
    #[arg(long)]
    expected_authorization_digest_hex: String,
    #[arg(long)]
    expected_provider_id_hex: String,
    #[arg(long)]
    expected_issuer_id_hex: String,
    #[arg(long)]
    expected_operator_key_hex: String,
    #[arg(long)]
    minimum_authorization_epoch: u64,
    #[arg(long)]
    approved_at: u64,
    #[arg(long)]
    not_after: u64,
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClearingAuthorizationConfig {
    authorization_id_hex: String,
    authorization_epoch: u64,
    provider_id_hex: String,
    issuer_id_hex: String,
    redeem_endpoint: String,
    redeem_leaf_spki_sha256_pins_hex: Vec<String>,
    settlement_account_id_hex: String,
    clearing_verifying_key_hex: String,
    not_before: u64,
    not_after: u64,
    rules: Vec<LedgerClearingRuleConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerClearingRuleConfig {
    credential_binding_digest_hex: String,
    accepted_value: u64,
    provider_credit: u64,
    issuer_fee: u64,
    denomination_profile: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CashuManifestConfig {
    manifest_epoch: u64,
    mint_endpoint: String,
    /// One or two canonical lowercase leaf-SPKI SHA-256 pins. WebPKI remains
    /// mandatory; two pins are only for a reviewed rotation overlap.
    leaf_spki_sha256_pins_hex: Vec<String>,
    unit: String,
    /// Offer/policy horizon used by the builder's self-verification.
    accepted_inputs_valid_through: u64,
    /// Wallet recovery horizon used by the builder's self-verification.
    active_output_valid_through: u64,
    keysets: Vec<CashuKeysetConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CashuKeysetConfig {
    #[serde(default)]
    active: bool,
    #[serde(default)]
    input_fee_ppk: u32,
    final_expiry: Option<u64>,
    keys: Vec<CashuDenominationKeyConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CashuDenominationKeyConfig {
    amount: u64,
    public_key_hex: String,
}

pub fn run(args: PaymentArtifactArgs) -> Result<(), String> {
    match args.command {
        PaymentArtifactCommand::QuoteDelegation(args) => build_quote_delegation(args),
        PaymentArtifactCommand::CredentialBinding(args) => build_credential_binding(args),
        PaymentArtifactCommand::CashuManifest(args) => build_cashu_manifest(args),
        PaymentArtifactCommand::ClearingAuthorization(args) => build_clearing_authorization(args),
        PaymentArtifactCommand::ClearingApproval(args) => build_clearing_approval(args),
    }
}

fn build_quote_delegation(args: QuoteDelegationArgs) -> Result<(), String> {
    let issuer_key = crate::keygen::read_secret_key(&args.issuer_root_key)?;
    let quote_key = crate::keygen::read_secret_key(&args.quote_signing_key)?;
    let payee = parse_hex_exact::<33>(
        "--expected-payee-pubkey-hex",
        &args.expected_payee_pubkey_hex,
    )?;
    let network = LightningNetworkV1::from(args.network);
    let delegation = Bolt11QuoteKeyDelegationV1::sign(
        network,
        payee,
        args.key_epoch,
        args.not_before,
        args.not_after,
        quote_key.verifying_key().to_bytes(),
        &issuer_key,
    )
    .map_err(|error| format!("construct quote delegation: {error}"))?;
    let encoded = delegation
        .encode()
        .map_err(|error| format!("encode quote delegation: {error}"))?;
    let decoded = Bolt11QuoteKeyDelegationV1::decode(&encoded)
        .map_err(|error| format!("decode generated quote delegation: {error}"))?;
    if decoded != delegation {
        return Err("generated quote delegation did not roundtrip exactly".to_owned());
    }
    let verified_quote_key = decoded
        .verify_for(
            &decoded.issuer_id,
            network,
            &payee,
            args.key_epoch,
            args.not_before,
        )
        .map_err(|error| format!("self-verify quote delegation: {error}"))?;
    if verified_quote_key.to_bytes() != quote_key.verifying_key().to_bytes() {
        return Err("self-verified quote key differs from input key".to_owned());
    }
    write_public_artifact(&args.out, &encoded, args.force)?;
    println!("issuer_id={}", hex::encode(decoded.issuer_id));
    println!("quote_key_id={}", hex::encode(decoded.quote_key_id));
    println!(
        "delegation_digest={}",
        hex::encode(
            decoded
                .delegation_digest()
                .map_err(|error| format!("digest quote delegation: {error}"))?
        )
    );
    println!("out={}", args.out.display());
    Ok(())
}

fn build_credential_binding(args: CredentialBindingArgs) -> Result<(), String> {
    let issuer_key = crate::keygen::read_secret_key(&args.issuer_root_key)?;
    let provider_id = parse_hex_exact::<32>("--provider-id-hex", &args.provider_id_hex)?;
    let scope_id = parse_hex_exact::<32>("--scope-id-hex", &args.scope_id_hex)?;
    let verification_key = parse_hex("--verification-key-hex", &args.verification_key_hex)?;
    let scheme = args.scheme.protocol();
    let presentation_limit = args.presentation_limit.unwrap_or({
        if matches!(args.scheme, CredentialBindingSchemeArg::ArcExperimental) {
            4
        } else {
            1
        }
    });
    let credential_key_id = credential_key_id(
        args.scheme,
        &provider_id,
        &scope_id,
        args.offer_id,
        args.entitlement_profile,
        args.keyset_epoch,
        &verification_key,
        args.credential_key_id_hex.as_deref(),
    )?;
    let binding = CredentialKeyBindingV1::sign(
        CredentialKeyBindingClaimsV1 {
            provider_id,
            scope_id,
            offer_id: args.offer_id,
            scheme,
            keyset_epoch: args.keyset_epoch,
            entitlement_profile: args.entitlement_profile,
            unit: args.scheme.unit(),
            amount: 1,
            presentation_limit,
            not_before: args.not_before,
            not_after: args.not_after,
            credential_key_id: credential_key_id.clone(),
            verification_key,
        },
        &issuer_key,
    )
    .map_err(|error| format!("construct credential binding: {error}"))?;
    let encoded = binding
        .encode()
        .map_err(|error| format!("encode credential binding: {error}"))?;
    let decoded = CredentialKeyBindingV1::decode(&encoded)
        .map_err(|error| format!("decode generated credential binding: {error}"))?;
    if decoded != binding {
        return Err("generated credential binding did not roundtrip exactly".to_owned());
    }
    decoded
        .verify_for(
            &CredentialKeyBindingExpectationV1 {
                issuer_id: &decoded.issuer_id,
                provider_id: &provider_id,
                scope_id: &scope_id,
                offer_id: args.offer_id,
                scheme,
                minimum_keyset_epoch: args.keyset_epoch,
                entitlement_profile: args.entitlement_profile,
                presentation_limit,
                credential_key_id: &credential_key_id,
            },
            args.not_before,
        )
        .map_err(|error| format!("self-verify credential binding: {error}"))?;
    write_public_artifact(&args.out, &encoded, args.force)?;
    println!("issuer_id={}", hex::encode(decoded.issuer_id));
    println!("credential_key_id={}", hex::encode(&credential_key_id));
    println!(
        "binding_digest={}",
        hex::encode(
            decoded
                .binding_digest()
                .map_err(|error| format!("digest credential binding: {error}"))?
        )
    );
    println!("out={}", args.out.display());
    Ok(())
}

fn build_clearing_authorization(args: ClearingAuthorizationArgs) -> Result<(), String> {
    let operator_key = crate::keygen::read_secret_key(&args.operator_signing_key)?;
    let config_bytes = read_bounded_public_file(&args.config, MAX_CLEARING_CONFIG_BYTES)?;
    let config: ClearingAuthorizationConfig = toml::from_str(
        std::str::from_utf8(&config_bytes)
            .map_err(|_| format!("{} is not UTF-8", args.config.display()))?,
    )
    .map_err(|error| format!("parse {}: {error}", args.config.display()))?;
    if config.not_before == 0 || config.authorization_epoch == 0 {
        return Err("clearing authorization epoch and not_before must be non-zero".to_owned());
    }
    let clearing_verifying_key = parse_hex_exact::<32>(
        "clearing_verifying_key_hex",
        &config.clearing_verifying_key_hex,
    )?;
    VerifyingKey::from_bytes(&clearing_verifying_key)
        .map_err(|_| "clearing_verifying_key_hex is not a valid Ed25519 key".to_owned())?;
    if clearing_verifying_key == operator_key.verifying_key().to_bytes() {
        return Err("operator and provider clearing keys must be distinct".to_owned());
    }
    let rules = config
        .rules
        .iter()
        .map(|rule| {
            Ok(SettlementRuleV1 {
                credential_binding_digest: parse_hex_exact::<32>(
                    "credential_binding_digest_hex",
                    &rule.credential_binding_digest_hex,
                )?,
                unit: SettlementUnitV1::AuthCredit,
                accepted_value: rule.accepted_value,
                provider_credit: rule.provider_credit,
                issuer_fee: rule.issuer_fee,
                denomination_profile: rule.denomination_profile,
                settlement_modes: SettlementModesV1::from_bits(SettlementModesV1::LEDGER_CREDIT)
                    .map_err(|error| format!("construct ledger-only settlement mode: {error}"))?,
                blind_output_minimum_validity_seconds: 0,
                blind_output_keyset: None,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let authorization = ProviderClearingAuthorizationV1::sign(
        ProviderClearingAuthorizationClaimsV1 {
            authorization_id: parse_hex_exact::<16>(
                "authorization_id_hex",
                &config.authorization_id_hex,
            )?,
            authorization_epoch: config.authorization_epoch,
            provider_id: parse_hex_exact::<32>("provider_id_hex", &config.provider_id_hex)?,
            issuer_id: parse_hex_exact::<32>("issuer_id_hex", &config.issuer_id_hex)?,
            redeem_endpoint: config.redeem_endpoint,
            redeem_leaf_spki_sha256_pins: config
                .redeem_leaf_spki_sha256_pins_hex
                .iter()
                .map(|pin| parse_hex_exact::<32>("redeem leaf SPKI SHA-256 pin", pin))
                .collect::<Result<Vec<_>, _>>()?,
            settlement_account_id: parse_hex_exact::<32>(
                "settlement_account_id_hex",
                &config.settlement_account_id_hex,
            )?,
            clearing_verifying_key,
            not_before: config.not_before,
            not_after: config.not_after,
            rules,
        },
        &operator_key,
    )
    .map_err(|error| format!("construct provider clearing authorization: {error}"))?;
    let encoded = authorization
        .encode()
        .map_err(|error| format!("encode provider clearing authorization: {error}"))?;
    let decoded = ProviderClearingAuthorizationV1::decode(&encoded)
        .map_err(|error| format!("decode generated provider clearing authorization: {error}"))?;
    if decoded != authorization
        || decoded
            .encode()
            .map_err(|error| format!("re-encode provider clearing authorization: {error}"))?
            != encoded
    {
        return Err("generated provider clearing authorization is not canonical".to_owned());
    }
    decoded
        .verify_for(
            &decoded.claims.provider_id,
            &decoded.claims.issuer_id,
            &operator_key.verifying_key(),
            decoded.claims.not_before,
            config.authorization_epoch,
        )
        .map_err(|error| format!("self-verify provider clearing authorization: {error}"))?;
    ensure_auth_credit_ledger_only(&decoded)?;
    let digest = decoded
        .authorization_digest()
        .map_err(|error| format!("digest provider clearing authorization: {error}"))?;
    write_public_artifact(&args.out, &encoded, args.force)?;
    println!("provider_id={}", hex::encode(decoded.claims.provider_id));
    println!("issuer_id={}", hex::encode(decoded.claims.issuer_id));
    println!(
        "operator_key={}",
        hex::encode(decoded.operator_verifying_key)
    );
    println!(
        "clearing_key={}",
        hex::encode(decoded.claims.clearing_verifying_key)
    );
    println!("authorization_digest={}", hex::encode(digest));
    println!("out={}", args.out.display());
    Ok(())
}

fn build_clearing_approval(args: ClearingApprovalArgs) -> Result<(), String> {
    if args.minimum_authorization_epoch == 0 || args.approved_at == 0 {
        return Err("minimum authorization epoch and approved_at must be non-zero".to_owned());
    }
    let exact = read_bounded_public_file(&args.authorization, MAX_CLEARING_AUTHORIZATION_BYTES)?;
    let authorization = ProviderClearingAuthorizationV1::decode(&exact)
        .map_err(|error| format!("decode provider clearing authorization: {error}"))?;
    if authorization
        .encode()
        .map_err(|error| format!("re-encode provider clearing authorization: {error}"))?
        != exact
    {
        return Err("provider clearing authorization is not canonical".to_owned());
    }
    let expected_digest = parse_hex_exact::<32>(
        "--expected-authorization-digest-hex",
        &args.expected_authorization_digest_hex,
    )?;
    if authorization
        .authorization_digest()
        .map_err(|error| format!("digest provider clearing authorization: {error}"))?
        != expected_digest
    {
        return Err(
            "provider clearing authorization digest does not match ceremony input".to_owned(),
        );
    }
    let expected_provider =
        parse_hex_exact::<32>("--expected-provider-id-hex", &args.expected_provider_id_hex)?;
    let expected_issuer =
        parse_hex_exact::<32>("--expected-issuer-id-hex", &args.expected_issuer_id_hex)?;
    let expected_operator_bytes = parse_hex_exact::<32>(
        "--expected-operator-key-hex",
        &args.expected_operator_key_hex,
    )?;
    let expected_operator = VerifyingKey::from_bytes(&expected_operator_bytes)
        .map_err(|_| "--expected-operator-key-hex is not a valid Ed25519 key".to_owned())?;
    authorization
        .verify_for(
            &expected_provider,
            &expected_issuer,
            &expected_operator,
            args.approved_at,
            args.minimum_authorization_epoch,
        )
        .map_err(|error| format!("verify provider clearing authorization: {error}"))?;
    ensure_auth_credit_ledger_only(&authorization)?;

    let settlement_key = crate::keygen::read_secret_key(&args.issuer_settlement_signing_key)?;
    let settlement_verifying_key = settlement_key.verifying_key().to_bytes();
    if settlement_verifying_key == authorization.operator_verifying_key
        || settlement_verifying_key == authorization.claims.clearing_verifying_key
    {
        return Err(
            "issuer settlement, provider operator, and provider clearing keys must be distinct"
                .to_owned(),
        );
    }
    let approval = IssuerClearingApprovalV1::sign(
        &authorization,
        args.approved_at,
        args.not_after,
        &settlement_key,
    )
    .map_err(|error| format!("construct issuer clearing approval: {error}"))?;
    let encoded = approval.encode();
    let decoded = IssuerClearingApprovalV1::decode(&encoded)
        .map_err(|error| format!("decode generated issuer clearing approval: {error}"))?;
    if decoded != approval || decoded.encode() != encoded {
        return Err("generated issuer clearing approval is not canonical".to_owned());
    }
    decoded
        .verify_for(
            &authorization,
            &settlement_key.verifying_key(),
            args.approved_at,
            args.minimum_authorization_epoch,
        )
        .map_err(|error| format!("self-verify issuer clearing approval: {error}"))?;
    write_public_artifact(&args.out, &encoded, args.force)?;
    println!(
        "authorization_digest={}",
        hex::encode(decoded.authorization_digest)
    );
    println!(
        "issuer_settlement_key_id={}",
        hex::encode(decoded.issuer_settlement_key_id)
    );
    println!("authorization_epoch={}", decoded.authorization_epoch);
    println!("out={}", args.out.display());
    Ok(())
}

fn ensure_auth_credit_ledger_only(
    authorization: &ProviderClearingAuthorizationV1,
) -> Result<(), String> {
    if authorization.claims.rules.is_empty()
        || authorization.claims.rules.iter().any(|rule| {
            rule.unit != SettlementUnitV1::AuthCredit
                || rule.settlement_modes.bits() != SettlementModesV1::LEDGER_CREDIT
                || rule.blind_output_minimum_validity_seconds != 0
                || rule.blind_output_keyset.is_some()
        })
    {
        return Err(
            "production clearing artifacts must contain auth-credit ledger-only rules".to_owned(),
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn credential_key_id(
    scheme: CredentialBindingSchemeArg,
    provider_id: &[u8; 32],
    scope_id: &[u8; 32],
    offer_id: u32,
    entitlement_profile: u16,
    keyset_epoch: u64,
    verification_key: &[u8],
    explicit_key_id_hex: Option<&str>,
) -> Result<Vec<u8>, String> {
    match scheme {
        CredentialBindingSchemeArg::FreeAnonymousTicket
        | CredentialBindingSchemeArg::Bolt11DirectReceipt => {
            if explicit_key_id_hex.is_some() {
                return Err(
                    "--credential-key-id-hex is only accepted for experimental ARC".to_owned(),
                );
            }
            let bytes: [u8; 32] = verification_key.try_into().map_err(|_| {
                "Ed25519 credential verification key must be exactly 32 bytes".to_owned()
            })?;
            let key = VerifyingKey::from_bytes(&bytes)
                .map_err(|_| "invalid Ed25519 credential verification key".to_owned())?;
            Ok(match scheme {
                CredentialBindingSchemeArg::FreeAnonymousTicket => {
                    free_anonymous_ticket_key_id(&key).to_vec()
                }
                CredentialBindingSchemeArg::Bolt11DirectReceipt => {
                    paid_receipt_key_id(&key).to_vec()
                }
                _ => unreachable!(),
            })
        }
        CredentialBindingSchemeArg::CashuBat => {
            if explicit_key_id_hex.is_some() {
                return Err(
                    "--credential-key-id-hex is only accepted for experimental ARC".to_owned(),
                );
            }
            let key: [u8; 33] = verification_key
                .try_into()
                .map_err(|_| "Cashu BAT verification key must be exactly 33 bytes".to_owned())?;
            Ok(derive_bat_key_id_v1(
                provider_id,
                scope_id,
                offer_id,
                entitlement_profile,
                keyset_epoch,
                &key,
            )
            .to_vec())
        }
        CredentialBindingSchemeArg::ArcExperimental => {
            let key: [u8; ARC_PUBLIC_KEY_LEN_V1] = verification_key.try_into().map_err(|_| {
                format!(
                    "experimental ARC verification key must be exactly {ARC_PUBLIC_KEY_LEN_V1} bytes"
                )
            })?;
            let fingerprint = arc_public_key_fingerprint_v1(&key)
                .map_err(|error| format!("invalid experimental ARC public key: {error}"))?;
            match explicit_key_id_hex {
                Some(value) => {
                    let key_id = parse_hex("--credential-key-id-hex", value)?;
                    if key_id.is_empty() || key_id.len() > MAX_CREDENTIAL_KEY_ID_LEN {
                        return Err(format!(
                            "--credential-key-id-hex must encode 1..={MAX_CREDENTIAL_KEY_ID_LEN} bytes"
                        ));
                    }
                    Ok(key_id)
                }
                None => Ok(fingerprint.to_vec()),
            }
        }
    }
}

fn build_cashu_manifest(args: CashuManifestArgs) -> Result<(), String> {
    let config_bytes = read_bounded_public_file(&args.config, MAX_MANIFEST_CONFIG_BYTES)?;
    let config: CashuManifestConfig = toml::from_str(
        std::str::from_utf8(&config_bytes)
            .map_err(|_| format!("{} is not UTF-8", args.config.display()))?,
    )
    .map_err(|error| format!("parse {}: {error}", args.config.display()))?;
    let manifest = manifest_from_config(&config)?;
    let encoded = manifest
        .encode()
        .map_err(|error| format!("encode Cashu manifest: {error}"))?;
    let decoded = StandardCashuMintManifestV1::decode(&encoded)
        .map_err(|error| format!("decode generated Cashu manifest: {error}"))?;
    if decoded != manifest {
        return Err("generated Cashu manifest did not roundtrip exactly".to_owned());
    }
    let digest = decoded
        .manifest_digest()
        .map_err(|error| format!("digest Cashu manifest: {error}"))?;
    let mint_id = decoded.mint_id();
    decoded
        .verify_for(
            &StandardCashuMintExpectationV1 {
                mint_id: &mint_id,
                manifest_digest: &digest,
                mint_endpoint: &config.mint_endpoint,
                unit: &config.unit,
                accepted_inputs_valid_through: config.accepted_inputs_valid_through,
                active_output_valid_through: config.active_output_valid_through,
            },
            config.manifest_epoch,
        )
        .map_err(|error| format!("self-verify Cashu manifest: {error}"))?;
    write_public_artifact(&args.out, &encoded, args.force)?;
    println!("mint_id={}", hex::encode(mint_id));
    println!("manifest_digest={}", hex::encode(digest));
    println!(
        "active_keyset_id={}",
        decoded.active_output_keyset.keyset_id
    );
    println!("out={}", args.out.display());
    Ok(())
}

fn manifest_from_config(
    config: &CashuManifestConfig,
) -> Result<StandardCashuMintManifestV1, String> {
    let active_count = config.keysets.iter().filter(|keyset| keyset.active).count();
    if active_count != 1 {
        return Err(format!(
            "Cashu manifest config must mark exactly one keyset active, found {active_count}"
        ));
    }
    let mut built = Vec::with_capacity(config.keysets.len());
    for keyset in &config.keysets {
        let mut keys = Vec::with_capacity(keyset.keys.len());
        for key in &keyset.keys {
            keys.push(CashuDenominationKeyV1 {
                amount: key.amount,
                public_key: parse_hex_exact::<33>(
                    "Cashu denomination public_key_hex",
                    &key.public_key_hex,
                )?,
            });
        }
        keys.sort_by_key(|key| key.amount);
        let keyset_id = derive_cashu_keyset_id_v2(
            &keys,
            &config.unit,
            keyset.input_fee_ppk,
            keyset.final_expiry,
        )
        .map_err(|error| format!("derive Cashu keyset ID: {error}"))?;
        let binding = CashuKeysetBindingV1 {
            keyset_id,
            unit: config.unit.clone(),
            input_fee_ppk: keyset.input_fee_ppk,
            final_expiry: keyset.final_expiry,
            keys,
        };
        binding
            .validate()
            .map_err(|error| format!("validate Cashu keyset: {error}"))?;
        built.push((keyset.active, binding));
    }
    let active_output_keyset = built
        .iter()
        .find_map(|(active, keyset)| active.then(|| keyset.clone()))
        .ok_or_else(|| "Cashu manifest config has no active keyset".to_owned())?;
    let mut accepted_input_keysets: Vec<_> = built.into_iter().map(|(_, keyset)| keyset).collect();
    accepted_input_keysets.sort_by(|left, right| left.keyset_id.cmp(&right.keyset_id));
    let leaf_spki_sha256_pins = config
        .leaf_spki_sha256_pins_hex
        .iter()
        .map(|value| parse_hex_exact::<32>("Cashu leaf SPKI SHA-256 pin", value))
        .collect::<Result<Vec<_>, _>>()?;
    let manifest = StandardCashuMintManifestV1 {
        manifest_epoch: config.manifest_epoch,
        mint_endpoint: config.mint_endpoint.clone(),
        leaf_spki_sha256_pins,
        unit: config.unit.clone(),
        required_nuts: CashuRequiredNutsV1::required_v1(),
        accepted_input_keysets,
        active_output_keyset,
    };
    // `encode` is the public validation entrypoint for the full manifest.
    manifest
        .encode()
        .map_err(|error| format!("validate Cashu manifest: {error}"))?;
    Ok(manifest)
}

pub(crate) fn parse_hex(name: &str, value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{name} must be canonical lowercase hexadecimal"));
    }
    hex::decode(value).map_err(|error| format!("decode {name}: {error}"))
}

pub(crate) fn parse_hex_exact<const N: usize>(name: &str, value: &str) -> Result<[u8; N], String> {
    let decoded = parse_hex(name, value)?;
    decoded.try_into().map_err(|bytes: Vec<u8>| {
        format!("{name} must encode exactly {N} bytes, got {}", bytes.len())
    })
}

pub(crate) fn read_bounded_public_file(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    #[cfg(unix)]
    let file = {
        use rustix::fs::{self as rustix_fs, FileType, Mode, OFlags};
        let fd = rustix_fs::open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| format!("read {}: {error}", path.display()))?;
        let stat = rustix_fs::fstat(&fd)
            .map_err(|error| format!("inspect {}: {error}", path.display()))?;
        if !FileType::from_raw_mode(stat.st_mode).is_file()
            || stat.st_size < 0
            || stat.st_size as u64 > maximum
        {
            return Err(format!(
                "{} must be a regular file no larger than {maximum} bytes",
                path.display()
            ));
        }
        std::fs::File::from(fd)
    };
    #[cfg(not(unix))]
    let file =
        std::fs::File::open(path).map_err(|error| format!("read {}: {error}", path.display()))?;

    let mut bytes = Vec::new();
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    if bytes.len() as u64 > maximum {
        return Err(format!("{} exceeds {maximum} bytes", path.display()));
    }
    Ok(bytes)
}

pub(crate) fn write_public_artifact(path: &Path, bytes: &[u8], force: bool) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }

    #[cfg(unix)]
    {
        use rustix::fs::{self as rustix_fs, FileType, Mode, OFlags};
        let public_mode = Mode::from_bits_truncate(0o644);
        let create_flags =
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let fd = match rustix_fs::open(path, create_flags, public_mode) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::EXIST) if force => rustix_fs::open(
                path,
                OFlags::WRONLY | OFlags::TRUNC | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| format!("open {}: {error}", path.display()))?,
            Err(rustix::io::Errno::EXIST) => {
                return Err(format!("{} already exists; use --force", path.display()))
            }
            Err(error) => return Err(format!("open {}: {error}", path.display())),
        };
        let stat = rustix_fs::fstat(&fd)
            .map_err(|error| format!("inspect {}: {error}", path.display()))?;
        if !FileType::from_raw_mode(stat.st_mode).is_file()
            || stat.st_uid != rustix::process::geteuid().as_raw()
        {
            return Err(format!(
                "{} must be a regular file owned by the effective user",
                path.display()
            ));
        }
        rustix_fs::fchmod(&fd, public_mode)
            .map_err(|error| format!("set permissions on {}: {error}", path.display()))?;
        let mut file = std::fs::File::from(fd);
        file.write_all(bytes)
            .map_err(|error| format!("write {}: {error}", path.display()))?;
        file.sync_all()
            .map_err(|error| format!("sync {}: {error}", path.display()))?;
    }

    #[cfg(not(unix))]
    {
        if path.exists() && !force {
            return Err(format!("{} already exists; use --force", path.display()));
        }
        std::fs::write(path, bytes)
            .map_err(|error| format!("write {}: {error}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::private_tempdir_v1 as private_tempdir;
    use ed25519_dalek::SigningKey;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::SecretKey;
    use pir_arc_adapter::{ArcSecretKeyV1, ARC_SECRET_KEY_LEN_V1};
    use zeroize::Zeroizing;

    fn point(value: u8) -> String {
        let key = SecretKey::from_slice(&[value; 32]).unwrap();
        hex::encode(key.public_key().to_encoded_point(true).as_bytes())
    }

    fn write_secret(path: &Path, bytes: &[u8]) {
        crate::keygen::write_secret_bytes_unix(path, bytes).unwrap();
    }

    fn clearing_config(
        operator: &SigningKey,
        clearing: &SigningKey,
        authorization_epoch: u64,
    ) -> String {
        assert_ne!(
            operator.verifying_key().to_bytes(),
            clearing.verifying_key().to_bytes()
        );
        format!(
            "authorization_id_hex = \"{}\"\n\
             authorization_epoch = {authorization_epoch}\n\
             provider_id_hex = \"{}\"\n\
             issuer_id_hex = \"{}\"\n\
             redeem_endpoint = \"https://issuer.example\"\n\
             redeem_leaf_spki_sha256_pins_hex = [\"{}\"]\n\
             settlement_account_id_hex = \"{}\"\n\
             clearing_verifying_key_hex = \"{}\"\n\
             not_before = 1700000000\n\
             not_after = 1900000000\n\
             [[rules]]\n\
             credential_binding_digest_hex = \"{}\"\n\
             accepted_value = 10\n\
             provider_credit = 9\n\
             issuer_fee = 1\n\
             denomination_profile = 7\n",
            hex::encode([0x51; 16]),
            hex::encode([0x52; 32]),
            hex::encode([0x53; 32]),
            hex::encode([0x54; 32]),
            hex::encode([0x55; 32]),
            hex::encode(clearing.verifying_key().to_bytes()),
            hex::encode([0x56; 32]),
        )
    }

    #[test]
    fn quote_delegation_command_writes_self_verified_roundtrip() {
        let directory = private_tempdir().unwrap();
        let issuer_path = directory.path().join("issuer.key");
        let quote_path = directory.path().join("quote.key");
        write_secret(&issuer_path, &[11; 32]);
        write_secret(&quote_path, &[12; 32]);
        let payee = SecretKey::from_slice(&[13; 32]).unwrap();
        let out = directory.path().join("delegation.bin");
        build_quote_delegation(QuoteDelegationArgs {
            issuer_root_key: issuer_path,
            quote_signing_key: quote_path,
            network: LightningNetworkArg::Regtest,
            expected_payee_pubkey_hex: hex::encode(
                payee.public_key().to_encoded_point(true).as_bytes(),
            ),
            key_epoch: 7,
            not_before: 1_700_000_000,
            not_after: 1_900_000_000,
            out: out.clone(),
            force: false,
        })
        .unwrap();
        let bytes = std::fs::read(out).unwrap();
        assert_eq!(
            Bolt11QuoteKeyDelegationV1::decode(&bytes)
                .unwrap()
                .encode()
                .unwrap(),
            bytes
        );
    }

    #[test]
    fn clearing_authorization_and_independent_approval_are_canonical_and_self_verified() {
        let directory = private_tempdir().unwrap();
        let operator = SigningKey::from_bytes(&[0x41; 32]);
        let clearing = SigningKey::from_bytes(&[0x42; 32]);
        let settlement = SigningKey::from_bytes(&[0x43; 32]);
        let operator_path = directory.path().join("operator.key");
        let settlement_path = directory.path().join("settlement.key");
        let config_path = directory.path().join("clearing.toml");
        let authorization_path = directory.path().join("authorization.bin");
        let approval_path = directory.path().join("approval.bin");
        write_secret(&operator_path, &operator.to_bytes());
        write_secret(&settlement_path, &settlement.to_bytes());
        std::fs::write(&config_path, clearing_config(&operator, &clearing, 7)).unwrap();

        build_clearing_authorization(ClearingAuthorizationArgs {
            operator_signing_key: operator_path,
            config: config_path,
            out: authorization_path.clone(),
            force: false,
        })
        .unwrap();
        let authorization_bytes = std::fs::read(&authorization_path).unwrap();
        let authorization = ProviderClearingAuthorizationV1::decode(&authorization_bytes).unwrap();
        assert_eq!(authorization.encode().unwrap(), authorization_bytes);
        assert_eq!(
            authorization.claims.clearing_verifying_key,
            clearing.verifying_key().to_bytes()
        );
        let authorization_digest = authorization.authorization_digest().unwrap();

        build_clearing_approval(ClearingApprovalArgs {
            authorization: authorization_path,
            issuer_settlement_signing_key: settlement_path,
            expected_authorization_digest_hex: hex::encode(authorization_digest),
            expected_provider_id_hex: hex::encode(authorization.claims.provider_id),
            expected_issuer_id_hex: hex::encode(authorization.claims.issuer_id),
            expected_operator_key_hex: hex::encode(operator.verifying_key().to_bytes()),
            minimum_authorization_epoch: 7,
            approved_at: 1_700_000_000,
            not_after: 1_900_000_000,
            out: approval_path.clone(),
            force: false,
        })
        .unwrap();
        let approval_bytes = std::fs::read(approval_path).unwrap();
        let approval = IssuerClearingApprovalV1::decode(&approval_bytes).unwrap();
        assert_eq!(approval.encode(), approval_bytes);
        approval
            .verify_for(
                &authorization,
                &settlement.verifying_key(),
                1_700_000_000,
                7,
            )
            .unwrap();
    }

    #[test]
    fn clearing_artifact_builders_reject_key_reuse_unknown_fields_and_swapped_digest() {
        let directory = private_tempdir().unwrap();
        let operator = SigningKey::from_bytes(&[0x61; 32]);
        let clearing = SigningKey::from_bytes(&[0x62; 32]);
        let settlement = SigningKey::from_bytes(&[0x63; 32]);
        let operator_path = directory.path().join("operator.key");
        let settlement_path = directory.path().join("settlement.key");
        write_secret(&operator_path, &operator.to_bytes());
        write_secret(&settlement_path, &settlement.to_bytes());

        let reused_config = directory.path().join("reused.toml");
        std::fs::write(
            &reused_config,
            clearing_config(&clearing, &operator, 1).replace(
                &hex::encode(clearing.verifying_key().to_bytes()),
                &hex::encode(operator.verifying_key().to_bytes()),
            ),
        )
        .unwrap();
        assert!(build_clearing_authorization(ClearingAuthorizationArgs {
            operator_signing_key: operator_path.clone(),
            config: reused_config,
            out: directory.path().join("must-not-exist.bin"),
            force: false,
        })
        .unwrap_err()
        .contains("must be distinct"));

        let unknown_config = directory.path().join("unknown.toml");
        std::fs::write(
            &unknown_config,
            format!(
                "{}\nunreviewed_mode = true\n",
                clearing_config(&operator, &clearing, 1)
            ),
        )
        .unwrap();
        assert!(build_clearing_authorization(ClearingAuthorizationArgs {
            operator_signing_key: operator_path.clone(),
            config: unknown_config,
            out: directory.path().join("must-not-exist-2.bin"),
            force: false,
        })
        .is_err());

        let config_path = directory.path().join("valid.toml");
        let authorization_path = directory.path().join("authorization.bin");
        std::fs::write(&config_path, clearing_config(&operator, &clearing, 3)).unwrap();
        build_clearing_authorization(ClearingAuthorizationArgs {
            operator_signing_key: operator_path,
            config: config_path,
            out: authorization_path.clone(),
            force: false,
        })
        .unwrap();
        let authorization =
            ProviderClearingAuthorizationV1::decode(&std::fs::read(&authorization_path).unwrap())
                .unwrap();
        let error = build_clearing_approval(ClearingApprovalArgs {
            authorization: authorization_path,
            issuer_settlement_signing_key: settlement_path,
            expected_authorization_digest_hex: hex::encode([0x99; 32]),
            expected_provider_id_hex: hex::encode(authorization.claims.provider_id),
            expected_issuer_id_hex: hex::encode(authorization.claims.issuer_id),
            expected_operator_key_hex: hex::encode(operator.verifying_key().to_bytes()),
            minimum_authorization_epoch: 3,
            approved_at: 1_700_000_000,
            not_after: 1_900_000_000,
            out: directory.path().join("must-not-exist-3.bin"),
            force: false,
        })
        .unwrap_err();
        assert!(error.contains("digest does not match"));
    }

    #[test]
    fn credential_binding_command_covers_every_binding_scheme() {
        let directory = private_tempdir().unwrap();
        let issuer_path = directory.path().join("issuer.key");
        write_secret(&issuer_path, &[21; 32]);
        let ed_public = SigningKey::from_bytes(&[22; 32])
            .verifying_key()
            .to_bytes()
            .to_vec();
        let bat_public = SecretKey::from_slice(&[23; 32])
            .unwrap()
            .public_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let mut arc_secret = [0u8; ARC_SECRET_KEY_LEN_V1];
        for component in 0..4 {
            arc_secret[component * 32 + 31] = component as u8 + 1;
        }
        let arc_public = ArcSecretKeyV1::from_zeroizing_bytes(vec![1], Zeroizing::new(arc_secret))
            .unwrap()
            .public_key_bytes()
            .to_vec();
        for (index, scheme, verification_key) in [
            (
                1u32,
                CredentialBindingSchemeArg::FreeAnonymousTicket,
                ed_public.clone(),
            ),
            (
                2,
                CredentialBindingSchemeArg::Bolt11DirectReceipt,
                ed_public.clone(),
            ),
            (3, CredentialBindingSchemeArg::CashuBat, bat_public),
            (4, CredentialBindingSchemeArg::ArcExperimental, arc_public),
        ] {
            let out = directory.path().join(format!("binding-{index}.bin"));
            build_credential_binding(CredentialBindingArgs {
                issuer_root_key: issuer_path.clone(),
                provider_id_hex: hex::encode([31; 32]),
                scope_id_hex: hex::encode([32; 32]),
                offer_id: index,
                scheme,
                keyset_epoch: 1,
                entitlement_profile: 9,
                presentation_limit: None,
                not_before: 1_700_000_000,
                not_after: 1_900_000_000,
                verification_key_hex: hex::encode(verification_key),
                credential_key_id_hex: None,
                out: out.clone(),
                force: false,
            })
            .unwrap();
            let bytes = std::fs::read(out).unwrap();
            assert_eq!(
                CredentialKeyBindingV1::decode(&bytes)
                    .unwrap()
                    .encode()
                    .unwrap(),
                bytes
            );
        }
    }

    #[test]
    fn cashu_manifest_command_parses_toml_and_writes_canonical_bytes() {
        let directory = private_tempdir().unwrap();
        let config = directory.path().join("cashu.toml");
        let source = format!(
            "manifest_epoch = 1\nmint_endpoint = \"https://mint.fixture.invalid\"\nleaf_spki_sha256_pins_hex = [\"{}\"]\nunit = \"sat\"\naccepted_inputs_valid_through = 2000000000\nactive_output_valid_through = 2000000100\n\n[[keysets]]\nactive = true\ninput_fee_ppk = 0\nfinal_expiry = 2000001000\n\n[[keysets.keys]]\namount = 1\npublic_key_hex = \"{}\"\n",
            hex::encode([0x31; 32]),
            point(41)
        );
        std::fs::write(&config, source).unwrap();
        let out = directory.path().join("cashu.bin");
        build_cashu_manifest(CashuManifestArgs {
            config,
            out: out.clone(),
            force: false,
        })
        .unwrap();
        let bytes = std::fs::read(out).unwrap();
        assert_eq!(
            StandardCashuMintManifestV1::decode(&bytes)
                .unwrap()
                .encode()
                .unwrap(),
            bytes
        );
    }

    #[test]
    fn strict_cashu_builder_derives_ids_sorts_and_roundtrips() {
        let config = CashuManifestConfig {
            manifest_epoch: 3,
            mint_endpoint: "https://mint.fixture.invalid".to_owned(),
            leaf_spki_sha256_pins_hex: vec![hex::encode([0x31; 32])],
            unit: "sat".to_owned(),
            accepted_inputs_valid_through: 2_000_000_000,
            active_output_valid_through: 2_000_000_100,
            keysets: vec![CashuKeysetConfig {
                active: true,
                input_fee_ppk: 0,
                final_expiry: Some(2_000_001_000),
                keys: vec![
                    CashuDenominationKeyConfig {
                        amount: 2,
                        public_key_hex: point(2),
                    },
                    CashuDenominationKeyConfig {
                        amount: 1,
                        public_key_hex: point(1),
                    },
                ],
            }],
        };
        let manifest = manifest_from_config(&config).unwrap();
        assert_eq!(manifest.active_output_keyset.keys[0].amount, 1);
        let encoded = manifest.encode().unwrap();
        assert_eq!(
            StandardCashuMintManifestV1::decode(&encoded).unwrap(),
            manifest
        );
    }

    #[test]
    fn strict_cashu_builder_requires_exactly_one_active_keyset() {
        let config = CashuManifestConfig {
            manifest_epoch: 1,
            mint_endpoint: "https://mint.fixture.invalid".to_owned(),
            leaf_spki_sha256_pins_hex: vec![hex::encode([0x31; 32])],
            unit: "sat".to_owned(),
            accepted_inputs_valid_through: 1,
            active_output_valid_through: 1,
            keysets: Vec::new(),
        };
        assert!(manifest_from_config(&config)
            .unwrap_err()
            .contains("exactly one"));
    }

    #[cfg(unix)]
    #[test]
    fn public_artifact_writer_sets_mode_and_rejects_symlink_even_with_force() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let directory = private_tempdir().unwrap();
        let target = directory.path().join("artifact.bin");
        write_public_artifact(&target, b"artifact", false).unwrap();
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o644
        );
        let real = directory.path().join("real.bin");
        std::fs::write(&real, b"unchanged").unwrap();
        let link = directory.path().join("link.bin");
        symlink(&real, &link).unwrap();
        assert!(write_public_artifact(&link, b"bad", true).is_err());
        assert_eq!(std::fs::read(&real).unwrap(), b"unchanged");
    }
}
