//! Read-only Mainnet Lightning V1 profile lint and live preflight.
//!
//! The live command contacts only local Bitcoin Core and Core Lightning CLIs.
//! It never creates an invoice, pays, mutates a wallet, or accepts Direct
//! receipt, Standard Cashu, or ARC provider entitlements. Shared BAT is the
//! declared issuer product, but this read-only preflight does not acquire one.

use clap::{Args, Subcommand};
use pir_service_protocol::{Bolt11QuoteKeyDelegationV1, LightningNetworkV1};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::lightning_staging::{
    digest_staticbackup_input_v1, read_protected_profile_input_v1,
    validate_pinned_executable_input_v1, CommandRequestV1, CommandRunnerV1, SystemCommandRunnerV1,
};

const PROFILE_SCHEMA_V1: u32 = 2;
const BACKUP_RECEIPT_SCHEMA_V1: u32 = 1;
const MAINNET_GENESIS_V1: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
const MAX_PROFILE_BYTES_V1: usize = 16 * 1024;
const MAX_PROTECTED_INPUT_BYTES_V1: usize = 16 * 1024;
const MAX_COMMAND_TIMEOUT_SECONDS_V1: u64 = 60;
const MAX_HEIGHT_LAG_V1: u64 = 24;
const MAX_BACKUP_AGE_SECONDS_V1: u64 = 7 * 24 * 60 * 60;
const MAX_CHANNELS_V1: usize = 256;

#[derive(Args, Debug)]
pub struct MainnetLightningV1Args {
    #[command(subcommand)]
    command: MainnetLightningV1Command,
}

#[derive(Subcommand, Debug)]
enum MainnetLightningV1Command {
    /// Validate the immutable public profile without contacting either node.
    #[command(name = "lint-profile")]
    LintProfile(MainnetLightningV1ProfileArgs),
    /// Run the read-only local Bitcoin Core and Core Lightning preflight.
    #[command(name = "preflight")]
    Preflight(MainnetLightningV1ProfileArgs),
}

#[derive(Args, Clone, Debug)]
struct MainnetLightningV1ProfileArgs {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    config_protected_parent: PathBuf,
    #[arg(long)]
    config_expected_uid: u32,
    #[arg(long)]
    config_expected_gid: u32,
    #[arg(long)]
    config_reader_expected_uid: u32,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MainnetLightningV1Profile {
    schema_version: u32,
    profile: MainnetProfileNameV1,
    network: MainnetNetworkV1,
    bitcoin_genesis_hash: String,
    bolt11_hrp: Bolt11HrpV1,
    capability: CapabilityV1,
    provider_count: u8,
    bat_lineage_count: u8,
    settlement: SettlementV1,
    payout: PayoutV1,
    direct_receipt: ForbiddenV1,
    standard_cashu: ForbiddenV1,
    arc: ForbiddenV1,
    expected_issuer_id_hex: String,
    expected_payee_node_id_hex: String,
    command_timeout_seconds: u64,
    max_block_height_lag: u64,
    bitcoin: BitcoinConfigV1,
    lightning: LightningConfigV1,
    quote_delegation: ProtectedArtifactV1,
    backup: BackupConfigV1,
    custody: CustodyV1,
    risk: RiskV1,
    operation: ReadOnlyOperationV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
enum MainnetProfileNameV1 {
    #[serde(rename = "mainnet-lightning-v1")]
    MainnetLightningV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
enum MainnetNetworkV1 {
    #[serde(rename = "bitcoin")]
    Bitcoin,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
enum Bolt11HrpV1 {
    #[serde(rename = "lnbc")]
    Mainnet,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
enum CapabilityV1 {
    #[serde(rename = "shared-bat-db0-db1")]
    SharedBatDb0Db1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
enum SettlementV1 {
    #[serde(rename = "ledger-only")]
    LedgerOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
enum PayoutV1 {
    #[serde(rename = "disabled")]
    Disabled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
enum ForbiddenV1 {
    #[serde(rename = "forbidden")]
    Forbidden,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinnedExecutableV1 {
    path: PathBuf,
    protected_parent: PathBuf,
    sha256_hex: String,
    expected_uid: u32,
    expected_gid: u32,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BitcoinConfigV1 {
    cli: PinnedExecutableV1,
    cli_args: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LightningConfigV1 {
    cli: PinnedExecutableV1,
    rpc_socket: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedArtifactV1 {
    path: PathBuf,
    protected_parent: PathBuf,
    expected_uid: u32,
    expected_gid: u32,
    sha256_hex: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupConfigV1 {
    receipt: ProtectedArtifactV1,
    max_age_seconds: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CustodyV1 {
    identity_restore_evidence_sha256: String,
    channel_recovery_restore_evidence_sha256: String,
    datastore_restore_evidence_sha256: String,
    custody_operation_authorized: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RiskV1 {
    max_invoice_msat: u64,
    max_total_exposure_msat: u64,
    max_invoices_per_runtime: u64,
    max_payment_attempts: u8,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadOnlyOperationV1 {
    read_only_node_contact: bool,
    invoice_creation: bool,
    payment_execution: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupReceiptV1 {
    schema_version: u32,
    node_id_hex: String,
    recorded_at_unix: u64,
    staticbackup_digest_hex: String,
    staticbackup_count: usize,
    identity_secret_backup_confirmed: bool,
    channel_state_backup_confirmed: bool,
}

#[derive(Debug, Deserialize)]
struct CoreChainInfoV1 {
    chain: String,
    blocks: u64,
    headers: u64,
    initialblockdownload: bool,
    signet_challenge: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct ClnGetInfoV1 {
    id: String,
    network: String,
    blockheight: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct ClnPeerChannelsV1 {
    channels: Vec<ClnPeerChannelV1>,
}

#[derive(Clone, Debug, Deserialize)]
struct ClnPeerChannelV1 {
    peer_connected: bool,
    state: String,
    short_channel_id: Option<String>,
    private: Option<bool>,
    lost_state: Option<bool>,
    spendable_msat: Option<MsatV1>,
    receivable_msat: Option<MsatV1>,
}

#[derive(Clone, Debug, Deserialize)]
struct ClnListFundsV1 {
    outputs: Vec<ClnOutputV1>,
}

#[derive(Clone, Debug, Deserialize)]
struct ClnOutputV1 {
    amount_msat: MsatV1,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum MsatV1 {
    Integer(u64),
    Object { msat: u64 },
    Text(String),
}

impl MsatV1 {
    fn value(&self) -> Option<u64> {
        match self {
            Self::Integer(value) | Self::Object { msat: value } => Some(*value),
            Self::Text(value) => value.strip_suffix("msat")?.parse().ok(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClnStaticBackupV1 {
    scb: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MainnetProfileFailureV1 {
    check: &'static str,
    reason: &'static str,
}

impl MainnetProfileFailureV1 {
    fn new(check: &'static str, reason: &'static str) -> Self {
        Self { check, reason }
    }
}

impl fmt::Display for MainnetProfileFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "result=FAIL check={} reason={}",
            self.check, self.reason
        )
    }
}

pub async fn run(args: MainnetLightningV1Args) -> Result<(), MainnetProfileFailureV1> {
    match args.command {
        MainnetLightningV1Command::LintProfile(args) => {
            let profile = read_profile_v1(&args)?;
            validate_profile_v1(&profile)?;
            println!(
                "schema_version=2 phase=lint network=bitcoin capability=shared-bat-db0-db1 providers=2 bat_lineages=12 settlement=ledger-only payout=disabled direct_receipt=forbidden standard_cashu=forbidden arc=forbidden result=PASS"
            );
            Ok(())
        }
        MainnetLightningV1Command::Preflight(args) => {
            let profile = read_profile_v1(&args)?;
            validate_profile_v1(&profile)?;
            validate_runtime_artifacts_v1(&profile)?;
            let delegation_bytes = read_artifact_v1(
                &profile.quote_delegation,
                args.config_reader_expected_uid,
                "delegation.file",
            )?;
            let receipt_bytes = read_artifact_v1(
                &profile.backup.receipt,
                args.config_reader_expected_uid,
                "backup.receipt-file",
            )?;
            let receipt_text = std::str::from_utf8(&receipt_bytes)
                .map_err(|_| MainnetProfileFailureV1::new("backup.receipt", "invalid-utf8"))?;
            let receipt: BackupReceiptV1 = toml::from_str(receipt_text)
                .map_err(|_| MainnetProfileFailureV1::new("backup.receipt", "invalid-toml"))?;
            let now_unix = unix_time_now_v1()?;
            let mut runner = SystemCommandRunnerV1;
            let success =
                run_live_preflight_v1(&profile, &delegation_bytes, &receipt, now_unix, &mut runner)
                    .await?;
            println!(
                "schema_version=2 phase=live network=bitcoin bitcoin_height={} cln_height={} active_public_inbound_channels={} staticbackup_entries={} backup_age_seconds={} result=PASS",
                success.bitcoin_height,
                success.cln_height,
                success.active_public_inbound_channels,
                success.staticbackup_count,
                success.backup_age_seconds,
            );
            Ok(())
        }
    }
}

fn read_profile_v1(
    args: &MainnetLightningV1ProfileArgs,
) -> Result<MainnetLightningV1Profile, MainnetProfileFailureV1> {
    let bytes = read_protected_profile_input_v1(
        &args.config,
        &args.config_protected_parent,
        args.config_expected_uid,
        args.config_expected_gid,
        args.config_reader_expected_uid,
    )
    .map_err(|_| MainnetProfileFailureV1::new("profile.path", "protected-input-rejected"))?;
    if bytes.len() > MAX_PROFILE_BYTES_V1 {
        return Err(MainnetProfileFailureV1::new("profile.path", "oversize"));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| MainnetProfileFailureV1::new("profile.parse", "invalid-utf8"))?;
    toml::from_str(text).map_err(|_| MainnetProfileFailureV1::new("profile.parse", "invalid-toml"))
}

fn validate_profile_v1(profile: &MainnetLightningV1Profile) -> Result<(), MainnetProfileFailureV1> {
    if profile.schema_version != PROFILE_SCHEMA_V1 {
        return Err(MainnetProfileFailureV1::new(
            "profile.schema",
            "unsupported-version",
        ));
    }
    if profile.profile != MainnetProfileNameV1::MainnetLightningV1
        || profile.network != MainnetNetworkV1::Bitcoin
        || !profile
            .bitcoin_genesis_hash
            .eq_ignore_ascii_case(MAINNET_GENESIS_V1)
        || profile.bolt11_hrp != Bolt11HrpV1::Mainnet
    {
        return Err(MainnetProfileFailureV1::new(
            "profile.network",
            "not-exact-mainnet",
        ));
    }
    if profile.capability != CapabilityV1::SharedBatDb0Db1
        || profile.provider_count != 2
        || profile.bat_lineage_count != 12
    {
        return Err(MainnetProfileFailureV1::new(
            "profile.capability",
            "not-shared-bat-two-provider-twelve-lineage",
        ));
    }
    if profile.settlement != SettlementV1::LedgerOnly || profile.payout != PayoutV1::Disabled {
        return Err(MainnetProfileFailureV1::new(
            "profile.clearing",
            "not-ledger-only-no-payout",
        ));
    }
    if profile.direct_receipt != ForbiddenV1::Forbidden
        || profile.standard_cashu != ForbiddenV1::Forbidden
        || profile.arc != ForbiddenV1::Forbidden
    {
        return Err(MainnetProfileFailureV1::new(
            "profile.methods",
            "direct-receipt-standard-cashu-or-arc-enabled",
        ));
    }
    decode_hex_exact_v1::<32>(
        &profile.expected_issuer_id_hex,
        "profile.issuer",
        "invalid-issuer-id",
    )?;
    decode_node_id_v1(&profile.expected_payee_node_id_hex, "profile.payee")?;
    if !(1..=MAX_COMMAND_TIMEOUT_SECONDS_V1).contains(&profile.command_timeout_seconds)
        || profile.max_block_height_lag > MAX_HEIGHT_LAG_V1
        || profile.backup.max_age_seconds == 0
        || profile.backup.max_age_seconds > MAX_BACKUP_AGE_SECONDS_V1
    {
        return Err(MainnetProfileFailureV1::new(
            "profile.bounds",
            "out-of-range",
        ));
    }
    validate_bitcoin_cli_args_v1(&profile.bitcoin.cli_args)?;
    validate_absolute_path_v1(&profile.lightning.rpc_socket, "profile.lightning-socket")?;
    for executable in [&profile.bitcoin.cli, &profile.lightning.cli] {
        validate_absolute_path_v1(&executable.path, "profile.cli")?;
        validate_absolute_path_v1(&executable.protected_parent, "profile.cli")?;
        decode_hex_exact_v1::<32>(&executable.sha256_hex, "profile.cli", "invalid-hash-pin")?;
    }
    for artifact in [&profile.quote_delegation, &profile.backup.receipt] {
        validate_absolute_path_v1(&artifact.path, "profile.artifact")?;
        validate_absolute_path_v1(&artifact.protected_parent, "profile.artifact")?;
        decode_hex_exact_v1::<32>(&artifact.sha256_hex, "profile.artifact", "invalid-hash-pin")?;
    }
    for digest in [
        &profile.custody.identity_restore_evidence_sha256,
        &profile.custody.channel_recovery_restore_evidence_sha256,
        &profile.custody.datastore_restore_evidence_sha256,
    ] {
        decode_hex_exact_v1::<32>(digest, "profile.custody", "invalid-evidence-digest")?;
    }
    if profile.custody.custody_operation_authorized {
        return Err(MainnetProfileFailureV1::new(
            "profile.custody",
            "operation-authorization-not-accepted",
        ));
    }
    if profile.risk.max_invoice_msat == 0
        || profile.risk.max_total_exposure_msat == 0
        || profile.risk.max_invoices_per_runtime == 0
        || profile.risk.max_payment_attempts != 1
    {
        return Err(MainnetProfileFailureV1::new(
            "profile.risk",
            "invalid-nonzero-risk-envelope",
        ));
    }
    let bounded_invoice_exposure = profile
        .risk
        .max_invoice_msat
        .checked_mul(profile.risk.max_invoices_per_runtime)
        .ok_or_else(|| MainnetProfileFailureV1::new("profile.risk", "exposure-overflow"))?;
    if bounded_invoice_exposure > profile.risk.max_total_exposure_msat {
        return Err(MainnetProfileFailureV1::new(
            "profile.risk",
            "invoice-envelope-exceeds-exposure",
        ));
    }
    if !profile.operation.read_only_node_contact
        || profile.operation.invoice_creation
        || profile.operation.payment_execution
    {
        return Err(MainnetProfileFailureV1::new(
            "profile.operation",
            "not-read-only-preflight",
        ));
    }
    Ok(())
}

fn validate_runtime_artifacts_v1(
    profile: &MainnetLightningV1Profile,
) -> Result<(), MainnetProfileFailureV1> {
    for executable in [&profile.bitcoin.cli, &profile.lightning.cli] {
        validate_pinned_executable_input_v1(
            &executable.path,
            &executable.protected_parent,
            &executable.sha256_hex,
            executable.expected_uid,
            executable.expected_gid,
        )
        .map_err(|_| MainnetProfileFailureV1::new("binary.pin", "pinned-executable-rejected"))?;
    }
    Ok(())
}

fn read_artifact_v1(
    artifact: &ProtectedArtifactV1,
    reader_uid: u32,
    check: &'static str,
) -> Result<Vec<u8>, MainnetProfileFailureV1> {
    let bytes = read_protected_profile_input_v1(
        &artifact.path,
        &artifact.protected_parent,
        artifact.expected_uid,
        artifact.expected_gid,
        reader_uid,
    )
    .map_err(|_| MainnetProfileFailureV1::new(check, "protected-input-rejected"))?;
    if bytes.is_empty() || bytes.len() > MAX_PROTECTED_INPUT_BYTES_V1 {
        return Err(MainnetProfileFailureV1::new(check, "invalid-size"));
    }
    let expected = decode_hex_exact_v1::<32>(&artifact.sha256_hex, check, "invalid-hash-pin")?;
    let actual: [u8; 32] = Sha256::digest(&bytes).into();
    if actual != expected {
        return Err(MainnetProfileFailureV1::new(check, "hash-mismatch"));
    }
    Ok(bytes)
}

#[derive(Debug)]
struct PreflightSuccessV1 {
    bitcoin_height: u64,
    cln_height: u64,
    active_public_inbound_channels: usize,
    staticbackup_count: usize,
    backup_age_seconds: u64,
}

async fn run_live_preflight_v1<R: CommandRunnerV1>(
    profile: &MainnetLightningV1Profile,
    delegation_bytes: &[u8],
    receipt: &BackupReceiptV1,
    now_unix: u64,
    runner: &mut R,
) -> Result<PreflightSuccessV1, MainnetProfileFailureV1> {
    let expected_payee = decode_node_id_v1(&profile.expected_payee_node_id_hex, "profile.payee")?;
    let expected_issuer = decode_hex_exact_v1::<32>(
        &profile.expected_issuer_id_hex,
        "profile.issuer",
        "invalid-issuer-id",
    )?;
    let delegation = Bolt11QuoteKeyDelegationV1::decode(delegation_bytes)
        .map_err(|_| MainnetProfileFailureV1::new("delegation.decode", "invalid-delegation"))?;
    delegation
        .verify_for(
            &expected_issuer,
            LightningNetworkV1::Bitcoin,
            &expected_payee,
            delegation.key_epoch,
            now_unix,
        )
        .map_err(|_| {
            MainnetProfileFailureV1::new("delegation.verify", "not-authentic-live-mainnet-payee")
        })?;

    let timeout = Duration::from_secs(profile.command_timeout_seconds);
    let chain: CoreChainInfoV1 = run_core_json_v1(
        runner,
        profile,
        "rpc.core.getblockchaininfo",
        &["getblockchaininfo"],
        timeout,
    )
    .await?;
    let genesis_bytes = run_core_bytes_v1(
        runner,
        profile,
        "rpc.core.getblockhash",
        &["getblockhash", "0"],
        timeout,
    )
    .await?;
    let genesis = std::str::from_utf8(&genesis_bytes)
        .map_err(|_| MainnetProfileFailureV1::new("core.genesis", "invalid-utf8"))?
        .trim();
    validate_core_snapshot_v1(profile, &chain, genesis)?;

    let getinfo: ClnGetInfoV1 =
        run_cln_json_v1(runner, profile, "rpc.cln.getinfo", &["getinfo"], timeout).await?;
    let peer_channels: ClnPeerChannelsV1 = run_cln_json_v1(
        runner,
        profile,
        "rpc.cln.listpeerchannels",
        &["listpeerchannels"],
        timeout,
    )
    .await?;
    let funds: ClnListFundsV1 = run_cln_json_v1(
        runner,
        profile,
        "rpc.cln.listfunds",
        &["listfunds"],
        timeout,
    )
    .await?;
    let staticbackup: ClnStaticBackupV1 = run_cln_json_v1(
        runner,
        profile,
        "rpc.cln.staticbackup",
        &["staticbackup"],
        timeout,
    )
    .await?;
    let live_payee = decode_node_id_v1(&getinfo.id, "lightning.identity")?;
    if getinfo.network != "bitcoin" || live_payee != expected_payee {
        return Err(MainnetProfileFailureV1::new(
            "lightning.identity",
            "network-or-payee-mismatch",
        ));
    }
    let cln_lag = chain.blocks.abs_diff(getinfo.blockheight);
    if cln_lag > profile.max_block_height_lag {
        return Err(MainnetProfileFailureV1::new(
            "lightning.height",
            "core-cln-height-mismatch",
        ));
    }
    let (scb_digest, scb_count) =
        digest_staticbackup_input_v1(&staticbackup.scb, false).map_err(|_| {
            MainnetProfileFailureV1::new("lightning.staticbackup", "invalid-staticbackup")
        })?;
    let backup_age_seconds = validate_backup_receipt_v1(
        receipt,
        &live_payee,
        scb_digest,
        scb_count,
        profile.backup.max_age_seconds,
        now_unix,
    )?;
    let active_public_inbound_channels =
        validate_custody_v1(profile, &peer_channels, &funds, scb_count)?;
    Ok(PreflightSuccessV1 {
        bitcoin_height: chain.blocks,
        cln_height: getinfo.blockheight,
        active_public_inbound_channels,
        staticbackup_count: scb_count,
        backup_age_seconds,
    })
}

fn validate_core_snapshot_v1(
    profile: &MainnetLightningV1Profile,
    chain: &CoreChainInfoV1,
    genesis: &str,
) -> Result<(), MainnetProfileFailureV1> {
    if chain.chain != "main" || chain.signet_challenge.is_some() {
        return Err(MainnetProfileFailureV1::new("core.chain", "not-mainnet"));
    }
    if !genesis.eq_ignore_ascii_case(MAINNET_GENESIS_V1)
        || !genesis.eq_ignore_ascii_case(&profile.bitcoin_genesis_hash)
    {
        return Err(MainnetProfileFailureV1::new(
            "core.genesis",
            "mainnet-genesis-mismatch",
        ));
    }
    if chain.initialblockdownload
        || chain.headers < chain.blocks
        || chain.headers - chain.blocks > profile.max_block_height_lag
    {
        return Err(MainnetProfileFailureV1::new("core.sync", "not-synced"));
    }
    Ok(())
}

fn validate_backup_receipt_v1(
    receipt: &BackupReceiptV1,
    live_payee: &[u8; 33],
    scb_digest: [u8; 32],
    scb_count: usize,
    max_age_seconds: u64,
    now_unix: u64,
) -> Result<u64, MainnetProfileFailureV1> {
    if receipt.schema_version != BACKUP_RECEIPT_SCHEMA_V1
        || !receipt.identity_secret_backup_confirmed
        || !receipt.channel_state_backup_confirmed
    {
        return Err(MainnetProfileFailureV1::new(
            "backup.receipt",
            "invalid-or-unconfirmed",
        ));
    }
    let receipt_node = decode_node_id_v1(&receipt.node_id_hex, "backup.receipt")?;
    let receipt_digest = decode_hex_exact_v1::<32>(
        &receipt.staticbackup_digest_hex,
        "backup.receipt",
        "invalid-staticbackup-digest",
    )?;
    if &receipt_node != live_payee
        || receipt_digest != scb_digest
        || receipt.staticbackup_count != scb_count
    {
        return Err(MainnetProfileFailureV1::new(
            "backup.receipt",
            "current-node-or-staticbackup-mismatch",
        ));
    }
    let age = now_unix
        .checked_sub(receipt.recorded_at_unix)
        .ok_or_else(|| MainnetProfileFailureV1::new("backup.receipt", "future-timestamp"))?;
    if age > max_age_seconds {
        return Err(MainnetProfileFailureV1::new(
            "backup.receipt",
            "stale-receipt",
        ));
    }
    Ok(age)
}

fn validate_custody_v1(
    profile: &MainnetLightningV1Profile,
    peer_channels: &ClnPeerChannelsV1,
    funds: &ClnListFundsV1,
    scb_count: usize,
) -> Result<usize, MainnetProfileFailureV1> {
    if peer_channels.channels.is_empty()
        || peer_channels.channels.len() > MAX_CHANNELS_V1
        || scb_count != peer_channels.channels.len()
    {
        return Err(MainnetProfileFailureV1::new(
            "custody.channels",
            "channel-or-staticbackup-count-mismatch",
        ));
    }
    let mut active_public_inbound = 0usize;
    let mut exposure_msat = 0u64;
    for channel in &peer_channels.channels {
        if !channel.peer_connected
            || channel.state != "CHANNELD_NORMAL"
            || channel.short_channel_id.is_none()
            || channel.private.unwrap_or(true)
            || channel.lost_state.unwrap_or(false)
        {
            return Err(MainnetProfileFailureV1::new(
                "custody.channels",
                "non-public-inactive-or-unsafe-channel",
            ));
        }
        let spendable = channel
            .spendable_msat
            .as_ref()
            .and_then(MsatV1::value)
            .ok_or_else(|| MainnetProfileFailureV1::new("custody.exposure", "invalid-msat"))?;
        let receivable = channel
            .receivable_msat
            .as_ref()
            .and_then(MsatV1::value)
            .ok_or_else(|| MainnetProfileFailureV1::new("custody.liquidity", "invalid-msat"))?;
        exposure_msat = exposure_msat
            .checked_add(spendable)
            .ok_or_else(|| MainnetProfileFailureV1::new("custody.exposure", "overflow"))?;
        if receivable >= profile.risk.max_invoice_msat {
            active_public_inbound += 1;
        }
    }
    for output in &funds.outputs {
        exposure_msat =
            exposure_msat
                .checked_add(output.amount_msat.value().ok_or_else(|| {
                    MainnetProfileFailureV1::new("custody.exposure", "invalid-msat")
                })?)
                .ok_or_else(|| MainnetProfileFailureV1::new("custody.exposure", "overflow"))?;
    }
    if active_public_inbound == 0 {
        return Err(MainnetProfileFailureV1::new(
            "custody.liquidity",
            "insufficient-public-inbound-liquidity",
        ));
    }
    if exposure_msat > profile.risk.max_total_exposure_msat {
        return Err(MainnetProfileFailureV1::new(
            "custody.exposure",
            "maximum-exposure-exceeded",
        ));
    }
    Ok(active_public_inbound)
}

async fn run_core_bytes_v1<R: CommandRunnerV1>(
    runner: &mut R,
    profile: &MainnetLightningV1Profile,
    check: &'static str,
    tail: &[&str],
    timeout: Duration,
) -> Result<Vec<u8>, MainnetProfileFailureV1> {
    let mut args: Vec<OsString> = profile
        .bitcoin
        .cli_args
        .iter()
        .map(OsString::from)
        .collect();
    args.extend(tail.iter().map(OsString::from));
    runner
        .execute(CommandRequestV1 {
            program: profile.bitcoin.cli.path.clone(),
            args,
            timeout,
        })
        .await
        .map_err(|failure| MainnetProfileFailureV1::new(check, failure.label()))
}

async fn run_core_json_v1<R: CommandRunnerV1, T: for<'de> Deserialize<'de>>(
    runner: &mut R,
    profile: &MainnetLightningV1Profile,
    check: &'static str,
    tail: &[&str],
    timeout: Duration,
) -> Result<T, MainnetProfileFailureV1> {
    let bytes = run_core_bytes_v1(runner, profile, check, tail, timeout).await?;
    serde_json::from_slice(&bytes).map_err(|_| MainnetProfileFailureV1::new(check, "invalid-json"))
}

async fn run_cln_json_v1<R: CommandRunnerV1, T: for<'de> Deserialize<'de>>(
    runner: &mut R,
    profile: &MainnetLightningV1Profile,
    check: &'static str,
    tail: &[&str],
    timeout: Duration,
) -> Result<T, MainnetProfileFailureV1> {
    let socket = profile
        .lightning
        .rpc_socket
        .to_str()
        .ok_or_else(|| MainnetProfileFailureV1::new(check, "invalid-socket-path"))?;
    let mut args = vec![
        OsString::from("--network=bitcoin"),
        OsString::from(format!("--rpc-file={socket}")),
        OsString::from("--notifications=none"),
    ];
    args.extend(tail.iter().map(OsString::from));
    let bytes = runner
        .execute(CommandRequestV1 {
            program: profile.lightning.cli.path.clone(),
            args,
            timeout,
        })
        .await
        .map_err(|failure| MainnetProfileFailureV1::new(check, failure.label()))?;
    serde_json::from_slice(&bytes).map_err(|_| MainnetProfileFailureV1::new(check, "invalid-json"))
}

fn validate_bitcoin_cli_args_v1(args: &[String]) -> Result<(), MainnetProfileFailureV1> {
    if args.is_empty() || args.len() > 16 {
        return Err(MainnetProfileFailureV1::new(
            "profile.bitcoin-cli-args",
            "invalid-arguments",
        ));
    }
    let mut selects_main = false;
    let mut seen = std::collections::BTreeSet::new();
    for arg in args {
        if arg.is_empty()
            || arg.len() > 4096
            || !arg.starts_with('-')
            || !arg.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        {
            return Err(MainnetProfileFailureV1::new(
                "profile.bitcoin-cli-args",
                "invalid-argument",
            ));
        }
        let lower = arg.to_ascii_lowercase();
        let key = if lower == "-chain=main" {
            selects_main = true;
            "network"
        } else if let Some(path) = arg.strip_prefix("-datadir=") {
            validate_cli_path_v1(path)?;
            "datadir"
        } else if let Some(path) = arg.strip_prefix("-rpccookiefile=") {
            validate_cli_path_v1(path)?;
            "rpccookiefile"
        } else if let Some(host) = lower.strip_prefix("-rpcconnect=") {
            if !matches!(host, "127.0.0.1" | "::1" | "[::1]") {
                return Err(MainnetProfileFailureV1::new(
                    "profile.bitcoin-cli-args",
                    "non-local-rpc-target",
                ));
            }
            "rpcconnect"
        } else if let Some(port) = lower.strip_prefix("-rpcport=") {
            if port.parse::<u16>().ok().filter(|port| *port != 0).is_none() {
                return Err(MainnetProfileFailureV1::new(
                    "profile.bitcoin-cli-args",
                    "invalid-rpc-port",
                ));
            }
            "rpcport"
        } else {
            return Err(MainnetProfileFailureV1::new(
                "profile.bitcoin-cli-args",
                "forbidden-argument",
            ));
        };
        if !seen.insert(key) {
            return Err(MainnetProfileFailureV1::new(
                "profile.bitcoin-cli-args",
                "duplicate-argument",
            ));
        }
    }
    if !selects_main {
        return Err(MainnetProfileFailureV1::new(
            "profile.bitcoin-cli-args",
            "missing-explicit-mainnet-selector",
        ));
    }
    Ok(())
}

fn validate_cli_path_v1(value: &str) -> Result<(), MainnetProfileFailureV1> {
    validate_absolute_path_v1(Path::new(value), "profile.bitcoin-cli-args")
}

fn validate_absolute_path_v1(
    path: &Path,
    check: &'static str,
) -> Result<(), MainnetProfileFailureV1> {
    if !path.is_absolute()
        || path.as_os_str().to_str().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(MainnetProfileFailureV1::new(check, "invalid-path"));
    }
    Ok(())
}

fn decode_node_id_v1(
    value: &str,
    check: &'static str,
) -> Result<[u8; 33], MainnetProfileFailureV1> {
    let bytes = decode_hex_exact_v1::<33>(value, check, "invalid-node-id")?;
    if (!value.starts_with("02") && !value.starts_with("03"))
        || k256::PublicKey::from_sec1_bytes(&bytes).is_err()
    {
        return Err(MainnetProfileFailureV1::new(check, "invalid-node-id"));
    }
    Ok(bytes)
}

fn decode_hex_exact_v1<const N: usize>(
    value: &str,
    check: &'static str,
    reason: &'static str,
) -> Result<[u8; N], MainnetProfileFailureV1> {
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(MainnetProfileFailureV1::new(check, reason));
    }
    let mut bytes = [0u8; N];
    hex::decode_to_slice(value, &mut bytes)
        .map_err(|_| MainnetProfileFailureV1::new(check, reason))?;
    Ok(bytes)
}

fn unix_time_now_v1() -> Result<u64, MainnetProfileFailureV1> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| MainnetProfileFailureV1::new("clock", "before-unix-epoch"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use ed25519_dalek::SigningKey;
    use std::collections::VecDeque;

    const NOW: u64 = 2_000_000;
    const NODE_ID: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    struct FakeRunnerV1 {
        responses: VecDeque<Vec<u8>>,
        requests: Vec<CommandRequestV1>,
    }

    #[async_trait(?Send)]
    impl CommandRunnerV1 for FakeRunnerV1 {
        async fn execute(
            &mut self,
            request: CommandRequestV1,
        ) -> Result<Vec<u8>, crate::lightning_staging::RunnerFailureV1> {
            self.requests.push(request);
            self.responses
                .pop_front()
                .ok_or(crate::lightning_staging::RunnerFailureV1::Output)
        }
    }

    fn delegation() -> (Bolt11QuoteKeyDelegationV1, Vec<u8>) {
        let issuer = SigningKey::from_bytes(&[7u8; 32]);
        let quote = SigningKey::from_bytes(&[8u8; 32]);
        let payee = decode_node_id_v1(NODE_ID, "test").unwrap();
        let delegation = Bolt11QuoteKeyDelegationV1::sign(
            LightningNetworkV1::Bitcoin,
            payee,
            1,
            NOW - 100,
            NOW + 100,
            quote.verifying_key().to_bytes(),
            &issuer,
        )
        .unwrap();
        let bytes = delegation.encode().unwrap();
        (delegation, bytes)
    }

    fn profile() -> MainnetLightningV1Profile {
        let (delegation, delegation_bytes) = delegation();
        MainnetLightningV1Profile {
            schema_version: 2,
            profile: MainnetProfileNameV1::MainnetLightningV1,
            network: MainnetNetworkV1::Bitcoin,
            bitcoin_genesis_hash: MAINNET_GENESIS_V1.to_owned(),
            bolt11_hrp: Bolt11HrpV1::Mainnet,
            capability: CapabilityV1::SharedBatDb0Db1,
            provider_count: 2,
            bat_lineage_count: 12,
            settlement: SettlementV1::LedgerOnly,
            payout: PayoutV1::Disabled,
            direct_receipt: ForbiddenV1::Forbidden,
            standard_cashu: ForbiddenV1::Forbidden,
            arc: ForbiddenV1::Forbidden,
            expected_issuer_id_hex: hex::encode(delegation.issuer_id),
            expected_payee_node_id_hex: NODE_ID.to_owned(),
            command_timeout_seconds: 10,
            max_block_height_lag: 2,
            bitcoin: BitcoinConfigV1 {
                cli: executable("/opt/bitcoin/bin/bitcoin-cli"),
                cli_args: vec![
                    "-chain=main".to_owned(),
                    "-rpcconnect=127.0.0.1".to_owned(),
                    "-rpcport=8332".to_owned(),
                ],
            },
            lightning: LightningConfigV1 {
                cli: executable("/opt/cln/bin/lightning-cli"),
                rpc_socket: PathBuf::from("/srv/lightning/bitcoin/lightning-rpc"),
            },
            quote_delegation: artifact("/etc/bpir/quote-delegation.bin", &delegation_bytes),
            backup: BackupConfigV1 {
                receipt: artifact("/etc/bpir/backup-receipt.toml", b"fixture"),
                max_age_seconds: 300,
            },
            custody: CustodyV1 {
                identity_restore_evidence_sha256: "11".repeat(32),
                channel_recovery_restore_evidence_sha256: "22".repeat(32),
                datastore_restore_evidence_sha256: "33".repeat(32),
                custody_operation_authorized: false,
            },
            risk: RiskV1 {
                max_invoice_msat: 1_000,
                max_total_exposure_msat: 10_000,
                max_invoices_per_runtime: 2,
                max_payment_attempts: 1,
            },
            operation: ReadOnlyOperationV1 {
                read_only_node_contact: true,
                invoice_creation: false,
                payment_execution: false,
            },
        }
    }

    fn executable(path: &str) -> PinnedExecutableV1 {
        PinnedExecutableV1 {
            path: PathBuf::from(path),
            protected_parent: PathBuf::from("/opt"),
            sha256_hex: "aa".repeat(32),
            expected_uid: 0,
            expected_gid: 0,
        }
    }

    fn artifact(path: &str, bytes: &[u8]) -> ProtectedArtifactV1 {
        ProtectedArtifactV1 {
            path: PathBuf::from(path),
            protected_parent: PathBuf::from("/etc/bpir"),
            expected_uid: 0,
            expected_gid: 995,
            sha256_hex: hex::encode(Sha256::digest(bytes)),
        }
    }

    fn valid_responses() -> VecDeque<Vec<u8>> {
        VecDeque::from(vec![
            serde_json::to_vec(&serde_json::json!({
                "chain": "main", "blocks": 900_000, "headers": 900_000,
                "initialblockdownload": false
            }))
            .unwrap(),
            format!("{MAINNET_GENESIS_V1}\n").into_bytes(),
            serde_json::to_vec(&serde_json::json!({
                "id": NODE_ID, "network": "bitcoin", "blockheight": 900_000
            }))
            .unwrap(),
            serde_json::to_vec(&serde_json::json!({
                "channels": [{
                    "peer_connected": true, "state": "CHANNELD_NORMAL",
                    "short_channel_id": "1x1x1", "private": false,
                    "lost_state": false, "spendable_msat": {"msat": 2_000},
                    "receivable_msat": {"msat": 5_000}
                }]
            }))
            .unwrap(),
            serde_json::to_vec(&serde_json::json!({
                "outputs": [{"amount_msat": {"msat": 1_000}}]
            }))
            .unwrap(),
            serde_json::to_vec(&serde_json::json!({"scb": ["01020304"]})).unwrap(),
        ])
    }

    fn receipt() -> BackupReceiptV1 {
        let (digest, count) =
            digest_staticbackup_input_v1(&["01020304".to_owned()], false).unwrap();
        BackupReceiptV1 {
            schema_version: 1,
            node_id_hex: NODE_ID.to_owned(),
            recorded_at_unix: NOW - 10,
            staticbackup_digest_hex: hex::encode(digest),
            staticbackup_count: count,
            identity_secret_backup_confirmed: true,
            channel_state_backup_confirmed: true,
        }
    }

    #[test]
    fn static_profile_requires_nonzero_checked_read_only_envelope() {
        validate_profile_v1(&profile()).unwrap();
        let mut zero = profile();
        zero.risk.max_invoice_msat = 0;
        assert_eq!(
            validate_profile_v1(&zero).unwrap_err().check,
            "profile.risk"
        );
        let mut overflow = profile();
        overflow.risk.max_invoice_msat = u64::MAX;
        assert_eq!(
            validate_profile_v1(&overflow).unwrap_err().reason,
            "exposure-overflow"
        );
        let mut activating = profile();
        activating.operation.invoice_creation = true;
        assert_eq!(
            validate_profile_v1(&activating).unwrap_err().check,
            "profile.operation"
        );
    }

    #[test]
    fn bitcoin_cli_requires_explicit_main_and_rejects_signet_or_credentials() {
        for args in [
            vec!["-rpcconnect=127.0.0.1".to_owned()],
            vec!["-chain=signet".to_owned()],
            vec!["-chain=main".to_owned(), "-rpcpassword=secret".to_owned()],
        ] {
            assert!(validate_bitcoin_cli_args_v1(&args).is_err());
        }
        validate_bitcoin_cli_args_v1(&["-chain=main".to_owned()]).unwrap();
    }

    #[test]
    fn rendered_public_template_parses_as_the_live_read_only_profile() {
        let (delegation, delegation_bytes) = delegation();
        let mut text = include_str!(
            "../../../deploy/payment-v1/lightning/mainnet-lightning-v1/preflight.toml.example"
        )
        .to_owned();
        for (name, value) in [
            (
                "MAINNET_EXPECTED_ISSUER_ID_HEX",
                hex::encode(delegation.issuer_id),
            ),
            ("MAINNET_PAYEE_NODE_ID_HEX", NODE_ID.to_owned()),
            ("BITCOIN_CORE_BUNDLE_SHA256", "11".repeat(32)),
            ("MAINNET_BITCOIN_CLI_SHA256", "77".repeat(32)),
            ("CLN_BUNDLE_SHA256", "22".repeat(32)),
            ("MAINNET_LIGHTNING_CLI_SHA256", "88".repeat(32)),
            ("BITCOIN_RPC_PORT", "8332".to_owned()),
            ("MAINNET_PREFLIGHT_GID", "736".to_owned()),
            ("CLN_GUARD_MAX_INVOICE_MSAT", "1000".to_owned()),
            ("CLN_GUARD_MAX_INVOICES_PER_RUNTIME", "2".to_owned()),
            ("MAINNET_MAX_TOTAL_EXPOSURE_MSAT", "2000".to_owned()),
            (
                "MAINNET_QUOTE_DELEGATION_SHA256",
                hex::encode(Sha256::digest(&delegation_bytes)),
            ),
            ("MAINNET_BACKUP_RECEIPT_SHA256", "33".repeat(32)),
            ("MAINNET_IDENTITY_RESTORE_EVIDENCE_SHA256", "44".repeat(32)),
            ("MAINNET_CHANNEL_RECOVERY_EVIDENCE_SHA256", "55".repeat(32)),
            ("MAINNET_DATASTORE_RESTORE_EVIDENCE_SHA256", "66".repeat(32)),
        ] {
            text = text.replace(&format!("@{name}@"), &value);
        }
        let parsed: MainnetLightningV1Profile = toml::from_str(&text).unwrap();
        validate_profile_v1(&parsed).unwrap();
    }

    #[tokio::test]
    async fn live_preflight_uses_exact_read_only_mainnet_cli_sequence() {
        let profile = profile();
        let (_, delegation_bytes) = delegation();
        let mut runner = FakeRunnerV1 {
            responses: valid_responses(),
            requests: Vec::new(),
        };
        let success =
            run_live_preflight_v1(&profile, &delegation_bytes, &receipt(), NOW, &mut runner)
                .await
                .unwrap();
        assert_eq!(success.bitcoin_height, 900_000);
        assert_eq!(runner.requests.len(), 6);
        let core_args: Vec<_> = runner.requests[0]
            .args
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();
        assert!(core_args.contains(&"-chain=main".to_owned()));
        let cln_args: Vec<_> = runner.requests[2]
            .args
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();
        assert_eq!(cln_args[0], "--network=bitcoin");
        for request in &runner.requests {
            let joined = request
                .args
                .iter()
                .map(|value| value.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ");
            assert!(!joined.contains("invoice"));
            assert!(!joined.contains("pay"));
            assert!(!joined.contains("cashu"));
            assert!(!joined.contains("arc"));
        }
    }

    #[tokio::test]
    async fn live_preflight_rejects_wrong_chain_payee_delegation_backup_and_custody() {
        let base = profile();
        let (_, delegation_bytes) = delegation();

        let mut wrong_chain = valid_responses();
        wrong_chain[0] = serde_json::to_vec(&serde_json::json!({
            "chain": "signet", "blocks": 1, "headers": 1,
            "initialblockdownload": false, "signet_challenge": "00"
        }))
        .unwrap();
        let mut runner = FakeRunnerV1 {
            responses: wrong_chain,
            requests: vec![],
        };
        assert_eq!(
            run_live_preflight_v1(&base, &delegation_bytes, &receipt(), NOW, &mut runner)
                .await
                .unwrap_err()
                .check,
            "core.chain"
        );

        let mut bad_receipt = receipt();
        bad_receipt.node_id_hex =
            "03f028892b6f8e8f0f34f6c4a966a2e2f1f5fdb071bc1f67efb0bdeed7e018f83".to_owned();
        let mut runner = FakeRunnerV1 {
            responses: valid_responses(),
            requests: vec![],
        };
        assert_eq!(
            run_live_preflight_v1(&base, &delegation_bytes, &bad_receipt, NOW, &mut runner)
                .await
                .unwrap_err()
                .check,
            "backup.receipt"
        );

        let mut insufficient = valid_responses();
        insufficient[3] = serde_json::to_vec(&serde_json::json!({
            "channels": [{
                "peer_connected": true, "state": "CHANNELD_NORMAL",
                "short_channel_id": "1x1x1", "private": false,
                "lost_state": false, "spendable_msat": 2_000,
                "receivable_msat": 1
            }]
        }))
        .unwrap();
        let mut runner = FakeRunnerV1 {
            responses: insufficient,
            requests: vec![],
        };
        assert_eq!(
            run_live_preflight_v1(&base, &delegation_bytes, &receipt(), NOW, &mut runner)
                .await
                .unwrap_err()
                .check,
            "custody.liquidity"
        );

        let (_, signet_delegation) = {
            let issuer = SigningKey::from_bytes(&[7u8; 32]);
            let quote = SigningKey::from_bytes(&[8u8; 32]);
            let signed = Bolt11QuoteKeyDelegationV1::sign(
                LightningNetworkV1::Signet,
                decode_node_id_v1(NODE_ID, "test").unwrap(),
                1,
                NOW - 1,
                NOW + 1,
                quote.verifying_key().to_bytes(),
                &issuer,
            )
            .unwrap();
            (signed.clone(), signed.encode().unwrap())
        };
        let mut runner = FakeRunnerV1 {
            responses: valid_responses(),
            requests: vec![],
        };
        assert_eq!(
            run_live_preflight_v1(&base, &signet_delegation, &receipt(), NOW, &mut runner)
                .await
                .unwrap_err()
                .check,
            "delegation.verify"
        );
    }
}
