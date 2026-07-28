//! Strict preflight and narrowly scoped local backup-receipt ceremony for the
//! long-lived default-Signet/CLN staging topology. The preflight is read-only;
//! the ceremony can atomically replace only the configured non-secret receipt.
//! This module has no bootstrap, wallet, address, funding, channel-open,
//! payment or remote-execution operations.

use async_trait::async_trait;
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::timeout;
use zeroize::Zeroizing;

const CONFIG_SCHEMA_V1: u32 = 1;
const BACKUP_RECEIPT_SCHEMA_V1: u32 = 1;
const MINIMUM_CORE_VERSION_V1: u64 = 290_000;
const DEFAULT_SIGNET_CHALLENGE_V1: &str = "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae";
const DEFAULT_SIGNET_GENESIS_V1: &str =
    "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6";
const MAX_CONFIG_BYTES_V1: u64 = 64 * 1024;
const MAX_RECEIPT_BYTES_V1: u64 = 16 * 1024;
const MAX_COMMAND_OUTPUT_BYTES_V1: usize = 512 * 1024;
const MAX_COMMAND_TIMEOUT_SECONDS_V1: u64 = 30;
const MAX_HEIGHT_LAG_V1: u64 = 12;
const MAX_BACKUP_AGE_SECONDS_V1: u64 = 7 * 24 * 60 * 60;
const MAX_PLUGIN_COUNT_V1: usize = 64;
const MAX_SCB_COUNT_V1: usize = 16;
const MAX_SCB_BYTES_V1: usize = 4096;
const MAX_CORE_COOKIE_BYTES_V1: u64 = 256;
const MIN_ROUTE_LIQUIDITY_MSAT_V1: u64 = 100_000;
const MAX_ROUTE_LIQUIDITY_MSAT_V1: u64 = 100_000_000;

#[derive(Args, Debug)]
pub struct LightningStagingArgs {
    #[command(subcommand)]
    command: LightningStagingCommand,
}

#[derive(Subcommand, Debug)]
enum LightningStagingCommand {
    /// Validate one local payer, router or issuer node without changing it.
    Preflight(LightningStagingPreflightArgs),
    /// Record a fresh local assertion after external backups were restore-checked.
    #[command(name = "record-backup-receipt")]
    RecordBackupReceipt(LightningStagingRecordBackupReceiptArgs),
}

#[derive(Args, Debug)]
struct LightningStagingPreflightArgs {
    /// Absolute path to the owner-controlled, non-secret TOML configuration.
    #[arg(long)]
    config: PathBuf,
    /// Trusted directory boundary containing the config (not read from it).
    #[arg(long)]
    config_protected_parent: PathBuf,
    /// Exact owner UID required for the config and protected subtree.
    #[arg(long)]
    config_expected_uid: u32,
    /// Exact owner GID required for the config and protected subtree.
    #[arg(long)]
    config_expected_gid: u32,
}

#[derive(Args, Debug)]
struct LightningStagingRecordBackupReceiptArgs {
    /// Absolute path to the owner-controlled, non-secret TOML configuration.
    #[arg(long)]
    config: PathBuf,
    /// Trusted directory boundary containing the config (not read from it).
    #[arg(long)]
    config_protected_parent: PathBuf,
    /// Exact owner UID required for the config and protected subtree.
    #[arg(long)]
    config_expected_uid: u32,
    /// Exact owner GID required for the config and protected subtree.
    #[arg(long)]
    config_expected_gid: u32,
    /// Assert that the node identity secret's offline backup was restore-checked.
    #[arg(
        long,
        required = true,
        action = clap::ArgAction::SetTrue
    )]
    acknowledge_identity_secret_offline_backup_restore_checked: bool,
    /// Assert that current channel recovery material was externally restore-checked.
    #[arg(
        long,
        required = true,
        action = clap::ArgAction::SetTrue
    )]
    acknowledge_channel_state_recovery_backup_restore_checked: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum StagingRoleV1 {
    Payer,
    Router,
    Issuer,
}

impl StagingRoleV1 {
    fn label(self) -> &'static str {
        match self {
            Self::Payer => "payer",
            Self::Router => "router",
            Self::Issuer => "issuer",
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LightningStagingConfigV1 {
    schema_version: u32,
    role: StagingRoleV1,
    payer_node_id_hex: String,
    router_node_id_hex: String,
    issuer_node_id_hex: String,
    command_timeout_seconds: u64,
    max_block_height_lag: u64,
    minimum_route_liquidity_msat: u64,
    bitcoin: BitcoinConfigV1,
    lightning: LightningConfigV1,
    backup: BackupConfigV1,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BitcoinConfigV1 {
    daemon: PinnedBinaryV1,
    cli: PinnedBinaryV1,
    rpc_cookie: ProtectedFileV1,
    /// `bitcoin-cli` options only. At least one exact default-Signet selector
    /// is required; positional RPC method names and inline credentials fail.
    cli_args: Vec<String>,
    expected_subversion: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LightningConfigV1 {
    daemon: PinnedBinaryV1,
    cli: PinnedBinaryV1,
    rpc_socket: PathBuf,
    protected_parent: PathBuf,
    expected_uid: u32,
    expected_gid: u32,
    expected_version: String,
    allowed_plugins: Vec<PinnedPluginV1>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupConfigV1 {
    receipt: PathBuf,
    protected_parent: PathBuf,
    expected_uid: u32,
    expected_gid: u32,
    max_age_seconds: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinnedBinaryV1 {
    path: PathBuf,
    protected_parent: PathBuf,
    sha256_hex: String,
    expected_uid: u32,
    expected_gid: u32,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinnedPluginV1 {
    /// Exact full pathname returned by `lightning-cli plugin list`.
    name: String,
    protected_parent: PathBuf,
    sha256_hex: String,
    expected_uid: u32,
    expected_gid: u32,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedFileV1 {
    path: PathBuf,
    protected_parent: PathBuf,
    expected_uid: u32,
    expected_gid: u32,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BackupReceiptV1 {
    schema_version: u32,
    node_id_hex: String,
    recorded_at_unix: u64,
    staticbackup_digest_hex: String,
    identity_secret_backup_confirmed: bool,
    channel_state_backup_confirmed: bool,
}

#[derive(Clone, Debug)]
struct NodeIdsV1 {
    payer: String,
    router: String,
    issuer: String,
}

impl NodeIdsV1 {
    fn own(&self, role: StagingRoleV1) -> &str {
        match role {
            StagingRoleV1::Payer => &self.payer,
            StagingRoleV1::Router => &self.router,
            StagingRoleV1::Issuer => &self.issuer,
        }
    }

    fn required_peers(&self, role: StagingRoleV1) -> Vec<&str> {
        match role {
            StagingRoleV1::Payer => vec![&self.router],
            StagingRoleV1::Router => vec![&self.payer, &self.issuer],
            StagingRoleV1::Issuer => vec![&self.router],
        }
    }

    fn required_gossip_pairs(&self, role: StagingRoleV1) -> Vec<(&str, &str)> {
        match role {
            StagingRoleV1::Payer | StagingRoleV1::Router => {
                vec![(&self.payer, &self.router), (&self.router, &self.issuer)]
            }
            StagingRoleV1::Issuer => vec![(&self.router, &self.issuer)],
        }
    }
}

#[derive(Debug)]
pub struct PreflightFailureV1 {
    check: &'static str,
    reason: &'static str,
}

impl PreflightFailureV1 {
    fn new(check: &'static str, reason: &'static str) -> Self {
        Self { check, reason }
    }
}

impl fmt::Display for PreflightFailureV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Both values are compile-time bounded labels. Never include paths,
        // RPC bodies, balances, SCBs, node IDs or subprocess diagnostics.
        write!(f, "result=FAIL check={} reason={}", self.check, self.reason)
    }
}

#[derive(Clone, Debug)]
struct CommandRequestV1 {
    program: PathBuf,
    args: Vec<OsString>,
    timeout: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RunnerFailureV1 {
    Spawn,
    Timeout,
    Exit,
    Output,
    Oversize,
}

impl RunnerFailureV1 {
    fn label(self) -> &'static str {
        match self {
            Self::Spawn => "command-spawn",
            Self::Timeout => "command-timeout",
            Self::Exit => "command-exit",
            Self::Output => "command-output",
            Self::Oversize => "command-output-oversize",
        }
    }
}

#[async_trait(?Send)]
trait CommandRunnerV1 {
    async fn execute(&mut self, request: CommandRequestV1) -> Result<Vec<u8>, RunnerFailureV1>;
}

struct SystemCommandRunnerV1;

#[async_trait(?Send)]
impl CommandRunnerV1 for SystemCommandRunnerV1 {
    async fn execute(&mut self, request: CommandRequestV1) -> Result<Vec<u8>, RunnerFailureV1> {
        let mut command = Command::new(&request.program);
        command
            .args(&request.args)
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(|_| RunnerFailureV1::Spawn)?;
        let stdout = child.stdout.take().ok_or(RunnerFailureV1::Output)?;
        let operation = async {
            let read = async move {
                let mut limited = stdout.take((MAX_COMMAND_OUTPUT_BYTES_V1 + 1) as u64);
                // `staticbackup` is one of the commands using this runner.
                // Keep partially read output zeroizing so timeout, read,
                // oversize and non-zero-exit paths cannot leave an SCB in a
                // freed ordinary allocation. The sensitive success path wraps
                // the returned allocation again before parsing it.
                // Allocate the checked bound once. Reallocation would free an
                // old buffer before `Zeroizing<Vec<_>>` could scrub an SCB
                // prefix copied into it.
                let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_COMMAND_OUTPUT_BYTES_V1 + 1));
                limited
                    .read_to_end(&mut bytes)
                    .await
                    .map_err(|_| RunnerFailureV1::Output)?;
                Ok::<Zeroizing<Vec<u8>>, RunnerFailureV1>(bytes)
            };
            let (bytes, status) = tokio::join!(read, child.wait());
            let mut bytes = bytes?;
            let status = status.map_err(|_| RunnerFailureV1::Output)?;
            if bytes.len() > MAX_COMMAND_OUTPUT_BYTES_V1 {
                return Err(RunnerFailureV1::Oversize);
            }
            if !status.success() {
                return Err(RunnerFailureV1::Exit);
            }
            Ok(std::mem::take(&mut *bytes))
        };
        match timeout(request.timeout, operation).await {
            Ok(result) => result,
            Err(_) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                Err(RunnerFailureV1::Timeout)
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct CoreNetworkInfoV1 {
    version: u64,
    subversion: String,
}

#[derive(Debug, Deserialize)]
struct CoreChainInfoV1 {
    chain: String,
    blocks: u64,
    headers: u64,
    initialblockdownload: bool,
    signet_challenge: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ClnGetInfoV1 {
    id: String,
    version: String,
    network: String,
    blockheight: u64,
}

#[derive(Debug, Deserialize)]
struct ClnPluginListV1 {
    command: String,
    plugins: Vec<ClnPluginV1>,
}

#[derive(Debug, Deserialize)]
struct ClnPluginV1 {
    name: String,
    active: bool,
}

#[derive(Clone, Debug, Deserialize)]
struct ClnPeerChannelsV1 {
    channels: Vec<ClnPeerChannelV1>,
}

#[derive(Clone, Debug, Deserialize)]
struct ClnPeerChannelV1 {
    peer_id: String,
    peer_connected: bool,
    state: String,
    short_channel_id: Option<String>,
    private: Option<bool>,
    lost_state: Option<bool>,
    reestablished: Option<bool>,
    spendable_msat: Option<u64>,
    receivable_msat: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
struct ClnListChannelsV1 {
    channels: Vec<ClnGossipChannelV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ClnGossipChannelV1 {
    source: String,
    destination: String,
    short_channel_id: String,
    public: bool,
    active: bool,
}

/// Borrowed view of the sensitive `staticbackup` response. SCB text remains
/// solely in the caller's `Zeroizing<Vec<u8>>`; this type intentionally has no
/// `Debug` implementation and owns no secret strings, including on parse
/// errors.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClnStaticBackupV1<'a> {
    #[serde(borrow)]
    scb: Vec<&'a str>,
}

#[derive(Clone, Debug)]
struct PreflightSnapshotV1 {
    core_version: u64,
    core_subversion: String,
    core_chain: String,
    core_blocks: u64,
    core_headers: u64,
    core_ibd: bool,
    signet_challenge: Option<String>,
    genesis_hash: String,
    cln_id: String,
    cln_version: String,
    cln_network: String,
    cln_blockheight: u64,
    plugins: Vec<(String, bool)>,
    peer_channels: Vec<ClnPeerChannelV1>,
    gossip_channels: Vec<ClnGossipChannelV1>,
    scb_digest: [u8; 32],
    scb_count: usize,
}

#[derive(Debug)]
struct PreflightSuccessV1 {
    role: StagingRoleV1,
    bitcoin_height: u64,
    cln_height: u64,
    peer_channel_count: usize,
    plugin_count: usize,
    backup_age_seconds: u64,
}

#[derive(Debug)]
struct BackupReceiptSuccessV1 {
    role: StagingRoleV1,
    recorded_at_unix: u64,
    scb_count: usize,
}

pub async fn run(args: LightningStagingArgs) -> Result<(), PreflightFailureV1> {
    match args.command {
        LightningStagingCommand::Preflight(args) => {
            let bytes = read_protected_config_v1(&args)?;
            let config = parse_config_v1(&bytes)?;
            let now_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| PreflightFailureV1::new("clock", "before-unix-epoch"))?
                .as_secs();
            let mut runner = SystemCommandRunnerV1;
            let success = run_preflight_v1(&config, now_unix, &mut runner).await?;
            println!(
                "schema_version=1 role={} bitcoin_height={} cln_height={} active_public_peer_channels={} active_allowed_plugins={} backup_age_seconds={} result=PASS",
                success.role.label(),
                success.bitcoin_height,
                success.cln_height,
                success.peer_channel_count,
                success.plugin_count,
                success.backup_age_seconds
            );
            Ok(())
        }
        LightningStagingCommand::RecordBackupReceipt(args) => {
            let bytes = read_protected_config_at_v1(
                &args.config,
                &args.config_protected_parent,
                args.config_expected_uid,
                args.config_expected_gid,
            )?;
            let config = parse_config_v1(&bytes)?;
            let now_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| PreflightFailureV1::new("clock", "before-unix-epoch"))?
                .as_secs();
            let mut runner = SystemCommandRunnerV1;
            let success = run_backup_receipt_ceremony_v1(
                &config,
                now_unix,
                args.acknowledge_identity_secret_offline_backup_restore_checked,
                args.acknowledge_channel_state_recovery_backup_restore_checked,
                &mut runner,
            )
            .await?;
            println!(
                "schema_version=1 role={} recorded_at_unix={} staticbackup_entries={} result=PASS",
                success.role.label(),
                success.recorded_at_unix,
                success.scb_count
            );
            Ok(())
        }
    }
}

fn parse_config_v1(bytes: &[u8]) -> Result<LightningStagingConfigV1, PreflightFailureV1> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| PreflightFailureV1::new("config.parse", "invalid-utf8"))?;
    toml::from_str(text).map_err(|_| PreflightFailureV1::new("config.parse", "invalid-toml"))
}

async fn run_preflight_v1<R: CommandRunnerV1>(
    config: &LightningStagingConfigV1,
    now_unix: u64,
    runner: &mut R,
) -> Result<PreflightSuccessV1, PreflightFailureV1> {
    let ids = validate_static_config_v1(config)?;
    validate_core_rpc_cookie_v1(&config.bitcoin.rpc_cookie)?;
    validate_pinned_binary_v1(&config.bitcoin.daemon, "binary.bitcoin-daemon")?;
    validate_pinned_binary_v1(&config.bitcoin.cli, "binary.bitcoin-cli")?;
    validate_pinned_binary_v1(&config.lightning.daemon, "binary.lightningd")?;
    validate_pinned_binary_v1(&config.lightning.cli, "binary.lightning-cli")?;
    for plugin in &config.lightning.allowed_plugins {
        validate_pinned_plugin_v1(plugin)?;
    }
    validate_protected_socket_v1(&config.lightning)?;
    let receipt_bytes = read_protected_receipt_v1(&config.backup)?;
    let receipt_text = std::str::from_utf8(&receipt_bytes)
        .map_err(|_| PreflightFailureV1::new("backup.receipt", "invalid-utf8"))?;
    let receipt: BackupReceiptV1 = toml::from_str(receipt_text)
        .map_err(|_| PreflightFailureV1::new("backup.receipt", "invalid-toml"))?;
    let snapshot = collect_snapshot_v1(config, &ids, runner).await?;
    validate_snapshot_v1(config, &ids, &snapshot, &receipt, now_unix)
}

async fn run_backup_receipt_ceremony_v1<R: CommandRunnerV1>(
    config: &LightningStagingConfigV1,
    now_unix: u64,
    identity_secret_backup_acknowledged: bool,
    channel_state_backup_acknowledged: bool,
    runner: &mut R,
) -> Result<BackupReceiptSuccessV1, PreflightFailureV1> {
    if !identity_secret_backup_acknowledged || !channel_state_backup_acknowledged {
        return Err(PreflightFailureV1::new(
            "backup.ceremony",
            "acknowledgements-required",
        ));
    }
    if now_unix == 0 {
        return Err(PreflightFailureV1::new("clock", "invalid-timestamp"));
    }

    let ids = validate_static_config_v1(config)?;
    validate_pinned_binary_v1(&config.lightning.daemon, "binary.lightningd")?;
    validate_pinned_binary_v1(&config.lightning.cli, "binary.lightning-cli")?;
    validate_protected_socket_v1(&config.lightning)?;

    let (node_id, scb_digest, scb_count) =
        collect_backup_receipt_material_v1(config, &ids, runner).await?;
    let receipt = BackupReceiptV1 {
        schema_version: BACKUP_RECEIPT_SCHEMA_V1,
        node_id_hex: node_id,
        recorded_at_unix: now_unix,
        staticbackup_digest_hex: hex::encode(scb_digest),
        identity_secret_backup_confirmed: true,
        channel_state_backup_confirmed: true,
    };
    let receipt_bytes = toml::to_string(&receipt)
        .map_err(|_| PreflightFailureV1::new("backup.receipt", "serialize-failed"))?;
    if receipt_bytes.is_empty() || receipt_bytes.len() as u64 > MAX_RECEIPT_BYTES_V1 {
        return Err(PreflightFailureV1::new(
            "backup.receipt",
            "serialized-size-invalid",
        ));
    }
    let reparsed: BackupReceiptV1 = toml::from_str(&receipt_bytes)
        .map_err(|_| PreflightFailureV1::new("backup.receipt", "self-check-failed"))?;
    validate_backup_receipt_v1(config, &ids, &reparsed, scb_digest, now_unix)?;
    write_atomic_backup_receipt_v1(&config.backup, receipt_bytes.as_bytes())?;

    Ok(BackupReceiptSuccessV1 {
        role: config.role,
        recorded_at_unix: now_unix,
        scb_count,
    })
}

async fn collect_backup_receipt_material_v1<R: CommandRunnerV1>(
    config: &LightningStagingConfigV1,
    ids: &NodeIdsV1,
    runner: &mut R,
) -> Result<(String, [u8; 32], usize), PreflightFailureV1> {
    let command_timeout = Duration::from_secs(config.command_timeout_seconds);
    let getinfo: ClnGetInfoV1 = run_cln_json_v1(
        runner,
        config,
        "rpc.cln.getinfo",
        &["getinfo"],
        command_timeout,
    )
    .await?;
    let node_id = normalize_node_id_v1(&getinfo.id)
        .map_err(|_| PreflightFailureV1::new("lightning.identity", "invalid-node-id"))?;
    if node_id != ids.own(config.role) {
        return Err(PreflightFailureV1::new(
            "lightning.identity",
            "role-node-id-mismatch",
        ));
    }
    if getinfo.network != "signet" {
        return Err(PreflightFailureV1::new("lightning.network", "not-signet"));
    }
    if getinfo.version != config.lightning.expected_version {
        return Err(PreflightFailureV1::new(
            "lightning.version",
            "version-mismatch",
        ));
    }

    let (scb_digest, scb_count) = run_cln_staticbackup_v1(
        runner,
        config,
        "rpc.cln.staticbackup",
        &["staticbackup"],
        command_timeout,
    )
    .await?;
    Ok((node_id, scb_digest, scb_count))
}

fn validate_static_config_v1(
    config: &LightningStagingConfigV1,
) -> Result<NodeIdsV1, PreflightFailureV1> {
    if config.schema_version != CONFIG_SCHEMA_V1 {
        return Err(PreflightFailureV1::new(
            "config.schema",
            "unsupported-version",
        ));
    }
    if !(1..=MAX_COMMAND_TIMEOUT_SECONDS_V1).contains(&config.command_timeout_seconds)
        || config.max_block_height_lag > MAX_HEIGHT_LAG_V1
        || config.backup.max_age_seconds == 0
        || config.backup.max_age_seconds > MAX_BACKUP_AGE_SECONDS_V1
        || !(MIN_ROUTE_LIQUIDITY_MSAT_V1..=MAX_ROUTE_LIQUIDITY_MSAT_V1)
            .contains(&config.minimum_route_liquidity_msat)
    {
        return Err(PreflightFailureV1::new("config.bounds", "out-of-range"));
    }
    let ids = NodeIdsV1 {
        payer: normalize_node_id_v1(&config.payer_node_id_hex)?,
        router: normalize_node_id_v1(&config.router_node_id_hex)?,
        issuer: normalize_node_id_v1(&config.issuer_node_id_hex)?,
    };
    if ids.payer == ids.router || ids.payer == ids.issuer || ids.router == ids.issuer {
        return Err(PreflightFailureV1::new(
            "config.node-ids",
            "duplicate-node-id",
        ));
    }
    validate_absolute_utf8_path_v1(&config.bitcoin.rpc_cookie.path, "config.core-rpc-cookie")?;
    validate_absolute_utf8_path_v1(
        &config.bitcoin.rpc_cookie.protected_parent,
        "config.core-rpc-cookie-parent",
    )?;
    validate_bitcoin_cli_args_v1(&config.bitcoin.cli_args, &config.bitcoin.rpc_cookie.path)?;
    validate_bounded_label_v1(
        &config.bitcoin.expected_subversion,
        "config.bitcoin-subversion",
    )?;
    validate_bounded_label_v1(
        &config.lightning.expected_version,
        "config.lightning-version",
    )?;
    if config.lightning.allowed_plugins.len() > MAX_PLUGIN_COUNT_V1 {
        return Err(PreflightFailureV1::new(
            "config.plugin-allowlist",
            "too-many-plugins",
        ));
    }
    let mut names = BTreeSet::new();
    for plugin in &config.lightning.allowed_plugins {
        if !Path::new(&plugin.name).is_absolute()
            || plugin.name.len() > 4096
            || !names.insert(plugin.name.clone())
        {
            return Err(PreflightFailureV1::new(
                "config.plugin-allowlist",
                "invalid-plugin-entry",
            ));
        }
    }
    validate_absolute_utf8_path_v1(&config.lightning.rpc_socket, "config.lightning-socket")?;
    validate_absolute_utf8_path_v1(
        &config.lightning.protected_parent,
        "config.lightning-parent",
    )?;
    validate_absolute_utf8_path_v1(&config.backup.receipt, "config.backup-receipt")?;
    validate_absolute_utf8_path_v1(&config.backup.protected_parent, "config.backup-parent")?;
    Ok(ids)
}

fn normalize_node_id_v1(value: &str) -> Result<String, PreflightFailureV1> {
    if value.len() != 66 || (!value.starts_with("02") && !value.starts_with("03")) {
        return Err(PreflightFailureV1::new(
            "config.node-ids",
            "invalid-node-id",
        ));
    }
    let bytes = hex::decode(value)
        .map_err(|_| PreflightFailureV1::new("config.node-ids", "invalid-node-id"))?;
    if bytes.len() != 33 {
        return Err(PreflightFailureV1::new(
            "config.node-ids",
            "invalid-node-id",
        ));
    }
    if k256::PublicKey::from_sec1_bytes(&bytes).is_err() {
        return Err(PreflightFailureV1::new(
            "config.node-ids",
            "invalid-node-id",
        ));
    }
    Ok(value.to_ascii_lowercase())
}

fn validate_bounded_label_v1(value: &str, check: &'static str) -> Result<(), PreflightFailureV1> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
    {
        return Err(PreflightFailureV1::new(check, "invalid-label"));
    }
    Ok(())
}

fn validate_bitcoin_cli_args_v1(
    args: &[String],
    expected_cookie_path: &Path,
) -> Result<(), PreflightFailureV1> {
    if args.is_empty() || args.len() > 32 {
        return Err(PreflightFailureV1::new(
            "config.bitcoin-cli-args",
            "invalid-arguments",
        ));
    }
    let mut selects_signet = false;
    let mut seen = BTreeSet::new();
    for arg in args {
        if arg.is_empty()
            || arg.len() > 4096
            || !arg.starts_with('-')
            || !arg.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        {
            return Err(PreflightFailureV1::new(
                "config.bitcoin-cli-args",
                "invalid-arguments",
            ));
        }
        let lower = arg.to_ascii_lowercase();
        let key = if lower == "-signet" || lower == "-chain=signet" {
            selects_signet = true;
            "network"
        } else if let Some(path) = arg.strip_prefix("-datadir=") {
            validate_cli_path_argument_v1(path)?;
            "datadir"
        } else if let Some(path) = arg.strip_prefix("-rpccookiefile=") {
            validate_cli_path_argument_v1(path)?;
            if Path::new(path) != expected_cookie_path {
                return Err(PreflightFailureV1::new(
                    "config.bitcoin-cli-args",
                    "cookie-path-mismatch",
                ));
            }
            "rpccookiefile"
        } else if let Some(host) = lower.strip_prefix("-rpcconnect=") {
            if !matches!(host, "127.0.0.1" | "::1" | "[::1]") {
                return Err(PreflightFailureV1::new(
                    "config.bitcoin-cli-args",
                    "non-local-rpc-target",
                ));
            }
            "rpcconnect"
        } else if let Some(port) = lower.strip_prefix("-rpcport=") {
            let parsed = port.parse::<u16>().map_err(|_| {
                PreflightFailureV1::new("config.bitcoin-cli-args", "invalid-rpc-port")
            })?;
            if parsed == 0 {
                return Err(PreflightFailureV1::new(
                    "config.bitcoin-cli-args",
                    "invalid-rpc-port",
                ));
            }
            "rpcport"
        } else if lower == "-rpcuser=" {
            "rpcuser-clear"
        } else if lower == "-rpcpassword=" {
            "rpcpassword-clear"
        } else {
            return Err(PreflightFailureV1::new(
                "config.bitcoin-cli-args",
                "forbidden-argument",
            ));
        };
        if !seen.insert(key) {
            return Err(PreflightFailureV1::new(
                "config.bitcoin-cli-args",
                "duplicate-argument",
            ));
        }
    }
    if !selects_signet {
        return Err(PreflightFailureV1::new(
            "config.bitcoin-cli-args",
            "missing-signet-selector",
        ));
    }
    if !seen.contains("rpcconnect") {
        return Err(PreflightFailureV1::new(
            "config.bitcoin-cli-args",
            "missing-local-rpc-target",
        ));
    }
    if !seen.contains("rpcport") {
        return Err(PreflightFailureV1::new(
            "config.bitcoin-cli-args",
            "missing-rpc-port",
        ));
    }
    if !seen.contains("rpccookiefile") {
        return Err(PreflightFailureV1::new(
            "config.bitcoin-cli-args",
            "missing-rpc-cookie",
        ));
    }
    if !seen.contains("rpcuser-clear") || !seen.contains("rpcpassword-clear") {
        return Err(PreflightFailureV1::new(
            "config.bitcoin-cli-args",
            "missing-config-auth-clear",
        ));
    }
    Ok(())
}

fn validate_cli_path_argument_v1(path: &str) -> Result<(), PreflightFailureV1> {
    if path.is_empty() || path.len() > 4096 || !Path::new(path).is_absolute() {
        return Err(PreflightFailureV1::new(
            "config.bitcoin-cli-args",
            "invalid-option-path",
        ));
    }
    if Path::new(path)
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(PreflightFailureV1::new(
            "config.bitcoin-cli-args",
            "invalid-option-path",
        ));
    }
    Ok(())
}

fn validate_absolute_utf8_path_v1(
    path: &Path,
    check: &'static str,
) -> Result<(), PreflightFailureV1> {
    if !path.is_absolute() || path.as_os_str().to_str().is_none() {
        return Err(PreflightFailureV1::new(check, "invalid-path"));
    }
    for component in path.components() {
        if matches!(component, Component::CurDir | Component::ParentDir) {
            return Err(PreflightFailureV1::new(check, "invalid-path"));
        }
    }
    Ok(())
}

fn read_bounded_regular_file_v1(
    path: &Path,
    max_bytes: u64,
    check: &'static str,
) -> Result<Vec<u8>, PreflightFailureV1> {
    validate_absolute_utf8_path_v1(path, check)?;
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > max_bytes {
        return Err(PreflightFailureV1::new(check, "unsafe-file"));
    }
    let mut file = File::open(path).map_err(|_| PreflightFailureV1::new(check, "open-failed"))?;
    let opened = file
        .metadata()
        .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
    validate_same_file_v1(&metadata, &opened, check)?;
    let read_limit = max_bytes
        .checked_add(1)
        .ok_or_else(|| PreflightFailureV1::new(check, "oversize"))?;
    let capacity =
        usize::try_from(read_limit).map_err(|_| PreflightFailureV1::new(check, "oversize"))?;
    // This helper also reads the Core RPC cookie. Preallocate the bound once
    // and scrub it on read, oversize and post-read metadata failure paths so
    // neither a partial secret nor an old reallocated prefix is abandoned.
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    file.by_ref()
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| PreflightFailureV1::new(check, "read-failed"))?;
    if bytes.len() as u64 > max_bytes {
        return Err(PreflightFailureV1::new(check, "oversize"));
    }
    let after = file
        .metadata()
        .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
    validate_same_file_v1(&opened, &after, check)?;
    Ok(std::mem::take(&mut *bytes))
}

fn read_protected_config_v1(
    args: &LightningStagingPreflightArgs,
) -> Result<Vec<u8>, PreflightFailureV1> {
    read_protected_config_at_v1(
        &args.config,
        &args.config_protected_parent,
        args.config_expected_uid,
        args.config_expected_gid,
    )
}

fn read_protected_config_at_v1(
    config: &Path,
    config_protected_parent: &Path,
    config_expected_uid: u32,
    config_expected_gid: u32,
) -> Result<Vec<u8>, PreflightFailureV1> {
    let check = "config.file";
    validate_absolute_utf8_path_v1(config, check)?;
    validate_absolute_utf8_path_v1(config_protected_parent, check)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        validate_protected_tree_v1(
            config_protected_parent,
            config,
            config_expected_uid,
            config_expected_gid,
            true,
            check,
        )?;
        let metadata = std::fs::symlink_metadata(config)
            .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
        let mode = metadata.permissions().mode() & 0o777;
        if metadata.uid() != config_expected_uid
            || metadata.gid() != config_expected_gid
            || mode != 0o600
            || metadata.len() > MAX_CONFIG_BYTES_V1
        {
            return Err(PreflightFailureV1::new(check, "unsafe-metadata"));
        }
        read_bounded_regular_file_v1(config, MAX_CONFIG_BYTES_V1, check)
    }
    #[cfg(not(unix))]
    {
        let _ = (
            config,
            config_protected_parent,
            config_expected_uid,
            config_expected_gid,
        );
        Err(PreflightFailureV1::new(check, "unsupported-platform"))
    }
}

fn validate_core_rpc_cookie_v1(config: &ProtectedFileV1) -> Result<(), PreflightFailureV1> {
    let check = "core.rpc-cookie";
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        validate_protected_tree_v1(
            &config.protected_parent,
            &config.path,
            config.expected_uid,
            config.expected_gid,
            true,
            check,
        )?;
        let metadata = std::fs::symlink_metadata(&config.path)
            .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
        let mode = metadata.permissions().mode() & 0o777;
        if metadata.uid() != config.expected_uid
            || metadata.gid() != config.expected_gid
            || mode != 0o600
            || metadata.len() == 0
            || metadata.len() > MAX_CORE_COOKIE_BYTES_V1
        {
            return Err(PreflightFailureV1::new(check, "unsafe-metadata"));
        }
        let bytes = Zeroizing::new(read_bounded_regular_file_v1(
            &config.path,
            MAX_CORE_COOKIE_BYTES_V1,
            check,
        )?);
        let value = bytes.strip_suffix(b"\n").unwrap_or(bytes.as_slice());
        let valid = value
            .iter()
            .position(|byte| *byte == b':')
            .is_some_and(|separator| {
                let (username, password_with_separator) = value.split_at(separator);
                let password = &password_with_separator[1..];
                username == b"__cookie__"
                    && password.len() == 64
                    && password.iter().all(u8::is_ascii_hexdigit)
            });
        if !valid {
            return Err(PreflightFailureV1::new(check, "invalid-cookie-format"));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = config;
        Err(PreflightFailureV1::new(check, "unsupported-platform"))
    }
}

fn validate_pinned_plugin_v1(plugin: &PinnedPluginV1) -> Result<(), PreflightFailureV1> {
    let binary = PinnedBinaryV1 {
        path: PathBuf::from(&plugin.name),
        protected_parent: plugin.protected_parent.clone(),
        sha256_hex: plugin.sha256_hex.clone(),
        expected_uid: plugin.expected_uid,
        expected_gid: plugin.expected_gid,
    };
    validate_pinned_binary_v1(&binary, "binary.cln-plugin")
}

fn validate_pinned_binary_v1(
    binary: &PinnedBinaryV1,
    check: &'static str,
) -> Result<(), PreflightFailureV1> {
    validate_absolute_utf8_path_v1(&binary.path, check)?;
    validate_absolute_utf8_path_v1(&binary.protected_parent, check)?;
    #[cfg(unix)]
    validate_protected_tree_v1(
        &binary.protected_parent,
        &binary.path,
        binary.expected_uid,
        binary.expected_gid,
        true,
        check,
    )?;
    #[cfg(not(unix))]
    return Err(PreflightFailureV1::new(check, "unsupported-platform"));
    let expected = decode_hex32_v1(&binary.sha256_hex, check, "invalid-hash-pin")?;
    let mut file =
        File::open(&binary.path).map_err(|_| PreflightFailureV1::new(check, "open-failed"))?;
    let before = file
        .metadata()
        .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
    validate_executable_metadata_v1(&before, binary.expected_uid, binary.expected_gid, check)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| PreflightFailureV1::new(check, "read-failed"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual: [u8; 32] = hasher.finalize().into();
    if actual != expected {
        return Err(PreflightFailureV1::new(check, "hash-mismatch"));
    }
    let after = file
        .metadata()
        .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
    validate_same_file_v1(&before, &after, check)?;
    Ok(())
}

#[cfg(unix)]
fn validate_executable_metadata_v1(
    metadata: &std::fs::Metadata,
    expected_uid: u32,
    expected_gid: u32,
    check: &'static str,
) -> Result<(), PreflightFailureV1> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let mode = metadata.permissions().mode() & 0o777;
    if !metadata.is_file()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || mode & 0o022 != 0
        || mode & 0o111 == 0
    {
        return Err(PreflightFailureV1::new(check, "unsafe-metadata"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_executable_metadata_v1(
    _metadata: &std::fs::Metadata,
    _expected_uid: u32,
    _expected_gid: u32,
    check: &'static str,
) -> Result<(), PreflightFailureV1> {
    Err(PreflightFailureV1::new(check, "unsupported-platform"))
}

#[cfg(unix)]
fn validate_same_file_v1(
    before: &std::fs::Metadata,
    after: &std::fs::Metadata,
    check: &'static str,
) -> Result<(), PreflightFailureV1> {
    use std::os::unix::fs::MetadataExt;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.uid() != after.uid()
        || before.gid() != after.gid()
        || before.mode() != after.mode()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(PreflightFailureV1::new(check, "file-changed"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_same_file_v1(
    _before: &std::fs::Metadata,
    _after: &std::fs::Metadata,
    check: &'static str,
) -> Result<(), PreflightFailureV1> {
    Err(PreflightFailureV1::new(check, "unsupported-platform"))
}

#[cfg(unix)]
fn validate_protected_socket_v1(config: &LightningConfigV1) -> Result<(), PreflightFailureV1> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    let check = "filesystem.lightning-rpc";
    validate_protected_tree_v1(
        &config.protected_parent,
        &config.rpc_socket,
        config.expected_uid,
        config.expected_gid,
        false,
        check,
    )?;
    let metadata = std::fs::symlink_metadata(&config.rpc_socket)
        .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
    let mode = metadata.permissions().mode() & 0o777;
    if !metadata.file_type().is_socket()
        || metadata.uid() != config.expected_uid
        || metadata.gid() != config.expected_gid
        || mode & 0o077 != 0
        || mode & 0o600 != 0o600
    {
        return Err(PreflightFailureV1::new(check, "unsafe-socket"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_protected_socket_v1(_config: &LightningConfigV1) -> Result<(), PreflightFailureV1> {
    Err(PreflightFailureV1::new(
        "filesystem.lightning-rpc",
        "unsupported-platform",
    ))
}

#[cfg(unix)]
fn validate_protected_tree_v1(
    protected_parent: &Path,
    target: &Path,
    expected_uid: u32,
    expected_gid: u32,
    final_is_regular: bool,
    check: &'static str,
) -> Result<(), PreflightFailureV1> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let relative = target
        .strip_prefix(protected_parent)
        .map_err(|_| PreflightFailureV1::new(check, "outside-protected-parent"))?;
    if relative.as_os_str().is_empty() {
        return Err(PreflightFailureV1::new(check, "invalid-target"));
    }
    let parent_metadata = std::fs::symlink_metadata(protected_parent)
        .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
    let parent_mode = parent_metadata.permissions().mode() & 0o777;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || parent_metadata.uid() != expected_uid
        || parent_metadata.gid() != expected_gid
        || parent_mode & 0o022 != 0
    {
        return Err(PreflightFailureV1::new(check, "unsafe-protected-parent"));
    }
    let mut current = protected_parent.to_path_buf();
    let components: Vec<_> = relative.components().collect();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(part) = component else {
            return Err(PreflightFailureV1::new(check, "invalid-target"));
        };
        current.push(part);
        let metadata = std::fs::symlink_metadata(&current)
            .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
        if metadata.file_type().is_symlink() {
            return Err(PreflightFailureV1::new(check, "symlink-rejected"));
        }
        if index + 1 != components.len() {
            let mode = metadata.permissions().mode() & 0o777;
            if !metadata.is_dir()
                || metadata.uid() != expected_uid
                || metadata.gid() != expected_gid
                || mode & 0o022 != 0
            {
                return Err(PreflightFailureV1::new(check, "unsafe-directory"));
            }
        } else if final_is_regular && !metadata.is_file() {
            return Err(PreflightFailureV1::new(check, "unsafe-file"));
        }
    }
    Ok(())
}

fn read_protected_receipt_v1(config: &BackupConfigV1) -> Result<Vec<u8>, PreflightFailureV1> {
    let check = "backup.receipt-file";
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        validate_protected_tree_v1(
            &config.protected_parent,
            &config.receipt,
            config.expected_uid,
            config.expected_gid,
            true,
            check,
        )?;
        let metadata = std::fs::symlink_metadata(&config.receipt)
            .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
        let mode = metadata.permissions().mode() & 0o777;
        if metadata.uid() != config.expected_uid
            || metadata.gid() != config.expected_gid
            || mode != 0o600
            || metadata.len() > MAX_RECEIPT_BYTES_V1
        {
            return Err(PreflightFailureV1::new(check, "unsafe-metadata"));
        }
        read_bounded_regular_file_v1(&config.receipt, MAX_RECEIPT_BYTES_V1, check)
    }
    #[cfg(not(unix))]
    {
        let _ = config;
        Err(PreflightFailureV1::new(check, "unsupported-platform"))
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BackupReceiptFileSnapshotV1 {
    device: u128,
    inode: u128,
    mode: u64,
    size: i128,
    uid: u32,
    gid: u32,
    modified_seconds: i128,
    modified_nanoseconds: i128,
    changed_seconds: i128,
    changed_nanoseconds: i128,
}

#[cfg(unix)]
fn backup_receipt_file_snapshot_v1(stat: &rustix::fs::Stat) -> BackupReceiptFileSnapshotV1 {
    BackupReceiptFileSnapshotV1 {
        device: stat.st_dev as u128,
        inode: stat.st_ino as u128,
        mode: stat.st_mode as u64,
        size: stat.st_size as i128,
        uid: stat.st_uid,
        gid: stat.st_gid,
        modified_seconds: stat.st_mtime as i128,
        modified_nanoseconds: stat.st_mtime_nsec as i128,
        changed_seconds: stat.st_ctime as i128,
        changed_nanoseconds: stat.st_ctime_nsec as i128,
    }
}

#[cfg(unix)]
fn inspect_backup_receipt_target_v1(
    parent: &File,
    file_name: &std::ffi::OsStr,
    config: &BackupConfigV1,
) -> Result<Option<BackupReceiptFileSnapshotV1>, PreflightFailureV1> {
    use rustix::fs::{self as rustix_fs, FileType, Mode, OFlags};

    let check = "backup.receipt-file";
    let fd = match rustix_fs::openat(
        parent,
        file_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(PreflightFailureV1::new(check, "unsafe-target")),
    };
    let stat = rustix_fs::fstat(&fd)
        .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != config.expected_uid
        || stat.st_gid != config.expected_gid
        || stat.st_mode & 0o777 != 0o600
        || stat.st_size < 0
        || stat.st_size as u64 > MAX_RECEIPT_BYTES_V1
    {
        return Err(PreflightFailureV1::new(check, "unsafe-metadata"));
    }
    Ok(Some(backup_receipt_file_snapshot_v1(&stat)))
}

#[cfg(unix)]
fn open_backup_receipt_parent_v1(
    config: &BackupConfigV1,
) -> Result<(File, OsString, PathBuf), PreflightFailureV1> {
    use rustix::fs::{self as rustix_fs, FileType, Mode, OFlags};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let check = "backup.receipt-file";
    validate_absolute_utf8_path_v1(&config.protected_parent, check)?;
    validate_absolute_utf8_path_v1(&config.receipt, check)?;
    let relative = config
        .receipt
        .strip_prefix(&config.protected_parent)
        .map_err(|_| PreflightFailureV1::new(check, "outside-protected-parent"))?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(PreflightFailureV1::new(check, "invalid-target"));
    }
    let target_parent = config
        .receipt
        .parent()
        .ok_or_else(|| PreflightFailureV1::new(check, "invalid-target"))?
        .to_path_buf();
    let file_name = config
        .receipt
        .file_name()
        .ok_or_else(|| PreflightFailureV1::new(check, "invalid-target"))?
        .to_os_string();

    if target_parent != config.protected_parent {
        validate_protected_tree_v1(
            &config.protected_parent,
            &target_parent,
            config.expected_uid,
            config.expected_gid,
            false,
            check,
        )?;
    }
    let metadata = std::fs::symlink_metadata(&target_parent)
        .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
    let mode = metadata.permissions().mode() & 0o777;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != config.expected_uid
        || metadata.gid() != config.expected_gid
        || mode & 0o022 != 0
    {
        return Err(PreflightFailureV1::new(check, "unsafe-output-parent"));
    }
    let fd = rustix_fs::open(
        &target_parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| PreflightFailureV1::new(check, "open-output-parent-failed"))?;
    let opened = rustix_fs::fstat(&fd)
        .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
    if !FileType::from_raw_mode(opened.st_mode).is_dir()
        || opened.st_uid != config.expected_uid
        || opened.st_gid != config.expected_gid
        || opened.st_mode & 0o022 != 0
        || opened.st_dev as u128 != metadata.dev() as u128
        || opened.st_ino as u128 != metadata.ino() as u128
    {
        return Err(PreflightFailureV1::new(check, "output-parent-changed"));
    }
    Ok((File::from(fd), file_name, target_parent))
}

#[cfg(unix)]
fn validate_opened_backup_parent_still_named_v1(
    parent: &File,
    target_parent: &Path,
    config: &BackupConfigV1,
) -> Result<(), PreflightFailureV1> {
    use rustix::fs::{self as rustix_fs, FileType};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let check = "backup.receipt-file";
    let named = std::fs::symlink_metadata(target_parent)
        .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
    let opened = rustix_fs::fstat(parent)
        .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
    if named.file_type().is_symlink()
        || !named.is_dir()
        || !FileType::from_raw_mode(opened.st_mode).is_dir()
        || named.uid() != config.expected_uid
        || named.gid() != config.expected_gid
        || named.permissions().mode() & 0o022 != 0
        || opened.st_uid != config.expected_uid
        || opened.st_gid != config.expected_gid
        || opened.st_mode & 0o022 != 0
        || opened.st_dev as u128 != named.dev() as u128
        || opened.st_ino as u128 != named.ino() as u128
    {
        return Err(PreflightFailureV1::new(check, "output-parent-changed"));
    }
    Ok(())
}

#[cfg(unix)]
fn write_atomic_backup_receipt_v1(
    config: &BackupConfigV1,
    bytes: &[u8],
) -> Result<(), PreflightFailureV1> {
    write_atomic_backup_receipt_with_hook_v1(config, bytes, || Ok(()))
}

#[cfg(unix)]
fn finish_backup_receipt_write_v1<E>(
    operation_result: Result<(), PreflightFailureV1>,
    unlock_result: Result<(), E>,
) -> Result<(), PreflightFailureV1> {
    match operation_result {
        Err(error) => Err(error),
        Ok(()) => unlock_result.map_err(|_| {
            PreflightFailureV1::new("backup.receipt-file", "unlock-output-parent-failed")
        }),
    }
}

#[cfg(unix)]
fn write_atomic_backup_receipt_with_hook_v1<F>(
    config: &BackupConfigV1,
    bytes: &[u8],
    before_commit: F,
) -> Result<(), PreflightFailureV1>
where
    F: FnOnce() -> Result<(), PreflightFailureV1>,
{
    use rustix::fs::{
        self as rustix_fs, AtFlags, FileType, FlockOperation, Mode, OFlags, RenameFlags,
    };
    use std::io::Write;

    let check = "backup.receipt-file";
    if bytes.is_empty() || bytes.len() as u64 > MAX_RECEIPT_BYTES_V1 {
        return Err(PreflightFailureV1::new(check, "invalid-output-size"));
    }
    let (parent, file_name, target_parent) = open_backup_receipt_parent_v1(config)?;
    rustix_fs::flock(&parent, FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| PreflightFailureV1::new(check, "output-parent-busy"))?;
    let operation_result = (|| {
        let before = inspect_backup_receipt_target_v1(&parent, &file_name, config)?;
        let target_name = file_name
            .to_str()
            .ok_or_else(|| PreflightFailureV1::new(check, "invalid-target"))?;
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| PreflightFailureV1::new(check, "randomness-unavailable"))?;
        let temporary = format!(".{target_name}.{}.tmp", hex::encode(nonce));
        let mut temporary_created = false;
        let result = (|| {
            let fd = rustix_fs::openat(
                &parent,
                temporary.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| PreflightFailureV1::new(check, "create-temporary-failed"))?;
            temporary_created = true;
            rustix_fs::fchmod(&fd, Mode::RUSR | Mode::WUSR)
                .map_err(|_| PreflightFailureV1::new(check, "secure-temporary-failed"))?;
            let mut file = File::from(fd);
            file.write_all(bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| PreflightFailureV1::new(check, "write-temporary-failed"))?;
            let stat = rustix_fs::fstat(&file)
                .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
            if !FileType::from_raw_mode(stat.st_mode).is_file()
                || stat.st_uid != config.expected_uid
                || stat.st_gid != config.expected_gid
                || stat.st_mode & 0o777 != 0o600
                || stat.st_size as i128 != bytes.len() as i128
            {
                return Err(PreflightFailureV1::new(check, "unsafe-temporary"));
            }
            drop(file);
            parent
                .sync_all()
                .map_err(|_| PreflightFailureV1::new(check, "sync-output-parent-failed"))?;
            validate_opened_backup_parent_still_named_v1(&parent, &target_parent, config)?;
            let current = inspect_backup_receipt_target_v1(&parent, &file_name, config)?;
            if current != before {
                return Err(PreflightFailureV1::new(check, "target-changed"));
            }
            before_commit()?;
            // Atomic namespace commit point. Before this call every error removes
            // the temporary and preserves the prior receipt. A following parent
            // fsync can still report an outcome-unknown durability failure; the
            // operator must inspect the exact target rather than invent a second
            // receipt.
            if before.is_none() {
                rustix_fs::renameat_with(
                    &parent,
                    temporary.as_str(),
                    &parent,
                    &file_name,
                    RenameFlags::NOREPLACE,
                )
            } else {
                rustix_fs::renameat(&parent, temporary.as_str(), &parent, &file_name)
            }
            .map_err(|_| PreflightFailureV1::new(check, "atomic-replace-failed"))?;
            temporary_created = false;
            parent
                .sync_all()
                .map_err(|_| PreflightFailureV1::new(check, "sync-committed-parent-failed"))?;
            Ok(())
        })();
        if temporary_created {
            let _ = rustix_fs::unlinkat(&parent, temporary.as_str(), AtFlags::empty());
        }
        result
    })();
    // A concurrently running test or hook may fork while this descriptor is
    // open. Explicit unlock releases the shared open-file-description lock
    // even if a child inherited a duplicate descriptor.
    let unlock_result = rustix_fs::flock(&parent, FlockOperation::Unlock);
    finish_backup_receipt_write_v1(operation_result, unlock_result)
}

#[cfg(not(unix))]
fn write_atomic_backup_receipt_v1(
    _config: &BackupConfigV1,
    _bytes: &[u8],
) -> Result<(), PreflightFailureV1> {
    Err(PreflightFailureV1::new(
        "backup.receipt-file",
        "unsupported-platform",
    ))
}

async fn collect_snapshot_v1<R: CommandRunnerV1>(
    config: &LightningStagingConfigV1,
    ids: &NodeIdsV1,
    runner: &mut R,
) -> Result<PreflightSnapshotV1, PreflightFailureV1> {
    let command_timeout = Duration::from_secs(config.command_timeout_seconds);
    let network: CoreNetworkInfoV1 = run_core_json_v1(
        runner,
        config,
        "rpc.core.getnetworkinfo",
        &["getnetworkinfo"],
        command_timeout,
    )
    .await?;
    let chain: CoreChainInfoV1 = run_core_json_v1(
        runner,
        config,
        "rpc.core.getblockchaininfo",
        &["getblockchaininfo"],
        command_timeout,
    )
    .await?;
    let genesis_bytes = run_core_bytes_v1(
        runner,
        config,
        "rpc.core.getblockhash",
        &["getblockhash", "0"],
        command_timeout,
    )
    .await?;
    let genesis_hash = std::str::from_utf8(&genesis_bytes)
        .map_err(|_| PreflightFailureV1::new("rpc.core.getblockhash", "invalid-utf8"))?
        .trim()
        .to_ascii_lowercase();

    let getinfo: ClnGetInfoV1 = run_cln_json_v1(
        runner,
        config,
        "rpc.cln.getinfo",
        &["getinfo"],
        command_timeout,
    )
    .await?;
    let plugin_list: ClnPluginListV1 = run_cln_json_v1(
        runner,
        config,
        "rpc.cln.plugin-list",
        &["plugin", "list"],
        command_timeout,
    )
    .await?;
    let peer_channels: ClnPeerChannelsV1 = run_cln_json_v1(
        runner,
        config,
        "rpc.cln.listpeerchannels",
        &["listpeerchannels"],
        command_timeout,
    )
    .await?;
    let mut gossip_channels = Vec::new();
    for source in [&ids.payer, &ids.router, &ids.issuer] {
        let source_arg = format!("source={source}");
        let list: ClnListChannelsV1 = run_cln_json_owned_v1(
            runner,
            config,
            "rpc.cln.listchannels",
            vec!["-k".to_owned(), "listchannels".to_owned(), source_arg],
            command_timeout,
        )
        .await?;
        if list.channels.len() > 256 {
            return Err(PreflightFailureV1::new(
                "rpc.cln.listchannels",
                "too-many-channels",
            ));
        }
        gossip_channels.extend(list.channels);
    }
    let (scb_digest, scb_count) = run_cln_staticbackup_v1(
        runner,
        config,
        "rpc.cln.staticbackup",
        &["staticbackup"],
        command_timeout,
    )
    .await?;
    if plugin_list.command != "list" {
        return Err(PreflightFailureV1::new(
            "rpc.cln.plugin-list",
            "unexpected-response",
        ));
    }
    Ok(PreflightSnapshotV1 {
        core_version: network.version,
        core_subversion: network.subversion,
        core_chain: chain.chain,
        core_blocks: chain.blocks,
        core_headers: chain.headers,
        core_ibd: chain.initialblockdownload,
        signet_challenge: chain.signet_challenge,
        genesis_hash,
        cln_id: getinfo.id,
        cln_version: getinfo.version,
        cln_network: getinfo.network,
        cln_blockheight: getinfo.blockheight,
        plugins: plugin_list
            .plugins
            .into_iter()
            .map(|plugin| (plugin.name, plugin.active))
            .collect(),
        peer_channels: peer_channels.channels,
        gossip_channels,
        scb_digest,
        scb_count,
    })
}

async fn run_core_bytes_v1<R: CommandRunnerV1>(
    runner: &mut R,
    config: &LightningStagingConfigV1,
    check: &'static str,
    tail: &[&str],
    command_timeout: Duration,
) -> Result<Vec<u8>, PreflightFailureV1> {
    let mut args: Vec<OsString> = config.bitcoin.cli_args.iter().map(OsString::from).collect();
    args.extend(tail.iter().map(OsString::from));
    runner
        .execute(CommandRequestV1 {
            program: config.bitcoin.cli.path.clone(),
            args,
            timeout: command_timeout,
        })
        .await
        .map_err(|failure| PreflightFailureV1::new(check, failure.label()))
}

async fn run_core_json_v1<R: CommandRunnerV1, T: for<'de> Deserialize<'de>>(
    runner: &mut R,
    config: &LightningStagingConfigV1,
    check: &'static str,
    tail: &[&str],
    command_timeout: Duration,
) -> Result<T, PreflightFailureV1> {
    let bytes = run_core_bytes_v1(runner, config, check, tail, command_timeout).await?;
    serde_json::from_slice(bytes.as_slice())
        .map_err(|_| PreflightFailureV1::new(check, "invalid-json"))
}

async fn run_cln_json_v1<R: CommandRunnerV1, T: for<'de> Deserialize<'de>>(
    runner: &mut R,
    config: &LightningStagingConfigV1,
    check: &'static str,
    tail: &[&str],
    command_timeout: Duration,
) -> Result<T, PreflightFailureV1> {
    run_cln_json_owned_v1(
        runner,
        config,
        check,
        tail.iter().map(|value| (*value).to_owned()).collect(),
        command_timeout,
    )
    .await
}

async fn run_cln_json_owned_v1<R: CommandRunnerV1, T: for<'de> Deserialize<'de>>(
    runner: &mut R,
    config: &LightningStagingConfigV1,
    check: &'static str,
    tail: Vec<String>,
    command_timeout: Duration,
) -> Result<T, PreflightFailureV1> {
    let bytes =
        Zeroizing::new(run_cln_bytes_owned_v1(runner, config, check, tail, command_timeout).await?);
    serde_json::from_slice(bytes.as_slice())
        .map_err(|_| PreflightFailureV1::new(check, "invalid-json"))
}

async fn run_cln_staticbackup_v1<R: CommandRunnerV1>(
    runner: &mut R,
    config: &LightningStagingConfigV1,
    check: &'static str,
    tail: &[&str],
    command_timeout: Duration,
) -> Result<([u8; 32], usize), PreflightFailureV1> {
    let bytes = Zeroizing::new(
        run_cln_bytes_owned_v1(
            runner,
            config,
            check,
            tail.iter().map(|value| (*value).to_owned()).collect(),
            command_timeout,
        )
        .await?,
    );
    // A valid CLN SCB is hex and needs no JSON escaping. Reject escapes before
    // borrowed deserialization so serde never needs a scratch allocation for
    // sensitive string contents; malformed output remains in zeroizing raw
    // storage until this function returns.
    if bytes.contains(&b'\\') {
        return Err(PreflightFailureV1::new(check, "invalid-json"));
    }
    let staticbackup: ClnStaticBackupV1<'_> = serde_json::from_slice(bytes.as_slice())
        .map_err(|_| PreflightFailureV1::new(check, "invalid-json"))?;
    digest_staticbackup_v1(&staticbackup.scb)
}

async fn run_cln_bytes_owned_v1<R: CommandRunnerV1>(
    runner: &mut R,
    config: &LightningStagingConfigV1,
    check: &'static str,
    tail: Vec<String>,
    command_timeout: Duration,
) -> Result<Vec<u8>, PreflightFailureV1> {
    let socket = config
        .lightning
        .rpc_socket
        .to_str()
        .ok_or_else(|| PreflightFailureV1::new(check, "invalid-socket-path"))?;
    let mut args = vec![
        OsString::from("--network=signet"),
        OsString::from(format!("--rpc-file={socket}")),
        OsString::from("--notifications=none"),
    ];
    args.extend(tail.into_iter().map(OsString::from));
    runner
        .execute(CommandRequestV1 {
            program: config.lightning.cli.path.clone(),
            args,
            timeout: command_timeout,
        })
        .await
        .map_err(|failure| PreflightFailureV1::new(check, failure.label()))
}

fn digest_staticbackup_v1<S: AsRef<str>>(
    encoded_entries: &[S],
) -> Result<([u8; 32], usize), PreflightFailureV1> {
    if encoded_entries.is_empty() || encoded_entries.len() > MAX_SCB_COUNT_V1 {
        return Err(PreflightFailureV1::new(
            "lightning.staticbackup",
            "invalid-entry-count",
        ));
    }
    let mut entries = Vec::with_capacity(encoded_entries.len());
    for encoded in encoded_entries {
        let encoded = encoded.as_ref();
        if encoded.len() > MAX_SCB_BYTES_V1 * 2 {
            return Err(PreflightFailureV1::new(
                "lightning.staticbackup",
                "invalid-entry",
            ));
        }
        if encoded.is_empty() || encoded.len() % 2 != 0 {
            return Err(PreflightFailureV1::new(
                "lightning.staticbackup",
                "invalid-entry",
            ));
        }
        // Decode directly into zeroizing storage. `hex::decode` would own a
        // partially filled ordinary Vec on malformed-input error paths.
        let mut bytes = Zeroizing::new(vec![0u8; encoded.len() / 2]);
        hex::decode_to_slice(encoded, &mut bytes[..])
            .map_err(|_| PreflightFailureV1::new("lightning.staticbackup", "invalid-entry"))?;
        if bytes.len() > MAX_SCB_BYTES_V1 {
            return Err(PreflightFailureV1::new(
                "lightning.staticbackup",
                "invalid-entry",
            ));
        }
        entries.push(bytes);
    }
    entries.sort_unstable_by(|left, right| left.as_slice().cmp(right.as_slice()));
    if entries
        .windows(2)
        .any(|pair| pair[0].as_slice() == pair[1].as_slice())
    {
        return Err(PreflightFailureV1::new(
            "lightning.staticbackup",
            "duplicate-entry",
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(b"bitcoinpir-cln-staticbackup-v1\0");
    for entry in &entries {
        hasher.update((entry.len() as u32).to_be_bytes());
        hasher.update(entry.as_slice());
    }
    Ok((hasher.finalize().into(), entries.len()))
}

fn validate_snapshot_v1(
    config: &LightningStagingConfigV1,
    ids: &NodeIdsV1,
    snapshot: &PreflightSnapshotV1,
    receipt: &BackupReceiptV1,
    now_unix: u64,
) -> Result<PreflightSuccessV1, PreflightFailureV1> {
    if snapshot.core_version < MINIMUM_CORE_VERSION_V1 {
        return Err(PreflightFailureV1::new("core.version", "below-minimum"));
    }
    if snapshot.core_subversion != config.bitcoin.expected_subversion {
        return Err(PreflightFailureV1::new(
            "core.version",
            "subversion-mismatch",
        ));
    }
    if snapshot.core_chain != "signet" {
        return Err(PreflightFailureV1::new("core.chain", "not-signet"));
    }
    if !snapshot
        .signet_challenge
        .as_deref()
        .is_some_and(|challenge| challenge.eq_ignore_ascii_case(DEFAULT_SIGNET_CHALLENGE_V1))
    {
        return Err(PreflightFailureV1::new(
            "core.signet-challenge",
            "default-challenge-mismatch",
        ));
    }
    if snapshot.genesis_hash != DEFAULT_SIGNET_GENESIS_V1 {
        return Err(PreflightFailureV1::new(
            "core.genesis",
            "default-genesis-mismatch",
        ));
    }
    if snapshot.core_ibd
        || snapshot.core_headers < snapshot.core_blocks
        || snapshot.core_headers - snapshot.core_blocks > config.max_block_height_lag
    {
        return Err(PreflightFailureV1::new("core.sync", "not-synced"));
    }
    let cln_id = normalize_node_id_v1(&snapshot.cln_id)
        .map_err(|_| PreflightFailureV1::new("lightning.identity", "invalid-node-id"))?;
    if cln_id != ids.own(config.role) {
        return Err(PreflightFailureV1::new(
            "lightning.identity",
            "node-id-mismatch",
        ));
    }
    if snapshot.cln_network != "signet" {
        return Err(PreflightFailureV1::new("lightning.network", "not-signet"));
    }
    if snapshot.cln_version != config.lightning.expected_version {
        return Err(PreflightFailureV1::new(
            "lightning.version",
            "version-mismatch",
        ));
    }
    if snapshot.core_blocks.abs_diff(snapshot.cln_blockheight) > config.max_block_height_lag {
        return Err(PreflightFailureV1::new(
            "lightning.height",
            "height-mismatch",
        ));
    }
    validate_plugins_v1(config, &snapshot.plugins)?;
    let required_peers = validate_peer_channels_v1(
        config.role,
        ids,
        &snapshot.peer_channels,
        config.minimum_route_liquidity_msat,
    )?;
    validate_gossip_v1(config.role, ids, &snapshot.gossip_channels)?;
    if snapshot.scb_count != required_peers {
        return Err(PreflightFailureV1::new(
            "lightning.staticbackup",
            "channel-count-mismatch",
        ));
    }
    let backup_age_seconds =
        validate_backup_receipt_v1(config, ids, receipt, snapshot.scb_digest, now_unix)?;
    Ok(PreflightSuccessV1 {
        role: config.role,
        bitcoin_height: snapshot.core_blocks,
        cln_height: snapshot.cln_blockheight,
        peer_channel_count: required_peers,
        plugin_count: snapshot.plugins.len(),
        backup_age_seconds,
    })
}

fn validate_plugins_v1(
    config: &LightningStagingConfigV1,
    actual: &[(String, bool)],
) -> Result<(), PreflightFailureV1> {
    if actual.len() > MAX_PLUGIN_COUNT_V1 {
        return Err(PreflightFailureV1::new(
            "lightning.plugins",
            "too-many-plugins",
        ));
    }
    let expected: BTreeSet<&str> = config
        .lightning
        .allowed_plugins
        .iter()
        .map(|plugin| plugin.name.as_str())
        .collect();
    let mut observed = BTreeMap::new();
    for (name, active) in actual {
        if name.len() > 4096 || observed.insert(name.as_str(), *active).is_some() {
            return Err(PreflightFailureV1::new(
                "lightning.plugins",
                "invalid-plugin-list",
            ));
        }
    }
    if observed.keys().copied().collect::<BTreeSet<_>>() != expected {
        return Err(PreflightFailureV1::new(
            "lightning.plugins",
            "allowlist-mismatch",
        ));
    }
    if observed.values().any(|active| !active) {
        return Err(PreflightFailureV1::new(
            "lightning.plugins",
            "plugin-inactive",
        ));
    }
    Ok(())
}

fn validate_peer_channels_v1(
    role: StagingRoleV1,
    ids: &NodeIdsV1,
    channels: &[ClnPeerChannelV1],
    minimum_route_liquidity_msat: u64,
) -> Result<usize, PreflightFailureV1> {
    let expected: BTreeSet<&str> = ids.required_peers(role).into_iter().collect();
    if channels.len() != expected.len() {
        return Err(PreflightFailureV1::new(
            "lightning.peer-channels",
            "channel-count-mismatch",
        ));
    }
    let mut observed = BTreeSet::new();
    for channel in channels {
        let peer_id = normalize_node_id_v1(&channel.peer_id)
            .map_err(|_| PreflightFailureV1::new("lightning.peer-channels", "invalid-peer-id"))?;
        if !expected.contains(peer_id.as_str()) || !observed.insert(peer_id.clone()) {
            return Err(PreflightFailureV1::new(
                "lightning.peer-channels",
                "unexpected-peer",
            ));
        }
        if !channel.peer_connected
            || channel.state != "CHANNELD_NORMAL"
            || channel
                .short_channel_id
                .as_deref()
                .unwrap_or_default()
                .is_empty()
            || channel.private != Some(false)
            || channel.lost_state == Some(true)
            || channel.reestablished != Some(true)
        {
            return Err(PreflightFailureV1::new(
                "lightning.peer-channels",
                "channel-not-public-active",
            ));
        }
        let estimate = match role {
            StagingRoleV1::Payer => channel.spendable_msat,
            StagingRoleV1::Router if peer_id == ids.payer => channel.receivable_msat,
            StagingRoleV1::Router => channel.spendable_msat,
            StagingRoleV1::Issuer => channel.receivable_msat,
        }
        .ok_or_else(|| PreflightFailureV1::new("lightning.liquidity", "missing-estimate"))?;
        if estimate < minimum_route_liquidity_msat {
            return Err(PreflightFailureV1::new(
                "lightning.liquidity",
                "below-threshold",
            ));
        }
    }
    if observed.len() != expected.len() {
        return Err(PreflightFailureV1::new(
            "lightning.peer-channels",
            "missing-peer",
        ));
    }
    Ok(expected.len())
}

fn validate_gossip_v1(
    role: StagingRoleV1,
    ids: &NodeIdsV1,
    channels: &[ClnGossipChannelV1],
) -> Result<(), PreflightFailureV1> {
    for (left, right) in ids.required_gossip_pairs(role) {
        if !has_bidirectional_public_active_gossip_v1(channels, left, right) {
            return Err(PreflightFailureV1::new(
                "lightning.gossip",
                "required-edge-missing",
            ));
        }
    }
    Ok(())
}

fn has_bidirectional_public_active_gossip_v1(
    channels: &[ClnGossipChannelV1],
    left: &str,
    right: &str,
) -> bool {
    let forward: BTreeSet<&str> = channels
        .iter()
        .filter(|channel| {
            channel.source.eq_ignore_ascii_case(left)
                && channel.destination.eq_ignore_ascii_case(right)
                && channel.public
                && channel.active
        })
        .map(|channel| channel.short_channel_id.as_str())
        .collect();
    channels.iter().any(|channel| {
        channel.source.eq_ignore_ascii_case(right)
            && channel.destination.eq_ignore_ascii_case(left)
            && channel.public
            && channel.active
            && forward.contains(channel.short_channel_id.as_str())
    })
}

fn validate_backup_receipt_v1(
    config: &LightningStagingConfigV1,
    ids: &NodeIdsV1,
    receipt: &BackupReceiptV1,
    scb_digest: [u8; 32],
    now_unix: u64,
) -> Result<u64, PreflightFailureV1> {
    if receipt.schema_version != BACKUP_RECEIPT_SCHEMA_V1 {
        return Err(PreflightFailureV1::new(
            "backup.receipt",
            "unsupported-version",
        ));
    }
    let receipt_node_id = normalize_node_id_v1(&receipt.node_id_hex)
        .map_err(|_| PreflightFailureV1::new("backup.receipt", "invalid-node-id"))?;
    if receipt_node_id != ids.own(config.role) {
        return Err(PreflightFailureV1::new(
            "backup.receipt",
            "node-id-mismatch",
        ));
    }
    if !receipt.identity_secret_backup_confirmed || !receipt.channel_state_backup_confirmed {
        return Err(PreflightFailureV1::new(
            "backup.receipt",
            "backup-unconfirmed",
        ));
    }
    let expected = decode_hex32_v1(
        &receipt.staticbackup_digest_hex,
        "backup.receipt",
        "invalid-staticbackup-digest",
    )?;
    if expected != scb_digest {
        return Err(PreflightFailureV1::new(
            "backup.receipt",
            "staticbackup-mismatch",
        ));
    }
    let age = now_unix
        .checked_sub(receipt.recorded_at_unix)
        .ok_or_else(|| PreflightFailureV1::new("backup.receipt", "future-timestamp"))?;
    if age > config.backup.max_age_seconds {
        return Err(PreflightFailureV1::new("backup.receipt", "stale-receipt"));
    }
    Ok(age)
}

fn decode_hex32_v1(
    value: &str,
    check: &'static str,
    reason: &'static str,
) -> Result<[u8; 32], PreflightFailureV1> {
    if value.len() != 64 {
        return Err(PreflightFailureV1::new(check, reason));
    }
    let bytes = hex::decode(value).map_err(|_| PreflightFailureV1::new(check, reason))?;
    bytes
        .try_into()
        .map_err(|_| PreflightFailureV1::new(check, reason))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    const NOW: u64 = 2_000_000;
    const PAYER: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const ROUTER: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    const ISSUER: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
    const PLUGIN: &str = "/opt/bitcoinpir/plugins/bookkeeper";

    fn pinned(path: &str) -> PinnedBinaryV1 {
        PinnedBinaryV1 {
            path: PathBuf::from(path),
            protected_parent: PathBuf::from("/opt/bitcoinpir"),
            sha256_hex: hex::encode([7u8; 32]),
            expected_uid: 1000,
            expected_gid: 1000,
        }
    }

    fn config(role: StagingRoleV1) -> LightningStagingConfigV1 {
        LightningStagingConfigV1 {
            schema_version: 1,
            role,
            payer_node_id_hex: PAYER.to_owned(),
            router_node_id_hex: ROUTER.to_owned(),
            issuer_node_id_hex: ISSUER.to_owned(),
            command_timeout_seconds: 5,
            max_block_height_lag: 2,
            minimum_route_liquidity_msat: 250_000,
            bitcoin: BitcoinConfigV1 {
                daemon: pinned("/opt/bitcoinpir/bin/bitcoind"),
                cli: pinned("/opt/bitcoinpir/bin/bitcoin-cli"),
                rpc_cookie: ProtectedFileV1 {
                    path: PathBuf::from("/srv/bitcoin/signet/.cookie"),
                    protected_parent: PathBuf::from("/srv/bitcoin"),
                    expected_uid: 1000,
                    expected_gid: 1000,
                },
                cli_args: vec![
                    "-signet".to_owned(),
                    "-datadir=/srv/bitcoin".to_owned(),
                    "-rpcconnect=127.0.0.1".to_owned(),
                    "-rpcport=38332".to_owned(),
                    "-rpccookiefile=/srv/bitcoin/signet/.cookie".to_owned(),
                    "-rpcuser=".to_owned(),
                    "-rpcpassword=".to_owned(),
                ],
                expected_subversion: "/Satoshi:29.0.0/".to_owned(),
            },
            lightning: LightningConfigV1 {
                daemon: pinned("/opt/bitcoinpir/bin/lightningd"),
                cli: pinned("/opt/bitcoinpir/bin/lightning-cli"),
                rpc_socket: PathBuf::from("/srv/lightning/signet/lightning-rpc"),
                protected_parent: PathBuf::from("/srv/lightning"),
                expected_uid: 1000,
                expected_gid: 1000,
                expected_version: "v26.06.6".to_owned(),
                allowed_plugins: vec![PinnedPluginV1 {
                    name: PLUGIN.to_owned(),
                    protected_parent: PathBuf::from("/opt/bitcoinpir"),
                    sha256_hex: hex::encode([8u8; 32]),
                    expected_uid: 0,
                    expected_gid: 0,
                }],
            },
            backup: BackupConfigV1 {
                receipt: PathBuf::from("/srv/bitcoinpir-backup/receipt.toml"),
                protected_parent: PathBuf::from("/srv/bitcoinpir-backup"),
                expected_uid: 1000,
                expected_gid: 1000,
                max_age_seconds: 3600,
            },
        }
    }

    fn peer(peer_id: &str) -> ClnPeerChannelV1 {
        ClnPeerChannelV1 {
            peer_id: peer_id.to_owned(),
            peer_connected: true,
            state: "CHANNELD_NORMAL".to_owned(),
            short_channel_id: Some("100x1x0".to_owned()),
            private: Some(false),
            lost_state: Some(false),
            reestablished: Some(true),
            spendable_msat: Some(1_000_000),
            receivable_msat: Some(1_000_000),
        }
    }

    fn gossip(left: &str, right: &str, scid: &str) -> Vec<ClnGossipChannelV1> {
        vec![
            ClnGossipChannelV1 {
                source: left.to_owned(),
                destination: right.to_owned(),
                short_channel_id: scid.to_owned(),
                public: true,
                active: true,
            },
            ClnGossipChannelV1 {
                source: right.to_owned(),
                destination: left.to_owned(),
                short_channel_id: scid.to_owned(),
                public: true,
                active: true,
            },
        ]
    }

    fn snapshot(role: StagingRoleV1) -> PreflightSnapshotV1 {
        let ids = NodeIdsV1 {
            payer: PAYER.to_owned(),
            router: ROUTER.to_owned(),
            issuer: ISSUER.to_owned(),
        };
        let peer_channels = ids
            .required_peers(role)
            .into_iter()
            .map(peer)
            .collect::<Vec<_>>();
        let mut gossip_channels = gossip(PAYER, ROUTER, "100x1x0");
        gossip_channels.extend(gossip(ROUTER, ISSUER, "101x1x0"));
        PreflightSnapshotV1 {
            core_version: 290_000,
            core_subversion: "/Satoshi:29.0.0/".to_owned(),
            core_chain: "signet".to_owned(),
            core_blocks: 1000,
            core_headers: 1000,
            core_ibd: false,
            signet_challenge: Some(DEFAULT_SIGNET_CHALLENGE_V1.to_owned()),
            genesis_hash: DEFAULT_SIGNET_GENESIS_V1.to_owned(),
            cln_id: ids.own(role).to_owned(),
            cln_version: "v26.06.6".to_owned(),
            cln_network: "signet".to_owned(),
            cln_blockheight: 999,
            plugins: vec![(PLUGIN.to_owned(), true)],
            peer_channels,
            gossip_channels,
            scb_digest: [9u8; 32],
            scb_count: ids.required_peers(role).len(),
        }
    }

    fn receipt(role: StagingRoleV1) -> BackupReceiptV1 {
        BackupReceiptV1 {
            schema_version: 1,
            node_id_hex: match role {
                StagingRoleV1::Payer => PAYER,
                StagingRoleV1::Router => ROUTER,
                StagingRoleV1::Issuer => ISSUER,
            }
            .to_owned(),
            recorded_at_unix: NOW - 30,
            staticbackup_digest_hex: hex::encode([9u8; 32]),
            identity_secret_backup_confirmed: true,
            channel_state_backup_confirmed: true,
        }
    }

    fn validate(
        config: &LightningStagingConfigV1,
        snapshot: &PreflightSnapshotV1,
        receipt: &BackupReceiptV1,
    ) -> Result<PreflightSuccessV1, PreflightFailureV1> {
        let ids = validate_static_config_v1(config)?;
        validate_snapshot_v1(config, &ids, snapshot, receipt, NOW)
    }

    #[test]
    fn all_three_roles_accept_the_exact_two_channel_topology() {
        for role in [
            StagingRoleV1::Payer,
            StagingRoleV1::Router,
            StagingRoleV1::Issuer,
        ] {
            let result = validate(&config(role), &snapshot(role), &receipt(role)).unwrap();
            assert_eq!(result.role, role);
        }
    }

    #[test]
    fn liquidity_estimates_follow_payer_to_router_to_issuer_direction() {
        let router_config = config(StagingRoleV1::Router);
        let router_receipt = receipt(StagingRoleV1::Router);
        let mut router_snapshot = snapshot(StagingRoleV1::Router);
        let payer_channel = router_snapshot
            .peer_channels
            .iter_mut()
            .find(|channel| channel.peer_id == PAYER)
            .unwrap();
        payer_channel.spendable_msat = Some(1_000_000);
        payer_channel.receivable_msat = Some(249_999);
        assert_eq!(
            validate(&router_config, &router_snapshot, &router_receipt)
                .unwrap_err()
                .check,
            "lightning.liquidity"
        );

        let mut router_snapshot = snapshot(StagingRoleV1::Router);
        let issuer_channel = router_snapshot
            .peer_channels
            .iter_mut()
            .find(|channel| channel.peer_id == ISSUER)
            .unwrap();
        issuer_channel.receivable_msat = Some(1_000_000);
        issuer_channel.spendable_msat = Some(249_999);
        assert_eq!(
            validate(&router_config, &router_snapshot, &router_receipt)
                .unwrap_err()
                .check,
            "lightning.liquidity"
        );

        let issuer_config = config(StagingRoleV1::Issuer);
        let issuer_receipt = receipt(StagingRoleV1::Issuer);
        let mut issuer_snapshot = snapshot(StagingRoleV1::Issuer);
        issuer_snapshot.peer_channels[0].receivable_msat = Some(249_999);
        assert_eq!(
            validate(&issuer_config, &issuer_snapshot, &issuer_receipt)
                .unwrap_err()
                .check,
            "lightning.liquidity"
        );
    }

    #[test]
    fn table_driven_security_failures_fail_closed() {
        #[derive(Clone, Copy)]
        enum Mutation {
            OldCore,
            WrongChain,
            MissingChallenge,
            WrongGenesis,
            Ibd,
            WrongClnIdentity,
            WrongClnNetwork,
            HeightLag,
            UnexpectedPlugin,
            InactivePlugin,
            PrivateChannel,
            DisconnectedChannel,
            MissingLiquidity,
            LowLiquidity,
            MissingRemoteGossip,
            ScbCount,
            StaleReceipt,
            WrongScbDigest,
            UnconfirmedBackup,
        }
        let cases = [
            (Mutation::OldCore, "core.version"),
            (Mutation::WrongChain, "core.chain"),
            (Mutation::MissingChallenge, "core.signet-challenge"),
            (Mutation::WrongGenesis, "core.genesis"),
            (Mutation::Ibd, "core.sync"),
            (Mutation::WrongClnIdentity, "lightning.identity"),
            (Mutation::WrongClnNetwork, "lightning.network"),
            (Mutation::HeightLag, "lightning.height"),
            (Mutation::UnexpectedPlugin, "lightning.plugins"),
            (Mutation::InactivePlugin, "lightning.plugins"),
            (Mutation::PrivateChannel, "lightning.peer-channels"),
            (Mutation::DisconnectedChannel, "lightning.peer-channels"),
            (Mutation::MissingLiquidity, "lightning.liquidity"),
            (Mutation::LowLiquidity, "lightning.liquidity"),
            (Mutation::MissingRemoteGossip, "lightning.gossip"),
            (Mutation::ScbCount, "lightning.staticbackup"),
            (Mutation::StaleReceipt, "backup.receipt"),
            (Mutation::WrongScbDigest, "backup.receipt"),
            (Mutation::UnconfirmedBackup, "backup.receipt"),
        ];
        for (mutation, expected_check) in cases {
            let config = config(StagingRoleV1::Payer);
            let mut snapshot = snapshot(StagingRoleV1::Payer);
            let mut receipt = receipt(StagingRoleV1::Payer);
            match mutation {
                Mutation::OldCore => snapshot.core_version = MINIMUM_CORE_VERSION_V1 - 1,
                Mutation::WrongChain => snapshot.core_chain = "regtest".to_owned(),
                Mutation::MissingChallenge => snapshot.signet_challenge = None,
                Mutation::WrongGenesis => snapshot.genesis_hash = hex::encode([1u8; 32]),
                Mutation::Ibd => snapshot.core_ibd = true,
                Mutation::WrongClnIdentity => snapshot.cln_id = ISSUER.to_owned(),
                Mutation::WrongClnNetwork => snapshot.cln_network = "testnet4".to_owned(),
                Mutation::HeightLag => snapshot.cln_blockheight = 900,
                Mutation::UnexpectedPlugin => {
                    snapshot.plugins.push(("/tmp/unknown".to_owned(), true));
                }
                Mutation::InactivePlugin => snapshot.plugins[0].1 = false,
                Mutation::PrivateChannel => snapshot.peer_channels[0].private = Some(true),
                Mutation::DisconnectedChannel => {
                    snapshot.peer_channels[0].peer_connected = false;
                }
                Mutation::MissingLiquidity => snapshot.peer_channels[0].spendable_msat = None,
                Mutation::LowLiquidity => {
                    snapshot.peer_channels[0].spendable_msat = Some(249_999);
                }
                Mutation::MissingRemoteGossip => snapshot
                    .gossip_channels
                    .retain(|channel| !(channel.source == ROUTER && channel.destination == ISSUER)),
                Mutation::ScbCount => snapshot.scb_count = 2,
                Mutation::StaleReceipt => receipt.recorded_at_unix = NOW - 3601,
                Mutation::WrongScbDigest => {
                    receipt.staticbackup_digest_hex = hex::encode([8u8; 32]);
                }
                Mutation::UnconfirmedBackup => receipt.channel_state_backup_confirmed = false,
            }
            let error = validate(&config, &snapshot, &receipt).unwrap_err();
            assert_eq!(error.check, expected_check, "mutation discriminant failed");
            assert!(!error.to_string().contains(PAYER));
            assert!(!error.to_string().contains('/'));
        }
    }

    #[test]
    fn staticbackup_digest_is_order_independent_and_rejects_duplicates() {
        let first = digest_staticbackup_v1(&["0102".to_owned(), "0304".to_owned()]).unwrap();
        let second = digest_staticbackup_v1(&["0304".to_owned(), "0102".to_owned()]).unwrap();
        assert_eq!(first, second);
        let error = digest_staticbackup_v1(&["0102".to_owned(), "0102".to_owned()]).unwrap_err();
        assert_eq!(error.reason, "duplicate-entry");
    }

    #[test]
    fn staticbackup_json_view_borrows_the_zeroizable_raw_storage() {
        let raw = br#"{"scb":["01020304"]}"#;
        let parsed: ClnStaticBackupV1<'_> = serde_json::from_slice(raw).unwrap();
        assert_eq!(parsed.scb.as_slice(), ["01020304"]);
        let raw_start = raw.as_ptr() as usize;
        let raw_end = raw_start + raw.len();
        let scb_start = parsed.scb[0].as_ptr() as usize;
        assert!(scb_start >= raw_start && scb_start < raw_end);
    }

    #[test]
    fn config_rejects_inline_rpc_credentials_and_implicit_network() {
        let mut value = config(StagingRoleV1::Payer);
        value.bitcoin.cli_args = vec!["-datadir=/srv/bitcoin".to_owned()];
        assert_eq!(
            validate_static_config_v1(&value).unwrap_err().reason,
            "missing-signet-selector"
        );
        value.bitcoin.cli_args = vec!["-signet".to_owned(), "-rpcpassword=secret".to_owned()];
        assert_eq!(
            validate_static_config_v1(&value).unwrap_err().reason,
            "forbidden-argument"
        );
        value.bitcoin.cli_args = vec!["-signet".to_owned(), "-generate".to_owned()];
        assert_eq!(
            validate_static_config_v1(&value).unwrap_err().reason,
            "forbidden-argument"
        );
        value.bitcoin.cli_args = vec!["-signet".to_owned()];
        assert_eq!(
            validate_static_config_v1(&value).unwrap_err().reason,
            "missing-local-rpc-target"
        );

        value = config(StagingRoleV1::Payer);
        value
            .bitcoin
            .cli_args
            .retain(|arg| !arg.starts_with("-rpcport="));
        assert_eq!(
            validate_static_config_v1(&value).unwrap_err().reason,
            "missing-rpc-port"
        );
        value = config(StagingRoleV1::Payer);
        value
            .bitcoin
            .cli_args
            .retain(|arg| !arg.starts_with("-rpccookiefile="));
        assert_eq!(
            validate_static_config_v1(&value).unwrap_err().reason,
            "missing-rpc-cookie"
        );
        value = config(StagingRoleV1::Payer);
        *value
            .bitcoin
            .cli_args
            .iter_mut()
            .find(|arg| arg.starts_with("-rpccookiefile="))
            .unwrap() = "-rpccookiefile=/srv/bitcoin/signet/other.cookie".to_owned();
        assert_eq!(
            validate_static_config_v1(&value).unwrap_err().reason,
            "cookie-path-mismatch"
        );
        value = config(StagingRoleV1::Payer);
        value.bitcoin.cli_args.retain(|arg| arg != "-rpcpassword=");
        assert_eq!(
            validate_static_config_v1(&value).unwrap_err().reason,
            "missing-config-auth-clear"
        );
        value = config(StagingRoleV1::Payer);
        value
            .bitcoin
            .cli_args
            .push("-conf=/srv/bitcoin/bitcoin.conf".to_owned());
        assert_eq!(
            validate_static_config_v1(&value).unwrap_err().reason,
            "forbidden-argument"
        );
    }

    #[test]
    fn backup_receipt_denies_unknown_fields() {
        let text = format!(
            "schema_version=1\nnode_id_hex=\"{PAYER}\"\nrecorded_at_unix=1\nstaticbackup_digest_hex=\"{}\"\nidentity_secret_backup_confirmed=true\nchannel_state_backup_confirmed=true\nsecret=\"unexpected\"\n",
            hex::encode([9u8; 32])
        );
        assert!(toml::from_str::<BackupReceiptV1>(&text).is_err());
    }

    #[test]
    fn published_config_template_parses_and_denies_unknown_fields() {
        let template =
            include_str!("../../../docs/payment/LIGHTNING_STAGING_PREFLIGHT.toml.example");
        assert!(toml::from_str::<LightningStagingConfigV1>(template).is_ok());
        let with_unknown_backup_field = format!("{template}\nunexpected = true\n");
        assert!(toml::from_str::<LightningStagingConfigV1>(&with_unknown_backup_field).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn executable_config_and_cookie_reject_unsafe_permissions() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = std::fs::metadata(directory.path()).unwrap();
        let executable = directory.path().join("bitcoin-cli");
        let executable_bytes = b"fixed-test-executable";
        std::fs::write(&executable, executable_bytes).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let binary = PinnedBinaryV1 {
            path: executable,
            protected_parent: directory.path().to_path_buf(),
            sha256_hex: hex::encode(Sha256::digest(executable_bytes)),
            expected_uid: metadata.uid(),
            expected_gid: metadata.gid(),
        };
        validate_pinned_binary_v1(&binary, "binary.test").unwrap();

        let config_path = directory.path().join("preflight.toml");
        std::fs::write(&config_path, b"schema_version=1\n").unwrap();
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let args = LightningStagingPreflightArgs {
            config: config_path,
            config_protected_parent: directory.path().to_path_buf(),
            config_expected_uid: metadata.uid(),
            config_expected_gid: metadata.gid(),
        };
        assert_eq!(
            read_protected_config_v1(&args).unwrap(),
            b"schema_version=1\n"
        );

        let cookie_path = directory.path().join(".cookie");
        let cookie = format!("__cookie__:{}\n", "a".repeat(64));
        std::fs::write(&cookie_path, cookie.as_bytes()).unwrap();
        std::fs::set_permissions(&cookie_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let cookie_config = ProtectedFileV1 {
            path: cookie_path.clone(),
            protected_parent: directory.path().to_path_buf(),
            expected_uid: metadata.uid(),
            expected_gid: metadata.gid(),
        };
        validate_core_rpc_cookie_v1(&cookie_config).unwrap();
        std::fs::set_permissions(&cookie_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            validate_core_rpc_cookie_v1(&cookie_config)
                .unwrap_err()
                .reason,
            "unsafe-metadata"
        );
        std::fs::set_permissions(&cookie_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let invalid_cookie = b"__cookie__:not-a-real-cookie-secret";
        std::fs::write(&cookie_path, invalid_cookie).unwrap();
        let error = validate_core_rpc_cookie_v1(&cookie_config).unwrap_err();
        assert_eq!(error.reason, "invalid-cookie-format");
        assert!(!error.to_string().contains("not-a-real-cookie-secret"));

        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        assert_eq!(
            validate_pinned_binary_v1(&binary, "binary.test")
                .unwrap_err()
                .reason,
            "unsafe-protected-parent"
        );
        assert_eq!(
            read_protected_config_v1(&args).unwrap_err().reason,
            "unsafe-protected-parent"
        );
        assert_eq!(
            validate_core_rpc_cookie_v1(&cookie_config)
                .unwrap_err()
                .reason,
            "unsafe-protected-parent"
        );
    }

    #[derive(Debug, Eq, PartialEq)]
    struct CapturedCommandV1 {
        program: PathBuf,
        args: Vec<String>,
    }

    struct FakeRunnerV1 {
        responses: VecDeque<Vec<u8>>,
        commands: Vec<CapturedCommandV1>,
    }

    #[async_trait(?Send)]
    impl CommandRunnerV1 for FakeRunnerV1 {
        async fn execute(&mut self, request: CommandRequestV1) -> Result<Vec<u8>, RunnerFailureV1> {
            self.commands.push(CapturedCommandV1 {
                program: request.program,
                args: request
                    .args
                    .iter()
                    .map(|arg| arg.to_string_lossy().into_owned())
                    .collect(),
            });
            self.responses.pop_front().ok_or(RunnerFailureV1::Output)
        }
    }

    #[tokio::test]
    async fn staticbackup_rpc_path_fails_categorically_on_every_sensitive_parse_error() {
        let config = config(StagingRoleV1::Payer);
        let expected = digest_staticbackup_v1(&["0102", "0304"]).unwrap();
        let mut runner = FakeRunnerV1 {
            responses: VecDeque::from(vec![br#"{"scb":["0304","0102"]}"#.to_vec()]),
            commands: Vec::new(),
        };
        assert_eq!(
            run_cln_staticbackup_v1(
                &mut runner,
                &config,
                "rpc.cln.staticbackup",
                &["staticbackup"],
                Duration::from_secs(1),
            )
            .await
            .unwrap(),
            expected
        );

        let cases: &[(&[u8], &str, &str, &str)] = &[
            (
                br#"{"scb":["01\u0032"]}"#,
                "rpc.cln.staticbackup",
                "invalid-json",
                "01\\u0032",
            ),
            (
                br#"{"scb":["deadbeef"],"unexpected":true}"#,
                "rpc.cln.staticbackup",
                "invalid-json",
                "deadbeef",
            ),
            (
                br#"{"scb":["feedface"]"#,
                "rpc.cln.staticbackup",
                "invalid-json",
                "feedface",
            ),
            (
                br#"{"scb":["nothex"]}"#,
                "lightning.staticbackup",
                "invalid-entry",
                "nothex",
            ),
        ];
        for (body, expected_check, expected_reason, sensitive_marker) in cases {
            let mut runner = FakeRunnerV1 {
                responses: VecDeque::from(vec![body.to_vec()]),
                commands: Vec::new(),
            };
            let error = run_cln_staticbackup_v1(
                &mut runner,
                &config,
                "rpc.cln.staticbackup",
                &["staticbackup"],
                Duration::from_secs(1),
            )
            .await
            .unwrap_err();
            assert_eq!(error.check, *expected_check);
            assert_eq!(error.reason, *expected_reason);
            assert!(!error.to_string().contains(*sensitive_marker));
        }
    }

    #[tokio::test]
    async fn backup_receipt_material_uses_exact_rpc_sequence_and_checks_role_identity_first() {
        let config = config(StagingRoleV1::Payer);
        let ids = validate_static_config_v1(&config).unwrap();
        let mut runner = FakeRunnerV1 {
            responses: VecDeque::from(vec![
                serde_json::to_vec(&serde_json::json!({
                    "id": PAYER,
                    "version": "v26.06.6",
                    "network": "signet",
                    "blockheight": 1000
                }))
                .unwrap(),
                serde_json::to_vec(&serde_json::json!({"scb": ["0102"]})).unwrap(),
            ]),
            commands: Vec::new(),
        };
        let (node_id, digest, count) =
            collect_backup_receipt_material_v1(&config, &ids, &mut runner)
                .await
                .unwrap();
        assert_eq!(node_id, PAYER);
        assert_eq!(digest, digest_staticbackup_v1(&["0102"]).unwrap().0);
        assert_eq!(count, 1);
        assert_eq!(
            runner.commands,
            vec![
                CapturedCommandV1 {
                    program: PathBuf::from("/opt/bitcoinpir/bin/lightning-cli"),
                    args: vec![
                        "--network=signet".to_owned(),
                        "--rpc-file=/srv/lightning/signet/lightning-rpc".to_owned(),
                        "--notifications=none".to_owned(),
                        "getinfo".to_owned(),
                    ],
                },
                CapturedCommandV1 {
                    program: PathBuf::from("/opt/bitcoinpir/bin/lightning-cli"),
                    args: vec![
                        "--network=signet".to_owned(),
                        "--rpc-file=/srv/lightning/signet/lightning-rpc".to_owned(),
                        "--notifications=none".to_owned(),
                        "staticbackup".to_owned(),
                    ],
                },
            ]
        );

        let mut mismatch_runner = FakeRunnerV1 {
            responses: VecDeque::from(vec![
                serde_json::to_vec(&serde_json::json!({
                    "id": ISSUER,
                    "version": "v26.06.6",
                    "network": "signet",
                    "blockheight": 1000
                }))
                .unwrap(),
                br#"{"scb":["sensitive-marker"]}"#.to_vec(),
            ]),
            commands: Vec::new(),
        };
        let error = collect_backup_receipt_material_v1(&config, &ids, &mut mismatch_runner)
            .await
            .unwrap_err();
        assert_eq!(error.check, "lightning.identity");
        assert_eq!(error.reason, "role-node-id-mismatch");
        assert_eq!(mismatch_runner.commands.len(), 1);
        assert_eq!(mismatch_runner.responses.len(), 1);
        assert!(!error.to_string().contains(PAYER));
        assert!(!error.to_string().contains(ISSUER));
        assert!(!error.to_string().contains("sensitive-marker"));
    }

    #[tokio::test]
    async fn backup_receipt_ceremony_requires_both_acknowledgements_before_any_rpc() {
        for acknowledgements in [(false, false), (true, false), (false, true)] {
            let mut runner = FakeRunnerV1 {
                responses: VecDeque::new(),
                commands: Vec::new(),
            };
            let error = run_backup_receipt_ceremony_v1(
                &config(StagingRoleV1::Payer),
                NOW,
                acknowledgements.0,
                acknowledgements.1,
                &mut runner,
            )
            .await
            .unwrap_err();
            assert_eq!(error.check, "backup.ceremony");
            assert_eq!(error.reason, "acknowledgements-required");
            assert!(runner.commands.is_empty());
        }
    }

    #[cfg(unix)]
    #[test]
    fn backup_receipt_unlock_failure_preserves_the_primary_error_and_fails_closed_after_success() {
        let primary = PreflightFailureV1::new("backup.test", "injected-failure");
        let error = finish_backup_receipt_write_v1(Err(primary), Err::<(), _>(())).unwrap_err();
        assert_eq!(error.check, "backup.test");
        assert_eq!(error.reason, "injected-failure");

        let error = finish_backup_receipt_write_v1(Ok(()), Err::<(), _>(())).unwrap_err();
        assert_eq!(error.check, "backup.receipt-file");
        assert_eq!(error.reason, "unlock-output-parent-failed");
        assert!(finish_backup_receipt_write_v1(Ok(()), Ok::<(), ()>(())).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn backup_receipt_atomic_commit_preserves_old_file_and_removes_temporary_on_failure() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let parent_metadata = std::fs::metadata(directory.path()).unwrap();
        let receipt_path = directory.path().join("backup-receipt.toml");
        let old = toml::to_string(&receipt(StagingRoleV1::Payer)).unwrap();
        std::fs::write(&receipt_path, old.as_bytes()).unwrap();
        std::fs::set_permissions(&receipt_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let backup = BackupConfigV1 {
            receipt: receipt_path.clone(),
            protected_parent: directory.path().to_path_buf(),
            expected_uid: parent_metadata.uid(),
            expected_gid: parent_metadata.gid(),
            max_age_seconds: 3600,
        };
        let new = toml::to_string(&BackupReceiptV1 {
            recorded_at_unix: NOW,
            ..receipt(StagingRoleV1::Payer)
        })
        .unwrap();

        let error = write_atomic_backup_receipt_with_hook_v1(&backup, new.as_bytes(), || {
            Err(PreflightFailureV1::new("backup.test", "injected-failure"))
        })
        .unwrap_err();
        assert_eq!(error.check, "backup.test");
        assert_eq!(std::fs::read_to_string(&receipt_path).unwrap(), old);
        assert_eq!(
            std::fs::read_dir(directory.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>(),
            vec![OsString::from("backup-receipt.toml")]
        );

        write_atomic_backup_receipt_v1(&backup, new.as_bytes()).unwrap();
        assert_eq!(std::fs::read_to_string(&receipt_path).unwrap(), new);
        assert_eq!(
            std::fs::metadata(&receipt_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::read_dir(directory.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>(),
            vec![OsString::from("backup-receipt.toml")]
        );

        let newest = toml::to_string(&BackupReceiptV1 {
            recorded_at_unix: NOW + 1,
            ..receipt(StagingRoleV1::Payer)
        })
        .unwrap();
        write_atomic_backup_receipt_v1(&backup, newest.as_bytes()).unwrap();
        assert_eq!(std::fs::read_to_string(&receipt_path).unwrap(), newest);
    }

    #[tokio::test]
    async fn command_layer_uses_the_exact_fixed_read_only_rpc_sequence() {
        let config = config(StagingRoleV1::Payer);
        let ids = validate_static_config_v1(&config).unwrap();
        let plugin_json = serde_json::json!({
            "command": "list",
            "plugins": [{"name": PLUGIN, "active": true, "dynamic": false}]
        });
        let peer_json = serde_json::json!({
            "channels": [{
                "peer_id": ROUTER,
                "peer_connected": true,
                "state": "CHANNELD_NORMAL",
                "short_channel_id": "100x1x0",
                "private": false,
                "lost_state": false,
                "reestablished": true,
                "spendable_msat": 1000000,
                "receivable_msat": 1000000
            }]
        });
        let payer_gossip = serde_json::json!({"channels": gossip(PAYER, ROUTER, "100x1x0")});
        let router_channels = [
            gossip(PAYER, ROUTER, "100x1x0"),
            gossip(ROUTER, ISSUER, "101x1x0"),
        ]
        .concat();
        let router_gossip = serde_json::json!({"channels": router_channels});
        let issuer_gossip = serde_json::json!({"channels": gossip(ROUTER, ISSUER, "101x1x0")});
        let mut runner = FakeRunnerV1 {
            responses: VecDeque::from(vec![
                serde_json::to_vec(&serde_json::json!({"version": 290000, "subversion": "/Satoshi:29.0.0/"})).unwrap(),
                serde_json::to_vec(&serde_json::json!({"chain": "signet", "blocks": 1000, "headers": 1000, "initialblockdownload": false, "signet_challenge": DEFAULT_SIGNET_CHALLENGE_V1})).unwrap(),
                format!("{DEFAULT_SIGNET_GENESIS_V1}\n").into_bytes(),
                serde_json::to_vec(&serde_json::json!({"id": PAYER, "version": "v26.06.6", "network": "signet", "blockheight": 1000})).unwrap(),
                serde_json::to_vec(&plugin_json).unwrap(),
                serde_json::to_vec(&peer_json).unwrap(),
                serde_json::to_vec(&payer_gossip).unwrap(),
                serde_json::to_vec(&router_gossip).unwrap(),
                serde_json::to_vec(&issuer_gossip).unwrap(),
                serde_json::to_vec(&serde_json::json!({"scb": ["0102"]})).unwrap(),
            ]),
            commands: Vec::new(),
        };
        let snapshot = collect_snapshot_v1(&config, &ids, &mut runner)
            .await
            .unwrap();
        assert_eq!(snapshot.scb_count, 1);
        assert!(runner.responses.is_empty());
        let core = PathBuf::from("/opt/bitcoinpir/bin/bitcoin-cli");
        let cln = PathBuf::from("/opt/bitcoinpir/bin/lightning-cli");
        let core_base = [
            "-signet",
            "-datadir=/srv/bitcoin",
            "-rpcconnect=127.0.0.1",
            "-rpcport=38332",
            "-rpccookiefile=/srv/bitcoin/signet/.cookie",
            "-rpcuser=",
            "-rpcpassword=",
        ];
        let cln_base = [
            "--network=signet",
            "--rpc-file=/srv/lightning/signet/lightning-rpc",
            "--notifications=none",
        ];
        let command = |program: &Path, base: &[&str], tail: &[&str]| CapturedCommandV1 {
            program: program.to_path_buf(),
            args: base
                .iter()
                .chain(tail.iter())
                .map(|value| (*value).to_owned())
                .collect(),
        };
        let payer_source = format!("source={PAYER}");
        let router_source = format!("source={ROUTER}");
        let issuer_source = format!("source={ISSUER}");
        assert_eq!(
            runner.commands,
            vec![
                command(&core, &core_base, &["getnetworkinfo"]),
                command(&core, &core_base, &["getblockchaininfo"]),
                command(&core, &core_base, &["getblockhash", "0"]),
                command(&cln, &cln_base, &["getinfo"]),
                command(&cln, &cln_base, &["plugin", "list"]),
                command(&cln, &cln_base, &["listpeerchannels"]),
                command(&cln, &cln_base, &["-k", "listchannels", &payer_source]),
                command(&cln, &cln_base, &["-k", "listchannels", &router_source]),
                command(&cln, &cln_base, &["-k", "listchannels", &issuer_source]),
                command(&cln, &cln_base, &["staticbackup"]),
            ]
        );
    }
}
