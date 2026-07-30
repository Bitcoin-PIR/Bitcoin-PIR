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
use std::io::{Read, Seek, SeekFrom};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
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
const BACKUP_RECEIPT_STATE_DIRECTORY_V1: &str = "/var/lib/bitcoinpir-lightning-preflight";
const BACKUP_RECEIPT_PATH_V1: &str = "/var/lib/bitcoinpir-lightning-preflight/backup-receipt.toml";
const CLN_SYSTEMD_INVOCATION_PARENT_V1: &str = "/run/systemd/units";
const CLN_SYSTEMD_INVOCATION_LINK_NAME_V1: &str = "invocation:bitcoinpir-core-lightning.service";
const PREFLIGHT_LEASE_SCHEMA_V1: u32 = 1;
const PREFLIGHT_LEASE_STATE_DIRECTORY_V1: &str = "/run/bitcoinpir-lightning-preflight";
const PREFLIGHT_LEASE_PATH_V1: &str = "/run/bitcoinpir-lightning-preflight/lease.toml";
const PREFLIGHT_LEASE_REFRESH_SECONDS_V1: u64 = 20;
const PREFLIGHT_LEASE_VALIDITY_SECONDS_V1: u64 = 180;
const PREFLIGHT_WATCHDOG_USEC_V1: u64 = 90 * 1_000_000;
const PREFLIGHT_RENEWAL_ROUND_TIMEOUT_SECONDS_V1: u64 = 55;

#[derive(Args, Debug)]
pub struct LightningStagingArgs {
    #[command(subcommand)]
    command: LightningStagingCommand,
}

#[derive(Subcommand, Debug)]
enum LightningStagingCommand {
    /// Validate one fresh, unfunded zero-channel node before any channel mutation.
    #[command(name = "bootstrap-preflight")]
    BootstrapPreflight(LightningStagingPreflightArgs),
    /// Validate one local payer, router or issuer node without changing it.
    Preflight(LightningStagingPreflightArgs),
    /// Continuously renew a short lease bound to one exact CLN systemd invocation.
    #[command(name = "preflight-supervisor")]
    PreflightSupervisor(LightningStagingPreflightArgs),
    /// Record a fresh local assertion after external backups were restore-checked.
    #[command(name = "record-backup-receipt")]
    RecordBackupReceipt(LightningStagingRecordBackupReceiptArgs),
}

#[derive(Args, Debug)]
struct LightningStagingPreflightArgs {
    /// Absolute path to the root-owned, non-secret TOML configuration.
    #[arg(long)]
    config: PathBuf,
    /// Trusted directory boundary containing the config (not read from it).
    #[arg(long)]
    config_protected_parent: PathBuf,
    /// Exact owner UID required for the config; V1 requires root (0).
    #[arg(long)]
    config_expected_uid: u32,
    /// Exact service-reader GID required for the config.
    #[arg(long)]
    config_expected_gid: u32,
    /// Exact non-root EUID under which the config reader must execute.
    #[arg(long)]
    config_reader_expected_uid: u32,
}

#[derive(Args, Debug)]
struct LightningStagingRecordBackupReceiptArgs {
    /// Absolute path to the root-owned, non-secret TOML configuration.
    #[arg(long)]
    config: PathBuf,
    /// Trusted directory boundary containing the config (not read from it).
    #[arg(long)]
    config_protected_parent: PathBuf,
    /// Exact owner UID required for the config; V1 requires root (0).
    #[arg(long)]
    config_expected_uid: u32,
    /// Exact service-reader GID required for the config.
    #[arg(long)]
    config_expected_gid: u32,
    /// Exact non-root EUID under which the config reader must execute.
    #[arg(long)]
    config_reader_expected_uid: u32,
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
    systemd: SystemdConfigV1,
    backup: BackupConfigV1,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SystemdConfigV1 {
    busctl: PinnedBinaryV1,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BitcoinConfigV1 {
    daemon: PinnedBinaryV1,
    cli: PinnedBinaryV1,
    rpc_cookie: CoreRpcCookieConfigV1,
    /// `bitcoin-cli` options only. At least one exact default-Signet selector
    /// is required; positional RPC method names and inline credentials fail.
    cli_args: Vec<String>,
    expected_subversion: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreRpcCookieConfigV1 {
    path: PathBuf,
    protected_parent: PathBuf,
    #[serde(default)]
    access_policy: CoreRpcCookieAccessPolicyV1,
    #[serde(default)]
    cross_uid_access: Option<CoreRpcCookieCrossUidAccessV1>,
    /// Exact bitcoind owner of the final network directory and cookie.
    expected_uid: u32,
    /// Exact cookie-only group. In cross-UID mode only CLN and the short-lived
    /// preflight may receive it; payment issuer and CLN RPC guard must not.
    expected_gid: u32,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum CoreRpcCookieAccessPolicyV1 {
    /// Backwards-compatible V1 staging layout: preflight and bitcoind share
    /// one UID, the final directory is exact mode 0700 and the cookie is 0600.
    #[default]
    SameUidOwnerOnly,
    /// Split-UID layout: a short-lived preflight unit traverses an exact
    /// bitcoind-owner/cookie-group mode-2710 setgid directory and reads a 0640
    /// cookie. The explicit policy name prevents an old mode-0710 config from
    /// silently acquiring the new directory-inheritance semantics.
    CrossUidSetgidSharedGroup,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct CoreRpcCookieCrossUidAccessV1 {
    /// Exact EUID under which the read-only preflight must execute.
    preflight_expected_uid: u32,
    /// The broad `protected_parent` is a root-owned deployment boundary, not
    /// the bitcoind-owned final network directory.
    protected_parent_expected_uid: u32,
    protected_parent_expected_gid: u32,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LightningConfigV1 {
    daemon: PinnedBinaryV1,
    cli: PinnedBinaryV1,
    rpc_socket: PathBuf,
    protected_parent: PathBuf,
    #[serde(default)]
    rpc_access_policy: LightningRpcAccessPolicyV1,
    #[serde(default)]
    cross_uid_access: Option<LightningCrossUidAccessV1>,
    /// Exact CLN owner of the final network directory and RPC socket.
    expected_uid: u32,
    /// Exact metadata GID; in cross-UID mode this is the native CLN RPC group
    /// the dedicated preflight and method guard hold, never the issuer.
    expected_gid: u32,
    expected_version: String,
    allowed_plugins: Vec<PinnedPluginV1>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum LightningRpcAccessPolicyV1 {
    /// Backwards-compatible V1 staging layout: the preflight process, socket
    /// parent and socket share one UID; the final parent is exact mode 0700
    /// and the socket is exact mode 0600.
    #[default]
    SameUidOwnerOnly,
    /// Production split-UID layout: the dedicated preflight traverses a
    /// CLN-owned mode-0710 network directory through an explicit shared group
    /// and connects to an exact mode-0660 socket.
    CrossUidSharedGroup,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct LightningCrossUidAccessV1 {
    /// Exact EUID under which this preflight must execute.
    client_expected_uid: u32,
    /// The broad `protected_parent` is a root-owned deployment boundary, not
    /// the CLN-owned final network directory.
    protected_parent_expected_uid: u32,
    protected_parent_expected_gid: u32,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PreflightLeaseV1 {
    schema_version: u32,
    cln_invocation_id: String,
    checked_at_unix: u64,
    valid_until_unix: u64,
}

#[derive(Debug)]
struct PreflightSupervisorRoundSuccessV1 {
    preflight: PreflightSuccessV1,
    invocation_id: String,
    committed_at_unix: u64,
    backup_age_seconds: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BusctlBooleanPropertyV1 {
    #[serde(rename = "type")]
    signature: String,
    data: bool,
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
#[serde(deny_unknown_fields)]
struct ClnPluginListV1 {
    command: String,
    plugins: Vec<ClnPluginV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ClnPluginV1 {
    name: String,
    active: bool,
    dynamic: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClnListFundsV1 {
    outputs: Vec<serde::de::IgnoredAny>,
    channels: Vec<serde::de::IgnoredAny>,
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
    plugins: Vec<ClnPluginV1>,
    peer_channels: Vec<ClnPeerChannelV1>,
    gossip_channels: Vec<ClnGossipChannelV1>,
    scb_digest: [u8; 32],
    scb_count: usize,
}

#[derive(Clone, Debug)]
struct BootstrapPreflightSnapshotV1 {
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
    plugins: Vec<ClnPluginV1>,
    peer_channel_count: usize,
    onchain_output_count: usize,
    funding_channel_count: usize,
    scb_count: usize,
}

#[derive(Debug)]
struct BootstrapPreflightSuccessV1 {
    role: StagingRoleV1,
    bitcoin_height: u64,
    cln_height: u64,
    plugin_count: usize,
}

#[derive(Debug)]
struct PreflightSuccessV1 {
    role: StagingRoleV1,
    bitcoin_height: u64,
    cln_height: u64,
    peer_channel_count: usize,
    plugin_count: usize,
    backup_age_seconds: u64,
    backup_receipt_recorded_at_unix: u64,
}

#[derive(Debug)]
struct BackupReceiptSuccessV1 {
    role: StagingRoleV1,
    recorded_at_unix: u64,
    scb_count: usize,
}

pub async fn run(args: LightningStagingArgs) -> Result<(), PreflightFailureV1> {
    match args.command {
        LightningStagingCommand::BootstrapPreflight(args) => {
            let config = load_validated_preflight_config_v1(&args)?;
            let mut runner = SystemCommandRunnerV1;
            let success = run_bootstrap_preflight_v1(&config, &mut runner).await?;
            println!(
                "schema_version=1 phase=bootstrap role={} bitcoin_height={} cln_height={} peer_channels=0 onchain_outputs=0 funding_channels=0 staticbackup_entries=0 active_allowed_plugins={} result=PASS",
                success.role.label(),
                success.bitcoin_height,
                success.cln_height,
                success.plugin_count
            );
            Ok(())
        }
        LightningStagingCommand::Preflight(args) => {
            let config = load_validated_preflight_config_v1(&args)?;
            let now_unix = unix_time_now_v1()?;
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
        LightningStagingCommand::PreflightSupervisor(args) => {
            run_preflight_supervisor_v1(&args).await
        }
        LightningStagingCommand::RecordBackupReceipt(args) => {
            let bytes = read_protected_config_at_v1(
                &args.config,
                &args.config_protected_parent,
                args.config_expected_uid,
                args.config_expected_gid,
                args.config_reader_expected_uid,
            )?;
            let config = parse_config_v1(&bytes)?;
            validate_backup_receipt_state_contract_v1(
                &config,
                args.config_expected_gid,
                args.config_reader_expected_uid,
            )?;
            validate_protected_config_runtime_group_set_v1(
                &config,
                args.config_expected_gid,
                args.config_reader_expected_uid,
            )?;
            let now_unix = unix_time_now_v1()?;
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

fn unix_time_now_v1() -> Result<u64, PreflightFailureV1> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PreflightFailureV1::new("clock", "before-unix-epoch"))
        .map(|duration| duration.as_secs())
}

fn load_validated_preflight_config_v1(
    args: &LightningStagingPreflightArgs,
) -> Result<LightningStagingConfigV1, PreflightFailureV1> {
    let bytes = read_protected_config_v1(args)?;
    let config = parse_config_v1(&bytes)?;
    validate_backup_receipt_state_contract_v1(
        &config,
        args.config_expected_gid,
        args.config_reader_expected_uid,
    )?;
    validate_protected_config_runtime_group_set_v1(
        &config,
        args.config_expected_gid,
        args.config_reader_expected_uid,
    )?;
    Ok(config)
}

async fn run_preflight_supervisor_v1(
    args: &LightningStagingPreflightArgs,
) -> Result<(), PreflightFailureV1> {
    let result = run_preflight_supervisor_loop_v1(args).await;
    if result.is_err() {
        remove_preflight_lease_best_effort_v1();
    }
    result
}

async fn run_preflight_supervisor_loop_v1(
    args: &LightningStagingPreflightArgs,
) -> Result<(), PreflightFailureV1> {
    validate_systemd_supervisor_environment_v1()?;
    let mut bound_invocation_id: Option<String> = None;
    let mut last_committed_at_unix: Option<u64> = None;

    loop {
        // One cooperative async deadline covers the complete renewal,
        // including the
        // manager watchdog check, all RPCs, generation recheck and durable
        // lease commit. A blocking fsync is bounded by systemd rather than
        // Tokio's cooperative timeout: TimeoutStartSec covers the first round,
        // and the watchdog covers steady-state renewals. There is
        // deliberately no watchdog notification inside this future: a partial
        // or wedged round can never extend systemd's liveness window.
        let round = timeout(
            Duration::from_secs(PREFLIGHT_RENEWAL_ROUND_TIMEOUT_SECONDS_V1),
            run_preflight_supervisor_round_v1(
                args,
                bound_invocation_id.as_deref(),
                last_committed_at_unix,
            ),
        )
        .await
        .map_err(|_| PreflightFailureV1::new("lease.round", "deadline-exceeded"))??;

        if bound_invocation_id.is_none() {
            systemd_notify_v1(b"READY=1\nWATCHDOG=1\nSTATUS=CLN preflight lease active")?;
            println!(
                "schema_version=1 phase=supervisor role={} bitcoin_height={} cln_height={} active_public_peer_channels={} active_allowed_plugins={} backup_age_seconds={} lease_validity_seconds={} result=PASS",
                round.preflight.role.label(),
                round.preflight.bitcoin_height,
                round.preflight.cln_height,
                round.preflight.peer_channel_count,
                round.preflight.plugin_count,
                round.backup_age_seconds,
                PREFLIGHT_LEASE_VALIDITY_SECONDS_V1,
            );
            bound_invocation_id = Some(round.invocation_id);
        } else {
            systemd_notify_v1(b"WATCHDOG=1\nSTATUS=CLN preflight lease active")?;
        }
        last_committed_at_unix = Some(round.committed_at_unix);

        tokio::time::sleep(Duration::from_secs(PREFLIGHT_LEASE_REFRESH_SECONDS_V1)).await;
    }
}

async fn run_preflight_supervisor_round_v1(
    args: &LightningStagingPreflightArgs,
    bound_invocation_id: Option<&str>,
    last_committed_at_unix: Option<u64>,
) -> Result<PreflightSupervisorRoundSuccessV1, PreflightFailureV1> {
    // Re-open and re-validate all static configuration and runtime identities
    // on every renewal. A prior successful pass never authorizes a later
    // generation of the config, CLN or systemd manager policy.
    let config = load_validated_preflight_config_v1(args)?;
    let mut runner = SystemCommandRunnerV1;
    validate_systemd_service_watchdogs_enabled_v1(&config, &mut runner).await?;
    let invocation_before = read_cln_systemd_invocation_id_v1()?;
    if let Some(expected) = bound_invocation_id {
        validate_cln_invocation_binding_v1(Some(expected), &invocation_before, &invocation_before)?;
    }

    let checked_at_unix = unix_time_now_v1()?;
    let success = run_preflight_v1(&config, checked_at_unix, &mut runner).await?;
    let invocation_after = read_cln_systemd_invocation_id_v1()?;
    validate_cln_invocation_binding_v1(bound_invocation_id, &invocation_before, &invocation_after)?;

    let committed_at_unix = unix_time_now_v1()?;
    validate_lease_clock_v1(checked_at_unix, committed_at_unix, last_committed_at_unix)?;
    let backup_age_seconds = validate_backup_receipt_age_v1(
        success.backup_receipt_recorded_at_unix,
        config.backup.max_age_seconds,
        committed_at_unix,
    )?;
    let lease = PreflightLeaseV1 {
        schema_version: PREFLIGHT_LEASE_SCHEMA_V1,
        cln_invocation_id: invocation_after.clone(),
        checked_at_unix: committed_at_unix,
        valid_until_unix: committed_at_unix
            .checked_add(PREFLIGHT_LEASE_VALIDITY_SECONDS_V1)
            .ok_or_else(|| PreflightFailureV1::new("lease.clock", "timestamp-overflow"))?,
    };
    write_preflight_lease_v1(args, &lease)?;

    Ok(PreflightSupervisorRoundSuccessV1 {
        preflight: success,
        invocation_id: invocation_after,
        committed_at_unix,
        backup_age_seconds,
    })
}

fn parse_systemd_service_watchdogs_property_v1(bytes: &[u8]) -> Result<(), PreflightFailureV1> {
    let check = "systemd.service-watchdogs";
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(PreflightFailureV1::new(check, "invalid-manager-property"));
    }
    let property: BusctlBooleanPropertyV1 = serde_json::from_slice(bytes)
        .map_err(|_| PreflightFailureV1::new(check, "invalid-manager-property"))?;
    if property.signature != "b" {
        return Err(PreflightFailureV1::new(check, "invalid-manager-property"));
    }
    if !property.data {
        return Err(PreflightFailureV1::new(check, "manager-disabled"));
    }
    Ok(())
}

async fn query_systemd_service_watchdogs_enabled_v1<R: CommandRunnerV1>(
    config: &LightningStagingConfigV1,
    runner: &mut R,
) -> Result<(), PreflightFailureV1> {
    let output = runner
        .execute(CommandRequestV1 {
            program: config.systemd.busctl.path.clone(),
            args: [
                "--system",
                "--json=short",
                "get-property",
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                "ServiceWatchdogs",
            ]
            .into_iter()
            .map(OsString::from)
            .collect(),
            timeout: Duration::from_secs(config.command_timeout_seconds),
        })
        .await
        .map_err(|failure| PreflightFailureV1::new("systemd.service-watchdogs", failure.label()))?;
    parse_systemd_service_watchdogs_property_v1(&output)
}

async fn validate_systemd_service_watchdogs_enabled_v1<R: CommandRunnerV1>(
    config: &LightningStagingConfigV1,
    runner: &mut R,
) -> Result<(), PreflightFailureV1> {
    validate_systemd_busctl_config_v1(config)?;
    validate_pinned_binary_v1(&config.systemd.busctl, "binary.busctl")?;
    query_systemd_service_watchdogs_enabled_v1(config, runner).await
}

fn validate_systemd_busctl_config_v1(
    config: &LightningStagingConfigV1,
) -> Result<(), PreflightFailureV1> {
    if config.systemd.busctl.path != Path::new("/usr/bin/busctl")
        || config.systemd.busctl.protected_parent != Path::new("/usr/bin")
        || config.systemd.busctl.expected_uid != 0
        || config.systemd.busctl.expected_gid != 0
    {
        return Err(PreflightFailureV1::new(
            "config.systemd-busctl",
            "invalid-binary-boundary",
        ));
    }
    Ok(())
}

fn validate_lease_clock_v1(
    checked_at_unix: u64,
    committed_at_unix: u64,
    previous_committed_at_unix: Option<u64>,
) -> Result<(), PreflightFailureV1> {
    if checked_at_unix == 0
        || committed_at_unix < checked_at_unix
        || previous_committed_at_unix.is_some_and(|previous| committed_at_unix <= previous)
    {
        return Err(PreflightFailureV1::new("lease.clock", "clock-regressed"));
    }
    Ok(())
}

fn validate_cln_invocation_binding_v1(
    expected: Option<&str>,
    before: &str,
    after: &str,
) -> Result<(), PreflightFailureV1> {
    let check = "systemd.cln-invocation";
    validate_cln_invocation_id_v1(before)?;
    validate_cln_invocation_id_v1(after)?;
    if before != after || expected.is_some_and(|value| value != before) {
        return Err(PreflightFailureV1::new(check, "generation-changed"));
    }
    Ok(())
}

fn validate_cln_invocation_id_v1(value: &str) -> Result<(), PreflightFailureV1> {
    let check = "systemd.cln-invocation";
    if value.len() != 32
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        || value.bytes().all(|byte| byte == b'0')
        || value.bytes().all(|byte| byte == b'f')
    {
        return Err(PreflightFailureV1::new(check, "invalid-invocation-id"));
    }
    Ok(())
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SystemdInvocationLinkSnapshotV1 {
    device: u128,
    inode: u128,
    mode: u64,
    size: i128,
    uid: u32,
    gid: u32,
    links: u128,
    modified_seconds: i128,
    modified_nanoseconds: i128,
    changed_seconds: i128,
    changed_nanoseconds: i128,
}

#[cfg(unix)]
fn systemd_invocation_link_snapshot_v1(stat: &rustix::fs::Stat) -> SystemdInvocationLinkSnapshotV1 {
    SystemdInvocationLinkSnapshotV1 {
        device: stat.st_dev as u128,
        inode: stat.st_ino as u128,
        mode: stat.st_mode as u64,
        size: stat.st_size as i128,
        uid: stat.st_uid,
        gid: stat.st_gid,
        links: stat.st_nlink as u128,
        modified_seconds: stat.st_mtime as i128,
        modified_nanoseconds: stat.st_mtime_nsec as i128,
        changed_seconds: stat.st_ctime as i128,
        changed_nanoseconds: stat.st_ctime_nsec as i128,
    }
}

#[cfg(unix)]
fn validate_systemd_invocation_link_snapshot_v1(
    snapshot: SystemdInvocationLinkSnapshotV1,
) -> Result<(), PreflightFailureV1> {
    use rustix::fs::FileType;

    if !FileType::from_raw_mode(snapshot.mode as _).is_symlink()
        || snapshot.uid != 0
        || snapshot.gid != 0
        || snapshot.links != 1
        || snapshot.size != 32
    {
        return Err(PreflightFailureV1::new(
            "systemd.cln-invocation",
            "unsafe-invocation-link",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn read_cln_systemd_invocation_id_v1() -> Result<String, PreflightFailureV1> {
    use rustix::fs::{self as rustix_fs, AtFlags};

    let check = "systemd.cln-invocation";
    let parent =
        open_protected_config_parent_v1(Path::new(CLN_SYSTEMD_INVOCATION_PARENT_V1), check)?;
    let before = rustix_fs::statat(
        &parent,
        CLN_SYSTEMD_INVOCATION_LINK_NAME_V1,
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|_| PreflightFailureV1::new(check, "invocation-link-unavailable"))?;
    let before = systemd_invocation_link_snapshot_v1(&before);
    validate_systemd_invocation_link_snapshot_v1(before)?;

    let target = rustix_fs::readlinkat(
        &parent,
        CLN_SYSTEMD_INVOCATION_LINK_NAME_V1,
        Vec::with_capacity(33),
    )
    .map_err(|_| PreflightFailureV1::new(check, "invocation-link-unavailable"))?;

    let after = rustix_fs::statat(
        &parent,
        CLN_SYSTEMD_INVOCATION_LINK_NAME_V1,
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|_| PreflightFailureV1::new(check, "invocation-link-unavailable"))?;
    let after = systemd_invocation_link_snapshot_v1(&after);
    validate_systemd_invocation_link_snapshot_v1(after)?;
    if before != after {
        return Err(PreflightFailureV1::new(check, "generation-changed"));
    }

    let invocation_id = std::str::from_utf8(target.as_bytes())
        .map_err(|_| PreflightFailureV1::new(check, "invalid-invocation-id"))?
        .to_owned();
    validate_cln_invocation_id_v1(&invocation_id)?;
    Ok(invocation_id)
}

#[cfg(not(unix))]
fn read_cln_systemd_invocation_id_v1() -> Result<String, PreflightFailureV1> {
    Err(PreflightFailureV1::new(
        "systemd.cln-invocation",
        "unsupported-platform",
    ))
}

fn preflight_lease_file_config_v1(args: &LightningStagingPreflightArgs) -> BackupConfigV1 {
    BackupConfigV1 {
        receipt: PathBuf::from(PREFLIGHT_LEASE_PATH_V1),
        protected_parent: PathBuf::from(PREFLIGHT_LEASE_STATE_DIRECTORY_V1),
        expected_uid: args.config_reader_expected_uid,
        expected_gid: args.config_expected_gid,
        max_age_seconds: PREFLIGHT_LEASE_VALIDITY_SECONDS_V1,
    }
}

fn write_preflight_lease_v1(
    args: &LightningStagingPreflightArgs,
    lease: &PreflightLeaseV1,
) -> Result<(), PreflightFailureV1> {
    validate_preflight_lease_v1(lease)?;
    let mut bytes = toml::to_string(lease)
        .map_err(|_| PreflightFailureV1::new("lease.file", "serialize-failed"))?
        .into_bytes();
    let parsed: PreflightLeaseV1 = toml::from_str(
        std::str::from_utf8(&bytes)
            .map_err(|_| PreflightFailureV1::new("lease.file", "self-check-failed"))?,
    )
    .map_err(|_| PreflightFailureV1::new("lease.file", "self-check-failed"))?;
    if parsed != *lease {
        return Err(PreflightFailureV1::new("lease.file", "self-check-failed"));
    }
    let result = write_atomic_backup_receipt_v1(&preflight_lease_file_config_v1(args), &bytes)
        .map_err(|_| PreflightFailureV1::new("lease.file", "write-failed"));
    bytes.fill(0);
    result
}

fn validate_preflight_lease_v1(lease: &PreflightLeaseV1) -> Result<(), PreflightFailureV1> {
    validate_cln_invocation_id_v1(&lease.cln_invocation_id)?;
    if lease.schema_version != PREFLIGHT_LEASE_SCHEMA_V1
        || lease.checked_at_unix == 0
        || lease.valid_until_unix
            != lease
                .checked_at_unix
                .checked_add(PREFLIGHT_LEASE_VALIDITY_SECONDS_V1)
                .ok_or_else(|| PreflightFailureV1::new("lease.clock", "timestamp-overflow"))?
    {
        return Err(PreflightFailureV1::new("lease.file", "invalid-lease"));
    }
    Ok(())
}

fn remove_preflight_lease_best_effort_v1() {
    let _ = std::fs::remove_file(PREFLIGHT_LEASE_PATH_V1);
}

#[cfg(unix)]
fn validate_systemd_supervisor_environment_values_v1(
    watchdog_usec: Option<&std::ffi::OsStr>,
    watchdog_pid: Option<&std::ffi::OsStr>,
    notify_socket: Option<&std::ffi::OsStr>,
    current_pid: u32,
) -> Result<(), PreflightFailureV1> {
    let check = "systemd.watchdog";
    let watchdog_usec = watchdog_usec
        .and_then(std::ffi::OsStr::to_str)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| PreflightFailureV1::new(check, "invalid-watchdog-environment"))?;
    if watchdog_usec != PREFLIGHT_WATCHDOG_USEC_V1 {
        return Err(PreflightFailureV1::new(
            check,
            "invalid-watchdog-environment",
        ));
    }
    if let Some(value) = watchdog_pid {
        let pid = value
            .to_str()
            .ok_or_else(|| PreflightFailureV1::new(check, "invalid-watchdog-environment"))?
            .parse::<u32>()
            .map_err(|_| PreflightFailureV1::new(check, "invalid-watchdog-environment"))?;
        if pid != current_pid {
            return Err(PreflightFailureV1::new(
                check,
                "invalid-watchdog-environment",
            ));
        }
    }
    let notify_socket = notify_socket
        .ok_or_else(|| PreflightFailureV1::new("systemd.notify", "notify-socket-unavailable"))?;
    let socket_bytes = notify_socket.as_bytes();
    if socket_bytes.len() < 2
        || !matches!(socket_bytes[0], b'/' | b'@')
        || socket_bytes.contains(&0)
    {
        return Err(PreflightFailureV1::new(
            "systemd.notify",
            "invalid-notify-socket",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_systemd_supervisor_environment_values_v1(
    _watchdog_usec: Option<&std::ffi::OsStr>,
    _watchdog_pid: Option<&std::ffi::OsStr>,
    _notify_socket: Option<&std::ffi::OsStr>,
    _current_pid: u32,
) -> Result<(), PreflightFailureV1> {
    Err(PreflightFailureV1::new(
        "systemd.watchdog",
        "unsupported-platform",
    ))
}

fn validate_systemd_supervisor_environment_v1() -> Result<(), PreflightFailureV1> {
    let watchdog_usec = std::env::var_os("WATCHDOG_USEC");
    let watchdog_pid = std::env::var_os("WATCHDOG_PID");
    let notify_socket = std::env::var_os("NOTIFY_SOCKET");
    validate_systemd_supervisor_environment_values_v1(
        watchdog_usec.as_deref(),
        watchdog_pid.as_deref(),
        notify_socket.as_deref(),
        std::process::id(),
    )
}

#[cfg(unix)]
fn systemd_notify_to_v1(
    notify_socket: &std::ffi::OsStr,
    message: &[u8],
) -> Result<(), PreflightFailureV1> {
    use rustix::net::{
        sendto, socket_with, AddressFamily, SendFlags, SocketAddrUnix, SocketFlags, SocketType,
    };

    let check = "systemd.notify";
    if message.is_empty() || message.len() > 512 || message.contains(&0) {
        return Err(PreflightFailureV1::new(check, "invalid-notification"));
    }
    let socket_bytes = notify_socket.as_bytes();
    if socket_bytes.is_empty() {
        return Err(PreflightFailureV1::new(check, "notify-socket-unavailable"));
    }
    let address = if socket_bytes[0] == b'@' {
        #[cfg(target_os = "linux")]
        {
            SocketAddrUnix::new_abstract_name(&socket_bytes[1..])
                .map_err(|_| PreflightFailureV1::new(check, "invalid-notify-socket"))?
        }
        #[cfg(not(target_os = "linux"))]
        {
            return Err(PreflightFailureV1::new(check, "invalid-notify-socket"));
        }
    } else {
        if socket_bytes[0] != b'/' {
            return Err(PreflightFailureV1::new(check, "invalid-notify-socket"));
        }
        SocketAddrUnix::new(notify_socket)
            .map_err(|_| PreflightFailureV1::new(check, "invalid-notify-socket"))?
    };
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| PreflightFailureV1::new(check, "notify-failed"))?;
    let sent = sendto(&socket, message, SendFlags::empty(), &address)
        .map_err(|_| PreflightFailureV1::new(check, "notify-failed"))?;
    if sent != message.len() {
        return Err(PreflightFailureV1::new(check, "notify-failed"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn systemd_notify_to_v1(
    _notify_socket: &std::ffi::OsStr,
    _message: &[u8],
) -> Result<(), PreflightFailureV1> {
    Err(PreflightFailureV1::new(
        "systemd.notify",
        "unsupported-platform",
    ))
}

fn systemd_notify_v1(message: &[u8]) -> Result<(), PreflightFailureV1> {
    let notify_socket = std::env::var_os("NOTIFY_SOCKET")
        .ok_or_else(|| PreflightFailureV1::new("systemd.notify", "notify-socket-unavailable"))?;
    systemd_notify_to_v1(&notify_socket, message)
}

async fn run_bootstrap_preflight_v1<R: CommandRunnerV1>(
    config: &LightningStagingConfigV1,
    runner: &mut R,
) -> Result<BootstrapPreflightSuccessV1, PreflightFailureV1> {
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
    let snapshot = collect_bootstrap_snapshot_v1(config, runner).await?;
    validate_bootstrap_snapshot_v1(config, &ids, &snapshot)
}

fn parse_config_v1(bytes: &[u8]) -> Result<LightningStagingConfigV1, PreflightFailureV1> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| PreflightFailureV1::new("config.parse", "invalid-utf8"))?;
    toml::from_str(text).map_err(|_| PreflightFailureV1::new("config.parse", "invalid-toml"))
}

fn validate_backup_receipt_state_contract_v1(
    config: &LightningStagingConfigV1,
    config_expected_gid: u32,
    config_reader_expected_uid: u32,
) -> Result<(), PreflightFailureV1> {
    let check = "config.backup-state";
    if config.backup.protected_parent != Path::new(BACKUP_RECEIPT_STATE_DIRECTORY_V1)
        || config.backup.receipt != Path::new(BACKUP_RECEIPT_PATH_V1)
        || config.backup.expected_uid != config_reader_expected_uid
        || config.backup.expected_gid != config_expected_gid
        || config_reader_expected_uid == 0
        || config_expected_gid == 0
    {
        return Err(PreflightFailureV1::new(check, "invalid-state-boundary"));
    }
    Ok(())
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
    validate_core_rpc_cookie_access_policy_v1(&config.bitcoin.rpc_cookie)?;
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
    validate_lightning_rpc_access_policy_v1(&config.lightning)?;
    validate_preflight_identity_separation_v1(config)?;
    validate_systemd_busctl_config_v1(config)?;
    validate_absolute_utf8_path_v1(&config.backup.receipt, "config.backup-receipt")?;
    validate_absolute_utf8_path_v1(&config.backup.protected_parent, "config.backup-parent")?;
    Ok(ids)
}

fn validate_core_rpc_cookie_access_policy_v1(
    config: &CoreRpcCookieConfigV1,
) -> Result<(), PreflightFailureV1> {
    let check = "config.core-rpc-cookie-access";
    match (config.access_policy, &config.cross_uid_access) {
        (CoreRpcCookieAccessPolicyV1::SameUidOwnerOnly, None) => Ok(()),
        (CoreRpcCookieAccessPolicyV1::SameUidOwnerOnly, Some(_)) => Err(PreflightFailureV1::new(
            check,
            "cross-uid-fields-with-same-uid-policy",
        )),
        (CoreRpcCookieAccessPolicyV1::CrossUidSetgidSharedGroup, None) => {
            Err(PreflightFailureV1::new(check, "missing-cross-uid-fields"))
        }
        (CoreRpcCookieAccessPolicyV1::CrossUidSetgidSharedGroup, Some(cross_uid)) => {
            if cross_uid.protected_parent_expected_uid != 0
                || cross_uid.protected_parent_expected_gid != 0
                || cross_uid.preflight_expected_uid == 0
                || config.expected_uid == 0
                || config.expected_gid == 0
                || cross_uid.preflight_expected_uid == config.expected_uid
            {
                return Err(PreflightFailureV1::new(
                    check,
                    "invalid-cross-uid-identities",
                ));
            }
            Ok(())
        }
    }
}

fn validate_preflight_identity_separation_v1(
    config: &LightningStagingConfigV1,
) -> Result<(), PreflightFailureV1> {
    let check = "config.preflight-identities";
    let core_preflight_uid = match config.bitcoin.rpc_cookie.access_policy {
        CoreRpcCookieAccessPolicyV1::SameUidOwnerOnly => config.bitcoin.rpc_cookie.expected_uid,
        CoreRpcCookieAccessPolicyV1::CrossUidSetgidSharedGroup => {
            config
                .bitcoin
                .rpc_cookie
                .cross_uid_access
                .as_ref()
                .ok_or_else(|| PreflightFailureV1::new(check, "missing-core-cross-uid-fields"))?
                .preflight_expected_uid
        }
    };
    let lightning_preflight_uid = match config.lightning.rpc_access_policy {
        LightningRpcAccessPolicyV1::SameUidOwnerOnly => config.lightning.expected_uid,
        LightningRpcAccessPolicyV1::CrossUidSharedGroup => {
            config
                .lightning
                .cross_uid_access
                .as_ref()
                .ok_or_else(|| {
                    PreflightFailureV1::new(check, "missing-lightning-cross-uid-fields")
                })?
                .client_expected_uid
        }
    };
    if core_preflight_uid != lightning_preflight_uid {
        return Err(PreflightFailureV1::new(check, "preflight-uid-conflict"));
    }
    if config.bitcoin.rpc_cookie.access_policy
        == CoreRpcCookieAccessPolicyV1::CrossUidSetgidSharedGroup
        && (config.bitcoin.rpc_cookie.expected_uid == config.lightning.expected_uid
            || config.bitcoin.rpc_cookie.expected_gid == config.lightning.expected_gid)
    {
        return Err(PreflightFailureV1::new(
            check,
            "core-and-lightning-identities-not-separated",
        ));
    }
    Ok(())
}

fn validate_lightning_rpc_access_policy_v1(
    config: &LightningConfigV1,
) -> Result<(), PreflightFailureV1> {
    let check = "config.lightning-rpc-access";
    match (config.rpc_access_policy, &config.cross_uid_access) {
        (LightningRpcAccessPolicyV1::SameUidOwnerOnly, None) => Ok(()),
        (LightningRpcAccessPolicyV1::SameUidOwnerOnly, Some(_)) => Err(PreflightFailureV1::new(
            check,
            "cross-uid-fields-with-same-uid-policy",
        )),
        (LightningRpcAccessPolicyV1::CrossUidSharedGroup, None) => {
            Err(PreflightFailureV1::new(check, "missing-cross-uid-fields"))
        }
        (LightningRpcAccessPolicyV1::CrossUidSharedGroup, Some(cross_uid)) => {
            // V1 intentionally supports one unambiguous production shape.
            // Root owns the broad boundary, a non-root CLN daemon owns the
            // final directory/socket, and a distinct non-root preflight EUID
            // reaches it only through the non-root shared group.
            if cross_uid.protected_parent_expected_uid != 0
                || cross_uid.protected_parent_expected_gid != 0
                || cross_uid.client_expected_uid == 0
                || config.expected_uid == 0
                || config.expected_gid == 0
                || cross_uid.client_expected_uid == config.expected_uid
            {
                return Err(PreflightFailureV1::new(
                    check,
                    "invalid-cross-uid-identities",
                ));
            }
            Ok(())
        }
    }
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
    // Preallocate the bound once and scrub it on read, oversize and post-read
    // metadata failure paths so no abandoned partial buffer survives an error.
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
        args.config_reader_expected_uid,
    )
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ProtectedConfigRuntimeIdentityV1 {
    effective_uid: u32,
    effective_gid: u32,
    supplementary_gids: BTreeSet<u32>,
}

#[cfg(unix)]
fn current_protected_config_runtime_identity_v1(
    check: &'static str,
) -> Result<ProtectedConfigRuntimeIdentityV1, PreflightFailureV1> {
    let supplementary_gids = rustix::process::getgroups()
        .map_err(|_| PreflightFailureV1::new(check, "group-list-unavailable"))?
        .into_iter()
        .map(|gid| gid.as_raw())
        .collect();
    Ok(ProtectedConfigRuntimeIdentityV1 {
        effective_uid: rustix::process::geteuid().as_raw(),
        effective_gid: rustix::process::getegid().as_raw(),
        supplementary_gids,
    })
}

#[cfg(unix)]
fn validate_protected_config_runtime_identity_v1(
    config_expected_uid: u32,
    config_expected_gid: u32,
    config_reader_expected_uid: u32,
    runtime: &ProtectedConfigRuntimeIdentityV1,
    check: &'static str,
) -> Result<(), PreflightFailureV1> {
    // V1 has one production shape: immutable root-owned configuration made
    // readable to exactly one non-root service group. The reader identity is
    // pinned separately from the file owner so neither can be substituted for
    // the other at the command line.
    if config_expected_uid != 0 || config_expected_gid == 0 || config_reader_expected_uid == 0 {
        return Err(PreflightFailureV1::new(check, "invalid-access-policy"));
    }
    if runtime.effective_uid != config_reader_expected_uid {
        return Err(PreflightFailureV1::new(check, "runtime-uid-mismatch"));
    }
    if runtime.effective_gid != config_expected_gid
        && !runtime.supplementary_gids.contains(&config_expected_gid)
    {
        return Err(PreflightFailureV1::new(check, "shared-group-missing"));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_protected_config_runtime_group_set_for_identity_v1(
    config: &LightningStagingConfigV1,
    config_expected_gid: u32,
    config_reader_expected_uid: u32,
    runtime: &ProtectedConfigRuntimeIdentityV1,
    check: &'static str,
) -> Result<(), PreflightFailureV1> {
    if runtime.effective_uid != config_reader_expected_uid {
        return Err(PreflightFailureV1::new(check, "runtime-uid-mismatch"));
    }
    let mut expected = BTreeSet::from([config_expected_gid]);
    if config.bitcoin.rpc_cookie.access_policy
        == CoreRpcCookieAccessPolicyV1::CrossUidSetgidSharedGroup
    {
        expected.insert(config.bitcoin.rpc_cookie.expected_gid);
    }
    if config.lightning.rpc_access_policy == LightningRpcAccessPolicyV1::CrossUidSharedGroup {
        expected.insert(config.lightning.expected_gid);
    }
    let mut actual = runtime.supplementary_gids.clone();
    actual.insert(runtime.effective_gid);
    if actual != expected {
        return Err(PreflightFailureV1::new(check, "runtime-group-set-mismatch"));
    }
    Ok(())
}

fn validate_protected_config_runtime_group_set_v1(
    config: &LightningStagingConfigV1,
    config_expected_gid: u32,
    config_reader_expected_uid: u32,
) -> Result<(), PreflightFailureV1> {
    let check = "config.reader-groups";
    #[cfg(unix)]
    {
        let runtime = current_protected_config_runtime_identity_v1(check)?;
        validate_protected_config_runtime_group_set_for_identity_v1(
            config,
            config_expected_gid,
            config_reader_expected_uid,
            &runtime,
            check,
        )
    }
    #[cfg(not(unix))]
    {
        let _ = (config, config_expected_gid, config_reader_expected_uid);
        Err(PreflightFailureV1::new(check, "unsupported-platform"))
    }
}

#[cfg(unix)]
fn validate_protected_config_parent_metadata_v1(
    metadata: &std::fs::Metadata,
    check: &'static str,
) -> Result<(), PreflightFailureV1> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let mode = metadata.permissions().mode() & 0o7777;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != 0
        || mode & 0o022 != 0
    {
        return Err(PreflightFailureV1::new(check, "unsafe-protected-parent"));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_protected_config_file_metadata_v1(
    metadata: &std::fs::Metadata,
    config_expected_uid: u32,
    config_expected_gid: u32,
    check: &'static str,
) -> Result<(), PreflightFailureV1> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let mode = metadata.permissions().mode() & 0o7777;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != config_expected_uid
        || metadata.gid() != config_expected_gid
        || mode != 0o440
        || metadata.nlink() != 1
        || metadata.len() > MAX_CONFIG_BYTES_V1
    {
        return Err(PreflightFailureV1::new(check, "unsafe-metadata"));
    }
    Ok(())
}

#[cfg(unix)]
fn open_protected_config_parent_v1(
    path: &Path,
    check: &'static str,
) -> Result<File, PreflightFailureV1> {
    use rustix::fs::{self as rustix_fs, Mode, OFlags};

    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let root = rustix_fs::open("/", flags, Mode::empty())
        .map_err(|_| PreflightFailureV1::new(check, "open-ancestor-failed"))?;
    let mut current = File::from(root);
    validate_protected_config_parent_metadata_v1(
        &current
            .metadata()
            .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?,
        check,
    )?;
    pir_private_files::reject_extended_acl_v1(&current, "preflight config ancestor")
        .map_err(|_| PreflightFailureV1::new(check, "unsafe-parent-acl"))?;

    for component in path.components() {
        let name = match component {
            Component::RootDir => continue,
            Component::Normal(name) => name,
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(PreflightFailureV1::new(
                    check,
                    "invalid-protected-parent-layout",
                ));
            }
        };
        let next = rustix_fs::openat(&current, name, flags, Mode::empty())
            .map_err(|_| PreflightFailureV1::new(check, "open-ancestor-failed"))?;
        let next = File::from(next);
        validate_protected_config_parent_metadata_v1(
            &next
                .metadata()
                .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?,
            check,
        )?;
        pir_private_files::reject_extended_acl_v1(&next, "preflight config ancestor")
            .map_err(|_| PreflightFailureV1::new(check, "unsafe-parent-acl"))?;
        current = next;
    }
    Ok(current)
}

fn read_protected_config_at_v1(
    config: &Path,
    config_protected_parent: &Path,
    config_expected_uid: u32,
    config_expected_gid: u32,
    config_reader_expected_uid: u32,
) -> Result<Vec<u8>, PreflightFailureV1> {
    let check = "config.file";
    validate_absolute_utf8_path_v1(config, check)?;
    validate_absolute_utf8_path_v1(config_protected_parent, check)?;
    #[cfg(unix)]
    {
        use rustix::fs::{self as rustix_fs, Mode, OFlags};
        use std::os::unix::fs::MetadataExt;

        let runtime = current_protected_config_runtime_identity_v1(check)?;
        validate_protected_config_runtime_identity_v1(
            config_expected_uid,
            config_expected_gid,
            config_reader_expected_uid,
            &runtime,
            check,
        )?;
        if config.parent() != Some(config_protected_parent) {
            return Err(PreflightFailureV1::new(check, "invalid-config-layout"));
        }
        for path in [config_protected_parent, config] {
            let canonical = std::fs::canonicalize(path)
                .map_err(|_| PreflightFailureV1::new(check, "canonicalize-failed"))?;
            if canonical != path {
                return Err(PreflightFailureV1::new(check, "non-canonical-path"));
            }
        }

        let parent_before = std::fs::symlink_metadata(config_protected_parent)
            .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
        validate_protected_config_parent_metadata_v1(&parent_before, check)?;
        let named_before = std::fs::symlink_metadata(config)
            .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
        validate_protected_config_file_metadata_v1(
            &named_before,
            config_expected_uid,
            config_expected_gid,
            check,
        )?;

        let parent_file = open_protected_config_parent_v1(config_protected_parent, check)?;
        let parent_opened = parent_file
            .metadata()
            .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
        validate_same_file_v1(&parent_before, &parent_opened, check)?;
        validate_protected_config_parent_metadata_v1(&parent_opened, check)?;
        pir_private_files::reject_extended_acl_v1(&parent_file, "preflight config parent")
            .map_err(|_| PreflightFailureV1::new(check, "unsafe-parent-acl"))?;

        let config_name = config
            .file_name()
            .ok_or_else(|| PreflightFailureV1::new(check, "invalid-config-layout"))?;
        let fd = rustix_fs::openat(
            &parent_file,
            config_name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| PreflightFailureV1::new(check, "open-failed"))?;
        let mut file = File::from(fd);
        let opened_before = file
            .metadata()
            .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
        validate_same_file_v1(&named_before, &opened_before, check)?;
        if named_before.nlink() != opened_before.nlink() {
            return Err(PreflightFailureV1::new(check, "file-changed"));
        }
        validate_protected_config_file_metadata_v1(
            &opened_before,
            config_expected_uid,
            config_expected_gid,
            check,
        )?;
        pir_private_files::reject_extended_acl_v1(&file, "preflight config")
            .map_err(|_| PreflightFailureV1::new(check, "unsafe-config-acl"))?;

        let read_limit = MAX_CONFIG_BYTES_V1 + 1;
        let mut bytes = Zeroizing::new(Vec::with_capacity(read_limit as usize));
        file.by_ref()
            .take(read_limit)
            .read_to_end(&mut bytes)
            .map_err(|_| PreflightFailureV1::new(check, "read-failed"))?;
        if bytes.len() as u64 > MAX_CONFIG_BYTES_V1 || bytes.len() as u64 != opened_before.len() {
            return Err(PreflightFailureV1::new(check, "size-changed"));
        }

        let opened_after = file
            .metadata()
            .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
        validate_same_file_v1(&opened_before, &opened_after, check)?;
        validate_protected_config_file_metadata_v1(
            &opened_after,
            config_expected_uid,
            config_expected_gid,
            check,
        )?;
        pir_private_files::reject_extended_acl_v1(&file, "preflight config")
            .map_err(|_| PreflightFailureV1::new(check, "unsafe-config-acl"))?;

        let named_after = std::fs::symlink_metadata(config)
            .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
        let parent_after = std::fs::symlink_metadata(config_protected_parent)
            .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
        validate_same_file_v1(&named_before, &named_after, check)?;
        validate_same_file_v1(&named_after, &opened_after, check)?;
        validate_same_file_v1(&parent_before, &parent_after, check)?;
        if named_after.nlink() != 1 {
            return Err(PreflightFailureV1::new(check, "file-changed"));
        }
        validate_protected_config_parent_metadata_v1(&parent_after, check)?;
        validate_protected_config_file_metadata_v1(
            &named_after,
            config_expected_uid,
            config_expected_gid,
            check,
        )?;
        Ok(std::mem::take(&mut *bytes))
    }
    #[cfg(not(unix))]
    {
        let _ = (
            config,
            config_protected_parent,
            config_expected_uid,
            config_expected_gid,
            config_reader_expected_uid,
        );
        Err(PreflightFailureV1::new(check, "unsupported-platform"))
    }
}

fn validate_core_rpc_cookie_v1(config: &CoreRpcCookieConfigV1) -> Result<(), PreflightFailureV1> {
    let check = "core.rpc-cookie";
    #[cfg(unix)]
    {
        let bytes = read_validated_core_rpc_cookie_with_hook_v1(config, || Ok(()))?;
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

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct CoreRpcCookieRuntimeIdentityV1 {
    effective_uid: u32,
    effective_gid: u32,
    supplementary_gids: BTreeSet<u32>,
}

#[cfg(unix)]
fn current_core_rpc_cookie_runtime_identity_v1(
    check: &'static str,
) -> Result<CoreRpcCookieRuntimeIdentityV1, PreflightFailureV1> {
    let supplementary_gids = rustix::process::getgroups()
        .map_err(|_| PreflightFailureV1::new(check, "group-list-unavailable"))?
        .into_iter()
        .map(|gid| gid.as_raw())
        .collect();
    Ok(CoreRpcCookieRuntimeIdentityV1 {
        effective_uid: rustix::process::geteuid().as_raw(),
        effective_gid: rustix::process::getegid().as_raw(),
        supplementary_gids,
    })
}

#[cfg(unix)]
fn validate_core_rpc_cookie_runtime_identity_v1(
    config: &CoreRpcCookieConfigV1,
    runtime: &CoreRpcCookieRuntimeIdentityV1,
) -> Result<(), PreflightFailureV1> {
    let check = "core.rpc-cookie";
    match config.access_policy {
        CoreRpcCookieAccessPolicyV1::SameUidOwnerOnly => {
            if runtime.effective_uid != config.expected_uid {
                return Err(PreflightFailureV1::new(check, "runtime-uid-mismatch"));
            }
        }
        CoreRpcCookieAccessPolicyV1::CrossUidSetgidSharedGroup => {
            let cross_uid = config
                .cross_uid_access
                .as_ref()
                .ok_or_else(|| PreflightFailureV1::new(check, "missing-cross-uid-fields"))?;
            if runtime.effective_uid != cross_uid.preflight_expected_uid {
                return Err(PreflightFailureV1::new(check, "runtime-uid-mismatch"));
            }
            if runtime.effective_gid != config.expected_gid
                && !runtime.supplementary_gids.contains(&config.expected_gid)
            {
                return Err(PreflightFailureV1::new(check, "shared-group-missing"));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CoreRpcCookieBoundaryKindV1 {
    Directory,
    RegularFile,
    Other,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CoreRpcCookieBoundaryMetadataV1 {
    kind: CoreRpcCookieBoundaryKindV1,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
    size: u64,
}

#[cfg(unix)]
fn core_rpc_cookie_boundary_metadata_v1(
    metadata: &std::fs::Metadata,
) -> CoreRpcCookieBoundaryMetadataV1 {
    use std::os::unix::fs::MetadataExt;
    let kind = if metadata.file_type().is_dir() {
        CoreRpcCookieBoundaryKindV1::Directory
    } else if metadata.is_file() {
        CoreRpcCookieBoundaryKindV1::RegularFile
    } else {
        CoreRpcCookieBoundaryKindV1::Other
    };
    CoreRpcCookieBoundaryMetadataV1 {
        kind,
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode() & 0o7777,
        nlink: metadata.nlink(),
        size: metadata.len(),
    }
}

#[cfg(unix)]
fn validate_core_rpc_cookie_file_metadata_v1(
    config: &CoreRpcCookieConfigV1,
    metadata: CoreRpcCookieBoundaryMetadataV1,
    check: &'static str,
) -> Result<(), PreflightFailureV1> {
    let expected_mode = match config.access_policy {
        CoreRpcCookieAccessPolicyV1::SameUidOwnerOnly => 0o600,
        CoreRpcCookieAccessPolicyV1::CrossUidSetgidSharedGroup => 0o640,
    };
    if metadata.kind != CoreRpcCookieBoundaryKindV1::RegularFile
        || metadata.uid != config.expected_uid
        || metadata.gid != config.expected_gid
        || metadata.mode != expected_mode
        || metadata.nlink != 1
        || metadata.size == 0
        || metadata.size > MAX_CORE_COOKIE_BYTES_V1
    {
        return Err(PreflightFailureV1::new(check, "unsafe-metadata"));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_core_rpc_cookie_boundary_metadata_v1(
    config: &CoreRpcCookieConfigV1,
    protected_parent: CoreRpcCookieBoundaryMetadataV1,
    final_parent: CoreRpcCookieBoundaryMetadataV1,
    cookie: CoreRpcCookieBoundaryMetadataV1,
    check: &'static str,
) -> Result<(), PreflightFailureV1> {
    if config.access_policy == CoreRpcCookieAccessPolicyV1::CrossUidSetgidSharedGroup {
        let cross_uid = config
            .cross_uid_access
            .as_ref()
            .ok_or_else(|| PreflightFailureV1::new(check, "missing-cross-uid-fields"))?;
        if protected_parent.kind != CoreRpcCookieBoundaryKindV1::Directory
            || protected_parent.uid != cross_uid.protected_parent_expected_uid
            || protected_parent.gid != cross_uid.protected_parent_expected_gid
            || protected_parent.mode != 0o755
        {
            return Err(PreflightFailureV1::new(check, "unsafe-protected-parent"));
        }
    }
    let expected_final_mode = match config.access_policy {
        CoreRpcCookieAccessPolicyV1::SameUidOwnerOnly => 0o700,
        CoreRpcCookieAccessPolicyV1::CrossUidSetgidSharedGroup => 0o2710,
    };
    if final_parent.kind != CoreRpcCookieBoundaryKindV1::Directory
        || final_parent.uid != config.expected_uid
        || final_parent.gid != config.expected_gid
        || final_parent.mode != expected_final_mode
    {
        return Err(PreflightFailureV1::new(check, "unsafe-directory"));
    }
    validate_core_rpc_cookie_file_metadata_v1(config, cookie, check)
}

#[cfg(unix)]
fn validate_canonical_core_rpc_cookie_layout_v1(
    config: &CoreRpcCookieConfigV1,
    check: &'static str,
) -> Result<PathBuf, PreflightFailureV1> {
    let final_parent = config
        .path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| PreflightFailureV1::new(check, "invalid-cookie-layout"))?
        .to_path_buf();
    let relative = config
        .path
        .strip_prefix(&config.protected_parent)
        .map_err(|_| PreflightFailureV1::new(check, "outside-protected-parent"))?;
    let components = relative.components().collect::<Vec<_>>();
    if components.is_empty()
        || !components
            .iter()
            .all(|component| matches!(component, Component::Normal(_)))
        || (config.access_policy == CoreRpcCookieAccessPolicyV1::CrossUidSetgidSharedGroup
            && components.len() != 2)
    {
        return Err(PreflightFailureV1::new(check, "invalid-cookie-layout"));
    }
    for path in [
        config.protected_parent.as_path(),
        final_parent.as_path(),
        config.path.as_path(),
    ] {
        let canonical = std::fs::canonicalize(path)
            .map_err(|_| PreflightFailureV1::new(check, "canonicalize-failed"))?;
        if canonical != path {
            return Err(PreflightFailureV1::new(check, "non-canonical-path"));
        }
    }
    Ok(final_parent)
}

#[cfg(unix)]
fn validate_same_core_rpc_cookie_entry_v1(
    before: &std::fs::Metadata,
    after: &std::fs::Metadata,
    check: &'static str,
) -> Result<(), PreflightFailureV1> {
    use std::os::unix::fs::MetadataExt;
    validate_same_file_v1(before, after, check)?;
    if before.nlink() != after.nlink() {
        return Err(PreflightFailureV1::new(check, "file-changed"));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_core_rpc_cookie_namespace_v1(
    config: &CoreRpcCookieConfigV1,
    final_parent: &Path,
    protected_parent: &std::fs::Metadata,
    final_parent_metadata: &std::fs::Metadata,
    cookie: &std::fs::Metadata,
    check: &'static str,
) -> Result<(), PreflightFailureV1> {
    if config.access_policy == CoreRpcCookieAccessPolicyV1::SameUidOwnerOnly {
        validate_protected_tree_v1(
            &config.protected_parent,
            &config.path,
            config.expected_uid,
            config.expected_gid,
            true,
            check,
        )?;
    }
    validate_core_rpc_cookie_boundary_metadata_v1(
        config,
        core_rpc_cookie_boundary_metadata_v1(protected_parent),
        core_rpc_cookie_boundary_metadata_v1(final_parent_metadata),
        core_rpc_cookie_boundary_metadata_v1(cookie),
        check,
    )?;
    let checked_path = match config.access_policy {
        CoreRpcCookieAccessPolicyV1::SameUidOwnerOnly => {
            pir_private_files::prepare_private_unix_socket_parent_v1(
                &config.path,
                config.expected_uid,
                None,
                "Core RPC cookie",
            )
        }
        CoreRpcCookieAccessPolicyV1::CrossUidSetgidSharedGroup => {
            pir_private_files::prepare_private_setgid_group_file_parent_v1(
                &config.path,
                config.expected_uid,
                config.expected_gid,
                "Core RPC cookie",
            )
        }
    }
    .map_err(|_| PreflightFailureV1::new(check, "unsafe-parent-boundary"))?;
    if checked_path != config.path || config.path.parent() != Some(final_parent) {
        return Err(PreflightFailureV1::new(check, "path-changed"));
    }
    Ok(())
}

#[cfg(unix)]
fn read_validated_core_rpc_cookie_with_hook_v1<F>(
    config: &CoreRpcCookieConfigV1,
    after_read: F,
) -> Result<Zeroizing<Vec<u8>>, PreflightFailureV1>
where
    F: FnOnce() -> Result<(), PreflightFailureV1>,
{
    use rustix::fs::{self as rustix_fs, Mode, OFlags};

    let check = "core.rpc-cookie";
    validate_core_rpc_cookie_access_policy_v1(config)?;
    let runtime = current_core_rpc_cookie_runtime_identity_v1(check)?;
    validate_core_rpc_cookie_runtime_identity_v1(config, &runtime)?;
    let final_parent = validate_canonical_core_rpc_cookie_layout_v1(config, check)?;
    let protected_parent_before = std::fs::symlink_metadata(&config.protected_parent)
        .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
    let final_parent_before = std::fs::symlink_metadata(&final_parent)
        .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
    let cookie_named_before = std::fs::symlink_metadata(&config.path)
        .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
    validate_core_rpc_cookie_namespace_v1(
        config,
        &final_parent,
        &protected_parent_before,
        &final_parent_before,
        &cookie_named_before,
        check,
    )?;

    let fd = rustix_fs::open(
        &config.path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| PreflightFailureV1::new(check, "open-failed"))?;
    let mut file = File::from(fd);
    let opened_before = file
        .metadata()
        .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
    validate_same_core_rpc_cookie_entry_v1(&cookie_named_before, &opened_before, check)?;
    validate_core_rpc_cookie_file_metadata_v1(
        config,
        core_rpc_cookie_boundary_metadata_v1(&opened_before),
        check,
    )?;
    pir_private_files::reject_extended_acl_v1(&file, "Core RPC cookie")
        .map_err(|_| PreflightFailureV1::new(check, "unsafe-cookie-acl"))?;

    let read_limit = MAX_CORE_COOKIE_BYTES_V1 + 1;
    let mut bytes = Zeroizing::new(Vec::with_capacity(read_limit as usize));
    file.by_ref()
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| PreflightFailureV1::new(check, "read-failed"))?;
    if bytes.len() as u64 > MAX_CORE_COOKIE_BYTES_V1 {
        return Err(PreflightFailureV1::new(check, "oversize"));
    }
    if bytes.len() as u64 != opened_before.len() {
        return Err(PreflightFailureV1::new(check, "size-changed"));
    }

    after_read()?;

    file.seek(SeekFrom::Start(0))
        .map_err(|_| PreflightFailureV1::new(check, "seek-failed"))?;
    let mut confirmed_bytes = Zeroizing::new(Vec::with_capacity(read_limit as usize));
    file.by_ref()
        .take(read_limit)
        .read_to_end(&mut confirmed_bytes)
        .map_err(|_| PreflightFailureV1::new(check, "read-failed"))?;
    if confirmed_bytes.len() as u64 > MAX_CORE_COOKIE_BYTES_V1 {
        return Err(PreflightFailureV1::new(check, "oversize"));
    }
    if confirmed_bytes.len() != bytes.len() {
        return Err(PreflightFailureV1::new(check, "size-changed"));
    }
    if confirmed_bytes.as_slice() != bytes.as_slice() {
        return Err(PreflightFailureV1::new(check, "content-changed"));
    }

    let opened_after = file
        .metadata()
        .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
    validate_same_core_rpc_cookie_entry_v1(&opened_before, &opened_after, check)?;
    validate_core_rpc_cookie_file_metadata_v1(
        config,
        core_rpc_cookie_boundary_metadata_v1(&opened_after),
        check,
    )?;
    if bytes.len() as u64 != opened_after.len() {
        return Err(PreflightFailureV1::new(check, "size-changed"));
    }
    pir_private_files::reject_extended_acl_v1(&file, "Core RPC cookie")
        .map_err(|_| PreflightFailureV1::new(check, "unsafe-cookie-acl"))?;

    let protected_parent_after = std::fs::symlink_metadata(&config.protected_parent)
        .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
    let final_parent_after = std::fs::symlink_metadata(&final_parent)
        .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
    let cookie_named_after = std::fs::symlink_metadata(&config.path)
        .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
    validate_same_core_rpc_cookie_entry_v1(
        &protected_parent_before,
        &protected_parent_after,
        check,
    )?;
    validate_same_core_rpc_cookie_entry_v1(&final_parent_before, &final_parent_after, check)?;
    validate_same_core_rpc_cookie_entry_v1(&cookie_named_before, &cookie_named_after, check)?;
    validate_same_core_rpc_cookie_entry_v1(&cookie_named_after, &opened_after, check)?;
    let final_parent_after_path = validate_canonical_core_rpc_cookie_layout_v1(config, check)?;
    if final_parent_after_path != final_parent {
        return Err(PreflightFailureV1::new(check, "path-changed"));
    }
    validate_core_rpc_cookie_namespace_v1(
        config,
        &final_parent,
        &protected_parent_after,
        &final_parent_after,
        &cookie_named_after,
        check,
    )?;
    Ok(bytes)
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
    let check = "filesystem.lightning-rpc";
    validate_lightning_rpc_access_policy_v1(config)?;
    let runtime = current_lightning_runtime_identity_v1(check)?;
    validate_lightning_runtime_identity_v1(config, &runtime)?;

    let final_parent = validate_canonical_lightning_socket_layout_v1(config, check)?;
    let protected_parent_before = std::fs::symlink_metadata(&config.protected_parent)
        .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
    let final_parent_before = std::fs::symlink_metadata(&final_parent)
        .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
    let socket_before = std::fs::symlink_metadata(&config.rpc_socket)
        .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;

    match config.rpc_access_policy {
        LightningRpcAccessPolicyV1::SameUidOwnerOnly => {
            // Preserve the V1 same-owner protected-tree pin while adding the
            // fd-walked final-parent/ACL and exact-mode checks below.
            validate_protected_tree_v1(
                &config.protected_parent,
                &config.rpc_socket,
                config.expected_uid,
                config.expected_gid,
                false,
                check,
            )?;
        }
        LightningRpcAccessPolicyV1::CrossUidSharedGroup => {
            validate_cross_uid_boundary_metadata_v1(
                config,
                lightning_boundary_metadata_v1(&protected_parent_before),
                lightning_boundary_metadata_v1(&final_parent_before),
                lightning_boundary_metadata_v1(&socket_before),
                check,
            )?;
        }
    }

    validate_lightning_socket_metadata_v1(
        config,
        lightning_boundary_metadata_v1(&socket_before),
        check,
    )?;

    // This component-by-component O_NOFOLLOW walk checks every ancestor and
    // the final socket parent, including the platform ACL policy. Same-UID
    // requires exact 0700; cross-UID requires exact CLN:GID 0710.
    let shared_gid = match config.rpc_access_policy {
        LightningRpcAccessPolicyV1::SameUidOwnerOnly => None,
        LightningRpcAccessPolicyV1::CrossUidSharedGroup => Some(config.expected_gid),
    };
    let checked_path = pir_private_files::prepare_private_unix_socket_parent_v1(
        &config.rpc_socket,
        config.expected_uid,
        shared_gid,
        "Lightning staging RPC socket",
    )
    .map_err(|_| PreflightFailureV1::new(check, "unsafe-parent-boundary"))?;
    if checked_path != config.rpc_socket {
        return Err(PreflightFailureV1::new(check, "path-changed"));
    }

    let protected_parent_after = std::fs::symlink_metadata(&config.protected_parent)
        .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
    let final_parent_after = std::fs::symlink_metadata(&final_parent)
        .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
    let socket_after = std::fs::symlink_metadata(&config.rpc_socket)
        .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
    validate_same_lightning_boundary_entry_v1(
        &protected_parent_before,
        &protected_parent_after,
        check,
    )?;
    validate_same_lightning_boundary_entry_v1(&final_parent_before, &final_parent_after, check)?;
    validate_same_lightning_boundary_entry_v1(&socket_before, &socket_after, check)?;

    match config.rpc_access_policy {
        LightningRpcAccessPolicyV1::SameUidOwnerOnly => {}
        LightningRpcAccessPolicyV1::CrossUidSharedGroup => {
            validate_cross_uid_boundary_metadata_v1(
                config,
                lightning_boundary_metadata_v1(&protected_parent_after),
                lightning_boundary_metadata_v1(&final_parent_after),
                lightning_boundary_metadata_v1(&socket_after),
                check,
            )?;
        }
    }
    validate_lightning_socket_metadata_v1(
        config,
        lightning_boundary_metadata_v1(&socket_after),
        check,
    )?;
    Ok(())
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct LightningRuntimeIdentityV1 {
    effective_uid: u32,
    effective_gid: u32,
    supplementary_gids: BTreeSet<u32>,
}

#[cfg(unix)]
fn current_lightning_runtime_identity_v1(
    check: &'static str,
) -> Result<LightningRuntimeIdentityV1, PreflightFailureV1> {
    let supplementary_gids = rustix::process::getgroups()
        .map_err(|_| PreflightFailureV1::new(check, "group-list-unavailable"))?
        .into_iter()
        .map(|gid| gid.as_raw())
        .collect();
    Ok(LightningRuntimeIdentityV1 {
        effective_uid: rustix::process::geteuid().as_raw(),
        effective_gid: rustix::process::getegid().as_raw(),
        supplementary_gids,
    })
}

#[cfg(unix)]
fn validate_lightning_runtime_identity_v1(
    config: &LightningConfigV1,
    runtime: &LightningRuntimeIdentityV1,
) -> Result<(), PreflightFailureV1> {
    let check = "filesystem.lightning-rpc";
    match config.rpc_access_policy {
        LightningRpcAccessPolicyV1::SameUidOwnerOnly => {
            if runtime.effective_uid != config.expected_uid {
                return Err(PreflightFailureV1::new(check, "runtime-uid-mismatch"));
            }
        }
        LightningRpcAccessPolicyV1::CrossUidSharedGroup => {
            let cross_uid = config
                .cross_uid_access
                .as_ref()
                .ok_or_else(|| PreflightFailureV1::new(check, "missing-cross-uid-fields"))?;
            if runtime.effective_uid != cross_uid.client_expected_uid {
                return Err(PreflightFailureV1::new(check, "runtime-uid-mismatch"));
            }
            if runtime.effective_gid != config.expected_gid
                && !runtime.supplementary_gids.contains(&config.expected_gid)
            {
                return Err(PreflightFailureV1::new(check, "shared-group-missing"));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LightningBoundaryKindV1 {
    Directory,
    Socket,
    Other,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LightningBoundaryMetadataV1 {
    kind: LightningBoundaryKindV1,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
}

#[cfg(unix)]
fn lightning_boundary_metadata_v1(metadata: &std::fs::Metadata) -> LightningBoundaryMetadataV1 {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let kind = if metadata.file_type().is_dir() {
        LightningBoundaryKindV1::Directory
    } else if metadata.file_type().is_socket() {
        LightningBoundaryKindV1::Socket
    } else {
        LightningBoundaryKindV1::Other
    };
    LightningBoundaryMetadataV1 {
        kind,
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode() & 0o7777,
        nlink: metadata.nlink(),
    }
}

#[cfg(unix)]
fn validate_cross_uid_boundary_metadata_v1(
    config: &LightningConfigV1,
    protected_parent: LightningBoundaryMetadataV1,
    final_parent: LightningBoundaryMetadataV1,
    socket: LightningBoundaryMetadataV1,
    check: &'static str,
) -> Result<(), PreflightFailureV1> {
    let cross_uid = config
        .cross_uid_access
        .as_ref()
        .ok_or_else(|| PreflightFailureV1::new(check, "missing-cross-uid-fields"))?;
    if protected_parent.kind != LightningBoundaryKindV1::Directory
        || protected_parent.uid != cross_uid.protected_parent_expected_uid
        || protected_parent.gid != cross_uid.protected_parent_expected_gid
        || protected_parent.mode != 0o755
    {
        return Err(PreflightFailureV1::new(check, "unsafe-protected-parent"));
    }
    if final_parent.kind != LightningBoundaryKindV1::Directory
        || final_parent.uid != config.expected_uid
        || final_parent.gid != config.expected_gid
        || final_parent.mode != 0o710
    {
        return Err(PreflightFailureV1::new(check, "unsafe-directory"));
    }
    validate_lightning_socket_metadata_v1(config, socket, check)
}

#[cfg(unix)]
fn validate_lightning_socket_metadata_v1(
    config: &LightningConfigV1,
    socket: LightningBoundaryMetadataV1,
    check: &'static str,
) -> Result<(), PreflightFailureV1> {
    let expected_mode = match config.rpc_access_policy {
        LightningRpcAccessPolicyV1::SameUidOwnerOnly => 0o600,
        LightningRpcAccessPolicyV1::CrossUidSharedGroup => 0o660,
    };
    if socket.kind != LightningBoundaryKindV1::Socket
        || socket.uid != config.expected_uid
        || socket.gid != config.expected_gid
        || socket.mode != expected_mode
        || socket.nlink != 1
    {
        return Err(PreflightFailureV1::new(check, "unsafe-socket"));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_canonical_lightning_socket_layout_v1(
    config: &LightningConfigV1,
    check: &'static str,
) -> Result<PathBuf, PreflightFailureV1> {
    let final_parent = config
        .rpc_socket
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| PreflightFailureV1::new(check, "invalid-socket-layout"))?
        .to_path_buf();
    if config.rpc_access_policy == LightningRpcAccessPolicyV1::CrossUidSharedGroup {
        let relative = config
            .rpc_socket
            .strip_prefix(&config.protected_parent)
            .map_err(|_| PreflightFailureV1::new(check, "outside-protected-parent"))?;
        let components = relative.components().collect::<Vec<_>>();
        if components.len() != 2
            || !components
                .iter()
                .all(|component| matches!(component, Component::Normal(_)))
        {
            return Err(PreflightFailureV1::new(check, "invalid-cross-uid-layout"));
        }
    }
    for path in [
        config.protected_parent.as_path(),
        final_parent.as_path(),
        config.rpc_socket.as_path(),
    ] {
        let canonical = std::fs::canonicalize(path)
            .map_err(|_| PreflightFailureV1::new(check, "canonicalize-failed"))?;
        if canonical != path {
            return Err(PreflightFailureV1::new(check, "non-canonical-path"));
        }
    }
    Ok(final_parent)
}

#[cfg(unix)]
fn validate_same_lightning_boundary_entry_v1(
    before: &std::fs::Metadata,
    after: &std::fs::Metadata,
    check: &'static str,
) -> Result<(), PreflightFailureV1> {
    use std::os::unix::fs::MetadataExt;
    validate_same_file_v1(before, after, check)?;
    if before.nlink() != after.nlink() {
        return Err(PreflightFailureV1::new(check, "file-changed"));
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
        let state_directory_metadata = std::fs::symlink_metadata(&config.protected_parent)
            .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
        validate_backup_receipt_state_directory_metadata_v1(
            &state_directory_metadata,
            config,
            check,
            "unsafe-protected-parent",
        )?;
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
        let mode = metadata.permissions().mode() & 0o7777;
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
fn validate_backup_receipt_state_directory_metadata_v1(
    metadata: &std::fs::Metadata,
    config: &BackupConfigV1,
    check: &'static str,
    reason: &'static str,
) -> Result<(), PreflightFailureV1> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != config.expected_uid
        || metadata.gid() != config.expected_gid
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(PreflightFailureV1::new(check, reason));
    }
    Ok(())
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
        || stat.st_mode & 0o7777 != 0o600
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
    use std::os::unix::fs::MetadataExt;

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
    validate_backup_receipt_state_directory_metadata_v1(
        &metadata,
        config,
        check,
        "unsafe-output-parent",
    )?;
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
        || opened.st_mode & 0o7777 != 0o700
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
    use std::os::unix::fs::MetadataExt;

    let check = "backup.receipt-file";
    let named = std::fs::symlink_metadata(target_parent)
        .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
    let opened = rustix_fs::fstat(parent)
        .map_err(|_| PreflightFailureV1::new(check, "metadata-unavailable"))?;
    if validate_backup_receipt_state_directory_metadata_v1(
        &named,
        config,
        check,
        "output-parent-changed",
    )
    .is_err()
        || !FileType::from_raw_mode(opened.st_mode).is_dir()
        || opened.st_uid != config.expected_uid
        || opened.st_gid != config.expected_gid
        || opened.st_mode & 0o7777 != 0o700
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
    write_atomic_backup_receipt_with_hook_v1(config, bytes, |_| Ok(()))
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
    F: FnOnce(&File) -> Result<(), PreflightFailureV1>,
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
                || stat.st_mode & 0o7777 != 0o600
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
            before_commit(&parent)?;
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

async fn collect_bootstrap_snapshot_v1<R: CommandRunnerV1>(
    config: &LightningStagingConfigV1,
    runner: &mut R,
) -> Result<BootstrapPreflightSnapshotV1, PreflightFailureV1> {
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
    let funds: ClnListFundsV1 = run_cln_json_v1(
        runner,
        config,
        "rpc.cln.listfunds",
        &["listfunds"],
        command_timeout,
    )
    .await?;
    let (_, scb_count) = run_cln_staticbackup_allow_empty_v1(
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
    Ok(BootstrapPreflightSnapshotV1 {
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
        plugins: plugin_list.plugins,
        peer_channel_count: peer_channels.channels.len(),
        onchain_output_count: funds.outputs.len(),
        funding_channel_count: funds.channels.len(),
        scb_count,
    })
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
        plugins: plugin_list.plugins,
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
    run_cln_staticbackup_with_empty_policy_v1(runner, config, check, tail, command_timeout, false)
        .await
}

async fn run_cln_staticbackup_allow_empty_v1<R: CommandRunnerV1>(
    runner: &mut R,
    config: &LightningStagingConfigV1,
    check: &'static str,
    tail: &[&str],
    command_timeout: Duration,
) -> Result<([u8; 32], usize), PreflightFailureV1> {
    run_cln_staticbackup_with_empty_policy_v1(runner, config, check, tail, command_timeout, true)
        .await
}

async fn run_cln_staticbackup_with_empty_policy_v1<R: CommandRunnerV1>(
    runner: &mut R,
    config: &LightningStagingConfigV1,
    check: &'static str,
    tail: &[&str],
    command_timeout: Duration,
    allow_empty: bool,
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
    if allow_empty {
        digest_staticbackup_with_empty_policy_v1(&staticbackup.scb, true)
    } else {
        digest_staticbackup_v1(&staticbackup.scb)
    }
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
    digest_staticbackup_with_empty_policy_v1(encoded_entries, false)
}

fn digest_staticbackup_with_empty_policy_v1<S: AsRef<str>>(
    encoded_entries: &[S],
    allow_empty: bool,
) -> Result<([u8; 32], usize), PreflightFailureV1> {
    if (!allow_empty && encoded_entries.is_empty()) || encoded_entries.len() > MAX_SCB_COUNT_V1 {
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

struct RuntimeSnapshotViewV1<'a> {
    core_version: u64,
    core_subversion: &'a str,
    core_chain: &'a str,
    core_blocks: u64,
    core_headers: u64,
    core_ibd: bool,
    signet_challenge: Option<&'a str>,
    genesis_hash: &'a str,
    cln_id: &'a str,
    cln_version: &'a str,
    cln_network: &'a str,
    cln_blockheight: u64,
    plugins: &'a [ClnPluginV1],
}

fn validate_runtime_snapshot_v1(
    config: &LightningStagingConfigV1,
    ids: &NodeIdsV1,
    snapshot: RuntimeSnapshotViewV1<'_>,
) -> Result<(), PreflightFailureV1> {
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
    let cln_id = normalize_node_id_v1(snapshot.cln_id)
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
    validate_plugins_v1(config, snapshot.plugins)
}

fn validate_bootstrap_snapshot_v1(
    config: &LightningStagingConfigV1,
    ids: &NodeIdsV1,
    snapshot: &BootstrapPreflightSnapshotV1,
) -> Result<BootstrapPreflightSuccessV1, PreflightFailureV1> {
    validate_runtime_snapshot_v1(
        config,
        ids,
        RuntimeSnapshotViewV1 {
            core_version: snapshot.core_version,
            core_subversion: &snapshot.core_subversion,
            core_chain: &snapshot.core_chain,
            core_blocks: snapshot.core_blocks,
            core_headers: snapshot.core_headers,
            core_ibd: snapshot.core_ibd,
            signet_challenge: snapshot.signet_challenge.as_deref(),
            genesis_hash: &snapshot.genesis_hash,
            cln_id: &snapshot.cln_id,
            cln_version: &snapshot.cln_version,
            cln_network: &snapshot.cln_network,
            cln_blockheight: snapshot.cln_blockheight,
            plugins: &snapshot.plugins,
        },
    )?;
    if snapshot.peer_channel_count != 0 {
        return Err(PreflightFailureV1::new(
            "lightning.bootstrap",
            "existing-peer-channels",
        ));
    }
    if snapshot.onchain_output_count != 0 || snapshot.funding_channel_count != 0 {
        return Err(PreflightFailureV1::new(
            "lightning.bootstrap",
            "existing-wallet-funds",
        ));
    }
    if snapshot.scb_count != 0 {
        return Err(PreflightFailureV1::new(
            "lightning.bootstrap",
            "existing-staticbackup",
        ));
    }
    Ok(BootstrapPreflightSuccessV1 {
        role: config.role,
        bitcoin_height: snapshot.core_blocks,
        cln_height: snapshot.cln_blockheight,
        plugin_count: snapshot.plugins.len(),
    })
}

fn validate_snapshot_v1(
    config: &LightningStagingConfigV1,
    ids: &NodeIdsV1,
    snapshot: &PreflightSnapshotV1,
    receipt: &BackupReceiptV1,
    now_unix: u64,
) -> Result<PreflightSuccessV1, PreflightFailureV1> {
    validate_runtime_snapshot_v1(
        config,
        ids,
        RuntimeSnapshotViewV1 {
            core_version: snapshot.core_version,
            core_subversion: &snapshot.core_subversion,
            core_chain: &snapshot.core_chain,
            core_blocks: snapshot.core_blocks,
            core_headers: snapshot.core_headers,
            core_ibd: snapshot.core_ibd,
            signet_challenge: snapshot.signet_challenge.as_deref(),
            genesis_hash: &snapshot.genesis_hash,
            cln_id: &snapshot.cln_id,
            cln_version: &snapshot.cln_version,
            cln_network: &snapshot.cln_network,
            cln_blockheight: snapshot.cln_blockheight,
            plugins: &snapshot.plugins,
        },
    )?;
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
        backup_receipt_recorded_at_unix: receipt.recorded_at_unix,
    })
}

fn validate_plugins_v1(
    config: &LightningStagingConfigV1,
    actual: &[ClnPluginV1],
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
    for plugin in actual {
        if plugin.name.len() > 4096
            || observed
                .insert(plugin.name.as_str(), (plugin.active, plugin.dynamic))
                .is_some()
        {
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
    if observed.values().any(|(_, dynamic)| *dynamic) {
        return Err(PreflightFailureV1::new(
            "lightning.plugins",
            "plugin-dynamic",
        ));
    }
    if observed.values().any(|(active, _)| !active) {
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
    validate_backup_receipt_age_v1(
        receipt.recorded_at_unix,
        config.backup.max_age_seconds,
        now_unix,
    )
}

fn validate_backup_receipt_age_v1(
    recorded_at_unix: u64,
    max_age_seconds: u64,
    now_unix: u64,
) -> Result<u64, PreflightFailureV1> {
    let age = now_unix
        .checked_sub(recorded_at_unix)
        .ok_or_else(|| PreflightFailureV1::new("backup.receipt", "future-timestamp"))?;
    if age > max_age_seconds {
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
                rpc_cookie: CoreRpcCookieConfigV1 {
                    path: PathBuf::from("/srv/bitcoin/signet/.cookie"),
                    protected_parent: PathBuf::from("/srv/bitcoin"),
                    access_policy: CoreRpcCookieAccessPolicyV1::SameUidOwnerOnly,
                    cross_uid_access: None,
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
                rpc_access_policy: LightningRpcAccessPolicyV1::SameUidOwnerOnly,
                cross_uid_access: None,
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
            systemd: SystemdConfigV1 {
                busctl: PinnedBinaryV1 {
                    path: PathBuf::from("/usr/bin/busctl"),
                    protected_parent: PathBuf::from("/usr/bin"),
                    sha256_hex: hex::encode([6u8; 32]),
                    expected_uid: 0,
                    expected_gid: 0,
                },
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

    fn cross_uid_config(role: StagingRoleV1) -> LightningStagingConfigV1 {
        let mut value = config(role);
        value.lightning.rpc_access_policy = LightningRpcAccessPolicyV1::CrossUidSharedGroup;
        value.lightning.cross_uid_access = Some(LightningCrossUidAccessV1 {
            client_expected_uid: 1001,
            protected_parent_expected_uid: 0,
            protected_parent_expected_gid: 0,
        });
        value.lightning.expected_uid = 1000;
        value.lightning.expected_gid = 1002;
        value.bitcoin.rpc_cookie.expected_uid = 1001;
        value.bitcoin.rpc_cookie.expected_gid = 1001;
        value
    }

    fn fully_cross_uid_config(role: StagingRoleV1) -> LightningStagingConfigV1 {
        let mut value = cross_uid_config(role);
        value.bitcoin.rpc_cookie.access_policy =
            CoreRpcCookieAccessPolicyV1::CrossUidSetgidSharedGroup;
        value.bitcoin.rpc_cookie.cross_uid_access = Some(CoreRpcCookieCrossUidAccessV1 {
            preflight_expected_uid: 1001,
            protected_parent_expected_uid: 0,
            protected_parent_expected_gid: 0,
        });
        value.bitcoin.rpc_cookie.expected_uid = 1003;
        value.bitcoin.rpc_cookie.expected_gid = 1004;
        value
    }

    #[cfg(unix)]
    fn same_uid_cookie_fixture() -> (tempfile::TempDir, CoreRpcCookieConfigV1, PathBuf) {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let protected_parent = std::fs::canonicalize(directory.path()).unwrap();
        let metadata = std::fs::metadata(&protected_parent).unwrap();
        let cookie_path = protected_parent.join(".cookie");
        let cookie = format!("__cookie__:{}\n", "a".repeat(64));
        std::fs::write(&cookie_path, cookie.as_bytes()).unwrap();
        std::fs::set_permissions(&cookie_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let config = CoreRpcCookieConfigV1 {
            path: cookie_path.clone(),
            protected_parent,
            access_policy: CoreRpcCookieAccessPolicyV1::SameUidOwnerOnly,
            cross_uid_access: None,
            expected_uid: metadata.uid(),
            expected_gid: metadata.gid(),
        };
        (directory, config, cookie_path)
    }

    #[cfg(unix)]
    fn same_uid_socket_fixture() -> (
        tempfile::TempDir,
        std::os::unix::net::UnixListener,
        LightningConfigV1,
        PathBuf,
    ) {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        // macOS TMPDIR normally begins with `/var`, which is an alias for
        // `/private/var`. Feed the validator the required canonical path.
        let protected_parent = std::fs::canonicalize(directory.path()).unwrap();
        let final_parent = protected_parent.join("signet");
        std::fs::create_dir(&final_parent).unwrap();
        std::fs::set_permissions(&final_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let rpc_socket = final_parent.join("lightning-rpc");
        let listener = std::os::unix::net::UnixListener::bind(&rpc_socket).unwrap();
        std::fs::set_permissions(&rpc_socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let metadata = std::fs::metadata(&protected_parent).unwrap();
        let mut lightning = config(StagingRoleV1::Issuer).lightning;
        lightning.rpc_socket = rpc_socket;
        lightning.protected_parent = protected_parent;
        lightning.rpc_access_policy = LightningRpcAccessPolicyV1::SameUidOwnerOnly;
        lightning.cross_uid_access = None;
        lightning.expected_uid = metadata.uid();
        lightning.expected_gid = metadata.gid();
        (directory, listener, lightning, final_parent)
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

    fn plugin(name: &str, active: bool, dynamic: bool) -> ClnPluginV1 {
        ClnPluginV1 {
            name: name.to_owned(),
            active,
            dynamic,
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
            plugins: vec![plugin(PLUGIN, true, false)],
            peer_channels,
            gossip_channels,
            scb_digest: [9u8; 32],
            scb_count: ids.required_peers(role).len(),
        }
    }

    fn bootstrap_snapshot(role: StagingRoleV1) -> BootstrapPreflightSnapshotV1 {
        let ids = NodeIdsV1 {
            payer: PAYER.to_owned(),
            router: ROUTER.to_owned(),
            issuer: ISSUER.to_owned(),
        };
        BootstrapPreflightSnapshotV1 {
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
            plugins: vec![plugin(PLUGIN, true, false)],
            peer_channel_count: 0,
            onchain_output_count: 0,
            funding_channel_count: 0,
            scb_count: 0,
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
    fn bootstrap_accepts_all_roles_only_before_any_channel_state_exists() {
        for role in [
            StagingRoleV1::Payer,
            StagingRoleV1::Router,
            StagingRoleV1::Issuer,
        ] {
            let config = config(role);
            let ids = validate_static_config_v1(&config).unwrap();
            let success =
                validate_bootstrap_snapshot_v1(&config, &ids, &bootstrap_snapshot(role)).unwrap();
            assert_eq!(success.role, role);

            let mut with_peer = bootstrap_snapshot(role);
            with_peer.peer_channel_count = 1;
            assert_eq!(
                validate_bootstrap_snapshot_v1(&config, &ids, &with_peer)
                    .unwrap_err()
                    .reason,
                "existing-peer-channels"
            );

            let mut with_scb = bootstrap_snapshot(role);
            with_scb.scb_count = 1;
            assert_eq!(
                validate_bootstrap_snapshot_v1(&config, &ids, &with_scb)
                    .unwrap_err()
                    .reason,
                "existing-staticbackup"
            );

            let mut with_outputs = bootstrap_snapshot(role);
            with_outputs.onchain_output_count = 1;
            assert_eq!(
                validate_bootstrap_snapshot_v1(&config, &ids, &with_outputs)
                    .unwrap_err()
                    .reason,
                "existing-wallet-funds"
            );

            let mut with_funding_channel = bootstrap_snapshot(role);
            with_funding_channel.funding_channel_count = 1;
            assert_eq!(
                validate_bootstrap_snapshot_v1(&config, &ids, &with_funding_channel)
                    .unwrap_err()
                    .reason,
                "existing-wallet-funds"
            );
        }
    }

    #[test]
    fn bootstrap_reuses_the_strict_runtime_trust_checks() {
        let config = config(StagingRoleV1::Issuer);
        let ids = validate_static_config_v1(&config).unwrap();

        let mut wrong_challenge = bootstrap_snapshot(StagingRoleV1::Issuer);
        wrong_challenge.signet_challenge = Some("00".repeat(32));
        assert_eq!(
            validate_bootstrap_snapshot_v1(&config, &ids, &wrong_challenge)
                .unwrap_err()
                .check,
            "core.signet-challenge"
        );

        let mut wrong_identity = bootstrap_snapshot(StagingRoleV1::Issuer);
        wrong_identity.cln_id = PAYER.to_owned();
        assert_eq!(
            validate_bootstrap_snapshot_v1(&config, &ids, &wrong_identity)
                .unwrap_err()
                .check,
            "lightning.identity"
        );

        let mut unexpected_plugin = bootstrap_snapshot(StagingRoleV1::Issuer);
        unexpected_plugin
            .plugins
            .push(plugin("/tmp/untrusted", true, false));
        assert_eq!(
            validate_bootstrap_snapshot_v1(&config, &ids, &unexpected_plugin)
                .unwrap_err()
                .check,
            "lightning.plugins"
        );
    }

    #[test]
    fn cln_plugin_list_requires_static_plugins_and_a_closed_item_shape() {
        let config = config(StagingRoleV1::Issuer);
        let valid: ClnPluginListV1 = serde_json::from_value(serde_json::json!({
            "command": "list",
            "plugins": [{"name": PLUGIN, "active": true, "dynamic": false}]
        }))
        .unwrap();
        validate_plugins_v1(&config, &valid.plugins).unwrap();

        let dynamic: ClnPluginListV1 = serde_json::from_value(serde_json::json!({
            "command": "list",
            "plugins": [{"name": PLUGIN, "active": true, "dynamic": true}]
        }))
        .unwrap();
        assert_eq!(
            validate_plugins_v1(&config, &dynamic.plugins)
                .unwrap_err()
                .reason,
            "plugin-dynamic"
        );

        for malformed in [
            serde_json::json!({
                "command": "list",
                "plugins": [{"name": PLUGIN, "active": true}]
            }),
            serde_json::json!({
                "command": "list",
                "plugins": [{"name": PLUGIN, "dynamic": false}]
            }),
            serde_json::json!({
                "command": "list",
                "plugins": [{
                    "name": PLUGIN,
                    "active": true,
                    "dynamic": false,
                    "autostart": true
                }]
            }),
            serde_json::json!({
                "command": "list",
                "plugins": [{"name": PLUGIN, "active": true, "dynamic": "false"}]
            }),
            serde_json::json!({"command": "list", "plugins": [PLUGIN]}),
            serde_json::json!({
                "command": "list",
                "plugins": [{"name": PLUGIN, "active": true, "dynamic": false}],
                "unknown_top_level": true
            }),
        ] {
            assert!(serde_json::from_value::<ClnPluginListV1>(malformed).is_err());
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
            DynamicPlugin,
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
            (Mutation::DynamicPlugin, "lightning.plugins"),
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
                    snapshot.plugins.push(plugin("/tmp/unknown", true, false));
                }
                Mutation::InactivePlugin => snapshot.plugins[0].active = false,
                Mutation::DynamicPlugin => snapshot.plugins[0].dynamic = true,
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
        assert_eq!(
            digest_staticbackup_v1::<String>(&[]).unwrap_err().reason,
            "invalid-entry-count"
        );
        assert_eq!(
            digest_staticbackup_with_empty_policy_v1::<String>(&[], true)
                .unwrap()
                .1,
            0
        );
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
    fn core_rpc_cookie_access_policy_is_explicit_and_fail_closed() {
        let legacy = config(StagingRoleV1::Issuer);
        assert_eq!(
            legacy.bitcoin.rpc_cookie.access_policy,
            CoreRpcCookieAccessPolicyV1::SameUidOwnerOnly
        );
        assert!(validate_static_config_v1(&legacy).is_ok());

        let mut same_with_cross_fields = legacy.clone();
        same_with_cross_fields.bitcoin.rpc_cookie.cross_uid_access =
            Some(CoreRpcCookieCrossUidAccessV1 {
                preflight_expected_uid: 1001,
                protected_parent_expected_uid: 0,
                protected_parent_expected_gid: 0,
            });
        assert_eq!(
            validate_static_config_v1(&same_with_cross_fields)
                .unwrap_err()
                .reason,
            "cross-uid-fields-with-same-uid-policy"
        );

        let mut missing_fields = legacy.clone();
        missing_fields.bitcoin.rpc_cookie.access_policy =
            CoreRpcCookieAccessPolicyV1::CrossUidSetgidSharedGroup;
        assert_eq!(
            validate_static_config_v1(&missing_fields)
                .unwrap_err()
                .reason,
            "missing-cross-uid-fields"
        );

        let valid_cross_uid = fully_cross_uid_config(StagingRoleV1::Issuer);
        assert!(validate_static_config_v1(&valid_cross_uid).is_ok());
        for mutation in 0..5 {
            let mut invalid = valid_cross_uid.clone();
            let daemon_uid = invalid.bitcoin.rpc_cookie.expected_uid;
            match mutation {
                0 => {
                    invalid
                        .bitcoin
                        .rpc_cookie
                        .cross_uid_access
                        .as_mut()
                        .unwrap()
                        .preflight_expected_uid = 0
                }
                1 => {
                    invalid
                        .bitcoin
                        .rpc_cookie
                        .cross_uid_access
                        .as_mut()
                        .unwrap()
                        .preflight_expected_uid = daemon_uid
                }
                2 => {
                    invalid
                        .bitcoin
                        .rpc_cookie
                        .cross_uid_access
                        .as_mut()
                        .unwrap()
                        .protected_parent_expected_uid = 1
                }
                3 => {
                    invalid
                        .bitcoin
                        .rpc_cookie
                        .cross_uid_access
                        .as_mut()
                        .unwrap()
                        .protected_parent_expected_gid = 1
                }
                4 => invalid.bitcoin.rpc_cookie.expected_gid = 0,
                _ => unreachable!(),
            }
            assert_eq!(
                validate_static_config_v1(&invalid).unwrap_err().reason,
                "invalid-cross-uid-identities"
            );
        }
    }

    #[test]
    fn core_cookie_and_lightning_identities_are_separate_but_share_preflight_euid() {
        let valid = fully_cross_uid_config(StagingRoleV1::Issuer);
        assert!(validate_preflight_identity_separation_v1(&valid).is_ok());

        let mut mismatched_preflight = valid.clone();
        mismatched_preflight
            .bitcoin
            .rpc_cookie
            .cross_uid_access
            .as_mut()
            .unwrap()
            .preflight_expected_uid += 1;
        assert_eq!(
            validate_preflight_identity_separation_v1(&mismatched_preflight)
                .unwrap_err()
                .reason,
            "preflight-uid-conflict"
        );

        let mut shared_daemon_uid = valid.clone();
        shared_daemon_uid.bitcoin.rpc_cookie.expected_uid =
            shared_daemon_uid.lightning.expected_uid;
        assert_eq!(
            validate_preflight_identity_separation_v1(&shared_daemon_uid)
                .unwrap_err()
                .reason,
            "core-and-lightning-identities-not-separated"
        );

        let mut shared_long_lived_group = valid;
        shared_long_lived_group.bitcoin.rpc_cookie.expected_gid =
            shared_long_lived_group.lightning.expected_gid;
        assert_eq!(
            validate_preflight_identity_separation_v1(&shared_long_lived_group)
                .unwrap_err()
                .reason,
            "core-and-lightning-identities-not-separated"
        );
    }

    #[cfg(unix)]
    #[test]
    fn core_rpc_cookie_runtime_identity_requires_exact_euid_and_cookie_group() {
        let same_uid = config(StagingRoleV1::Issuer);
        let mut runtime = CoreRpcCookieRuntimeIdentityV1 {
            effective_uid: same_uid.bitcoin.rpc_cookie.expected_uid,
            effective_gid: same_uid.bitcoin.rpc_cookie.expected_gid,
            supplementary_gids: BTreeSet::new(),
        };
        validate_core_rpc_cookie_runtime_identity_v1(&same_uid.bitcoin.rpc_cookie, &runtime)
            .unwrap();
        runtime.effective_uid += 1;
        assert_eq!(
            validate_core_rpc_cookie_runtime_identity_v1(&same_uid.bitcoin.rpc_cookie, &runtime)
                .unwrap_err()
                .reason,
            "runtime-uid-mismatch"
        );

        let cross_uid = fully_cross_uid_config(StagingRoleV1::Issuer);
        let cookie = &cross_uid.bitcoin.rpc_cookie;
        let preflight_uid = cookie
            .cross_uid_access
            .as_ref()
            .unwrap()
            .preflight_expected_uid;
        runtime = CoreRpcCookieRuntimeIdentityV1 {
            effective_uid: preflight_uid,
            effective_gid: preflight_uid,
            supplementary_gids: BTreeSet::from([cookie.expected_gid]),
        };
        validate_core_rpc_cookie_runtime_identity_v1(cookie, &runtime).unwrap();
        runtime.supplementary_gids.clear();
        assert_eq!(
            validate_core_rpc_cookie_runtime_identity_v1(cookie, &runtime)
                .unwrap_err()
                .reason,
            "shared-group-missing"
        );
        runtime.effective_gid = cookie.expected_gid;
        validate_core_rpc_cookie_runtime_identity_v1(cookie, &runtime).unwrap();
        runtime.effective_uid = cookie.expected_uid;
        assert_eq!(
            validate_core_rpc_cookie_runtime_identity_v1(cookie, &runtime)
                .unwrap_err()
                .reason,
            "runtime-uid-mismatch"
        );
    }

    #[cfg(unix)]
    #[test]
    fn core_rpc_cookie_boundary_metadata_requires_exact_split_uid_layout() {
        let config = fully_cross_uid_config(StagingRoleV1::Issuer);
        let cookie_config = &config.bitcoin.rpc_cookie;
        let protected_parent = CoreRpcCookieBoundaryMetadataV1 {
            kind: CoreRpcCookieBoundaryKindV1::Directory,
            uid: 0,
            gid: 0,
            mode: 0o755,
            nlink: 2,
            size: 0,
        };
        let final_parent = CoreRpcCookieBoundaryMetadataV1 {
            kind: CoreRpcCookieBoundaryKindV1::Directory,
            uid: cookie_config.expected_uid,
            gid: cookie_config.expected_gid,
            mode: 0o2710,
            nlink: 2,
            size: 0,
        };
        let cookie = CoreRpcCookieBoundaryMetadataV1 {
            kind: CoreRpcCookieBoundaryKindV1::RegularFile,
            uid: cookie_config.expected_uid,
            gid: cookie_config.expected_gid,
            mode: 0o640,
            nlink: 1,
            size: 76,
        };
        validate_core_rpc_cookie_boundary_metadata_v1(
            cookie_config,
            protected_parent,
            final_parent,
            cookie,
            "test.core-cookie",
        )
        .unwrap();

        let mutations = [
            (
                CoreRpcCookieBoundaryMetadataV1 {
                    uid: 1,
                    ..protected_parent
                },
                final_parent,
                cookie,
                "unsafe-protected-parent",
            ),
            (
                CoreRpcCookieBoundaryMetadataV1 {
                    mode: 0o750,
                    ..protected_parent
                },
                final_parent,
                cookie,
                "unsafe-protected-parent",
            ),
            (
                CoreRpcCookieBoundaryMetadataV1 {
                    gid: 1,
                    ..protected_parent
                },
                final_parent,
                cookie,
                "unsafe-protected-parent",
            ),
            (
                protected_parent,
                CoreRpcCookieBoundaryMetadataV1 {
                    uid: cookie_config.expected_uid + 1,
                    ..final_parent
                },
                cookie,
                "unsafe-directory",
            ),
            (
                protected_parent,
                CoreRpcCookieBoundaryMetadataV1 {
                    gid: cookie_config.expected_gid + 1,
                    ..final_parent
                },
                cookie,
                "unsafe-directory",
            ),
            (
                protected_parent,
                CoreRpcCookieBoundaryMetadataV1 {
                    mode: 0o710,
                    ..final_parent
                },
                cookie,
                "unsafe-directory",
            ),
            (
                protected_parent,
                CoreRpcCookieBoundaryMetadataV1 {
                    mode: 0o711,
                    ..final_parent
                },
                cookie,
                "unsafe-directory",
            ),
            (
                protected_parent,
                CoreRpcCookieBoundaryMetadataV1 {
                    mode: 0o3710,
                    ..final_parent
                },
                cookie,
                "unsafe-directory",
            ),
            (
                protected_parent,
                final_parent,
                CoreRpcCookieBoundaryMetadataV1 {
                    mode: 0o600,
                    ..cookie
                },
                "unsafe-metadata",
            ),
            (
                protected_parent,
                final_parent,
                CoreRpcCookieBoundaryMetadataV1 {
                    uid: cookie_config.expected_uid + 1,
                    ..cookie
                },
                "unsafe-metadata",
            ),
            (
                protected_parent,
                final_parent,
                CoreRpcCookieBoundaryMetadataV1 {
                    gid: cookie_config.expected_gid + 1,
                    ..cookie
                },
                "unsafe-metadata",
            ),
            (
                protected_parent,
                final_parent,
                CoreRpcCookieBoundaryMetadataV1 { nlink: 2, ..cookie },
                "unsafe-metadata",
            ),
            (
                protected_parent,
                final_parent,
                CoreRpcCookieBoundaryMetadataV1 { size: 0, ..cookie },
                "unsafe-metadata",
            ),
            (
                protected_parent,
                final_parent,
                CoreRpcCookieBoundaryMetadataV1 {
                    size: MAX_CORE_COOKIE_BYTES_V1 + 1,
                    ..cookie
                },
                "unsafe-metadata",
            ),
            (
                protected_parent,
                final_parent,
                CoreRpcCookieBoundaryMetadataV1 {
                    kind: CoreRpcCookieBoundaryKindV1::Other,
                    ..cookie
                },
                "unsafe-metadata",
            ),
        ];
        for (protected_parent, final_parent, cookie, expected_reason) in mutations {
            assert_eq!(
                validate_core_rpc_cookie_boundary_metadata_v1(
                    cookie_config,
                    protected_parent,
                    final_parent,
                    cookie,
                    "test.core-cookie",
                )
                .unwrap_err()
                .reason,
                expected_reason
            );
        }
    }

    #[test]
    fn lightning_rpc_access_policy_is_explicit_and_unambiguous() {
        let legacy = config(StagingRoleV1::Issuer);
        assert_eq!(
            legacy.lightning.rpc_access_policy,
            LightningRpcAccessPolicyV1::SameUidOwnerOnly
        );
        assert!(validate_static_config_v1(&legacy).is_ok());

        let mut same_with_cross_fields = legacy.clone();
        same_with_cross_fields.lightning.cross_uid_access = Some(LightningCrossUidAccessV1 {
            client_expected_uid: 1001,
            protected_parent_expected_uid: 0,
            protected_parent_expected_gid: 0,
        });
        assert_eq!(
            validate_static_config_v1(&same_with_cross_fields)
                .unwrap_err()
                .reason,
            "cross-uid-fields-with-same-uid-policy"
        );

        let mut missing_fields = legacy.clone();
        missing_fields.lightning.rpc_access_policy =
            LightningRpcAccessPolicyV1::CrossUidSharedGroup;
        assert_eq!(
            validate_static_config_v1(&missing_fields)
                .unwrap_err()
                .reason,
            "missing-cross-uid-fields"
        );

        let valid_cross_uid = cross_uid_config(StagingRoleV1::Issuer);
        assert!(validate_static_config_v1(&valid_cross_uid).is_ok());

        for mutation in 0..5 {
            let mut invalid = valid_cross_uid.clone();
            let daemon_uid = invalid.lightning.expected_uid;
            match mutation {
                0 => {
                    invalid
                        .lightning
                        .cross_uid_access
                        .as_mut()
                        .unwrap()
                        .client_expected_uid = 0
                }
                1 => {
                    invalid
                        .lightning
                        .cross_uid_access
                        .as_mut()
                        .unwrap()
                        .client_expected_uid = daemon_uid
                }
                2 => {
                    invalid
                        .lightning
                        .cross_uid_access
                        .as_mut()
                        .unwrap()
                        .protected_parent_expected_uid = 1
                }
                3 => {
                    invalid
                        .lightning
                        .cross_uid_access
                        .as_mut()
                        .unwrap()
                        .protected_parent_expected_gid = 1
                }
                4 => invalid.lightning.expected_gid = 0,
                _ => unreachable!(),
            }
            assert_eq!(
                validate_static_config_v1(&invalid).unwrap_err().reason,
                "invalid-cross-uid-identities"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn lightning_rpc_runtime_identity_requires_exact_client_and_shared_group() {
        let same_uid = config(StagingRoleV1::Issuer);
        let mut runtime = LightningRuntimeIdentityV1 {
            effective_uid: same_uid.lightning.expected_uid,
            effective_gid: same_uid.lightning.expected_gid,
            supplementary_gids: BTreeSet::new(),
        };
        validate_lightning_runtime_identity_v1(&same_uid.lightning, &runtime).unwrap();
        runtime.effective_uid += 1;
        assert_eq!(
            validate_lightning_runtime_identity_v1(&same_uid.lightning, &runtime)
                .unwrap_err()
                .reason,
            "runtime-uid-mismatch"
        );

        let cross_uid = cross_uid_config(StagingRoleV1::Issuer);
        let cross_fields = cross_uid.lightning.cross_uid_access.as_ref().unwrap();
        runtime = LightningRuntimeIdentityV1 {
            effective_uid: cross_fields.client_expected_uid,
            effective_gid: cross_fields.client_expected_uid,
            supplementary_gids: BTreeSet::from([cross_uid.lightning.expected_gid]),
        };
        validate_lightning_runtime_identity_v1(&cross_uid.lightning, &runtime).unwrap();

        runtime.supplementary_gids.clear();
        assert_eq!(
            validate_lightning_runtime_identity_v1(&cross_uid.lightning, &runtime)
                .unwrap_err()
                .reason,
            "shared-group-missing"
        );
        runtime.effective_gid = cross_uid.lightning.expected_gid;
        validate_lightning_runtime_identity_v1(&cross_uid.lightning, &runtime).unwrap();
        runtime.effective_uid = cross_uid.lightning.expected_uid;
        assert_eq!(
            validate_lightning_runtime_identity_v1(&cross_uid.lightning, &runtime)
                .unwrap_err()
                .reason,
            "runtime-uid-mismatch"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cross_uid_boundary_metadata_requires_exact_production_layout() {
        let config = cross_uid_config(StagingRoleV1::Issuer);
        let protected_parent = LightningBoundaryMetadataV1 {
            kind: LightningBoundaryKindV1::Directory,
            uid: 0,
            gid: 0,
            mode: 0o755,
            nlink: 2,
        };
        let final_parent = LightningBoundaryMetadataV1 {
            kind: LightningBoundaryKindV1::Directory,
            uid: config.lightning.expected_uid,
            gid: config.lightning.expected_gid,
            mode: 0o710,
            nlink: 2,
        };
        let socket = LightningBoundaryMetadataV1 {
            kind: LightningBoundaryKindV1::Socket,
            uid: config.lightning.expected_uid,
            gid: config.lightning.expected_gid,
            mode: 0o660,
            nlink: 1,
        };
        validate_cross_uid_boundary_metadata_v1(
            &config.lightning,
            protected_parent,
            final_parent,
            socket,
            "test.lightning-rpc",
        )
        .unwrap();

        let mutations = [
            (
                LightningBoundaryMetadataV1 {
                    uid: 1,
                    ..protected_parent
                },
                final_parent,
                socket,
                "unsafe-protected-parent",
            ),
            (
                LightningBoundaryMetadataV1 {
                    mode: 0o750,
                    ..protected_parent
                },
                final_parent,
                socket,
                "unsafe-protected-parent",
            ),
            (
                protected_parent,
                LightningBoundaryMetadataV1 {
                    gid: config.lightning.expected_gid + 1,
                    ..final_parent
                },
                socket,
                "unsafe-directory",
            ),
            (
                protected_parent,
                LightningBoundaryMetadataV1 {
                    mode: 0o711,
                    ..final_parent
                },
                socket,
                "unsafe-directory",
            ),
            (
                protected_parent,
                final_parent,
                LightningBoundaryMetadataV1 {
                    uid: config.lightning.expected_uid + 1,
                    ..socket
                },
                "unsafe-socket",
            ),
            (
                protected_parent,
                final_parent,
                LightningBoundaryMetadataV1 {
                    gid: config.lightning.expected_gid + 1,
                    ..socket
                },
                "unsafe-socket",
            ),
            (
                protected_parent,
                final_parent,
                LightningBoundaryMetadataV1 {
                    mode: 0o600,
                    ..socket
                },
                "unsafe-socket",
            ),
            (
                protected_parent,
                final_parent,
                LightningBoundaryMetadataV1 { nlink: 2, ..socket },
                "unsafe-socket",
            ),
            (
                protected_parent,
                final_parent,
                LightningBoundaryMetadataV1 {
                    kind: LightningBoundaryKindV1::Other,
                    ..socket
                },
                "unsafe-socket",
            ),
        ];
        for (protected_parent, final_parent, socket, expected_reason) in mutations {
            assert_eq!(
                validate_cross_uid_boundary_metadata_v1(
                    &config.lightning,
                    protected_parent,
                    final_parent,
                    socket,
                    "test.lightning-rpc",
                )
                .unwrap_err()
                .reason,
                expected_reason
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn same_uid_socket_validation_accepts_legacy_layout_but_requires_exact_modes() {
        use std::os::unix::fs::PermissionsExt;

        let (_directory, _listener, lightning, final_parent) = same_uid_socket_fixture();
        validate_protected_socket_v1(&lightning).unwrap();

        std::fs::set_permissions(
            &lightning.rpc_socket,
            std::fs::Permissions::from_mode(0o660),
        )
        .unwrap();
        assert_eq!(
            validate_protected_socket_v1(&lightning).unwrap_err().reason,
            "unsafe-socket"
        );
        std::fs::set_permissions(
            &lightning.rpc_socket,
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        std::fs::set_permissions(&final_parent, std::fs::Permissions::from_mode(0o710)).unwrap();
        assert_eq!(
            validate_protected_socket_v1(&lightning).unwrap_err().reason,
            "unsafe-parent-boundary"
        );
    }

    #[cfg(unix)]
    #[test]
    fn lightning_socket_validation_rejects_symlink_and_parent_metadata_drift() {
        use std::os::unix::fs::symlink;

        let (_directory, listener, lightning, final_parent) = same_uid_socket_fixture();
        let parent_before = std::fs::symlink_metadata(&final_parent).unwrap();
        let nested = final_parent.join("unexpected-child");
        std::fs::create_dir(&nested).unwrap();
        let parent_after = std::fs::symlink_metadata(&final_parent).unwrap();
        assert_eq!(
            validate_same_lightning_boundary_entry_v1(
                &parent_before,
                &parent_after,
                "test.lightning-rpc",
            )
            .unwrap_err()
            .reason,
            "file-changed"
        );
        std::fs::remove_dir(&nested).unwrap();

        drop(listener);
        let real_socket = final_parent.join("lightning-rpc.real");
        std::fs::rename(&lightning.rpc_socket, &real_socket).unwrap();
        symlink("lightning-rpc.real", &lightning.rpc_socket).unwrap();
        assert_eq!(
            validate_protected_socket_v1(&lightning).unwrap_err().reason,
            "non-canonical-path"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn lightning_socket_validation_rejects_extended_acl_on_final_parent() {
        let (_directory, _listener, lightning, final_parent) = same_uid_socket_fixture();
        assert!(std::process::Command::new("chmod")
            .args(["+a", "everyone allow read"])
            .arg(&final_parent)
            .status()
            .unwrap()
            .success());
        assert_eq!(
            validate_protected_socket_v1(&lightning).unwrap_err().reason,
            "unsafe-parent-boundary"
        );
    }

    #[test]
    fn published_config_template_parses_and_denies_unknown_fields() {
        let template =
            include_str!("../../../docs/payment/LIGHTNING_STAGING_PREFLIGHT.toml.example");
        let parsed = toml::from_str::<LightningStagingConfigV1>(template).unwrap();
        assert_eq!(
            parsed.bitcoin.rpc_cookie.access_policy,
            CoreRpcCookieAccessPolicyV1::CrossUidSetgidSharedGroup
        );
        assert_eq!(parsed.bitcoin.rpc_cookie.expected_uid, 990);
        assert_eq!(parsed.bitcoin.rpc_cookie.expected_gid, 994);
        assert_eq!(
            parsed
                .bitcoin
                .rpc_cookie
                .cross_uid_access
                .as_ref()
                .unwrap()
                .preflight_expected_uid,
            995
        );
        assert_eq!(
            parsed.lightning.rpc_access_policy,
            LightningRpcAccessPolicyV1::CrossUidSharedGroup
        );
        assert_eq!(parsed.lightning.expected_uid, 991);
        assert_eq!(parsed.lightning.expected_gid, 993);
        assert_eq!(
            parsed
                .lightning
                .cross_uid_access
                .as_ref()
                .unwrap()
                .client_expected_uid,
            995
        );
        assert_eq!(
            parsed.backup.protected_parent,
            Path::new(BACKUP_RECEIPT_STATE_DIRECTORY_V1)
        );
        assert_eq!(parsed.backup.receipt, Path::new(BACKUP_RECEIPT_PATH_V1));
        assert_eq!(parsed.backup.expected_uid, 995);
        assert_eq!(parsed.backup.expected_gid, 995);
        validate_backup_receipt_state_contract_v1(&parsed, 995, 995).unwrap();
        let mut legacy_template = String::new();
        let mut skipping_cross_uid_table = false;
        for line in template.lines() {
            if line.trim() == "[lightning.cross_uid_access]" {
                skipping_cross_uid_table = true;
                continue;
            }
            if skipping_cross_uid_table && line.trim() == "[lightning.daemon]" {
                skipping_cross_uid_table = false;
            }
            if skipping_cross_uid_table || line.trim_start().starts_with("rpc_access_policy =") {
                continue;
            }
            legacy_template.push_str(line);
            legacy_template.push('\n');
        }
        let legacy = toml::from_str::<LightningStagingConfigV1>(&legacy_template).unwrap();
        assert_eq!(
            legacy.lightning.rpc_access_policy,
            LightningRpcAccessPolicyV1::SameUidOwnerOnly
        );
        assert!(legacy.lightning.cross_uid_access.is_none());

        let mut core_legacy_template = String::new();
        let mut skipping_core_cross_uid_table = false;
        for line in template.lines() {
            if line.trim() == "[bitcoin.rpc_cookie.cross_uid_access]" {
                skipping_core_cross_uid_table = true;
                continue;
            }
            if skipping_core_cross_uid_table && line.trim() == "[bitcoin.daemon]" {
                skipping_core_cross_uid_table = false;
            }
            if skipping_core_cross_uid_table || line.trim_start().starts_with("access_policy =") {
                continue;
            }
            core_legacy_template.push_str(line);
            core_legacy_template.push('\n');
        }
        let core_legacy =
            toml::from_str::<LightningStagingConfigV1>(&core_legacy_template).unwrap();
        assert_eq!(
            core_legacy.bitcoin.rpc_cookie.access_policy,
            CoreRpcCookieAccessPolicyV1::SameUidOwnerOnly
        );
        assert!(core_legacy.bitcoin.rpc_cookie.cross_uid_access.is_none());

        let with_unknown_cross_uid_field = template.replace(
            "client_expected_uid = 995",
            "client_expected_uid = 995\nunexpected_cross_uid_field = true",
        );
        assert!(toml::from_str::<LightningStagingConfigV1>(&with_unknown_cross_uid_field).is_err());
        let with_unknown_core_cross_uid_field = template.replace(
            "preflight_expected_uid = 995",
            "preflight_expected_uid = 995\nunexpected_cookie_cross_uid_field = true",
        );
        assert!(
            toml::from_str::<LightningStagingConfigV1>(&with_unknown_core_cross_uid_field).is_err()
        );
        let with_obsolete_core_cookie_policy = template.replace(
            "access_policy = \"cross-uid-setgid-shared-group\"",
            "access_policy = \"cross-uid-shared-group\"",
        );
        assert!(
            toml::from_str::<LightningStagingConfigV1>(&with_obsolete_core_cookie_policy).is_err()
        );
        let with_unknown_backup_field = format!("{template}\nunexpected = true\n");
        assert!(toml::from_str::<LightningStagingConfigV1>(&with_unknown_backup_field).is_err());
    }

    #[test]
    fn backup_receipt_state_contract_rejects_path_or_preflight_identity_substitution() {
        let template =
            include_str!("../../../docs/payment/LIGHTNING_STAGING_PREFLIGHT.toml.example");
        let parsed = toml::from_str::<LightningStagingConfigV1>(template).unwrap();

        let mut wrong_parent = parsed.clone();
        wrong_parent.backup.protected_parent = PathBuf::from("/var/lib/other-preflight");
        assert_eq!(
            validate_backup_receipt_state_contract_v1(&wrong_parent, 995, 995)
                .unwrap_err()
                .reason,
            "invalid-state-boundary"
        );

        let mut wrong_receipt = parsed.clone();
        wrong_receipt.backup.receipt =
            PathBuf::from("/var/lib/bitcoinpir-lightning-preflight/alternate-receipt.toml");
        assert_eq!(
            validate_backup_receipt_state_contract_v1(&wrong_receipt, 995, 995)
                .unwrap_err()
                .reason,
            "invalid-state-boundary"
        );

        for (config_gid, reader_uid) in [(996, 995), (995, 996), (0, 995), (995, 0)] {
            assert_eq!(
                validate_backup_receipt_state_contract_v1(&parsed, config_gid, reader_uid)
                    .unwrap_err()
                    .reason,
                "invalid-state-boundary"
            );
        }

        let mut wrong_owner = parsed.clone();
        wrong_owner.backup.expected_uid = 996;
        assert_eq!(
            validate_backup_receipt_state_contract_v1(&wrong_owner, 995, 995)
                .unwrap_err()
                .reason,
            "invalid-state-boundary"
        );

        let mut wrong_group = parsed;
        wrong_group.backup.expected_gid = 996;
        assert_eq!(
            validate_backup_receipt_state_contract_v1(&wrong_group, 995, 995)
                .unwrap_err()
                .reason,
            "invalid-state-boundary"
        );
    }

    #[cfg(unix)]
    #[test]
    fn executable_and_cookie_reject_unsafe_permissions() {
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

        let cookie_parent = std::fs::canonicalize(directory.path()).unwrap();
        let cookie_path = cookie_parent.join(".cookie");
        let cookie = format!("__cookie__:{}\n", "a".repeat(64));
        std::fs::write(&cookie_path, cookie.as_bytes()).unwrap();
        std::fs::set_permissions(&cookie_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let cookie_config = CoreRpcCookieConfigV1 {
            path: cookie_path.clone(),
            protected_parent: cookie_parent,
            access_policy: CoreRpcCookieAccessPolicyV1::SameUidOwnerOnly,
            cross_uid_access: None,
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
            validate_core_rpc_cookie_v1(&cookie_config)
                .unwrap_err()
                .reason,
            "unsafe-protected-parent"
        );
    }

    #[cfg(unix)]
    #[test]
    fn protected_config_identity_contract_requires_root_owner_and_the_pinned_reader_group() {
        const READER_UID: u32 = 60_001;
        const READER_PRIMARY_GID: u32 = 60_002;
        const CONFIG_GID: u32 = 60_003;

        let supplementary_reader = ProtectedConfigRuntimeIdentityV1 {
            effective_uid: READER_UID,
            effective_gid: READER_PRIMARY_GID,
            supplementary_gids: BTreeSet::from([CONFIG_GID]),
        };
        validate_protected_config_runtime_identity_v1(
            0,
            CONFIG_GID,
            READER_UID,
            &supplementary_reader,
            "test.config",
        )
        .unwrap();

        let effective_group_reader = ProtectedConfigRuntimeIdentityV1 {
            effective_gid: CONFIG_GID,
            supplementary_gids: BTreeSet::new(),
            ..supplementary_reader.clone()
        };
        validate_protected_config_runtime_identity_v1(
            0,
            CONFIG_GID,
            READER_UID,
            &effective_group_reader,
            "test.config",
        )
        .unwrap();

        let wrong_reader = ProtectedConfigRuntimeIdentityV1 {
            effective_uid: READER_UID + 1,
            ..supplementary_reader.clone()
        };
        assert_eq!(
            validate_protected_config_runtime_identity_v1(
                0,
                CONFIG_GID,
                READER_UID,
                &wrong_reader,
                "test.config",
            )
            .unwrap_err()
            .reason,
            "runtime-uid-mismatch"
        );

        let missing_group = ProtectedConfigRuntimeIdentityV1 {
            supplementary_gids: BTreeSet::new(),
            ..supplementary_reader.clone()
        };
        assert_eq!(
            validate_protected_config_runtime_identity_v1(
                0,
                CONFIG_GID,
                READER_UID,
                &missing_group,
                "test.config",
            )
            .unwrap_err()
            .reason,
            "shared-group-missing"
        );

        for (owner, group, reader) in [
            (READER_UID, CONFIG_GID, READER_UID),
            (0, 0, READER_UID),
            (0, CONFIG_GID, 0),
        ] {
            assert_eq!(
                validate_protected_config_runtime_identity_v1(
                    owner,
                    group,
                    reader,
                    &supplementary_reader,
                    "test.config",
                )
                .unwrap_err()
                .reason,
                "invalid-access-policy"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn protected_config_runtime_group_set_rejects_missing_and_extra_groups() {
        let config: LightningStagingConfigV1 = toml::from_str(include_str!(
            "../../../docs/payment/LIGHTNING_STAGING_PREFLIGHT.toml.example"
        ))
        .unwrap();
        let exact = ProtectedConfigRuntimeIdentityV1 {
            effective_uid: 995,
            effective_gid: 995,
            supplementary_gids: BTreeSet::from([993, 994]),
        };
        validate_protected_config_runtime_group_set_for_identity_v1(
            &config,
            995,
            995,
            &exact,
            "test.config-groups",
        )
        .unwrap();

        for supplementary_gids in [BTreeSet::from([993]), BTreeSet::from([993, 994, 996])] {
            let runtime = ProtectedConfigRuntimeIdentityV1 {
                supplementary_gids,
                ..exact.clone()
            };
            assert_eq!(
                validate_protected_config_runtime_group_set_for_identity_v1(
                    &config,
                    995,
                    995,
                    &runtime,
                    "test.config-groups",
                )
                .unwrap_err()
                .reason,
                "runtime-group-set-mismatch"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn protected_config_cross_uid_linux_child() {
        if let Ok(uid) = std::env::var("BPIR_CONFIG_CONTRACT_CHILD_UID") {
            use rustix::process::{Gid, Uid};
            let uid = uid.parse::<u32>().unwrap();
            let gid = std::env::var("BPIR_CONFIG_CONTRACT_CHILD_GID")
                .unwrap()
                .parse::<u32>()
                .unwrap();
            let groups = std::env::var("BPIR_CONFIG_CONTRACT_CHILD_GROUPS").unwrap();
            let groups = if groups.is_empty() {
                Vec::new()
            } else {
                groups
                    .split(',')
                    .map(|group| Gid::from_raw(group.parse::<u32>().unwrap()))
                    .collect()
            };
            rustix::thread::set_thread_groups(&groups).unwrap();
            rustix::thread::set_thread_gid(Gid::from_raw(gid)).unwrap();
            rustix::thread::set_thread_uid(Uid::from_raw(uid)).unwrap();
        }
        let Ok(config_path) = std::env::var("BPIR_CONFIG_CONTRACT_CHILD_PATH") else {
            return;
        };
        let protected_parent = std::env::var("BPIR_CONFIG_CONTRACT_CHILD_PARENT").unwrap();
        let expected = std::env::var("BPIR_CONFIG_CONTRACT_CHILD_EXPECT").unwrap();
        let result = read_protected_config_at_v1(
            Path::new(&config_path),
            Path::new(&protected_parent),
            0,
            60_003,
            60_001,
        );
        if expected == "PASS" {
            assert_eq!(result.unwrap(), b"schema_version=1\n");
        } else {
            assert_eq!(result.unwrap_err().reason, expected);
        }
        if let Ok(group_expected) = std::env::var("BPIR_CONFIG_CONTRACT_CHILD_GROUP_SET_EXPECT") {
            let mut config: LightningStagingConfigV1 = toml::from_str(include_str!(
                "../../../docs/payment/LIGHTNING_STAGING_PREFLIGHT.toml.example"
            ))
            .unwrap();
            config.bitcoin.rpc_cookie.expected_gid = 60_004;
            config.lightning.expected_gid = 60_005;
            let runtime =
                current_protected_config_runtime_identity_v1("test.config-groups").unwrap();
            let result = validate_protected_config_runtime_group_set_for_identity_v1(
                &config,
                60_003,
                60_001,
                &runtime,
                "test.config-groups",
            );
            if group_expected == "PASS" {
                result.unwrap();
            } else {
                assert_eq!(result.unwrap_err().reason, group_expected);
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn protected_config_real_linux_uid_gid_and_mode_contract() {
        use rustix::fs::chown;
        use rustix::process::{Gid, Uid};
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command as StdCommand;

        const READER_UID: u32 = 60_001;
        const READER_PRIMARY_GID: u32 = 60_002;
        const CONFIG_GID: u32 = 60_003;
        const COOKIE_GID: u32 = 60_004;
        const LIGHTNING_GID: u32 = 60_005;
        const EXTRA_GID: u32 = 60_006;

        // The cross-UID subprocess setup needs privilege. Ordinary developer
        // runs still exercise the pure identity test above; the pinned Linux
        // root/container gate exercises real kernel DAC and credential state.
        if !rustix::process::geteuid().is_root() {
            assert!(
                std::env::var_os("BPIR_REQUIRE_ROOT_CREDENTIAL_TEST").is_none(),
                "the explicit Linux root credential gate did not run as root"
            );
            return;
        }

        let directory = tempfile::Builder::new()
            .prefix("bitcoinpir-config-contract-")
            .tempdir_in("/run")
            .unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let ancestor = std::fs::canonicalize(directory.path()).unwrap();
        let parent = ancestor.join("config");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        let parent = std::fs::canonicalize(parent).unwrap();
        let config_path = parent.join("preflight.toml");
        std::fs::write(&config_path, b"schema_version=1\n").unwrap();
        chown(
            &config_path,
            Some(Uid::ROOT),
            Some(Gid::from_raw(CONFIG_GID)),
        )
        .unwrap();
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o440)).unwrap();

        let run_child = |uid: u32,
                         gid: u32,
                         groups: &[u32],
                         expected: &str,
                         group_set_expected: Option<&str>| {
            let mut command = StdCommand::new(std::env::current_exe().unwrap());
            command
                .arg("--exact")
                .arg("lightning_staging::tests::protected_config_cross_uid_linux_child")
                .arg("--nocapture")
                .env("BPIR_CONFIG_CONTRACT_CHILD_PATH", &config_path)
                .env("BPIR_CONFIG_CONTRACT_CHILD_PARENT", &parent)
                .env("BPIR_CONFIG_CONTRACT_CHILD_EXPECT", expected)
                .env("BPIR_CONFIG_CONTRACT_CHILD_UID", uid.to_string())
                .env("BPIR_CONFIG_CONTRACT_CHILD_GID", gid.to_string())
                .env(
                    "BPIR_CONFIG_CONTRACT_CHILD_GROUPS",
                    groups
                        .iter()
                        .map(u32::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                );
            if let Some(group_set_expected) = group_set_expected {
                command.env(
                    "BPIR_CONFIG_CONTRACT_CHILD_GROUP_SET_EXPECT",
                    group_set_expected,
                );
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "cross-UID child failed: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        };

        run_child(READER_UID, READER_PRIMARY_GID, &[CONFIG_GID], "PASS", None);
        run_child(
            READER_UID,
            CONFIG_GID,
            &[COOKIE_GID, LIGHTNING_GID],
            "PASS",
            Some("PASS"),
        );
        run_child(
            READER_UID,
            CONFIG_GID,
            &[COOKIE_GID],
            "PASS",
            Some("runtime-group-set-mismatch"),
        );
        run_child(
            READER_UID,
            CONFIG_GID,
            &[COOKIE_GID, LIGHTNING_GID, EXTRA_GID],
            "PASS",
            Some("runtime-group-set-mismatch"),
        );
        run_child(
            READER_UID,
            READER_PRIMARY_GID,
            &[],
            "shared-group-missing",
            None,
        );
        run_child(
            READER_UID + 1,
            CONFIG_GID,
            &[COOKIE_GID, LIGHTNING_GID],
            "runtime-uid-mismatch",
            None,
        );

        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o640)).unwrap();
        run_child(
            READER_UID,
            CONFIG_GID,
            &[COOKIE_GID, LIGHTNING_GID],
            "unsafe-metadata",
            None,
        );

        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o440)).unwrap();
        chown(
            &config_path,
            Some(Uid::from_raw(READER_UID)),
            Some(Gid::from_raw(CONFIG_GID)),
        )
        .unwrap();
        run_child(
            READER_UID,
            CONFIG_GID,
            &[COOKIE_GID, LIGHTNING_GID],
            "unsafe-metadata",
            None,
        );

        chown(
            &config_path,
            Some(Uid::ROOT),
            Some(Gid::from_raw(CONFIG_GID)),
        )
        .unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o775)).unwrap();
        run_child(
            READER_UID,
            CONFIG_GID,
            &[COOKIE_GID, LIGHTNING_GID],
            "unsafe-protected-parent",
            None,
        );

        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o775)).unwrap();
        run_child(
            READER_UID,
            CONFIG_GID,
            &[COOKIE_GID, LIGHTNING_GID],
            "unsafe-protected-parent",
            None,
        );
    }

    #[cfg(unix)]
    #[test]
    fn core_rpc_cookie_rejects_hardlinks_symlinks_and_metadata_drift() {
        use std::io::{Seek, SeekFrom, Write};
        use std::os::unix::fs::{symlink, PermissionsExt};

        let (_directory, cookie_config, cookie_path) = same_uid_cookie_fixture();
        validate_core_rpc_cookie_v1(&cookie_config).unwrap();

        std::fs::set_permissions(
            &cookie_config.protected_parent,
            std::fs::Permissions::from_mode(0o710),
        )
        .unwrap();
        assert_eq!(
            validate_core_rpc_cookie_v1(&cookie_config)
                .unwrap_err()
                .reason,
            "unsafe-directory"
        );
        std::fs::set_permissions(
            &cookie_config.protected_parent,
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        validate_core_rpc_cookie_v1(&cookie_config).unwrap();

        let hardlink = cookie_config.protected_parent.join("cookie-hardlink");
        std::fs::hard_link(&cookie_path, &hardlink).unwrap();
        assert_eq!(
            validate_core_rpc_cookie_v1(&cookie_config)
                .unwrap_err()
                .reason,
            "unsafe-metadata"
        );
        std::fs::remove_file(&hardlink).unwrap();
        validate_core_rpc_cookie_v1(&cookie_config).unwrap();

        let real_cookie = cookie_config.protected_parent.join("cookie-real");
        std::fs::rename(&cookie_path, &real_cookie).unwrap();
        symlink("cookie-real", &cookie_path).unwrap();
        assert_eq!(
            validate_core_rpc_cookie_v1(&cookie_config)
                .unwrap_err()
                .reason,
            "non-canonical-path"
        );
        std::fs::remove_file(&cookie_path).unwrap();
        std::fs::rename(&real_cookie, &cookie_path).unwrap();
        validate_core_rpc_cookie_v1(&cookie_config).unwrap();

        let error = read_validated_core_rpc_cookie_with_hook_v1(&cookie_config, || {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&cookie_path)
                .map_err(|_| PreflightFailureV1::new("test.core-cookie", "open-failed"))?;
            file.write_all(b"x")
                .map_err(|_| PreflightFailureV1::new("test.core-cookie", "write-failed"))?;
            file.sync_all()
                .map_err(|_| PreflightFailureV1::new("test.core-cookie", "sync-failed"))
        })
        .unwrap_err();
        assert_eq!(error.reason, "size-changed");

        let valid_cookie = format!("__cookie__:{}\n", "b".repeat(64));
        std::fs::write(&cookie_path, valid_cookie.as_bytes()).unwrap();
        std::fs::set_permissions(&cookie_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let changed_cookie = format!("__cookie__:{}\n", "c".repeat(64));
        let error = read_validated_core_rpc_cookie_with_hook_v1(&cookie_config, || {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(&cookie_path)
                .map_err(|_| PreflightFailureV1::new("test.core-cookie", "open-failed"))?;
            file.seek(SeekFrom::Start(0))
                .map_err(|_| PreflightFailureV1::new("test.core-cookie", "seek-failed"))?;
            file.write_all(changed_cookie.as_bytes())
                .map_err(|_| PreflightFailureV1::new("test.core-cookie", "write-failed"))?;
            file.sync_all()
                .map_err(|_| PreflightFailureV1::new("test.core-cookie", "sync-failed"))
        })
        .unwrap_err();
        assert_eq!(error.reason, "content-changed");

        std::fs::write(&cookie_path, valid_cookie.as_bytes()).unwrap();
        std::fs::set_permissions(&cookie_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let replaced = cookie_config.protected_parent.join("cookie-replaced");
        let error = read_validated_core_rpc_cookie_with_hook_v1(&cookie_config, || {
            std::fs::rename(&cookie_path, &replaced)
                .map_err(|_| PreflightFailureV1::new("test.core-cookie", "rename-failed"))?;
            std::fs::write(&cookie_path, valid_cookie.as_bytes())
                .map_err(|_| PreflightFailureV1::new("test.core-cookie", "write-failed"))?;
            std::fs::set_permissions(&cookie_path, std::fs::Permissions::from_mode(0o600))
                .map_err(|_| PreflightFailureV1::new("test.core-cookie", "chmod-failed"))
        })
        .unwrap_err();
        assert_eq!(error.reason, "file-changed");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn core_rpc_cookie_rejects_extended_acl_on_cookie_and_parent() {
        let (_directory, cookie_config, cookie_path) = same_uid_cookie_fixture();
        assert!(std::process::Command::new("chmod")
            .args(["+a", "everyone allow read"])
            .arg(&cookie_path)
            .status()
            .unwrap()
            .success());
        assert_eq!(
            validate_core_rpc_cookie_v1(&cookie_config)
                .unwrap_err()
                .reason,
            "unsafe-cookie-acl"
        );

        assert!(std::process::Command::new("chmod")
            .args(["-N"])
            .arg(&cookie_path)
            .status()
            .unwrap()
            .success());
        assert!(std::process::Command::new("chmod")
            .args(["+a", "everyone allow read"])
            .arg(&cookie_config.protected_parent)
            .status()
            .unwrap()
            .success());
        assert_eq!(
            validate_core_rpc_cookie_v1(&cookie_config)
                .unwrap_err()
                .reason,
            "unsafe-parent-boundary"
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
    fn backup_receipt_state_directory_requires_exact_mode_0700() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let parent_metadata = std::fs::metadata(directory.path()).unwrap();
        let receipt_path = directory.path().join("backup-receipt.toml");
        let receipt_bytes = toml::to_string(&receipt(StagingRoleV1::Payer)).unwrap();
        std::fs::write(&receipt_path, receipt_bytes.as_bytes()).unwrap();
        std::fs::set_permissions(&receipt_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let backup = BackupConfigV1 {
            receipt: receipt_path,
            protected_parent: directory.path().to_path_buf(),
            expected_uid: parent_metadata.uid(),
            expected_gid: parent_metadata.gid(),
            max_age_seconds: 3600,
        };

        assert_eq!(
            read_protected_receipt_v1(&backup).unwrap_err().reason,
            "unsafe-protected-parent"
        );
        assert_eq!(
            write_atomic_backup_receipt_v1(&backup, receipt_bytes.as_bytes())
                .unwrap_err()
                .reason,
            "unsafe-output-parent"
        );
    }

    #[cfg(unix)]
    #[test]
    fn backup_receipt_unlock_releases_a_flock_while_duplicate_fd_remains_open() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let parent_metadata = std::fs::metadata(directory.path()).unwrap();
        let receipt_path = directory.path().join("backup-receipt.toml");
        let backup = BackupConfigV1 {
            receipt: receipt_path.clone(),
            protected_parent: directory.path().to_path_buf(),
            expected_uid: parent_metadata.uid(),
            expected_gid: parent_metadata.gid(),
            max_age_seconds: 3600,
        };
        let first = toml::to_string(&receipt(StagingRoleV1::Payer)).unwrap();
        let second = toml::to_string(&BackupReceiptV1 {
            recorded_at_unix: NOW + 1,
            ..receipt(StagingRoleV1::Payer)
        })
        .unwrap();
        let mut duplicate_parent = None;

        let first_result =
            write_atomic_backup_receipt_with_hook_v1(&backup, first.as_bytes(), |parent| {
                duplicate_parent = Some(
                    rustix::io::dup(parent)
                        .map_err(|_| PreflightFailureV1::new("backup.test", "dup-failed"))?,
                );
                Ok(())
            });

        // The duplicate still references the locked directory's original open
        // file description. Dropping only the writer's descriptor would leave
        // that flock held; its explicit LOCK_UN must make this second write pass.
        let second_result = if first_result.is_ok() && duplicate_parent.is_some() {
            Some(write_atomic_backup_receipt_v1(&backup, second.as_bytes()))
        } else {
            None
        };

        assert!(
            first_result.is_ok(),
            "first receipt write failed: {first_result:?}"
        );
        let duplicate_parent = duplicate_parent.expect("duplicate parent descriptor must exist");
        let second_result = second_result.expect("duplicate parent descriptor must exist");
        assert!(
            second_result.is_ok(),
            "explicit unlock did not release the shared flock: {second_result:?}",
        );
        drop(duplicate_parent);
        assert_eq!(std::fs::read_to_string(receipt_path).unwrap(), second);
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

        let error = write_atomic_backup_receipt_with_hook_v1(&backup, new.as_bytes(), |_| {
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
    async fn bootstrap_command_layer_is_fixed_read_only_and_skips_gossip() {
        let config = config(StagingRoleV1::Payer);
        let plugin_json = serde_json::json!({
            "command": "list",
            "plugins": [{"name": PLUGIN, "active": true, "dynamic": false}]
        });
        let mut runner = FakeRunnerV1 {
            responses: VecDeque::from(vec![
                serde_json::to_vec(&serde_json::json!({"version": 290000, "subversion": "/Satoshi:29.0.0/"})).unwrap(),
                serde_json::to_vec(&serde_json::json!({"chain": "signet", "blocks": 1000, "headers": 1000, "initialblockdownload": false, "signet_challenge": DEFAULT_SIGNET_CHALLENGE_V1})).unwrap(),
                format!("{DEFAULT_SIGNET_GENESIS_V1}\n").into_bytes(),
                serde_json::to_vec(&serde_json::json!({"id": PAYER, "version": "v26.06.6", "network": "signet", "blockheight": 1000})).unwrap(),
                serde_json::to_vec(&plugin_json).unwrap(),
                serde_json::to_vec(&serde_json::json!({"channels": []})).unwrap(),
                serde_json::to_vec(&serde_json::json!({"outputs": [], "channels": []})).unwrap(),
                serde_json::to_vec(&serde_json::json!({"scb": []})).unwrap(),
            ]),
            commands: Vec::new(),
        };
        let snapshot = collect_bootstrap_snapshot_v1(&config, &mut runner)
            .await
            .unwrap();
        let ids = validate_static_config_v1(&config).unwrap();
        validate_bootstrap_snapshot_v1(&config, &ids, &snapshot).unwrap();
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
        assert_eq!(
            runner.commands,
            vec![
                command(&core, &core_base, &["getnetworkinfo"]),
                command(&core, &core_base, &["getblockchaininfo"]),
                command(&core, &core_base, &["getblockhash", "0"]),
                command(&cln, &cln_base, &["getinfo"]),
                command(&cln, &cln_base, &["plugin", "list"]),
                command(&cln, &cln_base, &["listpeerchannels"]),
                command(&cln, &cln_base, &["listfunds"]),
                command(&cln, &cln_base, &["staticbackup"]),
            ]
        );
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

    #[test]
    fn cln_invocation_id_and_generation_binding_are_closed() {
        const FIRST: &str = "0123456789abcdef0123456789abcdef";
        const SECOND: &str = "1123456789abcdef0123456789abcdef";

        validate_cln_invocation_id_v1(FIRST).unwrap();
        validate_cln_invocation_binding_v1(None, FIRST, FIRST).unwrap();
        validate_cln_invocation_binding_v1(Some(FIRST), FIRST, FIRST).unwrap();

        for invalid in [
            "",
            "0123456789abcdef",
            "0123456789ABCDEF0123456789ABCDEF",
            "00000000000000000000000000000000",
            "ffffffffffffffffffffffffffffffff",
            "0123456789abcdef0123456789abcdeg",
            "/123456789abcdef0123456789abcdef",
        ] {
            assert_eq!(
                validate_cln_invocation_id_v1(invalid).unwrap_err().reason,
                "invalid-invocation-id"
            );
        }

        for error in [
            validate_cln_invocation_binding_v1(None, FIRST, SECOND).unwrap_err(),
            validate_cln_invocation_binding_v1(Some(SECOND), FIRST, FIRST).unwrap_err(),
        ] {
            assert_eq!(error.check, "systemd.cln-invocation");
            assert_eq!(error.reason, "generation-changed");
            assert!(!error.to_string().contains(FIRST));
            assert!(!error.to_string().contains(SECOND));
        }
    }

    #[cfg(unix)]
    #[test]
    fn systemd_invocation_mapping_requires_one_root_owned_fixed_size_symlink() {
        let valid = SystemdInvocationLinkSnapshotV1 {
            device: 1,
            inode: 2,
            mode: 0o120777,
            size: 32,
            uid: 0,
            gid: 0,
            links: 1,
            modified_seconds: 3,
            modified_nanoseconds: 4,
            changed_seconds: 5,
            changed_nanoseconds: 6,
        };
        validate_systemd_invocation_link_snapshot_v1(valid).unwrap();
        for invalid in [
            SystemdInvocationLinkSnapshotV1 {
                mode: 0o100444,
                ..valid
            },
            SystemdInvocationLinkSnapshotV1 { size: 31, ..valid },
            SystemdInvocationLinkSnapshotV1 { uid: 1, ..valid },
            SystemdInvocationLinkSnapshotV1 { gid: 1, ..valid },
            SystemdInvocationLinkSnapshotV1 { links: 2, ..valid },
        ] {
            assert_eq!(
                validate_systemd_invocation_link_snapshot_v1(invalid)
                    .unwrap_err()
                    .reason,
                "unsafe-invocation-link"
            );
        }
    }

    #[test]
    fn preflight_lease_has_one_exact_short_lifetime_and_generation() {
        // Source/render gates independently pin both downstream services to a
        // 30-second stop bound. Keep an additional full minute beyond the
        // watchdog plus that worst-case propagation window.
        const {
            assert!(PREFLIGHT_WATCHDOG_USEC_V1 % 1_000_000 == 0);
            assert!(
                PREFLIGHT_LEASE_REFRESH_SECONDS_V1 + PREFLIGHT_RENEWAL_ROUND_TIMEOUT_SECONDS_V1
                    < PREFLIGHT_WATCHDOG_USEC_V1 / 1_000_000
            );
            assert!(
                PREFLIGHT_LEASE_VALIDITY_SECONDS_V1
                    >= PREFLIGHT_WATCHDOG_USEC_V1 / 1_000_000 + 30 + 60
            );
        }
        let valid = PreflightLeaseV1 {
            schema_version: PREFLIGHT_LEASE_SCHEMA_V1,
            cln_invocation_id: "0123456789abcdef0123456789abcdef".to_owned(),
            checked_at_unix: NOW,
            valid_until_unix: NOW + PREFLIGHT_LEASE_VALIDITY_SECONDS_V1,
        };
        validate_preflight_lease_v1(&valid).unwrap();
        let encoded = toml::to_string(&valid).unwrap();
        assert_eq!(toml::from_str::<PreflightLeaseV1>(&encoded).unwrap(), valid);

        let invalid = [
            PreflightLeaseV1 {
                schema_version: 2,
                ..valid.clone()
            },
            PreflightLeaseV1 {
                checked_at_unix: 0,
                valid_until_unix: PREFLIGHT_LEASE_VALIDITY_SECONDS_V1,
                ..valid.clone()
            },
            PreflightLeaseV1 {
                valid_until_unix: NOW + PREFLIGHT_LEASE_VALIDITY_SECONDS_V1 - 1,
                ..valid.clone()
            },
            PreflightLeaseV1 {
                cln_invocation_id: "0".repeat(32),
                ..valid
            },
        ];
        for lease in invalid {
            assert!(validate_preflight_lease_v1(&lease).is_err());
        }
    }

    #[tokio::test]
    async fn supervisor_manager_watchdog_check_uses_exact_typed_busctl_request() {
        let payer_config = config(StagingRoleV1::Payer);
        let mut runner = FakeRunnerV1 {
            responses: VecDeque::from(vec![br#"{"type":"b","data":true}"#.to_vec()]),
            commands: Vec::new(),
        };
        query_systemd_service_watchdogs_enabled_v1(&payer_config, &mut runner)
            .await
            .unwrap();
        assert_eq!(
            runner.commands,
            vec![CapturedCommandV1 {
                program: PathBuf::from("/usr/bin/busctl"),
                args: vec![
                    "--system".to_owned(),
                    "--json=short".to_owned(),
                    "get-property".to_owned(),
                    "org.freedesktop.systemd1".to_owned(),
                    "/org/freedesktop/systemd1".to_owned(),
                    "org.freedesktop.systemd1.Manager".to_owned(),
                    "ServiceWatchdogs".to_owned(),
                ],
            }]
        );

        for (body, reason) in [
            (
                br#"{"type":"b","data":false}"#.as_slice(),
                "manager-disabled",
            ),
            (
                br#"{"type":"u","data":1}"#.as_slice(),
                "invalid-manager-property",
            ),
            (
                br#"{"type":"b","data":true,"extra":0}"#.as_slice(),
                "invalid-manager-property",
            ),
            (b"not-json".as_slice(), "invalid-manager-property"),
        ] {
            assert_eq!(
                parse_systemd_service_watchdogs_property_v1(body)
                    .unwrap_err()
                    .reason,
                reason
            );
        }

        let invalid_boundaries = [
            {
                let mut value = config(StagingRoleV1::Payer);
                value.systemd.busctl.path = PathBuf::from("/usr/local/bin/busctl");
                value
            },
            {
                let mut value = config(StagingRoleV1::Payer);
                value.systemd.busctl.protected_parent = PathBuf::from("/usr");
                value
            },
            {
                let mut value = config(StagingRoleV1::Payer);
                value.systemd.busctl.expected_uid = 1;
                value
            },
            {
                let mut value = config(StagingRoleV1::Payer);
                value.systemd.busctl.expected_gid = 1;
                value
            },
        ];
        for invalid in invalid_boundaries {
            let failure = validate_systemd_busctl_config_v1(&invalid).unwrap_err();
            assert_eq!(failure.check, "config.systemd-busctl");
            assert_eq!(failure.reason, "invalid-binary-boundary");
        }
    }

    #[test]
    fn preflight_lease_clock_must_advance_across_renewals() {
        validate_lease_clock_v1(NOW, NOW, None).unwrap();
        validate_lease_clock_v1(NOW + 1, NOW + 2, Some(NOW)).unwrap();

        for error in [
            validate_lease_clock_v1(0, NOW, None).unwrap_err(),
            validate_lease_clock_v1(NOW + 1, NOW, None).unwrap_err(),
            validate_lease_clock_v1(NOW, NOW, Some(NOW)).unwrap_err(),
            validate_lease_clock_v1(NOW, NOW - 1, Some(NOW)).unwrap_err(),
        ] {
            assert_eq!(error.check, "lease.clock");
            assert_eq!(error.reason, "clock-regressed");
        }
    }

    #[test]
    fn backup_receipt_age_is_rechecked_at_lease_commit_time() {
        assert_eq!(
            validate_backup_receipt_age_v1(NOW - 30, 30, NOW).unwrap(),
            30
        );
        assert_eq!(
            validate_backup_receipt_age_v1(NOW - 30, 30, NOW + 1)
                .unwrap_err()
                .reason,
            "stale-receipt"
        );
        assert_eq!(
            validate_backup_receipt_age_v1(NOW + 1, 30, NOW)
                .unwrap_err()
                .reason,
            "future-timestamp"
        );
    }

    #[cfg(unix)]
    #[test]
    fn supervisor_environment_requires_exact_watchdog_pid_and_notify_address() {
        const CURRENT_PID: u32 = 4_242;
        let usec = PREFLIGHT_WATCHDOG_USEC_V1.to_string();
        let pid = CURRENT_PID.to_string();
        validate_systemd_supervisor_environment_values_v1(
            Some(std::ffi::OsStr::new(&usec)),
            None,
            Some(std::ffi::OsStr::new("/run/systemd/notify")),
            CURRENT_PID,
        )
        .unwrap();
        validate_systemd_supervisor_environment_values_v1(
            Some(std::ffi::OsStr::new(&usec)),
            Some(std::ffi::OsStr::new(&pid)),
            Some(std::ffi::OsStr::new("@systemd-notify")),
            CURRENT_PID,
        )
        .unwrap();

        for error in [
            validate_systemd_supervisor_environment_values_v1(
                None,
                None,
                Some(std::ffi::OsStr::new("/run/systemd/notify")),
                CURRENT_PID,
            )
            .unwrap_err(),
            validate_systemd_supervisor_environment_values_v1(
                Some(std::ffi::OsStr::new("0")),
                None,
                Some(std::ffi::OsStr::new("/run/systemd/notify")),
                CURRENT_PID,
            )
            .unwrap_err(),
            validate_systemd_supervisor_environment_values_v1(
                Some(std::ffi::OsStr::new(&usec)),
                Some(std::ffi::OsStr::new("4243")),
                Some(std::ffi::OsStr::new("/run/systemd/notify")),
                CURRENT_PID,
            )
            .unwrap_err(),
        ] {
            assert_eq!(error.check, "systemd.watchdog");
            assert_eq!(error.reason, "invalid-watchdog-environment");
        }
        for notify_socket in [None, Some(""), Some("relative.sock"), Some("@")] {
            let error = validate_systemd_supervisor_environment_values_v1(
                Some(std::ffi::OsStr::new(&usec)),
                None,
                notify_socket.map(std::ffi::OsStr::new),
                CURRENT_PID,
            )
            .unwrap_err();
            assert_eq!(error.check, "systemd.notify");
        }
    }

    #[cfg(unix)]
    #[test]
    fn systemd_notify_uses_one_bounded_unix_datagram() {
        use std::os::unix::net::UnixDatagram;

        let directory = tempfile::Builder::new()
            .prefix("bpir-notify-")
            .tempdir_in("/tmp")
            .unwrap();
        let socket_path = directory.path().join("notify.sock");
        let receiver = UnixDatagram::bind(&socket_path).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let expected = b"READY=1\nWATCHDOG=1\nSTATUS=test";
        systemd_notify_to_v1(socket_path.as_os_str(), expected).unwrap();
        let mut received = [0u8; 128];
        let count = receiver.recv(&mut received).unwrap();
        assert_eq!(&received[..count], expected);

        for invalid in [b"".as_slice(), &[0u8][..], &[b'x'; 513][..]] {
            assert_eq!(
                systemd_notify_to_v1(socket_path.as_os_str(), invalid)
                    .unwrap_err()
                    .reason,
                "invalid-notification"
            );
        }
        assert_eq!(
            systemd_notify_to_v1(std::ffi::OsStr::new("relative.sock"), b"READY=1")
                .unwrap_err()
                .reason,
            "invalid-notify-socket"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn systemd_notify_supports_linux_abstract_socket() {
        use rustix::net::{
            bind, recvfrom, socket_with, AddressFamily, RecvFlags, SocketAddrUnix, SocketFlags,
            SocketType,
        };
        use std::mem::MaybeUninit;
        use std::os::unix::ffi::OsStringExt;

        let mut nonce = [0u8; 8];
        getrandom::getrandom(&mut nonce).unwrap();
        let name = format!("bpir-notify-{}-{}", std::process::id(), hex::encode(nonce));
        let address = SocketAddrUnix::new_abstract_name(name.as_bytes()).unwrap();
        let receiver = socket_with(
            AddressFamily::UNIX,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        bind(&receiver, &address).unwrap();

        let mut notify_name = vec![b'@'];
        notify_name.extend_from_slice(name.as_bytes());
        let notify_name = std::ffi::OsString::from_vec(notify_name);
        let expected = b"READY=1\nWATCHDOG=1";
        systemd_notify_to_v1(&notify_name, expected).unwrap();

        let mut buffer = [MaybeUninit::<u8>::uninit(); 128];
        let ((received, _unused), full_length, _) =
            recvfrom(&receiver, &mut buffer[..], RecvFlags::empty()).unwrap();
        assert_eq!(full_length, expected.len());
        assert_eq!(received, expected);
    }
}
