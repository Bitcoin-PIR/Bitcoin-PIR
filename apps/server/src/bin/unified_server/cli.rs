use crate::unified_server_pir2_sealed::{Pir2SealedCliV1, Pir2SealedStartupPhaseV1};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;

// ─── CLI ────────────────────────────────────────────────────────────────────

/// Loosely-coupled flag controlling **only OnionPIR loading** at startup.
///
/// History: `Primary` and `Secondary` originally bundled three
/// independent decisions — OnionPIR loading, HarmonyPIR query
/// dispatch, HarmonyPIR hint dispatch. That bundling pinned operators
/// into "primary host = full stack, secondary host = hint-only" which
/// made it awkward to allocate workload to where the hardware fits.
///
/// Today the role flag controls only one thing: whether to attempt
/// loading OnionPIR data files at startup. Both roles handle every
/// DPF and HarmonyPIR opcode (hint, query, batch query, info). The
/// CLIENT chooses which endpoint to send hint vs query requests to —
/// the two-server non-collusion property of HarmonyPIR comes from
/// picking independent operators/hardware, not from server-side
/// dispatch gating.
///
/// `--disable-onion` overrides the OnionPIR-loading default for a
/// primary-role instance that doesn't have the data files (e.g., the
/// VPSBG host, which is OnionPIR-free by design).
///
/// (The variant names are kept for back-compat with existing systemd
/// units and CLI invocations; semantically they could just as well be
/// `WithOnion`/`NoOnion`.)
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum ServerRole {
    /// Tries to load OnionPIR data at startup unless `--disable-onion`
    /// is set. Both Hetzner (which has OnionPIR data) and VPSBG (which
    /// doesn't, hence `--disable-onion`) can run as Primary safely;
    /// the loader gracefully skips on missing files.
    Primary,
    /// Skips OnionPIR loading entirely. Useful when the operator
    /// wants to be explicit about "this server is intentionally
    /// OnionPIR-free" without relying on file-presence detection.
    Secondary,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HarmonyPoolBinding {
    pub(crate) db_id: u8,
    pub(crate) pool_dir: Option<PathBuf>,
}

pub(crate) struct CliArgs {
    /// IP address to bind. The production-compatible default remains the
    /// dual-stack wildcard; local integration harnesses can explicitly bind
    /// 127.0.0.1 so the test listener is never exposed off-host.
    pub(crate) bind_address: IpAddr,
    pub(crate) port: u16,
    pub(crate) data_dir: PathBuf,
    pub(crate) role: ServerRole,
    /// Path to databases.toml config file (overrides --checkpoint/--delta).
    pub(crate) config_path: Option<PathBuf>,
    /// Checkpoint databases: (path, height).
    pub(crate) checkpoints: Vec<(PathBuf, u32)>,
    /// Delta databases: (path, base_height, tip_height).
    pub(crate) deltas: Vec<(PathBuf, u32, u32)>,
    /// Hex-encoded ed25519 admin pubkey (64 chars). When set, REQ_ADMIN_*
    /// requests are accepted and gated by challenge/response auth against
    /// this key. When unset, all REQ_ADMIN_* requests return an error
    /// envelope.
    pub(crate) admin_pubkey_hex: Option<String>,
    /// Skip OnionPIR loading even if files are present and this is a
    /// primary-role instance. Used on hosts that are intentionally
    /// OnionPIR-free (e.g., the VPSBG non-collusion partner where
    /// OnionPIR data is not synced from Hetzner). Primary role
    /// otherwise auto-loads OnionPIR if files exist.
    pub(crate) disable_onion: bool,
    /// Directory containing the AMD VCEK chain PEMs. Expected files:
    ///   - cert_chain.pem  (ASK + ARK concatenated, as AMD KDS returns)
    ///   - vcek.pem        (the per-chip VCEK for the current TCB)
    ///
    /// If unset (or files missing), the AttestResult ships empty cert
    /// fields and the browser-side verifier falls back to V2-binding-
    /// only mode. Operator's responsibility to refresh after TCB
    /// changes (kernel update, microcode update) — see
    /// docs/history/PHASE3_ROADMAP.md.
    pub(crate) vcek_dir: Option<PathBuf>,
    /// HarmonyPIR V2 hint pool size per configured database (0 = disabled).
    pub(crate) pool_size: usize,
    /// Exact immutable database/directory bindings for the V2 hint pools.
    /// Legacy `--pool-db-id`/`--pool-dir` normalizes to one entry; repeated
    /// `--harmony-pool-db <db_id>=<dir>` entries enable explicit multi-pool.
    pub(crate) harmony_pool_bindings: Vec<HarmonyPoolBinding>,
    /// Require ARC credential presentation before serving PIR queries.
    pub(crate) require_arc: bool,
    /// Path to the 128-byte ARC private key (`arc_key.bin`) shared with the
    /// issuer. When set with `--require-arc`, the verifier loads this key so
    /// externally-issued credentials verify. Without it, a random key is
    /// generated (no external credential can verify — dev/test only).
    pub(crate) arc_key_path: Option<PathBuf>,
    /// Operator-local admission configuration (`--local-admission-config`).
    /// Replaces the legacy signed-policy surface; mutually exclusive with it.
    pub(crate) local_admission_config: Option<PathBuf>,
    pub(crate) require_cashu: bool,
    pub(crate) cashu_keysets: Vec<(String, String)>,
    /// Measurement-bound pir2 identity dispatcher. This group is
    /// evaluated before any database, ORAM image, or listener is opened.
    pub(crate) pir2_sealed: Pir2SealedCliV1,
    /// Hard cap on live TCP/WebSocket tasks. Connections over the cap are
    /// dropped before allocating a WebSocket parser.
    pub(crate) max_connections: usize,
    pub(crate) websocket_handshake_timeout_ms: u64,
    pub(crate) connection_idle_timeout_ms: u64,
    /// Explicitly enables privacy-dangerous per-connection/per-query logs.
    #[cfg(any(test, feature = "test-only-unsafe-query-logging"))]
    pub(crate) unsafe_debug_query_logging: bool,
    /// Whether this server accepts HarmonyPIR hint requests
    /// (`REQ_HARMONY_HINTS` / `REQ_HARMONY_HINTS_V2`). Default `false`;
    /// must be explicitly enabled via `--serve-hints`. Combined with
    /// `--serve-queries` to pin the role: pir1 (Hetzner, no-SEV) runs
    /// `--serve-hints --serve-queries` (HarmonyPIR hint pool + DPF
    /// server-0 + OnionPIR); pir2 (VPSBG, SEV-SNP Tier 3) runs
    /// `--serve-queries` only (DPF server-1 + HarmonyPIR query phase).
    /// Misconfiguration (client hits the wrong role) becomes a
    /// wire-level rejection instead of silently falling through to
    /// the legacy V1-on-demand path or producing confusing errors.
    pub(crate) serve_hints: bool,
    /// Whether this server accepts PIR query requests (DPF batches,
    /// OnionPIR queries, HarmonyPIR query phase, Merkle siblings,
    /// tree-tops). Default `false`; must be explicitly enabled via
    /// `--serve-queries`. See `serve_hints` for the deployment
    /// topology rationale.
    pub(crate) serve_queries: bool,
    /// Path to the server's long-lived Ed25519 identity key (raw 32-byte
    /// seed). Combined with `--identity-cert-path` to build the
    /// REQ_ANNOUNCE bundle. If either is missing or fails to load,
    /// REQ_ANNOUNCE is disabled but the rest of the protocol runs
    /// normally. Generate one with `bpir-admin generate-identity`.
    pub(crate) identity_key_path: Option<PathBuf>,
    /// Path to the operator-signed IdentityCert (raw bytes produced by
    /// `bpir-admin sign-identity`, encoded per
    /// `pir_identity::IdentityCert::encode`).
    pub(crate) identity_cert_path: Option<PathBuf>,
    /// Human-readable server identifier (e.g. "pir1", "pir2"). Bound
    /// into the announcement bundle; cross-checked against the cert
    /// loaded from `--identity-cert-path`. Required if either of the
    /// identity flags is set.
    pub(crate) identity_server_id: Option<String>,
    /// Optional Circuit ORAM image directory for the two-level cuckoo tables
    /// (legacy alias for db_id=0, levels 0/1 only). Built by `oramctl build-circuit`.
    pub(crate) cuckoo_oram_dir: Option<PathBuf>,
    /// Optional per-database Circuit ORAM image directories.
    /// Repeatable as `--cuckoo-oram-db <db_id>=<dir>`.
    pub(crate) cuckoo_oram_dbs: Vec<(u8, PathBuf)>,
    /// Consecutive cuckoo bins packed into one ORAM logical block.
    pub(crate) cuckoo_oram_pack: usize,
    /// Public deterministic evictions drained after each ORAM bin read.
    pub(crate) cuckoo_oram_drain_per_access: u64,
    /// Whether ORAM metadata/payload page files are AEAD wrapped.
    pub(crate) cuckoo_oram_encrypted: bool,
    /// 32-byte hex key for encrypted ORAM page files.
    pub(crate) cuckoo_oram_key_hex: Option<String>,
    /// 32-byte hex key for encrypted ORAM controller state.
    pub(crate) cuckoo_oram_state_key_hex: Option<String>,
    /// Public top-tree levels cached in trusted memory.
    pub(crate) cuckoo_oram_cache_levels: usize,
    /// Authenticate disk-backed ORAM page images with split Merkle stores.
    pub(crate) cuckoo_oram_auth_store: bool,
    /// Do not persist trusted ORAM state after query responses.
    pub(crate) cuckoo_oram_no_save: bool,
    /// Optional direct-entry ORAM image directory for db_id=0.
    pub(crate) direct_oram_dir: Option<PathBuf>,
    /// Optional per-database direct-entry ORAM image directories.
    /// Repeatable as `--direct-oram-db <db_id>=<dir>`.
    pub(crate) direct_oram_dbs: Vec<(u8, PathBuf)>,
    /// Optional per-database trusted controller/auth state directories.
    /// Repeatable as `--direct-oram-trusted-state-db <db_id>=<dir>`.
    pub(crate) direct_oram_trusted_state_dbs: Vec<(u8, PathBuf)>,
    /// Development/test-only escape hatch for trusted state outside the
    /// measured `/run/bitcoinpir-oram-state` tmpfs.
    #[cfg_attr(not(feature = "cuckoo-oram"), allow(dead_code))]
    pub(crate) direct_oram_allow_trusted_state_outside_run_dev: bool,
    /// Public deterministic evictions drained after each direct ORAM read.
    pub(crate) direct_oram_drain_per_access: u64,
    /// Fixed direct ORAM access budget per ORAM lookup request.
    pub(crate) direct_oram_access_budget: usize,
    /// Whether direct ORAM metadata/payload page files are AEAD wrapped.
    pub(crate) direct_oram_encrypted: bool,
    /// 32-byte hex key for encrypted direct ORAM page files.
    pub(crate) direct_oram_key_hex: Option<String>,
    /// 32-byte hex key for encrypted direct ORAM controller state.
    pub(crate) direct_oram_state_key_hex: Option<String>,
    /// Public top-tree levels cached in trusted memory.
    pub(crate) direct_oram_cache_levels: usize,
    /// Authenticate disk-backed direct ORAM page images with split Merkle stores.
    pub(crate) direct_oram_auth_store: bool,
    /// Do not persist trusted direct ORAM state after query responses.
    pub(crate) direct_oram_no_save: bool,
}

pub(crate) fn parse_cuckoo_oram_db_arg(spec: &str) -> Result<(u8, PathBuf), String> {
    let Some((db_id_raw, dir_raw)) = spec.split_once('=') else {
        return Err(
            "--cuckoo-oram-db expects <db_id>=<dir> (legacy alias: --harmony-oram-db)".into(),
        );
    };
    let db_id = db_id_raw
        .parse::<u8>()
        .map_err(|e| format!("invalid --cuckoo-oram-db db_id `{}`: {}", db_id_raw, e))?;
    if dir_raw.is_empty() {
        return Err("--cuckoo-oram-db requires a non-empty directory".into());
    }
    Ok((db_id, PathBuf::from(dir_raw)))
}

pub(crate) fn parse_harmony_pool_db_arg(spec: &str) -> Result<(u8, PathBuf), String> {
    let Some((db_id_raw, dir_raw)) = spec.split_once('=') else {
        return Err("--harmony-pool-db expects <db_id>=<dir>".into());
    };
    let db_id = db_id_raw
        .parse::<u8>()
        .map_err(|e| format!("invalid --harmony-pool-db db_id `{db_id_raw}`: {e}"))?;
    if dir_raw.is_empty() {
        return Err("--harmony-pool-db requires a non-empty directory".into());
    }
    Ok((db_id, PathBuf::from(dir_raw)))
}

pub(crate) fn normalize_harmony_pool_bindings(
    pool_size: usize,
    legacy_db_id: u8,
    legacy_db_id_explicit: bool,
    legacy_pool_dir: Option<PathBuf>,
    explicit: Vec<(u8, PathBuf)>,
) -> Result<Vec<HarmonyPoolBinding>, String> {
    if explicit.is_empty() {
        return Ok((pool_size > 0)
            .then_some(HarmonyPoolBinding {
                db_id: legacy_db_id,
                pool_dir: legacy_pool_dir,
            })
            .into_iter()
            .collect());
    }
    if pool_size == 0 {
        return Err("--harmony-pool-db requires --pool-size greater than zero".into());
    }
    if legacy_db_id_explicit || legacy_pool_dir.is_some() {
        return Err("--harmony-pool-db cannot be combined with --pool-db-id or --pool-dir".into());
    }

    let mut by_database = BTreeMap::new();
    let mut directories = BTreeSet::new();
    for (db_id, pool_dir) in explicit {
        if by_database.contains_key(&db_id) {
            return Err(format!(
                "--harmony-pool-db configures database {db_id} more than once"
            ));
        }
        if !directories.insert(pool_dir.clone()) {
            return Err(format!(
                "--harmony-pool-db reuses pool directory {}",
                pool_dir.display()
            ));
        }
        by_database.insert(
            db_id,
            HarmonyPoolBinding {
                db_id,
                pool_dir: Some(pool_dir),
            },
        );
    }
    Ok(by_database.into_values().collect())
}

pub(crate) fn parse_direct_oram_db_arg(spec: &str) -> Result<(u8, PathBuf), String> {
    let Some((db_id_raw, dir_raw)) = spec.split_once('=') else {
        return Err("--direct-oram-db expects <db_id>=<dir>".into());
    };
    let db_id = db_id_raw
        .parse::<u8>()
        .map_err(|e| format!("invalid --direct-oram-db db_id `{}`: {}", db_id_raw, e))?;
    if dir_raw.is_empty() {
        return Err("--direct-oram-db requires a non-empty directory".into());
    }
    Ok((db_id, PathBuf::from(dir_raw)))
}

pub(crate) fn parse_direct_oram_trusted_state_db_arg(spec: &str) -> Result<(u8, PathBuf), String> {
    let Some((db_id_raw, dir_raw)) = spec.split_once('=') else {
        return Err("--direct-oram-trusted-state-db expects <db_id>=<dir>".into());
    };
    let db_id = db_id_raw.parse::<u8>().map_err(|e| {
        format!(
            "invalid --direct-oram-trusted-state-db db_id `{}`: {}",
            db_id_raw, e
        )
    })?;
    if dir_raw.is_empty() {
        return Err("--direct-oram-trusted-state-db requires a non-empty directory".into());
    }
    Ok((db_id, PathBuf::from(dir_raw)))
}

pub(crate) fn fatal_cli(msg: impl AsRef<str>) -> ! {
    eprintln!("ERROR: {}", msg.as_ref());
    std::process::exit(2);
}

pub(crate) fn parse_args() -> CliArgs {
    parse_args_from(std::env::args().collect())
}

pub(crate) fn parse_args_from(args: Vec<String>) -> CliArgs {
    let mut bind_address = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
    let mut port = 8091u16;
    let mut data_dir = PathBuf::from("/Volumes/Bitcoin/data/checkpoints/940611");
    let mut role = ServerRole::Primary;
    let mut config_path: Option<PathBuf> = None;
    let mut checkpoints: Vec<(PathBuf, u32)> = Vec::new();
    let mut deltas: Vec<(PathBuf, u32, u32)> = Vec::new();
    let mut admin_pubkey_hex: Option<String> = None;
    let mut disable_onion = false;
    let mut vcek_dir: Option<PathBuf> = None;
    let mut pool_size: usize = 0; // 0 = pool disabled
    let mut pool_db_id: u8 = 0;
    let mut pool_db_id_explicit = false;
    let mut pool_dir: Option<PathBuf> = None;
    let mut harmony_pool_dbs: Vec<(u8, PathBuf)> = Vec::new();
    let mut require_arc = false;
    let mut arc_key_path: Option<PathBuf> = None;
    let mut local_admission_config: Option<PathBuf> = None;
    let mut require_cashu = false;
    let mut cashu_keysets: Vec<(String, String)> = Vec::new();
    let mut pir2_sealed = Pir2SealedCliV1::default();
    let mut max_connections: usize = 128;
    let mut websocket_handshake_timeout_ms: u64 = 10_000;
    let mut connection_idle_timeout_ms: u64 = 30_000;
    #[cfg(any(test, feature = "test-only-unsafe-query-logging"))]
    let mut unsafe_debug_query_logging = false;
    let mut serve_hints = false;
    let mut serve_queries = false;
    let mut identity_key_path: Option<PathBuf> = None;
    let mut identity_cert_path: Option<PathBuf> = None;
    let mut identity_server_id: Option<String> = None;
    let mut cuckoo_oram_dir: Option<PathBuf> = None;
    let mut cuckoo_oram_dbs: Vec<(u8, PathBuf)> = Vec::new();
    let mut cuckoo_oram_pack: usize = 16;
    let mut cuckoo_oram_drain_per_access: u64 = 2;
    let mut cuckoo_oram_encrypted = false;
    let mut cuckoo_oram_key_hex: Option<String> = None;
    let mut cuckoo_oram_state_key_hex: Option<String> = None;
    let mut cuckoo_oram_cache_levels: usize = 0;
    let mut cuckoo_oram_auth_store = false;
    let mut cuckoo_oram_no_save = false;
    let mut direct_oram_dir: Option<PathBuf> = None;
    let mut direct_oram_dbs: Vec<(u8, PathBuf)> = Vec::new();
    let mut direct_oram_trusted_state_dbs: Vec<(u8, PathBuf)> = Vec::new();
    let mut direct_oram_allow_trusted_state_outside_run_dev = false;
    let mut direct_oram_drain_per_access: u64 = 2;
    let mut direct_oram_access_budget: usize = 75;
    let mut direct_oram_encrypted = false;
    let mut direct_oram_key_hex: Option<String> = None;
    let mut direct_oram_state_key_hex: Option<String> = None;
    let mut direct_oram_cache_levels: usize = 0;
    let mut direct_oram_auth_store = false;
    let mut direct_oram_no_save = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--bind-address" => {
                bind_address = args
                    .get(i + 1)
                    .unwrap_or_else(|| fatal_cli("--bind-address requires an IP address"))
                    .parse::<IpAddr>()
                    .unwrap_or_else(|_| fatal_cli("--bind-address requires a valid IP address"));
                i += 1;
            }
            "--port" | "-p" => {
                port = args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(8091);
                i += 1;
            }
            "--data-dir" | "-d" => {
                if let Some(dir) = args.get(i + 1) {
                    data_dir = PathBuf::from(dir);
                }
                i += 1;
            }
            "--role" | "-r" => {
                if let Some(r) = args.get(i + 1) {
                    role = match r.as_str() {
                        "secondary" | "s" | "2" => ServerRole::Secondary,
                        _ => ServerRole::Primary,
                    };
                }
                i += 1;
            }
            "--config" | "-c" => {
                if let Some(path) = args.get(i + 1) {
                    config_path = Some(PathBuf::from(path));
                }
                i += 1;
            }
            "--checkpoint" => {
                // --checkpoint <path> <height>
                if let (Some(path), Some(height)) = (
                    args.get(i + 1),
                    args.get(i + 2).and_then(|s| s.parse::<u32>().ok()),
                ) {
                    checkpoints.push((PathBuf::from(path), height));
                    i += 2;
                }
            }
            "--delta" => {
                // --delta <path> <base_height> <tip_height>
                if let (Some(path), Some(base), Some(tip)) = (
                    args.get(i + 1),
                    args.get(i + 2).and_then(|s| s.parse::<u32>().ok()),
                    args.get(i + 3).and_then(|s| s.parse::<u32>().ok()),
                ) {
                    deltas.push((PathBuf::from(path), base, tip));
                    i += 3;
                }
            }
            "--admin-pubkey-hex" => {
                if let Some(hex) = args.get(i + 1) {
                    admin_pubkey_hex = Some(hex.clone());
                }
                i += 1;
            }
            "--disable-onion" => {
                disable_onion = true;
            }
            "--vcek-dir" => {
                if let Some(dir) = args.get(i + 1) {
                    vcek_dir = Some(PathBuf::from(dir));
                }
                i += 1;
            }
            "--pool-size" => {
                pool_size = args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(0);
                i += 1;
            }
            "--pool-db-id" => {
                let value = args
                    .get(i + 1)
                    .unwrap_or_else(|| fatal_cli("--pool-db-id requires a u8 database ID"));
                pool_db_id = value.parse::<u8>().unwrap_or_else(|_| {
                    fatal_cli(format!(
                        "--pool-db-id must be a u8 database ID, got {value}"
                    ))
                });
                pool_db_id_explicit = true;
                i += 1;
            }
            "--pool-dir" => {
                if let Some(dir) = args.get(i + 1) {
                    pool_dir = Some(PathBuf::from(dir));
                }
                i += 1;
            }
            "--harmony-pool-db" => {
                let spec = args
                    .get(i + 1)
                    .unwrap_or_else(|| fatal_cli("--harmony-pool-db requires <db_id>=<dir>"));
                harmony_pool_dbs
                    .push(parse_harmony_pool_db_arg(spec).unwrap_or_else(|error| fatal_cli(error)));
                i += 1;
            }
            "--require-arc" => {
                require_arc = true;
            }
            "--arc-key" => {
                if let Some(p) = args.get(i + 1) {
                    arc_key_path = Some(PathBuf::from(p));
                }
                i += 1;
            }
            "--local-admission-config" => {
                let Some(p) = args.get(i + 1) else {
                    fatal_cli("--local-admission-config requires a file path");
                };
                local_admission_config = Some(PathBuf::from(p));
                i += 1;
            }
            "--require-cashu" => {
                require_cashu = true;
            }
            "--cashu-keyset" => {
                // Format: --cashu-keyset <id>:<hex_secret_key>
                // Can be repeated for multiple keysets.
                if let Some(kv) = args.get(i + 1) {
                    if let Some((id, sk_hex)) = kv.split_once(':') {
                        cashu_keysets.push((id.to_string(), sk_hex.to_string()));
                    }
                }
                i += 1;
            }
            "--max-connections" => {
                max_connections = args
                    .get(i + 1)
                    .and_then(|value| value.parse().ok())
                    .unwrap_or_else(|| fatal_cli("--max-connections requires an integer"));
                i += 1;
            }
            "--websocket-handshake-timeout-ms" => {
                websocket_handshake_timeout_ms = args
                    .get(i + 1)
                    .and_then(|value| value.parse().ok())
                    .unwrap_or_else(|| {
                        fatal_cli("--websocket-handshake-timeout-ms requires an integer")
                    });
                i += 1;
            }
            "--connection-idle-timeout-ms" => {
                connection_idle_timeout_ms = args
                    .get(i + 1)
                    .and_then(|value| value.parse().ok())
                    .unwrap_or_else(|| {
                        fatal_cli("--connection-idle-timeout-ms requires an integer")
                    });
                i += 1;
            }
            #[cfg(any(test, feature = "test-only-unsafe-query-logging"))]
            "--unsafe-debug-query-logging" => {
                unsafe_debug_query_logging = true;
            }
            "--serve-hints" => {
                serve_hints = true;
            }
            "--serve-queries" => {
                serve_queries = true;
            }
            "--pir2-snp-sealed-preflight-only" => {
                pir2_sealed.preflight_only = true;
            }
            "--pir2-snp-sealed-require-ready" => {
                pir2_sealed.require_ready = true;
            }
            "--pir2-snp-sealed-release" => {
                pir2_sealed.release_path =
                    Some(PathBuf::from(args.get(i + 1).unwrap_or_else(|| {
                        fatal_cli("--pir2-snp-sealed-release requires a path")
                    })));
                i += 1;
            }
            "--pir2-snp-sealed-envelope" => {
                pir2_sealed.envelope_path =
                    Some(PathBuf::from(args.get(i + 1).unwrap_or_else(|| {
                        fatal_cli("--pir2-snp-sealed-envelope requires a path")
                    })));
                i += 1;
            }
            "--pir2-snp-sealed-receipt" => {
                pir2_sealed.receipt_path =
                    Some(PathBuf::from(args.get(i + 1).unwrap_or_else(|| {
                        fatal_cli("--pir2-snp-sealed-receipt requires a path")
                    })));
                i += 1;
            }
            "--pir2-snp-sealed-marker" => {
                pir2_sealed.marker_path =
                    Some(PathBuf::from(args.get(i + 1).unwrap_or_else(|| {
                        fatal_cli("--pir2-snp-sealed-marker requires a path")
                    })));
                i += 1;
            }
            "--pir2-snp-sealed-phase" => {
                pir2_sealed.phase =
                    Some(
                        Pir2SealedStartupPhaseV1::parse(args.get(i + 1).unwrap_or_else(|| {
                            fatal_cli("--pir2-snp-sealed-phase requires a value")
                        }))
                        .unwrap_or_else(|error| fatal_cli(error)),
                    );
                i += 1;
            }
            "--pir2-snp-sealed-ordinal" => {
                pir2_sealed.ordinal = Some(
                    args.get(i + 1)
                        .and_then(|value| value.parse().ok())
                        .unwrap_or_else(|| {
                            fatal_cli("--pir2-snp-sealed-ordinal requires an integer")
                        }),
                );
                i += 1;
            }
            "--pir2-snp-sealed-verifier-nonce-hex" => {
                pir2_sealed.verifier_nonce_hex = Some(
                    args.get(i + 1)
                        .unwrap_or_else(|| {
                            fatal_cli("--pir2-snp-sealed-verifier-nonce-hex requires hex")
                        })
                        .clone(),
                );
                i += 1;
            }
            "--pir2-snp-sealed-current-boot-id-hex" => {
                pir2_sealed.current_boot_id_hex = Some(
                    args.get(i + 1)
                        .unwrap_or_else(|| {
                            fatal_cli("--pir2-snp-sealed-current-boot-id-hex requires hex")
                        })
                        .clone(),
                );
                i += 1;
            }
            "--pir2-snp-sealed-current-channel-pubkey-hex" => {
                pir2_sealed.current_channel_pubkey_hex = Some(
                    args.get(i + 1)
                        .unwrap_or_else(|| {
                            fatal_cli("--pir2-snp-sealed-current-channel-pubkey-hex requires hex")
                        })
                        .clone(),
                );
                i += 1;
            }
            "--pir2-snp-sealed-identity-cert" => {
                pir2_sealed.identity_cert_path =
                    Some(PathBuf::from(args.get(i + 1).unwrap_or_else(|| {
                        fatal_cli("--pir2-snp-sealed-identity-cert requires a path")
                    })));
                i += 1;
            }
            "--identity-key-path" => {
                if let Some(p) = args.get(i + 1) {
                    identity_key_path = Some(PathBuf::from(p));
                }
                i += 1;
            }
            "--identity-cert-path" => {
                if let Some(p) = args.get(i + 1) {
                    identity_cert_path = Some(PathBuf::from(p));
                }
                i += 1;
            }
            "--identity-server-id" => {
                if let Some(s) = args.get(i + 1) {
                    identity_server_id = Some(s.clone());
                }
                i += 1;
            }
            "--cuckoo-oram-dir" | "--harmony-oram-dir" => {
                if let Some(p) = args.get(i + 1) {
                    cuckoo_oram_dir = Some(PathBuf::from(p));
                }
                i += 1;
            }
            "--cuckoo-oram-db" | "--harmony-oram-db" => {
                let spec = args.get(i + 1).unwrap_or_else(|| {
                    fatal_cli("--cuckoo-oram-db requires <db_id>=<dir>");
                });
                let parsed = parse_cuckoo_oram_db_arg(spec).unwrap_or_else(|e| fatal_cli(e));
                cuckoo_oram_dbs.push(parsed);
                i += 1;
            }
            "--cuckoo-oram-pack" | "--harmony-oram-pack" => {
                cuckoo_oram_pack = args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(16);
                i += 1;
            }
            "--cuckoo-oram-drain-per-access" | "--harmony-oram-drain-per-access" => {
                cuckoo_oram_drain_per_access =
                    args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(2);
                i += 1;
            }
            "--cuckoo-oram-encrypted" | "--harmony-oram-encrypted" => {
                cuckoo_oram_encrypted = true;
            }
            "--cuckoo-oram-key-hex" | "--harmony-oram-key-hex" => {
                if let Some(hex) = args.get(i + 1) {
                    cuckoo_oram_key_hex = Some(hex.clone());
                }
                i += 1;
            }
            "--cuckoo-oram-state-key-hex" | "--harmony-oram-state-key-hex" => {
                if let Some(hex) = args.get(i + 1) {
                    cuckoo_oram_state_key_hex = Some(hex.clone());
                }
                i += 1;
            }
            "--cuckoo-oram-cache-levels" | "--harmony-oram-cache-levels" => {
                cuckoo_oram_cache_levels =
                    args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(0);
                i += 1;
            }
            "--cuckoo-oram-auth-store" | "--harmony-oram-auth-store" => {
                cuckoo_oram_auth_store = true;
            }
            "--cuckoo-oram-no-save" | "--harmony-oram-no-save" => {
                cuckoo_oram_no_save = true;
            }
            "--direct-oram-dir" => {
                if let Some(p) = args.get(i + 1) {
                    direct_oram_dir = Some(PathBuf::from(p));
                }
                i += 1;
            }
            "--direct-oram-db" => {
                let spec = args.get(i + 1).unwrap_or_else(|| {
                    fatal_cli("--direct-oram-db requires <db_id>=<dir>");
                });
                let parsed = parse_direct_oram_db_arg(spec).unwrap_or_else(|e| fatal_cli(e));
                direct_oram_dbs.push(parsed);
                i += 1;
            }
            "--direct-oram-trusted-state-db" => {
                let spec = args.get(i + 1).unwrap_or_else(|| {
                    fatal_cli("--direct-oram-trusted-state-db requires <db_id>=<dir>");
                });
                let parsed =
                    parse_direct_oram_trusted_state_db_arg(spec).unwrap_or_else(|e| fatal_cli(e));
                direct_oram_trusted_state_dbs.push(parsed);
                i += 1;
            }
            "--allow-direct-oram-trusted-state-outside-run-dev" => {
                direct_oram_allow_trusted_state_outside_run_dev = true;
            }
            "--direct-oram-drain-per-access" => {
                direct_oram_drain_per_access =
                    args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(2);
                i += 1;
            }
            "--direct-oram-access-budget" => {
                direct_oram_access_budget =
                    args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(75);
                i += 1;
            }
            "--direct-oram-encrypted" => {
                direct_oram_encrypted = true;
            }
            "--direct-oram-key-hex" => {
                if let Some(hex) = args.get(i + 1) {
                    direct_oram_key_hex = Some(hex.clone());
                }
                i += 1;
            }
            "--direct-oram-state-key-hex" => {
                if let Some(hex) = args.get(i + 1) {
                    direct_oram_state_key_hex = Some(hex.clone());
                }
                i += 1;
            }
            "--direct-oram-cache-levels" => {
                direct_oram_cache_levels =
                    args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(0);
                i += 1;
            }
            "--direct-oram-auth-store" => {
                direct_oram_auth_store = true;
            }
            "--direct-oram-no-save" => {
                direct_oram_no_save = true;
            }
            unknown => fatal_cli(unknown_cli_argument_v1(unknown)),
        }
        i += 1;
    }

    if !(1..=4_096).contains(&max_connections) {
        fatal_cli("--max-connections must be in 1..=4096");
    }
    if !(1_000..=60_000).contains(&websocket_handshake_timeout_ms) {
        fatal_cli("--websocket-handshake-timeout-ms must be in 1000..=60000");
    }
    if !(10_000..=600_000).contains(&connection_idle_timeout_ms) {
        fatal_cli("--connection-idle-timeout-ms must be in 10000..=600000");
    }
    let harmony_pool_bindings = normalize_harmony_pool_bindings(
        pool_size,
        pool_db_id,
        pool_db_id_explicit,
        pool_dir,
        harmony_pool_dbs,
    )
    .unwrap_or_else(|error| fatal_cli(error));

    CliArgs {
        bind_address,
        port,
        data_dir,
        role,
        config_path,
        checkpoints,
        deltas,
        admin_pubkey_hex,
        disable_onion,
        vcek_dir,
        pool_size,
        harmony_pool_bindings,
        require_arc,
        arc_key_path,
        local_admission_config,
        require_cashu,
        cashu_keysets,
        pir2_sealed,
        max_connections,
        websocket_handshake_timeout_ms,
        connection_idle_timeout_ms,
        #[cfg(any(test, feature = "test-only-unsafe-query-logging"))]
        unsafe_debug_query_logging,
        serve_hints,
        serve_queries,
        identity_key_path,
        identity_cert_path,
        identity_server_id,
        cuckoo_oram_dir,
        cuckoo_oram_dbs,
        cuckoo_oram_pack,
        cuckoo_oram_drain_per_access,
        cuckoo_oram_encrypted,
        cuckoo_oram_key_hex,
        cuckoo_oram_state_key_hex,
        cuckoo_oram_cache_levels,
        cuckoo_oram_auth_store,
        cuckoo_oram_no_save,
        direct_oram_dir,
        direct_oram_dbs,
        direct_oram_trusted_state_dbs,
        direct_oram_allow_trusted_state_outside_run_dev,
        direct_oram_drain_per_access,
        direct_oram_access_budget,
        direct_oram_encrypted,
        direct_oram_key_hex,
        direct_oram_state_key_hex,
        direct_oram_cache_levels,
        direct_oram_auth_store,
        direct_oram_no_save,
    }
}

pub(crate) fn unknown_cli_argument_v1(argument: &str) -> String {
    format!("unknown argument: {argument}")
}
