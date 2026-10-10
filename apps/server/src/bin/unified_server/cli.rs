use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;

// ─── CLI ────────────────────────────────────────────────────────────────────

/// Whether to load OnionPIR at startup: `primary` loads each database's
/// OnionPIR files when they exist, `secondary` never does. Every other request
/// is gated by `--serve-hints` / `--serve-queries`, not by the role.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum ServerRole {
    Primary,
    Secondary,
}

pub(crate) struct CliArgs {
    /// IP address to bind. The production-compatible default remains the
    /// dual-stack wildcard; local integration harnesses can explicitly bind
    /// 127.0.0.1 so the test listener is never exposed off-host.
    pub(crate) bind_address: IpAddr,
    pub(crate) port: u16,
    pub(crate) data_dir: PathBuf,
    pub(crate) role: ServerRole,
    /// Path to databases.toml config file (overrides --data-dir).
    pub(crate) config_path: Option<PathBuf>,
    /// Directory containing the AMD VCEK chain PEMs. Expected files:
    ///   - cert_chain.pem  (ASK + ARK concatenated, as AMD KDS returns)
    ///   - vcek.pem        (the per-chip VCEK for the current TCB)
    ///
    /// If unset (or files missing), the AttestResult ships empty cert
    /// fields. Refresh the files after a TCB change.
    pub(crate) vcek_dir: Option<PathBuf>,
    /// HarmonyPIR V2 hint pool size for database 0 (0 = no pool).
    pub(crate) pool_size: usize,
    /// Where the hint pool persists its entries (memory only when unset).
    pub(crate) pool_dir: Option<PathBuf>,
    /// The credit issuer's Ed25519 public keys (`--credit-issuer-pubkey
    /// FILE`, repeatable); its `/v2/redeem` answers must verify under one.
    pub(crate) credit_issuer_pubkeys: Vec<PathBuf>,
    /// Credit issuer base URL (`--credit-issuer-url URL`, https, or http on
    /// loopback for tests). Enables `REQ_CREDIT_PRESENT`: presentations are
    /// forwarded to `URL/v2/redeem`, whose signed answers must verify under
    /// a pinned `--credit-issuer-pubkey` key (docs/CREDITS.md).
    pub(crate) credit_issuer_url: Option<String>,
    /// Name this server settles under at the issuer (`--credit-server-id
    /// ID`); defaults to the identity certificate's server id.
    pub(crate) credit_server_id: Option<String>,
    /// Charge every metered frame to the connection's gas balance and
    /// refuse frames it cannot cover (`--require-credits`). Needs
    /// `--credit-issuer-url`. This is the default of the access policy;
    /// `--access` overrides it per backend.
    pub(crate) require_credits: bool,
    /// Per-backend access (`--access BACKEND=free|paid|best-effort[:N[:GAS_PER_HOUR]]`,
    /// repeatable; docs/CREDITS.md "Access policy").
    pub(crate) access: Vec<(pir_credit::Backend, pir_credit::Access)>,
    /// Threads of the low-priority pool best-effort free frames run on
    /// (`--free-threads N`).
    pub(crate) free_threads: usize,
    /// How long a free frame may wait for a best-effort slot
    /// (`--free-queue-wait-ms MS`).
    pub(crate) free_queue_wait_ms: u64,
    /// Operator-issued API keys (`--api-key-file FILE`, docs/CREDITS.md
    /// "API keys"): a connection that presents a listed key is unmetered.
    pub(crate) api_key_file: Option<PathBuf>,
    /// Hard cap on live TCP/WebSocket tasks. Connections over the cap are
    /// dropped before allocating a WebSocket parser.
    pub(crate) max_connections: usize,
    pub(crate) websocket_handshake_timeout_ms: u64,
    pub(crate) connection_idle_timeout_ms: u64,
    /// Whether this server answers HarmonyPIR hint requests
    /// (`--serve-hints`). pir1 serves hints and queries; the HarmonyPIR
    /// query server serves queries only, so it never sees a client's hints.
    pub(crate) serve_hints: bool,
    /// Whether this server answers PIR query requests (`--serve-queries`):
    /// DPF batches, OnionPIR queries, the HarmonyPIR query phase, Merkle
    /// siblings and tree-tops.
    pub(crate) serve_queries: bool,
    /// Serve Direct ORAM only (`--oram-only`). Each configured database is
    /// built from its V2 proof (geometry, chain anchor, exact `server-db`
    /// manifest) instead of its table files, which the host does not hold.
    /// Of the query requests only ORAM lookups are answered, and the
    /// attestation carries `pir_core::attest::oram_only_manifest_root` for
    /// each database instead of its manifest root.
    pub(crate) oram_only: bool,
    /// Path to the server's long-lived Ed25519 identity key (raw 32-byte
    /// seed). Combined with `--identity-cert-path` to build the
    /// REQ_ANNOUNCE bundle. If either is missing or fails to load,
    /// REQ_ANNOUNCE is disabled but the rest of the protocol runs
    /// normally. Generate one with `bpir-admin keygen`.
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
    /// Optional per-database direct-entry ORAM image directories.
    /// Repeatable as `--direct-oram-db <db_id>=<dir>`.
    pub(crate) direct_oram_dbs: Vec<(u8, PathBuf)>,
    /// Optional per-database trusted controller/auth state directories.
    /// Repeatable as `--direct-oram-trusted-state-db <db_id>=<dir>`.
    pub(crate) direct_oram_trusted_state_dbs: Vec<(u8, PathBuf)>,
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
}

/// `--oram-only` answers Direct ORAM and nothing else that would read table
/// files the host does not hold.
pub(crate) fn validate_oram_only_cli_v1(args: &CliArgs) -> Result<(), String> {
    if !cfg!(feature = "cuckoo-oram") {
        return Err("--oram-only needs a build with --features cuckoo-oram".into());
    }
    if args.config_path.is_none() {
        return Err(
            "--oram-only needs --config: each database's proof_v2_dir supplies its geometry".into(),
        );
    }
    Ok(())
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

/// `BACKEND=MODE` for `--access`: `dpf=best-effort:2`, `onion=paid`, ...
pub(crate) fn parse_access_arg(
    spec: &str,
) -> Result<(pir_credit::Backend, pir_credit::Access), String> {
    let (backend, mode) = spec
        .split_once('=')
        .ok_or_else(|| format!("--access expects BACKEND=MODE, got `{spec}`"))?;
    let backend = pir_credit::Backend::parse(backend).ok_or_else(|| {
        format!("--access: unknown backend `{backend}` (dpf, harmony, onion, oram)")
    })?;
    let access = pir_credit::Access::parse(mode).map_err(|e| format!("--access {spec}: {e}"))?;
    Ok((backend, access))
}

/// The access policy: every backend paid with `--require-credits`, free
/// otherwise, then the `--access` overrides (each backend at most once).
pub(crate) fn access_policy(args: &CliArgs) -> Result<pir_credit::AccessPolicy, String> {
    let mut policy = pir_credit::AccessPolicy::uniform(if args.require_credits {
        pir_credit::Access::Paid
    } else {
        pir_credit::Access::Free
    });
    let mut seen = std::collections::BTreeSet::new();
    for (backend, access) in &args.access {
        if !seen.insert(*backend) {
            return Err(format!("--access {backend} given more than once"));
        }
        policy.set(*backend, *access);
    }
    Ok(policy)
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

/// Flag reference printed by `--help`. Production values come from the
/// reviewed run scripts and unit files, never from this text.
pub(crate) const USAGE_V1: &str = "\
unified_server - BitcoinPIR unified PIR server (DPF, OnionPIR, HarmonyPIR, Direct ORAM)

usage: unified_server [FLAGS]           production flags come from the reviewed run
                                        scripts and unit files (docs/PRODUCTION_OPERATIONS.md)
       unified_server --help | -h       print this text and exit
       unified_server --version | -V    print crate version, git revision, binary sha256

listener:      --bind-address ADDR  --port N  --role primary|secondary  --serve-hints
               --serve-queries  --max-connections N  --connection-idle-timeout-ms MS
               --websocket-handshake-timeout-ms MS
databases:     --config databases.toml | --data-dir DIR  --oram-only
attestation:   --vcek-dir DIR  --identity-key-path FILE  --identity-cert-path FILE
               --identity-server-id ID
credits:       --credit-issuer-url URL  --credit-issuer-pubkey FILE  --credit-server-id ID
               --require-credits
access:        --access BACKEND=free|paid|best-effort[:N[:GAS_PER_HOUR]]  (BACKEND: dpf harmony
               onion oram; repeatable)  --free-threads N  --free-queue-wait-ms MS
               --api-key-file FILE  (`SHA256HEX LABEL` per line; listed keys are unmetered)
hint pool:     --pool-size N  --pool-dir DIR
direct oram:   --direct-oram-db ID=DIR  --direct-oram-trusted-state-db ID=DIR
               --direct-oram-drain-per-access N  --direct-oram-access-budget N
               --direct-oram-cache-levels N  --direct-oram-encrypted  --direct-oram-key-hex HEX
               --direct-oram-state-key-hex HEX  --direct-oram-auth-store
";

/// `--help`/`-h` and `--version`/`-V` as the only argument print and exit 0
/// before anything else runs; any other argument list goes to the parser,
/// which still rejects unknown flags. Returns the text to print.
pub(crate) fn informational_argument_v1(args: &[String]) -> Option<String> {
    if args.len() != 2 {
        return None;
    }
    match args[1].as_str() {
        "--help" | "-h" => Some(USAGE_V1.to_owned()),
        "--version" | "-V" => Some(version_line_v1()),
        _ => None,
    }
}

/// One line: crate version, the git revision baked at build time, and the
/// sha256 of the running executable (what the client pins), for install
/// sanity checks.
pub(crate) fn version_line_v1() -> String {
    let digest = pir_runtime_core::attest::self_exe_sha256();
    let binary = if digest == [0u8; 32] {
        "unavailable".to_owned()
    } else {
        hex::encode(digest)
    };
    format!(
        "unified_server {} git_rev={} binary_sha256={}\n",
        env!("CARGO_PKG_VERSION"),
        pir_runtime_core::attest::GIT_REV,
        binary
    )
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
    let mut vcek_dir: Option<PathBuf> = None;
    let mut pool_size: usize = 0; // 0 = pool disabled
    let mut pool_dir: Option<PathBuf> = None;
    let mut credit_issuer_pubkeys: Vec<PathBuf> = Vec::new();
    let mut credit_issuer_url: Option<String> = None;
    let mut credit_server_id: Option<String> = None;
    let mut require_credits = false;
    let mut access: Vec<(pir_credit::Backend, pir_credit::Access)> = Vec::new();
    let mut free_threads = crate::access_gate::DEFAULT_FREE_THREADS;
    let mut free_queue_wait_ms = crate::access_gate::DEFAULT_FREE_QUEUE_WAIT.as_millis() as u64;
    let mut api_key_file: Option<PathBuf> = None;
    let mut max_connections: usize = 128;
    let mut websocket_handshake_timeout_ms: u64 = 10_000;
    let mut connection_idle_timeout_ms: u64 = 30_000;
    let mut serve_hints = false;
    let mut serve_queries = false;
    let mut oram_only = false;
    let mut identity_key_path: Option<PathBuf> = None;
    let mut identity_cert_path: Option<PathBuf> = None;
    let mut identity_server_id: Option<String> = None;
    let mut direct_oram_dbs: Vec<(u8, PathBuf)> = Vec::new();
    let mut direct_oram_trusted_state_dbs: Vec<(u8, PathBuf)> = Vec::new();
    let mut direct_oram_drain_per_access: u64 = 2;
    let mut direct_oram_access_budget: usize = 75;
    let mut direct_oram_encrypted = false;
    let mut direct_oram_key_hex: Option<String> = None;
    let mut direct_oram_state_key_hex: Option<String> = None;
    let mut direct_oram_cache_levels: usize = 0;
    let mut direct_oram_auth_store = false;

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
            "--pool-dir" => {
                if let Some(dir) = args.get(i + 1) {
                    pool_dir = Some(PathBuf::from(dir));
                }
                i += 1;
            }
            "--credit-issuer-pubkey" => {
                let Some(p) = args.get(i + 1) else {
                    fatal_cli("--credit-issuer-pubkey requires a file path");
                };
                credit_issuer_pubkeys.push(PathBuf::from(p));
                i += 1;
            }
            "--credit-issuer-url" => {
                let Some(url) = args.get(i + 1) else {
                    fatal_cli("--credit-issuer-url requires a URL");
                };
                credit_issuer_url = Some(url.clone());
                i += 1;
            }
            "--credit-server-id" => {
                let Some(id) = args.get(i + 1) else {
                    fatal_cli("--credit-server-id requires a name");
                };
                credit_server_id = Some(id.clone());
                i += 1;
            }
            "--require-credits" => {
                require_credits = true;
            }
            "--access" => {
                let Some(spec) = args.get(i + 1) else {
                    fatal_cli("--access requires BACKEND=MODE");
                };
                access.push(parse_access_arg(spec).unwrap_or_else(|error| fatal_cli(error)));
                i += 1;
            }
            "--free-threads" => {
                free_threads = args
                    .get(i + 1)
                    .and_then(|value| value.parse().ok())
                    .filter(|n: &usize| *n >= 1)
                    .unwrap_or_else(|| {
                        fatal_cli("--free-threads requires an integer of at least 1")
                    });
                i += 1;
            }
            "--free-queue-wait-ms" => {
                free_queue_wait_ms = args
                    .get(i + 1)
                    .and_then(|value| value.parse().ok())
                    .unwrap_or_else(|| fatal_cli("--free-queue-wait-ms requires an integer"));
                i += 1;
            }
            "--api-key-file" => {
                let Some(p) = args.get(i + 1) else {
                    fatal_cli("--api-key-file requires a file path");
                };
                api_key_file = Some(PathBuf::from(p));
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
            "--serve-hints" => {
                serve_hints = true;
            }
            "--serve-queries" => {
                serve_queries = true;
            }
            "--oram-only" => {
                oram_only = true;
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
            unknown => fatal_cli(unknown_cli_argument_v1(unknown)),
        }
        i += 1;
    }

    CliArgs {
        bind_address,
        port,
        data_dir,
        role,
        config_path,
        vcek_dir,
        pool_size,
        pool_dir,
        credit_issuer_pubkeys,
        credit_issuer_url,
        credit_server_id,
        require_credits,
        access,
        free_threads,
        free_queue_wait_ms,
        api_key_file,
        max_connections,
        websocket_handshake_timeout_ms,
        connection_idle_timeout_ms,
        serve_hints,
        serve_queries,
        oram_only,
        identity_key_path,
        identity_cert_path,
        identity_server_id,
        direct_oram_dbs,
        direct_oram_trusted_state_dbs,
        direct_oram_drain_per_access,
        direct_oram_access_budget,
        direct_oram_encrypted,
        direct_oram_key_hex,
        direct_oram_state_key_hex,
        direct_oram_cache_levels,
        direct_oram_auth_store,
    }
}

pub(crate) fn unknown_cli_argument_v1(argument: &str) -> String {
    format!("unknown argument: {argument}")
}
