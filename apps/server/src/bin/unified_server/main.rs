//! Unified PIR WebSocket server: DPF, OnionPIR, HarmonyPIR and Direct ORAM
//! from one process. `--serve-hints` / `--serve-queries` pick the request
//! set; `--role primary` also loads OnionPIR.
//!
//! Usage: `unified_server --help` prints the flag reference (`cli::USAGE_V1`);
//! `unified_server --version` prints the crate version, git revision, and
//! binary sha256. Production flags come from the reviewed run scripts.

mod access_gate;
mod api_keys;
mod cli;
mod credit_gate;
mod credit_issuer;
mod credit_meter;
mod dispatch;
mod harmony_hints;
mod io;
mod logging;
mod onion;
mod oram;
mod serve;
mod state;

pub(crate) use cli::*;
#[allow(unused_imports)]
pub(crate) use harmony_hints::*;
pub(crate) use io::*;
pub(crate) use logging::*;
#[allow(unused_imports)]
pub(crate) use onion::*;
#[allow(unused_imports)]
pub(crate) use oram::*;
pub(crate) use state::*;

use runtime::config::ServerConfig;
use runtime::db_proof::load_database_proof_bundle;
use runtime::hint_pool;
use runtime::table::{DatabaseDescriptor, DatabaseType, MappedDatabase, ServerState};

use pir_core::params::{self, CHUNK_PARAMS, INDEX_PARAMS};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

// ─── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    if let Some(text) = informational_argument_v1(&std::env::args().collect::<Vec<_>>()) {
        print!("{text}");
        return;
    }
    let args = parse_args();
    #[cfg(feature = "test-only-unsafe-query-logging")]
    eprintln!(
        "!!! test-only-unsafe-query-logging build: logs expose peer IPs, client IDs, request timing, database/group selections and byte sizes !!!"
    );
    let role_name = match args.role {
        ServerRole::Primary => "primary",
        ServerRole::Secondary => "secondary",
    };

    if args.oram_only {
        cli::validate_oram_only_cli_v1(&args).unwrap_or_else(|error| fatal_cli(error));
    }

    // The channel key is generated fresh at every boot and never touches
    // disk; the attestation report binds its public half.
    let channel_keypair = pir_runtime_core::channel::ChannelKeypair::generate();
    let channel_pubkey = channel_keypair.public_bytes();

    println!("=== Unified PIR Server ({}) ===", role_name);
    println!("  Bind:     {}:{}", args.bind_address, args.port);
    println!(
        "  Mode:     hints={}, queries={}",
        if args.serve_hints { "yes" } else { "no" },
        if args.serve_queries { "yes" } else { "no" },
    );
    if let Some(ref config_path) = args.config_path {
        println!("  Config:   {}", config_path.display());
    } else {
        println!("  Data dir: {}", args.data_dir.display());
    }
    println!();

    let total_start = Instant::now();

    // ── Load databases ─────────────────────────────────────────────────
    let mut all_databases: Vec<MappedDatabase> = Vec::new();
    // Per-DB source directories for OnionPIR loading (db_id, label, path).
    // Populated alongside `all_databases` so OnionPIR setup can iterate over
    // every loaded DB and look for its OnionPIR files.
    let mut db_paths: Vec<(u8, String, PathBuf)> = Vec::new();

    if let Some(ref config_path) = args.config_path {
        let config = ServerConfig::load(config_path);
        println!(
            "[config] Loaded {} databases from {}",
            config.databases.len(),
            config_path.display()
        );

        for (i, db_cfg) in config.databases.iter().enumerate() {
            let db_type = match db_cfg.db_type.as_str() {
                "delta" => DatabaseType::Delta,
                _ => DatabaseType::Full,
            };
            let db_path = config.db_path(i);
            let descriptor = DatabaseDescriptor {
                name: db_cfg.name.clone(),
                db_type,
                base_height: db_cfg.base_height,
                height: db_cfg.height,
                index_params: INDEX_PARAMS,
                chunk_params: CHUNK_PARAMS,
            };
            let mut db = if args.oram_only {
                let proof_v2_dir = db_cfg.proof_v2_dir.as_ref().unwrap_or_else(|| {
                    fatal_cli(format!(
                        "--oram-only: database {} ({}) has no proof_v2_dir",
                        i, db_cfg.name
                    ))
                });
                io::load_oram_only_database_v1(i as u8, proof_v2_dir, descriptor)
                    .unwrap_or_else(|error| fatal_cli(error))
            } else {
                load_runtime_database_v1(&db_path, descriptor)
            };
            if let Some(proof_dir) = db_cfg.proof_dir.as_ref() {
                db.db_proof = Some(
                    load_database_proof_bundle(i as u8, proof_dir).unwrap_or_else(|e| {
                        panic!(
                            "[config] failed to load proof_dir for db {} from {}: {}",
                            db_cfg.name,
                            proof_dir.display(),
                            e
                        )
                    }),
                );
                println!(
                    "[config] DB proof loaded for db_id={} name={} from {}",
                    i,
                    db_cfg.name,
                    proof_dir.display()
                );
            }
            if let Some(proof_dir) = db_cfg.proof_v2_dir.as_ref().filter(|_| !args.oram_only) {
                db.db_proof_v2 = Some(
                    load_database_proof_bundle(i as u8, proof_dir).unwrap_or_else(|e| {
                        panic!(
                            "[config] failed to load proof_v2_dir for db {} from {}: {}",
                            db_cfg.name,
                            proof_dir.display(),
                            e
                        )
                    }),
                );
                println!(
                    "[config] DB proof v2 loaded for db_id={} name={} from {}",
                    i,
                    db_cfg.name,
                    proof_dir.display()
                );
            }
            let type_label = if db_type == DatabaseType::Delta {
                format!("Delta:{}→{}", db_cfg.base_height, db_cfg.height)
            } else {
                format!("Full:{}", db_cfg.height)
            };
            println!(
                "[{}] INDEX bins={}, CHUNK bins={}, dpf_n_index={}, dpf_n_chunk={}",
                type_label,
                db.index.bins_per_table,
                db.chunk.bins_per_table,
                params::compute_dpf_n(db.index.bins_per_table),
                params::compute_dpf_n(db.chunk.bins_per_table)
            );
            db_paths.push((i as u8, db_cfg.name.clone(), db_path));
            all_databases.push(db);
        }
    } else {
        let main_db = load_runtime_database_v1(
            &args.data_dir,
            DatabaseDescriptor {
                name: "main".to_string(),
                db_type: DatabaseType::Full,
                base_height: 0,
                height: 0,
                index_params: INDEX_PARAMS,
                chunk_params: CHUNK_PARAMS,
            },
        );
        db_paths.push((0u8, "main".to_string(), args.data_dir.clone()));
        all_databases.push(main_db);
    }

    #[cfg(not(feature = "cuckoo-oram"))]
    {
        let _ = (
            args.direct_oram_drain_per_access,
            args.direct_oram_access_budget,
            args.direct_oram_encrypted,
            args.direct_oram_key_hex.as_ref(),
            args.direct_oram_state_key_hex.as_ref(),
            args.direct_oram_cache_levels,
            args.direct_oram_auth_store,
            args.direct_oram_trusted_state_dbs.as_slice(),
        );
        if !args.direct_oram_dbs.is_empty() || !args.direct_oram_trusted_state_dbs.is_empty() {
            eprintln!(
                "ERROR: Direct ORAM flags require building unified_server with --features cuckoo-oram"
            );
            std::process::exit(2);
        }
    }

    #[cfg(feature = "cuckoo-oram")]
    let direct_oram = {
        let trusted_state_dirs: BTreeMap<u8, PathBuf> =
            args.direct_oram_trusted_state_dbs.iter().cloned().collect();
        let mut opened = HashMap::new();
        for (db_id, oram_dir) in &args.direct_oram_dbs {
            let db_id = *db_id;
            let Some((_, db_label, _)) = db_paths.iter().find(|(id, _, _)| *id == db_id) else {
                fatal_cli(format!(
                    "Direct ORAM configured for unknown db_id={db_id} (loaded db_ids: {:?})",
                    db_paths.iter().map(|(id, _, _)| *id).collect::<Vec<_>>()
                ));
            };
            // Unencrypted or unauthenticated pages, or controller state kept
            // with the pages, would let the host learn which blocks a query reads.
            if !args.direct_oram_encrypted || !args.direct_oram_auth_store {
                fatal_cli(format!(
                    "Direct ORAM for db_id={db_id} needs --direct-oram-encrypted and --direct-oram-auth-store"
                ));
            }
            let Some(trusted_state_dir) = trusted_state_dirs.get(&db_id) else {
                fatal_cli(format!(
                    "Direct ORAM for db_id={db_id} needs --direct-oram-trusted-state-db {db_id}=<dir>"
                ));
            };
            println!(
                "  Direct ORAM: enabled for db_id={} name={}, dir={}, trusted_state_dir={}, access_budget={}, drain_per_access={}, cache_levels={}",
                db_id,
                db_label,
                oram_dir.display(),
                trusted_state_dir.display(),
                args.direct_oram_access_budget,
                args.direct_oram_drain_per_access,
                args.direct_oram_cache_levels,
            );
            let tables = DirectOramTables::open_with_trusted_state(
                oram_dir,
                Some(trusted_state_dir),
                args.direct_oram_drain_per_access,
                args.direct_oram_access_budget,
                args.direct_oram_encrypted,
                args.direct_oram_key_hex.as_deref(),
                args.direct_oram_state_key_hex.as_deref(),
                args.direct_oram_cache_levels,
                args.direct_oram_auth_store,
                true,
            )
            .unwrap_or_else(|e| {
                panic!(
                    "failed to open Direct ORAM for db_id={} ({}): {}",
                    db_id, db_label, e
                )
            });
            tables
                .validate_dataset_binding(&all_databases[db_id as usize])
                .unwrap_or_else(|error| {
                    panic!(
                        "failed to bind Direct ORAM to verified DB for db_id={} ({}): {}",
                        db_id, db_label, error
                    )
                });
            opened.insert(db_id, tables);
        }
        if opened.is_empty() {
            println!("  Direct ORAM: disabled (use --direct-oram-db <db_id>=<dir> to enable)");
        }
        opened
    };

    let (onionpir_txs, onionpir_infos, onionpir_merkle_per_db) =
        crate::onion::setup_onionpir_workers(&args, &db_paths);

    // ── Build server state ──────────────────────────────────────────────
    // (OnionPIR per-bin Merkle info was built per-DB inside the loading
    // loop above; it's stored in `onionpir_merkle_per_db`.)

    println!();
    println!("Data loaded in {:.2?}", total_start.elapsed());
    println!();

    // ── Report the boot-fresh channel keypair ───────────────────────────
    // The announcement commits to this public key. The secret never
    // touches disk and remains owned by this process.
    //
    // Why on a non-SEV host (Hetzner) too? The channel layer is hosted
    // identically; only the attestation backing differs. Clients still
    // get an encrypted channel against pir1; they just don't get the
    // chip-signed binding.
    println!(
        "  Channel pubkey: {}",
        channel_pubkey
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );

    // ── Load AMD VCEK chain (optional) ───────────────────────────────────
    // Operator places ARK + ASK + VCEK PEMs at --vcek-dir; server reads
    // once at startup and ships them in every AttestResult so the
    // browser can chain-validate the SNP report's signature back to
    // AMD's known root without talking to kdsintf.amd.com directly
    // (CORS-blocked from the browser).
    let (ark_pem, ask_pem, vcek_pem) = match args.vcek_dir.as_ref() {
        Some(dir) => match load_vcek_chain(dir) {
            Ok((ark, ask, vcek)) => {
                println!(
                    "  VCEK chain: loaded from {} (ark={}B ask={}B vcek={}B)",
                    dir.display(),
                    ark.len(),
                    ask.len(),
                    vcek.len(),
                );
                (ark, ask, vcek)
            }
            Err(e) => {
                eprintln!(
                    "  VCEK chain: failed to load from {}: {} — AttestResult will ship empty cert fields, browser falls back to V2-binding-only verification",
                    dir.display(),
                    e
                );
                (Vec::new(), Vec::new(), Vec::new())
            }
        },
        None => {
            println!("  VCEK chain: not configured (--vcek-dir unset) — AttestResult ships empty cert fields");
            (Vec::new(), Vec::new(), Vec::new())
        }
    };

    // ── Build the operator-signed announcement bundle, if configured ─
    // [HUMAN-decided 2026-05-21] When either file is missing or the
    // cert / key disagree, log a warning and serve without announce
    // (REQ_ANNOUNCE returns RESP_ERROR). Existing attest / handshake
    // / query paths are unaffected.
    // The identity key and certificate also sign credit redeem requests
    // (docs/CREDITS.md); keep a copy before the announcement consumes them.
    let mut credit_identity: Option<(ed25519_dalek::SigningKey, pir_identity::IdentityCert)> = None;
    let announcement_bundle: Option<Vec<u8>> = {
        match (
            args.identity_key_path.as_ref(),
            args.identity_cert_path.as_ref(),
            args.identity_server_id.as_deref(),
        ) {
            (Some(key_path), Some(cert_path), Some(server_id)) => {
                let identity_key = read_exact_secret_v1::<32>(key_path, "identity signing key")
                    .map(|mut seed| {
                        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
                        seed.zeroize();
                        key
                    });
                match identity_key.and_then(|sk| {
                    pir_runtime_core::identity::load_identity_cert(cert_path)
                        .map(|cert| (sk, cert))
                        .map_err(|error| error.to_string())
                }) {
                    Ok((sk, cert)) => {
                        credit_identity = Some((sk.clone(), cert.clone()));
                        // Manifest roots in db_id order — same as the V2
                        // attest layout, so the bundle and the SEV report
                        // commit to the same set.
                        let manifest_roots =
                            state::attested_manifest_roots(&all_databases, args.oram_only);
                        let binary_sha256 = pir_runtime_core::attest::self_exe_sha256();
                        let git_rev = pir_runtime_core::attest::GIT_REV;
                        let issued_at = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(0);
                        match pir_runtime_core::identity::build_announcement_bundle(
                            &sk,
                            cert,
                            server_id,
                            channel_pubkey,
                            binary_sha256,
                            git_rev,
                            manifest_roots,
                            issued_at,
                        ) {
                            Ok(id) => {
                                let id_short: String = id.cert.identity_pubkey[..8]
                                    .iter()
                                    .map(|b| format!("{:02x}", b))
                                    .collect();
                                println!(
                                "  Identity announce: enabled (server_id={}, identity_pub={}…, issued_at={})",
                                server_id, id_short, issued_at
                            );
                                Some(id.encoded_bundle)
                            }
                            Err(e) => {
                                eprintln!(
                                "  Identity announce: DISABLED — failed to build bundle: {}. REQ_ANNOUNCE will return RESP_ERROR; attest/handshake/queries still serve normally.",
                                e
                            );
                                None
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!(
                        "  Identity announce: DISABLED — {}. REQ_ANNOUNCE will return RESP_ERROR; attest/handshake/queries still serve normally.",
                        e
                    );
                        None
                    }
                }
            }
            (None, None, None) => {
                println!(
                "  Identity announce: not configured (--identity-key-path / --identity-cert-path / --identity-server-id unset)"
            );
                None
            }
            _ => {
                eprintln!(
                "  Identity announce: DISABLED — all three of --identity-key-path, --identity-cert-path, --identity-server-id must be set together (or none of them)."
            );
                None
            }
        }
    };

    // ── Assemble ServerState ────────────────────────────────────────────
    let state = ServerState {
        databases: all_databases,
        server_static_pub: channel_pubkey,
        ark_pem,
        ask_pem,
        vcek_pem,
        announcement_bundle,
    };

    // ── Initialize the HarmonyPIR V2 hint pool for database 0 (if enabled) ──
    let mut hint_pools = BTreeMap::new();
    if args.pool_size > 0 {
        let pool_config = hint_pool::HintPoolConfig {
            pool_size: args.pool_size,
            // Advertise exactly the backend compiled into this runtime:
            // FastPRP with the feature, HMR12 otherwise.
            prp_backend: hint_pool::default_prp_backend(),
            pool_dir: args.pool_dir.clone(),
        };
        let backend_name = match pool_config.prp_backend {
            harmonypir::remote::PRP_HMR12 => "HMR12",
            harmonypir::remote::PRP_FASTPRP => "FastPRP",
            _ => "unknown",
        };
        println!(
            "  HarmonyPIR V2 hint pool: db_id=0, size={}, backend={}, dir={}",
            pool_config.pool_size,
            backend_name,
            pool_config
                .pool_dir
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "memory-only".into())
        );
        let pool = hint_pool::HintPool::new(pool_config, 0, &state.databases[0])
            .unwrap_or_else(|e| panic!("HarmonyPIR hint pool init failed: {e}"));
        hint_pools.insert(0u8, pool);
    } else {
        println!("  HarmonyPIR V2 hint pool: disabled (use --pool-size to enable)");
    }

    // Credits (docs/CREDITS.md): the issuer client and, with
    // --require-credits, the per-connection gas gate. The issuer's published
    // parameters price this server's frames; the built-in set applies when
    // the issuer cannot be reached at startup.
    let credits = credit_issuer::CreditsV1::from_cli(&args, credit_identity)
        .unwrap_or_else(|error| fatal_cli(error));
    let gas_params = match credits.as_ref() {
        Some(credits) => {
            println!("  {}", credits.startup_log_line());
            match credits.issuer.fetch_info().await {
                Ok(info) => {
                    println!(
                        "  Credits: issuer parameters credit_sat={} gas_per_credit={} base_gas_per_frame={} egress_gas_per_mb={}",
                        info.credit_sat,
                        info.gas_per_credit,
                        info.base_gas_per_frame,
                        info.egress_gas_per_mb
                    );
                    info.gas_params()
                }
                Err(error) => {
                    eprintln!(
                        "  Credits: issuer info unavailable ({error}); pricing with the built-in 2026-09 parameters"
                    );
                    pir_credit::GasParams::PRODUCTION_2026_09
                }
            }
        }
        None => pir_credit::GasParams::PRODUCTION_2026_09,
    };

    // Access policy (docs/CREDITS.md "Access policy"): per backend free,
    // paid, or free on a best-effort lane that paid frames overtake.
    let access = cli::access_policy(&args)
        .and_then(|policy| {
            access_gate::AccessGateV1::new(
                policy,
                credits.is_some(),
                args.free_threads,
                Duration::from_millis(args.free_queue_wait_ms),
            )
        })
        .unwrap_or_else(|error| fatal_cli(error));
    for line in access.startup_lines() {
        println!("  {line}");
    }

    // Operator-issued API keys (docs/CREDITS.md "API keys").
    let api_keys = args.api_key_file.as_deref().map(|path| {
        let keys = api_keys::ApiKeysV1::load(path).unwrap_or_else(|error| fatal_cli(error));
        println!(
            "  API keys: {} listed in {}; a connection that presents one is unmetered",
            keys.len(),
            path.display()
        );
        keys
    });

    // Gas table for every loaded database plus the hourly meter
    // (docs/CREDITS.md).
    let credit_meter = {
        #[cfg(feature = "cuckoo-oram")]
        let oram_slots: std::collections::BTreeMap<u8, u64> = direct_oram
            .iter()
            .map(|(db_id, tables)| (*db_id, tables.access_budget as u64))
            .collect();
        #[cfg(not(feature = "cuckoo-oram"))]
        let oram_slots: std::collections::BTreeMap<u8, u64> = std::collections::BTreeMap::new();
        credit_meter::CreditMeterV1::from_loaded(
            gas_params,
            &state,
            &onionpir_infos,
            &oram_slots,
            args.oram_only,
        )
    };
    for line in credit_meter.startup_lines() {
        println!("  {line}");
    }

    let server = Arc::new(UnifiedServerData {
        state,
        role: args.role,
        onionpir_txs,
        onionpir_infos,
        onionpir_merkle: onionpir_merkle_per_db,
        channel_keypair,
        hint_pools,
        #[cfg(feature = "cuckoo-oram")]
        direct_oram,
        v2_half_pending: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        credit_meter,
        credits,
        access,
        api_keys,
        serve_hints: args.serve_hints,
        serve_queries: args.serve_queries,
        oram_only: args.oram_only,
    });
    // Background task: garbage-collect V2-half pending entries whose
    // matching second half never arrived. Runs every 10 s; entries
    // older than `V2_HALF_PENDING_TTL_SECS` are evicted (their pool
    // entry is dropped — the pool generator will refill).
    {
        let pending = Arc::clone(&server.v2_half_pending);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                let cutoff =
                    Instant::now().checked_sub(Duration::from_secs(V2_HALF_PENDING_TTL_SECS));
                let Some(cutoff) = cutoff else { continue };
                let mut map = pending.lock().await;
                let before = map.len();
                map.retain(|_token, pend| pend.created_at >= cutoff);
                let evicted = before.saturating_sub(map.len());
                if evicted > 0 {
                    unsafe_debug_log!(
                        "[v2-half-pending] evicted {} stale entr(ies), {} remaining",
                        evicted,
                        map.len()
                    );
                }
            }
        });
    }

    // Background task: the hourly gas/CPU meter report (docs/CREDITS.md),
    // aggregates per opcode and database only.
    {
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                if let Some(lines) = server.credit_meter.due_lines(Instant::now()) {
                    for line in lines {
                        println!("{line}");
                    }
                }
                if let Some(lines) = server
                    .access
                    .due_lines(Instant::now(), credit_meter::METER_REPORT_INTERVAL)
                {
                    for line in lines {
                        println!("{line}");
                    }
                }
            }
        });
    }

    serve::serve_connections(&args, role_name.to_string(), server).await;
}

#[cfg(test)]
mod tests;
