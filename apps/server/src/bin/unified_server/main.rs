//! Unified PIR WebSocket server — serves all 3 protocols from one process.
//!
//! Roles:
//!   --role primary   (default): DPF + OnionPIR + HarmonyPIR (hint + query)
//!   --role secondary:           DPF only (2nd server for 2-server DPF protocol)
//!
//! Uses pir-core's MappedDatabase for table loading instead of legacy CuckooTablePair.
//!
//! Usage:
//!   unified_server --port 8091 [--data-dir /path/to/checkpoint] [--role primary|secondary]
//!     [--checkpoint /path/to/checkpoint <height>]...
//!     [--delta /path/to/delta <base_height> <tip_height>]...

mod admission;
mod cli;
mod dispatch;
mod harmony_hints;
mod io;
mod logging;
mod onion;
mod oram;
mod serve;
mod state;
mod unified_server_pir2_sealed;

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

use admission::arc::ArcAdmissionV1;
use admission::local::LocalAdmissionV1;
use runtime::config::ServerConfig;
use runtime::db_proof::load_database_proof_bundle;
use runtime::hint_pool;
use runtime::table::{DatabaseDescriptor, DatabaseType, MappedDatabase, ServerState};
use unified_server_pir2_sealed::{
    dispatch_pir2_sealed_startup_v1, source_pinned_pir2_operator_key_v1,
    validate_pir2_sealed_cli_v1, Pir2SealedStartupV1, PIR2_SEALED_INERT_SUCCESS_EXIT_CODE_V1,
};

use pir_core::params::{self, CHUNK_PARAMS, INDEX_PARAMS};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

#[cfg(any(test, feature = "test-only-unsafe-query-logging"))]
use std::sync::atomic::Ordering;

// ─── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let args = parse_args();
    if args.require_arc {
        eprintln!(
            "!!! WARNING: EXPERIMENTAL ARC ENABLED FOR THIS PIR SERVER; THE IMPLEMENTATION IS UNAUDITED AND MUST NOT BE USED IN PRODUCTION !!!"
        );
    }
    #[cfg(any(test, feature = "test-only-unsafe-query-logging"))]
    {
        UNSAFE_DEBUG_QUERY_LOGGING.store(args.unsafe_debug_query_logging, Ordering::Relaxed);
        if args.unsafe_debug_query_logging {
            eprintln!(
                "!!! UNSAFE DEBUG QUERY LOGGING ENABLED: logs may expose peer IPs, client IDs, request timing, database/group selections and byte sizes; never enable in production !!!"
            );
        }
    }
    let role_name = match args.role {
        ServerRole::Primary => "primary",
        ServerRole::Secondary => "secondary",
    };

    // ── Mode validation ────────────────────────────────────────────────
    // The server's accepted-opcode set is gated by two independent flags:
    //   --serve-hints   → REQ_HARMONY_HINTS / REQ_HARMONY_HINTS_V2
    //   --serve-queries → all PIR query opcodes (DPF batches, OnionPIR
    //                      queries, HarmonyPIR query phase, Merkle siblings,
    //                      tree-tops, batched index/chunk)
    // At least one must be enabled, else the server has no useful role.
    // Run-mode logged below; configure on each unit file (see
    // `deploy/systemd/pir-primary.service` and
    // `deploy/systemd/pir-secondary.service`).
    if !args.serve_hints && !args.serve_queries {
        eprintln!(
            "ERROR: must enable at least one of --serve-hints / --serve-queries.\n  \
             Hint-only deployment (HarmonyPIR V2 pool):  --serve-hints --pool-size N [--pool-db-id ID | --harmony-pool-db ID=DIR ...]\n  \
             Query-only deployment (DPF / OnionPIR / HarmonyPIR query): --serve-queries\n  \
             Both (legacy single-host or pir1 Hetzner topology):       --serve-hints --serve-queries"
        );
        std::process::exit(2);
    }

    validate_pir2_sealed_cli_v1(
        &args.pir2_sealed,
        args.identity_key_path.is_some()
            || args.identity_cert_path.is_some()
            || args.identity_server_id.is_some(),
    )
    .unwrap_or_else(|error| fatal_cli(error));
    // Generate the boot-fresh channel before sealed preflight so the same raw
    // public key is committed into the fresh receipt and later announcement.
    // No database, ORAM image, or listener has been touched at this point.
    let channel_keypair = pir_runtime_core::channel::ChannelKeypair::generate();
    let channel_pubkey = channel_keypair.public_bytes();
    let pinned_operator =
        source_pinned_pir2_operator_key_v1().unwrap_or_else(|error| fatal_cli(error));
    let sealed_now_unix = current_unix_seconds_v1().unwrap_or_else(|error| fatal_cli(error));
    let sealed_startup = dispatch_pir2_sealed_startup_v1(
        &args.pir2_sealed,
        &pinned_operator,
        sealed_now_unix,
        channel_pubkey,
        &pir_runtime_core::snp_sealed_secrets::LinuxSevSnpDerivedKeyProviderV1,
    )
    .unwrap_or_else(|error| fatal_cli(format!("pir2 sealed startup: {error}")));
    // Only the attestation identity is consumed here. The envelope still
    // unseals a second (clearing) seed for format compatibility; R5b drops
    // it from the sealed formats.
    let sealed_identity = match sealed_startup {
        Pir2SealedStartupV1::Disabled => None,
        Pir2SealedStartupV1::InertSuccess {
            phase,
            receipt_digest,
        } => {
            eprintln!(
                "pir2 sealed {:?} completed inertly; receipt_digest={}",
                phase,
                hex::encode(receipt_digest)
            );
            std::process::exit(PIR2_SEALED_INERT_SUCCESS_EXIT_CODE_V1);
        }
        Pir2SealedStartupV1::Ready {
            identity_key,
            identity_cert,
            ..
        } => Some((identity_key, identity_cert)),
    };

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
        for (path, height) in &args.checkpoints {
            println!("  Checkpoint: {} (height={})", path.display(), height);
        }
        for (path, base, tip) in &args.deltas {
            println!("  Delta:      {} ({}→{})", path.display(), base, tip);
        }
    }
    println!();

    let total_start = Instant::now();

    // A database explicitly configured for Direct ORAM may contain optional
    // bucket-Merkle artifacts for the mmap backend without the sibling tables
    // that backend requires. Only these exact DB ids may suppress that unused
    // backend; the Direct ORAM image is still opened and manifest-bound before
    // the listener starts. Builds without ORAM support never take this path.
    #[cfg(feature = "cuckoo-oram")]
    let direct_oram_db_ids: BTreeSet<u8> = args
        .direct_oram_dir
        .iter()
        .map(|_| 0u8)
        .chain(args.direct_oram_dbs.iter().map(|(db_id, _)| *db_id))
        .collect();
    #[cfg(not(feature = "cuckoo-oram"))]
    let direct_oram_db_ids = BTreeSet::<u8>::new();

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
            let mut db = load_runtime_database_v1(
                i as u8,
                &db_path,
                DatabaseDescriptor {
                    name: db_cfg.name.clone(),
                    db_type,
                    base_height: db_cfg.base_height,
                    height: db_cfg.height,
                    index_params: INDEX_PARAMS,
                    chunk_params: CHUNK_PARAMS,
                },
                &direct_oram_db_ids,
            );
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
            if let Some(proof_dir) = db_cfg.proof_v2_dir.as_ref() {
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
        // Legacy CLI mode: --data-dir + --checkpoint + --delta

        let main_db = load_runtime_database_v1(
            0,
            &args.data_dir,
            DatabaseDescriptor {
                name: "main".to_string(),
                db_type: DatabaseType::Full,
                base_height: 0,
                height: 0,
                index_params: INDEX_PARAMS,
                chunk_params: CHUNK_PARAMS,
            },
            &direct_oram_db_ids,
        );

        db_paths.push((0u8, "main".to_string(), args.data_dir.clone()));
        all_databases.push(main_db);

        for (path, height) in &args.checkpoints {
            let name = format!("checkpoint_{}", height);
            let db_id = all_databases.len() as u8;
            let db = load_runtime_database_v1(
                db_id,
                path,
                DatabaseDescriptor {
                    name: name.clone(),
                    db_type: DatabaseType::Full,
                    base_height: 0,
                    height: *height,
                    index_params: INDEX_PARAMS,
                    chunk_params: CHUNK_PARAMS,
                },
                &direct_oram_db_ids,
            );
            println!(
                "[Checkpoint:{}] INDEX bins={}, CHUNK bins={}, dpf_n_index={}, dpf_n_chunk={}",
                height,
                db.index.bins_per_table,
                db.chunk.bins_per_table,
                params::compute_dpf_n(db.index.bins_per_table),
                params::compute_dpf_n(db.chunk.bins_per_table)
            );
            db_paths.push((all_databases.len() as u8, name, path.clone()));
            all_databases.push(db);
        }

        for (path, base, tip) in &args.deltas {
            let name = format!("delta_{}_{}", base, tip);
            let db_id = all_databases.len() as u8;
            let db = load_runtime_database_v1(
                db_id,
                path,
                DatabaseDescriptor {
                    name: name.clone(),
                    db_type: DatabaseType::Delta,
                    base_height: *base,
                    height: *tip,
                    index_params: INDEX_PARAMS,
                    chunk_params: CHUNK_PARAMS,
                },
                &direct_oram_db_ids,
            );
            println!(
                "[Delta:{}→{}] INDEX bins={}, CHUNK bins={}, dpf_n_index={}, dpf_n_chunk={}",
                base,
                tip,
                db.index.bins_per_table,
                db.chunk.bins_per_table,
                params::compute_dpf_n(db.index.bins_per_table),
                params::compute_dpf_n(db.chunk.bins_per_table)
            );
            db_paths.push((all_databases.len() as u8, name, path.clone()));
            all_databases.push(db);
        }
    }

    let main_db = &all_databases[0];
    let _index_k = main_db.index.params.k;
    let _chunk_k = main_db.chunk.params.k;

    #[cfg(not(feature = "cuckoo-oram"))]
    {
        let _ = (
            args.cuckoo_oram_pack,
            args.cuckoo_oram_drain_per_access,
            args.cuckoo_oram_encrypted,
            args.cuckoo_oram_key_hex.as_ref(),
            args.cuckoo_oram_state_key_hex.as_ref(),
            args.cuckoo_oram_cache_levels,
            args.cuckoo_oram_auth_store,
            args.cuckoo_oram_no_save,
            args.direct_oram_drain_per_access,
            args.direct_oram_access_budget,
            args.direct_oram_encrypted,
            args.direct_oram_key_hex.as_ref(),
            args.direct_oram_state_key_hex.as_ref(),
            args.direct_oram_cache_levels,
            args.direct_oram_auth_store,
            args.direct_oram_no_save,
            args.direct_oram_trusted_state_dbs.as_slice(),
        );
        if args.cuckoo_oram_dir.is_some()
            || !args.cuckoo_oram_dbs.is_empty()
            || args.direct_oram_dir.is_some()
            || !args.direct_oram_dbs.is_empty()
            || !args.direct_oram_trusted_state_dbs.is_empty()
        {
            eprintln!(
                "ERROR: ORAM flags require building unified_server with --features cuckoo-oram \
                 (legacy alias: --features harmony-oram)"
            );
            std::process::exit(2);
        }
    }

    #[cfg(feature = "cuckoo-oram")]
    let cuckoo_oram = {
        let mut requested: BTreeMap<u8, PathBuf> = BTreeMap::new();
        if let Some(oram_dir) = args.cuckoo_oram_dir.as_ref() {
            requested.insert(0, oram_dir.clone());
        }
        for (db_id, oram_dir) in &args.cuckoo_oram_dbs {
            if requested.insert(*db_id, oram_dir.clone()).is_some() {
                eprintln!(
                    "ERROR: duplicate Cuckoo ORAM configuration for db_id={}",
                    db_id
                );
                std::process::exit(2);
            }
        }

        if requested.is_empty() {
            println!("  Cuckoo ORAM: disabled (use --cuckoo-oram-db <db_id>=<dir> to enable)");
            HashMap::new()
        } else {
            let mut opened = HashMap::new();
            for (db_id, oram_dir) in requested {
                let Some((_, db_label, db_path)) = db_paths
                    .iter()
                    .find(|(candidate, _, _)| *candidate == db_id)
                else {
                    eprintln!(
                        "ERROR: Cuckoo ORAM configured for unknown db_id={} (loaded db_ids: {:?})",
                        db_id,
                        db_paths.iter().map(|(id, _, _)| *id).collect::<Vec<_>>()
                    );
                    std::process::exit(2);
                };

                println!(
                    "  Cuckoo ORAM: enabled for db_id={} name={}, dir={}, pack={}, drain_per_access={}, encrypted={}, cache_levels={}, auth_store={}",
                    db_id,
                    db_label,
                    oram_dir.display(),
                    args.cuckoo_oram_pack,
                    args.cuckoo_oram_drain_per_access,
                    args.cuckoo_oram_encrypted,
                    args.cuckoo_oram_cache_levels,
                    args.cuckoo_oram_auth_store,
                );
                let tables = CuckooOramTables::open(
                    db_path,
                    &oram_dir,
                    args.cuckoo_oram_pack,
                    args.cuckoo_oram_drain_per_access,
                    args.cuckoo_oram_encrypted,
                    args.cuckoo_oram_key_hex.as_deref(),
                    args.cuckoo_oram_state_key_hex.as_deref(),
                    args.cuckoo_oram_cache_levels,
                    args.cuckoo_oram_auth_store,
                    !args.cuckoo_oram_no_save,
                )
                .unwrap_or_else(|e| {
                    panic!(
                        "failed to open Cuckoo ORAM for db_id={} ({}): {}",
                        db_id, db_label, e
                    )
                });
                opened.insert(db_id, tables);
            }

            let mmap_fallbacks: Vec<String> = db_paths
                .iter()
                .filter(|(db_id, _, _)| !opened.contains_key(db_id))
                .map(|(db_id, label, _)| format!("{}:{}", db_id, label))
                .collect();
            if !mmap_fallbacks.is_empty() {
                eprintln!(
                    "  Cuckoo ORAM: WARNING — DB(s) without ORAM config remain mmap-backed for Harmony queries: {}",
                    mmap_fallbacks.join(", ")
                );
            }
            opened
        }
    };

    #[cfg(feature = "cuckoo-oram")]
    let direct_oram = {
        let mut requested: BTreeMap<u8, PathBuf> = BTreeMap::new();
        let mut trusted_state_requested: BTreeMap<u8, PathBuf> = BTreeMap::new();
        if let Some(oram_dir) = args.direct_oram_dir.as_ref() {
            requested.insert(0, oram_dir.clone());
        }
        for (db_id, oram_dir) in &args.direct_oram_dbs {
            if requested.insert(*db_id, oram_dir.clone()).is_some() {
                eprintln!(
                    "ERROR: duplicate Direct ORAM configuration for db_id={}",
                    db_id
                );
                std::process::exit(2);
            }
        }
        for (db_id, trusted_state_dir) in &args.direct_oram_trusted_state_dbs {
            if trusted_state_requested
                .insert(*db_id, trusted_state_dir.clone())
                .is_some()
            {
                eprintln!(
                    "ERROR: duplicate Direct ORAM trusted-state configuration for db_id={}",
                    db_id
                );
                std::process::exit(2);
            }
        }
        for db_id in trusted_state_requested.keys() {
            if !requested.contains_key(db_id) {
                eprintln!(
                    "ERROR: Direct ORAM trusted-state configured without an image directory for db_id={}",
                    db_id
                );
                std::process::exit(2);
            }
        }

        if requested.is_empty() {
            println!("  Direct ORAM: disabled (use --direct-oram-db <db_id>=<dir> to enable)");
            HashMap::new()
        } else {
            let mut opened = HashMap::new();
            for (db_id, oram_dir) in requested {
                let trusted_state_dir = trusted_state_requested.remove(&db_id);
                let Some((_, db_label, _db_path)) = db_paths
                    .iter()
                    .find(|(candidate, _, _)| *candidate == db_id)
                else {
                    eprintln!(
                        "ERROR: Direct ORAM configured for unknown db_id={} (loaded db_ids: {:?})",
                        db_id,
                        db_paths.iter().map(|(id, _, _)| *id).collect::<Vec<_>>()
                    );
                    std::process::exit(2);
                };
                let database = all_databases.get(db_id as usize).unwrap_or_else(|| {
                    panic!("loaded DB vector is missing configured db_id={db_id}")
                });
                if !args.direct_oram_auth_store {
                    eprintln!(
                        "ERROR: production Direct ORAM for db_id={} requires --direct-oram-auth-store",
                        db_id
                    );
                    std::process::exit(2);
                }
                if !args.direct_oram_encrypted {
                    eprintln!(
                        "ERROR: production Direct ORAM for db_id={} requires --direct-oram-encrypted so the host cannot track plaintext block relocation",
                        db_id
                    );
                    std::process::exit(2);
                }
                if args.direct_oram_no_save {
                    eprintln!(
                        "ERROR: production Direct ORAM for db_id={} rejects --direct-oram-no-save because mutable controller/auth state must commit",
                        db_id
                    );
                    std::process::exit(2);
                }
                if trusted_state_dir.is_none() {
                    eprintln!(
                        "ERROR: production Direct ORAM for db_id={} requires a separate --direct-oram-trusted-state-db",
                        db_id
                    );
                    std::process::exit(2);
                }
                let trusted_state_dir = trusted_state_dir
                    .as_deref()
                    .expect("production Direct ORAM checked trusted-state directory");
                if !args.direct_oram_allow_trusted_state_outside_run_dev {
                    let trusted_state_dir = std::fs::canonicalize(trusted_state_dir)
                        .unwrap_or_else(|error| {
                            panic!(
                                "failed to resolve Direct ORAM trusted-state directory for db_id={} ({}): {}",
                                db_id,
                                trusted_state_dir.display(),
                                error
                            )
                        });
                    if !trusted_state_dir.starts_with("/run/bitcoinpir-oram-state") {
                        eprintln!(
                            "ERROR: production Direct ORAM for db_id={} requires trusted state under measured /run/bitcoinpir-oram-state; got {}",
                            db_id,
                            trusted_state_dir.display()
                        );
                        std::process::exit(2);
                    }
                    let bulk_dir = std::fs::canonicalize(&oram_dir).unwrap_or_else(|error| {
                        panic!(
                            "failed to resolve Direct ORAM bulk directory for db_id={} ({}): {}",
                            db_id,
                            oram_dir.display(),
                            error
                        )
                    });
                    if bulk_dir.starts_with(&trusted_state_dir)
                        || trusted_state_dir.starts_with(&bulk_dir)
                    {
                        eprintln!(
                            "ERROR: production Direct ORAM for db_id={} requires disjoint bulk and trusted-state directories",
                            db_id
                        );
                        std::process::exit(2);
                    }
                } else {
                    eprintln!(
                        "WARNING: Direct ORAM trusted state outside measured /run explicitly allowed for development/testing (db_id={})",
                        db_id
                    );
                }

                println!(
                    "  Direct ORAM: enabled for db_id={} name={}, dir={}, trusted_state_dir={}, access_budget={}, drain_per_access={}, encrypted={}, cache_levels={}, auth_store={}",
                    db_id,
                    db_label,
                    oram_dir.display(),
                    trusted_state_dir.display(),
                    args.direct_oram_access_budget,
                    args.direct_oram_drain_per_access,
                    args.direct_oram_encrypted,
                    args.direct_oram_cache_levels,
                    args.direct_oram_auth_store,
                );
                let tables = DirectOramTables::open_with_trusted_state(
                    &oram_dir,
                    Some(trusted_state_dir),
                    args.direct_oram_drain_per_access,
                    args.direct_oram_access_budget,
                    args.direct_oram_encrypted,
                    args.direct_oram_key_hex.as_deref(),
                    args.direct_oram_state_key_hex.as_deref(),
                    args.direct_oram_cache_levels,
                    args.direct_oram_auth_store,
                    !args.direct_oram_no_save,
                )
                .unwrap_or_else(|e| {
                    panic!(
                        "failed to open Direct ORAM for db_id={} ({}): {}",
                        db_id, db_label, e
                    )
                });
                tables
                    .validate_dataset_binding(database)
                    .unwrap_or_else(|error| {
                        panic!(
                            "failed to bind Direct ORAM to verified DB for db_id={} ({}): {}",
                            db_id, db_label, error
                        )
                    });
                opened.insert(db_id, tables);
            }
            opened
        }
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
    // It was generated before sealed preflight, so receipts and the server
    // announcement commit to this exact same public key. The secret never
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
    let announcement_bundle: Option<Vec<u8>> = if let Some((identity_key, identity_cert)) =
        sealed_identity
    {
        let server_id = identity_cert.server_id.clone();
        let manifest_roots: Vec<[u8; 32]> = all_databases
            .iter()
            .map(|db| db.manifest_root.unwrap_or([0u8; 32]))
            .collect();
        let issued_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(0);
        let identity = pir_runtime_core::identity::build_announcement_bundle(
            &identity_key,
            identity_cert,
            &server_id,
            channel_pubkey,
            pir_runtime_core::attest::self_exe_sha256(),
            pir_runtime_core::attest::GIT_REV,
            manifest_roots,
            issued_at,
        )
        .unwrap_or_else(|error| {
            fatal_cli(format!(
                "sealed pir2 identity cannot build the required announcement: {error}"
            ))
        });
        println!(
            "  Identity announce: enabled from SNP-sealed key (server_id={}, issued_at={})",
            server_id, issued_at
        );
        Some(identity.encoded_bundle)
    } else {
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
                        // Manifest roots in db_id order — same as the V2
                        // attest layout, so the bundle and the SEV report
                        // commit to the same set.
                        let manifest_roots: Vec<[u8; 32]> = all_databases
                            .iter()
                            .map(|db| db.manifest_root.unwrap_or([0u8; 32]))
                            .collect();
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
    let _num_databases = all_databases.len();
    let state = ServerState {
        databases: all_databases,
        server_static_pub: channel_pubkey,
        ark_pem,
        ask_pem,
        vcek_pem,
        announcement_bundle,
    };

    let admin_config = match args.admin_pubkey_hex.as_deref() {
        None => None,
        Some(hex) => match pir_runtime_core::admin::AdminConfig::from_hex(hex) {
            Ok(c) => {
                println!("  Admin auth: enabled (pubkey={})", &hex[..16]);
                Some(c)
            }
            Err(e) => panic!("invalid --admin-pubkey-hex: {}", e),
        },
    };

    // data_root = directory of databases.toml (where DB subdirs live)
    // when --config is given; otherwise fall back to --data-dir.
    let data_root = match args.config_path.as_ref() {
        Some(p) => p
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(".")),
        None => args.data_dir.clone(),
    };
    println!("  Data root: {}", data_root.display());

    // ── Initialize HarmonyPIR V2 hint pool (if enabled) ──────────────────
    let arc_admission = ArcAdmissionV1::from_cli(&args).unwrap_or_else(|error| panic!("{error}"));
    let (arc_verifier, require_arc) = arc_admission.into_parts();
    let local_admission = LocalAdmissionV1::load(args.local_admission_config.as_deref())
        .unwrap_or_else(|error| fatal_cli(error));
    println!("  {}", local_admission.startup_log_line());

    let (cashu_verifier, require_cashu) = if args.require_cashu {
        if args.cashu_keysets.is_empty() {
            panic!("--require-cashu requires at least one --cashu-keyset <id>:<hex_sk>");
        }
        let verifier =
            pir_runtime_core::cashu_verifier::CashuVerifier::from_keys(&args.cashu_keysets)
                .expect("valid Cashu keysets");
        println!(
            "  Cashu: enabled — {} keyset(s) loaded",
            verifier.keyset_count()
        );
        (Some(std::sync::Mutex::new(verifier)), true)
    } else {
        println!("  Cashu: disabled (use --require-cashu to enable)");
        (None, false)
    };

    let mut hint_pools = BTreeMap::new();
    for binding in &args.harmony_pool_bindings {
        let pool_config = hint_pool::HintPoolConfig {
            pool_size: args.pool_size,
            // Advertise exactly the backend compiled into this runtime:
            // FastPRP with the feature, HMR12 otherwise.
            prp_backend: hint_pool::default_prp_backend(),
            pool_dir: binding.pool_dir.clone(),
        };
        let pool_db = state.get_db(binding.db_id).unwrap_or_else(|| {
            panic!(
                "HarmonyPIR hint pool database db_id {} must be loaded",
                binding.db_id
            )
        });
        let backend_name = match pool_config.prp_backend {
            harmonypir::remote::PRP_HMR12 => "HMR12",
            harmonypir::remote::PRP_FASTPRP => "FastPRP",
            _ => "unknown",
        };
        println!(
            "  HarmonyPIR V2 hint pool: db_id={}, size={}, backend={}, dir={}",
            binding.db_id,
            pool_config.pool_size,
            backend_name,
            pool_config
                .pool_dir
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "memory-only".into())
        );
        let pool =
            hint_pool::HintPool::new(pool_config, binding.db_id, pool_db).unwrap_or_else(|e| {
                panic!(
                    "HarmonyPIR hint pool init failed for db {}: {e}",
                    binding.db_id
                )
            });
        let previous = hint_pools.insert(binding.db_id, pool);
        debug_assert!(
            previous.is_none(),
            "pool bindings were normalized as unique"
        );
    }
    if hint_pools.is_empty() {
        println!("  HarmonyPIR V2 hint pool: disabled (use --pool-size to enable)");
    }

    let server = Arc::new(UnifiedServerData {
        state,
        role: args.role,
        onionpir_txs,
        onionpir_infos,
        onionpir_merkle: onionpir_merkle_per_db,
        admin_config,
        data_root,
        channel_keypair,
        hint_pools,
        #[cfg(feature = "cuckoo-oram")]
        cuckoo_oram,
        #[cfg(feature = "cuckoo-oram")]
        direct_oram,
        v2_half_pending: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        arc_verifier,
        require_arc,
        cashu_verifier,
        require_cashu,
        serve_hints: args.serve_hints,
        serve_queries: args.serve_queries,
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

    serve::serve_connections(&args, role_name.to_string(), server).await;
}

#[cfg(test)]
mod tests;
