//! Local smoke client for the TEE ORAM backend.
//!
//! Usage:
//!   cargo run -p pir-sdk-client --example oram_local_smoke -- \
//!     --server ws://127.0.0.1:18091 \
//!     4242424242424242424242424242424242424242

use ed25519_dalek::VerifyingKey;
use pir_sdk_client::{
    dangerous_unpaired_build_authorization_proof_v1, DatabaseProofPolicy, OramClient, PirError,
    RootPolicy, ScriptHash, ServicePolicyCheckpointV1,
};
use pir_service_protocol::{
    pow_solution_meets_difficulty_v1, AuthScheme, BackendId, DatasetBindingV1, FreeModeV1,
    FreePowProofV1, PowChallengeResponseV1, WorkloadId,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct ServiceFreePowArgs {
    provider_id: [u8; 32],
    policy_signing_key: [u8; 32],
    manifest_root: [u8; 32],
    proof_params_hash: [u8; 32],
    builder_binary_sha256: [u8; 32],
    builder_git_commit: String,
}

struct Args {
    server: String,
    db_id: u8,
    script_hashes: Vec<ScriptHash>,
    expect_cleartext_reject: bool,
    padded_slots: Option<usize>,
    service_free_pow: Option<ServiceFreePowArgs>,
}

fn parse_args() -> Result<Args, String> {
    let mut server = "ws://127.0.0.1:18091".to_string();
    let mut db_id = 0u8;
    let mut script_hashes = Vec::new();
    let mut expect_cleartext_reject = false;
    let mut padded_slots = None;
    let mut service_free_pow = false;
    let mut service_provider_id = None;
    let mut service_policy_signing_key = None;
    let mut service_manifest_root = None;
    let mut service_proof_params_hash = None;
    let mut service_builder_binary_sha256 = None;
    let mut service_builder_git_commit = None;
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--server" | "-s" => {
                server = args
                    .next()
                    .ok_or_else(|| "--server requires a URL".to_string())?;
            }
            "--db-id" => {
                let raw = args
                    .next()
                    .ok_or_else(|| "--db-id requires a number".to_string())?;
                db_id = raw
                    .parse::<u8>()
                    .map_err(|e| format!("invalid --db-id `{raw}`: {e}"))?;
            }
            "--expect-cleartext-reject" => {
                expect_cleartext_reject = true;
            }
            "--padded-slots" => {
                let raw = args
                    .next()
                    .ok_or_else(|| "--padded-slots requires a number".to_string())?;
                padded_slots = Some(
                    raw.parse::<usize>()
                        .map_err(|e| format!("invalid --padded-slots `{raw}`: {e}"))?,
                );
            }
            "--service-free-pow" => service_free_pow = true,
            "--service-provider-id-hex" => {
                service_provider_id = Some(parse_hex_array(
                    "--service-provider-id-hex",
                    &args.next().ok_or_else(|| {
                        "--service-provider-id-hex requires 64 hex characters".to_string()
                    })?,
                )?);
            }
            "--service-policy-signing-key-hex" => {
                service_policy_signing_key = Some(parse_hex_array(
                    "--service-policy-signing-key-hex",
                    &args.next().ok_or_else(|| {
                        "--service-policy-signing-key-hex requires 64 hex characters".to_string()
                    })?,
                )?);
            }
            "--service-manifest-root-hex" => {
                service_manifest_root = Some(parse_hex_array(
                    "--service-manifest-root-hex",
                    &args.next().ok_or_else(|| {
                        "--service-manifest-root-hex requires 64 hex characters".to_string()
                    })?,
                )?);
            }
            "--service-proof-params-hash-hex" => {
                service_proof_params_hash = Some(parse_hex_array(
                    "--service-proof-params-hash-hex",
                    &args.next().ok_or_else(|| {
                        "--service-proof-params-hash-hex requires 64 hex characters".to_string()
                    })?,
                )?);
            }
            "--service-builder-binary-sha256-hex" => {
                service_builder_binary_sha256 = Some(parse_hex_array(
                    "--service-builder-binary-sha256-hex",
                    &args.next().ok_or_else(|| {
                        "--service-builder-binary-sha256-hex requires 64 hex characters".to_string()
                    })?,
                )?);
            }
            "--service-builder-git-commit" => {
                service_builder_git_commit = Some(args.next().ok_or_else(|| {
                    "--service-builder-git-commit requires a commit string".to_string()
                })?);
            }
            "--help" | "-h" => {
                println!(
                    "Usage: oram_local_smoke [--server <url>] [--db-id <n>] [--expect-cleartext-reject] [--padded-slots <n>] [--service-free-pow --service-provider-id-hex <hex64> --service-policy-signing-key-hex <hex64> --service-manifest-root-hex <hex64> --service-proof-params-hash-hex <hex64> --service-builder-binary-sha256-hex <hex64> --service-builder-git-commit <commit>] <script_hash_hex>..."
                );
                std::process::exit(0);
            }
            value if !value.starts_with('-') => {
                script_hashes.push(parse_script_hash(value)?);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    if script_hashes.is_empty() {
        script_hashes.push([0x42u8; 20]);
    }
    let service_free_pow = if service_free_pow {
        Some(ServiceFreePowArgs {
            provider_id: service_provider_id.ok_or_else(|| {
                "--service-free-pow requires --service-provider-id-hex".to_string()
            })?,
            policy_signing_key: service_policy_signing_key.ok_or_else(|| {
                "--service-free-pow requires --service-policy-signing-key-hex".to_string()
            })?,
            manifest_root: service_manifest_root.ok_or_else(|| {
                "--service-free-pow requires --service-manifest-root-hex".to_string()
            })?,
            proof_params_hash: service_proof_params_hash.ok_or_else(|| {
                "--service-free-pow requires --service-proof-params-hash-hex".to_string()
            })?,
            builder_binary_sha256: service_builder_binary_sha256.ok_or_else(|| {
                "--service-free-pow requires --service-builder-binary-sha256-hex".to_string()
            })?,
            builder_git_commit: service_builder_git_commit.ok_or_else(|| {
                "--service-free-pow requires --service-builder-git-commit".to_string()
            })?,
        })
    } else {
        if service_provider_id.is_some()
            || service_policy_signing_key.is_some()
            || service_manifest_root.is_some()
            || service_proof_params_hash.is_some()
            || service_builder_binary_sha256.is_some()
            || service_builder_git_commit.is_some()
        {
            return Err("service admission pins require --service-free-pow".to_string());
        }
        None
    };
    Ok(Args {
        server,
        db_id,
        script_hashes,
        expect_cleartext_reject,
        padded_slots,
        service_free_pow,
    })
}

fn parse_hex_array<const N: usize>(flag: &str, value: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(value).map_err(|e| format!("invalid {flag} hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("{flag} decoded to {} bytes, expected {N}", bytes.len()))
}

fn parse_script_hash(value: &str) -> Result<ScriptHash, String> {
    let bytes =
        hex::decode(value).map_err(|e| format!("invalid script hash hex `{value}`: {e}"))?;
    if bytes.len() != 20 {
        return Err(format!(
            "script hash `{value}` decoded to {} bytes, expected 20",
            bytes.len()
        ));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn now_unix() -> Result<u64, PirError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| PirError::InvalidState(format!("system clock before Unix epoch: {error}")))
}

async fn solve_pow(challenge: &PowChallengeResponseV1) -> Result<FreePowProofV1, PirError> {
    let challenge = challenge.clone();
    tokio::task::spawn_blocking(move || {
        let deadline = Instant::now() + Duration::from_secs(60);
        for nonce in 0..=u64::MAX {
            if nonce % 4096 == 0 && Instant::now() >= deadline {
                return Err(PirError::Protocol(
                    "proof-of-work solve timed out after 60s".into(),
                ));
            }
            let solution = FreePowProofV1 {
                challenge_id: challenge.challenge_id,
                nonce,
            };
            if pow_solution_meets_difficulty_v1(&challenge, &solution)
                .map_err(|error| PirError::Protocol(error.to_string()))?
            {
                return Ok(solution);
            }
        }
        Err(PirError::Protocol(
            "proof-of-work nonce space exhausted".into(),
        ))
    })
    .await
    .map_err(|error| PirError::Protocol(format!("proof-of-work solver failed: {error}")))?
}

async fn authorize_free_pow(
    client: &mut OramClient,
    db_id: u8,
    pins: ServiceFreePowArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    client.set_root_policy(RootPolicy::RequireVerified);
    let mut proof_policy = DatabaseProofPolicy::mainnet();
    proof_policy.expected_params_hash = Some(pins.proof_params_hash);
    proof_policy.allowed_builder_binary_sha256 = vec![pins.builder_binary_sha256];
    proof_policy.allowed_builder_git_commits = vec![pins.builder_git_commit];
    let roots = client.verify_database_proof(db_id, &proof_policy).await?;
    if roots.manifest_root != pins.manifest_root {
        return Err(format!(
            "verified db {db_id} manifest root mismatch: expected {}, got {}",
            hex::encode(pins.manifest_root),
            hex::encode(roots.manifest_root)
        )
        .into());
    }
    client.install_verified_database_roots(roots)?;
    println!("database_proof=verified");

    let signing_key = VerifyingKey::from_bytes(&pins.policy_signing_key)?;
    let accepted = client
        .fetch_service_policy_v1(
            db_id,
            pins.provider_id,
            &signing_key,
            now_unix()?,
            &ServicePolicyCheckpointV1::initial(),
        )
        .await?;
    let expected_dataset = DatasetBindingV1::ManifestRoot {
        root: pins.manifest_root,
    };
    let mut selected = None;
    for scope_policy in accepted.policy().scopes.iter() {
        if scope_policy.scope.backend != BackendId::TeeOramV1
            || scope_policy.scope.workload != WorkloadId::TeeOramQueryV1
            || scope_policy.scope.dataset != expected_dataset
        {
            continue;
        }
        for offer in scope_policy.offers.iter() {
            if offer.authorization == AuthScheme::FreeV1
                && offer.free_mode == FreeModeV1::ProofOfWork
            {
                if selected.is_some() {
                    return Err("multiple matching Free-PoW ORAM offers in verified policy".into());
                }
                selected = Some((scope_policy.scope.scope_id(), offer.offer_id));
            }
        }
    }
    let (scope_id, offer_id) =
        selected.ok_or("no exact manifest-bound Free-PoW TEE ORAM offer in verified policy")?;
    let challenge = client
        .request_service_pow_challenge_v1(db_id, &accepted, scope_id, offer_id, now_unix()?)
        .await?;
    let solution = solve_pow(&challenge).await?;
    let proof = dangerous_unpaired_build_authorization_proof_v1(
        &accepted,
        &scope_id,
        offer_id,
        &solution.encode()?,
    )?;
    client
        .authorize_service_v1(db_id, &accepted, scope_id, offer_id, proof)
        .await?;
    println!("service_authorization=free-pow");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    let Args {
        server,
        db_id,
        script_hashes,
        expect_cleartext_reject,
        padded_slots,
        service_free_pow,
    } = parse_args()?;

    println!("server={server}");
    println!("db_id={db_id}");
    println!("query_count={}", script_hashes.len());
    if let Some(padded_slots) = padded_slots {
        println!("padded_slots={padded_slots}");
    }

    let mut client = OramClient::new(&server);
    client.connect().await?;
    let catalog = client.fetch_catalog().await?;
    println!("catalog_databases={}", catalog.databases.len());
    for db in &catalog.databases {
        println!(
            "catalog db_id={} name={} height={} index_bins={} chunk_bins={} index_k={} chunk_k={}",
            db.db_id, db.name, db.height, db.index_bins, db.chunk_bins, db.index_k, db.chunk_k
        );
    }

    if expect_cleartext_reject {
        match client.lookup_raw(&script_hashes, db_id).await {
            Err(PirError::ServerError(msg)) if msg.contains("encrypted channel") => {
                println!("cleartext_reject=ok");
                client.disconnect().await?;
                return Ok(());
            }
            other => {
                return Err(format!(
                    "expected encrypted-channel ServerError for cleartext ORAM lookup, got {other:?}"
                )
                .into());
            }
        }
    }

    let mut eph_seed = [0u8; 32];
    let mut random_32 = [0u8; 32];
    let mut hs_nonce = [0u8; 32];
    getrandom::getrandom(&mut eph_seed)?;
    getrandom::getrandom(&mut random_32)?;
    getrandom::getrandom(&mut hs_nonce)?;

    let attestation = client.attest_with_eph_binding(eph_seed, random_32).await?;
    println!("sev_status={:?}", attestation.sev_status);
    println!(
        "server_static_pub={}",
        hex::encode(attestation.response.server_static_pub)
    );
    client
        .upgrade_to_secure_channel_with_seeds(
            attestation.response.server_static_pub,
            eph_seed,
            hs_nonce,
        )
        .await?;
    println!("secure_channel=established");

    if let Some(service_free_pow) = service_free_pow {
        authorize_free_pow(&mut client, db_id, service_free_pow).await?;
    }

    let results = if let Some(padded_slots) = padded_slots {
        client
            .query_batch_padded(&script_hashes, padded_slots, db_id)
            .await?
    } else {
        client.query_batch(&script_hashes, db_id).await?
    };
    for (i, (script_hash, result)) in script_hashes.iter().zip(results.iter()).enumerate() {
        println!("result[{i}].script_hash={}", hex::encode(script_hash));
        match result {
            None => println!("result[{i}].found=false"),
            Some(qr) => {
                println!("result[{i}].found=true");
                println!("result[{i}].is_whale={}", qr.is_whale);
                println!("result[{i}].utxo_count={}", qr.entries.len());
                println!("result[{i}].total_balance={}", qr.total_balance());
                println!(
                    "result[{i}].raw_chunk_data_len={}",
                    qr.raw_chunk_data.as_ref().map_or(0, Vec::len)
                );
                for (j, entry) in qr.entries.iter().enumerate() {
                    println!(
                        "result[{i}].utxo[{j}] txid={} vout={} amount_sats={}",
                        hex::encode(entry.txid),
                        entry.vout,
                        entry.amount_sats
                    );
                }
            }
        }
    }

    client.disconnect().await?;
    Ok(())
}
