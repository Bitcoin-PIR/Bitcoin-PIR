//! Local smoke client for the TEE ORAM backend.
//!
//! Usage:
//!   cargo run -p pir-sdk-client --example oram_local_smoke -- \
//!     --server ws://127.0.0.1:18091 \
//!     4242424242424242424242424242424242424242

use pir_sdk_client::{OramClient, PirError, ScriptHash};

struct Args {
    server: String,
    db_id: u8,
    script_hashes: Vec<ScriptHash>,
    expect_cleartext_reject: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut server = "ws://127.0.0.1:18091".to_string();
    let mut db_id = 0u8;
    let mut script_hashes = Vec::new();
    let mut expect_cleartext_reject = false;
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
            "--help" | "-h" => {
                println!(
                    "Usage: oram_local_smoke [--server <url>] [--db-id <n>] [--expect-cleartext-reject] <script_hash_hex>..."
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
    Ok(Args {
        server,
        db_id,
        script_hashes,
        expect_cleartext_reject,
    })
}

fn parse_script_hash(value: &str) -> Result<ScriptHash, String> {
    let bytes = hex::decode(value).map_err(|e| format!("invalid script hash hex `{value}`: {e}"))?;
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    let Args {
        server,
        db_id,
        script_hashes,
        expect_cleartext_reject,
    } = parse_args()?;

    println!("server={server}");
    println!("db_id={db_id}");
    println!("query_count={}", script_hashes.len());

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

    let results = client.query_batch(&script_hashes, db_id).await?;
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
