//! Dump empirical HarmonyPIR leakage profiles to a JSON corpus.
//!
//! ```bash
//! cargo run -p pir-sdk-client --example harmony_leakage_dump -- \
//!   --output web/test/fixtures/harmony_corpus.json
//! ```

use std::sync::Arc;

use pir_sdk::BufferingLeakageRecorder;
use pir_sdk_client::{HarmonyClient, PirClient, ScriptHash};

const DEFAULT_HINT_SERVER: &str = "wss://weikeng1.bitcoinpir.org";
const DEFAULT_QUERY_SERVER: &str = "wss://weikeng2.bitcoinpir.org";

struct Args {
    hint_server_url: String,
    query_server_url: String,
    output_path: String,
}

fn parse_args() -> Args {
    let argv: Vec<String> = std::env::args().collect();
    let mut hint_server_url = DEFAULT_HINT_SERVER.to_string();
    let mut query_server_url = DEFAULT_QUERY_SERVER.to_string();
    let mut output_path: Option<String> = None;
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--hint-server" => {
                i += 1;
                if i < argv.len() {
                    hint_server_url = argv[i].clone();
                }
            }
            "--query-server" => {
                i += 1;
                if i < argv.len() {
                    query_server_url = argv[i].clone();
                }
            }
            "--output" | "-o" => {
                i += 1;
                if i < argv.len() {
                    output_path = Some(argv[i].clone());
                }
            }
            "--help" | "-h" => {
                eprintln!(
                    "Usage: harmony_leakage_dump --output <path> [--hint-server <url>] [--query-server <url>]"
                );
                std::process::exit(0);
            }
            other => {
                eprintln!("Unknown argument: {other}");
                std::process::exit(2);
            }
        }
        i += 1;
    }
    let output_path = output_path.unwrap_or_else(|| {
        eprintln!("Error: --output <path> is required");
        std::process::exit(2);
    });
    Args {
        hint_server_url,
        query_server_url,
        output_path,
    }
}

fn corpus() -> Vec<ScriptHash> {
    let mut a = [0u8; 20];
    let mut b = [0u8; 20];
    for i in 0..20 {
        a[i] = (i as u8).wrapping_mul(17);
        b[i] = (i as u8).wrapping_mul(31).wrapping_add(7);
    }
    vec![a, b]
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args();
    let mut entries = Vec::new();

    for script_hash in corpus() {
        let recorder = Arc::new(BufferingLeakageRecorder::new());
        let mut client = HarmonyClient::new(&args.hint_server_url, &args.query_server_url);
        client.set_leakage_recorder(Some(recorder.clone()));

        client.connect().await?;
        let catalog = client.fetch_catalog().await?;
        let db_id = catalog
            .databases
            .first()
            .ok_or("production catalog contains no database")?
            .db_id;
        let _ = client.query_batch(&[script_hash], db_id).await?;
        client.disconnect().await?;

        let profile = recorder.take_profile("harmony");
        eprintln!(
            "Harmony {}: {} rounds, {} request bytes, {} response bytes",
            hex::encode(script_hash),
            profile.rounds.len(),
            profile
                .rounds
                .iter()
                .map(|round| round.request_bytes)
                .sum::<u64>(),
            profile
                .rounds
                .iter()
                .map(|round| round.response_bytes)
                .sum::<u64>(),
        );
        entries.push(serde_json::json!({
            "script_hash_hex": hex::encode(script_hash),
            "profile": profile,
        }));
    }

    let document = serde_json::json!({
        "backend": "harmony",
        "servers": {
            "hint": args.hint_server_url,
            "query": args.query_server_url,
        },
        "queries": entries,
    });
    std::fs::write(&args.output_path, serde_json::to_string_pretty(&document)?)?;
    eprintln!("Wrote {}", args.output_path);
    Ok(())
}
