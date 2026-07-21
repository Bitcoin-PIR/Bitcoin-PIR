//! Simple PIR query example.
//!
//! Usage:
//!   cargo run -p pir-sdk-client --example simple_query -- <script_hash_hex>
//!
//! Example:
//!   cargo run -p pir-sdk-client --example simple_query -- \
//!     --server0 ws://127.0.0.1:8091 \
//!     --server1 ws://127.0.0.1:8092 \
//!     76a914...88ac

use pir_sdk_client::{DpfClient, PirClient, ScriptHash};

fn parse_args() -> (String, String, Vec<ScriptHash>) {
    let args: Vec<String> = std::env::args().collect();

    let mut server0 = "ws://127.0.0.1:8091".to_string();
    let mut server1 = "ws://127.0.0.1:8092".to_string();
    let mut script_hashes = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--server0" | "-s0" => {
                i += 1;
                if i < args.len() {
                    server0 = args[i].clone();
                }
            }
            "--server1" | "-s1" => {
                i += 1;
                if i < args.len() {
                    server1 = args[i].clone();
                }
            }
            "--help" | "-h" => {
                println!("Usage: simple_query [OPTIONS] <script_hash_hex>...");
                println!();
                println!("Options:");
                println!("  --server0, -s0 <url>  Server 0 URL (default: ws://127.0.0.1:8091)");
                println!("  --server1, -s1 <url>  Server 1 URL (default: ws://127.0.0.1:8092)");
                println!("  --help, -h            Show this help");
                println!();
                println!("Script hash format: 40 hex characters (20 bytes)");
                std::process::exit(0);
            }
            arg if !arg.starts_with('-') => {
                // Parse as hex script hash
                if arg.len() == 40 {
                    let mut hash = [0u8; 20];
                    if let Ok(bytes) = hex::decode(arg) {
                        if bytes.len() == 20 {
                            hash.copy_from_slice(&bytes);
                            script_hashes.push(hash);
                        }
                    }
                } else {
                    eprintln!("Warning: Invalid script hash '{}' (expected 40 hex chars)", arg);
                }
            }
            _ => {
                eprintln!("Unknown option: {}", args[i]);
            }
        }
        i += 1;
    }

    (server0, server1, script_hashes)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let (server0, server1, script_hashes) = parse_args();

    if script_hashes.is_empty() {
        eprintln!("No script hashes provided. Use --help for usage.");
        std::process::exit(1);
    }

    println!("Connecting to PIR servers...");
    println!("  Server 0: {}", server0);
    println!("  Server 1: {}", server1);

    let mut client = DpfClient::new(&server0, &server1);
    client.connect().await?;

    println!("Connected! Fetching catalog...");
    let catalog = client.fetch_catalog().await?;

    println!("Server has {} database(s):", catalog.databases.len());
    for db in &catalog.databases {
        println!(
            "  [{}] {} {:?} height={} index_bins={} chunk_bins={}",
            db.db_id, db.name, db.kind, db.height, db.index_bins, db.chunk_bins
        );
    }

    println!();
    println!("Querying {} script hash(es)...", script_hashes.len());

    let result = client.sync(&script_hashes, None).await?;

    println!();
    println!("Results (synced to height {}):", result.synced_height);
    println!();

    for (i, script_hash) in script_hashes.iter().enumerate() {
        print!("Script hash {}: ", hex::encode(script_hash));

        match &result.results[i] {
            Some(query_result) => {
                if query_result.entries.is_empty() {
                    println!("(no UTXOs found)");
                } else {
                    println!("{} UTXO(s), {} sats total",
                        query_result.entries.len(),
                        query_result.total_balance()
                    );

                    for entry in &query_result.entries {
                        let txid_hex: String = entry.txid.iter().rev()
                            .map(|b| format!("{:02x}", b))
                            .collect();
                        println!("  - {}:{} = {} sats",
                            txid_hex,
                            entry.vout,
                            entry.amount_sats
                        );
                    }
                }

                if query_result.is_whale {
                    println!("  (whale address - may have more UTXOs)");
                }
            }
            None => {
                println!("(not found or empty)");
            }
        }
    }

    client.disconnect().await?;
    println!();
    println!("Done!");

    Ok(())
}
