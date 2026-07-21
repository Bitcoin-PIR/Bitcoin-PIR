//! Fetch UTXOs for Bitcoin addresses via the DPF PIR client.
//!
//! Derives each address's PIR script hash exactly the way the build
//! pipeline does — `HASH160(scriptPubKey)`, see
//! `build/src/gen_0_utxo_set.rs` — then runs a full DPF sync against the
//! production servers and prints the decoded UTXO set plus the
//! per-bucket Merkle verification verdict.
//!
//! This is the CI-exercised native client path, used here as the
//! ground-truth oracle for cross-checking the web client.
//!
//! Usage:
//!   cargo run --release -p pir-sdk-client --example fetch_addresses
//!   cargo run --release -p pir-sdk-client --example fetch_addresses -- <addr>...

use std::str::FromStr;

use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::{hash160, Hash};
use bitcoin::Address;
use pir_sdk_client::{DpfClient, PirClient, ScriptHash};

const DEFAULT_SERVER0: &str = "wss://weikeng1.bitcoinpir.org";
const DEFAULT_SERVER1: &str = "wss://weikeng2.bitcoinpir.org";

const DEFAULT_ADDRESSES: &[&str] = &[
    "1D4HSHPJxoPLqiBNFNarz34dcWPLvpiaeb",
    "bc1q2292d7mz8txc7462hjy4prs2gtx727ut8mcanr",
];

/// Derive the PIR script hash for an address: `HASH160(scriptPubKey)`.
/// Returns `(script_hash, scriptPubKey_hex)`.
fn address_to_script_hash(addr: &str) -> Result<(ScriptHash, String), String> {
    let parsed = Address::<NetworkUnchecked>::from_str(addr)
        .map_err(|e| format!("parse address `{addr}`: {e}"))?;
    let spk = parsed.assume_checked().script_pubkey();
    let spk_bytes = spk.as_bytes();
    let h = hash160::Hash::hash(spk_bytes);
    Ok((h.to_byte_array(), hex::encode(spk_bytes)))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let addresses: Vec<String> = if args.is_empty() {
        DEFAULT_ADDRESSES.iter().map(|s| s.to_string()).collect()
    } else {
        args
    };

    println!("=== Address → PIR script hash (HASH160(scriptPubKey)) ===");
    let mut script_hashes: Vec<ScriptHash> = Vec::new();
    for addr in &addresses {
        let (sh, spk_hex) = address_to_script_hash(addr)?;
        println!("  {addr}");
        println!("    scriptPubKey : {spk_hex}");
        println!("    script_hash  : {}", hex::encode(sh));
        script_hashes.push(sh);
    }
    println!();

    println!("Connecting: {DEFAULT_SERVER0} / {DEFAULT_SERVER1}");
    let mut client = DpfClient::new(DEFAULT_SERVER0, DEFAULT_SERVER1);
    client.connect().await?;

    let catalog = client.fetch_catalog().await?;
    println!("Catalog: {} database(s):", catalog.databases.len());
    for db in &catalog.databases {
        println!(
            "  [{}] {} {:?} height={} index_bins={} chunk_bins={}",
            db.db_id, db.name, db.kind, db.height, db.index_bins, db.chunk_bins
        );
    }
    println!();

    let result = client.sync(&script_hashes, None).await?;
    println!("Synced to height {}", result.synced_height);
    println!();

    for (i, addr) in addresses.iter().enumerate() {
        println!("=== {} ({}) ===", addr, hex::encode(script_hashes[i]));
        match &result.results[i] {
            Some(qr) => {
                println!("  merkle_verified : {}", qr.merkle_verified);
                println!("  is_whale        : {}", qr.is_whale);
                println!("  UTXO count      : {}", qr.entries.len());
                println!("  total balance   : {} sats", qr.total_balance());
                for e in &qr.entries {
                    // Reversed = block-explorer display order (big-endian).
                    let txid_display: String =
                        e.txid.iter().rev().map(|b| format!("{:02x}", b)).collect();
                    println!("    {txid_display}:{} = {} sats", e.vout, e.amount_sats);
                }
            }
            None => println!("  (not found)"),
        }
        println!();
    }

    client.disconnect().await?;
    Ok(())
}
