//! Delta synchronization example.
//!
//! Demonstrates how to efficiently sync by only querying changes since
//! the last known height, using delta databases when available. A delta plan
//! only carries changes, so the second sync passes the first sync's results
//! to `sync_with_plan` as the base.
//!
//! Usage:
//!   cargo run -p pir-sdk-client --example delta_sync

use pir_sdk::QueryResult;
use pir_sdk_client::{DpfClient, PirClient, ScriptHash};
use std::collections::HashMap;

/// Simulated wallet state
struct WalletState {
    /// Last synced height
    last_height: Option<u32>,
    /// Results of the last sync, one per address: the base for the next one
    results: Vec<Option<QueryResult>>,
    /// Cached balances per script hash
    balances: HashMap<ScriptHash, u64>,
}

impl WalletState {
    fn new() -> Self {
        Self {
            last_height: None,
            results: Vec::new(),
            balances: HashMap::new(),
        }
    }

    fn update(&mut self, script_hash: ScriptHash, balance: u64, height: u32) {
        self.balances.insert(script_hash, balance);
        self.last_height = Some(height);
    }
}

fn generate_test_addresses(count: usize) -> Vec<ScriptHash> {
    (0..count)
        .map(|i| {
            let mut hash = [0u8; 20];
            // Generate deterministic but varied hashes
            let seed = (i as u64).wrapping_mul(0x9e3779b97f4a7c15);
            hash[0..8].copy_from_slice(&seed.to_le_bytes());
            hash[8..16].copy_from_slice(&seed.wrapping_mul(0x6a09e667).to_le_bytes());
            hash[16..20].copy_from_slice(&(i as u32).to_le_bytes());
            hash
        })
        .collect()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let server0 = "ws://127.0.0.1:8091";
    let server1 = "ws://127.0.0.1:8092";

    println!("=== PIR Delta Sync Example ===");
    println!();

    // Create client and connect
    let mut client = DpfClient::new(server0, server1);

    println!("Connecting to PIR servers...");
    if let Err(e) = client.connect().await {
        eprintln!("Failed to connect: {}", e);
        eprintln!("Make sure PIR servers are running on ports 8091 and 8092");
        return Ok(());
    }

    // Fetch catalog
    let catalog = client.fetch_catalog().await?;
    println!(
        "Connected! Latest tip: {}",
        catalog.latest_tip().unwrap_or(0)
    );
    println!();

    // Generate test addresses
    let addresses = generate_test_addresses(3);
    let mut wallet = WalletState::new();

    // === First Sync (Fresh) ===
    println!("=== First Sync (Fresh) ===");
    let plan = client.compute_sync_plan(&catalog, wallet.last_height)?;
    println!(
        "Sync plan: {} step(s), fresh_sync={}",
        plan.steps.len(),
        plan.is_fresh_sync
    );
    for step in &plan.steps {
        println!(
            "  - {} (db_id={}, height={})",
            step.name, step.db_id, step.tip_height
        );
    }

    let result = client.sync(&addresses, None).await?;

    println!();
    println!("First sync complete! Height: {}", result.synced_height);
    for (i, addr) in addresses.iter().enumerate() {
        let balance = result.results[i]
            .as_ref()
            .map(|r| r.total_balance())
            .unwrap_or(0);
        wallet.update(*addr, balance, result.synced_height);
        println!("  Address {}: {} sats", hex::encode(&addr[0..4]), balance);
    }
    wallet.results = result.results;

    // === Second Sync (Delta) ===
    println!();
    println!("=== Second Sync (Delta) ===");

    // Re-fetch catalog to see if there are new blocks
    let catalog = client.fetch_catalog().await?;
    let plan = client.compute_sync_plan(&catalog, wallet.last_height)?;

    if plan.is_empty() {
        println!(
            "Already synced to latest height {}",
            wallet.last_height.unwrap_or(0)
        );
    } else {
        println!(
            "Sync plan: {} step(s), fresh_sync={}",
            plan.steps.len(),
            plan.is_fresh_sync
        );
        for step in &plan.steps {
            println!(
                "  - {} (db_id={}, height={})",
                step.name, step.db_id, step.tip_height
            );
        }

        // A delta plan only carries changes: apply it to the previous
        // sync's results (its spends remove their real outpoints).
        let result = client
            .sync_with_plan(&addresses, &plan, Some(&wallet.results))
            .await?;

        println!();
        println!("Delta sync complete! Height: {}", result.synced_height);
        for (i, addr) in addresses.iter().enumerate() {
            let old_balance = wallet.balances.get(addr).copied().unwrap_or(0);
            let new_balance = result.results[i]
                .as_ref()
                .map(|r| r.total_balance())
                .unwrap_or(0);

            let diff = new_balance as i64 - old_balance as i64;
            let diff_str = if diff > 0 {
                format!("+{}", diff)
            } else if diff < 0 {
                format!("{}", diff)
            } else {
                "unchanged".to_string()
            };

            wallet.update(*addr, new_balance, result.synced_height);
            println!(
                "  Address {}: {} sats ({})",
                hex::encode(&addr[0..4]),
                new_balance,
                diff_str
            );
        }
        wallet.results = result.results;
    }

    // === Summary ===
    println!();
    println!("=== Final Wallet State ===");
    println!("Last synced height: {}", wallet.last_height.unwrap_or(0));
    let total: u64 = wallet.balances.values().sum();
    println!(
        "Total balance: {} sats ({} addresses)",
        total,
        wallet.balances.len()
    );

    client.disconnect().await?;
    println!();
    println!("Done!");

    Ok(())
}
