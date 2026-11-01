//! Client for the memory test of PRs #466 (OnionPIR single pass) and #467
//! (DPF shared scan). Not part of the repository: `run.sh` copies it into
//! `crates/sdk/client/examples/` of the baseline checkout and builds it there.
//!
//!   bench_client dpf   <server0_url> <server1_url> [--concurrency N]
//!   bench_client onion <server_url>                [--concurrency N]
//!
//! Each of N clients (started together) runs a full sync (db 0) and a delta
//! sync (940611 -> tip, db 1) for its addresses. With N = 1 the one client
//! queries every address; with N > 1 client i queries address i mod len.
//! Prints one JSON object on stdout: per-client timings and the decoded
//! results, so two server builds can be compared result by result.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::{hash160, Hash};
use bitcoin::Address;
use pir_sdk_client::{DpfClient, OnionClient, PirClient, QueryResult, ScriptHash, SyncResult};
use serde_json::{json, Value};
use tokio::sync::Barrier;

const ADDRESSES: &[&str] = &[
    "1D4HSHPJxoPLqiBNFNarz34dcWPLvpiaeb",
    "bc1q2292d7mz8txc7462hjy4prs2gtx727ut8mcanr",
    "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
];
const DELTA_FROM_HEIGHT: u32 = 940_611;

fn script_hash(addr: &str) -> ScriptHash {
    let spk = Address::<NetworkUnchecked>::from_str(addr)
        .unwrap_or_else(|e| panic!("address {addr}: {e}"))
        .assume_checked()
        .script_pubkey();
    hash160::Hash::hash(spk.as_bytes()).to_byte_array()
}

fn result_json(r: &Option<QueryResult>) -> Value {
    match r {
        None => Value::Null,
        Some(q) => {
            let mut entries: Vec<(String, u32, u64)> = q
                .entries
                .iter()
                .map(|e| (hex::encode(e.txid), e.vout, e.amount_sats))
                .collect();
            entries.sort();
            json!({
                "is_whale": q.is_whale,
                "merkle_verified": q.merkle_verified,
                "entries": entries,
            })
        }
    }
}

fn sync_json(s: &SyncResult, addrs: &[&str]) -> Value {
    json!({
        "synced_height": s.synced_height,
        "results": addrs.iter().zip(&s.results)
            .map(|(a, r)| json!({"address": a, "result": result_json(r)}))
            .collect::<Vec<_>>(),
    })
}

async fn run_one<C: PirClient>(mut client: C, addrs: Vec<&'static str>, start: Arc<Barrier>) -> Value {
    let hashes: Vec<ScriptHash> = addrs.iter().map(|a| script_hash(a)).collect();
    // Connect and fetch the catalog before the barrier, so the timings
    // below cover the queries only.
    let prep = async {
        client.connect().await?;
        client.fetch_catalog().await
    }
    .await;
    start.wait().await;
    let catalog = match prep {
        Ok(c) => c,
        Err(e) => return json!({"error": format!("connect: {e}")}),
    };

    let t = Instant::now();
    let full = client.sync(&hashes, None).await;
    let full_s = t.elapsed().as_secs_f64();

    let t = Instant::now();
    let delta = match client.compute_sync_plan(&catalog, Some(DELTA_FROM_HEIGHT)) {
        Ok(plan) if !plan.is_fresh_sync && !plan.is_empty() => {
            let base = vec![None; hashes.len()];
            Some(client.sync_with_plan(&hashes, &plan, Some(&base)).await)
        }
        Ok(_) => None,
        Err(e) => Some(Err(e)),
    };
    let delta_s = t.elapsed().as_secs_f64();
    let _ = client.disconnect().await;

    json!({
        "addresses": addrs,
        "full_sync_s": full_s,
        "full": match &full { Ok(s) => sync_json(s, &addrs), Err(e) => json!({"error": e.to_string()}) },
        "delta_sync_s": delta.as_ref().map(|_| delta_s),
        "delta": match &delta {
            None => json!({"skipped": "catalog has no delta from 940611"}),
            Some(Ok(s)) => sync_json(s, &addrs),
            Some(Err(e)) => json!({"error": e.to_string()}),
        },
    })
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut concurrency = 1usize;
    let mut pos = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--concurrency" {
            concurrency = args[i + 1].parse().expect("--concurrency N");
            i += 2;
        } else {
            pos.push(args[i].clone());
            i += 1;
        }
    }
    let backend = pos.first().map(String::as_str).unwrap_or("");
    let urls: Vec<String> = pos.iter().skip(1).cloned().collect();
    match (backend, urls.len()) {
        ("dpf", 2) | ("onion", 1) => {}
        _ => {
            eprintln!("usage: bench_client dpf <s0> <s1> | onion <url>  [--concurrency N]");
            std::process::exit(2);
        }
    }

    let start = Arc::new(Barrier::new(concurrency));
    let t = Instant::now();
    let mut tasks = Vec::new();
    for c in 0..concurrency {
        let addrs: Vec<&'static str> = if concurrency == 1 {
            ADDRESSES.to_vec()
        } else {
            vec![ADDRESSES[c % ADDRESSES.len()]]
        };
        let start = Arc::clone(&start);
        let urls = urls.clone();
        let backend = backend.to_string();
        tasks.push(tokio::spawn(async move {
            if backend == "dpf" {
                run_one(DpfClient::new(&urls[0], &urls[1]), addrs, start).await
            } else {
                run_one(OnionClient::new(&urls[0]), addrs, start).await
            }
        }));
    }
    let mut clients = Vec::new();
    for task in tasks {
        clients.push(task.await.unwrap_or_else(|e| json!({"error": format!("task: {e}")})));
    }
    let out = json!({
        "backend": backend,
        "concurrency": concurrency,
        "wall_s": t.elapsed().as_secs_f64(),
        "clients": clients,
    });
    println!("{out}");
}
