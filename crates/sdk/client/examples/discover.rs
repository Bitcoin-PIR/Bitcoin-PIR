//! Read the BitcoinPIR service directory and print what a client would see
//! (docs/DIRECTORY_PROTOCOL.md). Loads no key and connects to no provider.
//!
//! Usage:
//!   cargo run -p pir-sdk-client --example discover -- \
//!     --directory-pubkey-hex HEX \
//!     --relay wss://relay-one.example [--relay wss://relay-two.example ...] \
//!     [--centralized-single-relay] [--floors FILE] [--timeout-ms 10000]
//!
//! The production directory is one relay, `wss://directory.bitcoinpir.org`,
//! in centralized mode; its publisher key is `PRODUCTION_DIRECTORY` in
//! `web/src/production-providers.ts`. Strict mode (the default) takes two to
//! eight distinct relays and compares their views. `--floors FILE` keeps the
//! rollback floors between runs (read before, written after). Exit status 1
//! when no shard was accepted.

use std::time::Duration;

use pir_sdk_client::directory::{
    discover_directory_v1, DirectoryConfigV1, DirectoryRelayModeV1, DirectoryRollbackFloorsV1,
    DIRECTORY_DEFAULT_TIMEOUT_V1,
};

const USAGE: &str = "usage: discover --directory-pubkey-hex HEX --relay URL [--relay URL ...] \
[--centralized-single-relay] [--floors FILE] [--timeout-ms MS]";

struct Args {
    config: DirectoryConfigV1,
    floors: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = std::env::args().skip(1);
    let mut relays = Vec::new();
    let mut key = None;
    let mut mode = DirectoryRelayModeV1::StrictMultiRelay;
    let mut floors = None;
    let mut timeout = DIRECTORY_DEFAULT_TIMEOUT_V1;
    while let Some(arg) = args.next() {
        let mut value = |name: &str| args.next().ok_or_else(|| format!("{name} needs a value"));
        match arg.as_str() {
            "--relay" => relays.push(value("--relay")?),
            "--directory-pubkey-hex" => {
                let hex = value("--directory-pubkey-hex")?;
                let bytes = hex::decode(&hex).map_err(|error| format!("directory key: {error}"))?;
                key = Some(
                    <[u8; 32]>::try_from(bytes)
                        .map_err(|_| "directory key must be 32 bytes".to_owned())?,
                );
            }
            "--centralized-single-relay" => mode = DirectoryRelayModeV1::CentralizedSingleRelay,
            "--floors" => floors = Some(value("--floors")?),
            "--timeout-ms" => {
                let ms: u64 = value("--timeout-ms")?
                    .parse()
                    .map_err(|_| "--timeout-ms takes milliseconds".to_owned())?;
                timeout = Duration::from_millis(ms);
            }
            "--help" | "-h" => return Err(USAGE.to_owned()),
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }
    Ok(Args {
        config: DirectoryConfigV1 {
            mode,
            relays,
            directory_pubkey: key
                .ok_or_else(|| format!("--directory-pubkey-hex is required\n{USAGE}"))?,
            timeout,
        },
        floors,
    })
}

fn read_floors(path: Option<&str>) -> Result<DirectoryRollbackFloorsV1, String> {
    match path.map(std::fs::read_to_string) {
        Some(Ok(json)) => {
            serde_json::from_str(&json).map_err(|error| format!("floors file: {error}"))
        }
        Some(Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(DirectoryRollbackFloorsV1::default())
        }
        Some(Err(error)) => Err(format!("floors file: {error}")),
        None => Ok(DirectoryRollbackFloorsV1::default()),
    }
}

#[tokio::main]
async fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    };
    let floors = match read_floors(args.floors.as_deref()) {
        Ok(floors) => floors,
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before 1970")
        .as_secs();
    let found = match discover_directory_v1(&args.config, floors, now).await {
        Ok(found) => found,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    };
    // The floors are stored before anything reads the catalog.
    if let Some(path) = &args.floors {
        if let Err(error) = std::fs::write(
            path,
            serde_json::to_string(&found.catalog.state).expect("floors serialize"),
        ) {
            eprintln!("floors file: {error}");
            std::process::exit(2);
        }
    }

    let catalog = &found.catalog;
    println!(
        "mode: {}{}",
        match found.mode {
            DirectoryRelayModeV1::StrictMultiRelay => "strict-multi-relay",
            DirectoryRelayModeV1::CentralizedSingleRelay => "centralized-single-relay",
        },
        if found.degraded { " (degraded)" } else { "" }
    );
    println!("relays with a complete view: {}", found.relays.join(", "));
    for failure in &found.unreachable {
        println!(
            "relay without a view: {} — {}",
            failure.relay, failure.reason
        );
    }
    println!(
        "shards accepted: {}/16, catalog valid until {}",
        catalog.shards.len(),
        catalog.valid_until
    );
    for shard in &catalog.shards {
        println!(
            "  shard {:x}: epoch {}, {} agreeing view(s)",
            shard.shard, shard.epoch, shard.views
        );
    }
    println!("entries: {}", catalog.entries.len());
    for entry in &catalog.entries {
        println!(
            "  {} (provider {}…, operator {}…, seq {}, valid until {}, {:?})",
            entry.server_id,
            &entry.provider_id[..16],
            &entry.operator_pubkey[..16],
            entry.directory_sequence,
            entry.valid_until,
            entry.health
        );
        for endpoint in &entry.endpoints {
            println!("    endpoint {endpoint}");
        }
        for hint in &entry.hints {
            println!(
                "    {:?}: {:?}, {:?}, attestation {:?}",
                hint.backend, hint.role, hint.access, hint.attestation
            );
        }
    }
    for rejection in &catalog.rejected {
        println!(
            "rejected: {} {}— {}",
            rejection
                .relay
                .map_or("all relays".to_owned(), |index| found.relays[index].clone()),
            rejection
                .shard
                .map_or(String::new(), |shard| format!("shard {shard:x} ")),
            rejection.reason
        );
    }
    if catalog.shards.is_empty() {
        std::process::exit(1);
    }
}
