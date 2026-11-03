//! Node announcements from the command line (docs/DIRECTORY_PROTOCOL.md
//! "Node announcements"). `announce` lists an operator's own node on the
//! relay's public lane. `announcements` reads every announcement a relay
//! holds, checks each node live the way a wallet does (REQ_ANNOUNCE identity,
//! GET_INFO_JSON role and access) and writes the nodes that pass as
//! `providers.tsv` lines with their assertion files, for
//! scripts/directory-publish.sh to sign into the directory. Neither command
//! loads the directory key.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Args;
use futures_util::{SinkExt, StreamExt};
use pir_directory_nostr::{
    node_announcements_req_json_v1, verify_node_announcement_event_v1, DirectoryAccessClassV1,
    DirectoryAttestationV1, DirectoryCatalogHintV1, DirectoryOperatorAssertionV1,
    DirectoryPublisherKeyV1, DirectoryServerRoleV1, NodeAnnouncementV1,
    MAX_DIRECTORY_ASSERTION_LEN_V1, MAX_NODE_ANNOUNCEMENT_EVENT_BYTES_V1,
    NODE_ANNOUNCEMENT_REQ_SUBSCRIPTION_V1,
};
use pir_sdk_client::announce::announce;
use pir_sdk_client::credit_transport::{Access, Backend};
use pir_sdk_client::WsConnection;
use serde::Deserialize;
use serde_json::value::RawValue;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

use crate::directory_artifact::{
    parse_backend_hints, read_public_bounded, write_output, AttestationArg, RoleArg,
};

/// The relay holds at most this many announcements.
const MAX_ANNOUNCEMENTS_READ: usize = 1_024;
const RELAY_TIMEOUT: Duration = Duration::from_secs(30);
const NODE_TIMEOUT: Duration = Duration::from_secs(20);
const REQ_GET_INFO_JSON: u8 = 0x03;

#[derive(Args, Debug)]
pub struct AnnounceArgs {
    /// The node's operator assertion (`directory-artifact assertion`).
    #[arg(long)]
    assertion: PathBuf,
    /// DPF slot the node runs as (`role` in its GET_INFO_JSON).
    #[arg(long, value_enum)]
    role: RoleArg,
    /// `BACKEND=ACCESS` the node serves, e.g. `dpf=best-effort`
    /// (`credits.access` in GET_INFO_JSON). Repeat per backend.
    #[arg(long = "backend", required = true)]
    backends: Vec<String>,
    /// The directory relay's public lane.
    #[arg(long, default_value = "wss://directory.bitcoinpir.org")]
    relay: String,
    #[arg(long)]
    now_unix: u64,
}

#[derive(Args, Debug)]
pub struct AnnouncementsArgs {
    /// The directory relay's public lane.
    #[arg(long, default_value = "wss://directory.bitcoinpir.org")]
    relay: String,
    /// Provider IDs already listed by hand; their announcements are skipped.
    #[arg(long = "skip-provider-id")]
    skip_provider_ids: Vec<String>,
    #[arg(long)]
    now_unix: u64,
    /// The previous run's `--out-dir` once it was published: the assertion
    /// each node was last listed with, and `<provider_id>.retired` for nodes
    /// dropped since. Absent on the first run.
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Receives `announced.tsv` and the next state: one
    /// `<provider_id>.assertion.bin` per node ever listed.
    #[arg(long)]
    out_dir: PathBuf,
}

/// Sign an announcement with a fresh one-off Nostr key (the operator identity
/// is the assertion inside) and send it to the relay's public lane.
pub async fn run_announce(args: AnnounceArgs) -> Result<(), String> {
    let assertion = read_assertion(&args.assertion)?;
    let hints = parse_backend_hints(
        &args.backends,
        args.role.into(),
        AttestationArg::None.into(),
    )?;
    let announcement = NodeAnnouncementV1::new(assertion, hints, args.now_unix)
        .map_err(|error| format!("announcement is not valid: {error}"))?;
    let key = DirectoryPublisherKeyV1::from_secret_bytes(random_32()?)
        .map_err(|error| format!("one-off Nostr key: {error}"))?;
    let event = key
        .sign_node_announcement_event(&announcement, args.now_unix, &random_32()?)
        .map_err(|error| format!("announcement signing failed: {error}"))?;
    let message = event
        .to_event_message_json_bytes()
        .map_err(|error| format!("announcement encoding failed: {error}"))?;
    let event_id = hex::encode(event.id());

    crate::directory_publish::install_default_crypto_provider();
    let (mut socket, _) = timeout(RELAY_TIMEOUT, tokio_tungstenite::connect_async(&args.relay))
        .await
        .map_err(|_| format!("{}: connect timed out", args.relay))?
        .map_err(|error| format!("{}: {error}", args.relay))?;
    let text = String::from_utf8(message).map_err(|_| "announcement is not UTF-8".to_owned())?;
    socket
        .send(Message::Text(text))
        .await
        .map_err(|error| format!("{}: send failed: {error}", args.relay))?;
    let reply = match timeout(RELAY_TIMEOUT, socket.next()).await {
        Ok(Some(Ok(Message::Text(reply)))) => reply,
        _ => return Err(format!("{}: no OK for the announcement", args.relay)),
    };
    let _ = socket.close(None).await;
    let (verb, id, accepted, note): (String, String, bool, String) =
        serde_json::from_str(&reply).map_err(|_| format!("unexpected relay reply: {reply}"))?;
    if verb != "OK" || id != event_id {
        return Err(format!("unexpected relay reply: {reply}"));
    }
    println!("provider_id={}", hex::encode(announcement.provider_id()));
    println!("event_id={event_id}");
    println!("relay_note={note}");
    if accepted {
        Ok(())
    } else {
        Err(format!("relay refused the announcement: {note}"))
    }
}

/// Read the relay's announcements, check each node live, and write the ones
/// that pass for the publisher. A node that fails is reported and left out;
/// one listed before is then marked retired (the script publishes its
/// tombstone).
pub async fn run_announcements(args: AnnouncementsArgs) -> Result<(), String> {
    crate::directory_publish::install_default_crypto_provider();
    let events = read_announcements(&args.relay).await?;
    std::fs::create_dir_all(&args.out_dir)
        .map_err(|error| format!("create {}: {error}", args.out_dir.display()))?;
    let previous = match &args.state_dir {
        Some(dir) => read_state(dir)?,
        None => BTreeMap::new(),
    };
    let mut tsv = String::new();
    let mut listed = BTreeSet::new();
    for event in events {
        let verified = match verify_node_announcement_event_v1(&event, args.now_unix) {
            Ok(verified) => verified,
            Err(error) => {
                eprintln!("skip: announcement does not verify: {error}");
                continue;
            }
        };
        let announcement = verified.announcement();
        let provider_id = hex::encode(announcement.provider_id());
        if args.skip_provider_ids.contains(&provider_id) || listed.contains(&provider_id) {
            continue;
        }
        let assertion = announcement.operator_assertion();
        let bytes = assertion.encode().map_err(|error| error.to_string())?;
        if let Err(reason) = check_epoch(previous.get(&provider_id), &bytes, assertion) {
            eprintln!("skip {provider_id}: {reason}");
            continue;
        }
        if let Err(reason) = check_node_live(announcement, args.now_unix).await {
            eprintln!("skip {provider_id}: {reason}");
            continue;
        }
        let assertion_path = args.out_dir.join(format!("{provider_id}.assertion.bin"));
        write_output(&assertion_path, &bytes, true)?;
        tsv.push_str(&providers_tsv_line(announcement, &assertion_path));
        println!("listed {provider_id} {}", assertion.endpoints[0].url);
        listed.insert(provider_id);
    }
    for (provider_id, (bytes, _)) in &previous {
        if listed.contains(provider_id) {
            continue;
        }
        write_output(
            &args.out_dir.join(format!("{provider_id}.assertion.bin")),
            bytes,
            true,
        )?;
        write_output(
            &args.out_dir.join(format!("{provider_id}.retired")),
            b"retired\n",
            true,
        )?;
    }
    write_output(&args.out_dir.join("announced.tsv"), tsv.as_bytes(), true)?;
    println!("announced_listed={}", listed.len());
    Ok(())
}

/// Assertion each node was last listed with, and whether it was dropped since.
fn read_state(dir: &Path) -> Result<BTreeMap<String, (Vec<u8>, bool)>, String> {
    let mut state = BTreeMap::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(state),
        Err(error) => return Err(format!("read {}: {error}", dir.display())),
    };
    for entry in entries {
        let path = entry.map_err(|error| error.to_string())?.path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        let Some(provider_id) = name.strip_suffix(".assertion.bin") else {
            continue;
        };
        let bytes = read_public_bounded(&path, MAX_DIRECTORY_ASSERTION_LEN_V1, "listed assertion")?;
        let retired = dir.join(format!("{provider_id}.retired")).exists();
        state.insert(provider_id.to_owned(), (bytes, retired));
    }
    Ok(state)
}

/// Wallets keep each provider's highest assertion epoch: a new assertion
/// needs a higher epoch, the same epoch must be the same assertion, and a
/// node listed again after it was dropped needs a higher epoch.
fn check_epoch(
    previous: Option<&(Vec<u8>, bool)>,
    bytes: &[u8],
    assertion: &DirectoryOperatorAssertionV1,
) -> Result<(), String> {
    let Some((previous_bytes, retired)) = previous else {
        return Ok(());
    };
    let previous = DirectoryOperatorAssertionV1::decode(previous_bytes)
        .map_err(|error| format!("listed assertion: {error}"))?;
    if assertion.assertion_epoch > previous.assertion_epoch
        || (!retired && previous_bytes.as_slice() == bytes)
    {
        return Ok(());
    }
    Err(format!(
        "assertion_epoch must be above {} for a new assertion",
        previous.assertion_epoch
    ))
}

async fn read_announcements(relay: &str) -> Result<Vec<Vec<u8>>, String> {
    let (mut socket, _) = timeout(RELAY_TIMEOUT, tokio_tungstenite::connect_async(relay))
        .await
        .map_err(|_| format!("{relay}: connect timed out"))?
        .map_err(|error| format!("{relay}: {error}"))?;
    let req = node_announcements_req_json_v1().map_err(|error| error.to_string())?;
    let req = String::from_utf8(req).map_err(|_| "REQ is not UTF-8".to_owned())?;
    socket
        .send(Message::Text(req))
        .await
        .map_err(|error| format!("{relay}: send failed: {error}"))?;
    let mut events = Vec::new();
    loop {
        let text = match timeout(RELAY_TIMEOUT, socket.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => text,
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
            _ => return Err(format!("{relay}: announcements ended before EOSE")),
        };
        if text.len() > MAX_NODE_ANNOUNCEMENT_EVENT_BYTES_V1 + 64 {
            return Err(format!("{relay}: oversized relay message"));
        }
        let parts: Vec<&RawValue> = serde_json::from_str(&text)
            .map_err(|_| format!("{relay}: unexpected relay message"))?;
        let verb: &str = parts
            .first()
            .and_then(|verb| serde_json::from_str(verb.get()).ok())
            .ok_or_else(|| format!("{relay}: unexpected relay message"))?;
        let subscription: Option<&str> = parts
            .get(1)
            .and_then(|value| serde_json::from_str(value.get()).ok());
        if subscription != Some(NODE_ANNOUNCEMENT_REQ_SUBSCRIPTION_V1) {
            return Err(format!("{relay}: reply for another subscription: {verb}"));
        }
        match (verb, parts.len()) {
            ("EVENT", 3) if events.len() < MAX_ANNOUNCEMENTS_READ => {
                events.push(parts[2].get().as_bytes().to_vec());
            }
            ("EOSE", 2) => break,
            _ => return Err(format!("{relay}: unexpected relay message: {verb}")),
        }
    }
    let _ = socket.close(None).await;
    Ok(events)
}

/// What a wallet checks before it trusts a directory entry: the node's
/// REQ_ANNOUNCE certificate names the asserted operator and `server_id`, and
/// its GET_INFO_JSON serves every announced backend with the same role and
/// access class. Announced nodes list without hardware attestation.
async fn check_node_live(announcement: &NodeAnnouncementV1, now_unix: u64) -> Result<(), String> {
    let assertion = announcement.operator_assertion();
    if announcement
        .catalog_hints()
        .iter()
        .any(|hint| hint.attestation != DirectoryAttestationV1::None)
    {
        return Err("announced nodes list with attestation none".to_owned());
    }
    let endpoint = &assertion.endpoints[0].url;
    let checks = async {
        let mut conn = WsConnection::connect(endpoint)
            .await
            .map_err(|error| format!("connect: {error}"))?;
        let identity = announce(&mut conn)
            .await
            .map_err(|error| format!("REQ_ANNOUNCE: {error}"))?;
        identity
            .check_pinned_operator(&assertion.operator_pubkey_ed25519, now_unix as i64)
            .map_err(|error| error.to_string())?;
        if identity.bundle.cert.server_id != assertion.stable_server_id {
            return Err("live server_id is not the asserted one".to_owned());
        }
        let info = conn
            .roundtrip(&[1, 0, 0, 0, REQ_GET_INFO_JSON])
            .await
            .map_err(|error| format!("GET_INFO_JSON: {error}"))?;
        let _ = conn.close().await;
        match info.split_first() {
            Some((&REQ_GET_INFO_JSON, json)) => check_live_info(announcement.catalog_hints(), json),
            _ => Err("GET_INFO_JSON: unexpected response".to_owned()),
        }
    };
    timeout(NODE_TIMEOUT, checks)
        .await
        .map_err(|_| format!("{endpoint}: timed out"))?
}

#[derive(Deserialize)]
struct LiveInfo {
    role: String,
    #[serde(default)]
    credits: Option<LiveCredits>,
}

#[derive(Deserialize)]
struct LiveCredits {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    required: bool,
    #[serde(default)]
    access: Option<pir_credit::PublishedAccess>,
}

/// The node's info JSON serves every hint's backend with its role and
/// access class, read as wallets read it (`resolveAccess` in web/src).
fn check_live_info(hints: &[DirectoryCatalogHintV1], json: &[u8]) -> Result<(), String> {
    let info: LiveInfo =
        serde_json::from_slice(json).map_err(|error| format!("GET_INFO_JSON: {error}"))?;
    let (published, required) = match &info.credits {
        Some(credits) => (credits.access.as_ref(), credits.enabled && credits.required),
        None => (None, false),
    };
    let policy = pir_credit::PublishedAccess::resolve(published, required);
    for hint in hints {
        if info.role != hint.role.name() {
            return Err(format!(
                "live role is {}, the announcement says {}",
                info.role,
                hint.role.name()
            ));
        }
        let backend = Backend::parse(hint.backend.name())
            .ok_or_else(|| format!("unknown backend {}", hint.backend.name()))?;
        let served = match policy.get(backend) {
            Access::Free => DirectoryAccessClassV1::Free,
            Access::Paid => DirectoryAccessClassV1::Paid,
            Access::BestEffort { .. } => DirectoryAccessClassV1::BestEffort,
        };
        if served != hint.access {
            return Err(format!(
                "live {} access is {}, the announcement says {}",
                hint.backend.name(),
                served.name(),
                hint.access.name()
            ));
        }
    }
    Ok(())
}

/// One `providers.tsv` line (scripts/directory-publish.sh): the name is the
/// provider ID, so the ledger keeps one sequence per node across runs.
fn providers_tsv_line(announcement: &NodeAnnouncementV1, assertion_path: &Path) -> String {
    let assertion = announcement.operator_assertion();
    let hints = announcement.catalog_hints();
    let backends = hints
        .iter()
        .map(|hint| format!("{}={}", hint.backend.name(), hint.access.name()))
        .collect::<Vec<_>>()
        .join(",");
    let role = hints
        .first()
        .map_or(DirectoryServerRoleV1::Primary, |hint| hint.role);
    let mut line = String::new();
    let _ = writeln!(
        line,
        "node-{}\t{}\t{}\t{}\tnone\t{}\t{}\t{}",
        hex::encode(announcement.provider_id()),
        assertion.stable_server_id,
        assertion.endpoints[0].url,
        role.name(),
        backends,
        assertion_path.display(),
        assertion.valid_until,
    );
    line
}

fn read_assertion(path: &Path) -> Result<DirectoryOperatorAssertionV1, String> {
    let bytes = read_public_bounded(path, MAX_DIRECTORY_ASSERTION_LEN_V1, "operator assertion")?;
    let assertion = DirectoryOperatorAssertionV1::decode(&bytes)
        .map_err(|error| format!("invalid operator assertion: {error}"))?;
    if assertion.encode().map_err(|error| error.to_string())? != bytes {
        return Err("operator assertion is not canonical".to_owned());
    }
    Ok(assertion)
}

fn random_32() -> Result<[u8; 32], String> {
    let mut value = [0u8; 32];
    getrandom::getrandom(&mut value).map_err(|error| format!("OS randomness: {error}"))?;
    Ok(value)
}

#[cfg(test)]
mod tests;
