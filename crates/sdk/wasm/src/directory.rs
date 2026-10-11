//! Browser verification of the Nostr service directory
//! (`docs/DIRECTORY_PROTOCOL.md`).
//!
//! JavaScript fetches the catalog: it sends the 16 shard `REQ`s from
//! [`directory_catalog_requests_v1`] to every configured relay and passes the
//! raw `EVENT` messages of each relay that reached `EOSE` on all of them to
//! [`verify_directory_catalog_v1`], together with the stored rollback floors.
//! Rust verifies each relay's view of each shard with `pir-directory-nostr`
//! (pinned-key NIP-01 signatures, replacement order, current validity,
//! rollback floors, exact checkpoint membership), compares the views of
//! different relays and returns the newest accepted view of every shard plus
//! the advanced floors, which the caller persists before using the catalog.
//! Each rejected view and shard is reported with its reason.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use pir_directory_nostr::{
    bind_persisted_directory_shard_catalog_v1, full_catalog_req_json_v1,
    nip01_addressable_replacement_order_v1, prepare_directory_checkpoint_acceptance_v1,
    prepare_directory_entry_acceptance_v1, verify_directory_checkpoint_event_v1,
    verify_directory_entry_event_v1, DirectoryCheckpointRollbackStateV1,
    DirectoryEntryRollbackStateV1, DirectoryErrorV1, DirectoryHealthClassV1, NostrEventV1,
    PersistedDirectoryEntryV1, VerifiedDirectoryCheckpointEventV1, VerifiedDirectoryEntryEventV1,
    DIRECTORY_CHECKPOINT_D_PREFIX_V1, DIRECTORY_REQ_SUBSCRIPTION_PREFIX_V1,
    DIRECTORY_SHARD_COUNT_V1,
};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use wasm_bindgen::prelude::*;

const SHARDS: usize = DIRECTORY_SHARD_COUNT_V1 as usize;

/// The 16 NIP-01 `REQ` messages of a full catalog refresh, byte-exact as the
/// directory relay profile expects them (`authors`, `kinds`, `#s`).
#[wasm_bindgen(js_name = directoryCatalogRequestsV1)]
pub fn directory_catalog_requests_v1(directory_pubkey: &[u8]) -> Result<Vec<String>, JsError> {
    catalog_requests(directory_pubkey).map_err(|error| JsError::new(&error))
}

/// Verify complete relay views of the catalog. `relays_json` is one JSON
/// array of raw `EVENT` message strings per relay; `state_json` the floors a
/// previous call returned (absent on first use). Returns the catalog JSON:
/// `{ validUntil, shards, entries, rejected, state }`.
#[wasm_bindgen(js_name = verifyDirectoryCatalogV1)]
pub fn verify_directory_catalog_v1(
    relays_json: &str,
    state_json: Option<String>,
    directory_pubkey: &[u8],
    now_unix: u64,
) -> Result<String, JsError> {
    verify_catalog_json(
        relays_json,
        state_json.as_deref(),
        directory_pubkey,
        now_unix,
    )
    .map_err(|error| JsError::new(&error))
}

/// Rollback floors as the browser stores them: the codec's encoded state per
/// provider id and per shard, in hex. No relay, mode or selection field.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RollbackFloorsV1 {
    entries: BTreeMap<String, String>,
    checkpoints: BTreeMap<u8, String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CatalogV1 {
    /// Earliest expiry over the accepted shards' checkpoints and entries,
    /// tombstones included; 0 when no shard was accepted.
    valid_until: u64,
    shards: Vec<CatalogShardV1>,
    /// Active entries of the accepted shards, by provider id.
    entries: Vec<CatalogEntryV1>,
    rejected: Vec<CatalogRejectionV1>,
    /// The floors after this refresh; persist them before using the catalog.
    state: RollbackFloorsV1,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CatalogShardV1 {
    shard: u8,
    epoch: u64,
    /// Relay views that returned exactly this checkpoint.
    views: usize,
    event_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CatalogEntryV1 {
    provider_id: String,
    event_id: String,
    directory_sequence: u64,
    valid_until: u64,
    server_id: String,
    operator_pubkey: String,
    endpoints: Vec<String>,
    health: &'static str,
    hints: Vec<CatalogHintV1>,
}

#[derive(Debug, Serialize)]
struct CatalogHintV1 {
    backend: &'static str,
    role: &'static str,
    access: &'static str,
    attestation: &'static str,
}

#[derive(Debug, Serialize)]
struct CatalogRejectionV1 {
    /// Index of the relay view; `None` for a whole shard.
    relay: Option<usize>,
    shard: Option<u8>,
    reason: String,
}

/// One relay's verified view of one shard.
struct ShardViewV1 {
    checkpoint: VerifiedDirectoryCheckpointEventV1,
    entries: Vec<VerifiedDirectoryEntryEventV1>,
}

/// A shard view that passed the floors and the checkpoint membership.
struct AcceptedViewV1 {
    epoch: u64,
    /// Catalog root and event id of the checkpoint.
    checkpoint: ([u8; 32], [u8; 32]),
    valid_until: u64,
    entries: Vec<CatalogEntryV1>,
    checkpoint_floor: Vec<u8>,
    entry_floors: Vec<([u8; 32], Vec<u8>)>,
}

fn catalog_requests(directory_pubkey: &[u8]) -> Result<Vec<String>, String> {
    full_catalog_req_json_v1(&directory_key(directory_pubkey)?)
        .map_err(reason)?
        .into_iter()
        .map(|request| String::from_utf8(request).map_err(reason))
        .collect()
}

fn verify_catalog_json(
    relays_json: &str,
    state_json: Option<&str>,
    directory_pubkey: &[u8],
    now_unix: u64,
) -> Result<String, String> {
    let key = directory_key(directory_pubkey)?;
    let relays: Vec<Vec<String>> = serde_json::from_str(relays_json)
        .map_err(|_| "relay views must be arrays of EVENT message strings".to_owned())?;
    let floors = match state_json {
        Some(json) => serde_json::from_str(json)
            .map_err(|_| "stored directory rollback floors are malformed".to_owned())?,
        None => RollbackFloorsV1::default(),
    };
    serde_json::to_string(&verify_catalog(&relays, floors, &key, now_unix)).map_err(reason)
}

fn verify_catalog(
    relays: &[Vec<String>],
    mut floors: RollbackFloorsV1,
    key: &[u8; 32],
    now_unix: u64,
) -> CatalogV1 {
    let mut rejected = Vec::new();
    let mut views: Vec<Vec<AcceptedViewV1>> = (0..SHARDS).map(|_| Vec::new()).collect();
    for (relay, messages) in relays.iter().enumerate() {
        let shards = match events_by_shard(messages) {
            Ok(shards) => shards,
            Err(reason) => {
                rejected.push(CatalogRejectionV1 {
                    relay: Some(relay),
                    shard: None,
                    reason,
                });
                continue;
            }
        };
        for (shard, events) in shards.iter().enumerate() {
            match verify_shard_view(events, shard as u8, key, now_unix)
                .and_then(|view| accept_view(view, &floors))
            {
                Ok(view) => views[shard].push(view),
                Err(reason) => rejected.push(CatalogRejectionV1 {
                    relay: Some(relay),
                    shard: Some(shard as u8),
                    reason,
                }),
            }
        }
    }

    let mut catalog = CatalogV1 {
        valid_until: u64::MAX,
        shards: Vec::new(),
        entries: Vec::new(),
        rejected,
        state: RollbackFloorsV1::default(),
    };
    for (shard, shard_views) in views.into_iter().enumerate() {
        let (view, agreeing) = match select_view(shard_views) {
            Ok(selected) => selected,
            Err(reason) => {
                catalog.rejected.push(CatalogRejectionV1 {
                    relay: None,
                    shard: Some(shard as u8),
                    reason,
                });
                continue;
            }
        };
        floors
            .checkpoints
            .insert(shard as u8, hex::encode(&view.checkpoint_floor));
        for (provider_id, floor) in &view.entry_floors {
            floors
                .entries
                .insert(hex::encode(provider_id), hex::encode(floor));
        }
        catalog.valid_until = catalog.valid_until.min(view.valid_until);
        catalog.shards.push(CatalogShardV1 {
            shard: shard as u8,
            epoch: view.epoch,
            views: agreeing,
            event_id: hex::encode(view.checkpoint.1),
        });
        catalog.entries.extend(view.entries);
    }
    if catalog.shards.is_empty() {
        catalog.valid_until = 0;
    }
    catalog.state = floors;
    catalog
}

/// Split one relay's `EVENT` messages by shard subscription, keeping each
/// event's exact JSON text for the verifier.
fn events_by_shard(messages: &[String]) -> Result<Vec<Vec<String>>, String> {
    let mut shards = vec![Vec::new(); SHARDS];
    for message in messages {
        let (command, subscription, event): (String, String, Box<RawValue>) =
            serde_json::from_str(message)
                .map_err(|_| "relay sent a malformed EVENT message".to_owned())?;
        let shard = (0..SHARDS)
            .find(|shard| {
                subscription == format!("{DIRECTORY_REQ_SUBSCRIPTION_PREFIX_V1}{shard:x}")
            })
            .filter(|_| command == "EVENT")
            .ok_or_else(|| "relay sent a message outside the catalog subscriptions".to_owned())?;
        shards[shard].push(event.get().to_owned());
    }
    Ok(shards)
}

/// The NIP-01 head of every coordinate among the events signed by the
/// pinned key, each head verified in full.
fn verify_shard_view(
    events: &[String],
    shard: u8,
    key: &[u8; 32],
    now_unix: u64,
) -> Result<ShardViewV1, String> {
    let mut heads: BTreeMap<String, (NostrEventV1, &str)> = BTreeMap::new();
    for raw in events {
        let event = NostrEventV1::parse_json(raw.as_bytes()).map_err(reason)?;
        event.verify_for_directory_key(key).map_err(reason)?;
        let d = match event.tags().first() {
            Some(tag) if tag.len() == 2 && tag[0] == "d" => tag[1].clone(),
            _ => return Err("directory event has no d tag".to_owned()),
        };
        let newer = match heads.get(&d) {
            Some((head, _)) => {
                nip01_addressable_replacement_order_v1(&event, head).map_err(reason)?
                    == Ordering::Greater
            }
            None => true,
        };
        if newer {
            heads.insert(d, (event, raw.as_str()));
        }
    }
    let mut checkpoint = None;
    let mut entries = Vec::new();
    for (d, (_, raw)) in heads {
        if d.starts_with(DIRECTORY_CHECKPOINT_D_PREFIX_V1) {
            let verified = verify_directory_checkpoint_event_v1(raw.as_bytes(), key, now_unix)
                .map_err(reason)?;
            if verified.checkpoint().shard() != shard {
                return Err("relay returned a checkpoint of another shard".to_owned());
            }
            checkpoint = Some(verified);
        } else {
            entries.push(
                verify_directory_entry_event_v1(raw.as_bytes(), key, now_unix).map_err(reason)?,
            );
        }
    }
    Ok(ShardViewV1 {
        checkpoint: checkpoint.ok_or_else(|| "relay returned no checkpoint".to_owned())?,
        entries,
    })
}

/// Check one shard view against the stored floors and the checkpoint's exact
/// entry set, and compute the advanced floors. The floors are confirmed here
/// because the caller persists the returned state before using the catalog.
fn accept_view(view: ShardViewV1, floors: &RollbackFloorsV1) -> Result<AcceptedViewV1, String> {
    let shard = view.checkpoint.checkpoint().shard();
    let current = floors
        .checkpoints
        .get(&shard)
        .map(|floor| decode_floor(floor, DirectoryCheckpointRollbackStateV1::decode))
        .transpose()?;
    let checkpoint = prepare_directory_checkpoint_acceptance_v1(view.checkpoint, current.as_ref())
        .map_err(reason)?;
    let checkpoint_floor = checkpoint.proposed_state().encode().map_err(reason)?;
    let checkpoint = checkpoint
        .confirm_durable_state(&checkpoint_floor)
        .map_err(reason)?;

    let mut entries = Vec::with_capacity(view.entries.len());
    let mut entry_floors = Vec::with_capacity(view.entries.len());
    for entry in view.entries {
        let provider_id = *entry.discovery_entry().provider_id();
        let current = floors
            .entries
            .get(&hex::encode(provider_id))
            .map(|floor| decode_floor(floor, DirectoryEntryRollbackStateV1::decode))
            .transpose()?;
        let entry =
            prepare_directory_entry_acceptance_v1(entry, current.as_ref()).map_err(reason)?;
        let floor = entry.proposed_state().encode().map_err(reason)?;
        entries.push(entry.confirm_durable_state(&floor).map_err(reason)?);
        entry_floors.push((provider_id, floor));
    }

    let catalog =
        bind_persisted_directory_shard_catalog_v1(&checkpoint, &entries).map_err(reason)?;
    let committed = checkpoint.verified().checkpoint();
    Ok(AcceptedViewV1 {
        epoch: committed.checkpoint_epoch(),
        checkpoint: (
            *committed.catalog_root(),
            *checkpoint.verified().event().id(),
        ),
        valid_until: entries
            .iter()
            .map(|entry| entry.verified().discovery_entry().directory_valid_until())
            .fold(committed.valid_until(), u64::min),
        entries: catalog.active_entries().filter_map(catalog_entry).collect(),
        checkpoint_floor,
        entry_floors,
    })
}

/// The newest accepted view of a shard and how many relay views returned it.
/// Two views at one epoch with different checkpoints mean the publisher
/// signed a split view: the shard is rejected.
fn select_view(views: Vec<AcceptedViewV1>) -> Result<(AcceptedViewV1, usize), String> {
    for (index, view) in views.iter().enumerate() {
        if views[index + 1..]
            .iter()
            .any(|other| other.epoch == view.epoch && other.checkpoint != view.checkpoint)
        {
            return Err(format!(
                "relays returned different checkpoints at epoch {} (split view)",
                view.epoch
            ));
        }
    }
    let newest = views.iter().map(|view| view.epoch).max().unwrap_or(0);
    let mut newest: Vec<AcceptedViewV1> = views
        .into_iter()
        .filter(|view| view.epoch == newest)
        .collect();
    let agreeing = newest.len();
    newest
        .pop()
        .map(|view| (view, agreeing))
        .ok_or_else(|| "no relay returned a valid view of this shard".to_owned())
}

fn catalog_entry(persisted: &PersistedDirectoryEntryV1) -> Option<CatalogEntryV1> {
    let verified = persisted.verified();
    let entry = verified.discovery_entry();
    let assertion = entry.operator_assertion()?;
    Some(CatalogEntryV1 {
        provider_id: hex::encode(entry.provider_id()),
        event_id: hex::encode(verified.event().id()),
        directory_sequence: entry.directory_sequence(),
        valid_until: entry.directory_valid_until(),
        server_id: assertion.stable_server_id.clone(),
        operator_pubkey: hex::encode(assertion.operator_pubkey_ed25519),
        endpoints: assertion
            .endpoints
            .iter()
            .map(|endpoint| endpoint.url.clone())
            .collect(),
        health: match entry.health().class {
            DirectoryHealthClassV1::Unknown => "unknown",
            DirectoryHealthClassV1::Available => "available",
            DirectoryHealthClassV1::Degraded => "degraded",
            DirectoryHealthClassV1::Unavailable => "unavailable",
        },
        hints: entry
            .catalog_hints()
            .iter()
            .map(|hint| CatalogHintV1 {
                backend: hint.backend.name(),
                role: hint.role.name(),
                access: hint.access.name(),
                attestation: hint.attestation.name(),
            })
            .collect(),
    })
}

fn decode_floor<T>(
    floor: &str,
    decode: fn(&[u8]) -> Result<T, DirectoryErrorV1>,
) -> Result<T, String> {
    let bytes =
        hex::decode(floor).map_err(|_| "stored directory rollback floor is not hex".to_owned())?;
    decode(&bytes).map_err(reason)
}

fn directory_key(bytes: &[u8]) -> Result<[u8; 32], String> {
    bytes
        .try_into()
        .map_err(|_| "directory public key must be 32 bytes".to_owned())
}

fn reason(error: impl core::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests;
