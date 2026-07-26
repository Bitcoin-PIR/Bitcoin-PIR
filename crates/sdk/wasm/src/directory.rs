//! Browser-facing Nostr directory verifier.
//!
//! JavaScript owns only relay I/O and encrypted IndexedDB transactions. Raw
//! NIP-01 EVENT messages reach this module unchanged so duplicate JSON fields
//! cannot be normalized away before Rust authenticates them. A catalog stays
//! inaccessible until the browser reads back the exact rollback states after
//! its durable CAS transaction. With no independent operator pin, the pinned
//! directory key is still the curatorial/Sybil trust root for discovered
//! identities/endpoints; exported operator and policy keys must be closed
//! against the live strict identity and service-policy verification paths.

use core::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use pir_directory_nostr::{
    bind_persisted_directory_shard_catalog_v1, checkpoint_d_tag_value_v1,
    coarse_shard_for_provider_v1, entry_d_tag_value_v1, full_catalog_req_json_v1,
    nip01_addressable_replacement_order_v1, prepare_directory_checkpoint_acceptance_v1,
    prepare_directory_entry_acceptance_v1, shard_tag_value_v1,
    verify_directory_checkpoint_event_v1, verify_directory_entry_event_v1,
    DirectoryCheckpointRollbackStateV1, DirectoryEntryRollbackStateV1, DirectoryEntryStatusV1,
    NostrEventV1, PersistedDirectoryCheckpointV1, PersistedDirectoryEntryV1,
    UnpersistedDirectoryCheckpointV1, UnpersistedDirectoryEntryV1,
    VerifiedDirectoryCheckpointEventV1, VerifiedDirectoryEntryEventV1,
    DIRECTORY_CHECKPOINT_D_PREFIX_V1, DIRECTORY_ENTRY_D_PREFIX_V1,
    DIRECTORY_REQ_SUBSCRIPTION_PREFIX_V1, DIRECTORY_SHARD_COUNT_V1,
    MAX_DIRECTORY_CHECKPOINT_ENTRIES_V1, MAX_NOSTR_EVENT_BYTES_V1,
};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use wasm_bindgen::prelude::*;

const MAX_RELAY_COUNT_V1: usize = 8;
const MAX_RELAY_BATCH_BYTES_V1: usize = 64 * 1024 * 1024;
const MAX_RELAY_EVENTS_V1: usize =
    (DIRECTORY_SHARD_COUNT_V1 as usize) * (MAX_DIRECTORY_CHECKPOINT_ENTRIES_V1 + 1);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RelayBatchInputV1 {
    version: u8,
    relays: Vec<RelayInputV1>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RelayInputV1 {
    relay_id: u32,
    event_messages: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CoordinateKindV1 {
    Entry,
    Checkpoint,
}

#[derive(Clone)]
struct EventCandidateV1 {
    raw_event: Vec<u8>,
    event: NostrEventV1,
    coordinate_kind: CoordinateKindV1,
    shard: u8,
}

#[derive(Clone, Debug)]
struct VerifiedRelayShardV1 {
    checkpoint: VerifiedDirectoryCheckpointEventV1,
    entries: Vec<VerifiedDirectoryEntryEventV1>,
}

struct PreparedEntryV1 {
    provider_id: [u8; 32],
    shard: u8,
    expected: Option<Vec<u8>>,
    successor: Vec<u8>,
    candidate: UnpersistedDirectoryEntryV1,
}

struct PreparedCheckpointV1 {
    shard: u8,
    expected: Option<Vec<u8>>,
    successor: Vec<u8>,
    candidate: UnpersistedDirectoryCheckpointV1,
}

struct PreparedCatalogV1 {
    entries: Vec<PreparedEntryV1>,
    checkpoints: Vec<PreparedCheckpointV1>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StateKeysOutputV1 {
    version: u8,
    directory_pubkey_hex: String,
    entries: Vec<String>,
    checkpoints: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StateEnvelopeV1 {
    version: u8,
    directory_pubkey_hex: String,
    entries: Vec<EntryStateV1>,
    checkpoints: Vec<CheckpointStateV1>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EntryStateV1 {
    provider_id_hex: String,
    state: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CheckpointStateV1 {
    shard: u8,
    state: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct RollbackPlanV1 {
    version: u8,
    directory_pubkey_hex: String,
    entries: Vec<EntryTransitionV1>,
    checkpoints: Vec<CheckpointTransitionV1>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct EntryTransitionV1 {
    provider_id_hex: String,
    expected: Option<Vec<u8>>,
    successor: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CheckpointTransitionV1 {
    shard: u8,
    expected: Option<Vec<u8>>,
    successor: Vec<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SelectableCatalogV1 {
    version: u8,
    directory_pubkey_hex: String,
    shards: Vec<SelectableShardV1>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SelectableShardV1 {
    shard: u8,
    checkpoint_epoch: String,
    checkpoint_root_hex: String,
    entries: Vec<SelectableEntryV1>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SelectableEntryV1 {
    provider_id_hex: String,
    event_id_hex: String,
    directory_sequence: String,
    directory_valid_until: String,
    operator_pubkey_ed25519_hex: String,
    stable_server_id: String,
    policy_signing_key_ed25519_hex: String,
    assertion_epoch: String,
    policy_epoch: String,
    policy_digest_hex: String,
    entry: serde_json::Value,
}

/// Verified relay result plus a persist-before-select state transition.
#[wasm_bindgen]
pub struct WasmDirectoryCatalogCandidateV1 {
    directory_pubkey: [u8; 32],
    shards: Vec<VerifiedRelayShardV1>,
    prepared: Option<PreparedCatalogV1>,
    selectable_catalog_json: Option<String>,
}

#[wasm_bindgen]
impl WasmDirectoryCatalogCandidateV1 {
    /// Authenticate at least two complete relay views, enforce all 16 shards,
    /// and reject same-epoch checkpoint root/event forks.
    #[wasm_bindgen(js_name = verifyRelayCatalogs)]
    pub fn verify_relay_catalogs(
        relay_batch_json: &[u8],
        pinned_directory_pubkey: &[u8],
        now_unix: u64,
    ) -> Result<WasmDirectoryCatalogCandidateV1, JsError> {
        let directory_pubkey = fixed_nonzero_32(pinned_directory_pubkey, "directory pubkey")?;
        let shards = verify_relay_batch_v1(relay_batch_json, &directory_pubkey, now_unix)
            .map_err(|error| JsError::new(&error))?;
        Ok(Self {
            directory_pubkey,
            shards,
            prepared: None,
            selectable_catalog_json: None,
        })
    }

    /// Exact rollback keys needed for this refresh. No provider pair, query,
    /// payment or relay URL is included.
    #[wasm_bindgen(js_name = stateKeysJson)]
    pub fn state_keys_json(&self) -> Result<String, JsError> {
        let mut providers = self
            .shards
            .iter()
            .flat_map(|shard| shard.entries.iter())
            .map(|entry| hex::encode(entry.discovery_entry().provider_id()))
            .collect::<Vec<_>>();
        providers.sort();
        providers.dedup();
        serde_json::to_string(&StateKeysOutputV1 {
            version: 1,
            directory_pubkey_hex: hex::encode(self.directory_pubkey),
            entries: providers,
            checkpoints: (0..DIRECTORY_SHARD_COUNT_V1).collect(),
        })
        .map_err(js_error)
    }

    /// Verify current durable rollback bytes and create an exact CAS plan.
    /// This does not make any directory entry selectable.
    #[wasm_bindgen(js_name = prepareRollback)]
    pub fn prepare_rollback(&mut self, current_state_json: &[u8]) -> Result<String, JsError> {
        if self.prepared.is_some() || self.selectable_catalog_json.is_some() {
            return Err(JsError::new(
                "directory rollback transition already prepared",
            ));
        }
        let current = parse_state_envelope(current_state_json, &self.directory_pubkey)?;
        let mut entry_states = BTreeMap::new();
        for row in current.entries {
            let provider_id = decode_hex_32(&row.provider_id_hex, "provider id")?;
            if entry_states.insert(provider_id, row.state).is_some() {
                return Err(JsError::new("duplicate directory entry rollback state"));
            }
        }
        let mut checkpoint_states = BTreeMap::new();
        for row in current.checkpoints {
            if row.shard >= DIRECTORY_SHARD_COUNT_V1
                || checkpoint_states.insert(row.shard, row.state).is_some()
            {
                return Err(JsError::new(
                    "duplicate or invalid checkpoint rollback state",
                ));
            }
        }

        let selected_providers = self
            .shards
            .iter()
            .flat_map(|shard| shard.entries.iter())
            .map(|entry| *entry.discovery_entry().provider_id())
            .collect::<BTreeSet<_>>();
        if entry_states
            .keys()
            .any(|key| !selected_providers.contains(key))
            || checkpoint_states
                .keys()
                .any(|shard| *shard >= DIRECTORY_SHARD_COUNT_V1)
        {
            return Err(JsError::new(
                "directory rollback state contains an unrequested key",
            ));
        }

        let mut prepared_entries = Vec::new();
        let mut prepared_checkpoints = Vec::with_capacity(DIRECTORY_SHARD_COUNT_V1 as usize);
        for shard in &self.shards {
            let shard_id = shard.checkpoint.checkpoint().shard();
            let checkpoint_expected = checkpoint_states.remove(&shard_id);
            let checkpoint_current = checkpoint_expected
                .as_deref()
                .map(DirectoryCheckpointRollbackStateV1::decode)
                .transpose()
                .map_err(js_error)?;
            let checkpoint_candidate = prepare_directory_checkpoint_acceptance_v1(
                shard.checkpoint.clone(),
                checkpoint_current.as_ref(),
            )
            .map_err(js_error)?;
            let checkpoint_successor = checkpoint_candidate
                .proposed_state()
                .encode()
                .map_err(js_error)?;
            prepared_checkpoints.push(PreparedCheckpointV1 {
                shard: shard_id,
                expected: checkpoint_expected,
                successor: checkpoint_successor,
                candidate: checkpoint_candidate,
            });

            for entry in &shard.entries {
                let provider_id = *entry.discovery_entry().provider_id();
                let expected = entry_states.remove(&provider_id);
                let current = expected
                    .as_deref()
                    .map(DirectoryEntryRollbackStateV1::decode)
                    .transpose()
                    .map_err(js_error)?;
                let candidate =
                    prepare_directory_entry_acceptance_v1(entry.clone(), current.as_ref())
                        .map_err(js_error)?;
                let successor = candidate.proposed_state().encode().map_err(js_error)?;
                prepared_entries.push(PreparedEntryV1 {
                    provider_id,
                    shard: shard_id,
                    expected,
                    successor,
                    candidate,
                });
            }
        }
        if !entry_states.is_empty() || !checkpoint_states.is_empty() {
            return Err(JsError::new(
                "directory rollback state was not fully consumed",
            ));
        }
        prepared_entries.sort_by_key(|entry| entry.provider_id);
        prepared_checkpoints.sort_by_key(|checkpoint| checkpoint.shard);
        let plan = RollbackPlanV1 {
            version: 1,
            directory_pubkey_hex: hex::encode(self.directory_pubkey),
            entries: prepared_entries
                .iter()
                .map(|entry| EntryTransitionV1 {
                    provider_id_hex: hex::encode(entry.provider_id),
                    expected: entry.expected.clone(),
                    successor: entry.successor.clone(),
                })
                .collect(),
            checkpoints: prepared_checkpoints
                .iter()
                .map(|checkpoint| CheckpointTransitionV1 {
                    shard: checkpoint.shard,
                    expected: checkpoint.expected.clone(),
                    successor: checkpoint.successor.clone(),
                })
                .collect(),
        };
        let encoded = serde_json::to_string(&plan).map_err(js_error)?;
        self.prepared = Some(PreparedCatalogV1 {
            entries: prepared_entries,
            checkpoints: prepared_checkpoints,
        });
        Ok(encoded)
    }

    /// Release the selectable catalog only after the durable adapter returns
    /// the exact post-CAS bytes for every entry and all 16 checkpoints.
    #[wasm_bindgen(js_name = acknowledgePersisted)]
    pub fn acknowledge_persisted(&mut self, durable_state_json: &[u8]) -> Result<(), JsError> {
        if self.selectable_catalog_json.is_some() {
            return Err(JsError::new(
                "directory catalog was already made selectable",
            ));
        }
        let durable = parse_state_envelope(durable_state_json, &self.directory_pubkey)?;
        let prepared = self
            .prepared
            .as_ref()
            .ok_or_else(|| JsError::new("prepare directory rollback before acknowledging it"))?;
        let observed_entries = unique_entry_state_map(durable.entries)?;
        let observed_checkpoints = unique_checkpoint_state_map(durable.checkpoints)?;
        if observed_entries.len() != prepared.entries.len()
            || observed_checkpoints.len() != prepared.checkpoints.len()
            || prepared
                .entries
                .iter()
                .any(|entry| observed_entries.get(&entry.provider_id) != Some(&entry.successor))
            || prepared.checkpoints.iter().any(|checkpoint| {
                observed_checkpoints.get(&checkpoint.shard) != Some(&checkpoint.successor)
            })
        {
            return Err(JsError::new(
                "durable directory rollback readback did not match the CAS successor",
            ));
        }

        let prepared = self.prepared.take().expect("checked above");
        let mut persisted_entries_by_shard = (0..DIRECTORY_SHARD_COUNT_V1)
            .map(|_| Vec::<PersistedDirectoryEntryV1>::new())
            .collect::<Vec<_>>();
        for entry in prepared.entries {
            let observed = observed_entries
                .get(&entry.provider_id)
                .expect("validated above");
            let persisted = entry
                .candidate
                .confirm_durable_state(observed)
                .map_err(js_error)?;
            persisted_entries_by_shard[usize::from(entry.shard)].push(persisted);
        }
        let mut persisted_checkpoints = (0..DIRECTORY_SHARD_COUNT_V1)
            .map(|_| None)
            .collect::<Vec<Option<PersistedDirectoryCheckpointV1>>>();
        for checkpoint in prepared.checkpoints {
            let observed = observed_checkpoints
                .get(&checkpoint.shard)
                .expect("validated above");
            persisted_checkpoints[usize::from(checkpoint.shard)] = Some(
                checkpoint
                    .candidate
                    .confirm_durable_state(observed)
                    .map_err(js_error)?,
            );
        }

        let mut selectable_shards = Vec::with_capacity(DIRECTORY_SHARD_COUNT_V1 as usize);
        for shard in 0..DIRECTORY_SHARD_COUNT_V1 {
            let checkpoint = persisted_checkpoints[usize::from(shard)]
                .as_ref()
                .ok_or_else(|| JsError::new("durable catalog is missing a checkpoint"))?;
            let entries = &persisted_entries_by_shard[usize::from(shard)];
            let catalog =
                bind_persisted_directory_shard_catalog_v1(checkpoint, entries).map_err(js_error)?;
            let mut selectable_entries = Vec::new();
            for persisted in catalog.active_entries() {
                let verified = persisted.verified();
                let discovery = verified.discovery_entry();
                debug_assert_eq!(discovery.status(), DirectoryEntryStatusV1::Active);
                let assertion = discovery
                    .operator_assertion()
                    .ok_or_else(|| JsError::new("active directory entry lost its assertion"))?;
                let canonical = discovery.canonical_json_bytes().map_err(js_error)?;
                let entry_value = serde_json::from_slice(&canonical).map_err(js_error)?;
                selectable_entries.push(SelectableEntryV1 {
                    provider_id_hex: hex::encode(discovery.provider_id()),
                    event_id_hex: hex::encode(verified.event().id()),
                    directory_sequence: discovery.directory_sequence().to_string(),
                    directory_valid_until: discovery.directory_valid_until().to_string(),
                    operator_pubkey_ed25519_hex: hex::encode(assertion.operator_pubkey_ed25519),
                    stable_server_id: assertion.stable_server_id.clone(),
                    policy_signing_key_ed25519_hex: hex::encode(
                        assertion.policy_signing_key_ed25519,
                    ),
                    assertion_epoch: assertion.assertion_epoch.to_string(),
                    policy_epoch: assertion.policy_epoch.to_string(),
                    policy_digest_hex: hex::encode(assertion.policy_digest),
                    entry: entry_value,
                });
            }
            selectable_entries
                .sort_by(|left, right| left.provider_id_hex.cmp(&right.provider_id_hex));
            selectable_shards.push(SelectableShardV1 {
                shard,
                checkpoint_epoch: checkpoint
                    .verified()
                    .checkpoint()
                    .checkpoint_epoch()
                    .to_string(),
                checkpoint_root_hex: hex::encode(checkpoint.verified().checkpoint().catalog_root()),
                entries: selectable_entries,
            });
        }
        self.selectable_catalog_json = Some(
            serde_json::to_string(&SelectableCatalogV1 {
                version: 1,
                directory_pubkey_hex: hex::encode(self.directory_pubkey),
                shards: selectable_shards,
            })
            .map_err(js_error)?,
        );
        Ok(())
    }

    #[wasm_bindgen(js_name = selectableCatalogJson)]
    pub fn selectable_catalog_json(&self) -> Result<String, JsError> {
        self.selectable_catalog_json
            .clone()
            .ok_or_else(|| JsError::new("directory catalog is not durably accepted"))
    }
}

/// Exact 16-shard REQ messages from the transport-neutral protocol crate.
#[wasm_bindgen(js_name = directoryFullCatalogReqJsonV1)]
pub fn directory_full_catalog_req_json_v1(
    pinned_directory_pubkey: &[u8],
) -> Result<String, JsError> {
    let directory_pubkey = fixed_nonzero_32(pinned_directory_pubkey, "directory pubkey")?;
    let requests = full_catalog_req_json_v1(&directory_pubkey).map_err(js_error)?;
    let values = requests
        .iter()
        .map(|request| serde_json::from_slice::<serde_json::Value>(request))
        .collect::<Result<Vec<_>, _>>()
        .map_err(js_error)?;
    serde_json::to_string(&values).map_err(js_error)
}

fn verify_relay_batch_v1(
    relay_batch_json: &[u8],
    directory_pubkey: &[u8; 32],
    now_unix: u64,
) -> Result<Vec<VerifiedRelayShardV1>, String> {
    if relay_batch_json.is_empty()
        || relay_batch_json.len() > MAX_RELAY_BATCH_BYTES_V1
        || now_unix == 0
    {
        return Err("directory relay batch is empty, oversized, or has no trusted time".to_owned());
    }
    let input: RelayBatchInputV1 =
        serde_json::from_slice(relay_batch_json).map_err(|_| "invalid relay batch JSON")?;
    if input.version != 1 || input.relays.len() < 2 || input.relays.len() > MAX_RELAY_COUNT_V1 {
        return Err("directory refresh requires two to eight complete relays".to_owned());
    }
    let mut relay_ids = BTreeSet::new();
    let mut relays = Vec::with_capacity(input.relays.len());
    for relay in input.relays {
        if !relay_ids.insert(relay.relay_id)
            || relay.event_messages.len() < DIRECTORY_SHARD_COUNT_V1 as usize
            || relay.event_messages.len() > MAX_RELAY_EVENTS_V1
        {
            return Err("relay catalog identifier/count is invalid".to_owned());
        }
        relays.push(verify_one_relay_v1(
            relay.event_messages,
            directory_pubkey,
            now_unix,
        )?);
    }

    let mut selected = Vec::with_capacity(DIRECTORY_SHARD_COUNT_V1 as usize);
    for shard in 0..DIRECTORY_SHARD_COUNT_V1 {
        let mut epoch_views = BTreeMap::<u64, ([u8; 32], [u8; 32])>::new();
        let mut highest: Option<(u64, usize)> = None;
        for (relay_index, relay) in relays.iter().enumerate() {
            let checkpoint = relay[usize::from(shard)].checkpoint.checkpoint();
            let view = (
                *checkpoint.catalog_root(),
                *relay[usize::from(shard)].checkpoint.event().id(),
            );
            if let Some(previous) = epoch_views.insert(checkpoint.checkpoint_epoch(), view) {
                if previous != view {
                    return Err(format!(
                        "directory split view at shard {shard:x} epoch {}",
                        checkpoint.checkpoint_epoch()
                    ));
                }
            }
            if highest
                .map(|(epoch, _)| checkpoint.checkpoint_epoch() > epoch)
                .unwrap_or(true)
            {
                highest = Some((checkpoint.checkpoint_epoch(), relay_index));
            }
        }
        let (_, relay_index) = highest.ok_or_else(|| "missing relay checkpoint".to_owned())?;
        selected.push(relays[relay_index][usize::from(shard)].clone());
    }
    Ok(selected)
}

fn verify_one_relay_v1(
    event_messages: Vec<String>,
    directory_pubkey: &[u8; 32],
    now_unix: u64,
) -> Result<Vec<VerifiedRelayShardV1>, String> {
    let mut winners = BTreeMap::<String, EventCandidateV1>::new();
    for message in event_messages {
        if message.is_empty() || message.len() > MAX_NOSTR_EVENT_BYTES_V1 + 256 {
            return Err("relay EVENT message exceeds its V1 bound".to_owned());
        }
        let (command, subscription, raw_event): (String, String, Box<RawValue>) =
            serde_json::from_str(&message).map_err(|_| "malformed NIP-01 EVENT message")?;
        if command != "EVENT" {
            return Err("relay catalog contains a non-EVENT payload".to_owned());
        }
        let raw_event = raw_event.get().as_bytes().to_vec();
        let event = NostrEventV1::parse_json(&raw_event).map_err(|error| error.to_string())?;
        event
            .verify_for_directory_key(directory_pubkey)
            .map_err(|error| error.to_string())?;
        let (d, shard, coordinate_kind) = classify_event_coordinate_v1(&event)?;
        let expected_subscription = format!("{DIRECTORY_REQ_SUBSCRIPTION_PREFIX_V1}{shard:x}");
        if subscription != expected_subscription {
            return Err("relay EVENT was delivered under the wrong shard subscription".to_owned());
        }
        let candidate = EventCandidateV1 {
            raw_event,
            event,
            coordinate_kind,
            shard,
        };
        match winners.get(&d) {
            None => {
                winners.insert(d, candidate);
            }
            Some(current) => {
                if nip01_addressable_replacement_order_v1(&candidate.event, &current.event)
                    .map_err(|error| error.to_string())?
                    == Ordering::Greater
                {
                    winners.insert(d, candidate);
                }
            }
        }
    }

    let mut checkpoints = (0..DIRECTORY_SHARD_COUNT_V1)
        .map(|_| None)
        .collect::<Vec<Option<VerifiedDirectoryCheckpointEventV1>>>();
    let mut entries = (0..DIRECTORY_SHARD_COUNT_V1)
        .map(|_| Vec::<VerifiedDirectoryEntryEventV1>::new())
        .collect::<Vec<_>>();
    for winner in winners.into_values() {
        match winner.coordinate_kind {
            CoordinateKindV1::Entry => {
                let verified =
                    verify_directory_entry_event_v1(&winner.raw_event, directory_pubkey, now_unix)
                        .map_err(|error| error.to_string())?;
                if verified.shard() != winner.shard {
                    return Err("directory entry shard changed during verification".to_owned());
                }
                entries[usize::from(winner.shard)].push(verified);
            }
            CoordinateKindV1::Checkpoint => {
                let verified = verify_directory_checkpoint_event_v1(
                    &winner.raw_event,
                    directory_pubkey,
                    now_unix,
                )
                .map_err(|error| error.to_string())?;
                if verified.checkpoint().shard() != winner.shard
                    || checkpoints[usize::from(winner.shard)]
                        .replace(verified)
                        .is_some()
                {
                    return Err("relay returned duplicate or mismatched checkpoints".to_owned());
                }
            }
        }
    }

    let mut shards = Vec::with_capacity(DIRECTORY_SHARD_COUNT_V1 as usize);
    for shard in 0..DIRECTORY_SHARD_COUNT_V1 {
        let checkpoint = checkpoints[usize::from(shard)]
            .take()
            .ok_or_else(|| format!("relay omitted checkpoint for shard {shard:x}"))?;
        let mut shard_entries = core::mem::take(&mut entries[usize::from(shard)]);
        shard_entries.sort_by_key(|entry| *entry.discovery_entry().provider_id());
        if shard_entries.len() != checkpoint.checkpoint().entries().len() {
            return Err(format!("relay shard {shard:x} entry set is incomplete"));
        }
        for (entry, expected) in shard_entries.iter().zip(checkpoint.checkpoint().entries()) {
            if entry.discovery_entry().provider_id() != &expected.provider_id
                || entry.discovery_entry().directory_sequence() != expected.directory_sequence
                || entry.event().id() != &expected.event_id
            {
                return Err(format!(
                    "relay shard {shard:x} does not match its checkpoint"
                ));
            }
        }
        shards.push(VerifiedRelayShardV1 {
            checkpoint,
            entries: shard_entries,
        });
    }
    Ok(shards)
}

fn classify_event_coordinate_v1(
    event: &NostrEventV1,
) -> Result<(String, u8, CoordinateKindV1), String> {
    let tags = event.tags();
    if tags.len() != 2
        || tags[0].len() != 2
        || tags[0][0] != "d"
        || tags[1].len() != 2
        || tags[1][0] != "s"
    {
        return Err("directory event has unexpected profile tags".to_owned());
    }
    let d = tags[0][1].clone();
    let (shard, kind) = if let Some(provider_hex) = d.strip_prefix(DIRECTORY_ENTRY_D_PREFIX_V1) {
        let provider_id = decode_hex_32_string(provider_hex, "directory provider id")?;
        (
            coarse_shard_for_provider_v1(&provider_id),
            CoordinateKindV1::Entry,
        )
    } else if let Some(shard_hex) = d.strip_prefix(DIRECTORY_CHECKPOINT_D_PREFIX_V1) {
        if shard_hex.len() != 1 {
            return Err("directory checkpoint coordinate is malformed".to_owned());
        }
        let shard = u8::from_str_radix(shard_hex, 16)
            .map_err(|_| "directory checkpoint coordinate is malformed")?;
        if shard >= DIRECTORY_SHARD_COUNT_V1 || format!("{shard:x}") != shard_hex {
            return Err("directory checkpoint coordinate is non-canonical".to_owned());
        }
        (shard, CoordinateKindV1::Checkpoint)
    } else {
        return Err("relay returned an unknown directory coordinate".to_owned());
    };
    if tags[1][1] != shard_tag_value_v1(shard)
        || (kind == CoordinateKindV1::Checkpoint && d != checkpoint_d_tag_value_v1(shard))
        || (kind == CoordinateKindV1::Entry
            && d != entry_d_tag_value_v1(&decode_hex_32_string(
                d.strip_prefix(DIRECTORY_ENTRY_D_PREFIX_V1)
                    .expect("classified entry"),
                "directory provider id",
            )?))
    {
        return Err("directory event shard/profile coordinate is inconsistent".to_owned());
    }
    Ok((d, shard, kind))
}

fn parse_state_envelope(
    bytes: &[u8],
    expected_directory_pubkey: &[u8; 32],
) -> Result<StateEnvelopeV1, JsError> {
    let envelope: StateEnvelopeV1 = serde_json::from_slice(bytes)
        .map_err(|_| JsError::new("directory rollback envelope is malformed"))?;
    if envelope.version != 1
        || decode_hex_32(&envelope.directory_pubkey_hex, "directory pubkey")?
            != *expected_directory_pubkey
    {
        return Err(JsError::new(
            "directory rollback envelope has the wrong namespace",
        ));
    }
    Ok(envelope)
}

fn unique_entry_state_map(rows: Vec<EntryStateV1>) -> Result<BTreeMap<[u8; 32], Vec<u8>>, JsError> {
    let mut map = BTreeMap::new();
    for row in rows {
        let provider = decode_hex_32(&row.provider_id_hex, "provider id")?;
        if map.insert(provider, row.state).is_some() {
            return Err(JsError::new("duplicate durable directory entry state"));
        }
    }
    Ok(map)
}

fn unique_checkpoint_state_map(
    rows: Vec<CheckpointStateV1>,
) -> Result<BTreeMap<u8, Vec<u8>>, JsError> {
    let mut map = BTreeMap::new();
    for row in rows {
        if row.shard >= DIRECTORY_SHARD_COUNT_V1 || map.insert(row.shard, row.state).is_some() {
            return Err(JsError::new("duplicate durable directory checkpoint state"));
        }
    }
    Ok(map)
}

fn fixed_nonzero_32(bytes: &[u8], field: &str) -> Result<[u8; 32], JsError> {
    let value: [u8; 32] = bytes
        .try_into()
        .map_err(|_| JsError::new(&format!("{field} must be exactly 32 bytes")))?;
    if value.iter().all(|byte| *byte == 0) {
        return Err(JsError::new(&format!("{field} must be non-zero")));
    }
    Ok(value)
}

fn decode_hex_32(value: &str, field: &str) -> Result<[u8; 32], JsError> {
    decode_hex_32_string(value, field).map_err(|error| JsError::new(&error))
}

fn decode_hex_32_string(value: &str, field: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{field} must be lowercase 32-byte hex"));
    }
    let decoded = hex::decode(value).map_err(|_| format!("{field} is invalid hex"))?;
    let fixed: [u8; 32] = decoded
        .try_into()
        .map_err(|_| format!("{field} must be 32 bytes"))?;
    if fixed.iter().all(|byte| *byte == 0) {
        return Err(format!("{field} must be non-zero"));
    }
    Ok(fixed)
}

fn js_error(error: impl core::fmt::Display) -> JsError {
    JsError::new(&error.to_string())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey as Ed25519SigningKey;
    use pir_directory_nostr::{
        DirectoryCatalogCheckpointV1, DirectoryCheckpointEntryV1, DirectoryEntryV1,
        DirectoryHealthClassV1, DirectoryHealthV1, DirectoryPublisherKeyV1,
    };
    use pir_service_protocol::{
        DirectoryEndpointV1, DirectoryOperatorAssertionV1, DirectoryTransportV1,
    };

    use super::*;

    const NOW: u64 = 1_500;

    fn event_message(event: &NostrEventV1, shard: u8) -> String {
        let event: serde_json::Value =
            serde_json::from_slice(&event.to_json_bytes().unwrap()).unwrap();
        serde_json::to_string(&serde_json::json!([
            "EVENT",
            format!("{DIRECTORY_REQ_SUBSCRIPTION_PREFIX_V1}{shard:x}"),
            event
        ]))
        .unwrap()
    }

    fn empty_catalog_messages(publisher: &DirectoryPublisherKeyV1, epoch: u64) -> Vec<String> {
        (0..DIRECTORY_SHARD_COUNT_V1)
            .map(|shard| {
                let checkpoint =
                    DirectoryCatalogCheckpointV1::new(shard, epoch, 1_000, 2_500, Vec::new(), NOW)
                        .unwrap();
                let event = publisher
                    .sign_checkpoint_event(&checkpoint, NOW, &[shard + 1; 32])
                    .unwrap();
                event_message(&event, shard)
            })
            .collect()
    }

    fn relay_batch(first: Vec<String>, second: Vec<String>) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "relays": [
                { "relayId": 0, "eventMessages": first },
                { "relayId": 1, "eventMessages": second }
            ]
        }))
        .unwrap()
    }

    #[test]
    fn complete_two_relay_catalog_stays_withheld_until_durable_ack_and_restarts() {
        let publisher = DirectoryPublisherKeyV1::from_secret_bytes([41; 32]).unwrap();
        let messages = empty_catalog_messages(&publisher, 7);
        let batch = relay_batch(messages.clone(), messages.clone());
        let shards = verify_relay_batch_v1(&batch, publisher.public_key(), NOW).unwrap();
        assert_eq!(shards.len(), 16);

        let mut candidate = WasmDirectoryCatalogCandidateV1 {
            directory_pubkey: *publisher.public_key(),
            shards,
            prepared: None,
            selectable_catalog_json: None,
        };
        let empty = serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "directoryPubkeyHex": hex::encode(publisher.public_key()),
            "entries": [],
            "checkpoints": []
        }))
        .unwrap();
        let plan: RollbackPlanV1 =
            serde_json::from_str(&candidate.prepare_rollback(&empty).unwrap()).unwrap();
        assert_eq!(plan.checkpoints.len(), 16);
        assert!(candidate.selectable_catalog_json.is_none());
        let durable = StateEnvelopeV1 {
            version: 1,
            directory_pubkey_hex: hex::encode(publisher.public_key()),
            entries: Vec::new(),
            checkpoints: plan
                .checkpoints
                .iter()
                .map(|row| CheckpointStateV1 {
                    shard: row.shard,
                    state: row.successor.clone(),
                })
                .collect(),
        };
        candidate
            .acknowledge_persisted(&serde_json::to_vec(&durable).unwrap())
            .unwrap();
        let selectable: serde_json::Value =
            serde_json::from_str(&candidate.selectable_catalog_json().unwrap()).unwrap();
        assert_eq!(selectable["shards"].as_array().unwrap().len(), 16);

        let restart_shards = verify_relay_batch_v1(&batch, publisher.public_key(), NOW).unwrap();
        let mut restart = WasmDirectoryCatalogCandidateV1 {
            directory_pubkey: *publisher.public_key(),
            shards: restart_shards,
            prepared: None,
            selectable_catalog_json: None,
        };
        let replay: RollbackPlanV1 = serde_json::from_str(
            &restart
                .prepare_rollback(&serde_json::to_vec(&durable).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert!(replay
            .checkpoints
            .iter()
            .all(|row| row.expected.as_ref() == Some(&row.successor)));
    }

    #[test]
    fn same_epoch_checkpoint_root_split_view_fails_closed() {
        let publisher = DirectoryPublisherKeyV1::from_secret_bytes([42; 32]).unwrap();
        let first = empty_catalog_messages(&publisher, 9);
        let mut second = first.clone();
        let provider_id = [0x20; 32];
        let tombstone = DirectoryEntryV1::new_tombstone(
            provider_id,
            1,
            2_500,
            DirectoryHealthV1 {
                class: DirectoryHealthClassV1::Unavailable,
                observed_bucket: NOW,
            },
            NOW,
        )
        .unwrap();
        let entry_event = publisher
            .sign_entry_event(&tombstone, NOW, &[81; 32])
            .unwrap();
        let checkpoint = DirectoryCatalogCheckpointV1::new(
            2,
            9,
            1_000,
            2_500,
            vec![DirectoryCheckpointEntryV1 {
                provider_id,
                directory_sequence: 1,
                event_id: *entry_event.id(),
            }],
            NOW,
        )
        .unwrap();
        let checkpoint_event = publisher
            .sign_checkpoint_event(&checkpoint, NOW, &[82; 32])
            .unwrap();
        second[2] = event_message(&checkpoint_event, 2);
        second.push(event_message(&entry_event, 2));

        let error = verify_relay_batch_v1(&relay_batch(first, second), publisher.public_key(), NOW)
            .unwrap_err();
        assert!(error.contains("split view"));
    }

    #[test]
    fn selectable_entry_exports_distinct_operator_and_policy_trust_keys() {
        let publisher = DirectoryPublisherKeyV1::from_secret_bytes([43; 32]).unwrap();
        let operator = Ed25519SigningKey::from_bytes(&[44; 32]);
        let policy = Ed25519SigningKey::from_bytes(&[45; 32]);
        let assertion = DirectoryOperatorAssertionV1::sign(
            "browser-provider".to_owned(),
            3,
            1_000,
            2_500,
            vec![DirectoryEndpointV1 {
                transport: DirectoryTransportV1::Wss,
                url: "wss://pir.example/v1".to_owned(),
            }],
            policy.verifying_key().to_bytes(),
            11,
            [0x55; 32],
            &operator,
        )
        .unwrap();
        let entry = DirectoryEntryV1::new_active(
            1,
            2_500,
            assertion,
            Vec::new(),
            DirectoryHealthV1 {
                class: DirectoryHealthClassV1::Available,
                observed_bucket: NOW,
            },
            NOW,
        )
        .unwrap();
        let entry_event = publisher.sign_entry_event(&entry, NOW, &[46; 32]).unwrap();
        let shard = coarse_shard_for_provider_v1(entry.provider_id());
        let checkpoint = DirectoryCatalogCheckpointV1::new(
            shard,
            12,
            1_000,
            2_500,
            vec![DirectoryCheckpointEntryV1 {
                provider_id: *entry.provider_id(),
                directory_sequence: entry.directory_sequence(),
                event_id: *entry_event.id(),
            }],
            NOW,
        )
        .unwrap();
        let checkpoint_event = publisher
            .sign_checkpoint_event(&checkpoint, NOW, &[47; 32])
            .unwrap();
        let mut messages = empty_catalog_messages(&publisher, 12);
        messages[usize::from(shard)] = event_message(&checkpoint_event, shard);
        messages.push(event_message(&entry_event, shard));
        let batch = relay_batch(messages.clone(), messages);
        let shards = verify_relay_batch_v1(&batch, publisher.public_key(), NOW).unwrap();
        let mut candidate = WasmDirectoryCatalogCandidateV1 {
            directory_pubkey: *publisher.public_key(),
            shards,
            prepared: None,
            selectable_catalog_json: None,
        };
        let empty = serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "directoryPubkeyHex": hex::encode(publisher.public_key()),
            "entries": [],
            "checkpoints": []
        }))
        .unwrap();
        let plan: RollbackPlanV1 =
            serde_json::from_str(&candidate.prepare_rollback(&empty).unwrap()).unwrap();
        let durable = StateEnvelopeV1 {
            version: 1,
            directory_pubkey_hex: hex::encode(publisher.public_key()),
            entries: plan
                .entries
                .iter()
                .map(|row| EntryStateV1 {
                    provider_id_hex: row.provider_id_hex.clone(),
                    state: row.successor.clone(),
                })
                .collect(),
            checkpoints: plan
                .checkpoints
                .iter()
                .map(|row| CheckpointStateV1 {
                    shard: row.shard,
                    state: row.successor.clone(),
                })
                .collect(),
        };
        candidate
            .acknowledge_persisted(&serde_json::to_vec(&durable).unwrap())
            .unwrap();
        let catalog: serde_json::Value =
            serde_json::from_str(&candidate.selectable_catalog_json().unwrap()).unwrap();
        let selected = &catalog["shards"][usize::from(shard)]["entries"][0];
        assert_eq!(
            selected["operatorPubkeyEd25519Hex"],
            hex::encode(operator.verifying_key().to_bytes())
        );
        assert_eq!(
            selected["policySigningKeyEd25519Hex"],
            hex::encode(policy.verifying_key().to_bytes())
        );
        assert_ne!(
            selected["operatorPubkeyEd25519Hex"],
            selected["policySigningKeyEd25519Hex"]
        );
    }
}

#[cfg(test)]
#[path = "directory_fake_relay_tests.rs"]
mod directory_fake_relay_tests;
