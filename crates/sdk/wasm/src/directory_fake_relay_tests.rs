//! End-to-end directory publication/read tests with a deterministic,
//! process-local NIP-01 relay. The harness intentionally has no network or
//! external-account dependency, but it still exchanges the production
//! `EVENT`, `REQ`, `EVENT` and `EOSE` JSON envelopes without normalizing the
//! signed event object before the production reader authenticates it.

use core::cmp::Ordering;
use std::collections::BTreeMap;

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use pir_directory_nostr::{
    coarse_shard_for_provider_v1, full_catalog_req_json_v1, nip01_addressable_replacement_order_v1,
    prepare_directory_checkpoint_acceptance_v1, prepare_directory_entry_acceptance_v1,
    DirectoryCatalogCheckpointV1, DirectoryCheckpointEntryV1, DirectoryCheckpointRollbackStateV1,
    DirectoryEntryRollbackStateV1, DirectoryEntryV1, DirectoryErrorV1, DirectoryHealthClassV1,
    DirectoryHealthV1, DirectoryPublisherKeyV1, NostrEventV1, BITCOINPIR_DIRECTORY_KIND_V1,
    DIRECTORY_SHARD_COUNT_V1,
};
use pir_service_protocol::{
    DirectoryEndpointV1, DirectoryOperatorAssertionV1, DirectoryTransportV1,
};
use serde::Deserialize;
use serde_json::value::RawValue;

use super::*;

const BASE_NOW: u64 = 1_500;
const CURRENT_NOW: u64 = BASE_NOW + 10;
const VALID_UNTIL: u64 = 2_500;

#[derive(Clone)]
struct StoredEventV1 {
    event: NostrEventV1,
    raw_event_json: String,
}

/// Minimal addressable-event behavior needed by the BitcoinPIR profile.
/// The relay authenticates NIP-01 IDs/signatures, applies NIP-01 replacement
/// ordering and filters by the exact author/kind/shard query emitted by Rust.
#[derive(Default)]
struct InProcessNostrRelayV1 {
    events: BTreeMap<([u8; 32], u16, String), StoredEventV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReqFilterV1 {
    authors: [String; 1],
    kinds: [u16; 1],
    #[serde(rename = "#s")]
    shards: [String; 1],
}

struct RelayReadV1 {
    event_messages: Vec<String>,
    eose_message: String,
}

impl InProcessNostrRelayV1 {
    fn publish(&mut self, event_message: &[u8]) -> Result<String, String> {
        let (command, raw_event): (String, Box<RawValue>) =
            serde_json::from_slice(event_message).map_err(|_| "malformed EVENT publish")?;
        if command != "EVENT" {
            return Err("publish envelope is not EVENT".to_owned());
        }
        let event = NostrEventV1::parse_json(raw_event.get().as_bytes())
            .map_err(|error| error.to_string())?;
        // A relay does not establish directory trust. This only rejects an
        // internally inconsistent NIP-01 event before storing it; the reader
        // still verifies against its independently pinned directory key.
        event
            .verify_for_directory_key(event.pubkey())
            .map_err(|error| error.to_string())?;
        let mut d_tags = event
            .tags()
            .iter()
            .filter(|tag| tag.len() == 2 && tag[0] == "d");
        let d = d_tags
            .next()
            .ok_or_else(|| "addressable event omitted d tag".to_owned())?[1]
            .clone();
        if d_tags.next().is_some() {
            return Err("addressable event duplicated d tag".to_owned());
        }
        let key = (*event.pubkey(), event.kind(), d);
        let candidate = StoredEventV1 {
            event,
            raw_event_json: raw_event.get().to_owned(),
        };
        let replace = match self.events.get(&key) {
            None => true,
            Some(current) => {
                nip01_addressable_replacement_order_v1(&candidate.event, &current.event)
                    .map_err(|error| error.to_string())?
                    == Ordering::Greater
            }
        };
        if replace {
            self.events.insert(key, candidate.clone());
        }
        Ok(serde_json::to_string(&serde_json::json!([
            "OK",
            hex::encode(candidate.event.id()),
            true,
            ""
        ]))
        .expect("static OK envelope serializes"))
    }

    fn read(&self, request: &[u8]) -> Result<RelayReadV1, String> {
        let (command, subscription, filter): (String, String, ReqFilterV1) =
            serde_json::from_slice(request).map_err(|_| "malformed REQ")?;
        if command != "REQ"
            || filter.kinds[0] != BITCOINPIR_DIRECTORY_KIND_V1
            || filter.authors[0].len() != 64
        {
            return Err("unsupported REQ filter".to_owned());
        }
        let subscription_json =
            serde_json::to_string(&subscription).expect("subscription string serializes");
        let mut event_messages = Vec::new();
        for stored in self.events.values() {
            let shard_matches = stored
                .event
                .tags()
                .iter()
                .any(|tag| tag.len() == 2 && tag[0] == "s" && tag[1] == filter.shards[0]);
            if hex::encode(stored.event.pubkey()) == filter.authors[0]
                && stored.event.kind() == filter.kinds[0]
                && shard_matches
            {
                event_messages.push(format!(
                    "[\"EVENT\",{subscription_json},{}]",
                    stored.raw_event_json
                ));
            }
        }
        Ok(RelayReadV1 {
            event_messages,
            eose_message: serde_json::to_string(&serde_json::json!(["EOSE", subscription]))
                .expect("EOSE envelope serializes"),
        })
    }
}

#[derive(Clone, Copy)]
struct ProviderKeysV1 {
    stable_server_id: &'static str,
    endpoint: &'static str,
    operator_seed: u8,
    policy_seed: u8,
    policy_digest_seed: u8,
}

const PROVIDERS: [ProviderKeysV1; 2] = [
    ProviderKeysV1 {
        stable_server_id: "provider-alpha",
        endpoint: "wss://alpha.pir.invalid/v1",
        operator_seed: 52,
        policy_seed: 53,
        policy_digest_seed: 54,
    },
    ProviderKeysV1 {
        stable_server_id: "provider-beta",
        endpoint: "wss://beta.pir.invalid/v1",
        operator_seed: 62,
        policy_seed: 63,
        policy_digest_seed: 64,
    },
];

struct BuiltCatalogV1 {
    publish_messages: Vec<Vec<u8>>,
    provider_ids: Vec<[u8; 32]>,
    operator_keys: Vec<[u8; 32]>,
    policy_keys: Vec<[u8; 32]>,
}

fn build_catalog(
    publisher: &DirectoryPublisherKeyV1,
    directory_sequence: u64,
    assertion_epoch: u64,
    checkpoint_epoch: u64,
    created_at: u64,
) -> BuiltCatalogV1 {
    let mut entry_events = Vec::new();
    let mut provider_ids = Vec::new();
    let mut operator_keys = Vec::new();
    let mut policy_keys = Vec::new();
    let mut aux = checkpoint_epoch as u8;

    for provider in PROVIDERS {
        let operator = Ed25519SigningKey::from_bytes(&[provider.operator_seed; 32]);
        let policy = Ed25519SigningKey::from_bytes(&[provider.policy_seed; 32]);
        let operator_key = operator.verifying_key().to_bytes();
        let policy_key = policy.verifying_key().to_bytes();
        let assertion = DirectoryOperatorAssertionV1::sign(
            provider.stable_server_id.to_owned(),
            assertion_epoch,
            1_000,
            VALID_UNTIL,
            vec![DirectoryEndpointV1 {
                transport: DirectoryTransportV1::Wss,
                url: provider.endpoint.to_owned(),
            }],
            policy_key,
            11,
            [provider.policy_digest_seed; 32],
            &operator,
        )
        .unwrap();
        let entry = DirectoryEntryV1::new_active(
            directory_sequence,
            VALID_UNTIL,
            assertion,
            Vec::new(),
            DirectoryHealthV1 {
                class: DirectoryHealthClassV1::Available,
                observed_bucket: BASE_NOW,
            },
            created_at,
        )
        .unwrap();
        aux = aux.wrapping_add(1);
        let event = publisher
            .sign_entry_event(&entry, created_at, &[aux; 32])
            .unwrap();
        provider_ids.push(*entry.provider_id());
        operator_keys.push(operator_key);
        policy_keys.push(policy_key);
        entry_events.push((entry, event));
    }

    let mut checkpoint_rows = (0..DIRECTORY_SHARD_COUNT_V1)
        .map(|_| Vec::<DirectoryCheckpointEntryV1>::new())
        .collect::<Vec<_>>();
    for (entry, event) in &entry_events {
        checkpoint_rows[usize::from(coarse_shard_for_provider_v1(entry.provider_id()))].push(
            DirectoryCheckpointEntryV1 {
                provider_id: *entry.provider_id(),
                directory_sequence: entry.directory_sequence(),
                event_id: *event.id(),
            },
        );
    }
    for rows in &mut checkpoint_rows {
        rows.sort_by_key(|row| row.provider_id);
    }

    let mut publish_messages = entry_events
        .iter()
        .map(|(_, event)| event.to_event_message_json_bytes().unwrap())
        .collect::<Vec<_>>();
    for shard in 0..DIRECTORY_SHARD_COUNT_V1 {
        let checkpoint = DirectoryCatalogCheckpointV1::new(
            shard,
            checkpoint_epoch,
            1_000,
            VALID_UNTIL,
            checkpoint_rows[usize::from(shard)].clone(),
            created_at,
        )
        .unwrap();
        aux = aux.wrapping_add(1);
        let event = publisher
            .sign_checkpoint_event(&checkpoint, created_at, &[aux; 32])
            .unwrap();
        publish_messages.push(event.to_event_message_json_bytes().unwrap());
    }
    BuiltCatalogV1 {
        publish_messages,
        provider_ids,
        operator_keys,
        policy_keys,
    }
}

fn publish_catalog(relay: &mut InProcessNostrRelayV1, catalog: &BuiltCatalogV1) {
    for message in &catalog.publish_messages {
        let ack: serde_json::Value =
            serde_json::from_str(&relay.publish(message).unwrap()).unwrap();
        assert_eq!(ack[0], "OK");
        assert_eq!(ack[2], true);
    }
}

fn read_complete_catalog(
    relay: &InProcessNostrRelayV1,
    directory_pubkey: &[u8; 32],
) -> Vec<String> {
    let requests = full_catalog_req_json_v1(directory_pubkey).unwrap();
    assert_eq!(requests.len(), usize::from(DIRECTORY_SHARD_COUNT_V1));
    let mut messages = Vec::new();
    for request in requests {
        let request_text = core::str::from_utf8(&request).unwrap();
        for forbidden in [
            "pair_id",
            "peer_provider",
            "selected_peer",
            "payment_hash",
            "invoice",
        ] {
            assert!(!request_text.contains(forbidden));
        }
        let response = relay.read(&request).unwrap();
        let eose: serde_json::Value = serde_json::from_str(&response.eose_message).unwrap();
        assert_eq!(eose[0], "EOSE");
        messages.extend(response.event_messages);
    }
    messages
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
fn signed_publish_to_fake_relays_reads_two_independent_providers_and_fails_closed() {
    let publisher = DirectoryPublisherKeyV1::from_secret_bytes([51; 32]).unwrap();
    let old_catalog = build_catalog(&publisher, 1, 1, 7, BASE_NOW);
    let current_catalog = build_catalog(&publisher, 2, 2, 8, CURRENT_NOW);

    assert_eq!(old_catalog.provider_ids, current_catalog.provider_ids);
    assert_ne!(
        current_catalog.provider_ids[0],
        current_catalog.provider_ids[1]
    );
    let mut reserved = current_catalog.operator_keys.clone();
    reserved.extend(current_catalog.policy_keys.iter().copied());
    publisher
        .ensure_distinct_from_xonly_keys(&reserved)
        .unwrap();
    for index in 0..PROVIDERS.len() {
        assert_ne!(
            current_catalog.operator_keys[index],
            current_catalog.policy_keys[index]
        );
        assert_ne!(
            publisher.public_key(),
            &current_catalog.operator_keys[index]
        );
        assert_ne!(publisher.public_key(), &current_catalog.policy_keys[index]);
    }
    for message in &current_catalog.publish_messages {
        let text = core::str::from_utf8(message).unwrap();
        for forbidden in ["pair_id", "peer_provider", "selected_peer"] {
            assert!(!text.contains(forbidden));
        }
    }

    // Both relays see the same independently signed catalog. Publishing the
    // later logical revision exercises addressable-event replacement rather
    // than returning both revisions to the reader.
    let mut relay_a = InProcessNostrRelayV1::default();
    let mut relay_b = InProcessNostrRelayV1::default();
    for relay in [&mut relay_a, &mut relay_b] {
        publish_catalog(relay, &old_catalog);
        publish_catalog(relay, &current_catalog);
        assert_eq!(relay.events.len(), 18);
    }
    let relay_a_messages = read_complete_catalog(&relay_a, publisher.public_key());
    let relay_b_messages = read_complete_catalog(&relay_b, publisher.public_key());
    assert_eq!(relay_a_messages.len(), 18);
    assert_eq!(relay_a_messages, relay_b_messages);
    let current_batch = relay_batch(relay_a_messages.clone(), relay_b_messages.clone());

    let shards = verify_relay_batch_v1(&current_batch, publisher.public_key(), CURRENT_NOW)
        .expect("signed two-relay catalog must verify");
    let mut candidate = WasmDirectoryCatalogCandidateV1 {
        directory_pubkey: *publisher.public_key(),
        shards,
        prepared: None,
        selectable_catalog_json: None,
    };
    let empty_state = serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "directoryPubkeyHex": hex::encode(publisher.public_key()),
        "entries": [],
        "checkpoints": []
    }))
    .unwrap();
    let plan: RollbackPlanV1 =
        serde_json::from_str(&candidate.prepare_rollback(&empty_state).unwrap()).unwrap();
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
    let selectable_text = candidate.selectable_catalog_json().unwrap();
    for forbidden in ["pair_id", "peer_provider", "selected_peer"] {
        assert!(!selectable_text.contains(forbidden));
    }
    let selectable: serde_json::Value = serde_json::from_str(&selectable_text).unwrap();
    let selected = selectable["shards"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|shard| shard["entries"].as_array().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(selected.len(), 2);
    let selected_provider_ids = selected
        .iter()
        .map(|entry| entry["providerIdHex"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(selected_provider_ids.len(), 2);
    for entry in selected {
        assert_ne!(
            entry["operatorPubkeyEd25519Hex"],
            entry["policySigningKeyEd25519Hex"]
        );
        assert_ne!(
            entry["operatorPubkeyEd25519Hex"].as_str().unwrap(),
            hex::encode(publisher.public_key())
        );
        assert_ne!(
            entry["policySigningKeyEd25519Hex"].as_str().unwrap(),
            hex::encode(publisher.public_key())
        );
    }

    // A relay-modified content byte is rejected by the production NIP-01
    // event-ID/signature verifier even when the other relay is intact.
    let mut tampered = relay_a_messages.clone();
    let position = tampered
        .iter()
        .position(|message| message.contains("available"))
        .expect("active entry is present");
    let original = tampered[position].clone();
    tampered[position] = original.replacen("available", "degraded", 1);
    assert_ne!(tampered[position], original);
    let tamper_error = verify_relay_batch_v1(
        &relay_batch(tampered, relay_b_messages.clone()),
        publisher.public_key(),
        CURRENT_NOW,
    )
    .unwrap_err();
    assert!(tamper_error.contains("event id"), "{tamper_error}");

    let wrong_directory = DirectoryPublisherKeyV1::from_secret_bytes([71; 32]).unwrap();
    let wrong_key_error =
        verify_relay_batch_v1(&current_batch, wrong_directory.public_key(), CURRENT_NOW)
            .unwrap_err();
    assert!(wrong_key_error.contains("pinned directory key"));
    let expiry_error =
        verify_relay_batch_v1(&current_batch, publisher.public_key(), VALID_UNTIL + 1).unwrap_err();
    assert!(expiry_error.contains("not currently valid"));

    // A fresh pair of relays can replay an older but still cryptographically
    // valid catalog. Durable per-provider/per-shard state, not relay memory,
    // is what rejects that rollback after restart.
    let mut rollback_relay_a = InProcessNostrRelayV1::default();
    let mut rollback_relay_b = InProcessNostrRelayV1::default();
    publish_catalog(&mut rollback_relay_a, &old_catalog);
    publish_catalog(&mut rollback_relay_b, &old_catalog);
    let old_batch = relay_batch(
        read_complete_catalog(&rollback_relay_a, publisher.public_key()),
        read_complete_catalog(&rollback_relay_b, publisher.public_key()),
    );
    let old_shards = verify_relay_batch_v1(&old_batch, publisher.public_key(), CURRENT_NOW)
        .expect("older catalog remains signed and within its validity window");
    for shard in old_shards {
        for entry in shard.entries {
            let provider_hex = hex::encode(entry.discovery_entry().provider_id());
            let current = plan
                .entries
                .iter()
                .find(|row| row.provider_id_hex == provider_hex)
                .map(|row| DirectoryEntryRollbackStateV1::decode(&row.successor).unwrap())
                .unwrap();
            assert_eq!(
                prepare_directory_entry_acceptance_v1(entry, Some(&current)),
                Err(DirectoryErrorV1::DirectorySequenceRollback)
            );
        }
        let current = plan
            .checkpoints
            .iter()
            .find(|row| row.shard == shard.checkpoint.checkpoint().shard())
            .map(|row| DirectoryCheckpointRollbackStateV1::decode(&row.successor).unwrap())
            .unwrap();
        assert_eq!(
            prepare_directory_checkpoint_acceptance_v1(shard.checkpoint, Some(&current)),
            Err(DirectoryErrorV1::CheckpointEpochRollback)
        );
    }
}
