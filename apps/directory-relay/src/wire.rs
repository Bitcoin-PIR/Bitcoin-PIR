//! Strict, bounded wire profile for the BitcoinPIR directory relay.

use std::collections::BTreeSet;

use pir_directory_nostr::{
    shard_tag_value_v1, verify_directory_checkpoint_event_v1, verify_directory_entry_event_v1,
    NostrEventV1, BITCOINPIR_DIRECTORY_KIND_V1, DIRECTORY_CHECKPOINT_D_PREFIX_V1,
    DIRECTORY_ENTRY_D_PREFIX_V1, DIRECTORY_SHARD_COUNT_V1, MAX_NOSTR_EVENT_BYTES_V1,
};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

pub const MAX_WIRE_MESSAGE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_EVENT_MESSAGE_BYTES: usize = MAX_NOSTR_EVENT_BYTES_V1 + 32;
/// ID readback is a recovery/commit-probe facility, not a bulk archive scan.
/// Catalog refresh uses the single-query shard filter below. Keeping this
/// bound small prevents one unauthenticated REQ from monopolizing SQLite.
pub const MAX_READBACK_IDS: usize = 64;
pub const MAX_CATALOG_EVENTS_PER_SHARD: usize = 1_025;
pub const MAX_DIRECTORY_ENTRIES_PER_SHARD: usize = 1_024;
pub const MAX_SNAPSHOT_PAGE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_SUBSCRIPTION_ID_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryEventProfile {
    Entry,
    Checkpoint,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedEvent {
    pub event: NostrEventV1,
    pub canonical_json: Vec<u8>,
    pub d_tag: String,
    pub s_tag: String,
    pub shard: u8,
    pub profile: DirectoryEventProfile,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestFilter {
    Catalog { shard: u8 },
    Ids(Vec<[u8; 32]>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientMessage {
    Event(Box<ValidatedEvent>),
    Req {
        subscription_id: String,
        filter: RequestFilter,
    },
    Close {
        subscription_id: String,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CatalogFilterWire {
    authors: Vec<String>,
    kinds: Vec<u16>,
    #[serde(rename = "#s")]
    shard: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IdFilterWire {
    ids: Vec<String>,
}

pub fn parse_client_message(
    bytes: &[u8],
    pinned_directory_pubkey: &[u8; 32],
    now_unix: u64,
) -> Result<ClientMessage, String> {
    if bytes.is_empty() || bytes.len() > MAX_WIRE_MESSAGE_BYTES {
        return Err("wire message exceeds the bounded profile".to_owned());
    }
    let values: Vec<Box<RawValue>> =
        serde_json::from_slice(bytes).map_err(|_| "wire message is not strict JSON".to_owned())?;
    let command: &str = values
        .first()
        .ok_or_else(|| "wire message is empty".to_owned())
        .and_then(|value| {
            serde_json::from_str(value.get()).map_err(|_| "wire command is not a string".to_owned())
        })?;
    match command {
        "EVENT" => {
            if values.len() != 2 || bytes.len() > MAX_EVENT_MESSAGE_BYTES {
                return Err("EVENT must contain exactly one event object".to_owned());
            }
            let event = validate_event_json(
                values[1].get().as_bytes(),
                pinned_directory_pubkey,
                now_unix,
            )?;
            if event
                .event
                .to_event_message_json_bytes()
                .map_err(|_| "EVENT envelope canonicalization failed".to_owned())?
                != bytes
            {
                return Err("EVENT envelope is not the exact canonical encoding".to_owned());
            }
            Ok(ClientMessage::Event(Box::new(event)))
        }
        "REQ" => {
            if values.len() != 3 {
                return Err("REQ must contain exactly one filter".to_owned());
            }
            let subscription_id: String = serde_json::from_str(values[1].get())
                .map_err(|_| "REQ subscription id is not a string".to_owned())?;
            validate_subscription_id(&subscription_id)?;
            let filter = parse_request_filter(values[2].get(), pinned_directory_pubkey)?;
            if canonical_req_message(&subscription_id, &filter, pinned_directory_pubkey)? != bytes {
                return Err("REQ envelope is not the exact canonical encoding".to_owned());
            }
            Ok(ClientMessage::Req {
                subscription_id,
                filter,
            })
        }
        "CLOSE" => {
            if values.len() != 2 {
                return Err("CLOSE must contain exactly one subscription id".to_owned());
            }
            let subscription_id: String = serde_json::from_str(values[1].get())
                .map_err(|_| "CLOSE subscription id is not a string".to_owned())?;
            validate_subscription_id(&subscription_id)?;
            if serde_json::to_vec(&("CLOSE", &subscription_id))
                .map_err(|_| "CLOSE canonicalization failed".to_owned())?
                != bytes
            {
                return Err("CLOSE envelope is not the exact canonical encoding".to_owned());
            }
            Ok(ClientMessage::Close { subscription_id })
        }
        _ => Err("unsupported wire command".to_owned()),
    }
}

fn canonical_req_message(
    subscription_id: &str,
    filter: &RequestFilter,
    pinned_directory_pubkey: &[u8; 32],
) -> Result<Vec<u8>, String> {
    match filter {
        RequestFilter::Catalog { shard } => serde_json::to_vec(&(
            "REQ",
            subscription_id,
            CatalogFilterWire {
                authors: vec![hex::encode(pinned_directory_pubkey)],
                kinds: vec![BITCOINPIR_DIRECTORY_KIND_V1],
                shard: vec![shard_tag_value_v1(*shard)],
            },
        )),
        RequestFilter::Ids(ids) => serde_json::to_vec(&(
            "REQ",
            subscription_id,
            IdFilterWire {
                ids: ids.iter().map(hex::encode).collect(),
            },
        )),
    }
    .map_err(|_| "REQ canonicalization failed".to_owned())
}

pub fn validate_event_json(
    event_json: &[u8],
    pinned_directory_pubkey: &[u8; 32],
    _now_unix: u64,
) -> Result<ValidatedEvent, String> {
    if event_json.is_empty() || event_json.len() > MAX_NOSTR_EVENT_BYTES_V1 {
        return Err("EVENT object exceeds the directory event bound".to_owned());
    }
    let event = NostrEventV1::parse_json(event_json)
        .map_err(|error| format!("EVENT object is invalid: {error}"))?;
    event
        .verify_for_directory_key(pinned_directory_pubkey)
        .map_err(|error| format!("EVENT identity verification failed: {error}"))?;
    let canonical_json = event
        .to_json_bytes()
        .map_err(|error| format!("EVENT canonical encoding failed: {error}"))?;
    if canonical_json != event_json {
        return Err("EVENT object is not the exact canonical encoding".to_owned());
    }

    let tags = event.tags();
    if tags.len() != 2
        || tags[0].len() != 2
        || tags[0][0] != "d"
        || tags[1].len() != 2
        || tags[1][0] != "s"
    {
        return Err("EVENT does not have the exact ordered d/s profile".to_owned());
    }
    let d_tag = tags[0][1].clone();
    let s_tag = tags[1][1].clone();
    let shard = parse_shard_tag(&s_tag)?;
    let profile = if let Some(provider_hex) = d_tag.strip_prefix(DIRECTORY_ENTRY_D_PREFIX_V1) {
        let provider = decode_lower_hex_32(provider_hex, "entry d-tag provider")?;
        if provider[0] >> 4 != shard {
            return Err("entry EVENT d/s shards disagree".to_owned());
        }
        DirectoryEventProfile::Entry
    } else if let Some(checkpoint_shard) = d_tag.strip_prefix(DIRECTORY_CHECKPOINT_D_PREFIX_V1) {
        if checkpoint_shard.len() != 1
            || char::from(checkpoint_shard.as_bytes()[0])
                .to_digit(16)
                .and_then(|value| u8::try_from(value).ok())
                != Some(shard)
            || checkpoint_shard.as_bytes()[0].is_ascii_uppercase()
        {
            return Err("checkpoint EVENT d/s shards disagree".to_owned());
        }
        DirectoryEventProfile::Checkpoint
    } else {
        return Err("EVENT has no BitcoinPIR directory d namespace".to_owned());
    };
    // Current content validity is deliberately deferred until the store has
    // checked its immutable archive. This lets an expired exact duplicate be
    // acknowledged idempotently without accepting a new expired event.
    Ok(ValidatedEvent {
        event,
        canonical_json,
        d_tag,
        s_tag,
        shard,
        profile,
    })
}

pub fn validate_current_event_profile(
    event: &ValidatedEvent,
    pinned_directory_pubkey: &[u8; 32],
    now_unix: u64,
) -> Result<(), String> {
    let entry =
        verify_directory_entry_event_v1(&event.canonical_json, pinned_directory_pubkey, now_unix);
    let checkpoint = verify_directory_checkpoint_event_v1(
        &event.canonical_json,
        pinned_directory_pubkey,
        now_unix,
    );
    match (event.profile, entry, checkpoint) {
        (DirectoryEventProfile::Entry, Ok(_), Err(_))
        | (DirectoryEventProfile::Checkpoint, Err(_), Ok(_)) => Ok(()),
        _ => Err("EVENT is not one current BitcoinPIR directory profile event".to_owned()),
    }
}

fn parse_request_filter(
    raw: &str,
    pinned_directory_pubkey: &[u8; 32],
) -> Result<RequestFilter, String> {
    if let Ok(filter) = serde_json::from_str::<CatalogFilterWire>(raw) {
        if filter.authors.len() != 1
            || filter.kinds.as_slice() != [BITCOINPIR_DIRECTORY_KIND_V1]
            || filter.shard.len() != 1
        {
            return Err("catalog REQ has the wrong exact filter cardinality".to_owned());
        }
        let author = decode_lower_hex_32(&filter.authors[0], "catalog author")?;
        if &author != pinned_directory_pubkey {
            return Err("catalog REQ author does not match the directory key".to_owned());
        }
        return Ok(RequestFilter::Catalog {
            shard: parse_shard_tag(&filter.shard[0])?,
        });
    }

    let filter: IdFilterWire = serde_json::from_str(raw)
        .map_err(|_| "REQ filter is outside the BitcoinPIR profile".to_owned())?;
    if filter.ids.is_empty() || filter.ids.len() > MAX_READBACK_IDS {
        return Err(format!(
            "ID readback REQ must contain 1..={MAX_READBACK_IDS} ids"
        ));
    }
    let mut unique = BTreeSet::new();
    let mut ids = Vec::with_capacity(filter.ids.len());
    for id in filter.ids {
        let decoded = decode_lower_hex_32(&id, "readback event id")?;
        if !unique.insert(decoded) {
            return Err("ID readback REQ contains a duplicate id".to_owned());
        }
        ids.push(decoded);
    }
    Ok(RequestFilter::Ids(ids))
}

fn parse_shard_tag(value: &str) -> Result<u8, String> {
    (0..DIRECTORY_SHARD_COUNT_V1)
        .find(|shard| value == shard_tag_value_v1(*shard))
        .ok_or_else(|| "directory shard tag is not canonical".to_owned())
}

fn validate_subscription_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_SUBSCRIPTION_ID_BYTES
        || value.chars().any(char::is_control)
    {
        return Err("subscription id is empty, oversized, or contains control text".to_owned());
    }
    Ok(())
}

fn decode_lower_hex_32(value: &str, label: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(format!("{label} must be exact lowercase 32-byte hex"));
    }
    let bytes = hex::decode(value).map_err(|_| format!("{label} is invalid hex"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{label} has the wrong length"))
}

pub fn best_effort_event_id(bytes: &[u8]) -> Option<String> {
    let values: Vec<Box<RawValue>> = serde_json::from_slice(bytes).ok()?;
    if values.len() != 2 || values[0].get() != "\"EVENT\"" {
        return None;
    }
    #[derive(Deserialize)]
    struct EventId<'a> {
        #[serde(borrow)]
        id: &'a str,
    }
    let id = serde_json::from_str::<EventId<'_>>(values[1].get())
        .ok()?
        .id;
    decode_lower_hex_32(id, "event id").ok()?;
    Some(id.to_owned())
}

pub fn best_effort_subscription_id(bytes: &[u8]) -> Option<String> {
    let values: Vec<Box<RawValue>> = serde_json::from_slice(bytes).ok()?;
    if values.len() < 2 {
        return None;
    }
    let command: &str = serde_json::from_str(values[0].get()).ok()?;
    if command != "REQ" && command != "CLOSE" {
        return None;
    }
    let id: String = serde_json::from_str(values[1].get()).ok()?;
    validate_subscription_id(&id).ok()?;
    Some(id)
}

pub fn ok_message(event_id: &[u8; 32], accepted: bool, reason: &str) -> String {
    serde_json::to_string(&("OK", hex::encode(event_id), accepted, reason))
        .expect("fixed OK message is serializable")
}

pub fn ok_message_hex(event_id: &str, accepted: bool, reason: &str) -> String {
    serde_json::to_string(&("OK", event_id, accepted, reason))
        .expect("fixed OK message is serializable")
}

pub fn event_message(subscription_id: &str, canonical_event_json: &[u8]) -> Result<String, String> {
    let subscription = serde_json::to_string(subscription_id)
        .map_err(|_| "serialize subscription id failed".to_owned())?;
    let event = std::str::from_utf8(canonical_event_json)
        .map_err(|_| "stored event is not UTF-8".to_owned())?;
    let mut message = String::with_capacity(event.len() + subscription.len() + 16);
    message.push_str("[\"EVENT\",");
    message.push_str(&subscription);
    message.push(',');
    message.push_str(event);
    message.push(']');
    if message.len() > MAX_WIRE_MESSAGE_BYTES {
        return Err("outbound EVENT exceeds the wire bound".to_owned());
    }
    Ok(message)
}

pub fn eose_message(subscription_id: &str) -> String {
    serde_json::to_string(&("EOSE", subscription_id)).expect("fixed EOSE is serializable")
}

pub fn closed_message(subscription_id: &str, reason: &str) -> String {
    serde_json::to_string(&("CLOSED", subscription_id, reason))
        .expect("fixed CLOSED is serializable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use pir_directory_nostr::{
        catalog_req_json_v1, DirectoryEntryV1, DirectoryHealthClassV1, DirectoryHealthV1,
        DirectoryPublisherKeyV1,
    };

    const NOW: u64 = 1_800_000;

    fn signed_event(publisher: &DirectoryPublisherKeyV1) -> NostrEventV1 {
        let entry = DirectoryEntryV1::new_tombstone(
            [0x21; 32],
            1,
            NOW + 10_000,
            DirectoryHealthV1 {
                class: DirectoryHealthClassV1::Unknown,
                observed_bucket: NOW,
            },
            NOW,
        )
        .unwrap();
        publisher.sign_entry_event(&entry, NOW, &[8; 32]).unwrap()
    }

    #[test]
    fn readback_accepts_current_publish_bound_and_rejects_duplicate() {
        let ids = (0..MAX_READBACK_IDS)
            .map(|value| format!("{value:064x}"))
            .collect::<Vec<_>>();
        let wire = serde_json::json!(["REQ", "readback", {"ids": ids}]).to_string();
        let parsed = parse_client_message(wire.as_bytes(), &[7; 32], 1).unwrap();
        let ClientMessage::Req {
            filter: RequestFilter::Ids(parsed),
            ..
        } = parsed
        else {
            panic!("wrong message");
        };
        assert_eq!(parsed.len(), MAX_READBACK_IDS);
        assert!(wire.len() < MAX_WIRE_MESSAGE_BYTES);

        let too_many = (0..=MAX_READBACK_IDS)
            .map(|value| format!("{value:064x}"))
            .collect::<Vec<_>>();
        let too_many = serde_json::json!(["REQ", "readback", {"ids": too_many}]).to_string();
        assert!(parse_client_message(too_many.as_bytes(), &[7; 32], 1).is_err());

        let duplicate =
            serde_json::json!(["REQ", "readback", {"ids": ["01".repeat(32), "01".repeat(32)]}])
                .to_string();
        assert!(parse_client_message(duplicate.as_bytes(), &[7; 32], 1).is_err());
    }

    #[test]
    fn request_filters_are_exact() {
        let key = [9; 32];
        let valid = String::from_utf8(catalog_req_json_v1(&key, 10).unwrap()).unwrap();
        assert!(matches!(
            parse_client_message(valid.as_bytes(), &key, 1).unwrap(),
            ClientMessage::Req {
                filter: RequestFilter::Catalog { shard: 10 },
                ..
            }
        ));
        for extra in [
            serde_json::json!(["REQ", "s", {"authors": [hex::encode(key)], "kinds": [30078], "#s": [shard_tag_value_v1(0)], "limit": 1}]),
            serde_json::json!(["REQ", "s", {"ids": ["01".repeat(32)], "limit": 1}]),
            serde_json::json!(["REQ", "s", {"ids": ["01"]}]),
        ] {
            assert!(parse_client_message(extra.to_string().as_bytes(), &key, 1).is_err());
        }
    }

    #[test]
    fn unknown_and_duplicate_filter_fields_are_rejected() {
        let key = [3; 32];
        let duplicate = format!(
            r#"["REQ","s",{{"ids":["{}"],"ids":["{}"]}}]"#,
            "01".repeat(32),
            "02".repeat(32)
        );
        assert!(parse_client_message(duplicate.as_bytes(), &key, 1).is_err());
    }

    #[test]
    fn event_requires_signature_key_kind_profile_and_exact_envelope() {
        let publisher = DirectoryPublisherKeyV1::from_secret_bytes([51; 32]).unwrap();
        let wrong = DirectoryPublisherKeyV1::from_secret_bytes([52; 32]).unwrap();
        let event = signed_event(&publisher);
        let message = event.to_event_message_json_bytes().unwrap();
        let parsed = parse_client_message(&message, publisher.public_key(), NOW).unwrap();
        assert!(matches!(parsed, ClientMessage::Event(_)));
        assert!(parse_client_message(&message, wrong.public_key(), NOW).is_err());

        let mut whitespace = message.clone();
        whitespace.push(b' ');
        assert!(parse_client_message(&whitespace, publisher.public_key(), NOW).is_err());

        let wrong_kind = String::from_utf8(message.clone())
            .unwrap()
            .replace("\"kind\":30078", "\"kind\":30079");
        assert!(parse_client_message(wrong_kind.as_bytes(), publisher.public_key(), NOW).is_err());

        let event_json = String::from_utf8(event.to_json_bytes().unwrap()).unwrap();
        let duplicate_id = format!(
            "{{\"id\":\"{}\",{}",
            hex::encode(event.id()),
            &event_json[1..]
        );
        let duplicate_id = format!("[\"EVENT\",{duplicate_id}]");
        assert!(
            parse_client_message(duplicate_id.as_bytes(), publisher.public_key(), NOW).is_err()
        );
    }

    #[test]
    fn wire_size_bounds_are_fail_closed() {
        let oversized = vec![b' '; MAX_WIRE_MESSAGE_BYTES + 1];
        assert!(parse_client_message(&oversized, &[7; 32], NOW).is_err());
        let event_oversized = format!(
            "[\"EVENT\",{{\"padding\":\"{}\"}}]",
            "x".repeat(MAX_EVENT_MESSAGE_BYTES)
        );
        assert!(event_oversized.len() > MAX_EVENT_MESSAGE_BYTES);
        assert!(parse_client_message(event_oversized.as_bytes(), &[7; 32], NOW).is_err());
    }
}
