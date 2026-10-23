//! Catalogs signed with the codec's publisher helpers and delivered as the
//! directory relay sends them: `["EVENT", <shard subscription>, <event>]`.

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;

use super::*;
use crate::hex::lower_hex;
use crate::{
    checkpoint_d_tag_value_v1, coarse_shard_for_provider_v1, derive_provider_id,
    DirectoryAccessClassV1, DirectoryAttestationV1, DirectoryBackendV1,
    DirectoryCatalogCheckpointV1, DirectoryCheckpointEntryV1, DirectoryEndpointV1,
    DirectoryEntryV1, DirectoryHealthV1, DirectoryOperatorAssertionV1, DirectoryPublisherKeyV1,
    DirectoryServerRoleV1, DirectoryTransportV1,
};

const NOW: u64 = 1_800_000_000;
const CREATED: u64 = NOW - 600;
const NOT_BEFORE: u64 = NOW - 3_600;
const VALID_UNTIL: u64 = NOW + 7 * 24 * 3_600;

struct Provider {
    operator_seed: u8,
    server_id: &'static str,
    endpoint: &'static str,
    attestation: DirectoryAttestationV1,
    backends: &'static [(DirectoryBackendV1, DirectoryAccessClassV1)],
}

/// A no-TEE server with an announce identity and an SEV-SNP ORAM host.
const PROVIDERS: [Provider; 2] = [
    Provider {
        operator_seed: 52,
        server_id: "alpha",
        endpoint: "wss://alpha.pir.example/v1",
        attestation: DirectoryAttestationV1::None,
        backends: &[
            (DirectoryBackendV1::Dpf, DirectoryAccessClassV1::BestEffort),
            (DirectoryBackendV1::Harmony, DirectoryAccessClassV1::Paid),
            (DirectoryBackendV1::Onion, DirectoryAccessClassV1::Paid),
        ],
    },
    Provider {
        operator_seed: 62,
        server_id: "beta-oram",
        endpoint: "wss://beta.pir.example",
        attestation: DirectoryAttestationV1::SevSnp,
        backends: &[(DirectoryBackendV1::Oram, DirectoryAccessClassV1::Free)],
    },
];

fn publisher() -> DirectoryPublisherKeyV1 {
    DirectoryPublisherKeyV1::from_secret_bytes([51; 32]).unwrap()
}

fn key() -> [u8; 32] {
    *publisher().public_key()
}

fn operator(provider: &Provider) -> SigningKey {
    SigningKey::from_bytes(&[provider.operator_seed; 32])
}

fn provider_shard(provider: &Provider) -> u8 {
    let operator = operator(provider).verifying_key().to_bytes();
    coarse_shard_for_provider_v1(&derive_provider_id(&operator, provider.server_id))
}

/// Every provider's entry at `sequence` plus all 16 checkpoints at `epoch`,
/// signed at `created_at` with fixed auxiliary randomness, so equal
/// arguments give byte-identical events.
fn catalog(sequence: u64, epoch: u64, created_at: u64) -> Vec<NostrEventV1> {
    let publisher = publisher();
    let mut rows = Vec::new();
    let mut events = Vec::new();
    for provider in &PROVIDERS {
        let assertion = DirectoryOperatorAssertionV1::sign(
            provider.server_id.to_owned(),
            sequence,
            NOT_BEFORE,
            VALID_UNTIL,
            vec![DirectoryEndpointV1 {
                transport: DirectoryTransportV1::Wss,
                url: provider.endpoint.to_owned(),
            }],
            &operator(provider),
        )
        .unwrap();
        let hints = provider
            .backends
            .iter()
            .map(|&(backend, access)| DirectoryCatalogHintV1 {
                backend,
                role: DirectoryServerRoleV1::Primary,
                access,
                attestation: provider.attestation,
            })
            .collect();
        let health = DirectoryHealthV1 {
            class: DirectoryHealthClassV1::Available,
            observed_bucket: NOW - 900,
        };
        let entry = DirectoryEntryV1::new_active(
            sequence,
            VALID_UNTIL,
            assertion,
            hints,
            health,
            created_at,
        )
        .unwrap();
        let event = publisher
            .sign_entry_event(&entry, created_at, &[provider.operator_seed; 32])
            .unwrap();
        rows.push(DirectoryCheckpointEntryV1 {
            provider_id: *entry.provider_id(),
            directory_sequence: sequence,
            event_id: *event.id(),
        });
        events.push(event);
    }
    rows.sort();
    for shard in 0..DIRECTORY_SHARD_COUNT_V1 {
        let entries = rows
            .iter()
            .copied()
            .filter(|row| coarse_shard_for_provider_v1(&row.provider_id) == shard)
            .collect();
        let checkpoint = DirectoryCatalogCheckpointV1::new(
            shard,
            epoch,
            NOT_BEFORE,
            VALID_UNTIL,
            entries,
            created_at,
        )
        .unwrap();
        events.push(
            publisher
                .sign_checkpoint_event(&checkpoint, created_at, &[shard + 1; 32])
                .unwrap(),
        );
    }
    events
}

/// The relay's `EVENT` messages for `events`, under their shard subscription.
fn relay(events: &[NostrEventV1]) -> Vec<String> {
    events
        .iter()
        .map(|event| {
            let shard = event.tags()[1][1].rsplit(':').next().unwrap();
            let event = String::from_utf8(event.to_json_bytes().unwrap()).unwrap();
            format!(r#"["EVENT","{DIRECTORY_REQ_SUBSCRIPTION_PREFIX_V1}{shard}",{event}]"#)
        })
        .collect()
}

fn floors() -> DirectoryRollbackFloorsV1 {
    DirectoryRollbackFloorsV1::default()
}

#[test]
fn one_relay_view_yields_entries_hints_and_replayable_floors() {
    let key = key();
    let view = relay(&catalog(1, 7, CREATED));
    let first = verify_directory_catalog_views_v1(std::slice::from_ref(&view), floors(), &key, NOW);
    assert!(first.rejected.is_empty(), "{:?}", first.rejected);
    assert_eq!(first.shards.len(), SHARDS);
    assert!(first
        .shards
        .iter()
        .all(|shard| shard.epoch == 7 && shard.views == 1));
    assert_eq!(first.valid_until, VALID_UNTIL);
    assert_eq!(first.state.checkpoints.len(), SHARDS);
    assert_eq!(first.state.entries.len(), PROVIDERS.len());

    let alpha = first
        .entries
        .iter()
        .find(|entry| entry.server_id == "alpha")
        .unwrap();
    assert_eq!(
        alpha.operator_pubkey,
        lower_hex(&operator(&PROVIDERS[0]).verifying_key().to_bytes())
    );
    assert_eq!(alpha.endpoints, ["wss://alpha.pir.example/v1"]);
    assert_eq!(alpha.health, DirectoryHealthClassV1::Available);
    assert_eq!(
        alpha
            .hints
            .iter()
            .map(|hint| (hint.backend, hint.role, hint.access, hint.attestation))
            .collect::<Vec<_>>(),
        [
            (
                DirectoryBackendV1::Dpf,
                DirectoryServerRoleV1::Primary,
                DirectoryAccessClassV1::BestEffort,
                DirectoryAttestationV1::None
            ),
            (
                DirectoryBackendV1::Harmony,
                DirectoryServerRoleV1::Primary,
                DirectoryAccessClassV1::Paid,
                DirectoryAttestationV1::None
            ),
            (
                DirectoryBackendV1::Onion,
                DirectoryServerRoleV1::Primary,
                DirectoryAccessClassV1::Paid,
                DirectoryAttestationV1::None
            ),
        ]
    );
    let beta = first
        .entries
        .iter()
        .find(|entry| entry.server_id == "beta-oram")
        .unwrap();
    assert_eq!(
        beta.hints
            .iter()
            .map(|hint| (hint.backend, hint.access, hint.attestation))
            .collect::<Vec<_>>(),
        [(
            DirectoryBackendV1::Oram,
            DirectoryAccessClassV1::Free,
            DirectoryAttestationV1::SevSnp
        )]
    );

    // The same catalog against its own floors is an exact replay.
    let replay = verify_directory_catalog_views_v1(&[view], first.state.clone(), &key, NOW);
    assert!(replay.rejected.is_empty(), "{:?}", replay.rejected);
    assert_eq!(replay.state, first.state);
}

#[test]
fn a_tombstone_counts_toward_expiry_and_floors_but_is_no_entry() {
    let key = key();
    let publisher = publisher();
    let shard = provider_shard(&PROVIDERS[0]);
    let mut retired = [0x11; 32];
    retired[0] = shard << 4;
    let health = DirectoryHealthV1 {
        class: DirectoryHealthClassV1::Unavailable,
        observed_bucket: NOW - 900,
    };
    let tombstone =
        DirectoryEntryV1::new_tombstone(retired, 3, VALID_UNTIL - 60, health, CREATED).unwrap();
    let tombstone = publisher
        .sign_entry_event(&tombstone, CREATED, &[90; 32])
        .unwrap();

    let mut events = catalog(1, 7, CREATED);
    let index = events
        .iter()
        .position(|event| event.tags()[0][1] == checkpoint_d_tag_value_v1(shard))
        .unwrap();
    let checkpoint =
        verify_directory_checkpoint_event_v1(&events[index].to_json_bytes().unwrap(), &key, NOW)
            .unwrap();
    let mut rows = checkpoint.checkpoint().entries().to_vec();
    rows.push(DirectoryCheckpointEntryV1 {
        provider_id: retired,
        directory_sequence: 3,
        event_id: *tombstone.id(),
    });
    rows.sort();
    let checkpoint =
        DirectoryCatalogCheckpointV1::new(shard, 7, NOT_BEFORE, VALID_UNTIL, rows, CREATED)
            .unwrap();
    events[index] = publisher
        .sign_checkpoint_event(&checkpoint, CREATED, &[91; 32])
        .unwrap();
    events.push(tombstone);

    let result = verify_directory_catalog_views_v1(&[relay(&events)], floors(), &key, NOW);
    assert!(result.rejected.is_empty(), "{:?}", result.rejected);
    assert_eq!(result.valid_until, VALID_UNTIL - 60);
    assert_eq!(result.entries.len(), PROVIDERS.len());
    assert!(result.state.entries.contains_key(&lower_hex(&retired)));
}

#[test]
fn agreeing_relays_are_counted_and_a_split_view_rejects_its_shard() {
    let key = key();
    let view = relay(&catalog(1, 7, CREATED));
    let both =
        verify_directory_catalog_views_v1(&[view.clone(), view.clone()], floors(), &key, NOW);
    assert!(both.rejected.is_empty(), "{:?}", both.rejected);
    assert!(both.shards.iter().all(|shard| shard.views == 2));

    // The same epoch with other entries: the provider shards' checkpoints
    // differ between the relays, the empty shards' stay byte-identical.
    let forked = relay(&catalog(2, 7, CREATED));
    let split = verify_directory_catalog_views_v1(&[view, forked], floors(), &key, NOW);
    let provider_shards = PROVIDERS
        .iter()
        .map(provider_shard)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        split
            .rejected
            .iter()
            .map(|rejection| (rejection.relay, rejection.shard.unwrap()))
            .collect::<BTreeSet<_>>(),
        provider_shards
            .iter()
            .map(|shard| (None, *shard))
            .collect::<BTreeSet<_>>()
    );
    assert!(split
        .rejected
        .iter()
        .all(|rejection| rejection.reason.contains("split view")));
    assert_eq!(split.shards.len(), SHARDS - provider_shards.len());
    assert!(split.shards.iter().all(|shard| shard.views == 2));
    assert!(split.entries.is_empty());
    assert!(provider_shards
        .iter()
        .all(|shard| !split.state.checkpoints.contains_key(shard)));
}

#[test]
fn a_tampered_or_foreign_event_rejects_only_that_view() {
    let key = key();
    let view = relay(&catalog(1, 7, CREATED));
    let alpha_shard = provider_shard(&PROVIDERS[0]);
    let mut tampered = view.clone();
    let alpha = tampered
        .iter()
        .position(|message| message.contains("alpha.pir.example"))
        .unwrap();
    tampered[alpha] = tampered[alpha].replacen("available", "degraded", 1);
    let result = verify_directory_catalog_views_v1(&[tampered, view.clone()], floors(), &key, NOW);
    assert_eq!(result.rejected.len(), 1, "{:?}", result.rejected);
    let rejection = &result.rejected[0];
    assert_eq!(
        (rejection.relay, rejection.shard),
        (Some(0), Some(alpha_shard))
    );
    assert!(
        rejection.reason.contains("event id"),
        "{}",
        rejection.reason
    );
    assert_eq!(result.shards[usize::from(alpha_shard)].views, 1);
    assert_eq!(result.entries.len(), PROVIDERS.len());

    // An EVENT outside the 16 shard subscriptions discards that relay view.
    let mut stray = view.clone();
    stray.push(stray[0].replacen("shard-", "other-", 1));
    let result = verify_directory_catalog_views_v1(&[stray, view.clone()], floors(), &key, NOW);
    assert_eq!(result.rejected.len(), 1);
    assert_eq!(
        (result.rejected[0].relay, result.rejected[0].shard),
        (Some(0), None)
    );
    assert!(result.shards.iter().all(|shard| shard.views == 1));

    // Events of another directory key, or past their validity, are no view.
    let foreign = DirectoryPublisherKeyV1::from_secret_bytes([71; 32]).unwrap();
    for result in [
        verify_directory_catalog_views_v1(
            std::slice::from_ref(&view),
            floors(),
            foreign.public_key(),
            NOW,
        ),
        verify_directory_catalog_views_v1(&[view], floors(), &key, VALID_UNTIL + 1),
    ] {
        assert!(result.shards.is_empty() && result.entries.is_empty());
        assert_eq!(result.valid_until, 0);
        assert_eq!(result.state, floors());
        assert_eq!(result.rejected.len(), 2 * SHARDS);
    }
}

#[test]
fn floors_advance_and_an_older_catalog_is_then_rejected_as_a_rollback() {
    let key = key();
    let older = relay(&catalog(1, 7, CREATED));
    let newer = relay(&catalog(2, 8, CREATED + 300));
    let first =
        verify_directory_catalog_views_v1(std::slice::from_ref(&older), floors(), &key, NOW);
    let advanced = verify_directory_catalog_views_v1(&[newer], first.state.clone(), &key, NOW);
    assert!(advanced.rejected.is_empty(), "{:?}", advanced.rejected);
    assert!(advanced.shards.iter().all(|shard| shard.epoch == 8));
    assert_ne!(advanced.state, first.state);

    let rollback = verify_directory_catalog_views_v1(&[older], advanced.state.clone(), &key, NOW);
    assert!(rollback.shards.is_empty() && rollback.entries.is_empty());
    assert_eq!(rollback.state, advanced.state);
    let relay_reasons = rollback
        .rejected
        .iter()
        .filter(|rejection| rejection.relay == Some(0))
        .map(|rejection| rejection.reason.as_str())
        .collect::<Vec<_>>();
    assert_eq!(relay_reasons.len(), SHARDS);
    assert!(relay_reasons
        .iter()
        .all(|reason| *reason == DirectoryErrorV1::CheckpointEpochRollback.to_string()));
}

#[test]
fn serializes_the_browser_json_shape_with_the_wire_names() {
    let key = key();
    let catalog =
        verify_directory_catalog_views_v1(&[relay(&catalog(1, 7, CREATED))], floors(), &key, NOW);
    let json: serde_json::Value = serde_json::to_value(&catalog).unwrap();
    assert_eq!(json["validUntil"], VALID_UNTIL);
    assert_eq!(json["shards"][0]["views"], 1);
    assert!(json["shards"][0]["eventId"].is_string());
    let alpha = json["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["serverId"] == "alpha")
        .unwrap();
    assert_eq!(alpha["health"], "available");
    assert_eq!(
        alpha["hints"][0],
        serde_json::json!({"backend": "dpf", "role": "primary", "access": "best-effort", "attestation": "none"})
    );
    let beta = json["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["serverId"] == "beta-oram")
        .unwrap();
    assert_eq!(beta["hints"][0]["attestation"], "sev-snp");
    assert!(beta["operatorPubkey"].is_string() && beta["providerId"].is_string());
    assert_eq!(json["rejected"], serde_json::json!([]));
    // The floors round-trip through their JSON form.
    let floors: DirectoryRollbackFloorsV1 = serde_json::from_value(json["state"].clone()).unwrap();
    assert_eq!(floors, catalog.state);
    assert!(serde_json::from_str::<DirectoryRollbackFloorsV1>(r#"{"entries":{}}"#).is_err());
}
