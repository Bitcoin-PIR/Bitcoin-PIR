use std::cmp::Ordering;
use std::future::{ready, Ready};

use ed25519_dalek::SigningKey;
use futures::executor::block_on;
use pir_service_protocol::{
    AcquisitionMethod, AuthPaddingClassV1, AuthScheme, BackendId, DatasetBindingV1,
    DeploymentStatus, DirectoryEndpointV1, DirectoryOperatorAssertionV1, DirectoryTransportV1,
    EntitlementLimitsV1, FreeModeV1, PolicyRollbackGuardV1, PriceV1, PrivacyLeakageV1,
    ServiceOfferV1, ServicePolicyEpochFloorsV1, ServicePolicyV1, ServiceScopePolicyV1,
    ServiceScopeV1, VerificationMode, WorkloadId,
};

use super::*;

const NOW: u64 = 1_500;

fn operator_assertion(epoch: u64, seed: u8) -> DirectoryOperatorAssertionV1 {
    operator_assertion_for_policy(epoch, seed, [0x41; 32], 9, [0x51; 32])
}

fn operator_assertion_for_policy(
    epoch: u64,
    seed: u8,
    policy_signing_key_ed25519: [u8; 32],
    policy_epoch: u64,
    policy_digest: [u8; 32],
) -> DirectoryOperatorAssertionV1 {
    DirectoryOperatorAssertionV1::sign(
        "provider-a".to_owned(),
        epoch,
        1_000,
        3_000,
        vec![DirectoryEndpointV1 {
            transport: DirectoryTransportV1::Wss,
            url: "wss://pir-a.example/v1".to_owned(),
        }],
        policy_signing_key_ed25519,
        policy_epoch,
        policy_digest,
        &SigningKey::from_bytes(&[seed; 32]),
    )
    .unwrap()
}

fn health(class: DirectoryHealthClassV1) -> DirectoryHealthV1 {
    DirectoryHealthV1 {
        class,
        observed_bucket: NOW,
    }
}

fn hint(seed: u8) -> DirectoryCatalogHintV1 {
    DirectoryCatalogHintV1 {
        scope_id: [seed; 32],
        backend: BackendId::DpfPirV1,
        workload: WorkloadId::DpfEvaluateJobV1,
        acquisition: AcquisitionMethod::Bolt11V1,
        authorization: AuthScheme::BitcoinPirCashuBatV1,
        deployment: DeploymentStatus::Stable,
    }
}

fn active_entry(sequence: u64, assertion_epoch: u64) -> DirectoryEntryV1 {
    DirectoryEntryV1::new_active(
        sequence,
        2_500,
        operator_assertion(assertion_epoch, 3),
        vec![hint(7)],
        health(DirectoryHealthClassV1::Available),
        NOW,
    )
    .unwrap()
}

fn free_policy(provider_id: [u8; 32], policy_epoch: u64) -> ServicePolicyV1 {
    let scope = ServiceScopeV1 {
        provider_id,
        backend: BackendId::DpfPirV1,
        workload: WorkloadId::DpfEvaluateJobV1,
        protocol_version: 1,
        dataset: DatasetBindingV1::Class { class_id: 1 },
        operation_profile: 1,
        entitlement_profile: 2,
    };
    let offer = ServiceOfferV1 {
        offer_id: 1,
        acquisition: AcquisitionMethod::FreeV1,
        free_mode: FreeModeV1::OpenBestEffort,
        free_quota: 0,
        free_window_seconds: 0,
        free_pow_difficulty_bits: 0,
        priority_class: 1,
        authorization: AuthScheme::FreeV1,
        verification: VerificationMode::ProviderLocal,
        deployment_status: DeploymentStatus::Stable,
        price: PriceV1::Free,
        issuer_id: [0; 32],
        key_id: Vec::new(),
        credential_binding: None,
        cashu_mint_manifest: None,
        endpoint: String::new(),
        invoice_expiry_seconds: 0,
        claim_window_seconds: 0,
        minimum_credential_validity_seconds: 1,
        retired_policy_grace_seconds: 0,
        credential_count: 1,
        credential_presentation_limit: 1,
        privacy_leakage: PrivacyLeakageV1::NONE,
    };
    ServicePolicyV1::sign(
        provider_id,
        policy_epoch,
        1_000,
        2_500,
        AuthPaddingClassV1::Class16KiB,
        vec![ServiceScopePolicyV1 {
            scope,
            limits: EntitlementLimitsV1 {
                max_logical_inputs: 1,
                max_frames: 100,
                max_request_bytes: 1_000_000,
                max_response_bytes: 2_000_000,
                max_wall_time_ms: 60_000,
                max_concurrent_sockets: 1,
                max_hint_groups: 0,
                max_work_units: 9_000,
            },
            offers: vec![offer],
        }],
        &SigningKey::from_bytes(&[41; 32]),
    )
    .unwrap()
}

fn signed_entry(
    publisher: &DirectoryPublisherKeyV1,
    entry: &DirectoryEntryV1,
    created_at: u64,
    randomness: u8,
) -> NostrEventV1 {
    publisher
        .sign_entry_event(entry, created_at, &[randomness; 32])
        .unwrap()
}

fn resign_event_with_tags(
    secret_key: [u8; 32],
    event: &NostrEventV1,
    tags: Vec<Vec<String>>,
    randomness: u8,
) -> NostrEventV1 {
    let id = super::event::canonical_event_id_for_parts(
        event.pubkey(),
        event.created_at(),
        &tags,
        event.content(),
    )
    .unwrap();
    let signing_key = k256::schnorr::SigningKey::from_bytes(&secret_key).unwrap();
    let pubkey = signing_key.verifying_key().to_bytes().into();
    let signature = signing_key
        .sign_prehash_with_aux_rand(&id, &[randomness; 32])
        .unwrap()
        .to_bytes();
    NostrEventV1::from_signed_parts(
        id,
        pubkey,
        event.created_at(),
        tags,
        event.content().to_owned(),
        signature,
    )
    .unwrap()
}

#[test]
fn publisher_entry_roundtrip_is_pinned_and_nip01_signed() {
    let publisher = DirectoryPublisherKeyV1::from_secret_bytes([11; 32]).unwrap();
    let entry = active_entry(1, 1);
    let event = signed_entry(&publisher, &entry, NOW, 12);
    let json = event.to_json_bytes().unwrap();
    let verified = verify_directory_entry_event_for_operator_v1(
        &json,
        publisher.public_key(),
        entry.provider_id(),
        &entry.operator_assertion().unwrap().operator_pubkey_ed25519,
        NOW,
    )
    .unwrap();
    assert_eq!(verified.discovery_entry(), &entry);
    assert_eq!(
        verified.shard(),
        coarse_shard_for_provider_v1(entry.provider_id())
    );
    assert_eq!(
        NostrEventV1::parse_json(&json)
            .unwrap()
            .to_json_bytes()
            .unwrap(),
        json
    );

    let event_message: serde_json::Value =
        serde_json::from_slice(&event.to_event_message_json_bytes().unwrap()).unwrap();
    let event_object: serde_json::Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(event_message[0], "EVENT");
    assert_eq!(event_message[1]["id"], event_object["id"]);

    let wrong = DirectoryPublisherKeyV1::from_secret_bytes([13; 32]).unwrap();
    assert_eq!(
        verify_directory_entry_event_v1(&json, wrong.public_key(), NOW),
        Err(DirectoryErrorV1::WrongDirectoryKey)
    );
    assert_eq!(
        verify_directory_entry_event_for_operator_v1(
            &json,
            publisher.public_key(),
            entry.provider_id(),
            &[0x99; 32],
            NOW,
        ),
        Err(DirectoryErrorV1::WrongOperatorIdentity)
    );
    assert_eq!(
        verify_directory_entry_event_v1(&json, publisher.public_key(), 2_501),
        Err(DirectoryErrorV1::EntryExpired)
    );

    #[cfg(not(target_arch = "wasm32"))]
    {
        use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
        let secp = Secp256k1::verification_only();
        let public_key = XOnlyPublicKey::from_slice(event.pubkey()).unwrap();
        let signature = Signature::from_slice(event.signature()).unwrap();
        let message = Message::from_digest(*event.id());
        secp.verify_schnorr(&signature, &message, &public_key)
            .unwrap();
    }
}

#[test]
fn nip01_canonical_preimage_and_event_id_fixture_are_locked() {
    let mut secret = [0; 32];
    secret[31] = 1;
    let publisher = DirectoryPublisherKeyV1::from_secret_bytes(secret).unwrap();
    let expected_pubkey: [u8; 32] = super::hex::decode_lower_hex(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )
    .unwrap();
    assert_eq!(publisher.public_key(), &expected_pubkey);
    let tags = vec![
        vec!["d".to_owned(), "bitcoinpir-test".to_owned()],
        vec![
            "s".to_owned(),
            "bitcoinpir-service-directory-shard-v1:0".to_owned(),
        ],
    ];
    let content = "{\"v\":1}";
    let id = super::event::canonical_event_id_for_parts(
        publisher.public_key(),
        1_700_000_000,
        &tags,
        content,
    )
    .unwrap();
    let expected_id: [u8; 32] = super::hex::decode_lower_hex(
        "7bd7ff3a73060700330a689564336338cf362f69c6eb25e2d794a74960fcc2dd",
    )
    .unwrap();
    assert_eq!(id, expected_id);
    let signature = k256::schnorr::SigningKey::from_bytes(&secret)
        .unwrap()
        .sign_prehash_with_aux_rand(&id, &[0; 32])
        .unwrap()
        .to_bytes();
    let event = NostrEventV1::from_signed_parts(
        id,
        expected_pubkey,
        1_700_000_000,
        tags,
        content.to_owned(),
        signature,
    )
    .unwrap();
    event
        .verify_for_directory_key(publisher.public_key())
        .unwrap();
    assert_eq!(
        String::from_utf8(event.canonical_id_preimage().unwrap()).unwrap(),
        concat!(
            "[0,\"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\",",
            "1700000000,30078,[[\"d\",\"bitcoinpir-test\"],[\"s\",",
            "\"bitcoinpir-service-directory-shard-v1:0\"]],\"{\\\"v\\\":1}\"]"
        )
    );
}

#[test]
fn nip01_addressable_order_and_strict_nip78_profile_are_enforced() {
    let publisher = DirectoryPublisherKeyV1::from_secret_bytes([11; 32]).unwrap();
    publisher
        .ensure_distinct_from_xonly_keys(&[[0x55; 32]])
        .unwrap();
    assert_eq!(
        publisher.ensure_distinct_from_xonly_keys(&[*publisher.public_key()]),
        Err(DirectoryErrorV1::InvalidValue)
    );
    let debug = format!("{publisher:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains(&"0b".repeat(32)));

    let first = signed_entry(&publisher, &active_entry(1, 1), NOW, 12);
    let later = signed_entry(&publisher, &active_entry(2, 2), NOW + 1, 13);
    assert_eq!(
        nip01_addressable_replacement_order_v1(&later, &first).unwrap(),
        Ordering::Greater
    );
    assert_eq!(
        nip01_addressable_replacement_order_v1(&first, &later).unwrap(),
        Ordering::Less
    );

    let other_entry = DirectoryEntryV1::new_active(
        1,
        2_500,
        operator_assertion(1, 4),
        vec![hint(7)],
        health(DirectoryHealthClassV1::Available),
        NOW,
    )
    .unwrap();
    let other = signed_entry(&publisher, &other_entry, NOW + 1, 14);
    assert_eq!(
        nip01_addressable_replacement_order_v1(&other, &first),
        Err(DirectoryErrorV1::DifferentAddressableCoordinate)
    );

    let mut leaking_tags = first.tags().to_vec();
    leaking_tags.push(vec!["bolt11".to_owned(), "invoice-artifact".to_owned()]);
    let leaking = resign_event_with_tags([11; 32], &first, leaking_tags, 15);
    assert_eq!(
        verify_directory_entry_event_v1(
            &leaking.to_json_bytes().unwrap(),
            publisher.public_key(),
            NOW,
        ),
        Err(DirectoryErrorV1::InvalidEntryTag)
    );

    let event_json: serde_json::Value =
        serde_json::from_slice(&first.to_json_bytes().unwrap()).unwrap();
    assert_eq!(event_json["tags"].as_array().unwrap().len(), 2);
    let content = event_json["content"].as_str().unwrap();
    for forbidden in [
        "invoice",
        "payment_hash",
        "preimage",
        "credential",
        "peer_provider",
        "pair_id",
    ] {
        assert!(!content.contains(forbidden));
    }
}

#[test]
fn canonical_content_rejects_aliases_and_payment_artifact_fields() {
    let canonical = active_entry(1, 1).canonical_json_bytes().unwrap();
    let mut with_whitespace = canonical.clone();
    with_whitespace.push(b' ');
    assert_eq!(
        DirectoryEntryV1::parse_canonical_json(&with_whitespace, NOW),
        Err(DirectoryErrorV1::NonCanonicalJson)
    );

    let canonical_text = String::from_utf8(canonical.clone()).unwrap();
    let provider_hex = super::hex::lower_hex(active_entry(1, 1).provider_id());
    let provider_field = format!("\"provider_id\":\"{provider_hex}\",");
    let uppercase = canonical_text.replacen(
        &provider_field,
        &format!("\"provider_id\":\"{}\",", provider_hex.to_uppercase()),
        1,
    );
    assert_eq!(
        DirectoryEntryV1::parse_canonical_json(uppercase.as_bytes(), NOW),
        Err(DirectoryErrorV1::InvalidHex)
    );
    let duplicate = canonical_text.replacen(
        &provider_field,
        &format!("{provider_field}{provider_field}"),
        1,
    );
    assert_eq!(
        DirectoryEntryV1::parse_canonical_json(duplicate.as_bytes(), NOW),
        Err(DirectoryErrorV1::InvalidJson)
    );

    let mut value: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
    value.as_object_mut().unwrap().insert(
        "payment_hash".to_owned(),
        serde_json::Value::String("00".repeat(32)),
    );
    assert_eq!(
        DirectoryEntryV1::parse_canonical_json(&serde_json::to_vec(&value).unwrap(), NOW),
        Err(DirectoryErrorV1::InvalidJson)
    );

    let publisher = DirectoryPublisherKeyV1::from_secret_bytes([16; 32]).unwrap();
    let event = signed_entry(&publisher, &active_entry(1, 1), NOW, 17);
    let mut outer: serde_json::Value =
        serde_json::from_slice(&event.to_json_bytes().unwrap()).unwrap();
    outer.as_object_mut().unwrap().insert(
        "payment_hash".to_owned(),
        serde_json::Value::String("11".repeat(32)),
    );
    assert_eq!(
        NostrEventV1::parse_json(&serde_json::to_vec(&outer).unwrap()),
        Err(DirectoryErrorV1::InvalidJson)
    );

    let late_now = 3_000_000;
    let tombstone = DirectoryEntryV1::new_tombstone(
        [0x22; 32],
        1,
        late_now + 100,
        DirectoryHealthV1 {
            class: DirectoryHealthClassV1::Unavailable,
            observed_bucket: late_now,
        },
        late_now,
    )
    .unwrap();
    let old_event = publisher
        .sign_entry_event(&tombstone, 1, &[18; 32])
        .unwrap();
    assert_eq!(
        verify_directory_entry_event_v1(
            &old_event.to_json_bytes().unwrap(),
            publisher.public_key(),
            late_now,
        ),
        Err(DirectoryErrorV1::EntryExpired)
    );
}

#[test]
fn discovery_hints_only_survive_exact_live_policy_binding() {
    let operator_template = operator_assertion(1, 3);
    let provider_id = operator_template.provider_id;
    let policy = free_policy(provider_id, 9);
    let policy_key = SigningKey::from_bytes(&[41; 32]).verifying_key();
    let verified_policy = policy
        .verify_current_for_acquisition(
            &provider_id,
            NOW,
            &PolicyRollbackGuardV1::initial(),
            &ServicePolicyEpochFloorsV1::initial(),
            &policy_key,
        )
        .unwrap();
    let scope = &policy.scopes[0].scope;
    let assertion = operator_assertion_for_policy(
        1,
        3,
        policy_key.to_bytes(),
        policy.policy_epoch,
        policy.policy_digest().unwrap(),
    );
    let entry = DirectoryEntryV1::new_active(
        1,
        2_500,
        assertion.clone(),
        vec![DirectoryCatalogHintV1 {
            scope_id: scope.scope_id(),
            backend: scope.backend,
            workload: scope.workload,
            acquisition: AcquisitionMethod::FreeV1,
            authorization: AuthScheme::FreeV1,
            deployment: DeploymentStatus::Stable,
        }],
        health(DirectoryHealthClassV1::Available),
        NOW,
    )
    .unwrap();
    let publisher = DirectoryPublisherKeyV1::from_secret_bytes([42; 32]).unwrap();
    let event = signed_entry(&publisher, &entry, NOW, 43);
    let mut store = MemoryRollbackStoreV1::default();
    let persisted_entry = block_on(verify_and_persist_directory_entry_v1(
        &mut store,
        &event.to_json_bytes().unwrap(),
        publisher.public_key(),
        NOW,
    ))
    .unwrap();
    let first_checkpoint = DirectoryCatalogCheckpointV1::new(
        persisted_entry.verified().shard(),
        1,
        1_000,
        2_500,
        vec![DirectoryCheckpointEntryV1 {
            provider_id,
            directory_sequence: entry.directory_sequence(),
            event_id: *event.id(),
        }],
        NOW,
    )
    .unwrap();
    let first_checkpoint_event = publisher
        .sign_checkpoint_event(&first_checkpoint, NOW + 1, &[45; 32])
        .unwrap();
    let persisted_checkpoint = block_on(verify_and_persist_directory_checkpoint_v1(
        &mut store,
        &first_checkpoint_event.to_json_bytes().unwrap(),
        publisher.public_key(),
        NOW + 1,
    ))
    .unwrap();
    let persisted_entries = [persisted_entry];
    let catalog =
        bind_persisted_directory_shard_catalog_v1(&persisted_checkpoint, &persisted_entries)
            .unwrap();
    let binding =
        bind_directory_entry_to_live_policy_v1(&catalog, &provider_id, verified_policy).unwrap();
    assert_eq!(
        binding.live_policy().policy_digest(),
        assertion.policy_digest
    );
    assert_eq!(
        binding.live_policy().policy_signing_key_ed25519(),
        assertion.policy_signing_key_ed25519
    );

    let wrong_policy_key = SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes();
    let misleading = DirectoryEntryV1::new_active(
        2,
        2_500,
        operator_assertion_for_policy(
            2,
            3,
            wrong_policy_key,
            policy.policy_epoch,
            policy.policy_digest().unwrap(),
        ),
        vec![DirectoryCatalogHintV1 {
            scope_id: scope.scope_id(),
            backend: scope.backend,
            workload: scope.workload,
            acquisition: AcquisitionMethod::FreeV1,
            authorization: AuthScheme::FreeV1,
            deployment: DeploymentStatus::Stable,
        }],
        health(DirectoryHealthClassV1::Available),
        NOW,
    )
    .unwrap();
    let misleading = signed_entry(&publisher, &misleading, NOW + 2, 44);
    let misleading = block_on(verify_and_persist_directory_entry_v1(
        &mut store,
        &misleading.to_json_bytes().unwrap(),
        publisher.public_key(),
        NOW + 2,
    ))
    .unwrap();
    let misleading_checkpoint = DirectoryCatalogCheckpointV1::new(
        misleading.verified().shard(),
        2,
        1_000,
        2_500,
        vec![DirectoryCheckpointEntryV1 {
            provider_id,
            directory_sequence: misleading.verified().discovery_entry().directory_sequence(),
            event_id: *misleading.verified().event().id(),
        }],
        NOW + 2,
    )
    .unwrap();
    let misleading_checkpoint_event = publisher
        .sign_checkpoint_event(&misleading_checkpoint, NOW + 3, &[46; 32])
        .unwrap();
    let misleading_checkpoint = block_on(verify_and_persist_directory_checkpoint_v1(
        &mut store,
        &misleading_checkpoint_event.to_json_bytes().unwrap(),
        publisher.public_key(),
        NOW + 3,
    ))
    .unwrap();
    let misleading_entries = [misleading];
    let misleading_catalog =
        bind_persisted_directory_shard_catalog_v1(&misleading_checkpoint, &misleading_entries)
            .unwrap();
    assert_eq!(
        bind_directory_entry_to_live_policy_v1(&misleading_catalog, &provider_id, verified_policy,),
        Err(DirectoryErrorV1::LivePolicyMismatch)
    );

    let newer_policy = free_policy(provider_id, 10);
    let newer_policy = newer_policy
        .verify_current_for_acquisition(
            &provider_id,
            NOW,
            &PolicyRollbackGuardV1::initial(),
            &ServicePolicyEpochFloorsV1::initial(),
            &policy_key,
        )
        .unwrap();
    assert_eq!(
        bind_directory_entry_to_live_policy_v1(&catalog, &provider_id, newer_policy),
        Err(DirectoryErrorV1::LivePolicyMismatch)
    );
}

#[test]
fn entry_rollback_tombstone_and_reactivation_rules_fail_closed() {
    let publisher = DirectoryPublisherKeyV1::from_secret_bytes([14; 32]).unwrap();
    let first_event = signed_entry(&publisher, &active_entry(1, 1), NOW, 15);
    let first = verify_directory_entry_event_v1(
        &first_event.to_json_bytes().unwrap(),
        publisher.public_key(),
        NOW,
    )
    .unwrap();
    let first = prepare_directory_entry_acceptance_v1(first, None).unwrap();
    assert_eq!(
        first.disposition(),
        DirectoryAcceptanceDispositionV1::Initial
    );
    let first_state = *first.proposed_state();
    assert_eq!(first_state.event_created_at_at_highest_sequence(), NOW);

    let same_timestamp_event = signed_entry(&publisher, &active_entry(2, 2), NOW, 19);
    let same_timestamp = verify_directory_entry_event_v1(
        &same_timestamp_event.to_json_bytes().unwrap(),
        publisher.public_key(),
        NOW,
    )
    .unwrap();
    assert_eq!(
        prepare_directory_entry_acceptance_v1(same_timestamp, Some(&first_state)),
        Err(DirectoryErrorV1::ReplaceableTimestampNotAdvanced)
    );

    let same_sequence_event = signed_entry(&publisher, &active_entry(1, 1), NOW + 1, 20);
    let same_sequence = verify_directory_entry_event_v1(
        &same_sequence_event.to_json_bytes().unwrap(),
        publisher.public_key(),
        NOW + 1,
    )
    .unwrap();
    assert_eq!(
        prepare_directory_entry_acceptance_v1(same_sequence, Some(&first_state)),
        Err(DirectoryErrorV1::DirectorySequenceFork)
    );

    let assertion_fork = DirectoryEntryV1::new_active(
        2,
        2_500,
        operator_assertion_for_policy(1, 3, [0x41; 32], 9, [0x52; 32]),
        vec![hint(7)],
        health(DirectoryHealthClassV1::Available),
        NOW,
    )
    .unwrap();
    let assertion_fork = signed_entry(&publisher, &assertion_fork, NOW + 1, 21);
    let assertion_fork = verify_directory_entry_event_v1(
        &assertion_fork.to_json_bytes().unwrap(),
        publisher.public_key(),
        NOW + 1,
    )
    .unwrap();
    assert_eq!(
        prepare_directory_entry_acceptance_v1(assertion_fork, Some(&first_state)),
        Err(DirectoryErrorV1::OperatorEpochFork)
    );

    let advanced_event = signed_entry(&publisher, &active_entry(2, 2), NOW + 1, 22);
    let advanced = verify_directory_entry_event_v1(
        &advanced_event.to_json_bytes().unwrap(),
        publisher.public_key(),
        NOW + 1,
    )
    .unwrap();
    let advanced_state = *prepare_directory_entry_acceptance_v1(advanced, Some(&first_state))
        .unwrap()
        .proposed_state();
    let operator_rollback_event = signed_entry(&publisher, &active_entry(3, 1), NOW + 2, 23);
    let operator_rollback = verify_directory_entry_event_v1(
        &operator_rollback_event.to_json_bytes().unwrap(),
        publisher.public_key(),
        NOW + 2,
    )
    .unwrap();
    assert_eq!(
        prepare_directory_entry_acceptance_v1(operator_rollback, Some(&advanced_state)),
        Err(DirectoryErrorV1::OperatorEpochRollback)
    );

    let tombstone = DirectoryEntryV1::new_tombstone(
        *active_entry(1, 1).provider_id(),
        2,
        2_500,
        health(DirectoryHealthClassV1::Unavailable),
        NOW,
    )
    .unwrap();
    let tombstone_event = signed_entry(&publisher, &tombstone, NOW + 1, 16);
    let tombstone_verified = verify_directory_entry_event_v1(
        &tombstone_event.to_json_bytes().unwrap(),
        publisher.public_key(),
        NOW + 1,
    )
    .unwrap();
    let tombstone_candidate =
        prepare_directory_entry_acceptance_v1(tombstone_verified.clone(), Some(&first_state))
            .unwrap();
    assert_eq!(
        tombstone_candidate.disposition(),
        DirectoryAcceptanceDispositionV1::Advanced
    );
    let tombstone_state = *tombstone_candidate.proposed_state();
    assert_eq!(
        prepare_directory_entry_acceptance_v1(tombstone_verified, Some(&tombstone_state))
            .unwrap()
            .disposition(),
        DirectoryAcceptanceDispositionV1::ExactReplay
    );

    let stale_reactivation_event = signed_entry(&publisher, &active_entry(3, 1), NOW + 2, 17);
    let stale_reactivation = verify_directory_entry_event_v1(
        &stale_reactivation_event.to_json_bytes().unwrap(),
        publisher.public_key(),
        NOW + 2,
    )
    .unwrap();
    assert_eq!(
        prepare_directory_entry_acceptance_v1(stale_reactivation, Some(&tombstone_state)),
        Err(DirectoryErrorV1::ReactivationRequiresNewOperatorEpoch)
    );

    let fresh_reactivation_event = signed_entry(&publisher, &active_entry(3, 2), NOW + 2, 18);
    let fresh_reactivation = verify_directory_entry_event_v1(
        &fresh_reactivation_event.to_json_bytes().unwrap(),
        publisher.public_key(),
        NOW + 2,
    )
    .unwrap();
    assert_eq!(
        prepare_directory_entry_acceptance_v1(fresh_reactivation, Some(&tombstone_state))
            .unwrap()
            .disposition(),
        DirectoryAcceptanceDispositionV1::Advanced
    );

    assert_eq!(
        prepare_directory_entry_acceptance_v1(
            verify_directory_entry_event_v1(
                &first_event.to_json_bytes().unwrap(),
                publisher.public_key(),
                NOW + 2,
            )
            .unwrap(),
            Some(&tombstone_state),
        ),
        Err(DirectoryErrorV1::DirectorySequenceRollback)
    );
}

fn checkpoint(shard: u8, epoch: u64, event_byte: u8) -> DirectoryCatalogCheckpointV1 {
    let mut provider_id = [0x20; 32];
    provider_id[1] = event_byte;
    DirectoryCatalogCheckpointV1::new(
        shard,
        epoch,
        1_000,
        2_500,
        vec![DirectoryCheckpointEntryV1 {
            provider_id,
            directory_sequence: u64::from(event_byte),
            event_id: [event_byte; 32],
        }],
        NOW,
    )
    .unwrap()
}

#[test]
fn checkpoint_split_view_and_epoch_rollback_are_rejected() {
    let publisher = DirectoryPublisherKeyV1::from_secret_bytes([21; 32]).unwrap();
    let first = checkpoint(2, 7, 1);
    let first_event = publisher
        .sign_checkpoint_event(&first, NOW, &[22; 32])
        .unwrap();
    let verified = verify_directory_checkpoint_event_v1(
        &first_event.to_json_bytes().unwrap(),
        publisher.public_key(),
        NOW,
    )
    .unwrap();
    let initial = prepare_directory_checkpoint_acceptance_v1(verified, None).unwrap();
    let state = *initial.proposed_state();
    assert_eq!(state.event_created_at_at_highest_epoch(), NOW);

    let same_root_new_event = publisher
        .sign_checkpoint_event(&first, NOW + 1, &[25; 32])
        .unwrap();
    let same_root_new_event = verify_directory_checkpoint_event_v1(
        &same_root_new_event.to_json_bytes().unwrap(),
        publisher.public_key(),
        NOW + 1,
    )
    .unwrap();
    assert_eq!(
        prepare_directory_checkpoint_acceptance_v1(same_root_new_event, Some(&state)),
        Err(DirectoryErrorV1::CheckpointEpochFork)
    );

    let fork = checkpoint(2, 7, 2);
    let fork_event = publisher
        .sign_checkpoint_event(&fork, NOW + 1, &[23; 32])
        .unwrap();
    let fork_verified = verify_directory_checkpoint_event_v1(
        &fork_event.to_json_bytes().unwrap(),
        publisher.public_key(),
        NOW + 1,
    )
    .unwrap();
    assert_eq!(
        prepare_directory_checkpoint_acceptance_v1(fork_verified, Some(&state)),
        Err(DirectoryErrorV1::CheckpointSplitView)
    );

    let older = checkpoint(2, 6, 3);
    let older_event = publisher
        .sign_checkpoint_event(&older, NOW + 1, &[24; 32])
        .unwrap();
    let older_verified = verify_directory_checkpoint_event_v1(
        &older_event.to_json_bytes().unwrap(),
        publisher.public_key(),
        NOW + 1,
    )
    .unwrap();
    assert_eq!(
        prepare_directory_checkpoint_acceptance_v1(older_verified, Some(&state)),
        Err(DirectoryErrorV1::CheckpointEpochRollback)
    );

    let same_timestamp_new_epoch = checkpoint(2, 8, 4);
    let same_timestamp_new_epoch = publisher
        .sign_checkpoint_event(&same_timestamp_new_epoch, NOW, &[26; 32])
        .unwrap();
    let same_timestamp_new_epoch = verify_directory_checkpoint_event_v1(
        &same_timestamp_new_epoch.to_json_bytes().unwrap(),
        publisher.public_key(),
        NOW + 1,
    )
    .unwrap();
    assert_eq!(
        prepare_directory_checkpoint_acceptance_v1(same_timestamp_new_epoch, Some(&state)),
        Err(DirectoryErrorV1::ReplaceableTimestampNotAdvanced)
    );
}

#[test]
fn complete_shard_must_exactly_match_checkpoint_event_ids() {
    let publisher = DirectoryPublisherKeyV1::from_secret_bytes([27; 32]).unwrap();
    let entry = active_entry(1, 1);
    let entry_event = signed_entry(&publisher, &entry, NOW, 28);
    let verified_entry = verify_directory_entry_event_v1(
        &entry_event.to_json_bytes().unwrap(),
        publisher.public_key(),
        NOW,
    )
    .unwrap();
    let checkpoint = DirectoryCatalogCheckpointV1::new(
        verified_entry.shard(),
        1,
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
        .sign_checkpoint_event(&checkpoint, NOW + 1, &[29; 32])
        .unwrap();
    let mut store = MemoryRollbackStoreV1::default();
    let persisted_entry = block_on(verify_and_persist_directory_entry_v1(
        &mut store,
        &entry_event.to_json_bytes().unwrap(),
        publisher.public_key(),
        NOW + 1,
    ))
    .unwrap();
    let persisted_checkpoint = block_on(verify_and_persist_directory_checkpoint_v1(
        &mut store,
        &checkpoint_event.to_json_bytes().unwrap(),
        publisher.public_key(),
        NOW + 1,
    ))
    .unwrap();
    let persisted_entries = [persisted_entry];
    let selectable =
        bind_persisted_directory_shard_catalog_v1(&persisted_checkpoint, &persisted_entries)
            .unwrap();
    assert_eq!(selectable.active_entries().count(), 1);
    assert_eq!(
        bind_persisted_directory_shard_catalog_v1(&persisted_checkpoint, &[]),
        Err(DirectoryErrorV1::CatalogEntrySetMismatch)
    );

    let foreign_publisher = DirectoryPublisherKeyV1::from_secret_bytes([30; 32]).unwrap();
    let foreign_event = signed_entry(&foreign_publisher, &entry, NOW, 31);
    let mut foreign_store = MemoryRollbackStoreV1::default();
    let foreign_persisted = block_on(verify_and_persist_directory_entry_v1(
        &mut foreign_store,
        &foreign_event.to_json_bytes().unwrap(),
        foreign_publisher.public_key(),
        NOW,
    ))
    .unwrap();
    assert_eq!(
        bind_persisted_directory_shard_catalog_v1(&persisted_checkpoint, &[foreign_persisted]),
        Err(DirectoryErrorV1::CatalogEntrySetMismatch)
    );
}

#[derive(Default)]
struct MemoryRollbackStoreV1 {
    entry: Option<(DirectoryEntryStateKeyV1, Vec<u8>)>,
    checkpoint: Option<(DirectoryCheckpointStateKeyV1, Vec<u8>)>,
    conflict_next: bool,
}

impl DirectoryRollbackStoreV1 for MemoryRollbackStoreV1 {
    type Error = &'static str;
    type LoadEntryFuture<'a> = Ready<Result<Option<Vec<u8>>, Self::Error>>;
    type CasEntryFuture<'a> = Ready<Result<DirectoryCasOutcomeV1, Self::Error>>;
    type LoadCheckpointFuture<'a> = Ready<Result<Option<Vec<u8>>, Self::Error>>;
    type CasCheckpointFuture<'a> = Ready<Result<DirectoryCasOutcomeV1, Self::Error>>;

    fn load_entry<'a>(&'a mut self, key: DirectoryEntryStateKeyV1) -> Self::LoadEntryFuture<'a> {
        ready(Ok(self
            .entry
            .as_ref()
            .filter(|(stored_key, _)| stored_key == &key)
            .map(|(_, bytes)| bytes.clone())))
    }

    fn compare_and_swap_entry<'a>(
        &'a mut self,
        key: DirectoryEntryStateKeyV1,
        expected: Option<Vec<u8>>,
        successor: Vec<u8>,
    ) -> Self::CasEntryFuture<'a> {
        if self.conflict_next {
            self.conflict_next = false;
            return ready(Ok(DirectoryCasOutcomeV1::Conflict));
        }
        let current = self
            .entry
            .as_ref()
            .filter(|(stored_key, _)| stored_key == &key)
            .map(|(_, bytes)| bytes.clone());
        if current == expected {
            self.entry = Some((key, successor));
            ready(Ok(DirectoryCasOutcomeV1::Applied))
        } else if current.as_ref() == Some(&successor) {
            ready(Ok(DirectoryCasOutcomeV1::AlreadyCurrent))
        } else {
            ready(Ok(DirectoryCasOutcomeV1::Conflict))
        }
    }

    fn load_checkpoint<'a>(
        &'a mut self,
        key: DirectoryCheckpointStateKeyV1,
    ) -> Self::LoadCheckpointFuture<'a> {
        ready(Ok(self
            .checkpoint
            .as_ref()
            .filter(|(stored_key, _)| stored_key == &key)
            .map(|(_, bytes)| bytes.clone())))
    }

    fn compare_and_swap_checkpoint<'a>(
        &'a mut self,
        key: DirectoryCheckpointStateKeyV1,
        expected: Option<Vec<u8>>,
        successor: Vec<u8>,
    ) -> Self::CasCheckpointFuture<'a> {
        let current = self
            .checkpoint
            .as_ref()
            .filter(|(stored_key, _)| stored_key == &key)
            .map(|(_, bytes)| bytes.clone());
        if current == expected {
            self.checkpoint = Some((key, successor));
            ready(Ok(DirectoryCasOutcomeV1::Applied))
        } else if current.as_ref() == Some(&successor) {
            ready(Ok(DirectoryCasOutcomeV1::AlreadyCurrent))
        } else {
            ready(Ok(DirectoryCasOutcomeV1::Conflict))
        }
    }
}

#[test]
fn async_persistence_requires_durable_cas_and_req_filters_are_bounded() {
    let publisher = DirectoryPublisherKeyV1::from_secret_bytes([31; 32]).unwrap();
    let event = signed_entry(&publisher, &active_entry(1, 1), NOW, 32);
    let event_json = event.to_json_bytes().unwrap();
    let mut store = MemoryRollbackStoreV1::default();
    let persisted = block_on(verify_and_persist_directory_entry_v1(
        &mut store,
        &event_json,
        publisher.public_key(),
        NOW,
    ))
    .unwrap();
    assert_eq!(
        persisted.disposition(),
        DirectoryAcceptanceDispositionV1::Initial
    );
    assert_eq!(
        block_on(verify_and_persist_directory_entry_v1(
            &mut store,
            &event_json,
            publisher.public_key(),
            NOW,
        ))
        .unwrap()
        .disposition(),
        DirectoryAcceptanceDispositionV1::ExactReplay
    );

    let mut conflicting_store = MemoryRollbackStoreV1 {
        conflict_next: true,
        ..MemoryRollbackStoreV1::default()
    };
    assert!(matches!(
        block_on(verify_and_persist_directory_entry_v1(
            &mut conflicting_store,
            &event_json,
            publisher.public_key(),
            NOW,
        )),
        Err(DirectoryAcceptErrorV1::ConcurrentStateChanged)
    ));

    let request_bytes = catalog_req_json_v1(publisher.public_key(), 2).unwrap();
    let request: serde_json::Value = serde_json::from_slice(&request_bytes).unwrap();
    assert_eq!(request[0], "REQ");
    assert_eq!(request[2]["kinds"][0], BITCOINPIR_DIRECTORY_KIND_V1);
    assert_eq!(request[2]["#s"][0], shard_tag_value_v1(2));
    let filter = request[2].as_object().unwrap();
    assert_eq!(filter.len(), 3);
    assert!(filter.contains_key("authors"));
    assert!(filter.contains_key("kinds"));
    assert!(filter.contains_key("#s"));
    let request_text = String::from_utf8(request_bytes).unwrap();
    for forbidden in [
        "pair",
        "peer",
        "query",
        "address",
        "method",
        "invoice",
        "payment_hash",
        "credential",
    ] {
        assert!(!request_text.contains(forbidden));
    }
    assert_eq!(
        full_catalog_req_json_v1(publisher.public_key())
            .unwrap()
            .len(),
        16
    );
    assert_eq!(
        catalog_req_json_v1(publisher.public_key(), DIRECTORY_SHARD_COUNT_V1),
        Err(DirectoryErrorV1::InvalidValue)
    );
}
