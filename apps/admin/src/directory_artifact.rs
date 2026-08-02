//! Construction and publication of directory assertions and NIP-01 messages.
//!
//! Artifact construction performs no network I/O. Every artifact is decoded
//! and verified through the production protocol implementation before an
//! atomic 0600 write. The explicit `publish` subcommand delegates transport to
//! `directory_publish` and never loads a signing key.

use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand, ValueEnum};
use ed25519_dalek::VerifyingKey;
use pir_directory_nostr::{
    verify_directory_checkpoint_event_v1, verify_directory_entry_event_for_operator_v1,
    verify_directory_entry_event_v1, DirectoryCatalogCheckpointV1, DirectoryCatalogHintV1,
    DirectoryCheckpointEntryV1, DirectoryEntryV1, DirectoryHealthClassV1, DirectoryHealthV1,
    DirectoryPublisherKeyV1, NostrEventV1, DIRECTORY_SHARD_COUNT_V1, MAX_NOSTR_EVENT_BYTES_V1,
};
use pir_service_protocol::{
    derive_provider_id, DirectoryAssertionRollbackGuardV1, DirectoryEndpointV1,
    DirectoryOperatorAssertionV1, DirectoryTransportV1, PolicyRollbackGuardV1,
    ServicePolicyEpochFloorsV1, ServicePolicyV1, MAX_DIRECTORY_ASSERTION_LEN_V1,
    MAX_SIGNED_POLICY_LEN,
};
use serde_json::value::RawValue;

pub(crate) const MAX_EVENT_MESSAGE_BYTES_V1: usize = MAX_NOSTR_EVENT_BYTES_V1 + 32;
pub(crate) const MAX_CHECKPOINT_BUNDLE_BYTES_V1: usize =
    MAX_EVENT_MESSAGE_BYTES_V1 * DIRECTORY_SHARD_COUNT_V1 as usize + 2;
const MAX_ENTRY_INPUTS_V1: usize = 16 * 1_024;

#[derive(Args, Debug)]
pub struct DirectoryArtifactArgs {
    #[command(subcommand)]
    command: DirectoryArtifactCommand,
}

#[derive(Subcommand, Debug)]
enum DirectoryArtifactCommand {
    /// Bind an operator identity/endpoints to one already-signed policy.
    Assertion(AssertionArgs),
    /// Build one signed NIP-01 EVENT message for a provider entry.
    Entry(EntryArgs),
    /// Retire one provider ID without advertising an operator assertion or offers.
    Tombstone(TombstoneArgs),
    /// Build one signed checkpoint EVENT for each of the 16 coarse shards.
    Checkpoints(CheckpointArgs),
    /// Publish already-signed EVENT artifacts unchanged to every relay.
    Publish(crate::directory_publish::DirectoryPublishArgs),
}

#[derive(Args, Debug)]
struct AssertionArgs {
    #[arg(long)]
    policy: PathBuf,
    #[arg(long)]
    policy_signing_key_hex: String,
    #[arg(long)]
    operator_signing_key: PathBuf,
    #[arg(long)]
    stable_server_id: String,
    #[arg(long)]
    assertion_epoch: u64,
    #[arg(long)]
    not_before: u64,
    #[arg(long)]
    valid_until: u64,
    /// Canonical public wss URL. Repeat for multiple independently reachable endpoints.
    #[arg(long = "endpoint", required = true)]
    endpoints: Vec<String>,
    #[arg(long)]
    now_unix: u64,
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    force: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum HealthClassArg {
    Unknown,
    Available,
    Degraded,
    Unavailable,
}

impl From<HealthClassArg> for DirectoryHealthClassV1 {
    fn from(value: HealthClassArg) -> Self {
        match value {
            HealthClassArg::Unknown => Self::Unknown,
            HealthClassArg::Available => Self::Available,
            HealthClassArg::Degraded => Self::Degraded,
            HealthClassArg::Unavailable => Self::Unavailable,
        }
    }
}

#[derive(Args, Debug)]
struct EntryArgs {
    #[arg(long)]
    assertion: PathBuf,
    #[arg(long)]
    policy: PathBuf,
    #[arg(long)]
    policy_signing_key_hex: String,
    #[arg(long)]
    directory_signing_key: PathBuf,
    /// Additional x-only secp256k1 role key which the directory key must not equal.
    #[arg(long = "reserved-xonly-pubkey-hex")]
    reserved_xonly_pubkey_hex: Vec<String>,
    #[arg(long)]
    directory_sequence: u64,
    #[arg(long)]
    directory_valid_until: u64,
    #[arg(long)]
    created_at: u64,
    #[arg(long, value_enum, default_value = "unknown")]
    health_class: HealthClassArg,
    /// Unix seconds floored to the directory's five-minute health bucket.
    #[arg(long)]
    health_observed_bucket: u64,
    #[arg(long)]
    now_unix: u64,
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    force: bool,
}

#[derive(Args, Debug)]
struct TombstoneArgs {
    /// Retired provider ID as 32-byte lowercase hexadecimal.
    #[arg(long)]
    provider_id_hex: String,
    #[arg(long)]
    directory_signing_key: PathBuf,
    /// Additional x-only secp256k1 role key which the directory key must not equal.
    #[arg(long = "reserved-xonly-pubkey-hex")]
    reserved_xonly_pubkey_hex: Vec<String>,
    #[arg(long)]
    directory_sequence: u64,
    #[arg(long)]
    directory_valid_until: u64,
    #[arg(long, value_enum, default_value = "unavailable")]
    health_class: HealthClassArg,
    /// Unix seconds floored to the directory's five-minute health bucket.
    #[arg(long)]
    health_observed_bucket: u64,
    #[arg(long)]
    created_at: u64,
    #[arg(long)]
    now_unix: u64,
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    force: bool,
}

#[derive(Args, Debug)]
struct CheckpointArgs {
    /// One NIP-01 ["EVENT", event] entry artifact. Repeat for every provider.
    #[arg(long = "entry-event")]
    entry_events: Vec<PathBuf>,
    #[arg(long)]
    directory_signing_key: PathBuf,
    /// Additional x-only secp256k1 role key which the directory key must not equal.
    #[arg(long = "reserved-xonly-pubkey-hex")]
    reserved_xonly_pubkey_hex: Vec<String>,
    #[arg(long)]
    checkpoint_epoch: u64,
    #[arg(long)]
    not_before: u64,
    #[arg(long)]
    valid_until: u64,
    #[arg(long)]
    created_at: u64,
    #[arg(long)]
    now_unix: u64,
    /// Atomic JSON array containing exactly 16 NIP-01 EVENT messages.
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    force: bool,
}

pub async fn run(args: DirectoryArtifactArgs) -> Result<(), String> {
    match args.command {
        DirectoryArtifactCommand::Assertion(args) => build_assertion(args),
        DirectoryArtifactCommand::Entry(args) => build_entry(args),
        DirectoryArtifactCommand::Tombstone(args) => build_tombstone(args),
        DirectoryArtifactCommand::Checkpoints(args) => build_checkpoints(args),
        DirectoryArtifactCommand::Publish(args) => crate::directory_publish::run(args).await,
    }
}

fn build_assertion(args: AssertionArgs) -> Result<(), String> {
    require_nonzero_time(args.now_unix)?;
    validate_stable_server_id(&args.stable_server_id)?;
    let policy_public = decode_lower_fixed_hex::<32>(
        &args.policy_signing_key_hex,
        "service-policy signing public key",
    )?;
    let policy_verifying = VerifyingKey::from_bytes(&policy_public)
        .map_err(|_| "service-policy signing public key is not valid Ed25519".to_owned())?;
    let operator_key = crate::keygen::read_secret_key(&args.operator_signing_key)?;
    let operator_public = operator_key.verifying_key().to_bytes();
    if operator_public == policy_public {
        return Err("operator and service-policy signing keys must be distinct".to_owned());
    }
    let provider_id = derive_provider_id(&operator_public, &args.stable_server_id);
    let policy =
        read_and_verify_policy(&args.policy, &provider_id, args.now_unix, &policy_verifying)?;
    if args.not_before < policy.issued_at || args.valid_until > policy.expires_at {
        return Err(
            "operator assertion validity must be contained in the signed policy window".to_owned(),
        );
    }
    let mut endpoints: Vec<_> = args
        .endpoints
        .into_iter()
        .map(|url| DirectoryEndpointV1 {
            transport: DirectoryTransportV1::Wss,
            url,
        })
        .collect();
    endpoints.sort();
    let assertion = DirectoryOperatorAssertionV1::sign(
        args.stable_server_id,
        args.assertion_epoch,
        args.not_before,
        args.valid_until,
        endpoints,
        policy_public,
        policy.policy_epoch,
        policy
            .policy_digest()
            .map_err(|error| format!("policy digest failed: {error}"))?,
        &operator_key,
    )
    .map_err(|error| format!("operator assertion signing failed: {error}"))?;
    assertion
        .verify_current_for(
            &provider_id,
            &operator_public,
            args.now_unix,
            &DirectoryAssertionRollbackGuardV1::initial(),
        )
        .map_err(|error| format!("operator assertion self-verification failed: {error}"))?;
    let bytes = assertion
        .encode()
        .map_err(|error| format!("operator assertion encoding failed: {error}"))?;
    if DirectoryOperatorAssertionV1::decode(&bytes)
        .map_err(|error| format!("operator assertion decode self-check failed: {error}"))?
        != assertion
    {
        return Err("operator assertion encode/decode self-check changed the artifact".to_owned());
    }
    write_atomic_private(&args.out, &bytes, args.force)?;
    println!("provider_id={}", hex::encode(provider_id));
    println!("operator_pubkey_ed25519={}", hex::encode(operator_public));
    println!("policy_signing_key_ed25519={}", hex::encode(policy_public));
    println!(
        "assertion_digest={}",
        hex::encode(
            assertion
                .assertion_digest()
                .map_err(|error| error.to_string())?
        )
    );
    Ok(())
}

fn build_entry(args: EntryArgs) -> Result<(), String> {
    require_nonzero_time(args.now_unix)?;
    if args.created_at == 0 || args.created_at > args.now_unix {
        return Err("--created-at must be non-zero and no later than --now-unix".to_owned());
    }
    let assertion_bytes = read_public_bounded(
        &args.assertion,
        MAX_DIRECTORY_ASSERTION_LEN_V1,
        "operator assertion",
    )?;
    let assertion = DirectoryOperatorAssertionV1::decode(&assertion_bytes)
        .map_err(|error| format!("invalid operator assertion: {error}"))?;
    if assertion.encode().map_err(|error| error.to_string())? != assertion_bytes {
        return Err("operator assertion is not canonical".to_owned());
    }
    assertion
        .verify_current_for(
            &assertion.provider_id,
            &assertion.operator_pubkey_ed25519,
            args.now_unix,
            &DirectoryAssertionRollbackGuardV1::initial(),
        )
        .map_err(|error| format!("operator assertion verification failed: {error}"))?;

    let policy_public = decode_lower_fixed_hex::<32>(
        &args.policy_signing_key_hex,
        "service-policy signing public key",
    )?;
    if assertion.policy_signing_key_ed25519 != policy_public {
        return Err("operator assertion does not bind the supplied policy key".to_owned());
    }
    let policy_verifying = VerifyingKey::from_bytes(&policy_public)
        .map_err(|_| "service-policy signing public key is not valid Ed25519".to_owned())?;
    let policy = read_and_verify_policy(
        &args.policy,
        &assertion.provider_id,
        args.now_unix,
        &policy_verifying,
    )?;
    if assertion.policy_epoch != policy.policy_epoch
        || assertion.policy_digest
            != policy
                .policy_digest()
                .map_err(|error| format!("policy digest failed: {error}"))?
    {
        return Err("operator assertion does not bind the exact signed policy".to_owned());
    }

    let hints = catalog_hints_from_policy(&policy)?;
    let entry = DirectoryEntryV1::new_active(
        args.directory_sequence,
        args.directory_valid_until,
        assertion.clone(),
        hints,
        DirectoryHealthV1 {
            class: args.health_class.into(),
            observed_bucket: args.health_observed_bucket,
        },
        args.now_unix,
    )
    .map_err(|error| format!("directory entry validation failed: {error}"))?;
    let reserved = decode_reserved_xonly_keys(&args.reserved_xonly_pubkey_hex)?;
    let publisher = load_directory_key(
        &args.directory_signing_key,
        &[assertion.operator_pubkey_ed25519, policy_public],
        &reserved,
    )?;
    let auxiliary_randomness = fresh_auxiliary_randomness()?;
    let event = publisher
        .sign_entry_event(&entry, args.created_at, &auxiliary_randomness)
        .map_err(|error| format!("directory entry EVENT signing failed: {error}"))?;
    let event_json = event
        .to_json_bytes()
        .map_err(|error| format!("directory entry EVENT encoding failed: {error}"))?;
    let verified = verify_directory_entry_event_for_operator_v1(
        &event_json,
        publisher.public_key(),
        entry.provider_id(),
        &assertion.operator_pubkey_ed25519,
        args.now_unix,
    )
    .map_err(|error| format!("directory entry EVENT self-verification failed: {error}"))?;
    if verified.discovery_entry() != &entry {
        return Err("directory entry EVENT self-check changed the entry".to_owned());
    }
    let message = event
        .to_event_message_json_bytes()
        .map_err(|error| format!("NIP-01 EVENT message encoding failed: {error}"))?;
    let reparsed = parse_event_message(&message, "generated directory entry EVENT")?;
    if reparsed != event_json {
        return Err("NIP-01 EVENT envelope self-check changed the event".to_owned());
    }
    write_atomic_private(&args.out, &message, args.force)?;
    println!(
        "directory_pubkey_xonly={}",
        hex::encode(publisher.public_key())
    );
    println!("provider_id={}", hex::encode(entry.provider_id()));
    println!("event_id={}", hex::encode(event.id()));
    println!("shard={:x}", verified.shard());
    Ok(())
}

fn build_tombstone(args: TombstoneArgs) -> Result<(), String> {
    require_nonzero_time(args.now_unix)?;
    if args.created_at == 0 || args.created_at > args.now_unix {
        return Err("--created-at must be non-zero and no later than --now-unix".to_owned());
    }
    let provider_id = decode_lower_fixed_hex::<32>(&args.provider_id_hex, "provider ID")?;
    let reserved = decode_reserved_xonly_keys(&args.reserved_xonly_pubkey_hex)?;
    let publisher = load_directory_key(&args.directory_signing_key, &[], &reserved)?;
    let entry = DirectoryEntryV1::new_tombstone(
        provider_id,
        args.directory_sequence,
        args.directory_valid_until,
        DirectoryHealthV1 {
            class: args.health_class.into(),
            observed_bucket: args.health_observed_bucket,
        },
        args.now_unix,
    )
    .map_err(|error| format!("directory tombstone validation failed: {error}"))?;
    let auxiliary_randomness = fresh_auxiliary_randomness()?;
    let event = publisher
        .sign_entry_event(&entry, args.created_at, &auxiliary_randomness)
        .map_err(|error| format!("directory tombstone EVENT signing failed: {error}"))?;
    let event_json = event
        .to_json_bytes()
        .map_err(|error| format!("directory tombstone EVENT encoding failed: {error}"))?;
    let verified =
        verify_directory_entry_event_v1(&event_json, publisher.public_key(), args.now_unix)
            .map_err(|error| {
                format!("directory tombstone EVENT self-verification failed: {error}")
            })?;
    if verified.discovery_entry() != &entry {
        return Err("directory tombstone EVENT self-check changed the entry".to_owned());
    }
    let message = event
        .to_event_message_json_bytes()
        .map_err(|error| format!("directory tombstone EVENT envelope failed: {error}"))?;
    if parse_event_message(&message, "generated directory tombstone EVENT")? != event_json {
        return Err("directory tombstone EVENT envelope changed the event".to_owned());
    }
    write_atomic_private(&args.out, &message, args.force)?;
    println!(
        "directory_pubkey_xonly={}",
        hex::encode(publisher.public_key())
    );
    println!("provider_id={}", hex::encode(entry.provider_id()));
    println!("event_id={}", hex::encode(event.id()));
    println!("shard={:x}", verified.shard());
    Ok(())
}

fn build_checkpoints(args: CheckpointArgs) -> Result<(), String> {
    require_nonzero_time(args.now_unix)?;
    if args.created_at == 0 || args.created_at > args.now_unix {
        return Err("--created-at must be non-zero and no later than --now-unix".to_owned());
    }
    if args.entry_events.len() > MAX_ENTRY_INPUTS_V1 {
        return Err(format!(
            "too many --entry-event inputs (maximum {MAX_ENTRY_INPUTS_V1})"
        ));
    }
    let reserved = decode_reserved_xonly_keys(&args.reserved_xonly_pubkey_hex)?;
    let (publisher, directory_seed_ed25519_public) =
        load_directory_key_with_ed25519_public(&args.directory_signing_key, &[], &reserved)?;
    let mut seen_providers = BTreeSet::new();
    let mut shards: [Vec<DirectoryCheckpointEntryV1>; DIRECTORY_SHARD_COUNT_V1 as usize] =
        std::array::from_fn(|_| Vec::new());
    for path in &args.entry_events {
        let message = read_public_bounded(path, MAX_EVENT_MESSAGE_BYTES_V1, "entry EVENT")?;
        let event_json = parse_event_message(&message, "entry EVENT")?;
        let verified =
            verify_directory_entry_event_v1(&event_json, publisher.public_key(), args.now_unix)
                .map_err(|error| {
                    format!("{} is not a valid entry EVENT: {error}", path.display())
                })?;
        let entry = verified.discovery_entry();
        if let Some(assertion) = entry.operator_assertion() {
            if directory_seed_ed25519_public == assertion.operator_pubkey_ed25519
                || directory_seed_ed25519_public == assertion.policy_signing_key_ed25519
            {
                return Err(format!(
                    "{} reuses the directory secret seed for an Ed25519 operator/policy role",
                    path.display()
                ));
            }
        }
        if !seen_providers.insert(*entry.provider_id()) {
            return Err(format!(
                "duplicate provider entry input: {}",
                hex::encode(entry.provider_id())
            ));
        }
        shards[usize::from(verified.shard())].push(DirectoryCheckpointEntryV1 {
            provider_id: *entry.provider_id(),
            directory_sequence: entry.directory_sequence(),
            event_id: *verified.event().id(),
        });
    }

    let mut messages = Vec::with_capacity(DIRECTORY_SHARD_COUNT_V1 as usize);
    for shard in 0..DIRECTORY_SHARD_COUNT_V1 {
        let entries = &mut shards[usize::from(shard)];
        entries.sort_by_key(|entry| entry.provider_id);
        let checkpoint = DirectoryCatalogCheckpointV1::new(
            shard,
            args.checkpoint_epoch,
            args.not_before,
            args.valid_until,
            entries.clone(),
            args.now_unix,
        )
        .map_err(|error| format!("checkpoint {shard:x} validation failed: {error}"))?;
        let auxiliary_randomness = fresh_auxiliary_randomness()?;
        let event = publisher
            .sign_checkpoint_event(&checkpoint, args.created_at, &auxiliary_randomness)
            .map_err(|error| format!("checkpoint {shard:x} EVENT signing failed: {error}"))?;
        let event_json = event
            .to_json_bytes()
            .map_err(|error| format!("checkpoint {shard:x} EVENT encoding failed: {error}"))?;
        let verified = verify_directory_checkpoint_event_v1(
            &event_json,
            publisher.public_key(),
            args.now_unix,
        )
        .map_err(|error| format!("checkpoint {shard:x} self-verification failed: {error}"))?;
        if verified.checkpoint() != &checkpoint {
            return Err(format!(
                "checkpoint {shard:x} self-check changed the artifact"
            ));
        }
        let message = event
            .to_event_message_json_bytes()
            .map_err(|error| format!("checkpoint {shard:x} envelope failed: {error}"))?;
        if parse_event_message(&message, "generated checkpoint EVENT")? != event_json {
            return Err(format!("checkpoint {shard:x} envelope changed the event"));
        }
        messages.push(message);
    }
    let bundle = encode_json_array(&messages, MAX_CHECKPOINT_BUNDLE_BYTES_V1)?;
    write_atomic_private(&args.out, &bundle, args.force)?;
    println!(
        "directory_pubkey_xonly={}",
        hex::encode(publisher.public_key())
    );
    println!("checkpoint_epoch={}", args.checkpoint_epoch);
    println!("checkpoint_count={}", messages.len());
    println!("entry_count={}", seen_providers.len());
    Ok(())
}

fn read_and_verify_policy(
    path: &Path,
    provider_id: &[u8; 32],
    now_unix: u64,
    policy_key: &VerifyingKey,
) -> Result<ServicePolicyV1, String> {
    let bytes = read_public_bounded(path, MAX_SIGNED_POLICY_LEN, "signed service policy")?;
    let policy = ServicePolicyV1::decode(&bytes)
        .map_err(|error| format!("invalid signed service policy: {error}"))?;
    if policy.encode().map_err(|error| error.to_string())? != bytes {
        return Err("signed service policy is not canonical".to_owned());
    }
    policy
        .verify_current_for_acquisition(
            provider_id,
            now_unix,
            &PolicyRollbackGuardV1::initial(),
            &ServicePolicyEpochFloorsV1::initial(),
            policy_key,
        )
        .map_err(|error| format!("signed service policy verification failed: {error}"))?;
    Ok(policy)
}

fn catalog_hints_from_policy(
    policy: &ServicePolicyV1,
) -> Result<Vec<DirectoryCatalogHintV1>, String> {
    let mut hints = Vec::new();
    for scope in &policy.scopes {
        for offer in &scope.offers {
            hints.push(DirectoryCatalogHintV1 {
                scope_id: scope.scope.scope_id(),
                backend: scope.scope.backend,
                workload: scope.scope.workload,
                acquisition: offer.acquisition,
                authorization: offer.authorization,
                deployment: offer.deployment_status,
            });
        }
    }
    hints.sort_by_key(|hint| {
        (
            hint.scope_id,
            hint.backend as u8,
            hint.workload as u8,
            hint.acquisition as u8,
            hint.authorization as u8,
            hint.deployment as u8,
        )
    });
    hints.dedup();
    if hints.is_empty() {
        return Err("signed policy contains no directory-advertisable offers".to_owned());
    }
    Ok(hints)
}

fn load_directory_key(
    path: &Path,
    forbidden_ed25519_public_keys: &[[u8; 32]],
    reserved_xonly_keys: &[[u8; 32]],
) -> Result<DirectoryPublisherKeyV1, String> {
    load_directory_key_with_ed25519_public(path, forbidden_ed25519_public_keys, reserved_xonly_keys)
        .map(|value| value.0)
}

fn load_directory_key_with_ed25519_public(
    path: &Path,
    forbidden_ed25519_public_keys: &[[u8; 32]],
    reserved_xonly_keys: &[[u8; 32]],
) -> Result<(DirectoryPublisherKeyV1, [u8; 32]), String> {
    // `read_secret_key` is the admin tool's single-FD O_NOFOLLOW, owner/mode,
    // exact-length loader. Ed25519 accepts every 32-byte seed, allowing this
    // wrapper to reuse that audited loader before the same bytes are parsed as
    // a BIP340 secret by `DirectoryPublisherKeyV1`.
    let loaded = crate::keygen::read_secret_key(path)?;
    let ed25519_public = loaded.verifying_key().to_bytes();
    if forbidden_ed25519_public_keys.contains(&ed25519_public) {
        return Err(
            "directory signing secret must not reuse an operator or policy Ed25519 seed".to_owned(),
        );
    }
    let publisher = DirectoryPublisherKeyV1::from_secret_bytes(loaded.to_bytes())
        .map_err(|error| format!("invalid directory BIP340 signing key: {error}"))?;
    publisher
        .ensure_distinct_from_xonly_keys(reserved_xonly_keys)
        .map_err(|_| "directory key equals a reserved x-only role key".to_owned())?;
    Ok((publisher, ed25519_public))
}

fn decode_reserved_xonly_keys(values: &[String]) -> Result<Vec<[u8; 32]>, String> {
    values
        .iter()
        .map(|value| decode_lower_fixed_hex(value, "reserved x-only public key"))
        .collect()
}

pub(crate) fn parse_event_message(bytes: &[u8], label: &str) -> Result<Vec<u8>, String> {
    if bytes.is_empty() || bytes.len() > MAX_EVENT_MESSAGE_BYTES_V1 {
        return Err(format!("{label} size is outside the allowed bound"));
    }
    let (verb, raw): (String, Box<RawValue>) =
        serde_json::from_slice(bytes).map_err(|error| format!("invalid {label}: {error}"))?;
    if verb != "EVENT" {
        return Err(format!("{label} must be a NIP-01 EVENT message"));
    }
    let raw = raw.get().as_bytes();
    let event = NostrEventV1::parse_json(raw)
        .map_err(|error| format!("invalid {label} event object: {error}"))?;
    event
        .to_json_bytes()
        .map_err(|error| format!("{label} event encoding failed: {error}"))
}

pub(crate) fn encode_json_array(items: &[Vec<u8>], max: usize) -> Result<Vec<u8>, String> {
    let estimated = items.iter().try_fold(2usize, |total, item| {
        total
            .checked_add(item.len())
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| "artifact bundle length overflow".to_owned())
    })?;
    if estimated > max {
        return Err("artifact bundle exceeds the output bound".to_owned());
    }
    let mut out = Vec::with_capacity(estimated);
    out.push(b'[');
    for (index, item) in items.iter().enumerate() {
        if index != 0 {
            out.push(b',');
        }
        out.extend_from_slice(item);
    }
    out.push(b']');
    if out.len() > max {
        return Err("artifact bundle exceeds the output bound".to_owned());
    }
    Ok(out)
}

fn fresh_auxiliary_randomness() -> Result<[u8; 32], String> {
    let mut value = [0u8; 32];
    getrandom::getrandom(&mut value)
        .map_err(|error| format!("OS randomness unavailable for BIP340 signing: {error}"))?;
    Ok(value)
}

fn require_nonzero_time(now_unix: u64) -> Result<(), String> {
    if now_unix == 0 {
        Err("--now-unix must be non-zero".to_owned())
    } else {
        Ok(())
    }
}

fn validate_stable_server_id(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        Err("stable server ID must be non-empty, bounded, and contain no controls".to_owned())
    } else {
        Ok(())
    }
}

fn decode_lower_fixed_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{label} must be exactly {N} bytes of lowercase hex"
        ));
    }
    hex::decode(value)
        .map_err(|_| format!("{label} is invalid hex"))?
        .try_into()
        .map_err(|_| format!("{label} must be exactly {N} bytes"))
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PublicFileSnapshotV1 {
    device: u128,
    inode: u128,
    mode: u64,
    size: i128,
    modified_seconds: i128,
    modified_nanoseconds: i128,
    changed_seconds: i128,
    changed_nanoseconds: i128,
}

#[cfg(unix)]
fn public_file_snapshot_v1(stat: &rustix::fs::Stat) -> PublicFileSnapshotV1 {
    PublicFileSnapshotV1 {
        device: stat.st_dev as u128,
        inode: stat.st_ino as u128,
        mode: stat.st_mode as u64,
        size: stat.st_size as i128,
        modified_seconds: stat.st_mtime as i128,
        modified_nanoseconds: stat.st_mtime_nsec as i128,
        changed_seconds: stat.st_ctime as i128,
        changed_nanoseconds: stat.st_ctime_nsec as i128,
    }
}

#[cfg(unix)]
pub(crate) fn read_public_bounded(path: &Path, max: usize, label: &str) -> Result<Vec<u8>, String> {
    use rustix::fs::{self as rustix_fs, FileType, Mode, OFlags};

    let fd = rustix_fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| format!("open {label} {} failed: {error}", path.display()))?;
    let stat = rustix_fs::fstat(&fd)
        .map_err(|error| format!("inspect {label} {} failed: {error}", path.display()))?;
    let snapshot = public_file_snapshot_v1(&stat);
    if !FileType::from_raw_mode(stat.st_mode).is_file() || stat.st_size <= 0 {
        return Err(format!("{label} must be a non-empty regular file"));
    }
    let length = usize::try_from(stat.st_size).map_err(|_| format!("{label} is too large"))?;
    if length > max {
        return Err(format!("{label} exceeds the {max}-byte bound"));
    }
    let file = fs::File::from(fd);
    let mut bytes = Vec::with_capacity(length);
    (&file)
        .take((max as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read {label} {} failed: {error}", path.display()))?;
    let after = rustix_fs::fstat(&file)
        .map_err(|error| format!("reinspect {label} {} failed: {error}", path.display()))?;
    if bytes.len() != length || bytes.len() > max || public_file_snapshot_v1(&after) != snapshot {
        return Err(format!("{label} changed while it was read"));
    }
    Ok(bytes)
}

#[cfg(not(unix))]
pub(crate) fn read_public_bounded(path: &Path, max: usize, label: &str) -> Result<Vec<u8>, String> {
    let _ = (path, max);
    Err(format!(
        "reading {label} requires a local Unix/POSIX filesystem"
    ))
}

#[cfg(unix)]
fn write_atomic_private(path: &Path, bytes: &[u8], force: bool) -> Result<(), String> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    if bytes.is_empty() {
        return Err("refusing to write an empty directory artifact".to_owned());
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent_meta = fs::symlink_metadata(parent)
        .map_err(|error| format!("inspect output parent {} failed: {error}", parent.display()))?;
    if !parent_meta.file_type().is_dir() || parent_meta.file_type().is_symlink() {
        return Err("output parent must be a non-symlink directory".to_owned());
    }
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "output path must have a UTF-8 file name".to_owned())?;
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce)
        .map_err(|error| format!("OS randomness unavailable for atomic output: {error}"))?;
    let temporary = parent.join(format!(".{file_name}.{}.tmp", hex::encode(nonce)));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|error| format!("create temporary artifact failed: {error}"))?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| format!("write temporary artifact failed: {error}"))?;
        let mode = file
            .metadata()
            .map_err(|error| format!("inspect temporary artifact failed: {error}"))?
            .permissions()
            .mode()
            & 0o777;
        if mode != 0o600 {
            return Err(format!("temporary artifact mode is {mode:o}, expected 600"));
        }
        drop(file);
        if force {
            fs::rename(&temporary, path).map_err(|error| {
                format!("atomically replace {} failed: {error}", path.display())
            })?;
        } else {
            fs::hard_link(&temporary, path)
                .map_err(|error| format!("atomically create {} failed: {error}", path.display()))?;
            fs::remove_file(&temporary)
                .map_err(|error| format!("remove temporary link failed: {error}"))?;
        }
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("sync output directory failed: {error}"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(unix)]
pub(crate) fn write_atomic_private_no_replace_v1(path: &Path, bytes: &[u8]) -> Result<(), String> {
    write_atomic_private_no_replace_with_hook_v1(path, bytes, |_| Ok(()))
}

#[cfg(unix)]
pub(crate) fn require_private_output_absent_v1(path: &Path) -> Result<(), String> {
    use rustix::fs::{self as rustix_fs, AtFlags, FileType, Mode, OFlags};

    let parent_path = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| "private output path must have a file name".to_owned())?;
    let parent_fd = rustix_fs::open(
        parent_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| format!("open private output parent failed: {error}"))?;
    let parent_stat = rustix_fs::fstat(&parent_fd)
        .map_err(|error| format!("inspect private output parent failed: {error}"))?;
    let parent_snapshot = private_output_parent_v1(&parent_stat);
    if !FileType::from_raw_mode(parent_stat.st_mode).is_dir()
        || parent_stat.st_uid != rustix::process::geteuid().as_raw()
        || parent_stat.st_gid != rustix::process::getegid().as_raw()
        || parent_stat.st_mode & 0o7777 != 0o700
    {
        return Err("private output parent must be an owner-matched 0700 directory".to_owned());
    }
    match rustix_fs::statat(&parent_fd, file_name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => {
            return Err(format!(
                "immutable private output already exists: {}",
                path.display()
            ));
        }
        Err(rustix::io::Errno::NOENT) => {}
        Err(error) => return Err(format!("inspect private output target failed: {error}")),
    }
    validate_private_output_parent_v1(parent_path, parent_snapshot)
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrivateNoReplaceCommitPointV1 {
    BeforePublish,
    AfterPublish,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PrivateOutputParentV1 {
    device: u128,
    inode: u128,
    gid: u32,
    mode: u64,
    uid: u32,
}

#[cfg(unix)]
fn private_output_parent_v1(stat: &rustix::fs::Stat) -> PrivateOutputParentV1 {
    PrivateOutputParentV1 {
        device: stat.st_dev as u128,
        inode: stat.st_ino as u128,
        gid: stat.st_gid,
        mode: stat.st_mode as u64,
        uid: stat.st_uid,
    }
}

#[cfg(unix)]
fn validate_private_output_parent_v1(
    parent_path: &Path,
    expected: PrivateOutputParentV1,
) -> Result<(), String> {
    use rustix::fs::{self as rustix_fs, FileType, Mode, OFlags};

    let reopened = rustix_fs::open(
        parent_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| format!("reopen output parent failed: {error}"))?;
    let stat = rustix_fs::fstat(&reopened)
        .map_err(|error| format!("reinspect output parent failed: {error}"))?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || private_output_parent_v1(&stat) != expected
    {
        return Err("output parent pathname or private generation changed".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
fn validate_committed_private_output_at_v1(
    parent: &fs::File,
    parent_path: &Path,
    parent_snapshot: PrivateOutputParentV1,
    file_name: &std::ffi::OsStr,
    expected: &[u8],
    committed_identity: (u128, u128),
) -> Result<(), String> {
    use rustix::fs::{self as rustix_fs, FileType, Mode, OFlags};

    let fd = rustix_fs::openat(
        parent,
        file_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| format!("open existing output failed: {error}"))?;
    let before = rustix_fs::fstat(&fd)
        .map_err(|error| format!("inspect existing output failed: {error}"))?;
    if !FileType::from_raw_mode(before.st_mode).is_file()
        || before.st_nlink != 1
        || before.st_mode & 0o7777 != 0o600
        || before.st_uid != rustix::process::geteuid().as_raw()
        || before.st_gid != rustix::process::getegid().as_raw()
        || usize::try_from(before.st_size).ok() != Some(expected.len())
        || before.st_dev as u128 != committed_identity.0
        || before.st_ino as u128 != committed_identity.1
    {
        return Err(
            "committed output metadata is not the exact owner-only 0600 one-link regular data"
                .to_owned(),
        );
    }
    let before_snapshot = public_file_snapshot_v1(&before);
    let file = fs::File::from(fd);
    let mut observed = Vec::with_capacity(expected.len());
    (&file)
        .take((expected.len() as u64).saturating_add(1))
        .read_to_end(&mut observed)
        .map_err(|error| format!("read committed output failed: {error}"))?;
    let after = rustix_fs::fstat(&file)
        .map_err(|error| format!("reinspect committed output failed: {error}"))?;
    if observed != expected || public_file_snapshot_v1(&after) != before_snapshot {
        return Err("committed output bytes or descriptor generation differ".to_owned());
    }
    let confirmation = rustix_fs::openat(
        parent,
        file_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| format!("reopen committed output failed: {error}"))?;
    let confirmed = rustix_fs::fstat(&confirmation)
        .map_err(|error| format!("confirm committed output failed: {error}"))?;
    if public_file_snapshot_v1(&confirmed) != before_snapshot {
        return Err("committed output pathname changed during validation".to_owned());
    }
    validate_private_output_parent_v1(parent_path, parent_snapshot)?;
    parent
        .sync_all()
        .map_err(|error| format!("sync committed output directory failed: {error}"))?;
    Ok(())
}

#[cfg(unix)]
fn write_atomic_private_no_replace_with_hook_v1<F>(
    path: &Path,
    bytes: &[u8],
    mut commit_hook: F,
) -> Result<(), String>
where
    F: FnMut(PrivateNoReplaceCommitPointV1) -> Result<(), String>,
{
    use rustix::fs::{self as rustix_fs, AtFlags, FileType, Mode, OFlags, RenameFlags};

    if bytes.is_empty() {
        return Err("refusing to write an empty private output".to_owned());
    }
    let parent_path = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| "private output path must have a file name".to_owned())?;
    let parent_fd = rustix_fs::open(
        parent_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| format!("open private output parent failed: {error}"))?;
    let parent = fs::File::from(parent_fd);
    let parent_stat = rustix_fs::fstat(&parent)
        .map_err(|error| format!("inspect private output parent failed: {error}"))?;
    let parent_snapshot = private_output_parent_v1(&parent_stat);
    if !FileType::from_raw_mode(parent_stat.st_mode).is_dir()
        || parent_stat.st_uid != rustix::process::geteuid().as_raw()
        || parent_stat.st_gid != rustix::process::getegid().as_raw()
        || parent_stat.st_mode & 0o7777 != 0o700
    {
        return Err("private output parent must be an owner-matched 0700 directory".to_owned());
    }

    let target_name = file_name
        .to_str()
        .ok_or_else(|| "private output path must have a UTF-8 file name".to_owned())?;
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce)
        .map_err(|error| format!("OS randomness unavailable for atomic output: {error}"))?;
    let temporary = format!(".{target_name}.{}.tmp", hex::encode(nonce));
    let mut temporary_created = false;
    let result = (|| {
        let fd = rustix_fs::openat(
            &parent,
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|error| format!("create private output temporary failed: {error}"))?;
        temporary_created = true;
        rustix_fs::fchmod(&fd, Mode::RUSR | Mode::WUSR)
            .map_err(|error| format!("secure private output temporary failed: {error}"))?;
        let mut temporary_file = fs::File::from(fd);
        temporary_file
            .write_all(bytes)
            .and_then(|()| temporary_file.sync_all())
            .map_err(|error| format!("write private output temporary failed: {error}"))?;
        let temporary_stat = rustix_fs::fstat(&temporary_file)
            .map_err(|error| format!("inspect private output temporary failed: {error}"))?;
        if !FileType::from_raw_mode(temporary_stat.st_mode).is_file()
            || temporary_stat.st_nlink != 1
            || temporary_stat.st_uid != rustix::process::geteuid().as_raw()
            || temporary_stat.st_gid != rustix::process::getegid().as_raw()
            || temporary_stat.st_mode & 0o7777 != 0o600
            || usize::try_from(temporary_stat.st_size).ok() != Some(bytes.len())
        {
            return Err(
                "private output temporary failed owner/mode/link/length validation".to_owned(),
            );
        }
        let committed_identity = (temporary_stat.st_dev as u128, temporary_stat.st_ino as u128);
        drop(temporary_file);
        parent.sync_all().map_err(|error| {
            format!("sync private output temporary directory entry failed: {error}")
        })?;
        validate_private_output_parent_v1(parent_path, parent_snapshot)?;
        commit_hook(PrivateNoReplaceCommitPointV1::BeforePublish)?;
        match rustix_fs::renameat_with(
            &parent,
            temporary.as_str(),
            &parent,
            file_name,
            RenameFlags::NOREPLACE,
        ) {
            Ok(()) => {
                temporary_created = false;
            }
            Err(rustix::io::Errno::EXIST) => {
                rustix_fs::unlinkat(&parent, temporary.as_str(), AtFlags::empty()).map_err(
                    |error| format!("remove colliding private output temporary failed: {error}"),
                )?;
                temporary_created = false;
                parent.sync_all().map_err(|error| {
                    format!("sync colliding private output cleanup failed: {error}")
                })?;
                validate_private_output_parent_v1(parent_path, parent_snapshot)?;
                return Err(format!(
                    "immutable private output already exists at atomic commit: {}",
                    path.display()
                ));
            }
            Err(error) => {
                return Err(format!(
                    "atomically publish private output without replacement failed: {error}"
                ));
            }
        }
        commit_hook(PrivateNoReplaceCommitPointV1::AfterPublish)?;
        parent
            .sync_all()
            .map_err(|error| format!("sync committed private output directory failed: {error}"))?;
        validate_committed_private_output_at_v1(
            &parent,
            parent_path,
            parent_snapshot,
            file_name,
            bytes,
            committed_identity,
        )
    })();
    if temporary_created {
        let _ = rustix_fs::unlinkat(&parent, temporary.as_str(), AtFlags::empty());
        let _ = parent.sync_all();
    }
    result
}

#[cfg(not(unix))]
fn write_atomic_private(_path: &Path, _bytes: &[u8], _force: bool) -> Result<(), String> {
    Err("directory artifacts require Unix atomic 0600 output semantics".to_owned())
}

#[cfg(not(unix))]
pub(crate) fn write_atomic_private_no_replace_v1(
    _path: &Path,
    _bytes: &[u8],
) -> Result<(), String> {
    Err("directory artifacts require Unix atomic 0600 output semantics".to_owned())
}

#[cfg(not(unix))]
pub(crate) fn require_private_output_absent_v1(_path: &Path) -> Result<(), String> {
    Err("directory artifacts require Unix atomic 0600 output semantics".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::private_tempdir_v1 as private_tempdir;
    use ed25519_dalek::SigningKey;
    use pir_directory_nostr::DirectoryEntryStatusV1;
    use pir_service_protocol::{
        AcquisitionMethod, AuthPaddingClassV1, AuthScheme, BackendId, DatasetBindingV1,
        DeploymentStatus, EntitlementLimitsV1, FreeModeV1, PriceV1, PrivacyLeakageV1,
        ServiceOfferV1, ServiceScopePolicyV1, ServiceScopeV1, VerificationMode, WorkloadId,
    };

    const NOW: u64 = 1_500;

    fn write_key(path: &Path, seed: [u8; 32]) {
        crate::keygen::write_secret_key_unix(path, &seed).unwrap();
    }

    fn write_policy(
        path: &Path,
        operator: &SigningKey,
        stable_server_id: &str,
        policy_key: &SigningKey,
    ) -> ServicePolicyV1 {
        let provider_id =
            derive_provider_id(&operator.verifying_key().to_bytes(), stable_server_id);
        let scope = ServiceScopeV1 {
            provider_id,
            backend: BackendId::DpfPirV1,
            workload: WorkloadId::DpfEvaluateJobV1,
            protocol_version: 1,
            dataset: DatasetBindingV1::Class { class_id: 1 },
            operation_profile: 1,
            entitlement_profile: 2,
        };
        let policy = ServicePolicyV1::sign(
            provider_id,
            9,
            1_000,
            2_500,
            AuthPaddingClassV1::Class16KiB,
            vec![ServiceScopePolicyV1 {
                scope,
                limits: EntitlementLimitsV1 {
                    max_logical_inputs: 1,
                    max_frames: 8,
                    max_request_bytes: 1_000,
                    max_response_bytes: 2_000,
                    max_wall_time_ms: 1_000,
                    max_concurrent_sockets: 1,
                    max_hint_groups: 0,
                    max_work_units: 100,
                },
                offers: vec![ServiceOfferV1 {
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
                }],
            }],
            policy_key,
        )
        .unwrap();
        fs::write(path, policy.encode().unwrap()).unwrap();
        policy
    }

    #[test]
    fn assertion_entry_and_all_sixteen_checkpoints_roundtrip_offline() {
        let directory = private_tempdir().unwrap();
        let operator_key = SigningKey::from_bytes(&[3; 32]);
        let policy_key = SigningKey::from_bytes(&[4; 32]);
        let operator_path = directory.path().join("operator.key");
        let directory_key_path = directory.path().join("directory.key");
        let policy_path = directory.path().join("policy.bin");
        let assertion_path = directory.path().join("assertion.bin");
        let entry_path = directory.path().join("entry.event.json");
        let checkpoints_path = directory.path().join("checkpoints.json");
        write_key(&operator_path, operator_key.to_bytes());
        write_key(&directory_key_path, [5; 32]);
        let policy = write_policy(&policy_path, &operator_key, "pir-a", &policy_key);
        let policy_key_hex = hex::encode(policy_key.verifying_key().to_bytes());

        build_assertion(AssertionArgs {
            policy: policy_path.clone(),
            policy_signing_key_hex: policy_key_hex.clone(),
            operator_signing_key: operator_path.clone(),
            stable_server_id: "pir-a".into(),
            assertion_epoch: 7,
            not_before: 1_000,
            valid_until: 2_500,
            endpoints: vec![
                "wss://pir-a.example/v2".into(),
                "wss://pir-a.example/v1".into(),
            ],
            now_unix: NOW,
            out: assertion_path.clone(),
            force: false,
        })
        .unwrap();
        let assertion =
            DirectoryOperatorAssertionV1::decode(&fs::read(&assertion_path).unwrap()).unwrap();
        assert_eq!(assertion.policy_epoch, policy.policy_epoch);

        let reused_seed_error = build_entry(EntryArgs {
            assertion: assertion_path.clone(),
            policy: policy_path.clone(),
            policy_signing_key_hex: policy_key_hex.clone(),
            directory_signing_key: operator_path,
            reserved_xonly_pubkey_hex: Vec::new(),
            directory_sequence: 11,
            directory_valid_until: 2_400,
            created_at: NOW,
            health_class: HealthClassArg::Available,
            health_observed_bucket: NOW,
            now_unix: NOW,
            out: directory.path().join("must-not-exist.event.json"),
            force: false,
        })
        .unwrap_err();
        assert!(reused_seed_error.contains("must not reuse"));

        build_entry(EntryArgs {
            assertion: assertion_path.clone(),
            policy: policy_path,
            policy_signing_key_hex: policy_key_hex,
            directory_signing_key: directory_key_path.clone(),
            reserved_xonly_pubkey_hex: Vec::new(),
            directory_sequence: 11,
            directory_valid_until: 2_400,
            created_at: NOW,
            health_class: HealthClassArg::Available,
            health_observed_bucket: NOW,
            now_unix: NOW,
            out: entry_path.clone(),
            force: false,
        })
        .unwrap();
        let publisher = DirectoryPublisherKeyV1::from_secret_bytes([5; 32]).unwrap();
        let entry_json =
            parse_event_message(&fs::read(&entry_path).unwrap(), "test entry").unwrap();
        verify_directory_entry_event_v1(&entry_json, publisher.public_key(), NOW).unwrap();

        build_checkpoints(CheckpointArgs {
            entry_events: vec![entry_path.clone()],
            directory_signing_key: directory_key_path,
            reserved_xonly_pubkey_hex: Vec::new(),
            checkpoint_epoch: 13,
            not_before: 1_000,
            valid_until: 2_400,
            created_at: NOW,
            now_unix: NOW,
            out: checkpoints_path.clone(),
            force: false,
        })
        .unwrap();
        let bundle: Vec<Box<RawValue>> =
            serde_json::from_slice(&fs::read(&checkpoints_path).unwrap()).unwrap();
        assert_eq!(bundle.len(), 16);
        for message in bundle {
            let event_json =
                parse_event_message(message.get().as_bytes(), "test checkpoint").unwrap();
            verify_directory_checkpoint_event_v1(&event_json, publisher.public_key(), NOW).unwrap();
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [assertion_path, entry_path, checkpoints_path] {
                assert_eq!(
                    fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
    }

    #[test]
    fn tombstone_and_checkpoint_roundtrip_offline() {
        let directory = private_tempdir().unwrap();
        let directory_key_path = directory.path().join("directory.key");
        let tombstone_path = directory.path().join("tombstone.event.json");
        let checkpoints_path = directory.path().join("checkpoints.json");
        write_key(&directory_key_path, [0x55; 32]);

        build_tombstone(TombstoneArgs {
            provider_id_hex: hex::encode([0x91; 32]),
            directory_signing_key: directory_key_path.clone(),
            reserved_xonly_pubkey_hex: Vec::new(),
            directory_sequence: 3,
            directory_valid_until: 2_400,
            health_class: HealthClassArg::Unavailable,
            health_observed_bucket: NOW,
            created_at: NOW,
            now_unix: NOW,
            out: tombstone_path.clone(),
            force: false,
        })
        .unwrap();

        let publisher = DirectoryPublisherKeyV1::from_secret_bytes([0x55; 32]).unwrap();
        let tombstone_json =
            parse_event_message(&fs::read(&tombstone_path).unwrap(), "test tombstone").unwrap();
        let verified =
            verify_directory_entry_event_v1(&tombstone_json, publisher.public_key(), NOW).unwrap();
        assert_eq!(
            verified.discovery_entry().status(),
            DirectoryEntryStatusV1::Tombstone
        );
        assert!(verified.discovery_entry().operator_assertion().is_none());

        build_checkpoints(CheckpointArgs {
            entry_events: vec![tombstone_path.clone()],
            directory_signing_key: directory_key_path,
            reserved_xonly_pubkey_hex: Vec::new(),
            checkpoint_epoch: 14,
            not_before: 1_000,
            valid_until: 2_400,
            created_at: NOW,
            now_unix: NOW,
            out: checkpoints_path.clone(),
            force: false,
        })
        .unwrap();
        let bundle: Vec<Box<RawValue>> =
            serde_json::from_slice(&fs::read(&checkpoints_path).unwrap()).unwrap();
        assert_eq!(bundle.len(), 16);
        for message in bundle {
            let event_json =
                parse_event_message(message.get().as_bytes(), "test checkpoint").unwrap();
            verify_directory_checkpoint_event_v1(&event_json, publisher.public_key(), NOW).unwrap();
        }
    }

    #[test]
    fn key_reuse_existing_output_and_wrong_directory_key_fail_closed() {
        let directory = private_tempdir().unwrap();
        let same_key = SigningKey::from_bytes(&[7; 32]);
        let operator_path = directory.path().join("operator.key");
        let policy_path = directory.path().join("policy.bin");
        let out = directory.path().join("assertion.bin");
        write_key(&operator_path, same_key.to_bytes());
        write_policy(&policy_path, &same_key, "pir-a", &same_key);
        let error = build_assertion(AssertionArgs {
            policy: policy_path,
            policy_signing_key_hex: hex::encode(same_key.verifying_key().to_bytes()),
            operator_signing_key: operator_path,
            stable_server_id: "pir-a".into(),
            assertion_epoch: 1,
            not_before: 1_000,
            valid_until: 2_000,
            endpoints: vec!["wss://pir-a.example/v1".into()],
            now_unix: NOW,
            out,
            force: false,
        })
        .unwrap_err();
        assert!(error.contains("must be distinct"));

        let existing = directory.path().join("existing");
        write_atomic_private_no_replace_v1(&existing, b"first").unwrap();
        assert!(write_atomic_private_no_replace_v1(&existing, b"first").is_err());
        assert!(write_atomic_private(&existing, b"second", false).is_err());
        assert!(write_atomic_private_no_replace_v1(&existing, b"second").is_err());
        assert_eq!(fs::read(existing).unwrap(), b"first");

        let wrong = DirectoryPublisherKeyV1::from_secret_bytes([8; 32]).unwrap();
        let right = DirectoryPublisherKeyV1::from_secret_bytes([9; 32]).unwrap();
        let entry = DirectoryEntryV1::new_tombstone(
            [0x91; 32],
            1,
            1_600,
            DirectoryHealthV1 {
                class: DirectoryHealthClassV1::Unavailable,
                observed_bucket: NOW,
            },
            NOW,
        )
        .unwrap();
        let event = wrong.sign_entry_event(&entry, NOW, &[1; 32]).unwrap();
        let event_json = event.to_json_bytes().unwrap();
        assert!(verify_directory_entry_event_v1(&event_json, right.public_key(), NOW).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn private_no_replace_receipt_has_one_atomic_commit_point_and_never_adopts() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let directory = private_tempdir().unwrap();
        let before = directory.path().join("before.json");
        let before_error =
            write_atomic_private_no_replace_with_hook_v1(&before, b"complete-before\n", |point| {
                if point == PrivateNoReplaceCommitPointV1::BeforePublish {
                    Err("injected-before-publish".to_owned())
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert!(before_error.contains("injected-before-publish"));
        assert!(!before.exists());

        let after = directory.path().join("after.json");
        let after_error =
            write_atomic_private_no_replace_with_hook_v1(&after, b"complete-after\n", |point| {
                if point == PrivateNoReplaceCommitPointV1::AfterPublish {
                    Err("injected-after-publish".to_owned())
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert!(after_error.contains("injected-after-publish"));
        assert_eq!(fs::read(&after).unwrap(), b"complete-after\n");
        let after_metadata = fs::symlink_metadata(&after).unwrap();
        assert_eq!(after_metadata.nlink(), 1);
        assert_eq!(after_metadata.permissions().mode() & 0o777, 0o600);

        assert!(write_atomic_private_no_replace_v1(&after, b"complete-after\n").is_err());
        assert!(write_atomic_private_no_replace_v1(&after, b"different\n").is_err());
        assert_eq!(fs::read(&after).unwrap(), b"complete-after\n");
        assert_eq!(fs::symlink_metadata(&after).unwrap().nlink(), 1);

        let special_parent = directory.path().join("special-parent");
        fs::create_dir(&special_parent).unwrap();
        fs::set_permissions(&special_parent, fs::Permissions::from_mode(0o1700)).unwrap();
        let special_output = special_parent.join("receipt.json");
        assert!(require_private_output_absent_v1(&special_output).is_err());
        assert!(write_atomic_private_no_replace_v1(&special_output, b"receipt\n").is_err());
        assert!(!special_output.exists());

        let leftover_temporaries = fs::read_dir(directory.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(leftover_temporaries, 0);
    }

    #[cfg(unix)]
    #[test]
    fn directory_secret_loader_rejects_symlink_and_group_readable_key() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = private_tempdir().unwrap();
        let target = directory.path().join("directory.key");
        let link = directory.path().join("directory-link.key");
        write_key(&target, [11; 32]);
        symlink(&target, &link).unwrap();
        assert!(load_directory_key(&link, &[], &[]).is_err());

        fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
        let error = load_directory_key(&target, &[], &[]).unwrap_err();
        assert!(error.contains("mode 0600/0400"));
    }

    #[cfg(unix)]
    #[test]
    fn public_artifact_reader_rejects_symlink_fifo_and_oversize_without_blocking() {
        use std::os::unix::fs::symlink;
        use std::process::Command;
        use std::sync::mpsc;
        use std::time::Duration;

        let directory = private_tempdir().unwrap();
        let artifact = directory.path().join("artifact.json");
        let link = directory.path().join("artifact-link.json");
        fs::write(&artifact, b"{}").unwrap();
        assert_eq!(
            read_public_bounded(&artifact, 2, "test artifact").unwrap(),
            b"{}"
        );
        symlink(&artifact, &link).unwrap();
        assert!(read_public_bounded(&link, 2, "test artifact").is_err());
        assert!(read_public_bounded(&artifact, 1, "test artifact").is_err());

        let fifo = directory.path().join("artifact.fifo");
        let status = Command::new("mkfifo").arg(&fifo).status().unwrap();
        assert!(status.success());
        let (sender, receiver) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            sender
                .send(read_public_bounded(&fifo, 2, "test artifact"))
                .ok();
        });
        let result = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("FIFO rejection must not wait for a writer");
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn public_artifact_snapshot_detects_every_stability_field_change() {
        let before = PublicFileSnapshotV1 {
            device: 1,
            inode: 2,
            mode: 0o100600,
            size: 3,
            modified_seconds: 4,
            modified_nanoseconds: 5,
            changed_seconds: 6,
            changed_nanoseconds: 7,
        };
        let changes = [
            PublicFileSnapshotV1 {
                device: 8,
                ..before
            },
            PublicFileSnapshotV1 { inode: 8, ..before },
            PublicFileSnapshotV1 {
                mode: 0o100400,
                ..before
            },
            PublicFileSnapshotV1 { size: 8, ..before },
            PublicFileSnapshotV1 {
                modified_seconds: 8,
                ..before
            },
            PublicFileSnapshotV1 {
                modified_nanoseconds: 8,
                ..before
            },
            PublicFileSnapshotV1 {
                changed_seconds: 8,
                ..before
            },
            PublicFileSnapshotV1 {
                changed_nanoseconds: 8,
                ..before
            },
        ];
        assert!(changes.iter().all(|after| *after != before));
    }
}
