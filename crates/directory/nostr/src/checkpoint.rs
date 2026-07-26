//! Canonical coarse-shard catalog checkpoints.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::event::{exact_directory_profile_tag_values, NostrEventV1, MAX_NOSTR_CONTENT_BYTES_V1};
use crate::hex::{decode_lower_hex, lower_hex};
use crate::{
    coarse_shard_for_provider_v1, shard_tag_value_v1, DirectoryErrorV1, DIRECTORY_SHARD_COUNT_V1,
};

pub const DIRECTORY_CHECKPOINT_D_PREFIX_V1: &str = "bitcoinpir-service-directory-checkpoint-v1:";
pub const DIRECTORY_CATALOG_ROOT_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/directory-catalog-checkpoint-root/v1";
pub const MAX_DIRECTORY_CHECKPOINT_ENTRIES_V1: usize = 1_024;
pub const MAX_DIRECTORY_CHECKPOINT_VALIDITY_SECONDS_V1: u64 = 31 * 24 * 60 * 60;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DirectoryCheckpointEntryV1 {
    pub provider_id: [u8; 32],
    pub directory_sequence: u64,
    pub event_id: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryCatalogCheckpointV1 {
    shard: u8,
    checkpoint_epoch: u64,
    not_before: u64,
    valid_until: u64,
    entries: Vec<DirectoryCheckpointEntryV1>,
    catalog_root: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDirectoryCheckpointEventV1 {
    event: NostrEventV1,
    checkpoint: DirectoryCatalogCheckpointV1,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DirectoryCheckpointJsonV1 {
    v: u8,
    shard: u8,
    checkpoint_epoch: u64,
    not_before: u64,
    valid_until: u64,
    entries: Vec<DirectoryCheckpointEntryJsonV1>,
    catalog_root: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DirectoryCheckpointEntryJsonV1 {
    provider_id: String,
    directory_sequence: u64,
    event_id: String,
}

impl DirectoryCatalogCheckpointV1 {
    pub fn new(
        shard: u8,
        checkpoint_epoch: u64,
        not_before: u64,
        valid_until: u64,
        entries: Vec<DirectoryCheckpointEntryV1>,
        now_unix: u64,
    ) -> Result<Self, DirectoryErrorV1> {
        let catalog_root =
            catalog_root_v1(shard, checkpoint_epoch, not_before, valid_until, &entries)?;
        let value = Self {
            shard,
            checkpoint_epoch,
            not_before,
            valid_until,
            entries,
            catalog_root,
        };
        value.validate_current(now_unix)?;
        Ok(value)
    }

    pub fn parse_canonical_json(bytes: &[u8], now_unix: u64) -> Result<Self, DirectoryErrorV1> {
        if bytes.is_empty() || bytes.len() > MAX_NOSTR_CONTENT_BYTES_V1 {
            return Err(DirectoryErrorV1::InputTooLarge);
        }
        core::str::from_utf8(bytes).map_err(|_| DirectoryErrorV1::InvalidJson)?;
        let wire: DirectoryCheckpointJsonV1 =
            serde_json::from_slice(bytes).map_err(|_| DirectoryErrorV1::InvalidJson)?;
        let canonical = serde_json::to_vec(&wire).map_err(|_| DirectoryErrorV1::InvalidJson)?;
        if canonical != bytes {
            return Err(DirectoryErrorV1::NonCanonicalJson);
        }
        let entries = wire
            .entries
            .into_iter()
            .map(|entry| {
                Ok(DirectoryCheckpointEntryV1 {
                    provider_id: decode_lower_hex(&entry.provider_id)?,
                    directory_sequence: entry.directory_sequence,
                    event_id: decode_lower_hex(&entry.event_id)?,
                })
            })
            .collect::<Result<Vec<_>, DirectoryErrorV1>>()?;
        if wire.v != 1 {
            return Err(DirectoryErrorV1::UnsupportedVersion);
        }
        let value = Self {
            shard: wire.shard,
            checkpoint_epoch: wire.checkpoint_epoch,
            not_before: wire.not_before,
            valid_until: wire.valid_until,
            entries,
            catalog_root: decode_lower_hex(&wire.catalog_root)?,
        };
        value.validate_current(now_unix)?;
        if value.canonical_json_bytes()? != bytes {
            return Err(DirectoryErrorV1::NonCanonicalJson);
        }
        Ok(value)
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, DirectoryErrorV1> {
        let wire = DirectoryCheckpointJsonV1 {
            v: 1,
            shard: self.shard,
            checkpoint_epoch: self.checkpoint_epoch,
            not_before: self.not_before,
            valid_until: self.valid_until,
            entries: self
                .entries
                .iter()
                .map(|entry| DirectoryCheckpointEntryJsonV1 {
                    provider_id: lower_hex(&entry.provider_id),
                    directory_sequence: entry.directory_sequence,
                    event_id: lower_hex(&entry.event_id),
                })
                .collect(),
            catalog_root: lower_hex(&self.catalog_root),
        };
        let bytes = serde_json::to_vec(&wire).map_err(|_| DirectoryErrorV1::InvalidJson)?;
        if bytes.len() > MAX_NOSTR_CONTENT_BYTES_V1 {
            return Err(DirectoryErrorV1::InputTooLarge);
        }
        Ok(bytes)
    }

    pub const fn shard(&self) -> u8 {
        self.shard
    }

    pub const fn checkpoint_epoch(&self) -> u64 {
        self.checkpoint_epoch
    }

    pub const fn not_before(&self) -> u64 {
        self.not_before
    }

    pub const fn valid_until(&self) -> u64 {
        self.valid_until
    }

    pub fn entries(&self) -> &[DirectoryCheckpointEntryV1] {
        &self.entries
    }

    pub const fn catalog_root(&self) -> &[u8; 32] {
        &self.catalog_root
    }

    fn validate_current(&self, now_unix: u64) -> Result<(), DirectoryErrorV1> {
        if self.shard >= DIRECTORY_SHARD_COUNT_V1
            || self.checkpoint_epoch == 0
            || self.not_before == 0
            || now_unix < self.not_before
            || now_unix > self.valid_until
            || self.valid_until.saturating_sub(self.not_before)
                > MAX_DIRECTORY_CHECKPOINT_VALIDITY_SECONDS_V1
        {
            return Err(DirectoryErrorV1::CheckpointExpired);
        }
        validate_checkpoint_entries(self.shard, &self.entries)?;
        let expected = catalog_root_v1(
            self.shard,
            self.checkpoint_epoch,
            self.not_before,
            self.valid_until,
            &self.entries,
        )?;
        if self.catalog_root != expected {
            return Err(DirectoryErrorV1::InvalidCatalogRoot);
        }
        Ok(())
    }
}

impl VerifiedDirectoryCheckpointEventV1 {
    pub const fn event(&self) -> &NostrEventV1 {
        &self.event
    }

    pub const fn checkpoint(&self) -> &DirectoryCatalogCheckpointV1 {
        &self.checkpoint
    }
}

pub fn catalog_root_v1(
    shard: u8,
    checkpoint_epoch: u64,
    not_before: u64,
    valid_until: u64,
    entries: &[DirectoryCheckpointEntryV1],
) -> Result<[u8; 32], DirectoryErrorV1> {
    if shard >= DIRECTORY_SHARD_COUNT_V1
        || checkpoint_epoch == 0
        || not_before == 0
        || valid_until < not_before
    {
        return Err(DirectoryErrorV1::InvalidCatalogRoot);
    }
    validate_checkpoint_entries(shard, entries)?;
    let count = u32::try_from(entries.len()).map_err(|_| DirectoryErrorV1::InvalidCatalogRoot)?;
    let mut hasher = Sha256::new();
    hasher.update(DIRECTORY_CATALOG_ROOT_DOMAIN_V1);
    hasher.update([1, shard]);
    hasher.update(checkpoint_epoch.to_le_bytes());
    hasher.update(not_before.to_le_bytes());
    hasher.update(valid_until.to_le_bytes());
    hasher.update(count.to_le_bytes());
    for entry in entries {
        hasher.update(entry.provider_id);
        hasher.update(entry.directory_sequence.to_le_bytes());
        hasher.update(entry.event_id);
    }
    Ok(hasher.finalize().into())
}

pub fn verify_directory_checkpoint_event_v1(
    event_json: &[u8],
    pinned_directory_pubkey: &[u8; 32],
    now_unix: u64,
) -> Result<VerifiedDirectoryCheckpointEventV1, DirectoryErrorV1> {
    let event = NostrEventV1::parse_json(event_json)?;
    event.verify_for_directory_key(pinned_directory_pubkey)?;
    if event.created_at() == 0 || event.created_at() > now_unix {
        return Err(DirectoryErrorV1::CheckpointExpired);
    }
    let checkpoint =
        DirectoryCatalogCheckpointV1::parse_canonical_json(event.content().as_bytes(), now_unix)?;
    let (d, shard) = exact_directory_profile_tag_values(&event)
        .map_err(|_| DirectoryErrorV1::InvalidCheckpointTag)?;
    if d != checkpoint_d_tag_value_v1(checkpoint.shard()) {
        return Err(DirectoryErrorV1::InvalidCheckpointTag);
    }
    if shard != shard_tag_value_v1(checkpoint.shard()) {
        return Err(DirectoryErrorV1::InvalidShard);
    }
    if event.created_at() < checkpoint.not_before() || event.created_at() > checkpoint.valid_until()
    {
        return Err(DirectoryErrorV1::CheckpointExpired);
    }
    Ok(VerifiedDirectoryCheckpointEventV1 { event, checkpoint })
}

pub fn checkpoint_d_tag_value_v1(shard: u8) -> String {
    if shard >= DIRECTORY_SHARD_COUNT_V1 {
        return String::new();
    }
    let mut value = String::from(DIRECTORY_CHECKPOINT_D_PREFIX_V1);
    value.push(char::from_digit(u32::from(shard), 16).expect("validated nibble"));
    value
}

fn validate_checkpoint_entries(
    shard: u8,
    entries: &[DirectoryCheckpointEntryV1],
) -> Result<(), DirectoryErrorV1> {
    if entries.len() > MAX_DIRECTORY_CHECKPOINT_ENTRIES_V1 {
        return Err(DirectoryErrorV1::InvalidCatalogRoot);
    }
    for entry in entries {
        if entry.provider_id.iter().all(|byte| *byte == 0)
            || entry.event_id.iter().all(|byte| *byte == 0)
            || entry.directory_sequence == 0
            || coarse_shard_for_provider_v1(&entry.provider_id) != shard
        {
            return Err(DirectoryErrorV1::InvalidCatalogRoot);
        }
    }
    if !entries
        .windows(2)
        .all(|pair| pair[0].provider_id < pair[1].provider_id)
    {
        return Err(DirectoryErrorV1::InvalidCatalogRoot);
    }
    Ok(())
}
