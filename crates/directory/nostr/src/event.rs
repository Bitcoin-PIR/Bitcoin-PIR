use core::cmp::Ordering;

use k256::schnorr::{
    signature::hazmat::PrehashVerifier, Signature as SchnorrSignature, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hex::{contains_control, decode_lower_hex, lower_hex};
use crate::DirectoryErrorV1;

pub const BITCOINPIR_DIRECTORY_KIND_V1: u16 = 30_078;
pub const MAX_NOSTR_EVENT_BYTES_V1: usize = 256 * 1024;
pub const MAX_NOSTR_CONTENT_BYTES_V1: usize = 192 * 1024;
pub const MAX_NOSTR_TAGS_V1: usize = 64;
pub const MAX_NOSTR_TAG_ITEMS_V1: usize = 8;
pub const MAX_NOSTR_TAG_VALUE_BYTES_V1: usize = 1_024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NostrEventV1 {
    id: [u8; 32],
    pubkey: [u8; 32],
    created_at: u64,
    kind: u16,
    tags: Vec<Vec<String>>,
    content: String,
    signature: [u8; 64],
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NostrEventJsonV1 {
    id: String,
    pubkey: String,
    created_at: u64,
    kind: u16,
    tags: Vec<Vec<String>>,
    content: String,
    sig: String,
}

impl NostrEventV1 {
    pub(crate) fn from_signed_parts(
        id: [u8; 32],
        pubkey: [u8; 32],
        created_at: u64,
        tags: Vec<Vec<String>>,
        content: String,
        signature: [u8; 64],
    ) -> Result<Self, DirectoryErrorV1> {
        let value = Self {
            id,
            pubkey,
            created_at,
            kind: BITCOINPIR_DIRECTORY_KIND_V1,
            tags,
            content,
            signature,
        };
        value.validate_bounds()?;
        Ok(value)
    }

    pub fn parse_json(bytes: &[u8]) -> Result<Self, DirectoryErrorV1> {
        if bytes.is_empty() || bytes.len() > MAX_NOSTR_EVENT_BYTES_V1 {
            return Err(DirectoryErrorV1::InputTooLarge);
        }
        let wire: NostrEventJsonV1 =
            serde_json::from_slice(bytes).map_err(|_| DirectoryErrorV1::InvalidJson)?;
        let value = Self {
            id: decode_lower_hex(&wire.id)?,
            pubkey: decode_lower_hex(&wire.pubkey)?,
            created_at: wire.created_at,
            kind: wire.kind,
            tags: wire.tags,
            content: wire.content,
            signature: decode_lower_hex(&wire.sig)?,
        };
        value.validate_bounds()?;
        Ok(value)
    }

    /// Serialize with a stable field order for publishing. Parsers deliberately
    /// do not require relay-returned event objects to use this key order.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, DirectoryErrorV1> {
        self.validate_bounds()?;
        let bytes =
            serde_json::to_vec(&self.to_wire()).map_err(|_| DirectoryErrorV1::InvalidJson)?;
        if bytes.len() > MAX_NOSTR_EVENT_BYTES_V1 {
            return Err(DirectoryErrorV1::InputTooLarge);
        }
        Ok(bytes)
    }

    pub fn canonical_id_preimage(&self) -> Result<Vec<u8>, DirectoryErrorV1> {
        self.validate_bounds()?;
        canonical_id_preimage_for_parts(
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        )
    }

    pub fn computed_id(&self) -> Result<[u8; 32], DirectoryErrorV1> {
        let mut hasher = Sha256::new();
        hasher.update(self.canonical_id_preimage()?);
        Ok(hasher.finalize().into())
    }

    pub fn verify_for_directory_key(
        &self,
        pinned_directory_pubkey: &[u8; 32],
    ) -> Result<(), DirectoryErrorV1> {
        self.validate_bounds()?;
        if &self.pubkey != pinned_directory_pubkey {
            return Err(DirectoryErrorV1::WrongDirectoryKey);
        }
        if self.kind != BITCOINPIR_DIRECTORY_KIND_V1 {
            return Err(DirectoryErrorV1::WrongEventKind);
        }
        let computed = self.computed_id()?;
        if computed != self.id {
            return Err(DirectoryErrorV1::InvalidEventId);
        }
        let verifying_key = VerifyingKey::from_bytes(&self.pubkey)
            .map_err(|_| DirectoryErrorV1::InvalidEventSignature)?;
        let signature = SchnorrSignature::try_from(self.signature.as_slice())
            .map_err(|_| DirectoryErrorV1::InvalidEventSignature)?;
        verifying_key
            .verify_prehash(&self.id, &signature)
            .map_err(|_| DirectoryErrorV1::InvalidEventSignature)
    }

    pub const fn id(&self) -> &[u8; 32] {
        &self.id
    }

    pub const fn pubkey(&self) -> &[u8; 32] {
        &self.pubkey
    }

    pub const fn created_at(&self) -> u64 {
        self.created_at
    }

    pub const fn kind(&self) -> u16 {
        self.kind
    }

    pub fn tags(&self) -> &[Vec<String>] {
        &self.tags
    }

    pub fn content(&self) -> &str {
        &self.content
    }

    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// NIP-01 client publish message. It contains the already signed event and
    /// therefore performs no network I/O and owns no relay state.
    pub fn to_event_message_json_bytes(&self) -> Result<Vec<u8>, DirectoryErrorV1> {
        self.validate_bounds()?;
        let bytes = serde_json::to_vec(&("EVENT", self.to_wire()))
            .map_err(|_| DirectoryErrorV1::InvalidJson)?;
        if bytes.len() > MAX_NOSTR_EVENT_BYTES_V1 + 32 {
            return Err(DirectoryErrorV1::InputTooLarge);
        }
        Ok(bytes)
    }

    fn to_wire(&self) -> NostrEventJsonV1 {
        NostrEventJsonV1 {
            id: lower_hex(&self.id),
            pubkey: lower_hex(&self.pubkey),
            created_at: self.created_at,
            kind: self.kind,
            tags: self.tags.clone(),
            content: self.content.clone(),
            sig: lower_hex(&self.signature),
        }
    }

    fn validate_bounds(&self) -> Result<(), DirectoryErrorV1> {
        if self.pubkey.iter().all(|byte| *byte == 0)
            || self.id.iter().all(|byte| *byte == 0)
            || self.content.len() > MAX_NOSTR_CONTENT_BYTES_V1
            || self.tags.len() > MAX_NOSTR_TAGS_V1
        {
            return Err(DirectoryErrorV1::InvalidValue);
        }
        for tag in &self.tags {
            if tag.is_empty() || tag.len() > MAX_NOSTR_TAG_ITEMS_V1 {
                return Err(DirectoryErrorV1::InvalidTags);
            }
            for value in tag {
                if value.len() > MAX_NOSTR_TAG_VALUE_BYTES_V1 || contains_control(value) {
                    return Err(DirectoryErrorV1::InvalidTags);
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn canonical_event_id_for_parts(
    pubkey: &[u8; 32],
    created_at: u64,
    tags: &[Vec<String>],
    content: &str,
) -> Result<[u8; 32], DirectoryErrorV1> {
    let preimage = canonical_id_preimage_for_parts(
        pubkey,
        created_at,
        BITCOINPIR_DIRECTORY_KIND_V1,
        tags,
        content,
    )?;
    let mut hasher = Sha256::new();
    hasher.update(preimage);
    Ok(hasher.finalize().into())
}

fn canonical_id_preimage_for_parts(
    pubkey: &[u8; 32],
    created_at: u64,
    kind: u16,
    tags: &[Vec<String>],
    content: &str,
) -> Result<Vec<u8>, DirectoryErrorV1> {
    serde_json::to_vec(&(0u8, lower_hex(pubkey), created_at, kind, tags, content))
        .map_err(|_| DirectoryErrorV1::InvalidJson)
}

pub(crate) fn exactly_one_tag_value<'a>(
    event: &'a NostrEventV1,
    tag_name: &str,
) -> Result<&'a str, DirectoryErrorV1> {
    let mut matching = event.tags().iter().filter(|tag| tag[0] == tag_name);
    let tag = matching.next().ok_or(DirectoryErrorV1::InvalidTags)?;
    if matching.next().is_some() || tag.len() != 2 {
        return Err(DirectoryErrorV1::InvalidTags);
    }
    Ok(&tag[1])
}

/// Apply NIP-01's replacement ordering to two already authenticated
/// addressable events. `Greater` means `candidate` is the event a conforming
/// relay should retain: a later `created_at` wins and, on a timestamp tie, the
/// lexicographically lower event id wins.
///
/// This helper does not authenticate either event. Callers must first verify
/// both events against the pinned directory key and the BitcoinPIR profile.
pub fn nip01_addressable_replacement_order_v1(
    candidate: &NostrEventV1,
    current: &NostrEventV1,
) -> Result<Ordering, DirectoryErrorV1> {
    if candidate.kind != BITCOINPIR_DIRECTORY_KIND_V1
        || current.kind != BITCOINPIR_DIRECTORY_KIND_V1
    {
        return Err(DirectoryErrorV1::WrongEventKind);
    }
    let candidate_d = exactly_one_tag_value(candidate, "d")?;
    let current_d = exactly_one_tag_value(current, "d")?;
    if candidate.kind != current.kind
        || candidate.pubkey != current.pubkey
        || candidate_d != current_d
    {
        return Err(DirectoryErrorV1::DifferentAddressableCoordinate);
    }
    Ok(candidate
        .created_at
        .cmp(&current.created_at)
        .then_with(|| current.id.cmp(&candidate.id)))
}

/// BitcoinPIR's NIP-78 profile deliberately permits only its two indexed
/// discovery tags. This is stricter than generic NIP-78 and removes protocol
/// fields that could accidentally carry a peer choice or payment artifact.
pub(crate) fn exact_directory_profile_tag_values(
    event: &NostrEventV1,
) -> Result<(&str, &str), DirectoryErrorV1> {
    if event.tags.len() != 2
        || event.tags[0].len() != 2
        || event.tags[0][0] != "d"
        || event.tags[1].len() != 2
        || event.tags[1][0] != "s"
    {
        return Err(DirectoryErrorV1::InvalidTags);
    }
    Ok((&event.tags[0][1], &event.tags[1][1]))
}
