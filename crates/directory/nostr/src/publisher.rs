//! Pure publishing and relay-message helpers.
//!
//! These helpers never open a relay connection. The publisher key is a
//! dedicated Nostr key type so it cannot be confused with an operator,
//! issuer, Lightning, receipt, clearing, or payout key.

use core::fmt;

use k256::{elliptic_curve::zeroize::Zeroize, schnorr::SigningKey};
use serde::Serialize;

use crate::checkpoint::{checkpoint_d_tag_value_v1, DirectoryCatalogCheckpointV1};
use crate::entry::{entry_d_tag_value_v1, DirectoryEntryV1};
use crate::event::{canonical_event_id_for_parts, NostrEventV1};
use crate::hex::lower_hex;
use crate::{
    shard_tag_value_v1, DirectoryErrorV1, BITCOINPIR_DIRECTORY_KIND_V1, DIRECTORY_SHARD_COUNT_V1,
};

pub const DIRECTORY_REQ_SUBSCRIPTION_PREFIX_V1: &str = "bitcoinpir-directory-v1-shard-";

pub struct DirectoryPublisherKeyV1 {
    signing_key: SigningKey,
    public_key: [u8; 32],
}

impl fmt::Debug for DirectoryPublisherKeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectoryPublisherKeyV1")
            .field("secret_key", &"[REDACTED]")
            .field("public_key", &lower_hex(&self.public_key))
            .finish()
    }
}

impl DirectoryPublisherKeyV1 {
    pub fn from_secret_bytes(mut secret_key: [u8; 32]) -> Result<Self, DirectoryErrorV1> {
        let parsed = SigningKey::from_bytes(&secret_key);
        secret_key.zeroize();
        let signing_key = parsed.map_err(|_| DirectoryErrorV1::InvalidValue)?;
        let public_key = signing_key.verifying_key().to_bytes().into();
        Ok(Self {
            signing_key,
            public_key,
        })
    }

    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Fail startup when this directory key is also configured for another
    /// x-only secp256k1 role. Cross-algorithm and secret-file separation still
    /// require an operator inventory; equal Ed25519/public byte strings are not
    /// a meaningful key-reuse test.
    pub fn ensure_distinct_from_xonly_keys(
        &self,
        reserved_public_keys: &[[u8; 32]],
    ) -> Result<(), DirectoryErrorV1> {
        if reserved_public_keys.contains(&self.public_key) {
            return Err(DirectoryErrorV1::InvalidValue);
        }
        Ok(())
    }

    /// Sign one active or tombstone entry. Auxiliary randomness must be fresh
    /// and obtained from the caller's CSPRNG; this crate deliberately owns no
    /// OS or browser randomness boundary.
    pub fn sign_entry_event(
        &self,
        entry: &DirectoryEntryV1,
        created_at: u64,
        auxiliary_randomness: &[u8; 32],
    ) -> Result<NostrEventV1, DirectoryErrorV1> {
        if created_at == 0 || created_at > entry.directory_valid_until() {
            return Err(DirectoryErrorV1::EntryExpired);
        }
        if let Some(assertion) = entry.operator_assertion() {
            if created_at < assertion.not_before || created_at > assertion.valid_until {
                return Err(DirectoryErrorV1::InvalidOperatorAssertion);
            }
        }
        self.sign_content(
            created_at,
            vec![
                vec!["d".to_owned(), entry_d_tag_value_v1(entry.provider_id())],
                vec![
                    "s".to_owned(),
                    shard_tag_value_v1(crate::coarse_shard_for_provider_v1(entry.provider_id())),
                ],
            ],
            entry.canonical_json_bytes()?,
            auxiliary_randomness,
        )
    }

    pub fn sign_checkpoint_event(
        &self,
        checkpoint: &DirectoryCatalogCheckpointV1,
        created_at: u64,
        auxiliary_randomness: &[u8; 32],
    ) -> Result<NostrEventV1, DirectoryErrorV1> {
        if created_at < checkpoint.not_before() || created_at > checkpoint.valid_until() {
            return Err(DirectoryErrorV1::CheckpointExpired);
        }
        self.sign_content(
            created_at,
            vec![
                vec![
                    "d".to_owned(),
                    checkpoint_d_tag_value_v1(checkpoint.shard()),
                ],
                vec!["s".to_owned(), shard_tag_value_v1(checkpoint.shard())],
            ],
            checkpoint.canonical_json_bytes()?,
            auxiliary_randomness,
        )
    }

    fn sign_content(
        &self,
        created_at: u64,
        required_tags: Vec<Vec<String>>,
        content: Vec<u8>,
        auxiliary_randomness: &[u8; 32],
    ) -> Result<NostrEventV1, DirectoryErrorV1> {
        let content = String::from_utf8(content).map_err(|_| DirectoryErrorV1::InvalidJson)?;
        let event_id =
            canonical_event_id_for_parts(&self.public_key, created_at, &required_tags, &content)?;
        let signature = self
            .signing_key
            .sign_prehash_with_aux_rand(&event_id, auxiliary_randomness)
            .map_err(|_| DirectoryErrorV1::InvalidValue)?;
        let public_key: [u8; 32] = self.signing_key.verifying_key().to_bytes().into();
        if public_key != self.public_key {
            return Err(DirectoryErrorV1::InvalidValue);
        }
        NostrEventV1::from_signed_parts(
            event_id,
            public_key,
            created_at,
            required_tags,
            content,
            signature.to_bytes(),
        )
    }
}

#[derive(Serialize)]
struct DirectoryReqFilterJsonV1 {
    authors: [String; 1],
    kinds: [u16; 1],
    #[serde(rename = "#s")]
    shard: [String; 1],
}

pub fn catalog_req_json_v1(
    pinned_directory_pubkey: &[u8; 32],
    shard: u8,
) -> Result<Vec<u8>, DirectoryErrorV1> {
    if pinned_directory_pubkey.iter().all(|byte| *byte == 0) || shard >= DIRECTORY_SHARD_COUNT_V1 {
        return Err(DirectoryErrorV1::InvalidValue);
    }
    let subscription_id = format!("{DIRECTORY_REQ_SUBSCRIPTION_PREFIX_V1}{shard:x}");
    serde_json::to_vec(&(
        "REQ",
        subscription_id,
        DirectoryReqFilterJsonV1 {
            authors: [lower_hex(pinned_directory_pubkey)],
            kinds: [BITCOINPIR_DIRECTORY_KIND_V1],
            shard: [shard_tag_value_v1(shard)],
        },
    ))
    .map_err(|_| DirectoryErrorV1::InvalidJson)
}

pub fn full_catalog_req_json_v1(
    pinned_directory_pubkey: &[u8; 32],
) -> Result<Vec<Vec<u8>>, DirectoryErrorV1> {
    (0..DIRECTORY_SHARD_COUNT_V1)
        .map(|shard| catalog_req_json_v1(pinned_directory_pubkey, shard))
        .collect()
}
