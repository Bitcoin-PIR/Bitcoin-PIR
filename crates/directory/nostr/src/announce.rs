//! Node announcements: an operator lists its own node by publishing one
//! signed Nostr event (docs/DIRECTORY_PROTOCOL.md "Node announcements").
//!
//! An announcement is the operator's request to be listed, not a directory
//! entry. Any Nostr key may sign it; the operator identity is the inner
//! Ed25519 operator assertion. The directory publisher reads announcements,
//! checks each node live and signs ordinary v1 entries for those it lists.

use serde::{Deserialize, Serialize};

use crate::assertion::{DirectoryAssertionRollbackGuardV1, DirectoryOperatorAssertionV1};
use crate::entry::{
    catalog_hint_from_wire, catalog_hint_to_wire, operator_assertion_from_wire,
    operator_assertion_to_wire, validate_catalog_hints, DirectoryCatalogHintJsonV1,
    DirectoryCatalogHintV1, DirectoryOperatorAssertionJsonV1,
};
use crate::event::NostrEventV1;
use crate::hex::{decode_lower_hex, lower_hex};
use crate::{DirectoryErrorV1, BITCOINPIR_DIRECTORY_KIND_V1};

pub const NODE_ANNOUNCEMENT_D_PREFIX_V1: &str = "bitcoinpir-node-announce-v1:";
pub const NODE_ANNOUNCEMENT_T_TAG_V1: &str = "bitcoinpir-node";
pub const NODE_ANNOUNCEMENT_REQ_SUBSCRIPTION_V1: &str = "bitcoinpir-node-announcements";
pub const MAX_NODE_ANNOUNCEMENT_EVENT_BYTES_V1: usize = 16 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeAnnouncementV1 {
    operator_assertion: DirectoryOperatorAssertionV1,
    catalog_hints: Vec<DirectoryCatalogHintV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedNodeAnnouncementEventV1 {
    event: NostrEventV1,
    announcement: NodeAnnouncementV1,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NodeAnnouncementJsonV1 {
    v: u8,
    operator_assertion: DirectoryOperatorAssertionJsonV1,
    catalog_hints: Vec<DirectoryCatalogHintJsonV1>,
}

impl NodeAnnouncementV1 {
    /// An announcement of the asserted node with the backends it serves.
    /// The assertion must be signed and currently valid.
    pub fn new(
        operator_assertion: DirectoryOperatorAssertionV1,
        catalog_hints: Vec<DirectoryCatalogHintV1>,
        now_unix: u64,
    ) -> Result<Self, DirectoryErrorV1> {
        let value = Self {
            operator_assertion,
            catalog_hints,
        };
        value.validate(now_unix)?;
        Ok(value)
    }

    pub fn parse_canonical_json(bytes: &[u8], now_unix: u64) -> Result<Self, DirectoryErrorV1> {
        if bytes.is_empty() || bytes.len() > MAX_NODE_ANNOUNCEMENT_EVENT_BYTES_V1 {
            return Err(DirectoryErrorV1::InputTooLarge);
        }
        let wire: NodeAnnouncementJsonV1 =
            serde_json::from_slice(bytes).map_err(|_| DirectoryErrorV1::InvalidJson)?;
        if wire.v != 1 {
            return Err(DirectoryErrorV1::UnsupportedVersion);
        }
        let value = Self {
            operator_assertion: operator_assertion_from_wire(wire.operator_assertion)?,
            catalog_hints: wire
                .catalog_hints
                .into_iter()
                .map(catalog_hint_from_wire)
                .collect::<Result<Vec<_>, _>>()?,
        };
        value.validate(now_unix)?;
        if value.canonical_json_bytes()? != bytes {
            return Err(DirectoryErrorV1::NonCanonicalJson);
        }
        Ok(value)
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, DirectoryErrorV1> {
        serde_json::to_vec(&NodeAnnouncementJsonV1 {
            v: 1,
            operator_assertion: operator_assertion_to_wire(&self.operator_assertion)?,
            catalog_hints: self
                .catalog_hints
                .iter()
                .map(catalog_hint_to_wire)
                .collect(),
        })
        .map_err(|_| DirectoryErrorV1::InvalidJson)
    }

    pub const fn operator_assertion(&self) -> &DirectoryOperatorAssertionV1 {
        &self.operator_assertion
    }

    pub fn catalog_hints(&self) -> &[DirectoryCatalogHintV1] {
        &self.catalog_hints
    }

    pub const fn provider_id(&self) -> &[u8; 32] {
        &self.operator_assertion.provider_id
    }

    fn validate(&self, now_unix: u64) -> Result<(), DirectoryErrorV1> {
        if self.catalog_hints.is_empty() {
            return Err(DirectoryErrorV1::InvalidCatalogHints);
        }
        validate_catalog_hints(&self.catalog_hints)?;
        let assertion = &self.operator_assertion;
        assertion
            .verify_current_for(
                &assertion.provider_id,
                &assertion.operator_pubkey_ed25519,
                now_unix,
                &DirectoryAssertionRollbackGuardV1::initial(),
            )
            .map_err(|_| DirectoryErrorV1::InvalidOperatorAssertion)?;
        Ok(())
    }
}

impl VerifiedNodeAnnouncementEventV1 {
    pub const fn event(&self) -> &NostrEventV1 {
        &self.event
    }

    pub const fn announcement(&self) -> &NodeAnnouncementV1 {
        &self.announcement
    }
}

/// The exact tags of an announcement: `d` names the provider, `expiration`
/// (NIP-40) is the assertion's `valid_until`, `t` lets relays and clients
/// filter announcements.
pub fn node_announcement_tags_v1(provider_id: &[u8; 32], valid_until: u64) -> Vec<Vec<String>> {
    vec![
        vec![
            "d".to_owned(),
            format!("{NODE_ANNOUNCEMENT_D_PREFIX_V1}{}", lower_hex(provider_id)),
        ],
        vec!["expiration".to_owned(), valid_until.to_string()],
        vec!["t".to_owned(), NODE_ANNOUNCEMENT_T_TAG_V1.to_owned()],
    ]
}

/// Verify one announcement event: its own BIP340 signature, the exact tags,
/// the canonical content and the operator assertion, current at `now_unix`.
/// It says nothing about the node itself; the publisher checks that live.
pub fn verify_node_announcement_event_v1(
    event_json: &[u8],
    now_unix: u64,
) -> Result<VerifiedNodeAnnouncementEventV1, DirectoryErrorV1> {
    if event_json.len() > MAX_NODE_ANNOUNCEMENT_EVENT_BYTES_V1 {
        return Err(DirectoryErrorV1::InputTooLarge);
    }
    let event = NostrEventV1::parse_json(event_json)?;
    event.verify_own_signature()?;
    let announcement =
        NodeAnnouncementV1::parse_canonical_json(event.content().as_bytes(), now_unix)?;
    let assertion = announcement.operator_assertion();
    if event.tags() != node_announcement_tags_v1(&assertion.provider_id, assertion.valid_until) {
        return Err(DirectoryErrorV1::InvalidTags);
    }
    if event.created_at() < assertion.not_before || event.created_at() > now_unix {
        return Err(DirectoryErrorV1::EntryExpired);
    }
    Ok(VerifiedNodeAnnouncementEventV1 {
        event,
        announcement,
    })
}

/// The one `REQ` that reads every announcement a relay holds.
pub fn node_announcements_req_json_v1() -> Result<Vec<u8>, DirectoryErrorV1> {
    #[derive(Serialize)]
    struct Filter {
        kinds: [u16; 1],
        #[serde(rename = "#t")]
        t: [&'static str; 1],
    }
    serde_json::to_vec(&(
        "REQ",
        NODE_ANNOUNCEMENT_REQ_SUBSCRIPTION_V1,
        Filter {
            kinds: [BITCOINPIR_DIRECTORY_KIND_V1],
            t: [NODE_ANNOUNCEMENT_T_TAG_V1],
        },
    ))
    .map_err(|_| DirectoryErrorV1::InvalidJson)
}

/// Provider id named by an announcement's `d` tag value.
pub fn node_announcement_provider_id_v1(d_value: &str) -> Result<[u8; 32], DirectoryErrorV1> {
    let hex = d_value
        .strip_prefix(NODE_ANNOUNCEMENT_D_PREFIX_V1)
        .ok_or(DirectoryErrorV1::InvalidTags)?;
    decode_lower_hex(hex)
}

#[cfg(test)]
mod tests;
