use serde::{Deserialize, Serialize};

use crate::assertion::{
    DirectoryAssertionRollbackGuardV1, DirectoryEndpointV1, DirectoryOperatorAssertionV1,
    DirectoryTransportV1,
};
use crate::event::{exact_directory_profile_tag_values, NostrEventV1, MAX_NOSTR_CONTENT_BYTES_V1};
use crate::hex::{decode_lower_hex, lower_hex};
use crate::{coarse_shard_for_provider_v1, shard_tag_value_v1, DirectoryErrorV1};

pub const DIRECTORY_ENTRY_D_PREFIX_V1: &str = "bitcoinpir-service-directory-v1:";
pub const MAX_DIRECTORY_CATALOG_HINTS_V1: usize = 64;
pub const HEALTH_BUCKET_SECONDS_V1: u64 = 300;
pub const MAX_DIRECTORY_ENTRY_VALIDITY_SECONDS_V1: u64 = 31 * 24 * 60 * 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryEntryStatusV1 {
    Active,
    Tombstone,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryHealthClassV1 {
    Unknown,
    Available,
    Degraded,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryHealthV1 {
    pub class: DirectoryHealthClassV1,
    /// Unix seconds floored to a five-minute boundary.
    pub observed_bucket: u64,
}

/// Backend a provider claims to serve. Names match the server's published
/// access policy (`credits.access` in `GET_INFO_JSON`).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum DirectoryBackendV1 {
    Dpf = 1,
    Harmony = 2,
    Onion = 3,
    Oram = 4,
}

/// DPF slot of the server (`role` in `GET_INFO_JSON`): the primary serves
/// DPF server 0 and HarmonyPIR hints, the secondary serves DPF server 1 and
/// HarmonyPIR queries.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum DirectoryServerRoleV1 {
    Primary = 1,
    Secondary = 2,
}

/// Coarse access class of one backend (`mode` of the published access
/// policy). Concurrency and gas budgets stay in the live policy only.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum DirectoryAccessClassV1 {
    Free = 1,
    Paid = 2,
    BestEffort = 3,
}

/// Hardware attestation the provider claims; verified live through the
/// secure-channel attestation path, never from the directory.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum DirectoryAttestationV1 {
    None = 1,
    SevSnp = 2,
}

/// Bounded, sorted mirror of what the provider serves. Hints only avoid
/// connecting to obviously unsuitable providers; every hint is compared with
/// the live identity, role, attestation and access policy before use.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryCatalogHintV1 {
    pub backend: DirectoryBackendV1,
    pub role: DirectoryServerRoleV1,
    pub access: DirectoryAccessClassV1,
    pub attestation: DirectoryAttestationV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryEntryV1 {
    provider_id: [u8; 32],
    directory_sequence: u64,
    directory_valid_until: u64,
    status: DirectoryEntryStatusV1,
    operator_assertion: Option<DirectoryOperatorAssertionV1>,
    operator_assertion_digest: Option<[u8; 32]>,
    catalog_hints: Vec<DirectoryCatalogHintV1>,
    health: DirectoryHealthV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDirectoryEntryEventV1 {
    event: NostrEventV1,
    entry: DirectoryEntryV1,
    shard: u8,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DirectoryEntryJsonV1 {
    v: u8,
    provider_id: String,
    directory_sequence: u64,
    directory_valid_until: u64,
    status: String,
    operator_assertion: Option<DirectoryOperatorAssertionJsonV1>,
    catalog_hints: Vec<DirectoryCatalogHintJsonV1>,
    health: DirectoryHealthJsonV1,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DirectoryOperatorAssertionJsonV1 {
    v: u8,
    operator_pubkey_ed25519: String,
    stable_server_id: String,
    provider_id: String,
    assertion_epoch: u64,
    not_before: u64,
    valid_until: u64,
    endpoints: Vec<DirectoryEndpointJsonV1>,
    signature_ed25519: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DirectoryEndpointJsonV1 {
    transport: String,
    url: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DirectoryCatalogHintJsonV1 {
    backend: String,
    role: String,
    access: String,
    attestation: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DirectoryHealthJsonV1 {
    class: String,
    observed_bucket: u64,
}

impl DirectoryEntryV1 {
    pub fn new_active(
        directory_sequence: u64,
        directory_valid_until: u64,
        operator_assertion: DirectoryOperatorAssertionV1,
        catalog_hints: Vec<DirectoryCatalogHintV1>,
        health: DirectoryHealthV1,
        now_unix: u64,
    ) -> Result<Self, DirectoryErrorV1> {
        let provider_id = operator_assertion.provider_id;
        let mut value = Self {
            provider_id,
            directory_sequence,
            directory_valid_until,
            status: DirectoryEntryStatusV1::Active,
            operator_assertion: Some(operator_assertion),
            operator_assertion_digest: None,
            catalog_hints,
            health,
        };
        value.validate_and_verify(now_unix)?;
        Ok(value)
    }

    pub fn new_tombstone(
        provider_id: [u8; 32],
        directory_sequence: u64,
        directory_valid_until: u64,
        health: DirectoryHealthV1,
        now_unix: u64,
    ) -> Result<Self, DirectoryErrorV1> {
        let mut value = Self {
            provider_id,
            directory_sequence,
            directory_valid_until,
            status: DirectoryEntryStatusV1::Tombstone,
            operator_assertion: None,
            operator_assertion_digest: None,
            catalog_hints: Vec::new(),
            health,
        };
        value.validate_and_verify(now_unix)?;
        Ok(value)
    }

    pub fn parse_canonical_json(bytes: &[u8], now_unix: u64) -> Result<Self, DirectoryErrorV1> {
        if bytes.is_empty() || bytes.len() > MAX_NOSTR_CONTENT_BYTES_V1 {
            return Err(DirectoryErrorV1::InputTooLarge);
        }
        core::str::from_utf8(bytes).map_err(|_| DirectoryErrorV1::InvalidJson)?;
        let wire: DirectoryEntryJsonV1 =
            serde_json::from_slice(bytes).map_err(|_| DirectoryErrorV1::InvalidJson)?;
        let canonical = serde_json::to_vec(&wire).map_err(|_| DirectoryErrorV1::InvalidJson)?;
        if canonical != bytes {
            return Err(DirectoryErrorV1::NonCanonicalJson);
        }
        let mut value = Self::from_wire(wire)?;
        value.validate_and_verify(now_unix)?;
        if value.canonical_json_bytes()? != bytes {
            return Err(DirectoryErrorV1::NonCanonicalJson);
        }
        Ok(value)
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, DirectoryErrorV1> {
        let wire = self.to_wire()?;
        let bytes = serde_json::to_vec(&wire).map_err(|_| DirectoryErrorV1::InvalidJson)?;
        if bytes.len() > MAX_NOSTR_CONTENT_BYTES_V1 {
            return Err(DirectoryErrorV1::InputTooLarge);
        }
        Ok(bytes)
    }

    pub const fn provider_id(&self) -> &[u8; 32] {
        &self.provider_id
    }

    pub const fn directory_sequence(&self) -> u64 {
        self.directory_sequence
    }

    pub const fn directory_valid_until(&self) -> u64 {
        self.directory_valid_until
    }

    pub const fn status(&self) -> DirectoryEntryStatusV1 {
        self.status
    }

    pub fn operator_assertion(&self) -> Option<&DirectoryOperatorAssertionV1> {
        self.operator_assertion.as_ref()
    }

    pub const fn operator_assertion_digest(&self) -> Option<[u8; 32]> {
        self.operator_assertion_digest
    }

    pub fn catalog_hints(&self) -> &[DirectoryCatalogHintV1] {
        &self.catalog_hints
    }

    pub const fn health(&self) -> DirectoryHealthV1 {
        self.health
    }

    fn from_wire(wire: DirectoryEntryJsonV1) -> Result<Self, DirectoryErrorV1> {
        if wire.v != 1 {
            return Err(DirectoryErrorV1::UnsupportedVersion);
        }
        let provider_id = decode_lower_hex(&wire.provider_id)?;
        let status = parse_entry_status(&wire.status)?;
        let operator_assertion = wire
            .operator_assertion
            .map(operator_assertion_from_wire)
            .transpose()?;
        let catalog_hints = wire
            .catalog_hints
            .into_iter()
            .map(catalog_hint_from_wire)
            .collect::<Result<Vec<_>, _>>()?;
        let health = DirectoryHealthV1 {
            class: parse_health_class(&wire.health.class)?,
            observed_bucket: wire.health.observed_bucket,
        };
        Ok(Self {
            provider_id,
            directory_sequence: wire.directory_sequence,
            directory_valid_until: wire.directory_valid_until,
            status,
            operator_assertion,
            operator_assertion_digest: None,
            catalog_hints,
            health,
        })
    }

    fn to_wire(&self) -> Result<DirectoryEntryJsonV1, DirectoryErrorV1> {
        Ok(DirectoryEntryJsonV1 {
            v: 1,
            provider_id: lower_hex(&self.provider_id),
            directory_sequence: self.directory_sequence,
            directory_valid_until: self.directory_valid_until,
            status: entry_status_name(self.status).to_owned(),
            operator_assertion: self
                .operator_assertion
                .as_ref()
                .map(operator_assertion_to_wire)
                .transpose()?,
            catalog_hints: self
                .catalog_hints
                .iter()
                .map(catalog_hint_to_wire)
                .collect(),
            health: DirectoryHealthJsonV1 {
                class: health_class_name(self.health.class).to_owned(),
                observed_bucket: self.health.observed_bucket,
            },
        })
    }

    fn validate_and_verify(&mut self, now_unix: u64) -> Result<(), DirectoryErrorV1> {
        if self.provider_id.iter().all(|byte| *byte == 0)
            || self.directory_sequence == 0
            || now_unix == 0
            || self.directory_valid_until < now_unix
            || self.directory_valid_until.saturating_sub(now_unix)
                > MAX_DIRECTORY_ENTRY_VALIDITY_SECONDS_V1
            || self.health.observed_bucket == 0
            || self.health.observed_bucket % HEALTH_BUCKET_SECONDS_V1 != 0
            || self.health.observed_bucket > now_unix
        {
            return Err(DirectoryErrorV1::EntryExpired);
        }
        validate_catalog_hints(&self.catalog_hints)?;
        match self.status {
            DirectoryEntryStatusV1::Active => {
                let assertion = self
                    .operator_assertion
                    .as_ref()
                    .ok_or(DirectoryErrorV1::InvalidOperatorAssertion)?;
                if assertion.provider_id != self.provider_id
                    || self.directory_valid_until > assertion.valid_until
                {
                    return Err(DirectoryErrorV1::InvalidOperatorAssertion);
                }
                let encoded = assertion
                    .encode()
                    .map_err(|_| DirectoryErrorV1::InvalidOperatorAssertion)?;
                let decoded = DirectoryOperatorAssertionV1::decode(&encoded)
                    .map_err(|_| DirectoryErrorV1::InvalidOperatorAssertion)?;
                if &decoded != assertion {
                    return Err(DirectoryErrorV1::InvalidOperatorAssertion);
                }
                let verified = assertion
                    .verify_current_for(
                        &self.provider_id,
                        &assertion.operator_pubkey_ed25519,
                        now_unix,
                        &DirectoryAssertionRollbackGuardV1::initial(),
                    )
                    .map_err(|_| DirectoryErrorV1::InvalidOperatorAssertion)?;
                self.operator_assertion_digest = Some(verified.assertion_digest());
            }
            DirectoryEntryStatusV1::Tombstone => {
                if self.operator_assertion.is_some() || !self.catalog_hints.is_empty() {
                    return Err(DirectoryErrorV1::InvalidValue);
                }
                self.operator_assertion_digest = None;
            }
        }
        Ok(())
    }
}

impl VerifiedDirectoryEntryEventV1 {
    pub const fn event(&self) -> &NostrEventV1 {
        &self.event
    }

    /// Directory-authenticated discovery metadata. Without an independent
    /// operator pin, the directory key is the curatorial/Sybil trust root for
    /// this candidate operator identity and endpoint. It is never by itself
    /// runtime, database, access-policy, payment, or non-collusion evidence;
    /// callers must close the live identity, attestation and access-policy
    /// checks through [`crate::bind_directory_entry_to_live_identity_v1`].
    pub const fn discovery_entry(&self) -> &DirectoryEntryV1 {
        &self.entry
    }

    pub const fn shard(&self) -> u8 {
        self.shard
    }
}

pub fn verify_directory_entry_event_v1(
    event_json: &[u8],
    pinned_directory_pubkey: &[u8; 32],
    now_unix: u64,
) -> Result<VerifiedDirectoryEntryEventV1, DirectoryErrorV1> {
    let event = NostrEventV1::parse_json(event_json)?;
    event.verify_for_directory_key(pinned_directory_pubkey)?;
    if event.created_at() == 0 || event.created_at() > now_unix {
        return Err(DirectoryErrorV1::EntryExpired);
    }
    let (d_value, shard_value) = exact_directory_profile_tag_values(&event)
        .map_err(|_| DirectoryErrorV1::InvalidEntryTag)?;
    let provider_hex = d_value
        .strip_prefix(DIRECTORY_ENTRY_D_PREFIX_V1)
        .ok_or(DirectoryErrorV1::InvalidEntryTag)?;
    let provider_from_tag: [u8; 32] = decode_lower_hex(provider_hex)?;
    let entry = DirectoryEntryV1::parse_canonical_json(event.content().as_bytes(), now_unix)?;
    if provider_from_tag != *entry.provider_id()
        || d_value != entry_d_tag_value_v1(entry.provider_id())
    {
        return Err(DirectoryErrorV1::InvalidEntryTag);
    }
    let shard = coarse_shard_for_provider_v1(entry.provider_id());
    if shard_value != shard_tag_value_v1(shard) {
        return Err(DirectoryErrorV1::InvalidShard);
    }
    if event.created_at() > entry.directory_valid_until() {
        return Err(DirectoryErrorV1::EntryExpired);
    }
    if entry
        .directory_valid_until()
        .saturating_sub(event.created_at())
        > MAX_DIRECTORY_ENTRY_VALIDITY_SECONDS_V1
    {
        return Err(DirectoryErrorV1::EntryExpired);
    }
    if let Some(assertion) = entry.operator_assertion() {
        if event.created_at() < assertion.not_before || event.created_at() > assertion.valid_until {
            return Err(DirectoryErrorV1::InvalidOperatorAssertion);
        }
    }
    Ok(VerifiedDirectoryEntryEventV1 {
        event,
        entry,
        shard,
    })
}

pub fn verify_directory_entry_event_for_operator_v1(
    event_json: &[u8],
    pinned_directory_pubkey: &[u8; 32],
    expected_provider_id: &[u8; 32],
    expected_operator_pubkey_ed25519: &[u8; 32],
    now_unix: u64,
) -> Result<VerifiedDirectoryEntryEventV1, DirectoryErrorV1> {
    let verified = verify_directory_entry_event_v1(event_json, pinned_directory_pubkey, now_unix)?;
    let entry = verified.discovery_entry();
    let assertion = entry
        .operator_assertion()
        .ok_or(DirectoryErrorV1::WrongOperatorIdentity)?;
    if entry.provider_id() != expected_provider_id
        || &assertion.operator_pubkey_ed25519 != expected_operator_pubkey_ed25519
    {
        return Err(DirectoryErrorV1::WrongOperatorIdentity);
    }
    assertion
        .verify_current_for(
            expected_provider_id,
            expected_operator_pubkey_ed25519,
            now_unix,
            &DirectoryAssertionRollbackGuardV1::initial(),
        )
        .map_err(|_| DirectoryErrorV1::WrongOperatorIdentity)?;
    Ok(verified)
}

pub fn entry_d_tag_value_v1(provider_id: &[u8; 32]) -> String {
    format!("{DIRECTORY_ENTRY_D_PREFIX_V1}{}", lower_hex(provider_id))
}

fn operator_assertion_from_wire(
    wire: DirectoryOperatorAssertionJsonV1,
) -> Result<DirectoryOperatorAssertionV1, DirectoryErrorV1> {
    if wire.v != 1 {
        return Err(DirectoryErrorV1::UnsupportedVersion);
    }
    Ok(DirectoryOperatorAssertionV1 {
        operator_pubkey_ed25519: decode_lower_hex(&wire.operator_pubkey_ed25519)?,
        stable_server_id: wire.stable_server_id,
        provider_id: decode_lower_hex(&wire.provider_id)?,
        assertion_epoch: wire.assertion_epoch,
        not_before: wire.not_before,
        valid_until: wire.valid_until,
        endpoints: wire
            .endpoints
            .into_iter()
            .map(|endpoint| {
                if endpoint.transport != "wss" {
                    return Err(DirectoryErrorV1::InvalidOperatorAssertion);
                }
                Ok(DirectoryEndpointV1 {
                    transport: DirectoryTransportV1::Wss,
                    url: endpoint.url,
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        signature_ed25519: decode_lower_hex(&wire.signature_ed25519)?,
    })
}

fn operator_assertion_to_wire(
    assertion: &DirectoryOperatorAssertionV1,
) -> Result<DirectoryOperatorAssertionJsonV1, DirectoryErrorV1> {
    assertion
        .encode()
        .map_err(|_| DirectoryErrorV1::InvalidOperatorAssertion)?;
    Ok(DirectoryOperatorAssertionJsonV1 {
        v: 1,
        operator_pubkey_ed25519: lower_hex(&assertion.operator_pubkey_ed25519),
        stable_server_id: assertion.stable_server_id.clone(),
        provider_id: lower_hex(&assertion.provider_id),
        assertion_epoch: assertion.assertion_epoch,
        not_before: assertion.not_before,
        valid_until: assertion.valid_until,
        endpoints: assertion
            .endpoints
            .iter()
            .map(|endpoint| DirectoryEndpointJsonV1 {
                transport: match endpoint.transport {
                    DirectoryTransportV1::Wss => "wss".to_owned(),
                },
                url: endpoint.url.clone(),
            })
            .collect(),
        signature_ed25519: lower_hex(&assertion.signature_ed25519),
    })
}

fn catalog_hint_from_wire(
    wire: DirectoryCatalogHintJsonV1,
) -> Result<DirectoryCatalogHintV1, DirectoryErrorV1> {
    Ok(DirectoryCatalogHintV1 {
        backend: DirectoryBackendV1::parse(&wire.backend)?,
        role: DirectoryServerRoleV1::parse(&wire.role)?,
        access: DirectoryAccessClassV1::parse(&wire.access)?,
        attestation: DirectoryAttestationV1::parse(&wire.attestation)?,
    })
}

fn catalog_hint_to_wire(hint: &DirectoryCatalogHintV1) -> DirectoryCatalogHintJsonV1 {
    DirectoryCatalogHintJsonV1 {
        backend: hint.backend.name().to_owned(),
        role: hint.role.name().to_owned(),
        access: hint.access.name().to_owned(),
        attestation: hint.attestation.name().to_owned(),
    }
}

/// Hints are strictly sorted by `(backend, access)`, unique per backend, and
/// carry one role and one attestation claim for the whole entry: a server has
/// exactly one DPF slot and one attestation tier.
fn validate_catalog_hints(hints: &[DirectoryCatalogHintV1]) -> Result<(), DirectoryErrorV1> {
    if hints.len() > MAX_DIRECTORY_CATALOG_HINTS_V1 {
        return Err(DirectoryErrorV1::InvalidCatalogHints);
    }
    if !hints
        .windows(2)
        .all(|pair| catalog_hint_key(&pair[0]) < catalog_hint_key(&pair[1]))
    {
        return Err(DirectoryErrorV1::InvalidCatalogHints);
    }
    if !hints
        .windows(2)
        .all(|pair| pair[0].backend != pair[1].backend)
    {
        return Err(DirectoryErrorV1::InvalidCatalogHints);
    }
    if let Some(first) = hints.first() {
        if hints
            .iter()
            .any(|hint| hint.role != first.role || hint.attestation != first.attestation)
        {
            return Err(DirectoryErrorV1::InvalidCatalogHints);
        }
    }
    Ok(())
}

fn catalog_hint_key(hint: &DirectoryCatalogHintV1) -> (u8, u8) {
    (hint.backend as u8, hint.access as u8)
}

impl DirectoryBackendV1 {
    pub const ALL: [Self; 4] = [Self::Dpf, Self::Harmony, Self::Onion, Self::Oram];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Dpf => "dpf",
            Self::Harmony => "harmony",
            Self::Onion => "onion",
            Self::Oram => "oram",
        }
    }

    pub fn parse(value: &str) -> Result<Self, DirectoryErrorV1> {
        Self::ALL
            .into_iter()
            .find(|backend| backend.name() == value)
            .ok_or(DirectoryErrorV1::InvalidCatalogHints)
    }
}

impl DirectoryServerRoleV1 {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Secondary => "secondary",
        }
    }

    pub fn parse(value: &str) -> Result<Self, DirectoryErrorV1> {
        match value {
            "primary" => Ok(Self::Primary),
            "secondary" => Ok(Self::Secondary),
            _ => Err(DirectoryErrorV1::InvalidCatalogHints),
        }
    }
}

impl DirectoryAccessClassV1 {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Paid => "paid",
            Self::BestEffort => "best-effort",
        }
    }

    pub fn parse(value: &str) -> Result<Self, DirectoryErrorV1> {
        match value {
            "free" => Ok(Self::Free),
            "paid" => Ok(Self::Paid),
            "best-effort" => Ok(Self::BestEffort),
            _ => Err(DirectoryErrorV1::InvalidCatalogHints),
        }
    }
}

impl DirectoryAttestationV1 {
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::SevSnp => "sev-snp",
        }
    }

    pub fn parse(value: &str) -> Result<Self, DirectoryErrorV1> {
        match value {
            "none" => Ok(Self::None),
            "sev-snp" => Ok(Self::SevSnp),
            _ => Err(DirectoryErrorV1::InvalidCatalogHints),
        }
    }
}

fn parse_entry_status(value: &str) -> Result<DirectoryEntryStatusV1, DirectoryErrorV1> {
    match value {
        "active" => Ok(DirectoryEntryStatusV1::Active),
        "tombstone" => Ok(DirectoryEntryStatusV1::Tombstone),
        _ => Err(DirectoryErrorV1::InvalidValue),
    }
}

fn entry_status_name(value: DirectoryEntryStatusV1) -> &'static str {
    match value {
        DirectoryEntryStatusV1::Active => "active",
        DirectoryEntryStatusV1::Tombstone => "tombstone",
    }
}

fn parse_health_class(value: &str) -> Result<DirectoryHealthClassV1, DirectoryErrorV1> {
    match value {
        "unknown" => Ok(DirectoryHealthClassV1::Unknown),
        "available" => Ok(DirectoryHealthClassV1::Available),
        "degraded" => Ok(DirectoryHealthClassV1::Degraded),
        "unavailable" => Ok(DirectoryHealthClassV1::Unavailable),
        _ => Err(DirectoryErrorV1::InvalidValue),
    }
}

fn health_class_name(value: DirectoryHealthClassV1) -> &'static str {
    match value {
        DirectoryHealthClassV1::Unknown => "unknown",
        DirectoryHealthClassV1::Available => "available",
        DirectoryHealthClassV1::Degraded => "degraded",
        DirectoryHealthClassV1::Unavailable => "unavailable",
    }
}
