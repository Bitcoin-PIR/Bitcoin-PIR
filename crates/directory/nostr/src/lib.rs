//! Strict, transport-free NIP-01/NIP-78 codec and rollback state machine for
//! the BitcoinPIR discovery directory.
//!
//! Directory output is candidate metadata only. It never establishes provider,
//! runtime, database, access-policy, payment, or two-provider independence
//! trust. See `docs/DIRECTORY_PROTOCOL.md`.

#![forbid(unsafe_code)]

mod assertion;
mod checkpoint;
mod entry;
mod error;
mod event;
mod hex;
mod publisher;
mod state;

pub use assertion::{
    derive_provider_id, is_canonical_public_wss_endpoint_v1, is_canonical_public_wss_origin_v1,
    DirectoryAssertionErrorV1, DirectoryAssertionRollbackGuardV1, DirectoryEndpointV1,
    DirectoryOperatorAssertionV1, DirectoryTransportV1, ProviderId,
    VerifiedDirectoryOperatorAssertionV1, DIRECTORY_ASSERTION_VERSION_V1,
    DIRECTORY_OPERATOR_ASSERTION_DIGEST_DOMAIN_V1,
    DIRECTORY_OPERATOR_ASSERTION_SIGNATURE_DOMAIN_V1, MAX_DIRECTORY_ASSERTION_LEN_V1,
    MAX_DIRECTORY_ASSERTION_VALIDITY_SECONDS_V1, MAX_DIRECTORY_ENDPOINTS_V1,
    MAX_DIRECTORY_ENDPOINT_LEN_V1, MAX_DIRECTORY_SERVER_ID_LEN_V1, PROVIDER_ID_DOMAIN_V1,
};

pub use checkpoint::{
    catalog_root_v1, checkpoint_d_tag_value_v1, verify_directory_checkpoint_event_v1,
    DirectoryCatalogCheckpointV1, DirectoryCheckpointEntryV1, VerifiedDirectoryCheckpointEventV1,
    DIRECTORY_CATALOG_ROOT_DOMAIN_V1, DIRECTORY_CHECKPOINT_D_PREFIX_V1,
    MAX_DIRECTORY_CHECKPOINT_ENTRIES_V1, MAX_DIRECTORY_CHECKPOINT_VALIDITY_SECONDS_V1,
};

pub use entry::{
    entry_d_tag_value_v1, verify_directory_entry_event_for_operator_v1,
    verify_directory_entry_event_v1, DirectoryAccessClassV1, DirectoryAttestationV1,
    DirectoryBackendV1, DirectoryCatalogHintV1, DirectoryEntryStatusV1, DirectoryEntryV1,
    DirectoryHealthClassV1, DirectoryHealthV1, DirectoryServerRoleV1,
    VerifiedDirectoryEntryEventV1, DIRECTORY_ENTRY_D_PREFIX_V1, HEALTH_BUCKET_SECONDS_V1,
    MAX_DIRECTORY_CATALOG_HINTS_V1, MAX_DIRECTORY_ENTRY_VALIDITY_SECONDS_V1,
};
pub use error::{DirectoryAcceptErrorV1, DirectoryErrorV1};
pub use event::{
    nip01_addressable_replacement_order_v1, validate_directory_xonly_public_key_v1, NostrEventV1,
    BITCOINPIR_DIRECTORY_KIND_V1, MAX_NOSTR_CONTENT_BYTES_V1, MAX_NOSTR_EVENT_BYTES_V1,
    MAX_NOSTR_TAGS_V1, MAX_NOSTR_TAG_ITEMS_V1, MAX_NOSTR_TAG_VALUE_BYTES_V1,
};
pub use publisher::{
    catalog_req_json_v1, full_catalog_req_json_v1, DirectoryPublisherKeyV1,
    DIRECTORY_REQ_SUBSCRIPTION_PREFIX_V1,
};
pub use state::{
    bind_directory_entry_to_live_identity_v1, bind_persisted_directory_shard_catalog_v1,
    prepare_directory_checkpoint_acceptance_v1, prepare_directory_entry_acceptance_v1,
    verify_and_persist_directory_checkpoint_v1, verify_and_persist_directory_entry_v1,
    DirectoryAcceptanceDispositionV1, DirectoryCasOutcomeV1, DirectoryCheckpointRollbackStateV1,
    DirectoryCheckpointStateKeyV1, DirectoryEntryRollbackStateV1, DirectoryEntryStateKeyV1,
    DirectoryRollbackStoreV1, LiveProviderIdentityV1, PersistedDirectoryCheckpointV1,
    PersistedDirectoryEntryV1, PersistedDirectoryShardCatalogV1, UnpersistedDirectoryCheckpointV1,
    UnpersistedDirectoryEntryV1, VerifiedDirectoryIdentityBindingV1,
};

pub const DIRECTORY_SHARD_COUNT_V1: u8 = 16;
pub const DIRECTORY_SHARD_TAG_PREFIX_V1: &str = "bitcoinpir-service-directory-shard-v1:";

pub const fn coarse_shard_for_provider_v1(provider_id: &[u8; 32]) -> u8 {
    provider_id[0] >> 4
}

pub fn shard_tag_value_v1(shard: u8) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    if shard >= DIRECTORY_SHARD_COUNT_V1 {
        return String::new();
    }
    let mut value = String::from(DIRECTORY_SHARD_TAG_PREFIX_V1);
    value.push(HEX[usize::from(shard)] as char);
    value
}

#[cfg(test)]
mod tests;
