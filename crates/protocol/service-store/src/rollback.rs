//! Independently durable anti-rollback authority contract.
//!
//! An implementation is trusted production infrastructure. It must not store
//! its state in the protected SQLite database, its WAL, or a backup set which
//! can be restored atomically with that database.

use std::fmt;

use crate::{StoreError, StoreIdentity, StoreResult, SCHEMA_VERSION};
use sha2::{Digest, Sha256};

pub const ROLLBACK_INITIAL_COMMITMENT_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/provider-store-initial-commitment/v1";
pub const ROLLBACK_MUTATION_COMMITMENT_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/provider-store-mutation-commitment/v1";

/// Exact independently anchored snapshot for one logical provider store.
///
/// The authority is keyed by `provider_id`; changing `store_instance_id` is a
/// keyset-revocation/new-store ceremony, never an automatic restore action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RollbackFloorV1 {
    pub store_instance_id: [u8; 16],
    pub provider_id: [u8; 32],
    pub store_generation: u64,
    pub spend_commit_seq: u64,
    pub rollback_commitment: [u8; 32],
    pub schema_version: u32,
}

impl RollbackFloorV1 {
    pub(crate) fn from_identity(identity: &StoreIdentity) -> Self {
        Self {
            store_instance_id: identity.store_instance_id,
            provider_id: identity.provider_id,
            store_generation: identity.store_generation,
            spend_commit_seq: identity.spend_commit_seq,
            rollback_commitment: identity.rollback_commitment,
            schema_version: identity.schema_version,
        }
    }

    pub(crate) fn validate(&self) -> StoreResult<()> {
        if self.store_instance_id.iter().all(|byte| *byte == 0)
            || self.provider_id.iter().all(|byte| *byte == 0)
            || self.rollback_commitment.iter().all(|byte| *byte == 0)
        {
            return Err(StoreError::RollbackAuthorityProtocol(
                "floor contains a zero identity or commitment".to_owned(),
            ));
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err(StoreError::RollbackAuthorityProtocol(
                "floor schema version is unsupported".to_owned(),
            ));
        }
        if self.spend_commit_seq > self.store_generation {
            return Err(StoreError::RollbackAuthorityProtocol(
                "floor spend sequence exceeds store generation".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Opaque failure reported by independently operated durable infrastructure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RollbackFloorAuthorityErrorV1 {
    reason: String,
}

impl RollbackFloorAuthorityErrorV1 {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl fmt::Display for RollbackFloorAuthorityErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for RollbackFloorAuthorityErrorV1 {}

/// Linearizable, independently durable compare-and-swap authority.
///
/// Every returned record is the durable live authority value after the
/// attempted operation. `Ok` alone does **not** mean the requested mutation
/// applied: `initialize` and `compare_and_advance` may return a conflicting
/// current record. Every caller must validate exact equality with the expected
/// initial/next floor (or apply its explicit domain reconciliation rule) before
/// treating the operation as successful. An implementation must never lower a
/// generation, change a store identity, or accept two different commitments at
/// one generation.
pub trait RollbackFloorAuthorityV1: fmt::Debug + Send + Sync + 'static {
    fn load(
        &self,
        provider_id: &[u8; 32],
    ) -> Result<Option<RollbackFloorV1>, RollbackFloorAuthorityErrorV1>;

    fn initialize(
        &self,
        initial: &RollbackFloorV1,
    ) -> Result<RollbackFloorV1, RollbackFloorAuthorityErrorV1>;

    fn compare_and_advance(
        &self,
        expected: &RollbackFloorV1,
        next: &RollbackFloorV1,
    ) -> Result<RollbackFloorV1, RollbackFloorAuthorityErrorV1>;
}

pub(crate) fn initial_commitment(store_instance_id: &[u8; 16], provider_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ROLLBACK_INITIAL_COMMITMENT_DOMAIN_V1);
    hasher.update(store_instance_id);
    hasher.update(provider_id);
    hasher.update(SCHEMA_VERSION.to_le_bytes());
    hasher.finalize().into()
}

pub(crate) fn next_commitment(
    previous: &[u8; 32],
    next_generation: u64,
    mutation_kind: &[u8],
    mutation_digest: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ROLLBACK_MUTATION_COMMITMENT_DOMAIN_V1);
    hasher.update(previous);
    hasher.update(next_generation.to_le_bytes());
    hasher.update((mutation_kind.len() as u16).to_le_bytes());
    hasher.update(mutation_kind);
    hasher.update(mutation_digest);
    hasher.finalize().into()
}
