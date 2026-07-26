//! Independently durable anti-rollback authority for issuer state.
//!
//! An implementation is trusted production infrastructure. Its state must not
//! be restored atomically with the protected SQLite database, WAL, or backups.

use crate::{StoreError, StoreIdentity, StoreResult, SCHEMA_VERSION};
use pir_service_protocol::LightningNetworkV1;
use sha2::{Digest, Sha256};
use std::fmt;

pub const ISSUER_ROLLBACK_INITIAL_COMMITMENT_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-store-initial-commitment/v1";
pub const ISSUER_ROLLBACK_MUTATION_COMMITMENT_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-store-mutation-commitment/v1";
const ISSUER_MUTATION_DIGEST_DOMAIN_V1: &[u8] = b"BitcoinPIR/issuer-store-mutation-digest/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IssuerRollbackFloorV1 {
    pub store_instance_id: [u8; 16],
    pub issuer_id: [u8; 32],
    pub network: LightningNetworkV1,
    pub store_generation: u64,
    pub rollback_commitment: [u8; 32],
    pub schema_version: u32,
}

impl IssuerRollbackFloorV1 {
    pub(crate) fn from_identity(identity: &StoreIdentity) -> Self {
        Self {
            store_instance_id: identity.store_instance_id,
            issuer_id: identity.issuer_id,
            network: identity.network,
            store_generation: identity.commit_seq,
            rollback_commitment: identity.rollback_commitment,
            schema_version: identity.schema_version,
        }
    }

    pub(crate) fn validate(&self) -> StoreResult<()> {
        if self.store_instance_id.iter().all(|byte| *byte == 0)
            || self.issuer_id.iter().all(|byte| *byte == 0)
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
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerRollbackFloorAuthorityErrorV1 {
    reason: String,
}

impl IssuerRollbackFloorAuthorityErrorV1 {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl fmt::Display for IssuerRollbackFloorAuthorityErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.reason)
    }
}

impl std::error::Error for IssuerRollbackFloorAuthorityErrorV1 {}

/// Linearizable, independently durable compare-and-swap authority.
///
/// `initialize` installs an absent generation-zero record and is idempotent
/// only for the exact same floor. `compare_and_advance` atomically changes
/// `expected` to `next`, or returns the already-current record. It must never
/// lower a generation, rebind an identity, or accept two commitments at the
/// same generation.
pub trait IssuerRollbackFloorAuthorityV1: fmt::Debug + Send + Sync + 'static {
    fn load(
        &self,
        issuer_id: &[u8; 32],
        network: LightningNetworkV1,
    ) -> Result<Option<IssuerRollbackFloorV1>, IssuerRollbackFloorAuthorityErrorV1>;

    fn initialize(
        &self,
        initial: &IssuerRollbackFloorV1,
    ) -> Result<IssuerRollbackFloorV1, IssuerRollbackFloorAuthorityErrorV1>;

    fn compare_and_advance(
        &self,
        expected: &IssuerRollbackFloorV1,
        next: &IssuerRollbackFloorV1,
    ) -> Result<IssuerRollbackFloorV1, IssuerRollbackFloorAuthorityErrorV1>;
}

pub(crate) fn initial_commitment(
    store_instance_id: &[u8; 16],
    issuer_id: &[u8; 32],
    network: LightningNetworkV1,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ISSUER_ROLLBACK_INITIAL_COMMITMENT_DOMAIN_V1);
    hasher.update(store_instance_id);
    hasher.update(issuer_id);
    hasher.update([network as u8]);
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
    hasher.update(ISSUER_ROLLBACK_MUTATION_COMMITMENT_DOMAIN_V1);
    hasher.update(previous);
    hasher.update(next_generation.to_le_bytes());
    hasher.update((mutation_kind.len() as u16).to_le_bytes());
    hasher.update(mutation_kind);
    hasher.update(mutation_digest);
    hasher.finalize().into()
}

pub(crate) fn mutation_digest(mutation_kind: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ISSUER_MUTATION_DIGEST_DOMAIN_V1);
    hasher.update((mutation_kind.len() as u16).to_le_bytes());
    hasher.update(mutation_kind);
    hasher.update((parts.len() as u16).to_le_bytes());
    for part in parts {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}
