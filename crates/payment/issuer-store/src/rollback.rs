//! Internal commit-chain bookkeeping for issuer state.
//!
//! Every committed mutation advances `commit_seq` and extends a hash chain
//! over the mutation history inside the same SQLite transaction. This is
//! plain bookkeeping used by integrity checks; there is no external
//! anti-rollback authority.

use sha2::{Digest, Sha256};

use crate::SCHEMA_VERSION;
use pir_service_protocol::LightningNetworkV1;

const ISSUER_ROLLBACK_INITIAL_COMMITMENT_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-store-initial-commitment/v1";
const ISSUER_ROLLBACK_MUTATION_COMMITMENT_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-store-mutation-commitment/v1";
const ISSUER_MUTATION_DIGEST_DOMAIN_V1: &[u8] = b"BitcoinPIR/issuer-store-mutation-digest/v1";

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
