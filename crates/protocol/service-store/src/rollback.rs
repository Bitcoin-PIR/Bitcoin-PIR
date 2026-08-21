//! Internal commit-chain bookkeeping for provider state.
//!
//! Every committed mutation advances the store generation and extends a hash
//! chain over the mutation history inside the same SQLite transaction. This is
//! plain bookkeeping used by integrity checks; there is no external
//! anti-rollback authority.

use sha2::{Digest, Sha256};

use crate::SCHEMA_VERSION;

const ROLLBACK_INITIAL_COMMITMENT_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/provider-store-initial-commitment/v1";
const ROLLBACK_MUTATION_COMMITMENT_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/provider-store-mutation-commitment/v1";

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
