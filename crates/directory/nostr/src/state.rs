//! Pure anti-rollback transitions and an asynchronous durable CAS boundary.
//!
//! The state is keyed independently per directory/provider or
//! directory/coarse-shard. It contains no provider-pair, payment, query, or
//! client identity field.

use core::future::Future;

use pir_service_protocol::{ProviderId, VerifiedCurrentPolicyV1};

use crate::{
    verify_directory_checkpoint_event_v1, verify_directory_entry_event_v1, DirectoryEntryStatusV1,
    DirectoryErrorV1, VerifiedDirectoryCheckpointEventV1, VerifiedDirectoryEntryEventV1,
    DIRECTORY_SHARD_COUNT_V1,
};

const ENTRY_STATE_DOMAIN_V1: &[u8] = b"BitcoinPIR/directory-entry-state/v1";
const CHECKPOINT_STATE_DOMAIN_V1: &[u8] = b"BitcoinPIR/directory-checkpoint-state/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryEntryStateKeyV1 {
    pub directory_pubkey: [u8; 32],
    pub provider_id: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryCheckpointStateKeyV1 {
    pub directory_pubkey: [u8; 32],
    pub shard: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryCasOutcomeV1 {
    Applied,
    /// The exact proposed successor was already made durable, for example
    /// after a successful write whose response was lost.
    AlreadyCurrent,
    Conflict,
}

/// Browser/native persistence contract. A successful CAS acknowledgment must
/// mean the exact successor bytes are durable. IndexedDB implementations may
/// use transaction futures; native implementations may return ready futures.
pub trait DirectoryRollbackStoreV1 {
    type Error;
    type LoadEntryFuture<'a>: Future<Output = Result<Option<Vec<u8>>, Self::Error>> + 'a
    where
        Self: 'a;
    type CasEntryFuture<'a>: Future<Output = Result<DirectoryCasOutcomeV1, Self::Error>> + 'a
    where
        Self: 'a;
    type LoadCheckpointFuture<'a>: Future<Output = Result<Option<Vec<u8>>, Self::Error>> + 'a
    where
        Self: 'a;
    type CasCheckpointFuture<'a>: Future<Output = Result<DirectoryCasOutcomeV1, Self::Error>> + 'a
    where
        Self: 'a;

    fn load_entry<'a>(&'a mut self, key: DirectoryEntryStateKeyV1) -> Self::LoadEntryFuture<'a>;

    fn compare_and_swap_entry<'a>(
        &'a mut self,
        key: DirectoryEntryStateKeyV1,
        expected: Option<Vec<u8>>,
        successor: Vec<u8>,
    ) -> Self::CasEntryFuture<'a>;

    fn load_checkpoint<'a>(
        &'a mut self,
        key: DirectoryCheckpointStateKeyV1,
    ) -> Self::LoadCheckpointFuture<'a>;

    fn compare_and_swap_checkpoint<'a>(
        &'a mut self,
        key: DirectoryCheckpointStateKeyV1,
        expected: Option<Vec<u8>>,
        successor: Vec<u8>,
    ) -> Self::CasCheckpointFuture<'a>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryEntryRollbackStateV1 {
    directory_pubkey: [u8; 32],
    provider_id: [u8; 32],
    highest_directory_sequence: u64,
    event_id_at_highest_sequence: [u8; 32],
    event_created_at_at_highest_sequence: u64,
    status_at_highest_sequence: DirectoryEntryStatusV1,
    highest_operator_assertion_epoch: u64,
    operator_assertion_digest_at_highest_epoch: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryCheckpointRollbackStateV1 {
    directory_pubkey: [u8; 32],
    shard: u8,
    highest_checkpoint_epoch: u64,
    catalog_root_at_highest_epoch: [u8; 32],
    event_id_at_highest_epoch: [u8; 32],
    event_created_at_at_highest_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryAcceptanceDispositionV1 {
    Initial,
    Advanced,
    ExactReplay,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnpersistedDirectoryEntryV1 {
    verified: VerifiedDirectoryEntryEventV1,
    expected_state: Option<DirectoryEntryRollbackStateV1>,
    successor_state: DirectoryEntryRollbackStateV1,
    disposition: DirectoryAcceptanceDispositionV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedDirectoryEntryV1 {
    verified: VerifiedDirectoryEntryEventV1,
    state: DirectoryEntryRollbackStateV1,
    disposition: DirectoryAcceptanceDispositionV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnpersistedDirectoryCheckpointV1 {
    verified: VerifiedDirectoryCheckpointEventV1,
    expected_state: Option<DirectoryCheckpointRollbackStateV1>,
    successor_state: DirectoryCheckpointRollbackStateV1,
    disposition: DirectoryAcceptanceDispositionV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedDirectoryCheckpointV1 {
    verified: VerifiedDirectoryCheckpointEventV1,
    state: DirectoryCheckpointRollbackStateV1,
    disposition: DirectoryAcceptanceDispositionV1,
}

/// Client-side evidence that every entry and the checkpoint were first made
/// durable under their independent rollback keys, then matched exactly as one
/// complete shard. Only this type is suitable for provider selection.
#[derive(Debug, Eq, PartialEq)]
pub struct PersistedDirectoryShardCatalogV1<'a> {
    checkpoint: &'a PersistedDirectoryCheckpointV1,
    entries: Vec<&'a PersistedDirectoryEntryV1>,
}

/// Evidence that one active entry came from a complete, durably accepted
/// checkpointed shard and matches a policy already verified through the live
/// provider trust path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedDirectoryPolicyBindingV1<'entry, 'policy> {
    entry: &'entry PersistedDirectoryEntryV1,
    policy: VerifiedCurrentPolicyV1<'policy>,
}

impl DirectoryEntryRollbackStateV1 {
    pub fn encode(&self) -> Result<Vec<u8>, DirectoryErrorV1> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(ENTRY_STATE_DOMAIN_V1.len() + 154);
        bytes.extend_from_slice(ENTRY_STATE_DOMAIN_V1);
        bytes.push(1);
        bytes.extend_from_slice(&self.directory_pubkey);
        bytes.extend_from_slice(&self.provider_id);
        bytes.extend_from_slice(&self.highest_directory_sequence.to_le_bytes());
        bytes.extend_from_slice(&self.event_id_at_highest_sequence);
        bytes.extend_from_slice(&self.event_created_at_at_highest_sequence.to_le_bytes());
        bytes.push(match self.status_at_highest_sequence {
            DirectoryEntryStatusV1::Active => 1,
            DirectoryEntryStatusV1::Tombstone => 2,
        });
        bytes.extend_from_slice(&self.highest_operator_assertion_epoch.to_le_bytes());
        bytes.extend_from_slice(&self.operator_assertion_digest_at_highest_epoch);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DirectoryErrorV1> {
        let expected_len = ENTRY_STATE_DOMAIN_V1.len() + 1 + 32 + 32 + 8 + 32 + 8 + 1 + 8 + 32;
        if bytes.len() != expected_len || !bytes.starts_with(ENTRY_STATE_DOMAIN_V1) {
            return Err(DirectoryErrorV1::CorruptRollbackState);
        }
        let mut offset = ENTRY_STATE_DOMAIN_V1.len();
        if take::<1>(bytes, &mut offset)?[0] != 1 {
            return Err(DirectoryErrorV1::CorruptRollbackState);
        }
        let value = Self {
            directory_pubkey: take(bytes, &mut offset)?,
            provider_id: take(bytes, &mut offset)?,
            highest_directory_sequence: u64::from_le_bytes(take(bytes, &mut offset)?),
            event_id_at_highest_sequence: take(bytes, &mut offset)?,
            event_created_at_at_highest_sequence: u64::from_le_bytes(take(bytes, &mut offset)?),
            status_at_highest_sequence: match take::<1>(bytes, &mut offset)?[0] {
                1 => DirectoryEntryStatusV1::Active,
                2 => DirectoryEntryStatusV1::Tombstone,
                _ => return Err(DirectoryErrorV1::CorruptRollbackState),
            },
            highest_operator_assertion_epoch: u64::from_le_bytes(take(bytes, &mut offset)?),
            operator_assertion_digest_at_highest_epoch: take(bytes, &mut offset)?,
        };
        if offset != bytes.len() {
            return Err(DirectoryErrorV1::CorruptRollbackState);
        }
        value.validate()?;
        Ok(value)
    }

    pub const fn key(&self) -> DirectoryEntryStateKeyV1 {
        DirectoryEntryStateKeyV1 {
            directory_pubkey: self.directory_pubkey,
            provider_id: self.provider_id,
        }
    }

    pub const fn highest_directory_sequence(&self) -> u64 {
        self.highest_directory_sequence
    }

    pub const fn event_id_at_highest_sequence(&self) -> &[u8; 32] {
        &self.event_id_at_highest_sequence
    }

    pub const fn event_created_at_at_highest_sequence(&self) -> u64 {
        self.event_created_at_at_highest_sequence
    }

    pub const fn status_at_highest_sequence(&self) -> DirectoryEntryStatusV1 {
        self.status_at_highest_sequence
    }

    pub const fn highest_operator_assertion_epoch(&self) -> u64 {
        self.highest_operator_assertion_epoch
    }

    pub const fn operator_assertion_digest_at_highest_epoch(&self) -> &[u8; 32] {
        &self.operator_assertion_digest_at_highest_epoch
    }

    fn validate(&self) -> Result<(), DirectoryErrorV1> {
        let digest_is_zero = self
            .operator_assertion_digest_at_highest_epoch
            .iter()
            .all(|byte| *byte == 0);
        if self.directory_pubkey.iter().all(|byte| *byte == 0)
            || self.provider_id.iter().all(|byte| *byte == 0)
            || self.highest_directory_sequence == 0
            || self
                .event_id_at_highest_sequence
                .iter()
                .all(|byte| *byte == 0)
            || self.event_created_at_at_highest_sequence == 0
            || (self.highest_operator_assertion_epoch == 0) != digest_is_zero
            || (self.status_at_highest_sequence == DirectoryEntryStatusV1::Active
                && self.highest_operator_assertion_epoch == 0)
        {
            return Err(DirectoryErrorV1::CorruptRollbackState);
        }
        Ok(())
    }
}

impl DirectoryCheckpointRollbackStateV1 {
    pub fn encode(&self) -> Result<Vec<u8>, DirectoryErrorV1> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(CHECKPOINT_STATE_DOMAIN_V1.len() + 114);
        bytes.extend_from_slice(CHECKPOINT_STATE_DOMAIN_V1);
        bytes.push(1);
        bytes.extend_from_slice(&self.directory_pubkey);
        bytes.push(self.shard);
        bytes.extend_from_slice(&self.highest_checkpoint_epoch.to_le_bytes());
        bytes.extend_from_slice(&self.catalog_root_at_highest_epoch);
        bytes.extend_from_slice(&self.event_id_at_highest_epoch);
        bytes.extend_from_slice(&self.event_created_at_at_highest_epoch.to_le_bytes());
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DirectoryErrorV1> {
        let expected_len = CHECKPOINT_STATE_DOMAIN_V1.len() + 1 + 32 + 1 + 8 + 32 + 32 + 8;
        if bytes.len() != expected_len || !bytes.starts_with(CHECKPOINT_STATE_DOMAIN_V1) {
            return Err(DirectoryErrorV1::CorruptRollbackState);
        }
        let mut offset = CHECKPOINT_STATE_DOMAIN_V1.len();
        if take::<1>(bytes, &mut offset)?[0] != 1 {
            return Err(DirectoryErrorV1::CorruptRollbackState);
        }
        let value = Self {
            directory_pubkey: take(bytes, &mut offset)?,
            shard: take::<1>(bytes, &mut offset)?[0],
            highest_checkpoint_epoch: u64::from_le_bytes(take(bytes, &mut offset)?),
            catalog_root_at_highest_epoch: take(bytes, &mut offset)?,
            event_id_at_highest_epoch: take(bytes, &mut offset)?,
            event_created_at_at_highest_epoch: u64::from_le_bytes(take(bytes, &mut offset)?),
        };
        if offset != bytes.len() {
            return Err(DirectoryErrorV1::CorruptRollbackState);
        }
        value.validate()?;
        Ok(value)
    }

    pub const fn key(&self) -> DirectoryCheckpointStateKeyV1 {
        DirectoryCheckpointStateKeyV1 {
            directory_pubkey: self.directory_pubkey,
            shard: self.shard,
        }
    }

    pub const fn highest_checkpoint_epoch(&self) -> u64 {
        self.highest_checkpoint_epoch
    }

    pub const fn catalog_root_at_highest_epoch(&self) -> &[u8; 32] {
        &self.catalog_root_at_highest_epoch
    }

    pub const fn event_id_at_highest_epoch(&self) -> &[u8; 32] {
        &self.event_id_at_highest_epoch
    }

    pub const fn event_created_at_at_highest_epoch(&self) -> u64 {
        self.event_created_at_at_highest_epoch
    }

    fn validate(&self) -> Result<(), DirectoryErrorV1> {
        if self.directory_pubkey.iter().all(|byte| *byte == 0)
            || self.shard >= DIRECTORY_SHARD_COUNT_V1
            || self.highest_checkpoint_epoch == 0
            || self
                .catalog_root_at_highest_epoch
                .iter()
                .all(|byte| *byte == 0)
            || self.event_id_at_highest_epoch.iter().all(|byte| *byte == 0)
            || self.event_created_at_at_highest_epoch == 0
        {
            return Err(DirectoryErrorV1::CorruptRollbackState);
        }
        Ok(())
    }
}

impl UnpersistedDirectoryEntryV1 {
    pub const fn disposition(&self) -> DirectoryAcceptanceDispositionV1 {
        self.disposition
    }

    pub const fn proposed_state(&self) -> &DirectoryEntryRollbackStateV1 {
        &self.successor_state
    }

    /// Convert this transition into selectable evidence only after a durable
    /// adapter reads back the exact proposed rollback state. This is the
    /// synchronous half of the browser persist-before-select boundary.
    pub fn confirm_durable_state(
        self,
        durable_state_bytes: &[u8],
    ) -> Result<PersistedDirectoryEntryV1, DirectoryErrorV1> {
        let durable_state = DirectoryEntryRollbackStateV1::decode(durable_state_bytes)?;
        if durable_state != self.successor_state {
            return Err(DirectoryErrorV1::CorruptRollbackState);
        }
        Ok(PersistedDirectoryEntryV1 {
            verified: self.verified,
            state: durable_state,
            disposition: self.disposition,
        })
    }
}

impl PersistedDirectoryEntryV1 {
    pub const fn verified(&self) -> &VerifiedDirectoryEntryEventV1 {
        &self.verified
    }

    pub const fn rollback_state(&self) -> &DirectoryEntryRollbackStateV1 {
        &self.state
    }

    pub const fn disposition(&self) -> DirectoryAcceptanceDispositionV1 {
        self.disposition
    }
}

impl UnpersistedDirectoryCheckpointV1 {
    pub const fn disposition(&self) -> DirectoryAcceptanceDispositionV1 {
        self.disposition
    }

    pub const fn proposed_state(&self) -> &DirectoryCheckpointRollbackStateV1 {
        &self.successor_state
    }

    /// Checkpoint counterpart of
    /// [`UnpersistedDirectoryEntryV1::confirm_durable_state`].
    pub fn confirm_durable_state(
        self,
        durable_state_bytes: &[u8],
    ) -> Result<PersistedDirectoryCheckpointV1, DirectoryErrorV1> {
        let durable_state = DirectoryCheckpointRollbackStateV1::decode(durable_state_bytes)?;
        if durable_state != self.successor_state {
            return Err(DirectoryErrorV1::CorruptRollbackState);
        }
        Ok(PersistedDirectoryCheckpointV1 {
            verified: self.verified,
            state: durable_state,
            disposition: self.disposition,
        })
    }
}

impl PersistedDirectoryCheckpointV1 {
    pub const fn verified(&self) -> &VerifiedDirectoryCheckpointEventV1 {
        &self.verified
    }

    pub const fn rollback_state(&self) -> &DirectoryCheckpointRollbackStateV1 {
        &self.state
    }

    pub const fn disposition(&self) -> DirectoryAcceptanceDispositionV1 {
        self.disposition
    }
}

impl<'a> PersistedDirectoryShardCatalogV1<'a> {
    pub const fn checkpoint(&self) -> &'a PersistedDirectoryCheckpointV1 {
        self.checkpoint
    }

    pub fn entries(&self) -> &[&'a PersistedDirectoryEntryV1] {
        &self.entries
    }

    pub fn active_entries(&self) -> impl Iterator<Item = &'a PersistedDirectoryEntryV1> + '_ {
        self.entries.iter().copied().filter(|entry| {
            entry.verified().discovery_entry().status() == DirectoryEntryStatusV1::Active
        })
    }
}

impl<'entry, 'policy> VerifiedDirectoryPolicyBindingV1<'entry, 'policy> {
    pub const fn directory_entry(&self) -> &'entry PersistedDirectoryEntryV1 {
        self.entry
    }

    pub const fn live_policy(&self) -> VerifiedCurrentPolicyV1<'policy> {
        self.policy
    }
}

/// Produce a selectable complete shard only after all rollback state is
/// durable. Input order is irrelevant. Missing, duplicate, stale, foreign, or
/// substituted entries fail closed against the checkpoint's exact event IDs.
pub fn bind_persisted_directory_shard_catalog_v1<'a>(
    checkpoint: &'a PersistedDirectoryCheckpointV1,
    entries: &'a [PersistedDirectoryEntryV1],
) -> Result<PersistedDirectoryShardCatalogV1<'a>, DirectoryErrorV1> {
    let committed = checkpoint.verified().checkpoint();
    if entries.len() != committed.entries().len() {
        return Err(DirectoryErrorV1::CatalogEntrySetMismatch);
    }
    let mut sorted = entries.iter().collect::<Vec<_>>();
    sorted.sort_by_key(|entry| *entry.verified().discovery_entry().provider_id());
    for (entry, expected) in sorted.iter().zip(committed.entries()) {
        let verified = entry.verified();
        if verified.event().pubkey() != checkpoint.verified().event().pubkey()
            || verified.shard() != committed.shard()
            || verified.discovery_entry().provider_id() != &expected.provider_id
            || verified.discovery_entry().directory_sequence() != expected.directory_sequence
            || verified.event().id() != &expected.event_id
        {
            return Err(DirectoryErrorV1::CatalogEntrySetMismatch);
        }
    }
    Ok(PersistedDirectoryShardCatalogV1 {
        checkpoint,
        entries: sorted,
    })
}

/// Bind one locally selected provider from a complete persisted shard to the
/// exact strictly verified live policy. No directory scope/method hint becomes
/// authoritative before this succeeds.
pub fn bind_directory_entry_to_live_policy_v1<'entries, 'policy>(
    catalog: &PersistedDirectoryShardCatalogV1<'entries>,
    expected_provider_id: &ProviderId,
    policy: VerifiedCurrentPolicyV1<'policy>,
) -> Result<VerifiedDirectoryPolicyBindingV1<'entries, 'policy>, DirectoryErrorV1> {
    let entry = catalog
        .entries
        .iter()
        .copied()
        .find(|entry| entry.verified().discovery_entry().provider_id() == expected_provider_id)
        .ok_or(DirectoryErrorV1::LivePolicyMismatch)?;
    let discovery = entry.verified().discovery_entry();
    let assertion = discovery
        .operator_assertion()
        .ok_or(DirectoryErrorV1::LivePolicyMismatch)?;
    let live = policy.policy();
    if discovery.status() != DirectoryEntryStatusV1::Active
        || discovery.provider_id() != &live.provider_id
        || assertion.provider_id != live.provider_id
        || assertion.policy_signing_key_ed25519 != policy.policy_signing_key_ed25519()
        || assertion.policy_epoch != live.policy_epoch
        || assertion.policy_digest != policy.policy_digest()
    {
        return Err(DirectoryErrorV1::LivePolicyMismatch);
    }
    for hint in discovery.catalog_hints() {
        let matches = live.scopes.iter().any(|scope_policy| {
            scope_policy.scope.scope_id() == hint.scope_id
                && scope_policy.scope.backend == hint.backend
                && scope_policy.scope.workload == hint.workload
                && scope_policy.offers.iter().any(|offer| {
                    offer.acquisition == hint.acquisition
                        && offer.authorization == hint.authorization
                        && offer.deployment_status == hint.deployment
                })
        });
        if !matches {
            return Err(DirectoryErrorV1::LivePolicyMismatch);
        }
    }
    Ok(VerifiedDirectoryPolicyBindingV1 { entry, policy })
}

pub fn prepare_directory_entry_acceptance_v1(
    verified: VerifiedDirectoryEntryEventV1,
    current: Option<&DirectoryEntryRollbackStateV1>,
) -> Result<UnpersistedDirectoryEntryV1, DirectoryErrorV1> {
    let entry = verified.discovery_entry();
    let directory_pubkey = *verified.event().pubkey();
    let provider_id = *entry.provider_id();
    if let Some(current) = current {
        current.validate()?;
        if current.directory_pubkey != directory_pubkey || current.provider_id != provider_id {
            return Err(DirectoryErrorV1::CorruptRollbackState);
        }
        if entry.directory_sequence() < current.highest_directory_sequence {
            return Err(DirectoryErrorV1::DirectorySequenceRollback);
        }
        if entry.directory_sequence() == current.highest_directory_sequence {
            if verified.event().id() != &current.event_id_at_highest_sequence {
                return Err(DirectoryErrorV1::DirectorySequenceFork);
            }
            if verified.event().created_at() != current.event_created_at_at_highest_sequence {
                return Err(DirectoryErrorV1::CorruptRollbackState);
            }
            if entry.status() != current.status_at_highest_sequence {
                return Err(DirectoryErrorV1::CorruptRollbackState);
            }
            return Ok(UnpersistedDirectoryEntryV1 {
                verified,
                expected_state: Some(*current),
                successor_state: *current,
                disposition: DirectoryAcceptanceDispositionV1::ExactReplay,
            });
        }
        if verified.event().created_at() <= current.event_created_at_at_highest_sequence {
            return Err(DirectoryErrorV1::ReplaceableTimestampNotAdvanced);
        }
    }

    let (candidate_operator_epoch, candidate_operator_digest) = match entry.operator_assertion() {
        Some(assertion) => (
            assertion.assertion_epoch,
            entry
                .operator_assertion_digest()
                .ok_or(DirectoryErrorV1::InvalidOperatorAssertion)?,
        ),
        None => (0, [0; 32]),
    };
    let (highest_operator_assertion_epoch, operator_assertion_digest_at_highest_epoch) =
        match current {
            Some(current) if entry.status() == DirectoryEntryStatusV1::Tombstone => (
                current.highest_operator_assertion_epoch,
                current.operator_assertion_digest_at_highest_epoch,
            ),
            Some(current) => {
                if current.status_at_highest_sequence == DirectoryEntryStatusV1::Tombstone
                    && candidate_operator_epoch <= current.highest_operator_assertion_epoch
                {
                    return Err(DirectoryErrorV1::ReactivationRequiresNewOperatorEpoch);
                }
                if candidate_operator_epoch < current.highest_operator_assertion_epoch {
                    return Err(DirectoryErrorV1::OperatorEpochRollback);
                }
                if candidate_operator_epoch == current.highest_operator_assertion_epoch
                    && candidate_operator_digest
                        != current.operator_assertion_digest_at_highest_epoch
                {
                    return Err(DirectoryErrorV1::OperatorEpochFork);
                }
                (candidate_operator_epoch, candidate_operator_digest)
            }
            None => (candidate_operator_epoch, candidate_operator_digest),
        };

    let successor_state = DirectoryEntryRollbackStateV1 {
        directory_pubkey,
        provider_id,
        highest_directory_sequence: entry.directory_sequence(),
        event_id_at_highest_sequence: *verified.event().id(),
        event_created_at_at_highest_sequence: verified.event().created_at(),
        status_at_highest_sequence: entry.status(),
        highest_operator_assertion_epoch,
        operator_assertion_digest_at_highest_epoch,
    };
    successor_state.validate()?;
    Ok(UnpersistedDirectoryEntryV1 {
        verified,
        expected_state: current.copied(),
        successor_state,
        disposition: if current.is_some() {
            DirectoryAcceptanceDispositionV1::Advanced
        } else {
            DirectoryAcceptanceDispositionV1::Initial
        },
    })
}

pub fn prepare_directory_checkpoint_acceptance_v1(
    verified: VerifiedDirectoryCheckpointEventV1,
    current: Option<&DirectoryCheckpointRollbackStateV1>,
) -> Result<UnpersistedDirectoryCheckpointV1, DirectoryErrorV1> {
    let checkpoint = verified.checkpoint();
    let directory_pubkey = *verified.event().pubkey();
    if let Some(current) = current {
        current.validate()?;
        if current.directory_pubkey != directory_pubkey || current.shard != checkpoint.shard() {
            return Err(DirectoryErrorV1::CorruptRollbackState);
        }
        if checkpoint.checkpoint_epoch() < current.highest_checkpoint_epoch {
            return Err(DirectoryErrorV1::CheckpointEpochRollback);
        }
        if checkpoint.checkpoint_epoch() == current.highest_checkpoint_epoch {
            if checkpoint.catalog_root() != &current.catalog_root_at_highest_epoch {
                return Err(DirectoryErrorV1::CheckpointSplitView);
            }
            if verified.event().id() != &current.event_id_at_highest_epoch {
                return Err(DirectoryErrorV1::CheckpointEpochFork);
            }
            if verified.event().created_at() != current.event_created_at_at_highest_epoch {
                return Err(DirectoryErrorV1::CorruptRollbackState);
            }
            return Ok(UnpersistedDirectoryCheckpointV1 {
                verified,
                expected_state: Some(*current),
                successor_state: *current,
                disposition: DirectoryAcceptanceDispositionV1::ExactReplay,
            });
        }
        if verified.event().created_at() <= current.event_created_at_at_highest_epoch {
            return Err(DirectoryErrorV1::ReplaceableTimestampNotAdvanced);
        }
    }
    let successor_state = DirectoryCheckpointRollbackStateV1 {
        directory_pubkey,
        shard: checkpoint.shard(),
        highest_checkpoint_epoch: checkpoint.checkpoint_epoch(),
        catalog_root_at_highest_epoch: *checkpoint.catalog_root(),
        event_id_at_highest_epoch: *verified.event().id(),
        event_created_at_at_highest_epoch: verified.event().created_at(),
    };
    successor_state.validate()?;
    Ok(UnpersistedDirectoryCheckpointV1 {
        verified,
        expected_state: current.copied(),
        successor_state,
        disposition: if current.is_some() {
            DirectoryAcceptanceDispositionV1::Advanced
        } else {
            DirectoryAcceptanceDispositionV1::Initial
        },
    })
}

pub async fn verify_and_persist_directory_entry_v1<S: DirectoryRollbackStoreV1>(
    store: &mut S,
    event_json: &[u8],
    pinned_directory_pubkey: &[u8; 32],
    now_unix: u64,
) -> Result<PersistedDirectoryEntryV1, crate::DirectoryAcceptErrorV1<S::Error>> {
    let verified = verify_directory_entry_event_v1(event_json, pinned_directory_pubkey, now_unix)?;
    let key = DirectoryEntryStateKeyV1 {
        directory_pubkey: *pinned_directory_pubkey,
        provider_id: *verified.discovery_entry().provider_id(),
    };
    let current_bytes = store
        .load_entry(key)
        .await
        .map_err(crate::DirectoryAcceptErrorV1::Store)?;
    let current = current_bytes
        .as_deref()
        .map(DirectoryEntryRollbackStateV1::decode)
        .transpose()?;
    let candidate = prepare_directory_entry_acceptance_v1(verified, current.as_ref())?;
    persist_entry_candidate(store, key, current_bytes, candidate).await
}

pub async fn verify_and_persist_directory_checkpoint_v1<S: DirectoryRollbackStoreV1>(
    store: &mut S,
    event_json: &[u8],
    pinned_directory_pubkey: &[u8; 32],
    now_unix: u64,
) -> Result<PersistedDirectoryCheckpointV1, crate::DirectoryAcceptErrorV1<S::Error>> {
    let verified =
        verify_directory_checkpoint_event_v1(event_json, pinned_directory_pubkey, now_unix)?;
    let key = DirectoryCheckpointStateKeyV1 {
        directory_pubkey: *pinned_directory_pubkey,
        shard: verified.checkpoint().shard(),
    };
    let current_bytes = store
        .load_checkpoint(key)
        .await
        .map_err(crate::DirectoryAcceptErrorV1::Store)?;
    let current = current_bytes
        .as_deref()
        .map(DirectoryCheckpointRollbackStateV1::decode)
        .transpose()?;
    let candidate = prepare_directory_checkpoint_acceptance_v1(verified, current.as_ref())?;
    persist_checkpoint_candidate(store, key, current_bytes, candidate).await
}

async fn persist_entry_candidate<S: DirectoryRollbackStoreV1>(
    store: &mut S,
    key: DirectoryEntryStateKeyV1,
    current_bytes: Option<Vec<u8>>,
    candidate: UnpersistedDirectoryEntryV1,
) -> Result<PersistedDirectoryEntryV1, crate::DirectoryAcceptErrorV1<S::Error>> {
    if candidate.disposition != DirectoryAcceptanceDispositionV1::ExactReplay {
        debug_assert_eq!(
            candidate.expected_state,
            current_bytes
                .as_deref()
                .map(DirectoryEntryRollbackStateV1::decode)
                .transpose()
                .ok()
                .flatten()
        );
        let successor = candidate.successor_state.encode()?;
        match store
            .compare_and_swap_entry(key, current_bytes, successor)
            .await
            .map_err(crate::DirectoryAcceptErrorV1::Store)?
        {
            DirectoryCasOutcomeV1::Applied | DirectoryCasOutcomeV1::AlreadyCurrent => {}
            DirectoryCasOutcomeV1::Conflict => {
                return Err(crate::DirectoryAcceptErrorV1::ConcurrentStateChanged)
            }
        }
    }
    Ok(PersistedDirectoryEntryV1 {
        verified: candidate.verified,
        state: candidate.successor_state,
        disposition: candidate.disposition,
    })
}

async fn persist_checkpoint_candidate<S: DirectoryRollbackStoreV1>(
    store: &mut S,
    key: DirectoryCheckpointStateKeyV1,
    current_bytes: Option<Vec<u8>>,
    candidate: UnpersistedDirectoryCheckpointV1,
) -> Result<PersistedDirectoryCheckpointV1, crate::DirectoryAcceptErrorV1<S::Error>> {
    if candidate.disposition != DirectoryAcceptanceDispositionV1::ExactReplay {
        debug_assert_eq!(
            candidate.expected_state,
            current_bytes
                .as_deref()
                .map(DirectoryCheckpointRollbackStateV1::decode)
                .transpose()
                .ok()
                .flatten()
        );
        let successor = candidate.successor_state.encode()?;
        match store
            .compare_and_swap_checkpoint(key, current_bytes, successor)
            .await
            .map_err(crate::DirectoryAcceptErrorV1::Store)?
        {
            DirectoryCasOutcomeV1::Applied | DirectoryCasOutcomeV1::AlreadyCurrent => {}
            DirectoryCasOutcomeV1::Conflict => {
                return Err(crate::DirectoryAcceptErrorV1::ConcurrentStateChanged)
            }
        }
    }
    Ok(PersistedDirectoryCheckpointV1 {
        verified: candidate.verified,
        state: candidate.successor_state,
        disposition: candidate.disposition,
    })
}

fn take<const N: usize>(bytes: &[u8], offset: &mut usize) -> Result<[u8; N], DirectoryErrorV1> {
    let end = offset
        .checked_add(N)
        .ok_or(DirectoryErrorV1::CorruptRollbackState)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(DirectoryErrorV1::CorruptRollbackState)?
        .try_into()
        .map_err(|_| DirectoryErrorV1::CorruptRollbackState)?;
    *offset = end;
    Ok(value)
}
