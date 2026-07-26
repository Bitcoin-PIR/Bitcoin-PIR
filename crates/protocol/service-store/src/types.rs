use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Current on-disk schema version. There are no implicit migrations.
pub const SCHEMA_VERSION: u32 = 5;

/// Maximum accepted policy envelope size.
pub const MAX_SIGNED_POLICY_BYTES: usize = 64 * 1024;

/// Maximum number of floor updates accepted in one policy transaction.
pub const MAX_FLOOR_UPDATES: usize = 4_096;

pub const MAX_CASHU_RECOVERY_NONCE_BYTES_V1: usize = 64;
pub const MAX_CASHU_RECOVERY_CIPHERTEXT_BYTES_V1: usize = 256 * 1024;

/// Runtime settings which are checked against SQLite after every connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreOptions {
    /// SQLite lock wait. Values must be in `1ms..=60s`.
    pub busy_timeout: Duration,
}

impl Default for StoreOptions {
    fn default() -> Self {
        Self {
            busy_timeout: Duration::from_secs(5),
        }
    }
}

/// Identity written exactly once when a provider store is explicitly created.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreIdentity {
    pub store_instance_id: [u8; 16],
    pub provider_id: [u8; 32],
    /// Monotonic sequence for every security-relevant provider-store mutation.
    pub store_generation: u64,
    pub spend_commit_seq: u64,
    /// Previous generation's rolling commitment. Zero only at generation 0.
    pub rollback_parent_commitment: [u8; 32],
    /// Rolling commitment anchored by an independent rollback-floor authority.
    pub rollback_commitment: [u8; 32],
    pub schema_version: u32,
}

/// Durable namespace state. Closed namespaces can never be reopened.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub enum NamespaceStatus {
    Active = 1,
    Closed = 2,
}

impl NamespaceStatus {
    pub(crate) fn from_db(value: i64) -> Option<Self> {
        match value {
            1 => Some(Self::Active),
            2 => Some(Self::Closed),
            _ => None,
        }
    }
}

/// Public cohort metadata for one credential spend namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpendNamespace {
    pub namespace_id: [u8; 32],
    pub scheme: u16,
    pub issuer_id: [u8; 32],
    pub key_id: Vec<u8>,
    pub binding_digest: [u8; 32],
    /// Inclusive Unix-second validity boundary.
    pub not_after: u64,
    pub status: NamespaceStatus,
}

/// Optional provider-local guard against reusing one raw cryptographic key for
/// two incompatible credential lineages.
///
/// `key_fingerprint` is a collision-resistant digest of the canonical raw
/// public key bytes, not a policy-controlled key identifier. `lineage_digest`
/// identifies the complete immutable lineage in which that raw key is allowed
/// to appear. Once recorded, the `(scheme, key_fingerprint)` mapping is never
/// removed or rebound, including after all referring namespaces are closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExclusiveKeyLineage {
    pub key_fingerprint: [u8; 32],
    pub lineage_digest: [u8; 32],
}

/// Derived metadata for one verified offer's durable spend namespace.
///
/// Downstream callers receive this from
/// `ProviderStore::install_verified_offer_namespace_v1` for routing later
/// spends. The low-level installer is crate-private, so constructing this type
/// does not let a caller bypass verified-offer derivation or omit BAT lineage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewSpendNamespace {
    pub namespace_id: [u8; 32],
    pub scheme: u16,
    pub issuer_id: [u8; 32],
    pub key_id: Vec<u8>,
    pub binding_digest: [u8; 32],
    /// Inclusive Unix-second validity boundary.
    pub not_after: u64,
    /// Required by callers for schemes whose raw verification key must remain
    /// exclusive to one cryptographic lineage, including Cashu BAT.
    pub exclusive_key_lineage: Option<ExclusiveKeyLineage>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceInstallOutcome {
    Installed,
    AlreadyPresent(NamespaceStatus),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceCloseOutcome {
    Closed,
    AlreadyClosed,
}

/// Input to the short `BEGIN IMMEDIATE` spend transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpendRequest {
    pub namespace_id: [u8; 32],
    pub spend_key: [u8; 32],
    pub now_unix_seconds: u64,
}

/// One provider-local, privacy-preserving fixed-window free-admission attempt.
///
/// `subject` is an HMAC-derived 32-byte cohort identifier. Callers must never
/// pass raw network addresses or any reversible address representation here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FreeIpRateLimitRequestV1 {
    pub subject: [u8; 32],
    pub policy_digest: [u8; 32],
    pub scope_id: [u8; 32],
    pub offer_id: u32,
    pub quota: u32,
    pub window_seconds: u32,
    pub max_buckets: usize,
    pub now_unix_seconds: u64,
}

/// Returned only after SQLite reports a successful durable commit.
///
/// Receiving this marker is the store-level precondition for installing a
/// connection-local authorization grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpendCommit {
    pub spend_commit_seq: u64,
}

/// Diagnostic read-back after SQLite returned an error from `COMMIT`.
/// This never authorizes the connection which attempted the spend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpendReadBack {
    Present,
    Absent,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyHead {
    pub highest_policy_epoch: u64,
    pub policy_digest: [u8; 32],
    pub signed_policy: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct CredentialEpochFloor {
    pub scope_id: [u8; 32],
    pub scheme: u16,
    pub issuer_id: [u8; 32],
    pub minimum_epoch: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct CashuManifestEpochFloor {
    pub mint_id: [u8; 32],
    pub unit: String,
    pub minimum_epoch: u64,
}

/// One atomic policy-head and monotonic-floor update.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyStateUpdate {
    pub head: PolicyHead,
    pub credential_floors: Vec<CredentialEpochFloor>,
    pub cashu_manifest_floors: Vec<CashuManifestEpochFloor>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyUpdateOutcome {
    Advanced,
    AlreadyCurrent,
}

/// Durable standard-Cashu merchant swap lifecycle. Values are an on-disk V1
/// contract and must never be renumbered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub enum CashuSwapIntentStateV1 {
    Prepared = 0,
    Submitted = 1,
    WalletStored = 2,
    GrantIssued = 3,
    Attention = 4,
}

impl CashuSwapIntentStateV1 {
    pub(crate) fn from_db(value: i64) -> Option<Self> {
        match value {
            0 => Some(Self::Prepared),
            1 => Some(Self::Submitted),
            2 => Some(Self::WalletStored),
            3 => Some(Self::GrantIssued),
            4 => Some(Self::Attention),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CashuSwapSealedRecoveryV1 {
    pub key_epoch: u64,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewCashuSwapIntentV1 {
    pub intent_id: [u8; 16],
    pub mint_id: [u8; 32],
    pub input_set_digest: [u8; 32],
    pub request_digest: [u8; 32],
    pub output_set_digest: [u8; 32],
    pub offer_binding_digest: [u8; 32],
    pub settlement_value: u64,
    pub sealed_recovery: CashuSwapSealedRecoveryV1,
    /// UTC hour bucket, never an exact request time.
    pub created_bucket: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CashuSwapIntentV1 {
    pub intent_id: [u8; 16],
    pub mint_id: [u8; 32],
    pub input_set_digest: [u8; 32],
    pub request_digest: [u8; 32],
    pub output_set_digest: [u8; 32],
    pub offer_binding_digest: [u8; 32],
    pub settlement_value: u64,
    pub state: CashuSwapIntentStateV1,
    pub sealed_recovery: CashuSwapSealedRecoveryV1,
    pub created_bucket: u64,
    pub updated_bucket: u64,
}

impl CashuSwapIntentV1 {
    pub fn matches_new(&self, proposed: &NewCashuSwapIntentV1) -> bool {
        self.intent_id == proposed.intent_id
            && self.mint_id == proposed.mint_id
            && self.input_set_digest == proposed.input_set_digest
            && self.request_digest == proposed.request_digest
            && self.output_set_digest == proposed.output_set_digest
            && self.offer_binding_digest == proposed.offer_binding_digest
            && self.settlement_value == proposed.settlement_value
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CashuSwapIntentInsertV1 {
    pub inserted: bool,
    pub intent: CashuSwapIntentV1,
}

/// A validated handle to one provider's existing store.
///
/// It contains no live SQLite connection. Each operation opens the path with
/// no `CREATE` flag, reapplies checked connection pragmas, and rechecks the
/// provider identity. Clones are safe to use from concurrent threads.
#[derive(Clone, Debug)]
pub(crate) struct StoreHandle {
    pub path: PathBuf,
    pub expected_provider_id: [u8; 32],
    pub options: StoreOptions,
    pub rollback_authority: Option<Arc<dyn crate::RollbackFloorAuthorityV1>>,
}
