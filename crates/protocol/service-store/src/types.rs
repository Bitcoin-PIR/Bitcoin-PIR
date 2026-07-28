use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroize;

/// Current on-disk schema version. There are no implicit migrations.
pub const SCHEMA_VERSION: u32 = 7;

/// Maximum accepted policy envelope size.
pub const MAX_SIGNED_POLICY_BYTES: usize = 64 * 1024;

/// Maximum number of floor updates accepted in one policy transaction.
pub const MAX_FLOOR_UPDATES: usize = 4_096;

pub const MAX_CASHU_RECOVERY_NONCE_BYTES_V1: usize = 64;
pub const MAX_CASHU_RECOVERY_CIPHERTEXT_BYTES_V1: usize = 256 * 1024;
pub const MAX_CASHU_CUSTODY_NOTES_PER_LOT_V1: usize =
    pir_service_protocol::MAX_STANDARD_CASHU_PROOFS_V1;
pub const MAX_CASHU_CUSTODY_EXPORT_LOTS_V1: usize = 4_096;
pub const MAX_CASHU_CUSTODY_EXPORT_NOTES_V1: usize = 512;
pub const MAX_CASHU_CUSTODY_EXPORT_KEYSET_GROUPS_V1: usize = 16;
pub const MAX_CASHU_CUSTODY_EXPORT_ARTIFACT_BYTES_V1: usize = 256 * 1024;

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

/// Aggregate, non-secret row counts for provider startup-capacity observation.
///
/// No namespace ID, spend key, IP-derived subject, Cashu transcript, policy
/// bytes, timing, or query material is exposed by this summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderStoreOperationalInventoryV1 {
    pub observed_store_generation: u64,
    pub observed_spend_commit_seq: u64,
    pub namespace_rows: u64,
    pub spent_capability_rows: u64,
    pub free_rate_limit_bucket_rows: u64,
    pub cashu_swap_intent_rows: u64,
    pub cashu_custody_lot_rows: u64,
    pub cashu_custody_note_rows: u64,
    pub cashu_custody_export_batch_rows: u64,
    pub cashu_custody_retirement_evidence_rows: u64,
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
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SpendRequest {
    pub namespace_id: [u8; 32],
    pub spend_key: [u8; 32],
    pub now_unix_seconds: u64,
}

impl std::fmt::Debug for SpendRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SpendRequest")
            .field("request", &"[REDACTED]")
            .finish()
    }
}

/// One provider-local, privacy-preserving fixed-window free-admission attempt.
///
/// `subject` is an HMAC-derived 32-byte cohort identifier. Callers must never
/// pass raw network addresses or any reversible address representation here.
#[derive(Clone, Copy, Eq, PartialEq)]
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

impl std::fmt::Debug for FreeIpRateLimitRequestV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FreeIpRateLimitRequestV1")
            .field("request", &"[REDACTED]")
            .finish()
    }
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

#[derive(Clone, Eq, PartialEq)]
pub struct CashuSwapSealedRecoveryV1 {
    pub key_epoch: u64,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl std::fmt::Debug for CashuSwapSealedRecoveryV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CashuSwapSealedRecoveryV1")
            .field("envelope", &"[REDACTED]")
            .finish()
    }
}

impl Drop for CashuSwapSealedRecoveryV1 {
    fn drop(&mut self) {
        self.nonce.zeroize();
        self.ciphertext.zeroize();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewCashuSwapIntentV1 {
    pub intent_id: [u8; 16],
    pub mint_id: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub unit: String,
    pub input_set_digest: [u8; 32],
    pub request_digest: [u8; 32],
    pub output_set_digest: [u8; 32],
    pub offer_binding_digest: [u8; 32],
    pub settlement_value: u64,
    pub expected_output_count: u32,
    pub sealed_recovery: CashuSwapSealedRecoveryV1,
    /// UTC hour bucket, never an exact request time.
    pub created_bucket: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CashuSwapIntentV1 {
    pub intent_id: [u8; 16],
    pub mint_id: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub unit: String,
    pub input_set_digest: [u8; 32],
    pub request_digest: [u8; 32],
    pub output_set_digest: [u8; 32],
    pub offer_binding_digest: [u8; 32],
    pub settlement_value: u64,
    pub expected_output_count: u32,
    pub state: CashuSwapIntentStateV1,
    pub sealed_recovery: CashuSwapSealedRecoveryV1,
    pub created_bucket: u64,
    pub updated_bucket: u64,
}

impl CashuSwapIntentV1 {
    pub fn matches_new(&self, proposed: &NewCashuSwapIntentV1) -> bool {
        self.intent_id == proposed.intent_id
            && self.mint_id == proposed.mint_id
            && self.manifest_digest == proposed.manifest_digest
            && self.unit == proposed.unit
            && self.input_set_digest == proposed.input_set_digest
            && self.request_digest == proposed.request_digest
            && self.output_set_digest == proposed.output_set_digest
            && self.offer_binding_digest == proposed.offer_binding_digest
            && self.settlement_value == proposed.settlement_value
            && self.expected_output_count == proposed.expected_output_count
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CashuSwapIntentInsertV1 {
    pub inserted: bool,
    pub intent: CashuSwapIntentV1,
}

/// Per-mint/unit limits applied before a new prepared Cashu intent is added.
///
/// Exposure is the checked sum of every non-`GrantIssued` intent plus every
/// custody lot not yet backed by an exact all-`SPENT` NUT-07 confirmation. A
/// delivery acknowledgement does not release exposure. The atomic grant
/// transition moves value from the first set to the second, so a successful
/// grant is never double counted and never creates a capacity gap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CashuCustodyExposureLimitsV1 {
    pub max_unsettled_value: u64,
    pub max_unsettled_notes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub enum CashuCustodyLotStateV1 {
    Available = 1,
    Reserved = 2,
    /// The exact export artifact was delivered to the intended recipient.
    /// Delivery alone does not release provider custody exposure.
    DeliveryAcknowledged = 3,
    /// Every exported note was later observed as `SPENT` through an exact,
    /// owner-initiated NUT-07 state check bound to durable evidence.
    SpentConfirmed = 4,
}

impl CashuCustodyLotStateV1 {
    pub(crate) fn from_db(value: i64) -> Option<Self> {
        match value {
            1 => Some(Self::Available),
            2 => Some(Self::Reserved),
            3 => Some(Self::DeliveryAcknowledged),
            4 => Some(Self::SpentConfirmed),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub enum CashuCustodyExportStateV1 {
    Reserved = 1,
    ArtifactStored = 2,
    /// The sealed artifact was handed to the intended external wallet. This
    /// says nothing about later melt, swap, payout, or economic settlement and
    /// therefore does not release provider custody exposure.
    DeliveryAcknowledged = 3,
    /// All exact member notes have durable all-`SPENT` confirmation evidence.
    /// This is the only terminal state excluded from custody exposure.
    SpentConfirmed = 4,
}

impl CashuCustodyExportStateV1 {
    pub(crate) fn from_db(value: i64) -> Option<Self> {
        match value {
            1 => Some(Self::Reserved),
            2 => Some(Self::ArtifactStored),
            3 => Some(Self::DeliveryAcknowledged),
            4 => Some(Self::SpentConfirmed),
            _ => None,
        }
    }
}

/// Strict NUT-07 state classification accepted by the store boundary.
///
/// The store retires custody only when every entry is [`Self::Spent`]. The
/// other variants are explicit fail-closed inputs so a caller cannot collapse
/// `UNSPENT`, `PENDING`, or an unknown state into success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CashuCustodyRetirementNoteStateV1 {
    Spent,
    Unspent,
    Pending,
    Unknown,
}

/// One transient NUT-07 result. `y` is validated and hashed in memory, but is
/// never written to ProviderStore.
#[derive(Eq, PartialEq)]
pub struct CashuCustodyRetirementNoteCheckV1 {
    pub y: [u8; 33],
    pub state: CashuCustodyRetirementNoteStateV1,
}

impl Drop for CashuCustodyRetirementNoteCheckV1 {
    fn drop(&mut self) {
        self.y.zeroize();
    }
}

impl std::fmt::Debug for CashuCustodyRetirementNoteCheckV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CashuCustodyRetirementNoteCheckV1")
            .field("y", &"[REDACTED]")
            .field("state", &self.state)
            .finish()
    }
}

/// Exact, stale-check-resistant input to the custody retirement transaction.
///
/// The caller must read the store identity, perform one owner-initiated NUT-07
/// check for the exported notes, and submit the same precondition floor. Any
/// intervening provider-store mutation makes the request stale and fails
/// closed. `nut07_response_digest` commits to the caller's domain-separated,
/// exact per-export NUT-07 observation projection without storing the
/// response or raw `Y` values. A digest shared by a wider multi-export HTTP
/// batch must not be used here because it would persist a cross-export link.
#[derive(Eq, PartialEq)]
pub struct CashuCustodySpentConfirmationRequestV1 {
    pub provider_id: [u8; 32],
    pub store_instance_id: [u8; 16],
    pub precondition_store_generation: u64,
    pub precondition_spend_commit_seq: u64,
    pub precondition_rollback_commitment: [u8; 32],
    pub export_id: [u8; 16],
    pub artifact_digest: [u8; 32],
    pub member_lot_ids: Vec<[u8; 16]>,
    pub note_checks: Vec<CashuCustodyRetirementNoteCheckV1>,
    pub nut07_response_digest: [u8; 32],
}

impl std::fmt::Debug for CashuCustodySpentConfirmationRequestV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CashuCustodySpentConfirmationRequestV1")
            .field("provider_id", &"[REDACTED]")
            .field("store_instance_id", &"[REDACTED]")
            .field(
                "precondition_store_generation",
                &self.precondition_store_generation,
            )
            .field(
                "precondition_spend_commit_seq",
                &self.precondition_spend_commit_seq,
            )
            .field("precondition_rollback_commitment", &"[REDACTED]")
            .field("export_id", &"[REDACTED]")
            .field("artifact_digest", &"[REDACTED]")
            .field("member_lot_count", &self.member_lot_ids.len())
            .field("note_check_count", &self.note_checks.len())
            .field("nut07_response_digest", &"[REDACTED]")
            .finish()
    }
}

/// Digest-only durable evidence for one terminal custody transition.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CashuCustodyRetirementEvidenceV1 {
    pub export_id: [u8; 16],
    pub provider_id: [u8; 32],
    pub store_instance_id: [u8; 16],
    pub precondition_store_generation: u64,
    pub precondition_spend_commit_seq: u64,
    pub precondition_rollback_commitment: [u8; 32],
    pub confirmed_store_generation: u64,
    pub confirmed_spend_commit_seq: u64,
    pub confirmed_rollback_commitment: [u8; 32],
    pub artifact_digest: [u8; 32],
    pub member_set_digest: [u8; 32],
    pub note_fingerprint_set_digest: [u8; 32],
    pub y_set_digest: [u8; 32],
    pub nut07_response_digest: [u8; 32],
    pub note_count: u64,
    pub evidence_digest: [u8; 32],
}

impl std::fmt::Debug for CashuCustodyRetirementEvidenceV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CashuCustodyRetirementEvidenceV1")
            .field("identities_and_digests", &"[REDACTED]")
            .field(
                "precondition_store_generation",
                &self.precondition_store_generation,
            )
            .field(
                "precondition_spend_commit_seq",
                &self.precondition_spend_commit_seq,
            )
            .field(
                "confirmed_store_generation",
                &self.confirmed_store_generation,
            )
            .field(
                "confirmed_spend_commit_seq",
                &self.confirmed_spend_commit_seq,
            )
            .field("note_count", &self.note_count)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CashuCustodySpentConfirmationV1 {
    pub confirmed: bool,
    pub evidence: CashuCustodyRetirementEvidenceV1,
}

/// Owner-only, exact-store request for a retirement snapshot.
///
/// ProviderStore cannot authenticate an operating-system user. Callers must
/// expose this API only through an owner-authorized offline process which has
/// exclusive access to the provider store and custody keys. These identities
/// prevent accidentally opening the wrong provider/store pair; they are not
/// an authorization credential.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CashuCustodyRetirementSnapshotRequestV1 {
    pub provider_id: [u8; 32],
    pub store_instance_id: [u8; 16],
    pub export_id: [u8; 16],
}

impl std::fmt::Debug for CashuCustodyRetirementSnapshotRequestV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CashuCustodyRetirementSnapshotRequestV1")
            .field("identities", &"[REDACTED]")
            .finish()
    }
}

/// Snapshot whose sealed notes may be decrypted only by the owner-side NUT-07
/// workflow. The exact checked identity is the confirmation precondition.
///
/// Dropping this value zeroizes every Rust-owned copy of the artifact and
/// sealed custody nonces/ciphertexts held by the snapshot. The SQLite pages
/// remain governed by the provider-store retention and encryption contract.
#[derive(Eq, PartialEq)]
pub struct CashuCustodyRetirementCheckableSnapshotV1 {
    pub checked_identity: StoreIdentity,
    pub batch: CashuCustodyExportBatchV1,
    pub member_lot_ids: Vec<[u8; 16]>,
    pub sealed_lots: Vec<CashuCustodyLotV1>,
}

impl Drop for CashuCustodyRetirementCheckableSnapshotV1 {
    fn drop(&mut self) {
        if let Some(artifact) = self.batch.artifact.as_mut() {
            artifact.bytes.zeroize();
        }
        for lot in &mut self.sealed_lots {
            lot.sealed_notes.nonce.zeroize();
            lot.sealed_notes.ciphertext.zeroize();
        }
    }
}

impl std::fmt::Debug for CashuCustodyRetirementCheckableSnapshotV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CashuCustodyRetirementCheckableSnapshotV1")
            .field(
                "checked_store_generation",
                &self.checked_identity.store_generation,
            )
            .field(
                "checked_spend_commit_seq",
                &self.checked_identity.spend_commit_seq,
            )
            .field("identities_and_artifact", &"[REDACTED]")
            .field("member_lot_count", &self.member_lot_ids.len())
            .field("sealed_lot_count", &self.sealed_lots.len())
            .field("note_count", &self.batch.note_count)
            .finish()
    }
}

/// Terminal snapshot for exact replay. It intentionally contains neither the
/// stored artifact bytes nor sealed custody lots, so an already retired export
/// cannot be used as a second secret-extraction API.
#[derive(Eq, PartialEq)]
pub struct CashuCustodyRetirementCompletedSnapshotV1 {
    pub checked_identity: StoreIdentity,
    pub export_id: [u8; 16],
    pub mint_id: [u8; 32],
    pub unit: String,
    pub settlement_value: u64,
    pub note_count: u64,
    pub artifact_digest: [u8; 32],
    pub evidence: CashuCustodyRetirementEvidenceV1,
}

impl std::fmt::Debug for CashuCustodyRetirementCompletedSnapshotV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CashuCustodyRetirementCompletedSnapshotV1")
            .field(
                "checked_store_generation",
                &self.checked_identity.store_generation,
            )
            .field(
                "checked_spend_commit_seq",
                &self.checked_identity.spend_commit_seq,
            )
            .field("identities_and_digests", &"[REDACTED]")
            .field("settlement_value", &self.settlement_value)
            .field("note_count", &self.note_count)
            .finish()
    }
}

pub enum CashuCustodyRetirementSnapshotV1 {
    Checkable(Box<CashuCustodyRetirementCheckableSnapshotV1>),
    SpentConfirmed(Box<CashuCustodyRetirementCompletedSnapshotV1>),
}

impl std::fmt::Debug for CashuCustodyRetirementSnapshotV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Checkable(snapshot) => snapshot.fmt(formatter),
            Self::SpentConfirmed(snapshot) => snapshot.fmt(formatter),
        }
    }
}

/// Opaque, externally authenticated ciphertext. ProviderStore never decrypts
/// it and never stores its plaintext alongside public bookkeeping rows.
#[derive(Clone, Eq, PartialEq)]
pub struct CashuCustodySealedBlobV1 {
    pub key_epoch: u64,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl Drop for CashuCustodySealedBlobV1 {
    fn drop(&mut self) {
        self.nonce.zeroize();
        self.ciphertext.zeroize();
    }
}

impl std::fmt::Debug for CashuCustodySealedBlobV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CashuCustodySealedBlobV1")
            .field("envelope", &"[REDACTED]")
            .finish()
    }
}

/// Exact recipient-sealed export artifact. ProviderStore treats `bytes` as an
/// opaque canonical envelope and never interprets it as a recovery ciphertext.
#[derive(Clone, Eq, PartialEq)]
pub struct CashuCustodyExportArtifactV1 {
    pub digest: [u8; 32],
    pub bytes: Vec<u8>,
}

impl std::fmt::Debug for CashuCustodyExportArtifactV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CashuCustodyExportArtifactV1")
            .field("artifact", &"[REDACTED]")
            .finish()
    }
}

impl Drop for CashuCustodyExportArtifactV1 {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Inputs needed to move one `WalletStored` intent to `GrantIssued` without an
/// asset-inventory gap. `note_ys` are public curve points used transiently to
/// derive the durable `H(mint_id || Y)` uniqueness keys; the points themselves
/// are not stored.
#[derive(Eq, PartialEq)]
pub struct NewCashuCustodyLotV1 {
    pub lot_id: [u8; 16],
    pub manifest_digest: [u8; 32],
    pub active_keyset_digest: [u8; 32],
    pub note_set_digest: [u8; 32],
    pub note_ys: Vec<[u8; 33]>,
    pub sealed_notes: CashuCustodySealedBlobV1,
}

impl Drop for NewCashuCustodyLotV1 {
    fn drop(&mut self) {
        self.note_ys.zeroize();
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CashuCustodyLotV1 {
    pub lot_id: [u8; 16],
    pub mint_id: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub active_keyset_digest: [u8; 32],
    pub note_set_digest: [u8; 32],
    pub unit: String,
    pub settlement_value: u64,
    pub note_count: u32,
    pub state: CashuCustodyLotStateV1,
    pub sealed_notes: CashuCustodySealedBlobV1,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CashuSwapGrantClaimV1 {
    pub issued: bool,
    pub lot: CashuCustodyLotV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewCashuCustodyExportV1 {
    pub export_id: [u8; 16],
    pub mint_id: [u8; 32],
    pub unit: String,
    /// Stable identifier of the recipient public key that must authenticate
    /// the opaque export artifact. It is public metadata, not key material.
    pub recipient_key_id: [u8; 32],
    pub max_lots: u32,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CashuCustodyExportBatchV1 {
    pub export_id: [u8; 16],
    pub mint_id: [u8; 32],
    pub unit: String,
    pub recipient_key_id: [u8; 32],
    pub requested_max_lots: u32,
    pub lot_count: u32,
    pub keyset_group_count: u32,
    pub settlement_value: u64,
    pub note_count: u64,
    pub state: CashuCustodyExportStateV1,
    pub artifact: Option<CashuCustodyExportArtifactV1>,
}

/// On a fresh reservation, `sealed_lots` contains the exact reserved material.
/// Replaying the same export ID after an artifact is stored returns that exact
/// artifact in `batch` and leaves `sealed_lots` empty.
#[derive(Clone, Eq, PartialEq)]
pub struct CashuCustodyExportReservationV1 {
    pub reserved: bool,
    pub batch: CashuCustodyExportBatchV1,
    pub sealed_lots: Vec<CashuCustodyLotV1>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CashuCustodyExportArtifactPersistV1 {
    pub persisted: bool,
    pub batch: CashuCustodyExportBatchV1,
}

/// Aggregate-only per-mint/unit custody view. It deliberately excludes intent,
/// lot, export, note, request, and timing identifiers and all ciphertext.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CashuCustodyInventoryV1 {
    pub pending_intent_value: u64,
    pub pending_intent_notes: u64,
    pub available_lot_count: u64,
    pub available_value: u64,
    pub available_notes: u64,
    pub reserved_lot_count: u64,
    pub reserved_value: u64,
    pub reserved_notes: u64,
    pub acknowledged_lot_count: u64,
    pub acknowledged_value: u64,
    pub acknowledged_notes: u64,
    pub spent_confirmed_lot_count: u64,
    pub spent_confirmed_value: u64,
    pub spent_confirmed_notes: u64,
    pub reserved_export_count: u64,
    pub materialized_export_count: u64,
    pub acknowledged_export_count: u64,
    pub spent_confirmed_export_count: u64,
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
