//! Durable provider-settlement workflow state and floor-authority adapters.
//!
//! The detailed store uses a small transition journal around every external
//! floor change.  A restart can therefore finish one exact transition without
//! inventing a new payout or status request.  A detailed-store rollback that
//! no longer matches the floor authority fails closed.
//!
//! [`LocalTestSqliteProviderSettlementFloorV1`] is deliberately named and
//! documented as a local/test adapter.  A second SQLite filename is not an
//! independent production rollback authority: co-snapshotting or restoring
//! both files can restore a stale but mutually consistent pair.  Production
//! deployments must provide a separately reviewed implementation of
//! [`ProviderSettlementFloorAuthorityV1`] in an independent administrative,
//! failure, backup, and restore domain.
//!
//! Database opens pin every ancestor one component at a time with `O_NOFOLLOW`,
//! require a private final parent and single-link mode-0600 file, and revalidate
//! the main-file identity after SQLite's internal reopen. Intermediate and
//! final symlinks are rejected. The final parent is the namespace and
//! confidentiality boundary for SQLite's WAL/SHM sidecars.

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use pir_service_protocol::{PayoutStateV1, ProviderId, ServiceProtocolError};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::{
    floor_is_satisfied, pending_payout_floor_v1, provider_payout_durable_state_commitment_v1,
    ProviderPayoutDurableStateV1, ProviderPayoutPendingFloorV1, ProviderPayoutPendingV1,
    ProviderPayoutRollbackFloorV1, ProviderPayoutStatusPendingV1, ProviderSettlementRegistrationV1,
    ProviderSettlementStateStoreV1, VerifiedProviderPayoutInitialWriteV1,
    VerifiedProviderPayoutPendingWriteV1, VerifiedProviderPayoutStatusPendingWriteV1,
    VerifiedProviderPayoutStatusWriteV1, MAX_SHARED_ISSUER_RESPONSE_BYTES_V1,
};

const STORE_APPLICATION_ID: i32 = 0x4250_5353; // "BPSS"
const FLOOR_APPLICATION_ID: i32 = 0x4250_464c; // "BPFL"
const STORE_SCHEMA_VERSION: u32 = 2;
const FLOOR_SCHEMA_VERSION: u32 = 2;
const MAX_STORED_RECORD_BYTES: usize = 512 * 1024;
const HISTORY_INITIAL_DOMAIN_V2: &[u8] = b"BitcoinPIR/provider-settlement/history-initial/v2";
const HISTORY_APPEND_DOMAIN_V2: &[u8] = b"BitcoinPIR/provider-settlement/history-append/v2";
const ACTIVE_COMMITMENT_DOMAIN_V2: &[u8] = b"BitcoinPIR/provider-settlement/active/v2";
const RECORD_COMMITMENT_DOMAIN_V2: &[u8] = b"BitcoinPIR/provider-settlement/record/v2";
const RECOVERY_SNAPSHOT_DOMAIN_V2: &[u8] = b"BitcoinPIR/provider-settlement/recovery/v2";

const STORE_SCHEMA: &str = r#"
CREATE TABLE workflow (
    singleton          INTEGER NOT NULL PRIMARY KEY CHECK(singleton = 1),
    store_instance_id  BLOB NOT NULL UNIQUE CHECK(length(store_instance_id) = 16 AND store_instance_id != zeroblob(16)),
    provider_id        BLOB NOT NULL UNIQUE CHECK(length(provider_id) = 32),
    current_state      BLOB CHECK(current_state IS NULL OR length(current_state) BETWEEN 1 AND 524288),
    committed_pending  BLOB CHECK(committed_pending IS NULL OR length(committed_pending) BETWEEN 1 AND 524288),
    active_pending     BLOB CHECK(active_pending IS NULL OR length(active_pending) BETWEEN 1 AND 524288),
    pending_status     BLOB CHECK(pending_status IS NULL OR length(pending_status) BETWEEN 1 AND 524288),
    transition_previous_state BLOB CHECK(transition_previous_state IS NULL OR length(transition_previous_state) BETWEEN 1 AND 524288),
    authority_revision INTEGER NOT NULL CHECK(authority_revision >= 0),
    transition_kind    INTEGER NOT NULL CHECK(transition_kind BETWEEN 0 AND 4)
) STRICT, WITHOUT ROWID;

CREATE TABLE payout_history (
    sequence           INTEGER NOT NULL PRIMARY KEY CHECK(sequence > 0),
    committed_pending  BLOB NOT NULL CHECK(length(committed_pending) BETWEEN 1 AND 524288),
    durable_state      BLOB NOT NULL CHECK(length(durable_state) BETWEEN 1 AND 524288)
) STRICT, WITHOUT ROWID;
"#;

const FLOOR_SCHEMA: &str = r#"
CREATE TABLE settlement_floor (
    singleton   INTEGER NOT NULL PRIMARY KEY CHECK(singleton = 1),
    floor_value BLOB NOT NULL CHECK(length(floor_value) BETWEEN 1 AND 256)
) STRICT, WITHOUT ROWID;
"#;

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ProviderSettlementFloorPhaseV1 {
    Pending {
        pending: ProviderPayoutPendingFloorV1,
        payout_request_digest: [u8; 32],
    },
    Payout {
        payout: ProviderPayoutRollbackFloorV1,
    },
    StatusPending {
        payout: ProviderPayoutRollbackFloorV1,
    },
}

impl core::fmt::Debug for ProviderSettlementFloorPhaseV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Pending { .. } => "Pending([REDACTED])",
            Self::Payout { .. } => "Payout([REDACTED])",
            Self::StatusPending { .. } => "StatusPending([REDACTED])",
        })
    }
}

/// Compact independently persisted authority value. `active_commitment` binds
/// every exact nullable workflow record for this phase; `history_commitment`
/// binds every archived raw pending/state record. The random store instance and
/// strictly increasing revision prevent another database for the same provider
/// from sharing or replaying this authority namespace.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ProviderSettlementFloorV1 {
    pub(crate) store_instance_id: [u8; 16],
    pub(crate) provider_id: ProviderId,
    pub(crate) revision: u64,
    pub(crate) active_commitment: [u8; 32],
    pub(crate) history_length: u64,
    pub(crate) history_commitment: [u8; 32],
    pub(crate) phase: ProviderSettlementFloorPhaseV1,
}

impl core::fmt::Debug for ProviderSettlementFloorV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let phase = match self.phase {
            ProviderSettlementFloorPhaseV1::Pending { .. } => "pending",
            ProviderSettlementFloorPhaseV1::Payout { .. } => "payout",
            ProviderSettlementFloorPhaseV1::StatusPending { .. } => "status-pending",
        };
        formatter
            .debug_struct("ProviderSettlementFloorV1")
            .field("store_instance_id", &"[REDACTED]")
            .field("provider_id", &"[REDACTED]")
            .field("revision", &self.revision)
            .field("history_length", &self.history_length)
            .field("phase", &phase)
            .finish_non_exhaustive()
    }
}

impl ProviderSettlementFloorV1 {
    pub fn store_instance_id(&self) -> &[u8; 16] {
        &self.store_instance_id
    }

    pub fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn active_commitment(&self) -> &[u8; 32] {
        &self.active_commitment
    }

    pub fn history_length(&self) -> u64 {
        self.history_length
    }

    pub fn history_commitment(&self) -> &[u8; 32] {
        &self.history_commitment
    }

    pub fn phase(&self) -> ProviderSettlementFloorPhaseV1 {
        self.phase
    }

    /// Validates the only legal first authority value: a provider-bound
    /// pending payout over the canonical empty-history anchor.
    pub fn validate_initial(&self) -> Result<(), ProviderSettlementFloorAuthorityErrorV1> {
        validate_initial_floor(self).map_err(floor_error_from_store)
    }

    /// Validates provider identity, origin binding, history-chain advancement,
    /// terminal-predecessor rules, and payout-state monotonicity for one CAS.
    /// Production authorities should call this before linearizing a successor.
    pub fn validate_successor(
        &self,
        next: &Self,
    ) -> Result<(), ProviderSettlementFloorAuthorityErrorV1> {
        validate_floor_transition(self, next).map_err(floor_error_from_store)
    }
}

/// Opaque, authenticated authority transition. Raw floors are data, not
/// mutation authority; only verified live writes or fully authenticated crash
/// recovery may construct this capability inside the crate.
#[derive(Clone)]
pub struct AuthenticatedProviderSettlementFloorTransitionV1 {
    expected: Option<ProviderSettlementFloorV1>,
    next: ProviderSettlementFloorV1,
}

impl AuthenticatedProviderSettlementFloorTransitionV1 {
    pub fn expected(&self) -> Option<&ProviderSettlementFloorV1> {
        self.expected.as_ref()
    }

    pub fn next(&self) -> &ProviderSettlementFloorV1 {
        &self.next
    }

    #[cfg(test)]
    pub(crate) fn for_remote_test(
        expected: Option<ProviderSettlementFloorV1>,
        next: ProviderSettlementFloorV1,
    ) -> Self {
        Self { expected, next }
    }
}

impl core::fmt::Debug for AuthenticatedProviderSettlementFloorTransitionV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AuthenticatedProviderSettlementFloorTransitionV1")
            .field("has_expected", &self.expected.is_some())
            .field("next_revision", &self.next.revision)
            .finish_non_exhaustive()
    }
}

/// Opaque error returned by a provider settlement floor authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderSettlementFloorAuthorityErrorV1 {
    reason: String,
}

impl ProviderSettlementFloorAuthorityErrorV1 {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl core::fmt::Display for ProviderSettlementFloorAuthorityErrorV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&self.reason)
    }
}

impl std::error::Error for ProviderSettlementFloorAuthorityErrorV1 {}

/// Independent monotonic authority for one provider payout workflow.
///
/// Both [`Self::load`] and [`Self::apply`] must be strongly consistent and
/// linearizable with respect to every caller of this authority. A successful
/// `apply` return means the successor is durably committed across authority
/// process/host restart; an implementation must never acknowledge a volatile
/// write. Returning the current value on a lost CAS lets the detailed store
/// distinguish an exact concurrent completion from a fork. Implementations
/// must accept mutation only through the opaque authenticated transition,
/// revalidate its monotonic structure, and live in an administrative and
/// rollback domain independent from the detailed store.
/// Production implementations must also place a bounded deadline on every
/// `load` and `apply`; an unbounded remote call can pin the detailed store's
/// read snapshot and prevent WAL checkpoint progress.
pub trait ProviderSettlementFloorAuthorityV1: core::fmt::Debug + Send + Sync + 'static {
    type Error: core::fmt::Display;

    fn load(&self) -> Result<Option<ProviderSettlementFloorV1>, Self::Error>;

    fn apply(
        &self,
        transition: &AuthenticatedProviderSettlementFloorTransitionV1,
    ) -> Result<ProviderSettlementFloorV1, Self::Error>;
}

/// SQLite floor implementation for local development, tests, and recovery
/// drills only.
///
/// This type is **not a production independent rollback authority**, even if
/// its file is stored at another path. It shares the host/filesystem/operator
/// failure domain unless a separately reviewed deployment proves otherwise.
#[derive(Clone)]
pub struct LocalTestSqliteProviderSettlementFloorV1 {
    path: PathBuf,
    busy_timeout: Duration,
}

impl core::fmt::Debug for LocalTestSqliteProviderSettlementFloorV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("LocalTestSqliteProviderSettlementFloorV1")
            .field("path", &self.path)
            .field("busy_timeout", &self.busy_timeout)
            .field("production_independent_authority", &false)
            .finish()
    }
}

impl LocalTestSqliteProviderSettlementFloorV1 {
    pub fn create(
        path: impl AsRef<Path>,
        busy_timeout: Duration,
    ) -> Result<Self, ProviderSettlementFloorAuthorityErrorV1> {
        validate_timeout(busy_timeout, "provider settlement floor")
            .map_err(floor_error_from_store)?;
        let path = path.as_ref().to_path_buf();
        create_empty_regular_file(&path, "provider settlement floor")
            .map_err(floor_error_from_store)?;
        let authority = Self { path, busy_timeout };
        let connection = authority.open_raw()?;
        configure(&connection, busy_timeout).map_err(floor_error_from_store)?;
        connection
            .execute_batch(FLOOR_SCHEMA)
            .map_err(floor_sql_error)?;
        set_schema_identity(&connection, FLOOR_APPLICATION_ID, FLOOR_SCHEMA_VERSION)
            .map_err(floor_error_from_store)?;
        checkpoint_and_sync(&connection, &authority.path, "provider settlement floor")
            .map_err(floor_error_from_store)?;
        authority.open_checked()?;
        Ok(authority)
    }

    pub fn open_existing(
        path: impl AsRef<Path>,
        busy_timeout: Duration,
    ) -> Result<Self, ProviderSettlementFloorAuthorityErrorV1> {
        validate_timeout(busy_timeout, "provider settlement floor")
            .map_err(floor_error_from_store)?;
        let authority = Self {
            path: path.as_ref().to_path_buf(),
            busy_timeout,
        };
        authority.open_checked()?;
        Ok(authority)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn open_raw(&self) -> Result<Connection, ProviderSettlementFloorAuthorityErrorV1> {
        open_existing_regular_file(&self.path, "provider settlement floor")
            .map_err(floor_error_from_store)
    }

    fn open_checked(&self) -> Result<Connection, ProviderSettlementFloorAuthorityErrorV1> {
        let connection = self.open_raw()?;
        configure(&connection, self.busy_timeout).map_err(floor_error_from_store)?;
        verify_schema_identity(
            &connection,
            FLOOR_APPLICATION_ID,
            FLOOR_SCHEMA_VERSION,
            "provider settlement floor",
        )
        .map_err(floor_error_from_store)?;
        verify_integrity(&connection, "provider settlement floor")
            .map_err(floor_error_from_store)?;
        verify_floor_schema(&connection).map_err(floor_error_from_store)?;
        let raw = read_raw_floor(&connection).map_err(floor_error_from_store)?;
        if let Some(raw) = raw {
            decode_authority_floor(&raw).map_err(floor_error_from_store)?;
        }
        Ok(connection)
    }
}

impl ProviderSettlementFloorAuthorityV1 for LocalTestSqliteProviderSettlementFloorV1 {
    type Error = ProviderSettlementFloorAuthorityErrorV1;

    fn load(&self) -> Result<Option<ProviderSettlementFloorV1>, Self::Error> {
        let connection = self.open_checked()?;
        read_raw_floor(&connection)
            .map_err(floor_error_from_store)?
            .map(|raw| decode_authority_floor(&raw).map_err(floor_error_from_store))
            .transpose()
    }

    fn apply(
        &self,
        transition: &AuthenticatedProviderSettlementFloorTransitionV1,
    ) -> Result<ProviderSettlementFloorV1, Self::Error> {
        match transition.expected {
            None => transition.next.validate_initial()?,
            Some(expected) => expected.validate_successor(&transition.next)?,
        }
        let mut connection = self.open_checked()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(floor_sql_error)?;
        let encoded_next = encode_authority_floor(&transition.next);
        let changed = match transition.expected {
            None => transaction
                .execute(
                    "INSERT OR IGNORE INTO settlement_floor (singleton, floor_value) VALUES (1, ?1)",
                    params![encoded_next],
                )
                .map_err(floor_sql_error)?,
            Some(expected) => transaction
                .execute(
                    "UPDATE settlement_floor SET floor_value = ?1 \
                     WHERE singleton = 1 AND floor_value = ?2",
                    params![encoded_next, encode_authority_floor(&expected)],
                )
                .map_err(floor_sql_error)?,
        };
        if changed == 1 {
            transaction.commit().map_err(floor_sql_error)?;
            return Ok(transition.next);
        }
        let raw = read_raw_floor(&transaction)
            .map_err(floor_error_from_store)?
            .ok_or_else(|| floor_error("provider settlement floor disappeared during CAS"))?;
        let current = decode_authority_floor(&raw).map_err(floor_error_from_store)?;
        transaction.rollback().map_err(floor_sql_error)?;
        Ok(current)
    }
}

/// Decoded, structurally validated state needed to resume one provider payout
/// workflow. Every returned object still needs the client's signature/trust
/// revalidation before a network request is sent.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderSettlementRecoveryV1 {
    pub active_pending_payout: Option<ProviderPayoutPendingV1>,
    pub committed_payout_origin: Option<ProviderPayoutPendingV1>,
    pub payout_state: Option<ProviderPayoutDurableStateV1>,
    pub pending_status: Option<ProviderPayoutStatusPendingV1>,
}

impl core::fmt::Debug for ProviderSettlementRecoveryV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProviderSettlementRecoveryV1")
            .field("has_active_pending", &self.active_pending_payout.is_some())
            .field(
                "has_committed_origin",
                &self.committed_payout_origin.is_some(),
            )
            .field("has_payout_state", &self.payout_state.is_some())
            .field("has_pending_status", &self.pending_status.is_some())
            .field("protocol_bytes", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Kind of interrupted detailed-store write. This is descriptive only; it is
/// never sufficient authority to move the independent floor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderSettlementRecoveryTransitionKindV2 {
    PendingPayout,
    InitialPayout,
    StatusPending,
    StatusCommit,
}

/// Pure-read snapshot of one interrupted journal. Every record is structurally
/// and content-commitment checked by the SQLite adapter, but remains untrusted
/// until [`crate::ProviderSettlementClientV1`] revalidates canonical protocol
/// bytes, signatures, key lineage, registration lineage, and progression.
#[derive(Clone, Eq, PartialEq)]
pub struct UnverifiedProviderSettlementRecoveryV2 {
    pub(crate) snapshot_digest: [u8; 32],
    pub(crate) transition_kind: ProviderSettlementRecoveryTransitionKindV2,
    pub(crate) workflow: ProviderSettlementRecoveryV1,
    pub(crate) transition_previous_state: Option<ProviderPayoutDurableStateV1>,
    pub(crate) expected_floor: Option<ProviderSettlementFloorV1>,
    pub(crate) desired_floor: ProviderSettlementFloorV1,
    pub(crate) authority_at_inspection: Option<ProviderSettlementFloorV1>,
}

impl core::fmt::Debug for UnverifiedProviderSettlementRecoveryV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("UnverifiedProviderSettlementRecoveryV2")
            .field("snapshot_digest", &"[REDACTED]")
            .field("transition_kind", &self.transition_kind)
            .field("workflow", &"[REDACTED]")
            .field(
                "has_transition_previous_state",
                &self.transition_previous_state.is_some(),
            )
            .finish_non_exhaustive()
    }
}

impl UnverifiedProviderSettlementRecoveryV2 {
    pub fn transition_kind(&self) -> ProviderSettlementRecoveryTransitionKindV2 {
        self.transition_kind
    }

    pub fn workflow(&self) -> &ProviderSettlementRecoveryV1 {
        &self.workflow
    }

    pub fn transition_previous_state(&self) -> Option<&ProviderPayoutDurableStateV1> {
        self.transition_previous_state.as_ref()
    }

    pub fn authority_at_inspection(&self) -> Option<&ProviderSettlementFloorV1> {
        self.authority_at_inspection.as_ref()
    }
}

/// Client-authenticated capability for completing exactly one previously
/// inspected crash-recovery transition. Private fields prevent store callers
/// from turning unauthenticated disk bytes into authority mutation rights.
#[derive(Clone)]
pub struct VerifiedProviderSettlementRecoveryV2 {
    pub(crate) snapshot_digest: [u8; 32],
    pub(crate) transition_kind: ProviderSettlementRecoveryTransitionKindV2,
    pub(crate) expected_floor: Option<ProviderSettlementFloorV1>,
    pub(crate) desired_floor: ProviderSettlementFloorV1,
}

impl core::fmt::Debug for VerifiedProviderSettlementRecoveryV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VerifiedProviderSettlementRecoveryV2")
            .field("transition_kind", &self.transition_kind)
            .field("desired_revision", &self.desired_floor.revision)
            .finish_non_exhaustive()
    }
}

/// Durable SQLite implementation of [`ProviderSettlementStateStoreV1`].
///
/// `authority` must be scoped to this one detailed store. The bundled SQLite
/// authority is suitable only for local/test use; production callers must
/// supply an independently reviewed authority implementation.
pub struct SqliteProviderSettlementStateStoreV1<A: ProviderSettlementFloorAuthorityV1> {
    path: PathBuf,
    provider_id: ProviderId,
    busy_timeout: Duration,
    authority: Arc<A>,
}

impl<A: ProviderSettlementFloorAuthorityV1> core::fmt::Debug
    for SqliteProviderSettlementStateStoreV1<A>
{
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SqliteProviderSettlementStateStoreV1")
            .field("path", &self.path)
            .field("provider_id", &self.provider_id)
            .field("busy_timeout", &self.busy_timeout)
            .finish_non_exhaustive()
    }
}

/// Opaque fail-closed error from the detailed SQLite state adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderSettlementSqliteStoreErrorV1 {
    reason: String,
}

impl core::fmt::Display for ProviderSettlementSqliteStoreErrorV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&self.reason)
    }
}

impl std::error::Error for ProviderSettlementSqliteStoreErrorV1 {}

impl<A> SqliteProviderSettlementStateStoreV1<A>
where
    A: ProviderSettlementFloorAuthorityV1,
{
    pub fn create(
        path: impl AsRef<Path>,
        provider_id: ProviderId,
        authority: Arc<A>,
        busy_timeout: Duration,
    ) -> Result<Self, ProviderSettlementSqliteStoreErrorV1> {
        validate_provider_id(&provider_id)?;
        validate_timeout(busy_timeout, "provider settlement state")?;
        if authority.load().map_err(authority_error)?.is_some() {
            return Err(store_error(
                "provider settlement floor is already initialized for a new detailed store",
            ));
        }
        let mut store_instance_id = [0_u8; 16];
        getrandom::getrandom(&mut store_instance_id).map_err(|_| {
            store_error("provider settlement store instance randomness unavailable")
        })?;
        if store_instance_id.iter().all(|byte| *byte == 0) {
            return Err(store_error(
                "provider settlement store instance randomness is all zero",
            ));
        }
        let path = path.as_ref().to_path_buf();
        create_empty_regular_file(&path, "provider settlement state")?;
        let store = Self {
            path,
            provider_id,
            busy_timeout,
            authority,
        };
        let connection = store.open_raw()?;
        configure(&connection, busy_timeout)?;
        connection.execute_batch(STORE_SCHEMA).map_err(sql_error)?;
        connection
            .execute(
                "INSERT INTO workflow (singleton, store_instance_id, provider_id, current_state, \
                 committed_pending, active_pending, pending_status, transition_previous_state, \
                 authority_revision, transition_kind) \
                 VALUES (1, ?1, ?2, NULL, NULL, NULL, NULL, NULL, 0, 0)",
                params![store_instance_id.as_slice(), provider_id.as_slice()],
            )
            .map_err(sql_error)?;
        set_schema_identity(&connection, STORE_APPLICATION_ID, STORE_SCHEMA_VERSION)?;
        checkpoint_and_sync(&connection, &store.path, "provider settlement state")?;
        store.open_checked()?;
        store.verify_alignment()?;
        Ok(store)
    }

    pub fn open_existing(
        path: impl AsRef<Path>,
        provider_id: ProviderId,
        authority: Arc<A>,
        busy_timeout: Duration,
    ) -> Result<Self, ProviderSettlementSqliteStoreErrorV1> {
        validate_provider_id(&provider_id)?;
        validate_timeout(busy_timeout, "provider settlement state")?;
        let store = Self {
            path: path.as_ref().to_path_buf(),
            provider_id,
            busy_timeout,
            authority,
        };
        store.open_checked()?;
        store.verify_recovery_alignment()?;
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Loads only a stable, authority-aligned workflow. An interrupted journal
    /// returns `RecoveryRequired`; opening or loading never advances authority.
    pub fn load_recovery(
        &self,
    ) -> Result<ProviderSettlementRecoveryV1, ProviderSettlementSqliteStoreErrorV1> {
        self.load_stable_recovery_with_floor()
            .map(|(recovery, _)| recovery)
    }

    fn open_raw(&self) -> Result<Connection, ProviderSettlementSqliteStoreErrorV1> {
        open_existing_regular_file(&self.path, "provider settlement state")
    }

    fn open_checked(&self) -> Result<Connection, ProviderSettlementSqliteStoreErrorV1> {
        let mut connection = self.open_raw()?;
        configure(&connection, self.busy_timeout)?;
        {
            // Schema, workflow and history must come from one SQLite snapshot.
            // In WAL mode, separate autocommit SELECTs could otherwise observe
            // a legitimate concurrent transition half old and half new.
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Deferred)
                .map_err(sql_error)?;
            verify_schema_identity(
                &transaction,
                STORE_APPLICATION_ID,
                STORE_SCHEMA_VERSION,
                "provider settlement state",
            )?;
            verify_integrity(&transaction, "provider settlement state")?;
            verify_store_schema(&transaction)?;
            let workflow = read_workflow(&transaction, &self.provider_id)?;
            let history =
                validate_history(&transaction, &workflow.store_instance_id, &self.provider_id)?;
            validate_workflow_history_link(&workflow, history.tail.as_ref())?;
            transaction.commit().map_err(sql_error)?;
        }
        Ok(connection)
    }

    fn load_stable_recovery_with_floor(
        &self,
    ) -> Result<
        (
            ProviderSettlementRecoveryV1,
            Option<ProviderSettlementFloorV1>,
        ),
        ProviderSettlementSqliteStoreErrorV1,
    > {
        let mut connection = self.open_checked()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sql_error)?;
        let workflow = read_workflow(&transaction, &self.provider_id)?;
        let history =
            validate_history(&transaction, &workflow.store_instance_id, &self.provider_id)?;
        validate_workflow_history_link(&workflow, history.tail.as_ref())?;
        if workflow.transition_kind != 0 {
            return Err(store_error(
                "provider settlement recovery is required for an unresolved transition",
            ));
        }
        let expected = stable_floor(&workflow, &history, &self.provider_id)?;
        let actual = self.authority.load().map_err(authority_error)?;
        if actual != expected {
            return Err(store_error(
                "provider settlement detailed state and floor authority disagree",
            ));
        }
        let recovery = ProviderSettlementRecoveryV1 {
            active_pending_payout: workflow.active_pending,
            committed_payout_origin: workflow.committed_pending,
            payout_state: workflow.current_state,
            pending_status: workflow.pending_status,
        };
        transaction.commit().map_err(sql_error)?;
        Ok((recovery, expected))
    }
}

enum LiveTransitionAuthorization<'a> {
    PendingPayout(&'a VerifiedProviderPayoutPendingWriteV1),
    InitialPayout(&'a VerifiedProviderPayoutInitialWriteV1),
    StatusPending(&'a VerifiedProviderPayoutStatusPendingWriteV1),
    StatusCommit(&'a VerifiedProviderPayoutStatusWriteV1),
}

impl LiveTransitionAuthorization<'_> {
    fn verify_exact(
        &self,
        inspection: &UnverifiedProviderSettlementRecoveryV2,
    ) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
        let exact = match self {
            Self::PendingPayout(write) => {
                inspection.transition_kind
                    == ProviderSettlementRecoveryTransitionKindV2::PendingPayout
                    && inspection.workflow.active_pending_payout.as_ref() == Some(&write.pending)
            }
            Self::InitialPayout(write) => {
                inspection.transition_kind
                    == ProviderSettlementRecoveryTransitionKindV2::InitialPayout
                    && inspection.workflow.active_pending_payout.as_ref() == Some(&write.pending)
                    && inspection.workflow.committed_payout_origin.as_ref() == Some(&write.pending)
                    && inspection.workflow.payout_state.as_ref() == Some(&write.state)
            }
            Self::StatusPending(write) => {
                inspection.transition_kind
                    == ProviderSettlementRecoveryTransitionKindV2::StatusPending
                    && inspection.workflow.pending_status.as_ref() == Some(&write.pending)
                    && inspection
                        .workflow
                        .payout_state
                        .as_ref()
                        .map(provider_payout_durable_state_commitment_v1)
                        .transpose()
                        .map_err(protocol_error)?
                        == Some(write.pending.previous_state_commitment)
            }
            Self::StatusCommit(write) => {
                inspection.transition_kind
                    == ProviderSettlementRecoveryTransitionKindV2::StatusCommit
                    && inspection.workflow.pending_status.as_ref() == Some(&write.pending)
                    && inspection.workflow.payout_state.as_ref() == Some(&write.state)
                    && inspection
                        .transition_previous_state
                        .as_ref()
                        .map(provider_payout_durable_state_commitment_v1)
                        .transpose()
                        .map_err(protocol_error)?
                        == Some(write.pending.previous_state_commitment)
            }
        };
        if !exact {
            return Err(store_error(
                "verified provider settlement write does not match the exact journal",
            ));
        }
        Ok(())
    }
}

fn recovery_transition_kind(
    value: u8,
) -> Result<ProviderSettlementRecoveryTransitionKindV2, ProviderSettlementSqliteStoreErrorV1> {
    match value {
        1 => Ok(ProviderSettlementRecoveryTransitionKindV2::PendingPayout),
        2 => Ok(ProviderSettlementRecoveryTransitionKindV2::InitialPayout),
        3 => Ok(ProviderSettlementRecoveryTransitionKindV2::StatusPending),
        4 => Ok(ProviderSettlementRecoveryTransitionKindV2::StatusCommit),
        _ => Err(store_error(
            "stable provider settlement workflow has no recovery kind",
        )),
    }
}

impl<A> ProviderSettlementStateStoreV1 for SqliteProviderSettlementStateStoreV1<A>
where
    A: ProviderSettlementFloorAuthorityV1,
{
    type Error = ProviderSettlementSqliteStoreErrorV1;

    fn persist_pending_payout(
        &mut self,
        write: &VerifiedProviderPayoutPendingWriteV1,
    ) -> Result<bool, Self::Error> {
        let pending = &write.pending;
        validate_pending_payout(pending, &self.provider_id)?;
        for _ in 0..8 {
            self.verify_alignment()?;

            let mut connection = self.open_checked()?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_error)?;
            let workflow = read_workflow(&transaction, &self.provider_id)?;
            if workflow.transition_kind != 0 {
                transaction.rollback().map_err(sql_error)?;
                continue;
            }
            if let Some(existing) = workflow.active_pending.as_ref() {
                let exact = existing == pending;
                transaction.rollback().map_err(sql_error)?;
                self.verify_alignment()?;
                return Ok(exact);
            }
            if workflow.pending_status.is_some() {
                transaction.rollback().map_err(sql_error)?;
                return Ok(false);
            }

            match pending.predecessor_floor {
                None => {
                    if workflow.current_state.is_some() || workflow.committed_pending.is_some() {
                        transaction.rollback().map_err(sql_error)?;
                        return Ok(false);
                    }
                }
                Some(predecessor) => {
                    let Some(current) = workflow.current_state.as_ref() else {
                        transaction.rollback().map_err(sql_error)?;
                        return Ok(false);
                    };
                    let Some(committed) = workflow.committed_pending.as_ref() else {
                        transaction.rollback().map_err(sql_error)?;
                        return Ok(false);
                    };
                    if !matches!(
                        predecessor.state(),
                        PayoutStateV1::Succeeded | PayoutStateV1::Failed
                    ) || current.rollback_floor != predecessor
                    {
                        transaction.rollback().map_err(sql_error)?;
                        return Ok(false);
                    }
                    archive_current(&transaction, committed, current)?;
                }
            }

            let encoded = encode_pending_payout(pending)?;
            let changed = transaction
                .execute(
                    "UPDATE workflow SET active_pending = ?1, transition_kind = 1 \
                 WHERE singleton = 1 AND transition_kind = 0 AND active_pending IS NULL",
                    params![encoded],
                )
                .map_err(sql_error)?;
            if changed != 1 {
                transaction.rollback().map_err(sql_error)?;
                return Ok(false);
            }
            transaction.commit().map_err(sql_error)?;
            self.apply_live_transition(LiveTransitionAuthorization::PendingPayout(write))?;
            let recovery = self.load_recovery()?;
            return Ok(recovery.active_pending_payout.as_ref() == Some(pending));
        }
        Err(store_error(
            "provider settlement pending payout did not converge after concurrent retries",
        ))
    }

    fn commit_initial_payout_from_pending(
        &mut self,
        write: &VerifiedProviderPayoutInitialWriteV1,
    ) -> Result<bool, Self::Error> {
        let pending = &write.pending;
        let state = &write.state;
        validate_pending_payout(pending, &self.provider_id)?;
        validate_durable_state(state)?;
        if state.rollback_floor.payout_request_digest() != &pending.payout_request_digest
            || state.rollback_floor.state() != PayoutStateV1::Accepted
            || state.rollback_floor.state_version() != 1
        {
            return Ok(false);
        }
        for _ in 0..8 {
            self.verify_alignment()?;

            let mut connection = self.open_checked()?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_error)?;
            let workflow = read_workflow(&transaction, &self.provider_id)?;
            if workflow.transition_kind != 0 {
                transaction.rollback().map_err(sql_error)?;
                continue;
            }
            let Some(active) = workflow.active_pending.as_ref() else {
                let exact = workflow.current_state.as_ref() == Some(state)
                    && workflow.committed_pending.as_ref() == Some(pending)
                    && workflow.pending_status.is_none();
                transaction.rollback().map_err(sql_error)?;
                self.verify_alignment()?;
                return Ok(exact);
            };
            if active != pending || workflow.pending_status.is_some() {
                transaction.rollback().map_err(sql_error)?;
                return Ok(false);
            }
            let predecessor_matches = match pending.predecessor_floor {
                None => workflow.current_state.is_none() && workflow.committed_pending.is_none(),
                Some(predecessor) => {
                    workflow
                        .current_state
                        .as_ref()
                        .is_some_and(|current| current.rollback_floor == predecessor)
                        && workflow.committed_pending.is_some()
                }
            };
            if !predecessor_matches {
                transaction.rollback().map_err(sql_error)?;
                return Ok(false);
            }

            let encoded_state = encode_durable_state(state)?;
            let encoded_pending = encode_pending_payout(pending)?;
            let changed = transaction
                .execute(
                    "UPDATE workflow SET current_state = ?1, committed_pending = ?2, \
                 transition_kind = 2 WHERE singleton = 1 AND transition_kind = 0",
                    params![encoded_state, encoded_pending],
                )
                .map_err(sql_error)?;
            if changed != 1 {
                transaction.rollback().map_err(sql_error)?;
                return Ok(false);
            }
            transaction.commit().map_err(sql_error)?;
            self.apply_live_transition(LiveTransitionAuthorization::InitialPayout(write))?;
            let recovery = self.load_recovery()?;
            return Ok(recovery.active_pending_payout.is_none()
                && recovery.committed_payout_origin.as_ref() == Some(pending)
                && recovery.payout_state.as_ref() == Some(state));
        }
        Err(store_error(
            "provider settlement initial payout did not converge after concurrent retries",
        ))
    }

    fn persist_pending_status(
        &mut self,
        write: &VerifiedProviderPayoutStatusPendingWriteV1,
    ) -> Result<bool, Self::Error> {
        let pending = &write.pending;
        validate_pending_status(pending, &self.provider_id)?;
        for _ in 0..8 {
            self.verify_alignment()?;

            let mut connection = self.open_checked()?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_error)?;
            let workflow = read_workflow(&transaction, &self.provider_id)?;
            if workflow.transition_kind != 0 {
                transaction.rollback().map_err(sql_error)?;
                continue;
            }
            if workflow.active_pending.is_some()
                || workflow.current_state.is_none()
                || workflow.committed_pending.is_none()
                || workflow
                    .current_state
                    .as_ref()
                    .is_some_and(|state| state.rollback_floor != pending.previous_floor)
            {
                transaction.rollback().map_err(sql_error)?;
                return Ok(false);
            }
            let current_commitment = provider_payout_durable_state_commitment_v1(
                workflow
                    .current_state
                    .as_ref()
                    .expect("current state checked above"),
            )
            .map_err(protocol_error)?;
            if current_commitment != pending.previous_state_commitment {
                transaction.rollback().map_err(sql_error)?;
                return Ok(false);
            }
            if let Some(existing) = workflow.pending_status.as_ref() {
                let exact = existing == pending;
                transaction.rollback().map_err(sql_error)?;
                self.verify_alignment()?;
                return Ok(exact);
            }
            let encoded = encode_pending_status(pending)?;
            let changed = transaction
                .execute(
                    "UPDATE workflow SET pending_status = ?1, transition_kind = 3 \
                 WHERE singleton = 1 \
                 AND transition_kind = 0 AND active_pending IS NULL \
                 AND pending_status IS NULL",
                    params![encoded],
                )
                .map_err(sql_error)?;
            if changed != 1 {
                transaction.rollback().map_err(sql_error)?;
                return Ok(false);
            }
            transaction.commit().map_err(sql_error)?;
            self.apply_live_transition(LiveTransitionAuthorization::StatusPending(write))?;
            let recovery = self.load_recovery()?;
            return Ok(recovery.pending_status.as_ref() == Some(pending));
        }
        Err(store_error(
            "provider settlement pending status did not converge after concurrent retries",
        ))
    }

    fn commit_status_update(
        &mut self,
        write: &VerifiedProviderPayoutStatusWriteV1,
    ) -> Result<bool, Self::Error> {
        let pending = &write.pending;
        let state = &write.state;
        validate_pending_status(pending, &self.provider_id)?;
        validate_durable_state(state)?;
        if !floor_is_satisfied(&pending.previous_floor, &state.rollback_floor) {
            return Ok(false);
        }
        for _ in 0..8 {
            self.verify_alignment()?;

            let mut connection = self.open_checked()?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_error)?;
            let workflow = read_workflow(&transaction, &self.provider_id)?;
            if workflow.transition_kind != 0 {
                transaction.rollback().map_err(sql_error)?;
                continue;
            }
            let Some(existing_pending) = workflow.pending_status.as_ref() else {
                let exact = workflow.active_pending.is_none()
                    && workflow.current_state.as_ref() == Some(state)
                    && workflow.committed_pending.is_some();
                transaction.rollback().map_err(sql_error)?;
                self.verify_alignment()?;
                return Ok(exact);
            };
            if existing_pending != pending
                || workflow.active_pending.is_some()
                || workflow.committed_pending.is_none()
                || workflow.current_state.as_ref().map_or(true, |current| {
                    current.rollback_floor != pending.previous_floor
                })
            {
                transaction.rollback().map_err(sql_error)?;
                return Ok(false);
            }
            let current = workflow
                .current_state
                .as_ref()
                .expect("current state checked above");
            if provider_payout_durable_state_commitment_v1(current).map_err(protocol_error)?
                != pending.previous_state_commitment
            {
                transaction.rollback().map_err(sql_error)?;
                return Ok(false);
            }
            let encoded_state = encode_durable_state(state)?;
            let encoded_previous_state = encode_durable_state(current)?;
            let changed = transaction
                .execute(
                    "UPDATE workflow SET current_state = ?1, transition_previous_state = ?2, \
                 transition_kind = 4 \
                 WHERE singleton = 1 AND transition_kind = 0",
                    params![encoded_state, encoded_previous_state],
                )
                .map_err(sql_error)?;
            if changed != 1 {
                transaction.rollback().map_err(sql_error)?;
                return Ok(false);
            }
            transaction.commit().map_err(sql_error)?;
            self.apply_live_transition(LiveTransitionAuthorization::StatusCommit(write))?;
            let recovery = self.load_recovery()?;
            return Ok(
                recovery.pending_status.is_none() && recovery.payout_state.as_ref() == Some(state)
            );
        }
        Err(store_error(
            "provider settlement status update did not converge after concurrent retries",
        ))
    }
}

impl<A> SqliteProviderSettlementStateStoreV1<A>
where
    A: ProviderSettlementFloorAuthorityV1,
{
    /// Inspects an interrupted transition without mutating either persistence
    /// domain. A journal is recoverable only when the authority is still at the
    /// exact predecessor or already at the exact successor.
    pub fn inspect_recovery(
        &self,
    ) -> Result<Option<UnverifiedProviderSettlementRecoveryV2>, ProviderSettlementSqliteStoreErrorV1>
    {
        let mut connection = self.open_checked()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sql_error)?;
        let workflow = read_workflow(&transaction, &self.provider_id)?;
        let history =
            validate_history(&transaction, &workflow.store_instance_id, &self.provider_id)?;
        validate_workflow_history_link(&workflow, history.tail.as_ref())?;
        if workflow.transition_kind == 0 {
            let expected = stable_floor(&workflow, &history, &self.provider_id)?;
            let actual = self.authority.load().map_err(authority_error)?;
            if actual != expected {
                return Err(store_error(
                    "provider settlement detailed state and floor authority disagree",
                ));
            }
            transaction.commit().map_err(sql_error)?;
            return Ok(None);
        }
        let (expected_floor, desired_floor) =
            transition_floors(&workflow, &history, &self.provider_id)?;
        let authority_at_inspection = self.authority.load().map_err(authority_error)?;
        if authority_at_inspection != expected_floor
            && authority_at_inspection != Some(desired_floor)
        {
            return Err(store_error(
                "provider settlement floor conflicts with the unresolved journal",
            ));
        }
        let snapshot_digest = transition_snapshot_digest(
            &workflow,
            &history,
            expected_floor.as_ref(),
            &desired_floor,
        )?;
        transaction.commit().map_err(sql_error)?;
        Ok(Some(UnverifiedProviderSettlementRecoveryV2 {
            snapshot_digest,
            transition_kind: recovery_transition_kind(workflow.transition_kind)?,
            workflow: ProviderSettlementRecoveryV1 {
                active_pending_payout: workflow.active_pending.clone(),
                committed_payout_origin: workflow.committed_pending.clone(),
                payout_state: workflow.current_state.clone(),
                pending_status: workflow.pending_status.clone(),
            },
            transition_previous_state: workflow.transition_previous_state.clone(),
            expected_floor,
            desired_floor,
            authority_at_inspection,
        }))
    }

    /// Completes one client-authenticated interrupted transition. The exact
    /// detailed snapshot is reread before authority CAS and again before local
    /// finalization, so a stale token is harmless.
    pub fn resume_recovery(
        &self,
        verified: &VerifiedProviderSettlementRecoveryV2,
    ) -> Result<ProviderSettlementRecoveryV1, ProviderSettlementSqliteStoreErrorV1> {
        for _ in 0..8 {
            let Some(inspection) = self.inspect_recovery()? else {
                let (recovery, floor) = self.load_stable_recovery_with_floor()?;
                if floor == Some(verified.desired_floor) {
                    return Ok(recovery);
                }
                return Err(store_error(
                    "provider settlement recovery token no longer names the stable state",
                ));
            };
            if inspection.snapshot_digest != verified.snapshot_digest
                || inspection.transition_kind != verified.transition_kind
                || inspection.expected_floor != verified.expected_floor
                || inspection.desired_floor != verified.desired_floor
            {
                return Err(store_error(
                    "provider settlement recovery token does not match the exact journal snapshot",
                ));
            }
            if inspection.authority_at_inspection != Some(verified.desired_floor) {
                let transition = AuthenticatedProviderSettlementFloorTransitionV1 {
                    expected: verified.expected_floor,
                    next: verified.desired_floor,
                };
                let advanced = self.authority.apply(&transition).map_err(authority_error)?;
                if advanced != verified.desired_floor {
                    return Err(store_error(
                        "provider settlement authority rejected the authenticated recovery CAS",
                    ));
                }
            }

            let mut final_connection = self.open_checked()?;
            let transaction = final_connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_error)?;
            let latest = read_workflow(&transaction, &self.provider_id)?;
            let latest_history =
                validate_history(&transaction, &latest.store_instance_id, &self.provider_id)?;
            if latest.transition_kind == 0 {
                transaction.rollback().map_err(sql_error)?;
                continue;
            }
            let (latest_expected, latest_desired) =
                transition_floors(&latest, &latest_history, &self.provider_id)?;
            let latest_snapshot = transition_snapshot_digest(
                &latest,
                &latest_history,
                latest_expected.as_ref(),
                &latest_desired,
            )?;
            if latest_snapshot != verified.snapshot_digest
                || latest_desired != verified.desired_floor
            {
                transaction.rollback().map_err(sql_error)?;
                return Err(store_error(
                    "provider settlement journal changed before recovery finalization",
                ));
            }
            if self.authority.load().map_err(authority_error)? != Some(verified.desired_floor) {
                transaction.rollback().map_err(sql_error)?;
                return Err(store_error(
                    "provider settlement authority changed before recovery finalization",
                ));
            }
            let statement = match latest.transition_kind {
                1 => {
                    "UPDATE workflow SET authority_revision = ?1, transition_kind = 0 \
                      WHERE singleton = 1 AND transition_kind = 1"
                }
                2 => {
                    "UPDATE workflow SET active_pending = NULL, authority_revision = ?1, \
                      transition_kind = 0 \
                      WHERE singleton = 1 AND transition_kind = 2"
                }
                3 => {
                    "UPDATE workflow SET authority_revision = ?1, transition_kind = 0 \
                      WHERE singleton = 1 AND transition_kind = 3"
                }
                4 => {
                    "UPDATE workflow SET pending_status = NULL, \
                      transition_previous_state = NULL, authority_revision = ?1, \
                      transition_kind = 0 \
                      WHERE singleton = 1 AND transition_kind = 4"
                }
                _ => return Err(store_error("invalid provider settlement transition kind")),
            };
            let next_revision = i64::try_from(verified.desired_floor.revision).map_err(|_| {
                store_error("provider settlement authority revision exceeds SQLite")
            })?;
            let changed = transaction
                .execute(statement, params![next_revision])
                .map_err(sql_error)?;
            if changed != 1 {
                transaction.rollback().map_err(sql_error)?;
                continue;
            }
            transaction.commit().map_err(sql_error)?;
            self.verify_alignment()?;
            return self.load_recovery();
        }
        Err(store_error(
            "provider settlement recovery did not converge after concurrent retries",
        ))
    }

    fn apply_live_transition(
        &self,
        authorization: LiveTransitionAuthorization<'_>,
    ) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
        let inspection = self.inspect_recovery()?.ok_or_else(|| {
            store_error("provider settlement live write has no unresolved journal")
        })?;
        authorization.verify_exact(&inspection)?;
        let verified = VerifiedProviderSettlementRecoveryV2 {
            snapshot_digest: inspection.snapshot_digest,
            transition_kind: inspection.transition_kind,
            expected_floor: inspection.expected_floor,
            desired_floor: inspection.desired_floor,
        };
        self.resume_recovery(&verified)?;
        Ok(())
    }

    fn verify_recovery_alignment(&self) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
        self.inspect_recovery().map(|_| ())
    }

    fn verify_alignment(&self) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
        self.load_stable_recovery_with_floor().map(|_| ())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DecodedWorkflow {
    store_instance_id: [u8; 16],
    current_state: Option<ProviderPayoutDurableStateV1>,
    committed_pending: Option<ProviderPayoutPendingV1>,
    active_pending: Option<ProviderPayoutPendingV1>,
    pending_status: Option<ProviderPayoutStatusPendingV1>,
    transition_previous_state: Option<ProviderPayoutDurableStateV1>,
    authority_revision: u64,
    transition_kind: u8,
}

fn transition_floors(
    workflow: &DecodedWorkflow,
    history: &HistoryValidation,
    provider_id: &ProviderId,
) -> Result<
    (Option<ProviderSettlementFloorV1>, ProviderSettlementFloorV1),
    ProviderSettlementSqliteStoreErrorV1,
> {
    match workflow.transition_kind {
        1 => {
            let pending = workflow
                .active_pending
                .as_ref()
                .ok_or_else(|| store_error("pending-floor transition has no payout"))?;
            let expected = match pending.predecessor_floor {
                None => None,
                Some(predecessor) => {
                    let origin = workflow.committed_pending.as_ref().ok_or_else(|| {
                        store_error("later pending transition has no committed predecessor origin")
                    })?;
                    let previous_history = history.before_tail.ok_or_else(|| {
                        store_error("later pending transition has no predecessor history anchor")
                    })?;
                    Some(authority_floor(
                        &workflow.store_instance_id,
                        provider_id,
                        workflow.authority_revision,
                        ProviderSettlementFloorPhaseV1::Payout {
                            payout: predecessor,
                        },
                        active_workflow_commitments(
                            workflow.current_state.as_ref(),
                            Some(origin),
                            None,
                            None,
                        )?,
                        previous_history,
                    )?)
                }
            };
            if expected.is_none() && workflow.authority_revision != 0 {
                return Err(store_error(
                    "first pending transition has a nonzero authority revision",
                ));
            }
            let next_revision = checked_next_revision(workflow.authority_revision)?;
            Ok((
                expected,
                authority_floor(
                    &workflow.store_instance_id,
                    provider_id,
                    next_revision,
                    ProviderSettlementFloorPhaseV1::Pending {
                        pending: pending.pending_floor,
                        payout_request_digest: pending.payout_request_digest,
                    },
                    active_workflow_commitments(
                        workflow.current_state.as_ref(),
                        workflow.committed_pending.as_ref(),
                        Some(pending),
                        None,
                    )?,
                    history.anchor,
                )?,
            ))
        }
        2 => {
            if workflow.authority_revision == 0 {
                return Err(store_error(
                    "initial-payout transition has a zero predecessor revision",
                ));
            }
            let pending = workflow
                .active_pending
                .as_ref()
                .ok_or_else(|| store_error("initial-payout transition has no pending payout"))?;
            let state = workflow
                .current_state
                .as_ref()
                .ok_or_else(|| store_error("initial-payout transition has no successor state"))?;
            let previous = history.tail.as_ref();
            let expected_revision = workflow.authority_revision;
            let expected = authority_floor(
                &workflow.store_instance_id,
                provider_id,
                expected_revision,
                ProviderSettlementFloorPhaseV1::Pending {
                    pending: pending.pending_floor,
                    payout_request_digest: pending.payout_request_digest,
                },
                active_workflow_commitments(
                    previous.map(|tail| &tail.state),
                    previous.map(|tail| &tail.pending),
                    Some(pending),
                    None,
                )?,
                history.anchor,
            )?;
            Ok((
                Some(expected),
                authority_floor(
                    &workflow.store_instance_id,
                    provider_id,
                    checked_next_revision(expected_revision)?,
                    ProviderSettlementFloorPhaseV1::Payout {
                        payout: state.rollback_floor,
                    },
                    active_workflow_commitments(Some(state), Some(pending), None, None)?,
                    history.anchor,
                )?,
            ))
        }
        3 => {
            if workflow.authority_revision == 0 {
                return Err(store_error(
                    "status-pending transition has a zero predecessor revision",
                ));
            }
            let pending = workflow
                .pending_status
                .as_ref()
                .ok_or_else(|| store_error("status-pending transition has no pending request"))?;
            let state = workflow
                .current_state
                .as_ref()
                .ok_or_else(|| store_error("status-pending transition has no payout state"))?;
            let origin = workflow
                .committed_pending
                .as_ref()
                .ok_or_else(|| store_error("status-pending transition has no payout origin"))?;
            let expected_revision = workflow.authority_revision;
            let expected = authority_floor(
                &workflow.store_instance_id,
                provider_id,
                expected_revision,
                ProviderSettlementFloorPhaseV1::Payout {
                    payout: state.rollback_floor,
                },
                active_workflow_commitments(Some(state), Some(origin), None, None)?,
                history.anchor,
            )?;
            Ok((
                Some(expected),
                authority_floor(
                    &workflow.store_instance_id,
                    provider_id,
                    checked_next_revision(expected_revision)?,
                    ProviderSettlementFloorPhaseV1::StatusPending {
                        payout: pending.previous_floor,
                    },
                    active_workflow_commitments(Some(state), Some(origin), None, Some(pending))?,
                    history.anchor,
                )?,
            ))
        }
        4 => {
            if workflow.authority_revision == 0 {
                return Err(store_error(
                    "status-commit transition has a zero predecessor revision",
                ));
            }
            let pending = workflow
                .pending_status
                .as_ref()
                .ok_or_else(|| store_error("status-commit transition has no pending request"))?;
            let state = workflow
                .current_state
                .as_ref()
                .ok_or_else(|| store_error("status-commit transition has no successor state"))?;
            let origin = workflow
                .committed_pending
                .as_ref()
                .ok_or_else(|| store_error("status-commit transition has no payout origin"))?;
            let expected_revision = workflow.authority_revision;
            let expected = authority_floor(
                &workflow.store_instance_id,
                provider_id,
                expected_revision,
                ProviderSettlementFloorPhaseV1::StatusPending {
                    payout: pending.previous_floor,
                },
                ActiveWorkflowCommitments {
                    current_state: Some(pending.previous_state_commitment),
                    committed_pending: Some(pending_record_commitment(origin)?),
                    active_pending: None,
                    pending_status: Some(status_record_commitment(pending)?),
                    transition_previous_state: None,
                },
                history.anchor,
            )?;
            Ok((
                Some(expected),
                authority_floor(
                    &workflow.store_instance_id,
                    provider_id,
                    checked_next_revision(expected_revision)?,
                    ProviderSettlementFloorPhaseV1::Payout {
                        payout: state.rollback_floor,
                    },
                    active_workflow_commitments(Some(state), Some(origin), None, None)?,
                    history.anchor,
                )?,
            ))
        }
        _ => Err(store_error(
            "stable provider settlement workflow has no transition floors",
        )),
    }
}

fn stable_floor(
    workflow: &DecodedWorkflow,
    history: &HistoryValidation,
    provider_id: &ProviderId,
) -> Result<Option<ProviderSettlementFloorV1>, ProviderSettlementSqliteStoreErrorV1> {
    if let Some(pending) = workflow.active_pending.as_ref() {
        if workflow.authority_revision == 0 {
            return Err(store_error(
                "stable pending payout has a zero authority revision",
            ));
        }
        return Ok(Some(authority_floor(
            &workflow.store_instance_id,
            provider_id,
            workflow.authority_revision,
            ProviderSettlementFloorPhaseV1::Pending {
                pending: pending.pending_floor,
                payout_request_digest: pending.payout_request_digest,
            },
            active_workflow_commitments(
                workflow.current_state.as_ref(),
                workflow.committed_pending.as_ref(),
                Some(pending),
                None,
            )?,
            history.anchor,
        )?));
    }
    match (
        workflow.current_state.as_ref(),
        workflow.committed_pending.as_ref(),
    ) {
        (None, None) if workflow.authority_revision == 0 => Ok(None),
        (None, None) => Err(store_error(
            "empty provider settlement workflow has a nonzero authority revision",
        )),
        (Some(state), Some(origin)) => {
            if workflow.authority_revision == 0 {
                return Err(store_error("stable payout has a zero authority revision"));
            }
            let phase = if workflow.pending_status.is_some() {
                ProviderSettlementFloorPhaseV1::StatusPending {
                    payout: state.rollback_floor,
                }
            } else {
                ProviderSettlementFloorPhaseV1::Payout {
                    payout: state.rollback_floor,
                }
            };
            Ok(Some(authority_floor(
                &workflow.store_instance_id,
                provider_id,
                workflow.authority_revision,
                phase,
                active_workflow_commitments(
                    Some(state),
                    Some(origin),
                    None,
                    workflow.pending_status.as_ref(),
                )?,
                history.anchor,
            )?))
        }
        _ => Err(store_error(
            "provider settlement stable state is missing its committed origin",
        )),
    }
}

#[derive(Clone, Copy)]
struct ActiveWorkflowCommitments {
    current_state: Option<[u8; 32]>,
    committed_pending: Option<[u8; 32]>,
    active_pending: Option<[u8; 32]>,
    pending_status: Option<[u8; 32]>,
    transition_previous_state: Option<[u8; 32]>,
}

fn active_workflow_commitments(
    current_state: Option<&ProviderPayoutDurableStateV1>,
    committed_pending: Option<&ProviderPayoutPendingV1>,
    active_pending: Option<&ProviderPayoutPendingV1>,
    pending_status: Option<&ProviderPayoutStatusPendingV1>,
) -> Result<ActiveWorkflowCommitments, ProviderSettlementSqliteStoreErrorV1> {
    Ok(ActiveWorkflowCommitments {
        current_state: current_state
            .map(provider_payout_durable_state_commitment_v1)
            .transpose()
            .map_err(protocol_error)?,
        committed_pending: committed_pending
            .map(pending_record_commitment)
            .transpose()?,
        active_pending: active_pending.map(pending_record_commitment).transpose()?,
        pending_status: pending_status.map(status_record_commitment).transpose()?,
        transition_previous_state: None,
    })
}

fn pending_record_commitment(
    pending: &ProviderPayoutPendingV1,
) -> Result<[u8; 32], ProviderSettlementSqliteStoreErrorV1> {
    record_commitment(1, &encode_pending_payout(pending)?)
}

fn status_record_commitment(
    pending: &ProviderPayoutStatusPendingV1,
) -> Result<[u8; 32], ProviderSettlementSqliteStoreErrorV1> {
    record_commitment(2, &encode_pending_status(pending)?)
}

fn record_commitment(
    kind: u8,
    bytes: &[u8],
) -> Result<[u8; 32], ProviderSettlementSqliteStoreErrorV1> {
    let len = u64::try_from(bytes.len())
        .map_err(|_| store_error("provider settlement record length does not fit u64"))?;
    let mut hasher = Sha256::new();
    hasher.update(RECORD_COMMITMENT_DOMAIN_V2);
    hasher.update([kind]);
    hasher.update(len.to_le_bytes());
    hasher.update(bytes);
    Ok(hasher.finalize().into())
}

fn transition_snapshot_digest(
    workflow: &DecodedWorkflow,
    history: &HistoryValidation,
    expected: Option<&ProviderSettlementFloorV1>,
    desired: &ProviderSettlementFloorV1,
) -> Result<[u8; 32], ProviderSettlementSqliteStoreErrorV1> {
    fn hash_optional(hasher: &mut Sha256, value: Option<&[u8]>) {
        match value {
            None => hasher.update([0]),
            Some(bytes) => {
                hasher.update([1]);
                hasher.update((bytes.len() as u64).to_le_bytes());
                hasher.update(bytes);
            }
        }
    }

    let current_state = workflow
        .current_state
        .as_ref()
        .map(encode_durable_state)
        .transpose()?;
    let committed_pending = workflow
        .committed_pending
        .as_ref()
        .map(encode_pending_payout)
        .transpose()?;
    let active_pending = workflow
        .active_pending
        .as_ref()
        .map(encode_pending_payout)
        .transpose()?;
    let pending_status = workflow
        .pending_status
        .as_ref()
        .map(encode_pending_status)
        .transpose()?;
    let transition_previous_state = workflow
        .transition_previous_state
        .as_ref()
        .map(encode_durable_state)
        .transpose()?;
    let encoded_expected = expected.map(encode_authority_floor);
    let encoded_desired = encode_authority_floor(desired);

    let mut hasher = Sha256::new();
    hasher.update(RECOVERY_SNAPSHOT_DOMAIN_V2);
    hasher.update(workflow.store_instance_id);
    hasher.update(desired.provider_id);
    hasher.update(workflow.authority_revision.to_le_bytes());
    hasher.update([workflow.transition_kind]);
    hasher.update(history.anchor.length.to_le_bytes());
    hasher.update(history.anchor.commitment);
    hash_optional(&mut hasher, current_state.as_deref());
    hash_optional(&mut hasher, committed_pending.as_deref());
    hash_optional(&mut hasher, active_pending.as_deref());
    hash_optional(&mut hasher, pending_status.as_deref());
    hash_optional(&mut hasher, transition_previous_state.as_deref());
    hash_optional(&mut hasher, encoded_expected.as_deref());
    hash_optional(&mut hasher, Some(&encoded_desired));
    Ok(hasher.finalize().into())
}

fn authority_floor(
    store_instance_id: &[u8; 16],
    provider_id: &ProviderId,
    revision: u64,
    phase: ProviderSettlementFloorPhaseV1,
    active: ActiveWorkflowCommitments,
    history: HistoryAnchor,
) -> Result<ProviderSettlementFloorV1, ProviderSettlementSqliteStoreErrorV1> {
    if revision == 0 {
        return Err(store_error(
            "provider settlement authority revision is zero",
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(ACTIVE_COMMITMENT_DOMAIN_V2);
    hasher.update(store_instance_id);
    hasher.update(provider_id);
    hasher.update(revision.to_le_bytes());
    hasher.update([phase_code(phase)]);
    hasher.update(history.length.to_le_bytes());
    hasher.update(history.commitment);
    for commitment in [
        active.current_state,
        active.committed_pending,
        active.active_pending,
        active.pending_status,
        active.transition_previous_state,
    ] {
        match commitment {
            None => hasher.update([0]),
            Some(value) => {
                hasher.update([1]);
                hasher.update(value);
            }
        }
    }
    Ok(ProviderSettlementFloorV1 {
        store_instance_id: *store_instance_id,
        provider_id: *provider_id,
        revision,
        active_commitment: hasher.finalize().into(),
        history_length: history.length,
        history_commitment: history.commitment,
        phase,
    })
}

fn phase_code(phase: ProviderSettlementFloorPhaseV1) -> u8 {
    match phase {
        ProviderSettlementFloorPhaseV1::Pending { .. } => 1,
        ProviderSettlementFloorPhaseV1::Payout { .. } => 2,
        ProviderSettlementFloorPhaseV1::StatusPending { .. } => 3,
    }
}

fn checked_next_revision(revision: u64) -> Result<u64, ProviderSettlementSqliteStoreErrorV1> {
    revision
        .checked_add(1)
        .ok_or_else(|| store_error("provider settlement authority revision overflow"))
}

fn read_workflow(
    connection: &Connection,
    expected_provider_id: &ProviderId,
) -> Result<DecodedWorkflow, ProviderSettlementSqliteStoreErrorV1> {
    type WorkflowLengths = (
        i64,
        i64,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
    );
    let lengths: WorkflowLengths = connection
        .query_row(
            "SELECT length(store_instance_id), length(provider_id), length(current_state), length(committed_pending), \
             length(active_pending), length(pending_status), length(transition_previous_state) \
             FROM workflow WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .map_err(sql_error)?;
    if lengths.0 != 16 || lengths.1 != 32 {
        return Err(store_error(
            "provider settlement store identity length is invalid",
        ));
    }
    for length in [lengths.2, lengths.3, lengths.4, lengths.5, lengths.6]
        .into_iter()
        .flatten()
    {
        validate_database_record_length(length)?;
    }
    type RawWorkflow = (
        Vec<u8>,
        Vec<u8>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        i64,
        i64,
    );
    let raw: RawWorkflow = connection
        .query_row(
            "SELECT store_instance_id, provider_id, current_state, committed_pending, active_pending, \
             pending_status, transition_previous_state, authority_revision, transition_kind \
             FROM workflow WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )
        .map_err(sql_error)?;
    let store_instance_id = fixed(raw.0, "invalid provider settlement store instance ID")?;
    if store_instance_id.iter().all(|byte| *byte == 0) {
        return Err(store_error("provider settlement store instance ID is zero"));
    }
    let provider_id: ProviderId = fixed(raw.1, "invalid provider settlement store provider ID")?;
    if &provider_id != expected_provider_id {
        return Err(store_error(
            "provider settlement store belongs to another provider",
        ));
    }
    let authority_revision = u64::try_from(raw.7)
        .map_err(|_| store_error("invalid provider settlement authority revision"))?;
    let transition_kind = u8::try_from(raw.8)
        .ok()
        .filter(|value| *value <= 4)
        .ok_or_else(|| store_error("invalid provider settlement transition kind"))?;
    let workflow = DecodedWorkflow {
        store_instance_id,
        current_state: raw
            .2
            .map(|bytes| decode_durable_state(&bounded_record(bytes)?))
            .transpose()?,
        committed_pending: raw
            .3
            .map(|bytes| decode_pending_payout(&bounded_record(bytes)?))
            .transpose()?,
        active_pending: raw
            .4
            .map(|bytes| decode_pending_payout(&bounded_record(bytes)?))
            .transpose()?,
        pending_status: raw
            .5
            .map(|bytes| decode_pending_status(&bounded_record(bytes)?))
            .transpose()?,
        transition_previous_state: raw
            .6
            .map(|bytes| decode_durable_state(&bounded_record(bytes)?))
            .transpose()?,
        authority_revision,
        transition_kind,
    };
    validate_workflow_shape(&workflow, expected_provider_id)?;
    Ok(workflow)
}

fn validate_workflow_shape(
    workflow: &DecodedWorkflow,
    provider_id: &ProviderId,
) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
    if let Some(pending) = workflow.committed_pending.as_ref() {
        validate_pending_payout(pending, provider_id)?;
    }
    if let Some(pending) = workflow.active_pending.as_ref() {
        validate_pending_payout(pending, provider_id)?;
    }
    if let Some(pending) = workflow.pending_status.as_ref() {
        validate_pending_status(pending, provider_id)?;
    }
    if let Some(state) = workflow.current_state.as_ref() {
        validate_durable_state(state)?;
    }
    if workflow.current_state.is_some() != workflow.committed_pending.is_some() {
        return Err(store_error(
            "provider settlement current state and committed origin are incomplete",
        ));
    }
    if let (Some(state), Some(origin)) = (
        workflow.current_state.as_ref(),
        workflow.committed_pending.as_ref(),
    ) {
        if state.rollback_floor.payout_request_digest() != &origin.payout_request_digest {
            return Err(store_error(
                "provider settlement state does not match its committed payout origin",
            ));
        }
    }

    match workflow.transition_kind {
        0 | 1 => {
            if workflow.transition_previous_state.is_some() {
                return Err(store_error(
                    "stable or pending-floor workflow retains a journal predecessor state",
                ));
            }
            if workflow.transition_kind == 1 && workflow.active_pending.is_none() {
                return Err(store_error(
                    "pending-floor transition is missing its payout",
                ));
            }
            if let Some(active) = workflow.active_pending.as_ref() {
                match active.predecessor_floor {
                    None => {
                        if workflow.current_state.is_some() || workflow.committed_pending.is_some()
                        {
                            return Err(store_error(
                                "first pending payout unexpectedly has predecessor state",
                            ));
                        }
                    }
                    Some(predecessor) => {
                        if !matches!(
                            predecessor.state(),
                            PayoutStateV1::Succeeded | PayoutStateV1::Failed
                        ) || workflow
                            .current_state
                            .as_ref()
                            .map_or(true, |state| state.rollback_floor != predecessor)
                            || workflow.committed_pending.is_none()
                        {
                            return Err(store_error(
                                "later pending payout does not match a terminal predecessor",
                            ));
                        }
                    }
                }
            }
            if let Some(pending_status) = workflow.pending_status.as_ref() {
                if workflow.active_pending.is_some()
                    || workflow.current_state.as_ref().map_or(true, |state| {
                        state.rollback_floor != pending_status.previous_floor
                            || provider_payout_durable_state_commitment_v1(state)
                                != Ok(pending_status.previous_state_commitment)
                    })
                {
                    return Err(store_error(
                        "pending payout status does not match current state",
                    ));
                }
            }
        }
        2 => {
            if workflow.transition_previous_state.is_some() {
                return Err(store_error(
                    "initial-payout transition retains an unexpected predecessor state",
                ));
            }
            let active = workflow.active_pending.as_ref().ok_or_else(|| {
                store_error("initial-payout transition is missing its pending payout")
            })?;
            let state = workflow.current_state.as_ref().ok_or_else(|| {
                store_error("initial-payout transition is missing its successor state")
            })?;
            if workflow.pending_status.is_some()
                || workflow.committed_pending.as_ref() != Some(active)
                || state.rollback_floor.payout_request_digest() != &active.payout_request_digest
                || state.rollback_floor.state() != PayoutStateV1::Accepted
                || state.rollback_floor.state_version() != 1
            {
                return Err(store_error("invalid initial-payout transition shape"));
            }
        }
        3 => {
            let pending = workflow
                .pending_status
                .as_ref()
                .ok_or_else(|| store_error("status-pending transition is missing its request"))?;
            let state = workflow
                .current_state
                .as_ref()
                .ok_or_else(|| store_error("status-pending transition is missing its state"))?;
            if workflow.active_pending.is_some()
                || workflow.committed_pending.is_none()
                || workflow.transition_previous_state.is_some()
                || pending.previous_floor != state.rollback_floor
                || provider_payout_durable_state_commitment_v1(state).map_err(protocol_error)?
                    != pending.previous_state_commitment
            {
                return Err(store_error("invalid status-pending transition shape"));
            }
        }
        4 => {
            let pending = workflow
                .pending_status
                .as_ref()
                .ok_or_else(|| store_error("status-commit transition is missing its request"))?;
            let state = workflow
                .current_state
                .as_ref()
                .ok_or_else(|| store_error("status-commit transition is missing its successor"))?;
            let previous = workflow.transition_previous_state.as_ref().ok_or_else(|| {
                store_error("status-commit transition is missing its predecessor state")
            })?;
            if workflow.active_pending.is_some()
                || workflow.committed_pending.is_none()
                || previous.rollback_floor != pending.previous_floor
                || provider_payout_durable_state_commitment_v1(previous).map_err(protocol_error)?
                    != pending.previous_state_commitment
                || !floor_is_satisfied(&pending.previous_floor, &state.rollback_floor)
            {
                return Err(store_error("invalid status-commit transition shape"));
            }
        }
        _ => return Err(store_error("invalid provider settlement transition kind")),
    }
    Ok(())
}

fn archive_current(
    transaction: &rusqlite::Transaction<'_>,
    committed: &ProviderPayoutPendingV1,
    current: &ProviderPayoutDurableStateV1,
) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
    let sequence: i64 = transaction
        .query_row(
            "SELECT COALESCE(MAX(sequence), 0) + 1 FROM payout_history",
            [],
            |row| row.get(0),
        )
        .map_err(sql_error)?;
    if sequence <= 0 {
        return Err(store_error("provider settlement history sequence overflow"));
    }
    transaction
        .execute(
            "INSERT INTO payout_history (sequence, committed_pending, durable_state) \
             VALUES (?1, ?2, ?3)",
            params![
                sequence,
                encode_pending_payout(committed)?,
                encode_durable_state(current)?
            ],
        )
        .map_err(sql_error)?;
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HistoryTail {
    pending: ProviderPayoutPendingV1,
    state: ProviderPayoutDurableStateV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HistoryAnchor {
    length: u64,
    commitment: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HistoryValidation {
    tail: Option<HistoryTail>,
    anchor: HistoryAnchor,
    before_tail: Option<HistoryAnchor>,
}

fn validate_history(
    connection: &Connection,
    store_instance_id: &[u8; 16],
    provider_id: &ProviderId,
) -> Result<HistoryValidation, ProviderSettlementSqliteStoreErrorV1> {
    let mut statement = connection
        .prepare(
            "SELECT sequence, length(committed_pending), length(durable_state) FROM payout_history \
             ORDER BY sequence",
        )
        .map_err(sql_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .map_err(sql_error)?;
    let mut metadata = Vec::new();
    for row in rows {
        metadata.push(row.map_err(sql_error)?);
    }
    drop(statement);
    let mut expected_sequence = 1_i64;
    let mut previous_floor = None;
    let mut tail = None;
    let mut anchor = initial_history_anchor(store_instance_id, provider_id);
    let mut before_tail = None;
    for (sequence, pending_len, state_len) in metadata {
        if sequence != expected_sequence {
            return Err(store_error(
                "provider settlement history sequence is not contiguous",
            ));
        }
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(|| store_error("provider settlement history sequence overflow"))?;
        validate_database_record_length(pending_len)?;
        validate_database_record_length(state_len)?;
        let (pending_raw, state_raw): (Vec<u8>, Vec<u8>) = connection
            .query_row(
                "SELECT committed_pending, durable_state FROM payout_history WHERE sequence = ?1",
                params![sequence],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(sql_error)?;
        let pending_raw = bounded_record(pending_raw)?;
        let state_raw = bounded_record(state_raw)?;
        let pending = decode_pending_payout(&pending_raw)?;
        let state = decode_durable_state(&state_raw)?;
        if encode_pending_payout(&pending)? != pending_raw
            || encode_durable_state(&state)? != state_raw
        {
            return Err(store_error(
                "provider settlement history contains a non-canonical exact record",
            ));
        }
        validate_pending_payout(&pending, provider_id)?;
        validate_durable_state(&state)?;
        if pending.predecessor_floor != previous_floor
            || state.rollback_floor.payout_request_digest() != &pending.payout_request_digest
            || !matches!(
                state.rollback_floor.state(),
                PayoutStateV1::Succeeded | PayoutStateV1::Failed
            )
        {
            return Err(store_error(
                "provider settlement history contains a non-terminal or mismatched payout",
            ));
        }
        previous_floor = Some(state.rollback_floor);
        before_tail = Some(anchor);
        let sequence_u64 = u64::try_from(sequence)
            .map_err(|_| store_error("provider settlement history sequence is negative"))?;
        anchor = append_history_anchor(
            store_instance_id,
            provider_id,
            anchor,
            sequence_u64,
            &pending_raw,
            &state_raw,
        )?;
        tail = Some(HistoryTail { pending, state });
    }
    Ok(HistoryValidation {
        tail,
        anchor,
        before_tail,
    })
}

fn validate_workflow_history_link(
    workflow: &DecodedWorkflow,
    history_tail: Option<&HistoryTail>,
) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
    match (
        history_tail,
        workflow.committed_pending.as_ref(),
        workflow.current_state.as_ref(),
    ) {
        (None, None, None) => Ok(()),
        (None, Some(origin), Some(_)) if origin.predecessor_floor.is_none() => Ok(()),
        (Some(_), None, None) => Err(store_error(
            "provider settlement history exists without a current payout",
        )),
        (Some(tail), Some(origin), Some(current))
            if tail.pending == *origin && tail.state == *current =>
        {
            if workflow.active_pending.is_none() {
                return Err(store_error(
                    "provider settlement current payout duplicates history without a successor",
                ));
            }
            Ok(())
        }
        (Some(tail), Some(origin), Some(_))
            if origin.predecessor_floor == Some(tail.state.rollback_floor) =>
        {
            Ok(())
        }
        _ => Err(store_error(
            "provider settlement current payout is not linked to terminal history",
        )),
    }
}

fn initial_history_anchor(store_instance_id: &[u8; 16], provider_id: &ProviderId) -> HistoryAnchor {
    let mut hasher = Sha256::new();
    hasher.update(HISTORY_INITIAL_DOMAIN_V2);
    hasher.update(store_instance_id);
    hasher.update(provider_id);
    HistoryAnchor {
        length: 0,
        commitment: hasher.finalize().into(),
    }
}

fn append_history_anchor(
    store_instance_id: &[u8; 16],
    provider_id: &ProviderId,
    previous: HistoryAnchor,
    sequence: u64,
    pending_raw: &[u8],
    state_raw: &[u8],
) -> Result<HistoryAnchor, ProviderSettlementSqliteStoreErrorV1> {
    let length = previous
        .length
        .checked_add(1)
        .ok_or_else(|| store_error("provider settlement history length overflow"))?;
    if sequence != length {
        return Err(store_error(
            "provider settlement history sequence does not match its anchor length",
        ));
    }
    let pending_len = u64::try_from(pending_raw.len())
        .map_err(|_| store_error("provider settlement history pending length overflows"))?;
    let state_len = u64::try_from(state_raw.len())
        .map_err(|_| store_error("provider settlement history state length overflows"))?;
    let mut hasher = Sha256::new();
    hasher.update(HISTORY_APPEND_DOMAIN_V2);
    hasher.update(store_instance_id);
    hasher.update(provider_id);
    hasher.update(previous.length.to_le_bytes());
    hasher.update(previous.commitment);
    hasher.update(sequence.to_le_bytes());
    hasher.update(pending_len.to_le_bytes());
    hasher.update(pending_raw);
    hasher.update(state_len.to_le_bytes());
    hasher.update(state_raw);
    Ok(HistoryAnchor {
        length,
        commitment: hasher.finalize().into(),
    })
}

fn validate_pending_payout(
    pending: &ProviderPayoutPendingV1,
    provider_id: &ProviderId,
) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
    validate_registration(&pending.registration, provider_id)?;
    validate_required_bytes(&pending.canonical_envelope, "pending payout envelope")?;
    validate_required_bytes(&pending.intent_request, "pending payout intent request")?;
    validate_required_bytes(&pending.intent_response, "pending payout intent response")?;
    if pending.payout_request_digest.iter().all(|byte| *byte == 0)
        || pending.idempotency_key.iter().all(|byte| *byte == 0)
    {
        return Err(store_error(
            "provider settlement pending payout has a zero digest or idempotency key",
        ));
    }
    let expected = pending_payout_floor_v1(
        &pending.canonical_envelope,
        &pending.payout_request_digest,
        &pending.idempotency_key,
        &pending.intent_request,
        &pending.intent_response,
        &pending.registration,
        pending.predecessor_floor.as_ref(),
    )
    .map_err(protocol_error)?;
    if expected != pending.pending_floor {
        return Err(store_error(
            "provider settlement pending payout digest binding is invalid",
        ));
    }
    Ok(())
}

fn validate_pending_status(
    pending: &ProviderPayoutStatusPendingV1,
    provider_id: &ProviderId,
) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
    validate_registration(&pending.registration, provider_id)?;
    validate_required_bytes(
        &pending.canonical_envelope,
        "pending payout status envelope",
    )?;
    if pending.request_digest.iter().all(|byte| *byte == 0)
        || pending
            .previous_state_commitment
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(store_error(
            "provider settlement pending status request or previous-state commitment is zero",
        ));
    }
    Ok(())
}

fn validate_durable_state(
    state: &ProviderPayoutDurableStateV1,
) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
    validate_required_bytes(&state.intent_request, "payout intent request")?;
    validate_required_bytes(&state.intent_response, "payout intent response")?;
    validate_required_bytes(&state.payout_request, "payout request")?;
    validate_required_bytes(&state.initial_payout_response, "initial payout response")?;
    if let Some(status) = state.latest_status_response.as_ref() {
        validate_required_bytes(status, "latest payout status response")?;
    }
    Ok(())
}

fn validate_registration(
    registration: &ProviderSettlementRegistrationV1,
    provider_id: &ProviderId,
) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
    if &registration.provider_id != provider_id
        || registration
            .registration_digest
            .iter()
            .all(|byte| *byte == 0)
        || registration.issuer_id.iter().all(|byte| *byte == 0)
        || registration
            .settlement_account_id
            .iter()
            .all(|byte| *byte == 0)
        || registration
            .provider_request_verifying_key
            .iter()
            .all(|byte| *byte == 0)
        || registration.payout_target_id.iter().all(|byte| *byte == 0)
        || registration.not_before == 0
        || registration.not_after <= registration.not_before
    {
        return Err(store_error(
            "provider settlement registration is invalid or belongs to another provider",
        ));
    }
    Ok(())
}

fn validate_required_bytes(
    bytes: &[u8],
    field: &'static str,
) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
    if bytes.is_empty() || bytes.len() > MAX_SHARED_ISSUER_RESPONSE_BYTES_V1 {
        return Err(store_error(format!(
            "{field} must be in 1..={MAX_SHARED_ISSUER_RESPONSE_BYTES_V1} bytes"
        )));
    }
    Ok(())
}

pub(crate) fn encode_authority_floor(floor: &ProviderSettlementFloorV1) -> Vec<u8> {
    let mut writer = RecordWriter::new(b"BPF2");
    writer.fixed(&floor.store_instance_id);
    writer.fixed(&floor.provider_id);
    writer.u64(floor.revision);
    writer.fixed(&floor.active_commitment);
    writer.u64(floor.history_length);
    writer.fixed(&floor.history_commitment);
    match floor.phase {
        ProviderSettlementFloorPhaseV1::Pending {
            pending,
            payout_request_digest,
        } => {
            writer.u8(1);
            writer.fixed(pending.pending_digest());
            writer.fixed(&payout_request_digest);
        }
        ProviderSettlementFloorPhaseV1::Payout { payout } => {
            writer.u8(2);
            encode_rollback_floor(&mut writer, &payout);
        }
        ProviderSettlementFloorPhaseV1::StatusPending { payout } => {
            writer.u8(3);
            encode_rollback_floor(&mut writer, &payout);
        }
    }
    writer.finish_unchecked()
}

pub(crate) fn decode_authority_floor(
    bytes: &[u8],
) -> Result<ProviderSettlementFloorV1, ProviderSettlementSqliteStoreErrorV1> {
    let mut reader = RecordReader::new(bytes, b"BPF2")?;
    let store_instance_id = reader.fixed()?;
    let provider_id = reader.fixed()?;
    let revision = reader.u64()?;
    let active_commitment = reader.fixed()?;
    let history_length = reader.u64()?;
    let history_commitment = reader.fixed()?;
    let phase = match reader.u8()? {
        1 => ProviderSettlementFloorPhaseV1::Pending {
            pending: ProviderPayoutPendingFloorV1::from_digest(reader.fixed()?)
                .map_err(protocol_error)?,
            payout_request_digest: reader.fixed()?,
        },
        2 => ProviderSettlementFloorPhaseV1::Payout {
            payout: decode_rollback_floor(&mut reader)?,
        },
        3 => ProviderSettlementFloorPhaseV1::StatusPending {
            payout: decode_rollback_floor(&mut reader)?,
        },
        _ => return Err(store_error("unknown provider settlement floor kind")),
    };
    reader.finish()?;
    let floor = ProviderSettlementFloorV1 {
        store_instance_id,
        provider_id,
        revision,
        active_commitment,
        history_length,
        history_commitment,
        phase,
    };
    validate_authority_floor(&floor)?;
    Ok(floor)
}

fn encode_pending_payout(
    pending: &ProviderPayoutPendingV1,
) -> Result<Vec<u8>, ProviderSettlementSqliteStoreErrorV1> {
    let mut writer = RecordWriter::new(b"BPP1");
    writer.bytes(&pending.canonical_envelope)?;
    writer.fixed(&pending.payout_request_digest);
    writer.fixed(&pending.idempotency_key);
    writer.bytes(&pending.intent_request)?;
    writer.bytes(&pending.intent_response)?;
    encode_registration(&mut writer, &pending.registration);
    match pending.predecessor_floor.as_ref() {
        None => writer.u8(0),
        Some(floor) => {
            writer.u8(1);
            encode_rollback_floor(&mut writer, floor);
        }
    }
    writer.fixed(pending.pending_floor.pending_digest());
    writer.finish()
}

fn decode_pending_payout(
    bytes: &[u8],
) -> Result<ProviderPayoutPendingV1, ProviderSettlementSqliteStoreErrorV1> {
    let mut reader = RecordReader::new(bytes, b"BPP1")?;
    let canonical_envelope = reader.bytes(MAX_SHARED_ISSUER_RESPONSE_BYTES_V1)?;
    let payout_request_digest = reader.fixed()?;
    let idempotency_key = reader.fixed()?;
    let intent_request = reader.bytes(MAX_SHARED_ISSUER_RESPONSE_BYTES_V1)?;
    let intent_response = reader.bytes(MAX_SHARED_ISSUER_RESPONSE_BYTES_V1)?;
    let registration = decode_registration(&mut reader)?;
    let predecessor_floor = match reader.u8()? {
        0 => None,
        1 => Some(decode_rollback_floor(&mut reader)?),
        _ => return Err(store_error("invalid pending payout predecessor tag")),
    };
    let pending_floor =
        ProviderPayoutPendingFloorV1::from_digest(reader.fixed()?).map_err(protocol_error)?;
    reader.finish()?;
    let pending = ProviderPayoutPendingV1 {
        canonical_envelope,
        payout_request_digest,
        idempotency_key,
        intent_request,
        intent_response,
        registration,
        predecessor_floor,
        pending_floor,
    };
    let expected = pending_payout_floor_v1(
        &pending.canonical_envelope,
        &pending.payout_request_digest,
        &pending.idempotency_key,
        &pending.intent_request,
        &pending.intent_response,
        &pending.registration,
        pending.predecessor_floor.as_ref(),
    )
    .map_err(protocol_error)?;
    if expected != pending.pending_floor {
        return Err(store_error(
            "decoded provider pending payout has an invalid floor digest",
        ));
    }
    Ok(pending)
}

fn encode_durable_state(
    state: &ProviderPayoutDurableStateV1,
) -> Result<Vec<u8>, ProviderSettlementSqliteStoreErrorV1> {
    let mut writer = RecordWriter::new(b"BPD1");
    writer.bytes(&state.intent_request)?;
    writer.bytes(&state.intent_response)?;
    writer.bytes(&state.payout_request)?;
    writer.bytes(&state.initial_payout_response)?;
    match state.latest_status_response.as_ref() {
        None => writer.u8(0),
        Some(status) => {
            writer.u8(1);
            writer.bytes(status)?;
        }
    }
    encode_rollback_floor(&mut writer, &state.rollback_floor);
    writer.finish()
}

fn decode_durable_state(
    bytes: &[u8],
) -> Result<ProviderPayoutDurableStateV1, ProviderSettlementSqliteStoreErrorV1> {
    let mut reader = RecordReader::new(bytes, b"BPD1")?;
    let intent_request = reader.bytes(MAX_SHARED_ISSUER_RESPONSE_BYTES_V1)?;
    let intent_response = reader.bytes(MAX_SHARED_ISSUER_RESPONSE_BYTES_V1)?;
    let payout_request = reader.bytes(MAX_SHARED_ISSUER_RESPONSE_BYTES_V1)?;
    let initial_payout_response = reader.bytes(MAX_SHARED_ISSUER_RESPONSE_BYTES_V1)?;
    let latest_status_response = match reader.u8()? {
        0 => None,
        1 => Some(reader.bytes(MAX_SHARED_ISSUER_RESPONSE_BYTES_V1)?),
        _ => return Err(store_error("invalid durable payout status tag")),
    };
    let rollback_floor = decode_rollback_floor(&mut reader)?;
    reader.finish()?;
    Ok(ProviderPayoutDurableStateV1 {
        intent_request,
        intent_response,
        payout_request,
        initial_payout_response,
        latest_status_response,
        rollback_floor,
    })
}

fn encode_pending_status(
    pending: &ProviderPayoutStatusPendingV1,
) -> Result<Vec<u8>, ProviderSettlementSqliteStoreErrorV1> {
    let mut writer = RecordWriter::new(b"BPS2");
    writer.bytes(&pending.canonical_envelope)?;
    writer.fixed(&pending.request_digest);
    encode_registration(&mut writer, &pending.registration);
    encode_rollback_floor(&mut writer, &pending.previous_floor);
    writer.fixed(&pending.previous_state_commitment);
    writer.finish()
}

fn decode_pending_status(
    bytes: &[u8],
) -> Result<ProviderPayoutStatusPendingV1, ProviderSettlementSqliteStoreErrorV1> {
    let mut reader = RecordReader::new(bytes, b"BPS2")?;
    let canonical_envelope = reader.bytes(MAX_SHARED_ISSUER_RESPONSE_BYTES_V1)?;
    let request_digest = reader.fixed()?;
    let registration = decode_registration(&mut reader)?;
    let previous_floor = decode_rollback_floor(&mut reader)?;
    let previous_state_commitment = reader.fixed()?;
    reader.finish()?;
    Ok(ProviderPayoutStatusPendingV1 {
        canonical_envelope,
        request_digest,
        registration,
        previous_floor,
        previous_state_commitment,
    })
}

fn encode_registration(writer: &mut RecordWriter, registration: &ProviderSettlementRegistrationV1) {
    writer.fixed(&registration.registration_digest);
    writer.fixed(&registration.provider_id);
    writer.fixed(&registration.issuer_id);
    writer.fixed(&registration.settlement_account_id);
    writer.fixed(&registration.provider_request_verifying_key);
    writer.fixed(&registration.payout_target_id);
    writer.u64(registration.not_before);
    writer.u64(registration.not_after);
}

fn decode_registration(
    reader: &mut RecordReader<'_>,
) -> Result<ProviderSettlementRegistrationV1, ProviderSettlementSqliteStoreErrorV1> {
    Ok(ProviderSettlementRegistrationV1 {
        registration_digest: reader.fixed()?,
        provider_id: reader.fixed()?,
        issuer_id: reader.fixed()?,
        settlement_account_id: reader.fixed()?,
        provider_request_verifying_key: reader.fixed()?,
        payout_target_id: reader.fixed()?,
        not_before: reader.u64()?,
        not_after: reader.u64()?,
    })
}

fn encode_rollback_floor(writer: &mut RecordWriter, floor: &ProviderPayoutRollbackFloorV1) {
    writer.fixed(floor.payout_id());
    writer.fixed(floor.payout_request_digest());
    writer.fixed(floor.ledger_transaction_id());
    writer.u8(floor.state() as u8);
    writer.u64(floor.state_version());
    writer.u64(floor.updated_at());
}

fn decode_rollback_floor(
    reader: &mut RecordReader<'_>,
) -> Result<ProviderPayoutRollbackFloorV1, ProviderSettlementSqliteStoreErrorV1> {
    ProviderPayoutRollbackFloorV1::from_parts(
        reader.fixed()?,
        reader.fixed()?,
        reader.fixed()?,
        decode_payout_state(reader.u8()?)?,
        reader.u64()?,
        reader.u64()?,
    )
    .map_err(protocol_error)
}

fn decode_payout_state(value: u8) -> Result<PayoutStateV1, ProviderSettlementSqliteStoreErrorV1> {
    match value {
        1 => Ok(PayoutStateV1::Accepted),
        2 => Ok(PayoutStateV1::InFlight),
        3 => Ok(PayoutStateV1::Succeeded),
        4 => Ok(PayoutStateV1::Failed),
        _ => Err(store_error("invalid provider payout state")),
    }
}

struct RecordWriter {
    bytes: Vec<u8>,
}

impl RecordWriter {
    fn new(magic: &[u8; 4]) -> Self {
        Self {
            bytes: magic.to_vec(),
        }
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn fixed(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
        let len = u32::try_from(value.len())
            .map_err(|_| store_error("provider settlement record field is too large"))?;
        self.bytes.extend_from_slice(&len.to_le_bytes());
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn finish(self) -> Result<Vec<u8>, ProviderSettlementSqliteStoreErrorV1> {
        if self.bytes.len() > MAX_STORED_RECORD_BYTES {
            return Err(store_error("provider settlement record is too large"));
        }
        Ok(self.bytes)
    }

    fn finish_unchecked(self) -> Vec<u8> {
        debug_assert!(self.bytes.len() <= 256);
        self.bytes
    }
}

struct RecordReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> RecordReader<'a> {
    fn new(bytes: &'a [u8], magic: &[u8; 4]) -> Result<Self, ProviderSettlementSqliteStoreErrorV1> {
        if bytes.len() > MAX_STORED_RECORD_BYTES || !bytes.starts_with(magic) {
            return Err(store_error(
                "provider settlement record magic or length is invalid",
            ));
        }
        Ok(Self { bytes, offset: 4 })
    }

    fn u8(&mut self) -> Result<u8, ProviderSettlementSqliteStoreErrorV1> {
        Ok(self.take(1)?[0])
    }

    fn u64(&mut self) -> Result<u64, ProviderSettlementSqliteStoreErrorV1> {
        Ok(u64::from_le_bytes(self.fixed()?))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], ProviderSettlementSqliteStoreErrorV1> {
        self.take(N)?
            .try_into()
            .map_err(|_| store_error("provider settlement fixed field has the wrong length"))
    }

    fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, ProviderSettlementSqliteStoreErrorV1> {
        let len = u32::from_le_bytes(self.fixed()?) as usize;
        if len > maximum {
            return Err(store_error(
                "provider settlement variable field exceeds its maximum",
            ));
        }
        Ok(self.take(len)?.to_vec())
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], ProviderSettlementSqliteStoreErrorV1> {
        let end = self
            .offset
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| store_error("provider settlement record is truncated"))?;
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn finish(self) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
        if self.offset != self.bytes.len() {
            return Err(store_error("provider settlement record has trailing bytes"));
        }
        Ok(())
    }
}

fn validate_initial_floor(
    initial: &ProviderSettlementFloorV1,
) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
    validate_authority_floor(initial)?;
    let initial_history = initial_history_anchor(&initial.store_instance_id, &initial.provider_id);
    if initial.revision == 1
        && initial.history_length == 0
        && initial.history_commitment == initial_history.commitment
        && matches!(
            initial.phase,
            ProviderSettlementFloorPhaseV1::Pending { .. }
        )
    {
        return Ok(());
    }
    Err(store_error(
        "provider settlement floor must initialize at revision one with an empty-history pending payout",
    ))
}

fn validate_authority_floor(
    floor: &ProviderSettlementFloorV1,
) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
    validate_provider_id(&floor.provider_id)?;
    if floor.store_instance_id.iter().all(|byte| *byte == 0)
        || floor.revision == 0
        || floor.revision > i64::MAX as u64
        || floor.active_commitment.iter().all(|byte| *byte == 0)
        || floor.history_commitment.iter().all(|byte| *byte == 0)
        || (floor.history_length == 0
            && floor.history_commitment
                != initial_history_anchor(&floor.store_instance_id, &floor.provider_id).commitment)
    {
        return Err(store_error(
            "provider settlement floor common binding is invalid",
        ));
    }
    match floor.phase {
        ProviderSettlementFloorPhaseV1::Pending {
            payout_request_digest,
            ..
        } => {
            if payout_request_digest.iter().all(|byte| *byte == 0) {
                return Err(store_error(
                    "provider settlement pending floor payout request digest is zero",
                ));
            }
        }
        ProviderSettlementFloorPhaseV1::Payout { payout }
        | ProviderSettlementFloorPhaseV1::StatusPending { payout } => {
            if payout.payout_id().iter().all(|byte| *byte == 0)
                || payout.payout_request_digest().iter().all(|byte| *byte == 0)
                || payout.ledger_transaction_id().iter().all(|byte| *byte == 0)
                || payout.state_version() == 0
                || payout.updated_at() == 0
            {
                return Err(store_error(
                    "provider settlement payout floor coordinates are invalid",
                ));
            }
        }
    }
    Ok(())
}

fn validate_floor_transition(
    expected: &ProviderSettlementFloorV1,
    next: &ProviderSettlementFloorV1,
) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
    validate_authority_floor(expected)?;
    validate_authority_floor(next)?;
    if expected.store_instance_id != next.store_instance_id
        || expected.provider_id != next.provider_id
        || checked_next_revision(expected.revision)? != next.revision
        || expected.active_commitment == next.active_commitment
    {
        return Err(store_error(
            "provider settlement floor successor has an invalid namespace or revision",
        ));
    }
    let same_history = expected.history_length == next.history_length
        && expected.history_commitment == next.history_commitment;
    let valid = match (expected.phase, next.phase) {
        (
            ProviderSettlementFloorPhaseV1::Pending {
                payout_request_digest,
                ..
            },
            ProviderSettlementFloorPhaseV1::Payout { payout },
        ) => {
            same_history
                && payout.payout_request_digest() == &payout_request_digest
                && payout.state() == PayoutStateV1::Accepted
                && payout.state_version() == 1
        }
        (
            ProviderSettlementFloorPhaseV1::Payout { payout },
            ProviderSettlementFloorPhaseV1::StatusPending {
                payout: next_payout,
            },
        ) => same_history && payout == next_payout,
        (
            ProviderSettlementFloorPhaseV1::StatusPending { payout },
            ProviderSettlementFloorPhaseV1::Payout {
                payout: next_payout,
            },
        ) => same_history && floor_is_satisfied(&payout, &next_payout),
        (
            ProviderSettlementFloorPhaseV1::Payout { payout },
            ProviderSettlementFloorPhaseV1::Pending { .. },
        ) => {
            matches!(
                payout.state(),
                PayoutStateV1::Succeeded | PayoutStateV1::Failed
            ) && expected
                .history_length
                .checked_add(1)
                .is_some_and(|length| length == next.history_length)
                && expected.history_commitment != next.history_commitment
        }
        _ => false,
    };
    if !valid {
        return Err(store_error(
            "provider settlement floor transition is not monotonic",
        ));
    }
    Ok(())
}

fn bounded_record(bytes: Vec<u8>) -> Result<Vec<u8>, ProviderSettlementSqliteStoreErrorV1> {
    if bytes.is_empty() || bytes.len() > MAX_STORED_RECORD_BYTES {
        return Err(store_error(
            "provider settlement database record is oversized",
        ));
    }
    Ok(bytes)
}

fn read_raw_floor(
    connection: &Connection,
) -> Result<Option<Vec<u8>>, ProviderSettlementSqliteStoreErrorV1> {
    let length = connection
        .query_row(
            "SELECT length(floor_value) FROM settlement_floor WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(sql_error)?;
    if let Some(length) = length {
        if !(1..=256).contains(&length) {
            return Err(store_error(
                "provider settlement floor database record is oversized",
            ));
        }
    } else {
        return Ok(None);
    }
    let raw = connection
        .query_row(
            "SELECT floor_value FROM settlement_floor WHERE singleton = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(sql_error)?;
    raw.map(bounded_record).transpose()
}

fn validate_database_record_length(
    length: i64,
) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
    let maximum = i64::try_from(MAX_STORED_RECORD_BYTES)
        .expect("provider settlement record maximum fits SQLite INTEGER");
    if !(1..=maximum).contains(&length) {
        return Err(store_error(
            "provider settlement database record is oversized",
        ));
    }
    Ok(())
}

fn configure(
    connection: &Connection,
    busy_timeout: Duration,
) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
    connection.busy_timeout(busy_timeout).map_err(sql_error)?;
    connection
        .execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA synchronous=FULL; \
             PRAGMA journal_mode=WAL; PRAGMA temp_store=MEMORY;",
        )
        .map_err(sql_error)?;
    let foreign_keys: i64 = connection
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .map_err(sql_error)?;
    let trusted_schema: i64 = connection
        .pragma_query_value(None, "trusted_schema", |row| row.get(0))
        .map_err(sql_error)?;
    let synchronous: i64 = connection
        .pragma_query_value(None, "synchronous", |row| row.get(0))
        .map_err(sql_error)?;
    let journal_mode: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(sql_error)?;
    if foreign_keys != 1
        || trusted_schema != 0
        || synchronous != 2
        || !journal_mode.eq_ignore_ascii_case("wal")
    {
        return Err(store_error(
            "provider settlement SQLite safety pragmas were not applied",
        ));
    }
    Ok(())
}

fn set_schema_identity(
    connection: &Connection,
    application_id: i32,
    schema_version: u32,
) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
    connection
        .pragma_update(None, "application_id", application_id)
        .map_err(sql_error)?;
    connection
        .pragma_update(None, "user_version", schema_version)
        .map_err(sql_error)?;
    Ok(())
}

fn verify_schema_identity(
    connection: &Connection,
    expected_application_id: i32,
    expected_schema_version: u32,
    kind: &'static str,
) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
    let application_id: i32 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(sql_error)?;
    let schema_version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(sql_error)?;
    if application_id != expected_application_id || schema_version != expected_schema_version {
        return Err(store_error(format!("{kind} schema identity mismatch")));
    }
    Ok(())
}

fn verify_integrity(
    connection: &Connection,
    kind: &'static str,
) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
    let integrity: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(sql_error)?;
    if integrity != "ok" {
        return Err(store_error(format!("{kind} integrity check failed")));
    }
    Ok(())
}

fn verify_store_schema(
    connection: &Connection,
) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
    verify_user_schema_objects(connection, &["payout_history", "workflow"], STORE_SCHEMA)?;
    verify_table(
        connection,
        "workflow",
        &[
            ("singleton", "INTEGER", true, true),
            ("store_instance_id", "BLOB", true, false),
            ("provider_id", "BLOB", true, false),
            ("current_state", "BLOB", false, false),
            ("committed_pending", "BLOB", false, false),
            ("active_pending", "BLOB", false, false),
            ("pending_status", "BLOB", false, false),
            ("transition_previous_state", "BLOB", false, false),
            ("authority_revision", "INTEGER", true, false),
            ("transition_kind", "INTEGER", true, false),
        ],
    )?;
    verify_table(
        connection,
        "payout_history",
        &[
            ("sequence", "INTEGER", true, true),
            ("committed_pending", "BLOB", true, false),
            ("durable_state", "BLOB", true, false),
        ],
    )
}

fn verify_floor_schema(
    connection: &Connection,
) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
    verify_user_schema_objects(connection, &["settlement_floor"], FLOOR_SCHEMA)?;
    verify_table(
        connection,
        "settlement_floor",
        &[
            ("singleton", "INTEGER", true, true),
            ("floor_value", "BLOB", true, false),
        ],
    )
}

fn verify_user_schema_objects(
    connection: &Connection,
    expected_tables: &[&str],
    expected_schema: &str,
) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
    let mut statement = connection
        .prepare(
            "SELECT type, name, sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' \
             ORDER BY type, name",
        )
        .map_err(sql_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })
        .map_err(sql_error)?;
    let mut actual = Vec::new();
    for row in rows {
        actual.push(row.map_err(sql_error)?);
    }
    let expected: Vec<(String, String)> = expected_tables
        .iter()
        .map(|name| ("table".to_owned(), (*name).to_owned()))
        .collect();
    let actual_identity: Vec<(String, String)> = actual
        .iter()
        .map(|(kind, name, _)| (kind.clone(), name.clone()))
        .collect();
    if actual_identity != expected {
        return Err(store_error(
            "provider settlement SQLite schema objects do not match v2",
        ));
    }
    let mut actual_sql: Vec<String> = actual
        .into_iter()
        .map(|(_, _, sql)| {
            sql.map(|value| normalize_schema_sql(&value))
                .ok_or_else(|| store_error("provider settlement SQLite schema object has no SQL"))
        })
        .collect::<Result<_, _>>()?;
    let mut expected_sql: Vec<String> = expected_schema
        .split(';')
        .map(str::trim)
        .filter(|statement| !statement.is_empty())
        .map(normalize_schema_sql)
        .collect();
    actual_sql.sort();
    expected_sql.sort();
    if actual_sql != expected_sql {
        return Err(store_error(
            "provider settlement SQLite schema definitions do not match v2",
        ));
    }
    Ok(())
}

fn normalize_schema_sql(sql: &str) -> String {
    sql.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn verify_table(
    connection: &Connection,
    table: &'static str,
    expected_columns: &[(&str, &str, bool, bool)],
) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
    let sql = format!("PRAGMA table_xinfo({table})");
    let mut statement = connection.prepare(&sql).map_err(sql_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })
        .map_err(sql_error)?;
    let mut actual = Vec::new();
    for row in rows {
        actual.push(row.map_err(sql_error)?);
    }
    let expected: Vec<(String, String, i64, i64, i64)> = expected_columns
        .iter()
        .map(|(name, kind, not_null, primary)| {
            (
                (*name).to_owned(),
                (*kind).to_owned(),
                if *not_null { 1 } else { 0 },
                if *primary { 1 } else { 0 },
                0,
            )
        })
        .collect();
    if actual != expected {
        return Err(store_error(format!(
            "provider settlement SQLite table {table} does not match v2"
        )));
    }
    let flags: (i64, i64) = connection
        .query_row(
            "SELECT wr, strict FROM pragma_table_list WHERE schema = 'main' AND name = ?1",
            params![table],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sql_error)?;
    if flags != (1, 1) {
        return Err(store_error(format!(
            "provider settlement SQLite table {table} is not STRICT WITHOUT ROWID"
        )));
    }
    Ok(())
}

fn validate_provider_id(
    provider_id: &ProviderId,
) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
    if provider_id.iter().all(|byte| *byte == 0) {
        return Err(store_error("provider settlement provider ID is zero"));
    }
    Ok(())
}

fn validate_timeout(
    timeout: Duration,
    kind: &'static str,
) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
    if timeout.is_zero() || timeout > Duration::from_secs(60) {
        return Err(store_error(format!(
            "{kind} busy timeout must be in 1ms..=60s"
        )));
    }
    Ok(())
}

fn create_empty_regular_file(
    path: &Path,
    kind: &'static str,
) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
    if path.as_os_str().is_empty() {
        return Err(store_error(format!("{kind} path is empty")));
    }
    let canonical_path =
        pir_private_files::prepare_new_private_file_v1(path, false, kind).map_err(store_error)?;
    let file = pir_private_files::create_new_private_file_v1(&canonical_path, kind)
        .map_err(store_error)?;
    file.sync_all().map_err(io_error)?;
    drop(file);
    pir_private_files::checked_existing_private_file_v1(
        &canonical_path,
        pir_private_files::PrivateFileModeV1::ReadWrite,
        kind,
    )
    .map_err(store_error)?;
    sync_parent(&canonical_path)?;
    Ok(())
}

fn open_existing_regular_file(
    path: &Path,
    kind: &'static str,
) -> Result<Connection, ProviderSettlementSqliteStoreErrorV1> {
    let checked = pir_private_files::checked_existing_private_file_v1(
        path,
        pir_private_files::PrivateFileModeV1::ReadWrite,
        kind,
    )
    .map_err(store_error)?;
    let connection = Connection::open_with_flags(
        checked.path(),
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(sql_error)?;
    let after = pir_private_files::checked_existing_private_file_v1(
        checked.path(),
        pir_private_files::PrivateFileModeV1::ReadWrite,
        kind,
    )
    .map_err(store_error)?;
    if after.identity() != checked.identity() {
        return Err(store_error(format!("{kind} changed while opening")));
    }
    Ok(connection)
}

fn checkpoint_and_sync(
    connection: &Connection,
    path: &Path,
    _kind: &'static str,
) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(sql_error)?;
    OpenOptions::new()
        .read(true)
        .open(path)
        .and_then(|file| file.sync_all())
        .map_err(io_error)?;
    sync_parent(path)
}

fn sync_parent(path: &Path) -> Result<(), ProviderSettlementSqliteStoreErrorV1> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(io_error)
}

fn fixed<const N: usize>(
    bytes: Vec<u8>,
    reason: &'static str,
) -> Result<[u8; N], ProviderSettlementSqliteStoreErrorV1> {
    bytes.try_into().map_err(|_| store_error(reason))
}

fn store_error(reason: impl Into<String>) -> ProviderSettlementSqliteStoreErrorV1 {
    ProviderSettlementSqliteStoreErrorV1 {
        reason: reason.into(),
    }
}

fn floor_error(reason: impl Into<String>) -> ProviderSettlementFloorAuthorityErrorV1 {
    ProviderSettlementFloorAuthorityErrorV1::new(reason)
}

fn floor_error_from_store(
    error: ProviderSettlementSqliteStoreErrorV1,
) -> ProviderSettlementFloorAuthorityErrorV1 {
    floor_error(error.to_string())
}

fn authority_error(error: impl core::fmt::Display) -> ProviderSettlementSqliteStoreErrorV1 {
    store_error(format!(
        "provider settlement floor authority unavailable: {error}"
    ))
}

fn protocol_error(error: ServiceProtocolError) -> ProviderSettlementSqliteStoreErrorV1 {
    store_error(format!(
        "provider settlement persisted protocol value is invalid: {error}"
    ))
}

fn sql_error(error: rusqlite::Error) -> ProviderSettlementSqliteStoreErrorV1 {
    store_error(format!("provider settlement SQLite error: {error}"))
}

fn floor_sql_error(error: rusqlite::Error) -> ProviderSettlementFloorAuthorityErrorV1 {
    floor_error(format!("provider settlement floor SQLite error: {error}"))
}

fn io_error(error: std::io::Error) -> ProviderSettlementSqliteStoreErrorV1 {
    store_error(format!("provider settlement I/O error: {error}"))
}

// Keep the store-level adversarial tests concise while the public trait accepts
// only client-created verified wrappers. These helpers exist only in test
// builds and cannot reintroduce an unauthenticated production write path.
#[cfg(test)]
impl<A> SqliteProviderSettlementStateStoreV1<A>
where
    A: ProviderSettlementFloorAuthorityV1,
{
    fn persist_pending_payout_for_test(
        &mut self,
        pending: &ProviderPayoutPendingV1,
    ) -> Result<bool, ProviderSettlementSqliteStoreErrorV1> {
        ProviderSettlementStateStoreV1::persist_pending_payout(
            self,
            &VerifiedProviderPayoutPendingWriteV1 {
                pending: pending.clone(),
            },
        )
    }

    fn commit_initial_payout_for_test(
        &mut self,
        pending: &ProviderPayoutPendingV1,
        state: &ProviderPayoutDurableStateV1,
    ) -> Result<bool, ProviderSettlementSqliteStoreErrorV1> {
        ProviderSettlementStateStoreV1::commit_initial_payout_from_pending(
            self,
            &VerifiedProviderPayoutInitialWriteV1 {
                pending: pending.clone(),
                state: state.clone(),
            },
        )
    }

    fn persist_pending_status_for_test(
        &mut self,
        pending: &ProviderPayoutStatusPendingV1,
    ) -> Result<bool, ProviderSettlementSqliteStoreErrorV1> {
        ProviderSettlementStateStoreV1::persist_pending_status(
            self,
            &VerifiedProviderPayoutStatusPendingWriteV1 {
                pending: pending.clone(),
            },
        )
    }

    fn commit_status_update_for_test(
        &mut self,
        pending: &ProviderPayoutStatusPendingV1,
        state: &ProviderPayoutDurableStateV1,
    ) -> Result<bool, ProviderSettlementSqliteStoreErrorV1> {
        ProviderSettlementStateStoreV1::commit_status_update(
            self,
            &VerifiedProviderPayoutStatusWriteV1 {
                pending: pending.clone(),
                state: state.clone(),
            },
        )
    }
}

#[cfg(all(test, unix))]
mod v2_tests {
    use super::*;

    use std::sync::{Condvar, Mutex};

    use tempfile::tempdir;

    const PROVIDER: ProviderId = [0x31; 32];

    fn timeout() -> Duration {
        Duration::from_secs(2)
    }

    fn private_tempdir() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn registration() -> ProviderSettlementRegistrationV1 {
        ProviderSettlementRegistrationV1 {
            registration_digest: [0x41; 32],
            provider_id: PROVIDER,
            issuer_id: [0x42; 32],
            settlement_account_id: [0x43; 32],
            provider_request_verifying_key: [0x44; 32],
            payout_target_id: [0x45; 32],
            not_before: 1_000,
            not_after: 2_000,
        }
    }

    fn rollback_floor(
        marker: u8,
        version: u64,
        state: PayoutStateV1,
    ) -> ProviderPayoutRollbackFloorV1 {
        ProviderPayoutRollbackFloorV1::from_parts(
            [marker.wrapping_add(20); 32],
            [marker; 32],
            [marker.wrapping_add(21); 32],
            state,
            version,
            1_000 + version,
        )
        .unwrap()
    }

    fn pending_payout(
        marker: u8,
        predecessor: Option<ProviderPayoutRollbackFloorV1>,
    ) -> ProviderPayoutPendingV1 {
        let mut pending = ProviderPayoutPendingV1 {
            canonical_envelope: vec![marker, 1],
            payout_request_digest: [marker; 32],
            idempotency_key: [marker.wrapping_add(1); 32],
            intent_request: vec![marker, 2],
            intent_response: vec![marker, 3],
            registration: registration(),
            predecessor_floor: predecessor,
            pending_floor: ProviderPayoutPendingFloorV1::from_digest([1; 32]).unwrap(),
        };
        pending.pending_floor = pending_payout_floor_v1(
            &pending.canonical_envelope,
            &pending.payout_request_digest,
            &pending.idempotency_key,
            &pending.intent_request,
            &pending.intent_response,
            &pending.registration,
            pending.predecessor_floor.as_ref(),
        )
        .unwrap();
        pending
    }

    fn durable_state(
        marker: u8,
        version: u64,
        state: PayoutStateV1,
    ) -> ProviderPayoutDurableStateV1 {
        ProviderPayoutDurableStateV1 {
            intent_request: vec![marker, 2],
            intent_response: vec![marker, 3],
            payout_request: vec![marker, 4],
            initial_payout_response: vec![marker, 5],
            latest_status_response: (version > 1).then(|| vec![marker, 6, version as u8]),
            rollback_floor: rollback_floor(marker, version, state),
        }
    }

    fn pending_status(
        marker: u8,
        previous: &ProviderPayoutDurableStateV1,
    ) -> ProviderPayoutStatusPendingV1 {
        ProviderPayoutStatusPendingV1 {
            canonical_envelope: vec![marker, 7],
            request_digest: [marker; 32],
            registration: registration(),
            previous_floor: previous.rollback_floor,
            previous_state_commitment: provider_payout_durable_state_commitment_v1(previous)
                .unwrap(),
        }
    }

    type LocalStore =
        SqliteProviderSettlementStateStoreV1<LocalTestSqliteProviderSettlementFloorV1>;

    #[derive(Debug, Default)]
    struct LoadGate {
        armed: bool,
        entered: bool,
        released: bool,
    }

    #[derive(Debug)]
    struct BlockingLoadAuthority {
        inner: LocalTestSqliteProviderSettlementFloorV1,
        gate: Mutex<LoadGate>,
        changed: Condvar,
    }

    impl BlockingLoadAuthority {
        fn new(inner: LocalTestSqliteProviderSettlementFloorV1) -> Self {
            Self {
                inner,
                gate: Mutex::new(LoadGate::default()),
                changed: Condvar::new(),
            }
        }

        fn arm(&self) {
            let mut gate = self.gate.lock().unwrap();
            *gate = LoadGate {
                armed: true,
                entered: false,
                released: false,
            };
        }

        fn wait_until_entered(&self) {
            let mut gate = self.gate.lock().unwrap();
            while !gate.entered {
                gate = self.changed.wait(gate).unwrap();
            }
        }

        fn release(&self) {
            let mut gate = self.gate.lock().unwrap();
            gate.released = true;
            self.changed.notify_all();
        }
    }

    impl ProviderSettlementFloorAuthorityV1 for BlockingLoadAuthority {
        type Error = ProviderSettlementFloorAuthorityErrorV1;

        fn load(&self) -> Result<Option<ProviderSettlementFloorV1>, Self::Error> {
            {
                let mut gate = self.gate.lock().unwrap();
                if gate.armed {
                    gate.entered = true;
                    self.changed.notify_all();
                    while !gate.released {
                        gate = self.changed.wait(gate).unwrap();
                    }
                    gate.armed = false;
                }
            }
            self.inner.load()
        }

        fn apply(
            &self,
            transition: &AuthenticatedProviderSettlementFloorTransitionV1,
        ) -> Result<ProviderSettlementFloorV1, Self::Error> {
            self.inner.apply(transition)
        }
    }

    fn local_pair(
        directory: &Path,
    ) -> (
        PathBuf,
        Arc<LocalTestSqliteProviderSettlementFloorV1>,
        LocalStore,
    ) {
        let authority = Arc::new(
            LocalTestSqliteProviderSettlementFloorV1::create(
                directory.join("floor.sqlite"),
                timeout(),
            )
            .unwrap(),
        );
        let state_path = directory.join("state.sqlite");
        let store =
            LocalStore::create(&state_path, PROVIDER, authority.clone(), timeout()).unwrap();
        (state_path, authority, store)
    }

    fn verified_from(
        inspection: &UnverifiedProviderSettlementRecoveryV2,
    ) -> VerifiedProviderSettlementRecoveryV2 {
        VerifiedProviderSettlementRecoveryV2 {
            snapshot_digest: inspection.snapshot_digest,
            transition_kind: inspection.transition_kind,
            expected_floor: inspection.expected_floor,
            desired_floor: inspection.desired_floor,
        }
    }

    #[test]
    fn stable_reads_do_not_mix_a_concurrent_journal_with_an_older_authority_floor() {
        for inspect in [false, true] {
            let directory = private_tempdir();
            let inner = LocalTestSqliteProviderSettlementFloorV1::create(
                directory.path().join("floor.sqlite"),
                timeout(),
            )
            .unwrap();
            let authority = Arc::new(BlockingLoadAuthority::new(inner));
            let state_path = directory.path().join("state.sqlite");
            let store = SqliteProviderSettlementStateStoreV1::create(
                &state_path,
                PROVIDER,
                authority.clone(),
                timeout(),
            )
            .unwrap();

            authority.arm();
            let reader = std::thread::spawn(move || {
                let stable = if inspect {
                    store.inspect_recovery().map(|value| value.is_none())
                } else {
                    store.load_recovery().map(|value| {
                        value.active_pending_payout.is_none()
                            && value.committed_payout_origin.is_none()
                            && value.payout_state.is_none()
                            && value.pending_status.is_none()
                    })
                };
                (store, stable)
            });
            authority.wait_until_entered();

            let pending = pending_payout(0x6a, None);
            Connection::open(&state_path)
                .unwrap()
                .execute(
                    "UPDATE workflow SET active_pending = ?1, transition_kind = 1 \
                     WHERE singleton = 1",
                    params![encode_pending_payout(&pending).unwrap()],
                )
                .unwrap();
            authority.release();

            let (store, stable) = reader.join().unwrap();
            assert!(stable.unwrap());
            assert!(store.inspect_recovery().unwrap().is_some());
        }
    }

    #[test]
    fn stable_workflow_uses_distinct_status_pending_phase_and_exact_state_commitment() {
        let directory = private_tempdir();
        let (state_path, authority, mut store) = local_pair(directory.path());
        let pending = pending_payout(0x51, None);
        assert!(store.persist_pending_payout_for_test(&pending).unwrap());
        let pending_floor = authority.load().unwrap().unwrap();
        assert_eq!(pending_floor.revision(), 1);
        assert!(matches!(
            pending_floor.phase(),
            ProviderSettlementFloorPhaseV1::Pending { .. }
        ));

        let initial = durable_state(0x51, 1, PayoutStateV1::Accepted);
        assert!(store
            .commit_initial_payout_for_test(&pending, &initial)
            .unwrap());
        let payout_floor = authority.load().unwrap().unwrap();
        assert_eq!(payout_floor.revision(), 2);
        assert!(matches!(
            payout_floor.phase(),
            ProviderSettlementFloorPhaseV1::Payout { .. }
        ));

        let status = pending_status(0x61, &initial);
        assert!(store.persist_pending_status_for_test(&status).unwrap());
        let status_floor = authority.load().unwrap().unwrap();
        assert_eq!(status_floor.revision(), 3);
        assert!(matches!(
            status_floor.phase(),
            ProviderSettlementFloorPhaseV1::StatusPending { .. }
        ));

        let successor = durable_state(0x51, 2, PayoutStateV1::InFlight);
        assert!(store
            .commit_status_update_for_test(&status, &successor)
            .unwrap());
        let successor_floor = authority.load().unwrap().unwrap();
        assert_eq!(successor_floor.revision(), 4);
        assert!(matches!(
            successor_floor.phase(),
            ProviderSettlementFloorPhaseV1::Payout { payout }
                if payout == successor.rollback_floor
        ));
        drop(store);

        let reopened =
            LocalStore::open_existing(&state_path, PROVIDER, authority, timeout()).unwrap();
        assert_eq!(
            reopened.load_recovery().unwrap().payout_state,
            Some(successor)
        );
    }

    #[test]
    fn open_is_pure_read_and_recovery_requires_an_authenticated_token() {
        for authority_already_advanced in [false, true] {
            let directory = private_tempdir();
            let (state_path, authority, store) = local_pair(directory.path());
            let pending = pending_payout(
                if authority_already_advanced {
                    0x63
                } else {
                    0x62
                },
                None,
            );
            Connection::open(&state_path)
                .unwrap()
                .execute(
                    "UPDATE workflow SET active_pending = ?1, transition_kind = 1 \
                     WHERE singleton = 1",
                    params![encode_pending_payout(&pending).unwrap()],
                )
                .unwrap();
            let inspection = store.inspect_recovery().unwrap().unwrap();
            if authority_already_advanced {
                let transition = AuthenticatedProviderSettlementFloorTransitionV1 {
                    expected: inspection.expected_floor,
                    next: inspection.desired_floor,
                };
                assert_eq!(
                    authority.apply(&transition).unwrap(),
                    inspection.desired_floor
                );
            }
            let authority_before_open = authority.load().unwrap();
            drop(store);

            let reopened =
                LocalStore::open_existing(&state_path, PROVIDER, authority.clone(), timeout())
                    .unwrap();
            assert_eq!(authority.load().unwrap(), authority_before_open);
            assert!(reopened
                .load_recovery()
                .unwrap_err()
                .to_string()
                .contains("recovery is required"));
            let reopened_inspection = reopened.inspect_recovery().unwrap().unwrap();
            let transition_kind: i64 = Connection::open(&state_path)
                .unwrap()
                .query_row(
                    "SELECT transition_kind FROM workflow WHERE singleton = 1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(transition_kind, 1);

            let recovered = reopened
                .resume_recovery(&verified_from(&reopened_inspection))
                .unwrap();
            assert_eq!(recovered.active_pending_payout, Some(pending));
            assert_eq!(
                authority.load().unwrap(),
                Some(reopened_inspection.desired_floor)
            );
        }
    }

    #[test]
    fn stale_recovery_token_cannot_advance_authority_after_exact_record_tamper() {
        let directory = private_tempdir();
        let (state_path, authority, store) = local_pair(directory.path());
        let pending = pending_payout(0x71, None);
        Connection::open(&state_path)
            .unwrap()
            .execute(
                "UPDATE workflow SET active_pending = ?1, transition_kind = 1 \
                 WHERE singleton = 1",
                params![encode_pending_payout(&pending).unwrap()],
            )
            .unwrap();
        let inspection = store.inspect_recovery().unwrap().unwrap();
        let verified = verified_from(&inspection);
        let replacement = pending_payout(0x72, None);
        Connection::open(&state_path)
            .unwrap()
            .execute(
                "UPDATE workflow SET active_pending = ?1 WHERE singleton = 1",
                params![encode_pending_payout(&replacement).unwrap()],
            )
            .unwrap();

        let error = store.resume_recovery(&verified).unwrap_err();
        assert!(error
            .to_string()
            .contains("does not match the exact journal snapshot"));
        assert_eq!(authority.load().unwrap(), None);
    }

    #[test]
    fn schema_v1_is_rejected_without_implicit_migration() {
        let directory = private_tempdir();
        let (state_path, authority, store) = local_pair(directory.path());
        drop(store);
        Connection::open(&state_path)
            .unwrap()
            .pragma_update(None, "user_version", 1_u32)
            .unwrap();
        let error =
            LocalStore::open_existing(&state_path, PROVIDER, authority, timeout()).unwrap_err();
        assert!(error.to_string().contains("schema identity mismatch"));
    }

    #[cfg(unix)]
    #[test]
    fn detailed_state_hardlinks_fail_closed() {
        let directory = private_tempdir();
        let (state_path, authority, store) = local_pair(directory.path());
        drop(store);
        let hardlink = directory.path().join("provider-state-hardlink.sqlite3");
        std::fs::hard_link(&state_path, &hardlink).unwrap();
        let original = std::fs::read(&state_path).unwrap();

        for path in [&state_path, &hardlink] {
            LocalStore::open_existing(path, PROVIDER, authority.clone(), timeout()).unwrap_err();
        }
        assert_eq!(std::fs::read(&state_path).unwrap(), original);
        assert_eq!(std::fs::read(&hardlink).unwrap(), original);
    }
}
