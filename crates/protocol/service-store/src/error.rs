use crate::SpendReadBack;
use std::fmt;
use std::io;
use std::path::PathBuf;

/// Fail-closed provider-store errors.
#[derive(Debug)]
pub enum StoreError {
    InvalidInput(&'static str),
    MissingDatabase(PathBuf),
    NotRegularDatabase(PathBuf),
    SchemaMismatch(String),
    IntegrityCheckFailed(String),
    ProviderMismatch,
    RollbackFloorMissing,
    RollbackFloorIdentityMismatch,
    RollbackDetected {
        database_generation: u64,
        authority_generation: u64,
    },
    RollbackFork,
    RollbackAuthorityProtocol(String),
    RollbackAuthorityUnavailable(String),
    /// SQLite committed, but the independently durable rollback anchor could
    /// not be confirmed. No authorization or successful mutation response may
    /// be returned to the caller.
    UnanchoredCommit {
        store_generation: u64,
        authority_error: String,
    },
    NamespaceMissing,
    NamespaceClosed,
    NamespaceExpired,
    NamespaceConflict,
    ExclusiveKeyLineageConflict,
    AlreadySpent,
    StoreGenerationExhausted,
    SpendSequenceExhausted,
    PolicyRollback,
    PolicyFork,
    CredentialFloorRollback,
    CashuFloorRollback,
    CashuSwapIntentMissing,
    CashuSwapIntentConflict,
    CashuSwapStateConflict,
    FreeIpQuotaExhausted,
    FreeIpClockRollback,
    ServiceProtocol(pir_service_protocol::ServiceProtocolError),
    /// SQLite returned an error from `COMMIT`. Read-back is diagnostic only;
    /// the connection which attempted this spend must be closed without a
    /// grant even when the key is observed as present.
    InternalAfterSpend {
        read_back: SpendReadBack,
        database_error: String,
    },
    Io(io::Error),
    Sqlite(rusqlite::Error),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(reason) => write!(f, "invalid provider-store input: {reason}"),
            Self::MissingDatabase(path) => {
                write!(f, "provider database does not exist: {}", path.display())
            }
            Self::NotRegularDatabase(path) => write!(
                f,
                "provider database is not a regular non-symlink file: {}",
                path.display()
            ),
            Self::SchemaMismatch(reason) => write!(f, "provider database schema mismatch: {reason}"),
            Self::IntegrityCheckFailed(reason) => {
                write!(f, "provider database integrity check failed: {reason}")
            }
            Self::ProviderMismatch => write!(f, "provider database identity mismatch"),
            Self::RollbackFloorMissing => write!(
                f,
                "independently durable provider rollback floor is missing"
            ),
            Self::RollbackFloorIdentityMismatch => write!(
                f,
                "provider rollback floor belongs to a different store identity"
            ),
            Self::RollbackDetected {
                database_generation,
                authority_generation,
            } => write!(
                f,
                "provider database rollback detected (database generation {database_generation}, authority floor {authority_generation})"
            ),
            Self::RollbackFork => write!(
                f,
                "provider database and rollback authority contain conflicting state at one generation"
            ),
            Self::RollbackAuthorityProtocol(reason) => {
                write!(f, "provider rollback authority contract violation: {reason}")
            }
            Self::RollbackAuthorityUnavailable(reason) => {
                write!(f, "provider rollback authority unavailable: {reason}")
            }
            Self::UnanchoredCommit {
                store_generation,
                authority_error,
            } => write!(
                f,
                "provider-store generation {store_generation} committed but is not externally anchored: {authority_error}"
            ),
            Self::NamespaceMissing => write!(f, "spend namespace is missing"),
            Self::NamespaceClosed => write!(f, "spend namespace is closed"),
            Self::NamespaceExpired => write!(f, "spend namespace is expired"),
            Self::NamespaceConflict => write!(f, "spend namespace conflicts with durable state"),
            Self::ExclusiveKeyLineageConflict => write!(
                f,
                "raw cryptographic key conflicts with its durable exclusive lineage"
            ),
            Self::AlreadySpent => write!(f, "capability was already spent"),
            Self::StoreGenerationExhausted => {
                write!(f, "provider-store generation is exhausted")
            }
            Self::SpendSequenceExhausted => write!(f, "spend commit sequence is exhausted"),
            Self::PolicyRollback => write!(f, "policy epoch rollback was rejected"),
            Self::PolicyFork => write!(f, "policy fork was rejected"),
            Self::CredentialFloorRollback => {
                write!(f, "credential keyset epoch rollback was rejected")
            }
            Self::CashuFloorRollback => {
                write!(f, "Cashu manifest epoch rollback was rejected")
            }
            Self::CashuSwapIntentMissing => write!(f, "Cashu swap intent is missing"),
            Self::CashuSwapIntentConflict => {
                write!(f, "Cashu swap intent conflicts with durable state")
            }
            Self::CashuSwapStateConflict => {
                write!(f, "Cashu swap intent transition conflicts with durable state")
            }
            Self::FreeIpQuotaExhausted => write!(f, "free IP quota is exhausted"),
            Self::FreeIpClockRollback => write!(f, "free IP quota clock rollback was rejected"),
            Self::ServiceProtocol(error) => {
                write!(f, "verified service offer could not be persisted safely: {error}")
            }
            Self::InternalAfterSpend {
                read_back,
                database_error,
            } => write!(
                f,
                "database commit outcome is not safe for authorization ({read_back:?}): {database_error}"
            ),
            Self::Io(error) => write!(f, "provider database I/O error: {error}"),
            Self::Sqlite(error) => write!(f, "provider database error: {error}"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            Self::ServiceProtocol(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for StoreError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

impl From<pir_service_protocol::ServiceProtocolError> for StoreError {
    fn from(value: pir_service_protocol::ServiceProtocolError) -> Self {
        Self::ServiceProtocol(value)
    }
}

pub type StoreResult<T> = Result<T, StoreError>;
