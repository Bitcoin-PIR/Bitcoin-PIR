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
    /// Concurrent writers raced the internal commit-chain compare-and-set.
    RollbackFork,
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
    CashuCustodyExposureExceeded,
    CashuCustodyLotMissing,
    CashuCustodyLotConflict,
    CashuCustodyExportMissing,
    CashuCustodyExportConflict,
    CashuCustodyStateConflict,
    CashuCustodyUnavailable,
    CashuCustodyNotesNotFullySpent,
    CashuCustodyRetirementFloorMismatch,
    CashuCustodyRetirementEvidenceMissing,
    CashuCustodyRetirementEvidenceConflict,
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
            Self::RollbackFork => write!(
                f,
                "concurrent provider-store writers conflicted at one commit generation"
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
            Self::CashuCustodyExposureExceeded => {
                write!(f, "Cashu custody exposure limit would be exceeded")
            }
            Self::CashuCustodyLotMissing => write!(f, "Cashu custody lot is missing"),
            Self::CashuCustodyLotConflict => {
                write!(f, "Cashu custody lot conflicts with durable state")
            }
            Self::CashuCustodyExportMissing => write!(f, "Cashu custody export is missing"),
            Self::CashuCustodyExportConflict => {
                write!(f, "Cashu custody export conflicts with durable state")
            }
            Self::CashuCustodyStateConflict => {
                write!(f, "Cashu custody transition conflicts with durable state")
            }
            Self::CashuCustodyUnavailable => {
                write!(f, "no available Cashu custody lot matches the export request")
            }
            Self::CashuCustodyNotesNotFullySpent => {
                write!(f, "Cashu custody notes are not all confirmed spent")
            }
            Self::CashuCustodyRetirementFloorMismatch => write!(
                f,
                "Cashu custody retirement check is stale or belongs to another store"
            ),
            Self::CashuCustodyRetirementEvidenceMissing => {
                write!(f, "Cashu custody retirement evidence is missing")
            }
            Self::CashuCustodyRetirementEvidenceConflict => {
                write!(f, "Cashu custody retirement evidence conflicts with durable state")
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
