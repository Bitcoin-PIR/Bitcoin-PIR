//! Durable single-instance SQLite storage and request processing for the
//! BitcoinPIR remote rollback-authority protocol.
//!
//! [`SqliteRollbackAuthorityProvisionerV1`] is the offline-only creation and
//! insert-only namespace provisioning surface. The deliberately narrower
//! [`SqliteRollbackAuthorityStoreV1`] is the online request processor and has
//! no provisioning, enumeration, reset, delete, or migration API.

#![forbid(unsafe_code)]

mod path;
mod schema;
mod store;

#[cfg(test)]
mod tests;

pub use store::{
    RollbackAuthorityOperationCapacityInventoryV1, SqliteRollbackAuthorityProvisionerV1,
    SqliteRollbackAuthorityStoreV1,
};

/// Smallest operation-log capacity accepted for one provisioned namespace.
pub const MIN_OPERATION_ROWS_PER_NAMESPACE_V1: u64 = 1;

/// Largest V1 operation-log capacity which can be provisioned for one authority.
///
/// The limit is intentionally finite and must still be capacity-planned against
/// the actual SQLite row/WAL/backup footprint. V1 has no safe pruning protocol.
pub const MAX_OPERATION_ROWS_PER_NAMESPACE_V1: u64 = 100_000_000;

/// Smallest durable per-call replay capacity accepted for one namespace.
pub const MIN_CALL_ROWS_PER_NAMESPACE_V1: u64 = 1;

/// Largest durable per-call replay capacity accepted for one namespace.
///
/// Every fresh authenticated Read and every fresh-nonce CAS attempt consumes
/// one row. Exact signed-request replay does not. V1 has no safe pruning
/// protocol, so the bound is explicit and immutable.
pub const MAX_CALL_ROWS_PER_NAMESPACE_V1: u64 = 100_000_000;

use core::fmt;

/// Redacted fail-closed errors. No variant carries a path, namespace, record,
/// operation ID, digest, public key, signature, or SQLite diagnostic string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackAuthorityStoreErrorV1 {
    InvalidConfiguration,
    DatabaseAlreadyExists,
    MissingDatabase,
    UnsafeDatabasePath,
    SchemaMismatch,
    AuthorityInstanceMismatch,
    NamespaceRebindRejected,
    OperationCapacityExhausted,
    CallCapacityExhausted,
    MalformedRequest,
    RequestRejected,
    OperationReplayMismatch,
    StorageFailure,
    ResponseSigningFailure,
}

impl fmt::Display for RollbackAuthorityStoreErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "rollback authority configuration is invalid",
            Self::DatabaseAlreadyExists => "rollback authority database already exists",
            Self::MissingDatabase => "rollback authority database is missing",
            Self::UnsafeDatabasePath => "rollback authority database path is unsafe",
            Self::SchemaMismatch => "rollback authority database schema is invalid",
            Self::AuthorityInstanceMismatch => "rollback authority instance does not match",
            Self::NamespaceRebindRejected => "rollback authority namespace rebind was rejected",
            Self::OperationCapacityExhausted => {
                "rollback authority operation capacity is exhausted"
            }
            Self::CallCapacityExhausted => "rollback authority call capacity is exhausted",
            Self::MalformedRequest => "rollback authority request is malformed",
            Self::RequestRejected => "rollback authority request was rejected",
            Self::OperationReplayMismatch => {
                "rollback authority operation ID was reused with different content"
            }
            Self::StorageFailure => "rollback authority storage operation failed",
            Self::ResponseSigningFailure => "rollback authority response signing failed",
        })
    }
}

impl std::error::Error for RollbackAuthorityStoreErrorV1 {}

pub type RollbackAuthorityStoreResultV1<T> = Result<T, RollbackAuthorityStoreErrorV1>;
