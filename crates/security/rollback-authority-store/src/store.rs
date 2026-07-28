use core::fmt;
use std::convert::TryFrom;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use pir_rollback_authority_protocol::{
    authority_client_key_id_v1, inspect_authority_request_locator_v1, verify_authority_request_v1,
    AuthorityBindingV1, AuthorityCasDispositionV1, AuthorityCasResolutionRefV1,
    AuthorityServerSignerV1, OpaqueAuthorityRecordV1, PersistedAuthorityOperationRefV1,
    PersistedAuthorityTerminalOutcomeRefV1, SignedAuthorityResponseV1,
    VerifiedAuthorityOperationRefV1, VerifiedAuthorityRequestV1, AUTHORITY_INSTANCE_ID_BYTES_V1,
    MAX_SIGNED_AUTHORITY_REQUEST_BYTES_V1, SIGNED_AUTHORITY_READ_REQUEST_BYTES_V1,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use zeroize::{Zeroize, Zeroizing};

use crate::path::{
    checked_existing_database_file_v1, create_private_database_file_v1, open_pinned_database_v1,
    sync_database_and_parent_v1, DatabaseFileIdentityV1,
};
use crate::schema::{
    APPLICATION_ID_V1, EXPECTED_TABLES_V1, SCHEMA_STATEMENTS_V1, SCHEMA_VERSION_V1,
};
use crate::{
    RollbackAuthorityStoreErrorV1, RollbackAuthorityStoreResultV1, MAX_CALL_ROWS_PER_NAMESPACE_V1,
    MAX_OPERATION_ROWS_PER_NAMESPACE_V1, MIN_CALL_ROWS_PER_NAMESPACE_V1,
    MIN_OPERATION_ROWS_PER_NAMESPACE_V1,
};

const MAX_BUSY_TIMEOUT_MILLIS_V1: u128 = 60_000;
const OUTCOME_EMPTY_V1: i64 = 0;
const OUTCOME_APPLIED_V1: i64 = 1;
const OUTCOME_CONFLICT_CURRENT_V1: i64 = 3;
const OPERATION_KIND_READ_V1: i64 = 1;
const OPERATION_KIND_COMPARE_AND_SWAP_V1: i64 = 2;
const CAS_DISPOSITION_NEWLY_LINEARIZED_V1: i64 = 1;
const CAS_DISPOSITION_EXACT_OPERATION_REPLAY_V1: i64 = 2;

type RawProvisionedNamespaceBindingV1 = (Vec<u8>, Vec<u8>, Vec<u8>, i64, i64);

struct StoreHandleV1 {
    path: PathBuf,
    file_identity: DatabaseFileIdentityV1,
    authority_instance_id: Zeroizing<[u8; AUTHORITY_INSTANCE_ID_BYTES_V1]>,
    busy_timeout: Duration,
}

impl StoreHandleV1 {
    fn into_online(self) -> SqliteRollbackAuthorityStoreV1 {
        SqliteRollbackAuthorityStoreV1 { handle: self }
    }

    fn open_operational(&self) -> RollbackAuthorityStoreResultV1<Connection> {
        let connection = open_pinned_database_v1(&self.path, self.file_identity)?;
        configure_existing_connection_v1(
            &connection,
            self.busy_timeout,
            &self.authority_instance_id,
            false,
        )?;
        Ok(connection)
    }

    fn open_checked(&self) -> RollbackAuthorityStoreResultV1<Connection> {
        let connection = open_pinned_database_v1(&self.path, self.file_identity)?;
        configure_existing_connection_v1(
            &connection,
            self.busy_timeout,
            &self.authority_instance_id,
            true,
        )?;
        Ok(connection)
    }
}

/// Usage-sensitive operation-log and call-replay capacities observed through
/// the offline-only provisioner surface.
///
/// The exact counters are intentionally absent from `Debug`. They contain no
/// namespace or key but can reveal one authority role's mutation activity.
pub struct RollbackAuthorityOperationCapacityInventoryV1 {
    provisioned_capacity: Option<((u64, u64), (u64, u64))>,
}

impl fmt::Debug for RollbackAuthorityOperationCapacityInventoryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RollbackAuthorityOperationCapacityInventoryV1")
            .field("capacity", &"[REDACTED]")
            .finish()
    }
}

impl RollbackAuthorityOperationCapacityInventoryV1 {
    pub fn is_provisioned(&self) -> bool {
        self.provisioned_capacity.is_some()
    }

    /// Returns `(used_operation_rows, max_operation_rows)` only after the one
    /// namespace has been provisioned.
    pub fn provisioned_capacity(&self) -> Option<(u64, u64)> {
        self.provisioned_capacity.map(|capacity| capacity.0)
    }

    /// Returns `(used_call_rows, max_call_rows)` only after provisioning.
    pub fn provisioned_call_capacity(&self) -> Option<(u64, u64)> {
        self.provisioned_capacity.map(|capacity| capacity.1)
    }
}

/// Offline-only database creation and insert-only namespace provisioning.
///
/// Convert this value with [`Self::into_online`] before serving requests. The
/// online type deliberately has no provisioning method.
pub struct SqliteRollbackAuthorityProvisionerV1 {
    handle: StoreHandleV1,
}

impl fmt::Debug for SqliteRollbackAuthorityProvisionerV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqliteRollbackAuthorityProvisionerV1")
            .field("database", &"[REDACTED]")
            .field("authority_instance_id", &"[REDACTED]")
            .finish()
    }
}

impl SqliteRollbackAuthorityProvisionerV1 {
    /// Exclusively creates one empty V1 authority database. Existing paths are
    /// never opened, adopted, truncated, or migrated by this operation.
    pub fn create(
        path: impl AsRef<Path>,
        authority_instance_id: [u8; AUTHORITY_INSTANCE_ID_BYTES_V1],
        busy_timeout: Duration,
    ) -> RollbackAuthorityStoreResultV1<Self> {
        validate_configuration_v1(&authority_instance_id, busy_timeout)?;
        let checked = create_private_database_file_v1(path.as_ref())?;
        let handle = StoreHandleV1 {
            path: checked.canonical_path,
            file_identity: checked.identity,
            authority_instance_id: Zeroizing::new(authority_instance_id),
            busy_timeout,
        };

        let mut connection = open_pinned_database_v1(&handle.path, handle.file_identity)?;
        configure_new_connection_v1(&connection, busy_timeout)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
        for statement in SCHEMA_STATEMENTS_V1 {
            transaction
                .execute_batch(statement)
                .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
        }
        transaction
            .execute(
                "INSERT INTO authority_identity \
                 (singleton, authority_instance_id, schema_version) VALUES (1, ?1, ?2)",
                params![
                    handle.authority_instance_id.as_slice(),
                    i64::from(SCHEMA_VERSION_V1),
                ],
            )
            .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
        transaction
            .commit()
            .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
        connection
            .pragma_update(None, "application_id", APPLICATION_ID_V1)
            .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
        connection
            .pragma_update(None, "user_version", SCHEMA_VERSION_V1)
            .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
        sync_database_and_parent_v1(&connection, &handle.path)?;
        validate_fixed_database_v1(&connection, &handle.authority_instance_id, true)?;
        Ok(Self { handle })
    }

    /// Opens only an exact existing schema and caller-pinned authority
    /// instance. It never adopts identity from disk or performs migration.
    pub fn open_existing(
        path: impl AsRef<Path>,
        expected_authority_instance_id: [u8; AUTHORITY_INSTANCE_ID_BYTES_V1],
        busy_timeout: Duration,
    ) -> RollbackAuthorityStoreResultV1<Self> {
        let handle =
            open_existing_handle_v1(path.as_ref(), expected_authority_instance_id, busy_timeout)?;
        Ok(Self { handle })
    }

    /// Inserts the only namespace-to-client-key binding for this authority and
    /// its immutable finite operation-log and call-replay capacities. Repeating
    /// the exact tuple and capacities is idempotent; a second namespace, key
    /// rebind, or capacity change fails closed.
    pub fn provision_namespace(
        &self,
        namespace: [u8; 32],
        client_verifying_key: &VerifyingKey,
        max_operation_rows: u64,
        max_call_rows: u64,
    ) -> RollbackAuthorityStoreResultV1<()> {
        if !(MIN_OPERATION_ROWS_PER_NAMESPACE_V1..=MAX_OPERATION_ROWS_PER_NAMESPACE_V1)
            .contains(&max_operation_rows)
            || !(MIN_CALL_ROWS_PER_NAMESPACE_V1..=MAX_CALL_ROWS_PER_NAMESPACE_V1)
                .contains(&max_call_rows)
        {
            return Err(RollbackAuthorityStoreErrorV1::InvalidConfiguration);
        }
        let max_operation_rows = i64::try_from(max_operation_rows)
            .map_err(|_| RollbackAuthorityStoreErrorV1::InvalidConfiguration)?;
        let max_call_rows = i64::try_from(max_call_rows)
            .map_err(|_| RollbackAuthorityStoreErrorV1::InvalidConfiguration)?;
        let binding = AuthorityBindingV1::for_client_key(
            *self.handle.authority_instance_id,
            namespace,
            client_verifying_key,
        )
        .map_err(|_| RollbackAuthorityStoreErrorV1::InvalidConfiguration)?;
        let mut connection = self.handle.open_operational()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
        let existing: Option<RawProvisionedNamespaceBindingV1> = transaction
            .query_row(
                "SELECT namespace, client_key_id, client_verifying_key, max_operation_rows, \
                        max_call_rows \
                 FROM provisioned_namespaces \
                 WHERE authority_instance_id = ?1",
                params![self.handle.authority_instance_id.as_slice()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
        if let Some((
            raw_namespace,
            raw_key_id,
            raw_key,
            existing_max_operation_rows,
            existing_max_call_rows,
        )) = existing
        {
            let existing_namespace = fixed_secret_v1::<32>(raw_namespace)?;
            let existing_key_id = fixed_secret_v1::<32>(raw_key_id)?;
            let existing_key = fixed_secret_v1::<32>(raw_key)?;
            if existing_namespace.as_slice() != binding.namespace()
                || existing_key_id.as_slice() != binding.client_key_id()
                || existing_key.as_slice() != client_verifying_key.as_bytes()
                || existing_max_operation_rows != max_operation_rows
                || existing_max_call_rows != max_call_rows
            {
                return Err(RollbackAuthorityStoreErrorV1::NamespaceRebindRejected);
            }
            transaction
                .commit()
                .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
            return Ok(());
        }

        transaction
            .execute(
                "INSERT INTO provisioned_namespaces \
                 (authority_instance_id, namespace, client_key_id, client_verifying_key, \
                  max_operation_rows, operation_rows, max_call_rows, call_rows) \
                 VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, 0)",
                params![
                    self.handle.authority_instance_id.as_slice(),
                    binding.namespace().as_slice(),
                    binding.client_key_id().as_slice(),
                    client_verifying_key.as_bytes().as_slice(),
                    max_operation_rows,
                    max_call_rows,
                ],
            )
            .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
        transaction
            .commit()
            .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)
    }

    /// Reads exact operation/call-row usage only through this offline
    /// administration type. Creating or opening the provisioner performs the
    /// full schema, integrity, and row-invariant check first.
    pub fn operation_capacity_inventory(
        &self,
    ) -> RollbackAuthorityStoreResultV1<RollbackAuthorityOperationCapacityInventoryV1> {
        let connection = self.handle.open_operational()?;
        let capacity: Option<(i64, i64, i64, i64)> = connection
            .query_row(
                "SELECT operation_rows, max_operation_rows, call_rows, max_call_rows \
                 FROM provisioned_namespaces WHERE authority_instance_id = ?1",
                params![self.handle.authority_instance_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
        let provisioned_capacity = capacity
            .map(|(used_operations, max_operations, used_calls, max_calls)| {
                Ok((
                    (
                        u64::try_from(used_operations)
                            .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?,
                        u64::try_from(max_operations)
                            .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?,
                    ),
                    (
                        u64::try_from(used_calls)
                            .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?,
                        u64::try_from(max_calls)
                            .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?,
                    ),
                ))
            })
            .transpose()?;
        Ok(RollbackAuthorityOperationCapacityInventoryV1 {
            provisioned_capacity,
        })
    }

    pub fn into_online(self) -> SqliteRollbackAuthorityStoreV1 {
        self.handle.into_online()
    }
}

/// Online authenticated Read/CAS processor for one pinned authority database.
///
/// It exposes no namespace provisioning, enumeration, deletion, reset, schema
/// migration, raw SQL connection, or recovery operation.
pub struct SqliteRollbackAuthorityStoreV1 {
    handle: StoreHandleV1,
}

impl fmt::Debug for SqliteRollbackAuthorityStoreV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqliteRollbackAuthorityStoreV1")
            .field("database", &"[REDACTED]")
            .field("authority_instance_id", &"[REDACTED]")
            .finish()
    }
}

impl SqliteRollbackAuthorityStoreV1 {
    pub fn open_existing(
        path: impl AsRef<Path>,
        expected_authority_instance_id: [u8; AUTHORITY_INSTANCE_ID_BYTES_V1],
        busy_timeout: Duration,
    ) -> RollbackAuthorityStoreResultV1<Self> {
        let handle =
            open_existing_handle_v1(path.as_ref(), expected_authority_instance_id, busy_timeout)?;
        Ok(Self { handle })
    }

    /// Authenticates and handles exactly one canonical signed request. The
    /// response is never signed before the corresponding transaction commits.
    pub fn handle_signed_request(
        &self,
        encoded_request: &[u8],
        server_signer: &AuthorityServerSignerV1,
    ) -> RollbackAuthorityStoreResultV1<SignedAuthorityResponseV1> {
        if encoded_request.len() < SIGNED_AUTHORITY_READ_REQUEST_BYTES_V1
            || encoded_request.len() > MAX_SIGNED_AUTHORITY_REQUEST_BYTES_V1
        {
            return Err(RollbackAuthorityStoreErrorV1::MalformedRequest);
        }
        let locator = inspect_authority_request_locator_v1(encoded_request)
            .map_err(|_| RollbackAuthorityStoreErrorV1::MalformedRequest)?;
        if locator.authority_instance_id() != self.handle.authority_instance_id.as_ref() {
            return Err(RollbackAuthorityStoreErrorV1::RequestRejected);
        }

        let mut connection = self.handle.open_operational()?;
        let client_verifying_key = lookup_client_verifying_key_v1(
            &connection,
            locator.authority_instance_id(),
            locator.namespace(),
            locator.client_key_id(),
        )?;
        let verified = verify_authority_request_v1(
            encoded_request,
            &self.handle.authority_instance_id,
            locator.namespace(),
            &client_verifying_key,
        )
        .map_err(|_| RollbackAuthorityStoreErrorV1::RequestRejected)?;

        match verified.operation() {
            VerifiedAuthorityOperationRefV1::Read => {
                self.handle_read_v1(&mut connection, &verified, server_signer)
            }
            VerifiedAuthorityOperationRefV1::CompareAndSwap { .. } => {
                self.handle_compare_and_swap_v1(&mut connection, &verified, server_signer)
            }
        }
    }

    fn handle_read_v1(
        &self,
        connection: &mut Connection,
        request: &VerifiedAuthorityRequestV1,
        server_signer: &AuthorityServerSignerV1,
    ) -> RollbackAuthorityStoreResultV1<SignedAuthorityResponseV1> {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
        let current = match read_call_v1(&transaction, request)? {
            Some(call) => {
                call.ensure_exact_request_v1(request, StoredCallKindV1::Read)?;
                call.observed_record
            }
            None => {
                ensure_operation_id_compatible_v1(&transaction, request, true)?;
                reserve_call_capacity_v1(&transaction, request)?;
                let current = read_current_record_v1(
                    &transaction,
                    request.binding().authority_instance_id(),
                    request.binding().namespace(),
                    request.binding().client_key_id(),
                )?;
                insert_call_v1(
                    &transaction,
                    request,
                    StoredCallKindV1::Read,
                    current.as_ref(),
                )?;
                current
            }
        };
        transaction
            .commit()
            .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
        server_signer
            .sign_read_response(request, current.as_ref())
            .map_err(|_| RollbackAuthorityStoreErrorV1::ResponseSigningFailure)
    }

    fn handle_compare_and_swap_v1(
        &self,
        connection: &mut Connection,
        request: &VerifiedAuthorityRequestV1,
        server_signer: &AuthorityServerSignerV1,
    ) -> RollbackAuthorityStoreResultV1<SignedAuthorityResponseV1> {
        let VerifiedAuthorityOperationRefV1::CompareAndSwap { expected, desired } =
            request.operation()
        else {
            return Err(RollbackAuthorityStoreErrorV1::RequestRejected);
        };

        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
        let persisted_call = read_call_v1(&transaction, request)?;
        let (disposition, observed_current) = if let Some(call) = persisted_call {
            call.ensure_exact_request_v1(request, StoredCallKindV1::CompareAndSwapNewlyLinearized)?;
            let disposition = call
                .kind
                .cas_disposition_v1()
                .ok_or(RollbackAuthorityStoreErrorV1::SchemaMismatch)?;
            (disposition, call.observed_record)
        } else {
            let existing = read_operation_v1(
                &transaction,
                request.binding().authority_instance_id(),
                request.binding().namespace(),
                request.binding().client_key_id(),
                request.call().operation_id(),
            )?;
            if let Some(existing) = existing.as_ref() {
                if existing.operation_digest.as_slice() != request.operation_digest() {
                    return Err(RollbackAuthorityStoreErrorV1::OperationReplayMismatch);
                }
            }
            ensure_operation_id_compatible_v1(&transaction, request, false)?;
            reserve_call_capacity_v1(&transaction, request)?;
            let (disposition, observed_current) = if existing.is_some() {
                (
                    AuthorityCasDispositionV1::ExactOperationReplay,
                    read_current_record_v1(
                        &transaction,
                        request.binding().authority_instance_id(),
                        request.binding().namespace(),
                        request.binding().client_key_id(),
                    )?,
                )
            } else {
                reserve_operation_capacity_v1(&transaction, request)?;
                let current = read_current_record_v1(
                    &transaction,
                    request.binding().authority_instance_id(),
                    request.binding().namespace(),
                    request.binding().client_key_id(),
                )?;
                let first_outcome = determine_and_apply_first_outcome_v1(
                    &transaction,
                    request,
                    expected,
                    desired,
                    current.as_ref(),
                )?;
                insert_operation_v1(&transaction, request, first_outcome)?;
                let applied_current = read_current_record_v1(
                    &transaction,
                    request.binding().authority_instance_id(),
                    request.binding().namespace(),
                    request.binding().client_key_id(),
                )?;
                (AuthorityCasDispositionV1::NewlyLinearized, applied_current)
            };
            let kind = match disposition {
                AuthorityCasDispositionV1::NewlyLinearized => {
                    StoredCallKindV1::CompareAndSwapNewlyLinearized
                }
                AuthorityCasDispositionV1::ExactOperationReplay => {
                    StoredCallKindV1::CompareAndSwapOperationReplay
                }
            };
            insert_call_v1(&transaction, request, kind, observed_current.as_ref())?;
            (disposition, observed_current)
        };

        // Re-read the operation row in this same transaction. The signer gets
        // that durable terminal row together with the call_log snapshot from
        // this call's original linearization, never a later live observation.
        let persisted = read_operation_v1(
            &transaction,
            request.binding().authority_instance_id(),
            request.binding().namespace(),
            request.binding().client_key_id(),
            request.call().operation_id(),
        )?
        .ok_or(RollbackAuthorityStoreErrorV1::StorageFailure)?;
        if persisted.operation_digest.as_slice() != request.operation_digest() {
            return Err(RollbackAuthorityStoreErrorV1::OperationReplayMismatch);
        }
        transaction
            .commit()
            .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;

        sign_committed_cas_resolution_v1(
            server_signer,
            request,
            &persisted,
            observed_current.as_ref(),
            disposition,
        )
    }

    #[cfg(test)]
    pub(crate) fn operation_count_for_tests(&self) -> RollbackAuthorityStoreResultV1<u64> {
        let connection = self.handle.open_operational()?;
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM operation_log", [], |row| row.get(0))
            .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
        u64::try_from(count).map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)
    }

    #[cfg(test)]
    pub(crate) fn operation_capacity_for_tests(
        &self,
    ) -> RollbackAuthorityStoreResultV1<(u64, u64)> {
        let connection = self.handle.open_operational()?;
        let (used, maximum): (i64, i64) = connection
            .query_row(
                "SELECT operation_rows, max_operation_rows FROM provisioned_namespaces",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
        Ok((
            u64::try_from(used).map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?,
            u64::try_from(maximum).map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?,
        ))
    }

    #[cfg(test)]
    pub(crate) fn call_count_for_tests(&self) -> RollbackAuthorityStoreResultV1<u64> {
        let connection = self.handle.open_operational()?;
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM call_log", [], |row| row.get(0))
            .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
        u64::try_from(count).map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)
    }

    #[cfg(test)]
    pub(crate) fn call_capacity_for_tests(&self) -> RollbackAuthorityStoreResultV1<(u64, u64)> {
        let connection = self.handle.open_operational()?;
        let (used, maximum): (i64, i64) = connection
            .query_row(
                "SELECT call_rows, max_call_rows FROM provisioned_namespaces",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
        Ok((
            u64::try_from(used).map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?,
            u64::try_from(maximum).map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?,
        ))
    }
}

fn open_existing_handle_v1(
    path: &Path,
    expected_authority_instance_id: [u8; AUTHORITY_INSTANCE_ID_BYTES_V1],
    busy_timeout: Duration,
) -> RollbackAuthorityStoreResultV1<StoreHandleV1> {
    validate_configuration_v1(&expected_authority_instance_id, busy_timeout)?;
    let checked = checked_existing_database_file_v1(path)?;
    let handle = StoreHandleV1 {
        path: checked.canonical_path,
        file_identity: checked.identity,
        authority_instance_id: Zeroizing::new(expected_authority_instance_id),
        busy_timeout,
    };
    handle.open_checked()?;
    Ok(handle)
}

fn validate_configuration_v1(
    authority_instance_id: &[u8; AUTHORITY_INSTANCE_ID_BYTES_V1],
    busy_timeout: Duration,
) -> RollbackAuthorityStoreResultV1<()> {
    if authority_instance_id.iter().all(|byte| *byte == 0)
        || busy_timeout.is_zero()
        || busy_timeout.as_millis() > MAX_BUSY_TIMEOUT_MILLIS_V1
    {
        return Err(RollbackAuthorityStoreErrorV1::InvalidConfiguration);
    }
    Ok(())
}

fn configure_new_connection_v1(
    connection: &Connection,
    busy_timeout: Duration,
) -> RollbackAuthorityStoreResultV1<()> {
    configure_connection_local_v1(connection, busy_timeout)?;
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
        .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(RollbackAuthorityStoreErrorV1::StorageFailure);
    }
    Ok(())
}

fn configure_existing_connection_v1(
    connection: &Connection,
    busy_timeout: Duration,
    expected_authority_instance_id: &[u8; AUTHORITY_INSTANCE_ID_BYTES_V1],
    complete_integrity_check: bool,
) -> RollbackAuthorityStoreResultV1<()> {
    // Connection-local safety settings are applied before parsing schema. No
    // persistent pragma is changed until the exact on-disk identity is known.
    configure_connection_local_v1(connection, busy_timeout)?;
    validate_fixed_database_v1(
        connection,
        expected_authority_instance_id,
        complete_integrity_check,
    )?;
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(RollbackAuthorityStoreErrorV1::SchemaMismatch);
    }
    Ok(())
}

fn configure_connection_local_v1(
    connection: &Connection,
    busy_timeout: Duration,
) -> RollbackAuthorityStoreResultV1<()> {
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
    connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
    connection
        .pragma_update(None, "trusted_schema", false)
        .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
    connection
        .pragma_update(None, "temp_store", "MEMORY")
        .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
    connection
        .busy_timeout(busy_timeout)
        .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
    check_pragma_v1(connection, "synchronous", 2)?;
    check_pragma_v1(connection, "foreign_keys", 1)?;
    check_pragma_v1(connection, "trusted_schema", 0)?;
    check_pragma_v1(connection, "temp_store", 2)?;
    check_pragma_v1(
        connection,
        "busy_timeout",
        i64::try_from(busy_timeout.as_millis())
            .map_err(|_| RollbackAuthorityStoreErrorV1::InvalidConfiguration)?,
    )
}

fn check_pragma_v1(
    connection: &Connection,
    pragma: &'static str,
    expected: i64,
) -> RollbackAuthorityStoreResultV1<()> {
    let query = format!("PRAGMA {pragma}");
    let actual: i64 = connection
        .query_row(&query, [], |row| row.get(0))
        .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
    if actual != expected {
        return Err(RollbackAuthorityStoreErrorV1::StorageFailure);
    }
    Ok(())
}

fn validate_fixed_database_v1(
    connection: &Connection,
    expected_authority_instance_id: &[u8; AUTHORITY_INSTANCE_ID_BYTES_V1],
    complete_integrity_check: bool,
) -> RollbackAuthorityStoreResultV1<()> {
    let application_id: i32 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?;
    let schema_version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?;
    if application_id != APPLICATION_ID_V1 || schema_version != SCHEMA_VERSION_V1 {
        return Err(RollbackAuthorityStoreErrorV1::SchemaMismatch);
    }
    verify_exact_schema_v1(connection)?;
    let actual_authority_instance_id = read_identity_v1(connection)?;
    if actual_authority_instance_id.as_slice() != expected_authority_instance_id {
        return Err(RollbackAuthorityStoreErrorV1::AuthorityInstanceMismatch);
    }
    if complete_integrity_check {
        let quick_check: String = connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?;
        if quick_check != "ok" {
            return Err(RollbackAuthorityStoreErrorV1::SchemaMismatch);
        }
        let mut foreign_keys = connection
            .prepare("PRAGMA foreign_key_check")
            .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?;
        if foreign_keys
            .query([])
            .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?
            .next()
            .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?
            .is_some()
        {
            return Err(RollbackAuthorityStoreErrorV1::SchemaMismatch);
        }
        validate_all_rows_v1(connection, expected_authority_instance_id)?;
    }
    Ok(())
}

fn verify_exact_schema_v1(connection: &Connection) -> RollbackAuthorityStoreResultV1<()> {
    let mut statement = connection
        .prepare(
            "SELECT type, name, sql FROM sqlite_schema \
             WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL \
             ORDER BY type, name",
        )
        .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?;
    let mut actual = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?;
    for (expected_name, expected_sql) in EXPECTED_TABLES_V1 {
        let (actual_type, actual_name, actual_sql) = actual
            .next()
            .ok_or(RollbackAuthorityStoreErrorV1::SchemaMismatch)?
            .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?;
        if actual_type != "table"
            || actual_name != expected_name
            || normalize_schema_sql_v1(&actual_sql) != normalize_schema_sql_v1(expected_sql)
        {
            return Err(RollbackAuthorityStoreErrorV1::SchemaMismatch);
        }
    }
    if actual.next().is_some() {
        return Err(RollbackAuthorityStoreErrorV1::SchemaMismatch);
    }
    Ok(())
}

fn normalize_schema_sql_v1(sql: &str) -> String {
    sql.chars()
        .filter(|character| !character.is_whitespace() && *character != ';')
        .collect()
}

fn read_identity_v1(
    connection: &Connection,
) -> RollbackAuthorityStoreResultV1<Zeroizing<[u8; AUTHORITY_INSTANCE_ID_BYTES_V1]>> {
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM authority_identity", [], |row| {
            row.get(0)
        })
        .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?;
    if count != 1 {
        return Err(RollbackAuthorityStoreErrorV1::SchemaMismatch);
    }
    let (raw_instance, schema_version): (Vec<u8>, i64) = connection
        .query_row(
            "SELECT authority_instance_id, schema_version \
             FROM authority_identity WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?;
    if schema_version != i64::from(SCHEMA_VERSION_V1) {
        return Err(RollbackAuthorityStoreErrorV1::SchemaMismatch);
    }
    let instance = fixed_secret_v1(raw_instance)?;
    if instance.iter().all(|byte| *byte == 0) {
        return Err(RollbackAuthorityStoreErrorV1::SchemaMismatch);
    }
    Ok(instance)
}

fn validate_all_rows_v1(
    connection: &Connection,
    expected_authority_instance_id: &[u8; AUTHORITY_INSTANCE_ID_BYTES_V1],
) -> RollbackAuthorityStoreResultV1<()> {
    let mut namespaces = connection
        .prepare(
            "SELECT provisioned.authority_instance_id, provisioned.namespace, \
                    provisioned.client_key_id, provisioned.client_verifying_key, \
                    provisioned.max_operation_rows, provisioned.operation_rows, \
                    provisioned.max_call_rows, provisioned.call_rows, \
                    (SELECT COUNT(*) FROM operation_log \
                      WHERE operation_log.authority_instance_id = provisioned.authority_instance_id \
                        AND operation_log.namespace = provisioned.namespace \
                        AND operation_log.client_key_id = provisioned.client_key_id), \
                    (SELECT COUNT(*) FROM call_log \
                      WHERE call_log.authority_instance_id = provisioned.authority_instance_id \
                        AND call_log.namespace = provisioned.namespace \
                        AND call_log.client_key_id = provisioned.client_key_id) \
             FROM provisioned_namespaces AS provisioned",
        )
        .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?;
    let rows = namespaces
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, i64>(9)?,
            ))
        })
        .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?;
    let mut namespace_rows = 0_u8;
    for row in rows {
        namespace_rows = namespace_rows
            .checked_add(1)
            .ok_or(RollbackAuthorityStoreErrorV1::SchemaMismatch)?;
        let (
            raw_instance,
            raw_namespace,
            raw_key_id,
            raw_key,
            max_operation_rows,
            stored_operation_rows,
            max_call_rows,
            stored_call_rows,
            actual_operation_rows,
            actual_call_rows,
        ) = row.map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?;
        let instance = fixed_secret_v1::<32>(raw_instance)?;
        let namespace = fixed_secret_v1::<32>(raw_namespace)?;
        let key_id = fixed_secret_v1::<32>(raw_key_id)?;
        let key_bytes = fixed_secret_v1::<32>(raw_key)?;
        let key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?;
        if instance.as_slice() != expected_authority_instance_id
            || namespace.iter().all(|byte| *byte == 0)
            || authority_client_key_id_v1(&key) != *key_id
            || max_operation_rows
                < i64::try_from(MIN_OPERATION_ROWS_PER_NAMESPACE_V1)
                    .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?
            || max_operation_rows
                > i64::try_from(MAX_OPERATION_ROWS_PER_NAMESPACE_V1)
                    .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?
            || stored_operation_rows < 0
            || stored_operation_rows > max_operation_rows
            || stored_operation_rows != actual_operation_rows
            || max_call_rows
                < i64::try_from(MIN_CALL_ROWS_PER_NAMESPACE_V1)
                    .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?
            || max_call_rows
                > i64::try_from(MAX_CALL_ROWS_PER_NAMESPACE_V1)
                    .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?
            || stored_call_rows < 0
            || stored_call_rows > max_call_rows
            || stored_call_rows != actual_call_rows
        {
            return Err(RollbackAuthorityStoreErrorV1::SchemaMismatch);
        }
    }
    if namespace_rows > 1 {
        return Err(RollbackAuthorityStoreErrorV1::SchemaMismatch);
    }

    let mut records = connection
        .prepare("SELECT opaque_record FROM current_records")
        .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?;
    let rows = records
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?;
    for row in rows {
        let raw = Zeroizing::new(row.map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?);
        OpaqueAuthorityRecordV1::decode(&raw)
            .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?;
    }

    let mut operations = connection
        .prepare(
            "SELECT operation_id, operation_digest, first_outcome, first_record \
             FROM operation_log",
        )
        .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?;
    let rows = operations
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
            ))
        })
        .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?;
    for row in rows {
        let (operation_id, operation_digest, outcome, record) =
            row.map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?;
        let operation_id = fixed_secret_v1::<32>(operation_id)?;
        fixed_secret_v1::<32>(operation_digest)?;
        if operation_id.iter().all(|byte| *byte == 0) {
            return Err(RollbackAuthorityStoreErrorV1::SchemaMismatch);
        }
        match (outcome, record) {
            (OUTCOME_EMPTY_V1, None) => {}
            (OUTCOME_APPLIED_V1 | OUTCOME_CONFLICT_CURRENT_V1, Some(raw)) => {
                let raw = Zeroizing::new(raw);
                OpaqueAuthorityRecordV1::decode(&raw)
                    .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?;
            }
            _ => return Err(RollbackAuthorityStoreErrorV1::SchemaMismatch),
        }
    }

    let mut calls = connection
        .prepare(
            "SELECT calls.call_nonce, calls.operation_id, calls.operation_digest, \
                    calls.request_digest, calls.operation_kind, calls.cas_disposition, \
                    calls.observed_record, \
                    EXISTS(SELECT 1 FROM operation_log AS operations \
                     WHERE operations.authority_instance_id = calls.authority_instance_id \
                       AND operations.namespace = calls.namespace \
                       AND operations.client_key_id = calls.client_key_id \
                       AND operations.operation_id = calls.operation_id \
                       AND operations.operation_digest = calls.operation_digest) \
             FROM call_log AS calls",
        )
        .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?;
    let rows = calls
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<i64>>(5)?,
                row.get::<_, Option<Vec<u8>>>(6)?,
                row.get::<_, i64>(7)?,
            ))
        })
        .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?;
    for row in rows {
        let (
            nonce,
            operation_id,
            operation_digest,
            request_digest,
            kind,
            disposition,
            record,
            operation_exists,
        ) = row.map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?;
        let nonce = fixed_secret_v1::<32>(nonce)?;
        let operation_id = fixed_secret_v1::<32>(operation_id)?;
        fixed_secret_v1::<32>(operation_digest)?;
        fixed_secret_v1::<32>(request_digest)?;
        let kind = StoredCallKindV1::from_columns_v1(kind, disposition)?;
        if nonce.iter().all(|byte| *byte == 0)
            || operation_id.iter().all(|byte| *byte == 0)
            || (matches!(kind, StoredCallKindV1::Read) && operation_exists != 0)
            || (!matches!(kind, StoredCallKindV1::Read) && operation_exists != 1)
        {
            return Err(RollbackAuthorityStoreErrorV1::SchemaMismatch);
        }
        if let Some(raw) = record {
            let raw = Zeroizing::new(raw);
            OpaqueAuthorityRecordV1::decode(&raw)
                .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?;
        }
    }

    let orphaned_operations: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM operation_log AS operations \
             WHERE NOT EXISTS (SELECT 1 FROM call_log AS calls \
              WHERE calls.authority_instance_id = operations.authority_instance_id \
                AND calls.namespace = operations.namespace \
                AND calls.client_key_id = operations.client_key_id \
                AND calls.operation_id = operations.operation_id \
                AND calls.operation_digest = operations.operation_digest \
                AND calls.operation_kind = 2)",
            [],
            |row| row.get(0),
        )
        .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?;
    if orphaned_operations != 0 {
        return Err(RollbackAuthorityStoreErrorV1::SchemaMismatch);
    }
    Ok(())
}

fn lookup_client_verifying_key_v1(
    connection: &Connection,
    authority_instance_id: &[u8; 32],
    namespace: &[u8; 32],
    client_key_id: &[u8; 32],
) -> RollbackAuthorityStoreResultV1<VerifyingKey> {
    let raw: Option<Vec<u8>> = connection
        .query_row(
            "SELECT client_verifying_key FROM provisioned_namespaces \
             WHERE authority_instance_id = ?1 AND namespace = ?2 AND client_key_id = ?3",
            params![
                authority_instance_id.as_slice(),
                namespace.as_slice(),
                client_key_id.as_slice(),
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
    let raw = raw.ok_or(RollbackAuthorityStoreErrorV1::RequestRejected)?;
    let key_bytes = fixed_secret_v1::<32>(raw)?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?;
    if authority_client_key_id_v1(&key) != *client_key_id {
        return Err(RollbackAuthorityStoreErrorV1::SchemaMismatch);
    }
    Ok(key)
}

fn read_current_record_v1(
    connection: &Connection,
    authority_instance_id: &[u8; 32],
    namespace: &[u8; 32],
    client_key_id: &[u8; 32],
) -> RollbackAuthorityStoreResultV1<Option<OpaqueAuthorityRecordV1>> {
    let raw: Option<Vec<u8>> = connection
        .query_row(
            "SELECT opaque_record FROM current_records \
             WHERE authority_instance_id = ?1 AND namespace = ?2 AND client_key_id = ?3",
            params![
                authority_instance_id.as_slice(),
                namespace.as_slice(),
                client_key_id.as_slice(),
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
    raw.map(|raw| {
        let raw = Zeroizing::new(raw);
        OpaqueAuthorityRecordV1::decode(&raw)
            .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)
    })
    .transpose()
}

#[derive(Clone, Copy)]
enum StoredCallKindV1 {
    Read,
    CompareAndSwapNewlyLinearized,
    CompareAndSwapOperationReplay,
}

impl StoredCallKindV1 {
    fn from_columns_v1(
        operation_kind: i64,
        cas_disposition: Option<i64>,
    ) -> RollbackAuthorityStoreResultV1<Self> {
        match (operation_kind, cas_disposition) {
            (OPERATION_KIND_READ_V1, None) => Ok(Self::Read),
            (OPERATION_KIND_COMPARE_AND_SWAP_V1, Some(CAS_DISPOSITION_NEWLY_LINEARIZED_V1)) => {
                Ok(Self::CompareAndSwapNewlyLinearized)
            }
            (
                OPERATION_KIND_COMPARE_AND_SWAP_V1,
                Some(CAS_DISPOSITION_EXACT_OPERATION_REPLAY_V1),
            ) => Ok(Self::CompareAndSwapOperationReplay),
            _ => Err(RollbackAuthorityStoreErrorV1::SchemaMismatch),
        }
    }

    fn columns_v1(self) -> (i64, Option<i64>) {
        match self {
            Self::Read => (OPERATION_KIND_READ_V1, None),
            Self::CompareAndSwapNewlyLinearized => (
                OPERATION_KIND_COMPARE_AND_SWAP_V1,
                Some(CAS_DISPOSITION_NEWLY_LINEARIZED_V1),
            ),
            Self::CompareAndSwapOperationReplay => (
                OPERATION_KIND_COMPARE_AND_SWAP_V1,
                Some(CAS_DISPOSITION_EXACT_OPERATION_REPLAY_V1),
            ),
        }
    }

    fn is_same_operation_kind_v1(self, other: Self) -> bool {
        matches!((self, other), (Self::Read, Self::Read))
            || matches!(
                (self, other),
                (
                    Self::CompareAndSwapNewlyLinearized | Self::CompareAndSwapOperationReplay,
                    Self::CompareAndSwapNewlyLinearized | Self::CompareAndSwapOperationReplay
                )
            )
    }

    fn cas_disposition_v1(self) -> Option<AuthorityCasDispositionV1> {
        match self {
            Self::Read => None,
            Self::CompareAndSwapNewlyLinearized => Some(AuthorityCasDispositionV1::NewlyLinearized),
            Self::CompareAndSwapOperationReplay => {
                Some(AuthorityCasDispositionV1::ExactOperationReplay)
            }
        }
    }
}

struct LoadedCallV1 {
    operation_id: Zeroizing<[u8; 32]>,
    operation_digest: Zeroizing<[u8; 32]>,
    request_digest: Zeroizing<[u8; 32]>,
    kind: StoredCallKindV1,
    observed_record: Option<OpaqueAuthorityRecordV1>,
}

impl LoadedCallV1 {
    fn ensure_exact_request_v1(
        &self,
        request: &VerifiedAuthorityRequestV1,
        expected_kind: StoredCallKindV1,
    ) -> RollbackAuthorityStoreResultV1<()> {
        if !self.kind.is_same_operation_kind_v1(expected_kind)
            || self.operation_id.as_slice() != request.call().operation_id()
            || self.operation_digest.as_slice() != request.operation_digest()
            || self.request_digest.as_slice() != request.request_digest()
        {
            return Err(RollbackAuthorityStoreErrorV1::OperationReplayMismatch);
        }
        Ok(())
    }
}

fn read_call_v1(
    connection: &Connection,
    request: &VerifiedAuthorityRequestV1,
) -> RollbackAuthorityStoreResultV1<Option<LoadedCallV1>> {
    type RawCallV1 = (Vec<u8>, Vec<u8>, Vec<u8>, i64, Option<i64>, Option<Vec<u8>>);
    let raw: Option<RawCallV1> = connection
        .query_row(
            "SELECT operation_id, operation_digest, request_digest, operation_kind, \
                    cas_disposition, observed_record \
             FROM call_log \
             WHERE authority_instance_id = ?1 AND namespace = ?2 \
               AND client_key_id = ?3 AND call_nonce = ?4",
            params![
                request.binding().authority_instance_id().as_slice(),
                request.binding().namespace().as_slice(),
                request.binding().client_key_id().as_slice(),
                request.call().call_nonce().as_slice(),
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()
        .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
    raw.map(|raw| {
        let observed_record = raw
            .5
            .map(|raw| {
                let raw = Zeroizing::new(raw);
                OpaqueAuthorityRecordV1::decode(&raw)
                    .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)
            })
            .transpose()?;
        Ok(LoadedCallV1 {
            operation_id: fixed_secret_v1(raw.0)?,
            operation_digest: fixed_secret_v1(raw.1)?,
            request_digest: fixed_secret_v1(raw.2)?,
            kind: StoredCallKindV1::from_columns_v1(raw.3, raw.4)?,
            observed_record,
        })
    })
    .transpose()
}

fn ensure_operation_id_compatible_v1(
    connection: &Connection,
    request: &VerifiedAuthorityRequestV1,
    request_is_read: bool,
) -> RollbackAuthorityStoreResultV1<()> {
    let incompatible: i64 = if request_is_read {
        connection.query_row(
            "SELECT COUNT(*) FROM call_log \
             WHERE authority_instance_id = ?1 AND namespace = ?2 AND client_key_id = ?3 \
               AND operation_id = ?4",
            params![
                request.binding().authority_instance_id().as_slice(),
                request.binding().namespace().as_slice(),
                request.binding().client_key_id().as_slice(),
                request.call().operation_id().as_slice(),
            ],
            |row| row.get(0),
        )
    } else {
        connection.query_row(
            "SELECT COUNT(*) FROM call_log \
             WHERE authority_instance_id = ?1 AND namespace = ?2 AND client_key_id = ?3 \
               AND operation_id = ?4 \
               AND (operation_kind != 2 OR operation_digest != ?5)",
            params![
                request.binding().authority_instance_id().as_slice(),
                request.binding().namespace().as_slice(),
                request.binding().client_key_id().as_slice(),
                request.call().operation_id().as_slice(),
                request.operation_digest().as_slice(),
            ],
            |row| row.get(0),
        )
    }
    .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
    if incompatible != 0 {
        return Err(RollbackAuthorityStoreErrorV1::OperationReplayMismatch);
    }
    Ok(())
}

/// Atomically claims one durable exact-call replay row before observing the
/// current floor. Exact signed-request replay never calls this function.
fn reserve_call_capacity_v1(
    connection: &Connection,
    request: &VerifiedAuthorityRequestV1,
) -> RollbackAuthorityStoreResultV1<()> {
    let changed = connection
        .execute(
            "UPDATE provisioned_namespaces \
             SET call_rows = call_rows + 1 \
             WHERE authority_instance_id = ?1 AND namespace = ?2 AND client_key_id = ?3 \
               AND call_rows < max_call_rows",
            params![
                request.binding().authority_instance_id().as_slice(),
                request.binding().namespace().as_slice(),
                request.binding().client_key_id().as_slice(),
            ],
        )
        .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
    if changed != 1 {
        return Err(RollbackAuthorityStoreErrorV1::CallCapacityExhausted);
    }
    Ok(())
}

fn insert_call_v1(
    connection: &Connection,
    request: &VerifiedAuthorityRequestV1,
    kind: StoredCallKindV1,
    observed_record: Option<&OpaqueAuthorityRecordV1>,
) -> RollbackAuthorityStoreResultV1<()> {
    let request_is_read = matches!(request.operation(), VerifiedAuthorityOperationRefV1::Read);
    if request_is_read != matches!(kind, StoredCallKindV1::Read) {
        return Err(RollbackAuthorityStoreErrorV1::RequestRejected);
    }
    let (operation_kind, cas_disposition) = kind.columns_v1();
    let encoded_record = observed_record.map(OpaqueAuthorityRecordV1::encode);
    let record_parameter = encoded_record.as_ref().map(|record| record.as_slice());
    let changed = connection
        .execute(
            "INSERT INTO call_log \
             (authority_instance_id, namespace, client_key_id, call_nonce, operation_id, \
              operation_digest, request_digest, operation_kind, cas_disposition, \
              observed_record) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                request.binding().authority_instance_id().as_slice(),
                request.binding().namespace().as_slice(),
                request.binding().client_key_id().as_slice(),
                request.call().call_nonce().as_slice(),
                request.call().operation_id().as_slice(),
                request.operation_digest().as_slice(),
                request.request_digest().as_slice(),
                operation_kind,
                cas_disposition,
                record_parameter,
            ],
        )
        .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
    if changed != 1 {
        return Err(RollbackAuthorityStoreErrorV1::StorageFailure);
    }
    Ok(())
}

fn determine_and_apply_first_outcome_v1<'a>(
    connection: &Connection,
    request: &VerifiedAuthorityRequestV1,
    expected: Option<&OpaqueAuthorityRecordV1>,
    desired: &'a OpaqueAuthorityRecordV1,
    current: Option<&'a OpaqueAuthorityRecordV1>,
) -> RollbackAuthorityStoreResultV1<FirstOutcomeRefV1<'a>> {
    match (expected, current) {
        (None, None) => {
            insert_current_record_v1(connection, request, desired)?;
            Ok(FirstOutcomeRefV1::Applied(desired))
        }
        (Some(_), None) => Ok(FirstOutcomeRefV1::Empty),
        (Some(expected), Some(current)) if expected == current => {
            update_current_record_v1(connection, request, desired)?;
            Ok(FirstOutcomeRefV1::Applied(desired))
        }
        (_, Some(current)) => Ok(FirstOutcomeRefV1::ConflictCurrent(current)),
    }
}

/// Atomically claims one operation-log row before the transaction observes or
/// mutates the current floor. A transaction rollback also rolls back this
/// counter increment. Exact operation replays never call this function.
fn reserve_operation_capacity_v1(
    connection: &Connection,
    request: &VerifiedAuthorityRequestV1,
) -> RollbackAuthorityStoreResultV1<()> {
    let changed = connection
        .execute(
            "UPDATE provisioned_namespaces \
             SET operation_rows = operation_rows + 1 \
             WHERE authority_instance_id = ?1 AND namespace = ?2 AND client_key_id = ?3 \
               AND operation_rows < max_operation_rows",
            params![
                request.binding().authority_instance_id().as_slice(),
                request.binding().namespace().as_slice(),
                request.binding().client_key_id().as_slice(),
            ],
        )
        .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
    if changed != 1 {
        return Err(RollbackAuthorityStoreErrorV1::OperationCapacityExhausted);
    }
    Ok(())
}

fn insert_current_record_v1(
    connection: &Connection,
    request: &VerifiedAuthorityRequestV1,
    desired: &OpaqueAuthorityRecordV1,
) -> RollbackAuthorityStoreResultV1<()> {
    let encoded = desired.encode();
    let changed = connection
        .execute(
            "INSERT INTO current_records \
             (authority_instance_id, namespace, client_key_id, opaque_record) \
             VALUES (?1, ?2, ?3, ?4)",
            params![
                request.binding().authority_instance_id().as_slice(),
                request.binding().namespace().as_slice(),
                request.binding().client_key_id().as_slice(),
                encoded.as_slice(),
            ],
        )
        .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
    if changed != 1 {
        return Err(RollbackAuthorityStoreErrorV1::StorageFailure);
    }
    Ok(())
}

fn update_current_record_v1(
    connection: &Connection,
    request: &VerifiedAuthorityRequestV1,
    desired: &OpaqueAuthorityRecordV1,
) -> RollbackAuthorityStoreResultV1<()> {
    let encoded = desired.encode();
    let changed = connection
        .execute(
            "UPDATE current_records SET opaque_record = ?1 \
             WHERE authority_instance_id = ?2 AND namespace = ?3 AND client_key_id = ?4",
            params![
                encoded.as_slice(),
                request.binding().authority_instance_id().as_slice(),
                request.binding().namespace().as_slice(),
                request.binding().client_key_id().as_slice(),
            ],
        )
        .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
    if changed != 1 {
        return Err(RollbackAuthorityStoreErrorV1::StorageFailure);
    }
    Ok(())
}

enum FirstOutcomeRefV1<'a> {
    Empty,
    Applied(&'a OpaqueAuthorityRecordV1),
    ConflictCurrent(&'a OpaqueAuthorityRecordV1),
}

fn insert_operation_v1(
    connection: &Connection,
    request: &VerifiedAuthorityRequestV1,
    first_outcome: FirstOutcomeRefV1<'_>,
) -> RollbackAuthorityStoreResultV1<()> {
    let (outcome, record) = match first_outcome {
        FirstOutcomeRefV1::Empty => (OUTCOME_EMPTY_V1, None),
        FirstOutcomeRefV1::Applied(record) => (OUTCOME_APPLIED_V1, Some(record.encode())),
        FirstOutcomeRefV1::ConflictCurrent(record) => {
            (OUTCOME_CONFLICT_CURRENT_V1, Some(record.encode()))
        }
    };
    let record_parameter = record.as_ref().map(|bytes| bytes.as_slice());
    let changed = connection
        .execute(
            "INSERT INTO operation_log \
             (authority_instance_id, namespace, client_key_id, operation_id, \
              operation_digest, first_outcome, first_record) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                request.binding().authority_instance_id().as_slice(),
                request.binding().namespace().as_slice(),
                request.binding().client_key_id().as_slice(),
                request.call().operation_id().as_slice(),
                request.operation_digest().as_slice(),
                outcome,
                record_parameter,
            ],
        )
        .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
    if changed != 1 {
        return Err(RollbackAuthorityStoreErrorV1::StorageFailure);
    }
    Ok(())
}

struct LoadedOperationV1 {
    authority_instance_id: Zeroizing<[u8; 32]>,
    namespace: Zeroizing<[u8; 32]>,
    client_key_id: Zeroizing<[u8; 32]>,
    operation_id: Zeroizing<[u8; 32]>,
    operation_digest: Zeroizing<[u8; 32]>,
    first_outcome: StoredTerminalOutcomeV1,
}

enum StoredTerminalOutcomeV1 {
    Empty,
    Applied(OpaqueAuthorityRecordV1),
    ConflictCurrent(OpaqueAuthorityRecordV1),
}

fn read_operation_v1(
    connection: &Connection,
    authority_instance_id: &[u8; 32],
    namespace: &[u8; 32],
    client_key_id: &[u8; 32],
    operation_id: &[u8; 32],
) -> RollbackAuthorityStoreResultV1<Option<LoadedOperationV1>> {
    type RawOperationV1 = (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
        Option<Vec<u8>>,
    );
    let raw: Option<RawOperationV1> = connection
        .query_row(
            "SELECT authority_instance_id, namespace, client_key_id, operation_id, \
                    operation_digest, first_outcome, first_record \
             FROM operation_log \
             WHERE authority_instance_id = ?1 AND namespace = ?2 \
               AND client_key_id = ?3 AND operation_id = ?4",
            params![
                authority_instance_id.as_slice(),
                namespace.as_slice(),
                client_key_id.as_slice(),
                operation_id.as_slice(),
            ],
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
        .optional()
        .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
    raw.map(|raw| {
        let first_outcome = match (raw.5, raw.6) {
            (OUTCOME_EMPTY_V1, None) => StoredTerminalOutcomeV1::Empty,
            (OUTCOME_APPLIED_V1, Some(raw)) => {
                let raw = Zeroizing::new(raw);
                StoredTerminalOutcomeV1::Applied(
                    OpaqueAuthorityRecordV1::decode(&raw)
                        .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?,
                )
            }
            (OUTCOME_CONFLICT_CURRENT_V1, Some(raw)) => {
                let raw = Zeroizing::new(raw);
                StoredTerminalOutcomeV1::ConflictCurrent(
                    OpaqueAuthorityRecordV1::decode(&raw)
                        .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?,
                )
            }
            _ => return Err(RollbackAuthorityStoreErrorV1::SchemaMismatch),
        };
        Ok(LoadedOperationV1 {
            authority_instance_id: fixed_secret_v1(raw.0)?,
            namespace: fixed_secret_v1(raw.1)?,
            client_key_id: fixed_secret_v1(raw.2)?,
            operation_id: fixed_secret_v1(raw.3)?,
            operation_digest: fixed_secret_v1(raw.4)?,
            first_outcome,
        })
    })
    .transpose()
}

fn sign_committed_cas_resolution_v1(
    server_signer: &AuthorityServerSignerV1,
    request: &VerifiedAuthorityRequestV1,
    persisted: &LoadedOperationV1,
    observed_current: Option<&OpaqueAuthorityRecordV1>,
    disposition: AuthorityCasDispositionV1,
) -> RollbackAuthorityStoreResultV1<SignedAuthorityResponseV1> {
    let first_outcome = match &persisted.first_outcome {
        StoredTerminalOutcomeV1::Empty => PersistedAuthorityTerminalOutcomeRefV1::Empty,
        StoredTerminalOutcomeV1::Applied(record) => {
            PersistedAuthorityTerminalOutcomeRefV1::Applied(record)
        }
        StoredTerminalOutcomeV1::ConflictCurrent(record) => {
            PersistedAuthorityTerminalOutcomeRefV1::ConflictCurrent(record)
        }
    };
    let persisted_ref = PersistedAuthorityOperationRefV1::from_persisted_row(
        &persisted.authority_instance_id,
        &persisted.namespace,
        &persisted.client_key_id,
        &persisted.operation_id,
        &persisted.operation_digest,
        first_outcome,
    )
    .map_err(|_| RollbackAuthorityStoreErrorV1::SchemaMismatch)?;
    let resolution = AuthorityCasResolutionRefV1::from_linearized_transaction(
        persisted_ref,
        observed_current,
        disposition,
    );
    server_signer
        .sign_compare_and_swap_response(request, resolution)
        .map_err(|_| RollbackAuthorityStoreErrorV1::ResponseSigningFailure)
}

fn fixed_secret_v1<const N: usize>(
    raw: Vec<u8>,
) -> RollbackAuthorityStoreResultV1<Zeroizing<[u8; N]>> {
    let mut raw = Zeroizing::new(raw);
    if raw.len() != N {
        return Err(RollbackAuthorityStoreErrorV1::SchemaMismatch);
    }
    let mut fixed = Zeroizing::new([0_u8; N]);
    fixed.copy_from_slice(&raw);
    raw.zeroize();
    Ok(fixed)
}
