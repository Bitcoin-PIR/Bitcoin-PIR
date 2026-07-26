//! A separately configured SQLite implementation of the rollback-floor
//! authority contract.
//!
//! The authority database must live outside the provider-store backup and
//! restore domain (ideally a separate host or volume). Co-locating and backing
//! up both files together defeats malicious/stale-snapshot rollback detection,
//! even though ordinary crash consistency remains correct.

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};

use crate::{
    RollbackFloorAuthorityErrorV1, RollbackFloorAuthorityV1, RollbackFloorV1, SCHEMA_VERSION,
};

const AUTHORITY_APPLICATION_ID: i32 = 0x4250_5246; // "BPRF"
const AUTHORITY_SCHEMA_VERSION: u32 = 1;
const AUTHORITY_SCHEMA: &str = r#"
CREATE TABLE rollback_floors (
    provider_id         BLOB PRIMARY KEY NOT NULL CHECK(length(provider_id) = 32),
    store_instance_id   BLOB NOT NULL CHECK(length(store_instance_id) = 16),
    store_generation    INTEGER NOT NULL CHECK(store_generation >= 0),
    spend_commit_seq    INTEGER NOT NULL CHECK(spend_commit_seq >= 0),
    rollback_commitment BLOB NOT NULL CHECK(length(rollback_commitment) = 32),
    provider_schema     INTEGER NOT NULL CHECK(provider_schema > 0)
) STRICT;
"#;

#[derive(Clone)]
pub struct SqliteRollbackFloorAuthorityV1 {
    path: PathBuf,
    busy_timeout: Duration,
}

impl core::fmt::Debug for SqliteRollbackFloorAuthorityV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SqliteRollbackFloorAuthorityV1")
            .field("path", &self.path)
            .field("busy_timeout", &self.busy_timeout)
            .finish()
    }
}

impl SqliteRollbackFloorAuthorityV1 {
    /// Create a new authority database. Existing files are never adopted or
    /// overwritten implicitly.
    pub fn create(
        path: impl AsRef<Path>,
        busy_timeout: Duration,
    ) -> Result<Self, RollbackFloorAuthorityErrorV1> {
        validate_timeout(busy_timeout)?;
        let path = path.as_ref().to_path_buf();
        if path.as_os_str().is_empty() {
            return Err(error("rollback authority path is empty"));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        drop(file);
        sync_parent(&path)?;

        let authority = Self { path, busy_timeout };
        let connection = authority.open_raw()?;
        configure(&connection, busy_timeout)?;
        connection
            .execute_batch(AUTHORITY_SCHEMA)
            .map_err(sql_error)?;
        connection
            .pragma_update(None, "application_id", AUTHORITY_APPLICATION_ID)
            .map_err(sql_error)?;
        connection
            .pragma_update(None, "user_version", AUTHORITY_SCHEMA_VERSION)
            .map_err(sql_error)?;
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(sql_error)?;
        drop(connection);
        OpenOptions::new()
            .read(true)
            .open(&authority.path)
            .and_then(|file| file.sync_all())
            .map_err(io_error)?;
        sync_parent(&authority.path)?;
        authority.open_checked()?;
        Ok(authority)
    }

    pub fn open_existing(
        path: impl AsRef<Path>,
        busy_timeout: Duration,
    ) -> Result<Self, RollbackFloorAuthorityErrorV1> {
        validate_timeout(busy_timeout)?;
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

    fn open_raw(&self) -> Result<Connection, RollbackFloorAuthorityErrorV1> {
        Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(sql_error)
    }

    fn open_checked(&self) -> Result<Connection, RollbackFloorAuthorityErrorV1> {
        let connection = self.open_raw()?;
        configure(&connection, self.busy_timeout)?;
        let application_id: i32 = connection
            .pragma_query_value(None, "application_id", |row| row.get(0))
            .map_err(sql_error)?;
        let user_version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(sql_error)?;
        if application_id != AUTHORITY_APPLICATION_ID || user_version != AUTHORITY_SCHEMA_VERSION {
            return Err(error("rollback authority schema identity mismatch"));
        }
        let integrity: String = connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .map_err(sql_error)?;
        if integrity != "ok" {
            return Err(error("rollback authority integrity check failed"));
        }
        Ok(connection)
    }
}

impl RollbackFloorAuthorityV1 for SqliteRollbackFloorAuthorityV1 {
    fn load(
        &self,
        provider_id: &[u8; 32],
    ) -> Result<Option<RollbackFloorV1>, RollbackFloorAuthorityErrorV1> {
        if provider_id.iter().all(|byte| *byte == 0) {
            return Err(error("rollback authority provider ID is zero"));
        }
        let connection = self.open_checked()?;
        read_floor(&connection, provider_id)
    }

    fn initialize(
        &self,
        initial: &RollbackFloorV1,
    ) -> Result<RollbackFloorV1, RollbackFloorAuthorityErrorV1> {
        validate_floor(initial)?;
        if initial.store_generation != 0 || initial.spend_commit_seq != 0 {
            return Err(error(
                "rollback authority initial floor is not generation zero",
            ));
        }
        let mut connection = self.open_checked()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        if let Some(current) = read_floor(&transaction, &initial.provider_id)? {
            transaction.rollback().map_err(sql_error)?;
            return Ok(current);
        }
        transaction
            .execute(
                "INSERT INTO rollback_floors (provider_id, store_instance_id, store_generation, \
                 spend_commit_seq, rollback_commitment, provider_schema) \
                 VALUES (?1, ?2, 0, 0, ?3, ?4)",
                params![
                    initial.provider_id.as_slice(),
                    initial.store_instance_id.as_slice(),
                    initial.rollback_commitment.as_slice(),
                    i64::from(initial.schema_version),
                ],
            )
            .map_err(sql_error)?;
        transaction.commit().map_err(sql_error)?;
        Ok(*initial)
    }

    fn compare_and_advance(
        &self,
        expected: &RollbackFloorV1,
        next: &RollbackFloorV1,
    ) -> Result<RollbackFloorV1, RollbackFloorAuthorityErrorV1> {
        validate_floor(expected)?;
        validate_floor(next)?;
        if expected.provider_id != next.provider_id
            || expected.store_instance_id != next.store_instance_id
            || expected.schema_version != next.schema_version
            || next.store_generation
                != expected
                    .store_generation
                    .checked_add(1)
                    .ok_or_else(|| error("rollback authority generation overflow"))?
            || next.spend_commit_seq < expected.spend_commit_seq
            || next.spend_commit_seq > expected.spend_commit_seq.saturating_add(1)
            || next.rollback_commitment == expected.rollback_commitment
        {
            return Err(error("rollback authority transition is invalid"));
        }

        let mut connection = self.open_checked()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        let changed = transaction
            .execute(
                "UPDATE rollback_floors SET store_generation = ?1, spend_commit_seq = ?2, \
                 rollback_commitment = ?3 WHERE provider_id = ?4 AND store_instance_id = ?5 \
                 AND store_generation = ?6 AND spend_commit_seq = ?7 \
                 AND rollback_commitment = ?8 AND provider_schema = ?9",
                params![
                    sql_u64(next.store_generation)?,
                    sql_u64(next.spend_commit_seq)?,
                    next.rollback_commitment.as_slice(),
                    next.provider_id.as_slice(),
                    next.store_instance_id.as_slice(),
                    sql_u64(expected.store_generation)?,
                    sql_u64(expected.spend_commit_seq)?,
                    expected.rollback_commitment.as_slice(),
                    i64::from(expected.schema_version),
                ],
            )
            .map_err(sql_error)?;
        if changed == 1 {
            transaction.commit().map_err(sql_error)?;
            return Ok(*next);
        }
        let current = read_floor(&transaction, &expected.provider_id)?
            .ok_or_else(|| error("rollback authority floor disappeared during CAS"))?;
        transaction.rollback().map_err(sql_error)?;
        Ok(current)
    }
}

fn configure(
    connection: &Connection,
    busy_timeout: Duration,
) -> Result<(), RollbackFloorAuthorityErrorV1> {
    connection.busy_timeout(busy_timeout).map_err(sql_error)?;
    connection
        .execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA synchronous=FULL; \
             PRAGMA journal_mode=WAL;",
        )
        .map_err(sql_error)?;
    Ok(())
}

fn read_floor(
    connection: &Connection,
    provider_id: &[u8; 32],
) -> Result<Option<RollbackFloorV1>, RollbackFloorAuthorityErrorV1> {
    type RawRollbackFloorRow = (Vec<u8>, Vec<u8>, i64, i64, Vec<u8>, i64);

    let raw: Option<RawRollbackFloorRow> = connection
        .query_row(
            "SELECT store_instance_id, provider_id, store_generation, spend_commit_seq, \
             rollback_commitment, provider_schema FROM rollback_floors WHERE provider_id = ?1",
            params![provider_id.as_slice()],
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
        .map_err(sql_error)?;
    raw.map(|raw| {
        let floor = RollbackFloorV1 {
            store_instance_id: fixed(raw.0, "invalid authority store instance ID")?,
            provider_id: fixed(raw.1, "invalid authority provider ID")?,
            store_generation: rust_u64(raw.2)?,
            spend_commit_seq: rust_u64(raw.3)?,
            rollback_commitment: fixed(raw.4, "invalid authority commitment")?,
            schema_version: u32::try_from(raw.5)
                .map_err(|_| error("invalid authority provider schema"))?,
        };
        validate_floor(&floor)?;
        Ok(floor)
    })
    .transpose()
}

fn validate_floor(floor: &RollbackFloorV1) -> Result<(), RollbackFloorAuthorityErrorV1> {
    if floor.store_instance_id.iter().all(|byte| *byte == 0)
        || floor.provider_id.iter().all(|byte| *byte == 0)
        || floor.rollback_commitment.iter().all(|byte| *byte == 0)
        || floor.schema_version != SCHEMA_VERSION
        || floor.spend_commit_seq > floor.store_generation
    {
        return Err(error("rollback authority floor is invalid"));
    }
    Ok(())
}

fn validate_timeout(timeout: Duration) -> Result<(), RollbackFloorAuthorityErrorV1> {
    if timeout.is_zero() || timeout > Duration::from_secs(60) {
        Err(error(
            "rollback authority busy timeout must be in 1ms..=60s",
        ))
    } else {
        Ok(())
    }
}

fn sql_u64(value: u64) -> Result<i64, RollbackFloorAuthorityErrorV1> {
    i64::try_from(value).map_err(|_| error("rollback authority integer exceeds SQLite range"))
}

fn rust_u64(value: i64) -> Result<u64, RollbackFloorAuthorityErrorV1> {
    u64::try_from(value).map_err(|_| error("rollback authority integer is negative"))
}

fn fixed<const N: usize>(
    bytes: Vec<u8>,
    reason: &'static str,
) -> Result<[u8; N], RollbackFloorAuthorityErrorV1> {
    bytes.try_into().map_err(|_| error(reason))
}

fn sync_parent(path: &Path) -> Result<(), RollbackFloorAuthorityErrorV1> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(io_error)
}

fn error(reason: impl Into<String>) -> RollbackFloorAuthorityErrorV1 {
    RollbackFloorAuthorityErrorV1::new(reason)
}

fn sql_error(error: rusqlite::Error) -> RollbackFloorAuthorityErrorV1 {
    RollbackFloorAuthorityErrorV1::new(format!("rollback authority SQLite error: {error}"))
}

fn io_error(error: std::io::Error) -> RollbackFloorAuthorityErrorV1 {
    RollbackFloorAuthorityErrorV1::new(format!("rollback authority I/O error: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn floor(generation: u64, spend: u64, commitment: u8) -> RollbackFloorV1 {
        RollbackFloorV1 {
            store_instance_id: [1; 16],
            provider_id: [2; 32],
            store_generation: generation,
            spend_commit_seq: spend,
            rollback_commitment: [commitment; 32],
            schema_version: SCHEMA_VERSION,
        }
    }

    #[test]
    fn authority_is_durable_idempotent_and_linearizable() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("floor.sqlite");
        let authority =
            SqliteRollbackFloorAuthorityV1::create(&path, Duration::from_secs(1)).unwrap();
        let zero = floor(0, 0, 3);
        assert_eq!(authority.initialize(&zero).unwrap(), zero);
        assert_eq!(authority.initialize(&zero).unwrap(), zero);
        let one = floor(1, 1, 4);
        assert_eq!(authority.compare_and_advance(&zero, &one).unwrap(), one);
        assert_eq!(
            authority
                .compare_and_advance(&zero, &floor(1, 0, 5))
                .unwrap(),
            one,
            "a losing CAS returns the durable current floor"
        );
        drop(authority);
        let reopened =
            SqliteRollbackFloorAuthorityV1::open_existing(&path, Duration::from_secs(1)).unwrap();
        assert_eq!(reopened.load(&[2; 32]).unwrap(), Some(one));
    }
}
