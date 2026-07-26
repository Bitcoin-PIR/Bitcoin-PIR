//! Separately configured SQLite authority for issuer-store rollback floors.
//!
//! This file must live outside the issuer-store backup/restore domain.

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::Duration;

use pir_service_protocol::LightningNetworkV1;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};

use crate::{
    IssuerRollbackFloorAuthorityErrorV1, IssuerRollbackFloorAuthorityV1, IssuerRollbackFloorV1,
    SCHEMA_VERSION,
};

const AUTHORITY_APPLICATION_ID: i32 = 0x4249_5246; // "BIRF"
const AUTHORITY_SCHEMA_VERSION: u32 = 1;
const AUTHORITY_SCHEMA: &str = r#"
CREATE TABLE rollback_floors (
    issuer_id           BLOB NOT NULL CHECK(length(issuer_id) = 32),
    network             INTEGER NOT NULL CHECK(network BETWEEN 1 AND 4),
    store_instance_id   BLOB NOT NULL CHECK(length(store_instance_id) = 16),
    store_generation    INTEGER NOT NULL CHECK(store_generation >= 0),
    rollback_commitment BLOB NOT NULL CHECK(length(rollback_commitment) = 32),
    issuer_schema       INTEGER NOT NULL CHECK(issuer_schema > 0),
    PRIMARY KEY (issuer_id, network)
) STRICT, WITHOUT ROWID;
"#;

#[derive(Clone)]
pub struct SqliteIssuerRollbackFloorAuthorityV1 {
    path: PathBuf,
    busy_timeout: Duration,
}

impl core::fmt::Debug for SqliteIssuerRollbackFloorAuthorityV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SqliteIssuerRollbackFloorAuthorityV1")
            .field("path", &self.path)
            .field("busy_timeout", &self.busy_timeout)
            .finish()
    }
}

impl SqliteIssuerRollbackFloorAuthorityV1 {
    pub fn create(
        path: impl AsRef<Path>,
        busy_timeout: Duration,
    ) -> Result<Self, IssuerRollbackFloorAuthorityErrorV1> {
        validate_timeout(busy_timeout)?;
        let path = path.as_ref().to_path_buf();
        if path.as_os_str().is_empty() {
            return Err(error("issuer rollback authority path is empty"));
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
    ) -> Result<Self, IssuerRollbackFloorAuthorityErrorV1> {
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

    fn open_raw(&self) -> Result<Connection, IssuerRollbackFloorAuthorityErrorV1> {
        let metadata = fs::symlink_metadata(&self.path).map_err(io_error)?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(error(
                "issuer rollback authority must be an existing non-symlink regular file",
            ));
        }
        Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(sql_error)
    }

    fn open_checked(&self) -> Result<Connection, IssuerRollbackFloorAuthorityErrorV1> {
        let connection = self.open_raw()?;
        configure(&connection, self.busy_timeout)?;
        let application_id: i32 = connection
            .pragma_query_value(None, "application_id", |row| row.get(0))
            .map_err(sql_error)?;
        let user_version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(sql_error)?;
        if application_id != AUTHORITY_APPLICATION_ID || user_version != AUTHORITY_SCHEMA_VERSION {
            return Err(error("issuer rollback authority schema identity mismatch"));
        }
        let integrity: String = connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .map_err(sql_error)?;
        if integrity != "ok" {
            return Err(error("issuer rollback authority integrity check failed"));
        }
        Ok(connection)
    }
}

impl IssuerRollbackFloorAuthorityV1 for SqliteIssuerRollbackFloorAuthorityV1 {
    fn load(
        &self,
        issuer_id: &[u8; 32],
        network: LightningNetworkV1,
    ) -> Result<Option<IssuerRollbackFloorV1>, IssuerRollbackFloorAuthorityErrorV1> {
        if issuer_id.iter().all(|byte| *byte == 0) {
            return Err(error("issuer rollback authority issuer ID is zero"));
        }
        let connection = self.open_checked()?;
        read_floor(&connection, issuer_id, network)
    }

    fn initialize(
        &self,
        initial: &IssuerRollbackFloorV1,
    ) -> Result<IssuerRollbackFloorV1, IssuerRollbackFloorAuthorityErrorV1> {
        validate_floor(initial)?;
        if initial.store_generation != 0 {
            return Err(error(
                "issuer rollback initial floor is not generation zero",
            ));
        }
        let mut connection = self.open_checked()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        if let Some(current) = read_floor(&transaction, &initial.issuer_id, initial.network)? {
            transaction.rollback().map_err(sql_error)?;
            return Ok(current);
        }
        transaction
            .execute(
                "INSERT INTO rollback_floors (issuer_id, network, store_instance_id, \
                 store_generation, rollback_commitment, issuer_schema) VALUES (?1, ?2, ?3, 0, ?4, ?5)",
                params![
                    initial.issuer_id.as_slice(),
                    initial.network as u8,
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
        expected: &IssuerRollbackFloorV1,
        next: &IssuerRollbackFloorV1,
    ) -> Result<IssuerRollbackFloorV1, IssuerRollbackFloorAuthorityErrorV1> {
        validate_floor(expected)?;
        validate_floor(next)?;
        if expected.issuer_id != next.issuer_id
            || expected.network != next.network
            || expected.store_instance_id != next.store_instance_id
            || expected.schema_version != next.schema_version
            || next.store_generation
                != expected
                    .store_generation
                    .checked_add(1)
                    .ok_or_else(|| error("issuer rollback generation overflow"))?
            || next.rollback_commitment == expected.rollback_commitment
        {
            return Err(error("issuer rollback authority transition is invalid"));
        }
        let mut connection = self.open_checked()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        let changed = transaction
            .execute(
                "UPDATE rollback_floors SET store_generation = ?1, rollback_commitment = ?2 \
                 WHERE issuer_id = ?3 AND network = ?4 AND store_instance_id = ?5 \
                 AND store_generation = ?6 AND rollback_commitment = ?7 AND issuer_schema = ?8",
                params![
                    sql_u64(next.store_generation)?,
                    next.rollback_commitment.as_slice(),
                    next.issuer_id.as_slice(),
                    next.network as u8,
                    next.store_instance_id.as_slice(),
                    sql_u64(expected.store_generation)?,
                    expected.rollback_commitment.as_slice(),
                    i64::from(expected.schema_version),
                ],
            )
            .map_err(sql_error)?;
        if changed == 1 {
            transaction.commit().map_err(sql_error)?;
            return Ok(*next);
        }
        let current = read_floor(&transaction, &expected.issuer_id, expected.network)?
            .ok_or_else(|| error("issuer rollback floor disappeared during CAS"))?;
        transaction.rollback().map_err(sql_error)?;
        Ok(current)
    }
}

fn configure(
    connection: &Connection,
    busy_timeout: Duration,
) -> Result<(), IssuerRollbackFloorAuthorityErrorV1> {
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
    issuer_id: &[u8; 32],
    network: LightningNetworkV1,
) -> Result<Option<IssuerRollbackFloorV1>, IssuerRollbackFloorAuthorityErrorV1> {
    type Raw = (Vec<u8>, Vec<u8>, i64, i64, Vec<u8>, i64);
    let raw: Option<Raw> = connection
        .query_row(
            "SELECT store_instance_id, issuer_id, network, store_generation, \
             rollback_commitment, issuer_schema FROM rollback_floors \
             WHERE issuer_id = ?1 AND network = ?2",
            params![issuer_id.as_slice(), network as u8],
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
        let floor = IssuerRollbackFloorV1 {
            store_instance_id: fixed(raw.0, "invalid authority store instance ID")?,
            issuer_id: fixed(raw.1, "invalid authority issuer ID")?,
            network: decode_network(raw.2)?,
            store_generation: rust_u64(raw.3)?,
            rollback_commitment: fixed(raw.4, "invalid authority commitment")?,
            schema_version: u32::try_from(raw.5)
                .map_err(|_| error("invalid authority issuer schema"))?,
        };
        validate_floor(&floor)?;
        Ok(floor)
    })
    .transpose()
}

fn validate_floor(
    floor: &IssuerRollbackFloorV1,
) -> Result<(), IssuerRollbackFloorAuthorityErrorV1> {
    if floor.store_instance_id.iter().all(|byte| *byte == 0)
        || floor.issuer_id.iter().all(|byte| *byte == 0)
        || floor.rollback_commitment.iter().all(|byte| *byte == 0)
        || floor.schema_version != SCHEMA_VERSION
    {
        return Err(error("issuer rollback authority floor is invalid"));
    }
    Ok(())
}

fn decode_network(value: i64) -> Result<LightningNetworkV1, IssuerRollbackFloorAuthorityErrorV1> {
    match value {
        1 => Ok(LightningNetworkV1::Bitcoin),
        2 => Ok(LightningNetworkV1::Testnet),
        3 => Ok(LightningNetworkV1::Signet),
        4 => Ok(LightningNetworkV1::Regtest),
        _ => Err(error("invalid issuer rollback network")),
    }
}

fn validate_timeout(timeout: Duration) -> Result<(), IssuerRollbackFloorAuthorityErrorV1> {
    if timeout.is_zero() || timeout > Duration::from_secs(60) {
        Err(error("issuer rollback busy timeout must be in 1ms..=60s"))
    } else {
        Ok(())
    }
}

fn sql_u64(value: u64) -> Result<i64, IssuerRollbackFloorAuthorityErrorV1> {
    i64::try_from(value).map_err(|_| error("issuer rollback integer exceeds SQLite range"))
}

fn rust_u64(value: i64) -> Result<u64, IssuerRollbackFloorAuthorityErrorV1> {
    u64::try_from(value).map_err(|_| error("issuer rollback integer is negative"))
}

fn fixed<const N: usize>(
    bytes: Vec<u8>,
    reason: &'static str,
) -> Result<[u8; N], IssuerRollbackFloorAuthorityErrorV1> {
    bytes.try_into().map_err(|_| error(reason))
}

fn sync_parent(path: &Path) -> Result<(), IssuerRollbackFloorAuthorityErrorV1> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(io_error)
}

fn error(reason: impl Into<String>) -> IssuerRollbackFloorAuthorityErrorV1 {
    IssuerRollbackFloorAuthorityErrorV1::new(reason)
}

fn sql_error(error_value: rusqlite::Error) -> IssuerRollbackFloorAuthorityErrorV1 {
    error(format!(
        "issuer rollback authority SQLite error: {error_value}"
    ))
}

fn io_error(error_value: std::io::Error) -> IssuerRollbackFloorAuthorityErrorV1 {
    error(format!(
        "issuer rollback authority I/O error: {error_value}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn floor(generation: u64, commitment: u8) -> IssuerRollbackFloorV1 {
        IssuerRollbackFloorV1 {
            store_instance_id: [1; 16],
            issuer_id: [2; 32],
            network: LightningNetworkV1::Regtest,
            store_generation: generation,
            rollback_commitment: [commitment; 32],
            schema_version: SCHEMA_VERSION,
        }
    }

    #[test]
    fn authority_is_durable_idempotent_and_linearizable() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("issuer-floor.sqlite");
        let authority =
            SqliteIssuerRollbackFloorAuthorityV1::create(&path, Duration::from_secs(1)).unwrap();
        let zero = floor(0, 3);
        assert_eq!(authority.initialize(&zero).unwrap(), zero);
        assert_eq!(authority.initialize(&zero).unwrap(), zero);
        let one = floor(1, 4);
        assert_eq!(authority.compare_and_advance(&zero, &one).unwrap(), one);
        assert_eq!(
            authority.compare_and_advance(&zero, &floor(1, 5)).unwrap(),
            one
        );
        drop(authority);
        let reopened =
            SqliteIssuerRollbackFloorAuthorityV1::open_existing(&path, Duration::from_secs(1))
                .unwrap();
        assert_eq!(
            reopened
                .load(&[2; 32], LightningNetworkV1::Regtest)
                .unwrap(),
            Some(one)
        );
    }
}
