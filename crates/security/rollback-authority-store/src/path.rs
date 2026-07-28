use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags};

use crate::{RollbackAuthorityStoreErrorV1, RollbackAuthorityStoreResultV1};

pub(crate) type DatabaseFileIdentityV1 = pir_private_files::PrivateFileIdentityV1;

pub(crate) struct CheckedDatabaseFileV1 {
    pub(crate) canonical_path: PathBuf,
    pub(crate) identity: DatabaseFileIdentityV1,
}

pub(crate) fn create_private_database_file_v1(
    path: &Path,
) -> RollbackAuthorityStoreResultV1<CheckedDatabaseFileV1> {
    if path.as_os_str().is_empty() {
        return Err(RollbackAuthorityStoreErrorV1::InvalidConfiguration);
    }
    if fs::symlink_metadata(path).is_ok() {
        return Err(RollbackAuthorityStoreErrorV1::DatabaseAlreadyExists);
    }
    let canonical_path =
        pir_private_files::prepare_new_private_file_v1(path, false, "rollback authority database")
            .map_err(|_| RollbackAuthorityStoreErrorV1::UnsafeDatabasePath)?;
    let file = pir_private_files::create_new_private_file_v1(
        &canonical_path,
        "rollback authority database",
    )
    .map_err(|_| RollbackAuthorityStoreErrorV1::DatabaseAlreadyExists)?;
    file.sync_all()
        .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
    drop(file);

    let checked = checked_existing_database_file_v1(&canonical_path)?;
    sync_parent_directory_v1(&checked.canonical_path)?;
    Ok(checked)
}

pub(crate) fn checked_existing_database_file_v1(
    path: &Path,
) -> RollbackAuthorityStoreResultV1<CheckedDatabaseFileV1> {
    if path.as_os_str().is_empty() {
        return Err(RollbackAuthorityStoreErrorV1::InvalidConfiguration);
    }
    let configured = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            RollbackAuthorityStoreErrorV1::MissingDatabase
        } else {
            RollbackAuthorityStoreErrorV1::StorageFailure
        }
    })?;
    if configured.file_type().is_symlink() || !configured.file_type().is_file() {
        return Err(RollbackAuthorityStoreErrorV1::UnsafeDatabasePath);
    }
    let checked = pir_private_files::checked_existing_private_file_v1(
        path,
        pir_private_files::PrivateFileModeV1::ReadWrite,
        "rollback authority database",
    )
    .map_err(|_| RollbackAuthorityStoreErrorV1::UnsafeDatabasePath)?;
    Ok(CheckedDatabaseFileV1 {
        canonical_path: checked.path().to_path_buf(),
        identity: checked.identity(),
    })
}

pub(crate) fn open_pinned_database_v1(
    path: &Path,
    expected_identity: DatabaseFileIdentityV1,
) -> RollbackAuthorityStoreResultV1<Connection> {
    let checked = checked_existing_database_file_v1(path)?;
    if checked.identity != expected_identity {
        return Err(RollbackAuthorityStoreErrorV1::UnsafeDatabasePath);
    }
    let connection = Connection::open_with_flags(
        checked.canonical_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
    // Close the check/open race: after SQLite owns its file descriptor, the
    // path must still name the exact pinned inode. A later replacement makes
    // the next operation fail before it opens a new connection.
    let after_open = checked_existing_database_file_v1(path)?;
    if after_open.identity != expected_identity {
        return Err(RollbackAuthorityStoreErrorV1::UnsafeDatabasePath);
    }
    Ok(connection)
}

pub(crate) fn sync_database_and_parent_v1(
    connection: &Connection,
    path: &Path,
) -> RollbackAuthorityStoreResultV1<()> {
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
    OpenOptions::new()
        .read(true)
        .open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)?;
    sync_parent_directory_v1(path)
}

fn sync_parent_directory_v1(path: &Path) -> RollbackAuthorityStoreResultV1<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|_| RollbackAuthorityStoreErrorV1::StorageFailure)
}
