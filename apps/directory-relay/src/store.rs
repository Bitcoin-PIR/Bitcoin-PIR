//! Owner-only SQLite archive and addressable-head store.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use pir_directory_nostr::{
    nip01_addressable_replacement_order_v1, NostrEventV1, BITCOINPIR_DIRECTORY_KIND_V1,
    DIRECTORY_SHARD_COUNT_V1,
};
use pir_private_files::{
    checked_existing_private_file_v1, create_new_private_file_v1, sync_private_file_and_parent_v1,
    PrivateFileIdentityV1, PrivateFileModeV1,
};
use rusqlite::{
    params, params_from_iter, Connection, InterruptHandle, OpenFlags, OptionalExtension,
    Transaction, TransactionBehavior,
};

use crate::wire::{
    validate_current_event_profile, validate_event_json, DirectoryEventProfile, RequestFilter,
    ValidatedEvent, MAX_CATALOG_EVENTS_PER_SHARD, MAX_DIRECTORY_ENTRIES_PER_SHARD,
    MAX_SNAPSHOT_PAGE_BYTES,
};

const APPLICATION_ID: i64 = 0x4250_4452; // "BPDR"
const SCHEMA_VERSION: i64 = 1;
const PROFILE_NAME: &str = "bitcoinpir-directory-profile-v1";
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

const SCHEMA: &str = r#"
CREATE TABLE metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    profile TEXT NOT NULL,
    directory_pubkey BLOB NOT NULL CHECK (length(directory_pubkey) = 32),
    max_archive_events INTEGER NOT NULL CHECK (max_archive_events > 0),
    max_archive_bytes INTEGER NOT NULL CHECK (max_archive_bytes > 0),
    archive_event_count INTEGER NOT NULL CHECK (archive_event_count >= 0),
    archive_bytes INTEGER NOT NULL CHECK (archive_bytes >= 0),
    created_at INTEGER NOT NULL CHECK (created_at > 0)
) STRICT;
CREATE TABLE events (
    event_id BLOB PRIMARY KEY CHECK (length(event_id) = 32),
    pubkey BLOB NOT NULL CHECK (length(pubkey) = 32),
    kind INTEGER NOT NULL CHECK (kind = 30078),
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    d_tag TEXT NOT NULL CHECK (length(d_tag) BETWEEN 1 AND 255),
    s_tag TEXT NOT NULL CHECK (length(s_tag) BETWEEN 1 AND 128),
    shard INTEGER NOT NULL CHECK (shard BETWEEN 0 AND 15),
    profile INTEGER NOT NULL CHECK (profile IN (1, 2)),
    event_json BLOB NOT NULL CHECK (length(event_json) BETWEEN 1 AND 262144),
    received_at INTEGER NOT NULL CHECK (received_at > 0)
) STRICT;
CREATE TABLE address_heads (
    pubkey BLOB NOT NULL CHECK (length(pubkey) = 32),
    kind INTEGER NOT NULL CHECK (kind = 30078),
    d_tag TEXT NOT NULL CHECK (length(d_tag) BETWEEN 1 AND 255),
    event_id BLOB NOT NULL UNIQUE CHECK (length(event_id) = 32),
    PRIMARY KEY (pubkey, kind, d_tag),
    FOREIGN KEY (event_id) REFERENCES events(event_id) ON DELETE RESTRICT
) STRICT;
CREATE INDEX events_shard_order ON events(shard, d_tag, event_id);
CREATE INDEX events_coordinate_order ON events(pubkey, kind, d_tag, created_at, event_id);
"#;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngestDisposition {
    Saved,
    Duplicate,
    ReplacedByNewer,
    ShardCapacityExceeded,
    ArchiveCapacityExceeded,
    InvalidCurrentEvent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreLimits {
    pub max_archive_events: u64,
    pub max_archive_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotPlan {
    pub event_ids: Vec<[u8; 32]>,
    pub event_json_bytes: u64,
}

pub struct DirectoryStore {
    connection: Connection,
    path: PathBuf,
    sidecars: SidecarSnapshot,
    pinned_directory_pubkey: [u8; 32],
    limits: StoreLimits,
}

impl DirectoryStore {
    pub fn open_or_create(
        path: &Path,
        pinned_directory_pubkey: [u8; 32],
        limits: StoreLimits,
        now_unix: u64,
    ) -> Result<Self, String> {
        if !path.is_absolute() {
            return Err("directory relay database path must be absolute".to_owned());
        }
        if pinned_directory_pubkey.iter().all(|byte| *byte == 0)
            || now_unix == 0
            || limits.max_archive_events == 0
            || limits.max_archive_bytes == 0
            || limits.max_archive_events > i64::MAX as u64
            || limits.max_archive_bytes > i64::MAX as u64
        {
            return Err("directory relay key/time configuration is invalid".to_owned());
        }
        let create = match fs::symlink_metadata(path) {
            Ok(_) => false,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(error) => return Err(format!("inspect directory relay database failed: {error}")),
        };
        if create {
            let file = create_new_private_file_v1(path, "directory relay SQLite database")?;
            file.sync_all()
                .map_err(|error| format!("sync new directory relay database failed: {error}"))?;
            drop(file);
        }
        let checked_before = checked_existing_private_file_v1(
            path,
            PrivateFileModeV1::ReadWrite,
            "directory relay SQLite database",
        )?;
        // The private-file walker returns the component-by-component checked
        // path, including macOS' normalized `/private/var` root alias. Opening
        // the caller spelling (normally `/var/...` for tempfile on macOS)
        // with SQLITE_OPEN_NOFOLLOW would correctly reject that ancestor
        // symlink. Reuse the already checked spelling so SQLite and every
        // sidecar check refer to the same namespace without weakening
        // NOFOLLOW.
        let checked_path = checked_before.path().to_path_buf();
        let sidecars_before = inspect_sidecars_at_path(&checked_path)?;

        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let connection = Connection::open_with_flags(&checked_path, flags)
            .map_err(|error| format!("open directory relay SQLite database failed: {error}"))?;
        configure_connection(&connection)?;
        if create {
            initialize_schema(&connection, &pinned_directory_pubkey, limits, now_unix)?;
            sync_private_file_and_parent_v1(&checked_path, "directory relay SQLite database")?;
        }
        let checked_after = checked_existing_private_file_v1(
            &checked_path,
            PrivateFileModeV1::ReadWrite,
            "directory relay SQLite database",
        )?;
        if checked_after.identity() != checked_before.identity() {
            return Err("directory relay SQLite file changed while it was opened".to_owned());
        }
        let sidecars_after = inspect_sidecars_at_path(&checked_path)?;
        validate_sidecar_open_transition(&sidecars_before, &sidecars_after)?;

        let store = Self {
            connection,
            path: checked_path,
            sidecars: sidecars_after,
            pinned_directory_pubkey,
            limits,
        };
        store.full_startup_validation()?;
        store.validate_sidecars()?;
        Ok(store)
    }

    pub fn interrupt_handle(&self) -> InterruptHandle {
        self.connection.get_interrupt_handle()
    }

    pub fn ingest(
        &mut self,
        event: &ValidatedEvent,
        received_at: u64,
    ) -> Result<IngestDisposition, String> {
        self.ingest_with_commit(event, received_at, |transaction| {
            transaction.commit().map_err(|error| error.to_string())
        })
    }

    fn ingest_with_commit<F>(
        &mut self,
        event: &ValidatedEvent,
        received_at: u64,
        commit: F,
    ) -> Result<IngestDisposition, String>
    where
        F: FnOnce(Transaction<'_>) -> Result<(), String>,
    {
        self.validate_sidecars()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| format!("begin EVENT transaction failed: {error}"))?;

        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT event_json FROM events WHERE event_id = ?1",
                params![event.event.id().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| format!("query duplicate EVENT failed: {error}"))?;
        if let Some(existing) = existing {
            if existing != event.canonical_json {
                return Err("stored EVENT id maps to different bytes".to_owned());
            }
            commit(transaction)
                .map_err(|error| format!("commit duplicate EVENT failed: {error}"))?;
            return Ok(IngestDisposition::Duplicate);
        }

        if received_at == 0 || event.event.created_at() > received_at {
            commit(transaction)
                .map_err(|error| format!("commit invalid EVENT time decision failed: {error}"))?;
            return Ok(IngestDisposition::InvalidCurrentEvent);
        }
        let created_at = i64::try_from(event.event.created_at())
            .map_err(|_| "EVENT timestamp exceeds SQLite range".to_owned())?;
        let received_at = i64::try_from(received_at)
            .map_err(|_| "receive timestamp exceeds SQLite range".to_owned())?;

        if validate_current_event_profile(event, &self.pinned_directory_pubkey, received_at as u64)
            .is_err()
        {
            commit(transaction)
                .map_err(|error| format!("commit invalid EVENT decision failed: {error}"))?;
            return Ok(IngestDisposition::InvalidCurrentEvent);
        }

        let current_json: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT e.event_json FROM address_heads h JOIN events e USING (event_id) \
                 WHERE h.pubkey = ?1 AND h.kind = ?2 AND h.d_tag = ?3",
                params![
                    event.event.pubkey().as_slice(),
                    i64::from(event.event.kind()),
                    &event.d_tag
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| format!("query address head failed: {error}"))?;
        let replacing = current_json.is_some();
        if let Some(current_json) = current_json {
            let current = validate_event_json(
                &current_json,
                &self.pinned_directory_pubkey,
                event.event.created_at().max(1),
            )
            .or_else(|_| {
                let parsed = NostrEventV1::parse_json(&current_json)
                    .map_err(|error| format!("stored address head is invalid: {error}"))?;
                validate_event_json(
                    &current_json,
                    &self.pinned_directory_pubkey,
                    parsed.created_at(),
                )
            })?;
            if nip01_addressable_replacement_order_v1(&event.event, &current.event)
                .map_err(|error| format!("compare addressable EVENT failed: {error}"))?
                != Ordering::Greater
            {
                commit(transaction)
                    .map_err(|error| format!("commit replaced EVENT decision failed: {error}"))?;
                return Ok(IngestDisposition::ReplacedByNewer);
            }
        }

        if !replacing {
            let head_count: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM address_heads h JOIN events e USING (event_id) \
                     WHERE e.shard = ?1 AND e.profile = ?2",
                    params![i64::from(event.shard), profile_code(event.profile)],
                    |row| row.get(0),
                )
                .map_err(|error| format!("count shard heads failed: {error}"))?;
            let capacity = match event.profile {
                DirectoryEventProfile::Entry => MAX_DIRECTORY_ENTRIES_PER_SHARD,
                DirectoryEventProfile::Checkpoint => 1,
            };
            if head_count >= capacity as i64 {
                commit(transaction)
                    .map_err(|error| format!("commit shard-capacity decision failed: {error}"))?;
                return Ok(IngestDisposition::ShardCapacityExceeded);
            }
        }

        let (archive_count, archive_bytes): (i64, i64) = transaction
            .query_row(
                "SELECT archive_event_count, archive_bytes FROM metadata WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| format!("read archive capacity failed: {error}"))?;
        let candidate_bytes = i64::try_from(event.canonical_json.len())
            .map_err(|_| "EVENT length exceeds SQLite range".to_owned())?;
        if archive_count >= self.limits.max_archive_events as i64
            || archive_bytes
                .checked_add(candidate_bytes)
                .map_or(true, |total| total > self.limits.max_archive_bytes as i64)
        {
            commit(transaction)
                .map_err(|error| format!("commit archive-capacity decision failed: {error}"))?;
            return Ok(IngestDisposition::ArchiveCapacityExceeded);
        }

        transaction
            .execute(
                "INSERT INTO events \
                 (event_id, pubkey, kind, created_at, d_tag, s_tag, shard, profile, event_json, received_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    event.event.id().as_slice(),
                    event.event.pubkey().as_slice(),
                    i64::from(event.event.kind()),
                    created_at,
                    &event.d_tag,
                    &event.s_tag,
                    i64::from(event.shard),
                    profile_code(event.profile),
                    &event.canonical_json,
                    received_at,
                ],
            )
            .map_err(|error| format!("archive EVENT failed: {error}"))?;
        transaction
            .execute(
                "UPDATE metadata SET archive_event_count = archive_event_count + 1, \
                 archive_bytes = archive_bytes + ?1 WHERE singleton = 1",
                params![candidate_bytes],
            )
            .map_err(|error| format!("advance archive capacity counters failed: {error}"))?;
        transaction
            .execute(
                "INSERT INTO address_heads (pubkey, kind, d_tag, event_id) VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(pubkey, kind, d_tag) DO UPDATE SET event_id = excluded.event_id",
                params![
                    event.event.pubkey().as_slice(),
                    i64::from(event.event.kind()),
                    &event.d_tag,
                    event.event.id().as_slice(),
                ],
            )
            .map_err(|error| format!("advance address head failed: {error}"))?;
        commit(transaction).map_err(|error| format!("commit EVENT failed: {error}"))?;
        self.validate_sidecars()?;
        Ok(IngestDisposition::Saved)
    }

    pub fn freeze_snapshot(&self, filter: &RequestFilter) -> Result<SnapshotPlan, String> {
        self.validate_sidecars()?;
        let result = match filter {
            RequestFilter::Catalog { shard } => self.catalog_snapshot_ids(*shard),
            RequestFilter::Ids(ids) => self.readback_snapshot_ids(ids),
        };
        self.validate_sidecars()?;
        result
    }

    fn catalog_snapshot_ids(&self, shard: u8) -> Result<SnapshotPlan, String> {
        if shard >= DIRECTORY_SHARD_COUNT_V1 {
            return Err("catalog shard is invalid".to_owned());
        }
        let mut statement = self
            .connection
            .prepare(
                "SELECT e.event_id, length(e.event_json) FROM address_heads h JOIN events e USING (event_id) \
                 WHERE e.pubkey = ?1 AND e.kind = ?2 AND e.shard = ?3 \
                 ORDER BY e.d_tag ASC, e.event_id ASC",
            )
            .map_err(|error| format!("prepare catalog snapshot failed: {error}"))?;
        let mut rows = statement
            .query(params![
                self.pinned_directory_pubkey.as_slice(),
                i64::from(BITCOINPIR_DIRECTORY_KIND_V1),
                i64::from(shard)
            ])
            .map_err(|error| format!("query catalog snapshot failed: {error}"))?;
        let mut event_ids = Vec::new();
        let mut event_json_bytes = 0u64;
        while let Some(row) = rows
            .next()
            .map_err(|error| format!("read catalog snapshot failed: {error}"))?
        {
            let event_id: Vec<u8> = row
                .get(0)
                .map_err(|error| format!("decode catalog snapshot failed: {error}"))?;
            let event_bytes: i64 = row
                .get(1)
                .map_err(|error| format!("decode catalog event length failed: {error}"))?;
            let event_bytes = u64::try_from(event_bytes)
                .map_err(|_| "catalog snapshot contains an invalid event length".to_owned())?;
            event_json_bytes = event_json_bytes
                .checked_add(event_bytes)
                .ok_or_else(|| "catalog snapshot byte count overflow".to_owned())?;
            event_ids.push(
                event_id
                    .try_into()
                    .map_err(|_| "catalog snapshot contains an invalid event id".to_owned())?,
            );
        }
        if event_ids.len() > MAX_CATALOG_EVENTS_PER_SHARD {
            return Err("catalog shard exceeds the protocol event bound".to_owned());
        }
        Ok(SnapshotPlan {
            event_ids,
            event_json_bytes,
        })
    }

    fn readback_snapshot_ids(&self, ids: &[[u8; 32]]) -> Result<SnapshotPlan, String> {
        if ids.is_empty() {
            return Err("ID readback snapshot cannot be empty".to_owned());
        }
        let placeholders = std::iter::repeat("?")
            .take(ids.len())
            .collect::<Vec<_>>()
            .join(",");
        let mut statement = self
            .connection
            .prepare(&format!(
                "SELECT event_id, length(event_json) FROM events WHERE event_id IN ({placeholders})"
            ))
            .map_err(|error| format!("prepare ID readback failed: {error}"))?;
        let rows = statement
            .query_map(
                params_from_iter(ids.iter().map(|id| id.as_slice())),
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
            )
            .map_err(|error| format!("query ID readback failed: {error}"))?;
        let mut lengths = HashMap::with_capacity(ids.len());
        for row in rows {
            let (event_id, event_bytes) =
                row.map_err(|error| format!("decode ID readback failed: {error}"))?;
            let event_id: [u8; 32] = event_id
                .try_into()
                .map_err(|_| "ID readback returned an invalid event id".to_owned())?;
            let event_bytes = u64::try_from(event_bytes)
                .map_err(|_| "readback event length is invalid".to_owned())?;
            if lengths.insert(event_id, event_bytes).is_some() {
                return Err("ID readback returned a duplicate event id".to_owned());
            }
        }

        let mut found = Vec::with_capacity(lengths.len());
        let mut event_json_bytes = 0u64;
        for id in ids {
            if let Some(event_bytes) = lengths.remove(id) {
                event_json_bytes = event_json_bytes
                    .checked_add(event_bytes)
                    .ok_or_else(|| "readback snapshot byte count overflow".to_owned())?;
                found.push(*id);
            }
        }
        Ok(SnapshotPlan {
            event_ids: found,
            event_json_bytes,
        })
    }

    pub fn load_snapshot_page(&self, ids: &[[u8; 32]]) -> Result<Vec<Vec<u8>>, String> {
        self.validate_sidecars()?;
        if ids.is_empty() || ids.len() > 8 {
            return Err("snapshot page must contain 1..=8 immutable event ids".to_owned());
        }
        let mut statement = self
            .connection
            .prepare("SELECT event_json FROM events WHERE event_id = ?1")
            .map_err(|error| format!("prepare snapshot page failed: {error}"))?;
        let mut events = Vec::with_capacity(ids.len());
        let mut bytes = 0usize;
        for id in ids {
            let event: Vec<u8> = statement
                .query_row(params![id.as_slice()], |row| row.get(0))
                .map_err(|error| format!("frozen snapshot EVENT disappeared: {error}"))?;
            reserve_snapshot_event(&mut bytes, &event)?;
            events.push(event);
        }
        self.validate_sidecars()?;
        Ok(events)
    }

    fn full_startup_validation(&self) -> Result<(), String> {
        validate_pragmas_and_schema(&self.connection)?;
        let integrity_rows = {
            let mut statement = self
                .connection
                .prepare("PRAGMA integrity_check")
                .map_err(|error| format!("prepare integrity_check failed: {error}"))?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|error| format!("run integrity_check failed: {error}"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| format!("read integrity_check failed: {error}"))?;
            rows
        };
        if integrity_rows.as_slice() != ["ok"] {
            return Err(format!(
                "directory relay SQLite integrity_check failed: {}",
                integrity_rows.join("; ")
            ));
        }
        let foreign_violation: Option<i64> = self
            .connection
            .query_row(
                "SELECT 1 FROM pragma_foreign_key_check LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| format!("run foreign_key_check failed: {error}"))?;
        if foreign_violation.is_some() {
            return Err("directory relay SQLite foreign_key_check failed".to_owned());
        }
        let metadata: Vec<(String, Vec<u8>, i64, i64, i64, i64)> = {
            let mut statement = self
                .connection
                .prepare(
                    "SELECT profile, directory_pubkey, max_archive_events, max_archive_bytes, \
                     archive_event_count, archive_bytes \
                     FROM metadata WHERE singleton = 1",
                )
                .map_err(|error| format!("prepare metadata validation failed: {error}"))?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                })
                .map_err(|error| format!("query metadata failed: {error}"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| format!("read metadata failed: {error}"))?;
            rows
        };
        if metadata.len() != 1
            || metadata[0].0 != PROFILE_NAME
            || metadata[0].1.as_slice() != self.pinned_directory_pubkey
            || metadata[0].2 != self.limits.max_archive_events as i64
            || metadata[0].3 != self.limits.max_archive_bytes as i64
        {
            return Err(
                "directory relay profile/key metadata does not match configuration".to_owned(),
            );
        }

        let mut winners = BTreeMap::<(Vec<u8>, u16, String), WinnerRecord>::new();
        let mut archive_count = 0u64;
        let mut archive_bytes = 0u64;
        {
            let mut statement = self
                .connection
                .prepare(
                    "SELECT event_id, pubkey, kind, created_at, d_tag, s_tag, shard, profile, \
                     event_json, received_at FROM events ORDER BY event_id",
                )
                .map_err(|error| format!("prepare archive validation failed: {error}"))?;
            let mut rows = statement
                .query([])
                .map_err(|error| format!("query archive validation failed: {error}"))?;
            while let Some(row) = rows
                .next()
                .map_err(|error| format!("read archive validation failed: {error}"))?
            {
                archive_count = archive_count
                    .checked_add(1)
                    .ok_or_else(|| "archive event count overflow".to_owned())?;
                if archive_count > self.limits.max_archive_events {
                    return Err("stored archive exceeds configured event capacity".to_owned());
                }
                let event_id: Vec<u8> = row
                    .get(0)
                    .map_err(|error| format!("decode archive event id failed: {error}"))?;
                let pubkey: Vec<u8> = row
                    .get(1)
                    .map_err(|error| format!("decode archive pubkey failed: {error}"))?;
                let kind: i64 = row
                    .get(2)
                    .map_err(|error| format!("decode archive kind failed: {error}"))?;
                let created_at: i64 = row
                    .get(3)
                    .map_err(|error| format!("decode archive timestamp failed: {error}"))?;
                let d_tag: String = row
                    .get(4)
                    .map_err(|error| format!("decode archive d tag failed: {error}"))?;
                let s_tag: String = row
                    .get(5)
                    .map_err(|error| format!("decode archive s tag failed: {error}"))?;
                let shard: i64 = row
                    .get(6)
                    .map_err(|error| format!("decode archive shard failed: {error}"))?;
                let profile: i64 = row
                    .get(7)
                    .map_err(|error| format!("decode archive profile failed: {error}"))?;
                let event_json: Vec<u8> = row
                    .get(8)
                    .map_err(|error| format!("decode archive event failed: {error}"))?;
                let received_at: i64 = row
                    .get(9)
                    .map_err(|error| format!("decode archive receive time failed: {error}"))?;
                archive_bytes = archive_bytes
                    .checked_add(event_json.len() as u64)
                    .ok_or_else(|| "archive byte count overflow".to_owned())?;
                if archive_bytes > self.limits.max_archive_bytes {
                    return Err("stored archive exceeds configured byte capacity".to_owned());
                }

                let parsed = NostrEventV1::parse_json(&event_json)
                    .map_err(|error| format!("stored EVENT parse failed: {error}"))?;
                let validated = validate_event_json(
                    &event_json,
                    &self.pinned_directory_pubkey,
                    parsed.created_at(),
                )?;
                validate_current_event_profile(
                    &validated,
                    &self.pinned_directory_pubkey,
                    parsed.created_at(),
                )?;
                if event_id.as_slice() != validated.event.id()
                    || pubkey.as_slice() != validated.event.pubkey()
                    || u16::try_from(kind).ok() != Some(validated.event.kind())
                    || u64::try_from(created_at).ok() != Some(validated.event.created_at())
                    || d_tag != validated.d_tag
                    || s_tag != validated.s_tag
                    || u8::try_from(shard).ok() != Some(validated.shard)
                    || profile != profile_code(validated.profile)
                    || received_at < created_at
                {
                    return Err("stored EVENT columns disagree with the signed event".to_owned());
                }
                let event_id: [u8; 32] = event_id
                    .try_into()
                    .map_err(|_| "stored EVENT id has the wrong length".to_owned())?;
                let coordinate = (
                    validated.event.pubkey().to_vec(),
                    validated.event.kind(),
                    validated.d_tag,
                );
                let candidate = WinnerRecord {
                    event_id,
                    created_at: validated.event.created_at(),
                    shard: validated.shard,
                    profile: validated.profile,
                };
                if let Some(current) = winners.get_mut(&coordinate) {
                    if candidate.created_at > current.created_at
                        || (candidate.created_at == current.created_at
                            && candidate.event_id < current.event_id)
                    {
                        *current = candidate;
                    }
                } else {
                    if winners.len()
                        >= DIRECTORY_SHARD_COUNT_V1 as usize * MAX_CATALOG_EVENTS_PER_SHARD
                    {
                        return Err("archive contains too many addressable coordinates".to_owned());
                    }
                    winners.insert(coordinate, candidate);
                }
            }
        }
        if metadata[0].4 != archive_count as i64 || metadata[0].5 != archive_bytes as i64 {
            return Err("archive capacity counters disagree with immutable rows".to_owned());
        }

        let mut entry_counts = [0usize; DIRECTORY_SHARD_COUNT_V1 as usize];
        let mut checkpoint_counts = [0usize; DIRECTORY_SHARD_COUNT_V1 as usize];
        let mut head_count = 0usize;
        {
            let mut statement = self
                .connection
                .prepare(
                    "SELECT pubkey, kind, d_tag, event_id FROM address_heads \
                     ORDER BY pubkey, kind, d_tag",
                )
                .map_err(|error| format!("prepare head validation failed: {error}"))?;
            let mut rows = statement
                .query([])
                .map_err(|error| format!("query head validation failed: {error}"))?;
            while let Some(row) = rows
                .next()
                .map_err(|error| format!("read head validation failed: {error}"))?
            {
                head_count += 1;
                if head_count > DIRECTORY_SHARD_COUNT_V1 as usize * MAX_CATALOG_EVENTS_PER_SHARD {
                    return Err("address head set exceeds the protocol bound".to_owned());
                }
                let pubkey: Vec<u8> = row
                    .get(0)
                    .map_err(|error| format!("decode head pubkey failed: {error}"))?;
                let kind: i64 = row
                    .get(1)
                    .map_err(|error| format!("decode head kind failed: {error}"))?;
                let d_tag: String = row
                    .get(2)
                    .map_err(|error| format!("decode head d tag failed: {error}"))?;
                let event_id: Vec<u8> = row
                    .get(3)
                    .map_err(|error| format!("decode head event id failed: {error}"))?;
                let coordinate = (
                    pubkey,
                    u16::try_from(kind).map_err(|_| "address head kind is invalid".to_owned())?,
                    d_tag,
                );
                let winner = winners
                    .remove(&coordinate)
                    .ok_or_else(|| "address head has no matching archive coordinate".to_owned())?;
                if event_id.as_slice() != winner.event_id {
                    return Err("address head is not the winning archived EVENT".to_owned());
                }
                match winner.profile {
                    DirectoryEventProfile::Entry => entry_counts[usize::from(winner.shard)] += 1,
                    DirectoryEventProfile::Checkpoint => {
                        checkpoint_counts[usize::from(winner.shard)] += 1
                    }
                }
            }
        }
        if !winners.is_empty() {
            return Err("address head set does not cover every archived coordinate".to_owned());
        }
        if entry_counts
            .iter()
            .any(|count| *count > MAX_DIRECTORY_ENTRIES_PER_SHARD)
            || checkpoint_counts.iter().any(|count| *count > 1)
        {
            return Err("stored catalog shard exceeds the protocol bound".to_owned());
        }
        Ok(())
    }

    fn validate_sidecars(&self) -> Result<(), String> {
        let current = inspect_sidecars_at_path(&self.path)?;
        if current != self.sidecars {
            return Err("directory relay SQLite sidecar identity changed while open".to_owned());
        }
        Ok(())
    }
}

struct WinnerRecord {
    event_id: [u8; 32],
    created_at: u64,
    shard: u8,
    profile: DirectoryEventProfile,
}

fn configure_connection(connection: &Connection) -> Result<(), String> {
    let journal: String = connection
        .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
        .map_err(|error| format!("enable SQLite WAL failed: {error}"))?;
    if !journal.eq_ignore_ascii_case("wal") {
        return Err("directory relay SQLite did not enter WAL mode".to_owned());
    }
    connection
        .pragma_update(None, "synchronous", "FULL")
        .and_then(|_| connection.pragma_update(None, "foreign_keys", true))
        .and_then(|_| connection.pragma_update(None, "trusted_schema", false))
        .and_then(|_| connection.pragma_update(None, "temp_store", "MEMORY"))
        .and_then(|_| connection.busy_timeout(BUSY_TIMEOUT))
        .map_err(|error| format!("configure directory relay SQLite failed: {error}"))?;
    Ok(())
}

fn initialize_schema(
    connection: &Connection,
    directory_pubkey: &[u8; 32],
    limits: StoreLimits,
    now_unix: u64,
) -> Result<(), String> {
    connection
        .execute_batch(&format!(
            "BEGIN IMMEDIATE; PRAGMA application_id = {APPLICATION_ID}; \
             PRAGMA user_version = {SCHEMA_VERSION}; {SCHEMA}"
        ))
        .map_err(|error| format!("create directory relay schema failed: {error}"))?;
    connection
        .execute(
            "INSERT INTO metadata \
             (singleton, profile, directory_pubkey, max_archive_events, max_archive_bytes, \
              archive_event_count, archive_bytes, created_at) \
             VALUES (1, ?1, ?2, ?3, ?4, 0, 0, ?5)",
            params![
                PROFILE_NAME,
                directory_pubkey.as_slice(),
                i64::try_from(limits.max_archive_events)
                    .map_err(|_| "archive event limit exceeds SQLite range")?,
                i64::try_from(limits.max_archive_bytes)
                    .map_err(|_| "archive byte limit exceeds SQLite range")?,
                i64::try_from(now_unix).map_err(|_| "metadata time exceeds SQLite range")?,
            ],
        )
        .map_err(|error| format!("write directory relay metadata failed: {error}"))?;
    connection
        .execute_batch("COMMIT")
        .map_err(|error| format!("commit directory relay schema failed: {error}"))?;
    Ok(())
}

fn validate_pragmas_and_schema(connection: &Connection) -> Result<(), String> {
    let application_id: i64 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(|error| format!("read application_id failed: {error}"))?;
    let user_version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| format!("read user_version failed: {error}"))?;
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(|error| format!("read synchronous failed: {error}"))?;
    let foreign_keys: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(|error| format!("read foreign_keys failed: {error}"))?;
    let trusted_schema: i64 = connection
        .query_row("PRAGMA trusted_schema", [], |row| row.get(0))
        .map_err(|error| format!("read trusted_schema failed: {error}"))?;
    let journal: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(|error| format!("read journal_mode failed: {error}"))?;
    if application_id != APPLICATION_ID
        || user_version != SCHEMA_VERSION
        || synchronous != 2
        || foreign_keys != 1
        || trusted_schema != 0
        || !journal.eq_ignore_ascii_case("wal")
    {
        return Err("directory relay SQLite pragma/schema identity mismatch".to_owned());
    }
    let actual = schema_entries(connection)?;
    let expected_connection = Connection::open_in_memory()
        .map_err(|error| format!("open expected schema database failed: {error}"))?;
    expected_connection
        .execute_batch(SCHEMA)
        .map_err(|error| format!("create expected directory schema failed: {error}"))?;
    let expected = schema_entries(&expected_connection)?;
    if actual != expected {
        return Err("directory relay SQLite DDL differs from the exact v1 schema".to_owned());
    }
    Ok(())
}

fn schema_entries(connection: &Connection) -> Result<Vec<(String, String, String)>, String> {
    let mut statement = connection
        .prepare(
            "SELECT type, name, sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' \
             AND type IN ('table', 'index', 'view', 'trigger') AND sql IS NOT NULL \
             ORDER BY type, name",
        )
        .map_err(|error| format!("prepare schema name validation failed: {error}"))?;
    let entries = statement
        .query_map([], |row| {
            let sql: String = row.get(2)?;
            Ok((
                row.get(0)?,
                row.get(1)?,
                sql.split_whitespace()
                    .collect::<String>()
                    .to_ascii_lowercase(),
            ))
        })
        .map_err(|error| format!("query schema names failed: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("read schema names failed: {error}"))?;
    Ok(entries)
}

fn reserve_snapshot_event(total: &mut usize, event: &[u8]) -> Result<(), String> {
    *total = total
        .checked_add(event.len())
        .ok_or_else(|| "snapshot byte count overflow".to_owned())?;
    if *total > MAX_SNAPSHOT_PAGE_BYTES {
        return Err("snapshot exceeds the bounded 2 MiB response profile".to_owned());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SidecarSnapshot {
    wal: Option<PrivateFileIdentityV1>,
    shm: Option<PrivateFileIdentityV1>,
}

fn inspect_sidecars_at_path(database: &Path) -> Result<SidecarSnapshot, String> {
    let mut identities = [None, None];
    for (index, suffix) in ["-wal", "-shm"].into_iter().enumerate() {
        let mut sidecar_name = database.as_os_str().to_os_string();
        sidecar_name.push(suffix);
        let path = PathBuf::from(sidecar_name);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                identities[index] = Some(
                    checked_existing_private_file_v1(
                        &path,
                        PrivateFileModeV1::ReadWrite,
                        "directory relay SQLite sidecar",
                    )?
                    .identity(),
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "inspect directory relay SQLite sidecar failed: {error}"
                ));
            }
        }
    }
    Ok(SidecarSnapshot {
        wal: identities[0],
        shm: identities[1],
    })
}

fn validate_sidecar_open_transition(
    before: &SidecarSnapshot,
    after: &SidecarSnapshot,
) -> Result<(), String> {
    for (label, before, after) in [
        ("WAL", before.wal, after.wal),
        ("SHM", before.shm, after.shm),
    ] {
        if before.is_some() && before != after {
            return Err(format!(
                "directory relay SQLite {label} sidecar changed while database opened"
            ));
        }
    }
    Ok(())
}

fn profile_code(profile: DirectoryEventProfile) -> i64 {
    match profile {
        DirectoryEventProfile::Entry => 1,
        DirectoryEventProfile::Checkpoint => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::os::unix::fs::PermissionsExt;

    use pir_directory_nostr::{
        DirectoryCatalogCheckpointV1, DirectoryEntryV1, DirectoryHealthClassV1, DirectoryHealthV1,
        DirectoryPublisherKeyV1,
    };

    const NOW: u64 = 2_000_000;

    fn test_store(key: &[u8; 32]) -> (tempfile::TempDir, DirectoryStore) {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("relay.sqlite");
        let store = DirectoryStore::open_or_create(
            &path,
            *key,
            StoreLimits {
                max_archive_events: 10_000,
                max_archive_bytes: 64 * 1024 * 1024,
            },
            NOW,
        )
        .unwrap();
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        (directory, store)
    }

    fn event(
        publisher: &DirectoryPublisherKeyV1,
        provider: [u8; 32],
        sequence: u64,
        created_at: u64,
        randomness: u8,
    ) -> ValidatedEvent {
        let entry = DirectoryEntryV1::new_tombstone(
            provider,
            sequence,
            created_at + 10_000,
            DirectoryHealthV1 {
                class: DirectoryHealthClassV1::Unknown,
                observed_bucket: created_at - (created_at % 300),
            },
            created_at,
        )
        .unwrap();
        let signed = publisher
            .sign_entry_event(&entry, created_at, &[randomness; 32])
            .unwrap();
        validate_event_json(
            &signed.to_json_bytes().unwrap(),
            publisher.public_key(),
            NOW,
        )
        .unwrap()
    }

    #[test]
    fn replacement_duplicate_restart_and_superseded_readback() {
        let publisher = DirectoryPublisherKeyV1::from_secret_bytes([41; 32]).unwrap();
        let (directory, mut store) = test_store(publisher.public_key());
        let provider = [0x21; 32];
        let first = event(&publisher, provider, 1, NOW - 20, 1);
        let second = event(&publisher, provider, 2, NOW - 10, 2);
        assert_eq!(store.ingest(&first, NOW).unwrap(), IngestDisposition::Saved);
        let frozen_before_replacement = store
            .freeze_snapshot(&RequestFilter::Catalog { shard: 2 })
            .unwrap();
        assert_eq!(frozen_before_replacement.event_ids, vec![*first.event.id()]);
        assert_eq!(
            store.ingest(&first, NOW).unwrap(),
            IngestDisposition::Duplicate
        );
        assert_eq!(
            store.ingest(&second, NOW).unwrap(),
            IngestDisposition::Saved
        );
        assert_eq!(
            store.ingest(&first, NOW).unwrap(),
            IngestDisposition::Duplicate,
            "superseded archive remains an idempotent positive duplicate"
        );
        let catalog = store
            .freeze_snapshot(&RequestFilter::Catalog { shard: 2 })
            .unwrap();
        assert_eq!(catalog.event_ids, vec![*second.event.id()]);
        let frozen_events = store
            .load_snapshot_page(&frozen_before_replacement.event_ids)
            .unwrap();
        assert_eq!(frozen_events, vec![first.canonical_json.clone()]);
        let readback = store
            .freeze_snapshot(&RequestFilter::Ids(vec![
                *first.event.id(),
                *second.event.id(),
            ]))
            .unwrap();
        assert_eq!(readback.event_ids.len(), 2);
        assert_eq!(
            store.load_snapshot_page(&readback.event_ids).unwrap().len(),
            2
        );
        let path = directory.path().join("relay.sqlite");
        drop(store);
        DirectoryStore::open_or_create(
            &path,
            *publisher.public_key(),
            StoreLimits {
                max_archive_events: 10_000,
                max_archive_bytes: 64 * 1024 * 1024,
            },
            NOW,
        )
        .unwrap();
    }

    #[test]
    fn commit_failure_never_persists_event() {
        let publisher = DirectoryPublisherKeyV1::from_secret_bytes([42; 32]).unwrap();
        let (directory, mut store) = test_store(publisher.public_key());
        let candidate = event(&publisher, [0x31; 32], 1, NOW - 1, 3);
        let result = store.ingest_with_commit(&candidate, NOW, |_transaction| {
            Err("injected commit failure".to_owned())
        });
        assert!(result.is_err());
        assert!(store
            .freeze_snapshot(&RequestFilter::Ids(vec![*candidate.event.id()]))
            .unwrap()
            .event_ids
            .is_empty());
        let path = directory.path().join("relay.sqlite");
        drop(store);
        let reopened = DirectoryStore::open_or_create(
            &path,
            *publisher.public_key(),
            StoreLimits {
                max_archive_events: 10_000,
                max_archive_bytes: 64 * 1024 * 1024,
            },
            NOW,
        )
        .unwrap();
        assert!(reopened
            .freeze_snapshot(&RequestFilter::Ids(vec![*candidate.event.id()]))
            .unwrap()
            .event_ids
            .is_empty());
    }

    #[test]
    fn equal_timestamp_lower_event_id_wins() {
        let publisher = DirectoryPublisherKeyV1::from_secret_bytes([43; 32]).unwrap();
        let (_directory, mut store) = test_store(publisher.public_key());
        let a = event(&publisher, [0x41; 32], 1, NOW - 1, 4);
        // Schnorr auxiliary randomness changes only the signature, while a
        // Nostr event ID excludes the signature. Vary signed content as well
        // so this genuinely exercises NIP-01's equal-timestamp event-ID
        // tiebreak rather than the same ID with non-canonical alternate bytes.
        let b = event(&publisher, [0x41; 32], 2, NOW - 1, 5);
        assert_ne!(a.event.id(), b.event.id());
        let (lower, higher) = if a.event.id() < b.event.id() {
            (a, b)
        } else {
            (b, a)
        };
        assert_eq!(
            store.ingest(&higher, NOW).unwrap(),
            IngestDisposition::Saved
        );
        assert_eq!(store.ingest(&lower, NOW).unwrap(), IngestDisposition::Saved);
        assert_eq!(
            store.ingest(&higher, NOW).unwrap(),
            IngestDisposition::Duplicate
        );
        let snapshot = store
            .freeze_snapshot(&RequestFilter::Catalog { shard: 4 })
            .unwrap();
        assert_eq!(snapshot.event_ids, vec![*lower.event.id()]);
    }

    #[test]
    fn wrong_key_fails_restart() {
        let publisher = DirectoryPublisherKeyV1::from_secret_bytes([44; 32]).unwrap();
        let wrong = DirectoryPublisherKeyV1::from_secret_bytes([45; 32]).unwrap();
        let (directory, store) = test_store(publisher.public_key());
        let path = directory.path().join("relay.sqlite");
        drop(store);
        assert!(DirectoryStore::open_or_create(
            &path,
            *wrong.public_key(),
            StoreLimits {
                max_archive_events: 10_000,
                max_archive_bytes: 64 * 1024 * 1024,
            },
            NOW,
        )
        .is_err());
    }

    #[test]
    fn expired_and_superseded_exact_duplicate_remains_idempotent() {
        let publisher = DirectoryPublisherKeyV1::from_secret_bytes([46; 32]).unwrap();
        let (directory, mut store) = test_store(publisher.public_key());
        let first = event(&publisher, [0x51; 32], 1, NOW - 20, 7);
        let second = event(&publisher, [0x51; 32], 2, NOW - 10, 8);
        assert_eq!(store.ingest(&first, NOW).unwrap(), IngestDisposition::Saved);
        assert_eq!(
            store.ingest(&second, NOW).unwrap(),
            IngestDisposition::Saved
        );
        assert_eq!(
            store.ingest(&first, first.event.created_at() - 1).unwrap(),
            IngestDisposition::Duplicate
        );
        assert_eq!(
            store.ingest(&first, NOW + 20_000).unwrap(),
            IngestDisposition::Duplicate
        );
        let expired_new = event(&publisher, [0x52; 32], 1, NOW - 20, 9);
        assert_eq!(
            store.ingest(&expired_new, NOW + 20_000).unwrap(),
            IngestDisposition::InvalidCurrentEvent
        );
        assert!(store
            .freeze_snapshot(&RequestFilter::Ids(vec![*expired_new.event.id()]))
            .unwrap()
            .event_ids
            .is_empty());
        let path = directory.path().join("relay.sqlite");
        drop(store);
        let mut reopened = DirectoryStore::open_or_create(
            &path,
            *publisher.public_key(),
            StoreLimits {
                max_archive_events: 10_000,
                max_archive_bytes: 64 * 1024 * 1024,
            },
            NOW + 20_000,
        )
        .unwrap();
        assert_eq!(
            reopened.ingest(&first, NOW + 20_000).unwrap(),
            IngestDisposition::Duplicate,
            "restart and natural expiry cannot invalidate a durable duplicate"
        );
    }

    #[test]
    fn archive_capacity_is_atomic_and_never_evicts_frozen_ids() {
        let publisher = DirectoryPublisherKeyV1::from_secret_bytes([47; 32]).unwrap();
        let first = event(&publisher, [0x61; 32], 1, NOW - 2, 10);
        let second = event(&publisher, [0x62; 32], 1, NOW - 1, 11);
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("capacity.sqlite");
        let limits = StoreLimits {
            max_archive_events: 1,
            max_archive_bytes: first.canonical_json.len() as u64,
        };
        let mut store =
            DirectoryStore::open_or_create(&path, *publisher.public_key(), limits, NOW).unwrap();
        assert_eq!(store.ingest(&first, NOW).unwrap(), IngestDisposition::Saved);
        assert_eq!(
            store.ingest(&second, NOW).unwrap(),
            IngestDisposition::ArchiveCapacityExceeded
        );
        assert_eq!(
            store
                .freeze_snapshot(&RequestFilter::Ids(vec![
                    *first.event.id(),
                    *second.event.id()
                ]))
                .unwrap()
                .event_ids,
            vec![*first.event.id()]
        );
        drop(store);
        DirectoryStore::open_or_create(&path, *publisher.public_key(), limits, NOW).unwrap();
    }

    #[test]
    fn exact_schema_rejects_added_trigger_on_restart() {
        let publisher = DirectoryPublisherKeyV1::from_secret_bytes([48; 32]).unwrap();
        let (directory, store) = test_store(publisher.public_key());
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER forbidden_trigger AFTER INSERT ON events BEGIN SELECT 1; END;",
            )
            .unwrap();
        let path = directory.path().join("relay.sqlite");
        drop(store);
        assert!(DirectoryStore::open_or_create(
            &path,
            *publisher.public_key(),
            StoreLimits {
                max_archive_events: 10_000,
                max_archive_bytes: 64 * 1024 * 1024,
            },
            NOW,
        )
        .is_err());
    }

    #[test]
    fn shard_supports_1024_entries_plus_one_checkpoint() {
        let publisher = DirectoryPublisherKeyV1::from_secret_bytes([49; 32]).unwrap();
        let (_directory, mut store) = test_store(publisher.public_key());
        let checkpoint =
            DirectoryCatalogCheckpointV1::new(0, 1, NOW - 100, NOW + 1_000, vec![], NOW).unwrap();
        let checkpoint = publisher
            .sign_checkpoint_event(&checkpoint, NOW, &[12; 32])
            .unwrap();
        let checkpoint = validate_event_json(
            &checkpoint.to_json_bytes().unwrap(),
            publisher.public_key(),
            NOW,
        )
        .unwrap();
        assert_eq!(
            store.ingest(&checkpoint, NOW).unwrap(),
            IngestDisposition::Saved
        );
        for index in 0..MAX_DIRECTORY_ENTRIES_PER_SHARD {
            let mut provider = [0_u8; 32];
            provider[0] = 1;
            provider[24..].copy_from_slice(&(index as u64).to_be_bytes());
            let entry = event(&publisher, provider, 1, NOW - 1, index as u8);
            assert_eq!(store.ingest(&entry, NOW).unwrap(), IngestDisposition::Saved);
        }
        let mut extra_provider = [0_u8; 32];
        extra_provider[0] = 1;
        extra_provider[24..]
            .copy_from_slice(&(MAX_DIRECTORY_ENTRIES_PER_SHARD as u64).to_be_bytes());
        let extra = event(&publisher, extra_provider, 1, NOW - 1, 13);
        assert_eq!(
            store.ingest(&extra, NOW).unwrap(),
            IngestDisposition::ShardCapacityExceeded
        );
        assert_eq!(
            store
                .freeze_snapshot(&RequestFilter::Catalog { shard: 0 })
                .unwrap()
                .event_ids
                .len(),
            MAX_CATALOG_EVENTS_PER_SHARD
        );
    }

    #[test]
    fn sidecars_reject_broken_symlink_mode_hardlink_and_identity_change() {
        let publisher = DirectoryPublisherKeyV1::from_secret_bytes([50; 32]).unwrap();
        let limits = StoreLimits {
            max_archive_events: 10_000,
            max_archive_bytes: 64 * 1024 * 1024,
        };

        let broken = tempfile::tempdir().unwrap();
        fs::set_permissions(broken.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let broken_db = broken.path().join("broken.sqlite");
        symlink(
            broken.path().join("missing-target"),
            broken.path().join("broken.sqlite-wal"),
        )
        .unwrap();
        assert!(
            DirectoryStore::open_or_create(&broken_db, *publisher.public_key(), limits, NOW)
                .is_err()
        );

        let wrong_mode = tempfile::tempdir().unwrap();
        fs::set_permissions(wrong_mode.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let wrong_mode_db = wrong_mode.path().join("mode.sqlite");
        let wrong_mode_wal = wrong_mode.path().join("mode.sqlite-wal");
        fs::write(&wrong_mode_wal, b"not-a-wal").unwrap();
        fs::set_permissions(&wrong_mode_wal, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(DirectoryStore::open_or_create(
            &wrong_mode_db,
            *publisher.public_key(),
            limits,
            NOW
        )
        .is_err());

        let linked = tempfile::tempdir().unwrap();
        fs::set_permissions(linked.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let linked_db = linked.path().join("linked.sqlite");
        let linked_wal = linked.path().join("linked.sqlite-wal");
        fs::write(&linked_wal, b"not-a-wal").unwrap();
        fs::set_permissions(&linked_wal, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&linked_wal, linked.path().join("second-link")).unwrap();
        assert!(
            DirectoryStore::open_or_create(&linked_db, *publisher.public_key(), limits, NOW)
                .is_err()
        );

        let replaced = tempfile::tempdir().unwrap();
        fs::set_permissions(replaced.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let replaced_db = replaced.path().join("replaced.sqlite");
        let replaced_wal = replaced.path().join("replaced.sqlite-wal");
        fs::write(&replaced_wal, b"first").unwrap();
        fs::set_permissions(&replaced_wal, fs::Permissions::from_mode(0o600)).unwrap();
        let before = inspect_sidecars_at_path(&replaced_db).unwrap();
        let replacement = replaced.path().join("replacement");
        fs::write(&replacement, b"second").unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(replacement, &replaced_wal).unwrap();
        let after = inspect_sidecars_at_path(&replaced_db).unwrap();
        assert!(validate_sidecar_open_transition(&before, &after).is_err());
    }

    #[test]
    fn live_sidecar_replacement_fails_before_snapshot_access() {
        let publisher = DirectoryPublisherKeyV1::from_secret_bytes([51; 32]).unwrap();
        let (directory, store) = test_store(publisher.public_key());
        assert!(store.sidecars.wal.is_some());
        let wal = directory.path().join("relay.sqlite-wal");
        let replacement = directory.path().join("replacement-wal");
        fs::write(&replacement, b"replacement").unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(replacement, wal).unwrap();
        assert!(store
            .freeze_snapshot(&RequestFilter::Catalog { shard: 0 })
            .is_err());
    }
}
