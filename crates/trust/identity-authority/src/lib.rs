//! Owner-only durable reservations for future server identity generations.
//!
//! This crate is deliberately absent from the server runtime. An inactive
//! reservation is only an allocation, never an active identity certificate.
//! The caller must persist the returned [`IdentityAuthorityHeadV1`] outside
//! this database and supply it on restart; an older or forked database then
//! fails closed.

#![forbid(unsafe_code)]

use ed25519_dalek::VerifyingKey;
use pir_identity::{GenerationBoundIdentityCertV2, IdentityError};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

const APPLICATION_ID: i64 = 0x4250_4941;
const SCHEMA_VERSION: i64 = 1;
const MAX_SERVER_ID_BYTES: usize = 256;
pub const MAX_IDENTITY_ACTIVATION_BYTES_V2: usize = 1024;
const INITIAL_HEAD_DOMAIN_V1: &[u8] = b"BitcoinPIR/identity-authority/initial-head/v1";
const MUTATION_HEAD_DOMAIN_V1: &[u8] = b"BitcoinPIR/identity-authority/mutation-head/v1";
const RESERVE_OPERATION_V1: &[u8] = b"reserve-identity-generation-v2";
const ACTIVATE_OPERATION_V1: &[u8] = b"activate-identity-generation-v2";
const HEAD_FILE_DOMAIN_V1: &[u8] = b"BPIR-IDENTITY-AUTHORITY-HEAD-V1\0";
pub const IDENTITY_AUTHORITY_HEAD_BYTES_V1: usize = HEAD_FILE_DOMAIN_V1.len() + 16 + 32 + 8 + 32;

const IDENTITY_SQL: &str = r#"CREATE TABLE identity_authority_state (
    singleton          INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
    registry_id        BLOB NOT NULL CHECK (length(registry_id) = 16 AND registry_id != zeroblob(16)),
    operator_pubkey    BLOB NOT NULL CHECK (length(operator_pubkey) = 32 AND operator_pubkey != zeroblob(32)),
    commit_seq         INTEGER NOT NULL CHECK (commit_seq >= 0),
    commitment         BLOB NOT NULL CHECK (length(commitment) = 32 AND commitment != zeroblob(32))
) STRICT"#;

const RESERVATIONS_SQL: &str = r#"CREATE TABLE identity_generation_reservations (
    server_id                    TEXT NOT NULL CHECK (length(server_id) BETWEEN 1 AND 256),
    identity_generation          INTEGER NOT NULL CHECK (identity_generation > 0),
    identity_pubkey              BLOB CHECK (
        identity_pubkey IS NULL OR
        (length(identity_pubkey) = 32 AND identity_pubkey != zeroblob(32))
    ),
    state                        INTEGER NOT NULL CHECK (state IN (0, 1)),
    exact_activation             BLOB CHECK (
        exact_activation IS NULL OR length(exact_activation) BETWEEN 1 AND 1024
    ),
    reservation_commit_seq       INTEGER NOT NULL CHECK (reservation_commit_seq > 0),
    activation_commit_seq        INTEGER CHECK (
        activation_commit_seq IS NULL OR activation_commit_seq > reservation_commit_seq
    ),
    PRIMARY KEY (server_id, identity_generation),
    UNIQUE (identity_pubkey),
    CHECK ((state = 0 AND identity_pubkey IS NULL AND exact_activation IS NULL AND activation_commit_seq IS NULL) OR
           (state = 1 AND identity_pubkey IS NOT NULL AND exact_activation IS NOT NULL AND activation_commit_seq IS NOT NULL))
) STRICT, WITHOUT ROWID"#;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentityAuthorityHeadV1 {
    pub registry_id: [u8; 16],
    pub operator_pubkey: [u8; 32],
    pub commit_seq: u64,
    pub commitment: [u8; 32],
}

impl IdentityAuthorityHeadV1 {
    pub fn initial(
        registry_id: [u8; 16],
        operator_pubkey: [u8; 32],
    ) -> IdentityAuthorityResultV1<Self> {
        validate_authority_identity(&registry_id, &operator_pubkey)?;
        Ok(Self {
            registry_id,
            operator_pubkey,
            commit_seq: 0,
            commitment: initial_commitment(&registry_id, &operator_pubkey),
        })
    }

    pub fn encode(self) -> [u8; IDENTITY_AUTHORITY_HEAD_BYTES_V1] {
        let mut encoded = [0u8; IDENTITY_AUTHORITY_HEAD_BYTES_V1];
        let mut position = 0usize;
        for field in [
            HEAD_FILE_DOMAIN_V1,
            self.registry_id.as_slice(),
            self.operator_pubkey.as_slice(),
            self.commit_seq.to_le_bytes().as_slice(),
            self.commitment.as_slice(),
        ] {
            let end = position + field.len();
            encoded[position..end].copy_from_slice(field);
            position = end;
        }
        encoded
    }

    pub fn decode(encoded: &[u8]) -> IdentityAuthorityResultV1<Self> {
        if encoded.len() != IDENTITY_AUTHORITY_HEAD_BYTES_V1
            || encoded.get(..HEAD_FILE_DOMAIN_V1.len()) != Some(HEAD_FILE_DOMAIN_V1)
        {
            return Err(IdentityAuthorityErrorV1::InvalidInput(
                "external head is not canonical V1",
            ));
        }
        let mut position = HEAD_FILE_DOMAIN_V1.len();
        let registry_id = take_fixed_input::<16>(encoded, &mut position)?;
        let operator_pubkey = take_fixed_input::<32>(encoded, &mut position)?;
        let commit_seq = u64::from_le_bytes(take_fixed_input::<8>(encoded, &mut position)?);
        let commitment = take_fixed_input::<32>(encoded, &mut position)?;
        validate_authority_identity(&registry_id, &operator_pubkey)?;
        if commitment.iter().all(|byte| *byte == 0) {
            return Err(IdentityAuthorityErrorV1::InvalidInput(
                "external head commitment is zero",
            ));
        }
        Ok(Self {
            registry_id,
            operator_pubkey,
            commit_seq,
            commitment,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityGenerationReservationV2 {
    pub server_id: String,
    pub identity_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityGenerationReservationStateV2 {
    Inactive,
    Active {
        identity_pubkey: [u8; 32],
        exact_activation: Vec<u8>,
        activation_commit_seq: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityGenerationReservationRecordV2 {
    pub reservation: IdentityGenerationReservationV2,
    pub state: IdentityGenerationReservationStateV2,
    pub reservation_commit_seq: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityAuthorityWriteDispositionV1 {
    Committed,
    ExactReplay,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityAuthorityWriteV1<T> {
    pub disposition: IdentityAuthorityWriteDispositionV1,
    pub head: IdentityAuthorityHeadV1,
    pub value: T,
}

#[derive(Debug)]
pub enum IdentityAuthorityErrorV1 {
    InvalidInput(&'static str),
    DatabaseAlreadyExists,
    MissingDatabase,
    UnsafeDatabase,
    SchemaMismatch(&'static str),
    IdentityMismatch,
    RollbackDetected,
    HeadFork,
    ReservationRollback,
    ReservationExists,
    ReservationMissing,
    ReservationMismatch,
    ActivationFork,
    RecoveryMismatch,
    Identity(IdentityError),
    Storage(String),
}

impl fmt::Display for IdentityAuthorityErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(reason) => {
                write!(formatter, "invalid identity authority input: {reason}")
            }
            Self::DatabaseAlreadyExists => {
                write!(formatter, "identity authority database already exists")
            }
            Self::MissingDatabase => write!(formatter, "identity authority database is missing"),
            Self::UnsafeDatabase => write!(formatter, "identity authority database path is unsafe"),
            Self::SchemaMismatch(reason) => {
                write!(formatter, "identity authority schema mismatch: {reason}")
            }
            Self::IdentityMismatch => write!(formatter, "identity authority identity mismatch"),
            Self::RollbackDetected => {
                write!(formatter, "identity authority database rollback detected")
            }
            Self::HeadFork => write!(formatter, "identity authority database head fork detected"),
            Self::ReservationRollback => write!(formatter, "identity generation rollback rejected"),
            Self::ReservationExists => write!(formatter, "identity generation is already reserved"),
            Self::ReservationMissing => {
                write!(formatter, "identity generation reservation is missing")
            }
            Self::ReservationMismatch => write!(
                formatter,
                "identity activation does not match its reservation"
            ),
            Self::ActivationFork => {
                write!(formatter, "identity generation has a different activation")
            }
            Self::RecoveryMismatch => {
                write!(
                    formatter,
                    "identity authority successor is not the expected lost operation"
                )
            }
            Self::Identity(error) => write!(formatter, "identity artifact invalid: {error}"),
            Self::Storage(error) => write!(formatter, "identity authority storage error: {error}"),
        }
    }
}

impl std::error::Error for IdentityAuthorityErrorV1 {}

impl From<rusqlite::Error> for IdentityAuthorityErrorV1 {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(error.to_string())
    }
}

impl From<std::io::Error> for IdentityAuthorityErrorV1 {
    fn from(error: std::io::Error) -> Self {
        Self::Storage(error.to_string())
    }
}

impl From<IdentityError> for IdentityAuthorityErrorV1 {
    fn from(error: IdentityError) -> Self {
        Self::Identity(error)
    }
}

pub type IdentityAuthorityResultV1<T> = Result<T, IdentityAuthorityErrorV1>;

pub struct IdentityAuthorityStoreV1 {
    path: PathBuf,
    file_identity: pir_private_files::PrivateFileIdentityV1,
    head: IdentityAuthorityHeadV1,
}

impl IdentityAuthorityStoreV1 {
    pub fn create(
        path: impl AsRef<Path>,
        registry_id: [u8; 16],
        operator_pubkey: [u8; 32],
    ) -> IdentityAuthorityResultV1<Self> {
        validate_authority_identity(&registry_id, &operator_pubkey)?;
        let path = path.as_ref();
        if path.as_os_str().is_empty() {
            return Err(IdentityAuthorityErrorV1::InvalidInput(
                "database path is empty",
            ));
        }
        if fs::symlink_metadata(path).is_ok() {
            return Err(IdentityAuthorityErrorV1::DatabaseAlreadyExists);
        }
        let path = pir_private_files::prepare_new_private_file_v1(
            path,
            false,
            "identity authority database",
        )
        .map_err(|_| IdentityAuthorityErrorV1::UnsafeDatabase)?;
        let file =
            pir_private_files::create_new_private_file_v1(&path, "identity authority database")
                .map_err(|_| IdentityAuthorityErrorV1::DatabaseAlreadyExists)?;
        file.sync_all()?;
        drop(file);
        let head = IdentityAuthorityHeadV1::initial(registry_id, operator_pubkey)?;
        let created = checked_file(&path)?;
        let connection = open_pinned(created.path(), created.identity())?;
        configure(&connection)?;
        connection.execute_batch("BEGIN IMMEDIATE")?;
        let setup = (|| -> IdentityAuthorityResultV1<()> {
            connection.execute_batch(IDENTITY_SQL)?;
            connection.execute_batch(RESERVATIONS_SQL)?;
            connection.pragma_update(None, "application_id", APPLICATION_ID)?;
            connection.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            connection.execute(
                "INSERT INTO identity_authority_state \
                 (singleton, registry_id, operator_pubkey, commit_seq, commitment) \
                 VALUES (1, ?1, ?2, 0, ?3)",
                params![
                    registry_id.as_slice(),
                    operator_pubkey.as_slice(),
                    head.commitment.as_slice(),
                ],
            )?;
            Ok(())
        })();
        if let Err(error) = setup {
            let _ = connection.execute_batch("ROLLBACK");
            return Err(error);
        }
        connection.execute_batch("COMMIT")?;
        pir_private_files::sync_private_file_and_parent_v1(&path, "identity authority database")
            .map_err(IdentityAuthorityErrorV1::Storage)?;
        drop(connection);
        Self::open_existing(path, registry_id, operator_pubkey, head)
    }

    pub fn open_existing(
        path: impl AsRef<Path>,
        expected_registry_id: [u8; 16],
        expected_operator_pubkey: [u8; 32],
        expected_head: IdentityAuthorityHeadV1,
    ) -> IdentityAuthorityResultV1<Self> {
        validate_authority_identity(&expected_registry_id, &expected_operator_pubkey)?;
        if expected_head.registry_id != expected_registry_id
            || expected_head.operator_pubkey != expected_operator_pubkey
        {
            return Err(IdentityAuthorityErrorV1::IdentityMismatch);
        }
        let checked = checked_file(path.as_ref())?;
        let connection = open_pinned(checked.path(), checked.identity())?;
        configure(&connection)?;
        validate_schema(&connection)?;
        let observed = read_head(&connection)?;
        verify_expected_head(&observed, &expected_head)?;
        verify_registry(&connection, &observed)?;
        drop(connection);
        Ok(Self {
            path: checked.path().to_path_buf(),
            file_identity: checked.identity(),
            head: observed,
        })
    }

    /// Recover only the single fully verified successor that reserves these
    /// exact coordinates. Ordinary opens never weaken to this crash recovery.
    pub fn recover_reservation_successor(
        path: impl AsRef<Path>,
        expected_head: IdentityAuthorityHeadV1,
        expected_reservation: &IdentityGenerationReservationV2,
    ) -> IdentityAuthorityResultV1<Self> {
        validate_reservation(expected_reservation)?;
        Self::recover_expected_successor(
            path.as_ref(),
            expected_head,
            RESERVE_OPERATION_V1,
            reserve_digest(expected_reservation),
        )
    }

    /// Recover only the single fully verified successor that activates the
    /// exact canonical signed certificate supplied by the owner.
    pub fn recover_activation_successor(
        path: impl AsRef<Path>,
        expected_head: IdentityAuthorityHeadV1,
        expected_activation: &GenerationBoundIdentityCertV2,
    ) -> IdentityAuthorityResultV1<Self> {
        expected_activation.verify()?;
        if expected_activation.operator_pubkey != expected_head.operator_pubkey {
            return Err(IdentityAuthorityErrorV1::ReservationMismatch);
        }
        if expected_activation.identity_pubkey == expected_head.operator_pubkey {
            return Err(IdentityAuthorityErrorV1::ReservationMismatch);
        }
        let exact = expected_activation.encode();
        if exact.len() > MAX_IDENTITY_ACTIVATION_BYTES_V2 {
            return Err(IdentityAuthorityErrorV1::InvalidInput(
                "activation exceeds bound",
            ));
        }
        Self::recover_expected_successor(
            path.as_ref(),
            expected_head,
            ACTIVATE_OPERATION_V1,
            activation_digest(&exact),
        )
    }

    fn recover_expected_successor(
        path: &Path,
        expected_head: IdentityAuthorityHeadV1,
        expected_operation: &'static [u8],
        expected_digest: [u8; 32],
    ) -> IdentityAuthorityResultV1<Self> {
        validate_authority_identity(&expected_head.registry_id, &expected_head.operator_pubkey)?;
        let checked = checked_file(path)?;
        let connection = open_pinned(checked.path(), checked.identity())?;
        configure(&connection)?;
        validate_schema(&connection)?;
        let observed = read_head(&connection)?;
        if observed.registry_id != expected_head.registry_id
            || observed.operator_pubkey != expected_head.operator_pubkey
        {
            return Err(IdentityAuthorityErrorV1::IdentityMismatch);
        }
        let expected_successor = expected_head
            .commit_seq
            .checked_add(1)
            .ok_or(IdentityAuthorityErrorV1::HeadFork)?;
        if observed.commit_seq < expected_head.commit_seq {
            return Err(IdentityAuthorityErrorV1::RollbackDetected);
        }
        if observed.commit_seq != expected_successor {
            return Err(IdentityAuthorityErrorV1::HeadFork);
        }
        let events = registry_events(&connection, &observed)?;
        verify_reconstructed_head(&events, &observed, observed.commit_seq)?;
        let predecessor = reconstruct_head(&events, &observed, expected_head.commit_seq)?;
        if predecessor != expected_head {
            return Err(IdentityAuthorityErrorV1::HeadFork);
        }
        if !matches!(
            events.last(),
            Some((sequence, operation, digest))
                if *sequence == observed.commit_seq
                    && *operation == expected_operation
                    && *digest == expected_digest
        ) {
            return Err(IdentityAuthorityErrorV1::RecoveryMismatch);
        }
        drop(connection);
        Ok(Self {
            path: checked.path().to_path_buf(),
            file_identity: checked.identity(),
            head: observed,
        })
    }

    pub fn head(&self) -> IdentityAuthorityHeadV1 {
        self.head
    }

    pub fn reservation(
        &self,
        server_id: &str,
        identity_generation: u64,
    ) -> IdentityAuthorityResultV1<Option<IdentityGenerationReservationRecordV2>> {
        validate_server_generation(server_id, identity_generation)?;
        let connection = self.open_checked()?;
        read_reservation(&connection, &self.head, server_id, identity_generation)
    }

    pub fn reserve_generation(
        &mut self,
        reservation: IdentityGenerationReservationV2,
    ) -> IdentityAuthorityResultV1<IdentityAuthorityWriteV1<IdentityGenerationReservationRecordV2>>
    {
        validate_reservation(&reservation)?;
        let mut connection = self.open_checked()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let observed = read_head(&transaction)?;
        verify_expected_head(&observed, &self.head)?;
        if read_reservation(
            &transaction,
            &self.head,
            &reservation.server_id,
            reservation.identity_generation,
        )?
        .is_some()
        {
            return Err(IdentityAuthorityErrorV1::ReservationExists);
        }
        let highest: Option<i64> = transaction.query_row(
            "SELECT MAX(identity_generation) FROM identity_generation_reservations WHERE server_id = ?1",
            [reservation.server_id.as_str()],
            |row| row.get(0),
        )?;
        if highest.unwrap_or(0) >= sql_u64(reservation.identity_generation)? {
            return Err(IdentityAuthorityErrorV1::ReservationRollback);
        }
        let digest = reserve_digest(&reservation);
        let next = advance_head(&observed, RESERVE_OPERATION_V1, &digest)?;
        transaction.execute(
            "INSERT INTO identity_generation_reservations \
             (server_id, identity_generation, identity_pubkey, state, exact_activation, \
              reservation_commit_seq, activation_commit_seq) VALUES (?1, ?2, NULL, 0, NULL, ?3, NULL)",
            params![
                reservation.server_id.as_str(),
                sql_u64(reservation.identity_generation)?,
                sql_u64(next.commit_seq)?,
            ],
        )?;
        write_head(&transaction, &next)?;
        transaction.commit()?;
        sync_database(&self.path)?;
        self.head = next;
        let value = self
            .reservation(&reservation.server_id, reservation.identity_generation)?
            .ok_or(IdentityAuthorityErrorV1::SchemaMismatch(
                "committed reservation missing",
            ))?;
        Ok(IdentityAuthorityWriteV1 {
            disposition: IdentityAuthorityWriteDispositionV1::Committed,
            head: next,
            value,
        })
    }

    pub fn activate(
        &mut self,
        activation: &GenerationBoundIdentityCertV2,
        now_unix: i64,
    ) -> IdentityAuthorityResultV1<IdentityAuthorityWriteV1<IdentityGenerationReservationRecordV2>>
    {
        activation.verify()?;
        if activation.operator_pubkey != self.head.operator_pubkey {
            return Err(IdentityAuthorityErrorV1::ReservationMismatch);
        }
        if activation.identity_pubkey == self.head.operator_pubkey {
            return Err(IdentityAuthorityErrorV1::ReservationMismatch);
        }
        let exact = activation.encode();
        if exact.len() > MAX_IDENTITY_ACTIVATION_BYTES_V2 {
            return Err(IdentityAuthorityErrorV1::InvalidInput(
                "activation exceeds bound",
            ));
        }
        let mut connection = self.open_checked()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let observed = read_head(&transaction)?;
        verify_expected_head(&observed, &self.head)?;
        let existing = read_reservation(
            &transaction,
            &self.head,
            &activation.server_id,
            activation.identity_generation,
        )?
        .ok_or(IdentityAuthorityErrorV1::ReservationMissing)?;
        match &existing.state {
            IdentityGenerationReservationStateV2::Active {
                exact_activation, ..
            } => {
                if exact_activation == &exact {
                    return Ok(IdentityAuthorityWriteV1 {
                        disposition: IdentityAuthorityWriteDispositionV1::ExactReplay,
                        head: self.head,
                        value: existing,
                    });
                }
                return Err(IdentityAuthorityErrorV1::ActivationFork);
            }
            IdentityGenerationReservationStateV2::Inactive => {}
        }
        let reused_identity: Option<i64> = transaction
            .query_row(
                "SELECT 1 FROM identity_generation_reservations WHERE identity_pubkey = ?1 LIMIT 1",
                [activation.identity_pubkey.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        if reused_identity.is_some() {
            return Err(IdentityAuthorityErrorV1::ActivationFork);
        }
        activation.check_validity(now_unix)?;
        let digest = activation_digest(&exact);
        let next = advance_head(&observed, ACTIVATE_OPERATION_V1, &digest)?;
        let changed = transaction.execute(
            "UPDATE identity_generation_reservations SET state = 1, identity_pubkey = ?1, \
                    exact_activation = ?2, activation_commit_seq = ?3 \
             WHERE server_id = ?4 AND identity_generation = ?5 AND state = 0 \
               AND identity_pubkey IS NULL",
            params![
                activation.identity_pubkey.as_slice(),
                exact.as_slice(),
                sql_u64(next.commit_seq)?,
                activation.server_id.as_str(),
                sql_u64(activation.identity_generation)?,
            ],
        )?;
        if changed != 1 {
            return Err(IdentityAuthorityErrorV1::ReservationMismatch);
        }
        write_head(&transaction, &next)?;
        transaction.commit()?;
        sync_database(&self.path)?;
        self.head = next;
        let value = self
            .reservation(&activation.server_id, activation.identity_generation)?
            .ok_or(IdentityAuthorityErrorV1::SchemaMismatch(
                "committed activation missing",
            ))?;
        Ok(IdentityAuthorityWriteV1 {
            disposition: IdentityAuthorityWriteDispositionV1::Committed,
            head: next,
            value,
        })
    }

    fn open_checked(&self) -> IdentityAuthorityResultV1<Connection> {
        let checked = checked_file(&self.path)?;
        if checked.identity() != self.file_identity {
            return Err(IdentityAuthorityErrorV1::UnsafeDatabase);
        }
        let connection = open_pinned(checked.path(), checked.identity())?;
        configure(&connection)?;
        validate_schema(&connection)?;
        let observed = read_head(&connection)?;
        verify_expected_head(&observed, &self.head)?;
        verify_registry(&connection, &observed)?;
        Ok(connection)
    }
}

fn checked_file(path: &Path) -> IdentityAuthorityResultV1<pir_private_files::CheckedPrivateFileV1> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(IdentityAuthorityErrorV1::MissingDatabase)
        }
        Err(error) => return Err(error.into()),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_file() => {
            return Err(IdentityAuthorityErrorV1::UnsafeDatabase)
        }
        Ok(_) => {}
    }
    pir_private_files::checked_existing_private_file_v1(
        path,
        pir_private_files::PrivateFileModeV1::ReadWrite,
        "identity authority database",
    )
    .map_err(|_| IdentityAuthorityErrorV1::UnsafeDatabase)
}

fn open_raw(path: &Path) -> IdentityAuthorityResultV1<Connection> {
    Ok(Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?)
}

fn open_pinned(
    path: &Path,
    expected_identity: pir_private_files::PrivateFileIdentityV1,
) -> IdentityAuthorityResultV1<Connection> {
    let connection = open_raw(path)?;
    let after = checked_file(path)?;
    if after.identity() != expected_identity {
        return Err(IdentityAuthorityErrorV1::UnsafeDatabase);
    }
    Ok(connection)
}

fn configure(connection: &Connection) -> IdentityAuthorityResultV1<()> {
    let journal: String =
        connection.query_row("PRAGMA journal_mode = DELETE", [], |row| row.get(0))?;
    if !journal.eq_ignore_ascii_case("delete") {
        return Err(IdentityAuthorityErrorV1::SchemaMismatch("journal mode"));
    }
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "trusted_schema", false)?;
    Ok(())
}

fn validate_schema(connection: &Connection) -> IdentityAuthorityResultV1<()> {
    let application_id: i64 =
        connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    let user_version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if application_id != APPLICATION_ID || user_version != SCHEMA_VERSION {
        return Err(IdentityAuthorityErrorV1::SchemaMismatch("version"));
    }
    let tables = connection
        .prepare("SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    if tables
        != [
            "identity_authority_state",
            "identity_generation_reservations",
        ]
    {
        return Err(IdentityAuthorityErrorV1::SchemaMismatch("table set"));
    }
    let definitions = connection
        .prepare("SELECT name, sql FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")?
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    let expected = [
        ("identity_authority_state", IDENTITY_SQL),
        ("identity_generation_reservations", RESERVATIONS_SQL),
    ];
    if definitions.len() != expected.len()
        || definitions
            .iter()
            .zip(expected.iter())
            .any(|(actual, expected)| {
                actual.0 != expected.0 || normalize_sql(&actual.1) != normalize_sql(expected.1)
            })
    {
        return Err(IdentityAuthorityErrorV1::SchemaMismatch("table definition"));
    }
    Ok(())
}

fn validate_authority_identity(
    registry_id: &[u8; 16],
    operator: &[u8; 32],
) -> IdentityAuthorityResultV1<()> {
    if registry_id.iter().all(|byte| *byte == 0) {
        return Err(IdentityAuthorityErrorV1::InvalidInput(
            "registry id is zero",
        ));
    }
    if operator.iter().all(|byte| *byte == 0) {
        return Err(IdentityAuthorityErrorV1::InvalidInput(
            "operator key is invalid",
        ));
    }
    VerifyingKey::from_bytes(operator)
        .map_err(|_| IdentityAuthorityErrorV1::InvalidInput("operator key is invalid"))?;
    Ok(())
}

fn validate_server_generation(server_id: &str, generation: u64) -> IdentityAuthorityResultV1<()> {
    if server_id.is_empty() || server_id.len() > MAX_SERVER_ID_BYTES {
        return Err(IdentityAuthorityErrorV1::InvalidInput(
            "server id is invalid",
        ));
    }
    if generation == 0 {
        return Err(IdentityAuthorityErrorV1::InvalidInput(
            "identity generation is zero",
        ));
    }
    Ok(())
}

fn validate_reservation(
    reservation: &IdentityGenerationReservationV2,
) -> IdentityAuthorityResultV1<()> {
    validate_server_generation(&reservation.server_id, reservation.identity_generation)
}

fn read_head(connection: &Connection) -> IdentityAuthorityResultV1<IdentityAuthorityHeadV1> {
    let raw: (Vec<u8>, Vec<u8>, i64, Vec<u8>) = connection.query_row(
        "SELECT registry_id, operator_pubkey, commit_seq, commitment \
         FROM identity_authority_state WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    Ok(IdentityAuthorityHeadV1 {
        registry_id: fixed(raw.0, "registry id")?,
        operator_pubkey: fixed(raw.1, "operator key")?,
        commit_seq: db_u64(raw.2)?,
        commitment: fixed(raw.3, "commitment")?,
    })
}

fn write_head(
    connection: &Connection,
    head: &IdentityAuthorityHeadV1,
) -> IdentityAuthorityResultV1<()> {
    let changed = connection.execute(
        "UPDATE identity_authority_state SET commit_seq = ?1, commitment = ?2 WHERE singleton = 1",
        params![sql_u64(head.commit_seq)?, head.commitment.as_slice()],
    )?;
    if changed != 1 {
        return Err(IdentityAuthorityErrorV1::SchemaMismatch(
            "identity singleton",
        ));
    }
    Ok(())
}

fn verify_expected_head(
    observed: &IdentityAuthorityHeadV1,
    expected: &IdentityAuthorityHeadV1,
) -> IdentityAuthorityResultV1<()> {
    if observed.registry_id != expected.registry_id
        || observed.operator_pubkey != expected.operator_pubkey
    {
        return Err(IdentityAuthorityErrorV1::IdentityMismatch);
    }
    if observed == expected {
        return Ok(());
    }
    if observed.commit_seq < expected.commit_seq {
        return Err(IdentityAuthorityErrorV1::RollbackDetected);
    }
    Err(IdentityAuthorityErrorV1::HeadFork)
}

fn read_reservation(
    connection: &Connection,
    head: &IdentityAuthorityHeadV1,
    server_id: &str,
    generation: u64,
) -> IdentityAuthorityResultV1<Option<IdentityGenerationReservationRecordV2>> {
    type Raw = (Option<Vec<u8>>, i64, Option<Vec<u8>>, i64, Option<i64>);
    let raw: Option<Raw> = connection
        .query_row(
            "SELECT identity_pubkey, state, exact_activation, reservation_commit_seq, activation_commit_seq \
             FROM identity_generation_reservations WHERE server_id = ?1 AND identity_generation = ?2",
            params![server_id, sql_u64(generation)?],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .optional()?;
    raw.map(|raw| rebuild_reservation(head, server_id, generation, raw))
        .transpose()
}

fn rebuild_reservation(
    head: &IdentityAuthorityHeadV1,
    server_id: &str,
    generation: u64,
    raw: (Option<Vec<u8>>, i64, Option<Vec<u8>>, i64, Option<i64>),
) -> IdentityAuthorityResultV1<IdentityGenerationReservationRecordV2> {
    validate_server_generation(server_id, generation)
        .map_err(|_| IdentityAuthorityErrorV1::SchemaMismatch("server generation"))?;
    let reservation_commit_seq = db_u64(raw.3)?;
    let state = match (raw.0, raw.1, raw.2, raw.4) {
        (None, 0, None, None) => IdentityGenerationReservationStateV2::Inactive,
        (Some(key), 1, Some(exact), Some(commit)) => {
            let identity_pubkey = fixed(key, "identity key")?;
            VerifyingKey::from_bytes(&identity_pubkey)
                .map_err(|_| IdentityAuthorityErrorV1::SchemaMismatch("identity key"))?;
            let cert = GenerationBoundIdentityCertV2::decode(&exact)?;
            cert.verify()?;
            if cert.operator_pubkey != head.operator_pubkey
                || cert.server_id != server_id
                || cert.identity_generation != generation
                || cert.identity_pubkey != identity_pubkey
                || identity_pubkey == head.operator_pubkey
            {
                return Err(IdentityAuthorityErrorV1::SchemaMismatch(
                    "activation binding",
                ));
            }
            IdentityGenerationReservationStateV2::Active {
                identity_pubkey,
                exact_activation: exact,
                activation_commit_seq: db_u64(commit)?,
            }
        }
        _ => {
            return Err(IdentityAuthorityErrorV1::SchemaMismatch(
                "reservation state",
            ))
        }
    };
    Ok(IdentityGenerationReservationRecordV2 {
        reservation: IdentityGenerationReservationV2 {
            server_id: server_id.to_owned(),
            identity_generation: generation,
        },
        state,
        reservation_commit_seq,
    })
}

type RegistryEventV1 = (u64, &'static [u8], [u8; 32]);

fn registry_events(
    connection: &Connection,
    head: &IdentityAuthorityHeadV1,
) -> IdentityAuthorityResultV1<Vec<RegistryEventV1>> {
    let mut statement = connection.prepare(
        "SELECT server_id, identity_generation, identity_pubkey, state, exact_activation, \
                reservation_commit_seq, activation_commit_seq \
         FROM identity_generation_reservations ORDER BY server_id, identity_generation",
    )?;
    let mut rows = statement.query([])?;
    let mut events: Vec<RegistryEventV1> = Vec::new();
    let mut previous_server = String::new();
    let mut previous_generation = 0u64;
    while let Some(row) = rows.next()? {
        let server_id: String = row.get(0)?;
        let generation = db_u64(row.get(1)?)?;
        let raw = (
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
        );
        let record = rebuild_reservation(head, &server_id, generation, raw)?;
        if server_id == previous_server && generation <= previous_generation {
            return Err(IdentityAuthorityErrorV1::SchemaMismatch("generation order"));
        }
        previous_server = server_id;
        previous_generation = generation;
        events.push((
            record.reservation_commit_seq,
            RESERVE_OPERATION_V1,
            reserve_digest(&record.reservation),
        ));
        if let IdentityGenerationReservationStateV2::Active {
            exact_activation,
            activation_commit_seq,
            ..
        } = record.state
        {
            events.push((
                activation_commit_seq,
                ACTIVATE_OPERATION_V1,
                activation_digest(&exact_activation),
            ));
        }
    }
    events.sort_by_key(|event| event.0);
    Ok(events)
}

fn reconstruct_head(
    events: &[RegistryEventV1],
    identity: &IdentityAuthorityHeadV1,
    target_commit_seq: u64,
) -> IdentityAuthorityResultV1<IdentityAuthorityHeadV1> {
    if target_commit_seq > events.len() as u64 {
        return Err(IdentityAuthorityErrorV1::SchemaMismatch(
            "commit sequence exceeds registry",
        ));
    }
    let mut reconstructed = IdentityAuthorityHeadV1 {
        registry_id: identity.registry_id,
        operator_pubkey: identity.operator_pubkey,
        commit_seq: 0,
        commitment: initial_commitment(&identity.registry_id, &identity.operator_pubkey),
    };
    for (index, (sequence, operation, digest)) in events.iter().enumerate() {
        if *sequence != (index as u64) + 1 {
            return Err(IdentityAuthorityErrorV1::SchemaMismatch(
                "commit sequence gap",
            ));
        }
        if *sequence > target_commit_seq {
            break;
        }
        reconstructed = advance_head(&reconstructed, operation, digest)?;
    }
    Ok(reconstructed)
}

fn verify_reconstructed_head(
    events: &[RegistryEventV1],
    head: &IdentityAuthorityHeadV1,
    target_commit_seq: u64,
) -> IdentityAuthorityResultV1<()> {
    if events.len() as u64 != head.commit_seq
        || target_commit_seq != head.commit_seq
        || reconstruct_head(events, head, target_commit_seq)? != *head
    {
        return Err(IdentityAuthorityErrorV1::HeadFork);
    }
    Ok(())
}

fn verify_registry(
    connection: &Connection,
    head: &IdentityAuthorityHeadV1,
) -> IdentityAuthorityResultV1<()> {
    let events = registry_events(connection, head)?;
    verify_reconstructed_head(&events, head, head.commit_seq)
}

fn reserve_digest(reservation: &IdentityGenerationReservationV2) -> [u8; 32] {
    digest_parts(&[
        reservation.server_id.as_bytes(),
        &reservation.identity_generation.to_le_bytes(),
    ])
}

fn activation_digest(exact: &[u8]) -> [u8; 32] {
    digest_parts(&[exact])
}

fn digest_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn initial_commitment(registry_id: &[u8; 16], operator: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(INITIAL_HEAD_DOMAIN_V1);
    hasher.update(registry_id);
    hasher.update(operator);
    hasher.finalize().into()
}

fn advance_head(
    previous: &IdentityAuthorityHeadV1,
    operation: &[u8],
    mutation: &[u8; 32],
) -> IdentityAuthorityResultV1<IdentityAuthorityHeadV1> {
    let commit_seq =
        previous
            .commit_seq
            .checked_add(1)
            .ok_or(IdentityAuthorityErrorV1::SchemaMismatch(
                "commit sequence exhausted",
            ))?;
    let mut hasher = Sha256::new();
    hasher.update(MUTATION_HEAD_DOMAIN_V1);
    hasher.update(previous.commitment);
    hasher.update(commit_seq.to_le_bytes());
    hasher.update((operation.len() as u64).to_le_bytes());
    hasher.update(operation);
    hasher.update(mutation);
    Ok(IdentityAuthorityHeadV1 {
        registry_id: previous.registry_id,
        operator_pubkey: previous.operator_pubkey,
        commit_seq,
        commitment: hasher.finalize().into(),
    })
}

fn fixed<const N: usize>(
    bytes: Vec<u8>,
    field: &'static str,
) -> IdentityAuthorityResultV1<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| IdentityAuthorityErrorV1::SchemaMismatch(field))
}

fn take_fixed_input<const N: usize>(
    encoded: &[u8],
    position: &mut usize,
) -> IdentityAuthorityResultV1<[u8; N]> {
    let end = position
        .checked_add(N)
        .ok_or(IdentityAuthorityErrorV1::InvalidInput(
            "external head length overflow",
        ))?;
    let bytes = encoded
        .get(*position..end)
        .ok_or(IdentityAuthorityErrorV1::InvalidInput(
            "external head is truncated",
        ))?;
    let mut output = [0u8; N];
    output.copy_from_slice(bytes);
    *position = end;
    Ok(output)
}

fn db_u64(value: i64) -> IdentityAuthorityResultV1<u64> {
    u64::try_from(value).map_err(|_| IdentityAuthorityErrorV1::SchemaMismatch("negative integer"))
}

fn sql_u64(value: u64) -> IdentityAuthorityResultV1<i64> {
    i64::try_from(value)
        .map_err(|_| IdentityAuthorityErrorV1::InvalidInput("integer exceeds SQLite range"))
}

fn sync_database(path: &Path) -> IdentityAuthorityResultV1<()> {
    pir_private_files::sync_private_file_and_parent_v1(path, "identity authority database")
        .map_err(IdentityAuthorityErrorV1::Storage)
}

fn normalize_sql(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use pir_identity::sign_generation_bound_identity_cert_v2;
    use tempfile::TempDir;

    fn fixture() -> (TempDir, IdentityAuthorityStoreV1, SigningKey, SigningKey) {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let operator = SigningKey::from_bytes(&[0x41; 32]);
        let identity = SigningKey::from_bytes(&[0x42; 32]);
        let store = IdentityAuthorityStoreV1::create(
            directory.path().join("identity.sqlite"),
            [0x43; 16],
            operator.verifying_key().to_bytes(),
        )
        .unwrap();
        (directory, store, operator, identity)
    }

    #[test]
    fn reserve_restart_readback_and_reject_duplicate_and_rollback() {
        let (directory, mut store, operator, _identity) = fixture();
        let reservation = IdentityGenerationReservationV2 {
            server_id: "pir2".to_owned(),
            identity_generation: 2,
        };
        let write = store.reserve_generation(reservation.clone()).unwrap();
        assert_eq!(
            write.disposition,
            IdentityAuthorityWriteDispositionV1::Committed
        );
        assert!(matches!(
            write.value.state,
            IdentityGenerationReservationStateV2::Inactive
        ));
        assert!(matches!(
            store.reserve_generation(reservation.clone()),
            Err(IdentityAuthorityErrorV1::ReservationExists)
        ));
        let rollback = IdentityGenerationReservationV2 {
            identity_generation: 1,
            ..reservation.clone()
        };
        assert!(matches!(
            store.reserve_generation(rollback),
            Err(IdentityAuthorityErrorV1::ReservationRollback)
        ));
        let head = store.head();
        drop(store);
        let reopened = IdentityAuthorityStoreV1::open_existing(
            directory.path().join("identity.sqlite"),
            [0x43; 16],
            operator.verifying_key().to_bytes(),
            head,
        )
        .unwrap();
        assert_eq!(
            reopened
                .reservation("pir2", 2)
                .unwrap()
                .unwrap()
                .reservation,
            reservation
        );
    }

    #[test]
    fn canonical_external_head_and_explicit_one_successor_recovery() {
        let (directory, mut store, _operator, _identity) = fixture();
        let initial = store.head();
        assert_eq!(
            IdentityAuthorityHeadV1::decode(&initial.encode()).unwrap(),
            initial
        );
        let mut corrupt = initial.encode();
        corrupt[0] ^= 1;
        assert!(matches!(
            IdentityAuthorityHeadV1::decode(&corrupt),
            Err(IdentityAuthorityErrorV1::InvalidInput(_))
        ));

        let reservation = IdentityGenerationReservationV2 {
            server_id: "pir2".to_owned(),
            identity_generation: 1,
        };
        let committed = store.reserve_generation(reservation.clone()).unwrap().head;
        drop(store);
        let recovered = IdentityAuthorityStoreV1::recover_reservation_successor(
            directory.path().join("identity.sqlite"),
            initial,
            &reservation,
        )
        .unwrap();
        assert_eq!(recovered.head(), committed);
        assert!(matches!(
            IdentityAuthorityStoreV1::recover_reservation_successor(
                directory.path().join("identity.sqlite"),
                committed,
                &IdentityGenerationReservationV2 {
                    server_id: "pir2".to_owned(),
                    identity_generation: 2,
                },
            ),
            Err(IdentityAuthorityErrorV1::HeadFork)
        ));
    }

    #[test]
    fn successor_recovery_rejects_a_different_predecessor_branch() {
        let (first_directory, mut first, operator, _identity) = fixture();
        let first_head = first
            .reserve_generation(IdentityGenerationReservationV2 {
                server_id: "pir1".to_owned(),
                identity_generation: 1,
            })
            .unwrap()
            .head;
        drop(first);

        let second_directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(second_directory.path(), fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let mut second = IdentityAuthorityStoreV1::create(
            second_directory.path().join("identity.sqlite"),
            [0x43; 16],
            operator.verifying_key().to_bytes(),
        )
        .unwrap();
        second
            .reserve_generation(IdentityGenerationReservationV2 {
                server_id: "pir2".to_owned(),
                identity_generation: 1,
            })
            .unwrap();
        second
            .reserve_generation(IdentityGenerationReservationV2 {
                server_id: "pir2".to_owned(),
                identity_generation: 2,
            })
            .unwrap();
        drop(second);

        assert!(matches!(
            IdentityAuthorityStoreV1::recover_reservation_successor(
                second_directory.path().join("identity.sqlite"),
                first_head,
                &IdentityGenerationReservationV2 {
                    server_id: "pir1".to_owned(),
                    identity_generation: 2,
                },
            ),
            Err(IdentityAuthorityErrorV1::HeadFork)
        ));
        drop(first_directory);
    }

    #[test]
    fn recovery_is_bound_to_exact_lost_operation() {
        let (directory, mut store, operator, identity) = fixture();
        let initial = store.head();
        let reservation = IdentityGenerationReservationV2 {
            server_id: "pir2".to_owned(),
            identity_generation: 1,
        };
        let reserved_head = store.reserve_generation(reservation.clone()).unwrap().head;
        drop(store);

        assert!(matches!(
            IdentityAuthorityStoreV1::recover_reservation_successor(
                directory.path().join("identity.sqlite"),
                initial,
                &IdentityGenerationReservationV2 {
                    server_id: "pir1".to_owned(),
                    identity_generation: 1,
                },
            ),
            Err(IdentityAuthorityErrorV1::RecoveryMismatch)
        ));
        let unexpected_activation = sign_generation_bound_identity_cert_v2(
            &operator,
            "pir2",
            1,
            identity.verifying_key().to_bytes(),
            10,
            20,
        )
        .unwrap();
        assert!(matches!(
            IdentityAuthorityStoreV1::recover_activation_successor(
                directory.path().join("identity.sqlite"),
                initial,
                &unexpected_activation,
            ),
            Err(IdentityAuthorityErrorV1::RecoveryMismatch)
        ));

        let mut recovered = IdentityAuthorityStoreV1::recover_reservation_successor(
            directory.path().join("identity.sqlite"),
            initial,
            &reservation,
        )
        .unwrap();
        let exact = sign_generation_bound_identity_cert_v2(
            &operator,
            "pir2",
            1,
            identity.verifying_key().to_bytes(),
            10,
            20,
        )
        .unwrap();
        let active_head = recovered.activate(&exact, 15).unwrap().head;
        drop(recovered);
        let wrong_identity = SigningKey::from_bytes(&[0x49; 32]);
        let wrong_certificate = sign_generation_bound_identity_cert_v2(
            &operator,
            "pir2",
            1,
            wrong_identity.verifying_key().to_bytes(),
            10,
            20,
        )
        .unwrap();
        assert!(matches!(
            IdentityAuthorityStoreV1::recover_activation_successor(
                directory.path().join("identity.sqlite"),
                reserved_head,
                &wrong_certificate,
            ),
            Err(IdentityAuthorityErrorV1::RecoveryMismatch)
        ));
        assert_eq!(
            IdentityAuthorityStoreV1::recover_activation_successor(
                directory.path().join("identity.sqlite"),
                reserved_head,
                &exact,
            )
            .unwrap()
            .head(),
            active_head
        );
    }

    #[test]
    fn activation_requires_exact_generation_and_key_without_state_change() {
        let (_directory, mut store, operator, identity) = fixture();
        store
            .reserve_generation(IdentityGenerationReservationV2 {
                server_id: "pir2".to_owned(),
                identity_generation: 1,
            })
            .unwrap();
        let before = store.head();
        let wrong_generation = sign_generation_bound_identity_cert_v2(
            &operator,
            "pir2",
            2,
            identity.verifying_key().to_bytes(),
            10,
            20,
        )
        .unwrap();
        assert!(matches!(
            store.activate(&wrong_generation, 15),
            Err(IdentityAuthorityErrorV1::ReservationMissing)
        ));
        assert_eq!(store.head(), before);
        assert!(matches!(
            store.reservation("pir2", 1).unwrap().unwrap().state,
            IdentityGenerationReservationStateV2::Inactive
        ));
        let operator_as_identity = sign_generation_bound_identity_cert_v2(
            &operator,
            "pir2",
            1,
            operator.verifying_key().to_bytes(),
            10,
            20,
        )
        .unwrap();
        assert!(matches!(
            store.activate(&operator_as_identity, 15),
            Err(IdentityAuthorityErrorV1::ReservationMismatch)
        ));
        assert_eq!(store.head(), before);
        let exact = sign_generation_bound_identity_cert_v2(
            &operator,
            "pir2",
            1,
            identity.verifying_key().to_bytes(),
            10,
            20,
        )
        .unwrap();
        let activated = store.activate(&exact, 15).unwrap();
        assert!(matches!(
            activated.value.state,
            IdentityGenerationReservationStateV2::Active {
                identity_pubkey,
                ..
            } if identity_pubkey == identity.verifying_key().to_bytes()
        ));
        assert_eq!(
            store.activate(&exact, 21).unwrap().disposition,
            IdentityAuthorityWriteDispositionV1::ExactReplay
        );
        let activated_head = store.head();
        let wrong_key = SigningKey::from_bytes(&[0x45; 32]);
        let wrong_key_cert = sign_generation_bound_identity_cert_v2(
            &operator,
            "pir2",
            1,
            wrong_key.verifying_key().to_bytes(),
            10,
            20,
        )
        .unwrap();
        assert!(matches!(
            store.activate(&wrong_key_cert, 15),
            Err(IdentityAuthorityErrorV1::ActivationFork)
        ));
        assert_eq!(store.head(), activated_head);

        store
            .reserve_generation(IdentityGenerationReservationV2 {
                server_id: "pir2".to_owned(),
                identity_generation: 2,
            })
            .unwrap();
        store
            .reserve_generation(IdentityGenerationReservationV2 {
                server_id: "pir1".to_owned(),
                identity_generation: 1,
            })
            .unwrap();
        for (server_id, generation) in [("pir2", 2), ("pir1", 1)] {
            let reused_key = sign_generation_bound_identity_cert_v2(
                &operator,
                server_id,
                generation,
                identity.verifying_key().to_bytes(),
                10,
                20,
            )
            .unwrap();
            let before_reuse = store.head();
            assert!(matches!(
                store.activate(&reused_key, 15),
                Err(IdentityAuthorityErrorV1::ActivationFork)
            ));
            assert_eq!(store.head(), before_reuse);
            assert!(matches!(
                store
                    .reservation(server_id, generation)
                    .unwrap()
                    .unwrap()
                    .state,
                IdentityGenerationReservationStateV2::Inactive
            ));
        }
    }

    #[test]
    fn caller_pinned_head_rejects_old_database_restore() {
        let (directory, mut store, operator, _identity) = fixture();
        let database = directory.path().join("identity.sqlite");
        let old = directory.path().join("old.sqlite");
        fs::copy(&database, &old).unwrap();
        let head = store
            .reserve_generation(IdentityGenerationReservationV2 {
                server_id: "pir2".to_owned(),
                identity_generation: 1,
            })
            .unwrap()
            .head;
        drop(store);
        fs::copy(&old, &database).unwrap();
        assert!(matches!(
            IdentityAuthorityStoreV1::open_existing(
                database,
                [0x43; 16],
                operator.verifying_key().to_bytes(),
                head,
            ),
            Err(IdentityAuthorityErrorV1::RollbackDetected)
        ));
    }
}
