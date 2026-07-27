use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use pir_service_protocol::validate_cashu_unit_v1;
use rusqlite::{params, Connection, ErrorCode, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::store::{
    CashuCustodyExposureLimitsV1, CashuSealedCustodyV1, CashuSealedRecoveryV1,
    CashuSwapGrantClaimV1, CashuSwapStateV1, CashuSwapStoreErrorV1, CashuSwapStoreV1,
    InsertCashuSwapIntentResultV1, NewCashuCustodyLotV1, NewCashuSwapIntentV1,
    StoredCashuCustodyLotV1, StoredCashuSwapIntentV1, MAX_CUSTODY_CIPHERTEXT_BYTES_V1,
    MAX_CUSTODY_NONCE_BYTES_V1, MAX_RECOVERY_CIPHERTEXT_BYTES_V1, MAX_RECOVERY_NONCE_BYTES_V1,
};

/// Test/development-only SQLite implementation.
///
/// Although proof secrets and blinding material are externally encrypted,
/// this implementation has no independently durable rollback floor. Restoring
/// an old database could re-submit a prepared intent or re-issue a grant. It is
/// therefore intentionally hidden unless tests or the explicit
/// `insecure-dev-sqlite-store` feature are enabled.
pub struct InsecureDevSqliteCashuSwapStoreV1 {
    connection: Mutex<Connection>,
}

struct RawCashuSwapIntentRowV1 {
    intent_id: Vec<u8>,
    mint_id: Vec<u8>,
    manifest_digest: Vec<u8>,
    unit: String,
    input_set_digest: Vec<u8>,
    request_digest: Vec<u8>,
    output_set_digest: Vec<u8>,
    offer_binding_digest: Vec<u8>,
    settlement_value: i64,
    expected_output_count: i64,
    state: u8,
    key_epoch: i64,
    nonce: Zeroizing<Vec<u8>>,
    ciphertext: Zeroizing<Vec<u8>>,
    created_bucket: i64,
    updated_bucket: i64,
}

struct RawCashuCustodyLotRowV1 {
    lot_id: Vec<u8>,
    mint_id: Vec<u8>,
    manifest_digest: Vec<u8>,
    active_keyset_digest: Vec<u8>,
    note_set_digest: Vec<u8>,
    unit: String,
    settlement_value: i64,
    note_count: i64,
    key_epoch: i64,
    nonce: Zeroizing<Vec<u8>>,
    ciphertext: Zeroizing<Vec<u8>>,
}

impl InsecureDevSqliteCashuSwapStoreV1 {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CashuSwapStoreErrorV1> {
        let connection = Connection::open(path).map_err(map_sqlite_error)?;
        Self::initialize(connection)
    }

    pub fn open_in_memory() -> Result<Self, CashuSwapStoreErrorV1> {
        let connection = Connection::open_in_memory().map_err(map_sqlite_error)?;
        Self::initialize(connection)
    }

    fn initialize(connection: Connection) -> Result<Self, CashuSwapStoreErrorV1> {
        connection
            .execute_batch(&format!(
                "PRAGMA foreign_keys = ON;
                 PRAGMA synchronous = FULL;
                 CREATE TABLE IF NOT EXISTS cashu_swap_intents (
                    intent_id BLOB NOT NULL PRIMARY KEY CHECK(length(intent_id) = 16),
                    mint_id BLOB NOT NULL CHECK(length(mint_id) = 32),
                    manifest_digest BLOB NOT NULL CHECK(length(manifest_digest) = 32),
                    unit TEXT NOT NULL CHECK(length(unit) BETWEEN 1 AND 16),
                    input_set_digest BLOB NOT NULL CHECK(length(input_set_digest) = 32),
                    request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
                    output_set_digest BLOB NOT NULL CHECK(length(output_set_digest) = 32),
                    offer_binding_digest BLOB NOT NULL CHECK(length(offer_binding_digest) = 32),
                    settlement_value INTEGER NOT NULL CHECK(settlement_value > 0),
                    expected_output_count INTEGER NOT NULL CHECK(expected_output_count > 0),
                    state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 4),
                    recovery_key_epoch INTEGER NOT NULL CHECK(recovery_key_epoch > 0),
                    recovery_nonce BLOB NOT NULL CHECK(
                        length(recovery_nonce) BETWEEN 1 AND {MAX_RECOVERY_NONCE_BYTES_V1}
                    ),
                    recovery_ciphertext BLOB NOT NULL CHECK(
                        length(recovery_ciphertext) BETWEEN 1 AND {MAX_RECOVERY_CIPHERTEXT_BYTES_V1}
                    ),
                    created_bucket INTEGER NOT NULL CHECK(created_bucket >= 0),
                    updated_bucket INTEGER NOT NULL CHECK(updated_bucket >= created_bucket),
                    UNIQUE(mint_id, input_set_digest)
                 ) STRICT, WITHOUT ROWID;
                 CREATE TABLE IF NOT EXISTS cashu_custody_lots (
                    lot_id BLOB NOT NULL PRIMARY KEY CHECK(length(lot_id) = 16),
                    intent_id BLOB NOT NULL UNIQUE CHECK(length(intent_id) = 16),
                    mint_id BLOB NOT NULL CHECK(length(mint_id) = 32),
                    manifest_digest BLOB NOT NULL CHECK(length(manifest_digest) = 32),
                    active_keyset_digest BLOB NOT NULL CHECK(length(active_keyset_digest) = 32),
                    note_set_digest BLOB NOT NULL CHECK(length(note_set_digest) = 32),
                    unit TEXT NOT NULL CHECK(length(unit) BETWEEN 1 AND 16),
                    settlement_value INTEGER NOT NULL CHECK(settlement_value > 0),
                    note_count INTEGER NOT NULL CHECK(note_count > 0),
                    sealed_key_epoch INTEGER NOT NULL CHECK(sealed_key_epoch > 0),
                    sealed_nonce BLOB NOT NULL CHECK(
                        length(sealed_nonce) BETWEEN 1 AND {MAX_CUSTODY_NONCE_BYTES_V1}
                    ),
                    sealed_ciphertext BLOB NOT NULL CHECK(
                        length(sealed_ciphertext) BETWEEN 1 AND {MAX_CUSTODY_CIPHERTEXT_BYTES_V1}
                    ),
                    FOREIGN KEY(intent_id) REFERENCES cashu_swap_intents(intent_id)
                 ) STRICT, WITHOUT ROWID;
                 CREATE TABLE IF NOT EXISTS cashu_custody_notes (
                    note_fingerprint BLOB NOT NULL PRIMARY KEY CHECK(length(note_fingerprint) = 32),
                    lot_id BLOB NOT NULL CHECK(length(lot_id) = 16),
                    FOREIGN KEY(lot_id) REFERENCES cashu_custody_lots(lot_id)
                 ) STRICT, WITHOUT ROWID;"
            ))
            .map_err(map_sqlite_error)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, CashuSwapStoreErrorV1> {
        self.connection
            .lock()
            .map_err(|_| CashuSwapStoreErrorV1::Unavailable)
    }
}

impl CashuSwapStoreV1 for InsecureDevSqliteCashuSwapStoreV1 {
    fn insert_prepared(
        &self,
        intent: &NewCashuSwapIntentV1,
        limits: CashuCustodyExposureLimitsV1,
    ) -> Result<InsertCashuSwapIntentResultV1, CashuSwapStoreErrorV1> {
        intent
            .sealed_recovery
            .validate()
            .map_err(|_| CashuSwapStoreErrorV1::Conflict)?;
        validate_cashu_unit_v1(&intent.unit).map_err(|_| CashuSwapStoreErrorV1::Conflict)?;
        let value = as_i64(intent.settlement_value)?;
        let created_bucket = as_i64(intent.created_bucket)?;
        let key_epoch = as_i64(intent.sealed_recovery.key_epoch)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        if let Some(stored) =
            load_by_input_from(&transaction, &intent.mint_id, &intent.input_set_digest)?
        {
            if !stored.matches_new(intent) {
                return Err(CashuSwapStoreErrorV1::Conflict);
            }
            transaction.commit().map_err(map_sqlite_error)?;
            return Ok(InsertCashuSwapIntentResultV1 {
                inserted: false,
                intent: stored,
            });
        }
        ensure_exposure_limit(&transaction, intent, limits)?;
        let inserted = transaction
            .execute(
                "INSERT OR IGNORE INTO cashu_swap_intents (
                    intent_id, mint_id, manifest_digest, unit, input_set_digest, request_digest,
                    output_set_digest, offer_binding_digest, settlement_value,
                    expected_output_count, state,
                    recovery_key_epoch, recovery_nonce, recovery_ciphertext,
                    created_bucket, updated_bucket
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0,
                           ?11, ?12, ?13, ?14, ?14)",
                params![
                    intent.intent_id.as_slice(),
                    intent.mint_id.as_slice(),
                    intent.manifest_digest.as_slice(),
                    &intent.unit,
                    intent.input_set_digest.as_slice(),
                    intent.request_digest.as_slice(),
                    intent.output_set_digest.as_slice(),
                    intent.offer_binding_digest.as_slice(),
                    value,
                    i64::from(intent.expected_output_count),
                    key_epoch,
                    &intent.sealed_recovery.nonce,
                    &intent.sealed_recovery.ciphertext,
                    created_bucket,
                ],
            )
            .map_err(map_sqlite_error)?
            == 1;
        let stored = load_by_input_from(&transaction, &intent.mint_id, &intent.input_set_digest)?
            .ok_or(CashuSwapStoreErrorV1::Corrupt)?;
        if !stored.matches_new(intent) {
            return Err(CashuSwapStoreErrorV1::Conflict);
        }
        transaction.commit().map_err(map_sqlite_error)?;
        Ok(InsertCashuSwapIntentResultV1 {
            inserted,
            intent: stored,
        })
    }

    fn load_by_input(
        &self,
        mint_id: &[u8; 32],
        input_set_digest: &[u8; 32],
    ) -> Result<Option<StoredCashuSwapIntentV1>, CashuSwapStoreErrorV1> {
        let connection = self.lock()?;
        load_by_input_from(&connection, mint_id, input_set_digest)
    }

    fn begin_submission(
        &self,
        intent_id: &[u8; 16],
        now_unix: u64,
    ) -> Result<bool, CashuSwapStoreErrorV1> {
        transition_state(
            self,
            intent_id,
            CashuSwapStateV1::Prepared,
            CashuSwapStateV1::Submitted,
            now_unix,
        )
    }

    fn commit_wallet(
        &self,
        intent_id: &[u8; 16],
        sealed_recovery: &CashuSealedRecoveryV1,
        now_unix: u64,
    ) -> Result<bool, CashuSwapStoreErrorV1> {
        sealed_recovery
            .validate()
            .map_err(|_| CashuSwapStoreErrorV1::Conflict)?;
        let key_epoch = as_i64(sealed_recovery.key_epoch)?;
        let now_bucket = as_i64(coarse_time_bucket_v1(now_unix))?;
        let connection = self.lock()?;
        let changed = connection
            .execute(
                "UPDATE cashu_swap_intents
                 SET state = 2, recovery_key_epoch = ?2, recovery_nonce = ?3,
                     recovery_ciphertext = ?4, updated_bucket = ?5
                 WHERE intent_id = ?1 AND state IN (1, 4)",
                params![
                    intent_id.as_slice(),
                    key_epoch,
                    &sealed_recovery.nonce,
                    &sealed_recovery.ciphertext,
                    now_bucket,
                ],
            )
            .map_err(map_sqlite_error)?;
        Ok(changed == 1)
    }

    fn mark_attention(
        &self,
        intent_id: &[u8; 16],
        now_unix: u64,
    ) -> Result<(), CashuSwapStoreErrorV1> {
        let now_bucket = as_i64(coarse_time_bucket_v1(now_unix))?;
        let connection = self.lock()?;
        connection
            .execute(
                "UPDATE cashu_swap_intents SET state = 4, updated_bucket = ?2
                 WHERE intent_id = ?1 AND state = 1",
                params![intent_id.as_slice(), now_bucket],
            )
            .map_err(map_sqlite_error)?;
        Ok(())
    }

    fn release_definite_rejection(
        &self,
        intent_id: &[u8; 16],
    ) -> Result<bool, CashuSwapStoreErrorV1> {
        if intent_id.iter().all(|byte| *byte == 0) {
            return Err(CashuSwapStoreErrorV1::Conflict);
        }
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        let changed = transaction
            .execute(
                "DELETE FROM cashu_swap_intents WHERE intent_id = ?1 AND state = 1",
                [intent_id.as_slice()],
            )
            .map_err(map_sqlite_error)?;
        transaction.commit().map_err(map_sqlite_error)?;
        Ok(changed == 1)
    }

    fn claim_grant_once_with_custody(
        &self,
        intent_id: &[u8; 16],
        lot: &NewCashuCustodyLotV1,
        now_unix: u64,
    ) -> Result<CashuSwapGrantClaimV1, CashuSwapStoreErrorV1> {
        lot.sealed_notes
            .validate()
            .map_err(|_| CashuSwapStoreErrorV1::CustodyConflict)?;
        if lot.lot_id.iter().all(|byte| *byte == 0)
            || lot.note_ys.is_empty()
            || lot.manifest_digest.iter().all(|byte| *byte == 0)
            || lot.active_keyset_digest.iter().all(|byte| *byte == 0)
            || lot.note_set_digest.iter().all(|byte| *byte == 0)
            || lot
                .note_ys
                .iter()
                .any(|y| !matches!(y[0], 0x02 | 0x03) || y[1..].iter().all(|byte| *byte == 0))
        {
            return Err(CashuSwapStoreErrorV1::CustodyConflict);
        }
        let now_bucket = as_i64(coarse_time_bucket_v1(now_unix))?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        let intent =
            load_by_id_from(&transaction, intent_id)?.ok_or(CashuSwapStoreErrorV1::Conflict)?;
        let mut fingerprints = lot
            .note_ys
            .iter()
            .map(|y| custody_note_fingerprint(&intent.mint_id, y))
            .collect::<Vec<_>>();
        fingerprints.sort_unstable();
        if fingerprints.windows(2).any(|pair| pair[0] == pair[1])
            || usize::try_from(intent.expected_output_count).ok() != Some(fingerprints.len())
        {
            return Err(CashuSwapStoreErrorV1::CustodyConflict);
        }
        if intent.state == CashuSwapStateV1::GrantIssued {
            let existing = load_custody_lot_by_intent(&transaction, intent_id)?
                .ok_or(CashuSwapStoreErrorV1::CustodyConflict)?;
            let stored_fingerprints = load_custody_fingerprints(&transaction, &existing.lot_id)?;
            if existing.lot_id != lot.lot_id
                || existing.mint_id != intent.mint_id
                || existing.manifest_digest != lot.manifest_digest
                || existing.active_keyset_digest != lot.active_keyset_digest
                || existing.note_set_digest != lot.note_set_digest
                || existing.unit != intent.unit
                || existing.settlement_value != intent.settlement_value
                || usize::try_from(existing.note_count).ok() != Some(fingerprints.len())
                || stored_fingerprints != fingerprints
            {
                return Err(CashuSwapStoreErrorV1::CustodyConflict);
            }
            transaction.commit().map_err(map_sqlite_error)?;
            return Ok(CashuSwapGrantClaimV1 {
                issued: false,
                lot: existing,
            });
        }
        if intent.state != CashuSwapStateV1::WalletStored {
            return Err(CashuSwapStoreErrorV1::Conflict);
        }
        let key_epoch = as_i64(lot.sealed_notes.key_epoch)?;
        transaction
            .execute(
                "INSERT INTO cashu_custody_lots (
                    lot_id, intent_id, mint_id, manifest_digest, active_keyset_digest,
                    note_set_digest, unit, settlement_value, note_count,
                    sealed_key_epoch, sealed_nonce, sealed_ciphertext
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    lot.lot_id.as_slice(),
                    intent_id.as_slice(),
                    intent.mint_id.as_slice(),
                    lot.manifest_digest.as_slice(),
                    lot.active_keyset_digest.as_slice(),
                    lot.note_set_digest.as_slice(),
                    &intent.unit,
                    as_i64(intent.settlement_value)?,
                    i64::from(intent.expected_output_count),
                    key_epoch,
                    &lot.sealed_notes.nonce,
                    &lot.sealed_notes.ciphertext,
                ],
            )
            .map_err(map_custody_sqlite_error)?;
        for fingerprint in &fingerprints {
            transaction
                .execute(
                    "INSERT INTO cashu_custody_notes (note_fingerprint, lot_id)
                     VALUES (?1, ?2)",
                    params![fingerprint.as_slice(), lot.lot_id.as_slice()],
                )
                .map_err(map_custody_sqlite_error)?;
        }
        let changed = transaction
            .execute(
                "UPDATE cashu_swap_intents SET state = 3, updated_bucket = ?2
                 WHERE intent_id = ?1 AND state = 2",
                params![intent_id.as_slice(), now_bucket],
            )
            .map_err(map_sqlite_error)?;
        if changed != 1 {
            return Err(CashuSwapStoreErrorV1::Conflict);
        }
        transaction.commit().map_err(map_sqlite_error)?;
        Ok(CashuSwapGrantClaimV1 {
            issued: true,
            lot: StoredCashuCustodyLotV1 {
                lot_id: lot.lot_id,
                mint_id: intent.mint_id,
                manifest_digest: lot.manifest_digest,
                active_keyset_digest: lot.active_keyset_digest,
                note_set_digest: lot.note_set_digest,
                unit: intent.unit,
                settlement_value: intent.settlement_value,
                note_count: intent.expected_output_count,
                sealed_notes: lot.sealed_notes.clone(),
            },
        })
    }
}

fn transition_state(
    store: &InsecureDevSqliteCashuSwapStoreV1,
    intent_id: &[u8; 16],
    from: CashuSwapStateV1,
    to: CashuSwapStateV1,
    now_unix: u64,
) -> Result<bool, CashuSwapStoreErrorV1> {
    let now_bucket = as_i64(coarse_time_bucket_v1(now_unix))?;
    let connection = store.lock()?;
    let changed = connection
        .execute(
            "UPDATE cashu_swap_intents SET state = ?2, updated_bucket = ?3
             WHERE intent_id = ?1 AND state = ?4",
            params![intent_id.as_slice(), to as u8, now_bucket, from as u8],
        )
        .map_err(map_sqlite_error)?;
    Ok(changed == 1)
}

fn load_by_input_from(
    connection: &Connection,
    mint_id: &[u8; 32],
    input_set_digest: &[u8; 32],
) -> Result<Option<StoredCashuSwapIntentV1>, CashuSwapStoreErrorV1> {
    connection
        .query_row(
            "SELECT intent_id, mint_id, manifest_digest, unit, input_set_digest, request_digest,
                    output_set_digest, offer_binding_digest, settlement_value,
                    expected_output_count, state,
                    recovery_key_epoch, recovery_nonce, recovery_ciphertext,
                    created_bucket, updated_bucket
            FROM cashu_swap_intents
             WHERE mint_id = ?1 AND input_set_digest = ?2",
            params![mint_id.as_slice(), input_set_digest.as_slice()],
            read_raw_swap_intent_row,
        )
        .optional()
        .map_err(map_sqlite_error)?
        .map(decode_row)
        .transpose()
}

fn load_by_id_from(
    connection: &Connection,
    intent_id: &[u8; 16],
) -> Result<Option<StoredCashuSwapIntentV1>, CashuSwapStoreErrorV1> {
    connection
        .query_row(
            "SELECT intent_id, mint_id, manifest_digest, unit, input_set_digest, request_digest,
                    output_set_digest, offer_binding_digest, settlement_value,
                    expected_output_count, state, recovery_key_epoch, recovery_nonce,
                    recovery_ciphertext, created_bucket, updated_bucket
            FROM cashu_swap_intents WHERE intent_id = ?1",
            [intent_id.as_slice()],
            read_raw_swap_intent_row,
        )
        .optional()
        .map_err(map_sqlite_error)?
        .map(decode_row)
        .transpose()
}

fn ensure_exposure_limit(
    connection: &Connection,
    intent: &NewCashuSwapIntentV1,
    limits: CashuCustodyExposureLimitsV1,
) -> Result<(), CashuSwapStoreErrorV1> {
    let (intent_value, intent_notes): (i64, i64) = connection
        .query_row(
            "SELECT COALESCE(SUM(settlement_value), 0),
                    COALESCE(SUM(expected_output_count), 0)
             FROM cashu_swap_intents
             WHERE mint_id = ?1 AND unit = ?2 AND state != 3",
            params![intent.mint_id.as_slice(), &intent.unit],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(map_sqlite_error)?;
    let (lot_value, lot_notes): (i64, i64) = connection
        .query_row(
            "SELECT COALESCE(SUM(settlement_value), 0), COALESCE(SUM(note_count), 0)
             FROM cashu_custody_lots WHERE mint_id = ?1 AND unit = ?2",
            params![intent.mint_id.as_slice(), &intent.unit],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(map_sqlite_error)?;
    let value = nonnegative_u64(intent_value)?
        .checked_add(nonnegative_u64(lot_value)?)
        .and_then(|value| value.checked_add(intent.settlement_value))
        .ok_or(CashuSwapStoreErrorV1::ExposureExceeded)?;
    let notes = nonnegative_u64(intent_notes)?
        .checked_add(nonnegative_u64(lot_notes)?)
        .and_then(|value| value.checked_add(u64::from(intent.expected_output_count)))
        .ok_or(CashuSwapStoreErrorV1::ExposureExceeded)?;
    if value > limits.max_unsettled_value() || notes > limits.max_unsettled_notes() {
        return Err(CashuSwapStoreErrorV1::ExposureExceeded);
    }
    Ok(())
}

fn load_custody_lot_by_intent(
    connection: &Connection,
    intent_id: &[u8; 16],
) -> Result<Option<StoredCashuCustodyLotV1>, CashuSwapStoreErrorV1> {
    connection
        .query_row(
            "SELECT lot_id, mint_id, manifest_digest, active_keyset_digest,
                    note_set_digest, unit, settlement_value, note_count,
                    sealed_key_epoch, sealed_nonce, sealed_ciphertext
             FROM cashu_custody_lots WHERE intent_id = ?1",
            [intent_id.as_slice()],
            |row| {
                // Guard sealed notes before any later column conversion can fail.
                let nonce = Zeroizing::new(row.get(9)?);
                let ciphertext = Zeroizing::new(row.get(10)?);
                Ok(RawCashuCustodyLotRowV1 {
                    lot_id: row.get(0)?,
                    mint_id: row.get(1)?,
                    manifest_digest: row.get(2)?,
                    active_keyset_digest: row.get(3)?,
                    note_set_digest: row.get(4)?,
                    unit: row.get(5)?,
                    settlement_value: row.get(6)?,
                    note_count: row.get(7)?,
                    key_epoch: row.get(8)?,
                    nonce,
                    ciphertext,
                })
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .map(|mut row| {
            let lot = StoredCashuCustodyLotV1 {
                lot_id: exact_array(row.lot_id)?,
                mint_id: exact_array(row.mint_id)?,
                manifest_digest: exact_array(row.manifest_digest)?,
                active_keyset_digest: exact_array(row.active_keyset_digest)?,
                note_set_digest: exact_array(row.note_set_digest)?,
                unit: row.unit,
                settlement_value: positive_u64(row.settlement_value)?,
                note_count: positive_u32(row.note_count)?,
                sealed_notes: CashuSealedCustodyV1 {
                    key_epoch: positive_u64(row.key_epoch)?,
                    nonce: std::mem::take(&mut *row.nonce),
                    ciphertext: std::mem::take(&mut *row.ciphertext),
                },
            };
            lot.sealed_notes
                .validate()
                .map_err(|_| CashuSwapStoreErrorV1::Corrupt)?;
            Ok(lot)
        })
        .transpose()
}

fn load_custody_fingerprints(
    connection: &Connection,
    lot_id: &[u8; 16],
) -> Result<Vec<[u8; 32]>, CashuSwapStoreErrorV1> {
    let mut statement = connection
        .prepare(
            "SELECT note_fingerprint FROM cashu_custody_notes
             WHERE lot_id = ?1 ORDER BY note_fingerprint",
        )
        .map_err(map_sqlite_error)?;
    let rows = statement
        .query_map([lot_id.as_slice()], |row| row.get::<_, Vec<u8>>(0))
        .map_err(map_sqlite_error)?;
    rows.map(|row| exact_array(row.map_err(map_sqlite_error)?))
        .collect()
}

fn custody_note_fingerprint(mint_id: &[u8; 32], y: &[u8; 33]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(mint_id);
    hasher.update(y);
    hasher.finalize().into()
}

fn read_raw_swap_intent_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawCashuSwapIntentRowV1> {
    // Guard opaque recovery bytes before any later column conversion can fail.
    let nonce = Zeroizing::new(row.get(12)?);
    let ciphertext = Zeroizing::new(row.get(13)?);
    Ok(RawCashuSwapIntentRowV1 {
        intent_id: row.get(0)?,
        mint_id: row.get(1)?,
        manifest_digest: row.get(2)?,
        unit: row.get(3)?,
        input_set_digest: row.get(4)?,
        request_digest: row.get(5)?,
        output_set_digest: row.get(6)?,
        offer_binding_digest: row.get(7)?,
        settlement_value: row.get(8)?,
        expected_output_count: row.get(9)?,
        state: row.get(10)?,
        key_epoch: row.get(11)?,
        nonce,
        ciphertext,
        created_bucket: row.get(14)?,
        updated_bucket: row.get(15)?,
    })
}

fn decode_row(
    mut row: RawCashuSwapIntentRowV1,
) -> Result<StoredCashuSwapIntentV1, CashuSwapStoreErrorV1> {
    let record = StoredCashuSwapIntentV1 {
        intent_id: exact_array(row.intent_id)?,
        mint_id: exact_array(row.mint_id)?,
        manifest_digest: exact_array(row.manifest_digest)?,
        unit: row.unit,
        input_set_digest: exact_array(row.input_set_digest)?,
        request_digest: exact_array(row.request_digest)?,
        output_set_digest: exact_array(row.output_set_digest)?,
        offer_binding_digest: exact_array(row.offer_binding_digest)?,
        settlement_value: positive_u64(row.settlement_value)?,
        expected_output_count: positive_u32(row.expected_output_count)?,
        state: CashuSwapStateV1::from_u8(row.state)?,
        sealed_recovery: CashuSealedRecoveryV1 {
            key_epoch: positive_u64(row.key_epoch)?,
            nonce: std::mem::take(&mut *row.nonce),
            ciphertext: std::mem::take(&mut *row.ciphertext),
        },
        created_bucket: nonnegative_u64(row.created_bucket)?,
        updated_bucket: nonnegative_u64(row.updated_bucket)?,
    };
    record
        .sealed_recovery
        .validate()
        .map_err(|_| CashuSwapStoreErrorV1::Corrupt)?;
    if validate_cashu_unit_v1(&record.unit).is_err()
        || record.updated_bucket < record.created_bucket
    {
        return Err(CashuSwapStoreErrorV1::Corrupt);
    }
    Ok(record)
}

fn exact_array<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], CashuSwapStoreErrorV1> {
    bytes.try_into().map_err(|_| CashuSwapStoreErrorV1::Corrupt)
}

fn positive_u64(value: i64) -> Result<u64, CashuSwapStoreErrorV1> {
    if value <= 0 {
        return Err(CashuSwapStoreErrorV1::Corrupt);
    }
    u64::try_from(value).map_err(|_| CashuSwapStoreErrorV1::Corrupt)
}

fn positive_u32(value: i64) -> Result<u32, CashuSwapStoreErrorV1> {
    if value <= 0 {
        return Err(CashuSwapStoreErrorV1::Corrupt);
    }
    u32::try_from(value).map_err(|_| CashuSwapStoreErrorV1::Corrupt)
}

fn nonnegative_u64(value: i64) -> Result<u64, CashuSwapStoreErrorV1> {
    u64::try_from(value).map_err(|_| CashuSwapStoreErrorV1::Corrupt)
}

fn as_i64(value: u64) -> Result<i64, CashuSwapStoreErrorV1> {
    i64::try_from(value).map_err(|_| CashuSwapStoreErrorV1::Conflict)
}

fn coarse_time_bucket_v1(now_unix: u64) -> u64 {
    now_unix / 3_600
}

fn map_sqlite_error(error: rusqlite::Error) -> CashuSwapStoreErrorV1 {
    match error {
        rusqlite::Error::SqliteFailure(inner, _)
            if matches!(
                inner.code,
                ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked
            ) =>
        {
            CashuSwapStoreErrorV1::Busy
        }
        rusqlite::Error::QueryReturnedNoRows => CashuSwapStoreErrorV1::Corrupt,
        _ => CashuSwapStoreErrorV1::Unavailable,
    }
}

fn map_custody_sqlite_error(error: rusqlite::Error) -> CashuSwapStoreErrorV1 {
    match error {
        rusqlite::Error::SqliteFailure(inner, _)
            if inner.code == ErrorCode::ConstraintViolation =>
        {
            CashuSwapStoreErrorV1::CustodyConflict
        }
        other => map_sqlite_error(other),
    }
}

#[cfg(test)]
mod sensitive_row_tests {
    use super::*;

    #[test]
    fn raw_sensitive_sqlite_rows_are_drop_types_and_decode_fails_closed() {
        assert!(std::mem::needs_drop::<RawCashuSwapIntentRowV1>());
        assert!(std::mem::needs_drop::<RawCashuCustodyLotRowV1>());

        let row = RawCashuSwapIntentRowV1 {
            intent_id: vec![1; 15],
            mint_id: vec![2; 32],
            manifest_digest: vec![3; 32],
            unit: "sat".to_owned(),
            input_set_digest: vec![4; 32],
            request_digest: vec![5; 32],
            output_set_digest: vec![6; 32],
            offer_binding_digest: vec![7; 32],
            settlement_value: 1,
            expected_output_count: 1,
            state: CashuSwapStateV1::Prepared as u8,
            key_epoch: 1,
            nonce: Zeroizing::new(b"sensitive-recovery-nonce".to_vec()),
            ciphertext: Zeroizing::new(b"sensitive-recovery-ciphertext".to_vec()),
            created_bucket: 1,
            updated_bucket: 1,
        };
        assert!(matches!(
            decode_row(row),
            Err(CashuSwapStoreErrorV1::Corrupt)
        ));

        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE cashu_custody_lots (
                    lot_id BLOB, intent_id BLOB, mint_id BLOB,
                    manifest_digest BLOB, active_keyset_digest BLOB,
                    note_set_digest BLOB, unit TEXT, settlement_value INTEGER,
                    note_count INTEGER, sealed_key_epoch INTEGER,
                    sealed_nonce BLOB, sealed_ciphertext BLOB
                 );",
            )
            .unwrap();
        let intent_id = [8_u8; 16];
        connection
            .execute(
                "INSERT INTO cashu_custody_lots VALUES
                 (?1, ?2, ?3, ?4, ?5, ?6, 'sat', 1, 1, 1, ?7, ?8)",
                rusqlite::params![
                    vec![1_u8; 15],
                    intent_id.as_slice(),
                    vec![2_u8; 32],
                    vec![3_u8; 32],
                    vec![4_u8; 32],
                    vec![5_u8; 32],
                    b"sensitive-custody-nonce".as_slice(),
                    b"sensitive-custody-ciphertext".as_slice(),
                ],
            )
            .unwrap();
        assert!(matches!(
            load_custody_lot_by_intent(&connection, &intent_id),
            Err(CashuSwapStoreErrorV1::Corrupt)
        ));
    }
}
