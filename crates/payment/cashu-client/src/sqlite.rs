use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{params, Connection, ErrorCode, OptionalExtension, TransactionBehavior};

use crate::store::{
    CashuSealedRecoveryV1, CashuSwapStateV1, CashuSwapStoreErrorV1, CashuSwapStoreV1,
    InsertCashuSwapIntentResultV1, NewCashuSwapIntentV1, StoredCashuSwapIntentV1,
    MAX_RECOVERY_CIPHERTEXT_BYTES_V1, MAX_RECOVERY_NONCE_BYTES_V1,
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
                    input_set_digest BLOB NOT NULL CHECK(length(input_set_digest) = 32),
                    request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
                    output_set_digest BLOB NOT NULL CHECK(length(output_set_digest) = 32),
                    offer_binding_digest BLOB NOT NULL CHECK(length(offer_binding_digest) = 32),
                    settlement_value INTEGER NOT NULL CHECK(settlement_value > 0),
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
    ) -> Result<InsertCashuSwapIntentResultV1, CashuSwapStoreErrorV1> {
        intent
            .sealed_recovery
            .validate()
            .map_err(|_| CashuSwapStoreErrorV1::Conflict)?;
        let value = as_i64(intent.settlement_value)?;
        let created_bucket = as_i64(intent.created_bucket)?;
        let key_epoch = as_i64(intent.sealed_recovery.key_epoch)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        let inserted = transaction
            .execute(
                "INSERT OR IGNORE INTO cashu_swap_intents (
                    intent_id, mint_id, input_set_digest, request_digest,
                    output_set_digest, offer_binding_digest, settlement_value, state,
                    recovery_key_epoch, recovery_nonce, recovery_ciphertext,
                    created_bucket, updated_bucket
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8, ?9, ?10, ?11, ?11)",
                params![
                    intent.intent_id.as_slice(),
                    intent.mint_id.as_slice(),
                    intent.input_set_digest.as_slice(),
                    intent.request_digest.as_slice(),
                    intent.output_set_digest.as_slice(),
                    intent.offer_binding_digest.as_slice(),
                    value,
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

    fn claim_grant_once(
        &self,
        intent_id: &[u8; 16],
        now_unix: u64,
    ) -> Result<bool, CashuSwapStoreErrorV1> {
        transition_state(
            self,
            intent_id,
            CashuSwapStateV1::WalletStored,
            CashuSwapStateV1::GrantIssued,
            now_unix,
        )
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
            "SELECT intent_id, mint_id, input_set_digest, request_digest,
                    output_set_digest, offer_binding_digest, settlement_value, state,
                    recovery_key_epoch, recovery_nonce, recovery_ciphertext,
                    created_bucket, updated_bucket
             FROM cashu_swap_intents
             WHERE mint_id = ?1 AND input_set_digest = ?2",
            params![mint_id.as_slice(), input_set_digest.as_slice()],
            |row| {
                let intent_id: Vec<u8> = row.get(0)?;
                let stored_mint_id: Vec<u8> = row.get(1)?;
                let stored_input_digest: Vec<u8> = row.get(2)?;
                let request_digest: Vec<u8> = row.get(3)?;
                let output_digest: Vec<u8> = row.get(4)?;
                let offer_binding_digest: Vec<u8> = row.get(5)?;
                let settlement_value: i64 = row.get(6)?;
                let state: u8 = row.get(7)?;
                let key_epoch: i64 = row.get(8)?;
                let nonce: Vec<u8> = row.get(9)?;
                let ciphertext: Vec<u8> = row.get(10)?;
                let created_bucket: i64 = row.get(11)?;
                let updated_bucket: i64 = row.get(12)?;
                Ok((
                    intent_id,
                    stored_mint_id,
                    stored_input_digest,
                    request_digest,
                    output_digest,
                    offer_binding_digest,
                    settlement_value,
                    state,
                    key_epoch,
                    nonce,
                    ciphertext,
                    created_bucket,
                    updated_bucket,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
        .map(decode_row)
        .transpose()
}

#[allow(clippy::type_complexity)]
fn decode_row(
    row: (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
        u8,
        i64,
        Vec<u8>,
        Vec<u8>,
        i64,
        i64,
    ),
) -> Result<StoredCashuSwapIntentV1, CashuSwapStoreErrorV1> {
    let (
        intent_id,
        mint_id,
        input_set_digest,
        request_digest,
        output_set_digest,
        offer_binding_digest,
        settlement_value,
        state,
        key_epoch,
        nonce,
        ciphertext,
        created_bucket,
        updated_bucket,
    ) = row;
    let record = StoredCashuSwapIntentV1 {
        intent_id: exact_array(intent_id)?,
        mint_id: exact_array(mint_id)?,
        input_set_digest: exact_array(input_set_digest)?,
        request_digest: exact_array(request_digest)?,
        output_set_digest: exact_array(output_set_digest)?,
        offer_binding_digest: exact_array(offer_binding_digest)?,
        settlement_value: positive_u64(settlement_value)?,
        state: CashuSwapStateV1::from_u8(state)?,
        sealed_recovery: CashuSealedRecoveryV1 {
            key_epoch: positive_u64(key_epoch)?,
            nonce,
            ciphertext,
        },
        created_bucket: nonnegative_u64(created_bucket)?,
        updated_bucket: nonnegative_u64(updated_bucket)?,
    };
    record
        .sealed_recovery
        .validate()
        .map_err(|_| CashuSwapStoreErrorV1::Corrupt)?;
    if record.updated_bucket < record.created_bucket {
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
