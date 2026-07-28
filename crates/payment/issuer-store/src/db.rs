use crate::schema::{indexes, schema, APPLICATION_ID};
use crate::types::{StoreHandle, StoreIdentity, StoreOptions, SCHEMA_VERSION};
use crate::{StoreError, StoreResult};
use pir_service_protocol::LightningNetworkV1;
use rusqlite::{params, Connection, OpenFlags};
use sha2::{Digest, Sha256};
use std::convert::TryFrom;
use std::fs::{self, File, OpenOptions};
use std::path::Path;

const MAX_BUSY_TIMEOUT_MILLIS: u128 = 60_000;
const BACKEND_LABEL_DOMAIN_V1: &[u8] = b"BitcoinPIR/issuer-backend-label/v1";

pub(crate) fn create_file(path: &Path) -> StoreResult<()> {
    if path.as_os_str().is_empty() {
        return Err(StoreError::InvalidInput("database path is empty"));
    }
    let file = pir_private_files::create_new_private_file_v1(path, "issuer database")
        .map_err(private_file_io_error_v1)?;
    file.sync_all()?;
    drop(file);
    sync_parent_directory(path)
}

pub(crate) fn open_checked(
    handle: &StoreHandle,
    run_integrity_check: bool,
) -> StoreResult<Connection> {
    let connection = open_raw_existing(&handle.path)?;
    configure_connection(&connection, handle.options)?;
    validate_schema(&connection)?;
    verify_expected_identity(&connection, handle)?;
    if run_integrity_check {
        run_integrity_checks(&connection, handle)?;
    }
    Ok(connection)
}

pub(crate) fn open_raw_existing(path: &Path) -> StoreResult<Connection> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(StoreError::MissingDatabase(path.to_path_buf()))
        }
        Err(error) => return Err(StoreError::Io(error)),
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(StoreError::NotRegularDatabase(path.to_path_buf()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.nlink() != 1 {
            return Err(StoreError::NotRegularDatabase(path.to_path_buf()));
        }
    }

    let checked = pir_private_files::checked_existing_private_file_v1(
        path,
        pir_private_files::PrivateFileModeV1::ReadWrite,
        "issuer database",
    )
    .map_err(private_file_io_error_v1)?;
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let connection = Connection::open_with_flags(checked.path(), flags)?;
    let after = pir_private_files::checked_existing_private_file_v1(
        checked.path(),
        pir_private_files::PrivateFileModeV1::ReadWrite,
        "issuer database",
    )
    .map_err(private_file_io_error_v1)?;
    if after.identity() != checked.identity() {
        return Err(StoreError::NotRegularDatabase(path.to_path_buf()));
    }
    Ok(connection)
}

fn private_file_io_error_v1(error: String) -> StoreError {
    StoreError::Io(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        error,
    ))
}

pub(crate) fn configure_connection(
    connection: &Connection,
    options: StoreOptions,
) -> StoreResult<()> {
    validate_options(options)?;
    let journal_mode: String =
        connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(StoreError::SchemaMismatch(
            "journal_mode is not WAL".to_owned(),
        ));
    }
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "trusted_schema", false)?;
    connection.pragma_update(None, "temp_store", "MEMORY")?;
    connection.busy_timeout(options.busy_timeout)?;

    check_pragma_i64(connection, "synchronous", 2)?;
    check_pragma_i64(connection, "foreign_keys", 1)?;
    check_pragma_i64(connection, "trusted_schema", 0)?;
    check_pragma_i64(connection, "temp_store", 2)?;
    check_pragma_i64(
        connection,
        "busy_timeout",
        i64::try_from(options.busy_timeout.as_millis())
            .map_err(|_| StoreError::InvalidInput("busy timeout exceeds SQLite range"))?,
    )?;
    Ok(())
}

pub(crate) fn validate_options(options: StoreOptions) -> StoreResult<()> {
    let millis = options.busy_timeout.as_millis();
    if millis == 0 || millis > MAX_BUSY_TIMEOUT_MILLIS {
        return Err(StoreError::InvalidInput(
            "busy timeout must be in 1ms..=60s",
        ));
    }
    Ok(())
}

pub(crate) fn validate_schema(connection: &Connection) -> StoreResult<()> {
    let application_id: i64 =
        connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    if application_id != APPLICATION_ID {
        return Err(StoreError::SchemaMismatch(
            "application_id is unknown".to_owned(),
        ));
    }
    let user_version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if user_version != i64::from(SCHEMA_VERSION) {
        return Err(StoreError::SchemaMismatch(
            "user_version is unsupported".to_owned(),
        ));
    }

    let expected = schema();
    let mut statement = connection.prepare(
        "SELECT name, sql FROM sqlite_schema \
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let actual = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if actual.len() != expected.len() {
        return Err(StoreError::SchemaMismatch(
            "unexpected table set".to_owned(),
        ));
    }
    for ((actual_name, actual_sql), (expected_name, expected_sql)) in
        actual.iter().zip(expected.iter())
    {
        if actual_name != expected_name || normalize_sql(actual_sql) != normalize_sql(expected_sql)
        {
            return Err(StoreError::SchemaMismatch(format!(
                "table {expected_name} does not match schema v{SCHEMA_VERSION}"
            )));
        }
    }

    let expected_indexes = indexes();
    let mut index_statement = connection.prepare(
        "SELECT name, sql FROM sqlite_schema \
         WHERE type = 'index' AND sql IS NOT NULL ORDER BY name",
    )?;
    let actual_indexes = index_statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if actual_indexes.len() != expected_indexes.len() {
        return Err(StoreError::SchemaMismatch(
            "unexpected explicit index set".to_owned(),
        ));
    }
    for ((actual_name, actual_sql), (expected_name, expected_sql)) in
        actual_indexes.iter().zip(expected_indexes.iter())
    {
        if actual_name != expected_name || normalize_sql(actual_sql) != normalize_sql(expected_sql)
        {
            return Err(StoreError::SchemaMismatch(format!(
                "index {expected_name} does not match schema v{SCHEMA_VERSION}"
            )));
        }
    }

    let unexpected_objects: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema \
         WHERE type IN ('trigger', 'view') AND sql IS NOT NULL",
        [],
        |row| row.get(0),
    )?;
    if unexpected_objects != 0 {
        return Err(StoreError::SchemaMismatch(
            "unexpected trigger or view".to_owned(),
        ));
    }

    let identity = read_identity(connection)?;
    if identity.schema_version != SCHEMA_VERSION {
        return Err(StoreError::SchemaMismatch(
            "identity schema_version is unsupported".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn read_identity(connection: &Connection) -> StoreResult<StoreIdentity> {
    let count: i64 =
        connection.query_row("SELECT COUNT(*) FROM store_identity", [], |row| row.get(0))?;
    if count != 1 {
        return Err(StoreError::SchemaMismatch(
            "store_identity must contain exactly one row".to_owned(),
        ));
    }
    type RawIdentity = (Vec<u8>, Vec<u8>, i64, i64, Vec<u8>, Vec<u8>, i64, i64);
    let raw: RawIdentity = connection.query_row(
        "SELECT store_instance_id, issuer_id, network, commit_seq, rollback_parent_commitment, \
         rollback_commitment, status_time_floor, schema_version \
         FROM store_identity WHERE singleton = 1",
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
            ))
        },
    )?;
    let identity = StoreIdentity {
        store_instance_id: fixed_blob(raw.0, "invalid store instance id")?,
        issuer_id: fixed_blob(raw.1, "invalid issuer id")?,
        network: network_from_db(raw.2)?,
        commit_seq: db_u64(raw.3, "negative commit sequence")?,
        rollback_parent_commitment: fixed_blob(raw.4, "invalid rollback parent commitment")?,
        rollback_commitment: fixed_blob(raw.5, "invalid rollback commitment")?,
        status_time_floor: db_u64(raw.6, "negative status time floor")?,
        schema_version: u32::try_from(raw.7)
            .map_err(|_| StoreError::SchemaMismatch("invalid schema version".to_owned()))?,
    };
    if is_zero(&identity.store_instance_id)
        || is_zero(&identity.issuer_id)
        || is_zero(&identity.rollback_commitment)
        || (identity.commit_seq == 0 && !is_zero(&identity.rollback_parent_commitment))
        || (identity.commit_seq != 0 && is_zero(&identity.rollback_parent_commitment))
    {
        return Err(StoreError::SchemaMismatch(
            "identity contains an all-zero sentinel".to_owned(),
        ));
    }
    Ok(identity)
}

pub(crate) fn verify_expected_identity(
    connection: &Connection,
    handle: &StoreHandle,
) -> StoreResult<StoreIdentity> {
    let identity = read_identity(connection)?;
    if identity.store_instance_id != handle.expected_store_instance_id {
        return Err(StoreError::StoreInstanceMismatch);
    }
    if identity.issuer_id != handle.expected_issuer_id {
        return Err(StoreError::IssuerMismatch);
    }
    if identity.network != handle.expected_network {
        return Err(StoreError::NetworkMismatch);
    }
    Ok(identity)
}

fn run_integrity_checks(connection: &Connection, handle: &StoreHandle) -> StoreResult<()> {
    let result: String = connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if result != "ok" {
        return Err(StoreError::IntegrityCheckFailed(result));
    }
    let mut foreign_keys = connection.prepare("PRAGMA foreign_key_check")?;
    if foreign_keys.query([])?.next()?.is_some() {
        return Err(StoreError::IntegrityCheckFailed(
            "foreign key check reported a violation".to_owned(),
        ));
    }

    let network = network_code(handle.expected_network);
    let issuer = handle.expected_issuer_id.as_slice();
    let foreign_rows: i64 = connection.query_row(
        "SELECT \
            (SELECT COUNT(*) FROM quotes WHERE issuer_id != ?1 OR network != ?2) + \
            (SELECT COUNT(*) FROM claims WHERE issuer_id != ?1) + \
            (SELECT COUNT(*) FROM quote_delegation_heads WHERE issuer_id != ?1 OR network != ?2) + \
            (SELECT COUNT(*) FROM receipt_serials WHERE issuer_id != ?1) + \
            (SELECT COUNT(*) FROM arc_key_lineages WHERE issuer_id != ?1) + \
            (SELECT COUNT(*) FROM bat_key_lineages WHERE issuer_id != ?1) + \
            (SELECT COUNT(*) FROM settlement_key_lineages WHERE issuer_id != ?1) + \
            (SELECT COUNT(*) FROM provider_registration_history WHERE issuer_id != ?1) + \
            (SELECT COUNT(*) FROM provider_registrations WHERE issuer_id != ?1) + \
            (SELECT COUNT(*) FROM clearing_authorizations WHERE issuer_id != ?1) + \
            (SELECT COUNT(*) FROM ledger_accounts WHERE issuer_id != ?1) + \
            (SELECT COUNT(*) FROM ledger_transactions WHERE issuer_id != ?1) + \
            (SELECT COUNT(*) FROM redemptions WHERE issuer_id != ?1) + \
            (SELECT COUNT(*) FROM settlement_deposits WHERE issuer_id != ?1) + \
            (SELECT COUNT(*) FROM settlement_note_spends WHERE issuer_id != ?1) + \
            (SELECT COUNT(*) FROM payout_intents WHERE issuer_id != ?1) + \
            (SELECT COUNT(*) FROM payout_outbox WHERE issuer_id != ?1) + \
            (SELECT COUNT(*) FROM payouts WHERE issuer_id != ?1)",
        params![issuer, network],
        |row| row.get(0),
    )?;
    if foreign_rows != 0 {
        return Err(StoreError::IssuerMismatch);
    }

    let bad_provider_registration_history: i64 = connection.query_row(
        "SELECT \
            (SELECT COUNT(*) FROM provider_registrations c \
                LEFT JOIN provider_registration_history h \
                  ON h.issuer_id = c.issuer_id AND h.provider_id = c.provider_id \
                 AND h.registration_epoch = c.registration_epoch \
                WHERE h.registration_digest IS NULL \
                   OR h.registration_digest != c.registration_digest \
                   OR h.settlement_account_id != c.settlement_account_id \
                   OR h.provider_request_verifying_key != c.provider_request_verifying_key \
                   OR h.payout_target_id != c.payout_target_id \
                   OR h.not_before != c.not_before OR h.not_after != c.not_after \
                   OR h.commit_seq != c.commit_seq) + \
            (SELECT COUNT(*) FROM provider_registration_history h \
                LEFT JOIN provider_registrations c \
                  ON c.issuer_id = h.issuer_id AND c.provider_id = h.provider_id \
                WHERE c.provider_id IS NULL \
                   OR h.settlement_account_id != c.settlement_account_id \
                   OR h.payout_target_id != c.payout_target_id \
                   OR h.registration_epoch > c.registration_epoch \
                   OR h.commit_seq > c.commit_seq)",
        [],
        |row| row.get(0),
    )?;
    if bad_provider_registration_history != 0 {
        return Err(StoreError::SchemaMismatch(
            "current and retained provider registrations disagree".to_owned(),
        ));
    }

    let bad_claim_states: i64 = connection.query_row(
        "SELECT \
            (SELECT COUNT(*) FROM claims c JOIN quotes q USING (quote_id) WHERE q.state != 3) + \
            (SELECT COUNT(*) FROM quotes q WHERE q.state = 3 AND NOT EXISTS \
                (SELECT 1 FROM claims c WHERE c.quote_id = q.quote_id))",
        [],
        |row| row.get(0),
    )?;
    if bad_claim_states != 0 {
        return Err(StoreError::SchemaMismatch(
            "claim rows and claimed quote states disagree".to_owned(),
        ));
    }

    let bad_ledger: i64 = connection.query_row(
        "SELECT \
            (SELECT COUNT(*) FROM ledger_transactions t WHERE \
                (SELECT COUNT(*) FROM ledger_postings p WHERE p.transaction_id = t.transaction_id) < 2) + \
            (SELECT COUNT(*) FROM (SELECT transaction_id, SUM(signed_amount) AS total \
                FROM ledger_postings GROUP BY transaction_id HAVING total != 0)) + \
            (SELECT COUNT(*) FROM redemptions r LEFT JOIN ledger_transactions t \
                ON t.transaction_id = r.ledger_transaction_id \
                WHERE t.transaction_id IS NULL OR t.reference_digest != r.request_digest \
                OR t.provider_id != r.provider_id OR t.unit != r.unit) + \
            (SELECT COUNT(*) FROM ledger_accounts a LEFT JOIN provider_registrations p \
                ON p.provider_id = a.provider_id \
                WHERE p.provider_id IS NULL OR p.settlement_account_id != a.account_id) + \
            (SELECT COUNT(*) FROM settlement_deposits d LEFT JOIN ledger_transactions t \
                ON t.transaction_id = d.ledger_transaction_id \
                WHERE t.transaction_id IS NULL OR t.reference_digest != d.request_digest \
                OR t.provider_id != d.provider_id OR t.unit != d.unit) + \
            (SELECT COUNT(*) FROM payouts p LEFT JOIN ledger_transactions t \
                ON t.transaction_id = p.ledger_transaction_id \
                WHERE t.transaction_id IS NULL OR t.reference_digest != p.request_digest \
                OR t.provider_id != p.provider_id OR t.unit != p.unit OR t.kind != 4) + \
            (SELECT COUNT(*) FROM payouts p LEFT JOIN payout_intents i \
                ON i.payout_intent_id = p.payout_intent_id \
                WHERE i.payout_intent_id IS NULL OR i.consumed_by_payout_id != p.payout_id \
                OR i.provider_id != p.provider_id OR i.account_id != p.account_id \
                OR i.payout_target_id != p.payout_target_id OR i.unit != p.unit \
                OR i.payout_value != p.payout_value OR i.total_debit != p.total_debit) + \
            (SELECT COUNT(*) FROM payout_intents i WHERE \
                (i.consumed_by_payout_id IS NULL AND EXISTS \
                    (SELECT 1 FROM payouts p WHERE p.payout_intent_id = i.payout_intent_id)) OR \
                (i.consumed_by_payout_id IS NOT NULL AND NOT EXISTS \
                    (SELECT 1 FROM payouts p WHERE p.payout_intent_id = i.payout_intent_id \
                     AND p.payout_id = i.consumed_by_payout_id))) + \
            (SELECT COUNT(*) FROM payout_outbox o LEFT JOIN payouts p ON p.payout_id = o.payout_id \
                WHERE p.payout_id IS NULL OR p.payout_target_id != o.payout_target_id \
                OR p.unit != o.unit OR p.payout_value != o.payout_value \
                OR ((p.state IN (3, 4)) != (o.state = 3))) + \
            (SELECT COUNT(*) FROM payouts p LEFT JOIN ledger_transactions t \
                ON t.transaction_id = p.terminal_ledger_transaction_id \
                WHERE (p.state IN (3, 4) AND (t.transaction_id IS NULL \
                    OR t.provider_id != p.provider_id OR t.unit != p.unit \
                    OR (p.state = 3 AND t.kind != 5) OR (p.state = 4 AND t.kind != 6))) \
                   OR (p.state IN (1, 2) AND p.terminal_ledger_transaction_id IS NOT NULL)) + \
            (SELECT COUNT(*) FROM ledger_accounts a WHERE \
                a.available_value != COALESCE((SELECT SUM(p.signed_amount) FROM ledger_postings p \
                    WHERE p.account_kind = 1 AND p.account_id = a.account_id), 0) OR \
                a.reserved_value != COALESCE((SELECT SUM(p.signed_amount) FROM ledger_postings p \
                    WHERE p.account_kind = 6 AND p.account_id = a.account_id), 0))",
        [],
        |row| row.get(0),
    )?;
    if bad_ledger != 0 {
        return Err(StoreError::SchemaMismatch(
            "issuer ledger conservation or registration linkage failed".to_owned(),
        ));
    }

    let identity = read_identity(connection)?;
    let max_referenced: i64 = connection.query_row(
        "SELECT MAX(value) FROM (\
            SELECT reservation_commit_seq AS value FROM quotes \
            UNION ALL SELECT finalization_commit_seq FROM quotes WHERE finalization_commit_seq IS NOT NULL \
            UNION ALL SELECT expiry_commit_seq FROM quotes WHERE expiry_commit_seq IS NOT NULL \
            UNION ALL SELECT settlement_commit_seq FROM quotes WHERE settlement_commit_seq IS NOT NULL \
            UNION ALL SELECT claim_commit_seq FROM claims \
            UNION ALL SELECT commit_seq FROM quote_delegation_heads \
            UNION ALL SELECT commit_seq FROM quote_status_nonces \
            UNION ALL SELECT commit_seq FROM arc_key_lineages \
            UNION ALL SELECT commit_seq FROM bat_key_lineages \
            UNION ALL SELECT commit_seq FROM settlement_key_lineages \
            UNION ALL SELECT commit_seq FROM provider_registration_history \
            UNION ALL SELECT commit_seq FROM provider_registrations \
            UNION ALL SELECT commit_seq FROM clearing_authorizations \
            UNION ALL SELECT commit_seq FROM ledger_accounts \
            UNION ALL SELECT commit_seq FROM ledger_transactions \
            UNION ALL SELECT commit_seq FROM redemptions \
            UNION ALL SELECT commit_seq FROM settlement_deposits \
            UNION ALL SELECT commit_seq FROM settlement_note_spends \
            UNION ALL SELECT commit_seq FROM payout_intents \
            UNION ALL SELECT commit_seq FROM payout_outbox \
            UNION ALL SELECT commit_seq FROM payouts)",
        [],
        |row| row.get::<_, Option<i64>>(0),
    )?.unwrap_or(0);
    if max_referenced < 0 || u64::try_from(max_referenced).ok() > Some(identity.commit_seq) {
        return Err(StoreError::SchemaMismatch(
            "row commit marker exceeds the identity commit sequence".to_owned(),
        ));
    }

    let mut statement = connection.prepare("SELECT quote_id, backend_label FROM quotes")?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
    })?;
    for row in rows {
        let (quote_id, label) = row?;
        let quote_id = fixed_blob(quote_id, "invalid quote id")?;
        if label
            != derive_backend_label(
                &handle.expected_issuer_id,
                handle.expected_network,
                &quote_id,
            )
        {
            return Err(StoreError::SchemaMismatch(
                "quote backend label is not deterministic".to_owned(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn advance_store_generation(
    connection: &Connection,
    previous: &StoreIdentity,
    mutation_kind: &[u8],
    mutation_digest: &[u8; 32],
) -> StoreResult<StoreIdentity> {
    if previous.commit_seq == i64::MAX as u64 {
        return Err(StoreError::CommitSequenceExhausted);
    }
    let next = previous.commit_seq + 1;
    let next_commitment = crate::rollback::next_commitment(
        &previous.rollback_commitment,
        next,
        mutation_kind,
        mutation_digest,
    );
    let changed = connection.execute(
        "UPDATE store_identity SET commit_seq = ?1, rollback_parent_commitment = ?2, \
         rollback_commitment = ?3 WHERE singleton = 1 AND commit_seq = ?4 \
         AND rollback_commitment = ?5",
        params![
            sql_integer(next, "commit sequence exceeds SQLite range")?,
            previous.rollback_commitment.as_slice(),
            next_commitment.as_slice(),
            sql_integer(previous.commit_seq, "commit sequence exceeds SQLite range")?,
            previous.rollback_commitment.as_slice(),
        ],
    )?;
    if changed != 1 {
        return Err(StoreError::SchemaMismatch(
            "commit sequence compare-and-set failed".to_owned(),
        ));
    }
    Ok(StoreIdentity {
        store_instance_id: previous.store_instance_id,
        issuer_id: previous.issuer_id,
        network: previous.network,
        commit_seq: next,
        rollback_parent_commitment: previous.rollback_commitment,
        rollback_commitment: next_commitment,
        status_time_floor: previous.status_time_floor,
        schema_version: previous.schema_version,
    })
}

pub(crate) fn commit(transaction: rusqlite::Transaction<'_>) -> StoreResult<()> {
    transaction
        .commit()
        .map_err(|error| StoreError::CommitOutcomeUnknown(error.to_string()))
}

pub(crate) fn checkpoint_new_store(connection: &Connection) -> StoreResult<()> {
    let (busy, log_frames, checkpointed_frames): (i64, i64, i64) =
        connection.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
    if busy != 0 || log_frames != checkpointed_frames {
        return Err(StoreError::IntegrityCheckFailed(
            "new store WAL checkpoint did not complete".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn sync_database_and_parent(path: &Path) -> StoreResult<()> {
    OpenOptions::new().read(true).open(path)?.sync_all()?;
    sync_parent_directory(path)
}

fn sync_parent_directory(path: &Path) -> StoreResult<()> {
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

pub(crate) fn derive_backend_label(
    issuer_id: &[u8; 32],
    network: LightningNetworkV1,
    quote_id: &[u8; 32],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(BACKEND_LABEL_DOMAIN_V1);
    hasher.update(issuer_id);
    hasher.update([network as u8]);
    hasher.update(quote_id);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut label = String::with_capacity(72);
    label.push_str("bpir-v1-");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(label, "{byte:02x}");
    }
    label
}

pub(crate) const fn network_code(network: LightningNetworkV1) -> i64 {
    network as u8 as i64
}

fn network_from_db(value: i64) -> StoreResult<LightningNetworkV1> {
    match value {
        1 => Ok(LightningNetworkV1::Bitcoin),
        2 => Ok(LightningNetworkV1::Testnet),
        3 => Ok(LightningNetworkV1::Signet),
        4 => Ok(LightningNetworkV1::Regtest),
        _ => Err(StoreError::SchemaMismatch(
            "invalid Lightning network".to_owned(),
        )),
    }
}

fn check_pragma_i64(connection: &Connection, name: &'static str, expected: i64) -> StoreResult<()> {
    let statement = format!("PRAGMA {name}");
    let actual: i64 = connection.query_row(&statement, [], |row| row.get(0))?;
    if actual != expected {
        return Err(StoreError::SchemaMismatch(format!(
            "checked pragma {name} has unexpected value"
        )));
    }
    Ok(())
}

fn normalize_sql(sql: &str) -> String {
    sql.trim_end_matches(';')
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn sql_integer(value: u64, reason: &'static str) -> StoreResult<i64> {
    i64::try_from(value).map_err(|_| StoreError::InvalidInput(reason))
}

pub(crate) fn db_u64(value: i64, reason: &'static str) -> StoreResult<u64> {
    u64::try_from(value).map_err(|_| StoreError::SchemaMismatch(reason.to_owned()))
}

pub(crate) fn fixed_blob<const N: usize>(
    value: Vec<u8>,
    reason: &'static str,
) -> StoreResult<[u8; N]> {
    value
        .try_into()
        .map_err(|_| StoreError::SchemaMismatch(reason.to_owned()))
}

pub(crate) fn optional_fixed_blob<const N: usize>(
    value: Option<Vec<u8>>,
    reason: &'static str,
) -> StoreResult<Option<[u8; N]>> {
    value.map(|value| fixed_blob(value, reason)).transpose()
}

pub(crate) fn is_zero(value: &[u8]) -> bool {
    value.iter().all(|byte| *byte == 0)
}
