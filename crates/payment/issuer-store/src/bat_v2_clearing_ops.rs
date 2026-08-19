use crate::bat_v2_ops::read_bat_acceptance_class_v2;
use crate::db::{
    advance_store_generation, commit, db_u64, fixed_blob, is_zero, sql_integer,
    verify_expected_identity,
};
use crate::rollback::mutation_digest;
use crate::{
    BatV2AccountingAuthorizationRecordV2, CommitMarker, DurableWrite, IssuerStore,
    ProviderAccountBindingRecordV2, StoreError, StoreResult, WriteDisposition,
    MAX_EXACT_BAT_V2_ACCOUNTING_APPROVAL_BYTES, MAX_EXACT_BAT_V2_ACCOUNTING_AUTHORIZATION_BYTES,
    MAX_EXACT_BAT_V2_REDEEM_SUCCESS_BYTES,
};
use ed25519_dalek::VerifyingKey;
use pir_service_protocol::{
    bat_v2_redeem_ledger_transaction_id_v2, BatV2RedeemCommitStoreV2, IssuerAccountingApprovalV2,
    ProviderAccountingAuthorizationV2, ProviderRedeemOutcomeV2, ProviderRedeemRequestV2,
    ProviderRedeemResponseV2, SettlementUnitV1, VerifiedBatV2RedeemCommitV2,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};

const SYSTEM_LEDGER_ACCOUNT_ID_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-store/system-ledger-account-id/v1";
const SYSTEM_ACCOUNT_CREDENTIAL_SOURCE: u8 = 1;
const SYSTEM_ACCOUNT_ISSUER_FEE: u8 = 2;
const ACCOUNT_KIND_PROVIDER: i64 = 1;
const ACCOUNT_KIND_CREDENTIAL_SOURCE: i64 = 2;
const ACCOUNT_KIND_ISSUER_FEE: i64 = 3;
const BAT_V2_LEDGER_TRANSACTION_KIND: i64 = 7;

type RawBatV2Authorization = (
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    Vec<u8>,
    Vec<u8>,
    i64,
);

/// Store adapter for the protocol fresh-commit gate. `now_unix` is captured
/// by the issuer before precheck and reused for transaction-time revalidation.
pub struct IssuerBatV2RedeemCommitterV2<'a> {
    store: &'a IssuerStore,
    now_unix: u64,
}

impl<'a> IssuerBatV2RedeemCommitterV2<'a> {
    pub fn new(store: &'a IssuerStore, now_unix: u64) -> StoreResult<Self> {
        if now_unix == 0 {
            return Err(StoreError::InvalidInput("BAT V2 redeem time is zero"));
        }
        Ok(Self { store, now_unix })
    }
}

impl BatV2RedeemCommitStoreV2 for IssuerBatV2RedeemCommitterV2<'_> {
    type Error = StoreError;

    fn commit_fresh(
        &mut self,
        verified: &VerifiedBatV2RedeemCommitV2,
        signed_initial_success: &ProviderRedeemResponseV2,
    ) -> Result<bool, Self::Error> {
        self.store
            .commit_fresh_bat_v2_redeem(verified, signed_initial_success, self.now_unix)
    }
}

impl IssuerStore {
    /// Registers exact BAT V2 operator and issuer accounting artifacts. The
    /// external keys are explicit pinned roots, never learned from the input.
    #[allow(clippy::too_many_arguments)]
    pub fn register_bat_v2_accounting_authorization(
        &self,
        authorization: &ProviderAccountingAuthorizationV2,
        approval: &IssuerAccountingApprovalV2,
        expected_operator_key: &VerifyingKey,
        expected_issuer_settlement_key: &VerifyingKey,
        now_unix: u64,
    ) -> StoreResult<DurableWrite<BatV2AccountingAuthorizationRecordV2>> {
        if now_unix == 0 {
            return Err(StoreError::InvalidInput(
                "BAT V2 accounting registration time is zero",
            ));
        }
        let exact_authorization = authorization.encode()?;
        let exact_approval = approval.encode().to_vec();
        let operator_root = expected_operator_key.to_bytes();
        let settlement_root = expected_issuer_settlement_key.to_bytes();
        if exact_authorization.len() > MAX_EXACT_BAT_V2_ACCOUNTING_AUTHORIZATION_BYTES
            || exact_approval.len() > MAX_EXACT_BAT_V2_ACCOUNTING_APPROVAL_BYTES
        {
            return Err(StoreError::InvalidInput(
                "BAT V2 accounting artifact exceeds store bound",
            ));
        }
        let digest = authorization.authorization_digest()?;
        let provider_id = authorization.claims.provider_id;
        let account_id = authorization.claims.settlement_account_id;

        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous_identity = verify_expected_identity(&transaction, &self.handle)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;

        if let Some(existing) = read_bat_v2_authorization(&transaction, self, &digest)? {
            if existing.exact_authorization == exact_authorization
                && existing.exact_approval == exact_approval
                && existing.operator_verifying_key == operator_root
                && existing.issuer_settlement_verifying_key == settlement_root
            {
                return Ok(DurableWrite {
                    disposition: WriteDisposition::ExactReplay,
                    commit: existing.commit,
                    value: existing,
                });
            }
            return Err(StoreError::BatV2ClearingAuthorizationFork);
        }

        let highest_epoch: Option<i64> = transaction.query_row(
            "SELECT MAX(authorization_epoch) FROM bat_v2_clearing_authorizations \
             WHERE issuer_id = ?1 AND provider_id = ?2",
            params![
                self.handle.expected_issuer_id.as_slice(),
                provider_id.as_slice(),
            ],
            |row| row.get(0),
        )?;
        let highest_epoch = highest_epoch
            .map(|value| db_u64(value, "negative BAT V2 authorization epoch"))
            .transpose()?
            .unwrap_or(0);
        if authorization.claims.authorization_epoch < highest_epoch {
            return Err(StoreError::BatV2ClearingAuthorizationRollback);
        }
        if authorization.claims.authorization_epoch == highest_epoch && highest_epoch != 0 {
            return Err(StoreError::BatV2ClearingAuthorizationFork);
        }
        authorization.verify_for(
            &provider_id,
            &self.handle.expected_issuer_id,
            expected_operator_key,
            now_unix,
            highest_epoch,
        )?;
        approval.verify_for(
            authorization,
            expected_issuer_settlement_key,
            now_unix,
            highest_epoch,
        )?;

        let mutation = mutation_digest(
            b"register-bat-v2-accounting-authorization-v2",
            &[
                &digest,
                &provider_id,
                &authorization.claims.authorization_epoch.to_le_bytes(),
                &account_id,
                &operator_root,
                &settlement_root,
                &exact_approval,
            ],
        );
        let committed_identity = advance_store_generation(
            &transaction,
            &previous_identity,
            b"register-bat-v2-accounting-authorization-v2",
            &mutation,
        )?;
        let sequence = committed_identity.commit_seq;
        ensure_provider_account_binding(
            &transaction,
            self,
            &provider_id,
            &account_id,
            SettlementUnitV1::AuthCredit,
            sequence,
        )?;
        ensure_ledger_account(
            &transaction,
            self,
            &provider_id,
            &account_id,
            SettlementUnitV1::AuthCredit,
            sequence,
        )?;
        transaction.execute(
            "INSERT INTO bat_v2_clearing_authorizations \
             (authorization_digest, issuer_id, authorization_id, authorization_epoch, \
              provider_id, settlement_account_id, operator_verifying_key, \
              issuer_settlement_verifying_key, not_before, not_after, exact_authorization, \
              exact_approval, commit_seq) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, \
              ?9, ?10, ?11, ?12, ?13)",
            params![
                digest.as_slice(),
                self.handle.expected_issuer_id.as_slice(),
                authorization.claims.authorization_id.as_slice(),
                sql_integer(
                    authorization.claims.authorization_epoch,
                    "BAT V2 authorization epoch exceeds SQLite range"
                )?,
                provider_id.as_slice(),
                account_id.as_slice(),
                operator_root.as_slice(),
                settlement_root.as_slice(),
                sql_integer(
                    authorization.claims.not_before.max(approval.approved_at),
                    "BAT V2 authorization not_before exceeds SQLite range"
                )?,
                sql_integer(
                    approval.not_after,
                    "BAT V2 authorization not_after exceeds SQLite range"
                )?,
                exact_authorization.as_slice(),
                exact_approval.as_slice(),
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
            ],
        )?;
        commit(transaction)?;
        self.anchor_committed_identity(&previous_floor, &committed_identity)?;
        let value = self
            .bat_v2_accounting_authorization(&digest)?
            .ok_or_else(|| {
                StoreError::SchemaMismatch(
                    "committed BAT V2 accounting authorization missing".to_owned(),
                )
            })?;
        Ok(DurableWrite {
            disposition: WriteDisposition::Committed,
            commit: marker(self, sequence),
            value,
        })
    }

    pub fn bat_v2_accounting_authorization(
        &self,
        digest: &[u8; 32],
    ) -> StoreResult<Option<BatV2AccountingAuthorizationRecordV2>> {
        if is_zero(digest) {
            return Err(StoreError::InvalidInput(
                "BAT V2 accounting authorization digest is zero",
            ));
        }
        let connection = self.open_checked(false)?;
        let value = read_bat_v2_authorization(&connection, self, digest)?;
        self.confirm_anchored_read(&connection, value)
    }

    /// Returns the sole authorization eligible for new debt for this
    /// provider. Digest-addressed history remains available only so callers
    /// can classify an old request without treating it as current authority.
    pub fn current_bat_v2_accounting_authorization(
        &self,
        provider_id: &[u8; 32],
    ) -> StoreResult<Option<BatV2AccountingAuthorizationRecordV2>> {
        if is_zero(provider_id) {
            return Err(StoreError::InvalidInput("BAT V2 provider id is zero"));
        }
        let connection = self.open_checked(false)?;
        let digest: Option<Vec<u8>> = connection
            .query_row(
                "SELECT authorization_digest FROM bat_v2_clearing_authorizations \
                 WHERE issuer_id = ?1 AND provider_id = ?2 \
                 ORDER BY authorization_epoch DESC LIMIT 1",
                params![
                    self.handle.expected_issuer_id.as_slice(),
                    provider_id.as_slice(),
                ],
                |row| row.get(0),
            )
            .optional()?;
        let value = digest
            .map(|digest| {
                let digest = fixed_blob(digest, "invalid current BAT V2 authorization digest")?;
                read_bat_v2_authorization(&connection, self, &digest)?.ok_or_else(|| {
                    StoreError::SchemaMismatch(
                        "current BAT V2 authorization disappeared".to_owned(),
                    )
                })
            })
            .transpose()?;
        self.confirm_anchored_read(&connection, value)
    }

    /// Returns only terminal attempt state. Prior success bytes are never
    /// exposed or replayed by a public API.
    pub fn bat_v2_attempt_is_committed(
        &self,
        provider_id: &[u8; 32],
        attempt_id: &[u8; 32],
    ) -> StoreResult<bool> {
        if is_zero(provider_id) || is_zero(attempt_id) {
            return Err(StoreError::InvalidInput(
                "BAT V2 provider or attempt id is zero",
            ));
        }
        let connection = self.open_checked(false)?;
        let found: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM bat_v2_redemptions \
             WHERE issuer_id = ?1 AND provider_id = ?2 AND attempt_id = ?3)",
            params![
                self.handle.expected_issuer_id.as_slice(),
                provider_id.as_slice(),
                attempt_id.as_slice(),
            ],
            |row| row.get(0),
        )?;
        self.confirm_anchored_read(&connection, found)
    }

    pub fn bat_v2_redeem_committer(
        &self,
        now_unix: u64,
    ) -> StoreResult<IssuerBatV2RedeemCommitterV2<'_>> {
        IssuerBatV2RedeemCommitterV2::new(self, now_unix)
    }

    fn commit_fresh_bat_v2_redeem(
        &self,
        verified: &VerifiedBatV2RedeemCommitV2,
        signed_initial_success: &ProviderRedeemResponseV2,
        now_unix: u64,
    ) -> StoreResult<bool> {
        let request = verified.request();
        if now_unix == 0 || request.issuer_id != self.handle.expected_issuer_id {
            return Err(StoreError::BatV2RedeemPreconditionChanged);
        }
        let request_digest = request.request_digest()?;
        let ledger_transaction_id = bat_v2_redeem_ledger_transaction_id_v2(request)?;
        let exact_success = signed_initial_success.encode()?;
        if exact_success.len() > MAX_EXACT_BAT_V2_REDEEM_SUCCESS_BYTES
            || is_zero(verified.global_spend_key())
        {
            return Err(StoreError::InvalidInput(
                "BAT V2 success encoding or spend key is invalid",
            ));
        }

        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous_identity = verify_expected_identity(&transaction, &self.handle)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;

        // BEGIN IMMEDIATE serializes this cross-table global-spend decision.
        // Conflicts are terminal but prior success bytes are never read.
        let already_committed: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM bat_v2_redemptions \
                 WHERE issuer_id = ?1 AND provider_id = ?2 AND attempt_id = ?3) \
             OR EXISTS(SELECT 1 FROM bat_v2_redemptions WHERE global_spend_key = ?4) \
             OR EXISTS(SELECT 1 FROM redemptions WHERE credential_spend_key = ?4)",
            params![
                self.handle.expected_issuer_id.as_slice(),
                request.provider_id.as_slice(),
                request.attempt_id.as_slice(),
                verified.global_spend_key().as_slice(),
            ],
            |row| row.get(0),
        )?;
        if already_committed {
            return Ok(false);
        }

        let authorization = read_bat_v2_authorization(
            &transaction,
            self,
            &request.accounting_authorization_digest,
        )?
        .ok_or(StoreError::BatV2RedeemPreconditionChanged)?;
        let highest_epoch: i64 = transaction.query_row(
            "SELECT MAX(authorization_epoch) FROM bat_v2_clearing_authorizations \
             WHERE issuer_id = ?1 AND provider_id = ?2",
            params![
                self.handle.expected_issuer_id.as_slice(),
                request.provider_id.as_slice(),
            ],
            |row| row.get(0),
        )?;
        if db_u64(highest_epoch, "negative BAT V2 authorization epoch")?
            != authorization.authorization_epoch
            || now_unix < authorization.not_before
            || now_unix > authorization.not_after
            || authorization.provider_id != request.provider_id
            || authorization.settlement_account_id != request.settlement_account_id
        {
            return Err(StoreError::BatV2RedeemPreconditionChanged);
        }
        let (exact_authorization, exact_approval) = authorization.decode_exact()?;
        exact_authorization.verify_for(
            &request.provider_id,
            &self.handle.expected_issuer_id,
            &VerifyingKey::from_bytes(&authorization.operator_verifying_key)
                .map_err(|_| StoreError::BatV2RedeemPreconditionChanged)?,
            now_unix,
            authorization.authorization_epoch,
        )?;
        let settlement_key =
            VerifyingKey::from_bytes(&authorization.issuer_settlement_verifying_key)
                .map_err(|_| StoreError::BatV2RedeemPreconditionChanged)?;
        exact_approval.verify_for(
            &exact_authorization,
            &settlement_key,
            now_unix,
            authorization.authorization_epoch,
        )?;
        let rule = exact_authorization
            .claims
            .rules
            .iter()
            .find(|rule| {
                rule.class_id == request.class_id
                    && rule.policy_digest == request.policy_digest
                    && rule.scope_id == request.scope_id
                    && rule.offer_id == request.offer_id
            })
            .ok_or(StoreError::BatV2RedeemPreconditionChanged)?;
        if rule.unit != request.unit
            || rule.accepted_value != request.accepted_value
            || rule.provider_credit != verified.provider_credit()
            || rule.issuer_fee != verified.issuer_fee()
        {
            return Err(StoreError::BatV2RedeemPreconditionChanged);
        }

        let class = read_bat_acceptance_class_v2(
            &transaction,
            self,
            &request.class_id,
            request.class_key_epoch,
        )?
        .ok_or(StoreError::BatV2RedeemPreconditionChanged)?;
        let member = class
            .members
            .iter()
            .find(|member| {
                member.provider_id == request.provider_id
                    && member.policy_digest == request.policy_digest
                    && member.scope_id == request.scope_id
                    && member.offer_id == request.offer_id
            })
            .ok_or(StoreError::BatV2RedeemPreconditionChanged)?;
        if class.artifact_digest != request.class_digest
            || class.bat_key_id != request.bat_key_id
            || now_unix < class.key_not_before
            || now_unix > class.key_not_after
            || now_unix > member.redemption_deadline
        {
            return Err(StoreError::BatV2RedeemPreconditionChanged);
        }
        require_provider_account_binding(
            &transaction,
            self,
            &request.provider_id,
            &request.settlement_account_id,
            request.unit,
        )?;
        signed_initial_success.verify_for_exact_request(request, &settlement_key)?;
        match &signed_initial_success.outcome {
            ProviderRedeemOutcomeV2::GrantableSuccess {
                account_id,
                ledger_transaction_id: response_transaction_id,
                unit,
                accepted_value,
                provider_credit,
                issuer_fee,
            } if account_id == &request.settlement_account_id
                && response_transaction_id == &ledger_transaction_id
                && unit == &request.unit
                && accepted_value == &request.accepted_value
                && *provider_credit == verified.provider_credit()
                && *issuer_fee == verified.issuer_fee() => {}
            _ => return Err(StoreError::BatV2RedeemPreconditionChanged),
        }

        let mutation = mutation_digest(
            b"commit-bat-v2-redeem-v2",
            &[
                &request_digest,
                verified.global_spend_key(),
                &ledger_transaction_id,
                &exact_success,
            ],
        );
        let committed_identity = advance_store_generation(
            &transaction,
            &previous_identity,
            b"commit-bat-v2-redeem-v2",
            &mutation,
        )?;
        let sequence = committed_identity.commit_seq;
        credit_provider_account(
            &transaction,
            self,
            &request.provider_id,
            &request.settlement_account_id,
            request.unit,
            verified.provider_credit(),
            sequence,
        )?;
        insert_bat_v2_ledger_transaction(
            &transaction,
            self,
            request,
            verified.provider_credit(),
            verified.issuer_fee(),
            &ledger_transaction_id,
            &request_digest,
            now_unix,
            sequence,
        )?;
        transaction.execute(
            "INSERT INTO bat_v2_redemptions \
             (issuer_id, provider_id, attempt_id, request_digest, authorization_digest, \
              settlement_account_id, class_id, class_key_epoch, class_digest, member_index, \
              credential_digest, global_spend_key, accepted_value, provider_credit, issuer_fee, \
              unit, ledger_transaction_id, exact_initial_success, redeemed_at, commit_seq) \
              VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, \
                      ?15, ?16, ?17, ?18, ?19, ?20)",
            params![
                self.handle.expected_issuer_id.as_slice(),
                request.provider_id.as_slice(),
                request.attempt_id.as_slice(),
                request_digest.as_slice(),
                request.accounting_authorization_digest.as_slice(),
                request.settlement_account_id.as_slice(),
                request.class_id.as_slice(),
                sql_integer(
                    request.class_key_epoch,
                    "BAT V2 class epoch exceeds SQLite range"
                )?,
                request.class_digest.as_slice(),
                i64::from(member.member_index),
                request.credential_digest.as_slice(),
                verified.global_spend_key().as_slice(),
                sql_integer(
                    request.accepted_value,
                    "BAT V2 accepted value exceeds SQLite range"
                )?,
                sql_integer(
                    verified.provider_credit(),
                    "BAT V2 provider credit exceeds SQLite range"
                )?,
                sql_integer(
                    verified.issuer_fee(),
                    "BAT V2 issuer fee exceeds SQLite range"
                )?,
                request.unit as u8,
                ledger_transaction_id.as_slice(),
                exact_success.as_slice(),
                sql_integer(now_unix, "BAT V2 redeem time exceeds SQLite range")?,
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
            ],
        )?;
        commit(transaction)?;
        self.anchor_committed_identity(&previous_floor, &committed_identity)?;
        Ok(true)
    }
}

pub(crate) fn ensure_provider_account_binding(
    connection: &Connection,
    store: &IssuerStore,
    provider_id: &[u8; 32],
    account_id: &[u8; 32],
    unit: SettlementUnitV1,
    sequence: u64,
) -> StoreResult<()> {
    connection.execute(
        "INSERT OR IGNORE INTO provider_account_bindings \
         (issuer_id, provider_id, settlement_account_id, unit, commit_seq) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            store.handle.expected_issuer_id.as_slice(),
            provider_id.as_slice(),
            account_id.as_slice(),
            unit as u8,
            sql_integer(sequence, "commit sequence exceeds SQLite range")?,
        ],
    )?;
    require_provider_account_binding(connection, store, provider_id, account_id, unit).map(|_| ())
}

fn require_provider_account_binding(
    connection: &Connection,
    store: &IssuerStore,
    provider_id: &[u8; 32],
    account_id: &[u8; 32],
    unit: SettlementUnitV1,
) -> StoreResult<ProviderAccountBindingRecordV2> {
    let raw: Option<(Vec<u8>, i64, i64)> = connection
        .query_row(
            "SELECT settlement_account_id, unit, commit_seq FROM provider_account_bindings \
             WHERE issuer_id = ?1 AND provider_id = ?2",
            params![
                store.handle.expected_issuer_id.as_slice(),
                provider_id.as_slice(),
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((stored_account, stored_unit, commit_seq)) = raw else {
        return Err(StoreError::ProviderAccountBindingConflict);
    };
    if stored_account.as_slice() != account_id || stored_unit != unit as i64 {
        return Err(StoreError::ProviderAccountBindingConflict);
    }
    Ok(ProviderAccountBindingRecordV2 {
        provider_id: *provider_id,
        settlement_account_id: fixed_blob(stored_account, "invalid provider account binding")?,
        unit,
        commit: marker(
            store,
            db_u64(commit_seq, "negative provider account binding commit")?,
        ),
    })
}

pub(crate) fn ensure_ledger_account(
    connection: &Connection,
    store: &IssuerStore,
    provider_id: &[u8; 32],
    account_id: &[u8; 32],
    unit: SettlementUnitV1,
    sequence: u64,
) -> StoreResult<()> {
    connection.execute(
        "INSERT OR IGNORE INTO ledger_accounts \
         (account_id, issuer_id, provider_id, unit, available_value, reserved_value, \
          ledger_sequence, commit_seq) VALUES (?1, ?2, ?3, ?4, 0, 0, 0, ?5)",
        params![
            account_id.as_slice(),
            store.handle.expected_issuer_id.as_slice(),
            provider_id.as_slice(),
            unit as u8,
            sql_integer(sequence, "commit sequence exceeds SQLite range")?,
        ],
    )?;
    let exact: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM ledger_accounts WHERE issuer_id = ?1 \
         AND provider_id = ?2 AND account_id = ?3 AND unit = ?4)",
        params![
            store.handle.expected_issuer_id.as_slice(),
            provider_id.as_slice(),
            account_id.as_slice(),
            unit as u8,
        ],
        |row| row.get(0),
    )?;
    if !exact {
        return Err(StoreError::ProviderAccountBindingConflict);
    }
    Ok(())
}

fn read_bat_v2_authorization(
    connection: &Connection,
    store: &IssuerStore,
    digest: &[u8; 32],
) -> StoreResult<Option<BatV2AccountingAuthorizationRecordV2>> {
    let raw: Option<RawBatV2Authorization> = connection
        .query_row(
            "SELECT authorization_id, authorization_epoch, provider_id, settlement_account_id, \
             operator_verifying_key, issuer_settlement_verifying_key, not_before, not_after, \
             exact_authorization, exact_approval, commit_seq \
             FROM bat_v2_clearing_authorizations \
             WHERE issuer_id = ?1 AND authorization_digest = ?2",
            params![
                store.handle.expected_issuer_id.as_slice(),
                digest.as_slice(),
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
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                ))
            },
        )
        .optional()?;
    raw.map(|raw| rebuild_bat_v2_authorization(store, digest, raw))
        .transpose()
}

fn rebuild_bat_v2_authorization(
    store: &IssuerStore,
    digest: &[u8; 32],
    raw: RawBatV2Authorization,
) -> StoreResult<BatV2AccountingAuthorizationRecordV2> {
    let exact_authorization = raw.8;
    let exact_approval = raw.9;
    let authorization = ProviderAccountingAuthorizationV2::decode(&exact_authorization)?;
    let approval = IssuerAccountingApprovalV2::decode(&exact_approval)?;
    let operator_verifying_key = fixed_blob(raw.4, "invalid BAT V2 operator key")?;
    let issuer_settlement_verifying_key =
        fixed_blob(raw.5, "invalid BAT V2 issuer settlement key")?;
    let operator_key = VerifyingKey::from_bytes(&operator_verifying_key)
        .map_err(|_| StoreError::SchemaMismatch("invalid BAT V2 operator root".to_owned()))?;
    let settlement_key = VerifyingKey::from_bytes(&issuer_settlement_verifying_key)
        .map_err(|_| StoreError::SchemaMismatch("invalid BAT V2 settlement root".to_owned()))?;
    let authorization_epoch = db_u64(raw.1, "negative BAT V2 authorization epoch")?;
    let not_before = db_u64(raw.6, "negative BAT V2 authorization not_before")?;
    let not_after = db_u64(raw.7, "negative BAT V2 authorization not_after")?;
    let signature_time = not_before.min(not_after);
    if authorization.encode()? != exact_authorization
        || approval.encode().as_slice() != exact_approval.as_slice()
        || authorization.authorization_digest()? != *digest
        || authorization.claims.authorization_id.as_slice() != raw.0.as_slice()
        || authorization.claims.authorization_epoch != authorization_epoch
        || authorization.claims.provider_id.as_slice() != raw.2.as_slice()
        || authorization.claims.settlement_account_id.as_slice() != raw.3.as_slice()
        || authorization.claims.issuer_id != store.handle.expected_issuer_id
        || authorization.operator_verifying_key != operator_verifying_key
        || authorization
            .verify_for(
                &authorization.claims.provider_id,
                &store.handle.expected_issuer_id,
                &operator_key,
                signature_time,
                authorization_epoch,
            )
            .is_err()
        || approval
            .verify_for(
                &authorization,
                &settlement_key,
                signature_time,
                authorization_epoch,
            )
            .is_err()
        || not_before != authorization.claims.not_before.max(approval.approved_at)
        || not_after != approval.not_after
    {
        return Err(StoreError::SchemaMismatch(
            "BAT V2 accounting authorization row is not canonical or root-bound".to_owned(),
        ));
    }
    Ok(BatV2AccountingAuthorizationRecordV2 {
        authorization_digest: *digest,
        authorization_id: fixed_blob(raw.0, "invalid BAT V2 authorization id")?,
        authorization_epoch,
        provider_id: fixed_blob(raw.2, "invalid BAT V2 provider id")?,
        settlement_account_id: fixed_blob(raw.3, "invalid BAT V2 settlement account")?,
        operator_verifying_key,
        issuer_settlement_verifying_key,
        not_before,
        not_after,
        exact_authorization,
        exact_approval,
        commit: marker(
            store,
            db_u64(raw.10, "negative BAT V2 authorization commit")?,
        ),
    })
}

fn credit_provider_account(
    connection: &Connection,
    store: &IssuerStore,
    provider_id: &[u8; 32],
    account_id: &[u8; 32],
    unit: SettlementUnitV1,
    credit: u64,
    sequence: u64,
) -> StoreResult<()> {
    let current: (i64, i64, i64) = connection.query_row(
        "SELECT available_value, reserved_value, ledger_sequence FROM ledger_accounts \
         WHERE issuer_id = ?1 AND provider_id = ?2 AND account_id = ?3 AND unit = ?4",
        params![
            store.handle.expected_issuer_id.as_slice(),
            provider_id.as_slice(),
            account_id.as_slice(),
            unit as u8,
        ],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let next = db_u64(current.0, "negative available ledger balance")?
        .checked_add(credit)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or(StoreError::LedgerBalanceOverflow)?;
    let ledger_sequence = db_u64(current.2, "negative ledger sequence")?
        .checked_add(1)
        .ok_or(StoreError::LedgerBalanceOverflow)?;
    let changed = connection.execute(
        "UPDATE ledger_accounts SET available_value = ?1, ledger_sequence = ?2, commit_seq = ?3 \
         WHERE account_id = ?4 AND available_value = ?5 AND reserved_value = ?6 \
         AND ledger_sequence = ?7",
        params![
            sql_integer(next, "available ledger balance exceeds SQLite range")?,
            sql_integer(ledger_sequence, "ledger sequence exceeds SQLite range")?,
            sql_integer(sequence, "commit sequence exceeds SQLite range")?,
            account_id.as_slice(),
            current.0,
            current.1,
            current.2,
        ],
    )?;
    if changed != 1 {
        return Err(StoreError::SchemaMismatch(
            "BAT V2 provider ledger compare-and-set failed".to_owned(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_bat_v2_ledger_transaction(
    connection: &Connection,
    store: &IssuerStore,
    request: &ProviderRedeemRequestV2,
    provider_credit: u64,
    issuer_fee: u64,
    transaction_id: &[u8; 32],
    request_digest: &[u8; 32],
    now_unix: u64,
    sequence: u64,
) -> StoreResult<()> {
    connection.execute(
        "INSERT INTO ledger_transactions (transaction_id, issuer_id, provider_id, kind, \
         reference_digest, unit, created_at, commit_seq) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            transaction_id.as_slice(),
            store.handle.expected_issuer_id.as_slice(),
            request.provider_id.as_slice(),
            BAT_V2_LEDGER_TRANSACTION_KIND,
            request_digest.as_slice(),
            request.unit as u8,
            sql_integer(now_unix, "BAT V2 ledger time exceeds SQLite range")?,
            sql_integer(sequence, "commit sequence exceeds SQLite range")?,
        ],
    )?;
    let provider_credit =
        i64::try_from(provider_credit).map_err(|_| StoreError::LedgerBalanceOverflow)?;
    let accepted =
        i64::try_from(request.accepted_value).map_err(|_| StoreError::LedgerBalanceOverflow)?;
    connection.execute(
        "INSERT INTO ledger_postings \
         (transaction_id, line_no, account_kind, account_id, signed_amount) \
         VALUES (?1, 1, ?2, ?3, ?4)",
        params![
            transaction_id.as_slice(),
            ACCOUNT_KIND_PROVIDER,
            request.settlement_account_id.as_slice(),
            provider_credit,
        ],
    )?;
    let mut source_line = 2i64;
    if issuer_fee != 0 {
        let issuer_fee =
            i64::try_from(issuer_fee).map_err(|_| StoreError::LedgerBalanceOverflow)?;
        connection.execute(
            "INSERT INTO ledger_postings \
             (transaction_id, line_no, account_kind, account_id, signed_amount) \
             VALUES (?1, 2, ?2, ?3, ?4)",
            params![
                transaction_id.as_slice(),
                ACCOUNT_KIND_ISSUER_FEE,
                system_account_id(store, SYSTEM_ACCOUNT_ISSUER_FEE).as_slice(),
                issuer_fee,
            ],
        )?;
        source_line = 3;
    }
    connection.execute(
        "INSERT INTO ledger_postings \
         (transaction_id, line_no, account_kind, account_id, signed_amount) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            transaction_id.as_slice(),
            source_line,
            ACCOUNT_KIND_CREDENTIAL_SOURCE,
            system_account_id(store, SYSTEM_ACCOUNT_CREDENTIAL_SOURCE).as_slice(),
            -accepted,
        ],
    )?;
    Ok(())
}

fn system_account_id(store: &IssuerStore, kind: u8) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SYSTEM_LEDGER_ACCOUNT_ID_DOMAIN_V1);
    hasher.update(store.handle.expected_issuer_id);
    hasher.update([kind]);
    hasher.finalize().into()
}

pub(crate) fn verify_all_bat_v2_clearing(
    store: &IssuerStore,
    connection: &Connection,
) -> StoreResult<()> {
    let mut statement = connection.prepare(
        "SELECT authorization_digest FROM bat_v2_clearing_authorizations \
         WHERE issuer_id = ?1 ORDER BY provider_id, authorization_epoch",
    )?;
    let digests = statement
        .query_map([store.handle.expected_issuer_id.as_slice()], |row| {
            row.get::<_, Vec<u8>>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for digest in digests {
        let digest = fixed_blob(digest, "invalid BAT V2 authorization digest")?;
        if read_bat_v2_authorization(connection, store, &digest)?.is_none() {
            return Err(StoreError::SchemaMismatch(
                "BAT V2 accounting authorization disappeared during integrity read".to_owned(),
            ));
        }
    }
    let bad_epoch_order: i64 = connection.query_row(
        "SELECT COUNT(*) FROM bat_v2_clearing_authorizations current \
         WHERE EXISTS (SELECT 1 FROM bat_v2_clearing_authorizations prior \
             WHERE prior.issuer_id = current.issuer_id \
               AND prior.provider_id = current.provider_id \
               AND prior.authorization_epoch < current.authorization_epoch \
               AND prior.commit_seq >= current.commit_seq)",
        [],
        |row| row.get(0),
    )?;
    if bad_epoch_order != 0 {
        return Err(StoreError::SchemaMismatch(
            "BAT V2 authorization epoch and commit order disagree".to_owned(),
        ));
    }
    verify_bat_v2_redemption_rows(store, connection)
}

fn verify_bat_v2_redemption_rows(store: &IssuerStore, connection: &Connection) -> StoreResult<()> {
    let mut statement = connection.prepare(
        "SELECT r.provider_id, r.attempt_id, r.request_digest, r.authorization_digest, \
         r.settlement_account_id, r.class_id, r.class_key_epoch, r.class_digest, \
         r.member_index, r.credential_digest, r.accepted_value, r.provider_credit, r.issuer_fee, \
         r.unit, r.ledger_transaction_id, r.exact_initial_success, r.redeemed_at, r.commit_seq \
         FROM bat_v2_redemptions r WHERE r.issuer_id = ?1 ORDER BY r.provider_id, r.attempt_id",
    )?;
    let mut rows = statement.query([store.handle.expected_issuer_id.as_slice()])?;
    while let Some(row) = rows.next()? {
        let provider_id: [u8; 32] = fixed_blob(row.get(0)?, "invalid BAT V2 redeem provider")?;
        let attempt_id: [u8; 32] = fixed_blob(row.get(1)?, "invalid BAT V2 attempt")?;
        let request_digest: [u8; 32] = fixed_blob(row.get(2)?, "invalid BAT V2 request digest")?;
        let authorization_digest: [u8; 32] =
            fixed_blob(row.get(3)?, "invalid BAT V2 authorization digest")?;
        let account_id: [u8; 32] = fixed_blob(row.get(4)?, "invalid BAT V2 account")?;
        let class_id: [u8; 32] = fixed_blob(row.get(5)?, "invalid BAT V2 class")?;
        let class_epoch = db_u64(row.get(6)?, "negative BAT V2 class epoch")?;
        let class_digest: [u8; 32] = fixed_blob(row.get(7)?, "invalid BAT V2 class digest")?;
        let member_index = usize::try_from(row.get::<_, i64>(8)?)
            .map_err(|_| StoreError::SchemaMismatch("invalid BAT V2 member index".to_owned()))?;
        let credential_digest: [u8; 32] =
            fixed_blob(row.get(9)?, "invalid BAT V2 credential digest")?;
        let accepted_value = db_u64(row.get(10)?, "negative BAT V2 accepted value")?;
        let provider_credit = db_u64(row.get(11)?, "negative BAT V2 provider credit")?;
        let issuer_fee = db_u64(row.get(12)?, "negative BAT V2 issuer fee")?;
        let unit = settlement_unit_from_db(row.get(13)?)?;
        let ledger_transaction_id: [u8; 32] =
            fixed_blob(row.get(14)?, "invalid BAT V2 ledger transaction")?;
        let exact_success: Vec<u8> = row.get(15)?;
        let redeemed_at = db_u64(row.get(16)?, "negative BAT V2 redeem time")?;
        let redemption_commit = db_u64(row.get(17)?, "negative BAT V2 redeem commit")?;
        let authorization = read_bat_v2_authorization(connection, store, &authorization_digest)?
            .ok_or_else(|| {
                StoreError::SchemaMismatch("BAT V2 redeem authorization missing".to_owned())
            })?;
        let (exact_authorization, _) = authorization.decode_exact()?;
        let class = read_bat_acceptance_class_v2(connection, store, &class_id, class_epoch)?
            .ok_or_else(|| StoreError::SchemaMismatch("BAT V2 redeem class missing".to_owned()))?;
        let member = class
            .members
            .get(member_index)
            .ok_or_else(|| StoreError::SchemaMismatch("BAT V2 redeem member missing".to_owned()))?;
        let request = ProviderRedeemRequestV2 {
            accounting_authorization_digest: authorization_digest,
            issuer_id: store.handle.expected_issuer_id,
            provider_id,
            policy_digest: member.policy_digest,
            scope_id: member.scope_id,
            offer_id: member.offer_id,
            class_id,
            class_digest,
            class_key_epoch: class_epoch,
            bat_key_id: class.bat_key_id,
            credential_digest,
            unit,
            accepted_value,
            settlement_account_id: account_id,
            attempt_id,
        };
        let rule = exact_authorization
            .claims
            .rules
            .iter()
            .find(|rule| {
                rule.class_id == class_id
                    && rule.policy_digest == member.policy_digest
                    && rule.scope_id == member.scope_id
                    && rule.offer_id == member.offer_id
            })
            .ok_or_else(|| {
                StoreError::SchemaMismatch("BAT V2 redeem accounting rule missing".to_owned())
            })?;
        let response = ProviderRedeemResponseV2::decode(&exact_success)?;
        let settlement_key =
            VerifyingKey::from_bytes(&authorization.issuer_settlement_verifying_key)
                .map_err(|_| StoreError::SchemaMismatch("invalid settlement root".to_owned()))?;
        if request.request_digest()? != request_digest
            || bat_v2_redeem_ledger_transaction_id_v2(&request)? != ledger_transaction_id
            || response.encode()? != exact_success
            || response
                .verify_for_exact_request(&request, &settlement_key)
                .is_err()
            || authorization.provider_id != provider_id
            || authorization.settlement_account_id != account_id
            || member.provider_id != provider_id
            || class.artifact_digest != class_digest
            || rule.unit != unit
            || rule.accepted_value != accepted_value
            || rule.provider_credit != provider_credit
            || rule.issuer_fee != issuer_fee
            || redeemed_at < authorization.not_before
            || redeemed_at > authorization.not_after
            || redeemed_at < class.key_not_before
            || redeemed_at > class.key_not_after
            || redeemed_at > member.redemption_deadline
            || !matches!(
                response.outcome,
                ProviderRedeemOutcomeV2::GrantableSuccess {
                    account_id: response_account,
                    ledger_transaction_id: response_transaction,
                    unit: response_unit,
                    accepted_value: response_accepted,
                    provider_credit: response_credit,
                    issuer_fee: response_fee,
                } if response_account == account_id
                    && response_transaction == ledger_transaction_id
                    && response_unit == unit
                    && response_accepted == accepted_value
                    && response_credit == provider_credit
                    && response_fee == issuer_fee
            )
        {
            return Err(StoreError::SchemaMismatch(
                "BAT V2 redemption row or exact initial success is inconsistent".to_owned(),
            ));
        }
        let superseded_at_commit: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM bat_v2_clearing_authorizations later \
             WHERE later.issuer_id = ?1 AND later.provider_id = ?2 \
               AND later.authorization_epoch > ?3 AND later.commit_seq <= ?4)",
            params![
                store.handle.expected_issuer_id.as_slice(),
                provider_id.as_slice(),
                sql_integer(
                    authorization.authorization_epoch,
                    "BAT V2 authorization epoch exceeds SQLite range"
                )?,
                sql_integer(
                    redemption_commit,
                    "BAT V2 redeem commit exceeds SQLite range"
                )?,
            ],
            |row| row.get(0),
        )?;
        if superseded_at_commit {
            return Err(StoreError::SchemaMismatch(
                "BAT V2 redemption used a superseded authorization".to_owned(),
            ));
        }
    }
    Ok(())
}

fn settlement_unit_from_db(value: i64) -> StoreResult<SettlementUnitV1> {
    match value {
        1 => Ok(SettlementUnitV1::MilliSatoshi),
        2 => Ok(SettlementUnitV1::Satoshi),
        3 => Ok(SettlementUnitV1::AuthCredit),
        _ => Err(StoreError::SchemaMismatch(
            "invalid BAT V2 ledger unit".to_owned(),
        )),
    }
}

fn marker(store: &IssuerStore, sequence: u64) -> CommitMarker {
    CommitMarker {
        store_instance_id: store.handle.expected_store_instance_id,
        commit_seq: sequence,
    }
}
