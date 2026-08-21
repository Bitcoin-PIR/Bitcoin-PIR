use crate::db::{
    advance_store_generation, commit, db_u64, fixed_blob, is_zero, sql_integer,
    verify_expected_identity,
};
use crate::rollback::mutation_digest;
use crate::{
    CommitMarker, DurableWrite, IssuerStore, LedgerTransactionKindV1, PayoutIntentRecordV1,
    PayoutOutboxCommandV1, PayoutOutboxStateV1, PayoutRecordV1, StoreError, StoreResult,
    WriteDisposition, MAX_EXACT_PAYOUT_INTENT_REQUEST_BYTES,
    MAX_EXACT_PAYOUT_INTENT_RESPONSE_BYTES, MAX_EXACT_PAYOUT_REQUEST_BYTES,
    MAX_EXACT_PAYOUT_RESPONSE_BYTES, MAX_EXACT_PAYOUT_STATUS_RESPONSE_BYTES,
};
use ed25519_dalek::VerifyingKey;
use pir_service_protocol::{
    verify_new_payout_intent_response_for, verify_payout_initial_response_for_exact_request,
    verify_payout_status_successor_for_store_v1, IssuerClearingApprovalV1,
    IssuerPayoutIntentResponseV1, IssuerPayoutResponseV1, IssuerPayoutStatusResponseV1,
    IssuerSettlementKeyringExpectationV1, PayoutExecutionCommitStoreV1, PayoutStateV1,
    PayoutStatusCasExpectationV1, PayoutStatusCompareAndSwapStoreV1,
    ProviderClearingAuthorizationV1, ProviderClearingExpectationV1, ProviderClearingRequestAuthV1,
    ProviderPayoutIntentRequestV1, ProviderPayoutRequestV1, SettlementUnitV1,
    VerifiedPayoutExecutionV1,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};

const PAYOUT_INTENT_ID_DOMAIN_V1: &[u8] = b"BitcoinPIR/issuer-store/payout-intent-id/v1";
const PAYOUT_ID_DOMAIN_V1: &[u8] = b"BitcoinPIR/issuer-store/payout-id/v1";
const PAYOUT_LEDGER_TRANSACTION_ID_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-store/payout-ledger-transaction-id/v1";
const PAYOUT_TERMINAL_LEDGER_TRANSACTION_ID_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-store/payout-terminal-ledger-transaction-id/v1";
const PAYOUT_TERMINAL_REFERENCE_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-store/payout-terminal-reference/v1";
const PAYOUT_OUTBOX_COMMAND_ID_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-store/payout-outbox-command-id/v1";
const PAYOUT_INTENT_IDEMPOTENCY_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-store/idempotency/POST-/v1/payout-intents/v1";
const PAYOUT_IDEMPOTENCY_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-store/idempotency/POST-/v1/payouts/v1";
const PAYOUT_OUTBOX_LEASE_OWNER_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-store/payout-outbox-lease-owner/v1";
const SYSTEM_LEDGER_ACCOUNT_ID_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-store/system-ledger-account-id/v1";

const ACCOUNT_KIND_PROVIDER_AVAILABLE: i64 = 1;
const ACCOUNT_KIND_ISSUER_FEE: i64 = 3;
const ACCOUNT_KIND_PAYOUT_CLEARING: i64 = 5;
const ACCOUNT_KIND_PROVIDER_RESERVED: i64 = 6;
const SYSTEM_ACCOUNT_ISSUER_FEE: u8 = 2;
const SYSTEM_ACCOUNT_PAYOUT_CLEARING: u8 = 4;

pub fn issuer_payout_intent_id_v1(issuer_id: &[u8; 32], request_digest: &[u8; 32]) -> [u8; 32] {
    hash_parts(PAYOUT_INTENT_ID_DOMAIN_V1, &[issuer_id, request_digest])
}

pub fn issuer_payout_id_v1(issuer_id: &[u8; 32], payout_intent_id: &[u8; 32]) -> [u8; 32] {
    hash_parts(PAYOUT_ID_DOMAIN_V1, &[issuer_id, payout_intent_id])
}

pub fn issuer_payout_ledger_transaction_id_v1(
    issuer_id: &[u8; 32],
    request_digest: &[u8; 32],
) -> [u8; 32] {
    hash_parts(
        PAYOUT_LEDGER_TRANSACTION_ID_DOMAIN_V1,
        &[issuer_id, request_digest],
    )
}

pub fn issuer_payout_outbox_command_id_v1(issuer_id: &[u8; 32], payout_id: &[u8; 32]) -> [u8; 32] {
    hash_parts(PAYOUT_OUTBOX_COMMAND_ID_DOMAIN_V1, &[issuer_id, payout_id])
}

/// Store wrapper that repeats signature verification at the public trait
/// boundary. A caller cannot bypass issuer authentication by invoking the
/// protocol's commit trait directly.
pub struct IssuerPayoutExecutionCommitterV1<'a> {
    store: &'a IssuerStore,
    issuer_settlement_key: &'a VerifyingKey,
}

impl PayoutExecutionCommitStoreV1 for IssuerPayoutExecutionCommitterV1<'_> {
    type Error = StoreError;

    fn commit_new_payout(
        &mut self,
        execution: &VerifiedPayoutExecutionV1<'_>,
        signed_response: &IssuerPayoutResponseV1,
    ) -> Result<bool, Self::Error> {
        let keyring = IssuerSettlementKeyringExpectationV1 {
            issuer_id: &self.store.handle.expected_issuer_id,
            current_key: self.issuer_settlement_key,
            retained_keys: &[],
        };
        verify_payout_initial_response_for_exact_request(
            signed_response,
            execution.request(),
            &keyring,
        )?;
        self.store
            .commit_new_payout_inner(execution, signed_response)
    }
}

/// Store wrapper for exact-predecessor payout status CAS. It authenticates
/// the signed successor again before any financial or outbox mutation.
pub struct IssuerPayoutStatusCommitterV1<'a> {
    store: &'a IssuerStore,
    issuer_settlement_key: &'a VerifyingKey,
}

impl PayoutStatusCompareAndSwapStoreV1 for IssuerPayoutStatusCommitterV1<'_> {
    type Error = StoreError;

    fn compare_and_swap_payout_status(
        &mut self,
        predecessor: &PayoutStatusCasExpectationV1,
        signed_successor: &IssuerPayoutStatusResponseV1,
    ) -> Result<bool, Self::Error> {
        verify_payout_status_successor_for_store_v1(
            signed_successor,
            predecessor,
            self.issuer_settlement_key,
        )?;
        self.store
            .compare_and_swap_payout_status_inner(predecessor, signed_successor)
    }
}

impl IssuerStore {
    pub fn payout_execution_committer<'a>(
        &'a self,
        issuer_settlement_key: &'a VerifyingKey,
    ) -> IssuerPayoutExecutionCommitterV1<'a> {
        IssuerPayoutExecutionCommitterV1 {
            store: self,
            issuer_settlement_key,
        }
    }

    pub fn payout_status_committer<'a>(
        &'a self,
        issuer_settlement_key: &'a VerifyingKey,
    ) -> IssuerPayoutStatusCommitterV1<'a> {
        IssuerPayoutStatusCommitterV1 {
            store: self,
            issuer_settlement_key,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn commit_payout_intent(
        &self,
        request: &ProviderPayoutIntentRequestV1,
        response: &IssuerPayoutIntentResponseV1,
        authorization: &ProviderClearingAuthorizationV1,
        approval: &IssuerClearingApprovalV1,
        request_auth: &ProviderClearingRequestAuthV1,
        expectation: &ProviderClearingExpectationV1<'_>,
    ) -> StoreResult<DurableWrite<PayoutIntentRecordV1>> {
        let idempotency_digest = payout_intent_idempotency_digest(self, &request.idempotency_key);
        let request_digest = request.request_digest()?;
        let replay_image = payout_intent_replay_image(self, request)?;
        let exact_response = response.encode()?;
        if replay_image.len() > MAX_EXACT_PAYOUT_INTENT_REQUEST_BYTES
            || exact_response.len() > MAX_EXACT_PAYOUT_INTENT_RESPONSE_BYTES
        {
            return Err(StoreError::InvalidInput(
                "payout intent encoding exceeds store bound",
            ));
        }

        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous_identity = verify_expected_identity(&transaction, &self.handle)?;

        if let Some(existing) = read_payout_intent(&transaction, self, &idempotency_digest)? {
            if existing.request_digest == request_digest
                && existing.exact_request_replay_image == replay_image
                && existing.exact_response == exact_response
            {
                return Ok(DurableWrite {
                    disposition: WriteDisposition::ExactReplay,
                    commit: existing.commit,
                    value: existing,
                });
            }
            return Err(StoreError::PayoutIntentIdempotencyConflict);
        }

        let (registered_account, registered_target) = require_current_payout_configuration(
            &transaction,
            self,
            request.provider_id,
            request.authorization_digest,
        )?;
        if request.account_id != registered_account {
            return Err(StoreError::InvalidInput(
                "payout intent account is not provider registration",
            ));
        }
        verify_new_payout_intent_response_for(
            response,
            request,
            &registered_target,
            authorization,
            approval,
            request_auth,
            expectation,
        )?;
        if request.issuer_id != self.handle.expected_issuer_id
            || request.unit != SettlementUnitV1::AuthCredit
            || response.payout_intent_id
                != issuer_payout_intent_id_v1(&self.handle.expected_issuer_id, &request_digest)
            || response.expires_at <= expectation.now_unix
        {
            return Err(StoreError::InvalidInput(
                "payout intent identity, unit, or expiry is invalid",
            ));
        }
        require_exact_registered_authorization(
            &transaction,
            self,
            request.authorization_digest,
            authorization,
            approval,
        )?;

        let mutation = mutation_digest(
            b"commit-payout-intent-v1",
            &[
                &idempotency_digest,
                &request_digest,
                &response.payout_intent_id,
                &exact_response,
            ],
        );
        let committed_identity = advance_store_generation(
            &transaction,
            &previous_identity,
            b"commit-payout-intent-v1",
            &mutation,
        )?;
        let sequence = committed_identity.commit_seq;
        transaction.execute(
            "INSERT INTO payout_intents (idempotency_digest, request_digest, issuer_id, \
             provider_id, account_id, payout_target_id, unit, payout_value, issuer_fee, \
             total_debit, payout_intent_id, expires_at, consumed_by_payout_id, \
             request_replay_image, exact_response, commit_seq) VALUES (?1, ?2, ?3, ?4, ?5, \
             ?6, ?7, ?8, ?9, ?10, ?11, ?12, NULL, ?13, ?14, ?15)",
            params![
                idempotency_digest.as_slice(),
                request_digest.as_slice(),
                self.handle.expected_issuer_id.as_slice(),
                request.provider_id.as_slice(),
                request.account_id.as_slice(),
                request.payout_target_id.as_slice(),
                request.unit as u8,
                sql_integer(request.payout_value, "payout value exceeds SQLite range")?,
                sql_integer(response.issuer_fee, "payout fee exceeds SQLite range")?,
                sql_integer(response.total_debit, "payout debit exceeds SQLite range")?,
                response.payout_intent_id.as_slice(),
                sql_integer(
                    response.expires_at,
                    "payout intent expiry exceeds SQLite range"
                )?,
                replay_image.as_slice(),
                exact_response.as_slice(),
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
            ],
        )?;
        commit(transaction)?;
        let value = self.payout_intent_by_idempotency(request)?.ok_or_else(|| {
            StoreError::SchemaMismatch("committed payout intent missing".to_owned())
        })?;
        Ok(DurableWrite {
            disposition: WriteDisposition::Committed,
            commit: marker(self, sequence),
            value,
        })
    }

    pub fn payout_intent_by_idempotency(
        &self,
        request: &ProviderPayoutIntentRequestV1,
    ) -> StoreResult<Option<PayoutIntentRecordV1>> {
        let digest = payout_intent_idempotency_digest(self, &request.idempotency_key);
        let request_digest = request.request_digest()?;
        let replay_image = payout_intent_replay_image(self, request)?;
        let connection = self.open_checked(false)?;
        let value = read_payout_intent(&connection, self, &digest)?;
        if let Some(record) = &value {
            if record.request_digest != request_digest
                || record.exact_request_replay_image != replay_image
            {
                return Err(StoreError::PayoutIntentIdempotencyConflict);
            }
        }
        Ok(value)
    }

    pub fn payout_by_idempotency(
        &self,
        request: &ProviderPayoutRequestV1,
    ) -> StoreResult<Option<PayoutRecordV1>> {
        let digest = payout_idempotency_digest(self, &request.idempotency_key);
        let request_digest = request.request_digest()?;
        let replay_image = payout_replay_image(self, request)?;
        let connection = self.open_checked(false)?;
        let value = read_payout(&connection, self, &digest)?;
        if let Some(record) = &value {
            if record.request_digest != request_digest
                || record.exact_request_replay_image != replay_image
            {
                return Err(StoreError::PayoutIdempotencyConflict);
            }
        }
        Ok(value)
    }

    pub fn payout_by_id(&self, payout_id: &[u8; 32]) -> StoreResult<Option<PayoutRecordV1>> {
        if is_zero(payout_id) {
            return Err(StoreError::InvalidInput("payout id is all zero"));
        }
        let connection = self.open_checked(false)?;
        let value = read_payout_by_id(&connection, self, payout_id)?;
        Ok(value)
    }

    /// Claims one pending or expired payout command under a durable lease.
    /// The raw worker identity is domain-hashed before persistence.
    pub fn claim_next_payout_outbox(
        &self,
        lease_owner: &[u8; 32],
        now_unix: u64,
        lease_seconds: u64,
    ) -> StoreResult<Option<DurableWrite<PayoutOutboxCommandV1>>> {
        if is_zero(lease_owner) || now_unix == 0 || lease_seconds == 0 {
            return Err(StoreError::InvalidInput("invalid payout outbox lease"));
        }
        let lease_until = now_unix
            .checked_add(lease_seconds)
            .ok_or(StoreError::InvalidInput("payout outbox lease overflows"))?;
        let owner_digest = hash_parts(
            PAYOUT_OUTBOX_LEASE_OWNER_DOMAIN_V1,
            &[&self.handle.expected_issuer_id, lease_owner],
        );
        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous_identity = verify_expected_identity(&transaction, &self.handle)?;
        let command_id: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT command_id FROM payout_outbox WHERE state = 1 OR \
                 (state = 2 AND lease_until < ?1) ORDER BY command_id LIMIT 1",
                params![sql_integer(
                    now_unix,
                    "outbox claim time exceeds SQLite range"
                )?],
                |row| row.get(0),
            )
            .optional()?;
        let Some(command_id) = command_id else {
            return Ok(None);
        };
        let command_id: [u8; 32] = fixed_blob(command_id, "invalid payout command id")?;
        let mutation = mutation_digest(
            b"claim-payout-outbox-v1",
            &[&command_id, &owner_digest, &lease_until.to_le_bytes()],
        );
        let committed_identity = advance_store_generation(
            &transaction,
            &previous_identity,
            b"claim-payout-outbox-v1",
            &mutation,
        )?;
        let sequence = committed_identity.commit_seq;
        let changed = transaction.execute(
            "UPDATE payout_outbox SET state = 2, attempt_count = attempt_count + 1, \
             lease_owner_digest = ?1, lease_until = ?2, commit_seq = ?3 WHERE command_id = ?4 \
             AND (state = 1 OR (state = 2 AND lease_until < ?5))",
            params![
                owner_digest.as_slice(),
                sql_integer(lease_until, "outbox lease expiry exceeds SQLite range")?,
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
                command_id.as_slice(),
                sql_integer(now_unix, "outbox claim time exceeds SQLite range")?,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::PayoutOutboxUnavailable);
        }
        commit(transaction)?;
        let connection = self.open_checked(false)?;
        let value = read_outbox_command(&connection, self, &command_id)?.ok_or_else(|| {
            StoreError::SchemaMismatch("claimed payout command missing".to_owned())
        })?;
        Ok(Some(DurableWrite {
            disposition: WriteDisposition::Committed,
            commit: marker(self, sequence),
            value,
        }))
    }

    fn commit_new_payout_inner(
        &self,
        execution: &VerifiedPayoutExecutionV1<'_>,
        response: &IssuerPayoutResponseV1,
    ) -> StoreResult<bool> {
        let request = execution.request();
        let request_digest = request.request_digest()?;
        let idempotency_digest = payout_idempotency_digest(self, &request.idempotency_key);
        let replay_image = payout_replay_image(self, request)?;
        let exact_response = response.encode()?;
        if replay_image.len() > MAX_EXACT_PAYOUT_REQUEST_BYTES
            || exact_response.len() > MAX_EXACT_PAYOUT_RESPONSE_BYTES
        {
            return Err(StoreError::InvalidInput(
                "payout encoding exceeds store bound",
            ));
        }

        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous_identity = verify_expected_identity(&transaction, &self.handle)?;
        if read_payout(&transaction, self, &idempotency_digest)?.is_some() {
            return Ok(false);
        }
        let Some(intent) =
            read_payout_intent_by_id(&transaction, self, execution.payout_intent_id())?
        else {
            return Err(StoreError::InvalidInput(
                "signed payout intent is not persisted",
            ));
        };
        let expected_payout_id = issuer_payout_id_v1(
            &self.handle.expected_issuer_id,
            execution.payout_intent_id(),
        );
        let expected_transaction_id = issuer_payout_ledger_transaction_id_v1(
            &self.handle.expected_issuer_id,
            &request_digest,
        );
        if intent.consumed_by_payout_id.is_some() {
            return Ok(false);
        }
        if request.issuer_id != self.handle.expected_issuer_id
            || request.unit != SettlementUnitV1::AuthCredit
            || request.provider_id != intent.provider_id
            || request.account_id != intent.account_id
            || request.payout_target_id != intent.payout_target_id
            || request.payout_value != intent.payout_value
            || request.total_debit != intent.total_debit
            || response.payout_id != expected_payout_id
            || response.ledger_transaction_id != expected_transaction_id
            || response.updated_at > intent.expires_at
        {
            return Err(StoreError::InvalidInput(
                "payout execution does not match persisted intent",
            ));
        }
        let intent_response = IssuerPayoutIntentResponseV1::decode(&intent.exact_response)?;
        if request.payout_intent_digest != intent_response.payout_intent_digest()? {
            return Err(StoreError::InvalidInput("payout intent digest mismatch"));
        }
        let (account_id, target_id) = require_current_payout_configuration(
            &transaction,
            self,
            request.provider_id,
            request.authorization_digest,
        )?;
        if account_id != request.account_id || target_id != request.payout_target_id {
            return Err(StoreError::InvalidInput(
                "payout execution conflicts with current provider registration",
            ));
        }

        let mutation = mutation_digest(
            b"commit-payout-execution-v1",
            &[
                &idempotency_digest,
                &request_digest,
                &expected_payout_id,
                &expected_transaction_id,
                &exact_response,
            ],
        );
        let committed_identity = advance_store_generation(
            &transaction,
            &previous_identity,
            b"commit-payout-execution-v1",
            &mutation,
        )?;
        let sequence = committed_identity.commit_seq;
        reserve_provider_balance(
            &transaction,
            self,
            request.provider_id,
            request.account_id,
            request.total_debit,
            sequence,
        )?;
        insert_payout_reservation_transaction(
            &transaction,
            self,
            request,
            &expected_transaction_id,
            sequence,
            response.updated_at,
        )?;
        transaction.execute(
            "INSERT INTO payouts (idempotency_digest, request_digest, issuer_id, provider_id, \
             account_id, payout_target_id, payout_intent_id, payout_id, unit, payout_value, \
             total_debit, state, ledger_transaction_id, terminal_ledger_transaction_id, \
             state_version, updated_at, request_replay_image, exact_initial_response, \
             exact_latest_status_response, commit_seq) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, \
             ?8, ?9, ?10, ?11, ?12, ?13, NULL, ?14, ?15, ?16, ?17, NULL, ?18)",
            params![
                idempotency_digest.as_slice(),
                request_digest.as_slice(),
                self.handle.expected_issuer_id.as_slice(),
                request.provider_id.as_slice(),
                request.account_id.as_slice(),
                request.payout_target_id.as_slice(),
                request.payout_intent_id.as_slice(),
                expected_payout_id.as_slice(),
                request.unit as u8,
                sql_integer(request.payout_value, "payout value exceeds SQLite range")?,
                sql_integer(request.total_debit, "payout debit exceeds SQLite range")?,
                PayoutStateV1::Accepted as u8,
                expected_transaction_id.as_slice(),
                sql_integer(
                    response.state_version,
                    "payout state version exceeds SQLite range"
                )?,
                sql_integer(
                    response.updated_at,
                    "payout update time exceeds SQLite range"
                )?,
                replay_image.as_slice(),
                exact_response.as_slice(),
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
            ],
        )?;
        let consumed = transaction.execute(
            "UPDATE payout_intents SET consumed_by_payout_id = ?1, commit_seq = ?2 \
             WHERE payout_intent_id = ?3 AND consumed_by_payout_id IS NULL",
            params![
                expected_payout_id.as_slice(),
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
                request.payout_intent_id.as_slice(),
            ],
        )?;
        if consumed != 1 {
            return Ok(false);
        }
        let command_id = issuer_payout_outbox_command_id_v1(
            &self.handle.expected_issuer_id,
            &expected_payout_id,
        );
        transaction.execute(
            "INSERT INTO payout_outbox (command_id, issuer_id, payout_id, payout_target_id, \
             unit, payout_value, state, attempt_count, lease_owner_digest, lease_until, commit_seq) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, 0, NULL, NULL, ?7)",
            params![
                command_id.as_slice(), self.handle.expected_issuer_id.as_slice(),
                expected_payout_id.as_slice(), request.payout_target_id.as_slice(),
                request.unit as u8,
                sql_integer(request.payout_value, "payout value exceeds SQLite range")?,
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
            ],
        )?;
        commit(transaction)?;
        Ok(true)
    }

    fn compare_and_swap_payout_status_inner(
        &self,
        predecessor: &PayoutStatusCasExpectationV1,
        successor: &IssuerPayoutStatusResponseV1,
    ) -> StoreResult<bool> {
        let exact_status = successor.encode()?;
        if exact_status.len() > MAX_EXACT_PAYOUT_STATUS_RESPONSE_BYTES {
            return Err(StoreError::InvalidInput(
                "payout status encoding exceeds store bound",
            ));
        }
        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous_identity = verify_expected_identity(&transaction, &self.handle)?;
        let Some(current) = read_payout_by_id(&transaction, self, predecessor.payout_id())? else {
            return Ok(false);
        };
        if current.request_digest != *predecessor.payout_request_digest()
            || current.ledger_transaction_id != *predecessor.ledger_transaction_id()
            || current.state != predecessor.state()
            || current.state_version != predecessor.state_version()
            || current.updated_at != predecessor.updated_at()
        {
            return Ok(false);
        }
        if successor.issuer_id != self.handle.expected_issuer_id
            || successor.provider_id != current.provider_id
            || successor.account_id != current.account_id
            || successor.payout_id != current.payout_id
            || successor.payout_request_digest != current.request_digest
            || successor.payout_target_id != current.payout_target_id
            || successor.unit != current.unit
            || successor.payout_value != current.payout_value
            || successor.total_debit != current.total_debit
            || successor.ledger_transaction_id != current.ledger_transaction_id
        {
            return Err(StoreError::PayoutStatusConflict);
        }
        let terminal_transition = current.state == PayoutStateV1::InFlight
            && matches!(
                successor.state,
                PayoutStateV1::Succeeded | PayoutStateV1::Failed
            );
        if (current.state == PayoutStateV1::Accepted && successor.state == PayoutStateV1::InFlight)
            || terminal_transition
        {
            let outbox_state: i64 = transaction.query_row(
                "SELECT state FROM payout_outbox WHERE payout_id = ?1",
                params![current.payout_id.as_slice()],
                |row| row.get(0),
            )?;
            if outbox_state != PayoutOutboxStateV1::Leased as i64 {
                return Err(StoreError::PayoutOutboxUnavailable);
            }
        }

        let terminal_transaction_id = if terminal_transition {
            Some(payout_terminal_transaction_id(
                self,
                &current.payout_id,
                successor.state,
            ))
        } else {
            current.terminal_ledger_transaction_id
        };
        let mutation = mutation_digest(
            b"commit-payout-status-v1",
            &[
                &current.payout_id,
                &successor.state_version.to_le_bytes(),
                &[successor.state as u8],
                &exact_status,
            ],
        );
        let committed_identity = advance_store_generation(
            &transaction,
            &previous_identity,
            b"commit-payout-status-v1",
            &mutation,
        )?;
        let sequence = committed_identity.commit_seq;
        if terminal_transition {
            settle_reserved_balance(&transaction, self, &current, successor.state, sequence)?;
            insert_payout_terminal_transaction(
                &transaction,
                self,
                &current,
                successor.state,
                &terminal_transaction_id.expect("terminal transition has transaction id"),
                successor.updated_at,
                sequence,
            )?;
        }
        let changed = transaction.execute(
            "UPDATE payouts SET state = ?1, terminal_ledger_transaction_id = ?2, \
             state_version = ?3, updated_at = ?4, exact_latest_status_response = ?5, \
             commit_seq = ?6 WHERE payout_id = ?7 AND request_digest = ?8 \
             AND ledger_transaction_id = ?9 AND state = ?10 AND state_version = ?11 \
             AND updated_at = ?12",
            params![
                successor.state as u8,
                terminal_transaction_id
                    .as_ref()
                    .map(|value| value.as_slice()),
                sql_integer(
                    successor.state_version,
                    "payout state version exceeds SQLite range"
                )?,
                sql_integer(
                    successor.updated_at,
                    "payout status time exceeds SQLite range"
                )?,
                exact_status.as_slice(),
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
                current.payout_id.as_slice(),
                current.request_digest.as_slice(),
                current.ledger_transaction_id.as_slice(),
                current.state as u8,
                sql_integer(
                    current.state_version,
                    "payout state version exceeds SQLite range"
                )?,
                sql_integer(
                    current.updated_at,
                    "payout update time exceeds SQLite range"
                )?,
            ],
        )?;
        if changed != 1 {
            return Ok(false);
        }
        if terminal_transition {
            let completed = transaction.execute(
                "UPDATE payout_outbox SET state = 3, lease_owner_digest = NULL, \
                 lease_until = NULL, commit_seq = ?1 WHERE payout_id = ?2 AND state = 2",
                params![
                    sql_integer(sequence, "commit sequence exceeds SQLite range")?,
                    current.payout_id.as_slice(),
                ],
            )?;
            if completed != 1 {
                return Err(StoreError::PayoutOutboxUnavailable);
            }
        }
        commit(transaction)?;
        Ok(true)
    }
}

fn require_current_payout_configuration(
    transaction: &Connection,
    store: &IssuerStore,
    provider_id: [u8; 32],
    authorization_digest: [u8; 32],
) -> StoreResult<([u8; 32], [u8; 32])> {
    let registration: Option<(Vec<u8>, Vec<u8>)> = transaction
        .query_row(
            "SELECT settlement_account_id, payout_target_id FROM provider_registrations \
             WHERE issuer_id = ?1 AND provider_id = ?2",
            params![
                store.handle.expected_issuer_id.as_slice(),
                provider_id.as_slice(),
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((account_id, payout_target_id)) = registration else {
        return Err(StoreError::InvalidInput(
            "provider settlement registration is missing",
        ));
    };
    let highest: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT authorization_digest FROM clearing_authorizations WHERE issuer_id = ?1 \
             AND provider_id = ?2 ORDER BY authorization_epoch DESC LIMIT 1",
            params![
                store.handle.expected_issuer_id.as_slice(),
                provider_id.as_slice(),
            ],
            |row| row.get(0),
        )
        .optional()?;
    if highest.as_deref() != Some(authorization_digest.as_slice()) {
        return Err(StoreError::ClearingAuthorizationRollback);
    }
    Ok((
        fixed_blob(account_id, "invalid provider account id")?,
        fixed_blob(payout_target_id, "invalid payout target id")?,
    ))
}

fn require_exact_registered_authorization(
    transaction: &Connection,
    store: &IssuerStore,
    digest: [u8; 32],
    authorization: &ProviderClearingAuthorizationV1,
    approval: &IssuerClearingApprovalV1,
) -> StoreResult<()> {
    let exact: Option<(Vec<u8>, Vec<u8>)> = transaction
        .query_row(
            "SELECT exact_authorization, exact_approval FROM clearing_authorizations \
             WHERE issuer_id = ?1 AND authorization_digest = ?2",
            params![
                store.handle.expected_issuer_id.as_slice(),
                digest.as_slice(),
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if exact != Some((authorization.encode()?, approval.encode())) {
        return Err(StoreError::ClearingAuthorizationFork);
    }
    Ok(())
}

fn reserve_provider_balance(
    transaction: &Connection,
    store: &IssuerStore,
    provider_id: [u8; 32],
    account_id: [u8; 32],
    debit: u64,
    sequence: u64,
) -> StoreResult<()> {
    let current: (i64, i64, i64) = transaction.query_row(
        "SELECT available_value, reserved_value, ledger_sequence FROM ledger_accounts \
         WHERE issuer_id = ?1 AND provider_id = ?2 AND account_id = ?3 AND unit = ?4",
        params![
            store.handle.expected_issuer_id.as_slice(),
            provider_id.as_slice(),
            account_id.as_slice(),
            SettlementUnitV1::AuthCredit as u8,
        ],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let available = db_u64(current.0, "negative available balance")?;
    let reserved = db_u64(current.1, "negative reserved balance")?;
    if available < debit {
        return Err(StoreError::InsufficientProviderBalance);
    }
    let next_reserved = reserved
        .checked_add(debit)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or(StoreError::LedgerBalanceOverflow)?;
    let next_ledger_sequence = db_u64(current.2, "negative ledger sequence")?
        .checked_add(1)
        .ok_or(StoreError::LedgerBalanceOverflow)?;
    let changed = transaction.execute(
        "UPDATE ledger_accounts SET available_value = ?1, reserved_value = ?2, \
         ledger_sequence = ?3, commit_seq = ?4 WHERE account_id = ?5 \
         AND available_value = ?6 AND reserved_value = ?7 AND ledger_sequence = ?8",
        params![
            sql_integer(available - debit, "available balance exceeds SQLite range")?,
            sql_integer(next_reserved, "reserved balance exceeds SQLite range")?,
            sql_integer(next_ledger_sequence, "ledger sequence exceeds SQLite range")?,
            sql_integer(sequence, "commit sequence exceeds SQLite range")?,
            account_id.as_slice(),
            current.0,
            current.1,
            current.2,
        ],
    )?;
    if changed != 1 {
        return Err(StoreError::PayoutStatusConflict);
    }
    Ok(())
}

fn settle_reserved_balance(
    transaction: &Connection,
    store: &IssuerStore,
    payout: &PayoutRecordV1,
    state: PayoutStateV1,
    sequence: u64,
) -> StoreResult<()> {
    let current: (i64, i64, i64) = transaction.query_row(
        "SELECT available_value, reserved_value, ledger_sequence FROM ledger_accounts \
         WHERE issuer_id = ?1 AND provider_id = ?2 AND account_id = ?3 AND unit = ?4",
        params![
            store.handle.expected_issuer_id.as_slice(),
            payout.provider_id.as_slice(),
            payout.account_id.as_slice(),
            payout.unit as u8,
        ],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let available = db_u64(current.0, "negative available balance")?;
    let reserved = db_u64(current.1, "negative reserved balance")?;
    if reserved < payout.total_debit {
        return Err(StoreError::PayoutStatusConflict);
    }
    let next_available = if state == PayoutStateV1::Failed {
        available
            .checked_add(payout.total_debit)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or(StoreError::LedgerBalanceOverflow)?
    } else {
        available
    };
    let next_ledger_sequence = db_u64(current.2, "negative ledger sequence")?
        .checked_add(1)
        .ok_or(StoreError::LedgerBalanceOverflow)?;
    let changed = transaction.execute(
        "UPDATE ledger_accounts SET available_value = ?1, reserved_value = ?2, \
         ledger_sequence = ?3, commit_seq = ?4 WHERE account_id = ?5 \
         AND available_value = ?6 AND reserved_value = ?7 AND ledger_sequence = ?8",
        params![
            sql_integer(next_available, "available balance exceeds SQLite range")?,
            sql_integer(
                reserved - payout.total_debit,
                "reserved balance exceeds SQLite range"
            )?,
            sql_integer(next_ledger_sequence, "ledger sequence exceeds SQLite range")?,
            sql_integer(sequence, "commit sequence exceeds SQLite range")?,
            payout.account_id.as_slice(),
            current.0,
            current.1,
            current.2,
        ],
    )?;
    if changed != 1 {
        return Err(StoreError::PayoutStatusConflict);
    }
    Ok(())
}

fn insert_payout_reservation_transaction(
    transaction: &Connection,
    store: &IssuerStore,
    request: &ProviderPayoutRequestV1,
    transaction_id: &[u8; 32],
    sequence: u64,
    created_at: u64,
) -> StoreResult<()> {
    let request_digest = request.request_digest()?;
    insert_ledger_header(
        transaction,
        store,
        request.provider_id,
        LedgerTransactionKindV1::PayoutDebit,
        transaction_id,
        &request_digest,
        request.unit,
        created_at,
        sequence,
    )?;
    let value =
        i64::try_from(request.total_debit).map_err(|_| StoreError::LedgerBalanceOverflow)?;
    insert_posting(
        transaction,
        transaction_id,
        1,
        ACCOUNT_KIND_PROVIDER_AVAILABLE,
        &request.account_id,
        -value,
    )?;
    insert_posting(
        transaction,
        transaction_id,
        2,
        ACCOUNT_KIND_PROVIDER_RESERVED,
        &request.account_id,
        value,
    )
}

fn insert_payout_terminal_transaction(
    transaction: &Connection,
    store: &IssuerStore,
    payout: &PayoutRecordV1,
    state: PayoutStateV1,
    transaction_id: &[u8; 32],
    created_at: u64,
    sequence: u64,
) -> StoreResult<()> {
    let reference = payout_terminal_reference(store, &payout.payout_id, state);
    let kind = if state == PayoutStateV1::Succeeded {
        LedgerTransactionKindV1::PayoutSucceeded
    } else {
        LedgerTransactionKindV1::PayoutFailed
    };
    insert_ledger_header(
        transaction,
        store,
        payout.provider_id,
        kind,
        transaction_id,
        &reference,
        payout.unit,
        created_at,
        sequence,
    )?;
    let debit = i64::try_from(payout.total_debit).map_err(|_| StoreError::LedgerBalanceOverflow)?;
    insert_posting(
        transaction,
        transaction_id,
        1,
        ACCOUNT_KIND_PROVIDER_RESERVED,
        &payout.account_id,
        -debit,
    )?;
    if state == PayoutStateV1::Failed {
        return insert_posting(
            transaction,
            transaction_id,
            2,
            ACCOUNT_KIND_PROVIDER_AVAILABLE,
            &payout.account_id,
            debit,
        );
    }
    let clearing = system_account_id(store, SYSTEM_ACCOUNT_PAYOUT_CLEARING);
    let payout_value =
        i64::try_from(payout.payout_value).map_err(|_| StoreError::LedgerBalanceOverflow)?;
    insert_posting(
        transaction,
        transaction_id,
        2,
        ACCOUNT_KIND_PAYOUT_CLEARING,
        &clearing,
        payout_value,
    )?;
    let fee = payout.total_debit - payout.payout_value;
    if fee != 0 {
        let fee_account = system_account_id(store, SYSTEM_ACCOUNT_ISSUER_FEE);
        insert_posting(
            transaction,
            transaction_id,
            3,
            ACCOUNT_KIND_ISSUER_FEE,
            &fee_account,
            i64::try_from(fee).map_err(|_| StoreError::LedgerBalanceOverflow)?,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_ledger_header(
    transaction: &Connection,
    store: &IssuerStore,
    provider_id: [u8; 32],
    kind: LedgerTransactionKindV1,
    transaction_id: &[u8; 32],
    reference_digest: &[u8; 32],
    unit: SettlementUnitV1,
    created_at: u64,
    sequence: u64,
) -> StoreResult<()> {
    transaction.execute(
        "INSERT INTO ledger_transactions (transaction_id, issuer_id, provider_id, kind, \
         reference_digest, unit, created_at, commit_seq) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            transaction_id.as_slice(),
            store.handle.expected_issuer_id.as_slice(),
            provider_id.as_slice(),
            kind as i64,
            reference_digest.as_slice(),
            unit as u8,
            sql_integer(created_at, "ledger transaction time exceeds SQLite range")?,
            sql_integer(sequence, "commit sequence exceeds SQLite range")?,
        ],
    )?;
    Ok(())
}

fn insert_posting(
    transaction: &Connection,
    transaction_id: &[u8; 32],
    line_no: i64,
    account_kind: i64,
    account_id: &[u8; 32],
    amount: i64,
) -> StoreResult<()> {
    transaction.execute(
        "INSERT INTO ledger_postings (transaction_id, line_no, account_kind, account_id, \
         signed_amount) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            transaction_id.as_slice(),
            line_no,
            account_kind,
            account_id.as_slice(),
            amount
        ],
    )?;
    Ok(())
}

fn read_payout_intent_by_id(
    connection: &Connection,
    store: &IssuerStore,
    payout_intent_id: &[u8; 32],
) -> StoreResult<Option<PayoutIntentRecordV1>> {
    let digest: Option<Vec<u8>> = connection
        .query_row(
            "SELECT idempotency_digest FROM payout_intents WHERE issuer_id = ?1 \
             AND payout_intent_id = ?2",
            params![
                store.handle.expected_issuer_id.as_slice(),
                payout_intent_id.as_slice()
            ],
            |row| row.get(0),
        )
        .optional()?;
    digest
        .map(|value| fixed_blob(value, "invalid payout intent idempotency digest"))
        .transpose()?
        .map(|digest| read_payout_intent(connection, store, &digest))
        .transpose()
        .map(Option::flatten)
}

fn read_payout_intent(
    connection: &Connection,
    store: &IssuerStore,
    idempotency_digest: &[u8; 32],
) -> StoreResult<Option<PayoutIntentRecordV1>> {
    type Raw = (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
        i64,
        i64,
        i64,
        Vec<u8>,
        i64,
        Option<Vec<u8>>,
        Vec<u8>,
        Vec<u8>,
        i64,
    );
    let raw: Option<Raw> = connection
        .query_row(
            "SELECT request_digest, provider_id, account_id, payout_target_id, unit, \
             payout_value, issuer_fee, total_debit, payout_intent_id, expires_at, \
             consumed_by_payout_id, request_replay_image, exact_response, commit_seq \
             FROM payout_intents WHERE issuer_id = ?1 AND idempotency_digest = ?2",
            params![
                store.handle.expected_issuer_id.as_slice(),
                idempotency_digest.as_slice()
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
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                ))
            },
        )
        .optional()?;
    raw.map(|raw| {
        let request_digest = fixed_blob(raw.0, "invalid payout intent request digest")?;
        let provider_id = fixed_blob(raw.1, "invalid payout intent provider id")?;
        let account_id = fixed_blob(raw.2, "invalid payout intent account id")?;
        let payout_target_id = fixed_blob(raw.3, "invalid payout intent target id")?;
        let unit = settlement_unit_from_db(raw.4)?;
        let payout_value = db_u64(raw.5, "negative payout intent value")?;
        let issuer_fee = db_u64(raw.6, "negative payout intent fee")?;
        let total_debit = db_u64(raw.7, "negative payout intent debit")?;
        let payout_intent_id = fixed_blob(raw.8, "invalid payout intent id")?;
        let exact_response: Vec<u8> = raw.12;
        let response = IssuerPayoutIntentResponseV1::decode(&exact_response)?;
        if response.encode()? != exact_response
            || response.request_digest != request_digest
            || response.issuer_id != store.handle.expected_issuer_id
            || response.provider_id != provider_id
            || response.account_id != account_id
            || response.payout_target_id != payout_target_id
            || response.unit != unit
            || response.payout_value != payout_value
            || response.issuer_fee != issuer_fee
            || response.total_debit != total_debit
            || response.payout_intent_id != payout_intent_id
            || response.expires_at != db_u64(raw.9, "negative payout intent expiry")?
        {
            return Err(StoreError::SchemaMismatch(
                "payout intent response is not row-bound".to_owned(),
            ));
        }
        Ok(PayoutIntentRecordV1 {
            idempotency_digest: *idempotency_digest,
            request_digest,
            provider_id,
            account_id,
            payout_target_id,
            unit,
            payout_value,
            issuer_fee,
            total_debit,
            payout_intent_id,
            expires_at: response.expires_at,
            consumed_by_payout_id: raw
                .10
                .map(|value| fixed_blob(value, "invalid consumed payout id"))
                .transpose()?,
            exact_request_replay_image: raw.11,
            exact_response,
            commit: marker(store, db_u64(raw.13, "negative payout intent commit")?),
        })
    })
    .transpose()
}

fn read_payout_by_id(
    connection: &Connection,
    store: &IssuerStore,
    payout_id: &[u8; 32],
) -> StoreResult<Option<PayoutRecordV1>> {
    let digest: Option<Vec<u8>> = connection
        .query_row(
            "SELECT idempotency_digest FROM payouts WHERE issuer_id = ?1 AND payout_id = ?2",
            params![
                store.handle.expected_issuer_id.as_slice(),
                payout_id.as_slice()
            ],
            |row| row.get(0),
        )
        .optional()?;
    digest
        .map(|value| fixed_blob(value, "invalid payout idempotency digest"))
        .transpose()?
        .map(|digest| read_payout(connection, store, &digest))
        .transpose()
        .map(Option::flatten)
}

fn read_payout(
    connection: &Connection,
    store: &IssuerStore,
    idempotency_digest: &[u8; 32],
) -> StoreResult<Option<PayoutRecordV1>> {
    type Raw = (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
        i64,
        i64,
        i64,
        Vec<u8>,
        Option<Vec<u8>>,
        i64,
        i64,
        Vec<u8>,
        Vec<u8>,
        Option<Vec<u8>>,
        i64,
    );
    let raw: Option<Raw> = connection
        .query_row(
            "SELECT request_digest, provider_id, account_id, payout_target_id, payout_intent_id, \
             payout_id, unit, payout_value, total_debit, state, ledger_transaction_id, \
             terminal_ledger_transaction_id, state_version, updated_at, request_replay_image, \
             exact_initial_response, exact_latest_status_response, commit_seq FROM payouts \
             WHERE issuer_id = ?1 AND idempotency_digest = ?2",
            params![
                store.handle.expected_issuer_id.as_slice(),
                idempotency_digest.as_slice()
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
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                    row.get(15)?,
                    row.get(16)?,
                    row.get(17)?,
                ))
            },
        )
        .optional()?;
    raw.map(|raw| {
        let request_digest = fixed_blob(raw.0, "invalid payout request digest")?;
        let provider_id = fixed_blob(raw.1, "invalid payout provider id")?;
        let account_id = fixed_blob(raw.2, "invalid payout account id")?;
        let payout_target_id = fixed_blob(raw.3, "invalid payout target id")?;
        let payout_intent_id = fixed_blob(raw.4, "invalid payout intent id")?;
        let payout_id = fixed_blob(raw.5, "invalid payout id")?;
        let unit = settlement_unit_from_db(raw.6)?;
        let payout_value = db_u64(raw.7, "negative payout value")?;
        let total_debit = db_u64(raw.8, "negative payout debit")?;
        let state = payout_state_from_db(raw.9)?;
        let ledger_transaction_id = fixed_blob(raw.10, "invalid payout ledger transaction id")?;
        let terminal_ledger_transaction_id = raw
            .11
            .map(|value| fixed_blob(value, "invalid payout terminal transaction id"))
            .transpose()?;
        let state_version = db_u64(raw.12, "negative payout state version")?;
        let updated_at = db_u64(raw.13, "negative payout update time")?;
        let exact_initial_response: Vec<u8> = raw.15;
        let initial = IssuerPayoutResponseV1::decode(&exact_initial_response)?;
        if initial.encode()? != exact_initial_response
            || initial.request_digest != request_digest
            || initial.issuer_id != store.handle.expected_issuer_id
            || initial.provider_id != provider_id
            || initial.account_id != account_id
            || initial.payout_target_id != payout_target_id
            || initial.payout_intent_id != payout_intent_id
            || initial.payout_id != payout_id
            || initial.unit != unit
            || initial.payout_value != payout_value
            || initial.total_debit != total_debit
            || initial.ledger_transaction_id != ledger_transaction_id
        {
            return Err(StoreError::SchemaMismatch(
                "initial payout response is not row-bound".to_owned(),
            ));
        }
        if let Some(exact) = &raw.16 {
            let status = IssuerPayoutStatusResponseV1::decode(exact)?;
            if status.encode()? != *exact
                || status.issuer_id != store.handle.expected_issuer_id
                || status.provider_id != provider_id
                || status.account_id != account_id
                || status.payout_id != payout_id
                || status.payout_request_digest != request_digest
                || status.payout_target_id != payout_target_id
                || status.unit != unit
                || status.payout_value != payout_value
                || status.total_debit != total_debit
                || status.state != state
                || status.ledger_transaction_id != ledger_transaction_id
                || status.state_version != state_version
                || status.updated_at != updated_at
            {
                return Err(StoreError::SchemaMismatch(
                    "latest payout status is not row-bound".to_owned(),
                ));
            }
        } else if state != PayoutStateV1::Accepted || state_version != 1 {
            return Err(StoreError::SchemaMismatch(
                "payout status snapshot is missing".to_owned(),
            ));
        }
        Ok(PayoutRecordV1 {
            idempotency_digest: *idempotency_digest,
            request_digest,
            provider_id,
            account_id,
            payout_target_id,
            payout_intent_id,
            payout_id,
            unit,
            payout_value,
            total_debit,
            state,
            ledger_transaction_id,
            terminal_ledger_transaction_id,
            state_version,
            updated_at,
            exact_request_replay_image: raw.14,
            exact_initial_response,
            exact_latest_status_response: raw.16,
            commit: marker(store, db_u64(raw.17, "negative payout commit")?),
        })
    })
    .transpose()
}

fn read_outbox_command(
    connection: &Connection,
    store: &IssuerStore,
    command_id: &[u8; 32],
) -> StoreResult<Option<PayoutOutboxCommandV1>> {
    type Raw = (
        Vec<u8>,
        Vec<u8>,
        i64,
        i64,
        i64,
        i64,
        Option<Vec<u8>>,
        Option<i64>,
        i64,
    );
    let raw: Option<Raw> = connection
        .query_row(
            "SELECT payout_id, payout_target_id, unit, payout_value, state, attempt_count, \
         lease_owner_digest, lease_until, commit_seq FROM payout_outbox \
         WHERE issuer_id = ?1 AND command_id = ?2",
            params![
                store.handle.expected_issuer_id.as_slice(),
                command_id.as_slice()
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
                ))
            },
        )
        .optional()?;
    raw.map(|raw| {
        Ok(PayoutOutboxCommandV1 {
            command_id: *command_id,
            payout_id: fixed_blob(raw.0, "invalid outbox payout id")?,
            payout_target_id: fixed_blob(raw.1, "invalid outbox target id")?,
            unit: settlement_unit_from_db(raw.2)?,
            payout_value: db_u64(raw.3, "negative outbox payout value")?,
            state: outbox_state_from_db(raw.4)?,
            attempt_count: u32::try_from(raw.5).map_err(|_| {
                StoreError::SchemaMismatch("invalid outbox attempt count".to_owned())
            })?,
            lease_owner_digest: raw
                .6
                .map(|value| fixed_blob(value, "invalid lease owner digest"))
                .transpose()?,
            lease_until: raw
                .7
                .map(|value| db_u64(value, "negative outbox lease expiry"))
                .transpose()?,
            commit: marker(store, db_u64(raw.8, "negative outbox commit")?),
        })
    })
    .transpose()
}

fn payout_intent_idempotency_digest(store: &IssuerStore, key: &[u8; 32]) -> [u8; 32] {
    hash_parts(
        PAYOUT_INTENT_IDEMPOTENCY_DOMAIN_V1,
        &[&store.handle.expected_issuer_id, key],
    )
}

fn payout_idempotency_digest(store: &IssuerStore, key: &[u8; 32]) -> [u8; 32] {
    hash_parts(
        PAYOUT_IDEMPOTENCY_DOMAIN_V1,
        &[&store.handle.expected_issuer_id, key],
    )
}

fn payout_intent_replay_image(
    store: &IssuerStore,
    request: &ProviderPayoutIntentRequestV1,
) -> StoreResult<Vec<u8>> {
    let mut sanitized = request.clone();
    sanitized.idempotency_key = payout_intent_idempotency_digest(store, &request.idempotency_key);
    Ok(sanitized.encode()?)
}

fn payout_replay_image(
    store: &IssuerStore,
    request: &ProviderPayoutRequestV1,
) -> StoreResult<Vec<u8>> {
    let mut sanitized = request.clone();
    sanitized.idempotency_key = payout_idempotency_digest(store, &request.idempotency_key);
    Ok(sanitized.encode()?)
}

fn payout_terminal_transaction_id(
    store: &IssuerStore,
    payout_id: &[u8; 32],
    state: PayoutStateV1,
) -> [u8; 32] {
    hash_parts(
        PAYOUT_TERMINAL_LEDGER_TRANSACTION_ID_DOMAIN_V1,
        &[&store.handle.expected_issuer_id, payout_id, &[state as u8]],
    )
}

fn payout_terminal_reference(
    store: &IssuerStore,
    payout_id: &[u8; 32],
    state: PayoutStateV1,
) -> [u8; 32] {
    hash_parts(
        PAYOUT_TERMINAL_REFERENCE_DOMAIN_V1,
        &[&store.handle.expected_issuer_id, payout_id, &[state as u8]],
    )
}

fn system_account_id(store: &IssuerStore, kind: u8) -> [u8; 32] {
    hash_parts(
        SYSTEM_LEDGER_ACCOUNT_ID_DOMAIN_V1,
        &[&store.handle.expected_issuer_id, &[kind]],
    )
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn settlement_unit_from_db(value: i64) -> StoreResult<SettlementUnitV1> {
    match value {
        1 => Ok(SettlementUnitV1::MilliSatoshi),
        2 => Ok(SettlementUnitV1::Satoshi),
        3 => Ok(SettlementUnitV1::AuthCredit),
        _ => Err(StoreError::SchemaMismatch(
            "invalid settlement unit".to_owned(),
        )),
    }
}

fn payout_state_from_db(value: i64) -> StoreResult<PayoutStateV1> {
    match value {
        1 => Ok(PayoutStateV1::Accepted),
        2 => Ok(PayoutStateV1::InFlight),
        3 => Ok(PayoutStateV1::Succeeded),
        4 => Ok(PayoutStateV1::Failed),
        _ => Err(StoreError::SchemaMismatch(
            "invalid payout state".to_owned(),
        )),
    }
}

fn outbox_state_from_db(value: i64) -> StoreResult<PayoutOutboxStateV1> {
    match value {
        1 => Ok(PayoutOutboxStateV1::Pending),
        2 => Ok(PayoutOutboxStateV1::Leased),
        3 => Ok(PayoutOutboxStateV1::Complete),
        _ => Err(StoreError::SchemaMismatch(
            "invalid payout outbox state".to_owned(),
        )),
    }
}

fn marker(store: &IssuerStore, commit_seq: u64) -> CommitMarker {
    CommitMarker {
        store_instance_id: store.handle.expected_store_instance_id,
        commit_seq,
    }
}
