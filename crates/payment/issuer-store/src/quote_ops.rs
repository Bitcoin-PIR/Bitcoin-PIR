use crate::bat_v2_ops::read_bat_acceptance_class_v2;
use crate::db::{
    advance_store_generation, commit, db_u64, fixed_blob, is_zero, network_code,
    optional_fixed_blob, sql_integer, verify_expected_identity,
};
use crate::rollback::mutation_digest;
use crate::{
    AuthenticatedQuoteStatus, BatV2ClaimCryptographicVerificationInputV2,
    BatV2ClaimCryptographicVerifierV2, BatV2ClaimWrite, BatV2CredentialMaterialRequirementV2,
    BatV2QuoteReservation, ClaimCryptographicVerificationInput, ClaimCryptographicVerifier,
    ClaimRecord, ClaimWrite, CommitMarker, DelegationAdvance, DelegationHead, DurableWrite,
    IssuerStore, QuoteCapacityV1, QuoteExpiry, QuoteFinalization, QuoteReconciliationCandidateV1,
    QuoteRecord, QuoteReservation, QuoteSettlement, QuoteState, QuoteStatusBip340Input,
    QuoteStatusBip340Verifier, ReceiptSerial, StoreError, StoreResult, WriteDisposition,
    MAX_EXACT_CLAIM_REQUEST_BYTES, MAX_EXACT_CLAIM_RESPONSE_BYTES, MAX_EXACT_DELEGATION_BYTES,
    MAX_EXACT_INTENT_BYTES, MAX_INVOICE_BYTES, MAX_RECEIPT_SERIALS_PER_CLAIM,
    MAX_SIGNED_QUOTE_BYTES,
};
use ed25519_dalek::Signature;
use pir_service_protocol::{
    ArcIssuanceCanonicalizerV1, BatAcceptanceClassV2, BatV2IssuanceResponseV2,
    Bolt11BatV2ClaimEnvelopeV2, Bolt11BatV2QuoteIntentV2, Bolt11QuoteClaimV1, Bolt11QuoteIntentV1,
    Bolt11QuoteKeyDelegationV1, Bolt11QuoteKeyRollbackGuardV1, Bolt11QuoteStatusRequestV1,
    Bolt11QuoteStatusV1, Bolt11QuoteV1, CredentialIssuanceRequestItemsV1,
    CredentialIssuanceRequestV1, CredentialIssuanceResponseItemsV1, CredentialIssuanceResponseV1,
    PersistedBolt11BatV2QuoteExpectationV2, BOLT11_QUOTE_SIGNATURE_DOMAIN,
    MAX_BOLT11_QUOTE_STATUS_REQUEST_AGE_SECONDS_V1,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const QUOTE_CREATE_IDEMPOTENCY_DIGEST_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-store/POST-/v1/quotes/idempotency-digest/v1";
const QUOTE_CLAIM_IDEMPOTENCY_DIGEST_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-store/POST-/v1/quotes/claim/idempotency-digest/v1";
const QUOTE_STATUS_NONCE_DIGEST_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-store/POST-/v1/quotes/status/nonce-digest/v1";
const QUOTE_PROTOCOL_V1: i64 = 1;
const QUOTE_PROTOCOL_BAT_V2: i64 = 2;
/// Bounds authenticated status-write amplification for any one purchased
/// quote during the five-minute replay window. The HTTP edge applies a
/// separate process-wide request budget.
const MAX_ACTIVE_STATUS_NONCES_PER_QUOTE_V1: u64 = 64;
pub const MAX_QUOTE_RECONCILIATION_BATCH_V1: u32 = 1_024;

const QUOTE_SELECT: &str = "quote_id, creation_idempotency_digest, backend_label, \
    intent_digest, intent_replay_image, payee_pubkey, delegation_epoch, delegation_digest, \
    exact_delegation, exact_amount_msat, invoice_created_not_before, invoice_created_not_after, \
    reservation_recovery_deadline, state, state_version, invoice, payment_hash, invoice_created_at, \
    invoice_expires_at, claim_deadline, credential_not_after, initial_signed_quote_response, \
    expiry_observed_at, expired_signed_quote_response, settled_at, settlement_observed_at, settled_amount_msat, \
    settlement_evidence_digest, settled_signed_quote_response, \
    reservation_commit_seq, finalization_commit_seq, expiry_commit_seq, settlement_commit_seq, \
    quote_protocol";

impl IssuerStore {
    /// Atomically advances the `(issuer, network, payee)` delegation guard.
    pub fn advance_delegation(
        &self,
        input: &DelegationAdvance,
    ) -> StoreResult<DurableWrite<DelegationHead>> {
        validate_delegation_input(self, input, false)?;
        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous_identity = verify_expected_identity(&transaction, &self.handle)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;

        if let Some(existing) = read_delegation_head(&transaction, self, &input.payee_pubkey)? {
            match compare_delegation(&existing, input)? {
                HeadDecision::Exact => {
                    return Ok(DurableWrite {
                        disposition: WriteDisposition::ExactReplay,
                        commit: existing.commit,
                        value: existing,
                    });
                }
                HeadDecision::Advance => {}
            }
        }
        validate_delegation_input(self, input, true)?;
        let epoch = input.delegation_epoch.to_le_bytes();
        let digest = mutation_digest(
            b"advance-delegation-v1",
            &[
                &input.payee_pubkey,
                &epoch,
                &input.delegation_digest,
                &input.exact_delegation,
            ],
        );
        let committed_identity = advance_store_generation(
            &transaction,
            &previous_identity,
            b"advance-delegation-v1",
            &digest,
        )?;
        let sequence = committed_identity.commit_seq;
        write_delegation_head(&transaction, self, input, sequence)?;
        commit(transaction)?;
        self.anchor_committed_identity(&previous_floor, &committed_identity)?;
        let head = self.delegation_head(&input.payee_pubkey)?.ok_or_else(|| {
            StoreError::SchemaMismatch("committed delegation head missing".to_owned())
        })?;
        Ok(DurableWrite {
            disposition: WriteDisposition::Committed,
            commit: marker(self, sequence),
            value: head,
        })
    }

    pub fn delegation_head(&self, payee_pubkey: &[u8; 33]) -> StoreResult<Option<DelegationHead>> {
        if is_zero(payee_pubkey) {
            return Err(StoreError::InvalidInput("payee public key is all zero"));
        }
        let connection = self.open_checked(false)?;
        let value = read_delegation_head(&connection, self, payee_pubkey)?;
        self.confirm_anchored_read(&connection, value)
    }

    /// Reserves quote/idempotency/backend-label state before calling the
    /// Lightning backend. The delegation guard advances in the same commit.
    pub fn reserve_quote(
        &self,
        reservation: &QuoteReservation,
    ) -> StoreResult<DurableWrite<QuoteRecord>> {
        self.reserve_quote_with_capacity(reservation, QuoteCapacityV1::unbounded())
    }

    /// Reserve a quote under atomically checked persistent capacity. Exact
    /// replay bypasses capacity so a browser can always recover a previously
    /// created invoice after a lost response.
    pub fn reserve_quote_with_capacity(
        &self,
        reservation: &QuoteReservation,
        capacity: QuoteCapacityV1,
    ) -> StoreResult<DurableWrite<QuoteRecord>> {
        if capacity.max_outstanding_unpaid == 0
            || capacity.max_active_records == 0
            || capacity.max_outstanding_unpaid > capacity.max_active_records
        {
            return Err(StoreError::InvalidInput("invalid quote capacity"));
        }
        validate_quote_reservation(self, reservation, false)?;
        let reservation_recovery_deadline = quote_reservation_recovery_deadline(self, reservation)?;
        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous_identity = verify_expected_identity(&transaction, &self.handle)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;

        let creation_digest =
            creation_idempotency_digest(self, &reservation.creation_idempotency_key);
        if let Some(existing) = read_quote_by_creation_digest(&transaction, self, &creation_digest)?
        {
            if quote_reservation_matches(self, &existing, reservation)? {
                return Ok(DurableWrite {
                    disposition: WriteDisposition::ExactReplay,
                    commit: existing.reservation_commit,
                    value: existing,
                });
            }
            return Err(StoreError::CreationIdempotencyConflict);
        }
        if read_quote(&transaction, self, &reservation.quote_id)?.is_some() {
            return Err(StoreError::QuoteConflict);
        }

        // Retain terminal rows permanently for recovery/audit without turning
        // the configured capacity into a process-lifetime quota. State 0 is
        // active through its bounded creation window. Open and
        // expired-pending-reconciliation quotes remain active through the
        // immutable claim/recovery horizon. Paid/claimed/late-paid rows release
        // admission capacity while all economic records remain durable.
        let active_records = db_u64(
            transaction.query_row(
                "SELECT COUNT(*) FROM quotes
                 WHERE (state = 0 AND reservation_recovery_deadline >= ?1)
                    OR (state IN (1, 4) AND claim_deadline >= ?1)",
                [sql_integer(
                    reservation.now_unix,
                    "quote capacity observation time",
                )?],
                |row| row.get(0),
            )?,
            "active quote record count is invalid",
        )?;
        let outstanding_unpaid = db_u64(
            transaction.query_row(
                "SELECT COUNT(*) FROM quotes
                 WHERE (state = 0 AND reservation_recovery_deadline >= ?1)
                    OR (state = 1 AND claim_deadline >= ?1)",
                [sql_integer(
                    reservation.now_unix,
                    "quote capacity observation time",
                )?],
                |row| row.get(0),
            )?,
            "outstanding quote count is invalid",
        )?;
        if active_records >= capacity.max_active_records
            || outstanding_unpaid >= capacity.max_outstanding_unpaid
        {
            return Err(StoreError::QuoteCapacityExceeded);
        }

        validate_quote_reservation(self, reservation, true)?;
        let delegation = DelegationAdvance {
            payee_pubkey: reservation.payee_pubkey,
            delegation_epoch: reservation.delegation_epoch,
            delegation_digest: reservation.delegation_digest,
            exact_delegation: reservation.exact_delegation.clone(),
            now_unix: reservation.now_unix,
        };
        let head_decision = read_delegation_head(&transaction, self, &reservation.payee_pubkey)?
            .map(|head| compare_delegation(&head, &delegation))
            .transpose()?
            .unwrap_or(HeadDecision::Advance);

        let replay_image = intent_replay_image(self, reservation)?;
        let digest = mutation_digest(
            b"reserve-quote-v1",
            &[
                &reservation.quote_id,
                &creation_digest,
                &reservation.intent_digest,
                &replay_image,
                &reservation.delegation_digest,
                &reservation.invoice_created_not_before.to_le_bytes(),
                &reservation.invoice_created_not_after.to_le_bytes(),
                &reservation_recovery_deadline.to_le_bytes(),
            ],
        );
        let committed_identity = advance_store_generation(
            &transaction,
            &previous_identity,
            b"reserve-quote-v1",
            &digest,
        )?;
        let sequence = committed_identity.commit_seq;
        if head_decision == HeadDecision::Advance {
            write_delegation_head(&transaction, self, &delegation, sequence)?;
        }
        let backend_label = self.backend_label_for_quote(&reservation.quote_id)?;
        transaction.execute(
            "INSERT INTO quotes (quote_id, issuer_id, network, quote_protocol, creation_idempotency_digest, \
             backend_label, intent_digest, intent_replay_image, payee_pubkey, delegation_epoch, \
             delegation_digest, exact_delegation, exact_amount_msat, invoice_created_not_before, \
             invoice_created_not_after, reservation_recovery_deadline, state, state_version, \
             reservation_commit_seq) \
             VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, 0, 0, ?16)",
            params![
                reservation.quote_id.as_slice(),
                self.handle.expected_issuer_id.as_slice(),
                network_code(self.handle.expected_network),
                creation_digest.as_slice(),
                backend_label,
                reservation.intent_digest.as_slice(),
                replay_image.as_slice(),
                reservation.payee_pubkey.as_slice(),
                sql_integer(
                    reservation.delegation_epoch,
                    "delegation epoch exceeds SQLite range"
                )?,
                reservation.delegation_digest.as_slice(),
                reservation.exact_delegation.as_slice(),
                sql_integer(reservation.exact_amount_msat, "amount exceeds SQLite range")?,
                sql_integer(
                    reservation.invoice_created_not_before,
                    "invoice creation lower bound exceeds SQLite range",
                )?,
                sql_integer(
                    reservation.invoice_created_not_after,
                    "invoice creation upper bound exceeds SQLite range",
                )?,
                sql_integer(
                    reservation_recovery_deadline,
                    "reservation recovery deadline exceeds SQLite range",
                )?,
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
            ],
        )?;
        commit(transaction)?;
        self.anchor_committed_identity(&previous_floor, &committed_identity)?;
        let record = self
            .quote(&reservation.quote_id)?
            .ok_or_else(|| StoreError::SchemaMismatch("committed quote missing".to_owned()))?;
        Ok(DurableWrite {
            disposition: WriteDisposition::Committed,
            commit: marker(self, sequence),
            value: record,
        })
    }

    /// Reserve one issuer-wide BAT V2 quote against the exact current class
    /// head. Exact replay is resolved before the current-head check, so an
    /// already durable quote remains recoverable after class rotation.
    pub fn reserve_bat_v2_quote(
        &self,
        reservation: &BatV2QuoteReservation,
    ) -> StoreResult<DurableWrite<QuoteRecord>> {
        self.reserve_bat_v2_quote_with_capacity(reservation, QuoteCapacityV1::unbounded())
    }

    pub fn reserve_bat_v2_quote_with_capacity(
        &self,
        reservation: &BatV2QuoteReservation,
        capacity: QuoteCapacityV1,
    ) -> StoreResult<DurableWrite<QuoteRecord>> {
        validate_quote_capacity(capacity)?;
        let (intent, delegation) = parse_bat_v2_reservation(self, reservation)?;
        let reservation_recovery_deadline =
            bat_v2_reservation_recovery_deadline(reservation.invoice_created_not_after, &intent)?;
        let creation_digest = creation_idempotency_digest(self, &intent.idempotency_key);
        let intent_digest = intent.request_digest().map_err(StoreError::Protocol)?;
        let replay_image = bat_v2_intent_replay_image(self, &intent)?;

        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous_identity = verify_expected_identity(&transaction, &self.handle)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;

        if let Some(existing) = read_quote_by_creation_digest_for_protocol(
            &transaction,
            self,
            &creation_digest,
            QUOTE_PROTOCOL_BAT_V2,
        )? {
            if bat_v2_quote_reservation_matches(
                self,
                &existing,
                reservation,
                &intent,
                &delegation,
                &replay_image,
                reservation_recovery_deadline,
            )? {
                return Ok(DurableWrite {
                    disposition: WriteDisposition::ExactReplay,
                    commit: existing.reservation_commit,
                    value: existing,
                });
            }
            return Err(StoreError::CreationIdempotencyConflict);
        }
        if read_quote_for_protocol(
            &transaction,
            self,
            &reservation.quote_id,
            QUOTE_PROTOCOL_BAT_V2,
        )?
        .is_some()
        {
            return Err(StoreError::QuoteConflict);
        }

        check_quote_capacity(&transaction, capacity, reservation.now_unix)?;

        let current_head: Option<(i64, Vec<u8>)> = transaction
            .query_row(
                "SELECT highest_key_epoch, artifact_digest FROM bat_v2_class_heads \
                 WHERE issuer_id = ?1 AND class_id = ?2",
                params![
                    self.handle.expected_issuer_id.as_slice(),
                    intent.class_id.as_slice(),
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (head_epoch, head_digest) = current_head.ok_or(StoreError::BatV2ClassMemberMismatch)?;
        let head_epoch = db_u64(head_epoch, "negative BAT V2 class head epoch")?;
        let head_digest: [u8; 32] = fixed_blob(head_digest, "invalid BAT V2 class head digest")?;
        if head_epoch != intent.class_key_epoch || head_digest != intent.class_digest {
            return Err(StoreError::BatV2ClassMemberMismatch);
        }
        let class_record = read_bat_acceptance_class_v2(
            &transaction,
            self,
            &intent.class_id,
            intent.class_key_epoch,
        )?
        .ok_or(StoreError::BatV2ClassMemberMismatch)?;
        let class = BatAcceptanceClassV2::decode(&class_record.exact_artifact)
            .map_err(StoreError::Protocol)?;

        let delegation_head =
            read_delegation_head(&transaction, self, &delegation.expected_payee_pubkey)?;
        let rollback_guard = match delegation_head.as_ref() {
            Some(head) => Bolt11QuoteKeyRollbackGuardV1::from_persisted(
                self.handle.expected_issuer_id,
                self.handle.expected_network,
                head.payee_pubkey,
                head.highest_epoch,
                head.delegation_digest,
            ),
            None => Bolt11QuoteKeyRollbackGuardV1::initial(
                self.handle.expected_issuer_id,
                self.handle.expected_network,
                delegation.expected_payee_pubkey,
            ),
        }
        .map_err(StoreError::Protocol)?;
        let verified = intent
            .verify_for_class_guarded(&class, &delegation, &rollback_guard, reservation.now_unix)
            .map_err(StoreError::Protocol)?;
        let upper_horizons = intent
            .derived_horizons(reservation.invoice_created_not_after)
            .map_err(StoreError::Protocol)?;
        if verified.advanced_guard().highest_epoch() != delegation.key_epoch
            || reservation.invoice_created_not_before < class.key_not_before
            || upper_horizons.credential_not_after > class.key_not_after
            || reservation.invoice_created_not_before < delegation.not_before
            || reservation_recovery_deadline > delegation.not_after
        {
            return Err(StoreError::InvalidInput(
                "BAT V2 class or delegation does not cover the reservation window",
            ));
        }

        let delegation_advance = DelegationAdvance {
            payee_pubkey: delegation.expected_payee_pubkey,
            delegation_epoch: delegation.key_epoch,
            delegation_digest: delegation
                .delegation_digest()
                .map_err(StoreError::Protocol)?,
            exact_delegation: reservation.exact_delegation.clone(),
            now_unix: reservation.now_unix,
        };
        let head_decision = delegation_head
            .map(|head| compare_delegation(&head, &delegation_advance))
            .transpose()?
            .unwrap_or(HeadDecision::Advance);

        let mutation = mutation_digest(
            b"reserve-bat-v2-quote-v2",
            &[
                &reservation.quote_id,
                &creation_digest,
                &intent_digest,
                &replay_image,
                &intent.class_digest,
                &delegation_advance.delegation_digest,
                &reservation.invoice_created_not_before.to_le_bytes(),
                &reservation.invoice_created_not_after.to_le_bytes(),
                &reservation_recovery_deadline.to_le_bytes(),
            ],
        );
        let committed_identity = advance_store_generation(
            &transaction,
            &previous_identity,
            b"reserve-bat-v2-quote-v2",
            &mutation,
        )?;
        let sequence = committed_identity.commit_seq;
        if head_decision == HeadDecision::Advance {
            write_delegation_head(&transaction, self, &delegation_advance, sequence)?;
        }
        let backend_label = self.backend_label_for_quote(&reservation.quote_id)?;
        transaction.execute(
            "INSERT INTO quotes (quote_id, issuer_id, network, quote_protocol, \
             creation_idempotency_digest, backend_label, intent_digest, intent_replay_image, \
             payee_pubkey, delegation_epoch, delegation_digest, exact_delegation, \
             exact_amount_msat, invoice_created_not_before, invoice_created_not_after, \
             reservation_recovery_deadline, state, state_version, reservation_commit_seq) \
             VALUES (?1, ?2, ?3, 2, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, 0, 0, ?16)",
            params![
                reservation.quote_id.as_slice(),
                self.handle.expected_issuer_id.as_slice(),
                network_code(self.handle.expected_network),
                creation_digest.as_slice(),
                backend_label,
                intent_digest.as_slice(),
                replay_image.as_slice(),
                delegation.expected_payee_pubkey.as_slice(),
                sql_integer(delegation.key_epoch, "delegation epoch exceeds SQLite range")?,
                delegation_advance.delegation_digest.as_slice(),
                reservation.exact_delegation.as_slice(),
                sql_integer(intent.exact_amount_msat, "amount exceeds SQLite range")?,
                sql_integer(
                    reservation.invoice_created_not_before,
                    "invoice creation lower bound exceeds SQLite range",
                )?,
                sql_integer(
                    reservation.invoice_created_not_after,
                    "invoice creation upper bound exceeds SQLite range",
                )?,
                sql_integer(
                    reservation_recovery_deadline,
                    "reservation recovery deadline exceeds SQLite range",
                )?,
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
            ],
        )?;
        commit(transaction)?;
        self.anchor_committed_identity(&previous_floor, &committed_identity)?;
        let record = self.bat_v2_quote(&reservation.quote_id)?.ok_or_else(|| {
            StoreError::SchemaMismatch("committed BAT V2 quote missing".to_owned())
        })?;
        Ok(DurableWrite {
            disposition: WriteDisposition::Committed,
            commit: marker(self, sequence),
            value: record,
        })
    }

    pub fn finalize_quote(
        &self,
        finalization: &QuoteFinalization,
    ) -> StoreResult<DurableWrite<QuoteRecord>> {
        self.finalize_quote_for_protocol(finalization, QUOTE_PROTOCOL_V1)
    }

    pub fn finalize_bat_v2_quote(
        &self,
        finalization: &QuoteFinalization,
    ) -> StoreResult<DurableWrite<QuoteRecord>> {
        self.finalize_quote_for_protocol(finalization, QUOTE_PROTOCOL_BAT_V2)
    }

    fn finalize_quote_for_protocol(
        &self,
        finalization: &QuoteFinalization,
        quote_protocol: i64,
    ) -> StoreResult<DurableWrite<QuoteRecord>> {
        validate_quote_finalization(finalization)?;
        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous_identity = verify_expected_identity(&transaction, &self.handle)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;
        let existing =
            read_quote_for_protocol(&transaction, self, &finalization.quote_id, quote_protocol)?
                .ok_or(StoreError::QuoteMissing)?;
        if let Some(commit_marker) = existing.finalization_commit {
            if quote_finalization_matches(&existing, finalization) {
                verify_persisted_quote_history_for_protocol(
                    &transaction,
                    self,
                    &existing,
                    quote_protocol,
                )?
                .ok_or(StoreError::SignedQuoteMismatch)?;
                return Ok(DurableWrite {
                    disposition: WriteDisposition::ExactReplay,
                    commit: commit_marker,
                    value: existing,
                });
            }
            return Err(StoreError::InvoiceConflict);
        }
        if existing.state != QuoteState::Reserved {
            return Err(StoreError::InvalidQuoteState);
        }
        let initial_snapshot = decode_and_verify_quote_snapshot_for_protocol(
            &transaction,
            self,
            &existing,
            &finalization.exact_signed_quote_response,
            quote_protocol,
        )?;
        verify_initial_snapshot(&initial_snapshot, finalization)?;

        let hash_owner: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT quote_id FROM quotes WHERE payment_hash = ?1",
                [finalization.payment_hash.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        if hash_owner.is_some() {
            return Err(StoreError::PaymentHashConflict);
        }
        let invoice_owner: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT quote_id FROM quotes WHERE invoice = ?1",
                [&finalization.invoice],
                |row| row.get(0),
            )
            .optional()?;
        if invoice_owner.is_some() {
            return Err(StoreError::InvoiceConflict);
        }

        let digest = mutation_digest(
            b"finalize-quote-v1",
            &[
                &finalization.quote_id,
                &finalization.payment_hash,
                finalization.invoice.as_bytes(),
                &finalization.exact_signed_quote_response,
            ],
        );
        let committed_identity = advance_store_generation(
            &transaction,
            &previous_identity,
            b"finalize-quote-v1",
            &digest,
        )?;
        let sequence = committed_identity.commit_seq;
        let changed = transaction.execute(
            "UPDATE quotes SET state = 1, state_version = state_version + 1, invoice = ?1, payment_hash = ?2, \
             invoice_created_at = ?3, invoice_expires_at = ?4, claim_deadline = ?5, \
             credential_not_after = ?6, initial_signed_quote_response = ?7, \
             finalization_commit_seq = ?8 WHERE quote_id = ?9 AND state = 0",
            params![
                &finalization.invoice,
                finalization.payment_hash.as_slice(),
                sql_integer(finalization.invoice_created_at, "invoice creation time exceeds SQLite range")?,
                sql_integer(finalization.invoice_expires_at, "invoice expiry exceeds SQLite range")?,
                sql_integer(finalization.claim_deadline, "claim deadline exceeds SQLite range")?,
                sql_integer(finalization.credential_not_after, "credential expiry exceeds SQLite range")?,
                finalization.exact_signed_quote_response.as_slice(),
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
                finalization.quote_id.as_slice(),
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::InvalidQuoteState);
        }
        commit(transaction)?;
        self.anchor_committed_identity(&previous_floor, &committed_identity)?;
        let record =
            read_committed_quote_for_protocol(self, &finalization.quote_id, quote_protocol)?
                .ok_or_else(|| {
                    StoreError::SchemaMismatch("committed quote finalization missing".to_owned())
                })?;
        Ok(DurableWrite {
            disposition: WriteDisposition::Committed,
            commit: marker(self, sequence),
            value: record,
        })
    }

    pub fn mark_invoice_expired(
        &self,
        expiry: &QuoteExpiry,
    ) -> StoreResult<DurableWrite<QuoteRecord>> {
        self.mark_invoice_expired_for_protocol(expiry, QUOTE_PROTOCOL_V1)
    }

    pub fn mark_bat_v2_invoice_expired(
        &self,
        expiry: &QuoteExpiry,
    ) -> StoreResult<DurableWrite<QuoteRecord>> {
        self.mark_invoice_expired_for_protocol(expiry, QUOTE_PROTOCOL_BAT_V2)
    }

    fn mark_invoice_expired_for_protocol(
        &self,
        expiry: &QuoteExpiry,
        quote_protocol: i64,
    ) -> StoreResult<DurableWrite<QuoteRecord>> {
        validate_quote_expiry(expiry)?;
        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous_identity = verify_expected_identity(&transaction, &self.handle)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;
        let existing =
            read_quote_for_protocol(&transaction, self, &expiry.quote_id, quote_protocol)?
                .ok_or(StoreError::QuoteMissing)?;
        if let Some(commit_marker) = existing.expiry_commit {
            if existing.expiry_observed_at == Some(expiry.observed_at)
                && existing.expired_signed_quote_response.as_deref()
                    == Some(expiry.exact_signed_quote_response.as_slice())
            {
                verify_persisted_quote_history_for_protocol(
                    &transaction,
                    self,
                    &existing,
                    quote_protocol,
                )?
                .ok_or(StoreError::SignedQuoteMismatch)?;
                return Ok(DurableWrite {
                    disposition: WriteDisposition::ExactReplay,
                    commit: commit_marker,
                    value: existing,
                });
            }
            return Err(StoreError::InvoiceConflict);
        }
        if existing.state != QuoteState::InvoiceOpen
            || expiry.observed_at
                < existing.invoice_expires_at.ok_or_else(|| {
                    StoreError::SchemaMismatch("open quote lacks invoice expiry".to_owned())
                })?
        {
            return Err(StoreError::InvalidQuoteState);
        }
        let prior_snapshot = verify_persisted_quote_history_for_protocol(
            &transaction,
            self,
            &existing,
            quote_protocol,
        )?
        .ok_or(StoreError::SignedQuoteMismatch)?;
        let expired_snapshot = decode_and_verify_quote_snapshot_for_protocol(
            &transaction,
            self,
            &existing,
            &expiry.exact_signed_quote_response,
            quote_protocol,
        )?;
        verify_successor_snapshot(
            &prior_snapshot,
            &expired_snapshot,
            Bolt11QuoteStatusV1::InvoiceExpiredPendingReconcile,
            2,
            expiry.observed_at,
        )?;
        let observed_at = expiry.observed_at.to_le_bytes();
        let digest = mutation_digest(
            b"expire-quote-v1",
            &[
                &expiry.quote_id,
                &observed_at,
                &expiry.exact_signed_quote_response,
            ],
        );
        let committed_identity = advance_store_generation(
            &transaction,
            &previous_identity,
            b"expire-quote-v1",
            &digest,
        )?;
        let sequence = committed_identity.commit_seq;
        let changed = transaction.execute(
            "UPDATE quotes SET state = 4, state_version = state_version + 1, expiry_observed_at = ?1, \
             expired_signed_quote_response = ?2, expiry_commit_seq = ?3 \
             WHERE quote_id = ?4 AND state = 1",
            params![
                sql_integer(expiry.observed_at, "expiry observation exceeds SQLite range")?,
                expiry.exact_signed_quote_response.as_slice(),
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
                expiry.quote_id.as_slice(),
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::InvalidQuoteState);
        }
        commit(transaction)?;
        self.anchor_committed_identity(&previous_floor, &committed_identity)?;
        let record = read_committed_quote_for_protocol(self, &expiry.quote_id, quote_protocol)?
            .ok_or_else(|| {
                StoreError::SchemaMismatch("committed expiry observation missing".to_owned())
            })?;
        Ok(DurableWrite {
            disposition: WriteDisposition::Committed,
            commit: marker(self, sequence),
            value: record,
        })
    }

    pub fn record_settlement(
        &self,
        settlement: &QuoteSettlement,
    ) -> StoreResult<DurableWrite<QuoteRecord>> {
        self.record_settlement_for_protocol(settlement, QUOTE_PROTOCOL_V1)
    }

    pub fn record_bat_v2_settlement(
        &self,
        settlement: &QuoteSettlement,
    ) -> StoreResult<DurableWrite<QuoteRecord>> {
        self.record_settlement_for_protocol(settlement, QUOTE_PROTOCOL_BAT_V2)
    }

    fn record_settlement_for_protocol(
        &self,
        settlement: &QuoteSettlement,
        quote_protocol: i64,
    ) -> StoreResult<DurableWrite<QuoteRecord>> {
        validate_quote_settlement(settlement)?;
        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous_identity = verify_expected_identity(&transaction, &self.handle)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;
        let existing =
            read_quote_for_protocol(&transaction, self, &settlement.quote_id, quote_protocol)?
                .ok_or(StoreError::QuoteMissing)?;
        let _ = existing.payment_hash.ok_or_else(|| {
            StoreError::SchemaMismatch("settlement quote lacks payment hash".to_owned())
        })?;
        if let Some(commit_marker) = existing.settlement_commit {
            if quote_settlement_matches(&existing, settlement) {
                verify_persisted_quote_history_for_protocol(
                    &transaction,
                    self,
                    &existing,
                    quote_protocol,
                )?
                .ok_or(StoreError::SignedQuoteMismatch)?;
                return Ok(DurableWrite {
                    disposition: WriteDisposition::ExactReplay,
                    commit: commit_marker,
                    value: existing,
                });
            }
            return Err(StoreError::SettlementConflict);
        }
        // A fixed-amount BOLT11 invoice is priced by `exact_amount_msat`.
        // Some Lightning backends report a larger received amount when the
        // payer deliberately overpays.  Persist that evidence, but never let
        // it rewrite the signed quote entitlement.  Underpayment remains a
        // hard mismatch.
        if settlement.settled_amount_msat < existing.exact_amount_msat {
            return Err(StoreError::SettlementConflict);
        }
        let next_state = match existing.state {
            QuoteState::InvoiceOpen => {
                let expiry = existing.invoice_expires_at.ok_or_else(|| {
                    StoreError::SchemaMismatch("open quote lacks invoice expiry".to_owned())
                })?;
                if settlement.settled_at > expiry {
                    return Err(StoreError::RequiresExpiryReconcile);
                }
                QuoteState::PaymentSettled
            }
            QuoteState::InvoiceExpiredPendingReconcile => QuoteState::LateSettledReconcile,
            _ => return Err(StoreError::InvalidQuoteState),
        };
        let prior_snapshot = verify_persisted_quote_history_for_protocol(
            &transaction,
            self,
            &existing,
            quote_protocol,
        )?
        .ok_or(StoreError::SignedQuoteMismatch)?;
        let settled_snapshot = decode_and_verify_quote_snapshot_for_protocol(
            &transaction,
            self,
            &existing,
            &settlement.exact_signed_quote_response,
            quote_protocol,
        )?;
        let expected_status = match next_state {
            QuoteState::PaymentSettled => Bolt11QuoteStatusV1::PaymentSettled,
            QuoteState::LateSettledReconcile => Bolt11QuoteStatusV1::LateSettledReconcile,
            _ => return Err(StoreError::InvalidQuoteState),
        };
        verify_successor_snapshot(
            &prior_snapshot,
            &settled_snapshot,
            expected_status,
            existing
                .state_version
                .checked_add(1)
                .ok_or(StoreError::SignedQuoteMismatch)?,
            settlement.observed_at,
        )?;
        let settled_at = settlement.settled_at.to_le_bytes();
        let observed_at = settlement.observed_at.to_le_bytes();
        let settled_amount_msat = settlement.settled_amount_msat.to_le_bytes();
        let digest = mutation_digest(
            b"settle-quote-v1",
            &[
                &settlement.quote_id,
                &settled_at,
                &observed_at,
                &settled_amount_msat,
                &settlement.settlement_evidence_digest,
                &settlement.exact_signed_quote_response,
            ],
        );
        let committed_identity = advance_store_generation(
            &transaction,
            &previous_identity,
            b"settle-quote-v1",
            &digest,
        )?;
        let sequence = committed_identity.commit_seq;
        let changed = transaction.execute(
            "UPDATE quotes SET state = ?1, state_version = state_version + 1, settled_at = ?2, \
             settlement_observed_at = ?3, settled_amount_msat = ?4, \
             settlement_evidence_digest = ?5, settled_signed_quote_response = ?6, \
             settlement_commit_seq = ?7 WHERE quote_id = ?8 AND settlement_commit_seq IS NULL",
            params![
                next_state as i64,
                sql_integer(
                    settlement.settled_at,
                    "settlement time exceeds SQLite range"
                )?,
                sql_integer(
                    settlement.observed_at,
                    "settlement observation exceeds SQLite range"
                )?,
                sql_integer(
                    settlement.settled_amount_msat,
                    "settled amount exceeds SQLite range"
                )?,
                settlement.settlement_evidence_digest.as_slice(),
                settlement.exact_signed_quote_response.as_slice(),
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
                settlement.quote_id.as_slice(),
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::InvalidQuoteState);
        }
        commit(transaction)?;
        self.anchor_committed_identity(&previous_floor, &committed_identity)?;
        let record = read_committed_quote_for_protocol(self, &settlement.quote_id, quote_protocol)?
            .ok_or_else(|| StoreError::SchemaMismatch("committed settlement missing".to_owned()))?;
        Ok(DurableWrite {
            disposition: WriteDisposition::Committed,
            commit: marker(self, sequence),
            value: record,
        })
    }

    /// Atomically commits one cryptographically verified issuance response.
    ///
    /// Exact idempotent recovery is checked before the current claim deadline
    /// and before invoking `verifier`, so a byte-for-byte replay remains
    /// recoverable after expiry or a signer outage. Every new claim requires a
    /// reviewed BIP340 and method-specific issuance verifier. Experimental ARC
    /// additionally requires its typed canonicalizer.
    pub fn record_claim(
        &self,
        claim: &ClaimWrite,
        verifier: &dyn ClaimCryptographicVerifier,
        arc_canonicalizer: Option<&dyn ArcIssuanceCanonicalizerV1>,
    ) -> StoreResult<DurableWrite<ClaimRecord>> {
        validate_claim(self, claim)?;
        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous_identity = verify_expected_identity(&transaction, &self.handle)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;

        let claim_idempotency_digest = claim_idempotency_digest(self, &claim.claim_idempotency_key);
        if let Some(existing) =
            read_claim_by_idempotency_digest(&transaction, self, &claim_idempotency_digest)?
        {
            if claim_matches(self, &existing, claim)? {
                let quote = read_quote(&transaction, self, &claim.quote_id)?
                    .ok_or(StoreError::QuoteMissing)?;
                verify_persisted_quote_history(&transaction, self, &quote)?
                    .ok_or(StoreError::SignedQuoteMismatch)?;
                return Ok(DurableWrite {
                    disposition: WriteDisposition::ExactReplay,
                    commit: existing.claim_commit,
                    value: existing,
                });
            }
            return Err(StoreError::ClaimIdempotencyConflict);
        }
        if read_claim(&transaction, self, &claim.quote_id)?.is_some() {
            return Err(StoreError::QuoteAlreadyClaimed);
        }
        if claim.now_unix == 0 {
            return Err(StoreError::InvalidInput("claim time is zero"));
        }
        let quote =
            read_quote(&transaction, self, &claim.quote_id)?.ok_or(StoreError::QuoteMissing)?;
        if !matches!(
            quote.state,
            QuoteState::PaymentSettled | QuoteState::LateSettledReconcile
        ) {
            return Err(StoreError::QuoteNotSettled);
        }
        let deadline = quote.claim_deadline.ok_or_else(|| {
            StoreError::SchemaMismatch("settled quote lacks claim deadline".to_owned())
        })?;
        if claim.now_unix > deadline {
            return Err(StoreError::ClaimDeadlineExpired);
        }

        let prior_snapshot = verify_persisted_quote_history(&transaction, self, &quote)?
            .ok_or(StoreError::SignedQuoteMismatch)?;
        let parsed_claim = parse_claim_for_write(self, claim)?;
        let parsed =
            parse_and_bind_issuance(self, &quote, &parsed_claim, claim, arc_canonicalizer)?;
        let claimed_snapshot =
            decode_and_verify_quote_snapshot(self, &quote, &claim.exact_signed_quote_response)?;
        verify_successor_snapshot(
            &prior_snapshot,
            &claimed_snapshot,
            Bolt11QuoteStatusV1::CredentialClaimed,
            quote
                .state_version
                .checked_add(1)
                .ok_or(StoreError::SignedQuoteMismatch)?,
            claim.now_unix,
        )?;
        let bip340_message_digest = parsed_claim
            .bip340_signing_digest()
            .map_err(|_| StoreError::ClaimProtocolMismatch)?;
        if !verifier.verify(ClaimCryptographicVerificationInput {
            claim: &parsed_claim,
            issuance_request: &parsed.request,
            issuance_response: &parsed.response,
            bip340_message_digest: &bip340_message_digest,
        }) {
            return Err(StoreError::BadClaimCryptography);
        }

        for serial in &parsed.receipt_serials {
            let owner: Option<Vec<u8>> = transaction
                .query_row(
                    "SELECT quote_id FROM receipt_serials \
                     WHERE issuer_id = ?1 AND serial = ?2",
                    params![
                        self.handle.expected_issuer_id.as_slice(),
                        serial.serial.as_slice(),
                    ],
                    |row| row.get(0),
                )
                .optional()?;
            if owner.is_some() {
                return Err(StoreError::ReceiptSerialConflict);
            }
        }

        let digest = mutation_digest(
            b"claim-quote-v1",
            &[
                &claim.quote_id,
                &claim_idempotency_digest,
                &claim.claim_request_digest,
                &claim.exact_credential_request,
                &claim.exact_claim_response,
                &claim.exact_signed_quote_response,
            ],
        );
        let committed_identity =
            advance_store_generation(&transaction, &previous_identity, b"claim-quote-v1", &digest)?;
        let sequence = committed_identity.commit_seq;
        transaction.execute(
            "INSERT INTO claims (quote_id, issuer_id, claim_idempotency_digest, \
             claim_request_digest, claim_request_replay_image, exact_credential_request, \
             exact_claim_response, exact_signed_quote_response, claimed_at, claim_commit_seq) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                claim.quote_id.as_slice(),
                self.handle.expected_issuer_id.as_slice(),
                claim_idempotency_digest.as_slice(),
                claim.claim_request_digest.as_slice(),
                claim_replay_image(self, claim)?.as_slice(),
                claim.exact_credential_request.as_slice(),
                claim.exact_claim_response.as_slice(),
                claim.exact_signed_quote_response.as_slice(),
                sql_integer(claim.now_unix, "claim time exceeds SQLite range")?,
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
            ],
        )?;
        for serial in &parsed.receipt_serials {
            transaction.execute(
                "INSERT INTO receipt_serials (issuer_id, key_id, serial, quote_id) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    self.handle.expected_issuer_id.as_slice(),
                    serial.key_id.as_slice(),
                    serial.serial.as_slice(),
                    claim.quote_id.as_slice(),
                ],
            )?;
        }
        let changed = transaction.execute(
            "UPDATE quotes SET state = 3, state_version = state_version + 1 \
             WHERE quote_id = ?1 AND state IN (2, 5)",
            [claim.quote_id.as_slice()],
        )?;
        if changed != 1 {
            return Err(StoreError::QuoteNotSettled);
        }
        commit(transaction)?;
        self.anchor_committed_identity(&previous_floor, &committed_identity)?;
        let record = self
            .claim(&claim.quote_id)?
            .ok_or_else(|| StoreError::SchemaMismatch("committed claim missing".to_owned()))?;
        Ok(DurableWrite {
            disposition: WriteDisposition::Committed,
            commit: marker(self, sequence),
            value: record,
        })
    }

    /// Atomically commit one class-bound BAT V2 issuance. Exact replay is
    /// resolved before time and cryptographic callbacks; no V2 path writes a
    /// `receipt_serials` row.
    pub fn record_bat_v2_claim(
        &self,
        write: &BatV2ClaimWrite,
        verifier: &dyn BatV2ClaimCryptographicVerifierV2,
    ) -> StoreResult<DurableWrite<ClaimRecord>> {
        let (envelope, response) = parse_bat_v2_claim_write(write)?;
        let quote_id = envelope.claim.quote_id;
        let claim_idempotency_digest =
            claim_idempotency_digest(self, &envelope.claim.idempotency_key);
        let claim_request_digest = envelope
            .claim
            .claim_request_digest()
            .map_err(StoreError::Protocol)?;

        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous_identity = verify_expected_identity(&transaction, &self.handle)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;
        let quote = read_quote_for_protocol(&transaction, self, &quote_id, QUOTE_PROTOCOL_BAT_V2)?
            .ok_or(StoreError::QuoteMissing)?;
        validate_bat_v2_envelope_for_quote(self, &quote, &envelope)?;
        let claim_replay_image = bat_v2_claim_replay_image(self, &envelope)?;
        let exact_credential_request = envelope
            .credential_request
            .encode()
            .map_err(StoreError::Protocol)?;

        if let Some(existing) = read_claim_where(
            &transaction,
            self,
            "claim_idempotency_digest",
            &claim_idempotency_digest,
            QUOTE_PROTOCOL_BAT_V2,
        )? {
            if bat_v2_claim_matches(
                &existing,
                write,
                &quote_id,
                claim_request_digest,
                &claim_replay_image,
                &exact_credential_request,
            ) {
                verify_persisted_quote_history_for_protocol(
                    &transaction,
                    self,
                    &quote,
                    QUOTE_PROTOCOL_BAT_V2,
                )?
                .ok_or(StoreError::SignedQuoteMismatch)?;
                return Ok(DurableWrite {
                    disposition: WriteDisposition::ExactReplay,
                    commit: existing.claim_commit,
                    value: existing,
                });
            }
            return Err(StoreError::ClaimIdempotencyConflict);
        }
        if read_claim_where(
            &transaction,
            self,
            "quote_id",
            &quote_id,
            QUOTE_PROTOCOL_BAT_V2,
        )?
        .is_some()
        {
            return Err(StoreError::QuoteAlreadyClaimed);
        }
        if write.now_unix == 0 {
            return Err(StoreError::InvalidInput("claim time is zero"));
        }
        if !matches!(
            quote.state,
            QuoteState::PaymentSettled | QuoteState::LateSettledReconcile
        ) {
            return Err(StoreError::QuoteNotSettled);
        }
        let deadline = quote.claim_deadline.ok_or_else(|| {
            StoreError::SchemaMismatch("settled BAT V2 quote lacks claim deadline".to_owned())
        })?;
        if write.now_unix > deadline {
            return Err(StoreError::ClaimDeadlineExpired);
        }

        let prior_snapshot = verify_persisted_quote_history_for_protocol(
            &transaction,
            self,
            &quote,
            QUOTE_PROTOCOL_BAT_V2,
        )?
        .ok_or(StoreError::SignedQuoteMismatch)?;
        let replay_intent = decode_replay_bat_v2_intent(self, &quote)?;
        let class_record = read_bat_acceptance_class_v2(
            &transaction,
            self,
            &replay_intent.class_id,
            replay_intent.class_key_epoch,
        )?
        .ok_or(StoreError::ClaimProtocolMismatch)?;
        let class = BatAcceptanceClassV2::decode(&class_record.exact_artifact)
            .map_err(|_| StoreError::ClaimProtocolMismatch)?;
        let delegation = Bolt11QuoteKeyDelegationV1::decode(&quote.exact_delegation)
            .map_err(|_| StoreError::ClaimProtocolMismatch)?;
        let verified_quote = prior_snapshot
            .verify_persisted_bat_v2_quote_for_store(
                PersistedBolt11BatV2QuoteExpectationV2 {
                    original_request_digest: &quote.intent_digest,
                    replay_intent: &replay_intent,
                    class: &class,
                    quote_id: &quote.quote_id,
                    invoice: quote
                        .invoice
                        .as_deref()
                        .ok_or(StoreError::SignedQuoteMismatch)?,
                    invoice_created_at: quote
                        .invoice_created_at
                        .ok_or(StoreError::SignedQuoteMismatch)?,
                    invoice_expires_at: quote
                        .invoice_expires_at
                        .ok_or(StoreError::SignedQuoteMismatch)?,
                    claim_deadline: deadline,
                    credential_not_after: quote
                        .credential_not_after
                        .ok_or(StoreError::SignedQuoteMismatch)?,
                },
                &delegation,
                write.now_unix,
            )
            .map_err(|_| StoreError::ClaimProtocolMismatch)?;
        let bip340 = envelope
            .credential_request
            .verify_for_verified_quote(&envelope.claim, &verified_quote, write.now_unix)
            .map_err(|_| StoreError::ClaimProtocolMismatch)?;
        let checked_response = response
            .verify_for_verified_quote(&envelope.credential_request, &verified_quote)
            .map_err(|_| StoreError::ClaimProtocolMismatch)?;
        let claimed_snapshot = decode_and_verify_quote_snapshot_for_protocol(
            &transaction,
            self,
            &quote,
            &write.exact_signed_quote_response,
            QUOTE_PROTOCOL_BAT_V2,
        )?;
        verify_successor_snapshot(
            &prior_snapshot,
            &claimed_snapshot,
            Bolt11QuoteStatusV1::CredentialClaimed,
            quote
                .state_version
                .checked_add(1)
                .ok_or(StoreError::SignedQuoteMismatch)?,
            write.now_unix,
        )?;
        if !verifier.verify(BatV2ClaimCryptographicVerificationInputV2 {
            claim_envelope: &envelope,
            issuance_response: &response,
            checked_response: &checked_response,
            bip340_message_digest: &bip340.message_digest,
        }) {
            return Err(StoreError::BadClaimCryptography);
        }

        let mutation = mutation_digest(
            b"claim-bat-v2-quote-v2",
            &[
                &quote_id,
                &claim_idempotency_digest,
                &claim_request_digest,
                &exact_credential_request,
                &write.exact_claim_response,
                &write.exact_signed_quote_response,
            ],
        );
        let committed_identity = advance_store_generation(
            &transaction,
            &previous_identity,
            b"claim-bat-v2-quote-v2",
            &mutation,
        )?;
        let sequence = committed_identity.commit_seq;
        transaction.execute(
            "INSERT INTO claims (quote_id, issuer_id, claim_idempotency_digest, \
             claim_request_digest, claim_request_replay_image, exact_credential_request, \
             exact_claim_response, exact_signed_quote_response, claimed_at, claim_commit_seq) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                quote_id.as_slice(),
                self.handle.expected_issuer_id.as_slice(),
                claim_idempotency_digest.as_slice(),
                claim_request_digest.as_slice(),
                claim_replay_image.as_slice(),
                exact_credential_request.as_slice(),
                write.exact_claim_response.as_slice(),
                write.exact_signed_quote_response.as_slice(),
                sql_integer(write.now_unix, "claim time exceeds SQLite range")?,
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
            ],
        )?;
        let changed = transaction.execute(
            "UPDATE quotes SET state = 3, state_version = state_version + 1 \
             WHERE quote_id = ?1 AND quote_protocol = 2 AND state IN (2, 5)",
            [quote_id.as_slice()],
        )?;
        if changed != 1 {
            return Err(StoreError::QuoteNotSettled);
        }
        commit(transaction)?;
        self.anchor_committed_identity(&previous_floor, &committed_identity)?;
        let record = self.bat_v2_claim(&quote_id)?.ok_or_else(|| {
            StoreError::SchemaMismatch("committed BAT V2 claim missing".to_owned())
        })?;
        Ok(DurableWrite {
            disposition: WriteDisposition::Committed,
            commit: marker(self, sequence),
            value: record,
        })
    }

    /// Issuer-internal lookup only. An HTTP adapter MUST authenticate a
    /// possession-bound status request before exposing this record; knowledge
    /// of `quote_id` alone is not authorization to read invoice or status.
    pub fn quote(&self, quote_id: &[u8; 32]) -> StoreResult<Option<QuoteRecord>> {
        if is_zero(quote_id) {
            return Err(StoreError::InvalidInput("quote id is all zero"));
        }
        let connection = self.open_checked(false)?;
        let value = read_quote(&connection, self, quote_id)?;
        self.confirm_anchored_read(&connection, value)
    }

    /// Issuer-internal exact-create recovery lookup. The raw key is hashed in
    /// memory and never persisted; this is not a public bearer-status API.
    pub fn quote_by_creation_idempotency_key(
        &self,
        idempotency_key: &[u8; 32],
    ) -> StoreResult<Option<QuoteRecord>> {
        if is_zero(idempotency_key) {
            return Err(StoreError::InvalidInput(
                "creation idempotency key is all zero",
            ));
        }
        let connection = self.open_checked(false)?;
        let digest = creation_idempotency_digest(self, idempotency_key);
        let value = read_quote_by_creation_digest(&connection, self, &digest)?;
        self.confirm_anchored_read(&connection, value)
    }

    /// Issuer-internal Lightning-backend reconciliation lookup. Backend labels
    /// are not bearer authorization and this method must not be exposed as a
    /// public status endpoint.
    pub fn quote_by_backend_label(&self, label: &str) -> StoreResult<Option<QuoteRecord>> {
        if label.is_empty() || label.len() > 96 {
            return Err(StoreError::InvalidInput("backend label length is invalid"));
        }
        let connection = self.open_checked(false)?;
        let value = read_quote_by_label(&connection, self, label)?;
        self.confirm_anchored_read(&connection, value)
    }

    /// Enumerate a bounded deterministic page of quotes whose Lightning
    /// lifecycle still needs background reconciliation. The cursor is the
    /// last returned quote ID; callers wrap only after observing an empty page.
    pub fn quote_reconciliation_candidates_after(
        &self,
        after_quote_id: Option<&[u8; 32]>,
        limit: u32,
        now_unix: u64,
    ) -> StoreResult<Vec<QuoteReconciliationCandidateV1>> {
        if limit == 0 || limit > MAX_QUOTE_RECONCILIATION_BATCH_V1 {
            return Err(StoreError::InvalidInput(
                "quote reconciliation batch limit is invalid",
            ));
        }
        if after_quote_id.is_some_and(|value| is_zero(value)) {
            return Err(StoreError::InvalidInput(
                "quote reconciliation cursor is all zero",
            ));
        }
        if now_unix == 0 {
            return Err(StoreError::InvalidInput(
                "quote reconciliation observation time is zero",
            ));
        }
        let connection = self.open_checked(false)?;
        let mut statement = connection.prepare(
            "SELECT quote_id, backend_label, delegation_digest
             FROM quotes
             WHERE quote_protocol = 1
               AND ((state = 0 AND reservation_recovery_deadline >= ?1)
                    OR (state IN (1, 4) AND claim_deadline >= ?1))
               AND (?2 IS NULL OR quote_id > ?2)
             ORDER BY quote_id ASC
             LIMIT ?3",
        )?;
        let cursor = after_quote_id.map(|value| value.as_slice());
        let rows = statement.query_map(
            params![
                sql_integer(now_unix, "quote reconciliation observation time")?,
                cursor,
                i64::from(limit)
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )?;
        let mut candidates = Vec::with_capacity(limit as usize);
        for row in rows {
            let (quote_id, backend_label, delegation_digest) = row?;
            let quote_id = fixed_blob(quote_id, "invalid reconciliation quote id")?;
            let delegation_digest = fixed_blob(
                delegation_digest,
                "invalid reconciliation delegation digest",
            )?;
            if is_zero(&quote_id)
                || is_zero(&delegation_digest)
                || backend_label != self.backend_label_for_quote(&quote_id)?
            {
                return Err(StoreError::SchemaMismatch(
                    "invalid quote reconciliation candidate".to_owned(),
                ));
            }
            candidates.push(QuoteReconciliationCandidateV1 {
                quote_id,
                backend_label,
                delegation_digest,
            });
        }
        drop(statement);
        self.confirm_anchored_read(&connection, candidates)
    }

    pub fn bat_v2_quote(&self, quote_id: &[u8; 32]) -> StoreResult<Option<QuoteRecord>> {
        if is_zero(quote_id) {
            return Err(StoreError::InvalidInput("quote id is all zero"));
        }
        let connection = self.open_checked(false)?;
        let value = read_quote_for_protocol(&connection, self, quote_id, QUOTE_PROTOCOL_BAT_V2)?;
        self.confirm_anchored_read(&connection, value)
    }

    pub fn bat_v2_quote_by_creation_idempotency_key(
        &self,
        idempotency_key: &[u8; 32],
    ) -> StoreResult<Option<QuoteRecord>> {
        if is_zero(idempotency_key) {
            return Err(StoreError::InvalidInput(
                "creation idempotency key is all zero",
            ));
        }
        let connection = self.open_checked(false)?;
        let digest = creation_idempotency_digest(self, idempotency_key);
        let value = read_quote_by_creation_digest_for_protocol(
            &connection,
            self,
            &digest,
            QUOTE_PROTOCOL_BAT_V2,
        )?;
        self.confirm_anchored_read(&connection, value)
    }

    pub fn bat_v2_quote_by_backend_label(&self, label: &str) -> StoreResult<Option<QuoteRecord>> {
        if label.is_empty() || label.len() > 96 {
            return Err(StoreError::InvalidInput("backend label length is invalid"));
        }
        let connection = self.open_checked(false)?;
        let value =
            read_quote_by_label_for_protocol(&connection, self, label, QUOTE_PROTOCOL_BAT_V2)?;
        self.confirm_anchored_read(&connection, value)
    }

    pub fn bat_v2_quote_reconciliation_candidates_after(
        &self,
        after_quote_id: Option<&[u8; 32]>,
        limit: u32,
        now_unix: u64,
    ) -> StoreResult<Vec<QuoteReconciliationCandidateV1>> {
        if limit == 0 || limit > MAX_QUOTE_RECONCILIATION_BATCH_V1 {
            return Err(StoreError::InvalidInput(
                "quote reconciliation batch limit is invalid",
            ));
        }
        if after_quote_id.is_some_and(|value| is_zero(value)) || now_unix == 0 {
            return Err(StoreError::InvalidInput(
                "invalid BAT V2 quote reconciliation cursor or time",
            ));
        }
        let connection = self.open_checked(false)?;
        let mut statement = connection.prepare(
            "SELECT quote_id, backend_label, delegation_digest FROM quotes
             WHERE quote_protocol = 2
               AND ((state = 0 AND reservation_recovery_deadline >= ?1)
                    OR (state IN (1, 4) AND claim_deadline >= ?1))
               AND (?2 IS NULL OR quote_id > ?2)
             ORDER BY quote_id ASC LIMIT ?3",
        )?;
        let cursor = after_quote_id.map(|value| value.as_slice());
        let rows = statement.query_map(
            params![
                sql_integer(now_unix, "quote reconciliation observation time")?,
                cursor,
                i64::from(limit),
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )?;
        let mut candidates = Vec::with_capacity(limit as usize);
        for row in rows {
            let (quote_id, backend_label, delegation_digest) = row?;
            let quote_id = fixed_blob(quote_id, "invalid reconciliation quote id")?;
            let delegation_digest = fixed_blob(
                delegation_digest,
                "invalid reconciliation delegation digest",
            )?;
            if is_zero(&quote_id)
                || is_zero(&delegation_digest)
                || backend_label != self.backend_label_for_quote(&quote_id)?
            {
                return Err(StoreError::SchemaMismatch(
                    "invalid BAT V2 quote reconciliation candidate".to_owned(),
                ));
            }
            candidates.push(QuoteReconciliationCandidateV1 {
                quote_id,
                backend_label,
                delegation_digest,
            });
        }
        drop(statement);
        self.confirm_anchored_read(&connection, candidates)
    }

    /// Enumerate BAT key epochs needed for one fresh acquisition from a live
    /// current class head, recovery of an unfinished historical V2 quote, or
    /// redemption of an already-issued credential while its retained class
    /// and at least one member remain redeemable.
    ///
    /// Each result carries the exact compressed public key that identifies a
    /// required private mint scalar in the caller's keyring. This store never
    /// persists or returns the scalar itself. Duplicate requirements from the
    /// three retention sources are collapsed by `(class_id, key_epoch)`.
    pub fn bat_v2_credential_material_requirements(
        &self,
        now_unix: u64,
    ) -> StoreResult<Vec<BatV2CredentialMaterialRequirementV2>> {
        if now_unix == 0 {
            return Err(StoreError::InvalidInput(
                "BAT V2 credential inventory time is zero",
            ));
        }
        let connection = self.open_checked(false)?;
        let mut statement = connection.prepare(
            "SELECT intent_replay_image FROM quotes
             WHERE quote_protocol = 2 AND (
                 (state = 0 AND reservation_recovery_deadline >= ?1) OR
                 (state IN (1, 2, 4, 5) AND claim_deadline >= ?1)
             ) ORDER BY quote_id",
        )?;
        let replay_images = statement
            .query_map(
                [sql_integer(
                    now_unix,
                    "BAT V2 credential inventory time exceeds SQLite range",
                )?],
                |row| row.get::<_, Vec<u8>>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);

        let mut referenced = BTreeSet::new();
        for replay_image in replay_images {
            let intent = Bolt11BatV2QuoteIntentV2::decode(&replay_image).map_err(|_| {
                StoreError::SchemaMismatch(
                    "unfinished BAT V2 quote has an invalid replay intent".to_owned(),
                )
            })?;
            referenced.insert((intent.class_id, intent.class_key_epoch));
        }

        let mut issued_statement = connection.prepare(
            "SELECT q.intent_replay_image
             FROM claims c
             JOIN quotes q ON q.quote_id = c.quote_id
             WHERE q.quote_protocol = 2 AND q.issuer_id = ?1
             ORDER BY q.quote_id",
        )?;
        let issued_replay_images = issued_statement
            .query_map([self.handle.expected_issuer_id.as_slice()], |row| {
                row.get::<_, Vec<u8>>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(issued_statement);
        for replay_image in issued_replay_images {
            let intent = Bolt11BatV2QuoteIntentV2::decode(&replay_image).map_err(|_| {
                StoreError::SchemaMismatch(
                    "issued BAT V2 credential has an invalid replay intent".to_owned(),
                )
            })?;
            let class = read_bat_acceptance_class_v2(
                &connection,
                self,
                &intent.class_id,
                intent.class_key_epoch,
            )?
            .ok_or_else(|| {
                StoreError::SchemaMismatch(
                    "issued BAT V2 credential references a missing class epoch".to_owned(),
                )
            })?;
            if class.key_not_after >= now_unix
                && class
                    .members
                    .iter()
                    .any(|member| member.redemption_deadline >= now_unix)
            {
                referenced.insert((intent.class_id, intent.class_key_epoch));
            }
        }

        let mut head_statement = connection.prepare(
            "SELECT class_id, highest_key_epoch FROM bat_v2_class_heads \
             WHERE issuer_id = ?1 ORDER BY class_id",
        )?;
        let heads = head_statement
            .query_map([self.handle.expected_issuer_id.as_slice()], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(head_statement);
        for (class_id, key_epoch) in heads {
            let class_id = fixed_blob(class_id, "invalid BAT V2 class head ID")?;
            let key_epoch = db_u64(key_epoch, "negative BAT V2 class head epoch")?;
            let record = read_bat_acceptance_class_v2(&connection, self, &class_id, key_epoch)?
                .ok_or_else(|| {
                    StoreError::SchemaMismatch(
                        "BAT V2 class head references a missing artifact".to_owned(),
                    )
                })?;
            let artifact = BatAcceptanceClassV2::decode(&record.exact_artifact).map_err(|_| {
                StoreError::SchemaMismatch("BAT V2 class head artifact is not canonical".to_owned())
            })?;
            let fresh_credential_horizon = now_unix
                .checked_add(u64::from(artifact.common_terms.invoice_expiry_seconds))
                .and_then(|value| {
                    value.checked_add(u64::from(artifact.common_terms.claim_window_seconds))
                })
                .and_then(|value| {
                    value.checked_add(u64::from(
                        artifact.common_terms.minimum_credential_validity_seconds,
                    ))
                });
            if now_unix >= artifact.key_not_before
                && fresh_credential_horizon.is_some_and(|horizon| horizon <= artifact.key_not_after)
            {
                referenced.insert((class_id, key_epoch));
            }
        }

        let mut requirements = Vec::with_capacity(referenced.len());
        for (class_id, class_key_epoch) in referenced {
            let class =
                read_bat_acceptance_class_v2(&connection, self, &class_id, class_key_epoch)?
                    .ok_or_else(|| {
                        StoreError::SchemaMismatch(
                            "unfinished BAT V2 quote references a missing class epoch".to_owned(),
                        )
                    })?;
            requirements.push(BatV2CredentialMaterialRequirementV2 {
                class_id,
                class_key_epoch,
                raw_public_key: class.raw_public_key,
                bat_key_id: class.bat_key_id,
            });
        }
        self.confirm_anchored_read(&connection, requirements)
    }

    /// Authenticates and atomically consumes a fresh private quote-status
    /// request before returning issuer-confidential invoice/status data.
    ///
    /// `verifier` must be a reviewed BIP340 implementation. The SQLite nonce
    /// commit is anchored in the independently durable rollback authority
    /// before this method releases either the status value or its marker.
    pub fn consume_quote_status_request(
        &self,
        request: &Bolt11QuoteStatusRequestV1,
        now_unix: u64,
        verifier: &dyn QuoteStatusBip340Verifier,
    ) -> StoreResult<DurableWrite<AuthenticatedQuoteStatus>> {
        self.consume_quote_status_request_for_protocol(
            request,
            now_unix,
            verifier,
            QUOTE_PROTOCOL_V1,
        )
    }

    /// BAT V2 counterpart of [`Self::consume_quote_status_request`]. The
    /// persisted class-bound quote typestate is reconstructed before the
    /// possession proof is accepted; a V1 quote therefore fails closed.
    pub fn consume_bat_v2_quote_status_request(
        &self,
        request: &Bolt11QuoteStatusRequestV1,
        now_unix: u64,
        verifier: &dyn QuoteStatusBip340Verifier,
    ) -> StoreResult<DurableWrite<AuthenticatedQuoteStatus>> {
        self.consume_quote_status_request_for_protocol(
            request,
            now_unix,
            verifier,
            QUOTE_PROTOCOL_BAT_V2,
        )
    }

    fn consume_quote_status_request_for_protocol(
        &self,
        request: &Bolt11QuoteStatusRequestV1,
        now_unix: u64,
        verifier: &dyn QuoteStatusBip340Verifier,
        quote_protocol: i64,
    ) -> StoreResult<DurableWrite<AuthenticatedQuoteStatus>> {
        if now_unix == 0 {
            return Err(StoreError::InvalidInput("status request time is zero"));
        }
        request
            .encode()
            .map_err(|_| StoreError::InvalidInput("status request is not canonical V1"))?;
        let preliminary_connection = self.open_checked(false)?;
        let preliminary = read_quote_for_protocol(
            &preliminary_connection,
            self,
            &request.quote_id,
            quote_protocol,
        )?
        .ok_or(StoreError::QuoteMissing)?;
        verify_status_request_binding_for_protocol(
            &preliminary_connection,
            self,
            request,
            &preliminary,
            now_unix,
            verifier,
            quote_protocol,
        )?;
        self.confirm_anchored_read(&preliminary_connection, ())?;
        drop(preliminary_connection);

        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous_identity = verify_expected_identity(&transaction, &self.handle)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;
        if now_unix < previous_identity.status_time_floor {
            return Err(StoreError::StatusTimeRollback);
        }
        let current =
            read_quote_for_protocol(&transaction, self, &request.quote_id, quote_protocol)?
                .ok_or(StoreError::QuoteMissing)?;
        if current.intent_digest != preliminary.intent_digest
            || current.intent_replay_image != preliminary.intent_replay_image
        {
            return Err(StoreError::SchemaMismatch(
                "immutable quote intent changed during status verification".to_owned(),
            ));
        }
        let latest_snapshot = verify_persisted_quote_history_for_protocol(
            &transaction,
            self,
            &current,
            quote_protocol,
        )?
        .ok_or(StoreError::InvalidQuoteState)?;
        let status = AuthenticatedQuoteStatus {
            quote_id: current.quote_id,
            state: current.state,
            state_version: current.state_version,
            exact_signed_quote_response: latest_snapshot
                .encode()
                .map_err(|_| StoreError::SignedQuoteMismatch)?,
        };

        let nonce_digest = status_nonce_digest(self, &request.quote_id, &request.request_nonce);
        let already_consumed: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM quote_status_nonces \
             WHERE quote_id = ?1 AND nonce_digest = ?2)",
            params![request.quote_id.as_slice(), nonce_digest.as_slice()],
            |row| row.get(0),
        )?;
        if already_consumed {
            return Err(StoreError::StatusNonceReplay);
        }
        let expires_at = request
            .requested_at
            .checked_add(MAX_BOLT11_QUOTE_STATUS_REQUEST_AGE_SECONDS_V1)
            .ok_or(StoreError::InvalidInput(
                "status request freshness horizon overflows",
            ))?;
        transaction.execute(
            "DELETE FROM quote_status_nonces WHERE expires_at < ?1",
            [sql_integer(now_unix, "status time exceeds SQLite range")?],
        )?;
        let active_for_quote = db_u64(
            transaction.query_row(
                "SELECT COUNT(*) FROM quote_status_nonces WHERE quote_id = ?1",
                [request.quote_id.as_slice()],
                |row| row.get(0),
            )?,
            "active quote-status nonce count is invalid",
        )?;
        if active_for_quote >= MAX_ACTIVE_STATUS_NONCES_PER_QUOTE_V1 {
            return Err(StoreError::StatusNonceCapacityExceeded);
        }
        let now = now_unix.to_le_bytes();
        let expiry = expires_at.to_le_bytes();
        let mutation_domain: &[u8] = if quote_protocol == QUOTE_PROTOCOL_V1 {
            b"consume-quote-status-nonce-v1"
        } else {
            b"consume-bat-v2-quote-status-nonce-v2"
        };
        let digest = mutation_digest(
            mutation_domain,
            &[&request.quote_id, &nonce_digest, &now, &expiry],
        );
        let committed_identity =
            advance_store_generation(&transaction, &previous_identity, mutation_domain, &digest)?;
        let sequence = committed_identity.commit_seq;
        transaction.execute(
            "INSERT INTO quote_status_nonces (quote_id, nonce_digest, expires_at, commit_seq) \
             VALUES (?1, ?2, ?3, ?4)",
            params![
                request.quote_id.as_slice(),
                nonce_digest.as_slice(),
                sql_integer(expires_at, "status nonce expiry exceeds SQLite range")?,
                sql_integer(sequence, "commit sequence exceeds SQLite range")?,
            ],
        )?;
        let changed = transaction.execute(
            "UPDATE store_identity SET status_time_floor = ?1 \
             WHERE singleton = 1 AND status_time_floor <= ?1",
            [sql_integer(now_unix, "status time exceeds SQLite range")?],
        )?;
        if changed != 1 {
            return Err(StoreError::StatusTimeRollback);
        }
        commit(transaction)?;
        self.anchor_committed_identity(&previous_floor, &committed_identity)?;
        Ok(DurableWrite {
            disposition: WriteDisposition::Committed,
            commit: marker(self, sequence),
            value: status,
        })
    }

    /// Issuer-internal exact-response recovery lookup. Public claim recovery
    /// must first authenticate the exact signed claim and idempotency key via
    /// [`Self::record_claim`].
    pub fn claim(&self, quote_id: &[u8; 32]) -> StoreResult<Option<ClaimRecord>> {
        if is_zero(quote_id) {
            return Err(StoreError::InvalidInput("quote id is all zero"));
        }
        let connection = self.open_checked(false)?;
        let value = read_claim(&connection, self, quote_id)?;
        self.confirm_anchored_read(&connection, value)
    }

    /// Issuer-internal diagnostic lookup; knowledge of an idempotency key alone
    /// must never become a network authorization mechanism.
    pub fn claim_by_idempotency_key(
        &self,
        idempotency_key: &[u8; 32],
    ) -> StoreResult<Option<ClaimRecord>> {
        if is_zero(idempotency_key) {
            return Err(StoreError::InvalidInput(
                "claim idempotency key is all zero",
            ));
        }
        let connection = self.open_checked(false)?;
        let digest = claim_idempotency_digest(self, idempotency_key);
        let value = read_claim_by_idempotency_digest(&connection, self, &digest)?;
        self.confirm_anchored_read(&connection, value)
    }

    /// Issuer-internal BAT V2 exact-response recovery lookup. The quote
    /// discriminator is checked through the claim's quote foreign key, so a
    /// V1 claim can never be decoded or returned through this path.
    pub fn bat_v2_claim(&self, quote_id: &[u8; 32]) -> StoreResult<Option<ClaimRecord>> {
        if is_zero(quote_id) {
            return Err(StoreError::InvalidInput("quote id is all zero"));
        }
        let connection = self.open_checked(false)?;
        let value = read_claim_where(
            &connection,
            self,
            "quote_id",
            quote_id,
            QUOTE_PROTOCOL_BAT_V2,
        )?;
        self.confirm_anchored_read(&connection, value)
    }

    /// Issuer-internal BAT V2 diagnostic recovery lookup. The raw key is
    /// hashed in memory and is never persisted or sufficient public
    /// authorization on its own.
    pub fn bat_v2_claim_by_idempotency_key(
        &self,
        idempotency_key: &[u8; 32],
    ) -> StoreResult<Option<ClaimRecord>> {
        if is_zero(idempotency_key) {
            return Err(StoreError::InvalidInput(
                "claim idempotency key is all zero",
            ));
        }
        let connection = self.open_checked(false)?;
        let digest = claim_idempotency_digest(self, idempotency_key);
        let value = read_claim_where(
            &connection,
            self,
            "claim_idempotency_digest",
            &digest,
            QUOTE_PROTOCOL_BAT_V2,
        )?;
        self.confirm_anchored_read(&connection, value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HeadDecision {
    Exact,
    Advance,
}

fn validate_quote_capacity(capacity: QuoteCapacityV1) -> StoreResult<()> {
    if capacity.max_outstanding_unpaid == 0
        || capacity.max_active_records == 0
        || capacity.max_outstanding_unpaid > capacity.max_active_records
    {
        Err(StoreError::InvalidInput("invalid quote capacity"))
    } else {
        Ok(())
    }
}

fn check_quote_capacity(
    transaction: &Transaction<'_>,
    capacity: QuoteCapacityV1,
    now_unix: u64,
) -> StoreResult<()> {
    let now = sql_integer(now_unix, "quote capacity observation time")?;
    let active_records = db_u64(
        transaction.query_row(
            "SELECT COUNT(*) FROM quotes
             WHERE (state = 0 AND reservation_recovery_deadline >= ?1)
                OR (state IN (1, 4) AND claim_deadline >= ?1)",
            [now],
            |row| row.get(0),
        )?,
        "active quote record count is invalid",
    )?;
    let outstanding_unpaid = db_u64(
        transaction.query_row(
            "SELECT COUNT(*) FROM quotes
             WHERE (state = 0 AND reservation_recovery_deadline >= ?1)
                OR (state = 1 AND claim_deadline >= ?1)",
            [now],
            |row| row.get(0),
        )?,
        "outstanding quote count is invalid",
    )?;
    if active_records >= capacity.max_active_records
        || outstanding_unpaid >= capacity.max_outstanding_unpaid
    {
        Err(StoreError::QuoteCapacityExceeded)
    } else {
        Ok(())
    }
}

fn parse_bat_v2_reservation(
    store: &IssuerStore,
    reservation: &BatV2QuoteReservation,
) -> StoreResult<(Bolt11BatV2QuoteIntentV2, Bolt11QuoteKeyDelegationV1)> {
    if is_zero(&reservation.quote_id)
        || reservation.exact_intent.is_empty()
        || reservation.exact_intent.len() > MAX_EXACT_INTENT_BYTES
        || reservation.exact_delegation.is_empty()
        || reservation.exact_delegation.len() > MAX_EXACT_DELEGATION_BYTES
        || reservation.invoice_created_not_before == 0
        || reservation.invoice_created_not_after < reservation.invoice_created_not_before
        || reservation.now_unix == 0
    {
        return Err(StoreError::InvalidInput("invalid BAT V2 quote reservation"));
    }
    let intent = Bolt11BatV2QuoteIntentV2::decode(&reservation.exact_intent)
        .map_err(|_| StoreError::InvalidInput("BAT V2 intent is not canonical"))?;
    let delegation = Bolt11QuoteKeyDelegationV1::decode(&reservation.exact_delegation)
        .map_err(|_| StoreError::InvalidInput("delegation is not canonical V1"))?;
    if intent.encode().map_err(StoreError::Protocol)? != reservation.exact_intent
        || delegation.encode().map_err(StoreError::Protocol)? != reservation.exact_delegation
        || intent.issuer_id != store.handle.expected_issuer_id
        || intent.network != store.handle.expected_network
        || intent.expected_payee_pubkey != delegation.expected_payee_pubkey
        || intent.minimum_quote_key_epoch != delegation.key_epoch
        || intent.quote_delegation_digest
            != delegation
                .delegation_digest()
                .map_err(StoreError::Protocol)?
        || delegation.issuer_id != store.handle.expected_issuer_id
        || delegation.network != store.handle.expected_network
    {
        return Err(StoreError::InvalidInput(
            "BAT V2 intent and delegation binding mismatch",
        ));
    }
    let _ = sql_integer(intent.exact_amount_msat, "amount exceeds SQLite range")?;
    let _ = sql_integer(
        reservation.invoice_created_not_before,
        "invoice creation lower bound exceeds SQLite range",
    )?;
    let _ = sql_integer(
        reservation.invoice_created_not_after,
        "invoice creation upper bound exceeds SQLite range",
    )?;
    Ok((intent, delegation))
}

fn bat_v2_reservation_recovery_deadline(
    invoice_created_not_after: u64,
    intent: &Bolt11BatV2QuoteIntentV2,
) -> StoreResult<u64> {
    let deadline = invoice_created_not_after
        .checked_add(u64::from(intent.invoice_expiry_seconds))
        .and_then(|value| value.checked_add(u64::from(intent.claim_window_seconds)))
        .ok_or(StoreError::InvalidInput(
            "BAT V2 reservation recovery horizon overflows Unix time",
        ))?;
    let _ = sql_integer(
        deadline,
        "BAT V2 reservation recovery horizon exceeds SQLite range",
    )?;
    Ok(deadline)
}

fn bat_v2_intent_replay_image(
    store: &IssuerStore,
    intent: &Bolt11BatV2QuoteIntentV2,
) -> StoreResult<Vec<u8>> {
    let mut replay = intent.clone();
    replay.idempotency_key = creation_idempotency_digest(store, &intent.idempotency_key);
    replay.encode().map_err(StoreError::Protocol)
}

#[allow(clippy::too_many_arguments)]
fn bat_v2_quote_reservation_matches(
    store: &IssuerStore,
    record: &QuoteRecord,
    reservation: &BatV2QuoteReservation,
    intent: &Bolt11BatV2QuoteIntentV2,
    delegation: &Bolt11QuoteKeyDelegationV1,
    replay_image: &[u8],
    reservation_recovery_deadline: u64,
) -> StoreResult<bool> {
    Ok(record.quote_id == reservation.quote_id
        && record.creation_idempotency_digest
            == creation_idempotency_digest(store, &intent.idempotency_key)
        && record.backend_label == store.backend_label_for_quote(&reservation.quote_id)?
        && record.intent_digest == intent.request_digest().map_err(StoreError::Protocol)?
        && record.intent_replay_image == replay_image
        && record.payee_pubkey == delegation.expected_payee_pubkey
        && record.delegation_epoch == delegation.key_epoch
        && record.delegation_digest
            == delegation
                .delegation_digest()
                .map_err(StoreError::Protocol)?
        && record.exact_delegation == reservation.exact_delegation
        && record.exact_amount_msat == intent.exact_amount_msat
        && record.invoice_created_not_before == reservation.invoice_created_not_before
        && record.invoice_created_not_after == reservation.invoice_created_not_after
        && record.reservation_recovery_deadline == reservation_recovery_deadline)
}

fn validate_delegation_input(
    store: &IssuerStore,
    input: &DelegationAdvance,
    require_current: bool,
) -> StoreResult<()> {
    if is_zero(&input.payee_pubkey)
        || input.delegation_epoch == 0
        || is_zero(&input.delegation_digest)
        || input.exact_delegation.is_empty()
        || input.exact_delegation.len() > MAX_EXACT_DELEGATION_BYTES
        || input.now_unix == 0
    {
        return Err(StoreError::InvalidInput("invalid quote-key delegation"));
    }
    let delegation = Bolt11QuoteKeyDelegationV1::decode(&input.exact_delegation)
        .map_err(|_| StoreError::InvalidInput("delegation is not canonical V1"))?;
    if delegation.encode().ok().as_deref() != Some(input.exact_delegation.as_slice())
        || delegation.issuer_id != store.handle.expected_issuer_id
        || delegation.network != store.handle.expected_network
        || delegation.expected_payee_pubkey != input.payee_pubkey
        || delegation.key_epoch != input.delegation_epoch
        || delegation.delegation_digest().ok() != Some(input.delegation_digest)
    {
        return Err(StoreError::InvalidInput(
            "delegation does not match issuer/network/payee/epoch/digest",
        ));
    }
    // This verifies the issuer-root signature at a time certainly within the
    // signed window. A new advancement additionally verifies currentness.
    delegation
        .verify_for(
            &store.handle.expected_issuer_id,
            store.handle.expected_network,
            &input.payee_pubkey,
            input.delegation_epoch,
            delegation.not_before,
        )
        .map_err(|_| StoreError::InvalidInput("delegation signature is invalid"))?;
    if require_current {
        delegation
            .verify_for(
                &store.handle.expected_issuer_id,
                store.handle.expected_network,
                &input.payee_pubkey,
                input.delegation_epoch,
                input.now_unix,
            )
            .map_err(|_| StoreError::InvalidInput("delegation is not currently valid"))?;
    }
    Ok(())
}

fn validate_quote_reservation(
    store: &IssuerStore,
    reservation: &QuoteReservation,
    require_current: bool,
) -> StoreResult<()> {
    if is_zero(&reservation.quote_id)
        || is_zero(&reservation.creation_idempotency_key)
        || is_zero(&reservation.intent_digest)
        || reservation.exact_intent.is_empty()
        || reservation.exact_intent.len() > MAX_EXACT_INTENT_BYTES
        || reservation.exact_amount_msat == 0
        || reservation.invoice_created_not_before == 0
        || reservation.invoice_created_not_after < reservation.invoice_created_not_before
    {
        return Err(StoreError::InvalidInput("invalid quote reservation"));
    }
    let _ = sql_integer(
        reservation.exact_amount_msat,
        "amount exceeds SQLite integer range",
    )?;
    let _ = sql_integer(
        reservation.invoice_created_not_before,
        "invoice creation lower bound exceeds SQLite integer range",
    )?;
    let _ = sql_integer(
        reservation.invoice_created_not_after,
        "invoice creation upper bound exceeds SQLite integer range",
    )?;
    let _ = parse_intent_for_reservation(store, reservation)?;
    validate_delegation_input(
        store,
        &DelegationAdvance {
            payee_pubkey: reservation.payee_pubkey,
            delegation_epoch: reservation.delegation_epoch,
            delegation_digest: reservation.delegation_digest,
            exact_delegation: reservation.exact_delegation.clone(),
            now_unix: reservation.now_unix,
        },
        require_current,
    )
}

fn quote_reservation_recovery_deadline(
    store: &IssuerStore,
    reservation: &QuoteReservation,
) -> StoreResult<u64> {
    let intent = parse_intent_for_reservation(store, reservation)?;
    let deadline = reservation
        .invoice_created_not_after
        .checked_add(u64::from(intent.invoice_expiry_seconds))
        .and_then(|value| value.checked_add(u64::from(intent.claim_window_seconds)))
        .ok_or(StoreError::InvalidInput(
            "quote reservation recovery horizon overflows Unix time",
        ))?;
    let _ = sql_integer(
        deadline,
        "quote reservation recovery horizon exceeds SQLite integer range",
    )?;
    Ok(deadline)
}

fn validate_quote_finalization(value: &QuoteFinalization) -> StoreResult<()> {
    if is_zero(&value.quote_id)
        || is_zero(&value.payment_hash)
        || value.invoice.is_empty()
        || value.invoice.len() > MAX_INVOICE_BYTES
        || !value
            .invoice
            .bytes()
            .all(|byte| (0x21..=0x7e).contains(&byte))
        || value.invoice_created_at == 0
        || value.invoice_created_at > value.invoice_expires_at
        || value.invoice_expires_at > value.claim_deadline
        || value.claim_deadline > value.credential_not_after
        || value.exact_signed_quote_response.is_empty()
        || value.exact_signed_quote_response.len() > MAX_SIGNED_QUOTE_BYTES
    {
        return Err(StoreError::InvalidInput("invalid quote finalization"));
    }
    for time in [
        value.invoice_created_at,
        value.invoice_expires_at,
        value.claim_deadline,
        value.credential_not_after,
    ] {
        let _ = sql_integer(time, "quote lifecycle time exceeds SQLite range")?;
    }
    Ok(())
}

fn validate_quote_expiry(value: &QuoteExpiry) -> StoreResult<()> {
    if is_zero(&value.quote_id)
        || value.observed_at == 0
        || value.exact_signed_quote_response.is_empty()
        || value.exact_signed_quote_response.len() > MAX_SIGNED_QUOTE_BYTES
    {
        return Err(StoreError::InvalidInput("invalid expiry observation"));
    }
    let _ = sql_integer(value.observed_at, "expiry observation exceeds SQLite range")?;
    Ok(())
}

fn validate_quote_settlement(value: &QuoteSettlement) -> StoreResult<()> {
    if is_zero(&value.quote_id)
        || value.settled_at == 0
        || value.observed_at < value.settled_at
        || value.settled_amount_msat == 0
        || is_zero(&value.settlement_evidence_digest)
        || value.exact_signed_quote_response.is_empty()
        || value.exact_signed_quote_response.len() > MAX_SIGNED_QUOTE_BYTES
    {
        return Err(StoreError::InvalidInput("invalid settlement observation"));
    }
    let _ = sql_integer(value.settled_at, "settlement time exceeds SQLite range")?;
    let _ = sql_integer(
        value.observed_at,
        "settlement observation exceeds SQLite range",
    )?;
    let _ = sql_integer(
        value.settled_amount_msat,
        "settled amount exceeds SQLite range",
    )?;
    Ok(())
}

fn validate_claim(store: &IssuerStore, value: &ClaimWrite) -> StoreResult<()> {
    if is_zero(&value.quote_id)
        || is_zero(&value.claim_idempotency_key)
        || is_zero(&value.claim_request_digest)
        || value.exact_claim_request.is_empty()
        || value.exact_claim_request.len() > MAX_EXACT_CLAIM_REQUEST_BYTES
        || value.exact_credential_request.is_empty()
        || value.exact_credential_request.len() > MAX_EXACT_CLAIM_REQUEST_BYTES
        || value.exact_claim_response.is_empty()
        || value.exact_claim_response.len() > MAX_EXACT_CLAIM_RESPONSE_BYTES
        || value.exact_signed_quote_response.is_empty()
        || value.exact_signed_quote_response.len() > MAX_SIGNED_QUOTE_BYTES
    {
        return Err(StoreError::InvalidInput("invalid claim write"));
    }
    let _ = parse_claim_for_write(store, value)?;
    Ok(())
}

fn parse_intent_for_reservation(
    store: &IssuerStore,
    value: &QuoteReservation,
) -> StoreResult<Bolt11QuoteIntentV1> {
    let intent = Bolt11QuoteIntentV1::decode(&value.exact_intent)
        .map_err(|_| StoreError::InvalidInput("quote intent is not canonical V1"))?;
    if intent.encode().ok().as_deref() != Some(value.exact_intent.as_slice())
        || intent.request_digest().ok() != Some(value.intent_digest)
        || intent.issuer_id != store.handle.expected_issuer_id
        || intent.network != store.handle.expected_network
        || intent.expected_payee_pubkey != value.payee_pubkey
        || intent.minimum_quote_key_epoch != value.delegation_epoch
        || intent.quote_delegation_digest != value.delegation_digest
        || intent.exact_amount_msat != value.exact_amount_msat
        || intent.idempotency_key != value.creation_idempotency_key
    {
        return Err(StoreError::InvalidInput(
            "quote intent does not match durable reservation fields",
        ));
    }
    Ok(intent)
}

fn intent_replay_image(store: &IssuerStore, value: &QuoteReservation) -> StoreResult<Vec<u8>> {
    let mut intent = parse_intent_for_reservation(store, value)?;
    intent.idempotency_key = creation_idempotency_digest(store, &value.creation_idempotency_key);
    intent
        .encode()
        .map_err(|_| StoreError::InvalidInput("failed to build intent replay image"))
}

fn parse_claim_for_write(
    store: &IssuerStore,
    value: &ClaimWrite,
) -> StoreResult<Bolt11QuoteClaimV1> {
    let claim = Bolt11QuoteClaimV1::decode(&value.exact_claim_request)
        .map_err(|_| StoreError::InvalidInput("claim is not canonical V1"))?;
    if claim.encode().ok().as_deref() != Some(value.exact_claim_request.as_slice())
        || claim.claim_request_digest().ok() != Some(value.claim_request_digest)
        || claim.issuer_id != store.handle.expected_issuer_id
        || claim.quote_id != value.quote_id
        || claim.idempotency_key != value.claim_idempotency_key
    {
        return Err(StoreError::InvalidInput(
            "claim does not match durable claim fields",
        ));
    }
    Ok(claim)
}

fn claim_replay_image(store: &IssuerStore, value: &ClaimWrite) -> StoreResult<Vec<u8>> {
    let mut claim = parse_claim_for_write(store, value)?;
    claim.idempotency_key = claim_idempotency_digest(store, &value.claim_idempotency_key);
    claim
        .encode()
        .map_err(|_| StoreError::InvalidInput("failed to build claim replay image"))
}

fn parse_bat_v2_claim_write(
    value: &BatV2ClaimWrite,
) -> StoreResult<(Bolt11BatV2ClaimEnvelopeV2, BatV2IssuanceResponseV2)> {
    if value.exact_claim_envelope.is_empty()
        || value.exact_claim_envelope.len() > MAX_EXACT_CLAIM_REQUEST_BYTES
        || value.exact_claim_response.is_empty()
        || value.exact_claim_response.len() > MAX_EXACT_CLAIM_RESPONSE_BYTES
        || value.exact_signed_quote_response.is_empty()
        || value.exact_signed_quote_response.len() > MAX_SIGNED_QUOTE_BYTES
    {
        return Err(StoreError::InvalidInput("invalid BAT V2 claim write"));
    }
    let envelope = Bolt11BatV2ClaimEnvelopeV2::decode(&value.exact_claim_envelope)
        .map_err(|_| StoreError::InvalidInput("claim envelope is not canonical BAT V2"))?;
    if envelope.encode().ok().as_deref() != Some(value.exact_claim_envelope.as_slice()) {
        return Err(StoreError::InvalidInput(
            "claim envelope is not canonical BAT V2",
        ));
    }
    let response = BatV2IssuanceResponseV2::decode(&value.exact_claim_response)
        .map_err(|_| StoreError::InvalidInput("claim response is not canonical BAT V2"))?;
    if response.encode().ok().as_deref() != Some(value.exact_claim_response.as_slice()) {
        return Err(StoreError::InvalidInput(
            "claim response is not canonical BAT V2",
        ));
    }
    Ok((envelope, response))
}

fn validate_bat_v2_envelope_for_quote(
    store: &IssuerStore,
    quote: &QuoteRecord,
    envelope: &Bolt11BatV2ClaimEnvelopeV2,
) -> StoreResult<()> {
    let original_intent_digest = envelope
        .quote_intent
        .request_digest()
        .map_err(|_| StoreError::ClaimProtocolMismatch)?;
    let mut replay_intent = envelope.quote_intent.clone();
    replay_intent.idempotency_key = quote.creation_idempotency_digest;
    let replay_image = replay_intent
        .encode()
        .map_err(|_| StoreError::ClaimProtocolMismatch)?;
    if envelope.quote_intent.issuer_id != store.handle.expected_issuer_id
        || envelope.quote_intent.network != store.handle.expected_network
        || envelope.claim.quote_id != quote.quote_id
        || envelope.claim.quote_request_digest != quote.intent_digest
        || original_intent_digest != quote.intent_digest
        || replay_image != quote.intent_replay_image
    {
        return Err(StoreError::ClaimProtocolMismatch);
    }
    Ok(())
}

fn bat_v2_claim_replay_image(
    store: &IssuerStore,
    envelope: &Bolt11BatV2ClaimEnvelopeV2,
) -> StoreResult<Vec<u8>> {
    let mut claim = envelope.claim.clone();
    claim.idempotency_key = claim_idempotency_digest(store, &claim.idempotency_key);
    claim
        .encode()
        .map_err(|_| StoreError::InvalidInput("failed to build BAT V2 claim replay image"))
}

fn bat_v2_claim_matches(
    record: &ClaimRecord,
    value: &BatV2ClaimWrite,
    quote_id: &[u8; 32],
    claim_request_digest: [u8; 32],
    claim_replay_image: &[u8],
    exact_credential_request: &[u8],
) -> bool {
    record.quote_id == *quote_id
        && record.claim_request_digest == claim_request_digest
        && record.claim_request_replay_image == claim_replay_image
        && record.exact_credential_request == exact_credential_request
        && record.exact_claim_response == value.exact_claim_response
        && record.exact_signed_quote_response == value.exact_signed_quote_response
}

struct ParsedIssuance {
    request: CredentialIssuanceRequestV1,
    response: CredentialIssuanceResponseV1,
    receipt_serials: Vec<ReceiptSerial>,
}

fn parse_and_bind_issuance(
    store: &IssuerStore,
    quote: &QuoteRecord,
    claim: &Bolt11QuoteClaimV1,
    value: &ClaimWrite,
    arc_canonicalizer: Option<&dyn ArcIssuanceCanonicalizerV1>,
) -> StoreResult<ParsedIssuance> {
    let intent = decode_replay_intent(store, quote)?;
    let request =
        CredentialIssuanceRequestV1::decode(&value.exact_credential_request, arc_canonicalizer)
            .map_err(|_| StoreError::ClaimProtocolMismatch)?;
    if request.encode().ok().as_deref() != Some(value.exact_credential_request.as_slice()) {
        return Err(StoreError::ClaimProtocolMismatch);
    }
    let response =
        CredentialIssuanceResponseV1::decode(&value.exact_claim_response, arc_canonicalizer)
            .map_err(|_| StoreError::ClaimProtocolMismatch)?;
    if response.encode().ok().as_deref() != Some(value.exact_claim_response.as_slice()) {
        return Err(StoreError::ClaimProtocolMismatch);
    }
    let request_digest = request
        .request_digest()
        .map_err(|_| StoreError::ClaimProtocolMismatch)?;
    if claim.issuer_id != store.handle.expected_issuer_id
        || claim.quote_id != quote.quote_id
        || claim.quote_request_digest != quote.intent_digest
        || claim.credential_request_digest != request_digest
        || claim.claim_pubkey_xonly != intent.claim_pubkey_xonly
        || request.issuer_id != store.handle.expected_issuer_id
        || request.quote_id != quote.quote_id
        || request.quote_request_digest != quote.intent_digest
        || request.authorization != intent.authorization
        || request.credential_binding_digest != intent.credential_binding_digest
        || request.credential_key_id != intent.credential_key_id
        || response.issuer_id != store.handle.expected_issuer_id
        || response.quote_id != quote.quote_id
        || response.quote_request_digest != quote.intent_digest
        || response.credential_request_digest != request_digest
        || response.authorization != intent.authorization
        || response.credential_binding_digest != intent.credential_binding_digest
        || response.credential_key_id != intent.credential_key_id
    {
        return Err(StoreError::ClaimProtocolMismatch);
    }

    let expected_count =
        usize::try_from(intent.credential_count).map_err(|_| StoreError::ClaimProtocolMismatch)?;
    if expected_count == 0 || expected_count > MAX_RECEIPT_SERIALS_PER_CLAIM {
        return Err(StoreError::ClaimProtocolMismatch);
    }
    let mut receipt_serials = Vec::new();
    match (&request.items, &response.items) {
        (
            CredentialIssuanceRequestItemsV1::DirectPaidReceipt,
            CredentialIssuanceResponseItemsV1::DirectPaidReceipts(receipts),
        ) if receipts.len() == expected_count => {
            let expected_key_id: [u8; 16] = intent
                .credential_key_id
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::ClaimProtocolMismatch)?;
            for receipt in receipts {
                if receipt.issuer_id != store.handle.expected_issuer_id
                    || receipt.key_id != expected_key_id
                    || receipt.binding.scope_id != intent.scope_id
                    || receipt.binding.offer_id != intent.offer_id
                    || receipt.binding.policy_digest != intent.policy_digest
                    || receipt.binding.entitlement_profile != intent.entitlement_profile
                    || receipt.not_before < quote.invoice_created_at.unwrap_or(0)
                    || receipt.not_before > quote.claim_deadline.unwrap_or(0)
                    || receipt.not_after != quote.credential_not_after.unwrap_or(0)
                {
                    return Err(StoreError::ClaimProtocolMismatch);
                }
                receipt_serials.push(ReceiptSerial {
                    key_id: receipt.key_id,
                    serial: receipt.serial,
                });
            }
        }
        (
            CredentialIssuanceRequestItemsV1::BitcoinPirCashuBat(requests),
            CredentialIssuanceResponseItemsV1::BitcoinPirCashuBat(responses),
        ) if requests.len() == expected_count && responses.len() == expected_count => {
            if requests
                .iter()
                .zip(responses)
                .any(|(request, response)| request.blinded_message != response.blinded_message)
            {
                return Err(StoreError::ClaimProtocolMismatch);
            }
        }
        (
            CredentialIssuanceRequestItemsV1::ArcExperimental(requests),
            CredentialIssuanceResponseItemsV1::ArcExperimental(responses),
        ) if requests.len() == expected_count && responses.len() == expected_count => {}
        _ => return Err(StoreError::ClaimProtocolMismatch),
    }

    receipt_serials.sort_unstable();
    if receipt_serials
        .windows(2)
        .any(|pair| pair[0].serial == pair[1].serial)
    {
        // The issuer-global serial namespace is intentionally stricter than
        // a receipt signing-key namespace.
        return Err(StoreError::ReceiptSerialConflict);
    }
    Ok(ParsedIssuance {
        request,
        response,
        receipt_serials,
    })
}

fn decode_replay_intent(
    store: &IssuerStore,
    quote: &QuoteRecord,
) -> StoreResult<Bolt11QuoteIntentV1> {
    let intent = Bolt11QuoteIntentV1::decode(&quote.intent_replay_image)
        .map_err(|_| StoreError::SignedQuoteMismatch)?;
    if intent.encode().ok().as_deref() != Some(quote.intent_replay_image.as_slice())
        || intent.issuer_id != store.handle.expected_issuer_id
        || intent.network != store.handle.expected_network
        || intent.expected_payee_pubkey != quote.payee_pubkey
        || intent.minimum_quote_key_epoch != quote.delegation_epoch
        || intent.quote_delegation_digest != quote.delegation_digest
        || intent.exact_amount_msat != quote.exact_amount_msat
        || intent.idempotency_key != quote.creation_idempotency_digest
    {
        return Err(StoreError::SignedQuoteMismatch);
    }
    Ok(intent)
}

fn decode_replay_bat_v2_intent(
    store: &IssuerStore,
    quote: &QuoteRecord,
) -> StoreResult<Bolt11BatV2QuoteIntentV2> {
    let intent = Bolt11BatV2QuoteIntentV2::decode(&quote.intent_replay_image)
        .map_err(|_| StoreError::SignedQuoteMismatch)?;
    if intent.encode().ok().as_deref() != Some(quote.intent_replay_image.as_slice())
        || intent.issuer_id != store.handle.expected_issuer_id
        || intent.network != store.handle.expected_network
        || intent.expected_payee_pubkey != quote.payee_pubkey
        || intent.minimum_quote_key_epoch != quote.delegation_epoch
        || intent.quote_delegation_digest != quote.delegation_digest
        || intent.exact_amount_msat != quote.exact_amount_msat
        || intent.idempotency_key != quote.creation_idempotency_digest
    {
        return Err(StoreError::SignedQuoteMismatch);
    }
    Ok(intent)
}

fn decode_and_verify_quote_snapshot_for_protocol(
    connection: &Connection,
    store: &IssuerStore,
    record: &QuoteRecord,
    exact: &[u8],
    quote_protocol: i64,
) -> StoreResult<Bolt11QuoteV1> {
    match quote_protocol {
        QUOTE_PROTOCOL_V1 => decode_and_verify_quote_snapshot(store, record, exact),
        QUOTE_PROTOCOL_BAT_V2 => {
            decode_and_verify_bat_v2_quote_snapshot(connection, store, record, exact)
        }
        _ => Err(StoreError::SchemaMismatch(
            "invalid quote protocol discriminator".to_owned(),
        )),
    }
}

fn decode_and_verify_bat_v2_quote_snapshot(
    connection: &Connection,
    store: &IssuerStore,
    record: &QuoteRecord,
    exact: &[u8],
) -> StoreResult<Bolt11QuoteV1> {
    if exact.is_empty() || exact.len() > MAX_SIGNED_QUOTE_BYTES || exact.len() < 64 {
        return Err(StoreError::SignedQuoteMismatch);
    }
    let snapshot = Bolt11QuoteV1::decode(exact).map_err(|_| StoreError::SignedQuoteMismatch)?;
    if snapshot.encode().ok().as_deref() != Some(exact) {
        return Err(StoreError::SignedQuoteMismatch);
    }
    let intent = decode_replay_bat_v2_intent(store, record)?;
    let class_record =
        read_bat_acceptance_class_v2(connection, store, &intent.class_id, intent.class_key_epoch)?
            .ok_or(StoreError::SignedQuoteMismatch)?;
    let class = BatAcceptanceClassV2::decode(&class_record.exact_artifact)
        .map_err(|_| StoreError::SignedQuoteMismatch)?;
    let delegation = Bolt11QuoteKeyDelegationV1::decode(&record.exact_delegation)
        .map_err(|_| StoreError::SignedQuoteMismatch)?;
    if delegation.encode().ok().as_deref() != Some(record.exact_delegation.as_slice())
        || delegation.delegation_digest().ok() != Some(record.delegation_digest)
        || delegation.issuer_id != store.handle.expected_issuer_id
        || delegation.network != store.handle.expected_network
        || delegation.expected_payee_pubkey != record.payee_pubkey
        || delegation.key_epoch != record.delegation_epoch
        || snapshot.invoice_created_at < record.invoice_created_not_before
        || snapshot.invoice_created_at > record.invoice_created_not_after
    {
        return Err(StoreError::SignedQuoteMismatch);
    }
    snapshot
        .verify_persisted_bat_v2_quote_for_store(
            PersistedBolt11BatV2QuoteExpectationV2 {
                original_request_digest: &record.intent_digest,
                replay_intent: &intent,
                class: &class,
                quote_id: &record.quote_id,
                invoice: record.invoice.as_deref().unwrap_or(&snapshot.invoice),
                invoice_created_at: record
                    .invoice_created_at
                    .unwrap_or(snapshot.invoice_created_at),
                invoice_expires_at: record
                    .invoice_expires_at
                    .unwrap_or(snapshot.invoice_expires_at),
                claim_deadline: record.claim_deadline.unwrap_or(snapshot.claim_deadline),
                credential_not_after: record
                    .credential_not_after
                    .unwrap_or(snapshot.credential_not_after),
            },
            &delegation,
            snapshot.status_updated_at,
        )
        .map_err(|_| StoreError::SignedQuoteMismatch)?;
    Ok(snapshot)
}

fn decode_and_verify_quote_snapshot(
    store: &IssuerStore,
    record: &QuoteRecord,
    exact: &[u8],
) -> StoreResult<Bolt11QuoteV1> {
    if exact.is_empty() || exact.len() > MAX_SIGNED_QUOTE_BYTES || exact.len() < 64 {
        return Err(StoreError::SignedQuoteMismatch);
    }
    let snapshot = Bolt11QuoteV1::decode(exact).map_err(|_| StoreError::SignedQuoteMismatch)?;
    if snapshot.encode().ok().as_deref() != Some(exact) {
        return Err(StoreError::SignedQuoteMismatch);
    }
    let intent = decode_replay_intent(store, record)?;
    let delegation = Bolt11QuoteKeyDelegationV1::decode(&record.exact_delegation)
        .map_err(|_| StoreError::SignedQuoteMismatch)?;
    if delegation.encode().ok().as_deref() != Some(record.exact_delegation.as_slice())
        || delegation.delegation_digest().ok() != Some(record.delegation_digest)
        || delegation.issuer_id != store.handle.expected_issuer_id
        || delegation.network != store.handle.expected_network
        || delegation.expected_payee_pubkey != record.payee_pubkey
        || delegation.key_epoch != record.delegation_epoch
        || snapshot.request_digest != record.intent_digest
        || snapshot.quote_id != record.quote_id
        || snapshot.quote_key_id != delegation.quote_key_id
        || snapshot.network != store.handle.expected_network
        || snapshot.payee_pubkey != record.payee_pubkey
        || snapshot.amount_msat != record.exact_amount_msat
        || snapshot.invoice_created_at < record.invoice_created_not_before
        || snapshot.invoice_created_at > record.invoice_created_not_after
    {
        return Err(StoreError::SignedQuoteMismatch);
    }
    let horizons = intent
        .derived_horizons(snapshot.invoice_created_at)
        .map_err(|_| StoreError::SignedQuoteMismatch)?;
    if snapshot.invoice_expires_at != horizons.invoice_expires_at
        || snapshot.claim_deadline != horizons.claim_deadline
        || snapshot.credential_not_after != horizons.credential_not_after
    {
        return Err(StoreError::SignedQuoteMismatch);
    }
    let verifying_key = delegation
        .verify_for(
            &store.handle.expected_issuer_id,
            store.handle.expected_network,
            &record.payee_pubkey,
            record.delegation_epoch,
            snapshot.invoice_created_at,
        )
        .map_err(|_| StoreError::SignedQuoteMismatch)?;
    delegation
        .verify_for(
            &store.handle.expected_issuer_id,
            store.handle.expected_network,
            &record.payee_pubkey,
            record.delegation_epoch,
            snapshot.status_updated_at,
        )
        .map_err(|_| StoreError::SignedQuoteMismatch)?;
    delegation
        .verify_for(
            &store.handle.expected_issuer_id,
            store.handle.expected_network,
            &record.payee_pubkey,
            record.delegation_epoch,
            snapshot.claim_deadline,
        )
        .map_err(|_| StoreError::SignedQuoteMismatch)?;
    let mut preimage = Vec::with_capacity(BOLT11_QUOTE_SIGNATURE_DOMAIN.len() + exact.len() - 64);
    preimage.extend_from_slice(BOLT11_QUOTE_SIGNATURE_DOMAIN);
    preimage.extend_from_slice(&exact[..exact.len() - 64]);
    verifying_key
        .verify_strict(&preimage, &Signature::from_bytes(&snapshot.signature))
        .map_err(|_| StoreError::SignedQuoteMismatch)?;
    Ok(snapshot)
}

fn verify_initial_snapshot(
    snapshot: &Bolt11QuoteV1,
    finalization: &QuoteFinalization,
) -> StoreResult<()> {
    if snapshot.status != Bolt11QuoteStatusV1::InvoiceOpen
        || snapshot.state_version != 1
        || snapshot.invoice != finalization.invoice
        || snapshot.invoice_created_at != finalization.invoice_created_at
        || snapshot.invoice_expires_at != finalization.invoice_expires_at
        || snapshot.claim_deadline != finalization.claim_deadline
        || snapshot.credential_not_after != finalization.credential_not_after
    {
        return Err(StoreError::SignedQuoteMismatch);
    }
    Ok(())
}

fn verify_successor_snapshot(
    previous: &Bolt11QuoteV1,
    next: &Bolt11QuoteV1,
    expected_status: Bolt11QuoteStatusV1,
    expected_version: u64,
    expected_observed_at: u64,
) -> StoreResult<()> {
    let successor_version = previous
        .state_version
        .checked_add(1)
        .ok_or(StoreError::SignedQuoteMismatch)?;
    if !quote_immutables_equal(previous, next)
        || next.status != expected_status
        || next.state_version != expected_version
        || next.state_version != successor_version
        || next.status_updated_at != expected_observed_at
        || next.status_updated_at <= previous.status_updated_at
        || !previous.status.allows_transition_to(next.status)
        || previous.status == next.status
    {
        return Err(StoreError::SignedQuoteMismatch);
    }
    Ok(())
}

fn quote_immutables_equal(left: &Bolt11QuoteV1, right: &Bolt11QuoteV1) -> bool {
    left.request_digest == right.request_digest
        && left.quote_id == right.quote_id
        && left.quote_key_id == right.quote_key_id
        && left.invoice == right.invoice
        && left.network == right.network
        && left.payee_pubkey == right.payee_pubkey
        && left.amount_msat == right.amount_msat
        && left.invoice_created_at == right.invoice_created_at
        && left.invoice_expires_at == right.invoice_expires_at
        && left.claim_deadline == right.claim_deadline
        && left.credential_not_after == right.credential_not_after
}

fn verify_persisted_quote_history(
    connection: &Connection,
    store: &IssuerStore,
    record: &QuoteRecord,
) -> StoreResult<Option<Bolt11QuoteV1>> {
    verify_persisted_quote_history_for_protocol(connection, store, record, QUOTE_PROTOCOL_V1)
}

fn verify_persisted_quote_history_for_protocol(
    connection: &Connection,
    store: &IssuerStore,
    record: &QuoteRecord,
    quote_protocol: i64,
) -> StoreResult<Option<Bolt11QuoteV1>> {
    if record.state == QuoteState::Reserved {
        return if record.state_version == 0 && record.initial_signed_quote_response.is_none() {
            Ok(None)
        } else {
            Err(StoreError::SignedQuoteMismatch)
        };
    }
    let initial_exact = record
        .initial_signed_quote_response
        .as_deref()
        .ok_or(StoreError::SignedQuoteMismatch)?;
    let initial = decode_and_verify_quote_snapshot_for_protocol(
        connection,
        store,
        record,
        initial_exact,
        quote_protocol,
    )?;
    let persisted_finalization = QuoteFinalization {
        quote_id: record.quote_id,
        invoice: record
            .invoice
            .clone()
            .ok_or(StoreError::SignedQuoteMismatch)?,
        payment_hash: record.payment_hash.ok_or(StoreError::SignedQuoteMismatch)?,
        invoice_created_at: record
            .invoice_created_at
            .ok_or(StoreError::SignedQuoteMismatch)?,
        invoice_expires_at: record
            .invoice_expires_at
            .ok_or(StoreError::SignedQuoteMismatch)?,
        claim_deadline: record
            .claim_deadline
            .ok_or(StoreError::SignedQuoteMismatch)?,
        credential_not_after: record
            .credential_not_after
            .ok_or(StoreError::SignedQuoteMismatch)?,
        exact_signed_quote_response: initial_exact.to_vec(),
    };
    verify_initial_snapshot(&initial, &persisted_finalization)?;
    let mut latest = initial;

    if let Some(exact) = record.expired_signed_quote_response.as_deref() {
        let expired = decode_and_verify_quote_snapshot_for_protocol(
            connection,
            store,
            record,
            exact,
            quote_protocol,
        )?;
        verify_successor_snapshot(
            &latest,
            &expired,
            Bolt11QuoteStatusV1::InvoiceExpiredPendingReconcile,
            2,
            record
                .expiry_observed_at
                .ok_or(StoreError::SignedQuoteMismatch)?,
        )?;
        latest = expired;
    }
    if let Some(exact) = record.settled_signed_quote_response.as_deref() {
        let settled = decode_and_verify_quote_snapshot_for_protocol(
            connection,
            store,
            record,
            exact,
            quote_protocol,
        )?;
        let expected_status = if record.expiry_commit.is_some() {
            Bolt11QuoteStatusV1::LateSettledReconcile
        } else {
            Bolt11QuoteStatusV1::PaymentSettled
        };
        verify_successor_snapshot(
            &latest,
            &settled,
            expected_status,
            latest
                .state_version
                .checked_add(1)
                .ok_or(StoreError::SignedQuoteMismatch)?,
            record
                .settlement_observed_at
                .ok_or(StoreError::SignedQuoteMismatch)?,
        )?;
        latest = settled;
    }
    if record.state == QuoteState::CredentialClaimed {
        let claim = read_claim_where(
            connection,
            store,
            "quote_id",
            &record.quote_id,
            quote_protocol,
        )?
        .ok_or(StoreError::SignedQuoteMismatch)?;
        let claimed = decode_and_verify_quote_snapshot_for_protocol(
            connection,
            store,
            record,
            &claim.exact_signed_quote_response,
            quote_protocol,
        )?;
        verify_successor_snapshot(
            &latest,
            &claimed,
            Bolt11QuoteStatusV1::CredentialClaimed,
            record.state_version,
            claim.claimed_at,
        )?;
        latest = claimed;
    }
    if latest.state_version != record.state_version
        || match record.state {
            QuoteState::InvoiceOpen => latest.status != Bolt11QuoteStatusV1::InvoiceOpen,
            QuoteState::PaymentSettled => latest.status != Bolt11QuoteStatusV1::PaymentSettled,
            QuoteState::CredentialClaimed => {
                latest.status != Bolt11QuoteStatusV1::CredentialClaimed
            }
            QuoteState::InvoiceExpiredPendingReconcile => {
                latest.status != Bolt11QuoteStatusV1::InvoiceExpiredPendingReconcile
            }
            QuoteState::LateSettledReconcile => {
                latest.status != Bolt11QuoteStatusV1::LateSettledReconcile
            }
            QuoteState::Reserved => true,
        }
    {
        return Err(StoreError::SignedQuoteMismatch);
    }
    Ok(Some(latest))
}

pub(crate) fn verify_all_quote_histories(
    store: &IssuerStore,
    connection: &Connection,
) -> StoreResult<()> {
    let mut statement =
        connection.prepare("SELECT quote_id, quote_protocol FROM quotes ORDER BY quote_id")?;
    let quote_ids = statement
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (raw_quote_id, quote_protocol) in quote_ids {
        let quote_id = fixed_blob(raw_quote_id, "invalid quote id")?;
        let quote = read_quote_for_protocol(connection, store, &quote_id, quote_protocol)?
            .ok_or_else(|| StoreError::SchemaMismatch("enumerated quote is missing".to_owned()))?;
        let _ =
            verify_persisted_quote_history_for_protocol(connection, store, &quote, quote_protocol)?;
    }
    Ok(())
}

fn compare_delegation(
    existing: &DelegationHead,
    input: &DelegationAdvance,
) -> StoreResult<HeadDecision> {
    if input.delegation_epoch < existing.highest_epoch {
        return Err(StoreError::DelegationRollback);
    }
    if input.delegation_epoch == existing.highest_epoch {
        if input.delegation_digest == existing.delegation_digest
            && input.exact_delegation == existing.exact_delegation
        {
            return Ok(HeadDecision::Exact);
        }
        return Err(StoreError::DelegationFork);
    }
    Ok(HeadDecision::Advance)
}

fn write_delegation_head(
    transaction: &Transaction<'_>,
    store: &IssuerStore,
    input: &DelegationAdvance,
    sequence: u64,
) -> StoreResult<()> {
    transaction.execute(
        "INSERT INTO quote_delegation_heads (issuer_id, network, payee_pubkey, highest_epoch, \
         delegation_digest, exact_delegation, commit_seq) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
         ON CONFLICT(issuer_id, network, payee_pubkey) DO UPDATE SET \
         highest_epoch = excluded.highest_epoch, delegation_digest = excluded.delegation_digest, \
         exact_delegation = excluded.exact_delegation, commit_seq = excluded.commit_seq",
        params![
            store.handle.expected_issuer_id.as_slice(),
            network_code(store.handle.expected_network),
            input.payee_pubkey.as_slice(),
            sql_integer(
                input.delegation_epoch,
                "delegation epoch exceeds SQLite range"
            )?,
            input.delegation_digest.as_slice(),
            input.exact_delegation.as_slice(),
            sql_integer(sequence, "commit sequence exceeds SQLite range")?,
        ],
    )?;
    Ok(())
}

fn read_delegation_head(
    connection: &Connection,
    store: &IssuerStore,
    payee_pubkey: &[u8; 33],
) -> StoreResult<Option<DelegationHead>> {
    type Raw = (i64, Vec<u8>, Vec<u8>, i64);
    let raw: Option<Raw> = connection
        .query_row(
            "SELECT highest_epoch, delegation_digest, exact_delegation, commit_seq \
             FROM quote_delegation_heads WHERE issuer_id = ?1 AND network = ?2 AND payee_pubkey = ?3",
            params![
                store.handle.expected_issuer_id.as_slice(),
                network_code(store.handle.expected_network),
                payee_pubkey.as_slice(),
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    raw.map(|raw| {
        if raw.2.is_empty() || raw.2.len() > MAX_EXACT_DELEGATION_BYTES {
            return Err(StoreError::SchemaMismatch(
                "invalid exact delegation length".to_owned(),
            ));
        }
        let digest = fixed_blob(raw.1, "invalid delegation digest")?;
        if is_zero(&digest) {
            return Err(StoreError::SchemaMismatch(
                "delegation digest is all zero".to_owned(),
            ));
        }
        Ok(DelegationHead {
            payee_pubkey: *payee_pubkey,
            highest_epoch: db_u64(raw.0, "negative delegation epoch")?,
            delegation_digest: digest,
            exact_delegation: raw.2,
            commit: marker(store, db_u64(raw.3, "negative delegation commit")?),
        })
    })
    .transpose()
}

fn quote_reservation_matches(
    store: &IssuerStore,
    record: &QuoteRecord,
    value: &QuoteReservation,
) -> StoreResult<bool> {
    Ok(record.quote_id == value.quote_id
        && record.creation_idempotency_digest
            == creation_idempotency_digest(store, &value.creation_idempotency_key)
        && record.backend_label == store.backend_label_for_quote(&value.quote_id)?
        && record.intent_digest == value.intent_digest
        && record.intent_replay_image == intent_replay_image(store, value)?
        && record.payee_pubkey == value.payee_pubkey
        && record.delegation_epoch == value.delegation_epoch
        && record.delegation_digest == value.delegation_digest
        && record.exact_delegation == value.exact_delegation
        && record.exact_amount_msat == value.exact_amount_msat
        && record.invoice_created_not_before == value.invoice_created_not_before
        && record.invoice_created_not_after == value.invoice_created_not_after
        && record.reservation_recovery_deadline
            == quote_reservation_recovery_deadline(store, value)?)
}

fn quote_finalization_matches(record: &QuoteRecord, value: &QuoteFinalization) -> bool {
    record.quote_id == value.quote_id
        && record.invoice.as_deref() == Some(value.invoice.as_str())
        && record.payment_hash == Some(value.payment_hash)
        && record.invoice_created_at == Some(value.invoice_created_at)
        && record.invoice_expires_at == Some(value.invoice_expires_at)
        && record.claim_deadline == Some(value.claim_deadline)
        && record.credential_not_after == Some(value.credential_not_after)
        && record.initial_signed_quote_response.as_deref()
            == Some(value.exact_signed_quote_response.as_slice())
}

fn quote_settlement_matches(record: &QuoteRecord, value: &QuoteSettlement) -> bool {
    record.quote_id == value.quote_id
        && record.settled_at == Some(value.settled_at)
        && record.settlement_observed_at == Some(value.observed_at)
        && record.settled_amount_msat == Some(value.settled_amount_msat)
        && record.settlement_evidence_digest == Some(value.settlement_evidence_digest)
        && record.settled_signed_quote_response.as_deref()
            == Some(value.exact_signed_quote_response.as_slice())
}

fn claim_matches(
    store: &IssuerStore,
    record: &ClaimRecord,
    value: &ClaimWrite,
) -> StoreResult<bool> {
    Ok(record.quote_id == value.quote_id
        && record.claim_idempotency_digest
            == claim_idempotency_digest(store, &value.claim_idempotency_key)
        && record.claim_request_digest == value.claim_request_digest
        && record.claim_request_replay_image == claim_replay_image(store, value)?
        && record.exact_credential_request == value.exact_credential_request
        && record.exact_claim_response == value.exact_claim_response
        && record.exact_signed_quote_response == value.exact_signed_quote_response)
}

struct RawQuote {
    quote_id: Vec<u8>,
    creation_key: Vec<u8>,
    backend_label: String,
    intent_digest: Vec<u8>,
    intent_replay_image: Vec<u8>,
    payee: Vec<u8>,
    delegation_epoch: i64,
    delegation_digest: Vec<u8>,
    exact_delegation: Vec<u8>,
    amount: i64,
    invoice_created_not_before: i64,
    invoice_created_not_after: i64,
    reservation_recovery_deadline: i64,
    state: i64,
    state_version: i64,
    invoice: Option<String>,
    payment_hash: Option<Vec<u8>>,
    invoice_created_at: Option<i64>,
    invoice_expires_at: Option<i64>,
    claim_deadline: Option<i64>,
    credential_not_after: Option<i64>,
    initial_response: Option<Vec<u8>>,
    expiry_observed_at: Option<i64>,
    expired_response: Option<Vec<u8>>,
    settled_at: Option<i64>,
    settlement_observed_at: Option<i64>,
    settled_amount: Option<i64>,
    evidence: Option<Vec<u8>>,
    settled_response: Option<Vec<u8>>,
    reservation_seq: i64,
    finalization_seq: Option<i64>,
    expiry_seq: Option<i64>,
    settlement_seq: Option<i64>,
    quote_protocol: i64,
}

fn raw_quote(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawQuote> {
    Ok(RawQuote {
        quote_id: row.get(0)?,
        creation_key: row.get(1)?,
        backend_label: row.get(2)?,
        intent_digest: row.get(3)?,
        intent_replay_image: row.get(4)?,
        payee: row.get(5)?,
        delegation_epoch: row.get(6)?,
        delegation_digest: row.get(7)?,
        exact_delegation: row.get(8)?,
        amount: row.get(9)?,
        invoice_created_not_before: row.get(10)?,
        invoice_created_not_after: row.get(11)?,
        reservation_recovery_deadline: row.get(12)?,
        state: row.get(13)?,
        state_version: row.get(14)?,
        invoice: row.get(15)?,
        payment_hash: row.get(16)?,
        invoice_created_at: row.get(17)?,
        invoice_expires_at: row.get(18)?,
        claim_deadline: row.get(19)?,
        credential_not_after: row.get(20)?,
        initial_response: row.get(21)?,
        expiry_observed_at: row.get(22)?,
        expired_response: row.get(23)?,
        settled_at: row.get(24)?,
        settlement_observed_at: row.get(25)?,
        settled_amount: row.get(26)?,
        evidence: row.get(27)?,
        settled_response: row.get(28)?,
        reservation_seq: row.get(29)?,
        finalization_seq: row.get(30)?,
        expiry_seq: row.get(31)?,
        settlement_seq: row.get(32)?,
        quote_protocol: row.get(33)?,
    })
}

fn read_quote(
    connection: &Connection,
    store: &IssuerStore,
    quote_id: &[u8; 32],
) -> StoreResult<Option<QuoteRecord>> {
    read_quote_for_protocol(connection, store, quote_id, QUOTE_PROTOCOL_V1)
}

fn read_quote_for_protocol(
    connection: &Connection,
    store: &IssuerStore,
    quote_id: &[u8; 32],
    expected_protocol: i64,
) -> StoreResult<Option<QuoteRecord>> {
    let sql = format!("SELECT {QUOTE_SELECT} FROM quotes WHERE quote_id = ?1");
    let raw = connection
        .query_row(&sql, [quote_id.as_slice()], raw_quote)
        .optional()?;
    raw.map(|raw| convert_quote(store, raw, expected_protocol))
        .transpose()
}

fn read_committed_quote_for_protocol(
    store: &IssuerStore,
    quote_id: &[u8; 32],
    quote_protocol: i64,
) -> StoreResult<Option<QuoteRecord>> {
    let connection = store.open_checked(false)?;
    let value = read_quote_for_protocol(&connection, store, quote_id, quote_protocol)?;
    store.confirm_anchored_read(&connection, value)
}

fn read_quote_by_creation_digest(
    connection: &Connection,
    store: &IssuerStore,
    key: &[u8; 32],
) -> StoreResult<Option<QuoteRecord>> {
    read_quote_by_creation_digest_for_protocol(connection, store, key, QUOTE_PROTOCOL_V1)
}

fn read_quote_by_creation_digest_for_protocol(
    connection: &Connection,
    store: &IssuerStore,
    key: &[u8; 32],
    expected_protocol: i64,
) -> StoreResult<Option<QuoteRecord>> {
    let sql = format!("SELECT {QUOTE_SELECT} FROM quotes WHERE creation_idempotency_digest = ?1");
    let raw = connection
        .query_row(&sql, [key.as_slice()], raw_quote)
        .optional()?;
    raw.map(|raw| convert_quote(store, raw, expected_protocol))
        .transpose()
}

fn read_quote_by_label(
    connection: &Connection,
    store: &IssuerStore,
    label: &str,
) -> StoreResult<Option<QuoteRecord>> {
    read_quote_by_label_for_protocol(connection, store, label, QUOTE_PROTOCOL_V1)
}

fn read_quote_by_label_for_protocol(
    connection: &Connection,
    store: &IssuerStore,
    label: &str,
    expected_protocol: i64,
) -> StoreResult<Option<QuoteRecord>> {
    let sql = format!("SELECT {QUOTE_SELECT} FROM quotes WHERE backend_label = ?1");
    let raw = connection.query_row(&sql, [label], raw_quote).optional()?;
    raw.map(|raw| convert_quote(store, raw, expected_protocol))
        .transpose()
}

fn convert_quote(
    store: &IssuerStore,
    raw: RawQuote,
    expected_protocol: i64,
) -> StoreResult<QuoteRecord> {
    if raw.quote_protocol != expected_protocol {
        return Err(StoreError::QuoteProtocolMismatch);
    }
    let quote_id = fixed_blob(raw.quote_id, "invalid quote id")?;
    let creation_idempotency_digest = fixed_blob(raw.creation_key, "invalid creation digest")?;
    let intent_digest = fixed_blob(raw.intent_digest, "invalid intent digest")?;
    let payee_pubkey = fixed_blob(raw.payee, "invalid payee public key")?;
    let delegation_digest = fixed_blob(raw.delegation_digest, "invalid delegation digest")?;
    let invoice_created_not_after = db_u64(
        raw.invoice_created_not_after,
        "negative invoice creation upper bound",
    )?;
    let reservation_recovery_deadline = db_u64(
        raw.reservation_recovery_deadline,
        "negative reservation recovery deadline",
    )?;
    let (invoice_expiry_seconds, claim_window_seconds) = match expected_protocol {
        QUOTE_PROTOCOL_V1 => {
            let intent = Bolt11QuoteIntentV1::decode(&raw.intent_replay_image).map_err(|_| {
                StoreError::SchemaMismatch("invalid persisted V1 quote intent".to_owned())
            })?;
            (intent.invoice_expiry_seconds, intent.claim_window_seconds)
        }
        QUOTE_PROTOCOL_BAT_V2 => {
            let intent =
                Bolt11BatV2QuoteIntentV2::decode(&raw.intent_replay_image).map_err(|_| {
                    StoreError::SchemaMismatch("invalid persisted BAT V2 quote intent".to_owned())
                })?;
            (intent.invoice_expiry_seconds, intent.claim_window_seconds)
        }
        _ => {
            return Err(StoreError::SchemaMismatch(
                "invalid quote protocol discriminator".to_owned(),
            ))
        }
    };
    let expected_recovery_deadline = invoice_created_not_after
        .checked_add(u64::from(invoice_expiry_seconds))
        .and_then(|value| value.checked_add(u64::from(claim_window_seconds)))
        .ok_or_else(|| {
            StoreError::SchemaMismatch(
                "persisted quote reservation recovery horizon overflows".to_owned(),
            )
        })?;
    if is_zero(&quote_id)
        || is_zero(&creation_idempotency_digest)
        || is_zero(&intent_digest)
        || is_zero(&delegation_digest)
        || raw.intent_replay_image.is_empty()
        || raw.intent_replay_image.len() > MAX_EXACT_INTENT_BYTES
        || raw.exact_delegation.is_empty()
        || raw.exact_delegation.len() > MAX_EXACT_DELEGATION_BYTES
        || raw.invoice_created_not_before <= 0
        || raw.invoice_created_not_after < raw.invoice_created_not_before
        || reservation_recovery_deadline != expected_recovery_deadline
        || raw.backend_label != store.backend_label_for_quote(&quote_id)?
    {
        return Err(StoreError::SchemaMismatch(
            "invalid persisted quote reservation".to_owned(),
        ));
    }
    Ok(QuoteRecord {
        quote_id,
        creation_idempotency_digest,
        backend_label: raw.backend_label,
        intent_digest,
        intent_replay_image: raw.intent_replay_image,
        payee_pubkey,
        delegation_epoch: db_u64(raw.delegation_epoch, "negative delegation epoch")?,
        delegation_digest,
        exact_delegation: raw.exact_delegation,
        exact_amount_msat: db_u64(raw.amount, "negative quote amount")?,
        invoice_created_not_before: db_u64(
            raw.invoice_created_not_before,
            "negative invoice creation lower bound",
        )?,
        invoice_created_not_after,
        reservation_recovery_deadline,
        state: QuoteState::from_db(raw.state)
            .ok_or_else(|| StoreError::SchemaMismatch("invalid quote state".to_owned()))?,
        state_version: db_u64(raw.state_version, "negative quote state version")?,
        invoice: raw.invoice,
        payment_hash: optional_fixed_blob(raw.payment_hash, "invalid payment hash")?,
        invoice_created_at: raw
            .invoice_created_at
            .map(|value| db_u64(value, "negative invoice creation time"))
            .transpose()?,
        invoice_expires_at: raw
            .invoice_expires_at
            .map(|value| db_u64(value, "negative invoice expiry"))
            .transpose()?,
        claim_deadline: raw
            .claim_deadline
            .map(|value| db_u64(value, "negative claim deadline"))
            .transpose()?,
        credential_not_after: raw
            .credential_not_after
            .map(|value| db_u64(value, "negative credential expiry"))
            .transpose()?,
        initial_signed_quote_response: raw.initial_response,
        expiry_observed_at: raw
            .expiry_observed_at
            .map(|value| db_u64(value, "negative expiry observation"))
            .transpose()?,
        expired_signed_quote_response: raw.expired_response,
        settled_at: raw
            .settled_at
            .map(|value| db_u64(value, "negative settlement time"))
            .transpose()?,
        settlement_observed_at: raw
            .settlement_observed_at
            .map(|value| db_u64(value, "negative settlement observation time"))
            .transpose()?,
        settled_amount_msat: raw
            .settled_amount
            .map(|value| db_u64(value, "negative settled amount"))
            .transpose()?,
        settlement_evidence_digest: optional_fixed_blob(
            raw.evidence,
            "invalid settlement evidence digest",
        )?,
        settled_signed_quote_response: raw.settled_response,
        reservation_commit: marker(
            store,
            db_u64(raw.reservation_seq, "negative reservation commit")?,
        ),
        finalization_commit: raw
            .finalization_seq
            .map(|value| db_u64(value, "negative finalization commit"))
            .transpose()?
            .map(|sequence| marker(store, sequence)),
        expiry_commit: raw
            .expiry_seq
            .map(|value| db_u64(value, "negative expiry commit"))
            .transpose()?
            .map(|sequence| marker(store, sequence)),
        settlement_commit: raw
            .settlement_seq
            .map(|value| db_u64(value, "negative settlement commit"))
            .transpose()?
            .map(|sequence| marker(store, sequence)),
    })
}

fn read_claim(
    connection: &Connection,
    store: &IssuerStore,
    quote_id: &[u8; 32],
) -> StoreResult<Option<ClaimRecord>> {
    read_claim_where(connection, store, "quote_id", quote_id, QUOTE_PROTOCOL_V1)
}

fn read_claim_by_idempotency_digest(
    connection: &Connection,
    store: &IssuerStore,
    key: &[u8; 32],
) -> StoreResult<Option<ClaimRecord>> {
    read_claim_where(
        connection,
        store,
        "claim_idempotency_digest",
        key,
        QUOTE_PROTOCOL_V1,
    )
}

fn read_claim_where(
    connection: &Connection,
    store: &IssuerStore,
    column: &'static str,
    value: &[u8; 32],
    expected_protocol: i64,
) -> StoreResult<Option<ClaimRecord>> {
    type Raw = (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
        i64,
        i64,
    );
    let sql = format!(
        "SELECT c.quote_id, c.claim_idempotency_digest, c.claim_request_digest, \
         c.claim_request_replay_image, c.exact_credential_request, c.exact_claim_response, \
         c.exact_signed_quote_response, c.claimed_at, c.claim_commit_seq, q.quote_protocol \
         FROM claims c JOIN quotes q ON q.quote_id = c.quote_id WHERE c.{column} = ?1"
    );
    let raw: Option<Raw> = connection
        .query_row(&sql, [value.as_slice()], |row| {
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
            ))
        })
        .optional()?;
    raw.map(|raw| {
        if raw.9 != expected_protocol {
            return Err(StoreError::QuoteProtocolMismatch);
        }
        let quote_id = fixed_blob(raw.0, "invalid claim quote id")?;
        let claim_idempotency_digest = fixed_blob(raw.1, "invalid claim idempotency digest")?;
        let claim_request_digest = fixed_blob(raw.2, "invalid claim request digest")?;
        if is_zero(&quote_id)
            || is_zero(&claim_idempotency_digest)
            || is_zero(&claim_request_digest)
            || raw.3.is_empty()
            || raw.3.len() > MAX_EXACT_CLAIM_REQUEST_BYTES
            || raw.4.is_empty()
            || raw.4.len() > MAX_EXACT_CLAIM_REQUEST_BYTES
            || raw.5.is_empty()
            || raw.5.len() > MAX_EXACT_CLAIM_RESPONSE_BYTES
            || raw.6.is_empty()
            || raw.6.len() > MAX_SIGNED_QUOTE_BYTES
        {
            return Err(StoreError::SchemaMismatch(
                "invalid persisted claim".to_owned(),
            ));
        }
        let mut statement = connection.prepare(
            "SELECT key_id, serial FROM receipt_serials WHERE quote_id = ?1 \
             ORDER BY key_id, serial",
        )?;
        let receipt_serials = statement
            .query_map([quote_id.as_slice()], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?
            .map(|row| {
                let (key_id, serial) = row?;
                Ok(ReceiptSerial {
                    key_id: fixed_blob(key_id, "invalid receipt key id")?,
                    serial: fixed_blob(serial, "invalid receipt serial")?,
                })
            })
            .collect::<StoreResult<Vec<_>>>()?;
        Ok(ClaimRecord {
            quote_id,
            claim_idempotency_digest,
            claim_request_digest,
            claim_request_replay_image: raw.3,
            exact_credential_request: raw.4,
            exact_claim_response: raw.5,
            exact_signed_quote_response: raw.6,
            claimed_at: db_u64(raw.7, "negative claim time")?,
            receipt_serials,
            claim_commit: marker(store, db_u64(raw.8, "negative claim commit")?),
        })
    })
    .transpose()
}

fn marker(store: &IssuerStore, sequence: u64) -> CommitMarker {
    CommitMarker {
        store_instance_id: store.handle.expected_store_instance_id,
        commit_seq: sequence,
    }
}

fn creation_idempotency_digest(store: &IssuerStore, raw_key: &[u8; 32]) -> [u8; 32] {
    idempotency_digest(QUOTE_CREATE_IDEMPOTENCY_DIGEST_DOMAIN_V1, store, raw_key)
}

fn claim_idempotency_digest(store: &IssuerStore, raw_key: &[u8; 32]) -> [u8; 32] {
    idempotency_digest(QUOTE_CLAIM_IDEMPOTENCY_DIGEST_DOMAIN_V1, store, raw_key)
}

fn idempotency_digest(domain: &[u8], store: &IssuerStore, raw_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(store.handle.expected_issuer_id);
    hasher.update([store.handle.expected_network as u8]);
    hasher.update(raw_key);
    hasher.finalize().into()
}

fn verify_status_request_binding(
    store: &IssuerStore,
    request: &Bolt11QuoteStatusRequestV1,
    quote: &QuoteRecord,
    now_unix: u64,
    verifier: &dyn QuoteStatusBip340Verifier,
) -> StoreResult<()> {
    let replay_intent = Bolt11QuoteIntentV1::decode(&quote.intent_replay_image).map_err(|_| {
        StoreError::SchemaMismatch("persisted intent replay image is invalid".to_owned())
    })?;
    if request.issuer_id != store.handle.expected_issuer_id
        || request.quote_id != quote.quote_id
        || request.quote_request_digest != quote.intent_digest
        || request.claim_pubkey_xonly != replay_intent.claim_pubkey_xonly
    {
        return Err(StoreError::StatusRequestBindingMismatch);
    }
    if request.requested_at > now_unix
        || now_unix.saturating_sub(request.requested_at)
            > MAX_BOLT11_QUOTE_STATUS_REQUEST_AGE_SECONDS_V1
    {
        return Err(StoreError::StatusRequestStale);
    }
    let message_digest = request
        .bip340_signing_digest()
        .map_err(|_| StoreError::InvalidInput("status request is invalid"))?;
    if !verifier.verify(QuoteStatusBip340Input {
        claim_pubkey_xonly: &request.claim_pubkey_xonly,
        message_digest: &message_digest,
        signature: &request.signature,
    }) {
        return Err(StoreError::BadStatusRequestSignature);
    }
    Ok(())
}

fn verify_status_request_binding_for_protocol(
    connection: &Connection,
    store: &IssuerStore,
    request: &Bolt11QuoteStatusRequestV1,
    quote: &QuoteRecord,
    now_unix: u64,
    verifier: &dyn QuoteStatusBip340Verifier,
    quote_protocol: i64,
) -> StoreResult<()> {
    if quote_protocol == QUOTE_PROTOCOL_V1 {
        return verify_status_request_binding(store, request, quote, now_unix, verifier);
    }
    if quote_protocol != QUOTE_PROTOCOL_BAT_V2 {
        return Err(StoreError::SchemaMismatch(
            "invalid quote protocol discriminator".to_owned(),
        ));
    }

    let latest = verify_persisted_quote_history_for_protocol(
        connection,
        store,
        quote,
        QUOTE_PROTOCOL_BAT_V2,
    )?
    .ok_or(StoreError::InvalidQuoteState)?;
    let replay_intent = decode_replay_bat_v2_intent(store, quote)?;
    let class_record = read_bat_acceptance_class_v2(
        connection,
        store,
        &replay_intent.class_id,
        replay_intent.class_key_epoch,
    )?
    .ok_or_else(|| {
        StoreError::SchemaMismatch(
            "BAT V2 quote status references a missing retained class epoch".to_owned(),
        )
    })?;
    let class = BatAcceptanceClassV2::decode(&class_record.exact_artifact)
        .map_err(|_| StoreError::SignedQuoteMismatch)?;
    let delegation = Bolt11QuoteKeyDelegationV1::decode(&quote.exact_delegation)
        .map_err(|_| StoreError::SignedQuoteMismatch)?;
    if request.requested_at > now_unix
        || now_unix.saturating_sub(request.requested_at)
            > MAX_BOLT11_QUOTE_STATUS_REQUEST_AGE_SECONDS_V1
    {
        return Err(StoreError::StatusRequestStale);
    }
    let verified_quote = latest
        .verify_persisted_bat_v2_quote_for_store(
            PersistedBolt11BatV2QuoteExpectationV2 {
                original_request_digest: &quote.intent_digest,
                replay_intent: &replay_intent,
                class: &class,
                quote_id: &quote.quote_id,
                invoice: quote
                    .invoice
                    .as_deref()
                    .ok_or(StoreError::SignedQuoteMismatch)?,
                invoice_created_at: quote
                    .invoice_created_at
                    .ok_or(StoreError::SignedQuoteMismatch)?,
                invoice_expires_at: quote
                    .invoice_expires_at
                    .ok_or(StoreError::SignedQuoteMismatch)?,
                claim_deadline: quote
                    .claim_deadline
                    .ok_or(StoreError::SignedQuoteMismatch)?,
                credential_not_after: quote
                    .credential_not_after
                    .ok_or(StoreError::SignedQuoteMismatch)?,
            },
            &delegation,
            now_unix,
        )
        .map_err(|_| StoreError::StatusRequestBindingMismatch)?;
    let bip340 = request
        .unverified_bip340_input_for_verified_bat_v2_quote(&verified_quote, now_unix)
        .map_err(|_| StoreError::StatusRequestBindingMismatch)?;
    if !verifier.verify(QuoteStatusBip340Input {
        claim_pubkey_xonly: &bip340.claim_pubkey_xonly,
        message_digest: &bip340.message_digest,
        signature: &bip340.signature,
    }) {
        return Err(StoreError::BadStatusRequestSignature);
    }
    Ok(())
}

fn status_nonce_digest(store: &IssuerStore, quote_id: &[u8; 32], raw_nonce: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(QUOTE_STATUS_NONCE_DIGEST_DOMAIN_V1);
    hasher.update(store.handle.expected_issuer_id);
    hasher.update([store.handle.expected_network as u8]);
    hasher.update(quote_id);
    hasher.update(raw_nonce);
    hasher.finalize().into()
}
