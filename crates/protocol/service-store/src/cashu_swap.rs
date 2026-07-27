//! Rollback-protected standard Cashu merchant swap persistence.
//!
//! This module stores only public digests, coarse time buckets, and opaque
//! externally authenticated recovery ciphertext. It does not verify Cashu
//! proofs and does not duplicate the external mint's authoritative spent-set.

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    advance_store_generation, db_u64, fixed_blob, is_zero, mutation_digest, read_identity,
    sql_integer, validate_cashu_unit, verify_expected_provider,
    CashuCustodyExportArtifactPersistV1, CashuCustodyExportArtifactV1, CashuCustodyExportBatchV1,
    CashuCustodyExportReservationV1, CashuCustodyExportStateV1, CashuCustodyExposureLimitsV1,
    CashuCustodyInventoryV1, CashuCustodyLotStateV1, CashuCustodyLotV1,
    CashuCustodyRetirementCheckableSnapshotV1, CashuCustodyRetirementCompletedSnapshotV1,
    CashuCustodyRetirementEvidenceV1, CashuCustodyRetirementNoteStateV1,
    CashuCustodyRetirementSnapshotRequestV1, CashuCustodyRetirementSnapshotV1,
    CashuCustodySealedBlobV1, CashuCustodySpentConfirmationRequestV1,
    CashuCustodySpentConfirmationV1, CashuSwapGrantClaimV1, CashuSwapIntentInsertV1,
    CashuSwapIntentStateV1, CashuSwapIntentV1, CashuSwapSealedRecoveryV1, NewCashuCustodyExportV1,
    NewCashuCustodyLotV1, NewCashuSwapIntentV1, ProviderStore, StoreError, StoreResult,
    MAX_CASHU_CUSTODY_EXPORT_ARTIFACT_BYTES_V1, MAX_CASHU_CUSTODY_EXPORT_KEYSET_GROUPS_V1,
    MAX_CASHU_CUSTODY_EXPORT_LOTS_V1, MAX_CASHU_CUSTODY_EXPORT_NOTES_V1,
    MAX_CASHU_CUSTODY_NOTES_PER_LOT_V1, MAX_CASHU_RECOVERY_CIPHERTEXT_BYTES_V1,
    MAX_CASHU_RECOVERY_NONCE_BYTES_V1,
};

struct RawCashuSwapIntentV1 {
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
    state: i64,
    recovery_key_epoch: i64,
    recovery_nonce: Zeroizing<Vec<u8>>,
    recovery_ciphertext: Zeroizing<Vec<u8>>,
    created_bucket: i64,
    updated_bucket: i64,
}

struct RawCashuCustodyLotV1 {
    lot_id: Vec<u8>,
    mint_id: Vec<u8>,
    manifest_digest: Vec<u8>,
    active_keyset_digest: Vec<u8>,
    note_set_digest: Vec<u8>,
    unit: String,
    settlement_value: i64,
    note_count: i64,
    state: i64,
    sealed_key_epoch: i64,
    sealed_nonce: Zeroizing<Vec<u8>>,
    sealed_ciphertext: Zeroizing<Vec<u8>>,
}

struct RawCashuCustodyExportV1 {
    export_id: Vec<u8>,
    mint_id: Vec<u8>,
    unit: String,
    recipient_key_id: Vec<u8>,
    requested_max_lots: i64,
    lot_count: i64,
    keyset_group_count: i64,
    settlement_value: i64,
    note_count: i64,
    state: i64,
    artifact_digest: Option<Vec<u8>>,
    artifact: Option<Zeroizing<Vec<u8>>>,
}

struct RetirementBatchGuardV1(Option<CashuCustodyExportBatchV1>);

impl RetirementBatchGuardV1 {
    fn as_ref(&self) -> &CashuCustodyExportBatchV1 {
        self.0
            .as_ref()
            .expect("retirement batch guard is populated")
    }

    fn take(&mut self) -> CashuCustodyExportBatchV1 {
        self.0.take().expect("retirement batch guard is populated")
    }
}

impl Drop for RetirementBatchGuardV1 {
    fn drop(&mut self) {
        if let Some(artifact) = self.0.as_mut().and_then(|batch| batch.artifact.as_mut()) {
            artifact.bytes.zeroize();
        }
    }
}

struct RetirementLotsGuardV1(Vec<CashuCustodyLotV1>);

impl RetirementLotsGuardV1 {
    fn take(&mut self) -> Vec<CashuCustodyLotV1> {
        std::mem::take(&mut self.0)
    }
}

impl Drop for RetirementLotsGuardV1 {
    fn drop(&mut self) {
        for lot in &mut self.0 {
            lot.sealed_notes.nonce.zeroize();
            lot.sealed_notes.ciphertext.zeroize();
        }
    }
}

impl ProviderStore {
    /// Insert one exact prepared NUT-03 recovery intent.
    ///
    /// The unique `(mint_id, input_set_digest)` namespace covers all service
    /// offers. An exact immutable replay returns the existing row; any changed
    /// request, output set, offer binding, or amount is a conflict. The opaque
    /// ciphertext need not byte-match an exact replay because authenticated
    /// encryption may use a fresh nonce; the first committed envelope wins.
    pub fn insert_cashu_swap_intent_v1(
        &self,
        proposed: &NewCashuSwapIntentV1,
        limits: CashuCustodyExposureLimitsV1,
    ) -> StoreResult<CashuSwapIntentInsertV1> {
        validate_new_intent(proposed)?;
        validate_exposure_limits(limits)?;
        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_expected_provider(&transaction, &self.handle.expected_provider_id)?;
        let previous_identity = read_identity(&transaction)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;

        if let Some(existing) =
            read_intent_by_input(&transaction, &proposed.mint_id, &proposed.input_set_digest)?
        {
            if !existing.matches_new(proposed) {
                return Err(StoreError::CashuSwapIntentConflict);
            }
            return Ok(CashuSwapIntentInsertV1 {
                inserted: false,
                intent: existing,
            });
        }
        if read_intent_by_id(&transaction, &proposed.intent_id)?.is_some() {
            return Err(StoreError::CashuSwapIntentConflict);
        }
        ensure_insert_within_exposure_limits(&transaction, proposed, limits)?;

        transaction.execute(
            "INSERT INTO cashu_swap_intents (
                intent_id, mint_id, manifest_digest, unit, input_set_digest,
                request_digest, output_set_digest, offer_binding_digest,
                settlement_value, expected_output_count, state,
                recovery_key_epoch, recovery_nonce, recovery_ciphertext,
                created_bucket, updated_bucket
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0,
                ?11, ?12, ?13, ?14, ?14
             )",
            params![
                proposed.intent_id.as_slice(),
                proposed.mint_id.as_slice(),
                proposed.manifest_digest.as_slice(),
                &proposed.unit,
                proposed.input_set_digest.as_slice(),
                proposed.request_digest.as_slice(),
                proposed.output_set_digest.as_slice(),
                proposed.offer_binding_digest.as_slice(),
                sql_integer(
                    proposed.settlement_value,
                    "Cashu settlement value exceeds SQLite integer range"
                )?,
                i64::from(proposed.expected_output_count),
                sql_integer(
                    proposed.sealed_recovery.key_epoch,
                    "Cashu recovery key epoch exceeds SQLite integer range"
                )?,
                &proposed.sealed_recovery.nonce,
                &proposed.sealed_recovery.ciphertext,
                sql_integer(
                    proposed.created_bucket,
                    "Cashu created bucket exceeds SQLite integer range"
                )?,
            ],
        )?;
        let digest = intent_insert_digest(proposed);
        let committed_identity = advance_store_generation(
            &transaction,
            &self.handle.expected_provider_id,
            &previous_identity,
            b"cashu-swap-prepare-v1",
            &digest,
            false,
        )?;
        transaction.commit()?;
        self.anchor_committed_identity(&connection, &previous_floor, &committed_identity)?;
        Ok(CashuSwapIntentInsertV1 {
            inserted: true,
            intent: CashuSwapIntentV1 {
                intent_id: proposed.intent_id,
                mint_id: proposed.mint_id,
                manifest_digest: proposed.manifest_digest,
                unit: proposed.unit.clone(),
                input_set_digest: proposed.input_set_digest,
                request_digest: proposed.request_digest,
                output_set_digest: proposed.output_set_digest,
                offer_binding_digest: proposed.offer_binding_digest,
                settlement_value: proposed.settlement_value,
                expected_output_count: proposed.expected_output_count,
                state: CashuSwapIntentStateV1::Prepared,
                sealed_recovery: proposed.sealed_recovery.clone(),
                created_bucket: proposed.created_bucket,
                updated_bucket: proposed.created_bucket,
            },
        })
    }

    pub fn cashu_swap_intent_by_input_v1(
        &self,
        mint_id: &[u8; 32],
        input_set_digest: &[u8; 32],
    ) -> StoreResult<Option<CashuSwapIntentV1>> {
        if is_zero(mint_id) || is_zero(input_set_digest) {
            return Err(StoreError::InvalidInput(
                "Cashu intent lookup contains a zero digest",
            ));
        }
        let connection = self.open_checked(false)?;
        read_intent_by_input(&connection, mint_id, input_set_digest)
    }

    /// Atomically and externally anchor `PREPARED -> SUBMITTED`.
    ///
    /// A caller may perform the NUT-03 transport side effect only from
    /// `Ok(true)`. Every error, including `UnanchoredCommit`, forbids sending.
    /// `Ok(false)` means the intent had already left `PREPARED`; NUT-03 must
    /// never be retried from that result.
    pub fn begin_cashu_swap_submission_v1(
        &self,
        intent_id: &[u8; 16],
        updated_bucket: u64,
    ) -> StoreResult<bool> {
        self.transition_cashu_swap_state_v1(
            intent_id,
            &[CashuSwapIntentStateV1::Prepared],
            CashuSwapIntentStateV1::Submitted,
            None,
            updated_bucket,
            b"cashu-swap-submit-v1",
            false,
        )
    }

    /// Persist verified/unblinded provider notes inside a replacement opaque
    /// recovery envelope, then enter `WALLET_STORED`.
    pub fn commit_cashu_swap_wallet_v1(
        &self,
        intent_id: &[u8; 16],
        sealed_recovery: &CashuSwapSealedRecoveryV1,
        updated_bucket: u64,
    ) -> StoreResult<bool> {
        validate_sealed_recovery(sealed_recovery)?;
        self.transition_cashu_swap_state_v1(
            intent_id,
            &[
                CashuSwapIntentStateV1::Submitted,
                CashuSwapIntentStateV1::Attention,
            ],
            CashuSwapIntentStateV1::WalletStored,
            Some(sealed_recovery),
            updated_bucket,
            b"cashu-swap-wallet-stored-v1",
            false,
        )
    }

    pub fn mark_cashu_swap_attention_v1(
        &self,
        intent_id: &[u8; 16],
        updated_bucket: u64,
    ) -> StoreResult<bool> {
        self.transition_cashu_swap_state_v1(
            intent_id,
            &[CashuSwapIntentStateV1::Submitted],
            CashuSwapIntentStateV1::Attention,
            None,
            updated_bucket,
            b"cashu-swap-attention-v1",
            false,
        )
    }

    /// Delete an exact `SUBMITTED` intent after the mint returned HTTP 400
    /// with a strict, bounded NUT-00 error response. The caller owns that
    /// protocol classification; this store method enforces only the durable
    /// state precondition. The deletion is externally rollback-anchored before
    /// success and intentionally leaves no terminal row.
    pub fn delete_cashu_swap_intent_after_definite_rejection_v1(
        &self,
        intent_id: &[u8; 16],
    ) -> StoreResult<bool> {
        if is_zero(intent_id) {
            return Err(StoreError::InvalidInput("Cashu intent id is all zero"));
        }
        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_expected_provider(&transaction, &self.handle.expected_provider_id)?;
        let previous_identity = read_identity(&transaction)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;
        let Some(existing) = read_intent_by_id(&transaction, intent_id)? else {
            return Ok(false);
        };
        if existing.state != CashuSwapIntentStateV1::Submitted {
            return Ok(false);
        }

        let changed = transaction.execute(
            "DELETE FROM cashu_swap_intents WHERE intent_id = ?1 AND state = 1",
            [intent_id.as_slice()],
        )?;
        if changed != 1 {
            return Err(StoreError::CashuSwapStateConflict);
        }
        let digest = definite_rejection_delete_digest(&existing);
        let committed_identity = advance_store_generation(
            &transaction,
            &self.handle.expected_provider_id,
            &previous_identity,
            b"cashu-swap-definite-rejection-delete-v1",
            &digest,
            false,
        )?;
        transaction.commit()?;
        self.anchor_committed_identity(&connection, &previous_floor, &committed_identity)?;
        Ok(true)
    }

    /// Claim service delivery once while atomically placing the provider's
    /// verified output notes into custody inventory.
    ///
    /// This is the only Cashu intent mutation that advances
    /// `spend_commit_seq`. `WalletStored -> GrantIssued`, the note-only sealed
    /// lot, and every `H(mint_id || Y)` uniqueness row share one
    /// `BEGIN IMMEDIATE` transaction, so no grant can exist without inventory.
    pub fn claim_cashu_swap_grant_once_v1(
        &self,
        intent_id: &[u8; 16],
        proposed_lot: &NewCashuCustodyLotV1,
        updated_bucket: u64,
    ) -> StoreResult<CashuSwapGrantClaimV1> {
        if is_zero(intent_id) {
            return Err(StoreError::InvalidInput("Cashu intent id is all zero"));
        }
        validate_new_custody_lot(proposed_lot)?;
        let updated_bucket_sql = sql_integer(
            updated_bucket,
            "Cashu updated bucket exceeds SQLite integer range",
        )?;
        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_expected_provider(&transaction, &self.handle.expected_provider_id)?;
        let previous_identity = read_identity(&transaction)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;
        let intent = read_intent_by_id(&transaction, intent_id)?
            .ok_or(StoreError::CashuSwapIntentMissing)?;

        if intent.updated_bucket > updated_bucket {
            return Err(StoreError::InvalidInput(
                "Cashu updated bucket moves backwards",
            ));
        }
        let note_fingerprints = custody_note_fingerprints(&intent.mint_id, &proposed_lot.note_ys)?;
        if proposed_lot.manifest_digest != intent.manifest_digest {
            return Err(StoreError::CashuCustodyLotConflict);
        }
        if usize::try_from(intent.expected_output_count).ok() != Some(note_fingerprints.len()) {
            return Err(StoreError::InvalidInput(
                "Cashu custody note count does not match the prepared intent",
            ));
        }

        if intent.state == CashuSwapIntentStateV1::GrantIssued {
            let existing = read_custody_lot_by_intent(&transaction, intent_id)?
                .ok_or(StoreError::CashuCustodyLotMissing)?;
            if existing.lot_id != proposed_lot.lot_id
                || existing.mint_id != intent.mint_id
                || existing.manifest_digest != proposed_lot.manifest_digest
                || existing.active_keyset_digest != proposed_lot.active_keyset_digest
                || existing.note_set_digest != proposed_lot.note_set_digest
                || existing.unit != intent.unit
                || existing.settlement_value != intent.settlement_value
                || usize::try_from(existing.note_count).ok() != Some(note_fingerprints.len())
                || read_custody_note_fingerprints(&transaction, &existing.lot_id)?
                    != note_fingerprints
            {
                return Err(StoreError::CashuCustodyLotConflict);
            }
            return Ok(CashuSwapGrantClaimV1 {
                issued: false,
                lot: existing,
            });
        }
        if intent.state != CashuSwapIntentStateV1::WalletStored {
            return Err(StoreError::CashuSwapStateConflict);
        }
        if read_custody_lot_by_id(&transaction, &proposed_lot.lot_id)?.is_some() {
            return Err(StoreError::CashuCustodyLotConflict);
        }
        for fingerprint in &note_fingerprints {
            let exists: bool = transaction.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM cashu_custody_notes WHERE note_fingerprint = ?1
                 )",
                [fingerprint.as_slice()],
                |row| row.get(0),
            )?;
            if exists {
                return Err(StoreError::CashuCustodyLotConflict);
            }
        }

        transaction.execute(
            "INSERT INTO cashu_custody_lots (
                lot_id, intent_id, mint_id, manifest_digest,
                active_keyset_digest, note_set_digest, unit, settlement_value,
                note_count, state, sealed_key_epoch, sealed_nonce,
                sealed_ciphertext
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, ?10, ?11, ?12)",
            params![
                proposed_lot.lot_id.as_slice(),
                intent_id.as_slice(),
                intent.mint_id.as_slice(),
                proposed_lot.manifest_digest.as_slice(),
                proposed_lot.active_keyset_digest.as_slice(),
                proposed_lot.note_set_digest.as_slice(),
                &intent.unit,
                sql_integer(
                    intent.settlement_value,
                    "Cashu custody value exceeds SQLite integer range"
                )?,
                i64::from(intent.expected_output_count),
                sql_integer(
                    proposed_lot.sealed_notes.key_epoch,
                    "Cashu custody key epoch exceeds SQLite integer range"
                )?,
                &proposed_lot.sealed_notes.nonce,
                &proposed_lot.sealed_notes.ciphertext,
            ],
        )?;
        for fingerprint in &note_fingerprints {
            transaction.execute(
                "INSERT INTO cashu_custody_notes (note_fingerprint, lot_id) VALUES (?1, ?2)",
                params![fingerprint.as_slice(), proposed_lot.lot_id.as_slice()],
            )?;
        }
        let changed = transaction.execute(
            "UPDATE cashu_swap_intents SET state = 3, updated_bucket = ?2
             WHERE intent_id = ?1 AND state = 2",
            params![intent_id.as_slice(), updated_bucket_sql],
        )?;
        if changed != 1 {
            return Err(StoreError::CashuSwapStateConflict);
        }

        let digest =
            custody_grant_digest(&intent, proposed_lot, &note_fingerprints, updated_bucket);
        let committed_identity = advance_store_generation(
            &transaction,
            &self.handle.expected_provider_id,
            &previous_identity,
            b"cashu-swap-grant-custody-v1",
            &digest,
            true,
        )?;
        transaction.commit()?;
        self.anchor_committed_identity(&connection, &previous_floor, &committed_identity)?;
        Ok(CashuSwapGrantClaimV1 {
            issued: true,
            lot: CashuCustodyLotV1 {
                lot_id: proposed_lot.lot_id,
                mint_id: intent.mint_id,
                manifest_digest: proposed_lot.manifest_digest,
                active_keyset_digest: proposed_lot.active_keyset_digest,
                note_set_digest: proposed_lot.note_set_digest,
                unit: intent.unit,
                settlement_value: intent.settlement_value,
                note_count: intent.expected_output_count,
                state: CashuCustodyLotStateV1::Available,
                sealed_notes: proposed_lot.sealed_notes.clone(),
            },
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn transition_cashu_swap_state_v1(
        &self,
        intent_id: &[u8; 16],
        allowed_from: &[CashuSwapIntentStateV1],
        target: CashuSwapIntentStateV1,
        replacement_recovery: Option<&CashuSwapSealedRecoveryV1>,
        updated_bucket: u64,
        mutation_kind: &'static [u8],
        increment_spend_sequence: bool,
    ) -> StoreResult<bool> {
        if is_zero(intent_id) {
            return Err(StoreError::InvalidInput("Cashu intent id is all zero"));
        }
        let updated_bucket_sql = sql_integer(
            updated_bucket,
            "Cashu updated bucket exceeds SQLite integer range",
        )?;
        if let Some(sealed) = replacement_recovery {
            validate_sealed_recovery(sealed)?;
        }
        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_expected_provider(&transaction, &self.handle.expected_provider_id)?;
        let previous_identity = read_identity(&transaction)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;
        let existing = read_intent_by_id(&transaction, intent_id)?
            .ok_or(StoreError::CashuSwapIntentMissing)?;

        if existing.updated_bucket > updated_bucket {
            return Err(StoreError::InvalidInput(
                "Cashu updated bucket moves backwards",
            ));
        }
        if !allowed_from.contains(&existing.state) {
            return if transition_already_applied_or_superseded(existing.state, target) {
                Ok(false)
            } else {
                Err(StoreError::CashuSwapStateConflict)
            };
        }

        let changed = match replacement_recovery {
            Some(sealed) => transaction.execute(
                "UPDATE cashu_swap_intents SET
                    state = ?2, recovery_key_epoch = ?3, recovery_nonce = ?4,
                    recovery_ciphertext = ?5, updated_bucket = ?6
                 WHERE intent_id = ?1 AND state = ?7",
                params![
                    intent_id.as_slice(),
                    target as i64,
                    sql_integer(
                        sealed.key_epoch,
                        "Cashu recovery key epoch exceeds SQLite integer range"
                    )?,
                    &sealed.nonce,
                    &sealed.ciphertext,
                    updated_bucket_sql,
                    existing.state as i64,
                ],
            )?,
            None => transaction.execute(
                "UPDATE cashu_swap_intents SET state = ?2, updated_bucket = ?3
                 WHERE intent_id = ?1 AND state = ?4",
                params![
                    intent_id.as_slice(),
                    target as i64,
                    updated_bucket_sql,
                    existing.state as i64,
                ],
            )?,
        };
        if changed != 1 {
            return Err(StoreError::CashuSwapStateConflict);
        }
        let digest = transition_digest(
            intent_id,
            existing.state,
            target,
            replacement_recovery,
            updated_bucket,
        );
        let committed_identity = advance_store_generation(
            &transaction,
            &self.handle.expected_provider_id,
            &previous_identity,
            mutation_kind,
            &digest,
            increment_spend_sequence,
        )?;
        transaction.commit()?;
        self.anchor_committed_identity(&connection, &previous_floor, &committed_identity)?;
        Ok(true)
    }

    /// Atomically reserves up to `max_lots` available lots for one export ID.
    /// Replaying the exact request returns the same members while the batch is
    /// still reserved, or the exact persisted artifact after materialization.
    pub fn reserve_cashu_custody_export_v1(
        &self,
        proposed: &NewCashuCustodyExportV1,
    ) -> StoreResult<CashuCustodyExportReservationV1> {
        validate_new_export(proposed)?;
        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_expected_provider(&transaction, &self.handle.expected_provider_id)?;
        let previous_identity = read_identity(&transaction)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;

        if let Some(existing) = read_custody_export(&transaction, &proposed.export_id)? {
            if existing.mint_id != proposed.mint_id
                || existing.unit != proposed.unit
                || existing.recipient_key_id != proposed.recipient_key_id
                || existing.requested_max_lots != proposed.max_lots
            {
                return Err(StoreError::CashuCustodyExportConflict);
            }
            validate_export_batch_members(&transaction, &existing)?;
            let sealed_lots = if existing.state == CashuCustodyExportStateV1::Reserved {
                read_custody_export_lots(&transaction, &existing.export_id)?
            } else {
                Vec::new()
            };
            return Ok(CashuCustodyExportReservationV1 {
                reserved: false,
                batch: existing,
                sealed_lots,
            });
        }

        let (lot_ids, selected_note_count, keyset_group_count) = {
            let mut statement = transaction.prepare(
                "SELECT lot_id, note_count, active_keyset_digest
                 FROM cashu_custody_lots
                 WHERE mint_id = ?1 AND unit = ?2 AND state = 1
                 ORDER BY lot_id LIMIT ?3",
            )?;
            let candidates = statement
                .query_map(
                    params![
                        proposed.mint_id.as_slice(),
                        &proposed.unit,
                        i64::try_from(MAX_CASHU_CUSTODY_EXPORT_LOTS_V1).map_err(|_| {
                            StoreError::InvalidInput("Cashu export scan limit overflow")
                        })?,
                    ],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                        ))
                    },
                )?
                .collect::<Result<Vec<_>, _>>()?;
            let mut selected = Vec::new();
            let mut notes = 0_u64;
            let mut keysets = BTreeSet::new();
            for (raw_lot_id, raw_note_count, raw_keyset_digest) in candidates {
                let lot_id = fixed_blob(raw_lot_id, "invalid Cashu custody lot id")?;
                let note_count = db_u64(raw_note_count, "negative Cashu custody note count")?;
                let keyset_digest: [u8; 32] = fixed_blob(
                    raw_keyset_digest,
                    "invalid Cashu custody active keyset digest",
                )?;
                if note_count == 0
                    || note_count
                        > u64::try_from(MAX_CASHU_CUSTODY_NOTES_PER_LOT_V1).unwrap_or(u64::MAX)
                    || is_zero(&keyset_digest)
                {
                    return Err(StoreError::SchemaMismatch(
                        "invalid Cashu custody export candidate".to_owned(),
                    ));
                }
                let Some(next_notes) = notes.checked_add(note_count) else {
                    return Err(StoreError::SchemaMismatch(
                        "Cashu custody export note count overflow".to_owned(),
                    ));
                };
                if next_notes > u64::try_from(MAX_CASHU_CUSTODY_EXPORT_NOTES_V1).unwrap_or(u64::MAX)
                {
                    continue;
                }
                let adds_keyset = !keysets.contains(&keyset_digest);
                if adds_keyset && keysets.len() >= MAX_CASHU_CUSTODY_EXPORT_KEYSET_GROUPS_V1 {
                    continue;
                }
                selected.push(lot_id);
                notes = next_notes;
                keysets.insert(keyset_digest);
                if selected.len() == usize::try_from(proposed.max_lots).unwrap_or(usize::MAX)
                    || notes == u64::try_from(MAX_CASHU_CUSTODY_EXPORT_NOTES_V1).unwrap_or(u64::MAX)
                {
                    break;
                }
            }
            (selected, notes, keysets.len())
        };
        if lot_ids.is_empty() {
            return Err(StoreError::CashuCustodyUnavailable);
        }
        let keyset_group_count = u32::try_from(keyset_group_count)
            .map_err(|_| StoreError::InvalidInput("Cashu export keyset group count overflow"))?;

        let mut sealed_lots = Vec::with_capacity(lot_ids.len());
        let mut settlement_value = 0_u64;
        let mut note_count = 0_u64;
        for lot_id in &lot_ids {
            let mut lot = read_custody_lot_by_id(&transaction, lot_id)?
                .ok_or(StoreError::CashuCustodyLotMissing)?;
            if lot.state != CashuCustodyLotStateV1::Available
                || lot.mint_id != proposed.mint_id
                || lot.unit != proposed.unit
            {
                return Err(StoreError::CashuCustodyStateConflict);
            }
            settlement_value = checked_aggregate_add(
                settlement_value,
                lot.settlement_value,
                "Cashu custody export value overflow",
            )?;
            note_count = checked_aggregate_add(
                note_count,
                u64::from(lot.note_count),
                "Cashu custody export note count overflow",
            )?;
            lot.state = CashuCustodyLotStateV1::Reserved;
            sealed_lots.push(lot);
        }
        if note_count != selected_note_count {
            return Err(StoreError::SchemaMismatch(
                "Cashu custody export selection note count changed".to_owned(),
            ));
        }

        transaction.execute(
            "INSERT INTO cashu_custody_export_batches (
                export_id, mint_id, unit, recipient_key_id,
                requested_max_lots, lot_count, keyset_group_count,
                settlement_value, note_count, state, artifact_digest, artifact
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, NULL, NULL)",
            params![
                proposed.export_id.as_slice(),
                proposed.mint_id.as_slice(),
                &proposed.unit,
                proposed.recipient_key_id.as_slice(),
                i64::from(proposed.max_lots),
                i64::try_from(lot_ids.len())
                    .map_err(|_| StoreError::InvalidInput("Cashu export lot count overflow"))?,
                i64::from(keyset_group_count),
                sql_integer(
                    settlement_value,
                    "Cashu custody export value exceeds SQLite integer range"
                )?,
                sql_integer(
                    note_count,
                    "Cashu custody export note count exceeds SQLite integer range"
                )?,
            ],
        )?;
        for (index, lot_id) in lot_ids.iter().enumerate() {
            let changed = transaction.execute(
                "UPDATE cashu_custody_lots SET state = 2 WHERE lot_id = ?1 AND state = 1",
                [lot_id.as_slice()],
            )?;
            if changed != 1 {
                return Err(StoreError::CashuCustodyStateConflict);
            }
            transaction.execute(
                "INSERT INTO cashu_custody_export_members (export_id, member_index, lot_id)
                 VALUES (?1, ?2, ?3)",
                params![
                    proposed.export_id.as_slice(),
                    i64::try_from(index).map_err(|_| StoreError::InvalidInput(
                        "Cashu export member index overflow"
                    ))?,
                    lot_id.as_slice(),
                ],
            )?;
        }
        let digest = custody_export_reserve_digest(
            proposed,
            &lot_ids,
            keyset_group_count,
            settlement_value,
            note_count,
        );
        let committed_identity = advance_store_generation(
            &transaction,
            &self.handle.expected_provider_id,
            &previous_identity,
            b"cashu-custody-export-reserve-v1",
            &digest,
            false,
        )?;
        transaction.commit()?;
        self.anchor_committed_identity(&connection, &previous_floor, &committed_identity)?;
        Ok(CashuCustodyExportReservationV1 {
            reserved: true,
            batch: CashuCustodyExportBatchV1 {
                export_id: proposed.export_id,
                mint_id: proposed.mint_id,
                unit: proposed.unit.clone(),
                recipient_key_id: proposed.recipient_key_id,
                requested_max_lots: proposed.max_lots,
                lot_count: u32::try_from(lot_ids.len())
                    .map_err(|_| StoreError::InvalidInput("Cashu export lot count overflow"))?,
                keyset_group_count,
                settlement_value,
                note_count,
                state: CashuCustodyExportStateV1::Reserved,
                artifact: None,
            },
            sealed_lots,
        })
    }

    /// Store one exact opaque export artifact. The first committed artifact is
    /// immutable; an exact replay returns it, and different bytes fail closed.
    pub fn persist_cashu_custody_export_artifact_v1(
        &self,
        export_id: &[u8; 16],
        artifact: &[u8],
    ) -> StoreResult<CashuCustodyExportArtifactPersistV1> {
        if is_zero(export_id) {
            return Err(StoreError::InvalidInput("Cashu export id is all zero"));
        }
        validate_export_artifact(artifact)?;
        let artifact_digest: [u8; 32] = Sha256::digest(artifact).into();
        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_expected_provider(&transaction, &self.handle.expected_provider_id)?;
        let previous_identity = read_identity(&transaction)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;
        let existing = read_custody_export(&transaction, export_id)?
            .ok_or(StoreError::CashuCustodyExportMissing)?;
        validate_export_batch_members(&transaction, &existing)?;

        if existing.state != CashuCustodyExportStateV1::Reserved {
            if existing
                .artifact
                .as_ref()
                .is_some_and(|stored| stored.digest == artifact_digest && stored.bytes == artifact)
            {
                return Ok(CashuCustodyExportArtifactPersistV1 {
                    persisted: false,
                    batch: existing,
                });
            }
            return Err(StoreError::CashuCustodyExportConflict);
        }
        require_export_members_in_state(
            &transaction,
            export_id,
            existing.lot_count,
            CashuCustodyLotStateV1::Reserved,
        )?;
        let changed = transaction.execute(
            "UPDATE cashu_custody_export_batches SET
                state = 2, artifact_digest = ?2, artifact = ?3
             WHERE export_id = ?1 AND state = 1",
            params![export_id.as_slice(), artifact_digest.as_slice(), artifact,],
        )?;
        if changed != 1 {
            return Err(StoreError::CashuCustodyStateConflict);
        }
        let digest = custody_export_artifact_digest(&existing, &artifact_digest, artifact);
        let committed_identity = advance_store_generation(
            &transaction,
            &self.handle.expected_provider_id,
            &previous_identity,
            b"cashu-custody-export-artifact-v1",
            &digest,
            false,
        )?;
        transaction.commit()?;
        self.anchor_committed_identity(&connection, &previous_floor, &committed_identity)?;
        let mut batch = existing;
        batch.state = CashuCustodyExportStateV1::ArtifactStored;
        batch.artifact = Some(CashuCustodyExportArtifactV1 {
            digest: artifact_digest,
            bytes: artifact.to_vec(),
        });
        Ok(CashuCustodyExportArtifactPersistV1 {
            persisted: true,
            batch,
        })
    }

    /// Record that the exact export artifact was delivered to its intended
    /// external wallet. This does **not** release local exposure and does not
    /// represent Cashu melt/swap, Lightning payment, or provider settlement.
    pub fn acknowledge_cashu_custody_export_v1(
        &self,
        export_id: &[u8; 16],
        artifact_digest: &[u8; 32],
    ) -> StoreResult<bool> {
        if is_zero(export_id) || is_zero(artifact_digest) {
            return Err(StoreError::InvalidInput(
                "Cashu export acknowledgement contains a zero identity",
            ));
        }
        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_expected_provider(&transaction, &self.handle.expected_provider_id)?;
        let previous_identity = read_identity(&transaction)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;
        let existing = read_custody_export(&transaction, export_id)?
            .ok_or(StoreError::CashuCustodyExportMissing)?;
        validate_export_batch_members(&transaction, &existing)?;
        if existing.artifact.as_ref().map(|value| value.digest) != Some(*artifact_digest) {
            return Err(StoreError::CashuCustodyExportConflict);
        }
        if matches!(
            existing.state,
            CashuCustodyExportStateV1::DeliveryAcknowledged
                | CashuCustodyExportStateV1::SpentConfirmed
        ) {
            return Ok(false);
        }
        if existing.state != CashuCustodyExportStateV1::ArtifactStored {
            return Err(StoreError::CashuCustodyStateConflict);
        }
        require_export_members_in_state(
            &transaction,
            export_id,
            existing.lot_count,
            CashuCustodyLotStateV1::Reserved,
        )?;
        let changed_lots = transaction.execute(
            "UPDATE cashu_custody_lots SET state = 3
             WHERE state = 2 AND lot_id IN (
                SELECT lot_id FROM cashu_custody_export_members WHERE export_id = ?1
             )",
            [export_id.as_slice()],
        )?;
        if changed_lots != usize::try_from(existing.lot_count).unwrap_or(usize::MAX) {
            return Err(StoreError::CashuCustodyStateConflict);
        }
        let changed_batch = transaction.execute(
            "UPDATE cashu_custody_export_batches SET state = 3
             WHERE export_id = ?1 AND state = 2",
            [export_id.as_slice()],
        )?;
        if changed_batch != 1 {
            return Err(StoreError::CashuCustodyStateConflict);
        }
        let digest = custody_export_ack_digest(&existing, artifact_digest);
        let committed_identity = advance_store_generation(
            &transaction,
            &self.handle.expected_provider_id,
            &previous_identity,
            b"cashu-custody-export-ack-v1",
            &digest,
            false,
        )?;
        transaction.commit()?;
        self.anchor_committed_identity(&connection, &previous_floor, &committed_identity)?;
        Ok(true)
    }

    /// Atomically retire one delivered export after an exact owner-initiated
    /// NUT-07 check reports every member note as `SPENT`.
    ///
    /// Raw `Y` values and per-note states are used only inside this call. The
    /// durable row contains domain-separated digests and the exact rollback
    /// floor on both sides of the transition. A byte-equivalent replay is
    /// idempotent; stale floors, changed evidence, missing notes, or any state
    /// other than `SPENT` fail without a write.
    pub fn confirm_cashu_custody_export_spent_v1(
        &self,
        request: &CashuCustodySpentConfirmationRequestV1,
    ) -> StoreResult<CashuCustodySpentConfirmationV1> {
        validate_spent_confirmation_request(request)?;
        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_expected_provider(&transaction, &self.handle.expected_provider_id)?;
        let previous_identity = read_identity(&transaction)?;
        let previous_floor = self.require_exact_rollback_floor(&previous_identity)?;
        let export = read_custody_export(&transaction, &request.export_id)?
            .ok_or(StoreError::CashuCustodyExportMissing)?;
        validate_export_batch_members(&transaction, &export)?;
        if export.artifact.as_ref().map(|artifact| artifact.digest) != Some(request.artifact_digest)
        {
            return Err(StoreError::CashuCustodyExportConflict);
        }

        let derived = derive_retirement_evidence_inputs(&transaction, &export, request)?;
        if export.state == CashuCustodyExportStateV1::SpentConfirmed {
            let evidence = read_retirement_evidence(&transaction, &request.export_id)?
                .ok_or(StoreError::CashuCustodyRetirementEvidenceMissing)?;
            validate_exact_retirement_replay(request, &derived, &evidence)?;
            return Ok(CashuCustodySpentConfirmationV1 {
                confirmed: false,
                evidence,
            });
        }
        if export.state != CashuCustodyExportStateV1::DeliveryAcknowledged {
            return Err(StoreError::CashuCustodyStateConflict);
        }
        require_exact_retirement_floor(request, &previous_identity)?;
        if read_retirement_evidence(&transaction, &request.export_id)?.is_some() {
            return Err(StoreError::CashuCustodyRetirementEvidenceConflict);
        }

        let mutation_digest = custody_export_spent_confirmation_digest(
            request,
            &derived.member_set_digest,
            &derived.note_fingerprint_set_digest,
            &derived.y_set_digest,
            derived.note_count,
        );
        let changed_lots = transaction.execute(
            "UPDATE cashu_custody_lots SET state = 4
             WHERE state = 3 AND lot_id IN (
                SELECT lot_id FROM cashu_custody_export_members WHERE export_id = ?1
             )",
            [request.export_id.as_slice()],
        )?;
        if changed_lots != usize::try_from(export.lot_count).unwrap_or(usize::MAX) {
            return Err(StoreError::CashuCustodyStateConflict);
        }
        let changed_export = transaction.execute(
            "UPDATE cashu_custody_export_batches SET state = 4
             WHERE export_id = ?1 AND state = 3",
            [request.export_id.as_slice()],
        )?;
        if changed_export != 1 {
            return Err(StoreError::CashuCustodyStateConflict);
        }
        let committed_identity = advance_store_generation(
            &transaction,
            &self.handle.expected_provider_id,
            &previous_identity,
            b"cashu-custody-export-spent-confirmed-v1",
            &mutation_digest,
            false,
        )?;
        let evidence = CashuCustodyRetirementEvidenceV1 {
            export_id: request.export_id,
            provider_id: previous_identity.provider_id,
            store_instance_id: previous_identity.store_instance_id,
            precondition_store_generation: previous_identity.store_generation,
            precondition_spend_commit_seq: previous_identity.spend_commit_seq,
            precondition_rollback_commitment: previous_identity.rollback_commitment,
            confirmed_store_generation: committed_identity.store_generation,
            confirmed_spend_commit_seq: committed_identity.spend_commit_seq,
            confirmed_rollback_commitment: committed_identity.rollback_commitment,
            artifact_digest: request.artifact_digest,
            member_set_digest: derived.member_set_digest,
            note_fingerprint_set_digest: derived.note_fingerprint_set_digest,
            y_set_digest: derived.y_set_digest,
            nut07_response_digest: request.nut07_response_digest,
            note_count: derived.note_count,
            evidence_digest: retirement_evidence_digest(
                request,
                &derived.member_set_digest,
                &derived.note_fingerprint_set_digest,
                &derived.y_set_digest,
                derived.note_count,
                &committed_identity.rollback_commitment,
            ),
        };
        insert_retirement_evidence(&transaction, &evidence)?;
        transaction.commit()?;
        self.anchor_committed_identity(&connection, &previous_floor, &committed_identity)?;
        Ok(CashuCustodySpentConfirmationV1 {
            confirmed: true,
            evidence,
        })
    }

    /// Read and cross-check the digest-only retirement evidence for one export.
    pub fn cashu_custody_retirement_evidence_v1(
        &self,
        export_id: &[u8; 16],
    ) -> StoreResult<Option<CashuCustodyRetirementEvidenceV1>> {
        if is_zero(export_id) {
            return Err(StoreError::InvalidInput("Cashu export id is all zero"));
        }
        let connection = self.open_checked(false)?;
        let export = read_custody_export(&connection, export_id)?;
        let evidence = read_retirement_evidence(&connection, export_id)?;
        match (export, evidence) {
            (None, None) => Ok(None),
            (Some(export), None) if export.state != CashuCustodyExportStateV1::SpentConfirmed => {
                validate_export_batch_members(&connection, &export)?;
                Ok(None)
            }
            (Some(export), Some(evidence))
                if export.state == CashuCustodyExportStateV1::SpentConfirmed =>
            {
                validate_export_batch_members(&connection, &export)?;
                validate_persisted_retirement_evidence(&connection, &export, &evidence)?;
                Ok(Some(evidence))
            }
            _ => Err(StoreError::SchemaMismatch(
                "Cashu retirement evidence state mismatch".to_owned(),
            )),
        }
    }

    /// Return one strongly checked owner-side snapshot for NUT-07 retirement.
    ///
    /// This is intentionally not a server-wire API. Filesystem/database access
    /// control and the caller's custody-key policy must restrict it to an
    /// offline owner process. `provider_id` and `store_instance_id` prevent a
    /// wrong-store accident but are not authentication credentials.
    ///
    /// `ArtifactStored` and `DeliveryAcknowledged` snapshots contain the exact
    /// artifact and sealed member lots. The caller should normally require
    /// delivery acknowledgement before contacting the mint. A terminal
    /// `SpentConfirmed` snapshot contains only cohort metadata and digest
    /// evidence: it never releases artifact bytes or sealed notes again.
    ///
    /// `checked_identity` is the only valid precondition for a subsequent
    /// confirmation. Any intervening store mutation, including confirmation of
    /// a different export, requires a fresh snapshot and a newly bound request.
    pub fn cashu_custody_retirement_snapshot_owner_v1(
        &self,
        request: &CashuCustodyRetirementSnapshotRequestV1,
    ) -> StoreResult<CashuCustodyRetirementSnapshotV1> {
        if is_zero(&request.provider_id)
            || is_zero(&request.store_instance_id)
            || is_zero(&request.export_id)
        {
            return Err(StoreError::InvalidInput(
                "Cashu retirement snapshot contains a zero identity",
            ));
        }
        if request.provider_id != self.handle.expected_provider_id {
            return Err(StoreError::ProviderMismatch);
        }

        let mut connection = self.open_checked(false)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        verify_expected_provider(&transaction, &request.provider_id)?;
        let checked_identity = read_identity(&transaction)?;
        if checked_identity.store_instance_id != request.store_instance_id {
            return Err(StoreError::CashuCustodyRetirementFloorMismatch);
        }
        let _ = self.require_exact_rollback_floor(&checked_identity)?;

        let mut batch_guard = RetirementBatchGuardV1(Some(
            read_custody_export(&transaction, &request.export_id)?
                .ok_or(StoreError::CashuCustodyExportMissing)?,
        ));
        let batch = batch_guard.as_ref();
        validate_custody_relational_invariants(&transaction, &batch.mint_id, &batch.unit)?;
        validate_export_batch_members(&transaction, batch)?;
        validate_retirement_evidence_state(&transaction, batch)?;
        let member_lot_ids = read_custody_export_member_ids(&transaction, &batch.export_id)?;
        if member_lot_ids.len() != usize::try_from(batch.lot_count).unwrap_or(usize::MAX) {
            return Err(StoreError::SchemaMismatch(
                "Cashu retirement snapshot member count mismatch".to_owned(),
            ));
        }

        let snapshot = match batch.state {
            CashuCustodyExportStateV1::Reserved => {
                return Err(StoreError::CashuCustodyStateConflict)
            }
            CashuCustodyExportStateV1::ArtifactStored
            | CashuCustodyExportStateV1::DeliveryAcknowledged => {
                let expected_lot_state = if batch.state == CashuCustodyExportStateV1::ArtifactStored
                {
                    CashuCustodyLotStateV1::Reserved
                } else {
                    CashuCustodyLotStateV1::DeliveryAcknowledged
                };
                if batch.artifact.is_none() {
                    return Err(StoreError::SchemaMismatch(
                        "Cashu retirement snapshot artifact is missing".to_owned(),
                    ));
                }
                let mut lots_guard = RetirementLotsGuardV1(read_custody_export_lots_in_state(
                    &transaction,
                    batch,
                    &member_lot_ids,
                    expected_lot_state,
                )?);
                let batch = batch_guard.take();
                CashuCustodyRetirementSnapshotV1::Checkable(Box::new(
                    CashuCustodyRetirementCheckableSnapshotV1 {
                        checked_identity,
                        batch,
                        member_lot_ids,
                        sealed_lots: lots_guard.take(),
                    },
                ))
            }
            CashuCustodyExportStateV1::SpentConfirmed => {
                let evidence = read_retirement_evidence(&transaction, &batch.export_id)?
                    .ok_or(StoreError::CashuCustodyRetirementEvidenceMissing)?;
                validate_persisted_retirement_evidence(&transaction, batch, &evidence)?;
                let artifact_digest = batch
                    .artifact
                    .as_ref()
                    .ok_or_else(|| {
                        StoreError::SchemaMismatch(
                            "Cashu spent-confirmed export artifact is missing".to_owned(),
                        )
                    })?
                    .digest;
                CashuCustodyRetirementSnapshotV1::SpentConfirmed(Box::new(
                    CashuCustodyRetirementCompletedSnapshotV1 {
                        checked_identity,
                        export_id: batch.export_id,
                        mint_id: batch.mint_id,
                        unit: batch.unit.clone(),
                        settlement_value: batch.settlement_value,
                        note_count: batch.note_count,
                        artifact_digest,
                        evidence,
                    },
                ))
            }
        };

        // A concurrent mutation after the first floor check makes this
        // snapshot stale. Rechecking before return fails closed if the external
        // authority has already advanced; later mutations are caught by the
        // confirmation request's exact precondition.
        let _ = self.require_exact_rollback_floor(&checked_identity)?;
        transaction.commit()?;
        Ok(snapshot)
    }

    pub fn cashu_custody_export_v1(
        &self,
        export_id: &[u8; 16],
    ) -> StoreResult<Option<CashuCustodyExportBatchV1>> {
        if is_zero(export_id) {
            return Err(StoreError::InvalidInput("Cashu export id is all zero"));
        }
        let connection = self.open_checked(false)?;
        let batch = read_custody_export(&connection, export_id)?;
        if let Some(batch) = batch.as_ref() {
            validate_export_batch_members(&connection, batch)?;
            validate_retirement_evidence_state(&connection, batch)?;
        }
        Ok(batch)
    }

    /// Returns only checked aggregate values and counts for one public
    /// mint/unit cohort. No intent, lot, note, export, ciphertext, or time data
    /// leaves this read API.
    pub fn cashu_custody_inventory_v1(
        &self,
        mint_id: &[u8; 32],
        unit: &str,
    ) -> StoreResult<CashuCustodyInventoryV1> {
        if is_zero(mint_id) {
            return Err(StoreError::InvalidInput("Cashu mint id is all zero"));
        }
        validate_cashu_unit(unit)?;
        let connection = self.open_checked(false)?;
        read_custody_inventory(&connection, mint_id, unit)
    }
}

fn transition_already_applied_or_superseded(
    current: CashuSwapIntentStateV1,
    target: CashuSwapIntentStateV1,
) -> bool {
    match target {
        CashuSwapIntentStateV1::Prepared => current == CashuSwapIntentStateV1::Prepared,
        CashuSwapIntentStateV1::Submitted => matches!(
            current,
            CashuSwapIntentStateV1::Submitted
                | CashuSwapIntentStateV1::Attention
                | CashuSwapIntentStateV1::WalletStored
                | CashuSwapIntentStateV1::GrantIssued
        ),
        CashuSwapIntentStateV1::Attention => matches!(
            current,
            CashuSwapIntentStateV1::Attention
                | CashuSwapIntentStateV1::WalletStored
                | CashuSwapIntentStateV1::GrantIssued
        ),
        CashuSwapIntentStateV1::WalletStored => matches!(
            current,
            CashuSwapIntentStateV1::WalletStored | CashuSwapIntentStateV1::GrantIssued
        ),
        CashuSwapIntentStateV1::GrantIssued => current == CashuSwapIntentStateV1::GrantIssued,
    }
}

fn validate_new_intent(intent: &NewCashuSwapIntentV1) -> StoreResult<()> {
    if is_zero(&intent.intent_id)
        || is_zero(&intent.mint_id)
        || is_zero(&intent.manifest_digest)
        || is_zero(&intent.input_set_digest)
        || is_zero(&intent.request_digest)
        || is_zero(&intent.output_set_digest)
        || is_zero(&intent.offer_binding_digest)
    {
        return Err(StoreError::InvalidInput(
            "Cashu intent identity contains a zero sentinel",
        ));
    }
    if intent.settlement_value == 0 {
        return Err(StoreError::InvalidInput("Cashu settlement value is zero"));
    }
    validate_cashu_unit(&intent.unit)?;
    if intent.expected_output_count == 0
        || usize::try_from(intent.expected_output_count).unwrap_or(usize::MAX)
            > MAX_CASHU_CUSTODY_NOTES_PER_LOT_V1
    {
        return Err(StoreError::InvalidInput(
            "Cashu expected output count is outside its bounds",
        ));
    }
    let _ = sql_integer(
        intent.settlement_value,
        "Cashu settlement value exceeds SQLite integer range",
    )?;
    let _ = sql_integer(
        intent.created_bucket,
        "Cashu created bucket exceeds SQLite integer range",
    )?;
    validate_sealed_recovery(&intent.sealed_recovery)
}

fn validate_sealed_recovery(sealed: &CashuSwapSealedRecoveryV1) -> StoreResult<()> {
    if sealed.key_epoch == 0
        || sealed.nonce.is_empty()
        || sealed.nonce.len() > MAX_CASHU_RECOVERY_NONCE_BYTES_V1
        || sealed.ciphertext.is_empty()
        || sealed.ciphertext.len() > MAX_CASHU_RECOVERY_CIPHERTEXT_BYTES_V1
    {
        return Err(StoreError::InvalidInput(
            "Cashu recovery envelope is outside its bounds",
        ));
    }
    let _ = sql_integer(
        sealed.key_epoch,
        "Cashu recovery key epoch exceeds SQLite integer range",
    )?;
    Ok(())
}

fn read_intent_by_input(
    connection: &Connection,
    mint_id: &[u8; 32],
    input_set_digest: &[u8; 32],
) -> StoreResult<Option<CashuSwapIntentV1>> {
    read_intent(
        connection,
        "WHERE mint_id = ?1 AND input_set_digest = ?2",
        params![mint_id.as_slice(), input_set_digest.as_slice()],
    )
}

fn read_intent_by_id(
    connection: &Connection,
    intent_id: &[u8; 16],
) -> StoreResult<Option<CashuSwapIntentV1>> {
    read_intent(
        connection,
        "WHERE intent_id = ?1",
        params![intent_id.as_slice()],
    )
}

fn read_intent<P: rusqlite::Params>(
    connection: &Connection,
    predicate: &str,
    parameters: P,
) -> StoreResult<Option<CashuSwapIntentV1>> {
    let sql = format!(
        "SELECT intent_id, mint_id, manifest_digest, unit, input_set_digest,
                request_digest, output_set_digest, offer_binding_digest,
                settlement_value, expected_output_count, state,
                recovery_key_epoch, recovery_nonce, recovery_ciphertext,
                created_bucket, updated_bucket
         FROM cashu_swap_intents {predicate}"
    );
    let raw: Option<RawCashuSwapIntentV1> = connection
        .query_row(&sql, parameters, |row| {
            // Guard opaque recovery bytes before any later column conversion
            // can fail and unwind this row decoder.
            let recovery_nonce = Zeroizing::new(row.get(12)?);
            let recovery_ciphertext = Zeroizing::new(row.get(13)?);
            Ok(RawCashuSwapIntentV1 {
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
                recovery_key_epoch: row.get(11)?,
                recovery_nonce,
                recovery_ciphertext,
                created_bucket: row.get(14)?,
                updated_bucket: row.get(15)?,
            })
        })
        .optional()?;
    raw.map(decode_intent).transpose()
}

fn decode_intent(mut raw: RawCashuSwapIntentV1) -> StoreResult<CashuSwapIntentV1> {
    let intent = CashuSwapIntentV1 {
        intent_id: fixed_blob(raw.intent_id, "invalid Cashu intent id")?,
        mint_id: fixed_blob(raw.mint_id, "invalid Cashu mint id")?,
        manifest_digest: fixed_blob(raw.manifest_digest, "invalid Cashu manifest digest")?,
        unit: raw.unit,
        input_set_digest: fixed_blob(raw.input_set_digest, "invalid Cashu input digest")?,
        request_digest: fixed_blob(raw.request_digest, "invalid Cashu request digest")?,
        output_set_digest: fixed_blob(raw.output_set_digest, "invalid Cashu output digest")?,
        offer_binding_digest: fixed_blob(
            raw.offer_binding_digest,
            "invalid Cashu offer binding digest",
        )?,
        settlement_value: db_u64(raw.settlement_value, "negative Cashu settlement value")?,
        expected_output_count: u32::try_from(raw.expected_output_count).map_err(|_| {
            StoreError::SchemaMismatch("invalid Cashu expected output count".to_owned())
        })?,
        state: CashuSwapIntentStateV1::from_db(raw.state)
            .ok_or_else(|| StoreError::SchemaMismatch("invalid Cashu intent state".to_owned()))?,
        sealed_recovery: CashuSwapSealedRecoveryV1 {
            key_epoch: db_u64(raw.recovery_key_epoch, "negative Cashu recovery key epoch")?,
            nonce: std::mem::take(&mut *raw.recovery_nonce),
            ciphertext: std::mem::take(&mut *raw.recovery_ciphertext),
        },
        created_bucket: db_u64(raw.created_bucket, "negative Cashu created bucket")?,
        updated_bucket: db_u64(raw.updated_bucket, "negative Cashu updated bucket")?,
    };
    if is_zero(&intent.intent_id)
        || is_zero(&intent.mint_id)
        || is_zero(&intent.manifest_digest)
        || is_zero(&intent.input_set_digest)
        || is_zero(&intent.request_digest)
        || is_zero(&intent.output_set_digest)
        || is_zero(&intent.offer_binding_digest)
        || intent.settlement_value == 0
        || intent.expected_output_count == 0
        || usize::try_from(intent.expected_output_count).unwrap_or(usize::MAX)
            > MAX_CASHU_CUSTODY_NOTES_PER_LOT_V1
        || intent.updated_bucket < intent.created_bucket
    {
        return Err(StoreError::SchemaMismatch(
            "Cashu intent contains an invalid sentinel or bucket".to_owned(),
        ));
    }
    validate_cashu_unit(&intent.unit)
        .map_err(|_| StoreError::SchemaMismatch("invalid Cashu unit".to_owned()))?;
    validate_sealed_recovery(&intent.sealed_recovery)
        .map_err(|_| StoreError::SchemaMismatch("invalid Cashu recovery envelope".to_owned()))?;
    Ok(intent)
}

fn intent_insert_digest(intent: &NewCashuSwapIntentV1) -> [u8; 32] {
    mutation_digest(
        b"cashu-swap-prepare-v1",
        &[
            &intent.intent_id,
            &intent.mint_id,
            &intent.manifest_digest,
            intent.unit.as_bytes(),
            &intent.input_set_digest,
            &intent.request_digest,
            &intent.output_set_digest,
            &intent.offer_binding_digest,
            &intent.settlement_value.to_le_bytes(),
            &intent.expected_output_count.to_le_bytes(),
            &intent.sealed_recovery.key_epoch.to_le_bytes(),
            &intent.sealed_recovery.nonce,
            &intent.sealed_recovery.ciphertext,
            &intent.created_bucket.to_le_bytes(),
        ],
    )
}

fn transition_digest(
    intent_id: &[u8; 16],
    from: CashuSwapIntentStateV1,
    to: CashuSwapIntentStateV1,
    sealed: Option<&CashuSwapSealedRecoveryV1>,
    updated_bucket: u64,
) -> [u8; 32] {
    let from_bytes = (from as i64).to_le_bytes();
    let to_bytes = (to as i64).to_le_bytes();
    let key_epoch = sealed
        .map(|value| value.key_epoch)
        .unwrap_or(0)
        .to_le_bytes();
    let nonce = sealed.map(|value| value.nonce.as_slice()).unwrap_or(&[]);
    let ciphertext = sealed
        .map(|value| value.ciphertext.as_slice())
        .unwrap_or(&[]);
    mutation_digest(
        b"cashu-swap-transition-v1",
        &[
            intent_id,
            &from_bytes,
            &to_bytes,
            &key_epoch,
            nonce,
            ciphertext,
            &updated_bucket.to_le_bytes(),
        ],
    )
}

fn definite_rejection_delete_digest(intent: &CashuSwapIntentV1) -> [u8; 32] {
    mutation_digest(
        b"cashu-swap-definite-rejection-delete-v1",
        &[
            &intent.intent_id,
            &intent.mint_id,
            &intent.manifest_digest,
            intent.unit.as_bytes(),
            &intent.input_set_digest,
            &intent.request_digest,
            &intent.output_set_digest,
            &intent.offer_binding_digest,
            &intent.settlement_value.to_le_bytes(),
            &intent.expected_output_count.to_le_bytes(),
            &(intent.state as i64).to_le_bytes(),
            &intent.sealed_recovery.key_epoch.to_le_bytes(),
            &intent.sealed_recovery.nonce,
            &intent.sealed_recovery.ciphertext,
            &intent.created_bucket.to_le_bytes(),
            &intent.updated_bucket.to_le_bytes(),
        ],
    )
}

fn ensure_insert_within_exposure_limits(
    connection: &Connection,
    proposed: &NewCashuSwapIntentV1,
    limits: CashuCustodyExposureLimitsV1,
) -> StoreResult<()> {
    validate_exposure_limits(limits)?;
    let inventory = read_custody_inventory(connection, &proposed.mint_id, &proposed.unit)?;
    let current_value = inventory
        .pending_intent_value
        .checked_add(inventory.available_value)
        .and_then(|value| value.checked_add(inventory.reserved_value))
        .and_then(|value| value.checked_add(inventory.acknowledged_value))
        .ok_or(StoreError::CashuCustodyExposureExceeded)?;
    let current_notes = inventory
        .pending_intent_notes
        .checked_add(inventory.available_notes)
        .and_then(|value| value.checked_add(inventory.reserved_notes))
        .and_then(|value| value.checked_add(inventory.acknowledged_notes))
        .ok_or(StoreError::CashuCustodyExposureExceeded)?;
    let next_value = current_value
        .checked_add(proposed.settlement_value)
        .ok_or(StoreError::CashuCustodyExposureExceeded)?;
    let next_notes = current_notes
        .checked_add(u64::from(proposed.expected_output_count))
        .ok_or(StoreError::CashuCustodyExposureExceeded)?;
    if next_value > limits.max_unsettled_value || next_notes > limits.max_unsettled_notes {
        return Err(StoreError::CashuCustodyExposureExceeded);
    }
    Ok(())
}

fn validate_exposure_limits(limits: CashuCustodyExposureLimitsV1) -> StoreResult<()> {
    const SQLITE_MAX: u64 = i64::MAX as u64;
    if limits.max_unsettled_value == 0
        || limits.max_unsettled_notes == 0
        || limits.max_unsettled_value > SQLITE_MAX
        || limits.max_unsettled_notes > SQLITE_MAX
    {
        return Err(StoreError::InvalidInput(
            "Cashu custody exposure limits must be in 1..=i64::MAX",
        ));
    }
    Ok(())
}

fn validate_new_custody_lot(lot: &NewCashuCustodyLotV1) -> StoreResult<()> {
    if is_zero(&lot.lot_id)
        || is_zero(&lot.manifest_digest)
        || is_zero(&lot.active_keyset_digest)
        || is_zero(&lot.note_set_digest)
    {
        return Err(StoreError::InvalidInput(
            "Cashu custody lot identity contains a zero sentinel",
        ));
    }
    if lot.note_ys.is_empty() || lot.note_ys.len() > MAX_CASHU_CUSTODY_NOTES_PER_LOT_V1 {
        return Err(StoreError::InvalidInput(
            "Cashu custody note count is outside its bounds",
        ));
    }
    validate_custody_sealed_blob(
        &lot.sealed_notes,
        MAX_CASHU_RECOVERY_CIPHERTEXT_BYTES_V1,
        "Cashu sealed note lot is outside its bounds",
    )
}

fn validate_new_export(export: &NewCashuCustodyExportV1) -> StoreResult<()> {
    if is_zero(&export.export_id) || is_zero(&export.mint_id) || is_zero(&export.recipient_key_id) {
        return Err(StoreError::InvalidInput(
            "Cashu export identity contains a zero sentinel",
        ));
    }
    validate_cashu_unit(&export.unit)?;
    if export.max_lots == 0
        || usize::try_from(export.max_lots).unwrap_or(usize::MAX) > MAX_CASHU_CUSTODY_EXPORT_LOTS_V1
    {
        return Err(StoreError::InvalidInput(
            "Cashu export lot limit is outside its bounds",
        ));
    }
    Ok(())
}

fn validate_custody_sealed_blob(
    sealed: &CashuCustodySealedBlobV1,
    max_ciphertext_bytes: usize,
    reason: &'static str,
) -> StoreResult<()> {
    if sealed.key_epoch == 0
        || sealed.nonce.is_empty()
        || sealed.nonce.len() > MAX_CASHU_RECOVERY_NONCE_BYTES_V1
        || sealed.ciphertext.is_empty()
        || sealed.ciphertext.len() > max_ciphertext_bytes
    {
        return Err(StoreError::InvalidInput(reason));
    }
    let _ = sql_integer(
        sealed.key_epoch,
        "Cashu custody key epoch exceeds SQLite integer range",
    )?;
    Ok(())
}

fn validate_export_artifact(artifact: &[u8]) -> StoreResult<()> {
    if artifact.is_empty() || artifact.len() > MAX_CASHU_CUSTODY_EXPORT_ARTIFACT_BYTES_V1 {
        return Err(StoreError::InvalidInput(
            "Cashu export artifact is outside its bounds",
        ));
    }
    Ok(())
}

fn custody_note_fingerprints(
    mint_id: &[u8; 32],
    note_ys: &[[u8; 33]],
) -> StoreResult<Vec<[u8; 32]>> {
    let mut fingerprints = Vec::with_capacity(note_ys.len());
    for note_y in note_ys {
        if !matches!(note_y[0], 0x02 | 0x03) {
            return Err(StoreError::InvalidInput(
                "Cashu custody Y is not a compressed curve point",
            ));
        }
        let mut hasher = Sha256::new();
        hasher.update(mint_id);
        hasher.update(note_y);
        fingerprints.push(hasher.finalize().into());
    }
    fingerprints.sort_unstable();
    if fingerprints.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(StoreError::InvalidInput(
            "Cashu custody lot contains a duplicate Y",
        ));
    }
    Ok(fingerprints)
}

fn read_custody_lot_by_id(
    connection: &Connection,
    lot_id: &[u8; 16],
) -> StoreResult<Option<CashuCustodyLotV1>> {
    read_custody_lot(connection, "WHERE lot_id = ?1", [lot_id.as_slice()])
}

fn read_custody_lot_by_intent(
    connection: &Connection,
    intent_id: &[u8; 16],
) -> StoreResult<Option<CashuCustodyLotV1>> {
    read_custody_lot(connection, "WHERE intent_id = ?1", [intent_id.as_slice()])
}

fn read_custody_lot<P: rusqlite::Params>(
    connection: &Connection,
    predicate: &str,
    parameters: P,
) -> StoreResult<Option<CashuCustodyLotV1>> {
    let sql = format!(
        "SELECT lot_id, mint_id, manifest_digest, active_keyset_digest,
                note_set_digest, unit, settlement_value, note_count, state,
                sealed_key_epoch, sealed_nonce, sealed_ciphertext
         FROM cashu_custody_lots {predicate}"
    );
    let raw: Option<RawCashuCustodyLotV1> = connection
        .query_row(&sql, parameters, |row| {
            // Guard sealed notes before any later column conversion can fail.
            let sealed_nonce = Zeroizing::new(row.get(10)?);
            let sealed_ciphertext = Zeroizing::new(row.get(11)?);
            Ok(RawCashuCustodyLotV1 {
                lot_id: row.get(0)?,
                mint_id: row.get(1)?,
                manifest_digest: row.get(2)?,
                active_keyset_digest: row.get(3)?,
                note_set_digest: row.get(4)?,
                unit: row.get(5)?,
                settlement_value: row.get(6)?,
                note_count: row.get(7)?,
                state: row.get(8)?,
                sealed_key_epoch: row.get(9)?,
                sealed_nonce,
                sealed_ciphertext,
            })
        })
        .optional()?;
    raw.map(|mut raw| {
        let lot = CashuCustodyLotV1 {
            lot_id: fixed_blob(raw.lot_id, "invalid Cashu custody lot id")?,
            mint_id: fixed_blob(raw.mint_id, "invalid Cashu custody mint id")?,
            manifest_digest: fixed_blob(
                raw.manifest_digest,
                "invalid Cashu custody manifest digest",
            )?,
            active_keyset_digest: fixed_blob(
                raw.active_keyset_digest,
                "invalid Cashu custody active keyset digest",
            )?,
            note_set_digest: fixed_blob(
                raw.note_set_digest,
                "invalid Cashu custody note set digest",
            )?,
            unit: raw.unit,
            settlement_value: db_u64(raw.settlement_value, "negative Cashu custody value")?,
            note_count: u32::try_from(raw.note_count).map_err(|_| {
                StoreError::SchemaMismatch("invalid Cashu custody note count".to_owned())
            })?,
            state: CashuCustodyLotStateV1::from_db(raw.state).ok_or_else(|| {
                StoreError::SchemaMismatch("invalid Cashu custody lot state".to_owned())
            })?,
            sealed_notes: CashuCustodySealedBlobV1 {
                key_epoch: db_u64(raw.sealed_key_epoch, "negative Cashu custody key epoch")?,
                nonce: std::mem::take(&mut *raw.sealed_nonce),
                ciphertext: std::mem::take(&mut *raw.sealed_ciphertext),
            },
        };
        if is_zero(&lot.lot_id)
            || is_zero(&lot.mint_id)
            || is_zero(&lot.manifest_digest)
            || is_zero(&lot.active_keyset_digest)
            || is_zero(&lot.note_set_digest)
            || lot.settlement_value == 0
            || lot.note_count == 0
            || usize::try_from(lot.note_count).unwrap_or(usize::MAX)
                > MAX_CASHU_CUSTODY_NOTES_PER_LOT_V1
        {
            return Err(StoreError::SchemaMismatch(
                "invalid Cashu custody lot".to_owned(),
            ));
        }
        validate_cashu_unit(&lot.unit)
            .map_err(|_| StoreError::SchemaMismatch("invalid Cashu custody unit".to_owned()))?;
        validate_custody_sealed_blob(
            &lot.sealed_notes,
            MAX_CASHU_RECOVERY_CIPHERTEXT_BYTES_V1,
            "invalid Cashu custody sealed notes",
        )
        .map_err(|_| StoreError::SchemaMismatch("invalid Cashu custody sealed notes".to_owned()))?;
        Ok(lot)
    })
    .transpose()
}

fn read_custody_note_fingerprints(
    connection: &Connection,
    lot_id: &[u8; 16],
) -> StoreResult<Vec<[u8; 32]>> {
    let mut statement = connection.prepare(
        "SELECT note_fingerprint FROM cashu_custody_notes
         WHERE lot_id = ?1 ORDER BY note_fingerprint",
    )?;
    let collected = statement
        .query_map([lot_id.as_slice()], |row| row.get::<_, Vec<u8>>(0))?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|raw| fixed_blob(raw, "invalid Cashu custody note fingerprint"))
        .collect();
    collected
}

fn read_custody_export(
    connection: &Connection,
    export_id: &[u8; 16],
) -> StoreResult<Option<CashuCustodyExportBatchV1>> {
    let raw: Option<RawCashuCustodyExportV1> = connection
        .query_row(
            "SELECT export_id, mint_id, unit, recipient_key_id,
                    requested_max_lots, lot_count, keyset_group_count, settlement_value,
                    note_count, state, artifact_digest, artifact
             FROM cashu_custody_export_batches WHERE export_id = ?1",
            [export_id.as_slice()],
            |row| {
                // Guard the recipient-sealed artifact before decoding the
                // remaining bookkeeping columns.
                let artifact = row.get::<_, Option<Vec<u8>>>(11)?.map(Zeroizing::new);
                Ok(RawCashuCustodyExportV1 {
                    export_id: row.get(0)?,
                    mint_id: row.get(1)?,
                    unit: row.get(2)?,
                    recipient_key_id: row.get(3)?,
                    requested_max_lots: row.get(4)?,
                    lot_count: row.get(5)?,
                    keyset_group_count: row.get(6)?,
                    settlement_value: row.get(7)?,
                    note_count: row.get(8)?,
                    state: row.get(9)?,
                    artifact_digest: row.get(10)?,
                    artifact,
                })
            },
        )
        .optional()?;
    raw.map(|raw| {
        let state = CashuCustodyExportStateV1::from_db(raw.state).ok_or_else(|| {
            StoreError::SchemaMismatch("invalid Cashu custody export state".to_owned())
        })?;
        let artifact = match (raw.artifact_digest, raw.artifact) {
            (None, None) if state == CashuCustodyExportStateV1::Reserved => None,
            (Some(digest), Some(mut bytes)) if state != CashuCustodyExportStateV1::Reserved => {
                validate_export_artifact(&bytes).map_err(|_| {
                    StoreError::SchemaMismatch("invalid Cashu export artifact".to_owned())
                })?;
                let digest: [u8; 32] = fixed_blob(digest, "invalid Cashu export artifact digest")?;
                if digest != <[u8; 32]>::from(Sha256::digest(bytes.as_slice())) {
                    return Err(StoreError::SchemaMismatch(
                        "Cashu export artifact digest mismatch".to_owned(),
                    ));
                }
                Some(CashuCustodyExportArtifactV1 {
                    digest,
                    bytes: std::mem::take(&mut *bytes),
                })
            }
            _ => {
                return Err(StoreError::SchemaMismatch(
                    "Cashu export artifact state mismatch".to_owned(),
                ))
            }
        };
        let batch = CashuCustodyExportBatchV1 {
            export_id: fixed_blob(raw.export_id, "invalid Cashu custody export id")?,
            mint_id: fixed_blob(raw.mint_id, "invalid Cashu custody export mint id")?,
            unit: raw.unit,
            recipient_key_id: fixed_blob(
                raw.recipient_key_id,
                "invalid Cashu export recipient key id",
            )?,
            requested_max_lots: u32::try_from(raw.requested_max_lots).map_err(|_| {
                StoreError::SchemaMismatch("invalid Cashu requested export lot count".to_owned())
            })?,
            lot_count: u32::try_from(raw.lot_count).map_err(|_| {
                StoreError::SchemaMismatch("invalid Cashu export lot count".to_owned())
            })?,
            keyset_group_count: u32::try_from(raw.keyset_group_count).map_err(|_| {
                StoreError::SchemaMismatch("invalid Cashu export keyset group count".to_owned())
            })?,
            settlement_value: db_u64(raw.settlement_value, "negative Cashu export value")?,
            note_count: db_u64(raw.note_count, "negative Cashu export note count")?,
            state,
            artifact,
        };
        if is_zero(&batch.export_id)
            || is_zero(&batch.mint_id)
            || is_zero(&batch.recipient_key_id)
            || batch.requested_max_lots == 0
            || usize::try_from(batch.requested_max_lots).unwrap_or(usize::MAX)
                > MAX_CASHU_CUSTODY_EXPORT_LOTS_V1
            || batch.lot_count == 0
            || batch.lot_count > batch.requested_max_lots
            || batch.keyset_group_count == 0
            || usize::try_from(batch.keyset_group_count).unwrap_or(usize::MAX)
                > MAX_CASHU_CUSTODY_EXPORT_KEYSET_GROUPS_V1
            || batch.settlement_value == 0
            || batch.note_count == 0
            || batch.note_count
                > u64::try_from(MAX_CASHU_CUSTODY_EXPORT_NOTES_V1).unwrap_or(u64::MAX)
        {
            return Err(StoreError::SchemaMismatch(
                "invalid Cashu custody export batch".to_owned(),
            ));
        }
        validate_cashu_unit(&batch.unit)
            .map_err(|_| StoreError::SchemaMismatch("invalid Cashu export unit".to_owned()))?;
        Ok(batch)
    })
    .transpose()
}

fn read_custody_export_lots(
    connection: &Connection,
    export_id: &[u8; 16],
) -> StoreResult<Vec<CashuCustodyLotV1>> {
    let lot_ids = {
        let mut statement = connection.prepare(
            "SELECT lot_id FROM cashu_custody_export_members
             WHERE export_id = ?1 ORDER BY member_index",
        )?;
        let collected = statement
            .query_map([export_id.as_slice()], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|raw| fixed_blob(raw, "invalid Cashu export member lot id"))
            .collect::<StoreResult<Vec<[u8; 16]>>>()?;
        collected
    };
    let mut lots = Vec::with_capacity(lot_ids.len());
    for lot_id in lot_ids {
        let lot = read_custody_lot_by_id(connection, &lot_id)?
            .ok_or(StoreError::CashuCustodyLotMissing)?;
        if lot.state != CashuCustodyLotStateV1::Reserved {
            return Err(StoreError::CashuCustodyStateConflict);
        }
        lots.push(lot);
    }
    Ok(lots)
}

fn read_custody_export_lots_in_state(
    connection: &Connection,
    batch: &CashuCustodyExportBatchV1,
    member_lot_ids: &[[u8; 16]],
    expected_state: CashuCustodyLotStateV1,
) -> StoreResult<Vec<CashuCustodyLotV1>> {
    let mut lots = RetirementLotsGuardV1(Vec::with_capacity(member_lot_ids.len()));
    for lot_id in member_lot_ids {
        let mut lot = read_custody_lot_by_id(connection, lot_id)?
            .ok_or(StoreError::CashuCustodyLotMissing)?;
        if lot.lot_id != *lot_id
            || lot.state != expected_state
            || lot.mint_id != batch.mint_id
            || lot.unit != batch.unit
            || lot.settlement_value == 0
            || lot.note_count == 0
        {
            lot.sealed_notes.nonce.zeroize();
            lot.sealed_notes.ciphertext.zeroize();
            return Err(StoreError::SchemaMismatch(
                "Cashu retirement snapshot member binding mismatch".to_owned(),
            ));
        }
        lots.0.push(lot);
    }
    if lots.0.len() != usize::try_from(batch.lot_count).unwrap_or(usize::MAX) {
        return Err(StoreError::SchemaMismatch(
            "Cashu retirement snapshot lot count mismatch".to_owned(),
        ));
    }
    Ok(lots.take())
}

fn require_export_members_in_state(
    connection: &Connection,
    export_id: &[u8; 16],
    expected_count: u32,
    expected_state: CashuCustodyLotStateV1,
) -> StoreResult<()> {
    let states = {
        let mut statement = connection.prepare(
            "SELECT lots.state
             FROM cashu_custody_export_members AS members
             JOIN cashu_custody_lots AS lots ON lots.lot_id = members.lot_id
             WHERE members.export_id = ?1 ORDER BY members.member_index",
        )?;
        let collected = statement
            .query_map([export_id.as_slice()], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        collected
    };
    if states.len() != usize::try_from(expected_count).unwrap_or(usize::MAX)
        || states
            .into_iter()
            .any(|state| state != expected_state as i64)
    {
        return Err(StoreError::CashuCustodyStateConflict);
    }
    Ok(())
}

fn validate_export_batch_members(
    connection: &Connection,
    batch: &CashuCustodyExportBatchV1,
) -> StoreResult<()> {
    type RawMember = (Vec<u8>, String, Vec<u8>, i64, i64, i64);
    let members = {
        let mut statement = connection.prepare(
            "SELECT lots.mint_id, lots.unit, lots.active_keyset_digest,
                    lots.settlement_value, lots.note_count, lots.state
             FROM cashu_custody_export_members AS members
             JOIN cashu_custody_lots AS lots ON lots.lot_id = members.lot_id
             WHERE members.export_id = ?1 ORDER BY members.member_index",
        )?;
        let collected = statement
            .query_map([batch.export_id.as_slice()], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            })?
            .collect::<Result<Vec<RawMember>, _>>()?;
        collected
    };
    let expected_state = match batch.state {
        CashuCustodyExportStateV1::Reserved | CashuCustodyExportStateV1::ArtifactStored => {
            CashuCustodyLotStateV1::Reserved
        }
        CashuCustodyExportStateV1::DeliveryAcknowledged => {
            CashuCustodyLotStateV1::DeliveryAcknowledged
        }
        CashuCustodyExportStateV1::SpentConfirmed => CashuCustodyLotStateV1::SpentConfirmed,
    };
    let mut value = 0_u64;
    let mut notes = 0_u64;
    let mut keysets = BTreeSet::new();
    for (raw_mint_id, unit, raw_keyset, raw_value, raw_notes, raw_state) in &members {
        let mint_id: [u8; 32] = fixed_blob(raw_mint_id.clone(), "invalid Cashu member mint id")?;
        let keyset: [u8; 32] = fixed_blob(
            raw_keyset.clone(),
            "invalid Cashu member active keyset digest",
        )?;
        if mint_id != batch.mint_id || unit != &batch.unit || *raw_state != expected_state as i64 {
            return Err(StoreError::SchemaMismatch(
                "Cashu export member cohort or state mismatch".to_owned(),
            ));
        }
        if is_zero(&keyset) {
            return Err(StoreError::SchemaMismatch(
                "Cashu export member keyset digest is zero".to_owned(),
            ));
        }
        let member_value = db_u64(*raw_value, "negative Cashu export member value")?;
        let member_notes = db_u64(*raw_notes, "negative Cashu export member note count")?;
        if member_value == 0
            || member_notes == 0
            || member_notes > u64::try_from(MAX_CASHU_CUSTODY_NOTES_PER_LOT_V1).unwrap_or(u64::MAX)
        {
            return Err(StoreError::SchemaMismatch(
                "Cashu export member value or note count is invalid".to_owned(),
            ));
        }
        keysets.insert(keyset);
        value = checked_aggregate_add(value, member_value, "Cashu export member value overflow")?;
        notes = checked_aggregate_add(
            notes,
            member_notes,
            "Cashu export member note count overflow",
        )?;
    }
    if u32::try_from(members.len()).ok() != Some(batch.lot_count)
        || u32::try_from(keysets.len()).ok() != Some(batch.keyset_group_count)
        || keysets.len() > MAX_CASHU_CUSTODY_EXPORT_KEYSET_GROUPS_V1
        || value != batch.settlement_value
        || notes != batch.note_count
        || notes > u64::try_from(MAX_CASHU_CUSTODY_EXPORT_NOTES_V1).unwrap_or(u64::MAX)
    {
        return Err(StoreError::SchemaMismatch(
            "Cashu export member aggregate mismatch".to_owned(),
        ));
    }
    Ok(())
}

struct DerivedRetirementEvidenceV1 {
    member_set_digest: [u8; 32],
    note_fingerprint_set_digest: [u8; 32],
    y_set_digest: [u8; 32],
    note_count: u64,
}

fn validate_spent_confirmation_request(
    request: &CashuCustodySpentConfirmationRequestV1,
) -> StoreResult<()> {
    if is_zero(&request.provider_id)
        || is_zero(&request.store_instance_id)
        || is_zero(&request.precondition_rollback_commitment)
        || is_zero(&request.export_id)
        || is_zero(&request.artifact_digest)
        || is_zero(&request.nut07_response_digest)
    {
        return Err(StoreError::InvalidInput(
            "Cashu spent confirmation contains a zero identity or digest",
        ));
    }
    let _ = sql_integer(
        request.precondition_store_generation,
        "Cashu spent-confirmation generation exceeds SQLite integer range",
    )?;
    let _ = sql_integer(
        request.precondition_spend_commit_seq,
        "Cashu spent-confirmation spend sequence exceeds SQLite integer range",
    )?;
    if request.precondition_spend_commit_seq > request.precondition_store_generation {
        return Err(StoreError::InvalidInput(
            "Cashu spent-confirmation spend sequence exceeds generation",
        ));
    }
    if request.member_lot_ids.is_empty()
        || request.member_lot_ids.len() > MAX_CASHU_CUSTODY_EXPORT_LOTS_V1
        || request.member_lot_ids.iter().any(|lot_id| is_zero(lot_id))
        || request
            .member_lot_ids
            .windows(2)
            .any(|pair| pair[0] == pair[1])
    {
        return Err(StoreError::InvalidInput(
            "Cashu spent-confirmation member list is invalid",
        ));
    }
    if request.note_checks.is_empty()
        || request.note_checks.len() > MAX_CASHU_CUSTODY_EXPORT_NOTES_V1
    {
        return Err(StoreError::InvalidInput(
            "Cashu spent-confirmation note count is outside its bounds",
        ));
    }
    if request
        .note_checks
        .iter()
        .any(|check| check.state != CashuCustodyRetirementNoteStateV1::Spent)
    {
        return Err(StoreError::CashuCustodyNotesNotFullySpent);
    }
    Ok(())
}

fn require_exact_retirement_floor(
    request: &CashuCustodySpentConfirmationRequestV1,
    identity: &crate::StoreIdentity,
) -> StoreResult<()> {
    if request.provider_id != identity.provider_id
        || request.store_instance_id != identity.store_instance_id
        || request.precondition_store_generation != identity.store_generation
        || request.precondition_spend_commit_seq != identity.spend_commit_seq
        || request.precondition_rollback_commitment != identity.rollback_commitment
    {
        return Err(StoreError::CashuCustodyRetirementFloorMismatch);
    }
    Ok(())
}

fn derive_retirement_evidence_inputs(
    connection: &Connection,
    export: &CashuCustodyExportBatchV1,
    request: &CashuCustodySpentConfirmationRequestV1,
) -> StoreResult<DerivedRetirementEvidenceV1> {
    let member_lot_ids = read_custody_export_member_ids(connection, &export.export_id)?;
    if member_lot_ids != request.member_lot_ids
        || member_lot_ids.len() != usize::try_from(export.lot_count).unwrap_or(usize::MAX)
    {
        return Err(StoreError::CashuCustodyRetirementEvidenceConflict);
    }

    let mut stored_fingerprints = Vec::new();
    for lot_id in &member_lot_ids {
        stored_fingerprints.extend(read_custody_note_fingerprints(connection, lot_id)?);
    }
    stored_fingerprints.sort_unstable();
    if stored_fingerprints
        .windows(2)
        .any(|pair| pair[0] == pair[1])
        || stored_fingerprints.len() != request.note_checks.len()
        || u64::try_from(stored_fingerprints.len()).ok() != Some(export.note_count)
    {
        return Err(StoreError::CashuCustodyRetirementEvidenceConflict);
    }

    let mut ys = Zeroizing::new(
        request
            .note_checks
            .iter()
            .map(|check| check.y)
            .collect::<Vec<_>>(),
    );
    ys.sort_unstable();
    if ys.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(StoreError::InvalidInput(
            "Cashu spent confirmation contains duplicate Y values",
        ));
    }
    let derived_fingerprints = custody_note_fingerprints(&export.mint_id, &ys)?;
    if derived_fingerprints != stored_fingerprints {
        return Err(StoreError::CashuCustodyRetirementEvidenceConflict);
    }

    Ok(DerivedRetirementEvidenceV1 {
        member_set_digest: digest_fixed_set_v1(
            b"BitcoinPIR/cashu-custody-retirement-members/v1",
            &member_lot_ids,
        ),
        note_fingerprint_set_digest: digest_fixed_set_v1(
            b"BitcoinPIR/cashu-custody-retirement-note-fingerprints/v1",
            &stored_fingerprints,
        ),
        y_set_digest: digest_fixed_set_v1(b"BitcoinPIR/cashu-custody-retirement-y-set/v1", &ys),
        note_count: export.note_count,
    })
}

fn read_custody_export_member_ids(
    connection: &Connection,
    export_id: &[u8; 16],
) -> StoreResult<Vec<[u8; 16]>> {
    let mut statement = connection.prepare(
        "SELECT member_index, lot_id FROM cashu_custody_export_members
         WHERE export_id = ?1 ORDER BY member_index",
    )?;
    let rows = statement
        .query_map([export_id.as_slice()], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .enumerate()
        .map(|(expected_index, (raw_index, raw_lot_id))| {
            if usize::try_from(raw_index).ok() != Some(expected_index) {
                return Err(StoreError::SchemaMismatch(
                    "Cashu export member index sequence is not canonical".to_owned(),
                ));
            }
            fixed_blob(raw_lot_id, "invalid Cashu export member lot id")
        })
        .collect()
}

fn digest_fixed_set_v1<const N: usize>(domain: &[u8], values: &[[u8; N]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((values.len() as u64).to_le_bytes());
    for value in values {
        hasher.update((N as u64).to_le_bytes());
        hasher.update(value);
    }
    hasher.finalize().into()
}

fn insert_retirement_evidence(
    connection: &Connection,
    evidence: &CashuCustodyRetirementEvidenceV1,
) -> StoreResult<()> {
    let inserted = connection.execute(
        "INSERT INTO cashu_custody_retirement_evidence (
            export_id, provider_id, store_instance_id,
            precondition_store_generation, precondition_spend_commit_seq,
            precondition_rollback_commitment, confirmed_store_generation,
            confirmed_spend_commit_seq, confirmed_rollback_commitment,
            artifact_digest, member_set_digest, note_fingerprint_set_digest,
            y_set_digest, nut07_response_digest, note_count, evidence_digest
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
            ?14, ?15, ?16
         )",
        params![
            evidence.export_id.as_slice(),
            evidence.provider_id.as_slice(),
            evidence.store_instance_id.as_slice(),
            sql_integer(
                evidence.precondition_store_generation,
                "Cashu retirement precondition generation exceeds SQLite range"
            )?,
            sql_integer(
                evidence.precondition_spend_commit_seq,
                "Cashu retirement precondition spend sequence exceeds SQLite range"
            )?,
            evidence.precondition_rollback_commitment.as_slice(),
            sql_integer(
                evidence.confirmed_store_generation,
                "Cashu retirement confirmed generation exceeds SQLite range"
            )?,
            sql_integer(
                evidence.confirmed_spend_commit_seq,
                "Cashu retirement confirmed spend sequence exceeds SQLite range"
            )?,
            evidence.confirmed_rollback_commitment.as_slice(),
            evidence.artifact_digest.as_slice(),
            evidence.member_set_digest.as_slice(),
            evidence.note_fingerprint_set_digest.as_slice(),
            evidence.y_set_digest.as_slice(),
            evidence.nut07_response_digest.as_slice(),
            sql_integer(
                evidence.note_count,
                "Cashu retirement note count exceeds SQLite range"
            )?,
            evidence.evidence_digest.as_slice(),
        ],
    )?;
    if inserted != 1 {
        return Err(StoreError::CashuCustodyRetirementEvidenceConflict);
    }
    Ok(())
}

fn read_retirement_evidence(
    connection: &Connection,
    export_id: &[u8; 16],
) -> StoreResult<Option<CashuCustodyRetirementEvidenceV1>> {
    type RawEvidence = (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
        i64,
        Vec<u8>,
        i64,
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
        Vec<u8>,
    );
    let raw: Option<RawEvidence> = connection
        .query_row(
            "SELECT export_id, provider_id, store_instance_id,
                    precondition_store_generation, precondition_spend_commit_seq,
                    precondition_rollback_commitment, confirmed_store_generation,
                    confirmed_spend_commit_seq, confirmed_rollback_commitment,
                    artifact_digest, member_set_digest, note_fingerprint_set_digest,
                    y_set_digest, nut07_response_digest, note_count, evidence_digest
             FROM cashu_custody_retirement_evidence WHERE export_id = ?1",
            [export_id.as_slice()],
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
                ))
            },
        )
        .optional()?;
    raw.map(|raw| {
        let evidence = CashuCustodyRetirementEvidenceV1 {
            export_id: fixed_blob(raw.0, "invalid Cashu retirement export id")?,
            provider_id: fixed_blob(raw.1, "invalid Cashu retirement provider id")?,
            store_instance_id: fixed_blob(raw.2, "invalid Cashu retirement store id")?,
            precondition_store_generation: db_u64(
                raw.3,
                "negative Cashu retirement precondition generation",
            )?,
            precondition_spend_commit_seq: db_u64(
                raw.4,
                "negative Cashu retirement precondition spend sequence",
            )?,
            precondition_rollback_commitment: fixed_blob(
                raw.5,
                "invalid Cashu retirement precondition commitment",
            )?,
            confirmed_store_generation: db_u64(
                raw.6,
                "negative Cashu retirement confirmed generation",
            )?,
            confirmed_spend_commit_seq: db_u64(
                raw.7,
                "negative Cashu retirement confirmed spend sequence",
            )?,
            confirmed_rollback_commitment: fixed_blob(
                raw.8,
                "invalid Cashu retirement confirmed commitment",
            )?,
            artifact_digest: fixed_blob(raw.9, "invalid Cashu retirement artifact digest")?,
            member_set_digest: fixed_blob(raw.10, "invalid Cashu retirement member digest")?,
            note_fingerprint_set_digest: fixed_blob(
                raw.11,
                "invalid Cashu retirement note-fingerprint digest",
            )?,
            y_set_digest: fixed_blob(raw.12, "invalid Cashu retirement Y-set digest")?,
            nut07_response_digest: fixed_blob(
                raw.13,
                "invalid Cashu retirement NUT-07 response digest",
            )?,
            note_count: db_u64(raw.14, "negative Cashu retirement note count")?,
            evidence_digest: fixed_blob(raw.15, "invalid Cashu retirement evidence digest")?,
        };
        validate_retirement_evidence_shape(&evidence)?;
        Ok(evidence)
    })
    .transpose()
}

fn validate_retirement_evidence_shape(
    evidence: &CashuCustodyRetirementEvidenceV1,
) -> StoreResult<()> {
    if is_zero(&evidence.export_id)
        || is_zero(&evidence.provider_id)
        || is_zero(&evidence.store_instance_id)
        || is_zero(&evidence.precondition_rollback_commitment)
        || is_zero(&evidence.confirmed_rollback_commitment)
        || is_zero(&evidence.artifact_digest)
        || is_zero(&evidence.member_set_digest)
        || is_zero(&evidence.note_fingerprint_set_digest)
        || is_zero(&evidence.y_set_digest)
        || is_zero(&evidence.nut07_response_digest)
        || is_zero(&evidence.evidence_digest)
        || evidence.precondition_spend_commit_seq > evidence.precondition_store_generation
        || evidence.confirmed_store_generation
            != evidence.precondition_store_generation.saturating_add(1)
        || evidence.confirmed_spend_commit_seq != evidence.precondition_spend_commit_seq
        || evidence.confirmed_rollback_commitment == evidence.precondition_rollback_commitment
        || evidence.note_count == 0
        || evidence.note_count
            > u64::try_from(MAX_CASHU_CUSTODY_EXPORT_NOTES_V1).unwrap_or(u64::MAX)
        || crate::rollback::next_commitment(
            &evidence.precondition_rollback_commitment,
            evidence.confirmed_store_generation,
            b"cashu-custody-export-spent-confirmed-v1",
            &custody_export_spent_confirmation_digest_from_evidence(evidence),
        ) != evidence.confirmed_rollback_commitment
        || retirement_evidence_digest_from_fields(evidence) != evidence.evidence_digest
    {
        return Err(StoreError::SchemaMismatch(
            "invalid Cashu custody retirement evidence".to_owned(),
        ));
    }
    Ok(())
}

fn validate_exact_retirement_replay(
    request: &CashuCustodySpentConfirmationRequestV1,
    derived: &DerivedRetirementEvidenceV1,
    evidence: &CashuCustodyRetirementEvidenceV1,
) -> StoreResult<()> {
    validate_retirement_evidence_shape(evidence)?;
    if evidence.export_id != request.export_id
        || evidence.provider_id != request.provider_id
        || evidence.store_instance_id != request.store_instance_id
        || evidence.precondition_store_generation != request.precondition_store_generation
        || evidence.precondition_spend_commit_seq != request.precondition_spend_commit_seq
        || evidence.precondition_rollback_commitment != request.precondition_rollback_commitment
        || evidence.artifact_digest != request.artifact_digest
        || evidence.member_set_digest != derived.member_set_digest
        || evidence.note_fingerprint_set_digest != derived.note_fingerprint_set_digest
        || evidence.y_set_digest != derived.y_set_digest
        || evidence.nut07_response_digest != request.nut07_response_digest
        || evidence.note_count != derived.note_count
    {
        return Err(StoreError::CashuCustodyRetirementEvidenceConflict);
    }
    Ok(())
}

fn validate_persisted_retirement_evidence(
    connection: &Connection,
    export: &CashuCustodyExportBatchV1,
    evidence: &CashuCustodyRetirementEvidenceV1,
) -> StoreResult<()> {
    validate_retirement_evidence_shape(evidence)?;
    let identity = read_identity(connection)?;
    let member_lot_ids = read_custody_export_member_ids(connection, &export.export_id)?;
    let mut fingerprints = Vec::new();
    for lot_id in &member_lot_ids {
        fingerprints.extend(read_custody_note_fingerprints(connection, lot_id)?);
    }
    fingerprints.sort_unstable();
    if evidence.export_id != export.export_id
        || evidence.provider_id != identity.provider_id
        || evidence.store_instance_id != identity.store_instance_id
        || identity.store_generation < evidence.confirmed_store_generation
        || identity.spend_commit_seq < evidence.confirmed_spend_commit_seq
        || (identity.store_generation == evidence.confirmed_store_generation
            && identity.rollback_commitment != evidence.confirmed_rollback_commitment)
        || export.artifact.as_ref().map(|artifact| artifact.digest)
            != Some(evidence.artifact_digest)
        || digest_fixed_set_v1(
            b"BitcoinPIR/cashu-custody-retirement-members/v1",
            &member_lot_ids,
        ) != evidence.member_set_digest
        || digest_fixed_set_v1(
            b"BitcoinPIR/cashu-custody-retirement-note-fingerprints/v1",
            &fingerprints,
        ) != evidence.note_fingerprint_set_digest
        || u64::try_from(fingerprints.len()).ok() != Some(evidence.note_count)
        || evidence.note_count != export.note_count
    {
        return Err(StoreError::SchemaMismatch(
            "Cashu retirement evidence binding mismatch".to_owned(),
        ));
    }
    Ok(())
}

fn validate_retirement_evidence_state(
    connection: &Connection,
    export: &CashuCustodyExportBatchV1,
) -> StoreResult<()> {
    let evidence = read_retirement_evidence(connection, &export.export_id)?;
    match (export.state, evidence.as_ref()) {
        (CashuCustodyExportStateV1::SpentConfirmed, Some(evidence)) => {
            validate_persisted_retirement_evidence(connection, export, evidence)
        }
        (CashuCustodyExportStateV1::SpentConfirmed, None) => {
            Err(StoreError::CashuCustodyRetirementEvidenceMissing)
        }
        (_, None) => Ok(()),
        (_, Some(_)) => Err(StoreError::SchemaMismatch(
            "Cashu retirement evidence exists before terminal state".to_owned(),
        )),
    }
}

fn retirement_evidence_digest_from_fields(evidence: &CashuCustodyRetirementEvidenceV1) -> [u8; 32] {
    mutation_digest(
        b"cashu-custody-retirement-evidence-v1",
        &[
            &evidence.export_id,
            &evidence.provider_id,
            &evidence.store_instance_id,
            &evidence.precondition_store_generation.to_le_bytes(),
            &evidence.precondition_spend_commit_seq.to_le_bytes(),
            &evidence.precondition_rollback_commitment,
            &evidence.confirmed_store_generation.to_le_bytes(),
            &evidence.confirmed_spend_commit_seq.to_le_bytes(),
            &evidence.confirmed_rollback_commitment,
            &evidence.artifact_digest,
            &evidence.member_set_digest,
            &evidence.note_fingerprint_set_digest,
            &evidence.y_set_digest,
            &evidence.nut07_response_digest,
            &evidence.note_count.to_le_bytes(),
        ],
    )
}

fn retirement_evidence_digest(
    request: &CashuCustodySpentConfirmationRequestV1,
    member_set_digest: &[u8; 32],
    note_fingerprint_set_digest: &[u8; 32],
    y_set_digest: &[u8; 32],
    note_count: u64,
    confirmed_rollback_commitment: &[u8; 32],
) -> [u8; 32] {
    let evidence = CashuCustodyRetirementEvidenceV1 {
        export_id: request.export_id,
        provider_id: request.provider_id,
        store_instance_id: request.store_instance_id,
        precondition_store_generation: request.precondition_store_generation,
        precondition_spend_commit_seq: request.precondition_spend_commit_seq,
        precondition_rollback_commitment: request.precondition_rollback_commitment,
        confirmed_store_generation: request.precondition_store_generation.saturating_add(1),
        confirmed_spend_commit_seq: request.precondition_spend_commit_seq,
        confirmed_rollback_commitment: *confirmed_rollback_commitment,
        artifact_digest: request.artifact_digest,
        member_set_digest: *member_set_digest,
        note_fingerprint_set_digest: *note_fingerprint_set_digest,
        y_set_digest: *y_set_digest,
        nut07_response_digest: request.nut07_response_digest,
        note_count,
        evidence_digest: [0; 32],
    };
    retirement_evidence_digest_from_fields(&evidence)
}

fn custody_export_spent_confirmation_digest(
    request: &CashuCustodySpentConfirmationRequestV1,
    member_set_digest: &[u8; 32],
    note_fingerprint_set_digest: &[u8; 32],
    y_set_digest: &[u8; 32],
    note_count: u64,
) -> [u8; 32] {
    mutation_digest(
        b"cashu-custody-export-spent-confirmed-v1",
        &[
            &request.provider_id,
            &request.store_instance_id,
            &request.precondition_store_generation.to_le_bytes(),
            &request.precondition_spend_commit_seq.to_le_bytes(),
            &request.precondition_rollback_commitment,
            &request.export_id,
            &request.artifact_digest,
            member_set_digest,
            note_fingerprint_set_digest,
            y_set_digest,
            &request.nut07_response_digest,
            &note_count.to_le_bytes(),
        ],
    )
}

fn custody_export_spent_confirmation_digest_from_evidence(
    evidence: &CashuCustodyRetirementEvidenceV1,
) -> [u8; 32] {
    mutation_digest(
        b"cashu-custody-export-spent-confirmed-v1",
        &[
            &evidence.provider_id,
            &evidence.store_instance_id,
            &evidence.precondition_store_generation.to_le_bytes(),
            &evidence.precondition_spend_commit_seq.to_le_bytes(),
            &evidence.precondition_rollback_commitment,
            &evidence.export_id,
            &evidence.artifact_digest,
            &evidence.member_set_digest,
            &evidence.note_fingerprint_set_digest,
            &evidence.y_set_digest,
            &evidence.nut07_response_digest,
            &evidence.note_count.to_le_bytes(),
        ],
    )
}

fn read_custody_inventory(
    connection: &Connection,
    mint_id: &[u8; 32],
    unit: &str,
) -> StoreResult<CashuCustodyInventoryV1> {
    validate_custody_relational_invariants(connection, mint_id, unit)?;
    let mut inventory = CashuCustodyInventoryV1 {
        pending_intent_value: 0,
        pending_intent_notes: 0,
        available_lot_count: 0,
        available_value: 0,
        available_notes: 0,
        reserved_lot_count: 0,
        reserved_value: 0,
        reserved_notes: 0,
        acknowledged_lot_count: 0,
        acknowledged_value: 0,
        acknowledged_notes: 0,
        spent_confirmed_lot_count: 0,
        spent_confirmed_value: 0,
        spent_confirmed_notes: 0,
        reserved_export_count: 0,
        materialized_export_count: 0,
        acknowledged_export_count: 0,
        spent_confirmed_export_count: 0,
    };
    {
        let mut statement = connection.prepare(
            "SELECT settlement_value, expected_output_count
             FROM cashu_swap_intents
             WHERE mint_id = ?1 AND unit = ?2 AND state != 3",
        )?;
        let rows = statement
            .query_map(params![mint_id.as_slice(), unit], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for (value, notes) in rows {
            inventory.pending_intent_value = checked_aggregate_add(
                inventory.pending_intent_value,
                db_u64(value, "negative Cashu pending intent value")?,
                "Cashu pending intent value overflow",
            )?;
            inventory.pending_intent_notes = checked_aggregate_add(
                inventory.pending_intent_notes,
                db_u64(notes, "negative Cashu pending intent note count")?,
                "Cashu pending intent note count overflow",
            )?;
        }
    }
    {
        let mut statement = connection.prepare(
            "SELECT settlement_value, note_count, state FROM cashu_custody_lots
             WHERE mint_id = ?1 AND unit = ?2",
        )?;
        let rows = statement
            .query_map(params![mint_id.as_slice(), unit], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for (value, notes, state) in rows {
            let value = db_u64(value, "negative Cashu custody value")?;
            let notes = db_u64(notes, "negative Cashu custody note count")?;
            match CashuCustodyLotStateV1::from_db(state).ok_or_else(|| {
                StoreError::SchemaMismatch("invalid Cashu custody lot state".to_owned())
            })? {
                CashuCustodyLotStateV1::Available => {
                    inventory.available_lot_count = checked_aggregate_add(
                        inventory.available_lot_count,
                        1,
                        "Cashu available lot count overflow",
                    )?;
                    inventory.available_value = checked_aggregate_add(
                        inventory.available_value,
                        value,
                        "Cashu available value overflow",
                    )?;
                    inventory.available_notes = checked_aggregate_add(
                        inventory.available_notes,
                        notes,
                        "Cashu available note count overflow",
                    )?;
                }
                CashuCustodyLotStateV1::Reserved => {
                    inventory.reserved_lot_count = checked_aggregate_add(
                        inventory.reserved_lot_count,
                        1,
                        "Cashu reserved lot count overflow",
                    )?;
                    inventory.reserved_value = checked_aggregate_add(
                        inventory.reserved_value,
                        value,
                        "Cashu reserved value overflow",
                    )?;
                    inventory.reserved_notes = checked_aggregate_add(
                        inventory.reserved_notes,
                        notes,
                        "Cashu reserved note count overflow",
                    )?;
                }
                CashuCustodyLotStateV1::DeliveryAcknowledged => {
                    inventory.acknowledged_lot_count = checked_aggregate_add(
                        inventory.acknowledged_lot_count,
                        1,
                        "Cashu acknowledged lot count overflow",
                    )?;
                    inventory.acknowledged_value = checked_aggregate_add(
                        inventory.acknowledged_value,
                        value,
                        "Cashu acknowledged value overflow",
                    )?;
                    inventory.acknowledged_notes = checked_aggregate_add(
                        inventory.acknowledged_notes,
                        notes,
                        "Cashu acknowledged note count overflow",
                    )?;
                }
                CashuCustodyLotStateV1::SpentConfirmed => {
                    inventory.spent_confirmed_lot_count = checked_aggregate_add(
                        inventory.spent_confirmed_lot_count,
                        1,
                        "Cashu spent-confirmed lot count overflow",
                    )?;
                    inventory.spent_confirmed_value = checked_aggregate_add(
                        inventory.spent_confirmed_value,
                        value,
                        "Cashu spent-confirmed value overflow",
                    )?;
                    inventory.spent_confirmed_notes = checked_aggregate_add(
                        inventory.spent_confirmed_notes,
                        notes,
                        "Cashu spent-confirmed note count overflow",
                    )?;
                }
            }
        }
    }
    {
        let mut statement = connection.prepare(
            "SELECT state FROM cashu_custody_export_batches
             WHERE mint_id = ?1 AND unit = ?2",
        )?;
        let states = statement
            .query_map(params![mint_id.as_slice(), unit], |row| {
                row.get::<_, i64>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for state in states {
            match CashuCustodyExportStateV1::from_db(state).ok_or_else(|| {
                StoreError::SchemaMismatch("invalid Cashu custody export state".to_owned())
            })? {
                CashuCustodyExportStateV1::Reserved => {
                    inventory.reserved_export_count = checked_aggregate_add(
                        inventory.reserved_export_count,
                        1,
                        "Cashu reserved export count overflow",
                    )?;
                }
                CashuCustodyExportStateV1::ArtifactStored => {
                    inventory.materialized_export_count = checked_aggregate_add(
                        inventory.materialized_export_count,
                        1,
                        "Cashu materialized export count overflow",
                    )?;
                }
                CashuCustodyExportStateV1::DeliveryAcknowledged => {
                    inventory.acknowledged_export_count = checked_aggregate_add(
                        inventory.acknowledged_export_count,
                        1,
                        "Cashu acknowledged export count overflow",
                    )?;
                }
                CashuCustodyExportStateV1::SpentConfirmed => {
                    inventory.spent_confirmed_export_count = checked_aggregate_add(
                        inventory.spent_confirmed_export_count,
                        1,
                        "Cashu spent-confirmed export count overflow",
                    )?;
                }
            }
        }
    }
    Ok(inventory)
}

fn validate_custody_relational_invariants(
    connection: &Connection,
    mint_id: &[u8; 32],
    unit: &str,
) -> StoreResult<()> {
    let broken_intent_lot: bool = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM cashu_swap_intents AS intents
            LEFT JOIN cashu_custody_lots AS lots ON lots.intent_id = intents.intent_id
            WHERE intents.mint_id = ?1 AND intents.unit = ?2 AND (
                (intents.state = 3 AND lots.lot_id IS NULL)
                OR (intents.state != 3 AND lots.lot_id IS NOT NULL)
                OR (lots.lot_id IS NOT NULL AND (
                    lots.mint_id != intents.mint_id OR lots.unit != intents.unit
                    OR lots.manifest_digest != intents.manifest_digest
                    OR lots.active_keyset_digest = zeroblob(32)
                    OR lots.note_set_digest = zeroblob(32)
                    OR lots.settlement_value != intents.settlement_value
                    OR lots.note_count != intents.expected_output_count
                ))
            )
         )",
        params![mint_id.as_slice(), unit],
        |row| row.get(0),
    )?;
    let broken_note_count: bool = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM cashu_custody_lots AS lots
            WHERE lots.mint_id = ?1 AND lots.unit = ?2
              AND lots.note_count != (
                SELECT COUNT(*) FROM cashu_custody_notes AS notes
                WHERE notes.lot_id = lots.lot_id
              )
         )",
        params![mint_id.as_slice(), unit],
        |row| row.get(0),
    )?;
    if broken_intent_lot || broken_note_count {
        return Err(StoreError::SchemaMismatch(
            "Cashu custody relational invariant failed".to_owned(),
        ));
    }

    let export_ids = {
        let mut statement = connection.prepare(
            "SELECT export_id
             FROM cashu_custody_export_batches WHERE mint_id = ?1 AND unit = ?2",
        )?;
        let collected = statement
            .query_map(params![mint_id.as_slice(), unit], |row| {
                row.get::<_, Vec<u8>>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        collected
    };
    for raw_export_id in export_ids {
        let export_id: [u8; 16] = fixed_blob(raw_export_id, "invalid Cashu export id")?;
        let batch = read_custody_export(connection, &export_id)?.ok_or_else(|| {
            StoreError::SchemaMismatch("Cashu export disappeared during validation".to_owned())
        })?;
        validate_export_batch_members(connection, &batch)?;
        validate_retirement_evidence_state(connection, &batch)?;
    }
    Ok(())
}

fn checked_aggregate_add(current: u64, added: u64, reason: &'static str) -> StoreResult<u64> {
    current
        .checked_add(added)
        .ok_or_else(|| StoreError::SchemaMismatch(reason.to_owned()))
}

fn custody_grant_digest(
    intent: &CashuSwapIntentV1,
    lot: &NewCashuCustodyLotV1,
    note_fingerprints: &[[u8; 32]],
    updated_bucket: u64,
) -> [u8; 32] {
    let settlement_value = intent.settlement_value.to_le_bytes();
    let output_count = intent.expected_output_count.to_le_bytes();
    let key_epoch = lot.sealed_notes.key_epoch.to_le_bytes();
    let updated_bucket = updated_bucket.to_le_bytes();
    let mut parts: Vec<&[u8]> = vec![
        &intent.intent_id,
        &lot.lot_id,
        &intent.mint_id,
        &lot.manifest_digest,
        &lot.active_keyset_digest,
        &lot.note_set_digest,
        intent.unit.as_bytes(),
        &settlement_value,
        &output_count,
        &key_epoch,
        &lot.sealed_notes.nonce,
        &lot.sealed_notes.ciphertext,
        &updated_bucket,
    ];
    parts.extend(note_fingerprints.iter().map(|value| value.as_slice()));
    mutation_digest(b"cashu-swap-grant-custody-v1", &parts)
}

fn custody_export_reserve_digest(
    export: &NewCashuCustodyExportV1,
    lot_ids: &[[u8; 16]],
    keyset_group_count: u32,
    settlement_value: u64,
    note_count: u64,
) -> [u8; 32] {
    let max_lots = export.max_lots.to_le_bytes();
    let keyset_group_count = keyset_group_count.to_le_bytes();
    let settlement_value = settlement_value.to_le_bytes();
    let note_count = note_count.to_le_bytes();
    let mut parts: Vec<&[u8]> = vec![
        &export.export_id,
        &export.mint_id,
        export.unit.as_bytes(),
        &export.recipient_key_id,
        &max_lots,
        &keyset_group_count,
        &settlement_value,
        &note_count,
    ];
    parts.extend(lot_ids.iter().map(|value| value.as_slice()));
    mutation_digest(b"cashu-custody-export-reserve-v1", &parts)
}

fn custody_export_artifact_digest(
    export: &CashuCustodyExportBatchV1,
    artifact_digest: &[u8; 32],
    artifact: &[u8],
) -> [u8; 32] {
    mutation_digest(
        b"cashu-custody-export-artifact-v1",
        &[
            &export.export_id,
            &export.recipient_key_id,
            artifact_digest,
            artifact,
        ],
    )
}

fn custody_export_ack_digest(
    export: &CashuCustodyExportBatchV1,
    artifact_digest: &[u8; 32],
) -> [u8; 32] {
    mutation_digest(
        b"cashu-custody-export-ack-v1",
        &[
            &export.export_id,
            &export.recipient_key_id,
            artifact_digest,
            &export.lot_count.to_le_bytes(),
            &export.keyset_group_count.to_le_bytes(),
            &export.settlement_value.to_le_bytes(),
            &export.note_count.to_le_bytes(),
        ],
    )
}

#[cfg(test)]
mod sensitive_row_tests {
    use super::*;

    #[test]
    fn raw_sensitive_sqlite_rows_are_drop_types_and_decode_fails_closed() {
        assert!(std::mem::needs_drop::<RawCashuSwapIntentV1>());
        assert!(std::mem::needs_drop::<RawCashuCustodyLotV1>());
        assert!(std::mem::needs_drop::<RawCashuCustodyExportV1>());

        let raw = RawCashuSwapIntentV1 {
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
            state: CashuSwapIntentStateV1::Prepared as i64,
            recovery_key_epoch: 1,
            recovery_nonce: Zeroizing::new(b"sensitive-recovery-nonce".to_vec()),
            recovery_ciphertext: Zeroizing::new(b"sensitive-recovery-ciphertext".to_vec()),
            created_bucket: 1,
            updated_bucket: 1,
        };
        assert!(matches!(
            decode_intent(raw),
            Err(StoreError::SchemaMismatch(_))
        ));

        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE cashu_custody_lots (
                    lot_id BLOB, mint_id BLOB, manifest_digest BLOB,
                    active_keyset_digest BLOB, note_set_digest BLOB, unit TEXT,
                    settlement_value INTEGER, note_count INTEGER, state INTEGER,
                    sealed_key_epoch INTEGER, sealed_nonce BLOB, sealed_ciphertext BLOB
                 );
                 CREATE TABLE cashu_custody_export_batches (
                    export_id BLOB, mint_id BLOB, unit TEXT, recipient_key_id BLOB,
                    requested_max_lots INTEGER, lot_count INTEGER,
                    keyset_group_count INTEGER, settlement_value INTEGER,
                    note_count INTEGER, state INTEGER, artifact_digest BLOB, artifact BLOB
                 );",
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO cashu_custody_lots VALUES
                 (?1, ?2, ?3, ?4, ?5, 'sat', 1, 1, 1, 1, ?6, ?7)",
                rusqlite::params![
                    vec![1_u8; 15],
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
            read_custody_lot(&connection, "", rusqlite::params![]),
            Err(StoreError::SchemaMismatch(_))
        ));

        let export_id = [8_u8; 16];
        let artifact = b"sensitive-recipient-sealed-artifact";
        let artifact_digest = Sha256::digest(artifact).to_vec();
        connection
            .execute(
                "INSERT INTO cashu_custody_export_batches VALUES
                 (?1, ?2, 'sat', ?3, 1, 1, 1, 1, 1, 2, ?4, ?5)",
                rusqlite::params![
                    export_id.as_slice(),
                    vec![9_u8; 31],
                    vec![10_u8; 32],
                    artifact_digest,
                    artifact.as_slice(),
                ],
            )
            .unwrap();
        assert!(matches!(
            read_custody_export(&connection, &export_id),
            Err(StoreError::SchemaMismatch(_))
        ));
    }
}
