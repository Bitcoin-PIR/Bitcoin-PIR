//! Rollback-protected standard Cashu merchant swap persistence.
//!
//! This module stores only public digests, coarse time buckets, and opaque
//! externally authenticated recovery ciphertext. It does not verify Cashu
//! proofs and does not duplicate the external mint's authoritative spent-set.

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::{
    advance_store_generation, db_u64, fixed_blob, is_zero, mutation_digest, read_identity,
    sql_integer, verify_expected_provider, CashuSwapIntentInsertV1, CashuSwapIntentStateV1,
    CashuSwapIntentV1, CashuSwapSealedRecoveryV1, NewCashuSwapIntentV1, ProviderStore, StoreError,
    StoreResult, MAX_CASHU_RECOVERY_CIPHERTEXT_BYTES_V1, MAX_CASHU_RECOVERY_NONCE_BYTES_V1,
};

type RawCashuSwapIntentV1 = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    i64,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
);

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
    ) -> StoreResult<CashuSwapIntentInsertV1> {
        validate_new_intent(proposed)?;
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

        transaction.execute(
            "INSERT INTO cashu_swap_intents (
                intent_id, mint_id, input_set_digest, request_digest,
                output_set_digest, offer_binding_digest, settlement_value,
                state, recovery_key_epoch, recovery_nonce, recovery_ciphertext,
                created_bucket, updated_bucket
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8, ?9, ?10, ?11, ?11)",
            params![
                proposed.intent_id.as_slice(),
                proposed.mint_id.as_slice(),
                proposed.input_set_digest.as_slice(),
                proposed.request_digest.as_slice(),
                proposed.output_set_digest.as_slice(),
                proposed.offer_binding_digest.as_slice(),
                sql_integer(
                    proposed.settlement_value,
                    "Cashu settlement value exceeds SQLite integer range"
                )?,
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
        self.anchor_committed_identity(&previous_floor, &committed_identity)?;
        Ok(CashuSwapIntentInsertV1 {
            inserted: true,
            intent: CashuSwapIntentV1 {
                intent_id: proposed.intent_id,
                mint_id: proposed.mint_id,
                input_set_digest: proposed.input_set_digest,
                request_digest: proposed.request_digest,
                output_set_digest: proposed.output_set_digest,
                offer_binding_digest: proposed.offer_binding_digest,
                settlement_value: proposed.settlement_value,
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

    /// Claim service delivery once. This is the only Cashu intent mutation
    /// that advances `spend_commit_seq`; the mint remains authoritative for
    /// input invalidation while ProviderStore is authoritative for grant
    /// delivery.
    pub fn claim_cashu_swap_grant_once_v1(
        &self,
        intent_id: &[u8; 16],
        updated_bucket: u64,
    ) -> StoreResult<bool> {
        self.transition_cashu_swap_state_v1(
            intent_id,
            &[CashuSwapIntentStateV1::WalletStored],
            CashuSwapIntentStateV1::GrantIssued,
            None,
            updated_bucket,
            b"cashu-swap-grant-v1",
            true,
        )
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
        self.anchor_committed_identity(&previous_floor, &committed_identity)?;
        Ok(true)
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
        "SELECT intent_id, mint_id, input_set_digest, request_digest,
                output_set_digest, offer_binding_digest, settlement_value,
                state, recovery_key_epoch, recovery_nonce, recovery_ciphertext,
                created_bucket, updated_bucket
         FROM cashu_swap_intents {predicate}"
    );
    let raw: Option<RawCashuSwapIntentV1> = connection
        .query_row(&sql, parameters, |row| {
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
            ))
        })
        .optional()?;
    raw.map(decode_intent).transpose()
}

fn decode_intent(raw: RawCashuSwapIntentV1) -> StoreResult<CashuSwapIntentV1> {
    let intent = CashuSwapIntentV1 {
        intent_id: fixed_blob(raw.0, "invalid Cashu intent id")?,
        mint_id: fixed_blob(raw.1, "invalid Cashu mint id")?,
        input_set_digest: fixed_blob(raw.2, "invalid Cashu input digest")?,
        request_digest: fixed_blob(raw.3, "invalid Cashu request digest")?,
        output_set_digest: fixed_blob(raw.4, "invalid Cashu output digest")?,
        offer_binding_digest: fixed_blob(raw.5, "invalid Cashu offer binding digest")?,
        settlement_value: db_u64(raw.6, "negative Cashu settlement value")?,
        state: CashuSwapIntentStateV1::from_db(raw.7)
            .ok_or_else(|| StoreError::SchemaMismatch("invalid Cashu intent state".to_owned()))?,
        sealed_recovery: CashuSwapSealedRecoveryV1 {
            key_epoch: db_u64(raw.8, "negative Cashu recovery key epoch")?,
            nonce: raw.9,
            ciphertext: raw.10,
        },
        created_bucket: db_u64(raw.11, "negative Cashu created bucket")?,
        updated_bucket: db_u64(raw.12, "negative Cashu updated bucket")?,
    };
    if is_zero(&intent.intent_id)
        || is_zero(&intent.mint_id)
        || is_zero(&intent.input_set_digest)
        || is_zero(&intent.request_digest)
        || is_zero(&intent.output_set_digest)
        || is_zero(&intent.offer_binding_digest)
        || intent.settlement_value == 0
        || intent.updated_bucket < intent.created_bucket
    {
        return Err(StoreError::SchemaMismatch(
            "Cashu intent contains an invalid sentinel or bucket".to_owned(),
        ));
    }
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
            &intent.input_set_digest,
            &intent.request_digest,
            &intent.output_set_digest,
            &intent.offer_binding_digest,
            &intent.settlement_value.to_le_bytes(),
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
