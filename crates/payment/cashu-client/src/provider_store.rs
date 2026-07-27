//! Production `CashuSwapStoreV1` adapter backed by ProviderStore schema v7.

use pir_service_store::{
    CashuCustodyExposureLimitsV1 as DurableExposureLimits,
    CashuCustodySealedBlobV1 as DurableCustodySealed, CashuSwapGrantClaimV1 as DurableGrantClaim,
    CashuSwapIntentStateV1 as DurableState, CashuSwapIntentV1 as DurableIntent,
    CashuSwapSealedRecoveryV1 as DurableSealed, NewCashuCustodyLotV1 as DurableNewCustodyLot,
    NewCashuSwapIntentV1 as DurableNewIntent, ProviderStore, StoreError,
};

use crate::{
    CashuCustodyExposureLimitsV1, CashuSealedCustodyV1, CashuSealedRecoveryV1,
    CashuSwapGrantClaimV1, CashuSwapStateV1, CashuSwapStoreErrorV1, CashuSwapStoreV1,
    InsertCashuSwapIntentResultV1, NewCashuCustodyLotV1, NewCashuSwapIntentV1,
    StoredCashuCustodyLotV1, StoredCashuSwapIntentV1,
};

impl CashuSwapStoreV1 for ProviderStore {
    fn insert_prepared(
        &self,
        intent: &NewCashuSwapIntentV1,
        limits: CashuCustodyExposureLimitsV1,
    ) -> Result<InsertCashuSwapIntentResultV1, CashuSwapStoreErrorV1> {
        let result = self
            .insert_cashu_swap_intent_v1(
                &DurableNewIntent {
                    intent_id: intent.intent_id,
                    mint_id: intent.mint_id,
                    manifest_digest: intent.manifest_digest,
                    unit: intent.unit.clone(),
                    input_set_digest: intent.input_set_digest,
                    request_digest: intent.request_digest,
                    output_set_digest: intent.output_set_digest,
                    offer_binding_digest: intent.offer_binding_digest,
                    settlement_value: intent.settlement_value,
                    expected_output_count: intent.expected_output_count,
                    sealed_recovery: to_durable_sealed(&intent.sealed_recovery),
                    created_bucket: intent.created_bucket,
                },
                DurableExposureLimits {
                    max_unsettled_value: limits.max_unsettled_value(),
                    max_unsettled_notes: limits.max_unsettled_notes(),
                },
            )
            .map_err(map_provider_store_error)?;
        Ok(InsertCashuSwapIntentResultV1 {
            inserted: result.inserted,
            intent: from_durable_intent(result.intent),
        })
    }

    fn load_by_input(
        &self,
        mint_id: &[u8; 32],
        input_set_digest: &[u8; 32],
    ) -> Result<Option<StoredCashuSwapIntentV1>, CashuSwapStoreErrorV1> {
        self.cashu_swap_intent_by_input_v1(mint_id, input_set_digest)
            .map(|intent| intent.map(from_durable_intent))
            .map_err(map_provider_store_error)
    }

    fn begin_submission(
        &self,
        intent_id: &[u8; 16],
        now_unix: u64,
    ) -> Result<bool, CashuSwapStoreErrorV1> {
        self.begin_cashu_swap_submission_v1(intent_id, coarse_time_bucket_v1(now_unix))
            .map_err(map_provider_store_error)
    }

    fn commit_wallet(
        &self,
        intent_id: &[u8; 16],
        sealed_recovery: &CashuSealedRecoveryV1,
        now_unix: u64,
    ) -> Result<bool, CashuSwapStoreErrorV1> {
        self.commit_cashu_swap_wallet_v1(
            intent_id,
            &to_durable_sealed(sealed_recovery),
            coarse_time_bucket_v1(now_unix),
        )
        .map_err(map_provider_store_error)
    }

    fn mark_attention(
        &self,
        intent_id: &[u8; 16],
        now_unix: u64,
    ) -> Result<(), CashuSwapStoreErrorV1> {
        self.mark_cashu_swap_attention_v1(intent_id, coarse_time_bucket_v1(now_unix))
            .map(|_| ())
            .map_err(map_provider_store_error)
    }

    fn release_definite_rejection(
        &self,
        intent_id: &[u8; 16],
    ) -> Result<bool, CashuSwapStoreErrorV1> {
        self.delete_cashu_swap_intent_after_definite_rejection_v1(intent_id)
            .map_err(map_provider_store_error)
    }

    fn claim_grant_once_with_custody(
        &self,
        intent_id: &[u8; 16],
        lot: &NewCashuCustodyLotV1,
        now_unix: u64,
    ) -> Result<CashuSwapGrantClaimV1, CashuSwapStoreErrorV1> {
        self.claim_cashu_swap_grant_once_v1(
            intent_id,
            &DurableNewCustodyLot {
                lot_id: lot.lot_id,
                manifest_digest: lot.manifest_digest,
                active_keyset_digest: lot.active_keyset_digest,
                note_set_digest: lot.note_set_digest,
                note_ys: lot.note_ys.clone(),
                sealed_notes: DurableCustodySealed {
                    key_epoch: lot.sealed_notes.key_epoch,
                    nonce: lot.sealed_notes.nonce.clone(),
                    ciphertext: lot.sealed_notes.ciphertext.clone(),
                },
            },
            coarse_time_bucket_v1(now_unix),
        )
        .map(from_durable_claim)
        .map_err(map_provider_store_error)
    }
}

fn to_durable_sealed(sealed: &CashuSealedRecoveryV1) -> DurableSealed {
    DurableSealed {
        key_epoch: sealed.key_epoch,
        nonce: sealed.nonce.clone(),
        ciphertext: sealed.ciphertext.clone(),
    }
}

fn from_durable_intent(mut intent: DurableIntent) -> StoredCashuSwapIntentV1 {
    let sealed_nonce = std::mem::take(&mut intent.sealed_recovery.nonce);
    let sealed_ciphertext = std::mem::take(&mut intent.sealed_recovery.ciphertext);
    StoredCashuSwapIntentV1 {
        intent_id: intent.intent_id,
        mint_id: intent.mint_id,
        manifest_digest: intent.manifest_digest,
        unit: intent.unit,
        input_set_digest: intent.input_set_digest,
        request_digest: intent.request_digest,
        output_set_digest: intent.output_set_digest,
        offer_binding_digest: intent.offer_binding_digest,
        settlement_value: intent.settlement_value,
        expected_output_count: intent.expected_output_count,
        state: match intent.state {
            DurableState::Prepared => CashuSwapStateV1::Prepared,
            DurableState::Submitted => CashuSwapStateV1::Submitted,
            DurableState::WalletStored => CashuSwapStateV1::WalletStored,
            DurableState::GrantIssued => CashuSwapStateV1::GrantIssued,
            DurableState::Attention => CashuSwapStateV1::Attention,
        },
        sealed_recovery: CashuSealedRecoveryV1 {
            key_epoch: intent.sealed_recovery.key_epoch,
            nonce: sealed_nonce,
            ciphertext: sealed_ciphertext,
        },
        created_bucket: intent.created_bucket,
        updated_bucket: intent.updated_bucket,
    }
}

fn from_durable_claim(mut claim: DurableGrantClaim) -> CashuSwapGrantClaimV1 {
    let sealed_nonce = std::mem::take(&mut claim.lot.sealed_notes.nonce);
    let sealed_ciphertext = std::mem::take(&mut claim.lot.sealed_notes.ciphertext);
    CashuSwapGrantClaimV1 {
        issued: claim.issued,
        lot: StoredCashuCustodyLotV1 {
            lot_id: claim.lot.lot_id,
            mint_id: claim.lot.mint_id,
            manifest_digest: claim.lot.manifest_digest,
            active_keyset_digest: claim.lot.active_keyset_digest,
            note_set_digest: claim.lot.note_set_digest,
            unit: claim.lot.unit,
            settlement_value: claim.lot.settlement_value,
            note_count: claim.lot.note_count,
            sealed_notes: CashuSealedCustodyV1 {
                key_epoch: claim.lot.sealed_notes.key_epoch,
                nonce: sealed_nonce,
                ciphertext: sealed_ciphertext,
            },
        },
    }
}

fn coarse_time_bucket_v1(now_unix: u64) -> u64 {
    now_unix / 3_600
}

fn map_provider_store_error(error: StoreError) -> CashuSwapStoreErrorV1 {
    match error {
        StoreError::CashuSwapIntentConflict
        | StoreError::CashuSwapStateConflict
        | StoreError::CashuSwapIntentMissing
        | StoreError::InvalidInput(_) => CashuSwapStoreErrorV1::Conflict,
        StoreError::CashuCustodyExposureExceeded => CashuSwapStoreErrorV1::ExposureExceeded,
        StoreError::CashuCustodyLotMissing | StoreError::CashuCustodyLotConflict => {
            CashuSwapStoreErrorV1::CustodyConflict
        }
        StoreError::SchemaMismatch(_)
        | StoreError::IntegrityCheckFailed(_)
        | StoreError::ProviderMismatch
        | StoreError::RollbackFloorMissing
        | StoreError::RollbackFloorIdentityMismatch
        | StoreError::RollbackDetected { .. }
        | StoreError::RollbackFork
        | StoreError::RollbackAuthorityProtocol(_) => CashuSwapStoreErrorV1::Corrupt,
        _ => CashuSwapStoreErrorV1::Unavailable,
    }
}
