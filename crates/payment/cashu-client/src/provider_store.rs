//! Production `CashuSwapStoreV1` adapter backed by ProviderStore schema v4.

use pir_service_store::{
    CashuSwapIntentStateV1 as DurableState, CashuSwapIntentV1 as DurableIntent,
    CashuSwapSealedRecoveryV1 as DurableSealed, NewCashuSwapIntentV1 as DurableNewIntent,
    ProviderStore, StoreError,
};

use crate::{
    CashuSealedRecoveryV1, CashuSwapStateV1, CashuSwapStoreErrorV1, CashuSwapStoreV1,
    InsertCashuSwapIntentResultV1, NewCashuSwapIntentV1, StoredCashuSwapIntentV1,
};

impl CashuSwapStoreV1 for ProviderStore {
    fn insert_prepared(
        &self,
        intent: &NewCashuSwapIntentV1,
    ) -> Result<InsertCashuSwapIntentResultV1, CashuSwapStoreErrorV1> {
        let result = self
            .insert_cashu_swap_intent_v1(&DurableNewIntent {
                intent_id: intent.intent_id,
                mint_id: intent.mint_id,
                input_set_digest: intent.input_set_digest,
                request_digest: intent.request_digest,
                output_set_digest: intent.output_set_digest,
                offer_binding_digest: intent.offer_binding_digest,
                settlement_value: intent.settlement_value,
                sealed_recovery: to_durable_sealed(&intent.sealed_recovery),
                created_bucket: intent.created_bucket,
            })
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

    fn claim_grant_once(
        &self,
        intent_id: &[u8; 16],
        now_unix: u64,
    ) -> Result<bool, CashuSwapStoreErrorV1> {
        self.claim_cashu_swap_grant_once_v1(intent_id, coarse_time_bucket_v1(now_unix))
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

fn from_durable_intent(intent: DurableIntent) -> StoredCashuSwapIntentV1 {
    StoredCashuSwapIntentV1 {
        intent_id: intent.intent_id,
        mint_id: intent.mint_id,
        input_set_digest: intent.input_set_digest,
        request_digest: intent.request_digest,
        output_set_digest: intent.output_set_digest,
        offer_binding_digest: intent.offer_binding_digest,
        settlement_value: intent.settlement_value,
        state: match intent.state {
            DurableState::Prepared => CashuSwapStateV1::Prepared,
            DurableState::Submitted => CashuSwapStateV1::Submitted,
            DurableState::WalletStored => CashuSwapStateV1::WalletStored,
            DurableState::GrantIssued => CashuSwapStateV1::GrantIssued,
            DurableState::Attention => CashuSwapStateV1::Attention,
        },
        sealed_recovery: CashuSealedRecoveryV1 {
            key_epoch: intent.sealed_recovery.key_epoch,
            nonce: intent.sealed_recovery.nonce,
            ciphertext: intent.sealed_recovery.ciphertext,
        },
        created_bucket: intent.created_bucket,
        updated_bucket: intent.updated_bucket,
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
