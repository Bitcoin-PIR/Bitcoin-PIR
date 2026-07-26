use crate::CashuClientErrorV1;

pub const MAX_RECOVERY_NONCE_BYTES_V1: usize = 64;
pub const MAX_RECOVERY_CIPHERTEXT_BYTES_V1: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CashuSwapStateV1 {
    Prepared = 0,
    Submitted = 1,
    WalletStored = 2,
    GrantIssued = 3,
    Attention = 4,
}

impl CashuSwapStateV1 {
    #[cfg(any(test, feature = "insecure-dev-sqlite-store"))]
    pub(crate) fn from_u8(value: u8) -> Result<Self, CashuSwapStoreErrorV1> {
        match value {
            0 => Ok(Self::Prepared),
            1 => Ok(Self::Submitted),
            2 => Ok(Self::WalletStored),
            3 => Ok(Self::GrantIssued),
            4 => Ok(Self::Attention),
            _ => Err(CashuSwapStoreErrorV1::Corrupt),
        }
    }
}

/// Ciphertext envelope for all Cashu inputs, output secrets, blinding factors,
/// mint promises, and received notes. The external cipher key is deliberately
/// absent; only its non-zero rotation epoch is persisted beside the blob.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CashuSealedRecoveryV1 {
    pub key_epoch: u64,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl CashuSealedRecoveryV1 {
    pub fn validate(&self) -> Result<(), CashuClientErrorV1> {
        if self.key_epoch == 0
            || self.nonce.is_empty()
            || self.nonce.len() > MAX_RECOVERY_NONCE_BYTES_V1
            || self.ciphertext.is_empty()
            || self.ciphertext.len() > MAX_RECOVERY_CIPHERTEXT_BYTES_V1
        {
            return Err(CashuClientErrorV1::InvalidCiphertextEnvelope);
        }
        Ok(())
    }
}

/// Immutable, non-secret associated data authenticated by the external
/// recovery cipher. State is excluded so the durable store can advance its
/// monotonic state without rewriting an unchanged prepared recovery blob.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CashuRecoveryAadV1 {
    pub intent_id: [u8; 16],
    pub mint_id: [u8; 32],
    pub input_set_digest: [u8; 32],
    pub request_digest: [u8; 32],
    pub output_set_digest: [u8; 32],
    pub offer_binding_digest: [u8; 32],
    pub settlement_value: u64,
}

impl CashuRecoveryAadV1 {
    pub fn encode(&self) -> [u8; 192] {
        let mut encoded = [0u8; 192];
        encoded[..16].copy_from_slice(&self.intent_id);
        encoded[16..48].copy_from_slice(&self.mint_id);
        encoded[48..80].copy_from_slice(&self.input_set_digest);
        encoded[80..112].copy_from_slice(&self.request_digest);
        encoded[112..144].copy_from_slice(&self.output_set_digest);
        encoded[144..176].copy_from_slice(&self.offer_binding_digest);
        encoded[176..184].copy_from_slice(&self.settlement_value.to_le_bytes());
        encoded[184..].copy_from_slice(b"BPIRCS01");
        encoded
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CashuRecoveryCipherErrorV1 {
    Unavailable,
    UnknownKeyEpoch,
    AuthenticationFailed,
    InvalidPlaintext,
}

/// Production implementations must use an authenticated encryption scheme,
/// source a fresh nonce for every `seal`, keep every live epoch key outside
/// the swap database, and bind the exact supplied AAD.
pub trait CashuRecoveryCipherV1: Send + Sync {
    fn seal(
        &self,
        aad: &CashuRecoveryAadV1,
        plaintext: &[u8],
    ) -> Result<CashuSealedRecoveryV1, CashuRecoveryCipherErrorV1>;

    fn open(
        &self,
        aad: &CashuRecoveryAadV1,
        sealed: &CashuSealedRecoveryV1,
    ) -> Result<Vec<u8>, CashuRecoveryCipherErrorV1>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CashuSwapStoreErrorV1 {
    Unavailable,
    Busy,
    Corrupt,
    Conflict,
}

#[derive(Clone)]
pub struct NewCashuSwapIntentV1 {
    pub intent_id: [u8; 16],
    pub mint_id: [u8; 32],
    pub input_set_digest: [u8; 32],
    pub request_digest: [u8; 32],
    pub output_set_digest: [u8; 32],
    pub offer_binding_digest: [u8; 32],
    pub settlement_value: u64,
    pub sealed_recovery: CashuSealedRecoveryV1,
    /// Coarse UTC hour bucket. Exact query/admission times must not be stored.
    pub created_bucket: u64,
}

impl NewCashuSwapIntentV1 {
    pub fn aad(&self) -> CashuRecoveryAadV1 {
        CashuRecoveryAadV1 {
            intent_id: self.intent_id,
            mint_id: self.mint_id,
            input_set_digest: self.input_set_digest,
            request_digest: self.request_digest,
            output_set_digest: self.output_set_digest,
            offer_binding_digest: self.offer_binding_digest,
            settlement_value: self.settlement_value,
        }
    }
}

#[derive(Clone)]
pub struct StoredCashuSwapIntentV1 {
    pub intent_id: [u8; 16],
    pub mint_id: [u8; 32],
    pub input_set_digest: [u8; 32],
    pub request_digest: [u8; 32],
    pub output_set_digest: [u8; 32],
    pub offer_binding_digest: [u8; 32],
    pub settlement_value: u64,
    pub state: CashuSwapStateV1,
    pub sealed_recovery: CashuSealedRecoveryV1,
    /// Coarse UTC hour buckets. Exact query/admission times must not be stored.
    pub created_bucket: u64,
    pub updated_bucket: u64,
}

impl StoredCashuSwapIntentV1 {
    pub fn aad(&self) -> CashuRecoveryAadV1 {
        CashuRecoveryAadV1 {
            intent_id: self.intent_id,
            mint_id: self.mint_id,
            input_set_digest: self.input_set_digest,
            request_digest: self.request_digest,
            output_set_digest: self.output_set_digest,
            offer_binding_digest: self.offer_binding_digest,
            settlement_value: self.settlement_value,
        }
    }

    pub fn matches_new(&self, proposed: &NewCashuSwapIntentV1) -> bool {
        self.intent_id == proposed.intent_id
            && self.mint_id == proposed.mint_id
            && self.input_set_digest == proposed.input_set_digest
            && self.request_digest == proposed.request_digest
            && self.output_set_digest == proposed.output_set_digest
            && self.offer_binding_digest == proposed.offer_binding_digest
            && self.settlement_value == proposed.settlement_value
    }
}

#[derive(Clone)]
pub struct InsertCashuSwapIntentResultV1 {
    pub inserted: bool,
    pub intent: StoredCashuSwapIntentV1,
}

/// Security-critical durable boundary. Implementations must serialize writers,
/// preserve the unique `(mint_id, input_set_digest)` namespace, compare every
/// immutable field on idempotent insert, and implement each transition as one
/// atomic compare-and-swap. Before returning a successful mutation they must
/// durably advance an independently stored, linearizable anti-rollback floor;
/// a database backup or WAL must not contain that authority. Exact admission
/// times and ciphertext plaintext must never be persisted or logged.
pub trait CashuSwapStoreV1: Send + Sync {
    fn insert_prepared(
        &self,
        intent: &NewCashuSwapIntentV1,
    ) -> Result<InsertCashuSwapIntentResultV1, CashuSwapStoreErrorV1>;

    fn load_by_input(
        &self,
        mint_id: &[u8; 32],
        input_set_digest: &[u8; 32],
    ) -> Result<Option<StoredCashuSwapIntentV1>, CashuSwapStoreErrorV1>;

    fn begin_submission(
        &self,
        intent_id: &[u8; 16],
        now_unix: u64,
    ) -> Result<bool, CashuSwapStoreErrorV1>;

    fn commit_wallet(
        &self,
        intent_id: &[u8; 16],
        sealed_recovery: &CashuSealedRecoveryV1,
        now_unix: u64,
    ) -> Result<bool, CashuSwapStoreErrorV1>;

    fn mark_attention(
        &self,
        intent_id: &[u8; 16],
        now_unix: u64,
    ) -> Result<(), CashuSwapStoreErrorV1>;

    fn claim_grant_once(
        &self,
        intent_id: &[u8; 16],
        now_unix: u64,
    ) -> Result<bool, CashuSwapStoreErrorV1>;
}
