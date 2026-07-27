use crate::CashuClientErrorV1;
use pir_service_protocol::validate_cashu_unit_v1;
use zeroize::Zeroize;

pub const MAX_RECOVERY_NONCE_BYTES_V1: usize = 64;
pub const MAX_RECOVERY_CIPHERTEXT_BYTES_V1: usize = 256 * 1024;
pub const MAX_CUSTODY_NONCE_BYTES_V1: usize = 64;
pub const MAX_CUSTODY_CIPHERTEXT_BYTES_V1: usize = 128 * 1024;

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
#[derive(Clone, Eq, PartialEq)]
pub struct CashuSealedRecoveryV1 {
    pub key_epoch: u64,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl std::fmt::Debug for CashuSealedRecoveryV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CashuSealedRecoveryV1")
            .field("envelope", &"[REDACTED]")
            .finish()
    }
}

impl Drop for CashuSealedRecoveryV1 {
    fn drop(&mut self) {
        self.nonce.zeroize();
        self.ciphertext.zeroize();
    }
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
    pub manifest_digest: [u8; 32],
    pub unit_digest: [u8; 32],
    pub input_set_digest: [u8; 32],
    pub request_digest: [u8; 32],
    pub output_set_digest: [u8; 32],
    pub offer_binding_digest: [u8; 32],
    pub settlement_value: u64,
    pub expected_output_count: u32,
}

impl CashuRecoveryAadV1 {
    pub fn encode(&self) -> [u8; 260] {
        let mut encoded = [0u8; 260];
        encoded[..16].copy_from_slice(&self.intent_id);
        encoded[16..48].copy_from_slice(&self.mint_id);
        encoded[48..80].copy_from_slice(&self.manifest_digest);
        encoded[80..112].copy_from_slice(&self.unit_digest);
        encoded[112..144].copy_from_slice(&self.input_set_digest);
        encoded[144..176].copy_from_slice(&self.request_digest);
        encoded[176..208].copy_from_slice(&self.output_set_digest);
        encoded[208..240].copy_from_slice(&self.offer_binding_digest);
        encoded[240..248].copy_from_slice(&self.settlement_value.to_le_bytes());
        encoded[248..252].copy_from_slice(&self.expected_output_count.to_le_bytes());
        encoded[252..].copy_from_slice(b"BPIRCR02");
        encoded
    }
}

/// Type-separated AAD for note-only custody encryption. It deliberately
/// excludes the swap intent, offer, request, query, and exact timestamps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CashuCustodyAadV1 {
    pub lot_id: [u8; 16],
    pub mint_id: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub unit_digest: [u8; 32],
    pub active_keyset_digest: [u8; 32],
    pub note_set_digest: [u8; 32],
    pub settlement_value: u64,
    pub note_count: u32,
}

impl CashuCustodyAadV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        lot_id: [u8; 16],
        mint_id: [u8; 32],
        manifest_digest: [u8; 32],
        unit: &str,
        active_keyset_digest: [u8; 32],
        note_set_digest: [u8; 32],
        settlement_value: u64,
        note_count: u32,
    ) -> Result<Self, CashuClientErrorV1> {
        if lot_id.iter().all(|byte| *byte == 0)
            || mint_id.iter().all(|byte| *byte == 0)
            || manifest_digest.iter().all(|byte| *byte == 0)
            || active_keyset_digest.iter().all(|byte| *byte == 0)
            || note_set_digest.iter().all(|byte| *byte == 0)
            || validate_cashu_unit_v1(unit).is_err()
            || settlement_value == 0
            || note_count == 0
        {
            return Err(CashuClientErrorV1::InvalidCustodyPlaintext);
        }
        Ok(Self {
            lot_id,
            mint_id,
            manifest_digest,
            unit_digest: crate::domain_digest_v1(
                crate::CUSTODY_UNIT_DIGEST_DOMAIN_V1,
                unit.as_bytes(),
            ),
            active_keyset_digest,
            note_set_digest,
            settlement_value,
            note_count,
        })
    }

    pub fn encode(&self) -> [u8; 196] {
        let mut encoded = [0u8; 196];
        encoded[..16].copy_from_slice(&self.lot_id);
        encoded[16..48].copy_from_slice(&self.mint_id);
        encoded[48..80].copy_from_slice(&self.manifest_digest);
        encoded[80..112].copy_from_slice(&self.unit_digest);
        encoded[112..144].copy_from_slice(&self.active_keyset_digest);
        encoded[144..176].copy_from_slice(&self.note_set_digest);
        encoded[176..184].copy_from_slice(&self.settlement_value.to_le_bytes());
        encoded[184..188].copy_from_slice(&self.note_count.to_le_bytes());
        encoded[188..].copy_from_slice(b"BPIRCU01");
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
pub enum CashuCustodyCipherErrorV1 {
    Unavailable,
    UnknownKeyEpoch,
    AuthenticationFailed,
    InvalidPlaintext,
}

/// Independent authenticated-encryption boundary for provider-owned notes.
/// Implementations must never substitute recovery AAD for this typed domain.
pub trait CashuCustodyCipherV1: Send + Sync {
    fn seal(
        &self,
        aad: &CashuCustodyAadV1,
        plaintext: &[u8],
    ) -> Result<CashuSealedCustodyV1, CashuCustodyCipherErrorV1>;

    fn open(
        &self,
        aad: &CashuCustodyAadV1,
        sealed: &CashuSealedCustodyV1,
    ) -> Result<Vec<u8>, CashuCustodyCipherErrorV1>;
}

#[derive(Clone, Eq, PartialEq)]
pub struct CashuSealedCustodyV1 {
    pub key_epoch: u64,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl std::fmt::Debug for CashuSealedCustodyV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CashuSealedCustodyV1")
            .field("envelope", &"[REDACTED]")
            .finish()
    }
}

impl Drop for CashuSealedCustodyV1 {
    fn drop(&mut self) {
        self.nonce.zeroize();
        self.ciphertext.zeroize();
    }
}

impl CashuSealedCustodyV1 {
    pub fn validate(&self) -> Result<(), CashuClientErrorV1> {
        if self.key_epoch == 0
            || self.nonce.is_empty()
            || self.nonce.len() > MAX_CUSTODY_NONCE_BYTES_V1
            || self.ciphertext.is_empty()
            || self.ciphertext.len() > MAX_CUSTODY_CIPHERTEXT_BYTES_V1
        {
            return Err(CashuClientErrorV1::InvalidCustodyCiphertextEnvelope);
        }
        Ok(())
    }
}

/// Finite limits applied independently to each checked `(mint_id, unit)`.
/// There is intentionally no default or unlimited constructor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CashuCustodyExposureLimitsV1 {
    max_unsettled_value: u64,
    max_unsettled_notes: u64,
}

impl CashuCustodyExposureLimitsV1 {
    pub const fn new(
        max_unsettled_value: u64,
        max_unsettled_notes: u64,
    ) -> Result<Self, CashuClientErrorV1> {
        if max_unsettled_value == 0
            || max_unsettled_notes == 0
            || max_unsettled_value > i64::MAX as u64
            || max_unsettled_notes > i64::MAX as u64
        {
            return Err(CashuClientErrorV1::InvalidExposureLimits);
        }
        Ok(Self {
            max_unsettled_value,
            max_unsettled_notes,
        })
    }

    pub const fn max_unsettled_value(self) -> u64 {
        self.max_unsettled_value
    }

    pub const fn max_unsettled_notes(self) -> u64 {
        self.max_unsettled_notes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CashuSwapStoreErrorV1 {
    Unavailable,
    Busy,
    Corrupt,
    Conflict,
    ExposureExceeded,
    CustodyConflict,
}

#[derive(Clone)]
pub struct NewCashuSwapIntentV1 {
    pub intent_id: [u8; 16],
    pub mint_id: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub unit: String,
    pub input_set_digest: [u8; 32],
    pub request_digest: [u8; 32],
    pub output_set_digest: [u8; 32],
    pub offer_binding_digest: [u8; 32],
    pub settlement_value: u64,
    pub expected_output_count: u32,
    pub sealed_recovery: CashuSealedRecoveryV1,
    /// Coarse UTC hour bucket. Exact query/admission times must not be stored.
    pub created_bucket: u64,
}

impl NewCashuSwapIntentV1 {
    pub fn aad(&self) -> CashuRecoveryAadV1 {
        CashuRecoveryAadV1 {
            intent_id: self.intent_id,
            mint_id: self.mint_id,
            manifest_digest: self.manifest_digest,
            unit_digest: crate::domain_digest_v1(
                crate::CUSTODY_UNIT_DIGEST_DOMAIN_V1,
                self.unit.as_bytes(),
            ),
            input_set_digest: self.input_set_digest,
            request_digest: self.request_digest,
            output_set_digest: self.output_set_digest,
            offer_binding_digest: self.offer_binding_digest,
            settlement_value: self.settlement_value,
            expected_output_count: self.expected_output_count,
        }
    }
}

#[derive(Clone)]
pub struct StoredCashuSwapIntentV1 {
    pub intent_id: [u8; 16],
    pub mint_id: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub unit: String,
    pub input_set_digest: [u8; 32],
    pub request_digest: [u8; 32],
    pub output_set_digest: [u8; 32],
    pub offer_binding_digest: [u8; 32],
    pub settlement_value: u64,
    pub expected_output_count: u32,
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
            manifest_digest: self.manifest_digest,
            unit_digest: crate::domain_digest_v1(
                crate::CUSTODY_UNIT_DIGEST_DOMAIN_V1,
                self.unit.as_bytes(),
            ),
            input_set_digest: self.input_set_digest,
            request_digest: self.request_digest,
            output_set_digest: self.output_set_digest,
            offer_binding_digest: self.offer_binding_digest,
            settlement_value: self.settlement_value,
            expected_output_count: self.expected_output_count,
        }
    }

    pub fn matches_new(&self, proposed: &NewCashuSwapIntentV1) -> bool {
        self.intent_id == proposed.intent_id
            && self.mint_id == proposed.mint_id
            && self.manifest_digest == proposed.manifest_digest
            && self.unit == proposed.unit
            && self.input_set_digest == proposed.input_set_digest
            && self.request_digest == proposed.request_digest
            && self.output_set_digest == proposed.output_set_digest
            && self.offer_binding_digest == proposed.offer_binding_digest
            && self.settlement_value == proposed.settlement_value
            && self.expected_output_count == proposed.expected_output_count
    }
}

#[derive(Clone)]
pub struct InsertCashuSwapIntentResultV1 {
    pub inserted: bool,
    pub intent: StoredCashuSwapIntentV1,
}

pub struct NewCashuCustodyLotV1 {
    pub lot_id: [u8; 16],
    pub manifest_digest: [u8; 32],
    pub active_keyset_digest: [u8; 32],
    pub note_set_digest: [u8; 32],
    pub note_ys: Vec<[u8; 33]>,
    pub sealed_notes: CashuSealedCustodyV1,
}

impl Drop for NewCashuCustodyLotV1 {
    fn drop(&mut self) {
        self.note_ys.zeroize();
    }
}

#[derive(Clone)]
pub struct StoredCashuCustodyLotV1 {
    pub lot_id: [u8; 16],
    pub mint_id: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub active_keyset_digest: [u8; 32],
    pub note_set_digest: [u8; 32],
    pub unit: String,
    pub settlement_value: u64,
    pub note_count: u32,
    pub sealed_notes: CashuSealedCustodyV1,
}

impl StoredCashuCustodyLotV1 {
    pub fn aad(&self) -> Result<CashuCustodyAadV1, CashuClientErrorV1> {
        CashuCustodyAadV1::from_parts(
            self.lot_id,
            self.mint_id,
            self.manifest_digest,
            &self.unit,
            self.active_keyset_digest,
            self.note_set_digest,
            self.settlement_value,
            self.note_count,
        )
    }
}

#[derive(Clone)]
pub struct CashuSwapGrantClaimV1 {
    pub issued: bool,
    pub lot: StoredCashuCustodyLotV1,
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
        limits: CashuCustodyExposureLimitsV1,
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

    /// Delete only an exact `SUBMITTED` intent after a standards-conforming
    /// NUT-03 rejection proved the mint did not commit the swap. Production
    /// implementations must bind the delete into their rollback authority
    /// before returning `Ok(true)`. No terminal tombstone is retained.
    fn release_definite_rejection(
        &self,
        intent_id: &[u8; 16],
    ) -> Result<bool, CashuSwapStoreErrorV1>;

    fn claim_grant_once_with_custody(
        &self,
        intent_id: &[u8; 16],
        lot: &NewCashuCustodyLotV1,
        now_unix: u64,
    ) -> Result<CashuSwapGrantClaimV1, CashuSwapStoreErrorV1>;
}
