//! Fail-closed standard Cashu merchant swap and recovery adapter.
//!
//! This crate is intentionally a merchant wallet, not a second Cashu mint.
//! The accepted external mint's atomic NUT-03 input invalidation is the only
//! authoritative spent-set. BitcoinPIR persists an encrypted recovery intent
//! and an at-most-once grant-delivery state, but never writes those inputs into
//! the provider-local bearer spent-set.

#![forbid(unsafe_code)]

mod custody;
mod denominations;
mod dto;
mod nut07;
mod store;
mod token_v4;

#[cfg(not(target_arch = "wasm32"))]
mod provider_store;

#[cfg(not(target_arch = "wasm32"))]
mod runtime_admission;

#[cfg(any(test, feature = "insecure-dev-sqlite-store"))]
mod sqlite;

use std::collections::HashSet;
use std::fmt;
use std::io::{self, Write};

use dto::{
    decode_json_v1, decode_lower_hex, decode_mint_response_json_v1, encode_json_v1,
    is_bounded_nut07_witness_v1, lower_hex, validate_item_count_v1, CashuBlindedMessageJsonV1,
    CashuPostCheckStateRequestJsonV1, CashuPostCheckStateResponseJsonV1,
    CashuPostRestoreRequestJsonV1, CashuPostRestoreResponseJsonV1, CashuPostSwapRequestJsonV1,
    CashuPostSwapResponseJsonV1, CashuProofJsonV1, CashuProofStateJsonV1,
};
use pir_payment_crypto::{
    blind_cashu_message_v1, cashu_hash_to_curve_v1, verify_and_unblind_cashu_promise_v1,
};
use pir_service_protocol::{
    check_standard_cashu_spend_for_offer, is_canonical_service_https_endpoint_v1,
    validate_leaf_spki_sha256_pins_v1, StandardCashuMintManifestV1, StandardCashuSpendCheckV1,
    StandardCashuSpendV1, VerifiedServiceOfferV1, MAX_STANDARD_CASHU_PROOFS_V1,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub use custody::{
    encode_cashub_from_custody_bundles_v1, CashuCustodyBundleV1, CashuCustodyNoteV1,
    MAX_CASHU_CUSTODY_PLAINTEXT_BYTES_V1,
};
pub use denominations::{
    solve_cashu_output_denominations_v1, MAX_CASHU_DENOMINATION_SOLVER_STATES_V1,
    MAX_CASHU_DENOMINATION_SOLVER_TRANSITIONS_V1,
};
pub use nut07::{
    check_cashu_custody_bundles_once_v1, derive_cashu_nut07_export_observation_digest_v1,
    CashuNut07BatchResultV1, CashuNut07CheckedNoteV1, CashuNut07LotResultV1, CashuNut07NoteStateV1,
    MAX_CASHU_NUT07_BUNDLES_V1, MAX_CASHU_NUT07_NOTES_V1,
};
pub use token_v4::{
    cashub_encoded_upper_bound_v1, CashuTokenV4GroupV1, CashuTokenV4ProofV1, CashuTokenV4V1,
    MAX_CASHUB_CBOR_BYTES_V1, MAX_CASHUB_GROUPS_V1, MAX_CASHUB_MINT_ENDPOINT_BYTES_V1,
    MAX_CASHUB_PROOFS_V1, MAX_CASHUB_SERIALIZED_CHARS_V1,
};

pub use store::{
    CashuCustodyAadV1, CashuCustodyCipherErrorV1, CashuCustodyCipherV1,
    CashuCustodyExposureLimitsV1, CashuRecoveryAadV1, CashuRecoveryCipherErrorV1,
    CashuRecoveryCipherV1, CashuSealedCustodyV1, CashuSealedRecoveryV1, CashuSwapGrantClaimV1,
    CashuSwapStateV1, CashuSwapStoreErrorV1, CashuSwapStoreV1, InsertCashuSwapIntentResultV1,
    NewCashuCustodyLotV1, NewCashuSwapIntentV1, StoredCashuCustodyLotV1, StoredCashuSwapIntentV1,
    MAX_CUSTODY_CIPHERTEXT_BYTES_V1, MAX_CUSTODY_NONCE_BYTES_V1, MAX_RECOVERY_CIPHERTEXT_BYTES_V1,
    MAX_RECOVERY_NONCE_BYTES_V1,
};

#[cfg(any(test, feature = "insecure-dev-sqlite-store"))]
pub use sqlite::InsecureDevSqliteCashuSwapStoreV1;

#[cfg(not(target_arch = "wasm32"))]
pub use runtime_admission::{
    ChaCha20Poly1305CustodyCipherV1, ChaCha20Poly1305CustodyDecryptorV1,
    ChaCha20Poly1305RecoveryCipherV1, OsRandomCashuOutputMaterialGeneratorV1,
    StandardCashuAdmissionCommitterV1,
};

pub const MAX_CASHU_SWAP_ITEMS_V1: usize = MAX_STANDARD_CASHU_PROOFS_V1;
pub const MAX_CASHU_MINT_JSON_BYTES_V1: usize = 128 * 1024;
pub const MAX_CASHU_RECOVERY_PLAINTEXT_BYTES_V1: usize = 224 * 1024;

/// A fixed-capacity zeroizing writer for bearer or recovery plaintexts.
///
/// Reserving the complete protocol bound up front is deliberate: a growing
/// `Vec` would free its old allocation without wiping it when it reallocates.
pub(crate) struct BoundedZeroizingWriterV1 {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
    limit_exceeded: bool,
}

impl BoundedZeroizingWriterV1 {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            bytes: Zeroizing::new(Vec::with_capacity(limit)),
            limit,
            limit_exceeded: false,
        }
    }

    pub(crate) const fn limit_exceeded(&self) -> bool {
        self.limit_exceeded
    }

    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.bytes.capacity()
    }

    pub(crate) fn into_inner(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }
}

impl Write for BoundedZeroizingWriterV1 {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let Some(next_len) = self.bytes.len().checked_add(input.len()) else {
            self.limit_exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "bounded buffer overflow",
            ));
        };
        if next_len > self.limit {
            self.limit_exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "bounded buffer limit exceeded",
            ));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

const INPUT_SET_DIGEST_DOMAIN_V1: &[u8] = b"BitcoinPIR/cashu-input-set/v1";
const REQUEST_DIGEST_DOMAIN_V1: &[u8] = b"BitcoinPIR/cashu-swap-request/v1";
const OUTPUT_SET_DIGEST_DOMAIN_V1: &[u8] = b"BitcoinPIR/cashu-output-set/v1";
const INTENT_ID_DOMAIN_V1: &[u8] = b"BitcoinPIR/cashu-swap-intent-id/v1";
const CUSTODY_NOTE_Y_DIGEST_DOMAIN_V1: &[u8] = b"BitcoinPIR/cashu-custody-note-y/v1";
const CUSTODY_NOTE_SET_DIGEST_DOMAIN_V1: &[u8] = b"BitcoinPIR/cashu-custody-note-set/v1";
const CUSTODY_LOT_ID_DOMAIN_V1: &[u8] = b"BitcoinPIR/cashu-custody-lot-id/v1";
const CUSTODY_KEYSET_DIGEST_DOMAIN_V1: &[u8] = b"BitcoinPIR/cashu-custody-keyset/v1";
pub(crate) const CUSTODY_UNIT_DIGEST_DOMAIN_V1: &[u8] = b"BitcoinPIR/cashu-unit/v1";
pub const CASHU_OFFER_BINDING_DIGEST_DOMAIN_V1: &[u8] = b"BitcoinPIR/cashu-offer-binding/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CashuClientErrorV1 {
    InvalidCheckedSpend,
    InvalidManifest,
    NoExactDenominationSolution,
    DenominationSearchLimitExceeded,
    ConditionalTokenUnsupported,
    InvalidOutputMaterial,
    InvalidItemCount,
    Underpayment,
    Overpayment,
    InvalidJson,
    JsonTooLarge,
    InvalidMintPoint,
    InvalidMintScalar,
    MintResponseMismatch,
    MintDleqVerificationFailed,
    Nut07CheckUnavailable,
    Nut07ResponseInvalid,
    InvalidCiphertextEnvelope,
    RecoveryCipherUnavailable,
    RecoveryAuthenticationFailed,
    RecoveryPlaintextInvalid,
    InvalidCustodyCiphertextEnvelope,
    CustodyCipherUnavailable,
    CustodyAuthenticationFailed,
    InvalidCustodyPlaintext,
    InvalidExposureLimits,
    ExposureLimitExceeded,
    InvalidCashuToken,
    StoreUnavailable,
    StoreConflict,
    IntentNotFound,
    StateConflict,
}

impl fmt::Display for CashuClientErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidCheckedSpend => "standard Cashu policy check is inconsistent",
            Self::InvalidManifest => "standard Cashu mint manifest is invalid or mismatched",
            Self::NoExactDenominationSolution => {
                "Cashu denominations cannot represent the exact value within the proof bound"
            }
            Self::DenominationSearchLimitExceeded => {
                "Cashu exact-denomination search exceeded its deterministic complexity bound"
            }
            Self::ConditionalTokenUnsupported => "conditional Cashu tokens are unsupported by V1",
            Self::InvalidOutputMaterial => "provider Cashu output material is invalid",
            Self::InvalidItemCount => "Cashu item count is outside the V1 bound",
            Self::Underpayment => "Cashu inputs underpay the exact offer",
            Self::Overpayment => "Cashu inputs overpay the exact no-change offer",
            Self::InvalidJson => "Cashu mint returned invalid or non-conforming JSON",
            Self::JsonTooLarge => "Cashu JSON exceeds the V1 bound",
            Self::InvalidMintPoint => "Cashu mint returned an invalid point",
            Self::InvalidMintScalar => "Cashu mint returned an invalid DLEQ scalar",
            Self::MintResponseMismatch => "Cashu mint response does not echo the exact output list",
            Self::MintDleqVerificationFailed => "Cashu mint NUT-12 verification failed",
            Self::Nut07CheckUnavailable => "Cashu mint NUT-07 state check is unavailable",
            Self::Nut07ResponseInvalid => "Cashu mint returned an invalid NUT-07 response",
            Self::InvalidCiphertextEnvelope => "Cashu recovery ciphertext envelope is invalid",
            Self::RecoveryCipherUnavailable => "Cashu recovery cipher is unavailable",
            Self::RecoveryAuthenticationFailed => "Cashu recovery ciphertext authentication failed",
            Self::RecoveryPlaintextInvalid => "Cashu recovery plaintext is inconsistent",
            Self::InvalidCustodyCiphertextEnvelope => {
                "Cashu custody ciphertext envelope is invalid"
            }
            Self::CustodyCipherUnavailable => "Cashu custody cipher is unavailable",
            Self::CustodyAuthenticationFailed => "Cashu custody ciphertext authentication failed",
            Self::InvalidCustodyPlaintext => "Cashu custody plaintext is inconsistent",
            Self::InvalidExposureLimits => "Cashu custody exposure limits are invalid",
            Self::ExposureLimitExceeded => "Cashu custody exposure limit is exceeded",
            Self::InvalidCashuToken => "Cashu V4 token is invalid or non-canonical",
            Self::StoreUnavailable => "Cashu durable store is unavailable or corrupt",
            Self::StoreConflict => "Cashu durable store rejected conflicting immutable state",
            Self::IntentNotFound => "Cashu swap intent was not found",
            Self::StateConflict => "Cashu swap state changed concurrently or regressed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for CashuClientErrorV1 {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CashuMintRouteV1 {
    Swap,
    Restore,
    CheckState,
}

impl CashuMintRouteV1 {
    pub const fn path(self) -> &'static str {
        match self {
            Self::Swap => "/v1/swap",
            Self::Restore => "/v1/restore",
            Self::CheckState => "/v1/checkstate",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CashuMintTransportFailureKindV1 {
    Timeout,
    Network,
    NotFound,
    HttpError,
    InvalidContentType,
    ResponseTooLarge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CashuMintTransportFailureV1 {
    kind: CashuMintTransportFailureKindV1,
    http_status: Option<u16>,
}

impl CashuMintTransportFailureV1 {
    pub const fn ambiguous(
        kind: CashuMintTransportFailureKindV1,
        http_status: Option<u16>,
    ) -> Self {
        Self { kind, http_status }
    }

    /// Classify one already-bounded, strict-content-type HTTP error response.
    /// NUT-00 defines the HTTP 400 error envelope, but neither NUT-00 nor
    /// NUT-03 makes that status proof that a swap did not commit. Therefore
    /// every HTTP response remains ambiguous for mutation recovery. The body
    /// is intentionally ignored and never enters logs or durable state.
    pub fn from_http_status(status: u16, _response_body: &[u8]) -> Self {
        let kind = if status == 404 {
            CashuMintTransportFailureKindV1::NotFound
        } else {
            CashuMintTransportFailureKindV1::HttpError
        };
        Self {
            kind,
            http_status: Some(status),
        }
    }

    pub const fn kind(&self) -> CashuMintTransportFailureKindV1 {
        self.kind
    }

    pub const fn http_status(&self) -> Option<u16> {
        self.http_status
    }
}

/// Borrowed, canonical transport trust derived from one already verified
/// signed Cashu manifest or its authenticated custody continuation.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CashuMintTrustV1<'a> {
    mint_endpoint: &'a str,
    leaf_spki_sha256_pins: &'a [[u8; 32]],
}

impl fmt::Debug for CashuMintTrustV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CashuMintTrustV1")
            .field("mint_endpoint", &"[REDACTED_ENDPOINT]")
            .field(
                "leaf_spki_sha256_pin_count",
                &self.leaf_spki_sha256_pins.len(),
            )
            .finish()
    }
}

impl<'a> CashuMintTrustV1<'a> {
    pub fn from_manifest(
        manifest: &'a StandardCashuMintManifestV1,
    ) -> Result<Self, CashuClientErrorV1> {
        if manifest.encode().is_err() {
            return Err(CashuClientErrorV1::InvalidManifest);
        }
        Self::from_parts(&manifest.mint_endpoint, &manifest.leaf_spki_sha256_pins)
    }

    pub(crate) fn from_parts(
        mint_endpoint: &'a str,
        leaf_spki_sha256_pins: &'a [[u8; 32]],
    ) -> Result<Self, CashuClientErrorV1> {
        if !is_canonical_service_https_endpoint_v1(mint_endpoint)
            || validate_leaf_spki_sha256_pins_v1(
                leaf_spki_sha256_pins,
                "CashuMintTrustV1.leaf_spki_sha256_pins",
            )
            .is_err()
        {
            return Err(CashuClientErrorV1::InvalidManifest);
        }
        Ok(Self {
            mint_endpoint,
            leaf_spki_sha256_pins,
        })
    }

    pub const fn mint_endpoint(self) -> &'a str {
        self.mint_endpoint
    }

    pub const fn leaf_spki_sha256_pins(self) -> &'a [[u8; 32]] {
        self.leaf_spki_sha256_pins
    }
}

/// Fail-closed mint transport boundary. A production implementation must use
/// the exact signed trust tuple, require WebPKI plus every-request leaf-SPKI
/// pin validation, append only `route.path()`, reject redirects and
/// cross-origin authentication, enforce HTTPS, set JSON content type, and stop
/// reading at `max_response_bytes`.
pub trait CashuMintTransportV1: Send + Sync {
    fn post_json(
        &self,
        trust: CashuMintTrustV1<'_>,
        route: CashuMintRouteV1,
        request_json: &[u8],
        max_response_bytes: usize,
    ) -> Result<Vec<u8>, CashuMintTransportFailureV1>;
}

/// Provider-generated material for one output denomination. `secret_bytes`
/// becomes a lowercase 64-character ordinary Cashu secret. The constructor
/// rejects all-zero secrets; the concrete crypto adapter rejects invalid or
/// zero blinding scalars.
pub struct CashuOutputMaterialV1 {
    amount: u64,
    secret_bytes: [u8; 32],
    blinding_scalar: [u8; 32],
}

impl CashuOutputMaterialV1 {
    pub fn new(amount: u64, mut secret_bytes: [u8; 32], mut blinding_scalar: [u8; 32]) -> Self {
        let material = Self {
            amount,
            secret_bytes,
            blinding_scalar,
        };
        // Arrays are `Copy`; wipe the constructor's argument slots after the
        // owned material has taken its copy, on both optimized and debug builds.
        secret_bytes.zeroize();
        blinding_scalar.zeroize();
        material
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn from_zeroizing(
        amount: u64,
        secret_bytes: Zeroizing<[u8; 32]>,
        blinding_scalar: Zeroizing<[u8; 32]>,
    ) -> Self {
        Self {
            amount,
            secret_bytes: *secret_bytes,
            blinding_scalar: *blinding_scalar,
        }
    }
}

impl Drop for CashuOutputMaterialV1 {
    fn drop(&mut self) {
        self.secret_bytes.zeroize();
        self.blinding_scalar.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CashuRecoveryObservationV1 {
    SwapResponseAmbiguous,
    InputsUnspentObserved,
    InputsPending,
    InputsSpentButPromisesMissing,
    InconsistentInputStates,
    MintUnavailable,
    BadMintResponse,
}

/// Private-field evidence that one exact NUT-03 commit produced and durably
/// stored fully verified provider notes and that grant delivery was claimed by
/// exactly one caller. This is not a reusable bearer token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use = "the server must install this exact operation grant or fail closed"]
pub struct VerifiedStandardCashuGrantV1 {
    intent_id: [u8; 16],
    mint_id: [u8; 32],
    input_set_digest: [u8; 32],
    offer_binding_digest: [u8; 32],
    settlement_value: u64,
    received_note_count: u8,
}

impl VerifiedStandardCashuGrantV1 {
    pub const fn intent_id(&self) -> &[u8; 16] {
        &self.intent_id
    }

    pub const fn mint_id(&self) -> &[u8; 32] {
        &self.mint_id
    }

    pub const fn input_set_digest(&self) -> &[u8; 32] {
        &self.input_set_digest
    }

    pub const fn offer_binding_digest(&self) -> &[u8; 32] {
        &self.offer_binding_digest
    }

    pub const fn settlement_value(&self) -> u64 {
        self.settlement_value
    }

    pub const fn received_note_count(&self) -> u8 {
        self.received_note_count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CashuSwapProgressV1 {
    Grant(VerifiedStandardCashuGrantV1),
    RecoveryPending {
        intent_id: [u8; 16],
        observation: CashuRecoveryObservationV1,
    },
    AttentionRequired {
        intent_id: [u8; 16],
        observation: CashuRecoveryObservationV1,
    },
    AlreadyGranted {
        intent_id: [u8; 16],
    },
}

pub struct StandardCashuClientV1<'a> {
    store: &'a dyn CashuSwapStoreV1,
    transport: &'a dyn CashuMintTransportV1,
    recovery_cipher: &'a dyn CashuRecoveryCipherV1,
    custody_cipher: &'a dyn CashuCustodyCipherV1,
    exposure_limits: CashuCustodyExposureLimitsV1,
}

impl<'a> StandardCashuClientV1<'a> {
    pub const fn new(
        store: &'a dyn CashuSwapStoreV1,
        transport: &'a dyn CashuMintTransportV1,
        recovery_cipher: &'a dyn CashuRecoveryCipherV1,
        custody_cipher: &'a dyn CashuCustodyCipherV1,
        exposure_limits: CashuCustodyExposureLimitsV1,
    ) -> Self {
        Self {
            store,
            transport,
            recovery_cipher,
            custody_cipher,
            exposure_limits,
        }
    }

    /// Persist the exact request and private recovery material before the one
    /// permitted NUT-03 submission. Concurrent starts converge on the existing
    /// input-set intent; only the winning durable state transition may submit.
    pub fn start_swap(
        &self,
        spend: &StandardCashuSpendV1,
        checked: &StandardCashuSpendCheckV1,
        verified_offer: &VerifiedServiceOfferV1<'_>,
        manifest: &StandardCashuMintManifestV1,
        output_materials: Vec<CashuOutputMaterialV1>,
        now_unix: u64,
    ) -> Result<CashuSwapProgressV1, CashuClientErrorV1> {
        let context = CheckedContextV1::new(spend, checked, verified_offer, manifest, now_unix)?;
        if let Some(existing) = self.load_for_context(&context)? {
            return self.drive(existing, &context);
        }

        let (new_intent, recovery) = self.prepare_intent(&context, output_materials)?;
        let insert = match self
            .store
            .insert_prepared(&new_intent, self.exposure_limits)
        {
            Ok(value) => value,
            Err(CashuSwapStoreErrorV1::Conflict) => {
                let existing = self
                    .load_for_context(&context)?
                    .ok_or(CashuClientErrorV1::StoreConflict)?;
                return self.drive(existing, &context);
            }
            Err(error) => return Err(map_store_error(error)),
        };
        drop(recovery);
        self.drive(insert.intent, &context)
    }

    /// Resume from encrypted durable state. Once an intent is `SUBMITTED`,
    /// this function only uses NUT-09/NUT-07 and never resends NUT-03 or creates
    /// new blinded outputs, including when NUT-07 currently reports UNSPENT.
    pub fn resume_swap(
        &self,
        spend: &StandardCashuSpendV1,
        checked: &StandardCashuSpendCheckV1,
        verified_offer: &VerifiedServiceOfferV1<'_>,
        manifest: &StandardCashuMintManifestV1,
        now_unix: u64,
    ) -> Result<CashuSwapProgressV1, CashuClientErrorV1> {
        let context = CheckedContextV1::new(spend, checked, verified_offer, manifest, now_unix)?;
        let record = self
            .load_for_context(&context)?
            .ok_or(CashuClientErrorV1::IntentNotFound)?;
        self.drive(record, &context)
    }

    fn prepare_intent(
        &self,
        context: &CheckedContextV1<'_>,
        output_materials: Vec<CashuOutputMaterialV1>,
    ) -> Result<(NewCashuSwapIntentV1, CashuSwapRecoveryPlaintextV1), CashuClientErrorV1> {
        let (request, outputs) = build_swap_request_v1(context, &output_materials)?;
        let request_json = Zeroizing::new(encode_json_v1(&request)?);
        let output_json = Zeroizing::new(encode_json_v1(&CashuPostRestoreRequestJsonV1 {
            outputs: request.outputs.clone(),
        })?);
        let input_set_digest = context.input_set_digest;
        let request_digest = domain_digest_v1(REQUEST_DIGEST_DOMAIN_V1, &request_json);
        let output_set_digest = domain_digest_v1(OUTPUT_SET_DIGEST_DOMAIN_V1, &output_json);
        let intent_id = derive_intent_id_v1(&context.checked.mint_id, &input_set_digest);
        let expected_output_count =
            u32::try_from(outputs.len()).map_err(|_| CashuClientErrorV1::InvalidItemCount)?;
        let request_text = std::str::from_utf8(request_json.as_slice())
            .map_err(|_| CashuClientErrorV1::RecoveryPlaintextInvalid)?;
        let mut owned_request = Zeroizing::new(String::with_capacity(request_text.len()));
        owned_request.push_str(request_text);
        let recovery = CashuSwapRecoveryPlaintextV1 {
            version: 1,
            request_json: SensitiveRecoveryStringV1::new(std::mem::take(&mut *owned_request)),
            outputs,
            response_json: None,
            received_notes: Vec::new(),
        };
        let aad = CashuRecoveryAadV1 {
            intent_id,
            mint_id: context.checked.mint_id,
            manifest_digest: context.checked.manifest_digest,
            unit_digest: domain_digest_v1(
                CUSTODY_UNIT_DIGEST_DOMAIN_V1,
                context.checked.unit.as_bytes(),
            ),
            input_set_digest,
            request_digest,
            output_set_digest,
            offer_binding_digest: context.offer_binding_digest,
            settlement_value: context.checked.policy_price,
            expected_output_count,
        };
        let sealed_recovery = self.seal_recovery(&aad, &recovery)?;
        let new_intent = NewCashuSwapIntentV1 {
            intent_id,
            mint_id: context.checked.mint_id,
            manifest_digest: context.checked.manifest_digest,
            unit: context.checked.unit.clone(),
            input_set_digest,
            request_digest,
            output_set_digest,
            offer_binding_digest: context.offer_binding_digest,
            settlement_value: context.checked.policy_price,
            expected_output_count,
            sealed_recovery,
            created_bucket: coarse_time_bucket_v1(context.now_unix),
        };
        Ok((new_intent, recovery))
    }

    fn drive(
        &self,
        mut record: StoredCashuSwapIntentV1,
        context: &CheckedContextV1<'_>,
    ) -> Result<CashuSwapProgressV1, CashuClientErrorV1> {
        for _ in 0..3 {
            let recovery = self.open_and_validate_recovery(&record, context)?;
            match record.state {
                CashuSwapStateV1::Prepared => {
                    if self
                        .store
                        .begin_submission(&record.intent_id, context.now_unix)
                        .map_err(map_store_error)?
                    {
                        return self.submit_once(&record, recovery, context);
                    }
                }
                CashuSwapStateV1::Submitted | CashuSwapStateV1::Attention => {
                    return self.restore_only(&record, recovery, context);
                }
                CashuSwapStateV1::WalletStored => {
                    return self.finish_grant(&record, recovery, context);
                }
                CashuSwapStateV1::GrantIssued => {
                    return Ok(CashuSwapProgressV1::AlreadyGranted {
                        intent_id: record.intent_id,
                    });
                }
            }
            record = self
                .load_for_context(context)?
                .ok_or(CashuClientErrorV1::StateConflict)?;
        }
        Err(CashuClientErrorV1::StateConflict)
    }

    fn submit_once(
        &self,
        record: &StoredCashuSwapIntentV1,
        recovery: CashuSwapRecoveryPlaintextV1,
        context: &CheckedContextV1<'_>,
    ) -> Result<CashuSwapProgressV1, CashuClientErrorV1> {
        let response = self.transport.post_json(
            CashuMintTrustV1::from_manifest(context.manifest)?,
            CashuMintRouteV1::Swap,
            recovery.request_json.as_bytes(),
            MAX_CASHU_MINT_JSON_BYTES_V1,
        );
        match response {
            Ok(bytes) => {
                let bytes = Zeroizing::new(bytes);
                match self.commit_response(record, recovery, context, bytes.as_slice()) {
                    Ok(progress) => Ok(progress),
                    Err(
                        CashuClientErrorV1::InvalidJson
                        | CashuClientErrorV1::JsonTooLarge
                        | CashuClientErrorV1::InvalidMintPoint
                        | CashuClientErrorV1::InvalidMintScalar
                        | CashuClientErrorV1::MintResponseMismatch
                        | CashuClientErrorV1::MintDleqVerificationFailed,
                    ) => {
                        let recovery = self.open_and_validate_recovery(record, context)?;
                        self.restore_only(record, recovery, context)
                    }
                    Err(error) => Err(error),
                }
            }
            Err(_) => self.restore_only(record, recovery, context),
        }
    }

    fn restore_only(
        &self,
        record: &StoredCashuSwapIntentV1,
        recovery: CashuSwapRecoveryPlaintextV1,
        context: &CheckedContextV1<'_>,
    ) -> Result<CashuSwapProgressV1, CashuClientErrorV1> {
        let request: CashuPostSwapRequestJsonV1 = decode_json_v1(recovery.request_json.as_bytes())?;
        let restore_request = CashuPostRestoreRequestJsonV1 {
            outputs: request.outputs.clone(),
        };
        let body = Zeroizing::new(encode_json_v1(&restore_request)?);
        let response = self.transport.post_json(
            CashuMintTrustV1::from_manifest(context.manifest)?,
            CashuMintRouteV1::Restore,
            body.as_slice(),
            MAX_CASHU_MINT_JSON_BYTES_V1,
        );

        if let Ok(bytes) = response {
            let bytes = Zeroizing::new(bytes);
            match decode_mint_response_json_v1::<CashuPostRestoreResponseJsonV1>(bytes.as_slice()) {
                Ok(restored)
                    if restored.outputs == request.outputs
                        && restored.signatures.len() == request.outputs.len() =>
                {
                    let swap_response = CashuPostSwapResponseJsonV1 {
                        signatures: restored.signatures,
                    };
                    let canonical = Zeroizing::new(encode_json_v1(&swap_response)?);
                    return match self.commit_response(
                        record,
                        recovery,
                        context,
                        canonical.as_slice(),
                    ) {
                        Ok(progress) => Ok(progress),
                        Err(
                            CashuClientErrorV1::InvalidJson
                            | CashuClientErrorV1::JsonTooLarge
                            | CashuClientErrorV1::InvalidMintPoint
                            | CashuClientErrorV1::InvalidMintScalar
                            | CashuClientErrorV1::MintResponseMismatch
                            | CashuClientErrorV1::MintDleqVerificationFailed,
                        ) => {
                            self.store
                                .mark_attention(&record.intent_id, context.now_unix)
                                .map_err(map_store_error)?;
                            Ok(CashuSwapProgressV1::AttentionRequired {
                                intent_id: record.intent_id,
                                observation: CashuRecoveryObservationV1::BadMintResponse,
                            })
                        }
                        Err(error) => Err(error),
                    };
                }
                Ok(restored)
                    if valid_partial_restore_v1(&request.outputs, &restored.outputs)
                        && restored.outputs.len() == restored.signatures.len() => {}
                Ok(_) => {
                    self.store
                        .mark_attention(&record.intent_id, context.now_unix)
                        .map_err(map_store_error)?;
                    return Ok(CashuSwapProgressV1::AttentionRequired {
                        intent_id: record.intent_id,
                        observation: CashuRecoveryObservationV1::BadMintResponse,
                    });
                }
                Err(_) => {}
            }
        }
        self.observe_input_states(record, context)
    }

    fn observe_input_states(
        &self,
        record: &StoredCashuSwapIntentV1,
        context: &CheckedContextV1<'_>,
    ) -> Result<CashuSwapProgressV1, CashuClientErrorV1> {
        let ys = Zeroizing::new(
            context
                .spend
                .proofs
                .iter()
                .map(|proof| {
                    cashu_hash_to_curve_v1(proof.secret.as_bytes())
                        .map(|y| lower_hex(&y))
                        .map_err(|_| CashuClientErrorV1::InvalidCheckedSpend)
                })
                .collect::<Result<Vec<_>, _>>()?,
        );
        let request = CashuPostCheckStateRequestJsonV1 {
            ys: ys.iter().cloned().collect(),
        };
        let body = Zeroizing::new(encode_json_v1(&request)?);
        let response = self.transport.post_json(
            CashuMintTrustV1::from_manifest(context.manifest)?,
            CashuMintRouteV1::CheckState,
            &body,
            MAX_CASHU_MINT_JSON_BYTES_V1,
        );
        let Ok(bytes) = response else {
            return Ok(CashuSwapProgressV1::RecoveryPending {
                intent_id: record.intent_id,
                observation: CashuRecoveryObservationV1::MintUnavailable,
            });
        };
        let bytes = Zeroizing::new(bytes);
        let Ok(response) =
            decode_mint_response_json_v1::<CashuPostCheckStateResponseJsonV1>(&bytes)
        else {
            return Ok(CashuSwapProgressV1::RecoveryPending {
                intent_id: record.intent_id,
                observation: CashuRecoveryObservationV1::MintUnavailable,
            });
        };
        if response.states.len() != ys.len()
            || response
                .states
                .iter()
                .zip(ys.iter())
                .any(|(state, expected_y)| {
                    state.y != *expected_y || !is_bounded_nut07_witness_v1(state.witness.as_deref())
                })
        {
            self.store
                .mark_attention(&record.intent_id, context.now_unix)
                .map_err(map_store_error)?;
            return Ok(CashuSwapProgressV1::AttentionRequired {
                intent_id: record.intent_id,
                observation: CashuRecoveryObservationV1::BadMintResponse,
            });
        }

        let spent = response
            .states
            .iter()
            .filter(|state| state.state == CashuProofStateJsonV1::Spent)
            .count();
        let pending = response
            .states
            .iter()
            .filter(|state| state.state == CashuProofStateJsonV1::Pending)
            .count();
        let total = response.states.len();
        if spent == total {
            self.store
                .mark_attention(&record.intent_id, context.now_unix)
                .map_err(map_store_error)?;
            Ok(CashuSwapProgressV1::AttentionRequired {
                intent_id: record.intent_id,
                observation: CashuRecoveryObservationV1::InputsSpentButPromisesMissing,
            })
        } else if spent != 0 {
            self.store
                .mark_attention(&record.intent_id, context.now_unix)
                .map_err(map_store_error)?;
            Ok(CashuSwapProgressV1::AttentionRequired {
                intent_id: record.intent_id,
                observation: CashuRecoveryObservationV1::InconsistentInputStates,
            })
        } else if pending != 0 {
            Ok(CashuSwapProgressV1::RecoveryPending {
                intent_id: record.intent_id,
                observation: CashuRecoveryObservationV1::InputsPending,
            })
        } else {
            // This observation does not authorize another output set or even a
            // replay of the original NUT-03 request: a timed-out request may
            // still commit after this point-in-time NUT-07 response.
            Ok(CashuSwapProgressV1::RecoveryPending {
                intent_id: record.intent_id,
                observation: CashuRecoveryObservationV1::InputsUnspentObserved,
            })
        }
    }

    fn commit_response(
        &self,
        record: &StoredCashuSwapIntentV1,
        mut recovery: CashuSwapRecoveryPlaintextV1,
        context: &CheckedContextV1<'_>,
        response_json: &[u8],
    ) -> Result<CashuSwapProgressV1, CashuClientErrorV1> {
        let notes = verify_mint_response_v1(&recovery, context, response_json)?;
        let response_text =
            std::str::from_utf8(response_json).map_err(|_| CashuClientErrorV1::InvalidJson)?;
        let mut owned_response = Zeroizing::new(String::with_capacity(response_text.len()));
        owned_response.push_str(response_text);
        recovery.response_json = Some(SensitiveRecoveryStringV1::new(std::mem::take(
            &mut *owned_response,
        )));
        recovery.received_notes = notes;
        let sealed = self.seal_recovery(&record.aad(), &recovery)?;
        if !self
            .store
            .commit_wallet(&record.intent_id, &sealed, context.now_unix)
            .map_err(map_store_error)?
        {
            let current = self
                .load_for_context(context)?
                .ok_or(CashuClientErrorV1::StateConflict)?;
            return self.drive(current, context);
        }
        let current = self
            .load_for_context(context)?
            .ok_or(CashuClientErrorV1::StateConflict)?;
        self.finish_grant(&current, recovery, context)
    }

    fn finish_grant(
        &self,
        record: &StoredCashuSwapIntentV1,
        recovery: CashuSwapRecoveryPlaintextV1,
        context: &CheckedContextV1<'_>,
    ) -> Result<CashuSwapProgressV1, CashuClientErrorV1> {
        let response_json = recovery
            .response_json
            .as_ref()
            .ok_or(CashuClientErrorV1::RecoveryPlaintextInvalid)?;
        let verified_notes = verify_mint_response_v1(&recovery, context, response_json.as_bytes())?;
        if verified_notes != recovery.received_notes {
            return Err(CashuClientErrorV1::RecoveryPlaintextInvalid);
        }
        let note_count =
            u8::try_from(verified_notes.len()).map_err(|_| CashuClientErrorV1::InvalidItemCount)?;
        let mut custody = build_custody_lot_v1(record, context, &verified_notes)?;
        let custody_plaintext = custody.bundle.encode_canonical()?;
        let sealed_notes = self
            .custody_cipher
            .seal(&custody.aad, &custody_plaintext)
            .map_err(map_custody_cipher_error)?;
        sealed_notes.validate()?;
        let claim = self
            .store
            .claim_grant_once_with_custody(
                &record.intent_id,
                &NewCashuCustodyLotV1 {
                    lot_id: custody.aad.lot_id,
                    manifest_digest: custody.aad.manifest_digest,
                    active_keyset_digest: custody.aad.active_keyset_digest,
                    note_set_digest: custody.aad.note_set_digest,
                    note_ys: std::mem::take(&mut custody.note_ys),
                    sealed_notes,
                },
                context.now_unix,
            )
            .map_err(map_store_error)?;
        if claim.issued {
            Ok(CashuSwapProgressV1::Grant(VerifiedStandardCashuGrantV1 {
                intent_id: record.intent_id,
                mint_id: record.mint_id,
                input_set_digest: record.input_set_digest,
                offer_binding_digest: record.offer_binding_digest,
                settlement_value: record.settlement_value,
                received_note_count: note_count,
            }))
        } else {
            if claim.lot.lot_id != custody.aad.lot_id
                || claim.lot.mint_id != record.mint_id
                || claim.lot.manifest_digest != custody.aad.manifest_digest
                || claim.lot.active_keyset_digest != custody.aad.active_keyset_digest
                || claim.lot.note_set_digest != custody.aad.note_set_digest
                || claim.lot.unit != record.unit
                || claim.lot.settlement_value != record.settlement_value
                || claim.lot.note_count != u32::from(note_count)
            {
                return Err(CashuClientErrorV1::StoreConflict);
            }
            Ok(CashuSwapProgressV1::AlreadyGranted {
                intent_id: record.intent_id,
            })
        }
    }

    fn load_for_context(
        &self,
        context: &CheckedContextV1<'_>,
    ) -> Result<Option<StoredCashuSwapIntentV1>, CashuClientErrorV1> {
        self.store
            .load_by_input(&context.checked.mint_id, &context.input_set_digest)
            .map_err(map_store_error)
    }

    fn seal_recovery(
        &self,
        aad: &CashuRecoveryAadV1,
        recovery: &CashuSwapRecoveryPlaintextV1,
    ) -> Result<CashuSealedRecoveryV1, CashuClientErrorV1> {
        let plaintext = encode_recovery_plaintext_v1(recovery)?;
        let sealed = self
            .recovery_cipher
            .seal(aad, &plaintext)
            .map_err(map_cipher_error)?;
        sealed.validate()?;
        Ok(sealed)
    }

    fn open_and_validate_recovery(
        &self,
        record: &StoredCashuSwapIntentV1,
        context: &CheckedContextV1<'_>,
    ) -> Result<CashuSwapRecoveryPlaintextV1, CashuClientErrorV1> {
        record.sealed_recovery.validate()?;
        let plaintext = Zeroizing::new(
            self.recovery_cipher
                .open(&record.aad(), &record.sealed_recovery)
                .map_err(map_cipher_error)?,
        );
        if plaintext.len() > MAX_CASHU_RECOVERY_PLAINTEXT_BYTES_V1 {
            return Err(CashuClientErrorV1::RecoveryPlaintextInvalid);
        }
        let recovery = decode_recovery_plaintext_v1(&plaintext)?;
        validate_recovery_v1(record, context, &recovery)?;
        Ok(recovery)
    }
}

struct CheckedContextV1<'a> {
    spend: &'a StandardCashuSpendV1,
    checked: &'a StandardCashuSpendCheckV1,
    manifest: &'a StandardCashuMintManifestV1,
    input_set_digest: [u8; 32],
    offer_binding_digest: [u8; 32],
    now_unix: u64,
}

impl<'a> CheckedContextV1<'a> {
    fn new(
        spend: &'a StandardCashuSpendV1,
        checked: &'a StandardCashuSpendCheckV1,
        verified_offer: &VerifiedServiceOfferV1<'_>,
        manifest: &'a StandardCashuMintManifestV1,
        now_unix: u64,
    ) -> Result<Self, CashuClientErrorV1> {
        if now_unix == 0 || manifest.encode().is_err() {
            return Err(CashuClientErrorV1::InvalidManifest);
        }
        let derived_check = check_standard_cashu_spend_for_offer(spend, verified_offer, now_unix)
            .map_err(|_| CashuClientErrorV1::InvalidCheckedSpend)?;
        if &derived_check != checked {
            return Err(CashuClientErrorV1::InvalidCheckedSpend);
        }
        let manifest_digest = manifest
            .manifest_digest()
            .map_err(|_| CashuClientErrorV1::InvalidManifest)?;
        if checked.mint_id != manifest.mint_id()
            || checked.manifest_digest != manifest_digest
            || checked.mint_endpoint != manifest.mint_endpoint
            || checked.unit != manifest.unit
            || checked.net_amount != checked.policy_price
            || checked.policy_price == 0
            || manifest
                .active_output_keyset
                .final_expiry
                .is_some_and(|expiry| now_unix > expiry)
        {
            return Err(CashuClientErrorV1::InvalidCheckedSpend);
        }
        let spend_encoding = Zeroizing::new(
            spend
                .encode()
                .map_err(|_| CashuClientErrorV1::InvalidCheckedSpend)?,
        );
        let mut gross = 0u64;
        let mut fees_ppk = 0u64;
        for proof in &spend.proofs {
            if is_conditional_cashu_secret_v1(&proof.secret) {
                return Err(CashuClientErrorV1::ConditionalTokenUnsupported);
            }
            let keyset = manifest
                .accepted_input_keysets
                .iter()
                .find(|keyset| keyset.keyset_id == proof.keyset_id)
                .ok_or(CashuClientErrorV1::InvalidCheckedSpend)?;
            if keyset.unit != checked.unit
                || keyset.keys.iter().all(|key| key.amount != proof.amount)
                || keyset.final_expiry.is_some_and(|expiry| now_unix > expiry)
            {
                return Err(CashuClientErrorV1::InvalidCheckedSpend);
            }
            gross = gross
                .checked_add(proof.amount)
                .ok_or(CashuClientErrorV1::InvalidCheckedSpend)?;
            fees_ppk = fees_ppk
                .checked_add(u64::from(keyset.input_fee_ppk))
                .ok_or(CashuClientErrorV1::InvalidCheckedSpend)?;
        }
        let fee = fees_ppk
            .checked_add(999)
            .ok_or(CashuClientErrorV1::InvalidCheckedSpend)?
            / 1_000;
        let net = gross
            .checked_sub(fee)
            .ok_or(CashuClientErrorV1::InvalidCheckedSpend)?;
        if gross != checked.gross_input_amount
            || fees_ppk != checked.input_fee_ppk_total
            || fee != checked.input_fee_amount
        {
            return Err(CashuClientErrorV1::InvalidCheckedSpend);
        }
        if net < checked.policy_price {
            return Err(CashuClientErrorV1::Underpayment);
        }
        if net > checked.policy_price {
            return Err(CashuClientErrorV1::Overpayment);
        }
        Ok(Self {
            spend,
            checked,
            manifest,
            input_set_digest: domain_digest_v1(INPUT_SET_DIGEST_DOMAIN_V1, &spend_encoding),
            offer_binding_digest: standard_cashu_offer_binding_digest_v1(verified_offer),
            now_unix,
        })
    }
}

struct CashuSwapRecoveryPlaintextV1 {
    version: u8,
    request_json: SensitiveRecoveryStringV1,
    outputs: Vec<CashuOutputRecoveryV1>,
    response_json: Option<SensitiveRecoveryStringV1>,
    received_notes: Vec<CashuReceivedNoteRecoveryV1>,
}

struct SensitiveRecoveryStringV1(Zeroizing<String>);

impl SensitiveRecoveryStringV1 {
    fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    fn from_bytes(value: &[u8]) -> Result<Self, CashuClientErrorV1> {
        let text =
            std::str::from_utf8(value).map_err(|_| CashuClientErrorV1::RecoveryPlaintextInvalid)?;
        let mut owned = Zeroizing::new(String::with_capacity(text.len()));
        owned.push_str(text);
        debug_assert!(owned.capacity() >= owned.len());
        Ok(Self(owned))
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    #[cfg(test)]
    fn capacity(&self) -> usize {
        self.0.capacity()
    }
}

impl Drop for SensitiveRecoveryStringV1 {
    fn drop(&mut self) {
        #[cfg(test)]
        let contained_sensitive_bytes = !self.0.is_empty();
        self.0.zeroize();
        #[cfg(test)]
        if contained_sensitive_bytes {
            RECOVERY_CODEC_ZEROIZED_DROPS_V1.with(|count| count.set(count.get().saturating_add(1)));
        }
    }
}

#[derive(Eq, Hash, PartialEq)]
struct SensitiveBytes32V1([u8; 32]);

impl SensitiveBytes32V1 {
    fn new(mut value: [u8; 32]) -> Self {
        let sensitive = Self(value);
        value.zeroize();
        sensitive
    }

    fn from_slice(value: &[u8]) -> Result<Self, CashuClientErrorV1> {
        if value.len() != 32 {
            return Err(CashuClientErrorV1::RecoveryPlaintextInvalid);
        }
        let mut sensitive = Self([0u8; 32]);
        sensitive.0.copy_from_slice(value);
        Ok(sensitive)
    }

    const fn as_array(&self) -> &[u8; 32] {
        &self.0
    }

    const fn copied(&self) -> [u8; 32] {
        self.0
    }
}

impl Drop for SensitiveBytes32V1 {
    fn drop(&mut self) {
        #[cfg(test)]
        let contained_sensitive_bytes = self.0.iter().any(|byte| *byte != 0);
        self.0.zeroize();
        #[cfg(test)]
        if contained_sensitive_bytes {
            RECOVERY_CODEC_ZEROIZED_DROPS_V1.with(|count| count.set(count.get().saturating_add(1)));
        }
    }
}

struct SensitiveBytes32SetV1(HashSet<SensitiveBytes32V1>);

impl SensitiveBytes32SetV1 {
    fn with_capacity(capacity: usize) -> Self {
        Self(HashSet::with_capacity(capacity))
    }

    fn insert(&mut self, value: [u8; 32]) -> bool {
        self.0.insert(SensitiveBytes32V1::new(value))
    }
}

impl Drop for SensitiveBytes32SetV1 {
    fn drop(&mut self) {
        // Clearing explicitly runs every key's zeroizing destructor before the
        // hash table releases its backing allocation.
        self.0.clear();
    }
}

struct CashuOutputRecoveryV1 {
    amount: u64,
    secret_bytes: SensitiveBytes32V1,
    blinding_scalar: SensitiveBytes32V1,
}

#[derive(Eq, PartialEq)]
struct CashuReceivedNoteRecoveryV1 {
    amount: u64,
    secret_bytes: SensitiveBytes32V1,
    unblinded_signature: SensitiveRecoveryBytesV1,
}

#[derive(Eq, PartialEq)]
struct SensitiveRecoveryBytesV1([u8; 33]);

impl SensitiveRecoveryBytesV1 {
    fn new(mut value: [u8; 33]) -> Self {
        let sensitive = Self(value);
        value.zeroize();
        sensitive
    }

    fn from_slice(value: &[u8]) -> Result<Self, CashuClientErrorV1> {
        if value.len() != 33 {
            return Err(CashuClientErrorV1::RecoveryPlaintextInvalid);
        }
        let mut sensitive = Self([0u8; 33]);
        sensitive.0.copy_from_slice(value);
        Ok(sensitive)
    }

    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Drop for SensitiveRecoveryBytesV1 {
    fn drop(&mut self) {
        #[cfg(test)]
        let contained_sensitive_bytes = self.0.iter().any(|byte| *byte != 0);
        self.0.zeroize();
        #[cfg(test)]
        if contained_sensitive_bytes {
            RECOVERY_CODEC_ZEROIZED_DROPS_V1.with(|count| count.set(count.get().saturating_add(1)));
        }
    }
}

#[cfg(test)]
std::thread_local! {
    static RECOVERY_CODEC_ZEROIZED_DROPS_V1: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

const CASHU_RECOVERY_MAGIC_V1: &[u8; 8] = b"BPIRRCV1";
const CASHU_RECOVERY_CODEC_VERSION_V1: u8 = 1;
const CASHU_RECOVERY_RESPONSE_PRESENT_V1: u8 = 0x01;
const CASHU_RECOVERY_HEADER_BYTES_V1: usize = 32;
const CASHU_OUTPUT_RECOVERY_BYTES_V1: usize = 8 + 32 + 32;
const CASHU_RECEIVED_NOTE_RECOVERY_BYTES_V1: usize = 8 + 32 + 33;

fn encode_recovery_plaintext_v1(
    recovery: &CashuSwapRecoveryPlaintextV1,
) -> Result<Zeroizing<Vec<u8>>, CashuClientErrorV1> {
    let encoded_len = recovery_plaintext_encoded_len_v1(recovery)?;
    let request_len = u32::try_from(recovery.request_json.as_bytes().len())
        .map_err(|_| CashuClientErrorV1::RecoveryPlaintextInvalid)?;
    let output_count = u32::try_from(recovery.outputs.len())
        .map_err(|_| CashuClientErrorV1::RecoveryPlaintextInvalid)?;
    let response_len = u32::try_from(
        recovery
            .response_json
            .as_ref()
            .map_or(0, |response| response.as_bytes().len()),
    )
    .map_err(|_| CashuClientErrorV1::RecoveryPlaintextInvalid)?;
    let received_count = u32::try_from(recovery.received_notes.len())
        .map_err(|_| CashuClientErrorV1::RecoveryPlaintextInvalid)?;
    let flags = if recovery.response_json.is_some() {
        CASHU_RECOVERY_RESPONSE_PRESENT_V1
    } else {
        0
    };
    let mut writer = BoundedZeroizingWriterV1::new(MAX_CASHU_RECOVERY_PLAINTEXT_BYTES_V1);
    {
        let mut write = |bytes: &[u8]| {
            writer
                .write_all(bytes)
                .map_err(|_| CashuClientErrorV1::RecoveryPlaintextInvalid)
        };
        write(CASHU_RECOVERY_MAGIC_V1)?;
        write(&[CASHU_RECOVERY_CODEC_VERSION_V1, flags])?;
        write(&0u16.to_le_bytes())?;
        write(
            &u32::try_from(encoded_len)
                .map_err(|_| CashuClientErrorV1::RecoveryPlaintextInvalid)?
                .to_le_bytes(),
        )?;
        write(&request_len.to_le_bytes())?;
        write(&output_count.to_le_bytes())?;
        write(&response_len.to_le_bytes())?;
        write(&received_count.to_le_bytes())?;
        write(recovery.request_json.as_bytes())?;
        for output in &recovery.outputs {
            write(&output.amount.to_le_bytes())?;
            write(output.secret_bytes.as_array())?;
            write(output.blinding_scalar.as_array())?;
        }
        if let Some(response) = &recovery.response_json {
            write(response.as_bytes())?;
        }
        for note in &recovery.received_notes {
            write(&note.amount.to_le_bytes())?;
            write(note.secret_bytes.as_array())?;
            write(note.unblinded_signature.as_slice())?;
        }
    }
    let plaintext = writer.into_inner();
    if plaintext.len() != encoded_len {
        return Err(CashuClientErrorV1::RecoveryPlaintextInvalid);
    }
    Ok(plaintext)
}

fn recovery_plaintext_encoded_len_v1(
    recovery: &CashuSwapRecoveryPlaintextV1,
) -> Result<usize, CashuClientErrorV1> {
    let request_len = recovery.request_json.as_bytes().len();
    if recovery.version != CASHU_RECOVERY_CODEC_VERSION_V1
        || request_len == 0
        || request_len > MAX_CASHU_MINT_JSON_BYTES_V1
        || recovery.outputs.is_empty()
        || recovery.outputs.len() > MAX_CASHU_SWAP_ITEMS_V1
        || recovery.outputs.iter().any(|output| {
            output.amount == 0
                || output.secret_bytes.as_array().iter().all(|byte| *byte == 0)
                || output
                    .blinding_scalar
                    .as_array()
                    .iter()
                    .all(|byte| *byte == 0)
        })
    {
        return Err(CashuClientErrorV1::RecoveryPlaintextInvalid);
    }
    let response_len = match &recovery.response_json {
        None if recovery.received_notes.is_empty() => 0,
        Some(response)
            if !response.as_bytes().is_empty()
                && response.as_bytes().len() <= MAX_CASHU_MINT_JSON_BYTES_V1
                && recovery.received_notes.len() == recovery.outputs.len()
                && recovery.received_notes.len() <= MAX_CASHU_SWAP_ITEMS_V1
                && recovery.received_notes.iter().all(|note| {
                    note.amount != 0
                        && note.secret_bytes.as_array().iter().any(|byte| *byte != 0)
                        && matches!(note.unblinded_signature.as_slice()[0], 0x02 | 0x03)
                        && note.unblinded_signature.as_slice()[1..]
                            .iter()
                            .any(|byte| *byte != 0)
                }) =>
        {
            response.as_bytes().len()
        }
        _ => return Err(CashuClientErrorV1::RecoveryPlaintextInvalid),
    };
    let encoded_len = CASHU_RECOVERY_HEADER_BYTES_V1
        .checked_add(request_len)
        .and_then(|length| {
            length.checked_add(
                recovery
                    .outputs
                    .len()
                    .checked_mul(CASHU_OUTPUT_RECOVERY_BYTES_V1)?,
            )
        })
        .and_then(|length| length.checked_add(response_len))
        .and_then(|length| {
            length.checked_add(
                recovery
                    .received_notes
                    .len()
                    .checked_mul(CASHU_RECEIVED_NOTE_RECOVERY_BYTES_V1)?,
            )
        })
        .ok_or(CashuClientErrorV1::RecoveryPlaintextInvalid)?;
    if encoded_len > MAX_CASHU_RECOVERY_PLAINTEXT_BYTES_V1 || u32::try_from(encoded_len).is_err() {
        return Err(CashuClientErrorV1::RecoveryPlaintextInvalid);
    }
    Ok(encoded_len)
}

fn decode_recovery_plaintext_v1(
    plaintext: &[u8],
) -> Result<CashuSwapRecoveryPlaintextV1, CashuClientErrorV1> {
    if plaintext.len() < CASHU_RECOVERY_HEADER_BYTES_V1
        || plaintext.len() > MAX_CASHU_RECOVERY_PLAINTEXT_BYTES_V1
    {
        return Err(CashuClientErrorV1::RecoveryPlaintextInvalid);
    }
    let mut reader = CashuRecoveryReaderV1::new(plaintext);
    if reader.take(CASHU_RECOVERY_MAGIC_V1.len())? != CASHU_RECOVERY_MAGIC_V1
        || reader.read_u8()? != CASHU_RECOVERY_CODEC_VERSION_V1
    {
        return Err(CashuClientErrorV1::RecoveryPlaintextInvalid);
    }
    let flags = reader.read_u8()?;
    if flags & !CASHU_RECOVERY_RESPONSE_PRESENT_V1 != 0 || reader.read_u16()? != 0 {
        return Err(CashuClientErrorV1::RecoveryPlaintextInvalid);
    }
    let total_len = reader.read_u32_as_usize()?;
    let request_len = reader.read_u32_as_usize()?;
    let output_count = reader.read_u32_as_usize()?;
    let response_len = reader.read_u32_as_usize()?;
    let received_count = reader.read_u32_as_usize()?;
    let response_present = flags == CASHU_RECOVERY_RESPONSE_PRESENT_V1;
    if total_len != plaintext.len()
        || request_len == 0
        || request_len > MAX_CASHU_MINT_JSON_BYTES_V1
        || output_count == 0
        || output_count > MAX_CASHU_SWAP_ITEMS_V1
        || response_present != (response_len != 0)
        || response_len > MAX_CASHU_MINT_JSON_BYTES_V1
        || (!response_present && received_count != 0)
        || (response_present
            && (received_count == 0
                || received_count != output_count
                || received_count > MAX_CASHU_SWAP_ITEMS_V1))
    {
        return Err(CashuClientErrorV1::RecoveryPlaintextInvalid);
    }
    let expected_len = CASHU_RECOVERY_HEADER_BYTES_V1
        .checked_add(request_len)
        .and_then(|length| {
            length.checked_add(output_count.checked_mul(CASHU_OUTPUT_RECOVERY_BYTES_V1)?)
        })
        .and_then(|length| length.checked_add(response_len))
        .and_then(|length| {
            length.checked_add(received_count.checked_mul(CASHU_RECEIVED_NOTE_RECOVERY_BYTES_V1)?)
        })
        .ok_or(CashuClientErrorV1::RecoveryPlaintextInvalid)?;
    if expected_len != total_len {
        return Err(CashuClientErrorV1::RecoveryPlaintextInvalid);
    }

    let request_json = SensitiveRecoveryStringV1::from_bytes(reader.take(request_len)?)?;
    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        let amount = reader.read_u64()?;
        if amount == 0 {
            return Err(CashuClientErrorV1::RecoveryPlaintextInvalid);
        }
        let secret_bytes = SensitiveBytes32V1::from_slice(reader.take(32)?)?;
        let blinding_scalar = SensitiveBytes32V1::from_slice(reader.take(32)?)?;
        if secret_bytes.as_array().iter().all(|byte| *byte == 0)
            || blinding_scalar.as_array().iter().all(|byte| *byte == 0)
        {
            return Err(CashuClientErrorV1::RecoveryPlaintextInvalid);
        }
        outputs.push(CashuOutputRecoveryV1 {
            amount,
            secret_bytes,
            blinding_scalar,
        });
    }

    let response_json = if response_present {
        Some(SensitiveRecoveryStringV1::from_bytes(
            reader.take(response_len)?,
        )?)
    } else {
        None
    };
    let mut received_notes = Vec::with_capacity(received_count);
    for _ in 0..received_count {
        let amount = reader.read_u64()?;
        if amount == 0 {
            return Err(CashuClientErrorV1::RecoveryPlaintextInvalid);
        }
        let secret_bytes = SensitiveBytes32V1::from_slice(reader.take(32)?)?;
        let unblinded_signature = SensitiveRecoveryBytesV1::from_slice(reader.take(33)?)?;
        if secret_bytes.as_array().iter().all(|byte| *byte == 0)
            || !matches!(unblinded_signature.as_slice()[0], 0x02 | 0x03)
            || unblinded_signature.as_slice()[1..]
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(CashuClientErrorV1::RecoveryPlaintextInvalid);
        }
        received_notes.push(CashuReceivedNoteRecoveryV1 {
            amount,
            secret_bytes,
            unblinded_signature,
        });
    }
    if !reader.is_at_end() {
        return Err(CashuClientErrorV1::RecoveryPlaintextInvalid);
    }
    Ok(CashuSwapRecoveryPlaintextV1 {
        version: CASHU_RECOVERY_CODEC_VERSION_V1,
        request_json,
        outputs,
        response_json,
        received_notes,
    })
}

struct CashuRecoveryReaderV1<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CashuRecoveryReaderV1<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], CashuClientErrorV1> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(CashuClientErrorV1::RecoveryPlaintextInvalid)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CashuClientErrorV1::RecoveryPlaintextInvalid)?;
        self.offset = end;
        Ok(value)
    }

    fn read_u8(&mut self) -> Result<u8, CashuClientErrorV1> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(CashuClientErrorV1::RecoveryPlaintextInvalid)
    }

    fn read_u16(&mut self) -> Result<u16, CashuClientErrorV1> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32_as_usize(&mut self) -> Result<usize, CashuClientErrorV1> {
        let bytes = self.take(4)?;
        usize::try_from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            .map_err(|_| CashuClientErrorV1::RecoveryPlaintextInvalid)
    }

    fn read_u64(&mut self) -> Result<u64, CashuClientErrorV1> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn is_at_end(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn build_swap_request_v1(
    context: &CheckedContextV1<'_>,
    output_materials: &[CashuOutputMaterialV1],
) -> Result<(CashuPostSwapRequestJsonV1, Vec<CashuOutputRecoveryV1>), CashuClientErrorV1> {
    validate_item_count_v1(output_materials.len())?;
    let active = &context.manifest.active_output_keyset;
    let mut secrets = SensitiveBytes32SetV1::with_capacity(output_materials.len());
    let mut blindings = SensitiveBytes32SetV1::with_capacity(output_materials.len());
    let mut blinded_points = HashSet::with_capacity(output_materials.len());
    let mut total = 0u64;
    let mut built = Vec::with_capacity(output_materials.len());
    for material in output_materials {
        if material.amount == 0
            || material.secret_bytes.iter().all(|byte| *byte == 0)
            || active.keys.iter().all(|key| key.amount != material.amount)
            || !secrets.insert(material.secret_bytes)
            || !blindings.insert(material.blinding_scalar)
        {
            return Err(CashuClientErrorV1::InvalidOutputMaterial);
        }
        total = total
            .checked_add(material.amount)
            .ok_or(CashuClientErrorV1::Overpayment)?;
        let secret_text = Zeroizing::new(lower_hex(&material.secret_bytes));
        let blinded_message =
            blind_cashu_message_v1(secret_text.as_bytes(), &material.blinding_scalar)
                .map_err(|_| CashuClientErrorV1::InvalidOutputMaterial)?;
        if !blinded_points.insert(blinded_message) {
            return Err(CashuClientErrorV1::InvalidOutputMaterial);
        }
        built.push((
            CashuBlindedMessageJsonV1 {
                amount: material.amount,
                id: active.keyset_id.clone(),
                blinded_message: lower_hex(&blinded_message),
            },
            CashuOutputRecoveryV1 {
                amount: material.amount,
                secret_bytes: SensitiveBytes32V1::new(material.secret_bytes),
                blinding_scalar: SensitiveBytes32V1::new(material.blinding_scalar),
            },
        ));
    }
    if total < context.checked.policy_price {
        return Err(CashuClientErrorV1::Underpayment);
    }
    if total > context.checked.policy_price {
        return Err(CashuClientErrorV1::Overpayment);
    }
    built.sort_by(|left, right| {
        left.0
            .amount
            .cmp(&right.0.amount)
            .then_with(|| left.0.blinded_message.cmp(&right.0.blinded_message))
    });
    let (outputs, output_recovery): (Vec<_>, Vec<_>) = built.into_iter().unzip();
    let inputs = context
        .spend
        .proofs
        .iter()
        .map(|proof| CashuProofJsonV1 {
            amount: proof.amount,
            id: proof.keyset_id.clone(),
            secret: proof.secret.clone(),
            c: lower_hex(&proof.c),
        })
        .collect();
    Ok((
        CashuPostSwapRequestJsonV1 { inputs, outputs },
        output_recovery,
    ))
}

fn validate_recovery_v1(
    record: &StoredCashuSwapIntentV1,
    context: &CheckedContextV1<'_>,
    recovery: &CashuSwapRecoveryPlaintextV1,
) -> Result<(), CashuClientErrorV1> {
    if recovery.version != 1
        || record.mint_id != context.checked.mint_id
        || record.manifest_digest != context.checked.manifest_digest
        || record.unit != context.checked.unit
        || record.input_set_digest != context.input_set_digest
        || record.offer_binding_digest != context.offer_binding_digest
        || record.settlement_value != context.checked.policy_price
        || usize::try_from(record.expected_output_count).ok() != Some(recovery.outputs.len())
    {
        return Err(CashuClientErrorV1::RecoveryPlaintextInvalid);
    }
    let request: CashuPostSwapRequestJsonV1 = decode_json_v1(recovery.request_json.as_bytes())?;
    let canonical_request = Zeroizing::new(encode_json_v1(&request)?);
    if canonical_request.as_slice() != recovery.request_json.as_bytes() {
        return Err(CashuClientErrorV1::RecoveryPlaintextInvalid);
    }
    let proposed: Vec<CashuOutputMaterialV1> = recovery
        .outputs
        .iter()
        .map(|output| {
            CashuOutputMaterialV1::new(
                output.amount,
                output.secret_bytes.copied(),
                output.blinding_scalar.copied(),
            )
        })
        .collect();
    let (expected, _) = build_swap_request_v1(context, &proposed)?;
    if request != expected {
        return Err(CashuClientErrorV1::RecoveryPlaintextInvalid);
    }
    let request_digest =
        domain_digest_v1(REQUEST_DIGEST_DOMAIN_V1, recovery.request_json.as_bytes());
    let output_json = Zeroizing::new(encode_json_v1(&CashuPostRestoreRequestJsonV1 {
        outputs: request.outputs,
    })?);
    let output_digest = domain_digest_v1(OUTPUT_SET_DIGEST_DOMAIN_V1, &output_json);
    if request_digest != record.request_digest || output_digest != record.output_set_digest {
        return Err(CashuClientErrorV1::RecoveryPlaintextInvalid);
    }
    if recovery.response_json.is_none() != recovery.received_notes.is_empty() {
        return Err(CashuClientErrorV1::RecoveryPlaintextInvalid);
    }
    Ok(())
}

fn verify_mint_response_v1(
    recovery: &CashuSwapRecoveryPlaintextV1,
    context: &CheckedContextV1<'_>,
    response_json: &[u8],
) -> Result<Vec<CashuReceivedNoteRecoveryV1>, CashuClientErrorV1> {
    let request: CashuPostSwapRequestJsonV1 = decode_json_v1(recovery.request_json.as_bytes())?;
    let response: CashuPostSwapResponseJsonV1 = decode_mint_response_json_v1(response_json)?;
    validate_item_count_v1(response.signatures.len())?;
    if request.outputs.len() != response.signatures.len()
        || request.outputs.len() != recovery.outputs.len()
    {
        return Err(CashuClientErrorV1::MintResponseMismatch);
    }
    let active = &context.manifest.active_output_keyset;
    let mut notes = Vec::with_capacity(response.signatures.len());
    let mut signatures = HashSet::with_capacity(response.signatures.len());
    for ((output, material), signature) in request
        .outputs
        .iter()
        .zip(&recovery.outputs)
        .zip(&response.signatures)
    {
        if signature.amount != output.amount
            || signature.id != output.id
            || signature.id != active.keyset_id
            || material.amount != output.amount
        {
            return Err(CashuClientErrorV1::MintResponseMismatch);
        }
        let blinded_message = decode_lower_hex::<33>(
            &output.blinded_message,
            CashuClientErrorV1::InvalidMintPoint,
        )?;
        let blinded_signature = decode_lower_hex::<33>(
            &signature.blinded_signature,
            CashuClientErrorV1::InvalidMintPoint,
        )?;
        if !signatures.insert(blinded_signature) {
            return Err(CashuClientErrorV1::MintResponseMismatch);
        }
        let dleq_e =
            decode_lower_hex::<32>(&signature.dleq.e, CashuClientErrorV1::InvalidMintScalar)?;
        let dleq_s =
            decode_lower_hex::<32>(&signature.dleq.s, CashuClientErrorV1::InvalidMintScalar)?;
        let denomination_key = active
            .keys
            .iter()
            .find(|key| key.amount == output.amount)
            .ok_or(CashuClientErrorV1::InvalidManifest)?;
        let secret_text = Zeroizing::new(lower_hex(material.secret_bytes.as_array()));
        let verified = verify_and_unblind_cashu_promise_v1(
            secret_text.as_bytes(),
            material.blinding_scalar.as_array(),
            &denomination_key.public_key,
            &blinded_message,
            &blinded_signature,
            &dleq_e,
            &dleq_s,
        )
        .map_err(|_| CashuClientErrorV1::MintDleqVerificationFailed)?;
        notes.push(CashuReceivedNoteRecoveryV1 {
            amount: output.amount,
            secret_bytes: SensitiveBytes32V1::new(material.secret_bytes.copied()),
            unblinded_signature: SensitiveRecoveryBytesV1::new(*verified.unblinded_signature()),
        });
    }
    Ok(notes)
}

struct BuiltCashuCustodyLotV1 {
    aad: CashuCustodyAadV1,
    note_ys: Vec<[u8; 33]>,
    bundle: CashuCustodyBundleV1,
}

impl Drop for BuiltCashuCustodyLotV1 {
    fn drop(&mut self) {
        self.note_ys.zeroize();
    }
}

fn build_custody_lot_v1(
    record: &StoredCashuSwapIntentV1,
    context: &CheckedContextV1<'_>,
    verified_notes: &[CashuReceivedNoteRecoveryV1],
) -> Result<BuiltCashuCustodyLotV1, CashuClientErrorV1> {
    validate_item_count_v1(verified_notes.len())?;
    if usize::try_from(record.expected_output_count).ok() != Some(verified_notes.len()) {
        return Err(CashuClientErrorV1::RecoveryPlaintextInvalid);
    }
    let mut total = 0u64;
    let mut notes = Vec::with_capacity(verified_notes.len());
    let mut note_ys = Zeroizing::new(Vec::with_capacity(verified_notes.len()));
    let mut y_digests = HashSet::with_capacity(verified_notes.len());
    for verified in verified_notes {
        total = total
            .checked_add(verified.amount)
            .ok_or(CashuClientErrorV1::InvalidCustodyPlaintext)?;
        let mut secret = Zeroizing::new(lower_hex(verified.secret_bytes.as_array()));
        let y = Zeroizing::new(
            cashu_hash_to_curve_v1(secret.as_bytes())
                .map_err(|_| CashuClientErrorV1::InvalidCustodyPlaintext)?,
        );
        let mut hasher = Sha256::new();
        hasher.update(CUSTODY_NOTE_Y_DIGEST_DOMAIN_V1);
        hasher.update(record.mint_id);
        hasher.update(y.as_slice());
        let y_digest: [u8; 32] = hasher.finalize().into();
        if !y_digests.insert(y_digest) {
            return Err(CashuClientErrorV1::InvalidCustodyPlaintext);
        }
        let c: [u8; 33] = verified
            .unblinded_signature
            .as_slice()
            .try_into()
            .map_err(|_| CashuClientErrorV1::InvalidCustodyPlaintext)?;
        notes.push(CashuCustodyNoteV1::new(
            verified.amount,
            std::mem::take(&mut *secret),
            c,
            y_digest,
        )?);
        note_ys.push(*y);
    }
    if total != record.settlement_value {
        return Err(CashuClientErrorV1::InvalidCustodyPlaintext);
    }
    custody::sort_custody_notes(&mut notes);
    note_ys.sort_unstable();
    let mut ordered_digests = y_digests.into_iter().collect::<Vec<_>>();
    ordered_digests.sort_unstable();
    let mut set_hasher = Sha256::new();
    set_hasher.update(CUSTODY_NOTE_SET_DIGEST_DOMAIN_V1);
    set_hasher.update((ordered_digests.len() as u32).to_le_bytes());
    for digest in &ordered_digests {
        set_hasher.update(digest);
    }
    let note_set_digest: [u8; 32] = set_hasher.finalize().into();
    let unit_digest = domain_digest_v1(CUSTODY_UNIT_DIGEST_DOMAIN_V1, record.unit.as_bytes());
    let active_keyset_digest = domain_digest_v1(
        CUSTODY_KEYSET_DIGEST_DOMAIN_V1,
        context.manifest.active_output_keyset.keyset_id.as_bytes(),
    );
    let mut lot_hasher = Sha256::new();
    lot_hasher.update(CUSTODY_LOT_ID_DOMAIN_V1);
    lot_hasher.update(record.mint_id);
    lot_hasher.update(record.manifest_digest);
    lot_hasher.update(unit_digest);
    lot_hasher.update(active_keyset_digest);
    lot_hasher.update(note_set_digest);
    lot_hasher.update(record.settlement_value.to_le_bytes());
    lot_hasher.update(record.expected_output_count.to_le_bytes());
    let lot_digest: [u8; 32] = lot_hasher.finalize().into();
    let lot_id: [u8; 16] = lot_digest[..16]
        .try_into()
        .map_err(|_| CashuClientErrorV1::InvalidCustodyPlaintext)?;
    if lot_id.iter().all(|byte| *byte == 0) {
        return Err(CashuClientErrorV1::InvalidCustodyPlaintext);
    }
    let mint_endpoint = context
        .manifest
        .mint_endpoint
        .trim_end_matches('/')
        .to_owned();
    let bundle = CashuCustodyBundleV1::new(
        mint_endpoint,
        record.manifest_digest,
        context.manifest.leaf_spki_sha256_pins.clone(),
        record.unit.clone(),
        context.manifest.active_output_keyset.keyset_id.clone(),
        note_set_digest,
        notes,
    )?;
    Ok(BuiltCashuCustodyLotV1 {
        aad: CashuCustodyAadV1 {
            lot_id,
            mint_id: record.mint_id,
            manifest_digest: record.manifest_digest,
            unit_digest,
            active_keyset_digest,
            note_set_digest,
            settlement_value: record.settlement_value,
            note_count: record.expected_output_count,
        },
        note_ys: std::mem::take(&mut *note_ys),
        bundle,
    })
}

fn valid_partial_restore_v1(
    expected: &[CashuBlindedMessageJsonV1],
    restored: &[CashuBlindedMessageJsonV1],
) -> bool {
    if restored.len() > expected.len() {
        return false;
    }
    let mut expected_iter = expected.iter();
    restored
        .iter()
        .all(|candidate| expected_iter.by_ref().any(|expected| expected == candidate))
}

fn is_conditional_cashu_secret_v1(secret: &str) -> bool {
    let Ok(serde_json::Value::Array(elements)) = serde_json::from_str(secret) else {
        return false;
    };
    elements.len() == 2 && elements[0].is_string() && elements[1].is_object()
}

pub(crate) fn domain_digest_v1(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(value);
    hasher.finalize().into()
}

/// Bind a successful external-mint swap to the exact signed provider offer
/// and service scope. Runtime admission must compare this digest with the
/// currently bound authorization attempt before installing the operation
/// grant; equal mint IDs and prices are not sufficient.
pub fn standard_cashu_offer_binding_digest_v1(
    verified_offer: &VerifiedServiceOfferV1<'_>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CASHU_OFFER_BINDING_DIGEST_DOMAIN_V1);
    hasher.update(verified_offer.policy_digest());
    hasher.update(verified_offer.scope().scope_id());
    hasher.update(verified_offer.offer().offer_id.to_le_bytes());
    hasher.finalize().into()
}

fn derive_intent_id_v1(mint_id: &[u8; 32], input_set_digest: &[u8; 32]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(INTENT_ID_DOMAIN_V1);
    hasher.update(mint_id);
    hasher.update(input_set_digest);
    let digest: [u8; 32] = hasher.finalize().into();
    digest[..16].try_into().expect("fixed digest prefix")
}

fn coarse_time_bucket_v1(now_unix: u64) -> u64 {
    now_unix / 3_600
}

fn map_store_error(error: CashuSwapStoreErrorV1) -> CashuClientErrorV1 {
    match error {
        CashuSwapStoreErrorV1::Conflict | CashuSwapStoreErrorV1::CustodyConflict => {
            CashuClientErrorV1::StoreConflict
        }
        CashuSwapStoreErrorV1::ExposureExceeded => CashuClientErrorV1::ExposureLimitExceeded,
        CashuSwapStoreErrorV1::Unavailable
        | CashuSwapStoreErrorV1::Busy
        | CashuSwapStoreErrorV1::Corrupt => CashuClientErrorV1::StoreUnavailable,
    }
}

fn map_custody_cipher_error(error: CashuCustodyCipherErrorV1) -> CashuClientErrorV1 {
    match error {
        CashuCustodyCipherErrorV1::AuthenticationFailed => {
            CashuClientErrorV1::CustodyAuthenticationFailed
        }
        CashuCustodyCipherErrorV1::InvalidPlaintext => CashuClientErrorV1::InvalidCustodyPlaintext,
        CashuCustodyCipherErrorV1::Unavailable | CashuCustodyCipherErrorV1::UnknownKeyEpoch => {
            CashuClientErrorV1::CustodyCipherUnavailable
        }
    }
}

fn map_cipher_error(error: CashuRecoveryCipherErrorV1) -> CashuClientErrorV1 {
    match error {
        CashuRecoveryCipherErrorV1::AuthenticationFailed => {
            CashuClientErrorV1::RecoveryAuthenticationFailed
        }
        CashuRecoveryCipherErrorV1::InvalidPlaintext => {
            CashuClientErrorV1::RecoveryPlaintextInvalid
        }
        CashuRecoveryCipherErrorV1::Unavailable | CashuRecoveryCipherErrorV1::UnknownKeyEpoch => {
            CashuClientErrorV1::RecoveryCipherUnavailable
        }
    }
}

#[cfg(test)]
mod tests;
