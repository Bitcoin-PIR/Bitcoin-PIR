//! Fail-closed standard Cashu merchant swap and recovery adapter.
//!
//! This crate is intentionally a merchant wallet, not a second Cashu mint.
//! The accepted external mint's atomic NUT-03 input invalidation is the only
//! authoritative spent-set. BitcoinPIR persists an encrypted recovery intent
//! and an at-most-once grant-delivery state, but never writes those inputs into
//! the provider-local bearer spent-set.

#![forbid(unsafe_code)]

mod dto;
mod store;

#[cfg(not(target_arch = "wasm32"))]
mod provider_store;

#[cfg(not(target_arch = "wasm32"))]
mod runtime_admission;

#[cfg(any(test, feature = "insecure-dev-sqlite-store"))]
mod sqlite;

use std::collections::HashSet;
use std::fmt;

use dto::{
    decode_json_v1, decode_lower_hex, encode_json_v1, lower_hex, validate_item_count_v1,
    CashuBlindedMessageJsonV1, CashuPostCheckStateRequestJsonV1, CashuPostCheckStateResponseJsonV1,
    CashuPostRestoreRequestJsonV1, CashuPostRestoreResponseJsonV1, CashuPostSwapRequestJsonV1,
    CashuPostSwapResponseJsonV1, CashuProofJsonV1, CashuProofStateJsonV1,
};
use pir_payment_crypto::{
    blind_cashu_message_v1, cashu_hash_to_curve_v1, verify_and_unblind_cashu_promise_v1,
};
use pir_service_protocol::{
    check_standard_cashu_spend_for_offer, StandardCashuMintManifestV1, StandardCashuSpendCheckV1,
    StandardCashuSpendV1, VerifiedServiceOfferV1, MAX_STANDARD_CASHU_PROOFS_V1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub use store::{
    CashuRecoveryAadV1, CashuRecoveryCipherErrorV1, CashuRecoveryCipherV1, CashuSealedRecoveryV1,
    CashuSwapStateV1, CashuSwapStoreErrorV1, CashuSwapStoreV1, InsertCashuSwapIntentResultV1,
    NewCashuSwapIntentV1, StoredCashuSwapIntentV1, MAX_RECOVERY_CIPHERTEXT_BYTES_V1,
    MAX_RECOVERY_NONCE_BYTES_V1,
};

#[cfg(any(test, feature = "insecure-dev-sqlite-store"))]
pub use sqlite::InsecureDevSqliteCashuSwapStoreV1;

#[cfg(not(target_arch = "wasm32"))]
pub use runtime_admission::{
    ChaCha20Poly1305RecoveryCipherV1, OsRandomCashuOutputMaterialGeneratorV1,
    StandardCashuAdmissionCommitterV1,
};

pub const MAX_CASHU_SWAP_ITEMS_V1: usize = MAX_STANDARD_CASHU_PROOFS_V1;
pub const MAX_CASHU_MINT_JSON_BYTES_V1: usize = 128 * 1024;
pub const MAX_CASHU_RECOVERY_PLAINTEXT_BYTES_V1: usize = 224 * 1024;

const INPUT_SET_DIGEST_DOMAIN_V1: &[u8] = b"BitcoinPIR/cashu-input-set/v1";
const REQUEST_DIGEST_DOMAIN_V1: &[u8] = b"BitcoinPIR/cashu-swap-request/v1";
const OUTPUT_SET_DIGEST_DOMAIN_V1: &[u8] = b"BitcoinPIR/cashu-output-set/v1";
const INTENT_ID_DOMAIN_V1: &[u8] = b"BitcoinPIR/cashu-swap-intent-id/v1";
pub const CASHU_OFFER_BINDING_DIGEST_DOMAIN_V1: &[u8] = b"BitcoinPIR/cashu-offer-binding/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CashuClientErrorV1 {
    InvalidCheckedSpend,
    InvalidManifest,
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
    InvalidCiphertextEnvelope,
    RecoveryCipherUnavailable,
    RecoveryAuthenticationFailed,
    RecoveryPlaintextInvalid,
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
            Self::InvalidCiphertextEnvelope => "Cashu recovery ciphertext envelope is invalid",
            Self::RecoveryCipherUnavailable => "Cashu recovery cipher is unavailable",
            Self::RecoveryAuthenticationFailed => "Cashu recovery ciphertext authentication failed",
            Self::RecoveryPlaintextInvalid => "Cashu recovery plaintext is inconsistent",
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
    pub kind: CashuMintTransportFailureKindV1,
    pub http_status: Option<u16>,
}

/// Fail-closed mint transport boundary. A production implementation must pin
/// the manifest endpoint, append only `route.path()`, reject redirects and
/// cross-origin authentication, enforce HTTPS, set JSON content type, and
/// stop reading at `max_response_bytes`.
pub trait CashuMintTransportV1: Send + Sync {
    fn post_json(
        &self,
        mint_endpoint: &str,
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
    pub fn new(amount: u64, secret_bytes: [u8; 32], blinding_scalar: [u8; 32]) -> Self {
        Self {
            amount,
            secret_bytes,
            blinding_scalar,
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
}

impl<'a> StandardCashuClientV1<'a> {
    pub const fn new(
        store: &'a dyn CashuSwapStoreV1,
        transport: &'a dyn CashuMintTransportV1,
        recovery_cipher: &'a dyn CashuRecoveryCipherV1,
    ) -> Self {
        Self {
            store,
            transport,
            recovery_cipher,
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
        let insert = match self.store.insert_prepared(&new_intent) {
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
        let request_json = encode_json_v1(&request)?;
        let output_json = encode_json_v1(&CashuPostRestoreRequestJsonV1 {
            outputs: request.outputs.clone(),
        })?;
        let input_set_digest = context.input_set_digest;
        let request_digest = domain_digest_v1(REQUEST_DIGEST_DOMAIN_V1, &request_json);
        let output_set_digest = domain_digest_v1(OUTPUT_SET_DIGEST_DOMAIN_V1, &output_json);
        let intent_id = derive_intent_id_v1(&context.checked.mint_id, &input_set_digest);
        let recovery = CashuSwapRecoveryPlaintextV1 {
            version: 1,
            request_json: String::from_utf8(request_json)
                .map_err(|_| CashuClientErrorV1::RecoveryPlaintextInvalid)?,
            outputs,
            response_json: None,
            received_notes: Vec::new(),
        };
        let aad = CashuRecoveryAadV1 {
            intent_id,
            mint_id: context.checked.mint_id,
            input_set_digest,
            request_digest,
            output_set_digest,
            offer_binding_digest: context.offer_binding_digest,
            settlement_value: context.checked.policy_price,
        };
        let sealed_recovery = self.seal_recovery(&aad, &recovery)?;
        let new_intent = NewCashuSwapIntentV1 {
            intent_id,
            mint_id: context.checked.mint_id,
            input_set_digest,
            request_digest,
            output_set_digest,
            offer_binding_digest: context.offer_binding_digest,
            settlement_value: context.checked.policy_price,
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
            &context.checked.mint_endpoint,
            CashuMintRouteV1::Swap,
            recovery.request_json.as_bytes(),
            MAX_CASHU_MINT_JSON_BYTES_V1,
        );
        match response {
            Ok(bytes) => match self.commit_response(record, recovery, context, &bytes) {
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
            },
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
        let body = encode_json_v1(&restore_request)?;
        let response = self.transport.post_json(
            &context.checked.mint_endpoint,
            CashuMintRouteV1::Restore,
            &body,
            MAX_CASHU_MINT_JSON_BYTES_V1,
        );

        if let Ok(bytes) = response {
            match decode_json_v1::<CashuPostRestoreResponseJsonV1>(&bytes) {
                Ok(restored)
                    if restored.outputs == request.outputs
                        && restored.signatures.len() == request.outputs.len() =>
                {
                    let swap_response = CashuPostSwapResponseJsonV1 {
                        signatures: restored.signatures,
                    };
                    let canonical = encode_json_v1(&swap_response)?;
                    return match self.commit_response(record, recovery, context, &canonical) {
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
        let ys = context
            .spend
            .proofs
            .iter()
            .map(|proof| {
                cashu_hash_to_curve_v1(proof.secret.as_bytes())
                    .map(|y| lower_hex(&y))
                    .map_err(|_| CashuClientErrorV1::InvalidCheckedSpend)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let request = CashuPostCheckStateRequestJsonV1 { ys: ys.clone() };
        let body = encode_json_v1(&request)?;
        let response = self.transport.post_json(
            &context.checked.mint_endpoint,
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
        let Ok(response) = decode_json_v1::<CashuPostCheckStateResponseJsonV1>(&bytes) else {
            return Ok(CashuSwapProgressV1::RecoveryPending {
                intent_id: record.intent_id,
                observation: CashuRecoveryObservationV1::MintUnavailable,
            });
        };
        if response.states.len() != ys.len()
            || response
                .states
                .iter()
                .zip(&ys)
                .any(|(state, expected_y)| state.y != *expected_y || state.witness.is_some())
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
        recovery.response_json = Some(
            String::from_utf8(response_json.to_vec())
                .map_err(|_| CashuClientErrorV1::InvalidJson)?,
        );
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
        if self
            .store
            .claim_grant_once(&record.intent_id, context.now_unix)
            .map_err(map_store_error)?
        {
            Ok(CashuSwapProgressV1::Grant(VerifiedStandardCashuGrantV1 {
                intent_id: record.intent_id,
                mint_id: record.mint_id,
                input_set_digest: record.input_set_digest,
                offer_binding_digest: record.offer_binding_digest,
                settlement_value: record.settlement_value,
                received_note_count: note_count,
            }))
        } else {
            let current = self
                .load_for_context(context)?
                .ok_or(CashuClientErrorV1::StateConflict)?;
            match current.state {
                CashuSwapStateV1::GrantIssued => Ok(CashuSwapProgressV1::AlreadyGranted {
                    intent_id: current.intent_id,
                }),
                _ => Err(CashuClientErrorV1::StateConflict),
            }
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
        let plaintext = Zeroizing::new(
            serde_json::to_vec(recovery)
                .map_err(|_| CashuClientErrorV1::RecoveryPlaintextInvalid)?,
        );
        if plaintext.len() > MAX_CASHU_RECOVERY_PLAINTEXT_BYTES_V1 {
            return Err(CashuClientErrorV1::RecoveryPlaintextInvalid);
        }
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
        let recovery: CashuSwapRecoveryPlaintextV1 = serde_json::from_slice(&plaintext)
            .map_err(|_| CashuClientErrorV1::RecoveryPlaintextInvalid)?;
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
        let spend_encoding = spend
            .encode()
            .map_err(|_| CashuClientErrorV1::InvalidCheckedSpend)?;
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

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CashuSwapRecoveryPlaintextV1 {
    version: u8,
    request_json: String,
    outputs: Vec<CashuOutputRecoveryV1>,
    response_json: Option<String>,
    received_notes: Vec<CashuReceivedNoteRecoveryV1>,
}

impl Drop for CashuSwapRecoveryPlaintextV1 {
    fn drop(&mut self) {
        self.request_json.zeroize();
        if let Some(response_json) = &mut self.response_json {
            response_json.zeroize();
        }
        for output in &mut self.outputs {
            output.secret_bytes.zeroize();
            output.blinding_scalar.zeroize();
        }
        for note in &mut self.received_notes {
            note.secret_bytes.zeroize();
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CashuOutputRecoveryV1 {
    amount: u64,
    secret_bytes: [u8; 32],
    blinding_scalar: [u8; 32],
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CashuReceivedNoteRecoveryV1 {
    amount: u64,
    secret_bytes: [u8; 32],
    unblinded_signature: Vec<u8>,
}

fn build_swap_request_v1(
    context: &CheckedContextV1<'_>,
    output_materials: &[CashuOutputMaterialV1],
) -> Result<(CashuPostSwapRequestJsonV1, Vec<CashuOutputRecoveryV1>), CashuClientErrorV1> {
    validate_item_count_v1(output_materials.len())?;
    let active = &context.manifest.active_output_keyset;
    let mut secrets = HashSet::with_capacity(output_materials.len());
    let mut blindings = HashSet::with_capacity(output_materials.len());
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
        let secret_text = lower_hex(&material.secret_bytes);
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
                secret_bytes: material.secret_bytes,
                blinding_scalar: material.blinding_scalar,
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
        || record.input_set_digest != context.input_set_digest
        || record.offer_binding_digest != context.offer_binding_digest
        || record.settlement_value != context.checked.policy_price
    {
        return Err(CashuClientErrorV1::RecoveryPlaintextInvalid);
    }
    let request: CashuPostSwapRequestJsonV1 = decode_json_v1(recovery.request_json.as_bytes())?;
    if encode_json_v1(&request)? != recovery.request_json.as_bytes() {
        return Err(CashuClientErrorV1::RecoveryPlaintextInvalid);
    }
    let proposed: Vec<CashuOutputMaterialV1> = recovery
        .outputs
        .iter()
        .map(|output| {
            CashuOutputMaterialV1::new(output.amount, output.secret_bytes, output.blinding_scalar)
        })
        .collect();
    let (expected, _) = build_swap_request_v1(context, &proposed)?;
    if request != expected {
        return Err(CashuClientErrorV1::RecoveryPlaintextInvalid);
    }
    let request_digest =
        domain_digest_v1(REQUEST_DIGEST_DOMAIN_V1, recovery.request_json.as_bytes());
    let output_json = encode_json_v1(&CashuPostRestoreRequestJsonV1 {
        outputs: request.outputs,
    })?;
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
    let response: CashuPostSwapResponseJsonV1 = decode_json_v1(response_json)?;
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
        let secret_text = lower_hex(&material.secret_bytes);
        let verified = verify_and_unblind_cashu_promise_v1(
            secret_text.as_bytes(),
            &material.blinding_scalar,
            &denomination_key.public_key,
            &blinded_message,
            &blinded_signature,
            &dleq_e,
            &dleq_s,
        )
        .map_err(|_| CashuClientErrorV1::MintDleqVerificationFailed)?;
        notes.push(CashuReceivedNoteRecoveryV1 {
            amount: output.amount,
            secret_bytes: material.secret_bytes,
            unblinded_signature: verified.unblinded_signature().to_vec(),
        });
    }
    Ok(notes)
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

fn domain_digest_v1(domain: &[u8], value: &[u8]) -> [u8; 32] {
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
        CashuSwapStoreErrorV1::Conflict => CashuClientErrorV1::StoreConflict,
        CashuSwapStoreErrorV1::Unavailable
        | CashuSwapStoreErrorV1::Busy
        | CashuSwapStoreErrorV1::Corrupt => CashuClientErrorV1::StoreUnavailable,
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
