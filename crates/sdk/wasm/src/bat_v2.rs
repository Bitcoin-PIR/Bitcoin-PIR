//! Browser-facing, class-bound BAT V2 BOLT11 acquisition.
//!
//! JavaScript supplies canonical issuer class bytes and performs HTTPS. Rust
//! verifies current provider membership once, then recovery contains only the
//! signed class, quote-key stream, claim state, and wallet secrets.

use pir_payment_crypto::{
    blind_cashu_message_v1, sign_bip340_prehash_v1, verify_and_unblind_cashu_promise_v1,
};
use pir_sdk_client::{
    AcceptedBolt11BatV2QuoteV2, AcceptedServicePolicyV1, Bolt11QuoteKeyCheckpointV1,
    PreparedBolt11BatV2ClaimV2, PreparedBolt11BatV2QuoteV2,
};
use pir_service_protocol::{
    BitcoinPirCashuBatIssuanceRequestItemV1, BitcoinPirCashuBatProofV2, Bolt11QuoteStatusV1,
    UnverifiedCashuBatDleqTupleV1,
};
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

const RECOVERY_MAGIC_V2: &[u8; 8] = b"BPIRBAW2";
const RECOVERY_VERSION_V2: u8 = 2;
const MAX_RECOVERY_STATE_LEN_V2: usize = 4 * 1024 * 1024;

struct BatWalletSecretV2 {
    secret: Zeroizing<[u8; 32]>,
    blinding_scalar: Zeroizing<[u8; 32]>,
}

/// Opaque class-bound acquisition handle. It emits issuer HTTP bodies only,
/// never a provider admission frame.
#[wasm_bindgen]
pub struct WasmBolt11BatV2AcquisitionV2 {
    prepared: PreparedBolt11BatV2QuoteV2,
    claim_secret_key: Zeroizing<[u8; 32]>,
    secrets: Vec<BatWalletSecretV2>,
    quote: Option<AcceptedBolt11BatV2QuoteV2>,
    claim: Option<PreparedBolt11BatV2ClaimV2>,
}

#[wasm_bindgen]
impl WasmBolt11BatV2AcquisitionV2 {
    /// Canonical body for `POST /v2/quotes/bolt11`.
    #[wasm_bindgen(js_name = quoteIntentBytes)]
    pub fn quote_intent_bytes(&self) -> Result<Vec<u8>, JsError> {
        self.prepared.intent_bytes().map_err(js_error)
    }

    /// Persist this issuer/network/payee rollback checkpoint before POST.
    #[wasm_bindgen(js_name = quoteKeyCheckpointBytes)]
    pub fn quote_key_checkpoint_bytes(&self) -> Vec<u8> {
        self.prepared.quote_key_checkpoint_bytes()
    }

    /// Opaque secret-bearing V2 recovery state. JavaScript must encrypt it.
    #[wasm_bindgen(js_name = recoveryStateBytes)]
    pub fn recovery_state_bytes(&self) -> Result<Vec<u8>, JsError> {
        encode_recovery(self)
    }

    /// V1 acquisition recovery cannot pass this distinct magic/version gate.
    pub fn restore(recovery_state: &[u8], now_unix: u64) -> Result<Self, JsError> {
        decode_recovery(recovery_state, now_unix)
    }

    #[wasm_bindgen(js_name = acceptInitialQuote)]
    pub fn accept_initial_quote(
        &mut self,
        quote_bytes: &[u8],
        now_unix: u64,
    ) -> Result<(), JsError> {
        if self.quote.is_some() {
            return Err(JsError::new("initial BAT V2 quote already accepted"));
        }
        self.quote = Some(
            self.prepared
                .accept_initial_quote_for_payment(quote_bytes, now_unix)
                .map_err(js_error)?,
        );
        Ok(())
    }

    pub fn invoice(&self) -> Result<String, JsError> {
        Ok(self.require_quote()?.invoice().to_owned())
    }

    #[wasm_bindgen(js_name = quoteIdHex)]
    pub fn quote_id_hex(&self) -> Result<String, JsError> {
        Ok(hex::encode(self.require_quote()?.quote_id()))
    }

    #[wasm_bindgen(js_name = quoteStatus)]
    pub fn quote_status(&self) -> Result<String, JsError> {
        Ok(status_name(self.require_quote()?.status()).to_owned())
    }

    #[wasm_bindgen(js_name = invoiceExpiresAtUnix)]
    pub fn invoice_expires_at_unix(&self) -> Result<String, JsError> {
        Ok(self.require_quote()?.invoice_expires_at().to_string())
    }

    #[wasm_bindgen(js_name = claimDeadlineUnix)]
    pub fn claim_deadline_unix(&self) -> Result<String, JsError> {
        Ok(self.require_quote()?.claim_deadline().to_string())
    }

    #[wasm_bindgen(js_name = buildStatusRequest)]
    pub fn build_status_request(&self, requested_at: u64) -> Result<Vec<u8>, JsError> {
        self.prepared
            .build_status_request(
                self.require_quote()?,
                &self.claim_secret_key,
                requested_at,
                random_nonzero_32()?,
                random_32()?,
            )
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = acceptStatus)]
    pub fn accept_status(&mut self, quote_bytes: &[u8], now_unix: u64) -> Result<(), JsError> {
        self.quote = Some(
            self.require_quote()?
                .accept_latest_after(&self.prepared, quote_bytes, now_unix)
                .map_err(js_error)?,
        );
        Ok(())
    }

    /// Prepare or replay one byte-identical idempotent claim envelope.
    #[wasm_bindgen(js_name = prepareClaim)]
    pub fn prepare_claim(&mut self, now_unix: u64) -> Result<Vec<u8>, JsError> {
        if self.claim.is_none() {
            let items = issuance_items(&self.secrets)?;
            self.claim = Some(
                self.prepared
                    .prepare_claim(
                        self.require_quote()?,
                        items,
                        &self.claim_secret_key,
                        random_32()?,
                        now_unix,
                    )
                    .map_err(js_error)?,
            );
        }
        Ok(self
            .claim
            .as_ref()
            .expect("claim initialized")
            .envelope_bytes()
            .to_vec())
    }

    /// Verify exact response binding and every NUT-12 proof before releasing
    /// a batch of class-bound vault records.
    #[wasm_bindgen(js_name = finishClaim)]
    pub fn finish_claim(
        &self,
        response_bytes: &[u8],
        now_unix: u64,
    ) -> Result<WasmIssuedBatV2ProofsV2, JsError> {
        let claim = self
            .claim
            .as_ref()
            .ok_or_else(|| JsError::new("prepare and persist the BAT V2 claim first"))?;
        let checked = self
            .prepared
            .verify_issuance_response(self.require_quote()?, claim, response_bytes, now_unix)
            .map_err(js_error)?;
        let tuples = checked.into_unverified_dleq();
        if tuples.len() != self.secrets.len() {
            return Err(JsError::new(
                "BAT V2 issuance response count differs from wallet state",
            ));
        }
        let (proofs, global_spend_keys) =
            finalize_issued_proofs(self.prepared.class(), &self.secrets, tuples)
                .map_err(|error| JsError::new(&error))?;
        Ok(WasmIssuedBatV2ProofsV2 {
            proofs,
            global_spend_keys,
            issuer_id: self.prepared.class().issuer_id,
            class_id: self.prepared.class().class_id,
            class_digest: self.prepared.class().class_digest().map_err(js_error)?,
            class_key_epoch: self.prepared.class().key_epoch,
            bat_key_id: self.prepared.class().bat_key_id(),
        })
    }

    fn require_quote(&self) -> Result<&AcceptedBolt11BatV2QuoteV2, JsError> {
        self.quote
            .as_ref()
            .ok_or_else(|| JsError::new("no verified BAT V2 quote is available"))
    }
}

fn finalize_issued_proofs(
    class: &pir_service_protocol::BatAcceptanceClassV2,
    secrets: &[BatWalletSecretV2],
    tuples: Vec<UnverifiedCashuBatDleqTupleV1>,
) -> Result<(Vec<Vec<u8>>, Vec<[u8; 32]>), String> {
    if secrets.len() != tuples.len() {
        return Err("BAT V2 issuance response count differs from wallet state".into());
    }
    let mut proofs = Vec::with_capacity(tuples.len());
    let mut global_spend_keys = Vec::with_capacity(tuples.len());
    for (secret, tuple) in secrets.iter().zip(tuples) {
        let verified = verify_and_unblind_cashu_promise_v1(
            &secret.secret[..],
            &secret.blinding_scalar,
            &tuple.issuer_public_key,
            &tuple.blinded_message,
            &tuple.blinded_signature,
            &tuple.dleq_e,
            &tuple.dleq_s,
        )
        .map_err(|error| error.to_string())?;
        let proof = BitcoinPirCashuBatProofV2::from_class(
            class,
            *secret.secret,
            *verified.unblinded_signature(),
        )
        .map_err(|error| error.to_string())?;
        global_spend_keys.push(
            proof
                .spend_key(&class.bat_verification_key)
                .map_err(|error| error.to_string())?,
        );
        proofs.push(proof.encode().map_err(|error| error.to_string())?.to_vec());
    }
    Ok((proofs, global_spend_keys))
}

/// Issued proofs are withheld as a batch until Web atomically stores all
/// records and removes the acquisition recovery entry.
#[wasm_bindgen]
pub struct WasmIssuedBatV2ProofsV2 {
    proofs: Vec<Vec<u8>>,
    global_spend_keys: Vec<[u8; 32]>,
    issuer_id: [u8; 32],
    class_id: [u8; 32],
    class_digest: [u8; 32],
    class_key_epoch: u64,
    bat_key_id: [u8; 32],
}

impl Drop for WasmIssuedBatV2ProofsV2 {
    fn drop(&mut self) {
        self.proofs.zeroize();
        self.global_spend_keys.zeroize();
    }
}

#[wasm_bindgen]
impl WasmIssuedBatV2ProofsV2 {
    pub fn count(&self) -> u32 {
        self.proofs.len() as u32
    }

    pub fn proof(&self, index: u32) -> Result<Vec<u8>, JsError> {
        self.proofs
            .get(index as usize)
            .cloned()
            .ok_or_else(|| JsError::new("issued BAT V2 proof index is out of range"))
    }

    #[wasm_bindgen(js_name = globalSpendKeyHex)]
    pub fn global_spend_key_hex(&self, index: u32) -> Result<String, JsError> {
        self.global_spend_keys
            .get(index as usize)
            .map(hex::encode)
            .ok_or_else(|| JsError::new("issued BAT V2 spend-key index is out of range"))
    }

    #[wasm_bindgen(js_name = classBindingJson)]
    pub fn class_binding_json(&self) -> JsValue {
        crate::to_js_object(&serde_json::json!({
            "issuerIdHex": hex::encode(self.issuer_id),
            "classIdHex": hex::encode(self.class_id),
            "classDigestHex": hex::encode(self.class_digest),
            "classKeyEpoch": self.class_key_epoch.to_string(),
            "batKeyIdHex": hex::encode(self.bat_key_id),
        }))
    }
}

/// Called only by the verified policy handle in `service.rs`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn begin_bat_v2_acquisition_v2(
    accepted: &AcceptedServicePolicyV1,
    scope_id: &[u8],
    offer_id: u32,
    class_bytes: &[u8],
    quote_delegation_bytes: &[u8],
    quote_key_checkpoint_bytes: &[u8],
    now_unix: u64,
) -> Result<WasmBolt11BatV2AcquisitionV2, JsError> {
    let scope_id: [u8; 32] = fixed(scope_id, "scope_id")?;
    let checkpoint =
        Bolt11QuoteKeyCheckpointV1::decode(quote_key_checkpoint_bytes).map_err(js_error)?;
    let verified = accepted
        .verify_current_bat_v2_offer_v2(&scope_id, offer_id, class_bytes, now_unix)
        .map_err(js_error)?;
    let (claim_secret_key, claim_pubkey_xonly) = fresh_claim_key()?;
    let prepared = PreparedBolt11BatV2QuoteV2::from_verified_current_offer(
        &verified,
        quote_delegation_bytes,
        &checkpoint,
        now_unix,
        claim_pubkey_xonly,
        random_nonzero_32()?,
    )
    .map_err(js_error)?;
    let count = usize::try_from(prepared.intent().credential_count)
        .map_err(|_| JsError::new("BAT V2 credential count does not fit this browser"))?;
    let mut secrets = Vec::with_capacity(count);
    for _ in 0..count {
        secrets.push(fresh_bat_secret()?);
    }
    Ok(WasmBolt11BatV2AcquisitionV2 {
        prepared,
        claim_secret_key: Zeroizing::new(claim_secret_key),
        secrets,
        quote: None,
        claim: None,
    })
}

fn issuance_items(
    secrets: &[BatWalletSecretV2],
) -> Result<Vec<BitcoinPirCashuBatIssuanceRequestItemV1>, JsError> {
    secrets
        .iter()
        .map(|secret| {
            Ok(BitcoinPirCashuBatIssuanceRequestItemV1 {
                blinded_message: blind_cashu_message_v1(
                    &secret.secret[..],
                    &secret.blinding_scalar,
                )
                .map_err(js_error)?,
            })
        })
        .collect()
}

fn encode_recovery(value: &WasmBolt11BatV2AcquisitionV2) -> Result<Vec<u8>, JsError> {
    let mut out = Vec::new();
    out.extend_from_slice(RECOVERY_MAGIC_V2);
    out.push(RECOVERY_VERSION_V2);
    put_bytes(&mut out, &value.prepared.intent_bytes().map_err(js_error)?)?;
    put_bytes(&mut out, &value.prepared.class_bytes().map_err(js_error)?)?;
    put_bytes(
        &mut out,
        &value.prepared.delegation_bytes().map_err(js_error)?,
    )?;
    put_bytes(&mut out, &value.prepared.quote_key_checkpoint_bytes())?;
    out.extend_from_slice(&value.claim_secret_key[..]);
    put_bytes(
        &mut out,
        &value
            .quote
            .as_ref()
            .map(AcceptedBolt11BatV2QuoteV2::bytes)
            .transpose()
            .map_err(js_error)?
            .unwrap_or_default(),
    )?;
    put_bytes(
        &mut out,
        value
            .claim
            .as_ref()
            .map(PreparedBolt11BatV2ClaimV2::envelope_bytes)
            .unwrap_or_default(),
    )?;
    put_count(&mut out, value.secrets.len())?;
    for secret in &value.secrets {
        out.extend_from_slice(&secret.secret[..]);
        out.extend_from_slice(&secret.blinding_scalar[..]);
    }
    if out.len() > MAX_RECOVERY_STATE_LEN_V2 {
        return Err(JsError::new("BAT V2 recovery state exceeds its bound"));
    }
    Ok(out)
}

fn decode_recovery(bytes: &[u8], now_unix: u64) -> Result<WasmBolt11BatV2AcquisitionV2, JsError> {
    if bytes.len() < RECOVERY_MAGIC_V2.len() + 1 || bytes.len() > MAX_RECOVERY_STATE_LEN_V2 {
        return Err(JsError::new("invalid BAT V2 recovery state length"));
    }
    let mut decoder = RecoveryDecoderV2::new(bytes);
    if !has_recovery_domain_v2(bytes) {
        return Err(JsError::new("unsupported BAT V2 recovery domain/version"));
    }
    decoder.take(RECOVERY_MAGIC_V2.len())?;
    decoder.u8()?;
    let intent = decoder.bytes()?;
    let class = decoder.bytes()?;
    let delegation = decoder.bytes()?;
    let checkpoint = decoder.bytes()?;
    let claim_secret_key = decoder.fixed::<32>()?;
    let quote_bytes = decoder.bytes()?;
    let claim_bytes = decoder.bytes()?;
    let count = decoder.u32()? as usize;
    let mut secrets = Vec::with_capacity(count);
    for _ in 0..count {
        secrets.push(BatWalletSecretV2 {
            secret: Zeroizing::new(decoder.fixed::<32>()?),
            blinding_scalar: Zeroizing::new(decoder.fixed::<32>()?),
        });
    }
    decoder.finish()?;
    let prepared =
        PreparedBolt11BatV2QuoteV2::restore(&intent, &class, &delegation, &checkpoint, now_unix)
            .map_err(js_error)?;
    let (public, _) =
        sign_bip340_prehash_v1(&claim_secret_key, &[7; 32], &[0; 32]).map_err(js_error)?;
    if public != prepared.intent().claim_pubkey_xonly
        || count
            != usize::try_from(prepared.intent().credential_count)
                .map_err(|_| JsError::new("BAT V2 credential count does not fit this browser"))?
    {
        return Err(JsError::new(
            "BAT V2 recovery secrets do not match the class-only intent",
        ));
    }
    let quote = if quote_bytes.is_empty() {
        None
    } else {
        Some(
            prepared
                .restore_quote_snapshot(&quote_bytes, now_unix)
                .map_err(js_error)?,
        )
    };
    let claim = if claim_bytes.is_empty() {
        None
    } else {
        Some(prepared.restore_claim(&claim_bytes).map_err(js_error)?)
    };
    if let Some(claim) = &claim {
        if claim.credential_request().items != issuance_items(&secrets)? {
            return Err(JsError::new(
                "restored BAT V2 claim differs from wallet secrets",
            ));
        }
    }
    Ok(WasmBolt11BatV2AcquisitionV2 {
        prepared,
        claim_secret_key: Zeroizing::new(claim_secret_key),
        secrets,
        quote,
        claim,
    })
}

fn has_recovery_domain_v2(bytes: &[u8]) -> bool {
    bytes.get(..RECOVERY_MAGIC_V2.len()) == Some(RECOVERY_MAGIC_V2.as_slice())
        && bytes.get(RECOVERY_MAGIC_V2.len()) == Some(&RECOVERY_VERSION_V2)
}

fn fresh_claim_key() -> Result<([u8; 32], [u8; 32]), JsError> {
    for _ in 0..32 {
        let secret = random_nonzero_32()?;
        if let Ok((public, _)) = sign_bip340_prehash_v1(&secret, &[7; 32], &[0; 32]) {
            return Ok((secret, public));
        }
    }
    Err(JsError::new(
        "could not generate a canonical BIP340 claim key",
    ))
}

fn fresh_bat_secret() -> Result<BatWalletSecretV2, JsError> {
    for _ in 0..64 {
        let secret = random_nonzero_32()?;
        let blinding_scalar = random_nonzero_32()?;
        if blind_cashu_message_v1(&secret, &blinding_scalar).is_ok() {
            return Ok(BatWalletSecretV2 {
                secret: Zeroizing::new(secret),
                blinding_scalar: Zeroizing::new(blinding_scalar),
            });
        }
    }
    Err(JsError::new(
        "could not generate a canonical BAT V2 blinding scalar",
    ))
}

fn status_name(value: Bolt11QuoteStatusV1) -> &'static str {
    match value {
        Bolt11QuoteStatusV1::InvoiceOpen => "invoice-open",
        Bolt11QuoteStatusV1::PaymentSettled => "payment-settled",
        Bolt11QuoteStatusV1::CredentialClaimed => "credential-claimed",
        Bolt11QuoteStatusV1::InvoiceExpiredPendingReconcile => "invoice-expired-pending-reconcile",
        Bolt11QuoteStatusV1::LateSettledReconcile => "late-settled-reconcile",
    }
}

fn random_32() -> Result<[u8; 32], JsError> {
    let mut value = [0; 32];
    getrandom::getrandom(&mut value).map_err(|_| JsError::new("Web Crypto RNG unavailable"))?;
    Ok(value)
}

fn random_nonzero_32() -> Result<[u8; 32], JsError> {
    for _ in 0..16 {
        let value = random_32()?;
        if value.iter().any(|byte| *byte != 0) {
            return Ok(value);
        }
    }
    Err(JsError::new("Web Crypto RNG repeatedly returned zero"))
}

fn fixed<const N: usize>(bytes: &[u8], field: &str) -> Result<[u8; N], JsError> {
    bytes
        .try_into()
        .map_err(|_| JsError::new(&format!("{field} must be exactly {N} bytes")))
}

fn put_count(out: &mut Vec<u8>, count: usize) -> Result<(), JsError> {
    let count = u32::try_from(count).map_err(|_| JsError::new("BAT V2 item count exceeds u32"))?;
    out.extend_from_slice(&count.to_le_bytes());
    Ok(())
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), JsError> {
    let len = u32::try_from(bytes.len()).map_err(|_| JsError::new("BAT V2 field exceeds u32"))?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

struct RecoveryDecoderV2<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> RecoveryDecoderV2<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], JsError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| JsError::new("BAT V2 recovery offset overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| JsError::new("truncated BAT V2 recovery state"))?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, JsError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, JsError> {
        Ok(u32::from_le_bytes(fixed(self.take(4)?, "u32")?))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], JsError> {
        fixed(self.take(N)?, "fixed BAT V2 recovery field")
    }

    fn bytes(&mut self) -> Result<Vec<u8>, JsError> {
        let len = self.u32()? as usize;
        if len > MAX_RECOVERY_STATE_LEN_V2 {
            return Err(JsError::new("BAT V2 recovery field exceeds its bound"));
        }
        Ok(self.take(len)?.to_vec())
    }

    fn finish(self) -> Result<(), JsError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(JsError::new("trailing BAT V2 recovery bytes"))
        }
    }
}

fn js_error(error: impl core::fmt::Display) -> JsError {
    JsError::new(&error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use pir_payment_crypto::K256CashuMintKeyringV1;
    use pir_service_protocol::{
        AuthPaddingClassV1, BackendId, BatAcceptanceClassV2, BatAcceptanceMemberV2,
        BatAcceptanceTermsV2, DatasetBindingV1, DeploymentStatus, EntitlementLimitsV1,
        PrivacyLeakageV1, WorkloadId,
    };

    fn class(bat_verification_key: [u8; 33]) -> BatAcceptanceClassV2 {
        BatAcceptanceClassV2::sign(
            [0x41; 32],
            1,
            100,
            1_000,
            bat_verification_key,
            BatAcceptanceTermsV2 {
                auth_padding_class: AuthPaddingClassV1::Class16KiB,
                backend: BackendId::DpfPirV1,
                workload: WorkloadId::DpfEvaluateJobV1,
                protocol_version: 1,
                dataset: DatasetBindingV1::Class { class_id: 1 },
                operation_profile: 1,
                entitlement_profile: 2,
                limits: EntitlementLimitsV1 {
                    max_logical_inputs: 1,
                    max_frames: 10,
                    max_request_bytes: 10_000,
                    max_response_bytes: 20_000,
                    max_wall_time_ms: 1_000,
                    max_concurrent_sockets: 1,
                    max_hint_groups: 0,
                    max_work_units: 100,
                },
                priority_class: 1,
                deployment_status: DeploymentStatus::Stable,
                price_msat: 1_000,
                issuer_endpoint: "https://issuer.invalid".into(),
                invoice_expiry_seconds: 10,
                claim_window_seconds: 10,
                minimum_credential_validity_seconds: 10,
                retired_policy_grace_seconds: 30,
                credential_count: 2,
                credential_presentation_limit: 1,
                privacy_leakage: PrivacyLeakageV1::from_bits(
                    PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING
                        | PrivacyLeakageV1::ISSUER_REDEMPTION_TIMING
                        | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER,
                )
                .unwrap(),
            },
            vec![BatAcceptanceMemberV2 {
                provider_id: [1; 32],
                policy_digest: [2; 32],
                scope_id: [3; 32],
                offer_id: 4,
            }],
            &SigningKey::from_bytes(&[5; 32]),
        )
        .unwrap()
    }

    #[test]
    fn v2_recovery_domain_rejects_v1_prefix() {
        assert!(!has_recovery_domain_v2(&[1; 128]));
        let mut v2 = RECOVERY_MAGIC_V2.to_vec();
        v2.push(RECOVERY_VERSION_V2);
        assert!(has_recovery_domain_v2(&v2));
    }

    #[test]
    fn generated_wallet_secret_reconstructs_blinded_message() {
        let secret = fresh_bat_secret().expect("secret");
        let first =
            blind_cashu_message_v1(&secret.secret[..], &secret.blinding_scalar).expect("blind");
        let second =
            blind_cashu_message_v1(&secret.secret[..], &secret.blinding_scalar).expect("blind");
        assert_eq!(first, second);
    }

    #[test]
    fn finish_proofs_verifies_dleq_and_derives_distinct_global_spend_keys() {
        let keyring = K256CashuMintKeyringV1::from_secret_keys([[7; 32]]).unwrap();
        let public_key = keyring.denomination_public_keys()[0];
        let class = class(public_key);
        let secrets = vec![
            BatWalletSecretV2 {
                secret: Zeroizing::new([11; 32]),
                blinding_scalar: Zeroizing::new([12; 32]),
            },
            BatWalletSecretV2 {
                secret: Zeroizing::new([13; 32]),
                blinding_scalar: Zeroizing::new([14; 32]),
            },
        ];
        let tuples = secrets
            .iter()
            .enumerate()
            .map(|(index, secret)| {
                let blinded_message =
                    blind_cashu_message_v1(&secret.secret[..], &secret.blinding_scalar).unwrap();
                let signed = keyring
                    .blind_sign_with_dleq_v1(&public_key, &blinded_message, &[20 + index as u8; 32])
                    .unwrap();
                UnverifiedCashuBatDleqTupleV1 {
                    issuer_public_key: public_key,
                    blinded_message,
                    blinded_signature: *signed.blinded_signature(),
                    dleq_e: *signed.dleq_e(),
                    dleq_s: *signed.dleq_s(),
                }
            })
            .collect::<Vec<_>>();
        let (proofs, spend_keys) =
            finalize_issued_proofs(&class, &secrets, tuples.clone()).unwrap();
        assert_eq!(proofs.len(), 2);
        assert_ne!(spend_keys[0], spend_keys[1]);
        for proof in proofs {
            BitcoinPirCashuBatProofV2::decode(&proof)
                .unwrap()
                .verify_class_binding(&class)
                .unwrap();
        }

        let mut tampered = tuples;
        tampered[0].dleq_s[0] ^= 1;
        assert!(finalize_issued_proofs(&class, &secrets, tampered).is_err());
    }
}
