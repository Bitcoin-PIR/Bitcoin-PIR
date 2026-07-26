//! Browser-facing, restart-safe BOLT11 acquisition state.
//!
//! JavaScript performs HTTPS only. All BOLT11 parsing, issuer/delegation
//! verification, BIP340 signing, Cashu DLEQ checking/unblinding, and ARC
//! finalization remain in Rust/WASM. Serialized state is opaque secret-bearing
//! material and must be immediately encrypted by the browser vault.

use pir_arc_adapter::{
    create_arc_credential_request, restore_arc_credential_request, ArcIssuanceCanonicalizerV1,
};
use pir_payment_crypto::{
    blind_cashu_message_v1, sign_bip340_prehash_v1, verify_and_unblind_cashu_promise_v1,
};
use pir_sdk_client::{
    AcceptedBolt11QuoteV1, AcceptedServicePolicyV1, Bolt11QuoteKeyCheckpointV1,
    PreparedBolt11ClaimV1, PreparedBolt11QuoteV1,
};
use pir_service_protocol::{
    AuthScheme, BitcoinPirCashuBatIssuanceRequestItemV1, BitcoinPirCashuBatProofV1,
    Bolt11QuoteStatusV1, CheckedCredentialIssuanceResponseV1, CredentialIssuanceRequestItemsV1,
    CredentialKeyBindingExpectationV1, LightningNetworkV1,
};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

const RECOVERY_VERSION_V1: u8 = 1;
const MAX_RECOVERY_STATE_LEN_V1: usize = 4 * 1024 * 1024;
const MAX_ARC_PENDING_STATE_LEN_V1: usize = 1024;
const ARC_VAULT_STATE_MAGIC_V1: &[u8; 8] = b"BPIRARC1";

struct BatWalletSecretV1 {
    secret: Zeroizing<[u8; 32]>,
    blinding_scalar: Zeroizing<[u8; 32]>,
}

enum MethodSecretsV1 {
    DirectReceipt,
    CashuBat(Vec<BatWalletSecretV1>),
    ArcExperimental(Vec<Zeroizing<Vec<u8>>>),
}

/// Opaque acquisition handle. It never emits a PIR authorization frame.
#[wasm_bindgen]
pub struct WasmBolt11AcquisitionV1 {
    prepared: PreparedBolt11QuoteV1,
    claim_secret_key: Zeroizing<[u8; 32]>,
    method: MethodSecretsV1,
    quote: Option<AcceptedBolt11QuoteV1>,
    claim: Option<PreparedBolt11ClaimV1>,
}

#[wasm_bindgen]
impl WasmBolt11AcquisitionV1 {
    /// Canonical body for `POST /v1/quotes/bolt11`.
    pub fn quote_intent_bytes(&self) -> Result<Vec<u8>, JsError> {
        self.prepared.intent_bytes().map_err(js_error)
    }

    /// Advanced issuer/network/payee rollback state. Persist this before
    /// posting the quote intent and before displaying or paying an invoice.
    pub fn quote_key_checkpoint_bytes(&self) -> Vec<u8> {
        self.prepared.quote_key_checkpoint_bytes()
    }

    /// Opaque secret-bearing recovery record. JavaScript must encrypt it with
    /// the non-extractable vault key before allowing the workflow to proceed.
    pub fn recovery_state_bytes(&self) -> Result<Vec<u8>, JsError> {
        encode_recovery(self)
    }

    /// Restore only state previously authenticated by the browser vault.
    pub fn restore(recovery_state: &[u8], now_unix: u64) -> Result<Self, JsError> {
        decode_recovery(recovery_state, now_unix)
    }

    /// Verify the issuer's initial quote plus the full BOLT11 signature and
    /// exact amount/network/payee fields. Callers must persist the resulting
    /// recovery state before exposing `invoice()` to wallet UI.
    pub fn accept_initial_quote(
        &mut self,
        quote_bytes: &[u8],
        now_unix: u64,
    ) -> Result<(), JsError> {
        if self.quote.is_some() {
            return Err(JsError::new("initial BOLT11 quote already accepted"));
        }
        self.quote = Some(
            self.prepared
                .accept_initial_quote_for_payment(quote_bytes, now_unix)
                .map_err(js_error)?,
        );
        Ok(())
    }

    /// Invoice text from an already verified quote. Persistence ordering is
    /// enforced by the Web controller, not by this low-level getter.
    pub fn invoice(&self) -> Result<String, JsError> {
        Ok(self.require_quote()?.invoice().to_owned())
    }

    pub fn quote_id_hex(&self) -> Result<String, JsError> {
        Ok(hex::encode(self.require_quote()?.quote_id()))
    }

    pub fn quote_status(&self) -> Result<String, JsError> {
        Ok(status_name(self.require_quote()?.status()).to_owned())
    }

    pub fn invoice_expires_at_unix(&self) -> Result<String, JsError> {
        Ok(self.require_quote()?.invoice_expires_at().to_string())
    }

    pub fn claim_deadline_unix(&self) -> Result<String, JsError> {
        Ok(self.require_quote()?.claim_deadline().to_string())
    }

    /// Build a fresh authenticated status request. A lost response does not
    /// mutate capability state; a later poll uses a fresh nonce.
    pub fn build_status_request(&self, requested_at: u64) -> Result<Vec<u8>, JsError> {
        let nonce = random_nonzero_32()?;
        let auxiliary_randomness = random_32()?;
        self.prepared
            .build_status_request(
                self.require_quote()?,
                &self.claim_secret_key,
                requested_at,
                nonce,
                auxiliary_randomness,
            )
            .map_err(js_error)
    }

    /// Verify and monotonically advance a signed status snapshot. The Web
    /// controller persists recovery state before exposing the new status.
    pub fn accept_status(&mut self, quote_bytes: &[u8], now_unix: u64) -> Result<(), JsError> {
        let previous = self.require_quote()?;
        self.quote = Some(
            previous
                .accept_latest_after(&self.prepared, quote_bytes, now_unix)
                .map_err(js_error)?,
        );
        Ok(())
    }

    /// Prepare (or replay) the exact idempotent claim envelope. The first call
    /// creates method-specific blinded requests and signs the claim; all later
    /// calls return byte-identical content, including after page restoration.
    pub fn prepare_claim(&mut self, now_unix: u64) -> Result<Vec<u8>, JsError> {
        if self.claim.is_none() {
            let items = self.issuance_request_items(now_unix)?;
            let auxiliary_randomness = random_32()?;
            self.claim = Some(
                self.prepared
                    .prepare_claim(
                        self.require_quote()?,
                        items,
                        &self.claim_secret_key,
                        auxiliary_randomness,
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

    /// Verify the exact issuance response and derive provider-local
    /// capabilities. No invoice, payment hash, quote ID, or claim key appears
    /// in any returned capability.
    pub fn finish_claim(
        &self,
        response_bytes: &[u8],
        now_unix: u64,
    ) -> Result<WasmIssuedCapabilitiesV1, JsError> {
        let quote = self.require_quote()?;
        let claim = self
            .claim
            .as_ref()
            .ok_or_else(|| JsError::new("prepare and persist the exact claim before finishing"))?;
        let arc_codec = ArcIssuanceCanonicalizerV1;
        let checked = self
            .prepared
            .verify_issuance_response(
                quote,
                claim,
                response_bytes,
                matches!(self.method, MethodSecretsV1::ArcExperimental(_))
                    .then_some(&arc_codec as &dyn pir_service_protocol::ArcIssuanceCanonicalizerV1),
                now_unix,
            )
            .map_err(js_error)?;
        let (scheme, capabilities) = match (&self.method, checked) {
            (
                MethodSecretsV1::DirectReceipt,
                CheckedCredentialIssuanceResponseV1::DirectPaidReceipts(receipts),
            ) => {
                let mut capabilities = Vec::with_capacity(receipts.len());
                for receipt in receipts {
                    capabilities.push(receipt.encode().map_err(js_error)?);
                }
                ("bolt11-direct-receipt", capabilities)
            }
            (
                MethodSecretsV1::CashuBat(secrets),
                CheckedCredentialIssuanceResponseV1::BitcoinPirCashuBat { unverified_dleq },
            ) if secrets.len() == unverified_dleq.len() => {
                let mut capabilities = Vec::with_capacity(secrets.len());
                for (secret, tuple) in secrets.iter().zip(unverified_dleq) {
                    let verified = verify_and_unblind_cashu_promise_v1(
                        &secret.secret[..],
                        &secret.blinding_scalar,
                        &tuple.issuer_public_key,
                        &tuple.blinded_message,
                        &tuple.blinded_signature,
                        &tuple.dleq_e,
                        &tuple.dleq_s,
                    )
                    .map_err(js_error)?;
                    let proof = BitcoinPirCashuBatProofV1 {
                        secret_raw: *secret.secret,
                        c: *verified.unblinded_signature(),
                    };
                    capabilities.push(proof.encode().map_err(js_error)?.to_vec());
                }
                ("cashu-bat", capabilities)
            }
            (
                MethodSecretsV1::ArcExperimental(pending),
                CheckedCredentialIssuanceResponseV1::ArcExperimental { pending_finalize },
            ) if pending.len() == pending_finalize.len() => {
                let expected = binding_expectation(&self.prepared);
                let event_time = quote.invoice_created_at();
                let mut capabilities = Vec::with_capacity(pending.len());
                for (encoded, pair) in pending.iter().zip(pending_finalize) {
                    let (_request, pending) = restore_arc_credential_request(
                        self.prepared.credential_binding(),
                        &expected,
                        event_time,
                        encoded,
                    )
                    .map_err(js_error)?;
                    let credential = pending
                        .finalize(
                            self.prepared.credential_binding(),
                            &expected,
                            event_time,
                            &pair,
                        )
                        .map_err(js_error)?;
                    let state = credential
                        .encode_for_encrypted_storage()
                        .map_err(js_error)?;
                    let mut wrapped =
                        Vec::with_capacity(ARC_VAULT_STATE_MAGIC_V1.len() + state.len());
                    wrapped.extend_from_slice(ARC_VAULT_STATE_MAGIC_V1);
                    wrapped.extend_from_slice(&state);
                    capabilities.push(wrapped);
                }
                ("arc-experimental", capabilities)
            }
            _ => {
                return Err(JsError::new(
                    "issuance response scheme/count differs from prepared acquisition",
                ))
            }
        };
        Ok(WasmIssuedCapabilitiesV1 {
            scheme: scheme.to_owned(),
            capabilities,
        })
    }

    fn require_quote(&self) -> Result<&AcceptedBolt11QuoteV1, JsError> {
        self.quote
            .as_ref()
            .ok_or_else(|| JsError::new("no verified BOLT11 quote is available"))
    }

    fn issuance_request_items(
        &self,
        now_unix: u64,
    ) -> Result<CredentialIssuanceRequestItemsV1, JsError> {
        match &self.method {
            MethodSecretsV1::DirectReceipt => {
                Ok(CredentialIssuanceRequestItemsV1::DirectPaidReceipt)
            }
            MethodSecretsV1::CashuBat(secrets) => {
                let mut items = Vec::with_capacity(secrets.len());
                for secret in secrets {
                    items.push(BitcoinPirCashuBatIssuanceRequestItemV1 {
                        blinded_message: blind_cashu_message_v1(
                            &secret.secret[..],
                            &secret.blinding_scalar,
                        )
                        .map_err(js_error)?,
                    });
                }
                Ok(CredentialIssuanceRequestItemsV1::BitcoinPirCashuBat(items))
            }
            MethodSecretsV1::ArcExperimental(pending) => {
                let expected = binding_expectation(&self.prepared);
                let mut items = Vec::with_capacity(pending.len());
                for encoded in pending {
                    let (request, _pending) = restore_arc_credential_request(
                        self.prepared.credential_binding(),
                        &expected,
                        now_unix,
                        encoded,
                    )
                    .map_err(js_error)?;
                    items.push(request);
                }
                Ok(CredentialIssuanceRequestItemsV1::ArcExperimental(items))
            }
        }
    }
}

/// Capabilities are withheld as a batch until the Web vault atomically stores
/// every item and removes the invoice recovery record.
#[wasm_bindgen]
pub struct WasmIssuedCapabilitiesV1 {
    scheme: String,
    capabilities: Vec<Vec<u8>>,
}

#[wasm_bindgen]
impl WasmIssuedCapabilitiesV1 {
    #[wasm_bindgen(getter)]
    pub fn scheme(&self) -> String {
        self.scheme.clone()
    }

    pub fn count(&self) -> u32 {
        self.capabilities.len() as u32
    }

    pub fn capability(&self, index: u32) -> Result<Vec<u8>, JsError> {
        self.capabilities
            .get(index as usize)
            .cloned()
            .ok_or_else(|| JsError::new("issued capability index is out of range"))
    }
}

/// Create a first-use quote-key checkpoint from trusted issuer configuration.
#[wasm_bindgen]
pub fn initial_bolt11_quote_key_checkpoint_v1(
    issuer_id: &[u8],
    network: &str,
    expected_payee_pubkey: &[u8],
) -> Result<Vec<u8>, JsError> {
    let issuer_id: [u8; 32] = fixed(issuer_id, "issuer_id")?;
    let expected_payee_pubkey: [u8; 33] = fixed(expected_payee_pubkey, "payee pubkey")?;
    Bolt11QuoteKeyCheckpointV1::initial(issuer_id, parse_network(network)?, expected_payee_pubkey)
        .map(|checkpoint| checkpoint.encode())
        .map_err(js_error)
}

/// Called by the verified policy handle; kept crate-visible so a raw policy
/// object cannot be supplied from JavaScript.
#[allow(clippy::too_many_arguments)]
pub(crate) fn begin_bolt11_acquisition_v1(
    accepted: &AcceptedServicePolicyV1,
    scope_id: &[u8],
    offer_id: u32,
    quote_delegation_bytes: &[u8],
    quote_key_checkpoint_bytes: &[u8],
    now_unix: u64,
) -> Result<WasmBolt11AcquisitionV1, JsError> {
    let scope_id: [u8; 32] = fixed(scope_id, "scope_id")?;
    let checkpoint =
        Bolt11QuoteKeyCheckpointV1::decode(quote_key_checkpoint_bytes).map_err(js_error)?;
    let (claim_secret_key, claim_pubkey_xonly) = fresh_claim_key()?;
    let idempotency_key = random_nonzero_32()?;
    let prepared = accepted
        .dangerous_unpaired_prepare_bolt11_quote_v1(
            &scope_id,
            offer_id,
            quote_delegation_bytes,
            &checkpoint,
            now_unix,
            claim_pubkey_xonly,
            idempotency_key,
        )
        .map_err(js_error)?;
    let count = usize::try_from(prepared.intent().credential_count)
        .map_err(|_| JsError::new("credential count does not fit this browser"))?;
    let method = match prepared.intent().authorization {
        AuthScheme::Bolt11DirectReceiptV1 => MethodSecretsV1::DirectReceipt,
        AuthScheme::BitcoinPirCashuBatV1 => {
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                values.push(fresh_bat_secret()?);
            }
            MethodSecretsV1::CashuBat(values)
        }
        AuthScheme::ArcV1Experimental => {
            let expected = binding_expectation(&prepared);
            let mut values = Vec::with_capacity(count);
            let mut rng = rand_core::OsRng;
            for _ in 0..count {
                let (_request, pending) = create_arc_credential_request(
                    prepared.credential_binding(),
                    &expected,
                    now_unix,
                    &mut rng,
                )
                .map_err(js_error)?;
                values.push(pending.encode_for_encrypted_storage().map_err(js_error)?);
            }
            MethodSecretsV1::ArcExperimental(values)
        }
        _ => {
            return Err(JsError::new(
                "selected offer is not a BOLT11 issuance scheme",
            ))
        }
    };
    Ok(WasmBolt11AcquisitionV1 {
        prepared,
        claim_secret_key: Zeroizing::new(claim_secret_key),
        method,
        quote: None,
        claim: None,
    })
}

fn binding_expectation(prepared: &PreparedBolt11QuoteV1) -> CredentialKeyBindingExpectationV1<'_> {
    let intent = prepared.intent();
    let binding = prepared.credential_binding();
    CredentialKeyBindingExpectationV1 {
        issuer_id: &intent.issuer_id,
        provider_id: &intent.provider_id,
        scope_id: &intent.scope_id,
        offer_id: intent.offer_id,
        scheme: intent.authorization,
        minimum_keyset_epoch: binding.claims.keyset_epoch,
        entitlement_profile: intent.entitlement_profile,
        presentation_limit: intent.credential_presentation_limit,
        credential_key_id: &intent.credential_key_id,
    }
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

fn fresh_bat_secret() -> Result<BatWalletSecretV1, JsError> {
    for _ in 0..64 {
        let secret = random_nonzero_32()?;
        let scalar = random_nonzero_32()?;
        if blind_cashu_message_v1(&secret, &scalar).is_ok() {
            return Ok(BatWalletSecretV1 {
                secret: Zeroizing::new(secret),
                blinding_scalar: Zeroizing::new(scalar),
            });
        }
    }
    Err(JsError::new(
        "could not generate a canonical Cashu BAT blinding scalar",
    ))
}

fn encode_recovery(value: &WasmBolt11AcquisitionV1) -> Result<Vec<u8>, JsError> {
    let mut out = Vec::new();
    out.push(RECOVERY_VERSION_V1);
    put_bytes(&mut out, &value.prepared.intent_bytes().map_err(js_error)?)?;
    put_bytes(
        &mut out,
        &value.prepared.delegation_bytes().map_err(js_error)?,
    )?;
    put_bytes(
        &mut out,
        &value
            .prepared
            .credential_binding_bytes()
            .map_err(js_error)?,
    )?;
    put_bytes(&mut out, &value.prepared.quote_key_checkpoint_bytes())?;
    out.extend_from_slice(&value.claim_secret_key[..]);
    put_bytes(
        &mut out,
        &value
            .quote
            .as_ref()
            .map(AcceptedBolt11QuoteV1::bytes)
            .transpose()
            .map_err(js_error)?
            .unwrap_or_default(),
    )?;
    put_bytes(
        &mut out,
        value
            .claim
            .as_ref()
            .map(PreparedBolt11ClaimV1::envelope_bytes)
            .unwrap_or_default(),
    )?;
    match &value.method {
        MethodSecretsV1::DirectReceipt => {
            out.push(1);
            out.extend_from_slice(&0u32.to_le_bytes());
        }
        MethodSecretsV1::CashuBat(values) => {
            out.push(2);
            put_count(&mut out, values.len())?;
            for item in values {
                out.extend_from_slice(&item.secret[..]);
                out.extend_from_slice(&item.blinding_scalar[..]);
            }
        }
        MethodSecretsV1::ArcExperimental(values) => {
            out.push(3);
            put_count(&mut out, values.len())?;
            for item in values {
                put_bytes(&mut out, item)?;
            }
        }
    }
    if out.len() > MAX_RECOVERY_STATE_LEN_V1 {
        return Err(JsError::new("BOLT11 recovery state exceeds its V1 bound"));
    }
    Ok(out)
}

fn decode_recovery(bytes: &[u8], now_unix: u64) -> Result<WasmBolt11AcquisitionV1, JsError> {
    if bytes.is_empty() || bytes.len() > MAX_RECOVERY_STATE_LEN_V1 {
        return Err(JsError::new("invalid BOLT11 recovery state length"));
    }
    let mut decoder = RecoveryDecoder::new(bytes);
    if decoder.u8()? != RECOVERY_VERSION_V1 {
        return Err(JsError::new("unsupported BOLT11 recovery state version"));
    }
    let intent = decoder.bytes()?;
    let delegation = decoder.bytes()?;
    let binding = decoder.bytes()?;
    let checkpoint = decoder.bytes()?;
    let claim_secret_key = decoder.fixed::<32>()?;
    let quote_bytes = decoder.bytes()?;
    let claim_bytes = decoder.bytes()?;
    let method_tag = decoder.u8()?;
    let count = decoder.u32()? as usize;
    let method = match method_tag {
        1 if count == 0 => MethodSecretsV1::DirectReceipt,
        2 => {
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                values.push(BatWalletSecretV1 {
                    secret: Zeroizing::new(decoder.fixed::<32>()?),
                    blinding_scalar: Zeroizing::new(decoder.fixed::<32>()?),
                });
            }
            MethodSecretsV1::CashuBat(values)
        }
        3 => {
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                let encoded = decoder.bytes()?;
                if encoded.len() > MAX_ARC_PENDING_STATE_LEN_V1 {
                    return Err(JsError::new("ARC pending state exceeds its V1 bound"));
                }
                values.push(Zeroizing::new(encoded));
            }
            MethodSecretsV1::ArcExperimental(values)
        }
        _ => return Err(JsError::new("invalid BOLT11 recovery method tag/count")),
    };
    decoder.finish()?;
    let prepared = PreparedBolt11QuoteV1::restore(&intent, &delegation, &binding, &checkpoint)
        .map_err(js_error)?;
    // The reviewed helper returns `SigningKey::verifying_key().to_bytes()`,
    // i.e. BIP340's canonical even-Y x-only key, followed by the signature.
    let (public, _) =
        sign_bip340_prehash_v1(&claim_secret_key, &[7; 32], &[0; 32]).map_err(js_error)?;
    if public != prepared.intent().claim_pubkey_xonly
        || !method_matches_intent(&method, prepared.intent().authorization, count)
        || count != expected_secret_count(&method, prepared.intent().credential_count)?
    {
        return Err(JsError::new(
            "BOLT11 recovery secrets do not match the verified quote intent",
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
    let arc_codec = ArcIssuanceCanonicalizerV1;
    let claim = if claim_bytes.is_empty() {
        None
    } else {
        Some(
            prepared
                .restore_claim(
                    &claim_bytes,
                    matches!(method, MethodSecretsV1::ArcExperimental(_)).then_some(
                        &arc_codec as &dyn pir_service_protocol::ArcIssuanceCanonicalizerV1,
                    ),
                )
                .map_err(js_error)?,
        )
    };
    let value = WasmBolt11AcquisitionV1 {
        prepared,
        claim_secret_key: Zeroizing::new(claim_secret_key),
        method,
        quote,
        claim,
    };
    validate_method_state(&value, now_unix)?;
    Ok(value)
}

fn validate_method_state(value: &WasmBolt11AcquisitionV1, now_unix: u64) -> Result<(), JsError> {
    let Some(claim) = &value.claim else {
        return Ok(());
    };
    match (&value.method, claim.credential_request().items.clone()) {
        (MethodSecretsV1::DirectReceipt, CredentialIssuanceRequestItemsV1::DirectPaidReceipt) => {
            Ok(())
        }
        (
            MethodSecretsV1::CashuBat(secrets),
            CredentialIssuanceRequestItemsV1::BitcoinPirCashuBat(items),
        ) if secrets.len() == items.len() => {
            for (secret, item) in secrets.iter().zip(items) {
                if blind_cashu_message_v1(&secret.secret[..], &secret.blinding_scalar)
                    .map_err(js_error)?
                    != item.blinded_message
                {
                    return Err(JsError::new(
                        "restored BAT request differs from wallet secrets",
                    ));
                }
            }
            Ok(())
        }
        (
            MethodSecretsV1::ArcExperimental(pending),
            CredentialIssuanceRequestItemsV1::ArcExperimental(items),
        ) if pending.len() == items.len() => {
            let expected = binding_expectation(&value.prepared);
            let validation_time = value
                .quote
                .as_ref()
                .map(AcceptedBolt11QuoteV1::invoice_created_at)
                .unwrap_or(now_unix);
            for (encoded, item) in pending.iter().zip(items) {
                let (restored, _) = restore_arc_credential_request(
                    value.prepared.credential_binding(),
                    &expected,
                    validation_time,
                    encoded,
                )
                .map_err(js_error)?;
                if restored != item {
                    return Err(JsError::new(
                        "restored ARC request differs from client secrets",
                    ));
                }
            }
            Ok(())
        }
        _ => Err(JsError::new(
            "restored claim request differs from method-specific client state",
        )),
    }
}

fn method_matches_intent(
    method: &MethodSecretsV1,
    authorization: AuthScheme,
    count: usize,
) -> bool {
    matches!(
        (method, authorization),
        (
            MethodSecretsV1::DirectReceipt,
            AuthScheme::Bolt11DirectReceiptV1
        ) | (
            MethodSecretsV1::CashuBat(_),
            AuthScheme::BitcoinPirCashuBatV1
        ) | (
            MethodSecretsV1::ArcExperimental(_),
            AuthScheme::ArcV1Experimental
        )
    ) && (!matches!(method, MethodSecretsV1::DirectReceipt) || count == 0)
}

fn expected_secret_count(method: &MethodSecretsV1, signed_count: u32) -> Result<usize, JsError> {
    if matches!(method, MethodSecretsV1::DirectReceipt) {
        Ok(0)
    } else {
        usize::try_from(signed_count)
            .map_err(|_| JsError::new("signed credential count does not fit this browser"))
    }
}

fn parse_network(value: &str) -> Result<LightningNetworkV1, JsError> {
    match value {
        "bitcoin" => Ok(LightningNetworkV1::Bitcoin),
        "testnet" => Ok(LightningNetworkV1::Testnet),
        "signet" => Ok(LightningNetworkV1::Signet),
        "regtest" => Ok(LightningNetworkV1::Regtest),
        _ => Err(JsError::new("unsupported Lightning network")),
    }
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
    let mut value = [0u8; 32];
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
    let count = u32::try_from(count).map_err(|_| JsError::new("item count exceeds V1"))?;
    out.extend_from_slice(&count.to_le_bytes());
    Ok(())
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), JsError> {
    let len = u32::try_from(bytes.len()).map_err(|_| JsError::new("field exceeds V1"))?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

struct RecoveryDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> RecoveryDecoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], JsError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| JsError::new("BOLT11 recovery offset overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| JsError::new("truncated BOLT11 recovery state"))?;
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
        fixed(self.take(N)?, "fixed recovery field")
    }

    fn bytes(&mut self) -> Result<Vec<u8>, JsError> {
        let len = self.u32()? as usize;
        if len > MAX_RECOVERY_STATE_LEN_V1 {
            return Err(JsError::new("BOLT11 recovery field exceeds V1"));
        }
        Ok(self.take(len)?.to_vec())
    }

    fn finish(self) -> Result<(), JsError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(JsError::new("trailing BOLT11 recovery bytes"))
        }
    }
}

fn js_error(error: impl core::fmt::Display) -> JsError {
    JsError::new(&error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_key_uses_bip340_xonly_verifying_key_not_signature_prefix() {
        let (secret, expected_xonly) = fresh_claim_key().ok().expect("fresh claim key");
        let (actual_xonly, signature) =
            sign_bip340_prehash_v1(&secret, &[9; 32], &[3; 32]).expect("sign");
        assert_eq!(actual_xonly, expected_xonly);
        assert_ne!(signature[..32], expected_xonly);
    }

    #[test]
    fn generated_bat_wallet_state_reconstructs_its_blinded_message() {
        let state = fresh_bat_secret().ok().expect("fresh BAT state");
        let first =
            blind_cashu_message_v1(&state.secret[..], &state.blinding_scalar).expect("blind once");
        let restored =
            blind_cashu_message_v1(&state.secret[..], &state.blinding_scalar).expect("blind twice");
        assert_eq!(first, restored);
    }
}
