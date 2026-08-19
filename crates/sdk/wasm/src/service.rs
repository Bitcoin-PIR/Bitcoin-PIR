//! Browser bindings for strict V1 provider service policies.
//!
//! Each value is provider-local. It has no peer-server field and carries no
//! invoice, payment hash, payer, query identifier, or Bitcoin address.

use ed25519_dalek::VerifyingKey;
use pir_arc_adapter::{arc_public_key_fingerprint_v1, ARC_PUBLIC_KEY_LEN_V1};
use pir_sdk_client::{
    accept_pow_challenge_response_v1, accept_retained_service_policy_response_v1,
    accept_service_policy_response_v1, build_pow_challenge_request_v1,
    build_retained_service_policy_request_v1, build_service_policy_request_v1,
    dangerous_unpaired_accept_retained_service_authorization_response_v1,
    dangerous_unpaired_accept_service_authorization_response_v1,
    dangerous_unpaired_build_authorization_proof_v1,
    dangerous_unpaired_build_retained_authorization_proof_v1,
    dangerous_unpaired_build_retained_service_authorization_request_v1,
    dangerous_unpaired_build_service_authorization_request_v1, AcceptedRetiredServiceRedemptionV1,
    AcceptedServicePolicyV1, ServicePolicyCheckpointV1,
};
use pir_service_protocol::{
    bat_verification_key_fingerprint_v1, pow_solution_meets_difficulty_v1, AcquisitionMethod,
    AuthGrantedV1, AuthScheme, BackendId, DatasetBindingV1, DeploymentStatus, EntitlementLimitsV1,
    FreeModeV1, FreePowProofV1, OperationStartV1, PowChallengeResponseV1, PriceV1, ServiceOfferV1,
    VerificationMode, WorkloadId,
};
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// One signed policy accepted against an independently pinned provider.
#[wasm_bindgen]
pub struct WasmAcceptedServicePolicyV1 {
    pub(crate) inner: AcceptedServicePolicyV1,
    checkpoint_persisted: bool,
}

/// Exact historical policy typestate. It has no checkpoint, offer-selection,
/// PoW, quote, or acquisition API and can only redeem its fixed credential.
#[wasm_bindgen]
pub struct WasmAcceptedRetainedServiceRedemptionV1 {
    pub(crate) inner: AcceptedRetiredServiceRedemptionV1,
}

/// Opaque, verified proof-of-work challenge bound to one provider connection
/// and one exact operation. No challenge identifier is exposed to normal JS
/// metadata/logging paths.
#[wasm_bindgen]
pub struct WasmServicePowChallengeV1 {
    pub(crate) inner: PowChallengeResponseV1,
}

/// Transport-free service-admission state for the standalone C++/SEAL
/// OnionPIR browser. The caller sends each returned frame over the exact
/// authenticated socket whose exporter initialized this value.
#[wasm_bindgen]
pub struct WasmStandaloneOnionServiceAdmissionV1 {
    db_id: u8,
    secure_channel_exporter: [u8; 32],
}

#[wasm_bindgen]
impl WasmStandaloneOnionServiceAdmissionV1 {
    #[wasm_bindgen(constructor)]
    pub fn new(db_id: u8, secure_channel_exporter: &[u8]) -> Result<Self, JsError> {
        let secure_channel_exporter: [u8; 32] = secure_channel_exporter
            .try_into()
            .map_err(|_| JsError::new("secureChannelExporter must be exactly 32 bytes"))?;
        if secure_channel_exporter.iter().all(|byte| *byte == 0) {
            return Err(JsError::new("secureChannelExporter must be non-zero"));
        }
        Ok(Self {
            db_id,
            secure_channel_exporter,
        })
    }

    /// Fetching a policy is non-consuming and may occur immediately after the
    /// strict transport identity checks.
    #[wasm_bindgen(js_name = policyRequest)]
    pub fn policy_request(&self) -> Vec<u8> {
        build_service_policy_request_v1()
    }

    #[wasm_bindgen(js_name = retainedPolicyRequest)]
    pub fn retained_policy_request(&self, policy_digest: &[u8]) -> Result<Vec<u8>, JsError> {
        build_retained_service_policy_request_v1(parse_digest_v1("policyDigest", policy_digest)?)
            .map_err(|error| JsError::new(&error.to_string()))
    }

    /// Fail before capability retirement if `accepted` came from a previous
    /// secure-channel session.
    #[wasm_bindgen(js_name = verifyPolicySession)]
    pub fn verify_policy_session(
        &self,
        accepted: &WasmAcceptedServicePolicyV1,
    ) -> Result<(), JsError> {
        accepted
            .inner
            .verify_service_authorization_exporter_v1(&self.secure_channel_exporter)
            .map_err(|error| JsError::new(&error.to_string()))
    }

    #[wasm_bindgen(js_name = acceptPolicyResponse)]
    pub fn accept_policy_response(
        &self,
        response_frame: &[u8],
        expected_provider_id: &[u8],
        policy_signing_key: &[u8],
        now_unix: u64,
        checkpoint_bytes: &[u8],
    ) -> Result<WasmAcceptedServicePolicyV1, JsError> {
        let (provider_id, signing_key, checkpoint) =
            parse_service_trust_v1(expected_provider_id, policy_signing_key, checkpoint_bytes)?;
        let payload =
            crate::standalone_channel::exact_payload(response_frame, "service policy response")?;
        let accepted = accept_service_policy_response_v1(
            payload,
            provider_id,
            &signing_key,
            now_unix,
            &checkpoint,
            self.secure_channel_exporter,
        )
        .map_err(|error| JsError::new(&error.to_string()))?;
        Ok(WasmAcceptedServicePolicyV1::from_native(accepted))
    }

    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = acceptRetainedPolicyResponse)]
    pub fn accept_retained_policy_response(
        &self,
        response_frame: &[u8],
        expected_provider_id: &[u8],
        policy_signing_key: &[u8],
        expected_policy_digest: &[u8],
        scope_id: &[u8],
        offer_id: u32,
        now_unix: u64,
    ) -> Result<WasmAcceptedRetainedServiceRedemptionV1, JsError> {
        let (provider_id, signing_key) =
            parse_provider_and_key_v1(expected_provider_id, policy_signing_key)?;
        let payload = crate::standalone_channel::exact_payload(
            response_frame,
            "retained service policy response",
        )?;
        let accepted = accept_retained_service_policy_response_v1(
            payload,
            provider_id,
            &signing_key,
            parse_digest_v1("expectedPolicyDigest", expected_policy_digest)?,
            parse_scope_id_v1(scope_id)?,
            offer_id,
            now_unix,
            self.secure_channel_exporter,
        )
        .map_err(|error| JsError::new(&error.to_string()))?;
        Ok(WasmAcceptedRetainedServiceRedemptionV1 { inner: accepted })
    }

    #[wasm_bindgen(js_name = verifyRetainedPolicySession)]
    pub fn verify_retained_policy_session(
        &self,
        accepted: &WasmAcceptedRetainedServiceRedemptionV1,
        now_unix: u64,
    ) -> Result<(), JsError> {
        accepted
            .inner
            .verify_service_authorization_exporter_v1(&self.secure_channel_exporter)
            .and_then(|_| accepted.inner.verify_redemption_ready_v1(now_unix))
            .map_err(|error| JsError::new(&error.to_string()))
    }

    #[wasm_bindgen(js_name = powChallengeRequest)]
    pub fn pow_challenge_request(
        &self,
        accepted: &WasmAcceptedServicePolicyV1,
        scope_id: &[u8],
        offer_id: u32,
    ) -> Result<Vec<u8>, JsError> {
        accepted.require_checkpoint_persisted()?;
        accepted
            .inner
            .verify_service_authorization_exporter_v1(&self.secure_channel_exporter)
            .map_err(|error| JsError::new(&error.to_string()))?;
        build_pow_challenge_request_v1(
            &accepted.inner,
            parse_scope_id_v1(scope_id)?,
            offer_id,
            OperationStartV1::OnionSession { db_id: self.db_id },
        )
        .map_err(|error| JsError::new(&error.to_string()))
    }

    #[wasm_bindgen(js_name = acceptPowChallengeResponse)]
    pub fn accept_pow_challenge_response(
        &self,
        response_frame: &[u8],
        accepted: &WasmAcceptedServicePolicyV1,
        scope_id: &[u8],
        offer_id: u32,
        now_unix: u64,
    ) -> Result<WasmServicePowChallengeV1, JsError> {
        accepted.require_checkpoint_persisted()?;
        accepted
            .inner
            .verify_service_authorization_exporter_v1(&self.secure_channel_exporter)
            .map_err(|error| JsError::new(&error.to_string()))?;
        let payload = crate::standalone_channel::exact_payload(
            response_frame,
            "proof-of-work challenge response",
        )?;
        let challenge = accept_pow_challenge_response_v1(
            payload,
            &accepted.inner,
            parse_scope_id_v1(scope_id)?,
            offer_id,
            OperationStartV1::OnionSession { db_id: self.db_id },
            &self.secure_channel_exporter,
            now_unix,
        )
        .map_err(|error| JsError::new(&error.to_string()))?;
        Ok(WasmServicePowChallengeV1::from_native(challenge))
    }

    /// Build only after JS has durably retired/advanced the selected proof.
    /// This method never sends and never retains the proof.
    #[wasm_bindgen(js_name = authorizationRequest)]
    pub fn authorization_request(
        &self,
        accepted: &WasmAcceptedServicePolicyV1,
        scope_id: &[u8],
        offer_id: u32,
        proof_bytes: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        accepted
            .inner
            .verify_service_authorization_exporter_v1(&self.secure_channel_exporter)
            .map_err(|error| JsError::new(&error.to_string()))?;
        let scope_id = parse_scope_id_v1(scope_id)?;
        let proof = build_proof_v1(accepted, &scope_id, offer_id, proof_bytes)?;
        dangerous_unpaired_build_service_authorization_request_v1(
            &accepted.inner,
            scope_id,
            offer_id,
            OperationStartV1::OnionSession { db_id: self.db_id },
            proof,
        )
        .map_err(|error| JsError::new(&error.to_string()))
    }

    #[wasm_bindgen(js_name = retainedAuthorizationRequest)]
    pub fn retained_authorization_request(
        &self,
        accepted: &WasmAcceptedRetainedServiceRedemptionV1,
        proof_bytes: &[u8],
        now_unix: u64,
    ) -> Result<Vec<u8>, JsError> {
        self.verify_retained_policy_session(accepted, now_unix)?;
        let proof =
            dangerous_unpaired_build_retained_authorization_proof_v1(&accepted.inner, proof_bytes)
                .map_err(|error| JsError::new(&error.to_string()))?;
        dangerous_unpaired_build_retained_service_authorization_request_v1(
            &accepted.inner,
            OperationStartV1::OnionSession { db_id: self.db_id },
            proof,
            now_unix,
        )
        .map_err(|error| JsError::new(&error.to_string()))
    }

    #[wasm_bindgen(js_name = acceptAuthorizationResponse)]
    pub fn accept_authorization_response(
        &self,
        response_frame: &[u8],
        accepted: &WasmAcceptedServicePolicyV1,
        scope_id: &[u8],
    ) -> Result<JsValue, JsError> {
        accepted.require_checkpoint_persisted()?;
        accepted
            .inner
            .verify_service_authorization_exporter_v1(&self.secure_channel_exporter)
            .map_err(|error| JsError::new(&error.to_string()))?;
        let scope_id = parse_scope_id_v1(scope_id)?;
        let payload = crate::standalone_channel::exact_payload(
            response_frame,
            "service authorization response",
        )?;
        let grant = dangerous_unpaired_accept_service_authorization_response_v1(
            payload,
            &accepted.inner,
            scope_id,
        )
        .map_err(|error| JsError::new(&error.to_string()))?;
        Ok(grant_json_v1(&grant))
    }

    #[wasm_bindgen(js_name = acceptRetainedAuthorizationResponse)]
    pub fn accept_retained_authorization_response(
        &self,
        response_frame: &[u8],
        accepted: &WasmAcceptedRetainedServiceRedemptionV1,
        now_unix: u64,
    ) -> Result<JsValue, JsError> {
        self.verify_retained_policy_session(accepted, now_unix)?;
        let payload = crate::standalone_channel::exact_payload(
            response_frame,
            "retained service authorization response",
        )?;
        let grant = dangerous_unpaired_accept_retained_service_authorization_response_v1(
            payload,
            &accepted.inner,
        )
        .map_err(|error| JsError::new(&error.to_string()))?;
        Ok(grant_json_v1(&grant))
    }
}

#[wasm_bindgen]
impl WasmAcceptedRetainedServiceRedemptionV1 {
    #[wasm_bindgen(getter, js_name = providerIdHex)]
    pub fn provider_id_hex(&self) -> String {
        hex::encode(self.inner.policy().provider_id)
    }

    #[wasm_bindgen(getter, js_name = policyDigestHex)]
    pub fn policy_digest_hex(&self) -> String {
        hex::encode(self.inner.policy_digest())
    }

    #[wasm_bindgen(getter, js_name = scopeIdHex)]
    pub fn scope_id_hex(&self) -> String {
        hex::encode(self.inner.scope_id())
    }

    #[wasm_bindgen(getter, js_name = offerId)]
    pub fn offer_id(&self) -> u32 {
        self.inner.offer_id()
    }

    #[wasm_bindgen(js_name = assertRedemptionReady)]
    pub fn assert_redemption_ready(&self, now_unix: u64) -> Result<(), JsError> {
        self.inner
            .verify_redemption_ready_v1(now_unix)
            .map_err(|error| JsError::new(&error.to_string()))
    }

    #[wasm_bindgen(js_name = validateAuthorizationProof)]
    pub fn validate_authorization_proof(&self, proof_bytes: &[u8]) -> Result<(), JsError> {
        dangerous_unpaired_build_retained_authorization_proof_v1(&self.inner, proof_bytes)
            .map(|_| ())
            .map_err(|error| JsError::new(&error.to_string()))
    }

    /// Non-secret metadata from the exact historical signed selector. The
    /// trusted clock re-check prevents UI/pair preflight from treating an
    /// expired grace window as redeemable.
    #[wasm_bindgen(js_name = redemptionJson)]
    pub fn redemption_json(&self, now_unix: u64) -> Result<JsValue, JsError> {
        let verified = self
            .inner
            .verified_offer_for_redemption_v1(now_unix)
            .map_err(|error| JsError::new(&error.to_string()))?;
        let scope = verified.scope();
        json_compatible_js_value_v1(&serde_json::json!({
            "providerIdHex": self.provider_id_hex(),
            "policyDigestHex": self.policy_digest_hex(),
            "scope": {
                "scopeIdHex": hex::encode(scope.scope_id()),
                "backend": backend_label(scope.backend),
                "workload": workload_label(scope.workload),
                "protocolVersion": scope.protocol_version,
                "operationProfile": scope.operation_profile,
                "entitlementProfile": scope.entitlement_profile,
                "dataset": dataset_json_v1(&scope.dataset),
                "limits": limits_json_v1(verified.limits()),
                "offers": [],
            },
            "offer": service_offer_json_v1(verified.offer()),
        }))
        .map_err(|error| JsError::new(&error.to_string()))
    }
}

impl WasmServicePowChallengeV1 {
    pub(crate) fn from_native(inner: PowChallengeResponseV1) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
impl WasmServicePowChallengeV1 {
    #[wasm_bindgen(getter, js_name = difficultyBits)]
    pub fn difficulty_bits(&self) -> u8 {
        self.inner.difficulty_bits
    }

    #[wasm_bindgen(getter, js_name = expiresAtUnix)]
    pub fn expires_at_unix(&self) -> String {
        self.inner.expires_at_unix.to_string()
    }

    /// Search a bounded nonce range. Empty means no solution in this chunk;
    /// callers should yield to the browser event loop before the next chunk.
    #[wasm_bindgen(js_name = solveChunk)]
    pub fn solve_chunk(&self, start_nonce: u64, max_attempts: u32) -> Result<Vec<u8>, JsError> {
        if max_attempts == 0 || max_attempts > 1_000_000 {
            return Err(JsError::new("maxAttempts must be within 1..=1000000"));
        }
        let mut nonce = start_nonce;
        for attempt in 0..max_attempts {
            let proof = FreePowProofV1 {
                challenge_id: self.inner.challenge_id,
                nonce,
            };
            if pow_solution_meets_difficulty_v1(&self.inner, &proof)
                .map_err(|error| JsError::new(&error.to_string()))?
            {
                return proof
                    .encode()
                    .map(|bytes| bytes.to_vec())
                    .map_err(|error| JsError::new(&error.to_string()));
            }
            if attempt + 1 < max_attempts {
                nonce = nonce
                    .checked_add(1)
                    .ok_or_else(|| JsError::new("proof-of-work nonce space exhausted"))?;
            }
        }
        Ok(Vec::new())
    }
}

impl WasmAcceptedServicePolicyV1 {
    pub(crate) fn from_native(inner: AcceptedServicePolicyV1) -> Self {
        Self {
            inner,
            checkpoint_persisted: false,
        }
    }

    pub(crate) fn require_checkpoint_persisted(&self) -> Result<(), JsError> {
        if self.checkpoint_persisted {
            Ok(())
        } else {
            Err(JsError::new(
                "persist checkpointBytes in the provider-specific vault before authorization",
            ))
        }
    }
}

#[wasm_bindgen]
impl WasmAcceptedServicePolicyV1 {
    #[wasm_bindgen(getter, js_name = providerIdHex)]
    pub fn provider_id_hex(&self) -> String {
        hex::encode(self.inner.policy().provider_id)
    }

    #[wasm_bindgen(getter, js_name = policyDigestHex)]
    pub fn policy_digest_hex(&self) -> String {
        hex::encode(self.inner.policy_digest())
    }

    /// Decimal strings avoid JavaScript's 53-bit integer limit.
    #[wasm_bindgen(getter, js_name = policyEpoch)]
    pub fn policy_epoch(&self) -> String {
        self.inner.policy().policy_epoch.to_string()
    }

    #[wasm_bindgen(getter, js_name = expiresAtUnix)]
    pub fn expires_at_unix(&self) -> String {
        self.inner.policy().expires_at.to_string()
    }

    /// Opaque per-provider anti-rollback state. It contains only policy and
    /// keyset floors, never payment/query material.
    #[wasm_bindgen(js_name = checkpointBytes)]
    pub fn checkpoint_bytes(&self) -> Result<Vec<u8>, JsError> {
        self.inner
            .checkpoint()
            .encode()
            .map_err(|error| JsError::new(&error.to_string()))
    }

    /// Call only after `checkpointBytes` has durably committed in IndexedDB.
    #[wasm_bindgen(js_name = acknowledgeCheckpointPersisted)]
    pub fn acknowledge_checkpoint_persisted(&mut self) {
        self.checkpoint_persisted = true;
    }

    /// Begin a provider-independent BOLT11 acquisition for one exact signed
    /// scope/offer. The provider policy checkpoint must already be durable;
    /// the returned quote-key checkpoint has its own persist-before-POST rule.
    #[wasm_bindgen(js_name = beginBolt11Acquisition)]
    pub fn begin_bolt11_acquisition(
        &self,
        scope_id: &[u8],
        offer_id: u32,
        quote_delegation_bytes: &[u8],
        quote_key_checkpoint_bytes: &[u8],
        now_unix: u64,
    ) -> Result<crate::bolt11::WasmBolt11AcquisitionV1, JsError> {
        self.require_checkpoint_persisted()?;
        crate::bolt11::begin_bolt11_acquisition_v1(
            &self.inner,
            scope_id,
            offer_id,
            quote_delegation_bytes,
            quote_key_checkpoint_bytes,
            now_unix,
        )
    }

    /// Decode and validate one canonical method proof against this exact
    /// signed scope/offer without sending or consuming it.
    #[wasm_bindgen(js_name = validateAuthorizationProof)]
    pub fn validate_authorization_proof(
        &self,
        scope_id: &[u8],
        offer_id: u32,
        proof_bytes: &[u8],
    ) -> Result<(), JsError> {
        let scope_id = parse_scope_id_v1(scope_id)?;
        build_proof_v1(self, &scope_id, offer_id, proof_bytes).map(|_| ())
    }

    /// Strictly import a wallet Cashu V3/V4 token for one exact signed offer.
    /// This performs no network request. Known NUT-12 DLEQ metadata is
    /// verified locally and stripped; its private `r` never enters the
    /// provider wire. Unknown fields, witness data, NUT-10 secrets, wrong
    /// mint/unit/keyset/denomination/amount, duplicate proofs, and
    /// non-canonical encodings fail before any vault write.
    #[wasm_bindgen(js_name = importStandardCashuToken)]
    pub fn import_standard_cashu_token(
        &self,
        scope_id: &[u8],
        offer_id: u32,
        serialized_token: &str,
        now_unix: u64,
    ) -> Result<Vec<u8>, JsError> {
        self.require_checkpoint_persisted()?;
        let scope_id = parse_scope_id_v1(scope_id)?;
        crate::standard_cashu::import_standard_cashu_token_v1(
            &self.inner,
            &scope_id,
            offer_id,
            serialized_token,
            now_unix,
        )
        .map_err(|error| JsError::new(&error))
    }

    /// Non-secret offer metadata for independent UI selection.
    #[wasm_bindgen(js_name = offersJson)]
    pub fn offers_json(&self) -> JsValue {
        let scopes: Vec<serde_json::Value> = self
            .inner
            .policy()
            .scopes
            .iter()
            .map(|scope_policy| {
                let offers: Vec<serde_json::Value> = scope_policy
                    .offers
                    .iter()
                    .map(service_offer_json_v1)
                    .collect();
                serde_json::json!({
                    "scopeIdHex": hex::encode(scope_policy.scope.scope_id()),
                    "backend": backend_label(scope_policy.scope.backend),
                    "workload": workload_label(scope_policy.scope.workload),
                    "protocolVersion": scope_policy.scope.protocol_version,
                    "operationProfile": scope_policy.scope.operation_profile,
                    "entitlementProfile": scope_policy.scope.entitlement_profile,
                    "dataset": dataset_json_v1(&scope_policy.scope.dataset),
                    "limits": limits_json_v1(&scope_policy.limits),
                    "offers": offers,
                })
            })
            .collect();
        json_compatible_js_value_v1(&serde_json::json!({
            "providerIdHex": self.provider_id_hex(),
            "policyDigestHex": self.policy_digest_hex(),
            "policyEpoch": self.policy_epoch(),
            "expiresAtUnix": self.expires_at_unix(),
            "scopes": scopes,
        }))
        .unwrap_or(JsValue::NULL)
    }
}

#[wasm_bindgen(js_name = initialServicePolicyCheckpointV1)]
pub fn initial_service_policy_checkpoint_v1() -> Result<Vec<u8>, JsError> {
    ServicePolicyCheckpointV1::initial()
        .encode()
        .map_err(|error| JsError::new(&error.to_string()))
}

pub(crate) fn parse_service_trust_v1(
    expected_provider_id: &[u8],
    policy_signing_key: &[u8],
    checkpoint_bytes: &[u8],
) -> Result<([u8; 32], VerifyingKey, ServicePolicyCheckpointV1), JsError> {
    let provider_id: [u8; 32] = expected_provider_id.try_into().map_err(|_| {
        JsError::new(&format!(
            "expectedProviderId must be 32 bytes, got {}",
            expected_provider_id.len()
        ))
    })?;
    let key_bytes: [u8; 32] = policy_signing_key.try_into().map_err(|_| {
        JsError::new(&format!(
            "policySigningKey must be 32 bytes, got {}",
            policy_signing_key.len()
        ))
    })?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| JsError::new("policySigningKey is not a valid Ed25519 public key"))?;
    let checkpoint = if checkpoint_bytes.is_empty() {
        ServicePolicyCheckpointV1::initial()
    } else {
        ServicePolicyCheckpointV1::decode(checkpoint_bytes)
            .map_err(|error| JsError::new(&error.to_string()))?
    };
    Ok((provider_id, key, checkpoint))
}

pub(crate) fn parse_provider_and_key_v1(
    expected_provider_id: &[u8],
    policy_signing_key: &[u8],
) -> Result<([u8; 32], VerifyingKey), JsError> {
    let provider_id: [u8; 32] = expected_provider_id.try_into().map_err(|_| {
        JsError::new(&format!(
            "expectedProviderId must be 32 bytes, got {}",
            expected_provider_id.len()
        ))
    })?;
    let key_bytes: [u8; 32] = policy_signing_key.try_into().map_err(|_| {
        JsError::new(&format!(
            "policySigningKey must be 32 bytes, got {}",
            policy_signing_key.len()
        ))
    })?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| JsError::new("policySigningKey is not a valid Ed25519 public key"))?;
    Ok((provider_id, key))
}

pub(crate) fn parse_digest_v1(field: &str, value: &[u8]) -> Result<[u8; 32], JsError> {
    let digest: [u8; 32] = value
        .try_into()
        .map_err(|_| JsError::new(&format!("{field} must be exactly 32 bytes")))?;
    if digest.iter().all(|byte| *byte == 0) {
        return Err(JsError::new(&format!("{field} must be non-zero")));
    }
    Ok(digest)
}

pub(crate) fn parse_scope_id_v1(scope_id: &[u8]) -> Result<[u8; 32], JsError> {
    scope_id
        .try_into()
        .map_err(|_| JsError::new(&format!("scopeId must be 32 bytes, got {}", scope_id.len())))
}

pub(crate) fn build_proof_v1(
    accepted: &WasmAcceptedServicePolicyV1,
    scope_id: &[u8; 32],
    offer_id: u32,
    proof_bytes: &[u8],
) -> Result<pir_service_protocol::AuthorizationProofV1, JsError> {
    accepted.require_checkpoint_persisted()?;
    dangerous_unpaired_build_authorization_proof_v1(
        &accepted.inner,
        scope_id,
        offer_id,
        proof_bytes,
    )
    .map_err(|error| JsError::new(&error.to_string()))
}

pub(crate) fn build_retained_proof_v1(
    accepted: &WasmAcceptedRetainedServiceRedemptionV1,
    proof_bytes: &[u8],
    now_unix: u64,
) -> Result<pir_service_protocol::AuthorizationProofV1, JsError> {
    accepted
        .inner
        .verify_redemption_ready_v1(now_unix)
        .map_err(|error| JsError::new(&error.to_string()))?;
    dangerous_unpaired_build_retained_authorization_proof_v1(&accepted.inner, proof_bytes)
        .map_err(|error| JsError::new(&error.to_string()))
}

pub(crate) fn grant_json_v1(grant: &AuthGrantedV1) -> JsValue {
    // A half-stream attach secret never enters this general-purpose summary.
    json_compatible_js_value_v1(&grant_json_value_v1(grant)).unwrap_or(JsValue::NULL)
}

fn grant_json_value_v1(grant: &AuthGrantedV1) -> serde_json::Value {
    serde_json::json!({
        "scopeIdHex": hex::encode(grant.scope_id),
        "enforcedProfile": grant.enforced_profile,
        "expiresInMs": grant.expires_in_ms,
        "hasHarmonyAttach": grant.harmony_attach.is_some(),
    })
}

/// TypeScript-facing `*Json()` methods promise plain JSON objects. The
/// serde-wasm-bindgen default represents maps as JavaScript `Map` values,
/// which makes ordinary property access such as `view.scopes` undefined.
fn json_compatible_js_value_v1(
    value: &serde_json::Value,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    value.serialize(&serde_wasm_bindgen::Serializer::json_compatible())
}

fn service_offer_json_v1(offer: &ServiceOfferV1) -> serde_json::Value {
    let bat_verification_key_fingerprint_hex = if offer.authorization
        == AuthScheme::BitcoinPirCashuBatV1
    {
        offer
            .credential_binding
            .as_ref()
            .and_then(|binding| {
                let key: [u8; 33] = binding.claims.verification_key.as_slice().try_into().ok()?;
                bat_verification_key_fingerprint_v1(&key).ok()
            })
            .map(hex::encode)
            .unwrap_or_default()
    } else {
        String::new()
    };
    let arc_verification_key_fingerprint_hex = arc_verification_key_fingerprint_hex_v1(offer);
    let price = match &offer.price {
        PriceV1::Free => serde_json::json!({ "kind": "free" }),
        PriceV1::MilliSatoshi(amount) => serde_json::json!({
            "kind": "msat",
            "amount": amount.to_string(),
        }),
        PriceV1::Cashu { unit, amount } => serde_json::json!({
            "kind": "cashu",
            "unit": unit,
            "amount": amount.to_string(),
        }),
    };
    serde_json::json!({
        "offerId": offer.offer_id,
        "acquisition": acquisition_label(offer.acquisition),
        "authorization": auth_scheme_label(offer.authorization),
        "freeMode": free_mode_label(offer.free_mode),
        "verification": verification_label(offer.verification),
        "deploymentStatus": deployment_label(offer.deployment_status),
        "priorityClass": offer.priority_class,
        "price": price,
        "issuerIdHex": hex::encode(offer.issuer_id),
        "keyIdHex": hex::encode(&offer.key_id),
        "batVerificationKeyFingerprintHex": bat_verification_key_fingerprint_hex,
        "arcVerificationKeyFingerprintHex": arc_verification_key_fingerprint_hex,
        "endpoint": offer.endpoint,
        "credentialCount": offer.credential_count,
        "credentialPresentationLimit": offer.credential_presentation_limit,
        "privacyLeakageBits": offer.privacy_leakage.bits(),
    })
}

fn arc_verification_key_fingerprint_hex_v1(offer: &ServiceOfferV1) -> String {
    if offer.authorization != AuthScheme::ArcV1Experimental {
        return String::new();
    }
    offer
        .credential_binding
        .as_ref()
        .and_then(|binding| {
            let key: [u8; ARC_PUBLIC_KEY_LEN_V1] =
                binding.claims.verification_key.as_slice().try_into().ok()?;
            arc_public_key_fingerprint_v1(&key).ok()
        })
        .map(hex::encode)
        .unwrap_or_default()
}

fn limits_json_v1(limits: &EntitlementLimitsV1) -> serde_json::Value {
    serde_json::json!({
        "maxLogicalInputs": limits.max_logical_inputs,
        "maxFrames": limits.max_frames,
        "maxRequestBytes": limits.max_request_bytes.to_string(),
        "maxResponseBytes": limits.max_response_bytes.to_string(),
        "maxWallTimeMs": limits.max_wall_time_ms,
        "maxConcurrentSockets": limits.max_concurrent_sockets,
        "maxHintGroups": limits.max_hint_groups,
        "maxWorkUnits": limits.max_work_units.to_string(),
    })
}

fn dataset_json_v1(dataset: &DatasetBindingV1) -> serde_json::Value {
    match dataset {
        DatasetBindingV1::Class { class_id } => serde_json::json!({
            "kind": "class",
            "classId": class_id,
        }),
        DatasetBindingV1::CatalogEpoch { epoch } => serde_json::json!({
            "kind": "catalog-epoch",
            "epoch": epoch.to_string(),
        }),
        DatasetBindingV1::ManifestRoot { root } => serde_json::json!({
            "kind": "manifest-root",
            "rootHex": hex::encode(root),
        }),
    }
}

const fn acquisition_label(value: AcquisitionMethod) -> &'static str {
    match value {
        AcquisitionMethod::FreeV1 => "free",
        AcquisitionMethod::Bolt11V1 => "bolt11",
        AcquisitionMethod::CashuEcashV1 => "cashu-ecash",
    }
}

const fn auth_scheme_label(value: AuthScheme) -> &'static str {
    match value {
        AuthScheme::FreeV1 => "free",
        AuthScheme::Bolt11DirectReceiptV1 => "bolt11-direct-receipt",
        AuthScheme::CashuEcashV1 => "cashu-ecash",
        AuthScheme::BitcoinPirCashuBatV1 => "cashu-bat",
        AuthScheme::ArcV1Experimental => "arc-experimental",
        AuthScheme::BitcoinPirCashuBatV2 => "cashu-bat-v2",
    }
}

const fn free_mode_label(value: FreeModeV1) -> &'static str {
    match value {
        FreeModeV1::NotFree => "not-free",
        FreeModeV1::OpenBestEffort => "open-best-effort",
        FreeModeV1::IpRateLimited => "ip-rate-limited",
        FreeModeV1::ProofOfWork => "proof-of-work",
        FreeModeV1::AnonymousTicket => "anonymous-ticket",
    }
}

const fn verification_label(value: VerificationMode) -> &'static str {
    match value {
        VerificationMode::ProviderLocal => "provider-local",
        VerificationMode::SharedIssuerOnline => "shared-issuer-online",
        VerificationMode::StandardCashuMintOnline => "standard-cashu-mint-online",
    }
}

const fn deployment_label(value: DeploymentStatus) -> &'static str {
    match value {
        DeploymentStatus::Stable => "stable",
        DeploymentStatus::Experimental => "experimental",
    }
}

const fn backend_label(value: BackendId) -> &'static str {
    match value {
        BackendId::DpfPirV1 => "dpf-pir",
        BackendId::HarmonyPirV2 => "harmony-pir",
        BackendId::OnionPirV1 => "onion-pir",
        BackendId::TeeOramV1 => "tee-oram",
    }
}

const fn workload_label(value: WorkloadId) -> &'static str {
    match value {
        WorkloadId::DpfEvaluateJobV1 => "dpf-query",
        WorkloadId::HarmonyHintBundleV1 => "harmony-hint",
        WorkloadId::HarmonyQueryJobV1 => "harmony-query",
        WorkloadId::OnionEvaluateJobV1 => "onion-session",
        WorkloadId::TeeOramQueryV1 => "tee-oram-query",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use pir_service_protocol::{
        CredentialKeyBindingClaimsV1, CredentialKeyBindingV1, CredentialUnitV1, PrivacyLeakageV1,
    };

    #[test]
    fn grant_json_value_matches_the_plain_typescript_object_contract() {
        let grant = AuthGrantedV1 {
            scope_id: [0x2a; 32],
            enforced_profile: 17,
            expires_in_ms: 9_000,
            harmony_attach: None,
        };
        let value = grant_json_value_v1(&grant);
        let object = value.as_object().expect("grant JSON object");
        let expected_scope_id = hex::encode([0x2a; 32]);
        assert_eq!(
            object.get("scopeIdHex").and_then(|value| value.as_str()),
            Some(expected_scope_id.as_str())
        );
        assert_eq!(
            object
                .get("enforcedProfile")
                .and_then(|value| value.as_u64()),
            Some(17)
        );
        assert_eq!(
            object.get("expiresInMs").and_then(|value| value.as_u64()),
            Some(9_000)
        );
        assert_eq!(
            object
                .get("hasHarmonyAttach")
                .and_then(|value| value.as_bool()),
            Some(false)
        );
    }

    #[test]
    fn entitlement_limits_json_preserves_every_signed_counter_without_number_loss() {
        let limits = EntitlementLimitsV1 {
            max_logical_inputs: u16::MAX,
            max_frames: u32::MAX,
            max_request_bytes: u64::MAX,
            max_response_bytes: u64::MAX - 1,
            max_wall_time_ms: u32::MAX,
            max_concurrent_sockets: u8::MAX,
            max_hint_groups: u16::MAX - 1,
            max_work_units: u64::MAX - 2,
        };
        let value = limits_json_v1(&limits);
        assert_eq!(
            value["maxLogicalInputs"].as_u64(),
            Some(u64::from(u16::MAX))
        );
        assert_eq!(value["maxFrames"].as_u64(), Some(u64::from(u32::MAX)));
        assert_eq!(
            value["maxRequestBytes"].as_str(),
            Some("18446744073709551615")
        );
        assert_eq!(
            value["maxResponseBytes"].as_str(),
            Some("18446744073709551614")
        );
        assert_eq!(value["maxWallTimeMs"].as_u64(), Some(u64::from(u32::MAX)));
        assert_eq!(
            value["maxConcurrentSockets"].as_u64(),
            Some(u64::from(u8::MAX))
        );
        assert_eq!(
            value["maxHintGroups"].as_u64(),
            Some(u64::from(u16::MAX - 1))
        );
        assert_eq!(value["maxWorkUnits"].as_str(), Some("18446744073709551613"));
    }

    #[test]
    fn dataset_json_preserves_manifest_root_and_u64_epoch_canonically() {
        let root = dataset_json_v1(&DatasetBindingV1::ManifestRoot { root: [0x5a; 32] });
        assert_eq!(root["kind"].as_str(), Some("manifest-root"));
        assert_eq!(
            root["rootHex"].as_str(),
            Some(hex::encode([0x5a; 32]).as_str())
        );

        let epoch = dataset_json_v1(&DatasetBindingV1::CatalogEpoch { epoch: u64::MAX });
        assert_eq!(epoch["kind"].as_str(), Some("catalog-epoch"));
        assert_eq!(epoch["epoch"].as_str(), Some("18446744073709551615"));
    }

    #[test]
    fn service_offer_json_exposes_only_the_arc_raw_key_fingerprint_for_arc() {
        let mut rng = rand_core::OsRng;
        let (_, public_key) = arc::setup_server(&mut rng);
        let public_key_bytes = public_key.to_bytes();
        let expected_fingerprint =
            hex::encode(arc_public_key_fingerprint_v1(&public_key_bytes).unwrap());
        let credential_key_id = vec![0x41; 16];
        let binding = CredentialKeyBindingV1::sign(
            CredentialKeyBindingClaimsV1 {
                provider_id: [0x11; 32],
                scope_id: [0x22; 32],
                offer_id: 7,
                scheme: AuthScheme::ArcV1Experimental,
                keyset_epoch: 1,
                entitlement_profile: 3,
                unit: CredentialUnitV1::Auth,
                amount: 1,
                presentation_limit: 2,
                not_before: 100,
                not_after: 1_000,
                credential_key_id: credential_key_id.clone(),
                verification_key: public_key_bytes.to_vec(),
            },
            &SigningKey::from_bytes(&[0x33; 32]),
        )
        .unwrap();
        let mut offer = ServiceOfferV1 {
            offer_id: 7,
            acquisition: AcquisitionMethod::Bolt11V1,
            free_mode: FreeModeV1::NotFree,
            free_quota: 0,
            free_window_seconds: 0,
            free_pow_difficulty_bits: 0,
            priority_class: 1,
            authorization: AuthScheme::ArcV1Experimental,
            verification: VerificationMode::ProviderLocal,
            deployment_status: DeploymentStatus::Experimental,
            price: PriceV1::MilliSatoshi(1_000),
            issuer_id: binding.issuer_id,
            key_id: credential_key_id,
            credential_binding: Some(binding),
            cashu_mint_manifest: None,
            endpoint: "https://issuer.invalid".into(),
            invoice_expiry_seconds: 60,
            claim_window_seconds: 60,
            minimum_credential_validity_seconds: 60,
            retired_policy_grace_seconds: 300,
            credential_count: 1,
            credential_presentation_limit: 2,
            privacy_leakage: PrivacyLeakageV1::NONE,
        };

        let arc_json = service_offer_json_v1(&offer);
        let arc_fingerprint = arc_json["arcVerificationKeyFingerprintHex"]
            .as_str()
            .unwrap();
        assert_eq!(arc_fingerprint, expected_fingerprint);
        assert_eq!(arc_fingerprint.len(), 64);
        assert!(arc_fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        assert_eq!(
            arc_json["batVerificationKeyFingerprintHex"].as_str(),
            Some("")
        );

        offer.authorization = AuthScheme::Bolt11DirectReceiptV1;
        let non_arc_json = service_offer_json_v1(&offer);
        assert_eq!(
            non_arc_json["arcVerificationKeyFingerprintHex"].as_str(),
            Some("")
        );
    }
}
