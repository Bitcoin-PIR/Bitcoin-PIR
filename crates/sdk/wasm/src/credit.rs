//! ARC credentials in the browser (docs/CREDITS.md "ARC parameters"):
//! blind credential requests for `POST /v2/credentials`, finalization of
//! the issuer's response, and `REQ_CREDIT_PRESENT` kind-2 payloads.
//!
//! Persistence is the caller's job and it matters: store
//! [`WasmArcCredentialRequest::secrets_bytes`] and
//! [`WasmArcCredentialRequest::request_bytes`] before paying (the issuer
//! answers one request per token), and store the credential bytes plus
//! [`WasmArcCredential::next_nonce`] before sending every payload (a
//! presentation whose nonce is reused is a double spend at the issuer).
//!
//! The logic lives in [`ArcRequestState`] and [`ArcCredentialState`], which
//! know nothing about JavaScript; the `Wasm*` types are the bindings.

use arc::group::{deserialize_element, deserialize_scalar, serialize_element, serialize_scalar};
use arc::presentation::PresentationState;
use arc::{
    create_credential_request, finalize_credential, make_presentation_state, present,
    ClientSecrets, Credential, CredentialRequest, CredentialResponse, ServerPublicKey,
};
use pir_credit::arc::{encode_presentations, presentation_context, request_context};
use wasm_bindgen::prelude::*;

/// `m1 ‖ m2 ‖ r1 ‖ r2`, four 32-byte scalars.
pub const ARC_SECRETS_LEN: usize = 4 * 32;
/// `m1 ‖ U ‖ U' ‖ X1`: one 32-byte scalar and three 33-byte points.
pub const ARC_CREDENTIAL_LEN: usize = 32 + 3 * 33;

/// A blinded credential request and the secrets that finish it.
pub struct ArcRequestState {
    epoch: u32,
    secrets: ClientSecrets,
    request: CredentialRequest,
}

impl ArcRequestState {
    pub fn new(epoch: u32) -> Result<Self, String> {
        let (secrets, request) =
            create_credential_request(&request_context(epoch), &mut rand_core::OsRng)
                .map_err(|e| format!("ARC credential request: {e}"))?;
        Ok(Self {
            epoch,
            secrets,
            request,
        })
    }

    pub fn from_bytes(epoch: u32, secrets: &[u8], request: &[u8]) -> Result<Self, String> {
        if secrets.len() != ARC_SECRETS_LEN {
            return Err(format!(
                "ARC secrets must be {ARC_SECRETS_LEN} bytes, got {}",
                secrets.len()
            ));
        }
        let scalar = |i: usize| {
            deserialize_scalar(&secrets[i * 32..(i + 1) * 32])
                .map_err(|e| format!("ARC secrets: {e}"))
        };
        let secrets = ClientSecrets {
            m1: scalar(0)?,
            m2: scalar(1)?,
            r1: scalar(2)?,
            r2: scalar(3)?,
        };
        let request = CredentialRequest::from_bytes(request)
            .map_err(|e| format!("ARC credential request: {e}"))?;
        Ok(Self {
            epoch,
            secrets,
            request,
        })
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    pub fn request_bytes(&self) -> Vec<u8> {
        self.request.to_bytes().to_vec()
    }

    pub fn secrets_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ARC_SECRETS_LEN);
        for scalar in [
            &self.secrets.m1,
            &self.secrets.m2,
            &self.secrets.r1,
            &self.secrets.r2,
        ] {
            out.extend_from_slice(&serialize_scalar(scalar));
        }
        out
    }

    /// Verify the issuer's response under the key it named and return the
    /// credential bytes.
    pub fn finalize(
        &self,
        issuer_public_key_hex: &str,
        response: &[u8],
    ) -> Result<Vec<u8>, String> {
        let pk = hex::decode(issuer_public_key_hex)
            .map_err(|e| format!("issuer public key: {e}"))
            .and_then(|bytes| {
                ServerPublicKey::from_bytes(&bytes).map_err(|e| format!("issuer public key: {e}"))
            })?;
        let response = CredentialResponse::from_bytes(response)
            .map_err(|e| format!("ARC credential response: {e}"))?;
        let credential = finalize_credential(&self.secrets, &pk, &self.request, &response)
            .map_err(|e| format!("ARC credential: {e}"))?;
        Ok(credential_to_bytes(&credential))
    }
}

fn credential_to_bytes(credential: &Credential) -> Vec<u8> {
    let mut out = Vec::with_capacity(ARC_CREDENTIAL_LEN);
    out.extend_from_slice(&serialize_scalar(&credential.m1));
    out.extend_from_slice(&serialize_element(&credential.u));
    out.extend_from_slice(&serialize_element(&credential.u_prime));
    out.extend_from_slice(&serialize_element(&credential.x1));
    out
}

fn credential_from_bytes(bytes: &[u8]) -> Result<Credential, String> {
    if bytes.len() != ARC_CREDENTIAL_LEN {
        return Err(format!(
            "ARC credential must be {ARC_CREDENTIAL_LEN} bytes, got {}",
            bytes.len()
        ));
    }
    let element = |range: std::ops::Range<usize>| {
        deserialize_element(&bytes[range]).map_err(|e| format!("ARC credential: {e}"))
    };
    Ok(Credential {
        m1: deserialize_scalar(&bytes[..32]).map_err(|e| format!("ARC credential: {e}"))?,
        u: element(32..65)?,
        u_prime: element(65..98)?,
        x1: element(98..131)?,
    })
}

/// A finished credential with its presentation counter.
pub struct ArcCredentialState {
    epoch: u32,
    state: PresentationState,
}

impl ArcCredentialState {
    pub fn new(
        credential: &[u8],
        epoch: u32,
        presentation_limit: u32,
        next_nonce: u32,
    ) -> Result<Self, String> {
        let credential = credential_from_bytes(credential)?;
        let mut state = make_presentation_state(
            credential,
            &presentation_context(epoch),
            u64::from(presentation_limit),
        );
        state.next_nonce = u64::from(next_nonce);
        Ok(Self { epoch, state })
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    pub fn presentation_limit(&self) -> u32 {
        u32::try_from(self.state.presentation_limit).unwrap_or(u32::MAX)
    }

    pub fn next_nonce(&self) -> u32 {
        u32::try_from(self.state.next_nonce).unwrap_or(u32::MAX)
    }

    pub fn remaining(&self) -> u32 {
        u32::try_from(
            self.state
                .presentation_limit
                .saturating_sub(self.state.next_nonce),
        )
        .unwrap_or(u32::MAX)
    }

    /// A kind-2 payload of `count` presentations; the nonce counter advances
    /// only when the whole payload was built.
    pub fn present(&mut self, count: u32) -> Result<Vec<u8>, String> {
        if count == 0 {
            return Err("present: count must be at least 1".to_owned());
        }
        if count > self.remaining() {
            return Err(format!(
                "present: {count} presentations requested, {} left on this credential",
                self.remaining()
            ));
        }
        let mut presentations = Vec::with_capacity(count as usize);
        let mut state = self.state.clone();
        for _ in 0..count {
            let (next, _nonce, presentation) =
                present(&state, &mut rand_core::OsRng).map_err(|e| format!("ARC present: {e}"))?;
            state = next;
            presentations.push(presentation.to_bytes());
        }
        let payload = encode_presentations(self.epoch, &presentations)
            .map_err(|e| format!("ARC payload: {e}"))?;
        self.state = state;
        Ok(payload)
    }
}

fn js(error: String) -> JsError {
    JsError::new(&error)
}

/// JavaScript view of [`ArcRequestState`].
#[wasm_bindgen]
pub struct WasmArcCredentialRequest {
    inner: ArcRequestState,
}

#[wasm_bindgen]
impl WasmArcCredentialRequest {
    /// A fresh request for `epoch` (the issuer's current epoch from
    /// `GET /v2/info`).
    #[wasm_bindgen(constructor)]
    pub fn new(epoch: u32) -> Result<WasmArcCredentialRequest, JsError> {
        Ok(Self {
            inner: ArcRequestState::new(epoch).map_err(js)?,
        })
    }

    /// Restore a request persisted before paying.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(
        epoch: u32,
        secrets: &[u8],
        request: &[u8],
    ) -> Result<WasmArcCredentialRequest, JsError> {
        Ok(Self {
            inner: ArcRequestState::from_bytes(epoch, secrets, request).map_err(js)?,
        })
    }

    pub fn epoch(&self) -> u32 {
        self.inner.epoch()
    }

    /// Bytes to send as `request_hex` in `POST /v2/credentials`.
    #[wasm_bindgen(js_name = requestBytes)]
    pub fn request_bytes(&self) -> Vec<u8> {
        self.inner.request_bytes()
    }

    /// Secrets to persist next to the request bytes.
    #[wasm_bindgen(js_name = secretsBytes)]
    pub fn secrets_bytes(&self) -> Vec<u8> {
        self.inner.secrets_bytes()
    }

    /// Finish with the issuer's answer (`response_hex` decoded, and the
    /// `issuer_public_key_hex` it named): verifies the issuance proof and
    /// returns the credential bytes to persist.
    pub fn finalize(
        &self,
        issuer_public_key_hex: &str,
        response: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        self.inner
            .finalize(issuer_public_key_hex, response)
            .map_err(js)
    }
}

/// JavaScript view of [`ArcCredentialState`].
#[wasm_bindgen]
pub struct WasmArcCredential {
    inner: ArcCredentialState,
}

#[wasm_bindgen]
impl WasmArcCredential {
    /// `credential` from [`WasmArcCredentialRequest::finalize`], the epoch
    /// and presentation limit the issuer named, and the persisted
    /// `next_nonce` (0 for a fresh credential).
    #[wasm_bindgen(constructor)]
    pub fn new(
        credential: &[u8],
        epoch: u32,
        presentation_limit: u32,
        next_nonce: u32,
    ) -> Result<WasmArcCredential, JsError> {
        Ok(Self {
            inner: ArcCredentialState::new(credential, epoch, presentation_limit, next_nonce)
                .map_err(js)?,
        })
    }

    pub fn epoch(&self) -> u32 {
        self.inner.epoch()
    }

    #[wasm_bindgen(js_name = presentationLimit)]
    pub fn presentation_limit(&self) -> u32 {
        self.inner.presentation_limit()
    }

    /// Persist this after every [`Self::present`], before sending the payload.
    #[wasm_bindgen(js_name = nextNonce)]
    pub fn next_nonce(&self) -> u32 {
        self.inner.next_nonce()
    }

    /// Presentations (credits) left.
    pub fn remaining(&self) -> u32 {
        self.inner.remaining()
    }

    /// A `REQ_CREDIT_PRESENT` kind-2 payload of `count` presentations,
    /// advancing the nonce counter. Fails without consuming anything when
    /// fewer than `count` remain.
    pub fn present(&mut self, count: u32) -> Result<Vec<u8>, JsError> {
        self.inner.present(count).map_err(js)
    }
}

/// `{ gasAdded, gasBalance }` for the `presentCredits` wrappers.
pub(crate) fn credit_receipt_to_js(receipt: pir_sdk_client::credits::CreditReceipt) -> JsValue {
    let object = js_sys::Object::new();
    let _ = js_sys::Reflect::set(
        &object,
        &JsValue::from_str("gasAdded"),
        &JsValue::from_f64(receipt.gas_added as f64),
    );
    let _ = js_sys::Reflect::set(
        &object,
        &JsValue::from_str("gasBalance"),
        &JsValue::from_f64(receipt.gas_balance as f64),
    );
    object.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny issuer for the round trip (the real one is the cashier).
    fn issuer() -> (arc::ServerPrivateKey, ServerPublicKey) {
        arc::setup_server(&mut rand_core::OsRng)
    }

    #[test]
    fn request_secrets_and_credential_bytes_round_trip() {
        let (sk, pk) = issuer();
        let epoch = 231;
        let request = ArcRequestState::new(epoch).unwrap();
        let secrets = request.secrets_bytes();
        let request_bytes = request.request_bytes();
        assert_eq!(secrets.len(), ARC_SECRETS_LEN);
        assert_eq!(request_bytes.len(), CredentialRequest::SIZE);
        let restored = ArcRequestState::from_bytes(epoch, &secrets, &request_bytes).unwrap();
        assert_eq!(restored.secrets_bytes(), secrets);
        assert_eq!(restored.request_bytes(), request_bytes);
        assert!(ArcRequestState::from_bytes(epoch, &secrets[1..], &request_bytes).is_err());
        assert!(ArcRequestState::from_bytes(epoch, &secrets, &request_bytes[1..]).is_err());

        let response = arc::create_credential_response(
            &sk,
            &pk,
            &CredentialRequest::from_bytes(&request_bytes).unwrap(),
            &mut rand_core::OsRng,
        )
        .unwrap();
        let pk_hex = hex::encode(pk.to_bytes());
        let credential = restored.finalize(&pk_hex, &response.to_bytes()).unwrap();
        assert_eq!(credential.len(), ARC_CREDENTIAL_LEN);
        // Another issuer's key does not finish this request.
        let (_, other_pk) = issuer();
        assert!(restored
            .finalize(&hex::encode(other_pk.to_bytes()), &response.to_bytes())
            .is_err());
        assert!(restored.finalize("zz", &response.to_bytes()).is_err());
        assert!(restored
            .finalize(&pk_hex, &response.to_bytes()[1..])
            .is_err());

        let mut holder = ArcCredentialState::new(&credential, epoch, 4, 0).unwrap();
        assert_eq!(holder.remaining(), 4);
        assert_eq!(holder.presentation_limit(), 4);
        let payload = holder.present(3).unwrap();
        assert_eq!(holder.next_nonce(), 3);
        assert_eq!(holder.remaining(), 1);
        let (decoded_epoch, presentations) =
            pir_credit::arc::decode_presentations(&payload).unwrap();
        assert_eq!(decoded_epoch, epoch);
        assert_eq!(presentations.len(), 3);
        for presentation in &presentations {
            let p = arc::Presentation::from_bytes(presentation, 4).unwrap();
            arc::verify_presentation(
                &sk,
                &pk,
                &request_context(epoch),
                &presentation_context(epoch),
                &p,
                4,
            )
            .unwrap();
        }
        // Too many: nothing consumed.
        assert!(holder.present(2).is_err());
        assert_eq!(holder.next_nonce(), 3);
        assert!(holder.present(0).is_err());
        holder.present(1).unwrap();
        assert_eq!(holder.remaining(), 0);
        // Restoring at a persisted nonce continues, never repeats.
        let resumed = ArcCredentialState::new(&credential, epoch, 4, 2).unwrap();
        assert_eq!(resumed.remaining(), 2);
        assert!(ArcCredentialState::new(&credential[..100], epoch, 4, 0).is_err());
    }
}
