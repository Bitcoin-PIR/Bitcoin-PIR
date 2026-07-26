//! WASM bindings for ARC (Anonymous Rate-limited Credentials).
//!
//! Exposes credential presentation to the browser so the web frontend can
//! attach ARC proofs to PIR queries without native code.

use arc::group::{deserialize_element, deserialize_scalar, serialize_element, serialize_scalar};
use arc::{
    create_credential_request, finalize_credential, make_presentation_state, present,
    ClientSecrets, Credential, CredentialRequest, CredentialResponse, PresentationState,
    ServerPublicKey,
};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

const ARC_VAULT_STATE_MAGIC_V1: &[u8; 8] = b"BPIRARC1";
const REVIEWED_ARC_STATE_LEN_V1: usize = 1 + 32 + 32 + 8 + 8 + 32 + (3 * 33);
const CREDENTIAL_PRESENTATION_CONTEXT_DOMAIN: &[u8] =
    pir_service_protocol::CREDENTIAL_PRESENTATION_CONTEXT_DOMAIN;

#[derive(Clone, Copy)]
struct ReviewedArcBindingStateV1 {
    binding_digest: [u8; 32],
    public_key_fingerprint: [u8; 32],
}

/// Opaque handle wrapping an ARC `PresentationState` + `Credential`.
///
/// The credential is obtained from the payment service as a byte blob
/// (see `from_credential_bytes`). The presentation state is created
/// client-side with a `presentation_context` (typically a random session
/// nonce) and a `limit` (the max number of queries this credential allows).
///
/// Each call to `present()` bumps the internal nonce counter and returns
/// the wire-format presentation bytes to send to the server via
/// `REQ_CREDENTIAL_PRESENT`.
#[wasm_bindgen]
pub struct WasmArcPresentationState {
    state: PresentationState,
    reviewed_binding: Option<ReviewedArcBindingStateV1>,
}

#[wasm_bindgen]
impl WasmArcPresentationState {
    /// Deserialize a credential (received from the payment service) and
    /// initialize presentation state.
    ///
    /// `credential_bytes`: 131-byte blob encoding `(m1: 32B, u: 33B, u_prime: 33B, x1: 33B)`.
    /// `presentation_context`: arbitrary bytes scoping the tag namespace (e.g., a fresh random 32B session ID).
    /// `limit`: maximum number of queries this credential authorizes.
    #[wasm_bindgen(constructor)]
    pub fn new(
        credential_bytes: &[u8],
        presentation_context: &[u8],
        limit: u64,
    ) -> Result<WasmArcPresentationState, JsError> {
        if credential_bytes.len() != 131 {
            return Err(JsError::new(&format!(
                "credential_bytes must be 131 bytes, got {}",
                credential_bytes.len()
            )));
        }
        let m1 = deserialize_scalar(&credential_bytes[..32])
            .map_err(|_| JsError::new("invalid m1 scalar"))?;
        let u = deserialize_element(&credential_bytes[32..65])
            .map_err(|e| JsError::new(&format!("invalid u: {}", e)))?;
        let u_prime = deserialize_element(&credential_bytes[65..98])
            .map_err(|e| JsError::new(&format!("invalid u_prime: {}", e)))?;
        let x1 = deserialize_element(&credential_bytes[98..131])
            .map_err(|e| JsError::new(&format!("invalid x1: {}", e)))?;

        let credential = Credential { m1, u, u_prime, x1 };
        let state = make_presentation_state(credential, presentation_context, limit);
        Ok(WasmArcPresentationState {
            state,
            reviewed_binding: None,
        })
    }

    /// Produce the next presentation.
    ///
    /// Returns the wire-format presentation bytes (to send to the server in
    /// `REQ_CREDENTIAL_PRESENT`), or throws if the credential is exhausted.
    pub fn present(&mut self) -> Result<Vec<u8>, JsError> {
        if self.reviewed_binding.is_some() {
            return Err(JsError::new(
                "reviewed ARC state requires prepare_presentation and durable successor persistence",
            ));
        }
        let mut rng = rand_core::OsRng;
        let (new_state, _nonce, presentation) = present(&self.state, &mut rng)
            .map_err(|e| JsError::new(&format!("ARC present failed: {}", e)))?;
        self.state = new_state;
        Ok(presentation.to_bytes())
    }

    /// Prepare a successor and withhold its presentation until the browser
    /// vault has durably stored `successor_state_bytes()`.
    pub fn prepare_presentation(&self) -> Result<WasmPreparedArcPresentationV1, JsError> {
        let mut rng = rand_core::OsRng;
        let (successor, _nonce, presentation) = present(&self.state, &mut rng)
            .map_err(|e| JsError::new(&format!("ARC present failed: {}", e)))?;
        Ok(WasmPreparedArcPresentationV1 {
            successor: WasmArcPresentationState {
                state: successor,
                reviewed_binding: self.reviewed_binding,
            },
            presentation: Some(presentation.to_bytes()),
        })
    }

    /// How many presentations remain before exhaustion.
    pub fn remaining(&self) -> u64 {
        self.state
            .presentation_limit
            .saturating_sub(self.state.next_nonce)
    }

    /// The presentation limit for this credential.
    pub fn limit(&self) -> u64 {
        self.state.presentation_limit
    }

    /// The current nonce (how many presentations already made).
    pub fn nonce(&self) -> u64 {
        self.state.next_nonce
    }

    /// Serialize the full state for encrypted provider-bound persistence.
    ///
    /// Format: `[credential: 131B][pres_ctx_len: 4B LE][pres_ctx][next_nonce: 8B LE][limit: 8B LE]`
    pub fn serialize(&self) -> Vec<u8> {
        if let Some(binding) = self.reviewed_binding {
            let mut out =
                Vec::with_capacity(ARC_VAULT_STATE_MAGIC_V1.len() + REVIEWED_ARC_STATE_LEN_V1);
            out.extend_from_slice(ARC_VAULT_STATE_MAGIC_V1);
            out.push(1);
            out.extend_from_slice(&binding.binding_digest);
            out.extend_from_slice(&binding.public_key_fingerprint);
            out.extend_from_slice(&self.state.presentation_limit.to_le_bytes());
            out.extend_from_slice(&self.state.next_nonce.to_le_bytes());
            out.extend_from_slice(&serialize_scalar(&self.state.credential.m1));
            out.extend_from_slice(&serialize_element(&self.state.credential.u));
            out.extend_from_slice(&serialize_element(&self.state.credential.u_prime));
            out.extend_from_slice(&serialize_element(&self.state.credential.x1));
            return out;
        }
        let cred_bytes = serialize_credential(&self.state.credential);
        let ctx = &self.state.presentation_context;
        let mut out = Vec::with_capacity(131 + 4 + ctx.len() + 8 + 8);
        out.extend_from_slice(&cred_bytes);
        out.extend_from_slice(&(ctx.len() as u32).to_le_bytes());
        out.extend_from_slice(ctx);
        out.extend_from_slice(&self.state.next_nonce.to_le_bytes());
        out.extend_from_slice(&self.state.presentation_limit.to_le_bytes());
        out
    }

    /// Deserialize state previously produced by `serialize()`.
    pub fn deserialize(bytes: &[u8]) -> Result<WasmArcPresentationState, JsError> {
        if bytes.starts_with(ARC_VAULT_STATE_MAGIC_V1) {
            return deserialize_reviewed_arc_state_v1(&bytes[ARC_VAULT_STATE_MAGIC_V1.len()..]);
        }
        if bytes.len() < 131 + 4 {
            return Err(JsError::new("serialized state too short"));
        }
        let credential_bytes = &bytes[..131];
        let ctx_len = u32::from_le_bytes(bytes[131..135].try_into().unwrap()) as usize;
        if bytes.len() < 131 + 4 + ctx_len + 8 + 8 {
            return Err(JsError::new("serialized state truncated"));
        }
        let pres_ctx = bytes[135..135 + ctx_len].to_vec();
        let off = 135 + ctx_len;
        let next_nonce = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
        let limit = u64::from_le_bytes(bytes[off + 8..off + 16].try_into().unwrap());

        let m1 =
            deserialize_scalar(&credential_bytes[..32]).map_err(|_| JsError::new("invalid m1"))?;
        let u = deserialize_element(&credential_bytes[32..65])
            .map_err(|e| JsError::new(&format!("invalid u: {}", e)))?;
        let u_prime = deserialize_element(&credential_bytes[65..98])
            .map_err(|e| JsError::new(&format!("invalid u_prime: {}", e)))?;
        let x1 = deserialize_element(&credential_bytes[98..131])
            .map_err(|e| JsError::new(&format!("invalid x1: {}", e)))?;

        let credential = Credential { m1, u, u_prime, x1 };
        // Create state then manually set nonce to restored value
        let mut state = make_presentation_state(credential, &pres_ctx, limit);
        state.next_nonce = next_nonce;
        Ok(WasmArcPresentationState {
            state,
            reviewed_binding: None,
        })
    }
}

/// ARC presentation transition whose wire bytes remain inaccessible until
/// the caller explicitly acknowledges durable successor-state persistence.
#[wasm_bindgen]
pub struct WasmPreparedArcPresentationV1 {
    successor: WasmArcPresentationState,
    presentation: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl WasmPreparedArcPresentationV1 {
    pub fn successor_state_bytes(&self) -> Vec<u8> {
        self.successor.serialize()
    }

    pub fn remaining(&self) -> u64 {
        self.successor.remaining()
    }

    /// The strict Web vault calls this only after its IndexedDB transaction
    /// commits. Consuming the bytes prevents a second release from one handle.
    pub fn release_after_persisted(&mut self) -> Result<Vec<u8>, JsError> {
        self.presentation
            .take()
            .ok_or_else(|| JsError::new("ARC presentation was already released"))
    }
}

fn deserialize_reviewed_arc_state_v1(bytes: &[u8]) -> Result<WasmArcPresentationState, JsError> {
    if bytes.len() != REVIEWED_ARC_STATE_LEN_V1 || bytes[0] != 1 {
        return Err(JsError::new(
            "invalid reviewed ARC client state length or version",
        ));
    }
    let binding_digest: [u8; 32] = bytes[1..33]
        .try_into()
        .map_err(|_| JsError::new("invalid ARC binding digest"))?;
    let public_key_fingerprint: [u8; 32] = bytes[33..65]
        .try_into()
        .map_err(|_| JsError::new("invalid ARC public-key fingerprint"))?;
    if binding_digest.iter().all(|byte| *byte == 0)
        || public_key_fingerprint.iter().all(|byte| *byte == 0)
    {
        return Err(JsError::new(
            "reviewed ARC binding identifiers must be non-zero",
        ));
    }
    let presentation_limit = u64::from_le_bytes(
        bytes[65..73]
            .try_into()
            .map_err(|_| JsError::new("invalid ARC presentation limit"))?,
    );
    let next_nonce = u64::from_le_bytes(
        bytes[73..81]
            .try_into()
            .map_err(|_| JsError::new("invalid ARC next nonce"))?,
    );
    if !(2..=1024).contains(&presentation_limit) || next_nonce > presentation_limit {
        return Err(JsError::new("reviewed ARC nonce/limit state is invalid"));
    }
    let m1 =
        deserialize_scalar(&bytes[81..113]).map_err(|_| JsError::new("invalid reviewed ARC m1"))?;
    let u = deserialize_element(&bytes[113..146])
        .map_err(|_| JsError::new("invalid reviewed ARC u"))?;
    let u_prime = deserialize_element(&bytes[146..179])
        .map_err(|_| JsError::new("invalid reviewed ARC u_prime"))?;
    let x1 = deserialize_element(&bytes[179..212])
        .map_err(|_| JsError::new("invalid reviewed ARC x1"))?;
    let mut context_hasher = Sha256::new();
    context_hasher.update(CREDENTIAL_PRESENTATION_CONTEXT_DOMAIN);
    context_hasher.update(binding_digest);
    let presentation_context: [u8; 32] = context_hasher.finalize().into();
    let value = WasmArcPresentationState {
        state: PresentationState {
            credential: Credential { m1, u, u_prime, x1 },
            presentation_context: presentation_context.to_vec(),
            next_nonce,
            presentation_limit,
        },
        reviewed_binding: Some(ReviewedArcBindingStateV1 {
            binding_digest,
            public_key_fingerprint,
        }),
    };
    let encoded = value.serialize();
    if encoded[ARC_VAULT_STATE_MAGIC_V1.len()..] != *bytes {
        return Err(JsError::new("reviewed ARC state is non-canonical"));
    }
    Ok(value)
}

/// Opaque handle for the client side of ARC issuance ("obtain" leg).
///
/// Holds the per-request `ClientSecrets` (the blinding factors) **inside
/// WASM** so they never cross into JS, alongside the `CredentialRequest`.
/// Lifecycle:
///
/// 1. `new(request_context)` — build a blinded request (fresh `m1`, etc.).
/// 2. `request_bytes()` — 226-byte body to POST to the issuer
///    (`/dev/arc/issue`).
/// 3. `finalize(pubkey, response)` — combine the issuer's 454-byte response
///    with the held secrets into a 131-byte credential, ready for
///    [`WasmArcPresentationState::new`].
///
/// `request_context` MUST match the value the verifier expects
/// (`pir_runtime_core::arc_verifier::DEFAULT_REQUEST_CONTEXT` =
/// `b"bitcoin-pir-v1"`); the issuer's `m2` is re-derived from it at
/// presentation time.
#[wasm_bindgen]
pub struct WasmArcCredentialRequest {
    secrets: ClientSecrets,
    request: CredentialRequest,
}

#[wasm_bindgen]
impl WasmArcCredentialRequest {
    /// Build a fresh blinded credential request for `request_context`.
    #[wasm_bindgen(constructor)]
    pub fn new(request_context: &[u8]) -> Result<WasmArcCredentialRequest, JsError> {
        let mut rng = rand_core::OsRng;
        let (secrets, request) = create_credential_request(request_context, &mut rng)
            .map_err(|e| JsError::new(&format!("create_credential_request failed: {}", e)))?;
        Ok(WasmArcCredentialRequest { secrets, request })
    }

    /// The 226-byte `CredentialRequest` to POST to the issuer.
    pub fn request_bytes(&self) -> Vec<u8> {
        self.request.to_bytes().to_vec()
    }

    /// Finalize: combine the issuer's response with the held secrets.
    ///
    /// `pubkey_bytes`: 99-byte issuer `ServerPublicKey` (from
    /// `GET /dev/arc/pubkey`).
    /// `response_bytes`: 454-byte `CredentialResponse` (from
    /// `POST /dev/arc/issue`).
    ///
    /// Returns the 131-byte credential blob for
    /// [`WasmArcPresentationState::new`]. Throws if the response proof is
    /// invalid (e.g. wrong issuer key).
    pub fn finalize(&self, pubkey_bytes: &[u8], response_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
        let pk = ServerPublicKey::from_bytes(pubkey_bytes)
            .map_err(|e| JsError::new(&format!("invalid issuer pubkey: {}", e)))?;
        let response = CredentialResponse::from_bytes(response_bytes)
            .map_err(|e| JsError::new(&format!("invalid credential response: {}", e)))?;
        let credential = finalize_credential(&self.secrets, &pk, &self.request, &response)
            .map_err(|e| JsError::new(&format!("finalize_credential failed: {}", e)))?;
        Ok(serialize_credential(&credential).to_vec())
    }
}

/// Serialize a credential to 131 bytes: `m1(32) || u(33) || u_prime(33) || x1(33)`.
fn serialize_credential(cred: &Credential) -> [u8; 131] {
    let mut out = [0u8; 131];
    out[..32].copy_from_slice(&serialize_scalar(&cred.m1));
    out[32..65].copy_from_slice(&serialize_element(&cred.u));
    out[65..98].copy_from_slice(&serialize_element(&cred.u_prime));
    out[98..131].copy_from_slice(&serialize_element(&cred.x1));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST_CONTEXT: &[u8] = b"bitcoin-pir-v1";

    #[test]
    fn request_bytes_is_226() {
        let req = WasmArcCredentialRequest::new(REQUEST_CONTEXT)
            .ok()
            .expect("new request");
        assert_eq!(req.request_bytes().len(), 226);
    }

    /// Full obtain leg in-process: request → (issuer responds) → finalize →
    /// 131-byte credential → presentation state → present. Mirrors the
    /// browser path with the HTTP hop replaced by a direct issuer call.
    #[test]
    fn wasm_obtain_leg_request_issue_finalize_present() {
        let mut rng = rand_core::OsRng;
        let (sk, pk) = arc::setup_server(&mut rng);

        // Client builds the request via the WASM binding.
        let req = WasmArcCredentialRequest::new(REQUEST_CONTEXT)
            .ok()
            .expect("new request");
        let req_bytes = req.request_bytes();
        assert_eq!(req_bytes.len(), 226);

        // Issuer side (what dev-issuer does).
        let parsed = CredentialRequest::from_bytes(&req_bytes).expect("parse request");
        let response = arc::create_credential_response(&sk, &pk, &parsed, &mut rng).expect("issue");
        let resp_bytes = response.to_bytes();
        assert_eq!(resp_bytes.len(), 454);

        // Client finalizes via the WASM binding.
        let pk_bytes = pk.to_bytes();
        let cred = req.finalize(&pk_bytes, &resp_bytes).ok().expect("finalize");
        assert_eq!(cred.len(), 131);

        // Feed into the presentation-state binding and present once.
        let mut state = WasmArcPresentationState::new(&cred, b"wasm-sess", 16)
            .ok()
            .expect("presentation state");
        assert_eq!(state.remaining(), 16);
        let presentation = state.present().ok().expect("present");
        assert!(!presentation.is_empty());
        assert_eq!(state.remaining(), 15);
    }

    /// Finalizing against the WRONG issuer pubkey must fail (response proof
    /// is bound to the issuing key).
    ///
    /// NOTE: we assert the underlying `arc::finalize_credential` rejection
    /// rather than calling `WasmArcCredentialRequest::finalize` directly,
    /// because that wrapper's error path constructs a `JsError`, which traps
    /// ("cannot call wasm-bindgen imported functions") on non-wasm test
    /// targets. The wrapper simply maps this `Err` to that `JsError`.
    #[test]
    fn finalize_rejects_wrong_pubkey() {
        let mut rng = rand_core::OsRng;
        let (sk, pk) = arc::setup_server(&mut rng);
        let (_other_sk, other_pk) = arc::setup_server(&mut rng);

        let (secrets, request) =
            create_credential_request(REQUEST_CONTEXT, &mut rng).expect("request");
        let response =
            arc::create_credential_response(&sk, &pk, &request, &mut rng).expect("issue");

        // Finalize with a different pubkey → must error at the arc layer.
        let result = finalize_credential(&secrets, &other_pk, &request, &response);
        assert!(result.is_err(), "finalize accepted the wrong issuer pubkey");
    }
}
