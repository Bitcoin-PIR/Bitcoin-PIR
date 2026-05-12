//! WASM bindings for ARC (Anonymous Rate-limited Credentials).
//!
//! Exposes credential presentation to the browser so the web frontend can
//! attach ARC proofs to PIR queries without native code.

use arc::group::{deserialize_element, deserialize_scalar, serialize_element, serialize_scalar};
use arc::{
    make_presentation_state, present, Credential, Presentation, PresentationState,
};
use wasm_bindgen::prelude::*;

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
        Ok(WasmArcPresentationState { state })
    }

    /// Produce the next presentation.
    ///
    /// Returns the wire-format presentation bytes (to send to the server in
    /// `REQ_CREDENTIAL_PRESENT`), or throws if the credential is exhausted.
    pub fn present(&mut self) -> Result<Vec<u8>, JsError> {
        let mut rng = rand_core::OsRng;
        let (new_state, _nonce, presentation) = present(&self.state, &mut rng)
            .map_err(|e| JsError::new(&format!("ARC present failed: {}", e)))?;
        self.state = new_state;
        Ok(presentation.to_bytes())
    }

    /// How many presentations remain before exhaustion.
    pub fn remaining(&self) -> u64 {
        self.state.presentation_limit.saturating_sub(self.state.next_nonce)
    }

    /// The presentation limit for this credential.
    pub fn limit(&self) -> u64 {
        self.state.presentation_limit
    }

    /// The current nonce (how many presentations already made).
    pub fn nonce(&self) -> u64 {
        self.state.next_nonce
    }

    /// Serialize the full state for persistence (e.g., localStorage).
    ///
    /// Format: `[credential: 131B][pres_ctx_len: 4B LE][pres_ctx][next_nonce: 8B LE][limit: 8B LE]`
    pub fn serialize(&self) -> Vec<u8> {
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

        let m1 = deserialize_scalar(&credential_bytes[..32])
            .map_err(|_| JsError::new("invalid m1"))?;
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
        Ok(WasmArcPresentationState { state })
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
