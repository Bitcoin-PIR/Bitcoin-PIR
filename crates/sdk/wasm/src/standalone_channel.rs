//! Same-socket secure-channel bridge for browser-native PIR backends.
//!
//! OnionPIR's browser client owns a C++/SEAL WASM instance and therefore
//! cannot use `WasmOnionClient`. This bridge keeps the attestation nonce,
//! X25519 secret, HKDF and AEAD sequence state in Rust/WASM while allowing
//! TypeScript to send the resulting frames over the exact WebSocket used by
//! the SEAL protocol. No channel key or ephemeral secret crosses into JS.

use js_sys::Uint8Array;
use pir_channel::{ClientHandshake, Direction, Session};
use wasm_bindgen::prelude::*;

use crate::client::WasmAttestVerification;

const REQ_ATTEST: u8 = 0x05;
const REQ_HANDSHAKE: u8 = 0x06;
const RESP_HANDSHAKE: u8 = 0x06;
const RESP_ERROR: u8 = 0xff;

#[wasm_bindgen]
pub struct WasmStandaloneSecureChannelV1 {
    handshake: Option<ClientHandshake>,
    session: Option<Session>,
    attest_nonce: [u8; 32],
}

#[wasm_bindgen]
impl WasmStandaloneSecureChannelV1 {
    /// Create one one-shot, attestation-bound channel attempt.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<Self, JsError> {
        let mut eph_seed = [0u8; 32];
        let mut attest_random = [0u8; 32];
        let mut handshake_nonce = [0u8; 32];
        getrandom::getrandom(&mut eph_seed)
            .map_err(|error| JsError::new(&format!("channel entropy: {error}")))?;
        getrandom::getrandom(&mut attest_random)
            .map_err(|error| JsError::new(&format!("attestation entropy: {error}")))?;
        getrandom::getrandom(&mut handshake_nonce)
            .map_err(|error| JsError::new(&format!("handshake entropy: {error}")))?;

        let handshake = ClientHandshake::new(eph_seed, handshake_nonce);
        let attest_nonce =
            pir_core::attest::derive_attest_nonce(handshake.client_eph_pub(), attest_random);
        Ok(Self {
            handshake: Some(handshake),
            session: None,
            attest_nonce,
        })
    }

    /// Canonical cleartext `REQ_ATTEST` frame for this channel attempt.
    #[wasm_bindgen(js_name = attestRequest)]
    pub fn attest_request(&self) -> Vec<u8> {
        encode_frame(REQ_ATTEST, &self.attest_nonce)
    }

    /// Verify a same-socket `RESP_ATTEST` with the nonce bound to our hidden
    /// X25519 ephemeral key. The returned handle retains all existing AMD
    /// chain, binary-pin and policy verification methods.
    #[wasm_bindgen(js_name = verifyAttestation)]
    pub fn verify_attestation(
        &self,
        response_frame: &[u8],
    ) -> Result<WasmAttestVerification, JsError> {
        let payload = exact_payload(response_frame, "attestation response")?;
        let verified =
            pir_sdk_client::attest::verify_attest_response(payload, self.attest_nonce)
                .map_err(|error| JsError::new(&format!("attestation verification: {error}")))?;
        Ok(WasmAttestVerification::from_inner(verified))
    }

    /// Canonical cleartext `REQ_HANDSHAKE` using the same hidden ephemeral
    /// key committed by [`Self::attest_request`].
    #[wasm_bindgen(js_name = handshakeRequest)]
    pub fn handshake_request(&self) -> Result<Vec<u8>, JsError> {
        let handshake = self
            .handshake
            .as_ref()
            .ok_or_else(|| JsError::new("secure-channel handshake is no longer available"))?;
        let mut body = Vec::with_capacity(64);
        body.extend_from_slice(&handshake.client_eph_pub());
        body.extend_from_slice(&handshake.nonce());
        Ok(encode_frame(REQ_HANDSHAKE, &body))
    }

    /// Consume the handshake secret and install the AEAD session.
    #[wasm_bindgen(js_name = completeHandshake)]
    pub fn complete_handshake(
        &mut self,
        response_frame: &[u8],
        server_static_pub: &[u8],
    ) -> Result<(), JsError> {
        if self.session.is_some() {
            return Err(JsError::new("secure-channel handshake already completed"));
        }
        let server_static_pub: [u8; 32] = server_static_pub
            .try_into()
            .map_err(|_| JsError::new("server static public key must be exactly 32 bytes"))?;
        if server_static_pub.iter().all(|byte| *byte == 0) {
            return Err(JsError::new("server static public key is all zero"));
        }
        let payload = exact_payload(response_frame, "handshake response")?;
        if payload.first() == Some(&RESP_ERROR) {
            return Err(JsError::new(&format!(
                "server rejected secure-channel handshake: {}",
                String::from_utf8_lossy(&payload[1..])
            )));
        }
        if payload.len() != 33 || payload[0] != RESP_HANDSHAKE {
            return Err(JsError::new(
                "non-canonical secure-channel handshake response",
            ));
        }
        let server_ephemeral_pub: [u8; 32] = payload[1..]
            .try_into()
            .map_err(|_| JsError::new("invalid server ephemeral public key"))?;
        if server_ephemeral_pub.iter().all(|byte| *byte == 0) {
            return Err(JsError::new("server ephemeral public key is all zero"));
        }
        let handshake = self
            .handshake
            .take()
            .ok_or_else(|| JsError::new("secure-channel handshake is no longer available"))?;
        self.session =
            Some(handshake.complete_handshake(&server_static_pub, &server_ephemeral_pub));
        Ok(())
    }

    #[wasm_bindgen(getter, js_name = established)]
    pub fn established(&self) -> bool {
        self.session.is_some()
    }

    /// Seal one complete length-prefixed BitcoinPIR frame.
    #[wasm_bindgen(js_name = sealFrame)]
    pub fn seal_frame(&mut self, frame: &[u8]) -> Result<Vec<u8>, JsError> {
        let payload = exact_payload(frame, "outgoing frame")?;
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| JsError::new("secure channel is not established"))?;
        let sealed = session
            .seal(Direction::ClientToServer, payload)
            .map_err(|error| JsError::new(&format!("secure-channel seal: {error}")))?;
        Ok(prefix_payload(&sealed))
    }

    /// Authenticate and open one complete length-prefixed server frame.
    #[wasm_bindgen(js_name = openFrame)]
    pub fn open_frame(&mut self, frame: &[u8]) -> Result<Vec<u8>, JsError> {
        let payload = exact_payload(frame, "incoming frame")?;
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| JsError::new("secure channel is not established"))?;
        let opened = session
            .open(Direction::ServerToClient, payload)
            .map_err(|error| JsError::new(&format!("secure-channel open: {error}")))?;
        Ok(prefix_payload(&opened))
    }

    /// Non-secret exporter used by service authorization transcript binding.
    #[wasm_bindgen(js_name = serviceAuthorizationExporterV1)]
    pub fn service_authorization_exporter_v1(&self) -> Result<Uint8Array, JsError> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| JsError::new("secure channel is not established"))?;
        Ok(Uint8Array::from(
            &session.service_authorization_exporter_v1()[..],
        ))
    }
}

fn encode_frame(opcode: u8, body: &[u8]) -> Vec<u8> {
    let payload_len = 1usize
        .checked_add(body.len())
        .and_then(|len| u32::try_from(len).ok())
        .expect("bounded protocol body must fit u32");
    let mut frame = Vec::with_capacity(4 + payload_len as usize);
    frame.extend_from_slice(&payload_len.to_le_bytes());
    frame.push(opcode);
    frame.extend_from_slice(body);
    frame
}

fn prefix_payload(payload: &[u8]) -> Vec<u8> {
    let payload_len = u32::try_from(payload.len()).expect("protocol payload must fit u32");
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&payload_len.to_le_bytes());
    frame.extend_from_slice(payload);
    frame
}

pub(crate) fn exact_payload<'a>(frame: &'a [u8], label: &str) -> Result<&'a [u8], JsError> {
    if frame.len() < 4 {
        return Err(JsError::new(&format!(
            "{label} is shorter than its length prefix"
        )));
    }
    let declared = u32::from_le_bytes(frame[..4].try_into().expect("checked length")) as usize;
    if declared == 0 || declared != frame.len() - 4 {
        return Err(JsError::new(&format!(
            "{label} has a non-canonical length prefix"
        )));
    }
    Ok(&frame[4..])
}
