//! Client-side admin authentication and (Slice 3b) DB upload helpers.
//!
//! ## Authentication (Slice 3a)
//!
//! [`authenticate`] runs the two-step challenge/response flow against
//! a server's WebSocket connection:
//!
//! 1. Send `REQ_ADMIN_AUTH_CHALLENGE` → receive a 32-byte nonce.
//! 2. Sign `ADMIN_AUTH_DOMAIN_TAG || nonce` with the operator's
//!    ed25519 private key. Send `REQ_ADMIN_AUTH_RESPONSE { signature }`.
//! 3. On success, the server marks the WebSocket connection
//!    authenticated and accepts subsequent `REQ_ADMIN_*` requests.
//!
//! Returning a typed [`AuthOutcome`] rather than a `Result` lets the
//! CLI distinguish "server says no" (e.g. wrong key) from "transport
//! broke" (e.g. timeout). Both flow as `Err` from `?` callers, but
//! `bpir-admin` displays them differently.

use crate::protocol::encode_request;
use crate::transport::PirTransport;
use ed25519_dalek::{Signer, SigningKey};
use pir_sdk::{PirError, PirResult};

/// Domain-separation tag for admin-auth signatures. Must match the
/// server's `pir_runtime_core::protocol::ADMIN_AUTH_DOMAIN_TAG`.
pub const ADMIN_AUTH_DOMAIN_TAG: &[u8] = b"BPIR-ADMIN-AUTH-V1";

pub(crate) const REQ_ADMIN_AUTH_CHALLENGE: u8 = 0x80;
pub(crate) const REQ_ADMIN_AUTH_RESPONSE: u8 = 0x81;
pub(crate) const RESP_ADMIN_AUTH_CHALLENGE: u8 = 0x80;
pub(crate) const RESP_ADMIN_AUTH_RESPONSE: u8 = 0x81;
const RESP_ERROR: u8 = 0xff;

/// Outcome of an `authenticate` call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthOutcome {
    /// Server accepted the signature; connection is now authenticated.
    Ok,
    /// Server replied OK=false (e.g. wrong key, no challenge issued,
    /// signature mismatch). The included `msg` is the server's
    /// human-readable reason.
    Rejected { msg: String },
}

/// Run the full challenge/response auth flow against a server.
///
/// On success, the same `transport` is left in a state where
/// subsequent `REQ_ADMIN_*` requests are accepted. The auth is
/// per-connection — disconnecting (or letting the transport be
/// dropped) requires a fresh `authenticate` call.
pub async fn authenticate<T: PirTransport + ?Sized>(
    transport: &mut T,
    signing_key: &SigningKey,
) -> PirResult<AuthOutcome> {
    // Step 1 — challenge
    let request = encode_request(REQ_ADMIN_AUTH_CHALLENGE, &[]);
    let response = transport.roundtrip(&request).await?;
    if response.is_empty() {
        return Err(PirError::Protocol(
            "empty challenge response".into(),
        ));
    }
    match response[0] {
        RESP_ADMIN_AUTH_CHALLENGE => { /* fall through */ }
        RESP_ERROR => {
            let msg = String::from_utf8_lossy(&response[1..]).to_string();
            return Err(PirError::ServerError(msg));
        }
        v => {
            return Err(PirError::Protocol(format!(
                "unexpected challenge variant 0x{:02x}",
                v
            )));
        }
    }
    if response.len() < 1 + 32 {
        return Err(PirError::Protocol(
            "challenge response missing nonce".into(),
        ));
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&response[1..33]);

    // Step 2 — sign and respond
    let mut signed_blob = Vec::with_capacity(ADMIN_AUTH_DOMAIN_TAG.len() + 32);
    signed_blob.extend_from_slice(ADMIN_AUTH_DOMAIN_TAG);
    signed_blob.extend_from_slice(&nonce);
    let sig = signing_key.sign(&signed_blob).to_bytes();

    let request = encode_request(REQ_ADMIN_AUTH_RESPONSE, &sig);
    let response = transport.roundtrip(&request).await?;
    if response.is_empty() {
        return Err(PirError::Protocol("empty auth response".into()));
    }
    match response[0] {
        RESP_ADMIN_AUTH_RESPONSE => {
            if response.len() < 1 + 1 + 2 {
                return Err(PirError::Protocol("auth response too short".into()));
            }
            let ok = response[1] != 0;
            let msg_len = u16::from_le_bytes(response[2..4].try_into().unwrap()) as usize;
            if 4 + msg_len > response.len() {
                return Err(PirError::Protocol("auth response truncated msg".into()));
            }
            let msg = String::from_utf8_lossy(&response[4..4 + msg_len]).to_string();
            if ok {
                Ok(AuthOutcome::Ok)
            } else {
                Ok(AuthOutcome::Rejected { msg })
            }
        }
        RESP_ERROR => {
            let msg = String::from_utf8_lossy(&response[1..]).to_string();
            Err(PirError::ServerError(msg))
        }
        v => Err(PirError::Protocol(format!(
            "unexpected auth response variant 0x{:02x}",
            v
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use std::sync::Mutex;

    /// In-memory server that actually exercises the wire protocol +
    /// signature verification, so the test catches drift between
    /// client and server domain tags / wire layout / sig format.
    struct ServerSim {
        admin_pk: VerifyingKey,
        pending_nonce: Mutex<Option<[u8; 32]>>,
        authenticated: Mutex<bool>,
    }

    impl ServerSim {
        fn new(pk: VerifyingKey) -> Self {
            Self {
                admin_pk: pk,
                pending_nonce: Mutex::new(None),
                authenticated: Mutex::new(false),
            }
        }

        fn handle(&self, request: &[u8]) -> Vec<u8> {
            // Strip 4-byte length prefix
            let payload = &request[4..];
            match payload[0] {
                REQ_ADMIN_AUTH_CHALLENGE => {
                    let nonce = [0xAAu8; 32]; // deterministic for tests
                    *self.pending_nonce.lock().unwrap() = Some(nonce);
                    let mut resp = vec![RESP_ADMIN_AUTH_CHALLENGE];
                    resp.extend_from_slice(&nonce);
                    resp
                }
                REQ_ADMIN_AUTH_RESPONSE => {
                    let sig_bytes: [u8; 64] = payload[1..65].try_into().unwrap();
                    let sig = Signature::from_bytes(&sig_bytes);

                    let nonce = self.pending_nonce.lock().unwrap().take();
                    let (ok, msg) = match nonce {
                        None => (false, "no challenge"),
                        Some(n) => {
                            let mut blob = Vec::new();
                            blob.extend_from_slice(ADMIN_AUTH_DOMAIN_TAG);
                            blob.extend_from_slice(&n);
                            match self.admin_pk.verify(&blob, &sig) {
                                Ok(()) => {
                                    *self.authenticated.lock().unwrap() = true;
                                    (true, "ok")
                                }
                                Err(_) => (false, "bad sig"),
                            }
                        }
                    };
                    let mut resp = vec![RESP_ADMIN_AUTH_RESPONSE];
                    resp.push(if ok { 1 } else { 0 });
                    let mb = msg.as_bytes();
                    resp.extend_from_slice(&(mb.len() as u16).to_le_bytes());
                    resp.extend_from_slice(mb);
                    resp
                }
                _ => vec![RESP_ERROR],
            }
        }
    }

    struct ServerSimTransport {
        sim: std::sync::Arc<ServerSim>,
    }

    #[async_trait]
    impl PirTransport for ServerSimTransport {
        async fn send(&mut self, _data: Vec<u8>) -> PirResult<()> {
            Ok(())
        }
        async fn recv(&mut self) -> PirResult<Vec<u8>> {
            unimplemented!()
        }
        async fn roundtrip(&mut self, request: &[u8]) -> PirResult<Vec<u8>> {
            Ok(self.sim.handle(request))
        }
        async fn close(&mut self) -> PirResult<()> {
            Ok(())
        }
        fn url(&self) -> &str {
            "sim://test"
        }
    }

    /// Deterministic-but-distinct keypair derived from a seed byte —
    /// tests need different keys per call, but the values themselves
    /// don't need crypto-grade randomness.
    fn keypair_seeded(seed_byte: u8) -> (SigningKey, VerifyingKey) {
        let mut seed = [seed_byte; 32];
        // Mix in the seed_byte more so the sk is materially different.
        for (i, b) in seed.iter_mut().enumerate() {
            *b = b.wrapping_add(i as u8);
        }
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key();
        (sk, pk)
    }

    fn keypair() -> (SigningKey, VerifyingKey) {
        keypair_seeded(0x42)
    }

    #[tokio::test]
    async fn happy_path_authenticates() {
        let (sk, pk) = keypair();
        let sim = std::sync::Arc::new(ServerSim::new(pk));
        let mut transport = ServerSimTransport { sim: sim.clone() };

        let outcome = authenticate(&mut transport, &sk).await.unwrap();
        assert_eq!(outcome, AuthOutcome::Ok);
        assert!(*sim.authenticated.lock().unwrap());
    }

    #[tokio::test]
    async fn wrong_key_is_rejected() {
        let (_real_sk, pk) = keypair_seeded(0x11);
        let (attacker_sk, _attacker_pk) = keypair_seeded(0x22);
        let sim = std::sync::Arc::new(ServerSim::new(pk));
        let mut transport = ServerSimTransport { sim: sim.clone() };

        let outcome = authenticate(&mut transport, &attacker_sk).await.unwrap();
        match outcome {
            AuthOutcome::Rejected { msg } => assert_eq!(msg, "bad sig"),
            _ => panic!("expected Rejected, got {:?}", outcome),
        }
        assert!(!*sim.authenticated.lock().unwrap());
    }

    #[tokio::test]
    async fn signature_blob_uses_domain_tag() {
        // If the client signs WITHOUT the domain tag, the server's
        // verification (which does include the tag) must reject.
        let (sk, pk) = keypair();
        let sim = std::sync::Arc::new(ServerSim::new(pk));

        // Manually drive a request that signs without the domain tag.
        // First trigger a challenge:
        let challenge_req = encode_request(REQ_ADMIN_AUTH_CHALLENGE, &[]);
        let challenge_resp = sim.handle(&challenge_req);
        let nonce: [u8; 32] = challenge_resp[1..33].try_into().unwrap();

        // Sign nonce alone (no domain tag)
        let bad_sig = sk.sign(&nonce).to_bytes();
        let bad_resp_req = encode_request(REQ_ADMIN_AUTH_RESPONSE, &bad_sig);
        let resp = sim.handle(&bad_resp_req);

        assert_eq!(resp[0], RESP_ADMIN_AUTH_RESPONSE);
        assert_eq!(resp[1], 0, "should be ok=false");
        assert!(!*sim.authenticated.lock().unwrap());
    }
}
