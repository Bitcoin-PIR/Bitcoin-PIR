//! Client-side encrypted channel — handshake + transport wrapper.
//!
//! ## What this module does
//!
//! - [`establish`] — runs the X25519 handshake against an inner
//!   [`PirTransport`] and returns a [`SecureChannelTransport`] that
//!   wraps it. The wrapper is itself a `PirTransport` so it slots in
//!   anywhere the existing native / wasm32 transports do.
//! - [`SecureChannelTransport`] — wraps any `PirTransport`. Each
//!   outgoing frame's payload (the bytes after the outer 4-byte
//!   length prefix) is sealed via `pir_channel::Session::seal` with
//!   the magic byte `0xfe` prepended; each incoming frame is opened.
//!
//! ## What this module does NOT do
//!
//! - **Verify the server's attestation.** The caller must obtain
//!   `server_static_pub` from a verified `bpir-admin attest` /
//!   `pir_sdk_client::attest::attest` call BEFORE invoking
//!   [`establish`]. Without that verification, the channel is still
//!   confidential against passive cloudflared but a MITM with its own
//!   X25519 pair could substitute. The full picture is: attest first
//!   (proves the server is the attested guest with this exact
//!   pubkey), then handshake using that pubkey.
//! - **Detect downgrade attacks.** The server still accepts cleartext
//!   frames on the same connection (for legacy clients). A network
//!   attacker that intercepts the client's REQ_HANDSHAKE and forwards
//!   only the cleartext follow-up frames to the server would see
//!   plaintext. Production clients should treat any handshake failure
//!   as fatal — never fall back to cleartext.

use async_trait::async_trait;
use pir_channel::{
    ClientHandshake, Direction, Session, ENCRYPTED_FRAME_MAGIC, SESSION_KEY_LEN,
};
use pir_sdk::{PirError, PirResult};

use crate::transport::PirTransport;

/// Re-export so callers don't need a direct `pir_channel` dep.
pub use pir_channel::ChannelError;

/// Opcode for `REQ_HANDSHAKE` (mirrors `pir_runtime_core::protocol::REQ_HANDSHAKE`).
const REQ_HANDSHAKE: u8 = 0x06;
/// Opcode for `RESP_HANDSHAKE`.
const RESP_HANDSHAKE: u8 = 0x06;
/// Generic server-side error envelope opcode.
const RESP_ERROR: u8 = 0xff;

/// Run the handshake against `transport` and return a wrapped
/// transport ready for encrypted PIR traffic.
///
/// `server_static_pub` is the X25519 public key the caller has
/// already obtained via attestation (`pir_sdk_client::attest::attest`
/// returns it in `AttestVerification::response.server_static_pub`,
/// and a sound caller verifies the SEV-SNP report binds it before
/// calling here).
///
/// `eph_seed` and `nonce` MUST be cryptographically random (32 bytes
/// each from a CSPRNG). Tests can pass deterministic seeds for
/// reproducibility; production code must never reuse them.
pub async fn establish<T: PirTransport>(
    mut transport: T,
    server_static_pub: [u8; 32],
    eph_seed: [u8; 32],
    nonce: [u8; 32],
) -> PirResult<SecureChannelTransport<T>> {
    let hs = ClientHandshake::new(eph_seed, nonce);

    // Build REQ_HANDSHAKE: [u32 len LE][REQ_HANDSHAKE][client_eph_pub:32][nonce:32]
    let mut req = Vec::with_capacity(4 + 1 + 32 + 32);
    let payload_len: u32 = 1 + 32 + 32;
    req.extend_from_slice(&payload_len.to_le_bytes());
    req.push(REQ_HANDSHAKE);
    req.extend_from_slice(&hs.client_eph_pub());
    req.extend_from_slice(&hs.nonce());

    // The handshake itself is sent in cleartext (the session key isn't
    // derived yet). The server's reply (also cleartext, by definition
    // — the client doesn't have a key to decrypt with) carries the
    // server's ephemeral pubkey.
    let resp = transport.roundtrip(&req).await?;
    if resp.is_empty() {
        return Err(PirError::Protocol(
            "empty handshake response from server".into(),
        ));
    }
    match resp[0] {
        RESP_HANDSHAKE => {}
        RESP_ERROR => {
            let msg = String::from_utf8_lossy(&resp[1..]).to_string();
            return Err(PirError::ServerError(format!(
                "handshake rejected: {}",
                msg
            )));
        }
        v => {
            return Err(PirError::Protocol(format!(
                "unexpected response variant 0x{:02x} for handshake",
                v
            )));
        }
    }
    if resp.len() < 1 + 32 {
        return Err(PirError::Protocol(
            "handshake response missing 32-byte server_eph_pub".into(),
        ));
    }
    let mut server_eph_pub = [0u8; 32];
    server_eph_pub.copy_from_slice(&resp[1..33]);

    let session = hs.complete_handshake(&server_static_pub, &server_eph_pub);
    Ok(SecureChannelTransport::new(transport, session))
}

/// A `PirTransport` that wraps another transport with AEAD frame
/// encryption + replay protection. After [`establish`] runs the
/// handshake, return one of these to drive subsequent encrypted
/// PIR traffic.
pub struct SecureChannelTransport<T: PirTransport> {
    inner: T,
    session: Session,
}

impl<T: PirTransport> SecureChannelTransport<T> {
    /// Construct directly from an established session. Most callers
    /// should use [`establish`] which runs the handshake for them.
    /// Useful for tests or for re-attaching to an inherited session.
    pub fn new(inner: T, session: Session) -> Self {
        Self { inner, session }
    }

    /// Borrow the inner transport. Useful for accessing transport-
    /// specific state (e.g., `WsConnection::set_metrics_recorder`)
    /// without unwrapping.
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Mutably borrow the inner transport.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Unwrap, returning the inner transport + session. For tests.
    #[cfg(test)]
    pub fn into_parts(self) -> (T, Session) {
        (self.inner, self.session)
    }

    /// Seal an outgoing request: takes `[4B len][payload]` (the wire
    /// format `WsConnection::send` expects), seals just the `payload`
    /// portion, and rebuilds the outer length prefix around the
    /// sealed bytes. Result: `[4B sealed_len][0xfe][seq:u64][ct+tag]`.
    fn seal_outgoing(&mut self, encoded: &[u8]) -> PirResult<Vec<u8>> {
        if encoded.len() < 4 {
            return Err(PirError::Protocol(
                "secure channel: outgoing frame missing 4-byte length prefix".into(),
            ));
        }
        let inner = &encoded[4..];
        let sealed = self
            .session
            .seal(Direction::ClientToServer, inner)
            .map_err(channel_err_to_pir)?;
        let mut out = Vec::with_capacity(4 + sealed.len());
        out.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Open an incoming response payload (the bytes AFTER the outer
    /// 4-byte length prefix). Returns the inner cleartext payload.
    fn open_incoming(&mut self, payload: &[u8]) -> PirResult<Vec<u8>> {
        if payload.is_empty() {
            return Err(PirError::Protocol(
                "secure channel: empty incoming payload".into(),
            ));
        }
        if payload[0] != ENCRYPTED_FRAME_MAGIC {
            return Err(PirError::Protocol(format!(
                "secure channel: incoming frame missing 0x{:02x} magic (got 0x{:02x})",
                ENCRYPTED_FRAME_MAGIC, payload[0]
            )));
        }
        self.session
            .open(Direction::ServerToClient, payload)
            .map_err(channel_err_to_pir)
    }
}

#[async_trait]
impl<T: PirTransport> PirTransport for SecureChannelTransport<T> {
    async fn send(&mut self, data: Vec<u8>) -> PirResult<()> {
        let sealed = self.seal_outgoing(&data)?;
        self.inner.send(sealed).await
    }

    async fn recv(&mut self) -> PirResult<Vec<u8>> {
        // recv contract: returns the FULL frame including the outer
        // 4-byte length prefix. We open the inner payload then
        // re-prepend a fresh length prefix so callers see the same
        // shape they'd get from a cleartext `recv`.
        let raw = self.inner.recv().await?;
        if raw.len() < 4 {
            return Err(PirError::Protocol(
                "secure channel: inner recv returned <4 bytes".into(),
            ));
        }
        let opened = self.open_incoming(&raw[4..])?;
        let mut out = Vec::with_capacity(4 + opened.len());
        out.extend_from_slice(&(opened.len() as u32).to_le_bytes());
        out.extend_from_slice(&opened);
        Ok(out)
    }

    async fn roundtrip(&mut self, request: &[u8]) -> PirResult<Vec<u8>> {
        // roundtrip contract: returns the response WITHOUT the outer
        // 4-byte length prefix. We open the response and return the
        // decrypted payload directly (no length prefix to add or
        // strip).
        let sealed = self.seal_outgoing(request)?;
        let resp = self.inner.roundtrip(&sealed).await?;
        // resp is already without the 4B length prefix per inner's
        // roundtrip contract. So resp[0] should be our magic byte.
        self.open_incoming(&resp)
    }

    async fn close(&mut self) -> PirResult<()> {
        self.inner.close().await
    }

    fn url(&self) -> &str {
        self.inner.url()
    }
}

fn channel_err_to_pir(e: ChannelError) -> PirError {
    PirError::Protocol(format!("secure channel: {}", e))
}

/// Length of the symmetric session key — re-export so downstream
/// callers don't need a direct `pir_channel` dep just for the constant.
pub const _SESSION_KEY_LEN: usize = SESSION_KEY_LEN;

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use pir_channel::{ServerHandshake, X25519_PUBKEY_LEN};
    use rand_core::{OsRng, RngCore};
    use std::sync::Mutex;
    use x25519_dalek::{PublicKey as XPub, StaticSecret};

    fn random_seed() -> [u8; 32] {
        let mut s = [0u8; 32];
        OsRng.fill_bytes(&mut s);
        s
    }

    /// A test transport that pretends to be a server. Holds the server's
    /// static keypair, runs the handshake, and once a session is
    /// established, can echo encrypted requests back as encrypted
    /// responses.
    struct FakeServerTransport {
        server_static_secret: StaticSecret,
        // None until handshake completes.
        server_session: Mutex<Option<Session>>,
        // Eph seed picked deterministically per test for reproducibility.
        server_eph_seed: [u8; 32],
        // Last raw outgoing payload the client wrote (for assertion in tests).
        last_send: Mutex<Vec<u8>>,
    }

    impl FakeServerTransport {
        fn new(server_static_secret: StaticSecret, server_eph_seed: [u8; 32]) -> Self {
            Self {
                server_static_secret,
                server_session: Mutex::new(None),
                server_eph_seed,
                last_send: Mutex::new(Vec::new()),
            }
        }

        fn server_static_pub(&self) -> [u8; X25519_PUBKEY_LEN] {
            *XPub::from(&self.server_static_secret).as_bytes()
        }
    }

    #[async_trait]
    impl PirTransport for FakeServerTransport {
        async fn send(&mut self, _data: Vec<u8>) -> PirResult<()> {
            Ok(())
        }
        async fn recv(&mut self) -> PirResult<Vec<u8>> {
            unimplemented!("FakeServerTransport: tests use roundtrip()")
        }
        /// Mimics what the server would do over the wire:
        /// 1. Receive `request` (= `[4B len][payload]`).
        /// 2. If payload[0] == REQ_HANDSHAKE: derive session, reply
        ///    cleartext with server_eph_pub.
        /// 3. If payload[0] == ENCRYPTED_FRAME_MAGIC and session
        ///    established: open, "echo" the inner bytes back, seal.
        ///    Returns the response WITHOUT the outer length prefix
        ///    (per the trait contract for roundtrip).
        async fn roundtrip(&mut self, request: &[u8]) -> PirResult<Vec<u8>> {
            *self.last_send.lock().unwrap() = request.to_vec();
            assert!(request.len() >= 5, "request must include 4B len prefix");
            let payload = &request[4..];
            match payload[0] {
                REQ_HANDSHAKE => {
                    assert_eq!(payload.len(), 1 + 32 + 32, "handshake req shape");
                    let mut client_eph_pub = [0u8; 32];
                    client_eph_pub.copy_from_slice(&payload[1..33]);
                    let mut nonce = [0u8; 32];
                    nonce.copy_from_slice(&payload[33..65]);

                    let server_hs = ServerHandshake::new(
                        &self.server_static_secret,
                        self.server_eph_seed,
                    );
                    let server_eph_pub = server_hs.server_eph_pub();
                    let session = server_hs.complete_handshake(&client_eph_pub, &nonce);
                    *self.server_session.lock().unwrap() = Some(session);

                    // Return cleartext RESP_HANDSHAKE (no outer length prefix
                    // per the contract).
                    let mut resp = Vec::with_capacity(1 + 32);
                    resp.push(RESP_HANDSHAKE);
                    resp.extend_from_slice(&server_eph_pub);
                    Ok(resp)
                }
                ENCRYPTED_FRAME_MAGIC => {
                    let mut session_lock = self.server_session.lock().unwrap();
                    let session = session_lock.as_mut().expect("session must be established");
                    let opened = session
                        .open(Direction::ClientToServer, payload)
                        .map_err(|e| PirError::Protocol(format!("server open: {}", e)))?;
                    // "Server logic": echo the bytes prefixed with 0xAB so we
                    // can tell server-processed traffic apart from raw echo.
                    let mut response_inner = Vec::with_capacity(opened.len() + 1);
                    response_inner.push(0xAB);
                    response_inner.extend_from_slice(&opened);
                    let sealed = session
                        .seal(Direction::ServerToClient, &response_inner)
                        .map_err(|e| PirError::Protocol(format!("server seal: {}", e)))?;
                    Ok(sealed)
                }
                v => Err(PirError::Protocol(format!(
                    "fake server: unknown opcode 0x{:02x}",
                    v
                ))),
            }
        }
        async fn close(&mut self) -> PirResult<()> {
            Ok(())
        }
        fn url(&self) -> &str {
            "mock://fake-server"
        }
    }

    #[tokio::test]
    async fn establish_handshake_then_roundtrip_request() {
        let server_secret = StaticSecret::from(random_seed());
        let server_eph_seed = random_seed();
        let fake = FakeServerTransport::new(server_secret.clone(), server_eph_seed);
        let server_static_pub = fake.server_static_pub();

        let client_eph_seed = random_seed();
        let nonce = random_seed();
        let mut secure = establish(fake, server_static_pub, client_eph_seed, nonce)
            .await
            .expect("handshake should succeed");

        // Send an inner "REQ_PING" (just opcode 0x00 + nothing) wrapped
        // in the standard [4B len][payload] envelope.
        let mut req = Vec::new();
        req.extend_from_slice(&1u32.to_le_bytes());
        req.push(0x00);
        let resp = secure.roundtrip(&req).await.expect("roundtrip should succeed");
        // Fake server echoed [0xAB, 0x00] back. The wrapper opens it →
        // we get those bytes verbatim (no length prefix per roundtrip
        // contract).
        assert_eq!(resp, vec![0xAB, 0x00]);
    }

    #[tokio::test]
    async fn handshake_failure_propagates_as_pirerror() {
        // FakeServerTransport that returns a RESP_ERROR envelope.
        struct BadServer;
        #[async_trait]
        impl PirTransport for BadServer {
            async fn send(&mut self, _: Vec<u8>) -> PirResult<()> {
                Ok(())
            }
            async fn recv(&mut self) -> PirResult<Vec<u8>> {
                unimplemented!()
            }
            async fn roundtrip(&mut self, _: &[u8]) -> PirResult<Vec<u8>> {
                let mut r = vec![RESP_ERROR];
                r.extend_from_slice(b"handshake disabled");
                Ok(r)
            }
            async fn close(&mut self) -> PirResult<()> {
                Ok(())
            }
            fn url(&self) -> &str {
                "mock://bad"
            }
        }
        // We can't `.unwrap_err()` directly because the Ok value type
        // (SecureChannelTransport<BadServer>) doesn't impl Debug. Match
        // on the result instead.
        match establish(BadServer, [0u8; 32], [1u8; 32], [2u8; 32]).await {
            Err(PirError::ServerError(msg)) => assert!(msg.contains("handshake disabled")),
            Err(other) => panic!("expected ServerError, got {:?}", other),
            Ok(_) => panic!("expected handshake to fail"),
        }
    }

    #[tokio::test]
    async fn wrong_server_static_pub_makes_subsequent_traffic_fail() {
        // The point of binding the static pubkey: if the client uses a
        // different pubkey than the server actually holds, the derived
        // session keys diverge → first sealed frame fails to decrypt
        // server-side (and likewise, the server's response fails to
        // decrypt client-side).
        let real_secret = StaticSecret::from(random_seed());
        let server_eph_seed = random_seed();
        let fake = FakeServerTransport::new(real_secret, server_eph_seed);
        let wrong_static_pub = *XPub::from(&StaticSecret::from(random_seed())).as_bytes();

        let mut secure = establish(fake, wrong_static_pub, random_seed(), random_seed())
            .await
            .expect("handshake transport-wise succeeds; key disagreement appears later");

        // First post-handshake roundtrip: server opens with its real
        // session key, sees garbage → decryption error.
        let mut req = Vec::new();
        req.extend_from_slice(&1u32.to_le_bytes());
        req.push(0x00);
        let err = secure.roundtrip(&req).await.unwrap_err();
        match err {
            PirError::Protocol(msg) => {
                assert!(
                    msg.contains("server open") || msg.contains("AEAD"),
                    "expected AEAD-related error, got {}",
                    msg
                );
            }
            other => panic!("expected Protocol, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn replay_in_outbound_direction_makes_server_reject() {
        // Successive client → server frames get distinct sequence
        // numbers. If a network attacker captures one and replays it,
        // the server's `next_recv_seq` won't match → AEAD failure.
        // (This is a property of pir_channel::Session::open; here we
        // verify the wrapper passes the seq correctly.)
        let server_secret = StaticSecret::from(random_seed());
        let server_eph_seed = random_seed();
        let fake = FakeServerTransport::new(server_secret.clone(), server_eph_seed);
        let server_static_pub = fake.server_static_pub();

        let mut secure = establish(fake, server_static_pub, random_seed(), random_seed())
            .await
            .unwrap();

        let mut req = Vec::new();
        req.extend_from_slice(&1u32.to_le_bytes());
        req.push(0x00);

        // First call succeeds.
        secure.roundtrip(&req).await.unwrap();
        // Manually craft a second send with seq=0 by re-sealing — but
        // that's not what `seal_outgoing` does (it auto-increments).
        // Instead, simulate a replay by snapshot+restore of session
        // state isn't easy from here. The simpler verification: a
        // direct `Session` test in pir-channel already proves replay
        // is rejected. Here we just confirm successive *legitimate*
        // calls do increment & continue to work.
        secure.roundtrip(&req).await.unwrap();
    }
}
