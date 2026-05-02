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
pub(crate) const REQ_ADMIN_DB_UPLOAD_BEGIN: u8 = 0x82;
pub(crate) const REQ_ADMIN_DB_UPLOAD_CHUNK: u8 = 0x83;
pub(crate) const REQ_ADMIN_DB_UPLOAD_FINALIZE: u8 = 0x84;
pub(crate) const REQ_ADMIN_DB_ACTIVATE: u8 = 0x85;
pub(crate) const RESP_ADMIN_AUTH_CHALLENGE: u8 = 0x80;
pub(crate) const RESP_ADMIN_AUTH_RESPONSE: u8 = 0x81;
pub(crate) const RESP_ADMIN_DB_UPLOAD_BEGIN: u8 = 0x82;
pub(crate) const RESP_ADMIN_DB_UPLOAD_CHUNK: u8 = 0x83;
pub(crate) const RESP_ADMIN_DB_UPLOAD_FINALIZE: u8 = 0x84;
pub(crate) const RESP_ADMIN_DB_ACTIVATE: u8 = 0x85;
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

/// Generic admin ack returned by BEGIN, CHUNK, ACTIVATE.
#[derive(Clone, Debug)]
pub struct AdminAck {
    pub ok: bool,
    pub msg: String,
}

/// Result of a FINALIZE call. On success, `manifest_root` matches what
/// `MappedDatabase::load()` would emit for the staged dir.
#[derive(Clone, Debug)]
pub struct FinalizeResult {
    pub ok: bool,
    pub msg: String,
    pub manifest_root: [u8; 32],
}

/// Send `REQ_ADMIN_DB_UPLOAD_BEGIN`. Server creates `<data_root>/.staging/<name>/`
/// and writes `MANIFEST.toml` from the supplied bytes.
pub async fn upload_begin<T: PirTransport + ?Sized>(
    transport: &mut T,
    name: &str,
    manifest_toml: &[u8],
) -> PirResult<AdminAck> {
    let mut payload = Vec::with_capacity(name.len() + manifest_toml.len() + 16);
    encode_lp(&mut payload, name.as_bytes());
    payload.extend_from_slice(&(manifest_toml.len() as u32).to_le_bytes());
    payload.extend_from_slice(manifest_toml);
    let req = encode_request(REQ_ADMIN_DB_UPLOAD_BEGIN, &payload);
    let resp = transport.roundtrip(&req).await?;
    parse_ack(&resp, RESP_ADMIN_DB_UPLOAD_BEGIN, "BEGIN")
}

/// Send `REQ_ADMIN_DB_UPLOAD_CHUNK`. Server appends `data` to
/// `<staging>/<file_path>` at byte `offset`.
pub async fn upload_chunk<T: PirTransport + ?Sized>(
    transport: &mut T,
    name: &str,
    file_path: &str,
    offset: u64,
    data: &[u8],
) -> PirResult<AdminAck> {
    let mut payload = Vec::with_capacity(name.len() + file_path.len() + 16 + data.len());
    encode_lp(&mut payload, name.as_bytes());
    encode_lp(&mut payload, file_path.as_bytes());
    payload.extend_from_slice(&offset.to_le_bytes());
    payload.extend_from_slice(&(data.len() as u32).to_le_bytes());
    payload.extend_from_slice(data);
    let req = encode_request(REQ_ADMIN_DB_UPLOAD_CHUNK, &payload);
    let resp = transport.roundtrip(&req).await?;
    parse_ack(&resp, RESP_ADMIN_DB_UPLOAD_CHUNK, "CHUNK")
}

/// Send `REQ_ADMIN_DB_UPLOAD_FINALIZE`. Server hashes every file
/// against the manifest and returns the manifest root.
pub async fn upload_finalize<T: PirTransport + ?Sized>(
    transport: &mut T,
    name: &str,
) -> PirResult<FinalizeResult> {
    let mut payload = Vec::new();
    encode_lp(&mut payload, name.as_bytes());
    let req = encode_request(REQ_ADMIN_DB_UPLOAD_FINALIZE, &payload);
    let resp = transport.roundtrip(&req).await?;
    if resp.is_empty() {
        return Err(PirError::Protocol("empty FINALIZE response".into()));
    }
    match resp[0] {
        RESP_ADMIN_DB_UPLOAD_FINALIZE => {
            // [1B ok][2B msg_len][msg][32B root]
            if resp.len() < 1 + 1 + 2 + 32 {
                return Err(PirError::Protocol("FINALIZE response too short".into()));
            }
            let ok = resp[1] != 0;
            let msg_len = u16::from_le_bytes(resp[2..4].try_into().unwrap()) as usize;
            if 4 + msg_len + 32 > resp.len() {
                return Err(PirError::Protocol("FINALIZE response truncated".into()));
            }
            let msg = String::from_utf8_lossy(&resp[4..4 + msg_len]).to_string();
            let mut manifest_root = [0u8; 32];
            manifest_root.copy_from_slice(&resp[4 + msg_len..4 + msg_len + 32]);
            Ok(FinalizeResult { ok, msg, manifest_root })
        }
        RESP_ERROR => {
            let msg = String::from_utf8_lossy(&resp[1..]).to_string();
            Err(PirError::ServerError(msg))
        }
        v => Err(PirError::Protocol(format!("unexpected FINALIZE variant 0x{:02x}", v))),
    }
}

/// Send `REQ_ADMIN_DB_ACTIVATE`. Server atomically renames
/// `<staging>/<name>/` → `<data_root>/<target_path>/`. The operator
/// must restart the server to pick up the new DB (this slice has
/// no hot-reload).
pub async fn activate<T: PirTransport + ?Sized>(
    transport: &mut T,
    name: &str,
    target_path: &str,
) -> PirResult<AdminAck> {
    let mut payload = Vec::new();
    encode_lp(&mut payload, name.as_bytes());
    encode_lp(&mut payload, target_path.as_bytes());
    let req = encode_request(REQ_ADMIN_DB_ACTIVATE, &payload);
    let resp = transport.roundtrip(&req).await?;
    parse_ack(&resp, RESP_ADMIN_DB_ACTIVATE, "ACTIVATE")
}

fn encode_lp(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(bytes);
}

fn parse_ack(resp: &[u8], expected_variant: u8, op: &str) -> PirResult<AdminAck> {
    if resp.is_empty() {
        return Err(PirError::Protocol(format!("empty {} response", op)));
    }
    match resp[0] {
        v if v == expected_variant => {
            if resp.len() < 1 + 1 + 2 {
                return Err(PirError::Protocol(format!("{} response too short", op)));
            }
            let ok = resp[1] != 0;
            let msg_len = u16::from_le_bytes(resp[2..4].try_into().unwrap()) as usize;
            if 4 + msg_len > resp.len() {
                return Err(PirError::Protocol(format!("{} response truncated msg", op)));
            }
            let msg = String::from_utf8_lossy(&resp[4..4 + msg_len]).to_string();
            Ok(AdminAck { ok, msg })
        }
        RESP_ERROR => {
            let msg = String::from_utf8_lossy(&resp[1..]).to_string();
            Err(PirError::ServerError(msg))
        }
        v => Err(PirError::Protocol(format!(
            "unexpected {} response variant 0x{:02x}",
            op, v
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

    // ─── Upload helper tests (Slice 3b) ──────────────────────────────────
    //
    // These exercise the client-side wire encoding + response parsing.
    // The real server-side state machine lives in pir-runtime-core's
    // admin.rs and has its own test coverage there.

    /// Mock that returns a canned reply per opcode and records the last request.
    struct CannedTransport {
        replies: std::collections::HashMap<u8, Vec<u8>>,
        last_request: std::sync::Mutex<Vec<u8>>,
    }
    #[async_trait]
    impl PirTransport for CannedTransport {
        async fn send(&mut self, _data: Vec<u8>) -> PirResult<()> {
            Ok(())
        }
        async fn recv(&mut self) -> PirResult<Vec<u8>> {
            unimplemented!()
        }
        async fn roundtrip(&mut self, request: &[u8]) -> PirResult<Vec<u8>> {
            *self.last_request.lock().unwrap() = request.to_vec();
            // request format: [4B len LE][1B variant][...]
            let variant = request[4];
            Ok(self.replies.get(&variant).cloned().unwrap_or_else(|| vec![RESP_ERROR]))
        }
        async fn close(&mut self) -> PirResult<()> {
            Ok(())
        }
        fn url(&self) -> &str {
            "canned://test"
        }
    }

    fn ack_reply(variant: u8, ok: bool, msg: &str) -> Vec<u8> {
        let mut r = vec![variant, if ok { 1 } else { 0 }];
        let mb = msg.as_bytes();
        r.extend_from_slice(&(mb.len() as u16).to_le_bytes());
        r.extend_from_slice(mb);
        r
    }

    fn finalize_reply(ok: bool, msg: &str, root: [u8; 32]) -> Vec<u8> {
        let mut r = vec![RESP_ADMIN_DB_UPLOAD_FINALIZE, if ok { 1 } else { 0 }];
        let mb = msg.as_bytes();
        r.extend_from_slice(&(mb.len() as u16).to_le_bytes());
        r.extend_from_slice(mb);
        r.extend_from_slice(&root);
        r
    }

    #[tokio::test]
    async fn upload_begin_encodes_correctly_and_parses_ok() {
        let mut replies = std::collections::HashMap::new();
        replies.insert(RESP_ADMIN_DB_UPLOAD_BEGIN, ack_reply(RESP_ADMIN_DB_UPLOAD_BEGIN, true, "ok"));
        let mut t = CannedTransport {
            replies,
            last_request: std::sync::Mutex::new(Vec::new()),
        };
        let manifest = b"[manifest]\nversion = 1\n[files]\n";
        let ack = upload_begin(&mut t, "snap1", manifest).await.unwrap();
        assert!(ack.ok);
        assert_eq!(ack.msg, "ok");
        // Validate the request bytes start with REQ_ADMIN_DB_UPLOAD_BEGIN
        let req = t.last_request.lock().unwrap().clone();
        assert_eq!(req[4], REQ_ADMIN_DB_UPLOAD_BEGIN);
        // Name length-prefix
        let name_len = u32::from_le_bytes(req[5..9].try_into().unwrap()) as usize;
        assert_eq!(name_len, "snap1".len());
        assert_eq!(&req[9..9 + name_len], b"snap1");
        // Manifest length-prefix
        let mlen_off = 9 + name_len;
        let mlen = u32::from_le_bytes(req[mlen_off..mlen_off + 4].try_into().unwrap()) as usize;
        assert_eq!(mlen, manifest.len());
        assert_eq!(&req[mlen_off + 4..mlen_off + 4 + mlen], manifest);
    }

    #[tokio::test]
    async fn upload_chunk_encodes_offset_and_data() {
        let mut replies = std::collections::HashMap::new();
        replies.insert(RESP_ADMIN_DB_UPLOAD_CHUNK, ack_reply(RESP_ADMIN_DB_UPLOAD_CHUNK, true, ""));
        let mut t = CannedTransport {
            replies,
            last_request: std::sync::Mutex::new(Vec::new()),
        };
        let data = vec![0xAAu8; 1234];
        upload_chunk(&mut t, "snap1", "a.bin", 0xDEAD_BEEF_DEAD_BEEFu64, &data).await.unwrap();
        let req = t.last_request.lock().unwrap().clone();
        assert_eq!(req[4], REQ_ADMIN_DB_UPLOAD_CHUNK);
        // Find the offset field (after two LP strings) and check it's intact.
        // name_len(4) + name + path_len(4) + path + offset(8) + data_len(4) + data
        let mut pos = 5;
        let nl = u32::from_le_bytes(req[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4 + nl;
        let pl = u32::from_le_bytes(req[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4 + pl;
        let offset = u64::from_le_bytes(req[pos..pos + 8].try_into().unwrap());
        assert_eq!(offset, 0xDEAD_BEEF_DEAD_BEEFu64);
        pos += 8;
        let dl = u32::from_le_bytes(req[pos..pos + 4].try_into().unwrap()) as usize;
        assert_eq!(dl, data.len());
        assert_eq!(&req[pos + 4..pos + 4 + dl], &data[..]);
    }

    #[tokio::test]
    async fn finalize_returns_root() {
        let root = [0xCDu8; 32];
        let mut replies = std::collections::HashMap::new();
        replies.insert(RESP_ADMIN_DB_UPLOAD_FINALIZE, finalize_reply(true, "verified", root));
        let mut t = CannedTransport {
            replies,
            last_request: std::sync::Mutex::new(Vec::new()),
        };
        let r = upload_finalize(&mut t, "snap1").await.unwrap();
        assert!(r.ok);
        assert_eq!(r.manifest_root, root);
        assert_eq!(r.msg, "verified");
    }

    #[tokio::test]
    async fn server_error_on_upload_propagates() {
        // Server returned RESP_ERROR (e.g., not authenticated)
        let mut replies = std::collections::HashMap::new();
        let mut err_reply = vec![RESP_ERROR];
        err_reply.extend_from_slice(b"not authenticated");
        replies.insert(RESP_ADMIN_DB_UPLOAD_BEGIN, err_reply);
        let mut t = CannedTransport {
            replies,
            last_request: std::sync::Mutex::new(Vec::new()),
        };
        let err = upload_begin(&mut t, "snap1", b"...").await.unwrap_err();
        match err {
            PirError::ServerError(m) => assert!(m.contains("not authenticated")),
            _ => panic!("expected ServerError, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn activate_encodes_target_path() {
        let mut replies = std::collections::HashMap::new();
        replies.insert(RESP_ADMIN_DB_ACTIVATE, ack_reply(RESP_ADMIN_DB_ACTIVATE, true, "activated"));
        let mut t = CannedTransport {
            replies,
            last_request: std::sync::Mutex::new(Vec::new()),
        };
        let ack = activate(&mut t, "snap1", "checkpoints/940611").await.unwrap();
        assert!(ack.ok);
        assert_eq!(ack.msg, "activated");
        let req = t.last_request.lock().unwrap().clone();
        assert_eq!(req[4], REQ_ADMIN_DB_ACTIVATE);
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
