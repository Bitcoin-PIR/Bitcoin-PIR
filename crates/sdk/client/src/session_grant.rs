//! Client-side `REQ_SESSION_GRANT_PRESENT` caller — attaches a cashier-signed
//! session grant to a connected server so its query-bearing frames can spend
//! the grant's credits.
//!
//! ## What this does
//!
//! - Sends `REQ_SESSION_GRANT_PRESENT` (opcode 0x0b) carrying the 133-byte
//!   grant over any [`PirTransport`].
//! - Parses `RESP_SESSION_GRANT_OK { remaining_credits: u32 LE }`.
//! - Surfaces the server's `RESP_ERROR` text ("session grants not enabled on
//!   this server", issuer not pinned, expired, exhausted) as
//!   [`PirError::ServerError`].
//!
//! ## What this does NOT do
//!
//! - **Parse or verify the grant.** The cashier issues it and the server
//!   verifies it (`pir_session_grant`); the client only carries bytes.
//! - **Hide the grant from the transport.** A grant is a bearer token:
//!   present it only after `upgrade_to_secure_channel`, so cloudflared and
//!   any other intermediary see ciphertext. The per-client wrappers
//!   ([`crate::DpfClient::present_session_grant`] and friends) run over
//!   whatever transport the client currently holds — the caller owns that
//!   ordering.

use crate::protocol::encode_request;
use crate::transport::PirTransport;
use pir_sdk::{PirError, PirResult};

/// Mirrors `pir_runtime_core::protocol::REQ_SESSION_GRANT_PRESENT`.
pub(crate) const REQ_SESSION_GRANT_PRESENT: u8 = 0x0b;
/// Mirrors `pir_runtime_core::protocol::RESP_SESSION_GRANT_OK`.
pub(crate) const RESP_SESSION_GRANT_OK: u8 = 0x0b;
/// Generic server-side error envelope.
const RESP_ERROR: u8 = 0xff;
/// Encoded length of a version-1 grant (mirrors
/// `pir_session_grant::SESSION_GRANT_LEN`). Checked before sending so a
/// truncated grant fails locally with a clear message.
pub const SESSION_GRANT_LEN: usize = 133;

/// Present `grant` on `transport` and return the credits remaining on this
/// server's ledger. See the module docs for the error mapping.
pub async fn present_session_grant<T: PirTransport + ?Sized>(
    transport: &mut T,
    grant: &[u8],
) -> PirResult<u32> {
    if grant.len() != SESSION_GRANT_LEN {
        return Err(PirError::Protocol(format!(
            "session grant must be {SESSION_GRANT_LEN} bytes, got {}",
            grant.len()
        )));
    }
    let request = encode_request(REQ_SESSION_GRANT_PRESENT, grant);
    let response = transport.roundtrip(&request).await?;
    parse_session_grant_response(&response)
}

/// Parse a raw response payload (starting at the variant byte) into the
/// remaining-credit count. Exposed so transports that are not a
/// [`PirTransport`] can reuse the exact decoder.
pub fn parse_session_grant_response(response: &[u8]) -> PirResult<u32> {
    match response.first() {
        None => Err(PirError::Protocol("empty session grant response".into())),
        Some(&RESP_SESSION_GRANT_OK) => {
            if response.len() != 5 {
                return Err(PirError::Protocol(format!(
                    "session grant response must be 5 bytes, got {}",
                    response.len()
                )));
            }
            Ok(u32::from_le_bytes(
                response[1..5].try_into().expect("four bytes"),
            ))
        }
        Some(&RESP_ERROR) => Err(PirError::ServerError(decode_error_envelope(response))),
        Some(variant) => Err(PirError::Protocol(format!(
            "unexpected response variant 0x{variant:02x} for session grant presentation"
        ))),
    }
}

/// `[RESP_ERROR][u32 len LE][utf-8 msg]`, tolerant of truncation.
fn decode_error_envelope(response: &[u8]) -> String {
    if response.len() >= 5 {
        let len = u32::from_le_bytes(response[1..5].try_into().expect("four bytes")) as usize;
        if 5 + len <= response.len() {
            return String::from_utf8_lossy(&response[5..5 + len]).into_owned();
        }
        return "<truncated error message>".into();
    }
    String::from_utf8_lossy(&response[1..]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Mutex;

    struct MockTransport {
        reply: Vec<u8>,
        last_request: Mutex<Vec<u8>>,
    }

    #[async_trait]
    impl PirTransport for MockTransport {
        async fn send(&mut self, _data: Vec<u8>) -> PirResult<()> {
            Ok(())
        }
        async fn recv(&mut self) -> PirResult<Vec<u8>> {
            Ok(self.reply.clone())
        }
        async fn roundtrip(&mut self, request: &[u8]) -> PirResult<Vec<u8>> {
            *self.last_request.lock().unwrap() = request.to_vec();
            Ok(self.reply.clone())
        }
        async fn close(&mut self) -> PirResult<()> {
            Ok(())
        }
        fn url(&self) -> &str {
            "mock://test"
        }
    }

    fn mock(reply: Vec<u8>) -> MockTransport {
        MockTransport {
            reply,
            last_request: Mutex::new(Vec::new()),
        }
    }

    fn grant_bytes() -> Vec<u8> {
        (0..SESSION_GRANT_LEN).map(|i| (i % 251) as u8).collect()
    }

    #[tokio::test]
    async fn accepted_presentation_returns_remaining_and_sends_the_grant() {
        let mut reply = vec![RESP_SESSION_GRANT_OK];
        reply.extend_from_slice(&42u32.to_le_bytes());
        let mut transport = mock(reply);
        let remaining = present_session_grant(&mut transport, &grant_bytes())
            .await
            .unwrap();
        assert_eq!(remaining, 42);

        let request = transport.last_request.lock().unwrap().clone();
        assert_eq!(request.len(), 4 + 1 + SESSION_GRANT_LEN);
        assert_eq!(
            u32::from_le_bytes(request[..4].try_into().unwrap()) as usize,
            1 + SESSION_GRANT_LEN
        );
        assert_eq!(request[4], REQ_SESSION_GRANT_PRESENT);
        assert_eq!(&request[5..], &grant_bytes()[..]);
    }

    #[tokio::test]
    async fn server_error_envelope_becomes_server_error() {
        let message = b"session grant: session grant credits are exhausted";
        let mut reply = vec![RESP_ERROR];
        reply.extend_from_slice(&(message.len() as u32).to_le_bytes());
        reply.extend_from_slice(message);
        let mut transport = mock(reply);
        match present_session_grant(&mut transport, &grant_bytes())
            .await
            .unwrap_err()
        {
            PirError::ServerError(text) => assert!(text.contains("exhausted"), "{text}"),
            other => panic!("expected ServerError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn wrong_grant_length_is_rejected_before_sending() {
        let mut transport = mock(Vec::new());
        let error = present_session_grant(&mut transport, &[0u8; 10])
            .await
            .unwrap_err();
        assert!(matches!(error, PirError::Protocol(_)), "{error:?}");
        assert!(transport.last_request.lock().unwrap().is_empty());
    }

    #[test]
    fn malformed_responses_are_protocol_errors() {
        let protocol = |bytes: &[u8]| {
            matches!(
                parse_session_grant_response(bytes),
                Err(PirError::Protocol(_))
            )
        };
        assert!(protocol(&[]));
        assert!(protocol(&[RESP_SESSION_GRANT_OK, 1, 2]));
        assert!(protocol(&[RESP_SESSION_GRANT_OK, 1, 0, 0, 0, 9]));
        assert!(protocol(&[0x42, 0, 0, 0, 0]));
        assert!(matches!(
            parse_session_grant_response(&[RESP_ERROR, 9, 0, 0, 0, b'x']),
            Err(PirError::ServerError(_))
        ));
        assert_eq!(
            parse_session_grant_response(&[RESP_SESSION_GRANT_OK, 7, 0, 0, 0]).unwrap(),
            7
        );
    }
}
