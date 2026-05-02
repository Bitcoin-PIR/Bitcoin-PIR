//! Server-side admin authentication and (Slice 3b) DB upload state.
//!
//! ## Authentication (Slice 3a)
//!
//! Per-WebSocket-connection ed25519 challenge/response:
//!
//! 1. Client sends `REQ_ADMIN_AUTH_CHALLENGE`.
//! 2. Server generates a fresh 32-byte nonce, stashes it in
//!    [`AdminConnectionState::pending_challenge`], returns it.
//! 3. Client signs `ADMIN_AUTH_DOMAIN_TAG || nonce` with their
//!    ed25519 sk and sends `REQ_ADMIN_AUTH_RESPONSE { signature }`.
//! 4. Server calls [`AdminConnectionState::verify_response`] which
//!    consumes the pending challenge and verifies the signature
//!    against [`AdminConfig::admin_pubkey`]. On success the
//!    connection is marked authenticated for the rest of its
//!    lifetime; on failure the pending challenge is dropped (force
//!    re-issue).
//!
//! Disconnecting and reconnecting requires a fresh challenge — admin
//! state never persists across WebSocket lifetimes. This is the cheap
//! way to get session expiry without a clock.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::protocol::ADMIN_AUTH_DOMAIN_TAG;

/// Server-wide admin config — loaded once at startup. Holds the
/// ed25519 public key the operator's `bpir-admin` CLI will sign with.
#[derive(Clone, Debug)]
pub struct AdminConfig {
    pub admin_pubkey: VerifyingKey,
}

impl AdminConfig {
    /// Parse an admin pubkey from a 64-character lowercase hex string
    /// (the on-the-wire representation of a 32-byte ed25519 pubkey).
    pub fn from_hex(hex: &str) -> Result<Self, String> {
        if hex.len() != 64 {
            return Err(format!(
                "admin pubkey must be 64 hex chars (32 bytes), got {} chars",
                hex.len()
            ));
        }
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            let byte_str = &hex[i * 2..i * 2 + 2];
            bytes[i] = u8::from_str_radix(byte_str, 16)
                .map_err(|_| format!("invalid hex at byte {}: {:?}", i, byte_str))?;
        }
        let admin_pubkey = VerifyingKey::from_bytes(&bytes)
            .map_err(|e| format!("invalid ed25519 pubkey bytes: {}", e))?;
        Ok(Self { admin_pubkey })
    }
}

/// Per-connection auth state. Created fresh for each WebSocket
/// accept; lives for the connection's lifetime.
#[derive(Default, Debug)]
pub struct AdminConnectionState {
    /// 32-byte nonce returned by the most recent
    /// `REQ_ADMIN_AUTH_CHALLENGE`. `None` if no challenge is
    /// outstanding (or if a response just consumed it).
    pub pending_challenge: Option<[u8; 32]>,
    /// `true` once a valid `REQ_ADMIN_AUTH_RESPONSE` has been
    /// processed. Stays true until the connection drops.
    pub authenticated: bool,
}

impl AdminConnectionState {
    /// Generate and store a fresh challenge nonce. Returns the bytes
    /// to send to the client. Replaces any previously-pending
    /// challenge (forces the client to use the latest one).
    pub fn issue_challenge(&mut self) -> [u8; 32] {
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce).expect("getrandom failed — kernel CSPRNG broken");
        self.pending_challenge = Some(nonce);
        nonce
    }

    /// Verify a client-supplied signature against the pending
    /// challenge and the server's configured admin pubkey.
    ///
    /// Always consumes the pending challenge (success or failure) so
    /// a failed attempt forces the client to request a new challenge
    /// — replays of the same signature against fresh challenges are
    /// impossible.
    pub fn verify_response(
        &mut self,
        signature: &[u8; 64],
        config: &AdminConfig,
    ) -> Result<(), AuthError> {
        let nonce = self.pending_challenge.take().ok_or(AuthError::NoChallenge)?;

        let mut signed_blob = Vec::with_capacity(ADMIN_AUTH_DOMAIN_TAG.len() + 32);
        signed_blob.extend_from_slice(ADMIN_AUTH_DOMAIN_TAG);
        signed_blob.extend_from_slice(&nonce);

        let sig = Signature::from_bytes(signature);
        config
            .admin_pubkey
            .verify(&signed_blob, &sig)
            .map_err(|_| AuthError::BadSignature)?;

        self.authenticated = true;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// Client sent REQ_ADMIN_AUTH_RESPONSE without first having a
    /// pending REQ_ADMIN_AUTH_CHALLENGE issued (or the previous
    /// challenge was already consumed).
    NoChallenge,
    /// Signature verification failed against the server's pubkey.
    BadSignature,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoChallenge => write!(f, "no pending challenge — call REQ_ADMIN_AUTH_CHALLENGE first"),
            Self::BadSignature => write!(f, "signature did not verify against admin pubkey"),
        }
    }
}

impl std::error::Error for AuthError {}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn keypair() -> (SigningKey, AdminConfig) {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).unwrap();
        let sk = SigningKey::from_bytes(&seed);
        let cfg = AdminConfig {
            admin_pubkey: sk.verifying_key(),
        };
        (sk, cfg)
    }

    fn sign(sk: &SigningKey, nonce: &[u8; 32]) -> [u8; 64] {
        let mut blob = Vec::new();
        blob.extend_from_slice(ADMIN_AUTH_DOMAIN_TAG);
        blob.extend_from_slice(nonce);
        sk.sign(&blob).to_bytes()
    }

    #[test]
    fn happy_path_authenticates() {
        let (sk, cfg) = keypair();
        let mut state = AdminConnectionState::default();
        assert!(!state.authenticated);

        let nonce = state.issue_challenge();
        let sig = sign(&sk, &nonce);
        state.verify_response(&sig, &cfg).unwrap();

        assert!(state.authenticated);
        // Pending challenge should be cleared after consume.
        assert!(state.pending_challenge.is_none());
    }

    #[test]
    fn response_without_challenge_is_no_challenge_error() {
        let (sk, cfg) = keypair();
        let mut state = AdminConnectionState::default();
        let bogus_nonce = [0u8; 32];
        let sig = sign(&sk, &bogus_nonce);
        let err = state.verify_response(&sig, &cfg).unwrap_err();
        assert_eq!(err, AuthError::NoChallenge);
        assert!(!state.authenticated);
    }

    #[test]
    fn signature_against_wrong_nonce_fails() {
        let (sk, cfg) = keypair();
        let mut state = AdminConnectionState::default();

        // Issue and discard one nonce
        let _ = state.issue_challenge();
        // Sign a DIFFERENT nonce
        let wrong_nonce = [0xFFu8; 32];
        let sig = sign(&sk, &wrong_nonce);

        let err = state.verify_response(&sig, &cfg).unwrap_err();
        assert_eq!(err, AuthError::BadSignature);
        assert!(!state.authenticated);
        // Pending challenge consumed even on failure
        assert!(state.pending_challenge.is_none());
    }

    #[test]
    fn wrong_keypair_fails() {
        let (_real_sk, cfg) = keypair();
        let (attacker_sk, _) = keypair(); // different sk
        let mut state = AdminConnectionState::default();
        let nonce = state.issue_challenge();
        let sig = sign(&attacker_sk, &nonce);
        let err = state.verify_response(&sig, &cfg).unwrap_err();
        assert_eq!(err, AuthError::BadSignature);
    }

    #[test]
    fn replay_of_earlier_signature_fails() {
        // Even if attacker captures a valid signature, they can't
        // replay it: the second challenge has a different nonce.
        let (sk, cfg) = keypair();
        let mut state1 = AdminConnectionState::default();
        let nonce1 = state1.issue_challenge();
        let sig1 = sign(&sk, &nonce1);
        state1.verify_response(&sig1, &cfg).unwrap();

        // New connection, new state
        let mut state2 = AdminConnectionState::default();
        let _nonce2 = state2.issue_challenge();
        // Replay the OLD signature against the NEW challenge
        let err = state2.verify_response(&sig1, &cfg).unwrap_err();
        assert_eq!(err, AuthError::BadSignature);
    }

    #[test]
    fn config_from_hex_roundtrip() {
        let (sk, _) = keypair();
        let pk_bytes = sk.verifying_key().to_bytes();
        let hex: String = pk_bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let cfg = AdminConfig::from_hex(&hex).unwrap();
        assert_eq!(cfg.admin_pubkey.to_bytes(), pk_bytes);
    }

    #[test]
    fn config_from_hex_rejects_wrong_length() {
        let err = AdminConfig::from_hex("deadbeef").unwrap_err();
        assert!(err.contains("64 hex chars"), "got: {}", err);
    }

    #[test]
    fn config_from_hex_rejects_non_hex_chars() {
        let bad = "z".repeat(64);
        let err = AdminConfig::from_hex(&bad).unwrap_err();
        assert!(err.contains("invalid hex"), "got: {}", err);
    }

    #[test]
    fn issue_challenge_overwrites_pending() {
        let (sk, cfg) = keypair();
        let mut state = AdminConnectionState::default();
        let n1 = state.issue_challenge();
        let n2 = state.issue_challenge();
        // Different nonces (CSPRNG)
        assert_ne!(n1, n2);
        // Stored challenge is the latest
        assert_eq!(state.pending_challenge, Some(n2));
        // Signing the old nonce should fail (it's no longer the pending one)
        let sig_old = sign(&sk, &n1);
        let err = state.verify_response(&sig_old, &cfg).unwrap_err();
        assert_eq!(err, AuthError::BadSignature);
    }
}
