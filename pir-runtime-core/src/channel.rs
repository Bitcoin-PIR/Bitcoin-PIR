//! Long-lived X25519 channel keypair for end-to-end encrypted client
//! sessions.
//!
//! The pure-crypto handshake / AEAD primitives live in `pir-channel`
//! (so the same code is callable from the wasm32 client). This module
//! adds the server-side pieces that pir-channel doesn't deal with:
//! generating + holding the long-lived static keypair, and bridging
//! to `pir_channel::ServerHandshake` for the per-connection handshake.
//!
//! Re-exports `pir_channel::ServerHandshake` and `pir_channel::Session`
//! for callers that want to drive the handshake from this crate.
//!
//! ## Why this exists
//!
//! cloudflared sits between the browser and `unified_server` and
//! terminates TLS at the tunnel edge — meaning the cloudflared process
//! (and Cloudflare's infrastructure) sees plaintext PIR query/response
//! frames today. The PIR property hides *which* scripthash the client
//! is querying from the server; it does NOT hide query bytes from any
//! party between the browser and the server. Closing that gap requires
//! an inner encrypted channel keyed off something cloudflared cannot
//! influence.
//!
//! ## How
//!
//! `unified_server` generates a [`ChannelKeypair`] inside its SEV-SNP
//! guest at startup. The public half is committed to REPORT_DATA via
//! `pir_core::attest::build_report_data` (V2 layout), so the chip-
//! signed attestation report binds *this exact pubkey* to *this
//! attested boot*. Clients that verify the report know subsequent
//! ECDH handshakes terminate inside the attested guest, not inside
//! cloudflared or anywhere upstream.
//!
//! The secret half stays in process memory inside the guest; SEV-SNP
//! memory encryption keeps it from any host-side observer. It is
//! never written to disk and is regenerated on every boot — so a
//! single binary update + UKI re-bake forces key rotation
//! organically.
//!
//! ## Slice scope
//!
//! Slice A (this module): keypair generation + pubkey accessor.
//! Slice B (next): per-session ECDH + AEAD frame wrapping.

use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

// Re-export the handshake types so server code can drive a per-
// connection handshake without depending on pir-channel directly.
pub use pir_channel::{Direction, Session, ServerHandshake};

/// X25519 keypair the server uses for the inner encrypted channel.
///
/// Generate one with [`Self::generate`] at process start and stash it
/// in your server state. The public half goes into [`crate::table::ServerState::server_static_pub`]
/// (and from there into REPORT_DATA + AttestResult); the secret half
/// is consumed by per-session handshakes (Slice B — not yet wired).
pub struct ChannelKeypair {
    secret: StaticSecret,
    public: PublicKey,
}

impl ChannelKeypair {
    /// Generate a fresh keypair using OS randomness.
    ///
    /// Inside a SEV-SNP guest the OS RNG is seeded from `RDRAND` /
    /// `RDSEED` (the kernel uses those as entropy sources for
    /// `getrandom(2)`), and the in-memory state is encrypted by the
    /// chip — so a host-side observer can't recover the secret.
    pub fn generate() -> Self {
        // x25519-dalek 2.x uses rand_core 0.6; pull entropy from OsRng
        // (which on Linux ultimately reads /dev/urandom → getrandom(2)).
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let secret = StaticSecret::from(seed);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Raw bytes of the X25519 public key (RFC 7748 §6.1, 32 bytes).
    pub fn public_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    /// Borrow the secret half. The server uses this to construct a
    /// per-connection [`ServerHandshake`] when a client sends
    /// REQ_HANDSHAKE; the handshake then derives the session key
    /// against the client's ephemeral pubkey.
    pub fn secret(&self) -> &StaticSecret {
        &self.secret
    }

    /// Convenience: build a per-connection [`ServerHandshake`] using
    /// this server's long-lived static secret + a freshly-minted
    /// ephemeral seed (pulled from `OsRng`). Each call mints a new
    /// ephemeral keypair — every session has its own forward-secret
    /// half.
    pub fn new_handshake(&self) -> ServerHandshake<'_> {
        let mut eph_seed = [0u8; 32];
        OsRng.fill_bytes(&mut eph_seed);
        ServerHandshake::new(&self.secret, eph_seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_pubkey_is_32_bytes() {
        let kp = ChannelKeypair::generate();
        // Just ensure the type produces a non-trivial 32-byte pubkey
        // (X25519 effectively never produces all-zero on real entropy,
        // but assert the length contract — that's what the wire format
        // counts on).
        let pub_bytes = kp.public_bytes();
        assert_eq!(pub_bytes.len(), 32);
    }

    #[test]
    fn two_keypairs_have_different_pubkeys() {
        // Birthday paradox is astronomical for 32 fresh bytes, so this
        // doubles as a smoke test that we're actually pulling from OsRng
        // each time and not returning a constant.
        let a = ChannelKeypair::generate();
        let b = ChannelKeypair::generate();
        assert_ne!(a.public_bytes(), b.public_bytes());
    }

    #[test]
    fn pubkey_matches_secret_via_diffie_hellman_self_test() {
        // Sanity: the public half of the keypair really is X25519(secret, BASE)
        // — i.e. an out-of-band recipient using PublicKey::from(secret) gets
        // the same bytes. Catches a hypothetical wiring bug where the struct's
        // pubkey is divorced from its secret.
        let kp = ChannelKeypair::generate();
        let derived = PublicKey::from(kp.secret());
        assert_eq!(*derived.as_bytes(), kp.public_bytes());
    }
}
