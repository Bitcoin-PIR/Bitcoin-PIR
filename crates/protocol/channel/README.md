# pir-channel

End-to-end encrypted channel primitives for Bitcoin PIR.

X25519 ECDH handshake (static + ephemeral, both for forward secrecy
and identity binding to the SEV-SNP-attested server pubkey) plus
ChaCha20-Poly1305 AEAD frame wrapping with replay protection.

Used by both `pir-runtime-core` (server) and `pir-sdk-client`
(client) so cloudflared (or any other transport-layer intermediary)
sees only ciphertext PIR frames.

See module docs in `src/lib.rs` for the full handshake protocol +
frame format.
