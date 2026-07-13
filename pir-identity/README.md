# pir-identity

Operator-signed server identity primitives for BitcoinPIR.

The crate implements a two-tier Ed25519 chain:

1. An offline operator key signs an `IdentityCert` for a server identity key.
2. That identity key signs a per-boot `ChannelManifest` binding the server ID,
   encrypted-channel public key, binary hash, git revision, and database
   manifest roots.

Clients with the operator public key pinned can authenticate the encrypted
channel on servers without hardware attestation and add defense in depth on
SEV-SNP hosts. The crate contains only canonical encoding and cryptographic
sign/verify logic; filesystem, network, and operator tooling live elsewhere in
the BitcoinPIR workspace.

See the module documentation in `src/lib.rs` and
[`docs/OPERATOR_IDENTITY.md`](../docs/OPERATOR_IDENTITY.md) for the protocol and
deployment model.
