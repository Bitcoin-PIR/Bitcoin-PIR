# BitcoinPIR payment cryptography adapters

This crate upgrades explicitly unverified payment-protocol transcripts into
private-field evidence types after concrete cryptographic verification.

Implemented:

- BIP340 prehash verification for paid quote claims;
- BIP340 prehash verification for authenticated quote-status polling; and
- browser-compatible BIP340 prehash signing with caller-provided auxiliary
  randomness; and
- concrete Cashu NUT-12 verification for blind issuance responses, including
  the specification's lowercase-hex challenge transcript and official vectors;
- wallet-side Cashu hash-to-curve, blinding, DLEQ-gated unblinding, and private
  `r` retention; and
- issuer-side Cashu blind signing with caller-randomized NUT-12 DLEQ proofs,
  while denomination secret scalars remain inside the zeroizing keyring; and
- an issuer-side zeroizing denomination-key registry that verifies ordinary
  NUT-00 notes while failing closed on NUT-10 conditional secrets/witnesses.

The protocol transcript is already a domain-separated SHA-256 digest. These
functions deliberately use k256's `PrehashVerifier`; using its ordinary
`Verifier` would hash the digest again and verify a different message.

Planned in this crate or a sibling audited adapter:

- concrete `lightning-invoice` BOLT11 parsing/signature validation;
- reviewed NUT-10/NUT-11/NUT-14 conditional-note adapters (V1 currently accepts
  only ordinary unconditional notes); and
- the reviewed ARC adapter. ARC remains experimental until independent review.
