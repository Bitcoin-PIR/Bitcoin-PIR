# BitcoinPIR shared issuer clearing

This crate is the reviewed cryptographic adapter between canonical shared
issuer credentials and `pir-issuer-store`'s atomic redemption typestate. It
verifies provider-bound Free anonymous tickets and Cashu BAT proofs, and wires
the draft-01 ARC verifier only as an explicitly experimental method.

It can construct issuer-signed ledger-credit or blinded Cashu settlement
responses. Blind-signature proof nonces are deterministically derived from an
issuer-secret response key and the exact redeem request so a crash before the
SQLite commit can reconstruct the same candidate response. The store must
commit that exact response, the global credential spend key, and balanced
ledger effects before any success is returned.

This crate has no HTTP, Lightning, payout executor, PIR query, payer identity,
invoice, payment hash, or browser data. ARC remains experimental pending an
independent cryptographic review.
