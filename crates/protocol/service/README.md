# pir-service-protocol

Pure shared types and strict canonical codecs for BitcoinPIR service offers and
query authorization. This crate deliberately contains no network, filesystem,
Lightning, Cashu, ARC, database, or provider business logic, so the native
server, Rust SDK, WASM SDK, Web client, and issuer can share one wire contract.

The normative design is in `docs/payment/ARCHITECTURE.md` and
`docs/payment/PROTOCOL.md`.

## Provider authorization boundary

Providers must enter authorization through `bind_auth_begin_v1`. It binds all
untrusted `AuthBeginV1` selectors to one `VerifiedServiceOfferV1`, takes limits
from that offer's signed scope-policy entry, resolves the complete operation
through `TrustedServiceCatalogV1`, and then decodes the proof according to the
signed scheme/free mode. ARC cannot pass this boundary without a typed
decode/re-encode canonicalizer.

The returned `BoundAuthAttemptV1` establishes structural and policy/catalog
binding only. It does **not** prove that a payment or credential is valid, fresh,
or unspent, and it does not consume a capability. The runtime gate must already
be on the authenticated secure channel and must perform method-specific
cryptographic verification plus the required atomic free-admission/spend
transition before permitting any backend work.
