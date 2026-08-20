# BitcoinPIR experimental ARC adapter

This crate is the typed cryptographic boundary for BitcoinPIR's experimental
ARC support. It pins the Bitcoin-PIR Rust port of
`draft-ietf-privacypass-arc-crypto-01` at Git revision
`de6c1709eee0faa32985d5a452be11904ee95de4`.

The adapter:

- strictly decodes and byte-for-byte re-encodes draft-01 credential requests,
  responses, public keys, and presentations;
- verifies the complete issuer-signed `CredentialKeyBindingV1`, its current
  validity, its `ArcV1Experimental` scheme, and its canonical 99-byte P-256
  public key;
- derives request and presentation contexts only from the complete binding;
- takes `presentation_limit` only from that binding;
- keeps the four private verification scalars in zeroizing ARC types and does
  not expose them through `Debug` or an export API;
- returns a private-field `VerifiedArcSpendV1` containing the canonical tag
  and a provider-global spend key, but owns no authoritative spent set; and
- consumes the current wallet state and releases a presentation only after a
  caller-supplied durable store acknowledges the successor state.

`ArcClientStateStoreV1` is a security boundary, not an optional cache. A
production implementation must atomically compare-and-swap the predecessor
digest to the exact successor bytes, serialize access across browser tabs,
and reject rollback from stale browser backups. In the browser this normally
means encrypted IndexedDB state plus Web Locks and an independently protected
monotonic record. The trait contract deliberately has no in-memory or SQLite
implementation in this crate. Secret state must not be placed in
`localStorage`, URLs, analytics, logs, or invoice/query correlation records.
The client must likewise call
`PendingArcCredentialRequestV1::encode_for_encrypted_storage` and durably
encrypt the pending request state before submitting the issuance request;
`restore_arc_credential_request` checks the proof, context-derived scalar,
commitments, binding digest, and raw-key fingerprint before recovery.

This crate does **not** persist provider spend keys, browser state, issuer
redemptions, or settlement bookkeeping. A provider must commit
`VerifiedArcSpendV1::spend_key()` through its externally anchored spent store
before granting service. A shared issuer must atomically combine verification,
issuer-global tag consumption, and provider crediting.

`ArcExclusiveKeyLineageV1` supplies the raw-key fingerprint, complete binding
digest, and a domain-separated lineage digest needed by the provider store.
Offer installation must atomically enforce a permanent
`raw_public_key_fingerprint -> lineage_digest` mapping. The adapter does not
pretend an in-memory keyring is that authority: the provider runtime now passes
this input to the durable ProviderStore and retained-policy startup rechecks the
exact lineage. Runtime activation additionally requires the explicit
`--allow-experimental-arc` acknowledgement; that flag is for isolated testing
and does not authorize production use.

ARC remains `experimental`. Passing these functional tests and the upstream
working-group vectors is not an independent cryptographic review. The dated
review record is retained in
[`docs/archive/payment/ARC_EXPERIMENTAL_REVIEW.md`](../../../docs/archive/payment/ARC_EXPERIMENTAL_REVIEW.md);
the current production workflow selects the artifacts listed in its runbooks.

The adapter currently rejects `presentation_limit = 1`. In the pinned
draft-01 implementation that limit has an empty range-proof basis, and the
verifier's sum check cannot equal the randomized nonce commitment. Limits 2,
3, 10, and the protocol maximum 1024 are covered here. Supporting limit 1
requires an upstream/spec resolution and independent review; silently issuing
an unusable one-presentation credential is not permitted.
