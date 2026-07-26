# BitcoinPIR standard Cashu merchant adapter

This crate implements the fail-closed core for accepting ordinary standard
Cashu eCash through a mint pinned by a signed BitcoinPIR service offer.

The caller first obtains `StandardCashuSpendCheckV1` from
`check_standard_cashu_spend_for_offer` and supplies the same private-field
`VerifiedServiceOfferV1`. The adapter reruns the policy check and requires the
exact result, then checks it against the canonical spend and pinned manifest;
a caller cannot construct the public result fields to bypass signed pricing.
It creates exact-value provider-controlled outputs (V1 has no change), encrypts
the exact NUT-03 request plus every output secret and blinding scalar, and
durably stores the intent before submitting it.

After `PREPARED -> SUBMITTED`, the adapter never sends NUT-03 again. A lost or
invalid response is recovered only with the identical ordered `B_` values via
NUT-09. NUT-07 is observational: even an `UNSPENT` response cannot authorize a
new output set because the timed-out request may still commit. Service is
granted only after exact amount/keyset/order checks, concrete NUT-12 and local
`(secret, r) -> B_` verification, unblinding, encrypted note persistence, and
an at-most-once durable grant claim. The durable intent and returned typestate
also carry a digest of the exact signed policy, scope, and offer; equal mint IDs
and equal prices cannot move a grant to another backend or workload.

Conditional NUT-10/NUT-11/NUT-14 proofs fail closed. The provider never writes
standard Cashu inputs to BitcoinPIR's provider-local bearer spent-set; the
mint's atomic NUT-03 invalidation is authoritative.

## Production store boundary

`CashuSwapStoreV1` requires an independently durable, linearizable
anti-rollback floor for every successful mutation. That authority must not be
inside the protected SQLite database, WAL, or backup set. A stale snapshot at
`PREPARED` could otherwise resubmit NUT-03; a stale snapshot at `WALLET_STORED`
could issue the grant twice.

On native targets, the default build implements `CashuSwapStoreV1` directly
for `pir_service_store::ProviderStore` schema v4. Each actual intent mutation
advances the ProviderStore generation and the external rollback-floor CAS.
`begin_submission` returns `true` only after `PREPARED -> SUBMITTED` is both
committed and externally anchored; the caller treats every error as a hard
prohibition on sending NUT-03. A lost CAS response can later reconcile the
already-submitted state, but can never recreate `PREPARED` or authorize a
second submission. Only the final at-most-once grant claim advances
`spend_commit_seq`.

The included `InsecureDevSqliteCashuSwapStoreV1` deliberately does **not**
provide that authority. It is available only to unit tests or with the
explicit `insecure-dev-sqlite-store` feature, and must never back production
admission. Production operation still requires a reviewed implementation of
the ProviderStore external CAS authority; there is no process-local or SQLite
fallback.

ProviderStore performs no implicit schema migration. Schema v3 and every
unknown schema are rejected on open. See
[`docs/payment/PROVIDER_STORE_V4_MIGRATION.md`](../../../docs/payment/PROVIDER_STORE_V4_MIGRATION.md)
for the explicit offline migration design.

Recovery encryption is also external. `CashuRecoveryCipherV1` implementations
must use authenticated encryption, fresh nonces, key epochs whose keys live
outside the swap database, and the exact supplied associated data. The store
contains public digests, coarse hour buckets, and ciphertext only; proof
secrets, output secrets, blinding scalars, promises, and received note secrets
must never be plaintext columns or logs.

## Transport boundary

`CashuMintTransportV1` receives the signed manifest endpoint and one fixed
route (`/v1/swap`, `/v1/restore`, or `/v1/checkstate`). Production transports
must require HTTPS, reject redirects, append only that route, enforce JSON
content type and response bounds, and never accept a mint URL supplied by the
authorization payload.
