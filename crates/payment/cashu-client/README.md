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
NUT-09. This includes HTTP 400 carrying a well-formed NUT-00 error: the
standard error envelope does not prove that NUT-03 did not commit, so it never
deletes or releases the durable intent. NUT-07 is observational: even an
`UNSPENT` response cannot authorize a new output set because the timed-out
request may still commit. Service is
granted only after exact amount/keyset/order checks, concrete NUT-12 and local
`(secret, r) -> B_` verification, unblinding, encrypted note persistence, and
an at-most-once durable grant claim. `WalletStored -> GrantIssued`, the
note-only custody lot, and every cross-lot `Y` uniqueness row commit atomically;
a service grant can never exist without provider-owned note custody. The
durable intent and returned typestate
also carry a digest of the exact signed policy, scope, and offer; equal mint IDs
and equal prices cannot move a grant to another backend or workload.

`StandardCashuClientV1::new` requires type-separated recovery and custody AEAD
boundaries plus explicit finite value/note exposure limits. Limits apply per
checked `(mint_id, unit)` before NUT-03; there is no default or unlimited
production bypass. Recovery ciphertext contains request/recovery material.
Custody ciphertext contains only the normalized mint endpoint, unit, active
keyset, provider-created amount/secret/C notes, and domain-separated Y/note-set
digests. It contains no user input proof, request/response JSON,
offer/intent/query identifier, or exact timestamp.

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
for `pir_service_store::ProviderStore` schema v7. Each actual intent mutation
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
admission. It still enforces finite exposure caps, atomic custody insertion,
and cross-swap Y uniqueness; there is no security-relevant test bypass.
Production operation still requires a reviewed implementation of
the ProviderStore external CAS authority; there is no process-local or SQLite
fallback.

ProviderStore performs no implicit schema migration. Every earlier or unknown
schema is rejected on open; deployment must use the matching explicit offline
migration runbook.

Recovery encryption is also external. `CashuRecoveryCipherV1` implementations
must use authenticated encryption, fresh nonces, key epochs whose keys live
outside the swap database, and the exact supplied associated data. The store
contains public digests, coarse hour buckets, and ciphertext only; proof
secrets, output secrets, blinding scalars, promises, and received note secrets
must never be plaintext columns or logs.

The recovery plaintext inside that AEAD is a deterministic, length-delimited
binary V1 envelope, not nested JSON. It has a fixed magic/version/header,
bounded raw request/response JSON byte fields, fixed-size output and received
note records, checked counts, and exact EOF. Decoder-owned secret buffers are
zeroizing and allocated at their complete bound before any copy. The previous
serde-JSON recovery plaintext was development-only and never released; this is
an intentional fresh replacement with no legacy-ciphertext migration path.

## Transport boundary

`CashuMintTransportV1` receives the signed manifest endpoint and one fixed
route (`/v1/swap`, `/v1/restore`, or `/v1/checkstate`). Production transports
must require HTTPS, reject redirects, append only that route, enforce JSON
content type and response bounds, and never accept a mint URL supplied by the
authorization payload.

## Offline custody and opt-in CDK interop

Offline tooling reconstructs typed AAD with `CashuCustodyAadV1::from_parts`,
uses `ChaCha20Poly1305CustodyDecryptorV1` (which cannot seal), and aggregates
authenticated bundles with `encode_cashub_from_custody_bundles_v1`. Rotation
lots sharing a mint/unit are grouped by full keyset ID; short-ID collisions use
the full 33-byte ID. The deterministic `cashuB` result uses CDK-compatible
`m,u,t` root ordering, omits DLEQ secrets and memos, and is returned in a
zeroizing string. The public upper-bound helper fixes a batch at most 512
proofs and 16 keysets under the 64 KiB CBOR ceiling.

`check_cashu_custody_bundles_once_v1` is the owner-initiated retirement helper.
It performs exactly one bounded NUT-07 request for same-endpoint/unit bundles,
requires the response to preserve the exact ordered `Y` list, accepts only the
canonical three states and a required bounded nullable witness field, and
returns transient zeroizing `Y`/state mappings plus per-lot commitments. It
does not poll or write ProviderStore. The admin layer may commit only exact
all-`SPENT` results and derives a distinct observation digest for every export;
the wider HTTP-batch digest must never be persisted across exports. This proves
only that the old notes are spent, not NUT-05, Lightning settlement or payout.

The ignored CDK codec test consumes a disposable token only from the process
environment and never prints or commits it. The separate
`tests/cdk_nut03_interop.rs` target consumes owner-only token/keyset files from
the repository runner, maps one synthetic HTTPS manifest identity to its exact
validated loopback mint, and proves a real CDK NUT-03 response passes DLEQ
verification before the grant and custody lot commit atomically:

```sh
BITCOINPIR_CDK_CASHUB_TOKEN='cashuB…' \
  cargo test -p pir-cashu-client cdk_cashub_token_strict_semantic_round_trip \
  -- --ignored --exact

cargo test -p pir-cashu-client --features insecure-dev-sqlite-store \
  --test cdk_nut03_interop \
  real_cdk_nut03_swap_verifies_dleq_and_commits_custody -- --ignored --exact
```

Use the repository's disposable CDK runner to populate the variable. This
does not relax the production HTTPS/WebPKI transport boundary.
