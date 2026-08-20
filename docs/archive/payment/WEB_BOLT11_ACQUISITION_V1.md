# Web BOLT11 capability acquisition V1 (archived)

This document describes the browser implementation in
`web/src/service-acquisition.ts`. It is payment/credential acquisition, not
PIR admission: no invoice, payment hash, preimage, quote ID, or claim key is
ever sent to a PIR server.

## Trust and ordering

The caller first completes the ordinary strict provider verification flow and
obtains a `WasmAcceptedServicePolicyV1`. The selected provider-local signed
offer fixes the scope, offer ID, issuer ID, endpoint, exact millisatoshi
amount, credential scheme/count, key binding, and validity horizons.

For one explicit purchase the browser then:

1. fetches the issuer-root-signed current quote-key delegation;
2. verifies it in WASM against the offer issuer and the caller-pinned
   Lightning network/payee;
3. atomically advances the `(issuer, network, payee)` rollback checkpoint
   across tabs;
4. encrypts an opaque recovery record in IndexedDB;
5. posts one canonical quote intent;
6. parses and verifies the complete BOLT11 invoice in Rust/WASM;
7. persists the accepted signed quote before returning invoice text to UI;
8. polls only when explicitly requested, with a fresh BIP340-authenticated
   status nonce;
9. prepares and persists one exact signed/idempotent claim before posting it;
10. verifies and finalizes every returned credential; and
11. installs the whole capability batch and deletes quote recovery in one
    IndexedDB transaction.

`start`, `ensureQuote`, `pollStatus`, and `claim` issue at most one HTTP
request. There is no hidden retry loop. A lost quote or claim response leaves
the recovery record intact; `resume` performs no I/O, and a later explicit
call replays the byte-identical idempotent intent/claim.

## HTTP contract

| Operation | Method/path | Request content type | Response content type |
| --- | --- | --- | --- |
| Current delegation | `GET /v1/quote-keys/current` | none | `application/vnd.bitcoinpir.bolt11-quote-key-delegation-v1` |
| Retained delegation | `GET /v1/quote-keys/{32 lowercase hex}` | none | same as above |
| Create/recover quote | `POST /v1/quotes/bolt11` | `application/vnd.bitcoinpir.bolt11-quote-intent-v1` | `application/vnd.bitcoinpir.bolt11-quote-v1` |
| Poll status | `POST /v1/quotes/{quote_id}/status` | `application/vnd.bitcoinpir.bolt11-quote-status-request-v1` | `application/vnd.bitcoinpir.bolt11-quote-v1` |
| Claim | `POST /v1/quotes/{quote_id}/claim` | `application/vnd.bitcoinpir.bolt11-quote-claim-envelope-v1` | `application/vnd.bitcoinpir.credential-issuance-response-v1` |

Requests omit cookies and referrers, disable caches, and reject redirects.
Production endpoints must be HTTPS origins. Plain HTTP is accepted only for
explicitly enabled loopback integration tests.

## Credential methods

- Direct receipts: Ed25519 signatures and exact quote/binding/count are
  verified before receipt bytes enter the capability vault.
- BitcoinPIR Cashu BAT: secrets and blinding scalars stay in opaque encrypted
  WASM recovery. Every NUT-12 DLEQ proof and echoed blinded message is checked
  before unblinding into a single-use BAT.
- ARC: remains `experimental`. Requests use the pinned typed ARC adapter and
  binding-derived contexts. Finalized client state is persisted before a
  presentation transition can release wire bytes.
- Standard Cashu eCash: uses the standard Cashu mint/NUT-04 client, not the
  custom BOLT11 claim endpoint.

## Browser persistence boundary

The IndexedDB schema exposes only random record IDs and AES-GCM ciphertexts.
The encrypted recovery plaintext contains the exact issuer endpoint, issuer
ID, Lightning network, expected compressed payee key, provider/scope/offer
binding, and opaque WASM state. These fields are authenticated so a recovery
cannot be resumed under a different issuer or payee. It contains no Bitcoin
address, PIR query, query result, peer-provider ID, or server-pair identifier.
The invoice is present only inside the encrypted WASM state and is deleted
after atomic credential installation. Upgrading IndexedDB from V3 to V4
discards contextless in-flight recovery rows while retaining capabilities and
anti-rollback checkpoints; such old quotes must not be resumed. Physically
retained V3 capabilities acquired via BOLT11 also lack this context and are
therefore intentionally unspendable on strict current or retained paths.
Non-BOLT contextless capabilities remain usable. A funded production V3
deployment would require an explicit migration/refund policy before V4 rollout.

The non-extractable WebCrypto key protects against accidental plaintext
persistence, not XSS or a copied/unlocked browser profile. Production must
therefore retain the existing CSP, dependency pinning, and origin-isolation
requirements.
