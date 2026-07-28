# BitcoinPIR issuer store

This crate is the fail-closed SQLite persistence core for a BitcoinPIR payment
and credential issuer. It owns only:

- BOLT11 quote reservations, invoice lifecycle, and exact response recovery;
- one claim per quote with an independent idempotency namespace;
- authenticated, nonce-consuming private quote-status reads;
- issuer-global paid-receipt serial uniqueness;
- immutable Cashu BAT, experimental ARC and settlement key lineages;
- retained signed provider-policy and credential/Cashu epoch floors;
- current provider settlement registrations plus append-only request-key
  history for exact payout-status response recovery;
- shared-issuer redemption, settlement deposits and balanced provider ledger;
- payout intents and a durable at-least-once execution/status outbox; and
- the per-payee quote-key delegation rollback/fork guard.

The current on-disk schema is version 5. It includes the immutable lower and
upper bounds accepted for a Lightning-node-assigned invoice timestamp, an
exact reserved-quote recovery deadline, active-capacity/recovery-horizon
indexes, retained policy/key lineage, clearing ledger and payout state. Older
schemas are rejected; this crate performs no implicit migration, so any future
migration must be an explicit offline operator procedure coordinated with the
external rollback authority.

It deliberately contains no HTTP server, Lightning client, wallet keys,
external payout executor, payer identity, browser IP, PIR query, Bitcoin
address, or peer-server data.

The store canonical-decodes every persisted protocol object, verifies the
issuer-root quote-key delegation and every Ed25519-signed lifecycle snapshot,
binds lifecycle status/timestamps to an exact monotonic `state_version`, and
rejects a corrupt signed history on production open. Quote finalization still
requires the upper adapter to obtain amount/network/payee/timestamp/expiry and
payment hash from a signature-verifying BOLT11 parser or trusted Lightning
backend before constructing the signed snapshot; this persistence crate is not
an invoice parser.

Every new claim requires a `ClaimCryptographicVerifier`. Its input contains the
exact BIP340 digest plus the canonical issuance request and response; the
adapter must verify claim-key possession and method-specific cryptography
(direct receipt signatures, BAT blind signatures/DLEQ, or experimental ARC).
The store independently checks the issuer/quote/request/scheme/key/count/order
binding and derives receipt serials from the response, never from a caller
supplied list. ARC decoding also requires the reviewed typed ARC canonicalizer.
An exact durable replay bypasses the live deadline/verifier so recovery remains
possible after expiry or signer outage.

Every successful mutation first commits SQLite, then compare-and-swaps the new
generation and rolling commitment into a required, independently durable
`IssuerRollbackFloorAuthorityV1`. A value or `CommitMarker` is returned only
after that authority confirms the exact new generation. If the SQLite commit
or external CAS outcome is uncertain, the operation fails closed and the
caller must recover by replaying its exact idempotent request.

Raw HTTP idempotency keys are accepted transiently, converted to
endpoint-domain-separated digests, and never stored. Canonical request replay
images replace the raw key field with that digest while a separate request
digest commits to the complete original wire bytes. Incoming Lightning payment
preimages remain in the Lightning node; this store retains only the invoice,
payment hash, and an authoritative settlement-evidence digest.

`IssuerStore::quote` is an internal persistence lookup, not an unauthenticated
HTTP API. A network adapter must use `consume_quote_status_request`, backed by a
reviewed BIP340 verifier, before returning invoice or status; knowing a quote ID
is insufficient. The method returns a narrow `AuthenticatedQuoteStatus` with
only the exact signed snapshot and public lifecycle coordinates; backend
labels, payment hashes, replay images, and settlement evidence remain internal.
Only a domain-separated nonce digest is stored, and the status-service clock
may not move below its durable floor.

Both `create` and `open_existing` require the rollback authority; there is no
unprotected open API. The authority record binds the random store-instance ID,
issuer ID, Lightning network, schema version, generation, and rolling
commitment. It must be linearizable, durable, and outside the backup/restore
domain of the SQLite database and WAL. A stale generation, a different
commitment at the same generation, a missing record, or an authority outage is
fatal.

SQLite commits before the external CAS so the store can recover from a lost
CAS response without ever acknowledging an uncommitted database write. On
open, an exact authority match is accepted. The only automatically recoverable
mismatch is exactly one SQLite successor whose parent equals the authoritative
commitment; the store CAS-anchors that successor before serving. A database two
or more generations ahead, a same-generation fork, or an authority ahead of
SQLite fails closed. This one-successor rule prevents a process from stacking
unanchored mutations.

All issuer replicas must use the same strongly ordered external authority. A
process-local mutex, a copy stored beside SQLite, or a caller-managed integer
floor is not sufficient. Deployments without such an authority must not expose
paid issuance.

`RemoteIssuerRollbackFloorAuthorityV1` is the production remote adapter. It
requires a pinned-HTTPS rollback-authority client and a client-only value codec
bound to the same authority instance, namespace, and Ed25519 client key. The
authority receives only a fixed-size opaque AEAD record and its revision. Each
operation performs a fresh signed read and an exact compare-and-swap; remote,
signature, binding, authentication, decoding, timeout, and ambiguous-outcome
failures have no local fallback. `SqliteIssuerRollbackFloorAuthorityV1`
remains an explicit development/test adapter and is not an independent
production authority.

An outcome-unknown CAS is reconciled in-process with the same operation ID and
exact expected/desired opaque records. Following process loss, V1 performs a
fresh authenticated read and converges only when the decoded logical floor is
the expected or desired floor; it does not claim to replay the same remote
operation-log entry across restart. That stronger property requires durable
storage of the operation ID and both opaque records before the first CAS.

Floor-only restart convergence is safe for this trait because issuer SQLite
commits before anchoring, permits at most one unanchored generation, and binds
each exact one-step successor to the same issuer, network, store instance, and
schema with a changed rolling commitment. A fresh authority read equal to the
SQLite successor proves the lost CAS completed; equality with its predecessor
permits exactly that successor CAS. Missing, advanced, or forked observations
remain fatal to the issuer store.

Every quote, authenticated status, retained-policy/key-lineage, clearing,
ledger, settlement and payout mutation uses the same commit-then-CAS barrier.
Exact idempotent replays do not create a generation, but still require the
database and authority to match before returning.

Provider registration rotation keeps one mutable current row and writes every
accepted epoch, including the current epoch, into digest-addressed history in
the same anchored transaction. Only the current row authorizes fresh reads or
financial mutations. A historical request key may authenticate only an exact
payout-status request whose request digest already appears in the payout's
durable latest signed status response. Registration history has no V1 garbage
collector: deleting it can strand a lost-response retry, and any future archive
or retention policy needs a separately reviewed recovery proof.

Read APIs also check the authority both before and after materializing their
result. A concurrent SQLite successor that appears in the commit-before-CAS
window must be externally anchored before the read can return; authority
failure or a fork discards the local result. A concurrent read may return an
older already-anchored snapshot, so callers must still tolerate ordinary stale
reads and use idempotent recovery.

`quote`, `quote_by_creation_idempotency_key`, and
`quote_by_backend_label` return an internal `QuoteRecord`, including invoice
and payment-hash fields. `consume_quote_status_request` returns only a narrow
authenticated status object, although its exact signed quote snapshot itself
contains the invoice. `claim` and `claim_by_idempotency_key` return internal
claim records whose exact response contains issued credentials. None of these
internal persistence reads is authorization to expose the data over a network.

This crate persists verified shared-issuer redemption, settlement deposits,
provider balances and the payout outbox. It deliberately does not perform
Lightning RPC, execute an external payout, operate an HTTP listener, or decide
commercial policy; those effects remain in bounded adapters/workers. Passing
this crate's tests is therefore not sufficient evidence to enable a payment
service or real-funds payout.
