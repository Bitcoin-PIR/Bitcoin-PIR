# Payment security and privacy invariants

Status: release-gating checklist. `MUST` items are fail-closed requirements.

## Invariants

1. A PIR provider receives no peer provider identity, pair ID, or common query
   ID from the payment layer.
2. Every authorization is bound to one provider, backend, workload role,
   protocol version, dataset rule, operation profile, and entitlement profile.
3. DPF capabilities do not encode client slot 0/1 unless a future cost model
   proves the shares asymmetric and the privacy model is updated.
4. Harmony hint and Harmony query are separate scopes and separate charges.
5. Payment acquisition and query authorization are separate. A PIR server and
   PIR wire never receive BOLT11, payment hash, preimage, payer identity, or
   Lightning routing data.
6. Authorization is accepted only in an authenticated, successfully upgraded
   secure channel and only after database/root/policy verification by the
   strict client.
7. A server rejects cleartext authorization frames even after a channel has
   been negotiated.
8. A client does not pay a direct provider until that provider passes strict
   identity, binary, attestation-when-available, database proof, trusted-root,
   and policy checks.
9. Client-provided amount, limit, priority, profile, context, and quota are
   untrusted. Entitlement comes only from signed server policy and issuer/key
   binding.
10. Durable spend/tag insertion is atomic, survives restart, and precedes
    `AUTH_GRANTED`.
11. Concurrent redemption of one capability has exactly one successful
    consumer.
12. One grant authorizes one bounded logical backend operation. It never
    unlocks an arbitrary connection or unrelated opcodes.
13. Mandatory preflight and inclusion/Merkle verification remain in the
    authorized opcode DFA. Payment failure never enables an insecure fallback.
14. Query or verification failure after durable spend does not remove spent
    state. This is the explicit at-most-once product policy.
15. Failures before durable spend do not consume a capability.
16. Scheme rejection errors are coarse and do not expose a signature/spent
    oracle beyond what is needed for safe client behavior.
17. Provider and issuer logs omit invoices, payment hashes/preimages, raw
    query addresses, results, peer identity, and browser recovery secrets.
18. Authentication plaintext is padded to a declared length class before
    encryption. For V1 the complete request application record is fixed at
    16,414 bytes. This hides method, scope, operation variant and proof length
    only from request-size observation by a party without channel keys; it does
    not hide them from the provider, and it does not hide authorization timing
    or the variable response shape.
19. Browser token selection and burn is atomic across tabs and binds the exact
    provider, policy digest, scope, offer and scheme in its lock and encrypted
    record authentication. No bearer token, ARC nonce state, invoice, or query
    link record is stored in `localStorage`.
20. Shared issuer private mint/ARC keys are never distributed to participating
    providers.
21. Shared issuer online redemption is an explicitly declared availability
    and timing-correlation dependency. Outage fails closed.
22. Shared redeem authenticates a registered provider clearing key even when
    signing blinded settlement outputs. Blind outputs hide only the later
    deposit-serial join; they do not hide provider identity at redeem.
23. The directory key is distinct from server/operator/payment keys. Directory
    events are discovery hints and never override live strict verification.
    Without an independent operator pin/diversity source, the directory remains
    a centralized curation/Sybil boundary and clients must not claim that live
    verification proves two providers have independent control.
24. ARC is advertised and displayed as experimental until independent review
    closes all cryptographic and implementation findings.
25. Standard Cashu eCash and `bpir_cashu_bat_v1` use distinct method IDs,
    keysets, encodings, and security claims.
26. Every paid quote is bound to a browser-generated claim public key; quote
    ID disclosure alone cannot claim issuance.
27. Policy/key rotation retains paid quote and receipt validity until their
    explicit claim/use horizons. Rotation cannot silently confiscate paid
    entitlement.
28. Directory sequence, expiry, inner operator authorization, and tombstones
    are fail-closed. Provider/method selection occurs locally from a catalog.
29. Provider-specific blind issuance necessarily reveals the target provider,
    scope, offer, and entitlement profile to the issuer even when later
    presentations are unlinkable. Signed privacy flags must not understate it.
30. Proof-level Cashu DLEQ fields and wallet blinding scalars never cross the
    PIR wire. Standard Cashu imports are normalized before authorization.
31. Accepted policy, credential-keyset, Cashu-manifest, clearing-authorization,
    and directory epochs have durable monotonic rollback floors.
32. Blind clearing commits to one issuer-approved settlement keyset and its
    recovery horizon before the provider reveals blinded outputs.
33. A quote intent binds the exact issuer-root-signed quote-key delegation,
    including network, payee, epoch and validity window. A durable per-stream
    guard rejects epoch rollback and same-epoch forks before an invoice is
    displayed or paid.
34. Provider-local BAT uniqueness is
    `H(domain || fingerprint(raw_DHKE_key) || secret)`, never an
    audience-derived key ID. One raw BAT key belongs permanently to one
    provider/scope/offer/profile/key-epoch lineage, and the two PIR providers
    use different raw keys.
35. Settlement blind promises become usable only after an external NUT-12
    verifier checks the exact denomination key, `B_`, `C_`, `e` and `s`.
    Deposited notes become creditable only after an external Cashu verifier
    verifies signature/spending conditions and derives the authoritative `Y`.
    The retained keyset registry is trusted local state bound to the same
    `issuer_id` as the provider registration and response.
36. A payout intent is globally single-use. Intent consumption, account
    reserve/debit, payout creation and one durable outbox command commit in one
    transaction before a signed success response is released. Every status
    successor commits with an atomic exact-predecessor CAS; issuer-side versions
    increment by one, concurrent branches cannot both commit, and terminal
    states never reverse.
37. Fresh status recovery uses only the current provider registration plus the
    exact original request and issuer-signed initial response. Every accepted
    registration epoch is retained, but an old provider request key may be
    consulted only when the canonical request digest already matches the
    payout's durable latest exact status response; it cannot authorize a fresh
    nonce or a new CAS. Initial and historical issuer signatures resolve by
    signed key ID from a current-plus-retained keyring bound to the same issuer
    lineage. Read-only status polling returns live latest state and is never
    satisfied from an idempotency cache.
38. BOLT11 quote status is disclosed only after a fresh claim-key BIP340
    signature and atomic nonce consumption. Quote-ID knowledge is not status
    read authority, and status requests are POST bodies rather than URL query
    secrets.
39. Quote lifecycle transitions use issuer-store compare-and-swap. Clients
    retain the highest exact signed snapshot and reject lower versions,
    same-version forks, unreachable successors, or a changed quote ID.
40. Production code obtains BOLT11 network, payee, amount, node-assigned
    creation time and expiry only by parsing and signature-verifying the exact
    invoice text. Creation time is not a caller-selected backend idempotency
    field; it is checked against bounded clock/delegation rules after parsing.
    Parsed facts have private fields and no production fixture constructor.
    Native builds use pinned `lightning-invoice` 0.34.0 and cross-check every
    extracted fact with the pure-Rust verifier. WASM uses that pure-Rust
    `bech32`/`k256` verifier directly. Both paths require the recoverable ECDSA
    signature and exact lowercase canonical encoding, reject amountless/zero
    invoices and simnet, and obtain the payee from `n` or signature recovery.
    Caller-asserted invoice facts are never a fallback.
41. Both provider and issuer databases are checked against an authority stored
    outside the SQLite backup domain. A missing or lower restore floor fails
    closed; an operator cannot resume from a stale internally consistent copy.
42. Directory clients retain monotonic per-provider state and compare signed
    catalog checkpoints across configured relays. A same-sequence fork is a
    split-view failure; silent first-seen-wins behavior is forbidden.
43. A strict two-provider browser verifies each live announce bundle with its
    own independently selected operator pin. Missing, swapped, or equal pins
    fail closed; the deprecated single-pin adapter field is advisory only.
44. Standard-Cashu recovery keys, online note-custody keys and offline export
    recipient keys are separate domains. Provider 0 and provider 1 do not reuse
    any of them.
45. A standard-Cashu grant is impossible without the same durable transaction
    installing a bounded encrypted provider-note lot and globally unique note
    fingerprints. Exact finite `(mint_id, unit)` value/note caps are checked
    before NUT-03; there is no unlimited fallback.
46. Cashu custody export binds one export ID immutably to provider, mint, unit,
    requested lot bound and recipient key ID, persists one exact sealed
    artifact before release and never interprets external-custody ACK as
    settlement or payout.
47. Payment-authority network timeouts are absolute wall-clock budgets, not
    idle timers. DNS plus all HTTPS candidate addresses share one connect
    deadline; TLS, request and response share one I/O deadline; one CLN RPC
    shares one local-socket connect/write/read deadline. Once any mutation
    request byte may have been sent, timeout remains outcome-unknown and is
    recovered only through the exact idempotency protocol.
48. A Nostr directory readback never accepts a signing key or publish path.
    Relay destinations use the same raw canonical public-`wss://` grammar as
    the Rust publisher. Readback requires the publisher's domain-separated
    event-set digest and recomputes every NIP-01 event ID; every artifact is a
    stable regular file read under one cumulative bound before exact
    event-value comparison. URL
    normalization, symlinks, devices, FIFOs or a changing file never relax the
    boundary.

The canonical relay grammar is a syntactic boundary, not DNS-rebinding
protection or proof that a hostname resolves only to public addresses. Relay
targets are explicit operator inputs. A production publisher/readback host
MUST also use reviewed DNS and egress policy if access to loopback, private or
metadata networks is in its threat model.

For invariant 15, “durable spend” is scheme-specific: the local uniqueness
transaction for offline/local proofs, the mint's NUT-03 input invalidation for
standard eCash, or the shared issuer's atomic redeem for online BAT/ARC. A
second local commit must never become authoritative after an external spender
has already committed.

Before selecting two providers, the strict client compares the raw BAT and ARC
verification-key fingerprints in their independently verified policies. It
rejects a pair that advertises the same raw key for either method, without
sending either provider the peer identity. Both raw-key comparisons must pass
before an explicit shared-issuer override can permit a common issuer identity.
This catches copied keys across self-run or different issuers, which no
provider-local or per-issuer registry can detect.

The analogous issuer-ID and HTTPS-origin checks are only negative safety
checks: equality proves an obvious shared correlation boundary, but different
IDs, keys, domains, IP addresses, or origins do **not** prove independent
operation. One organization can control all of them. A product that promises
issuer/operator diversity therefore needs a separately authenticated governance
assertion or user pin for the controlling organization, plus operational review;
cryptographic offer selection alone cannot establish that fact.

These local diversity checks remove visible common identifiers; they do **not**
prove independent operational control. One actor can publish different
provider IDs, policy/operator keys, issuer IDs, HTTPS domains and BAT keys.
Strict privacy therefore still depends on independently obtained operator
trust/diversity evidence. A future signed operator-group or governance
assertion may make that evidence machine-readable, but merely observing unequal
keys or origins must never be described as proof of non-collusion.

## Explicitly accepted leakage

Depending on the chosen offer, a provider necessarily learns:

- that one authorization for one of its published scopes was used;
- the selected authorization scheme, backend/workload, scope, operation and
  entitlement profile, plus the credential presentation needed to authorize;
- the approximate start time, connection metadata, and the existing PIR wire
  leakage for that backend;
- a provider-local spent identifier or an online issuer redemption outcome.

Direct BOLT11 additionally lets the provider payment service link invoice and
receipt/query time. Standard Cashu or blind-issued capabilities break the
deterministic issuance-to-spend join, but sparse timing and denomination can
still correlate them.

A shared online issuer learns provider, token/tag, scope, and redemption time
because provider authentication prevents the bearer client from stealing
settlement outputs. Blinding prevents a direct join from the later deposited
note serial to that redemption, not knowledge of the provider at redeem.
It may also infer that independently scoped events came from one client using
IP, cookies, connections, amount, or timing. The protocol removes explicit
peer/pair IDs; it cannot prevent this common-infrastructure traffic analysis.

Lightning participants may learn:

- payer wallet: invoice, payee identity/routing hints, amount, route it chose;
- payer's first hop: payer channel relationship, outgoing amount/timing and
  next hop, but normally not full route or final query;
- intermediate hops: adjacent hops, amount/timing/CLTV for their segment;
- every hop of a classic HTLC route observes the same payment hash, including
  across MPP parts that use that hash, so colluding hops can strengthen timing
  and path correlation;
- payee and its last hop: incoming amount/timing, last hop, payment hash and
  successful settlement; payee knows invoice metadata and preimage;
- a global or well-positioned network observer may correlate endpoints by
  amount and timing.

Lightning does not itself reveal the Bitcoin address queried unless the
application, logs, browser storage, or timing joins the payment to the PIR
operation. The architecture's token separation reduces that application join;
it cannot eliminate global timing analysis.

## Process-memory handling boundary

Bearer material is erased on a best-effort basis wherever this implementation
retains an owned mutable buffer. The server wraps the complete plaintext frame
returned by secure-channel opening in a zeroizing guard, and the decoded
authorization proof has its own zeroizing drop path. Native SDK and standalone
WASM paths likewise zeroize controllable intermediate plaintext copies. A
WASM-issued capability batch and an unreleased experimental-ARC presentation
are zeroized when their handles are freed. The browser waits for the encrypted
vault transaction to settle, then overwrites its mutable issuance/import copy
on both success and failure; it must not erase that copy before the asynchronous
vault operation has consumed it.

These controls are memory-lifetime reduction, not forensic erasure. Immutable
JavaScript strings used for JSON, Base64, BOLT11 invoices and imported `cashuB`
tokens cannot be overwritten. `wasm-bindgen`, the WASM allocator, JavaScript
GC/JIT, WebCrypto, browser message queues and operating-system buffers may make
copies outside application control. Process abort, crash dumps, swap and a
malicious browser extension are also outside the zeroizing-drop guarantee.
Strict mode still ensures that browser/WebSocket/OS network queues receive the
secure-channel ciphertext rather than a plaintext PIR authorization frame.
Security claims MUST say "best-effort zeroization" and MUST NOT promise
forensic process-memory erasure. ARC remains experimental until its wrapper and
cryptography receive an independent review.

## Threats and required controls

### Invoice manipulation

- the concrete pinned adapter verifies BOLT11 syntax, semantics, signature and
  exact canonical text, then parses fixed amount, supported network, explicit
  or recovered payee, node-assigned creation time and expiry directly from the
  invoice; issuer policy rejects timestamps outside its bounded clock and
  delegation window;
- native and WASM clients use the same pure-Rust BOLT11 parser and signature
  recovery path; neither accepts browser-supplied invoice facts as verified;
- quote amount is derived from immutable offer data;
- one satoshi never selects an arbitrary issuance count;
- an idempotency key is bound to the full request digest;
- the request includes a fresh claim public key and claim signatures bind the
  quote, request digest, and blinded outputs;
- overpayment never increases entitlement.

### Replay and restart

- receipt serial, authoritative Cashu `Y`, BAT raw-key fingerprint plus secret,
  and a reviewed ARC adapter's authoritative presentation tag/nullifier map to
  domain-separated spend keys;
- spent state is fsync-backed before success;
- restart and backup restore tests verify old spends remain rejected;
- restoring an old database snapshot is a security rollback. Production needs
  a separately durable monotonic authority or must fail closed and revoke all
  keysets whose missing spend rows could be replayed before service resumes.
- issuer quote transitions and payout transitions use database predecessor
  version CAS so two workers cannot sign competing economic outcomes;
- quote reservation has atomic outstanding and total-record ceilings; active
  authenticated status nonces are capped per quote and expire after the
  signed replay window. The issuer edge applies separate bounded request
  budgets so a valid claim key cannot amplify rollback-authority writes;
- a claim handler loads settlement state from the authoritative database and
  never promotes a client-submitted signed snapshot into payment evidence.

### Timing correlation

- wallets should acquire batches ahead of query time when using blind methods;
- standard denominations and fixed issuance bundles avoid unique fingerprints;
- providers may delay/batch settlement deposits;
- online redemption may use Tor/OHTTP/common ingress to reduce network-origin
  leakage, but issuer-visible provider authentication remains;
- no cross-provider synchronous calls or common identifiers are introduced.

### Malicious provider

A provider can accept/consume a credential and fail to serve. With no trusted
execution receipt shared across independent servers and no refund policy, this
is an accepted commercial risk. Reputation, signed policy history, monitoring,
and small denominations mitigate it. A provider cannot be allowed to mint its
own shared-service settlement credit.

A bearer client must not be able to request provider settlement signatures.
Every shared redeem therefore proves possession of the registered provider
clearing key and binds its idempotency key and blinded outputs into that
authentication.

### Malicious issuer

An issuer can refuse issuance/redemption, selectively tag keysets, create
unique denominations, or collude on timing. Clients must verify DLEQ where the
scheme supports it, reject undeclared keysets, and prefer standard bundle
sizes. Providers choose whether to trust and advertise an issuer.

## Logging contract

Allowed high-level fields:

- coarse timestamp bucket;
- provider ID, policy epoch, scope ID, scheme ID and outcome code;
- keyed/rotating diagnostic digest;
- aggregate latency and resource counters.

Forbidden fields:

- BOLT11 invoice, payment hash, preimage or route;
- raw receipt/token/tag/secret/signature;
- token-specific exact timestamps or insertion order exposed as application
  fields;
- Bitcoin address/scripthash or PIR result;
- browser IP combined in the same record with credential digest;
- peer provider, pair ID, shared query ID;
- quote recovery secret or wallet identifier.

Payment and PIR logs use separate retention and access domains. Default PIR
runtime logs are startup/aggregate only: no raw peer IP, connection/client ID,
per-query timing, database/group selection or request/response size. Detailed
runtime logging exists only behind the explicit
`--unsafe-debug-query-logging` escape hatch, which emits a startup warning and
is forbidden in production. Even that mode must not log payment artifacts,
credentials, addresses/results or peer-provider/pair identifiers.

## Release gates

- threat-model review of all five schemes;
- independent ARC cryptographic review before removing `experimental`;
- protocol fuzzing and malformed length tests;
- crash/restart/concurrency tests for every spent path;
- query state-machine tests for every backend/workload;
- browser multi-tab and storage-loss tests;
- grep/static assertions for forbidden wire/log fields;
- product-side executable wire-shape contract and Rust conformance tests cover
  the secure-channel auth round, exact request framing, independent per-server
  selection, and the separate network/provider observer projections;
- external EasyCrypt proof, proof manifest, product proof lock and trusted CI
  verification record updated together for the admitted per-server
  method/scope/operation/timing/result-shape leakage;
- reproducible offline build and dependency audit;
- admission-disabled configuration validation followed by a no-funds enforced
  canary; no credential-consuming shadow mode is permitted;
- explicit operator approval before production deployment or real funds.
