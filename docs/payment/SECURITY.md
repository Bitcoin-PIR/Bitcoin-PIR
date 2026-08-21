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
14. One fixed enforced-mode pre-authorization deadline covers reads and every
    pre-grant WebSocket write/flush, including DB-proof/tree-top preflight and
    delivery of `AUTH_GRANTED`. A durable commit does not switch the connection
    to its idle timeout: only successful flush of the granted AUTH result does.
    The commit itself is not cancelled and may already have consumed the
    capability; expiry closes fail-closed before PIR work, with no automatic
    refund or resurrection in V1.
15. Query or verification failure after durable spend does not remove spent
    state. This is the explicit at-most-once product policy.
16. Failures before durable spend do not consume a capability.
17. Scheme rejection errors are coarse and do not expose a signature/spent
    oracle beyond what is needed for safe client behavior.
18. Provider and issuer logs omit invoices, payment hashes/preimages, raw
    query addresses, results, peer identity, and browser recovery secrets.
19. Authentication plaintext is padded to a declared length class before
    encryption. For V1 the complete request application record is fixed at
    16,414 bytes. This hides method, scope, operation variant and proof length
    only from request-size observation by a party without channel keys; it does
    not hide them from the provider, and it does not hide authorization timing
    or the variable response shape.
20. Browser token selection and burn is atomic across tabs and binds the exact
    provider, policy digest, scope, offer and scheme in its lock and encrypted
    record authentication. No bearer token, ARC nonce state, invoice, or query
    link record is stored in `localStorage`.
21. Shared issuer private mint/ARC keys are never distributed to participating
    providers.
22. Shared issuer online redemption is an explicitly declared availability
    and timing-correlation dependency. Outage fails closed.
23. Shared redeem authenticates a registered provider clearing key even when
    signing blinded settlement outputs. Blind outputs hide only the later
    deposit-serial join; they do not hide provider identity at redeem.
24. The directory key is distinct from server/operator/payment keys. Directory
    events are discovery hints and never override live strict verification.
    Without an independent operator pin/diversity source, the directory remains
    a centralized curation/Sybil boundary and clients must not claim that live
    verification proves two providers have independent control.
25. ARC is advertised and displayed as experimental until independent review
    closes all cryptographic and implementation findings.
26. Standard Cashu eCash and `bpir_cashu_bat_v1` use distinct method IDs,
    keysets, encodings, and security claims.
27. Every paid quote is bound to a browser-generated claim public key; quote
    ID disclosure alone cannot claim issuance.
28. Policy/key rotation retains paid quote and receipt validity until their
    explicit claim/use horizons. Rotation cannot silently confiscate paid
    entitlement.
29. Directory sequence, expiry, inner operator authorization, and tombstones
    are fail-closed. Provider/method selection occurs locally from a catalog.
30. Provider-specific blind issuance necessarily reveals the target provider,
    scope, offer, and entitlement profile to the issuer even when later
    presentations are unlinkable. Signed privacy flags must not understate it.
31. Proof-level Cashu DLEQ fields and wallet blinding scalars never cross the
    PIR wire. Standard Cashu imports are normalized before authorization.
32. Accepted policy, credential-keyset, Cashu-manifest, clearing-authorization,
    and directory epochs are monotonic within each store's durable state: a
    store never accepts an epoch lower than the highest it has recorded. The
    only provider-policy exception is the measured storeless Free-PoW profile
    in invariant 71: its exact complete signed policy digest is the immutable
    floor for one UKI measurement.
33. Blind clearing commits to one issuer-approved settlement keyset and its
    recovery horizon before the provider reveals blinded outputs.
34. A quote intent binds the exact issuer-root-signed quote-key delegation,
    including network, payee, epoch and validity window. A durable per-stream
    guard rejects epoch rollback and same-epoch forks before an invoice is
    displayed or paid.
35. Provider-local BAT uniqueness is
    `H(domain || fingerprint(raw_DHKE_key) || secret)`, never an
    audience-derived key ID. One raw BAT key belongs permanently to one
    provider/scope/offer/profile/key-epoch lineage, and the two PIR providers
    use different raw keys.
36. Settlement blind promises become usable only after an external NUT-12
    verifier checks the exact denomination key, `B_`, `C_`, `e` and `s`.
    Deposited notes become creditable only after an external Cashu verifier
    verifies signature/spending conditions and derives the authoritative `Y`.
    The retained keyset registry is trusted local state bound to the same
    `issuer_id` as the provider registration and response.
37. A payout intent is globally single-use. Intent consumption, account
    reserve/debit, payout creation and one durable outbox command commit in one
    transaction before a signed success response is released. Every status
    successor commits with an atomic exact-predecessor CAS; issuer-side versions
    increment by one, concurrent branches cannot both commit, and terminal
    states never reverse.
38. Fresh status recovery uses only the current provider registration plus the
    exact original request and issuer-signed initial response. Every accepted
    registration epoch is retained, but an old provider request key may be
    consulted only when the canonical request digest already matches the
    payout's durable latest exact status response; it cannot authorize a fresh
    nonce or a new CAS. Initial and historical issuer signatures resolve by
    signed key ID from a current-plus-retained keyring bound to the same issuer
    lineage. Read-only status polling returns live latest state and is never
    satisfied from an idempotency cache.
39. BOLT11 quote status is disclosed only after a fresh claim-key BIP340
    signature and atomic nonce consumption. Quote-ID knowledge is not status
    read authority, and status requests are POST bodies rather than URL query
    secrets.
40. Quote lifecycle transitions use issuer-store compare-and-swap. Clients
    retain the highest exact signed snapshot and reject lower versions,
    same-version forks, unreachable successors, or a changed quote ID.
41. Production code obtains BOLT11 network, payee, amount, node-assigned
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
42. Every stateful provider database and every issuer database is checked
    against an authority stored outside the SQLite backup domain. A missing or
    lower restore floor fails closed; an operator cannot resume from a stale
    internally consistent copy. Invariant 71's exact-pinned Free-PoW profile is
    stateless and must not create either database.
43. Directory clients retain monotonic per-provider state and compare signed
    catalog checkpoints across configured relays. A same-sequence fork is a
    split-view failure; silent first-seen-wins behavior is forbidden.
44. A strict two-provider browser verifies each live announce bundle with its
    own independently selected operator pin. Missing, swapped, or equal pins
    fail closed; the deprecated single-pin adapter field is advisory only.
45. Standard-Cashu recovery keys, online note-custody keys and offline export
    recipient keys are separate domains. Provider 0 and provider 1 do not reuse
    any of them.
46. A standard-Cashu grant is impossible without the same durable transaction
    installing a bounded encrypted provider-note lot and globally unique note
    fingerprints. Exact finite `(mint_id, unit)` value/note caps are checked
    before NUT-03; there is no unlimited fallback.
47. Cashu custody export binds one export ID immutably to provider, mint, unit,
    requested lot bound and recipient key ID, persists one exact sealed
    artifact before release and never interprets external-custody ACK as
    settlement or payout.
48. Payment-authority network timeouts are absolute wall-clock budgets, not
    idle timers. DNS plus all HTTPS candidate addresses share one connect
    deadline; TLS, request and response share one I/O deadline; one CLN RPC
    shares one local-socket connect/write/read deadline. Once any mutation
    request byte may have been sent, timeout remains outcome-unknown and is
    recovered only through the exact idempotency protocol.
49. A Cashu NUT-00 HTTP 400 error is not a proof that NUT-03 failed before
    commit. Standard-Cashu admission retains the submitted intent and exposure,
    never resends the swap, and performs only NUT-09/NUT-07 recovery.
50. A Nostr directory readback never accepts a signing key or publish path.
    Relay destinations use the same raw canonical public-`wss://` grammar as
    the Rust publisher. Readback requires the publisher's domain-separated
    event-set digest and recomputes every NIP-01 event ID; every artifact is a
    stable regular file read under one cumulative bound before exact
    event-value comparison. URL
    normalization, symlinks, devices, FIFOs or a changing file never relax the
    boundary.
51. Payment stores keep an internal hash-chained commit sequence for
    diagnostics only. There is no separate rollback-floor file or external
    rollback authority: restoring an older database snapshot restores older
    state. This is an accepted owner decision (2026-08-21).
52. A payout worker commits signed `Accepted -> InFlight` before the first
    external submission and performs only reconciliation for an `InFlight`
    command after restart or ambiguity. A real-funds executor MUST provide a
    linearizable durable command-ID submit/lookup primitive or equivalent
    authoritative no-submit fence. A local lease is not external exactly-once
    authority. Every external call MUST receive and enforce an absolute deadline
    strictly earlier than its durably committed `lease_until`; timeout and
    cancellation remain `OutcomeUnknown`, never definite failure. The opaque
    `payout_target_id` is a stable provider payout-routing pseudonym linkable by
    the issuer/executor across payouts, so targets and payout/command IDs MUST
    NOT be logged. V1 ships only a permanently disabled no-funds executor.
53. A Signet backup receipt is only an operator assertion bound to node identity
    and the current `staticbackup` digest. SCB/staticbackup material is channel
    recovery data, not a live/dynamic CLN database backup. Receipt success MUST
    NOT substitute for separate identity-secret and datastore backup/restore
    rehearsals.
54. Test-only `NoSevHost`, synthetic report-data binding and synthetic database
    proof installation MUST NOT be described as production attestation or
    production-database evidence. A browser E2E may claim Merkle preflight, PIR
    query or inclusion/result verification only when it explicitly executes and
    verifies those exact operations; such a result remains confined to its
    synthetic trust and data boundary.
55. Store mutations advance the internal commit sequence with a same-database
    compare-and-set, so two concurrent writers cannot commit conflicting state
    at one generation.
56. A standard-Cashu policy signs one canonical mint endpoint and one or two
    nonzero, strictly sorted leaf-SPKI SHA-256 pins. Every provider NUT-03,
    NUT-09 and NUT-07 call uses that exact tuple with ordinary WebPKI; there is
    no process-wide endpoint/pin override, TOFU, pin-only mode, or unpinned
    fallback.
57. A shared-issuer clearing authorization, and therefore its issuer
    countersignature, binds one canonical redeem origin and one or two nonzero,
    strictly sorted leaf-SPKI pins. The signed offer origin must match exactly.
    Cashu-mint and shared-issuer trust tuples are constructed independently;
    neither endpoint nor pin set may authorize the other.
58. Encrypted standard-Cashu note custody authenticates the exact manifest
    digest and pin set in addition to mint, unit and keyset. One NUT-07 batch
    contains only one identical endpoint/pin/manifest/unit cohort. A legacy
    manifest, clearing authorization, or custody bundle that omits these fields
    fails canonical decoding; V1 never supplies ambient defaults.
59. Ordinary browser `fetch` does not expose the peer certificate SPKI. Browser
    quote/acquisition HTTP therefore has the browser/OS WebPKI boundary unless
    a separately reviewed native pinned transport is used, and documentation
    MUST NOT claim browser-side SPKI enforcement. This limitation never permits
    the Rust PIR provider to skip its signed mint/issuer pin checks or to fall
    back to an unverified payment method.
60. A private test CA is accepted only by the non-default process-E2E feature;
    its root is loaded through the owner-only private-file boundary. Default
    builds have neither the CLI flag nor the constructor path. Cargo release
    profiles reject the feature at build-script and source-cfg boundaries even
    if debug assertions are forced on; assertions-enabled test artifacts remain
    forbidden for deployment. The signed leaf-SPKI pin remains mandatory in
    tests.
61. A default `payment-issuer` artifact contains neither the fake-Lightning
    backend, the `serve-fake` CLI variant, nor `/__test/fake/settle`. Local
    no-funds HTTP/browser tests must explicitly enable
    `test-only-fake-lightning`. Both the crate build script and source reject
    that feature for every release profile, including release builds with
    debug assertions forced on. Feature-enabled debug/test artifacts are
    non-deployable and must never handle real funds.
62. A Harmony V2Full disk pool is bound by an owner-only, ACL-checked local
    marker to one exact database, PRP backend and geometry. The marker is not a
    signature or MAC; its integrity comes from the private filesystem boundary.
    A ready artifact is locked but
    not renamed during authorization; the first main dispatch must verify the
    same inode, unlink it and durably sync the directory before exposing its
    PRP key. Any mismatch or durability ambiguity fails closed. Old and new
    lock/marker protocols MUST NOT share a live pool directory, and live mmap
    backing files MUST NOT be modified or truncated in place.
63. A structurally valid authorization presentation is not proof of value
    before its provider-local or online authority check completes. Reserving a
    scarce V2Full inode before that check prevents invalid or losing concurrent
    proofs from burning a hint, but permits bounded temporary capacity locks.
    Online V2Full MUST acquire its narrower class permit before the global AUTH
    permit, retain that class permit through pending dispatch/drop, and obey an
    absolute post-grant dispatch deadline. The deadline MUST be armed only after
    the complete encrypted `AUTH_GRANTED` frame is flushed, MUST then remain
    immutable, and MUST bound both the next pending read and any Ping/Pong
    response; control traffic cannot reset it. The only actionable application
    frame while the reservation is pending MUST be the exact encrypted canonical
    V2Full main request for the database bound into the grant. Reservation under
    the cross-process capacity lock MUST leave at least one **currently
    lockable** ready inode for provider-local methods, counted only from the
    current process's fully validated ready `PoolState` paths; unvalidated or
    corrupt canonical-looking disk surplus MUST NOT satisfy the floor. The hot
    path MUST try rather than block on the capacity lock, and a ready inode
    already locked by another process MUST NOT permanently head-of-line block a
    later usable validated candidate. The configured target pool size is not
    sufficient while refilling. The floor prevents a successful online
    reservation from taking the last validated lockable entry at that instant;
    it does not guarantee a provider-local caller fairness, priority or immediate
    admission. Production MUST also
    combine finite authorization concurrency and absolute deadlines with
    environment-specific pool headroom and source-aware edge admission or a
    reviewed client puzzle. These controls limit cost/duration and isolate the
    online slice; they do not prove fair online admission against distributed
    attackers.
64. Shared-issuer redeem uses a deterministic, per-provider-secret HMAC wire
    idempotency key over the exact clearing authorization, credential binding
    and credential. The provider MUST verify the canonical issuer-signed success
    and exact request/offer match before deriving and atomically claiming a
    separate HMAC local grant-delivery key in its durable synthetic
    namespace. Only the first local claim may grant. This local claim is not an
    issuer nullifier, settlement mutation or cross-provider spent set.
65. The browser quote-claim private key, provider-to-issuer wire idempotency key
    and provider-local delivery key are three distinct domains. A provider MUST
    NOT persist the browser key. Its local delivery row MAY persist only the
    HMAC-derived key/digest and minimal namespace bookkeeping; it MUST NOT contain
    invoice, payment hash/preimage, raw credential/token, payer identity or an
    exact token-specific timestamp. The issuer cannot derive that local key.
66. A credential binding's protocol `amount` and a clearing rule's
    `accepted_value` are independently authenticated values. Settlement MUST
    enforce `accepted_value = provider_credit + issuer_fee` and MUST NOT infer
    either value from the other.
67. Every grant-producing provider mutation uses a fresh nonzero 256-bit OS-RNG
    nonce in its committed successor and advances `spend_seq` for provider-local
    spend, Free-IP admission and final Standard-Cashu grant. Two exact callers
    starting from cloned detailed state and racing one external CAS have exactly
    one anchored winner; the loser fails closed. Independent ProviderStore
    databases MUST NOT be operated as active/active replicas.
68. After a shared-redeem HTTP outcome becomes unknown, only an explicit
    low-level recovery path retaining the identical proof may replay the exact
    deterministic transcript. The official Web flow burns/deletes the proof
    before send and MUST NOT retry automatically. Loss of `AUTH_GRANTED` after
    the local delivery claim leaves the entitlement consumed.
69. The local shared-delivery claim reuses ProviderStore schema v7 and does not
    authorize an in-place schema migration. Its first production activation is
    clean and forward-only. If any old deployment may have issuer exact-replay
    history without the matching local-claim history, operators MUST stop every
    old instance and rotate either the per-provider idempotency secret or the
    clearing authorization digest/epoch before serving; an empty local-claim set
    MUST NOT be paired with that old replay history.
70. DPF and Harmony retained-policy redemption is never exposed under an
    ordinary one-sided SDK name. Rust and WASM low-level entry points are
    explicitly named `dangerous_unpaired_*` / `dangerousUnpaired*`; using one
    verifies only that provider's secure-channel, database and retained-policy
    binding. Product code must first freeze the independently selected DPF
    server pair or Harmony hint/query payment context. This rule does not apply
    to the genuinely single-provider Onion and TEE-ORAM backends.
71. Storeless service admission is permitted only for a nonempty canonical
    signed policy with no empty scope and only provider-local
    `FreeV1`/`ProofOfWork`/zero-price offers with no issuer, key, credential,
    Cashu manifest, endpoint, retained grace or privacy-leakage field. Startup
    requires the exact nonzero domain-separated digest of the complete signed
    policy and rejects every ProviderStore, retained policy,
    Free-IP quota/key, payment/Cashu/BAT/ARC/shared-issuer, legacy credential or
    test-root input. The digest argument and provider/policy-key pins MUST be in
    the measured UKI. Each challenge is random, single-outstanding,
    connection-local, short-lived and bound to the secure-channel exporter plus
    exact provider/policy/scope/offer/operation. A policy-byte change, including
    renewal or difficulty/limit change, requires a new UKI measurement and
    client pin update; expiry or mismatch fails closed without a stateful or
    legacy fallback.

## TLS revocation residual

The strict HTTPS client enforces the ordinary rustls/WebPKI certificate chain,
DNS name and validity-time checks plus the signed or out-of-band leaf-SPKI pin.
V1 does not configure an independent CRL set and does not require an OCSP
response, so it makes no separate certificate-revocation enforcement claim.
Operators should use short-lived certificates and, after key compromise,
remove the affected pin through a newly authenticated manifest/clearing or
authority configuration and complete the bounded overlap promptly. A pin is an
identity restriction and rotation boundary, not proof that CA revocation was
checked.

The V1 server loads one shared-issuer clearing authorization. Its two-pin
overlap supports certificate-key rotation at the same origin, but it is not a
multi-origin migration mechanism. The old origin must remain the signed offer
origin and stay available until every retained-policy redemption grace window
has ended; otherwise those older capabilities intentionally fail closed.

The provider runtime likewise has no retained shared-authorization keyring:
`SharedIssuerAdmissionCommitterV1` receives one authorization, approval key and
issuer settlement key. Retained settlement keys at the issuer or in
`ProviderLedgerBalanceClientV1` do not recover an in-flight provider redeem
after one of those bindings rotates. Operators must drain/reconcile pending
redeems before rotation or explicitly accept fail-closed manual recovery risk;
V1 makes no cross-authorization/key-rotation recovery claim.

Standard-Cashu custody likewise retains the exact manifest digest and pins
that authorized the swap. Before a planned mint leaf-key change, operators
must publish a signed two-pin overlap and export, spend, and NUT-07-retire
older single-pin lots while the old key remains available. V1 does not silently
graft a newer manifest onto old custody; after an emergency uncompensated key
change, NUT-07 for those lots remains unavailable pending an explicit future migration
protocol or manual incident reconciliation.

The canonical relay grammar is a syntactic boundary, not DNS-rebinding
protection or proof that a hostname resolves only to public addresses. Relay
targets are explicit operator inputs. A production publisher/readback host
MUST also use reviewed DNS and egress policy if access to loopback, private or
metadata networks is in its threat model.

For invariant 16, “durable spend” is scheme-specific: the local uniqueness
transaction for offline/local proofs, the mint's NUT-03 input invalidation for
standard eCash, or the shared issuer's atomic redeem for online BAT/ARC. The
external mint/issuer remains the authoritative credential spender. Standard
Cashu adds no second local authoritative input spend. Shared redeem nevertheless
requires the provider-local delivery claim from invariants 64–65 after exact
issuer-success verification and before `AUTH_GRANTED`; that claim prevents a
signed replay from delivering service twice without pretending to re-spend or
settle the credential.

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

The browser's independent trust bootstrap binds Lightning payees per exact
signed `(issuer ID, canonical HTTPS issuer origin, network)` tuple. The PIR
provider WebSocket origin is a separate trust field and is never substituted
for the issuer origin. Provider-wide payee wildcards, duplicate tuples,
credential-bearing issuer URLs, and BOLT11 offers without exactly one match
fail closed. Free and Cashu-acquired offers carry no Lightning payee context.

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
- restoring an old database snapshot can replay spends whose rows are missing
  from the snapshot. There is no external rollback authority; the operator
  accepts this risk and must treat store restores as a keyset-revocation
  decision point.
- issuer quote transitions and payout transitions use database predecessor
  version CAS so two workers cannot sign competing economic outcomes;
- quote reservation has atomic outstanding and total-record ceilings; active
  authenticated status nonces are capped per quote and expire after the
  signed replay window. The issuer edge applies separate bounded request
  budgets;
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
runtime logs are startup/coarse-health only: no raw peer IP, connection/client
ID, per-query timing, database/group selection, request/response size, exact
store generation, spent/quote count, rate-limit bucket count, or Cashu custody
inventory. Exact business inventory is available only through an explicitly
invoked non-serving store check in an isolated operator context. Detailed runtime
logging is absent from normal binaries. It exists only when the explicit
`test-only-unsafe-query-logging` Cargo feature is enabled in a debug artifact;
that artifact recognizes `--unsafe-debug-query-logging` and emits a startup
warning. The package build script rejects the feature for every non-debug Cargo
profile, including release builds with forced debug assertions. Even this
local-test mode must not log payment artifacts, credentials, addresses/results
or peer-provider/pair identifiers.

## Release gates

- threat-model review of all five schemes;
- independent ARC cryptographic review before removing `experimental`;
- protocol fuzzing and malformed length tests;
- crash/restart/concurrency tests for every spent path;
- a separately reviewed real-funds payout executor with authoritative durable
  command-ID status/fencing; the shipped no-funds worker is not activation;
- Lightning identity-secret, SCB and supported datastore backup/restore drills;
  a backup receipt alone is not acceptance;
- query state-machine tests for every backend/workload;
- retain green real-process Harmony V2Full
  reserve/grant/disconnect/first-dispatch/restart and commit-failure tests in the
  final matrix, plus an operator old/new pool-directory migration drill;
- deployed Harmony V2Full authorization saturation testing with accepted pool
  headroom, dependency deadlines, source-aware admission and overload policy;
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
