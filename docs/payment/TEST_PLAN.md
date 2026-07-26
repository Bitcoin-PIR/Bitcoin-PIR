# Payment integration and fault test plan

Status: normative release plan. Not every item below is implemented. The
currently reproducible no-funds coverage and its precise limitations are in
`LOCAL_ACCEPTANCE.md`; `IMPLEMENTATION_STATUS.md` lists release blockers. In
particular, the five-method/backend matrix is a canonical wire/gate integration
test. Separate loopback tests execute direct receipt, Free, provider-local BAT
and experimental ARC admission plus DPF work through two real provider
processes. A separate Chromium boundary now executes generated WASM against a
real loopback no-funds issuer, but it does not launch a provider or query.
Standard-Cashu process success, non-DPF process cells, public-relay,
external-mint, real-Lightning and a deployed browser/issuer/two-provider
network E2E remain unexecuted.

## Positive conformance matrix

Every cell must exercise a real secure-channel authorization frame, durable
consumption, the backend state machine, and mandatory verification. A unit test
of a mint alone does not satisfy a cell.

| Scope | Free | BOLT11 receipt | Cashu eCash | Cashu BAT | ARC experimental |
|---|---:|---:|---:|---:|---:|
| DPF evaluate job | required | required | required | required | required |
| Harmony hint bundle | required | required | required | required | required |
| Harmony query job | required | required | required | required | required |
| Onion evaluate job | required | required | required | required | required |
| TEE-ORAM query job | required | required | required | required | required |

Mixed-provider scenarios:

- DPF provider A Free, provider B ARC;
- DPF provider A BOLT11 receipt, provider B Cashu BAT;
- DPF provider A Cashu eCash, provider B Free;
- Harmony hint ARC, query Cashu eCash;
- first provider selected and completed before the second is discovered;
- no packet, log, state row, or API body contains a peer/common ID.

### Implemented loopback process acceptance

`cargo test --offline -p runtime --test payment_v1_process_e2e` and
`cargo test --offline -p runtime --test payment_v1_methods_process_e2e`
launch two independent provider child processes on explicit `127.0.0.1`
listeners. Both perform the real WebSocket and encrypted-channel handshake,
verify each provider's exact signed manifest-root policy, execute a valid DPF
frame, enforce the signed frame limit and reject replay after restart.

The first test covers provider-specific direct receipts. The same provider-1
receipt is rejected at provider 0 and subsequently accepted at provider 1, so
it detects accidental cross-provider burn/shared spent state; a misspelled
bind flag must also exit before listening. The second covers Free open,
provider-local durable IP quota, an actual Cashu BAT blind/DLEQ/unblind proof,
and real experimental ARC issuance/presentation. It verifies independent
provider keys/quotas, cross-provider BAT/ARC rejection, and durable quota,
BAT-spend and ARC-nullifier rejection after both provider processes restart.

This is deliberately a local wire/gate test with `NoSevHost`, deterministic
keys and SDK `dangerous_unpaired_*` helpers. It does not satisfy production
identity/binary pin, hardware proof, database proof/trusted-root, Merkle
preflight/inclusion, real issuer/browser, external dependency, or non-DPF
process-level cells. Standard Cashu success remains behind a deterministic
mint transport because the production client accepts only WebPKI roots; the
tests do not introduce a local CA bypass. Those remaining boundaries are
listed in `LOCAL_ACCEPTANCE.md`.

## Negative protocol tests

- wrong provider audience;
- wrong backend, workload, dataset rule, operation profile, or entitlement;
- Harmony query token used for hints and vice versa;
- provider A token used at provider B;
- client rejects a selected provider pair that advertises the same raw BAT
  verification-key fingerprint, without making a pair-specific network call;
- stale or unknown policy digest;
- Free proof attempts to select or upgrade a different signed free mode;
- forged free quota/window/PoW target/priority is ignored or rejected;
- client-forged amount, limit, priority, ARC context, or profile;
- cleartext service-policy or auth request after/before handshake;
- valid auth followed by an unrelated backend opcode;
- second logical operation attempted on one grant;
- resource counter/byte/frame/wall-clock exhaustion;
- truncated, oversized, noncanonical, duplicate, or trailing fields;
- auth padding not exactly an advertised class;
- detailed verifier error is not exposed to client.

## Consumption and persistence tests

For provider-local receipt, anonymous ticket, BAT, ARC, and settlement credit:

- first spend succeeds; replay fails;
- 2, 8, and 64 concurrent spends have exactly one winner;
- process killed before commit leaves unspent;
- process killed after commit but before response remains spent;
- restart rejects spent proof;
- backup/restore runbook detects stale ledger rollback.

For shared-issuer redeem and every HTTP state transition:

- idempotent retry returns the identical stored response bytes;
- the same idempotency key with a changed request digest fails;
- a new idempotency key cannot redeem the same capability;
- authorization validity is checked only after exact committed-request lookup,
  so a lost response remains recoverable after rotation.

For standard Cashu eCash, the external mint's atomic NUT-03 invalidation is the
only authoritative spend boundary. The PIR provider must not add a second
local authoritative spent commit after a successful swap.

ARC-specific:

- client changes presentation context;
- client resets nonce;
- client inflates presentation limit;
- key epoch rotates;
- tags persist until the declared keyset retirement horizon.

Cashu-specific:

- invalid/missing DLEQ fails wallet acquisition;
- concrete NUT-12 verification matches the official challenge and blind
  signature vectors and rejects point/scalar/proof tampering;
- wallet unblinding succeeds only after DLEQ verification and an exact local
  `(secret, r) -> B_` reconstruction; issuer note verification rejects unknown
  mint keys, bad signatures, witnesses, and NUT-10-shaped secrets;
- wrong keyset/unit/amount fails;
- exact-value swap includes NUT-02 input fees and conserves value;
- provider persists blinded outputs before swap;
- `PREPARED -> SUBMITTED` advances ProviderStore generation and its independent
  rollback-floor CAS before NUT-03 is sent;
- a lost or failed submit CAS response performs zero NUT-03 calls; checked
  restart observes `SUBMITTED` and uses only NUT-09/NUT-07;
- exact replay and 2/8 concurrent prepare, submit, and grant callers each have
  one durable mutation winner under `UNIQUE(mint_id, input_set_digest)`;
- restoring a `PREPARED` backup after submit/grant fails against the external
  floor and cannot revive NUT-03 or the grant;
- lost swap response is recovered with NUT-09 using identical outputs;
- proof-level `dleq.r/e/s` and witness fields are rejected before they cross
  the PIR wire, not merely stripped before forwarding to the mint;
- BAT presentation and shared redeem contain no DLEQ proof/blinding scalar;
- BAT spend keys remain identical when only policy/audience-derived metadata is
  rebound, while different raw DHKE keys produce different spend keys;
- one BAT raw key cannot be installed under another provider/scope/offer/profile
  or key epoch, including after namespace close and process restart;
- duplicate proof inside one request fails atomically;
- standard V4 short/full IDs and base64 variants are accepted only by the
  wallet import layer and normalize to one full-ID binary PIR proof;
- Cashu eCash and BAT decoders reject each other's encodings.

## Backend state-machine tests

### DPF

- grant covers the expected INDEX, CHUNK, and Merkle rounds only;
- padding invariants remain unchanged;
- two independent providers accept unrelated schemes;
- no slot index is added to capability or logs.

### Harmony hint

- one complete V2 bundle consumes once;
- V2 half two-socket attach consumes once;
- wrong/random/expired session token cannot attach;
- scarce hint pool check happens before spend;
- cached compatible hint causes no hint authorization/redeem;
- hint and sibling capacity limits cannot be exceeded.

### Harmony query

- query server does not learn hint provider;
- query grant cannot fetch hints;
- cached hint metadata is compatible with policy/dataset binding;
- required Merkle traffic remains allowed after query frames.

### Onion

- one grant covers bounded key registration and query phases;
- extra key registration/query session is rejected;
- Merkle tree-top/sibling requests remain mandatory and bounded.

### TEE-ORAM

- one entitlement covers exactly one bounded logical browser request group,
  including every frame produced by its fixed batch planner;
- the server accounts every frame/input/byte/work unit against the signed grant
  and accepts no second logical request group;
- abort, truncation, extra frames and concurrent reuse cannot reopen a completed
  or spent grant;
- cleartext ORAM and an ORAM operation under any PIR/Harmony/Onion scope fail
  closed.

## Invoice lifecycle tests

- invoice created only after quote row is durable;
- crash after Lightning invoice creation but before the mapping commit recovers
  by deterministic backend label and leaves no orphan payable invoice;
- fixed amount/network/expiry are parsed and checked;
- the quote intent binds the exact root-signed quote-key delegation;
- quote-key rollback and same-epoch delegation forks fail before invoice
  display, including after restart;
- a delegation whose validity does not cover the complete claim deadline is
  rejected;
- unpaid, settled, expired, canceled, and backend-unknown states;
- notification lost, lookup reconciliation finds settlement;
- HTTP response lost after payment; claim recovers same issuance;
- leaked quote ID without the claim private key cannot claim issuance;
- leaked quote ID cannot read invoice/status; status requires a fresh BIP340
  claim-key request and a replayed `(quote_id, nonce)` is rejected;
- stale quote snapshots, changed quote IDs, same-version forks and unreachable
  lifecycle successors fail against the browser's highest stored snapshot;
- two concurrent transition workers race one predecessor version and exactly
  one issuer-store CAS/signature commits;
- claim ignores client-provided quote status and succeeds only from an
  authoritative store row in settled/late-settled or exact claimed replay;
- the production BOLT11 adapter accepts an official signed vector, exercises
  both explicit and signature-recovered payees, maps Bitcoin/testnet/signet/
  regtest exactly, and rejects bad signatures, simnet, wrong HRP/network,
  wrong payee, amountless/zero invoices, wrong amount, altered expiry,
  uppercase/mixed-case and any non-canonical round-trip;
- claim signature cannot be replayed with changed blinded outputs;
- BIP340 claim/status adapters use prehash verification (no accidental second
  SHA-256) and pass official positive and negative BIP340 vectors;
- BitcoinPIR quote claims reject NUT-20-domain signatures and standard NUT-04
  claims reject BitcoinPIR-domain signatures;
- paid old-policy quote and receipt remain usable through the declared grace
  window, then fail closed;
- the original current-policy request remains exactly `[version=1]`; retained
  lookup requires selector plus the exact non-zero digest and rejects missing,
  unknown, wrong, zero, truncated or trailing selectors/digests;
- retained startup rejects current/newer, duplicate, wrong-provider/key,
  free-only and missing durable namespace configurations; exact reload after a
  restart is idempotent;
- a retained response permits only its exact provider-bound scope/offer during
  grace; Free/PoW acquisition and request/auth digest substitution fail before
  credential commit;
- native and Web/WASM retained handles are secure-channel-exporter-bound and
  expose redemption only; acquisition, Free and PoW remain current-policy only;
- verification, policy and Merkle/tree-top preflight responses consume the
  exact final encoded WebSocket message count and byte length from a separate
  fixed per-connection budget; exhausting either dimension is terminal and a
  later opcode cannot reset it;
- a chunked preflight response reserves its complete encoded message group and
  byte length before the first message is sent, so an over-budget tree-top is
  rejected without a partial response;
- service authorization and Harmony attach responses do not consume the
  preflight budget, so preflight accounting cannot strand an otherwise valid
  credential commit response;
- a source-level forbidden-field scan proves default unified-server connection
  logs contain no raw peer/client identifier, per-query timing, selected
  database/group, sequence/round identifier or request/response size; enabling
  detailed logs requires `--unsafe-debug-query-logging` and emits a prominent
  non-production warning;
- issuer restart in each state;
- issuer `init-store` refuses overwrite, public parents and canonical aliases,
  emits mode-0600 files, verifies exact generation-zero identity, and reopens
  both independent files before success; failure never auto-deletes unknown
  partial state;
- issuer and enforced provider startup reject final-component symlinks,
  group/world-accessible files, non-private parents and store/rollback paths
  resolving to one inode; SQLite WAL/SHM remain confined by the private parent;
- CORS `--allow-origin` accepts only one canonical exact HTTPS origin or HTTP
  localhost origin and rejects userinfo, path, query, fragment, default/non-
  canonical ports, uppercase hosts and every ASCII control/whitespace byte;
- restoring an internally consistent but stale issuer backup fails against an
  independently persisted monotonic floor before any quote/claim is served;
- page close/reopen restores quote without localStorage invoice history;
- one sat cannot obtain a higher price/bundle;
- overpayment does not increase issuance;
- routing fee is not treated as underpayment;
- late settlement issues once if backend says settled;
- no automatic refund/query-credit restore.

## Directory tests

- outer Nostr signature and inner operator assertion both verify;
- a deterministic, process-local NIP-01 fake relay accepts the real signed
  `EVENT` publish envelopes, applies addressable-event replacement, and serves
  the Rust-generated 16-shard `REQ`/`EVENT`/`EOSE` flow into the production
  WASM catalog verifier and durable rollback/selectability boundary;
- that publish-to-read harness carries two independent providers with distinct
  directory, operator and policy keys and no peer/pair identifier; relay
  tampering, a wrong pinned directory key, expiry and a replayed older catalog
  all fail closed;
- stale, expired, lower-sequence, wrong-key, and malformed events fail closed;
- unexpected Nostr tags/JSON fields cannot carry payment or selected-peer
  artifacts, and logical revisions require strictly increasing NIP-01
  `created_at` values;
- signed tombstone supersedes every lower sequence;
- same-epoch catalog checkpoint forks across relays fail closed;
- a complete shard must exactly match the checkpoint's sorted provider,
  sequence, and event-ID tuples before any entry is selectable;
- a consistent directory catalog is explicitly not treated as proof of
  independent provider control;
- catalog download does not send a requested provider pair or payment method;
- live verified policy/identity mismatch overrides directory discovery;
- manual endpoint plus pinned operator fingerprint works without the directory.

Real-money tests are excluded until separately approved. Regtest/signet or a
deterministic fake Lightning backend is used by default.

## Shared clearing and settlement tests

- identified redeem credits only the authenticated provider;
- blind redeem also requires provider authentication and signs exactly the
  fixed settlement denomination;
- bearer client cannot redirect settlement to its own blinded outputs;
- invalid ticket cannot obtain a blinded signature;
- atomic failure signs no output and leaves ticket unspent, or commits both;
- provider unblinds and stores note before serving in the test harness;
- delayed batched deposit credits the right total;
- duplicate settlement-note deposit rejected;
- arbitrary compressed points without valid NUT-12 fail blind-promise
  verification;
- a structurally valid settlement note without a valid Cashu signature or
  spending-condition witness never reaches the ledger; the adapter-derived
  authoritative `Y` is the only spent identifier input;
- retained settlement keyset expiry fails closed, while an expired historical
  clearing authorization does not block recovery under a current provider
  registration;
- a valid retained keyset copied into another issuer lineage is rejected before
  deposit verification or credit;
- issuer fee plus provider credit equals accepted value;
- shared-issuer-online and standard-Cashu verification fail closed before PIR
  work when their issuer/mint is unavailable;
- a previously issued, unexpired provider-local receipt, BAT, anonymous ticket,
  or experimental ARC credential remains verifiable during an issuer outage;
- privacy documentation states that issuer learns provider at redeem;
- an anonymizing ingress claim is tested separately from clearing-key
  authentication and never presented as hiding provider from the issuer.
- one signed payout intent cannot create two payouts under different HTTP
  idempotency keys; intent consume, debit, payout and outbox are atomic;
- payout status binds the original signed response, rejects payout-ID
  substitution, stale/lower versions and terminal reversal; a fresh nonce
  commits a latest signed successor, while an exact retry returns the same
  durable bytes after restart, registration expiry and provider request-key
  rotation without allowing an old-key fresh request; retained-registration
  digest tampering and wrong-provider lookup fail closed, and once a newer
  latest status commits the older exact request is no longer replayable;
- rotating the current issuer settlement key does not strand an initial payout
  response signed by a retained key, while a missing/wrong-issuer keyring fails
  closed;
- two workers signing `Succeeded` and `Failed` from the same exact predecessor
  race one store CAS; exactly one commits and the loser returns no response.

The settlement HTTP/service and transport-neutral provider-client
implementations cover these boundaries in focused local suites. The final
append-only registration-history implementation passes its focused
issuer-store cases and the issuer-service payout/restart case. Historical
registration is valid only after a durable latest response, exact canonical
request digest and provider match have been established; it is never authority
for a fresh status request or financial mutation. Whole-tree CI remains the
release record for interactions outside these focused cases.

The initial-payout persist-before-send P1 is closed by the provider-client
typestate and independently rerun focused suite. The client durably prepares
the exact initial payout envelope before transport submission, exposes only a
persisted/restored marker to submit, recovers the identical request after an
outcome-unknown/restart and atomically installs the verified response plus
rollback floor. A next payout starts only from a `Succeeded`/`Failed`
predecessor, atomically CASes and archives it and forms one monotonic
repeat-payout chain. Fresh preparation uses real current time, the current
provider registration and current issuer key; retained material is valid only
for exact committed replay. Production activation still requires a concrete
persistent provider store, genuinely independent floor adapter and payout
worker.

## Browser tests

- IndexedDB schema migration and rollback;
- Web Lock + transaction makes one multi-tab spender win;
- token is burned before send;
- ARC next nonce is committed before send;
- refresh does not resurrect a burned token;
- quota inventory is separated by provider/scope/scheme/keyset;
- quote recovery is not linked to address/query history;
- strict verification failure prevents invoice creation and presentation;
- payment service failure cannot select an insecure/free fallback unless the
  user explicitly selects a separately advertised Free offer.
- current-policy rotation does not strand an exact-digest retained capability
  or BOLT11 recovery record during its signed grace; a missing, altered or
  wrong-scheme retained binding fails closed before presentation.
- provider legs are prepared, frozen, acquired and authorized independently;
  the pair correlation guard runs once both exact verified selections exist and
  again immediately before the query.

The implemented real-browser subset runs with:

```sh
cd web
npm run test:e2e:payment-vault
npm run test:e2e:payment-real-issuer
```

The first command uses two same-origin Chromium tabs and the production
vault/acquisition controller to cover Web Lock contention, single-use validation release versus
delete-before-return commit, ARC persist-before-presentation, page reload,
byte-identical paid-claim replay, one-winner recovery, atomic capability
installation and zero payment-material `localStorage` writes. Its SDK is a
Vite-selected test-only state-machine double and issuer HTTP is locally
intercepted. This is not evidence for generated Rust/WASM cryptography, a
running issuer/provider, a wallet, a full query lifecycle, strict PIR
verification, deployment or remote interoperability. The existing product
controller unit test separately executes a query sentinel while making
`localStorage.setItem` fail on any call.

The second command adds a distinct acquisition boundary: current generated
Rust/WASM verifies the signed fixture policy and direct-receipt issuance, while
real Chromium talks over HTTP to a real loopback `payment-issuer serve-fake`.
It covers exact-price fake settlement, authenticated status, lost-response
exact claim replay after reload, issuer idempotency, atomic vault installation,
WASM capability validation/single-use consumption, and the absence of invoice
or query-sentinel bytes from claims and `localStorage`. Its provider channel
exporter and signed policy response framing are test fixtures; it does not
launch a provider, execute a query, use a wallet/Lightning node or real funds,
or exercise BAT/ARC acquisition.

## Formal Payment V1 lock

The current product lock is implemented and must remain a release gate:

```sh
python3 verification/scripts/verify_formal_lock.py
cargo test --locked --offline -p pir-sdk --features serde --test wire_shape_contract
cargo test --locked --offline -p pir-runtime-core --test payment_authorization_wire_contract
```

It binds `Bitcoin-PIR/protocol-proofs` commit
`c519f1960aa9567ac324856f30c71071b04a4a17`, manifest SHA-256
`5763b9a4e5e40f7eed1f1f1eadeb44950c6b4172ea55c995ca24f062e0ee860d`,
product contract SHA-256
`648227ffba4946b5adc55291bdb77eb452d93a5c03c553a17dc6f5d053b97bf7`
and content-addressed record SHA-256
`c97d8fff7b072154e78fb0388a076cb849a2d99e9968be7a9cd0d838268b54d8`.
The record was produced by passing GitHub EasyCrypt run
[`30202980581`](https://github.com/Bitcoin-PIR/protocol-proofs/actions/runs/30202980581).
Product CI checks out that exact revision, validates source/manifest/toolchain
bindings and reruns the trusted EasyCrypt command. A Payment wire-contract
change must not merge until the external proof, record and product lock are
advanced together.

This lock is evidence for its declared wire-shape claims only. It does not
cover payment cryptography, XSS, edge abuse, operator custody or deployment.

## Fault matrix

| Stage | Failure before durable spend | Failure after durable spend | Recovery |
|---|---|---|---|
| strict server verification | no payment/presentation | impossible | reject provider |
| invoice creation | no entitlement | n/a | retry idempotent quote API |
| Lightning settlement notification | quote remains reconcilable | payment ledger says paid | lookup/poll then claim once |
| credential issuance | paid quote remains `ISSUING` | issuance response may be lost | resume same blind transcript/idempotent claim |
| connect/readiness before proof selection | token remains in vault | n/a | no automatic retry; user may later select an unused token |
| proof burned locally, send outcome unknown | n/a | browser treats token as burned | no query retry and no resurrection after refresh |
| auth verification | local proof remains unspent; external intent is recoverable | external mint/issuer commit or local spend commit means spent | finish identical reconciliation if the connection lives; otherwise no query retry |
| spent commit/ACK | n/a | spent | no restoration |
| preflight | n/a | spent | disconnect, surface failure |
| query | n/a | spent | disconnect, surface failure |
| inclusion verification | n/a | spent | fail closed; never display unverified result |
| settlement deposit | notes retained before commit | ledger may have committed | idempotent deposit lookup/retry |
| provider payout submission | exact canonical request must be persisted before send | issuer payout may have committed | resend only the persisted request; verify and atomically install response plus floor |

## CI layers

The ordinary offline CI suite includes a deterministic adversarial corpus for
every public Payment V1 canonical decoder, the provider service-opcode boundary
and the strict issuer/mint HTTP response parser. It covers truncation, exact
fixed-frame boundaries, malformed `u16`/`u32` lengths, oversized top-level
messages, non-canonical padding, duplicate `Content-Length`, `CL`+`TE`, invalid
chunk sizes and endpoint/header injection. Corpus count and maximum allocation
are fixed in the tests, so this gate is reproducible and cannot become an
unbounded CI fuzz job. It is not evidence that later coverage-guided or
long-running fuzzing has been completed.

The explicit commands are:

```sh
cargo test --offline -p pir-service-protocol --test payment_v1_adversarial
cargo test --offline -p pir-runtime-core --test service_admission_adversarial
cargo test --offline -p runtime --bin unified_server service_http::adversarial_tests::
```

1. fast codec/model/property and bounded adversarial decoder tests;
2. durable store crash/concurrency tests;
3. issuer HTTP and fake-Lightning integration;
4. unified-server secure-channel/backend matrix;
5. native SDK and WASM tests;
6. browser Playwright tests in the dedicated no-business-service Chromium job:
   fake-SDK multi-tab fault injection plus real-WASM/loopback-fake-issuer
   direct-receipt acquisition;
7. pinned-action CI and pinned `wasm-pack 0.14.0 --locked` installation under
   Rust 1.94.1, without a remote shell installer or ambient `wasm-opt`;
   generation is Cargo locked/offline, the Pages job builds the real workspace,
   its build dependencies have no Pages/OIDC write authority, Node is fixed to
   supported LTS 24.18.0, all WASM toolchain/vendor/trust inputs trigger the
   gates, and Pages reruns TypeScript/unit and both no-funds Chromium Payment
   boundaries before publishing;
8. fuzz, dependency, forbidden-field, formal-contract, and offline-build jobs;
9. optional ignored regtest/signet canary; no mainnet funds in CI.

## Production-only acceptance gates

None of the default commands may use funds or remote infrastructure. Separate
approval and an isolated experimental/staging environment are required for:

- a Core Lightning regtest/signet node and wallet lifecycle, an external
  WebPKI-trusted Cashu mint, and public Nostr relay interoperability;
- a browser/issuer/two-provider topology with production
  identity/attestation/binary/database pins and mandatory Merkle verification;
- standard Cashu and Harmony hint/query, Onion and TEE-ORAM provider-process
  success plus fault injection;
- a rollback-floor authority deployed in a failure and administrative domain
  independent from each provider/issuer database, including restore/failover
  drills;
- production TLS/edge limits, source-aware abuse controls, telemetry, overload
  tests, supervision, backup and key-custody review;
- browser XSS/CSP/runtime-dependency review, resolution of documented
  upstream/vendor audit warnings, deployed-origin and user manual acceptance;
- independent ARC cryptographic and implementation review.

Passing local CI does not authorize any of these activities. No remote server,
external CLN/Cashu/Nostr service or real Lightning funds were used to establish
the local evidence in this document.
