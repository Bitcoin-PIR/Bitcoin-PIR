# Payment V1 implementation security review — 2026-07-26 (archived)

> Historical snapshot: the body of this review is bound to repository commit
> `bc465c76` and records the evidence available on 2026-07-26. Later CLN, CDK,
> Cashu-custody-v7 and public-Nostr work must not be inferred from statements in
> the historical body. The additive 2026-07-27 delta is also a dated snapshot.
> The post-delta current-tree note at the end controls for later
> settlement-v2, payout-worker, Signet-receipt, browser-topology and CDK changes;
> none of the older aggregate counts is a result for the current tree.

Status: independent agent review of the implementation tree on
`codex/payment-platform`. This record is suitable for draft-PR and no-funds
staging preparation. It is **not** production activation approval and it is
not the external cryptographic review required for ARC.

## Result

- implementation-code P0 open: **0**
- implementation-code P1 open: **0**, subject to final pushed GitHub CI
- production-activation P1 blockers: **open**, as listed below
- accepted implementation/operational residuals: **multiple**, explicitly
  listed below rather than compressed into one misleading count

Production deployment, remote-server operation, public relay/external mint
access and real Lightning funds remain separate approval gates.

## Scope reviewed

- canonical service policy, scope, offer, credential-binding and wire codecs;
- provider-local Free, direct receipt, standard Cashu, Cashu BAT and
  experimental ARC admission;
- independent provider stores, rollback floors, replay and concurrency;
- BOLT11 quote creation, settlement, claim, key rotation and crash recovery;
- shared issuer clearing, provider accounting and payout state;
- ledger-only settlement HTTP routes and the provider settlement client,
  including exact-response recovery across request-key rotation;
- Core Lightning RPC and HTTP listener boundaries;
- Rust SDK, WASM, encrypted browser vault, multi-tab reservation and product
  admission orchestration;
- Nostr directory validation, rollback and split-view handling;
- two-provider process integration, command-line fail-closed behavior,
  logging fields and documented production boundaries;
- the product-to-`protocol-proofs` Payment V1 wire-shape lock and its
  content-addressed GitHub EasyCrypt verification record.

## Closed findings

1. **A retained quote signer could be mistaken for current acquisition
   authority.** Current and retained quote material are now distinct. A fresh
   quote must use the exact current delegation; retained material is accepted
   only for an exact durable idempotent continuation. See
   `crates/payment/issuer-service/src/lib.rs` and its acquisition tests.
2. **Issuer restart could omit private material still required by live durable
   state.** Startup now derives the required quote delegation and credential
   policy set from current heads plus quotes within their immutable recovery or
   claim horizon, then fails closed if exact receipt/BAT/ARC material is absent.
   See `crates/payment/issuer-store/src/policy_ops.rs`.
3. **Shared-clearing BAT/ARC private material could be retired before the last
   accepted binding expired.** Every effective rule must resolve to exact,
   immutable key lineage and the matching secret remains required through the
   signed `not_after` boundary.
4. **Historical quote rows could permanently consume active quote capacity or
   reconciliation work.** Capacity and reconciliation selection now use the
   durable reservation-recovery/claim horizon. Exact idempotent replay remains
   recoverable before capacity rejection.
5. **Key-readiness selection still decoded every historical unclaimed quote.**
   Horizon predicates now execute in SQL before replay-image decoding. The
   regression corrupts an expired replay image and proves it is skipped, while
   the same malformed row inside its live horizon fails closed. See
   `material_readiness_filters_expired_quotes_before_replay_decode`.
6. **One ORAM entitlement could be split into multiple backend frames.** The
   product boundary now requires one atomic padded ORAM frame of at most 25
   logical inputs and rejects a larger request before network I/O.
7. **Policy rotation could strand browser recovery or present against an
   inexact policy.** Native, WASM and Web recovery retain and verify the exact
   provider, scope, offer, scheme, policy digest and credential binding through
   its bounded grace period.
8. **Staged provider selection could authorize the wrong first leg.** The
   controller now freezes and authorizes each independently selected provider,
   reruns the pair-correlation guard after both exact selections exist, and
   never introduces a provider-pair identifier.
9. **A misspelled server flag could silently fall back to a wildcard listener.**
   Unknown `unified_server` arguments now fail before listening. The process
   test covers `--bind-addres`, and `--bind-address` preserves the prior `[::]`
   default while allowing an explicit loopback bind.
10. **Cross-provider spending semantics lacked a real-process assertion.** The
    loopback E2E sends one provider-1 receipt to provider 0 (rejected), then
    spends that exact receipt successfully at provider 1. Provider 0 accepts
    its own receipt and rejects replay after a process restart. No shared spent
    set or pair identifier is involved.
11. **Provider request-key rotation could strand an exact payout-status replay.**
    Provider registration epochs are now written to append-only issuer history
    in the same rollback-anchored transaction that updates the current row.
    Fresh status and every financial mutation still require the current
    registration. A historical key is consulted only after the issuer has
    found a durable latest status response whose stored request digest exactly
    matches the canonical retry and whose provider matches. Current-to-history
    consistency, canonical registration digests, issuer lineage and commit
    bounds are part of store integrity validation. The implementation is
    covered by the focused issuer-store and issuer-service payout/restart
    suites.
12. **Generated WASM service-policy objects were exposed to TypeScript as
    `Map` values.** The TypeScript-facing service JSON surfaces now use the
    JSON-compatible serializer. The real generated-WASM Chromium boundary
    exercises ordinary object property access rather than a test double.
13. **Initial provider payout sent before its recovery transcript was durable.**
    The client now exposes prepare/restore/submit typestate: only prepare or an
    exact rollback-protected restore can construct the private submit marker,
    and submit rechecks the pending state before POST. The pending floor binds
    the complete canonical envelope, intent, registration and predecessor.
    Its authority value also carries the payout-request digest and optional
    predecessor explicitly: initialization requires no predecessor,
    pending-to-payout requires the matching digest and `Accepted` version 1,
    and a later pending transition must name the exact current terminal payout.
    An outcome-unknown restart resends the exact bytes; fresh preparation uses
    real current time, the current registration and current issuer key, while
    retained material is exact-replay-only. A repeated payout can advance only
    from an atomically archived terminal `Succeeded`/`Failed` predecessor.
    Focused tests prove one economic side effect under lost-response recovery
    and concurrent exact submit. The independent audit reran all ten client
    cases and warnings-as-errors clippy; this implementation P1 is closed.

## P1 production activation blockers and accepted residuals

### Independent rollback authority is not deployed

Both provider and issuer serving paths require a monotonic rollback floor and
fail closed when it is missing or inconsistent. The bundled implementation is
a separately configured SQLite file. That is useful for local verification but
is **not** an independent production failure or administrative domain: a
coordinated database-plus-floor restore can make a stale pair self-consistent.
Production activation therefore requires a reviewed, linearizable floor
adapter and deployment whose custody, backup, restore, monitoring and failover
are independent of the payment database. No such production adapter or
deployment has been accepted in this work. The provider client now has a
durable SQLite `ProviderSettlementStateStoreV1` adapter with an exact
crash-recoverable transition journal, but its bundled floor implementation is
explicitly local/test-only. A no-funds payout worker core now exists, but its
default executor is permanently disabled and there is no real-funds executor or
accepted production floor/deployment. Library typestate and the worker lease
are not authorization to activate settlement.

### Operational P2: retained-history startup cost

`IssuerStore::open_existing` performs full retained-history integrity checks,
including quote replay-image and append-only provider-registration validation.
The newer readiness queries are horizon-bounded, but the complete startup path
remains O(total retained issuer history), and V1 has no provider-registration
history GC. Before staging activation, operators must measure startup latency
and memory at explicit retained-row thresholds, define an SLO and refuse
activation when it is exceeded. Before sustained high-volume production,
design and review an authenticated archive/retention format; ad-hoc row
deletion is forbidden.

The provider settlement SQLite adapter likewise validates its complete
terminal-payout history and rolling commitment on each checked open and state
operation. Settlement frequency should be much lower than query frequency,
but the cost is still O(provider payout history). Production review must set a
measured history bound or introduce a reviewed checkpoint/archive design; rows
must not be deleted merely to reduce latency because the external commitment
intentionally makes that fail closed.

### ARC remains experimental

Functional integration does not substitute for cryptographic review. ARC must
remain labelled `experimental`, optional and production-disabled until the
review gate in `ARC_EXPERIMENTAL_REVIEW.md` is closed.

### External and production boundaries are untested

No real Core Lightning node, external Cashu mint, public Nostr relay, production
TLS/edge, remote provider or real funds participated. The process E2E uses
`NoSevHost`, deterministic public fixture keys and SDK `dangerous_unpaired_*`
helpers. It proves the local secure wire and admission gate, not production
identity, binary pin, hardware attestation, database proof/trusted root,
tree-top preflight or inclusion verification.

At the 2026-07-26 snapshot, standard Cashu success had not crossed a real
provider-process/external-mint boundary. Harmony hint/query, Onion and TEE-ORAM
had likewise not crossed the real provider-process boundary under Payment V1.
The canonical in-process matrix was valuable gate coverage, but was not
equivalent to those release E2Es. Later CDK evidence is recorded only in the
dated closeout delta below.

### Browser and shared-infrastructure boundaries

The non-extractable WebCrypto key prevents accidental plaintext persistence;
it does not defend against XSS or a copied unlocked browser profile. A
capability is burned before send, and an ambiguous network failure is not
automatically retried or refunded. Using one online shared issuer for both PIR
legs remains an explicit correlation/availability tradeoff even though the
provider-bound capabilities are cryptographically unrelated.

Before production, the browser boundary still needs an explicit XSS/CSP and
dependency review, deployed-origin testing and user manual acceptance. The
issuer/provider edges still need production TLS, source-aware abuse controls,
telemetry, overload evidence, process supervision, backup/restore drills and
operator key-custody acceptance. These are activation blockers, not claims
that the local cryptographic or persistence tests exercise a deployed system.

### Attribution, exact-replay and correlation residuals

Persistent Free IP quota requires a deployment-specific, authenticated client
source boundary; the local loopback tests do not prove correct attribution
through a production proxy. Exact durable replay is intentionally looked up
before an expired credential/registration is rejected so that a lost response
remains recoverable. That creates a bounded database-read DoS surface which
must remain behind loopback listener policy and production edge rate controls.
A shared issuer or central directory also retains timing/availability and
traffic-analysis correlation risk even though neither sends a provider-pair ID
and the two provider-bound credentials are unrelated.

### Rotation and capacity constraints

Retained quote material must have the same issuer root, Lightning network and
payee as the current issuer instance. Root or Lightning-node identity rotation
therefore requires draining every old recovery/claim horizon or running a
parallel old recovery instance; the audience checks must never be weakened.
`priority_class` is signed/displayed metadata only and does not yet implement a
server scheduler. Production edge rate, bandwidth, overload and telemetry work
remains mandatory.

## Verification evidence at review close

- The external proof lock binds
  `Bitcoin-PIR/protocol-proofs@c519f1960aa9567ac324856f30c71071b04a4a17`,
  manifest digest
  `5763b9a4e5e40f7eed1f1f1eadeb44950c6b4172ea55c995ca24f062e0ee860d`
  and GitHub EasyCrypt run
  [`30202980581`](https://github.com/Bitcoin-PIR/protocol-proofs/actions/runs/30202980581).
  Its downloaded verification record is stored at
  `verification/records/formal/c97d8fff7b072154e78fb0388a076cb849a2d99e9968be7a9cd0d838268b54d8.json`
  and hashes to its filename. The local lock check in `LOCAL_ACCEPTANCE.md`
  passes against the current product contract.
- The loopback provider-process commands in `LOCAL_ACCEPTANCE.md` pass for
  direct receipt (two cases) and for the Free/BAT/experimental-ARC DPF method
  adapter (one case), including cross-provider rejection and restart
  persistence. Standard Cashu and non-DPF process success remain release gaps.
- The payment-vault Playwright command passed its four Chromium cases. The
  real-issuer Playwright command passed its one generated-WASM plus real
  loopback `payment-issuer serve-fake` case. Neither test used a wallet, a
  Lightning node, a remote service or funds. Exact commands are recorded in
  `LOCAL_ACCEPTANCE.md`.
- The final append-only registration-history implementation passed three
  focused issuer-store cases and the issuer-service payout/restart case. Old
  keys recover only an exact durable latest response; fresh requests remain
  current-registration-only. The provider settlement client independently
  passed all ten focused cases, including initial-payout persist-before-send,
  outcome-unknown/restart exact replay, independent pending-floor rollback,
  terminal repeat-payout chaining and concurrent one-economic-effect submit;
  warnings-as-errors clippy also passed. After Payment implementation source
  edits stopped, `scripts/payment-v1-local-check.sh --full` completed with
  exit code zero,
  including the complete offline Rust suite, Payment clippy, wasm32 and fresh
  WASM generation, 326 passing Web unit tests, the four-case vault boundary
  and the one-case real-WASM/no-funds-issuer boundary. The pushed GitHub CI
  record is still required before merge.
- The bounded Payment HTTP adversarial boundary passed its three focused cases.
- Payment browser CI, the general Web PR gate and the Pages build no longer
  execute a remote `curl | sh` installer or permit `wasm-pack` to download its
  own CLI during the build. They install `wasm-pack 0.14.0` and lockfile-matched
  `wasm-bindgen-cli 0.2.114` with Cargo `--locked` under Rust 1.94.1, then build
  with `--mode no-install`, `--no-opt` and Cargo locked/offline. This also
  prevents execution of an unpinned ambient `wasm-opt`. The Pages build no
  longer rewrites the root workspace before compiling. Its Cargo/npm build job
  has contents-read permission only; Pages write/OIDC is confined to the
  separate deploy job. Newly used workflow actions are pinned to exact commit
  SHAs; Node is fixed to supported LTS 24.18.0 on Ubuntu 24.04; the
  Payment/Web filters watch toolchain, Cargo configuration, vendor, trust and
  Web inputs. The Pages build also reruns strict TypeScript, unit tests and all
  three local no-funds Chromium Payment boundaries. Failure of those reruns in
  this build prevents publication; it does not rely on a parallel workflow.
  The scheduled strict-production canary
  uses the same fixed Node/runner/action boundary and refuses implicit `npx`
  package installation, but was not triggered here. A cold local smoke of the
  exact pinned installation commands passed; the exact build command also
  passed locally. YAML parsing and diff checks passed for this change; GitHub
  CI remains authoritative after push. Disabling
  post-link `wasm-opt` trades some possible artifact-size optimization for a
  closed executable supply chain. The current local baseline is 3,600,060
  bytes raw / 1,195,176 bytes gzip for `pir_sdk_wasm_bg.wasm`, and the local
  real-WASM Chromium case loaded it successfully; deployed-origin load
  performance remains a staging/manual gate. No Pages deployment was run
  during this review.
- A lockfile-pinned YAML 1.2 semantic guard now fixes the Pages workflow to the
  exact push/manual triggers and default-false confirmation input, confines
  Pages/OIDC write capability and exact-SHA deploy actions to the build-gated
  environment job, and rejects aliases, merge keys, `write-all`, Actions-write
  permissions, reusable-workflow delegation and sibling workflows outside an
  exact contents-read boundary. This is a repository-static/default-
  `GITHUB_TOKEN` control, not proof against external PAT/GitHub-App dispatch or
  mutable repository/environment settings. Those credentials, default
  permissions, Pages build mode, rulesets and a required environment reviewer
  remain production checks.
- The 2026-07-26 production-dependency check
  `npm audit --omit=dev --audit-level=moderate` reported zero vulnerabilities.
  `cargo audit` exited successfully with no vulnerability finding and four
  allowed warnings, not zero warnings: indirect `bincode 1.3.3` is
  unmaintained; indirect `memmap2 0.9.10` is covered by RUSTSEC-2026-0186
  (patched in 0.9.11, which the current vendor has not supplied) but this tree
  does not call the affected `advise_range`/`flush_range` APIs; indirect
  `rand 0.8.5` is covered by RUSTSEC-2026-0097 (patched in 0.8.6, also not yet
  supplied by the vendor) whose trigger requires recursive `ThreadRng` use in
  a custom logger, while this tree defines no custom logger; indirect
  `spin 0.9.8` is yanked through the SEV/tracing dependency path. These remain
  vendored-upstream residuals. This Payment change does not silently refresh
  the complete vendor tree.
- Fresh WASM bindings, wasm32 checks, the no-funds fixture and all reproducible
  commands are recorded in `LOCAL_ACCEPTANCE.md` and
  `scripts/payment-v1-local-check.sh`. This review intentionally avoids a stale
  aggregate test count; the final CI record is authoritative for the complete
  tree.

## Review verdict

The architecture correctly keeps invoice, payment hash, preimage and payer
state out of PIR providers. Each provider independently advertises and consumes
one workload-specific capability, and neither provider needs to know the peer.
The implementation is appropriate for a draft PR and approved no-funds staging
preparation. Production activation remains blocked on an actually independent
rollback-floor deployment, production browser/edge/operations review, the ARC
review, external CLN/Cashu/Nostr/staging canaries, the remaining process E2Es
and user manual acceptance. The initial-payout implementation P1 is closed;
the absence of an independent production floor and reviewed real-funds executor
remains an activation blocker. A strict-WebPKI provider-settlement transport
exists but is not deployed. No remote operation or real-funds test was
performed by this review.

## 2026-07-27 additive closeout delta

This delta reviews the later CLN deadline, standard-Cashu custody, Nostr
publisher/readback and best-effort secret-lifetime changes in the current
`codex/payment-platform` worktree. It supersedes only contradictory evidence
statements in the historical body above; it does not convert local test
coverage into production approval.

### Current finding disposition

- implementation-code P0 open: **0**;
- implementation-code P1 open: **0**, subject to the pushed GitHub CI result;
- production-activation P1: **1 architectural blocker** remains: the bundled
  rollback floor is another local SQLite file, not a reviewed linearizable
  authority in an independent failure and administrative domain;
- the durable local settlement-v2 state adapter and no-funds worker core are not
  a production deployment; no independent floor or real-funds executor exists,
  so payout remains disabled. That gap, production edge, distributed abuse
  control, backup/restore ceremony, monitoring, external canaries, deployed-
  origin browser policy, ARC review and user manual acceptance are explicit release gates,
  not additional items in the counted production data-integrity P1 total.

The final independent static deadline and sensitive-buffer reviews found no
additional P0/P1. ARC remains experimental and production-disabled until its
independent cryptographic and implementation review is complete.

### Current verification evidence

- GitHub run `30231837753` on pushed commit `394988fc` exposed a real
  availability/acknowledgement race in the Free quota concurrency test: two
  callers returned success for a quota of three because one committed writer
  observed that a later writer had already advanced the rollback authority.
  There was no over-grant. The fix confirms a superseding floor only by
  reconciling the exact SQLite connection that performed the original COMMIT;
  an authority advance from a cloned fork still fails closed. All 13 mutation
  call sites pass their committing connection. Deterministic same-database and
  cloned-fork tests pass; the independent reviewer repeated each 100 times,
  repeated the real SQLite quota contention test 500 times with exactly three
  successes, and reported P0/P1/P2 = 0 for this correction. The full
  service-store suite passed 79 unit tests plus two documentation tests, and
  warnings-as-errors clippy passed.
- After that correction,
  `CARGO_BUILD_JOBS=1 scripts/payment-v1-local-check.sh --full` completed with
  exit code zero. It reran the complete offline Rust/platform, provider-process,
  clippy, wasm32, fresh-WASM, 333-test Web, four-case vault and one-case real-
  WASM/no-funds-issuer boundaries. New pushed GitHub CI remains authoritative
  before merge.
- With source edits stopped, an isolated
  `CARGO_TARGET_DIR=/tmp/bitcoinpir-final-20260727 CARGO_BUILD_JOBS=1
  scripts/payment-v1-local-check.sh --full` completed with exit code zero. It
  covered the complete offline Payment/platform Rust suites, 39 unified-server
  tests, both loopback provider-process suites, the 10-case Node Nostr
  readback suite, dedicated Payment clippy with warnings denied, wasm32, fresh
  WASM generation, TypeScript and production bundle builds, **333 passing Web
  unit tests** with two intentional leakage-diff skips, four passing Chromium
  multi-tab vault cases, and one passing generated-WASM/real-loopback-issuer
  case with the two opt-in CLN cases skipped by the default no-funds run.
- The opt-in CLN runner separately passed all three real local-regtest cases
  against disposable Bitcoin Core plus two Core Lightning nodes: a channel and
  routed BOLT11 payment, then generated-WASM direct/BAT/experimental-ARC
  acquisition. It used only valueless regtest coins. An earlier attempt hit
  Playwright's global-setup timeout while an unrelated reviewer held the shared
  Cargo target lock; all temporary children were cleaned, and the isolated
  retry passed 3/3. This was infrastructure contention, not a protocol test
  failure.
- The opt-in CDK 0.17.3 fake-wallet runner passed both ignored interoperability
  cases: real padded V4 `cashuB` import, and provider-side NUT-03 plus NUT-12
  verification/custody commit followed by NUT-07 proof that the original inputs
  were `SPENT` and fresh custody outputs were `UNSPENT`. It deliberately did
  not pass bearer tokens in process argv, so real-CDK custody
  `UNSPENT -> SPENT` and admin retirement remain unproved. The verified
  official Apple-arm64 SHA-256 digests were
  `78390b850e6e24f11af1848f54004bdf7439771d81970b115241922435e944b9`
  for `cdk-cli` and
  `05b2e8cb01c2500a0200264947eb5b41cb82fcfc02263de6c0c1af7d531b89ab`
  for `cdk-mintd`.
- The separately authorized public Nostr smoke used a disposable key and empty
  short-lived checkpoint, not the production directory key. The owner-only
  production key exists only in its repository-external local directory; it
  has not been backed up, copied to a host, used to sign a production catalog
  or published.
- `npm audit --omit=dev --audit-level=moderate` again reported zero
  vulnerabilities. `cargo audit` exited zero with no vulnerability finding and
  the same four allowed upstream/vendor warnings documented above:
  `bincode 1.3.3`, `memmap2 0.9.10`, `rand 0.8.5` and yanked `spin 0.9.8`.
- The main production HTML now escapes server/proof strings at the remaining
  reviewed raw-HTML sinks, renders provider-derived sync-plan text through DOM
  `textContent`, and has no HTML event-handler attributes. Its meta CSP denies
  by default, permits scripts only from self plus the exact SHA-256 of each
  source inline block, and permits WebAssembly explicitly without permitting
  arbitrary inline script. A unit test recomputes every hash and rejects an
  inline-handler regression. Strict TypeScript, the complete **335 passing**
  Web unit suite, a production Vite bundle, and an in-app Chromium load/click
  smoke completed with no CSP or runtime warning/error. GitHub Pages cannot
  express `frame-ancestors` through a meta policy, so the deployed edge must
  still add and verify a header policy (including `frame-ancestors 'none'`)
  that is at least as strict; this local result is not deployed-origin
  acceptance.

No public-network Lightning node, real funds, external WebPKI Cashu mint,
production catalog, remote PIR server or production database participated in
these tests.

### Accepted P2 and environmental residuals

- Deadline guarantees are process-local monotonic elapsed-time budgets, not
  kernel cancellation or real-time scheduling guarantees. HTTPS uses one
  connect budget for resolver wait plus all TCP candidates and a second I/O
  budget for TLS handshake, complete request write and response read-to-EOF.
  A timed-out system resolver may continue in a capped background worker. The
  current trickle test exercises the deadline TCP wrapper; it is structural
  coverage for rustls I/O, not a full end-to-end trickled-TLS test.
- CLN creates one deadline before local-socket path validation and spends its
  remainder on connect, full write and full read. Filesystem metadata calls are
  not preemptible by that budget. After any positive application-byte write,
  timeout, EOF, oversize, framing, JSON or unverifiable response is
  outcome-unknown and may recover only by lookup or byte-exact replay under
  the same durable private label. A deterministic real Unix zero-byte-write
  failure injection remains absent; the semantic precommit boundary is tested.
- Publisher and readback stable-file checks assume a protected local
  Unix/POSIX regular filesystem with coherent metadata. Same-file-descriptor
  pre/post snapshots cover device, inode, mode, size, mtime and ctime, and Rust
  synthetic tests mutate each field. Node has symlink/FIFO/device/size and
  aggregate-bound tests but no deterministic live changing-file case. NFS,
  FUSE, a writable parent, same-UID compromise, root compromise or a malicious
  filesystem are availability/operations trust boundaries, not properties
  repaired by `O_NONBLOCK` or relay timeouts.
- Payment-owned mutable buffers are cleared on the reviewed server, Rust SDK,
  WASM wrapper and asynchronous Web success/error paths on a best-effort
  basis. Immutable JavaScript strings, JSON/Base64, wasm-bindgen/WebCrypto/GC,
  allocator history, browser networking and OS buffers can retain copies. No
  forensic-erasure claim is made. Some public Rust `Vec<u8>` bearer APIs and
  BOLT11 recovery/request copies remain P2 hardening opportunities.

The privacy verdict is unchanged: invoices, payment hashes, preimages and
payer data remain outside PIR providers and the PIR query wire. The residual
shared-issuer timing correlation described above remains, which is why the
strict default selects provider and payment method independently for each leg.

## Post-delta current-tree note — 2026-07-28

This note records code facts and narrowly scoped local evidence added after the
dated review above. It is not a new complete independent security-review verdict,
production acceptance or substitute for pushed CI. The final aggregate local
execution record is stated explicitly at the end of this note.

- A later red-team P0 found that an exact issuer-signed shared-redeem replay
  could deliver a second provider grant because issuer atomic redeem had no
  separate provider-local delivery claim. It also found that exact grant
  successors constructed from cloned ProviderStore state could be byte-identical
  at the external CAS boundary. The fixes derive the wire idempotency key from a
  deterministic per-provider-secret HMAC of the exact credential coordinates,
  verify the canonical issuer-signed success, and only then claim a separately
  domain-separated HMAC local-delivery key in ProviderStore synthetic namespace
  `0x8001`. First claim alone grants; providers retain independent secrets and
  stores and do not share a spent set. Every grant transition now includes a
  fresh nonzero 256-bit OS-RNG nonce; provider-local spend, Free-IP and final
  Standard-Cashu grant advance `spend_seq`, so a cloned exact race has one
  anchored winner and one fail-closed loser. Independent detailed databases are
  not supported active/active replicas.
- The browser quote-claim private key, redeem wire idempotency key and local
  delivery key are distinct. Only the HMAC-derived local key/digest and minimal
  namespace bookkeeping may occupy the spent row; invoice, payment hash,
  preimage, token/raw credential and exact token timestamp remain absent. The
  credential binding's `amount` is also independent from clearing
  `accepted_value`; only the latter equals provider credit plus issuer fee.
- Outcome-unknown shared redeem permits exact replay only to a low-level caller
  that explicitly retained the identical proof. Official Web burns/deletes
  before send and does not auto-retry; loss of `AUTH_GRANTED` after the local
  claim consumes the entitlement. Focused current-tree results are 93/93
  `pir-service-store` tests and 6/6 provider-clearing shared-grant tests. The
  subsequent final pinned-Linux aggregate and process matrix passed; pushed CI
  remains a separate per-commit merge gate.
- This correction reuses ProviderStore schema v7; it is not a migration. First
  activation is clean and forward-only. Recovery from any older local store or
  issuer replay history requires stopping every old process and rotating either
  the per-provider idempotency secret or clearing authorization digest/epoch.
  Reusing an empty local-claim set with old exact issuer replay history is
  forbidden.
- Provider settlement now has a schema-v2 SQLite detailed-state adapter with a
  random store-instance namespace, explicit `Pending`/`Payout`/`StatusPending`
  floor phases, history commitments and explicit authenticated recovery. Its
  bundled floor is local/test-only. Current-tree remote protocol/client/store
  and domain adapters are implemented, and provider/issuer application wiring
  accepts the shared pinned-HTTPS deployment config without local fallback;
  they have not yet received a complete current-tree security closeout or a
  production deployment. In the strict topology provider 0, provider 1 and
  their independently selected issuers require separately authenticated and
  operated authority instances whose observations are not pooled; one shared
  service would add a common timing, administration and availability observer
  even if its namespaces were access-controlled.
- `StrictHttpsProviderSettlementTransportV1` supplies a concrete
  WebPKI-plus-leaf-SPKI-pin provider-to-issuer adapter. Its constructor requires
  one or two distinct pins and has no unpinned fallback. It accepts only HTTP
  200 as success, preserves exact endpoint/media-type bindings and conservative
  outcome-unknown semantics after possible request transmission. It has not
  been deployed or accepted at a production edge.
- `IssuerPayoutOutboxWorkerV1` now exists. It persists `InFlight` before first
  submission and reconciles rather than resubmitting after restart or an
  ambiguous result. The shipped `NoFundsPayoutExecutorV1` is permanently
  disabled. No real-funds adapter exists, and a future adapter must supply a
  linearizable durable command-ID submission/lookup primitive or equivalent
  no-submit fence. A local worker lease is not external exactly-once authority.
- The Signet backup receipt is a strict, atomically replaced **operator
  assertion** bound to `getinfo` plus the current `staticbackup` digest. It does
  not prove an offline copy exists or restores. SCB/`staticbackup` supports
  channel recovery; it is not a live/dynamic `lightningd.sqlite3` backup and
  does not replace datastore-specific replication/backup and restore drills.
  Its output-parent advisory lock is explicitly released on every ordinary
  path: operation errors remain primary and success plus unlock failure fails
  closed. The current admin suite passed 106/106 five times under default
  parallelism and once single-threaded, with warnings denied.
- A browser/two-issuer/two-provider no-funds harness now extends generated-WASM
  direct-receipt/BAT admission through proof-bound Merkle preflight, one real
  encrypted two-server DPF query and an explicit inclusion/absence verdict.
  It still uses `NoSevHost`, synthetic report/database-proof material and an
  all-zero database, so it is not production identity, hardware-attestation or
  production-data evidence. The complete-query Free/ARC extension passed a
  dedicated local branch run after its admission-only predecessor. The final
  isolated-target current-tree rerun passed all three complete-query cases;
  exact-head CI remains separate. This is not deployed-origin evidence.
- The CDK ignored case now spends authenticated provider custody through a
  second independent NUT-03 client and expects first-custody
  `UNSPENT -> SPENT` plus successor-custody `UNSPENT` without argv bearer
  exposure. After two earlier branch passes, the final 2026-07-28 current-tree
  default-mode runner exited 0: its current admin/WASM build succeeded and its
  Chromium, native-WASM and provider-custody cases each passed 1/1. The run
  performed two real NUT-03 swaps and four exact NUT-07 observations against
  the disposable loopback mint, then left no owned CDK child or private runtime
  directory. The gate first caught and closed a required synthetic leaf-SPKI
  field omission and an obsolete ignored-test import. The older CDK evidence
  above proves only original-input `SPENT` and initial custody `UNSPENT`.
- The final 2026-07-28 current-tree CLN regtest runner exited 0 after rebuilding
  WASM offline. One disposable `bitcoind` and issuer/router/payer CLN topology
  forced the payments over two announced channels. Acquisition/recovery passed
  3/3 and the joined two-provider verified-query phase passed 1/1; cleanup left
  no owned Core/CLN process or private runtime directory. This validates the
  stated local adapter and synthetic provider/query composition only. It is not
  Signet, public-Lightning, real-funds, production-attestation or deployed-edge
  evidence, and ARC remains experimental.
- Native strict-pair selection now matches the Web guard: after each signed
  credential binding has supplied the protocol-required 99-byte ARC key shape,
  the SDK reuses the pinned ARC adapter's typed P-256 decode, byte-exact
  re-encode and domain-separated public-key fingerprint. It rejects malformed,
  zero/identity, non-canonical or reused raw ARC keys before considering the
  shared-issuer override, including when provider, policy, directory-operator,
  issuer and endpoint identities are otherwise independent. Positive distinct-
  key and negative copied-key tests passed in the coordinated non-server
  package run and final 27-package aggregate; pushed CI remains required per
  candidate commit.
- ARC remains experimental and production-disabled pending independent
  cryptographic and implementation review.
- Harmony V2Full now keeps the ready filename unchanged and holds only an
  advisory inode lock across authorization. Rejection or disconnect before the
  first main dispatch performs no attacker-driven rename/fsync/refill; first
  dispatch verifies the inode and durably unlinks it before PRP exposure. The
  pool also has an exact binding marker and conservative stable-snapshot
  reconciliation. mmap ownership is now `Arc<Mmap>` through the worker lifetime and the
  pool joins the worker on drop; the lifecycle/lock-order review found no
  remaining UAF or ABBA blocker under the documented immutable-local-POSIX
  filesystem contract.
- This change intentionally leaves a bounded availability tradeoff: a
  canonical but invalid proof, especially one requiring Standard Cashu or
  shared-issuer online authorization, can hold a scarce ready inode until the
  bounded check or pre-authorization deadline ends. It cannot consume/refill
  that hint. A new online-V2Full sub-limit always leaves one global AUTH permit
  and one ready entry for provider-local verification, but the online slice can
  still be saturated. Source-aware edge admission or a reviewed puzzle, tight
  concurrency/dependency deadlines, pool headroom and saturation testing are a
  production activation gate; finite semaphores alone do not promise fair
  online admission against a distributed attacker. Online V2Full now acquires
  its narrower permit before the global AUTH permit and retains it through
  pending dispatch/drop. Its 30-second-or-shorter dispatch deadline is armed
  only after the complete encrypted `AUTH_GRANTED` frame is written and flushed,
  so a slow successful flush cannot consume the dispatch window. The absolute
  instant is then immutable and bounds each pending read plus any Ping/Pong
  response. Apart from bounded WebSocket control handling, the only accepted
  application frame is the exact encrypted canonical `HarmonyHintsV2` request
  for the grant-bound database; malformed, cleartext, wrong-database and
  unrelated application frames close and release the unexposed reservation.
- Floor-aware reservation uses a non-blocking attempt on the cross-process
  capacity lock and counts only currently lockable paths from the current
  process's fully validated, ready `PoolState` snapshot. A corrupt or
  not-yet-validated canonical-looking disk file cannot satisfy the floor. A
  `SelectedLocked` queue head rotates behind the bounded snapshot so a peer-held
  inode cannot hide a later usable candidate. Each successful online decision
  leaves one validated, currently lockable entry at that instant, even while the
  pool is partially filled or opened by more than one process. It does not
  reserve that entry for a provider-local caller or promise fairness, priority or
  immediate admission.
- Capacity, durable/legacy reservation, generation, staged and reconciliation
  inode locks now use explicit-unlock guards with primary-error precedence and
  success-plus-unlock-error fail-closed behavior. This closes the fork/exec
  window in which child ownership of a duplicated open-file description could
  transiently retain a lock after the parent dropped its `File`.
- The 2026-07-28 current focused closeout passed 56/56 hint-pool unit tests five
  times under default parallelism and once single-threaded, plus warnings-denied
  runtime-lib clippy. The final pinned-Linux matrix then passed the current
  56/56 hint-pool suite, 64/64 `unified_server` suite and real Harmony lifecycle
  E2E 1/1. The repeated focused results remain separately identified rather
  than being folded into a false unique aggregate count.
- A final independent read-only gate found no implementation P0/P1 after its
  generation-marker cleanup P2 was corrected. Its non-blocking residuals remain
  explicit: the child
  floor test sequences a parent-held reservation before releasing the child's
  already-loaded snapshot rather than randomizing simultaneous capacity-lock
  acquisition; one test helper's final `wait_with_output` has no parent-side
  watchdog; cross-process online and provider-local callers still contend on a
  non-fair `try_lock`; and real WebSocket backpressure/Ping integration plus an
  explicit global-AUTH-full permit-return regression would strengthen future
  DoS testing. None changes the provider-local no-fairness/no-immediate-admission
  boundary or removes the production saturation gate.
- The new unlock tests cover same-process success/error/drop reuse and the
  default-parallel stress above, but do not deterministically hold an inherited
  duplicate descriptor across a fork barrier. That stronger regression remains
  a P2 test improvement, not evidence that the production guard still relies on
  descriptor close for release.
- The extended CDK lifecycle and forced two-hop three-node CLN runner passed
  final 2026-07-28 current-tree opt-in reruns. The feature-gated
  Standard-Cashu/Free two-provider process cell subsequently passed the final
  current-tree pinned-Linux matrix 1/1 with its clippy and release guards. The
  final isolated-target current-tree browser rerun passed the real-issuer case
  1/1 and complete-query harness 3/3. Exact-head CI remains separate. None is
  external-mint, public-Lightning, deployed-origin or
  real-funds acceptance.
- Pre-marker and current binaries are not live-compatible on one pool
  directory. The runbook now requires a full drain, a fresh empty private
  directory for the new binary, and a preserved separate directory for any old
  binary rollback. Markerless recognized pool state, mismatched/corrupt markers
  and exact legacy tmp/consumed residue fail startup without automatic deletion;
  an older reserved artifact under a valid matching marker is instead recovered
  conservatively under lock.

The subsequent final pinned-Linux current-tree matrix reported 1294 aggregate
passes and 41 explicit opt-in/documentation ignores, with all dedicated Rust,
process, clippy, release-guard, fixture and runner-validation stages passing.
This supplies an aggregate local execution record, not a new independent
security-review verdict or production acceptance. Every dedicated result above
retains its stated local/no-funds boundary, and exact-head pushed CI remains a
separate merge gate.
