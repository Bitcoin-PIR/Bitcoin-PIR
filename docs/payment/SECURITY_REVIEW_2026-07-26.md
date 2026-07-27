# Payment V1 implementation security review — 2026-07-26

> Historical snapshot: the body of this review is bound to repository commit
> `bc465c76` and records the evidence available on 2026-07-26. Later CLN, CDK,
> Cashu-custody-v7 and public-Nostr work must not be inferred from statements in
> the historical body. The additive 2026-07-27 delta at the end is the current
> closeout record; where the two differ, the dated delta controls.

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
deployment has been accepted in this work. The transport-neutral provider
client also has no production `ProviderSettlementStateStoreV1` adapter or payout
worker; its library typestate is not authorization to activate settlement.

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
  Web inputs. The Pages build also reruns strict TypeScript, unit tests and both
  local no-funds Chromium Payment boundaries, so it cannot publish while those
  gates fail in a parallel workflow. The scheduled strict-production canary
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
the absence of a concrete production provider store/worker/independent-floor
adapter remains an activation blocker. No remote operation or real-funds test
was performed by this review.

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
- a production provider settlement state adapter and worker are not deployed,
  so payout remains disabled. That gap, production edge, distributed abuse
  control, backup/restore ceremony, monitoring, external canaries, browser/XSS
  review, ARC review and user manual acceptance are explicit release gates,
  not additional items in the counted production data-integrity P1 total.

The final independent static deadline and sensitive-buffer reviews found no
additional P0/P1. ARC remains experimental and production-disabled until its
independent cryptographic and implementation review is complete.

### Current verification evidence

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
