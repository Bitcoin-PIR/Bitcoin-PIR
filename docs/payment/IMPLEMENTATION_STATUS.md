# Payment platform implementation status

Status snapshot: 2026-07-27. This document describes repository code and local
tests, not a production deployment. “Implemented” means that a code path exists;
“tested” names the boundary actually exercised. It does not mean that an
operator has activated the path with real money or public infrastructure.

## Frozen protocol decisions

- [x] The browser selects and authorizes each PIR provider independently. A
      provider does not need to know its peer and receives no pair identifier.
- [x] Offers are bound to provider, backend, workload role, dataset rule,
      operation profile and entitlement. Harmony hint and Harmony query are
      distinct scopes because their costs differ.
- [x] Free, direct BOLT11 receipt, standard Cashu eCash, BitcoinPIR Cashu BAT
      and ARC are in the v1 protocol surface. ARC is explicitly experimental.
- [x] BOLT11 acquisition is separate from PIR authorization. The PIR server and
      PIR wire do not receive the invoice, payment hash, preimage or payer data.
- [x] Consumption is at-most-once. There is no automatic query retry, refund or
      credit restoration after the authoritative spend boundary.
- [x] Provider-local keys and stores are independent. The default strict
      two-provider profile does **not** use one shared online issuer for both
      legs.
- [x] A shared issuer/clearing service is optional. It learns the authenticated
      provider, scope and redemption timing and is therefore a common
      correlation and availability boundary, even when capability issuance is
      blind.
- [x] The currently central directory is discovery infrastructure, not a trust
      root. Live identity, attestation, binary, database-root and policy checks
      remain authoritative.
- [x] Operator identity, directory, Lightning node, issuer root/delegation,
      provider policy, receipt, BAT/ARC and settlement keys have distinct roles.
- [x] The untracked legacy `/Users/cusgadmin/bitcoin-pir/payment` prototype is
      quarantined as non-reproducible reference code; its LDK state is not an
      allowed migration source. See `LEGACY_PROTOTYPE_AUDIT.md`.

## Implemented and wired

### Protocol and persistence

- [x] Canonical, bounded service-policy, authorization, quote, issuance,
      clearing, settlement and directory types in the shared protocol crates.
- [x] `REQ_SERVICE_POLICY_V1` / `REQ_SERVICE_AUTH_V1` handling on the encrypted
      channel and strict rejection before secure-channel establishment.
- [x] Exact-digest retained-policy redemption on unified-server, native SDK and
      Web/WASM. The legacy current-policy request remains byte-compatible;
      retained policies are operator allowlisted, older than current,
      redemption-only, grace-bounded, exact-catalog-bound, and require
      pre-existing durable provider spend state.
- [x] Signed policy activation with provider identity, policy epoch/fork,
      credential-keyset and Cashu-manifest rollback floors.
- [x] ProviderStore schema v7 with global provider-local spend uniqueness,
      BAT raw-key lineage, durable Free IP quota state, standard-Cashu swap
      recovery intents, finite per-mint/unit custody exposure, encrypted
      provider-note lots, rollback-anchored offline export batches and
      digest-only all-SPENT custody-retirement evidence. Delivery ACK remains
      inside the exposure cap; only `SpentConfirmed` releases it.
- [x] ProviderStore and IssuerStore require a separate monotonic rollback-floor
      authority. Serving binaries open existing stores and fail closed on
      missing, stale, wrong-identity or wrong-schema state.
- [x] IssuerStore quote/claim, exact replay, key lineage, redemption,
      double-entry ledger, settlement and payout/outbox state.
- [x] Backend grant DFA and resource accounting for DPF, Harmony full hints,
      Harmony V2 two-socket hints, Harmony query, Onion and TEE-ORAM operations.
- [x] Unified-server process-wide connection and authorization semaphores,
      WebSocket handshake and connection-idle timeouts, a 512 KiB frame/message
      limit, a 16 MiB per-request chunk-reassembly limit and a 64 MiB
      process-wide reassembly budget. In enforced mode an additional absolute
      pre-authorization deadline starts after the WebSocket handshake and
      cannot be extended with Ping/control frames. Configurable limits have
      bounded CLI ranges and saturation fails before additional work.
- [x] Verification/tree-top preflight uses a separate fixed per-connection
      budget of 32 actual encoded WebSocket messages and 16 MiB. Chunked
      responses reserve the whole group before first egress; exhaustion is
      terminal and cannot be reset by another opcode.
- [x] Unified-server default runtime logs omit raw peer/client identifiers,
      query timing, selected database/group and per-query sizes. Detailed
      correlation logging requires `--unsafe-debug-query-logging` and emits a
      prominent non-production startup warning; a source-level forbidden-field
      scan guards the default connection loop.
- [x] Unified-server accepts an explicit `--bind-address`; its omitted default
      remains the pre-existing dual-stack wildcard `[::]`. Unknown or
      misspelled CLI arguments now fail closed instead of silently falling back
      to defaults.

### Payment and credential methods

- [x] Free open, persistent provider-local IP quota, secure-channel-bound proof
      of work and anonymous-ticket policy models. The server does not trust a
      client-asserted quota or priority.
- [ ] `priority_class` is signed and exposed as provider metadata, but the
      current `unified_server` has no class-aware connection or backend-work
      scheduler. Paid-priority/QoS claims are therefore not enabled in V1.
- [x] Provider-local direct BOLT11 receipt issuance and durable receipt spend.
- [x] Standard Cashu eCash merchant swap with exact-value NUT-03, NUT-09/NUT-07
      recovery, NUT-12 verification, encrypted recovery material and
      at-most-once grant issuance. Grant issuance atomically stores a separate,
      note-only custody lot; recovery and custody use distinct keyrings. The
      external mint remains the authoritative spender and an online
      availability dependency.
- [x] BitcoinPIR Cashu BAT blind/unblind/DLEQ path, provider-local verification,
      raw-DHKE-key lineage and durable spend adapter.
- [x] Scoped ARC draft-01 issuance/presentation, client nonce typestate,
      runtime adapter, ProviderStore tag persistence and restart/concurrency
      tests. This remains **experimental** until an independent cryptographic
      and implementation review is complete.
- [x] Transport-neutral authenticated shared-issuer redeem, blind settlement
      promise, provider ledger credit/deposit/balance, payout intent and
      durable payout/outbox models.
- [x] `payment-issuer` serves ledger-only `/v1/redeems`, balance,
      payout-intent, payout and payout-status routes. A raw loopback HTTP test
      covers BAT redeem through payout/status, store reopen, exact response
      replay after authorization/registration expiry and provider request-key
      rotation. Provider registration epochs are append-only issuer history;
      old keys authenticate only the durable latest exact replay, while old
      fresh, signature-tampered and wrong-provider requests fail closed. The
      final history-integrity implementation is covered by focused issuer-store
      and issuer-service payout/restart tests.
- [x] The transport-neutral provider settlement client covers authenticated
      balance, payout-intent, payout and status requests; canonical bounded
      response verification; retained issuer signing keys and provider
      registrations; and exact same-request recovery. It persists an exact
      pending **status** envelope before send and advances provider state plus
      a mandatory external rollback floor by CAS.
- [x] Initial payout uses a prepare/restore/submit typestate and independent
      pending floor. Only a persisted or exact rollback-protected restored
      marker may submit; response loss/restart resends identical bytes, and
      repeated payouts advance only from an atomically archived terminal
      predecessor. Fresh preparation uses real current time/current
      registration/current issuer key; retained trust is exact-replay-only.
      The independent audit reran all ten focused client cases and
      warnings-as-errors clippy, closing the send-before-persist P1.
- [ ] A production transport, concrete persistent
      `ProviderSettlementStateStoreV1` plus truly independent floor adapter,
      payout worker and deployment remain unselected. The passing library
      typestate does not enable production settlement payout.
- [ ] Settlement Cashu `/v1/settlement/keysets` and
      `/v1/settlement/deposits` remain transport-neutral protocol/store code;
      `payment-issuer` does not route them and no production ceremony enables
      them. The external payout worker and real-funds execution also remain
      disabled.

### Lightning issuer and clients

- [x] Durable BOLT11 quote/status/claim lifecycle, exact request idempotency,
      private claim-key status polling, signed monotonic snapshots and lost
      response recovery.
- [x] Native Core Lightning adapter over a checked local Unix JSON-RPC socket.
      It validates the returned invoice, amount, network, payee, creation time,
      expiry and payment hash and does not expose the preimage. Each RPC has
      one absolute wall-clock deadline across Unix-socket connect, complete
      request write and complete response read; trickled bytes cannot refresh
      that budget, and write-before/after failure classification is preserved.
- [x] Pure-Rust/WASM BOLT11 parser with signature recovery, canonical lowercase
      round-trip, fixed non-zero amount, network and payee verification. The
      browser controller persists encrypted recovery state before displaying
      the invoice and supports refresh/reopen recovery.
- [x] `payment-issuer init-store` creates only canonical-parent, private
      owner-only SQLite state, sets both DBs to 0600 and self-checks a clean
      production reopen. Issuer and enforced provider serving reject symlink,
      non-regular, wrong-owner/public-mode, non-private-parent and same-inode
      store/authority paths on supported Unix platforms. Both listeners are
      loopback-only and have bounded headers/bodies, I/O timeout, connection and
      process-wide request-rate limits. `serve-fake` is a deterministic local
      harness; `serve-cln` uses a checked local Core Lightning Unix RPC socket.
      Neither substitutes for a separately operated production TLS/abuse edge.
- [x] The shared strict HTTPS client gives DNS plus all candidate addresses one
      bounded connect deadline and gives TLS handshake plus the full request and
      response one I/O deadline. Resolver workers and returned addresses are
      capped, multi-address attempts share the remaining budget, and a timeout
      after any application request byte remains outcome-unknown.
- [x] Native SDK and WASM service-policy/auth helpers, browser encrypted
      capability/quote vaults, multi-tab locks and local independent-provider
      offer checks.
- [x] Selected high-risk, application-controllable owned mutable copies added by
      Payment V1 are best-effort zeroized at the server secure-channel boundary,
      SDK/WASM intermediate-copy boundary, unreleased WASM batch/ARC-handle
      boundary, and after asynchronous browser vault success or failure. This
      is lifetime reduction only: public Rust `Vec<u8>`/typed return
      allocations, some browser BOLT11 request/response/recovery buffers,
      immutable JavaScript JSON/Base64/invoice/token strings, and browser,
      WebCrypto, wasm-bindgen, allocator and OS copies remain explicit P2
      residuals. This is not a forensic-erasure claim. ARC remains
      experimental.
- [x] Strict browser standard-Cashu V3/V4 import normalizes wallet tokens to
      canonical `StandardCashuSpendV1`, rejects unknown fields, witness and
      NUT-10 conditions, accepts only the known NUT-12 wallet metadata shape,
      verifies each `dleq.e/s/r` proof against the signed manifest denomination
      key and the proof's exact `secret` and `C`, then strips every DLEQ value
      locally and never sends it to a PIR provider. It closes mint, unit,
      keyset, denomination, fees and amount to the exact signed offer before
      encrypted-vault installation.
- [x] Browser capabilities and BOLT11 recovery bind the exact policy digest in
      authenticated storage and lock selection. The IndexedDB v3 migration
      deletes legacy capability/recovery records that cannot prove that bind.
- [x] DPF and Harmony adapters accept independent per-leg operator pins;
      strict identity verification rejects missing or reused pins and never
      treats the deprecated shared-pin field as two independent anchors.

### Directory and operator tooling

- [x] Canonical NIP-01 event verification, provider assertion, 16-shard catalog
      checkpoints, tombstones, relay split-view checks and rollback state.
- [x] Browser relay fetching and encrypted IndexedDB directory state.
- [x] A no-account, process-local NIP-01 fake-relay integration test closes the
      signed publisher-artifact to two-relay read path through all 16 shards,
      production WASM verification and durable rollback acceptance. It covers
      independent-provider/key separation plus tamper, wrong-key, expiry and
      rollback rejection; it is not evidence of public-relay interoperability.
- [x] Offline `bpir-admin service-keygen`, `service-policy`, directory assertion,
      entry and checkpoint builders, plus an explicit native
      `directory-artifact publish` transport. Publishing accepts no signing key,
      requires a pinned directory public key, two through eight credential-free
      public `wss://` relay hostnames, exact per-event positive OK and bounded
      per-relay time/bytes. It attempts every relay and fails the command on any
      partial result; exact immutable artifacts can be rerun manually.
- [x] The staging-only Nostr readback tool accepts no key or publish operation,
      mirrors the Rust canonical public-`wss://` grammar on the raw input, and
      requires the Rust publisher's domain-separated event-set digest, valid
      recomputed NIP-01 event IDs, exact frozen event values and EOSE. Artifact inputs share one
      5 MiB budget and are opened without following the final symlink or
      blocking on a raced FIFO/device; pre/post `fstat` checks reject mutation.
      Node black-box tests cover URL aliases, symlink, FIFO, device, oversized
      and aggregate-oversized inputs and run in the payment CI browser job.
- [x] Offline `bpir-admin cashu-custody` tooling generates a provider-bound
      X25519 recipient key, reports aggregate inventory, atomically reserves a
      bounded note batch, persists one immutable recipient-sealed artifact
      before release, replays the exact artifact, decrypts to an owner-only
      canonical `cashuB` file and requires an explicit external-custody-only
      acknowledgement. ACK does not release exposure. The explicit one-shot
      `spent-confirm` command batches same-mint/unit exports through the strict
      HTTPS Cashu client, accepts only exact all-`SPENT` NUT-07 results, refreshes
      the rollback floor for every per-export commit and supports network-free,
      key-free exact terminal replay. It does not poll or claim NUT-05,
      Lightning settlement or provider payout.
- [x] Dedicated payment-platform CI workflow for Rust, unified-server wiring,
      wasm32 compilation and both local Chromium boundaries: multi-tab vault
      fault injection and generated-WASM/real-loopback-issuer acquisition. Its
      browser job uses pinned action SHAs, installs `wasm-pack 0.14.0` with
      Cargo `--locked` under Rust 1.94.1 instead of a remote shell installer,
      pins the lockfile-matched `wasm-bindgen-cli`, forbids install during the
      locked/offline build, disables execution of an ambient `wasm-opt`, and
      includes every `web/**` change in its path trigger.
- [x] The general Web PR and Pages workflows use the same pinned, locked,
      no-install/no-opt WASM boundary and exact action SHAs. The Pages build no
      longer rewrites the root workspace and therefore validates the real
      dependency graph before producing its artifact. Cargo/npm build steps
      have contents-read permission only; Pages write/OIDC is isolated to the
      deploy job. CI uses exact Node 24.18.0 on Ubuntu 24.04, watches the WASM
      toolchain/vendor/trust inputs, and the Pages build reruns TypeScript,
      unit tests, multi-tab vault and real-WASM/loopback-issuer boundaries
      before publishing. This is build hardening only; no deployment was
      triggered or authorized here.

## What the tests currently prove

- [x] A canonical encrypted authorization frame for each of the five v1
      methods reaches each of DPF, Harmony full hint, Harmony query, Onion and
      TEE-ORAM gate state, with replay terminal after the spend boundary.
- [x] Direct receipt and BAT production ProviderStore adapters persist/reject
      replay across restart; Free, Cashu and experimental ARC have focused
      persistence and concurrency suites.
- [x] Fake-Lightning backend, quote/claim state machines, issuer stores,
      clearing/settlement models and Core Lightning RPC mapping have
      deterministic no-funds tests.
- [x] Focused settlement coverage exercises the ledger-only HTTP service,
      transport-neutral provider client, append-only registration history,
      exact latest-response recovery across request-key rotation, wrong-
      provider/tampered-history rejection and mandatory provider-side floor
      progression. Initial payout coverage includes persist-before-send,
      outcome-unknown/restart exact replay, independent pending-floor rollback,
      terminal predecessor chaining and concurrent one-economic-effect submit.
      The final local `scripts/payment-v1-local-check.sh --full` run passed;
      pushed GitHub CI remains authoritative before merge.
- [x] Two no-funds loopback tests launch independent `unified_server` provider
      processes with distinct method keys and durable stores, then exercise
      real WebSocket, ephemeral-bound secure-channel, exact signed
      manifest-root policy, DPF execution, resource-limit rejection and
      restart persistence. Together they cover direct receipt, Free open/IP
      quota, provider-local Cashu BAT and experimental ARC, including
      cross-provider rejection without a shared spent set. They intentionally
      use `NoSevHost` and `dangerous_unpaired_*`, so they are not production
      identity, binary-pin or hardware-attestation evidence. Standard Cashu
      success remains at the deterministic mint-transport boundary because
      production HTTPS accepts only WebPKI roots and no test CA bypass exists.
- [x] Web unit tests cover acquisition recovery, directory storage, vault
      locking and local pair-selection boundaries.
- [x] A dedicated Playwright job runs the production browser vault and
      acquisition controller in real Chromium tabs. It covers one-winner
      single-use retirement, validation release/delete-before-return commit,
      ARC persist-before-presentation, reload plus exact lost-claim replay,
      atomic issuance installation and no payment-material `localStorage`
      writes. The SDK state machine and issuer HTTP are local test doubles;
      this is not a generated-WASM, issuer/provider-process, full-query or
      deployed-page E2E.
- [x] A separate Chromium boundary uses freshly generated `pir-sdk-wasm` and a
      real loopback `payment-issuer serve-fake` process for signed-policy
      verification, exact-price direct-receipt acquisition, authenticated
      status, lost-response byte-identical claim replay, issuer idempotency,
      atomic vault installation and WASM single-use validation. It uses only a
      deterministic no-funds regtest fixture and a test-only settlement route;
      the provider secure-channel exporter is synthetic, no provider/query is
      executed, and no wallet, Lightning node or real funds participate.
- [x] Offline CI runs a deterministic, bounded malformed-length/adversarial
      corpus across all public Payment V1 canonical decoders, known provider
      admission opcodes and the strict issuer/mint HTTP response boundary. The
      gate requires no network-installed fuzz tooling and retains explicit
      case-count/input-size bounds.
- [x] An opt-in disposable CDK 0.17.3 fake-wallet runner starts only a random
      loopback HTTP mint, obtains a real padded V4 `cashuB` token containing
      NUT-12 wallet metadata, and proves the production WASM importer accepts
      and normalizes it without forwarding DLEQ material. It then runs the
      production provider-side NUT-03 state machine against that real CDK mint,
      verifies the official full NUT-02 V2 keyset derivation and NUT-12 DLEQ,
      atomically commits the grant plus custody notes, and proves resume does
      not send a second swap. It uses no Lightning node or real funds and maps
      only one synthetic test identity to loopback; the production WebPKI HTTPS
      transport is unchanged. An unmodified provider-process/public-mint E2E
      remains a staging gap.
- [x] The product-owned wire-shape contract and compiled Rust conformance tests
      bind all five authorization methods and all five workload starts to one
      16,414-byte encrypted application request record. They separately admit
      authorization timing and variable result shape to a no-key network
      observer, and scheme/scope/operation/presentation/timing to the provider.
- [x] The external Payment V1 EasyCrypt lock is complete. It binds
      `Bitcoin-PIR/protocol-proofs@c519f1960aa9567ac324856f30c71071b04a4a17`,
      manifest digest
      `5763b9a4e5e40f7eed1f1f1eadeb44950c6b4172ea55c995ca24f062e0ee860d`,
      product contract digest
      `648227ffba4946b5adc55291bdb77eb452d93a5c03c553a17dc6f5d053b97bf7`
      and GitHub EasyCrypt run
      [`30202980581`](https://github.com/Bitcoin-PIR/protocol-proofs/actions/runs/30202980581).
      The downloaded verification record is content-addressed as
      `verification/records/formal/c97d8fff7b072154e78fb0388a076cb849a2d99e9968be7a9cd0d838268b54d8.json`.

The exact reproducible commands are in `LOCAL_ACCEPTANCE.md` and
`scripts/payment-v1-local-check.sh`. These are library and loopback provider
process integration tests. A separate authorized short-lived Nostr smoke is
recorded below; none of this is evidence of an external mint, persistent public
Lightning node, production catalog, production proof-chain or deployed
browser/issuer/two-provider end-to-end run.

The current 2026-07-27 closeout completed
`scripts/payment-v1-local-check.sh --full` from a fresh isolated Cargo target
with exit code zero: complete offline Rust/platform coverage, dedicated Payment
clippy, wasm32 plus fresh generated bindings, 333 passing Web unit tests with
two intentional skips, Chromium vault 4/4 and generated-WASM/real local issuer
1/1. Separate opt-in no-real-funds runs passed CLN local regtest 3/3 and both
CDK 0.17.3 interoperability cases. Exact boundaries and the one infrastructure
contention retry are recorded in `LOCAL_ACCEPTANCE.md`; pushed GitHub CI remains
authoritative before merge.

## Implemented but not production-activated

- [ ] The `payment-issuer serve-cln` executable path is implemented and has
      crossed the disposable two-node local-regtest boundary below, but has not
      been connected to a persistent, external or public-network node. It
      deliberately binds loopback and expects an exact-owner local Unix RPC
      socket. Production TLS ingress, source-aware abuse controls, process
      supervision and operational key custody remain deployment work.
- [x] The opt-in local-regtest runner connects the production CLN adapter to two
      disposable Core Lightning nodes, opens a regtest-only channel and pays a
      real BOLT11 invoice with valueless mined coins. It never reaches a public
      Lightning network or uses real funds; either still needs explicit
      approval.
- [x] A disposable loopback CDK 0.17.3 fake-wallet mint has exercised padded V4
      import, provider-side NUT-03 swap/NUT-12 verification, custody commit and
      one-shot NUT-07 verification that the original NUT-03 inputs are `SPENT`
      and the fresh provider-custody outputs are `UNSPENT`. CDK 0.17.3 exposes
      custody receive only through bearer-token argv, so this runner
      intentionally does not prove custody `UNSPENT -> SPENT` or execute admin
      retirement against CDK. No public/WebPKI Cashu mint has been contacted,
      and production availability, fee behavior and recovery have not been
      canary-tested.
- [x] Native Nostr publisher transport is implemented and covered through
      transport-neutral local WebSocket sessions, including positive, reject,
      duplicate/unexpected/missing, non-text, oversized, timeout and partial
      failure behavior. Distinct hostnames do not prove independent operators.
- [x] One authorized public-relay smoke published a 30-minute, empty 16-shard
      checkpoint signed by a disposable test key. nos.lol and
      `relay.primal.net` each returned 16 positive matching OKs, then returned
      all 16 exact event values plus EOSE on ID-filtered readback. Damus failed
      at the transport boundary and was not counted as success. The test key
      and local artifact were deleted; this is public transport/relay-policy
      evidence, not a production catalog or proof of relay-operator
      independence.
- [x] The main browser UI exposes an inline payment/access row for each selected
      provider and drives strict offer selection, acquisition/recovery, vault
      reservation and authorization before query. Harmony hint and query remain
      separate selections. This is unit-tested product wiring, not evidence of
      a deployed browser-to-two-server network E2E.
- [ ] A dedicated production directory key has been generated locally in an
      owner-only repository-external directory, but it has not been backed up,
      copied to a host or used to sign/publish a production catalog. No
      production deployment, remote-server operation, database migration or
      real-money operation has been performed. Each still requires its explicit
      deployment ceremony and approval boundary.
- [ ] No user manual acceptance test has been performed.

## Production release blockers and gates

The implementation-code P1 findings, including initial payout
persist-before-send, are closed. One production data-integrity P1 remains: an
actually independent linearizable rollback authority is not deployed. The
other numbered items below are mandatory production release, operations,
external-review or manual-acceptance gates; they are not all implementation P1
findings and must not be collapsed into that count.

1. **Issuer production edge.** Both listeners cap simultaneous TCP connections,
   header/body size and I/O time and enforce process-wide quote, status,
   mutation and reconciliation rates plus durable quote capacity. They still
   lack a production TLS edge, source-aware/distributed abuse budgets, metrics,
   alerting, load evidence and a reviewed overload policy. Do not expose invoice
   creation publicly until those controls are deployed and tested.
2. **Tree-top/preflight edge capacity.** The server now has global connection
   and authorization concurrency caps, handshake/idle timeouts, an absolute
   enforced-mode pre-authorization deadline, a 512 KiB frame/message cap, a
   16 MiB per-grant reassembly cap, a 64 MiB global reassembly budget and a
   separate 32-message/16-MiB per-connection preflight egress budget, in
   addition to per-grant limits and Harmony shared-socket accounting. Tree-top
   preflight remains intentionally available before a paid grant and can serve
   large public blobs across many connections. Production still needs
   independently tested reverse-proxy/edge bandwidth, request-frequency and
   aggregate egress controls plus overload telemetry; the in-process limits do
   not close a distributed DDoS surface.
3. **Rollback authority deployment.** “Separate file” is necessary but not
   sufficient, and it is the only bundled floor adapter. The SQLite database
   and rollback authority must be restored and backed up in independent
   failure/administrative domains. Co-snapshotting them lets a stale pair
   become self-consistent and defeats rollback defense. A reviewed
   linearizable production adapter/deployment plus independent custody,
   monitoring, recovery and failover drills are still required. Provider
   settlement payout additionally has no concrete production
   `ProviderSettlementStateStoreV1` adapter or worker; the transport-neutral
   library cannot be activated by itself.
4. **First production store ceremony.** Payment V1 has no released v6 store to
   migrate. The fresh-v7 initialization tool exists, but independent backup /
   rollback-authority placement, restore drills and operational custody still
   need environment-specific acceptance. Development v4 state is not migration
   input; see `PROVIDER_STORE_V7_MIGRATION.md`.
5. **Reproducible network E2E.** A committed deterministic no-funds fixture
   assembles two independent providers, all five workloads/methods and issuer
   artifacts. The current acceptance additionally launches two independent
   loopback providers for direct-receipt, Free, provider-local Cashu BAT and
   experimental ARC DPF wire/gate coverage, and separately launches real
   Chromium with generated WASM plus a real loopback fake issuer. It still does
   not launch the browser, issuer and both providers as one fault-injected
   topology; it does not execute standard Cashu success, Harmony hint/query,
   Onion or TEE-ORAM across provider process boundaries.
6. **External dependency canaries.** The disposable local CLN and CDK runners
   and one short-lived public Nostr transport/readback smoke are complete.
   Persistent Testnet4 Lightning, an external WebPKI Cashu mint, production
   catalog publication and monitored relay selection remain staging gates. The
   final topology also needs production identity/attestation/pins, TLS/edge
   controls, outage/restart drills, compatibility observations and
   data-retention review.
7. **ARC review.** ARC must remain hidden behind an experimental offer/UX label
   and must not be a production-required method until independent review is
   closed.
8. **Security closeout.** Coverage-guided/long-running fuzzing beyond the
   bounded deterministic CI corpus, broader DoS coverage, forbidden-field
   logging audit, browser XSS/CSP review, deployed-edge abuse testing,
   operator/store drills and an independent end-to-end security review remain
   release gates. The local dependency audit found no vulnerability and four
   documented allowed upstream/vendor warnings; their ownership and upgrade
   plan remain explicit residual work. The completed formal lock is not a
   substitute for these implementation and deployment reviews.

The current formal Payment V1 lock is not a blocker. Any future change to the
wire-shape contract, however, invalidates the pinned EasyCrypt manifest and
verification record and must repeat the external proof CI plus product relock
before merge.

## Default topology and privacy warning

For a strict two-provider query, choose provider 0 and provider 1 separately,
use separate provider keys/stores, and by default use independent issuers or
provider-local/offline-verifiable methods. Do not configure both legs to redeem
synchronously through one shared online issuer unless the user explicitly
accepts that the issuer can correlate provider, scope and timing across both
redemption streams. Different blind capabilities remove a direct token join;
they do not remove common-infrastructure traffic analysis.

## Production guard

Production deployment, remote-server operations, production-catalog
public-relay publication, external mint access and real Lightning funds are
outside the completed work. They require a fresh, explicit user approval
immediately before execution.
