# Payment platform implementation status

Status snapshot: 2026-07-26. This document describes repository code and local
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
- [x] ProviderStore schema v5 with global provider-local spend uniqueness,
      BAT raw-key lineage, durable Free IP quota state and standard-Cashu swap
      recovery intents.
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
      at-most-once grant issuance. The external mint remains the authoritative
      spender and an online availability dependency.
- [x] BitcoinPIR Cashu BAT blind/unblind/DLEQ path, provider-local verification,
      raw-DHKE-key lineage and durable spend adapter.
- [x] Scoped ARC draft-01 issuance/presentation, client nonce typestate,
      runtime adapter, ProviderStore tag persistence and restart/concurrency
      tests. This remains **experimental** until an independent cryptographic
      and implementation review is complete.
- [x] Optional authenticated shared-issuer redeem, blind settlement promise,
      provider ledger credit, deposit, balance, payout intent and durable
      payout outbox models.

### Lightning issuer and clients

- [x] Durable BOLT11 quote/status/claim lifecycle, exact request idempotency,
      private claim-key status polling, signed monotonic snapshots and lost
      response recovery.
- [x] Native Core Lightning adapter over a checked local Unix JSON-RPC socket.
      It validates the returned invoice, amount, network, payee, creation time,
      expiry and payment hash and does not expose the preimage.
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
- [x] Native SDK and WASM service-policy/auth helpers, browser encrypted
      capability/quote vaults, multi-tab locks and local independent-provider
      offer checks.
- [x] Strict browser standard-Cashu V3/V4 import normalizes wallet tokens to
      canonical `StandardCashuSpendV1`, rejects unknown/witness/DLEQ/NUT-10
      fields, and closes mint, unit, keyset, denomination, fees and amount to
      the exact signed offer before encrypted-vault installation.
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
- [x] Offline `bpir-admin service-keygen`, `service-policy` and
      `directory-artifact` commands. Directory tooling emits artifacts; it does
      not publish them to a relay.
- [x] Dedicated payment-platform CI workflow for Rust, unified-server wiring
      and wasm32 compilation.

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
- [x] A no-funds loopback test launches two independent `unified_server`
      provider processes with distinct policy/receipt keys and durable stores,
      then exercises real WebSocket, ephemeral-bound secure-channel, exact
      signed manifest-root policy, direct-receipt admission, DPF execution,
      resource-limit rejection, cross-provider isolation and replay rejection
      after provider restart. It intentionally uses `NoSevHost` and
      `dangerous_unpaired_*`, so it is not production identity, binary-pin or
      hardware-attestation evidence.
- [x] Web unit tests cover acquisition recovery, directory storage, vault
      locking and local pair-selection boundaries.

The exact reproducible commands are in `LOCAL_ACCEPTANCE.md` and
`scripts/payment-v1-local-check.sh`. These are library and loopback provider
process integration tests. They are **not** evidence of a public-relay,
external-mint, real-node, production proof-chain or deployed
browser/issuer/two-provider end-to-end run.

## Implemented but not production-activated

- [ ] The `payment-issuer serve-cln` executable path is implemented but has not
      been connected to a node. It deliberately binds loopback and expects an
      exact-owner local Unix RPC socket. Production TLS ingress, source-aware
      abuse controls, process supervision and operational key custody remain
      deployment work.
- [ ] No real Lightning node has been connected and no real invoice has been
      paid as part of this work. Real-funds operation needs explicit approval.
- [ ] No external Cashu mint has been contacted. Mint compatibility,
      availability, fee behavior and recovery have not been canary-tested.
- [ ] No public Nostr relay has been read or written. Native relay transport is
      not implemented; browser relay transport and offline publisher artifacts
      are implemented.
- [x] The main browser UI exposes an inline payment/access row for each selected
      provider and drives strict offer selection, acquisition/recovery, vault
      reservation and authorization before query. Harmony hint and query remain
      separate selections. This is unit-tested product wiring, not evidence of
      a deployed browser-to-two-server network E2E.
- [ ] No production deployment, remote-server operation, key installation,
      database migration or real-money operation has been performed. Each
      requires fresh user approval immediately before execution.
- [ ] No user manual acceptance test has been performed.

## Release blockers

The following are blockers, not follow-up polish:

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
   sufficient. The SQLite database and rollback authority must be restored and
   backed up in independent failure/administrative domains. Co-snapshotting
   them lets a stale pair become self-consistent and defeats rollback defense.
   Key custody, monitoring, recovery and failover procedures need an operator
   drill.
4. **First production store ceremony.** Payment V1 has no released v4 store to
   migrate. The fresh-v5 initialization tool exists, but independent backup /
   rollback-authority placement, restore drills and operational custody still
   need environment-specific acceptance. Development v4 state is not migration
   input; see `PROVIDER_STORE_V4_MIGRATION.md`.
5. **Reproducible network E2E.** A committed deterministic no-funds fixture
   assembles two independent providers, all five workloads/methods and issuer
   artifacts. The current acceptance additionally launches two independent
   loopback provider processes for direct-receipt DPF wire/gate coverage. It
   still does not launch the browser, fake issuer and both providers as one
   fault-injected topology, and it does not execute Cashu/ARC or the Harmony,
   Onion and TEE-ORAM backends across process boundaries.
6. **External dependency canaries.** Core Lightning, an external Cashu mint and
   public Nostr relays need approved regtest/signet/staging canaries, outage and
   restart drills, compatibility observations and data-retention review.
7. **ARC review.** ARC must remain hidden behind an experimental offer/UX label
   and must not be a production-required method until independent review is
   closed.
8. **Security closeout.** Fuzz/DoS coverage, forbidden-field logging audit,
   dependency review, browser threat review and an independent end-to-end
   security review remain release gates.

## Default topology and privacy warning

For a strict two-provider query, choose provider 0 and provider 1 separately,
use separate provider keys/stores, and by default use independent issuers or
provider-local/offline-verifiable methods. Do not configure both legs to redeem
synchronously through one shared online issuer unless the user explicitly
accepts that the issuer can correlate provider, scope and timing across both
redemption streams. Different blind capabilities remove a direct token join;
they do not remove common-infrastructure traffic analysis.

## Production guard

Production deployment, remote-server operations, public relay publication,
external mint access and real Lightning funds are outside the completed work.
They require a fresh, explicit user approval immediately before execution.
