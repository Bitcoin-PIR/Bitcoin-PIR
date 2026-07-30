# Payment platform implementation status

Status snapshot: 2026-07-30. This document describes repository code and local
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
- [x] Shared redeem separates the issuer's authoritative credential/settlement
      mutation from the provider's one-time grant delivery. The wire replay key
      is a deterministic per-provider-secret HMAC of the exact credential
      coordinates. Only after exact signed issuer-success verification does the
      provider claim a separately domain-separated HMAC key in its own
      rollback-protected store; the first claim alone grants, and providers do
      not share a spent set.
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
- [x] A separate exact-digest storeless activation path is intended for a
      measured Free-PoW provider. It rejects empty policies/scopes and every
      non-provider-local Free proof-of-work or decorated issuer/credential
      offer, and `unified_server` refuses retained policies, ProviderStore,
      rollback, Free-IP, payment, Cashu/BAT/ARC/shared-issuer, legacy keyset and
      test-root inputs in that mode. A real loopback child-process test performs
      secure-channel challenge, PoW solution, AUTH and one protected DPF frame,
      rejects the same solution on a second secure-channel exporter with no
      outstanding challenge, and confirms that no provider/rollback
      SQLite/WAL/SHM appears. This is source/test evidence, not proof that a
      VPSBG UKI has been built, uploaded, or measured. A deployment may claim
      measurement only after its exact policy digest and startup arguments are
      covered by independently verified UKI/attestation evidence; any policy
      renewal or signed-byte change then requires a new UKI and client pin
      ceremony.
- [x] ProviderStore schema v7 with global provider-local spend uniqueness,
      BAT raw-key lineage, durable Free IP quota state, standard-Cashu swap
      recovery intents, finite per-mint/unit custody exposure, encrypted
      provider-note lots, rollback-anchored offline export batches and
      digest-only all-SPENT custody-retirement evidence. Delivery ACK remains
      inside the exposure cap; only `SpentConfirmed` releases it. The same
      schema now stores the shared-issuer local grant-delivery claim under
      synthetic namespace scheme `0x8001`: only its HMAC-derived local key and
      minimal spent bookkeeping are retained, never invoice/payment/token/raw
      credential data or a browser quote-claim private key. This is not a schema
      bump.
- [x] Grant-producing ProviderStore transitions use a fresh nonzero 256-bit
      OS-RNG nonce. Provider-local spend, Free-IP and final Standard-Cashu grant
      advance `spend_seq`; exact cloned-state callers racing the same external
      floor CAS have one anchored winner and a fail-closed loser. Independent
      ProviderStore databases are not an active/active replication mechanism.
- [x] ProviderStore and IssuerStore require a separate monotonic rollback-floor
      authority. Serving binaries open existing stores and fail closed on
      missing, stale, wrong-identity or wrong-schema state.
- [x] The shared remote rollback-authority protocol, durable store and blocking
      client authenticate every Read/CAS and use WebPKI plus one or two
      out-of-band leaf-SPKI pins. Provider and issuer domain adapters seal
      independent namespace-bound opaque floors. `unified_server`, provider
      store init/check and every Cashu-custody store open accept exactly one
      local-test SQLite floor or remote config with no fallback; public provider
      serving requires an explicit dev acknowledgement for local mode. Remote
      init requires a pre-preserved store-instance ID. Non-default loopback
      process E2Es now exercise both `unified_server` and the real
      `payment-issuer` binary through separate rollback-authority and pinned-TLS
      processes, including restart, wrong-CA, wrong-pin and offline fail-closed
      cases. These paths are not yet deployed.
      The fresh-store-only authority schema v2 separately bounds CAS operation
      rows and exact-call replay rows. It atomically persists each Read/CAS
      nonce, full request digest and opaque response snapshot, so byte-exact
      replay cannot observe a later live floor while fresh-nonce recovery keeps
      its normal semantics.
- [x] IssuerStore quote/claim, exact replay, key lineage, redemption,
      double-entry ledger, settlement and payout/outbox state.
- [x] Backend grant DFA and resource accounting for DPF, Harmony full hints,
      Harmony V2 two-socket hints, Harmony query, Onion and TEE-ORAM operations.
      Harmony V2Full remains granted after its main bundle for the same-socket
      cold-cache level-10+/20+ sibling sequence; query admission binds exact
      padded level/round pairs and rejects legacy `0x42`. Onion is register-once
      with monotonic INDEX/CHUNK/Merkle phases. DPF permits consecutive INDEX
      jobs but rejects INDEX rollback after its first CHUNK/Merkle follow-up.
      Padded K, T-1 indices and FHE ciphertext fanout count as work rather than
      logical inputs. SDK decoders
      bind response opcode/level/round and reject malformed canonical errors,
      truncation and trailing bytes. V2Full now has canonical two/three-byte
      request bodies;
      `--pool-db-id` binds one process's single pool to one loaded snapshot or
      delta, and a granted client forces V2Full for that exact database without
      paid V1 fallback. Same-process multi-database pools remain out of V1
      scope. V2Full now reserves one entry atomically after exact structural
      binding but before credential commit by locking the unchanged ready inode;
      rejection/pre-use disconnect returns it without a filesystem mutation,
      while first main dispatch unlinks and directory-fsyncs only the
      connection's exact inode before exposing its PRP key. The pool now has an
      exact database/backend/geometry binding marker, conservative startup
      reconciliation, stable directory scans and short-lock inode identity
      checks. Online floor accounting considers only fully validated, currently
      ready local `PoolState` paths; corrupt/unvalidated canonical-looking disk
      surplus cannot make the floor pass. The reservation hot path uses a
      non-blocking capacity-lock attempt, and a `SelectedLocked` queue head
      rotates behind the bounded snapshot so it cannot hide a later usable
      candidate. A real child-process barrier test holds one inode in another OS
      process and confirms that online admission preserves the remaining entry
      for provider-local reservation. Capacity, durable reservation, legacy,
      generation, staged and reconciliation inode locks now use explicit-unlock
      guards, so a forked child cannot retain a released open-file-description
      lock merely by inheriting a descriptor. Operation errors remain primary;
      success followed by unlock failure fails closed. The 2026-07-28 focused
      Linux Rust 1.94.1 closeout passed the resulting 56/56 hint-pool tests five
      times under default parallelism and once single-threaded, plus warnings-
      denied runtime-lib clippy. Full-matrix and pushed-CI evidence remain
      separate below.
- [x] Unified-server process-wide connection and authorization semaphores,
      WebSocket handshake and connection-idle timeouts, a 512 KiB frame/message
      limit, a 16 MiB per-request chunk-reassembly limit and a 64 MiB
      process-wide reassembly budget. In enforced mode an additional absolute
      pre-authorization deadline starts after the WebSocket handshake and
      cannot be extended with Ping/control frames. The same fixed deadline
      covers every pre-grant write/flush, including preflight groups and the
      authorization result. It is rechecked after a potentially blocking
      authorization/remote-authority commit, which is not cancelled; only a
      successfully flushed granted result switches to ordinary idle handling.
      An expired connection performs no backend work. A V2Full reservation then
      uses a separate immutable 30-second-or-shorter post-grant dispatch
      deadline, armed only after the complete encrypted `AUTH_GRANTED` frame is
      written and flushed. The same instant bounds pending reads and Ping/Pong;
      no frame resets it. Apart from bounded WebSocket control handling, the
      only accepted pending application frame is the exact encrypted canonical
      `HarmonyHintsV2` request for the grant-bound database. The 2026-07-28
      focused closeout passed 64/64 `unified_server` unit tests and repeated the
      real Harmony pool process E2E three times successfully. The subsequent
      final pinned-Linux matrix passed the current 64/64 server suite, 56/56
      hint-pool suite and Harmony process E2E 1/1. Configurable limits have
      bounded CLI ranges and saturation fails before additional work.
- [x] Verification/tree-top preflight uses a separate fixed per-connection
      budget of 32 actual encoded WebSocket messages and 16 MiB. Chunked
      responses reserve the whole group before first egress; exhaustion is
      terminal and cannot be reset by another opcode.
- [x] Unified-server default runtime logs omit raw peer/client identifiers,
      query timing, selected database/group and per-query sizes. Detailed
      correlation logging is absent from normal artifacts and requires the
      explicit `test-only-unsafe-query-logging` feature in Cargo's debug
      profile plus `--unsafe-debug-query-logging`; release and assertions-enabled
      release builds reject the feature. A source-level forbidden-field scan
      guards the default connection loop.
- [x] Provider serving still executes the full operational-inventory integrity
      read at startup but emits only a coarse success marker and elapsed time.
      Exact generation, spent, quota-bucket and Cashu inventory fields remain
      available only through the explicit non-serving store-check command.
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
      durable payout/outbox models. Shared service authorization derives one
      deterministic wire idempotency key from a provider-secret HMAC of the
      exact authorization/binding/credential digests. It verifies the exact
      issuer-signed response before claiming the separate local-delivery HMAC
      key in ProviderStore and maps a repeated local claim to `InvalidOrSpent`.
      The issuer never receives the local claim key. Credential-binding `amount`
      and clearing `accepted_value` are checked independently; the clearing
      invariant is `accepted_value = provider_credit + issuer_fee`.
- [x] Shared-redeem response-loss behavior is intentionally asymmetric. A
      low-level caller that explicitly retains the identical proof can replay
      the same deterministic transcript. The official Web path deletes/burns
      the proof before transmission and does not automatically retry; loss of
      `AUTH_GRANTED` after the local claim consumes the entitlement.
- [x] The production/default `payment-issuer` HTTP surface is ledger-accrual
      only: `/v1/redeems` credits the authenticated provider account and
      `/v1/settlement/balance` returns a signed balance. Payout-intent, payout
      and payout-status paths return the exact unknown-path response before
      clock access, content-type/body parsing, authentication, rate limiting or
      store access; their match arms and decoders are absent from non-test
      builds and there is no production enable flag. Production uses the
      explicit ledger-only service constructor and has no payout-target, fee or
      intent-TTL CLI/configuration. Each required store registration receives a
      fixed, domain-separated, non-zero disabled-target sentinel which cannot be
      selected by a request; all three transport-neutral payout methods also
      return `NotFound` before input decoding or store access in this mode. The
      settlement signing key remains necessary for redeem/balance signatures,
      and retained verifying keys remain available for exact committed redeem
      and approval recovery after rotation. Production registration now
      requires a separate provider-request public key for every authorization;
      startup rejects count mismatch, invalid keys and reuse with clearing,
      operator or issuer-settlement roles. Offline `bpir-admin` builders create
      and self-verify the operator authorization and independent issuer
      approval, while `ProviderLedgerBalanceClientV1` reads the signed
      auth-credit balance without inventing a payout registration or target.
      A private Rust unit-fixture
      switch retains the raw loopback payout/status roundtrip solely to test the
      transport-neutral state machines, store reopen, exact response replay
      after authorization/registration expiry and provider request-key
      rotation. Provider registration epochs are append-only issuer history;
      old keys authenticate only the durable latest exact replay, while old
      fresh, signature-tampered and wrong-provider requests fail closed.
      Focused Rust cases now assert removed production CLI flags and
      side-effect-free ledger-only method rejection; this no-Cargo deployment
      hardening pass formatted and parsed those files but leaves execution of
      the Rust cases to the exact-commit CI run.
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
      The send-before-persist implementation finding is closed by this state
      machine; current-tree verification evidence must be recorded separately
      after the settlement-v2 and worker changes stop.
- [x] A concrete SQLite `ProviderSettlementStateStoreV1` persists the exact
      provider payout workflow with a transition journal, random store-instance
      namespace, exact active/history commitments and strictly increasing floor
      revision. Checked open is pure read: an interrupted journal requires an
      explicit client-authenticated recovery token and exact snapshot rereads;
      startup never trusts structurally valid disk bytes enough to advance the
      authority. `StatusPending` is a distinct floor phase, and status-commit
      recovery proves that the signed successor answers the exact persisted
      request/nonce. Schema/magic v1 data fails closed without implicit
      migration. The bundled SQLite floor is explicitly local/test-only and
      does not establish an independent production rollback domain. Checked
      opens and mutations validate the full terminal history in O(provider
      payout history); no production scalability claim follows without a
      measured bound or reviewed checkpoint/archive design.
- [x] `IssuerPayoutOutboxWorkerV1` implements the no-funds payout worker state
      machine. It durably moves an accepted payout to `InFlight` before the
      first external submission, uses the stable command ID as the executor
      idempotency key, and performs reconcile-only handling after restart or an
      ambiguous result. Its bundled `NoFundsPayoutExecutorV1` is deliberately
      never ready and cannot move value. No application binary instantiates the
      worker in V1, and the production issuer cannot create its payout/outbox
      records through HTTP.
- [x] `StrictHttpsProviderSettlementTransportV1` is the concrete provider-to-
      issuer HTTPS adapter. Its production constructor requires normal WebPKI
      verification plus one or two distinct out-of-band leaf-SPKI SHA-256 pins;
      there is no unpinned fallback. It also enforces HTTP 200 as the sole
      success status, exact endpoint/media-type mappings, no
      redirect/cookie/proxy/decompression path, bounded responses, and
      conservative outcome-unknown classification after any request byte may
      have been sent. It has not been deployed.
- [ ] The remote production floor adapters exist for provider, issuer and
      provider-settlement state, but truly independent authority deployments,
      a real-funds payout executor and payout product remain unselected. A real
      executor must
      provide a linearizable durable command-ID lookup/submission primitive or
      equivalent no-submit fence; neither the worker lease nor local SQLite
      creates external exactly-once semantics. Ledger accrual and authenticated
      balance are the complete V1 settlement product; they do not promise or
      enable automatic value transfer.
- [ ] Settlement Cashu `/v1/settlement/keysets` and
      `/v1/settlement/deposits` remain transport-neutral protocol/store code;
      `payment-issuer` does not route them and no production ceremony enables
      them. The no-funds worker exists, but no real-funds executor is shipped or
      enabled.

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
      The prepared deployment adds a separately pinned, separate-UID method
      guard: it alone reaches the native CLN group socket, accepts only exact
      bounded `getinfo`, private-label `listinvoices` and invoice-creation
      shapes, reconstructs minimal responses, strips preimage/error payloads,
      enforces invoice amount/rate/burst/runtime ceilings and exposes a second
      issuer-group socket. The long-running issuer receives neither the native
      CLN group nor the Bitcoin-cookie group. Latest Linux ACL/hardlink and
      complete guard test evidence remains an exact-commit CI requirement.
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
      process-wide request-rate limits. `serve-fake`, its backend, and its
      settlement route are absent from default artifacts and require the
      explicit `test-only-fake-lightning` debug/test feature; build-script and
      source guards reject that feature in release profiles, even with forced
      debug assertions. `serve-cln` reaches only the checked guard Unix socket
      in the prepared production topology; no application flag bypasses it.
      Neither substitutes for a separately operated production TLS/abuse edge.
- [x] The shared strict HTTPS client gives DNS plus all candidate addresses one
      bounded connect deadline and gives TLS handshake plus the full request and
      response one I/O deadline. Resolver workers and returned addresses are
      capped, multi-address attempts share the remaining budget, HTTP 200 is the
      only success status, and a timeout after any application request byte
      remains outcome-unknown.
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
      The v4 migration additionally deletes only V3 in-flight BOLT11 recovery
      rows, because they did not authenticate issuer ID, network, or expected
      payee; capabilities plus policy/quote anti-rollback checkpoints remain.
      Contextless V3 capabilities acquired through BOLT11 remain physically
      encrypted but strict current/retained paths deliberately cannot spend
      them; they are stranded rather than unsafely rebound. Contextless
      capabilities from non-BOLT acquisition remain usable. Production must
      not activate V4 over funded V3 BOLT11 inventory without an explicit
      migration/refund decision; the first pre-production activation has no
      such user inventory.
- [x] DPF and Harmony native/WASM/Web adapters expose a true staged provider
      lifecycle. The browser connects, attests, upgrades, pins, installs the
      database proof and may load role 0's signed policy before it enables role
      1 selection; neither transport receives the peer choice, peer key or a
      pair identifier. Before role 1 is dialled, browser-local validation
      requires two non-zero, distinct operator pins. The complete pair then has
      to pass the same pin gate again plus distinct-identity,
      compatible-catalog and exact-root gates. A one-shot Merkle tree-top
      preflight runs for the selected `db_id` **before** either capability is
      acquired or authorized, and only then makes capability paths and that
      database's PIR query method reachable. Failure spends neither role and
      cannot revive readiness or retry within the attempt. Per-leg
      generation/client/URL/config owners prevent late connect, catalog, proof,
      announce or preflight completions from publishing stale readiness after
      disconnect/replacement. The deprecated shared-pin field never counts as
      two independent anchors.
- [x] The DPF browser freezes the selected `db_id` after role 0 bootstrap and
      reuses that exact value for role 1 policy admission, the real query and
      its Merkle verification; later selector changes cannot move a paid grant
      onto a different database.
- [x] Harmony hint and query roles use separate workload scopes and independent
      prices. A hint provider may expose its signed policy before a query
      provider is selected, but filling or restoring the exact
      dataset/PRP-bound browser cache waits for the pair's pre-authorization
      tree-top gate. A
      hint transport close invalidates its session-bound V2Full grant; cached
      hint bytes may remain, while query execution remains blocked until an
      independently admitted query role and the pre-authorization pair gate
      complete.

### Directory and operator tooling

- [x] The fixed same-host directory-publisher network now has a source-closed
      activation ceremony in addition to its inert render profile. A canonical
      plan binds exact installed files, external sentinels, firewall evidence,
      Caddy/publisher preimages, boot identity and regular Node/systemctl/ip
      executables, plus the executor's exact two-module local import closure. A
      fresh at-most-one-hour approval can start only the netns
      unit; a different receipt-bound approval can stop only that unit. Runtime
      verification closes nsfs, veth txid aliases/MACs/cross-indices, loopback,
      the reviewed down/addressless kernel fallback subset, connected routes
      and zero forwarding. Descriptor-pinned command execution and owner-only
      pending/final receipt recovery pass real Linux tests; the native helper's
      crash/monitor/cleanup harness passes in a disposable arm64 Linux
      container. The ceremony never changes Caddy/firewall/sentinels, starts
      the publisher or handles a private key. This is source/test closure, not
      target installation or activation. The publication-interval firewall
      generation guard, exact target pins, remote mutation/start approvals,
      Caddy overlay receipt and new-boot runtime evidence remain mandatory.
- [x] Canonical NIP-01 event verification, provider assertion, 16-shard catalog
      checkpoints, tombstones, strict-mode relay split-view checks and rollback
      state. The separate centralized-single-relay API requires an explicit
      exact-one-relay opt-in and marks the result degraded without persisting its
      mode or a relay URL in rollback state. Selectable output carries the
      conservative minimum checkpoint/all-entry expiry, including tombstones;
      the Web path reconstructs exact immutable typed output, uses one
      nondecreasing wall-clock plus page-elapsed time floor, and rechecks freshness before admission,
      payment, token, authorization, and query transitions. Expiry clears
      active trust without manual fallback. Mode, ordered origin-only relay
      origins, publisher key and bootstrap revision form an immutable refresh
      intent, so stale relay/CAS completion cannot activate.
- [x] A repository-owned directory-only Nostr relay now implements the exact
      bounded `EVENT`/`REQ`/`CLOSE` subset for one pinned kind-30078 publisher.
      It binds loopback, stores an immutable canonical-event archive plus
      addressable heads in owner-only SQLite WAL/FULL state, makes duplicate
      publish acknowledgement idempotent, freezes paged snapshots, bounds
      connections/operations/work/egress/archive/time and exposes no publisher
      private key, generic subscription language, live push, NIP-42 or event
      logging. Its current macOS library and binary unit suites passed 23/23;
      Linux clippy, installed shutdown/backup drills and public WSS behavior
      remain exact-commit/deployment evidence rather than source claims.
- [x] A CI-wired, explicitly selected process test starts two copies of the
      repository's production `bitcoinpir-directory-relay` binary with
      independent config/SQLite/runtime state and four distinct loopback
      listeners. Every accepted signed `EVENT` uses a publisher lane; every
      accepted ID/catalog `REQ` and returned `EVENT`/`EOSE` uses a public lane.
      Deliberate wrong-lane probes must close, and an exact-ID public readback
      proves the rejected EVENT sentinel was not persisted. It fails closed on
      offline/exact split-view errors, recovers lost ACK by a public-lane durable
      ID probe plus publisher-lane idempotent retry, and verifies both listeners
      plus stored heads across independent restarts. A
      companion three-authority test separates provider
      0, provider 1 and issuer DB/key/namespace/TLS material. It starts authority
      and TLS-edge child test harnesses; each authority harness invokes
      production `rollback_authority::run`, while the parent directly calls the
      production ProviderStore/IssuerStore adapters. Deployment-set validation,
      raw-client rejection and Store-adapter rejection are asserted at their
      respective boundaries. Provider- and issuer-authority backends are stopped
      independently while their TLS edges remain online; only the affected Store
      fails closed, while the other two Stores remain independently openable and
      authenticated through their own authorities. The issuer recovers the exact
      same generation and commitment from its original authority database. It
      does not launch `unified_server`, `payment-issuer`, or
      installed binaries. These are local topology tests, not claims of
      operational independence; their first Linux CI execution remains
      candidate-commit evidence.
- [x] Browser relay fetching and encrypted IndexedDB directory state.
- [x] A no-account, process-local NIP-01 fake-relay integration test closes the
      signed publisher-artifact to two-relay read path through all 16 shards,
      production WASM verification and durable rollback acceptance. It covers
      independent-provider/key separation plus tamper, wrong-key, expiry and
      rollback rejection; it is not evidence of public-relay interoperability.
- [x] Offline `bpir-admin service-keygen`, `service-policy`, directory assertion,
      entry and checkpoint builders, plus an explicit native
      `directory-artifact publish` transport. Publishing accepts no signing key,
      requires a pinned directory public key, and defaults to two through eight
      credential-free public `wss://` relay hostnames. Exactly one relay requires
      `--centralized-single-relay`; its receipts are explicitly
      `centralized=true degraded=true`, while zero relays and mismatched
      flag/count combinations fail before network I/O. Publishing requires exact
      per-event positive OK and bounded per-relay time/bytes. It attempts every
      relay and fails the command on any partial result; exact immutable artifacts
      can be rerun manually.
- [x] The staging-only Nostr readback tool accepts no key or publish operation,
      mirrors the Rust canonical public-`wss://` grammar on the raw input, and
      requires the Rust publisher's domain-separated event-set digest, valid
      recomputed NIP-01 event IDs, exact frozen event values and EOSE. Artifact inputs share one
      5 MiB budget and are opened without following the final symlink or
      blocking on a raced FIFO/device; pre/post `fstat` checks reject mutation.
      Node black-box tests cover URL aliases, symlink, FIFO, device, oversized
      and aggregate-oversized inputs and run in the payment CI browser job.
- [x] Owner-only `bpir-admin cashu-custody` tooling generates a provider-bound
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
      wasm32 compilation and three local Chromium boundaries: multi-tab vault
      fault injection, generated-WASM/real-loopback-issuer acquisition and
      browser/two-issuer/two-provider local DPF query plus Merkle verification. Its
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
      unit tests and all three local Chromium Payment boundaries
      before publishing. Main-branch pushes build/test and upload only; the
      production deploy job requires a separate manual dispatch selected on
      `main` with `confirm_production_deploy=true`. That run rebuilds/retests
      the selected main ref rather than promoting an earlier push artifact.
      A lockfile-pinned YAML 1.2 semantic regression guard runs after `npm ci`
      and enforces that exact condition, the boolean-default-false input,
      `needs: build`, absence of `always()`, the protected `github-pages`
      environment, and exactly one Pages-write, OIDC-write, configure and deploy
      action, all confined to that job. Its strict schema rejects
      anchors/aliases/merge keys, `write-all`, Actions-write permissions,
      reusable-workflow delegation, extra jobs and sibling workflows outside
      the exact contents-read permission boundary; every workflow change
      triggers Payment CI. The Pages build runs the same guard. Its fail-closed
      truth table and Unicode-escape controls run there. This static/default-
      `GITHUB_TOKEN` guard cannot exclude dispatch by an external PAT or GitHub
      App token; credential governance and mutable repository/environment
      policy remain deployment gates. No deployment was triggered or
      authorized here.
- [x] A repository-wide workflow supply-chain gate parses every workflow with
      the locked YAML parser, rejects anchors/aliases/merge keys, permits only
      reviewed action-name/40-hex-commit pairs, and requires every checkout to
      use the YAML boolean `persist-credentials: false`. It rejects the
      higher-priority `web/npm-shrinkwrap.json` before installing or importing
      the parser, leaving `web/package-lock.json` as the only npm parser lock.
      The SDK, generated-proof, audit and build-determinism workflows now use
      those exact pins. The lightweight pir-core determinism job no longer
      restores a Cargo/target cache, uses `--locked --offline` for every Cargo
      command, and is retriggered by its root manifest, lockfile, toolchain,
      Cargo configuration and vendored-source inputs. Updating an action still
      requires a reviewed allowlist change in the same checked revision. Its PR
      trigger is intentionally path-unfiltered and it handles merge groups, so
      a future required check reports for every protected-main PR and merge-
      queue candidate instead of remaining Pending.
      A read-only 2026-07-29 recheck still found no classic branch protection or
      repository ruleset on `main`; that is an external governance blocker, not
      something this source change can close. Until a required-check/no-direct-
      push rule is installed, this in-repository gate can be rewritten or
      deleted and a push failure is only post-merge detection. It also does not
      replace GitHub token/PAT/App governance.

## What the tests currently prove

- [x] A canonical encrypted authorization frame for each of the five v1
      methods reaches each of DPF, Harmony full hint, Harmony query, Onion and
      TEE-ORAM gate state, with replay terminal after the spend boundary.
- [x] Direct receipt and BAT production ProviderStore adapters persist/reject
      replay across restart; Free, Cashu and experimental ARC have focused
      persistence and concurrency suites.
- [x] A dedicated two-provider OnionPIR process test performs real chunked key
      registration and decrypts production INDEX, CHUNK and both Merkle-sibling
      worker responses. It proves wrong-provider and structural wrong-scope
      failures are non-consuming, post-spend DFA failures are terminal, and
      receipt replay remains rejected after ProviderStore/process restart.
- [x] The GitHub-closeout run exposed a conservative same-database
      rollback-floor acknowledgement race: a later writer could anchor a
      successor before an earlier caller received its CAS result, consuming
      quota while returning an error but never over-granting. Post-commit
      confirmation now reconciles only through the same SQLite connection;
      deterministic same-lineage and cloned-fork tests, 500 repeated Free
      contention runs and the then-current 79-test store suite passed. That
      count is historical. The 2026-07-28 focused P0 closeout passes the current
      93/93 `pir-service-store` tests, including exact cloned-state one-winner
      fencing for generic, Free-IP and final Standard-Cashu grants, and 6/6
      shared-grant provider-clearing tests. Those six cover
      Free/BAT/experimental-ARC exact replay, eight-way concurrent replay, an
      explicit identical-proof outcome-unknown recovery, invalid response/no
      local claim, wrong-provider rejection before transport, and the real
      issuer-service ExactReplay-to-provider-local-claim boundary. They also use
      binding `amount = 1` with clearing `accepted_value = 10` to prove the
      fields are independent. The focused results were subsequently included
      in the passing final pinned-Linux package matrix; pushed CI remains a
      separate per-commit merge gate.
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
      These statements describe the pre-settlement-v2 focused evidence. The
      current payout-store/worker tree is included in the final passing 27-
      package aggregate and warnings-denied Payment clippy run; pushed GitHub
      CI remains authoritative before merge.
- [x] Two no-funds loopback tests launch independent `unified_server` provider
      processes with distinct method keys and durable stores, then exercise
      real WebSocket, ephemeral-bound secure-channel, exact signed
      manifest-root policy, DPF execution, resource-limit rejection and
      restart persistence. Together they cover direct receipt, Free open/IP
      quota, provider-local Cashu BAT and experimental ARC, including
      cross-provider rejection without a shared spent set. They intentionally
      use `NoSevHost` and `dangerous_unpaired_*`, so they are not production
      identity, binary-pin or hardware-attestation evidence.
- [x] A separate `cuckoo-oram` process E2E builds tiny direct INDEX/CHUNK
      Circuit ORAM images, authenticated sidecars and controller state in an
      independent trusted-state directory, then launches the real
      ORAM-enabled `unified_server`. It proves cleartext and pre-authorization
      fail-closed behavior, provider/backend/workload scope binding, one-shot
      accounting, exact direct-ORAM result bytes, durable receipt replay
      rejection and authenticated ORAM reopen with a fresh receipt after
      process restart. The pinned Linux run passed 1/1 and warnings-denied
      clippy. Its deterministic data, local SQLite floor, `NoSevHost` and
      unpaired SDK primitives are test boundaries, not production TEE or
      trust-chain evidence.
- [x] A non-default Standard Cashu process E2E is implemented and wired into
      Payment CI. It launches a deterministic TLS NUT-03 mint plus two real,
      independently configured `unified_server` processes: one signed policy
      selects Standard Cashu and the other independently selects
      Free/OpenBestEffort. The client completes both bound secure channels,
      verifies both policies, performs proof-bound tree-top preflight, executes
      a two-server DPF query and verifies its Merkle absence result. Restart
      rejects the same Cashu bearer without another mint swap; fresh providers
      fail closed for wrong CA, wrong signed leaf-SPKI pin and offline mint.
      The extra CA is available only through a non-default test feature and
      owner-only test file, while ordinary WebPKI plus the signed endpoint/pin
      tuple remain mandatory. Default builds reject its CLI flag; release
      profiles reject the feature at build-script and source-cfg boundaries,
      including when debug assertions are forced on. The final coordinated
      current-tree Linux matrix passed this exact process cell 1/1 plus its
      warnings-denied clippy and default-CLI/release-feature guards. Pushed CI
      remains required before merge.
      It remains `NoSevHost` deterministic local evidence, not production
      identity, proof-chain, independent rollback-floor or external
      public-WebPKI mint evidence.
- [x] A separate non-default shared-issuer process E2E is implemented and wired
      into Payment CI. It builds a real test-only-fake-Lightning
      `payment-issuer`, places a private WebPKI TLS edge with a signed leaf-SPKI
      pin in front of its redeem-only route, and launches a real paid
      `unified_server` plus an independently selected Free/Open peer. A BAT
      redemption reaches a complete canonical issuer success, after which the
      test edge drops one response. The provider fails closed without a local
      delivery claim; restarting issuer and provider against their original
      stores/floors and replaying the identical proof reproduces the same
      canonical-body, request and idempotency-key digests, credits ledger
      sequence one exactly once and creates exactly one local claim. A later
      replay cannot create a second grant. The fixed-size digest transcript is
      test-local and retains no raw envelope, credential, idempotency key, HTTP
      metadata, peer address or timing. Wrong CA, wrong signed pin and offline
      issuer all fail closed before issuer application handling and create
      neither a local claim nor a provider account. The test also checks that
      payout rows remain zero and server logs contain no invoice, payment hash,
      preimage or raw BAT secret. The fake-Lightning issuer binary is supplied
      only by an absolute, non-symlink path and the shared test feature inherits
      the release-rejected WebPKI hook. This branch's first executable proof is
      intentionally pending the Linux Payment CI run; implementation and static
      formatting alone are not recorded as a pass.
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
      Its browser setup explicitly enables `test-only-fake-lightning`; normal
      and CLN-regtest issuer builds omit the feature.
- [x] A third no-funds Chromium harness is wired into the local full check and
      Payment CI. It launches two independent fake issuers and two independent
      loopback providers, establishes both secure channels, checks every pinned
      synthetic catalog/database-proof field, installs that proof, fetches two
      signed policies and exposes two exact local selections. The first acquires
      independent direct-receipt and BAT capabilities. The second sends signed
      Free/IP-rate-limited with a signed quota of 1, a 3600-second window and
      the IP-rate-bucket leakage disclosure, without invoice/issuer I/O, and
      acquires an explicitly experimental ARC credential through generated
      WASM and a real local issuer. Direct-peer-IP trust is enabled only for
      loopback provider 0. Both ARC processes require the opt-in flag and use a
      dedicated fixture key. Each success selection exercises both real
      provider/store gates, binds generated arity-8 tree tops to the installed
      proof root, runs one real encrypted two-server DPF query and requires an
      explicit inclusion/absence verdict. It then requires the same provider's
      second Free connection to receive durable `server-busy`, verifies that
      provider 1 can still consume another ARC presentation, and replays that
      exact ARC presentation for durable rejection.
      `NoSevHost`, the synthetic report and the all-zero database remain a
      deliberate test boundary, not AMD attestation or production-data
      evidence. A final isolated-target current-tree rerun passed all three
      complete-query cases, including Free/experimental-ARC. The companion
      generated-WASM/real-loopback-issuer case passed 1/1 while its two explicit
      CLN cases remained skipped by default. Pushed CI remains a separate
      exact-commit gate; this is not deployed-origin acceptance.
- [x] Offline CI runs a deterministic, bounded malformed-length/adversarial
      corpus across all public Payment V1 canonical decoders, known provider
      admission opcodes and the strict issuer/mint HTTP response boundary. The
      gate requires no network-installed fuzz tooling and retains explicit
      case-count/input-size bounds.
- [x] An opt-in disposable CDK 0.17.3 fake-wallet runner starts only a random
      loopback HTTP mint and creates two independent 8-sat padded V4 `cashuB`
      notes. Current generated JS/WASM imports the first note in Chromium,
      rejects its untouched HTTP identity, retires the accepted capability from
      the encrypted vault, and emits owner-only canonical provider wire bytes.
      A feature-gated private-CA TLS proxy exposes only the signed
      `https://localhost:<port>` identity and fixed leaf-SPKI pin to a real
      Standard Cashu `unified_server`; an independently configured Free server
      completes the pair. The joined process test establishes both secure
      channels, verifies exact manifest-root policies, runs proof-bound
      preflight, DPF and Merkle absence verification, restarts both providers,
      and rejects replay from provider-local durable state while the CDK proxy
      request count remains one. The second note separately covers native
      NUT-02/NUT-03/NUT-12 plus four NUT-07 custody observations, including
      first custody `UNSPENT -> SPENT` and independent successor custody
      `UNSPENT`, without placing a bearer in process argv. The 2026-07-29 Linux
      run passed the Chromium, joined provider, native-WASM and native-custody
      cells 1/1 each. CDK stdout/file logs contained no bearer, payment hash,
      preimage or BOLT invoice value. The runner uses no Lightning node or real
      funds; production WebPKI HTTPS is unchanged and release compilation with
      the test root is forbidden. External public-mint interoperability,
      independent production rollback authority and admin retirement remain
      staging gaps.
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
browser/issuer/two-provider complete-query end-to-end run.

A historical 2026-07-27 closeout before the later settlement-v2 payout store,
payout worker, Signet backup ceremony, browser two-provider harness and extended
CDK custody-lifecycle case completed the then-current full local command. Its
exact historical counts remain in `LOCAL_ACCEPTANCE.md`; they are **not** a
current-tree result and must not be copied into release evidence. The final
current-tree pinned-Linux Rust/process matrix, extended CDK case and isolated-
target Web/browser closeout have since passed. They are recorded separately in
`LOCAL_ACCEPTANCE.md` so repeated focused stages are not folded into a false
unique aggregate count. Exact-head pushed CI remains a separate merge gate.

## Implemented but not production-activated

- [x] The core-pattern ceremony v2 binds all three Noble Apport sysctls,
      official handler and unit bytes/metadata/semantics and the exact
      enablement symlink. It separates stable configuration from accepted
      settled active/exited or inactive/dead observation; rejects matching
      sysctl globs/negative exclusions, quoted/escaped foreign action
      dependencies, load-path overrides, reverse Wants and implicit socket/path
      triggers, multi-level aliases and direct handler `Exec*`; and never
      executes stock Apport start/stop. Runtime checks use complete
      Unit/Service `GetAll` values fenced by stable unit/job lists and static
      configuration. The exact Noble systemd-sysctl unit/binary and vendor boot
      symlink are pinned; candidate retains a drop-in that clears every
      systemd credential source so `sysctl.extra` cannot override the safe
      policy on reboot. Before publishing pending it durably
      publishes an approval-bound lease, then arms an early three-sysctl guard
      plus Apport and systemd-sysctl preflight gates. Apply converges to an
      exact manager-loaded mask; recovery binds the actual `/proc` boot, newest
      exact lease/preflight/pending subject, and ordered approval-digest chain;
      terminal cleanup removes only the exact preflight/guards/pending/lease/lock
      generation. Receipt candidates receive a final full terminal-state check,
      and cleanup is revalidated before lease release. Fixed symlink and
      regular-file quarantines, including coexistence, plus empty exact lock
      directories replay every namespace/fsync boundary; symlink replay uses
      no-clobber hard links. The lock launcher is
      closed to exact mutation argv and a five-variable exec environment. Pure
      SIGTERM/SIGKILL/SIGABRT restart tests pass, including preflight-safe reboot
      and terminal rollback restoration. The
      invalid shared-kernel privileged-container matrix is retired; the
      independent-kernel VM gate is static-only and the VM matrix is unrun.
      This is source/test evidence only; no production approval or host action
      has occurred. See `CORE_PATTERN_CEREMONY.md`.

- [x] `bpir-admin lightning-staging bootstrap-preflight`, `preflight`, and
      `preflight-supervisor` implement read-only, fail-closed default-Signet
      gates for one local
      payer/router/issuer role. Bootstrap is receipt-independent, queries no
      gossip and accepts only zero peer channels, zero `listfunds`
      outputs/channels plus empty `staticbackup`; it is the no-funds
      identity/runtime gate before any faucet or channel mutation. The
      pre-start layout gate requires the restored native 32-byte `hsm_secret`
      with exact owner and mode `0400`, so an absent secret cannot generate a
      replacement identity. Full preflight remains the post-channel activation
      gate. The production supervisor no longer latches one successful pass:
      before and after every renewal it validates the root-owned systemd
      InvocationID mapping for the exact CLN unit, binds its first generation,
      writes a private 180-second volatile lease after the initial pass and
      after each 20-second sleep,
      and sends
      `READY`/watchdog notifications only after a complete successful renewal
      covered by one cooperative 55-second async deadline; blocking filesystem
      calls are bounded by exact `TimeoutStartSec=120` before the first
      `READY`, then by the 90-second systemd watchdog. Every renewal
      revalidates the exact
      root-owned, content-pinned `/usr/bin/busctl` and requires the systemd
      manager's typed `ServiceWatchdogs=true`. The unit is
      `Type=notify`, `WatchdogSec=90`, `Restart=no`; both the RPC guard and
      issuer bind to it, so any renewal failure, hang or CLN generation change
      stops downstream payment access. Their 30-second stop bounds leave about
      60 seconds of margin before the lease expires. Preflight and guard each
      consume a distinct one-shot token from a root:root mode-`0700` runtime
      directory before dropping privileges, so restarting CLN cannot silently
      create a fresh downstream generation.
      Live runtime evidence reads typed systemd D-Bus dependency arrays and
      `TimeoutStopUSec`, `ExecStartEx`, `ExecStartPreEx`, `WatchdogUSec`, and
      `WatchdogTimestampMonotonic`, plus two typed manager
      `ServiceWatchdogs` passes. Each watchdog pass binds the immediately
      following boot uptime, requires a fresh timestamp, and rejects rollback;
      standalone D-Bus `t` values are stored as lossless canonical decimal
      strings, including exact uint64 max for an inactive unit's infinity
      sentinel. Scalar/typed pairs are lifecycle-closed: stopped is
      `infinity`/uint64-max, ordinary live is `0`/`0`, and live preflight is
      `1min 30s`/`90000000`;
      every rendered relationship must be loaded by the manager and the
      snapshots repeat at final sealing. Stale pre-`daemon-reload` manager
      state fails closed.
      It pins Core/CLN/CLI/plugin binaries below explicit protected parents,
      authenticates an explicit loopback Core RPC endpoint with an owner-only
      pinned cookie, checks the exact default challenge/genesis, verifies CLN
      role/channel/gossip topology and directional minimum-liquidity estimates,
      and binds a fresh backup receipt to the current SCB digest. The static
      preflight TOML contract is root:dedicated-preflight-group mode `0440`
      below a root-owned non-writable parent; every path ancestor is a
      root-owned non-writable `O_NOFOLLOW`-opened directory. The command pins
      both the actual non-root reader EUID and the exact effective plus
      supplementary group set (config, cookie and CLN groups only). The
      receipt is ceremony-created preflight-owned mode `0600` state below the
      unit's mode-`0700` `StateDirectory`; V1 pins the exact
      `/var/lib/bitcoinpir-lightning-preflight/backup-receipt.toml` path and
      binds its configured owner/group to the trusted reader UID/config GID.
      It is never a rendered `/etc` payload or static hash-manifest input.
      Atomic receipt writes explicitly unlock the pinned output-parent
      descriptor on every ordinary success/error path; the primary operation
      error wins, while a successful write followed by parent `fsync` or unlock
      failure is explicitly outcome-unknown and fails closed. Both command
      runners are mock-tested against separate fixed
      read-only RPC allowlists.
      The rendered v26.06.6 bundle gate now requires the exact selected
      38-file deployment-file set: `lightning-cli`, `lightning-hsmtool`, all
      eight mandatory CLN subdaemons, `lightningd`, and all 27 built-in plugin
      bytes at the
      official `libexec` path. Only `bcli` and `chanbackup` remain executable;
      the other 25 are exact root-owned `0444` payloads and exact-disabled by
      basename. A root:root `0555` tmpfiles/runtime-evidence placeholder makes
      the actual `/srv/lightning/plugins` default scan path a required,
      non-ignore-missing namespace mask. The pre-start layout verifier does not
      misclassify that already-masked path as absent; it separately rejects the
      non-default network-local lookalike. The
      live preflight requires exactly two active, non-dynamic plugins. This
      replaces the crashing v26.06.6 `clear-plugins` path and closes the
      previously misidentified `/srv/lightning/plugins` scan surface. A
      separate one-entry manifest binds exactly one
      private `libpq.so.5` below a digest-equals-file root. A source skeleton
      can no longer omit a member of the selected deployment-file set. The CLN
      unit exposes only that independent root through `LD_LIBRARY_PATH`, and
      source, rendered and offline-manifest gates reject a second library,
      `LD_PRELOAD` or an alternate loader path. This preserves
      `CLN_BUNDLE_SHA256` as the upstream release-archive identity, but it does
      not prove the live mapped object or a complete ELF closure. The private
      libpq retains host-ABI dependencies on libssl, libcrypto, GSSAPI, LDAP and
      libc. Production CLN activation remains blocked until maps-plus-inode
      runtime evidence is implemented and that host ABI trust is approved. The
      core unit intentionally omits `CLN-LOADER-MAPS-APPROVED` so a no-funds
      generation can produce that evidence; preflight, guard and issuer require
      it. The sentinel must remain absent until the separately reviewed schema
      PR and evidence approval exist. These paths have not yet been run on the
      final persistent Signet hosts and do not replace actual liquidity,
      payment, restore or
      peer/bootstrap acceptance. The receipt is an operator assertion:
      `staticbackup`/SCB material supports channel recovery but is not a live or
      dynamic `lightningd.sqlite3` backup, and the command neither copies nor
      proves restoration of node identity, SCB or database state.
- [ ] The `payment-issuer serve-cln` executable path is implemented and has
      crossed the current disposable three-node local-regtest boundary below,
      but has not been connected to a persistent, external or public-network node.
      It deliberately binds loopback and, in the prepared production topology,
      expects the guard-UID/issuer-GID method-scoped Unix socket. A separate
      dedicated preflight supervisor UID checks the native cross-UID CLN socket and Bitcoin
      cookie after the CLN daemon itself runs the recursive layout verifier.
      Production TLS ingress, source-aware abuse controls, Linux installed-
      artifact/runtime evidence, process supervision and operational key
      custody remain deployment work.
- [x] Issuer startup authenticates the current quote delegation and validates
      the configured Lightning backend before opening or mutating the issuer
      store. A wrong CLN socket, payee identity or network therefore cannot
      advance retained-policy or key-lineage state during a failed start.
- [x] `bitcoinpir-cln-rpc-guard` implements the production method-scoped Unix
      boundary between the issuer and Core Lightning. It validates kernel peer
      credentials plus parent/socket identity, mode, single-link and Linux ACL
      state; reconstructs only bounded `getinfo`, private-label `listinvoices`
      and anonymous `invoice` RPCs; enforces absolute deadlines, inflight and
      per-generation invoice limits; and never forwards raw CLN errors or logs
      invoice, hash or preimage material. Its production unit deliberately uses
      `Restart=no` so a crash cannot silently reset the custody deadman. The
      source and deterministic tests are present, but Linux CI and a target-host
      cross-UID access drill remain required before activation.
- [x] The current opt-in local-regtest runner wires the production CLN adapter
      to three disposable Core Lightning nodes and two 1,000,000-sat announced
      localhost channels. There is no payer-to-issuer channel: payer gossip must
      learn the active public router-to-issuer direction before its 1-sat
      direct, 4-sat BAT, and 4-sat experimental-ARC invoices can use the forced
      two-hop route. The final 2026-07-28 current-tree opt-in run exited 0 after
      rebuilding WASM offline: its acquisition/recovery phase passed 3/3 and
      its joined two-provider query phase passed 1/1. The marker-owned
      `bitcoind`, three `lightningd` processes and private runtime directory were
      absent after cleanup. It never reaches a public Lightning network or uses
      real funds; either still needs explicit approval.
- [x] A prior disposable loopback CDK 0.17.3 fake-wallet run exercised padded V4
      import, provider-side NUT-03 swap/NUT-12 verification, custody commit and
      one-shot NUT-07 verification that the original NUT-03 inputs are `SPENT`
      and the fresh provider-custody outputs are `UNSPENT`. CDK 0.17.3 exposes
      custody receive only through bearer-token argv, so that run intentionally
      did not prove custody `UNSPENT -> SPENT` or execute admin retirement
      against CDK. The current Rust case now performs a second direct NUT-03
      spend from authenticated custody memory and checks first-custody
      `UNSPENT -> SPENT` plus successor `UNSPENT`. The final 2026-07-28
      current-tree default-mode run passed all three script stages and cleaned
      its child/runtime artifacts. No public/WebPKI Cashu mint has been
      contacted, and production availability, fee behavior and recovery have
      not been canary-tested.
- [x] Native Nostr publisher transport is implemented and covered through
      transport-neutral local WebSocket sessions, including positive, reject,
      duplicate/unexpected/missing, non-text, oversized, timeout and partial
      failure behavior. Its `--validate-only` preflight applies the exact
      artifact/key/time/relay checks without invoking transport. Distinct
      hostnames do not prove independent operators. Strict mode remains the
      two-to-eight default; centralized mode is an explicit exact-one flag and
      every outcome labels its degraded assurance. Publisher, readback and Web
      adapters now share the exact credential-free WSS-origin/no-path grammar.
- [x] `bitcoinpir-directory-relay` implements the intentionally narrow
      directory-only Nostr surface: canonical signed EVENT validation for one
      pinned publisher/kind, bounded ID-filtered REQ/EOSE readback, immutable
      SQLite event archive plus current heads, durable duplicate handling,
      bounded connection/work/egress/archive/time dimensions and graceful
      drain. It is not a general-purpose relay. The production selection is
      resolved for exact source/archive/lockfile/build-manifest/binary/config/
      public-key hashes and explicit degraded `centralized-single-relay` mode.
      The unit is content-addressed and hash-preflighted but remains inert until
      all three explicit startup sentinels exist; stopped and fresh-live host
      evidence, source-fair ingress and publication approvals remain gates. An
      independent second operator is stronger than the approved centralized
      profile but is not falsely inferred from same-host origin diversity.
- [x] Source-template, rendered-profile and live-Linux evidence tools are
      checked in. The source gate freezes inactive templates and the unchanged
      VPSBG baseline. The rendered gate binds one externally approved plan to
      exact staged bytes, path/file classes and consuming service identities;
      the Caddy gate closes exact bind/upstream sets and rejects imports,
      invokes, snippets, named routes and non-v2 transports, while the pinned
      adapted-JSON/socket test proves wrong-bind requests return 4xx without
      touching any backend;
      the live collector binds installed bytes, systemd state and real process
      credentials to one machine/boot/invocation. Runtime-evidence v8 binds
      render-plan/manifest schema v2, request and host to exact
      `systemd 255 (255.4-1ubuntu8.15)` and accepts
      only the closed files-authoritative NSS sequences `files` and
      `files systemd` (the latter only as the same second-position fallback for
      both passwd and group), binds `/etc/nsswitch.conf`, `/etc/passwd` and
      `/etc/group`, and rejects UID/GID aliases or extra protected-group
      primary/explicit/effective members. All manifest-bound service IDs and
      Caddy denial-inventory IDs are restricted to static `1..60000`, outside
      systemd's recycled `DynamicUser` range and `nobody`; the checked-in
      examples now reserve `52901..52952`. A final complete getent/id enumeration,
      not merely another policy-file stat, closes identity drift during the
      remainder of live collection. Two bounded
      all-process/all-thread passes additionally reject stale protected UID/GID
      holders outside the exact current unit cgroups, record every active
      capability set plus `CapBnd`, reject reviewed dangerous non-root
      capabilities, require Caddy-only `CAP_NET_BIND_SERVICE` and zero HAProxy
      capabilities, and re-confirm every
      MainPID/unit generation; runtime paths are rechecked after the scan. This
      version reads systemd's structured `Conditions` property through a pinned
      `/usr/bin/busctl` rather than accepting systemd 255's
      `Conditions=[unprintable]`, and proves the exact evaluated condition set
      plus current path truth before and after collection. It separately reads
      `ImportCredential`, `LoadCredential`, `LoadCredentialEncrypted`,
      `SetCredential` and `SetCredentialEncrypted` from the Service interface
      and requires the exact empty `as`, `a(ss)`, `a(ss)`, `a(say)` and
      `a(say)` arrays. All five are request-bound and repeated in live,
      stopped-edge and stopped-relay final sealing; systemd 255's
      `[unprintable]` text is never treated as empty. The same typed Service
      passes now bind `ExecStartEx` and `ExecStartPreEx` with exact
      `a(sasasttttuii)` path/argv/flags; only the guard/preflight token-unlink
      precommands are privileged. Scalar command records are strict
      systemd-255 redundancy with one-newline delimiters and coherent
      running/completed/stopped metadata. The raw busctl parser preserves all
      standalone `t` integers as decimal strings before JSON number rounding
      can occur and rejects old numeric evidence, malformed syntax and
      text/typed watchdog lifecycle mismatches.
      The release closure is the collector, rendered gate and
      deployment-template gate from one frozen commit; tests exact-match all
      local and `node:` specifiers and reject alternate dynamic, CommonJS and
      worker loaders. Installed-file
      content, independent SHA-256, stat, ACL, xattr and capability probes now
      use one open descriptor, while initial and final `O_NOFOLLOW` path
      descriptors must retain the same device/inode. Every secret's final parent
      must also be consumer-EUID-owned mode `0700`, with each ancestor matching
      the Linux `pir-private-files` DAC ownership/write/root-sticky policy;
      readability alone is insufficient. The runtime collector separately
      rejects named/default POSIX ACLs, xattrs and capabilities on every pinned
      directory descriptor, which is deliberately stricter than the loader and
      is not a claim that the loader audits Linux POSIX/NFSv4/FUSE ACLs. The
      complete directory set and every secret file are revalidated after all
      long external probes; only then does the final lightweight typed-
      credential/Conditions/unit-generation pass run immediately before
      evidence construction. This
      is not an already-connected-FD proof. The stopped-edge evidence type
      therefore requires inactive/dead units, absent socket paths, locked
      non-login service accounts and an empty protected-credential closure
      before HAProxy may start, followed by Caddy and a fresh live proof in the
      host initial PID namespace. The earlier pinned Ubuntu 24.04,
      HAProxy 2.8.16 and Caddy 2.11.3 container run passed the complete
      deployment/rendered/live/source-fair/Nostr Node gate, including real
      `getent`, per-user `id -G`, full procfs thread scans and the
      descriptor-bound installed-file and secret-directory ABA tests. Record a
      fresh aggregate count from the final branch before activation rather than
      reusing an older pre-race-test total. Caddy 2.11.3 is now historical
      compatibility evidence only, not production evidence: current edge CI
      resolves and pins Caddy 2.11.4 and its exact amd64 binary. A current-tree
      pinned Ubuntu 24.04 / HAProxy 2.8.16 / Caddy 2.11.4 targeted run passed
      all 15 source-fair template and real-process tests with no skip; the
      larger final aggregate and exact-head CI remain separate merge gates.
      An Alpine procfs regression also passes for legal repeated `Groups:`
      entries. The first root-only target Linux collection still
      remains candidate-commit/host evidence and cannot be inferred from those
      deterministic tests.
- [x] The directory relay unit, source gate, rendered request, stopped
      preparation evidence and fresh-live evidence bind
      `ProtectProc=invisible` and `ProcSubset=pid`. This narrows a compromised
      relay's `/proc` view of co-located processes and network metadata; it does
      not replace host separation or the PIR non-collusion assumption.
- [x] A local, undeployed `bhtm-caddy-admin-uds-v1` maintenance gate now
      derives the complete candidate Caddyfile and `bhtm-caddy.service` unit
      only from exact preimages. It moves the global admin listener to
      `unix//run/bitcoinpir-caddy-admin/admin.sock|0200`, requires root:root
      `RuntimeDirectory` mode `0700`, `UMask=0077`, `LimitCORE=0`,
      `MemorySwapMax=0`, `StandardOutput=null`, `StandardError=null`, no
      drop-ins or effective `CADDY_ADMIN`, no `--environ`, Caddy imports or environment-backed
      substitutions, and an explicit UDS reload address. It pins the exact
      production Caddy v2.11.4 preimage at the host's exact
      `/usr/local/bin/caddy` independently from the resolved Caddy 2.11.4 test
      image, and pins Node v22.22.2 independently from Node 24
      browser CI. A real Linux container process test proves root `/config/`
      readback, descriptor-pinned `setpriv` execution with zero effective
      capabilities/cleared groups, `EACCES` for six simulated non-root service
      UIDs, absent IPv4/IPv6 TCP 2019, exact directory/socket ownership and mode, and
      same-process reload over the UDS, plus real import-override and
      permission-drift regressions. Exact Caddy v2.11.4 regressions also prove
      that all 21 non-canonical Unicode whitespace code points and quoted
      `admin` directives can alter the adapted admin listener and are rejected
      by the closed-profile lexer. Canonical adapted JSON additionally rejects
      global, access and request-scoped log sinks; the candidate binds its
      canonical digest and size, and the committed root readback must reproduce
      that digest. The read-only gate still consumes an externally generated
      adapter artifact for offline review. A separate source-hash-closed,
      local-host-only cold executor now runs the plan-pinned Caddy binary on
      both the exact disk preimage bytes and the exact candidate before mutation.
      It requires the approved canonical old adapted-JSON digest to equal the
      live TCP-admin readback and requires the loaded old unit to have the
      exact fragment and old Exec commands, `NeedDaemonReload=no`, no drop-ins,
      `EnvironmentFile`, or `PassEnvironment`. It requires root, Linux, systemd
      `255`, same-boot/PID/Invocation/preimage pins and a pre-existing exact
      `kernel.core_pattern=|/usr/bin/false`; it never changes the sysctl. The
      plan requires a cold
      stop/install/daemon-reload/start with a new nonzero 32-lowercase-hex
      systemd InvocationID, complete actual
      service-UID and existing-site inventories, exact old-config+old-unit
      rollback, and outcome-unknown handling after an ambiguous start. The
      executor uses an exclusive lock, exact-byte/root-only backups,
      same-parent fsynced atomic replacements, closed public/direct/TLS probes,
      verified pre-start rollback, and never auto-rolls back after a candidate
      start request. Fake-ops fault tests cover each outcome region and durable
      receipt ordering. No installation, host mutation or activation is
      claimed. In addition to static `systemd-analyze verify`, an
      isolated real-systemd-PID-1 compatibility test now proves two distinct
      cold generations plus stop-time removal and start-time recreation of the
      runtime directory/socket. It feeds each real InvocationID into the
      production validator, binds the zero core/swap and null stream settings,
      and confirms an intentionally failing request sentinel does not reach
      journald. The target-host cold ceremony and its
      independently transferred evidence remain deployment gates.
- [x] The local, undeployed `integrated-existing-bhtm-caddy-v1` alternative is
      renderable as a dependency-closed source-fair bundle plus an externally
      approved overlay transaction plan. It appends only to the exact pinned
      hardened `bhtm-caddy.service` preimage and requires a canonical,
      owner-only committed admin-UDS receipt whose Caddy binary, Caddyfile,
      unit and InvocationID equal that preimage. It uses a content-addressed
      `renameat2(RENAME_EXCHANGE)` helper, preserves the swapped-out preimage
      until an atomically published durable receipt, and includes deterministic
      stale-lock/crash recovery plus WebPKI/hostname/leaf and WebSocket-accept
      health checks. The executor validates the complete canonical hardening
      plan/receipt and collects fresh descriptor-sealed UDS mode,
      zero-capability UID-denial, root readback, TCP-refusal, boot and
      generation evidence before exchange and after reload/health. Those
      probes now bind the current effective fragment/drop-ins/environment-name
      policy, `ExecStart`, UDS `ExecReload`, daemon-reload state,
      runtime-directory/identity/umask/core/swap/output settings and exact MainPID argv/start
      ticks; process environment values are never retained. Stable runtime
      snapshots are repeated immediately before exchange and reload. Recovery
      validates the original persisted monotonic windows unchanged, so corrupt
      cross-window evidence fails before mutation instead of being normalized
      into an acceptable receipt. Adapted JSON is exact-digest pinned to the
      hardened preimage before exchange and to the overlay candidate after
      reload and after health checks. Recovery permits either reviewed digest
      only during ambiguous classification, then re-probes the exact terminal
      or aborted generation before publishing state, cleanup or return. Phase
      state and lock ownership use atomic pending-file
      publication; helper return ambiguity is resolved only by supplemental
      fsync and stable exact-pair classification; unknown outcomes prohibit
      rollback, receipt terminalization and cleanup. Mutable transaction
      directory identities and final receipt ownership metadata are sealed
      across recovery, and the helper is parent-death bound. Helper protocol v4
      checks the expected supervisor PID and `/proc/<pid>/stat` start ticks both
      before and after `PR_SET_PDEATHSIG`, so subreaper adoption cannot authorize
      a delayed mutation. An installed pair
      cannot enter automatic rollback until its `exchanged` phase is durable;
      failed abort publication preserves the candidate recovery witness;
      cleanup failures remain attached to the primary error; and a durable
      committed receipt remains attached through terminal-phase finalization
      failure.
      Recovery may reclaim a malformed unpublished `owner.json.pending` only
      when it is the sole exact root-owned owner-only single-link entry; a
      malformed authoritative owner or any ambiguous shape remains fail closed.
      The overlay also re-pins the installed admin-UDS gate itself and requires
      its complete file generation to equal the prerequisite hardening plan.
      Mock failure-window tests and real Linux open/write/fsync/rename,
      applied-then-error, SIGKILL/late-helper and repeated-recovery tests pass.
      The root-only lock/publication suites are routed through the CI root
      invocation so these cases cannot be silently skipped.
      This does not perform the cold admin migration and does
      not isolate the remaining existing root Caddy global/ACME/UID-0 domain, does
      not replace cold edge evidence, and is not deployable on the currently
      inspected Hetzner network until a distinct RFC1918/ULA publisher route is
      separately provisioned and approved.
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
- [x] A dedicated production directory key has been generated locally in an
      owner-only repository-external directory. Its 32-byte scalar, secp256k1
      validity, single-link regular-file shape, effective-user ownership,
      mode-0600 file and mode-0700 final-parent boundary were checked without
      disclosing the secret or copying it into this repository.
- [ ] The production directory key has not been backed up, copied to a host or
      used to sign/publish a production catalog. No production deployment,
      remote-server operation, database migration or real-money operation has
      been performed. Each still requires its explicit deployment ceremony and
      approval boundary.
- [ ] No user manual acceptance test has been performed.

## Production release blockers and gates

The previously reviewed gate/store implementation P1 findings, including
initial payout persist-before-send, are closed. The shared-issuer operator
workflow is also implemented: separate offline builders create the provider
clearing authorization and issuer approval, production registration requires a
distinct provider-request key, and `ProviderLedgerBalanceClientV1` uses the
clearing key without inventing a payout registration or target. An actually
independent linearizable rollback authority is still not deployed. The
numbered items below are mandatory production release, operations,
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
   not close a distributed DDoS surface. The same gate applies to scarce
   Harmony V2Full entries: reservation precedes the authoritative online check,
   so structurally valid but invalid Standard Cashu/shared-issuer proofs can
   hold ready inodes until the bounded check/deadline completes. No hint is
   consumed or regenerated on rejection. A dedicated online-V2Full semaphore
   defaults to at most eight, is acquired before the global AUTH permit and is
   retained from authority check through dispatch/drop. Pending grants arm a
   30-second-or-shorter immutable deadline only after the complete encrypted
   `AUTH_GRANTED` frame is flushed; the same instant bounds pending reads and
   Ping/Pong, and the only actionable application frame is the exact encrypted
   bound-database V2Full main dispatch. Reservation tries rather than blocks on
   the cross-process capacity lock and counts only currently lockable paths from
   the current process's fully validated ready `PoolState`, rather than trusting
   target size or canonical-looking disk surplus. A locked selected inode
   rotates so another bounded-snapshot candidate can proceed. Each successful
   online decision preserves one such entry for provider-local methods, but does
   not reserve it for a caller or guarantee fair/immediate local admission;
   invalid configurations fail startup. A distributed attacker can still deny
   the online-method slice.
   Production activation therefore also requires environment-specific pool
   headroom, tight authorization/dependency deadlines, source-aware edge
   admission or a reviewed puzzle, and an overload test; concurrency bounds
   alone do not provide fairness.
3. **Rollback authority deployment.** A separate local SQLite file is necessary
   but not sufficient and remains a development/test compatibility adapter.
   The provider store, issuer store, and provider-settlement detailed store now
   have a shared authenticated, WebPKI-plus-SPKI-pinned remote authority
   protocol and domain-specific adapters. That code is not deployment evidence:
   each selected role still needs an independently administered authority/TLS
   instance, separate custody and backup domains, monitoring, recovery,
   failover drills, and staging acceptance. Co-snapshotting a detailed store
   with its authority lets a stale pair become self-consistent and defeats the
   rollback defense. Provider payout also has a durable detailed-state adapter
   and a no-funds worker, but no approved real-funds executor; neither the
   transport-neutral library nor any local/test floor activates one.
4. **First production store ceremony.** Payment V1 has no released v6 store to
   migrate and the shared-delivery fix does not bump schema v7. The first
   production activation must use a clean store and a forward-only binary. If
   an older ProviderStore or issuer redeem-history database could contain an
   exact issuer replay without matching local-delivery claims, stop every old
   process and rotate either the per-provider shared-idempotency secret or the
   clearing authorization digest/epoch before serving; never pair that old
   issuer history with an empty local-claim namespace. The fresh-v7
   initialization tool exists, but independent backup /
   rollback-authority placement, restore drills and operational custody still
   need environment-specific acceptance. Development v4 state is not migration
   input; see `PROVIDER_STORE_V7_MIGRATION.md`.
   Harmony V2Full has a separate first-release ceremony: all pre-marker
   processes must be fully stopped, the new binary must start with a fresh
   empty private pool directory, and rollback must use the preserved old or a
   different empty directory. Old and new binaries must never share one
   pool-directory state domain.
   The VPSBG storeless Free-PoW profile is not a shortcut for these stateful
   roles: it is eligible only because it has no store or retained/payment
   method. Its separate release gate is a newly built/uploaded measured UKI
   containing the literal exact signed-policy digest, followed by fresh
   attestation/binary/client-pin acceptance. Policy expiry/renewal, difficulty,
   scope, limit or dataset changes all require another UKI; host-side edits fail
   closed.
5. **Reproducible network E2E.** A committed deterministic no-funds fixture
   assembles two independent providers, all five workloads/methods and issuer
   artifacts. The current acceptance additionally launches two independent
   loopback providers for direct-receipt, Free, provider-local Cashu BAT and
   experimental ARC DPF wire/gate coverage, and separately launches real
   Chromium with generated WASM plus a real loopback fake issuer. The new
   browser/two-issuer/two-provider harness joins these process boundaries for
   direct receipt and BAT admission, but uses explicit `NoSevHost` plus a
   synthetic report/database proof. The complete-query extension has passed a
   dedicated local branch run with proof-bound Merkle preflight, one real
   encrypted DPF query and explicit inclusion/absence verification. The
   feature-gated provider-process supplement now joins Free, Standard Cashu,
   Cashu BAT and experimental ARC production committers to Harmony hint/query,
   Onion and TEE-ORAM handlers, including wrong-operation non-burn and durable
   restart replay. Together with the DPF method-adapter and direct-receipt
   backend cases, this closes the 25 method/workload process cells. The
   isolated current-tree browser rerun passed the real-issuer case
   1/1 and complete-query topology 3/3. Pushed CI remains a per-commit merge
   gate. Production trust-chain remains open. The local Standard-Cashu
   browser/provider join is complete. The
   direct-receipt two-provider process test executes a complete four-frame
   K-padded Harmony query under a distinct Harmony scope, offer and credential
   key, including wrong-scope non-consumption, terminal-DFA rejection and
   restart replay rejection. TEE-ORAM and OnionPIR now have local real-provider
   process boundaries. TEE production attestation/data/floor and browser
   integration remain open; Onion's tiny sibling fixture is not production
   inclusion-proof evidence.
6. **External dependency canaries.** Recorded runs exist for the earlier
   two-node local CLN runner, the disposable CDK runner, and one short-lived
   public Nostr transport/readback smoke. The extended CDK lifecycle and forced
   two-hop three-CLN-node topology both passed final 2026-07-28 current-tree
   opt-in reruns. These are local fake-wallet/regtest boundaries, not an
   aggregate full-suite or production-network result.
   Persistent default-signet Lightning, including an external check of the
   default-signet challenge that the coarse CLN `signet` identity cannot prove,
   an external WebPKI Cashu mint, production catalog publication, and stopped
   plus fresh-live evidence for the resolved relay selection remain staging
   gates. The final topology also needs
   production identity/attestation/pins, TLS/edge controls, outage/restart
   drills, compatibility observations and data-retention review.
7. **ARC review.** ARC must remain hidden behind an experimental offer/UX label
   and must not be a production-required method until independent review is
   closed.
8. **Security closeout.** Coverage-guided/long-running fuzzing beyond the
   bounded deterministic CI corpus, broader DoS coverage, forbidden-field
   logging audit, deployed enforcement of the locally hash-pinned browser CSP
   (including a `frame-ancestors 'none'` response header), deployed-edge abuse
   testing, operator/store drills and an independent end-to-end security
   review remain release gates. The source-level CSP/XSS sink review, hash
   regression test and local production-bundle browser smoke are complete.
   The local dependency audit found no vulnerability and four documented
   allowed upstream/vendor warnings; their ownership and upgrade plan remain
   explicit residual work. A read-only 2026-07-28 GitHub check found no classic
   branch protection or repository ruleset on `main`; the `github-pages`
   environment separately allowed only `main`. This merge is manually gated on
   its final head, but production readiness requires a reviewed required-check/
   no-direct-push ruleset, a Pages required reviewer, revalidation of the Pages
   build mode/default workflow permissions, and review of PAT/GitHub-App
   credentials able to dispatch Actions. No repository setting was changed
   without separate operator approval. The
   completed formal lock is not a substitute for these implementation and
   deployment reviews.

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
