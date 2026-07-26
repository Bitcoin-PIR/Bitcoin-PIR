# Payment V1 implementation security review — 2026-07-26

Status: independent agent review of the implementation tree on
`codex/payment-platform`. This record is suitable for draft-PR and no-funds
staging preparation. It is **not** production activation approval and it is
not the external cryptographic review required for ARC.

## Result

- P0 open: **0**
- P1 open: **0**
- implementation P2 findings fixed in this review: **all closed**
- operational P2 residual: **1** — issuer startup integrity validation remains
  O(total retained quote history)

Production deployment, remote-server operation, public relay/external mint
access and real Lightning funds remain separate approval gates.

## Scope reviewed

- canonical service policy, scope, offer, credential-binding and wire codecs;
- provider-local Free, direct receipt, standard Cashu, Cashu BAT and
  experimental ARC admission;
- independent provider stores, rollback floors, replay and concurrency;
- BOLT11 quote creation, settlement, claim, key rotation and crash recovery;
- shared issuer clearing, provider accounting and payout state;
- Core Lightning RPC and HTTP listener boundaries;
- Rust SDK, WASM, encrypted browser vault, multi-tab reservation and product
  admission orchestration;
- Nostr directory validation, rollback and split-view handling;
- two-provider process integration, command-line fail-closed behavior,
  logging fields and documented production boundaries.

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

## Open release blockers and accepted residuals

### Operational P2: retained-history startup cost

`IssuerStore::open_existing` performs full retained-history integrity checks,
including quote replay-image validation. The newer readiness queries are
horizon-bounded, but the complete startup path remains O(total retained
history). Before staging activation, operators must measure startup latency and
memory at explicit retained-row thresholds, define an SLO and refuse activation
when it is exceeded. Before sustained high-volume production, design and review
an authenticated archive/retention format; ad-hoc row deletion is forbidden.

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

### Browser and shared-infrastructure boundaries

The non-extractable WebCrypto key prevents accidental plaintext persistence;
it does not defend against XSS or a copied unlocked browser profile. A
capability is burned before send, and an ambiguous network failure is not
automatically retried or refunded. Using one online shared issuer for both PIR
legs remains an explicit correlation/availability tradeoff even though the
provider-bound capabilities are cryptographically unrelated.

### Rotation and capacity constraints

Retained quote material must have the same issuer root, Lightning network and
payee as the current issuer instance. Root or Lightning-node identity rotation
therefore requires draining every old recovery/claim horizon or running a
parallel old recovery instance; the audience checks must never be weakened.
`priority_class` is signed/displayed metadata only and does not yet implement a
server scheduler. Production edge rate, bandwidth, overload and telemetry work
remains mandatory.

## Verification evidence at review close

- issuer: `payment-issuer` 14 tests; issuer-service 4 unit + 5 acquisition;
  issuer-store 1 unit + 30 integration — all passed;
- loopback provider process E2E: 2 passed, 0 failed;
- Web: strict TypeScript build passed; 324 tests passed and 2 were explicitly
  skipped; production Vite bundle passed;
- fresh WASM bindings, wasm32 checks, no-funds fixture, dependency audits and
  the complete reproducible command are recorded in `LOCAL_ACCEPTANCE.md` and
  `scripts/payment-v1-local-check.sh`;
- final tree checks must remain green after this record is added and before the
  branch is pushed.

## Review verdict

The architecture correctly keeps invoice, payment hash, preimage and payer
state out of PIR providers. Each provider independently advertises and consumes
one workload-specific capability, and neither provider needs to know the peer.
The implementation is appropriate for a draft PR and approved no-funds staging
preparation. Production activation remains blocked on the items above, the ARC
review, approved external canaries and user manual acceptance.
