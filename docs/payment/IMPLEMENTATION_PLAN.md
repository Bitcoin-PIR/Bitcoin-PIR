# Payment platform implementation plan

Status: active coordinator plan. This file sequences implementation; it does
not authorize production deployment, remote-host access, or real Lightning
funds.

## Repository and release shape

V1 stays in the BitcoinPIR monorepo. The service-policy wire, provider gate,
Rust/WASM SDK, browser and integration fixtures must evolve atomically, and a
single workspace lockfile gives dependency and MSRV review one boundary.

The payment/credential issuer is nevertheless an independent process with an
independent database, keys, configuration and deployable binary. Its Rust
library, protocol types and first binary live in this repository until the
HTTP API and migration contract are stable. A later repository split must not
change the signed or canonical wire encodings and is not on V1's critical
path.

Development uses `codex/payment-platform` with auditable checkpoint commits.
Parallel agents own disjoint crates/files; the coordinator reviews shared
boundaries and runs the combined matrix before each checkpoint. A draft PR is
opened only after the local fake-backend end-to-end gate is green. Production
configuration remains impossible by default.

## Dependency graph

```text
signed policy + canonical service wire
            |
            +--> provider store + anti-rollback floor
            |             |
            |             +--> encrypted runtime admission DFA
            |                          |
            |                          +--> DPF / Harmony / Onion / ORAM grants
            |
            +--> quote / issuance / clearing protocol
                          |
                          +--> issuer store + fake Lightning backend
                          |             |
                          |             +--> issuer HTTP service
                          |
                          +--> BIP340 / Cashu / ARC adapters
                                        |
                                        +--> Rust SDK / WASM / browser vault

directory schema + publisher/client --> discovery only; never a trust root

all lanes ---------------------------> fault tests + security review + ops docs
```

## Workstreams

### A. Protocol, persistence and cryptography

Deliver canonical bounded types, signed policy and delegation chains, concrete
BOLT11/BIP340/Cashu verification, issuer/provider durable stores, replay
protection and independent rollback floors. This lane must expose verified
private-field typestates rather than boolean assertions or public unchecked
constructors.

Exit criteria:

- every method has one canonical wire shape and one authoritative spent state;
- stale restore, same-version fork, duplicate/concurrent spend and lost-response
  tests pass;
- native Clippy is warning-free and browser-facing crates build for wasm32;
- ARC stays `experimental` and cannot be configured as stable.

ARC's confirmed demo gaps, fixed-context construction and independent-review
gate are specified in `ARC_EXPERIMENTAL_REVIEW.md`.

### B. Provider admission and backend grants

Replace the legacy connection-local ARC/Cashu booleans with an encrypted
connection DFA. Policy retrieval follows verified identity/channel/database
setup; authorization occurs before scarce/expensive work. A grant binds the
exact operation, database, backend, workload, protocol/profile and limits.

Harmony hint generation and Harmony query are separate scopes. A half-hint
operation may attach two transport halves to one already-consumed logical
grant without introducing a peer-provider identifier. DPF, Onion and TEE-ORAM
each have their own bounded operation transitions.

Exit criteria:

- unencrypted policy/auth and every pre-grant expensive opcode fail closed;
- all Free modes, direct receipt, standard Cashu, BAT, shared online redeem and
  ARC-experimental dispatch explicitly; an unavailable adapter rejects rather
  than falls back;
- one successful durable/authoritative consume creates at most one bounded
  connection grant;
- old `0x08`/`0x09` demo frames cannot authorize production work.

### C. Issuer and settlement service

Build the HTTP service over the issuer store with authenticated status polling,
exact idempotency, fake Lightning settlement events, direct receipt/BAT/ARC
issuance, shared online redeem, provider ledger credit and payout outbox.
Define the blind settlement-note deposit and keyset surfaces in the canonical
protocol/store, but keep their HTTP routes disabled until a retained-keyset
operations ceremony is reviewed. Real payout execution remains disabled.

Exit criteria:

- invoice amount and entitlement come only from a verified signed offer;
- a settled quote can be recovered after lost HTTP responses and restart;
- claim signature, exact issuance request and credential count/order are
  verified inside the transaction boundary;
- serial/nullifier uniqueness is issuer-global where required;
- payment hash/preimage never enters PIR wire or provider storage;
- fake-backend crash/replay/concurrency tests are green.

### D. Standard Cashu merchant adapter

Implement exact-value NUT-03 merchant swaps against the mint committed by the
signed offer. Persist encrypted output recovery material before submission,
verify NUT-12 and local blinding transcripts, and use the same outputs for
NUT-09 recovery. NUT-07 can diagnose input state but never authorizes a second
swap with different outputs.

Exit criteria:

- no plaintext proof secret, output secret or blinding scalar is persisted or
  logged;
- timeout/lost response/restart recovers the same promises;
- underpayment, overpayment-without-extra-entitlement, wrong keyset/order/amount, partial restore and bad
  DLEQ all fail closed;
- mint commit is the only authoritative input spend; no duplicate provider
  spent-set write exists.

### E. SDK, WASM and browser

Expose strict policy verification and method selection in the native SDK and
WASM. Store claim keys, quote snapshots and anonymous capabilities in
IndexedDB; use Web Locks plus transactional reservations for multiple tabs.
Never write invoice-to-query linkage to `localStorage`.

The client selects and pays each provider independently. It may find provider
0 first and provider 1 later; neither policy nor request contains the other
provider's identity. The client rejects raw BAT- or ARC-verification-key reuse
across the two selected verified policies before it considers an explicit
shared-issuer override.

Exit criteria:

- strict identity/binary/attestation/channel/database/root/policy ordering is
  enforced before capability presentation;
- each provider can independently select a different supported method;
- page close/reopen recovers paid issuance without associating a capability
  with a Bitcoin address or query;
- multi-tab tests cannot double-reserve a one-use capability;
- verification failure never downgrades to plaintext or unpaid service.

### F. Directory and operator tooling

Define versioned Nostr events for provider endpoints, backend/workload scopes,
the exact live-policy epoch/digest and coarse health. Policies themselves are
retrieved only through the strictly verified provider connection; the central
directory signs with a key
distinct from every provider/operator/payment key. Clients still verify the
provider's own signed policy and trust chain. The canonical v1 event,
inner-operator assertion and client rollback rules are specified in
`DIRECTORY_PROTOCOL.md`.

Provide offline key-generation, policy validation/signing, epoch rotation and
store initialization tools. Secret keys never appear in Nostr events or normal
command output.

Exit criteria:

- stale/replayed/equivocating directory events cannot override provider trust;
- every provider advertises independent keys and pricing per workload;
- policy lint rejects shared BAT raw keys, ARC stable status, missing recovery
  horizons and unsupported method combinations.

### G. Integration, security and operations

Run method-by-method end-to-end tests with two independently configured fake
providers, a fake issuer/Lightning backend and a fake Cashu mint. Add network
fault injection at every durable boundary, then perform a fresh adversarial
review of correlation, replay, rollback, confused-deputy and strict-mode
downgrade risks.

Exit criteria:

- the full failure matrix in `TEST_PLAN.md` passes on native and applicable
  browser targets;
- logs and database schemas pass a forbidden-field audit;
- explicit-legacy/enforced compatibility, fresh-store initialization and
  rollback runbooks are rehearsed locally;
- a draft PR contains focused commits and an explicit residual-risk register;
- no production deployment or real-fund command has run.

## Checkpoints

1. **Core checkpoint:** protocol, crypto, provider/issuer stores and rollback
   floors pass their isolated matrices.
2. **Fake service checkpoint:** issuer HTTP plus fake Lightning/Cashu transports
   and provider admission work end to end without real funds.
3. **Client checkpoint:** Rust/WASM/Web complete independent two-provider
   purchase and query flows, including crash and multi-tab tests.
4. **Discovery checkpoint:** signed Nostr directory and policy tooling interop
   with the same fixtures.
5. **Security checkpoint:** independent review findings are fixed or recorded;
   ARC remains experimental regardless of functional tests.
6. **PR checkpoint:** draft PR, CI, migration/rollback/operator/user docs and a
   reproducible local demo are ready.
7. **Manual acceptance:** the user runs the documented fake-funds browser test
   and reviews privacy-visible records.
8. **Deployment decision:** only then request separate approval for each
   production/remote/live-funds action and name its exact host, service, key and
   rollback step.

## Compatibility and rollback

The server has two explicit modes: legacy admission selected by omitting all V1
service configuration, and enforced V1 selected with
`--require-service-auth-v1`. There is deliberately no credential-consuming
"shadow" mode: verifying or reserving bearer material while still allowing a
legacy query would create ambiguous spend and downgrade semantics. Enforced
mode requires a valid signed policy, external rollback authority and every
advertised method adapter at startup; partial V1 configuration is fatal.

Legacy `0x08` ARC and `0x09` BAT messages remain demo-only during migration.
They are never translated into a production grant. Rollback from enforced mode
means restoring the previous binary/configuration while keeping new credential
and spent databases intact; it never means lowering policy/store floors or
restoring a stale spent database.

## Decisions deliberately deferred

The protocol does not depend on a particular production Lightning node API or
rollback-floor vendor. A Core Lightning Unix-RPC adapter is implemented as the
first executable backend, but choosing it (or a future backend), its custody
model, network and backup/HA contract remains an operator decision. Before
deployment, each provider must also choose a separately administered
rollback-floor authority whose metadata leakage is acceptable. These are
operational trust decisions, not pricing-policy fields.
