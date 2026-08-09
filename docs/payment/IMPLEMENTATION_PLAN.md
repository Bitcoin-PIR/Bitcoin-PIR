# Payment platform implementation plan

Status: functional-beta browser acceptance completed on 2026-08-09. This plan
prioritizes a usable payment path and user acceptance over exhaustive security
hardening. It does not authorize production deployment, remote-host mutation,
public service changes or real Lightning funds.

The previous plan mixed basic implementation, production hardening and broad
security research into one critical path. That encouraged increasingly complex
gates before the main user flow was complete. This revision separates:

1. functionality required for a Payment V1 functional beta;
2. the smallest tests needed to keep it correct; and
3. production/mainnet work that belongs in a later, separately approved plan.

## Functional-beta target

A user can discover two independent PIR providers, strictly verify each one,
independently choose an offered payment method, acquire or select a capability,
authorize one bounded operation, complete the PIR query and verify its result.
Failures during payment, issuance, authorization or query execution have an
explicit recoverable or terminal outcome.

The supported methods are Free, direct BOLT11 receipt, standard Cashu eCash,
BitcoinPIR Cashu BAT and experimental ARC. The first release target is a
no-funds or Signet functional beta. Mainnet, real-value settlement and automatic
provider payouts are separate products.

## Required invariants

Only properties that would make the basic implementation incorrect remain on
the functional critical path:

- PIR providers never receive an invoice, payment hash, preimage, payer
  identity or issuer quote identifier;
- provider 0 and provider 1 have independent selection, authorization, keys
  and spent state; the default flow has no shared raw token or pair identifier;
- price and entitlement come from a verified provider-signed policy or offer,
  never from client-supplied amounts or limits;
- capability consumption is bounded and at-most-once at an authoritative
  durable boundary; replay and cross-provider use fail closed;
- identity, secure channel, database proof and policy verification happen
  before capability presentation or payment;
- an unavailable verifier or payment adapter never downgrades to plaintext,
  unverified or accidentally unpaid service.

ARC stays optional and visibly experimental. An independent review is required
only before promoting it to stable or making it a production-required method.

## Delivery priorities

### P0 — complete the user path

P0 items may block the functional beta.

| Workstream | Deliverable | Minimum evidence |
| --- | --- | --- |
| Policy and wire | One bounded policy/auth envelope shared by server, issuer, SDK, WASM and Web; grants bind provider, database, backend, workload and limits | Canonical codec tests; unsupported methods and legacy demo frames reject |
| Issuer and methods | Recoverable quote/status/claim lifecycle; fake Lightning; optional Signet CLN; Free/direct/Cashu/BAT/ARC adapters | Amount comes from signed offer; restart/lost-response recovery; duplicate and cross-provider rejection |
| Provider admission | Encrypted bounded grant replaces connection-wide credential booleans; admission precedes expensive work | Representative real-process tests reach DPF, Harmony hint/query, Onion and TEE-ORAM; wrong scope and replay do not burn a valid capability |
| Rust/WASM/Web | Real client performs policy verification, acquisition, IndexedDB storage, authorization, query and result verification | Two providers may use different methods; page reopen recovers issuance; multiple tabs cannot reserve one capability twice |
| Directory and operator | Versioned Nostr discovery plus minimum key/policy/store tooling; directory remains discovery, not a trust root | Publish/readback works; stale checkpoint rejects; tooling does not print secrets |

For the functional beta, provider ledger accrual and a signed balance are a
sufficient shared-settlement product. Real payouts and Settlement Cashu deposit
routes are not required until their operator and custody model is selected.

### P1 — minimal sufficient validation

P1 protects the P0 path and should remain smaller than the implementation.
Required validation is:

- focused unit/contract tests for canonical encoding, quote entitlement,
  replay, cross-provider rejection and durable recovery;
- one representative real-process path per payment adapter;
- shared backend grant contract tests plus targeted process coverage, rather
  than duplicating every method/workload combination in every harness;
- one strict two-provider end-to-end query with mandatory result verification;
- Web typecheck, unit tests and production bundle build;
- a small startup/migration/rollback smoke for the selected beta profile; and
- exact-head CI for the boundaries changed by the PR.

The complete method/workload matrix may run as a scheduled or release gate. It
is not a reason to create several overlapping E2E suites or rerun Chromium for
unrelated server-only changes.

### P2 — deploy and obtain acceptance

After P0 and P1:

1. render one reproducible no-funds or Signet beta configuration;
2. deploy only explicitly approved services and topology;
3. verify catalog readback, service health, one strict two-provider Free query
   and one approved paid-admission smoke;
4. retain a concrete rollback path without enabling real-value payout;
5. ask the user to perform the documented browser acceptance; and
6. record observed evidence and limitations without making stronger production
   claims.

## Test and audit policy

### Default profiles

- normal agent work uses the quick browserless check;
- the PR profile runs Rust/process/WASM, Web typecheck, unit tests and bundle
  generation without Playwright or Chromium;
- browser checks run only when the user asks, browser-only behavior changed, or
  a named release candidate needs acceptance;
- public relays, external mints, Lightning nodes, remote servers and funds are
  always opt-in and separately approved.

### Add a test only when it protects

- a previously observed regression;
- a shared canonical wire or persistence contract;
- an at-most-once money/capability transition;
- a direct privacy or fail-closed boundary; or
- the primary user path and its recovery behavior.

Do not add a gate merely because another static assertion is possible. Avoid
duplicate tests for the same property, exhaustive mutation of template fields,
full browser matrices for server-only changes, and long manual command lists
that an AI agent must follow. Prefer one authoritative script with named
profiles.

Security review is milestone-driven. Changes to credential verification, spent
state, key separation, strict-channel ordering or provider independence receive
focused review. Other hardening ideas go to the backlog unless concrete
evidence shows that they block the current user path.

When the acceptance criteria pass, stop. Do not convert every discovered
defence-in-depth idea into a new prerequisite.

## Deferred from the functional-beta critical path

These items may be selected for a later production/mainnet plan, but must not
delay the basic Payment V1 path:

- paid-priority/QoS scheduling beyond signed metadata;
- real-funds payout execution and Settlement Cashu deposit activation;
- approved live Mainnet Lightning operation and real-money operation;
- production TLS edge, distributed abuse controls, overload benchmarking,
  metrics and alerting;
- independently hosted production rollback authorities, HA/failover and
  production custody ceremonies;
- external public-WebPKI Cashu mint and long-lived public-network canaries;
- promotion of ARC from experimental to stable;
- long-running fuzzing, exhaustive fault injection, broad log audits and an
  independent end-to-end security assessment;
- complete ELF/loader provenance, coredump/PID1 evidence, immutable-root proofs
  and unrelated system-wide host isolation; and
- repository governance and credential-administration projects, unless chosen
  separately as release-management work.

Deferral is not a claim that these items are complete or unnecessary for a
real-money production service. The beta must state the corresponding limits.

## Mainnet Lightning V1 handoff boundary

The repository now has a bounded source-readiness lane for the Mainnet
`direct-bolt11-dpf` profile. Run
`scripts/payment-v1-mainnet-lightning-v1-check.sh` for the focused offline Rust,
source/render, and Web Direct+Direct contract; do not substitute it for full
CI or a live deployment check.

This lane is **source-ready; live approval pending**. A later, explicitly
approved operation must supply the public identifiers/path/hash pins, selected
Mainnet CLN node, risk caps and liquidity/funding envelope, then separately
approve rendering, remote mutation, custody/funds, activation, and any invoice
or payment action. The runbook deliberately keeps secrets out of source and is
the authoritative short handoff:
[`MAINNET_LIGHTNING_V1_RUNBOOK.md`](MAINNET_LIGHTNING_V1_RUNBOOK.md).

## Compatibility and rollback

The server retains explicit legacy and enforced Payment V1 modes. There is no
credential-consuming shadow mode. Rollback restores the previous binary and
configuration while preserving credential/spent databases; it does not lower
floors or restore stale spend state. A beta deployment uses fresh stores unless
an explicit tested migration belongs to that release.

## Checkpoints

1. **Core path:** policy, issuer lifecycle, provider grant and client
   acquisition pass focused tests.
2. **Method path:** each of the five methods passes one authoritative adapter or
   process boundary.
3. **Two-provider path:** independently selected providers complete one strict,
   verified query with no shared payment identifier.
4. **Beta deployment:** the approved no-funds/Signet topology publishes and
   reads back its catalog and passes bounded smoke tests.
5. **Manual acceptance — complete (2026-08-09):** the user completed the live
   browser flow with two verified servers; the result showed `Verified` and the
   log reached `Batch complete`.
6. **Production decision:** after beta acceptance, create a separate plan only
   for the selected mainnet, payout, hardening and operations scope.

## Definition of done

Payment V1 is functionally complete when checkpoints 1–5 pass, the default
browserless PR checks are green, known user-path blockers are fixed, and
remaining hardening is recorded as non-blocking backlog with honest scope
labels.

The beta is not incomplete merely because every possible audit or production
hardening task has not been performed. Conversely, passing local or CI tests is
not evidence of mainnet readiness, real-funds safety or user acceptance.
