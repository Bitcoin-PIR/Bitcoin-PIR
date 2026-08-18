# db1 Free-PoW + BAT implementation plan

Status: db1 dataset/proof and Free-PoW source work completed on 2026-08-18; the
provider-specific BAT production contract was superseded later that day and
requires the issuer-wide V2 work in
[`payment/MAINNET_SHARED_BAT_PRODUCTION_PLAN.md`](payment/MAINNET_SHARED_BAT_PRODUCTION_PLAN.md).
This document is not production deployment, policy rotation, database rebuild,
public Web publication, or funds authorization.

## Product contract

The production product supports both database entries in the active catalog:

- db0 is the full snapshot;
- db1 is the delta that advances a client with the matching base state to the
  same current height.

DPF, Harmony, Onion and Direct ORAM must all support db1. Every production db1
query scope offers exactly these two stable entitlement paths:

1. provider-local Free proof of work;
2. a blinded issuer-wide BitcoinPIR Cashu BAT whose reviewed acceptance class
   includes the selected provider offer and whose first successful redemption
   is consumed globally by the shared issuer.

BOLT11 is the issuer-side way to purchase the blind BAT. It is not a separate
provider query entitlement: the PIR provider must not receive the invoice,
payment hash, preimage, payer identity, or route data. A production db1 profile
must not advertise a direct-receipt offer as an alternative to BAT.

Standard Cashu and experimental ARC are not part of this rollout. Their generic
protocol and test support may remain in the repository, but this work must not
add either method to a db1 production scope.

## Scope matrix

Each row below needs an independent db1 scope bound to the backend-specific
strict verified dataset root selected for db1. DPF/Harmony use their verified
DB-proof sidecar root, Onion uses its V2 proof root, and Direct ORAM uses the
verified loaded server-manifest root. These roots describe the same logical
db1 catalog entry but must not be collapsed into one placeholder. A db1 scope
must not reuse the db0 scope ID, offer ID, price or resource limits merely
because the workload name is the same. Its BAT offer must name an exact
acceptance-class membership. A raw BAT lineage may be shared across provider
scopes only inside one reviewed class with identical BAT-relevant terms; it
must not be copied across classes.

| Backend | Provider role | db1 workload | Required stable offers |
| --- | --- | --- | --- |
| DPF | pir1 evaluate leg | `dpf-evaluate-job-v1` | Free-PoW + BAT |
| DPF | pir2 evaluate leg | `dpf-evaluate-job-v1` | Free-PoW + BAT |
| Harmony | pir1 hint leg | `harmony-hint-bundle-v1` | Free-PoW + BAT |
| Harmony | pir2 query leg | `harmony-query-job-v1` | Free-PoW + BAT |
| Onion | pir1 evaluate leg | `onion-evaluate-job-v1` | Free-PoW + BAT |
| Direct ORAM | pir2 measured runtime | `tee-oram-query-v1` | Free-PoW + BAT |

The two providers keep independent identities, policies and live admission
decisions. The issuer keeps the only durable BAT spent set. The browser may use
one issuer-wide BAT at either compatible provider, but a paid two-provider
query still consumes two independent BATs.

## Source result and remaining release boundary

- Complete pir1/pir2 source templates cover every matrix row for db0 and db1,
  with exactly Free-PoW and a BAT placeholder in each scope. Their current
  provider-specific BAT bindings are inert superseded draft input, not a
  production-ready policy; Phase D of the issuer-wide plan must replace them.
- Read-only implementation inspection confirmed that Payment V1 already binds
  arbitrary exact `db_id` together with provider, backend, workload, protocol,
  dataset root and profile. No db0-special runtime branch or missing payment
  wire needed to be changed; the new static gate validates the complete source
  policy matrix instead of duplicating that generic admission machinery.
- The retained db1 native V2 delta evidence and Direct input binding are now in
  the Web source tree. The verifier selects db0 or db1 by exact ID, rejects
  cross-selected artifacts and unknown IDs, and the ORAM catalog refresh keeps
  the user's selected db for the next admission attempt.
- The active database lineage keeps its accepted mixed provenance. The 4A
  runbook rule applies prospectively to the next candidate and does not rebuild
  or relabel the current lineage.
- Remaining work includes the executable production profiles and their later
  operational release. The ordered source and deployment boundary is recorded
  in
  [`payment/MAINNET_SHARED_BAT_PRODUCTION_PLAN.md`](payment/MAINNET_SHARED_BAT_PRODUCTION_PLAN.md).
  Nothing in this completed db1 source PR activates a provider, issuer,
  payment, database, UKI or public site.

## Historical source sequence and superseding boundary

The steps below record the completed db1 source slice. Any assertion that a
BAT key, vault record or spent namespace must remain provider-specific is
superseded by the issuer-wide plan. Dataset roots, db isolation, Free-PoW and
Direct-proof work remain valid.

## Implementation sequence

### Step 1 — Freeze the policy shape

Add db1 variants to the source policy/profile templates. For every workload,
bind the scope to the exact backend-specific db1 dataset root and include only
Free-PoW and stable shared-issuer BAT offers. Use separate DPF/Harmony, Onion,
and Direct ORAM root placeholders even when a retained release record shows
related logical database metadata. Generate fresh offer IDs. BAT class
membership is added only by the new V2 plan; do not promote the current
provider-specific binding placeholders.

Acceptance:

- the source templates parse and expose distinct db0 and db1 scopes;
- every db1 scope has exactly one Free-PoW and one stable BAT offer;
- no db1 scope contains direct receipt, Standard Cashu, or ARC;
- DPF, Harmony hint/query, Onion and Direct ORAM remain distinct workloads with
  independently configurable limits and prices.

### Step 2 — Prove admission and client selection

Reuse the existing dataset-bound Payment V1 admission machinery. Add only the
missing selection/wiring needed for clients to request a db1 scope and for each
backend grant DFA to accept db1 operations after authorization.

Acceptance:

- one focused matrix test admits both Free-PoW and BAT for every db1 workload;
- a db0 authorization cannot admit db1 work, and a db1 authorization cannot
  admit db0 work;
- the historical V1 gate keeps its provider/scope/offer isolation until it is
  replaced rather than silently weakening the old wire;
- preflight remains non-consuming and expensive work remains behind admission.

Implementation result: no admission/client payment code change was necessary
for the db1 dataset slice. The old source gate checked all six workloads and
the provider-specific bindings that existed at that time. The issuer-wide V2
work must replace those binding assertions; existing arbitrary-db isolation
remains valid and does not need a duplicate db1-special Rust matrix.

Superseding V2 acceptance remains pending: one BAT may target any compatible
acceptance-class member, but the issuer's first successful commit must make
every later presentation globally spent. That is Phase B/D work in the
issuer-wide plan, not evidence from this completed historical step.

### Step 3 — Publish and verify the Direct ORAM db1 source proof

Publish only the small retained V2 evidence needed to bind db1 Direct inputs to
the attested delta build. Do not publish mutable ORAM pages or treat their byte
hashes as a browser trust gate. Extend the public proof registry and verifier so
the caller selects the proof by exact db ID/root rather than relying on a single
db0 `current.json`.

Acceptance:

- the browser verifier validates both db0 and db1 against their own production
  pins, live database proof and measured runtime root;
- substituting a db0 artifact, db1 artifact, manifest root or Direct input hash
  fails closed;
- the db1 proof records delta build semantics and its base/current anchors;
- only the closed, reviewed public artifact set is accepted.

Implementation result: the immutable db1 directory contains only the six
reviewed small artifacts (12,401 bytes total); mutable ORAM pages, logs, build
summary and controller state remain excluded. The source is ready for a later
Web deployment but has not been published by this work.

### Step 4 — Record the future builder boundary (decision 4A)

Keep the current db0/db1 artifacts and their historical mixed provenance. Add a
release requirement that the next normal production database rotation uses the
reviewed attested-builder to emit the complete server-loadable artifact set,
followed by end-to-end consistency verification before activation. Local
wrappers remain development/reproduction tools and cannot become the producer
of a future production rotation by omission.

Acceptance:

- the database rotation runbook names the reviewed producer, complete required
  outputs, evidence retention and consistency check;
- it explicitly says the rule is prospective and does not authorize rebuilding
  the active lineage;
- no CI database build or production rebuild is introduced.

Implementation result: the prospective rule, retention requirements and
correct native V2 snapshot/delta runbook are recorded without changing builder
code, database tooling or CI.

### Step 5 — Focused verification and PR handoff

Run tests by changed boundary, not by repository size:

1. the focused Payment service-admission test while changing admission code;
2. the existing static deployment-template audit while changing templates;
3. targeted Web unit tests for db1 scope/proof selection if Web code changes;
4. the relevant Rust proof parser test only if a proof format/parser changes.

Do not run a production browser check, public canary, full database build, UKI
build, deployment, or real-funds flow as part of source development. A broader
Payment `--pr` profile is justified once, before PR handoff, only if the final
diff crosses multiple Payment/WASM boundaries.

Actual focused evidence for this source implementation:

- `node scripts/payment-v1-deployment-template-gate.mjs` — PASS;
- `node --test scripts/payment-v1-deployment-template-gate.test.mjs` — 31/31;
- `npm exec vitest run src/__tests__/oram-source-proof.test.ts` — 16/16;
- `npm run test:production-canary-readiness` — PASS;
- `npm run build && npm run build-web` — TypeScript, Vite and CSP PASS; and
- `git diff --check` — PASS at each commit boundary.

No Cargo/Payment `--pr`, broad deploy audit, browser, database build, ORAM bulk
rebuild, UKI build or production test was run. There was no Rust admission or
proof-format change to justify Cargo, and the dedicated template gate already
covered the new directory without re-running unrelated Caddy/netns audits.

## Commit and review boundaries

Keep the work reviewable in this order:

1. this plan and its product/non-goal contract;
2. db1 policy/profile and admission/client changes;
3. Direct ORAM db1 public-proof changes;
4. prospective attested-builder rotation documentation;
5. focused verification evidence and final status updates.

Production mutation remains separate. The provider-specific BAT templates must
not be materialized. After the issuer-wide source work is merged, a coordinated
pir1/pir2 policy and binary release, acceptance-class key creation, public
proof publication, and any real-value Lightning activation each require their
normal explicit operator approvals.
