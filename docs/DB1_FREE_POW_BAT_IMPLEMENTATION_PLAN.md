# db1 Free-PoW + BAT implementation plan

Status: source implementation complete and focused PR validation passed on
2026-08-18. This document is not production deployment, policy rotation,
database rebuild, public Web publication, or funds authorization.

## Product contract

The production product supports both database entries in the active catalog:

- db0 is the full snapshot;
- db1 is the delta that advances a client with the matching base state to the
  same current height.

DPF, Harmony, Onion and Direct ORAM must all support db1. Every production db1
query scope offers exactly these two stable entitlement paths:

1. provider-local Free proof of work;
2. a blinded, provider-specific BitcoinPIR Cashu BAT redeemed through the
   approved shared issuer.

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
must not reuse the db0 scope ID, offer IDs, BAT binding, BAT key lineage, price,
or resource limits merely because the workload name is the same.

| Backend | Provider role | db1 workload | Required stable offers |
| --- | --- | --- | --- |
| DPF | pir1 evaluate leg | `dpf-evaluate-job-v1` | Free-PoW + BAT |
| DPF | pir2 evaluate leg | `dpf-evaluate-job-v1` | Free-PoW + BAT |
| Harmony | pir1 hint leg | `harmony-hint-bundle-v1` | Free-PoW + BAT |
| Harmony | pir2 query leg | `harmony-query-job-v1` | Free-PoW + BAT |
| Onion | pir1 evaluate leg | `onion-evaluate-job-v1` | Free-PoW + BAT |
| Direct ORAM | pir2 measured runtime | `tee-oram-query-v1` | Free-PoW + BAT |

The two providers keep independent identities, policies, stores, BAT key
lineages and admission decisions. The browser acquires and presents one
provider-specific authorization for each provider involved in a query.

## Source result and remaining release boundary

- Complete pir1/pir2 policies now cover every matrix row for db0 and db1, with
  exactly Free-PoW and stable shared-issuer BAT in each scope.
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
- Remaining work is operational: render/review/sign the policies, create BAT
  lineages and issuer authorization, publish the Web artifacts, and coordinate
  the pir1/pir2 release under separate approvals. Nothing in this PR activates
  a provider, issuer, payment, database, UKI or public site.

## Implementation sequence

### Step 1 — Freeze the policy shape

Add db1 variants to the source policy/profile templates. For every workload,
bind the scope to the exact backend-specific db1 dataset root and include only
Free-PoW and stable shared-issuer BAT offers. Use separate DPF/Harmony, Onion,
and Direct ORAM root placeholders even when a retained release record shows
related logical database metadata. Generate fresh placeholder namespaces for
the db1 offer IDs and BAT bindings; do not copy the db0 audience coordinates.

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
- a BAT for one provider, scope, workload, or offer cannot be reused for
  another;
- preflight remains non-consuming and expensive work remains behind admission.

Implementation result: no admission/client payment code change was necessary.
The new source gate checks all six provider workloads across db0/db1, unique
roots/bindings/offers, and the exact two-method profile. Existing runtime tests
already exercise exact arbitrary-db isolation, so a duplicate db1-special Rust
matrix was intentionally not added.

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

Production mutation remains separate. After the source PR is merged, a
coordinated pir1/pir2 policy and binary release, issuer BAT lineage creation,
public proof publication, and any real-value Lightning activation each require
their normal explicit operator approvals.
