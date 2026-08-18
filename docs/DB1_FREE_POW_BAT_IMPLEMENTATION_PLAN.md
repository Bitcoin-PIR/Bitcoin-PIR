# db1 Free-PoW + BAT implementation plan

Status: approved product direction; source implementation in progress. This
document is not production deployment, policy-rotation, database-rebuild, or
funds authorization.

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

## Current gaps

- The production-oriented DPF and Harmony templates are intentionally db0-only;
  Harmony hint and Onion do not yet have equivalent db1 production entries.
- Direct ORAM already has a db1 Free-PoW runtime scope, but it has no stable BAT
  offer.
- The published Direct ORAM source proof currently covers db0 only. db1 cannot
  be described as formally supported until its retained V2 delta evidence and
  Direct input binding are exposed through the same fail-closed public verifier.
- The active database lineage has accepted mixed provenance. It is not being
  rebuilt merely to rewrite that history.

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
