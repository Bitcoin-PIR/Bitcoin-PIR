# Payment V1 private render-plan skeletons

These files mirror schema version `1` and the closed profile catalog in
`scripts/payment-v1-rendered-artifact-gate.mjs`. They are review aids, not
ready-to-render examples.

Every skeleton is deliberately unusable:

- every `source_sha256`, `expected_sha256` and digest/public-key placeholder is
  an invalid non-hex marker;
- DNS, IP, origin, network-limit and other placeholder values are explicit
  invalid replacement markers;
- payload `source_path` values name deliberately nonexistent relative entries
  beneath a future private input root;
- binary target paths retain an invalid digest marker except the resolved
  directory-relay selection, whose reviewed binary digest is already fixed; and
- numeric service identities are documentation examples and must be replaced
  with the exact approved NSS values on the target host. Every service UID/GID
  must be in the static range `1..60000`; the render gates reject systemd's
  `DynamicUser` range `61184..65519`, `nobody` `65534`, and all larger IDs.

The gate must reject an untouched skeleton. Making one syntactically acceptable
is not approval to install or activate it.

The Bitcoin Core skeleton is a separate failure domain from the issuer
skeleton. Its content-address root is the externally approved release archive
SHA-256, while its canonical provenance receipt separately binds extracted
`bitcoind`/`bitcoin-cli` digests, one exact `guix.sigs` commit and at least three
distinct valid builder fingerprints. The issuer plan must not carry or replace
any of those Core-owned payloads.

The integrated existing-Caddy overlay plan carries two distinct adapted-JSON
pins. `target.admin_uds_hardening.adapted_json_sha256` is the exact live
hardened-preimage digest; `managed_block.candidate_adapted_json_sha256` is the
exact post-overlay digest. Both use the admin-UDS gate canonicalizer, not the
newline-terminated overlay plan/receipt encoding.

The three provider skeletons are separate closed profiles, not optional-field
variants. `provider-v1` retains its complete Standard Cashu inputs unchanged.
`provider-no-standard-cashu-v1` uses a distinct unit, service identity, state
directory, configuration root and activation sentinel. Its current policy must
omit every Standard Cashu offer and stay within the profile's adapter
material. The template and rendered gates reject retained-policy flags and
payloads. Current method coverage therefore checks the only configured policy;
there is no old-policy redemption route in this profile. Do not copy Cashu
custody, recovery or exposure fields into this plan.
`provider-direct-v1` has another distinct unit, identity, state/configuration
root and sentinel. Its nine payloads contain only the unified-server binary and
manifest, database config, provider identity key/certificate, signed policy,
and the owner-only remote rollback-authority config, client-signing seed and
value-root key. It has no BAT, Standard Cashu, shared-issuer,
ARC or Free-IP material. Current acquisition routes are limited to Free open-
best-effort, Free proof-of-work, provider-local Free anonymous tickets and direct
BOLT11 receipts. In this checked-in zero-retained profile the gate rejects retained
policies entirely. Startup method coverage rejects every other applicable
current route.

The three provider plans are mutually exclusive on one host. Each unit requires
the other two profile sentinels to be absent when it starts. Because systemd
conditions are not continuous revocation, a switch must stop and deauthorize
the old unit, prove it inactive with no listener on `8191`, then create exactly
one new profile sentinel and start only that unit.

Separate state roots do not make economic state disposable. For the same
logical provider, these zero-retained plans require issuance/admission to stop,
the longest old capability/grace horizon to expire, Standard Cashu custody to
be fully retired/reconciled, and all shared-issuer redeems to have known
outcomes. A separately reviewed transition record must establish that drain;
the static render plan cannot. Only then may a separately reviewed offline
ProviderStore migration that preserves the stable server ID, operator key and
derived provider ID, policy-signing key, provider identity certificate/key,
store-instance identity, spend and replay history, remote authority
instance/key, namespace, client-verifying-key identity, client-signing seed,
value-root key and floor before the new unit may
call `open_existing`. Re-render the TOML only with the new profile's canonical
secret paths. Rotating any authority-identity field requires a separately
reviewed migration ceremony; V1 has no online rebind or reset. If that
continuity is unavailable, use a
new provider/server identity and publish a distinct directory entry instead of
initializing a blank store and calling it a switch.

## Closed skeleton set

| File | Gate profile | Scope |
| --- | --- | --- |
| `bitcoin-core-signet-v1.plan.json.example` | `bitcoin-core-signet-v1` | Wallet-disabled, outbound-only default-Signet Core with exact bitcoind UID/primary GID 52928, distinct cookie GID 52929, cookie-only loopback RPC, threshold provenance receipt, seven-payload closure and a separate non-installable unit/sentinel lifecycle. |
| `directory-relay-v1.plan.json.example` | `directory-relay-v1` | One resolved, still sentinel-gated relay: config fixed to UID 52951/GID 52952/mode 0400, exact content-addressed binary, two root-owned one-entry hash manifests, and effective `ProtectProc=invisible` plus `ProcSubset=pid`. V2 stopped evidence still precedes activation; no publisher private key, start or publication authority. |
| `edge-hetzner-v1.plan.json.example` | `edge-hetzner-v1` | Public Caddy plus source-fair HAProxy edge. |
| `edge-rollback-authority-v1.plan.json.example` | `edge-rollback-authority-v1` | Sole-client private TLS edge for one rollback authority. |
| `issuer-lightning-signet-v1.plan.json.example` | `issuer-lightning-signet-v1` | Default-Signet CLN, RPC guard, preflight and payment issuer. |
| `provider-v1.plan.json.example` | `provider-v1` | One provider process and its complete Payment V1 material. |
| `provider-no-standard-cashu-v1.plan.json.example` | `provider-no-standard-cashu-v1` | Direct receipt, provider-local BAT and shared issuer, without Standard Cashu. |
| `provider-direct-v1.plan.json.example` | `provider-direct-v1` | Built-in Free subset and direct BOLT11 receipt, without optional payment-adapter material. |
| `rollback-authority-v1.plan.json.example` | `rollback-authority-v1` | One independent monotonic rollback authority. |

The directory-relay skeleton is intentionally weaker than an activation plan.
It binds the resolved selection source SHA-256 and requires exactly the selected
binary plus `binary.sha256` and `config.sha256`; all three private input paths
and both manifest-file digests remain invalid replacement markers. The binary
target/digest is fixed to the selected artifact. The live collector accepts
only the exact resolved profile, while stopped evidence must first prove the
`RELAY-SELECTION-RESOLVED` sentinel absent (so the three conditions are not all
satisfied) and the installed closure unchanged.
Installation, start, publisher-private-key use, routing and publication remain
separately approved actions. The fixed unit/NSS/config/state paths describe one
instance, and the selected `centralized-single-relay` mode is explicitly
degraded; it cannot silently downgrade or masquerade as strict multi-relay.

The separate `bhtm-caddy-admin-uds-v1.plan.json.example` is not a rendered
service profile and is not part of `payment-v1-rendered-artifact-gate.mjs`.
Its required companion
`bhtm-caddy-admin-uds-v1.site-inventory.json.example` demonstrates the exact
canonical inventory shape: at least one direct HTTP, public HTTPS and TLS-leaf
probe, sorted by ID and bound to the plan by its full SHA-256 and identical
`probe_ids`. Both files remain deliberately non-runnable skeletons.
It describes one stopped-service maintenance transaction for the exact existing
root `bhtm-caddy.service`. Its dedicated read-only gate deterministically
derives a hardened Caddyfile and unit from their exact preimages, canonicalizes
externally generated old and candidate adapted-JSON artifacts, rejects
configured log sinks, and binds both exact digest/size tuples. Before stop the
cold executor independently adapts the descriptor-read old bytes and requires
that digest to equal the live TCP-admin readback; it also requires the exact
loaded old Exec commands, fragment, `NeedDaemonReload=no`, and no drop-ins or
environment files. It is not itself a
rendered service profile; the separately source-hash-closed cold executor
performs the stop/start only with a privately materialized, externally
approved plan and site inventory. See
[`../CADDY_ADMIN_UDS_HARDENING.md`](../CADDY_ADMIN_UDS_HARDENING.md).
The read-only gate does not itself prove that Caddy generated the supplied
artifact; the cold executor runs the plan-pinned Caddy binary against the exact
candidate and compares the same tuple before mutation.
Its runtime closure includes the exact cold executor, admin-UDS gate, Node,
probe and `setpriv` binaries, exact systemd `255`, plus a
same-boot privileged process/capability inventory. The integrated-existing-Caddy
overlay skeleton separately pins both this canonical plan and its complete
committed receipt, the canonical adapted-JSON digest, and the fresh runtime
probe executables; a receipt summary alone is not sufficient. Its rendered
bundle also carries the exact admin-UDS executor, gate and probe sources. The executor
descriptor-pins the gate generation, reads its exact bytes once and supplies
those bytes with their reviewed SHA-256 on the probe's stdin; the probe verifies
that digest before a data-URL import, so it never resolves the gate by pathname.
The root-owned overlay executor statically imports both the admin-UDS gate and
overlay gate as part of its own exact full-source bootstrap TCB; those imports
are not claimed to be descriptor-loaded. Install the admin-UDS executor, gate
and probe before the cold admin-UDS transaction and pin their resulting
regular-file generations as `runtime.executor`, `runtime.gate` and
`runtime.probe` in the hardening
plan. The later overlay plan must repeat those exact full pins as
`runtime.admin_uds_gate` and `runtime.admin_probe`; replacing either installed
artifact after the hardening receipt requires a new cold hardening transaction
and receipt.

See [`../DEPLOYMENT_INPUT_MATRIX.md`](../DEPLOYMENT_INPUT_MATRIX.md) for the
non-secret input, failure-domain, approval and evidence register.

## Materialization procedure

1. From the frozen reviewed source commit, create an owner-only private work
   directory outside every Git worktree, cloud-synced folder and CI checkout.
   Set `umask 077`; require the directory to be owned by the deployment
   preparer's effective user with mode `0700` and no inherited/default ACL.
2. Copy exactly one skeleton into that directory as `plan.json`. Do not edit the
   repository example. Create a separate mode-`0700` private input root for the
   payload bytes.
3. Replace every `INVALID_REPLACE_...` or `INVALID-REPLACE-...` value and every
   example UID/GID. The render gate rejects either marker form in a payload
   `source_path`. Replace
   `deployment_id` with a unique, approved lowercase slug that is not reused by
   another plan, host generation or failure domain. Keep the exact top-level,
   service-identity, rendered-artifact and payload-artifact key sets. Keep the
   exact rendered `source_path`/`target_path` set for the selected profile. Do
   not add an artifact from another profile.
4. Stage every payload as a single-link regular file under its relative
   `source_path`. The plan contains no secret bytes and no real absolute input
   paths. Secret payloads remain owner-only and are never printed, uploaded to
   CI or copied into the rendered bundle review channel independently of its
   approved custody procedure.
5. Compute each template and payload SHA-256 from the exact staged bytes. Bind
   binary digest placeholders to the exact binary target path and closed hash
   manifest. Review canonical policy/config bytes before treating their digest
   as approved.
6. Validate the completed plan with a separately held candidate approval
   digest only after all semantic review is complete. Do not weaken the gate to
   accept a marker or a cross-profile dependency.

The materialized `plan.json`, its private input root and any rendered bundle
are deployment artifacts. **Do not commit them.** Add them neither to a branch
nor to an ad-hoc repository. Back them up only under the approved owner/access
policy for that failure domain.

## Canonical plan-digest ceremony

The approved digest is over the gate's strict parsed object encoded by
`canonicalJson`, not over the original whitespace or key order. From the frozen
repository root, the plan preparer may compute the candidate digest without
printing plan contents:

```sh
PLAN=/absolute/owner-only/plan.json
node --input-type=module --eval '
  import { readFileSync } from "node:fs";
  import {
    computeApprovedPlanSha256,
    parseStrictJson,
  } from "./scripts/payment-v1-rendered-artifact-gate.mjs";
  const plan = parseStrictJson(readFileSync(process.argv[1], "utf8"), "render plan");
  process.stdout.write(`${computeApprovedPlanSha256(plan)}\n`);
' "$PLAN"
```

Use this as a two-party ceremony:

1. the preparer freezes the exact source commit, private input inventory and
   complete materialized plan, computes the candidate digest, then makes the
   plan read-only;
2. an independently authorized reviewer obtains the exact plan through the
   approved private channel, reviews origins, pins, public keys, owners/modes,
   payment topology, artifact closure and failure domains, and recomputes the
   digest from a separate clean checkout of the frozen commit;
3. the reviewer records only `(deployment_id, deployment_profile, source
   commit, plan_sha256, approval scope, reviewer role/signing-key identifier,
   time)` in the external approval register and transfers the digest
   independently from the plan; and
4. rendering receives that externally approved digest through a separate
   argument. A digest computed and immediately trusted by the same render
   invocation is not external approval.

Schema-v1 `plan.json` deliberately has no `source_commit` field. The external
approval tuple above binds the exact commit and gate-script digest, while the
plan binds every selected template source hash and payload byte. Do not describe
the plan alone as proof of its source commit.

Example render/verify shape, shown only after the above ceremony:

```sh
node scripts/payment-v1-rendered-artifact-gate.mjs render \
  --source-root /absolute/frozen/source \
  --input-root /absolute/owner-only/private-inputs \
  --plan /absolute/owner-only/plan.json \
  --approved-plan-sha256 APPROVED_64_LOWER_HEX_SHA256 \
  --bundle /absolute/owner-only/rendered-bundle

node scripts/payment-v1-rendered-artifact-gate.mjs verify \
  --source-root /absolute/frozen/source \
  --input-root /absolute/owner-only/private-inputs \
  --plan /absolute/owner-only/plan.json \
  --approved-plan-sha256 APPROVED_64_LOWER_HEX_SHA256 \
  --bundle /absolute/owner-only/rendered-bundle
```

The command placeholders above are prose, not valid values. Use explicit shell
variables only after validating their exact non-broad paths; never place a
secret on the command line. Rendering and verification do not authorize
installation, service activation, public routing, relay publication, Signet
wallet/channel operations or real Lightning funds.

## Reviewer checklist

- No `INVALID_REPLACE_` or `INVALID-REPLACE-` marker or example UID/GID remains;
  `deployment_id` is a newly approved unique slug, not the repository example.
- Strict JSON has no duplicate keys, unknown keys, BOM or trailing data.
- The profile, rendered template set and installation targets equal the gate
  catalog byte-for-byte.
- Every relative private source resolves below the reviewed owner-only input
  root without a symlink or hard link.
- Every digest was recomputed from exact bytes; every binary digest agrees with
  its target path and hash manifest.
- Secret targets are owned by exactly one consuming service at mode `0400`.
- Origins, addresses, WebPKI/SPKI pins, provider/issuer/payee/mint public keys
  and signed policies agree across the plan and client/operator records.
- Provider 0 and provider 1 have no pair identifier or reused provider-specific
  key/state; shared issuer/payee use is an explicit privacy approval.
- Store and rollback-authority hosts, administrators and backup/restore domains
  are independent as claimed.
- The plan contains no invoice, payment hash/preimage, wallet seed, bearer
  credential, Cashu proof, query material, database contents, raw backup or
  external access credential.
- The canonical plan digest was recomputed independently and the materialized
  plan remains outside version control.
