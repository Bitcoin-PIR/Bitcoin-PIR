# Payment V1 private render-plan skeletons

Mainnet note (2026-08-18): an unmerged draft proposed a provider-specific
2/12/2 shared-BAT issuer/provider shape, which is now superseded. The currently
checked-in Mainnet issuer skeleton is an empty legacy V1 placeholder, and the
provider skeletons are older stateful V1 profiles. None may be completed or
rendered as the production BAT target. The replacement issuer-wide
acceptance-class and payment-storeless provider profiles are specified in
[`../MAINNET_SHARED_BAT_PRODUCTION_PLAN.md`](../MAINNET_SHARED_BAT_PRODUCTION_PLAN.md)
but do not exist yet.

The main Payment V1 render-plan skeletons mirror schema version `2` and the
closed profile catalog in `scripts/payment-v1-rendered-artifact-gate.mjs`.
The Caddy site-inventory and directory-publisher namespace prerequisite inputs
remain separate schema-version `1` catalogs; the publisher ceremony plan,
apply approval and rollback approval use schema version `2`. The deliberately
separate failed-start recovery approval/receipt use schema version `1` of their
own kinds and are valid only with the exact schema-v2 plan they name. All files
are review aids, not ready-to-render examples.

Every skeleton is deliberately unusable:

- every `source_sha256`, `expected_sha256` and digest/public-key placeholder is
  an invalid non-hex marker, except the public, committed relay-selection
  digest in the publisher skeleton;
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

The integrated existing-Caddy overlay plan carries two distinct adapted-JSON
pins. `target.admin_uds_hardening.adapted_json_sha256` is the exact live
hardened-preimage digest; `managed_block.candidate_adapted_json_sha256` is the
exact post-overlay digest. Both use the admin-UDS gate canonicalizer, not the
newline-terminated overlay plan/receipt encoding.

The three checked-in provider skeletons are separate V1 profiles, not
optional-field variants. `provider-v1` retains its complete Standard Cashu
inputs unchanged. `provider-no-standard-cashu-v1` is the older stateful,
single-Harmony-pool profile with provider-local BAT and shared-issuer inputs.
The server's independently re-landed exact-db multi-pool routing is available
as a source foundation, but the checked-in profile still configures one pool
and its payment shape is superseded. It is not the V2 payment-storeless pir1
profile, cannot be materialized for Mainnet, and must not be described as the
current production skeleton.
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

The revised Mainnet product still has one issuer and the two pir1/pir2 service
roles, but none of the current provider-specific skeletons is its closed
profile. The issuer will consume two policies, a reviewed nonzero set of
issuer-wide acceptance-class keysets, and two provider accounting/
authentication relationships. pir1 and pir2 will have no payment ProviderStore,
shared-idempotency secret or provider payment rollback client. pir2 will keep
distinct service-identity and clearing seeds only inside one measurement-bound
AEAD sealed envelope; the ordinary rootfs holds ciphertext and the measured
initramfs decrypts only into zeroizing process memory after the exact
derived-key and strict report-policy gates. That source path and its separately
authorized observation/reproduction boot, fresh-nonce/current-channel Boot-0
and exact-final-UKI two-reboot canary remain P1 work. Do not
solve them by completing the obsolete stateful skeleton or by embedding a
private key in the public UKI. No Direct receipt, Standard Cashu or ARC material
belongs in the replacement profile.

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

The old Mainnet Direct issuer needs the same explicit transition treatment.
Before materializing shared BAT, inventory every owner-only Direct plan/bundle,
installed unit, issuer/provider store and WAL/SHM, rollback namespace/floor,
identity/key lineage, CLN backup and outstanding quote/claim/recovery/capability
horizon. The empty checked-in Mainnet skeleton does not prove those private
artifacts never existed. If any exist, stop new issuance/admission and either
drain all horizons or retain the isolated exact old recovery runtime, stores,
floors, issuer root, network/payee and signing lineages until the last horizon.
Do not overwrite old state or pair old issuer history with an empty claim
namespace. The final drain, retention and destruction decision requires a
separately reviewed owner-only record; a skeleton cannot establish it.

## Closed skeleton set

| File | Gate profile | Scope |
| --- | --- | --- |
| `directory-relay-v1.plan.json.example` | `directory-relay-v1` | One resolved, still sentinel-gated relay: config fixed to UID 52951/GID 52952/mode 0400, exact content-addressed binary, two root-owned one-entry hash manifests, and effective `ProtectProc=invisible` plus `ProcSubset=pid`. V4 stopped-relay evidence still precedes activation; no publisher private key, start or publication authority. |
| `edge-hetzner-v1.plan.json.example` | `edge-hetzner-v1` | Public Caddy plus source-fair HAProxy edge. |
| `integrated-existing-bhtm-caddy-directory-public-v1.plan.json.example` | `integrated-existing-bhtm-caddy-directory-public-v1` | Non-activating isolated directory-read assets for the existing root Caddy process and the static HAProxy 2.8.26 candidate. It retains unsatisfied source-ready and generation-guard blockers; rendering does not provide their receipts or authorize activation. |
| `edge-rollback-authority-v1.plan.json.example` | `edge-rollback-authority-v1` | Sole-client private TLS edge for one rollback authority. |
| `directory-publisher-netns-v1.plan.json.example` | `directory-publisher-netns-v1` | One no-key publisher bound to the exact committed, resolved centralized relay selection and publisher key, plus a sealed route-less network namespace. |
| `publisher-netns-ceremony-v1.plan.json.example` | source-closed activation ceremony | Schema-v2 exact installed/runtime/Caddy/firewall/sentinel and loaded-systemd-generation preimages, content-addressed native launcher plus manifest, fixed private topology and owner-only transaction paths for starting only the namespace unit. |
| `publisher-netns-ceremony-v1.apply-approval.json.example` | short-lived apply authority | At-most-one-hour schema-v2 canonical plan/executor/launcher/manifest approval for starting only the exact namespace unit. |
| `publisher-netns-ceremony-v1.failed-recovery-approval.json.example` | separate failed-generation recovery authority | At-most-one-hour schema-v1 approval binding one durable start intent, its original activation approval and one complete terminal `failed/failed` InvocationID to the fixed `systemctl reset-failed` argv. A durable reset intent can survive approval expiry only under a fresh approval for the identical tuple, and its receipt preserves both approval digests. It grants no start, stop, restart or reload. |
| `publisher-netns-ceremony-v1.rollback-approval.json.example` | separate rollback authority | At-most-one-hour schema-v2 plan/executor/launcher/manifest/committed-receipt approval for stopping only the exact namespace unit. |
| `issuer-lightning-signet-v1.plan.json.example` | `issuer-lightning-signet-v1` | Default-Signet CLN, RPC guard, preflight and payment issuer. |
| `issuer-lightning-mainnet-v1.plan.json.example` | `issuer-lightning-mainnet-v1` | Deliberately empty, gate-rejected legacy V1 placeholder. It implements neither the unmerged 2/12/2 draft nor the approved V2 contract, cannot render or deploy, and must not be completed. A future V2 issuer-wide skeleton is not yet checked in. |
| `provider-v1.plan.json.example` | `provider-v1` | One provider process and its complete Payment V1 material. |
| `provider-no-standard-cashu-v1.plan.json.example` | `provider-no-standard-cashu-v1` | Older stateful, single-pool V1 profile with local-BAT/shared-issuer inputs. The server now has independently re-landed db0/db1 multi-pool routing, but this checked-in payment profile is not the issuer-wide production skeleton and must not be materialized for it. |
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

The directory-publisher skeleton independently pins the same committed
`deploy/payment-v1/relay-selection.toml.example` bytes. Rendering fails closed
unless that digest matches, the selection is `RESOLVED`, its mode is exactly
`centralized-single-relay`, and its `publisher_pubkey_hex` equals the plan's
`DIRECTORY_PUBLISHER_PUBKEY_HEX`. The rendered manifest carries the selection
source/digest, publisher key, mode, status, and the canonical credential-free
`wss://host` relay origin. The runtime request binds that manifest by digest,
so a later ceremony can cite this exact closure without trusting the unit's
command line as an independent relay-selection input.

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
loaded old Exec commands, fragment, `NeedDaemonReload=no`, exactly the pinned
one-way publisher-namespace drop-in, and no environment files. It is not itself a
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
