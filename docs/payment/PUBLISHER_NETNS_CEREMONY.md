# Publisher network-namespace activation ceremony

Status: source-complete, non-activating production preparation. This document
does not authorize an SSH session, installation, firewall mutation, Caddy
reload/restart, service start, DNS change, Nostr publication, private-key copy,
or creation/removal of an activation sentinel.

The ceremony in
`scripts/payment-v1-publisher-netns-ceremony.mjs` has one deliberately narrow
mutation on apply: it asks systemd to start exactly
`bitcoinpir-payment-v1-publisher-netns.service`. Its separately approved
rollback asks systemd to stop exactly that unit. It never starts, stops or
reloads Caddy, the directory publisher, source-fair edge, relay, issuer,
provider or payment services.

## Closed topology and trust boundary

```text
directory publisher (no signing key; inactive during this ceremony)
  namespace /run/netns/bpir-directory-publisher (nsfs)
  lo = 127.0.0.1/8
  bpir-pub-c = 10.203.0.2/30
       |
       | one transaction-branded veth pair
       | no default route; no gateway; no NAT; no forwarding
       |
  bpir-pub-h = 10.203.0.1/30
  existing host Caddy private publisher SNI :443 (unchanged)
```

The functional namespace interfaces are exactly `lo` and `bpir-pub-c`. Linux
may instantiate a subset of nine kernel fallback tunnel devices when their
modules are already loaded. The ceremony accepts only the same closed subset as
the reviewed native helper (`erspan0`, `gre0`, `gretap0`, `ip6_vti0`,
`ip6gre0`, `ip6tnl0`, `ip_vti0`, `sit0`, `tunl0`), with the exact reviewed
kind, down state, no address and no alias. Any other interface, or any usable
fallback tunnel, fails closed.

The namespace gets no production directory-publisher private key. The signing
key remains on the offline signing system. The host may later receive only the
frozen, already-signed public provider/checkpoint artifacts and the public
directory key needed to verify them. The plan recursively rejects publisher
private-key fields/values and payment/query correlation fields.

## Inputs that must already exist

Installation/rendering is a separate approved transaction. Before preparing a
ceremony plan, it must have installed and independently pinned:

- the content-addressed native helper and one-entry helper manifest;
- the exact namespace owner unit, publisher unit and one-way Caddy drop-in;
- the network policy and network-input manifest;
- the exact files-only name-service inputs under
  `/etc/netns/bpir-directory-publisher/`;
- the source-closed ceremony executor at
  `/usr/local/libexec/bitcoinpir/payment-v1-publisher-netns-ceremony.mjs`;
- its two exact sibling imports,
  `payment-v1-integrated-caddy-overlay-gate.mjs` and
  `payment-v1-publisher-netns-gate.mjs`, installed root-owned and pinned in
  the same plan;
- regular, no-follow `/usr/bin/node`, `/usr/bin/systemctl` and `/usr/bin/ip`;
- root-owned `0700` transaction parents
  `/var/lib/bitcoinpir/payment-v1/publisher-netns/receipts` and
  `/var/lib/bitcoinpir/payment-v1/publisher-netns/transactions`; and
- a root-owned `0700` evidence parent containing the owner-only canonical
  firewall evidence file.

Do not use `/usr/sbin/ip` in the plan. On reviewed Ubuntu/Debian releases it is
a symbolic link; the ceremony intentionally rejects it. `/usr/bin/ip` is the
no-follow regular executable pinned and invoked by descriptor.

All five activation sentinels are external authorization records. This
ceremony verifies their complete inode/metadata/content pins but never creates,
removes or changes them. The currently missing
`PUBLISHER-FIREWALL-GENERATION-GUARD-IMPLEMENTED` sentinel remains a separate
publisher-start blocker and must not be fabricated from point-in-time evidence.

## Firewall evidence

Collect the exact UFW/nft outputs using the command set documented in
`deploy/payment-v1/network/README.md`. First verify the directory, then emit
the same validated values as canonical JSON:

```sh
node scripts/payment-v1-publisher-netns-gate.mjs \
  verify-firewall-directory /absolute/review/firewall-output
node scripts/payment-v1-publisher-netns-gate.mjs \
  emit-firewall-json /absolute/review/firewall-output \
  > /absolute/staging/firewall.json
```

Installing that staged file as
`/var/lib/bitcoinpir/payment-v1/publisher-netns/evidence/firewall.json`, owner
`root:root`, mode `0400`, single link, is a separate deployment-plan action.
The ceremony re-parses and semantically validates the exact pinned bytes before
and after namespace start. It also verifies both host forwarding sysctls are
zero and both routing tables contain only the connected `10.203.0.0/30` route.
It does not install a rule or claim the point-in-time snapshot stayed unchanged
during a later publication.

The helper manifest must be one canonical `sha256sum` line binding the exact
content-addressed helper. The network-input manifest must canonically bind the
four pinned hosts, NSS, resolver and network-policy files. A plan cannot approve
manifest bytes that point at a different helper or network input.

## Plan and short-lived approvals

Start from the three inert skeletons:

- `publisher-netns-ceremony-v1.plan.json.example`;
- `publisher-netns-ceremony-v1.apply-approval.json.example`;
- `publisher-netns-ceremony-v1.rollback-approval.json.example`.

Replace every `INVALID_...` marker from two stable observations of the target.
Every file pin contains device, inode, uid, gid, mode, link count, size,
mtime/ctime nanoseconds and SHA-256. The plan also binds the current boot,
machine identity digest, exact systemd 255 version, Caddyfile and active Caddy
generation, its exact loaded one-way `Wants+After` drop-in relation with no
reverse stop edge or pending daemon reload, inactive publisher/netns
generations with no pending daemon reload, fixed topology, source commit,
runtime executables and transaction paths. The executor's local import
closure is exactly the two sibling gates above; both are runtime pins and are
re-read before and after namespace mutation.

The independently reviewed digest is SHA-256 over canonical JSON, not the
whitespace of the source file. A reviewer can calculate it without trusting the
installed executor:

```sh
node --input-type=module -e '
  import {createHash} from "node:crypto";
  import {readFileSync} from "node:fs";
  import {canonicalJson,parseStrictJson} from "./scripts/payment-v1-integrated-caddy-overlay-gate.mjs";
  const p=process.argv[1];
  const v=parseStrictJson(readFileSync(p,"utf8"),"publisher netns plan");
  process.stdout.write(createHash("sha256").update(canonicalJson(v)).digest("hex")+"\n");
' /absolute/review/publisher-netns.plan.json
```

Apply and rollback approvals are different documents. Each binds the canonical
plan digest, exact executor digest, ceremony ID, reviewer identity, exact
acknowledgement list and a whole-second UTC validity interval of at most one
hour. Rollback additionally binds the SHA-256 of the exact committed receipt
bytes. Approval-document digests are likewise over canonical JSON. A future or
expired approval, more than five minutes of negative clock skew, or any field
drift fails before the lock or systemd mutation.

## Required activation order

1. Complete the separately reviewed installation/render transaction and
   `daemon-reload`. Keep Caddy on its pinned preimage; keep the directory
   publisher inactive.
2. Independently verify absence of `/run/netns/bpir-directory-publisher` and
   `bpir-pub-h`, the exact inactive unit preimages and absence of a publisher
   private key.
3. Install/review the external sentinels and validated firewall evidence under
   their separate authorities. Do not create the publication-only firewall
   generation sentinel.
4. Produce the closed plan from two stable target observations. Compute and
   transfer its canonical digest independently.
5. Produce a fresh apply approval no longer than one hour and independently
   transfer its canonical digest.
6. Run read-only validation on the target:

   ```sh
   sudo /usr/bin/node \
     /usr/local/libexec/bitcoinpir/payment-v1-publisher-netns-ceremony.mjs \
     validate-plan \
     --plan /absolute/review/publisher-netns.plan.json \
     --approved-plan-sha256 PLAN_SHA256 \
     --approved-source-sha256 EXECUTOR_SHA256
   ```

7. Run apply with the same plan/digests and the absolute approval path:

   ```sh
   sudo /usr/bin/node \
     /usr/local/libexec/bitcoinpir/payment-v1-publisher-netns-ceremony.mjs \
     apply \
     --plan /absolute/review/publisher-netns.plan.json \
     --approved-plan-sha256 PLAN_SHA256 \
     --approved-source-sha256 EXECUTOR_SHA256 \
     --approval /absolute/review/publisher-netns.apply-approval.json \
     --approved-approval-sha256 APPLY_APPROVAL_SHA256
   ```

8. Independently transfer and verify the owner-only receipt. It binds both the
   approval that authorized `systemctl start` and, after crash recovery, the
   fresh approval that authorized terminalization; exact Caddy/publisher
   preimages; all installed/runtime/sentinel pins; firewall evidence; systemd
   generation; nsfs inode; veth indices/MACs/transaction aliases; loopback;
   inert fallback subset; connected routes; and forwarding sysctls.
9. A later integrated-Caddy overlay plan must bind this exact committed receipt
   as a prerequisite. The ceremony itself does not modify or reload Caddy.
10. Only after the integrated overlay, fresh edge/runtime evidence, a reviewed
    firewall-generation guard and a distinct publication approval may the
    one-shot publisher be considered. This ceremony grants no Nostr write.

The Caddy dependency is intentionally one-way: Caddy has only `Wants=` and
`After=` toward the namespace. Namespace teardown cannot stop the shared Caddy
process. The publisher has `Requires=`/`BindsTo=` toward the namespace and
therefore cannot outlive it.

## Atomicity, idempotency and crash recovery

The root-only lock records boot ID, PID and `/proc/<pid>/stat` start ticks.
`recover-*` can reclaim only one exact owner record whose process generation is
dead; an empty, malformed, linked, foreign or live lock fails closed for manual
review.

State and receipts are canonical owner-only records. Publication uses an
exclusive pending inode, fsync, no-replace hard link, parent fsync, pending
unlink and a second parent fsync. Recovery handles both durable crash windows:
a valid pending-only record and a final+pending two-link inode. Contradictory
bytes, owners, modes, links or inodes are never normalized. Transaction
directories accept only the six reviewed phase filenames and their pending
counterparts.

Plain `apply` refuses an already-active namespace. If the systemctl response
was lost after the durable `05-start-intent.json`, run `recover-commit` with a
currently valid approval. Recovery requires that exact start intent, verifies
the live topology, retains the original activation-approval digest in the
receipt and records the fresh terminalization approval separately. It does not
call `systemctl start` again. If there is no durable start intent, it refuses to
adopt the namespace.

An exact committed replay revalidates the live unit generation, topology,
Caddy/publisher state and every closed input before returning the prior receipt.
It never treats a historical receipt as current runtime evidence.

## Rollback order

Rollback is deliberately not automatic and never consumes the apply approval.
Before preparing a fresh rollback approval:

1. ensure the directory publisher is inactive;
2. if an integrated Caddy overlay was applied, roll that transaction back to
   the exact Caddyfile preimage first;
3. verify Caddy's process generation is still the one bound by the ceremony;
4. hash the exact committed receipt bytes; and
5. issue the separate receipt-bound rollback approval, valid for at most one
   hour.

Run:

```sh
sudo /usr/bin/node \
  /usr/local/libexec/bitcoinpir/payment-v1-publisher-netns-ceremony.mjs \
  rollback \
  --plan /absolute/review/publisher-netns.plan.json \
  --approved-plan-sha256 PLAN_SHA256 \
  --approved-source-sha256 EXECUTOR_SHA256 \
  --rollback-approval /absolute/review/publisher-netns.rollback-approval.json \
  --approved-rollback-approval-sha256 ROLLBACK_APPROVAL_SHA256 \
  --approved-receipt-sha256 COMMITTED_RECEIPT_SHA256
```

It stops only the namespace unit, verifies the unit is inactive and both the
named nsfs path and owned host veth are absent, proves Caddy/publisher unchanged,
then atomically publishes a rollback receipt. Plain rollback refuses an
already-stopped namespace; `recover-rollback` reconciles a lost stop response
without issuing a second stop only when the exact receipt-bound durable stop
intent already exists. The rollback receipt preserves both the approval that
authorized the stop and the fresh approval that terminalized recovery. An
inactive namespace without that intent is external/unknown state and fails
closed. A Caddy/config/process generation change or an active publisher forbids
this narrow rollback and requires a separately reviewed incident/cold-edge
procedure.

## Reboot semantics

The namespace unit has no `[Install]` target. After initial activation, the
persistent external sentinels plus the Caddy drop-in cause systemd to recreate
the namespace before a boot-time Caddy start. The overlay's private bind then
makes Caddy startup fail if the namespace could not be created. Caddy stop or
restart may stop the namespace through the namespace unit's `PartOf=` relation;
the reverse stop edge does not exist.

The ceremony receipt is intentionally scoped to one boot and one systemd/nsfs
generation. It remains provenance after reboot, not proof of the new runtime.
After every reboot, collect fresh standard runtime evidence before publication.
The narrow receipt-bound rollback is intentionally unavailable after a Caddy or
boot generation change; use the reviewed cold-edge/deauthorization procedure,
not a stale receipt or an ad-hoc `systemctl` command.

## Failure matrix

| Phase/failure | Mutation possible | Required recovery |
| --- | --- | --- |
| Plan, source, runtime pin, sentinel, firewall or Caddy preflight fails | None | Correct the external input; create a new plan/approval when any pin changes. |
| Lock exists with a live/unknown owner | None | Wait for the exact process or perform manual forensic review; never delete by name alone. |
| Start command returns nonzero | Helper may have journaled partial kernel work; no ceremony receipt | Inspect the unit/helper journal. Use the unit's exact cleanup path under a separate operator action; then regenerate preimage evidence. |
| Start response is lost but durable start intent and exact topology exist | Namespace active; no receipt | Run `recover-commit` with a fresh valid approval. |
| Active namespace has no exact start intent | Unknown | Fail closed; do not adopt or publish a receipt. |
| Runtime interface/address/route/sysctl/nsfs/Caddy/input or boot/systemd identity verification fails | Namespace may be active or stopped; no new receipt | Keep publisher/Caddy overlay inactive; investigate and explicitly clean up under the cold incident procedure. |
| Receipt pending/final publication is interrupted | Verified namespace may be active | Repeat `recover-commit`; exact pending inode recovery is idempotent. |
| Caddy/publisher changes during apply | Namespace may be active; no receipt | Stop advancement and use the reviewed cold-edge/cleanup procedure. |
| Rollback stop returns nonzero | Committed receipt and durable stop intent remain authoritative | Investigate the exact unit. If its committed generation is still active, a fresh approval may run explicit `recover-rollback`; otherwise use the cold incident procedure. Do not publish a rollback receipt until absence is proven. |
| Stop response is lost, durable stop intent exists and topology is absent | Namespace stopped; no rollback receipt | Run `recover-rollback` with a fresh valid receipt-bound approval; the receipt preserves both approval digests. |
| Namespace is inactive but the exact durable stop intent is absent or drifted | Unknown external stop | Fail closed; do not adopt the state or publish a rollback receipt. |
| Caddy generation/config or publisher changed before rollback | No rollback mutation | Undo overlay/stop publisher first; generation drift requires a separate cold incident procedure. |
| Reboot | systemd may recreate namespace before Caddy | Treat old receipt as provenance only; collect new-boot runtime evidence. |

## Tests and remaining production blockers

Pure Node tests cover canonical plans, RFC1918/ULA validation, expired and
overlong approvals, active/adopt refusal, lost-response recovery, Caddy and
firewall drift, veth identity, route/forwarding/interface negatives, receipt
idempotency, boot/systemd identity drift across start and stop, separate
rollback authority and both receipt crash windows.
Privileged disposable-Linux tests execute pinned command descriptors across a
real network namespace and exercise the native helper's setup, monitoring,
fault injection and exact cleanup.

Passing them does not remove these deployment gates:

- reviewed/merged source and exact target-specific installed pins;
- explicit approval to mutate the Hetzner host and to start this exact unit;
- exact target UFW/nft evidence and the still-unimplemented continuous or
  pre/post publication firewall-generation guard;
- approved private publisher SNI/SAN, integrated-Caddy overlay receipt and
  stopped/fresh edge evidence;
- independently verified absence of the production publisher signing key from
  the host; and
- a distinct approval for any Caddy lifecycle action, directory publication,
  remote deployment or production key use.
