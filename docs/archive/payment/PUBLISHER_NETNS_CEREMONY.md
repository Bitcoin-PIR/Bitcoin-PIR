# Publisher network-namespace activation ceremony (archived)

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
provider or payment services. A third authority exists only after a failed
start: it may clear one approved terminal `failed/failed` InvocationID with the
fixed argv `systemctl reset-failed bitcoinpir-payment-v1-publisher-netns.service`.
It is neither implicit apply authority nor a wildcard systemd repair action.

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
- its three exact sibling imports,
  `payment-v1-integrated-caddy-overlay-gate.mjs` and
  `payment-v1-publisher-netns-gate.mjs`, plus the no-cycle
  `payment-v1-publisher-netns-schema.mjs` validator, installed root-owned and
  pinned in the same plan;
- the source-closed private ingress probe at
  `/usr/local/libexec/bitcoinpir/payment-v1-publisher-private-health-probe.mjs`;
- the independently compiled, statically linked, content-addressed native launcher at
  `/opt/bitcoinpir/publisher-netns-launcher/<launcher-sha256>/payment-v1-publisher-netns-launcher`;
- the exact seven-entry, root-owned `0444` launcher manifest at
  `/etc/bitcoinpir/payment-v1/publisher-netns/launcher-inputs.sha256`, in this
  canonical order: `/usr/bin/node`, integrated-Caddy gate, ceremony executor,
  publisher-netns gate, shared schema validator, private health probe, Node
  loader-closure manifest;
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
removes or changes them. The separate
`PUBLISHER-LIVE-FIREWALL-LINEAGE-IMPLEMENTED` publication condition is
intentionally unavailable. The continuous owner guard exists, but the required
owner-pre-READY live semantic lineage does not; never fabricate that condition
from point-in-time evidence.

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
It does not install a rule. The owner opens the host nftables multicast monitor
and takes `/run/xtables.lock` before namespace mutation; it reaches READY only
after a final stop/firewall/child/topology barrier and retains the lock/monitor
until owner exit. This closes generation drift after subscription, but does not
prove that the earlier evidence file equals the live generation at subscription
time. Publication stays blocked until live semantics are re-collected after the
lock/subscription and bound to owner InvocationID, boot, rule digest and the
publication approval before READY. Planned UFW/iptables/nftables maintenance
must stop and deauthorize the owner first.

The captured UFW base/before chains deliberately include Ubuntu's stateful
`RELATED,ESTABLISHED` accept exception. Every IPv4/IPv6 INPUT/FORWARD before
chain must contain exactly one such rule before its user-chain jump. The
optional IPv4 INPUT allowlist additionally permits loopback, selected ICMP
error/echo-request, DHCP client UDP 67-to-68, mDNS `224.0.0.251:5353` and SSDP
`239.255.255.250:1900` accepts; IPv4 FORWARD may additionally contain only the
selected ICMP accepts. The optional IPv6 INPUT allowlist permits loopback,
selected ICMPv6/ND/MLD compatibility forms, DHCPv6 UDP 547-to-546, mDNS
`[ff02::fb]:5353` and the reviewed UFW SSDP destination `[ff02::f]:1900`;
IPv6 FORWARD may additionally contain only selected ICMPv6 control accepts.
When present, these rules may accept
matching packets before the interface-wide user deny. The exact user-chain
allow-then-deny pair controls a new `10.203.0.2 -> 10.203.0.1:443` TCP flow
that reaches it; it is not a claim that every other packet class reaches that
pair. Both forwarding directions, NAT, the namespace default route and host
forwarding remain closed and independently evidence-bound.

The helper manifest must be one canonical `sha256sum` line binding the exact
content-addressed helper. The network-input manifest must canonically bind the
four pinned hosts, NSS, resolver and network-policy files. A plan cannot approve
manifest bytes that point at a different helper or network input.

Build the launcher on reviewed Linux and install only its content-addressed
static result; the following is a build recipe, not deployment authority:

```sh
cc -std=c11 -O2 -static -Wall -Wextra -Werror \
  scripts/payment-v1-publisher-netns-launcher.c \
  -o /absolute/staging/payment-v1-publisher-netns-launcher
ldd /absolute/staging/payment-v1-publisher-netns-launcher 2>&1 |
  grep -E 'not a dynamic executable|statically linked'
sha256sum /absolute/staging/payment-v1-publisher-netns-launcher
```

Create `launcher-inputs.sha256` with ordinary `sha256sum` output in the exact
seven-path order listed above. Its bytes and its SHA-256 are independent review
inputs; the launcher accepts neither reordered nor additional entries.

`ldd` is only an operator convenience. The schema-v2 plan additionally binds a
machine-parsed ELF64 little-endian `ET_EXEC` record: exact launcher SHA-256,
`EM_X86_64`, bounded program-header count, and explicit absence of both
`PT_INTERP` and `PT_DYNAMIC`. `inspectStaticElfV1()` in the shared validator
derives that record from the same launcher bytes, and the ceremony recomputes
it from the pinned file before mutation.

After the launcher's final manifest identity recheck, Node and all five local
modules are executed from already-open, hash-verified descriptors. A fixed
`vm.SourceTextModule` loader permits only those sealed file URLs and Node
built-ins; it never reopens the entrypoint or a local import by pathname. All
other inherited descriptors are marked close-on-exec, and the bootstrap closes
the five intentional module descriptors after reading them.

The only launcher subcommand that changes network namespaces is the fixed
`publisher-private-health-probe` shape. Before `setns(CLONE_NEWNET)`, the
launcher descriptor-opens `/run/netns/bpir-directory-publisher` and requires
its nsfs device/inode to equal the committed ceremony receipt; it then proves
the current namespace has the same identity. The sealed probe performs an
ordinary WebPKI/SNI TLS validation against the host OpenSSL CA store (selected
by the launcher's fixed `--use-openssl-ca` flag), an independently pinned
leaf-certificate SHA-256 check, and a bounded RFC 6455 upgrade check. CA-store
drift can deny availability but cannot substitute a different leaf because the
full leaf DER digest is checked after WebPKI. A disposable privileged
E2E proves that the same request receives 404 from the host namespace and 101
only after this receipt-bound transition.

The lifecycle lock is also shared with the Caddy-admin UDS cold transaction.
Explicit publisher recovery may replace only a dead owner record for the exact
same publisher transaction ID; it refuses a dead foreign/Admin owner. This
preserves an Admin transaction's deliberately retained outcome-unknown lock.

## Plan and short-lived approvals

Start from the four inert skeletons:

- `publisher-netns-ceremony-v1.plan.json.example`;
- `publisher-netns-ceremony-v1.apply-approval.json.example`;
- `publisher-netns-ceremony-v1.failed-recovery-approval.json.example`; and
- `publisher-netns-ceremony-v1.rollback-approval.json.example`.

Replace every `INVALID_...` marker from two stable observations of the target.
Every file pin contains device, inode, uid, gid, mode, link count, size,
mtime/ctime nanoseconds and SHA-256. The plan also binds the current boot,
machine identity digest, exact systemd 255 version, Caddyfile and active Caddy
`active/running` generation with nonzero `MainPID`, `InvocationID` and
activation timestamp, its exact loaded one-way `Wants+After` relation with no
reverse stop edge or pending daemon reload, inactive publisher/netns
generations with no pending daemon reload, fixed topology, source commit,
runtime executables and transaction paths. The executor's local import
closure is exactly the two sibling gates above; both are runtime pins and are
re-read before and after namespace mutation. Plan schema v2 additionally binds
the loaded namespace unit, the current PID 1/systemd manager generation, the
native launcher and its exact manifest. Apply and rollback approval schema v2
bind both launcher digests. Legacy schema-v1 documents using the apply,
rollback or committed-receipt kinds are invalid and must never be migrated or
replayed as v2 authority. The distinct failed-recovery approval/receipt v1
kinds are not legacy apply authority and are accepted only with the exact
schema-v2 plan they name.

The launcher first hashes its own `/proc/self/exe` and requires both the
independently approved launcher digest and its exact content-addressed path. It
then verifies the approved manifest, opens and hashes Node, the executor and
both imports before Node can load any JavaScript. The production build must be
static so a dynamic loader cannot act on `LD_PRELOAD` before `main`; the test
harness checks this. The launcher rejects Node, shell and dynamic-loader
influence variables, rechecks every descriptor/path identity, clears the
environment and executes the pinned Node descriptor. Production ceremony
commands must go through this launcher; direct `sudo /usr/bin/node ...` is
test-only and is not an approved operator path.

Continuous namespace-owner runtime evidence also reads the effective
`UnsetEnvironment` property and requires the exact reviewed removal set for
shell, dynamic-loader and Node injection variables. A correct fragment on disk
is insufficient if the loaded property or daemon generation has drifted.

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

Apply, failed-start recovery and rollback approvals are different documents.
Apply and rollback each bind the canonical
plan digest, exact executor digest, ceremony ID, reviewer identity, exact
acknowledgement list and a whole-second UTC validity interval of at most one
hour. Rollback additionally binds the SHA-256 of the exact committed receipt
bytes. A failed-start recovery approval can be prepared only after observing a
terminal failure. It additionally binds the exact bytes of the durable
`05-start-intent.json`, the original activation-approval digest, and the full
failed unit snapshot: nonzero InvocationID, `failed/failed`, `MainPID=0`,
nonzero inactive/state-change monotonic timestamps, exact `Result`,
`ExecMainCode`/`ExecMainStatus`, loaded fragment generation and fixed reset
argv. Approval-document digests are likewise over canonical JSON. A future or
expired approval, more than five minutes of negative clock skew, or any field
drift fails before the lock or systemd mutation.

## Required activation order

1. Complete the separately reviewed installation/render transaction and
   `daemon-reload` while the publisher-netns activation sentinel is absent.
   This loads the exact Caddy `Wants+After` drop-in without allowing it to
   start the namespace. Keep the directory publisher inactive.
2. Complete the schema-v2 Caddy admin-UDS cold transaction and retain its
   committed receipt. Independently prove the publisher namespace remained
   inactive. The
   later namespace ceremony must bind that exact hardened Caddy
   PID/InvocationID/config generation.
3. Independently verify absence of `/run/netns/bpir-directory-publisher` and
   `bpir-pub-h`, the exact inactive unit preimages and absence of a publisher
   private key.
4. Install/review the external sentinels and validated firewall evidence under
   their separate authorities. Do not create the publication-only firewall
   generation sentinel.
5. Produce the closed plan from two stable target observations. Compute and
   transfer its canonical digest independently.
6. Produce a fresh apply approval no longer than one hour and independently
   transfer its canonical digest.
7. Run read-only validation on the target:

   ```sh
   sudo /opt/bitcoinpir/publisher-netns-launcher/LAUNCHER_SHA256/payment-v1-publisher-netns-launcher \
     --approved-launcher-sha256 LAUNCHER_SHA256 \
     --approved-manifest-sha256 LAUNCHER_MANIFEST_SHA256 -- \
     validate-plan \
     --plan /absolute/review/publisher-netns.plan.json \
     --approved-plan-sha256 PLAN_SHA256 \
     --approved-source-sha256 EXECUTOR_SHA256
   ```

8. Run apply with the same plan/digests and the absolute approval path:

   ```sh
   sudo /opt/bitcoinpir/publisher-netns-launcher/LAUNCHER_SHA256/payment-v1-publisher-netns-launcher \
     --approved-launcher-sha256 LAUNCHER_SHA256 \
     --approved-manifest-sha256 LAUNCHER_MANIFEST_SHA256 -- \
     apply \
     --plan /absolute/review/publisher-netns.plan.json \
     --approved-plan-sha256 PLAN_SHA256 \
     --approved-source-sha256 EXECUTOR_SHA256 \
     --approval /absolute/review/publisher-netns.apply-approval.json \
     --approved-approval-sha256 APPLY_APPROVAL_SHA256
   ```

   Both pre-start closure passes bracket the exact inactive unit and absent
   nsfs/veth proof with `Unit.Job` absence checks. The second pass occurs after
   the durable start intent and immediately before the sole start request, so a
   previously queued PID 1 job cannot be attributed to this ceremony.

9. Independently transfer and verify the owner-only receipt. It binds both the
   approval that authorized `systemctl start` and, after crash recovery, the
   fresh approval that authorized terminalization; exact Caddy/publisher
   preimages; all installed/runtime/sentinel pins; firewall evidence; systemd
   generation; nsfs inode; veth indices/MACs/transaction aliases; loopback;
   inert fallback subset; connected routes; and forwarding sysctls.
10. A later integrated-Caddy overlay plan must bind both the exact admin-UDS
    receipt and this exact namespace receipt, and prove the namespace ceremony
    occurred on the same hardened Caddy generation, before any Caddy change.
    The ceremony itself does not modify or reload Caddy.
11. Even after the integrated overlay and fresh edge/runtime evidence, the
    one-shot publisher remains blocked. A separately reviewed implementation
    must close owner-pre-READY live firewall semantic lineage and remove the
    policy blocker before a distinct publication approval may be considered.
    This ceremony grants no Nostr write.

The Caddy dependency is intentionally one-way: Caddy has only `Wants=` and
`After=` toward the namespace. Namespace teardown cannot stop the shared Caddy
process. The publisher has `Requires=`/`BindsTo=` toward the namespace and
therefore cannot outlive it.

## Atomicity, idempotency and crash recovery

The root-only lock records a canonical nonzero boot UUID, positive safe-integer
PID and canonical positive `/proc/<pid>/stat` start ticks; malformed owner
fields are never interpolated into a `/proc` path.
`recover-*` can reclaim only one exact authoritative owner record whose process
generation is dead. A malformed authoritative owner, linked/foreign/live owner
or unknown directory shape fails closed for manual review. The sole exception
is one exact root-owned `0400`, single-link `owner.json.pending` with empty or
strict-JSON-malformed bytes: that name is unpublished authority, so recovery
may remove only its twice-revalidated inode generation and retry. A concurrent
writer whose partial inode is removed must fail its later pathname/link proof;
it cannot proceed as a second holder.

State and receipts are canonical owner-only records. Publication uses an
exclusive pending inode, fsync, no-replace hard link, parent fsync, pending
unlink and a second parent fsync. The pending inode write loops until every byte
is written and rejects zero, negative or otherwise invalid short-write results.
Recovery handles both durable crash windows:
a valid pending-only record and a final+pending two-link inode. Contradictory
bytes, owners, modes, links or inodes are never normalized. Transaction
directories accept only the eight reviewed phase filenames and their pending
counterparts. A real Linux SIGKILL test stops owner publication after a partial
write and proves explicit recovery converges without adopting those bytes.

Plain `apply` refuses an already-active namespace. If the systemctl response
was lost after the durable `05-start-intent.json`, run `recover-commit` with a
currently valid approval. Recovery requires that exact start intent, verifies
the live topology, retains the original activation-approval digest in the
receipt and records the fresh terminalization approval separately. It does not
call `systemctl start` again. If there is no durable start intent, it refuses to
adopt the namespace.

Once `systemctl start` has been requested, a thrown error, timeout, nonzero
status or later receipt-proof failure is outcome-unknown and deliberately keeps
the shared lifecycle lock. Only same-transaction `recover-commit` may replace
its dead owner. If the start activated late, recovery verifies that exact live
generation and terminalizes the receipt without a second start. If it did not
activate, recovery may release the lock only after repeated proof that PID 1
has no pending unit job, the unit equals the plan's `inactive/dead` generation
with `NeedDaemonReload=no`, the nsfs path and host veth are absent, and all five
external sentinels still have the plan-bound bytes and metadata. Any pending
job, late activation during that proof, sentinel drift or unknown state keeps
the lock for further explicit recovery.

Real `Type=notify` and `ExecStart` timeouts commonly terminate as
`ActiveState=failed`, `SubState=failed`, `MainPID=0` while retaining a nonzero
InvocationID. That state is never treated as the inactive plan preimage and an
ordinary apply approval cannot clear it. Collect the complete failed snapshot
twice, hash the durable start intent, and issue a fresh
`publisher-netns-failed-recovery-approval-v1` for exactly that tuple. Recovery
then proves no PID 1 job, exact failed InvocationID, `MainPID=0`, absent nsfs
and host veth, unchanged boot/manager/Caddy/publisher/loaded-unit generation,
and unchanged installed/runtime/sentinel/firewall inputs. Immediately before
mutation it durably writes `06-reset-failed-intent.json` and invokes only:

```text
/usr/bin/systemctl reset-failed bitcoinpir-payment-v1-publisher-netns.service
```

Afterwards it repeats no-job, exact `inactive/dead`, no-process-generation,
absent-topology and closed-input proofs before atomically writing the dedicated
failed-recovery receipt and `07-failed-start-recovered.json`. A lost reset
response is idempotent: an exact inactive terminal state is adopted only when
that exact reset intent already exists and binds its first recovery approval,
the start intent, original activation approval and failed-unit digest. If that
short-lived approval expires after the intent is durable, a fresh approval may
continue only when it independently binds the same complete tuple; it cannot
replace or broaden the existing intent. The receipt records both
`reset_intent_approval_sha256` (the approval authorizing the first mutation
attempt) and `approved_recovery_approval_sha256` (the currently valid approval
that proved and published the terminal result). Otherwise the shared lifecycle
lock remains retained. A different InvocationID, pending job, surviving
namespace/interface, changed sentinel or missing intent never causes a reset.
Receipt replay revalidates that durable intent and restores a missing
`07-failed-start-recovered.json` after the receipt-to-state crash window; it
does not issue another reset.

The recovery invocation deliberately reuses the `--approval` transport name,
but its document kind is distinct and accepted only by `recover-commit`:

```sh
sudo /opt/bitcoinpir/publisher-netns-launcher/LAUNCHER_SHA256/payment-v1-publisher-netns-launcher \
  --approved-launcher-sha256 LAUNCHER_SHA256 \
  --approved-manifest-sha256 LAUNCHER_MANIFEST_SHA256 -- \
  recover-commit \
  --plan /absolute/review/publisher-netns.plan.json \
  --approved-plan-sha256 PLAN_SHA256 \
  --approved-source-sha256 EXECUTOR_SHA256 \
  --approval /absolute/review/publisher-netns.failed-recovery-approval.json \
  --approved-approval-sha256 FAILED_RECOVERY_APPROVAL_SHA256
```

An exact committed replay requires no pending PID 1 job and revalidates the
live unit generation, topology, Caddy/publisher state and every closed input
before returning the prior receipt.
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
sudo /opt/bitcoinpir/publisher-netns-launcher/LAUNCHER_SHA256/payment-v1-publisher-netns-launcher \
  --approved-launcher-sha256 LAUNCHER_SHA256 \
  --approved-manifest-sha256 LAUNCHER_MANIFEST_SHA256 -- \
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
| Start command errors, times out or returns nonzero after durable intent | Helper/PID 1 may activate late, terminate `failed/failed`, or have partial kernel work; no ceremony receipt; shared lifecycle lock retained | Run same-transaction `recover-commit`. It terminalizes an exact late-active generation. Exact-inactive recovery uses repeated no-job/absence/input proof. Terminal `failed/failed` additionally requires a fresh approval binding the exact InvocationID, failed snapshot, durable start intent and original activation approval before fixed-argv `reset-failed`. |
| Failed recovery has a different InvocationID, PID 1 job, MainPID, topology, input generation or missing/mismatched reset intent | None, unless a prior exact reset response was lost; shared lifecycle lock retained | Fail closed and investigate. Never issue a wildcard or manually broadened `reset-failed`; prepare a new approval only for a separately proven same start attempt. |
| `reset-failed` response is lost or its approval expires after durable reset intent | Unit may already be exact `inactive/dead`, or remain the exact approved `failed/failed` generation; no failed-recovery receipt; shared lifecycle lock retained | Repeat `recover-commit` with the same still-valid approval or a fresh approval binding the identical start/activation/failed-generation tuple. The durable intent is never replaced; an already-inactive result is proved and adopted without resetting twice. |
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
rollback authority and both receipt crash windows. The failed-start mocks use
the real systemd 255 `failed/failed`, nonzero InvocationID, `MainPID=0`,
`Result=timeout`, signal code/status shape and prove exact-generation approval,
pending-job/topology refusal, fixed reset argv, lost-reset-response recovery
and dedicated receipt replay.
Privileged disposable-Linux tests execute pinned command descriptors across a
real network namespace and exercise the native helper's setup, monitoring,
fault injection and exact cleanup. They also require exclusive xtables-lock
ownership, inject a direct nftables generation change, and require owner
failure before exact cleanup. The exact systemd-255 PID-1 test proves guard
failure before READY, during publisher execution and after retained oneshot
success.
The native launcher harness also proves that a tampered imported module,
malicious `NODE_OPTIONS` and an `LD_PRELOAD` constructor are rejected before
any payload can execute.
A separate disposable Ubuntu 24.04 `CAP_NET_ADMIN` harness applies the exact UFW
rules, reloads UFW, captures raw iptables/nftables state twice and requires the
semantic firewall gate to accept both generations.

Passing them does not remove these deployment gates:

- reviewed/merged source and exact target-specific installed pins;
- explicit approval to mutate the Hetzner host and to start this exact unit;
- exact target UFW/nft evidence, an available root-owned single-link
  `/run/xtables.lock`, and no concurrent firewall manager during namespace
  activation;
- approved private publisher SNI/SAN, integrated-Caddy overlay receipt and
  stopped/fresh edge evidence;
- independently verified absence of the production publisher signing key from
  the host; and
- a distinct approval for any Caddy lifecycle action, directory publication,
  remote deployment or production key use.
