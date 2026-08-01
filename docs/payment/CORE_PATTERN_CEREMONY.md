# Payment V1 host core-diagnostic ceremony v2

Status: implemented and tested, but not approved, materialized, installed, or run
on a production host. This document is not host-mutation authority.

kernel.core_pattern, fs.suid_dumpable, and kernel.core_pipe_limit are
host-global. The ceremony is separate from every Caddy, edge, relay, and
Payment V1 service transaction. Apply, recovery, and rollback each require a
fresh, exact, digest-bound risk approval.

## Why v1 was rejected

Ubuntu Noble Apport 2.28.2 data/apport lines 693-709 performs these ordered
writes:

- start: Apport pipe handler, fs.suid_dumpable=2, core_pipe_limit=10;
- stop: core_pipe_limit=0, fs.suid_dumpable=0, core_pattern=core.

The official source is
https://archive.ubuntu.com/ubuntu/pool/main/a/apport/apport_2.28.2.orig.tar.xz
with SHA-256
d249f388f0a0bb3aeed4bb51f405e590d99cf2474d5302679dac45f48e1b4229.
The original data/apport SHA-256 is
1b8b5e2c53e8970dd2f47c9a0892030d1ebad57cae1f7242c43a6252f1f6dff2.
The installed /usr/share/apport/apport generation is bound to those exact
44,730 bytes as root:root mode 0755 with one link.

The exact Noble unit is /usr/lib/systemd/system/apport.service, SHA-256
c2026a8f813776108e2d91629f51ff0cf5bf013fac03314164cabcda6c9698aa.
It is Type=oneshot, RemainAfterExit=yes, directly executes
/usr/share/apport/apport --start and --stop, and does not consult
/etc/default/apport.

The same reviewed host generation also contains the exact root:root mode 0644
`/usr/lib/systemd/system/apport-coredump-hook@.service` (787 bytes, SHA-256
`fdabfbd44847bd34d03efd9cc52d847d3dbaffec96e13cd413a40b35acc39a00`)
and
`/usr/lib/systemd/system/systemd-coredump@.service.d/apport-coredump-hook.conf`
(49 bytes, SHA-256
`d025d2395f1d5f0e9fc183b39db11dd5f121740fd818fc2333ed5ca4a39dbfaa`).
The latter has `OnSuccess=apport-coredump-hook@%i.service`, so proving only the
legacy `apport.service` path would leave a second crash-handler activation
edge.

V1 called stock systemctl stop. A SIGKILL after Apport's last stop write and
before JavaScript restored the safe pipe left native core dumps enabled. V1
also used a /run lock, bound only one sysctl, had no reboot lineage, and could
treat a hard-link receipt publication error as an uncommitted mutation.

## V2 action closure

V2 never executes the stock Apport handler. It does not call `systemctl start`,
`stop`, `enable`, or `disable`. After changing the gate or mask closure it calls
the pinned systemd D-Bus `Manager.Reload` method and then re-reads loaded unit
state and manager jobs before proceeding. Each runtime check fences one
`ListUnits`/`ListJobs` generation around complete `Properties.GetAll` reads for
the Unit and Service interfaces; any row, job, static load-path, PID, fragment,
drop-in, dependency, or `Exec*Ex` mismatch is rejected. The manager's ordered
`UnitPath` must equal the reviewed systemd 255 default search path; a custom or
reordered manager path is not silently treated as an additional trusted root.
Every present `UnitPath` root, every ancestor up to and including `/`, and every
nested directory is opened without following symlinks and must remain root:root
and not group- or world-writable. The plan records either absence or the
complete device/inode/time/link/owner/mode generation for every ancestor, root,
and traversed directory. The ancestor set is fenced before and after the full
traversal. Empty writable drop-in directories therefore fail closed too.
Runtime configuration fences repeat that traversal;
`Manager.Reload` is fenced before and after, allowing only systemd's own
inode/time/link churn in the three `/run/systemd/generator*` roots while
holding their path, presence, owner and mode plus every trigger/load-path byte
and filesystem device exact. Directory or trigger drift elsewhere rejects the
operation.

The official unit bytes, semantics, fragment path, empty drop-in set, and exact
single enablement symlink are plan inputs. The scan closes administrator,
runtime, transient, generated, attached, local-vendor, and vendor systemd unit
roots (with canonical-root deduplication). It rejects reverse activation edges
such as foreign Wants/Requires/Conflicts/PropagatesStopTo/OnFailure/OnSuccess
references (including reverse `OnFailureOf` and `OnSuccessOf` properties),
ordering/namespace edges, `Slice=`, `Sockets=`, and protected mount prefixes in
`RequiresMountsFor=`, including quoted or escaped
unit names, symlinked units whose targets contain such edges, and implicit
`apport.socket`, `.path`, `.timer`,
`.automount`, or `.busname` triggers. Multi-level aliases resolving to the
official unit and every foreign `Exec*` directive naming the handler are also
rejected. Physical comment lines do not terminate a systemd continuation,
matching the pinned systemd 255 parser. Dynamic `$VAR`/`${VAR}` manager
arguments and every shell/environment-interpreter dollar expansion fail
closed; manager and interpreter identities are resolved through filesystem
symlink and device/inode hard-link aliases, and every deprecated
semicolon-separated `Exec*` command is scanned individually. An unresolved
systemd `%` template is rejected when its fixed
prefix/suffix and normalized path can expand to the Apport unit, any protected
coredump-family unit/type, or the handler;
interpreter commands with unresolved arguments also fail closed. Stock-like
templates whose fixed text cannot name Apport remain admissible. The same
closed search covers every effective fragment and drop-in
for Apport, `systemd-sysctl.service`, and the reboot guard across control,
transient, generator, administrator, local-vendor, and vendor roots. Thus an
empty `ExecCondition=` reset in an exact-unit, dash-prefix, unit-type, or
higher-precedence drop-in is not ignored. Noble's one reviewed exception to
the general no-alias rule is the root-owned vendor link
`/usr/lib/systemd/system/procps.service -> systemd-sysctl.service`. Its path,
literal relative target, resolved official fragment, and unique presence are
checked on every managed load-path scan. `procps.service.d` is included in the
same inherited drop-in closure; any file there, or any other alias or
activation path resolving to the sysctl fragment, fails closed.

The foreign-activation scan also models the executable lookup boundary in the
reviewed systemd 255.4 generation. `Environment=PATH=` does not select the
first `Exec*=` executable: only a non-empty `ExecSearchPath=` or systemd's
compiled default does. For scanning, the four-directory merged-usr Noble
default is conservatively overapproximated with `/sbin` and `/bin` as well; the
documentation does not treat that six-directory set as systemd's exact
compiled value. After that first process starts, `nice`, `env`, and the
reviewed shell subset resolve their nested command from the effective child
`PATH`: manager/default environment, `ExecSearchPath=`, `PassEnvironment=`,
`Environment=`, then execution-time `EnvironmentFile=`, with
`UnsetEnvironment=` applied last. PATH absence is not treated as “no lookup”;
the scanner uses the Noble libc `/bin:/usr/bin` fallback for `nice`/`env` and
the Noble shell fallback for `sh`. Empty, relative, specifier-dependent, or
Linux non-root-owned/writable search generations fail closed. A present,
optional, globbed, or later-created `EnvironmentFile=` and an unpinned
`PassEnvironment=PATH` are unknown execution-time inputs: they are admissible
for a fully absolute inert command, but not for a wrapper whose nested command
depends on PATH.

Fragment and drop-in inputs are therefore combined per effective unit rather
than assessed only as isolated files. Exact fragments retain manager UnitPath
priority; equal-named drop-ins retain UnitPath shadowing; instance/template,
recursive dash-prefix, and type-wide directories are merged before wrapper
analysis. Every semicolon-separated command and executable-position systemd
specifier is tested for intersection with both protected handler paths and
manager identities. The `:` Exec prefix disables only systemd's argv
environment substitution; it does not disable specifier expansion or a
subsequent shell's `$` expansion.

Executable identity is evaluated in the service namespace. Literal
`RootDirectory=` and `BindPaths=`/`BindReadOnlyPaths=` mappings are followed,
including directory-prefix binds and `+` sources relative to the service root.
Their Linux sources/search ancestors must be root:root and non-writable. An
optional `-` bind is rejected because its source may appear after the scan
without a manager reload. A bind source or destination containing a systemd
specifier (`%`) or `$` is opaque: in particular, systemd 255 expands a dynamic
destination, but the scanner cannot reverse-map its directory suffix exactly.
`RootImage=`, `MountImages=`, `ExtensionImages=`, `ExtensionDirectories=`,
dynamic roots, and other unresolved image-backed views fail closed. The
disposable Noble PID 1 test confirms a harmless marker bind with a `%i`
destination is expanded by systemd. Thus binding `/usr/bin/systemctl` onto
`/opt/manager` cannot hide a manager invocation from the host-side scan.

Shell handling is intentionally a small conservative parser, not a proof of
arbitrary shell semantics. Static words, quotes, backslash removal and `;`
command boundaries are recursively checked; expansion, command substitution,
globs, redirection, pipelines, grouping, `eval`, `source`, `cd`, or malformed
syntax fail closed. Leading shell assignment words are normalized before the
command; wrapper options, cwd-changing `env`, relative nested pathnames,
control flow, and shell entrypoints without a literal `-c` command are outside
the subset and fail closed. This closes constructions
such as escaped pieces of `systemctl` and `systemd-coredump.socket`. An opaque
root-owned executable that
internally chooses to call systemd remains in the explicitly trusted UID 0
administrator boundary; the scanner does not claim to decompile arbitrary
binaries.

The complete untouched Noble `/usr/lib/systemd/system` tree is a required
benign test fixture. Its conservative scan produces exactly four reviewed
false positives. Three are dependency-only `%i` intersections:
`systemd-fsck@.service`, `systemd-growfs@.service`, and
`systemd-pcrfs@.service`. The fourth is `debug-shell.service`, whose exact
`ExecStart=/usr/bin/bash` intentionally enters an interactive root shell
without the statically reviewed `-c` subset; arbitrary commands entered by a
root operator are already inside the explicit trusted-UID-0 boundary. These
are not family, specifier, or shell relaxations. Each exception requires its
exact absolute path, dpkg owner `systemd`, installed package/status
`255.4-1ubuntu8.15`, complete fragment bytes and SHA-256, root:root `0644`
one-link metadata and exact byte size, plus either the exact `%i.device` or
`%i.mount` `BindsTo=`/`After=` values or the exact debug-shell `ExecStart=`.
A copied unit, package revision, metadata change, extra byte, or
directive/value near miss still fails closed.

The inspected Hetzner boot also contains one root-owned generator link whose
literal relative target is currently absent:
`/run/systemd/generator/multi-user.target.wants/systemd-networkd.service ->
../systemd-networkd.service`. The executor source requires exactly this one
broken activation link and includes its path, target and ownership in the
configuration-generation digest. Any other broken link, a missing or resolved
reviewed link, or target/ownership drift fails closed and requires a new plan
and source review. Existing regular unit targets are still scanned for Apport
references; this exception does not admit an unresolved Apport basename.
Observation enumerates already-loaded units with D-Bus `ListUnits` and then
uses non-loading `GetUnit`; an unloaded Apport unit is rejected.
Apply removes only this exact symlink:

    /etc/systemd/system/multi-user.target.wants/apport.service
      -> /usr/lib/systemd/system/apport.service

Stable unit configuration is separate from transient service bookkeeping. The
same transaction accepts either settled `active/exited` or settled
`inactive/dead`; neither observation appears in the receipt post-state and the
ceremony never claims to start or stop the service. On the original plan boot,
the observed pair must remain exactly the plan's pair; after a separately
approved reboot, either settled pair is accepted because systemd may have
reevaluated the oneshot. Apply installs an exact
`/etc/systemd/system/apport.service -> /dev/null` mask and removes the exact
enablement link, so the next manager load cannot start Apport. Rollback removes
that mask, recreates the exact enablement link, and restores all three approved
sysctl values without starting Apport. Apart from the single source-fixed
Noble sysctl alias described above, no Alias, Also unit, arbitrary root-owned
fragment, or foreign activation edge is accepted. The ceremony does
not import the handler's Python module graph. A rollback approval authorizes
restoring the exact top-level handler configuration but is not an attestation
of every module that a later boot may import.

Apply additionally installs fixed root-owned `/dev/null` masks for
`apport-coredump-hook@.service`, `systemd-coredump@.service`, and
`systemd-coredump.socket`. It requires exact D-Bus unit-file state `masked`, no
loaded concrete template instance, no queued job, no alias or dependency edge,
and a complete absence closure for the `systemd-coredump` package, binary,
vendor service/socket and configuration roots. Rollback proves the
package/path/vendor/static-load-path closure around a fenced runtime snapshot
before restoring any approved Apport sysctl, then repeats that proof
synchronously inside the mutator immediately before removing the first
coredump mask. It never invokes `systemctl stop`
to make a loaded handler disappear; any loaded protected-family unit of any
systemd 255 unit type or queued job fails closed. The static proof mechanically
rejects every protected-family fragment, including `.path`, `.timer`,
`.socket`, implicit same-name service/template activation and `Accept=yes`, in
the complete manager `UnitPath`, independent of the file contents. It likewise
rejects symlink and hard-link aliases and every drop-in directory systemd 255
would merge, including recursive dash truncation while retaining both the
concrete `@instance` and template `@` forms. A benign `Environment=` value that
only contains a protected-family string remains admissible because it has no
activation semantics. Descendant slice names are protected too because systemd
automatically requires and activates their dash-truncated parent slices. The
sole admitted coredump drop-in remains the exact
pinned Noble `systemd-coredump@.service.d/apport-coredump-hook.conf`
generation.

The candidate persistent policy has exact safety-first bytes:

    kernel.core_pattern=|/usr/bin/false
    fs.suid_dumpable=0
    kernel.core_pipe_limit=0

Apply writes and immediately reads back `core_pattern` first, then the other
two. No V2 code path writes `core_pattern=core`. Rollback retains the mask,
pending gate, early guard, and safe policy while it restores enablement and the
three preimage values; it restores the Apport pipe last.

Runtime validation follows systemd 255 mask semantics: the mask symlink itself
is the masked `FragmentPath`, masked Apport has no parsed start/stop commands or
dependencies, and its reviewed preflight drop-in/`ExecCondition` remains
visible until cleanup. `systemd-sysctl.service` must retain the single official
`/usr/lib/systemd/systemd-sysctl` `ExecStartEx`; every other start/reload/stop
slot is empty, apart from the reviewed preflight `ExecConditionEx`. The reboot
guard likewise has one exact `ExecStartEx` and empty condition/pre/post/reload/
stop slots.

The reviewed Noble 255.4-1ubuntu8.15 `systemd-sysctl.service` bytes, amd64
`systemd-sysctl` binary, and vendor `sysinit.target.wants` symlink are fixed
inputs. The official `procps.service` compatibility alias is a source-fixed
Noble platform invariant rather than a new mutable plan field; it is included
in the configuration-generation digest and every live validation. Runtime
D-Bus evidence requires `Names` to equal exactly `procps.service` plus
`systemd-sysctl.service` for this unit. Apport and the reboot guard still admit
only their canonical name, and any missing or additional name is rejected.
Runtime evidence also requires exact `WantedBy=sysinit.target`. Apply
retains an exact `80-bitcoinpir-credential-closure.conf` drop-in which clears
`ImportCredential`, `LoadCredential`, `LoadCredentialEncrypted`,
`SetCredential`, and `SetCredentialEncrypted`; this prevents a boot-time
`sysctl.extra` system credential from overriding the reviewed persistent
policy. Rollback removes that closure only while the preflight gate still
forces/skips the loader, then restores the approved preimage.

## Exact plan state

The canonical schema-v2 plan binds:

- original plan boot ID, machine ID digest, Noble OS bytes, systemd 255 version;
- exact Node, executor source, /usr/bin/false, systemctl version probe, busctl,
  `/usr/bin/dpkg-query`, content-addressed renameat2 helper, and maintenance-lock
  helper binaries;
- official Noble source URL/archive/handler hashes, exact unit bytes, and exact
  coredump hook unit/drop-in bytes and metadata;
- the exact installed Noble handler path, bytes, size, ownership, mode, and
  one-link metadata even though the ceremony never executes it;
- all three live sysctl preimages and candidates;
- every effective assignment for all three sysctls, including systemd
  same-basename precedence and `/dev/null` masks; any glob or negative
  exclusion that can match a reviewed key is rejected rather than silently
  omitted;
- the official Noble systemd-sysctl unit/binary generation, exact boot
  enablement symlink and `WantedBy`, and the candidate credential-reset drop-in;
- through the approval-bound executor source, the exact root-owned
  `procps.service` compatibility alias and its otherwise-empty alias drop-in
  closure;
- exact stable Apport fragment and empty drop-ins, the closed enablement and
  activation set, plus a separately labelled settled `active/exited` or
  `inactive/dead` observation with `NeedDaemonReload=no`;
- exact final Apport mask, preflight-only Apport and systemd-sysctl
  `ExecCondition` gates, early guard,
  persistent policy, and every fixed symlink/file quarantine or prepared temp,
  lock, pending, receipt, and rollback-receipt path;
- the fixed ordered three-mask coredump generation plus absence of every
  reviewed `systemd-coredump` package/path generation; the plan and receipts
  bind the same normalized protected-template load-path closure used by runtime
  generation fences and the rollback in-mutator re-proof, as well as the masks
  and pinned vendor closure;
- the exact ordered manager `UnitPath`, plus absent-or-present trusted
  directory generations for every ancestor (including `/`), every root, and
  every nested directory traversed by the static proof;
- /var/crash directory device, inode, uid, gid, mode 3777, and sorted empty
  entry observation.

Plans rendered by an earlier, unapproved schema-v2 implementation do not carry
the ancestor generation and are deliberately rejected. Render a fresh plan on
the target boot and issue fresh approvals; never splice ancestor observations
into old canonical plan bytes.

/var/crash entries are a point-in-time observation. Apply and rollback repeat
the directory identity and entries check immediately before their terminal
receipt. A receipt does not claim another privileged process cannot create a
future entry.

## Durable state and reboot lineage

The approval-bound lease, lock, pending, and receipts live below
`/var/lib/bitcoinpir/payment-v1/core-pattern`, not `/run`. The boot-visible,
canonical preflight intent is `/etc/systemd/bitcoinpir-payment-v1-core-pattern-preflight.json`.

Apply and rollback prove the inherited dpkg/apt locks before any mutation,
publish an approval/mode/boot/plan/source-bound lease, install and manager-reload
three inert boot controls, and only then publish preflight:

1. a `sysinit.target` guard ordered before `systemd-sysctl.service`,
   `apport.service`, all three protected coredump unit names, and
   `sysinit.target`, which writes all three safe values.
   It is a non-retaining oneshot: after a reboot run it becomes inactive/dead,
   so removal plus manager reload can garbage-collect the unit;
2. an Apport `ExecCondition` that blocks activation whenever preflight exists;
3. a `systemd-sysctl.service` `ExecCondition` that writes the safe tuple again
   and skips the normal sysctl loader whenever preflight exists.

After the gate reload, the non-loading D-Bus observation is repeated
immediately before initial preflight publication; the same PID/job/transition
checks are repeated immediately before either terminal receipt publication.

Before preflight the exact controls are inert, so a lease-only/bootstrap crash
retains the approved preimage behavior and is recoverable only through the
official recovery command. Once preflight is visible, every incomplete boot
writes the safe tuple before `systemd-sysctl`, writes it again at the sysctl
gate, skips vendor assignments, and blocks Apport. Thus no incomplete boot has
an interval in which normal `systemd-sysctl` can restore the Apport tuple.
Pending is published only after that boot invariant exists. Closed locale,
path, timezone, Node, and dynamic-loader environments apply to all early calls.

The receipt is the terminal commit point while preflight, gates, pending, and
lease still exist. Cleanup first proves/reclaims the exact lease, removes
pending, then removes preflight (the terminal boot transition), removes and
manager-reloads the exact gates, and releases the lease last. A visible
rollback receipt whose preflight survived a reboot re-establishes the approved
rollback sysctls before cleanup. Apply retains the safe policy, credential
closure, Apport mask and all three coredump masks; rollback restores the exact
stable preimage only after the coredump absence closure is re-proved before the
first Apport sysctl restore, then re-proved again immediately before the first
coredump mask removal.

Pending and preflight updates carry an integer generation plus the SHA-256 of
their exact predecessor. Exchange replay accepts only a direct predecessor or
the exact prepared direct successor. A complete prepared-but-not-linked JSON
generation is normalized only by approved recovery. All read-only discovery
uses a non-mutating peek; hard-link normalization, publication, deletion, and
cleanup require the already-proven maintenance-lock capability.

The plan retains plan_boot_id. Every short-lived approval contains plan_boot_id
and the freshly observed action_boot_id.

- Apply requires action_boot_id equal to plan_boot_id.
- Recovery may use a later boot. Its fresh approval names `lease`, `preflight`,
  or `pending` and binds the exact newest subject digest actually reread, the
  original approval digest, and apply/rollback mode. The approval digest is
  durably appended before advancing a nonterminal transaction, and every
  receipt binds the exact preflight digest and that complete ordered recovery
  chain. If a terminal receipt is already visible, it remains immutable; the
  fresh subject-bound recovery approval authorizes only deterministic cleanup
  and is not retroactively added to the terminal receipt.
- Rollback may use a later boot, but its fresh approval binds the exact
  committed receipt.
- Receipts record `apply_boot_id` and the actual action-time `/proc` boot ID as
  `action_boot_id`. `host_reboot_performed` is derived from their inequality.

An old apply approval cannot authorize post-reboot recovery.

## Root/package-maintenance race closure

The Node process must be execed by the pinned
payment-v1-core-pattern-lock-exec helper. The helper acquires exclusive POSIX
fcntl locks on the dpkg/apt maintenance files, retains the descriptors across
exec through a five-variable closed environment (lock descriptors, locale,
path, and UTC timezone), and the executor proves exact descriptor inodes plus
/proc/locks entries. Before acquiring locks it accepts only exact `/usr/bin/node`,
the canonical installed ceremony source, one of `apply`, `recover`, or
`rollback`, and that command's exact non-duplicated option set. Node exec flags,
alternate programs/sources, non-maintenance subcommands, loader variables,
Node variables, and forged inherited-lock variables are rejected; exec receives
only the closed five-variable environment.

Regular-file replacement uses a pinned content-addressed Linux
renameat2(RENAME_EXCHANGE) helper. After exchange, the executor verifies the
swapped-out inode is exactly the approved generation. If package/root mutation
won the race, it exchanges that generation back and fails closed instead of
overwriting it. Removal first renames to fixed quarantine, verifies approved
identity, and restores a raced generation before refusing.

The Apport enablement, Apport/coredump mask symlinks and guard enablement
symlink use distinct fixed same-directory no-clobber quarantines.
Install/removal replay handles both
names linked to the same symlink inode, either name alone, and every
link/unlink/verify/parent-fsync boundary. Quarantine-to-live symlink recovery
uses a no-clobber hard link and reclassifies `EEXIST`, never a replacing rename.
Guard and gate regular files
likewise use fixed prepared/quarantine names, including the exact live-plus-
quarantine replay state. Re-publication uses a pinned no-replace operation and
reclassifies a raced exact live generation instead of overwriting it. Detached
JSON prepared generations are accepted only when hard-linked to the exact live
inode; a separate live inode plus detached prepared inode is rejected. An
empty exact 0700 prepared or current lock directory
left between `mkdir` and owner publication is repaired only from the already
validated durable lease; unknown contents remain rejected. Unexpected targets,
bytes, or inodes are rejected or restored. Root can always subvert a root
process after checks; the contract closes ordinary package-maintenance races
and power-loss replay, not malicious root.

The coredump masks have the same boundary: they constrain systemd activation,
non-root callers and cooperative package maintenance. A malicious UID 0 can
remove them or execute a pinned handler directly and remains part of the
trusted host-administrator boundary. The ceremony does not claim otherwise.

## Receipt publication and exact outcomes

Canonical receipt bytes are persisted into pending before publication.
Publication uses a fixed prepared inode and no-clobber hard link. If the target
is visible and link-following fsync or verification fails, the executor does a
descriptor-bound reread. An exact visible receipt is terminal, the linked temp
must be the same inode, containment is forbidden, and replay returns identical
receipt bytes.

Each receipt distinguishes `terminal_commit_state` from `post_state`. The
terminal state intentionally includes the pending guard and gate that make a
reboot safe; the post-state describes the exact result after deterministic
cleanup. After persisting a receipt candidate in pending, apply and rollback
repeat both the fenced runtime check and a full exact inspection against that
candidate immediately before publication. The final synchronous inspection
and atomic no-clobber publication are one executor operation with no JavaScript
`await` or callback boundary between them. This narrows the point-in-time
linearization window but does not protect a root process from a malicious
concurrent root writer. Cleanup repeats the phase-specific
runtime check and full `post_state` inspection before releasing the durable
lease. Recovery approval SHA-256 values are an ordered, unique receipt field,
not an unrecorded operator-side fact.

Outcomes distinguish committed, receipt-visible-commit-uncertain, terminal
lock-retained variants, contained-needs-fresh-recovery-approval,
recovery-refused-lock-retained,
rollback-contained-needs-fresh-recovery-approval, and
outcome-unknown-lock-retained. Lock-release failures are never swallowed.

## Approval files

Unusable materialization skeletons are under
docs/payment/render-plan-skeletons:

- core-pattern-ceremony-v2.plan.json.example
- core-pattern-ceremony-v2.apply-approval.json.example
- core-pattern-ceremony-v2.recovery-approval.json.example
- core-pattern-ceremony-v2.rollback-approval.json.example

Every approval window is positive and at most one hour. The operator must
externally compare the canonical plan, executor source, installed helper
binaries, fresh boot ID, and approval digests. No checked-in file is approval.

## Materialization and command shapes

This section specifies interfaces; it does not authorize installation or host
mutation. Materialize in an owner-only directory outside Git. Install the
reviewed executor at exact root:root mode 0555 and compile the checked-in C
maintenance-lock launcher with warnings denied, then install its independently
approved bytes at exact root:root mode 0555. Reuse the already reviewed
content-addressed rename-exchange helper generation; do not substitute a new
helper path.

Read-only observation and validation do not acquire the package locks:

    /usr/bin/node /usr/local/libexec/bitcoinpir/payment-v1-core-pattern-ceremony.mjs \
      observe-plan --ceremony-id "$FRESH_CEREMONY_ID" \
      > "$OWNER_ONLY/core-pattern.plan.json"

    /usr/bin/node /usr/local/libexec/bitcoinpir/payment-v1-core-pattern-ceremony.mjs \
      validate-plan --plan "$PLAN" \
      --approved-plan-sha256 "$PLAN_SHA256" \
      --approved-source-sha256 "$EXECUTOR_SHA256"

Every mutating interface must enter through the exact maintenance-lock helper:

    /usr/local/libexec/bitcoinpir/payment-v1-core-pattern-lock-exec -- \
      /usr/bin/node /usr/local/libexec/bitcoinpir/payment-v1-core-pattern-ceremony.mjs \
      apply --plan "$PLAN" --approved-plan-sha256 "$PLAN_SHA256" \
      --approved-source-sha256 "$EXECUTOR_SHA256" \
      --approval "$APPLY_APPROVAL" \
      --approved-approval-sha256 "$APPLY_APPROVAL_SHA256"

    /usr/local/libexec/bitcoinpir/payment-v1-core-pattern-lock-exec -- \
      /usr/bin/node /usr/local/libexec/bitcoinpir/payment-v1-core-pattern-ceremony.mjs \
      recover --plan "$PLAN" --approved-plan-sha256 "$PLAN_SHA256" \
      --approved-source-sha256 "$EXECUTOR_SHA256" \
      --recovery-approval "$RECOVERY_APPROVAL" \
      --approved-recovery-approval-sha256 "$RECOVERY_APPROVAL_SHA256"

    /usr/local/libexec/bitcoinpir/payment-v1-core-pattern-lock-exec -- \
      /usr/bin/node /usr/local/libexec/bitcoinpir/payment-v1-core-pattern-ceremony.mjs \
      rollback --plan "$PLAN" --approved-plan-sha256 "$PLAN_SHA256" \
      --approved-source-sha256 "$EXECUTOR_SHA256" \
      --approved-receipt-sha256 "$COMMITTED_RECEIPT_SHA256" \
      --rollback-approval "$ROLLBACK_APPROVAL" \
      --approved-rollback-approval-sha256 "$ROLLBACK_APPROVAL_SHA256"

The full plan, source, helper, approval, pending, and receipt digests must be
transferred and compared independently. A command shape is never approval.

## Verification

Pure and hard-crash suites:

    node --check scripts/payment-v1-core-pattern-ceremony.mjs
    node --check scripts/payment-v1-core-pattern-test-fixture.mjs
    node --check scripts/payment-v1-core-pattern-crash-worker.mjs
    node --check scripts/payment-v1-core-pattern-lock-exec.test.mjs
    node --test scripts/payment-v1-core-pattern-ceremony.test.mjs \
      scripts/payment-v1-core-pattern-crash.test.mjs \
      scripts/payment-v1-core-pattern-lock-exec.test.mjs

The hard-crash suite kills independent child processes with SIGTERM, SIGKILL,
and SIGABRT after every apply/rollback commit boundary, including lease-only,
empty lock-directory, gate quarantine, and gate-armed preflight windows. It
reloads only persisted state, simulates a reboot, and asserts the exact complete
three-sysctl tuple before recovery and after convergence. The Linux-only unit
cell separately replays every guard symlink namespace/fsync boundary. Pure
tests also cover every regular-file quarantine boundary, terminal-candidate
tuple drift, systemd load-path bypasses, quoted/escaped dependency directives,
and torn D-Bus unit/job snapshots. The C-helper suite compiles with warnings
denied and exercises executable, argv, and environment rejection.

The former privileged-container PID 1 integration is retired and exits 78.
Containers share the host kernel and cannot prove isolated `core_pattern`
reboot behavior. It is absent from automatic CI. CI instead statically checks
the fail-closed independent-kernel guest gate:

    sh -n scripts/payment-v1-core-pattern-independent-kernel-gate.sh
    node --test scripts/payment-v1-core-pattern-independent-kernel-gate.test.mjs

An operator may separately provision a disposable VM with its own kernel and
run a separately reviewed matrix through
`payment-v1-core-pattern-independent-kernel-gate.sh`. The gate requires Linux
systemd PID 1, rejects container virtualization, allowlists VM hypervisors,
binds a UUID in the guest kernel command line, binds the current boot ID and
matrix SHA-256 in a root:root 0400 marker, and accepts only an exact root:root
0500 matrix. The gate never provisions, reboots, or destroys a VM. No such VM
matrix was run by this implementation task.

## Remaining production risk gate

Apply removes host-wide crash collection and can reduce future diagnostic
evidence for every process. Rollback restores a handler that may collect
secret-bearing memory and correlation data. Either action still requires a
separate human risk decision for the exact host, fresh boot, exact
plan/source/helper digests, and exact approval. No code grants that approval.

The receipt is exact point-in-time evidence, not a continuous root-isolation
boundary. The ceremony manager-reloads and proves the current unit is settled,
has zero MainPID/ControlPID, has no queued job, has the reviewed drop-in set,
and is loaded/masked as required. It validates complete Unit/Service `GetAll`
snapshots between identical manager unit/job lists and identical static
load-path generations immediately before preflight and receipt publication.
A later privileged configuration replacement, package post-install action
outside the held maintenance locks, direct `/proc/sys` writer, or newly created
transient/generated reverse dependency can still defeat that point-in-time
state. Future sysctl files, `/var/crash` entries, kernel/module behavior, or
replacement of reviewed executable generations are also outside the receipt.

Therefore stopped/live activation evidence must be collected after the
ceremony and invalidated by later package, service-manager, sysctl, or
privileged host maintenance. No independent-kernel VM matrix, production
reboot, materialization, installation, or host mutation was performed by this
implementation task.

### Suggested separate production approval wording

The operator should replace every bracketed value only after independently
comparing it; this paragraph is a template, not approval:

> I approve the host-global core-pattern apply on host machine-id digest
> `[MACHINE_ID_SHA256]`, actual boot `[ACTION_BOOT_ID]`, plan
> `[PLAN_SHA256]`, executor `[SOURCE_SHA256]`, lock helper
> `[LOCK_HELPER_SHA256]`, and exchange helper `[EXCHANGE_HELPER_SHA256]`.
> I accept loss of native core diagnostics and Apport collection for all host
> processes, replacement of all three Apport sysctls, installation of the
> three reviewed coredump unit masks, the fact that those masks do not constrain
> malicious root/direct execution, retention of existing
> crash/journal history, manager reload, incomplete-boot sysctl skip/guard, and
> point-in-time privileged-maintenance limits. This does not approve a
> reboot, history deletion, service activation, deployment, routing, or funds.

Recovery and rollback require new texts that additionally name the exact
newest lease/preflight/pending recovery subject or committed-receipt digest and
current `/proc` boot ID; the apply text cannot be reused.
