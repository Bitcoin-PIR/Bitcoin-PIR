# Existing Caddy admin Unix-socket hardening

Status: reviewed-source cold-executor candidate, **not activated**. This
profile does not authorize SSH, installation, a Caddy stop/start, public
routing, or any other host mutation. It contains a read-only plan/receipt gate,
deterministic candidate builders and a local-host-only fail-closed executor.
Checking in the executor is not approval to run it; a private fully
materialized plan, site-probe inventory, external plan-digest approval and a
separately authorized outage remain mandatory.

## Scope and boundary

`bhtm-caddy-admin-uds-v1` is a maintenance prerequisite for the existing root
`bhtm-caddy.service`. It migrates only the Caddy admin endpoint from
`127.0.0.1:2019` (explicit or Caddy's equivalent implicit default) to:

```text
unix//run/bitcoinpir-caddy-admin/admin.sock|0200
```

The hardened unit must run as `root:root`, expose no `CADDY_ADMIN` environment
value, and have exactly one loaded drop-in:

```text
/etc/systemd/system/bhtm-caddy.service.d/bitcoinpir-publisher-netns.conf
```

That root-owned pinned file may contain only the one-way
`Wants=` plus `After=` relation toward
`bitcoinpir-payment-v1-publisher-netns.service`; `Requires=`, `BindsTo=` and
reverse stop propagation are forbidden. The unit must also read back these
exact properties:

```text
RuntimeDirectory=bitcoinpir-caddy-admin
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=no
LimitCORE=0
MemorySwapMax=0
StandardOutput=null
StandardError=null
UMask=0077
UnsetEnvironment=CADDY_ADMIN
```

Its reset `ExecReload` dials
`unix//run/bitcoinpir-caddy-admin/admin.sock` explicitly. The mode suffix is a
listener creation option and is not part of the dial address.

The isolation claim is deliberately narrower than “root-only”: it is a DAC
boundary against capability-free, unprivileged, non-root processes. UID 0 and
any process retaining `CAP_DAC_OVERRIDE` remain in the trusted host boundary.
The plan therefore binds a same-boot privileged-process/capability inventory;
each service-UID probe is launched through the descriptor-pinned
`/usr/bin/setpriv`, clears supplementary groups and all inheritable, ambient,
effective and bounding capabilities, and records `CapEff=0` plus its exact
group set.

This is not an append-only overlay. A site block cannot change a global Caddy
admin address or create a systemd runtime directory. The maintenance window
must replace the exact complete Caddyfile and exact complete unit while the
service is stopped. The later `integrated-existing-bhtm-caddy-v1` overlay is a
different transaction: it may run only when its new preimages are the exact
hardened Caddyfile, unit and binary and it has pinned a canonical, owner-only
committed hardening receipt.

## Exact candidate construction

Start from a fresh descriptor-bound inventory of the Hetzner host's exact
`/usr/local/bin/caddy` (the reviewed service `ExecStart` path;
`/usr/bin/caddy` is absent on this host),
`/etc/caddy/Caddyfile`, `/etc/systemd/system/bhtm-caddy.service`, the active
unit generation and effective loaded unit, `/usr/bin/node`, `/usr/bin/setpriv`, the installed probe, the
installed hardening gate and the installed cold executor. The plan also pins
exact systemd `255`. Fill
[`bhtm-caddy-admin-uds-v1.plan.json.example`](render-plan-skeletons/bhtm-caddy-admin-uds-v1.plan.json.example)
outside version control and obtain an independent approval of its canonical
digest.

The gate accepts one of three explicit Caddyfile edit modes:

- `replace-explicit-tcp-admin` replaces the sole exact global
  `admin 127.0.0.1:2019` line;
- `insert-existing-global-options` inserts the exact UDS line into an existing
  global-options block that has no admin directive; or
- `prepend-new-global-options` prepends a new two-directive-free global block
  when no global-options block exists.

In every mode, every byte outside that one admin insertion/replacement remains
unchanged. This retains all existing site and ACME-related Caddyfile bytes. The
closed V1 grammar rejects every Caddy `import` token (including inline imports
and zero-match globs), `{env.*}` and `{$...}` substitution so an unpinned file
or environment cannot replace the reviewed admin directive after validation.
It also rejects quoted `import`/`admin` directive tokens and every Unicode
White_Space code point outside the four-character canonical subset. The lexer
recognizes only the four ASCII space/tab/CR/LF whitespace characters as
canonical. The enclosing canonical-text rule separately rejects CR and
requires LF line endings. This is deliberate because Caddy's adapter accepts
Unicode and quoted spellings that a narrower lexer could otherwise miss. The
unit builder preserves every unrelated line byte-for-byte; it removes only
the old root `User`/`Group`, old `ExecReload`, any old `LimitCORE`,
`MemorySwapMax`, `StandardOutput` and `StandardError`, and an exact standalone
`CADDY_ADMIN=127.0.0.1:2019`
assignment, replaces `ExecStart` with the exact non-`--environ` command, then
adds the reviewed block. It rejects an
environment file, every `PassEnvironment`, command-line
environment files, continuation lines, a non-root service, or any pre-existing
`RuntimeDirectory`, `RuntimeDirectoryMode`, `RuntimeDirectoryPreserve`,
`UMask`, or `UnsetEnvironment` setting instead of silently overwriting it.
This target-specific first-generation profile also requires the old loaded and
on-disk `ExecStart` to retain the exact reviewed `--environ` form and
`ExecReload` to retain the exact reviewed `--force` form shown in the checked-in
preimage fixture. A different legacy unit must use a new reviewed profile
rather than widening this executor.
`LimitCORE`, `MemorySwapMax`, `StandardOutput` and `StandardError` are
deliberately replaced rather than rejected because closing the existing dump,
swap and journald paths is part of this migration. `LimitCORE=0` does not make
a Linux pipe core handler safe by itself; target activation still requires the
separate exact `kernel.core_pattern=|/usr/bin/false` host proof.
That proof comes from the independently approved, all-three-sysctl ceremony in
[`CORE_PATTERN_CEREMONY.md`](CORE_PATTERN_CEREMONY.md); this Caddy executor is
forbidden from changing Apport, its enablement symlink, or any host sysctl.

ACME storage is not copied, renamed or reinitialized. The complete existing
site inventory and its before/after probes are separate approved plan inputs.
Preserving config bytes is not a claim that the wider existing root Caddy,
plugins, ACME account, or all sites become isolated. The canonical adapted JSON
must additionally have no top-level `logging`, HTTP-server `logs`, `log_append`
or `log_name` configuration. `StandardOutput=null` and `StandardError=null`
close only the implicit process-stream-to-journald path; they cannot neutralize
an explicit file, network or syslog sink in Caddy JSON, so such a sink is an
activation blocker.

The approved preimage and candidate each record both the SHA-256 and byte length of the
admin-UDS gate's no-trailing-newline
`canonicalizeAdaptedCaddyJson(caddyAdaptOutput)` bytes. Offline `validate-plan`
canonicalizes the supplied adapter artifacts, applies the privacy gate and
requires both exact tuples. Before any stop request, the executor feeds the
descriptor-read old Caddyfile bytes to the descriptor-pinned production Caddy
through stdin and requires that approved preimage tuple to equal the live TCP
admin `/config/` canonical digest. This rejects a hot-loaded configuration that
cannot be reconstructed from the rollback bytes. The committed receipt's root `/config/` readback is
strictly parsed and canonicalized the same way, and its `body_sha256` must equal
the approved candidate digest. Both the plan and live probe use the same
2 MiB bound and reject non-interoperable unsafe integers. Hashing the raw
adapter or HTTP response layout is not accepted evidence.

Nulling both service streams intentionally removes Caddy startup, ACME and
reverse-proxy diagnostics as well as request-correlating errors. Production
operation therefore relies on systemd state, certificate-expiry alarms,
external endpoint probes, binary/config digest drift alarms and bounded
non-request-bearing metrics. Re-enabling journald for troubleshooting is a
privacy-affecting configuration change, not an ordinary logging toggle.

## Version and test evidence

The production binary remains an independently inventoried exact preimage. Its
digest need not equal a Docker image binary, but its reviewed version is
`v2.11.4`; `v2.11.3` is not production evidence for this profile.

Compatibility/process tests use only these resolved registry objects:

| Runtime | Resolved tag | OCI index digest | Linux/amd64 manifest |
| --- | --- | --- | --- |
| Caddy | `2.11.4` | `sha256:844f60b64e4724a5aa8245e019dace0d3f199f7433ce6c57676cb30a920dbad9` | `sha256:98eb57d882ccd5213d1688764db10c1ca2c58a1ca3a6717a3411ad798f7a423a` |
| Node | `22.22.2-bookworm-slim` | `sha256:9f6d5975c7dca860947d3915877f85607946403fc55349f39b4bc3688448bb6e` | `sha256:868499d55378719bffa87b0ed1f099591823c029b543043c09c2483468e93201` |

The Caddy amd64 binary in that exact test image has SHA-256
`b7105518e3ed1c0761f232e44fc09345535533c9cb0abf0e12809416c7ac64d9`.
The remote gate runtime is separately pinned as `/usr/bin/node` `v22.22.2`;
passing under the repository's Node 24 browser CI is not treated as equivalent
host evidence.

The process suite runs the exact Caddy and Node objects, proves a real imported
directive can override a preceding UDS admin directive (and that the gate
rejects that input), checks that `--environ` is absent and a sentinel service
environment is not logged, exercises the descriptor-pinned `setpriv` adapter,
and demonstrates fail-closed behavior after intentionally widening the
directory/socket modes. The same exact Caddy v2.11.4 adapter test proves that
all 21 rejected non-canonical Unicode whitespace code points and both quoted
directive syntaxes can introduce a real second admin directive before the
closed-profile gate rejects them. It also proves that the exact candidate's
real adapter output and live UDS `/config/` readback have the same canonical
JSON digest. CI additionally runs `systemd-analyze
verify` against the byte-exact generated unit fixture.

## Cold maintenance transaction

`RuntimeDirectory` first exists only after systemd starts the new generation.
A reload of the old generation therefore cannot prove or apply this migration.
The approved transaction is:

1. Hold the exact shared publisher-lifecycle lock at
   `/run/lock/bitcoinpir-payment-v1-publisher-lifecycle.lock` and re-read the approved old binary,
   Caddyfile, unit, active PID, `InvocationID`, and site health. Require the
   loaded unit's exact fragment, the singleton approved publisher-namespace
   drop-in and exact one-way relationship, no `EnvironmentFile` or
   `PassEnvironment`, exact old `ExecStart`/`ExecReload`, and
   `NeedDaemonReload=no`. Adapt the exact disk Caddyfile bytes with the pinned
   Caddy descriptor and require its approved canonical digest to equal the
   live TCP-admin `/config/` digest. Repeat the loaded-unit/process/admin
   bindings immediately before the stop boundary.
   The plan also binds the publisher namespace unit to exact `inactive/dead`
   state with no generation, plus absence of its nsfs path, host veth and all
   five activation sentinels. Validate that state before locking, after locking,
   and as the final operation immediately before the Caddy stop. The namespace
   ceremony uses the same lock, so the two reviewed mutators cannot overlap.
   An active or raced namespace at this boundary rejects with no Caddy
   stop/start/reload request. The lock owner is domain-separated as an Admin
   UDS transaction; a publisher recovery cannot discard an Admin lock retained
   for outcome-unknown review merely because its original process exited.
2. Validate the deterministic candidates with the exact production Caddy
   binary, require the canonical adapted JSON's exact UDS `admin.listen`,
   privacy policy, digest and size, and run `systemd-analyze verify` on the
   candidate unit. Exclusively
   create and fsync exact old backups and both candidates.
3. Stop `bhtm-caddy.service`. Prove `inactive/dead`, no MainPID, no pending
   systemd unit job, no admin socket, and connection refusal on both
   `127.0.0.1:2019` and `[::1]:2019`.
4. While stopped, replace the Caddyfile and unit with the two exact approved
   candidates and fsync both parent directories. Partial pairs are never
   started.
5. Run `systemctl daemon-reload`, repeat the exact inactive/absent publisher
   namespace proof as the final operation before the command, start the unit, and require a new
   `InvocationID` and active-enter timestamp. A systemd `InvocationID` is the
   exact nonzero 32-character lowercase hexadecimal value returned by
   `systemctl show`; it is not a hyphenated UUID. `restart` and warm `reload`
   are not substitutes for this proof.
   For an inactive unit the collector normalizes either an empty value or
   systemd's 32-zero sentinel to the receipt's canonical empty string.
6. Require `NeedDaemonReload=no`, the exact main fragment, the same singleton
   publisher-namespace drop-in and one-way relationship, no
   effective `CADDY_ADMIN`, exact effective `LimitCORE=0`, `MemorySwapMax=0`,
   `StandardOutput=null` and `StandardError=null`, root API `GET /config/`
   success over the UDS with the same canonical adapted-JSON digest,
   root:root `0700` runtime directory, root:root `0200` socket, both TCP-2019
   probes refused, and `EACCES` from every non-root UID in the approved complete
   service inventory (including `pir` and `cloudflared`) after `setpriv` proves
   zero capabilities and only the requested primary group.
7. Re-run every approved existing-site probe, including at least one public
   WebPKI HTTPS response, one direct-upstream HTTP response and one independent
   WebPKI TLS handshake/leaf-certificate probe. Only then exclusively create,
   fsync and parent-fsync a canonical mode-`0400` committed receipt.

An exact rollback repeats the old effective-unit and canonical old-admin
readback checks after the rollback start and again after the long site probes;
restoring only the two disk files is not accepted as proof of restoring the old
runtime state. The rollback start has the same immediately-adjacent inactive
publisher-namespace check; if that proof fails, the executor leaves Caddy
stopped and reports outcome unknown rather than starting into an unapproved
combined lifecycle.

The checked-in gate validates this plan and an already-collected committed
receipt. The separate
`scripts/payment-v1-caddy-admin-uds-transaction.mjs` implements these steps on
the local Linux host only. It has no SSH or remote-control surface, requires
EUID 0, Linux and exact systemd `255`, and refuses the transaction unless
`kernel.core_pattern` already reads exactly `|/usr/bin/false`. It never writes
that sysctl; the sysctl change and its approval remain a separate ceremony.

The executor accepts a private canonical site-inventory JSON document whose
SHA-256 is exactly `site_preservation.existing_site_inventory_sha256`. Its
sorted IDs must equal the plan's complete `probe_ids` and it permits only three
closed probe shapes: `public-https`, `direct-http`, and `tls-handshake`.
Public HTTPS and TLS use WebPKI hostname verification and an approved leaf DER
SHA-256; HTTP responses bind exact status and body SHA-256. Arbitrary commands,
redirects and shell expansion are not probe inputs.
Start from the deliberately invalid shape-only
[`bhtm-caddy-admin-uds-v1.site-inventory.json.example`](render-plan-skeletons/bhtm-caddy-admin-uds-v1.site-inventory.json.example),
replace every placeholder outside version control, canonicalize it, and bind
its exact bytes in the approved plan.

Before stop, the executor descriptor-reads every runtime/preimage pin, proves
the same boot/PID/InvocationID/process executable and argv, and hashes the
running Caddy image through the same `/proc/<MainPID>/exe` descriptor. It also
requires its `import.meta.url` to be the exact installed executor path and
binds both `process.execPath` and descriptor-read `/proc/self/exe` to the same
approved `/usr/bin/node` snapshot. It also requires empty `process.execArgv`,
the exact documented `/proc/self/cmdline` argument order, and no `NODE_*`,
dynamic-loader or OpenSSL trust-path control environment. Pinned
Caddy/Node/`setpriv` execution uses
the already-hashed descriptor rather than reopening its pathname. The executor
runs the exact plan-pinned Caddy adapter itself, validates the canonical
adapted-JSON tuple, runs `systemd-analyze verify`, and exclusively fsyncs
same-parent candidates plus root-only exact-byte backups. It never copies or
replaces the Caddy binary. Replacement keeps both old and prepared descriptors
open across the immediate pre-rename checks, verifies the inode transition,
then parent-fsyncs the atomic rename. The rendered-artifact gate carries the
executor as an exact full-source-hash-closed artifact beside the gate and
probe.

Static `systemd-analyze verify` and the direct Caddy container exercise do not
by themselves prove systemd PID 1 lifecycle behavior. The checked-in
`payment-v1-caddy-admin-uds-systemd.test.sh` therefore refuses any host with an
existing unit, config or runtime path, installs the byte-exact fixtures on an
otherwise isolated Linux systemd PID 1, and proves two distinct cold
generations. It requires cold stop to remove the `RuntimeDirectory` and socket,
cold start to recreate both as root:root `0700`/`0200`, validates each real
systemd 32-hex `InvocationID` through the production gate, proves effective
zero core/swap limits and null output/error streams, UDS admin readback, absent
TCP 2019 and a same-PID UDS reload. This is staging compatibility
evidence, not target-host activation evidence: the target still needs the
approved plan, stopped-host inventory, complete UID probes, site probes,
transaction/rollback ceremony and committed receipt described above.

Plan and receipt schema v2 bind the complete drop-in inode/content pin before,
during and after the cold transition. Schema v1 plans and receipts are invalid;
they cannot be upgraded into authority by adding fields after the fact.

The dependent integrated-overlay executor additionally re-reads the current
effective systemd properties and `/proc` process identity around each admin
probe and immediately before each file exchange or reload. It requires the
exact fragment, the singleton approved drop-in and no environment files, the approved `ExecStart` and
UDS `ExecReload`, `NeedDaemonReload=no`, the reviewed runtime-directory,
identity, zero core/swap limits, null output/error streams, umask and
environment-name policy, and the exact MainPID argv/start
ticks with no process `CADDY_ADMIN`. Environment values are not placed in the
receipt. Stable before/after snapshots bind those checks to the same boot,
unit generation and process. This closes a no-op reload or additional/drop-in
bypass for the overlay; it is not a substitute for a target-host run and its
real PID 1 evidence.

## Outcome taxonomy, rollback and fail-closed behavior

The executor reports three disjoint transaction regions:

- `pre-stop-failed-no-active-mutation`: the old generation and active
  Caddyfile/unit pins were still before the stop-request boundary. Prepared
  candidates, backups or journal records may exist, but the executor had not
  asked systemd to stop the service and did not replace either active path.
- `stopped-pre-start-failed-rolled-back`: stop was proven and candidate start
  had not been requested. Only an allowed exact old/candidate digest pair can
  authorize restoration of both exact old byte streams and approved
  owner/mode metadata, parent fsync, daemon-reload, a new old-config start, old
  TCP-admin readback equality and all old site probes.
- `outcome-unknown`: the candidate start request was issued, a rollback start
  became ambiguous, any requested stop returned an error without a complete
  stopped proof, the full inactive/socket/TCP stopped proof could not be
  repeated, the stopped pair was unclassified, a rollback-start journal could
  not be durably published, or durable receipt publication was uncertain. A
  stop command may continue asynchronously after a client timeout, so an old
  generation that merely still appears active never downgrades this case to
  pre-stop. No automatic candidate rollback or committed receipt is permitted.
  A best-effort recovery classification is written to
  `40-recovery-required.json`, printed by the CLI, and the exclusive lock is
  retained for explicit review.

Lock-release failure never overwrites the terminal classification. A verified
rollback error retains its rollback outcome plus a cleanup annotation. If the
receipt was already durably committed, the executor reports a typed
`committed` cleanup error with the receipt evidence instead of relabelling the
transaction as a pre-stop failure.

While the unit is stopped, classify only four exact digest pairs:

| Caddyfile/unit pair | Safe action before any start request |
| --- | --- |
| old / old | remain stopped or retry preparation |
| candidate / old | restore both exact old preimages, fsync, daemon-reload |
| candidate / candidate | continue only after all candidate and parent seals pass |
| old / candidate | restore both exact old preimages, fsync, daemon-reload |

Any other bytes or inode/parent drift leave the service stopped and require
manual review. Rollback always restores the exact old Caddyfile **and** old
unit, daemon-reloads, then starts a new old-config generation and re-runs the
old admin/site checks. After the potentially long site-probe sequence it again
requires the same boot, runtime pins, rollback generation, process, old admin
readback and old/old file pair before publishing the rolled-back terminal
record. Any drift is `outcome-unknown` and retains the lock. A mixed old/new
pair is never started.

After a candidate start request, any command error, missing new generation, unproven admin
readback, or uncertain receipt publication is `outcome-unknown`. Automatic
rollback is forbidden because the new Caddy may already be serving. First
classify the active generation, exact file pair, UDS/TCP state and receipt
durability. Until that explicit recovery completes, do not run the integrated
overlay and do not claim the hardening committed.

The precise old Caddyfile and unit backups are rollback authority for this
maintenance transaction. Losing either backup, its digest approval, or its
parent durability proof makes rollback unavailable; it does not authorize
reconstructing a plausible old file.

Overlay crash recovery validates persisted receipts without rewriting their
monotonic timestamps. Corrupt or cross-boot evidence whose saved `after`
window precedes the durable `before` window is rejected before journal
publication, file exchange or reload; recovery cannot make such evidence look
fresh by normalizing it in memory.

## Commands for offline validation and an explicitly approved local run

These commands are read-only with respect to the target host and require a
private, fully materialized plan plus exact copied preimage bytes:

```sh
node scripts/payment-v1-caddy-admin-uds-gate.mjs validate-plan \
  /absolute/private/plan.json \
  /absolute/private/old.Caddyfile \
  /absolute/private/old-bhtm-caddy.service \
  /absolute/private/preimage-adapted.json \
  /absolute/private/candidate-adapted.json \
  APPROVED_64_LOWER_HEX_PLAN_SHA256

node scripts/payment-v1-caddy-admin-uds-gate.mjs validate-receipt \
  /absolute/private/plan.json \
  /absolute/private/committed-receipt.json \
  APPROVED_64_LOWER_HEX_PLAN_SHA256 \
  TRUSTED_64_LOWER_HEX_RECEIPT_SHA256
```

Neither command writes candidates, invokes Caddy or contacts systemd. The two
adapted artifacts must be produced by the plan-pinned Caddy binary from the
exact old and candidate Caddyfile bytes respectively. The cold executor
independently adapts both exact byte strings and binds the old tuple to the live
TCP-admin readback before stop; merely supplying arbitrary JSON files to this
read-only gate does not prove their provenance. A passing result is not
deployment approval.

After installing and pinning the exact executor source, and only inside a
separately approved cold-maintenance window on the target host, its interface
is:

```sh
/usr/bin/env -i LANG=C LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin \
  /usr/bin/node \
  /usr/local/libexec/bitcoinpir/payment-v1-caddy-admin-uds-transaction.mjs \
  execute \
  --plan /absolute/private/plan.json \
  --site-inventory /absolute/private/site-inventory.json \
  --approved-plan-sha256 APPROVED_64_LOWER_HEX_PLAN_SHA256
```

This documents the closed interface; it does not authorize a run. Do not
invoke it over SSH until the outage, rollback authority, exact private inputs
and current-host prerequisites receive separate approval.
The trusted root launcher must establish the clean environment before Node
starts: a `--require`/`--import`, inspector flag, `NODE_OPTIONS` or
`LD_PRELOAD` can execute before JavaScript self-checks run. The executor detects
and refuses such a launch before its own maintenance mutation, but that cannot
retroactively make a compromised launcher or preload harmless.
