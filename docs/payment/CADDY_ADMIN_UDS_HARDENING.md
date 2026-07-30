# Existing Caddy admin Unix-socket hardening

Status: reviewed-source candidate, **not activated**. This profile does not
authorize SSH, installation, a Caddy stop/start, public routing, or any other
host mutation. It contains a read-only plan/receipt gate and deterministic
candidate builders; it deliberately contains no installation executor.

## Scope and boundary

`bhtm-caddy-admin-uds-v1` is a maintenance prerequisite for the existing root
`bhtm-caddy.service`. It migrates only the Caddy admin endpoint from
`127.0.0.1:2019` (explicit or Caddy's equivalent implicit default) to:

```text
unix//run/bitcoinpir-caddy-admin/admin.sock|0200
```

The hardened unit must run as `root:root`, have no drop-ins, expose no
`CADDY_ADMIN` environment value, and read back these exact properties:

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

Start from a fresh descriptor-bound inventory of `/usr/bin/caddy`,
`/etc/caddy/Caddyfile`, `/etc/systemd/system/bhtm-caddy.service`, the active
unit generation, `/usr/bin/node`, `/usr/bin/setpriv`, the installed probe, and
the installed hardening gate. Fill
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
`LimitCORE`, `MemorySwapMax`, `StandardOutput` and `StandardError` are
deliberately replaced rather than rejected because closing the existing dump,
swap and journald paths is part of this migration. `LimitCORE=0` does not make
a Linux pipe core handler safe by itself; target activation still requires the
separate exact `kernel.core_pattern=|/usr/bin/false` host proof. The source-
hash/plan/approval-bound host transaction is specified in
[`CORE_PATTERN_CEREMONY.md`](CORE_PATTERN_CEREMONY.md); this Caddy gate and any
future Caddy executor remain forbidden from changing the sysctl or Apport.

ACME storage is not copied, renamed or reinitialized. The complete existing
site inventory and its before/after probes are separate approved plan inputs.
Preserving config bytes is not a claim that the wider existing root Caddy,
plugins, ACME account, or all sites become isolated. The canonical adapted JSON
must additionally have no top-level `logging`, HTTP-server `logs`, `log_append`
or `log_name` configuration. `StandardOutput=null` and `StandardError=null`
close only the implicit process-stream-to-journald path; they cannot neutralize
an explicit file, network or syslog sink in Caddy JSON, so such a sink is an
activation blocker.

The approved candidate records both the SHA-256 and byte length of the
admin-UDS gate's no-trailing-newline
`canonicalizeAdaptedCaddyJson(caddyAdaptOutput)` bytes. Offline `validate-plan`
canonicalizes the supplied adapter artifact, applies the privacy gate and
requires that exact tuple. The committed receipt's root `/config/` readback is
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

1. Hold the exact single-use lock and re-read the approved old binary,
   Caddyfile, unit, active PID, `InvocationID`, and site health.
2. Validate the deterministic candidates with the exact production Caddy
   binary, require the canonical adapted JSON's exact UDS `admin.listen`,
   privacy policy, digest and size, and run `systemd-analyze verify` on the
   candidate unit. Exclusively
   create and fsync exact old backups and both candidates.
3. Stop `bhtm-caddy.service`. Prove `inactive/dead`, no MainPID, no admin socket,
   and connection refusal on both `127.0.0.1:2019` and `[::1]:2019`.
4. While stopped, replace the Caddyfile and unit with the two exact approved
   candidates and fsync both parent directories. Partial pairs are never
   started.
5. Run `systemctl daemon-reload`, start the unit, and require a new
   `InvocationID` and active-enter timestamp. A systemd `InvocationID` is the
   exact nonzero 32-character lowercase hexadecimal value returned by
   `systemctl show`; it is not a hyphenated UUID. `restart` and warm `reload`
   are not substitutes for this proof.
   For an inactive unit the collector normalizes either an empty value or
   systemd's 32-zero sentinel to the receipt's canonical empty string.
6. Require `NeedDaemonReload=no`, the exact main fragment, no drop-ins, no
   effective `CADDY_ADMIN`, exact effective `LimitCORE=0`, `MemorySwapMax=0`,
   `StandardOutput=null` and `StandardError=null`, root API `GET /config/`
   success over the UDS with the same canonical adapted-JSON digest,
   root:root `0700` runtime directory, root:root `0200` socket, both TCP-2019
   probes refused, and `EACCES` from every non-root UID in the approved complete
   service inventory (including `pir` and `cloudflared`) after `setpriv` proves
   zero capabilities and only the requested primary group.
7. Re-run every approved existing-site probe. Only then exclusively create,
   fsync and parent-fsync a canonical mode-`0400` committed receipt.

The checked-in gate validates this plan and an already-collected committed
receipt. It does not perform these steps. A future executor must implement the
same crash-safe journal/publication standard as the integrated overlay before
any host run is proposed.

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

The dependent integrated-overlay executor additionally re-reads the current
effective systemd properties and `/proc` process identity around each admin
probe and immediately before each file exchange or reload. It requires the
exact fragment, no drop-ins or environment files, the approved `ExecStart` and
UDS `ExecReload`, `NeedDaemonReload=no`, the reviewed runtime-directory,
identity, zero core/swap limits, null output/error streams, umask and
environment-name policy, and the exact MainPID argv/start
ticks with no process `CADDY_ADMIN`. Environment values are not placed in the
receipt. Stable before/after snapshots bind those checks to the same boot,
unit generation and process. This closes a no-op reload or effective-drop-in
bypass for the overlay; it is not a substitute for the still-missing real PID
1 cold lifecycle gate above.

## Crash classification, rollback and fail-closed behavior

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
old admin/site checks. A mixed old/new pair is never started.

After a start request, any command error, missing new generation, unproven admin
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

## Commands for offline validation

These commands are read-only with respect to the target host and require a
private, fully materialized plan plus exact copied preimage bytes:

```sh
node scripts/payment-v1-caddy-admin-uds-gate.mjs validate-plan \
  /absolute/private/plan.json \
  /absolute/private/old.Caddyfile \
  /absolute/private/old-bhtm-caddy.service \
  /absolute/private/candidate-adapted.json \
  APPROVED_64_LOWER_HEX_PLAN_SHA256

node scripts/payment-v1-caddy-admin-uds-gate.mjs validate-receipt \
  /absolute/private/plan.json \
  /absolute/private/committed-receipt.json \
  APPROVED_64_LOWER_HEX_PLAN_SHA256 \
  TRUSTED_64_LOWER_HEX_RECEIPT_SHA256
```

Neither command writes candidates, invokes Caddy or contacts systemd. The
adapted artifact must be produced by the plan-pinned Caddy binary from the
exact candidate. The future cold executor must perform that operation itself
and bind the same tuple; merely supplying an arbitrary JSON file to this
read-only gate does not prove its provenance. A passing result is not
deployment approval.
