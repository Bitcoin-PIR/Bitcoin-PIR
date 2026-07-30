# Payment V1 host core-pattern ceremony

This ceremony is the only reviewed path in this repository for changing the
host-wide Linux core-dump policy required by the Payment V1 edge evidence. It
is deliberately independent from Caddy, HAProxy, relay, issuer and provider
transactions. Those executors must never write `kernel.core_pattern`, edit
`/etc/default/apport`, or manage `apport.service`.

The target is exact:

```text
kernel.core_pattern=|/usr/bin/false
```

## Host-wide risk and approval boundary

This is not a Payment V1-only setting. A successful application disables native
core diagnostics for **every process on the host**, disables and stops Apport,
and prevents new `/var/crash` reports. That removes a useful incident-debugging
and postmortem channel for Caddy, Payment V1, SSH, the kernel-facing userspace
and every unrelated service. External health probes, systemd state and bounded
non-request-bearing metrics must replace that diagnostic channel.

The same change closes a host-wide secret/correlation path: a pipe-style core
handler can run even when a service has `LimitCORE=0`, and a dump can contain
keys, invoices, credentials, peer addresses, timing data or request material.
This V1 ceremony therefore chooses privacy over native crash diagnostics.

The exact canonical technical plan is not authorization. Application requires a
second canonical approval document with all four fixed risk acknowledgements,
the exact plan digest, exact executor-source digest, an affirmative decision and
a validity window of at most 24 hours. Restoring Apport and the old core handler
requires a different rollback approval that also binds the committed receipt.
Neither approval authorizes a reboot, any Payment V1/Caddy activation, deletion
of old crash files, or journal cleanup.

## Confirmed and still-to-be-materialized Hetzner preimage

The read-only 2026-07-30 observation used to design this ceremony recorded:

- Ubuntu with systemd 255;
- `apport.service` active and enabled;
- exact `/etc/default/apport` bytes `enabled=1\n`;
- exact live value
  `|/usr/share/apport/apport -p%p -s%s -c%c -d%d -P%P -u%u -g%g -F%F -- %E`;
- an absent
  `/etc/sysctl.d/99-z-bitcoinpir-payment-v1-no-core.conf`; and
- an empty `/var/crash` directory.

These observations are not an executable plan. Immediately before approval, a
local owner-only materialization must bind the current boot ID, machine-ID file
digest, `/etc/os-release`, exact first `systemctl --version` line, exact Apport
substate and unit fragment, the four runtime executables, and every existing
`kernel.core_pattern` assignment file. Every file pin includes path, bytes hash,
size, owner, group, mode and link count. Any observation that differs from the
plan fails before mutation. Apport must have no drop-ins and
`NeedDaemonReload=no`, so the pinned fragment is the loaded service definition.

V1 accepts only an empty `/var/crash` inventory. If a crash file appears, do not
delete or move it to make the plan pass. Stop and design a new evidence format
that pins existing crash objects without exposing their content. The ceremony
never clears `/var/crash`, journald or any other historical diagnostic data.

## Persistent-policy constraint

The executor scans all `.conf` files beneath `/etc/sysctl.d`, `/run/sysctl.d`,
`/usr/local/lib/sysctl.d`, `/usr/lib/sysctl.d` and `/lib/sysctl.d`, plus legacy
`/etc/sysctl.conf`, for either dotted or slash-form `kernel.core_pattern`
assignments. The canonical plan must pin the complete observed set.
Same-basename files follow systemd's `/etc` -> `/run` -> `/usr/local/lib` ->
`/usr/lib` priority; an exact `/dev/null` mask is honored, while other symlinked
inputs are rejected.

The candidate filename is fixed to
`99-z-bitcoinpir-payment-v1-no-core.conf`. An existing assignment whose basename
sorts at or after that filename is rejected. Any assignment in
`/etc/sysctl.conf` is rejected because a later `sysctl --system` invocation can
give it different precedence. The candidate file is root-owned `0644`, contains
only `kernel.core_pattern=|/usr/bin/false\n`, and is atomically published before
the live sysctl changes. Runtime evidence still checks the live value on every
activation; persistence is not permission to skip readback.

## Transaction and durability order

`scripts/payment-v1-core-pattern-ceremony.mjs` executes this apply sequence:

1. strictly parse canonical plan and approval bytes and compare all three
   externally supplied SHA-256 digests (plan, approval and executor source);
2. require Linux EUID 0, the exact boot/host/systemd/tool closure and the exact
   active/enabled Apport preimage;
3. acquire the root-only host-global lock and repeat the complete preimage read;
4. durably publish the persistent sysctl candidate with no-clobber semantics;
5. atomically replace exact `enabled=1\n` with exact `enabled=0\n`;
6. disable (but do not yet stop) `apport.service`;
7. write `|/usr/bin/false` directly to `/proc/sys/kernel/core_pattern` and
   immediately read it back;
8. stop Apport, reapply and read back `|/usr/bin/false` in case the stop helper
   touched the sysctl, then re-read the complete candidate state; and
9. atomically publish a root-only committed receipt before releasing the lock.

Files are staged on the target filesystem, file-synced, atomically linked or
renamed, and followed by a parent-directory sync. The executor never invokes a
shell, package manager, `sysctl --system`, reboot, Caddy command, Payment V1
service activation, crash cleanup or journal cleanup. Only an explicitly
approved rollback can start Apport itself.

The chosen order avoids two important windows. The boot-persistent safe policy
exists before any service change, and the live safe handler is applied both
before and after Apport is stopped. Disabling a unit is not treated as disabling
the kernel pipe handler, and an Apport stop helper is not trusted to preserve it.

## Failure and recovery semantics

Before the first mutation, any mismatch releases the lock and returns
`preflight-failed`. After mutation begins, the executor does **not** automatically
restore the privacy-weaker Apport preimage. It independently attempts to:

- install the safe persistent policy;
- set `/etc/default/apport` to `enabled=0`;
- apply the safe live core pattern;
- stop Apport; and
- disable Apport.

If the complete candidate is then exact, the outcome is
`contained-needs-recovery`; otherwise it is `outcome-unknown`. Both retain the
root-only lock and publish no committed receipt. Never delete that lock by hand
and rerun `apply`. After inspecting the phase records, `recover-commit` may be
used with the same exact plan and still-valid apply approval only when the
complete candidate is exact. A mixed state remains locked for manual security
review.

A committed receipt is terminal. If only lock release fails after receipt
publication, the result is `committed-lock-retained`; do not apply again.

## Explicit rollback

Rollback starts only from an exact committed candidate and requires:

- the exact canonical plan and executor source digests;
- the exact committed-receipt digest; and
- a fresh rollback approval, valid for at most 24 hours, that binds all three.

It atomically restores exact `enabled=1\n`, enables and starts Apport while the
safe handler is still live, restores the exact old apport pipe, then removes the
persistent safe-policy file. It verifies the complete original state before
publishing a separate rollback receipt. Any failure after rollback mutation
begins re-applies the safe candidate and keeps the lock. Thus an uncertain
rollback fails closed instead of leaving an unverified diagnostic path active.

Rollback restores native crash diagnostics and their secret/correlation risk;
it is not an ordinary operational toggle.

## Materialization and commands

Start from the deliberately unusable skeletons:

- `render-plan-skeletons/core-pattern-ceremony-v1.plan.json.example`;
- `render-plan-skeletons/core-pattern-ceremony-v1.apply-approval.json.example`;
- `render-plan-skeletons/core-pattern-ceremony-v1.rollback-approval.json.example`.

Materialize canonical JSON in an owner-only directory outside Git. Install the
reviewed executor at exact root-owned mode `0555` under
`/usr/local/libexec/bitcoinpir/`. Transfer every full digest independently from
the plan bytes. The installed executor can collect a canonical technical plan
without mutation; the output file is still not authorization:

```sh
umask 077
/usr/bin/node \
  /usr/local/libexec/bitcoinpir/payment-v1-core-pattern-ceremony.mjs \
  observe-plan --ceremony-id "$FRESH_CEREMONY_ID" \
  > /root/owner-only/core-pattern.plan.json
```

`observe-plan` requires Linux EUID 0 and the exact installed Node/source paths,
then refuses every preimage outside the V1 closed state. Review and transfer the
resulting digest out of band. Validation is non-mutating:

```sh
/usr/bin/node \
  /usr/local/libexec/bitcoinpir/payment-v1-core-pattern-ceremony.mjs \
  validate-plan \
  --plan /root/owner-only/core-pattern.plan.json \
  --approved-plan-sha256 "$PLAN_SHA256" \
  --approved-source-sha256 "$EXECUTOR_SHA256"
```

Application, recovery and rollback are intentionally shown only as interface
shapes; filling the variables is the separate production approval step:

```sh
# Apply
/usr/bin/node /usr/local/libexec/bitcoinpir/payment-v1-core-pattern-ceremony.mjs \
  apply --plan "$PLAN" --approved-plan-sha256 "$PLAN_SHA256" \
  --approved-source-sha256 "$EXECUTOR_SHA256" \
  --approval "$APPLY_APPROVAL" \
  --approved-approval-sha256 "$APPLY_APPROVAL_SHA256"

# Recover only an exact contained candidate
/usr/bin/node /usr/local/libexec/bitcoinpir/payment-v1-core-pattern-ceremony.mjs \
  recover-commit --plan "$PLAN" --approved-plan-sha256 "$PLAN_SHA256" \
  --approved-source-sha256 "$EXECUTOR_SHA256" \
  --approval "$APPLY_APPROVAL" \
  --approved-approval-sha256 "$APPLY_APPROVAL_SHA256"

# Roll back only with a separately approved receipt-bound document
/usr/bin/node /usr/local/libexec/bitcoinpir/payment-v1-core-pattern-ceremony.mjs \
  rollback --plan "$PLAN" --approved-plan-sha256 "$PLAN_SHA256" \
  --approved-source-sha256 "$EXECUTOR_SHA256" \
  --approved-receipt-sha256 "$COMMITTED_RECEIPT_SHA256" \
  --rollback-approval "$ROLLBACK_APPROVAL" \
  --approved-rollback-approval-sha256 "$ROLLBACK_APPROVAL_SHA256"
```

This repository slice supplies code, documentation and negative tests only. It
does not authorize or perform a remote install or host mutation.
