# Hetzner secondary retirement — 2026-08-18

Status: **completed and read back**.

This is point-in-time operational evidence. Current operations start at
[`../PRODUCTION_OPERATIONS.md`](../PRODUCTION_OPERATIONS.md).

## Decision

The operator selected these two boundaries:

1. Retire the legacy Hetzner `pir-secondary.service` on port 8092. Preserve
   its unit, binary, databases, and logs as evidence; do not treat it as a
   warm public fallback.
2. Keep the active Hetzner pir1 `c836e11a...` binary intentionally frozen.
   Revisit it when a DPF/Harmony/Onion db1 or payment-policy change requires a
   coordinated host release, or when a P0/P1 defect requires an earlier fix.
   A Direct ORAM-only change on pir2 does not trigger a pir1 rebuild.

## Pre-retirement evidence

Read-only checks immediately before the operation established:

- Host `pir` ran `pir-primary.service` on `127.0.0.1:8091`; the service was
  active and enabled.
- The same host ran `pir-secondary.service` on `*:8092` from
  `/home/pir/BitcoinPIR/target/release/unified_server`; its binary SHA-256 was
  `cc4ec24b9ecf54c962d20843a374a8235d9b71954adf05bdb4d6bb3155e16b1e`.
  The service was active but already disabled, so stopping it would not remove
  a boot-time dependency or allow it to return at reboot.
- `cloudflared.service` ordered itself after the secondary but did not require
  or want it. The reverse dependency query contained no dependent service.
- A direct external TCP probe could not reach the Hetzner host on port 8092.
- Public attestation identified `weikeng1.bitcoinpir.org` as the pinned
  `c836e11a...` Hetzner process and `weikeng2.bitcoinpir.org` as the pinned
  `4b05fc90...` measured VPSBG process. Neither public identity matched the
  legacy 8092 binary.
- The VPSBG control plane reported server 25285 active in measured boot with
  attached image 265.
- The host also ran a distinct loopback-only
  `bitcoinpir-provider-functional-beta-2.service` on port 8292. That process is
  part of the Payment functional-beta topology, is not `pir-secondary.service`,
  and was explicitly outside this retirement.

These checks establish that 8092 was neither a public provider nor required by
the active ingress process. They do not turn the old process into an approved
recovery artifact.

## Recovery replacement

For a pir2 incident:

1. Run `scripts/vpsbg-production-status.sh`.
2. Use the repository VPSBG measured-boot API procedure for an authorized
   rollback or release. Do not SSH to VPSBG and do not route traffic to the
   retired Hetzner process.
3. If a future topology decision requires a Hetzner replacement, create a new
   reviewed deployment with the then-current binary, Payment-V1 policy,
   identity, database pins, and a loopback-only origin. Changing public ingress
   and running the post-release canary each require explicit authorization.

The old 8092 unit, binary, database inputs, and logs remain retained for
forensics. Re-enabling the old unit is not a rollback procedure.

## Host operation

Authorized operation:

```text
systemctl disable --now pir-secondary.service
```

Post-operation state is recorded below after readback.

## Post-retirement readback

The command completed at 2026-08-18 00:55:53 UTC. Readback established:

- `pir-secondary.service`: `inactive`, `dead`, `disabled`, `MainPID=0`, and
  systemd `Result=success`. Its terminated main process reported status 15,
  the expected SIGTERM from the authorized stop.
- No process listened on port 8092. The retained old binary and data were not
  deleted.
- `pir-primary.service` and `cloudflared.service` remained active; the only
  listener in the 8091/8092 check was `127.0.0.1:8091`.
- Fresh public identity checks after the stop still matched the pinned
  `c836e11a...` Hetzner binary and the `4b05fc90...` VPSBG binary. VPSBG also
  returned the pinned image-265 launch measurement with matching REPORT_DATA.
- The VPSBG control plane remained active, reachable, running, and in measured
  boot on image 265.

No public ingress, pir1 binary, Payment functional-beta service, database,
policy, identity, VPSBG image, or retained artifact was changed.
