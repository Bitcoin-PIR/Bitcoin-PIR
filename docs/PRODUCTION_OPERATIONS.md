# Production operations

This is the operator/agent entry point. It routes observation and authorized
release work; it is not deployment authorization.

## Status first

Run this before a browser, `502`, or log search:

```bash
scripts/vpsbg-production-status.sh
```

The default path makes read-only GET requests to the VPSBG control plane and
`https://weikeng2.bitcoinpir.org/status.json`; it never uses SSH. Its current
facts are control-plane state, boot mode, and attached image.

`/status.json` is temporary: Direct ORAM build/switch exposes it from a
loopback HTTP origin. Once `unified_server` owns port 8091, it is expected to
be unavailable; the command still returns control-plane state and marks ORAM
fields `unavailable`. Runtime profile, measurement, attestation, generation,
database identity, and any unavailable field must not be inferred. `--root`
reads an offline evidence directory for fixtures or post-incident review only.

## Release routes

Web publication only uses manual `deploy-web.yml` dispatch from `main` with
its production confirmation; use the workflow deployment record as release
evidence.

VPSBG release and rollback use the measured-boot procedure in the
[VPSBG measured-boot skill](../.agents/skills/vpsbg-measured-boot/SKILL.md).
Use the reported attached image as the rollback reference; do not substitute a
historical preflight for current state.

Production Tier 3 builds must set `BPIR_TIER3_SERVICE_POLICY` to the exact
currently approved signed policy. The build fails when it is missing and
rejects anything except the reviewed digest locked in `build_uki_tier3.sh`; it
then verifies that the initramfs contains byte-identical policy data before
emitting an uploadable UKI. A policy-epoch rotation must update that source lock
in a reviewed change. Never rely on the mutable-rootfs policy fallback for a
new release.

Run a manual production canary only after a deliberate web or VPSBG release,
never as the first diagnostic step.

Mainnet Lightning activation is pending; source and functional-beta evidence
are not proof of a deployed mainnet Lightning service. See
[`docs/payment/IMPLEMENTATION_STATUS.md`](payment/IMPLEMENTATION_STATUS.md).

Historical preflights, incidents, and plans are evidence only; use the
[history index](history/README.md).
