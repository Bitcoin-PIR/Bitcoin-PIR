# BitcoinPIR agent instructions

Project background and invariants: [`CLAUDE.md`](CLAUDE.md).
Documentation index: [`docs/README.md`](docs/README.md).

## Delivery

- Finish the smallest useful implementation and its user-facing path first.
  Only P0/P1 correctness or user-safety defects block delivery.
- Do not invent new security properties, proof obligations, CI gates, audit
  scripts, or status documents. If you believe one is needed, propose it and
  stop.
- Documentation rule: prose documents describe *how things work now*. Dated
  evidence goes to `docs/history/` or git history. Never copy identity values
  (hashes, image IDs, measurements) into prose — link
  `web/src/attest-pin.ts` or query live state.

## Testing

- Pick checks by change class from [`docs/TESTING.md`](docs/TESTING.md).
  Run the narrowest matching check, not the whole world.
- No production/browser tests unless the user explicitly asks.

## Bounded work

- Before any long build, upload, or data transform: state expected duration,
  a hard stop, and the observable progress signal. Missing progress means the
  hypothesis is probably wrong — stop and report rather than push on.
- When a stated success/stop condition is reached, stop. Do not roll into the
  next phase without authorization.

## Production and data

- Every production operation starts at
  [`docs/PRODUCTION_OPERATIONS.md`](docs/PRODUCTION_OPERATIONS.md).
  Upload, switch, reboot, rollback, deployment, and funds all require
  explicit authorization per run.
- VPSBG measured-boot operations use `scripts/vpsbg-measured-boot.sh` (API),
  not SSH.
- Read [`docs/DATABASE_ARTIFACT_RETENTION.md`](docs/DATABASE_ARTIFACT_RETENTION.md)
  before touching database or ORAM artifacts.

## Git

- New branches use the `codex/` prefix. Keep commits and PRs narrow; do not
  mix production mutations with documentation cleanup.
- Preserve dirty or untracked work; delete a branch/worktree only after
  proving it is merged and clean.
