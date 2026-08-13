# BitcoinPIR agent instructions

## Delivery priority

- Finish the smallest useful implementation and its user-facing path before
  adding audit, reproducibility, or defence-in-depth machinery.
- Only P0/P1 correctness or user-safety defects block delivery. Record P2/P3
  work instead of silently expanding the task.
- Do not invent a new security property, proof obligation, or CI gate unless
  the user explicitly asks for it or an existing production contract requires
  it.

## Bounded investigation

- Before a long build, upload, database transform, or production test, state an
  expected duration, a hard stop, and the observable progress signal.
- Treat missing progress as evidence that the current hypothesis may be wrong.
  For Direct ORAM debugging, stop after three minutes without stage progress;
  target ten minutes and use a fifteen-minute hard stop unless a reviewed
  runbook gives a narrower bound.
- When a stated success/stop condition is reached, stop and report it. Do not
  continue into the next deployment or rebuild phase without authorization.

## Testing

- Use the browserless quick/PR profiles in `docs/TESTING.md` by default.
- Do not run production browser checks unless the user explicitly asks for a
  browser test. Test backends independently so one failure does not hide the
  others.
- Prefer one short automated entry point over asking an agent to follow a long
  manual checklist.

## Production and data

- Start at `docs/PRODUCTION_OPERATIONS.md`; do not diagnose a production 502 by
  immediately opening a browser or guessing from old logs.
- VPSBG measured-boot operations use the repository skill and API, not SSH.
  Upload, switch, reboot, rollback, deployment, and funds all require explicit
  authorization.
- Before rebuilding database or ORAM artifacts, read
  `docs/DATABASE_ARTIFACT_RETENTION.md`. Preserve the locked raw snapshots,
  Direct ORAM inputs, exact server manifests, and small V2 evidence on both the
  external Bitcoin volume and the Hetzner archive host.
- Mutable ORAM page files are derived runtime state. Do not confuse them with
  the retained source inputs or make their byte hashes a browser trust gate.

## Git hygiene

- Preserve dirty and untracked work. Remove a branch or worktree only after
  proving it is clean, merged into `origin/main`, and not the head of an open
  pull request.
- Use `codex/` for new branches. Keep commits and pull requests narrow, and do
  not mix production mutations with documentation cleanup.
