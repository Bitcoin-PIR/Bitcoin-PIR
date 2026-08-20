# BitcoinPIR agent instructions

## Delivery

- Deliver the smallest useful implementation and its user-facing path first.
- Treat P0/P1 correctness and user-safety issues as release blockers; record
  lower-priority follow-up work without expanding the current task.
- Add a security property, proof obligation, or CI gate only when a production
  contract or the user requires it.

## Long operations

- Before a long build, upload, database transform, or production test, state
  the expected duration, hard stop, and observable progress signal.
- If Direct ORAM has no stage progress for three minutes, reassess; target ten
  minutes and stop at fifteen unless its runbook sets a narrower limit.
- Report when the stated success or stop condition is reached. Confirm the
  authorization for each subsequent deployment or rebuild action.

## Testing

- Use the browserless quick/PR profiles in `docs/TESTING.md` by default.
- Run production browser checks when the user requests a browser test.
- Prefer a short automated entry point that keeps backend results independent.

## Production and data

- Start at `docs/PRODUCTION_OPERATIONS.md` and update
  `docs/CURRENT_PRODUCTION_STATE.md` after an authorized operation.
- Run the ordered Payment/UKI/VPSBG path through the
  [production workflow skill](.agents/skills/bitcoinpir-production-workflow/SKILL.md).
- Use [the VPSBG measured-boot skill](.agents/skills/vpsbg-measured-boot/SKILL.md)
  and the VPSBG runbook for image inspection and changes.
- Before rebuilding database or ORAM artifacts, read
  `docs/DATABASE_ARTIFACT_RETENTION.md` and retain the locked raw snapshots,
  Direct ORAM inputs, server manifests, and V2 evidence at its listed
  locations.
- Treat mutable ORAM pages as derived runtime state; retain their source inputs
  and manifests as the release evidence.

## Git hygiene

- Preserve dirty and untracked work.
- Remove a branch or worktree after confirming it is clean, merged into
  `origin/main`, and not the head of an open pull request.
- Use `codex/` for new branches. Keep commits and pull requests narrow.
