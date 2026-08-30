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
- Start with `cargo check --locked --offline -p <crate>`. On failure, rerun
  one test with `-- --exact <name> --nocapture`. Do not escalate to a wider
  suite, a second crate, or a CI lane.
- Forbidden unless the user names them: `gh run watch`, polling `gh run list`,
  `sleep` loops waiting on CI, local `scripts/payment-v1-ci-lane.sh` full
  matrix, production or browser tests, local EasyCrypt / formal-proof runs.
- At most one background cargo job. Process e2e tests must be serial.
- No production/browser tests unless the user explicitly asks.

## Structure

- Do not add new types or protocol arms to a `.rs` file already over 1500
  lines. Extract a module first.
- New tests go in `src/foo/tests.rs` or crate `tests/`, not in the
  implementation file.
- The Payment V1 `legacy/` tree is deleted. Do not resurrect signed-policy,
  clearing, directory, or PoW types.
- Padding / Merkle-symmetry changes must run the existing symmetry tests,
  not just `cargo check`.

## Debug

- Read rustc errors and `PirError::kind` first.
- Do not add per-query logs on the production path.
- Request-level logs only via the existing `test-only-unsafe-query-logging`
  feature, and only when the user asks for local diagnostics.

## Bounded work

- Before any long build, upload, or data transform: state expected duration,
  a hard stop, and the observable progress signal. Missing progress means the
  hypothesis is probably wrong — stop and report rather than push on.
- When a stated success/stop condition is reached, stop. Do not roll into the
  next phase without authorization.

## Production and data

- Every production operation starts at
  [`docs/PRODUCTION_OPERATIONS.md`](docs/PRODUCTION_OPERATIONS.md).
  Pick one numbered flow (A–I). Upload, switch, reboot, rollback,
  Pages deploy, and funds all require explicit authorization per step.
- VPSBG measured-boot operations use `scripts/vpsbg-measured-boot.sh` (API),
  not SSH. VPSBG data-disk edits use `scripts/vpsbg-data-disk.sh`.
- Read [`docs/DATABASE_ARTIFACT_RETENTION.md`](docs/DATABASE_ARTIFACT_RETENTION.md)
  before touching database or ORAM artifacts.

## Git

- New branches use the `codex/` prefix. Keep commits and PRs narrow; do not
  mix production mutations with documentation cleanup.
- Preserve dirty or untracked work; delete a branch/worktree only after
  proving it is merged and clean.
