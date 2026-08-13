# Git cleanup record — 2026-08-13

This is a point-in-time cleanup record, not a list of active work.

Removed after fetching/pruning and proving the heads were ancestors of
`origin/main`:

- 81 local branches whose commits were either ancestors of `origin/main` or
  exact merged-PR heads;
- 9 merged remote branches;
- the clean `BitcoinPIR-fix-tier3-policy` worktree;
- the clean detached `BitcoinPIR-release-98bc49cc` worktree.

No open PR head was removed. Dependabot PRs 169–171 were the only open PRs at
the time of cleanup and were left untouched.

The following worktrees were deliberately retained because they contained
uncommitted changes or commits not merged into `origin/main`:

- `payment-v1-cln-loader-maps-evidence`;
- `payment-v1-integrated-cold-evidence`;
- `payment-v1-signet-core-replay-v2` (including unresolved conflicts);
- `payment-v1-uki-release-gate`;
- `service-admission-smoke`;
- the four `.claude/worktrees/agent-*` worktrees.

The main checkout's pre-existing modified formal-proof record was preserved in
a stash named `preserve pre-cleanup formal proof record 2026-08-13` before the
checkout was fast-forwarded to `origin/main`. Do not drop that stash until its
older proof record has been intentionally accepted or discarded.

The safe cleanup rule is now in the repository `AGENTS.md`: a worktree/branch
must be clean, merged, and unrelated to an open PR before removal.
