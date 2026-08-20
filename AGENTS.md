# BitcoinPIR agent instructions

## Delivery priority

- Finish the smallest useful implementation and its user-facing path before
  adding audit, reproducibility, or defence-in-depth machinery.
- Only P0/P1 correctness or user-safety defects block delivery. Record P2/P3
  work instead of silently expanding the task.
- Do not invent a new security property, proof obligation, or CI gate unless
  the user explicitly asks for it or an existing production contract requires
  it.

## 成熟路径与模型分工

- 默认沿用已验证的构造路径、工具和流程；不得为探索性、便利性或模型偏好引入替代方案。
- `gpt-5.6-sol` 默认不得编写实现代码、改变成熟构造路径或新增工具流程；实现工作由 Terra 完成。
- 仅当用户明确授权，且 Terra 已用具体证据证明原路径不能满足当前需求时，才可例外；例外仅限解决该不足所必需的最小范围。
- 任何偏离既有路径的提议，必须先说明原路径的具体不足、支持证据及最小差异；未经此说明不得实施。
- 部署仅可执行已合并、已冻结且已有成熟运行路径的代码或工件；发现缺失源码能力或需要新增诊断、部署工具时，立即停止部署，转为独立开发任务，未经再次授权不得在部署窗口内边写边试。
- 构建、发布、VPSBG 和生产配置等部署任务默认由单一 Terra 代理端到端执行；Sol 仅可限定用户授权范围、汇总证据并在阻塞时暂停，不得穿插命令、临时改方案或接管执行。

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
