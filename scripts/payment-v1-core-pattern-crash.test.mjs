import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import {
  APPORT_SYSCTLS,
  TARGET_CORE_PATTERN,
  TARGET_SYSCTLS,
  canonicalJson,
  expectedCandidate,
  expectedPreimage,
} from "./payment-v1-core-pattern-ceremony.mjs";
import { fixturePlan } from "./payment-v1-core-pattern-test-fixture.mjs";

const WORKER = new URL("./payment-v1-core-pattern-crash-worker.mjs", import.meta.url);

function runWorker(mode, statePath, boundary, signal) {
  const args = [WORKER.pathname, mode, statePath];
  if (boundary !== undefined) args.push(boundary, signal);
  return spawnSync(process.execPath, args, {
    encoding: "utf8",
    env: { LANG: "C", LC_ALL: "C", PATH: process.env.PATH },
    timeout: 15_000,
  });
}

function readState(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

const APPLY_BOUNDARIES = [
  "create-preflight",
  "create-pending",
  "ensure-coredump-admin-masks",
  "install-persistent",
  "write:kernel.core_pattern=" + TARGET_CORE_PATTERN,
  "write:fs.suid_dumpable=0",
  "write:kernel.core_pipe_limit=0",
  "ensure-apport-mask",
  "remove-apport-enablement",
  "write-pending",
  "publish-receipt-after-full-inspection",
  "terminal-remove-guard",
  "terminal-clear-pending",
  "terminal-clear-preflight",
  "release-lock",
];

const ROLLBACK_BOUNDARIES = [
  "create-preflight",
  "create-pending",
  "install-persistent",
  "write:kernel.core_pattern=" + TARGET_CORE_PATTERN,
  "write:fs.suid_dumpable=0",
  "write:kernel.core_pipe_limit=0",
  "ensure-apport-enablement",
  "write:kernel.core_pipe_limit=10",
  "write:fs.suid_dumpable=2",
  "write:kernel.core_pattern=" + APPORT_SYSCTLS["kernel.core_pattern"],
  "remove-coredump-admin-masks",
  "remove-persistent",
  "remove-apport-mask",
  "write-pending",
  "publish-rollback-receipt-after-full-inspection",
  "terminal-remove-guard",
  "terminal-clear-pending",
  "terminal-clear-preflight",
  "release-lock",
];

const SIGNALS = ["SIGTERM", "SIGKILL", "SIGABRT"];

function rebootAndRead(statePath, expectedSysctls) {
  const rebooted = runWorker("reboot", statePath);
  assert.equal(rebooted.status, 0, rebooted.stderr);
  const state = readState(statePath);
  assert.deepEqual(state.state.sysctls, expectedSysctls);
  return state;
}

test("hard SIGKILL after apply lease publication requires official lease-bound recovery", () => {
  const root = mkdtempSync(join(tmpdir(), "bitcoinpir-core-preflight-crash-"));
  const statePath = join(root, "state.json");
  try {
    const crashed = runWorker("apply", statePath, "acquire-lock", "SIGKILL");
    assert.notEqual(crashed.status, 0);
    const afterCrash = readState(statePath);
    assert.equal(afterCrash.locked, true);
    assert.equal(afterCrash.pending, null);
    assert.equal(canonicalJson(afterCrash.state), canonicalJson(expectedPreimage(fixturePlan())));
    const replay = runWorker("recover", statePath);
    assert.equal(replay.status, 0, replay.stderr);
    const final = readState(statePath);
    assert.equal(canonicalJson(final.state), canonicalJson(expectedCandidate(fixturePlan())));
    assert.equal(final.locked, false);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("hard SIGKILL after apply guard arm but before intent is inert on reboot and officially recoverable", () => {
  const root = mkdtempSync(join(tmpdir(), "bitcoinpir-core-pre-pending-guard-"));
  const statePath = join(root, "state.json");
  try {
    const crashed = runWorker("apply", statePath, "ensure-guard", "SIGKILL");
    assert.notEqual(crashed.status, 0);
    const afterBoot = rebootAndRead(statePath, APPORT_SYSCTLS);
    assert.equal(afterBoot.pending, null);
    const replay = runWorker("recover", statePath);
    assert.equal(replay.status, 0, replay.stderr);
    assert.deepEqual(readState(statePath).state.sysctls, TARGET_SYSCTLS);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("hard SIGTERM after rollback lease publication requires official lease-bound recovery", () => {
  const root = mkdtempSync(join(tmpdir(), "bitcoinpir-core-rollback-preflight-crash-"));
  const statePath = join(root, "state.json");
  try {
    const applied = runWorker("apply", statePath);
    assert.equal(applied.status, 0, applied.stderr);
    const crashed = runWorker("rollback", statePath, "acquire-lock", "SIGTERM");
    assert.notEqual(crashed.status, 0);
    const afterCrash = readState(statePath);
    assert.equal(afterCrash.locked, true);
    assert.equal(afterCrash.pending, null);
    assert.equal(canonicalJson(afterCrash.state), canonicalJson(expectedCandidate(fixturePlan())));
    const replay = runWorker("recover", statePath);
    assert.equal(replay.status, 0, replay.stderr);
    const final = readState(statePath);
    assert.equal(canonicalJson(final.state), canonicalJson(expectedPreimage(fixturePlan())));
    assert.equal(final.locked, false);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

for (const [index, boundary] of APPLY_BOUNDARIES.entries()) {
  const signal = SIGNALS[index % SIGNALS.length];
  test("hard " + signal + " apply boundary recovers without native core: " + boundary, () => {
    const root = mkdtempSync(join(tmpdir(), "bitcoinpir-core-crash-"));
    const statePath = join(root, "state.json");
    try {
      const crashed = runWorker("apply", statePath, boundary, signal);
      assert.notEqual(crashed.status, 0);
      rebootAndRead(statePath, TARGET_SYSCTLS);
      const recovered = runWorker("recover", statePath);
      assert.equal(recovered.status, 0, recovered.stderr);
      const final = readState(statePath);
      assert.equal(
        canonicalJson(final.state),
        canonicalJson(expectedCandidate(fixturePlan())),
      );
      assert.deepEqual(final.state.sysctls, TARGET_SYSCTLS);
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  });
}

test("hard SIGABRT after rollback guard arm but before intent stays exact-safe and recovers officially", () => {
  const root = mkdtempSync(join(tmpdir(), "bitcoinpir-core-rollback-pre-pending-guard-"));
  const statePath = join(root, "state.json");
  try {
    const applied = runWorker("apply", statePath);
    assert.equal(applied.status, 0, applied.stderr);
    const crashed = runWorker("rollback", statePath, "ensure-guard", "SIGABRT");
    assert.notEqual(crashed.status, 0);
    rebootAndRead(statePath, TARGET_SYSCTLS);
    const replay = runWorker("recover", statePath);
    assert.equal(replay.status, 0, replay.stderr);
    assert.deepEqual(readState(statePath).state.sysctls, APPORT_SYSCTLS);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

for (const [index, boundary] of ROLLBACK_BOUNDARIES.entries()) {
  const signal = SIGNALS[(index + 1) % SIGNALS.length];
  test("hard " + signal + " rollback boundary resumes exact approved rollback: " + boundary, () => {
    const root = mkdtempSync(join(tmpdir(), "bitcoinpir-core-rollback-crash-"));
    const statePath = join(root, "state.json");
    try {
      const applied = runWorker("apply", statePath);
      assert.equal(applied.status, 0, applied.stderr);
      const crashed = runWorker("rollback", statePath, boundary, signal);
      assert.notEqual(crashed.status, 0);
      const terminalPreflightCleared = boundary === "terminal-clear-preflight" ||
        boundary === "terminal-remove-guard" || boundary === "release-lock";
      rebootAndRead(statePath, terminalPreflightCleared ? APPORT_SYSCTLS : TARGET_SYSCTLS);
      const recovered = runWorker("recover", statePath);
      assert.equal(recovered.status, 0, recovered.stderr);
      const final = readState(statePath);
      assert.equal(
        canonicalJson(final.state),
        canonicalJson(expectedPreimage(fixturePlan())),
      );
      assert.deepEqual(final.state.sysctls, APPORT_SYSCTLS);
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  });
}
