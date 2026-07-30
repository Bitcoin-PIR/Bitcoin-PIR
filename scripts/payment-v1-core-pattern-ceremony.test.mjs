import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  APPORT_DEFAULT_PATH,
  APPORT_UNIT,
  APPLY_ACKNOWLEDGEMENTS,
  APPLY_APPROVAL_KIND,
  CEREMONY_KIND,
  CeremonyError,
  EXECUTOR_PATH,
  PERSISTENT_POLICY_PATH,
  RECEIPT_KIND,
  ROLLBACK_ACKNOWLEDGEMENTS,
  ROLLBACK_APPROVAL_KIND,
  ROLLBACK_RECEIPT_KIND,
  TARGET_CORE_PATTERN,
  applyCeremony,
  canonicalJson,
  expectedCandidate,
  expectedPreimage,
  planSha256,
  recoverCommittedCandidate,
  rollbackCeremony,
  scanCorePatternAssignments,
  sha256,
  validateApplyApproval,
  validatePlan,
  validateRollbackApproval,
} from "./payment-v1-core-pattern-ceremony.mjs";

const SCRIPT = new URL("./payment-v1-core-pattern-ceremony.mjs", import.meta.url);
const FIXED_NOW = Date.parse("2026-07-30T08:30:00Z");

function hash(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function pin(path, bytes, mode = "0644", { gid = 0, uid = 0 } = {}) {
  const body = Buffer.from(bytes);
  return {
    gid,
    mode,
    nlink: 1,
    path,
    sha256: hash(body),
    size: body.length,
    uid,
  };
}

function embeddedPin(path, bytes, mode = "0644") {
  return { ...pin(path, bytes, mode), bytes_base64: Buffer.from(bytes).toString("base64") };
}

function executablePin(path, label, shaOverride) {
  const value = pin(path, `${label}\n`, "0555");
  if (shaOverride !== undefined) value.sha256 = shaOverride;
  return value;
}

function fixturePlan({ sourceSha256 = "a".repeat(64) } = {}) {
  const ceremonyId = "hetzner-core-pattern-20260730-a";
  const apportPattern =
    "|/usr/share/apport/apport -p%p -s%s -c%c -d%d -P%P -u%u -g%g -F%F -- %E";
  return {
    candidate: {
      apport_default: embeddedPin(APPORT_DEFAULT_PATH, "enabled=0\n"),
      core_pattern: TARGET_CORE_PATTERN,
      persistent_policy: embeddedPin(
        PERSISTENT_POLICY_PATH,
        `kernel.core_pattern=${TARGET_CORE_PATTERN}\n`,
      ),
    },
    ceremony_id: ceremonyId,
    executor: {
      false_handler: executablePin("/usr/bin/false", "false"),
      node: executablePin("/usr/bin/node", "node"),
      source: executablePin(EXECUTOR_PATH, "source", sourceSha256),
      systemctl: executablePin("/usr/bin/systemctl", "systemctl"),
    },
    host: {
      boot_id: "14d184fd-83ce-435d-ab4d-116f00a98dcc",
      machine_id_sha256: "9".repeat(64),
      os_release: pin("/usr/lib/os-release", "ubuntu\n"),
      systemd_version: "systemd 255 (255.4-1ubuntu8.15)",
    },
    kind: CEREMONY_KIND,
    preimage: {
      apport_default: embeddedPin(APPORT_DEFAULT_PATH, "enabled=1\n"),
      apport_service: {
        active_state: "active",
        dropin_paths: [],
        fragment: pin("/usr/lib/systemd/system/apport.service", "unit\n"),
        load_state: "loaded",
        name: APPORT_UNIT,
        need_daemon_reload: "no",
        sub_state: "exited",
        unit_file_state: "enabled",
      },
      core_pattern: apportPattern,
      core_pattern_assignment_files: [
        {
          assignments: [`kernel.core_pattern=${apportPattern}`],
          file: pin("/usr/lib/sysctl.d/50-apport.conf", `kernel.core_pattern=${apportPattern}\n`),
        },
      ],
      crash_entries: [],
      persistent_policy_state: "absent",
    },
    rollback_policy: "separate-digest-approved-rollback-document-v1",
    schema_version: 1,
    transaction: {
      lock_path: "/run/bitcoinpir-payment-v1-core-pattern.lock",
      receipt_path: `/var/lib/bitcoinpir/payment-v1/core-pattern/receipts/${ceremonyId}.json`,
      rollback_receipt_path: `/var/lib/bitcoinpir/payment-v1/core-pattern/receipts/${ceremonyId}.rollback.json`,
      state_directory: `/var/lib/bitcoinpir/payment-v1/core-pattern/transactions/${ceremonyId}`,
    },
  };
}

function applyApproval(plan, planDigest, sourceDigest) {
  return {
    acknowledgements: [...APPLY_ACKNOWLEDGEMENTS],
    approved_at_utc: "2026-07-30T08:00:00Z",
    approved_by: "production-operator",
    ceremony_id: plan.ceremony_id,
    decision: "approve-disable-host-core-diagnostics",
    executor_sha256: sourceDigest,
    expires_at_utc: "2026-07-30T09:00:00Z",
    kind: APPLY_APPROVAL_KIND,
    plan_sha256: planDigest,
    schema_version: 1,
  };
}

function rollbackApproval(plan, planDigest, sourceDigest, receiptDigest) {
  return {
    acknowledgements: [...ROLLBACK_ACKNOWLEDGEMENTS],
    approved_at_utc: "2026-07-30T08:00:00Z",
    approved_by: "production-operator",
    ceremony_id: plan.ceremony_id,
    committed_receipt_sha256: receiptDigest,
    decision: "approve-restore-host-core-diagnostics",
    executor_sha256: sourceDigest,
    expires_at_utc: "2026-07-30T09:00:00Z",
    kind: ROLLBACK_APPROVAL_KIND,
    plan_sha256: planDigest,
    schema_version: 1,
  };
}

function clone(value) {
  return structuredClone(value);
}

class FakeOps {
  constructor(plan, state = expectedPreimage(plan), options = {}) {
    this.plan = plan;
    this.state = clone(state);
    this.calls = [];
    this.options = options;
    this.failed = new Set();
    this.receipts = new Map();
    this.states = new Map();
    this.locked = false;
    this.lockReleased = false;
  }

  maybeFail(name) {
    if (this.options.failAlways?.includes(name)) throw new Error(`forced ${name} failure`);
    if (this.options.failOnce?.includes(name) && !this.failed.has(name)) {
      this.failed.add(name);
      throw new Error(`forced ${name} failure`);
    }
  }

  async inspect() {
    this.calls.push("inspect");
    this.maybeFail("inspect");
    return clone(this.state);
  }

  async verifyHostAndTools() {
    this.calls.push("verify-host-tools");
    this.maybeFail("verify-host-tools");
  }

  async acquireLock() {
    this.calls.push("acquire-lock");
    this.maybeFail("acquire-lock");
    assert.equal(this.locked, false);
    this.locked = true;
    return async () => {
      this.calls.push("release-lock");
      this.maybeFail("release-lock");
      this.lockReleased = true;
      this.locked = false;
    };
  }

  async recoverLock() {
    this.calls.push("recover-lock");
    this.maybeFail("recover-lock");
    assert.equal(this.locked, true);
    return async () => {
      this.calls.push("release-lock");
      this.maybeFail("release-lock");
      this.lockReleased = true;
      this.locked = false;
    };
  }

  async publishState(_directory, phase, details) {
    this.calls.push(`state:${phase}`);
    this.maybeFail(`state:${phase}`);
    this.states.set(phase, clone(details));
  }

  async installPersistent(pinValue) {
    this.calls.push("install-persistent");
    this.maybeFail("install-persistent");
    this.state.persistent_policy = { file: clone(pinValue), state: "present" };
    const retained = this.state.core_pattern_assignment_files.filter(
      (entry) => entry.file.path !== pinValue.path,
    );
    retained.push({
      assignments: [`kernel.core_pattern=${TARGET_CORE_PATTERN}`],
      file: clone(pinValue),
    });
    this.state.core_pattern_assignment_files = retained.sort((a, b) =>
      a.file.path.localeCompare(b.file.path),
    );
  }

  async replaceApportDefault(pinValue) {
    this.calls.push(
      Buffer.from(pinValue.bytes_base64, "base64").toString("utf8") === "enabled=0\n"
        ? "replace-apport-candidate"
        : "replace-apport-preimage",
    );
    this.maybeFail("replace-apport-default");
    this.state.apport_default = clone(pinValue);
  }

  async systemctl(verb) {
    this.calls.push(`systemctl:${verb}`);
    this.maybeFail(`systemctl:${verb}`);
    if (verb === "disable") this.state.apport_service.unit_file_state = "disabled";
    if (verb === "enable") this.state.apport_service.unit_file_state = "enabled";
    if (verb === "stop") {
      this.state.apport_service.active_state = "inactive";
      this.state.apport_service.sub_state = "dead";
    }
    if (verb === "start") {
      this.state.apport_service.active_state = "active";
      this.state.apport_service.sub_state = this.plan.preimage.apport_service.sub_state;
    }
  }

  async writeCorePattern(value) {
    this.calls.push(value === TARGET_CORE_PATTERN ? "write-core-candidate" : "write-core-preimage");
    this.maybeFail("write-core-pattern");
    this.state.core_pattern = value;
  }

  async readCorePattern() {
    this.calls.push("read-core");
    this.maybeFail("read-core-pattern");
    return this.state.core_pattern;
  }

  async removePersistent() {
    this.calls.push("remove-persistent");
    this.maybeFail("remove-persistent");
    this.state.persistent_policy = { path: PERSISTENT_POLICY_PATH, state: "absent" };
    this.state.core_pattern_assignment_files = this.state.core_pattern_assignment_files.filter(
      (entry) => entry.file.path !== PERSISTENT_POLICY_PATH,
    );
  }

  async publishReceipt(path, receipt) {
    this.calls.push(path.endsWith(".rollback.json") ? "publish-rollback-receipt" : "publish-receipt");
    this.maybeFail("publish-receipt");
    this.receipts.set(path, clone(receipt));
  }

  now() {
    return FIXED_NOW;
  }
}

function contextFor(plan) {
  return {
    approvalSha256: "b".repeat(64),
    ceremonyId: plan.ceremony_id,
    planSha256: planSha256(plan),
    sourceSha256: plan.executor.source.sha256,
  };
}

test("reviewed fixture plan validates and has a deterministic digest", () => {
  const plan = fixturePlan();
  assert.equal(validatePlan(plan), plan);
  assert.equal(planSha256(plan), sha256(Buffer.from(canonicalJson(plan))));
  assert.match(planSha256(plan), /^[0-9a-f]{64}$/u);
});

test("plan pins the observed Hetzner apport pipe exactly", () => {
  const plan = fixturePlan();
  assert.equal(
    plan.preimage.core_pattern,
    "|/usr/share/apport/apport -p%p -s%s -c%c -d%d -P%P -u%u -g%g -F%F -- %E",
  );
  assert.deepEqual(plan.preimage.crash_entries, []);
});

test("plan permits a bounded standalone Node binary but rejects oversized tools", () => {
  const plan = fixturePlan();
  plan.executor.node.size = 64 * 1024 * 1024;
  assert.doesNotThrow(() => validatePlan(plan));
  plan.executor.node.size = 256 * 1024 * 1024 + 1;
  assert.throws(() => validatePlan(plan), /outside the reviewed bound/u);
});

test("plan rejects every unreviewed preimage or candidate relaxation", () => {
  const mutations = [
    (plan) => { plan.preimage.apport_default = embeddedPin(APPORT_DEFAULT_PATH, "enabled=1\nextra=1\n"); },
    (plan) => { plan.preimage.apport_service.active_state = "inactive"; },
    (plan) => { plan.preimage.apport_service.dropin_paths = ["/etc/systemd/system/apport.service.d/override.conf"]; },
    (plan) => { plan.preimage.apport_service.need_daemon_reload = "yes"; },
    (plan) => { plan.preimage.persistent_policy_state = "present"; },
    (plan) => { plan.preimage.crash_entries = ["old-crash"]; },
    (plan) => { plan.candidate.core_pattern = "core"; },
    (plan) => { plan.candidate.apport_default.mode = "0600"; },
    (plan) => { plan.rollback_policy = "automatic"; },
    (plan) => { plan.transaction.lock_path = "/tmp/lock"; },
  ];
  for (const mutate of mutations) {
    const plan = fixturePlan();
    mutate(plan);
    assert.throws(() => validatePlan(plan));
  }
});

test("plan rejects later-precedence and legacy sysctl assignments", () => {
  const late = fixturePlan();
  late.preimage.core_pattern_assignment_files[0].file.path =
    "/usr/lib/sysctl.d/zzzz-after-bitcoinpir.conf";
  assert.throws(() => validatePlan(late), /sorts at or after/u);

  const legacy = fixturePlan();
  legacy.preimage.core_pattern_assignment_files[0].file.path = "/etc/sysctl.conf";
  assert.throws(() => validatePlan(legacy), /must not assign/u);
});

test("sysctl scan follows systemd same-basename priority and /dev/null masks", (t) => {
  const root = mkdtempSync(join(tmpdir(), "bpir-sysctl-scan-"));
  t.after(() => rmSync(root, { force: true, recursive: true }));
  const high = join(root, "etc");
  const low = join(root, "usr");
  mkdirSync(high);
  mkdirSync(low);
  const filename = "50-apport.conf";
  writeFileSync(join(low, filename), "kernel.core_pattern=vendor-core\n");
  writeFileSync(join(high, filename), "# administrator mask by replacement\n");
  assert.deepEqual(scanCorePatternAssignments([high, low], null), []);

  unlinkSync(join(high, filename));
  assert.equal(
    scanCorePatternAssignments([high, low], null)[0].file.path,
    join(realpathSync(low), filename),
  );

  symlinkSync("/dev/null", join(high, filename));
  assert.deepEqual(scanCorePatternAssignments([high, low], null), []);
  unlinkSync(join(high, filename));
  symlinkSync(join(low, filename), join(high, filename));
  assert.throws(
    () => scanCorePatternAssignments([high, low], null),
    /must not be a non-\/dev\/null symlink/u,
  );
});

test("apply approval is separate, exact, digest-bound, and short-lived", () => {
  const plan = fixturePlan();
  const digest = planSha256(plan);
  const approval = applyApproval(plan, digest, plan.executor.source.sha256);
  assert.equal(
    validateApplyApproval(approval, plan, digest, plan.executor.source.sha256, FIXED_NOW),
    approval,
  );
  const expired = clone(approval);
  assert.throws(
    () => validateApplyApproval(expired, plan, digest, plan.executor.source.sha256, Date.parse("2026-07-30T10:00:00Z")),
    /not currently valid/u,
  );
  const reordered = clone(approval);
  reordered.acknowledgements.reverse();
  assert.throws(() => validateApplyApproval(reordered, plan, digest, plan.executor.source.sha256, FIXED_NOW));
  const widened = clone(approval);
  widened.expires_at_utc = "2026-08-01T08:00:01Z";
  assert.throws(() => validateApplyApproval(widened, plan, digest, plan.executor.source.sha256, FIXED_NOW));
});

test("rollback approval separately binds the committed receipt", () => {
  const plan = fixturePlan();
  const digest = planSha256(plan);
  const receipt = "c".repeat(64);
  const approval = rollbackApproval(plan, digest, plan.executor.source.sha256, receipt);
  assert.equal(
    validateRollbackApproval(
      approval,
      plan,
      digest,
      plan.executor.source.sha256,
      receipt,
      FIXED_NOW,
    ),
    approval,
  );
  assert.throws(
    () => validateRollbackApproval(approval, plan, digest, plan.executor.source.sha256, "d".repeat(64), FIXED_NOW),
    /does not bind/u,
  );
});

test("complete apply is ordered persistent -> defaults -> disable -> live write -> stop", async () => {
  const plan = fixturePlan();
  const ops = new FakeOps(plan);
  const result = await applyCeremony(plan, contextFor(plan), ops);
  assert.equal(result.outcome, "committed");
  assert.equal(result.receipt.kind, RECEIPT_KIND);
  assert.equal(result.receipt.history_cleanup_performed, false);
  assert.equal(result.receipt.host_reboot_performed, false);
  assert.deepEqual(ops.state, expectedCandidate(plan));
  assert.equal(ops.lockReleased, true);
  const order = [
    "install-persistent",
    "replace-apport-candidate",
    "systemctl:disable",
    "write-core-candidate",
    "systemctl:stop",
    "publish-receipt",
  ].map((entry) => ops.calls.indexOf(entry));
  assert.ok(order.every((entry) => entry >= 0));
  assert.deepEqual(order, [...order].sort((a, b) => a - b));
});

test("preflight drift causes no mutation and no receipt", async () => {
  const plan = fixturePlan();
  const drift = expectedPreimage(plan);
  drift.crash_entries = ["new-crash"];
  const ops = new FakeOps(plan, drift);
  await assert.rejects(
    () => applyCeremony(plan, contextFor(plan), ops),
    (error) => error instanceof CeremonyError && error.outcome === "preflight-failed",
  );
  assert.equal(ops.calls.includes("install-persistent"), false);
  assert.equal(ops.receipts.size, 0);
});

test("locked preflight catches drift introduced after the first snapshot", async () => {
  const plan = fixturePlan();
  const ops = new FakeOps(plan);
  const originalAcquire = ops.acquireLock.bind(ops);
  ops.acquireLock = async (...args) => {
    const release = await originalAcquire(...args);
    ops.state.core_pattern = "drift";
    return release;
  };
  await assert.rejects(
    () => applyCeremony(plan, contextFor(plan), ops),
    (error) => error.outcome === "preflight-failed",
  );
  assert.equal(ops.lockReleased, true);
  assert.equal(ops.calls.includes("install-persistent"), false);
});

for (const failure of [
  "install-persistent",
  "replace-apport-default",
  "systemctl:disable",
  "write-core-pattern",
  "systemctl:stop",
  "state:50-apport-stopped",
  "state:60-core-pattern-reapplied",
  "publish-receipt",
]) {
  test(`apply failure at ${failure} converges to exact safe candidate and retains lock`, async () => {
    const plan = fixturePlan();
    const ops = new FakeOps(plan, expectedPreimage(plan), { failOnce: [failure] });
    await assert.rejects(
      () => applyCeremony(plan, contextFor(plan), ops),
      (error) =>
        error instanceof CeremonyError &&
        error.outcome === "contained-needs-recovery" &&
        error.containment.exact_candidate === true,
    );
    assert.deepEqual(ops.state, expectedCandidate(plan));
    assert.equal(ops.locked, true);
    assert.equal(ops.lockReleased, false);
  });
}

test("failed containment reports outcome unknown and never claims a receipt", async () => {
  const plan = fixturePlan();
  const ops = new FakeOps(plan, expectedPreimage(plan), {
    failAlways: ["install-persistent"],
    failOnce: ["replace-apport-default"],
  });
  await assert.rejects(
    () => applyCeremony(plan, contextFor(plan), ops),
    (error) => error instanceof CeremonyError && error.outcome === "outcome-unknown",
  );
  assert.equal(ops.receipts.size, 0);
  assert.equal(ops.locked, true);
});

test("exact contained candidate can be recovered into a committed receipt", async () => {
  const plan = fixturePlan();
  const context = contextFor(plan);
  const ops = new FakeOps(plan, expectedPreimage(plan), { failOnce: ["publish-receipt"] });
  await assert.rejects(() => applyCeremony(plan, context, ops));
  assert.equal(ops.locked, true);
  const result = await recoverCommittedCandidate(plan, context, ops);
  assert.equal(result.outcome, "committed-after-contained-recovery");
  assert.equal(result.receipt.kind, RECEIPT_KIND);
  assert.equal(ops.lockReleased, true);
});

test("recovery refuses drift and retains the stale lock for manual inspection", async () => {
  const plan = fixturePlan();
  const ops = new FakeOps(plan, expectedCandidate(plan));
  ops.locked = true;
  ops.state.core_pattern = "drift";
  await assert.rejects(() => recoverCommittedCandidate(plan, contextFor(plan), ops));
  assert.equal(ops.locked, true);
  assert.equal(ops.receipts.size, 0);
});

test("recovery receipt remains terminal when stale-lock removal fails", async () => {
  const plan = fixturePlan();
  const ops = new FakeOps(plan, expectedCandidate(plan), { failAlways: ["release-lock"] });
  ops.locked = true;
  await assert.rejects(
    () => recoverCommittedCandidate(plan, contextFor(plan), ops),
    (error) => error.outcome === "committed-lock-retained",
  );
  assert.equal(ops.receipts.has(plan.transaction.receipt_path), true);
  assert.equal(ops.locked, true);
});

test("receipt publication is terminal even if lock release fails", async () => {
  const plan = fixturePlan();
  const ops = new FakeOps(plan, expectedPreimage(plan), { failAlways: ["release-lock"] });
  await assert.rejects(
    () => applyCeremony(plan, contextFor(plan), ops),
    (error) => error.outcome === "committed-lock-retained",
  );
  assert.equal(ops.receipts.has(plan.transaction.receipt_path), true);
  assert.deepEqual(ops.state, expectedCandidate(plan));
});

test("separately approved rollback restores exact old bytes/service/pattern last", async () => {
  const plan = fixturePlan();
  const context = {
    ...contextFor(plan),
    receiptSha256: "c".repeat(64),
    rollbackApprovalSha256: "d".repeat(64),
  };
  const ops = new FakeOps(plan, expectedCandidate(plan));
  const result = await rollbackCeremony(plan, context, ops);
  assert.equal(result.outcome, "rolled-back-to-approved-preimage");
  assert.equal(result.receipt.kind, ROLLBACK_RECEIPT_KIND);
  assert.deepEqual(ops.state, expectedPreimage(plan));
  const expectedOrder = [
    "replace-apport-preimage",
    "systemctl:enable",
    "systemctl:start",
    "write-core-preimage",
    "remove-persistent",
    "publish-rollback-receipt",
  ];
  const indexes = expectedOrder.map((entry) => ops.calls.indexOf(entry));
  assert.ok(indexes.every((entry) => entry >= 0));
  assert.deepEqual(indexes, [...indexes].sort((a, b) => a - b));
});

test("rollback receipt is terminal even if lock release fails", async () => {
  const plan = fixturePlan();
  const context = {
    ...contextFor(plan),
    receiptSha256: "c".repeat(64),
    rollbackApprovalSha256: "d".repeat(64),
  };
  const ops = new FakeOps(plan, expectedCandidate(plan), { failAlways: ["release-lock"] });
  await assert.rejects(
    () => rollbackCeremony(plan, context, ops),
    (error) => error.outcome === "rolled-back-lock-retained",
  );
  assert.equal(ops.receipts.has(plan.transaction.rollback_receipt_path), true);
  assert.deepEqual(ops.state, expectedPreimage(plan));
});

for (const failure of [
  "replace-apport-default",
  "systemctl:enable",
  "systemctl:start",
  "write-core-pattern",
  "remove-persistent",
  "publish-receipt",
]) {
  test(`rollback failure at ${failure} re-contains to the safe candidate`, async () => {
    const plan = fixturePlan();
    const context = {
      ...contextFor(plan),
      receiptSha256: "c".repeat(64),
      rollbackApprovalSha256: "d".repeat(64),
    };
    const ops = new FakeOps(plan, expectedCandidate(plan), { failOnce: [failure] });
    await assert.rejects(
      () => rollbackCeremony(plan, context, ops),
      (error) => error.outcome === "rollback-contained-safe",
    );
    assert.deepEqual(ops.state, expectedCandidate(plan));
    assert.equal(ops.locked, true);
  });
}

test("rollback preflight never accepts a partial candidate", async () => {
  const plan = fixturePlan();
  const partial = expectedCandidate(plan);
  partial.apport_service.unit_file_state = "enabled";
  const ops = new FakeOps(plan, partial);
  await assert.rejects(
    () => rollbackCeremony(plan, contextFor(plan), ops),
    (error) => error.outcome === "rollback-preflight-failed",
  );
  assert.equal(ops.calls.includes("replace-apport-preimage"), false);
});

test("canonical CLI validate-plan accepts only the externally pinned bytes and source", (t) => {
  const directory = mkdtempSync(join(tmpdir(), "bpir-core-pattern-test-"));
  t.after(() => rmSync(directory, { force: true, recursive: true }));
  const sourceDigest = hash(readFileSync(SCRIPT));
  const plan = fixturePlan({ sourceSha256: sourceDigest });
  const planBytes = canonicalJson(plan);
  const path = join(directory, "plan.json");
  writeFileSync(path, planBytes);
  const digest = hash(Buffer.from(planBytes));
  const output = execFileSync(
    process.execPath,
    [
      fileURLToPath(SCRIPT),
      "validate-plan",
      "--plan",
      path,
      "--approved-plan-sha256",
      digest,
      "--approved-source-sha256",
      sourceDigest,
    ],
    { encoding: "utf8" },
  );
  assert.match(output, /^core-pattern-plan=PASS /u);

  writeFileSync(path, `${planBytes}\n`);
  const noncanonicalDigest = hash(readFileSync(path));
  const failed = spawnSync(
    process.execPath,
    [
      fileURLToPath(SCRIPT),
      "validate-plan",
      "--plan",
      path,
      "--approved-plan-sha256",
      noncanonicalDigest,
      "--approved-source-sha256",
      sourceDigest,
    ],
    { encoding: "utf8" },
  );
  assert.notEqual(failed.status, 0);
  assert.match(failed.stderr, /canonical encoding/u);
});

test("observe-plan is a distinct host-bound read-only interface", () => {
  const observed = spawnSync(
    process.execPath,
    [fileURLToPath(SCRIPT), "observe-plan", "--ceremony-id", "host-plan-test"],
    { encoding: "utf8" },
  );
  if (process.platform === "linux" && process.geteuid?.() === 0) {
    // CI containers do not have the exact installed executor path, so they
    // still fail before reading or mutating host policy.
    assert.notEqual(observed.status, 0);
    assert.match(observed.stderr, /exact installed Node and ceremony source paths/u);
  } else {
    assert.notEqual(observed.status, 0);
    assert.match(observed.stderr, /requires Linux EUID 0/u);
  }
  assert.equal(observed.stdout, "");
});
