import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  APPORT_GATE_PATH,
  APPORT_MASK_PATH,
  APPORT_SYSCTLS,
  APPORT_UNIT,
  APPORT_UNIT_PATH,
  APPLY_ACKNOWLEDGEMENTS,
  APPLY_APPROVAL_KIND,
  CeremonyError,
  GUARD_UNIT,
  GUARD_UNIT_PATH,
  NOBLE_APPORT_ARCHIVE_SHA256,
  NOBLE_APPORT_HANDLER_SOURCE_SHA256,
  NOBLE_APPORT_SOURCE_URL,
  NOBLE_APPORT_UNIT_BYTES,
  NOBLE_APPORT_UNIT_SHA256,
  NOBLE_SYSTEMD_SYSCTL_UNIT_BYTES,
  NOBLE_SYSTEMD_SYSCTL_UNIT_SHA256,
  RECOVERY_ACKNOWLEDGEMENTS,
  RECOVERY_APPROVAL_KIND,
  ROLLBACK_ACKNOWLEDGEMENTS,
  ROLLBACK_APPROVAL_KIND,
  SYSTEMD_SYSCTL_ALIAS_PATH,
  SYSTEMD_SYSCTL_ALIAS_TARGET,
  SYSTEMD_SYSCTL_ALIAS_UNIT,
  SYSTEMD_SYSCTL_UNIT,
  SYSTEMD_SYSCTL_UNIT_PATH,
  SYSTEMD_SYSCTL_ENABLEMENT_PATH,
  SYSTEMD_MANAGER_UNIT_PATHS,
  SYSCTL_CREDENTIAL_CLOSURE_PATH,
  SYSCTL_GATE_PATH,
  TARGET_CORE_PATTERN,
  TARGET_SYSCTLS,
  applyCeremony,
  assertApportRuntimeLineageForTest,
  assertManagerSnapshotFenceForTest,
  atomicCreatePinnedForTest,
  canonicalJson,
  classifyRetainedGeneration,
  expectedCandidate,
  expectedGuardedCandidate,
  expectedGuardedPreimage,
  expectedPreimage,
  ensurePinnedWithQuarantineForTest,
  planSha256,
  parseBusctlJson,
  parseBusctlGetAll,
  parseCanonicalJsonBytes,
  parseLoadedApportUnitRows,
  parseSystemdWords,
  peekPublishedJson,
  recoverCeremony,
  recoverLockDirectoryGenerationForTest,
  realOps,
  rollbackCeremony,
  removePinnedByQuarantineForTest,
  scanApportEnablement,
  scanManagedUnitLoadPaths,
  scanSysctlAssignments,
  sha256,
  transactionLayout,
  validateApplyApproval,
  validateLoadedUnitMetadataForTest,
  validateManagerUnitPathForTest,
  validatePlan,
  validateRecoveryApproval,
  validateRollbackApproval,
  validateRuntimeConfigurationForTest,
  validateSystemdSysctlLoadPathsForTest,
  ensureSymlinkForTest,
  removeSymlinkForTest,
} from "./payment-v1-core-pattern-ceremony.mjs";
import {
  FRESH_BOOT_ID,
  FIXED_NOW,
  PLAN_BOOT_ID,
  FakeOps,
  contextFor,
  fixturePlan,
  leaseFor,
  pendingFor,
  preflightFor,
  pin,
  serializedDigest,
} from "./payment-v1-core-pattern-test-fixture.mjs";

function clone(value) {
  return structuredClone(value);
}

function applyApproval(plan, actionBootId) {
  return {
    acknowledgements: Array.from(APPLY_ACKNOWLEDGEMENTS),
    action_boot_id: actionBootId || PLAN_BOOT_ID,
    approved_at_utc: "2026-07-30T08:00:00Z",
    approved_by: "production-operator",
    ceremony_id: plan.ceremony_id,
    decision: "approve-disable-host-core-diagnostics",
    executor_sha256: plan.executor.source.sha256,
    expires_at_utc: "2026-07-30T09:00:00Z",
    kind: APPLY_APPROVAL_KIND,
    plan_boot_id: PLAN_BOOT_ID,
    plan_sha256: planSha256(plan),
    schema_version: 2,
  };
}

function recoveryApproval(plan, subject, mode, actionBootId, subjectKind) {
  const kind = subjectKind || "pending";
  return {
    acknowledgements: Array.from(RECOVERY_ACKNOWLEDGEMENTS),
    action_boot_id: actionBootId || FRESH_BOOT_ID,
    approved_at_utc: "2026-07-30T08:00:00Z",
    approved_by: "recovery-operator",
    ceremony_id: plan.ceremony_id,
    decision: "approve-resume-fail-closed-host-transaction",
    executor_sha256: plan.executor.source.sha256,
    expires_at_utc: "2026-07-30T09:00:00Z",
    kind: RECOVERY_APPROVAL_KIND,
    original_approval_sha256: subject.original_approval_sha256,
    plan_boot_id: PLAN_BOOT_ID,
    plan_sha256: planSha256(plan),
    recovery_mode: mode,
    recovery_subject_kind: kind,
    recovery_subject_sha256: serializedDigest(subject),
    schema_version: 2,
  };
}

function rollbackApproval(plan, receiptDigest, actionBootId) {
  return {
    acknowledgements: Array.from(ROLLBACK_ACKNOWLEDGEMENTS),
    action_boot_id: actionBootId || PLAN_BOOT_ID,
    approved_at_utc: "2026-07-30T08:00:00Z",
    approved_by: "rollback-operator",
    ceremony_id: plan.ceremony_id,
    committed_receipt_sha256: receiptDigest,
    decision: "approve-restore-host-core-diagnostics",
    executor_sha256: plan.executor.source.sha256,
    expires_at_utc: "2026-07-30T09:00:00Z",
    kind: ROLLBACK_APPROVAL_KIND,
    plan_boot_id: PLAN_BOOT_ID,
    plan_sha256: planSha256(plan),
    schema_version: 2,
  };
}

test("v2 plan validates and deterministically binds the official Noble source/unit", () => {
  const plan = fixturePlan();
  assert.equal(validatePlan(plan), plan);
  assert.deepEqual(plan.transaction, transactionLayout(plan.ceremony_id));
  assert.equal(planSha256(plan), sha256(Buffer.from(canonicalJson(plan), "utf8")));
  assert.equal(plan.official_noble_apport.source_url, NOBLE_APPORT_SOURCE_URL);
  assert.equal(plan.official_noble_apport.archive_sha256, NOBLE_APPORT_ARCHIVE_SHA256);
  assert.equal(plan.official_noble_apport.handler_source_sha256, NOBLE_APPORT_HANDLER_SOURCE_SHA256);
  assert.equal(plan.official_noble_apport.handler.sha256, NOBLE_APPORT_HANDLER_SOURCE_SHA256);
  assert.equal(plan.official_noble_apport.handler.size, 44730);
  assert.equal(
    sha256(Buffer.from(NOBLE_APPORT_UNIT_BYTES, "utf8")),
    NOBLE_APPORT_UNIT_SHA256,
  );
  assert.equal(
    sha256(Buffer.from(NOBLE_SYSTEMD_SYSCTL_UNIT_BYTES, "utf8")),
    NOBLE_SYSTEMD_SYSCTL_UNIT_SHA256,
  );
  assert.equal(plan.systemd_sysctl.unit.sha256, NOBLE_SYSTEMD_SYSCTL_UNIT_SHA256);
  assert.deepEqual(plan.official_noble_apport.unit_semantics, {
    exec_start: ["/usr/share/apport/apport --start"],
    exec_stop: ["/usr/share/apport/apport --stop"],
    remain_after_exit: true,
    type: "oneshot",
    wanted_by: ["multi-user.target"],
  });
});

test("render-plan skeletons stay canonical and derive from the production v2 schemas", () => {
  const directory = new URL("../docs/payment/render-plan-skeletons/", import.meta.url);
  const plan = fixturePlan();
  const planBytes = readFileSync(new URL("core-pattern-ceremony-v2.plan.json.example", directory));
  const skeletonPlan = parseCanonicalJsonBytes(planBytes, "plan skeleton");
  assert.equal(skeletonPlan.host.machine_id_sha256, "INVALID_REPLACE_WITH_64_LOWER_HEX");
  skeletonPlan.host.machine_id_sha256 = plan.host.machine_id_sha256;
  assert.deepEqual(skeletonPlan, plan);

  const pending = pendingFor(plan, "apply");
  const approvalPairs = [
    ["core-pattern-ceremony-v2.apply-approval.json.example", applyApproval(plan)],
    [
      "core-pattern-ceremony-v2.recovery-approval.json.example",
      recoveryApproval(plan, pending, "apply", FRESH_BOOT_ID),
    ],
    [
      "core-pattern-ceremony-v2.rollback-approval.json.example",
      rollbackApproval(plan, "c".repeat(64), FRESH_BOOT_ID),
    ],
  ];
  for (const [name, productionShape] of approvalPairs) {
    const example = parseCanonicalJsonBytes(readFileSync(new URL(name, directory)), name);
    assert.deepEqual(Object.keys(example).sort(), Object.keys(productionShape).sort());
  }
});

test("retained exchange recovery accepts only the exact adjacent generation on either side", () => {
  const plan = fixturePlan();
  const older = pendingFor(plan, "apply");
  const newer = {
    ...older,
    action_boot_id: FRESH_BOOT_ID,
    generation: older.generation + 1,
    previous_generation_sha256: serializedDigest(older),
    recovery_approval_sha256s: ["b".repeat(64)],
  };
  assert.equal(classifyRetainedGeneration(older, newer), "prepared-successor");
  assert.equal(classifyRetainedGeneration(newer, older), "committed-predecessor");
  assert.throws(function () {
    classifyRetainedGeneration(older, { ...newer, previous_generation_sha256: "f".repeat(64) });
  }, /outside the direct generation chain/u);
});

test("stable config is independent of settled active/exited versus inactive/dead bookkeeping", async () => {
  const plan = fixturePlan();
  plan.preimage.apport_runtime_observation = {
    active_state: "inactive",
    load_state: "loaded",
    need_daemon_reload: "no",
    sub_state: "dead",
  };
  assert.equal(validatePlan(plan), plan);
  const ops = new FakeOps(plan);
  const result = await applyCeremony(plan, contextFor(plan), ops);
  assert.deepEqual(result.receipt.post_state, expectedCandidate(plan));
  assert.equal(Object.hasOwn(result.receipt.post_state, "apport_runtime_observation"), false);
});

test("cross-boot recovery accepts settled Apport state change while same-boot action rejects it", () => {
  const expected = {
    active_state: "active",
    load_state: "loaded",
    need_daemon_reload: "no",
    sub_state: "exited",
  };
  const afterReboot = {
    active_state: "inactive",
    load_state: "masked",
    need_daemon_reload: "no",
    sub_state: "dead",
  };
  assert.equal(
    assertApportRuntimeLineageForTest(afterReboot, expected, false, "recovery-after-reboot"),
    true,
  );
  assert.throws(
    function () {
      assertApportRuntimeLineageForTest(afterReboot, expected, true, "same-boot-apply");
    },
    /runtime changed or transitioned/u,
  );
});

test("Noble side-effect fixture proves start/stop mutate all three sysctls in dangerous order", () => {
  const fixture = readFileSync(
    new URL("./fixtures/apport-2.28.2-start-stop.py", import.meta.url),
    "utf8",
  );
  const start = fixture.slice(fixture.indexOf("def start_apport"), fixture.indexOf("def stop_apport"));
  const stop = fixture.slice(fixture.indexOf("def stop_apport"));
  assert.ok(start.indexOf("\"kernel/core_pattern\"") < start.indexOf("\"fs/suid_dumpable\""));
  assert.ok(start.indexOf("\"fs/suid_dumpable\"") < start.indexOf("\"kernel/core_pipe_limit\""));
  assert.ok(stop.indexOf("\"kernel/core_pipe_limit\", \"0\"") < stop.indexOf("\"fs/suid_dumpable\", \"0\""));
  assert.ok(stop.indexOf("\"fs/suid_dumpable\", \"0\"") < stop.indexOf("\"kernel/core_pattern\", \"core\""));
});

test("plan rejects relaxation of sysctl, Noble, helper, guard, crash-dir, or persistent-state bindings", () => {
  const mutations = [
    function (plan) { plan.preimage.sysctls["fs.suid_dumpable"] = "0"; },
    function (plan) { plan.preimage.sysctls["kernel.core_pipe_limit"] = "0"; },
    function (plan) { plan.candidate.sysctls["kernel.core_pattern"] = "core"; },
    function (plan) { plan.official_noble_apport.unit_semantics.exec_stop = []; },
    function (plan) { plan.official_noble_apport.handler.sha256 = "f".repeat(64); },
    function (plan) { plan.official_noble_apport.unit.bytes_base64 = Buffer.from("foreign\n").toString("base64"); },
    function (plan) { plan.preimage.apport_enablement_symlinks[0].target = "/foreign"; },
    function (plan) { plan.preimage.apport_service.dropin_paths = ["/foreign.conf"]; },
    function (plan) { plan.preimage.apport_service.sub_state = "running"; },
    function (plan) { plan.preimage.guard_state = "present"; },
    function (plan) { plan.systemd_sysctl.unit.bytes_base64 = Buffer.from("foreign\n").toString("base64"); },
    function (plan) { plan.systemd_sysctl.binary.sha256 = "f".repeat(64); },
    function (plan) { plan.systemd_sysctl.enablement.target = "/dev/null"; },
    function (plan) { plan.candidate.sysctl_credential_closure.bytes_base64 = Buffer.from("[Service]\n").toString("base64"); },
    function (plan) { plan.preimage.sysctl_credential_closure_state = "present"; },
    function (plan) { plan.preimage.crash_directory.inode = "0"; },
    function (plan) { plan.preimage.crash_entries = ["old.crash"]; },
    function (plan) {
      plan.executor.exchange_helper.path =
        "/opt/bitcoinpir/payment-v1-rename-exchange/" + "f".repeat(64) +
        "/payment-v1-rename-exchange";
    },
    function (plan) { plan.transaction.lock_path = "/run/unsafe-lock"; },
    function (plan) { plan.transaction.temp_paths.state_exchange += ".random"; },
  ];
  for (const mutate of mutations) {
    const plan = fixturePlan();
    mutate(plan);
    assert.throws(function () { validatePlan(plan); });
  }
});

test("approval types are fresh, boot-lineage-bound, and mutually non-substitutable", () => {
  const plan = fixturePlan();
  const planDigest = planSha256(plan);
  const apply = applyApproval(plan);
  assert.equal(
    validateApplyApproval(
      apply, plan, planDigest, plan.executor.source.sha256, PLAN_BOOT_ID, FIXED_NOW,
    ),
    apply,
  );
  const pending = pendingFor(plan, "apply", "a".repeat(64), PLAN_BOOT_ID);
  const recovery = recoveryApproval(plan, pending, "apply", FRESH_BOOT_ID);
  assert.equal(
    validateRecoveryApproval(
      recovery,
      plan,
      planDigest,
      plan.executor.source.sha256,
      "pending",
      serializedDigest(pending),
      pending.original_approval_sha256,
      "apply",
      FRESH_BOOT_ID,
      FIXED_NOW,
    ),
    recovery,
  );
  const rollback = rollbackApproval(plan, "c".repeat(64), FRESH_BOOT_ID);
  assert.equal(
    validateRollbackApproval(
      rollback,
      plan,
      planDigest,
      plan.executor.source.sha256,
      "c".repeat(64),
      FRESH_BOOT_ID,
      FIXED_NOW,
    ),
    rollback,
  );
  const wrongBoot = clone(apply);
  wrongBoot.action_boot_id = FRESH_BOOT_ID;
  assert.throws(function () {
    validateApplyApproval(
      wrongBoot, plan, planDigest, plan.executor.source.sha256, PLAN_BOOT_ID, FIXED_NOW,
    );
  }, /identity\/lineage/u);
  assert.throws(function () {
    validateRecoveryApproval(
      recovery,
      plan,
      planDigest,
      plan.executor.source.sha256,
      "pending",
      serializedDigest(pending),
      pending.original_approval_sha256,
      "apply",
      "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
      FIXED_NOW,
    );
  }, /identity\/lineage/u);
  assert.throws(function () {
    validateRollbackApproval(
      rollback,
      plan,
      planDigest,
      plan.executor.source.sha256,
      "c".repeat(64),
      "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
      FIXED_NOW,
    );
  }, /identity\/lineage/u);
  const stale = clone(recovery);
  stale.expires_at_utc = "2026-07-30T08:01:00Z";
  assert.throws(function () {
    validateRecoveryApproval(
      stale,
      plan,
      planDigest,
      plan.executor.source.sha256,
      "pending",
      serializedDigest(pending),
      pending.original_approval_sha256,
      "apply",
      FRESH_BOOT_ID,
      FIXED_NOW,
    );
  }, /not fresh/u);
});

test("complete apply writes safe core_pattern first, binds all three sysctls, and never invokes stock handlers", async () => {
  const plan = fixturePlan();
  const ops = new FakeOps(plan);
  const result = await applyCeremony(plan, contextFor(plan), ops);
  assert.equal(result.outcome, "committed");
  assert.deepEqual(result.receipt.pre_state.sysctls, APPORT_SYSCTLS);
  assert.deepEqual(result.receipt.post_state.sysctls, TARGET_SYSCTLS);
  assert.deepEqual(result.receipt.recovery_approval_sha256s, []);
  assert.equal(result.receipt.apply_boot_id, PLAN_BOOT_ID);
  assert.equal(result.receipt.action_boot_id, PLAN_BOOT_ID);
  assert.deepEqual(ops.state, expectedCandidate(plan));
  const coreWrite = ops.calls.indexOf("write:kernel.core_pattern=" + TARGET_CORE_PATTERN);
  const disable = ops.calls.indexOf("remove-apport-enablement");
  assert.ok(coreWrite >= 0 && coreWrite < disable);
  assert.deepEqual(ops.state.apport_service, plan.preimage.apport_service);
  assert.ok(ops.calls.includes("write:fs.suid_dumpable=0"));
  assert.ok(ops.calls.includes("write:kernel.core_pipe_limit=0"));
  assert.equal(
    ops.calls.indexOf("assert-runtime:apply-preflight-pre-publish") + 1,
    ops.calls.indexOf("create-preflight"),
  );
  assert.equal(
    ops.calls.indexOf("assert-runtime:apply-pre-publish") + 1,
    ops.calls.indexOf("publish-receipt-after-full-inspection"),
  );
  assert.ok(
    ops.calls.indexOf("assert-runtime:apply-cleanup-pre-release") >= 0 &&
      ops.calls.indexOf("assert-runtime:apply-cleanup-pre-release") <
        ops.calls.indexOf("release-lock"),
  );
  assert.equal(ops.calls.some(function (call) {
    return call.includes("/usr/share/apport/apport") || call.includes("systemctl:start") ||
      call.includes("systemctl:stop");
  }), false);
});

test("apply rechecks /var/crash directory identity and entries immediately before receipt", async () => {
  const plan = fixturePlan();
  let injected = false;
  const ops = new FakeOps(plan, undefined, {
    onBoundary(name) {
      if (name === "remove-apport-enablement" && !injected) {
        injected = true;
        ops.state.crash_entries.push("late.crash");
      }
    },
  });
  await assert.rejects(
    function () { return applyCeremony(plan, contextFor(plan), ops); },
    function (error) {
      return error instanceof CeremonyError &&
        error.outcome === "outcome-unknown-lock-retained";
    },
  );
  assert.equal(Object.keys(ops.receipts).length, 0);
  assert.equal(ops.locked, true);
});

test("full final apply inspection rejects tuple drift after pending receipt-candidate publication", async () => {
  const plan = fixturePlan();
  let injected = false;
  let ops;
  ops = new FakeOps(plan, undefined, {
    onBoundary(name) {
      if (name === "write-pending" && !injected) {
        injected = true;
        ops.state.sysctls["fs.suid_dumpable"] = "2";
      }
    },
  });
  await assert.rejects(
    function () { return applyCeremony(plan, contextFor(plan), ops); },
    function (error) {
      return error instanceof CeremonyError &&
        error.outcome === "contained-needs-fresh-recovery-approval";
    },
  );
  assert.equal(Object.hasOwn(ops.receipts, plan.transaction.receipt_path), false);
  assert.notEqual(ops.pending, null);
  assert.notEqual(ops.lease, null);
  assert.equal(ops.locked, true);
});

test("apply final inspection and receipt publication have no injectable JavaScript boundary", async () => {
  const plan = fixturePlan();
  let armed = false;
  let inspectBoundaryAfterArm = false;
  let ops;
  ops = new FakeOps(plan, undefined, {
    onBoundary(name) {
      if (name === "assert-runtime:apply-pre-publish") armed = true;
      if (armed && name === "inspect") {
        inspectBoundaryAfterArm = true;
        ops.state.sysctls["fs.suid_dumpable"] = "2";
      }
      if (name === "publish-receipt-after-full-inspection") armed = false;
    },
  });
  const result = await applyCeremony(plan, contextFor(plan), ops);
  assert.equal(result.outcome, "committed");
  assert.equal(inspectBoundaryAfterArm, false);
  assert.deepEqual(result.receipt.terminal_commit_state, expectedGuardedCandidate(plan));
});

const APPLY_MUTATION_BOUNDARIES = [
  "create-pending",
  "install-persistent",
  "write:kernel.core_pattern=" + TARGET_CORE_PATTERN,
  "write:fs.suid_dumpable=0",
  "write:kernel.core_pipe_limit=0",
  "ensure-apport-mask",
  "remove-apport-enablement",
  "write-pending",
];

test("failure after preflight gate arm retains the approval-bound lease for official recovery", async () => {
  const plan = fixturePlan();
  const ops = new FakeOps(plan, undefined, { failAfter: ["ensure-guard"] });
  await assert.rejects(function () {
    return applyCeremony(plan, contextFor(plan), ops);
  });
  assert.equal(ops.pending, null);
  assert.equal(ops.preflight, null);
  assert.equal(ops.locked, true);
  assert.deepEqual(ops.lease, leaseFor(plan, "apply"));
  assert.deepEqual(ops.state, expectedGuardedPreimage(plan));
});

test("bootstrap refusal before lease publication does not invent a recovery subject", async () => {
  const plan = fixturePlan();
  const ops = new FakeOps(plan, undefined, { failBefore: ["acquire-lock"] });
  await assert.rejects(
    function () { return applyCeremony(plan, contextFor(plan), ops); },
    function (error) {
      return error instanceof CeremonyError &&
        error.outcome === "apply-bootstrap-refused-no-recovery-subject";
    },
  );
  assert.equal(ops.lease, null);
  assert.equal(ops.locked, false);
  assert.deepEqual(ops.state, expectedPreimage(plan));
});

for (const boundary of APPLY_MUTATION_BOUNDARIES) {
  test("failure after apply boundary remains non-native and recoverable: " + boundary, async () => {
    const plan = fixturePlan();
    const ops = new FakeOps(plan, undefined, { failAfter: [boundary] });
    await assert.rejects(function () {
      return applyCeremony(plan, contextFor(plan), ops);
    });
    assert.notEqual(ops.state.sysctls["kernel.core_pattern"], "core");
    if (Object.hasOwn(ops.receipts, plan.transaction.receipt_path)) {
      assert.deepEqual(ops.receipts[plan.transaction.receipt_path].post_state, expectedCandidate(plan));
      return;
    }
    assert.equal(ops.locked, true);
  });
}

test("receipt visible after link/fsync-style failure is terminal and does not trigger containment", async () => {
  const plan = fixturePlan();
  const ops = new FakeOps(plan, undefined, {
    failAfter: ["publish-receipt-after-full-inspection"],
  });
  const result = await applyCeremony(plan, contextFor(plan), ops);
  assert.equal(result.outcome, "receipt-visible-commit-uncertain");
  const publishIndex = ops.calls.indexOf("publish-receipt-after-full-inspection");
  assert.equal(
    ops.calls.slice(publishIndex + 1).some(function (call) {
      return call.startsWith("write:") || call === "remove-apport-enablement";
    }),
    false,
  );
  assert.deepEqual(ops.receipts[plan.transaction.receipt_path].post_state, expectedCandidate(plan));
});

test("an exact existing receipt is idempotent and terminal before any host mutation", async () => {
  const plan = fixturePlan();
  const ops = new FakeOps(plan);
  const first = await applyCeremony(plan, contextFor(plan), ops);
  const replay = new FakeOps(plan, ops.serialize());
  const second = await applyCeremony(plan, contextFor(plan), replay);
  assert.equal(second.outcome, "already-committed");
  assert.deepEqual(second.receipt, first.receipt);
  assert.equal(replay.calls.some(function (call) {
    return call === "ensure-guard" || call.startsWith("write:");
  }), false);
});

test("release failure after visible apply receipt is reported exactly and receipt remains terminal", async () => {
  const plan = fixturePlan();
  const ops = new FakeOps(plan, undefined, { releaseFailure: true });
  await assert.rejects(
    function () { return applyCeremony(plan, contextFor(plan), ops); },
    function (error) {
      return error instanceof CeremonyError &&
        error.outcome === "committed-cleanup-retained";
    },
  );
  assert.ok(Object.hasOwn(ops.receipts, plan.transaction.receipt_path));
  assert.equal(ops.locked, true);
});

test("cleanup reload revalidation failure retains lease until exact post-state is re-proven", async () => {
  const plan = fixturePlan();
  const ops = new FakeOps(plan, undefined, {
    failAfter: ["assert-runtime:apply-cleanup-pre-release"],
  });
  await assert.rejects(
    function () { return applyCeremony(plan, contextFor(plan), ops); },
    function (error) {
      return error instanceof CeremonyError &&
        error.outcome === "committed-cleanup-retained";
    },
  );
  assert.ok(Object.hasOwn(ops.receipts, plan.transaction.receipt_path));
  assert.equal(ops.locked, true);
  assert.notEqual(ops.lease, null);
});

test("post-receipt cleanup uses a fresh subject approval without rewriting the immutable receipt", async () => {
  const plan = fixturePlan();
  const ops = new FakeOps(plan, undefined, { releaseFailure: true });
  await assert.rejects(function () { return applyCeremony(plan, contextFor(plan), ops); });
  const committed = structuredClone(ops.receipts[plan.transaction.receipt_path]);
  assert.deepEqual(committed.recovery_approval_sha256s, []);
  ops.options.releaseFailure = false;
  const cleanupContext = contextFor(plan, {
    actionBootId: FRESH_BOOT_ID,
    recoveryApprovedSubjectSha256: serializedDigest(ops.lease),
    recoverySubjectKind: "lease",
    recoveryApprovalSha256: "e".repeat(64),
  });
  const recovered = await recoverCeremony(plan, cleanupContext, ops);
  assert.equal(recovered.outcome, "already-committed");
  assert.deepEqual(recovered.receipt, committed);
  assert.equal(ops.locked, false);
  assert.equal(ops.lease, null);
});

test("recovery refuses missing lineage and explicitly retains the persistent lock", async () => {
  const plan = fixturePlan();
  const ops = new FakeOps(plan);
  ops.locked = true;
  await assert.rejects(
    function () {
      return recoverCeremony(
        plan,
        contextFor(plan, { actionBootId: FRESH_BOOT_ID }),
        ops,
      );
    },
    function (error) {
      return error.outcome === "recovery-refused-no-subject";
    },
  );
  assert.equal(ops.locked, true);
});

test("apply replay detects durable pending before inspecting or mutating partial host state", async () => {
  const plan = fixturePlan();
  const ops = new FakeOps(plan);
  ops.locked = true;
  ops.pending = pendingFor(plan, "apply");
  ops.state.sysctls["kernel.core_pattern"] = TARGET_CORE_PATTERN;
  await assert.rejects(
    function () { return applyCeremony(plan, contextFor(plan), ops); },
    function (error) {
      return error instanceof CeremonyError &&
        error.outcome === "recovery-approval-required-lock-retained";
    },
  );
  assert.equal(ops.calls.includes("inspect"), false);
  assert.equal(ops.locked, true);
});

test("fresh-boot recovery records apply_boot_id and action_boot_id and is idempotent", async () => {
  const plan = fixturePlan();
  const crashed = new FakeOps(plan);
  crashed.locked = true;
  crashed.lease = leaseFor(plan, "apply", "a".repeat(64), PLAN_BOOT_ID);
  crashed.preflight = preflightFor(plan, "apply", "a".repeat(64), PLAN_BOOT_ID);
  crashed.pending = pendingFor(plan, "apply", "a".repeat(64), PLAN_BOOT_ID);
  await crashed.ensureGuard(plan.candidate.guard_unit, plan.candidate.guard_enablement);
  await crashed.installPersistent(plan.candidate.persistent_policy);
  await crashed.writeSysctl("kernel.core_pattern", TARGET_CORE_PATTERN);
  await assert.rejects(
    function () {
      return recoverCeremony(plan, contextFor(plan, {
        actionBootId: FRESH_BOOT_ID,
        recoveryApprovedSubjectSha256: "f".repeat(64),
      }), crashed);
    },
    /does not bind the exact durable recovery subject generation/u,
  );
  assert.deepEqual(crashed.pending.recovery_approval_sha256s, []);
  const context = contextFor(plan, {
    actionBootId: FRESH_BOOT_ID,
    recoveryApprovedSubjectSha256: serializedDigest(crashed.pending),
  });
  const recovered = await recoverCeremony(plan, context, crashed);
  assert.equal(recovered.receipt.apply_boot_id, PLAN_BOOT_ID);
  assert.equal(recovered.receipt.action_boot_id, FRESH_BOOT_ID);
  assert.equal(recovered.receipt.host_reboot_performed, true);
  assert.deepEqual(recovered.receipt.recovery_approval_sha256s, ["b".repeat(64)]);
  assert.deepEqual(recovered.receipt.post_state, expectedCandidate(plan));
  const replay = new FakeOps(plan, crashed.serialize());
  const again = await recoverCeremony(plan, context, replay);
  assert.equal(again.outcome, "already-committed");
  assert.deepEqual(again.receipt, recovered.receipt);
});

test("rollback restores exact symlink and all three sysctls without stock ExecStart", async () => {
  const plan = fixturePlan();
  const ops = new FakeOps(plan);
  const apply = await applyCeremony(plan, contextFor(plan), ops);
  const rollbackContext = {
    ...contextFor(plan),
    applyApprovalSha256: apply.receipt.apply_approval_sha256,
    receiptSha256: apply.receipt_sha256,
    rollbackApprovalSha256: "d".repeat(64),
  };
  const result = await rollbackCeremony(plan, rollbackContext, ops);
  assert.equal(result.outcome, "rolled-back-to-approved-preimage");
  assert.deepEqual(ops.state, expectedPreimage(plan));
  assert.ok(
    ops.calls.indexOf("write:kernel.core_pipe_limit=10") <
      ops.calls.indexOf("write:kernel.core_pattern=" + APPORT_SYSCTLS["kernel.core_pattern"]),
  );
  assert.ok(
    ops.calls.indexOf("write:fs.suid_dumpable=2") <
      ops.calls.indexOf("write:kernel.core_pattern=" + APPORT_SYSCTLS["kernel.core_pattern"]),
  );
  assert.equal(ops.calls.includes("ensure-apport-enablement"), true);
  assert.equal(ops.calls.includes("start-apport-stock-handler"), false);
  assert.equal(
    ops.calls.indexOf("assert-runtime:rollback-preflight-pre-publish") + 1,
    ops.calls.indexOf(
      "create-preflight",
      ops.calls.indexOf("publish-receipt-after-full-inspection") + 1,
    ),
  );
  assert.equal(
    ops.calls.indexOf("assert-runtime:rollback-pre-publish") + 1,
    ops.calls.indexOf("publish-rollback-receipt-after-full-inspection"),
  );
  assert.ok(
    ops.calls.indexOf("assert-runtime:rollback-cleanup-pre-release") >= 0 &&
      ops.calls.indexOf("assert-runtime:rollback-cleanup-pre-release") <
        ops.calls.lastIndexOf("release-lock"),
  );
});

test("full final rollback inspection rejects tuple drift after pending receipt-candidate publication", async () => {
  const plan = fixturePlan();
  const ops = new FakeOps(plan);
  const apply = await applyCeremony(plan, contextFor(plan), ops);
  let injected = false;
  ops.options.onBoundary = function (name) {
    if (name === "write-pending" && ops.pending?.mode === "rollback" && !injected) {
      injected = true;
      ops.state.sysctls["kernel.core_pipe_limit"] = "0";
    }
  };
  await assert.rejects(
    function () {
      return rollbackCeremony(plan, {
        ...contextFor(plan),
        applyApprovalSha256: apply.receipt.apply_approval_sha256,
        receiptSha256: apply.receipt_sha256,
        rollbackApprovalSha256: "d".repeat(64),
      }, ops);
    },
    function (error) {
      return error instanceof CeremonyError &&
        error.outcome === "rollback-contained-needs-fresh-recovery-approval";
    },
  );
  assert.equal(Object.hasOwn(ops.receipts, plan.transaction.rollback_receipt_path), false);
  assert.notEqual(ops.pending, null);
  assert.notEqual(ops.lease, null);
  assert.equal(ops.locked, true);
});

test("rollback final inspection and receipt publication have no injectable JavaScript boundary", async () => {
  const plan = fixturePlan();
  const ops = new FakeOps(plan);
  const apply = await applyCeremony(plan, contextFor(plan), ops);
  let armed = false;
  let inspectBoundaryAfterArm = false;
  ops.options.onBoundary = function (name) {
    if (name === "assert-runtime:rollback-pre-publish") armed = true;
    if (armed && name === "inspect") {
      inspectBoundaryAfterArm = true;
      ops.state.sysctls["kernel.core_pipe_limit"] = "0";
    }
    if (name === "publish-rollback-receipt-after-full-inspection") armed = false;
  };
  const result = await rollbackCeremony(plan, {
    ...contextFor(plan),
    applyApprovalSha256: apply.receipt.apply_approval_sha256,
    receiptSha256: apply.receipt_sha256,
    rollbackApprovalSha256: "d".repeat(64),
  }, ops);
  assert.equal(result.outcome, "rolled-back-to-approved-preimage");
  assert.equal(inspectBoundaryAfterArm, false);
  assert.deepEqual(result.receipt.terminal_commit_state, expectedGuardedPreimage(plan));
});

test("concurrent root mutation during removal is restored and rollback contains to exact safe candidate", async () => {
  const plan = fixturePlan();
  const ops = new FakeOps(plan);
  const apply = await applyCeremony(plan, contextFor(plan), ops);
  ops.options.concurrentPersistentMutation = true;
  const rollbackContext = {
    ...contextFor(plan),
    applyApprovalSha256: apply.receipt.apply_approval_sha256,
    receiptSha256: apply.receipt_sha256,
    rollbackApprovalSha256: "d".repeat(64),
  };
  await assert.rejects(
    function () { return rollbackCeremony(plan, rollbackContext, ops); },
    function (error) {
      return error.outcome === "rollback-contained-needs-fresh-recovery-approval";
    },
  );
  assert.equal(ops.options.concurrentPersistentMutationRestored, true);
  assert.notEqual(ops.state.sysctls["kernel.core_pattern"], "core");
});

test("atomic create treats link, fsync, and verify failures as exact visible terminal commits", () => {
  for (const option of ["faultAfterLink", "faultAfterFsync", "faultAfterVerify"]) {
    const root = mkdtempSync(join(tmpdir(), "bitcoinpir-core-atomic-"));
    try {
      const target = join(root, "receipt.json");
      const temp = join(root, "receipt.json.pending");
      const bytes = Buffer.from("{\"ok\":true}\n");
      const owner = statSync(root);
      const filePin = {
        bytes_base64: bytes.toString("base64"),
        gid: owner.gid,
        mode: "0600",
        nlink: 1,
        path: target,
        sha256: sha256(bytes),
        size: bytes.length,
        uid: owner.uid,
      };
      const result = atomicCreatePinnedForTest(filePin, {
        [option]: true,
        tempPath: temp,
      });
      assert.equal(result.status, "visible-commit-uncertain");
      assert.equal(readFileSync(target, "utf8"), "{\"ok\":true}\n");
      const replay = atomicCreatePinnedForTest(filePin, { tempPath: temp });
      assert.equal(replay.status, "already-visible");
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  }
});

test("fixed prepared temp is reusable after a simulated power-loss boundary", () => {
  const root = mkdtempSync(join(tmpdir(), "bitcoinpir-core-temp-"));
  try {
    const target = join(root, "state.json");
    const temp = join(root, "state.json.pending");
    const bytes = Buffer.from("state\n");
    const owner = statSync(root);
    writeFileSync(temp, bytes, { mode: 0o600 });
    chmodSync(temp, 0o600);
    const filePin = {
      bytes_base64: bytes.toString("base64"),
      gid: owner.gid,
      mode: "0600",
      nlink: 1,
      path: target,
      sha256: sha256(bytes),
      size: bytes.length,
      uid: owner.uid,
    };
    const result = atomicCreatePinnedForTest(filePin, { tempPath: temp });
    assert.equal(result.status, "published");
    assert.equal(readFileSync(target, "utf8"), "state\n");
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("published JSON rejects a detached prepared inode even when both bytes are canonical", () => {
  const root = mkdtempSync(join(tmpdir(), "bitcoinpir-core-detached-json-"));
  try {
    const target = join(root, "owner.json");
    const prepared = target + ".pending";
    const ownerStat = statSync(root);
    const owner = { gid: ownerStat.gid, uid: ownerStat.uid };
    writeFileSync(target, "{\"generation\":1}\n", { mode: 0o600 });
    writeFileSync(prepared, "{\"generation\":1}\n", { mode: 0o600 });
    assert.throws(
      function () { peekPublishedJson(target, prepared, owner); },
      /detached prepared generation/u,
    );
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("durable lease recovery repairs exact empty prepared/current lock directories", () => {
  const root = mkdtempSync(join(tmpdir(), "bitcoinpir-core-lock-repair-"));
  try {
    const ownerStat = statSync(root);
    const owner = { gid: ownerStat.gid, uid: ownerStat.uid };
    const locks = join(root, "locks");
    mkdirSync(locks, { mode: 0o700 });
    const current = join(locks, "ceremony");
    const lease = { approval: "a".repeat(64), kind: "lease", mode: "apply" };

    mkdirSync(current + ".pending", { mode: 0o700 });
    recoverLockDirectoryGenerationForTest(current, lease, { owner });
    assert.deepEqual(
      parseCanonicalJsonBytes(readFileSync(join(current, "owner.json")), "repaired owner"),
      lease,
    );

    unlinkSync(join(current, "owner.json"));
    recoverLockDirectoryGenerationForTest(current, lease, { owner });
    assert.deepEqual(
      parseCanonicalJsonBytes(readFileSync(join(current, "owner.json")), "repaired deleted owner"),
      lease,
    );

    unlinkSync(join(current, "owner.json"));
    writeFileSync(join(current, "foreign"), "unknown\n");
    assert.throws(
      function () { recoverLockDirectoryGenerationForTest(current, lease, { owner }); },
      /unknown generation/u,
    );
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("regular guard/gate quarantine recovery replays real filesystem boundaries", () => {
  const ensureBoundaries = [
    "ensure-file-rename-quarantine-to-live",
    "ensure-file-fsync-quarantine-rename",
    "ensure-file-verify-restored",
    "ensure-file-unlink-quarantine",
    "ensure-file-fsync-quarantine-unlink",
  ];
  const removeBoundaries = [
    "remove-file-publish-quarantine",
    "remove-file-fsync-publish",
    "remove-file-unlink-quarantine",
    "remove-file-fsync-quarantine-unlink",
  ];
  function fixture() {
    const root = mkdtempSync(join(tmpdir(), "bitcoinpir-core-file-quarantine-"));
    const ownerStat = statSync(root);
    const live = join(root, "guard.service");
    const bytes = Buffer.from("reviewed generation\n");
    return {
      bytes,
      live,
      pin: {
        ...pin(live, bytes, "0644", { gid: ownerStat.gid, uid: ownerStat.uid }),
        bytes_base64: bytes.toString("base64"),
      },
      quarantine: live + ".bitcoinpir-quarantine",
      root,
      temp: live + ".pending",
    };
  }
  for (const boundary of ensureBoundaries) {
    const state = fixture();
    try {
      writeFileSync(state.quarantine, state.bytes, { mode: 0o644 });
      if ([
        "ensure-file-unlink-quarantine",
        "ensure-file-fsync-quarantine-unlink",
      ].includes(boundary)) {
        writeFileSync(state.live, state.bytes, { mode: 0o644 });
      }
      assert.throws(function () {
        ensurePinnedWithQuarantineForTest(state.pin, state.temp, state.quarantine, {
          afterBoundary(name) { if (name === boundary) throw new Error("power loss"); },
        });
      }, /power loss/u);
      ensurePinnedWithQuarantineForTest(state.pin, state.temp, state.quarantine);
      assert.equal(readFileSync(state.live, "utf8"), state.bytes.toString("utf8"));
      assert.equal(existsSync(state.quarantine), false);
    } finally {
      rmSync(state.root, { force: true, recursive: true });
    }
  }
  for (const boundary of removeBoundaries) {
    const state = fixture();
    try {
      writeFileSync(state.live, state.bytes, { mode: 0o644 });
      assert.throws(function () {
        removePinnedByQuarantineForTest(state.pin, state.quarantine, {
          afterBoundary(name) { if (name === boundary) throw new Error("power loss"); },
          publish(left, right) { renameSync(left, right); },
        });
      }, /power loss/u);
      removePinnedByQuarantineForTest(state.pin, state.quarantine, {
        publish(left, right) { renameSync(left, right); },
      });
      assert.equal(existsSync(state.live), false);
      assert.equal(existsSync(state.quarantine), false);
    } finally {
      rmSync(state.root, { force: true, recursive: true });
    }
  }
  const coexist = fixture();
  try {
    writeFileSync(coexist.live, coexist.bytes, { mode: 0o644 });
    writeFileSync(coexist.quarantine, coexist.bytes, { mode: 0o644 });
    removePinnedByQuarantineForTest(coexist.pin, coexist.quarantine, {
      publish(left, right) { renameSync(left, right); },
    });
    assert.equal(existsSync(coexist.live), false);
    assert.equal(existsSync(coexist.quarantine), false);
  } finally {
    rmSync(coexist.root, { force: true, recursive: true });
  }
  const raced = fixture();
  try {
    writeFileSync(raced.quarantine, raced.bytes, { mode: 0o644 });
    ensurePinnedWithQuarantineForTest(raced.pin, raced.temp, raced.quarantine, {
      publish() {
        writeFileSync(raced.live, raced.bytes, { mode: 0o644 });
        const error = new Error("destination already exists");
        error.code = "EEXIST";
        throw error;
      },
    });
    assert.equal(readFileSync(raced.live, "utf8"), raced.bytes.toString("utf8"));
    assert.equal(existsSync(raced.quarantine), false);
  } finally {
    rmSync(raced.root, { force: true, recursive: true });
  }
});

test("hard-killed filesystem workers recover empty lock and guard quarantine generations", () => {
  const moduleUrl = new URL("./payment-v1-core-pattern-ceremony.mjs", import.meta.url).href;
  const root = mkdtempSync(join(tmpdir(), "bitcoinpir-core-hard-fs-crash-"));
  try {
    const ownerStat = statSync(root);
    const owner = { gid: ownerStat.gid, uid: ownerStat.uid };
    const locks = join(root, "locks");
    mkdirSync(locks, { mode: 0o700 });
    const current = join(locks, "ceremony");
    const lease = { approval: "f".repeat(64), kind: "lease", mode: "apply" };
    const lockWorker = [
      "const api = await import(process.argv[1]);",
      "const expected = JSON.parse(process.argv[3]);",
      "const owner = JSON.parse(process.argv[4]);",
      "api.recoverLockDirectoryGenerationForTest(process.argv[2], expected, {",
      "  owner,",
      "  afterBoundary(name) { if (name === process.argv[5]) process.kill(process.pid, 'SIGKILL'); },",
      "});",
    ].join("\n");
    const killedAfterMkdir = spawnSync(process.execPath, [
      "--input-type=module", "-e", lockWorker, moduleUrl, current,
      JSON.stringify(lease), JSON.stringify(owner), "lock-mkdir-prepared",
    ]);
    assert.equal(killedAfterMkdir.signal, "SIGKILL");
    assert.deepEqual(recoverLockDirectoryGenerationForTest(current, lease, { owner }), lease);
    unlinkSync(join(current, "owner.json"));
    const killedAfterOwner = spawnSync(process.execPath, [
      "--input-type=module", "-e", lockWorker, moduleUrl, current,
      JSON.stringify(lease), JSON.stringify(owner), "lock-owner-published",
    ]);
    assert.equal(killedAfterOwner.signal, "SIGKILL");
    assert.deepEqual(recoverLockDirectoryGenerationForTest(current, lease, { owner }), lease);

    const live = join(root, "guard.service");
    const quarantine = live + ".bitcoinpir-quarantine";
    const temp = live + ".pending";
    const bytes = Buffer.from("reviewed guard\n");
    const filePin = {
      ...pin(live, bytes, "0644", owner),
      bytes_base64: bytes.toString("base64"),
    };
    writeFileSync(quarantine, bytes, { mode: 0o644 });
    const ensureWorker = [
      "const api = await import(process.argv[1]);",
      "const pin = JSON.parse(process.argv[2]);",
      "api.ensurePinnedWithQuarantineForTest(pin, process.argv[3], process.argv[4], {",
      "  afterBoundary(name) { if (name === 'ensure-file-rename-quarantine-to-live') process.kill(process.pid, 'SIGKILL'); },",
      "});",
    ].join("\n");
    const killedEnsure = spawnSync(process.execPath, [
      "--input-type=module", "-e", ensureWorker, moduleUrl,
      JSON.stringify(filePin), temp, quarantine,
    ]);
    assert.equal(killedEnsure.signal, "SIGKILL");
    ensurePinnedWithQuarantineForTest(filePin, temp, quarantine);
    assert.equal(readFileSync(live, "utf8"), bytes.toString("utf8"));
    assert.equal(existsSync(quarantine), false);

    const removeWorker = [
      "const { renameSync } = await import('node:fs');",
      "const api = await import(process.argv[1]);",
      "const pin = JSON.parse(process.argv[2]);",
      "api.removePinnedByQuarantineForTest(pin, process.argv[3], {",
      "  publish(left, right) { renameSync(left, right); },",
      "  afterBoundary(name) { if (name === 'remove-file-publish-quarantine') process.kill(process.pid, 'SIGKILL'); },",
      "});",
    ].join("\n");
    const killedRemove = spawnSync(process.execPath, [
      "--input-type=module", "-e", removeWorker, moduleUrl,
      JSON.stringify(filePin), quarantine,
    ]);
    assert.equal(killedRemove.signal, "SIGKILL");
    removePinnedByQuarantineForTest(filePin, quarantine, {
      publish(left, right) { renameSync(left, right); },
    });
    assert.equal(existsSync(live), false);
    assert.equal(existsSync(quarantine), false);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("sysctl scan covers all three keys, systemd basename priority, and /dev/null masks", async (t) => {
  const fs = await import("node:fs");
  const root = mkdtempSync(join(tmpdir(), "bitcoinpir-core-sysctl-"));
  t.after(function () { rmSync(root, { force: true, recursive: true }); });
  const high = join(root, "etc");
  const low = join(root, "usr");
  fs.mkdirSync(high);
  fs.mkdirSync(low);
  writeFileSync(
    join(low, "50-apport.conf"),
    "kernel.core_pattern=pipe\nfs.suid_dumpable=2\nkernel.core_pipe_limit=10\n",
  );
  fs.symlinkSync("/dev/null", join(high, "50-apport.conf"));
  writeFileSync(join(high, "40-local.conf"), "fs.suid_dumpable=1\n");
  writeFileSync(
    join(high, "41-negative-prefix.conf"),
    "-kernel.core_pipe_limit=10\nnet.ipv4.conf.*.rp_filter=2\n",
  );
  const found = scanSysctlAssignments([high, low], null);
  assert.equal(found.length, 2);
  assert.deepEqual(found[0].assignments, ["fs.suid_dumpable=1"]);
  assert.deepEqual(found[1].assignments, ["-kernel.core_pipe_limit=10"]);
  writeFileSync(join(high, "42-glob.conf"), "kernel.core_*=0\n");
  assert.throws(function () {
    scanSysctlAssignments([high, low], null);
  }, /glob may affect a reviewed key/u);
  rmSync(join(high, "42-glob.conf"));
  writeFileSync(join(high, "42-negative-exclusion.conf"), "-kernel.core_*\n");
  assert.throws(function () {
    scanSysctlAssignments([high, low], null);
  }, /negative sysctl exclusion/u);
  writeFileSync(join(high, "42-negative-exclusion.conf"), "-kernel.core_pattern\n");
  assert.throws(function () {
    scanSysctlAssignments([high, low], null);
  }, /negative sysctl exclusion/u);
});

test("Apport enablement scan closes runtime, local, vendor, and administrator roots", () => {
  const root = mkdtempSync(join(tmpdir(), "bitcoinpir-core-enablement-"));
  try {
    const administrator = join(root, "etc-systemd");
    const vendor = join(root, "usr-systemd");
    const administratorWants = join(administrator, "multi-user.target.wants");
    const vendorWants = join(vendor, "graphical.target.wants");
    mkdirSync(administratorWants, { recursive: true });
    mkdirSync(vendorWants, { recursive: true });
    symlinkSync(APPORT_UNIT_PATH, join(administratorWants, "apport.service"));
    symlinkSync(APPORT_UNIT_PATH, join(vendorWants, "foreign-name.service"));
    const found = scanApportEnablement([administrator, vendor]);
    assert.deepEqual(found.map(function (entry) { return entry.path; }), [
      join(realpathSync(administratorWants), "apport.service"),
      join(realpathSync(vendorWants), "foreign-name.service"),
    ]);
    const runtime = join(root, "run-systemd", "multi-user.target.wants");
    mkdirSync(runtime, { recursive: true });
    writeFileSync(join(runtime, "apport.service"), "foreign dependency\n");
    assert.throws(function () {
      scanApportEnablement([administrator, vendor, join(root, "run-systemd")]);
    });
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("Apport activation closure rejects external Wants and implicit socket/path triggers", () => {
  const root = mkdtempSync(join(tmpdir(), "bitcoinpir-core-activation-"));
  try {
    writeFileSync(join(root, "external.service"), "[Unit]\nWants=apport.service\n");
    assert.throws(function () { scanApportEnablement([root]); }, /references apport\.service/u);
    rmSync(join(root, "external.service"));
    const linked = join(root, "linked");
    mkdirSync(linked);
    const linkedTarget = join(root, "linked-target.service");
    writeFileSync(linkedTarget, "[Unit]\nOnFailure=apport.service\n");
    symlinkSync(linkedTarget, join(linked, "external-alias.service"));
    assert.throws(function () {
      scanApportEnablement([linked]);
    }, /symlinked systemd unit references apport\.service/u);
    rmSync(linked, { recursive: true });
    rmSync(linkedTarget);
    writeFileSync(join(root, "apport.socket"), "[Socket]\nListenStream=1234\n");
    assert.throws(function () { scanApportEnablement([root]); }, /fragment\/dependency/u);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("activation closure resolves multi-level aliases and rejects direct handler Exec directives", () => {
  const root = mkdtempSync(join(tmpdir(), "bitcoinpir-core-alias-"));
  try {
    const official = join(root, "apport.service");
    const middle = join(root, "middle.service");
    const deep = join(root, "deep.service");
    writeFileSync(official, NOBLE_APPORT_UNIT_BYTES);
    symlinkSync("apport.service", middle);
    symlinkSync("middle.service", deep);
    const aliases = scanApportEnablement([root], undefined, undefined, official);
    assert.deepEqual(
      aliases.map(function (entry) { return entry.path.slice(entry.path.lastIndexOf("/") + 1); }),
      ["deep.service", "middle.service"],
    );
    rmSync(deep);
    rmSync(middle);
    writeFileSync(
      join(root, "foreign.service"),
      "[Service]\nExecStart=-/usr/share/apport/apport --start\n",
    );
    assert.throws(
      function () { scanApportEnablement([root], undefined, undefined, official); },
      /references apport\.service/u,
    );
    unlinkSync(join(root, "foreign.service"));
    writeFileSync(
      join(root, "foreign.service"),
      "[Service]\nExecStart=/bin/sh -c '/usr/share/apport/apport --start'\n",
    );
    assert.throws(
      function () { scanApportEnablement([root], undefined, undefined, official); },
      /references apport\.service/u,
    );
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("managed unit load-path closure rejects runtime, control, generator, vendor, and top-level bypasses", () => {
  const root = mkdtempSync(join(tmpdir(), "bitcoinpir-core-load-paths-"));
  try {
    const etc = join(root, "etc-system");
    const runtime = join(root, "run-system");
    const control = join(root, "run-control");
    const generator = join(root, "run-generator");
    const vendor = join(root, "usr-system");
    for (const directory of [etc, runtime, control, generator, vendor]) {
      mkdirSync(directory, { recursive: true });
    }
    const apportFragment = join(vendor, APPORT_UNIT);
    const sysctlFragment = join(vendor, SYSTEMD_SYSCTL_UNIT);
    const sysctlAlias = join(realpathSync(vendor), SYSTEMD_SYSCTL_ALIAS_UNIT);
    const sysctlWants = join(vendor, "sysinit.target.wants");
    const sysctlEnablement = join(sysctlWants, SYSTEMD_SYSCTL_UNIT);
    const guardFragment = join(etc, GUARD_UNIT);
    const apportGate = join(etc, APPORT_UNIT + ".d", "90-reviewed.conf");
    const sysctlGate = join(etc, SYSTEMD_SYSCTL_UNIT + ".d", "90-reviewed.conf");
    mkdirSync(join(etc, APPORT_UNIT + ".d"));
    mkdirSync(join(etc, SYSTEMD_SYSCTL_UNIT + ".d"));
    mkdirSync(sysctlWants);
    for (const path of [apportFragment, sysctlFragment, guardFragment, apportGate, sysctlGate]) {
      writeFileSync(path, "[Unit]\nDescription=reviewed\n");
    }
    symlinkSync("../" + SYSTEMD_SYSCTL_UNIT, sysctlEnablement);
    symlinkSync(SYSTEMD_SYSCTL_ALIAS_TARGET, sysctlAlias);
    const canonicalSysctlEnablement = join(realpathSync(sysctlWants), SYSTEMD_SYSCTL_UNIT);
    const allowlist = {
      [APPORT_UNIT]: {
        dropin_paths: [realpathSync(apportGate)],
        fragment_paths: [realpathSync(apportFragment)],
      },
      [GUARD_UNIT]: { dropin_paths: [], fragment_paths: [realpathSync(guardFragment)] },
      [SYSTEMD_SYSCTL_UNIT]: {
        alias_paths: [sysctlAlias],
        alias_targets: { [sysctlAlias]: SYSTEMD_SYSCTL_ALIAS_TARGET },
        dropin_paths: [realpathSync(sysctlGate)],
        enablement_paths: [canonicalSysctlEnablement],
        enablement_targets: { [canonicalSysctlEnablement]: "../" + SYSTEMD_SYSCTL_UNIT },
        fragment_paths: [realpathSync(sysctlFragment)],
      },
    };
    const roots = [control, runtime, generator, etc, vendor];
    const closed = scanManagedUnitLoadPaths(roots, allowlist);
    assert.deepEqual(closed[SYSTEMD_SYSCTL_UNIT].alias_paths, [sysctlAlias]);
    assert.deepEqual(closed[SYSTEMD_SYSCTL_UNIT].dropin_paths, [realpathSync(sysctlGate)]);
    assert.deepEqual(closed[SYSTEMD_SYSCTL_UNIT].enablement_paths, [canonicalSysctlEnablement]);
    const nestedAlias = join(sysctlWants, "evil.service");
    symlinkSync("../" + SYSTEMD_SYSCTL_UNIT, nestedAlias);
    assert.throws(
      function () { scanManagedUnitLoadPaths(roots, allowlist); },
      /unreviewed alias or activation path/u,
    );
    unlinkSync(nestedAlias);
    const topLevelAlias = join(runtime, "evil.service");
    symlinkSync(realpathSync(sysctlFragment), topLevelAlias);
    assert.throws(
      function () { scanManagedUnitLoadPaths(roots, allowlist); },
      /unreviewed alias or activation path/u,
    );
    unlinkSync(topLevelAlias);
    unlinkSync(sysctlAlias);
    symlinkSync("./" + SYSTEMD_SYSCTL_UNIT, sysctlAlias);
    assert.throws(
      function () { scanManagedUnitLoadPaths(roots, allowlist); },
      /alias differs from reviewed state/u,
    );
    unlinkSync(sysctlAlias);
    symlinkSync(SYSTEMD_SYSCTL_ALIAS_TARGET, sysctlAlias);
    for (const bypassRoot of [runtime, control, generator, vendor]) {
      const directory = join(bypassRoot, SYSTEMD_SYSCTL_UNIT + ".d");
      mkdirSync(directory, { recursive: true });
      const bypass = join(directory, "99-bypass.conf");
      writeFileSync(bypass, "[Service]\nExecCondition=\n");
      assert.throws(
        function () { scanManagedUnitLoadPaths(roots, allowlist); },
        /unreviewed drop-in\/load path/u,
      );
      unlinkSync(bypass);
      rmSync(directory, { recursive: true });
    }
    for (const inheritedDirectory of ["service.d", "systemd-.service.d"]) {
      const directory = join(runtime, inheritedDirectory);
      mkdirSync(directory);
      const bypass = join(directory, "99-inherited-bypass.conf");
      writeFileSync(bypass, "[Service]\nExecCondition=\n");
      assert.throws(
        function () { scanManagedUnitLoadPaths(roots, allowlist); },
        /unreviewed drop-in\/load path/u,
      );
      rmSync(directory, { recursive: true });
    }
    const aliasDropinDirectory = join(runtime, SYSTEMD_SYSCTL_ALIAS_UNIT + ".d");
    mkdirSync(aliasDropinDirectory);
    writeFileSync(join(aliasDropinDirectory, "99-alias-bypass.conf"), "[Service]\nExecCondition=\n");
    assert.throws(
      function () { scanManagedUnitLoadPaths(roots, allowlist); },
      /unreviewed drop-in\/load path/u,
    );
    rmSync(aliasDropinDirectory, { recursive: true });
    const shadow = join(runtime, SYSTEMD_SYSCTL_UNIT);
    writeFileSync(shadow, "[Service]\nExecCondition=\n");
    assert.throws(
      function () { scanManagedUnitLoadPaths(roots, allowlist); },
      /unreviewed effective fragment/u,
    );
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("systemd-sysctl load-path validation requires the exact vendor boot enablement", () => {
  const exact = {
    [SYSTEMD_SYSCTL_UNIT]: {
      alias_paths: [SYSTEMD_SYSCTL_ALIAS_PATH],
      enablement_paths: [SYSTEMD_SYSCTL_ENABLEMENT_PATH],
      fragment_paths: [SYSTEMD_SYSCTL_UNIT_PATH],
    },
  };
  assert.equal(validateSystemdSysctlLoadPathsForTest(exact), true);
  const missingAlias = structuredClone(exact);
  missingAlias[SYSTEMD_SYSCTL_UNIT].alias_paths = [];
  assert.throws(
    function () { validateSystemdSysctlLoadPathsForTest(missingAlias); },
    /alias\/fragment\/boot enablement/u,
  );
  const extraAlias = structuredClone(exact);
  extraAlias[SYSTEMD_SYSCTL_UNIT].alias_paths.push("/usr/lib/systemd/system/extra.service");
  assert.throws(
    function () { validateSystemdSysctlLoadPathsForTest(extraAlias); },
    /alias\/fragment\/boot enablement/u,
  );
  const missing = structuredClone(exact);
  missing[SYSTEMD_SYSCTL_UNIT].enablement_paths = [];
  assert.throws(
    function () { validateSystemdSysctlLoadPathsForTest(missing); },
    /boot enablement/u,
  );
});

test("systemd-equivalent word parsing closes quoted Wants and stop/reload dependency directives", () => {
  assert.deepEqual(parseSystemdWords("  one 'two three' \"apport\\x2eservice\"  "), [
    "one", "two three", APPORT_UNIT,
  ]);
  const root = mkdtempSync(join(tmpdir(), "bitcoinpir-core-dependencies-"));
  try {
    const cases = [
      "Wants=\"apport.service\"",
      "Conflicts=apport.service",
      "OnFailureOf=apport.service",
      "OnSuccessOf=apport.service",
      "PropagatesStopTo=apport.service",
      "PropagatesReloadTo='apport.service'",
      "PartOf=apport\\x2eservice",
    ];
    for (const directive of cases) {
      const path = join(root, "foreign.service");
      writeFileSync(path, "[Unit]\n" + directive + "\n");
      assert.throws(
        function () { scanApportEnablement([root]); },
        /references apport\.service/u,
        directive,
      );
      unlinkSync(path);
    }
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("systemd unit discovery rejects unresolved specifiers in action and Exec directives", () => {
  const root = mkdtempSync(join(tmpdir(), "bitcoinpir-core-specifiers-"));
  try {
    const cases = [
      "[Unit]\nWants=%i.service\n",
      "[Service]\nExecStart=/usr/share/%i/apport --start\n",
      "[Service]\nExecStart=/usr/share/foo/../%i/apport --start\n",
      "[Service]\nExecStart=/usr/share/apport/../apport/apport --start\n",
      "[Service]\nExecStart=/usr/share//apport/apport --start\n",
      "[Service]\nExecSearchPath=/usr/share/apport\nExecStart=apport --start\n",
      "[Service]\nExecStart=/usr/bin/env /usr/share/%i/apport --start\n",
      "[Service]\nExecStart=/bin/sh -c 'exec /usr/share/%i/apport --start'\n",
    ];
    for (const bytes of cases) {
      const path = join(root, "foreign@.service");
      writeFileSync(path, bytes);
      assert.throws(
        function () { scanApportEnablement([root]); },
        /references apport\.service/u,
      );
      unlinkSync(path);
    }
    for (const bytes of [
      "[Unit]\nRequires=systemd-fsck@%i.service\n",
      "[Service]\nExecStart=/usr/lib/systemd/systemd-fsck %f\n",
    ]) {
      const path = join(root, "stock-like@.service");
      writeFileSync(path, bytes);
      assert.deepEqual(scanApportEnablement([root]), []);
      unlinkSync(path);
    }
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("production canonical and D-Bus parsers reject non-canonical, duplicate, and unloaded input", () => {
  const plan = fixturePlan();
  const bytes = Buffer.from(canonicalJson(plan), "utf8");
  assert.deepEqual(parseCanonicalJsonBytes(bytes, "plan"), plan);
  assert.throws(
    function () { parseCanonicalJsonBytes(Buffer.from("{\"b\":1,\"a\":2}\n"), "plan"); },
    /not canonical/u,
  );
  assert.throws(
    function () { parseCanonicalJsonBytes(Buffer.from("{\"a\":1,\"a\":1}\n"), "plan"); },
    /not canonical/u,
  );
  const row = [
    "apport.service", "Apport", "loaded", "active", "exited", "",
    "/org/freedesktop/systemd1/unit/apport_2eservice", 0, "", "/",
  ];
  const envelope = JSON.stringify({ type: "a(ssssssouso)", data: [row] });
  assert.deepEqual(
    parseLoadedApportUnitRows(parseBusctlJson(envelope, "a(ssssssouso)", "ListUnits")),
    row,
  );
  assert.throws(function () { parseLoadedApportUnitRows([]); }, /already be present/u);
  assert.throws(
    function () { parseLoadedApportUnitRows([[...row.slice(0, 2), "not-found", ...row.slice(3)]]); },
    /unloaded Apport unit/u,
  );
  assert.throws(
    function () {
      parseBusctlJson(
        "{\"type\":\"s\",\"type\":\"s\",\"data\":\"loaded\"}",
        "s",
        "LoadState",
      );
    },
    /duplicate-key/u,
  );
});

test("GetAll parsing and manager fences reject duplicate, torn, queued, PID, job, and reload evidence", () => {
  const getAll = parseBusctlGetAll(
    '{"type":"a{sv}","data":[{"NeedDaemonReload":{"type":"b","data":false},' +
      '"Huge":{"type":"t","data":18446744073709551615}}]}',
    "GetAll",
  );
  assert.equal(getAll.NeedDaemonReload.data, false);
  assert.deepEqual(getAll.Huge.data, { raw_integer: "18446744073709551615" });
  assert.throws(
    function () {
      parseBusctlGetAll(
        '{"type":"a{sv}","data":[{"Id":{"type":"s","data":"a"},' +
          '"Id":{"type":"s","data":"a"}}]}',
        "GetAll",
      );
    },
    /duplicate JSON key/u,
  );
  for (const malformedData of [
    '{}',
    '[]',
    '[{},{}]',
    '[[]]',
  ]) {
    assert.throws(
      function () {
        parseBusctlGetAll('{"type":"a{sv}","data":' + malformedData + '}', "GetAll");
      },
      /signature differs from a\{sv\}/u,
    );
  }
  const objectPath = "/org/freedesktop/systemd1/unit/apport_2eservice";
  const row = [APPORT_UNIT, "Apport", "loaded", "active", "exited", "", objectPath, 0, "", "/"];
  const variant = function (type, data) { return { data, type }; };
  const unit = {
    ActiveState: variant("s", "active"),
    DropInPaths: variant("as", []),
    FragmentPath: variant("s", APPORT_UNIT_PATH),
    Id: variant("s", APPORT_UNIT),
    Job: variant("(uo)", [0, "/"]),
    LoadState: variant("s", "loaded"),
    Names: variant("as", [APPORT_UNIT]),
    NeedDaemonReload: variant("b", false),
    SourcePath: variant("s", ""),
    SubState: variant("s", "exited"),
    Transient: variant("b", false),
  };
  const service = { ControlPID: variant("u", 0), MainPID: variant("u", 0) };
  assert.equal(validateLoadedUnitMetadataForTest(APPORT_UNIT, row, unit, service).values.main_pid, 0);
  const sysctlObjectPath =
    "/org/freedesktop/systemd1/unit/systemd_2dsysctl_2eservice";
  const sysctlRow = [
    SYSTEMD_SYSCTL_UNIT,
    "Apply Kernel Variables",
    "loaded",
    "active",
    "exited",
    "",
    sysctlObjectPath,
    0,
    "",
    "/",
  ];
  const sysctlUnit = structuredClone(unit);
  sysctlUnit.Id.data = SYSTEMD_SYSCTL_UNIT;
  sysctlUnit.Names.data = [SYSTEMD_SYSCTL_UNIT, SYSTEMD_SYSCTL_ALIAS_UNIT];
  sysctlUnit.FragmentPath.data = SYSTEMD_SYSCTL_UNIT_PATH;
  assert.deepEqual(
    validateLoadedUnitMetadataForTest(
      SYSTEMD_SYSCTL_UNIT,
      sysctlRow,
      sysctlUnit,
      service,
    ).values.names,
    [SYSTEMD_SYSCTL_ALIAS_UNIT, SYSTEMD_SYSCTL_UNIT].sort(),
  );
  for (const names of [
    [SYSTEMD_SYSCTL_UNIT],
    [SYSTEMD_SYSCTL_ALIAS_UNIT, SYSTEMD_SYSCTL_UNIT, "extra.service"],
  ]) {
    const changedUnit = structuredClone(sysctlUnit);
    changedUnit.Names.data = names;
    assert.throws(
      function () {
        validateLoadedUnitMetadataForTest(
          SYSTEMD_SYSCTL_UNIT,
          sysctlRow,
          changedUnit,
          service,
        );
      },
      /aliased/u,
    );
  }
  const apportAlias = structuredClone(unit);
  apportAlias.Names.data = [APPORT_UNIT, "extra.service"];
  assert.throws(
    function () { validateLoadedUnitMetadataForTest(APPORT_UNIT, row, apportAlias, service); },
    /aliased/u,
  );
  for (const mutate of [
    function (copy) { copy.unit.NeedDaemonReload.data = true; },
    function (copy) { copy.service.MainPID.data = 99; },
    function (copy) { copy.unit.Job.data = [7, "/org/freedesktop/systemd1/job/7"]; },
    function (copy) { copy.row[7] = 7; copy.row[8] = "reload"; },
  ]) {
    const copy = { row: structuredClone(row), service: structuredClone(service), unit: structuredClone(unit) };
    mutate(copy);
    assert.throws(
      function () { validateLoadedUnitMetadataForTest(APPORT_UNIT, copy.row, copy.unit, copy.service); },
      /executing|transitioning|queued|reload/u,
    );
  }
  assert.equal(assertManagerSnapshotFenceForTest([row], [], [row], []), true);
  const changed = structuredClone(row);
  changed[3] = "inactive";
  changed[4] = "dead";
  assert.throws(
    function () { assertManagerSnapshotFenceForTest([row], [], [changed], []); },
    /changed across/u,
  );
  assert.throws(
    function () {
      assertManagerSnapshotFenceForTest(
        [row], [], [row], [[1, APPORT_UNIT, "restart", "waiting", "/job/1", objectPath]],
      );
    },
    /changed across/u,
  );
  const manager = {
    UnitPath: { data: Array.from(SYSTEMD_MANAGER_UNIT_PATHS), type: "as" },
  };
  assert.deepEqual(validateManagerUnitPathForTest(manager), SYSTEMD_MANAGER_UNIT_PATHS);
  const customManager = structuredClone(manager);
  customManager.UnitPath.data.unshift("/run/unreviewed-systemd-units");
  assert.throws(
    function () { validateManagerUnitPathForTest(customManager); },
    /UnitPath differs/u,
  );
  assert.throws(
    function () {
      assertManagerSnapshotFenceForTest(
        [row], [], [row], [], manager.UnitPath.data, customManager.UnitPath.data,
      );
    },
    /changed across/u,
  );
});

test("effective GetAll closure rejects every foreign Apport edge and requires cleared guarded ExecStop", () => {
  const variant = function (type, data) { return { data, type }; };
  const exec = function (path, argv) {
    return [path, argv, [], 0, 0, 0, 0, 0, 0, 0];
  };
  const execProperties = function (commands) {
    const properties = {};
    for (const name of [
      "ExecConditionEx", "ExecStartPreEx", "ExecStartEx", "ExecStartPostEx",
      "ExecReloadEx", "ExecStopEx", "ExecStopPostEx",
    ]) {
      properties[name] = variant("a(sasasttttuii)", commands[name] || []);
    }
    return properties;
  };
  const values = function (fragmentPath, dropinPaths) {
    return {
      active_state: "inactive",
      control_pid: 0,
      dropin_paths: dropinPaths,
      fragment_path: fragmentPath,
      job: [0, "/"],
      load_state: "loaded",
      main_pid: 0,
      names: fragmentPath === SYSTEMD_SYSCTL_UNIT_PATH
        ? [SYSTEMD_SYSCTL_ALIAS_UNIT, SYSTEMD_SYSCTL_UNIT].sort()
        : fragmentPath === GUARD_UNIT_PATH ? [GUARD_UNIT] : [APPORT_UNIT],
      need_daemon_reload: false,
      source_path: "",
      sub_state: "dead",
      transient: false,
    };
  };
  const apportUnit = {};
  for (const property of [
    "BindsTo", "BoundBy", "ConflictedBy", "Conflicts", "ConsistsOf", "OnFailure",
    "OnFailureOf", "OnSuccess", "OnSuccessOf", "PartOf", "PropagatesReloadTo",
    "PropagatesStopTo", "ReloadPropagatedFrom",
    "RequiredBy", "Requires", "Requisite", "RequisiteOf", "StopPropagatedFrom", "TriggeredBy",
    "Triggers", "UpheldBy", "Upholds", "WantedBy", "Wants",
  ]) {
    apportUnit[property] = variant("as", []);
  }
  apportUnit.Conflicts.data = ["shutdown.target"];
  apportUnit.Requires.data = ["sysinit.target"];
  apportUnit.WantedBy.data = ["multi-user.target"];
  apportUnit.StopWhenUnneeded = variant("b", false);
  const snapshot = {
    apport: {
      service: execProperties({
        ExecConditionEx: [exec("/usr/bin/node", [
          "/usr/bin/node", "/usr/local/libexec/bitcoinpir/payment-v1-core-pattern-ceremony.mjs",
          "early-apport-gate",
        ])],
        ExecStartEx: [exec("/usr/share/apport/apport", ["/usr/share/apport/apport", "--start"])],
      }),
      unit: apportUnit,
      values: values(APPORT_UNIT_PATH, [APPORT_GATE_PATH]),
    },
    guard: {
      service: execProperties({
        ExecStartEx: [exec("/usr/bin/node", [
          "/usr/bin/node", "/usr/local/libexec/bitcoinpir/payment-v1-core-pattern-ceremony.mjs",
          "early-fail-closed",
        ])],
      }),
      unit: {},
      values: values(GUARD_UNIT_PATH, []),
    },
    sysctl: {
      service: execProperties({
        ExecConditionEx: [exec("/usr/bin/node", [
          "/usr/bin/node", "/usr/local/libexec/bitcoinpir/payment-v1-core-pattern-ceremony.mjs",
          "early-sysctl-gate",
        ])],
        ExecStartEx: [exec("/usr/lib/systemd/systemd-sysctl", ["/usr/lib/systemd/systemd-sysctl"])],
      }),
      unit: { WantedBy: variant("as", ["sysinit.target"]) },
      values: values(SYSTEMD_SYSCTL_UNIT_PATH, [SYSCTL_GATE_PATH]),
    },
  };
  snapshot.sysctl.service.ImportCredential = variant("as", ["sysctl.*"]);
  snapshot.sysctl.service.LoadCredential = variant("a(ss)", []);
  snapshot.sysctl.service.LoadCredentialEncrypted = variant("a(ss)", []);
  snapshot.sysctl.service.SetCredential = variant("a(say)", []);
  snapshot.sysctl.service.SetCredentialEncrypted = variant("a(say)", []);
  assert.equal(validateRuntimeConfigurationForTest(snapshot, "guarded-preimage"), true);
  for (const names of [
    [SYSTEMD_SYSCTL_UNIT],
    [SYSTEMD_SYSCTL_ALIAS_UNIT, SYSTEMD_SYSCTL_UNIT, "extra.service"],
  ]) {
    const changed = structuredClone(snapshot);
    changed.sysctl.values.names = names;
    assert.throws(
      function () { validateRuntimeConfigurationForTest(changed, "guarded-preimage"); },
      /Names/u,
    );
  }
  const foreignApportName = structuredClone(snapshot);
  foreignApportName.apport.values.names = [APPORT_UNIT, "extra.service"];
  assert.throws(
    function () { validateRuntimeConfigurationForTest(foreignApportName, "guarded-preimage"); },
    /Names/u,
  );
  const missingGuardName = structuredClone(snapshot);
  missingGuardName.guard.values.names = [];
  assert.throws(
    function () { validateRuntimeConfigurationForTest(missingGuardName, "guarded-preimage"); },
    /Names/u,
  );
  for (const property of [
    "Wants", "ConflictedBy", "OnFailureOf", "OnSuccessOf", "RequiredBy",
    "ReloadPropagatedFrom", "StopPropagatedFrom",
  ]) {
    const changed = structuredClone(snapshot);
    changed.apport.unit[property].data = ["foreign.service"];
    assert.throws(
      function () { validateRuntimeConfigurationForTest(changed, "guarded-preimage"); },
      /unreviewed start\/stop\/reload edge/u,
      property,
    );
  }
  const stopRestored = structuredClone(snapshot);
  stopRestored.apport.service.ExecStopEx.data = [
    exec("/usr/share/apport/apport", ["/usr/share/apport/apport", "--stop"]),
  ];
  assert.throws(
    function () { validateRuntimeConfigurationForTest(stopRestored, "guarded-preimage"); },
    /ExecStopEx differs/u,
  );
  const wrongFragment = structuredClone(snapshot);
  wrongFragment.sysctl.values.fragment_path = "/run/systemd/system/systemd-sysctl.service";
  assert.throws(
    function () { validateRuntimeConfigurationForTest(wrongFragment, "guarded-preimage"); },
    /FragmentPath/u,
  );
  const unsafeSysctlExec = structuredClone(snapshot);
  unsafeSysctlExec.sysctl.service.ExecStartPreEx.data = [
    exec("/bin/sh", ["/bin/sh", "-c", "echo unsafe >/proc/sys/kernel/core_pattern"]),
  ];
  assert.throws(
    function () { validateRuntimeConfigurationForTest(unsafeSysctlExec, "guarded-preimage"); },
    /ExecStartPreEx differs/u,
  );
  const replacedSysctlExec = structuredClone(snapshot);
  replacedSysctlExec.sysctl.service.ExecStartEx.data = [exec("/bin/true", ["/bin/true"])];
  assert.throws(
    function () { validateRuntimeConfigurationForTest(replacedSysctlExec, "guarded-preimage"); },
    /ExecStartEx differs/u,
  );
  const masked = structuredClone(snapshot);
  masked.apport.values.load_state = "masked";
  masked.apport.values.fragment_path = APPORT_MASK_PATH;
  masked.apport.unit.Conflicts.data = [];
  masked.apport.unit.Requires.data = [];
  masked.apport.unit.WantedBy.data = [];
  masked.apport.service.ExecStartEx.data = [];
  masked.sysctl.values.dropin_paths = [SYSCTL_CREDENTIAL_CLOSURE_PATH, SYSCTL_GATE_PATH];
  masked.sysctl.service.ImportCredential.data = [];
  assert.equal(validateRuntimeConfigurationForTest(masked, "apply-terminal"), true);
  assert.equal(
    validateRuntimeConfigurationForTest(masked, "rollback-preflight-pre-publish"),
    true,
  );
  masked.apport.values.fragment_path = "/dev/null";
  assert.throws(
    function () { validateRuntimeConfigurationForTest(masked, "apply-terminal"); },
    /FragmentPath/u,
  );
  const freshCandidate = structuredClone(masked);
  freshCandidate.apport.values.fragment_path = APPORT_MASK_PATH;
  freshCandidate.apport.values.dropin_paths = [];
  freshCandidate.apport.service.ExecConditionEx.data = [];
  freshCandidate.guard = null;
  freshCandidate.sysctl.values.dropin_paths = [SYSCTL_CREDENTIAL_CLOSURE_PATH];
  freshCandidate.sysctl.service.ExecConditionEx.data = [];
  assert.equal(validateRuntimeConfigurationForTest(freshCandidate, "fresh-candidate"), true);
  const credentialBypass = structuredClone(masked);
  credentialBypass.apport.values.fragment_path = APPORT_MASK_PATH;
  credentialBypass.sysctl.service.ImportCredential.data = ["sysctl.*"];
  assert.throws(
    function () { validateRuntimeConfigurationForTest(credentialBypass, "apply-terminal"); },
    /ImportCredential/u,
  );
  const missingBootActivation = structuredClone(masked);
  missingBootActivation.apport.values.fragment_path = APPORT_MASK_PATH;
  missingBootActivation.sysctl.unit.WantedBy.data = [];
  assert.throws(
    function () { validateRuntimeConfigurationForTest(missingBootActivation, "apply-terminal"); },
    /boot activation/u,
  );
  const wrongDropin = structuredClone(snapshot);
  wrongDropin.guard.values.dropin_paths = ["/run/systemd/system/guard.service.d/99.conf"];
  assert.throws(
    function () { validateRuntimeConfigurationForTest(wrongDropin, "guarded-preimage"); },
    /FragmentPath\/DropInPaths/u,
  );
});

test("all mutating ceremony entry points prove maintenance locks before state access", async () => {
  const plan = fixturePlan();
  const applyOps = new FakeOps(plan);
  const applied = await applyCeremony(plan, contextFor(plan), applyOps);
  assert.equal(applyOps.calls[0], "verify-host-tools");

  const rollbackOps = new FakeOps(plan, applyOps.serialize());
  await rollbackCeremony(plan, {
    ...contextFor(plan),
    applyApprovalSha256: applied.receipt.apply_approval_sha256,
    receiptSha256: applied.receipt_sha256,
    rollbackApprovalSha256: "d".repeat(64),
  }, rollbackOps);
  assert.equal(rollbackOps.calls[0], "verify-host-tools");

  const recoveryOps = new FakeOps(plan);
  recoveryOps.locked = true;
  recoveryOps.lease = leaseFor(plan, "apply");
  const recoveryContext = contextFor(plan, {
    actionBootId: FRESH_BOOT_ID,
    recoveryApprovedSubjectSha256: serializedDigest(recoveryOps.lease),
    recoverySubjectKind: "lease",
  });
  await recoverCeremony(plan, recoveryContext, recoveryOps);
  assert.equal(recoveryOps.calls[0], "verify-host-tools");
});

test("every production publish, cleanup, and host mutator rejects before maintenance-lock proof", async () => {
  const plan = fixturePlan();
  const ops = realOps(plan);
  const context = contextFor(plan);
  const lease = leaseFor(plan, "apply");
  const preflight = preflightFor(plan, "apply");
  const pending = pendingFor(plan, "apply");
  const mutations = [
    function () { return ops.acquireLock(plan.transaction.lock_path, context, lease); },
    function () { return ops.recoverLock(plan.transaction.lock_path, context, lease); },
    function () { return ops.makeRelease(plan.transaction.lock_path, lease)(); },
    function () { return ops.createPending(plan.transaction.pending_path, pending); },
    function () { return ops.createPreflight(preflight); },
    function () { return ops.clearPending(plan.transaction.pending_path, pending); },
    function () {
      return ops.finalizeTerminal(
        plan.transaction.lock_path,
        plan.transaction.pending_path,
        pending,
        context,
      );
    },
    function () { return ops.ensureApportEnablement(plan.preimage.apport_enablement_symlinks[0]); },
    function () { return ops.ensureApportMask(plan.candidate.apport_mask); },
    function () { return ops.ensureGuard(plan.candidate.guard_unit, plan.candidate.guard_enablement); },
    function () { return ops.installPersistent(plan.candidate.persistent_policy); },
    function () { return ops.publishReceipt(plan.transaction.receipt_path, pending); },
    function () {
      return ops.publishReceiptAfterFullInspection(
        plan.transaction.receipt_path,
        pending,
        expectedPreimage(plan),
        "mutation gate",
      );
    },
    function () { return ops.removeApportEnablement(plan.preimage.apport_enablement_symlinks[0]); },
    function () { return ops.removeApportMask(plan.candidate.apport_mask); },
    function () { return ops.removeGuard(plan.candidate.guard_unit, plan.candidate.guard_enablement); },
    function () { return ops.removePersistent(plan.candidate.persistent_policy); },
    function () { return ops.reloadManager(); },
    function () { return ops.writePreflight(preflight); },
    function () { return ops.writePending(plan.transaction.pending_path, pending); },
    function () { return ops.writeSysctl("kernel.core_pattern", TARGET_CORE_PATTERN); },
  ];
  for (const mutate of mutations) {
    await assert.rejects(mutate, /requires inherited maintenance locks to be proven first/u);
  }
});

test("guard symlink install/removal replays every link, rename, unlink, verify, and fsync boundary", (t) => {
  if (process.platform !== "linux") {
    t.skip("Linux link(2) symlink semantics run on the ordinary Linux CI worker");
    return;
  }
  const removalBoundaries = [
    "remove-link-quarantine",
    "remove-fsync-link",
    "remove-verify-linked-pair",
    "remove-unlink-live",
    "remove-fsync-live-unlink",
    "remove-verify-quarantine",
    "remove-unlink-quarantine",
    "remove-fsync-quarantine-unlink",
  ];
  const replayBoundaries = [
    "remove-replay-unlink-live",
    "remove-replay-fsync-live",
    "remove-replay-unlink-quarantine",
    "remove-replay-fsync-quarantine",
  ];
  const ensureBoundaries = [
    "ensure-create-symlink",
    "ensure-fsync-created",
    "ensure-verify-created",
  ];
  const ensureQuarantineLinkBoundaries = [
    "ensure-quarantine-live-observed-absent",
    "ensure-link-quarantine-to-live",
    "ensure-fsync-after-quarantine-link",
    "ensure-verify-quarantine-link",
  ];
  const ensureLinkedBoundaries = [
    "ensure-unlink-quarantine",
    "ensure-fsync-after-quarantine-unlink",
  ];
  function fixture() {
    const root = mkdtempSync(join(tmpdir(), "bitcoinpir-core-link-"));
    const ownerStat = statSync(root);
    return {
      live: join(root, "guard.service"),
      options: { owner: { gid: ownerStat.gid, uid: ownerStat.uid } },
      quarantine: join(root, "guard.service.quarantine"),
      root,
      target: "/reviewed/guard.service",
    };
  }
  for (const boundary of ensureBoundaries) {
    const state = fixture();
    try {
      assert.throws(function () {
        ensureSymlinkForTest(state.live, state.target, state.quarantine, {
          ...state.options,
          afterBoundary(name) { if (name === boundary) throw new Error("power loss"); },
        });
      }, /power loss/u);
      ensureSymlinkForTest(state.live, state.target, state.quarantine, state.options);
      assert.equal(readlinkSync(state.live), state.target);
      assert.equal(existsSync(state.quarantine), false);
    } finally {
      rmSync(state.root, { force: true, recursive: true });
    }
  }
  for (const boundary of ensureQuarantineLinkBoundaries) {
    const state = fixture();
    try {
      symlinkSync(state.target, state.quarantine);
      assert.throws(function () {
        ensureSymlinkForTest(state.live, state.target, state.quarantine, {
          ...state.options,
          afterBoundary(name) { if (name === boundary) throw new Error("power loss"); },
        });
      }, /power loss/u);
      ensureSymlinkForTest(state.live, state.target, state.quarantine, state.options);
      assert.equal(readlinkSync(state.live), state.target);
      assert.equal(existsSync(state.quarantine), false);
    } finally {
      rmSync(state.root, { force: true, recursive: true });
    }
  }
  {
    const state = fixture();
    try {
      symlinkSync(state.target, state.quarantine);
      assert.throws(function () {
        ensureSymlinkForTest(state.live, state.target, state.quarantine, {
          ...state.options,
          afterBoundary(name) {
            if (name === "ensure-quarantine-live-observed-absent") {
              symlinkSync(state.target, state.live);
            }
          },
        });
      }, /raced retained quarantine publication/u);
      assert.equal(readlinkSync(state.live), state.target);
      const live = lstatSync(state.live, { bigint: true });
      const quarantine = lstatSync(state.quarantine, { bigint: true });
      assert.notEqual(live.ino, quarantine.ino);
    } finally {
      rmSync(state.root, { force: true, recursive: true });
    }
  }
  for (const boundary of ensureLinkedBoundaries) {
    const state = fixture();
    try {
      symlinkSync(state.target, state.live);
      linkSync(state.live, state.quarantine);
      assert.throws(function () {
        ensureSymlinkForTest(state.live, state.target, state.quarantine, {
          ...state.options,
          afterBoundary(name) { if (name === boundary) throw new Error("power loss"); },
        });
      }, /power loss/u);
      ensureSymlinkForTest(state.live, state.target, state.quarantine, state.options);
      assert.equal(readlinkSync(state.live), state.target);
      assert.equal(existsSync(state.quarantine), false);
    } finally {
      rmSync(state.root, { force: true, recursive: true });
    }
  }
  for (const boundary of removalBoundaries) {
    const state = fixture();
    try {
      symlinkSync(state.target, state.live);
      assert.throws(function () {
        removeSymlinkForTest(state.live, state.target, state.quarantine, {
          ...state.options,
          afterBoundary(name) { if (name === boundary) throw new Error("power loss"); },
        });
      }, /power loss/u);
      removeSymlinkForTest(state.live, state.target, state.quarantine, state.options);
      removeSymlinkForTest(state.live, state.target, state.quarantine, state.options);
      assert.equal(existsSync(state.live), false);
      assert.equal(existsSync(state.quarantine), false);
    } finally {
      rmSync(state.root, { force: true, recursive: true });
    }
  }
  for (const boundary of replayBoundaries) {
    const state = fixture();
    try {
      symlinkSync(state.target, state.live);
      linkSync(state.live, state.quarantine);
      assert.throws(function () {
        removeSymlinkForTest(state.live, state.target, state.quarantine, {
          ...state.options,
          afterBoundary(name) { if (name === boundary) throw new Error("power loss"); },
        });
      }, /power loss/u);
      removeSymlinkForTest(state.live, state.target, state.quarantine, state.options);
      assert.equal(existsSync(state.live), false);
      assert.equal(existsSync(state.quarantine), false);
    } finally {
      rmSync(state.root, { force: true, recursive: true });
    }
  }
});

test("receipt post-state does not claim /var/crash is continuously immutable", async () => {
  const plan = fixturePlan();
  const ops = new FakeOps(plan);
  const result = await applyCeremony(plan, contextFor(plan), ops);
  assert.deepEqual(result.receipt.post_state.crash_entries, []);
  assert.equal(Object.hasOwn(result.receipt.post_state, "crash_entries_remain_unchanged"), false);
  assert.deepEqual(result.receipt.post_state.crash_directory, plan.preimage.crash_directory);
});
