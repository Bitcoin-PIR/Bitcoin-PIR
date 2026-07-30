#!/usr/bin/env node

import { readFileSync, writeFileSync } from "node:fs";

import {
  applyCeremony,
  canonicalJson,
  recoverCeremony,
  rollbackCeremony,
  sha256,
} from "./payment-v1-core-pattern-ceremony.mjs";
import {
  FRESH_BOOT_ID,
  FakeOps,
  contextFor,
  fixturePlan,
} from "./payment-v1-core-pattern-test-fixture.mjs";

const [mode, statePath, crashBoundary, crashSignal] = process.argv.slice(2);
if (!["apply", "reboot", "recover", "rollback"].includes(mode) || statePath === undefined) {
  throw new Error("usage: worker apply|reboot|recover|rollback STATE [BOUNDARY SIGNAL]");
}

let serialized;
try {
  serialized = JSON.parse(readFileSync(statePath, "utf8"));
} catch (error) {
  if (error.code !== "ENOENT") throw error;
}

const plan = fixturePlan();
let crashed = false;
const ops = new FakeOps(plan, serialized, {
  onBoundary(name, state) {
    writeFileSync(statePath, canonicalJson(state), { encoding: "utf8", flag: "w" });
    if (!crashed && crashBoundary !== undefined && name === crashBoundary) {
      crashed = true;
      if (crashSignal === "SIGABRT") process.abort();
      process.kill(process.pid, crashSignal || "SIGKILL");
    }
  },
});

const recoverySubject = serialized?.pending ?? serialized?.preflight ?? serialized?.lease;
const recoverySubjectKind = serialized?.pending !== null && serialized?.pending !== undefined
  ? "pending"
  : serialized?.preflight !== null && serialized?.preflight !== undefined
    ? "preflight"
    : "lease";
const context = contextFor(plan, {
  actionBootId: mode === "recover" ? FRESH_BOOT_ID : undefined,
  recoveryApprovedSubjectSha256:
    mode === "recover" && recoverySubject !== null && recoverySubject !== undefined
      ? sha256(Buffer.from(canonicalJson(recoverySubject), "utf8"))
      : undefined,
  recoverySubjectKind,
});
if (mode === "reboot") {
  ops.simulateReboot();
  writeFileSync(statePath, canonicalJson(ops.serialize()), { encoding: "utf8", flag: "w" });
  process.stdout.write("rebooted\n");
  process.exit(0);
}
if (mode === "rollback") {
  const receipt = serialized.receipts[plan.transaction.receipt_path];
  Object.assign(context, {
    applyApprovalSha256: receipt.apply_approval_sha256,
    receiptSha256: sha256(Buffer.from(canonicalJson(receipt), "utf8")),
    rollbackApprovalSha256: "d".repeat(64),
  });
}
if (mode === "recover" && recoverySubject?.mode === "rollback") {
  const receipt = serialized.receipts[plan.transaction.receipt_path];
  Object.assign(context, {
    applyApprovalSha256: receipt.apply_approval_sha256,
    receiptSha256: sha256(Buffer.from(canonicalJson(receipt), "utf8")),
  });
}
const result = mode === "apply"
  ? await applyCeremony(plan, context, ops)
  : mode === "rollback"
    ? await rollbackCeremony(plan, context, ops)
    : await recoverCeremony(plan, context, ops);
writeFileSync(statePath, canonicalJson(ops.serialize()), { encoding: "utf8", flag: "w" });
process.stdout.write(result.outcome + "\n");
