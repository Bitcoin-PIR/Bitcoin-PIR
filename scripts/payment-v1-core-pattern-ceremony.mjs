#!/usr/bin/env node

// Host-wide Payment V1 core-diagnostic ceremony. This executor is deliberately
// separate from every Caddy/service transaction: callers must approve the exact
// canonical plan, the exact approval document, and this exact source digest.

import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  closeSync,
  constants,
  fchmodSync,
  fchownSync,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmdirSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const CEREMONY_KIND = "bitcoinpir-payment-v1-core-pattern-ceremony-v1";
export const APPLY_APPROVAL_KIND =
  "bitcoinpir-payment-v1-core-pattern-apply-approval-v1";
export const ROLLBACK_APPROVAL_KIND =
  "bitcoinpir-payment-v1-core-pattern-rollback-approval-v1";
export const RECEIPT_KIND = "bitcoinpir-payment-v1-core-pattern-receipt-v1";
export const ROLLBACK_RECEIPT_KIND =
  "bitcoinpir-payment-v1-core-pattern-rollback-receipt-v1";
export const TARGET_CORE_PATTERN = "|/usr/bin/false";
export const OBSERVED_APPORT_CORE_PATTERN =
  "|/usr/share/apport/apport -p%p -s%s -c%c -d%d -P%P -u%u -g%g -F%F -- %E";
export const APPORT_DEFAULT_PATH = "/etc/default/apport";
export const APPORT_UNIT = "apport.service";
export const PERSISTENT_POLICY_PATH =
  "/etc/sysctl.d/99-z-bitcoinpir-payment-v1-no-core.conf";
export const EXECUTOR_PATH =
  "/usr/local/libexec/bitcoinpir/payment-v1-core-pattern-ceremony.mjs";
export const APPLY_ACKNOWLEDGEMENTS = Object.freeze([
  "host-wide-native-core-diagnostics-will-be-unavailable",
  "apport-will-be-disabled-and-new-var-crash-reports-will-not-be-produced",
  "existing-var-crash-files-and-journal-records-will-be-retained",
  "this-approval-does-not-authorize-reboot-payment-service-activation-or-history-deletion",
]);
export const ROLLBACK_ACKNOWLEDGEMENTS = Object.freeze([
  "host-wide-native-core-diagnostics-will-be-restored",
  "apport-will-be-enabled-and-started",
  "restored-crash-material-may-contain-secrets-or-request-correlating-data",
  "this-approval-does-not-authorize-reboot-payment-service-activation-or-history-deletion",
]);

const MAX_JSON_BYTES = 1024 * 1024;
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024;
const SYSCTL_DIRS = Object.freeze([
  "/etc/sysctl.d",
  "/run/sysctl.d",
  "/usr/local/lib/sysctl.d",
  "/usr/lib/sysctl.d",
  "/lib/sysctl.d",
]);
const CORE_ASSIGNMENT = /^\s*-?\/?kernel(?:\.|\/)core_pattern\s*=.*$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const MODE = /^0[0-7]{3}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const SLUG = /^[a-z0-9](?:[a-z0-9-]{0,126}[a-z0-9])?$/u;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u;

function fail(message) {
  throw new Error(message);
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function canonicalize(value) {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) fail("canonical JSON numbers must be safe integers");
    return String(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (isPlainObject(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
      .join(",")}}`;
  }
  fail("canonical JSON contains an unsupported value");
}

export function canonicalJson(value) {
  return `${canonicalize(value)}\n`;
}

export function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function exactKeys(value, expected, label) {
  if (!isPlainObject(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((entry, i) => entry !== wanted[i])) {
    fail(`${label} keys must equal ${JSON.stringify(wanted)}, got ${JSON.stringify(actual)}`);
  }
}

function exactArray(actual, expected, label) {
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    fail(`${label} must equal the reviewed closed set`);
  }
}

function validateSha(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) fail(`${label} must be SHA-256`);
}

function validateAbsolutePath(value, label) {
  if (
    typeof value !== "string" ||
    !value.startsWith("/") ||
    value.includes("\0") ||
    resolve(value) !== value
  ) {
    fail(`${label} must be a normalized absolute path`);
  }
}

function validateFilePin(
  value,
  label,
  { exactPath, bytesRequired = false, maxBytes = MAX_FILE_BYTES } = {},
) {
  const keys = ["gid", "mode", "nlink", "path", "sha256", "size", "uid"];
  if (bytesRequired) keys.push("bytes_base64");
  exactKeys(value, keys, label);
  validateAbsolutePath(value.path, `${label}.path`);
  if (exactPath !== undefined && value.path !== exactPath) {
    fail(`${label}.path must equal ${exactPath}`);
  }
  validateSha(value.sha256, `${label}.sha256`);
  if (!Number.isSafeInteger(value.size) || value.size < 0 || value.size > maxBytes) {
    fail(`${label}.size is outside the reviewed bound`);
  }
  if (!Number.isSafeInteger(value.uid) || value.uid < 0) fail(`${label}.uid is invalid`);
  if (!Number.isSafeInteger(value.gid) || value.gid < 0) fail(`${label}.gid is invalid`);
  if (!Number.isSafeInteger(value.nlink) || value.nlink !== 1) {
    fail(`${label}.nlink must equal 1`);
  }
  if (typeof value.mode !== "string" || !MODE.test(value.mode)) {
    fail(`${label}.mode must be four-digit octal text`);
  }
  if (bytesRequired) {
    if (typeof value.bytes_base64 !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/u.test(value.bytes_base64)) {
      fail(`${label}.bytes_base64 is invalid`);
    }
    const bytes = Buffer.from(value.bytes_base64, "base64");
    if (bytes.length !== value.size || sha256(bytes) !== value.sha256) {
      fail(`${label} embedded bytes do not match size/SHA-256`);
    }
  }
  return value;
}

function validateRootNonWritableExecutable(value, label, exactPath, maxBytes = MAX_FILE_BYTES) {
  validateFilePin(value, label, { exactPath, maxBytes });
  const mode = Number.parseInt(value.mode, 8);
  if (value.uid !== 0 || value.gid !== 0 || (mode & 0o022) !== 0 || (mode & 0o111) === 0) {
    fail(`${label} must be a root-owned, non-group/other-writable executable`);
  }
}

function validateTimestamp(value, label) {
  const parsed = typeof value === "string" ? Date.parse(value) : Number.NaN;
  if (
    typeof value !== "string" ||
    !ISO_UTC.test(value) ||
    !Number.isFinite(parsed) ||
    new Date(parsed).toISOString().replace(/\.000Z$/u, "Z") !== value
  ) {
    fail(`${label} must be whole-second UTC text`);
  }
}

function validateTransactionPaths(value, ceremonyId) {
  exactKeys(value, ["lock_path", "receipt_path", "rollback_receipt_path", "state_directory"], "transaction");
  const root = "/var/lib/bitcoinpir/payment-v1/core-pattern";
  const expected = {
    lock_path: "/run/bitcoinpir-payment-v1-core-pattern.lock",
    receipt_path: `${root}/receipts/${ceremonyId}.json`,
    rollback_receipt_path: `${root}/receipts/${ceremonyId}.rollback.json`,
    state_directory: `${root}/transactions/${ceremonyId}`,
  };
  for (const [key, path] of Object.entries(expected)) {
    if (value[key] !== path) fail(`transaction.${key} must equal ${path}`);
  }
}

function validateAssignmentFile(value, index) {
  exactKeys(value, ["assignments", "file"], `preimage.core_pattern_assignment_files[${index}]`);
  validateFilePin(value.file, `preimage.core_pattern_assignment_files[${index}].file`);
  if (value.file.uid !== 0 || (Number.parseInt(value.file.mode, 8) & 0o022) !== 0) {
    fail(`preimage.core_pattern_assignment_files[${index}].file is not root-owned/non-writable`);
  }
  if (!Array.isArray(value.assignments) || value.assignments.length === 0) {
    fail(`preimage.core_pattern_assignment_files[${index}].assignments must be non-empty`);
  }
  for (const assignment of value.assignments) {
    if (typeof assignment !== "string" || !CORE_ASSIGNMENT.test(assignment)) {
      fail(`preimage.core_pattern_assignment_files[${index}] has a malformed assignment`);
    }
  }
  if (value.file.path === "/etc/sysctl.conf") {
    fail("/etc/sysctl.conf must not assign kernel.core_pattern");
  }
  if (!SYSCTL_DIRS.some((directory) => value.file.path.startsWith(`${directory}/`))) {
    fail("core_pattern assignment file is outside the reviewed sysctl directories");
  }
  if (basename(value.file.path) >= basename(PERSISTENT_POLICY_PATH)) {
    fail("an existing core_pattern assignment sorts at or after the ceremony policy");
  }
}

export function validatePlan(plan) {
  exactKeys(
    plan,
    [
      "candidate",
      "ceremony_id",
      "executor",
      "host",
      "kind",
      "preimage",
      "rollback_policy",
      "schema_version",
      "transaction",
    ],
    "plan",
  );
  if (plan.schema_version !== 1 || plan.kind !== CEREMONY_KIND) {
    fail("plan schema/kind is not reviewed");
  }
  if (typeof plan.ceremony_id !== "string" || !SLUG.test(plan.ceremony_id)) {
    fail("ceremony_id must be a lowercase slug");
  }
  if (plan.rollback_policy !== "separate-digest-approved-rollback-document-v1") {
    fail("rollback_policy must require a separate digest-approved document");
  }

  exactKeys(plan.executor, ["false_handler", "node", "source", "systemctl"], "executor");
  validateRootNonWritableExecutable(plan.executor.false_handler, "executor.false_handler", "/usr/bin/false");
  validateRootNonWritableExecutable(
    plan.executor.node,
    "executor.node",
    "/usr/bin/node",
    256 * 1024 * 1024,
  );
  validateRootNonWritableExecutable(plan.executor.source, "executor.source", EXECUTOR_PATH);
  validateRootNonWritableExecutable(plan.executor.systemctl, "executor.systemctl", "/usr/bin/systemctl");

  exactKeys(plan.host, ["boot_id", "machine_id_sha256", "os_release", "systemd_version"], "host");
  if (typeof plan.host.boot_id !== "string" || !UUID.test(plan.host.boot_id)) {
    fail("host.boot_id must be a lowercase UUID");
  }
  validateSha(plan.host.machine_id_sha256, "host.machine_id_sha256");
  validateFilePin(plan.host.os_release, "host.os_release");
  if (plan.host.os_release.uid !== 0 || (Number.parseInt(plan.host.os_release.mode, 8) & 0o022) !== 0) {
    fail("host.os_release must be root-owned and non-writable by group/other");
  }
  if (typeof plan.host.systemd_version !== "string" || !/^systemd 255(?:\s|\.)/u.test(plan.host.systemd_version)) {
    fail("host.systemd_version must pin systemd 255");
  }

  exactKeys(
    plan.preimage,
    [
      "apport_default",
      "apport_service",
      "core_pattern",
      "core_pattern_assignment_files",
      "crash_entries",
      "persistent_policy_state",
    ],
    "preimage",
  );
  validateFilePin(plan.preimage.apport_default, "preimage.apport_default", {
    bytesRequired: true,
    exactPath: APPORT_DEFAULT_PATH,
  });
  if (plan.preimage.apport_default.uid !== 0 || plan.preimage.apport_default.gid !== 0 || plan.preimage.apport_default.mode !== "0644") {
    fail("preimage.apport_default must be root:root 0644");
  }
  const oldApport = Buffer.from(plan.preimage.apport_default.bytes_base64, "base64").toString("utf8");
  if (oldApport !== "enabled=1\n") {
    fail("V1 requires exact /etc/default/apport bytes enabled=1\\n");
  }
  if (plan.preimage.core_pattern !== OBSERVED_APPORT_CORE_PATTERN) {
    fail("preimage.core_pattern must pin the exact observed apport pipe command");
  }
  if (plan.preimage.persistent_policy_state !== "absent") {
    fail("preimage.persistent_policy_state must equal absent");
  }
  if (!Array.isArray(plan.preimage.crash_entries)) fail("preimage.crash_entries must be an array");
  if (plan.preimage.crash_entries.some((entry) => typeof entry !== "string" || entry.includes("/") || entry === "." || entry === "..")) {
    fail("preimage.crash_entries contains an unsafe name");
  }
  const sortedCrash = [...plan.preimage.crash_entries].sort();
  exactArray(plan.preimage.crash_entries, sortedCrash, "preimage.crash_entries");
  if (plan.preimage.crash_entries.length !== 0) {
    fail("V1 accepts only the observed empty /var/crash inventory and never deletes entries");
  }
  if (!Array.isArray(plan.preimage.core_pattern_assignment_files)) {
    fail("preimage.core_pattern_assignment_files must be an array");
  }
  plan.preimage.core_pattern_assignment_files.forEach(validateAssignmentFile);
  const assignmentPaths = plan.preimage.core_pattern_assignment_files.map((entry) => entry.file.path);
  exactArray(assignmentPaths, [...assignmentPaths].sort(), "core_pattern assignment path order");
  if (new Set(assignmentPaths).size !== assignmentPaths.length) {
    fail("core_pattern assignment paths must be unique");
  }

  exactKeys(
    plan.preimage.apport_service,
    [
      "active_state",
      "dropin_paths",
      "fragment",
      "load_state",
      "name",
      "need_daemon_reload",
      "sub_state",
      "unit_file_state",
    ],
    "preimage.apport_service",
  );
  if (
    plan.preimage.apport_service.name !== APPORT_UNIT ||
    plan.preimage.apport_service.load_state !== "loaded" ||
    plan.preimage.apport_service.active_state !== "active" ||
    plan.preimage.apport_service.need_daemon_reload !== "no" ||
    !["exited", "running"].includes(plan.preimage.apport_service.sub_state) ||
    plan.preimage.apport_service.unit_file_state !== "enabled"
  ) {
    fail("preimage.apport_service must pin the exact loaded active enabled service");
  }
  exactArray(plan.preimage.apport_service.dropin_paths, [], "preimage.apport_service.dropin_paths");
  validateFilePin(plan.preimage.apport_service.fragment, "preimage.apport_service.fragment");
  if (plan.preimage.apport_service.fragment.uid !== 0 || (Number.parseInt(plan.preimage.apport_service.fragment.mode, 8) & 0o022) !== 0) {
    fail("apport service fragment must be root-owned and non-writable by group/other");
  }

  exactKeys(plan.candidate, ["apport_default", "core_pattern", "persistent_policy"], "candidate");
  validateFilePin(plan.candidate.apport_default, "candidate.apport_default", {
    bytesRequired: true,
    exactPath: APPORT_DEFAULT_PATH,
  });
  if (
    plan.candidate.apport_default.uid !== 0 ||
    plan.candidate.apport_default.gid !== 0 ||
    plan.candidate.apport_default.mode !== "0644" ||
    Buffer.from(plan.candidate.apport_default.bytes_base64, "base64").toString("utf8") !== "enabled=0\n"
  ) {
    fail("candidate.apport_default must be exact root:root 0644 enabled=0\\n");
  }
  validateFilePin(plan.candidate.persistent_policy, "candidate.persistent_policy", {
    bytesRequired: true,
    exactPath: PERSISTENT_POLICY_PATH,
  });
  if (
    plan.candidate.persistent_policy.uid !== 0 ||
    plan.candidate.persistent_policy.gid !== 0 ||
    plan.candidate.persistent_policy.mode !== "0644" ||
    Buffer.from(plan.candidate.persistent_policy.bytes_base64, "base64").toString("utf8") !==
      `kernel.core_pattern=${TARGET_CORE_PATTERN}\n`
  ) {
    fail("candidate.persistent_policy bytes/metadata are not reviewed");
  }
  if (plan.candidate.core_pattern !== TARGET_CORE_PATTERN) {
    fail(`candidate.core_pattern must equal ${TARGET_CORE_PATTERN}`);
  }
  validateTransactionPaths(plan.transaction, plan.ceremony_id);
  return plan;
}

export function planSha256(plan) {
  validatePlan(plan);
  return sha256(Buffer.from(canonicalJson(plan), "utf8"));
}

function validateApprovalCommon(approval, plan, planDigest, sourceDigest, kind, acknowledgements) {
  exactKeys(
    approval,
    [
      "acknowledgements",
      "approved_at_utc",
      "approved_by",
      "ceremony_id",
      "decision",
      "executor_sha256",
      "expires_at_utc",
      "kind",
      "plan_sha256",
      "schema_version",
    ],
    "approval",
  );
  if (approval.schema_version !== 1 || approval.kind !== kind) fail("approval schema/kind is not reviewed");
  if (approval.ceremony_id !== plan.ceremony_id) fail("approval ceremony_id does not bind the plan");
  if (approval.plan_sha256 !== planDigest) fail("approval plan_sha256 does not bind the plan");
  if (approval.executor_sha256 !== sourceDigest) fail("approval executor_sha256 does not bind the source");
  if (typeof approval.approved_by !== "string" || approval.approved_by.length < 1 || approval.approved_by.length > 128) {
    fail("approval.approved_by is invalid");
  }
  validateTimestamp(approval.approved_at_utc, "approval.approved_at_utc");
  validateTimestamp(approval.expires_at_utc, "approval.expires_at_utc");
  const approved = Date.parse(approval.approved_at_utc);
  const expires = Date.parse(approval.expires_at_utc);
  if (expires <= approved || expires - approved > 24 * 60 * 60 * 1000) {
    fail("approval validity window must be positive and at most 24 hours");
  }
  exactArray(approval.acknowledgements, acknowledgements, "approval.acknowledgements");
}

export function validateApplyApproval(approval, plan, planDigest, sourceDigest, now = Date.now()) {
  validateApprovalCommon(approval, plan, planDigest, sourceDigest, APPLY_APPROVAL_KIND, APPLY_ACKNOWLEDGEMENTS);
  if (approval.decision !== "approve-disable-host-core-diagnostics") {
    fail("apply approval decision is not affirmative");
  }
  if (now < Date.parse(approval.approved_at_utc) || now > Date.parse(approval.expires_at_utc)) {
    fail("apply approval is not currently valid");
  }
  return approval;
}

export function validateRollbackApproval(approval, plan, planDigest, sourceDigest, receiptDigest, now = Date.now()) {
  const common = { ...approval };
  const receipt = common.committed_receipt_sha256;
  delete common.committed_receipt_sha256;
  validateApprovalCommon(common, plan, planDigest, sourceDigest, ROLLBACK_APPROVAL_KIND, ROLLBACK_ACKNOWLEDGEMENTS);
  if (approval.decision !== "approve-restore-host-core-diagnostics") {
    fail("rollback approval decision is not affirmative");
  }
  validateSha(receipt, "approval.committed_receipt_sha256");
  if (receipt !== receiptDigest) fail("rollback approval does not bind the committed receipt");
  if (now < Date.parse(approval.approved_at_utc) || now > Date.parse(approval.expires_at_utc)) {
    fail("rollback approval is not currently valid");
  }
  return approval;
}

function same(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

export function expectedPreimage(plan) {
  return {
    apport_default: plan.preimage.apport_default,
    apport_service: plan.preimage.apport_service,
    core_pattern: plan.preimage.core_pattern,
    core_pattern_assignment_files: plan.preimage.core_pattern_assignment_files,
    crash_entries: plan.preimage.crash_entries,
    persistent_policy: { path: PERSISTENT_POLICY_PATH, state: "absent" },
  };
}

export function expectedCandidate(plan) {
  return {
    apport_default: plan.candidate.apport_default,
    apport_service: {
      ...plan.preimage.apport_service,
      active_state: "inactive",
      sub_state: "dead",
      unit_file_state: "disabled",
    },
    core_pattern: TARGET_CORE_PATTERN,
    core_pattern_assignment_files: [
      ...plan.preimage.core_pattern_assignment_files,
      { assignments: [`kernel.core_pattern=${TARGET_CORE_PATTERN}`], file: plan.candidate.persistent_policy },
    ].sort((a, b) => a.file.path.localeCompare(b.file.path)),
    crash_entries: plan.preimage.crash_entries,
    persistent_policy: { file: plan.candidate.persistent_policy, state: "present" },
  };
}

function assertSnapshot(actual, expected, label) {
  if (!same(actual, expected)) fail(`${label} does not match the exact approved state`);
}

export class CeremonyError extends Error {
  constructor(message, { outcome, phase, cause, containment } = {}) {
    super(message, { cause });
    this.name = "CeremonyError";
    this.outcome = outcome;
    this.phase = phase;
    this.containment = containment;
  }
}

async function bestEffortContainment(plan, ops) {
  const actions = [];
  const attempt = async (name, operation) => {
    try {
      await operation();
      actions.push({ action: name, result: "ok" });
    } catch (error) {
      actions.push({ action: name, error: error.message, result: "failed" });
    }
  };
  await attempt("install-persistent-policy", () => ops.installPersistent(plan.candidate.persistent_policy));
  await attempt("replace-apport-default", () => ops.replaceApportDefault(plan.candidate.apport_default));
  await attempt("apply-safe-core-pattern-before-stop", () => ops.writeCorePattern(TARGET_CORE_PATTERN));
  await attempt("stop-apport", () => ops.systemctl("stop"));
  await attempt("disable-apport", () => ops.systemctl("disable"));
  await attempt("reapply-safe-core-pattern-after-stop", () => ops.writeCorePattern(TARGET_CORE_PATTERN));
  let exactCandidate = false;
  await attempt("inspect-contained-state", async () => {
    const snapshot = await ops.inspect();
    assertSnapshot(snapshot, expectedCandidate(plan), "contained state");
    exactCandidate = true;
  });
  return { actions, exact_candidate: exactCandidate };
}

function receiptBase(plan, context, outcome, before, after, now) {
  return {
    approval_sha256: context.approvalSha256,
    ceremony_id: plan.ceremony_id,
    committed_at_utc: new Date(now).toISOString().replace(/\.\d{3}Z$/u, "Z"),
    executor_sha256: context.sourceSha256,
    history_cleanup_performed: false,
    host_reboot_performed: false,
    kind: RECEIPT_KIND,
    outcome,
    plan_sha256: context.planSha256,
    post_state: after,
    pre_state: before,
    schema_version: 1,
  };
}

export async function applyCeremony(plan, context, ops) {
  validatePlan(plan);
  let release;
  let mutated = false;
  let phase = "preflight";
  let before;
  let committedReceipt;
  try {
    before = await ops.inspect();
    assertSnapshot(before, expectedPreimage(plan), "preflight");
    await ops.verifyHostAndTools(plan);
    release = await ops.acquireLock(plan.transaction.lock_path, context);
    assertSnapshot(await ops.inspect(), expectedPreimage(plan), "locked preflight");
    await ops.publishState(plan.transaction.state_directory, "00-prepared", {
      approval_sha256: context.approvalSha256,
      plan_sha256: context.planSha256,
      source_sha256: context.sourceSha256,
    });

    phase = "persistent-policy";
    mutated = true;
    await ops.installPersistent(plan.candidate.persistent_policy);
    await ops.publishState(plan.transaction.state_directory, "10-persistent-policy", {});

    phase = "apport-default";
    await ops.replaceApportDefault(plan.candidate.apport_default);
    await ops.publishState(plan.transaction.state_directory, "20-apport-default", {});

    phase = "disable-apport";
    await ops.systemctl("disable");
    await ops.publishState(plan.transaction.state_directory, "30-apport-disabled", {});

    phase = "apply-core-pattern";
    await ops.writeCorePattern(TARGET_CORE_PATTERN);
    if ((await ops.readCorePattern()) !== TARGET_CORE_PATTERN) {
      fail("immediate core_pattern readback differs from the safe target");
    }
    await ops.publishState(plan.transaction.state_directory, "40-core-pattern-applied", {});

    phase = "stop-apport";
    await ops.systemctl("stop");
    await ops.publishState(plan.transaction.state_directory, "50-apport-stopped", {});

    phase = "reapply-core-pattern-after-stop";
    await ops.writeCorePattern(TARGET_CORE_PATTERN);
    if ((await ops.readCorePattern()) !== TARGET_CORE_PATTERN) {
      fail("post-stop core_pattern readback differs from the safe target");
    }
    await ops.publishState(plan.transaction.state_directory, "60-core-pattern-reapplied", {});

    phase = "final-verification";
    const after = await ops.inspect();
    assertSnapshot(after, expectedCandidate(plan), "final state");
    const receipt = receiptBase(plan, context, "committed", before, after, ops.now());
    await ops.publishReceipt(plan.transaction.receipt_path, receipt);
    committedReceipt = receipt;
    await release();
    release = undefined;
    return { outcome: "committed", receipt, receipt_sha256: sha256(Buffer.from(canonicalJson(receipt))) };
  } catch (cause) {
    if (committedReceipt !== undefined) {
      throw new CeremonyError(`ceremony committed but lock release failed: ${cause.message}`, {
        cause,
        outcome: "committed-lock-retained",
        phase: "lock-release",
      });
    }
    if (!mutated) {
      if (release !== undefined) await release().catch(() => {});
      throw new CeremonyError(`core-pattern ceremony failed before mutation: ${cause.message}`, {
        cause,
        outcome: "preflight-failed",
        phase,
      });
    }
    const containment = await bestEffortContainment(plan, ops);
    await ops.publishState(plan.transaction.state_directory, "90-contained-or-unknown", containment).catch(() => {});
    throw new CeremonyError(
      `core-pattern ceremony did not commit; fail-closed containment attempted: ${cause.message}`,
      {
        cause,
        containment,
        outcome: containment.exact_candidate ? "contained-needs-recovery" : "outcome-unknown",
        phase,
      },
    );
  }
}

export async function recoverCommittedCandidate(plan, context, ops) {
  validatePlan(plan);
  const release = await ops.recoverLock(plan.transaction.lock_path, context);
  let keepLock = true;
  try {
    await ops.verifyHostAndTools(plan);
    const current = await ops.inspect();
    assertSnapshot(current, expectedCandidate(plan), "recovery state");
    const receipt = receiptBase(
      plan,
      context,
      "committed-after-contained-recovery",
      expectedPreimage(plan),
      current,
      ops.now(),
    );
    await ops.publishReceipt(plan.transaction.receipt_path, receipt);
    try {
      await release();
      keepLock = false;
    } catch (cause) {
      throw new CeremonyError(`recovered receipt committed but lock release failed: ${cause.message}`, {
        cause,
        outcome: "committed-lock-retained",
        phase: "lock-release",
      });
    }
    return { outcome: receipt.outcome, receipt, receipt_sha256: sha256(Buffer.from(canonicalJson(receipt))) };
  } finally {
    if (keepLock) {
      // A non-exact recovery state intentionally retains the persistent lock.
    }
  }
}

export async function rollbackCeremony(plan, context, ops) {
  validatePlan(plan);
  let release;
  let mutated = false;
  let phase = "rollback-preflight";
  let committedReceipt;
  try {
    const current = await ops.inspect();
    assertSnapshot(current, expectedCandidate(plan), "rollback preflight");
    await ops.verifyHostAndTools(plan);
    release = await ops.acquireLock(plan.transaction.lock_path, context);
    assertSnapshot(await ops.inspect(), expectedCandidate(plan), "locked rollback preflight");
    await ops.publishState(plan.transaction.state_directory, "r00-prepared", {
      rollback_approval_sha256: context.rollbackApprovalSha256,
      committed_receipt_sha256: context.receiptSha256,
    });

    phase = "restore-apport-default";
    mutated = true;
    await ops.replaceApportDefault(plan.preimage.apport_default);
    phase = "enable-apport";
    await ops.systemctl("enable");
    phase = "start-apport";
    await ops.systemctl("start");
    phase = "restore-core-pattern";
    await ops.writeCorePattern(plan.preimage.core_pattern);
    if ((await ops.readCorePattern()) !== plan.preimage.core_pattern) {
      fail("rollback core_pattern readback differs from the approved preimage");
    }
    phase = "remove-persistent-policy";
    await ops.removePersistent(plan.candidate.persistent_policy);
    const after = await ops.inspect();
    assertSnapshot(after, expectedPreimage(plan), "rollback final state");
    const receipt = {
      ceremony_id: plan.ceremony_id,
      committed_receipt_sha256: context.receiptSha256,
      completed_at_utc: new Date(ops.now()).toISOString().replace(/\.\d{3}Z$/u, "Z"),
      executor_sha256: context.sourceSha256,
      history_cleanup_performed: false,
      host_reboot_performed: false,
      kind: ROLLBACK_RECEIPT_KIND,
      outcome: "rolled-back-to-approved-preimage",
      plan_sha256: context.planSha256,
      post_state: after,
      rollback_approval_sha256: context.rollbackApprovalSha256,
      schema_version: 1,
    };
    await ops.publishReceipt(plan.transaction.rollback_receipt_path, receipt);
    committedReceipt = receipt;
    await release();
    release = undefined;
    return { outcome: receipt.outcome, receipt, receipt_sha256: sha256(Buffer.from(canonicalJson(receipt))) };
  } catch (cause) {
    if (committedReceipt !== undefined) {
      throw new CeremonyError(`rollback committed but lock release failed: ${cause.message}`, {
        cause,
        outcome: "rolled-back-lock-retained",
        phase: "lock-release",
      });
    }
    if (!mutated) {
      if (release !== undefined) await release().catch(() => {});
      throw new CeremonyError(`rollback failed before mutation: ${cause.message}`, {
        cause,
        outcome: "rollback-preflight-failed",
        phase,
      });
    }
    const containment = await bestEffortContainment(plan, ops);
    await ops.publishState(plan.transaction.state_directory, "r90-contained-or-unknown", containment).catch(() => {});
    throw new CeremonyError(
      `rollback did not complete; safe-policy containment attempted: ${cause.message}`,
      {
        cause,
        containment,
        outcome: containment.exact_candidate ? "rollback-contained-safe" : "outcome-unknown",
        phase,
      },
    );
  }
}

function modeText(stat) {
  return `0${(stat.mode & 0o7777).toString(8).padStart(3, "0")}`;
}

function stableFilePin(path, bytes, stat) {
  return {
    gid: stat.gid,
    mode: modeText(stat),
    nlink: stat.nlink,
    path,
    sha256: sha256(bytes),
    size: stat.size,
    uid: stat.uid,
  };
}

function pinWithoutBytes(pin) {
  const { bytes_base64: _ignored, ...rest } = pin;
  return rest;
}

function openBoundRegular(path, label, maxBytes = MAX_FILE_BYTES) {
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC);
    const before = fstatSync(fd, { bigint: false });
    if (!before.isFile() || before.nlink !== 1 || before.size > maxBytes) {
      fail(`${label} is not a bounded one-link regular file`);
    }
    const bytes = readFileSync(fd);
    const after = fstatSync(fd, { bigint: false });
    const pathAfter = lstatSync(path, { bigint: false });
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.dev !== pathAfter.dev ||
      before.ino !== pathAfter.ino ||
      before.size !== bytes.length ||
      before.mtimeMs !== after.mtimeMs ||
      before.ctimeMs !== after.ctimeMs
    ) {
      fail(`${label} changed during its descriptor-bound read`);
    }
    return { bytes, pin: stableFilePin(path, bytes, before) };
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function assertPin(actual, expected, label) {
  if (!same(actual, expected)) fail(`${label} drifted from its approved pin`);
}

function assertRootParent(path) {
  const stat = lstatSync(path, { bigint: false });
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== 0 || stat.gid !== 0 || (stat.mode & 0o022) !== 0) {
    fail(`mutable parent is not an exact root-owned non-writable directory: ${path}`);
  }
  return stat;
}

function fsyncDirectory(path) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | constants.O_CLOEXEC);
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function writePrepared(path, bytes, pin) {
  const parent = dirname(path);
  assertRootParent(parent);
  const temp = join(parent, `.${basename(path)}.${process.pid}.${randomBytes(12).toString("hex")}.pending`);
  let fd;
  try {
    fd = openSync(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW | constants.O_CLOEXEC, 0o600);
    writeFileSync(fd, bytes);
    fchownSync(fd, pin.uid, pin.gid);
    fchmodSync(fd, Number.parseInt(pin.mode, 8));
    fsyncSync(fd);
    const stat = fstatSync(fd, { bigint: false });
    assertPin(stableFilePin(path, bytes, stat), pinWithoutBytes(pin), `prepared ${path}`);
    return temp;
  } catch (error) {
    try {
      if (fd !== undefined) closeSync(fd);
      fd = undefined;
      unlinkSync(temp);
    } catch {}
    throw error;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function atomicCreatePinned(pin) {
  const bytes = Buffer.from(pin.bytes_base64, "base64");
  try {
    const existing = openBoundRegular(pin.path, `existing ${pin.path}`);
    assertPin(existing.pin, pinWithoutBytes(pin), `existing ${pin.path}`);
    return;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const temp = writePrepared(pin.path, bytes, pin);
  try {
    linkSync(temp, pin.path);
    unlinkSync(temp);
    fsyncDirectory(dirname(pin.path));
    const actual = openBoundRegular(pin.path, `published ${pin.path}`);
    assertPin(actual.pin, pinWithoutBytes(pin), `published ${pin.path}`);
  } catch (error) {
    try { unlinkSync(temp); } catch {}
    throw error;
  }
}

function atomicReplacePinned(pin) {
  const bytes = Buffer.from(pin.bytes_base64, "base64");
  const temp = writePrepared(pin.path, bytes, pin);
  try {
    renameSync(temp, pin.path);
    fsyncDirectory(dirname(pin.path));
    const actual = openBoundRegular(pin.path, `replaced ${pin.path}`);
    assertPin(actual.pin, pinWithoutBytes(pin), `replaced ${pin.path}`);
  } catch (error) {
    try { unlinkSync(temp); } catch {}
    throw error;
  }
}

function atomicRemovePinned(pin) {
  const actual = openBoundRegular(pin.path, `removal target ${pin.path}`);
  assertPin(actual.pin, pinWithoutBytes(pin), `removal target ${pin.path}`);
  unlinkSync(pin.path);
  fsyncDirectory(dirname(pin.path));
  try {
    lstatSync(pin.path);
    fail(`removed path unexpectedly remains: ${pin.path}`);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
}

function runCommand(path, args, label) {
  const result = spawnSync(path, args, {
    cwd: "/",
    encoding: "utf8",
    env: { LANG: "C", LC_ALL: "C", PATH: "/usr/sbin:/usr/bin" },
    maxBuffer: MAX_COMMAND_OUTPUT_BYTES,
    shell: false,
    timeout: 30_000,
  });
  if (result.error !== undefined) fail(`${label} failed to execute: ${result.error.message}`);
  if (result.status !== 0 || result.signal !== null) {
    fail(`${label} failed status=${result.status} signal=${result.signal ?? "none"}`);
  }
  return result.stdout;
}

function systemctlSnapshot(fragmentPin) {
  const stdout = runCommand(
    "/usr/bin/systemctl",
    [
      "show",
      APPORT_UNIT,
      "--property=ActiveState",
      "--property=FragmentPath",
      "--property=LoadState",
      "--property=DropInPaths",
      "--property=NeedDaemonReload",
      "--property=SubState",
      "--property=UnitFileState",
    ],
    "systemctl show apport",
  );
  const values = {};
  for (const line of stdout.trimEnd().split("\n")) {
    const index = line.indexOf("=");
    if (index < 1) fail("systemctl show emitted malformed output");
    const key = line.slice(0, index);
    if (Object.hasOwn(values, key)) fail("systemctl show emitted a duplicate property");
    values[key] = line.slice(index + 1);
  }
  exactKeys(
    values,
    [
      "ActiveState",
      "DropInPaths",
      "FragmentPath",
      "LoadState",
      "NeedDaemonReload",
      "SubState",
      "UnitFileState",
    ],
    "systemctl apport projection",
  );
  const fragment = openBoundRegular(values.FragmentPath, "apport unit fragment");
  if (fragmentPin !== undefined) assertPin(fragment.pin, fragmentPin, "apport unit fragment");
  return {
    active_state: values.ActiveState,
    dropin_paths: values.DropInPaths === "" ? [] : values.DropInPaths.split(" "),
    fragment: fragment.pin,
    load_state: values.LoadState,
    name: APPORT_UNIT,
    need_daemon_reload: values.NeedDaemonReload,
    sub_state: values.SubState,
    unit_file_state: values.UnitFileState,
  };
}

export function scanCorePatternAssignments(
  configuredDirectories = SYSCTL_DIRS,
  legacyPath = "/etc/sysctl.conf",
) {
  const found = [];
  const selectedBasenames = new Set();
  const canonicalDirectories = [];
  for (const configuredDirectory of configuredDirectories) {
    let directory;
    try {
      directory = realpathSync(configuredDirectory);
    } catch (error) {
      if (error.code === "ENOENT") continue;
      throw error;
    }
    if (!canonicalDirectories.includes(directory)) canonicalDirectories.push(directory);
  }
  for (const directory of canonicalDirectories) {
    let names;
    try {
      names = readdirSync(directory).filter((name) => name.endsWith(".conf")).sort();
    } catch (error) {
      if (error.code === "ENOENT") continue;
      throw error;
    }
    for (const name of names) {
      if (selectedBasenames.has(name)) continue;
      selectedBasenames.add(name);
      const path = join(directory, name);
      const discovered = lstatSync(path, { bigint: false });
      if (discovered.isSymbolicLink()) {
        const target = realpathSync(path);
        if (target === "/dev/null") continue;
        fail(`reviewed sysctl input must not be a non-/dev/null symlink: ${path}`);
      }
      const opened = openBoundRegular(path, `sysctl input ${path}`, MAX_FILE_BYTES);
      const text = opened.bytes.toString("utf8");
      if (!Buffer.from(text, "utf8").equals(opened.bytes)) fail(`sysctl input is not UTF-8: ${path}`);
      const assignments = text.split(/\n/u).filter((line) => CORE_ASSIGNMENT.test(line));
      if (assignments.length > 0) {
        found.push({ assignments, file: opened.pin });
      }
    }
  }
  if (legacyPath !== null) {
    try {
      const opened = openBoundRegular(legacyPath, `legacy ${legacyPath}`);
      const text = opened.bytes.toString("utf8");
      if (!Buffer.from(text, "utf8").equals(opened.bytes)) {
        fail(`legacy ${legacyPath} is not UTF-8`);
      }
      const assignments = text.split(/\n/u).filter((line) => CORE_ASSIGNMENT.test(line));
      if (assignments.length > 0) found.push({ assignments, file: opened.pin });
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
  return found.sort((a, b) => a.file.path.localeCompare(b.file.path));
}

function readCorePattern() {
  const value = readFileSync("/proc/sys/kernel/core_pattern", "utf8");
  if (!value.endsWith("\n") || value.slice(0, -1).includes("\n")) {
    fail("/proc/sys/kernel/core_pattern is malformed");
  }
  return value.slice(0, -1);
}

function writeCorePattern(value) {
  if (value !== TARGET_CORE_PATTERN && value !== OBSERVED_APPORT_CORE_PATTERN) {
    fail("refusing to write an unreviewed core_pattern value");
  }
  writeFileSync("/proc/sys/kernel/core_pattern", `${value}\n`, { encoding: "utf8", flag: "w" });
  if (readCorePattern() !== value) fail("core_pattern immediate readback failed");
}

function optionalPersistent(pin) {
  try {
    const opened = openBoundRegular(pin.path, `persistent policy ${pin.path}`);
    return { file: opened.pin, state: "present" };
  } catch (error) {
    if (error.code === "ENOENT") return { path: pin.path, state: "absent" };
    throw error;
  }
}

function readCrashEntries() {
  return readdirSync("/var/crash").sort();
}

function ensureRootDirectory(path, mode) {
  try {
    mkdirSync(path, { mode });
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
  }
  const stat = lstatSync(path, { bigint: false });
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== 0 || stat.gid !== 0 || modeText(stat) !== `0${mode.toString(8).padStart(3, "0")}`) {
    fail(`state directory metadata is not exact: ${path}`);
  }
}

function ensureRootAncestor(path) {
  try {
    mkdirSync(path, { mode: 0o755 });
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
  }
  assertRootParent(path);
}

function ensureStateParents(stateDirectory) {
  assertRootParent("/var");
  assertRootParent("/var/lib");
  for (const path of [
    "/var/lib/bitcoinpir",
    "/var/lib/bitcoinpir/payment-v1",
  ]) ensureRootAncestor(path);
  for (const path of [
    "/var/lib/bitcoinpir/payment-v1/core-pattern",
    "/var/lib/bitcoinpir/payment-v1/core-pattern/transactions",
    "/var/lib/bitcoinpir/payment-v1/core-pattern/receipts",
    stateDirectory,
  ]) ensureRootDirectory(path, 0o700);
}

function atomicPublishJson(path, value) {
  const bytes = Buffer.from(canonicalJson(value), "utf8");
  const pin = {
    bytes_base64: bytes.toString("base64"),
    gid: 0,
    mode: "0600",
    nlink: 1,
    path,
    sha256: sha256(bytes),
    size: bytes.length,
    uid: 0,
  };
  atomicCreatePinned(pin);
}

function lockOwner(context) {
  return {
    approval_sha256: context.approvalSha256 ?? context.rollbackApprovalSha256,
    ceremony_id: context.ceremonyId,
    plan_sha256: context.planSha256,
    source_sha256: context.sourceSha256,
  };
}

function acquireLock(path, context) {
  assertRootParent(dirname(path));
  try {
    mkdirSync(path, { mode: 0o700 });
  } catch (error) {
    if (error.code === "EEXIST") fail("ceremony lock already exists; explicit recovery inspection is required");
    throw error;
  }
  const stat = lstatSync(path, { bigint: false });
  if (!stat.isDirectory() || stat.uid !== 0 || stat.gid !== 0 || modeText(stat) !== "0700") {
    fail("new ceremony lock metadata is not exact");
  }
  atomicPublishJson(join(path, "owner.json"), lockOwner(context));
  fsyncDirectory(dirname(path));
  return async () => {
    const owner = openBoundRegular(join(path, "owner.json"), "ceremony lock owner");
    if (!owner.bytes.equals(Buffer.from(canonicalJson(lockOwner(context))))) {
      fail("ceremony lock ownership drifted");
    }
    unlinkSync(join(path, "owner.json"));
    rmdirSync(path);
    fsyncDirectory(dirname(path));
  };
}

function recoverLock(path, context) {
  const stat = lstatSync(path, { bigint: false });
  if (!stat.isDirectory() || stat.uid !== 0 || stat.gid !== 0 || modeText(stat) !== "0700") {
    fail("recovery lock metadata is not exact");
  }
  const owner = openBoundRegular(join(path, "owner.json"), "recovery lock owner");
  if (!owner.bytes.equals(Buffer.from(canonicalJson(lockOwner(context))))) {
    fail("recovery lock does not belong to this exact ceremony approval");
  }
  return async () => {
    unlinkSync(join(path, "owner.json"));
    rmdirSync(path);
    fsyncDirectory(dirname(path));
  };
}

function realOps(plan) {
  return {
    acquireLock: async (path, context) => {
      ensureStateParents(plan.transaction.state_directory);
      return acquireLock(path, context);
    },
    inspect: async () => {
      const apport = openBoundRegular(APPORT_DEFAULT_PATH, "apport defaults");
      return {
        apport_default: {
          ...apport.pin,
          bytes_base64: apport.bytes.toString("base64"),
        },
        apport_service: systemctlSnapshot(plan.preimage.apport_service.fragment),
        core_pattern: readCorePattern(),
        core_pattern_assignment_files: scanCorePatternAssignments(),
        crash_entries: readCrashEntries(),
        persistent_policy: optionalPersistent(plan.candidate.persistent_policy),
      };
    },
    installPersistent: async (pin) => atomicCreatePinned(pin),
    now: () => Date.now(),
    publishReceipt: async (path, receipt) => atomicPublishJson(path, receipt),
    publishState: async (directory, phase, details) => {
      atomicPublishJson(join(directory, `${phase}.json`), {
        ceremony_id: plan.ceremony_id,
        details,
        phase,
        recorded_at_utc: new Date().toISOString().replace(/\.\d{3}Z$/u, "Z"),
      });
    },
    readCorePattern: async () => readCorePattern(),
    recoverLock: async (path, context) => recoverLock(path, context),
    removePersistent: async (pin) => atomicRemovePinned(pin),
    replaceApportDefault: async (pin) => {
      const current = openBoundRegular(APPORT_DEFAULT_PATH, "current apport defaults");
      const allowed = [plan.preimage.apport_default, plan.candidate.apport_default].map(pinWithoutBytes);
      if (!allowed.some((candidate) => same(current.pin, candidate))) {
        fail("current apport defaults are neither the approved preimage nor candidate");
      }
      atomicReplacePinned(pin);
    },
    systemctl: async (verb) => {
      if (!new Set(["disable", "enable", "start", "stop"]).has(verb)) fail("unreviewed systemctl verb");
      runCommand("/usr/bin/systemctl", [verb, APPORT_UNIT], `systemctl ${verb} apport`);
    },
    verifyHostAndTools: async (approved) => verifyHostAndTools(approved),
    writeCorePattern: async (value) => writeCorePattern(value),
  };
}

function verifyHostAndTools(plan) {
  if (process.platform !== "linux" || process.geteuid?.() !== 0) {
    fail("execution requires Linux EUID 0");
  }
  const boot = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
  if (boot !== plan.host.boot_id) fail("host boot_id drifted");
  const machineId = readFileSync("/etc/machine-id");
  if (sha256(machineId) !== plan.host.machine_id_sha256) fail("host machine-id digest drifted");
  const osReleasePath = realpathSync("/etc/os-release");
  if (osReleasePath !== plan.host.os_release.path) fail("host os-release canonical path drifted");
  const osRelease = openBoundRegular(osReleasePath, "OS release");
  assertPin(osRelease.pin, plan.host.os_release, "host os-release");
  const version = runCommand("/usr/bin/systemctl", ["--version"], "systemctl version").split("\n", 1)[0];
  if (version !== plan.host.systemd_version) fail("systemd version drifted");
  for (const [label, pin] of Object.entries(plan.executor)) {
    const opened = openBoundRegular(pin.path, `executor ${label}`, label === "node" ? 256 * 1024 * 1024 : MAX_FILE_BYTES);
    assertPin(opened.pin, pin, `executor ${label}`);
    if (realpathSync(pin.path) !== pin.path) fail(`executor ${label} path is not canonical`);
  }
  if (realpathSync(process.execPath) !== plan.executor.node.path) fail("running Node binary differs from plan");
  const sourcePath = realpathSync(fileURLToPath(import.meta.url));
  if (sourcePath !== plan.executor.source.path) fail("running ceremony source path differs from plan");
}

function embeddedRootPin(path, bytes, mode) {
  const body = Buffer.from(bytes, "utf8");
  return {
    bytes_base64: body.toString("base64"),
    gid: 0,
    mode,
    nlink: 1,
    path,
    sha256: sha256(body),
    size: body.length,
    uid: 0,
  };
}

function observePlan(ceremonyId) {
  if (process.platform !== "linux" || process.geteuid?.() !== 0) {
    fail("observe-plan requires Linux EUID 0");
  }
  if (typeof ceremonyId !== "string" || !SLUG.test(ceremonyId)) {
    fail("observe-plan ceremony-id must be a lowercase slug");
  }
  const nodePath = realpathSync(process.execPath);
  const sourcePath = realpathSync(fileURLToPath(import.meta.url));
  if (nodePath !== "/usr/bin/node" || sourcePath !== EXECUTOR_PATH) {
    fail("observe-plan requires the exact installed Node and ceremony source paths");
  }
  const apportDefault = openBoundRegular(APPORT_DEFAULT_PATH, "observed apport defaults");
  const persistent = optionalPersistent({ path: PERSISTENT_POLICY_PATH });
  if (persistent.state !== "absent") fail("candidate persistent policy already exists");
  const osReleasePath = realpathSync("/etc/os-release");
  const osRelease = openBoundRegular(osReleasePath, "observed OS release");
  const systemdVersion = runCommand("/usr/bin/systemctl", ["--version"], "systemctl version")
    .split("\n", 1)[0];
  const plan = {
    candidate: {
      apport_default: embeddedRootPin(APPORT_DEFAULT_PATH, "enabled=0\n", "0644"),
      core_pattern: TARGET_CORE_PATTERN,
      persistent_policy: embeddedRootPin(
        PERSISTENT_POLICY_PATH,
        `kernel.core_pattern=${TARGET_CORE_PATTERN}\n`,
        "0644",
      ),
    },
    ceremony_id: ceremonyId,
    executor: {
      false_handler: openBoundRegular("/usr/bin/false", "observed false handler").pin,
      node: openBoundRegular("/usr/bin/node", "observed Node", 256 * 1024 * 1024).pin,
      source: openBoundRegular(EXECUTOR_PATH, "observed ceremony source").pin,
      systemctl: openBoundRegular("/usr/bin/systemctl", "observed systemctl").pin,
    },
    host: {
      boot_id: readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim(),
      machine_id_sha256: sha256(readFileSync("/etc/machine-id")),
      os_release: osRelease.pin,
      systemd_version: systemdVersion,
    },
    kind: CEREMONY_KIND,
    preimage: {
      apport_default: {
        ...apportDefault.pin,
        bytes_base64: apportDefault.bytes.toString("base64"),
      },
      apport_service: systemctlSnapshot(),
      core_pattern: readCorePattern(),
      core_pattern_assignment_files: scanCorePatternAssignments(),
      crash_entries: readCrashEntries(),
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
  validatePlan(plan);
  return plan;
}

function parseCanonicalJsonFile(path, label) {
  const opened = openBoundRegular(path, label, MAX_JSON_BYTES);
  const text = opened.bytes.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(opened.bytes)) fail(`${label} is not UTF-8`);
  let value;
  try {
    value = JSON.parse(text);
  } catch (error) {
    fail(`${label} is not valid JSON: ${error.message}`);
  }
  if (!opened.bytes.equals(Buffer.from(canonicalJson(value)))) {
    fail(`${label} must use the canonical encoding (duplicates/noncanonical bytes forbidden)`);
  }
  return { bytes: opened.bytes, sha256: opened.pin.sha256, value };
}

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const allowedCommands = new Set([
    "apply",
    "observe-plan",
    "recover-commit",
    "rollback",
    "validate-plan",
  ]);
  if (!allowedCommands.has(command)) {
    fail("command must be apply, observe-plan, recover-commit, rollback, or validate-plan");
  }
  const args = {};
  for (let i = 0; i < rest.length; i += 2) {
    const key = rest[i];
    const value = rest[i + 1];
    if (!key?.startsWith("--") || value === undefined) fail("CLI options require --name value pairs");
    const name = key.slice(2).replaceAll("-", "_");
    if (Object.hasOwn(args, name)) fail(`duplicate CLI option ${key}`);
    args[name] = value;
  }
  const common = ["approved_plan_sha256", "approved_source_sha256", "plan"];
  const apply = ["approval", "approved_approval_sha256"];
  const rollback = ["approved_receipt_sha256", "approved_rollback_approval_sha256", "rollback_approval"];
  const expected = command === "observe-plan"
    ? ["ceremony_id"]
    : command === "validate-plan"
      ? common
      : command === "rollback"
        ? [...common, ...rollback]
        : [...common, ...apply];
  exactKeys(args, expected, "CLI options");
  return { args, command };
}

function requireExternalDigest(actual, expected, label) {
  validateSha(expected, label);
  if (actual !== expected) fail(`${label} does not match the exact file`);
}

function loadPlanAndSource(args) {
  const loaded = parseCanonicalJsonFile(args.plan, "ceremony plan");
  validatePlan(loaded.value);
  requireExternalDigest(loaded.sha256, args.approved_plan_sha256, "approved plan SHA-256");
  if (loaded.sha256 !== planSha256(loaded.value)) fail("plan file digest differs from canonical plan digest");
  const source = openBoundRegular(fileURLToPath(import.meta.url), "ceremony source", MAX_FILE_BYTES);
  requireExternalDigest(source.pin.sha256, args.approved_source_sha256, "approved source SHA-256");
  if (loaded.value.executor.source.sha256 !== source.pin.sha256) fail("plan source digest differs from executor");
  return { plan: loaded.value, planSha256: loaded.sha256, sourceSha256: source.pin.sha256 };
}

function validateCommittedReceipt(value, plan, context) {
  exactKeys(
    value,
    [
      "approval_sha256",
      "ceremony_id",
      "committed_at_utc",
      "executor_sha256",
      "history_cleanup_performed",
      "host_reboot_performed",
      "kind",
      "outcome",
      "plan_sha256",
      "post_state",
      "pre_state",
      "schema_version",
    ],
    "committed receipt",
  );
  if (
    value.schema_version !== 1 ||
    value.kind !== RECEIPT_KIND ||
    value.ceremony_id !== plan.ceremony_id ||
    !["committed", "committed-after-contained-recovery"].includes(value.outcome) ||
    value.plan_sha256 !== context.planSha256 ||
    value.executor_sha256 !== context.sourceSha256 ||
    value.history_cleanup_performed !== false ||
    value.host_reboot_performed !== false
  ) fail("committed receipt identity or outcome is not reviewed");
  validateSha(value.approval_sha256, "committed receipt approval_sha256");
  validateTimestamp(value.committed_at_utc, "committed receipt committed_at_utc");
  assertSnapshot(value.pre_state, expectedPreimage(plan), "receipt pre_state");
  assertSnapshot(value.post_state, expectedCandidate(plan), "receipt post_state");
}

async function main() {
  process.umask(0o077);
  const { args, command } = parseArgs(process.argv.slice(2));
  if (command === "observe-plan") {
    process.stdout.write(canonicalJson(observePlan(args.ceremony_id)));
    return;
  }
  const context = loadPlanAndSource(args);
  context.ceremonyId = context.plan.ceremony_id;
  if (command === "validate-plan") {
    process.stdout.write(`core-pattern-plan=PASS sha256=${context.planSha256} source_sha256=${context.sourceSha256}\n`);
    return;
  }
  if (command === "apply" || command === "recover-commit") {
    const approval = parseCanonicalJsonFile(args.approval, "apply approval");
    requireExternalDigest(approval.sha256, args.approved_approval_sha256, "approved apply approval SHA-256");
    validateApplyApproval(approval.value, context.plan, context.planSha256, context.sourceSha256);
    context.approvalSha256 = approval.sha256;
    const result = command === "apply"
      ? await applyCeremony(context.plan, context, realOps(context.plan))
      : await recoverCommittedCandidate(context.plan, context, realOps(context.plan));
    process.stdout.write(`${result.outcome} receipt_sha256=${result.receipt_sha256}\n`);
    return;
  }
  const receipt = parseCanonicalJsonFile(context.plan.transaction.receipt_path, "committed receipt");
  requireExternalDigest(receipt.sha256, args.approved_receipt_sha256, "approved committed receipt SHA-256");
  validateCommittedReceipt(receipt.value, context.plan, context);
  const approval = parseCanonicalJsonFile(args.rollback_approval, "rollback approval");
  requireExternalDigest(
    approval.sha256,
    args.approved_rollback_approval_sha256,
    "approved rollback approval SHA-256",
  );
  validateRollbackApproval(
    approval.value,
    context.plan,
    context.planSha256,
    context.sourceSha256,
    receipt.sha256,
  );
  context.receiptSha256 = receipt.sha256;
  context.rollbackApprovalSha256 = approval.sha256;
  const result = await rollbackCeremony(context.plan, context, realOps(context.plan));
  process.stdout.write(`${result.outcome} receipt_sha256=${result.receipt_sha256}\n`);
}

const isMain = process.argv[1] !== undefined && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (isMain) {
  main().catch((error) => {
    const outcome = error.outcome ?? "preflight-failed";
    const phase = error.phase ?? "preflight";
    process.stderr.write(`core-pattern-ceremony=FAIL outcome=${outcome} phase=${phase}: ${error.message}\n`);
    process.exitCode = 1;
  });
}
