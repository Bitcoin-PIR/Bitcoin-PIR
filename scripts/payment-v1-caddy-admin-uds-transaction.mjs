#!/usr/bin/env node

import { createHash, randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
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
  readlinkSync,
  renameSync,
  rmdirSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { connect as netConnect, isIP } from "node:net";
import { hostname as osHostname } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import tls from "node:tls";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  ADMIN_DIRECTORY,
  ADMIN_DIAL,
  ADMIN_LISTEN,
  ADMIN_PROBE_PATH,
  ADMIN_SOCKET,
  CADDY_BINARY_PATH,
  COLLECTOR,
  EXECUTOR_PATH,
  PROFILE,
  PUBLISHER_NETNS_DROPIN_PATH,
  PUBLISHER_NETNS_HOST_INTERFACE_PATH,
  PUBLISHER_NETNS_LIFECYCLE_LOCK,
  PUBLISHER_NETNS_NAMESPACE_PATH,
  PUBLISHER_NETNS_SENTINEL_PATHS,
  PUBLISHER_NETNS_UNIT,
  SETPRIV_PATH,
  TARGET_CONFIG,
  TARGET_FRAGMENT,
  TARGET_UNIT,
  buildCandidates,
  canonicalJson,
  canonicalizeAdaptedCaddyJson,
  computeApprovedPlanSha256,
  parseStrictJson,
  sha256,
  validateCandidateAdaptedJson,
  validateAdaptedCaddyPrivacy,
  validateAdaptedCaddyPrivacyPolicy,
  validateCommittedReceipt,
  validatePlan,
  validatePublisherNetnsDropInBytes,
  validatePublisherNetnsPreimage,
  validatePreimageAdaptedJson,
} from "./payment-v1-caddy-admin-uds-gate.mjs";

const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024;
const MAX_HTTP_BODY_BYTES = 2 * 1024 * 1024;
const SYSTEMCTL_PATH = "/usr/bin/systemctl";
const SYSTEMD_ANALYZE_PATH = "/usr/bin/systemd-analyze";
const CORE_PATTERN_PATH = "/proc/sys/kernel/core_pattern";
const REQUIRED_CORE_PATTERN = "|/usr/bin/false";
const LOCK_OWNER_FILE = "owner.json";
const SITE_INVENTORY_SCHEMA_VERSION = 1;
const RECEIPT_MODE = "0400";
const STATE_MODE = "0400";
const SYSTEMD_VERSION = "255";
const SITE_PROBE_KINDS = new Set(["direct-http", "public-https", "tls-handshake"]);

export const COLD_OUTCOMES = Object.freeze({
  committed: "committed",
  outcomeUnknown: "outcome-unknown",
  preStopFailed: "pre-stop-failed-no-active-mutation",
  rolledBack: "stopped-pre-start-failed-rolled-back",
});

function fail(message) {
  throw new Error(message);
}

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype ||
      Object.getPrototypeOf(value) === null)
  );
}

function exactKeys(value, expected, label) {
  if (!isPlainObject(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) {
    fail(`${label} keys must equal ${wanted.join(", ")}`);
  }
}

function same(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

async function assertPublisherNetnsInactivePreimage(plan, ops, label) {
  const observed = await ops.publisherNetnsPreimage();
  validatePublisherNetnsPreimage(observed, `${label} publisher namespace preimage`);
  if (!same(observed, plan.publisher_netns_preimage)) {
    fail(`${label} publisher namespace preimage drifted from the exact inactive plan binding`);
  }
  return observed;
}

function validateHex64(value, label) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) {
    fail(`${label} must be 64 lowercase hex`);
  }
}

function validateHostName(value, label) {
  if (typeof value !== "string" || value.length < 1 || value.length > 253) {
    fail(`${label} must be a canonical lowercase DNS name`);
  }
  const labels = value.split(".");
  if (
    labels.some(
      (part) =>
        part.length < 1 ||
        part.length > 63 ||
        !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(part),
    )
  ) {
    fail(`${label} must be a canonical lowercase DNS name`);
  }
}

function validateHttpPath(value, label) {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 2048 ||
    !value.startsWith("/") ||
    /[\u0000-\u001f\u007f\s]/u.test(value)
  ) {
    fail(`${label} must be one bounded absolute HTTP path`);
  }
}

function validatePort(value, label) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 65535) {
    fail(`${label} must be a TCP port`);
  }
}

function validateExpectedResponse(probe, label) {
  if (
    !Number.isSafeInteger(probe.expected_status) ||
    probe.expected_status < 100 ||
    probe.expected_status > 599
  ) {
    fail(`${label}.expected_status is invalid`);
  }
  validateHex64(probe.expected_body_sha256, `${label}.expected_body_sha256`);
}

function validateSiteProbe(probe, label) {
  if (!isPlainObject(probe) || !SITE_PROBE_KINDS.has(probe.kind)) {
    fail(`${label}.kind is not reviewed`);
  }
  if (typeof probe.id !== "string" || !/^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/u.test(probe.id)) {
    fail(`${label}.id must be a canonical slug`);
  }
  if (probe.kind === "public-https") {
    exactKeys(
      probe,
      [
        "expected_body_sha256",
        "expected_leaf_sha256",
        "expected_status",
        "hostname",
        "id",
        "kind",
        "path",
        "port",
      ],
      label,
    );
    validateHostName(probe.hostname, `${label}.hostname`);
    validatePort(probe.port, `${label}.port`);
    validateHttpPath(probe.path, `${label}.path`);
    validateExpectedResponse(probe, label);
    validateHex64(probe.expected_leaf_sha256, `${label}.expected_leaf_sha256`);
    return;
  }
  if (probe.kind === "direct-http") {
    exactKeys(
      probe,
      ["address", "expected_body_sha256", "expected_status", "host_header", "id", "kind", "path", "port"],
      label,
    );
    if (typeof probe.address !== "string" || isIP(probe.address) === 0) {
      fail(`${label}.address must be a literal IPv4 or IPv6 address`);
    }
    validateHostName(probe.host_header, `${label}.host_header`);
    validatePort(probe.port, `${label}.port`);
    validateHttpPath(probe.path, `${label}.path`);
    validateExpectedResponse(probe, label);
    return;
  }
  exactKeys(
    probe,
    ["address", "expected_leaf_sha256", "id", "kind", "port", "server_name"],
    label,
  );
  if (typeof probe.address !== "string") {
    fail(`${label}.address must be a literal IP or canonical lowercase DNS name`);
  }
  if (isIP(probe.address) === 0) validateHostName(probe.address, `${label}.address`);
  validateHostName(probe.server_name, `${label}.server_name`);
  validatePort(probe.port, `${label}.port`);
  validateHex64(probe.expected_leaf_sha256, `${label}.expected_leaf_sha256`);
}

export function validateSiteInventory({ bytes, plan }) {
  const buffer = Buffer.from(bytes);
  if (buffer.length < 1 || buffer.length > MAX_FILE_BYTES) {
    fail("site inventory size is outside the reviewed bound");
  }
  if (sha256(buffer) !== plan.site_preservation.existing_site_inventory_sha256) {
    fail("site inventory bytes do not match the approved plan SHA-256");
  }
  const inventory = parseStrictJson(buffer.toString("utf8"), "site inventory");
  if (!buffer.equals(Buffer.from(canonicalJson(inventory), "utf8"))) {
    fail("site inventory bytes must equal their canonical JSON encoding");
  }
  exactKeys(inventory, ["probes", "schema_version"], "site inventory");
  if (inventory.schema_version !== SITE_INVENTORY_SCHEMA_VERSION) {
    fail(`site inventory schema_version must equal ${SITE_INVENTORY_SCHEMA_VERSION}`);
  }
  if (!Array.isArray(inventory.probes) || inventory.probes.length < 3 || inventory.probes.length > 128) {
    fail("site inventory must contain 3..128 probes");
  }
  let previous = "";
  const kinds = new Set();
  for (const [index, probe] of inventory.probes.entries()) {
    validateSiteProbe(probe, `site inventory probe[${index}]`);
    if (probe.id <= previous) fail("site inventory probes must be sorted and unique by ID");
    previous = probe.id;
    kinds.add(probe.kind);
  }
  for (const kind of SITE_PROBE_KINDS) {
    if (!kinds.has(kind)) fail(`site inventory must include a ${kind} probe`);
  }
  const ids = inventory.probes.map(({ id }) => id);
  if (!same(ids, plan.site_preservation.probe_ids)) {
    fail("site inventory probe IDs do not equal the complete approved plan inventory");
  }
  return inventory;
}

function assertExactSnapshot(actual, expected, label) {
  if (!same(actual, expected)) fail(`${label} drifted from its exact approved snapshot`);
}

function assertContentSnapshot(actual, expected, label) {
  for (const key of ["gid", "mode", "path", "sha256", "size", "uid"]) {
    if (actual[key] !== expected[key]) fail(`${label}.${key} drifted from the approved pin`);
  }
  if (actual.nlink !== 1) fail(`${label}.nlink must equal 1`);
}

function assertHost(host, plan, label) {
  exactKeys(host, ["boot_id", "hostname"], label);
  if (host.boot_id !== plan.privileged_access_inventory.boot_id) {
    fail(`${label} boot ID drifted from the approved same-boot inventory`);
  }
  if (typeof host.hostname !== "string" || host.hostname.length < 1 || host.hostname.length > 255) {
    fail(`${label} hostname is invalid`);
  }
}

function assertGeneration(actual, expected, label) {
  if (!same(actual, expected)) fail(`${label} PID/InvocationID generation drifted`);
}

function assertObservedUnitGeneration(value, { active, label }) {
  exactKeys(
    value,
    [
      "active_enter_timestamp_monotonic",
      "active_state",
      "control_group",
      "invocation_id",
      "main_pid",
      "sub_state",
      "unit_name",
    ],
    label,
  );
  if (
    value.control_group !== `/system.slice/${TARGET_UNIT}` ||
    value.unit_name !== TARGET_UNIT
  ) {
    fail(`${label} is not the exact reviewed Caddy unit/cgroup`);
  }
  if (active) {
    if (
      value.active_state !== "active" ||
      value.sub_state !== "running" ||
      !/^[1-9][0-9]*$/u.test(value.main_pid) ||
      !/^[1-9][0-9]*$/u.test(value.active_enter_timestamp_monotonic) ||
      !/^(?!0{32}$)[0-9a-f]{32}$/u.test(value.invocation_id)
    ) {
      fail(`${label} is not one canonical active/running systemd generation`);
    }
    return;
  }
  if (
    value.active_state !== "inactive" ||
    value.sub_state !== "dead" ||
    value.main_pid !== "0" ||
    value.invocation_id !== "" ||
    value.active_enter_timestamp_monotonic !== "0"
  ) {
    fail(`${label} is not the canonical stopped systemd state`);
  }
}

function expectedProcessArgv({ hardened }) {
  const result = [CADDY_BINARY_PATH, "run"];
  if (!hardened) result.push("--environ");
  result.push("--config", TARGET_CONFIG, "--adapter", "caddyfile");
  return result;
}

function assertProcessRuntime(actual, generation, { binaryPin, hardened, label }) {
  exactKeys(
    actual,
    ["caddy_admin_environment_absent", "cmdline_argv", "effective_environment_names", "exe_path", "exe_snapshot", "main_pid", "start_time_ticks"],
    label,
  );
  assertExactSnapshot(actual.exe_snapshot, binaryPin, `${label} executable`);
  const allowedArgv = hardened
    ? [expectedProcessArgv({ hardened: true })]
    : [expectedProcessArgv({ hardened: false })];
  if (
    actual.main_pid !== generation.main_pid ||
    actual.exe_path !== CADDY_BINARY_PATH ||
    !/^[1-9][0-9]*$/u.test(actual.start_time_ticks ?? "") ||
    !allowedArgv.some((argv) => same(argv, actual.cmdline_argv)) ||
    !Array.isArray(actual.effective_environment_names) ||
    actual.effective_environment_names.length > 512 ||
    actual.effective_environment_names.some(
      (name, index, names) =>
        typeof name !== "string" ||
        !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name) ||
        (index > 0 && names[index - 1] >= name),
    )
  ) {
    fail(`${label} does not match the exact Caddy process generation`);
  }
  if (hardened && actual.caddy_admin_environment_absent !== true) {
    fail(`${label} retained CADDY_ADMIN`);
  }
}

function expectedPublisherNetnsDependency() {
  return {
    after_namespace_owner: true,
    binds_to_namespace_owner: false,
    dropin_paths: [PUBLISHER_NETNS_DROPIN_PATH],
    need_daemon_reload: "no",
    part_of_namespace_owner: false,
    requires_namespace_owner: false,
    wants_namespace_owner: true,
  };
}

function expectedPreimageEffectiveUnit() {
  return {
    dropin_paths: [PUBLISHER_NETNS_DROPIN_PATH],
    environment_files: [],
    exec_reload: {
      argv: `${CADDY_BINARY_PATH} reload --config ${TARGET_CONFIG} --adapter caddyfile --force`,
      ignore_errors: "no",
      path: CADDY_BINARY_PATH,
    },
    exec_start: {
      argv: `${CADDY_BINARY_PATH} run --environ --config ${TARGET_CONFIG} --adapter caddyfile`,
      ignore_errors: "no",
      path: CADDY_BINARY_PATH,
    },
    fragment_path: TARGET_FRAGMENT,
    need_daemon_reload: "no",
    pass_environment: [],
    publisher_netns_dependency: expectedPublisherNetnsDependency(),
  };
}

function assertPreimageEffectiveUnit(actual, label) {
  if (!same(actual, expectedPreimageEffectiveUnit())) {
    fail(`${label} is not the exact loaded disk preimage with NeedDaemonReload=no`);
  }
}

async function collectPinnedActivePreimage(plan, ops, label) {
  const host = await ops.hostIdentity();
  assertHost(host, plan, `${label} host`);
  const [binary, config, publisherNetnsDropin, unit] = await Promise.all([
    ops.readRegular(plan.preimage.binary.path),
    ops.readRegular(plan.preimage.config.path),
    ops.readRegular(plan.publisher_netns_dropin.path),
    ops.readRegular(plan.preimage.unit.path),
  ]);
  assertExactSnapshot(binary.snapshot, plan.preimage.binary, `${label} Caddy binary`);
  assertExactSnapshot(config.snapshot, plan.preimage.config, `${label} Caddyfile`);
  assertExactSnapshot(unit.snapshot, plan.preimage.unit, `${label} unit`);
  assertExactSnapshot(
    publisherNetnsDropin.snapshot,
    plan.publisher_netns_dropin,
    `${label} publisher namespace drop-in`,
  );
  validatePublisherNetnsDropInBytes(
    publisherNetnsDropin.bytes,
    plan.publisher_netns_dropin.sha256,
  );
  const generation = await ops.readUnitGeneration(TARGET_UNIT);
  assertGeneration(generation, plan.preimage.unit_generation, `${label} unit`);
  const effectiveUnit = await ops.readPreimageEffectiveUnit(TARGET_UNIT);
  assertPreimageEffectiveUnit(effectiveUnit, `${label} effective unit`);
  const process = await ops.readProcessRuntime(generation.main_pid);
  assertProcessRuntime(process, generation, {
    binaryPin: plan.preimage.binary,
    hardened: false,
    label: `${label} process`,
  });
  return {
    binary, config, effectiveUnit, generation, host, process,
    publisherNetnsDropin, unit,
  };
}

async function assertRuntimePins(plan, ops, label) {
  for (const [pin, pinLabel] of [
    [plan.runtime.executor, "executor"],
    [plan.runtime.gate, "gate"],
    [plan.runtime.node_binary, "Node"],
    [plan.runtime.probe, "admin probe"],
    [plan.runtime.setpriv_binary, "setpriv"],
  ]) {
    const observed = await ops.readRegular(pin.path);
    assertExactSnapshot(observed.snapshot, pin, `${label} ${pinLabel}`);
  }
}

function assertSelfIdentity(actual, approvedPlanSha256, plan, label) {
  exactKeys(
    actual,
    [
      "executor_path",
      "executor_snapshot",
      "node_proc_exe_path",
      "node_proc_exe_snapshot",
      "node_cmdline_argv",
      "node_control_environment_names",
      "node_exec_argv",
      "node_process_argv",
      "node_process_exec_path",
      "node_version",
    ],
    label,
  );
  if (
    actual.executor_path !== EXECUTOR_PATH ||
    actual.node_proc_exe_path !== plan.runtime.node_binary.path ||
    actual.node_process_exec_path !== plan.runtime.node_binary.path ||
    actual.node_version !== plan.runtime.node_version
  ) {
    fail(`${label} is not the exact approved executor/Node process identity`);
  }
  const expectedPrefix = [
    plan.runtime.node_binary.path,
    EXECUTOR_PATH,
    "execute",
    "--plan",
  ];
  if (
    !Array.isArray(actual.node_exec_argv) ||
    !Array.isArray(actual.node_control_environment_names) ||
    !Array.isArray(actual.node_process_argv) ||
    !Array.isArray(actual.node_cmdline_argv) ||
    !same(actual.node_exec_argv, []) ||
    !same(actual.node_control_environment_names, []) ||
    !same(actual.node_process_argv, actual.node_cmdline_argv) ||
    actual.node_cmdline_argv.length !== 9 ||
    !same(actual.node_cmdline_argv.slice(0, 4), expectedPrefix) ||
    !isAbsolute(actual.node_cmdline_argv[4]) ||
    resolve(actual.node_cmdline_argv[4]) !== actual.node_cmdline_argv[4] ||
    actual.node_cmdline_argv[5] !== "--site-inventory" ||
    !isAbsolute(actual.node_cmdline_argv[6]) ||
    resolve(actual.node_cmdline_argv[6]) !== actual.node_cmdline_argv[6] ||
    actual.node_cmdline_argv[7] !== "--approved-plan-sha256" ||
    actual.node_cmdline_argv[8] !== approvedPlanSha256
  ) {
    fail(`${label} has an unreviewed Node argv, preload, inspector or environment control plane`);
  }
  assertExactSnapshot(actual.executor_snapshot, plan.runtime.executor, `${label} executor`);
  assertExactSnapshot(actual.node_proc_exe_snapshot, plan.runtime.node_binary, `${label} Node`);
}

async function runSiteProbes(inventory, ops, phase) {
  const results = [];
  for (const probe of inventory.probes) {
    const observed = await ops.runSiteProbe(probe, phase);
    if (!isPlainObject(observed) || observed.id !== probe.id || observed.result !== "passed") {
      fail(`${phase} site probe ${probe.id} did not return an exact pass`);
    }
    results.push({ id: probe.id, result: "passed" });
  }
  return results;
}

function siteHealthReceipt(before, after) {
  if (before.length !== after.length) fail("site probe counts changed across the transaction");
  return before.map((entry, index) => {
    if (entry.id !== after[index].id) fail("site probe order changed across the transaction");
    return { after: "passed", before: "passed", id: entry.id };
  });
}

function assertLegacyAdmin(actual, expected, label) {
  exactKeys(actual, ["body_sha256", "listen", "status", "transport"], label);
  validateHex64(actual.body_sha256, `${label}.body_sha256`);
  if (
    actual.listen !== "127.0.0.1:2019" ||
    actual.status !== 200 ||
    actual.transport !== "tcp"
  ) {
    fail(`${label} did not prove the old TCP admin endpoint`);
  }
  if (expected !== undefined && !same(actual, expected)) {
    fail(`${label} drifted from the pre-stop old admin readback`);
  }
}

function assertStoppedEvidence(value) {
  exactKeys(
    value,
    ["admin_socket_absent", "tcp_admin", "unit_generation", "unit_job_absent"],
    "stopped evidence",
  );
  if (value.admin_socket_absent !== true || value.unit_job_absent !== true) {
    fail("stopped evidence retained the admin socket or a pending systemd job");
  }
  assertObservedUnitGeneration(value.unit_generation, {
    active: false,
    label: "stopped unit generation",
  });
  assertTcpRefused(value.tcp_admin, "stopped TCP admin");
}

function assertTcpRefused(value, label) {
  const expected = ["127.0.0.1:2019", "[::1]:2019"];
  if (!Array.isArray(value) || value.length !== expected.length) {
    fail(`${label} must contain the exact IPv4/IPv6 pair`);
  }
  value.forEach((probe, index) => {
    if (!same(probe, { endpoint: expected[index], result: "connection-refused" })) {
      fail(`${label} did not prove ${expected[index]} refused`);
    }
  });
}

function classifyPair(configSnapshot, unitSnapshot, plan) {
  const classify = (snapshot, oldPin, candidatePin) => {
    const content = (pin) =>
      ["gid", "mode", "path", "sha256", "size", "uid"].every(
        (key) => snapshot[key] === pin[key],
      ) && snapshot.nlink === 1;
    if (content(oldPin)) return "old";
    if (content(candidatePin)) return "candidate";
    return "unknown";
  };
  return `${classify(configSnapshot, plan.preimage.config, plan.candidate.config)}/${classify(unitSnapshot, plan.preimage.unit, plan.candidate.unit)}`;
}

async function collectFilePair(plan, ops) {
  const config = await ops.readRegular(TARGET_CONFIG);
  const unit = await ops.readRegular(TARGET_FRAGMENT);
  return {
    config,
    kind: classifyPair(config.snapshot, unit.snapshot, plan),
    unit,
  };
}

function expectedActivationProperties() {
  return {
    Group: "root",
    LimitCORE: "0",
    MemorySwapMax: "0",
    RuntimeDirectory: "bitcoinpir-caddy-admin",
    RuntimeDirectoryMode: "0700",
    RuntimeDirectoryPreserve: "no",
    StandardError: "null",
    StandardOutput: "null",
    UMask: "0077",
    UnsetEnvironment: ["CADDY_ADMIN"],
    User: "root",
  };
}

function assertActivation(value, plan) {
  exactKeys(
    value,
    ["binary_version", "dropin_paths", "effective_environment_names", "fragment_path", "need_daemon_reload", "properties", "publisher_netns_dependency", "unit_generation"],
    "activation evidence",
  );
  const generation = value.unit_generation;
  assertObservedUnitGeneration(generation, {
    active: true,
    label: "activation unit generation",
  });
  if (
    generation.active_state !== "active" ||
    generation.sub_state !== "running" ||
    generation.main_pid === "0" ||
    generation.invocation_id === plan.preimage.unit_generation.invocation_id ||
    generation.active_enter_timestamp_monotonic ===
      plan.preimage.unit_generation.active_enter_timestamp_monotonic
  ) {
    fail("activation did not prove a new active/running systemd generation");
  }
  if (
    value.binary_version !== "v2.11.4" ||
    value.fragment_path !== TARGET_FRAGMENT ||
    value.need_daemon_reload !== "no" ||
    !same(value.dropin_paths, [PUBLISHER_NETNS_DROPIN_PATH]) ||
    !same(value.publisher_netns_dependency, expectedPublisherNetnsDependency()) ||
    !same(value.properties, expectedActivationProperties()) ||
    !Array.isArray(value.effective_environment_names) ||
    value.effective_environment_names.includes("CADDY_ADMIN")
  ) {
    fail("activation effective unit drifted from the exact hardened profile");
  }
}

function normalizeAdminProbe(value, expected, planEntry) {
  if (!isPlainObject(value)) fail("admin probe result must be an object");
  if (expected === "root-readback") {
    const result = {
      body_sha256: value.body_sha256,
      cap_eff: value.cap_eff,
      gid: value.gid,
      groups: value.groups,
      listen: value.listen,
      path: value.path,
      status: value.status,
      transport: value.transport,
      uid: value.uid,
    };
    if (!same(result, {
      body_sha256: planEntry,
      cap_eff: "0000000000000000",
      gid: 0,
      groups: [0],
      listen: ADMIN_LISTEN,
      path: "/config/",
      status: 200,
      transport: "unix",
      uid: 0,
    })) {
      fail("root admin readback did not equal the approved canonical candidate");
    }
    return result;
  }
  const result = {
    cap_eff: value.cap_eff,
    error: value.error,
    gid: value.gid,
    groups: value.groups,
    name: planEntry.name,
    uid: value.uid,
  };
  if (!same(result, {
    cap_eff: "0000000000000000",
    error: "EACCES",
    gid: planEntry.uid,
    groups: [planEntry.uid],
    name: planEntry.name,
    uid: planEntry.uid,
  })) {
    fail(`admin denial probe ${planEntry.name} was not an exact capability-free EACCES proof`);
  }
  return result;
}

function recoveryRecord({ approvedPlanSha256, observed, phase, plan, reason }) {
  return {
    approved_plan_sha256: approvedPlanSha256,
    automatic_rollback_performed: false,
    collector: COLLECTOR,
    deployment_profile: PROFILE,
    observed,
    outcome: COLD_OUTCOMES.outcomeUnknown,
    phase,
    reason,
    schema_version: 1,
    transaction_id: plan.transaction_id,
  };
}

export class ColdTransactionError extends Error {
  constructor(message, { cause, outcome, phase, result } = {}) {
    super(message, { cause });
    this.name = "ColdTransactionError";
    this.outcome = outcome;
    this.phase = phase;
    this.result = result;
  }
}

export class ColdOutcomeUnknownError extends ColdTransactionError {
  constructor(message, options = {}) {
    super(message, { ...options, outcome: COLD_OUTCOMES.outcomeUnknown });
    this.name = "ColdOutcomeUnknownError";
  }
}

async function publishOutcomeUnknown({ approvedPlanSha256, ops, phase, plan, reason }) {
  let observed;
  try {
    observed = await ops.recoverySnapshot(plan);
  } catch (error) {
    observed = { collection_error: error.message };
  }
  const record = recoveryRecord({ approvedPlanSha256, observed, phase, plan, reason });
  try {
    await ops.publishState(
      plan.transaction.state_directory,
      "40-recovery-required.json",
      Buffer.from(canonicalJson(record), "utf8"),
      STATE_MODE,
    );
  } catch (publicationError) {
    record.recovery_record_publication_error = publicationError.message;
  }
  return record;
}

async function validatePreflight({ approvedPlanSha256, inventory, ops, plan }) {
  validatePlan(plan);
  validateHex64(approvedPlanSha256, "approved plan SHA-256");
  if (computeApprovedPlanSha256(plan) !== approvedPlanSha256) {
    fail("hardening plan does not match the externally approved SHA-256");
  }
  if (plan.runtime.systemd_version !== SYSTEMD_VERSION) {
    fail(`plan systemd version must equal ${SYSTEMD_VERSION}`);
  }
  if (plan.preimage.binary.path !== CADDY_BINARY_PATH) {
    fail(`plan Caddy binary path must equal ${CADDY_BINARY_PATH}`);
  }
  if (plan.runtime.executor.path !== EXECUTOR_PATH) {
    fail(`plan executor path must equal ${EXECUTOR_PATH}`);
  }
  assertSelfIdentity(
    await ops.selfIdentity(),
    approvedPlanSha256,
    plan,
    "cold executor self identity",
  );
  const prerequisites = await ops.hostPrerequisites();
  exactKeys(
    prerequisites,
    ["core_pattern", "euid", "platform", "systemd_version"],
    "host prerequisites",
  );
  if (
    prerequisites.euid !== 0 ||
    prerequisites.platform !== "linux" ||
    prerequisites.systemd_version !== SYSTEMD_VERSION
  ) {
    fail("cold executor requires Linux root and exact systemd 255");
  }
  if (prerequisites.core_pattern !== REQUIRED_CORE_PATTERN) {
    fail(
      `kernel.core_pattern must already equal ${REQUIRED_CORE_PATTERN}; this executor never changes it`,
    );
  }
  await assertPublisherNetnsInactivePreimage(plan, ops, "preflight");
  validateSiteInventory({ bytes: inventory.bytes, plan });
}

async function validatePreparedArtifacts({ adaptedJsonBytes, candidates, ops, plan }) {
  const config = await ops.readRegular(plan.transaction.candidate_config_path);
  const unit = await ops.readRegular(plan.transaction.candidate_unit_path);
  assertContentSnapshot(
    config.snapshot,
    { ...plan.candidate.config, path: plan.transaction.candidate_config_path },
    "prepared candidate Caddyfile",
  );
  assertContentSnapshot(
    unit.snapshot,
    { ...plan.candidate.unit, path: plan.transaction.candidate_unit_path },
    "prepared candidate unit",
  );
  if (!config.bytes.equals(candidates.config) || !unit.bytes.equals(candidates.unit)) {
    fail("prepared candidate bytes changed after their durable write");
  }
  validateCandidateAdaptedJson({ adaptedJsonBytes, plan });
  return { config, unit };
}

async function restoreOldPair({ ops, plan }) {
  const pair = await collectFilePair(plan, ops);
  const allowed = new Set(plan.transaction.classification.allowed_stopped_pairs);
  if (!allowed.has(pair.kind)) {
    fail(`stopped file pair ${pair.kind} is not rollback-safe; leaving the service stopped`);
  }
  await ops.restoreFromBackup({
    backupPath: plan.transaction.backup_config_path,
    pin: plan.preimage.config,
    targetPath: TARGET_CONFIG,
  });
  await ops.restoreFromBackup({
    backupPath: plan.transaction.backup_unit_path,
    pin: plan.preimage.unit,
    targetPath: TARGET_FRAGMENT,
  });
  const restored = await collectFilePair(plan, ops);
  if (restored.kind !== "old/old") fail("rollback did not restore the exact old/old pair");
  return { before: pair.kind, after: restored.kind };
}

async function rollbackStoppedFailure({
  approvedPlanSha256,
  beforeAdmin,
  inventory,
  ops,
  plan,
  primaryError,
}) {
  let pair;
  try {
    pair = await restoreOldPair({ ops, plan });
  } catch (rollbackError) {
    const recovery = await publishOutcomeUnknown({
      approvedPlanSha256,
      ops,
      phase: "stopped-pre-start-rollback-unavailable",
      plan,
      reason: `${primaryError.message}; rollback classification failed: ${rollbackError.message}`,
    });
    throw new ColdOutcomeUnknownError(
      "stopped transaction failed and exact rollback could not be proven",
      { cause: rollbackError, phase: "stopped-pre-start-rollback-unavailable", result: recovery },
    );
  }

  let rollbackStartRequested = false;
  try {
    const reload = await ops.run(plan.transaction.daemon_reload_argv, {
      label: "rollback daemon-reload",
    });
    if (reload.status !== 0) fail("rollback daemon-reload returned nonzero");
    await ops.publishState(
      plan.transaction.state_directory,
      "30-rollback-start-requested.json",
      Buffer.from(canonicalJson({
        approved_plan_sha256: approvedPlanSha256,
        phase: "rollback-start-requested",
        schema_version: 1,
        transaction_id: plan.transaction_id,
      }), "utf8"),
      STATE_MODE,
    );
    await assertPublisherNetnsInactivePreimage(
      plan,
      ops,
      "immediate pre-rollback-start",
    );
    rollbackStartRequested = true;
    const start = await ops.run(plan.transaction.start_argv, { label: "rollback start" });
    if (start.status !== 0) fail("old-generation rollback start returned nonzero");
  } catch (rollbackStartError) {
    const phase = rollbackStartRequested
      ? "rollback-post-start"
      : "stopped-pre-start-rollback-start-unrequested";
    const recovery = await publishOutcomeUnknown({
      approvedPlanSha256,
      ops,
      phase,
      plan,
      reason: `${primaryError.message}; rollback restart boundary failed: ${rollbackStartError.message}`,
    });
    throw new ColdOutcomeUnknownError("old-generation rollback restart outcome is unknown", {
      cause: rollbackStartError,
      phase,
      result: recovery,
    });
  }

  try {
    const host = await ops.hostIdentity();
    assertHost(host, plan, "rollback host");
    const generation = await ops.readUnitGeneration(TARGET_UNIT);
    assertObservedUnitGeneration(generation, {
      active: true,
      label: "rollback unit generation",
    });
    if (
      generation.invocation_id === plan.preimage.unit_generation.invocation_id
    ) {
      fail("rollback did not create a new active old-config generation");
    }
    const process = await ops.readProcessRuntime(generation.main_pid);
    assertProcessRuntime(process, generation, {
      binaryPin: plan.preimage.binary,
      hardened: false,
      label: "rollback process",
    });
    const effectiveUnit = await ops.readPreimageEffectiveUnit(TARGET_UNIT);
    assertPreimageEffectiveUnit(effectiveUnit, "rollback effective unit");
    const admin = await ops.probeLegacyAdmin();
    assertLegacyAdmin(admin, beforeAdmin, "rollback old admin");
    await runSiteProbes(inventory, ops, "rollback-after");
    const finalHost = await ops.hostIdentity();
    assertHost(finalHost, plan, "final rollback host");
    await assertRuntimePins(plan, ops, "final rollback runtime");
    const finalGeneration = await ops.readUnitGeneration(TARGET_UNIT);
    assertGeneration(finalGeneration, generation, "final rollback unit");
    const finalProcess = await ops.readProcessRuntime(generation.main_pid);
    if (!same(finalProcess, process)) {
      fail("old Caddy process changed across rollback site probes");
    }
    const finalEffectiveUnit = await ops.readPreimageEffectiveUnit(TARGET_UNIT);
    assertPreimageEffectiveUnit(finalEffectiveUnit, "final rollback effective unit");
    if (!same(finalEffectiveUnit, effectiveUnit)) {
      fail("old effective unit changed across rollback site probes");
    }
    const finalAdmin = await ops.probeLegacyAdmin();
    assertLegacyAdmin(finalAdmin, beforeAdmin, "final rollback old admin");
    if (!same(finalAdmin, admin)) fail("old admin readback changed across rollback site probes");
    const restored = await collectFilePair(plan, ops);
    if (restored.kind !== "old/old") fail("rollback old pair drifted after restart");
    const result = {
      approved_plan_sha256: approvedPlanSha256,
      failure: primaryError.message,
      old_admin: admin,
      old_generation: generation,
      outcome: COLD_OUTCOMES.rolledBack,
      pair,
      schema_version: 1,
      transaction_id: plan.transaction_id,
    };
    await ops.publishState(
      plan.transaction.state_directory,
      "50-rolled-back.json",
      Buffer.from(canonicalJson(result), "utf8"),
      STATE_MODE,
    );
    throw new ColdTransactionError(
      `cold hardening failed before candidate start and exact rollback was verified: ${primaryError.message}`,
      {
        cause: primaryError,
        outcome: COLD_OUTCOMES.rolledBack,
        phase: "stopped-pre-start",
        result,
      },
    );
  } catch (error) {
    if (error instanceof ColdTransactionError) throw error;
    const recovery = await publishOutcomeUnknown({
      approvedPlanSha256,
      ops,
      phase: "rollback-post-start-verification",
      plan,
      reason: `${primaryError.message}; rollback verification failed: ${error.message}`,
    });
    throw new ColdOutcomeUnknownError("old-generation rollback verification is incomplete", {
      cause: error,
      phase: "rollback-post-start-verification",
      result: recovery,
    });
  }
}

async function collectCommittedEvidence({
  approvedPlanSha256,
  before,
  beforeSites,
  inventory,
  ops,
  plan,
  stopped,
}) {
  const host = await ops.hostIdentity();
  assertHost(host, plan, "post-start host");
  await assertRuntimePins(plan, ops, "post-start runtime");
  const installedBinary = await ops.readRegular(plan.candidate.binary.path);
  const installedConfig = await ops.readRegular(plan.candidate.config.path);
  const installedUnit = await ops.readRegular(plan.candidate.unit.path);
  const installedPublisherNetnsDropin = await ops.readRegular(
    plan.publisher_netns_dropin.path,
  );
  assertContentSnapshot(installedBinary.snapshot, plan.candidate.binary, "installed binary");
  assertContentSnapshot(installedConfig.snapshot, plan.candidate.config, "installed config");
  assertContentSnapshot(installedUnit.snapshot, plan.candidate.unit, "installed unit");
  assertExactSnapshot(
    installedPublisherNetnsDropin.snapshot,
    plan.publisher_netns_dropin,
    "installed publisher namespace drop-in",
  );
  validatePublisherNetnsDropInBytes(
    installedPublisherNetnsDropin.bytes,
    plan.publisher_netns_dropin.sha256,
  );
  const generation = await ops.readUnitGeneration(TARGET_UNIT);
  const effective = await ops.readEffectiveUnit(TARGET_UNIT);
  const binaryVersion = await ops.binaryVersion(plan.candidate.binary);
  const activation = {
    binary_version: binaryVersion,
    dropin_paths: effective.dropin_paths,
    effective_environment_names: effective.effective_environment_names,
    fragment_path: effective.fragment_path,
    need_daemon_reload: effective.need_daemon_reload,
    properties: effective.properties,
    publisher_netns_dependency: effective.publisher_netns_dependency,
    unit_generation: generation,
  };
  assertActivation(activation, plan);
  const process = await ops.readProcessRuntime(generation.main_pid);
  assertProcessRuntime(process, generation, {
    binaryPin: plan.preimage.binary,
    hardened: true,
    label: "post-start process",
  });

  const runtimeDirectory = await ops.readAdminRuntimePath(ADMIN_DIRECTORY);
  const socket = await ops.readAdminRuntimePath(ADMIN_SOCKET);
  if (!same(runtimeDirectory, {
    gid: 0,
    mode: "0700",
    path: ADMIN_DIRECTORY,
    type: "directory",
    uid: 0,
  })) {
    fail("admin RuntimeDirectory is not exact root:root 0700");
  }
  if (!same(socket, {
    gid: 0,
    mode: "0200",
    path: ADMIN_SOCKET,
    type: "socket",
    uid: 0,
  })) {
    fail("admin socket is not exact root:root 0200");
  }
  const rootReadback = normalizeAdminProbe(
    await ops.probeAdminApi({
      expected: "root-readback",
      gid: 0,
      label: "root",
      plan,
      uid: 0,
    }),
    "root-readback",
    plan.candidate.adapted_json_sha256,
  );
  const deniedServiceUids = [];
  for (const entry of plan.service_uid_inventory) {
    deniedServiceUids.push(normalizeAdminProbe(
      await ops.probeAdminApi({
        expected: "EACCES",
        gid: entry.uid,
        label: entry.name,
        plan,
        uid: entry.uid,
      }),
      "EACCES",
      entry,
    ));
  }
  const tcpAdmin = await ops.probeTcpAdmin();
  assertTcpRefused(tcpAdmin, "post-start TCP admin");
  const afterSites = await runSiteProbes(inventory, ops, "after");

  const finalHost = await ops.hostIdentity();
  assertHost(finalHost, plan, "final host");
  const finalGeneration = await ops.readUnitGeneration(TARGET_UNIT);
  assertGeneration(finalGeneration, generation, "final unit");
  const finalProcess = await ops.readProcessRuntime(generation.main_pid);
  if (!same(finalProcess, process)) fail("Caddy process changed across post-start probes");
  const finalEffective = await ops.readEffectiveUnit(TARGET_UNIT);
  if (!same(finalEffective, effective)) fail("effective Caddy unit changed across post-start probes");
  const finalRuntimeDirectory = await ops.readAdminRuntimePath(ADMIN_DIRECTORY);
  const finalSocket = await ops.readAdminRuntimePath(ADMIN_SOCKET);
  if (!same(finalRuntimeDirectory, runtimeDirectory) || !same(finalSocket, socket)) {
    fail("admin runtime path metadata changed across post-start probes");
  }
  const finalRootReadback = normalizeAdminProbe(
    await ops.probeAdminApi({
      expected: "root-readback",
      gid: 0,
      label: "root-final",
      plan,
      uid: 0,
    }),
    "root-readback",
    plan.candidate.adapted_json_sha256,
  );
  if (!same(finalRootReadback, rootReadback)) {
    fail("root admin readback changed across post-start probes");
  }
  const finalDeniedServiceUids = [];
  for (const entry of plan.service_uid_inventory) {
    finalDeniedServiceUids.push(normalizeAdminProbe(
      await ops.probeAdminApi({
        expected: "EACCES",
        gid: entry.uid,
        label: `${entry.name}-final`,
        plan,
        uid: entry.uid,
      }),
      "EACCES",
      entry,
    ));
  }
  if (!same(finalDeniedServiceUids, deniedServiceUids)) {
    fail("admin denial evidence changed across post-start probes");
  }
  const finalTcpAdmin = await ops.probeTcpAdmin();
  assertTcpRefused(finalTcpAdmin, "final TCP admin");
  if (!same(finalTcpAdmin, tcpAdmin)) fail("TCP admin evidence changed across post-start probes");
  await assertRuntimePins(plan, ops, "final runtime");
  const finalPair = await collectFilePair(plan, ops);
  if (finalPair.kind !== "candidate/candidate") {
    fail("candidate file pair drifted before receipt publication");
  }

  return {
    activation,
    admin: {
      denied_service_uids: deniedServiceUids,
      root_readback: rootReadback,
      runtime_directory: runtimeDirectory,
      socket,
      tcp_admin: tcpAdmin,
    },
    approved_plan_sha256: approvedPlanSha256,
    before: {
      binary: before.binary.snapshot,
      config: before.config.snapshot,
      publisher_netns_dependency: before.effectiveUnit.publisher_netns_dependency,
      publisher_netns_dropin: before.publisherNetnsDropin.snapshot,
      unit: before.unit.snapshot,
      unit_generation: before.generation,
    },
    collector: COLLECTOR,
    deployment_profile: PROFILE,
    durability: {
      parent_fsynced: true,
      receipt_exclusive_create: true,
      receipt_file_fsynced: true,
    },
    host,
    installed: {
      binary: installedBinary.snapshot,
      config: installedConfig.snapshot,
      publisher_netns_dropin: installedPublisherNetnsDropin.snapshot,
      unit: installedUnit.snapshot,
    },
    outcome: "committed",
    privileged_access_inventory: plan.privileged_access_inventory,
    publisher_netns_dropin: plan.publisher_netns_dropin,
    recovery_classification: "candidate/candidate-new-generation",
    rollback: { outcome: "not-required", performed: false },
    runtime: plan.runtime,
    schema_version: 2,
    site_health: siteHealthReceipt(beforeSites, afterSites),
    stopped,
    transaction_id: plan.transaction_id,
  };
}

export async function executeCaddyAdminUdsTransaction({
  approvedPlanSha256,
  ops,
  plan,
  siteInventoryBytes,
}) {
  const inventory = { bytes: Buffer.from(siteInventoryBytes) };
  await validatePreflight({ approvedPlanSha256, inventory, ops, plan });
  inventory.probes = validateSiteInventory({ bytes: inventory.bytes, plan }).probes;

  let releaseLock;
  let lockAcquired = false;
  let keepLock = false;
  let stopped = false;
  let stopRequested = false;
  let startRequested = false;
  let beforeAdmin;
  let beforeSites;
  let terminalError;
  let terminalResult;
  try {
    const acquiredRelease = await ops.acquireLock(plan.transaction.lock_path, {
      transactionId: plan.transaction_id,
    });
    if (typeof acquiredRelease !== "function") fail("lock acquisition did not return an exact release function");
    releaseLock = acquiredRelease;
    lockAcquired = true;
    await validatePreflight({ approvedPlanSha256, inventory, ops, plan });
    const before = await collectPinnedActivePreimage(plan, ops, "initial");
    await assertRuntimePins(plan, ops, "initial runtime");
    const preimageAdaptedJsonBytes = await ops.verifyPreimage({
      configPreimageBytes: before.config.bytes,
      plan,
    });
    validatePreimageAdaptedJson({ adaptedJsonBytes: preimageAdaptedJsonBytes, plan });
    beforeAdmin = await ops.probeLegacyAdmin();
    assertLegacyAdmin(beforeAdmin, {
      body_sha256: plan.preimage.adapted_json_sha256,
      listen: "127.0.0.1:2019",
      status: 200,
      transport: "tcp",
    }, "pre-stop old admin");
    beforeSites = await runSiteProbes(inventory, ops, "before");

    const candidates = buildCandidates({
      configPreimageBytes: before.config.bytes,
      plan,
      unitPreimageBytes: before.unit.bytes,
    });
    await ops.prepareArtifact(
      plan.transaction.candidate_config_path,
      candidates.config,
      plan.candidate.config.mode,
    );
    await ops.prepareArtifact(
      plan.transaction.candidate_unit_path,
      candidates.unit,
      plan.candidate.unit.mode,
    );
    const adaptedJsonBytes = await ops.verifyCandidate({ candidates, plan });
    const preparedCandidates = await validatePreparedArtifacts({
      adaptedJsonBytes,
      candidates,
      ops,
      plan,
    });
    await ops.prepareArtifact(
      plan.transaction.backup_config_path,
      before.config.bytes,
      RECEIPT_MODE,
    );
    await ops.prepareArtifact(
      plan.transaction.backup_unit_path,
      before.unit.bytes,
      RECEIPT_MODE,
    );
    const backupConfig = await ops.readRegular(plan.transaction.backup_config_path);
    const backupUnit = await ops.readRegular(plan.transaction.backup_unit_path);
    if (
      !backupConfig.bytes.equals(before.config.bytes) ||
      !backupUnit.bytes.equals(before.unit.bytes) ||
      backupConfig.snapshot.mode !== RECEIPT_MODE ||
      backupUnit.snapshot.mode !== RECEIPT_MODE ||
      backupConfig.snapshot.uid !== 0 ||
      backupConfig.snapshot.gid !== 0 ||
      backupUnit.snapshot.uid !== 0 ||
      backupUnit.snapshot.gid !== 0
    ) {
      fail("rollback backups do not contain the exact old bytes under root-only metadata");
    }
    await ops.publishState(
      plan.transaction.state_directory,
      "00-prepared.json",
      Buffer.from(canonicalJson({
        approved_plan_sha256: approvedPlanSha256,
        backup_metadata: {
          config: plan.preimage.config,
          unit: plan.preimage.unit,
        },
        candidate_config: preparedCandidates.config.snapshot,
        candidate_unit: preparedCandidates.unit.snapshot,
        phase: "prepared",
        schema_version: 1,
        transaction_id: plan.transaction_id,
      }), "utf8"),
      STATE_MODE,
    );

    const finalPreStop = await collectPinnedActivePreimage(plan, ops, "immediate pre-stop");
    const finalPrerequisites = await ops.hostPrerequisites();
    if (
      finalPrerequisites.euid !== 0 ||
      finalPrerequisites.platform !== "linux" ||
      finalPrerequisites.systemd_version !== SYSTEMD_VERSION ||
      finalPrerequisites.core_pattern !== REQUIRED_CORE_PATTERN
    ) {
      fail("host prerequisites drifted immediately before the stop boundary");
    }
    if (!same(finalPreStop.process, before.process)) {
      fail("Caddy process changed between preparation and the stop boundary");
    }
    if (!same(finalPreStop.effectiveUnit, before.effectiveUnit)) {
      fail("effective Caddy unit changed between preparation and the stop boundary");
    }
    const finalAdmin = await ops.probeLegacyAdmin();
    assertLegacyAdmin(finalAdmin, beforeAdmin, "immediate pre-stop old admin");
    await assertPublisherNetnsInactivePreimage(plan, ops, "immediate pre-stop");

    stopRequested = true;
    const stop = await ops.run(plan.transaction.stop_argv, { label: "cold stop" });
    if (stop.status !== 0) fail("systemctl stop returned nonzero");
    const stoppedEvidence = await ops.collectStoppedEvidence();
    assertStoppedEvidence(stoppedEvidence);
    stopped = true;
    const stoppedHost = await ops.hostIdentity();
    assertHost(stoppedHost, plan, "stopped host");
    await ops.publishState(
      plan.transaction.state_directory,
      "10-stopped.json",
      Buffer.from(canonicalJson({
        approved_plan_sha256: approvedPlanSha256,
        evidence: stoppedEvidence,
        phase: "stopped",
        schema_version: 1,
        transaction_id: plan.transaction_id,
      }), "utf8"),
      STATE_MODE,
    );

    await ops.replacePrepared({
      expectedCurrent: plan.preimage.config,
      pin: plan.candidate.config,
      preparedPath: plan.transaction.candidate_config_path,
      targetPath: TARGET_CONFIG,
    });
    await ops.replacePrepared({
      expectedCurrent: plan.preimage.unit,
      pin: plan.candidate.unit,
      preparedPath: plan.transaction.candidate_unit_path,
      targetPath: TARGET_FRAGMENT,
    });
    const installedPair = await collectFilePair(plan, ops);
    if (installedPair.kind !== "candidate/candidate") {
      fail("stopped installation did not produce the exact candidate/candidate pair");
    }
    const reload = await ops.run(plan.transaction.daemon_reload_argv, {
      label: "candidate daemon-reload",
    });
    if (reload.status !== 0) fail("candidate daemon-reload returned nonzero");
    await ops.publishState(
      plan.transaction.state_directory,
      "20-installed.json",
      Buffer.from(canonicalJson({
        approved_plan_sha256: approvedPlanSha256,
        pair: installedPair.kind,
        phase: "installed-before-start",
        schema_version: 1,
        transaction_id: plan.transaction_id,
      }), "utf8"),
      STATE_MODE,
    );
    await ops.publishState(
      plan.transaction.state_directory,
      "30-start-requested.json",
      Buffer.from(canonicalJson({
        approved_plan_sha256: approvedPlanSha256,
        phase: "candidate-start-requested",
        schema_version: 1,
        transaction_id: plan.transaction_id,
      }), "utf8"),
      STATE_MODE,
    );
    await assertPublisherNetnsInactivePreimage(plan, ops, "immediate pre-candidate-start");
    startRequested = true;
    const start = await ops.run(plan.transaction.start_argv, { label: "candidate start" });
    if (start.status !== 0) fail("candidate start command returned nonzero");

    const receipt = await collectCommittedEvidence({
      approvedPlanSha256,
      before,
      beforeSites,
      inventory,
      ops,
      plan,
      stopped: stoppedEvidence,
    });
    const receiptBytes = Buffer.from(canonicalJson(receipt), "utf8");
    const receiptSha256 = sha256(receiptBytes);
    validateCommittedReceipt({
      approvedPlanSha256,
      plan,
      receipt,
      trustedReceiptSha256: receiptSha256,
    });
    await ops.publishReceipt(plan.transaction.receipt_path, receiptBytes, RECEIPT_MODE);
    terminalResult = {
      outcome: COLD_OUTCOMES.committed,
      receipt,
      receipt_sha256: receiptSha256,
      transaction_id: plan.transaction_id,
    };
    return terminalResult;
  } catch (error) {
    try {
      if (error instanceof ColdTransactionError) {
        if (error instanceof ColdOutcomeUnknownError) keepLock = true;
        throw error;
      }
      if (!lockAcquired) {
        throw new ColdTransactionError(
          `cold hardening failed before lock acquisition completed: ${error.message}`,
          {
            cause: error,
            outcome: COLD_OUTCOMES.preStopFailed,
            phase: "lock-acquisition",
            result: {
              outcome: COLD_OUTCOMES.preStopFailed,
              transaction_id: plan.transaction_id,
            },
          },
        );
      }
      if (startRequested) {
        keepLock = true;
        const recovery = await publishOutcomeUnknown({
          approvedPlanSha256,
          ops,
          phase: "post-start",
          plan,
          reason: error.message,
        });
        throw new ColdOutcomeUnknownError(
          `candidate start was requested; automatic rollback is forbidden: ${error.message}`,
          { cause: error, phase: "post-start", result: recovery },
        );
      }
      if (!stopped) {
        if (!stopRequested) {
          throw new ColdTransactionError(
            `cold hardening failed before the stop boundary; no active mutation was requested: ${error.message}`,
            {
              cause: error,
              outcome: COLD_OUTCOMES.preStopFailed,
              phase: "pre-stop",
              result: {
                outcome: COLD_OUTCOMES.preStopFailed,
                transaction_id: plan.transaction_id,
              },
            },
          );
        }
        let generation;
        try {
          generation = await ops.readUnitGeneration(TARGET_UNIT);
        } catch {
          generation = undefined;
        }
        if (
          generation?.active_state === "inactive" &&
          generation?.sub_state === "dead" &&
          generation?.main_pid === "0"
        ) {
          try {
            const recoveredStoppedEvidence = await ops.collectStoppedEvidence();
            assertStoppedEvidence(recoveredStoppedEvidence);
            stopped = true;
          } catch (stoppedProofError) {
            keepLock = true;
            const recovery = await publishOutcomeUnknown({
              approvedPlanSha256,
              ops,
              phase: "stop-outcome-unknown-before-start",
              plan,
              reason: `${error.message}; full stopped-state proof failed: ${stoppedProofError.message}`,
            });
            throw new ColdOutcomeUnknownError(
              "inactive/dead alone is insufficient; full stopped-state proof failed",
              {
                cause: stoppedProofError,
                phase: "stop-outcome-unknown-before-start",
                result: recovery,
              },
            );
          }
        } else {
          keepLock = true;
          const recovery = await publishOutcomeUnknown({
            approvedPlanSha256,
            ops,
            phase: "stop-outcome-unknown-before-start",
            plan,
            reason: `${error.message}; a requested systemd stop may still complete asynchronously`,
          });
          throw new ColdOutcomeUnknownError(
            "stop was requested but a complete stopped state was not proven",
            {
            cause: error,
            phase: "stop-outcome-unknown-before-start",
            result: recovery,
            },
          );
        }
      }
      try {
        await rollbackStoppedFailure({
          approvedPlanSha256,
          beforeAdmin,
          inventory,
          ops,
          plan,
          primaryError: error,
        });
      } catch (rollbackError) {
        if (rollbackError instanceof ColdOutcomeUnknownError) keepLock = true;
        throw rollbackError;
      }
    } catch (classifiedError) {
      terminalError = classifiedError;
      throw classifiedError;
    }
  } finally {
    if (releaseLock !== undefined && !keepLock) {
      try {
        await releaseLock();
      } catch (lockReleaseError) {
        if (terminalError !== undefined) {
          terminalError.lock_release_error = lockReleaseError.message;
        } else if (terminalResult !== undefined) {
          throw new ColdTransactionError(
            `transaction committed but lock release failed: ${lockReleaseError.message}`,
            {
              cause: lockReleaseError,
              outcome: COLD_OUTCOMES.committed,
              phase: "lock-release-failed",
              result: {
                ...terminalResult,
                lock_release_error: lockReleaseError.message,
              },
            },
          );
        } else {
          throw new ColdTransactionError(
            `transaction terminal state was reached but lock release failed: ${lockReleaseError.message}`,
            {
              cause: lockReleaseError,
              outcome: COLD_OUTCOMES.outcomeUnknown,
              phase: "lock-release-failed",
              result: { lock_release_error: lockReleaseError.message },
            },
          );
        }
      }
    }
  }
}

function modeString(stat) {
  return (Number(stat.mode) & 0o7777).toString(8).padStart(4, "0");
}

function snapshotFromStat(path, stat, bytes) {
  return {
    ctime_ns: stat.ctimeNs.toString(),
    device: stat.dev.toString(),
    gid: Number(stat.gid),
    inode: stat.ino.toString(),
    mode: modeString(stat),
    mtime_ns: stat.mtimeNs.toString(),
    nlink: Number(stat.nlink),
    path,
    sha256: sha256(bytes),
    size: String(bytes.length),
    uid: Number(stat.uid),
  };
}

function sameInode(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function sameStableStat(left, right) {
  return (
    sameInode(left, right) &&
    left.ctimeNs === right.ctimeNs &&
    left.mtimeNs === right.mtimeNs &&
    left.size === right.size &&
    left.nlink === right.nlink &&
    left.mode === right.mode &&
    left.uid === right.uid &&
    left.gid === right.gid
  );
}

function directorySealFromStat(path, stat) {
  if (!stat.isDirectory()) fail(`${path} is not a directory`);
  return {
    device: stat.dev.toString(),
    gid: Number(stat.gid),
    inode: stat.ino.toString(),
    mode: modeString(stat),
    path,
    uid: Number(stat.uid),
  };
}

function directorySeal(path) {
  const stat = lstatSync(path, { bigint: true, throwIfNoEntry: true });
  return directorySealFromStat(path, stat);
}

function assertDirectorySeal(path, before, label) {
  const after = directorySeal(path);
  if (!same(after, before)) fail(`${label} directory changed: ${path}`);
}

function fsyncDirectory(path, expected) {
  const fd = openSync(
    path,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
  );
  try {
    const stat = fstatSync(fd, { bigint: true });
    if (!same(directorySealFromStat(path, stat), expected)) {
      fail(`pre-fsync descriptor does not match the sealed directory: ${path}`);
    }
    assertDirectorySeal(path, expected, "pre-fsync");
    fsyncSync(fd);
    if (!same(directorySealFromStat(path, fstatSync(fd, { bigint: true })), expected)) {
      fail(`post-fsync descriptor does not match the sealed directory: ${path}`);
    }
    assertDirectorySeal(path, expected, "post-fsync");
  } finally {
    closeSync(fd);
  }
}

function ensurePrivateDirectory(path) {
  if (!isAbsolute(path) || resolve(path) !== path) {
    fail(`private directory must be an absolute normalized path: ${path}`);
  }
  const pieces = path.split("/").filter(Boolean);
  let current = "/";
  for (const piece of pieces) {
    current = join(current, piece);
    let stat;
    try {
      stat = lstatSync(current, { bigint: true, throwIfNoEntry: true });
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
      mkdirSync(current, { mode: 0o700 });
      stat = lstatSync(current, { bigint: true, throwIfNoEntry: true });
      fchownDirectory(current);
    }
    if (!stat.isDirectory() || Number(stat.uid) !== 0 || Number(stat.gid) !== 0) {
      fail(`private path component is not a root-owned directory: ${current}`);
    }
    if (current !== "/" && (Number(stat.mode) & 0o022) !== 0) {
      fail(`private path component is group/world writable: ${current}`);
    }
  }
  return directorySeal(path);
}

function fchownDirectory(path) {
  const fd = openSync(
    path,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
  );
  try {
    fchownSync(fd, 0, 0);
    fchmodSync(fd, 0o700);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  const parent = dirname(path);
  if (parent !== path) fsyncDirectory(parent, directorySeal(parent));
}

function openBoundRegular(path, maxBytes = MAX_FILE_BYTES, label = path) {
  const parentPath = dirname(path);
  const parent = directorySeal(parentPath);
  const fd = openSync(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
  );
  try {
    const before = fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size > BigInt(maxBytes)) {
      fail(`${label} is not one bounded single-link regular file`);
    }
    const bytes = readFileSync(fd);
    const after = fstatSync(fd, { bigint: true });
    const pathStat = lstatSync(path, { bigint: true, throwIfNoEntry: true });
    if (
      !sameStableStat(before, after) ||
      !pathStat.isFile() ||
      !sameStableStat(before, pathStat)
    ) {
      fail(`${label} changed during descriptor-bound read`);
    }
    assertDirectorySeal(parentPath, parent, "regular-file read");
    return {
      before,
      bytes,
      fd,
      parent,
      parentPath,
      path,
      snapshot: snapshotFromStat(path, before, bytes),
    };
  } catch (error) {
    closeSync(fd);
    throw error;
  }
}

function confirmBoundRegular(handle, label) {
  const after = fstatSync(handle.fd, { bigint: true });
  const pathStat = lstatSync(handle.path, { bigint: true, throwIfNoEntry: true });
  if (
    !sameStableStat(handle.before, after) ||
    !pathStat.isFile() ||
    !sameStableStat(handle.before, pathStat)
  ) {
    fail(`${label} changed while its descriptor was held`);
  }
  assertDirectorySeal(handle.parentPath, handle.parent, `${label} parent`);
}

function openPinnedDescriptor(pin, maxBytes, label) {
  const handle = openBoundRegular(pin.path, maxBytes, label);
  try {
    assertExactSnapshot(handle.snapshot, pin, label);
    return handle;
  } catch (error) {
    closeSync(handle.fd);
    throw error;
  }
}

function openContentPinnedDescriptor(path, pin, maxBytes, label) {
  const handle = openBoundRegular(path, maxBytes, label);
  try {
    assertContentSnapshot(handle.snapshot, { ...pin, path }, label);
    return handle;
  } catch (error) {
    closeSync(handle.fd);
    throw error;
  }
}

function realReadRegular(path, maxBytes = MAX_FILE_BYTES) {
  const handle = openBoundRegular(path, maxBytes);
  try {
    return { bytes: handle.bytes, snapshot: handle.snapshot };
  } finally {
    closeSync(handle.fd);
  }
}

function realReadOptionalRegular(path, maxBytes = MAX_FILE_BYTES) {
  try {
    return realReadRegular(path, maxBytes);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

function allowedCreateParent(path) {
  const parentPath = dirname(path);
  if (
    path.startsWith("/var/lib/bitcoinpir/payment-v1/bhtm-caddy-admin-uds/") ||
    (dirname(path) === "/etc/caddy" && basename(path).startsWith(".")) ||
    (dirname(path) === "/etc/systemd/system" && basename(path).startsWith("."))
  ) {
    return ensurePrivateDirectory(parentPath);
  }
  fail(`refusing to create an artifact outside the closed transaction roots: ${path}`);
}

function realWriteExclusive(path, bytes, mode) {
  const buffer = Buffer.from(bytes);
  if (buffer.length < 1 || buffer.length > MAX_FILE_BYTES) {
    fail(`exclusive artifact size is outside the reviewed bound: ${path}`);
  }
  const parentPath = dirname(path);
  const parent = allowedCreateParent(path);
  const numericMode = Number.parseInt(mode, 8);
  const fd = openSync(
    path,
    constants.O_WRONLY |
      constants.O_CREAT |
      constants.O_EXCL |
      constants.O_NOFOLLOW |
      constants.O_CLOEXEC,
    numericMode,
  );
  let writtenSnapshot;
  try {
    fchownSync(fd, 0, 0);
    fchmodSync(fd, numericMode);
    writeFileSync(fd, buffer);
    fsyncSync(fd);
    const stat = fstatSync(fd, { bigint: true });
    if (!stat.isFile() || stat.nlink !== 1n || Number(stat.uid) !== 0 || Number(stat.gid) !== 0) {
      fail(`exclusive artifact metadata is invalid: ${path}`);
    }
    writtenSnapshot = snapshotFromStat(path, stat, buffer);
  } finally {
    closeSync(fd);
  }
  assertDirectorySeal(parentPath, parent, "exclusive write");
  fsyncDirectory(parentPath, parent);
  const observed = realReadRegular(path);
  if (!observed.bytes.equals(buffer) || !same(observed.snapshot, writtenSnapshot)) {
    fail(`exclusive artifact readback failed: ${path}`);
  }
  return observed;
}

function realPublishExclusive(path, bytes, mode) {
  const parentPath = dirname(path);
  const parent = allowedCreateParent(path);
  const pendingPath = join(
    parentPath,
    `.${basename(path)}.${process.pid}.${randomBytes(12).toString("hex")}.pending`,
  );
  const pending = realWriteExclusive(pendingPath, bytes, mode);
  return publishPreparedExclusive({ parent, path, pending, pendingPath });
}

function publishPreparedExclusive({ parent, path, pending, pendingPath }) {
  const parentPath = dirname(path);
  if (dirname(pendingPath) !== parentPath) {
    fail("exclusive publication pending path must share the final parent directory");
  }
  try {
    assertExactSnapshot(
      realReadRegular(pendingPath).snapshot,
      pending.snapshot,
      `immediate publication input ${pendingPath}`,
    );
    linkSync(pendingPath, path);
    fsyncDirectory(parentPath, parent);
    const pendingStat = lstatSync(pendingPath, { bigint: true, throwIfNoEntry: true });
    const publishedStat = lstatSync(path, { bigint: true, throwIfNoEntry: true });
    if (
      !pendingStat.isFile() ||
      !publishedStat.isFile() ||
      !sameInode(pendingStat, publishedStat) ||
      pendingStat.nlink !== 2n ||
      publishedStat.nlink !== 2n
    ) {
      fail(`published artifact did not expose the exact pending inode: ${path}`);
    }
    unlinkSync(pendingPath);
    fsyncDirectory(parentPath, parent);
    const final = realReadRegular(path);
    if (
      final.snapshot.nlink !== 1 ||
      final.snapshot.device !== pending.snapshot.device ||
      final.snapshot.inode !== pending.snapshot.inode ||
      final.snapshot.gid !== pending.snapshot.gid ||
      final.snapshot.mode !== pending.snapshot.mode ||
      final.snapshot.mtime_ns !== pending.snapshot.mtime_ns ||
      final.snapshot.sha256 !== pending.snapshot.sha256 ||
      final.snapshot.size !== pending.snapshot.size ||
      final.snapshot.uid !== pending.snapshot.uid
    ) {
      fail(`published artifact did not retain the exact prepared inode and bytes: ${path}`);
    }
    return final;
  } catch (error) {
    // The pending file is intentionally retained if publication is uncertain.
    // Its random name is not authoritative; the final name plus parent fsync is.
    error.pending_path = pendingPath;
    error.pending_snapshot = pending.snapshot;
    throw error;
  }
}

function realReplacePrepared({ expectedCurrent, pin, preparedPath, targetPath }) {
  if (dirname(preparedPath) !== dirname(targetPath)) {
    fail("prepared replacement must be on the exact target filesystem and parent directory");
  }
  const parentPath = dirname(targetPath);
  const parent = directorySeal(parentPath);
  const current = openPinnedDescriptor(
    expectedCurrent,
    MAX_FILE_BYTES,
    `replacement preimage ${targetPath}`,
  );
  let prepared;
  try {
    prepared = openContentPinnedDescriptor(
      preparedPath,
      pin,
      MAX_FILE_BYTES,
      `prepared replacement ${preparedPath}`,
    );
    if (prepared.snapshot.device !== current.snapshot.device) {
      fail(`prepared replacement is not on the target filesystem: ${preparedPath}`);
    }
    confirmBoundRegular(current, `immediate replacement preimage ${targetPath}`);
    confirmBoundRegular(prepared, `immediate prepared replacement ${preparedPath}`);
    renameSync(preparedPath, targetPath);
    const oldAfter = fstatSync(current.fd, { bigint: true });
    const preparedAfter = fstatSync(prepared.fd, { bigint: true });
    const targetAfter = lstatSync(targetPath, { bigint: true, throwIfNoEntry: true });
    if (
      !sameInode(current.before, oldAfter) ||
      oldAfter.nlink !== 0n ||
      oldAfter.size !== current.before.size ||
      oldAfter.mtimeNs !== current.before.mtimeNs ||
      !sameInode(prepared.before, preparedAfter) ||
      !sameInode(prepared.before, targetAfter) ||
      preparedAfter.nlink !== 1n ||
      targetAfter.nlink !== 1n ||
      preparedAfter.size !== prepared.before.size ||
      preparedAfter.mtimeNs !== prepared.before.mtimeNs
    ) {
      fail(`atomic replacement inode transition was not exact: ${targetPath}`);
    }
    fsyncDirectory(parentPath, parent);
    const installed = realReadRegular(targetPath);
    assertContentSnapshot(installed.snapshot, pin, `installed replacement ${targetPath}`);
    return installed;
  } finally {
    if (prepared !== undefined) closeSync(prepared.fd);
    closeSync(current.fd);
  }
}

function realRestoreFromBackup({ backupPath, pin, targetPath }) {
  const backup = openBoundRegular(backupPath, MAX_FILE_BYTES, `rollback backup ${backupPath}`);
  const parentPath = dirname(targetPath);
  const parent = directorySeal(parentPath);
  const pendingPath = join(
    parentPath,
    `.${basename(targetPath)}.${process.pid}.${randomBytes(12).toString("hex")}.rollback`,
  );
  let current;
  let pending;
  try {
    if (
      backup.snapshot.sha256 !== pin.sha256 ||
      backup.snapshot.size !== pin.size ||
      backup.snapshot.uid !== 0 ||
      backup.snapshot.gid !== 0 ||
      backup.snapshot.mode !== RECEIPT_MODE
    ) {
      fail(`rollback backup bytes or metadata drifted: ${backupPath}`);
    }
    realWriteExclusive(pendingPath, backup.bytes, pin.mode);
    pending = openContentPinnedDescriptor(
      pendingPath,
      pin,
      MAX_FILE_BYTES,
      `rollback replacement ${pendingPath}`,
    );
    current = openBoundRegular(targetPath, MAX_FILE_BYTES, `rollback target ${targetPath}`);
    if (
      pending.snapshot.device !== current.snapshot.device ||
      pending.snapshot.device !== parent.device
    ) {
      fail(`rollback temp is not on the target filesystem: ${pendingPath}`);
    }
    confirmBoundRegular(backup, `immediate rollback backup ${backupPath}`);
    confirmBoundRegular(current, `immediate rollback target ${targetPath}`);
    confirmBoundRegular(pending, `immediate rollback replacement ${pendingPath}`);
    renameSync(pendingPath, targetPath);
    const oldAfter = fstatSync(current.fd, { bigint: true });
    const pendingAfter = fstatSync(pending.fd, { bigint: true });
    const targetAfter = lstatSync(targetPath, { bigint: true, throwIfNoEntry: true });
    if (
      !sameInode(current.before, oldAfter) ||
      oldAfter.nlink !== 0n ||
      oldAfter.size !== current.before.size ||
      oldAfter.mtimeNs !== current.before.mtimeNs ||
      !sameInode(pending.before, pendingAfter) ||
      !sameInode(pending.before, targetAfter) ||
      pendingAfter.nlink !== 1n ||
      targetAfter.nlink !== 1n ||
      pendingAfter.size !== pending.before.size ||
      pendingAfter.mtimeNs !== pending.before.mtimeNs
    ) {
      fail(`atomic rollback inode transition was not exact: ${targetPath}`);
    }
    fsyncDirectory(parentPath, parent);
    const restored = realReadRegular(targetPath);
    assertContentSnapshot(restored.snapshot, pin, `restored rollback target ${targetPath}`);
    return restored;
  } finally {
    if (pending !== undefined) closeSync(pending.fd);
    if (current !== undefined) closeSync(current.fd);
    closeSync(backup.fd);
  }
}

function commandResult(argv, { captureStdout = false, input, maxBytes = MAX_FILE_BYTES, stdioExtra = [], timeoutMs = 10_000 } = {}) {
  const result = spawnSync(argv[0], argv.slice(1), {
    encoding: null,
    env: { LANG: "C", LC_ALL: "C", PATH: "/usr/sbin:/usr/bin:/sbin:/bin" },
    input,
    killSignal: "SIGKILL",
    maxBuffer: maxBytes,
    shell: false,
    stdio: [input === undefined ? "ignore" : "pipe", captureStdout ? "pipe" : "ignore", "pipe", ...stdioExtra],
    timeout: timeoutMs,
  });
  return {
    status: result.status ?? 255,
    stderr: result.stderr ?? Buffer.alloc(0),
    stdout: result.stdout ?? Buffer.alloc(0),
  };
}

function runPinnedBinary(
  pin,
  args,
  { captureStdout = true, input, maxBytes = MAX_FILE_BYTES, timeoutMs = 10_000 } = {},
) {
  const max = pin.path === CADDY_BINARY_PATH || pin.path === "/usr/bin/node" || pin.path === SETPRIV_PATH
    ? MAX_EXECUTABLE_BYTES
    : MAX_FILE_BYTES;
  const executable = openPinnedDescriptor(pin, max, `pinned executable ${pin.path}`);
  try {
    const result = commandResult(["/proc/self/fd/3", ...args], {
      captureStdout,
      input,
      maxBytes,
      stdioExtra: [executable.fd],
      timeoutMs,
    });
    confirmBoundRegular(executable, `post-run executable ${pin.path}`);
    return result;
  } finally {
    closeSync(executable.fd);
  }
}

function systemctlShowProperties(unitName, properties, { optionalEmpty = [] } = {}) {
  const result = commandResult([
    SYSTEMCTL_PATH,
    "show",
    unitName,
    "--no-pager",
    ...properties.map((property) => `--property=${property}`),
  ], { captureStdout: true, maxBytes: 256 * 1024 });
  if (result.status !== 0 || result.stderr.length !== 0) {
    fail(`systemctl show failed or wrote diagnostics for ${unitName}`);
  }
  const values = new Map();
  for (const line of result.stdout.toString("utf8").trimEnd().split("\n")) {
    const separator = line.indexOf("=");
    if (separator < 1) fail(`malformed systemctl show output for ${unitName}`);
    const key = line.slice(0, separator);
    if (values.has(key)) fail(`duplicate systemctl property ${key}`);
    values.set(key, line.slice(separator + 1));
  }
  for (const key of optionalEmpty) if (!values.has(key)) values.set(key, "");
  if (values.size !== properties.length || properties.some((key) => !values.has(key))) {
    fail(`systemctl show omitted a property for ${unitName}`);
  }
  return values;
}

function realUnitGeneration(unitName) {
  const values = systemctlShowProperties(unitName, [
    "ActiveEnterTimestampMonotonic",
    "ActiveState",
    "ControlGroup",
    "InvocationID",
    "MainPID",
    "SubState",
  ]);
  const active = values.get("ActiveState") === "active";
  const rawInvocation = values.get("InvocationID");
  const invocation = active
    ? rawInvocation
    : rawInvocation === "0".repeat(32) ? "" : rawInvocation;
  return {
    active_enter_timestamp_monotonic: active
      ? values.get("ActiveEnterTimestampMonotonic")
      : "0",
    active_state: values.get("ActiveState"),
    control_group: values.get("ControlGroup"),
    invocation_id: invocation,
    main_pid: values.get("MainPID"),
    sub_state: values.get("SubState"),
    unit_name: unitName,
  };
}

function assertFilesystemPathAbsent(path, label) {
  try {
    lstatSync(path);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  fail(`${label} exists at ${path}`);
}

function realPublisherNetnsPreimage() {
  const generationBefore = realUnitGeneration(PUBLISHER_NETNS_UNIT);
  const before = {
    activation_sentinels_absent: [...PUBLISHER_NETNS_SENTINEL_PATHS],
    host_interface_absent: PUBLISHER_NETNS_HOST_INTERFACE_PATH,
    namespace_path_absent: PUBLISHER_NETNS_NAMESPACE_PATH,
    unit_generation: generationBefore,
  };
  validatePublisherNetnsPreimage(before, "observed publisher namespace preimage");
  assertFilesystemPathAbsent(
    PUBLISHER_NETNS_NAMESPACE_PATH,
    "publisher namespace path",
  );
  assertFilesystemPathAbsent(
    PUBLISHER_NETNS_HOST_INTERFACE_PATH,
    "publisher namespace host veth",
  );
  for (const path of PUBLISHER_NETNS_SENTINEL_PATHS) {
    assertFilesystemPathAbsent(path, "publisher activation sentinel");
  }
  const generationAfter = realUnitGeneration(PUBLISHER_NETNS_UNIT);
  if (!same(generationAfter, generationBefore)) {
    fail("publisher namespace unit generation changed while proving inactive absence");
  }
  return before;
}

function splitSystemdWords(value, label) {
  if (value === "") return [];
  if (!/^[A-Za-z0-9_./:@+-]+(?:[\t ]+[A-Za-z0-9_./:@+-]+)*$/u.test(value)) {
    fail(`${label} contains an unreviewed systemd word serialization`);
  }
  return value.split(/[\t ]+/u).sort();
}

function environmentNames(value, label) {
  if (value === "") return [];
  const names = [];
  for (const assignment of value.split(/[\t ]+/u)) {
    const match = /^([A-Za-z_][A-Za-z0-9_]*)=/u.exec(assignment);
    if (match === null || names.includes(match[1])) {
      fail(`${label} contains a malformed or duplicate environment assignment`);
    }
    names.push(match[1]);
  }
  return names.sort();
}

function extractSystemdExec(value, label) {
  const records = [...value.matchAll(/\{[^{}]*\}/gu)];
  if (records.length !== 1 || records[0][0] !== value.trim()) {
    fail(`${label} must contain exactly one command`);
  }
  const record = records[0][0];
  const path = /(?:^\{[\t ]*|[\t ]*;[\t ]*)path=([^ ;]+)[\t ]*;/u.exec(record)?.[1];
  const argv = /(?:^\{[\t ]*|[\t ]*;[\t ]*)argv\[\]=(.+?)[\t ]*;[\t ]*ignore_errors=/u.exec(record)?.[1]?.trim();
  const ignoreErrors = /(?:^\{[\t ]*|[\t ]*;[\t ]*)ignore_errors=(yes|no)[\t ]*;/u.exec(record)?.[1];
  if (path === undefined || argv === undefined || ignoreErrors !== "no") {
    fail(`${label} has an unreviewed systemd Exec serialization`);
  }
  return { argv, ignore_errors: ignoreErrors, path };
}

const PREIMAGE_EFFECTIVE_UNIT_PROPERTIES = Object.freeze([
  "After",
  "BindsTo",
  "DropInPaths",
  "EnvironmentFiles",
  "ExecReload",
  "ExecStart",
  "FragmentPath",
  "NeedDaemonReload",
  "PartOf",
  "PassEnvironment",
  "Requires",
  "Wants",
]);

function publisherNetnsDependencyFromSystemd(values, label) {
  const words = (property) => splitSystemdWords(
    values.get(property),
    `${label} ${property}`,
  );
  const relation = (property) => words(property).includes(PUBLISHER_NETNS_UNIT);
  return {
    after_namespace_owner: relation("After"),
    binds_to_namespace_owner: relation("BindsTo"),
    dropin_paths: words("DropInPaths"),
    need_daemon_reload: values.get("NeedDaemonReload"),
    part_of_namespace_owner: relation("PartOf"),
    requires_namespace_owner: relation("Requires"),
    wants_namespace_owner: relation("Wants"),
  };
}

function normalizePreimageEffectiveUnitProperties(values) {
  return {
    dropin_paths: splitSystemdWords(values.get("DropInPaths"), "preimage DropInPaths"),
    environment_files: splitSystemdWords(
      values.get("EnvironmentFiles"),
      "preimage EnvironmentFiles",
    ),
    exec_reload: extractSystemdExec(values.get("ExecReload"), "preimage ExecReload"),
    exec_start: extractSystemdExec(values.get("ExecStart"), "preimage ExecStart"),
    fragment_path: values.get("FragmentPath"),
    need_daemon_reload: values.get("NeedDaemonReload"),
    pass_environment: splitSystemdWords(
      values.get("PassEnvironment"),
      "preimage PassEnvironment",
    ),
    publisher_netns_dependency: publisherNetnsDependencyFromSystemd(
      values,
      "preimage",
    ),
  };
}

function realPreimageEffectiveUnit(unitName) {
  const values = systemctlShowProperties(unitName, PREIMAGE_EFFECTIVE_UNIT_PROPERTIES, {
    optionalEmpty: ["EnvironmentFiles"],
  });
  return normalizePreimageEffectiveUnitProperties(values);
}

function realEffectiveUnit(unitName) {
  const properties = [
    "After",
    "BindsTo",
    "DropInPaths",
    "Environment",
    "EnvironmentFiles",
    "ExecReload",
    "ExecStart",
    "FragmentPath",
    "Group",
    "LimitCORE",
    "MemorySwapMax",
    "NeedDaemonReload",
    "PartOf",
    "PassEnvironment",
    "Requires",
    "RuntimeDirectory",
    "RuntimeDirectoryMode",
    "RuntimeDirectoryPreserve",
    "StandardError",
    "StandardOutput",
    "UMask",
    "UnsetEnvironment",
    "User",
    "Wants",
  ];
  const values = systemctlShowProperties(unitName, properties, {
    optionalEmpty: ["EnvironmentFiles"],
  });
  if (
    canonicalJson(splitSystemdWords(values.get("DropInPaths"), "DropInPaths")) !==
      canonicalJson([PUBLISHER_NETNS_DROPIN_PATH]) ||
    values.get("EnvironmentFiles") !== "" ||
    values.get("PassEnvironment") !== ""
  ) {
    fail("effective Caddy unit has an unreviewed drop-in, EnvironmentFile or PassEnvironment");
  }
  const start = extractSystemdExec(values.get("ExecStart"), "effective ExecStart");
  const reload = extractSystemdExec(values.get("ExecReload"), "effective ExecReload");
  const expectedStart = `${CADDY_BINARY_PATH} run --config ${TARGET_CONFIG} --adapter caddyfile`;
  const expectedReload = `${CADDY_BINARY_PATH} reload --config ${TARGET_CONFIG} --adapter caddyfile --address ${ADMIN_DIAL}`;
  if (
    start.path !== CADDY_BINARY_PATH ||
    start.argv !== expectedStart ||
    reload.path !== CADDY_BINARY_PATH ||
    reload.argv !== expectedReload
  ) {
    fail("effective Caddy ExecStart/ExecReload drifted from the exact hardened unit");
  }
  const runtimeDirectories = splitSystemdWords(values.get("RuntimeDirectory"), "RuntimeDirectory");
  const unset = splitSystemdWords(values.get("UnsetEnvironment"), "UnsetEnvironment");
  if (!same(runtimeDirectories, ["bitcoinpir-caddy-admin"]) || !same(unset, ["CADDY_ADMIN"])) {
    fail("effective Caddy runtime directory or UnsetEnvironment drifted");
  }
  return {
    dropin_paths: [PUBLISHER_NETNS_DROPIN_PATH],
    effective_environment_names: environmentNames(values.get("Environment"), "Environment"),
    fragment_path: values.get("FragmentPath"),
    need_daemon_reload: values.get("NeedDaemonReload"),
    properties: {
      Group: values.get("Group"),
      LimitCORE: values.get("LimitCORE"),
      MemorySwapMax: values.get("MemorySwapMax"),
      RuntimeDirectory: runtimeDirectories[0],
      RuntimeDirectoryMode: values.get("RuntimeDirectoryMode"),
      RuntimeDirectoryPreserve: values.get("RuntimeDirectoryPreserve"),
      StandardError: values.get("StandardError"),
      StandardOutput: values.get("StandardOutput"),
      UMask: values.get("UMask"),
      UnsetEnvironment: unset,
      User: values.get("User"),
    },
    publisher_netns_dependency: publisherNetnsDependencyFromSystemd(
      values,
      "effective",
    ),
  };
}

function processStartTicks(pid) {
  const text = readFileSync(`/proc/${pid}/stat`, "utf8");
  const close = text.lastIndexOf(")");
  if (close < 1) fail(`malformed /proc/${pid}/stat`);
  const fields = text.slice(close + 2).trim().split(" ");
  const value = fields[19];
  if (!/^[1-9][0-9]*$/u.test(value ?? "")) fail(`invalid /proc/${pid}/stat start time`);
  return value;
}

function nulFields(bytes, label, maxBytes) {
  if (bytes.length < 1 || bytes.length > maxBytes || bytes[bytes.length - 1] !== 0) {
    fail(`${label} must be one bounded NUL-terminated vector`);
  }
  const result = [];
  let start = 0;
  for (let index = 0; index < bytes.length; index += 1) {
    if (bytes[index] !== 0) continue;
    if (index === start) fail(`${label} contains an empty member`);
    result.push(bytes.subarray(start, index));
    start = index + 1;
  }
  return result;
}

function canonicalProcArgv(pid, label) {
  return nulFields(
    readFileSync(`/proc/${pid}/cmdline`),
    `${label} /proc/${pid}/cmdline`,
    64 * 1024,
  ).map((field) => {
    const value = field.toString("utf8");
    if (!Buffer.from(value, "utf8").equals(field) || !/^[\x20-\x7e]+$/u.test(value)) {
      fail(`${label} cmdline contains a non-canonical argument`);
    }
    return value;
  });
}

function readProcExecutableSnapshot(pid, normalizedPath) {
  const procPath = `/proc/${pid}/exe`;
  const linkBefore = readlinkSync(procPath);
  const fd = openSync(procPath, constants.O_RDONLY | constants.O_CLOEXEC);
  try {
    const before = fstatSync(fd, { bigint: true });
    if (
      !before.isFile() ||
      before.nlink !== 1n ||
      before.size < 1n ||
      before.size > BigInt(MAX_EXECUTABLE_BYTES)
    ) {
      fail(`${procPath} is not one bounded single-link executable`);
    }
    const bytes = readFileSync(fd);
    const after = fstatSync(fd, { bigint: true });
    const linkAfter = readlinkSync(procPath);
    if (!sameStableStat(before, after) || linkAfter !== linkBefore) {
      fail(`${procPath} changed during descriptor-bound executable read`);
    }
    return {
      path: linkBefore,
      snapshot: snapshotFromStat(normalizedPath, before, bytes),
    };
  } finally {
    closeSync(fd);
  }
}

function realProcessRuntime(pid) {
  if (typeof pid !== "string" || !/^[1-9][0-9]*$/u.test(pid)) {
    fail("Caddy MainPID is not a positive canonical decimal");
  }
  const startTimeTicks = processStartTicks(Number(pid));
  const cmdlineArgv = canonicalProcArgv(pid, "Caddy");
  const effectiveEnvironmentNames = [];
  for (const field of nulFields(
    readFileSync(`/proc/${pid}/environ`),
    `Caddy /proc/${pid}/environ`,
    1024 * 1024,
  )) {
    const separator = field.indexOf(0x3d);
    if (separator < 1) fail("Caddy environment contains a malformed assignment");
    const nameBytes = field.subarray(0, separator);
    const name = nameBytes.toString("ascii");
    if (!Buffer.from(name, "ascii").equals(nameBytes) || !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name)) {
      fail("Caddy environment contains a non-canonical name");
    }
    if (effectiveEnvironmentNames.includes(name)) fail("Caddy environment contains a duplicate name");
    effectiveEnvironmentNames.push(name);
  }
  effectiveEnvironmentNames.sort();
  const executable = readProcExecutableSnapshot(pid, CADDY_BINARY_PATH);
  if (processStartTicks(Number(pid)) !== startTimeTicks) {
    fail(`Caddy PID ${pid} changed generation during runtime inspection`);
  }
  return {
    caddy_admin_environment_absent: !effectiveEnvironmentNames.includes("CADDY_ADMIN"),
    cmdline_argv: cmdlineArgv,
    effective_environment_names: effectiveEnvironmentNames,
    exe_path: executable.path,
    exe_snapshot: executable.snapshot,
    main_pid: pid,
    start_time_ticks: startTimeTicks,
  };
}

function realSelfIdentity() {
  const executorPath = fileURLToPath(import.meta.url);
  const node = readProcExecutableSnapshot("self", "/usr/bin/node");
  const nodeControlEnvironmentNames = Object.keys(process.env).filter(
    (name) =>
      name === "NODE" ||
      name.startsWith("NODE_") ||
      name.startsWith("LD_") ||
      name.startsWith("DYLD_") ||
      ["OPENSSL_CONF", "SSL_CERT_DIR", "SSL_CERT_FILE"].includes(name),
  ).sort();
  return {
    executor_path: executorPath,
    executor_snapshot: realReadRegular(executorPath).snapshot,
    node_cmdline_argv: canonicalProcArgv("self", "Node"),
    node_control_environment_names: nodeControlEnvironmentNames,
    node_exec_argv: [...process.execArgv],
    node_proc_exe_path: node.path,
    node_proc_exe_snapshot: node.snapshot,
    node_process_argv: [...process.argv],
    node_process_exec_path: process.execPath,
    node_version: process.version,
  };
}

function realAdminRuntimePath(path) {
  if (![ADMIN_DIRECTORY, ADMIN_SOCKET].includes(path)) fail(`unreviewed runtime path ${path}`);
  const stat = lstatSync(path, { bigint: true, throwIfNoEntry: true });
  const type = stat.isDirectory() ? "directory" : stat.isSocket() ? "socket" : "other";
  return {
    gid: Number(stat.gid),
    mode: modeString(stat),
    path,
    type,
    uid: Number(stat.uid),
  };
}

function boundedHttpRequest(options, { expectedLeafSha256 } = {}) {
  return new Promise((resolvePromise, rejectPromise) => {
    const request = options.protocol === "https:" ? httpsRequest : httpRequest;
    let done = false;
    let probe;
    const finish = (error, value) => {
      if (done) return;
      done = true;
      clearTimeout(wallTimer);
      if (error === undefined) resolvePromise(value);
      else rejectPromise(error);
    };
    const wallTimer = setTimeout(() => {
      const error = new Error("HTTP probe exceeded its absolute wall-clock bound");
      probe?.destroy(error);
      finish(error);
    }, 6_000);
    try {
      probe = request({ ...options, timeout: 5_000 }, (response) => {
        const chunks = [];
        let length = 0;
        response.on("data", (chunk) => {
          length += chunk.length;
          if (length > MAX_HTTP_BODY_BYTES) {
            const error = new Error("HTTP probe body exceeded the reviewed bound");
            response.destroy(error);
            finish(error);
            return;
          }
          chunks.push(chunk);
        });
        response.once("aborted", () => finish(new Error("HTTP probe response was aborted")));
        response.once("error", (error) => finish(error));
        response.once("close", () => {
          if (!response.complete) finish(new Error("HTTP probe response closed before completion"));
        });
        response.on("end", () => {
          try {
            if (!response.complete) fail("HTTP probe ended before a complete response was parsed");
            if (expectedLeafSha256 !== undefined) {
              const certificate = response.socket.getPeerCertificate?.(true);
              const raw = certificate?.raw;
              if (!Buffer.isBuffer(raw) || sha256(raw) !== expectedLeafSha256) {
                fail("HTTPS leaf certificate did not match the approved SHA-256");
              }
            }
            finish(undefined, { body: Buffer.concat(chunks), status: response.statusCode });
          } catch (error) {
            finish(error);
          }
        });
      });
    } catch (error) {
      finish(error);
      return;
    }
    probe.on("timeout", () => {
      const error = new Error("HTTP probe timed out");
      probe.destroy(error);
      finish(error);
    });
    probe.on("error", (error) => finish(error));
    probe.end();
  });
}

async function realSiteProbe(probe) {
  if (probe.kind === "tls-handshake") {
    await new Promise((resolvePromise, rejectPromise) => {
      const socket = tls.connect({
        host: probe.address,
        port: probe.port,
        rejectUnauthorized: true,
        servername: probe.server_name,
      });
      const timer = setTimeout(() => socket.destroy(new Error("TLS probe timed out")), 5_000);
      socket.once("secureConnect", () => {
        clearTimeout(timer);
        const certificate = socket.getPeerCertificate(true);
        if (!Buffer.isBuffer(certificate?.raw) || sha256(certificate.raw) !== probe.expected_leaf_sha256) {
          socket.destroy();
          rejectPromise(new Error(`TLS probe ${probe.id} leaf SHA-256 drifted`));
          return;
        }
        socket.end();
        resolvePromise();
      });
      socket.once("error", (error) => {
        clearTimeout(timer);
        rejectPromise(error);
      });
    });
    return { id: probe.id, result: "passed" };
  }
  const result = probe.kind === "public-https"
    ? await boundedHttpRequest({
        hostname: probe.hostname,
        method: "GET",
        path: probe.path,
        port: probe.port,
        protocol: "https:",
        servername: probe.hostname,
      }, { expectedLeafSha256: probe.expected_leaf_sha256 })
    : await boundedHttpRequest({
        headers: { Host: probe.host_header },
        hostname: probe.address,
        method: "GET",
        path: probe.path,
        port: probe.port,
        protocol: "http:",
      });
  if (result.status !== probe.expected_status || sha256(result.body) !== probe.expected_body_sha256) {
    fail(`site probe ${probe.id} response drifted from its approved status/body`);
  }
  return { id: probe.id, result: "passed" };
}

function validateLegacyAdminAdaptedJson(adapted) {
  if (adapted.admin === undefined) {
    validateAdaptedCaddyPrivacyPolicy(adapted);
  } else {
    validateAdaptedCaddyPrivacy(adapted, "127.0.0.1:2019");
  }
  return true;
}

function legacyAdminProbe() {
  return new Promise((resolvePromise, rejectPromise) => {
    let done = false;
    let probe;
    const finish = (error, value) => {
      if (done) return;
      done = true;
      clearTimeout(wallTimer);
      if (error === undefined) resolvePromise(value);
      else rejectPromise(error);
    };
    const wallTimer = setTimeout(() => {
      const error = new Error("legacy admin probe exceeded its absolute wall-clock bound");
      probe?.destroy(error);
      finish(error);
    }, 4_000);
    try {
      probe = httpRequest({
        host: "127.0.0.1",
        method: "GET",
        path: "/config/",
        port: 2019,
        timeout: 3_000,
      }, (response) => {
        const chunks = [];
        let length = 0;
        response.on("data", (chunk) => {
          length += chunk.length;
          if (length > MAX_HTTP_BODY_BYTES) {
            const error = new Error("legacy admin response exceeded the reviewed bound");
            response.destroy(error);
            finish(error);
            return;
          }
          chunks.push(chunk);
        });
        response.once("aborted", () => finish(new Error("legacy admin response was aborted")));
        response.once("error", (error) => finish(error));
        response.once("close", () => {
          if (!response.complete) finish(new Error("legacy admin response closed before completion"));
        });
        response.on("end", () => {
          try {
            if (!response.complete) fail("legacy admin ended before a complete response was parsed");
            if (response.statusCode !== 200) {
              fail(`legacy admin returned status ${response.statusCode}`);
            }
            const body = Buffer.concat(chunks);
            const adapted = parseStrictJson(body.toString("utf8"), "legacy admin readback");
            validateLegacyAdminAdaptedJson(adapted);
            const canonical = Buffer.from(canonicalJson(adapted), "utf8");
            finish(undefined, {
              body_sha256: sha256(canonical),
              listen: "127.0.0.1:2019",
              status: 200,
              transport: "tcp",
            });
          } catch (error) {
            finish(error);
          }
        });
      });
    } catch (error) {
      finish(error);
      return;
    }
    probe.on("timeout", () => {
      const error = new Error("legacy admin probe timed out");
      probe.destroy(error);
      finish(error);
    });
    probe.on("error", (error) => finish(error));
    probe.end();
  });
}

function tcpRefusal(endpoint) {
  const host = endpoint === "127.0.0.1:2019"
    ? "127.0.0.1"
    : endpoint === "[::1]:2019" ? "::1" : fail(`unreviewed TCP endpoint ${endpoint}`);
  return new Promise((resolvePromise, rejectPromise) => {
    let done = false;
    const socket = netConnect({ host, port: 2019 });
    const finish = (error) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      socket.destroy();
      if (error === undefined) resolvePromise({ endpoint, result: "connection-refused" });
      else rejectPromise(error);
    };
    const timer = setTimeout(() => finish(new Error(`TCP probe timed out for ${endpoint}`)), 3_000);
    socket.once("connect", () => finish(new Error(`TCP admin remained reachable at ${endpoint}`)));
    socket.once("error", (error) => {
      if (error?.code === "ECONNREFUSED") finish();
      else finish(new Error(`TCP probe ${endpoint} failed with ${error?.code ?? error.message}`));
    });
  });
}

async function realTcpAdminProbes() {
  return [
    await tcpRefusal("127.0.0.1:2019"),
    await tcpRefusal("[::1]:2019"),
  ];
}

function parseCanonicalProbeOutput(stdout, label) {
  if (!stdout.toString("utf8").endsWith("\n") || stdout.subarray(0, -1).includes(0x0a)) {
    fail(`${label} did not return one JSON line`);
  }
  const bytes = stdout.subarray(0, -1);
  const value = parseStrictJson(bytes.toString("utf8"), label);
  if (!bytes.equals(Buffer.from(canonicalJson(value), "utf8"))) {
    fail(`${label} output was not canonical JSON`);
  }
  return value;
}

function realPinnedAdminProbe({ expected, gid, label, plan, uid }) {
  if (!new Set(["EACCES", "root-readback"]).has(expected)) fail("unreviewed admin probe expectation");
  const pins = [
    [plan.runtime.gate, MAX_FILE_BYTES, "gate"],
    [plan.runtime.node_binary, MAX_EXECUTABLE_BYTES, "Node"],
    [plan.runtime.probe, MAX_FILE_BYTES, "probe"],
    [plan.runtime.setpriv_binary, MAX_EXECUTABLE_BYTES, "setpriv"],
  ];
  const files = [];
  try {
    for (const [pin, maxBytes, pinLabel] of pins) {
      files.push({
        ...openPinnedDescriptor(pin, maxBytes, `admin ${pinLabel}`),
        pin,
        pinLabel,
      });
    }
    const [gate, node, probe, setpriv] = files;
    const result = spawnSync("/proc/self/fd/6", [
      `--reuid=${uid}`,
      `--regid=${gid}`,
      "--clear-groups",
      "--no-new-privs",
      "--bounding-set=-all",
      "--inh-caps=-all",
      "--ambient-caps=-all",
      "/proc/self/fd/5",
      "/proc/self/fd/4",
    ], {
      encoding: null,
      env: {
        BPIR_ADMIN_GATE_SHA256: plan.runtime.gate.sha256,
        BPIR_ADMIN_PROBE_FORMAT: "json",
        BPIR_ADMIN_PROBE_LABEL: label,
        BPIR_EXPECT_ADMIN_PROBE: expected,
        LANG: "C",
        LC_ALL: "C",
        PATH: "/usr/sbin:/usr/bin:/sbin:/bin",
      },
      input: gate.bytes,
      killSignal: "SIGKILL",
      maxBuffer: MAX_HTTP_BODY_BYTES,
      shell: false,
      stdio: ["pipe", "pipe", "pipe", gate.fd, probe.fd, node.fd, setpriv.fd],
      timeout: 5_000,
    });
    for (const file of files) {
      confirmBoundRegular(file, `post-probe ${file.pinLabel}`);
    }
    if ((result.status ?? 255) !== 0) {
      fail(`admin probe ${label} failed: ${(result.stderr ?? Buffer.alloc(0)).toString("utf8").trim()}`);
    }
    return parseCanonicalProbeOutput(result.stdout ?? Buffer.alloc(0), `admin probe ${label}`);
  } finally {
    for (const file of files.reverse()) closeSync(file.fd);
  }
}

async function realCollectStoppedEvidence() {
  const unitJobIsAbsent = () => {
    const values = systemctlShowProperties(TARGET_UNIT, ["Job"], {
      optionalEmpty: ["Job"],
    });
    return values.get("Job") === "";
  };
  if (!unitJobIsAbsent()) fail("stopped evidence found a pending systemd unit job");
  const generationBefore = realUnitGeneration(TARGET_UNIT);
  const socketIsAbsent = () => {
    try {
      lstatSync(ADMIN_SOCKET, { bigint: true, throwIfNoEntry: true });
      return false;
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
      return true;
    }
  };
  if (!socketIsAbsent()) fail("stopped evidence found the admin socket before TCP probes");
  const tcpAdmin = await realTcpAdminProbes();
  const generationAfter = realUnitGeneration(TARGET_UNIT);
  if (!same(generationAfter, generationBefore) || !socketIsAbsent() || !unitJobIsAbsent()) {
    fail("stopped unit/socket/job state changed while collecting refusal evidence");
  }
  return {
    admin_socket_absent: true,
    tcp_admin: tcpAdmin,
    unit_generation: generationAfter,
    unit_job_absent: true,
  };
}

function realVerifyCandidate({ candidates, plan }) {
  const verifyDirectory = join(plan.transaction.state_directory, "verify");
  ensurePrivateDirectory(verifyDirectory);
  const verifyUnitPath = join(verifyDirectory, TARGET_UNIT);
  realWriteExclusive(verifyUnitPath, candidates.unit, "0600");
  const unitResult = commandResult([SYSTEMD_ANALYZE_PATH, "verify", verifyUnitPath], {
    captureStdout: true,
    maxBytes: MAX_FILE_BYTES,
    timeoutMs: 10_000,
  });
  if (unitResult.status !== 0) {
    fail(`systemd-analyze verify rejected the candidate unit: ${unitResult.stderr.toString("utf8").trim()}`);
  }
  const adapted = runPinnedBinary(
    plan.preimage.binary,
    ["adapt", "--config", plan.transaction.candidate_config_path, "--adapter", "caddyfile"],
    { captureStdout: true, maxBytes: MAX_HTTP_BODY_BYTES, timeoutMs: 10_000 },
  );
  if (adapted.status !== 0 || adapted.stderr.length !== 0) {
    fail(`plan-pinned Caddy adapter rejected the candidate: ${adapted.stderr.toString("utf8").trim()}`);
  }
  validateCandidateAdaptedJson({ adaptedJsonBytes: adapted.stdout, plan });
  return adapted.stdout;
}

function realVerifyPreimage({ configPreimageBytes, plan }) {
  const adapted = runPinnedBinary(
    plan.preimage.binary,
    ["adapt", "--config", "-", "--adapter", "caddyfile"],
    {
      captureStdout: true,
      input: Buffer.from(configPreimageBytes),
      maxBytes: MAX_HTTP_BODY_BYTES,
      timeoutMs: 10_000,
    },
  );
  if (adapted.status !== 0 || adapted.stderr.length !== 0) {
    fail(`plan-pinned Caddy adapter rejected the preimage: ${adapted.stderr.toString("utf8").trim()}`);
  }
  validatePreimageAdaptedJson({ adaptedJsonBytes: adapted.stdout, plan });
  return adapted.stdout;
}

function lockOwner(transactionId) {
  return {
    boot_id: readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim(),
    pid: process.pid,
    process_start_ticks: processStartTicks(process.pid),
    transaction_id: `bhtm-caddy-admin-uds:${transactionId}`,
  };
}

function realAcquireLock(path, { transactionId }) {
  if (path !== PUBLISHER_NETNS_LIFECYCLE_LOCK) {
    fail("transaction lock path is not reviewed");
  }
  const parentPath = dirname(path);
  const parent = directorySeal(parentPath);
  try {
    mkdirSync(path, { mode: 0o700 });
  } catch (error) {
    if (error?.code === "EEXIST") {
      fail("transaction lock is already held; explicit stale-lock review is required");
    }
    throw error;
  }
  const lockFd = openSync(
    path,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
  );
  fchownSync(lockFd, 0, 0);
  fchmodSync(lockFd, 0o700);
  fsyncSync(lockFd);
  closeSync(lockFd);
  fsyncDirectory(parentPath, parent);
  const lockSeal = directorySeal(path);
  if (lockSeal.uid !== 0 || lockSeal.gid !== 0 || lockSeal.mode !== "0700") {
    fail("transaction lock directory is not root:root 0700");
  }
  const owner = Buffer.from(canonicalJson(lockOwner(transactionId)), "utf8");
  const ownerPath = join(path, LOCK_OWNER_FILE);
  const ownerFd = openSync(
    ownerPath,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW | constants.O_CLOEXEC,
    0o400,
  );
  try {
    fchownSync(ownerFd, 0, 0);
    fchmodSync(ownerFd, 0o400);
    writeFileSync(ownerFd, owner);
    fsyncSync(ownerFd);
  } finally {
    closeSync(ownerFd);
  }
  fsyncDirectory(path, lockSeal);
  const ownerSnapshot = realReadRegular(ownerPath);
  return async () => {
    assertDirectorySeal(path, lockSeal, "lock release");
    const observed = realReadRegular(ownerPath);
    if (!observed.bytes.equals(owner) || !same(observed.snapshot, ownerSnapshot.snapshot)) {
      fail("transaction lock ownership changed before release");
    }
    unlinkSync(ownerPath);
    fsyncDirectory(path, lockSeal);
    rmdirSync(path);
    fsyncDirectory(parentPath, parent);
  };
}

async function bestEffortObservation(fn) {
  try {
    return { ok: true, value: await fn() };
  } catch (error) {
    return { error: error.message, ok: false };
  }
}

async function realRecoverySnapshot(plan) {
  return {
    admin_socket: await bestEffortObservation(async () => {
      const stat = lstatSync(ADMIN_SOCKET, { bigint: true, throwIfNoEntry: false });
      return stat === undefined
        ? { state: "absent" }
        : { gid: Number(stat.gid), mode: modeString(stat), state: stat.isSocket() ? "socket" : "other", uid: Number(stat.uid) };
    }),
    config: await bestEffortObservation(async () => realReadRegular(TARGET_CONFIG).snapshot),
    host: await bestEffortObservation(async () => ({
      boot_id: readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim(),
      hostname: osHostname(),
    })),
    receipt: await bestEffortObservation(async () => realReadOptionalRegular(plan.transaction.receipt_path)?.snapshot ?? { state: "absent" }),
    tcp_admin: await bestEffortObservation(async () => realTcpAdminProbes()),
    unit: await bestEffortObservation(async () => realReadRegular(TARGET_FRAGMENT).snapshot),
    unit_generation: await bestEffortObservation(async () => realUnitGeneration(TARGET_UNIT)),
  };
}

function realPublishState(directory, name, bytes, mode) {
  if (
    directory !== undefined &&
    (!directory.startsWith("/var/lib/bitcoinpir/payment-v1/bhtm-caddy-admin-uds/transactions/") ||
      !/^[0-9a-z.-]+\.json$/u.test(name))
  ) {
    fail("state publication path is outside the closed transaction directory");
  }
  ensurePrivateDirectory(directory);
  return realPublishExclusive(join(directory, name), bytes, mode);
}

export function parseSystemdVersionOutput(bytes) {
  const buffer = Buffer.from(bytes);
  const text = buffer.toString("utf8");
  if (
    buffer.length < 1 ||
    buffer.length > 64 * 1024 ||
    !Buffer.from(text, "utf8").equals(buffer) ||
    !text.endsWith("\n") ||
    /[\r\0]/u.test(text)
  ) {
    fail("systemctl --version output is not canonical bounded UTF-8 text");
  }
  const firstLine = text.slice(0, text.indexOf("\n"));
  const match = /^systemd ([0-9]+)(?: \([A-Za-z0-9.+:~_-]+\))?$/u.exec(firstLine);
  if (match === null) fail("systemctl --version did not identify systemd on its first line");
  return match[1];
}

function realHostPrerequisites() {
  const version = commandResult([SYSTEMCTL_PATH, "--version"], {
    captureStdout: true,
    maxBytes: 64 * 1024,
  });
  if (version.status !== 0 || version.stderr.length !== 0) {
    fail("systemctl --version failed or wrote diagnostics");
  }
  const systemdVersion = parseSystemdVersionOutput(version.stdout);
  const corePatternBytes = readFileSync(CORE_PATTERN_PATH);
  if (!corePatternBytes.equals(Buffer.from(`${corePatternBytes.toString("utf8").trim()}\n`, "utf8"))) {
    fail("kernel.core_pattern is not canonical single-line text");
  }
  return {
    core_pattern: corePatternBytes.toString("utf8").trim(),
    euid: process.geteuid?.() ?? -1,
    platform: process.platform,
    systemd_version: systemdVersion,
  };
}

export function linuxCaddyAdminUdsOps() {
  return {
    acquireLock: realAcquireLock,
    async binaryVersion(pin) {
      const result = runPinnedBinary(pin, ["version"]);
      if (result.status !== 0 || result.stderr.length !== 0) fail("Caddy version command failed");
      return result.stdout.toString("utf8").trim().split(/[\t ]+/u)[0];
    },
    collectStoppedEvidence: realCollectStoppedEvidence,
    hostIdentity: async () => ({
      boot_id: readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim(),
      hostname: osHostname(),
    }),
    hostPrerequisites: async () => realHostPrerequisites(),
    prepareArtifact: async (path, bytes, mode) => realWriteExclusive(path, bytes, mode),
    probeAdminApi: async (options) => realPinnedAdminProbe(options),
    probeLegacyAdmin: legacyAdminProbe,
    probeTcpAdmin: realTcpAdminProbes,
    publisherNetnsPreimage: async () => realPublisherNetnsPreimage(),
    publishReceipt: async (path, bytes, mode) => realPublishExclusive(path, bytes, mode),
    publishState: async (directory, name, bytes, mode) => realPublishState(directory, name, bytes, mode),
    readAdminRuntimePath: async (path) => realAdminRuntimePath(path),
    readEffectiveUnit: async (unitName) => realEffectiveUnit(unitName),
    readPreimageEffectiveUnit: async (unitName) => realPreimageEffectiveUnit(unitName),
    readProcessRuntime: async (pid) => realProcessRuntime(pid),
    readRegular: async (path) => realReadRegular(
      path,
      [CADDY_BINARY_PATH, "/usr/bin/node", SETPRIV_PATH].includes(path)
        ? MAX_EXECUTABLE_BYTES
        : MAX_FILE_BYTES,
    ),
    readUnitGeneration: async (unitName) => realUnitGeneration(unitName),
    recoverySnapshot: realRecoverySnapshot,
    replacePrepared: async (options) => realReplacePrepared(options),
    restoreFromBackup: async (options) => realRestoreFromBackup(options),
    selfIdentity: async () => realSelfIdentity(),
    async run(argv) {
      const allowed = new Set([
        canonicalJson([SYSTEMCTL_PATH, "stop", TARGET_UNIT]),
        canonicalJson([SYSTEMCTL_PATH, "start", TARGET_UNIT]),
        canonicalJson([SYSTEMCTL_PATH, "daemon-reload"]),
      ]);
      if (!allowed.has(canonicalJson(argv))) fail(`unreviewed systemctl command: ${argv.join(" ")}`);
      return commandResult(argv, { captureStdout: true, maxBytes: 256 * 1024, timeoutMs: 30_000 });
    },
    runSiteProbe: async (probe) => realSiteProbe(probe),
    verifyCandidate: async (options) => realVerifyCandidate(options),
    verifyPreimage: async (options) => realVerifyPreimage(options),
  };
}

export const CADDY_ADMIN_UDS_TEST_ONLY_IO = Object.freeze({
  boundedHttpRequest,
  normalizePreimageEffectiveUnitProperties(properties) {
    exactKeys(properties, PREIMAGE_EFFECTIVE_UNIT_PROPERTIES, "test preimage effective unit");
    return normalizePreimageEffectiveUnitProperties(new Map(Object.entries(properties)));
  },
  publishPreparedExclusive({ path, pendingPath }) {
    const parentPath = dirname(path);
    if (dirname(pendingPath) !== parentPath) fail("test publication paths must share a parent");
    return publishPreparedExclusive({
      parent: directorySeal(parentPath),
      path,
      pending: realReadRegular(pendingPath),
      pendingPath,
    });
  },
  readRegular: realReadRegular,
  replacePrepared: realReplacePrepared,
  runPinnedBinary,
  validateLegacyAdminAdaptedJson,
});

function usage() {
  return [
    "usage:",
    "  payment-v1-caddy-admin-uds-transaction.mjs execute --plan PLAN --site-inventory SITE_INVENTORY --approved-plan-sha256 SHA256",
    "",
    "The executor is local-host-only. It never uses SSH and never changes kernel.core_pattern.",
  ].join("\n");
}

function parseArguments(argv) {
  const args = [...argv];
  if (args.length === 1 && ["--help", "-h"].includes(args[0])) return { help: true };
  const [
    command,
    planFlag,
    planPath,
    inventoryFlag,
    siteInventoryPath,
    digestFlag,
    approvedPlanSha256,
  ] = args;
  if (
    args.length !== 7 ||
    command !== "execute" ||
    planFlag !== "--plan" ||
    inventoryFlag !== "--site-inventory" ||
    digestFlag !== "--approved-plan-sha256"
  ) {
    fail(usage());
  }
  return {
    approvedPlanSha256,
    planPath,
    siteInventoryPath,
  };
}

async function main(argv) {
  const options = parseArguments(argv);
  if (options.help) {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  for (const [path, label] of [
    [options.planPath, "plan"],
    [options.siteInventoryPath, "site inventory"],
  ]) {
    if (!isAbsolute(path) || resolve(path) !== path) {
      fail(`${label} path must be absolute and normalized`);
    }
  }
  const planFile = realReadRegular(options.planPath);
  const siteInventoryFile = realReadRegular(options.siteInventoryPath);
  const plan = parseStrictJson(planFile.bytes.toString("utf8"), "hardening plan");
  const result = await executeCaddyAdminUdsTransaction({
    approvedPlanSha256: options.approvedPlanSha256,
    ops: linuxCaddyAdminUdsOps(),
    plan,
    siteInventoryBytes: siteInventoryFile.bytes,
  });
  process.stdout.write(
    `${result.outcome} receipt=${plan.transaction.receipt_path} sha256=${result.receipt_sha256}\n`,
  );
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(
      `caddy-admin-uds-transaction=FAIL outcome=${error.outcome ?? "preflight-failed"} phase=${error.phase ?? "preflight"}: ${error.message}\n`,
    );
    if (error.result !== undefined) {
      process.stderr.write(`recovery_state=${canonicalJson(error.result)}\n`);
    }
    process.exitCode = 1;
  });
}
