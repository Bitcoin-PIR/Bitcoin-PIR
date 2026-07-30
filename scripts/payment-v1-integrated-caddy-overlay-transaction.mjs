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
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmdirSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import tls from "node:tls";
import { connect as netConnect } from "node:net";
import { basename, dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  OVERLAY_COLLECTOR,
  OVERLAY_RECEIPT_SCHEMA_VERSION,
  PUBLISHER_NETNS_DROPIN_PATH,
  buildOverlayCandidateFromRendered,
  canonicalJson,
  computeApprovedOverlayPlanSha256,
  parseStrictJson,
  validateOverlayPlan,
  validateOverlayPreparedContext,
  validateOverlayReceipt,
} from "./payment-v1-integrated-caddy-overlay-gate.mjs";
import {
  ADMIN_DIRECTORY,
  ADMIN_DIAL,
  ADMIN_LISTEN,
  ADMIN_SOCKET,
  DAC_BOUNDARY,
  canonicalJson as canonicalAdminUdsJson,
  canonicalizeAdaptedCaddyJson,
  computeApprovedPlanSha256 as computeApprovedAdminUdsPlanSha256,
  validateCommittedReceipt as validateAdminUdsCommittedReceipt,
  validatePublisherNetnsDropInBytes,
} from "./payment-v1-caddy-admin-uds-gate.mjs";
import {
  PUBLISHER_NETNS_CEREMONY_KIND,
  PUBLISHER_NETNS_RECEIPT_KIND,
  computePublisherNetnsPlanSha256V2,
  validatePublisherNetnsPlanV2,
  validatePublisherNetnsReceiptV2,
} from "./payment-v1-publisher-netns-schema.mjs";

const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024;
const MAX_COMMAND_BYTES = 8 * 1024 * 1024;
const TARGET_CONFIG = "/etc/caddy/Caddyfile";
const TARGET_UNIT = "bhtm-caddy.service";
const SOURCE_FAIR_UNIT = "bitcoinpir-payment-v1-source-fair-edge.service";
const PUBLISHER_NETNS_UNIT = "bitcoinpir-payment-v1-publisher-netns.service";
const PUBLISHER_UNIT = "bitcoinpir-payment-v1-directory-publisher.service";
const RENAME_EXCHANGE_HELPER =
  "/opt/bitcoinpir/payment-v1-rename-exchange/@OVERLAY_EXCHANGE_SHA256@/payment-v1-rename-exchange";
const RENAME_EXCHANGE_MANIFEST =
  "/etc/bitcoinpir/payment-v1/integrated-existing-bhtm-caddy/rename-exchange.sha256";
const LOCK_OWNER = "owner.json";
const LOCK_OWNER_PENDING = `${LOCK_OWNER}.pending`;
const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

export const OVERLAY_STATE_FILES = Object.freeze({
  aborted: "50-aborted-before-install.json",
  committed: "50-committed.json",
  exchanged: "10-exchanged.json",
  prepared: "00-prepared.json",
  reloaded: "20-reloaded.json",
  rollbackExchanged: "30-rollback-exchanged.json",
  rollbackReloaded: "40-rollback-reloaded.json",
  rolledBack: "50-rolled-back.json",
});

const PHASE_TO_FILE = Object.freeze({
  "aborted-before-install": OVERLAY_STATE_FILES.aborted,
  committed: OVERLAY_STATE_FILES.committed,
  exchanged: OVERLAY_STATE_FILES.exchanged,
  prepared: OVERLAY_STATE_FILES.prepared,
  reloaded: OVERLAY_STATE_FILES.reloaded,
  "rollback-exchanged": OVERLAY_STATE_FILES.rollbackExchanged,
  "rollback-reloaded": OVERLAY_STATE_FILES.rollbackReloaded,
  "rolled-back": OVERLAY_STATE_FILES.rolledBack,
});

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function fail(message) {
  throw new Error(message);
}

function same(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function exactKeys(value, expected, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail(`${label} keys drifted`);
  }
}

function exactRegularSnapshot(actual, expected, label) {
  if (!same(actual, expected)) fail(`${label} drifted from the approved regular-file pin`);
}

function exactGeneration(actual, expected, label) {
  if (!same(actual, expected)) fail(`${label} process generation drifted`);
}

function expectedCaddyEffectiveUnit(plan, environmentNames) {
  const binary = plan.target.binary.path;
  return {
    dropin_paths: [PUBLISHER_NETNS_DROPIN_PATH],
    environment_names: environmentNames,
    environment_files: [],
    exec_reload: {
      argv: `${binary} reload --config ${TARGET_CONFIG} --adapter caddyfile --address ${ADMIN_DIAL}`,
      ignore_errors: "no",
      path: binary,
    },
    exec_start: {
      argv: `${binary} run --config ${TARGET_CONFIG} --adapter caddyfile`,
      ignore_errors: "no",
      path: binary,
    },
    fragment_path: plan.target.unit_fragment.path,
    group: "root",
    limit_core: "0",
    memory_swap_max: "0",
    need_daemon_reload: "no",
    pass_environment: [],
    publisher_netns_dependency: {
      after_namespace_owner: true,
      binds_to_namespace_owner: false,
      dropin_paths: [PUBLISHER_NETNS_DROPIN_PATH],
      need_daemon_reload: "no",
      part_of_namespace_owner: false,
      requires_namespace_owner: false,
      wants_namespace_owner: true,
    },
    runtime_directory: ["bitcoinpir-caddy-admin"],
    runtime_directory_mode: "0700",
    runtime_directory_preserve: "no",
    standard_error: "null",
    standard_output: "null",
    umask: "0077",
    unset_environment: ["CADDY_ADMIN"],
    user: "root",
  };
}

function assertEffectiveUnit(actual, plan, hardening, label) {
  const environmentNames = [...hardening.receipt.activation.effective_environment_names].sort();
  if (
    environmentNames.includes("CADDY_ADMIN") ||
    environmentNames.some(
      (name, index) =>
        typeof name !== "string" ||
        !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name) ||
        (index > 0 && environmentNames[index - 1] === name),
    )
  ) {
    fail(`${label} approved effective Environment name inventory is malformed`);
  }
  if (!same(actual, expectedCaddyEffectiveUnit(plan, environmentNames))) {
    fail(`${label} current effective systemd unit drifted from the exact hardened profile`);
  }
}

function assertCaddyProcessRuntime(actual, plan, label) {
  exactKeys(
    actual,
    [
      "caddy_admin_environment_absent",
      "cmdline_argv",
      "effective_environment_names",
      "main_pid",
      "start_time_ticks",
    ],
    label,
  );
  const expectedArgv = [
    plan.target.binary.path,
    "run",
    "--config",
    TARGET_CONFIG,
    "--adapter",
    "caddyfile",
  ];
  if (
    actual.caddy_admin_environment_absent !== true ||
    actual.main_pid !== plan.target.unit_generation.main_pid ||
    !/^[1-9][0-9]*$/u.test(actual.start_time_ticks ?? "") ||
    !same(actual.cmdline_argv, expectedArgv) ||
    !Array.isArray(actual.effective_environment_names) ||
    actual.effective_environment_names.length > 512 ||
    actual.effective_environment_names.some(
      (name, index, names) =>
        typeof name !== "string" ||
        !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name) ||
        (index > 0 && names[index - 1] >= name),
    ) ||
    actual.effective_environment_names.includes("CADDY_ADMIN")
  ) {
    fail(`${label} current /proc identity, argv or environment drifted from the hardened generation`);
  }
}

function assertCaddyRuntimeBoundary(value, plan, hardening, label) {
  exactKeys(
    value,
    ["boot_id", "effective_unit", "process", "unit_generation"],
    label,
  );
  if (
    value.boot_id !== hardening.receipt.host.boot_id ||
    value.boot_id !== hardening.hardeningPlan.privileged_access_inventory.boot_id
  ) {
    fail(`${label} boot drifted from the approved privileged access evidence`);
  }
  exactGeneration(value.unit_generation, plan.target.unit_generation, `${label} Caddy`);
  assertEffectiveUnit(value.effective_unit, plan, hardening, `${label} effective unit`);
  assertCaddyProcessRuntime(value.process, plan, `${label} process`);
}

async function readCaddyRuntimeBoundary(plan, hardening, ops, label) {
  const host = await ops.hostIdentity();
  const unitGeneration = await ops.readUnitGeneration(TARGET_UNIT);
  const effectiveUnit = await ops.readEffectiveUnit(TARGET_UNIT);
  const process = await ops.readProcessRuntime(unitGeneration.main_pid);
  const value = {
    boot_id: host.boot_id,
    effective_unit: effectiveUnit,
    process,
    unit_generation: unitGeneration,
  };
  assertCaddyRuntimeBoundary(value, plan, hardening, label);
  return value;
}

async function collectStableCaddyRuntimeBoundary(plan, hardening, ops, label) {
  const before = await readCaddyRuntimeBoundary(plan, hardening, ops, `${label} before`);
  const after = await readCaddyRuntimeBoundary(plan, hardening, ops, `${label} after`);
  if (!same(after, before)) fail(`${label} Caddy runtime changed across the action boundary`);
  return before;
}

function assertRuntimePath(actual, expected, label) {
  if (!same(actual, expected)) fail(`${label} runtime path drifted`);
}

function assertFinalConfig(snapshot, digest, label) {
  if (
    snapshot.path !== TARGET_CONFIG ||
    snapshot.sha256 !== digest ||
    snapshot.uid !== 0 ||
    snapshot.gid !== 0 ||
    snapshot.mode !== "0644" ||
    snapshot.nlink !== 1
  ) {
    fail(`${label} is not the exact root-owned single-link Caddyfile generation`);
  }
}

function assertExchangeIdentity(actual, expected, path, label) {
  const keys = [
    "device",
    "gid",
    "inode",
    "mode",
    "mtime_ns",
    "nlink",
    "sha256",
    "size",
    "uid",
  ];
  if (actual.path !== path || keys.some((key) => actual[key] !== expected[key])) {
    fail(`${label} does not contain the exact exchanged inode and bytes`);
  }
}

function assertManifest(manifestBytes, helperPin) {
  const expected = Buffer.from(`${helperPin.sha256}  ${helperPin.path}\n`, "utf8");
  if (!Buffer.from(manifestBytes).equals(expected)) {
    fail("rename-exchange manifest does not bind only the exact plan-pinned helper");
  }
}

function parseCanonicalAdminUdsEvidence(bytes, label) {
  const buffer = Buffer.from(bytes);
  const value = parseStrictJson(buffer.toString("utf8"), label);
  if (!buffer.equals(Buffer.from(canonicalAdminUdsJson(value), "utf8"))) {
    fail(`${label} bytes must equal their canonical JSON encoding`);
  }
  return value;
}

function assertAdminUdsHardeningEvidence(
  planBytes,
  receiptBytes,
  summary,
  adminProbePin,
  adminGatePin,
  nodePin,
) {
  const hardeningPlan = parseCanonicalAdminUdsEvidence(planBytes, "Caddy admin UDS plan");
  const receipt = parseCanonicalAdminUdsEvidence(receiptBytes, "Caddy admin UDS receipt");
  if (computeApprovedAdminUdsPlanSha256(hardeningPlan) !== summary.approved_plan_sha256) {
    fail("Caddy admin UDS plan does not equal its externally approved digest");
  }
  validateAdminUdsCommittedReceipt({
    approvedPlanSha256: summary.approved_plan_sha256,
    plan: hardeningPlan,
    receipt,
    trustedReceiptSha256: summary.receipt.sha256,
  });
  if (hardeningPlan.transaction_id !== summary.transaction_id) {
    fail("Caddy admin UDS evidence transaction ID does not equal the overlay summary");
  }
  if (
    hardeningPlan.schema_version !== summary.plan_schema_version ||
    receipt.schema_version !== summary.receipt_schema_version ||
    hardeningPlan.publisher_netns_dropin.sha256 !==
      summary.publisher_netns_dropin_sha256 ||
    receipt.publisher_netns_dropin.sha256 !==
      summary.publisher_netns_dropin_sha256
  ) {
    fail("Caddy admin UDS evidence does not bind the exact schema-v2 publisher drop-in");
  }
  if (!same(hardeningPlan.runtime.probe, adminProbePin)) {
    fail("overlay admin probe does not equal the exact approved hardening probe generation");
  }
  if (!same(hardeningPlan.runtime.gate, adminGatePin)) {
    fail("overlay admin UDS gate does not equal the exact approved hardening gate generation");
  }
  if (hardeningPlan.runtime.node_binary.sha256 !== nodePin.sha256) {
    fail("overlay Node binary does not equal the approved hardening Node digest");
  }
  if (
    hardeningPlan.runtime.setpriv_binary.sha256 !== summary.setpriv_binary_sha256
  ) {
    fail("overlay setpriv pin does not equal the approved hardening setpriv binary");
  }
  if (
    sha256(Buffer.from(canonicalAdminUdsJson(hardeningPlan.service_uid_inventory), "utf8")) !==
    summary.service_uid_inventory_sha256
  ) {
    fail("overlay service UID inventory digest does not equal the complete hardening inventory");
  }
  for (const [key, expected] of [
    [hardeningPlan.candidate.adapted_json_sha256, summary.adapted_json_sha256],
    [hardeningPlan.candidate.binary.sha256, summary.binary_sha256],
    [hardeningPlan.candidate.config.sha256, summary.config_sha256],
    [hardeningPlan.candidate.unit.sha256, summary.unit_sha256],
    [receipt.activation.unit_generation.invocation_id, summary.unit_invocation_id],
  ]) {
    if (key !== expected) fail("Caddy admin UDS full evidence does not equal the overlay preimage summary");
  }
  return { hardeningPlan, receipt };
}

function parseCanonicalOverlayEvidence(bytes, label) {
  const buffer = Buffer.from(bytes);
  const value = parseStrictJson(buffer.toString("utf8"), label);
  if (!buffer.equals(Buffer.from(canonicalJson(value), "utf8"))) {
    fail(`${label} bytes must equal their canonical JSON encoding`);
  }
  return value;
}

function assertPublisherNetnsCeremonyEvidence(
  planBytes,
  receiptBytes,
  summary,
  overlayPlan,
) {
  const ceremonyPlan = parseCanonicalOverlayEvidence(
    planBytes,
    "publisher namespace ceremony plan",
  );
  const receipt = parseCanonicalOverlayEvidence(
    receiptBytes,
    "publisher namespace ceremony receipt",
  );
  validatePublisherNetnsPlanV2(ceremonyPlan);
  if (computePublisherNetnsPlanSha256V2(ceremonyPlan) !== summary.approved_plan_sha256) {
    fail("publisher namespace ceremony plan does not equal its approved digest");
  }
  if (
    ceremonyPlan.schema_version !== summary.plan_schema_version ||
    ceremonyPlan.kind !== PUBLISHER_NETNS_CEREMONY_KIND ||
    ceremonyPlan.ceremony_id !== summary.ceremony_id ||
    ceremonyPlan.transaction?.receipt_path !== summary.receipt.path
  ) {
    fail("publisher namespace ceremony plan identity or receipt path drifted");
  }
  validatePublisherNetnsReceiptV2({
    approvedPlanSha256: summary.approved_plan_sha256,
    plan: ceremonyPlan,
    receipt,
  });
  if (
    receipt.schema_version !== summary.receipt_schema_version ||
    receipt.kind !== PUBLISHER_NETNS_RECEIPT_KIND ||
    receipt.outcome !== "committed" ||
    receipt.ceremony_id !== summary.ceremony_id ||
    receipt.approved_plan_sha256 !== summary.approved_plan_sha256
  ) {
    fail("publisher namespace ceremony receipt identity or outcome drifted");
  }
  const planDropin = ceremonyPlan.installed_files?.find(
    (entry) => entry?.id === "caddy-netns-dropin",
  );
  const receiptDropins = receipt.installed_files?.filter(
    (entry) => entry?.path === PUBLISHER_NETNS_DROPIN_PATH,
  );
  if (
    planDropin === undefined ||
    !same(planDropin.pin, summary.dropin) ||
    !Array.isArray(receiptDropins) ||
    receiptDropins.length !== 1 ||
    !same(receiptDropins[0], summary.dropin)
  ) {
    fail("publisher namespace ceremony evidence does not bind the unique Caddy drop-in");
  }
  if (
    receipt.netns_unit?.active_state !== "active" ||
    receipt.netns_unit?.name !== PUBLISHER_NETNS_UNIT ||
    receipt.netns_unit?.invocation_id !== summary.netns_invocation_id ||
    receipt.netns_unit?.need_daemon_reload !== "no" ||
    receipt.publisher_unit?.active_state !== "inactive" ||
    receipt.publisher_unit?.name !== PUBLISHER_UNIT ||
    receipt.topology?.namespace?.device !== summary.namespace_device ||
    receipt.topology?.namespace?.inode !== summary.namespace_inode ||
    sha256(Buffer.from(canonicalJson(receipt.topology), "utf8")) !== summary.topology_sha256
  ) {
    fail("publisher namespace ceremony receipt does not bind the active isolated topology");
  }
  const caddy = ceremonyPlan.caddy_preimage;
  const unit = caddy?.unit;
  const generation = overlayPlan.target.unit_generation;
  if (
    !same(caddy?.config, overlayPlan.target.config_preimage) ||
    !same(receipt.caddy_before, caddy) ||
    !same(receipt.caddy_after, caddy) ||
    unit?.active_enter_timestamp_monotonic !==
      generation.active_enter_timestamp_monotonic ||
    unit?.active_state !== generation.active_state ||
    unit?.invocation_id !== generation.invocation_id ||
    unit?.main_pid !== generation.main_pid ||
    unit?.name !== generation.unit_name ||
    unit?.sub_state !== generation.sub_state ||
    unit?.load_state !== "loaded" ||
    unit?.need_daemon_reload !== "no"
  ) {
    fail("publisher namespace ceremony did not occur on the exact hardened Caddy preimage generation");
  }
  return { ceremonyPlan, receipt };
}

function assertPublisherNetnsLiveGeneration(actual, expected, label) {
  if (
    actual.unit_name !== PUBLISHER_NETNS_UNIT ||
    actual.active_state !== "active" ||
    actual.sub_state !== expected.sub_state ||
    actual.invocation_id !== expected.invocation_id ||
    actual.main_pid !== expected.main_pid ||
    actual.active_enter_timestamp_monotonic !== expected.active_enter_timestamp_monotonic
  ) {
    fail(`${label} publisher namespace systemd generation drifted`);
  }
}

function assertPublisherInactive(actual, label) {
  if (
    actual.unit_name !== PUBLISHER_UNIT ||
    actual.active_state !== "inactive" ||
    actual.main_pid !== "0"
  ) {
    fail(`${label} directory publisher must remain inactive during the network-only overlay`);
  }
}

function requireMonotonicNs(value, label) {
  if (typeof value !== "string" || !/^[1-9][0-9]*$/u.test(value)) {
    fail(`${label} must be positive canonical monotonic nanoseconds`);
  }
  return BigInt(value);
}

function assertAdminRuntimePath(value, expected, label) {
  exactKeys(
    value,
    ["ctime_ns", "device", "gid", "inode", "mode", "path", "type", "uid"],
    label,
  );
  if (
    value.path !== expected.path ||
    value.type !== expected.type ||
    value.mode !== expected.mode ||
    value.uid !== 0 ||
    value.gid !== 0 ||
    !/^[1-9][0-9]*$/u.test(value.inode) ||
    !/^(?:0|[1-9][0-9]*)$/u.test(value.device) ||
    !/^(?:0|[1-9][0-9]*)$/u.test(value.ctime_ns)
  ) {
    fail(`${label} does not match the exact capability-free non-root DAC boundary`);
  }
}

async function collectFreshAdminRuntime(
  plan,
  hardening,
  ops,
  label,
  expectedAdaptedJsonSha256s,
) {
  if (
    !Array.isArray(expectedAdaptedJsonSha256s) ||
    expectedAdaptedJsonSha256s.length < 1 ||
    expectedAdaptedJsonSha256s.some((digest) => !/^[0-9a-f]{64}$/u.test(digest))
  ) {
    fail(`${label} lacks an exact reviewed adapted JSON digest set`);
  }
  const boundaryBefore = await readCaddyRuntimeBoundary(
    plan,
    hardening,
    ops,
    `${label} admin probe before`,
  );
  const monotonicStartNs = await ops.monotonicNowNs();
  const directoryBefore = await ops.readAdminRuntimePath(ADMIN_DIRECTORY);
  const socketBefore = await ops.readAdminRuntimePath(ADMIN_SOCKET);
  assertAdminRuntimePath(
    directoryBefore,
    { mode: "0700", path: ADMIN_DIRECTORY, type: "directory" },
    `${label} admin runtime directory`,
  );
  assertAdminRuntimePath(
    socketBefore,
    { mode: "0200", path: ADMIN_SOCKET, type: "socket" },
    `${label} admin socket`,
  );
  const rootReadback = await ops.probeAdminApi({
    expected: "root-readback",
    gatePin: plan.runtime.admin_uds_gate,
    gid: 0,
    label: "root",
    nodePin: plan.runtime.node_binary,
    probePin: plan.runtime.admin_probe,
    setprivPin: plan.runtime.setpriv_binary,
    uid: 0,
  });
  exactKeys(
    rootReadback,
    ["body_sha256", "cap_eff", "error", "gid", "groups", "label", "listen", "path", "status", "transport", "uid"],
    `${label} root admin readback`,
  );
  if (!expectedAdaptedJsonSha256s.includes(rootReadback.body_sha256)) {
    fail(`${label} root readback does not equal the reviewed active adapted JSON`);
  }
  if (
    rootReadback.cap_eff !== "0000000000000000" ||
    rootReadback.error !== null ||
    rootReadback.gid !== 0 ||
    !same(rootReadback.groups, [0]) ||
    rootReadback.label !== "root" ||
    rootReadback.listen !== ADMIN_LISTEN ||
    rootReadback.path !== "/config/" ||
    rootReadback.status !== 200 ||
    rootReadback.transport !== "unix" ||
    rootReadback.uid !== 0
  ) {
    fail(`${label} root did not read back the exact active UDS admin config`);
  }
  const deniedServiceUids = [];
  for (const service of hardening.hardeningPlan.service_uid_inventory) {
    const denial = await ops.probeAdminApi({
      expected: "EACCES",
      gatePin: plan.runtime.admin_uds_gate,
      gid: service.uid,
      label: service.name,
      nodePin: plan.runtime.node_binary,
      probePin: plan.runtime.admin_probe,
      setprivPin: plan.runtime.setpriv_binary,
      uid: service.uid,
    });
    exactKeys(
      denial,
      ["body_sha256", "cap_eff", "error", "gid", "groups", "label", "listen", "path", "status", "transport", "uid"],
      `${label} ${service.name} admin denial`,
    );
    if (
      denial.body_sha256 !== null ||
      denial.cap_eff !== "0000000000000000" ||
      denial.error !== "EACCES" ||
      denial.gid !== service.uid ||
      !same(denial.groups, [service.uid]) ||
      denial.label !== service.name ||
      denial.listen !== null ||
      denial.path !== "/config/" ||
      denial.status !== null ||
      denial.transport !== "unix" ||
      denial.uid !== service.uid
    ) {
      fail(`${label} ${service.name} did not receive exact EACCES as its capability-free service UID`);
    }
    deniedServiceUids.push({
      cap_eff: denial.cap_eff,
      error: "EACCES",
      gid: denial.gid,
      groups: denial.groups,
      name: service.name,
      uid: service.uid,
    });
  }
  const tcpAdmin = [];
  for (const endpoint of ["127.0.0.1:2019", "[::1]:2019"]) {
    const result = await ops.probeTcpAdmin(endpoint);
    if (result !== "connection-refused") {
      fail(`${label} ${endpoint} did not refuse the TCP admin probe`);
    }
    tcpAdmin.push({ endpoint, result });
  }
  const directoryAfter = await ops.readAdminRuntimePath(ADMIN_DIRECTORY);
  const socketAfter = await ops.readAdminRuntimePath(ADMIN_SOCKET);
  const monotonicEndNs = await ops.monotonicNowNs();
  const boundaryAfter = await readCaddyRuntimeBoundary(
    plan,
    hardening,
    ops,
    `${label} admin probe after`,
  );
  if (
    !same(directoryAfter, directoryBefore) ||
    !same(socketAfter, socketBefore) ||
    !same(boundaryAfter, boundaryBefore)
  ) {
    fail(`${label} admin runtime, boot, effective unit or Caddy process drifted during fresh probes`);
  }
  const start = requireMonotonicNs(monotonicStartNs, `${label} monotonic_start_ns`);
  const end = requireMonotonicNs(monotonicEndNs, `${label} monotonic_end_ns`);
  if (end < start || end - start > 60_000_000_000n) {
    fail(`${label} admin runtime probe window is reversed or exceeds 60 seconds`);
  }
  return {
    boot_id: boundaryBefore.boot_id,
    boundary: DAC_BOUNDARY,
    denied_service_uids: deniedServiceUids,
    effective_unit: boundaryBefore.effective_unit,
    monotonic_end_ns: monotonicEndNs,
    monotonic_start_ns: monotonicStartNs,
    root_readback: rootReadback,
    runtime_directory: directoryBefore,
    socket: socketBefore,
    tcp_admin: tcpAdmin,
    process: boundaryBefore.process,
    unit_generation: boundaryBefore.unit_generation,
  };
}

async function collectPinnedState(
  plan,
  ops,
  label,
  { expectedAdminRuntime, requirePreimage = true } = {},
) {
  const pins = [
    [plan.runtime.node_binary, `${label} Node runtime`],
    [plan.runtime.setpriv_binary, `${label} setpriv runtime`],
    [plan.runtime.admin_probe, `${label} Caddy admin UDS probe`],
    [plan.runtime.admin_uds_gate, `${label} Caddy admin UDS gate`],
    [plan.runtime.gate, `${label} overlay gate`],
    [plan.runtime.executor, `${label} overlay executor`],
    [plan.runtime.exchange_helper, `${label} rename-exchange helper`],
    [plan.runtime.exchange_manifest, `${label} rename-exchange manifest`],
    [plan.runtime.managed_block, `${label} rendered managed block`],
    [plan.target.binary, `${label} Caddy binary`],
    [plan.target.unit_fragment, `${label} Caddy unit fragment`],
    [
      plan.target.publisher_netns_ceremony.dropin,
      `${label} publisher namespace Caddy drop-in`,
    ],
    [
      plan.target.publisher_netns_ceremony.plan,
      `${label} publisher namespace ceremony plan`,
    ],
    [
      plan.target.publisher_netns_ceremony.receipt,
      `${label} publisher namespace ceremony receipt`,
    ],
    [
      plan.target.admin_uds_hardening.plan,
      `${label} Caddy admin UDS hardening plan`,
    ],
    [
      plan.target.admin_uds_hardening.receipt,
      `${label} Caddy admin UDS hardening receipt`,
    ],
    [plan.source_fair.haproxy_binary, `${label} HAProxy binary`],
    [plan.source_fair.haproxy_config, `${label} HAProxy config`],
    [plan.source_fair.unit_fragment, `${label} HAProxy unit fragment`],
    ...plan.tls_dependencies.map((entry, index) => [
      entry.pin,
      `${label} TLS dependency ${index}`,
    ]),
  ];
  const files = new Map();
  const snapshots = new Map();
  for (const [pin, pinLabel] of pins) {
    const observed = await ops.readRegular(pin.path);
    exactRegularSnapshot(observed.snapshot, pin, pinLabel);
    files.set(pin.path, Buffer.from(observed.bytes));
    snapshots.set(pin.path, observed.snapshot);
  }
  assertManifest(files.get(plan.runtime.exchange_manifest.path), plan.runtime.exchange_helper);
  validatePublisherNetnsDropInBytes(
    files.get(plan.target.publisher_netns_ceremony.dropin.path),
    plan.target.publisher_netns_ceremony.dropin.sha256,
  );
  const publisherNetnsCeremony = assertPublisherNetnsCeremonyEvidence(
    files.get(plan.target.publisher_netns_ceremony.plan.path),
    files.get(plan.target.publisher_netns_ceremony.receipt.path),
    plan.target.publisher_netns_ceremony,
    plan,
  );
  const hardening = assertAdminUdsHardeningEvidence(
    files.get(plan.target.admin_uds_hardening.plan.path),
    files.get(plan.target.admin_uds_hardening.receipt.path),
    plan.target.admin_uds_hardening,
    plan.runtime.admin_probe,
    plan.runtime.admin_uds_gate,
    plan.runtime.node_binary,
  );
  if (
    !same(
      hardening.hardeningPlan.publisher_netns_dropin,
      plan.target.publisher_netns_ceremony.dropin,
    ) ||
    !same(
      hardening.receipt.publisher_netns_dropin,
      plan.target.publisher_netns_ceremony.dropin,
    )
  ) {
    fail(`${label} admin hardening and namespace ceremony drop-in pins disagree`);
  }
  const config = await ops.readRegular(plan.target.config_preimage.path);
  if (requirePreimage) {
    exactRegularSnapshot(config.snapshot, plan.target.config_preimage, `${label} Caddyfile preimage`);
  }
  const expectedRuntime = expectedAdminRuntime ??
    (requirePreimage ? "hardened-preimage" : undefined);
  let expectedAdaptedJsonSha256s;
  if (expectedRuntime === "hardened-preimage") {
    expectedAdaptedJsonSha256s = [
      hardening.hardeningPlan.candidate.adapted_json_sha256,
    ];
  } else if (expectedRuntime === "managed-candidate") {
    expectedAdaptedJsonSha256s = [
      plan.managed_block.candidate_adapted_json_sha256,
    ];
  } else if (expectedRuntime === "either-reviewed") {
    expectedAdaptedJsonSha256s = [
      hardening.hardeningPlan.candidate.adapted_json_sha256,
      plan.managed_block.candidate_adapted_json_sha256,
    ];
  } else {
    fail(`${label} must select the exact expected active adapted JSON generation`);
  }
  const adminRuntime = await collectFreshAdminRuntime(
    plan,
    hardening,
    ops,
    label,
    expectedAdaptedJsonSha256s,
  );
  const caddyGeneration = adminRuntime.unit_generation;
  const publisherNetnsGeneration = await ops.readUnitGeneration(PUBLISHER_NETNS_UNIT);
  assertPublisherNetnsLiveGeneration(
    publisherNetnsGeneration,
    publisherNetnsCeremony.receipt.netns_unit,
    label,
  );
  const publisherGeneration = await ops.readUnitGeneration(PUBLISHER_UNIT);
  assertPublisherInactive(publisherGeneration, label);
  const sourceFairGeneration = await ops.readUnitGeneration(SOURCE_FAIR_UNIT);
  exactGeneration(sourceFairGeneration, plan.source_fair.unit_generation, `${label} source-fair HAProxy`);
  for (const [index, expected] of plan.source_fair.runtime_paths.entries()) {
    assertRuntimePath(
      await ops.readRuntimePath(expected.path),
      expected,
      `${label} source_fair.runtime_paths[${index}]`,
    );
  }
  for (const [index, dependency] of plan.tls_dependencies.entries()) {
    const parent = await ops.readDirectory(dependency.parent.path);
    if (!same(parent, dependency.parent)) fail(`${label} TLS dependency ${index} parent drifted`);
  }
  const configParent = await ops.readDirectory(plan.target.config_parent.path);
  if (!same(configParent, plan.target.config_parent)) fail(`${label} Caddy config parent drifted`);
  return {
    adminRuntime,
    caddyGeneration,
    config,
    files,
    hardening,
    publisherGeneration,
    publisherNetnsCeremony,
    publisherNetnsGeneration,
    snapshots,
    sourceFairGeneration,
  };
}

function receiptSnapshot(plan, state, configSnapshot) {
  return {
    admin_runtime: state.adminRuntime,
    binary: state.snapshots.get(plan.target.binary.path),
    config: configSnapshot,
    source_fair_generation: state.sourceFairGeneration,
    target_generation: state.caddyGeneration,
    unit_fragment: state.snapshots.get(plan.target.unit_fragment.path),
  };
}

function runtimeBoundaryFromAdminRuntime(adminRuntime) {
  return {
    boot_id: adminRuntime.boot_id,
    effective_unit: adminRuntime.effective_unit,
    process: adminRuntime.process,
    unit_generation: adminRuntime.unit_generation,
  };
}

function baseReceipt({
  approvedPlanSha256,
  backup,
  before,
  healthResults,
  host,
  installation,
  outcome,
  plan,
  preparation,
  reload,
  rollback,
  after,
}) {
  return {
    after,
    approved_plan_sha256: approvedPlanSha256,
    backup,
    before,
    collector: OVERLAY_COLLECTOR,
    health_results: healthResults,
    host,
    installation,
    outcome,
    preparation,
    publisher_netns_ceremony: structuredClone(plan.target.publisher_netns_ceremony),
    reload,
    rollback,
    schema_version: OVERLAY_RECEIPT_SCHEMA_VERSION,
    transaction_id: plan.transaction_id,
  };
}

function noRollback() {
  return {
    attempted: false,
    directory_fsync: false,
    exact_candidate_swapped_out: false,
    exact_preimage_restored: false,
    exchanged: false,
    reload_exit_status: null,
    runtime_before: null,
  };
}

function stateRecord(plan, approvedPlanSha256, phase, previousPhase, extra = {}) {
  return {
    approved_plan_sha256: approvedPlanSha256,
    phase,
    previous_phase: previousPhase,
    schema_version: 1,
    transaction_id: plan.transaction_id,
    ...extra,
  };
}

function ownerOnlyRecordShape(snapshot, path, label) {
  if (
    snapshot.path !== path ||
    snapshot.uid !== 0 ||
    snapshot.gid !== 0 ||
    snapshot.mode !== "0400" ||
    snapshot.nlink !== 1
  ) {
    fail(`${label} is not one root-owned owner-only single-link record`);
  }
}

async function settleAtomicPublication({
  bytes,
  finalPath,
  helperPin,
  label,
  ops,
  parentSeal,
  pendingPath,
  publish,
}) {
  const verify = (observed, path, recordLabel) => {
    ownerOnlyRecordShape(observed.snapshot, path, recordLabel);
    if (!observed.bytes.equals(bytes)) fail(`${recordLabel} bytes disagree with this transaction`);
  };
  let final = await ops.readOptionalRegular(finalPath);
  let pending = await ops.readOptionalRegular(pendingPath);
  if (final !== null) {
    verify(final, finalPath, `${label} final record`);
    await ops.fsyncParent(finalPath, parentSeal);
    const confirmed = await ops.readRegular(finalPath);
    verify(confirmed, finalPath, `${label} confirmed final record`);
    if (!same(final.snapshot, confirmed.snapshot)) {
      fail(`${label} final record changed across its first durability confirmation`);
    }
    if (pending !== null) {
      ownerOnlyRecordShape(pending.snapshot, pendingPath, `${label} leftover pending record`);
      if (!pending.bytes.equals(bytes)) fail(`${label} final and pending records disagree`);
      await ops.removeIfExact(pendingPath, pending.snapshot, parentSeal);
    }
    await ops.fsyncParent(finalPath, parentSeal);
    const terminal = await ops.readRegular(finalPath);
    verify(terminal, finalPath, `${label} terminal final record`);
    if (!same(confirmed.snapshot, terminal.snapshot)) {
      fail(`${label} final record changed during pending cleanup confirmation`);
    }
    return terminal;
  }
  if (pending !== null) {
    ownerOnlyRecordShape(pending.snapshot, pendingPath, `${label} pending record`);
    if (!pending.bytes.equals(bytes)) {
      await ops.removeIfExact(pendingPath, pending.snapshot, parentSeal);
    } else {
      await ops.fsyncRegular(pendingPath, pending.snapshot, parentSeal);
      await publish(pendingPath, finalPath, helperPin, parentSeal);
    }
  }
  await ops.fsyncParent(finalPath, parentSeal);
  final = await ops.readOptionalRegular(finalPath);
  pending = await ops.readOptionalRegular(pendingPath);
  await ops.fsyncParent(finalPath, parentSeal);
  const finalConfirmation = await ops.readOptionalRegular(finalPath);
  const pendingConfirmation = await ops.readOptionalRegular(pendingPath);
  if (final === null && pending === null && finalConfirmation === null && pendingConfirmation === null) {
    return null;
  }
  if (final !== null && finalConfirmation !== null) {
    verify(final, finalPath, `${label} recovered final record`);
    verify(finalConfirmation, finalPath, `${label} recovered final confirmation`);
    if (!same(final.snapshot, finalConfirmation.snapshot)) {
      fail(`${label} final record changed across durability confirmation`);
    }
    if (pending !== null || pendingConfirmation !== null) {
      fail(`${label} pending record remained after final publication`);
    }
    return finalConfirmation;
  }
  fail(`${label} publication could not be classified exactly`);
}

async function writeState(ops, plan, record, stateDirectorySeal) {
  const filename = PHASE_TO_FILE[record.phase];
  if (filename === undefined) fail(`unknown transaction phase ${record.phase}`);
  const bytes = Buffer.from(canonicalJson(record), "utf8");
  const finalPath = `${plan.transaction.state_directory}/${filename}`;
  const pendingPath = `${finalPath}.pending`;
  let primary;
  try {
    await ops.writeState(
      plan.transaction.state_directory,
      filename,
      bytes,
      plan.runtime.exchange_helper,
      stateDirectorySeal,
    );
  } catch (error) {
    primary = error;
  }
  let observed;
  try {
    observed = await settleAtomicPublication({
      bytes,
      finalPath,
      helperPin: plan.runtime.exchange_helper,
      label: `phase ${record.phase}`,
      ops,
      parentSeal: stateDirectorySeal,
      pendingPath,
      publish: (...args) => ops.publishPendingState(...args),
    });
  } catch (error) {
    throw outcomeUnknown(
      `phase ${record.phase} publication outcome is unknown; explicit recovery is required: ${error.message}`,
      primary ?? error,
    );
  }
  if (observed === null) {
    if (primary !== undefined) throw primary;
    throw outcomeUnknown(`phase ${record.phase} reported success without a durable record`);
  }
}

function receiptDigest(receipt) {
  return sha256(Buffer.from(canonicalJson(receipt), "utf8"));
}

async function writeReceipt(
  ops,
  plan,
  approvedPlanSha256,
  receipt,
  receiptParentSeal,
) {
  validateOverlayReceipt({ approvedPlanSha256, plan, receipt });
  const bytes = Buffer.from(canonicalJson(receipt), "utf8");
  let primary;
  try {
    await ops.writeReceipt(
      plan.transaction.receipt_pending_path,
      plan.transaction.receipt_path,
      bytes,
      plan.runtime.exchange_helper,
      receiptParentSeal,
    );
  } catch (error) {
    primary = error;
  }
  let observed;
  try {
    observed = await settleAtomicPublication({
      bytes,
      finalPath: plan.transaction.receipt_path,
      helperPin: plan.runtime.exchange_helper,
      label: "terminal receipt",
      ops,
      parentSeal: receiptParentSeal,
      pendingPath: plan.transaction.receipt_pending_path,
      publish: (...args) => ops.publishPendingReceipt(...args),
    });
  } catch (error) {
    throw outcomeUnknown(
      `terminal receipt publication outcome is unknown; explicit recovery is required: ${error.message}`,
      primary ?? error,
    );
  }
  if (observed === null) {
    if (primary !== undefined) throw primary;
    throw outcomeUnknown("terminal receipt reported success without a durable record");
  }
  return sha256(bytes);
}

export class OverlayTransactionError extends Error {
  constructor(message, { cause, phase, receipt } = {}) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "OverlayTransactionError";
    this.phase = phase;
    this.receipt = receipt;
  }
}

export class OverlayOutcomeUnknownError extends OverlayTransactionError {
  constructor(message, { cause, phase = "outcome-unknown" } = {}) {
    super(message, { cause, phase });
    this.name = "OverlayOutcomeUnknownError";
  }
}

function outcomeUnknown(message, cause) {
  return new OverlayOutcomeUnknownError(message, { cause });
}

async function releasePreservingPrimary(release, operation) {
  let value;
  let primary;
  try {
    value = await operation();
  } catch (error) {
    primary = error;
  }
  try {
    await release();
  } catch (releaseError) {
    if (primary !== undefined) {
      primary.lockReleaseError = releaseError;
    } else {
      primary = new OverlayTransactionError(
        `transaction completed but lock release failed closed: ${releaseError.message}`,
        { cause: releaseError, phase: "lock-release-failed", receipt: value },
      );
    }
  }
  if (primary !== undefined) throw primary;
  return value;
}

function installationRecord(plan) {
  return {
    candidate_path: plan.transaction.candidate_path,
    config_parent_fsync: true,
    exchange_helper_sha256: plan.runtime.exchange_helper.sha256,
    exchanged: true,
    live_candidate_verified: true,
    same_filesystem: true,
    swapped_out_preimage_verified: true,
  };
}

function mutableParentPaths(plan) {
  return [...new Set([
    dirname(plan.transaction.adapted_json_path),
    dirname(plan.transaction.backup_path),
    dirname(plan.transaction.receipt_path),
    dirname(plan.transaction.state_directory),
  ])].sort();
}

function requireOwnerOnlyDirectory(snapshot, path, label) {
  if (
    snapshot.path !== path ||
    snapshot.uid !== 0 ||
    snapshot.gid !== 0 ||
    snapshot.mode !== "0700" ||
    typeof snapshot.device !== "string" ||
    !/^(?:0|[1-9][0-9]{0,19})$/u.test(snapshot.device) ||
    typeof snapshot.inode !== "string" ||
    !/^[1-9][0-9]{0,19}$/u.test(snapshot.inode)
  ) {
    fail(`${label} is not one sealed root-owned mode-0700 directory`);
  }
}

async function sealMutableParents(plan, ops) {
  const seals = new Map();
  for (const path of mutableParentPaths(plan)) {
    const snapshot = await ops.readDirectory(path);
    requireOwnerOnlyDirectory(snapshot, path, `mutable transaction parent ${path}`);
    seals.set(path, snapshot);
  }
  return seals;
}

function sealRecord(parentSeals, stateDirectorySeal) {
  return [...parentSeals.values(), stateDirectorySeal]
    .map((snapshot) => structuredClone(snapshot))
    .sort((left, right) => left.path.localeCompare(right.path));
}

function sealFor(parentSeals, path) {
  const seal = parentSeals.get(dirname(path));
  if (seal === undefined) fail(`missing mutable parent seal for ${path}`);
  return seal;
}

function validateRecordedDirectorySeals(recorded, plan) {
  if (!Array.isArray(recorded)) fail("prepared directory seals must be an array");
  const expectedPaths = [...mutableParentPaths(plan), plan.transaction.state_directory].sort();
  if (recorded.length !== expectedPaths.length) fail("prepared directory seal count drifted");
  const byPath = new Map();
  for (const snapshot of recorded) {
    exactKeys(snapshot, ["device", "gid", "inode", "mode", "path", "uid"], "prepared directory seal");
    if (byPath.has(snapshot.path)) fail("prepared directory seals contain a duplicate path");
    requireOwnerOnlyDirectory(snapshot, snapshot.path, `prepared directory seal ${snapshot.path}`);
    byPath.set(snapshot.path, snapshot);
  }
  if (expectedPaths.some((path) => !byPath.has(path))) {
    fail("prepared directory seal paths drifted from the transaction plan");
  }
  return byPath;
}

async function verifyInstalledPair(plan, ops, candidateSnapshot) {
  const live = await ops.readRegular(TARGET_CONFIG);
  const swapped = await ops.readRegular(plan.transaction.candidate_path);
  assertExchangeIdentity(live.snapshot, candidateSnapshot, TARGET_CONFIG, "live exchanged candidate");
  assertExchangeIdentity(
    swapped.snapshot,
    plan.target.config_preimage,
    plan.transaction.candidate_path,
    "swapped-out Caddyfile preimage",
  );
  return { live, swapped };
}

function stablePairIdentity(pair) {
  return {
    candidate: pair.candidate?.snapshot ?? null,
    kind: pair.kind,
    live: pair.live.snapshot,
  };
}

async function classifyDurablePair(plan, ops, candidateSnapshot, label) {
  try {
    await ops.fsyncParent(TARGET_CONFIG, plan.target.config_parent);
    const first = await classifyPair(plan, ops, candidateSnapshot);
    await ops.fsyncParent(TARGET_CONFIG, plan.target.config_parent);
    const second = await classifyPair(plan, ops, candidateSnapshot);
    if (!same(stablePairIdentity(first), stablePairIdentity(second))) {
      fail(`${label} target/candidate pair changed across its durability confirmation`);
    }
    return second;
  } catch (error) {
    throw outcomeUnknown(
      `${label} outcome is unknown; refusing rollback, terminal receipt and cleanup: ${error.message}`,
      error,
    );
  }
}

async function exchange(ops, plan) {
  await ops.exchange(
    plan.transaction.candidate_path,
    TARGET_CONFIG,
    plan.runtime.exchange_helper,
    plan.target.config_parent,
  );
}

async function exchangeAndClassify({
  candidateSnapshot,
  expectedAfter,
  label,
  ops,
  plan,
}) {
  let helperError;
  try {
    await exchange(ops, plan);
  } catch (error) {
    helperError = error;
  }
  const pair = await classifyDurablePair(plan, ops, candidateSnapshot, label);
  if (pair.kind === expectedAfter) return pair;
  const expectedBefore = expectedAfter === "installed" ? "rolled-back" : "installed";
  if (pair.kind === expectedBefore) {
    const suffix = helperError === undefined ? "reported success without applying the exchange" :
      `did not apply the exchange: ${helperError.message}`;
    throw new OverlayTransactionError(`${label} ${suffix}`, {
      cause: helperError,
      phase: `${label}-not-applied`,
    });
  }
  throw outcomeUnknown(
    `${label} reached unsupported exact pair ${pair.kind}; refusing any compensating mutation`,
    helperError,
  );
}

async function exchangeInstalledPairForRollback(plan, ops, candidateSnapshot) {
  await verifyInstalledPair(plan, ops, candidateSnapshot);
  await exchangeAndClassify({
    candidateSnapshot,
    expectedAfter: "rolled-back",
    label: "rollback-exchange",
    ops,
    plan,
  });
}

async function rollbackInstalled({
  approvedPlanSha256,
  candidateSnapshot,
  context,
  hardening,
  ops,
  plan,
  previousPhase,
  receiptParentSeal,
  reload,
  stateDirectorySeal,
}) {
  await collectStableCaddyRuntimeBoundary(
    plan,
    hardening,
    ops,
    "pre-rollback-exchange",
  );
  await exchangeInstalledPairForRollback(plan, ops, candidateSnapshot);
  await writeState(
    ops,
    plan,
    stateRecord(plan, approvedPlanSha256, "rollback-exchanged", previousPhase),
    stateDirectorySeal,
  );
  const rollbackRuntimeBefore = await collectStableCaddyRuntimeBoundary(
    plan,
    hardening,
    ops,
    "pre-rollback-reload",
  );
  const rollbackReload = await ops.run(plan.transaction.reload_argv, {
    captureStdout: false,
    maxBytes: MAX_COMMAND_BYTES,
    timeoutMs: 30_000,
  });
  if (rollbackReload.status !== 0) fail("rollback reload failed");
  const restoredState = await collectPinnedState(plan, ops, "post-rollback", {
    expectedAdminRuntime: "hardened-preimage",
    requirePreimage: false,
  });
  const finalConfig = await ops.readRegular(TARGET_CONFIG);
  assertFinalConfig(finalConfig.snapshot, plan.target.config_preimage.sha256, "post-rollback Caddyfile");
  const rollback = {
    attempted: true,
    directory_fsync: true,
    exact_candidate_swapped_out: true,
    exact_preimage_restored: true,
    exchanged: true,
    reload_exit_status: rollbackReload.status,
    runtime_before: rollbackRuntimeBefore,
  };
  const after = receiptSnapshot(plan, restoredState, finalConfig.snapshot);
  await writeState(
    ops,
    plan,
    stateRecord(plan, approvedPlanSha256, "rollback-reloaded", "rollback-exchanged", {
      after,
      rollback,
    }),
    stateDirectorySeal,
  );
  const receipt = baseReceipt({
    after,
    approvedPlanSha256,
    backup: context.backup,
    before: context.before,
    healthResults: [],
    host: context.host,
    installation: context.installation,
    outcome: "rolled-back",
    plan,
    preparation: context.preparation,
    reload,
    rollback,
  });
  const digest = await writeReceipt(
    ops,
    plan,
    approvedPlanSha256,
    receipt,
    receiptParentSeal,
  );
  try {
    await writeState(
      ops,
      plan,
      stateRecord(plan, approvedPlanSha256, "rolled-back", "rollback-reloaded", {
        receipt_sha256: digest,
      }),
      stateDirectorySeal,
    );
    await ops.removeIfExact(
      plan.transaction.candidate_path,
      candidateSnapshot,
      plan.target.config_parent,
    );
  } catch (error) {
    throw new OverlayTransactionError(
      `rolled-back receipt is durable; explicit recovery must finalize cleanup: ${error.message}`,
      { cause: error, phase: "rollback-finalization-failed", receipt },
    );
  }
  return receipt;
}

async function executeLocked({ approvedPlanSha256, ops, plan }) {
  const parentSeals = await sealMutableParents(plan, ops);
  const stateDirectorySeal = await ops.initializeStateDirectory(
    plan.transaction.state_directory,
    sealFor(parentSeals, plan.transaction.state_directory),
  );
  let candidateSnapshot;
  let prepared = false;
  let exchanged = false;
  let exchangedRecorded = false;
  let previousPhase = "prepared";
  let context;
  let hardening;
  let durableCommitReceipt;
  let reload = {
    argv: structuredClone(plan.transaction.reload_argv),
    exit_status: null,
    restart_invoked: false,
    runtime_before: null,
  };
  try {
    const initial = await collectPinnedState(plan, ops, "initial");
    hardening = initial.hardening;
    const preimage = Buffer.from(initial.config.bytes);
    const before = receiptSnapshot(plan, initial, initial.config.snapshot);
    const candidate = buildOverlayCandidateFromRendered({
      approvedPlanSha256,
      managedBlockBytes: initial.files.get(plan.runtime.managed_block.path),
      plan,
      preimageBytes: preimage,
    });
    const candidateWrite = await ops.writeExclusive(
      plan.transaction.candidate_path,
      candidate.candidate,
      "0644",
      plan.target.config_parent,
    );
    candidateSnapshot = candidateWrite.snapshot;

    const adapt = await ops.run(plan.transaction.adapt_argv, {
      captureStdout: true,
      maxBytes: MAX_COMMAND_BYTES,
      timeoutMs: 30_000,
    });
    if (adapt.status !== 0) {
      throw new OverlayTransactionError("Caddy adapt failed before installation", { phase: "adapt" });
    }
    const adaptedBytes = canonicalizeAdaptedCaddyJson(
      Buffer.from(adapt.stdout),
      "Caddy adapted JSON",
    );
    if (sha256(adaptedBytes) !== plan.managed_block.candidate_adapted_json_sha256) {
      throw new OverlayTransactionError("Caddy adapted JSON drifted from the approved candidate", {
        phase: "adapt",
      });
    }
    await ops.writeExclusive(
      plan.transaction.adapted_json_path,
      adaptedBytes,
      "0400",
      sealFor(parentSeals, plan.transaction.adapted_json_path),
    );
    const validate = await ops.run(plan.transaction.validate_argv, {
      captureStdout: false,
      maxBytes: MAX_COMMAND_BYTES,
      timeoutMs: 30_000,
    });
    if (validate.status !== 0) {
      throw new OverlayTransactionError("Caddy validate failed before installation", { phase: "validate" });
    }
    const preparation = {
      adapt_argv: structuredClone(plan.transaction.adapt_argv),
      adapt_exit_status: adapt.status,
      adapted_json_sha256: sha256(adaptedBytes),
      candidate_sha256: candidate.candidateSha256,
      managed_block_sha256: candidate.blockSha256,
      preimage_sha256: candidate.preimageSha256,
      validate_argv: structuredClone(plan.transaction.validate_argv),
      validate_exit_status: validate.status,
    };
    const validatedCandidate = await ops.readRegular(plan.transaction.candidate_path);
    exactRegularSnapshot(validatedCandidate.snapshot, candidateSnapshot, "validated candidate");
    await collectPinnedState(plan, ops, "post-validation");

    const backupWrite = await ops.writeExclusive(
      plan.transaction.backup_path,
      preimage,
      "0400",
      sealFor(parentSeals, plan.transaction.backup_path),
    );
    const backup = {
      directory_fsync: backupWrite.directoryFsync,
      exclusive_create: backupWrite.exclusiveCreate,
      file_fsync: backupWrite.fileFsync,
      gid: backupWrite.snapshot.gid,
      mode: backupWrite.snapshot.mode,
      nlink: backupWrite.snapshot.nlink,
      path: backupWrite.snapshot.path,
      sha256: backupWrite.snapshot.sha256,
      uid: backupWrite.snapshot.uid,
    };
    if (
      backup.path !== plan.transaction.backup_path ||
      backup.sha256 !== plan.target.config_preimage.sha256 ||
      backup.uid !== 0 ||
      backup.gid !== 0 ||
      backup.mode !== "0400" ||
      backup.nlink !== 1 ||
      backup.exclusive_create !== true ||
      backup.file_fsync !== true ||
      backup.directory_fsync !== true
    ) {
      fail("backup adapter did not durably create the exact owner-only preimage");
    }
    const finalPreinstall = await ops.readRegular(TARGET_CONFIG);
    exactRegularSnapshot(finalPreinstall.snapshot, plan.target.config_preimage, "final pre-install Caddyfile");
    context = {
      backup,
      before,
      directory_seals: sealRecord(parentSeals, stateDirectorySeal),
      host: await ops.hostIdentity(),
      preparation,
    };
    await writeState(
      ops,
      plan,
      stateRecord(plan, approvedPlanSha256, "prepared", null, {
        candidate_snapshot: candidateSnapshot,
        context,
      }),
      stateDirectorySeal,
    );
    prepared = true;

    await collectStableCaddyRuntimeBoundary(
      plan,
      hardening,
      ops,
      "pre-install-exchange",
    );
    await exchangeAndClassify({
      candidateSnapshot,
      expectedAfter: "installed",
      label: "install-exchange",
      ops,
      plan,
    });
    exchanged = true;
    const installation = installationRecord(plan);
    context.installation = installation;
    await writeState(
      ops,
      plan,
      stateRecord(plan, approvedPlanSha256, "exchanged", "prepared", { installation }),
      stateDirectorySeal,
    );
    exchangedRecorded = true;
    previousPhase = "exchanged";

    reload.runtime_before = await collectStableCaddyRuntimeBoundary(
      plan,
      hardening,
      ops,
      "pre-install-reload",
    );
    const reloadResult = await ops.run(plan.transaction.reload_argv, {
      captureStdout: false,
      maxBytes: MAX_COMMAND_BYTES,
      timeoutMs: 30_000,
    });
    reload.exit_status = reloadResult.status;
    if (reloadResult.status !== 0) throw new Error("Caddy reload failed");
    await writeState(
      ops,
      plan,
      stateRecord(plan, approvedPlanSha256, "reloaded", "exchanged", { reload }),
      stateDirectorySeal,
    );
    previousPhase = "reloaded";

    await collectPinnedState(plan, ops, "post-reload", {
      expectedAdminRuntime: "managed-candidate",
      requirePreimage: false,
    });
    const committedConfig = await ops.readRegular(TARGET_CONFIG);
    assertFinalConfig(committedConfig.snapshot, plan.managed_block.candidate_sha256, "post-reload Caddyfile");
    const healthResults = [];
    for (const check of plan.health_checks) {
      const result = await ops.health(check);
      if (
        result.success !== true ||
        result.status !== check.expected_status ||
        result.leaf_certificate_sha256 !== check.leaf_certificate_sha256 ||
        (check.expected_body_sha256 === null
          ? result.body_sha256 !== null
          : result.body_sha256 !== check.expected_body_sha256)
      ) {
        throw new Error(`health check failed for ${check.lane}`);
      }
      healthResults.push({
        body_sha256: result.body_sha256,
        check: structuredClone(check),
        leaf_certificate_sha256: result.leaf_certificate_sha256,
        status: result.status,
        success: true,
      });
    }
    // Health can take seconds. Re-bind the exact file pair and both process
    // generations after the last network probe and immediately before making
    // a committed receipt durable.
    const finalCommittedState = await collectPinnedState(plan, ops, "post-health", {
      expectedAdminRuntime: "managed-candidate",
      requirePreimage: false,
    });
    const finalInstalled = await verifyInstalledPair(plan, ops, candidateSnapshot);
    assertFinalConfig(
      finalInstalled.live.snapshot,
      plan.managed_block.candidate_sha256,
      "post-health Caddyfile",
    );
    const receipt = baseReceipt({
      after: receiptSnapshot(plan, finalCommittedState, finalInstalled.live.snapshot),
      approvedPlanSha256,
      backup,
      before,
      healthResults,
      host: context.host,
      installation,
      outcome: "committed",
      plan,
      preparation,
      reload,
      rollback: noRollback(),
    });
    const digest = await writeReceipt(
      ops,
      plan,
      approvedPlanSha256,
      receipt,
      sealFor(parentSeals, plan.transaction.receipt_path),
    );
    durableCommitReceipt = receipt;
    await writeState(
      ops,
      plan,
      stateRecord(plan, approvedPlanSha256, "committed", "reloaded", {
        receipt_sha256: digest,
      }),
      stateDirectorySeal,
    );
    await ops.removeIfExact(
      plan.transaction.candidate_path,
      {
        ...plan.target.config_preimage,
        path: plan.transaction.candidate_path,
      },
      plan.target.config_parent,
    );
    return receipt;
  } catch (error) {
    if (durableCommitReceipt !== undefined) {
      throw new OverlayTransactionError(
        `committed receipt is durable; explicit recovery must finalize cleanup: ${error.message}`,
        {
          cause: error,
          phase: "commit-finalization-failed",
          receipt: durableCommitReceipt,
        },
      );
    }
    if (error instanceof OverlayOutcomeUnknownError) throw error;
    if (exchanged && !exchangedRecorded) {
      throw outcomeUnknown(
        `installed Caddyfile pair has no durable exchanged phase; explicit recovery is required: ${error.message}`,
        error,
      );
    }
    if (!exchanged) {
      if (prepared) {
        try {
          await writeState(
            ops,
            plan,
            stateRecord(plan, approvedPlanSha256, "aborted-before-install", "prepared"),
            stateDirectorySeal,
          );
        } catch (abortFinalizationError) {
          // A durable prepared root requires either its exact candidate or a
          // durable abort record. Preserve the candidate on every abort-state
          // failure, even when publication is proven not to have happened, so
          // explicit recovery can append the missing terminal phase.
          try {
            error.abortFinalizationError = abortFinalizationError;
          } catch {
            attachCleanupError(error, abortFinalizationError);
          }
          throw error;
        }
      }
      if (candidateSnapshot !== undefined) {
        try {
          await ops.removeIfExact(
            plan.transaction.candidate_path,
            candidateSnapshot,
            plan.target.config_parent,
          );
        } catch (cleanupError) {
          // Never mask the initiating failure, but retain exact evidence that
          // recovery may still need to remove the transaction candidate.
          attachCleanupError(error, cleanupError);
        }
      }
      const reported = error instanceof OverlayTransactionError
        ? error
        : new OverlayTransactionError(
            `integrated Caddy transaction aborted before installation: ${error.message}`,
            { cause: error, phase: "pre-install" },
          );
      if (reported !== error) {
        for (const cleanupError of error?.cleanupErrors ?? []) {
          attachCleanupError(reported, cleanupError);
        }
      }
      throw reported;
    }
    try {
      const receipt = await rollbackInstalled({
        approvedPlanSha256,
        candidateSnapshot,
        context,
        hardening,
        ops,
        plan,
        previousPhase,
        reload,
        receiptParentSeal: sealFor(parentSeals, plan.transaction.receipt_path),
        stateDirectorySeal,
      });
      throw new OverlayTransactionError(
        `Caddy overlay failed and exact preimage was restored: ${error.message}`,
        { cause: error, phase: "rolled-back", receipt },
      );
    } catch (rollbackError) {
      if (rollbackError instanceof OverlayOutcomeUnknownError) {
        rollbackError.primaryError = error;
        throw rollbackError;
      }
      if (rollbackError instanceof OverlayTransactionError && rollbackError.receipt !== undefined) {
        rollbackError.primaryError ??= error;
        throw rollbackError;
      }
      const combined = new OverlayTransactionError(
        `Caddy overlay failed (${error.message}) and rollback is not proven: ${rollbackError.message}`,
        { cause: error, phase: "rollback-failed" },
      );
      combined.rollbackError = rollbackError;
      throw combined;
    }
  }
}

export async function executeOverlayTransaction({ approvedPlanSha256, ops, plan }) {
  validateOverlayPlan(plan);
  if (computeApprovedOverlayPlanSha256(plan) !== approvedPlanSha256) {
    fail("transaction plan does not match its externally approved SHA-256");
  }
  const release = await ops.acquireLock(plan.transaction.lock_path, {
    helperPin: plan.runtime.exchange_helper,
    recoverStale: false,
    transactionId: plan.transaction_id,
  });
  return releasePreservingPrimary(release, () =>
    executeLocked({ approvedPlanSha256, ops, plan }));
}

function validateStateCommon(record, plan, approvedPlanSha256, phase) {
  if (
    record.schema_version !== 1 ||
    record.phase !== phase ||
    record.transaction_id !== plan.transaction_id ||
    record.approved_plan_sha256 !== approvedPlanSha256
  ) {
    fail(`durable transaction state ${phase} drifted from the approved plan`);
  }
}

function validateRecoveryCandidateSnapshot(snapshot, plan) {
  exactKeys(
    snapshot,
    ["ctime_ns", "device", "gid", "inode", "mode", "mtime_ns", "nlink", "path", "sha256", "size", "uid"],
    "prepared candidate snapshot",
  );
  if (
    snapshot.path !== plan.transaction.candidate_path ||
    snapshot.sha256 !== plan.managed_block.candidate_sha256 ||
    snapshot.uid !== 0 ||
    snapshot.gid !== 0 ||
    snapshot.mode !== "0644" ||
    snapshot.nlink !== 1
  ) {
    fail("prepared state candidate snapshot drifted");
  }
  for (const key of ["ctime_ns", "device", "inode", "mtime_ns", "size"]) {
    if (typeof snapshot[key] !== "string" || !/^(?:0|[1-9][0-9]{0,19})$/u.test(snapshot[key])) {
      fail(`prepared state candidate snapshot ${key} is not a canonical decimal`);
    }
  }
  if (snapshot.inode === "0") fail("prepared state candidate snapshot inode must be positive");
}

function validateRecoveryReceiptComponents({
  after,
  approvedPlanSha256,
  context,
  installation,
  plan,
  reload,
  rollback,
}) {
  validateOverlayReceipt({
    approvedPlanSha256,
    plan,
    receipt: baseReceipt({
      after,
      approvedPlanSha256,
      backup: context.backup,
      before: context.before,
      healthResults: [],
      host: context.host,
      installation,
      outcome: "rolled-back",
      plan,
      preparation: context.preparation,
      reload,
      rollback,
    }),
  });
}

function loadRecoveryModel(records, plan, approvedPlanSha256) {
  const byPhase = new Map();
  for (const [filename, bytes] of records) {
    const phase = Object.entries(PHASE_TO_FILE).find((entry) => entry[1] === filename)?.[0];
    if (phase === undefined) fail(`unknown durable transaction state file ${filename}`);
    const record = parseStrictJson(Buffer.from(bytes).toString("utf8"), `state ${filename}`);
    validateStateCommon(record, plan, approvedPlanSha256, phase);
    byPhase.set(phase, record);
  }
  const prepared = byPhase.get("prepared");
  if (byPhase.size > 0 && prepared === undefined) fail("durable state is missing its prepared root record");
  const phaseExtraKeys = {
    "aborted-before-install": [],
    committed: ["receipt_sha256"],
    exchanged: ["installation"],
    prepared: ["candidate_snapshot", "context"],
    reloaded: ["reload"],
    "rollback-exchanged": [],
    "rollback-reloaded": ["after", "rollback"],
    "rolled-back": ["receipt_sha256"],
  };
  for (const [phase, record] of byPhase) {
    exactKeys(
      record,
      [
        "approved_plan_sha256",
        "phase",
        "previous_phase",
        "schema_version",
        "transaction_id",
        ...phaseExtraKeys[phase],
      ],
      `${phase} state`,
    );
  }
  if (prepared !== undefined) {
    if (prepared.previous_phase !== null) fail("prepared state has a predecessor");
    validateRecoveryCandidateSnapshot(prepared.candidate_snapshot, plan);
    exactKeys(
      prepared.context,
      ["backup", "before", "directory_seals", "host", "preparation"],
      "prepared recovery context",
    );
    validateRecordedDirectorySeals(prepared.context.directory_seals, plan);
    validateOverlayPreparedContext({
      approvedPlanSha256,
      context: {
        backup: prepared.context.backup,
        before: prepared.context.before,
        host: prepared.context.host,
        preparation: prepared.context.preparation,
      },
      plan,
    });
  }
  const exchanged = byPhase.get("exchanged");
  if (exchanged !== undefined && !same(exchanged.installation, installationRecord(plan))) {
    fail("durable exchanged installation proof drifted");
  }
  const reloaded = byPhase.get("reloaded");
  if (reloaded !== undefined) {
    exactKeys(
      reloaded.reload,
      ["argv", "exit_status", "restart_invoked", "runtime_before"],
      "reloaded state reload",
    );
    if (
      !same(reloaded.reload.argv, plan.transaction.reload_argv) ||
      reloaded.reload.exit_status !== 0 ||
      reloaded.reload.restart_invoked !== false ||
      !same(
        reloaded.reload.runtime_before,
        runtimeBoundaryFromAdminRuntime(prepared.context.before.admin_runtime),
      )
    ) {
      fail("durable reloaded state drifted");
    }
  }
  const rollbackReloaded = byPhase.get("rollback-reloaded");
  if (rollbackReloaded !== undefined) {
    validateRecoveryReceiptComponents({
      after: rollbackReloaded.after,
      approvedPlanSha256,
      context: prepared.context,
      installation: exchanged?.installation ?? installationRecord(plan),
      plan,
      reload: reloaded?.reload ?? {
        argv: structuredClone(plan.transaction.reload_argv),
        exit_status: null,
        restart_invoked: false,
        runtime_before: null,
      },
      rollback: rollbackReloaded.rollback,
    });
  }
  for (const phase of ["committed", "rolled-back"]) {
    const terminal = byPhase.get(phase);
    if (
      terminal !== undefined &&
      (typeof terminal.receipt_sha256 !== "string" ||
        !/^[0-9a-f]{64}$/u.test(terminal.receipt_sha256))
    ) {
      fail(`durable ${phase} receipt digest is malformed`);
    }
  }
  const required = [
    ["exchanged", "prepared"],
    ["reloaded", "exchanged"],
    ["rollback-reloaded", "rollback-exchanged"],
    ["committed", "reloaded"],
    ["rolled-back", "rollback-reloaded"],
    ["aborted-before-install", "prepared"],
  ];
  for (const [phase, predecessor] of required) {
    const record = byPhase.get(phase);
    if (record !== undefined) {
      if (record.previous_phase !== predecessor) {
        fail(`durable ${phase} state has the wrong predecessor`);
      }
      if (!byPhase.has(predecessor)) {
        fail(`durable ${phase} state is missing predecessor ${predecessor}`);
      }
    }
  }
  const rollbackExchanged = byPhase.get("rollback-exchanged");
  if (
    rollbackExchanged !== undefined &&
    (!["exchanged", "reloaded"].includes(rollbackExchanged.previous_phase) ||
      !byPhase.has(rollbackExchanged.previous_phase))
  ) {
    fail("durable rollback-exchanged state has the wrong predecessor");
  }
  if (byPhase.has("committed") && (byPhase.has("rolled-back") || byPhase.has("rollback-exchanged"))) {
    fail("durable state contains contradictory terminal branches");
  }
  if (
    byPhase.has("aborted-before-install") &&
    [...byPhase.keys()].some((phase) => !["prepared", "aborted-before-install"].includes(phase))
  ) {
    fail("durable state contains both aborted and post-install branches");
  }
  return { byPhase, prepared };
}

async function reconcileStateJournal({
  approvedPlanSha256,
  currentDirectorySeals,
  ops,
  plan,
  stateDirectorySeal,
}) {
  let entries;
  try {
    const first = await ops.readStateRecords(
      plan.transaction.state_directory,
      stateDirectorySeal,
    );
    // A process can die after renameat2 made a final phase name visible but
    // before either helper or executor fsynced the directory. Establish that
    // durability before any record influences target/candidate mutation, then
    // require a stable exact byte-for-byte journal reread.
    await ops.fsyncParent(
      `${plan.transaction.state_directory}/.journal-durability`,
      stateDirectorySeal,
    );
    const second = await ops.readStateRecords(
      plan.transaction.state_directory,
      stateDirectorySeal,
    );
    if (
      first.size !== second.size ||
      [...first].some(([name, bytes]) => !second.get(name)?.equals(bytes))
    ) {
      fail("phase journal changed across its durability confirmation");
    }
    entries = second;
  } catch (error) {
    throw outcomeUnknown(
      `phase journal durability is unknown; refusing recovery mutation: ${error.message}`,
      error,
    );
  }
  const finalNames = new Set(Object.values(OVERLAY_STATE_FILES));
  const proposed = new Map();
  const pendingToRemove = [];
  const pendingToPublish = [];
  for (const [name, bytes] of entries) {
    if (finalNames.has(name)) proposed.set(name, Buffer.from(bytes));
  }
  for (const [name, bytes] of entries) {
    if (!name.endsWith(".pending")) continue;
    const finalName = name.slice(0, -".pending".length);
    if (!finalNames.has(finalName)) fail(`unknown pending phase journal entry ${name}`);
    const pendingPath = `${plan.transaction.state_directory}/${name}`;
    const pending = await ops.readRegular(pendingPath);
    ownerOnlyRecordShape(pending.snapshot, pendingPath, `pending phase ${finalName}`);
    if (!pending.bytes.equals(bytes)) fail(`pending phase ${finalName} changed during recovery read`);
    const finalBytes = proposed.get(finalName);
    if (finalBytes !== undefined) {
      if (!Buffer.from(finalBytes).equals(bytes)) {
        fail(`final and pending phase ${finalName} records disagree`);
      }
      pendingToRemove.push({ path: pendingPath, snapshot: pending.snapshot });
      continue;
    }
    try {
      parseStrictJson(Buffer.from(bytes).toString("utf8"), `pending state ${name}`);
    } catch {
      // A process death can expose an exclusively-created pending inode before
      // its write or file fsync completed. It is never authoritative by name.
      pendingToRemove.push({ path: pendingPath, snapshot: pending.snapshot });
      continue;
    }
    proposed.set(finalName, Buffer.from(bytes));
    pendingToPublish.push({ bytes: Buffer.from(bytes), finalName, pendingPath });
  }
  // Validate the complete proposed append-only chain before publishing any
  // pending member. This prevents a well-formed but contradictory suffix from
  // becoming authoritative merely because its JSON parses.
  const proposedModel = loadRecoveryModel(proposed, plan, approvedPlanSha256);
  if (pendingToPublish.length > 1) {
    fail("more than one unpublished phase exists; refusing a non-sequential journal suffix");
  }
  if (proposedModel.prepared !== undefined) {
    const recorded = validateRecordedDirectorySeals(
      proposedModel.prepared.context.directory_seals,
      plan,
    );
    for (const [path, seal] of recorded) {
      if (!same(currentDirectorySeals.get(path), seal)) {
        fail(`mutable transaction directory ${path} changed across crash recovery`);
      }
    }
  }
  for (const pending of pendingToRemove) {
    await ops.removeIfExact(pending.path, pending.snapshot, stateDirectorySeal);
  }
  for (const pending of pendingToPublish) {
    const finalPath = `${plan.transaction.state_directory}/${pending.finalName}`;
    let observed;
    try {
      observed = await settleAtomicPublication({
        bytes: pending.bytes,
        finalPath,
        helperPin: plan.runtime.exchange_helper,
        label: `recovery phase ${pending.finalName}`,
        ops,
        parentSeal: stateDirectorySeal,
        pendingPath: pending.pendingPath,
        publish: (...args) => ops.publishPendingState(...args),
      });
    } catch (error) {
      throw outcomeUnknown(
        `recovery phase ${pending.finalName} publication outcome is unknown: ${error.message}`,
        error,
      );
    }
    if (observed === null) fail(`valid pending phase ${pending.finalName} vanished`);
  }
  const confirmed = await ops.readStateRecords(
    plan.transaction.state_directory,
    stateDirectorySeal,
  );
  for (const name of confirmed.keys()) {
    if (name.endsWith(".pending")) fail(`pending phase journal entry survived reconciliation: ${name}`);
  }
  return confirmed;
}

async function classifyPair(plan, ops, candidateSnapshot) {
  const live = await ops.readRegular(TARGET_CONFIG);
  const candidate = await ops.readOptionalRegular(plan.transaction.candidate_path);
  const liveDigest = live.snapshot.sha256;
  const candidateDigest = candidate?.snapshot.sha256;
  if (
    liveDigest === plan.target.config_preimage.sha256 &&
    candidateDigest === plan.managed_block.candidate_sha256
  ) {
    assertExchangeIdentity(live.snapshot, plan.target.config_preimage, TARGET_CONFIG, "recovery live preimage");
    if (candidateSnapshot !== undefined) {
      assertExchangeIdentity(candidate.snapshot, candidateSnapshot, plan.transaction.candidate_path, "recovery candidate");
    }
    return { candidate, kind: "rolled-back", live };
  }
  if (
    liveDigest === plan.managed_block.candidate_sha256 &&
    candidateDigest === plan.target.config_preimage.sha256
  ) {
    if (candidateSnapshot !== undefined) {
      assertExchangeIdentity(live.snapshot, candidateSnapshot, TARGET_CONFIG, "recovery live candidate");
    } else {
      assertFinalConfig(live.snapshot, plan.managed_block.candidate_sha256, "recovery live candidate");
    }
    assertExchangeIdentity(candidate.snapshot, plan.target.config_preimage, plan.transaction.candidate_path, "recovery swapped preimage");
    return { candidate, kind: "installed", live };
  }
  if (liveDigest === plan.target.config_preimage.sha256 && candidate === null) {
    assertExchangeIdentity(live.snapshot, plan.target.config_preimage, TARGET_CONFIG, "recovery live preimage");
    return { candidate: null, kind: "preimage-only", live };
  }
  if (liveDigest === plan.managed_block.candidate_sha256 && candidate === null) {
    assertFinalConfig(live.snapshot, plan.managed_block.candidate_sha256, "recovery committed candidate");
    return { candidate: null, kind: "candidate-only", live };
  }
  fail("recovery found an unknown target/candidate digest combination; refusing to overwrite either entry");
}

function pendingReceiptShape(snapshot, plan) {
  ownerOnlyRecordShape(
    snapshot,
    plan.transaction.receipt_pending_path,
    "pending receipt",
  );
}

function finalReceiptShape(snapshot, plan) {
  ownerOnlyRecordShape(snapshot, plan.transaction.receipt_path, "final receipt");
}

async function readAndValidateReceipt(
  ops,
  plan,
  approvedPlanSha256,
  pairKind,
  receiptParentSeal,
) {
  let observed = await ops.readOptionalRegular(plan.transaction.receipt_path);
  const pending = await ops.readOptionalRegular(plan.transaction.receipt_pending_path);
  if (observed === null && pending !== null) {
    pendingReceiptShape(pending.snapshot, plan);
    let pendingReceipt;
    try {
      pendingReceipt = parseStrictJson(pending.bytes.toString("utf8"), "pending overlay receipt");
      validateOverlayReceipt({
        approvedPlanSha256,
        plan,
        receipt: pendingReceipt,
        trustedReceiptSha256: pending.snapshot.sha256,
      });
    } catch {
      // A crash can leave the exclusively-created pending entry before its
      // bytes or fsync complete. Its exact owner-only transaction name is not
      // authoritative until strict receipt validation succeeds.
      await ops.removeIfExact(
        plan.transaction.receipt_pending_path,
        pending.snapshot,
        receiptParentSeal,
      );
      return null;
    }
    const expectedPairs = pendingReceipt.outcome === "committed"
      ? ["installed", "candidate-only"]
      : ["rolled-back", "preimage-only"];
    if (!expectedPairs.includes(pairKind)) {
      fail("valid pending receipt contradicts the exact target/candidate file pair");
    }
    try {
      observed = await settleAtomicPublication({
        bytes: pending.bytes,
        finalPath: plan.transaction.receipt_path,
        helperPin: plan.runtime.exchange_helper,
        label: "recovery terminal receipt",
        ops,
        parentSeal: receiptParentSeal,
        pendingPath: plan.transaction.receipt_pending_path,
        publish: (...args) => ops.publishPendingReceipt(...args),
      });
    } catch (error) {
      throw outcomeUnknown(
        `recovery receipt publication outcome is unknown: ${error.message}`,
        error,
      );
    }
    if (observed === null) fail("valid pending receipt vanished before publication");
  } else if (observed !== null && pending !== null) {
    pendingReceiptShape(pending.snapshot, plan);
    if (!pending.bytes.equals(observed.bytes)) {
      fail("final and pending receipt entries disagree");
    }
    try {
      observed = await settleAtomicPublication({
        bytes: observed.bytes,
        finalPath: plan.transaction.receipt_path,
        helperPin: plan.runtime.exchange_helper,
        label: "recovery duplicate terminal receipt",
        ops,
        parentSeal: receiptParentSeal,
        pendingPath: plan.transaction.receipt_pending_path,
        publish: (...args) => ops.publishPendingReceipt(...args),
      });
    } catch (error) {
      throw outcomeUnknown(
        `recovery duplicate receipt cleanup outcome is unknown: ${error.message}`,
        error,
      );
    }
  }
  if (observed === null) return null;
  finalReceiptShape(observed.snapshot, plan);
  let confirmed;
  try {
    await ops.fsyncParent(plan.transaction.receipt_path, receiptParentSeal);
    confirmed = await ops.readRegular(plan.transaction.receipt_path);
    finalReceiptShape(confirmed.snapshot, plan);
    if (!same(observed.snapshot, confirmed.snapshot) || !observed.bytes.equals(confirmed.bytes)) {
      fail("final receipt changed across its durability confirmation");
    }
  } catch (error) {
    throw outcomeUnknown(
      `final receipt durability is unknown; refusing recovery mutation: ${error.message}`,
      error,
    );
  }
  observed = confirmed;
  const receipt = parseStrictJson(observed.bytes.toString("utf8"), "durable overlay receipt");
  validateOverlayReceipt({
    approvedPlanSha256,
    plan,
    receipt,
    trustedReceiptSha256: observed.snapshot.sha256,
  });
  return { observed, receipt };
}

async function recoverLocked({ approvedPlanSha256, ops, plan }) {
  const parentSeals = await sealMutableParents(plan, ops);
  const stateDirectorySeal = await ops.sealStateDirectory(plan.transaction.state_directory);
  const currentDirectorySeals = new Map([
    ...parentSeals,
    [plan.transaction.state_directory, stateDirectorySeal],
  ]);
  const records = await reconcileStateJournal({
    approvedPlanSha256,
    currentDirectorySeals,
    ops,
    plan,
    stateDirectorySeal,
  });
  const model = loadRecoveryModel(records, plan, approvedPlanSha256);
  if (model.prepared !== undefined) {
    const recorded = validateRecordedDirectorySeals(
      model.prepared.context.directory_seals,
      plan,
    );
    for (const [path, seal] of recorded) {
      if (!same(currentDirectorySeals.get(path), seal)) {
        fail(`mutable transaction directory ${path} changed across crash recovery`);
      }
    }
  }
  // Re-bind the currently loaded unit and the live Caddy process before any
  // recovery classification can authorize target mutation, reload or cleanup.
  const recoveryState = await collectPinnedState(plan, ops, "recovery initial", {
    expectedAdminRuntime: "either-reviewed",
    requirePreimage: false,
  });
  const candidateSnapshot = model.prepared?.candidate_snapshot;
  const pair = await classifyDurablePair(
    plan,
    ops,
    candidateSnapshot,
    "crash recovery initial classification",
  );
  const durableReceipt = await readAndValidateReceipt(
    ops,
    plan,
    approvedPlanSha256,
    pair.kind,
    sealFor(parentSeals, plan.transaction.receipt_path),
  );
  if (durableReceipt !== null) {
    const expectedPair = durableReceipt.receipt.outcome === "committed"
      ? ["installed", "candidate-only"]
      : ["rolled-back", "preimage-only"];
    if (!expectedPair.includes(pair.kind)) {
      fail("durable receipt outcome contradicts the exact recovery file pair");
    }
    const terminalPhase = durableReceipt.receipt.outcome === "committed" ? "committed" : "rolled-back";
    const terminalPredecessor = terminalPhase === "committed" ? "reloaded" : "rollback-reloaded";
    if (!model.byPhase.has(terminalPredecessor)) {
      fail(`durable ${terminalPhase} receipt is missing predecessor ${terminalPredecessor}`);
    }
    const terminalRecord = model.byPhase.get(terminalPhase);
    if (
      terminalRecord !== undefined &&
      terminalRecord.receipt_sha256 !== durableReceipt.observed.snapshot.sha256
    ) {
      fail("terminal state receipt digest contradicts the durable receipt");
    }
    // The receipt proves the live config at publication time, not forever.
    // Re-probe the current admin body with the terminal outcome's exact
    // generation before recovery can publish terminal state or remove the
    // remaining file-pair witness.
    await collectPinnedState(plan, ops, `recovery durable ${terminalPhase}`, {
      expectedAdminRuntime: terminalPhase === "committed"
        ? "managed-candidate"
        : "hardened-preimage",
      requirePreimage: false,
    });
    if (!model.byPhase.has(terminalPhase)) {
      await writeState(
        ops,
        plan,
        stateRecord(
          plan,
          approvedPlanSha256,
          terminalPhase,
          terminalPredecessor,
          { receipt_sha256: durableReceipt.observed.snapshot.sha256 },
        ),
        stateDirectorySeal,
      );
    }
    if (pair.candidate !== null) {
      await ops.removeIfExact(
        plan.transaction.candidate_path,
        terminalPhase === "committed"
          ? { ...plan.target.config_preimage, path: plan.transaction.candidate_path }
          : candidateSnapshot,
        plan.target.config_parent,
      );
    }
    return durableReceipt.receipt;
  }
  if (model.byPhase.has("committed") || model.byPhase.has("rolled-back")) {
    fail("terminal state exists without its exact durable receipt");
  }
  if (pair.kind === "preimage-only") {
    if (model.byPhase.size === 0 || model.byPhase.has("aborted-before-install")) {
      await collectPinnedState(plan, ops, "recovery aborted preimage-only", {
        expectedAdminRuntime: "hardened-preimage",
        requirePreimage: false,
      });
      return { outcome: "aborted-before-install", transaction_id: plan.transaction_id };
    }
    fail("recovery is missing the candidate required to prove an unfinished transaction");
  }
  if (pair.kind === "rolled-back" && !model.byPhase.has("exchanged")) {
    await collectPinnedState(plan, ops, "recovery aborted rolled-back pair", {
      expectedAdminRuntime: "hardened-preimage",
      requirePreimage: false,
    });
    if (model.byPhase.size === 0) {
      await ops.removeIfExact(
        plan.transaction.candidate_path,
        pair.candidate.snapshot,
        plan.target.config_parent,
      );
      return { outcome: "aborted-before-install", transaction_id: plan.transaction_id };
    }
    if (!model.byPhase.has("aborted-before-install")) {
      await writeState(
        ops,
        plan,
        stateRecord(plan, approvedPlanSha256, "aborted-before-install", "prepared"),
        stateDirectorySeal,
      );
    }
    await ops.removeIfExact(
      plan.transaction.candidate_path,
      candidateSnapshot,
      plan.target.config_parent,
    );
    return { outcome: "aborted-before-install", transaction_id: plan.transaction_id };
  }
  if (pair.kind === "installed") {
    if (!model.byPhase.has("exchanged")) {
      const installation = installationRecord(plan);
      await writeState(
        ops,
        plan,
        stateRecord(plan, approvedPlanSha256, "exchanged", "prepared", { installation }),
        stateDirectorySeal,
      );
      model.byPhase.set("exchanged", { installation });
    }
    await collectStableCaddyRuntimeBoundary(
      plan,
      recoveryState.hardening,
      ops,
      "recovery pre-rollback-exchange",
    );
    await exchangeInstalledPairForRollback(plan, ops, candidateSnapshot);
    if (!model.byPhase.has("rollback-exchanged")) {
      await writeState(
        ops,
        plan,
        stateRecord(
          plan,
          approvedPlanSha256,
          "rollback-exchanged",
          model.byPhase.has("reloaded") ? "reloaded" : "exchanged",
        ),
        stateDirectorySeal,
      );
      model.byPhase.set("rollback-exchanged", {});
    }
  } else if (pair.kind !== "rolled-back") {
    fail("recovery cannot prove a rollback-safe file pair");
  }
  if (pair.kind === "rolled-back" && !model.byPhase.has("rollback-exchanged")) {
    await writeState(
      ops,
      plan,
      stateRecord(
        plan,
        approvedPlanSha256,
        "rollback-exchanged",
        model.byPhase.has("reloaded") ? "reloaded" : "exchanged",
      ),
      stateDirectorySeal,
    );
    model.byPhase.set("rollback-exchanged", {});
  }
  const prepared = model.prepared;
  if (prepared === undefined) fail("rollback recovery lacks its durable prepared context");
  const exchangedRecord = model.byPhase.get("exchanged");
  const installation = exchangedRecord.installation ?? installationRecord(plan);
  const reloadedRecord = model.byPhase.get("reloaded");
  const reload = reloadedRecord?.reload ?? {
    argv: structuredClone(plan.transaction.reload_argv),
    exit_status: null,
    restart_invoked: false,
    runtime_before: null,
  };
  const rollbackRuntimeBefore = await collectStableCaddyRuntimeBoundary(
    plan,
    recoveryState.hardening,
    ops,
    "recovery pre-rollback-reload",
  );
  const rollbackReload = await ops.run(plan.transaction.reload_argv, {
    captureStdout: false,
    maxBytes: MAX_COMMAND_BYTES,
    timeoutMs: 30_000,
  });
  if (rollbackReload.status !== 0) fail("recovery rollback reload failed");
  const restoredState = await collectPinnedState(plan, ops, "recovery post-rollback", {
    expectedAdminRuntime: "hardened-preimage",
    requirePreimage: false,
  });
  const finalConfig = await ops.readRegular(TARGET_CONFIG);
  assertFinalConfig(finalConfig.snapshot, plan.target.config_preimage.sha256, "recovery restored Caddyfile");
  const rollback = {
    attempted: true,
    directory_fsync: true,
    exact_candidate_swapped_out: true,
    exact_preimage_restored: true,
    exchanged: true,
    reload_exit_status: rollbackReload.status,
    runtime_before: rollbackRuntimeBefore,
  };
  const after = receiptSnapshot(plan, restoredState, finalConfig.snapshot);
  if (!model.byPhase.has("rollback-reloaded")) {
    await writeState(
      ops,
      plan,
      stateRecord(plan, approvedPlanSha256, "rollback-reloaded", "rollback-exchanged", {
        after,
        rollback,
      }),
      stateDirectorySeal,
    );
  }
  const context = prepared.context;
  const receipt = baseReceipt({
    after,
    approvedPlanSha256,
    backup: context.backup,
    before: context.before,
    healthResults: [],
    host: context.host,
    installation,
    outcome: "rolled-back",
    plan,
    preparation: context.preparation,
    reload,
    rollback,
  });
  const digest = await writeReceipt(
    ops,
    plan,
    approvedPlanSha256,
    receipt,
    sealFor(parentSeals, plan.transaction.receipt_path),
  );
  await writeState(
    ops,
    plan,
    stateRecord(plan, approvedPlanSha256, "rolled-back", "rollback-reloaded", {
      receipt_sha256: digest,
    }),
    stateDirectorySeal,
  );
  await ops.removeIfExact(
    plan.transaction.candidate_path,
    candidateSnapshot,
    plan.target.config_parent,
  );
  return receipt;
}

export async function recoverOverlayTransaction({ approvedPlanSha256, ops, plan }) {
  validateOverlayPlan(plan);
  if (computeApprovedOverlayPlanSha256(plan) !== approvedPlanSha256) {
    fail("recovery plan does not match its externally approved SHA-256");
  }
  const release = await ops.acquireLock(plan.transaction.lock_path, {
    helperPin: plan.runtime.exchange_helper,
    recoverStale: true,
    transactionId: plan.transaction_id,
  });
  return releasePreservingPrimary(release, () =>
    recoverLocked({ approvedPlanSha256, ops, plan }));
}

function modeString(stat) {
  return (Number(stat.mode & 0o7777n)).toString(8).padStart(4, "0");
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
    size: stat.size.toString(),
    uid: Number(stat.uid),
  };
}

function canonicalAbsolute(path) {
  if (!isAbsolute(path) || resolve(path) !== path || path.includes("//") || path.includes("\0")) {
    fail(`path is not one canonical absolute path: ${path}`);
  }
  return path;
}

function sameInode(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function attachCleanupError(primary, cleanupError) {
  if (primary === cleanupError || primary === null || typeof primary !== "object") return;
  try {
    if (!Array.isArray(primary.cleanupErrors)) primary.cleanupErrors = [];
    primary.cleanupErrors.push(cleanupError);
  } catch {
    // The initiating failure remains authoritative even if a foreign Error
    // object is non-extensible. Cleanup failures must never replace it.
  }
}

function runWithSyncCleanups(operation, cleanups) {
  let primary;
  let value;
  try {
    value = operation();
  } catch (error) {
    primary = error;
  }
  for (const cleanup of cleanups) {
    try {
      cleanup();
    } catch (cleanupError) {
      if (primary === undefined) primary = cleanupError;
      else attachCleanupError(primary, cleanupError);
    }
  }
  if (primary !== undefined) throw primary;
  return value;
}

function openSealedParent(path) {
  canonicalAbsolute(path);
  const components = dirname(path).split("/").filter(Boolean);
  const descriptors = [];
  let fd;
  try {
    fd = openSync(
      "/",
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
    );
    descriptors.push({ fd, path: "/", stat: null });
    descriptors.at(-1).stat = fstatSync(fd, { bigint: true });
    let currentPath = "";
    for (const component of components) {
      currentPath += `/${component}`;
      const next = openSync(
        `/proc/self/fd/${fd}/${component}`,
        constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
      );
      descriptors.push({ fd: next, path: currentPath, stat: null });
      const descriptorStat = fstatSync(next, { bigint: true });
      descriptors.at(-1).stat = descriptorStat;
      const pathStat = lstatSync(currentPath, { bigint: true, throwIfNoEntry: true });
      if (!descriptorStat.isDirectory() || !pathStat.isDirectory() || !sameInode(descriptorStat, pathStat)) {
        fail(`directory parent changed or became a symlink: ${currentPath}`);
      }
      fd = next;
    }
  } catch (error) {
    for (const descriptor of descriptors.reverse()) {
      try {
        closeSync(descriptor.fd);
      } catch {
        // Preserve the traversal failure; no descriptor remains usable here.
      }
    }
    throw error;
  }
  let closed = false;
  return {
    close() {
      if (closed) return;
      closed = true;
      runWithSyncCleanups(
        () => undefined,
        [...descriptors].reverse().map((descriptor) => () => closeSync(descriptor.fd)),
      );
    },
    confirm() {
      for (const descriptor of descriptors) {
        const current = lstatSync(descriptor.path, { bigint: true, throwIfNoEntry: true });
        if (!current.isDirectory() || !sameInode(current, descriptor.stat)) {
          fail(`directory parent drifted during descriptor operation: ${descriptor.path}`);
        }
      }
    },
    fd,
    procPath: `/proc/self/fd/${fd}/${basename(path)}`,
  };
}

function realReadRegular(path, maxBytes = MAX_FILE_BYTES) {
  const parent = openSealedParent(path);
  let fd;
  return runWithSyncCleanups(
    () => {
      fd = openSync(
        parent.procPath,
        constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
      );
      const stat = fstatSync(fd, { bigint: true });
      if (!stat.isFile() || stat.nlink !== 1n || stat.size > BigInt(maxBytes)) {
        fail(`regular-file boundary failed for ${path}`);
      }
      const bytes = readFileSync(fd);
      if (bytes.length > maxBytes) fail(`regular file exceeded its bounded read: ${path}`);
      const confirmation = fstatSync(fd, { bigint: true });
      if (
        !sameInode(confirmation, stat) ||
        confirmation.size !== stat.size ||
        confirmation.ctimeNs !== stat.ctimeNs ||
        confirmation.mtimeNs !== stat.mtimeNs
      ) {
        fail(`regular file changed during descriptor read: ${path}`);
      }
      const pathStat = lstatSync(path, { bigint: true, throwIfNoEntry: true });
      if (!pathStat.isFile() || !sameInode(pathStat, stat)) {
        fail(`regular file path changed or became a symlink during descriptor read: ${path}`);
      }
      parent.confirm();
      return { bytes, snapshot: snapshotFromStat(path, stat, bytes) };
    },
    [
      () => { if (fd !== undefined) closeSync(fd); },
      () => parent.close(),
    ],
  );
}

function pinnedReadLimit(path) {
  if (
    new Set(["/usr/local/bin/caddy", "/usr/bin/node", "/usr/bin/setpriv"]).has(path) ||
    /^\/opt\/bitcoinpir\/(?:haproxy|payment-v1-rename-exchange)\/[0-9a-f]{64}\//u.test(path)
  ) {
    return MAX_EXECUTABLE_BYTES;
  }
  return MAX_FILE_BYTES;
}

function realReadOptionalRegular(path) {
  try {
    return realReadRegular(path);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

function realReadDirectory(path) {
  const parent = openSealedParent(`${path}/.directory-pin`);
  return runWithSyncCleanups(
    () => {
      const stat = fstatSync(parent.fd, { bigint: true });
      parent.confirm();
      return {
        device: stat.dev.toString(),
        gid: Number(stat.gid),
        inode: stat.ino.toString(),
        mode: modeString(stat),
        path,
        uid: Number(stat.uid),
      };
    },
    [() => parent.close()],
  );
}

function realReadAdminRuntimePath(path) {
  if (![ADMIN_DIRECTORY, ADMIN_SOCKET].includes(path)) {
    fail(`unreviewed Caddy admin runtime path: ${path}`);
  }
  const parent = openSealedParent(
    path === ADMIN_DIRECTORY ? `${ADMIN_DIRECTORY}/.directory-pin` : path,
  );
  return runWithSyncCleanups(
    () => {
      const stat = path === ADMIN_DIRECTORY
        ? fstatSync(parent.fd, { bigint: true })
        : lstatSync(parent.procPath, { bigint: true, throwIfNoEntry: true });
      const type = stat.isDirectory() ? "directory" : stat.isSocket() ? "socket" : "other";
      const expectedType = path === ADMIN_DIRECTORY ? "directory" : "socket";
      if (type !== expectedType) fail(`${path} is not the required ${expectedType}`);
      if (path === ADMIN_SOCKET) {
        const pathStat = lstatSync(path, { bigint: true, throwIfNoEntry: true });
        if (!pathStat.isSocket() || !sameInode(pathStat, stat)) {
          fail(`${path} changed or became a symlink during the sealed runtime read`);
        }
      }
      parent.confirm();
      return {
        ctime_ns: stat.ctimeNs.toString(),
        device: stat.dev.toString(),
        gid: Number(stat.gid),
        inode: stat.ino.toString(),
        mode: modeString(stat),
        path,
        type,
        uid: Number(stat.uid),
      };
    },
    [() => parent.close()],
  );
}

function assertDirectorySeal(parent, path, expected, label) {
  if (expected === undefined) return;
  const stat = fstatSync(parent.fd, { bigint: true });
  const actual = {
    device: stat.dev.toString(),
    gid: Number(stat.gid),
    inode: stat.ino.toString(),
    mode: modeString(stat),
    path: dirname(path),
    uid: Number(stat.uid),
  };
  if (!same(actual, expected)) fail(`${label} parent directory drifted from its invocation seal`);
}

function fsyncParent(path, expectedParent) {
  const parent = openSealedParent(path);
  runWithSyncCleanups(
    () => {
      assertDirectorySeal(parent, path, expectedParent, "fsync");
      fsyncSync(parent.fd);
      parent.confirm();
      assertDirectorySeal(parent, path, expectedParent, "confirmed fsync");
    },
    [() => parent.close()],
  );
}

function fsyncRegularExact(path, expectedSnapshot, expectedParent) {
  const parent = openSealedParent(path);
  let fd;
  runWithSyncCleanups(
    () => {
      assertDirectorySeal(parent, path, expectedParent, "regular fsync");
      fd = openSync(
        parent.procPath,
        constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
      );
      const stat = fstatSync(fd, { bigint: true });
      if (!stat.isFile() || stat.nlink !== 1n || stat.size > BigInt(MAX_FILE_BYTES)) {
        fail(`regular fsync boundary failed for ${path}`);
      }
      const bytes = readFileSync(fd);
      const snapshot = snapshotFromStat(path, stat, bytes);
      if (!same(snapshot, expectedSnapshot)) fail(`regular fsync target drifted: ${path}`);
      fsyncSync(fd);
      const confirmation = fstatSync(fd, { bigint: true });
      if (!sameInode(confirmation, stat) || confirmation.ctimeNs !== stat.ctimeNs ||
          confirmation.mtimeNs !== stat.mtimeNs || confirmation.size !== stat.size) {
        fail(`regular fsync target changed during sync: ${path}`);
      }
      parent.confirm();
      assertDirectorySeal(parent, path, expectedParent, "confirmed regular fsync");
    },
    [
      () => { if (fd !== undefined) closeSync(fd); },
      () => parent.close(),
    ],
  );
}

function injectFault(faultInjector, point) {
  if (faultInjector !== undefined) faultInjector(point);
}

function realWriteExclusive(path, bytes, mode, expectedParent, faultInjector) {
  if (!Buffer.isBuffer(bytes) || bytes.length > MAX_FILE_BYTES) {
    fail(`exclusive write is not one bounded byte buffer: ${path}`);
  }
  const parent = openSealedParent(path);
  const numericMode = Number.parseInt(mode, 8);
  let fd;
  runWithSyncCleanups(
    () => {
      assertDirectorySeal(parent, path, expectedParent, "exclusive write");
      injectFault(faultInjector, "before-open");
      fd = openSync(
        parent.procPath,
        constants.O_WRONLY |
          constants.O_CREAT |
          constants.O_EXCL |
          constants.O_NOFOLLOW |
          constants.O_CLOEXEC,
        numericMode,
      );
      injectFault(faultInjector, "after-open");
      fchmodSync(fd, numericMode);
      fchownSync(fd, 0, 0);
      if (faultInjector === undefined || bytes.length < 2) {
        writeFileSync(fd, bytes);
      } else {
        const split = Math.floor(bytes.length / 2);
        writeFileSync(fd, bytes.subarray(0, split));
        injectFault(faultInjector, "after-partial-write");
        writeFileSync(fd, bytes.subarray(split));
      }
      injectFault(faultInjector, "after-write");
      fsyncSync(fd);
      injectFault(faultInjector, "after-file-fsync");
      parent.confirm();
      assertDirectorySeal(parent, path, expectedParent, "exclusive write confirmation");
      injectFault(faultInjector, "before-pending-dir-fsync");
      fsyncSync(parent.fd);
      injectFault(faultInjector, "after-pending-dir-fsync");
      parent.confirm();
      assertDirectorySeal(parent, path, expectedParent, "exclusive write durable confirmation");
    },
    [
      () => { if (fd !== undefined) closeSync(fd); },
      () => parent.close(),
    ],
  );
  if (expectedParent !== undefined) {
    const parentConfirmation = realReadDirectory(dirname(path));
    if (!same(parentConfirmation, expectedParent)) {
      fail(`exclusive write parent changed before final readback: ${path}`);
    }
  }
  const observed = realReadRegular(path);
  if (expectedParent !== undefined) {
    const parentConfirmation = realReadDirectory(dirname(path));
    if (!same(parentConfirmation, expectedParent)) {
      fail(`exclusive write parent changed after final readback: ${path}`);
    }
  }
  return {
    directoryFsync: true,
    exclusiveCreate: true,
    fileFsync: true,
    snapshot: observed.snapshot,
  };
}

function realRemoveIfExact(path, expectedSnapshot, expectedParent) {
  const parent = openSealedParent(path);
  let fd;
  runWithSyncCleanups(
    () => {
      assertDirectorySeal(parent, path, expectedParent, "exact removal");
      try {
        fd = openSync(
          parent.procPath,
          constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
        );
      } catch (error) {
        if (error?.code === "ENOENT") {
          // Absence can itself be the visible but not-yet-durable result of a
          // prior crashed unlink. Commit and reconfirm the directory before
          // reporting the idempotent removal complete.
          fsyncSync(parent.fd);
          parent.confirm();
          assertDirectorySeal(parent, path, expectedParent, "durable exact absence");
          const confirmation = lstatSync(parent.procPath, {
            bigint: true,
            throwIfNoEntry: false,
          });
          if (confirmation !== undefined) fail(`exact removal entry reappeared: ${path}`);
          return;
        }
        throw error;
      }
      const stat = fstatSync(fd, { bigint: true });
      if (!stat.isFile() || stat.nlink !== 1n || stat.size > BigInt(MAX_FILE_BYTES)) {
        fail(`exact removal boundary failed for ${path}`);
      }
      const bytes = readFileSync(fd);
      const snapshot = snapshotFromStat(path, stat, bytes);
      assertExchangeIdentity(snapshot, expectedSnapshot, path, "exact removal entry");
      const pathStat = lstatSync(parent.procPath, { bigint: true, throwIfNoEntry: true });
      if (!pathStat.isFile() || !sameInode(pathStat, stat)) {
        fail(`exact removal pathname drifted: ${path}`);
      }
      parent.confirm();
      assertDirectorySeal(parent, path, expectedParent, "confirmed exact removal");
      unlinkSync(parent.procPath);
      fsyncSync(parent.fd);
      parent.confirm();
      assertDirectorySeal(parent, path, expectedParent, "durable exact removal");
    },
    [
      () => { if (fd !== undefined) closeSync(fd); },
      () => parent.close(),
    ],
  );
}

function commandResult(argv, { captureStdout, maxBytes, timeoutMs, extraFd } = {}) {
  const stdio = ["ignore", captureStdout ? "pipe" : "ignore", "pipe"];
  if (extraFd !== undefined) stdio.push(extraFd);
  const result = spawnSync(argv[0], argv.slice(1), {
    encoding: null,
    env: { LANG: "C", LC_ALL: "C", PATH: "/usr/sbin:/usr/bin:/sbin:/bin" },
    killSignal: "SIGKILL",
    maxBuffer: maxBytes,
    shell: false,
    stdio,
    timeout: timeoutMs,
  });
  return {
    status: result.status ?? 255,
    stderr: result.stderr ?? Buffer.alloc(0),
    stdout: result.stdout ?? Buffer.alloc(0),
  };
}

function pinnedDescriptorSnapshot(fd, pin, label, maxBytes, retainBytes = false) {
  const stat = fstatSync(fd, { bigint: true });
  if (!stat.isFile() || stat.nlink !== 1n || stat.size > BigInt(maxBytes)) {
    fail(`${label} is not one bounded single-link regular file`);
  }
  const bytes = readFileSync(fd);
  const snapshot = snapshotFromStat(pin.path, stat, bytes);
  exactRegularSnapshot(snapshot, pin, label);
  return retainBytes ? { bytes, stat } : { stat };
}

export function runPinnedAdminProbe({ expected, gatePin, gid, label, nodePin, probePin, setprivPin, uid }) {
  if (!new Set(["EACCES", "root-readback"]).has(expected)) fail("unreviewed admin probe expectation");
  if (!Number.isSafeInteger(uid) || !Number.isSafeInteger(gid) || uid < 0 || gid < 0) {
    fail("admin probe UID/GID is invalid");
  }
  const gateParent = openSealedParent(gatePin.path);
  const nodeParent = openSealedParent(nodePin.path);
  const probeParent = openSealedParent(probePin.path);
  const setprivParent = openSealedParent(setprivPin.path);
  let gateFd;
  let nodeFd;
  let probeFd;
  let setprivFd;
  return runWithSyncCleanups(
    () => {
      gateFd = openSync(
        gateParent.procPath,
        constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
      );
      nodeFd = openSync(
        nodeParent.procPath,
        constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
      );
      probeFd = openSync(
        probeParent.procPath,
        constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
      );
      setprivFd = openSync(
        setprivParent.procPath,
        constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
      );
      const gateSnapshot = pinnedDescriptorSnapshot(
        gateFd,
        gatePin,
        "admin probe gate source",
        MAX_FILE_BYTES,
        true,
      );
      const nodeStat = pinnedDescriptorSnapshot(
        nodeFd,
        nodePin,
        "admin probe Node binary",
        MAX_EXECUTABLE_BYTES,
      ).stat;
      const probeStat = pinnedDescriptorSnapshot(
        probeFd,
        probePin,
        "admin probe script",
        MAX_FILE_BYTES,
      ).stat;
      const setprivStat = pinnedDescriptorSnapshot(
        setprivFd,
        setprivPin,
        "admin probe setpriv binary",
        MAX_EXECUTABLE_BYTES,
      ).stat;
      gateParent.confirm();
      nodeParent.confirm();
      probeParent.confirm();
      setprivParent.confirm();
      const result = spawnSync("/proc/self/fd/5", [
        `--reuid=${uid}`,
        `--regid=${gid}`,
        "--clear-groups",
        "--no-new-privs",
        "--bounding-set=-all",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "/proc/self/fd/4",
        "/proc/self/fd/3",
      ], {
        encoding: null,
        env: {
          BPIR_ADMIN_PROBE_FORMAT: "json",
          BPIR_ADMIN_GATE_SHA256: gatePin.sha256,
          BPIR_ADMIN_PROBE_LABEL: label,
          BPIR_EXPECT_ADMIN_PROBE: expected,
          LANG: "C",
          LC_ALL: "C",
          PATH: "/usr/sbin:/usr/bin:/sbin:/bin",
        },
        killSignal: "SIGKILL",
        input: gateSnapshot.bytes,
        maxBuffer: 2 * 1024 * 1024,
        shell: false,
        stdio: ["pipe", "pipe", "pipe", probeFd, nodeFd, setprivFd],
        timeout: 5_000,
      });
      for (const [fd, before, descriptorLabel] of [
        [gateFd, gateSnapshot.stat, "gate source"],
        [nodeFd, nodeStat, "Node binary"],
        [probeFd, probeStat, "probe script"],
        [setprivFd, setprivStat, "setpriv binary"],
      ]) {
        const after = fstatSync(fd, { bigint: true });
        if (
          !sameInode(after, before) || after.ctimeNs !== before.ctimeNs ||
          after.mtimeNs !== before.mtimeNs || after.size !== before.size
        ) {
          fail(`admin probe ${descriptorLabel} drifted during descriptor execution`);
        }
      }
      if (result.status !== 0) {
        fail(`admin probe ${label} failed: ${(result.stderr ?? Buffer.alloc(0)).toString("utf8").trim()}`);
      }
      const stdout = result.stdout ?? Buffer.alloc(0);
      if (!stdout.toString("utf8").endsWith("\n") || stdout.subarray(0, -1).includes(0x0a)) {
        fail(`admin probe ${label} did not return one canonical JSON line`);
      }
      const value = parseStrictJson(stdout.subarray(0, -1).toString("utf8"), `admin probe ${label}`);
      if (!stdout.subarray(0, -1).equals(Buffer.from(canonicalJson(value).slice(0, -1), "utf8"))) {
        fail(`admin probe ${label} JSON was not canonical`);
      }
      gateParent.confirm();
      nodeParent.confirm();
      probeParent.confirm();
      setprivParent.confirm();
      return value;
    },
    [
      () => { if (setprivFd !== undefined) closeSync(setprivFd); },
      () => { if (probeFd !== undefined) closeSync(probeFd); },
      () => { if (nodeFd !== undefined) closeSync(nodeFd); },
      () => { if (gateFd !== undefined) closeSync(gateFd); },
      () => setprivParent.close(),
      () => probeParent.close(),
      () => nodeParent.close(),
      () => gateParent.close(),
    ],
  );
}

function tcpAdminRefusal(endpoint) {
  const address = endpoint === "127.0.0.1:2019" ? "127.0.0.1" : endpoint === "[::1]:2019" ? "::1" : null;
  if (address === null) fail(`unreviewed TCP admin endpoint ${endpoint}`);
  return new Promise((resolvePromise, rejectPromise) => {
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (error) rejectPromise(error);
      else resolvePromise(value);
    };
    const socket = netConnect({ host: address, port: 2019 });
    const timer = setTimeout(
      () => finish(new Error(`TCP admin probe timed out for ${endpoint}`)),
      3_000,
    );
    socket.once("connect", () => finish(new Error(`TCP admin remained reachable at ${endpoint}`)));
    socket.once("error", (error) => {
      if (error?.code === "ECONNREFUSED") finish(null, "connection-refused");
      else finish(new Error(`TCP admin probe ${endpoint} failed with ${error?.code ?? error.message}`));
    });
  });
}

function systemctlShowProperties(unitName, properties, { optionalEmpty = [] } = {}) {
  const result = commandResult(
    [
      "/usr/bin/systemctl",
      "show",
      unitName,
      "--no-pager",
      ...properties.map((property) => `--property=${property}`),
    ],
    { captureStdout: true, maxBytes: 256 * 1024, timeoutMs: 10_000 },
  );
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
  for (const key of optionalEmpty) {
    if (!values.has(key)) values.set(key, "");
  }
  if (values.size !== properties.length || properties.some((key) => !values.has(key))) {
    fail(`systemctl show omitted a property for ${unitName}`);
  }
  return values;
}

function unitGeneration(unitName) {
  const properties = [
    "ActiveEnterTimestampMonotonic",
    "ActiveState",
    "CanReload",
    "ControlGroup",
    "InvocationID",
    "MainPID",
    "SubState",
  ];
  const values = systemctlShowProperties(unitName, properties);
  return {
    active_enter_timestamp_monotonic: values.get("ActiveEnterTimestampMonotonic"),
    active_state: values.get("ActiveState"),
    can_reload: values.get("CanReload"),
    control_group: values.get("ControlGroup"),
    invocation_id: values.get("InvocationID"),
    main_pid: values.get("MainPID"),
    sub_state: values.get("SubState"),
    unit_name: unitName,
  };
}

function splitSystemdLiteralWords(value, label) {
  if (value === "") return [];
  if (!/^[A-Za-z0-9_./:@+-]+(?:[\t ]+[A-Za-z0-9_./:@+-]+)*$/u.test(value)) {
    fail(`${label} contains an unreviewed systemd word serialization`);
  }
  return value.split(/[\t ]+/u).sort();
}

function systemdEnvironmentNames(value, label) {
  if (value === "") return [];
  const names = [];
  for (const assignment of value.split(/[\t ]+/u)) {
    const match = /^([A-Za-z_][A-Za-z0-9_]*)=[A-Za-z0-9_./:@%+,-]*$/u.exec(assignment);
    if (match === null || names.includes(match[1])) {
      fail(`${label} contains an unreviewed or duplicate assignment serialization`);
    }
    names.push(match[1]);
  }
  names.sort();
  return names;
}

function extractSingleSystemdExec(value, label) {
  const records = [...value.matchAll(/\{[^{}]*\}/gu)];
  if (records.length !== 1 || records[0][0] !== value.trim()) {
    fail(`${label} must contain exactly one systemd Exec command`);
  }
  const record = records[0][0];
  const path = /(?:^\{[\t ]*|[\t ]*;[\t ]*)path=([^ ;]+)[\t ]*;/u.exec(record)?.[1];
  const argv = /(?:^\{[\t ]*|[\t ]*;[\t ]*)argv\[\]=(.+?)[\t ]*;[\t ]*ignore_errors=/u.exec(record)?.[1]?.trim();
  const ignoreErrors = /(?:^\{[\t ]*|[\t ]*;[\t ]*)ignore_errors=(yes|no)[\t ]*;/u.exec(record)?.[1];
  if (
    path === undefined || argv === undefined || ignoreErrors === undefined ||
    !/^[A-Za-z0-9_./:@+=|-]+(?:[\t ]+[A-Za-z0-9_./:@+=|-]+)*$/u.test(argv)
  ) {
    fail(`${label} has an unreviewed systemd Exec serialization`);
  }
  return { argv, ignore_errors: ignoreErrors, path };
}

const EFFECTIVE_UNIT_PROPERTIES = Object.freeze([
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
]);

function publisherNetnsDependencyFromSystemd(values, label) {
  const words = (property) => splitSystemdLiteralWords(
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

function normalizeEffectiveUnitProperties(values) {
  const dropinPaths = splitSystemdLiteralWords(
    values.get("DropInPaths"),
    "effective Caddy DropInPaths",
  );
  if (!same(dropinPaths, [PUBLISHER_NETNS_DROPIN_PATH])) {
    fail("effective Caddy unit does not have the unique publisher namespace drop-in");
  }
  if (values.get("EnvironmentFiles") !== "") fail("effective Caddy unit has an EnvironmentFile");
  return {
    dropin_paths: dropinPaths,
    environment_names: systemdEnvironmentNames(values.get("Environment"), "effective Caddy Environment"),
    environment_files: [],
    exec_reload: extractSingleSystemdExec(values.get("ExecReload"), "effective Caddy ExecReload"),
    exec_start: extractSingleSystemdExec(values.get("ExecStart"), "effective Caddy ExecStart"),
    fragment_path: values.get("FragmentPath"),
    group: values.get("Group"),
    limit_core: values.get("LimitCORE"),
    memory_swap_max: values.get("MemorySwapMax"),
    need_daemon_reload: values.get("NeedDaemonReload"),
    pass_environment: splitSystemdLiteralWords(values.get("PassEnvironment"), "effective Caddy PassEnvironment"),
    publisher_netns_dependency: publisherNetnsDependencyFromSystemd(
      values,
      "effective Caddy",
    ),
    runtime_directory: splitSystemdLiteralWords(values.get("RuntimeDirectory"), "effective Caddy RuntimeDirectory"),
    runtime_directory_mode: values.get("RuntimeDirectoryMode"),
    runtime_directory_preserve: values.get("RuntimeDirectoryPreserve"),
    standard_error: values.get("StandardError"),
    standard_output: values.get("StandardOutput"),
    umask: values.get("UMask"),
    unset_environment: splitSystemdLiteralWords(values.get("UnsetEnvironment"), "effective Caddy UnsetEnvironment"),
    user: values.get("User"),
  };
}

export function testOnlyNormalizeEffectiveUnitProperties(properties) {
  exactKeys(properties, EFFECTIVE_UNIT_PROPERTIES, "test effective-unit properties");
  return normalizeEffectiveUnitProperties(new Map(Object.entries(properties)));
}

function effectiveUnitState(unitName) {
  if (unitName !== TARGET_UNIT) fail(`unreviewed effective-unit target ${unitName}`);
  const values = systemctlShowProperties(unitName, EFFECTIVE_UNIT_PROPERTIES, {
    optionalEmpty: ["EnvironmentFiles"],
  });
  return normalizeEffectiveUnitProperties(values);
}

function nulTerminatedFields(bytes, label, maxBytes) {
  if (bytes.length === 0 || bytes.length > maxBytes || bytes[bytes.length - 1] !== 0) {
    fail(`${label} is not one bounded NUL-terminated vector`);
  }
  const fields = [];
  let start = 0;
  for (let index = 0; index < bytes.length; index += 1) {
    if (bytes[index] !== 0) continue;
    if (index === start) fail(`${label} contains an empty member`);
    fields.push(bytes.subarray(start, index));
    start = index + 1;
  }
  return fields;
}

function processRuntime(pid) {
  if (typeof pid !== "string" || !/^[1-9][0-9]*$/u.test(pid)) {
    fail("Caddy MainPID is not a positive canonical decimal");
  }
  const cmdlineFields = nulTerminatedFields(
    readFileSync(`/proc/${pid}/cmdline`),
    `Caddy /proc/${pid}/cmdline`,
    64 * 1024,
  );
  const cmdlineArgv = cmdlineFields.map((field) => {
    const value = field.toString("utf8");
    if (!Buffer.from(value, "utf8").equals(field) || !/^[\x20-\x7e]+$/u.test(value)) {
      fail("Caddy cmdline contains a non-canonical argument");
    }
    return value;
  });
  const environmentNames = [];
  for (const field of nulTerminatedFields(
    readFileSync(`/proc/${pid}/environ`),
    `Caddy /proc/${pid}/environ`,
    1024 * 1024,
  )) {
    const separator = field.indexOf(0x3d);
    if (separator < 1) fail("Caddy process environment contains a malformed assignment");
    const nameBytes = field.subarray(0, separator);
    const name = nameBytes.toString("ascii");
    if (!Buffer.from(name, "ascii").equals(nameBytes) || !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name)) {
      fail("Caddy process environment contains a non-canonical name");
    }
    if (environmentNames.includes(name)) fail("Caddy process environment contains a duplicate name");
    environmentNames.push(name);
  }
  environmentNames.sort();
  return {
    caddy_admin_environment_absent: !environmentNames.includes("CADDY_ADMIN"),
    cmdline_argv: cmdlineArgv,
    effective_environment_names: environmentNames,
    main_pid: pid,
    start_time_ticks: processStartTicks(Number(pid)),
  };
}

function runtimePath(path) {
  const stat = lstatSync(path, { bigint: true });
  return {
    file_type: stat.isDirectory() ? "directory" : stat.isSocket() ? "socket" : "other",
    gid: Number(stat.gid),
    mode: modeString(stat),
    path,
    uid: Number(stat.uid),
  };
}

function parseHeaders(headerBytes, lane) {
  const lines = headerBytes.toString("ascii").split("\r\n");
  const match = /^HTTP\/1\.[01] ([0-9]{3})(?: |$)/u.exec(lines.shift() ?? "");
  if (!match) fail(`malformed health response status for ${lane}`);
  const headers = new Map();
  for (const line of lines) {
    const separator = line.indexOf(":");
    if (separator < 1) fail(`malformed health response header for ${lane}`);
    const name = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    if (headers.has(name)) fail(`duplicate health response header ${name} for ${lane}`);
    headers.set(name, value);
  }
  return { headers, status: Number(match[1]) };
}

export function verifyWebSocketUpgrade({
  expectedStatus,
  headerBytes,
  key,
  lane = "websocket-health",
}) {
  const { headers, status } = parseHeaders(Buffer.from(headerBytes), lane);
  const expectedAccept = createHash("sha1")
    .update(`${key}${WS_GUID}`)
    .digest("base64");
  if (
    status !== expectedStatus ||
    headers.get("upgrade")?.toLowerCase() !== "websocket" ||
    !(headers.get("connection") ?? "")
      .split(",")
      .map((value) => value.trim().toLowerCase())
      .includes("upgrade") ||
    headers.get("sec-websocket-accept") !== expectedAccept
  ) {
    fail(`WebSocket upgrade proof failed for ${lane}`);
  }
  return status;
}

function decodeChunked(bytes, lane) {
  const chunks = [];
  let offset = 0;
  while (true) {
    const end = bytes.indexOf("\r\n", offset);
    if (end < 0) fail(`truncated chunk header for ${lane}`);
    const line = bytes.subarray(offset, end).toString("ascii");
    if (!/^[0-9A-Fa-f]+$/u.test(line)) fail(`invalid chunk length for ${lane}`);
    const length = Number.parseInt(line, 16);
    offset = end + 2;
    if (length === 0) {
      if (!bytes.subarray(offset).equals(Buffer.from("\r\n"))) {
        fail(`health response trailers are not accepted for ${lane}`);
      }
      return Buffer.concat(chunks);
    }
    if (offset + length + 2 > bytes.length) fail(`truncated chunk body for ${lane}`);
    chunks.push(bytes.subarray(offset, offset + length));
    offset += length;
    if (!bytes.subarray(offset, offset + 2).equals(Buffer.from("\r\n"))) {
      fail(`malformed chunk terminator for ${lane}`);
    }
    offset += 2;
  }
}

function responseBody(response, headerEnd, headers, lane) {
  let body = response.subarray(headerEnd + 4);
  const transferEncoding = headers.get("transfer-encoding")?.toLowerCase();
  const contentLength = headers.get("content-length");
  if (transferEncoding !== undefined && contentLength !== undefined) {
    fail(`ambiguous health response framing for ${lane}`);
  }
  if (transferEncoding !== undefined) {
    if (transferEncoding !== "chunked") fail(`unsupported health transfer encoding for ${lane}`);
    body = decodeChunked(body, lane);
  } else if (contentLength !== undefined) {
    if (!/^(?:0|[1-9][0-9]*)$/u.test(contentLength)) fail(`invalid health content-length for ${lane}`);
    if (body.length !== Number(contentLength)) fail(`health content-length mismatch for ${lane}`);
  }
  return body;
}

export function healthCheck(check) {
  return new Promise((resolvePromise, rejectPromise) => {
    let settled = false;
    let response = Buffer.alloc(0);
    let leafCertificateSha256;
    let websocketKey;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (error) rejectPromise(error);
      else resolvePromise(value);
    };
    const socket = tls.connect({
      host: check.connect_ip,
      minVersion: "TLSv1.2",
      port: 443,
      rejectUnauthorized: true,
      servername: check.host,
    });
    const timer = setTimeout(
      () => finish(new Error(`health timeout for ${check.lane}`)),
      check.timeout_ms,
    );
    socket.once("secureConnect", () => {
      if (!socket.authorized) {
        finish(new Error(`health TLS chain or hostname rejected for ${check.lane}`));
        return;
      }
      const certificate = socket.getPeerCertificate(true);
      if (!certificate?.raw) {
        finish(new Error(`health TLS certificate missing for ${check.lane}`));
        return;
      }
      leafCertificateSha256 = sha256(certificate.raw);
      if (leafCertificateSha256 !== check.leaf_certificate_sha256) {
        finish(new Error(`health TLS certificate drift for ${check.lane}`));
        return;
      }
      const websocket = check.kind === "websocket-upgrade";
      if (websocket) websocketKey = randomBytes(16).toString("base64");
      socket.write([
        `GET ${check.path} HTTP/1.1`,
        `Host: ${check.host}`,
        websocket ? "Connection: Upgrade" : "Connection: close",
        ...(websocket
          ? [
              "Upgrade: websocket",
              "Sec-WebSocket-Version: 13",
              `Sec-WebSocket-Key: ${websocketKey}`,
            ]
          : []),
        "User-Agent: bitcoinpir-overlay-health-v1",
        "",
        "",
      ].join("\r\n"));
    });
    socket.on("data", (chunk) => {
      response = Buffer.concat([response, chunk]);
      if (response.length > check.max_response_bytes) {
        finish(new Error(`health response too large for ${check.lane}`));
        return;
      }
      const headerEnd = response.indexOf("\r\n\r\n");
      if (headerEnd < 0 || check.kind !== "websocket-upgrade") return;
      try {
        const status = verifyWebSocketUpgrade({
          expectedStatus: check.expected_status,
          headerBytes: response.subarray(0, headerEnd),
          key: websocketKey,
          lane: check.lane,
        });
        finish(null, {
          body_sha256: null,
          leaf_certificate_sha256: leafCertificateSha256,
          status,
          success: true,
        });
      } catch (error) {
        finish(error);
      }
    });
    socket.once("end", () => {
      if (check.kind === "websocket-upgrade") return;
      try {
        const headerEnd = response.indexOf("\r\n\r\n");
        if (headerEnd < 0) fail(`truncated health response for ${check.lane}`);
        const { headers, status } = parseHeaders(response.subarray(0, headerEnd), check.lane);
        const body = responseBody(response, headerEnd, headers, check.lane);
        const bodySha256 = sha256(body);
        finish(null, {
          body_sha256: bodySha256,
          leaf_certificate_sha256: leafCertificateSha256,
          status,
          success: status === check.expected_status && bodySha256 === check.expected_body_sha256,
        });
      } catch (error) {
        finish(error);
      }
    });
    socket.once("error", (error) => finish(error));
  });
}

function processStartTicks(pid) {
  const text = readFileSync(`/proc/${pid}/stat`, "utf8");
  const close = text.lastIndexOf(")");
  if (close < 1) fail(`malformed /proc/${pid}/stat`);
  const fields = text.slice(close + 2).trim().split(/\s+/u);
  const start = fields[19];
  if (!/^[1-9][0-9]*$/u.test(start ?? "")) fail(`missing process starttime for PID ${pid}`);
  return start;
}

function bootId() {
  const value = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(value)
  ) {
    fail("kernel boot_id is malformed");
  }
  return value;
}

function lockOwner(transactionId) {
  return {
    boot_id: bootId(),
    pid: process.pid,
    process_start_ticks: processStartTicks(process.pid),
    transaction_id: transactionId,
  };
}

function parseLockOwner(bytes) {
  const owner = parseStrictJson(Buffer.from(bytes).toString("utf8"), "lock owner");
  exactKeys(owner, ["boot_id", "pid", "process_start_ticks", "transaction_id"], "lock owner");
  if (
    typeof owner.boot_id !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(owner.boot_id)
  ) {
    fail("lock owner boot ID is malformed");
  }
  if (!Number.isSafeInteger(owner.pid) || owner.pid < 1) {
    fail("lock owner PID is malformed");
  }
  if (
    typeof owner.process_start_ticks !== "string" ||
    !/^[1-9][0-9]*$/u.test(owner.process_start_ticks)
  ) {
    fail("lock owner process start ticks are malformed");
  }
  if (
    typeof owner.transaction_id !== "string" ||
    !/^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/u.test(owner.transaction_id)
  ) {
    fail("lock owner transaction ID is malformed");
  }
  return owner;
}

function ownerIsLive(owner) {
  if (owner.boot_id !== bootId()) return false;
  try {
    return processStartTicks(owner.pid) === owner.process_start_ticks;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

export function acquireFilesystemLock(
  path,
  {
    allowUnpinnedTestHelper = false,
    helperPin,
    recoverStale,
    testOnlyFaultInjector,
    transactionId,
  },
) {
  if (helperPin === undefined && allowUnpinnedTestHelper !== true) {
    fail("transaction lock owner publication requires the pinned no-replace helper");
  }
  if (testOnlyFaultInjector !== undefined && allowUnpinnedTestHelper !== true) {
    fail("transaction lock fault injection is test-only");
  }
  if (testOnlyFaultInjector !== undefined && typeof testOnlyFaultInjector !== "function") {
    fail("transaction lock test fault injector must be a function");
  }
  const create = () => {
    mkdirSync(path, { mode: 0o700 });
    fsyncParent(path);
    const lockDirectorySeal = realReadDirectory(path);
    if (
      lockDirectorySeal.uid !== 0 ||
      lockDirectorySeal.gid !== 0 ||
      lockDirectorySeal.mode !== "0700"
    ) {
      fail("transaction lock directory is not root:root mode 0700");
    }
    const owner = lockOwner(transactionId);
    const ownerBytes = Buffer.from(canonicalJson(owner), "utf8");
    const pendingPath = `${path}/${LOCK_OWNER_PENDING}`;
    const ownerPath = `${path}/${LOCK_OWNER}`;
    const pending = realWriteExclusive(
      pendingPath,
      ownerBytes,
      "0400",
      lockDirectorySeal,
      testOnlyFaultInjector,
    );
    try {
      if (allowUnpinnedTestHelper) {
        // Test-only direct callers may not have a rendered helper pin. The
        // newly-created lock directory still makes this rename atomic; the
        // production adapter always supplies the no-replace helper below.
        renameSync(pendingPath, ownerPath);
        fsyncParent(ownerPath, lockDirectorySeal);
      } else {
        invokePinnedHelper(
          "--publish",
          pendingPath,
          ownerPath,
          helperPin,
          lockDirectorySeal,
        );
      }
    } catch (error) {
      let observed;
      try {
        observed = realReadOptionalRegular(ownerPath);
        if (observed === null) throw error;
        if (!observed.bytes.equals(ownerBytes)) {
          fail("visible lock owner bytes disagree after a failed atomic publication");
        }
        ownerOnlyRecordShape(observed.snapshot, ownerPath, "lock owner");
        fsyncParent(ownerPath, lockDirectorySeal);
      } catch (classificationError) {
        if (classificationError === error) throw error;
        const unknown = outcomeUnknown(
          `lock owner publication outcome is unknown; explicit stale-lock recovery is required: ${classificationError.message}`,
          error,
        );
        unknown.publicationClassificationError = classificationError;
        throw unknown;
      }
    }
    const published = realReadRegular(ownerPath, 64 * 1024);
    ownerOnlyRecordShape(published.snapshot, ownerPath, "published lock owner");
    if (!published.bytes.equals(ownerBytes)) fail("published lock owner bytes drifted");
    assertExchangeIdentity(
      published.snapshot,
      pending.snapshot,
      ownerPath,
      "published lock owner generation",
    );
    if (realReadOptionalRegular(pendingPath) !== null) {
      fail("lock owner pending entry remained after atomic publication");
    }
    return { lockDirectorySeal, owner, ownerBytes, pendingSnapshot: pending.snapshot };
  };
  let held;
  try {
    held = create();
  } catch (error) {
    if (error?.code !== "EEXIST") throw error;
    if (!recoverStale) fail("transaction lock already exists; use the explicit recover command");
    const lockDirectorySeal = realReadDirectory(path);
    if (
      lockDirectorySeal.uid !== 0 ||
      lockDirectorySeal.gid !== 0 ||
      lockDirectorySeal.mode !== "0700"
    ) {
      fail("stale lock directory is not root:root mode 0700");
    }
    const entries = readdirSync(path, { withFileTypes: true });
    if (entries.length === 0) {
      rmdirSync(path);
      fsyncParent(path);
      held = create();
    } else {
      if (
        entries.length !== 1 ||
        ![LOCK_OWNER, LOCK_OWNER_PENDING].includes(entries[0].name) ||
        !entries[0].isFile()
      ) {
        fail("stale lock directory has an unknown shape; refusing to guess ownership");
      }
      const existing = realReadRegular(`${path}/${entries[0].name}`, 64 * 1024);
      ownerOnlyRecordShape(
        existing.snapshot,
        `${path}/${entries[0].name}`,
        "stale lock owner",
      );
      let owner;
      try {
        owner = parseLockOwner(existing.bytes);
      } catch (error) {
        if (entries[0].name === LOCK_OWNER) {
          fail(
            `authoritative lock owner is malformed; refusing stale-lock recovery: ${error.message}`,
          );
        }
        // owner.json.pending is written before the atomic publication that
        // makes the lock authoritative. If it is the sole, exact root-owned
        // entry, malformed bytes prove acquisition never returned and the
        // overlay transaction could not have started under this generation.
        // All metadata and directory-shape checks above remain fail closed.
        owner = null;
      }
      if (owner !== null && ownerIsLive(owner)) {
        fail("transaction lock is held by a live process generation");
      }
      realRemoveIfExact(
        `${path}/${entries[0].name}`,
        existing.snapshot,
        lockDirectorySeal,
      );
      rmdirSync(path);
      fsyncParent(path);
      held = create();
    }
  }
  return async () => {
    const lockDirectory = realReadDirectory(path);
    if (!same(lockDirectory, held.lockDirectorySeal)) {
      fail("transaction lock directory identity changed before release");
    }
    const observed = realReadRegular(`${path}/${LOCK_OWNER}`, 64 * 1024);
    ownerOnlyRecordShape(observed.snapshot, `${path}/${LOCK_OWNER}`, "released lock owner");
    if (!observed.bytes.equals(held.ownerBytes)) fail("transaction lock ownership changed before release");
    const entries = readdirSync(path, { withFileTypes: true });
    if (entries.length !== 1 || entries[0].name !== LOCK_OWNER || !entries[0].isFile()) {
      fail("transaction lock directory changed before release");
    }
    realRemoveIfExact(
      `${path}/${LOCK_OWNER}`,
      observed.snapshot,
      held.lockDirectorySeal,
    );
    rmdirSync(path);
    fsyncParent(path);
  };
}

function invokePinnedHelper(
  action,
  left,
  right,
  helperPin,
  expectedParent,
  faultInjector,
) {
  if (!["--exchange", "--publish"].includes(action)) fail("unreviewed rename helper action");
  const supervisorPid = process.pid;
  const supervisorStartTicks = processStartTicks(supervisorPid);
  const helper = realReadRegular(helperPin.path);
  exactRegularSnapshot(helper.snapshot, helperPin, "rename-exchange helper before invocation");
  const fd = openSync(
    helperPin.path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
  );
  runWithSyncCleanups(
    () => {
      const stat = fstatSync(fd, { bigint: true });
      if (stat.dev.toString() !== helperPin.device || stat.ino.toString() !== helperPin.inode) {
        fail("rename-exchange helper path raced after verification");
      }
      injectFault(faultInjector, "before-rename");
      const result = commandResult(
        [
          "/proc/self/fd/3",
          action,
          String(supervisorPid),
          supervisorStartTicks,
          left,
          right,
        ],
        {
          captureStdout: false,
          extraFd: fd,
          maxBytes: 64 * 1024,
          timeoutMs: 10_000,
        },
      );
      if (result.status !== 0) {
        fail(`renameat2 helper ${action} failed: ${result.stderr.toString("utf8").trim()}`);
      }
      injectFault(faultInjector, "after-rename");
    },
    [() => closeSync(fd)],
  );
  injectFault(faultInjector, "before-final-dir-fsync");
  fsyncParent(left, expectedParent);
  injectFault(faultInjector, "after-final-dir-fsync");
}

export function linuxOverlayOps() {
  if (process.platform !== "linux") fail("integrated Caddy transaction requires Linux");
  if (typeof process.geteuid !== "function" || process.geteuid() !== 0) {
    fail("integrated Caddy transaction requires effective UID 0");
  }
  return {
    async acquireLock(path, options) {
      if (options.helperPin === undefined) fail("transaction lock requires the pinned rename helper");
      return acquireFilesystemLock(path, options);
    },
    async exchange(left, right, helperPin, expectedParent) {
      if (dirname(left) !== dirname(right)) fail("exchange entries must share one exact parent");
      invokePinnedHelper("--exchange", left, right, helperPin, expectedParent);
    },
    async fsyncParent(path, expectedParent) {
      fsyncParent(path, expectedParent);
    },
    async fsyncRegular(path, expectedSnapshot, expectedParent) {
      fsyncRegularExact(path, expectedSnapshot, expectedParent);
    },
    async health(check) {
      return healthCheck(check);
    },
    async hostIdentity() {
      return {
        boot_id: bootId(),
        machine_id_sha256: sha256(readFileSync("/etc/machine-id")),
      };
    },
    async initializeStateDirectory(path, expectedParent) {
      const before = realReadDirectory(dirname(path));
      if (expectedParent !== undefined && !same(before, expectedParent)) {
        fail("transactions parent directory drifted before state-directory creation");
      }
      mkdirSync(path, { mode: 0o700 });
      fsyncParent(path, expectedParent);
      const observed = realReadDirectory(path);
      if (observed.uid !== 0 || observed.gid !== 0 || observed.mode !== "0700") {
        fail("transaction state directory is not root:root mode 0700");
      }
      const after = realReadDirectory(dirname(path));
      if (expectedParent !== undefined && !same(after, expectedParent)) {
        fail("transactions parent directory drifted after state-directory creation");
      }
      return observed;
    },
    async sealStateDirectory(path) {
      const observed = realReadDirectory(path);
      if (observed.uid !== 0 || observed.gid !== 0 || observed.mode !== "0700") {
        fail("transaction state directory is not root:root mode 0700");
      }
      return observed;
    },
    async monotonicNowNs() {
      return process.hrtime.bigint().toString();
    },
    async probeAdminApi(options) {
      return runPinnedAdminProbe(options);
    },
    async probeTcpAdmin(endpoint) {
      return tcpAdminRefusal(endpoint);
    },
    async readAdminRuntimePath(path) {
      return realReadAdminRuntimePath(path);
    },
    async readDirectory(path) {
      return realReadDirectory(path);
    },
    async readEffectiveUnit(unitName) {
      return effectiveUnitState(unitName);
    },
    async readOptionalRegular(path) {
      return realReadOptionalRegular(path);
    },
    async readRegular(path) {
      return realReadRegular(path, pinnedReadLimit(path));
    },
    async readProcessRuntime(pid) {
      return processRuntime(pid);
    },
    async readRuntimePath(path) {
      return runtimePath(path);
    },
    async readStateRecords(path, expectedParent) {
      const observedParent = realReadDirectory(path);
      if (expectedParent !== undefined && !same(observedParent, expectedParent)) {
        fail("transaction state directory drifted before journal read");
      }
      const finalNames = Object.values(OVERLAY_STATE_FILES);
      const allowed = new Set([
        ...finalNames,
        ...finalNames.map((name) => `${name}.pending`),
      ]);
      const entries = readdirSync(path, { withFileTypes: true });
      const records = new Map();
      for (const entry of entries) {
        if (!entry.isFile() || !allowed.has(entry.name)) {
          fail(`unknown entry in durable transaction state: ${entry.name}`);
        }
        const entryPath = `${path}/${entry.name}`;
        const observed = realReadRegular(entryPath);
        ownerOnlyRecordShape(observed.snapshot, entryPath, `phase journal ${entry.name}`);
        records.set(entry.name, observed.bytes);
      }
      const confirmedParent = realReadDirectory(path);
      if (expectedParent !== undefined && !same(confirmedParent, expectedParent)) {
        fail("transaction state directory drifted after journal read");
      }
      return records;
    },
    async readUnitGeneration(unitName) {
      return unitGeneration(unitName);
    },
    async removeIfExact(path, expectedSnapshot, expectedParent) {
      realRemoveIfExact(path, expectedSnapshot, expectedParent);
    },
    async run(argv, options) {
      return commandResult(argv, options);
    },
    async writeExclusive(path, bytes, mode, expectedParent) {
      return realWriteExclusive(path, bytes, mode, expectedParent);
    },
    async publishPendingReceipt(pendingPath, finalPath, helperPin, expectedParent) {
      if (dirname(pendingPath) !== dirname(finalPath)) {
        fail("pending and final receipt entries must share one exact parent");
      }
      invokePinnedHelper("--publish", pendingPath, finalPath, helperPin, expectedParent);
    },
    async publishPendingState(pendingPath, finalPath, helperPin, expectedParent) {
      if (dirname(pendingPath) !== dirname(finalPath)) {
        fail("pending and final state entries must share one exact parent");
      }
      invokePinnedHelper("--publish", pendingPath, finalPath, helperPin, expectedParent);
    },
    async writeReceipt(pendingPath, finalPath, bytes, helperPin, expectedParent) {
      realWriteExclusive(pendingPath, bytes, "0400", expectedParent);
      invokePinnedHelper("--publish", pendingPath, finalPath, helperPin, expectedParent);
      const published = realReadRegular(finalPath);
      ownerOnlyRecordShape(published.snapshot, finalPath, "published receipt");
      if (!published.bytes.equals(bytes)) fail("published receipt bytes drifted");
      return published;
    },
    async writeState(directory, filename, bytes, helperPin, expectedParent) {
      const finalPath = `${directory}/${filename}`;
      const pendingPath = `${finalPath}.pending`;
      realWriteExclusive(pendingPath, bytes, "0400", expectedParent);
      invokePinnedHelper("--publish", pendingPath, finalPath, helperPin, expectedParent);
      const published = realReadRegular(finalPath);
      ownerOnlyRecordShape(published.snapshot, finalPath, "published phase state");
      if (!published.bytes.equals(bytes)) fail("published phase state bytes drifted");
      return published;
    },
  };
}

export async function testOnlyAtomicPublicationFaultHarness({
  bytes,
  directory,
  faultAt,
  helperPath,
}) {
  if (process.platform !== "linux" || process.geteuid?.() !== 0) {
    fail("atomic publication fault harness requires root Linux");
  }
  canonicalAbsolute(directory);
  canonicalAbsolute(helperPath);
  const payload = Buffer.from(bytes);
  const parentSeal = realReadDirectory(directory);
  requireOwnerOnlyDirectory(parentSeal, directory, "fault-harness directory");
  const helperPin = realReadRegular(helperPath).snapshot;
  const pendingPath = `${directory}/record.json.pending`;
  const finalPath = `${directory}/record.json`;
  let fired = false;
  const faultInjector = (point) => {
    if (!fired && point === faultAt) {
      fired = true;
      throw new Error(`injected atomic-publication fault at ${point}`);
    }
  };
  let initialError = null;
  try {
    realWriteExclusive(pendingPath, payload, "0400", parentSeal, faultInjector);
    invokePinnedHelper(
      "--publish",
      pendingPath,
      finalPath,
      helperPin,
      parentSeal,
      faultInjector,
    );
  } catch (error) {
    initialError = error.message;
  }
  const ops = linuxOverlayOps();
  const observed = await settleAtomicPublication({
    bytes: payload,
    finalPath,
    helperPin,
    label: "fault-harness record",
    ops,
    parentSeal,
    pendingPath,
    publish: (...args) => ops.publishPendingState(...args),
  });
  return {
    final: await ops.readOptionalRegular(finalPath),
    initial_error: initialError,
    pending: await ops.readOptionalRegular(pendingPath),
    settled: observed,
  };
}

function parseArgs(argv) {
  const args = [...argv];
  const command = args[0]?.startsWith("--") ? "execute" : (args.shift() ?? "execute");
  const options = new Map();
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index];
    const value = args[index + 1];
    if (!key?.startsWith("--") || value === undefined || options.has(key)) {
      fail("transaction arguments must be unique --name value pairs");
    }
    options.set(key, value);
  }
  return { command, options };
}

function requiredOption(options, name) {
  const value = options.get(name);
  if (value === undefined) fail(`missing required ${name}`);
  return value;
}

async function main(argv) {
  if (process.platform !== "linux") fail("integrated Caddy transaction requires Linux");
  const { command, options } = parseArgs(argv);
  const planPath = resolve(requiredOption(options, "--plan"));
  const plan = parseStrictJson(realReadRegular(planPath).bytes.toString("utf8"), "overlay plan");
  const approvedPlanSha256 = requiredOption(options, "--approved-plan-sha256");
  validateOverlayPlan(plan);
  if (
    plan.runtime.exchange_helper.path !== RENAME_EXCHANGE_HELPER ||
    plan.runtime.exchange_manifest.path !== RENAME_EXCHANGE_MANIFEST
  ) {
    fail("rendered executor helper dependencies do not match the exact overlay plan pins");
  }
  if (fileURLToPath(import.meta.url) !== plan.runtime.executor.path) {
    fail("transaction executor was not invoked from the exact plan-pinned path");
  }
  if (process.execPath !== plan.runtime.node_binary.path) {
    fail("transaction executor is not running under the exact plan-pinned Node path");
  }
  const ops = linuxOverlayOps();
  const result = command === "execute"
    ? await executeOverlayTransaction({ approvedPlanSha256, ops, plan })
    : command === "recover"
      ? await recoverOverlayTransaction({ approvedPlanSha256, ops, plan })
      : fail("usage: overlay-transaction.mjs execute|recover --plan ... --approved-plan-sha256 ...");
  if (result?.schema_version === 1) {
    process.stdout.write(
      `${result.outcome} receipt=${plan.transaction.receipt_path} sha256=${receiptDigest(result)}\n`,
    );
  } else {
    process.stdout.write(`${canonicalJson(result)}`);
  }
}

const isMain = process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (isMain) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    if (error?.receipt !== undefined) {
      process.stderr.write(`receipt=${error.receipt.transaction_id}\n`);
    }
    if (error?.lockReleaseError !== undefined) {
      process.stderr.write(`lock_release_error=${error.lockReleaseError.message}\n`);
    }
    if (error?.abortFinalizationError !== undefined) {
      process.stderr.write(`abort_finalization_error=${error.abortFinalizationError.message}\n`);
    }
    if (error?.primaryError !== undefined) {
      process.stderr.write(`primary_error=${error.primaryError.message}\n`);
    }
    if (error?.rollbackError !== undefined) {
      process.stderr.write(`rollback_error=${error.rollbackError.message}\n`);
    }
    for (const cleanupError of error?.cleanupErrors ?? []) {
      process.stderr.write(`cleanup_error=${cleanupError.message}\n`);
    }
    process.exitCode = 1;
  });
}
