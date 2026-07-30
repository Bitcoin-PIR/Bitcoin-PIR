#!/usr/bin/env node

import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
} from "node:fs";
import { isIP } from "node:net";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const OVERLAY_PLAN_SCHEMA_VERSION = 1;
export const OVERLAY_RECEIPT_SCHEMA_VERSION = 1;
export const OVERLAY_PROFILE = "integrated-existing-bhtm-caddy-v1";
export const OVERLAY_COLLECTOR =
  "bitcoinpir-payment-v1-integrated-caddy-transaction-v1";
export const MANAGED_BLOCK_SOURCE =
  "deploy/payment-v1/edge/integrated-existing-bhtm-caddy.managed.Caddyfile.in";

const BEGIN_MARKER =
  "# BEGIN BITCOINPIR PAYMENT V1 MANAGED BLOCK integrated-existing-bhtm-caddy-v1";
const END_MARKER =
  "# END BITCOINPIR PAYMENT V1 MANAGED BLOCK integrated-existing-bhtm-caddy-v1";
const SOURCE_FAIR_UNIT = "bitcoinpir-payment-v1-source-fair-edge.service";
const SOURCE_FAIR_FRAGMENT =
  "/etc/systemd/system/bitcoinpir-payment-v1-source-fair-edge.service";
const SOURCE_FAIR_CONFIG =
  "/etc/bitcoinpir/payment-v1/source-fair-edge/haproxy.cfg";
const SOURCE_FAIR_RUNTIME = "/run/bitcoinpir-source-fair-edge";
const TARGET_UNIT = "bhtm-caddy.service";
const TARGET_FRAGMENT = "/etc/systemd/system/bhtm-caddy.service";
const TARGET_CONFIG = "/etc/caddy/Caddyfile";
const ADMIN_UDS_PROFILE = "bhtm-caddy-admin-uds-v1";
const ADMIN_UDS_ROOT = "/var/lib/bitcoinpir/payment-v1/bhtm-caddy-admin-uds";
const ADMIN_UDS_LISTEN = "unix//run/bitcoinpir-caddy-admin/admin.sock|0200";
const ADMIN_UDS_DIAL = "unix//run/bitcoinpir-caddy-admin/admin.sock";
const ADMIN_UDS_PROBE =
  "/usr/local/libexec/bitcoinpir/payment-v1-caddy-admin-uds-probe.mjs";
const ADMIN_UDS_GATE =
  "/usr/local/libexec/bitcoinpir/payment-v1-caddy-admin-uds-gate.mjs";
const SETPRIV_BINARY = "/usr/bin/setpriv";
const LOCK_PATH =
  "/run/lock/bitcoinpir-payment-v1-integrated-bhtm-caddy.lock";
const TRANSACTION_ROOT =
  "/var/lib/bitcoinpir/payment-v1/integrated-existing-bhtm-caddy";
const TLS_ROOT = "/etc/bitcoinpir/payment-v1/edge";
const OVERLAY_GATE_PATH =
  "/usr/local/libexec/bitcoinpir/payment-v1-integrated-caddy-overlay-gate.mjs";
const OVERLAY_EXECUTOR_PATH =
  "/usr/local/libexec/bitcoinpir/payment-v1-integrated-caddy-overlay-transaction.mjs";
const HEX64 = /^[0-9a-f]{64}$/u;
const BOOT_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SYSTEMD_INVOCATION_ID = /^[0-9a-f]{32}$/u;
const SLUG = /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/u;
const DNS_HOST =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const MAX_PREIMAGE_BYTES = 2 * 1024 * 1024;
const MAX_BLOCK_BYTES = 512 * 1024;
const MAX_JSON_BYTES = 8 * 1024 * 1024;

const PLACEHOLDER_NAMES = Object.freeze([
  "DIRECTORY_PUBLISHER_CLIENT_IP",
  "DIRECTORY_PUBLISHER_HTTPS_HOST",
  "DIRECTORY_PUBLISHER_PRIVATE_BIND",
  "DIRECTORY_RELAY_WSS_HOST",
  "PAYMENT_ISSUER_HTTPS_HOST",
  "PROVIDER_WSS_HOST",
  "PUBLIC_HTTPS_BIND",
]);

const SOCKET_NAMES = Object.freeze([
  "directory-public.sock",
  "directory-publisher.sock",
  "issuer.sock",
  "provider.sock",
]);

const HEALTH_LANES = Object.freeze([
  Object.freeze({
    hostPlaceholder: "DIRECTORY_RELAY_WSS_HOST",
    kind: "websocket-upgrade",
    lane: "directory-public",
    path: "/",
    private: false,
    status: 101,
  }),
  Object.freeze({
    hostPlaceholder: "DIRECTORY_PUBLISHER_HTTPS_HOST",
    kind: "websocket-upgrade",
    lane: "directory-publisher",
    path: "/",
    private: true,
    status: 101,
  }),
  Object.freeze({
    hostPlaceholder: "PAYMENT_ISSUER_HTTPS_HOST",
    kind: "https-response",
    lane: "issuer",
    path: "/v1/quote-keys/current",
    private: false,
    status: 200,
  }),
  Object.freeze({
    hostPlaceholder: "PROVIDER_WSS_HOST",
    kind: "websocket-upgrade",
    lane: "provider",
    path: "/v1/pir",
    private: false,
    status: 101,
  }),
]);

function fail(message) {
  throw new Error(message);
}

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === null ||
      Object.getPrototypeOf(value) === Object.prototype)
  );
}

class StrictJsonParser {
  constructor(text, label) {
    this.text = text;
    this.label = label;
    this.index = 0;
  }

  parse() {
    if (Buffer.byteLength(this.text, "utf8") > MAX_JSON_BYTES) {
      fail(`${this.label} exceeds ${MAX_JSON_BYTES} bytes`);
    }
    if (this.text.charCodeAt(0) === 0xfeff) fail(`${this.label} contains a BOM`);
    const value = this.parseValue();
    this.skipWhitespace();
    if (this.index !== this.text.length) {
      fail(`${this.label} has trailing JSON data at byte ${this.index}`);
    }
    return value;
  }

  skipWhitespace() {
    while (/[\t\n\r ]/u.test(this.text[this.index] ?? "")) this.index += 1;
  }

  parseValue() {
    this.skipWhitespace();
    const character = this.text[this.index];
    if (character === "{") return this.parseObject();
    if (character === "[") return this.parseArray();
    if (character === '"') return this.parseString();
    if (character === "t" && this.consumeLiteral("true")) return true;
    if (character === "f" && this.consumeLiteral("false")) return false;
    if (character === "n" && this.consumeLiteral("null")) return null;
    if (character === "-" || /[0-9]/u.test(character ?? "")) return this.parseNumber();
    fail(`${this.label} has invalid JSON at byte ${this.index}`);
  }

  consumeLiteral(literal) {
    if (this.text.slice(this.index, this.index + literal.length) !== literal) return false;
    this.index += literal.length;
    return true;
  }

  parseString() {
    const start = this.index;
    this.index += 1;
    let escaped = false;
    while (this.index < this.text.length) {
      const code = this.text.charCodeAt(this.index);
      const character = this.text[this.index];
      if (!escaped && character === '"') {
        this.index += 1;
        try {
          return JSON.parse(this.text.slice(start, this.index));
        } catch {
          fail(`${this.label} has an invalid JSON string at byte ${start}`);
        }
      }
      if (!escaped && code < 0x20) {
        fail(`${this.label} has a raw control character at byte ${this.index}`);
      }
      if (!escaped && character === "\\") escaped = true;
      else escaped = false;
      this.index += 1;
    }
    fail(`${this.label} has an unterminated JSON string at byte ${start}`);
  }

  parseNumber() {
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(
      this.text.slice(this.index),
    );
    if (!match) fail(`${this.label} has an invalid number at byte ${this.index}`);
    this.index += match[0].length;
    const value = Number(match[0]);
    if (!Number.isFinite(value)) fail(`${this.label} contains a non-finite number`);
    return value;
  }

  parseArray() {
    const result = [];
    this.index += 1;
    this.skipWhitespace();
    if (this.text[this.index] === "]") {
      this.index += 1;
      return result;
    }
    while (true) {
      result.push(this.parseValue());
      this.skipWhitespace();
      if (this.text[this.index] === "]") {
        this.index += 1;
        return result;
      }
      if (this.text[this.index] !== ",") {
        fail(`${this.label} array is missing a comma at byte ${this.index}`);
      }
      this.index += 1;
    }
  }

  parseObject() {
    const result = Object.create(null);
    const seen = new Set();
    this.index += 1;
    this.skipWhitespace();
    if (this.text[this.index] === "}") {
      this.index += 1;
      return result;
    }
    while (true) {
      this.skipWhitespace();
      if (this.text[this.index] !== '"') {
        fail(`${this.label} object key must be a string at byte ${this.index}`);
      }
      const key = this.parseString();
      if (seen.has(key)) fail(`${this.label} repeats JSON key ${JSON.stringify(key)}`);
      seen.add(key);
      this.skipWhitespace();
      if (this.text[this.index] !== ":") {
        fail(`${this.label} object key is missing ':' at byte ${this.index}`);
      }
      this.index += 1;
      result[key] = this.parseValue();
      this.skipWhitespace();
      if (this.text[this.index] === "}") {
        this.index += 1;
        return result;
      }
      if (this.text[this.index] !== ",") {
        fail(`${this.label} object is missing a comma at byte ${this.index}`);
      }
      this.index += 1;
    }
  }
}

export function parseStrictJson(text, label = "JSON document") {
  if (typeof text !== "string") fail(`${label} must be UTF-8 text`);
  return new StrictJsonParser(text, label).parse();
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

function exactKeys(value, expected, label) {
  if (!isPlainObject(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((entry, index) => entry !== wanted[index])
  ) {
    fail(`${label} keys must equal ${JSON.stringify(wanted)}, got ${JSON.stringify(actual)}`);
  }
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function readBoundedNoFollow(path, maxBytes, label) {
  const absolute = resolve(path);
  if (absolute !== path || path.includes("//") || path.includes("\0")) {
    fail(`${label} path must be one canonical absolute path`);
  }
  const parents = [];
  let current = dirname(path);
  while (true) {
    const stat = lstatSync(current, { bigint: true, throwIfNoEntry: true });
    if (!stat.isDirectory()) fail(`${label} parent is not a real directory: ${current}`);
    parents.push({ device: stat.dev, inode: stat.ino, path: current });
    if (current === "/") break;
    current = dirname(current);
  }
  const fd = openSync(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
  );
  try {
    const before = fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size > BigInt(maxBytes)) {
      fail(`${label} must be one bounded single-link regular file`);
    }
    const bytes = readFileSync(fd);
    if (bytes.length > maxBytes) fail(`${label} exceeded its bounded descriptor read`);
    const after = fstatSync(fd, { bigint: true });
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.ctimeNs !== after.ctimeNs ||
      before.mtimeNs !== after.mtimeNs
    ) {
      fail(`${label} changed during its descriptor read`);
    }
    const finalPath = lstatSync(path, { bigint: true, throwIfNoEntry: true });
    if (!finalPath.isFile() || finalPath.dev !== before.dev || finalPath.ino !== before.ino) {
      fail(`${label} path changed or became a symlink during its descriptor read`);
    }
    for (const parent of parents) {
      const confirmed = lstatSync(parent.path, { bigint: true, throwIfNoEntry: true });
      if (
        !confirmed.isDirectory() ||
        confirmed.dev !== parent.device ||
        confirmed.ino !== parent.inode
      ) {
        fail(`${label} parent chain changed during its descriptor read`);
      }
    }
    return bytes;
  } finally {
    closeSync(fd);
  }
}

function validateSha256(value, label) {
  if (typeof value !== "string" || !HEX64.test(value)) {
    fail(`${label} must be 64 lowercase hexadecimal characters`);
  }
}

function validateSlug(value, label) {
  if (typeof value !== "string" || !SLUG.test(value)) {
    fail(`${label} must be a bounded lowercase slug`);
  }
  if (value.startsWith("replace-")) fail(`${label} retains the repository example marker`);
}

function validateDecimal(value, label, { allowZero = false } = {}) {
  if (
    typeof value !== "string" ||
    !/^(?:0|[1-9][0-9]{0,19})$/u.test(value) ||
    (!allowZero && value === "0")
  ) {
    fail(`${label} must be a canonical ${allowZero ? "non-negative" : "positive"} decimal string`);
  }
}

function validateBootUuid(value, label) {
  if (typeof value !== "string" || !BOOT_UUID.test(value)) {
    fail(`${label} must be a lowercase UUID`);
  }
}

function validateInvocationId(value, label) {
  if (
    typeof value !== "string" ||
    !SYSTEMD_INVOCATION_ID.test(value) ||
    value === "0".repeat(32)
  ) {
    fail(`${label} must be a nonzero 32-character lowercase systemd InvocationID`);
  }
}

function validateMode(value, expected, label) {
  if (typeof value !== "string" || !expected.includes(value)) {
    fail(`${label} mode must be one of ${JSON.stringify(expected)}`);
  }
}

function validateUidGid(value, label) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 4_294_967_294) {
    fail(`${label} must be a safe uint32 identity`);
  }
}

function validateIp(value, label, { privateOnly = false } = {}) {
  if (typeof value !== "string" || isIP(value) === 0) {
    fail(`${label} must be one numeric IP address`);
  }
  if (["0.0.0.0", "127.0.0.1", "::", "::1"].includes(value)) {
    fail(`${label} must be concrete and non-loopback`);
  }
  if (!privateOnly) return;
  if (isIP(value) === 4) {
    const [first, second] = value.split(".").map(Number);
    if (
      first === 10 ||
      (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && second === 168)
    ) return;
  } else if (/^(?:fc|fd)/iu.test(value)) {
    return;
  }
  fail(`${label} must be an RFC1918 IPv4 or ULA IPv6 address`);
}

function validateDnsHost(value, label) {
  if (typeof value !== "string" || value !== value.toLowerCase() || !DNS_HOST.test(value)) {
    fail(`${label} must be one canonical lowercase DNS hostname`);
  }
}

function validateRegularPin(pin, label, {
  paths,
  modes,
  uid = 0,
  gid = 0,
} = {}) {
  exactKeys(
    pin,
    ["ctime_ns", "device", "gid", "inode", "mode", "mtime_ns", "nlink", "path", "sha256", "size", "uid"],
    label,
  );
  if (!Array.isArray(paths) || !paths.includes(pin.path)) {
    fail(`${label}.path is outside its exact reviewed target set`);
  }
  validateSha256(pin.sha256, `${label}.sha256`);
  validateUidGid(pin.uid, `${label}.uid`);
  validateUidGid(pin.gid, `${label}.gid`);
  if (pin.uid !== uid || pin.gid !== gid) fail(`${label} must be owned by ${uid}:${gid}`);
  validateMode(pin.mode, modes, label);
  if (pin.nlink !== 1) fail(`${label}.nlink must equal 1`);
  for (const key of ["device", "inode", "size", "ctime_ns", "mtime_ns"]) {
    validateDecimal(pin[key], `${label}.${key}`, { allowZero: key !== "inode" });
  }
}

function validateUnitGeneration(value, label, expected) {
  exactKeys(
    value,
    [
      "active_enter_timestamp_monotonic",
      "active_state",
      "can_reload",
      "control_group",
      "invocation_id",
      "main_pid",
      "sub_state",
      "unit_name",
    ],
    label,
  );
  if (value.unit_name !== expected.unitName) fail(`${label}.unit_name must equal ${expected.unitName}`);
  if (value.active_state !== "active" || value.sub_state !== "running") {
    fail(`${label} must pin an active/running unit`);
  }
  if (value.can_reload !== expected.canReload) {
    fail(`${label}.can_reload must equal ${expected.canReload}`);
  }
  validateDecimal(value.main_pid, `${label}.main_pid`);
  validateDecimal(
    value.active_enter_timestamp_monotonic,
    `${label}.active_enter_timestamp_monotonic`,
  );
  validateInvocationId(value.invocation_id, `${label}.invocation_id`);
  if (value.control_group !== `/system.slice/${expected.unitName}`) {
    fail(`${label}.control_group must be the exact system slice`);
  }
}

function validateSourceFair(value) {
  exactKeys(
    value,
    [
      "deployment_manifest_sha256",
      "deployment_profile",
      "haproxy_binary",
      "haproxy_config",
      "runtime_evidence_sha256",
      "runtime_paths",
      "unit_fragment",
      "unit_generation",
    ],
    "source_fair",
  );
  if (value.deployment_profile !== OVERLAY_PROFILE) {
    fail(`source_fair.deployment_profile must equal ${OVERLAY_PROFILE}`);
  }
  validateSha256(value.deployment_manifest_sha256, "source_fair deployment manifest SHA-256");
  validateSha256(value.runtime_evidence_sha256, "source_fair runtime evidence SHA-256");
  validateRegularPin(value.unit_fragment, "source_fair.unit_fragment", {
    paths: [SOURCE_FAIR_FRAGMENT],
    modes: ["0644"],
  });
  validateRegularPin(value.haproxy_config, "source_fair.haproxy_config", {
    paths: [SOURCE_FAIR_CONFIG],
    modes: ["0400", "0440"],
    gid: value.haproxy_config.gid,
  });
  if (value.haproxy_config.uid !== 0 || value.haproxy_config.gid === 0) {
    fail("source_fair.haproxy_config must be root-owned and private to one non-root group");
  }
  if (
    typeof value.haproxy_binary?.path !== "string" ||
    !/^\/opt\/bitcoinpir\/haproxy\/([0-9a-f]{64})\/haproxy$/u.test(
      value.haproxy_binary.path,
    )
  ) {
    fail("source_fair.haproxy_binary path must be content addressed");
  }
  validateRegularPin(value.haproxy_binary, "source_fair.haproxy_binary", {
    paths: [value.haproxy_binary.path],
    modes: ["0555"],
  });
  if (value.haproxy_binary.path.split("/").at(-2) !== value.haproxy_binary.sha256) {
    fail("source_fair HAProxy content-addressed path must equal its digest");
  }
  validateUnitGeneration(value.unit_generation, "source_fair.unit_generation", {
    canReload: "no",
    unitName: SOURCE_FAIR_UNIT,
  });
  if (!Array.isArray(value.runtime_paths) || value.runtime_paths.length !== 5) {
    fail("source_fair.runtime_paths must bind one directory and four sockets");
  }
  const expectedPaths = [SOURCE_FAIR_RUNTIME, ...SOCKET_NAMES.map((name) => `${SOURCE_FAIR_RUNTIME}/${name}`)];
  for (const [index, runtimePath] of value.runtime_paths.entries()) {
    exactKeys(runtimePath, ["file_type", "gid", "mode", "path", "uid"], `source_fair.runtime_paths[${index}]`);
    if (runtimePath.path !== expectedPaths[index]) {
      fail("source_fair.runtime_paths must be in the canonical exact order");
    }
    const directory = index === 0;
    if (runtimePath.file_type !== (directory ? "directory" : "socket")) {
      fail(`source_fair.runtime_paths[${index}] has the wrong file type`);
    }
    validateMode(runtimePath.mode, [directory ? "0750" : "0660"], `source_fair.runtime_paths[${index}]`);
    validateUidGid(runtimePath.uid, `source_fair.runtime_paths[${index}].uid`);
    validateUidGid(runtimePath.gid, `source_fair.runtime_paths[${index}].gid`);
    if (
      runtimePath.uid === 0 ||
      runtimePath.gid === 0 ||
      runtimePath.uid !== value.runtime_paths[0].uid ||
      runtimePath.gid !== value.runtime_paths[0].gid
    ) {
      fail("source_fair runtime directory and sockets must share one non-root service identity");
    }
  }
}

function validateTarget(value) {
  exactKeys(
    value,
    [
      "admin_uds_hardening",
      "binary",
      "config_parent",
      "config_preimage",
      "unit_fragment",
      "unit_generation",
    ],
    "target",
  );
  validateRegularPin(value.binary, "target.binary", {
    paths: ["/usr/local/bin/caddy"],
    modes: ["0555", "0755"],
  });
  validateRegularPin(value.unit_fragment, "target.unit_fragment", {
    paths: [TARGET_FRAGMENT],
    modes: ["0644"],
  });
  validateRegularPin(value.config_preimage, "target.config_preimage", {
    paths: [TARGET_CONFIG],
    modes: ["0644"],
  });
  exactKeys(
    value.config_parent,
    ["device", "gid", "inode", "mode", "path", "uid"],
    "target.config_parent",
  );
  if (value.config_parent.path !== "/etc/caddy") fail("target.config_parent.path must equal /etc/caddy");
  if (value.config_parent.uid !== 0 || value.config_parent.gid !== 0) {
    fail("target.config_parent must be root:root");
  }
  validateMode(value.config_parent.mode, ["0755"], "target.config_parent");
  for (const key of ["device", "inode"]) {
    validateDecimal(value.config_parent[key], `target.config_parent.${key}`);
  }
  validateUnitGeneration(value.unit_generation, "target.unit_generation", {
    canReload: "yes",
    unitName: TARGET_UNIT,
  });
  validateAdminUdsHardening(value.admin_uds_hardening, value);
}

function validateAdminUdsHardening(value, target) {
  exactKeys(
    value,
    [
      "admin_listen",
      "adapted_json_sha256",
      "all_service_uids_denied",
      "approved_plan_sha256",
      "binary_sha256",
      "cold_new_generation",
      "config_sha256",
      "deployment_profile",
      "plan",
      "receipt",
      "runtime_directory",
      "runtime_directory_mode",
      "setpriv_binary_sha256",
      "service_uid_inventory_sha256",
      "socket_mode",
      "socket_path",
      "tcp_admin_absent",
      "transaction_id",
      "unit_invocation_id",
      "unit_sha256",
    ],
    "target.admin_uds_hardening",
  );
  if (value.deployment_profile !== ADMIN_UDS_PROFILE) {
    fail(`target.admin_uds_hardening.deployment_profile must equal ${ADMIN_UDS_PROFILE}`);
  }
  validateSlug(value.transaction_id, "target.admin_uds_hardening.transaction_id");
  validateSha256(
    value.adapted_json_sha256,
    "target.admin_uds_hardening.adapted_json_sha256",
  );
  validateSha256(value.approved_plan_sha256, "target.admin_uds_hardening.approved_plan_sha256");
  validateSha256(
    value.service_uid_inventory_sha256,
    "target.admin_uds_hardening.service_uid_inventory_sha256",
  );
  validateSha256(
    value.setpriv_binary_sha256,
    "target.admin_uds_hardening.setpriv_binary_sha256",
  );
  const receiptPath = `${ADMIN_UDS_ROOT}/receipts/${value.transaction_id}.json`;
  const planPath = `${ADMIN_UDS_ROOT}/plans/${value.transaction_id}.json`;
  validateRegularPin(value.plan, "target.admin_uds_hardening.plan", {
    paths: [planPath],
    modes: ["0400"],
  });
  if (value.plan.sha256 !== value.approved_plan_sha256) {
    fail("target.admin_uds_hardening.plan must equal the approved canonical plan digest");
  }
  validateRegularPin(value.receipt, "target.admin_uds_hardening.receipt", {
    paths: [receiptPath],
    modes: ["0400"],
  });
  for (const [key, expected] of [
    ["binary_sha256", target.binary.sha256],
    ["config_sha256", target.config_preimage.sha256],
    ["unit_sha256", target.unit_fragment.sha256],
    ["unit_invocation_id", target.unit_generation.invocation_id],
  ]) {
    if (value[key] !== expected) {
      fail(`target.admin_uds_hardening.${key} must equal the overlay target preimage`);
    }
  }
  const exact = {
    admin_listen: ADMIN_UDS_LISTEN,
    all_service_uids_denied: true,
    cold_new_generation: true,
    runtime_directory: "/run/bitcoinpir-caddy-admin",
    runtime_directory_mode: "0700",
    socket_mode: "0200",
    socket_path: "/run/bitcoinpir-caddy-admin/admin.sock",
    tcp_admin_absent: true,
  };
  for (const [key, expected] of Object.entries(exact)) {
    if (value[key] !== expected) {
      fail(`target.admin_uds_hardening.${key} must equal ${String(expected)}`);
    }
  }
}

function validateRuntime(value) {
  exactKeys(
    value,
    [
      "admin_uds_gate",
      "exchange_helper",
      "exchange_manifest",
      "admin_probe",
      "executor",
      "gate",
      "managed_block",
      "node_binary",
      "setpriv_binary",
    ],
    "runtime",
  );
  validateRegularPin(value.node_binary, "runtime.node_binary", {
    paths: ["/usr/bin/node"],
    modes: ["0555", "0755"],
  });
  validateRegularPin(value.admin_probe, "runtime.admin_probe", {
    paths: [ADMIN_UDS_PROBE],
    modes: ["0555", "0755"],
  });
  validateRegularPin(value.admin_uds_gate, "runtime.admin_uds_gate", {
    paths: [ADMIN_UDS_GATE],
    modes: ["0555", "0755"],
  });
  validateRegularPin(value.setpriv_binary, "runtime.setpriv_binary", {
    paths: [SETPRIV_BINARY],
    modes: ["0555", "0755"],
  });
  validateRegularPin(value.gate, "runtime.gate", {
    paths: [OVERLAY_GATE_PATH],
    modes: ["0555", "0755"],
  });
  validateRegularPin(value.executor, "runtime.executor", {
    paths: [OVERLAY_EXECUTOR_PATH],
    modes: ["0555", "0755"],
  });
  if (
    typeof value.exchange_helper?.path !== "string" ||
    !/^\/opt\/bitcoinpir\/payment-v1-rename-exchange\/([0-9a-f]{64})\/payment-v1-rename-exchange$/u.test(
      value.exchange_helper.path,
    )
  ) {
    fail("runtime.exchange_helper path must be content addressed");
  }
  validateRegularPin(value.exchange_helper, "runtime.exchange_helper", {
    paths: [value.exchange_helper.path],
    modes: ["0555"],
  });
  if (value.exchange_helper.path.split("/").at(-2) !== value.exchange_helper.sha256) {
    fail("runtime.exchange_helper path digest must equal its binary SHA-256");
  }
  validateRegularPin(value.exchange_manifest, "runtime.exchange_manifest", {
    paths: [
      "/etc/bitcoinpir/payment-v1/integrated-existing-bhtm-caddy/rename-exchange.sha256",
    ],
    modes: ["0444"],
  });
  validateRegularPin(value.managed_block, "runtime.managed_block", {
    paths: [
      "/etc/bitcoinpir/payment-v1/integrated-existing-bhtm-caddy/managed.Caddyfile",
    ],
    modes: ["0444"],
  });
}

function validateManagedBlock(value) {
  exactKeys(
    value,
    [
      "candidate_adapted_json_sha256",
      "candidate_sha256",
      "placeholders",
      "rendered_sha256",
      "source_path",
      "source_sha256",
    ],
    "managed_block",
  );
  if (value.source_path !== MANAGED_BLOCK_SOURCE) {
    fail(`managed_block.source_path must equal ${MANAGED_BLOCK_SOURCE}`);
  }
  for (const key of [
    "source_sha256",
    "rendered_sha256",
    "candidate_sha256",
    "candidate_adapted_json_sha256",
  ]) {
    validateSha256(value[key], `managed_block.${key}`);
  }
  exactKeys(value.placeholders, PLACEHOLDER_NAMES, "managed_block.placeholders");
  for (const name of [
    "DIRECTORY_PUBLISHER_HTTPS_HOST",
    "DIRECTORY_RELAY_WSS_HOST",
    "PAYMENT_ISSUER_HTTPS_HOST",
    "PROVIDER_WSS_HOST",
  ]) {
    validateDnsHost(value.placeholders[name], `managed_block.placeholders.${name}`);
  }
  if (
    new Set([
      value.placeholders.DIRECTORY_PUBLISHER_HTTPS_HOST,
      value.placeholders.DIRECTORY_RELAY_WSS_HOST,
      value.placeholders.PAYMENT_ISSUER_HTTPS_HOST,
      value.placeholders.PROVIDER_WSS_HOST,
    ]).size !== 4
  ) {
    fail("managed block requires four distinct hostnames");
  }
  validateIp(value.placeholders.PUBLIC_HTTPS_BIND, "managed_block.placeholders.PUBLIC_HTTPS_BIND");
  validateIp(
    value.placeholders.DIRECTORY_PUBLISHER_PRIVATE_BIND,
    "managed_block.placeholders.DIRECTORY_PUBLISHER_PRIVATE_BIND",
    { privateOnly: true },
  );
  validateIp(
    value.placeholders.DIRECTORY_PUBLISHER_CLIENT_IP,
    "managed_block.placeholders.DIRECTORY_PUBLISHER_CLIENT_IP",
    { privateOnly: true },
  );
  if (
    value.placeholders.PUBLIC_HTTPS_BIND ===
      value.placeholders.DIRECTORY_PUBLISHER_PRIVATE_BIND ||
    value.placeholders.DIRECTORY_PUBLISHER_PRIVATE_BIND ===
      value.placeholders.DIRECTORY_PUBLISHER_CLIENT_IP ||
    value.placeholders.PUBLIC_HTTPS_BIND ===
      value.placeholders.DIRECTORY_PUBLISHER_CLIENT_IP
  ) {
    fail("public bind, publisher private bind and publisher client must be distinct");
  }
  if (
    isIP(value.placeholders.DIRECTORY_PUBLISHER_PRIVATE_BIND) !==
    isIP(value.placeholders.DIRECTORY_PUBLISHER_CLIENT_IP)
  ) {
    fail("publisher private bind and sole client must use the same IP family");
  }
}

function validateTlsDependencies(value) {
  if (!Array.isArray(value) || value.length !== 2) {
    fail("tls_dependencies must contain exactly the publisher certificate and key");
  }
  const expected = [
    {
      class: "certificate",
      modes: ["0444"],
      path: `${TLS_ROOT}/directory-publisher-server.crt`,
    },
    {
      class: "private-key",
      modes: ["0400"],
      path: `${TLS_ROOT}/directory-publisher-server.key`,
    },
  ];
  for (const [index, artifact] of value.entries()) {
    exactKeys(
      artifact,
      ["class", "parent", "pin"],
      `tls_dependencies[${index}]`,
    );
    if (artifact.class !== expected[index].class) {
      fail("tls_dependencies must be in canonical certificate/key order");
    }
    validateRegularPin(artifact.pin, `tls_dependencies[${index}].pin`, {
      paths: [expected[index].path],
      modes: expected[index].modes,
    });
    exactKeys(
      artifact.parent,
      ["device", "gid", "inode", "mode", "path", "uid"],
      `tls_dependencies[${index}].parent`,
    );
    if (
      artifact.parent.path !== TLS_ROOT ||
      artifact.parent.uid !== 0 ||
      artifact.parent.gid !== 0 ||
      artifact.parent.mode !== "0700"
    ) {
      fail("publisher TLS final parent must be root:root mode 0700");
    }
    for (const key of ["device", "inode"]) {
      validateDecimal(
        artifact.parent[key],
        `tls_dependencies[${index}].parent.${key}`,
      );
    }
    if (
      index > 0 &&
      canonicalJson(artifact.parent) !== canonicalJson(value[0].parent)
    ) {
      fail("publisher TLS files must share the exact pinned final parent");
    }
  }
}

function validateTransaction(value, plan) {
  exactKeys(
    value,
    [
      "adapt_argv",
      "adapted_json_path",
      "backup_mode",
      "backup_path",
      "candidate_path",
      "installation_mode",
      "lock_path",
      "reload_argv",
      "require_same_active_enter_timestamp_monotonic",
      "require_same_invocation_id",
      "require_same_main_pid",
      "receipt_path",
      "receipt_pending_path",
      "restart_forbidden",
      "rollback_mode",
      "rollback_on_any_post_install_failure",
      "state_directory",
      "validate_argv",
    ],
    "transaction",
  );
  const id = plan.transaction_id;
  const candidatePath = `/etc/caddy/.bitcoinpir-${id}.candidate`;
  const adaptedPath = `${TRANSACTION_ROOT}/adapted/${id}.json`;
  const backupPath = `${TRANSACTION_ROOT}/backups/${id}-${plan.target.config_preimage.sha256}.Caddyfile`;
  const receiptPath = `${TRANSACTION_ROOT}/receipts/${id}.json`;
  const receiptPendingPath = `${receiptPath}.pending`;
  const stateDirectory = `${TRANSACTION_ROOT}/transactions/${id}`;
  if (value.lock_path !== LOCK_PATH) fail(`transaction.lock_path must equal ${LOCK_PATH}`);
  if (value.candidate_path !== candidatePath) fail(`transaction.candidate_path must equal ${candidatePath}`);
  if (value.adapted_json_path !== adaptedPath) fail(`transaction.adapted_json_path must equal ${adaptedPath}`);
  if (value.backup_path !== backupPath) fail(`transaction.backup_path must equal ${backupPath}`);
  if (value.receipt_path !== receiptPath) fail(`transaction.receipt_path must equal ${receiptPath}`);
  if (value.receipt_pending_path !== receiptPendingPath) {
    fail(`transaction.receipt_pending_path must equal ${receiptPendingPath}`);
  }
  if (value.state_directory !== stateDirectory) fail(`transaction.state_directory must equal ${stateDirectory}`);
  const expectedValidate = [
    plan.target.binary.path,
    "validate",
    "--config",
    candidatePath,
    "--adapter",
    "caddyfile",
  ];
  const expectedAdapt = [
    plan.target.binary.path,
    "adapt",
    "--config",
    candidatePath,
    "--adapter",
    "caddyfile",
  ];
  const expectedReload = ["/usr/bin/systemctl", "reload", TARGET_UNIT];
  for (const [key, expected] of [
    ["validate_argv", expectedValidate],
    ["adapt_argv", expectedAdapt],
    ["reload_argv", expectedReload],
  ]) {
    if (!Array.isArray(value[key]) || canonicalJson(value[key]) !== canonicalJson(expected)) {
      fail(`transaction.${key} must equal ${JSON.stringify(expected)}`);
    }
  }
  const exactStrings = {
    backup_mode: "exclusive-create-fsync-file-and-parent",
    installation_mode:
      "same-directory-renameat2-exchange-verify-swapped-preimage-and-live-candidate-parent-fsync",
    rollback_mode:
      "same-directory-renameat2-exchange-verify-swapped-candidate-and-restored-preimage-parent-fsync-then-reload",
  };
  for (const [key, expected] of Object.entries(exactStrings)) {
    if (value[key] !== expected) fail(`transaction.${key} must equal ${expected}`);
  }
  for (const key of [
    "require_same_active_enter_timestamp_monotonic",
    "require_same_invocation_id",
    "require_same_main_pid",
    "restart_forbidden",
    "rollback_on_any_post_install_failure",
  ]) {
    if (value[key] !== true) fail(`transaction.${key} must equal true`);
  }
}

function validateHealthChecks(value, placeholders) {
  if (!Array.isArray(value) || value.length !== HEALTH_LANES.length) {
    fail("health_checks must contain the four canonical application lanes");
  }
  for (const [index, check] of value.entries()) {
    exactKeys(
      check,
      [
        "connect_ip",
        "expected_body_sha256",
        "expected_status",
        "host",
        "kind",
        "lane",
        "leaf_certificate_sha256",
        "max_response_bytes",
        "path",
        "timeout_ms",
      ],
      `health_checks[${index}]`,
    );
    const expected = HEALTH_LANES[index];
    for (const key of ["kind", "lane", "path"]) {
      if (check[key] !== expected[key]) {
        fail(`health_checks[${index}].${key} must equal ${expected[key]}`);
      }
    }
    if (check.host !== placeholders[expected.hostPlaceholder]) {
      fail(`health_checks[${index}].host does not match its managed hostname`);
    }
    const expectedIp = expected.private
      ? placeholders.DIRECTORY_PUBLISHER_PRIVATE_BIND
      : placeholders.PUBLIC_HTTPS_BIND;
    if (check.connect_ip !== expectedIp) {
      fail(`health_checks[${index}].connect_ip does not match its exact bind`);
    }
    if (check.expected_status !== expected.status) {
      fail(`health_checks[${index}].expected_status must equal ${expected.status}`);
    }
    validateSha256(
      check.leaf_certificate_sha256,
      `health_checks[${index}].leaf_certificate_sha256`,
    );
    if (expected.kind === "https-response") {
      validateSha256(check.expected_body_sha256, `health_checks[${index}].expected_body_sha256`);
    } else if (check.expected_body_sha256 !== null) {
      fail(`health_checks[${index}].expected_body_sha256 must be null for WebSocket upgrade`);
    }
    if (!Number.isSafeInteger(check.max_response_bytes) || check.max_response_bytes < 1 || check.max_response_bytes > 262_144) {
      fail(`health_checks[${index}].max_response_bytes is outside [1, 262144]`);
    }
    if (!Number.isSafeInteger(check.timeout_ms) || check.timeout_ms < 100 || check.timeout_ms > 30_000) {
      fail(`health_checks[${index}].timeout_ms is outside [100, 30000]`);
    }
  }
}

function validateTrustAcknowledgements(value) {
  const keys = [
    "append_only_cannot_disable_global_admin",
    "adapted_json_has_no_configured_log_sink",
    "append_only_cannot_disable_global_zero_rtt",
    "existing_preimage_remains_authoritative",
    "existing_root_caddy_retains_admin_and_acme_trust",
    "existing_root_caddy_expands_failure_domain",
    "fresh_admin_runtime_probes_required_before_and_after_reload",
    "reload_does_not_refresh_cold_runtime_evidence",
  ];
  exactKeys(value, keys, "trust_acknowledgements");
  for (const key of keys) {
    if (value[key] !== true) fail(`trust_acknowledgements.${key} must equal true`);
  }
}

export function validateOverlayPlan(plan) {
  exactKeys(
    plan,
    [
      "deployment_profile",
      "health_checks",
      "managed_block",
      "runtime",
      "schema_version",
      "source_fair",
      "target",
      "tls_dependencies",
      "transaction",
      "transaction_id",
      "trust_acknowledgements",
    ],
    "overlay plan",
  );
  if (plan.schema_version !== OVERLAY_PLAN_SCHEMA_VERSION) {
    fail(`overlay plan schema_version must equal ${OVERLAY_PLAN_SCHEMA_VERSION}`);
  }
  if (plan.deployment_profile !== OVERLAY_PROFILE) {
    fail(`overlay plan deployment_profile must equal ${OVERLAY_PROFILE}`);
  }
  validateSlug(plan.transaction_id, "overlay plan transaction_id");
  validateSourceFair(plan.source_fair);
  validateRuntime(plan.runtime);
  validateTarget(plan.target);
  if (
    plan.runtime.setpriv_binary.sha256 !==
    plan.target.admin_uds_hardening.setpriv_binary_sha256
  ) {
    fail("overlay runtime setpriv binary must equal the approved hardening setpriv digest");
  }
  validateManagedBlock(plan.managed_block);
  if (plan.runtime.managed_block.sha256 !== plan.managed_block.rendered_sha256) {
    fail("runtime managed block must equal the reviewed rendered block digest");
  }
  validateTlsDependencies(plan.tls_dependencies);
  validateTransaction(plan.transaction, plan);
  validateHealthChecks(plan.health_checks, plan.managed_block.placeholders);
  validateTrustAcknowledgements(plan.trust_acknowledgements);
  return true;
}

export function computeApprovedOverlayPlanSha256(plan) {
  validateOverlayPlan(plan);
  return sha256(Buffer.from(canonicalJson(plan), "utf8"));
}

function validateRenderedManagedBlock(blockBytes, placeholders) {
  if (blockBytes.length < 1 || blockBytes.length > MAX_BLOCK_BYTES) {
    fail("rendered managed block size is outside its bounded range");
  }
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(blockBytes);
  } catch {
    fail("rendered managed block must be valid UTF-8");
  }
  if (text.includes("\r") || text.includes("\0") || !text.endsWith("\n")) {
    fail("rendered managed block must be canonical LF text ending in newline");
  }
  if (/@[A-Z][A-Z0-9_]+@/u.test(text)) fail("managed block retains an unresolved placeholder");
  if ((text.match(new RegExp(BEGIN_MARKER, "gu")) ?? []).length !== 1 ||
      (text.match(new RegExp(END_MARKER, "gu")) ?? []).length !== 1) {
    fail("managed block must contain exactly one begin/end marker pair");
  }
  const uncommented = text
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("#"))
    .join("\n");
  if (/^\s*(?:log|log_append|log_name)\b/mu.test(uncommented)) {
    fail("managed application block must not enable access logging");
  }
  if ((uncommented.match(/^\s*header_up -\*$/gmu) ?? []).length !== 7) {
    fail("managed block must clear every upstream header on all seven proxy routes");
  }
  if ((uncommented.match(/^\s*proxy_protocol v2$/gmu) ?? []).length !== 7) {
    fail("managed block must use PROXY v2 on all seven source-fair hops");
  }
  if ((uncommented.match(/^\s*respond "" 404$/gmu) ?? []).length !== 4) {
    fail("managed block must retain an unmatched 404 for every hostname");
  }
  if ((uncommented.match(/^\s*reverse_proxy unix\/\/run\/bitcoinpir-source-fair-edge\/(?:provider|issuer|directory-public|directory-publisher)\.sock \{$/gmu) ?? []).length !== 7) {
    fail("managed block may proxy only to its four exact source-fair Unix sockets");
  }
  if (/header_up\s+(?:Authorization|Cookie|Forwarded|Proxy-Authorization|Traceparent|Tracestate|Baggage|X-Forwarded(?:-[A-Za-z0-9-]+)?|X-Real-IP|X-Request-ID)\b/iu.test(uncommented)) {
    fail("managed block forwards a forbidden identity, auth, cookie or trace header");
  }
  if (/\b(?:reverse_proxy|proxy_pass)\s+(?:https?:\/\/|127\.0\.0\.1|localhost|\[?::1\]?)/iu.test(uncommented)) {
    fail("managed block bypasses the source-fair Unix-socket boundary");
  }
  if (/^\s*\{\s*$/mu.test(uncommented)) {
    fail("managed block must not contain a Caddy global-options block");
  }
  for (const hostname of [
    placeholders.DIRECTORY_PUBLISHER_HTTPS_HOST,
    placeholders.DIRECTORY_RELAY_WSS_HOST,
    placeholders.PAYMENT_ISSUER_HTTPS_HOST,
    placeholders.PROVIDER_WSS_HOST,
  ]) {
    const escaped = hostname.replaceAll(".", "\\.");
    if ((text.match(new RegExp(`^${escaped} \\{$`, "gmu")) ?? []).length !== 1) {
      fail(`rendered managed block must contain exactly one site block for ${hostname}`);
    }
  }
  return Buffer.from(text, "utf8");
}

function renderManagedBlock(sourceBytes, placeholders) {
  if (sourceBytes.length < 1 || sourceBytes.length > MAX_BLOCK_BYTES) {
    fail("managed block source size is outside its bounded range");
  }
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(sourceBytes);
  } catch {
    fail("managed block source must be valid UTF-8");
  }
  if (text.includes("\r") || text.includes("\0") || !text.endsWith("\n")) {
    fail("managed block source must be canonical LF text ending in newline");
  }
  for (const [name, value] of Object.entries(placeholders)) {
    text = text.split(`@${name}@`).join(value);
  }
  return validateRenderedManagedBlock(Buffer.from(text, "utf8"), placeholders);
}

function buildCandidateWithBlock({
  approvedPlanSha256,
  blockBytes,
  plan,
  preimageBytes,
}) {
  validateOverlayPlan(plan);
  validateSha256(approvedPlanSha256, "externally approved overlay plan SHA-256");
  const computedPlanSha256 = computeApprovedOverlayPlanSha256(plan);
  if (approvedPlanSha256 !== computedPlanSha256) {
    fail("overlay plan does not match the externally approved SHA-256");
  }
  const block = validateRenderedManagedBlock(
    Buffer.from(blockBytes),
    plan.managed_block.placeholders,
  );
  if (sha256(block) !== plan.managed_block.rendered_sha256) {
    fail("rendered managed block SHA-256 does not match the plan");
  }
  const preimage = Buffer.from(preimageBytes);
  if (preimage.length < 1 || preimage.length > MAX_PREIMAGE_BYTES) {
    fail("Caddyfile preimage size is outside its bounded range");
  }
  if (sha256(preimage) !== plan.target.config_preimage.sha256) {
    fail("Caddyfile preimage SHA-256 does not match the exact target pin");
  }
  let preimageText;
  try {
    preimageText = new TextDecoder("utf-8", { fatal: true }).decode(preimage);
  } catch {
    fail("Caddyfile preimage must be valid UTF-8");
  }
  if (preimageText.includes("\0") || !preimageText.endsWith("\n")) {
    fail("Caddyfile preimage must end in LF and contain no NUL");
  }
  if (preimageText.includes(BEGIN_MARKER) || preimageText.includes(END_MARKER)) {
    fail("Caddyfile preimage already contains the managed overlay marker");
  }
  for (const hostname of [
    plan.managed_block.placeholders.DIRECTORY_PUBLISHER_HTTPS_HOST,
    plan.managed_block.placeholders.DIRECTORY_RELAY_WSS_HOST,
    plan.managed_block.placeholders.PAYMENT_ISSUER_HTTPS_HOST,
    plan.managed_block.placeholders.PROVIDER_WSS_HOST,
  ]) {
    if (preimageText.includes(hostname)) {
      fail(`Caddyfile preimage already mentions managed hostname ${hostname}`);
    }
  }
  const candidate = Buffer.concat([preimage, Buffer.from("\n"), block]);
  if (sha256(candidate) !== plan.managed_block.candidate_sha256) {
    fail("constructed candidate SHA-256 does not match the plan");
  }
  return {
    approvedPlanSha256: computedPlanSha256,
    block,
    blockSha256: sha256(block),
    candidate,
    candidateSha256: sha256(candidate),
    preimageSha256: sha256(preimage),
  };
}

export function buildOverlayCandidateFromRendered({
  approvedPlanSha256,
  managedBlockBytes,
  plan,
  preimageBytes,
}) {
  return buildCandidateWithBlock({
    approvedPlanSha256,
    blockBytes: managedBlockBytes,
    plan,
    preimageBytes,
  });
}

export function buildOverlayCandidate({
  approvedPlanSha256,
  plan,
  preimageBytes,
  sourceBytes,
}) {
  const source = Buffer.from(sourceBytes);
  if (sha256(source) !== plan.managed_block.source_sha256) {
    fail("managed block source SHA-256 does not match the plan");
  }
  const block = renderManagedBlock(source, plan.managed_block.placeholders);
  return {
    ...buildCandidateWithBlock({
      approvedPlanSha256,
      blockBytes: block,
      plan,
      preimageBytes,
    }),
    sourceSha256: sha256(source),
  };
}

function expectedCaddyEffectiveUnit(plan, environmentNames) {
  const binary = plan.target.binary.path;
  return {
    dropin_paths: [],
    environment_names: environmentNames,
    environment_files: [],
    exec_reload: {
      argv: `${binary} reload --config ${TARGET_CONFIG} --adapter caddyfile --address ${ADMIN_UDS_DIAL}`,
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

function validateCaddyEffectiveUnit(value, label, plan) {
  if (
    value === null || typeof value !== "object" || Array.isArray(value) ||
    !Array.isArray(value.environment_names) ||
    value.environment_names.length > 512 ||
    value.environment_names.includes("CADDY_ADMIN") ||
    value.environment_names.some(
      (name, index, names) =>
        typeof name !== "string" ||
        !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name) ||
        (index > 0 && names[index - 1] >= name),
    )
  ) {
    fail(`${label}.environment_names is not a canonical CADDY_ADMIN-free inventory`);
  }
  if (
    canonicalJson(value) !==
    canonicalJson(expectedCaddyEffectiveUnit(plan, value.environment_names))
  ) {
    fail(`${label} drifted from the exact current hardened unit`);
  }
}

function validateCaddyProcessRuntime(value, label, plan) {
  exactKeys(
    value,
    [
      "caddy_admin_environment_absent",
      "cmdline_argv",
      "effective_environment_names",
      "main_pid",
      "start_time_ticks",
    ],
    label,
  );
  const binary = plan.target.binary.path;
  const expectedArgv = [binary, "run", "--config", TARGET_CONFIG, "--adapter", "caddyfile"];
  if (
    value.caddy_admin_environment_absent !== true ||
    canonicalJson(value.cmdline_argv) !== canonicalJson(expectedArgv) ||
    value.main_pid !== plan.target.unit_generation.main_pid ||
    typeof value.start_time_ticks !== "string" ||
    !/^[1-9][0-9]*$/u.test(value.start_time_ticks) ||
    !Array.isArray(value.effective_environment_names) ||
    value.effective_environment_names.length > 512 ||
    value.effective_environment_names.includes("CADDY_ADMIN") ||
    value.effective_environment_names.some(
      (name, index, names) =>
        typeof name !== "string" ||
        !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name) ||
        (index > 0 && names[index - 1] >= name),
    )
  ) {
    fail(`${label} did not bind the exact current Caddy argv and environment boundary`);
  }
}

function validateCaddyRuntimeBoundary(value, label, plan, expectedBootId) {
  exactKeys(value, ["boot_id", "effective_unit", "process", "unit_generation"], label);
  if (value.boot_id !== expectedBootId) fail(`${label}.boot_id drifted`);
  validateCaddyEffectiveUnit(value.effective_unit, `${label}.effective_unit`, plan);
  validateCaddyProcessRuntime(value.process, `${label}.process`, plan);
  if (canonicalJson(value.unit_generation) !== canonicalJson(plan.target.unit_generation)) {
    fail(`${label}.unit_generation drifted`);
  }
}

function validateAdminRuntimeEvidence(
  value,
  label,
  plan,
  expectedBootId,
  expectedAdaptedJsonSha256,
) {
  exactKeys(
    value,
    [
      "boot_id",
      "boundary",
      "denied_service_uids",
      "effective_unit",
      "monotonic_end_ns",
      "monotonic_start_ns",
      "process",
      "root_readback",
      "runtime_directory",
      "socket",
      "tcp_admin",
      "unit_generation",
    ],
    label,
  );
  if (
    value.boot_id !== expectedBootId ||
    value.boundary !== "capability-free-unprivileged-non-root-dac-only"
  ) {
    fail(`${label} boot or capability boundary drifted`);
  }
  validateCaddyEffectiveUnit(value.effective_unit, `${label}.effective_unit`, plan);
  validateCaddyProcessRuntime(value.process, `${label}.process`, plan);
  for (const [key, path, type, mode] of [
    ["runtime_directory", "/run/bitcoinpir-caddy-admin", "directory", "0700"],
    ["socket", "/run/bitcoinpir-caddy-admin/admin.sock", "socket", "0200"],
  ]) {
    const runtime = value[key];
    exactKeys(
      runtime,
      ["ctime_ns", "device", "gid", "inode", "mode", "path", "type", "uid"],
      `${label}.${key}`,
    );
    if (
      runtime.path !== path || runtime.type !== type || runtime.mode !== mode ||
      runtime.uid !== 0 || runtime.gid !== 0
    ) {
      fail(`${label}.${key} drifted from the exact DAC boundary`);
    }
    for (const decimal of ["ctime_ns", "device", "inode"]) {
      validateDecimal(runtime[decimal], `${label}.${key}.${decimal}`);
    }
    if (runtime.inode === "0") fail(`${label}.${key}.inode must be positive`);
  }
  exactKeys(
    value.root_readback,
    ["body_sha256", "cap_eff", "error", "gid", "groups", "label", "listen", "path", "status", "transport", "uid"],
    `${label}.root_readback`,
  );
  if (
    value.root_readback.cap_eff !== "0000000000000000" ||
    value.root_readback.error !== null || value.root_readback.gid !== 0 ||
    canonicalJson(value.root_readback.groups) !== canonicalJson([0]) ||
    value.root_readback.label !== "root" || value.root_readback.listen !== ADMIN_UDS_LISTEN ||
    value.root_readback.path !== "/config/" || value.root_readback.status !== 200 ||
    value.root_readback.transport !== "unix" || value.root_readback.uid !== 0
  ) {
    fail(`${label}.root_readback did not prove the active UDS config`);
  }
  validateSha256(value.root_readback.body_sha256, `${label}.root_readback.body_sha256`);
  if (value.root_readback.body_sha256 !== expectedAdaptedJsonSha256) {
    fail(`${label}.root_readback does not equal the reviewed active adapted JSON`);
  }
  if (!Array.isArray(value.denied_service_uids) || value.denied_service_uids.length < 2) {
    fail(`${label}.denied_service_uids is incomplete`);
  }
  const inventory = [];
  for (const [index, denial] of value.denied_service_uids.entries()) {
    exactKeys(denial, ["cap_eff", "error", "gid", "groups", "name", "uid"], `${label}.denied_service_uids[${index}]`);
    validateSlug(denial.name, `${label}.denied_service_uids[${index}].name`);
    validateUidGid(denial.uid, `${label}.denied_service_uids[${index}].uid`);
    if (
      denial.uid === 0 || denial.error !== "EACCES" ||
      denial.cap_eff !== "0000000000000000" || denial.gid !== denial.uid ||
      canonicalJson(denial.groups) !== canonicalJson([denial.uid])
    ) {
      fail(`${label}.denied_service_uids[${index}] is not an unprivileged EACCES proof`);
    }
    inventory.push({ name: denial.name, uid: denial.uid });
  }
  if (
    sha256(Buffer.from(canonicalize(inventory), "utf8")) !==
    plan.target.admin_uds_hardening.service_uid_inventory_sha256
  ) {
    fail(`${label}.denied_service_uids does not equal the complete approved inventory`);
  }
  const expectedTcp = ["127.0.0.1:2019", "[::1]:2019"];
  if (
    !Array.isArray(value.tcp_admin) || value.tcp_admin.length !== 2 ||
    value.tcp_admin.some((probe, index) => {
      exactKeys(probe, ["endpoint", "result"], `${label}.tcp_admin[${index}]`);
      return probe.endpoint !== expectedTcp[index] || probe.result !== "connection-refused";
    })
  ) {
    fail(`${label}.tcp_admin did not prove IPv4 and IPv6 refusal`);
  }
  if (canonicalJson(value.unit_generation) !== canonicalJson(plan.target.unit_generation)) {
    fail(`${label}.unit_generation drifted`);
  }
  validateDecimal(value.monotonic_start_ns, `${label}.monotonic_start_ns`);
  validateDecimal(value.monotonic_end_ns, `${label}.monotonic_end_ns`);
  const start = BigInt(value.monotonic_start_ns);
  const end = BigInt(value.monotonic_end_ns);
  if (start === 0n || end < start || end - start > 60_000_000_000n) {
    fail(`${label} monotonic probe window is invalid or exceeds 60 seconds`);
  }
}

function validateReceiptSnapshot(
  snapshot,
  label,
  plan,
  expectedConfigSha256,
  expectedBootId,
  expectedAdaptedJsonSha256,
) {
  exactKeys(
    snapshot,
    ["admin_runtime", "binary", "config", "source_fair_generation", "target_generation", "unit_fragment"],
    label,
  );
  validateAdminRuntimeEvidence(
    snapshot.admin_runtime,
    `${label}.admin_runtime`,
    plan,
    expectedBootId,
    expectedAdaptedJsonSha256,
  );
  for (const [key, expected] of [
    ["binary", plan.target.binary],
    ["unit_fragment", plan.target.unit_fragment],
  ]) {
    if (canonicalJson(snapshot[key]) !== canonicalJson(expected)) {
      fail(`${label}.${key} drifted from the exact overlay plan pin`);
    }
  }
  if (
    snapshot.config.path !== TARGET_CONFIG ||
    snapshot.config.sha256 !== expectedConfigSha256 ||
    snapshot.config.uid !== 0 ||
    snapshot.config.gid !== 0 ||
    snapshot.config.mode !== "0644" ||
    snapshot.config.nlink !== 1
  ) {
    fail(`${label}.config does not bind the required Caddyfile generation`);
  }
  validateRegularPin(snapshot.config, `${label}.config`, {
    paths: [TARGET_CONFIG],
    modes: ["0644"],
  });
  if (canonicalJson(snapshot.source_fair_generation) !== canonicalJson(plan.source_fair.unit_generation)) {
    fail(`${label}.source_fair_generation drifted`);
  }
  if (canonicalJson(snapshot.target_generation) !== canonicalJson(plan.target.unit_generation)) {
    fail(`${label}.target_generation drifted`);
  }
}

export function validateOverlayPreparedContext({ approvedPlanSha256, context, plan }) {
  validateOverlayPlan(plan);
  validateSha256(approvedPlanSha256, "externally approved overlay plan SHA-256");
  if (computeApprovedOverlayPlanSha256(plan) !== approvedPlanSha256) {
    fail("receipt overlay plan does not match the externally approved SHA-256");
  }
  exactKeys(context, ["backup", "before", "host", "preparation"], "overlay prepared context");
  exactKeys(context.host, ["boot_id", "machine_id_sha256"], "overlay receipt host");
  validateBootUuid(context.host.boot_id, "overlay receipt host.boot_id");
  validateSha256(context.host.machine_id_sha256, "overlay receipt host.machine_id_sha256");
  validateReceiptSnapshot(
    context.before,
    "overlay receipt before",
    plan,
    plan.target.config_preimage.sha256,
    context.host.boot_id,
    plan.target.admin_uds_hardening.adapted_json_sha256,
  );
  exactKeys(
    context.preparation,
    ["adapt_argv", "adapt_exit_status", "adapted_json_sha256", "candidate_sha256", "managed_block_sha256", "preimage_sha256", "validate_argv", "validate_exit_status"],
    "overlay receipt preparation",
  );
  for (const [key, expected] of [
    ["adapt_argv", plan.transaction.adapt_argv],
    ["validate_argv", plan.transaction.validate_argv],
  ]) {
    if (canonicalJson(context.preparation[key]) !== canonicalJson(expected)) {
      fail(`overlay receipt preparation.${key} drifted`);
    }
  }
  if (context.preparation.adapt_exit_status !== 0 || context.preparation.validate_exit_status !== 0) {
    fail("overlay receipt candidate adapt/validate did not both succeed");
  }
  validateSha256(context.preparation.adapted_json_sha256, "overlay receipt adapted JSON SHA-256");
  for (const [key, expected] of [
    ["adapted_json_sha256", plan.managed_block.candidate_adapted_json_sha256],
    ["candidate_sha256", plan.managed_block.candidate_sha256],
    ["managed_block_sha256", plan.managed_block.rendered_sha256],
    ["preimage_sha256", plan.target.config_preimage.sha256],
  ]) {
    if (context.preparation[key] !== expected) fail(`overlay receipt preparation.${key} drifted`);
  }
  exactKeys(
    context.backup,
    ["directory_fsync", "exclusive_create", "file_fsync", "gid", "mode", "nlink", "path", "sha256", "uid"],
    "overlay receipt backup",
  );
  if (
    context.backup.path !== plan.transaction.backup_path ||
    context.backup.sha256 !== plan.target.config_preimage.sha256 ||
    context.backup.uid !== 0 ||
    context.backup.gid !== 0 ||
    context.backup.mode !== "0400" ||
    context.backup.nlink !== 1 ||
    context.backup.exclusive_create !== true ||
    context.backup.file_fsync !== true ||
    context.backup.directory_fsync !== true
  ) {
    fail("overlay receipt backup is not one durable exclusive exact-preimage copy");
  }
  return true;
}

export function validateOverlayReceipt({
  approvedPlanSha256,
  plan,
  receipt,
  trustedReceiptSha256,
}) {
  validateOverlayPlan(plan);
  validateSha256(approvedPlanSha256, "externally approved overlay plan SHA-256");
  if (computeApprovedOverlayPlanSha256(plan) !== approvedPlanSha256) {
    fail("receipt overlay plan does not match the externally approved SHA-256");
  }
  exactKeys(
    receipt,
    [
      "after",
      "approved_plan_sha256",
      "backup",
      "before",
      "collector",
      "health_results",
      "host",
      "installation",
      "outcome",
      "preparation",
      "reload",
      "rollback",
      "schema_version",
      "transaction_id",
    ],
    "overlay receipt",
  );
  if (receipt.schema_version !== OVERLAY_RECEIPT_SCHEMA_VERSION) {
    fail(`overlay receipt schema_version must equal ${OVERLAY_RECEIPT_SCHEMA_VERSION}`);
  }
  if (receipt.collector !== OVERLAY_COLLECTOR) fail("overlay receipt collector is not reviewed");
  if (receipt.approved_plan_sha256 !== approvedPlanSha256) fail("overlay receipt does not bind its approved plan");
  if (receipt.transaction_id !== plan.transaction_id) fail("overlay receipt transaction_id drifted");
  validateOverlayPreparedContext({
    approvedPlanSha256,
    context: {
      backup: receipt.backup,
      before: receipt.before,
      host: receipt.host,
      preparation: receipt.preparation,
    },
    plan,
  });
  exactKeys(
    receipt.installation,
    [
      "candidate_path",
      "config_parent_fsync",
      "exchange_helper_sha256",
      "exchanged",
      "live_candidate_verified",
      "same_filesystem",
      "swapped_out_preimage_verified",
    ],
    "overlay receipt installation",
  );
  if (
    receipt.installation.candidate_path !== plan.transaction.candidate_path ||
    receipt.installation.exchange_helper_sha256 !== plan.runtime.exchange_helper.sha256 ||
    receipt.installation.exchanged !== true ||
    receipt.installation.config_parent_fsync !== true ||
    receipt.installation.live_candidate_verified !== true ||
    receipt.installation.same_filesystem !== true ||
    receipt.installation.swapped_out_preimage_verified !== true
  ) {
    fail("overlay receipt installation does not prove a verified durable same-directory exchange");
  }
  exactKeys(
    receipt.reload,
    ["argv", "exit_status", "restart_invoked", "runtime_before"],
    "overlay receipt reload",
  );
  if (
    canonicalJson(receipt.reload.argv) !== canonicalJson(plan.transaction.reload_argv) ||
    receipt.reload.restart_invoked !== false
  ) {
    fail("overlay receipt must use only the exact reload command and no restart");
  }
  if (receipt.reload.runtime_before !== null) {
    validateCaddyRuntimeBoundary(
      receipt.reload.runtime_before,
      "overlay receipt reload.runtime_before",
      plan,
      receipt.host.boot_id,
    );
  } else if (receipt.reload.exit_status !== null) {
    fail("overlay receipt reload with an observed status lacks its current runtime boundary");
  }
  exactKeys(
    receipt.rollback,
    [
      "attempted",
      "directory_fsync",
      "exact_candidate_swapped_out",
      "exact_preimage_restored",
      "exchanged",
      "reload_exit_status",
      "runtime_before",
    ],
    "overlay receipt rollback",
  );
  if (receipt.outcome === "committed") {
    if (receipt.reload.exit_status !== 0) fail("committed overlay reload did not succeed");
    if (
      receipt.rollback.attempted !== false ||
      receipt.rollback.directory_fsync !== false ||
      receipt.rollback.exact_candidate_swapped_out !== false ||
      receipt.rollback.exact_preimage_restored !== false ||
      receipt.rollback.exchanged !== false ||
      receipt.rollback.reload_exit_status !== null ||
      receipt.rollback.runtime_before !== null
    ) {
      fail("committed overlay receipt has a contradictory rollback record");
    }
    if (!Array.isArray(receipt.health_results) || receipt.health_results.length !== plan.health_checks.length) {
      fail("committed overlay receipt must cover every health check");
    }
    for (const [index, result] of receipt.health_results.entries()) {
      exactKeys(result, ["body_sha256", "check", "leaf_certificate_sha256", "status", "success"], `overlay receipt health_results[${index}]`);
      const check = plan.health_checks[index];
      if (
        canonicalJson(result.check) !== canonicalJson(check) ||
        result.status !== check.expected_status ||
        result.leaf_certificate_sha256 !== check.leaf_certificate_sha256 ||
        result.success !== true
      ) {
        fail(`overlay receipt health_results[${index}] failed or drifted`);
      }
      if (
        check.expected_body_sha256 === null
          ? result.body_sha256 !== null
          : result.body_sha256 !== check.expected_body_sha256
      ) {
        fail(`overlay receipt health_results[${index}] body digest drifted`);
      }
    }
  } else if (receipt.outcome === "rolled-back") {
    if (
      receipt.rollback.attempted !== true ||
      receipt.rollback.directory_fsync !== true ||
      receipt.rollback.exact_candidate_swapped_out !== true ||
      receipt.rollback.exact_preimage_restored !== true ||
      receipt.rollback.exchanged !== true ||
      receipt.rollback.reload_exit_status !== 0 ||
      receipt.rollback.runtime_before === null
    ) {
      fail("rolled-back overlay receipt does not prove exact durable preimage restoration and reload");
    }
    validateCaddyRuntimeBoundary(
      receipt.rollback.runtime_before,
      "overlay receipt rollback.runtime_before",
      plan,
      receipt.host.boot_id,
    );
    if (!Array.isArray(receipt.health_results) || receipt.health_results.length > plan.health_checks.length) {
      fail("rolled-back overlay receipt health result list is malformed");
    }
  } else {
    fail("overlay receipt outcome must be committed or rolled-back");
  }
  const expectedFinalSha = receipt.outcome === "committed"
    ? plan.managed_block.candidate_sha256
    : plan.target.config_preimage.sha256;
  const expectedFinalAdaptedJsonSha256 = receipt.outcome === "committed"
    ? plan.managed_block.candidate_adapted_json_sha256
    : plan.target.admin_uds_hardening.adapted_json_sha256;
  validateReceiptSnapshot(
    receipt.after,
    "overlay receipt after",
    plan,
    expectedFinalSha,
    receipt.host.boot_id,
    expectedFinalAdaptedJsonSha256,
  );
  if (
    BigInt(receipt.after.admin_runtime.monotonic_start_ns) <
    BigInt(receipt.before.admin_runtime.monotonic_end_ns)
  ) {
    fail("overlay receipt final admin runtime probe predates its initial probe");
  }
  if (trustedReceiptSha256 !== undefined) {
    validateSha256(trustedReceiptSha256, "trusted overlay receipt SHA-256");
    if (sha256(Buffer.from(canonicalJson(receipt), "utf8")) !== trustedReceiptSha256) {
      fail("overlay receipt does not match the externally trusted SHA-256");
    }
  }
  return true;
}

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const options = new Map();
  for (let index = 0; index < rest.length; index += 2) {
    const key = rest[index];
    const value = rest[index + 1];
    if (!key?.startsWith("--") || value === undefined || options.has(key)) {
      fail("overlay gate arguments must be unique --name value pairs");
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
  const { command, options } = parseArgs(argv);
  const planPath = resolve(requiredOption(options, "--plan"));
  const plan = parseStrictJson(
    readBoundedNoFollow(planPath, MAX_JSON_BYTES, "overlay plan").toString("utf8"),
    "overlay plan",
  );
  const approvedPlanSha256 = requiredOption(options, "--approved-plan-sha256");
  if (command === "prepare") {
    const sourceRoot = resolve(requiredOption(options, "--source-root"));
    const model = buildOverlayCandidate({
      approvedPlanSha256,
      plan,
      preimageBytes: readBoundedNoFollow(
        resolve(requiredOption(options, "--preimage")),
        MAX_PREIMAGE_BYTES,
        "Caddyfile preimage",
      ),
      sourceBytes: readBoundedNoFollow(
        resolve(join(sourceRoot, MANAGED_BLOCK_SOURCE)),
        MAX_BLOCK_BYTES,
        "managed block source",
      ),
    });
    process.stdout.write(`${canonicalJson({
      approved_plan_sha256: model.approvedPlanSha256,
      candidate_sha256: model.candidateSha256,
      managed_block_sha256: model.blockSha256,
      preimage_sha256: model.preimageSha256,
      source_sha256: model.sourceSha256,
    })}\n`);
    return;
  }
  if (command === "verify-receipt") {
    const receipt = parseStrictJson(
      readBoundedNoFollow(
        resolve(requiredOption(options, "--receipt")),
        MAX_JSON_BYTES,
        "overlay receipt",
      ).toString("utf8"),
      "overlay receipt",
    );
    validateOverlayReceipt({
      approvedPlanSha256,
      plan,
      receipt,
      trustedReceiptSha256: options.get("--trusted-receipt-sha256"),
    });
    process.stdout.write("integrated existing-Caddy overlay receipt verified\n");
    return;
  }
  fail("usage: overlay-gate.mjs prepare|verify-receipt --plan ... --approved-plan-sha256 ...");
}

const isMain = process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (isMain) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
