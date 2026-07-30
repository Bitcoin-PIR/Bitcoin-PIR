#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

export const PLAN_SCHEMA_VERSION = 1;
export const RECEIPT_SCHEMA_VERSION = 1;
export const PROFILE = "bhtm-caddy-admin-uds-v1";
export const COLLECTOR = "bitcoinpir-bhtm-caddy-admin-uds-cold-migration-v1";
export const TARGET_UNIT = "bhtm-caddy.service";
export const TARGET_FRAGMENT = "/etc/systemd/system/bhtm-caddy.service";
export const TARGET_CONFIG = "/etc/caddy/Caddyfile";
export const CADDY_BINARY_PATH = "/usr/local/bin/caddy";
export const ADMIN_DIRECTORY = "/run/bitcoinpir-caddy-admin";
export const ADMIN_SOCKET = `${ADMIN_DIRECTORY}/admin.sock`;
export const ADMIN_LISTEN = `unix/${ADMIN_SOCKET}|0200`;
export const ADMIN_DIAL = `unix/${ADMIN_SOCKET}`;
export const ADMIN_PROBE_PATH =
  "/usr/local/libexec/bitcoinpir/payment-v1-caddy-admin-uds-probe.mjs";
export const EXECUTOR_PATH =
  "/usr/local/libexec/bitcoinpir/payment-v1-caddy-admin-uds-transaction.mjs";
export const SETPRIV_PATH = "/usr/bin/setpriv";
export const DAC_BOUNDARY = "capability-free-unprivileged-non-root-dac-only";
export const MAX_ADAPTED_JSON_BYTES = 2 * 1024 * 1024;
export const CADDY_IMAGE_INDEX =
  "sha256:844f60b64e4724a5aa8245e019dace0d3f199f7433ce6c57676cb30a920dbad9";
export const CADDY_AMD64_MANIFEST =
  "sha256:98eb57d882ccd5213d1688764db10c1ca2c58a1ca3a6717a3411ad798f7a423a";
export const CADDY_AMD64_BINARY =
  "b7105518e3ed1c0761f232e44fc09345535533c9cb0abf0e12809416c7ac64d9";
export const NODE_IMAGE_INDEX =
  "sha256:9f6d5975c7dca860947d3915877f85607946403fc55349f39b4bc3688448bb6e";
export const NODE_AMD64_MANIFEST =
  "sha256:868499d55378719bffa87b0ed1f099591823c029b543043c09c2483468e93201";

const MAX_JSON_BYTES = 4 * 1024 * 1024;
const MAX_TEXT_BYTES = MAX_ADAPTED_JSON_BYTES;
const HEX64 = /^[0-9a-f]{64}$/u;
const SHA256 = /^sha256:[0-9a-f]{64}$/u;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/u;
const BOOT_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SYSTEMD_INVOCATION_ID = /^[0-9a-f]{32}$/u;
const SLUG = /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/u;
const BEGIN_MARKER = "# BEGIN BITCOINPIR CADDY ADMIN UDS V1";
const END_MARKER = "# END BITCOINPIR CADDY ADMIN UDS V1";
const CONFIG_EDIT_MODES = new Set([
  "replace-explicit-tcp-admin",
  "insert-existing-global-options",
  "prepend-new-global-options",
]);
const REJECTED_RUNTIME_LOG_HANDLERS = new Set(["log_append", "log_name"]);
const SERVICE_IDENTITY_MIN = 1;
const SERVICE_IDENTITY_MAX = 60_000;
const SYSTEMD_DYNAMIC_ID_MIN = 61_184;
const SYSTEMD_DYNAMIC_ID_MAX = 65_519;
const NOBODY_ID = 65_534;

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

function exactKeys(value, keys, label) {
  if (!isPlainObject(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(`${label} keys must equal ${expected.join(", ")}`);
  }
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
      fail(`${this.label} has trailing data at byte ${this.index}`);
    }
    return value;
  }

  skipWhitespace() {
    while (/^[\t\n\r ]$/u.test(this.text[this.index] ?? "")) this.index += 1;
  }

  parseValue() {
    this.skipWhitespace();
    const character = this.text[this.index];
    if (character === "{") return this.parseObject();
    if (character === "[") return this.parseArray();
    if (character === '"') return this.parseString();
    if (this.consumeLiteral("true")) return true;
    if (this.consumeLiteral("false")) return false;
    if (this.consumeLiteral("null")) return null;
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
      const character = this.text[this.index];
      const code = this.text.charCodeAt(this.index);
      if (!escaped && character === '"') {
        this.index += 1;
        try {
          return JSON.parse(this.text.slice(start, this.index));
        } catch {
          fail(`${this.label} has an invalid string at byte ${start}`);
        }
      }
      if (!escaped && code < 0x20) {
        fail(`${this.label} has a raw control character at byte ${this.index}`);
      }
      if (!escaped && character === "\\") escaped = true;
      else escaped = false;
      this.index += 1;
    }
    fail(`${this.label} has an unterminated string at byte ${start}`);
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
      if (Object.prototype.hasOwnProperty.call(result, key)) {
        fail(`${this.label} contains duplicate key ${JSON.stringify(key)}`);
      }
      this.skipWhitespace();
      if (this.text[this.index] !== ":") {
        fail(`${this.label} object key is missing a colon at byte ${this.index}`);
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
  return new StrictJsonParser(text, label).parse();
}

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
  if (isPlainObject(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  ) {
    return JSON.stringify(value);
  }
  fail("canonical JSON contains an unsupported value");
}

export function parseCanonicalReceipt(bytes) {
  const buffer = Buffer.from(bytes);
  const receipt = parseStrictJson(buffer.toString("utf8"), "hardening receipt");
  if (!buffer.equals(Buffer.from(canonicalJson(receipt), "utf8"))) {
    fail("hardening receipt bytes must equal their canonical JSON encoding");
  }
  return receipt;
}

export function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function validateHex64(value, label) {
  if (typeof value !== "string" || !HEX64.test(value)) fail(`${label} must be 64 lowercase hex`);
}

function validateDigest(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) fail(`${label} must be sha256:<64 lowercase hex>`);
}

function validateDecimal(value, label) {
  if (typeof value !== "string" || !DECIMAL.test(value)) fail(`${label} must be canonical decimal text`);
}

export function validateSystemdInvocationId(value, label = "systemd InvocationID") {
  if (
    typeof value !== "string" ||
    !SYSTEMD_INVOCATION_ID.test(value) ||
    value === "0".repeat(32)
  ) {
    fail(`${label} must be a nonzero 32-character lowercase systemd InvocationID`);
  }
  return true;
}

export function normalizeSystemdInvocationId(
  value,
  { active, label = "systemd InvocationID" },
) {
  if (active) {
    validateSystemdInvocationId(value, label);
    return value;
  }
  if (value === "" || value === "0".repeat(32)) return "";
  fail(`${label} for an inactive unit must be empty or 32 zeroes`);
}

function validateUid(value, label, { nonRoot = false } = {}) {
  if (!Number.isSafeInteger(value) || value < (nonRoot ? 1 : 0) || value > 4_294_967_294) {
    fail(`${label} is outside the reviewed UID range`);
  }
}

function validateServiceIdentityId(value, label) {
  if (
    !Number.isSafeInteger(value) ||
    value < SERVICE_IDENTITY_MIN ||
    value > SERVICE_IDENTITY_MAX
  ) {
    fail(
      `${label} must be a static service uid/gid in ` +
      `[${SERVICE_IDENTITY_MIN}, ${SERVICE_IDENTITY_MAX}], outside systemd DynamicUser ` +
      `[${SYSTEMD_DYNAMIC_ID_MIN}, ${SYSTEMD_DYNAMIC_ID_MAX}] and nobody ${NOBODY_ID}`,
    );
  }
}

function validateSlug(value, label) {
  if (typeof value !== "string" || !SLUG.test(value)) fail(`${label} must be a canonical slug`);
}

function validateContentPin(value, label, { path, modes }, { exact = true } = {}) {
  if (exact) exactKeys(value, ["gid", "mode", "path", "sha256", "size", "uid"], label);
  if (value.path !== path) fail(`${label}.path must equal ${path}`);
  validateHex64(value.sha256, `${label}.sha256`);
  validateDecimal(value.size, `${label}.size`);
  validateUid(value.uid, `${label}.uid`);
  validateUid(value.gid, `${label}.gid`);
  if (value.uid !== 0 || value.gid !== 0) fail(`${label} must be root:root`);
  if (!modes.includes(value.mode)) fail(`${label}.mode must be one of ${modes.join(", ")}`);
}

function validateSnapshot(value, label, options) {
  exactKeys(
    value,
    [
      "ctime_ns",
      "device",
      "gid",
      "inode",
      "mode",
      "mtime_ns",
      "nlink",
      "path",
      "sha256",
      "size",
      "uid",
    ],
    label,
  );
  validateContentPin(value, label, options, { exact: false });
  for (const key of ["ctime_ns", "device", "inode", "mtime_ns", "size"]) {
    validateDecimal(value[key], `${label}.${key}`);
  }
  if (value.nlink !== 1) fail(`${label}.nlink must equal 1`);
}

function validateUnitGeneration(value, label, { active }) {
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
  if (value.unit_name !== TARGET_UNIT) fail(`${label}.unit_name must equal ${TARGET_UNIT}`);
  if (value.control_group !== `/system.slice/${TARGET_UNIT}`) {
    fail(`${label}.control_group must equal /system.slice/${TARGET_UNIT}`);
  }
  if (active) {
    if (value.active_state !== "active" || value.sub_state !== "running") {
      fail(`${label} must be active/running`);
    }
    validateDecimal(value.main_pid, `${label}.main_pid`);
    if (value.main_pid === "0") fail(`${label}.main_pid must be nonzero`);
    validateDecimal(
      value.active_enter_timestamp_monotonic,
      `${label}.active_enter_timestamp_monotonic`,
    );
    validateSystemdInvocationId(value.invocation_id, `${label}.invocation_id`);
  } else {
    if (value.active_state !== "inactive" || value.sub_state !== "dead") {
      fail(`${label} must be inactive/dead`);
    }
    if (
      value.main_pid !== "0" ||
      value.invocation_id !== "" ||
      value.active_enter_timestamp_monotonic !== "0"
    ) {
      fail(`${label} must have no live process generation`);
    }
  }
}

function canonicalText(bytes, label) {
  const buffer = Buffer.from(bytes);
  if (buffer.length < 1 || buffer.length > MAX_TEXT_BYTES) {
    fail(`${label} size is outside [1, ${MAX_TEXT_BYTES}]`);
  }
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
  } catch {
    fail(`${label} must be valid UTF-8`);
  }
  if (text.includes("\0") || text.includes("\r") || !text.endsWith("\n")) {
    fail(`${label} must be canonical LF text ending in LF`);
  }
  return text;
}

function significant(line) {
  return line.trim() !== "" && !line.trimStart().startsWith("#");
}

function braceDelta(line) {
  let delta = 0;
  let quote = null;
  let escaped = false;
  for (const character of line) {
    if (quote === '"' && escaped) {
      escaped = false;
      continue;
    }
    if (quote === '"' && character === "\\") {
      escaped = true;
      continue;
    }
    if (quote !== null) {
      if (character === quote) quote = null;
      continue;
    }
    if (character === "#") break;
    if (character === '"' || character === "`") {
      quote = character;
      continue;
    }
    if (character === "{") delta += 1;
    if (character === "}") delta -= 1;
  }
  if (quote !== null) fail("Caddyfile contains an unterminated quoted token");
  return delta;
}

function globalBlock(lines, label) {
  const first = lines.findIndex(significant);
  if (first === -1 || lines[first].trim() !== "{") return null;
  let depth = 0;
  for (let index = first; index < lines.length; index += 1) {
    depth += braceDelta(lines[index]);
    if (depth < 0) fail(`${label} closes its global options block unexpectedly`);
    if (index > first && depth === 0) return { close: index, open: first };
  }
  fail(`${label} has an unterminated global options block`);
}

function adminDirectiveIndexes(lines, block) {
  if (block === null) return { all: [], topLevel: [] };
  const all = [];
  const topLevel = [];
  let depth = 1;
  for (let index = block.open + 1; index < block.close; index += 1) {
    const trimmed = lines[index].trimStart();
    if (!trimmed.startsWith("#") && /^admin(?:[\t ]|$)/u.test(trimmed)) {
      all.push(index);
      if (depth === 1) topLevel.push(index);
    }
    depth += braceDelta(lines[index]);
  }
  return { all, topLevel };
}

function isCaddyWhitespace(character) {
  return /^\p{White_Space}$/u.test(character);
}

function isCanonicalCaddyWhitespace(character) {
  return character === " " || character === "\t" || character === "\n" || character === "\r";
}

function rejectDynamicCaddyInputs(text, label) {
  if (/(?:\{env\.[^}]*\}|\{\$[^}]*\})/u.test(text)) {
    fail(`${label} must not contain environment-backed Caddy placeholders`);
  }
  let token = "";
  let quote = null;
  let quotedToken = "";
  let escaped = false;
  let comment = false;
  const finishToken = () => {
    if (token === "import") {
      fail(`${label} must not contain import directives in the closed V1 profile`);
    }
    token = "";
  };
  const finishQuotedToken = () => {
    // Caddy removes both double-quote and backtick delimiters before directive
    // dispatch. Quoted directive names therefore cannot be ignored by a
    // closed-profile lexer even though quoted arguments remain valid.
    if (quotedToken === "import") {
      fail(`${label} must not contain quoted import directives in the closed V1 profile`);
    }
    if (quotedToken === "admin") {
      fail(`${label} must not contain quoted admin directives in the closed V1 profile`);
    }
    quotedToken = "";
  };
  for (const character of text) {
    if (comment) {
      if (character === "\n") comment = false;
      continue;
    }
    if (quote === '"' && escaped) {
      quotedToken += character;
      escaped = false;
      continue;
    }
    if (quote === '"' && character === "\\") {
      escaped = true;
      continue;
    }
    if (quote !== null) {
      if (character === quote) {
        finishQuotedToken();
        quote = null;
      } else {
        quotedToken += character;
      }
      continue;
    }
    if (character === "#") {
      finishToken();
      comment = true;
    } else if (character === '"' || character === "`") {
      finishToken();
      quote = character;
      quotedToken = "";
    } else if (isCaddyWhitespace(character)) {
      // Caddy v2.11.4 delegates token separation to Go's Unicode whitespace
      // table. V1 permits only the canonical ASCII subset so visually
      // ambiguous separators can never evade the line-oriented policy checks.
      if (!isCanonicalCaddyWhitespace(character)) {
        const codePoint = character.codePointAt(0).toString(16).toUpperCase().padStart(4, "0");
        fail(`${label} contains non-canonical Caddy whitespace U+${codePoint}`);
      }
      finishToken();
    } else if (character === "{" || character === "}") {
      finishToken();
    } else {
      token += character;
    }
  }
  if (quote !== null) fail(`${label} contains an unterminated quoted token`);
  finishToken();
}

export function buildHardenedCaddyfile(preimageBytes, editMode) {
  if (!CONFIG_EDIT_MODES.has(editMode)) fail("config edit mode is not reviewed");
  const text = canonicalText(preimageBytes, "Caddyfile preimage");
  rejectDynamicCaddyInputs(text, "Caddyfile preimage");
  if (text.includes("CADDY_ADMIN")) fail("Caddyfile preimage must not derive admin from CADDY_ADMIN");
  const lines = text.slice(0, -1).split("\n");
  const block = globalBlock(lines, "Caddyfile preimage");
  const indexes = adminDirectiveIndexes(lines, block);
  if (editMode === "replace-explicit-tcp-admin") {
    if (block === null || indexes.all.length !== 1 || indexes.topLevel.length !== 1) {
      fail("replace-explicit-tcp-admin requires exactly one top-level global admin directive");
    }
    const match = /^([\t ]*)admin[\t ]+127\.0\.0\.1:2019[\t ]*$/u.exec(
      lines[indexes.topLevel[0]],
    );
    if (!match) fail("the explicit preimage admin directive must equal 127.0.0.1:2019");
    lines[indexes.topLevel[0]] = `${match[1]}admin ${ADMIN_LISTEN}`;
  } else if (editMode === "insert-existing-global-options") {
    if (block === null || indexes.all.length !== 0) {
      fail("insert-existing-global-options requires one global block with no admin directive");
    }
    lines.splice(block.open + 1, 0, `\tadmin ${ADMIN_LISTEN}`);
  } else {
    if (block !== null || indexes.all.length !== 0) {
      fail("prepend-new-global-options requires no existing global options block");
    }
    lines.unshift("{", `\tadmin ${ADMIN_LISTEN}`, "}", "");
  }
  const candidate = Buffer.from(`${lines.join("\n")}\n`, "utf8");
  validateHardenedCaddyfile(candidate);
  return candidate;
}

export function validateHardenedCaddyfile(candidateBytes) {
  const text = canonicalText(candidateBytes, "hardened Caddyfile");
  rejectDynamicCaddyInputs(text, "hardened Caddyfile");
  if (text.includes("CADDY_ADMIN")) fail("hardened Caddyfile must not reference CADDY_ADMIN");
  const lines = text.slice(0, -1).split("\n");
  const block = globalBlock(lines, "hardened Caddyfile");
  if (block === null) fail("hardened Caddyfile must have a global options block");
  const indexes = adminDirectiveIndexes(lines, block);
  if (
    indexes.all.length !== 1 ||
    indexes.topLevel.length !== 1 ||
    lines[indexes.topLevel[0]].trim() !== `admin ${ADMIN_LISTEN}`
  ) {
    fail(`hardened Caddyfile admin must equal ${ADMIN_LISTEN}`);
  }
  if (/^\s*admin(?:[\t ]|$)/mu.test(lines.slice(block.close + 1).join("\n"))) {
    fail("hardened Caddyfile contains an admin directive outside the global block");
  }
  return true;
}

function rejectRuntimeLogHandlers(value, path = "adapted") {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => rejectRuntimeLogHandlers(entry, `${path}[${index}]`));
    return;
  }
  if (!isPlainObject(value)) return;
  if (REJECTED_RUNTIME_LOG_HANDLERS.has(value.handler)) {
    fail(`${path}.handler enables a request-correlating runtime log handler`);
  }
  for (const [key, entry] of Object.entries(value)) {
    rejectRuntimeLogHandlers(entry, `${path}.${key}`);
  }
}

function rejectUnsafeAdaptedJsonNumbers(value, path = "adapted") {
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      fail(`${path} contains a non-finite JSON number`);
    }
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      fail(`${path} contains an integer outside the interoperable safe range`);
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) => rejectUnsafeAdaptedJsonNumbers(entry, `${path}[${index}]`));
    return;
  }
  if (!isPlainObject(value)) return;
  for (const [key, entry] of Object.entries(value)) {
    rejectUnsafeAdaptedJsonNumbers(entry, `${path}.${key}`);
  }
}

export function validateAdaptedCaddyPrivacyPolicy(adapted) {
  if (!isPlainObject(adapted)) fail("adapted Caddy JSON must be an object");
  rejectUnsafeAdaptedJsonNumbers(adapted);
  if (Object.hasOwn(adapted, "logging")) {
    fail("adapted Caddy JSON must not configure a global logging sink");
  }
  const servers = adapted.apps?.http?.servers;
  if (servers !== undefined) {
    if (!isPlainObject(servers)) fail("adapted Caddy JSON apps.http.servers must be an object");
    for (const [name, server] of Object.entries(servers)) {
      if (!isPlainObject(server)) fail(`adapted Caddy JSON server ${name} must be an object`);
      if (Object.hasOwn(server, "logs")) {
        fail(`adapted Caddy JSON server ${name} must not enable access logging`);
      }
    }
  }
  rejectRuntimeLogHandlers(adapted);
  return true;
}

export function validateAdaptedCaddyPrivacy(adapted, expectedAdminListen = ADMIN_LISTEN) {
  validateAdaptedCaddyPrivacyPolicy(adapted);
  if (!isPlainObject(adapted.admin) || adapted.admin.listen !== expectedAdminListen) {
    fail(`adapted Caddy JSON admin.listen must equal ${expectedAdminListen}`);
  }
  return true;
}

function serviceSectionBounds(lines, label) {
  const indexes = [];
  for (const [index, line] of lines.entries()) {
    if (line.trim() === "[Service]") indexes.push(index);
  }
  if (indexes.length !== 1) fail(`${label} must contain exactly one [Service] section`);
  const start = indexes[0];
  let end = lines.length;
  for (let index = start + 1; index < lines.length; index += 1) {
    if (/^\s*\[[^\]]+\]\s*$/u.test(lines[index])) {
      end = index;
      break;
    }
  }
  return { end, start };
}

function systemdDirective(line) {
  const match = /^\s*([A-Za-z][A-Za-z0-9]*)\s*=(.*)$/u.exec(line);
  return match === null ? null : { name: match[1], value: match[2].trim() };
}

function unquote(value) {
  if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
    return value.slice(1, -1);
  }
  return value;
}

function validateExecStart(value, binaryPath, label, { allowEnviron = false } = {}) {
  const tokens = value.split(/[\t ]+/u).filter((token) => token !== "");
  if (tokens[0] !== binaryPath || tokens[1] !== "run") {
    fail(`${label} must execute the exact plan-pinned Caddy binary with run`);
  }
  let index = 2;
  if (tokens[index] === "--environ") {
    if (!allowEnviron) {
      fail(`${label} must not use --environ because it writes the service environment to logs`);
    }
    index += 1;
  }
  if (
    tokens[index] !== "--config" ||
    tokens[index + 1] !== TARGET_CONFIG ||
    tokens[index + 2] !== "--adapter" ||
    tokens[index + 3] !== "caddyfile" ||
    index + 4 !== tokens.length
  ) {
    fail(`${label} must use only the exact Caddyfile config and adapter arguments`);
  }
}

function validatePreimageUnit(lines, bounds, binaryPath) {
  let user = "root";
  let group = "root";
  let execStart = 0;
  let execReload = 0;
  for (let index = bounds.start + 1; index < bounds.end; index += 1) {
    const directive = systemdDirective(lines[index]);
    if (directive === null) continue;
    if (
      new Set([
        "RuntimeDirectory",
        "RuntimeDirectoryMode",
        "RuntimeDirectoryPreserve",
        "UMask",
        "UnsetEnvironment",
      ]).has(directive.name)
    ) {
      fail(`unit preimage already defines ${directive.name}; this first-generation profile will not overwrite it`);
    }
    if (directive.name === "EnvironmentFile") {
      fail("unit preimage with EnvironmentFile cannot prove CADDY_ADMIN absence");
    }
    if (directive.name === "PassEnvironment") {
      fail("unit preimage must not use PassEnvironment in the closed V1 profile");
    }
    if (directive.name === "Environment" && directive.value.includes("CADDY_ADMIN")) {
      const value = unquote(directive.value);
      if (value !== "CADDY_ADMIN=127.0.0.1:2019") {
        fail("unit preimage has an unreviewed CADDY_ADMIN assignment");
      }
    }
    if (directive.name === "User") user = directive.value;
    if (directive.name === "Group") group = directive.value;
    if (directive.name === "ExecStart" && directive.value !== "") {
      execStart += 1;
      validateExecStart(directive.value, binaryPath, "unit preimage ExecStart", {
        allowEnviron: true,
      });
      if (!directive.value.split(/[\t ]+/u).includes("--environ")) {
        fail("unit preimage ExecStart must retain the exact reviewed --environ argument");
      }
    }
    if (directive.name === "ExecReload" && directive.value !== "") {
      execReload += 1;
      if (
        directive.value !==
        `${binaryPath} reload --config ${TARGET_CONFIG} --adapter caddyfile --force`
      ) {
        fail("unit preimage ExecReload must equal the exact reviewed TCP-admin reload command");
      }
    }
    if (/--envfile(?:[=\t ]|$)/u.test(directive.value)) {
      fail("unit preimage must not load an environment file from an Exec command");
    }
  }
  if (user !== "root" || group !== "root") fail("bhtm-caddy.service preimage must run as root:root");
  if (execStart !== 1) fail("bhtm-caddy.service preimage must have exactly one ExecStart");
  if (execReload !== 1) fail("bhtm-caddy.service preimage must have exactly one ExecReload");
}

const REPLACED_UNIT_DIRECTIVES = new Set([
  "ExecReload",
  "ExecStart",
  "Group",
  "LimitCORE",
  "MemorySwapMax",
  "StandardError",
  "StandardOutput",
  "User",
]);
const MANAGED_UNIT_DIRECTIVES = new Set([
  ...REPLACED_UNIT_DIRECTIVES,
  "RuntimeDirectory",
  "RuntimeDirectoryMode",
  "RuntimeDirectoryPreserve",
  "UMask",
  "UnsetEnvironment",
]);

export function buildHardenedUnit(preimageBytes, binaryPath = CADDY_BINARY_PATH) {
  if (binaryPath !== CADDY_BINARY_PATH) {
    fail(`Caddy binary path must equal the reviewed Hetzner path ${CADDY_BINARY_PATH}`);
  }
  const text = canonicalText(preimageBytes, "unit preimage");
  if (text.includes("\\\n")) fail("unit preimage must not contain continuation lines");
  if (text.includes(BEGIN_MARKER) || text.includes(END_MARKER)) {
    fail("unit preimage already contains the managed hardening marker");
  }
  const lines = text.slice(0, -1).split("\n");
  const bounds = serviceSectionBounds(lines, "unit preimage");
  validatePreimageUnit(lines, bounds, binaryPath);
  const kept = [];
  for (let index = bounds.start + 1; index < bounds.end; index += 1) {
    const line = lines[index];
    const directive = systemdDirective(line);
    if (directive !== null && REPLACED_UNIT_DIRECTIVES.has(directive.name)) continue;
    if (
      directive !== null &&
      directive.name === "Environment" &&
      unquote(directive.value) === "CADDY_ADMIN=127.0.0.1:2019"
    ) {
      continue;
    }
    kept.push(line);
  }
  const block = [
    BEGIN_MARKER,
    "User=root",
    "Group=root",
    "RuntimeDirectory=bitcoinpir-caddy-admin",
    "RuntimeDirectoryMode=0700",
    "RuntimeDirectoryPreserve=no",
    "LimitCORE=0",
    "MemorySwapMax=0",
    "StandardOutput=null",
    "StandardError=null",
    "UMask=0077",
    "UnsetEnvironment=CADDY_ADMIN",
    `ExecStart=${binaryPath} run --config ${TARGET_CONFIG} --adapter caddyfile`,
    "ExecReload=",
    `ExecReload=${binaryPath} reload --config ${TARGET_CONFIG} --adapter caddyfile --address ${ADMIN_DIAL}`,
    END_MARKER,
  ];
  lines.splice(bounds.start + 1, bounds.end - bounds.start - 1, ...kept, ...block);
  const candidate = Buffer.from(`${lines.join("\n")}\n`, "utf8");
  validateHardenedUnit(candidate, binaryPath);
  return candidate;
}

export function validateHardenedUnit(candidateBytes, binaryPath = CADDY_BINARY_PATH) {
  if (binaryPath !== CADDY_BINARY_PATH) {
    fail(`Caddy binary path must equal the reviewed Hetzner path ${CADDY_BINARY_PATH}`);
  }
  const text = canonicalText(candidateBytes, "hardened unit");
  if ((text.match(new RegExp(`^${BEGIN_MARKER}$`, "gmu")) ?? []).length !== 1 ||
      (text.match(new RegExp(`^${END_MARKER}$`, "gmu")) ?? []).length !== 1) {
    fail("hardened unit must contain one exact managed marker pair");
  }
  const lines = text.slice(0, -1).split("\n");
  const bounds = serviceSectionBounds(lines, "hardened unit");
  const values = new Map();
  let execStart = 0;
  const execReload = [];
  for (let index = bounds.start + 1; index < bounds.end; index += 1) {
    const directive = systemdDirective(lines[index]);
    if (directive === null) continue;
    if (directive.name === "EnvironmentFile") fail("hardened unit must not use EnvironmentFile");
    if (directive.name === "Environment" && directive.value.includes("CADDY_ADMIN")) {
      fail("hardened unit retains a CADDY_ADMIN environment assignment");
    }
    if (directive.name === "PassEnvironment") {
      fail("hardened unit must not use PassEnvironment in the closed V1 profile");
    }
    if (/--envfile(?:[=\t ]|$)/u.test(directive.value)) {
      fail("hardened unit loads an environment file from an Exec command");
    }
    if (directive.name === "ExecStart" && directive.value !== "") {
      execStart += 1;
      validateExecStart(directive.value, binaryPath, "hardened unit ExecStart");
    }
    if (directive.name === "ExecReload") execReload.push(directive.value);
    if (MANAGED_UNIT_DIRECTIVES.has(directive.name) && directive.name !== "ExecReload") {
      const entries = values.get(directive.name) ?? [];
      entries.push(directive.value);
      values.set(directive.name, entries);
    }
  }
  const expected = new Map([
    ["User", ["root"]],
    ["Group", ["root"]],
    ["LimitCORE", ["0"]],
    ["MemorySwapMax", ["0"]],
    ["RuntimeDirectory", ["bitcoinpir-caddy-admin"]],
    ["RuntimeDirectoryMode", ["0700"]],
    ["RuntimeDirectoryPreserve", ["no"]],
    ["StandardError", ["null"]],
    ["StandardOutput", ["null"]],
    ["UMask", ["0077"]],
    ["UnsetEnvironment", ["CADDY_ADMIN"]],
  ]);
  for (const [name, exact] of expected) {
    if (JSON.stringify(values.get(name) ?? []) !== JSON.stringify(exact)) {
      fail(`hardened unit ${name} must equal ${exact.join(" ")}`);
    }
  }
  const expectedReload = [
    "",
    `${binaryPath} reload --config ${TARGET_CONFIG} --adapter caddyfile --address ${ADMIN_DIAL}`,
  ];
  if (JSON.stringify(execReload) !== JSON.stringify(expectedReload)) {
    fail("hardened unit must reset ExecReload and dial the exact admin Unix socket");
  }
  if (execStart !== 1) fail("hardened unit must retain exactly one ExecStart");
  return true;
}

function validateSupplyChain(value, binarySha256) {
  exactKeys(value, ["caddy", "node"], "supply_chain");
  exactKeys(
    value.caddy,
    [
      "amd64_binary_sha256",
      "amd64_manifest_digest",
      "image",
      "image_index_digest",
      "production_binary_sha256",
      "resolved_tag",
      "version",
    ],
    "supply_chain.caddy",
  );
  const caddyExpected = {
    amd64_binary_sha256: CADDY_AMD64_BINARY,
    amd64_manifest_digest: CADDY_AMD64_MANIFEST,
    image: "docker.io/library/caddy",
    image_index_digest: CADDY_IMAGE_INDEX,
    production_binary_sha256: binarySha256,
    resolved_tag: "2.11.4",
    version: "v2.11.4",
  };
  for (const [key, expected] of Object.entries(caddyExpected)) {
    if (value.caddy[key] !== expected) fail(`supply_chain.caddy.${key} must equal ${expected}`);
  }
  exactKeys(
    value.node,
    ["amd64_manifest_digest", "image", "image_index_digest", "resolved_tag", "version"],
    "supply_chain.node",
  );
  const nodeExpected = {
    amd64_manifest_digest: NODE_AMD64_MANIFEST,
    image: "docker.io/library/node",
    image_index_digest: NODE_IMAGE_INDEX,
    resolved_tag: "22.22.2-bookworm-slim",
    version: "v22.22.2",
  };
  for (const [key, expected] of Object.entries(nodeExpected)) {
    if (value.node[key] !== expected) fail(`supply_chain.node.${key} must equal ${expected}`);
  }
}

function validateRuntime(value) {
  exactKeys(
    value,
    ["executor", "gate", "node_binary", "node_version", "probe", "setpriv_binary", "systemd_version"],
    "runtime",
  );
  validateSnapshot(value.executor, "runtime.executor", {
    modes: ["0555"],
    path: EXECUTOR_PATH,
  });
  validateSnapshot(value.gate, "runtime.gate", {
    modes: ["0555", "0755"],
    path: "/usr/local/libexec/bitcoinpir/payment-v1-caddy-admin-uds-gate.mjs",
  });
  validateSnapshot(value.node_binary, "runtime.node_binary", {
    modes: ["0555", "0755"],
    path: "/usr/bin/node",
  });
  validateSnapshot(value.probe, "runtime.probe", {
    modes: ["0555", "0755"],
    path: ADMIN_PROBE_PATH,
  });
  validateSnapshot(value.setpriv_binary, "runtime.setpriv_binary", {
    modes: ["0555", "0755"],
    path: SETPRIV_PATH,
  });
  if (value.node_version !== "v22.22.2") fail("runtime.node_version must equal v22.22.2");
  if (value.systemd_version !== "255") fail("runtime.systemd_version must equal 255");
}

function validatePrivilegedAccessInventory(value) {
  exactKeys(
    value,
    [
      "boot_id",
      "captured_monotonic_ns",
      "evidence_sha256",
      "process_count",
      "root_or_cap_dac_override_not_isolated",
      "scope",
    ],
    "privileged_access_inventory",
  );
  if (typeof value.boot_id !== "string" || !BOOT_UUID.test(value.boot_id)) {
    fail("privileged_access_inventory.boot_id must be a lowercase UUID");
  }
  validateDecimal(value.captured_monotonic_ns, "privileged_access_inventory.captured_monotonic_ns");
  if (value.captured_monotonic_ns === "0") {
    fail("privileged_access_inventory.captured_monotonic_ns must be positive");
  }
  validateHex64(value.evidence_sha256, "privileged_access_inventory.evidence_sha256");
  if (!Number.isSafeInteger(value.process_count) || value.process_count < 1 || value.process_count > 1_000_000) {
    fail("privileged_access_inventory.process_count is outside [1, 1000000]");
  }
  if (value.scope !== DAC_BOUNDARY || value.root_or_cap_dac_override_not_isolated !== true) {
    fail(`privileged_access_inventory must acknowledge ${DAC_BOUNDARY}`);
  }
}

function validatePreimage(value) {
  exactKeys(
    value,
    ["adapted_json_sha256", "adapted_json_size", "admin", "binary", "config", "unit", "unit_generation"],
    "preimage",
  );
  validateHex64(value.adapted_json_sha256, "preimage.adapted_json_sha256");
  validateDecimal(value.adapted_json_size, "preimage.adapted_json_size");
  const adaptedJsonSize = Number(value.adapted_json_size);
  if (
    !Number.isSafeInteger(adaptedJsonSize) ||
    adaptedJsonSize < 1 ||
    adaptedJsonSize > MAX_TEXT_BYTES
  ) {
    fail(`preimage.adapted_json_size must be inside [1, ${MAX_TEXT_BYTES}]`);
  }
  validateSnapshot(value.binary, "preimage.binary", {
    modes: ["0555", "0755"],
    path: CADDY_BINARY_PATH,
  });
  validateSnapshot(value.config, "preimage.config", { modes: ["0644"], path: TARGET_CONFIG });
  validateSnapshot(value.unit, "preimage.unit", { modes: ["0644"], path: TARGET_FRAGMENT });
  validateUnitGeneration(value.unit_generation, "preimage.unit_generation", { active: true });
  exactKeys(value.admin, ["kind", "listen"], "preimage.admin");
  if (value.admin.kind !== "tcp" || value.admin.listen !== "127.0.0.1:2019") {
    fail("preimage.admin must bind the reviewed TCP endpoint 127.0.0.1:2019");
  }
}

function validateCandidate(value) {
  exactKeys(
    value,
    [
      "adapted_json_sha256",
      "adapted_json_size",
      "binary",
      "config",
      "unit",
      "unit_policy",
    ],
    "candidate",
  );
  validateHex64(value.adapted_json_sha256, "candidate.adapted_json_sha256");
  validateDecimal(value.adapted_json_size, "candidate.adapted_json_size");
  const adaptedJsonSize = Number(value.adapted_json_size);
  if (
    !Number.isSafeInteger(adaptedJsonSize) ||
    adaptedJsonSize < 1 ||
    adaptedJsonSize > MAX_TEXT_BYTES
  ) {
    fail(`candidate.adapted_json_size must be inside [1, ${MAX_TEXT_BYTES}]`);
  }
  validateContentPin(value.binary, "candidate.binary", {
    modes: ["0555", "0755"],
    path: CADDY_BINARY_PATH,
  });
  validateContentPin(value.config, "candidate.config", { modes: ["0644"], path: TARGET_CONFIG });
  validateContentPin(value.unit, "candidate.unit", { modes: ["0644"], path: TARGET_FRAGMENT });
  exactKeys(
    value.unit_policy,
    [
      "admin_dial",
      "admin_listen",
      "caddy_admin_environment_absent",
      "dropins",
      "runtime_directory",
      "runtime_directory_mode",
      "runtime_directory_preserve",
      "service_gid",
      "service_uid",
      "limit_core",
      "memory_swap_max",
      "standard_error",
      "standard_output",
      "umask",
    ],
    "candidate.unit_policy",
  );
  const exact = {
    admin_dial: ADMIN_DIAL,
    admin_listen: ADMIN_LISTEN,
    caddy_admin_environment_absent: true,
    runtime_directory: ADMIN_DIRECTORY,
    runtime_directory_mode: "0700",
    runtime_directory_preserve: "no",
    service_gid: 0,
    service_uid: 0,
    limit_core: "0",
    memory_swap_max: "0",
    standard_error: "null",
    standard_output: "null",
    umask: "0077",
  };
  for (const [key, expected] of Object.entries(exact)) {
    if (value.unit_policy[key] !== expected) fail(`candidate.unit_policy.${key} must equal ${expected}`);
  }
  if (!Array.isArray(value.unit_policy.dropins) || value.unit_policy.dropins.length !== 0) {
    fail("candidate.unit_policy.dropins must be empty");
  }
}

function validateServiceUidInventory(value) {
  if (!Array.isArray(value) || value.length < 2 || value.length > 128) {
    fail("service_uid_inventory must contain 2..128 non-root services");
  }
  const names = new Set();
  const uids = new Set();
  let previous = "";
  for (const [index, entry] of value.entries()) {
    exactKeys(entry, ["name", "uid"], `service_uid_inventory[${index}]`);
    validateSlug(entry.name, `service_uid_inventory[${index}].name`);
    validateServiceIdentityId(entry.uid, `service_uid_inventory[${index}].uid`);
    const key = `${entry.name}:${String(entry.uid).padStart(10, "0")}`;
    if (key <= previous) fail("service_uid_inventory must use canonical name/UID order");
    previous = key;
    if (names.has(entry.name) || uids.has(entry.uid)) fail("service_uid_inventory names and UIDs must be unique");
    names.add(entry.name);
    uids.add(entry.uid);
  }
  for (const required of ["cloudflared", "pir"]) {
    if (!names.has(required)) fail(`service_uid_inventory must include ${required}`);
  }
}

function validateSitePreservation(value) {
  exactKeys(
    value,
    ["acme_storage_migration", "existing_site_inventory_sha256", "probe_ids"],
    "site_preservation",
  );
  validateHex64(value.existing_site_inventory_sha256, "site_preservation.existing_site_inventory_sha256");
  if (value.acme_storage_migration !== "none") {
    fail("site_preservation.acme_storage_migration must equal none");
  }
  if (!Array.isArray(value.probe_ids) || value.probe_ids.length < 3 || value.probe_ids.length > 128) {
    fail("site_preservation.probe_ids must contain 3..128 complete public/direct/TLS site probes");
  }
  let previous = "";
  for (const [index, id] of value.probe_ids.entries()) {
    validateSlug(id, `site_preservation.probe_ids[${index}]`);
    if (id <= previous) fail("site_preservation.probe_ids must be sorted and unique");
    previous = id;
  }
}

function validateTransaction(value, transactionId) {
  exactKeys(
    value,
    [
      "activation_mode",
      "automatic_rollback_after_ambiguous_start",
      "backup_config_path",
      "backup_unit_path",
      "candidate_config_path",
      "candidate_unit_path",
      "classification",
      "daemon_reload_argv",
      "installation_mode",
      "lock_path",
      "new_invocation_required",
      "outcome_unknown_conditions",
      "receipt_path",
      "reload_forbidden",
      "rollback_mode",
      "runtime_directory_creation",
      "start_argv",
      "state_directory",
      "stop_argv",
    ],
    "transaction",
  );
  const root = "/var/lib/bitcoinpir/payment-v1/bhtm-caddy-admin-uds";
  const exact = {
    activation_mode: "cold-stop-install-daemon-reload-start-new-generation",
    automatic_rollback_after_ambiguous_start: false,
    backup_config_path: `${root}/backups/${transactionId}.old.Caddyfile`,
    backup_unit_path: `${root}/backups/${transactionId}.old.service`,
    candidate_config_path: `/etc/caddy/.bitcoinpir-${transactionId}.candidate`,
    candidate_unit_path: `/etc/systemd/system/.bitcoinpir-${transactionId}.candidate`,
    installation_mode: "service-stopped-two-exact-rename-replacements-with-parent-fsync",
    lock_path: "/run/lock/bitcoinpir-bhtm-caddy-admin-uds.lock",
    new_invocation_required: true,
    receipt_path: `${root}/receipts/${transactionId}.json`,
    reload_forbidden: true,
    rollback_mode: "stop-classify-exact-pair-restore-both-old-preimages-daemon-reload-start-old-generation",
    runtime_directory_creation: "systemd-first-cold-start-only",
    state_directory: `${root}/transactions/${transactionId}`,
  };
  for (const [key, expected] of Object.entries(exact)) {
    if (value[key] !== expected) fail(`transaction.${key} must equal ${expected}`);
  }
  const argv = {
    daemon_reload_argv: ["/usr/bin/systemctl", "daemon-reload"],
    start_argv: ["/usr/bin/systemctl", "start", TARGET_UNIT],
    stop_argv: ["/usr/bin/systemctl", "stop", TARGET_UNIT],
  };
  for (const [key, expected] of Object.entries(argv)) {
    if (canonicalJson(value[key]) !== canonicalJson(expected)) {
      fail(`transaction.${key} must equal ${JSON.stringify(expected)}`);
    }
  }
  const conditions = [
    "systemctl-command-error-after-stop-request-without-complete-stopped-proof",
    "systemctl-command-error-after-start-request",
    "unclassified-config-unit-digest-pair",
    "active-generation-with-unproven-admin-readback",
    "receipt-publication-or-parent-fsync-uncertain",
  ];
  if (canonicalJson(value.outcome_unknown_conditions) !== canonicalJson(conditions)) {
    fail("transaction.outcome_unknown_conditions are not the reviewed closed set");
  }
  exactKeys(value.classification, ["allowed_stopped_pairs", "unknown_pair_action"], "transaction.classification");
  const pairs = ["old/old", "candidate/old", "candidate/candidate", "old/candidate"];
  if (canonicalJson(value.classification.allowed_stopped_pairs) !== canonicalJson(pairs)) {
    fail("transaction.classification.allowed_stopped_pairs are not canonical");
  }
  if (value.classification.unknown_pair_action !== "leave-stopped-fail-closed") {
    fail("transaction.classification.unknown_pair_action must fail closed");
  }
}

function validateTrust(value) {
  const keys = [
    "acme_storage_not_migrated",
    "append_only_overlay_cannot_perform_this_hardening",
    "automatic_rollback_forbidden_after_ambiguous_start",
    "candidate_config_changes_only_admin_endpoint_bytes",
    "candidate_unit_changes_only_reviewed_admin_runtime_directives",
    "existing_site_inventory_complete",
    "no_remote_action_authorized",
    "outcome_unknown_fails_closed",
    "runtime_directory_requires_cold_start",
    "privileged_access_inventory_complete_for_boot",
    "root_and_cap_dac_override_not_isolated",
    "service_uid_inventory_complete",
  ];
  exactKeys(value, keys, "trust_acknowledgements");
  for (const key of keys) {
    if (value[key] !== true) fail(`trust_acknowledgements.${key} must equal true`);
  }
}

export function validatePlan(plan) {
  exactKeys(
    plan,
    [
      "candidate",
      "config_edit_mode",
      "deployment_profile",
      "preimage",
      "privileged_access_inventory",
      "runtime",
      "schema_version",
      "service_uid_inventory",
      "site_preservation",
      "supply_chain",
      "transaction",
      "transaction_id",
      "trust_acknowledgements",
    ],
    "hardening plan",
  );
  if (plan.schema_version !== PLAN_SCHEMA_VERSION) fail(`schema_version must equal ${PLAN_SCHEMA_VERSION}`);
  if (plan.deployment_profile !== PROFILE) fail(`deployment_profile must equal ${PROFILE}`);
  validateSlug(plan.transaction_id, "transaction_id");
  if (!CONFIG_EDIT_MODES.has(plan.config_edit_mode)) fail("config_edit_mode is not reviewed");
  validatePreimage(plan.preimage);
  validateCandidate(plan.candidate);
  if (
    plan.preimage.binary.path !== plan.candidate.binary.path ||
    plan.preimage.binary.sha256 !== plan.candidate.binary.sha256 ||
    plan.preimage.binary.size !== plan.candidate.binary.size ||
    plan.preimage.binary.mode !== plan.candidate.binary.mode
  ) {
    fail("candidate must retain the exact reviewed Caddy binary");
  }
  validateSupplyChain(plan.supply_chain, plan.preimage.binary.sha256);
  validateRuntime(plan.runtime);
  validatePrivilegedAccessInventory(plan.privileged_access_inventory);
  validateServiceUidInventory(plan.service_uid_inventory);
  validateSitePreservation(plan.site_preservation);
  validateTransaction(plan.transaction, plan.transaction_id);
  validateTrust(plan.trust_acknowledgements);
  return true;
}

export function computeApprovedPlanSha256(plan) {
  validatePlan(plan);
  return sha256(Buffer.from(canonicalJson(plan), "utf8"));
}

export function buildCandidates({ configPreimageBytes, plan, unitPreimageBytes }) {
  validatePlan(plan);
  const configPreimage = Buffer.from(configPreimageBytes);
  const unitPreimage = Buffer.from(unitPreimageBytes);
  for (const [bytes, pin, label] of [
    [configPreimage, plan.preimage.config, "Caddyfile preimage"],
    [unitPreimage, plan.preimage.unit, "unit preimage"],
  ]) {
    if (sha256(bytes) !== pin.sha256 || String(bytes.length) !== pin.size) {
      fail(`${label} bytes do not match the exact plan pin`);
    }
  }
  const config = buildHardenedCaddyfile(configPreimage, plan.config_edit_mode);
  const unit = buildHardenedUnit(unitPreimage, plan.preimage.binary.path);
  for (const [bytes, pin, label] of [
    [config, plan.candidate.config, "candidate Caddyfile"],
    [unit, plan.candidate.unit, "candidate unit"],
  ]) {
    if (sha256(bytes) !== pin.sha256 || String(bytes.length) !== pin.size) {
      fail(`${label} bytes do not match the exact plan pin`);
    }
  }
  return { config, unit };
}

export function canonicalizeAdaptedCaddyJson(
  adaptedJsonBytes,
  label = "candidate adapted JSON",
) {
  const buffer = Buffer.from(adaptedJsonBytes);
  if (buffer.length < 1 || buffer.length > MAX_TEXT_BYTES) {
    fail(`${label} size is outside [1, ${MAX_TEXT_BYTES}]`);
  }
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
  } catch {
    fail(`${label} must be valid UTF-8`);
  }
  const adapted = parseStrictJson(text, label);
  validateAdaptedCaddyPrivacy(adapted);
  return Buffer.from(canonicalJson(adapted), "utf8");
}

function canonicalizePreimageAdaptedCaddyJson(
  adaptedJsonBytes,
  label = "preimage adapted JSON",
) {
  const buffer = Buffer.from(adaptedJsonBytes);
  if (buffer.length < 1 || buffer.length > MAX_TEXT_BYTES) {
    fail(`${label} size is outside [1, ${MAX_TEXT_BYTES}]`);
  }
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
  } catch {
    fail(`${label} must be valid UTF-8`);
  }
  const adapted = parseStrictJson(text, label);
  if (adapted.admin === undefined) {
    validateAdaptedCaddyPrivacyPolicy(adapted);
  } else {
    validateAdaptedCaddyPrivacy(adapted, "127.0.0.1:2019");
  }
  return Buffer.from(canonicalJson(adapted), "utf8");
}

export function validatePreimageAdaptedJson({ adaptedJsonBytes, plan }) {
  validatePlan(plan);
  const canonical = canonicalizePreimageAdaptedCaddyJson(adaptedJsonBytes);
  if (String(canonical.length) !== plan.preimage.adapted_json_size) {
    fail("preimage canonical adapted JSON does not match the approved size");
  }
  if (sha256(canonical) !== plan.preimage.adapted_json_sha256) {
    fail("preimage canonical adapted JSON does not match the approved SHA-256");
  }
  return canonical;
}

export function validateCandidateAdaptedJson({ adaptedJsonBytes, plan }) {
  validatePlan(plan);
  const canonical = canonicalizeAdaptedCaddyJson(adaptedJsonBytes);
  if (String(canonical.length) !== plan.candidate.adapted_json_size) {
    fail("candidate canonical adapted JSON does not match the approved size");
  }
  if (sha256(canonical) !== plan.candidate.adapted_json_sha256) {
    fail("candidate canonical adapted JSON does not match the approved SHA-256");
  }
  return canonical;
}

function exactContentSnapshot(snapshot, pin, label) {
  validateSnapshot(snapshot, label, { modes: [pin.mode], path: pin.path });
  for (const key of ["gid", "mode", "path", "sha256", "size", "uid"]) {
    if (snapshot[key] !== pin[key]) fail(`${label}.${key} drifted from the approved candidate`);
  }
}

function validateTcpProbes(value, label) {
  if (!Array.isArray(value) || value.length !== 2) fail(`${label} must contain IPv4 and IPv6 port 2019 probes`);
  const expected = ["127.0.0.1:2019", "[::1]:2019"];
  for (const [index, probe] of value.entries()) {
    exactKeys(probe, ["endpoint", "result"], `${label}[${index}]`);
    if (probe.endpoint !== expected[index] || probe.result !== "connection-refused") {
      fail(`${label}[${index}] must prove ${expected[index]} connection-refused`);
    }
  }
}

export function validateCommittedReceipt({ approvedPlanSha256, plan, receipt, trustedReceiptSha256 }) {
  validatePlan(plan);
  validateHex64(approvedPlanSha256, "approved plan SHA-256");
  if (computeApprovedPlanSha256(plan) !== approvedPlanSha256) {
    fail("plan does not match the externally approved SHA-256");
  }
  validateHex64(trustedReceiptSha256, "trusted receipt SHA-256");
  const computedReceipt = sha256(Buffer.from(canonicalJson(receipt), "utf8"));
  if (computedReceipt !== trustedReceiptSha256) fail("receipt does not match its trusted SHA-256");
  exactKeys(
    receipt,
    [
      "activation",
      "admin",
      "approved_plan_sha256",
      "before",
      "collector",
      "deployment_profile",
      "durability",
      "host",
      "installed",
      "outcome",
      "privileged_access_inventory",
      "recovery_classification",
      "rollback",
      "runtime",
      "schema_version",
      "site_health",
      "stopped",
      "transaction_id",
    ],
    "hardening receipt",
  );
  if (receipt.schema_version !== RECEIPT_SCHEMA_VERSION) fail(`receipt schema_version must equal ${RECEIPT_SCHEMA_VERSION}`);
  if (receipt.collector !== COLLECTOR || receipt.deployment_profile !== PROFILE) {
    fail("receipt collector/profile is not reviewed");
  }
  if (receipt.approved_plan_sha256 !== approvedPlanSha256 || receipt.transaction_id !== plan.transaction_id) {
    fail("receipt does not bind the approved plan transaction");
  }
  if (receipt.outcome !== "committed") fail("only an exact committed hardening receipt is authoritative");
  if (canonicalJson(receipt.privileged_access_inventory) !== canonicalJson(plan.privileged_access_inventory)) {
    fail("receipt privileged access inventory drifted from the approved boot evidence");
  }
  if (canonicalJson(receipt.runtime) !== canonicalJson(plan.runtime)) {
    fail("receipt.runtime drifted from the exact Node/gate/probe/setpriv pins");
  }
  exactKeys(receipt.host, ["boot_id", "hostname"], "receipt.host");
  if (typeof receipt.host.hostname !== "string" || receipt.host.hostname.length < 1 || receipt.host.hostname.length > 255) {
    fail("receipt.host.hostname is invalid");
  }
  if (typeof receipt.host.boot_id !== "string" || !BOOT_UUID.test(receipt.host.boot_id)) {
    fail("receipt.host.boot_id must be a lowercase UUID");
  }
  if (receipt.host.boot_id !== plan.privileged_access_inventory.boot_id) {
    fail("receipt host boot_id does not match the approved privileged access inventory boot");
  }
  exactKeys(receipt.before, ["binary", "config", "unit", "unit_generation"], "receipt.before");
  for (const key of ["binary", "config", "unit"]) {
    if (canonicalJson(receipt.before[key]) !== canonicalJson(plan.preimage[key])) {
      fail(`receipt.before.${key} drifted from the approved preimage`);
    }
  }
  if (canonicalJson(receipt.before.unit_generation) !== canonicalJson(plan.preimage.unit_generation)) {
    fail("receipt.before.unit_generation drifted from the approved preimage generation");
  }
  exactKeys(
    receipt.stopped,
    ["admin_socket_absent", "tcp_admin", "unit_generation", "unit_job_absent"],
    "receipt.stopped",
  );
  if (receipt.stopped.admin_socket_absent !== true || receipt.stopped.unit_job_absent !== true) {
    fail("stopped evidence must show no admin socket or pending systemd job");
  }
  validateTcpProbes(receipt.stopped.tcp_admin, "receipt.stopped.tcp_admin");
  validateUnitGeneration(receipt.stopped.unit_generation, "receipt.stopped.unit_generation", { active: false });
  exactKeys(receipt.installed, ["binary", "config", "unit"], "receipt.installed");
  for (const key of ["binary", "config", "unit"]) {
    exactContentSnapshot(receipt.installed[key], plan.candidate[key], `receipt.installed.${key}`);
  }
  exactKeys(
    receipt.activation,
    [
      "dropin_paths",
      "binary_version",
      "effective_environment_names",
      "fragment_path",
      "need_daemon_reload",
      "properties",
      "unit_generation",
    ],
    "receipt.activation",
  );
  validateUnitGeneration(receipt.activation.unit_generation, "receipt.activation.unit_generation", { active: true });
  if (receipt.activation.binary_version !== plan.supply_chain.caddy.version) {
    fail("activation Caddy version does not match the approved production version");
  }
  if (
    receipt.activation.unit_generation.invocation_id === plan.preimage.unit_generation.invocation_id ||
    receipt.activation.unit_generation.active_enter_timestamp_monotonic ===
      plan.preimage.unit_generation.active_enter_timestamp_monotonic
  ) {
    fail("cold activation must have a new InvocationID and active-enter timestamp");
  }
  if (receipt.activation.fragment_path !== TARGET_FRAGMENT || receipt.activation.need_daemon_reload !== "no") {
    fail("activation must bind the exact fragment with NeedDaemonReload=no");
  }
  if (!Array.isArray(receipt.activation.dropin_paths) || receipt.activation.dropin_paths.length !== 0) {
    fail("activation must have no unit drop-ins");
  }
  if (
    !Array.isArray(receipt.activation.effective_environment_names) ||
    receipt.activation.effective_environment_names.length > 512 ||
    receipt.activation.effective_environment_names.includes("CADDY_ADMIN") ||
    receipt.activation.effective_environment_names.some(
      (name, index, names) =>
        typeof name !== "string" ||
        !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name) ||
        (index > 0 && names[index - 1] >= name),
    )
  ) {
    fail("activation effective environment names must be canonical, sorted and exclude CADDY_ADMIN");
  }
  exactKeys(
    receipt.activation.properties,
    [
      "Group",
      "LimitCORE",
      "MemorySwapMax",
      "RuntimeDirectory",
      "RuntimeDirectoryMode",
      "RuntimeDirectoryPreserve",
      "StandardError",
      "StandardOutput",
      "UMask",
      "UnsetEnvironment",
      "User",
    ],
    "receipt.activation.properties",
  );
  const properties = {
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
  if (canonicalJson(receipt.activation.properties) !== canonicalJson(properties)) {
    fail("activation systemd properties do not match the hardened unit");
  }
  exactKeys(receipt.admin, ["denied_service_uids", "root_readback", "runtime_directory", "socket", "tcp_admin"], "receipt.admin");
  exactKeys(receipt.admin.runtime_directory, ["gid", "mode", "path", "type", "uid"], "receipt.admin.runtime_directory");
  if (canonicalJson(receipt.admin.runtime_directory) !== canonicalJson({ gid: 0, mode: "0700", path: ADMIN_DIRECTORY, type: "directory", uid: 0 })) {
    fail("admin runtime directory must be exact root:root 0700");
  }
  exactKeys(receipt.admin.socket, ["gid", "mode", "path", "type", "uid"], "receipt.admin.socket");
  if (canonicalJson(receipt.admin.socket) !== canonicalJson({ gid: 0, mode: "0200", path: ADMIN_SOCKET, type: "socket", uid: 0 })) {
    fail("admin socket must be exact root:root 0200");
  }
  exactKeys(receipt.admin.root_readback, ["body_sha256", "cap_eff", "gid", "groups", "listen", "path", "status", "transport", "uid"], "receipt.admin.root_readback");
  validateHex64(receipt.admin.root_readback.body_sha256, "receipt.admin.root_readback.body_sha256");
  if (receipt.admin.root_readback.body_sha256 !== plan.candidate.adapted_json_sha256) {
    fail("root readback canonical body SHA-256 does not match the approved adapted JSON");
  }
  if (canonicalJson({ ...receipt.admin.root_readback, body_sha256: "x" }) !== canonicalJson({ body_sha256: "x", cap_eff: "0000000000000000", gid: 0, groups: [0], listen: ADMIN_LISTEN, path: "/config/", status: 200, transport: "unix", uid: 0 })) {
    fail("root readback must succeed over the exact Unix admin endpoint");
  }
  validateTcpProbes(receipt.admin.tcp_admin, "receipt.admin.tcp_admin");
  if (!Array.isArray(receipt.admin.denied_service_uids) || receipt.admin.denied_service_uids.length !== plan.service_uid_inventory.length) {
    fail("admin denied_service_uids must cover the complete approved inventory");
  }
  for (const [index, denial] of receipt.admin.denied_service_uids.entries()) {
    exactKeys(denial, ["cap_eff", "error", "gid", "groups", "name", "uid"], `receipt.admin.denied_service_uids[${index}]`);
    const expected = plan.service_uid_inventory[index];
    if (
      denial.cap_eff !== "0000000000000000" ||
      denial.error !== "EACCES" ||
      denial.gid !== expected.uid ||
      canonicalJson(denial.groups) !== canonicalJson([expected.uid]) ||
      denial.name !== expected.name ||
      denial.uid !== expected.uid
    ) {
      fail(`receipt.admin.denied_service_uids[${index}] is not an exact EACCES proof`);
    }
  }
  if (!Array.isArray(receipt.site_health) || receipt.site_health.length !== plan.site_preservation.probe_ids.length) {
    fail("receipt.site_health must cover every approved existing-site probe");
  }
  for (const [index, result] of receipt.site_health.entries()) {
    exactKeys(result, ["after", "before", "id"], `receipt.site_health[${index}]`);
    if (
      result.id !== plan.site_preservation.probe_ids[index] ||
      result.before !== "passed" ||
      result.after !== "passed"
    ) {
      fail(`receipt.site_health[${index}] must pass before and after`);
    }
  }
  exactKeys(receipt.rollback, ["outcome", "performed"], "receipt.rollback");
  if (receipt.rollback.performed !== false || receipt.rollback.outcome !== "not-required") {
    fail("committed receipt must not claim rollback");
  }
  if (receipt.recovery_classification !== "candidate/candidate-new-generation") {
    fail("committed receipt has the wrong exact-pair recovery classification");
  }
  exactKeys(receipt.durability, ["parent_fsynced", "receipt_exclusive_create", "receipt_file_fsynced"], "receipt.durability");
  for (const value of Object.values(receipt.durability)) {
    if (value !== true) fail("committed receipt must be exclusively created and durably fsynced");
  }
  return true;
}

function usage() {
  return [
    "usage:",
    "  payment-v1-caddy-admin-uds-gate.mjs digest-plan PLAN",
    "  payment-v1-caddy-admin-uds-gate.mjs validate-plan PLAN CONFIG_PREIMAGE UNIT_PREIMAGE PREIMAGE_ADAPTED_JSON CANDIDATE_ADAPTED_JSON APPROVED_PLAN_SHA256",
    "  payment-v1-caddy-admin-uds-gate.mjs validate-receipt PLAN RECEIPT APPROVED_PLAN_SHA256 TRUSTED_RECEIPT_SHA256",
  ].join("\n");
}

function readJson(path, label) {
  return parseStrictJson(readFileSync(path, "utf8"), label);
}

function main(argv) {
  if (argv.length === 1 && ["--help", "-h"].includes(argv[0])) {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  if (argv[0] === "digest-plan" && argv.length === 2) {
    const plan = readJson(argv[1], "hardening plan");
    process.stdout.write(`${computeApprovedPlanSha256(plan)}\n`);
    return;
  }
  if (argv[0] === "validate-plan" && argv.length === 7) {
    const plan = readJson(argv[1], "hardening plan");
    buildCandidates({
      configPreimageBytes: readFileSync(argv[2]),
      plan,
      unitPreimageBytes: readFileSync(argv[3]),
    });
    validatePreimageAdaptedJson({ adaptedJsonBytes: readFileSync(argv[4]), plan });
    validateCandidateAdaptedJson({ adaptedJsonBytes: readFileSync(argv[5]), plan });
    validateHex64(argv[6], "externally approved plan SHA-256");
    if (computeApprovedPlanSha256(plan) !== argv[6]) {
      fail("hardening plan does not match the externally approved SHA-256");
    }
    process.stdout.write(`caddy-admin-uds-plan=PASS sha256=${argv[6]}\n`);
    return;
  }
  if (argv[0] === "validate-receipt" && argv.length === 5) {
    const plan = readJson(argv[1], "hardening plan");
    const receipt = parseCanonicalReceipt(readFileSync(argv[2]));
    validateCommittedReceipt({
      approvedPlanSha256: argv[3],
      plan,
      receipt,
      trustedReceiptSha256: argv[4],
    });
    process.stdout.write("caddy-admin-uds-receipt=PASS outcome=committed\n");
    return;
  }
  fail(usage());
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`caddy-admin-uds-gate=FAIL: ${error.message}\n`);
    process.exitCode = 1;
  }
}
