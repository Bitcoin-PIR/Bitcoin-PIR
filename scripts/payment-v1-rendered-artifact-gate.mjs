#!/usr/bin/env node

import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { isIP } from "node:net";
import {
  basename,
  dirname,
  join,
  posix,
  relative,
  resolve,
  sep,
} from "node:path";
import { pathToFileURL } from "node:url";

const PLAN_SCHEMA_VERSION = 1;
const MANIFEST_SCHEMA_VERSION = 1;
const EVIDENCE_SCHEMA_VERSION = 4;
export const RUNTIME_COLLECTOR =
  "bitcoinpir-payment-v1-linux-runtime-evidence-v4";

const MAX_JSON_BYTES = 8 * 1024 * 1024;
const MAX_TEMPLATE_BYTES = 2 * 1024 * 1024;
const MAX_PAYLOAD_BYTES = 512 * 1024 * 1024;
const MAX_BUNDLE_BYTES = 2 * 1024 * 1024 * 1024;
const MAX_TREE_ENTRIES = 4096;
const MAX_PATH_COMPONENTS = 24;
const EMPTY_SHA256 =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const SYSTEMD_HARDENING_KEYS = Object.freeze([
  "AmbientCapabilities",
  "CapabilityBoundingSet",
  "Group",
  "IPAddressAllow",
  "IPAddressDeny",
  "InaccessiblePaths",
  "LimitCORE",
  "LimitNOFILE",
  "LockPersonality",
  "MemoryMax",
  "MemorySwapMax",
  "MemoryDenyWriteExecute",
  "NoNewPrivileges",
  "PrivateDevices",
  "PrivateTmp",
  "ProtectClock",
  "ProtectControlGroups",
  "ProtectHome",
  "ProtectHostname",
  "ProtectKernelLogs",
  "ProtectKernelModules",
  "ProtectKernelTunables",
  "ProtectSystem",
  "ReadOnlyPaths",
  "ReadWritePaths",
  "RemainAfterExit",
  "Restart",
  "RestartSec",
  "RestrictAddressFamilies",
  "RestrictNamespaces",
  "RestrictRealtime",
  "RestrictSUIDSGID",
  "RuntimeDirectory",
  "RuntimeDirectoryMode",
  "StateDirectory",
  "StateDirectoryMode",
  "StandardError",
  "StandardOutput",
  "SupplementaryGroups",
  "SystemCallArchitectures",
  "TasksMax",
  "TimeoutStartSec",
  "TimeoutStopSec",
  "Type",
  "UMask",
  "User",
  "WorkingDirectory",
]);

const SYSTEMD_UNIT_KEYS = Object.freeze([
  "After",
  "Before",
  "BindsTo",
  "ConditionPathExists",
  "Description",
  "Requires",
  "Wants",
]);

const SYSTEMD_SERVICE_KEYS = Object.freeze([
  ...SYSTEMD_HARDENING_KEYS,
  "Environment",
  "ExecStart",
  "ExecStartPre",
]);

const PROFILE_CATALOG = Object.freeze({
  "directory-relay-v1": Object.freeze({
    templates: Object.freeze([
      "deploy/payment-v1/directory-relay.toml.example",
      "deploy/payment-v1/systemd/hetzner-directory-relay.service.in",
    ]),
  }),
  "integrated-existing-bhtm-caddy-v1": Object.freeze({
    // The existing root Caddy process is deliberately not represented as a
    // bundle-owned systemd unit. This profile closes and proves the HAProxy
    // half of the composite overlay. The separate integrated-Caddy overlay
    // plan binds the mutable Caddy preimage, managed block, unit, binary,
    // process generation, TLS inputs, transaction, rollback and health proof.
    templates: Object.freeze([
      "deploy/payment-v1/edge/integrated-existing-bhtm-caddy.managed.Caddyfile.in",
      "deploy/payment-v1/edge/source-fair-haproxy.cfg.in",
      "deploy/payment-v1/systemd/payment-v1-source-fair-edge.service.in",
      "scripts/payment-v1-caddy-admin-uds-gate.mjs",
      "scripts/payment-v1-caddy-admin-uds-probe.mjs",
      "scripts/payment-v1-caddy-admin-uds-transaction.mjs",
      "scripts/payment-v1-integrated-caddy-overlay-gate.mjs",
      "scripts/payment-v1-integrated-caddy-overlay-transaction.mjs",
    ]),
  }),
  "edge-hetzner-v1": Object.freeze({
    templates: Object.freeze([
      "deploy/payment-v1/edge/hetzner-public.Caddyfile.in",
      "deploy/payment-v1/edge/source-fair-haproxy.cfg.in",
      "deploy/payment-v1/systemd/payment-v1-public-edge.service.in",
      "deploy/payment-v1/systemd/payment-v1-source-fair-edge.service.in",
    ]),
  }),
  "edge-rollback-authority-v1": Object.freeze({
    templates: Object.freeze([
      "deploy/payment-v1/edge/rollback-authority.Caddyfile.in",
      "deploy/payment-v1/systemd/payment-v1-edge.service.in",
    ]),
  }),
  "issuer-lightning-signet-v1": Object.freeze({
    templates: Object.freeze([
      "deploy/payment-v1/lightning/cln-rpc-guard-tmpfiles.conf.in",
      "deploy/payment-v1/lightning/lightningd.conf.in",
      "deploy/payment-v1/lightning/verify-layout.sh.in",
      "deploy/payment-v1/systemd/hetzner-cln-rpc-guard.service.in",
      "deploy/payment-v1/systemd/hetzner-core-lightning.service.in",
      "deploy/payment-v1/systemd/hetzner-lightning-preflight.service.in",
      "deploy/payment-v1/systemd/hetzner-payment-issuer.service.in",
    ]),
  }),
  "provider-v1": Object.freeze({
    templates: Object.freeze([
      "deploy/payment-v1/systemd/hetzner-provider.service.in",
    ]),
  }),
  "provider-no-standard-cashu-v1": Object.freeze({
    templates: Object.freeze([
      "deploy/payment-v1/systemd/hetzner-provider-no-standard-cashu.service.in",
    ]),
  }),
  "provider-direct-v1": Object.freeze({
    templates: Object.freeze([
      "deploy/payment-v1/systemd/hetzner-provider-direct.service.in",
    ]),
  }),
  "rollback-authority-v1": Object.freeze({
    templates: Object.freeze([
      "deploy/payment-v1/systemd/rollback-authority.service.in",
    ]),
  }),
});

const MANAGED_FILE_PREFIXES = Object.freeze([
  "/etc/bitcoinpir/payment-v1/",
  "/opt/bitcoinpir/",
  "/usr/local/libexec/bitcoinpir/",
]);

const REQUIRED_SYSTEMD_HARDENING = Object.freeze({
  LockPersonality: ["true"],
  MemoryDenyWriteExecute: ["true"],
  NoNewPrivileges: ["true"],
  PrivateTmp: ["true"],
  ProtectControlGroups: ["true"],
  ProtectHome: ["true"],
  ProtectKernelLogs: ["true"],
  ProtectKernelModules: ["true"],
  ProtectKernelTunables: ["true"],
  ProtectSystem: ["strict"],
  RestrictNamespaces: ["true"],
  RestrictRealtime: ["true"],
  RestrictSUIDSGID: ["true"],
  SystemCallArchitectures: ["native"],
});

export const RUNTIME_SYSTEMCTL_SHOW_PROPERTIES = Object.freeze([
  "ActiveEnterTimestampMonotonic",
  "ActiveState",
  "AmbientCapabilities",
  "BindPaths",
  "BindReadOnlyPaths",
  "CapabilityBoundingSet",
  "ConditionResult",
  "ControlGroup",
  "DropInPaths",
  "Environment",
  "EnvironmentFiles",
  "ExecCondition",
  "ExecMainCode",
  "ExecMainStatus",
  "ExecStart",
  "ExecStartPost",
  "ExecStartPre",
  "FragmentPath",
  "Group",
  "IPAddressAllow",
  "IPAddressDeny",
  "InaccessiblePaths",
  "InvocationID",
  "LimitCORE",
  "LimitCORESoft",
  "LimitNOFILE",
  "LimitNOFILESoft",
  "LoadCredential",
  "LoadState",
  "LockPersonality",
  "MainPID",
  "MemoryDenyWriteExecute",
  "MemoryMax",
  "MemorySwapCurrent",
  "MemorySwapMax",
  "NoNewPrivileges",
  "PrivateDevices",
  "PrivateTmp",
  "ProtectClock",
  "ProtectControlGroups",
  "ProtectHome",
  "ProtectHostname",
  "ProtectKernelLogs",
  "ProtectKernelModules",
  "ProtectKernelTunables",
  "ProtectSystem",
  "ReadOnlyPaths",
  "ReadWritePaths",
  "RemainAfterExit",
  "Restart",
  "RestrictAddressFamilies",
  "RestrictNamespaces",
  "RestrictRealtime",
  "RestrictSUIDSGID",
  "Result",
  "RootDirectory",
  "RootImage",
  "SetCredential",
  "StandardError",
  "StandardOutput",
  "SubState",
  "SupplementaryGroups",
  "SystemCallArchitectures",
  "TasksMax",
  "Type",
  "UMask",
  "User",
  "WorkingDirectory",
]);

// Conditions is an `a(sbbsi)` D-Bus property. systemctl 255 renders it as
// `[unprintable]`, so the root collector must read it through busctl's strict
// JSON mode instead of pretending it is one of the scalar show properties.
export const RUNTIME_BUSCTL_UNIT_PROPERTIES = Object.freeze(["Conditions"]);

const TEMPLATE_CATALOG = Object.freeze({
  "deploy/payment-v1/edge/integrated-existing-bhtm-caddy.managed.Caddyfile.in": {
    artifactClass: "config",
    targetPath:
      "/etc/bitcoinpir/payment-v1/integrated-existing-bhtm-caddy/managed.Caddyfile",
    modes: ["0444"],
    rootOwned: true,
  },
  "scripts/payment-v1-integrated-caddy-overlay-gate.mjs": {
    artifactClass: "executable-config",
    targetPath:
      "/usr/local/libexec/bitcoinpir/payment-v1-integrated-caddy-overlay-gate.mjs",
    modes: ["0555"],
    rootOwned: true,
  },
  "scripts/payment-v1-caddy-admin-uds-gate.mjs": {
    artifactClass: "executable-config",
    targetPath:
      "/usr/local/libexec/bitcoinpir/payment-v1-caddy-admin-uds-gate.mjs",
    modes: ["0555"],
    rootOwned: true,
  },
  "scripts/payment-v1-caddy-admin-uds-probe.mjs": {
    artifactClass: "executable-config",
    targetPath:
      "/usr/local/libexec/bitcoinpir/payment-v1-caddy-admin-uds-probe.mjs",
    modes: ["0555"],
    rootOwned: true,
  },
  "scripts/payment-v1-caddy-admin-uds-transaction.mjs": {
    artifactClass: "executable-config",
    targetPath:
      "/usr/local/libexec/bitcoinpir/payment-v1-caddy-admin-uds-transaction.mjs",
    modes: ["0555"],
    rootOwned: true,
  },
  "scripts/payment-v1-integrated-caddy-overlay-transaction.mjs": {
    artifactClass: "executable-config",
    targetPath:
      "/usr/local/libexec/bitcoinpir/payment-v1-integrated-caddy-overlay-transaction.mjs",
    modes: ["0555"],
    rootOwned: true,
  },
  "deploy/payment-v1/systemd/hetzner-core-lightning.service.in": {
    artifactClass: "systemd-unit",
    targetPath: "/etc/systemd/system/bitcoinpir-core-lightning.service",
    modes: ["0644"],
    rootOwned: true,
  },
  "deploy/payment-v1/systemd/hetzner-cln-rpc-guard.service.in": {
    artifactClass: "systemd-unit",
    targetPath: "/etc/systemd/system/bitcoinpir-cln-rpc-guard.service",
    modes: ["0644"],
    rootOwned: true,
  },
  "deploy/payment-v1/systemd/hetzner-lightning-preflight.service.in": {
    artifactClass: "systemd-unit",
    targetPath: "/etc/systemd/system/bitcoinpir-lightning-preflight.service",
    modes: ["0644"],
    rootOwned: true,
  },
  "deploy/payment-v1/systemd/hetzner-payment-issuer.service.in": {
    artifactClass: "systemd-unit",
    targetPath: "/etc/systemd/system/bitcoinpir-payment-issuer.service",
    modes: ["0644"],
    rootOwned: true,
  },
  "deploy/payment-v1/systemd/hetzner-provider.service.in": {
    artifactClass: "systemd-unit",
    targetPath: "/etc/systemd/system/bitcoinpir-provider.service",
    modes: ["0644"],
    rootOwned: true,
  },
  "deploy/payment-v1/systemd/hetzner-provider-no-standard-cashu.service.in": {
    artifactClass: "systemd-unit",
    targetPath: "/etc/systemd/system/bitcoinpir-provider-no-standard-cashu.service",
    modes: ["0644"],
    rootOwned: true,
  },
  "deploy/payment-v1/systemd/hetzner-provider-direct.service.in": {
    artifactClass: "systemd-unit",
    targetPath: "/etc/systemd/system/bitcoinpir-provider-direct.service",
    modes: ["0644"],
    rootOwned: true,
  },
  "deploy/payment-v1/systemd/payment-v1-edge.service.in": {
    artifactClass: "systemd-unit",
    targetPath: "/etc/systemd/system/bitcoinpir-payment-v1-edge.service",
    modes: ["0644"],
    rootOwned: true,
  },
  "deploy/payment-v1/systemd/payment-v1-public-edge.service.in": {
    artifactClass: "systemd-unit",
    targetPath: "/etc/systemd/system/bitcoinpir-payment-v1-public-edge.service",
    modes: ["0644"],
    rootOwned: true,
  },
  "deploy/payment-v1/systemd/payment-v1-source-fair-edge.service.in": {
    artifactClass: "systemd-unit",
    targetPath: "/etc/systemd/system/bitcoinpir-payment-v1-source-fair-edge.service",
    modes: ["0644"],
    rootOwned: true,
  },
  "deploy/payment-v1/systemd/rollback-authority.service.in": {
    artifactClass: "systemd-unit",
    targetPath: "/etc/systemd/system/bitcoinpir-rollback-authority.service",
    modes: ["0644"],
    rootOwned: true,
  },
  "deploy/payment-v1/systemd/hetzner-directory-relay.service.in": {
    artifactClass: "systemd-unit",
    targetPath: "/etc/systemd/system/bitcoinpir-directory-relay.service",
    modes: ["0644"],
    rootOwned: true,
  },
  "deploy/payment-v1/edge/hetzner-public.Caddyfile.in": {
    artifactClass: "config",
    targetPath: "/etc/bitcoinpir/payment-v1/edge/hetzner-public.Caddyfile",
    modes: ["0400", "0440", "0600", "0640"],
    rootOwned: false,
  },
  "deploy/payment-v1/edge/rollback-authority.Caddyfile.in": {
    artifactClass: "config",
    targetPath: "/etc/bitcoinpir/payment-v1/edge/rollback-authority.Caddyfile",
    modes: ["0400", "0440", "0600", "0640"],
    rootOwned: false,
  },
  "deploy/payment-v1/edge/source-fair-haproxy.cfg.in": {
    artifactClass: "config",
    targetPath: "/etc/bitcoinpir/payment-v1/source-fair-edge/haproxy.cfg",
    modes: ["0400", "0440", "0600", "0640"],
    rootOwned: false,
  },
  "deploy/payment-v1/lightning/lightningd.conf.in": {
    artifactClass: "config",
    targetPath: "/etc/bitcoinpir/payment-v1/lightning/lightningd.conf",
    modes: ["0400", "0440", "0600", "0640"],
    rootOwned: false,
  },
  "deploy/payment-v1/lightning/verify-layout.sh.in": {
    artifactClass: "executable-config",
    targetPath: "/usr/local/libexec/bitcoinpir/verify-lightning-layout",
    modes: ["0755"],
    rootOwned: true,
  },
  "deploy/payment-v1/lightning/issuer-cln.args.in": {
    artifactClass: "argument-fragment",
    targetPath: "/etc/bitcoinpir/payment-v1/issuer/issuer-cln.args",
    modes: ["0400", "0440", "0600", "0640"],
    rootOwned: false,
  },
  "deploy/payment-v1/lightning/cln-rpc-guard-tmpfiles.conf.in": {
    artifactClass: "config",
    targetPath: "/etc/tmpfiles.d/bitcoinpir-cln-rpc-guard.conf",
    modes: ["0644"],
    rootOwned: true,
  },
  "deploy/payment-v1/directory-relay.toml.example": {
    artifactClass: "config",
    targetPath: "/etc/bitcoinpir/payment-v1/directory-relay/config.toml",
    modes: ["0400"],
    rootOwned: false,
  },
});

const HEX64_PLACEHOLDERS = new Set([
  "AUTHORITY_PUBKEY_HEX",
  "BITCOIN_CORE_BUNDLE_SHA256",
  "BPIR_ADMIN_SHA256",
  "CADDY_SHA256",
  "CASHU_MINT_ID_HEX",
  "CLN_BUNDLE_SHA256",
  "CLN_RPC_GUARD_SHA256",
  "DIRECTORY_PUBLISHER_PUBKEY_HEX",
  "HAPROXY_SHA256",
  "OVERLAY_EXCHANGE_SHA256",
  "HETZNER_OPERATOR_PUBKEY_HEX",
  "HETZNER_POLICY_PUBKEY_HEX",
  "HETZNER_PROVIDER_ID_HEX",
  "ISSUER_SETTLEMENT_PUBKEY_HEX",
  "PAYMENT_ISSUER_SHA256",
  "ROLLBACK_AUTHORITY_SHA256",
  "UNIFIED_SERVER_SHA256",
]);

const DNS_HOST_PLACEHOLDERS = new Set([
  "DIRECTORY_PUBLISHER_HTTPS_HOST",
  "DIRECTORY_RELAY_WSS_HOST",
  "PAYMENT_ISSUER_HTTPS_HOST",
  "PROVIDER_WSS_HOST",
  "ROLLBACK_AUTHORITY_HTTPS_HOST",
]);

const IP_ADDRESS_PLACEHOLDERS = new Set([
  "DIRECTORY_PUBLISHER_CLIENT_IP",
  "DIRECTORY_PUBLISHER_PRIVATE_BIND",
  "PUBLIC_HTTPS_BIND",
  "ROLLBACK_AUTHORITY_CLIENT_IP",
  "ROLLBACK_AUTHORITY_PRIVATE_BIND",
]);

const UID_GID_PLACEHOLDERS = new Set([
  "ISSUER_GID",
  "ISSUER_UID",
  "LIGHTNING_GID",
  "LIGHTNING_UID",
  "CLN_GUARD_UID",
  "PREFLIGHT_GID",
  "PREFLIGHT_UID",
]);

const POSITIVE_SERVICE_VALUE_PLACEHOLDERS = new Set([
  "CASHU_MAX_UNSETTLED_NOTES",
  "CASHU_MAX_UNSETTLED_VALUE",
  "SHARED_MINIMUM_AUTHORIZATION_EPOCH",
]);

const ALL_PLACEHOLDER_NAMES = new Set([
  ...HEX64_PLACEHOLDERS,
  ...DNS_HOST_PLACEHOLDERS,
  ...IP_ADDRESS_PLACEHOLDERS,
  ...UID_GID_PLACEHOLDERS,
  ...POSITIVE_SERVICE_VALUE_PLACEHOLDERS,
  "BITCOIND_SYSTEMD_UNIT",
  "BITCOINPIR_WEB_ORIGIN",
  "BITCOIN_RPC_PORT",
  "CLN_GUARD_MAX_INVOICE_BURST",
  "CLN_GUARD_MAX_INVOICE_MSAT",
  "CLN_GUARD_MAX_INVOICES_PER_MINUTE",
  "CLN_GUARD_MAX_INVOICES_PER_RUNTIME",
  "CLN_P2P_ANNOUNCE_ADDR",
  "CLN_P2P_BIND_ADDR",
  "HETZNER_PROVIDER_SERVER_ID",
  "LIGHTNING_NETWORK",
]);

function fail(message) {
  throw new Error(message);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function asciiCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === null || Object.getPrototypeOf(value) === Object.prototype)
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
    fail(
      `${label} keys must equal ${JSON.stringify(wanted)}, got ${JSON.stringify(actual)}`,
    );
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
      if (!escaped && character === "\\") {
        escaped = true;
      } else {
        escaped = false;
      }
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

export function computeApprovedPlanSha256(plan) {
  return sha256(Buffer.from(canonicalJson(plan)));
}

function requireApprovedPlan(plan, approvedPlanSha256) {
  validateSha256(approvedPlanSha256, "externally approved plan SHA-256");
  const computed = computeApprovedPlanSha256(plan);
  if (computed !== approvedPlanSha256) {
    fail("render plan does not match the externally approved plan SHA-256");
  }
  return computed;
}

function readStrictJsonFile(path, label) {
  const bytes = readRegularSingleLinkFile(path, label);
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail(`${label} is not valid UTF-8`);
  }
  return parseStrictJson(text, label);
}

function readRegularSingleLinkFile(path, label, maxBytes = MAX_JSON_BYTES) {
  let stat;
  try {
    stat = lstatSync(path);
  } catch {
    fail(`${label} is missing: ${path}`);
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    fail(`${label} must be a regular non-symlink file: ${path}`);
  }
  if (stat.nlink !== 1) fail(`${label} must have exactly one hard link: ${path}`);
  if (!Number.isSafeInteger(stat.size) || stat.size < 0 || stat.size > maxBytes) {
    fail(`${label} exceeds the ${maxBytes}-byte size limit: ${path}`);
  }
  return readFileSync(path);
}

function requireCanonicalRoot(path, label) {
  const absolute = resolve(path);
  let stat;
  try {
    stat = lstatSync(absolute);
  } catch {
    fail(`${label} does not exist: ${absolute}`);
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    fail(`${label} must be a real directory: ${absolute}`);
  }
  // macOS intentionally exposes /var as an alias of /private/var. Canonicalize
  // already-existing ancestors here, then require every selected descendant
  // to resolve byte-for-byte below this real root in resolveUnder(). The root
  // itself is still rejected when its final component is a symlink.
  return realpathSync(absolute);
}

function safeRelativePath(value, label) {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 512 ||
    value.startsWith("/") ||
    value.includes("\\") ||
    !/^[A-Za-z0-9._/-]+$/u.test(value)
  ) {
    fail(`${label} must be a bounded portable relative path`);
  }
  if (/INVALID(?:_|-)REPLACE/u.test(value)) {
    fail(`${label} retains an invalid replacement marker`);
  }
  const components = value.split("/");
  if (components.some((component) => component === "" || component === "." || component === "..")) {
    fail(`${label} contains an empty, dot, or parent component`);
  }
  if (components.length > MAX_PATH_COMPONENTS) {
    fail(`${label} exceeds the ${MAX_PATH_COMPONENTS}-component depth limit`);
  }
  if (posix.normalize(value) !== value) fail(`${label} is not canonical`);
  return value;
}

function safeTargetPath(value, label) {
  if (
    typeof value !== "string" ||
    value.length < 2 ||
    value.length > 512 ||
    !value.startsWith("/") ||
    value.endsWith("/") ||
    value.includes("\\") ||
    !/^\/[A-Za-z0-9._/-]+$/u.test(value)
  ) {
    fail(`${label} must be a canonical absolute ASCII target path`);
  }
  if (value.split("/").some((component, index) => index > 0 && ["", ".", ".."].includes(component))) {
    fail(`${label} contains an empty, dot, or parent component`);
  }
  if (value.split("/").length - 1 > MAX_PATH_COMPONENTS) {
    fail(`${label} exceeds the ${MAX_PATH_COMPONENTS}-component depth limit`);
  }
  if (posix.normalize(value) !== value) fail(`${label} is not canonical`);
  return value;
}

function resolveUnder(root, relativePath, label) {
  const path = join(root, ...relativePath.split("/"));
  const rel = relative(root, path);
  if (rel === "" || rel === ".." || rel.startsWith(`..${sep}`) || resolve(path) !== path) {
    fail(`${label} escapes its root`);
  }
  let real;
  try {
    real = realpathSync(path);
  } catch {
    fail(`${label} is missing: ${relativePath}`);
  }
  if (real !== path) fail(`${label} resolves through a symlink: ${relativePath}`);
  return path;
}

function validateSha256(value, label) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) {
    fail(`${label} must be a lowercase SHA-256 hex digest`);
  }
  if (/^0{64}$/u.test(value)) fail(`${label} must not be all zero`);
  return value;
}

function validateMode(value, allowed, label) {
  if (typeof value !== "string" || !/^[0-7]{4}$/u.test(value) || !allowed.includes(value)) {
    fail(`${label} mode must be one of ${JSON.stringify(allowed)}`);
  }
}

function validateUidGid(value, label, { allowRoot = true } = {}) {
  if (!Number.isSafeInteger(value) || value < (allowRoot ? 0 : 1) || value > 4_294_967_294) {
    fail(`${label} must be a bounded numeric uid/gid`);
  }
}

function validateSafeAscii(value, label, maxLength = 256) {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maxLength ||
    !/^[\x21-\x7e]+$/u.test(value)
  ) {
    fail(`${label} must be bounded, non-empty printable ASCII without whitespace`);
  }
  if (/["'\\$%@]/u.test(value)) {
    fail(`${label} contains a forbidden quote, backslash, dollar, percent, or at-sign`);
  }
}

function validateDnsHost(value, label) {
  validateSafeAscii(value, label, 253);
  if (value !== value.toLowerCase() || value.endsWith(".") || !value.includes(".")) {
    fail(`${label} must be a canonical lowercase DNS hostname with at least two labels`);
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
    fail(`${label} is not a canonical DNS hostname`);
  }
}

function parseUnsignedDecimal(value, label, minimum, maximum) {
  validateSafeAscii(value, label, 20);
  if (!/^(?:0|[1-9][0-9]*)$/u.test(value)) fail(`${label} must be canonical decimal`);
  const parsed = BigInt(value);
  if (parsed < minimum || parsed > maximum) {
    fail(`${label} must be in [${minimum}, ${maximum}]`);
  }
}

function parseHostPort(value, label, { announce = false } = {}) {
  validateSafeAscii(value, label, 320);
  let host;
  let portText;
  const bracketed = /^\[([^\]]+)\]:([0-9]+)$/u.exec(value);
  if (bracketed) {
    host = bracketed[1];
    portText = bracketed[2];
    if (isIP(host) !== 6) fail(`${label} has an invalid bracketed IPv6 address`);
  } else {
    const match = /^([^:]+):([0-9]+)$/u.exec(value);
    if (!match) fail(`${label} must be host:port or [IPv6]:port`);
    host = match[1];
    portText = match[2];
    if (isIP(host) === 0) validateDnsHost(host, `${label} host`);
  }
  parseUnsignedDecimal(portText, `${label} port`, 1n, 65_535n);
  if (announce && ["0.0.0.0", "127.0.0.1", "::", "::1"].includes(host)) {
    fail(`${label} must not announce an unspecified or loopback address`);
  }
}

function isPrivateNumericAddress(value) {
  if (isIP(value) === 4) {
    const [first, second] = value.split(".").map(Number);
    return (
      first === 10 ||
      (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && second === 168)
    );
  }
  if (isIP(value) === 6) {
    const canonical = value.toLowerCase();
    return canonical.startsWith("fc") || canonical.startsWith("fd");
  }
  return false;
}

function validatePlaceholderValue(name, value) {
  const label = `placeholder ${name}`;
  if (!ALL_PLACEHOLDER_NAMES.has(name)) fail(`${label} is not in the closed-world schema`);
  validateSafeAscii(value, label, 512);
  if (HEX64_PLACEHOLDERS.has(name)) {
    validateSha256(value, label);
    return;
  }
  if (DNS_HOST_PLACEHOLDERS.has(name)) {
    validateDnsHost(value, label);
    return;
  }
  if (IP_ADDRESS_PLACEHOLDERS.has(name)) {
    validateSafeAscii(value, label, 45);
    if (isIP(value) === 0 || ["0.0.0.0", "127.0.0.1", "::", "::1"].includes(value)) {
      fail(`${label} must be one concrete non-loopback numeric address`);
    }
    if (
      new Set([
        "DIRECTORY_PUBLISHER_CLIENT_IP",
        "DIRECTORY_PUBLISHER_PRIVATE_BIND",
        "ROLLBACK_AUTHORITY_CLIENT_IP",
        "ROLLBACK_AUTHORITY_PRIVATE_BIND",
      ]).has(name) &&
      !isPrivateNumericAddress(value)
    ) {
      fail(`${label} must be an RFC1918 IPv4 or ULA IPv6 private address`);
    }
    return;
  }
  if (UID_GID_PLACEHOLDERS.has(name)) {
    parseUnsignedDecimal(value, label, 1n, 4_294_967_294n);
    return;
  }
  if (POSITIVE_SERVICE_VALUE_PLACEHOLDERS.has(name)) {
    parseUnsignedDecimal(value, label, 1n, 9_223_372_036_854_775_807n);
    return;
  }
  switch (name) {
    case "BITCOIND_SYSTEMD_UNIT":
      if (!/^[A-Za-z0-9_.-]{1,128}\.service$/u.test(value)) {
        fail(`${label} must be one literal systemd .service unit name`);
      }
      return;
    case "BITCOINPIR_WEB_ORIGIN": {
      const match = /^https:\/\/([^/]+)$/u.exec(value);
      if (!match) fail(`${label} must be one canonical HTTPS origin without path or port`);
      validateDnsHost(match[1], `${label} host`);
      return;
    }
    case "BITCOIN_RPC_PORT":
      parseUnsignedDecimal(value, label, 1n, 65_535n);
      return;
    case "CLN_GUARD_MAX_INVOICE_MSAT":
      parseUnsignedDecimal(value, label, 1n, 2_100_000_000_000_000_000n);
      return;
    case "CLN_GUARD_MAX_INVOICES_PER_MINUTE":
      parseUnsignedDecimal(value, label, 1n, 600n);
      return;
    case "CLN_GUARD_MAX_INVOICE_BURST":
      parseUnsignedDecimal(value, label, 1n, 100n);
      return;
    case "CLN_GUARD_MAX_INVOICES_PER_RUNTIME":
      parseUnsignedDecimal(value, label, 1n, 100_000n);
      return;
    case "CLN_P2P_ANNOUNCE_ADDR":
      parseHostPort(value, label, { announce: true });
      return;
    case "CLN_P2P_BIND_ADDR":
      parseHostPort(value, label);
      return;
    case "HETZNER_PROVIDER_SERVER_ID":
      if (!/^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/u.test(value)) {
        fail(`${label} must be a bounded lowercase server-id slug`);
      }
      return;
    case "LIGHTNING_NETWORK":
      if (value !== "signet") fail(`${label} must equal signet for Payment V1 staging`);
      return;
    default:
      fail(`${label} has no validator`);
  }
}

function expectedPayloadClass(targetPath) {
  if (
    targetPath.startsWith("/opt/bitcoinpir/") ||
    targetPath.startsWith("/usr/local/libexec/bitcoinpir/")
  ) {
    return "binary";
  }
  const name = basename(targetPath).toLowerCase();
  // The Rust remote-rollback loader treats the TOML itself as private
  // deployment material: it must be owned by the service effective UID at
  // 0400/0600.
  // Keep that stronger contract even though the filename has a .toml suffix.
  if (name === "remote-rollback-authority.toml") return "secret";
  if (name.endsWith(".sha256")) return "hash-manifest";
  if (
    name.endsWith(".key") ||
    name.endsWith(".seed") ||
    /(?:secret|derivation|signing|custody|idempotency)/u.test(name)
  ) {
    return "secret";
  }
  if (
    name.endsWith(".bin") ||
    /(?:policy|authorization|approval|delegation|receipt|metadata)/u.test(name)
  ) {
    return "policy";
  }
  return "config";
}

function validatePrivateReadableMetadata(artifact, label) {
  const ownerPrivate = artifact.uid > 0 && artifact.gid >= 0 && artifact.mode === "0400";
  const groupPrivate = artifact.uid === 0 && artifact.gid > 0 && artifact.mode === "0440";
  const rootPrivate = artifact.uid === 0 && artifact.gid === 0 && artifact.mode === "0400";
  if (!ownerPrivate && !groupPrivate && !rootPrivate) {
    fail(
      `${label} must be 0400 for one owner or 0440 for one non-root service group`,
    );
  }
}

function validatePayloadMetadata(artifact, label) {
  const expectedClass = expectedPayloadClass(artifact.target_path);
  if (artifact.class !== expectedClass) {
    fail(`${label}.class must equal target-derived class ${expectedClass}`);
  }
  switch (artifact.class) {
    case "binary":
      if (artifact.uid !== 0 || artifact.gid !== 0 || artifact.mode !== "0555") {
        fail(`${label} binary must be immutable root:root mode 0555`);
      }
      break;
    case "hash-manifest":
      if (artifact.uid !== 0 || artifact.gid !== 0 || artifact.mode !== "0444") {
        fail(`${label} hash manifest must be immutable root:root mode 0444`);
      }
      break;
    case "secret":
    case "policy":
      validatePrivateReadableMetadata(artifact, label);
      break;
    case "config":
      if (artifact.mode === "0444" && artifact.uid === 0 && artifact.gid === 0) break;
      validatePrivateReadableMetadata(artifact, label);
      break;
    default:
      fail(`${label}.class is outside the closed payload class schema`);
  }
  if (artifact.class === "secret" && /4$/u.test(artifact.mode)) {
    fail(`${label} secret must never be world-readable`);
  }
}

function validateRenderedMetadata(artifact, catalog, label) {
  validateMode(artifact.mode, catalog.modes, label);
  if (catalog.rootOwned && (artifact.uid !== 0 || artifact.gid !== 0)) {
    fail(`${label} must be root:root at its installation target`);
  }
  if (
    !catalog.rootOwned &&
    (catalog.artifactClass === "config" || catalog.artifactClass === "argument-fragment")
  ) {
    validatePrivateReadableMetadata(artifact, label);
  }
}

function secretConsumerUnit(deploymentProfile, targetPath) {
  const mappings = {
    "directory-relay-v1": [[
      "/etc/bitcoinpir/payment-v1/directory-relay/",
      "bitcoinpir-directory-relay.service",
    ]],
    "edge-hetzner-v1": [["/etc/bitcoinpir/payment-v1/edge/", "bitcoinpir-payment-v1-public-edge.service"]],
    "edge-rollback-authority-v1": [["/etc/bitcoinpir/payment-v1/edge/", "bitcoinpir-payment-v1-edge.service"]],
    "issuer-lightning-signet-v1": [
      ["/etc/bitcoinpir/payment-v1/issuer/", "bitcoinpir-payment-issuer.service"],
      ["/etc/bitcoinpir/payment-v1/lightning/", "bitcoinpir-core-lightning.service"],
    ],
    "provider-v1": [["/etc/bitcoinpir/payment-v1/provider/", "bitcoinpir-provider.service"]],
    "provider-no-standard-cashu-v1": [[
      "/etc/bitcoinpir/payment-v1/provider-no-standard-cashu/",
      "bitcoinpir-provider-no-standard-cashu.service",
    ]],
    "provider-direct-v1": [[
      "/etc/bitcoinpir/payment-v1/provider-direct/",
      "bitcoinpir-provider-direct.service",
    ]],
    "rollback-authority-v1": [["/etc/bitcoinpir/payment-v1/rollback-authority/", "bitcoinpir-rollback-authority.service"]],
  };
  return mappings[deploymentProfile]?.find(([prefix]) => targetPath.startsWith(prefix))?.[1];
}

function privateLoaderConsumerUnit(deploymentProfile, artifact) {
  if (artifact.artifact_class === "secret") {
    return secretConsumerUnit(deploymentProfile, artifact.target_path);
  }
  if (
    deploymentProfile === "directory-relay-v1" &&
    artifact.artifact_class === "config" &&
    artifact.target_path ===
      "/etc/bitcoinpir/payment-v1/directory-relay/config.toml"
  ) {
    return secretConsumerUnit(deploymentProfile, artifact.target_path);
  }
  return undefined;
}

function validateSecretOwnerBindings(plan) {
  const identities = new Map(plan.service_identities.map((identity) => [identity.unit_name, identity]));
  const artifacts = plan.payload_artifacts ?? plan.artifacts;
  for (const artifact of artifacts) {
    if ((artifact.class ?? artifact.artifact_class) !== "secret") continue;
    const unitName = secretConsumerUnit(plan.deployment_profile, artifact.target_path);
    const identity = identities.get(unitName);
    if (!unitName || !identity) {
      fail(`secret target has no exact service identity binding: ${artifact.target_path}`);
    }
    if (artifact.uid !== identity.uid || artifact.gid !== identity.gid || artifact.mode !== "0400") {
      fail(
        `secret must be owned exclusively by ${unitName} uid=${identity.uid} gid=${identity.gid} mode 0400: ${artifact.target_path}`,
      );
    }
  }
}

function remoteRollbackPathsForProfile(profile) {
  const roots = {
    "issuer-lightning-signet-v1": "/etc/bitcoinpir/payment-v1/issuer",
    "provider-v1": "/etc/bitcoinpir/payment-v1/provider",
    "provider-no-standard-cashu-v1":
      "/etc/bitcoinpir/payment-v1/provider-no-standard-cashu",
    "provider-direct-v1": "/etc/bitcoinpir/payment-v1/provider-direct",
  };
  const root = roots[profile];
  if (!root) return null;
  return Object.freeze({
    config: `${root}/remote-rollback-authority.toml`,
    signingSeed: `${root}/remote-rollback-client-signing.seed`,
    valueRoot: `${root}/remote-rollback-value-root.key`,
  });
}

function validateRemoteRollbackPayloadMetadata(plan) {
  const paths = remoteRollbackPathsForProfile(plan.deployment_profile);
  if (!paths) return;
  const artifacts = new Map(
    plan.payload_artifacts.map((artifact) => [artifact.target_path, artifact]),
  );
  for (const [role, targetPath] of Object.entries(paths)) {
    const artifact = artifacts.get(targetPath);
    if (!artifact) {
      fail(`${plan.deployment_profile} remote rollback ${role} payload is missing`);
    }
    if (artifact.class !== "secret") {
      fail(
        `${plan.deployment_profile} remote rollback ${role} must use the owner-only secret artifact class`,
      );
    }
  }
}

function validateProviderPayloadClosure(plan) {
  const profile = plan.deployment_profile;
  if (!new Set(["provider-v1", "provider-no-standard-cashu-v1", "provider-direct-v1"]).has(profile)) {
    return;
  }
  const direct = profile === "provider-direct-v1";
  const noStandardCashu = profile !== "provider-v1";
  const root = profile === "provider-v1"
    ? "/etc/bitcoinpir/payment-v1/provider"
    : direct
      ? "/etc/bitcoinpir/payment-v1/provider-direct"
      : "/etc/bitcoinpir/payment-v1/provider-no-standard-cashu";
  if (plan.payload_artifacts.some((artifact) =>
    /(?:^|[-_.])retained(?:[-_.]|$)/u.test(basename(artifact.source_path)) ||
    /(?:^|[-_.])retained(?:[-_.]|$)/u.test(basename(artifact.target_path)))) {
    fail(`${profile} is a zero-retained closed profile and must not include retained-policy payload material`);
  }
  const remote = remoteRollbackPathsForProfile(profile);
  const expected = new Set([
    ...(!direct ? [
      `${root}/cashu-bat.key`,
      `${root}/provider-clearing-signing.key`,
      `${root}/shared-clearing-approval.bin`,
      `${root}/shared-clearing-authorization.bin`,
      `${root}/shared-redeem-idempotency.key`,
    ] : []),
    ...(!noStandardCashu ? [
      `${root}/cashu-custody-epoch-1.key`,
      `${root}/cashu-recovery-epoch-1.key`,
    ] : []),
    `${root}/databases.toml`,
    `${root}/provider-identity.cert`,
    `${root}/provider-identity.key`,
    remote.config,
    remote.signingSeed,
    remote.valueRoot,
    `${root}/service-policy.bin`,
    `${root}/unified-server.sha256`,
    `/opt/bitcoinpir/unified-server/${plan.placeholders.UNIFIED_SERVER_SHA256}/unified_server`,
  ]);
  assertSameStringSet(
    new Set(plan.payload_artifacts.map((artifact) => artifact.target_path)),
    expected,
    `${profile} payload targets`,
  );
  if (
    noStandardCashu &&
    Object.keys(plan.placeholders).some((name) => name.startsWith("CASHU_"))
  ) {
    fail(`${profile} must not declare Standard Cashu placeholders`);
  }
}

function validateDirectoryRelayConfigOwnerBinding(document) {
  if (document.deployment_profile !== "directory-relay-v1") return;
  const identities = document.service_identities ?? [];
  if (
    identities.length !== 1 ||
    identities[0].unit_name !== "bitcoinpir-directory-relay.service" ||
    identities[0].uid !== 62951 ||
    identities[0].gid !== 62952
  ) {
    fail("directory-relay-v1 must bind the reviewed relay UID 62951 and GID 62952");
  }
  const artifacts = document.rendered_artifacts ?? document.artifacts ?? [];
  const config = artifacts.find(
    (artifact) => artifact.target_path === "/etc/bitcoinpir/payment-v1/directory-relay/config.toml",
  );
  if (!config || config.uid !== 62951 || config.gid !== 62952 || config.mode !== "0400") {
    fail("directory-relay-v1 config must be relay-owned UID 62951 GID 62952 mode 0400");
  }
}

function validatePlan(plan) {
  exactKeys(
    plan,
    [
      "deployment_id",
      "deployment_profile",
      "payload_artifacts",
      "placeholders",
      "rendered_artifacts",
      "schema_version",
      "service_identities",
    ],
    "render plan",
  );
  if (plan.schema_version !== PLAN_SCHEMA_VERSION) {
    fail(`render plan schema_version must equal ${PLAN_SCHEMA_VERSION}`);
  }
  if (
    typeof plan.deployment_id !== "string" ||
    !/^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/u.test(plan.deployment_id)
  ) {
    fail("render plan deployment_id must be a bounded lowercase slug");
  }
  if (plan.deployment_id.startsWith("replace-")) {
    fail("render plan deployment_id retains the repository example marker");
  }
  if (typeof plan.deployment_profile !== "string" || !PROFILE_CATALOG[plan.deployment_profile]) {
    fail(
      `render plan deployment_profile must be one of ${JSON.stringify(Object.keys(PROFILE_CATALOG).sort(asciiCompare))}`,
    );
  }
  if (!isPlainObject(plan.placeholders)) fail("render plan placeholders must be an object");
  if (!Array.isArray(plan.rendered_artifacts) || plan.rendered_artifacts.length < 1) {
    fail("render plan rendered_artifacts must be a non-empty array");
  }
  if (!Array.isArray(plan.payload_artifacts)) {
    fail("render plan payload_artifacts must be an array");
  }
  if (!Array.isArray(plan.service_identities) || plan.service_identities.length < 1 || plan.service_identities.length > 32) {
    fail("render plan service_identities must be a bounded non-empty array");
  }
  if (plan.rendered_artifacts.length > 64 || plan.payload_artifacts.length > 1024) {
    fail("render plan contains too many artifacts");
  }

  for (const [index, identity] of plan.service_identities.entries()) {
    const label = `service_identities[${index}]`;
    exactKeys(identity, ["gid", "group_name", "uid", "unit_name", "user_name"], label);
    if (!/^bitcoinpir-[a-z0-9-]+\.service$/u.test(identity.unit_name)) {
      fail(`${label}.unit_name is not a reviewed BitcoinPIR service name`);
    }
    for (const key of ["group_name", "user_name"]) {
      if (!/^bitcoinpir-[a-z0-9-]+$/u.test(identity[key])) {
        fail(`${label}.${key} is not a reviewed BitcoinPIR NSS name`);
      }
    }
    validateUidGid(identity.uid, `${label}.uid`);
    validateUidGid(identity.gid, `${label}.gid`);
    if (identity.uid === 0 || identity.gid === 0) fail(`${label} must bind a non-root service identity`);
    if (index > 0 && asciiCompare(plan.service_identities[index - 1].unit_name, identity.unit_name) >= 0) {
      fail("render plan service_identities must be unique and bytewise sorted by unit_name");
    }
  }
  if (new Set(plan.service_identities.map((identity) => identity.uid)).size !== plan.service_identities.length) {
    fail("render plan service identities must use distinct UIDs");
  }

  const renderedSources = new Set();
  const targets = new Set();
  for (const [index, artifact] of plan.rendered_artifacts.entries()) {
    const label = `rendered_artifacts[${index}]`;
    exactKeys(
      artifact,
      ["gid", "mode", "source_path", "source_sha256", "target_path", "uid"],
      label,
    );
    const sourcePath = safeRelativePath(artifact.source_path, `${label}.source_path`);
    const catalog = TEMPLATE_CATALOG[sourcePath];
    if (!catalog) fail(`${label}.source_path is not in the reviewed template catalog`);
    if (artifact.target_path !== catalog.targetPath) {
      fail(`${label}.target_path must equal ${catalog.targetPath}`);
    }
    safeTargetPath(artifact.target_path, `${label}.target_path`);
    validateSha256(artifact.source_sha256, `${label}.source_sha256`);
    validateRenderedMetadata(artifact, catalog, label);
    validateUidGid(artifact.uid, `${label}.uid`);
    validateUidGid(artifact.gid, `${label}.gid`);
    if (renderedSources.has(sourcePath)) fail(`${label} repeats a rendered source`);
    renderedSources.add(sourcePath);
    if (targets.has(artifact.target_path)) fail(`${label} repeats an installation target`);
    targets.add(artifact.target_path);
  }

  for (const [index, artifact] of plan.payload_artifacts.entries()) {
    const label = `payload_artifacts[${index}]`;
    exactKeys(
      artifact,
      ["class", "expected_sha256", "gid", "mode", "source_path", "target_path", "uid"],
      label,
    );
    safeRelativePath(artifact.source_path, `${label}.source_path`);
    safeTargetPath(artifact.target_path, `${label}.target_path`);
    validateSha256(artifact.expected_sha256, `${label}.expected_sha256`);
    if (!["binary", "config", "policy", "secret", "hash-manifest"].includes(artifact.class)) {
      fail(`${label}.class is outside the closed payload class schema`);
    }
    const prefixes =
      artifact.class === "binary"
        ? ["/opt/bitcoinpir/", "/usr/local/libexec/bitcoinpir/"]
        : artifact.class === "policy"
          ? ["/etc/bitcoinpir/payment-v1/", "/home/pir/data/payment-v1/"]
          : ["/etc/bitcoinpir/payment-v1/"];
    if (!prefixes.some((prefix) => artifact.target_path.startsWith(prefix))) {
      fail(`${label}.target_path is outside the reviewed ${artifact.class} prefixes`);
    }
    validateUidGid(artifact.uid, `${label}.uid`);
    validateUidGid(artifact.gid, `${label}.gid`);
    validatePayloadMetadata(artifact, label);
    if (targets.has(artifact.target_path)) fail(`${label} repeats an installation target`);
    targets.add(artifact.target_path);
  }

  const expectedTemplates = PROFILE_CATALOG[plan.deployment_profile].templates;
  assertSameStringSet(renderedSources, expectedTemplates, "deployment profile templates");
  validateProviderPayloadClosure(plan);
  validateRemoteRollbackPayloadMetadata(plan);
  validateDirectoryRelayConfigOwnerBinding(plan);
  validateSecretOwnerBindings(plan);
}

function remoteRollbackConfigManagedReferences(profile, targetPath, bytes) {
  const paths = remoteRollbackPathsForProfile(profile);
  if (!paths || targetPath !== paths.config) return [];
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail(`${profile} remote rollback config is not valid UTF-8`);
  }
  if (/\r|\0/u.test(text)) {
    fail(`${profile} remote rollback config must use canonical LF text`);
  }
  for (const [key, expected] of [
    ["client_signing_seed_path", paths.signingSeed],
    ["value_root_key_path", paths.valueRoot],
  ]) {
    const exactLine = `${key} = "${expected}"`;
    const occurrences = text.split("\n").filter((line) => line.includes(key));
    if (canonicalize(occurrences) !== canonicalize([exactLine])) {
      fail(`${profile} remote rollback config must bind exact ${key}=${expected}`);
    }
  }
  return [paths.signingSeed, paths.valueRoot];
}

function extractPlaceholders(text) {
  return new Set(text.match(/@[A-Z][A-Z0-9_]{0,63}@/gu)?.map((token) => token.slice(1, -1)) ?? []);
}

function renderTemplate(text, placeholders, label) {
  let rendered = text;
  for (const name of [...extractPlaceholders(text)].sort()) {
    rendered = rendered.split(`@${name}@`).join(placeholders[name]);
  }
  if (/@[A-Z][A-Z0-9_]{0,63}@/u.test(rendered)) {
    fail(`${label} retains an unresolved @PLACEHOLDER@ token`);
  }
  if (/\bUNRESOLVED\b/u.test(rendered)) fail(`${label} retains an UNRESOLVED marker`);
  if (/\r|\0/u.test(rendered)) fail(`${label} contains a carriage return or NUL byte`);
  return rendered;
}

function managedReferencesFromCommand(command, label) {
  if (/[$%`;&|<>\n\r\0]/u.test(command)) {
    fail(`${label} contains variable expansion, a specifier, or shell metacharacter`);
  }
  if (/['"]/u.test(command)) fail(`${label} must not rely on quoting semantics`);
  const first = command.trim().split(/\s+/u)[0] ?? "";
  if (!first.startsWith("/") || /^[!+@:-]/u.test(first)) {
    fail(`${label} command must start with one literal absolute executable path`);
  }
  const references = new Set();
  for (const match of command.matchAll(/\/(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+/gu)) {
    const candidate = match[0];
    if (MANAGED_FILE_PREFIXES.some((prefix) => candidate.startsWith(prefix))) {
      safeTargetPath(candidate, `${label} managed path`);
      references.add(candidate);
    }
  }
  return references;
}

function parseSystemdUnit(text, label) {
  if (/^\s*\[Install\]\s*$/imu.test(text)) fail(`${label} contains forbidden [Install]`);
  if (/%/u.test(text)) fail(`${label} contains a forbidden systemd percent specifier`);
  if (/\$/u.test(text)) fail(`${label} contains forbidden systemd variable expansion`);
  if (!/^[\x00-\x7f]*$/u.test(text)) fail(`${label} must be stable ASCII text`);
  const logicalLines = [];
  let pending = "";
  for (const original of text.split("\n")) {
    const trimmed = original.trim();
    if (trimmed === "" || trimmed.startsWith("#") || trimmed.startsWith(";")) continue;
    const continued = original.trimEnd().endsWith("\\");
    const fragment = continued ? original.trimEnd().slice(0, -1).trim() : trimmed;
    pending = pending === "" ? fragment : `${pending} ${fragment}`;
    if (!continued) {
      logicalLines.push(pending);
      pending = "";
    }
  }
  if (pending !== "") fail(`${label} has an unterminated continuation`);

  const sections = new Map();
  let section;
  for (const line of logicalLines) {
    const sectionMatch = /^\[([A-Za-z][A-Za-z0-9]*)\]$/u.exec(line);
    if (sectionMatch) {
      section = sectionMatch[1];
      if (!["Unit", "Service"].includes(section)) fail(`${label} has forbidden [${section}]`);
      if (sections.has(section)) fail(`${label} repeats [${section}]`);
      sections.set(section, new Map());
      continue;
    }
    if (!section) fail(`${label} has a directive outside a section`);
    const match = /^([A-Za-z][A-Za-z0-9]*)=(.*)$/u.exec(line);
    if (!match) fail(`${label} has a malformed directive: ${line}`);
    const key = match[1];
    const value = match[2].trim();
    const allowedKeys = section === "Unit" ? SYSTEMD_UNIT_KEYS : SYSTEMD_SERVICE_KEYS;
    if (!allowedKeys.includes(key)) {
      fail(`${label} contains closed-world forbidden directive ${section}.${key}=`);
    }
    if (value === "" && !["AmbientCapabilities", "CapabilityBoundingSet"].includes(key)) {
      fail(`${label} contains a forbidden empty ${key}= reset`);
    }
    const values = sections.get(section).get(key) ?? [];
    if (
      values.length > 0 &&
      !(
        (section === "Unit" && key === "ConditionPathExists") ||
        (section === "Service" && key === "ExecStartPre")
      )
    ) {
      fail(`${label} repeats single-valued directive ${section}.${key}=`);
    }
    values.push(value);
    sections.get(section).set(key, values);
  }
  if (!sections.has("Unit") || !sections.has("Service")) {
    fail(`${label} must contain exactly [Unit] and [Service]`);
  }
  const service = sections.get("Service");
  const unit = sections.get("Unit");
  const execStart = service.get("ExecStart") ?? [];
  if (execStart.length !== 1) fail(`${label} must have exactly one effective ExecStart`);
  const conditions = [...unit.entries()]
    .filter(([key]) => key.startsWith("Condition"))
    .flatMap(([key, values]) => values.map((value) => `${key}=${value}`))
    .sort();
  if (conditions.length < 1) fail(`${label} must retain at least one fail-closed condition`);

  const environment = [];
  for (const directive of service.get("Environment") ?? []) {
    if (/["'\\$%]/u.test(directive)) fail(`${label} Environment= must use literal assignments`);
    for (const assignment of directive.split(/\s+/u)) {
      if (!/^[A-Za-z_][A-Za-z0-9_]*=[^\s]+$/u.test(assignment)) {
        fail(`${label} has a malformed Environment= assignment`);
      }
      environment.push(assignment);
    }
  }
  environment.sort();
  if (new Set(environment.map((value) => value.split("=", 1)[0])).size !== environment.length) {
    fail(`${label} repeats an Environment= variable`);
  }

  const hardening = Object.create(null);
  for (const key of SYSTEMD_HARDENING_KEYS) {
    const values = service.get(key);
    if (values) hardening[key] = [...values];
  }
  for (const [key, expected] of Object.entries(REQUIRED_SYSTEMD_HARDENING)) {
    if (canonicalize(hardening[key] ?? []) !== canonicalize(expected)) {
      fail(`${label} ${key} must equal ${JSON.stringify(expected)}`);
    }
  }
  for (const key of ["AmbientCapabilities", "CapabilityBoundingSet"]) {
    const values = hardening[key];
    if (!values || values.length !== 1) fail(`${label} must explicitly set ${key}`);
    if (values[0] !== "" && values[0] !== "CAP_NET_BIND_SERVICE") {
      fail(`${label} ${key} contains an unreviewed capability`);
    }
  }
  const managedReferences = new Set();
  for (const [key, commands] of [
    ["ExecStart", execStart],
    ["ExecStartPre", service.get("ExecStartPre") ?? []],
  ]) {
    for (const [index, command] of commands.entries()) {
      for (const reference of managedReferencesFromCommand(
        command,
        `${label} ${key}[${index}]`,
      )) {
        managedReferences.add(reference);
      }
    }
  }
  return {
    conditions,
    environment,
    environment_files: [],
    exec_start: [...execStart],
    exec_start_pre: [...(service.get("ExecStartPre") ?? [])],
    hardening,
    managed_references: [...managedReferences].sort(asciiCompare),
  };
}

const PROFILE_UNIT_CONDITIONS = Object.freeze({
  "directory-relay-v1": Object.freeze({
    "/etc/systemd/system/bitcoinpir-directory-relay.service": Object.freeze([
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/RELAY-ACTIVATION-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/RELAY-SELECTION-RESOLVED",
    ]),
  }),
  "integrated-existing-bhtm-caddy-v1": Object.freeze({
    "/etc/systemd/system/bitcoinpir-payment-v1-source-fair-edge.service": Object.freeze([
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/DIRECTORY-PUBLISHER-PRIVATE-INGRESS-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/EDGE-ACTIVATION-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/SOURCE-FAIR-PREFLIGHT-APPROVED",
    ]),
  }),
  "edge-hetzner-v1": Object.freeze({
    "/etc/systemd/system/bitcoinpir-payment-v1-public-edge.service": Object.freeze([
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/DIRECTORY-PUBLISHER-PRIVATE-INGRESS-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/EDGE-ACTIVATION-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/EDGE-PREFLIGHT-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/SOURCE-FAIR-PREFLIGHT-APPROVED",
    ]),
    "/etc/systemd/system/bitcoinpir-payment-v1-source-fair-edge.service": Object.freeze([
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/DIRECTORY-PUBLISHER-PRIVATE-INGRESS-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/EDGE-ACTIVATION-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/SOURCE-FAIR-PREFLIGHT-APPROVED",
    ]),
  }),
  "edge-rollback-authority-v1": Object.freeze({
    "/etc/systemd/system/bitcoinpir-payment-v1-edge.service": Object.freeze([
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/EDGE-PREFLIGHT-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/ROLLBACK-AUTHORITY-PRIVATE-INGRESS-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/ROLLBACK-EDGE-ACTIVATION-APPROVED",
    ]),
  }),
  "issuer-lightning-signet-v1": Object.freeze({
    "/etc/systemd/system/bitcoinpir-cln-rpc-guard.service": Object.freeze([
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/LIGHTNING-BACKUP-RESTORE-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/LIGHTNING-CUSTODY-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/SIGNET-ISSUER-ACTIVATION-APPROVED",
    ]),
    "/etc/systemd/system/bitcoinpir-core-lightning.service": Object.freeze([
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/LIGHTNING-BACKUP-RESTORE-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/LIGHTNING-CUSTODY-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/SIGNET-ISSUER-ACTIVATION-APPROVED",
    ]),
    "/etc/systemd/system/bitcoinpir-lightning-preflight.service": Object.freeze([
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/LIGHTNING-BACKUP-RESTORE-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/LIGHTNING-CUSTODY-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/SIGNET-ISSUER-ACTIVATION-APPROVED",
    ]),
    "/etc/systemd/system/bitcoinpir-payment-issuer.service": Object.freeze([
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/LIGHTNING-BACKUP-RESTORE-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/LIGHTNING-CUSTODY-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/SIGNET-ISSUER-ACTIVATION-APPROVED",
    ]),
  }),
  "provider-v1": Object.freeze({
    "/etc/systemd/system/bitcoinpir-provider.service": Object.freeze([
      "ConditionPathExists=!/etc/bitcoinpir/payment-v1/PROVIDER-DIRECT-ACTIVATION-APPROVED",
      "ConditionPathExists=!/etc/bitcoinpir/payment-v1/PROVIDER-NO-STANDARD-CASHU-ACTIVATION-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/PROVIDER-ACTIVATION-APPROVED",
    ]),
  }),
  "provider-no-standard-cashu-v1": Object.freeze({
    "/etc/systemd/system/bitcoinpir-provider-no-standard-cashu.service": Object.freeze([
      "ConditionPathExists=!/etc/bitcoinpir/payment-v1/PROVIDER-ACTIVATION-APPROVED",
      "ConditionPathExists=!/etc/bitcoinpir/payment-v1/PROVIDER-DIRECT-ACTIVATION-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/PROVIDER-NO-STANDARD-CASHU-ACTIVATION-APPROVED",
    ]),
  }),
  "provider-direct-v1": Object.freeze({
    "/etc/systemd/system/bitcoinpir-provider-direct.service": Object.freeze([
      "ConditionPathExists=!/etc/bitcoinpir/payment-v1/PROVIDER-ACTIVATION-APPROVED",
      "ConditionPathExists=!/etc/bitcoinpir/payment-v1/PROVIDER-NO-STANDARD-CASHU-ACTIVATION-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/PROVIDER-DIRECT-ACTIVATION-APPROVED",
    ]),
  }),
  "rollback-authority-v1": Object.freeze({
    "/etc/systemd/system/bitcoinpir-rollback-authority.service": Object.freeze([
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/ROLLBACK-AUTHORITY-ACTIVATION-APPROVED",
    ]),
  }),
});

function validateProfileUnitPolicy(
  deploymentProfile,
  fragmentPath,
  conditions,
  hardening,
  execStart,
  execStartPre,
  label,
) {
  const expectedConditions = PROFILE_UNIT_CONDITIONS[deploymentProfile]?.[fragmentPath];
  if (!expectedConditions) {
    fail(`${label} has no closed profile-specific activation-condition policy`);
  }
  if (canonicalize(conditions) !== canonicalize([...expectedConditions].sort(asciiCompare))) {
    fail(`${label} must retain the exact global and profile-specific activation conditions`);
  }
  if (deploymentProfile === "directory-relay-v1") {
    if (
      canonicalize(execStart) !== canonicalize(["/usr/bin/false"]) ||
      canonicalize(execStartPre) !== canonicalize([])
    ) {
      fail(`${label} directory-relay-v1 must remain stopped-only with ExecStart=/usr/bin/false`);
    }
    for (const [key, expected] of [
      ["LimitCORE", "0"],
      ["LimitNOFILE", "4096"],
      ["MemoryMax", "536870912"],
      ["MemorySwapMax", "0"],
      ["TasksMax", "128"],
      ["StandardError", "null"],
      ["StandardOutput", "null"],
      ["ProtectClock", "true"],
      ["ProtectHostname", "true"],
      ["Restart", "no"],
    ]) {
      if (canonicalize(hardening[key] ?? []) !== canonicalize([expected])) {
        fail(`${label} must keep directory-relay-v1 ${key}=${expected}`);
      }
    }
  }
  const privateRequestEdge =
    (deploymentProfile === "integrated-existing-bhtm-caddy-v1" &&
      fragmentPath === "/etc/systemd/system/bitcoinpir-payment-v1-source-fair-edge.service") ||
    (deploymentProfile === "edge-hetzner-v1" &&
      new Set([
        "/etc/systemd/system/bitcoinpir-payment-v1-public-edge.service",
        "/etc/systemd/system/bitcoinpir-payment-v1-source-fair-edge.service",
      ]).has(fragmentPath)) ||
    (deploymentProfile === "edge-rollback-authority-v1" &&
      fragmentPath === "/etc/systemd/system/bitcoinpir-payment-v1-edge.service");
  if (privateRequestEdge) {
    for (const [key, expected] of [
      ["StandardError", "null"],
      ["StandardOutput", "null"],
      ["LimitCORE", "0"],
      ["MemorySwapMax", "0"],
    ]) {
      if (canonicalize(hardening[key] ?? []) !== canonicalize([expected])) {
        fail(`${label} must keep ${key}=${expected} so request-source state cannot persist`);
      }
    }
  }
  if (
    deploymentProfile === "issuer-lightning-signet-v1" &&
    fragmentPath === "/etc/systemd/system/bitcoinpir-cln-rpc-guard.service"
  ) {
    if (canonicalize(hardening.Restart ?? []) !== canonicalize(["no"])) {
      fail(`${label} must keep the CLN guard deadman Restart=no`);
    }
    if (hardening.RestartSec !== undefined) {
      fail(`${label} must not configure RestartSec for the non-restarting CLN guard`);
    }
  }
  if (
    new Set(["provider-v1", "provider-no-standard-cashu-v1", "provider-direct-v1"]).has(deploymentProfile) &&
    new Set([
      "/etc/systemd/system/bitcoinpir-provider.service",
      "/etc/systemd/system/bitcoinpir-provider-no-standard-cashu.service",
      "/etc/systemd/system/bitcoinpir-provider-direct.service",
    ]).has(fragmentPath)
  ) {
    for (const key of ["PrivateDevices", "ProtectClock", "ProtectHostname"]) {
      if (canonicalize(hardening[key] ?? []) !== canonicalize(["true"])) {
        fail(`${label} must keep provider ${key}=true`);
      }
    }
  }
  if (
    new Set(["provider-v1", "provider-no-standard-cashu-v1", "provider-direct-v1"]).has(
      deploymentProfile,
    )
  ) {
    const command = execStart.join("\n");
    if (/--service-retained-policy(?:\s|=|$)/u.test(command)) {
      fail(
        `${label} is a zero-retained closed profile and must not configure --service-retained-policy`,
      );
    }
    if (
      /--service-(?:arc-key|free-ip-key|trust-direct-peer-ip)(?:\s|=|$)|--allow-experimental-arc(?:\s|=|$)|--require-arc(?:\s|=|$)/u.test(
        command,
      )
    ) {
      fail(`${label} must keep production ARC and Free-IP adapters unavailable`);
    }
  }
  if (deploymentProfile === "provider-no-standard-cashu-v1") {
    const command = execStart.join("\n");
    if (
      /--service-cashu-(?:recovery-key|recovery-active-epoch|custody-key|custody-active-epoch|exposure-limit)(?:\s|=|$)/u.test(
        command,
      )
    ) {
      fail(`${label} must not configure Standard Cashu custody, recovery or exposure material`);
    }
  }
  if (deploymentProfile === "provider-direct-v1") {
    const command = execStart.join("\n");
    if (
      /--service-(?:bat-key|cashu-[a-z-]+|shared-[a-z-]+)(?:\s|=|$)|--require-cashu(?:\s|=|$)|--cashu-keyset(?:\s|=|$)/u.test(
        command,
      )
    ) {
      fail(`${label} must keep BAT, Standard Cashu, shared issuer, ARC and Free-IP adapters unavailable`);
    }
  }
}

function validateRuntimeServiceIdentities(plan, runtimeUnits) {
  if (
    canonicalize(plan.service_identities.map((identity) => identity.unit_name)) !==
    canonicalize(runtimeUnits.map((unit) => unit.unit_name))
  ) {
    fail("render plan service_identities must exactly cover the rendered runtime units");
  }
  const issuerPins = {
    "bitcoinpir-cln-rpc-guard.service": ["CLN_GUARD_UID", "LIGHTNING_GID"],
    "bitcoinpir-core-lightning.service": ["LIGHTNING_UID", "LIGHTNING_GID"],
    "bitcoinpir-lightning-preflight.service": ["PREFLIGHT_UID", "PREFLIGHT_GID"],
    "bitcoinpir-payment-issuer.service": ["ISSUER_UID", "ISSUER_GID"],
  };
  for (const unit of runtimeUnits) {
    const identity = plan.service_identities.find((entry) => entry.unit_name === unit.unit_name);
    if (
      !identity ||
      canonicalize(unit.hardening.User ?? []) !== canonicalize([identity.user_name]) ||
      canonicalize(unit.hardening.Group ?? []) !== canonicalize([identity.group_name])
    ) {
      fail(`service identity does not match rendered User=/Group=: ${unit.unit_name}`);
    }
    const pins = issuerPins[unit.unit_name];
    if (plan.deployment_profile === "issuer-lightning-signet-v1" && pins) {
      if (
        identity.uid !== Number(plan.placeholders[pins[0]]) ||
        identity.gid !== Number(plan.placeholders[pins[1]])
      ) {
        fail(`issuer service identity does not match its externally approved UID/GID placeholders: ${unit.unit_name}`);
      }
    }
  }
}

function artifactBundlePath(targetPath) {
  return `files/${targetPath.slice(1)}`;
}

function hashBindingClass(artifactClass) {
  if (artifactClass === "binary") return "binary";
  if (artifactClass === "policy") return "policy";
  if (artifactClass === "secret") return "secret";
  if (artifactClass === "hash-manifest") return "hash_manifest";
  return "config";
}

const ADMIN_GATE_IMPORT_HEADER = [
  "#!/usr/bin/env node",
  "",
  'import { createHash } from "node:crypto";',
  'import { readFileSync } from "node:fs";',
  'import { pathToFileURL } from "node:url";',
  "",
  "",
].join("\n");

const ADMIN_PROBE_IMPORT_HEADER = [
  "#!/usr/bin/env node",
  "",
  'import { createHash } from "node:crypto";',
  'import { readFileSync } from "node:fs";',
  'import { request } from "node:http";',
  "",
  "const MAX_GATE_SOURCE_BYTES = 8 * 1024 * 1024;",
  "const expectedGateSha256 = process.env.BPIR_ADMIN_GATE_SHA256;",
  'if (!/^[0-9a-f]{64}$/u.test(expectedGateSha256 ?? "")) {',
  '  throw new Error("BPIR_ADMIN_GATE_SHA256 must be one lowercase SHA-256 digest");',
  "}",
  "const gateChunks = [];",
  "let gateSize = 0;",
  "for await (const chunk of process.stdin) {",
  "  gateSize += chunk.length;",
  "  if (gateSize > MAX_GATE_SOURCE_BYTES) {",
  "    throw new Error(`admin gate source exceeded ${MAX_GATE_SOURCE_BYTES} bytes`);",
  "  }",
  "  gateChunks.push(chunk);",
  "}",
  'if (gateSize === 0) throw new Error("admin gate source stdin was empty");',
  "const gateSource = Buffer.concat(gateChunks);",
  'const observedGateSha256 = createHash("sha256").update(gateSource).digest("hex");',
  "if (observedGateSha256 !== expectedGateSha256) {",
  '  throw new Error("admin gate source stdin did not match BPIR_ADMIN_GATE_SHA256");',
  "}",
  'new TextDecoder("utf-8", { fatal: true }).decode(gateSource);',
  "const {",
  "  MAX_ADAPTED_JSON_BYTES,",
  "  canonicalizeAdaptedCaddyJson,",
  "  sha256,",
  '} = await import(`data:text/javascript;base64,${gateSource.toString("base64")}`);',
  "if (",
  "  !Number.isSafeInteger(MAX_ADAPTED_JSON_BYTES) ||",
  "  MAX_ADAPTED_JSON_BYTES < 1 ||",
  '  typeof canonicalizeAdaptedCaddyJson !== "function" ||',
  '  typeof sha256 !== "function"',
  ") {",
  '  throw new Error("admin gate source did not export the exact probe interface");',
  "}",
  "",
  "",
].join("\n");

const EXACT_REVIEWED_JAVASCRIPT_SHA256 = Object.freeze({
  adminGate: "db888a58861a2401f537edce40268d45d39f2ad0b39d84a4730bda3e9f27122e",
  adminProbe: "088b8f37272ebd1ccd0c5d762ea35040481c648538640aca4542c85613a4f17c",
  adminTransaction: "c56190d9db34bc7481e554f7f81039ee67496cca5d666f141faa0bd652040ccc",
  overlayGate: "cbc060dc48c164de8ee6faebc1e05ffe7bf7ce1c94b98dad3ec12e96e424b6ab",
  overlayTransaction: "7d215529237a9b00da5fd162806f291e2802cb1813ee5c63f02a7d8862cd2dcf",
});

const OVERLAY_TRANSACTION_IMPORT_HEADER = [
  "#!/usr/bin/env node",
  "",
  'import { createHash, randomBytes } from "node:crypto";',
  'import { spawnSync } from "node:child_process";',
  "import {",
  "  closeSync,",
  "  constants,",
  "  fchmodSync,",
  "  fchownSync,",
  "  fstatSync,",
  "  fsyncSync,",
  "  lstatSync,",
  "  mkdirSync,",
  "  openSync,",
  "  readFileSync,",
  "  readdirSync,",
  "  renameSync,",
  "  rmdirSync,",
  "  unlinkSync,",
  "  writeFileSync,",
  '} from "node:fs";',
  'import tls from "node:tls";',
  'import { connect as netConnect } from "node:net";',
  'import { basename, dirname, isAbsolute, resolve } from "node:path";',
  'import { fileURLToPath, pathToFileURL } from "node:url";',
  "",
  "import {",
  "  OVERLAY_COLLECTOR,",
  "  buildOverlayCandidateFromRendered,",
  "  canonicalJson,",
  "  computeApprovedOverlayPlanSha256,",
  "  parseStrictJson,",
  "  validateOverlayPlan,",
  "  validateOverlayPreparedContext,",
  "  validateOverlayReceipt,",
  '} from "./payment-v1-integrated-caddy-overlay-gate.mjs";',
  "import {",
  "  ADMIN_DIRECTORY,",
  "  ADMIN_DIAL,",
  "  ADMIN_LISTEN,",
  "  ADMIN_SOCKET,",
  "  DAC_BOUNDARY,",
  "  canonicalJson as canonicalAdminUdsJson,",
  "  canonicalizeAdaptedCaddyJson,",
  "  computeApprovedPlanSha256 as computeApprovedAdminUdsPlanSha256,",
  "  validateCommittedReceipt as validateAdminUdsCommittedReceipt,",
  '} from "./payment-v1-caddy-admin-uds-gate.mjs";',
  "",
  "",
].join("\n");

function requireClosedJavaScriptImportHeader(text, expectedHeader, label) {
  if (!text.startsWith(expectedHeader)) {
    fail(`${label} does not have its exact reviewed import header`);
  }
}

function requireExactReviewedJavaScript(text, expectedSha256, label) {
  if (sha256(Buffer.from(text, "utf8")) !== expectedSha256) {
    fail(`${label} does not equal its exact reviewed source`);
  }
}

function normalizedOverlayTransactionSource(text, expectedHelperSha256) {
  if (!/^[0-9a-f]{64}$/u.test(expectedHelperSha256 ?? "")) {
    fail("rendered integrated-Caddy transaction executor lacks the exact plan helper digest");
  }
  let replacements = 0;
  let observedHelperSha256;
  const normalized = text.replace(
    /\/opt\/bitcoinpir\/payment-v1-rename-exchange\/([0-9a-f]{64})\/payment-v1-rename-exchange/gu,
    (_match, digest) => {
      replacements += 1;
      observedHelperSha256 = digest;
      return "/opt/bitcoinpir/payment-v1-rename-exchange/@OVERLAY_EXCHANGE_SHA256@/payment-v1-rename-exchange";
    },
  );
  if (replacements !== 1) {
    fail("rendered integrated-Caddy transaction executor does not have one exact helper substitution");
  }
  if (observedHelperSha256 !== expectedHelperSha256) {
    fail("rendered integrated-Caddy transaction executor helper digest differs from the render plan");
  }
  return normalized;
}

function configManagedReferences(sourcePath, text, plan) {
  if (sourcePath === "scripts/payment-v1-caddy-admin-uds-gate.mjs") {
    requireClosedJavaScriptImportHeader(
      text,
      ADMIN_GATE_IMPORT_HEADER,
      "rendered Caddy admin UDS gate",
    );
    requireExactReviewedJavaScript(
      text,
      EXACT_REVIEWED_JAVASCRIPT_SHA256.adminGate,
      "rendered Caddy admin UDS gate",
    );
    return [];
  }
  if (sourcePath === "scripts/payment-v1-caddy-admin-uds-probe.mjs") {
    requireClosedJavaScriptImportHeader(
      text,
      ADMIN_PROBE_IMPORT_HEADER,
      "rendered Caddy admin UDS probe",
    );
    requireExactReviewedJavaScript(
      text,
      EXACT_REVIEWED_JAVASCRIPT_SHA256.adminProbe,
      "rendered Caddy admin UDS probe",
    );
    return [
      "/usr/local/libexec/bitcoinpir/payment-v1-caddy-admin-uds-gate.mjs",
    ];
  }
  if (sourcePath === "scripts/payment-v1-caddy-admin-uds-transaction.mjs") {
    requireExactReviewedJavaScript(
      text,
      EXACT_REVIEWED_JAVASCRIPT_SHA256.adminTransaction,
      "rendered Caddy admin UDS cold transaction executor",
    );
    return [
      "/usr/local/libexec/bitcoinpir/payment-v1-caddy-admin-uds-gate.mjs",
      "/usr/local/libexec/bitcoinpir/payment-v1-caddy-admin-uds-probe.mjs",
    ];
  }
  if (sourcePath === "scripts/payment-v1-integrated-caddy-overlay-gate.mjs") {
    requireExactReviewedJavaScript(
      text,
      EXACT_REVIEWED_JAVASCRIPT_SHA256.overlayGate,
      "rendered integrated-Caddy overlay gate",
    );
    return [];
  }
  if (
    sourcePath ===
    "scripts/payment-v1-integrated-caddy-overlay-transaction.mjs"
  ) {
    requireClosedJavaScriptImportHeader(
      text,
      OVERLAY_TRANSACTION_IMPORT_HEADER,
      "rendered integrated-Caddy transaction executor",
    );
    requireExactReviewedJavaScript(
      normalizedOverlayTransactionSource(
        text,
        plan.placeholders.OVERLAY_EXCHANGE_SHA256,
      ),
      EXACT_REVIEWED_JAVASCRIPT_SHA256.overlayTransaction,
      "rendered integrated-Caddy transaction executor",
    );
    if (/@OVERLAY_EXCHANGE_SHA256@/u.test(text)) {
      fail("rendered integrated-Caddy transaction executor retains its helper placeholder");
    }
    const binary = text.match(
      /"(\/opt\/bitcoinpir\/payment-v1-rename-exchange\/[0-9a-f]{64}\/payment-v1-rename-exchange)"/u,
    )?.[1];
    const manifest = text.match(
      /"(\/etc\/bitcoinpir\/payment-v1\/integrated-existing-bhtm-caddy\/rename-exchange\.sha256)"/u,
    )?.[1];
    if (binary === undefined || manifest === undefined) {
      fail("rendered integrated-Caddy transaction executor does not close its exchange helper dependencies");
    }
    const expectedBinary =
      `/opt/bitcoinpir/payment-v1-rename-exchange/${plan.placeholders.OVERLAY_EXCHANGE_SHA256}/payment-v1-rename-exchange`;
    if (binary !== expectedBinary) {
      fail("rendered integrated-Caddy transaction executor helper path differs from the render plan");
    }
    return [
      manifest,
      binary,
      "/usr/local/libexec/bitcoinpir/payment-v1-caddy-admin-uds-gate.mjs",
      "/usr/local/libexec/bitcoinpir/payment-v1-integrated-caddy-overlay-gate.mjs",
    ].sort(asciiCompare);
  }
  const edgeReferences = {
    "deploy/payment-v1/edge/hetzner-public.Caddyfile.in": [
      "/etc/bitcoinpir/payment-v1/edge/directory-publisher-server.crt",
      "/etc/bitcoinpir/payment-v1/edge/directory-publisher-server.key",
    ],
    "deploy/payment-v1/edge/rollback-authority.Caddyfile.in": [
      "/etc/bitcoinpir/payment-v1/edge/rollback-authority-server.crt",
      "/etc/bitcoinpir/payment-v1/edge/rollback-authority-server.key",
    ],
  };
  if (edgeReferences[sourcePath]) {
    const expected = new Set(edgeReferences[sourcePath]);
    const observed = new Set();
    for (const match of text.matchAll(/\/(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+/gu)) {
      if (match[0].startsWith("/etc/bitcoinpir/payment-v1/edge/")) observed.add(match[0]);
    }
    if (canonicalize([...observed].sort(asciiCompare)) !== canonicalize([...expected].sort(asciiCompare))) {
      fail(`rendered ${sourcePath} must reference exactly its reviewed TLS files`);
    }
    return [...observed].sort(asciiCompare);
  }
  if (sourcePath !== "deploy/payment-v1/lightning/lightningd.conf.in") return [];
  const references = new Set();
  for (const original of text.split("\n")) {
    const line = original.trim();
    if (line === "" || line.startsWith("#") || !line.includes("=")) continue;
    const value = line.slice(line.indexOf("=") + 1);
    if (/[$%`;&|<>\r\0]/u.test(value)) {
      fail(`rendered ${sourcePath} contains a dynamic or shell-like value`);
    }
    for (const match of value.matchAll(/\/(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+/gu)) {
      if (MANAGED_FILE_PREFIXES.some((prefix) => match[0].startsWith(prefix))) {
        references.add(match[0]);
      }
    }
  }
  return [...references].sort(asciiCompare);
}

function parseTmpfilesDirectories(sourcePath, text) {
  if (sourcePath !== "deploy/payment-v1/lightning/cln-rpc-guard-tmpfiles.conf.in") return [];
  const directories = [];
  for (const [index, original] of text.split("\n").entries()) {
    const line = original.trim();
    if (line === "" || line.startsWith("#")) continue;
    const fields = line.split(/\s+/u);
    if (
      fields.length !== 7 ||
      fields[0] !== "d" ||
      fields[5] !== "-" ||
      fields[6] !== "-"
    ) {
      fail(`rendered ${sourcePath} line ${index + 1} is outside the closed tmpfiles schema`);
    }
    const targetPath = safeTargetPath(fields[1], `rendered ${sourcePath} directory`);
    if (!targetPath.startsWith("/run/bitcoinpir-cln-rpc-guard")) {
      fail(`rendered ${sourcePath} has an unreviewed runtime directory`);
    }
    validateMode(fields[2], ["0710"], `rendered ${sourcePath} directory`);
    for (const [field, label] of [[fields[3], "user"], [fields[4], "group"]]) {
      if (!/^[a-z_][a-z0-9_-]{0,31}$/u.test(field)) {
        fail(`rendered ${sourcePath} tmpfiles ${label} is not one literal NSS name`);
      }
    }
    directories.push({
      group_name: fields[4],
      mode: fields[2],
      target_path: targetPath,
      user_name: fields[3],
    });
  }
  directories.sort((left, right) => asciiCompare(left.target_path, right.target_path));
  if (directories.length !== 2) fail(`rendered ${sourcePath} must define exactly two directories`);
  return directories;
}

function parseHashManifest(bytes, label) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail(`${label} must be UTF-8`);
  }
  if (!/^[\x00-\x7f]*$/u.test(text) || text.length < 1 || !text.endsWith("\n")) {
    fail(`${label} must be non-empty canonical ASCII ending in newline`);
  }
  const entries = [];
  const seen = new Set();
  for (const [index, line] of text.slice(0, -1).split("\n").entries()) {
    const match = /^([0-9a-f]{64})  (\/[A-Za-z0-9._/-]+)$/u.exec(line);
    if (!match) fail(`${label} line ${index + 1} is not strict sha256sum syntax`);
    const targetPath = safeTargetPath(match[2], `${label} line ${index + 1} path`);
    if (!MANAGED_FILE_PREFIXES.some((prefix) => targetPath.startsWith(prefix))) {
      fail(`${label} line ${index + 1} is outside managed deployment prefixes`);
    }
    if (seen.has(targetPath)) fail(`${label} repeats ${targetPath}`);
    seen.add(targetPath);
    entries.push({ sha256: match[1], target_path: targetPath });
  }
  const sorted = [...entries].sort((left, right) => asciiCompare(left.target_path, right.target_path));
  if (canonicalize(entries) !== canonicalize(sorted)) {
    fail(`${label} entries must be bytewise ASCII sorted by absolute target path`);
  }
  return entries;
}

function validateHashManifestScope(manifestPath, entries, plan) {
  const oneExact = (targetPath) => {
    if (entries.length !== 1 || entries[0].target_path !== targetPath) {
      fail(`hash manifest ${manifestPath} must bind only ${targetPath}`);
    }
  };
  switch (manifestPath) {
    case "/etc/bitcoinpir/payment-v1/edge/caddy.sha256":
      oneExact(`/opt/bitcoinpir/caddy/${plan.placeholders.CADDY_SHA256}/caddy`);
      return;
    case "/etc/bitcoinpir/payment-v1/edge/edge-config.sha256":
      oneExact(
        plan.deployment_profile === "edge-hetzner-v1"
          ? "/etc/bitcoinpir/payment-v1/edge/hetzner-public.Caddyfile"
          : "/etc/bitcoinpir/payment-v1/edge/rollback-authority.Caddyfile",
      );
      return;
    case "/etc/bitcoinpir/payment-v1/source-fair-edge/haproxy.sha256":
      oneExact(`/opt/bitcoinpir/haproxy/${plan.placeholders.HAPROXY_SHA256}/haproxy`);
      return;
    case "/etc/bitcoinpir/payment-v1/source-fair-edge/source-fair-config.sha256":
      oneExact("/etc/bitcoinpir/payment-v1/source-fair-edge/haproxy.cfg");
      return;
    case "/etc/bitcoinpir/payment-v1/integrated-existing-bhtm-caddy/rename-exchange.sha256":
      oneExact(
        `/opt/bitcoinpir/payment-v1-rename-exchange/${plan.placeholders.OVERLAY_EXCHANGE_SHA256}/payment-v1-rename-exchange`,
      );
      return;
    case "/etc/bitcoinpir/payment-v1/issuer/payment-issuer.sha256":
      oneExact(`/opt/bitcoinpir/payment-issuer/${plan.placeholders.PAYMENT_ISSUER_SHA256}/payment-issuer`);
      return;
    case "/etc/bitcoinpir/payment-v1/lightning/bpir-admin.sha256":
      oneExact(`/opt/bitcoinpir/bpir-admin/${plan.placeholders.BPIR_ADMIN_SHA256}/bpir-admin`);
      return;
    case "/etc/bitcoinpir/payment-v1/lightning/cln-rpc-guard.sha256":
      oneExact(`/opt/bitcoinpir/cln-rpc-guard/${plan.placeholders.CLN_RPC_GUARD_SHA256}/bitcoinpir-cln-rpc-guard`);
      return;
    case "/etc/bitcoinpir/payment-v1/lightning/layout-verifier.sha256":
      oneExact("/usr/local/libexec/bitcoinpir/verify-lightning-layout");
      return;
    case "/etc/bitcoinpir/payment-v1/lightning/lightningd-config.sha256":
      oneExact("/etc/bitcoinpir/payment-v1/lightning/lightningd.conf");
      return;
    case "/etc/bitcoinpir/payment-v1/lightning/preflight-config.sha256":
      oneExact("/etc/bitcoinpir/payment-v1/lightning/preflight.toml");
      return;
    case "/etc/bitcoinpir/payment-v1/lightning/backup-receipt.sha256":
      if (
        entries.length !== 1 ||
        !/^\/etc\/bitcoinpir\/payment-v1\/lightning\/backup-receipt\.(?:bin|json|toml)$/u.test(
          entries[0].target_path,
        )
      ) {
        fail(`hash manifest ${manifestPath} must bind one reviewed backup-receipt artifact`);
      }
      return;
    case "/etc/bitcoinpir/payment-v1/lightning/cln-bundle.sha256": {
      const prefix = `/opt/bitcoinpir/core-lightning/${plan.placeholders.CLN_BUNDLE_SHA256}/`;
      if (entries.length < 3 || entries.some((entry) => !entry.target_path.startsWith(prefix))) {
        fail(`hash manifest ${manifestPath} must remain inside the selected CLN bundle`);
      }
      for (const required of ["bin/lightningd", "plugins/bcli", "plugins/chanbackup"]) {
        if (!entries.some((entry) => entry.target_path === `${prefix}${required}`)) {
          fail(`hash manifest ${manifestPath} is missing ${required}`);
        }
      }
      return;
    }
    case "/etc/bitcoinpir/payment-v1/lightning/bitcoin-core-bundle.sha256": {
      const prefix = `/opt/bitcoinpir/bitcoin-core/${plan.placeholders.BITCOIN_CORE_BUNDLE_SHA256}/`;
      if (entries.length < 1 || entries.some((entry) => !entry.target_path.startsWith(prefix))) {
        fail(`hash manifest ${manifestPath} must remain inside the selected Bitcoin Core bundle`);
      }
      if (!entries.some((entry) => entry.target_path === `${prefix}bin/bitcoin-cli`)) {
        fail(`hash manifest ${manifestPath} is missing bin/bitcoin-cli`);
      }
      return;
    }
    case "/etc/bitcoinpir/payment-v1/provider/unified-server.sha256":
      oneExact(`/opt/bitcoinpir/unified-server/${plan.placeholders.UNIFIED_SERVER_SHA256}/unified_server`);
      return;
    case "/etc/bitcoinpir/payment-v1/provider-no-standard-cashu/unified-server.sha256":
      oneExact(`/opt/bitcoinpir/unified-server/${plan.placeholders.UNIFIED_SERVER_SHA256}/unified_server`);
      return;
    case "/etc/bitcoinpir/payment-v1/provider-direct/unified-server.sha256":
      oneExact(`/opt/bitcoinpir/unified-server/${plan.placeholders.UNIFIED_SERVER_SHA256}/unified_server`);
      return;
    case "/etc/bitcoinpir/payment-v1/rollback-authority/rollback-authority.sha256":
      oneExact(`/opt/bitcoinpir/rollback-authority/${plan.placeholders.ROLLBACK_AUTHORITY_SHA256}/rollback-authority`);
      return;
    default:
      fail(`hash manifest target is not in the closed deployment schema: ${manifestPath}`);
  }
}

function enforceDependencyClosure({ artifacts, fileBytes, initialReferences, plan }) {
  const byTarget = new Map(artifacts.map((artifact) => [artifact.target_path, artifact]));
  const reachable = new Set(initialReferences);
  const queue = [...initialReferences].sort(asciiCompare);
  while (queue.length > 0) {
    const targetPath = queue.shift();
    const artifact = byTarget.get(targetPath);
    if (!artifact) {
      if ([...byTarget.keys()].some((candidate) => candidate.startsWith(`${targetPath}/`))) {
        continue;
      }
      fail(`deployment dependency is missing from the manifest: ${targetPath}`);
    }
    if (artifact.artifact_class !== "hash-manifest") continue;
    const bytes = fileBytes.get(artifact.bundle_path);
    const manifestEntries = parseHashManifest(bytes, `hash manifest ${targetPath}`);
    validateHashManifestScope(targetPath, manifestEntries, plan);
    for (const entry of manifestEntries) {
      const dependency = byTarget.get(entry.target_path);
      if (!dependency) {
        fail(`hash manifest ${targetPath} references missing artifact ${entry.target_path}`);
      }
      if (dependency.rendered_sha256 !== entry.sha256) {
        fail(`hash manifest ${targetPath} has the wrong digest for ${entry.target_path}`);
      }
      if (!reachable.has(entry.target_path)) {
        reachable.add(entry.target_path);
        queue.push(entry.target_path);
        queue.sort(asciiCompare);
      }
    }
  }
  for (const artifact of artifacts) {
    if (artifact.source_kind === "payload" && !reachable.has(artifact.target_path)) {
      fail(`payload artifact is not reachable from the closed deployment profile: ${artifact.target_path}`);
    }
  }

  const pathChecks = [
    ["CADDY_SHA256", "/opt/bitcoinpir/caddy/", "/caddy", true],
    ["HAPROXY_SHA256", "/opt/bitcoinpir/haproxy/", "/haproxy", true],
    [
      "OVERLAY_EXCHANGE_SHA256",
      "/opt/bitcoinpir/payment-v1-rename-exchange/",
      "/payment-v1-rename-exchange",
      true,
    ],
    ["CLN_RPC_GUARD_SHA256", "/opt/bitcoinpir/cln-rpc-guard/", "/bitcoinpir-cln-rpc-guard", true],
    ["BPIR_ADMIN_SHA256", "/opt/bitcoinpir/bpir-admin/", "/bpir-admin", true],
    ["PAYMENT_ISSUER_SHA256", "/opt/bitcoinpir/payment-issuer/", "/payment-issuer", true],
    ["UNIFIED_SERVER_SHA256", "/opt/bitcoinpir/unified-server/", "/unified_server", true],
    ["ROLLBACK_AUTHORITY_SHA256", "/opt/bitcoinpir/rollback-authority/", "/rollback-authority", true],
  ];
  for (const [placeholder, prefix, suffix, digestIsBinary] of pathChecks) {
    const digest = plan.placeholders[placeholder];
    if (digest === undefined) continue;
    const target = `${prefix}${digest}${suffix}`;
    const artifact = byTarget.get(target);
    if (!artifact || artifact.artifact_class !== "binary") {
      fail(`${placeholder} must select the exact binary target ${target}`);
    }
    if (digestIsBinary && artifact.rendered_sha256 !== digest) {
      fail(`${placeholder} must equal the selected single-file binary digest`);
    }
  }
}

function buildBundleModel({ sourceRoot, inputRoot, plan, approvedPlanSha256 }) {
  const canonicalSourceRoot = requireCanonicalRoot(sourceRoot, "source root");
  const canonicalInputRoot = requireCanonicalRoot(inputRoot, "payload input root");
  validatePlan(plan);
  const approvedPlanDigest = requireApprovedPlan(plan, approvedPlanSha256);

  const selectedTemplates = [];
  const requiredPlaceholders = new Set();
  for (const specification of plan.rendered_artifacts) {
    const sourcePath = resolveUnder(
      canonicalSourceRoot,
      specification.source_path,
      `template source ${specification.source_path}`,
    );
    const sourceBytes = readRegularSingleLinkFile(
      sourcePath,
      `template source ${specification.source_path}`,
      MAX_TEMPLATE_BYTES,
    );
    const sourceSha256 = sha256(sourceBytes);
    if (sourceSha256 !== specification.source_sha256) {
      fail(`template source hash mismatch for ${specification.source_path}`);
    }
    let sourceText;
    try {
      sourceText = new TextDecoder("utf-8", { fatal: true }).decode(sourceBytes);
    } catch {
      fail(`template source is not valid UTF-8: ${specification.source_path}`);
    }
    for (const name of extractPlaceholders(sourceText)) {
      if (!ALL_PLACEHOLDER_NAMES.has(name)) {
        fail(`template ${specification.source_path} uses unknown placeholder ${name}`);
      }
      requiredPlaceholders.add(name);
    }
    selectedTemplates.push({ specification, sourceBytes, sourceSha256, sourceText });
  }

  exactKeys(plan.placeholders, [...requiredPlaceholders], "render plan placeholders");
  for (const name of requiredPlaceholders) validatePlaceholderValue(name, plan.placeholders[name]);
  if (
    plan.deployment_profile === "edge-hetzner-v1" &&
    new Set([
      plan.placeholders.PUBLIC_HTTPS_BIND,
      plan.placeholders.DIRECTORY_PUBLISHER_PRIVATE_BIND,
      plan.placeholders.DIRECTORY_PUBLISHER_CLIENT_IP,
    ]).size !== 3
  ) {
    fail("edge-hetzner-v1 public, publisher-private bind, and publisher-client roles must use distinct addresses");
  }
  if (
    plan.deployment_profile === "edge-hetzner-v1" &&
    isIP(plan.placeholders.DIRECTORY_PUBLISHER_PRIVATE_BIND) !==
      isIP(plan.placeholders.DIRECTORY_PUBLISHER_CLIENT_IP)
  ) {
    fail("edge-hetzner-v1 publisher private bind and client addresses must use the same IP family");
  }
  if (
    plan.deployment_profile === "edge-rollback-authority-v1" &&
    plan.placeholders.ROLLBACK_AUTHORITY_PRIVATE_BIND ===
      plan.placeholders.ROLLBACK_AUTHORITY_CLIENT_IP
  ) {
    fail("rollback-authority private bind and sole-client addresses must differ");
  }
  if (plan.deployment_profile === "issuer-lightning-signet-v1") {
    const uidValues = ["ISSUER_UID", "LIGHTNING_UID", "CLN_GUARD_UID", "PREFLIGHT_UID"].map(
      (name) => plan.placeholders[name],
    );
    const gidValues = ["ISSUER_GID", "LIGHTNING_GID", "PREFLIGHT_GID"].map(
      (name) => plan.placeholders[name],
    );
    if (new Set(uidValues).size !== uidValues.length || new Set(gidValues).size !== gidValues.length) {
      fail("issuer Lightning profile service UIDs and service GIDs must be distinct per namespace");
    }
  }
  if (
    requiredPlaceholders.has("CLN_GUARD_MAX_INVOICE_BURST") &&
    BigInt(plan.placeholders.CLN_GUARD_MAX_INVOICE_BURST) >
      BigInt(plan.placeholders.CLN_GUARD_MAX_INVOICES_PER_MINUTE)
  ) {
    fail("CLN guard invoice burst must not exceed its per-minute rate");
  }

  const artifacts = [];
  const fileBytes = new Map();
  const runtimeUnits = [];
  const tmpfilesDirectories = [];
  const initialReferences = new Set();
  for (const selected of selectedTemplates) {
    const { specification, sourceSha256, sourceText } = selected;
    const catalog = TEMPLATE_CATALOG[specification.source_path];
    const renderedText = renderTemplate(
      sourceText,
      plan.placeholders,
      `rendered ${specification.source_path}`,
    );
    const renderedBytes = Buffer.from(renderedText, "utf8");
    const renderedSha256 = sha256(renderedBytes);
    const bundlePath = artifactBundlePath(specification.target_path);
    fileBytes.set(bundlePath, renderedBytes);
    artifacts.push({
      artifact_class: catalog.artifactClass,
      bundle_path: bundlePath,
      gid: specification.gid,
      mode: specification.mode,
      rendered_sha256: renderedSha256,
      source_kind: "template",
      source_path: specification.source_path,
      source_sha256: sourceSha256,
      target_path: specification.target_path,
      uid: specification.uid,
    });
    if (catalog.artifactClass === "systemd-unit") {
      const parsed = parseSystemdUnit(renderedText, `rendered unit ${specification.target_path}`);
      validateProfileUnitPolicy(
        plan.deployment_profile,
        specification.target_path,
        parsed.conditions,
        parsed.hardening,
        parsed.exec_start,
        parsed.exec_start_pre,
        `rendered unit ${specification.target_path}`,
      );
      for (const reference of parsed.managed_references) initialReferences.add(reference);
      const { managed_references: _managedReferences, ...runtimeUnit } = parsed;
      runtimeUnits.push({
        ...runtimeUnit,
        fragment_path: specification.target_path,
        unit_name: basename(specification.target_path),
      });
    }
    for (const reference of configManagedReferences(specification.source_path, renderedText, plan)) {
      initialReferences.add(reference);
    }
    tmpfilesDirectories.push(...parseTmpfilesDirectories(specification.source_path, renderedText));
  }

  for (const specification of plan.payload_artifacts) {
    const sourcePath = resolveUnder(
      canonicalInputRoot,
      specification.source_path,
      `payload source ${specification.source_path}`,
    );
    const sourceBytes = readRegularSingleLinkFile(
      sourcePath,
      `payload source ${specification.source_path}`,
      MAX_PAYLOAD_BYTES,
    );
    const sourceSha256 = sha256(sourceBytes);
    if (sourceSha256 !== specification.expected_sha256) {
      fail(`payload source hash mismatch for ${specification.source_path}`);
    }
    for (const reference of remoteRollbackConfigManagedReferences(
      plan.deployment_profile,
      specification.target_path,
      sourceBytes,
    )) {
      initialReferences.add(reference);
    }
    const bundlePath = artifactBundlePath(specification.target_path);
    fileBytes.set(bundlePath, sourceBytes);
    artifacts.push({
      artifact_class: specification.class,
      bundle_path: bundlePath,
      gid: specification.gid,
      mode: specification.mode,
      rendered_sha256: sourceSha256,
      source_kind: "payload",
      source_path: specification.source_path,
      source_sha256: sourceSha256,
      target_path: specification.target_path,
      uid: specification.uid,
    });
  }

  artifacts.sort((left, right) => asciiCompare(left.target_path, right.target_path));
  runtimeUnits.sort((left, right) => asciiCompare(left.unit_name, right.unit_name));
  validateRuntimeServiceIdentities(plan, runtimeUnits);
  enforceDependencyClosure({ artifacts, fileBytes, initialReferences, plan });
  const hashBindings = { binary: [], config: [], hash_manifest: [], policy: [], secret: [] };
  for (const artifact of artifacts) {
    hashBindings[hashBindingClass(artifact.artifact_class)].push({
      sha256: artifact.rendered_sha256,
      target_path: artifact.target_path,
    });
  }

  const canonicalPlan = canonicalJson(plan);
  const manifest = {
    artifacts,
    approved_plan_sha256: approvedPlanDigest,
    deployment_id: plan.deployment_id,
    deployment_profile: plan.deployment_profile,
    hash_bindings: hashBindings,
    placeholder_commitment_sha256: sha256(Buffer.from(canonicalJson(plan.placeholders))),
    plan_sha256: approvedPlanDigest,
    runtime_units: runtimeUnits,
    schema_version: MANIFEST_SCHEMA_VERSION,
    service_identities: plan.service_identities,
    tmpfiles_directories: tmpfilesDirectories,
  };
  const manifestBytes = Buffer.from(canonicalJson(manifest));
  const manifestSha256 = sha256(manifestBytes);
  const request = runtimeRequestFromManifest(manifest, manifestSha256);
  const requestBytes = Buffer.from(canonicalJson(request));
  fileBytes.set("payment-v1-manifest.json", manifestBytes);
  fileBytes.set("runtime-evidence-request.json", requestBytes);
  return {
    artifacts,
    fileBytes,
    manifest,
    manifestBytes,
    manifestSha256,
    request,
    requestBytes,
  };
}

export function runtimeRequestFromManifest(manifest, manifestSha256) {
  validateSha256(manifestSha256, "manifest SHA-256");
  exactKeys(
    manifest,
    [
      "approved_plan_sha256",
      "artifacts",
      "deployment_id",
      "deployment_profile",
      "hash_bindings",
      "placeholder_commitment_sha256",
      "plan_sha256",
      "runtime_units",
      "schema_version",
      "service_identities",
      "tmpfiles_directories",
    ],
    "rendered manifest",
  );
  if (manifest.schema_version !== MANIFEST_SCHEMA_VERSION) {
    fail(`rendered manifest schema_version must equal ${MANIFEST_SCHEMA_VERSION}`);
  }
  validateSha256(manifest.approved_plan_sha256, "rendered manifest approved plan SHA-256");
  if (manifest.plan_sha256 !== manifest.approved_plan_sha256) {
    fail("rendered manifest plan digest is not the externally approved digest");
  }
  if (!PROFILE_CATALOG[manifest.deployment_profile]) {
    fail("rendered manifest deployment profile is not reviewed");
  }
  if (!Array.isArray(manifest.service_identities) || manifest.service_identities.length < 1 || manifest.service_identities.length > 32) {
    fail("rendered manifest service_identities must be a bounded non-empty array");
  }
  for (const [index, identity] of manifest.service_identities.entries()) {
    const label = `rendered manifest service_identities[${index}]`;
    exactKeys(identity, ["gid", "group_name", "uid", "unit_name", "user_name"], label);
    if (!/^bitcoinpir-[a-z0-9-]+\.service$/u.test(identity.unit_name)) fail(`${label}.unit_name is malformed`);
    for (const key of ["group_name", "user_name"]) {
      if (!/^bitcoinpir-[a-z0-9-]+$/u.test(identity[key])) fail(`${label}.${key} is malformed`);
    }
    validateUidGid(identity.uid, `${label}.uid`);
    validateUidGid(identity.gid, `${label}.gid`);
    if (identity.uid === 0 || identity.gid === 0) fail(`${label} must be non-root`);
    if (index > 0 && asciiCompare(manifest.service_identities[index - 1].unit_name, identity.unit_name) >= 0) {
      fail("rendered manifest service_identities must be unique and bytewise sorted");
    }
  }
  if (new Set(manifest.service_identities.map((identity) => identity.uid)).size !== manifest.service_identities.length) {
    fail("rendered manifest service identities must use distinct UIDs");
  }
  if (
    typeof manifest.deployment_id !== "string" ||
    !/^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/u.test(manifest.deployment_id)
  ) {
    fail("rendered manifest deployment_id is malformed");
  }
  validateSha256(manifest.placeholder_commitment_sha256, "rendered manifest placeholder commitment");
  if (!Array.isArray(manifest.artifacts) || manifest.artifacts.length < 1 || manifest.artifacts.length > MAX_TREE_ENTRIES) {
    fail("rendered manifest artifacts must be a bounded non-empty array");
  }
  const installedFiles = manifest.artifacts.map((artifact, index) => {
    const label = `rendered manifest artifacts[${index}]`;
    exactKeys(
      artifact,
      [
        "artifact_class",
        "bundle_path",
        "gid",
        "mode",
        "rendered_sha256",
        "source_kind",
        "source_path",
        "source_sha256",
        "target_path",
        "uid",
      ],
      label,
    );
    safeTargetPath(artifact.target_path, `${label}.target_path`);
    if (artifact.bundle_path !== artifactBundlePath(artifact.target_path)) {
      fail(`${label}.bundle_path is not derived from target_path`);
    }
    safeRelativePath(artifact.source_path, `${label}.source_path`);
    validateSha256(artifact.source_sha256, `${label}.source_sha256`);
    validateSha256(artifact.rendered_sha256, `${label}.rendered_sha256`);
    if (![
      "argument-fragment",
      "binary",
      "config",
      "executable-config",
      "hash-manifest",
      "policy",
      "secret",
      "systemd-unit",
    ].includes(artifact.artifact_class)) {
      fail(`${label}.artifact_class is not reviewed`);
    }
    if (!["payload", "template"].includes(artifact.source_kind)) {
      fail(`${label}.source_kind is not reviewed`);
    }
    validateMode(artifact.mode, ["0400", "0440", "0444", "0555", "0644", "0710", "0755"], label);
    validateUidGid(artifact.uid, `${label}.uid`);
    validateUidGid(artifact.gid, `${label}.gid`);
    return {
      file_type: "regular",
      gid: artifact.gid,
      mode: artifact.mode,
      nlink: 1,
      sha256: artifact.rendered_sha256,
      target_path: artifact.target_path,
      uid: artifact.uid,
    };
  });
  for (let index = 1; index < installedFiles.length; index += 1) {
    if (asciiCompare(installedFiles[index - 1].target_path, installedFiles[index].target_path) >= 0) {
      fail("rendered manifest artifacts must be unique bytewise ASCII sorted targets");
    }
  }
  validateDirectoryRelayConfigOwnerBinding(manifest);
  const expectedHashBindings = { binary: [], config: [], hash_manifest: [], policy: [], secret: [] };
  for (const artifact of manifest.artifacts) {
    expectedHashBindings[hashBindingClass(artifact.artifact_class)].push({
      sha256: artifact.rendered_sha256,
      target_path: artifact.target_path,
    });
  }
  exactKeys(manifest.hash_bindings, Object.keys(expectedHashBindings), "rendered manifest hash_bindings");
  if (canonicalize(manifest.hash_bindings) !== canonicalize(expectedHashBindings)) {
    fail("rendered manifest hash_bindings do not exactly cover its artifacts");
  }
  if (!Array.isArray(manifest.runtime_units) || manifest.runtime_units.length > 32) {
    fail("rendered manifest runtime_units must be bounded");
  }
  const artifactByTarget = new Map(manifest.artifacts.map((artifact) => [artifact.target_path, artifact]));
  for (const [index, unit] of manifest.runtime_units.entries()) {
    const label = `rendered manifest runtime_units[${index}]`;
    exactKeys(
      unit,
      [
        "conditions",
        "environment",
        "environment_files",
        "exec_start",
        "exec_start_pre",
        "fragment_path",
        "hardening",
        "unit_name",
      ],
      label,
    );
    safeTargetPath(unit.fragment_path, `${label}.fragment_path`);
    if (
      !unit.fragment_path.startsWith("/etc/systemd/system/bitcoinpir-") ||
      !unit.fragment_path.endsWith(".service") ||
      unit.unit_name !== basename(unit.fragment_path)
    ) {
      fail(`${label} is not one reviewed bitcoinpir systemd unit`);
    }
    if (artifactByTarget.get(unit.fragment_path)?.artifact_class !== "systemd-unit") {
      fail(`${label}.fragment_path is not a rendered systemd artifact`);
    }
    for (const [key, minimum] of [["conditions", 1], ["exec_start", 1]]) {
      validateStringArray(unit[key], `${label}.${key}`, { maxItems: 64, maxLength: 8192 });
      if (unit[key].length < minimum) fail(`${label}.${key} is incomplete`);
    }
    if (unit.exec_start.length !== 1) fail(`${label}.exec_start must contain exactly one command`);
    for (const key of ["environment", "environment_files", "exec_start_pre"]) {
      validateStringArray(unit[key], `${label}.${key}`, { maxItems: 64, maxLength: 8192 });
    }
    if (unit.environment_files.length !== 0) fail(`${label}.environment_files must be empty`);
    if (!isPlainObject(unit.hardening)) fail(`${label}.hardening must be an object`);
    for (const [key, values] of Object.entries(unit.hardening)) {
      if (!SYSTEMD_HARDENING_KEYS.includes(key)) fail(`${label}.hardening has unknown key ${key}`);
      validateStringArray(values, `${label}.hardening.${key}`, { maxItems: 8, maxLength: 4096 });
    }
    for (const [key, expected] of Object.entries(REQUIRED_SYSTEMD_HARDENING)) {
      if (canonicalize(unit.hardening[key] ?? []) !== canonicalize(expected)) {
        fail(`${label}.hardening.${key} is weaker than the reviewed baseline`);
      }
    }
    validateProfileUnitPolicy(
      manifest.deployment_profile,
      unit.fragment_path,
      unit.conditions,
      unit.hardening,
      unit.exec_start,
      unit.exec_start_pre,
      label,
    );
  }
  if (
    canonicalize(manifest.service_identities.map((identity) => identity.unit_name)) !==
    canonicalize(manifest.runtime_units.map((unit) => unit.unit_name))
  ) {
    fail("rendered manifest service_identities must exactly cover runtime_units");
  }
  for (const unit of manifest.runtime_units) {
    const identity = manifest.service_identities.find((entry) => entry.unit_name === unit.unit_name);
    if (
      !identity ||
      canonicalize(unit.hardening.User ?? []) !== canonicalize([identity.user_name]) ||
      canonicalize(unit.hardening.Group ?? []) !== canonicalize([identity.group_name])
    ) {
      fail(`rendered manifest service identity does not match User=/Group=: ${unit.unit_name}`);
    }
  }
  validateSecretOwnerBindings(manifest);
  const systemdArtifactTargets = manifest.artifacts
    .filter((artifact) => artifact.artifact_class === "systemd-unit")
    .map((artifact) => artifact.target_path);
  const runtimeFragmentPaths = manifest.runtime_units.map((unit) => unit.fragment_path);
  if (canonicalize(runtimeFragmentPaths) !== canonicalize(systemdArtifactTargets)) {
    fail("rendered manifest runtime_units must exactly cover its systemd-unit artifacts in bytewise order");
  }
  if (!Array.isArray(manifest.tmpfiles_directories) || manifest.tmpfiles_directories.length > 16) {
    fail("rendered manifest tmpfiles_directories must be bounded");
  }
  for (const [index, directory] of manifest.tmpfiles_directories.entries()) {
    const label = `rendered manifest tmpfiles_directories[${index}]`;
    exactKeys(directory, ["group_name", "mode", "target_path", "user_name"], label);
    safeTargetPath(directory.target_path, `${label}.target_path`);
    validateMode(directory.mode, ["0710"], label);
    for (const key of ["group_name", "user_name"]) {
      if (!/^[a-z_][a-z0-9_-]{0,31}$/u.test(directory[key])) {
        fail(`${label}.${key} is not a literal NSS name`);
      }
    }
  }
  const systemdAnalyzeArgv = [
    "/usr/bin/systemd-analyze",
    "verify",
    ...manifest.runtime_units.map((unit) => unit.fragment_path),
  ];
  const secretFiles = manifest.artifacts
    .map((artifact) => ({
      artifact,
      consumerUnitName: privateLoaderConsumerUnit(
        manifest.deployment_profile,
        artifact,
      ),
    }))
    .filter(({ consumerUnitName }) => consumerUnitName !== undefined)
    .map(({ artifact, consumerUnitName }) => ({
      consumer_unit_name: consumerUnitName,
      gid: artifact.gid,
      mode: artifact.mode,
      target_path: artifact.target_path,
      uid: artifact.uid,
    }));
  const runtimePaths = [];
  if (
    new Set([
      "edge-hetzner-v1",
      "integrated-existing-bhtm-caddy-v1",
    ]).has(manifest.deployment_profile)
  ) {
    const sourceFairIdentity = manifest.service_identities.find(
      (identity) => identity.unit_name === "bitcoinpir-payment-v1-source-fair-edge.service",
    );
    if (!sourceFairIdentity) {
      fail("Hetzner source-fair runtime request is missing its service identity");
    }
    runtimePaths.push({
      file_type: "directory",
      gid: sourceFairIdentity.gid,
      mode: "0750",
      target_path: "/run/bitcoinpir-source-fair-edge",
      uid: sourceFairIdentity.uid,
    });
    for (const name of [
      "directory-public.sock",
      "directory-publisher.sock",
      "issuer.sock",
      "provider.sock",
    ]) {
      runtimePaths.push({
        file_type: "socket",
        gid: sourceFairIdentity.gid,
        mode: "0660",
        target_path: `/run/bitcoinpir-source-fair-edge/${name}`,
        uid: sourceFairIdentity.uid,
      });
    }
  }
  if (manifest.deployment_profile === "edge-rollback-authority-v1") {
    const edgeIdentity = manifest.service_identities.find(
      (identity) => identity.unit_name === "bitcoinpir-payment-v1-edge.service",
    );
    if (!edgeIdentity) {
      fail("rollback-authority edge runtime request is missing its service identity");
    }
    runtimePaths.push({
      file_type: "directory",
      gid: edgeIdentity.gid,
      mode: "0700",
      target_path: "/run/bitcoinpir-rollback-authority-edge",
      uid: edgeIdentity.uid,
    });
  }
  return {
    approved_plan_sha256: manifest.approved_plan_sha256,
    collector: RUNTIME_COLLECTOR,
    deployment_profile: manifest.deployment_profile,
    installed_files: installedFiles,
    manifest_sha256: manifestSha256,
    runtime_paths: runtimePaths,
    schema_version: EVIDENCE_SCHEMA_VERSION,
    secret_files: secretFiles,
    service_identities: manifest.service_identities,
    busctl_unit_properties: RUNTIME_BUSCTL_UNIT_PROPERTIES,
    systemctl_show_properties: RUNTIME_SYSTEMCTL_SHOW_PROPERTIES,
    systemd_analyze_argv: systemdAnalyzeArgv,
    tmpfiles_directories: manifest.tmpfiles_directories,
    units: manifest.runtime_units,
  };
}

function requireAbsent(path, label) {
  if (existsSync(path)) fail(`${label} already exists: ${path}`);
}

function ensurePrivateParent(path) {
  const requestedAbsolute = resolve(path);
  const requestedParent = dirname(requestedAbsolute);
  const parent = requireCanonicalRoot(requestedParent, "bundle output parent");
  const absolute = join(parent, basename(requestedAbsolute));
  requireAbsent(absolute, "bundle output");
  return { absolute, parent };
}

function writePrivateFile(root, relativePath, bytes) {
  const target = join(root, ...relativePath.split("/"));
  const rel = relative(root, target);
  if (rel === "" || rel === ".." || rel.startsWith(`..${sep}`)) {
    fail(`internal bundle path escapes root: ${relativePath}`);
  }
  const components = relativePath.split("/");
  let cursor = root;
  for (const component of components.slice(0, -1)) {
    cursor = join(cursor, component);
    if (!existsSync(cursor)) mkdirSync(cursor, { mode: 0o700 });
    const stat = lstatSync(cursor);
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      fail(`bundle parent is not a real directory: ${cursor}`);
    }
    chmodSync(cursor, 0o700);
  }
  writeFileSync(target, bytes, { flag: "wx", mode: 0o600 });
  chmodSync(target, 0o600);
}

export function renderBundle({ sourceRoot, inputRoot, plan, approvedPlanSha256, outputRoot }) {
  const model = buildBundleModel({ sourceRoot, inputRoot, plan, approvedPlanSha256 });
  const { absolute, parent } = ensurePrivateParent(outputRoot);
  const temporary = mkdtempSync(join(parent, `.${basename(absolute)}.tmp-`));
  chmodSync(temporary, 0o700);
  try {
    for (const [relativePath, bytes] of [...model.fileBytes.entries()].sort(([left], [right]) =>
      asciiCompare(left, right),
    )) {
      writePrivateFile(temporary, relativePath, bytes);
    }
    renameSync(temporary, absolute);
  } catch (error) {
    if (existsSync(temporary)) rmSync(temporary, { recursive: true, force: true });
    throw error;
  }
  return model;
}

function expectedBundleEntries(fileBytes) {
  const files = new Set(fileBytes.keys());
  const directories = new Set();
  for (const file of files) {
    const components = file.split("/");
    for (let index = 1; index < components.length; index += 1) {
      directories.add(components.slice(0, index).join("/"));
    }
  }
  return { directories, files };
}

function inspectBundleTree(root) {
  const rootStat = lstatSync(root);
  if ((rootStat.mode & 0o777) !== 0o700) {
    fail("rendered bundle root must remain mode 0700");
  }
  const files = new Map();
  const directories = new Set();
  let entryCount = 0;
  let totalBytes = 0;
  function walk(directory, prefix) {
    for (const entry of readdirSync(directory).sort(asciiCompare)) {
      entryCount += 1;
      if (entryCount > MAX_TREE_ENTRIES) fail(`bundle exceeds ${MAX_TREE_ENTRIES} tree entries`);
      const path = join(directory, entry);
      const relativePath = prefix === "" ? entry : `${prefix}/${entry}`;
      if (relativePath.split("/").length > MAX_PATH_COMPONENTS + 2) {
        fail(`bundle entry exceeds the depth limit: ${relativePath}`);
      }
      const stat = lstatSync(path);
      if (stat.isSymbolicLink()) fail(`bundle contains symlink: ${relativePath}`);
      if (stat.isDirectory()) {
        if ((stat.mode & 0o777) !== 0o700) {
          fail(`bundle staging directory must be mode 0700: ${relativePath}`);
        }
        directories.add(relativePath);
        walk(path, relativePath);
      } else if (stat.isFile()) {
        if (stat.nlink !== 1) fail(`bundle file has multiple hard links: ${relativePath}`);
        if ((stat.mode & 0o777) !== 0o600) {
          fail(`bundle staging file must be mode 0600: ${relativePath}`);
        }
        totalBytes += stat.size;
        if (!Number.isSafeInteger(totalBytes) || totalBytes > MAX_BUNDLE_BYTES) {
          fail(`bundle exceeds ${MAX_BUNDLE_BYTES} bytes`);
        }
        files.set(relativePath, readFileSync(path));
      } else {
        fail(`bundle contains a non-regular special file: ${relativePath}`);
      }
    }
  }
  walk(root, "");
  return { directories, files };
}

function assertSameStringSet(actual, expected, label) {
  const left = [...actual].sort();
  const right = [...expected].sort();
  if (canonicalize(left) !== canonicalize(right)) {
    fail(`${label} must equal the closed-world set ${JSON.stringify(right)}, got ${JSON.stringify(left)}`);
  }
}

export function verifyBundle({ sourceRoot, inputRoot, plan, approvedPlanSha256, bundleRoot }) {
  const model = buildBundleModel({ sourceRoot, inputRoot, plan, approvedPlanSha256 });
  const canonicalBundleRoot = requireCanonicalRoot(bundleRoot, "rendered bundle root");
  const actual = inspectBundleTree(canonicalBundleRoot);
  const expected = expectedBundleEntries(model.fileBytes);
  assertSameStringSet(actual.directories, expected.directories, "bundle directories");
  assertSameStringSet(actual.files.keys(), expected.files, "bundle files");
  for (const [relativePath, expectedBytes] of model.fileBytes) {
    const actualBytes = actual.files.get(relativePath);
    if (!actualBytes || !actualBytes.equals(expectedBytes)) {
      fail(`rendered bundle byte mismatch: ${relativePath}`);
    }
  }
  return model;
}

function validateStringArray(value, label, { maxItems = 2048, maxLength = 4096 } = {}) {
  if (!Array.isArray(value) || value.length > maxItems) fail(`${label} must be a bounded array`);
  for (const [index, entry] of value.entries()) {
    if (
      typeof entry !== "string" ||
      entry.length > maxLength ||
      /[\0\r\n]/u.test(entry)
    ) {
      fail(`${label}[${index}] must be a bounded single-line string`);
    }
  }
}

function canonicalEqual(actual, expected, label) {
  if (canonicalize(actual) !== canonicalize(expected)) {
    fail(`${label} does not match the rendered manifest expectation`);
  }
}

export function validateRuntimeEvidence({ model, evidence }) {
  if (model.manifest.deployment_profile === "directory-relay-v1") {
    fail("directory-relay-v1 is stopped-only and requires the Linux stopped-relay evidence gate");
  }
  exactKeys(
    evidence,
    [
      "collected_at_unix_seconds",
      "collector",
      "host",
      "installed_files",
      "manifest_sha256",
      "schema_version",
      "systemd_analyze_verify",
      "units",
    ],
    "runtime evidence",
  );
  if (evidence.schema_version !== EVIDENCE_SCHEMA_VERSION) {
    fail(`runtime evidence schema_version must equal ${EVIDENCE_SCHEMA_VERSION}`);
  }
  if (evidence.collector !== RUNTIME_COLLECTOR) fail("runtime evidence collector is not reviewed");
  if (evidence.manifest_sha256 !== model.manifestSha256) {
    fail("runtime evidence manifest_sha256 does not bind the rendered manifest");
  }
  if (
    !Number.isSafeInteger(evidence.collected_at_unix_seconds) ||
    evidence.collected_at_unix_seconds < 1
  ) {
    fail("runtime evidence collected_at_unix_seconds must be a positive safe integer");
  }
  exactKeys(
    evidence.host,
    ["boot_id", "kernel_release", "machine_id_sha256", "systemd_version"],
    "runtime evidence host",
  );
  validateSha256(evidence.host.machine_id_sha256, "runtime evidence host.machine_id_sha256");
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(evidence.host.boot_id)) {
    fail("runtime evidence host.boot_id must be a lowercase UUID");
  }
  for (const key of ["kernel_release", "systemd_version"]) {
    validateSafeAscii(evidence.host[key], `runtime evidence host.${key}`, 128);
  }

  exactKeys(
    evidence.systemd_analyze_verify,
    ["argv", "exit_status", "stderr", "stdout"],
    "runtime evidence systemd_analyze_verify",
  );
  validateStringArray(evidence.systemd_analyze_verify.argv, "systemd-analyze argv");
  canonicalEqual(
    evidence.systemd_analyze_verify.argv,
    model.request.systemd_analyze_argv,
    "systemd-analyze argv",
  );
  if (evidence.systemd_analyze_verify.exit_status !== 0) {
    fail("systemd-analyze verify did not exit successfully");
  }
  if (evidence.systemd_analyze_verify.stdout !== "" || evidence.systemd_analyze_verify.stderr !== "") {
    fail("systemd-analyze verify must produce no warnings or output");
  }
  if (sha256(Buffer.from(evidence.systemd_analyze_verify.stdout)) !== EMPTY_SHA256) {
    fail("systemd-analyze stdout hash is not empty");
  }

  canonicalEqual(evidence.installed_files, model.request.installed_files, "installed file evidence");
  if (!Array.isArray(evidence.units) || evidence.units.length !== model.request.units.length) {
    fail("runtime unit evidence count does not match the rendered manifest");
  }
  for (let index = 0; index < evidence.units.length; index += 1) {
    const actual = evidence.units[index];
    const expected = model.request.units[index];
    const label = `runtime evidence units[${index}]`;
    exactKeys(
      actual,
      [
        "active_state",
        "conditions",
        "drop_in_paths",
        "environment",
        "environment_files",
        "exec_start",
        "exec_start_pre",
        "fragment_path",
        "hardening",
        "load_state",
        "unit_name",
      ],
      label,
    );
    if (actual.load_state !== "loaded") fail(`${label}.load_state must equal loaded`);
    if (!["active", "inactive"].includes(actual.active_state)) {
      fail(`${label}.active_state must be active or inactive, never failed/unknown`);
    }
    if (!Array.isArray(actual.drop_in_paths) || actual.drop_in_paths.length !== 0) {
      fail(`${label}.drop_in_paths must be empty`);
    }
    for (const key of [
      "conditions",
      "environment",
      "environment_files",
      "exec_start",
      "exec_start_pre",
    ]) {
      validateStringArray(actual[key], `${label}.${key}`);
    }
    if (actual.environment_files.length !== 0) {
      fail(`${label}.environment_files must be empty`);
    }
    canonicalEqual(actual.unit_name, expected.unit_name, `${label}.unit_name`);
    canonicalEqual(actual.fragment_path, expected.fragment_path, `${label}.fragment_path`);
    canonicalEqual(actual.exec_start, expected.exec_start, `${label}.exec_start`);
    canonicalEqual(actual.exec_start_pre, expected.exec_start_pre, `${label}.exec_start_pre`);
    canonicalEqual(actual.environment, expected.environment, `${label}.environment`);
    canonicalEqual(actual.environment_files, expected.environment_files, `${label}.environment_files`);
    canonicalEqual(actual.conditions, expected.conditions, `${label}.conditions`);
    canonicalEqual(actual.hardening, expected.hardening, `${label}.hardening`);
  }
  return true;
}

function parseCli(argv) {
  const command = argv[0];
  if (!["render", "verify", "verify-runtime"].includes(command)) {
    fail("usage: payment-v1-rendered-artifact-gate.mjs <render|verify|verify-runtime> --source-root ABS --input-root ABS --plan ABS --approved-plan-sha256 HEX --bundle ABS [--evidence ABS --trusted-evidence-sha256 HEX]");
  }
  const values = Object.create(null);
  const allowed = new Set([
    "--source-root",
    "--input-root",
    "--plan",
    "--approved-plan-sha256",
    "--bundle",
    "--evidence",
    "--trusted-evidence-sha256",
  ]);
  for (let index = 1; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!allowed.has(flag) || value === undefined || values[flag] !== undefined) {
      fail(`invalid, repeated, or missing CLI option: ${flag ?? "<missing>"}`);
    }
    if (!["--approved-plan-sha256", "--trusted-evidence-sha256"].includes(flag) && !value.startsWith("/")) {
      fail(`${flag} must be an absolute path`);
    }
    values[flag] = value;
  }
  for (const required of [
    "--source-root",
    "--input-root",
    "--plan",
    "--approved-plan-sha256",
    "--bundle",
  ]) {
    if (values[required] === undefined) fail(`missing required CLI option ${required}`);
  }
  if (command === "verify-runtime" && values["--evidence"] === undefined) {
    fail("verify-runtime requires --evidence");
  }
  if (command === "verify-runtime" && values["--trusted-evidence-sha256"] === undefined) {
    fail("offline verify-runtime requires an externally trusted evidence SHA-256 pin");
  }
  if (command !== "verify-runtime" && values["--evidence"] !== undefined) {
    fail("--evidence is valid only for verify-runtime");
  }
  if (command !== "verify-runtime" && values["--trusted-evidence-sha256"] !== undefined) {
    fail("--trusted-evidence-sha256 is valid only for verify-runtime");
  }
  validateSha256(values["--approved-plan-sha256"], "CLI approved plan SHA-256");
  if (values["--trusted-evidence-sha256"] !== undefined) {
    validateSha256(values["--trusted-evidence-sha256"], "CLI trusted evidence SHA-256");
  }
  return { command, values };
}

function runCli(argv) {
  const { command, values } = parseCli(argv);
  const plan = readStrictJsonFile(values["--plan"], "render plan");
  const common = {
    bundleRoot: values["--bundle"],
    inputRoot: values["--input-root"],
    plan,
    approvedPlanSha256: values["--approved-plan-sha256"],
    sourceRoot: values["--source-root"],
  };
  if (command === "render") {
    renderBundle({ ...common, outputRoot: common.bundleRoot });
    process.stdout.write("payment-v1-rendered-artifact-gate: render PASS\n");
    return;
  }
  const model = verifyBundle(common);
  if (command === "verify-runtime") {
    const evidenceBytes = readRegularSingleLinkFile(
      values["--evidence"],
      "runtime evidence",
      MAX_JSON_BYTES,
    );
    if (sha256(evidenceBytes) !== values["--trusted-evidence-sha256"]) {
      fail("runtime evidence does not match the externally trusted evidence SHA-256 pin");
    }
    let evidenceText;
    try {
      evidenceText = new TextDecoder("utf-8", { fatal: true }).decode(evidenceBytes);
    } catch {
      fail("runtime evidence is not valid UTF-8");
    }
    const evidence = parseStrictJson(evidenceText, "runtime evidence");
    validateRuntimeEvidence({ model, evidence });
    process.stdout.write("payment-v1-rendered-artifact-gate: offline pinned runtime structure PASS\n");
    return;
  }
  process.stdout.write("payment-v1-rendered-artifact-gate: verify PASS\n");
}

const isMain =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;

if (isMain) {
  try {
    runCli(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`payment-v1-rendered-artifact-gate: FAIL: ${error.message}\n`);
    process.exitCode = 1;
  }
}
