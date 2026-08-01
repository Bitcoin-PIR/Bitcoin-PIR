#!/usr/bin/node

// Payment V1 host-global core diagnostic ceremony, v2.
//
// Security invariants:
// - the stock Noble Apport ExecStart/ExecStop handler is never executed;
// - no transition writes kernel.core_pattern=core;
// - all three Apport-mutated sysctls are plan/receipt/readback bound;
// - an approval-bound lease, boot-visible preflight, and early guards survive reboot;
// - an exact visible receipt is terminal, including commit-uncertain publication;
// - root-owned replacements use renameat2 exchange and restore raced bytes.

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  closeSync,
  chmodSync,
  chownSync,
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
  readlinkSync,
  realpathSync,
  renameSync,
  rmdirSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const CEREMONY_KIND = "bitcoinpir-payment-v1-core-pattern-ceremony-v2";
export const APPLY_APPROVAL_KIND =
  "bitcoinpir-payment-v1-core-pattern-apply-approval-v2";
export const RECOVERY_APPROVAL_KIND =
  "bitcoinpir-payment-v1-core-pattern-recovery-approval-v2";
export const ROLLBACK_APPROVAL_KIND =
  "bitcoinpir-payment-v1-core-pattern-rollback-approval-v2";
export const RECEIPT_KIND = "bitcoinpir-payment-v1-core-pattern-receipt-v2";
export const ROLLBACK_RECEIPT_KIND =
  "bitcoinpir-payment-v1-core-pattern-rollback-receipt-v2";
export const PENDING_KIND = "bitcoinpir-payment-v1-core-pattern-pending-v2";
export const PREFLIGHT_KIND =
  "bitcoinpir-payment-v1-core-pattern-preflight-intent-v2";
export const LEASE_KIND =
  "bitcoinpir-payment-v1-core-pattern-transaction-lease-v2";

export const TARGET_CORE_PATTERN = "|/usr/bin/false";
export const OBSERVED_APPORT_CORE_PATTERN =
  "|/usr/share/apport/apport -p%p -s%s -c%c -d%d -P%P -u%u -g%g -F%F -- %E";
export const TARGET_SYSCTLS = Object.freeze({
  "fs.suid_dumpable": "0",
  "kernel.core_pattern": TARGET_CORE_PATTERN,
  "kernel.core_pipe_limit": "0",
});
export const APPORT_SYSCTLS = Object.freeze({
  "fs.suid_dumpable": "2",
  "kernel.core_pattern": OBSERVED_APPORT_CORE_PATTERN,
  "kernel.core_pipe_limit": "10",
});

export const APPORT_UNIT = "apport.service";
export const APPORT_UNIT_PATH = "/usr/lib/systemd/system/apport.service";
export const SYSTEMD_SYSCTL_UNIT = "systemd-sysctl.service";
export const SYSTEMD_SYSCTL_UNIT_PATH =
  "/usr/lib/systemd/system/systemd-sysctl.service";
export const SYSTEMD_SYSCTL_BINARY_PATH = "/usr/lib/systemd/systemd-sysctl";
export const SYSTEMD_SYSCTL_ENABLEMENT_PATH =
  "/usr/lib/systemd/system/sysinit.target.wants/systemd-sysctl.service";
export const SYSTEMD_SYSCTL_ENABLEMENT_TARGET = "../systemd-sysctl.service";
export const GUARD_UNIT =
  "bitcoinpir-payment-v1-core-pattern-guard.service";
export const APPORT_HANDLER_PATH = "/usr/share/apport/apport";
export const APPORT_ENABLEMENT_PATH =
  "/etc/systemd/system/multi-user.target.wants/apport.service";
export const APPORT_ENABLEMENT_TARGET = APPORT_UNIT_PATH;
export const APPORT_MASK_PATH = "/etc/systemd/system/apport.service";
export const APPORT_MASK_TARGET = "/dev/null";
export const APPORT_GATE_PATH =
  "/etc/systemd/system/apport.service.d/90-bitcoinpir-pending-gate.conf";
export const APPORT_GATE_DIRECTORY = "/etc/systemd/system/apport.service.d";
export const SYSCTL_GATE_PATH =
  "/etc/systemd/system/systemd-sysctl.service.d/90-bitcoinpir-preflight-gate.conf";
export const SYSCTL_GATE_DIRECTORY =
  "/etc/systemd/system/systemd-sysctl.service.d";
export const SYSCTL_CREDENTIAL_CLOSURE_PATH =
  "/etc/systemd/system/systemd-sysctl.service.d/80-bitcoinpir-credential-closure.conf";
export const PREFLIGHT_PATH =
  "/etc/systemd/bitcoinpir-payment-v1-core-pattern-preflight.json";
export const PERSISTENT_POLICY_PATH =
  "/etc/sysctl.d/99-z-bitcoinpir-payment-v1-no-core.conf";
export const GUARD_UNIT_PATH =
  "/etc/systemd/system/bitcoinpir-payment-v1-core-pattern-guard.service";
export const GUARD_ENABLEMENT_PATH =
  "/etc/systemd/system/sysinit.target.wants/bitcoinpir-payment-v1-core-pattern-guard.service";
export const EXECUTOR_PATH =
  "/usr/local/libexec/bitcoinpir/payment-v1-core-pattern-ceremony.mjs";

export const NOBLE_APPORT_SOURCE_URL =
  "https://archive.ubuntu.com/ubuntu/pool/main/a/apport/apport_2.28.2.orig.tar.xz";
export const NOBLE_APPORT_ARCHIVE_SHA256 =
  "d249f388f0a0bb3aeed4bb51f405e590d99cf2474d5302679dac45f48e1b4229";
export const NOBLE_APPORT_HANDLER_SOURCE_SHA256 =
  "1b8b5e2c53e8970dd2f47c9a0892030d1ebad57cae1f7242c43a6252f1f6dff2";
export const NOBLE_APPORT_UNIT_SHA256 =
  "c2026a8f813776108e2d91629f51ff0cf5bf013fac03314164cabcda6c9698aa";
export const NOBLE_SYSTEMD_SYSCTL_UNIT_SHA256 =
  "67802699b135aa011f76ff08ecaf37b3a5d821de3a1e6f8ee55c3404e6df208a";
export const NOBLE_SYSTEMD_SYSCTL_BINARY_SHA256 =
  "de624ddf866f7af840f667a358f78b7f683e1e73aff5c13001f7095292c15210";
export const NOBLE_SYSTEMD_SYSCTL_UNIT_BYTES =
  "#  SPDX-License-Identifier: LGPL-2.1-or-later\n" +
  "#\n" +
  "#  This file is part of systemd.\n" +
  "#\n" +
  "#  systemd is free software; you can redistribute it and/or modify it\n" +
  "#  under the terms of the GNU Lesser General Public License as published by\n" +
  "#  the Free Software Foundation; either version 2.1 of the License, or\n" +
  "#  (at your option) any later version.\n" +
  "\n" +
  "[Unit]\n" +
  "Description=Apply Kernel Variables\n" +
  "Documentation=man:systemd-sysctl.service(8) man:sysctl.d(5)\n" +
  "DefaultDependencies=no\n" +
  "Conflicts=shutdown.target\n" +
  "After=systemd-modules-load.service\n" +
  "Before=sysinit.target shutdown.target\n" +
  "ConditionPathIsReadWrite=/proc/sys/net/\n" +
  "\n" +
  "[Service]\n" +
  "Type=oneshot\n" +
  "RemainAfterExit=yes\n" +
  "ExecStart=/usr/lib/systemd/systemd-sysctl\n" +
  "TimeoutSec=90s\n" +
  "ImportCredential=sysctl.*\n";
export const NOBLE_APPORT_UNIT_BYTES =
  "[Unit]\n" +
  "Description=automatic crash report generation\n" +
  "After=remote-fs.target\n" +
  "ConditionVirtualization=!container\n" +
  "\n" +
  "[Service]\n" +
  "Type=oneshot\n" +
  "RemainAfterExit=yes\n" +
  "ExecStart=/usr/share/apport/apport --start\n" +
  "ExecStop=/usr/share/apport/apport --stop\n" +
  "\n" +
  "[Install]\n" +
  "WantedBy=multi-user.target\n";

export const APPLY_ACKNOWLEDGEMENTS = Object.freeze([
  "host-wide-native-core-diagnostics-will-be-unavailable",
  "all-three-apport-sysctls-will-be-replaced-host-wide",
  "apport-handler-execstart-and-execstop-will-not-be-executed",
  "systemd-manager-will-be-reloaded-without-starting-or-stopping-apport",
  "incomplete-transaction-boots-will-skip-systemd-sysctl-and-write-the-safe-tuple-first",
  "existing-var-crash-files-and-journal-records-will-be-retained",
  "this-approval-does-not-authorize-reboot-payment-service-activation-or-history-deletion",
]);
export const RECOVERY_ACKNOWLEDGEMENTS = Object.freeze([
  "a-durable-incomplete-host-wide-transaction-will-be-resumed-fail-closed",
  "the-original-plan-boot-and-current-action-boot-are-distinct-lineage-fields",
  "apport-handler-execstart-and-execstop-will-not-be-executed",
  "systemd-manager-will-be-reloaded-without-starting-or-stopping-apport",
  "incomplete-transaction-boots-will-skip-systemd-sysctl-and-write-the-safe-tuple-first",
  "this-approval-does-not-authorize-payment-service-activation-or-history-deletion",
]);
export const ROLLBACK_ACKNOWLEDGEMENTS = Object.freeze([
  "host-wide-apport-diagnostics-will-be-restored",
  "all-three-apport-sysctls-will-be-restored-to-the-approved-preimage",
  "apport-handler-execstart-and-execstop-will-not-be-executed-during-rollback",
  "systemd-manager-will-be-reloaded-without-starting-or-stopping-apport",
  "restored-crash-material-may-contain-secrets-or-request-correlating-data",
  "this-approval-does-not-authorize-reboot-payment-service-activation-or-history-deletion",
]);

const MAX_JSON_BYTES = 1024 * 1024;
const MAX_FILE_BYTES = 256 * 1024 * 1024;
const SHA256 = /^[0-9a-f]{64}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const MODE = /^0[0-7]{3}$/u;
const SLUG = /^[a-z0-9](?:[a-z0-9-]{0,126}[a-z0-9])?$/u;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u;
const SYSCTL_PATHS = Object.freeze({
  "fs.suid_dumpable": "/proc/sys/fs/suid_dumpable",
  "kernel.core_pattern": "/proc/sys/kernel/core_pattern",
  "kernel.core_pipe_limit": "/proc/sys/kernel/core_pipe_limit",
});
const SYSCTL_DIRS = Object.freeze([
  "/etc/sysctl.d",
  "/run/sysctl.d",
  "/usr/local/lib/sysctl.d",
  "/usr/lib/sysctl.d",
  "/lib/sysctl.d",
]);
const SYSTEMD_UNIT_ROOTS = Object.freeze([
  "/etc/systemd/system.control",
  "/run/systemd/system.control",
  "/run/systemd/transient",
  "/run/systemd/generator.early",
  "/etc/systemd/system",
  "/etc/systemd/system.attached",
  "/run/systemd/system",
  "/run/systemd/system.attached",
  "/run/systemd/generator",
  "/usr/local/lib/systemd/system",
  "/usr/lib/systemd/system",
  "/run/systemd/generator.late",
  "/lib/systemd/system",
]);
export const SYSTEMD_MANAGER_UNIT_PATHS = Object.freeze(
  SYSTEMD_UNIT_ROOTS.filter(function (path) { return path !== "/lib/systemd/system"; }),
);
const REVIEWED_SYSCTLS = new Set(Object.keys(TARGET_SYSCTLS));
const SYSCTL_ASSIGNMENT = /^\s*(-)?([^\s=]+)\s*=.*$/u;
const POLICY_BYTES =
  "kernel.core_pattern=" + TARGET_CORE_PATTERN + "\n" +
  "fs.suid_dumpable=0\n" +
  "kernel.core_pipe_limit=0\n";
const APPORT_GATE_BYTES =
  "[Service]\n" +
  "ExecStop=\n" +
  "ExecCondition=/usr/bin/node " + EXECUTOR_PATH + " early-apport-gate\n" +
  "Environment=LANG=C\n" +
  "Environment=LC_ALL=C\n" +
  "Environment=PATH=/usr/sbin:/usr/bin\n" +
  "Environment=TZ=UTC\n" +
  "UnsetEnvironment=NODE_OPTIONS NODE_PATH LD_PRELOAD LD_LIBRARY_PATH\n";
const SYSCTL_GATE_BYTES =
  "[Service]\n" +
  "ExecCondition=/usr/bin/node " + EXECUTOR_PATH + " early-sysctl-gate\n" +
  "Environment=LANG=C\n" +
  "Environment=LC_ALL=C\n" +
  "Environment=PATH=/usr/sbin:/usr/bin\n" +
  "Environment=TZ=UTC\n" +
  "UnsetEnvironment=NODE_OPTIONS NODE_PATH LD_PRELOAD LD_LIBRARY_PATH\n";
const SYSCTL_CREDENTIAL_CLOSURE_BYTES =
  "[Service]\n" +
  "ImportCredential=\n" +
  "LoadCredential=\n" +
  "LoadCredentialEncrypted=\n" +
  "SetCredential=\n" +
  "SetCredentialEncrypted=\n";
export function guardUnitBytes(ceremonyId) {
  if (typeof ceremonyId !== "string" || !SLUG.test(ceremonyId)) {
    fail("guard ceremony id must be a lowercase slug");
  }
  return "[Unit]\n" +
    "Description=BitcoinPIR fail-closed core-pattern recovery guard\n" +
    "DefaultDependencies=no\n" +
    "Before=systemd-sysctl.service apport.service sysinit.target\n" +
    "ConditionPathExists=" + PREFLIGHT_PATH + "\n" +
    "\n" +
    "[Service]\n" +
    "Type=oneshot\n" +
    "ExecStart=/usr/bin/node " + EXECUTOR_PATH + " early-fail-closed\n" +
    "ExecStop=\n" +
    "Environment=LANG=C\n" +
    "Environment=LC_ALL=C\n" +
    "Environment=PATH=/usr/sbin:/usr/bin\n" +
    "Environment=TZ=UTC\n" +
    "UnsetEnvironment=NODE_OPTIONS NODE_PATH LD_PRELOAD LD_LIBRARY_PATH\n" +
    "\n" +
    "[Install]\n" +
    "WantedBy=sysinit.target\n";
}

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
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  if (isPlainObject(value)) {
    return "{" + Object.keys(value).sort().map(function (key) {
      return JSON.stringify(key) + ":" + canonicalize(value[key]);
    }).join(",") + "}";
  }
  fail("canonical JSON contains an unsupported value");
}

export function canonicalJson(value) {
  return canonicalize(value) + "\n";
}

export function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function same(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function exactKeys(value, expected, label) {
  if (!isPlainObject(value)) fail(label + " must be an object");
  const actual = Object.keys(value).sort();
  const wanted = Array.from(expected).sort();
  if (!same(actual, wanted)) {
    fail(label + " keys must equal " + JSON.stringify(wanted) + ", got " + JSON.stringify(actual));
  }
}

function exactArray(actual, expected, label) {
  if (!same(actual, expected)) fail(label + " must equal the reviewed closed set");
}

function validateSha(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) fail(label + " must be SHA-256");
}

function validateTimestamp(value, label) {
  if (typeof value !== "string" || !ISO_UTC.test(value)) fail(label + " must be whole-second UTC text");
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString().replace(".000Z", "Z") !== value) {
    fail(label + " is not canonical UTC");
  }
}

function validatePath(value, label) {
  if (typeof value !== "string" || !value.startsWith("/") || value.includes("\0") || resolve(value) !== value) {
    fail(label + " must be a canonical absolute path");
  }
}

function validatePin(value, label, options) {
  const config = options || {};
  const keys = ["gid", "mode", "nlink", "path", "sha256", "size", "uid"];
  if (config.bytesRequired) keys.push("bytes_base64");
  exactKeys(value, keys, label);
  validatePath(value.path, label + ".path");
  if (config.path !== undefined && value.path !== config.path) fail(label + ".path is not reviewed");
  validateSha(value.sha256, label + ".sha256");
  if (!Number.isSafeInteger(value.size) || value.size < 0 || value.size > (config.maxBytes || MAX_FILE_BYTES)) {
    fail(label + ".size is outside the reviewed bound");
  }
  if (!Number.isSafeInteger(value.uid) || !Number.isSafeInteger(value.gid) || value.uid < 0 || value.gid < 0) {
    fail(label + " owner is invalid");
  }
  if (value.nlink !== 1 || typeof value.mode !== "string" || !MODE.test(value.mode)) {
    fail(label + " metadata is invalid");
  }
  if (config.rootExecutable) {
    const mode = Number.parseInt(value.mode, 8);
    if (value.uid !== 0 || value.gid !== 0 || (mode & 0o022) !== 0 || (mode & 0o111) === 0) {
      fail(label + " must be a root-owned non-writable executable");
    }
  }
  if (config.bytesRequired) {
    if (typeof value.bytes_base64 !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/u.test(value.bytes_base64)) {
      fail(label + ".bytes_base64 is invalid");
    }
    const bytes = Buffer.from(value.bytes_base64, "base64");
    if (bytes.length !== value.size || sha256(bytes) !== value.sha256) {
      fail(label + " embedded bytes mismatch");
    }
  }
}

function withoutBytes(pin) {
  const copy = { ...pin };
  delete copy.bytes_base64;
  return copy;
}

function embeddedPin(path, text, mode) {
  const bytes = Buffer.from(text, "utf8");
  return {
    bytes_base64: bytes.toString("base64"),
    gid: 0,
    mode,
    nlink: 1,
    path,
    sha256: sha256(bytes),
    size: bytes.length,
    uid: 0,
  };
}

function validateDirectoryPin(value, label, expectedPath) {
  exactKeys(value, ["device", "gid", "inode", "mode", "path", "uid"], label);
  validatePath(value.path, label + ".path");
  if (value.path !== expectedPath || value.uid !== 0 || value.gid !== 0 || value.mode !== "3777") {
    fail(label + " must pin exact root:root 3777 " + expectedPath);
  }
  if (typeof value.device !== "string" || !/^[1-9][0-9]*$/u.test(value.device) ||
      typeof value.inode !== "string" || !/^[1-9][0-9]*$/u.test(value.inode)) {
    fail(label + " device/inode must be canonical positive decimal strings");
  }
}

function validateManagedDirectory(value, label, expectedPath) {
  exactKeys(value, ["gid", "mode", "path", "uid"], label);
  if (value.path !== expectedPath || value.uid !== 0 || value.gid !== 0 ||
      value.mode !== "0755") {
    fail(label + " must be exact root:root 0755 " + expectedPath);
  }
}

function validateSymlink(value, label, expectedPath, expectedTarget) {
  exactKeys(value, ["gid", "path", "target", "uid"], label);
  if (value.path !== expectedPath || value.target !== expectedTarget ||
      value.uid !== 0 || value.gid !== 0) {
    fail(label + " is not the exact reviewed symlink");
  }
}

function canonicalSysctlKey(key) {
  let normalized = key;
  if (normalized.startsWith("/")) normalized = normalized.slice(1);
  return normalized.replaceAll("/", ".");
}

function sysctlGlobRegex(pattern) {
  let source = "^";
  for (let index = 0; index < pattern.length; index += 1) {
    const character = pattern[index];
    if (character === "*") {
      source += ".*";
    } else if (character === "?") {
      source += ".";
    } else if (character === "[") {
      const close = pattern.indexOf("]", index + 1);
      if (close === -1) {
        source += ".*";
      } else {
        const body = pattern.slice(index + 1, close);
        if (!/^[!^]?[A-Za-z0-9_.-]+$/u.test(body)) {
          source += ".*";
        } else {
          const negated = body.startsWith("!") ? "^" + body.slice(1) : body;
          source += "[" + negated.replaceAll("\\", "\\\\") + "]";
        }
        index = close;
      }
    } else {
      source += character.replace(/[\\^$.*+?()[\]{}|]/gu, "\\$&");
    }
  }
  return new RegExp(source + "$", "u");
}

function parseSysctlAssignment(line) {
  const trimmed = line.trim();
  if (trimmed === "" || trimmed.startsWith("#") || trimmed.startsWith(";")) return null;
  const match = line.match(SYSCTL_ASSIGNMENT);
  if (match === null) {
    const exclusion = trimmed.match(/^-([^\s=]+)$/u);
    if (exclusion !== null) {
      const possible = canonicalSysctlKey(exclusion[1]);
      if (Array.from(REVIEWED_SYSCTLS).some(function (key) {
        return sysctlGlobRegex(possible).test(key);
      })) {
        fail("negative sysctl exclusion may affect a reviewed key: " + line);
      }
    }
    return null;
  }
  const key = canonicalSysctlKey(match[2]);
  if (/[*?[\]]/u.test(key)) {
    if (Array.from(REVIEWED_SYSCTLS).some(function (reviewed) {
      return sysctlGlobRegex(key).test(reviewed);
    })) {
      fail("sysctl glob may affect a reviewed key and is not admissible: " + line);
    }
    return null;
  }
  return { ignore_failure: match[1] === "-", key };
}

function normalizeAssignmentKey(line) {
  const parsed = parseSysctlAssignment(line);
  return parsed === null || !REVIEWED_SYSCTLS.has(parsed.key) ? null : parsed.key;
}

function validateAssignmentFile(entry, index) {
  const label = "preimage.sysctl_assignment_files[" + index + "]";
  exactKeys(entry, ["assignments", "file"], label);
  validatePin(entry.file, label + ".file");
  if (entry.file.uid !== 0 || (Number.parseInt(entry.file.mode, 8) & 0o022) !== 0) {
    fail(label + ".file must be root-owned and non-writable");
  }
  if (!Array.isArray(entry.assignments) || entry.assignments.length === 0) {
    fail(label + ".assignments must be non-empty");
  }
  for (const line of entry.assignments) {
    const key = typeof line === "string" ? normalizeAssignmentKey(line) : null;
    if (key === null || !REVIEWED_SYSCTLS.has(key)) fail(label + " has an unreviewed assignment");
  }
  if (entry.file.path === "/etc/sysctl.conf") fail("/etc/sysctl.conf must not assign reviewed sysctls");
  if (!SYSCTL_DIRS.some(function (directory) {
    return entry.file.path.startsWith(directory + "/");
  })) fail(label + " is outside reviewed sysctl directories");
  if (basename(entry.file.path) >= basename(PERSISTENT_POLICY_PATH)) {
    fail(label + " sorts at or after the ceremony policy");
  }
}

function validateOfficialNoble(value) {
  exactKeys(value, [
    "archive_sha256",
    "handler",
    "handler_source_sha256",
    "source_url",
    "unit",
    "unit_semantics",
  ], "official_noble_apport");
  if (value.source_url !== NOBLE_APPORT_SOURCE_URL ||
      value.archive_sha256 !== NOBLE_APPORT_ARCHIVE_SHA256 ||
      value.handler_source_sha256 !== NOBLE_APPORT_HANDLER_SOURCE_SHA256) {
    fail("official Noble Apport source identity is not reviewed");
  }
  validatePin(value.handler, "official_noble_apport.handler", {
    path: APPORT_HANDLER_PATH,
    rootExecutable: true,
  });
  if (value.handler.sha256 !== NOBLE_APPORT_HANDLER_SOURCE_SHA256 ||
      value.handler.size !== 44730 || value.handler.uid !== 0 || value.handler.gid !== 0 ||
      value.handler.mode !== "0755") {
    fail("official Noble Apport handler bytes/metadata are not exact");
  }
  validatePin(value.unit, "official_noble_apport.unit", {
    bytesRequired: true,
    path: APPORT_UNIT_PATH,
  });
  const unitBytes = Buffer.from(value.unit.bytes_base64, "base64").toString("utf8");
  if (unitBytes !== NOBLE_APPORT_UNIT_BYTES || value.unit.sha256 !== NOBLE_APPORT_UNIT_SHA256 ||
      value.unit.uid !== 0 || value.unit.gid !== 0 || value.unit.mode !== "0644") {
    fail("official Noble Apport unit bytes/metadata are not exact");
  }
  exactKeys(value.unit_semantics, [
    "exec_start",
    "exec_stop",
    "remain_after_exit",
    "type",
    "wanted_by",
  ], "official_noble_apport.unit_semantics");
  exactArray(value.unit_semantics.exec_start, ["/usr/share/apport/apport --start"], "Noble ExecStart");
  exactArray(value.unit_semantics.exec_stop, ["/usr/share/apport/apport --stop"], "Noble ExecStop");
  if (value.unit_semantics.type !== "oneshot" ||
      value.unit_semantics.remain_after_exit !== true ||
      !same(value.unit_semantics.wanted_by, ["multi-user.target"])) {
    fail("official Noble Apport unit semantics are not exact");
  }
}

function validateSystemdSysctlInputs(value) {
  exactKeys(value, ["binary", "enablement", "unit"], "systemd_sysctl");
  validatePin(value.unit, "systemd_sysctl.unit", {
    bytesRequired: true,
    path: SYSTEMD_SYSCTL_UNIT_PATH,
  });
  if (Buffer.from(value.unit.bytes_base64, "base64").toString("utf8") !==
        NOBLE_SYSTEMD_SYSCTL_UNIT_BYTES ||
      value.unit.sha256 !== NOBLE_SYSTEMD_SYSCTL_UNIT_SHA256 ||
      value.unit.size !== Buffer.byteLength(NOBLE_SYSTEMD_SYSCTL_UNIT_BYTES) ||
      value.unit.uid !== 0 || value.unit.gid !== 0 || value.unit.mode !== "0644") {
    fail("systemd-sysctl unit is not the reviewed Noble systemd 255 generation");
  }
  validatePin(value.binary, "systemd_sysctl.binary", {
    path: SYSTEMD_SYSCTL_BINARY_PATH,
    rootExecutable: true,
  });
  if (value.binary.sha256 !== NOBLE_SYSTEMD_SYSCTL_BINARY_SHA256 ||
      value.binary.size !== 23104 || value.binary.uid !== 0 || value.binary.gid !== 0 ||
      value.binary.mode !== "0755") {
    fail("systemd-sysctl binary is not the reviewed Noble amd64 generation");
  }
  validateSymlink(
    value.enablement,
    "systemd_sysctl.enablement",
    SYSTEMD_SYSCTL_ENABLEMENT_PATH,
    SYSTEMD_SYSCTL_ENABLEMENT_TARGET,
  );
}

function validateService(value, label, expectedFragment) {
  exactKeys(value, [
    "dropin_paths",
    "fragment",
    "name",
  ], label);
  if (value.name !== APPORT_UNIT) fail(label + " identity is not exact");
  exactArray(value.dropin_paths, [], label + ".dropin_paths");
  validatePin(value.fragment, label + ".fragment", { path: APPORT_UNIT_PATH });
  if (!same(value.fragment, withoutBytes(expectedFragment))) {
    fail(label + ".fragment differs from official Noble bytes");
  }
}

function validateRuntimeObservation(value, label) {
  exactKeys(value, [
    "active_state",
    "load_state",
    "need_daemon_reload",
    "sub_state",
  ], label);
  const settled = (value.active_state === "active" && value.sub_state === "exited") ||
    (value.active_state === "inactive" && value.sub_state === "dead");
  if (!settled || value.load_state !== "loaded" || value.need_daemon_reload !== "no") {
    fail(label + " must be settled active/exited or inactive/dead evidence");
  }
}

function sysctlGateSnapshotShape(state, directory, file) {
  return state === "present"
    ? { directory, file, state }
    : { directory_path: SYSCTL_GATE_DIRECTORY, file_path: SYSCTL_GATE_PATH, state };
}

function sysctlCredentialClosureSnapshotShape(state, directory, file) {
  return state === "present"
    ? { directory, file, state }
    : {
      directory_path: SYSCTL_GATE_DIRECTORY,
      file_path: SYSCTL_CREDENTIAL_CLOSURE_PATH,
      state,
    };
}

export function transactionLayout(ceremonyId) {
  if (typeof ceremonyId !== "string" || !SLUG.test(ceremonyId)) {
    fail("transaction ceremony id must be a lowercase slug");
  }
  const root = "/var/lib/bitcoinpir/payment-v1/core-pattern";
  const lockPath = root + "/locks/" + ceremonyId;
  const leasePath = root + "/lease.json";
  const pendingPath = root + "/pending.json";
  const receiptPath = root + "/receipts/" + ceremonyId + ".json";
  const rollbackReceiptPath = root + "/receipts/" + ceremonyId + ".rollback.json";
  return {
    lease_path: leasePath,
    lock_path: lockPath,
    pending_path: pendingPath,
    preflight_path: PREFLIGHT_PATH,
    receipt_path: receiptPath,
    rollback_receipt_path: rollbackReceiptPath,
    temp_paths: {
      apport_enablement_quarantine: APPORT_ENABLEMENT_PATH + ".bitcoinpir-quarantine",
      apport_gate_pending: APPORT_GATE_PATH + ".pending",
      apport_gate_quarantine: APPORT_GATE_PATH + ".bitcoinpir-quarantine",
      apport_mask_quarantine: APPORT_MASK_PATH + ".bitcoinpir-quarantine",
      guard_enablement_quarantine: GUARD_ENABLEMENT_PATH + ".bitcoinpir-quarantine",
      guard_unit_pending: GUARD_UNIT_PATH + ".pending",
      guard_unit_quarantine: GUARD_UNIT_PATH + ".bitcoinpir-quarantine",
      lease_prepared: leasePath + ".pending",
      lock_prepared: lockPath + ".pending",
      pending_prepared: pendingPath + ".pending",
      preflight_exchange: PREFLIGHT_PATH + ".exchange",
      preflight_prepared: PREFLIGHT_PATH + ".pending",
      persistent_policy_exchange: PERSISTENT_POLICY_PATH + ".bitcoinpir-exchange",
      receipt_pending: receiptPath + ".pending",
      rollback_receipt_pending: rollbackReceiptPath + ".pending",
      state_exchange: pendingPath + ".exchange",
      sysctl_credential_closure_pending: SYSCTL_CREDENTIAL_CLOSURE_PATH + ".pending",
      sysctl_credential_closure_quarantine:
        SYSCTL_CREDENTIAL_CLOSURE_PATH + ".bitcoinpir-quarantine",
      sysctl_gate_pending: SYSCTL_GATE_PATH + ".pending",
      sysctl_gate_quarantine: SYSCTL_GATE_PATH + ".bitcoinpir-quarantine",
    },
  };
}

function validateTransaction(value, ceremonyId) {
  exactKeys(value, [
    "lock_path",
    "lease_path",
    "pending_path",
    "preflight_path",
    "receipt_path",
    "rollback_receipt_path",
    "temp_paths",
  ], "transaction");
  const expected = transactionLayout(ceremonyId);
  for (const key of Object.keys(expected).filter(function (key) { return key !== "temp_paths"; })) {
    if (value[key] !== expected[key]) fail("transaction." + key + " must equal " + expected[key]);
  }
  const exactTemps = expected.temp_paths;
  exactKeys(value.temp_paths, Object.keys(exactTemps), "transaction.temp_paths");
  for (const key of Object.keys(exactTemps)) {
    if (value.temp_paths[key] !== exactTemps[key]) fail("transaction.temp_paths." + key + " is not fixed");
  }
}

export function validatePlan(plan) {
  exactKeys(plan, [
    "candidate",
    "ceremony_id",
    "executor",
    "host",
    "kind",
    "official_noble_apport",
    "preimage",
    "rollback_policy",
    "schema_version",
    "systemd_sysctl",
    "transaction",
  ], "plan");
  if (plan.schema_version !== 2 || plan.kind !== CEREMONY_KIND) fail("plan schema/kind is not v2");
  if (typeof plan.ceremony_id !== "string" || !SLUG.test(plan.ceremony_id)) {
    fail("ceremony_id must be a lowercase slug");
  }
  if (plan.rollback_policy !== "fresh-receipt-bound-approval-with-reboot-lineage-v2") {
    fail("rollback policy is not reviewed");
  }
  validateOfficialNoble(plan.official_noble_apport);
  validateSystemdSysctlInputs(plan.systemd_sysctl);

  exactKeys(plan.host, ["machine_id_sha256", "os_release", "plan_boot_id", "systemd_version"], "host");
  if (!UUID.test(plan.host.plan_boot_id)) fail("host.plan_boot_id must be a UUID");
  validateSha(plan.host.machine_id_sha256, "host.machine_id_sha256");
  validatePin(plan.host.os_release, "host.os_release");
  if (plan.host.os_release.uid !== 0 ||
      (Number.parseInt(plan.host.os_release.mode, 8) & 0o022) !== 0 ||
      plan.host.systemd_version !== "systemd 255 (255.4-1ubuntu8.15)") {
    fail("host OS/systemd identity is not Noble-compatible");
  }

  exactKeys(plan.executor, [
    "busctl",
    "exchange_helper",
    "false_handler",
    "maintenance_lock_helper",
    "node",
    "source",
    "systemctl",
  ], "executor");
  for (const key of Object.keys(plan.executor)) {
    validatePin(plan.executor[key], "executor." + key, {
      path: key === "false_handler" ? "/usr/bin/false" :
        key === "busctl" ? "/usr/bin/busctl" :
        key === "node" ? "/usr/bin/node" :
        key === "source" ? EXECUTOR_PATH :
        key === "systemctl" ? "/usr/bin/systemctl" : undefined,
      rootExecutable: true,
    });
  }
  const exchangeHelperPath =
    /^\/opt\/bitcoinpir\/payment-v1-rename-exchange\/([0-9a-f]{64})\/payment-v1-rename-exchange$/u.exec(
      plan.executor.exchange_helper.path,
    );
  if (exchangeHelperPath === null ||
      exchangeHelperPath[1] !== plan.executor.exchange_helper.sha256 ||
      plan.executor.maintenance_lock_helper.path !==
      "/usr/local/libexec/bitcoinpir/payment-v1-core-pattern-lock-exec") {
    fail("executor helper paths are not the reviewed content-addressed closure");
  }

  exactKeys(plan.preimage, [
    "apport_enablement_symlinks",
    "apport_gate_state",
    "apport_mask_state",
    "apport_runtime_observation",
    "apport_service",
    "crash_directory",
    "crash_entries",
    "guard_state",
    "persistent_policy_state",
    "preflight_state",
    "sysctl_credential_closure_state",
    "sysctl_gate_state",
    "sysctl_assignment_files",
    "sysctls",
  ], "preimage");
  validateService(plan.preimage.apport_service, "preimage.apport_service", plan.official_noble_apport.unit);
  validateRuntimeObservation(
    plan.preimage.apport_runtime_observation,
    "preimage.apport_runtime_observation",
  );
  exactArray(plan.preimage.apport_enablement_symlinks, [{
    gid: 0,
    path: APPORT_ENABLEMENT_PATH,
    target: APPORT_ENABLEMENT_TARGET,
    uid: 0,
  }], "preimage.apport_enablement_symlinks");
  validateSymlink(
    plan.preimage.apport_enablement_symlinks[0],
    "preimage.apport_enablement_symlinks[0]",
    APPORT_ENABLEMENT_PATH,
    APPORT_ENABLEMENT_TARGET,
  );
  if (plan.preimage.apport_mask_state !== "absent") {
    fail("preimage Apport mask must be absent");
  }
  if (plan.preimage.apport_gate_state !== "absent") {
    fail("preimage Apport activation gate must be absent");
  }
  if (plan.preimage.preflight_state !== "absent" ||
      plan.preimage.sysctl_gate_state !== "absent" ||
      plan.preimage.sysctl_credential_closure_state !== "absent") {
    fail("preimage preflight/systemd-sysctl drop-in state must be absent");
  }
  if (!same(plan.preimage.sysctls, APPORT_SYSCTLS)) fail("preimage must bind all three Noble Apport sysctls");
  if (plan.preimage.persistent_policy_state !== "absent" || plan.preimage.guard_state !== "absent") {
    fail("preimage policy/guard state must be absent");
  }
  validateDirectoryPin(plan.preimage.crash_directory, "preimage.crash_directory", "/var/crash");
  if (!Array.isArray(plan.preimage.crash_entries) ||
      plan.preimage.crash_entries.some(function (entry) {
        return typeof entry !== "string" || entry.includes("/") || entry === "." || entry === "..";
      }) ||
      !same(plan.preimage.crash_entries, Array.from(plan.preimage.crash_entries).sort()) ||
      plan.preimage.crash_entries.length !== 0) {
    fail("v2 accepts only a sorted empty /var/crash point-in-time observation");
  }
  if (!Array.isArray(plan.preimage.sysctl_assignment_files)) fail("sysctl assignment closure must be an array");
  plan.preimage.sysctl_assignment_files.forEach(validateAssignmentFile);
  const assignmentPaths = plan.preimage.sysctl_assignment_files.map(function (entry) {
    return entry.file.path;
  });
  if (!same(assignmentPaths, Array.from(assignmentPaths).sort()) ||
      new Set(assignmentPaths).size !== assignmentPaths.length) {
    fail("sysctl assignment files must be unique and sorted");
  }

  exactKeys(plan.candidate, [
    "apport_mask",
    "apport_gate",
    "apport_gate_directory",
    "guard_enablement",
    "guard_unit",
    "persistent_policy",
    "sysctl_credential_closure",
    "sysctl_gate",
    "sysctl_gate_directory",
    "sysctls",
  ], "candidate");
  validateSymlink(
    plan.candidate.apport_mask,
    "candidate.apport_mask",
    APPORT_MASK_PATH,
    APPORT_MASK_TARGET,
  );
  validatePin(plan.candidate.apport_gate, "candidate.apport_gate", {
    bytesRequired: true,
    path: APPORT_GATE_PATH,
  });
  if (Buffer.from(plan.candidate.apport_gate.bytes_base64, "base64").toString("utf8") !==
        APPORT_GATE_BYTES || plan.candidate.apport_gate.uid !== 0 ||
      plan.candidate.apport_gate.gid !== 0 || plan.candidate.apport_gate.mode !== "0644") {
    fail("candidate Apport activation gate bytes/metadata are not exact");
  }
  validateManagedDirectory(
    plan.candidate.apport_gate_directory,
    "candidate.apport_gate_directory",
    APPORT_GATE_DIRECTORY,
  );
  validatePin(plan.candidate.sysctl_gate, "candidate.sysctl_gate", {
    bytesRequired: true,
    path: SYSCTL_GATE_PATH,
  });
  if (Buffer.from(plan.candidate.sysctl_gate.bytes_base64, "base64").toString("utf8") !==
        SYSCTL_GATE_BYTES || plan.candidate.sysctl_gate.uid !== 0 ||
      plan.candidate.sysctl_gate.gid !== 0 || plan.candidate.sysctl_gate.mode !== "0644") {
    fail("candidate systemd-sysctl gate bytes/metadata are not exact");
  }
  validatePin(
    plan.candidate.sysctl_credential_closure,
    "candidate.sysctl_credential_closure",
    { bytesRequired: true, path: SYSCTL_CREDENTIAL_CLOSURE_PATH },
  );
  if (Buffer.from(
    plan.candidate.sysctl_credential_closure.bytes_base64,
    "base64",
  ).toString("utf8") !== SYSCTL_CREDENTIAL_CLOSURE_BYTES ||
      plan.candidate.sysctl_credential_closure.uid !== 0 ||
      plan.candidate.sysctl_credential_closure.gid !== 0 ||
      plan.candidate.sysctl_credential_closure.mode !== "0644") {
    fail("candidate systemd-sysctl credential closure bytes/metadata are not exact");
  }
  validateManagedDirectory(
    plan.candidate.sysctl_gate_directory,
    "candidate.sysctl_gate_directory",
    SYSCTL_GATE_DIRECTORY,
  );
  if (!same(plan.candidate.sysctls, TARGET_SYSCTLS)) fail("candidate must bind all three safe sysctls");
  validatePin(plan.candidate.persistent_policy, "candidate.persistent_policy", {
    bytesRequired: true,
    path: PERSISTENT_POLICY_PATH,
  });
  if (Buffer.from(plan.candidate.persistent_policy.bytes_base64, "base64").toString("utf8") !== POLICY_BYTES ||
      plan.candidate.persistent_policy.uid !== 0 || plan.candidate.persistent_policy.gid !== 0 ||
      plan.candidate.persistent_policy.mode !== "0644") {
    fail("candidate persistent policy bytes/metadata are not exact");
  }
  validatePin(plan.candidate.guard_unit, "candidate.guard_unit", {
    bytesRequired: true,
    path: GUARD_UNIT_PATH,
  });
  if (Buffer.from(plan.candidate.guard_unit.bytes_base64, "base64").toString("utf8") !==
        guardUnitBytes(plan.ceremony_id) ||
      plan.candidate.guard_unit.uid !== 0 || plan.candidate.guard_unit.gid !== 0 ||
      plan.candidate.guard_unit.mode !== "0644") {
    fail("candidate guard unit bytes/metadata are not exact");
  }
  validateSymlink(
    plan.candidate.guard_enablement,
    "candidate.guard_enablement",
    GUARD_ENABLEMENT_PATH,
    GUARD_UNIT_PATH,
  );
  validateTransaction(plan.transaction, plan.ceremony_id);
  return plan;
}

export function planSha256(plan) {
  validatePlan(plan);
  return sha256(Buffer.from(canonicalJson(plan), "utf8"));
}

function validateApprovalWindow(approval, now) {
  validateTimestamp(approval.approved_at_utc, "approval.approved_at_utc");
  validateTimestamp(approval.expires_at_utc, "approval.expires_at_utc");
  const start = Date.parse(approval.approved_at_utc);
  const end = Date.parse(approval.expires_at_utc);
  if (end <= start || end - start > 60 * 60 * 1000) {
    fail("approval window must be positive and at most one hour");
  }
  if (now < start || now > end) fail("approval is not fresh at action time");
}

function validateApprovalBase(approval, plan, planDigest, sourceDigest, kind, acknowledgements, now) {
  const baseKeys = [
    "acknowledgements",
    "action_boot_id",
    "approved_at_utc",
    "approved_by",
    "ceremony_id",
    "decision",
    "executor_sha256",
    "expires_at_utc",
    "kind",
    "plan_boot_id",
    "plan_sha256",
    "schema_version",
  ];
  return baseKeys;
}

function assertApprovalBase(
  approval,
  plan,
  planDigest,
  sourceDigest,
  kind,
  acknowledgements,
  actionBootId,
  now,
) {
  if (approval.schema_version !== 2 || approval.kind !== kind ||
      approval.ceremony_id !== plan.ceremony_id ||
      approval.plan_sha256 !== planDigest ||
      approval.executor_sha256 !== sourceDigest ||
      approval.plan_boot_id !== plan.host.plan_boot_id ||
      approval.action_boot_id !== actionBootId || !UUID.test(actionBootId) ||
      typeof approval.approved_by !== "string" || approval.approved_by.length < 1 ||
      approval.approved_by.length > 128 || !UUID.test(approval.action_boot_id)) {
    fail("approval identity/lineage is not reviewed");
  }
  exactArray(approval.acknowledgements, acknowledgements, "approval.acknowledgements");
  validateApprovalWindow(approval, now);
}

export function validateApplyApproval(approval, plan, planDigest, sourceDigest, actionBootId, now) {
  exactKeys(approval, validateApprovalBase(), "apply approval");
  assertApprovalBase(
    approval, plan, planDigest, sourceDigest,
    APPLY_APPROVAL_KIND, APPLY_ACKNOWLEDGEMENTS, actionBootId,
    now === undefined ? Date.now() : now,
  );
  if (approval.action_boot_id !== plan.host.plan_boot_id ||
      approval.decision !== "approve-disable-host-core-diagnostics") {
    fail("apply approval must act on the exact plan boot");
  }
  return approval;
}

export function validateRecoveryApproval(
  approval,
  plan,
  planDigest,
  sourceDigest,
  recoverySubjectKind,
  recoverySubjectDigest,
  originalApprovalDigest,
  mode,
  actionBootId,
  now,
) {
  const keys = validateApprovalBase().concat([
    "original_approval_sha256",
    "recovery_mode",
    "recovery_subject_kind",
    "recovery_subject_sha256",
  ]);
  exactKeys(approval, keys, "recovery approval");
  assertApprovalBase(
    approval, plan, planDigest, sourceDigest,
    RECOVERY_APPROVAL_KIND, RECOVERY_ACKNOWLEDGEMENTS, actionBootId,
    now === undefined ? Date.now() : now,
  );
  validateSha(approval.recovery_subject_sha256, "approval.recovery_subject_sha256");
  validateSha(approval.original_approval_sha256, "approval.original_approval_sha256");
  if (!["lease", "preflight", "pending"].includes(recoverySubjectKind) ||
      approval.recovery_subject_kind !== recoverySubjectKind ||
      approval.recovery_subject_sha256 !== recoverySubjectDigest ||
      approval.original_approval_sha256 !== originalApprovalDigest ||
      approval.recovery_mode !== mode ||
      approval.decision !== "approve-resume-fail-closed-host-transaction") {
    fail("recovery approval does not bind the durable recovery subject lineage");
  }
  return approval;
}

export function validateRollbackApproval(
  approval,
  plan,
  planDigest,
  sourceDigest,
  receiptDigest,
  actionBootId,
  now,
) {
  const keys = validateApprovalBase().concat(["committed_receipt_sha256"]);
  exactKeys(approval, keys, "rollback approval");
  assertApprovalBase(
    approval, plan, planDigest, sourceDigest,
    ROLLBACK_APPROVAL_KIND, ROLLBACK_ACKNOWLEDGEMENTS, actionBootId,
    now === undefined ? Date.now() : now,
  );
  validateSha(approval.committed_receipt_sha256, "approval.committed_receipt_sha256");
  if (approval.committed_receipt_sha256 !== receiptDigest ||
      approval.decision !== "approve-restore-host-core-diagnostics") {
    fail("rollback approval does not bind the exact committed receipt");
  }
  return approval;
}

export function expectedPreimage(plan) {
  return {
    apport_enablement_symlinks: plan.preimage.apport_enablement_symlinks,
    apport_gate: {
      directory_path: APPORT_GATE_DIRECTORY,
      file_path: APPORT_GATE_PATH,
      state: "absent",
    },
    apport_mask: { path: APPORT_MASK_PATH, state: "absent" },
    apport_service: plan.preimage.apport_service,
    crash_directory: plan.preimage.crash_directory,
    crash_entries: plan.preimage.crash_entries,
    guard: { state: "absent" },
    sysctl_credential_closure: sysctlCredentialClosureSnapshotShape("absent"),
    sysctl_gate: sysctlGateSnapshotShape("absent"),
    persistent_policy: { path: PERSISTENT_POLICY_PATH, state: "absent" },
    sysctl_assignment_files: plan.preimage.sysctl_assignment_files,
    sysctls: plan.preimage.sysctls,
  };
}

export function expectedCandidate(plan) {
  return {
    apport_enablement_symlinks: [],
    apport_gate: {
      directory_path: APPORT_GATE_DIRECTORY,
      file_path: APPORT_GATE_PATH,
      state: "absent",
    },
    apport_mask: { link: plan.candidate.apport_mask, state: "present" },
    apport_service: plan.preimage.apport_service,
    crash_directory: plan.preimage.crash_directory,
    crash_entries: plan.preimage.crash_entries,
    guard: { state: "absent" },
    sysctl_credential_closure: sysctlCredentialClosureSnapshotShape(
      "present",
      plan.candidate.sysctl_gate_directory,
      plan.candidate.sysctl_credential_closure,
    ),
    sysctl_gate: sysctlGateSnapshotShape("absent"),
    persistent_policy: {
      file: plan.candidate.persistent_policy,
      state: "present",
    },
    sysctl_assignment_files: plan.preimage.sysctl_assignment_files.concat([{
      assignments: POLICY_BYTES.trimEnd().split("\n"),
      file: withoutBytes(plan.candidate.persistent_policy),
    }]).sort(function (a, b) {
      return a.file.path.localeCompare(b.file.path);
    }),
    sysctls: plan.candidate.sysctls,
  };
}

export function expectedGuardedCandidate(plan) {
  const candidate = expectedCandidate(plan);
  candidate.apport_gate = {
    directory: plan.candidate.apport_gate_directory,
    file: plan.candidate.apport_gate,
    state: "present",
  };
  candidate.apport_service = {
    ...candidate.apport_service,
    dropin_paths: [APPORT_GATE_PATH],
  };
  candidate.guard = {
    enablement: plan.candidate.guard_enablement,
    state: "present",
    unit: plan.candidate.guard_unit,
  };
  candidate.sysctl_gate = sysctlGateSnapshotShape(
    "present",
    plan.candidate.sysctl_gate_directory,
    plan.candidate.sysctl_gate,
  );
  return candidate;
}

export function expectedGuardedPreimage(plan) {
  const preimage = expectedPreimage(plan);
  preimage.apport_gate = {
    directory: plan.candidate.apport_gate_directory,
    file: plan.candidate.apport_gate,
    state: "present",
  };
  preimage.apport_service = {
    ...preimage.apport_service,
    dropin_paths: [APPORT_GATE_PATH],
  };
  preimage.guard = {
    enablement: plan.candidate.guard_enablement,
    state: "present",
    unit: plan.candidate.guard_unit,
  };
  preimage.sysctl_gate = sysctlGateSnapshotShape(
    "present",
    plan.candidate.sysctl_gate_directory,
    plan.candidate.sysctl_gate,
  );
  return preimage;
}

function assertSnapshot(actual, expected, label) {
  if (!same(actual, expected)) fail(label + " does not match the exact approved state");
}

export class CeremonyError extends Error {
  constructor(message, details) {
    super(message, { cause: details === undefined ? undefined : details.cause });
    this.name = "CeremonyError";
    this.outcome = details === undefined ? undefined : details.outcome;
    this.phase = details === undefined ? undefined : details.phase;
    this.containment = details === undefined ? undefined : details.containment;
  }
}

function assertContextApprovalBoot(context, field, label) {
  if (!UUID.test(context.actionBootId) || context[field] !== context.actionBootId) {
    fail(label + " action_boot_id differs from the actual /proc boot ID");
  }
}

function wholeSecond(value) {
  return new Date(value).toISOString().replace(/\.\d{3}Z$/u, "Z");
}

function originalApprovalSha256(context, mode) {
  const digest = mode === "apply" ? context.approvalSha256 : context.rollbackApprovalSha256;
  validateSha(digest, mode + " original approval SHA-256");
  return digest;
}

function transactionLeaseBase(plan, context, mode) {
  return {
    action_boot_id: context.actionBootId,
    ceremony_id: plan.ceremony_id,
    kind: LEASE_KIND,
    mode,
    original_approval_sha256: originalApprovalSha256(context, mode),
    plan_sha256: context.planSha256,
    schema_version: 2,
    source_sha256: context.sourceSha256,
    started_at_utc: wholeSecond(context.approvedAtUtc),
  };
}

function validateLease(value, plan, context, label) {
  exactKeys(value, [
    "action_boot_id",
    "ceremony_id",
    "kind",
    "mode",
    "original_approval_sha256",
    "plan_sha256",
    "schema_version",
    "source_sha256",
    "started_at_utc",
  ], label);
  if (value.schema_version !== 2 || value.kind !== LEASE_KIND ||
      value.ceremony_id !== plan.ceremony_id || value.plan_sha256 !== context.planSha256 ||
      value.source_sha256 !== context.sourceSha256 || !UUID.test(value.action_boot_id) ||
      !["apply", "rollback"].includes(value.mode)) {
    fail(label + " identity/lineage is not reviewed");
  }
  validateSha(value.original_approval_sha256, label + " original approval SHA-256");
  validateTimestamp(value.started_at_utc, label + " start time");
  return value;
}

function preflightBase(plan, context, lease, recoveryApprovalSha256s) {
  validateLease(lease, plan, context, "transaction lease");
  const chain = recoveryApprovalSha256s || [];
  return {
    action_boot_id: context.actionBootId,
    apply_boot_id: plan.host.plan_boot_id,
    ceremony_id: plan.ceremony_id,
    generation: 0,
    kind: PREFLIGHT_KIND,
    mode: lease.mode,
    original_approval_sha256: lease.original_approval_sha256,
    plan_sha256: context.planSha256,
    previous_generation_sha256: null,
    recovery_approval_sha256s: chain,
    schema_version: 2,
    source_sha256: context.sourceSha256,
    started_at_utc: lease.started_at_utc,
  };
}

function validateDigestChain(value, label) {
  if (!Array.isArray(value) || new Set(value).size !== value.length) {
    fail(label + " must be a unique ordered array");
  }
  value.forEach(function (digest, index) {
    validateSha(digest, label + "[" + index + "]");
  });
}

function validateGeneration(value, label) {
  if (!Number.isSafeInteger(value.generation) || value.generation < 0) {
    fail(label + " generation must be a non-negative safe integer");
  }
  if ((value.generation === 0 && value.previous_generation_sha256 !== null) ||
      (value.generation > 0 && !SHA256.test(value.previous_generation_sha256))) {
    fail(label + " previous-generation link is invalid");
  }
}

function validatePreflight(value, plan, context, label) {
  exactKeys(value, [
    "action_boot_id",
    "apply_boot_id",
    "ceremony_id",
    "generation",
    "kind",
    "mode",
    "original_approval_sha256",
    "plan_sha256",
    "previous_generation_sha256",
    "recovery_approval_sha256s",
    "schema_version",
    "source_sha256",
    "started_at_utc",
  ], label);
  if (value.schema_version !== 2 || value.kind !== PREFLIGHT_KIND ||
      value.ceremony_id !== plan.ceremony_id || value.plan_sha256 !== context.planSha256 ||
      value.source_sha256 !== context.sourceSha256 ||
      value.apply_boot_id !== plan.host.plan_boot_id || !UUID.test(value.action_boot_id) ||
      !["apply", "rollback"].includes(value.mode)) {
    fail(label + " identity/lineage is not reviewed");
  }
  validateSha(value.original_approval_sha256, label + " original approval SHA-256");
  validateTimestamp(value.started_at_utc, label + " start time");
  validateDigestChain(value.recovery_approval_sha256s, label + " recovery approval chain");
  validateGeneration(value, label);
  return value;
}

function nextGeneration(value, changes) {
  return {
    ...value,
    ...changes,
    generation: value.generation + 1,
    previous_generation_sha256: sha256(Buffer.from(canonicalJson(value), "utf8")),
  };
}

function pendingBase(plan, context, preflight) {
  validatePreflight(preflight, plan, context, "pending preflight lineage");
  return {
    action_boot_id: context.actionBootId,
    apply_boot_id: plan.host.plan_boot_id,
    ceremony_id: plan.ceremony_id,
    generation: 0,
    kind: PENDING_KIND,
    mode: preflight.mode,
    original_approval_sha256: preflight.original_approval_sha256,
    plan_sha256: context.planSha256,
    preflight_sha256: sha256(Buffer.from(canonicalJson(preflight), "utf8")),
    previous_generation_sha256: null,
    receipt_candidate: null,
    recovery_approval_sha256s: preflight.recovery_approval_sha256s,
    schema_version: 2,
    source_sha256: context.sourceSha256,
    started_at_utc: wholeSecond(context.approvedAtUtc),
  };
}

function validatePendingBase(value, plan, context, label) {
  exactKeys(value, [
    "action_boot_id",
    "apply_boot_id",
    "ceremony_id",
    "generation",
    "kind",
    "mode",
    "original_approval_sha256",
    "plan_sha256",
    "preflight_sha256",
    "previous_generation_sha256",
    "receipt_candidate",
    "recovery_approval_sha256s",
    "schema_version",
    "source_sha256",
    "started_at_utc",
  ], label);
  if (value.schema_version !== 2 || value.kind !== PENDING_KIND ||
      value.ceremony_id !== plan.ceremony_id ||
      value.plan_sha256 !== context.planSha256 ||
      value.source_sha256 !== context.sourceSha256 ||
      value.apply_boot_id !== plan.host.plan_boot_id ||
      !UUID.test(value.action_boot_id) ||
      !["apply", "rollback"].includes(value.mode)) {
    fail(label + " identity/lineage is not reviewed");
  }
  validateSha(value.original_approval_sha256, label + " approval SHA-256");
  validateSha(value.preflight_sha256, label + " preflight SHA-256");
  validateDigestChain(value.recovery_approval_sha256s, label + " recovery approval chain");
  validateGeneration(value, label);
  validateTimestamp(value.started_at_utc, label + " start time");
  return value;
}

function validateInitialPending(value, plan) {
  validatePendingBase(value, plan, {
    planSha256: planSha256(plan),
    sourceSha256: plan.executor.source.sha256,
  }, "initial pending state");
  if (value.receipt_candidate !== null) {
    fail("initial pending state must not contain a receipt candidate");
  }
  if (value.generation !== 0 || value.previous_generation_sha256 !== null) {
    fail("initial pending generation must be zero with no predecessor");
  }
  return value;
}

function isDirectGenerationSuccessor(newer, older) {
  if (!isPlainObject(newer) || !isPlainObject(older) ||
      newer.generation !== older.generation + 1 ||
      newer.previous_generation_sha256 !== sha256(Buffer.from(canonicalJson(older), "utf8"))) {
    return false;
  }
  for (const key of [
    "apply_boot_id", "ceremony_id", "kind", "mode", "original_approval_sha256",
    "plan_sha256", "source_sha256", "started_at_utc",
  ]) {
    if (!same(newer[key], older[key])) return false;
  }
  return true;
}

export function classifyRetainedGeneration(current, retained) {
  if (isDirectGenerationSuccessor(retained, current)) return "prepared-successor";
  if (isDirectGenerationSuccessor(current, retained)) return "committed-predecessor";
  fail("retained exchange is outside the direct generation chain");
}

function receiptBase(plan, context, pending, before, after) {
  return {
    action_boot_id: context.actionBootId,
    apply_approval_sha256:
      pending.mode === "apply" ? pending.original_approval_sha256 : context.applyApprovalSha256,
    apply_boot_id: plan.host.plan_boot_id,
    ceremony_id: plan.ceremony_id,
    committed_at_utc: pending.started_at_utc,
    executor_sha256: context.sourceSha256,
    history_cleanup_performed: false,
    host_reboot_performed: context.actionBootId !== plan.host.plan_boot_id,
    kind: RECEIPT_KIND,
    outcome: "committed",
    plan_sha256: context.planSha256,
    post_state: expectedCandidate(plan),
    preflight_sha256: pending.preflight_sha256,
    pre_state: before,
    recovery_approval_sha256s: pending.recovery_approval_sha256s,
    schema_version: 2,
    terminal_commit_state: after,
  };
}

function rollbackReceiptBase(plan, context, pending, after) {
  return {
    action_boot_id: context.actionBootId,
    apply_boot_id: plan.host.plan_boot_id,
    ceremony_id: plan.ceremony_id,
    committed_receipt_sha256: context.receiptSha256,
    completed_at_utc: pending.started_at_utc,
    executor_sha256: context.sourceSha256,
    history_cleanup_performed: false,
    host_reboot_performed: context.actionBootId !== plan.host.plan_boot_id,
    kind: ROLLBACK_RECEIPT_KIND,
    outcome: "rolled-back-to-approved-preimage",
    plan_sha256: context.planSha256,
    post_state: expectedPreimage(plan),
    preflight_sha256: pending.preflight_sha256,
    recovery_approval_sha256s: pending.recovery_approval_sha256s,
    rollback_approval_sha256: pending.original_approval_sha256,
    schema_version: 2,
    terminal_commit_state: after,
  };
}

export function validateCommittedReceipt(value, plan, context) {
  exactKeys(value, [
    "action_boot_id",
    "apply_approval_sha256",
    "apply_boot_id",
    "ceremony_id",
    "committed_at_utc",
    "executor_sha256",
    "history_cleanup_performed",
    "host_reboot_performed",
    "kind",
    "outcome",
    "plan_sha256",
    "post_state",
    "preflight_sha256",
    "pre_state",
    "recovery_approval_sha256s",
    "schema_version",
    "terminal_commit_state",
  ], "committed receipt");
  if (value.schema_version !== 2 || value.kind !== RECEIPT_KIND ||
      value.ceremony_id !== plan.ceremony_id ||
      value.plan_sha256 !== context.planSha256 ||
      value.executor_sha256 !== context.sourceSha256 ||
      value.apply_boot_id !== plan.host.plan_boot_id ||
      !UUID.test(value.action_boot_id) ||
      value.host_reboot_performed !== (value.action_boot_id !== value.apply_boot_id) ||
      value.history_cleanup_performed !== false ||
      value.outcome !== "committed") {
    fail("committed receipt identity/lineage is not reviewed");
  }
  validateSha(value.apply_approval_sha256, "receipt.apply_approval_sha256");
  validateSha(value.preflight_sha256, "receipt.preflight_sha256");
  if (!Array.isArray(value.recovery_approval_sha256s) ||
      new Set(value.recovery_approval_sha256s).size !== value.recovery_approval_sha256s.length) {
    fail("receipt recovery approval chain is invalid");
  }
  value.recovery_approval_sha256s.forEach(function (digest, index) {
    validateSha(digest, "receipt.recovery_approval_sha256s[" + index + "]");
  });
  validateTimestamp(value.committed_at_utc, "receipt.committed_at_utc");
  assertSnapshot(value.pre_state, expectedPreimage(plan), "receipt pre_state");
  assertSnapshot(value.post_state, expectedCandidate(plan), "receipt post_state");
  assertSnapshot(
    value.terminal_commit_state,
    expectedGuardedCandidate(plan),
    "receipt terminal_commit_state",
  );
  return value;
}

export function validateRollbackReceipt(value, plan, context) {
  exactKeys(value, [
    "action_boot_id",
    "apply_boot_id",
    "ceremony_id",
    "committed_receipt_sha256",
    "completed_at_utc",
    "executor_sha256",
    "history_cleanup_performed",
    "host_reboot_performed",
    "kind",
    "outcome",
    "plan_sha256",
    "post_state",
    "preflight_sha256",
    "recovery_approval_sha256s",
    "rollback_approval_sha256",
    "schema_version",
    "terminal_commit_state",
  ], "rollback receipt");
  if (value.schema_version !== 2 || value.kind !== ROLLBACK_RECEIPT_KIND ||
      value.ceremony_id !== plan.ceremony_id ||
      value.plan_sha256 !== context.planSha256 ||
      value.executor_sha256 !== context.sourceSha256 ||
      value.apply_boot_id !== plan.host.plan_boot_id ||
      !UUID.test(value.action_boot_id) ||
      value.host_reboot_performed !== (value.action_boot_id !== value.apply_boot_id) ||
      value.history_cleanup_performed !== false ||
      value.outcome !== "rolled-back-to-approved-preimage" ||
      value.committed_receipt_sha256 !== context.receiptSha256) {
    fail("rollback receipt identity/lineage is not reviewed");
  }
  validateSha(value.rollback_approval_sha256, "rollback receipt approval digest");
  validateSha(value.preflight_sha256, "rollback receipt preflight digest");
  if (!Array.isArray(value.recovery_approval_sha256s) ||
      new Set(value.recovery_approval_sha256s).size !== value.recovery_approval_sha256s.length) {
    fail("rollback receipt recovery approval chain is invalid");
  }
  value.recovery_approval_sha256s.forEach(function (digest, index) {
    validateSha(digest, "rollback receipt.recovery_approval_sha256s[" + index + "]");
  });
  validateTimestamp(value.completed_at_utc, "rollback receipt completion time");
  assertSnapshot(value.post_state, expectedPreimage(plan), "rollback receipt post_state");
  assertSnapshot(
    value.terminal_commit_state,
    expectedGuardedPreimage(plan),
    "rollback receipt terminal_commit_state",
  );
  return value;
}

async function bindCommittedReceiptLineage(plan, context, ops) {
  const committed = await ops.readReceipt(plan.transaction.receipt_path);
  if (committed === null) fail("rollback requires the exact committed receipt");
  validateCommittedReceipt(committed, plan, context);
  const digest = sha256(Buffer.from(canonicalJson(committed), "utf8"));
  if (context.receiptSha256 !== undefined && context.receiptSha256 !== digest) {
    fail("approved committed receipt SHA-256 differs from exact committed receipt");
  }
  context.applyApprovalSha256 = committed.apply_approval_sha256;
  context.receiptSha256 = digest;
  return committed;
}

async function exactExistingReceipt(plan, context, ops) {
  const existing = await ops.readReceipt(plan.transaction.receipt_path);
  if (existing === null) return null;
  validateCommittedReceipt(existing, plan, context);
  if (await ops.readRecoverySubject() !== null) {
    throw new CeremonyError("exact receipt is visible but retained state requires fresh recovery approval", {
      outcome: "recovery-approval-required-lock-retained",
      phase: "terminal-state-cleanup",
    });
  }
  assertSnapshot(await ops.inspect(), existing.post_state, "already-clean committed post-state");
  return {
    outcome: "already-committed",
    receipt: existing,
    receipt_sha256: sha256(Buffer.from(canonicalJson(existing), "utf8")),
  };
}

async function publishTerminalReceipt(plan, context, pending, before, after, ops) {
  const receipt = pending.receipt_candidate === null
    ? receiptBase(plan, context, pending, before, after)
    : pending.receipt_candidate;
  if (pending.receipt_candidate === null) {
    pending = nextGeneration(pending, { receipt_candidate: receipt });
    await ops.writePending(plan.transaction.pending_path, pending);
  }
  await ops.assertRuntime("apply-pre-publish");
  let uncertain = false;
  try {
    await ops.publishReceiptAfterFullInspection(
      plan.transaction.receipt_path,
      receipt,
      receipt.terminal_commit_state,
      "apply final full pre-publication inspection",
    );
  } catch (cause) {
    const visible = await ops.readReceipt(plan.transaction.receipt_path);
    if (visible === null || !same(visible, receipt)) throw cause;
    uncertain = true;
  }
  const visible = await ops.readReceipt(plan.transaction.receipt_path);
  if (visible === null || !same(visible, receipt)) fail("receipt publication did not expose exact deterministic bytes");
  const baseOutcome = uncertain ? "receipt-visible-commit-uncertain" : "committed";
  try {
    await ops.finalizeTerminal(
      plan.transaction.lock_path,
      plan.transaction.pending_path,
      receipt,
      context,
    );
  } catch (cause) {
    throw new CeremonyError("receipt is terminal but deterministic cleanup failed: " + cause.message, {
      cause,
      outcome: baseOutcome + "-cleanup-retained",
      phase: "terminal-state-cleanup",
    });
  }
  return {
    outcome: baseOutcome,
    receipt,
    receipt_sha256: sha256(Buffer.from(canonicalJson(receipt), "utf8")),
  };
}

async function ensureFailClosedCandidate(plan, ops) {
  await ops.ensureGuard(plan.candidate.guard_unit, plan.candidate.guard_enablement);
  await ops.installPersistent(plan.candidate.persistent_policy);
  await ops.writeSysctl("kernel.core_pattern", TARGET_SYSCTLS["kernel.core_pattern"]);
  await ops.assertSysctls({ "kernel.core_pattern": TARGET_SYSCTLS["kernel.core_pattern"] });
  await ops.writeSysctl("fs.suid_dumpable", TARGET_SYSCTLS["fs.suid_dumpable"]);
  await ops.writeSysctl("kernel.core_pipe_limit", TARGET_SYSCTLS["kernel.core_pipe_limit"]);
  await ops.assertSysctls(TARGET_SYSCTLS);
  await ops.ensureApportMask(plan.candidate.apport_mask);
  await ops.removeApportEnablement(plan.preimage.apport_enablement_symlinks[0]);
  await ops.reloadManager();
  await ops.assertRuntime("apply-terminal");
  await ops.assertSysctls(TARGET_SYSCTLS);
}

async function bestEffortContainment(plan, ops) {
  const actions = [];
  async function attempt(name, callback) {
    try {
      await callback();
      actions.push({ action: name, result: "ok" });
    } catch (error) {
      actions.push({ action: name, error: error.message, result: "failed" });
    }
  }
  await attempt("ensure-guard", function () {
    return ops.ensureGuard(plan.candidate.guard_unit, plan.candidate.guard_enablement);
  });
  await attempt("install-policy", function () {
    return ops.installPersistent(plan.candidate.persistent_policy);
  });
  await attempt("write-safe-core-pattern", function () {
    return ops.writeSysctl("kernel.core_pattern", TARGET_SYSCTLS["kernel.core_pattern"]);
  });
  await attempt("write-safe-suid-dumpable", function () {
    return ops.writeSysctl("fs.suid_dumpable", TARGET_SYSCTLS["fs.suid_dumpable"]);
  });
  await attempt("write-safe-core-pipe-limit", function () {
    return ops.writeSysctl("kernel.core_pipe_limit", TARGET_SYSCTLS["kernel.core_pipe_limit"]);
  });
  await attempt("ensure-apport-mask", function () {
    return ops.ensureApportMask(plan.candidate.apport_mask);
  });
  await attempt("remove-enablement", function () {
    return ops.removeApportEnablement(plan.preimage.apport_enablement_symlinks[0]);
  });
  await attempt("reload-systemd-manager", function () {
    return ops.reloadManager();
  });
  await attempt("assert-settled-masked-runtime", function () {
    return ops.assertRuntime("apply-terminal");
  });
  let exact = false;
  await attempt("inspect-exact-candidate", async function () {
    assertSnapshot(await ops.inspect(), expectedGuardedCandidate(plan), "contained candidate");
    exact = true;
  });
  return { actions, exact_candidate: exact };
}

async function applyFromPending(plan, context, ops, pending) {
  let phase = "drive-fail-closed";
  try {
    await ensureFailClosedCandidate(plan, ops);
    phase = "final-recheck";
    const after = await ops.inspect();
    assertSnapshot(
      after,
      expectedGuardedCandidate(plan),
      "guarded terminal candidate including /var/crash recheck",
    );
    return await publishTerminalReceipt(plan, context, pending, expectedPreimage(plan), after, ops);
  } catch (cause) {
    if (cause instanceof CeremonyError) throw cause;
    const visible = await ops.readReceipt(plan.transaction.receipt_path).catch(function () {
      return null;
    });
    if (visible !== null) {
      validateCommittedReceipt(visible, plan, context);
      throw new CeremonyError("exact receipt is visible; host post-state is terminal", {
        cause,
        outcome: "receipt-visible-commit-uncertain-lock-retained",
        phase: "receipt-publication",
      });
    }
    const containment = await bestEffortContainment(plan, ops);
    throw new CeremonyError("apply did not commit; fail-closed containment attempted: " + cause.message, {
      cause,
      containment,
      outcome: containment.exact_candidate ? "contained-needs-fresh-recovery-approval" : "outcome-unknown-lock-retained",
      phase,
    });
  }
}

export async function applyCeremony(plan, context, ops) {
  validatePlan(plan);
  assertContextApprovalBoot(context, "applyApprovalActionBootId", "apply approval");
  await ops.verifyHostAndTools(plan, context.actionBootId, false);
  const terminal = await exactExistingReceipt(plan, context, ops);
  if (terminal !== null) return terminal;
  const retainedSubject = await ops.readRecoverySubject();
  if (retainedSubject !== null) {
    throw new CeremonyError("durable transaction state requires a fresh recovery approval", {
      outcome: "recovery-approval-required-lock-retained",
      phase: "preflight",
    });
  }
  const lease = transactionLeaseBase(plan, context, "apply");
  let phase = "acquire-approval-bound-lease";
  try {
    await ops.assertRuntime("fresh-preimage");
    await ops.acquireLock(plan.transaction.lock_path, context, lease);
    assertSnapshot(await ops.inspect(), expectedPreimage(plan), "locked preflight");
    phase = "arm-boot-and-activation-gates-before-intent";
    await ops.ensureGuard(plan.candidate.guard_unit, plan.candidate.guard_enablement);
    await ops.reloadManager();
    await ops.assertRuntime("guarded-preimage");
    assertSnapshot(
      await ops.inspect(),
      expectedGuardedPreimage(plan),
      "guard-armed pre-intent state",
    );
    phase = "publish-approval-bound-preflight-intent";
    await ops.assertRuntime("apply-preflight-pre-publish");
    const preflight = preflightBase(plan, context, lease);
    await ops.createPreflight(preflight);
    phase = "persist-pending-after-preflight";
    const pending = pendingBase(plan, context, preflight);
    await ops.createPending(plan.transaction.pending_path, pending);
    return await applyFromPending(plan, context, ops, pending);
  } catch (cause) {
    if (cause instanceof CeremonyError) throw cause;
    if (await ops.readRecoverySubject() === null) {
      throw new CeremonyError(
        "apply bootstrap stopped before a durable recovery subject was published: " + cause.message,
        {
          cause,
          outcome: "apply-bootstrap-refused-no-recovery-subject",
          phase,
        },
      );
    }
    throw new CeremonyError("apply bootstrap retained its approval-bound recovery subject: " + cause.message, {
      cause,
      outcome: "fresh-recovery-approval-required-lock-retained",
      phase,
    });
  }
}

async function rollbackFromPending(plan, context, ops, pending) {
  let phase = "rollback-guard";
  try {
    await ops.ensureGuard(plan.candidate.guard_unit, plan.candidate.guard_enablement);
    await ops.installPersistent(plan.candidate.persistent_policy);
    await ops.ensureApportMask(plan.candidate.apport_mask);
    await ops.writeSysctl("kernel.core_pattern", TARGET_CORE_PATTERN);
    await ops.writeSysctl("fs.suid_dumpable", "0");
    await ops.writeSysctl("kernel.core_pipe_limit", "0");
    phase = "restore-enablement-without-handler-execution";
    await ops.ensureApportEnablement(plan.preimage.apport_enablement_symlinks[0]);
    phase = "restore-three-sysctls";
    await ops.writeSysctl("kernel.core_pipe_limit", APPORT_SYSCTLS["kernel.core_pipe_limit"]);
    await ops.writeSysctl("fs.suid_dumpable", APPORT_SYSCTLS["fs.suid_dumpable"]);
    await ops.writeSysctl("kernel.core_pattern", APPORT_SYSCTLS["kernel.core_pattern"]);
    await ops.assertSysctls(APPORT_SYSCTLS);
    phase = "remove-policy-then-mask-with-guard-retained";
    await ops.removePersistent(plan.candidate.persistent_policy);
    await ops.removeApportMask(plan.candidate.apport_mask);
    await ops.reloadManager();
    await ops.assertRuntime("rollback-terminal");
    const after = await ops.inspect();
    assertSnapshot(
      after,
      expectedGuardedPreimage(plan),
      "rollback guarded terminal state including /var/crash recheck",
    );
    const receipt = pending.receipt_candidate === null
      ? rollbackReceiptBase(plan, context, pending, after)
      : pending.receipt_candidate;
    if (pending.receipt_candidate === null) {
      pending = nextGeneration(pending, { receipt_candidate: receipt });
      await ops.writePending(plan.transaction.pending_path, pending);
    }
    await ops.assertRuntime("rollback-pre-publish");
    let uncertain = false;
    try {
      await ops.publishReceiptAfterFullInspection(
        plan.transaction.rollback_receipt_path,
        receipt,
        receipt.terminal_commit_state,
        "rollback final full pre-publication inspection",
      );
    } catch (cause) {
      const visible = await ops.readReceipt(plan.transaction.rollback_receipt_path);
      if (visible === null || !same(visible, receipt)) throw cause;
      uncertain = true;
    }
    const base = uncertain ? "rollback-receipt-visible-commit-uncertain" : receipt.outcome;
    try {
      await ops.finalizeTerminal(
        plan.transaction.lock_path,
        plan.transaction.pending_path,
        receipt,
        context,
      );
    } catch (cause) {
      throw new CeremonyError("rollback receipt is terminal but deterministic cleanup failed: " + cause.message, {
        cause,
        outcome: base + "-cleanup-retained",
        phase: "terminal-state-cleanup",
      });
    }
    return {
      outcome: base,
      receipt,
      receipt_sha256: sha256(Buffer.from(canonicalJson(receipt), "utf8")),
    };
  } catch (cause) {
    if (cause instanceof CeremonyError) throw cause;
    const visible = await ops.readReceipt(plan.transaction.rollback_receipt_path).catch(function () {
      return null;
    });
    if (visible !== null) {
      throw new CeremonyError("exact rollback receipt is visible; rollback is terminal", {
        cause,
        outcome: "rollback-receipt-visible-commit-uncertain-lock-retained",
        phase: "rollback-receipt-publication",
      });
    }
    const containment = await bestEffortContainment(plan, ops);
    throw new CeremonyError("rollback incomplete; fail-closed candidate restored: " + cause.message, {
      cause,
      containment,
      outcome: containment.exact_candidate ? "rollback-contained-needs-fresh-recovery-approval" : "outcome-unknown-lock-retained",
      phase,
    });
  }
}

async function reestablishVisibleRollbackPostState(plan, ops) {
  const preflight = await ops.readPreflight();
  await ops.ensureGuard(plan.candidate.guard_unit, plan.candidate.guard_enablement);
  await ops.reloadManager();
  await ops.assertRuntime("rollback-terminal");
  const current = await ops.inspect();
  if (same(current, expectedGuardedPreimage(plan))) return;
  if (preflight === null) {
    fail("visible rollback receipt drifted after its preflight intent was cleared");
  }
  await ops.installPersistent(plan.candidate.persistent_policy);
  await ops.ensureApportMask(plan.candidate.apport_mask);
  await ops.writeSysctl("kernel.core_pattern", TARGET_CORE_PATTERN);
  await ops.writeSysctl("fs.suid_dumpable", "0");
  await ops.writeSysctl("kernel.core_pipe_limit", "0");
  await ops.ensureApportEnablement(plan.preimage.apport_enablement_symlinks[0]);
  await ops.writeSysctl("kernel.core_pipe_limit", APPORT_SYSCTLS["kernel.core_pipe_limit"]);
  await ops.writeSysctl("fs.suid_dumpable", APPORT_SYSCTLS["fs.suid_dumpable"]);
  await ops.writeSysctl("kernel.core_pattern", APPORT_SYSCTLS["kernel.core_pattern"]);
  await ops.assertSysctls(APPORT_SYSCTLS);
  await ops.removePersistent(plan.candidate.persistent_policy);
  await ops.removeApportMask(plan.candidate.apport_mask);
  await ops.reloadManager();
  await ops.assertRuntime("rollback-terminal");
  assertSnapshot(
    await ops.inspect(),
    expectedGuardedPreimage(plan),
    "re-established visible rollback receipt post-state",
  );
}

export async function rollbackCeremony(plan, context, ops) {
  validatePlan(plan);
  assertContextApprovalBoot(context, "rollbackApprovalActionBootId", "rollback approval");
  await ops.verifyHostAndTools(plan, context.actionBootId, true);
  const existingRollback = await ops.readReceipt(plan.transaction.rollback_receipt_path);
  if (existingRollback !== null) {
    await bindCommittedReceiptLineage(plan, context, ops);
    validateRollbackReceipt(existingRollback, plan, context);
    if (await ops.readRecoverySubject() !== null) {
      throw new CeremonyError("rollback receipt is visible but retained state requires fresh recovery approval", {
        outcome: "recovery-approval-required-lock-retained",
        phase: "rollback-terminal-cleanup",
      });
    }
    assertSnapshot(await ops.inspect(), existingRollback.post_state, "already-clean rollback post-state");
    return {
      outcome: "already-rolled-back",
      receipt: existingRollback,
      receipt_sha256: sha256(Buffer.from(canonicalJson(existingRollback), "utf8")),
    };
  }
  const retainedSubject = await ops.readRecoverySubject();
  if (retainedSubject !== null) {
    throw new CeremonyError("durable rollback state requires a fresh recovery approval", {
      outcome: "recovery-approval-required-lock-retained",
      phase: "rollback-preflight",
    });
  }
  await bindCommittedReceiptLineage(plan, context, ops);
  await ops.assertRuntime("fresh-candidate");
  const lease = transactionLeaseBase(plan, context, "rollback");
  try {
    await ops.acquireLock(plan.transaction.lock_path, context, lease);
    assertSnapshot(await ops.inspect(), expectedCandidate(plan), "rollback preflight");
    await ops.ensureGuard(plan.candidate.guard_unit, plan.candidate.guard_enablement);
    await ops.reloadManager();
    await ops.assertRuntime("guarded-candidate");
    assertSnapshot(
      await ops.inspect(),
      expectedGuardedCandidate(plan),
      "rollback guard-armed pre-intent state",
    );
    await ops.assertRuntime("rollback-preflight-pre-publish");
    const preflight = preflightBase(plan, context, lease);
    await ops.createPreflight(preflight);
    const pending = pendingBase(plan, context, preflight);
    await ops.createPending(plan.transaction.pending_path, pending);
    return rollbackFromPending(plan, context, ops, pending);
  } catch (cause) {
    if (cause instanceof CeremonyError) throw cause;
    if (await ops.readRecoverySubject() === null) {
      throw new CeremonyError(
        "rollback bootstrap stopped before a durable recovery subject was published: " + cause.message,
        {
          cause,
          outcome: "rollback-bootstrap-refused-no-recovery-subject",
          phase: "rollback-bootstrap",
        },
      );
    }
    throw new CeremonyError("rollback bootstrap retained its approval-bound recovery subject: " + cause.message, {
      cause,
      outcome: "rollback-fresh-recovery-approval-required-lock-retained",
      phase: "rollback-bootstrap",
    });
  }
}

export async function recoverCeremony(plan, context, ops) {
  validatePlan(plan);
  assertContextApprovalBoot(context, "recoveryApprovalActionBootId", "recovery approval");
  await ops.verifyHostAndTools(plan, context.actionBootId, true);
  const subject = await ops.readRecoverySubject();
  if (subject === null) {
    const rollbackReceipt = await ops.readReceipt(plan.transaction.rollback_receipt_path);
    if (rollbackReceipt !== null) {
      await bindCommittedReceiptLineage(plan, context, ops);
      validateRollbackReceipt(rollbackReceipt, plan, context);
      assertSnapshot(await ops.inspect(), rollbackReceipt.post_state, "clean rollback terminal state");
      return {
        outcome: "already-rolled-back",
        receipt: rollbackReceipt,
        receipt_sha256: sha256(Buffer.from(canonicalJson(rollbackReceipt), "utf8")),
      };
    }
    const committed = await ops.readReceipt(plan.transaction.receipt_path);
    if (committed !== null) {
      validateCommittedReceipt(committed, plan, context);
      assertSnapshot(await ops.inspect(), committed.post_state, "clean apply terminal state");
      return {
        outcome: "already-committed",
        receipt: committed,
        receipt_sha256: sha256(Buffer.from(canonicalJson(committed), "utf8")),
      };
    }
    throw new CeremonyError("durable recovery subject is missing", {
      outcome: "recovery-refused-no-subject",
      phase: "recovery-preflight",
    });
  }
  const subjectDigest = sha256(Buffer.from(canonicalJson(subject.value), "utf8"));
  if (context.recoverySubjectKind !== subject.kind ||
      context.recoveryApprovedSubjectSha256 !== subjectDigest) {
    fail("recovery approval does not bind the exact durable recovery subject generation");
  }
  validateSha(context.recoveryApprovalSha256, "actual recovery approval SHA-256");
  const lease = await ops.readLease();
  validateLease(lease, plan, context, "durable transaction lease");
  if (lease.mode !== subject.value.mode ||
      lease.original_approval_sha256 !== subject.value.original_approval_sha256) {
    fail("recovery subject differs from the approval-bound transaction lease");
  }
  await ops.recoverLock(plan.transaction.lock_path, context, lease);

  const rollbackReceipt = await ops.readReceipt(plan.transaction.rollback_receipt_path);
  if (rollbackReceipt !== null) {
    await bindCommittedReceiptLineage(plan, context, ops);
    validateRollbackReceipt(rollbackReceipt, plan, context);
    await reestablishVisibleRollbackPostState(plan, ops);
    await ops.finalizeTerminal(
      plan.transaction.lock_path,
      plan.transaction.pending_path,
      rollbackReceipt,
      context,
    );
    return {
      outcome: "already-rolled-back",
      receipt: rollbackReceipt,
      receipt_sha256: sha256(Buffer.from(canonicalJson(rollbackReceipt), "utf8")),
    };
  }
  const committed = await ops.readReceipt(plan.transaction.receipt_path);
  if (committed !== null && lease.mode === "apply") {
    validateCommittedReceipt(committed, plan, context);
    await ops.finalizeTerminal(
      plan.transaction.lock_path,
      plan.transaction.pending_path,
      committed,
      context,
    );
    return {
      outcome: "already-committed",
      receipt: committed,
      receipt_sha256: sha256(Buffer.from(canonicalJson(committed), "utf8")),
    };
  }
  if (lease.mode === "rollback") await bindCommittedReceiptLineage(plan, context, ops);

  let preflight = await ops.readPreflight();
  let pending = await ops.readPending(plan.transaction.pending_path);
  if (subject.kind === "lease") {
    if (preflight !== null || pending !== null) fail("lease recovery subject is not the newest durable state");
    await ops.ensureGuard(plan.candidate.guard_unit, plan.candidate.guard_enablement);
    await ops.reloadManager();
    await ops.assertRuntime(lease.mode === "apply" ? "guarded-preimage" : "guarded-candidate");
    preflight = preflightBase(plan, context, lease, [context.recoveryApprovalSha256]);
    await ops.createPreflight(preflight);
  } else if (subject.kind === "preflight") {
    validatePreflight(preflight, plan, context, "durable preflight intent");
    if (!same(preflight, subject.value) || pending !== null) {
      fail("preflight recovery subject is not the newest durable state");
    }
    if (preflight.recovery_approval_sha256s.includes(context.recoveryApprovalSha256)) {
      fail("recovery approval digest is already present in the authorization chain");
    }
    preflight = nextGeneration(preflight, {
      action_boot_id: context.actionBootId,
      recovery_approval_sha256s: preflight.recovery_approval_sha256s.concat([
        context.recoveryApprovalSha256,
      ]),
    });
    await ops.writePreflight(preflight);
    await ops.ensureGuard(plan.candidate.guard_unit, plan.candidate.guard_enablement);
    await ops.reloadManager();
    await ops.assertRuntime(lease.mode === "apply" ? "guarded-preimage" : "guarded-candidate");
  } else if (subject.kind === "pending") {
    validatePendingBase(pending, plan, context, "durable pending state");
    if (!same(pending, subject.value) || preflight === null ||
        pending.preflight_sha256 !== sha256(Buffer.from(canonicalJson(preflight), "utf8"))) {
      fail("pending recovery subject lost its exact preflight lineage");
    }
    if (pending.receipt_candidate !== null) {
      if (pending.mode === "apply") {
        validateCommittedReceipt(pending.receipt_candidate, plan, context);
        if (pending.receipt_candidate.apply_approval_sha256 !== pending.original_approval_sha256 ||
            pending.receipt_candidate.committed_at_utc !== pending.started_at_utc) {
          fail("apply receipt candidate lost its original approval/time lineage");
        }
      } else {
        validateRollbackReceipt(pending.receipt_candidate, plan, context);
        if (pending.receipt_candidate.rollback_approval_sha256 !== pending.original_approval_sha256 ||
            pending.receipt_candidate.completed_at_utc !== pending.started_at_utc) {
          fail("rollback receipt candidate lost its original approval/time lineage");
        }
      }
      if (pending.receipt_candidate.preflight_sha256 !== pending.preflight_sha256 ||
          !same(pending.receipt_candidate.recovery_approval_sha256s,
            pending.recovery_approval_sha256s)) {
        fail("pending receipt candidate lost its preflight/recovery lineage");
      }
    }
    if (pending.recovery_approval_sha256s.includes(context.recoveryApprovalSha256)) {
      fail("recovery approval digest is already present in the authorization chain");
    }
    pending = nextGeneration(pending, {
      action_boot_id: context.actionBootId,
      receipt_candidate: null,
      recovery_approval_sha256s: pending.recovery_approval_sha256s.concat([
        context.recoveryApprovalSha256,
      ]),
    });
    await ops.writePending(plan.transaction.pending_path, pending);
  } else {
    fail("durable recovery subject kind is not reviewed");
  }

  if (pending === null) {
    pending = pendingBase(plan, context, preflight);
    await ops.createPending(plan.transaction.pending_path, pending);
  }
  if (lease.mode === "apply") return applyFromPending(plan, context, ops, pending);
  return rollbackFromPending(plan, context, ops, pending);
}

// Backward-compatible export name for downstream test runners; semantics are v2.
export const recoverCommittedCandidate = recoverCeremony;

function modeText(stat) {
  const mode = typeof stat.mode === "bigint"
    ? Number(stat.mode & 0o7777n)
    : stat.mode & 0o7777;
  return "0" + mode.toString(8).padStart(3, "0");
}

function stablePin(path, bytes, stat) {
  return {
    gid: Number(stat.gid),
    mode: modeText(stat),
    nlink: Number(stat.nlink),
    path,
    sha256: sha256(bytes),
    size: bytes.length,
    uid: Number(stat.uid),
  };
}

function openBoundRegular(path, label, maxBytes, allowedLinks) {
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC);
    const before = fstatSync(fd, { bigint: true });
    const links = (allowedLinks === undefined ? [1] : allowedLinks).map(BigInt);
    if (!before.isFile() || !links.includes(before.nlink) ||
        before.size > BigInt(maxBytes || MAX_FILE_BYTES) ||
        before.uid > BigInt(Number.MAX_SAFE_INTEGER) ||
        before.gid > BigInt(Number.MAX_SAFE_INTEGER) ||
        before.nlink > BigInt(Number.MAX_SAFE_INTEGER)) {
      fail(label + " is not a bounded one-link regular file");
    }
    const bytes = readFileSync(fd);
    const after = fstatSync(fd, { bigint: true });
    const pathAfter = lstatSync(path, { bigint: true });
    if (before.dev !== after.dev || before.ino !== after.ino ||
        before.dev !== pathAfter.dev || before.ino !== pathAfter.ino ||
        before.size !== BigInt(bytes.length) || before.mtimeNs !== after.mtimeNs ||
        before.ctimeNs !== after.ctimeNs) {
      fail(label + " changed during descriptor-bound read");
    }
    return {
      bytes,
      identity: { dev: before.dev.toString(), ino: before.ino.toString() },
      pin: stablePin(path, bytes, before),
    };
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function optionalExactJson(path, owner) {
  const expected = owner || { gid: 0, uid: 0 };
  try {
    const opened = openBoundRegular(path, "JSON " + path, MAX_JSON_BYTES);
    if (opened.pin.uid !== expected.uid || opened.pin.gid !== expected.gid ||
        opened.pin.mode !== "0600") {
      fail(path + " is not exact owner-bound 0600 state");
    }
    return parseCanonicalOpenedJson(opened, path);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

function parseCanonicalOpenedJson(opened, path) {
  return parseCanonicalJsonBytes(opened.bytes, path);
}

export function parseCanonicalJsonBytes(bytes, label) {
  if (!Buffer.isBuffer(bytes) || bytes.length > MAX_JSON_BYTES) {
    fail(label + " is not bounded canonical JSON bytes");
  }
  let parsed;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    fail(label + " is not JSON: " + error.message);
  }
  if (!bytes.equals(Buffer.from(canonicalJson(parsed), "utf8"))) {
    fail(label + " is not canonical JSON");
  }
  return parsed;
}

export function peekPublishedJson(path, tempPath, owner) {
  const expected = owner || { gid: 0, uid: 0 };
  let opened;
  try {
    opened = openBoundRegular(path, "published JSON " + path, MAX_JSON_BYTES, [1, 2]);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
  const parsed = parseCanonicalOpenedJson(opened, path);
  if (opened.pin.uid !== expected.uid || opened.pin.gid !== expected.gid ||
      opened.pin.mode !== "0600") {
    fail(path + " is not exact owner-bound 0600 published state");
  }
  if (opened.pin.nlink === 2) {
    const prepared = openBoundRegular(tempPath, "linked JSON temp " + tempPath, MAX_JSON_BYTES, [2]);
    if (opened.identity.dev !== prepared.identity.dev || opened.identity.ino !== prepared.identity.ino ||
        !opened.bytes.equals(prepared.bytes)) {
      fail("published JSON target/temp are not the same linked inode");
    }
  } else {
    try {
      lstatSync(tempPath);
      fail("published JSON has a detached prepared generation");
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
  return parsed;
}

function normalizePublishedJson(path, tempPath, owner) {
  const parsed = peekPublishedJson(path, tempPath, owner);
  if (parsed === null) return null;
  const opened = openBoundRegular(path, "published JSON normalization", MAX_JSON_BYTES, [1, 2]);
  if (opened.pin.nlink === 2) {
    unlinkSync(tempPath);
    fsyncDirectory(dirname(tempPath));
    const finalized = openBoundRegular(path, "finalized published JSON " + path, MAX_JSON_BYTES);
    if (!finalized.bytes.equals(opened.bytes)) fail("published JSON changed during finalization");
  }
  return parsed;
}

function normalizePreparedJsonPublication(path, tempPath) {
  let parsed = normalizePublishedJson(path, tempPath);
  if (parsed !== null) return parsed;
  const quarantine = optionalExactJson(path + ".terminal-quarantine");
  const prepared = optionalExactJson(tempPath);
  if (quarantine !== null && prepared !== null) {
    fail("prepared JSON and terminal quarantine coexist: " + path);
  }
  if (quarantine !== null || prepared === null) return null;
  atomicCreatePinnedForTest(atomicJsonPin(path, prepared), { tempPath });
  parsed = normalizePublishedJson(path, tempPath);
  if (parsed === null || !same(parsed, prepared)) {
    fail("prepared JSON publication did not become exact visible state: " + path);
  }
  return parsed;
}

function readRetainedAdjacentGeneration(path, current, label) {
  const live = optionalExactJson(path);
  const quarantined = optionalExactJson(path + ".terminal-quarantine");
  if (live !== null && quarantined !== null) {
    fail(label + " and its terminal quarantine coexist");
  }
  const retained = live || quarantined;
  if (retained === null) return null;
  if (current === null) fail(label + " exists without its published generation");
  classifyRetainedGeneration(current, retained);
  return retained;
}

function removeRetainedAdjacentGeneration(path, current, label) {
  const retained = readRetainedAdjacentGeneration(path, current, label);
  if (retained === null) return;
  removeExactJsonByQuarantine(path, retained);
}

function assertRootDirectory(path, mode) {
  const stat = lstatSync(path, { bigint: false });
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== 0 || stat.gid !== 0 ||
      (mode !== undefined && modeText(stat) !== mode) ||
      (stat.mode & 0o022) !== 0) {
    fail("directory is not exact root-owned non-writable state: " + path);
  }
}

function fsyncDirectory(path) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | constants.O_CLOEXEC);
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function ensureDirectory(path, mode) {
  try {
    mkdirSync(path, { mode });
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
  }
  const stat = lstatSync(path, { bigint: false });
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== 0 || stat.gid !== 0 ||
      modeText(stat) !== "0" + mode.toString(8).padStart(3, "0")) {
    fail("state directory metadata mismatch: " + path);
  }
  fsyncDirectory(dirname(path));
}

function ensureApportGateDirectory() {
  try {
    mkdirSync(APPORT_GATE_DIRECTORY, { mode: 0o700 });
    fsyncDirectory(dirname(APPORT_GATE_DIRECTORY));
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
  }
  const entries = readdirSync(APPORT_GATE_DIRECTORY).sort();
  const allowed = new Set([
    basename(APPORT_GATE_PATH),
    basename(APPORT_GATE_PATH + ".pending"),
    basename(APPORT_GATE_PATH + ".bitcoinpir-quarantine"),
  ]);
  if (entries.some(function (entry) { return !allowed.has(entry); })) {
    fail("Apport activation gate directory contains an unreviewed entry");
  }
  const stat = lstatSync(APPORT_GATE_DIRECTORY, { bigint: false });
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== 0 || stat.gid !== 0 ||
      !["0700", "0755"].includes(modeText(stat))) {
    fail("Apport activation gate directory is outside the recoverable generation");
  }
  chownSync(APPORT_GATE_DIRECTORY, 0, 0);
  chmodSync(APPORT_GATE_DIRECTORY, 0o755);
  fsyncDirectory(APPORT_GATE_DIRECTORY);
  fsyncDirectory(dirname(APPORT_GATE_DIRECTORY));
  assertRootDirectory(APPORT_GATE_DIRECTORY, "0755");
}

function removeApportGateDirectory() {
  try {
    const entries = readdirSync(APPORT_GATE_DIRECTORY);
    if (entries.length !== 0) fail("Apport activation gate directory is not empty at cleanup");
    rmdirSync(APPORT_GATE_DIRECTORY);
    fsyncDirectory(dirname(APPORT_GATE_DIRECTORY));
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    fsyncDirectory(dirname(APPORT_GATE_DIRECTORY));
  }
}

function ensureSysctlGateDirectory() {
  try {
    mkdirSync(SYSCTL_GATE_DIRECTORY, { mode: 0o700 });
    fsyncDirectory(dirname(SYSCTL_GATE_DIRECTORY));
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
  }
  const entries = readdirSync(SYSCTL_GATE_DIRECTORY).sort();
  const allowed = new Set([
    basename(SYSCTL_CREDENTIAL_CLOSURE_PATH),
    basename(SYSCTL_CREDENTIAL_CLOSURE_PATH + ".pending"),
    basename(SYSCTL_CREDENTIAL_CLOSURE_PATH + ".bitcoinpir-quarantine"),
    basename(SYSCTL_GATE_PATH),
    basename(SYSCTL_GATE_PATH + ".pending"),
    basename(SYSCTL_GATE_PATH + ".bitcoinpir-quarantine"),
  ]);
  if (entries.some(function (entry) { return !allowed.has(entry); })) {
    fail("systemd-sysctl gate directory contains an unreviewed entry");
  }
  const stat = lstatSync(SYSCTL_GATE_DIRECTORY, { bigint: false });
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== 0 || stat.gid !== 0 ||
      !["0700", "0755"].includes(modeText(stat))) {
    fail("systemd-sysctl gate directory is outside the recoverable generation");
  }
  chownSync(SYSCTL_GATE_DIRECTORY, 0, 0);
  chmodSync(SYSCTL_GATE_DIRECTORY, 0o755);
  fsyncDirectory(SYSCTL_GATE_DIRECTORY);
  fsyncDirectory(dirname(SYSCTL_GATE_DIRECTORY));
  assertRootDirectory(SYSCTL_GATE_DIRECTORY, "0755");
}

function removeSysctlGateDirectory() {
  try {
    const entries = readdirSync(SYSCTL_GATE_DIRECTORY);
    if (same(entries.sort(), [basename(SYSCTL_CREDENTIAL_CLOSURE_PATH)])) {
      assertRootDirectory(SYSCTL_GATE_DIRECTORY, "0755");
      return;
    }
    if (entries.length !== 0) fail("systemd-sysctl gate directory is not empty at cleanup");
    rmdirSync(SYSCTL_GATE_DIRECTORY);
    fsyncDirectory(dirname(SYSCTL_GATE_DIRECTORY));
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    fsyncDirectory(dirname(SYSCTL_GATE_DIRECTORY));
  }
}

function ensureStateParents(plan) {
  assertRootDirectory("/var");
  assertRootDirectory("/var/lib");
  ensureDirectory("/var/lib/bitcoinpir", 0o700);
  ensureDirectory("/var/lib/bitcoinpir/payment-v1", 0o700);
  ensureDirectory("/var/lib/bitcoinpir/payment-v1/core-pattern", 0o700);
  ensureDirectory("/var/lib/bitcoinpir/payment-v1/core-pattern/locks", 0o700);
  ensureDirectory("/var/lib/bitcoinpir/payment-v1/core-pattern/receipts", 0o700);
  ensureDirectory(dirname(plan.transaction.pending_path), 0o700);
}

function prepareFixed(pin, tempPath) {
  const bytes = Buffer.from(pin.bytes_base64, "base64");
  try {
    const existing = openBoundRegular(tempPath, "fixed prepared file");
    if (!existing.bytes.equals(bytes) ||
        existing.pin.uid !== pin.uid || existing.pin.gid !== pin.gid ||
        existing.pin.mode !== pin.mode) {
      fail("fixed transaction temp contains unknown bytes: " + tempPath);
    }
    return existing;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  let fd;
  try {
    fd = openSync(
      tempPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL |
        constants.O_NOFOLLOW | constants.O_CLOEXEC,
      0o600,
    );
    writeFileSync(fd, bytes);
    fchownSync(fd, pin.uid, pin.gid);
    fchmodSync(fd, Number.parseInt(pin.mode, 8));
    fsyncSync(fd);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
  fsyncDirectory(dirname(tempPath));
  return openBoundRegular(tempPath, "prepared fixed file");
}

function exactPin(opened, pin, label) {
  if (!same(opened.pin, withoutBytes(pin))) fail(label + " differs from exact pin");
}

export function atomicCreatePinnedForTest(pin, options) {
  const config = options || {};
  const tempPath = config.tempPath || pin.path + ".pending";
  function finishLinkedPublication(label) {
    const visible = openBoundRegular(pin.path, label, undefined, [1, 2]);
    if (visible.pin.nlink === 1) {
      exactPin(visible, pin, label);
      try {
        lstatSync(tempPath);
        fail(label + " has a detached prepared generation");
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
      return;
    }
    const prepared = openBoundRegular(tempPath, label + " temp", undefined, [2]);
    if (visible.identity.dev !== prepared.identity.dev || visible.identity.ino !== prepared.identity.ino) {
      fail(label + " target/temp are not the same linked inode");
    }
    const expectedLinked = { ...withoutBytes(pin), nlink: 2 };
    if (!same(visible.pin, expectedLinked)) fail(label + " linked target differs from exact bytes");
    unlinkSync(tempPath);
    fsyncDirectory(dirname(tempPath));
    exactPin(openBoundRegular(pin.path, label + " finalized"), pin, label + " finalized");
  }
  try {
    const existing = openBoundRegular(pin.path, "existing exact publication", undefined, [1, 2]);
    if (existing.pin.nlink === 2) finishLinkedPublication("existing commit-uncertain publication");
    else exactPin(existing, pin, "existing exact publication");
    return { status: existing.pin.nlink === 2 ? "visible-commit-uncertain" : "already-visible" };
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const prepared = prepareFixed(pin, tempPath);
  exactPin(prepared, { ...pin, path: tempPath }, "prepared publication");
  try {
    linkSync(tempPath, pin.path);
    if (config.faultAfterLink) throw new Error("injected fault after link");
    fsyncDirectory(dirname(pin.path));
    if (config.faultAfterFsync) throw new Error("injected fault after directory fsync");
    finishLinkedPublication("visible publication");
    if (config.faultAfterVerify) throw new Error("injected fault after verify");
    return { status: "published" };
  } catch (cause) {
    let visible = false;
    try {
      finishLinkedPublication("commit-uncertain publication");
      visible = true;
    } catch (readCause) {
      if (readCause.code !== "ENOENT") throw readCause;
    }
    if (visible) {
      return { cause, status: "visible-commit-uncertain" };
    }
    throw cause;
  }
}

function pathExistsNoFollow(path) {
  try {
    lstatSync(path);
    return true;
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

function normalizeAtomicPublicationIfPresent(pin, tempPath) {
  if (!pathExistsNoFollow(pin.path) && !pathExistsNoFollow(tempPath)) return;
  atomicCreatePinnedForTest(pin, { tempPath });
}

function invokeExchange(plan, action, left, right) {
  const helperPin = plan.executor.exchange_helper;
  const helper = openBoundRegular(helperPin.path, "rename-exchange helper");
  exactPin(helper, helperPin, "rename-exchange helper");
  const fd = openSync(helperPin.path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC);
  let result;
  try {
    result = spawnSync("/proc/self/fd/3", [
      action,
      String(process.pid),
      processStartTicks(process.pid),
      left,
      right,
    ], {
      cwd: "/",
      encoding: "utf8",
      env: { LANG: "C", LC_ALL: "C", PATH: "/usr/sbin:/usr/bin" },
      shell: false,
      stdio: ["ignore", "pipe", "pipe", fd],
      timeout: 10_000,
    });
  } finally {
    closeSync(fd);
  }
  if (result.status !== 0 || result.signal !== null || result.error !== undefined) {
    fail("rename-exchange helper failed: " + (result.error?.message || result.stderr || result.signal));
  }
}

function processStartTicks(pid) {
  const text = readFileSync("/proc/" + pid + "/stat", "utf8");
  const close = text.lastIndexOf(")");
  if (close < 0) fail("process stat is malformed");
  return text.slice(close + 2).split(" ")[19];
}

function verifyInheritedMaintenanceLocks() {
  const paths = [
    "/var/lib/dpkg/lock-frontend",
    "/var/lib/dpkg/lock",
    "/var/lib/apt/lists/lock",
    "/var/cache/apt/archives/lock",
  ];
  const text = process.env.BITCOINPIR_CORE_PATTERN_MAINTENANCE_LOCK_FDS;
  if (typeof text !== "string" || !/^[1-9][0-9]*(?:,[1-9][0-9]*){3}$/u.test(text)) {
    fail("ceremony must be execed by the pinned fcntl maintenance-lock helper");
  }
  const fds = text.split(",").map(Number);
  if (new Set(fds).size !== paths.length) fail("maintenance lock descriptors must be distinct");
  const procLocks = readFileSync("/proc/locks", "utf8").split("\n");
  for (let index = 0; index < paths.length; index += 1) {
    const fdStat = fstatSync(fds[index], { bigint: true });
    const pathStat = statSync(paths[index], { bigint: true });
    if (!fdStat.isFile() || fdStat.dev !== pathStat.dev || fdStat.ino !== pathStat.ino) {
      fail("inherited package maintenance lock descriptor raced: " + paths[index]);
    }
    const held = procLocks.some(function (line) {
      return line.includes(" POSIX ") && line.includes(" WRITE ") &&
        line.includes(" " + process.pid + " ") &&
        line.includes(":" + fdStat.ino.toString() + " ");
    });
    if (!held) fail("exclusive fcntl maintenance lock is not held: " + paths[index]);
  }
}

function replaceByExchange(plan, pin, approvedPins, tempPath) {
  const bytes = Buffer.from(pin.bytes_base64, "base64");
  try {
    const current = openBoundRegular(pin.path, "replacement current");
    if (current.bytes.equals(bytes) && same(current.pin, withoutBytes(pin))) {
      try {
        const retained = openBoundRegular(tempPath, "retained exchanged preimage");
        if (!approvedPins.some(function (approved) {
          return same(retained.pin, { ...withoutBytes(approved), path: tempPath });
        })) fail("retained exchanged preimage is not an approved generation");
        unlinkSync(tempPath);
        fsyncDirectory(dirname(tempPath));
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
      return;
    }
    if (!approvedPins.some(function (approved) {
      return same(current.pin, withoutBytes(approved));
    })) fail("replacement current is not an approved generation");
  } catch (error) {
    if (error.code === "ENOENT") {
      atomicCreatePinnedForTest(pin, { tempPath });
      return;
    }
    throw error;
  }
  prepareFixed({ ...pin, path: tempPath }, tempPath);
  invokeExchange(plan, "--exchange", pin.path, tempPath);
  let swapped;
  try {
    swapped = openBoundRegular(tempPath, "swapped-out approved generation");
    if (!approvedPins.some(function (approved) {
      return same(swapped.pin, { ...withoutBytes(approved), path: tempPath });
    })) fail("concurrent mutation was exchanged out");
  } catch (cause) {
    invokeExchange(plan, "--exchange", pin.path, tempPath);
    const restored = openBoundRegular(pin.path, "atomically restored raced generation");
    if (restored.identity.dev !== swapped?.identity.dev || restored.identity.ino !== swapped?.identity.ino) {
      fail("failed to restore the raced root-owned generation atomically");
    }
    throw cause;
  }
  fsyncDirectory(dirname(pin.path));
  const visible = openBoundRegular(pin.path, "replacement candidate");
  exactPin(visible, pin, "replacement candidate");
  const retained = openBoundRegular(tempPath, "verified exchanged preimage cleanup");
  if (retained.identity.dev !== swapped.identity.dev || retained.identity.ino !== swapped.identity.ino) {
    fail("exchanged preimage changed before fixed-temp cleanup");
  }
  unlinkSync(tempPath);
  fsyncDirectory(dirname(tempPath));
}

function ensurePinnedWithQuarantine(pin, tempPath, quarantinePath, options) {
  const config = options || {};
  function boundary(name) {
    if (typeof config.afterBoundary === "function") config.afterBoundary(name);
  }
  function publish(left, right) {
    if (typeof config.publish === "function") config.publish(left, right);
    else if (config.plan !== undefined) invokeExchange(config.plan, "--publish", left, right);
    else renameSync(left, right);
  }
  function removeCoexistingQuarantine() {
    exactPin(openBoundRegular(pin.path, "live ensure generation"), pin, "live ensure generation");
    exactPin(
      openBoundRegular(quarantinePath, "retained ensure quarantine recheck"),
      { ...pin, path: quarantinePath },
      "retained ensure quarantine recheck",
    );
    unlinkSync(quarantinePath);
    boundary("ensure-file-unlink-quarantine");
    fsyncDirectory(dirname(quarantinePath));
    boundary("ensure-file-fsync-quarantine-unlink");
  }
  if (pathExistsNoFollow(pin.path) || pathExistsNoFollow(tempPath)) {
    atomicCreatePinnedForTest(pin, { tempPath });
  }
  let quarantined;
  try {
    quarantined = openBoundRegular(quarantinePath, "retained ensure quarantine");
    exactPin(quarantined, { ...pin, path: quarantinePath }, "retained ensure quarantine");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  if (quarantined !== undefined) {
    try {
      removeCoexistingQuarantine();
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      try {
        publish(quarantinePath, pin.path);
      } catch (cause) {
        try {
          removeCoexistingQuarantine();
          return atomicCreatePinnedForTest(pin, { tempPath });
        } catch (classificationError) {
          if (classificationError.code === "ENOENT") throw cause;
          throw classificationError;
        }
      }
      boundary("ensure-file-rename-quarantine-to-live");
      fsyncDirectory(dirname(pin.path));
      boundary("ensure-file-fsync-quarantine-rename");
      exactPin(openBoundRegular(pin.path, "restored ensure generation"), pin, "restored ensure generation");
      boundary("ensure-file-verify-restored");
    }
  }
  return atomicCreatePinnedForTest(pin, { tempPath });
}

export function ensurePinnedWithQuarantineForTest(pin, tempPath, quarantinePath, options) {
  return ensurePinnedWithQuarantine(pin, tempPath, quarantinePath, options);
}

function removeByQuarantine(plan, pin, quarantinePath, options) {
  const config = options || {};
  function boundary(name) {
    if (typeof config.afterBoundary === "function") config.afterBoundary(name);
  }
  function publish(left, right) {
    if (typeof config.publish === "function") config.publish(left, right);
    else invokeExchange(plan, "--publish", left, right);
  }
  try {
    const retained = openBoundRegular(quarantinePath, "retained removal quarantine");
    if (!same(retained.pin, { ...withoutBytes(pin), path: quarantinePath })) {
      fail("retained removal quarantine is not the exact approved generation");
    }
    try {
      const live = openBoundRegular(pin.path, "coexisting live removal generation");
      exactPin(live, pin, "coexisting live removal generation");
      unlinkSync(pin.path);
      boundary("remove-file-replay-unlink-live");
      fsyncDirectory(dirname(pin.path));
      boundary("remove-file-replay-fsync-live");
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    exactPin(
      openBoundRegular(quarantinePath, "retained removal quarantine recheck"),
      { ...pin, path: quarantinePath },
      "retained removal quarantine recheck",
    );
    unlinkSync(quarantinePath);
    boundary("remove-file-replay-unlink-quarantine");
    fsyncDirectory(dirname(quarantinePath));
    boundary("remove-file-replay-fsync-quarantine");
    return;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  let current;
  try {
    current = openBoundRegular(pin.path, "removal current");
    exactPin(current, pin, "removal current");
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw error;
  }
  try {
    lstatSync(quarantinePath);
    fail("fixed quarantine already exists");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  publish(pin.path, quarantinePath);
  boundary("remove-file-publish-quarantine");
  let quarantined;
  try {
    quarantined = openBoundRegular(quarantinePath, "quarantined removal");
    if (quarantined.identity.dev !== current.identity.dev ||
        quarantined.identity.ino !== current.identity.ino ||
        !same(quarantined.pin, { ...withoutBytes(pin), path: quarantinePath })) {
      fail("removal target raced before quarantine");
    }
  } catch (cause) {
    publish(quarantinePath, pin.path);
    throw cause;
  }
  fsyncDirectory(dirname(pin.path));
  boundary("remove-file-fsync-publish");
  unlinkSync(quarantinePath);
  boundary("remove-file-unlink-quarantine");
  fsyncDirectory(dirname(quarantinePath));
  boundary("remove-file-fsync-quarantine-unlink");
}

export function removePinnedByQuarantineForTest(pin, quarantinePath, options) {
  return removeByQuarantine(null, pin, quarantinePath, options);
}

function readSysctl(name) {
  const path = SYSCTL_PATHS[name];
  if (path === undefined) fail("unreviewed sysctl " + name);
  const value = readFileSync(path, "utf8");
  if (!value.endsWith("\n") || value.slice(0, -1).includes("\n")) fail(path + " is malformed");
  return value.slice(0, -1);
}

function writeSysctl(name, value) {
  const allowed = [TARGET_SYSCTLS[name], APPORT_SYSCTLS[name]];
  if (!allowed.includes(value)) fail("refusing unreviewed " + name + " value");
  writeFileSync(SYSCTL_PATHS[name], value + "\n", { flag: "w" });
  if (readSysctl(name) !== value) fail(name + " immediate readback failed");
}

function crashDirectorySnapshot() {
  const before = lstatSync("/var/crash", { bigint: true });
  if (!before.isDirectory() || before.isSymbolicLink()) fail("/var/crash is not a directory");
  const entries = readdirSync("/var/crash").sort();
  const after = lstatSync("/var/crash", { bigint: true });
  if (before.dev !== after.dev || before.ino !== after.ino ||
      before.uid !== after.uid || before.gid !== after.gid ||
      before.mode !== after.mode) fail("/var/crash changed during observation");
  return {
    directory: {
      device: before.dev.toString(),
      gid: Number(before.gid),
      inode: before.ino.toString(),
      mode: (Number(before.mode) & 0o7777).toString(8).padStart(4, "0"),
      path: "/var/crash",
      uid: Number(before.uid),
    },
    entries,
  };
}

const APPORT_ACTION_DIRECTIVES = new Set([
  "Alias",
  "Also",
  "BindsTo",
  "Conflicts",
  "OnFailure",
  "OnFailureOf",
  "OnSuccess",
  "OnSuccessOf",
  "PartOf",
  "PropagatesReloadTo",
  "PropagatesStopTo",
  "ReloadPropagatedFrom",
  "Requires",
  "RequiredBy",
  "Requisite",
  "RequisiteOf",
  "Service",
  "StopPropagatedFrom",
  "TriggeredBy",
  "Triggers",
  "Unit",
  "Upholds",
  "UpheldBy",
  "WantedBy",
  "Wants",
]);

function decodeSystemdEscape(text, offset) {
  const code = text[offset + 1];
  if (code === undefined) fail("systemd word ends with a backslash");
  const simple = {
    "\\": "\\",
    "\"": "\"",
    "'": "'",
    a: "\x07",
    b: "\x08",
    f: "\x0c",
    n: "\n",
    r: "\r",
    s: " ",
    t: "\t",
    v: "\x0b",
  };
  if (Object.hasOwn(simple, code)) return { next: offset + 2, value: simple[code] };
  const widths = { u: 4, U: 8, x: 2 };
  if (Object.hasOwn(widths, code)) {
    const width = widths[code];
    const digits = text.slice(offset + 2, offset + 2 + width);
    if (digits.length !== width || !/^[0-9a-fA-F]+$/u.test(digits)) {
      fail("systemd word contains an invalid hexadecimal escape");
    }
    const point = Number.parseInt(digits, 16);
    if (point === 0 || point > 0x10ffff || (point >= 0xd800 && point <= 0xdfff)) {
      fail("systemd word contains an invalid Unicode scalar");
    }
    return { next: offset + 2 + width, value: String.fromCodePoint(point) };
  }
  if (/[0-7]/u.test(code)) {
    const digits = text.slice(offset + 1, offset + 4);
    if (!/^[0-7]{3}$/u.test(digits)) fail("systemd word contains an invalid octal escape");
    const point = Number.parseInt(digits, 8);
    if (point === 0) fail("systemd word contains a NUL escape");
    return { next: offset + 4, value: String.fromCodePoint(point) };
  }
  fail("systemd word contains an unreviewed escape");
}

export function parseSystemdWords(value) {
  if (typeof value !== "string" || value.includes("\0")) fail("systemd word list is malformed");
  const words = [];
  let word = "";
  let quote = null;
  let started = false;
  for (let index = 0; index < value.length;) {
    const character = value[index];
    if (character === "\\") {
      const decoded = decodeSystemdEscape(value, index);
      word += decoded.value;
      started = true;
      index = decoded.next;
      continue;
    }
    if (quote !== null) {
      if (character === quote) quote = null;
      else word += character;
      started = true;
      index += 1;
      continue;
    }
    if (character === "'" || character === "\"") {
      quote = character;
      started = true;
      index += 1;
      continue;
    }
    if (/\s/u.test(character)) {
      if (started) {
        words.push(word);
        word = "";
        started = false;
      }
      index += 1;
      continue;
    }
    word += character;
    started = true;
    index += 1;
  }
  if (quote !== null) fail("systemd word list has an unterminated quote");
  if (started) words.push(word);
  return words;
}

function systemdTemplateCouldEqual(value, target) {
  let pattern = "^";
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (character !== "%") {
      pattern += character.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
      continue;
    }
    const specifier = value[index + 1];
    if (specifier === undefined) return true;
    index += 1;
    if (specifier === "%") pattern += "%";
    else pattern += ".*";
  }
  return new RegExp(pattern + "$", "u").test(target);
}

function normalizedExecPathReferencesApport(value) {
  if (!value.startsWith("/")) return false;
  const normalized = resolve("/", value);
  if (normalized === APPORT_HANDLER_PATH) return true;
  try {
    return realpathSync(normalized) === APPORT_HANDLER_PATH;
  } catch (error) {
    if (error.code === "ENOENT" || error.code === "ENOTDIR") return false;
    throw error;
  }
}

function literalExecWordReferencesApport(value) {
  if (value.includes(APPORT_HANDLER_PATH)) return true;
  const absolutePaths = value.match(/\/[^\s'"`;|&()<>]+/gu) || [];
  return absolutePaths.some(function (path) {
    return systemdTemplateCouldEqual(resolve("/", path), APPORT_HANDLER_PATH) ||
      normalizedExecPathReferencesApport(path);
  });
}

function unitFileReferencesApport(bytes) {
  const logical = bytes.toString("utf8").replace(/\\\r?\n[ \t]*/gu, " ");
  const assignments = [];
  for (const raw of logical.split("\n")) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#") || line.startsWith(";")) continue;
    const equals = line.indexOf("=");
    if (equals < 1) continue;
    const directive = line.slice(0, equals).trim();
    const value = line.slice(equals + 1).trim();
    assignments.push({ directive, value });
  }
  const searchPaths = assignments
    .filter(function (entry) { return entry.directive === "ExecSearchPath"; })
    .flatMap(function (entry) { return parseSystemdWords(entry.value); })
    .flatMap(function (value) { return value.split(":"); })
    .filter(function (value) { return value !== ""; });
  for (const { directive, value } of assignments) {
    if (/^Exec[A-Za-z]*$/u.test(directive)) {
      const command = parseSystemdWords(value);
      if (command.length === 0) continue;
      const executable = command[0].replace(/^[-:@+!]+/u, "");
      const interpreter = new Set([
        "/bin/bash", "/bin/dash", "/bin/sh", "/bin/zsh", "/usr/bin/env",
      ]).has(resolve("/", executable)) ||
        new Set(["bash", "dash", "env", "sh", "zsh"]).has(executable);
      const searchResolved = searchPaths.some(function (directory) {
        if (!directory.startsWith("/") || executable.startsWith("/")) return false;
        return systemdTemplateCouldEqual(resolve("/", directory, executable), APPORT_HANDLER_PATH);
      });
      if (systemdTemplateCouldEqual(executable, APPORT_HANDLER_PATH) ||
          normalizedExecPathReferencesApport(executable) || searchResolved ||
          command.some(literalExecWordReferencesApport) ||
          (interpreter && command.slice(1).some(function (word) { return word.includes("%"); }))) {
        return true;
      }
    }
    if (!APPORT_ACTION_DIRECTIVES.has(directive)) continue;
    const dependencies = parseSystemdWords(value);
    if (dependencies.some(function (unit) {
      return systemdTemplateCouldEqual(unit, APPORT_UNIT);
    })) return true;
  }
  return false;
}

function defaultManagedUnitAllowlist() {
  return {
    [APPORT_UNIT]: {
      dropin_paths: [APPORT_GATE_PATH],
      enablement_paths: [APPORT_ENABLEMENT_PATH],
      enablement_targets: { [APPORT_ENABLEMENT_PATH]: APPORT_ENABLEMENT_TARGET },
      fragment_paths: [APPORT_MASK_PATH, APPORT_UNIT_PATH],
    },
    [GUARD_UNIT]: {
      dropin_paths: [],
      enablement_paths: [GUARD_ENABLEMENT_PATH],
      enablement_targets: { [GUARD_ENABLEMENT_PATH]: GUARD_UNIT_PATH },
      fragment_paths: [GUARD_UNIT_PATH],
    },
    [SYSTEMD_SYSCTL_UNIT]: {
      dropin_paths: [SYSCTL_CREDENTIAL_CLOSURE_PATH, SYSCTL_GATE_PATH],
      enablement_paths: [SYSTEMD_SYSCTL_ENABLEMENT_PATH],
      enablement_targets: {
        [SYSTEMD_SYSCTL_ENABLEMENT_PATH]: SYSTEMD_SYSCTL_ENABLEMENT_TARGET,
      },
      fragment_paths: [SYSTEMD_SYSCTL_UNIT_PATH],
    },
  };
}

function systemdDropinDirectoryNames(unit) {
  const separator = unit.lastIndexOf(".");
  if (separator < 1 || separator === unit.length - 1) {
    fail("managed systemd unit name has no reviewed type suffix");
  }
  const stem = unit.slice(0, separator);
  const type = unit.slice(separator + 1);
  const names = new Set([unit + ".d", type + ".d"]);
  for (let index = stem.indexOf("-"); index >= 0; index = stem.indexOf("-", index + 1)) {
    names.add(stem.slice(0, index + 1) + "." + type + ".d");
  }
  return names;
}

export function scanManagedUnitLoadPaths(configuredRoots, configuredAllowlist) {
  const roots = configuredRoots || SYSTEMD_UNIT_ROOTS;
  const allowlist = configuredAllowlist || defaultManagedUnitAllowlist();
  const units = Object.keys(allowlist).sort();
  const dropinNames = Object.fromEntries(units.map(function (unit) {
    return [unit, systemdDropinDirectoryNames(unit)];
  }));
  const observed = Object.fromEntries(units.map(function (unit) {
    return [unit, { dropin_paths: [], enablement_paths: [], fragment_paths: [] }];
  }));
  function record(path, entry, root) {
    const parentName = basename(dirname(path));
    const dropinUnit = units.find(function (unit) { return dropinNames[unit].has(parentName); });
    if (dropinUnit !== undefined) {
      if (!entry.isFile() || entry.isSymbolicLink() ||
          !allowlist[dropinUnit].dropin_paths.includes(path)) {
        fail("managed systemd unit has an unreviewed drop-in/load path: " + path);
      }
      observed[dropinUnit].dropin_paths.push(path);
      return;
    }
    if (units.some(function (unit) { return dropinNames[unit].has(entry.name); }) &&
        (!entry.isDirectory() || entry.isSymbolicLink())) {
      fail("managed systemd drop-in path is not a directory: " + path);
    }
    const unit = units.find(function (candidate) { return entry.name === candidate; });
    if (unit === undefined) {
      if (entry.isSymbolicLink()) {
        let target;
        try {
          target = realpathSync(path);
        } catch (error) {
          if (error.code === "ENOENT") return;
          throw error;
        }
        if (units.some(function (candidate) {
          return allowlist[candidate].fragment_paths.includes(target);
        })) {
          fail("managed systemd unit has an unreviewed alias or activation path: " + path);
        }
      }
      return;
    }
    if (dirname(path) !== root) {
      const allowedEnablementPaths = allowlist[unit].enablement_paths || [];
      if (!entry.isSymbolicLink() || !allowedEnablementPaths.includes(path)) {
        fail("managed systemd unit has an unreviewed nested activation path: " + path);
      }
      const expectedTarget = allowlist[unit].enablement_targets?.[path];
      const stat = lstatSync(path, { bigint: false });
      if ((expectedTarget !== undefined && readlinkSync(path) !== expectedTarget) ||
          (configuredRoots === undefined && (stat.uid !== 0 || stat.gid !== 0))) {
        fail("managed systemd enablement symlink differs from reviewed state: " + path);
      }
      observed[unit].enablement_paths.push(path);
      return;
    }
    if (!allowlist[unit].fragment_paths.includes(path)) {
      fail("managed systemd unit has an unreviewed effective fragment: " + path);
    }
    if (path === APPORT_MASK_PATH) {
      if (!entry.isSymbolicLink() || realpathSync(path) !== APPORT_MASK_TARGET) {
        fail("Apport mask load path is not the exact /dev/null mask");
      }
    } else if (!entry.isFile() || entry.isSymbolicLink()) {
      fail("managed systemd fragment is not a regular file: " + path);
    }
    observed[unit].fragment_paths.push(path);
  }
  const visited = new Set();
  for (const configured of roots) {
    let root;
    try {
      root = realpathSync(configured);
    } catch (error) {
      if (error.code === "ENOENT") continue;
      throw error;
    }
    if (visited.has(root)) continue;
    visited.add(root);
    function visit(path, depth) {
      if (depth > 4) fail("managed systemd load-path scan exceeded reviewed depth");
      for (const entry of readdirSync(path, { withFileTypes: true })) {
        const child = join(path, entry.name);
        record(child, entry, root);
        if (entry.isDirectory() && !entry.isSymbolicLink()) visit(child, depth + 1);
      }
    }
    visit(root, 0);
  }
  for (const unit of units) {
    observed[unit].dropin_paths.sort();
    observed[unit].enablement_paths.sort();
    observed[unit].fragment_paths.sort();
  }
  return observed;
}

export function validateSystemdSysctlLoadPathsForTest(managed) {
  if (!isPlainObject(managed) || !isPlainObject(managed[SYSTEMD_SYSCTL_UNIT]) ||
      !same(managed[SYSTEMD_SYSCTL_UNIT].fragment_paths, [SYSTEMD_SYSCTL_UNIT_PATH]) ||
      !same(
        managed[SYSTEMD_SYSCTL_UNIT].enablement_paths,
        [SYSTEMD_SYSCTL_ENABLEMENT_PATH],
      )) {
    fail("systemd-sysctl fragment/boot enablement closure differs from the plan");
  }
  return true;
}

function exactSystemdSysctlInputs(plan, managedLoadPaths) {
  const unit = openBoundRegular(SYSTEMD_SYSCTL_UNIT_PATH, "systemd-sysctl unit");
  exactPin(unit, plan.systemd_sysctl.unit, "systemd-sysctl unit");
  const binary = openBoundRegular(SYSTEMD_SYSCTL_BINARY_PATH, "systemd-sysctl binary");
  exactPin(binary, plan.systemd_sysctl.binary, "systemd-sysctl binary");
  const enablementStat = exactSymlinkAt(
    SYSTEMD_SYSCTL_ENABLEMENT_PATH,
    SYSTEMD_SYSCTL_ENABLEMENT_TARGET,
  );
  if (enablementStat.uid !== 0n || enablementStat.gid !== 0n) {
    fail("systemd-sysctl enablement is not root-owned");
  }
  const managed = managedLoadPaths || scanManagedUnitLoadPaths(reviewedManagerUnitPath());
  validateSystemdSysctlLoadPathsForTest(managed);
  return {
    binary: binary.pin,
    enablement: plan.systemd_sysctl.enablement,
    unit: { ...unit.pin, bytes_base64: unit.bytes.toString("base64") },
  };
}

export function scanApportActivation(
  configuredRoots,
  reviewedGuardPin,
  reviewedGatePin,
  configuredOfficialUnitPath,
) {
  const officialUnitPath = configuredOfficialUnitPath === undefined
    ? APPORT_UNIT_PATH
    : realpathSync(configuredOfficialUnitPath);
  const roots = configuredRoots || SYSTEMD_UNIT_ROOTS;
  const found = [];
  const implicitTriggers = new Set([
    "apport.automount",
    "apport.busname",
    "apport.path",
    "apport.socket",
    "apport.timer",
  ]);
  let mask = { path: APPORT_MASK_PATH, state: "absent" };
  function assertTrustedInput(opened, path) {
    if (configuredRoots === undefined &&
        (opened.pin.uid !== 0 || opened.pin.gid !== 0 ||
        (Number.parseInt(opened.pin.mode, 8) & 0o022) !== 0)) {
      fail("systemd activation input is not root-owned and non-writable: " + path);
    }
  }
  function visit(path, depth) {
    if (depth > 4) fail("systemd enablement scan exceeded reviewed depth");
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const child = join(path, entry.name);
      if (entry.isDirectory()) visit(child, depth + 1);
      if (implicitTriggers.has(entry.name)) {
        fail("implicit Apport activation fragment/dependency exists: " + child);
      }
      if (entry.isSymbolicLink()) {
        const target = readlinkSync(child);
        if (entry.name === APPORT_UNIT && target === APPORT_MASK_TARGET) {
          if (child !== APPORT_MASK_PATH || mask.state !== "absent") {
            fail("foreign or duplicate Apport mask exists: " + child);
          }
          const stat = lstatSync(child, { bigint: false });
          mask = {
            link: { gid: stat.gid, path: child, target, uid: stat.uid },
            state: "present",
          };
        } else if (entry.name === APPORT_UNIT || basename(target) === APPORT_UNIT) {
          const stat = lstatSync(child, { bigint: false });
          found.push({ gid: stat.gid, path: child, target, uid: stat.uid });
        } else if (target !== "/dev/null") {
          let resolvedTarget;
          try {
            resolvedTarget = realpathSync(child);
          } catch (error) {
            if (error.code === "ENOENT") {
              fail("broken systemd activation symlink is outside the closed set: " + child);
            }
            throw error;
          }
          if (resolvedTarget === officialUnitPath) {
            const stat = lstatSync(child, { bigint: false });
            found.push({ gid: stat.gid, path: child, target, uid: stat.uid });
            continue;
          }
          const opened = openBoundRegular(
            resolvedTarget,
            "systemd symlink activation target",
            MAX_JSON_BYTES,
          );
          assertTrustedInput(opened, resolvedTarget);
          if (unitFileReferencesApport(opened.bytes)) {
            fail("foreign symlinked systemd unit references apport.service: " + child);
          }
        }
      } else if (entry.isFile()) {
        if (entry.name === APPORT_UNIT && child !== officialUnitPath) {
          fail("non-symlink Apport fragment/dependency exists outside the official unit path: " + child);
        }
        if (child === officialUnitPath) continue;
        const opened = openBoundRegular(child, "systemd activation input", MAX_JSON_BYTES);
        assertTrustedInput(opened, child);
        if (child === APPORT_GATE_PATH && reviewedGatePin !== undefined) {
          exactPin(opened, reviewedGatePin, "reviewed Apport activation gate");
          continue;
        }
        if (child.includes("/apport.service.d/")) {
          fail("Apport drop-in exists outside the reviewed closure: " + child);
        }
        if (child === GUARD_UNIT_PATH && reviewedGuardPin !== undefined) {
          exactPin(opened, reviewedGuardPin, "reviewed reboot guard");
          continue;
        }
        if (unitFileReferencesApport(opened.bytes)) {
          fail("foreign systemd unit references apport.service: " + child);
        }
      }
    }
  }
  const visited = new Set();
  for (const configured of roots) {
    let root;
    try {
      root = realpathSync(configured);
    } catch (error) {
      if (error.code === "ENOENT") continue;
      throw error;
    }
    if (visited.has(root)) continue;
    visited.add(root);
    visit(root, 0);
  }
  return {
    enablement_symlinks: found.sort(function (a, b) { return a.path.localeCompare(b.path); }),
    mask,
  };
}

export function scanApportEnablement(
  configuredRoots,
  reviewedGuardPin,
  reviewedGatePin,
  configuredOfficialUnitPath,
) {
  return scanApportActivation(
    configuredRoots,
    reviewedGuardPin,
    reviewedGatePin,
    configuredOfficialUnitPath,
  ).enablement_symlinks;
}

export function scanSysctlAssignments(
  configuredDirectories,
  legacyPath,
) {
  const directories = configuredDirectories || SYSCTL_DIRS;
  const legacy = legacyPath === undefined ? "/etc/sysctl.conf" : legacyPath;
  const found = [];
  const selected = new Set();
  const canonicalDirectories = [];
  for (const configured of directories) {
    try {
      const real = realpathSync(configured);
      if (!canonicalDirectories.includes(real)) canonicalDirectories.push(real);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
  for (const directory of canonicalDirectories) {
    const names = readdirSync(directory).filter(function (name) {
      return name.endsWith(".conf");
    }).sort();
    for (const name of names) {
      if (selected.has(name)) continue;
      selected.add(name);
      const path = join(directory, name);
      const discovered = lstatSync(path, { bigint: false });
      if (discovered.isSymbolicLink()) {
        if (realpathSync(path) === "/dev/null") continue;
        fail("sysctl input is a foreign symlink: " + path);
      }
      const opened = openBoundRegular(path, "sysctl input");
      const assignments = opened.bytes.toString("utf8").split("\n").filter(function (line) {
        return normalizeAssignmentKey(line) !== null;
      });
      if (assignments.length > 0) found.push({ assignments, file: opened.pin });
    }
  }
  if (legacy !== null) {
    try {
      const opened = openBoundRegular(legacy, "legacy sysctl input");
      const assignments = opened.bytes.toString("utf8").split("\n").filter(function (line) {
        return normalizeAssignmentKey(line) !== null;
      });
      if (assignments.length > 0) found.push({ assignments, file: opened.pin });
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
  return found.sort(function (a, b) { return a.file.path.localeCompare(b.file.path); });
}

export const scanCorePatternAssignments = scanSysctlAssignments;

function runCommand(path, args, label) {
  const result = spawnSync(path, args, {
    cwd: "/",
    encoding: "utf8",
    env: { LANG: "C", LC_ALL: "C", PATH: "/usr/sbin:/usr/bin" },
    maxBuffer: 1024 * 1024,
    shell: false,
    timeout: 30_000,
  });
  if (result.error !== undefined || result.status !== 0 || result.signal !== null) {
    fail(label + " failed");
  }
  return result.stdout;
}

export function parseBusctlJson(text, expectedType, label) {
  if (typeof text !== "string" || Buffer.byteLength(text, "utf8") > MAX_JSON_BYTES) {
    fail(label + " returned unbounded busctl JSON");
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch (error) {
    fail(label + " returned malformed JSON: " + error.message);
  }
  if (JSON.stringify(value) !== text.trim()) {
    fail(label + " returned non-canonical or duplicate-key busctl JSON");
  }
  exactKeys(value, ["data", "type"], label + " envelope");
  if (value.type !== expectedType) {
    fail(label + " signature differs from " + expectedType);
  }
  return value.data;
}

function busctlJson(args, expectedType, label) {
  return parseBusctlJson(
    runCommand("/usr/bin/busctl", ["--json=short", "--system"].concat(args), label),
    expectedType,
    label,
  );
}

function parseLosslessJson(text, label) {
  let offset = 0;
  function skipWhitespace() {
    while (/[\t\n\r ]/u.test(text[offset] || "")) offset += 1;
  }
  function parseString() {
    const start = offset;
    offset += 1;
    let escaped = false;
    while (offset < text.length) {
      const character = text[offset];
      if (!escaped && character === "\"") {
        offset += 1;
        try {
          return JSON.parse(text.slice(start, offset));
        } catch (error) {
          fail(label + " contains an invalid JSON string: " + error.message);
        }
      }
      if (!escaped && character === "\\") escaped = true;
      else escaped = false;
      offset += 1;
    }
    fail(label + " contains an unterminated JSON string");
  }
  function parseNumber() {
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(text.slice(offset));
    if (match === null) fail(label + " contains an invalid JSON number");
    offset += match[0].length;
    const numeric = Number(match[0]);
    if (!Number.isFinite(numeric)) fail(label + " contains a non-finite JSON number");
    if (!match[0].includes(".") && !/[eE]/u.test(match[0]) && !Number.isSafeInteger(numeric)) {
      return { raw_integer: match[0] };
    }
    return numeric;
  }
  function parseValue() {
    skipWhitespace();
    const character = text[offset];
    if (character === "\"") return parseString();
    if (character === "[") {
      offset += 1;
      const values = [];
      skipWhitespace();
      if (text[offset] === "]") {
        offset += 1;
        return values;
      }
      while (true) {
        values.push(parseValue());
        skipWhitespace();
        if (text[offset] === "]") {
          offset += 1;
          return values;
        }
        if (text[offset] !== ",") fail(label + " contains a malformed JSON array");
        offset += 1;
      }
    }
    if (character === "{") {
      offset += 1;
      const value = Object.create(null);
      skipWhitespace();
      if (text[offset] === "}") {
        offset += 1;
        return value;
      }
      while (true) {
        skipWhitespace();
        if (text[offset] !== "\"") fail(label + " contains a non-string JSON key");
        const key = parseString();
        if (Object.hasOwn(value, key)) fail(label + " contains a duplicate JSON key");
        skipWhitespace();
        if (text[offset] !== ":") fail(label + " contains a malformed JSON object");
        offset += 1;
        value[key] = parseValue();
        skipWhitespace();
        if (text[offset] === "}") {
          offset += 1;
          return value;
        }
        if (text[offset] !== ",") fail(label + " contains a malformed JSON object");
        offset += 1;
      }
    }
    for (const [token, value] of [["true", true], ["false", false], ["null", null]]) {
      if (text.startsWith(token, offset)) {
        offset += token.length;
        return value;
      }
    }
    if (character === "-" || /[0-9]/u.test(character || "")) return parseNumber();
    fail(label + " contains an invalid JSON value");
  }
  const value = parseValue();
  skipWhitespace();
  if (offset !== text.length) fail(label + " contains trailing JSON data");
  return value;
}

export function parseBusctlGetAll(text, label) {
  if (typeof text !== "string" || Buffer.byteLength(text, "utf8") > MAX_JSON_BYTES) {
    fail(label + " returned unbounded busctl GetAll JSON");
  }
  const envelope = parseLosslessJson(text, label);
  exactKeys(envelope, ["data", "type"], label + " envelope");
  // busctl renders a D-Bus dictionary array as one JSON object inside an array.
  if (envelope.type !== "a{sv}" || !Array.isArray(envelope.data) ||
      envelope.data.length !== 1 || !isPlainObject(envelope.data[0])) {
    fail(label + " signature differs from a{sv}");
  }
  const properties = envelope.data[0];
  for (const [property, variant] of Object.entries(properties)) {
    exactKeys(variant, ["data", "type"], label + "." + property);
    if (typeof variant.type !== "string" || variant.type.length === 0) {
      fail(label + "." + property + " has an invalid variant signature");
    }
  }
  return properties;
}

function busctlGetAll(path, iface) {
  const label = "systemd D-Bus GetAll " + iface + " " + path;
  return parseBusctlGetAll(
    runCommand("/usr/bin/busctl", [
      "--json=short", "--system", "call", "org.freedesktop.systemd1", path,
      "org.freedesktop.DBus.Properties", "GetAll", "s", iface,
    ], label),
    label,
  );
}

function variantProperty(properties, property, signature, label) {
  if (!Object.hasOwn(properties, property)) fail(label + " is missing " + property);
  const variant = properties[property];
  if (variant.type !== signature) fail(label + "." + property + " signature differs from " + signature);
  return variant.data;
}

function stringSetProperty(properties, property, label) {
  const value = variantProperty(properties, property, "as", label);
  if (!Array.isArray(value) || value.some(function (entry) { return typeof entry !== "string"; }) ||
      new Set(value).size !== value.length) {
    fail(label + "." + property + " is not a unique string array");
  }
  return Array.from(value).sort();
}

function orderedStringArrayProperty(properties, property, label) {
  const value = variantProperty(properties, property, "as", label);
  if (!Array.isArray(value) || value.some(function (entry) { return typeof entry !== "string"; }) ||
      new Set(value).size !== value.length) {
    fail(label + "." + property + " is not a unique string array");
  }
  return Array.from(value);
}

export function validateManagerUnitPathForTest(properties) {
  const paths = orderedStringArrayProperty(
    properties,
    "UnitPath",
    "effective systemd manager",
  );
  if (!same(paths, SYSTEMD_MANAGER_UNIT_PATHS)) {
    fail("systemd Manager.UnitPath differs from the reviewed search path");
  }
  return paths;
}

function reviewedManagerUnitPath() {
  return validateManagerUnitPathForTest(busctlGetAll(
    "/org/freedesktop/systemd1",
    "org.freedesktop.systemd1.Manager",
  ));
}

function parseExecCommands(properties, property, label) {
  const value = variantProperty(properties, property, "a(sasasttttuii)", label);
  if (!Array.isArray(value) || value.length > 16) fail(label + "." + property + " is unbounded");
  return value.map(function (tuple, index) {
    if (!Array.isArray(tuple) || tuple.length !== 10 || typeof tuple[0] !== "string" ||
        !Array.isArray(tuple[1]) || tuple[1].length === 0 || tuple[1][0] !== tuple[0] ||
        tuple[1].some(function (argument) { return typeof argument !== "string"; }) ||
        !Array.isArray(tuple[2]) || tuple[2].some(function (flag) { return flag !== "privileged"; })) {
      fail(label + "." + property + "[" + index + "] is malformed");
    }
    return { argv: tuple[1], flags: tuple[2], path: tuple[0] };
  });
}

function exactExec(properties, property, expected, label) {
  const commands = parseExecCommands(properties, property, label);
  if (!same(commands, expected)) fail(label + "." + property + " differs from the reviewed command set");
}

const APPORT_DBUS_DEPENDENCIES = Object.freeze([
  "BindsTo", "BoundBy", "ConflictedBy", "Conflicts", "ConsistsOf", "OnFailure",
  "OnFailureOf", "OnSuccess", "OnSuccessOf", "PartOf", "PropagatesReloadTo",
  "PropagatesStopTo", "ReloadPropagatedFrom",
  "RequiredBy", "Requires", "Requisite", "RequisiteOf", "StopPropagatedFrom", "TriggeredBy",
  "Triggers", "UpheldBy", "Upholds", "WantedBy", "Wants",
]);

function validateApportDependencyClosure(properties, enablementExpected, masked, label) {
  const allowed = masked ? {} : {
    Conflicts: ["shutdown.target"],
    Requires: ["sysinit.target"],
    WantedBy: enablementExpected ? ["multi-user.target"] : [],
  };
  for (const property of APPORT_DBUS_DEPENDENCIES) {
    const actual = stringSetProperty(properties, property, label);
    if (!same(actual, (allowed[property] || []).slice().sort())) {
      fail(label + "." + property + " contains an unreviewed start/stop/reload edge");
    }
  }
  if (variantProperty(properties, "StopWhenUnneeded", "b", label) !== false) {
    fail(label + ".StopWhenUnneeded is not fail-closed");
  }
}

function normalizeManagerRows(rows) {
  if (!Array.isArray(rows)) fail("systemd ListUnits data must be an array");
  for (const row of rows) {
    if (!Array.isArray(row) || row.length !== 10 ||
        row.slice(0, 7).some(function (value) { return typeof value !== "string"; }) ||
        !Number.isSafeInteger(row[7]) || typeof row[8] !== "string" || typeof row[9] !== "string") {
      fail("systemd ListUnits row is malformed");
    }
  }
  return Array.from(rows).sort(function (left, right) {
    return canonicalJson(left).localeCompare(canonicalJson(right));
  });
}

function normalizeManagerJobs(jobs) {
  if (!Array.isArray(jobs)) fail("systemd ListJobs data must be an array");
  for (const job of jobs) {
    if (!Array.isArray(job) || job.length !== 6 || !Number.isSafeInteger(job[0]) ||
        job.slice(1).some(function (value) { return typeof value !== "string"; })) {
      fail("systemd ListJobs row is malformed");
    }
  }
  return Array.from(jobs).sort(function (left, right) {
    return canonicalJson(left).localeCompare(canonicalJson(right));
  });
}

export function assertManagerSnapshotFenceForTest(
  unitsBefore,
  jobsBefore,
  unitsAfter,
  jobsAfter,
  unitPathBefore,
  unitPathAfter,
) {
  const normalizedUnitsBefore = normalizeManagerRows(unitsBefore);
  const normalizedUnitsAfter = normalizeManagerRows(unitsAfter);
  const normalizedJobsBefore = normalizeManagerJobs(jobsBefore);
  const normalizedJobsAfter = normalizeManagerJobs(jobsAfter);
  if (!same(normalizedUnitsBefore, normalizedUnitsAfter) ||
      !same(normalizedJobsBefore, normalizedJobsAfter) ||
      (unitPathBefore !== undefined && !same(unitPathBefore, unitPathAfter))) {
    fail("systemd ListUnits/ListJobs changed across the GetAll snapshot");
  }
  return true;
}

export function parseLoadedApportUnitRows(rows) {
  const normalized = normalizeManagerRows(rows);
  const matches = normalized.filter(function (row) { return row[0] === APPORT_UNIT; });
  if (matches.length !== 1) {
    fail("Apport must already be present exactly once in non-loading ListUnits output");
  }
  if (!["loaded", "masked"].includes(matches[0][2])) {
    fail("non-loading ListUnits reports an unloaded Apport unit");
  }
  if (matches[0][5] !== "" || matches[0][7] !== 0 ||
      matches[0][8] !== "" || matches[0][9] !== "/") {
    fail("non-loading ListUnits reports an alias or queued Apport job");
  }
  return matches[0];
}

function managerListUnits() {
  return normalizeManagerRows(busctlJson(
    ["call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
      "org.freedesktop.systemd1.Manager", "ListUnits"],
    "a(ssssssouso)",
    "systemd Manager.ListUnits",
  ));
}

function managerListJobs() {
  return normalizeManagerJobs(busctlJson(
    ["call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
      "org.freedesktop.systemd1.Manager", "ListJobs"],
    "a(usssoo)",
    "systemd Manager.ListJobs",
  ));
}

function validateLoadedUnitMetadata(name, row, unit, service) {
  const label = "effective systemd unit " + name;
  if (!Array.isArray(row) || row.length !== 10 || row[0] !== name ||
      !["loaded", "masked"].includes(row[2]) || row[5] !== "" || row[7] !== 0 ||
      row[8] !== "" || row[9] !== "/") {
    fail(name + " is unloaded, aliased, transitioning, or queued");
  }
  const values = {
    active_state: variantProperty(unit, "ActiveState", "s", label),
    control_pid: variantProperty(service, "ControlPID", "u", label),
    dropin_paths: stringSetProperty(unit, "DropInPaths", label),
    fragment_path: variantProperty(unit, "FragmentPath", "s", label),
    job: variantProperty(unit, "Job", "(uo)", label),
    load_state: variantProperty(unit, "LoadState", "s", label),
    main_pid: variantProperty(service, "MainPID", "u", label),
    names: stringSetProperty(unit, "Names", label),
    need_daemon_reload: variantProperty(unit, "NeedDaemonReload", "b", label),
    source_path: variantProperty(unit, "SourcePath", "s", label),
    sub_state: variantProperty(unit, "SubState", "s", label),
    transient: variantProperty(unit, "Transient", "b", label),
  };
  if (variantProperty(unit, "Id", "s", label) !== name || values.control_pid !== 0 ||
      values.main_pid !== 0 || !same(values.job, [0, "/"]) ||
      !same(values.names, [name]) || values.need_daemon_reload !== false ||
      values.source_path !== "" || values.transient !== false) {
    fail(name + " is executing, transitioning, aliased, transient, generated, or needs reload");
  }
  if (row[2] !== values.load_state || row[3] !== values.active_state || row[4] !== values.sub_state) {
    fail(name + " changed between non-loading enumeration and GetAll readback");
  }
  const settled = (values.active_state === "active" && values.sub_state === "exited") ||
    (values.active_state === "inactive" && values.sub_state === "dead");
  if (!settled) fail(name + " runtime is not settled");
  return { row, service, unit, values };
}

export function validateLoadedUnitMetadataForTest(name, row, unit, service) {
  return validateLoadedUnitMetadata(name, row, unit, service);
}

function loadedUnitSnapshot(name, rows, required) {
  const matches = rows.filter(function (row) { return row[0] === name; });
  if (matches.length === 0 && !required) return null;
  if (matches.length !== 1) fail(name + " must appear exactly once in non-loading ListUnits output");
  const row = matches[0];
  if (!required) fail(name + " remains loaded outside its reviewed generation");
  const unitPath = busctlJson(
    ["call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
      "org.freedesktop.systemd1.Manager", "GetUnit", "s", name],
    "o",
    "systemd Manager.GetUnit",
  );
  if (typeof unitPath !== "string" || unitPath !== row[6]) {
    fail("non-loading GetUnit path differs from the enumerated " + name + " object");
  }
  const unit = busctlGetAll(unitPath, "org.freedesktop.systemd1.Unit");
  const service = busctlGetAll(unitPath, "org.freedesktop.systemd1.Service");
  return validateLoadedUnitMetadata(name, row, unit, service);
}

function runtimePhase(phase) {
  const guarded = [
    "guarded-preimage", "guarded-candidate", "apply-preflight-pre-publish",
    "rollback-preflight-pre-publish", "apply-terminal", "apply-pre-publish",
    "rollback-terminal", "rollback-pre-publish",
  ].includes(phase);
  const masked = [
    "fresh-candidate", "guarded-candidate", "rollback-preflight-pre-publish",
    "apply-terminal", "apply-pre-publish", "apply-cleanup-pre-release",
  ].includes(phase);
  const enabled = [
    "fresh-preimage", "guarded-preimage", "apply-preflight-pre-publish",
    "rollback-terminal", "rollback-pre-publish", "rollback-cleanup-pre-release",
  ].includes(phase);
  const credentialClosure = [
    "fresh-candidate", "guarded-candidate", "rollback-preflight-pre-publish",
    "apply-terminal", "apply-pre-publish", "apply-cleanup-pre-release",
  ].includes(phase);
  return { credentialClosure, enabled, guarded, masked };
}

function assertNoApportEdge(properties, label) {
  for (const property of APPORT_DBUS_DEPENDENCIES) {
    if (!Object.hasOwn(properties, property)) continue;
    if (stringSetProperty(properties, property, label).includes(APPORT_UNIT)) {
      fail(label + "." + property + " contains a foreign Apport action edge");
    }
  }
}

function validateRuntimeConfiguration(snapshot, phase) {
  const expected = runtimePhase(phase);
  const apport = snapshot.apport;
  const sysctl = snapshot.sysctl;
  const guard = snapshot.guard;
  if (apport === null || sysctl === null || (expected.guarded && guard === null)) {
    fail("managed systemd runtime generation is incomplete during " + phase);
  }
  if (!expected.guarded && guard !== null) fail("guard remains loaded during " + phase);
  const apportLabel = "effective systemd unit " + APPORT_UNIT;
  if (apport.values.load_state !== (expected.masked ? "masked" : "loaded") ||
      apport.values.fragment_path !== (expected.masked ? APPORT_MASK_PATH : APPORT_UNIT_PATH) ||
      !same(apport.values.dropin_paths, expected.guarded ? [APPORT_GATE_PATH] : [])) {
    fail("Apport FragmentPath/DropInPaths/LoadState differ during " + phase);
  }
  validateApportDependencyClosure(apport.unit, expected.enabled, expected.masked, apportLabel);
  exactExec(apport.service, "ExecStartEx", expected.masked ? [] : [{
    argv: [APPORT_HANDLER_PATH, "--start"], flags: [], path: APPORT_HANDLER_PATH,
  }], apportLabel);
  exactExec(apport.service, "ExecStopEx", expected.guarded || expected.masked ? [] : [{
    argv: [APPORT_HANDLER_PATH, "--stop"], flags: [], path: APPORT_HANDLER_PATH,
  }], apportLabel);
  exactExec(apport.service, "ExecConditionEx", expected.guarded ? [{
    argv: ["/usr/bin/node", EXECUTOR_PATH, "early-apport-gate"], flags: [], path: "/usr/bin/node",
  }] : [], apportLabel);
  for (const property of ["ExecStartPreEx", "ExecStartPostEx", "ExecReloadEx", "ExecStopPostEx"]) {
    exactExec(apport.service, property, [], apportLabel);
  }
  const sysctlLabel = "effective systemd unit " + SYSTEMD_SYSCTL_UNIT;
  const expectedSysctlDropins = [
    expected.credentialClosure ? SYSCTL_CREDENTIAL_CLOSURE_PATH : null,
    expected.guarded ? SYSCTL_GATE_PATH : null,
  ].filter(function (path) { return path !== null; }).sort();
  if (sysctl.values.load_state !== "loaded" ||
      sysctl.values.fragment_path !== SYSTEMD_SYSCTL_UNIT_PATH ||
      !same(sysctl.values.dropin_paths, expectedSysctlDropins)) {
    fail("systemd-sysctl FragmentPath/DropInPaths/LoadState differ during " + phase);
  }
  exactExec(sysctl.service, "ExecConditionEx", expected.guarded ? [{
    argv: ["/usr/bin/node", EXECUTOR_PATH, "early-sysctl-gate"], flags: [], path: "/usr/bin/node",
  }] : [], sysctlLabel);
  exactExec(sysctl.service, "ExecStartEx", [{
    argv: [SYSTEMD_SYSCTL_BINARY_PATH],
    flags: [],
    path: SYSTEMD_SYSCTL_BINARY_PATH,
  }], sysctlLabel);
  for (const [property, signature] of [
    ["LoadCredential", "a(ss)"],
    ["LoadCredentialEncrypted", "a(ss)"],
    ["SetCredential", "a(say)"],
    ["SetCredentialEncrypted", "a(say)"],
  ]) {
    if (!same(variantProperty(sysctl.service, property, signature, sysctlLabel), [])) {
      fail(sysctlLabel + "." + property + " is not empty");
    }
  }
  const importedCredentials = stringSetProperty(sysctl.service, "ImportCredential", sysctlLabel);
  if (!same(importedCredentials, expected.credentialClosure ? [] : ["sysctl.*"])) {
    fail(sysctlLabel + ".ImportCredential differs from the reviewed phase");
  }
  if (!same(stringSetProperty(sysctl.unit, "WantedBy", sysctlLabel), ["sysinit.target"])) {
    fail(sysctlLabel + ".WantedBy does not prove exact boot activation");
  }
  assertNoApportEdge(sysctl.unit, sysctlLabel);
  for (const property of [
    "ExecStartPreEx", "ExecStartPostEx", "ExecReloadEx", "ExecStopEx", "ExecStopPostEx",
  ]) {
    exactExec(sysctl.service, property, [], sysctlLabel);
  }
  if (guard !== null) {
    const guardLabel = "effective systemd unit " + GUARD_UNIT;
    if (guard.values.load_state !== "loaded" || guard.values.fragment_path !== GUARD_UNIT_PATH ||
        !same(guard.values.dropin_paths, [])) {
      fail("guard FragmentPath/DropInPaths/LoadState differ during " + phase);
    }
    exactExec(guard.service, "ExecStartEx", [{
      argv: ["/usr/bin/node", EXECUTOR_PATH, "early-fail-closed"], flags: [], path: "/usr/bin/node",
    }], guardLabel);
    exactExec(guard.service, "ExecStopEx", [], guardLabel);
    for (const property of [
      "ExecConditionEx", "ExecStartPreEx", "ExecStartPostEx", "ExecReloadEx", "ExecStopPostEx",
    ]) {
      exactExec(guard.service, property, [], guardLabel);
    }
    assertNoApportEdge(guard.unit, guardLabel);
  }
}

export function validateRuntimeConfigurationForTest(snapshot, phase) {
  validateRuntimeConfiguration(snapshot, phase);
  return true;
}

export function assertApportRuntimeLineageForTest(
  snapshot,
  expectedRuntime,
  requirePlanBootState,
  phase,
) {
  if (snapshot.need_daemon_reload !== "no") {
    fail("Apport needs a manager reload during " + phase);
  }
  if (requirePlanBootState &&
      (snapshot.active_state !== expectedRuntime.active_state ||
       snapshot.sub_state !== expectedRuntime.sub_state)) {
    fail("Apport runtime changed or transitioned during " + phase);
  }
  return true;
}

function runtimeServiceSnapshot(phase) {
  const expected = runtimePhase(phase);
  const unitPathBefore = reviewedManagerUnitPath();
  const unitsBefore = managerListUnits();
  const jobsBefore = managerListJobs();
  const snapshot = {
    apport: loadedUnitSnapshot(APPORT_UNIT, unitsBefore, true),
    guard: loadedUnitSnapshot(GUARD_UNIT, unitsBefore, expected.guarded),
    sysctl: loadedUnitSnapshot(SYSTEMD_SYSCTL_UNIT, unitsBefore, true),
  };
  const jobsAfter = managerListJobs();
  const unitsAfter = managerListUnits();
  const unitPathAfter = reviewedManagerUnitPath();
  assertManagerSnapshotFenceForTest(
    unitsBefore,
    jobsBefore,
    unitsAfter,
    jobsAfter,
    unitPathBefore,
    unitPathAfter,
  );
  const managed = new Set([APPORT_UNIT, GUARD_UNIT, SYSTEMD_SYSCTL_UNIT]);
  if (jobsBefore.some(function (job) { return managed.has(job[1]); })) {
    fail("managed systemd unit has a queued manager job");
  }
  validateRuntimeConfiguration(snapshot, phase);
  return {
    active_state: snapshot.apport.values.active_state,
    load_state: snapshot.apport.values.load_state,
    need_daemon_reload: "no",
    sub_state: snapshot.apport.values.sub_state,
    _configuration: {
      dropin_paths: snapshot.apport.values.dropin_paths,
      fragment_path: snapshot.apport.values.fragment_path,
    },
  };
}

function publicRuntimeObservation(snapshot) {
  return {
    active_state: snapshot.active_state,
    load_state: snapshot.load_state,
    need_daemon_reload: snapshot.need_daemon_reload,
    sub_state: snapshot.sub_state,
  };
}

function apportGateSnapshot(plan) {
  let directory;
  try {
    const stat = lstatSync(APPORT_GATE_DIRECTORY, { bigint: false });
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      fail("Apport activation gate directory is not a directory");
    }
    directory = {
      gid: stat.gid,
      mode: modeText(stat),
      path: APPORT_GATE_DIRECTORY,
      uid: stat.uid,
    };
    validateManagedDirectory(
      directory,
      "Apport activation gate directory",
      APPORT_GATE_DIRECTORY,
    );
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  let gate;
  try {
    gate = openBoundRegular(APPORT_GATE_PATH, "Apport activation gate");
    exactPin(gate, plan.candidate.apport_gate, "Apport activation gate");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  if (directory === undefined && gate === undefined) {
    return {
      directory_path: APPORT_GATE_DIRECTORY,
      file_path: APPORT_GATE_PATH,
      state: "absent",
    };
  }
  if (directory === undefined || gate === undefined) {
    fail("Apport activation gate directory/file is a partial generation");
  }
  return {
    directory,
    file: { ...gate.pin, bytes_base64: gate.bytes.toString("base64") },
    state: "present",
  };
}

function systemdSysctlDropinsSnapshot(plan) {
  let directory;
  try {
    const stat = lstatSync(SYSCTL_GATE_DIRECTORY, { bigint: false });
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      fail("systemd-sysctl gate directory is not a directory");
    }
    directory = {
      gid: stat.gid,
      mode: modeText(stat),
      path: SYSCTL_GATE_DIRECTORY,
      uid: stat.uid,
    };
    validateManagedDirectory(
      directory,
      "systemd-sysctl gate directory",
      SYSCTL_GATE_DIRECTORY,
    );
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  function optionalDropin(path, pin, label) {
    try {
      const opened = openBoundRegular(path, label);
      exactPin(opened, pin, label);
      return { ...opened.pin, bytes_base64: opened.bytes.toString("base64") };
    } catch (error) {
      if (error.code === "ENOENT") return undefined;
      throw error;
    }
  }
  const gate = optionalDropin(
    SYSCTL_GATE_PATH,
    plan.candidate.sysctl_gate,
    "systemd-sysctl preflight gate",
  );
  const credentialClosure = optionalDropin(
    SYSCTL_CREDENTIAL_CLOSURE_PATH,
    plan.candidate.sysctl_credential_closure,
    "systemd-sysctl credential closure",
  );
  const expectedEntries = [
    gate === undefined ? null : basename(SYSCTL_GATE_PATH),
    credentialClosure === undefined ? null : basename(SYSCTL_CREDENTIAL_CLOSURE_PATH),
  ].filter(function (entry) { return entry !== null; }).sort();
  if (directory === undefined && expectedEntries.length === 0) {
    return {
      credential_closure: sysctlCredentialClosureSnapshotShape("absent"),
      gate: sysctlGateSnapshotShape("absent"),
    };
  }
  if (directory === undefined || expectedEntries.length === 0 ||
      !same(readdirSync(SYSCTL_GATE_DIRECTORY).sort(), expectedEntries)) {
    fail("systemd-sysctl drop-in directory/files are a partial or unknown generation");
  }
  return {
    credential_closure: credentialClosure === undefined
      ? sysctlCredentialClosureSnapshotShape("absent")
      : sysctlCredentialClosureSnapshotShape("present", directory, credentialClosure),
    gate: gate === undefined
      ? sysctlGateSnapshotShape("absent")
      : sysctlGateSnapshotShape("present", directory, gate),
  };
}

function serviceSnapshot(plan, gateSnapshot) {
  const fragment = openBoundRegular(APPORT_UNIT_PATH, "Apport unit");
  exactPin(fragment, plan.official_noble_apport.unit, "Apport unit");
  return {
    dropin_paths: gateSnapshot.state === "present" ? [APPORT_GATE_PATH] : [],
    fragment: fragment.pin,
    name: APPORT_UNIT,
  };
}

function optionalPolicy(plan) {
  try {
    const opened = openBoundRegular(PERSISTENT_POLICY_PATH, "persistent policy");
    return { file: opened.pin, state: "present" };
  } catch (error) {
    if (error.code === "ENOENT") return { path: PERSISTENT_POLICY_PATH, state: "absent" };
    throw error;
  }
}

function guardSnapshot(plan) {
  const unitExists = pathExistsNoFollow(GUARD_UNIT_PATH);
  const enablementExists = pathExistsNoFollow(GUARD_ENABLEMENT_PATH);
  if (!unitExists && !enablementExists) return { state: "absent" };
  if (!unitExists || !enablementExists) {
    fail("reboot guard unit/enablement is a partial generation");
  }
  const unit = openBoundRegular(GUARD_UNIT_PATH, "guard unit");
  exactPin(unit, plan.candidate.guard_unit, "guard unit");
  const stat = lstatSync(GUARD_ENABLEMENT_PATH, { bigint: false });
  if (!stat.isSymbolicLink()) fail("guard enablement is not a symlink");
  const enablement = {
    gid: stat.gid,
    path: GUARD_ENABLEMENT_PATH,
    target: readlinkSync(GUARD_ENABLEMENT_PATH),
    uid: stat.uid,
  };
  validateSymlink(enablement, "guard enablement", GUARD_ENABLEMENT_PATH, GUARD_UNIT_PATH);
  return {
    enablement,
    state: "present",
    unit: { ...unit.pin, bytes_base64: unit.bytes.toString("base64") },
  };
}

function systemdConfigurationGeneration(plan) {
  const unitPath = reviewedManagerUnitPath();
  const managedLoadPaths = scanManagedUnitLoadPaths(unitPath);
  const sysctlDropins = systemdSysctlDropinsSnapshot(plan);
  return sha256(Buffer.from(canonicalJson({
    apport_activation: scanApportActivation(
      undefined,
      plan.candidate.guard_unit,
      plan.candidate.apport_gate,
    ),
    apport_gate: apportGateSnapshot(plan),
    guard: guardSnapshot(plan),
    managed_load_paths: managedLoadPaths,
    systemd_sysctl_inputs: exactSystemdSysctlInputs(plan, managedLoadPaths),
    sysctl_dropins: sysctlDropins,
  }), "utf8"));
}

function realInspect(plan) {
  const managedLoadPaths = scanManagedUnitLoadPaths(reviewedManagerUnitPath());
  exactSystemdSysctlInputs(plan, managedLoadPaths);
  const apportActivation = scanApportActivation(
    undefined,
    plan.candidate.guard_unit,
    plan.candidate.apport_gate,
  );
  const gate = apportGateSnapshot(plan);
  const apportService = serviceSnapshot(plan, gate);
  const policy = optionalPolicy(plan);
  const guard = guardSnapshot(plan);
  const sysctlDropins = systemdSysctlDropinsSnapshot(plan);
  const assignments = scanSysctlAssignments();
  const sysctls = {
    "fs.suid_dumpable": readSysctl("fs.suid_dumpable"),
    "kernel.core_pattern": readSysctl("kernel.core_pattern"),
    "kernel.core_pipe_limit": readSysctl("kernel.core_pipe_limit"),
  };
  const crash = crashDirectorySnapshot();
  return {
    apport_enablement_symlinks: apportActivation.enablement_symlinks,
    apport_gate: gate,
    apport_mask: apportActivation.mask,
    apport_service: apportService,
    crash_directory: crash.directory,
    crash_entries: crash.entries,
    guard,
    sysctl_credential_closure: sysctlDropins.credential_closure,
    sysctl_gate: sysctlDropins.gate,
    persistent_policy: policy,
    sysctl_assignment_files: assignments,
    sysctls,
  };
}

function exactSymlinkAt(path, target, owner) {
  const expected = owner || { gid: 0, uid: 0 };
  const stat = lstatSync(path, { bigint: true });
  if (!stat.isSymbolicLink() || stat.uid !== BigInt(expected.uid) ||
      stat.gid !== BigInt(expected.gid) || readlinkSync(path) !== target) {
    fail("symlink is not exact: " + path);
  }
  return stat;
}

function ensureSymlink(path, target, quarantine, options) {
  const config = options || {};
  function boundary(name) {
    if (typeof config.afterBoundary === "function") config.afterBoundary(name);
  }
  if (quarantine !== undefined) {
    let quarantined;
    try {
      quarantined = exactSymlinkAt(quarantine, target, config.owner);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    if (quarantined !== undefined) {
      try {
        const live = exactSymlinkAt(path, target, config.owner);
        if (live.dev !== quarantined.dev || live.ino !== quarantined.ino) {
          fail("live symlink differs from retained quarantine: " + path);
        }
        unlinkSync(quarantine);
        boundary("ensure-unlink-quarantine");
        fsyncDirectory(dirname(quarantine));
        boundary("ensure-fsync-after-quarantine-unlink");
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
        boundary("ensure-quarantine-live-observed-absent");
        try {
          linkSync(quarantine, path);
        } catch (linkError) {
          if (linkError.code !== "EEXIST") throw linkError;
          const racedLive = exactSymlinkAt(path, target, config.owner);
          const retained = exactSymlinkAt(quarantine, target, config.owner);
          if (racedLive.dev !== retained.dev || racedLive.ino !== retained.ino) {
            fail("live symlink raced retained quarantine publication: " + path);
          }
        }
        boundary("ensure-link-quarantine-to-live");
        fsyncDirectory(dirname(path));
        boundary("ensure-fsync-after-quarantine-link");
        const linkedLive = exactSymlinkAt(path, target, config.owner);
        const linkedQuarantine = exactSymlinkAt(quarantine, target, config.owner);
        if (linkedLive.dev !== linkedQuarantine.dev || linkedLive.ino !== linkedQuarantine.ino) {
          fail("published symlink differs from retained quarantine: " + path);
        }
        boundary("ensure-verify-quarantine-link");
        unlinkSync(quarantine);
        boundary("ensure-unlink-quarantine");
        fsyncDirectory(dirname(quarantine));
        boundary("ensure-fsync-after-quarantine-unlink");
      }
    }
  }
  try {
    exactSymlinkAt(path, target, config.owner);
    fsyncDirectory(dirname(path));
    boundary("ensure-fsync-existing");
    exactSymlinkAt(path, target, config.owner);
    boundary("ensure-verify-existing");
    return;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  symlinkSync(target, path);
  boundary("ensure-create-symlink");
  fsyncDirectory(dirname(path));
  boundary("ensure-fsync-created");
  exactSymlinkAt(path, target, config.owner);
  boundary("ensure-verify-created");
}

function removeSymlinkQuarantine(path, target, quarantine, options) {
  const config = options || {};
  function boundary(name) {
    if (typeof config.afterBoundary === "function") config.afterBoundary(name);
  }
  let quarantined;
  try {
    quarantined = exactSymlinkAt(quarantine, target, config.owner);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  if (quarantined !== undefined) {
    try {
      const live = exactSymlinkAt(path, target, config.owner);
      if (live.dev !== quarantined.dev || live.ino !== quarantined.ino) {
        fail("live symlink changed while exact quarantine was retained");
      }
      unlinkSync(path);
      boundary("remove-replay-unlink-live");
      fsyncDirectory(dirname(path));
      boundary("remove-replay-fsync-live");
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    unlinkSync(quarantine);
    boundary("remove-replay-unlink-quarantine");
    fsyncDirectory(dirname(quarantine));
    boundary("remove-replay-fsync-quarantine");
    return;
  }
  let live;
  try {
    live = exactSymlinkAt(path, target, config.owner);
  } catch (error) {
    if (error.code === "ENOENT") {
      fsyncDirectory(dirname(path));
      boundary("remove-fsync-already-absent");
      return;
    }
    throw error;
  }
  linkSync(path, quarantine);
  boundary("remove-link-quarantine");
  fsyncDirectory(dirname(path));
  boundary("remove-fsync-link");
  quarantined = exactSymlinkAt(quarantine, target, config.owner);
  const linkedLive = exactSymlinkAt(path, target, config.owner);
  boundary("remove-verify-linked-pair");
  if (live.dev !== quarantined.dev || live.ino !== quarantined.ino ||
      linkedLive.dev !== quarantined.dev || linkedLive.ino !== quarantined.ino) {
    unlinkSync(quarantine);
    fsyncDirectory(dirname(quarantine));
    fail("symlink changed during no-clobber quarantine link");
  }
  unlinkSync(path);
  boundary("remove-unlink-live");
  fsyncDirectory(dirname(path));
  boundary("remove-fsync-live-unlink");
  exactSymlinkAt(quarantine, target, config.owner);
  boundary("remove-verify-quarantine");
  unlinkSync(quarantine);
  boundary("remove-unlink-quarantine");
  fsyncDirectory(dirname(quarantine));
  boundary("remove-fsync-quarantine-unlink");
}

export function ensureSymlinkForTest(path, target, quarantine, options) {
  ensureSymlink(path, target, quarantine, options);
}

export function removeSymlinkForTest(path, target, quarantine, options) {
  removeSymlinkQuarantine(path, target, quarantine, options);
}

function atomicJsonPin(path, value, owner) {
  const bytes = Buffer.from(canonicalJson(value), "utf8");
  const metadata = owner || { gid: 0, uid: 0 };
  return {
    bytes_base64: bytes.toString("base64"),
    gid: metadata.gid,
    mode: "0600",
    nlink: 1,
    path,
    sha256: sha256(bytes),
    size: bytes.length,
    uid: metadata.uid,
  };
}

function removeExactJsonByQuarantine(path, value) {
  const expected = Buffer.from(canonicalJson(value), "utf8");
  const quarantine = path + ".terminal-quarantine";
  let current;
  try {
    current = openBoundRegular(path, "exact JSON removal");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    const retained = openBoundRegular(quarantine, "retained terminal JSON quarantine");
    if (!retained.bytes.equals(expected) || retained.pin.uid !== 0 || retained.pin.gid !== 0 ||
        retained.pin.mode !== "0600") {
      fail("retained terminal JSON quarantine bytes/metadata drifted");
    }
    unlinkSync(quarantine);
    fsyncDirectory(dirname(quarantine));
    return;
  }
  if (!current.bytes.equals(expected) || current.pin.uid !== 0 || current.pin.gid !== 0 ||
      current.pin.mode !== "0600") {
    fail("exact JSON removal bytes/metadata drifted");
  }
  try {
    lstatSync(quarantine);
    fail("terminal JSON quarantine already exists");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  renameSync(path, quarantine);
  try {
    const moved = openBoundRegular(quarantine, "terminal JSON quarantine");
    if (moved.identity.dev !== current.identity.dev || moved.identity.ino !== current.identity.ino ||
        !moved.bytes.equals(expected) || moved.pin.uid !== 0 || moved.pin.gid !== 0 ||
        moved.pin.mode !== "0600") {
      fail("terminal JSON removal raced");
    }
  } catch (cause) {
    renameSync(quarantine, path);
    fsyncDirectory(dirname(path));
    throw cause;
  }
  fsyncDirectory(dirname(path));
  unlinkSync(quarantine);
  fsyncDirectory(dirname(path));
}

function exactLockDirectory(path, owner) {
  const expected = owner || { gid: 0, uid: 0 };
  const stat = lstatSync(path, { bigint: false });
  if (!stat.isDirectory() || stat.isSymbolicLink() ||
      stat.uid !== expected.uid || stat.gid !== expected.gid ||
      modeText(stat) !== "0700") {
    fail("persistent lock directory metadata drifted");
  }
}

function assertClosedLockSet(path, requireCurrent, owner) {
  const root = dirname(path);
  exactLockDirectory(root, owner);
  const current = basename(path);
  const prepared = current + ".pending";
  const entries = readdirSync(root).sort();
  if (entries.some(function (entry) { return entry !== current && entry !== prepared; }) ||
      entries.length > 1 || (requireCurrent && entries.length !== 1)) {
    fail("persistent lock directory contains a foreign or missing ceremony generation");
  }
  return entries.length !== 0;
}

function recoverLockOwnerGeneration(path, expected, options) {
  const config = typeof options === "boolean" ? { repairEmpty: options } : (options || {});
  const ownerMetadata = config.owner || { gid: 0, uid: 0 };
  function boundary(name) {
    if (typeof config.afterBoundary === "function") config.afterBoundary(name);
  }
  exactLockDirectory(path, ownerMetadata);
  const ownerPath = join(path, "owner.json");
  const pendingPath = ownerPath + ".pending";
  const quarantinePath = ownerPath + ".terminal-quarantine";
  const entries = readdirSync(path).sort();
  if (entries.length === 0 && config.repairEmpty) {
    atomicCreatePinnedForTest(atomicJsonPin(ownerPath, expected, ownerMetadata), {
      tempPath: pendingPath,
    });
    boundary("lock-owner-published");
    fsyncDirectory(path);
    boundary("lock-owner-directory-fsynced");
    return expected;
  }
  const allowed = [
    ["owner.json"],
    ["owner.json", "owner.json.pending"],
    ["owner.json.pending"],
    ["owner.json.terminal-quarantine"],
  ];
  if (!allowed.some(function (candidate) { return same(entries, candidate); })) {
    fail("persistent lock contains an unknown generation");
  }
  let owner;
  if (entries[0] === "owner.json.terminal-quarantine") {
    owner = optionalExactJson(quarantinePath, ownerMetadata);
  } else {
    owner = normalizePublishedJson(ownerPath, pendingPath, ownerMetadata);
    if (owner === null) {
      owner = optionalExactJson(pendingPath, ownerMetadata);
      if (!same(owner, expected)) fail("persistent prepared lock owner differs");
      atomicCreatePinnedForTest(atomicJsonPin(ownerPath, owner, ownerMetadata), { tempPath: pendingPath });
      owner = normalizePublishedJson(ownerPath, pendingPath, ownerMetadata);
    }
  }
  if (!same(owner, expected)) fail("persistent recovery lock owner differs");
  return owner;
}

export function recoverEmptyLockOwnerForTest(path, expected, options) {
  return recoverLockOwnerGeneration(path, expected, {
    owner: options?.owner,
    repairEmpty: true,
  });
}

function peekAtomicJsonState(path, tempPath) {
  const quarantinePath = path + ".terminal-quarantine";
  const visible = peekPublishedJson(path, tempPath);
  if (visible !== null) {
    if (pathExistsNoFollow(quarantinePath)) {
      fail("published JSON and terminal quarantine coexist: " + path);
    }
    return visible;
  }
  const quarantine = optionalExactJson(quarantinePath);
  const prepared = optionalExactJson(tempPath);
  if (quarantine !== null && prepared !== null) {
    fail("prepared JSON and terminal quarantine coexist: " + path);
  }
  return quarantine || prepared;
}

function peekLockOwnerGeneration(path, owner) {
  let actualPath = path;
  try {
    if (!assertClosedLockSet(path, false, owner)) return null;
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
  if (!pathExistsNoFollow(path)) actualPath = path + ".pending";
  exactLockDirectory(actualPath, owner);
  const ownerPath = join(actualPath, "owner.json");
  const entries = readdirSync(actualPath).sort();
  const allowed = [
    [],
    ["owner.json"],
    ["owner.json", "owner.json.pending"],
    ["owner.json.pending"],
    ["owner.json.terminal-quarantine"],
  ];
  if (!allowed.some(function (candidate) { return same(entries, candidate); })) {
    fail("persistent transaction lease contains an unknown generation");
  }
  const entriesAreEmpty = entries.length === 0;
  if (entriesAreEmpty) return null;
  const visible = peekPublishedJson(ownerPath, ownerPath + ".pending", owner);
  if (visible !== null) return visible;
  return optionalExactJson(ownerPath + ".terminal-quarantine", owner) ||
    optionalExactJson(ownerPath + ".pending", owner);
}

function recoverLockDirectoryGeneration(path, expected, options) {
  const config = options || {};
  const metadata = config.owner || { gid: 0, uid: 0 };
  function boundary(name) {
    if (typeof config.afterBoundary === "function") config.afterBoundary(name);
  }
  assertClosedLockSet(path, false, metadata);
  const preparedPath = path + ".pending";
  if (!pathExistsNoFollow(path) && !pathExistsNoFollow(preparedPath)) {
    mkdirSync(preparedPath, { mode: 0o700 });
    boundary("lock-mkdir-prepared");
    atomicCreatePinnedForTest(
      atomicJsonPin(join(preparedPath, "owner.json"), expected, metadata),
      { tempPath: join(preparedPath, "owner.json.pending") },
    );
    fsyncDirectory(preparedPath);
    fsyncDirectory(dirname(preparedPath));
  }
  if (!pathExistsNoFollow(path)) {
    recoverLockOwnerGeneration(preparedPath, expected, {
      afterBoundary: config.afterBoundary,
      owner: metadata,
      repairEmpty: true,
    });
    const preparedOwner = peekLockOwnerGeneration(path, metadata);
    if (!same(preparedOwner, expected)) fail("prepared transaction lock owner differs from lease");
    renameSync(preparedPath, path);
    boundary("lock-rename-prepared-current");
    fsyncDirectory(dirname(path));
    boundary("lock-parent-fsynced");
  }
  recoverLockOwnerGeneration(path, expected, {
    afterBoundary: config.afterBoundary,
    owner: metadata,
    repairEmpty: true,
  });
  return expected;
}

export function recoverLockDirectoryGenerationForTest(path, expected, options) {
  return recoverLockDirectoryGeneration(path, expected, options);
}

export function realOps(plan) {
  let maintenanceLocksVerified = false;
  let actionUsesPlanBoot = null;
  function requireMutationLease(label) {
    if (!maintenanceLocksVerified) {
      fail(label + " requires inherited maintenance locks to be proven first");
    }
  }
  const ops = {
    async acquireLock(path, context, lease) {
      requireMutationLease("acquire transaction lease");
      validateLease(lease, plan, context, "new transaction lease");
      ensureStateParents(plan);
      if (assertClosedLockSet(path, false)) {
        fail("persistent ceremony lock exists; recovery approval is required");
      }
      if (peekAtomicJsonState(plan.transaction.lease_path, plan.transaction.temp_paths.lease_prepared) !== null) {
        fail("persistent transaction lease exists; recovery approval is required");
      }
      atomicCreatePinnedForTest(atomicJsonPin(plan.transaction.lease_path, lease), {
        tempPath: plan.transaction.temp_paths.lease_prepared,
      });
      const preparedPath = plan.transaction.temp_paths.lock_prepared;
      try {
        mkdirSync(preparedPath, { mode: 0o700 });
      } catch (error) {
        if (error.code === "EEXIST") fail("persistent ceremony lock exists; recovery approval is required");
        throw error;
      }
      const owner = lease;
      atomicCreatePinnedForTest(atomicJsonPin(join(preparedPath, "owner.json"), owner), {
        tempPath: join(preparedPath, "owner.json.pending"),
      });
      fsyncDirectory(preparedPath);
      fsyncDirectory(dirname(preparedPath));
      renameSync(preparedPath, path);
      fsyncDirectory(dirname(path));
      return this.makeRelease(path, owner);
    },
    async recoverLock(path, context, lease) {
      requireMutationLease("recover transaction lease");
      validateLease(lease, plan, context, "recovered transaction lease");
      const durableLease = normalizePreparedJsonPublication(
        plan.transaction.lease_path,
        plan.transaction.temp_paths.lease_prepared,
      ) || optionalExactJson(plan.transaction.lease_path + ".terminal-quarantine");
      if (!same(durableLease, lease)) fail("durable transaction lease differs from recovery approval");
      recoverLockDirectoryGeneration(path, lease);
      return this.makeRelease(path, lease);
    },
    makeRelease(path, owner) {
      return async function () {
        requireMutationLease("release transaction lease");
        if (pathExistsNoFollow(path) || pathExistsNoFollow(path + ".pending")) {
          if (!pathExistsNoFollow(path)) {
            renameSync(path + ".pending", path);
            fsyncDirectory(dirname(path));
          }
          recoverLockOwnerGeneration(path, owner, true);
          removeExactJsonByQuarantine(join(path, "owner.json"), owner);
          rmdirSync(path);
          fsyncDirectory(dirname(path));
        }
        removeExactJsonByQuarantine(plan.transaction.lease_path, owner);
      };
    },
    async assertSysctls(expected) {
      for (const key of Object.keys(expected)) {
        if (readSysctl(key) !== expected[key]) fail(key + " readback differs");
      }
    },
    async createPending(path, pending) {
      requireMutationLease("create pending state");
      const tempPath = plan.transaction.temp_paths.pending_prepared;
      const existing = normalizePublishedJson(path, tempPath);
      if (existing !== null) {
        if (!same(existing, pending)) fail("pending state already exists with different lineage");
        return;
      }
      atomicCreatePinnedForTest(atomicJsonPin(path, pending), {
        tempPath,
      });
    },
    async createPreflight(preflight) {
      requireMutationLease("create preflight intent");
      validatePreflight(preflight, plan, {
        planSha256: preflight.plan_sha256,
        sourceSha256: preflight.source_sha256,
      }, "new preflight intent");
      const existing = normalizePublishedJson(
        plan.transaction.preflight_path,
        plan.transaction.temp_paths.preflight_prepared,
      );
      if (existing !== null) {
        if (!same(existing, preflight)) fail("preflight intent already has different lineage");
        return;
      }
      atomicCreatePinnedForTest(atomicJsonPin(plan.transaction.preflight_path, preflight), {
        tempPath: plan.transaction.temp_paths.preflight_prepared,
      });
    },
    async clearPending(path, pending) {
      requireMutationLease("clear pending state");
      removeExactJsonByQuarantine(path, pending);
    },
    async finalizeTerminal(lockPath, pendingPath, receipt, context) {
      requireMutationLease("finalize terminal state");
      const lease = await this.readLease();
      if (lease === null) {
        if (await this.readPending(pendingPath) !== null || await this.readPreflight() !== null) {
          fail("terminal cleanup state exists without its durable transaction lease");
        }
        assertSnapshot(await this.inspect(), receipt.post_state, "already-clean terminal post_state");
        return;
      }
      await this.recoverLock(lockPath, context, lease);
      const pending = normalizePublishedJson(
        pendingPath,
        plan.transaction.temp_paths.pending_prepared,
      ) || optionalExactJson(pendingPath + ".terminal-quarantine");
      if (pending !== null) {
        if (pending.kind !== PENDING_KIND || pending.ceremony_id !== plan.ceremony_id ||
            pending.plan_sha256 !== context.planSha256 ||
            !same(pending.receipt_candidate, receipt)) {
          fail("terminal receipt has an unknown retained pending generation");
        }
        removeRetainedAdjacentGeneration(
          plan.transaction.temp_paths.state_exchange,
          pending,
          "terminal pending exchange",
        );
        removeExactJsonByQuarantine(pendingPath, pending);
      } else {
        readRetainedAdjacentGeneration(
          plan.transaction.temp_paths.state_exchange,
          null,
          "terminal pending exchange",
        );
      }
      const preflight = normalizePublishedJson(
        plan.transaction.preflight_path,
        plan.transaction.temp_paths.preflight_prepared,
      ) || optionalExactJson(plan.transaction.preflight_path + ".terminal-quarantine");
      if (preflight !== null) {
        validatePreflight(preflight, plan, context, "terminal preflight intent");
        if (preflight.mode !== lease.mode ||
            preflight.original_approval_sha256 !== lease.original_approval_sha256 ||
            receipt.preflight_sha256 !== sha256(Buffer.from(canonicalJson(preflight), "utf8"))) {
          fail("terminal receipt has an unknown retained preflight generation");
        }
        removeRetainedAdjacentGeneration(
          plan.transaction.temp_paths.preflight_exchange,
          preflight,
          "terminal preflight exchange",
        );
        removeExactJsonByQuarantine(plan.transaction.preflight_path, preflight);
      } else {
        readRetainedAdjacentGeneration(
          plan.transaction.temp_paths.preflight_exchange,
          null,
          "terminal preflight exchange",
        );
      }
      await this.removeGuard(plan.candidate.guard_unit, plan.candidate.guard_enablement);
      await this.reloadManager();
      await this.assertRuntime(
        receipt.kind === RECEIPT_KIND
          ? "apply-cleanup-pre-release"
          : "rollback-cleanup-pre-release",
      );
      assertSnapshot(
        await this.inspect(),
        receipt.post_state,
        "terminal cleanup pre-release post_state",
      );
      const release = this.makeRelease(lockPath, lease);
      await release();
      assertSnapshot(await this.inspect(), receipt.post_state, "terminal cleanup post_state");
    },
    async ensureApportEnablement(link) {
      requireMutationLease("ensure Apport enablement");
      ensureSymlink(
        link.path,
        link.target,
        plan.transaction.temp_paths.apport_enablement_quarantine,
      );
    },
    async ensureApportMask(link) {
      requireMutationLease("ensure Apport mask");
      ensureSymlink(
        link.path,
        link.target,
        plan.transaction.temp_paths.apport_mask_quarantine,
      );
    },
    async ensureGuard(unit, enablement) {
      requireMutationLease("ensure boot and activation gates");
      ensureApportGateDirectory();
      ensurePinnedWithQuarantine(
        plan.candidate.apport_gate,
        plan.transaction.temp_paths.apport_gate_pending,
        plan.transaction.temp_paths.apport_gate_quarantine,
        { plan },
      );
      ensureSysctlGateDirectory();
      ensurePinnedWithQuarantine(
        plan.candidate.sysctl_gate,
        plan.transaction.temp_paths.sysctl_gate_pending,
        plan.transaction.temp_paths.sysctl_gate_quarantine,
        { plan },
      );
      ensurePinnedWithQuarantine(
        unit,
        plan.transaction.temp_paths.guard_unit_pending,
        plan.transaction.temp_paths.guard_unit_quarantine,
        { plan },
      );
      ensureSymlink(
        enablement.path,
        enablement.target,
        plan.transaction.temp_paths.guard_enablement_quarantine,
      );
    },
    async inspect() {
      return realInspect(plan);
    },
    async installPersistent(pin) {
      requireMutationLease("install persistent sysctl policy");
      ensureSysctlGateDirectory();
      ensurePinnedWithQuarantine(
        plan.candidate.sysctl_credential_closure,
        plan.transaction.temp_paths.sysctl_credential_closure_pending,
        plan.transaction.temp_paths.sysctl_credential_closure_quarantine,
        { plan },
      );
      atomicCreatePinnedForTest(pin, {
        tempPath: plan.transaction.temp_paths.persistent_policy_exchange,
      });
    },
    async publishReceipt(path, receipt) {
      requireMutationLease("publish terminal receipt");
      const tempPath = path === plan.transaction.receipt_path
        ? plan.transaction.temp_paths.receipt_pending
        : plan.transaction.temp_paths.rollback_receipt_pending;
      const result = atomicCreatePinnedForTest(atomicJsonPin(path, receipt), { tempPath });
      if (result.status === "visible-commit-uncertain") {
        throw new Error("receipt visible after commit-uncertain publication");
      }
    },
    async publishReceiptAfterFullInspection(path, receipt, expected, label) {
      requireMutationLease("inspect and publish terminal receipt");
      // Deliberately keep the final synchronous host inspection and atomic
      // publication in one operation. There must be no JavaScript await or
      // callback boundary between these two point-in-time actions.
      assertSnapshot(realInspect(plan), expected, label);
      const tempPath = path === plan.transaction.receipt_path
        ? plan.transaction.temp_paths.receipt_pending
        : plan.transaction.temp_paths.rollback_receipt_pending;
      const result = atomicCreatePinnedForTest(atomicJsonPin(path, receipt), { tempPath });
      if (result.status === "visible-commit-uncertain") {
        throw new Error("receipt visible after commit-uncertain publication");
      }
    },
    async readPending(path) {
      const tempPath = plan.transaction.temp_paths.pending_prepared;
      const value = peekAtomicJsonState(path, tempPath);
      if (value !== null && value.generation === 0) validateInitialPending(value, plan);
      readRetainedAdjacentGeneration(
        plan.transaction.temp_paths.state_exchange,
        value,
        "retained pending exchange",
      );
      return value;
    },
    async readPreflight() {
      const value = peekAtomicJsonState(
        plan.transaction.preflight_path,
        plan.transaction.temp_paths.preflight_prepared,
      );
      readRetainedAdjacentGeneration(
        plan.transaction.temp_paths.preflight_exchange,
        value,
        "retained preflight exchange",
      );
      return value;
    },
    async readLease() {
      return peekAtomicJsonState(
        plan.transaction.lease_path,
        plan.transaction.temp_paths.lease_prepared,
      );
    },
    async readRecoverySubject() {
      const pending = await this.readPending(plan.transaction.pending_path);
      const preflight = await this.readPreflight();
      const lease = await this.readLease();
      const lockOwner = peekLockOwnerGeneration(plan.transaction.lock_path);
      if ((pending !== null || preflight !== null || lockOwner !== null) && lease === null) {
        fail("durable transaction state exists without its approval-bound lease");
      }
      if (pending !== null && preflight === null) {
        fail("durable pending state exists without its preflight lineage");
      }
      if (lockOwner !== null && !same(lockOwner, lease)) {
        fail("persistent lock owner differs from its durable transaction lease");
      }
      if (pending !== null) return { kind: "pending", value: pending };
      if (preflight !== null) return { kind: "preflight", value: preflight };
      return lease === null ? null : { kind: "lease", value: lease };
    },
    async readReceipt(path) {
      const tempPath = path === plan.transaction.receipt_path
        ? plan.transaction.temp_paths.receipt_pending
        : plan.transaction.temp_paths.rollback_receipt_pending;
      return peekPublishedJson(path, tempPath);
    },
    async removeApportEnablement(link) {
      requireMutationLease("remove Apport enablement");
      removeSymlinkQuarantine(
        link.path,
        link.target,
        plan.transaction.temp_paths.apport_enablement_quarantine,
      );
    },
    async removeApportMask(link) {
      requireMutationLease("remove Apport mask");
      removeSymlinkQuarantine(
        link.path,
        link.target,
        plan.transaction.temp_paths.apport_mask_quarantine,
      );
    },
    async removeGuard(unit, enablement) {
      requireMutationLease("remove boot and activation gates");
      removeSymlinkQuarantine(
        enablement.path,
        enablement.target,
        plan.transaction.temp_paths.guard_enablement_quarantine,
      );
      normalizeAtomicPublicationIfPresent(
        unit,
        plan.transaction.temp_paths.guard_unit_pending,
      );
      removeByQuarantine(
        plan,
        unit,
        plan.transaction.temp_paths.guard_unit_quarantine,
      );
      normalizeAtomicPublicationIfPresent(
        plan.candidate.apport_gate,
        plan.transaction.temp_paths.apport_gate_pending,
      );
      removeByQuarantine(
        plan,
        plan.candidate.apport_gate,
        plan.transaction.temp_paths.apport_gate_quarantine,
      );
      removeApportGateDirectory();
      normalizeAtomicPublicationIfPresent(
        plan.candidate.sysctl_gate,
        plan.transaction.temp_paths.sysctl_gate_pending,
      );
      removeByQuarantine(
        plan,
        plan.candidate.sysctl_gate,
        plan.transaction.temp_paths.sysctl_gate_quarantine,
      );
      removeSysctlGateDirectory();
    },
    async removePersistent(pin) {
      requireMutationLease("remove persistent sysctl policy");
      normalizeAtomicPublicationIfPresent(
        plan.candidate.sysctl_credential_closure,
        plan.transaction.temp_paths.sysctl_credential_closure_pending,
      );
      removeByQuarantine(
        plan,
        plan.candidate.sysctl_credential_closure,
        plan.transaction.temp_paths.sysctl_credential_closure_quarantine,
      );
      removeByQuarantine(
        plan,
        pin,
        plan.transaction.temp_paths.persistent_policy_exchange,
      );
    },
    async reloadManager() {
      requireMutationLease("reload systemd manager");
      runCommand(
        "/usr/bin/busctl",
        ["--system", "call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
          "org.freedesktop.systemd1.Manager", "Reload"],
        "systemd Manager.Reload",
      );
    },
    async assertRuntime(phase) {
      if (actionUsesPlanBoot === null) fail("runtime validation precedes action-boot verification");
      const configurationBefore = systemdConfigurationGeneration(plan);
      const snapshot = runtimeServiceSnapshot(phase);
      const configurationAfter = systemdConfigurationGeneration(plan);
      if (configurationBefore !== configurationAfter) {
        fail("systemd configuration changed across the D-Bus GetAll snapshot during " + phase);
      }
      assertApportRuntimeLineageForTest(
        snapshot,
        plan.preimage.apport_runtime_observation,
        actionUsesPlanBoot,
        phase,
      );
    },
    async verifyHostAndTools(approved, actionBootId, freshBootAllowed) {
      if (process.platform !== "linux" || process.geteuid?.() !== 0) fail("host action requires Linux EUID 0");
      const boot = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
      if (boot !== actionBootId) fail("action boot differs from fresh approval");
      if (!freshBootAllowed && boot !== approved.host.plan_boot_id) fail("apply left the plan boot");
      actionUsesPlanBoot = boot === approved.host.plan_boot_id;
      verifyInheritedMaintenanceLocks();
      for (const protectedDirectory of [
        "/etc",
        "/etc/sysctl.d",
        "/etc/systemd",
        "/etc/systemd/system",
        "/etc/systemd/system/multi-user.target.wants",
        "/etc/systemd/system/sysinit.target.wants",
        "/usr/lib/systemd/system",
        "/usr/share/apport",
      ]) {
        assertRootDirectory(protectedDirectory);
      }
      const machineId = openBoundRegular("/etc/machine-id", "machine-id", 4096);
      if (machineId.pin.sha256 !== approved.host.machine_id_sha256) fail("machine-id drifted");
      const osPath = realpathSync("/etc/os-release");
      const os = openBoundRegular(osPath, "os-release");
      exactPin(os, approved.host.os_release, "os-release");
      const version = runCommand("/usr/bin/systemctl", ["--version"], "systemd version").split("\n")[0];
      if (version !== approved.host.systemd_version) fail("systemd version drifted");
      const official = openBoundRegular(APPORT_UNIT_PATH, "official Noble Apport unit");
      exactPin(official, approved.official_noble_apport.unit, "official Noble Apport unit");
      const officialHandler = openBoundRegular(APPORT_HANDLER_PATH, "official Noble Apport handler");
      exactPin(
        officialHandler,
        approved.official_noble_apport.handler,
        "official Noble Apport handler",
      );
      exactSystemdSysctlInputs(approved);
      for (const key of Object.keys(approved.executor)) {
        const opened = openBoundRegular(approved.executor[key].path, "executor " + key);
        exactPin(opened, approved.executor[key], "executor " + key);
        if (realpathSync(approved.executor[key].path) !== approved.executor[key].path) {
          fail("executor " + key + " is not canonical");
        }
      }
      if (realpathSync(process.execPath) !== approved.executor.node.path ||
          realpathSync(fileURLToPath(import.meta.url)) !== approved.executor.source.path) {
        fail("running executable/source differs from plan");
      }
      maintenanceLocksVerified = true;
    },
    async writePreflight(preflight) {
      requireMutationLease("advance preflight generation");
      validatePreflight(preflight, plan, {
        planSha256: preflight.plan_sha256,
        sourceSha256: preflight.source_sha256,
      }, "advanced preflight intent");
      const path = plan.transaction.preflight_path;
      const old = normalizePreparedJsonPublication(
        path,
        plan.transaction.temp_paths.preflight_prepared,
      );
      if (old === null || old.kind !== PREFLIGHT_KIND || !isDirectGenerationSuccessor(preflight, old)) {
        fail("preflight intent is not the exact next linked generation");
      }
      const exchangePath = plan.transaction.temp_paths.preflight_exchange;
      removeRetainedAdjacentGeneration(exchangePath, old, "retained preflight exchange");
      replaceByExchange(
        plan,
        atomicJsonPin(path, preflight),
        [atomicJsonPin(path, old)],
        exchangePath,
      );
      try { unlinkSync(exchangePath); } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
      fsyncDirectory(dirname(path));
    },
    async writePending(path, pending) {
      requireMutationLease("advance pending generation");
      validatePendingBase(pending, plan, {
        planSha256: pending.plan_sha256,
        sourceSha256: pending.source_sha256,
      }, "advanced pending state");
      const old = normalizePreparedJsonPublication(path, path + ".pending");
      if (old === null || old.kind !== PENDING_KIND ||
          !isDirectGenerationSuccessor(pending, old)) {
        fail("pending state is not the exact next linked generation");
      }
      const exchangePath = plan.transaction.temp_paths.state_exchange;
      removeRetainedAdjacentGeneration(exchangePath, old, "retained pending exchange");
      const pin = atomicJsonPin(path, pending);
      replaceByExchange(
        plan,
        pin,
        [atomicJsonPin(path, old)],
        exchangePath,
      );
      try { unlinkSync(exchangePath); } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
      fsyncDirectory(dirname(path));
    },
    async writeSysctl(name, value) {
      requireMutationLease("write host sysctl");
      writeSysctl(name, value);
    },
  };
  return ops;
}

function observePlan(ceremonyId) {
  if (process.platform !== "linux" || process.geteuid?.() !== 0) fail("observe-plan requires Linux EUID 0");
  if (!SLUG.test(ceremonyId)) fail("invalid ceremony id");
  const unit = openBoundRegular(APPORT_UNIT_PATH, "official Noble Apport unit");
  if (unit.bytes.toString("utf8") !== NOBLE_APPORT_UNIT_BYTES ||
      unit.pin.sha256 !== NOBLE_APPORT_UNIT_SHA256) {
    fail("installed Apport unit does not equal official Noble 2.28.2 bytes");
  }
  const handler = openBoundRegular(APPORT_HANDLER_PATH, "official Noble Apport handler");
  if (handler.pin.sha256 !== NOBLE_APPORT_HANDLER_SOURCE_SHA256 ||
      handler.pin.size !== 44730 || handler.pin.uid !== 0 || handler.pin.gid !== 0 ||
      handler.pin.mode !== "0755") {
    fail("installed Apport handler does not equal official Noble 2.28.2 source bytes");
  }
  const crash = crashDirectorySnapshot();
  const osPath = realpathSync("/etc/os-release");
  const os = openBoundRegular(osPath, "os-release");
  const source = openBoundRegular(realpathSync(fileURLToPath(import.meta.url)), "ceremony source");
  const systemdSysctlUnit = openBoundRegular(
    SYSTEMD_SYSCTL_UNIT_PATH,
    "systemd-sysctl unit",
  );
  const systemdSysctlBinary = openBoundRegular(
    SYSTEMD_SYSCTL_BINARY_PATH,
    "systemd-sysctl binary",
  );
  const systemdSysctlEnablementStat = exactSymlinkAt(
    SYSTEMD_SYSCTL_ENABLEMENT_PATH,
    SYSTEMD_SYSCTL_ENABLEMENT_TARGET,
  );
  if (systemdSysctlEnablementStat.uid !== 0n || systemdSysctlEnablementStat.gid !== 0n) {
    fail("systemd-sysctl enablement is not root-owned");
  }
  const candidateGate = embeddedPin(APPORT_GATE_PATH, APPORT_GATE_BYTES, "0644");
  const candidateSysctlGate = embeddedPin(SYSCTL_GATE_PATH, SYSCTL_GATE_BYTES, "0644");
  const candidateSysctlCredentialClosure = embeddedPin(
    SYSCTL_CREDENTIAL_CLOSURE_PATH,
    SYSCTL_CREDENTIAL_CLOSURE_BYTES,
    "0644",
  );
  const candidateGuard = embeddedPin(GUARD_UNIT_PATH, guardUnitBytes(ceremonyId), "0644");
  const managedLoadPaths = scanManagedUnitLoadPaths(reviewedManagerUnitPath());
  if (!same(
    managedLoadPaths[SYSTEMD_SYSCTL_UNIT].fragment_paths,
    [SYSTEMD_SYSCTL_UNIT_PATH],
  ) || !same(
    managedLoadPaths[SYSTEMD_SYSCTL_UNIT].enablement_paths,
    [SYSTEMD_SYSCTL_ENABLEMENT_PATH],
  )) {
    fail("observe-plan requires exact systemd-sysctl fragment and boot enablement");
  }
  const apportActivation = scanApportActivation(
    undefined,
    candidateGuard,
    candidateGate,
  );
  const observedGate = apportGateSnapshot({ candidate: { apport_gate: candidateGate } });
  const observedSysctlDropins = systemdSysctlDropinsSnapshot({
    candidate: {
      sysctl_credential_closure: candidateSysctlCredentialClosure,
      sysctl_gate: candidateSysctlGate,
    },
  });
  const observedGuard = guardSnapshot({ candidate: { guard_unit: candidateGuard } });
  const observedPolicy = optionalPolicy();
  const exchangeRoot = "/opt/bitcoinpir/payment-v1-rename-exchange";
  const exchangeGenerations = readdirSync(exchangeRoot, { withFileTypes: true }).filter(function (entry) {
    return entry.isDirectory() && /^[0-9a-f]{64}$/u.test(entry.name);
  });
  if (exchangeGenerations.length !== 1) {
    fail("observe-plan requires exactly one content-addressed rename-exchange helper generation");
  }
  const helperPaths = {
    exchange_helper: exchangeRoot + "/" + exchangeGenerations[0].name + "/payment-v1-rename-exchange",
    maintenance_lock_helper: "/usr/local/libexec/bitcoinpir/payment-v1-core-pattern-lock-exec",
  };
  const plan = {
    candidate: {
      apport_gate: candidateGate,
      apport_gate_directory: {
        gid: 0,
        mode: "0755",
        path: APPORT_GATE_DIRECTORY,
        uid: 0,
      },
      apport_mask: { gid: 0, path: APPORT_MASK_PATH, target: APPORT_MASK_TARGET, uid: 0 },
      guard_enablement: { gid: 0, path: GUARD_ENABLEMENT_PATH, target: GUARD_UNIT_PATH, uid: 0 },
      guard_unit: candidateGuard,
      persistent_policy: embeddedPin(PERSISTENT_POLICY_PATH, POLICY_BYTES, "0644"),
      sysctl_credential_closure: candidateSysctlCredentialClosure,
      sysctl_gate: candidateSysctlGate,
      sysctl_gate_directory: {
        gid: 0,
        mode: "0755",
        path: SYSCTL_GATE_DIRECTORY,
        uid: 0,
      },
      sysctls: TARGET_SYSCTLS,
    },
    ceremony_id: ceremonyId,
    executor: {
      busctl: openBoundRegular("/usr/bin/busctl", "busctl").pin,
      exchange_helper: openBoundRegular(helperPaths.exchange_helper, "exchange helper").pin,
      false_handler: openBoundRegular("/usr/bin/false", "false handler").pin,
      maintenance_lock_helper: openBoundRegular(helperPaths.maintenance_lock_helper, "maintenance lock helper").pin,
      node: openBoundRegular("/usr/bin/node", "Node").pin,
      source: source.pin,
      systemctl: openBoundRegular("/usr/bin/systemctl", "systemctl").pin,
    },
    host: {
      machine_id_sha256: openBoundRegular("/etc/machine-id", "machine-id", 4096).pin.sha256,
      os_release: os.pin,
      plan_boot_id: readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim(),
      systemd_version: runCommand("/usr/bin/systemctl", ["--version"], "systemd version").split("\n")[0],
    },
    kind: CEREMONY_KIND,
    official_noble_apport: {
      archive_sha256: NOBLE_APPORT_ARCHIVE_SHA256,
      handler: handler.pin,
      handler_source_sha256: NOBLE_APPORT_HANDLER_SOURCE_SHA256,
      source_url: NOBLE_APPORT_SOURCE_URL,
      unit: { ...unit.pin, bytes_base64: unit.bytes.toString("base64") },
      unit_semantics: {
        exec_start: ["/usr/share/apport/apport --start"],
        exec_stop: ["/usr/share/apport/apport --stop"],
        remain_after_exit: true,
        type: "oneshot",
        wanted_by: ["multi-user.target"],
      },
    },
    preimage: {
      apport_enablement_symlinks: apportActivation.enablement_symlinks,
      apport_gate_state: observedGate.state,
      apport_mask_state: apportActivation.mask.state,
      apport_runtime_observation: publicRuntimeObservation(runtimeServiceSnapshot("fresh-preimage")),
      apport_service: serviceSnapshot({
        official_noble_apport: { unit: { ...unit.pin, bytes_base64: unit.bytes.toString("base64") } },
      }, observedGate),
      crash_directory: crash.directory,
      crash_entries: crash.entries,
      guard_state: observedGuard.state,
      persistent_policy_state: observedPolicy.state,
      preflight_state: [
        PREFLIGHT_PATH,
        PREFLIGHT_PATH + ".pending",
        PREFLIGHT_PATH + ".exchange",
        PREFLIGHT_PATH + ".terminal-quarantine",
      ].some(pathExistsNoFollow) ? "present" : "absent",
      sysctl_credential_closure_state: observedSysctlDropins.credential_closure.state,
      sysctl_gate_state: observedSysctlDropins.gate.state,
      sysctl_assignment_files: scanSysctlAssignments(),
      sysctls: {
        "fs.suid_dumpable": readSysctl("fs.suid_dumpable"),
        "kernel.core_pattern": readSysctl("kernel.core_pattern"),
        "kernel.core_pipe_limit": readSysctl("kernel.core_pipe_limit"),
      },
    },
    rollback_policy: "fresh-receipt-bound-approval-with-reboot-lineage-v2",
    schema_version: 2,
    systemd_sysctl: {
      binary: systemdSysctlBinary.pin,
      enablement: {
        gid: Number(systemdSysctlEnablementStat.gid),
        path: SYSTEMD_SYSCTL_ENABLEMENT_PATH,
        target: SYSTEMD_SYSCTL_ENABLEMENT_TARGET,
        uid: Number(systemdSysctlEnablementStat.uid),
      },
      unit: {
        ...systemdSysctlUnit.pin,
        bytes_base64: systemdSysctlUnit.bytes.toString("base64"),
      },
    },
    transaction: transactionLayout(ceremonyId),
  };
  validatePlan(plan);
  return plan;
}

function parseCanonicalJsonFile(path, label) {
  const opened = openBoundRegular(path, label, MAX_JSON_BYTES);
  const value = parseCanonicalJsonBytes(opened.bytes, label);
  return { sha256: opened.pin.sha256, value };
}

function parseArgs(argv) {
  const command = argv[0];
  const allowed = new Set([
    "apply",
    "early-apport-gate",
    "early-fail-closed",
    "early-sysctl-gate",
    "observe-plan",
    "recover",
    "rollback",
    "validate-plan",
  ]);
  if (!allowed.has(command)) fail("unreviewed command");
  const args = {};
  for (let index = 1; index < argv.length; index += 2) {
    if (!argv[index]?.startsWith("--") || argv[index + 1] === undefined) fail("options require pairs");
    const key = argv[index].slice(2).replaceAll("-", "_");
    if (Object.hasOwn(args, key)) fail("duplicate option " + key);
    args[key] = argv[index + 1];
  }
  return { args, command };
}

function earlyApportGateAllowsActivation() {
  return !pathExistsNoFollow(PREFLIGHT_PATH);
}

function requireDigest(actual, expected, label) {
  validateSha(expected, label);
  if (actual !== expected) fail(label + " differs from exact file");
}

function loadPlan(args) {
  const loaded = parseCanonicalJsonFile(args.plan, "plan");
  validatePlan(loaded.value);
  requireDigest(loaded.sha256, args.approved_plan_sha256, "approved plan SHA-256");
  const source = openBoundRegular(fileURLToPath(import.meta.url), "source");
  requireDigest(source.pin.sha256, args.approved_source_sha256, "approved source SHA-256");
  if (loaded.value.executor.source.sha256 !== source.pin.sha256) fail("plan source pin differs");
  return {
    plan: loaded.value,
    planSha256: loaded.sha256,
    sourceSha256: source.pin.sha256,
  };
}

async function main() {
  process.umask(0o077);
  const parsed = parseArgs(process.argv.slice(2));
  if (parsed.command === "early-apport-gate") {
    exactKeys(parsed.args, [], "early-apport-gate options");
    process.exitCode = earlyApportGateAllowsActivation() ? 0 : 1;
    return;
  }
  if (parsed.command === "early-sysctl-gate") {
    exactKeys(parsed.args, [], "early-sysctl-gate options");
    if (pathExistsNoFollow(PREFLIGHT_PATH)) {
      writeSysctl("kernel.core_pattern", TARGET_CORE_PATTERN);
      writeSysctl("fs.suid_dumpable", "0");
      writeSysctl("kernel.core_pipe_limit", "0");
      process.exitCode = 1;
    } else {
      process.exitCode = 0;
    }
    return;
  }
  if (parsed.command === "early-fail-closed") {
    exactKeys(parsed.args, [], "early-fail-closed options");
    if (pathExistsNoFollow(PREFLIGHT_PATH)) {
      writeSysctl("kernel.core_pattern", TARGET_CORE_PATTERN);
      writeSysctl("fs.suid_dumpable", "0");
      writeSysctl("kernel.core_pipe_limit", "0");
    }
    return;
  }
  if (parsed.command === "observe-plan") {
    exactKeys(parsed.args, ["ceremony_id"], "observe-plan options");
    process.stdout.write(canonicalJson(observePlan(parsed.args.ceremony_id)));
    return;
  }
  exactKeys(parsed.args, parsed.command === "validate-plan"
    ? ["approved_plan_sha256", "approved_source_sha256", "plan"]
    : parsed.command === "apply"
      ? ["approval", "approved_approval_sha256", "approved_plan_sha256", "approved_source_sha256", "plan"]
      : parsed.command === "recover"
        ? ["approved_plan_sha256", "approved_recovery_approval_sha256", "approved_source_sha256", "plan", "recovery_approval"]
        : ["approved_plan_sha256", "approved_receipt_sha256", "approved_rollback_approval_sha256", "approved_source_sha256", "plan", "rollback_approval"],
    "CLI options");
  const context = loadPlan(parsed.args);
  if (parsed.command === "validate-plan") {
    process.stdout.write("core-pattern-plan-v2=PASS sha256=" + context.planSha256 +
      " source_sha256=" + context.sourceSha256 + "\n");
    return;
  }
  const boot = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
  const ops = realOps(context.plan);
  if (parsed.command === "apply") {
    const approval = parseCanonicalJsonFile(parsed.args.approval, "apply approval");
    requireDigest(approval.sha256, parsed.args.approved_approval_sha256, "approved apply approval SHA-256");
    validateApplyApproval(
      approval.value,
      context.plan,
      context.planSha256,
      context.sourceSha256,
      boot,
    );
    Object.assign(context, {
      actionBootId: boot,
      applyApprovalActionBootId: approval.value.action_boot_id,
      approvalSha256: approval.sha256,
      approvedAtUtc: Date.parse(approval.value.approved_at_utc),
    });
    const result = await applyCeremony(context.plan, context, ops);
    process.stdout.write(result.outcome + " receipt_sha256=" + result.receipt_sha256 + "\n");
    return;
  }
  if (parsed.command === "recover") {
    const subject = await ops.readRecoverySubject();
    if (subject === null) fail("durable recovery subject is absent");
    if (subject.kind === "pending") {
      validatePendingBase(subject.value, context.plan, context, "pending recovery subject");
    } else if (subject.kind === "preflight") {
      validatePreflight(subject.value, context.plan, context, "preflight recovery subject");
    } else if (subject.kind === "lease") {
      validateLease(subject.value, context.plan, context, "lease recovery subject");
    } else {
      fail("recovery subject kind is not reviewed");
    }
    const subjectSha256 = sha256(Buffer.from(canonicalJson(subject.value), "utf8"));
    const approval = parseCanonicalJsonFile(parsed.args.recovery_approval, "recovery approval");
    requireDigest(approval.sha256, parsed.args.approved_recovery_approval_sha256, "approved recovery approval SHA-256");
    validateRecoveryApproval(
      approval.value,
      context.plan,
      context.planSha256,
      context.sourceSha256,
      subject.kind,
      subjectSha256,
      subject.value.original_approval_sha256,
      subject.value.mode,
      boot,
    );
    Object.assign(context, {
      actionBootId: boot,
      approvedAtUtc: Date.parse(approval.value.approved_at_utc),
      recoveryApprovedSubjectSha256: approval.value.recovery_subject_sha256,
      recoveryApprovalSha256: approval.sha256,
      recoveryApprovalActionBootId: approval.value.action_boot_id,
      recoverySubjectKind: approval.value.recovery_subject_kind,
    });
    if (subject.value.mode === "rollback") {
      const committedValue = await ops.readReceipt(context.plan.transaction.receipt_path);
      if (committedValue === null) fail("committed receipt for rollback recovery is absent");
      context.applyApprovalSha256 = committedValue.apply_approval_sha256;
      context.receiptSha256 = sha256(Buffer.from(canonicalJson(committedValue), "utf8"));
    }
    const result = await recoverCeremony(context.plan, context, ops);
    process.stdout.write(result.outcome + " receipt_sha256=" + result.receipt_sha256 + "\n");
    return;
  }
  const receiptValue = await ops.readReceipt(context.plan.transaction.receipt_path);
  if (receiptValue === null) fail("committed receipt is absent");
  const receipt = {
    sha256: sha256(Buffer.from(canonicalJson(receiptValue), "utf8")),
    value: receiptValue,
  };
  requireDigest(receipt.sha256, parsed.args.approved_receipt_sha256, "approved receipt SHA-256");
  const approval = parseCanonicalJsonFile(parsed.args.rollback_approval, "rollback approval");
  requireDigest(approval.sha256, parsed.args.approved_rollback_approval_sha256, "approved rollback approval SHA-256");
  validateRollbackApproval(
    approval.value,
    context.plan,
    context.planSha256,
    context.sourceSha256,
    receipt.sha256,
    boot,
  );
  Object.assign(context, {
    actionBootId: boot,
    approvedAtUtc: Date.parse(approval.value.approved_at_utc),
    applyApprovalSha256: receipt.value.apply_approval_sha256,
    receiptSha256: receipt.sha256,
    rollbackApprovalSha256: approval.sha256,
    rollbackApprovalActionBootId: approval.value.action_boot_id,
  });
  const result = await rollbackCeremony(context.plan, context, ops);
  process.stdout.write(result.outcome + " receipt_sha256=" + result.receipt_sha256 + "\n");
}

const isMain = process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (isMain) {
  main().catch(function (error) {
    const outcome = error instanceof CeremonyError ? " outcome=" + error.outcome + " phase=" + error.phase : "";
    process.stderr.write("core-pattern-ceremony-v2: FAIL" + outcome + " " + error.message + "\n");
    process.exitCode = 1;
  });
}
