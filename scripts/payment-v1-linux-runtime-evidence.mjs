#!/usr/bin/env node

// Production runtime evidence is collected and checked in one root-owned Linux
// process.  Offline JSON is only meaningful when its complete SHA-256 digest is
// approved out of band; this program never accepts caller-authored JSON in a
// collection path.

import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  readSync,
  realpathSync,
  statfsSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { pathToFileURL } from "node:url";

import {
  RUNTIME_COLLECTOR,
  RUNTIME_SYSTEMCTL_SHOW_PROPERTIES,
  canonicalJson,
  parseStrictJson,
  runtimeRequestFromManifest,
} from "./payment-v1-rendered-artifact-gate.mjs";

export const LIVE_EVIDENCE_KIND = "bitcoinpir-payment-v1-linux-root-live-v3";
export const STOPPED_EDGE_EVIDENCE_KIND =
  "bitcoinpir-payment-v1-linux-root-stopped-edge-v2";
export const NSS_ENUMERATION_KIND = "getent-passwd-group-plus-id-groups-v2";
export const NSS_BACKEND_PROFILE = "local-files-only-v1";
const LIVE_SCHEMA_VERSION = 3;
const STOPPED_EDGE_SCHEMA_VERSION = 2;
const MAX_JSON_BYTES = 8 * 1024 * 1024;
const MAX_COMMAND_OUTPUT_BYTES = 2 * 1024 * 1024;
const MAX_COLLECTION_SECONDS = 120;
const MAX_NSS_EVIDENCE_BYTES = 2 * 1024 * 1024;
const MAX_NSS_USERS = 4096;
const MAX_NSS_GROUPS = 16384;
const MAX_NSS_GROUP_MEMBERS = 4096;
const MAX_NSS_NAME_BYTES = 128;
const MAX_NSS_ID_COLLECTION_MILLISECONDS = 30_000;
const MAX_NSS_ID_LOOKUP_MILLISECONDS = 2_000;
const MAX_NSS_POLICY_FILE_BYTES = 1024 * 1024;
const MAX_PROC_STAT_BYTES = 16 * 1024;
const MAX_PROC_STATUS_BYTES = 256 * 1024;
const MAX_PROC_CGROUP_BYTES = 64 * 1024;
const MAX_PROC_PROCESSES = 65_536;
const MAX_PROC_THREADS = 262_144;
const MAX_PROC_CREDENTIAL_SCAN_MILLISECONDS = 30_000;
const MAX_PROC_CLOSURE_EVIDENCE_BYTES = 4 * 1024 * 1024;
const PROC_SUPER_MAGIC = 0x9fa0;
export const PROTECTED_PROCESS_ENUMERATION_KIND =
  "procfs-v3-all-thread-protected-credentials-dangerous-capabilities-two-pass-v3";
const CAPABILITY_RECORD_KEYS = Object.freeze([
  "ambient",
  "bounding",
  "effective",
  "inheritable",
  "permitted",
]);
const CAPABILITY_HEX = /^[0-9a-f]{16}$/u;
const CAP_NET_BIND_SERVICE_MASK = 1n << 10n;
const NET_BIND_SERVICE_UNITS = new Set([
  "bitcoinpir-payment-v1-edge.service",
  "bitcoinpir-payment-v1-public-edge.service",
]);
const DANGEROUS_NONROOT_CAPABILITY_BITS = Object.freeze([
  0, // CAP_CHOWN
  1, // CAP_DAC_OVERRIDE
  2, // CAP_DAC_READ_SEARCH
  3, // CAP_FOWNER
  4, // CAP_FSETID
  5, // CAP_KILL
  6, // CAP_SETGID
  7, // CAP_SETUID
  8, // CAP_SETPCAP
  12, // CAP_NET_ADMIN
  13, // CAP_NET_RAW
  15, // CAP_IPC_OWNER
  16, // CAP_SYS_MODULE
  17, // CAP_SYS_RAWIO
  19, // CAP_SYS_PTRACE
  21, // CAP_SYS_ADMIN
  23, // CAP_SYS_NICE
  24, // CAP_SYS_RESOURCE
  27, // CAP_MKNOD
  30, // CAP_AUDIT_CONTROL
  31, // CAP_SETFCAP
  32, // CAP_MAC_OVERRIDE
  33, // CAP_MAC_ADMIN
  34, // CAP_SYSLOG
  37, // CAP_AUDIT_READ
  38, // CAP_PERFMON
  39, // CAP_BPF
  40, // CAP_CHECKPOINT_RESTORE
]);
const DANGEROUS_NONROOT_CAPABILITY_MASK = DANGEROUS_NONROOT_CAPABILITY_BITS.reduce(
  (mask, bit) => mask | (1n << BigInt(bit)),
  0n,
);
const LOCKED_SERVICE_ACCOUNT_SHELLS = Object.freeze([
  "/bin/false",
  "/usr/sbin/nologin",
]);
const REVIEWED_ONESHOT_UNIT = "bitcoinpir-lightning-preflight.service";
const REVIEWED_ONESHOT_FRAGMENT = "/etc/systemd/system/bitcoinpir-lightning-preflight.service";
const REQUIRED_COMMANDS = Object.freeze([
  "/usr/bin/false",
  "/usr/bin/getent",
  "/usr/bin/getfacl",
  "/usr/bin/getfattr",
  "/usr/bin/id",
  "/usr/bin/setpriv",
  "/usr/bin/sha256sum",
  "/usr/bin/stat",
  "/usr/bin/systemctl",
  "/usr/bin/systemd-analyze",
  "/usr/bin/test",
  "/usr/bin/uname",
  "/usr/sbin/getcap",
]);

function fail(message) {
  throw new Error(message);
}

function hashBytes(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function validateDigest(value, label) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value) || /^0{64}$/u.test(value)) {
    fail(`${label} must be a non-zero lowercase SHA-256 digest`);
  }
  return value;
}

function exactKeys(value, keys, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    fail(`${label} keys must equal ${JSON.stringify(expected)}`);
  }
}

function validateAbsolutePath(value, label) {
  if (
    typeof value !== "string" ||
    value.length < 2 ||
    value.length > 512 ||
    !value.startsWith("/") ||
    value.includes("\\") ||
    !/^\/[A-Za-z0-9._/-]+$/u.test(value) ||
    resolve(value) !== value
  ) {
    fail(`${label} must be one canonical absolute ASCII path`);
  }
  return value;
}

function validateUuid(value, label) {
  if (typeof value !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(value)) {
    fail(`${label} must be a lowercase UUID`);
  }
}

function readOneLinkRegular(path, label, maxBytes = MAX_JSON_BYTES) {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
    fail(`${label} must be a one-link regular file: ${path}`);
  }
  if (realpathSync(path) !== path) fail(`${label} resolves through a symlink: ${path}`);
  if (!Number.isSafeInteger(stat.size) || stat.size < 0 || stat.size > maxBytes) {
    fail(`${label} exceeds its size limit: ${path}`);
  }
  return readFileSync(path);
}

function strictJsonBytes(bytes, label) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail(`${label} is not UTF-8`);
  }
  return parseStrictJson(text, label);
}

function readPinnedBundle(bundleRoot, manifestPin, planPin) {
  const canonicalRoot = realpathSync(resolve(bundleRoot));
  if (canonicalRoot !== resolve(bundleRoot) || !lstatSync(canonicalRoot).isDirectory()) {
    fail("bundle root must be a canonical real directory");
  }
  const manifestPath = `${canonicalRoot}/payment-v1-manifest.json`;
  const manifestBytes = readOneLinkRegular(manifestPath, "rendered manifest");
  if (hashBytes(manifestBytes) !== manifestPin) {
    fail("rendered manifest does not match the externally approved manifest SHA-256");
  }
  const manifest = strictJsonBytes(manifestBytes, "rendered manifest");
  if (manifest.approved_plan_sha256 !== planPin || manifest.plan_sha256 !== planPin) {
    fail("rendered manifest does not match the externally approved plan SHA-256");
  }
  const request = runtimeRequestFromManifest(manifest, manifestPin);
  const requestPath = `${canonicalRoot}/runtime-evidence-request.json`;
  const requestBytes = readOneLinkRegular(requestPath, "runtime evidence request");
  if (!requestBytes.equals(Buffer.from(canonicalJson(request)))) {
    fail("bundled runtime request is not the deterministic manifest-derived request");
  }
  return { manifest, request };
}

function runAbsolute(command, args, { allowOutput = true, timeout = 10_000 } = {}) {
  validateAbsolutePath(command, "subprocess executable");
  if (!REQUIRED_COMMANDS.includes(command)) fail(`subprocess executable is not reviewed: ${command}`);
  if (!Array.isArray(args) || args.some((entry) => typeof entry !== "string" || /[\0\r\n]/u.test(entry))) {
    fail(`subprocess argv is malformed for ${command}`);
  }
  const result = spawnSync(command, args, {
    encoding: "utf8",
    env: { LC_ALL: "C", PATH: "/usr/sbin:/usr/bin" },
    maxBuffer: MAX_COMMAND_OUTPUT_BYTES,
    shell: false,
    timeout,
  });
  if (result.error) fail(`${command} failed to execute: ${result.error.message}`);
  const record = {
    argv: [command, ...args],
    exit_status: result.status,
    stderr: result.stderr ?? "",
    stdout: result.stdout ?? "",
  };
  if (!allowOutput && (record.stdout !== "" || record.stderr !== "")) {
    fail(`${command} unexpectedly produced output`);
  }
  return record;
}

function inspectTrustedCommand(path) {
  const stat = lstatSync(path);
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.uid !== 0 ||
    stat.nlink !== 1 ||
    (stat.mode & 0o022) !== 0 ||
    realpathSync(path) !== path
  ) {
    fail(`runtime helper is not a root-owned, one-link, non-writable regular file: ${path}`);
  }
  return {
    gid: stat.gid,
    mode: (stat.mode & 0o7777).toString(8).padStart(4, "0"),
    nlink: stat.nlink,
    path,
    sha256: hashBytes(readFileSync(path)),
    uid: stat.uid,
  };
}

function stableStat(stat) {
  return {
    dev: stat.dev.toString(),
    gid: stat.gid,
    ino: stat.ino.toString(),
    mode: (stat.mode & 0o7777).toString(8).padStart(4, "0"),
    nlink: stat.nlink,
    size: stat.size,
    uid: stat.uid,
  };
}

function collectExtendedMetadata(path, expectedType) {
  const statRecord = runAbsolute("/usr/bin/stat", ["-c", "%d:%i:%u:%g:%a:%h:%s:%F", "--", path]);
  if (statRecord.exit_status !== 0 || statRecord.stderr !== "") fail(`stat failed for ${path}`);
  const nodeStat = lstatSync(path);
  const statType = {
    directory: "directory",
    regular: "regular file",
    socket: "socket",
  }[expectedType];
  if (statType === undefined) fail(`unreviewed extended metadata type: ${expectedType}`);
  const expectedStatLine = `${nodeStat.dev}:${nodeStat.ino}:${nodeStat.uid}:${nodeStat.gid}:${(
    nodeStat.mode & 0o7777
  ).toString(8)}:${nodeStat.nlink}:${nodeStat.size}:${statType}\n`;
  if (statRecord.stdout !== expectedStatLine) fail(`independent stat mismatch for ${path}`);

  const acl = runAbsolute("/usr/bin/getfacl", ["-c", "-p", "-n", "--", path]);
  if (acl.exit_status !== 0 || acl.stderr !== "") fail(`getfacl failed for ${path}`);
  if (/^(?:default:|mask:|user:[^:]|group:[^:])/mu.test(acl.stdout)) {
    fail(`extended or named ACL is forbidden: ${path}`);
  }

  const xattrs = runAbsolute("/usr/bin/getfattr", ["--absolute-names", "--dump", "--match", "-", "--", path]);
  if (xattrs.exit_status !== 0 || xattrs.stderr !== "") fail(`getfattr failed for ${path}`);
  const xattrPayload = xattrs.stdout.split("\n").filter((line) => line !== "" && !line.startsWith("#"));
  if (xattrPayload.length !== 0) fail(`extended attributes are forbidden: ${path}`);

  const capabilities = runAbsolute("/usr/sbin/getcap", ["-n", "--", path]);
  if (capabilities.exit_status !== 0 || capabilities.stderr !== "" || capabilities.stdout !== "") {
    fail(`file capabilities are forbidden: ${path}`);
  }
  return {
    acl_sha256: hashBytes(Buffer.from(acl.stdout)),
    capability_sha256: hashBytes(Buffer.from(capabilities.stdout)),
    expected_type: expectedType,
    stat_command_sha256: hashBytes(Buffer.from(statRecord.stdout)),
    xattr_sha256: hashBytes(Buffer.from(xattrs.stdout)),
  };
}

function collectInstalledFile(expected) {
  const path = expected.target_path;
  const before = lstatSync(path);
  if (!before.isFile() || before.isSymbolicLink() || realpathSync(path) !== path) {
    fail(`installed artifact is not a canonical regular file: ${path}`);
  }
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = fstatSync(fd);
    const bytes = readFileSync(fd);
    const after = fstatSync(fd);
    if (canonicalJson(stableStat(opened)) !== canonicalJson(stableStat(after))) {
      fail(`installed artifact metadata changed while hashing: ${path}`);
    }
    const sha256Command = runAbsolute("/usr/bin/sha256sum", ["--binary", "--", path]);
    const shaMatch = /^([0-9a-f]{64}) \*.+\n$/u.exec(sha256Command.stdout);
    if (sha256Command.exit_status !== 0 || sha256Command.stderr !== "" || !shaMatch) {
      fail(`sha256sum failed for ${path}`);
    }
    const observed = {
      ...stableStat(after),
      file_type: "regular",
      sha256: hashBytes(bytes),
      sha256_command_sha256: hashBytes(Buffer.from(sha256Command.stdout)),
      target_path: path,
      ...collectExtendedMetadata(path, "regular"),
    };
    if (shaMatch[1] !== observed.sha256) fail(`independent SHA-256 mismatch: ${path}`);
    for (const key of ["gid", "mode", "nlink", "sha256", "uid"]) {
      if (observed[key] !== expected[key]) fail(`installed artifact ${key} mismatch: ${path}`);
    }
    return observed;
  } finally {
    closeSync(fd);
  }
}

function validateNssName(value, label) {
  if (
    typeof value !== "string" ||
    Buffer.byteLength(value, "utf8") < 1 ||
    Buffer.byteLength(value, "utf8") > MAX_NSS_NAME_BYTES ||
    !/^[A-Za-z_][A-Za-z0-9_.-]{0,126}\$?$/u.test(value)
  ) {
    fail(`${label} is not a bounded canonical NSS name`);
  }
  return value;
}

function compareNssNames(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function parseNssUnsigned(value, label) {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]*)$/u.test(value)) {
    fail(`${label} is not a canonical unsigned decimal`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > 0xffff_ffff) {
    fail(`${label} is outside the supported Linux ID range`);
  }
  return parsed;
}

function nssEnumerationLines(stdout, label, maximumRecords) {
  if (
    typeof stdout !== "string" ||
    stdout === "" ||
    stdout.includes("\0") ||
    stdout.includes("\r") ||
    Buffer.byteLength(stdout, "utf8") > MAX_COMMAND_OUTPUT_BYTES
  ) {
    fail(`${label} enumeration output is malformed or oversized`);
  }
  const lines = stdout.endsWith("\n") ? stdout.slice(0, -1).split("\n") : stdout.split("\n");
  if (lines.length < 1 || lines.length > maximumRecords || lines.some((line) => line === "")) {
    fail(`${label} enumeration record count is invalid`);
  }
  return lines;
}

export function parsePasswdEnumerationV2(stdout) {
  const records = nssEnumerationLines(stdout, "passwd", MAX_NSS_USERS).map((line, index) => {
    const fields = line.split(":");
    if (fields.length !== 7) fail(`passwd record ${index} does not have seven fields`);
    return {
      name: validateNssName(fields[0], `passwd record ${index} name`),
      primary_gid: parseNssUnsigned(fields[3], `passwd record ${index} primary GID`),
      uid: parseNssUnsigned(fields[2], `passwd record ${index} UID`),
    };
  });
  records.sort((left, right) => compareNssNames(left.name, right.name));
  if (new Set(records.map((record) => record.name)).size !== records.length) {
    fail("passwd enumeration repeats a user name");
  }
  return records;
}

export function parseGroupEnumerationV2(stdout) {
  const records = nssEnumerationLines(stdout, "group", MAX_NSS_GROUPS).map((line, index) => {
    const fields = line.split(":");
    if (fields.length !== 4) fail(`group record ${index} does not have four fields`);
    const members = fields[3] === ""
      ? []
      : fields[3].split(",").map((member, memberIndex) =>
        validateNssName(member, `group record ${index} member ${memberIndex}`));
    if (members.length > MAX_NSS_GROUP_MEMBERS || new Set(members).size !== members.length) {
      fail(`group record ${index} has duplicate or excessive members`);
    }
    members.sort(compareNssNames);
    return {
      gid: parseNssUnsigned(fields[2], `group record ${index} GID`),
      members,
      name: validateNssName(fields[0], `group record ${index} name`),
    };
  });
  records.sort((left, right) => compareNssNames(left.name, right.name));
  if (new Set(records.map((record) => record.name)).size !== records.length) {
    fail("group enumeration repeats a group name");
  }
  return records;
}

function localPolicyLines(text, label, maximumRecords) {
  if (
    typeof text !== "string" ||
    text === "" ||
    text.includes("\0") ||
    text.includes("\r") ||
    Buffer.byteLength(text, "utf8") > MAX_NSS_POLICY_FILE_BYTES
  ) {
    fail(`${label} is malformed or oversized`);
  }
  const lines = text.endsWith("\n") ? text.slice(0, -1).split("\n") : text.split("\n");
  if (
    lines.length < 1 ||
    lines.length > maximumRecords ||
    lines.some((line) => line === "")
  ) {
    fail(`${label} record count is invalid`);
  }
  return lines;
}

export function parseLockedServiceAccountPolicyV1(
  passwdText,
  shadowText,
  serviceIdentities,
) {
  if (
    !Array.isArray(serviceIdentities) ||
    serviceIdentities.length < 1 ||
    serviceIdentities.length > MAX_NSS_USERS
  ) {
    fail("service identity policy is empty or oversized");
  }
  const expectedByName = new Map();
  for (const [index, identity] of serviceIdentities.entries()) {
    exactKeys(
      identity,
      ["gid", "group_name", "uid", "unit_name", "user_name"],
      `service identity policy[${index}]`,
    );
    const userName = validateNssName(identity.user_name, `service identity policy[${index}] user`);
    if (
      expectedByName.has(userName) ||
      !Number.isSafeInteger(identity.uid) ||
      identity.uid < 1 ||
      identity.uid > 0xffff_ffff ||
      !Number.isSafeInteger(identity.gid) ||
      identity.gid < 1 ||
      identity.gid > 0xffff_ffff
    ) {
      fail("service identity account binding is duplicated or malformed");
    }
    expectedByName.set(userName, identity);
  }

  const passwdByName = new Map();
  for (const [index, line] of localPolicyLines(passwdText, "passwd account policy", MAX_NSS_USERS).entries()) {
    const fields = line.split(":");
    if (fields.length !== 7) fail(`passwd account policy record ${index} does not have seven fields`);
    const name = validateNssName(fields[0], `passwd account policy record ${index} name`);
    if (passwdByName.has(name)) fail("passwd account policy repeats a user name");
    passwdByName.set(name, {
      gid: parseNssUnsigned(fields[3], `passwd account policy record ${index} GID`),
      shell: fields[6],
      uid: parseNssUnsigned(fields[2], `passwd account policy record ${index} UID`),
    });
  }

  const shadowByName = new Map();
  for (const [index, line] of localPolicyLines(shadowText, "shadow account policy", MAX_NSS_USERS).entries()) {
    const fields = line.split(":");
    if (fields.length !== 9) fail(`shadow account policy record ${index} does not have nine fields`);
    const name = validateNssName(fields[0], `shadow account policy record ${index} name`);
    if (shadowByName.has(name)) fail("shadow account policy repeats a user name");
    shadowByName.set(name, fields[1]);
  }

  const accounts = [];
  for (const [userName, expected] of expectedByName) {
    const passwd = passwdByName.get(userName);
    const password = shadowByName.get(userName);
    if (
      !passwd ||
      passwd.uid !== expected.uid ||
      passwd.gid !== expected.gid ||
      !LOCKED_SERVICE_ACCOUNT_SHELLS.includes(passwd.shell) ||
      typeof password !== "string" ||
      !/^[!*]/u.test(password)
    ) {
      fail(`service account is not identity-pinned, login-disabled, and password-locked: ${userName}`);
    }
    accounts.push({
      gid: passwd.gid,
      password_state: "locked",
      shell: passwd.shell,
      uid: passwd.uid,
      user_name: userName,
    });
  }
  accounts.sort((left, right) => compareNssNames(left.user_name, right.user_name));
  return accounts;
}

function decodeNssPolicyFile(bytes, label) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail(`${label} is not UTF-8`);
  }
  if (text === "" || text.includes("\0") || text.includes("\r")) {
    fail(`${label} is empty or contains forbidden bytes`);
  }
  return text;
}

function readNssPolicyFile(path, label) {
  const before = lstatSync(path);
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.uid !== 0 ||
    before.nlink !== 1 ||
    (before.mode & 0o7000) !== 0 ||
    (before.mode & 0o022) !== 0 ||
    before.size < 1 ||
    before.size > MAX_NSS_POLICY_FILE_BYTES ||
    realpathSync(path) !== path
  ) {
    fail(`${label} must be a bounded root-owned, one-link, non-writable regular file`);
  }
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = fstatSync(fd);
    const bytes = readFileSync(fd);
    const after = fstatSync(fd);
    if (
      canonicalJson(stableStat(before)) !== canonicalJson(stableStat(opened)) ||
      canonicalJson(stableStat(opened)) !== canonicalJson(stableStat(after))
    ) {
      fail(`${label} changed while collecting its NSS policy snapshot`);
    }
    return {
      bytes,
      evidence: {
        ...stableStat(after),
        path,
        sha256: hashBytes(bytes),
      },
    };
  } finally {
    closeSync(fd);
  }
}

export function parseLocalFilesNsswitchV1(text) {
  if (
    typeof text !== "string" ||
    text === "" ||
    text.includes("\0") ||
    text.includes("\r") ||
    Buffer.byteLength(text, "utf8") > MAX_NSS_POLICY_FILE_BYTES
  ) {
    fail("nsswitch.conf is malformed or oversized");
  }
  const databases = new Map();
  for (const [index, sourceLine] of text.split("\n").entries()) {
    const line = sourceLine.split("#", 1)[0].trim();
    if (line === "") continue;
    const separator = line.indexOf(":");
    if (separator < 1 || line.indexOf(":", separator + 1) !== -1) {
      fail(`nsswitch.conf line ${index} is malformed`);
    }
    const database = line.slice(0, separator).trim();
    if (!/^[a-z][a-z0-9_-]{0,63}$/u.test(database)) {
      fail(`nsswitch.conf line ${index} has a noncanonical database name`);
    }
    if (!new Set(["passwd", "group", "initgroups"]).has(database)) continue;
    if (databases.has(database)) fail(`nsswitch.conf repeats the ${database} database`);
    const sourceText = line.slice(separator + 1).trim();
    const sources = sourceText === "" ? [] : sourceText.split(/\s+/u);
    if (sources.some((source) => !/^[a-z][a-z0-9_-]{0,63}$/u.test(source))) {
      fail(`nsswitch.conf ${database} sources are not a simple local profile`);
    }
    databases.set(database, sources);
  }
  if (
    canonicalJson(databases.get("passwd")) !== canonicalJson(["files"]) ||
    canonicalJson(databases.get("group")) !== canonicalJson(["files"]) ||
    databases.has("initgroups")
  ) {
    fail("NSS backend is not the reviewed local-files-only profile");
  }
  return {
    group: ["files"],
    initgroups: "inherits-group",
    passwd: ["files"],
  };
}

function collectLocalFilesNssPolicy() {
  const nsswitch = readNssPolicyFile("/etc/nsswitch.conf", "nsswitch.conf");
  const passwd = readNssPolicyFile("/etc/passwd", "passwd file");
  const group = readNssPolicyFile("/etc/group", "group file");
  const sources = parseLocalFilesNsswitchV1(
    decodeNssPolicyFile(nsswitch.bytes, "nsswitch.conf"),
  );
  const passwdRecords = parsePasswdEnumerationV2(
    decodeNssPolicyFile(passwd.bytes, "passwd file"),
  );
  const groupRecords = parseGroupEnumerationV2(
    decodeNssPolicyFile(group.bytes, "group file"),
  );
  return {
    evidence: {
      backend_profile: NSS_BACKEND_PROFILE,
      group_file: group.evidence,
      nsswitch_file: nsswitch.evidence,
      passwd_file: passwd.evidence,
      sources,
    },
    groupRecords,
    passwdRecords,
  };
}

export function collectVisibleNssEvidenceV2() {
  const passwdRecord = runAbsolute("/usr/bin/getent", ["passwd"], { timeout: 15_000 });
  const groupRecord = runAbsolute("/usr/bin/getent", ["group"], { timeout: 15_000 });
  if (passwdRecord.exit_status !== 0 || passwdRecord.stderr !== "") {
    fail("complete passwd NSS enumeration failed");
  }
  if (groupRecord.exit_status !== 0 || groupRecord.stderr !== "") {
    fail("complete group NSS enumeration failed");
  }
  const passwdRecords = parsePasswdEnumerationV2(passwdRecord.stdout);
  const groups = parseGroupEnumerationV2(groupRecord.stdout);
  const idDeadline = performance.now() + MAX_NSS_ID_COLLECTION_MILLISECONDS;
  const users = passwdRecords.map((record) => {
    const remaining = idDeadline - performance.now();
    if (remaining < 1) fail("complete NSS supplementary-group enumeration timed out");
    const groupsRecord = runAbsolute("/usr/bin/id", ["-G", "--", record.name], {
      timeout: Math.max(
        1,
        Math.floor(Math.min(MAX_NSS_ID_LOOKUP_MILLISECONDS, remaining)),
      ),
    });
    if (groupsRecord.exit_status !== 0 || groupsRecord.stderr !== "") {
      fail(`id -G failed for enumerated user ${record.name}`);
    }
    const text = groupsRecord.stdout.trim();
    if (text === "" || !/^(?:0|[1-9][0-9]*)(?:\s+(?:0|[1-9][0-9]*))*$/u.test(text)) {
      fail(`enumerated user ${record.name} has malformed group membership`);
    }
    const supplementaryGids = text
      .split(/\s+/u)
      .map((gid, index) => parseNssUnsigned(gid, `${record.name} group ${index}`));
    const canonicalGids = [...new Set(supplementaryGids)].sort((left, right) => left - right);
    if (!canonicalGids.includes(record.primary_gid)) {
      fail(`enumerated user ${record.name} group set omits its primary GID`);
    }
    return { ...record, supplementary_gids: canonicalGids };
  });
  const nss = {
    enumeration_kind: NSS_ENUMERATION_KIND,
    group_stdout_sha256: hashBytes(Buffer.from(groupRecord.stdout)),
    groups,
    passwd_stdout_sha256: hashBytes(Buffer.from(passwdRecord.stdout)),
    users,
  };
  return nss;
}

function collectNss() {
  const policyBefore = collectLocalFilesNssPolicy();
  const visible = collectVisibleNssEvidenceV2();
  const policyAfter = collectLocalFilesNssPolicy();
  if (
    canonicalJson(policyBefore) !== canonicalJson(policyAfter) ||
    canonicalJson(policyAfter.passwdRecords) !==
      canonicalJson(visible.users.map(({ supplementary_gids: _ignored, ...record }) => record)) ||
    canonicalJson(policyAfter.groupRecords) !== canonicalJson(visible.groups)
  ) {
    fail("local NSS policy or files changed, or getent did not enumerate the exact local files");
  }
  const nss = {
    ...policyAfter.evidence,
    ...visible,
  };
  if (Buffer.byteLength(canonicalJson(nss), "utf8") > MAX_NSS_EVIDENCE_BYTES) {
    fail("canonical complete NSS evidence exceeds its size limit");
  }
  return nss;
}

function recordedLocalFilesNssPolicy(nss) {
  return {
    evidence: {
      backend_profile: nss.backend_profile,
      group_file: nss.group_file,
      nsswitch_file: nss.nsswitch_file,
      passwd_file: nss.passwd_file,
      sources: nss.sources,
    },
    groupRecords: nss.groups,
    passwdRecords: nss.users.map(({ supplementary_gids: _ignored, ...record }) => record),
  };
}

export function assertLocalFilesNssPolicyUnchanged(nss, currentPolicy) {
  if (canonicalJson(recordedLocalFilesNssPolicy(nss)) !== canonicalJson(currentPolicy)) {
    fail("local NSS policy or identity files changed after complete enumeration");
  }
  return true;
}

function confirmLocalFilesNssPolicyUnchanged(nss) {
  return assertLocalFilesNssPolicyUnchanged(nss, collectLocalFilesNssPolicy());
}

function collectLockedServiceAccountPolicy(request, nss) {
  const passwd = readNssPolicyFile("/etc/passwd", "passwd account policy file");
  const shadow = readNssPolicyFile("/etc/shadow", "shadow account policy file");
  if (canonicalJson(passwd.evidence) !== canonicalJson(nss.passwd_file)) {
    fail("passwd account policy is not bound to the complete NSS snapshot");
  }
  return {
    accounts: parseLockedServiceAccountPolicyV1(
      decodeNssPolicyFile(passwd.bytes, "passwd account policy file"),
      decodeNssPolicyFile(shadow.bytes, "shadow account policy file"),
      request.service_identities,
    ),
    passwd_file: passwd.evidence,
    shadow_file: shadow.evidence,
  };
}

function collectTmpfilesDirectory(expected, nss) {
  const user = nss.users.find((entry) => entry.name === expected.user_name);
  const group = nss.groups.find((entry) => entry.name === expected.group_name);
  if (!user || !group) fail(`tmpfiles directory has unresolved NSS owner: ${expected.target_path}`);
  const stat = lstatSync(expected.target_path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || realpathSync(expected.target_path) !== expected.target_path) {
    fail(`tmpfiles target is not a canonical directory: ${expected.target_path}`);
  }
  const observed = {
    ...stableStat(stat),
    file_type: "directory",
    group_name: expected.group_name,
    target_path: expected.target_path,
    user_name: expected.user_name,
    ...collectExtendedMetadata(expected.target_path, "directory"),
  };
  if (observed.uid !== user.uid || observed.gid !== group.gid || observed.mode !== expected.mode) {
    fail(`tmpfiles directory owner or mode mismatch: ${expected.target_path}`);
  }
  return observed;
}

function collectRuntimePath(expected) {
  const stat = lstatSync(expected.target_path);
  const typeMatches =
    (expected.file_type === "directory" && stat.isDirectory()) ||
    (expected.file_type === "socket" && stat.isSocket());
  if (!typeMatches || stat.isSymbolicLink() || realpathSync(expected.target_path) !== expected.target_path) {
    fail(`runtime path is not the expected canonical ${expected.file_type}: ${expected.target_path}`);
  }
  const observed = {
    ...stableStat(stat),
    file_type: expected.file_type,
    target_path: expected.target_path,
    ...collectExtendedMetadata(expected.target_path, expected.file_type),
  };
  for (const key of ["file_type", "gid", "mode", "target_path", "uid"]) {
    if (observed[key] !== expected[key]) {
      fail(`runtime path ${key} mismatch: ${expected.target_path}`);
    }
  }
  return observed;
}

function collectAbsentRuntimeSocket(expected) {
  if (expected.file_type !== "socket") {
    fail(`stopped-edge absence collection only accepts sockets: ${expected.target_path}`);
  }
  const assertAbsent = () => {
    try {
      lstatSync(expected.target_path);
    } catch (error) {
      if (error?.code === "ENOENT") return;
      throw error;
    }
    fail(`runtime socket still exists before edge activation: ${expected.target_path}`);
  };
  const parentPath = dirname(expected.target_path);
  assertAbsent();
  let parentBefore;
  try {
    parentBefore = lstatSync(parentPath);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    assertAbsent();
    try {
      lstatSync(parentPath);
    } catch (confirmationError) {
      if (confirmationError?.code === "ENOENT") {
        return {
          parent_dev: null,
          parent_ino: null,
          parent_path: parentPath,
          parent_state: "absent",
          target_path: expected.target_path,
        };
      }
      throw confirmationError;
    }
    fail(`runtime socket parent appeared during absence collection: ${parentPath}`);
  }
  if (
    !parentBefore.isDirectory() ||
    parentBefore.isSymbolicLink() ||
    realpathSync(parentPath) !== parentPath
  ) {
    fail(`runtime socket parent is not a canonical directory: ${parentPath}`);
  }
  assertAbsent();
  const parentAfter = lstatSync(parentPath);
  if (
    !parentAfter.isDirectory() ||
    parentAfter.isSymbolicLink() ||
    realpathSync(parentPath) !== parentPath ||
    parentAfter.dev !== parentBefore.dev ||
    parentAfter.ino !== parentBefore.ino
  ) {
    fail(`runtime socket parent changed during absence collection: ${parentPath}`);
  }
  assertAbsent();
  return {
    parent_dev: parentAfter.dev.toString(),
    parent_ino: parentAfter.ino.toString(),
    parent_path: parentPath,
    parent_state: "canonical-directory",
    target_path: expected.target_path,
  };
}

function collectAbsentRuntimeSockets(request) {
  const sockets = request.runtime_paths
    .filter((entry) => entry.file_type === "socket")
    .map(collectAbsentRuntimeSocket)
    .sort((left, right) => left.target_path < right.target_path ? -1 : left.target_path > right.target_path ? 1 : 0);
  if (sockets.length < 1) fail("edge runtime request has no socket listener to prove absent");
  return sockets;
}

function secretParentPaths(secretFiles) {
  const paths = new Set();
  for (const secret of secretFiles) {
    let cursor = dirname(secret.target_path);
    for (;;) {
      paths.add(cursor);
      if (cursor === "/") break;
      cursor = dirname(cursor);
    }
  }
  return [...paths].sort();
}

function collectSecretParentDirectory(path) {
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || realpathSync(path) !== path) {
    fail(`secret parent is not a canonical directory: ${path}`);
  }
  return {
    ...stableStat(stat),
    file_type: "directory",
    target_path: path,
    ...collectExtendedMetadata(path, "directory"),
  };
}

function secretProbeArgv(identity, targetPath) {
  return [
    "/usr/bin/setpriv",
    "--no-new-privs",
    "--inh-caps=-all",
    "--ambient-caps=-all",
    "--bounding-set=-all",
    "--reuid", String(identity.uid),
    "--regid", String(identity.gid),
    "--groups", identity.groups.join(","),
    "--",
    "/usr/bin/test",
    "-r",
    targetPath,
  ];
}

function collectSecretAccessChecks(request, nss) {
  const checks = [];
  for (const secret of request.secret_files) {
    const consumer = request.service_identities.find(
      (identity) => identity.unit_name === secret.consumer_unit_name,
    );
    if (!consumer) fail(`secret consumer identity is missing: ${secret.target_path}`);
    for (const identity of request.service_identities) {
      const unit = request.units.find((entry) => entry.unit_name === identity.unit_name);
      if (!unit) fail(`secret access probe unit is missing: ${identity.unit_name}`);
      const expectedIdentity = resolveExpectedUnitProcessIdentity(
        unit,
        nss,
        request.service_identities,
      );
      const expectedReadable = identity.unit_name === consumer.unit_name;
      const argv = secretProbeArgv(expectedIdentity, secret.target_path);
      const record = runAbsolute(argv[0], argv.slice(1));
      if (record.stdout !== "" || record.stderr !== "") {
        fail(`secret access probe produced output: ${identity.unit_name} -> ${secret.target_path}`);
      }
      if (record.exit_status !== (expectedReadable ? 0 : 1)) {
        fail(
          `secret access isolation failed: ${identity.unit_name} -> ${secret.target_path}`,
        );
      }
      checks.push({
        argv: record.argv,
        exit_status: record.exit_status,
        expected_readable: expectedReadable,
        stderr: record.stderr,
        stdout: record.stdout,
        target_path: secret.target_path,
        unit_name: identity.unit_name,
      });
    }
  }
  return checks;
}

function nssMaps(nss) {
  return {
    groupsByName: new Map(nss.groups.map((group) => [group.name, group])),
    usersByName: new Map(nss.users.map((user) => [user.name, user])),
  };
}

function resolveExpectedUnitProcessIdentity(unit, nss, serviceIdentities) {
  const { groupsByName, usersByName } = nssMaps(nss);
  const userName = unit.hardening.User?.[0];
  const groupName = unit.hardening.Group?.[0];
  const user = usersByName.get(userName);
  const group = groupsByName.get(groupName);
  const pinned = serviceIdentities.find((identity) => identity.unit_name === unit.unit_name);
  if (
    !user ||
    !group ||
    !pinned ||
    pinned.user_name !== userName ||
    pinned.group_name !== groupName ||
    pinned.uid !== user.uid ||
    pinned.gid !== group.gid ||
    !Number.isSafeInteger(user.uid) ||
    user.uid < 1 ||
    !Number.isSafeInteger(group.gid) ||
    group.gid < 1 ||
    user.primary_gid !== group.gid
  ) {
    fail(`unit has unresolved or inconsistent runtime identity: ${unit.unit_name}`);
  }
  const gids = new Set([group.gid]);
  for (const directive of unit.hardening.SupplementaryGroups ?? []) {
    for (const supplementaryName of directive.split(/\s+/u)) {
      const supplementary = groupsByName.get(supplementaryName);
      if (!supplementary || !Number.isSafeInteger(supplementary.gid) || supplementary.gid < 1) {
        fail(`unit supplementary group is unresolved: ${unit.unit_name}.${supplementaryName}`);
      }
      gids.add(supplementary.gid);
    }
  }
  return {
    gid: group.gid,
    groups: [...gids].sort((left, right) => left - right),
    uid: user.uid,
  };
}

function protectedCredentialsForRequest(request, nss) {
  const { groupsByName, usersByName } = nssMaps(nss);
  const protectedGids = new Set();
  const protectedUids = new Set();
  const add = (set, value, label) => {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
      fail(`${label} is not a reviewed Linux identity`);
    }
    if (value > 0) set.add(value);
  };
  for (const unit of request.units) {
    const identity = resolveExpectedUnitProcessIdentity(unit, nss, request.service_identities);
    add(protectedUids, identity.uid, `${unit.unit_name} UID`);
    add(protectedGids, identity.gid, `${unit.unit_name} GID`);
    for (const gid of identity.groups) add(protectedGids, gid, `${unit.unit_name} group`);
  }
  for (const entry of [...request.runtime_paths, ...request.secret_files]) {
    add(protectedUids, entry.uid, `${entry.target_path} owner UID`);
    add(protectedGids, entry.gid, `${entry.target_path} owner GID`);
  }
  for (const directory of request.tmpfiles_directories) {
    const user = usersByName.get(directory.user_name);
    const group = groupsByName.get(directory.group_name);
    if (!user || !group) {
      fail(`tmpfiles directory has unresolved protected identity: ${directory.target_path}`);
    }
    add(protectedUids, user.uid, `${directory.target_path} owner UID`);
    add(protectedGids, group.gid, `${directory.target_path} owner GID`);
  }
  return {
    protectedGids: [...protectedGids].sort((left, right) => left - right),
    protectedUids: [...protectedUids].sort((left, right) => left - right),
  };
}

function readBoundedProcFile(path, label, maxBytes) {
  const before = lstatSync(path);
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.nlink !== 1 ||
    (before.mode & 0o222) !== 0 ||
    realpathSync(path) !== path
  ) {
    fail(`${label} is not a canonical read-only one-link procfs file`);
  }
  const fd = openSync(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | (constants.O_CLOEXEC ?? 0),
  );
  try {
    const opened = fstatSync(fd);
    if (
      !opened.isFile() ||
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      (opened.mode & 0o222) !== 0
    ) {
      fail(`${label} changed before it could be opened safely`);
    }
    const buffer = Buffer.allocUnsafe(maxBytes + 1);
    let offset = 0;
    while (offset <= maxBytes) {
      const count = readSync(fd, buffer, offset, maxBytes + 1 - offset, null);
      if (count === 0) break;
      offset += count;
    }
    if (offset > maxBytes) fail(`${label} exceeds its reviewed size bound`);
    const after = fstatSync(fd);
    if (after.dev !== opened.dev || after.ino !== opened.ino || (after.mode & 0o222) !== 0) {
      fail(`${label} metadata changed while it was read`);
    }
    return buffer.subarray(0, offset);
  } finally {
    closeSync(fd);
  }
}

function decodeProcText(bytes, label) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail(`${label} is not valid UTF-8`);
  }
  if (text.includes("\0")) fail(`${label} contains NUL`);
  return text;
}

function validateCapabilityRecord(capabilities, label) {
  exactKeys(capabilities, CAPABILITY_RECORD_KEYS, label);
  for (const key of CAPABILITY_RECORD_KEYS) {
    if (typeof capabilities[key] !== "string" || !CAPABILITY_HEX.test(capabilities[key])) {
      fail(`${label}.${key} must be one canonical 64-bit lowercase hexadecimal mask`);
    }
  }
  return capabilities;
}

function activeCapabilityMask(capabilities) {
  validateCapabilityRecord(capabilities, "procfs capabilities");
  return ["ambient", "effective", "inheritable", "permitted"].reduce(
    (mask, key) => mask | BigInt(`0x${capabilities[key]}`),
    0n,
  );
}

export function validateNonRootEdgeCapabilitiesV1(identity, pid, tid = pid) {
  if (
    identity === null ||
    typeof identity !== "object" ||
    !Array.isArray(identity.uid) ||
    identity.uid.some((uid) => !Number.isSafeInteger(uid) || uid < 0)
  ) {
    fail(`thread ${pid}/${tid} has malformed UID capability identity`);
  }
  const dangerous = activeCapabilityMask(identity.capabilities) &
    DANGEROUS_NONROOT_CAPABILITY_MASK;
  if (!identity.uid.includes(0) && dangerous !== 0n) {
    fail(
      `non-root thread ${pid}/${tid} retains dangerous edge capabilities 0x${dangerous.toString(16)}`,
    );
  }
  return true;
}

function parseProcStat(bytes, pid, label = `/proc/${pid}/stat`) {
  const text = decodeProcText(bytes, label).trimEnd();
  const prefix = `${pid} (`;
  const close = text.lastIndexOf(")");
  if (!text.startsWith(prefix) || close < prefix.length || text[close + 1] !== " ") {
    fail(`${label} has malformed pid/comm framing`);
  }
  const fields = text.slice(close + 2).split(/\s+/u);
  if (fields.length < 20 || !/^[A-Za-z]$/u.test(fields[0])) {
    fail(`${label} has an incomplete field layout`);
  }
  const startTimeTicks = fields[19];
  if (!/^[1-9][0-9]*$/u.test(startTimeTicks)) fail(`${label} has malformed starttime`);
  if (["X", "x", "Z"].includes(fields[0])) fail(`${label} describes a dead process`);
  return { processState: fields[0], startTimeTicks };
}

export function parseProcStatus(
  bytes,
  pid,
  { expectedTgid = pid, label = `/proc/${pid}/status` } = {},
) {
  const lines = decodeProcText(bytes, label).split("\n");
  const field = (name) => {
    const matches = lines.filter((line) => line.startsWith(`${name}:`));
    if (matches.length !== 1) fail(`${label} must contain exactly one ${name}: field`);
    return matches[0].slice(name.length + 1).trim();
  };
  const parseIds = (name, count) => {
    const tokens = field(name).split(/\s+/u);
    if (tokens.length !== count || tokens.some((token) => !/^(?:0|[1-9][0-9]*)$/u.test(token))) {
      fail(`${label} has malformed ${name}: values`);
    }
    const values = tokens.map(Number);
    if (values.some((value) => !Number.isSafeInteger(value) || value < 0)) {
      fail(`${label} has out-of-range ${name}: values`);
    }
    return values;
  };
  const observedPid = parseIds("Pid", 1)[0];
  if (observedPid !== pid) fail(`${label} belongs to a different process`);
  const observedTgid = parseIds("Tgid", 1)[0];
  if (observedTgid !== expectedTgid) fail(`${label} belongs to a different thread group`);
  const groupsText = field("Groups");
  const groups = groupsText === "" ? [] : groupsText.split(/\s+/u).map((token) => {
    if (!/^(?:0|[1-9][0-9]*)$/u.test(token)) fail(`${label} has malformed Groups: values`);
    const gid = Number(token);
    if (!Number.isSafeInteger(gid) || gid < 0) fail(`${label} has out-of-range Groups: values`);
    return gid;
  });
  const capabilityField = (name) => {
    const value = field(name);
    if (!/^[0-9a-fA-F]{1,16}$/u.test(value)) fail(`${label} has malformed ${name}: value`);
    return value.toLowerCase().padStart(16, "0");
  };
  const capabilities = {
    ambient: capabilityField("CapAmb"),
    bounding: capabilityField("CapBnd"),
    effective: capabilityField("CapEff"),
    inheritable: capabilityField("CapInh"),
    permitted: capabilityField("CapPrm"),
  };
  const setidCapabilities =
    (activeCapabilityMask(capabilities) & ((1n << 6n) | (1n << 7n))) !== 0n;
  return {
    capabilities,
    gid: parseIds("Gid", 4),
    groups: [...new Set(groups)].sort((left, right) => left - right),
    setidCapabilities,
    uid: parseIds("Uid", 4),
  };
}

function inspectProcDirectory(path, label) {
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || realpathSync(path) !== path) {
    fail(`${label} is not a canonical procfs directory: ${path}`);
  }
  return { dev: stat.dev.toString(), ino: stat.ino.toString() };
}

function collectProcIdentityAt(path, pid, expectedTgid, label) {
  const directoryBefore = inspectProcDirectory(path, `${label} directory`);
  const statBefore = parseProcStat(
    readBoundedProcFile(`${path}/stat`, `${label} stat`, MAX_PROC_STAT_BYTES),
    pid,
    `${path}/stat`,
  );
  const identity = parseProcStatus(
    readBoundedProcFile(`${path}/status`, `${label} status`, MAX_PROC_STATUS_BYTES),
    pid,
    { expectedTgid, label: `${path}/status` },
  );
  const statAfter = parseProcStat(
    readBoundedProcFile(`${path}/stat`, `${label} stat confirmation`, MAX_PROC_STAT_BYTES),
    pid,
    `${path}/stat`,
  );
  const directoryAfter = inspectProcDirectory(path, `${label} directory`);
  if (
    canonicalJson(directoryBefore) !== canonicalJson(directoryAfter) ||
    statBefore.startTimeTicks !== statAfter.startTimeTicks
  ) {
    fail(`${label} restarted while its procfs identity was collected`);
  }
  return {
    ...identity,
    procDirectoryDev: directoryAfter.dev,
    procDirectoryIno: directoryAfter.ino,
    processState: statAfter.processState,
    startTimeTicks: statAfter.startTimeTicks,
  };
}

function collectProcIdentitySnapshot(pid) {
  return collectProcIdentityAt(`/proc/${pid}`, pid, pid, `process ${pid}`);
}

function isVanishedProcError(error) {
  return error?.code === "ENOENT" || error?.code === "ESRCH";
}

function canonicalNumericProcEntries(path, label, maximum) {
  const entries = readdirSync(path, { withFileTypes: true });
  const values = [];
  for (const entry of entries) {
    if (!/^[0-9]+$/u.test(entry.name)) continue;
    if (!/^[1-9][0-9]*$/u.test(entry.name) || !entry.isDirectory()) {
      fail(`${label} contains a noncanonical numeric entry`);
    }
    const value = Number(entry.name);
    if (!Number.isSafeInteger(value) || value < 1) {
      fail(`${label} contains an out-of-range numeric entry`);
    }
    values.push(value);
  }
  values.sort((left, right) => left - right);
  if (values.length > maximum || new Set(values).size !== values.length) {
    fail(`${label} exceeds its reviewed unique-entry bound`);
  }
  return values;
}

function parseUnifiedProcCgroup(bytes, label) {
  const text = decodeProcText(bytes, label);
  if (!text.endsWith("\n") || text.includes("\r")) {
    fail(`${label} is not a canonical cgroup membership record`);
  }
  const lines = text.trimEnd().split("\n");
  if (lines.length !== 1 || !lines[0].startsWith("0::")) {
    fail(`${label} does not describe exactly one unified cgroup v2 membership`);
  }
  const controlGroup = lines[0].slice(3);
  if (
    controlGroup.length < 1 ||
    controlGroup.length > 4096 ||
    !controlGroup.startsWith("/") ||
    controlGroup.includes("//") ||
    controlGroup.split("/").some((segment) => segment === "." || segment === "..")
  ) {
    fail(`${label} has a noncanonical unified control-group path`);
  }
  return controlGroup;
}

function hasProtectedCredential(identity, protectedUids, protectedGids) {
  return (
    identity.uid.some((uid) => protectedUids.has(uid)) ||
    identity.gid.some((gid) => protectedGids.has(gid)) ||
    identity.groups.some((gid) => protectedGids.has(gid))
  );
}

function collectStableProtectedTask(pid, tid, protectedUids, protectedGids) {
  const path = `/proc/${pid}/task/${tid}`;
  const cgroupPath = `${path}/cgroup`;
  const cgroupBefore = parseUnifiedProcCgroup(
    readBoundedProcFile(cgroupPath, `thread ${pid}/${tid} cgroup`, MAX_PROC_CGROUP_BYTES),
    cgroupPath,
  );
  const snapshot = collectProcIdentityAt(path, tid, pid, `thread ${pid}/${tid}`);
  const cgroupAfter = parseUnifiedProcCgroup(
    readBoundedProcFile(cgroupPath, `thread ${pid}/${tid} cgroup confirmation`, MAX_PROC_CGROUP_BYTES),
    cgroupPath,
  );
  if (cgroupAfter !== cgroupBefore) {
    fail(`thread ${pid}/${tid} changed control groups during credential collection`);
  }
  if (!hasProtectedCredential(snapshot, protectedUids, protectedGids)) return null;
  validateNonRootEdgeCapabilitiesV1(snapshot, pid, tid);
  return {
    capabilities: snapshot.capabilities,
    control_group: cgroupAfter,
    gid: snapshot.gid,
    groups: snapshot.groups,
    pid,
    proc_directory_dev: snapshot.procDirectoryDev,
    proc_directory_ino: snapshot.procDirectoryIno,
    start_time_ticks: snapshot.startTimeTicks,
    tid,
    uid: snapshot.uid,
  };
}

function collectProtectedCredentialProcessPass(protectedUids, protectedGids, deadline) {
  const pids = canonicalNumericProcEntries("/proc", "/proc", MAX_PROC_PROCESSES);
  const holders = [];
  let processesEnumerated = 0;
  let threadsExamined = 0;
  for (const pid of pids) {
    if (performance.now() > deadline) fail("protected process credential scan timed out");
    let tids;
    try {
      tids = canonicalNumericProcEntries(
        `/proc/${pid}/task`,
        `process ${pid} task directory`,
        MAX_PROC_THREADS,
      );
    } catch (error) {
      if (isVanishedProcError(error)) continue;
      throw error;
    }
    processesEnumerated += 1;
    for (const tid of tids) {
      threadsExamined += 1;
      if (threadsExamined > MAX_PROC_THREADS) {
        fail("protected process credential scan exceeds its total thread bound");
      }
      if (performance.now() > deadline) fail("protected process credential scan timed out");
      const statusPath = `/proc/${pid}/task/${tid}/status`;
      let initial;
      try {
        initial = parseProcStatus(
          readBoundedProcFile(statusPath, `thread ${pid}/${tid} status`, MAX_PROC_STATUS_BYTES),
          tid,
          { expectedTgid: pid, label: statusPath },
        );
      } catch (error) {
        if (isVanishedProcError(error)) continue;
        throw error;
      }
      if (!hasProtectedCredential(initial, protectedUids, protectedGids)) continue;
      // Capability closure applies to processes which can read one of the
      // protected service identities. Unrelated host/runner processes may
      // legitimately carry capabilities such as CAP_NET_RAW and are outside
      // this evidence object's authority boundary.
      validateNonRootEdgeCapabilitiesV1(initial, pid, tid);
      let holder;
      try {
        holder = collectStableProtectedTask(pid, tid, protectedUids, protectedGids);
      } catch (error) {
        if (isVanishedProcError(error)) continue;
        throw error;
      }
      if (holder !== null) holders.push(holder);
    }
  }
  holders.sort((left, right) => left.pid - right.pid || left.tid - right.tid);
  return {
    holders,
    processes_enumerated: processesEnumerated,
    threads_examined: threadsExamined,
  };
}

export function collectProtectedCredentialProcessClosureV1({ protectedGids, protectedUids }) {
  const procType = statfsSync("/proc").type;
  if (procType !== PROC_SUPER_MAGIC) fail("/proc is not the reviewed procfs filesystem");
  const canonicalUids = [...new Set(protectedUids)].sort((left, right) => left - right);
  const canonicalGids = [...new Set(protectedGids)].sort((left, right) => left - right);
  for (const [label, values] of [["UID", canonicalUids], ["GID", canonicalGids]]) {
    if (
      values.some((value) => !Number.isSafeInteger(value) || value < 1 || value > 0xffff_ffff)
    ) {
      fail(`protected ${label} set is malformed`);
    }
  }
  const deadline = performance.now() + MAX_PROC_CREDENTIAL_SCAN_MILLISECONDS;
  const passes = [
    collectProtectedCredentialProcessPass(new Set(canonicalUids), new Set(canonicalGids), deadline),
    collectProtectedCredentialProcessPass(new Set(canonicalUids), new Set(canonicalGids), deadline),
  ];
  if (canonicalJson(passes[0].holders) !== canonicalJson(passes[1].holders)) {
    fail("protected process holders changed between complete procfs passes");
  }
  const closure = {
    enumeration_kind: PROTECTED_PROCESS_ENUMERATION_KIND,
    passes,
    protected_gids: canonicalGids,
    protected_uids: canonicalUids,
  };
  if (Buffer.byteLength(canonicalJson(closure), "utf8") > MAX_PROC_CLOSURE_EVIDENCE_BYTES) {
    fail("protected process closure exceeds its reviewed evidence byte bound");
  }
  return closure;
}

const EFFECTIVE_CRITICAL_KEYS = Object.freeze([
  "AmbientCapabilities",
  "CapabilityBoundingSet",
  "Group",
  "IPAddressAllow",
  "IPAddressDeny",
  "InaccessiblePaths",
  "LimitCORE",
  "LimitCORESoft",
  "LockPersonality",
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
  "StandardError",
  "StandardOutput",
  "SupplementaryGroups",
  "SystemCallArchitectures",
  "TasksMax",
  "Type",
  "UMask",
  "User",
  "WorkingDirectory",
]);

const EFFECTIVE_BASE_PROPERTIES = Object.freeze([
  "ActiveEnterTimestampMonotonic",
  "ActiveState",
  "BindPaths",
  "BindReadOnlyPaths",
  "ConditionResult",
  "Conditions",
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
  "InvocationID",
  "LoadCredential",
  "LoadState",
  "MainPID",
  "Result",
  "RootDirectory",
  "RootImage",
  "SetCredential",
  "SubState",
]);

function effectivePropertyNames() {
  const local = [...new Set([...EFFECTIVE_BASE_PROPERTIES, ...EFFECTIVE_CRITICAL_KEYS])].sort();
  if (canonicalJson(local) !== canonicalJson(RUNTIME_SYSTEMCTL_SHOW_PROPERTIES)) {
    fail("collector and rendered runtime systemctl property schemas diverged");
  }
  return [...RUNTIME_SYSTEMCTL_SHOW_PROPERTIES];
}

function splitLiteralWords(value) {
  if (value === "") return [];
  if (/[$%`;&|<>\r\n\0]/u.test(value)) fail("systemctl effective value contains dynamic syntax");
  return value
    .trim()
    .split(/\s+/u)
    .map((word) => word.replace(/^"(.*)"$/u, "$1"))
    .sort();
}

function expectedWords(values) {
  return values.flatMap((value) => value.split(/\s+/u)).sort();
}

function extractExecArgv(value, label) {
  if (value === "") return [];
  const result = [];
  for (const match of value.matchAll(/(?:^|\s*;\s*)\{[^{}]*?argv\[\]=(.+?)\s*;\s*ignore_errors=/gu)) {
    result.push(match[1].trim());
  }
  if (result.length === 0) fail(`${label} has an unreviewed systemctl Exec serialization`);
  return result;
}

function parseUnsignedDecimal(value, label, { allowZero = true } = {}) {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]*)$/u.test(value)) {
    fail(`${label} is not a canonical unsigned decimal`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0 || (!allowZero && parsed === 0)) {
    fail(`${label} is outside the reviewed safe-integer range`);
  }
  return parsed;
}

function expectedSystemUnitControlGroup(unitName) {
  if (typeof unitName !== "string" || !/^[a-z0-9][a-z0-9_.@-]{0,127}\.service$/u.test(unitName)) {
    fail("systemd unit name cannot be mapped to a reviewed control group");
  }
  return `/system.slice/${unitName}`;
}

function validateUnitLifecycle(unit, properties, uptimeFinishedMilliseconds) {
  if (properties.ActiveState !== "active") fail(`unit is not active: ${unit.unit_name}`);
  if (properties.ConditionResult !== "yes") fail(`unit conditions did not pass: ${unit.unit_name}`);
  if (!/^[0-9a-f]{32}$/u.test(properties.InvocationID) || /^0{32}$/u.test(properties.InvocationID)) {
    fail(`unit InvocationID is not a canonical non-zero generation id: ${unit.unit_name}`);
  }
  const activeEnterMicroseconds = parseUnsignedDecimal(
    properties.ActiveEnterTimestampMonotonic,
    `${unit.unit_name}.ActiveEnterTimestampMonotonic`,
    { allowZero: false },
  );
  if (
    uptimeFinishedMilliseconds !== undefined &&
    activeEnterMicroseconds > uptimeFinishedMilliseconds * 1000
  ) {
    fail(`unit activation timestamp is not bound to this boot: ${unit.unit_name}`);
  }
  const mainPid = parseUnsignedDecimal(properties.MainPID, `${unit.unit_name}.MainPID`);
  if (properties.ControlGroup !== expectedSystemUnitControlGroup(unit.unit_name)) {
    fail(`unit is outside its reviewed system.slice control group: ${unit.unit_name}`);
  }
  if (properties.Type === "oneshot") {
    if (
      unit.unit_name !== REVIEWED_ONESHOT_UNIT ||
      unit.fragment_path !== REVIEWED_ONESHOT_FRAGMENT ||
      canonicalJson(unit.hardening.Type ?? []) !== canonicalJson(["oneshot"]) ||
      canonicalJson(unit.hardening.RemainAfterExit ?? []) !== canonicalJson(["yes"])
    ) {
      fail(`unit is not the uniquely reviewed successful oneshot: ${unit.unit_name}`);
    }
    if (
      mainPid !== 0 ||
      properties.SubState !== "exited" ||
      properties.Result !== "success" ||
      properties.ExecMainCode !== "1" ||
      properties.ExecMainStatus !== "0"
    ) {
      fail(`reviewed oneshot completion proof failed: ${unit.unit_name}`);
    }
    return { kind: "successful-oneshot", mainPid };
  }
  if (!["simple", "notify"].includes(properties.Type)) {
    fail(`unit has an unreviewed long-running Type: ${unit.unit_name}`);
  }
  if (mainPid === 0 || properties.SubState !== "running") {
    fail(`long-running unit has no active MainPID: ${unit.unit_name}`);
  }
  return { kind: "long-running", mainPid };
}

function validateEffectiveUnitProperties(unit, properties, uptimeFinishedMilliseconds) {
  exactKeys(properties, effectivePropertyNames(), `effective properties for ${unit.unit_name}`);
  if (properties.FragmentPath !== unit.fragment_path) fail(`FragmentPath drift: ${unit.unit_name}`);
  if (properties.DropInPaths !== "") fail(`systemd drop-ins are forbidden: ${unit.unit_name}`);
  if (properties.LoadState !== "loaded") fail(`unit is not loaded: ${unit.unit_name}`);
  if (unit.conditions.length > 0 && properties.Conditions === "") {
    fail(`effective conditions are missing: ${unit.unit_name}`);
  }
  for (const condition of unit.conditions) {
    const separator = condition.indexOf("=");
    const key = condition.slice(0, separator);
    const value = condition.slice(separator + 1);
    if (!properties.Conditions.includes(key) || !properties.Conditions.includes(value)) {
      fail(`effective condition drift: ${unit.unit_name}`);
    }
  }
  for (const forbidden of [
    "ExecStartPost",
    "ExecCondition",
    "EnvironmentFiles",
    "RootDirectory",
    "RootImage",
    "BindPaths",
    "BindReadOnlyPaths",
    "LoadCredential",
    "SetCredential",
  ]) {
    if (properties[forbidden] !== "") fail(`effective ${forbidden} is forbidden: ${unit.unit_name}`);
  }
  const actualStart = extractExecArgv(properties.ExecStart, `${unit.unit_name}.ExecStart`);
  const actualPre = extractExecArgv(properties.ExecStartPre, `${unit.unit_name}.ExecStartPre`);
  if (canonicalJson(actualStart) !== canonicalJson(unit.exec_start)) fail(`effective ExecStart drift: ${unit.unit_name}`);
  if (canonicalJson(actualPre) !== canonicalJson(unit.exec_start_pre)) fail(`effective ExecStartPre drift: ${unit.unit_name}`);
  if (canonicalJson(splitLiteralWords(properties.Environment)) !== canonicalJson([...unit.environment].sort())) {
    fail(`effective Environment drift: ${unit.unit_name}`);
  }
  for (const key of EFFECTIVE_CRITICAL_KEYS) {
    const expected = unit.hardening[key];
    if (expected === undefined) {
      continue;
    }
    if (expected.length === 1 && expected[0] === "true") {
      if (!new Set(["yes", "true"]).has(properties[key])) fail(`effective ${key} drift: ${unit.unit_name}`);
      continue;
    }
    if (expected.length === 1 && expected[0] === "") {
      if (properties[key] !== "") fail(`effective ${key} drift: ${unit.unit_name}`);
      continue;
    }
    if (canonicalJson(splitLiteralWords(properties[key])) !== canonicalJson(expectedWords(expected))) {
      fail(`effective ${key} drift: ${unit.unit_name}`);
    }
  }
  if (unit.hardening.LimitCORE !== undefined && properties.LimitCORESoft !== "0") {
    fail(`effective LimitCORESoft drift: ${unit.unit_name}`);
  }
  if (
    unit.hardening.MemorySwapMax !== undefined &&
    properties.MemorySwapCurrent !== "0"
  ) {
    fail(`effective MemorySwapCurrent drift: ${unit.unit_name}`);
  }
  return validateUnitLifecycle(unit, properties, uptimeFinishedMilliseconds);
}

function collectSystemctlValue(unitName, property) {
  const record = runAbsolute("/usr/bin/systemctl", ["show", unitName, `--property=${property}`, "--value"]);
  if (record.exit_status !== 0 || record.stderr !== "") fail(`systemctl show failed for ${unitName}.${property}`);
  return record.stdout.replace(/\n$/u, "");
}

function collectStoppedUnitState(unit) {
  const state = {
    active_state: collectSystemctlValue(unit.unit_name, "ActiveState"),
    control_group: collectSystemctlValue(unit.unit_name, "ControlGroup"),
    drop_in_paths: collectSystemctlValue(unit.unit_name, "DropInPaths"),
    fragment_path: collectSystemctlValue(unit.unit_name, "FragmentPath"),
    invocation_id: collectSystemctlValue(unit.unit_name, "InvocationID"),
    load_state: collectSystemctlValue(unit.unit_name, "LoadState"),
    main_pid: collectSystemctlValue(unit.unit_name, "MainPID"),
    sub_state: collectSystemctlValue(unit.unit_name, "SubState"),
    unit_name: unit.unit_name,
  };
  if (
    state.active_state !== "inactive" ||
    state.sub_state !== "dead" ||
    state.main_pid !== "0" ||
    state.control_group !== "" ||
    state.drop_in_paths !== "" ||
    state.fragment_path !== unit.fragment_path ||
    state.load_state !== "loaded" ||
    !new Set(["", "0".repeat(32)]).has(state.invocation_id)
  ) {
    fail(`unit is not in the reviewed fully stopped state: ${unit.unit_name}`);
  }
  return state;
}

function collectStoppedUnitStates(request) {
  return request.units.map(collectStoppedUnitState);
}

function confirmUnitGeneration(unit, properties) {
  const confirmation = {
    active_enter_timestamp_monotonic: collectSystemctlValue(unit.unit_name, "ActiveEnterTimestampMonotonic"),
    active_state: collectSystemctlValue(unit.unit_name, "ActiveState"),
    control_group: collectSystemctlValue(unit.unit_name, "ControlGroup"),
    invocation_id: collectSystemctlValue(unit.unit_name, "InvocationID"),
    main_pid: collectSystemctlValue(unit.unit_name, "MainPID"),
  };
  if (
    confirmation.active_state !== properties.ActiveState ||
    confirmation.control_group !== properties.ControlGroup ||
    confirmation.main_pid !== properties.MainPID ||
    confirmation.invocation_id !== properties.InvocationID ||
    confirmation.active_enter_timestamp_monotonic !== properties.ActiveEnterTimestampMonotonic
  ) {
    fail(`systemd unit generation changed during live collection: ${unit.unit_name}`);
  }
  return confirmation;
}

function capabilityDirectiveMask(values, label) {
  if (!Array.isArray(values) || values.length !== 1 || typeof values[0] !== "string") {
    fail(`${label} must be one reviewed systemd capability directive`);
  }
  const tokens = values[0] === "" ? [] : values[0].split(/\s+/u);
  if (new Set(tokens).size !== tokens.length) fail(`${label} contains duplicate capabilities`);
  let mask = 0n;
  for (const token of tokens) {
    if (token !== "CAP_NET_BIND_SERVICE") {
      fail(`${label} contains an unreviewed capability ${token}`);
    }
    mask |= CAP_NET_BIND_SERVICE_MASK;
  }
  return mask;
}

function allowedUnitCapabilityMasks(unit) {
  const ambient = capabilityDirectiveMask(
    unit.hardening.AmbientCapabilities,
    `${unit.unit_name}.AmbientCapabilities`,
  );
  const bounding = capabilityDirectiveMask(
    unit.hardening.CapabilityBoundingSet,
    `${unit.unit_name}.CapabilityBoundingSet`,
  );
  if ((ambient & ~bounding) !== 0n) {
    fail(`${unit.unit_name} ambient capabilities exceed its bounding set`);
  }
  if (
    (ambient !== 0n || bounding !== 0n) &&
    !NET_BIND_SERVICE_UNITS.has(unit.unit_name)
  ) {
    fail(`${unit.unit_name} is not a reviewed Caddy capability-bearing unit`);
  }
  return { ambient, bounding };
}

function validateManagedProcessCapabilities(capabilities, unit) {
  validateCapabilityRecord(capabilities, `${unit.unit_name} procfs capabilities`);
  const allowed = allowedUnitCapabilityMasks(unit);
  for (const key of ["bounding", "effective", "inheritable", "permitted"]) {
    const observed = BigInt(`0x${capabilities[key]}`);
    if ((observed & ~allowed.bounding) !== 0n) {
      fail(`${unit.unit_name} procfs ${key} capabilities exceed the reviewed bounding set`);
    }
  }
  const ambient = BigInt(`0x${capabilities.ambient}`);
  if ((ambient & ~allowed.ambient) !== 0n) {
    fail(`${unit.unit_name} procfs ambient capabilities exceed the reviewed ambient set`);
  }
}

function assertSnapshotIdentity(snapshot, expected, unit) {
  if (
    canonicalJson(snapshot.uid) !== canonicalJson([expected.uid, expected.uid, expected.uid, expected.uid]) ||
    canonicalJson(snapshot.gid) !== canonicalJson([expected.gid, expected.gid, expected.gid, expected.gid]) ||
    canonicalJson(snapshot.groups) !== canonicalJson(expected.groups)
  ) {
    fail(`running process identity differs from the reviewed unit identity: ${unit.unit_name}`);
  }
  validateNonRootEdgeCapabilitiesV1(snapshot, unit.unit_name, "MainPID");
  validateManagedProcessCapabilities(snapshot.capabilities, unit);
}

function collectLongRunningProcessIdentity(unit, properties, nss, serviceIdentities) {
  const pid = parseUnsignedDecimal(properties.MainPID, `${unit.unit_name}.MainPID`, { allowZero: false });
  const expected = resolveExpectedUnitProcessIdentity(unit, nss, serviceIdentities);
  const before = collectProcIdentitySnapshot(pid);
  assertSnapshotIdentity(before, expected, unit);
  const firstConfirmation = confirmUnitGeneration(unit, properties);
  const middle = collectProcIdentitySnapshot(pid);
  assertSnapshotIdentity(middle, expected, unit);
  const secondConfirmation = confirmUnitGeneration(unit, properties);
  const after = collectProcIdentitySnapshot(pid);
  assertSnapshotIdentity(after, expected, unit);
  for (const snapshot of [middle, after]) {
    if (
      snapshot.procDirectoryDev !== before.procDirectoryDev ||
      snapshot.procDirectoryIno !== before.procDirectoryIno ||
      snapshot.startTimeTicks !== before.startTimeTicks ||
      canonicalJson(snapshot.uid) !== canonicalJson(before.uid) ||
      canonicalJson(snapshot.gid) !== canonicalJson(before.gid) ||
      canonicalJson(snapshot.groups) !== canonicalJson(before.groups) ||
      canonicalJson(snapshot.capabilities) !== canonicalJson(before.capabilities)
    ) {
      fail(`running process restarted or changed credentials during live collection: ${unit.unit_name}`);
    }
  }
  return {
    confirmations: [firstConfirmation, secondConfirmation],
    evidence: {
      capabilities_after: after.capabilities,
      capabilities_before: before.capabilities,
      gid_after: after.gid,
      gid_before: before.gid,
      groups_after: after.groups,
      groups_before: before.groups,
      main_pid: pid,
      proc_directory_dev_after: after.procDirectoryDev,
      proc_directory_dev_before: before.procDirectoryDev,
      proc_directory_ino_after: after.procDirectoryIno,
      proc_directory_ino_before: before.procDirectoryIno,
      process_state_after: after.processState,
      process_state_before: before.processState,
      start_time_ticks_after: after.startTimeTicks,
      start_time_ticks_before: before.startTimeTicks,
      uid_after: after.uid,
      uid_before: before.uid,
    },
  };
}

function collectUnit(unit, nss, serviceIdentities, uptimeFinishedMilliseconds) {
  const properties = Object.create(null);
  for (const property of effectivePropertyNames()) {
    properties[property] = collectSystemctlValue(unit.unit_name, property);
  }
  const lifecycle = validateEffectiveUnitProperties(unit, properties, uptimeFinishedMilliseconds);
  let generationConfirmations;
  let processIdentity;
  if (lifecycle.kind === "long-running") {
    const collected = collectLongRunningProcessIdentity(unit, properties, nss, serviceIdentities);
    generationConfirmations = collected.confirmations;
    processIdentity = collected.evidence;
  } else {
    generationConfirmations = [confirmUnitGeneration(unit, properties), confirmUnitGeneration(unit, properties)];
    processIdentity = null;
  }
  const fragmentBytes = readOneLinkRegular(unit.fragment_path, `systemd fragment ${unit.unit_name}`, 2 * 1024 * 1024);
  return {
    fragment_sha256: hashBytes(fragmentBytes),
    generation_confirmations: generationConfirmations,
    process_identity: processIdentity,
    properties,
    unit_name: unit.unit_name,
  };
}

function readPidNamespaceBinding() {
  const readNamespace = (path) => {
    const stat = lstatSync(path);
    if (!stat.isSymbolicLink()) fail(`${path} is not a procfs namespace link`);
    const value = readlinkSync(path);
    if (!/^pid:\[[1-9][0-9]*\]$/u.test(value)) fail(`${path} has a malformed namespace id`);
    return value;
  };
  const pid1Namespace = readNamespace("/proc/1/ns/pid");
  const collectorNamespace = readNamespace("/proc/self/ns/pid");
  if (pid1Namespace !== collectorNamespace) {
    fail("collector does not share PID 1's visible PID namespace");
  }
  const pid1Status = decodeProcText(
    readBoundedProcFile("/proc/1/status", "PID 1 status", MAX_PROC_STATUS_BYTES),
    "/proc/1/status",
  ).split("\n");
  const uniqueField = (name) => {
    const matches = pid1Status.filter((line) => line.startsWith(`${name}:`));
    if (matches.length !== 1) fail(`/proc/1/status must contain one ${name}: field`);
    return matches[0].slice(name.length + 1).trim();
  };
  if (uniqueField("Name") !== "systemd" || uniqueField("NSpid") !== "1") {
    fail("PID 1 is not the reviewed systemd namespace root");
  }
  return {
    collector_pid_namespace: collectorNamespace,
    pid1_name: "systemd",
    pid1_nspid: [1],
    pid1_pid_namespace: pid1Namespace,
  };
}

function readHostBinding() {
  const bootId = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
  validateUuid(bootId, "Linux boot id");
  const corePattern = readFileSync("/proc/sys/kernel/core_pattern", "utf8").trim();
  if (corePattern === "" || /[\r\n\0]/u.test(corePattern)) {
    fail("Linux core_pattern is malformed");
  }
  const machineId = readFileSync("/etc/machine-id");
  const uptimeText = readFileSync("/proc/uptime", "utf8").trim().split(/\s+/u)[0];
  const uptimeMilliseconds = Math.floor(Number(uptimeText) * 1000);
  if (!Number.isSafeInteger(uptimeMilliseconds) || uptimeMilliseconds < 0) fail("Linux uptime is malformed");
  const kernel = runAbsolute("/usr/bin/uname", ["-r"]);
  const systemd = runAbsolute("/usr/bin/systemctl", ["--version"]);
  if (kernel.exit_status !== 0 || kernel.stderr !== "" || systemd.exit_status !== 0 || systemd.stderr !== "") {
    fail("host version collection failed");
  }
  const pidNamespace = readPidNamespaceBinding();
  return {
    boot_id: bootId,
    core_pattern: corePattern,
    kernel_release: kernel.stdout.trim(),
    machine_id_sha256: hashBytes(machineId),
    ...pidNamespace,
    systemd_version: systemd.stdout.split("\n", 1)[0],
    uptime_milliseconds: uptimeMilliseconds,
  };
}

function validateGenerationConfirmations(confirmations, properties, unitName) {
  if (!Array.isArray(confirmations) || confirmations.length !== 3) {
    fail(`unit generation confirmations are incomplete: ${unitName}`);
  }
  for (const [index, confirmation] of confirmations.entries()) {
    exactKeys(
      confirmation,
      ["active_enter_timestamp_monotonic", "active_state", "control_group", "invocation_id", "main_pid"],
      `${unitName} generation confirmation[${index}]`,
    );
    if (
      confirmation.active_enter_timestamp_monotonic !== properties.ActiveEnterTimestampMonotonic ||
      confirmation.active_state !== properties.ActiveState ||
      confirmation.control_group !== properties.ControlGroup ||
      confirmation.invocation_id !== properties.InvocationID ||
      confirmation.main_pid !== properties.MainPID
    ) {
      fail(`unit generation changed during collection: ${unitName}`);
    }
  }
}

function validateIdVector(value, expected, label) {
  if (
    !Array.isArray(value) ||
    value.length !== 4 ||
    value.some((entry) => !Number.isSafeInteger(entry) || entry < 1) ||
    value.some((entry) => entry !== expected)
  ) {
    fail(`${label} does not contain four copies of the expected service id`);
  }
}

function validateProcessIdentityEvidence(processIdentity, lifecycle, expectedIdentity, unit) {
  const unitName = unit.unit_name;
  if (lifecycle.kind === "successful-oneshot") {
    if (processIdentity !== null) fail(`reviewed oneshot must not claim procfs process identity: ${unitName}`);
    return;
  }
  exactKeys(
    processIdentity,
    [
      "capabilities_after",
      "capabilities_before",
      "gid_after",
      "gid_before",
      "groups_after",
      "groups_before",
      "main_pid",
      "proc_directory_dev_after",
      "proc_directory_dev_before",
      "proc_directory_ino_after",
      "proc_directory_ino_before",
      "process_state_after",
      "process_state_before",
      "start_time_ticks_after",
      "start_time_ticks_before",
      "uid_after",
      "uid_before",
    ],
    `${unitName} procfs process identity`,
  );
  if (processIdentity.main_pid !== lifecycle.mainPid || processIdentity.main_pid < 1) {
    fail(`procfs identity MainPID drift: ${unitName}`);
  }
  for (const key of [
    "proc_directory_dev_before",
    "proc_directory_dev_after",
    "proc_directory_ino_before",
    "proc_directory_ino_after",
    "start_time_ticks_before",
    "start_time_ticks_after",
  ]) {
    if (typeof processIdentity[key] !== "string" || !/^[1-9][0-9]*$/u.test(processIdentity[key])) {
      fail(`procfs identity ${key} is malformed: ${unitName}`);
    }
  }
  for (const [beforeKey, afterKey] of [
    ["proc_directory_dev_before", "proc_directory_dev_after"],
    ["proc_directory_ino_before", "proc_directory_ino_after"],
    ["start_time_ticks_before", "start_time_ticks_after"],
  ]) {
    if (processIdentity[beforeKey] !== processIdentity[afterKey]) {
      fail(`procfs process restart race detected: ${unitName}`);
    }
  }
  for (const key of ["process_state_before", "process_state_after"]) {
    if (typeof processIdentity[key] !== "string" || !/^[A-Za-z]$/u.test(processIdentity[key]) || ["X", "x", "Z"].includes(processIdentity[key])) {
      fail(`procfs process state is dead or malformed: ${unitName}`);
    }
  }
  validateIdVector(processIdentity.uid_before, expectedIdentity.uid, `${unitName} Uid before`);
  validateIdVector(processIdentity.uid_after, expectedIdentity.uid, `${unitName} Uid after`);
  validateIdVector(processIdentity.gid_before, expectedIdentity.gid, `${unitName} Gid before`);
  validateIdVector(processIdentity.gid_after, expectedIdentity.gid, `${unitName} Gid after`);
  for (const key of ["groups_before", "groups_after"]) {
    if (
      !Array.isArray(processIdentity[key]) ||
      canonicalJson(processIdentity[key]) !== canonicalJson(expectedIdentity.groups)
    ) {
      fail(`procfs process Groups drift: ${unitName}`);
    }
  }
  if (
    canonicalJson(processIdentity.uid_before) !== canonicalJson(processIdentity.uid_after) ||
    canonicalJson(processIdentity.gid_before) !== canonicalJson(processIdentity.gid_after) ||
    canonicalJson(processIdentity.groups_before) !== canonicalJson(processIdentity.groups_after) ||
    canonicalJson(processIdentity.capabilities_before) !==
      canonicalJson(processIdentity.capabilities_after)
  ) {
    fail(`procfs process credentials changed during collection: ${unitName}`);
  }
  for (const key of ["capabilities_before", "capabilities_after"]) {
    validateNonRootEdgeCapabilitiesV1(
      { capabilities: processIdentity[key], uid: processIdentity.uid_before },
      unitName,
      key,
    );
    validateManagedProcessCapabilities(processIdentity[key], unit);
  }
}

function validateProtectedProcessIdVector(value, expected, label) {
  if (
    !Array.isArray(value) ||
    value.length !== 4 ||
    value.some((entry) => !Number.isSafeInteger(entry) || entry < 0 || entry > 0xffff_ffff) ||
    value.some((entry) => entry !== expected)
  ) {
    fail(`${label} does not match the reviewed service identity`);
  }
}

function validateProtectedProcessClosure(closure, request, nss, units, lifecycleByUnit) {
  exactKeys(
    closure,
    ["enumeration_kind", "passes", "protected_gids", "protected_uids"],
    "protected process credential closure",
  );
  if (closure.enumeration_kind !== PROTECTED_PROCESS_ENUMERATION_KIND) {
    fail("protected process closure does not use the reviewed full-thread enumeration");
  }
  const expectedProtected = protectedCredentialsForRequest(request, nss);
  if (
    canonicalJson(closure.protected_gids) !== canonicalJson(expectedProtected.protectedGids) ||
    canonicalJson(closure.protected_uids) !== canonicalJson(expectedProtected.protectedUids)
  ) {
    fail("protected process closure identity set is incomplete");
  }
  if (!Array.isArray(closure.passes) || closure.passes.length !== 2) {
    fail("protected process closure requires exactly two complete passes");
  }
  if (Buffer.byteLength(canonicalJson(closure), "utf8") > MAX_PROC_CLOSURE_EVIDENCE_BYTES) {
    fail("protected process closure exceeds its reviewed evidence byte bound");
  }
  const allowedByControlGroup = new Map();
  const allowedByUid = new Map();
  for (const unit of request.units) {
    const lifecycle = lifecycleByUnit.get(unit.unit_name);
    if (lifecycle?.kind !== "long-running") continue;
    const actual = units.find((entry) => entry.unit_name === unit.unit_name);
    const controlGroup = actual?.properties?.ControlGroup;
    if (allowedByControlGroup.has(controlGroup)) {
      fail("multiple managed units share one protected control group");
    }
    const identity = resolveExpectedUnitProcessIdentity(unit, nss, request.service_identities);
    if (allowedByUid.has(identity.uid)) {
      fail("multiple managed units share one protected service UID");
    }
    allowedByUid.set(identity.uid, unit.unit_name);
    allowedByControlGroup.set(controlGroup, {
      identity,
      mainPid: lifecycle.mainPid,
      unit,
      unitName: unit.unit_name,
    });
  }
  for (const [passIndex, pass] of closure.passes.entries()) {
    exactKeys(
      pass,
      ["holders", "processes_enumerated", "threads_examined"],
      `protected process pass[${passIndex}]`,
    );
    if (
      !Number.isSafeInteger(pass.processes_enumerated) ||
      pass.processes_enumerated < 1 ||
      pass.processes_enumerated > MAX_PROC_PROCESSES ||
      !Number.isSafeInteger(pass.threads_examined) ||
      pass.threads_examined < pass.processes_enumerated ||
      pass.threads_examined > MAX_PROC_THREADS ||
      !Array.isArray(pass.holders) ||
      pass.holders.length > pass.threads_examined
    ) {
      fail(`protected process pass[${passIndex}] has invalid enumeration bounds`);
    }
    const observed = new Set();
    let previous = null;
    for (const [holderIndex, holder] of pass.holders.entries()) {
      exactKeys(
        holder,
        [
          "capabilities",
          "control_group",
          "gid",
          "groups",
          "pid",
          "proc_directory_dev",
          "proc_directory_ino",
          "start_time_ticks",
          "tid",
          "uid",
        ],
        `protected process pass[${passIndex}] holder[${holderIndex}]`,
      );
      if (
        !Number.isSafeInteger(holder.pid) ||
        holder.pid < 1 ||
        !Number.isSafeInteger(holder.tid) ||
        holder.tid < 1 ||
        typeof holder.control_group !== "string" ||
        typeof holder.proc_directory_dev !== "string" ||
        !/^[1-9][0-9]*$/u.test(holder.proc_directory_dev) ||
        typeof holder.proc_directory_ino !== "string" ||
        !/^[1-9][0-9]*$/u.test(holder.proc_directory_ino) ||
        typeof holder.start_time_ticks !== "string" ||
        !/^[1-9][0-9]*$/u.test(holder.start_time_ticks)
      ) {
        fail(`protected process pass[${passIndex}] holder is malformed`);
      }
      const ordering = [holder.pid, holder.tid];
      if (
        previous !== null &&
        (ordering[0] < previous[0] ||
          (ordering[0] === previous[0] && ordering[1] <= previous[1]))
      ) {
        fail(`protected process pass[${passIndex}] holders are not uniquely sorted`);
      }
      previous = ordering;
      const allowed = allowedByControlGroup.get(holder.control_group);
      if (!allowed) {
        fail(`protected credential holder is outside every managed unit cgroup: ${holder.pid}/${holder.tid}`);
      }
      validateNonRootEdgeCapabilitiesV1(holder, holder.pid, holder.tid);
      validateManagedProcessCapabilities(holder.capabilities, allowed.unit);
      validateProtectedProcessIdVector(
        holder.uid,
        allowed.identity.uid,
        `${allowed.unitName} protected holder UID`,
      );
      validateProtectedProcessIdVector(
        holder.gid,
        allowed.identity.gid,
        `${allowed.unitName} protected holder GID`,
      );
      if (canonicalJson(holder.groups) !== canonicalJson(allowed.identity.groups)) {
        fail(`${allowed.unitName} protected holder supplementary groups drift`);
      }
      if (holder.pid === allowed.mainPid && holder.tid === allowed.mainPid) {
        observed.add(allowed.unitName);
      }
    }
    for (const allowed of allowedByControlGroup.values()) {
      if (!observed.has(allowed.unitName)) {
        fail(`protected process pass[${passIndex}] omits managed MainPID: ${allowed.unitName}`);
      }
    }
  }
  if (canonicalJson(closure.passes[0].holders) !== canonicalJson(closure.passes[1].holders)) {
    fail("protected process holders changed between complete procfs passes");
  }
}

function validatePolicyFileEvidence(file, path, label) {
  exactKeys(
    file,
    ["dev", "gid", "ino", "mode", "nlink", "path", "sha256", "size", "uid"],
    label,
  );
  validateDigest(file.sha256, `${label} SHA-256`);
  if (
    file.path !== path ||
    file.uid !== 0 ||
    !Number.isSafeInteger(file.gid) ||
    file.gid < 0 ||
    file.gid > 0xffff_ffff ||
    file.nlink !== 1 ||
    !Number.isSafeInteger(file.size) ||
    file.size < 1 ||
    file.size > MAX_NSS_POLICY_FILE_BYTES ||
    typeof file.dev !== "string" ||
    !/^(?:0|[1-9][0-9]*)$/u.test(file.dev) ||
    typeof file.ino !== "string" ||
    !/^(?:0|[1-9][0-9]*)$/u.test(file.ino) ||
    typeof file.mode !== "string" ||
    !/^[0-7]{4}$/u.test(file.mode) ||
    (Number.parseInt(file.mode, 8) & 0o7000) !== 0 ||
    (Number.parseInt(file.mode, 8) & 0o022) !== 0
  ) {
    fail(`${label} metadata is not trusted`);
  }
}

function validateStoppedNssEvidence(nss, request) {
  exactKeys(
    nss,
    [
      "backend_profile",
      "enumeration_kind",
      "group_file",
      "group_stdout_sha256",
      "groups",
      "nsswitch_file",
      "passwd_file",
      "passwd_stdout_sha256",
      "sources",
      "users",
    ],
    "stopped-edge NSS evidence",
  );
  if (
    nss.backend_profile !== NSS_BACKEND_PROFILE ||
    nss.enumeration_kind !== NSS_ENUMERATION_KIND ||
    canonicalJson(nss.sources) !== canonicalJson({
      group: ["files"],
      initgroups: "inherits-group",
      passwd: ["files"],
    })
  ) {
    fail("stopped-edge NSS evidence is not the reviewed complete local-files profile");
  }
  validatePolicyFileEvidence(nss.nsswitch_file, "/etc/nsswitch.conf", "stopped-edge nsswitch file");
  validatePolicyFileEvidence(nss.passwd_file, "/etc/passwd", "stopped-edge passwd file");
  validatePolicyFileEvidence(nss.group_file, "/etc/group", "stopped-edge group file");
  validateDigest(nss.passwd_stdout_sha256, "stopped-edge passwd enumeration SHA-256");
  validateDigest(nss.group_stdout_sha256, "stopped-edge group enumeration SHA-256");
  if (
    !Array.isArray(nss.users) ||
    nss.users.length < 1 ||
    nss.users.length > MAX_NSS_USERS ||
    !Array.isArray(nss.groups) ||
    nss.groups.length < 1 ||
    nss.groups.length > MAX_NSS_GROUPS ||
    Buffer.byteLength(canonicalJson(nss), "utf8") > MAX_NSS_EVIDENCE_BYTES
  ) {
    fail("stopped-edge NSS evidence exceeds its reviewed bounds");
  }
  const usersByName = new Map();
  const usersByUid = new Map();
  for (const user of nss.users) {
    exactKeys(user, ["name", "primary_gid", "supplementary_gids", "uid"], "stopped-edge NSS user");
    validateNssName(user.name, "stopped-edge NSS user name");
    if (
      usersByName.has(user.name) ||
      usersByUid.has(user.uid) ||
      !Number.isSafeInteger(user.uid) ||
      user.uid < 0 ||
      user.uid > 0xffff_ffff ||
      !Number.isSafeInteger(user.primary_gid) ||
      user.primary_gid < 0 ||
      user.primary_gid > 0xffff_ffff ||
      !Array.isArray(user.supplementary_gids) ||
      user.supplementary_gids.length < 1 ||
      user.supplementary_gids.some((gid) => !Number.isSafeInteger(gid) || gid < 0 || gid > 0xffff_ffff) ||
      canonicalJson(user.supplementary_gids) !==
        canonicalJson([...new Set(user.supplementary_gids)].sort((left, right) => left - right)) ||
      !user.supplementary_gids.includes(user.primary_gid)
    ) {
      fail("stopped-edge NSS user data is malformed or aliased");
    }
    usersByName.set(user.name, user);
    usersByUid.set(user.uid, user);
  }
  if (canonicalJson([...usersByName.keys()]) !== canonicalJson([...usersByName.keys()].sort())) {
    fail("stopped-edge NSS users are not canonically sorted");
  }
  const groupsByName = new Map();
  const groupsByGid = new Map();
  for (const group of nss.groups) {
    exactKeys(group, ["gid", "members", "name"], "stopped-edge NSS group");
    validateNssName(group.name, "stopped-edge NSS group name");
    if (
      groupsByName.has(group.name) ||
      groupsByGid.has(group.gid) ||
      !Number.isSafeInteger(group.gid) ||
      group.gid < 0 ||
      group.gid > 0xffff_ffff ||
      !Array.isArray(group.members) ||
      group.members.length > MAX_NSS_GROUP_MEMBERS ||
      canonicalJson(group.members) !== canonicalJson([...new Set(group.members)].sort())
    ) {
      fail("stopped-edge NSS group data is malformed or aliased");
    }
    for (const member of group.members) validateNssName(member, "stopped-edge NSS group member");
    groupsByName.set(group.name, group);
    groupsByGid.set(group.gid, group);
  }
  if (canonicalJson([...groupsByName.keys()]) !== canonicalJson([...groupsByName.keys()].sort())) {
    fail("stopped-edge NSS groups are not canonically sorted");
  }
  for (const group of nss.groups) {
    for (const memberName of group.members) {
      const member = usersByName.get(memberName);
      if (!member || !member.supplementary_gids.includes(group.gid)) {
        fail(`stopped-edge NSS group membership is inconsistent: ${group.name}`);
      }
    }
  }
  for (const user of nss.users) {
    if (!groupsByGid.has(user.primary_gid)) {
      fail(`stopped-edge NSS user primary group is missing: ${user.name}`);
    }
    for (const gid of user.supplementary_gids) {
      if (gid === user.primary_gid) continue;
      if (!groupsByGid.get(gid)?.members.includes(user.name)) {
        fail(`stopped-edge NSS reverse group membership is inconsistent: ${user.name}`);
      }
    }
  }

  const expectedByUser = new Map();
  const expectedExplicitMembersByGid = new Map();
  for (const unit of request.units) {
    const identity = resolveExpectedUnitProcessIdentity(unit, nss, request.service_identities);
    const userName = unit.hardening.User?.[0];
    if (expectedByUser.has(userName)) fail("multiple stopped-edge units share one service user");
    expectedByUser.set(userName, identity);
    for (const gid of identity.groups) {
      if (gid === identity.gid) continue;
      const members = expectedExplicitMembersByGid.get(gid) ?? [];
      members.push(userName);
      expectedExplicitMembersByGid.set(gid, members);
    }
  }
  const expectedProtected = protectedCredentialsForRequest(request, nss);
  const protectedUids = new Set(expectedProtected.protectedUids);
  const protectedGids = new Set(expectedProtected.protectedGids);
  for (const user of nss.users) {
    const expected = expectedByUser.get(user.name);
    if (expected) {
      if (
        user.uid !== expected.uid ||
        user.primary_gid !== expected.gid ||
        canonicalJson(user.supplementary_gids) !== canonicalJson(expected.groups)
      ) {
        fail(`stopped-edge service account group closure drift: ${user.name}`);
      }
      continue;
    }
    if (
      protectedUids.has(user.uid) ||
      protectedGids.has(user.primary_gid) ||
      user.supplementary_gids.some((gid) => protectedGids.has(gid))
    ) {
      fail(`stopped-edge protected identity is held by an unreviewed account: ${user.name}`);
    }
  }
  for (const gid of expectedProtected.protectedGids) {
    const group = groupsByGid.get(gid);
    if (!group) fail(`stopped-edge protected GID is not enumerable: ${gid}`);
    const expectedMembers = [...(expectedExplicitMembersByGid.get(gid) ?? [])].sort();
    if (canonicalJson(group.members) !== canonicalJson(expectedMembers)) {
      fail(`stopped-edge protected group membership drift: ${group.name}`);
    }
  }
  return expectedProtected;
}

function validateStoppedProtectedClosure(closure, expectedProtected) {
  exactKeys(
    closure,
    ["enumeration_kind", "passes", "protected_gids", "protected_uids"],
    "stopped-edge protected process closure",
  );
  if (
    closure.enumeration_kind !== PROTECTED_PROCESS_ENUMERATION_KIND ||
    canonicalJson(closure.protected_gids) !== canonicalJson(expectedProtected.protectedGids) ||
    canonicalJson(closure.protected_uids) !== canonicalJson(expectedProtected.protectedUids) ||
    !Array.isArray(closure.passes) ||
    closure.passes.length !== 2 ||
    Buffer.byteLength(canonicalJson(closure), "utf8") > MAX_PROC_CLOSURE_EVIDENCE_BYTES
  ) {
    fail("stopped-edge protected process closure is incomplete");
  }
  for (const [index, pass] of closure.passes.entries()) {
    exactKeys(pass, ["holders", "processes_enumerated", "threads_examined"], `stopped-edge proc pass[${index}]`);
    if (
      !Number.isSafeInteger(pass.processes_enumerated) ||
      pass.processes_enumerated < 1 ||
      pass.processes_enumerated > MAX_PROC_PROCESSES ||
      !Number.isSafeInteger(pass.threads_examined) ||
      pass.threads_examined < pass.processes_enumerated ||
      pass.threads_examined > MAX_PROC_THREADS ||
      !Array.isArray(pass.holders) ||
      pass.holders.length !== 0
    ) {
      fail(`stopped-edge proc pass[${index}] found a protected credential holder or invalid bounds`);
    }
  }
  if (canonicalJson(closure.passes[0].holders) !== canonicalJson(closure.passes[1].holders)) {
    fail("stopped-edge proc passes are not one stable empty credential closure");
  }
}

function validateStoppedUnitPasses(passes, request) {
  if (!Array.isArray(passes) || passes.length !== 2) {
    fail("stopped-edge unit evidence requires two complete passes");
  }
  for (const [passIndex, pass] of passes.entries()) {
    if (!Array.isArray(pass) || pass.length !== request.units.length) {
      fail(`stopped-edge unit pass[${passIndex}] is incomplete`);
    }
    for (const [index, state] of pass.entries()) {
      const expected = request.units[index];
      exactKeys(
        state,
        [
          "active_state",
          "control_group",
          "drop_in_paths",
          "fragment_path",
          "invocation_id",
          "load_state",
          "main_pid",
          "sub_state",
          "unit_name",
        ],
        `stopped-edge unit pass[${passIndex}][${index}]`,
      );
      if (
        state.unit_name !== expected.unit_name ||
        state.active_state !== "inactive" ||
        state.sub_state !== "dead" ||
        state.main_pid !== "0" ||
        state.control_group !== "" ||
        state.drop_in_paths !== "" ||
        state.fragment_path !== expected.fragment_path ||
        state.load_state !== "loaded" ||
        !new Set(["", "0".repeat(32)]).has(state.invocation_id)
      ) {
        fail(`stopped-edge unit is not fully stopped: ${expected.unit_name}`);
      }
    }
  }
  if (canonicalJson(passes[0]) !== canonicalJson(passes[1])) {
    fail("stopped-edge unit state changed during credential closure collection");
  }
}

function validateRuntimeSocketAbsencePasses(passes, request) {
  const expectedPaths = request.runtime_paths
    .filter((entry) => entry.file_type === "socket")
    .map((entry) => entry.target_path)
    .sort();
  if (expectedPaths.length < 1 || !Array.isArray(passes) || passes.length !== 2) {
    fail("stopped-edge socket absence evidence is incomplete");
  }
  for (const [passIndex, pass] of passes.entries()) {
    if (!Array.isArray(pass) || pass.length !== expectedPaths.length) {
      fail(`stopped-edge socket absence pass[${passIndex}] is incomplete`);
    }
    for (const [index, entry] of pass.entries()) {
      exactKeys(
        entry,
        ["parent_dev", "parent_ino", "parent_path", "parent_state", "target_path"],
        `stopped-edge socket absence pass[${passIndex}][${index}]`,
      );
      if (
        entry.target_path !== expectedPaths[index] ||
        entry.parent_path !== dirname(entry.target_path) ||
        !new Set(["absent", "canonical-directory"]).has(entry.parent_state)
      ) {
        fail(`stopped-edge socket absence path drift: ${expectedPaths[index]}`);
      }
      if (entry.parent_state === "absent") {
        if (entry.parent_dev !== null || entry.parent_ino !== null) {
          fail("absent stopped-edge socket parent carries an inode claim");
        }
      } else if (
        typeof entry.parent_dev !== "string" ||
        !/^(?:0|[1-9][0-9]*)$/u.test(entry.parent_dev) ||
        typeof entry.parent_ino !== "string" ||
        !/^[1-9][0-9]*$/u.test(entry.parent_ino)
      ) {
        fail("canonical stopped-edge socket parent has malformed inode evidence");
      }
    }
  }
  if (canonicalJson(passes[0]) !== canonicalJson(passes[1])) {
    fail("stopped-edge socket absence changed during credential closure collection");
  }
}

function validateStoppedAccountPolicy(policy, request, nss) {
  exactKeys(policy, ["accounts", "passwd_file", "shadow_file"], "stopped-edge account policy");
  if (canonicalJson(policy.passwd_file) !== canonicalJson(nss.passwd_file)) {
    fail("stopped-edge account policy is not bound to the NSS passwd file");
  }
  validatePolicyFileEvidence(policy.shadow_file, "/etc/shadow", "stopped-edge shadow file");
  const expected = [...request.service_identities]
    .sort((left, right) => compareNssNames(left.user_name, right.user_name));
  if (!Array.isArray(policy.accounts) || policy.accounts.length !== expected.length) {
    fail("stopped-edge account policy does not cover every service identity");
  }
  for (const [index, account] of policy.accounts.entries()) {
    exactKeys(account, ["gid", "password_state", "shell", "uid", "user_name"], `stopped-edge account[${index}]`);
    if (
      account.user_name !== expected[index].user_name ||
      account.uid !== expected[index].uid ||
      account.gid !== expected[index].gid ||
      account.password_state !== "locked" ||
      !LOCKED_SERVICE_ACCOUNT_SHELLS.includes(account.shell)
    ) {
      fail(`stopped-edge service account is not locked and login-disabled: ${expected[index].user_name}`);
    }
  }
}

function validateStoppedHost(host, request, expectedMachineIdSha256, expectedBootId) {
  exactKeys(
    host,
    [
      "boot_id",
      "collector_pid_namespace",
      "core_pattern",
      "kernel_release",
      "machine_id_sha256",
      "pid1_name",
      "pid1_nspid",
      "pid1_pid_namespace",
      "systemd_version",
      "uptime_finished_milliseconds",
      "uptime_started_milliseconds",
    ],
    "stopped-edge host",
  );
  validateUuid(host.boot_id, "stopped-edge boot id");
  if (
    host.machine_id_sha256 !== expectedMachineIdSha256 ||
    (expectedBootId !== undefined && host.boot_id !== expectedBootId) ||
    host.collector_pid_namespace !== host.pid1_pid_namespace ||
    typeof host.pid1_pid_namespace !== "string" ||
    !/^pid:\[[1-9][0-9]*\]$/u.test(host.pid1_pid_namespace) ||
    host.pid1_name !== "systemd" ||
    canonicalJson(host.pid1_nspid) !== canonicalJson([1]) ||
    !Number.isSafeInteger(host.uptime_started_milliseconds) ||
    !Number.isSafeInteger(host.uptime_finished_milliseconds) ||
    host.uptime_finished_milliseconds < host.uptime_started_milliseconds ||
    request.deployment_profile !== "edge-hetzner-v1" ||
    host.core_pattern !== "|/usr/bin/false"
  ) {
    fail("stopped-edge host, boot, PID namespace, or core policy is not approved");
  }
}

function validateTrustedCommandClosure(commands, label) {
  if (!Array.isArray(commands) || commands.length !== REQUIRED_COMMANDS.length + 1) {
    fail(`${label} does not bind the complete command TCB`);
  }
  for (const command of commands) {
    exactKeys(command, ["gid", "mode", "nlink", "path", "sha256", "uid"], `${label} command`);
    validateAbsolutePath(command.path, `${label} command path`);
    validateDigest(command.sha256, `${label} command digest`);
    if (command.uid !== 0 || command.nlink !== 1 || (Number.parseInt(command.mode, 8) & 0o022) !== 0) {
      fail(`${label} has untrusted command metadata: ${command.path}`);
    }
  }
  if (
    canonicalJson(commands.map((entry) => entry.path).sort()) !==
    canonicalJson([...REQUIRED_COMMANDS, "/usr/bin/node"].sort())
  ) {
    fail(`${label} command TCB paths are not closed`);
  }
}

export function validateStoppedEdgeActivationEvidence({
  evidence,
  request,
  expectedMachineIdSha256,
  expectedBootId,
  nowUnixSeconds,
  maxAgeSeconds = 120,
}) {
  exactKeys(
    evidence,
    [
      "account_policy",
      "approved_plan_sha256",
      "challenge_hex",
      "collected_finished_unix_seconds",
      "collected_started_unix_seconds",
      "collector",
      "collector_process",
      "evidence_kind",
      "host",
      "manifest_sha256",
      "nss",
      "protected_process_closure",
      "runtime_socket_absence_passes",
      "schema_version",
      "stopped_unit_passes",
      "trusted_commands",
    ],
    "stopped-edge activation evidence",
  );
  if (
    evidence.schema_version !== STOPPED_EDGE_SCHEMA_VERSION ||
    evidence.evidence_kind !== STOPPED_EDGE_EVIDENCE_KIND ||
    evidence.collector !== RUNTIME_COLLECTOR ||
    request.schema_version !== LIVE_SCHEMA_VERSION ||
    request.collector !== RUNTIME_COLLECTOR ||
    request.deployment_profile !== "edge-hetzner-v1" ||
    evidence.manifest_sha256 !== request.manifest_sha256 ||
    evidence.approved_plan_sha256 !== request.approved_plan_sha256
  ) {
    fail("stopped-edge evidence schema, collector, profile, or artifact binding is not reviewed");
  }
  if (
    typeof evidence.challenge_hex !== "string" ||
    !/^[0-9a-f]{64}$/u.test(evidence.challenge_hex) ||
    /^0{64}$/u.test(evidence.challenge_hex)
  ) {
    fail("stopped-edge challenge must be an internally random 256-bit value");
  }
  const start = evidence.collected_started_unix_seconds;
  const finish = evidence.collected_finished_unix_seconds;
  if (
    !Number.isSafeInteger(start) ||
    !Number.isSafeInteger(finish) ||
    finish < start ||
    finish - start > MAX_COLLECTION_SECONDS ||
    !Number.isSafeInteger(nowUnixSeconds) ||
    nowUnixSeconds < finish ||
    nowUnixSeconds - finish > maxAgeSeconds
  ) {
    fail("stopped-edge evidence collection window is stale or invalid");
  }
  exactKeys(evidence.collector_process, ["egid", "euid", "pid"], "stopped-edge collector process");
  if (evidence.collector_process.euid !== 0 || evidence.collector_process.egid !== 0) {
    fail("stopped-edge collector was not root");
  }
  validateStoppedHost(evidence.host, request, expectedMachineIdSha256, expectedBootId);
  validateTrustedCommandClosure(evidence.trusted_commands, "stopped-edge evidence");
  const expectedProtected = validateStoppedNssEvidence(evidence.nss, request);
  validateStoppedAccountPolicy(evidence.account_policy, request, evidence.nss);
  validateStoppedUnitPasses(evidence.stopped_unit_passes, request);
  validateRuntimeSocketAbsencePasses(evidence.runtime_socket_absence_passes, request);
  validateStoppedProtectedClosure(evidence.protected_process_closure, expectedProtected);
  return true;
}

export function validateLiveRuntimeEvidence({
  evidence,
  request,
  expectedMachineIdSha256,
  expectedBootId,
  nowUnixSeconds,
  maxAgeSeconds = 120,
}) {
  exactKeys(
    evidence,
    [
      "approved_plan_sha256",
      "challenge_hex",
      "collected_finished_unix_seconds",
      "collected_started_unix_seconds",
      "collector",
      "collector_process",
      "evidence_kind",
      "host",
      "installed_files",
      "manifest_sha256",
      "nss",
      "protected_process_closure",
      "runtime_directories",
      "runtime_paths",
      "schema_version",
      "secret_access_checks",
      "secret_parent_directories",
      "systemd_analyze_verify",
      "trusted_commands",
      "units",
    ],
    "live runtime evidence",
  );
  if (evidence.schema_version !== LIVE_SCHEMA_VERSION || evidence.evidence_kind !== LIVE_EVIDENCE_KIND) {
    fail("live runtime evidence schema or kind is not reviewed");
  }
  if (request.schema_version !== LIVE_SCHEMA_VERSION || request.collector !== RUNTIME_COLLECTOR) {
    fail("runtime evidence request schema or collector is not reviewed");
  }
  if (evidence.collector !== RUNTIME_COLLECTOR) fail("live runtime collector identity mismatch");
  if (canonicalJson(request.systemctl_show_properties) !== canonicalJson(RUNTIME_SYSTEMCTL_SHOW_PROPERTIES)) {
    fail("runtime request systemctl property schema is not the reviewed closed set");
  }
  if (!Array.isArray(request.service_identities) || request.service_identities.length !== request.units.length) {
    fail("runtime request service identity bindings are incomplete");
  }
  if (evidence.manifest_sha256 !== request.manifest_sha256 || evidence.approved_plan_sha256 !== request.approved_plan_sha256) {
    fail("live evidence is not bound to the approved manifest and plan");
  }
  if (typeof evidence.challenge_hex !== "string" || !/^[0-9a-f]{64}$/u.test(evidence.challenge_hex) || /^0{64}$/u.test(evidence.challenge_hex)) {
    fail("live evidence challenge must be an internally random 256-bit value");
  }
  const start = evidence.collected_started_unix_seconds;
  const finish = evidence.collected_finished_unix_seconds;
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(finish) || finish < start || finish - start > MAX_COLLECTION_SECONDS) {
    fail("live evidence collection window is invalid");
  }
  if (!Number.isSafeInteger(nowUnixSeconds) || nowUnixSeconds < finish || nowUnixSeconds - finish > maxAgeSeconds) {
    fail("live evidence is stale or from the future");
  }
  exactKeys(evidence.collector_process, ["egid", "euid", "pid"], "collector process");
  if (evidence.collector_process.euid !== 0 || evidence.collector_process.egid !== 0) {
    fail("live collector was not root");
  }
  exactKeys(
    evidence.host,
    [
      "boot_id",
      "collector_pid_namespace",
      "core_pattern",
      "kernel_release",
      "machine_id_sha256",
      "pid1_name",
      "pid1_nspid",
      "pid1_pid_namespace",
      "systemd_version",
      "uptime_finished_milliseconds",
      "uptime_started_milliseconds",
    ],
    "live evidence host",
  );
  validateUuid(evidence.host.boot_id, "live evidence boot id");
  if (evidence.host.machine_id_sha256 !== expectedMachineIdSha256) fail("live evidence came from another host");
  if (expectedBootId !== undefined && evidence.host.boot_id !== expectedBootId) fail("live evidence came from another boot");
  if (
    evidence.host.collector_pid_namespace !== evidence.host.pid1_pid_namespace ||
    typeof evidence.host.pid1_pid_namespace !== "string" ||
    !/^pid:\[[1-9][0-9]*\]$/u.test(evidence.host.pid1_pid_namespace) ||
    evidence.host.pid1_name !== "systemd" ||
    canonicalJson(evidence.host.pid1_nspid) !== canonicalJson([1])
  ) {
    fail("live evidence is not bound to its visible systemd PID namespace root");
  }
  if (
    new Set(["edge-hetzner-v1", "edge-rollback-authority-v1"]).has(
      request.deployment_profile,
    ) &&
    evidence.host.core_pattern !== "|/usr/bin/false"
  ) {
    fail("edge live evidence requires kernel.core_pattern=|/usr/bin/false");
  }
  if (
    !Number.isSafeInteger(evidence.host.uptime_started_milliseconds) ||
    !Number.isSafeInteger(evidence.host.uptime_finished_milliseconds) ||
    evidence.host.uptime_finished_milliseconds < evidence.host.uptime_started_milliseconds
  ) fail("live evidence uptime binding is invalid");

  if (!Array.isArray(evidence.trusted_commands) || evidence.trusted_commands.length !== REQUIRED_COMMANDS.length + 1) {
    fail("live evidence does not bind the complete command TCB");
  }
  for (const command of evidence.trusted_commands) {
    exactKeys(command, ["gid", "mode", "nlink", "path", "sha256", "uid"], "trusted command");
    validateAbsolutePath(command.path, "trusted command path");
    validateDigest(command.sha256, "trusted command digest");
    if (command.uid !== 0 || command.nlink !== 1 || (Number.parseInt(command.mode, 8) & 0o022) !== 0) {
      fail(`untrusted runtime command metadata: ${command.path}`);
    }
  }
  const commandPaths = evidence.trusted_commands.map((entry) => entry.path).sort();
  const expectedCommandPaths = [...REQUIRED_COMMANDS, "/usr/bin/node"].sort();
  if (canonicalJson(commandPaths) !== canonicalJson(expectedCommandPaths)) {
    fail("live evidence command TCB paths are not closed");
  }

  if (!Array.isArray(evidence.installed_files) || evidence.installed_files.length !== request.installed_files.length) {
    fail("live installed-file evidence is incomplete");
  }
  for (let index = 0; index < request.installed_files.length; index += 1) {
    const expected = request.installed_files[index];
    const actual = evidence.installed_files[index];
    exactKeys(
      actual,
      [
        "acl_sha256",
        "capability_sha256",
        "dev",
        "expected_type",
        "file_type",
        "gid",
        "ino",
        "mode",
        "nlink",
        "sha256",
        "sha256_command_sha256",
        "size",
        "stat_command_sha256",
        "target_path",
        "uid",
        "xattr_sha256",
      ],
      `live installed_files[${index}]`,
    );
    for (const key of ["file_type", "gid", "mode", "nlink", "sha256", "target_path", "uid"]) {
      if (actual[key] !== expected[key]) fail(`live installed-file ${key} drift: ${expected.target_path}`);
    }
    for (const key of ["acl_sha256", "capability_sha256", "sha256_command_sha256", "stat_command_sha256", "xattr_sha256"]) {
      validateDigest(actual[key], `live installed-file ${key}`);
    }
  }
  const expectedSecretParentPaths = secretParentPaths(request.secret_files);
  if (
    !Array.isArray(evidence.secret_parent_directories) ||
    evidence.secret_parent_directories.length !== expectedSecretParentPaths.length
  ) {
    fail("live secret parent directory evidence is incomplete");
  }
  for (let index = 0; index < expectedSecretParentPaths.length; index += 1) {
    const actual = evidence.secret_parent_directories[index];
    exactKeys(
      actual,
      [
        "acl_sha256",
        "capability_sha256",
        "dev",
        "expected_type",
        "file_type",
        "gid",
        "ino",
        "mode",
        "nlink",
        "size",
        "stat_command_sha256",
        "target_path",
        "uid",
        "xattr_sha256",
      ],
      `live secret_parent_directories[${index}]`,
    );
    if (actual.target_path !== expectedSecretParentPaths[index] || actual.file_type !== "directory" || actual.expected_type !== "directory") {
      fail(`live secret parent directory path/type drift: ${expectedSecretParentPaths[index]}`);
    }
    for (const key of ["acl_sha256", "capability_sha256", "stat_command_sha256", "xattr_sha256"]) {
      validateDigest(actual[key], `live secret parent ${key}`);
    }
  }
  if (!Array.isArray(evidence.runtime_directories) || evidence.runtime_directories.length !== request.tmpfiles_directories.length) {
    fail("live tmpfiles directory evidence is incomplete");
  }
  for (let index = 0; index < request.tmpfiles_directories.length; index += 1) {
    const expected = request.tmpfiles_directories[index];
    const actual = evidence.runtime_directories[index];
    exactKeys(
      actual,
      [
        "acl_sha256",
        "capability_sha256",
        "dev",
        "expected_type",
        "file_type",
        "gid",
        "group_name",
        "ino",
        "mode",
        "nlink",
        "size",
        "stat_command_sha256",
        "target_path",
        "uid",
        "user_name",
        "xattr_sha256",
      ],
      `live runtime_directories[${index}]`,
    );
    if (
      actual.target_path !== expected.target_path ||
      actual.mode !== expected.mode ||
      actual.user_name !== expected.user_name ||
      actual.group_name !== expected.group_name ||
      actual.file_type !== "directory" ||
      actual.expected_type !== "directory"
    ) fail(`live tmpfiles directory drift: ${expected.target_path}`);
    for (const key of ["acl_sha256", "capability_sha256", "stat_command_sha256", "xattr_sha256"]) {
      validateDigest(actual[key], `live tmpfiles directory ${key}`);
    }
  }
  if (!Array.isArray(request.runtime_paths) || !Array.isArray(evidence.runtime_paths)) {
    fail("live runtime path schema is incomplete");
  }
  if (evidence.runtime_paths.length !== request.runtime_paths.length) {
    fail("live runtime path evidence is incomplete");
  }
  for (let index = 0; index < request.runtime_paths.length; index += 1) {
    const expected = request.runtime_paths[index];
    const actual = evidence.runtime_paths[index];
    exactKeys(
      actual,
      [
        "acl_sha256",
        "capability_sha256",
        "dev",
        "expected_type",
        "file_type",
        "gid",
        "ino",
        "mode",
        "nlink",
        "size",
        "stat_command_sha256",
        "target_path",
        "uid",
        "xattr_sha256",
      ],
      `live runtime_paths[${index}]`,
    );
    for (const key of ["file_type", "gid", "mode", "target_path", "uid"]) {
      if (actual[key] !== expected[key]) {
        fail(`live runtime path ${key} drift: ${expected.target_path}`);
      }
    }
    if (actual.expected_type !== expected.file_type) {
      fail(`live runtime path type drift: ${expected.target_path}`);
    }
    for (const key of ["acl_sha256", "capability_sha256", "stat_command_sha256", "xattr_sha256"]) {
      validateDigest(actual[key], `live runtime path ${key}`);
    }
  }
  if (!Array.isArray(evidence.units) || evidence.units.length !== request.units.length) {
    fail("live systemd unit evidence is incomplete");
  }
  const lifecycleByUnit = new Map();
  for (let index = 0; index < request.units.length; index += 1) {
    const expected = request.units[index];
    const actual = evidence.units[index];
    exactKeys(
      actual,
      ["fragment_sha256", "generation_confirmations", "process_identity", "properties", "unit_name"],
      `live units[${index}]`,
    );
    if (actual.unit_name !== expected.unit_name || actual.properties.FragmentPath !== expected.fragment_path) {
      fail(`live systemd unit identity drift: ${expected.unit_name}`);
    }
    if (actual.properties.DropInPaths !== "") fail(`live systemd drop-in detected: ${expected.unit_name}`);
    for (const key of ["ExecStartPost", "ExecCondition", "EnvironmentFiles", "RootDirectory", "RootImage", "BindPaths", "BindReadOnlyPaths", "LoadCredential", "SetCredential"]) {
      if (actual.properties[key] !== "") fail(`live systemd ${key} is forbidden: ${expected.unit_name}`);
    }
    const fragment = request.installed_files.find((file) => file.target_path === expected.fragment_path);
    if (!fragment || actual.fragment_sha256 !== fragment.sha256) {
      fail(`live systemd fragment hash drift: ${expected.unit_name}`);
    }
    const lifecycle = validateEffectiveUnitProperties(
      expected,
      actual.properties,
      evidence.host.uptime_finished_milliseconds,
    );
    validateGenerationConfirmations(actual.generation_confirmations, actual.properties, expected.unit_name);
    lifecycleByUnit.set(expected.unit_name, lifecycle);
  }
  if (
    evidence.systemd_analyze_verify.exit_status !== 0 ||
    evidence.systemd_analyze_verify.stdout !== "" ||
    evidence.systemd_analyze_verify.stderr !== "" ||
    canonicalJson(evidence.systemd_analyze_verify.argv) !== canonicalJson(request.systemd_analyze_argv)
  ) fail("live systemd-analyze verify evidence failed");
  exactKeys(
    evidence.nss,
    [
      "backend_profile",
      "enumeration_kind",
      "group_file",
      "group_stdout_sha256",
      "groups",
      "nsswitch_file",
      "passwd_file",
      "passwd_stdout_sha256",
      "sources",
      "users",
    ],
    "live NSS evidence",
  );
  if (evidence.nss.backend_profile !== NSS_BACKEND_PROFILE) {
    fail("live NSS evidence does not use the reviewed local-files-only backend");
  }
  if (evidence.nss.enumeration_kind !== NSS_ENUMERATION_KIND) {
    fail("live NSS evidence does not use the reviewed complete-enumeration profile");
  }
  exactKeys(evidence.nss.sources, ["group", "initgroups", "passwd"], "live NSS sources");
  if (
    canonicalJson(evidence.nss.sources) !== canonicalJson({
      group: ["files"],
      initgroups: "inherits-group",
      passwd: ["files"],
    })
  ) {
    fail("live NSS sources are not the reviewed local-files-only profile");
  }
  for (const [key, path] of [
    ["nsswitch_file", "/etc/nsswitch.conf"],
    ["passwd_file", "/etc/passwd"],
    ["group_file", "/etc/group"],
  ]) {
    const file = evidence.nss[key];
    exactKeys(
      file,
      ["dev", "gid", "ino", "mode", "nlink", "path", "sha256", "size", "uid"],
      `live NSS ${key}`,
    );
    validateDigest(file.sha256, `live NSS ${key} SHA-256`);
    if (
      file.path !== path ||
      file.uid !== 0 ||
      !Number.isSafeInteger(file.gid) ||
      file.gid < 0 ||
      file.gid > 0xffff_ffff ||
      file.nlink !== 1 ||
      !Number.isSafeInteger(file.size) ||
      file.size < 1 ||
      file.size > MAX_NSS_POLICY_FILE_BYTES ||
      typeof file.dev !== "string" ||
      !/^(?:0|[1-9][0-9]*)$/u.test(file.dev) ||
      typeof file.ino !== "string" ||
      !/^(?:0|[1-9][0-9]*)$/u.test(file.ino) ||
      typeof file.mode !== "string" ||
      !/^[0-7]{4}$/u.test(file.mode) ||
      (Number.parseInt(file.mode, 8) & 0o7000) !== 0 ||
      (Number.parseInt(file.mode, 8) & 0o022) !== 0
    ) {
      fail(`live NSS ${key} metadata is not trusted`);
    }
  }
  validateDigest(evidence.nss.passwd_stdout_sha256, "live passwd enumeration SHA-256");
  validateDigest(evidence.nss.group_stdout_sha256, "live group enumeration SHA-256");
  if (!Array.isArray(evidence.nss.groups) || !Array.isArray(evidence.nss.users)) {
    fail("live NSS evidence arrays are missing");
  }
  if (
    evidence.nss.users.length < 1 ||
    evidence.nss.users.length > MAX_NSS_USERS ||
    evidence.nss.groups.length < 1 ||
    evidence.nss.groups.length > MAX_NSS_GROUPS ||
    Buffer.byteLength(canonicalJson(evidence.nss), "utf8") > MAX_NSS_EVIDENCE_BYTES
  ) {
    fail("live complete NSS evidence exceeds its record or byte bound");
  }
  const usersByName = new Map(evidence.nss.users.map((user) => [user.name, user]));
  const groupsByName = new Map(evidence.nss.groups.map((group) => [group.name, group]));
  if (usersByName.size !== evidence.nss.users.length || groupsByName.size !== evidence.nss.groups.length) {
    fail("live NSS evidence repeats identities");
  }
  if (
    canonicalJson(evidence.nss.users.map((user) => user.name)) !==
      canonicalJson(evidence.nss.users.map((user) => user.name).sort()) ||
    canonicalJson(evidence.nss.groups.map((group) => group.name)) !==
      canonicalJson(evidence.nss.groups.map((group) => group.name).sort())
  ) {
    fail("live NSS evidence identities are not canonically sorted");
  }
  if (new Set(evidence.nss.users.map((user) => user.uid)).size !== evidence.nss.users.length) {
    fail("live complete NSS evidence aliases a UID");
  }
  if (new Set(evidence.nss.groups.map((group) => group.gid)).size !== evidence.nss.groups.length) {
    fail("live complete NSS evidence aliases a GID");
  }
  for (const group of evidence.nss.groups) {
    exactKeys(group, ["gid", "members", "name"], `live NSS group ${group.name ?? "<unknown>"}`);
    validateNssName(group.name, "live NSS group name");
    if (Array.isArray(group.members)) {
      for (const member of group.members) {
        validateNssName(member, `live NSS group ${group.name} member`);
      }
    }
    if (
      !Number.isSafeInteger(group.gid) ||
      group.gid < 0 ||
      group.gid > 0xffff_ffff ||
      !Array.isArray(group.members) ||
      group.members.length > MAX_NSS_GROUP_MEMBERS ||
      canonicalJson(group.members) !== canonicalJson([...new Set(group.members)].sort())
    ) {
      fail("live NSS group data is malformed");
    }
  }
  for (const user of evidence.nss.users) {
    exactKeys(user, ["name", "primary_gid", "supplementary_gids", "uid"], `live NSS user ${user.name ?? "<unknown>"}`);
    validateNssName(user.name, "live NSS user name");
    if (
      !Number.isSafeInteger(user.uid) || user.uid < 0 || user.uid > 0xffff_ffff ||
      !Number.isSafeInteger(user.primary_gid) ||
      user.primary_gid < 0 ||
      user.primary_gid > 0xffff_ffff ||
      !Array.isArray(user.supplementary_gids) ||
      user.supplementary_gids.length < 1 ||
      user.supplementary_gids.some(
        (gid) => !Number.isSafeInteger(gid) || gid < 0 || gid > 0xffff_ffff,
      ) ||
      canonicalJson(user.supplementary_gids) !==
        canonicalJson([...new Set(user.supplementary_gids)].sort((left, right) => left - right)) ||
      !user.supplementary_gids.includes(user.primary_gid)
    ) fail("live NSS user data is malformed");
  }
  for (let index = 0; index < request.tmpfiles_directories.length; index += 1) {
    const expected = request.tmpfiles_directories[index];
    const actual = evidence.runtime_directories[index];
    const user = usersByName.get(expected.user_name);
    const group = groupsByName.get(expected.group_name);
    if (!user || !group || actual.uid !== user.uid || actual.gid !== group.gid) {
      fail(`live tmpfiles directory NSS owner drift: ${expected.target_path}`);
    }
  }
  for (const group of evidence.nss.groups) {
    for (const memberName of group.members) {
      const member = usersByName.get(memberName);
      if (!member || !member.supplementary_gids.includes(group.gid)) {
        fail(`live NSS group membership is inconsistent: ${group.name}`);
      }
    }
  }
  for (const user of evidence.nss.users) {
    for (const gid of user.supplementary_gids) {
      if (gid === user.primary_gid) continue;
      const group = evidence.nss.groups.find((entry) => entry.gid === gid);
      if (!group || !group.members.includes(user.name)) {
        fail(`live NSS reverse group membership is inconsistent: ${user.name}`);
      }
    }
  }
  const expectedPrimaryUsersByGid = new Map();
  const expectedExplicitMembersByGid = new Map();
  const expectedAllMembersByGid = new Map();
  const protectedGids = new Set();
  const addExpected = (map, gid, userName) => {
    const values = map.get(gid) ?? new Set();
    values.add(userName);
    map.set(gid, values);
  };
  for (const unit of request.units) {
    const userName = unit.hardening.User?.[0];
    const groupName = unit.hardening.Group?.[0];
    const user = usersByName.get(userName);
    const group = groupsByName.get(groupName);
    const pinned = request.service_identities.find((identity) => identity.unit_name === unit.unit_name);
    if (
      !user ||
      !group ||
      !pinned ||
      pinned.user_name !== userName ||
      pinned.group_name !== groupName ||
      pinned.uid !== user.uid ||
      pinned.gid !== group.gid ||
      user.uid < 1 ||
      group.gid < 1 ||
      user.primary_gid !== group.gid
    ) {
      fail(`live NSS primary identity drift: ${unit.unit_name}`);
    }
    protectedGids.add(group.gid);
    addExpected(expectedPrimaryUsersByGid, group.gid, userName);
    addExpected(expectedAllMembersByGid, group.gid, userName);
    const expectedGroups = new Set([group.gid]);
    for (const directive of unit.hardening.SupplementaryGroups ?? []) {
      for (const supplementaryName of directive.split(/\s+/u)) {
        const supplementary = groupsByName.get(supplementaryName);
        if (!supplementary) fail(`live NSS supplementary group missing: ${supplementaryName}`);
        expectedGroups.add(supplementary.gid);
        protectedGids.add(supplementary.gid);
        addExpected(expectedExplicitMembersByGid, supplementary.gid, userName);
        addExpected(expectedAllMembersByGid, supplementary.gid, userName);
      }
    }
    if (
      canonicalJson([...new Set(user.supplementary_gids)].sort((left, right) => left - right)) !==
      canonicalJson([...expectedGroups].sort((left, right) => left - right))
    ) {
      fail(`live NSS unexpected supplementary group: ${unit.unit_name}`);
    }
    const expectedProcessIdentity = resolveExpectedUnitProcessIdentity(
      unit,
      evidence.nss,
      request.service_identities,
    );
    const actualUnit = evidence.units.find((entry) => entry.unit_name === unit.unit_name);
    validateProcessIdentityEvidence(
      actualUnit?.process_identity,
      lifecycleByUnit.get(unit.unit_name),
      expectedProcessIdentity,
      unit,
    );
  }
  for (const entry of [...request.runtime_paths, ...request.secret_files]) {
    if (Number.isSafeInteger(entry.gid) && entry.gid > 0) protectedGids.add(entry.gid);
  }
  for (const directory of request.tmpfiles_directories) {
    const group = groupsByName.get(directory.group_name);
    if (!group) fail(`live NSS tmpfiles group missing: ${directory.group_name}`);
    if (group.gid > 0) protectedGids.add(group.gid);
  }
  for (const gid of [...protectedGids].sort((left, right) => left - right)) {
    const group = evidence.nss.groups.find((entry) => entry.gid === gid);
    if (!group) fail(`live NSS protected GID is not enumerable: ${gid}`);
    const actualPrimaryUsers = evidence.nss.users
      .filter((user) => user.primary_gid === gid)
      .map((user) => user.name)
      .sort();
    const expectedPrimaryUsers = [...(expectedPrimaryUsersByGid.get(gid) ?? [])].sort();
    if (canonicalJson(actualPrimaryUsers) !== canonicalJson(expectedPrimaryUsers)) {
      fail(`live NSS protected primary-GID holder drift: ${group.name}`);
    }
    const expectedExplicitMembers = [...(expectedExplicitMembersByGid.get(gid) ?? [])].sort();
    if (canonicalJson(group.members) !== canonicalJson(expectedExplicitMembers)) {
      fail(`live NSS protected explicit group membership drift: ${group.name}`);
    }
    const actualAllMembers = evidence.nss.users
      .filter((user) => user.supplementary_gids.includes(gid))
      .map((user) => user.name)
      .sort();
    const expectedAllMembers = [...(expectedAllMembersByGid.get(gid) ?? [])].sort();
    if (canonicalJson(actualAllMembers) !== canonicalJson(expectedAllMembers)) {
      fail(`live NSS protected effective group membership drift: ${group.name}`);
    }
  }
  validateProtectedProcessClosure(
    evidence.protected_process_closure,
    request,
    evidence.nss,
    evidence.units,
    lifecycleByUnit,
  );
  const expectedAccessCheckCount = request.secret_files.length * request.service_identities.length;
  if (!Array.isArray(evidence.secret_access_checks) || evidence.secret_access_checks.length !== expectedAccessCheckCount) {
    fail("live secret positive/negative access probes are incomplete");
  }
  let accessIndex = 0;
  for (const secret of request.secret_files) {
    for (const identity of request.service_identities) {
      const unit = request.units.find((entry) => entry.unit_name === identity.unit_name);
      const expectedIdentity = resolveExpectedUnitProcessIdentity(
        unit,
        evidence.nss,
        request.service_identities,
      );
      const expectedReadable = identity.unit_name === secret.consumer_unit_name;
      const actual = evidence.secret_access_checks[accessIndex];
      exactKeys(
        actual,
        ["argv", "exit_status", "expected_readable", "stderr", "stdout", "target_path", "unit_name"],
        `live secret_access_checks[${accessIndex}]`,
      );
      if (
        actual.unit_name !== identity.unit_name ||
        actual.target_path !== secret.target_path ||
        actual.expected_readable !== expectedReadable ||
        actual.exit_status !== (expectedReadable ? 0 : 1) ||
        actual.stdout !== "" ||
        actual.stderr !== "" ||
        canonicalJson(actual.argv) !== canonicalJson(secretProbeArgv(expectedIdentity, secret.target_path))
      ) {
        fail(`live secret access isolation evidence failed: ${identity.unit_name} -> ${secret.target_path}`);
      }
      accessIndex += 1;
    }
  }
  return true;
}

function assertRootLinuxCollector(command) {
  if (process.platform !== "linux") fail(`${command} is Linux-only`);
  if (
    process.getuid?.() !== 0 ||
    process.getgid?.() !== 0 ||
    process.geteuid?.() !== 0 ||
    process.getegid?.() !== 0
  ) fail(`${command} requires real and effective root`);
  if (process.execPath !== "/usr/bin/node") {
    fail(`${command} requires the reviewed absolute /usr/bin/node runtime`);
  }
}

function sameHostGeneration(started, finished) {
  return (
    finished.boot_id === started.boot_id &&
    finished.core_pattern === started.core_pattern &&
    finished.machine_id_sha256 === started.machine_id_sha256 &&
    finished.collector_pid_namespace === started.collector_pid_namespace &&
    finished.pid1_pid_namespace === started.pid1_pid_namespace &&
    finished.pid1_name === started.pid1_name &&
    canonicalJson(finished.pid1_nspid) === canonicalJson(started.pid1_nspid)
  );
}

export function collectStoppedEdgeActivationEvidence({
  bundleRoot,
  approvedManifestSha256,
  approvedPlanSha256,
  expectedMachineIdSha256,
}) {
  assertRootLinuxCollector("collect-stopped-edge");
  validateDigest(approvedManifestSha256, "approved manifest SHA-256");
  validateDigest(approvedPlanSha256, "approved plan SHA-256");
  validateDigest(expectedMachineIdSha256, "expected machine-id SHA-256");
  const { request } = readPinnedBundle(bundleRoot, approvedManifestSha256, approvedPlanSha256);
  if (request.deployment_profile !== "edge-hetzner-v1") {
    fail("collect-stopped-edge only accepts the reviewed Hetzner public-edge profile");
  }
  const trustedCommands = [...REQUIRED_COMMANDS, process.execPath].sort().map(inspectTrustedCommand);
  const started = Math.floor(Date.now() / 1000);
  const hostStarted = readHostBinding();
  if (hostStarted.machine_id_sha256 !== expectedMachineIdSha256) {
    fail("collector is running on an unapproved host");
  }
  const challengeHex = randomBytes(32).toString("hex");
  const nss = collectNss();
  const accountPolicyStarted = collectLockedServiceAccountPolicy(request, nss);
  const stoppedUnitStarted = collectStoppedUnitStates(request);
  const runtimeSocketAbsenceStarted = collectAbsentRuntimeSockets(request);
  const protectedProcessClosure = collectProtectedCredentialProcessClosureV1(
    protectedCredentialsForRequest(request, nss),
  );
  const runtimeSocketAbsenceFinished = collectAbsentRuntimeSockets(request);
  const stoppedUnitFinished = collectStoppedUnitStates(request);
  const accountPolicyFinished = collectLockedServiceAccountPolicy(request, nss);
  if (canonicalJson(accountPolicyStarted) !== canonicalJson(accountPolicyFinished)) {
    fail("service account login policy changed during stopped-edge collection");
  }
  confirmLocalFilesNssPolicyUnchanged(nss);
  const hostFinished = readHostBinding();
  const finished = Math.floor(Date.now() / 1000);
  if (!sameHostGeneration(hostStarted, hostFinished)) {
    fail("host or boot identity changed during stopped-edge collection");
  }
  const evidence = {
    account_policy: accountPolicyFinished,
    approved_plan_sha256: approvedPlanSha256,
    challenge_hex: challengeHex,
    collected_finished_unix_seconds: finished,
    collected_started_unix_seconds: started,
    collector: RUNTIME_COLLECTOR,
    collector_process: { egid: process.getegid(), euid: process.geteuid(), pid: process.pid },
    evidence_kind: STOPPED_EDGE_EVIDENCE_KIND,
    host: {
      boot_id: hostStarted.boot_id,
      collector_pid_namespace: hostStarted.collector_pid_namespace,
      core_pattern: hostStarted.core_pattern,
      kernel_release: hostStarted.kernel_release,
      machine_id_sha256: hostStarted.machine_id_sha256,
      pid1_name: hostStarted.pid1_name,
      pid1_nspid: hostStarted.pid1_nspid,
      pid1_pid_namespace: hostStarted.pid1_pid_namespace,
      systemd_version: hostStarted.systemd_version,
      uptime_finished_milliseconds: hostFinished.uptime_milliseconds,
      uptime_started_milliseconds: hostStarted.uptime_milliseconds,
    },
    manifest_sha256: approvedManifestSha256,
    nss,
    protected_process_closure: protectedProcessClosure,
    runtime_socket_absence_passes: [
      runtimeSocketAbsenceStarted,
      runtimeSocketAbsenceFinished,
    ],
    schema_version: STOPPED_EDGE_SCHEMA_VERSION,
    stopped_unit_passes: [stoppedUnitStarted, stoppedUnitFinished],
    trusted_commands: trustedCommands,
  };
  validateStoppedEdgeActivationEvidence({
    evidence,
    expectedBootId: hostStarted.boot_id,
    expectedMachineIdSha256,
    maxAgeSeconds: 0,
    nowUnixSeconds: finished,
    request,
  });
  return evidence;
}

export function collectLiveRuntimeEvidence({ bundleRoot, approvedManifestSha256, approvedPlanSha256, expectedMachineIdSha256 }) {
  assertRootLinuxCollector("collect-live");
  validateDigest(approvedManifestSha256, "approved manifest SHA-256");
  validateDigest(approvedPlanSha256, "approved plan SHA-256");
  validateDigest(expectedMachineIdSha256, "expected machine-id SHA-256");
  const { request } = readPinnedBundle(bundleRoot, approvedManifestSha256, approvedPlanSha256);
  const trustedCommands = [...REQUIRED_COMMANDS, process.execPath].sort().map(inspectTrustedCommand);
  const started = Math.floor(Date.now() / 1000);
  const hostStarted = readHostBinding();
  if (hostStarted.machine_id_sha256 !== expectedMachineIdSha256) fail("collector is running on an unapproved host");
  const challengeHex = randomBytes(32).toString("hex");
  const nss = collectNss();
  const installedFiles = request.installed_files.map(collectInstalledFile);
  const runtimeDirectories = request.tmpfiles_directories.map((entry) => collectTmpfilesDirectory(entry, nss));
  const runtimePaths = request.runtime_paths.map(collectRuntimePath);
  const secretParentDirectories = secretParentPaths(request.secret_files).map(collectSecretParentDirectory);
  const secretAccessChecks = collectSecretAccessChecks(request, nss);
  for (const secret of request.secret_files) {
    const before = installedFiles.find((entry) => entry.target_path === secret.target_path);
    const expected = request.installed_files.find((entry) => entry.target_path === secret.target_path);
    if (!before || !expected) fail(`secret is absent from installed-file closure: ${secret.target_path}`);
    const after = collectInstalledFile(expected);
    if (canonicalJson(before) !== canonicalJson(after)) {
      fail(`secret metadata or content changed around access probes: ${secret.target_path}`);
    }
  }
  const secretParentConfirmation = secretParentPaths(request.secret_files).map(collectSecretParentDirectory);
  if (canonicalJson(secretParentDirectories) !== canonicalJson(secretParentConfirmation)) {
    fail("secret parent directory metadata changed around access probes");
  }
  const units = request.units.map((unit) =>
    collectUnit(unit, nss, request.service_identities, hostStarted.uptime_milliseconds),
  );
  const runtimePathConfirmation = request.runtime_paths.map(collectRuntimePath);
  if (canonicalJson(runtimePaths) !== canonicalJson(runtimePathConfirmation)) {
    fail("runtime path metadata changed while live unit evidence was collected");
  }
  const analyze = runAbsolute(request.systemd_analyze_argv[0], request.systemd_analyze_argv.slice(1), { allowOutput: false, timeout: 30_000 });
  if (analyze.exit_status !== 0) fail("systemd-analyze verify failed");
  const protectedProcessClosure = collectProtectedCredentialProcessClosureV1(
    protectedCredentialsForRequest(request, nss),
  );
  const finalRuntimeDirectories = request.tmpfiles_directories.map((entry) =>
    collectTmpfilesDirectory(entry, nss),
  );
  if (canonicalJson(runtimeDirectories) !== canonicalJson(finalRuntimeDirectories)) {
    fail("runtime directory metadata changed during protected process collection");
  }
  const finalRuntimePaths = request.runtime_paths.map(collectRuntimePath);
  if (canonicalJson(runtimePaths) !== canonicalJson(finalRuntimePaths)) {
    fail("runtime path metadata changed during protected process collection");
  }
  for (let index = 0; index < request.units.length; index += 1) {
    units[index].generation_confirmations.push(
      confirmUnitGeneration(request.units[index], units[index].properties),
    );
  }
  confirmLocalFilesNssPolicyUnchanged(nss);
  const hostFinished = readHostBinding();
  const finished = Math.floor(Date.now() / 1000);
  if (!sameHostGeneration(hostStarted, hostFinished)) {
    fail("host or boot identity changed during live collection");
  }
  const evidence = {
    approved_plan_sha256: approvedPlanSha256,
    challenge_hex: challengeHex,
    collected_finished_unix_seconds: finished,
    collected_started_unix_seconds: started,
    collector: RUNTIME_COLLECTOR,
    collector_process: { egid: process.getegid(), euid: process.geteuid(), pid: process.pid },
    evidence_kind: LIVE_EVIDENCE_KIND,
    host: {
      boot_id: hostStarted.boot_id,
      collector_pid_namespace: hostStarted.collector_pid_namespace,
      core_pattern: hostStarted.core_pattern,
      kernel_release: hostStarted.kernel_release,
      machine_id_sha256: hostStarted.machine_id_sha256,
      pid1_name: hostStarted.pid1_name,
      pid1_nspid: hostStarted.pid1_nspid,
      pid1_pid_namespace: hostStarted.pid1_pid_namespace,
      systemd_version: hostStarted.systemd_version,
      uptime_finished_milliseconds: hostFinished.uptime_milliseconds,
      uptime_started_milliseconds: hostStarted.uptime_milliseconds,
    },
    installed_files: installedFiles,
    manifest_sha256: approvedManifestSha256,
    nss,
    protected_process_closure: protectedProcessClosure,
    runtime_directories: runtimeDirectories,
    runtime_paths: runtimePaths,
    schema_version: LIVE_SCHEMA_VERSION,
    secret_access_checks: secretAccessChecks,
    secret_parent_directories: secretParentDirectories,
    systemd_analyze_verify: analyze,
    trusted_commands: trustedCommands,
    units,
  };
  validateLiveRuntimeEvidence({
    evidence,
    expectedBootId: hostStarted.boot_id,
    expectedMachineIdSha256,
    maxAgeSeconds: 0,
    nowUnixSeconds: finished,
    request,
  });
  return evidence;
}

function parseCli(argv) {
  const command = argv[0];
  if (![
    "collect-live",
    "collect-stopped-edge",
    "verify-offline",
    "verify-stopped-edge-offline",
  ].includes(command)) {
    fail("usage: payment-v1-linux-runtime-evidence.mjs <collect-live|collect-stopped-edge|verify-offline|verify-stopped-edge-offline> --bundle ABS --approved-manifest-sha256 HEX --approved-plan-sha256 HEX --expected-machine-id-sha256 HEX --output ABS | --evidence ABS --trusted-evidence-sha256 HEX --expected-boot-id UUID");
  }
  const values = Object.create(null);
  const allowed = new Set([
    "--bundle",
    "--approved-manifest-sha256",
    "--approved-plan-sha256",
    "--expected-machine-id-sha256",
    "--expected-boot-id",
    "--evidence",
    "--trusted-evidence-sha256",
    "--output",
  ]);
  for (let index = 1; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!allowed.has(flag) || value === undefined || values[flag] !== undefined) {
      fail(`invalid, repeated, or missing CLI option: ${flag ?? "<missing>"}`);
    }
    values[flag] = value;
  }
  for (const required of ["--bundle", "--approved-manifest-sha256", "--approved-plan-sha256", "--expected-machine-id-sha256"]) {
    if (values[required] === undefined) fail(`missing required CLI option ${required}`);
  }
  validateAbsolutePath(values["--bundle"], "CLI bundle path");
  for (const flag of ["--approved-manifest-sha256", "--approved-plan-sha256", "--expected-machine-id-sha256"]) {
    validateDigest(values[flag], flag);
  }
  if (command.startsWith("collect-")) {
    if (values["--output"] === undefined) fail(`${command} requires --output`);
    validateAbsolutePath(values["--output"], "CLI output path");
    for (const forbidden of ["--evidence", "--trusted-evidence-sha256", "--expected-boot-id"]) {
      if (values[forbidden] !== undefined) fail(`${command} forbids caller evidence option ${forbidden}`);
    }
  } else {
    for (const required of ["--evidence", "--trusted-evidence-sha256", "--expected-boot-id"]) {
      if (values[required] === undefined) fail(`${command} requires ${required}`);
    }
    if (values["--output"] !== undefined) fail(`${command} forbids --output`);
    validateAbsolutePath(values["--evidence"], "CLI evidence path");
    validateDigest(values["--trusted-evidence-sha256"], "trusted evidence SHA-256");
    validateUuid(values["--expected-boot-id"], "expected boot id");
  }
  return { command, values };
}

function runCli(argv) {
  const { command, values } = parseCli(argv);
  const common = {
    approvedManifestSha256: values["--approved-manifest-sha256"],
    approvedPlanSha256: values["--approved-plan-sha256"],
    bundleRoot: values["--bundle"],
    expectedMachineIdSha256: values["--expected-machine-id-sha256"],
  };
  if (command.startsWith("collect-")) {
    if (existsSync(values["--output"])) fail(`${command} refuses to overwrite evidence output`);
    if (realpathSync(dirname(values["--output"])) !== dirname(values["--output"])) {
      fail(`${command} output parent must be canonical`);
    }
    const evidence = command === "collect-live"
      ? collectLiveRuntimeEvidence(common)
      : collectStoppedEdgeActivationEvidence(common);
    writeFileSync(values["--output"], canonicalJson(evidence), { flag: "wx", mode: 0o600 });
    const label = command === "collect-live" ? "live" : "stopped-edge";
    process.stdout.write(`payment-v1-linux-runtime-evidence: ${label} PASS challenge=${evidence.challenge_hex}\n`);
    return;
  }
  const { request } = readPinnedBundle(common.bundleRoot, common.approvedManifestSha256, common.approvedPlanSha256);
  const evidenceBytes = readOneLinkRegular(values["--evidence"], "offline live evidence");
  if (hashBytes(evidenceBytes) !== values["--trusted-evidence-sha256"]) {
    fail("offline evidence does not match the out-of-band trusted SHA-256 pin");
  }
  const evidence = strictJsonBytes(evidenceBytes, "offline live evidence");
  const validate = command === "verify-offline"
    ? validateLiveRuntimeEvidence
    : validateStoppedEdgeActivationEvidence;
  validate({
    evidence,
    expectedBootId: values["--expected-boot-id"],
    expectedMachineIdSha256: common.expectedMachineIdSha256,
    maxAgeSeconds: Number.MAX_SAFE_INTEGER,
    nowUnixSeconds: evidence.collected_finished_unix_seconds,
    request,
  });
  const label = command === "verify-offline" ? "live" : "stopped-edge";
  process.stdout.write(`payment-v1-linux-runtime-evidence: offline trusted-pin ${label} structure PASS\n`);
}

const isMain = process.argv[1] !== undefined && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (isMain) {
  try {
    runCli(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`payment-v1-linux-runtime-evidence: FAIL: ${error.message}\n`);
    process.exitCode = 1;
  }
}
