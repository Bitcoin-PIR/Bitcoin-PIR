#!/usr/bin/env node

// Production runtime evidence is collected and checked in one root-owned Linux
// process.  Offline JSON is only meaningful when its complete SHA-256 digest is
// approved out of band; this program never accepts caller-authored JSON in the
// collect-live path.

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
  readSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import {
  RUNTIME_COLLECTOR,
  RUNTIME_SYSTEMCTL_SHOW_PROPERTIES,
  canonicalJson,
  parseStrictJson,
  runtimeRequestFromManifest,
} from "./payment-v1-rendered-artifact-gate.mjs";

export const LIVE_EVIDENCE_KIND = "bitcoinpir-payment-v1-linux-root-live-v1";
const LIVE_SCHEMA_VERSION = 1;
const MAX_JSON_BYTES = 8 * 1024 * 1024;
const MAX_COMMAND_OUTPUT_BYTES = 2 * 1024 * 1024;
const MAX_COLLECTION_SECONDS = 120;
const MAX_PROC_STAT_BYTES = 16 * 1024;
const MAX_PROC_STATUS_BYTES = 256 * 1024;
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

function parseGetentLine(record, label) {
  if (record.exit_status !== 0 || record.stderr !== "") fail(`${label} NSS lookup failed`);
  const line = record.stdout.trim();
  if (line === "" || line.includes("\n")) fail(`${label} NSS lookup was ambiguous`);
  return line.split(":");
}

function collectNss(request) {
  const userNames = new Set();
  const groupNames = new Set();
  for (const unit of request.units) {
    for (const value of unit.hardening.User ?? []) userNames.add(value);
    for (const value of unit.hardening.Group ?? []) groupNames.add(value);
    for (const directive of unit.hardening.SupplementaryGroups ?? []) {
      for (const value of directive.split(/\s+/u)) groupNames.add(value);
    }
  }
  for (const directory of request.tmpfiles_directories) {
    userNames.add(directory.user_name);
    groupNames.add(directory.group_name);
  }
  const users = [...userNames].sort().map((name) => {
    const fields = parseGetentLine(runAbsolute("/usr/bin/getent", ["passwd", name]), `user ${name}`);
    if (fields.length !== 7 || fields[0] !== name) fail(`user ${name} has malformed NSS data`);
    const groupsRecord = runAbsolute("/usr/bin/id", ["-G", name]);
    if (groupsRecord.exit_status !== 0 || groupsRecord.stderr !== "") fail(`id -G failed for ${name}`);
    const supplementaryGids = groupsRecord.stdout.trim().split(/\s+/u).map(Number);
    if (supplementaryGids.some((gid) => !Number.isSafeInteger(gid) || gid < 1)) {
      fail(`user ${name} has malformed group membership`);
    }
    return {
      name,
      primary_gid: Number(fields[3]),
      supplementary_gids: [...new Set(supplementaryGids)].sort((left, right) => left - right),
      uid: Number(fields[2]),
    };
  });
  const groups = [...groupNames].sort().map((name) => {
    const fields = parseGetentLine(runAbsolute("/usr/bin/getent", ["group", name]), `group ${name}`);
    if (fields.length !== 4 || fields[0] !== name) fail(`group ${name} has malformed NSS data`);
    return {
      gid: Number(fields[2]),
      members: fields[3] === "" ? [] : fields[3].split(",").sort(),
      name,
    };
  });
  return { groups, users };
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

function parseProcStat(bytes, pid) {
  const label = `/proc/${pid}/stat`;
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

function parseProcStatus(bytes, pid) {
  const label = `/proc/${pid}/status`;
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
  const groupsText = field("Groups");
  const groups = groupsText === "" ? [] : groupsText.split(/\s+/u).map((token) => {
    if (!/^(?:0|[1-9][0-9]*)$/u.test(token)) fail(`${label} has malformed Groups: values`);
    const gid = Number(token);
    if (!Number.isSafeInteger(gid) || gid < 0) fail(`${label} has out-of-range Groups: values`);
    return gid;
  });
  if (new Set(groups).size !== groups.length) fail(`${label} repeats a Groups: value`);
  return {
    gid: parseIds("Gid", 4),
    groups: [...groups].sort((left, right) => left - right),
    uid: parseIds("Uid", 4),
  };
}

function inspectProcDirectory(pid) {
  const path = `/proc/${pid}`;
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || realpathSync(path) !== path) {
    fail(`process directory is not a canonical procfs directory: ${path}`);
  }
  return { dev: stat.dev.toString(), ino: stat.ino.toString() };
}

function collectProcIdentitySnapshot(pid) {
  const directoryBefore = inspectProcDirectory(pid);
  const statBefore = parseProcStat(
    readBoundedProcFile(`/proc/${pid}/stat`, `process ${pid} stat`, MAX_PROC_STAT_BYTES),
    pid,
  );
  const identity = parseProcStatus(
    readBoundedProcFile(`/proc/${pid}/status`, `process ${pid} status`, MAX_PROC_STATUS_BYTES),
    pid,
  );
  const statAfter = parseProcStat(
    readBoundedProcFile(`/proc/${pid}/stat`, `process ${pid} stat confirmation`, MAX_PROC_STAT_BYTES),
    pid,
  );
  const directoryAfter = inspectProcDirectory(pid);
  if (
    canonicalJson(directoryBefore) !== canonicalJson(directoryAfter) ||
    statBefore.startTimeTicks !== statAfter.startTimeTicks
  ) {
    fail(`process ${pid} restarted while its procfs identity was collected`);
  }
  return {
    ...identity,
    procDirectoryDev: directoryAfter.dev,
    procDirectoryIno: directoryAfter.ino,
    processState: statAfter.processState,
    startTimeTicks: statAfter.startTimeTicks,
  };
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

function confirmUnitGeneration(unit, properties) {
  const confirmation = {
    active_enter_timestamp_monotonic: collectSystemctlValue(unit.unit_name, "ActiveEnterTimestampMonotonic"),
    active_state: collectSystemctlValue(unit.unit_name, "ActiveState"),
    invocation_id: collectSystemctlValue(unit.unit_name, "InvocationID"),
    main_pid: collectSystemctlValue(unit.unit_name, "MainPID"),
  };
  if (
    confirmation.active_state !== properties.ActiveState ||
    confirmation.main_pid !== properties.MainPID ||
    confirmation.invocation_id !== properties.InvocationID ||
    confirmation.active_enter_timestamp_monotonic !== properties.ActiveEnterTimestampMonotonic
  ) {
    fail(`systemd unit generation changed during live collection: ${unit.unit_name}`);
  }
  return confirmation;
}

function assertSnapshotIdentity(snapshot, expected, unitName) {
  if (
    canonicalJson(snapshot.uid) !== canonicalJson([expected.uid, expected.uid, expected.uid, expected.uid]) ||
    canonicalJson(snapshot.gid) !== canonicalJson([expected.gid, expected.gid, expected.gid, expected.gid]) ||
    canonicalJson(snapshot.groups) !== canonicalJson(expected.groups)
  ) {
    fail(`running process identity differs from the reviewed unit identity: ${unitName}`);
  }
}

function collectLongRunningProcessIdentity(unit, properties, nss, serviceIdentities) {
  const pid = parseUnsignedDecimal(properties.MainPID, `${unit.unit_name}.MainPID`, { allowZero: false });
  const expected = resolveExpectedUnitProcessIdentity(unit, nss, serviceIdentities);
  const before = collectProcIdentitySnapshot(pid);
  assertSnapshotIdentity(before, expected, unit.unit_name);
  const firstConfirmation = confirmUnitGeneration(unit, properties);
  const middle = collectProcIdentitySnapshot(pid);
  assertSnapshotIdentity(middle, expected, unit.unit_name);
  const secondConfirmation = confirmUnitGeneration(unit, properties);
  const after = collectProcIdentitySnapshot(pid);
  assertSnapshotIdentity(after, expected, unit.unit_name);
  for (const snapshot of [middle, after]) {
    if (
      snapshot.procDirectoryDev !== before.procDirectoryDev ||
      snapshot.procDirectoryIno !== before.procDirectoryIno ||
      snapshot.startTimeTicks !== before.startTimeTicks ||
      canonicalJson(snapshot.uid) !== canonicalJson(before.uid) ||
      canonicalJson(snapshot.gid) !== canonicalJson(before.gid) ||
      canonicalJson(snapshot.groups) !== canonicalJson(before.groups)
    ) {
      fail(`running process restarted or changed credentials during live collection: ${unit.unit_name}`);
    }
  }
  return {
    confirmations: [firstConfirmation, secondConfirmation],
    evidence: {
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
  return {
    boot_id: bootId,
    core_pattern: corePattern,
    kernel_release: kernel.stdout.trim(),
    machine_id_sha256: hashBytes(machineId),
    systemd_version: systemd.stdout.split("\n", 1)[0],
    uptime_milliseconds: uptimeMilliseconds,
  };
}

function validateGenerationConfirmations(confirmations, properties, unitName) {
  if (!Array.isArray(confirmations) || confirmations.length !== 2) {
    fail(`unit generation confirmations are incomplete: ${unitName}`);
  }
  for (const [index, confirmation] of confirmations.entries()) {
    exactKeys(
      confirmation,
      ["active_enter_timestamp_monotonic", "active_state", "invocation_id", "main_pid"],
      `${unitName} generation confirmation[${index}]`,
    );
    if (
      confirmation.active_enter_timestamp_monotonic !== properties.ActiveEnterTimestampMonotonic ||
      confirmation.active_state !== properties.ActiveState ||
      confirmation.invocation_id !== properties.InvocationID ||
      confirmation.main_pid !== properties.MainPID
    ) {
      fail(`unit MainPID or InvocationID changed during collection: ${unitName}`);
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

function validateProcessIdentityEvidence(processIdentity, lifecycle, expectedIdentity, unitName) {
  if (lifecycle.kind === "successful-oneshot") {
    if (processIdentity !== null) fail(`reviewed oneshot must not claim procfs process identity: ${unitName}`);
    return;
  }
  exactKeys(
    processIdentity,
    [
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
    canonicalJson(processIdentity.groups_before) !== canonicalJson(processIdentity.groups_after)
  ) {
    fail(`procfs process credentials changed during collection: ${unitName}`);
  }
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
    ["boot_id", "core_pattern", "kernel_release", "machine_id_sha256", "systemd_version", "uptime_finished_milliseconds", "uptime_started_milliseconds"],
    "live evidence host",
  );
  validateUuid(evidence.host.boot_id, "live evidence boot id");
  if (evidence.host.machine_id_sha256 !== expectedMachineIdSha256) fail("live evidence came from another host");
  if (expectedBootId !== undefined && evidence.host.boot_id !== expectedBootId) fail("live evidence came from another boot");
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
      actual.file_type !== "directory"
    ) fail(`live tmpfiles directory drift: ${expected.target_path}`);
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
  exactKeys(evidence.nss, ["groups", "users"], "live NSS evidence");
  if (!Array.isArray(evidence.nss.groups) || !Array.isArray(evidence.nss.users)) {
    fail("live NSS evidence arrays are missing");
  }
  const usersByName = new Map(evidence.nss.users.map((user) => [user.name, user]));
  const groupsByName = new Map(evidence.nss.groups.map((group) => [group.name, group]));
  if (usersByName.size !== evidence.nss.users.length || groupsByName.size !== evidence.nss.groups.length) {
    fail("live NSS evidence repeats identities");
  }
  if (new Set(evidence.nss.users.map((user) => user.uid)).size !== evidence.nss.users.length) {
    fail("live NSS evidence aliases service UIDs");
  }
  if (new Set(evidence.nss.groups.map((group) => group.gid)).size !== evidence.nss.groups.length) {
    fail("live NSS evidence aliases service GIDs");
  }
  for (const group of evidence.nss.groups) {
    exactKeys(group, ["gid", "members", "name"], `live NSS group ${group.name ?? "<unknown>"}`);
    if (!Number.isSafeInteger(group.gid) || group.gid < 1 || !Array.isArray(group.members)) {
      fail("live NSS group data is malformed");
    }
  }
  for (const user of evidence.nss.users) {
    exactKeys(user, ["name", "primary_gid", "supplementary_gids", "uid"], `live NSS user ${user.name ?? "<unknown>"}`);
    if (
      !Number.isSafeInteger(user.uid) || user.uid < 1 ||
      !Number.isSafeInteger(user.primary_gid) || user.primary_gid < 1 ||
      !Array.isArray(user.supplementary_gids)
    ) fail("live NSS user data is malformed");
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
    const expectedGroups = new Set([group.gid]);
    for (const directive of unit.hardening.SupplementaryGroups ?? []) {
      for (const supplementaryName of directive.split(/\s+/u)) {
        const supplementary = groupsByName.get(supplementaryName);
        if (!supplementary) fail(`live NSS supplementary group missing: ${supplementaryName}`);
        expectedGroups.add(supplementary.gid);
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
      unit.unit_name,
    );
  }
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

export function collectLiveRuntimeEvidence({ bundleRoot, approvedManifestSha256, approvedPlanSha256, expectedMachineIdSha256 }) {
  if (process.platform !== "linux") fail("collect-live is Linux-only");
  if (
    process.getuid?.() !== 0 ||
    process.getgid?.() !== 0 ||
    process.geteuid?.() !== 0 ||
    process.getegid?.() !== 0
  ) fail("collect-live requires real and effective root");
  if (process.execPath !== "/usr/bin/node") fail("collect-live requires the reviewed absolute /usr/bin/node runtime");
  validateDigest(approvedManifestSha256, "approved manifest SHA-256");
  validateDigest(approvedPlanSha256, "approved plan SHA-256");
  validateDigest(expectedMachineIdSha256, "expected machine-id SHA-256");
  const { request } = readPinnedBundle(bundleRoot, approvedManifestSha256, approvedPlanSha256);
  const trustedCommands = [...REQUIRED_COMMANDS, process.execPath].sort().map(inspectTrustedCommand);
  const started = Math.floor(Date.now() / 1000);
  const hostStarted = readHostBinding();
  if (hostStarted.machine_id_sha256 !== expectedMachineIdSha256) fail("collector is running on an unapproved host");
  const challengeHex = randomBytes(32).toString("hex");
  const nss = collectNss(request);
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
  const hostFinished = readHostBinding();
  const finished = Math.floor(Date.now() / 1000);
  if (
    hostFinished.boot_id !== hostStarted.boot_id ||
    hostFinished.core_pattern !== hostStarted.core_pattern ||
    hostFinished.machine_id_sha256 !== hostStarted.machine_id_sha256
  ) {
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
      core_pattern: hostStarted.core_pattern,
      kernel_release: hostStarted.kernel_release,
      machine_id_sha256: hostStarted.machine_id_sha256,
      systemd_version: hostStarted.systemd_version,
      uptime_finished_milliseconds: hostFinished.uptime_milliseconds,
      uptime_started_milliseconds: hostStarted.uptime_milliseconds,
    },
    installed_files: installedFiles,
    manifest_sha256: approvedManifestSha256,
    nss,
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
  if (!["collect-live", "verify-offline"].includes(command)) {
    fail("usage: payment-v1-linux-runtime-evidence.mjs <collect-live|verify-offline> --bundle ABS --approved-manifest-sha256 HEX --approved-plan-sha256 HEX --expected-machine-id-sha256 HEX --output ABS | --evidence ABS --trusted-evidence-sha256 HEX --expected-boot-id UUID");
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
  if (command === "collect-live") {
    if (values["--output"] === undefined) fail("collect-live requires --output");
    validateAbsolutePath(values["--output"], "CLI output path");
    for (const forbidden of ["--evidence", "--trusted-evidence-sha256", "--expected-boot-id"]) {
      if (values[forbidden] !== undefined) fail(`collect-live forbids caller evidence option ${forbidden}`);
    }
  } else {
    for (const required of ["--evidence", "--trusted-evidence-sha256", "--expected-boot-id"]) {
      if (values[required] === undefined) fail(`verify-offline requires ${required}`);
    }
    if (values["--output"] !== undefined) fail("verify-offline forbids --output");
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
  if (command === "collect-live") {
    if (existsSync(values["--output"])) fail("collect-live refuses to overwrite evidence output");
    if (realpathSync(dirname(values["--output"])) !== dirname(values["--output"])) {
      fail("collect-live output parent must be canonical");
    }
    const evidence = collectLiveRuntimeEvidence(common);
    writeFileSync(values["--output"], canonicalJson(evidence), { flag: "wx", mode: 0o600 });
    process.stdout.write(`payment-v1-linux-runtime-evidence: live PASS challenge=${evidence.challenge_hex}\n`);
    return;
  }
  const { request } = readPinnedBundle(common.bundleRoot, common.approvedManifestSha256, common.approvedPlanSha256);
  const evidenceBytes = readOneLinkRegular(values["--evidence"], "offline live evidence");
  if (hashBytes(evidenceBytes) !== values["--trusted-evidence-sha256"]) {
    fail("offline evidence does not match the out-of-band trusted SHA-256 pin");
  }
  const evidence = strictJsonBytes(evidenceBytes, "offline live evidence");
  validateLiveRuntimeEvidence({
    evidence,
    expectedBootId: values["--expected-boot-id"],
    expectedMachineIdSha256: common.expectedMachineIdSha256,
    maxAgeSeconds: Number.MAX_SAFE_INTEGER,
    nowUnixSeconds: evidence.collected_finished_unix_seconds,
    request,
  });
  process.stdout.write("payment-v1-linux-runtime-evidence: offline trusted-pin structure PASS\n");
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
