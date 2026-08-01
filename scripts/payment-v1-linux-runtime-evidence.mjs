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
  RUNTIME_BUSCTL_MANAGER_PROPERTIES,
  RUNTIME_BUSCTL_SERVICE_PROPERTIES,
  RUNTIME_BUSCTL_UNIT_PROPERTIES,
  RUNTIME_COLLECTOR,
  RUNTIME_SYSTEMCTL_SHOW_PROPERTIES,
  REVIEWED_SYSTEMD_MANAGER_VERSION,
  REVIEWED_SYSTEMD_VERSION,
  canonicalJson,
  computeDirectoryPublishArgvSha256V1,
  isResolvedDirectoryRelayRuntimeRequest,
  parseStrictJson,
  runtimeRequestFromManifest,
  validateServiceIdentityId,
} from "./payment-v1-rendered-artifact-gate.mjs";
import {
  PUBLISHER_FIREWALL_OUTPUT_KEYS,
  validatePublisherFirewallOutputs,
} from "./payment-v1-publisher-netns-gate.mjs";

export const LIVE_EVIDENCE_KIND = "bitcoinpir-payment-v1-linux-root-live-v9";
export const STOPPED_EDGE_EVIDENCE_KIND =
  "bitcoinpir-payment-v1-linux-root-stopped-edge-v5";
export const STOPPED_RELAY_EVIDENCE_KIND =
  "bitcoinpir-payment-v1-linux-root-stopped-directory-relay-v4";
export const NSS_ENUMERATION_KIND = "getent-passwd-group-plus-id-groups-v2";
export const NSS_BACKEND_PROFILE =
  "local-files-authoritative-reviewed-systemd-fallback-v2";
const LIVE_SCHEMA_VERSION = 9;
const STOPPED_EDGE_SCHEMA_VERSION = 5;
const STOPPED_RELAY_SCHEMA_VERSION = 4;
const MAX_JSON_BYTES = 8 * 1024 * 1024;
const MAX_COMMAND_OUTPUT_BYTES = 2 * 1024 * 1024;
const MAX_COMMAND_BYTES = 256 * 1024 * 1024;
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
const UINT64_MAX = (1n << 64n) - 1n;
const UINT64_MAX_DECIMAL = UINT64_MAX.toString(10);
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
const REVIEWED_NSS_SOURCE_PROFILES = Object.freeze([
  Object.freeze({
    group: Object.freeze(["files"]),
    initgroups: "inherits-group",
    passwd: Object.freeze(["files"]),
  }),
  Object.freeze({
    group: Object.freeze(["files", "systemd"]),
    initgroups: "inherits-group",
    passwd: Object.freeze(["files", "systemd"]),
  }),
]);
const REQUIRED_COMMANDS = Object.freeze([
  "/usr/bin/busctl",
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
  "/usr/bin/unlink",
  "/usr/bin/uname",
  "/usr/sbin/getcap",
]);
const PUBLISHER_NETWORK_COMMANDS = Object.freeze([
  "/usr/bin/python3.12",
  "/usr/sbin/nft",
  "/usr/sbin/ufw",
]);
const ALLOWED_COMMANDS = Object.freeze([
  ...new Set([...REQUIRED_COMMANDS, ...PUBLISHER_NETWORK_COMMANDS]),
]);

function requiredCommandsForRequest(request) {
  return request?.publisher_network === undefined
    ? [...REQUIRED_COMMANDS]
    : [...REQUIRED_COMMANDS, ...PUBLISHER_NETWORK_COMMANDS];
}

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

function assertReviewedNssSources(sources, label = "NSS sources") {
  exactKeys(sources, ["group", "initgroups", "passwd"], label);
  const encoded = canonicalJson(sources);
  if (
    !REVIEWED_NSS_SOURCE_PROFILES.some(
      (profile) => canonicalJson(profile) === encoded,
    )
  ) {
    fail(
      `${label} must be exactly files-only or files-then-systemd for both passwd and group with inherited initgroups`,
    );
  }
  return sources;
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

export function readOneLinkRegular(path, label, maxBytes = MAX_JSON_BYTES) {
  return readOneLinkRegularBoundToDescriptor(path, label, maxBytes).bytes;
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

let activeTrustedCommandPins;

function inspectCommandPin(path, { requireRootOwner = true } = {}) {
  validateAbsolutePath(path, "runtime command path");
  const observed = readOneLinkRegularBoundToDescriptor(
    path,
    "runtime command",
    MAX_COMMAND_BYTES,
  );
  const fingerprint = observed.fingerprint;
  if (
    (requireRootOwner && fingerprint.uid !== 0) ||
    fingerprint.nlink !== 1 ||
    (Number.parseInt(fingerprint.mode, 8) & 0o022) !== 0 ||
    (Number.parseInt(fingerprint.mode, 8) & 0o111) === 0
  ) {
    fail(`runtime helper is not an approved-owner, one-link, non-writable executable: ${path}`);
  }
  return {
    ctime_ns: fingerprint.ctime_ns,
    dev: fingerprint.dev,
    gid: fingerprint.gid,
    ino: fingerprint.ino,
    mode: fingerprint.mode,
    mtime_ns: fingerprint.mtime_ns,
    nlink: fingerprint.nlink,
    path,
    sha256: hashBytes(observed.bytes),
    size: fingerprint.size,
    uid: fingerprint.uid,
  };
}

function assertCommandPinUnchanged(expected, observed, label) {
  if (canonicalJson(observed) !== canonicalJson(expected)) {
    fail(`${label} pathname, inode, metadata, or SHA-256 changed: ${expected.path}`);
  }
}

function beginTrustedCommandSession(paths) {
  if (activeTrustedCommandPins !== undefined) {
    fail("runtime command-pin session is already active");
  }
  const pins = paths.map(inspectTrustedCommand);
  activeTrustedCommandPins = new Map(pins.map((pin) => [pin.path, pin]));
  return pins;
}

function finishTrustedCommandSession(pins) {
  if (
    activeTrustedCommandPins === undefined ||
    !Array.isArray(pins) ||
    pins.length !== activeTrustedCommandPins.size
  ) {
    fail("runtime command-pin session is incomplete at final sealing");
  }
  for (const pin of pins) {
    const active = activeTrustedCommandPins.get(pin.path);
    if (active === undefined) fail(`runtime command pin disappeared: ${pin.path}`);
    assertCommandPinUnchanged(pin, active, "runtime command session");
    assertCommandPinUnchanged(
      pin,
      inspectTrustedCommand(pin.path),
      "final runtime command pin",
    );
  }
  activeTrustedCommandPins = undefined;
}

function openPinnedCommandDescriptor(pin, label) {
  const command = pin.path;
  const before = lstatSync(command, { bigint: true });
  assertOneLinkCanonicalRegular(command, before, label, MAX_COMMAND_BYTES);
  const fd = openSync(
    command,
    constants.O_RDONLY | constants.O_NOFOLLOW | (constants.O_CLOEXEC ?? 0),
  );
  try {
    const opened = fstatSync(fd, { bigint: true });
    assertSameInstalledFileSnapshot(before, opened, `${label} pathname and opened descriptor`, command);
    assertSamePreciseInstalledFileSnapshot(
      before,
      opened,
      `${label} pathname and opened descriptor`,
      command,
    );
    const bytes = readExactDescriptorBytes(fd, opened.size, label, command);
    const afterRead = fstatSync(fd, { bigint: true });
    assertSameInstalledFileSnapshot(opened, afterRead, `${label} descriptor read`, command);
    assertSamePreciseInstalledFileSnapshot(opened, afterRead, `${label} descriptor read`, command);
    const openedPin = {
      ctime_ns: statNanoseconds(afterRead, "ctime"),
      dev: afterRead.dev.toString(),
      gid: statInteger(afterRead.gid, `${label} GID`),
      ino: afterRead.ino.toString(),
      mode: statMode(afterRead),
      mtime_ns: statNanoseconds(afterRead, "mtime"),
      nlink: statInteger(afterRead.nlink, `${label} link count`),
      path: command,
      sha256: hashBytes(bytes),
      size: statInteger(afterRead.size, `${label} size`),
      uid: statInteger(afterRead.uid, `${label} UID`),
    };
    assertCommandPinUnchanged(pin, openedPin, `${label} descriptor`);
    return { fd, label, pin, snapshot: afterRead };
  } catch (error) {
    closeSync(fd);
    throw error;
  }
}

function confirmPinnedCommandDescriptor(binding, stage) {
  const current = fstatSync(binding.fd, { bigint: true });
  const bytes = readExactDescriptorBytes(
    binding.fd,
    current.size,
    `${binding.label} ${stage}`,
    binding.pin.path,
  );
  if (hashBytes(bytes) !== binding.pin.sha256) {
    fail(`${binding.label} SHA-256 changed ${stage}: ${binding.pin.path}`);
  }
  assertSameInstalledFileSnapshot(
    binding.snapshot,
    current,
    `${binding.label} descriptor ${stage}`,
    binding.pin.path,
  );
  assertSamePreciseInstalledFileSnapshot(
    binding.snapshot,
    current,
    `${binding.label} descriptor ${stage}`,
    binding.pin.path,
  );
  return current;
}

function confirmPinnedCommandPath(binding, stage) {
  assertCommandPinUnchanged(
    binding.pin,
    inspectCommandPin(binding.pin.path, { requireRootOwner: binding.pin.uid === 0 }),
    `${binding.label} ${stage}`,
  );
}

function commandPinForExecution(command) {
  const pin = activeTrustedCommandPins?.get(command) ?? inspectTrustedCommand(command);
  if (activeTrustedCommandPins !== undefined && !activeTrustedCommandPins.has(command)) {
    fail(`subprocess executable is outside the active command-pin closure: ${command}`);
  }
  return pin;
}

function executePinnedCommand(
  pin,
  args,
  {
    allowOutput = true,
    timeout = 10_000,
    testHooks = undefined,
  } = {},
) {
  const command = pin.path;
  const binding = openPinnedCommandDescriptor(pin, "runtime command");
  let nestedBinding;
  let interpreterBinding;
  try {
    testHooks?.afterDescriptorVerification?.();

    // Re-read the still-open descriptor after the test-only race hook and
    // execute that descriptor through procfs. The pathname is never passed to
    // execve after its pin has been accepted.
    confirmPinnedCommandDescriptor(binding, "before descriptor execution");
    let descriptorPath = `/proc/${process.pid}/fd/${binding.fd}`;
    let spawnArgs = args;
    let stdio;
    let argv0 = command;
    if (command === "/usr/sbin/ufw") {
      // Ubuntu 24.04's reviewed UFW entry point is a Python script. Bypass its
      // pathname shebang resolution: execute the pinned canonical interpreter
      // descriptor and pass the already-open UFW script as inherited fd 3.
      interpreterBinding = openPinnedCommandDescriptor(
        commandPinForExecution("/usr/bin/python3.12"),
        "runtime command interpreter",
      );
      confirmPinnedCommandDescriptor(interpreterBinding, "before descriptor execution");
      descriptorPath = `/proc/${process.pid}/fd/${interpreterBinding.fd}`;
      argv0 = "/usr/bin/python3.12";
      spawnArgs = ["/proc/self/fd/3", ...args];
      stdio = ["ignore", "pipe", "pipe", binding.fd];
    } else if (command === "/usr/bin/setpriv") {
      const separators = args.flatMap((value, index) => value === "--" ? [index] : []);
      if (
        separators.length !== 1 ||
        separators[0] + 2 > args.length ||
        args[separators[0] + 1] !== "/usr/bin/test"
      ) {
        fail("setpriv runtime probe must execute only the reviewed /usr/bin/test command");
      }
      nestedBinding = openPinnedCommandDescriptor(
        commandPinForExecution("/usr/bin/test"),
        "nested runtime command",
      );
      confirmPinnedCommandDescriptor(nestedBinding, "before descriptor execution");
      spawnArgs = [...args];
      spawnArgs[separators[0] + 1] = "/proc/self/fd/3";
      stdio = ["ignore", "pipe", "pipe", nestedBinding.fd];
    }
    const result = spawnSync(descriptorPath, spawnArgs, {
      argv0,
      encoding: "utf8",
      env: { LC_ALL: "C", PATH: "/usr/sbin:/usr/bin" },
      maxBuffer: MAX_COMMAND_OUTPUT_BYTES,
      shell: false,
      ...(stdio === undefined ? {} : { stdio }),
      timeout,
    });
    testHooks?.afterSpawn?.();

    confirmPinnedCommandDescriptor(binding, "after descriptor execution");
    confirmPinnedCommandPath(binding, "final pathname");
    if (nestedBinding !== undefined) {
      confirmPinnedCommandDescriptor(nestedBinding, "after descriptor execution");
      confirmPinnedCommandPath(nestedBinding, "final pathname");
    }
    if (interpreterBinding !== undefined) {
      confirmPinnedCommandDescriptor(interpreterBinding, "after descriptor execution");
      confirmPinnedCommandPath(interpreterBinding, "final pathname");
    }
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
  } finally {
    if (interpreterBinding !== undefined) closeSync(interpreterBinding.fd);
    if (nestedBinding !== undefined) closeSync(nestedBinding.fd);
    closeSync(binding.fd);
  }
}

function runAbsolute(command, args, { allowOutput = true, timeout = 10_000 } = {}) {
  validateAbsolutePath(command, "subprocess executable");
  if (!ALLOWED_COMMANDS.includes(command)) fail(`subprocess executable is not reviewed: ${command}`);
  if (!Array.isArray(args) || args.some((entry) => typeof entry !== "string" || /[\0\r\n]/u.test(entry))) {
    fail(`subprocess argv is malformed for ${command}`);
  }
  return executePinnedCommand(commandPinForExecution(command), args, { allowOutput, timeout });
}

function inspectTrustedCommand(path) {
  return inspectCommandPin(path);
}

export function runDescriptorBoundCommandForTestV1(command, args, testHooks) {
  validateAbsolutePath(command, "test runtime command");
  if (!Array.isArray(args) || args.some((entry) => typeof entry !== "string" || /[\0\r\n]/u.test(entry))) {
    fail("test runtime command argv is malformed");
  }
  const pin = inspectCommandPin(command, { requireRootOwner: false });
  return executePinnedCommand(pin, args, { testHooks });
}

export function runDescriptorBoundSetprivProbeForTestV1() {
  return runAbsolute("/usr/bin/setpriv", [
    "--no-new-privs",
    "--inh-caps=-all",
    "--ambient-caps=-all",
    "--bounding-set=-all",
    "--",
    "/usr/bin/test",
    "-r",
    "/proc/self/status",
  ]);
}

export function confirmDescriptorBoundCommandPinsForTestV1(paths, betweenChecks) {
  if (
    !Array.isArray(paths) ||
    paths.length < 1 ||
    paths.some((path, index) =>
      typeof path !== "string" || (index > 0 && paths[index - 1] >= path)) ||
    typeof betweenChecks !== "function"
  ) {
    fail("test command pin set must be a non-empty sorted unique path array");
  }
  const pins = paths.map((path) => inspectCommandPin(path, { requireRootOwner: false }));
  betweenChecks();
  for (const pin of pins) {
    assertCommandPinUnchanged(
      pin,
      inspectCommandPin(pin.path, { requireRootOwner: false }),
      "test final runtime command pin",
    );
  }
  return pins;
}

function statInteger(value, label) {
  const number = typeof value === "bigint" ? Number(value) : value;
  if (!Number.isSafeInteger(number) || number < 0) {
    fail(`${label} is outside the safe evidence integer range`);
  }
  return number;
}

function statMode(stat) {
  const mode = typeof stat.mode === "bigint"
    ? Number(stat.mode & 0o7777n)
    : stat.mode & 0o7777;
  return mode.toString(8).padStart(4, "0");
}

function statNanoseconds(stat, field) {
  const nanoseconds = stat[`${field}Ns`];
  if (typeof nanoseconds === "bigint") return nanoseconds.toString();
  const milliseconds = stat[`${field}Ms`];
  if (!Number.isFinite(milliseconds) || milliseconds < 0) {
    fail(`installed artifact ${field} timestamp is invalid`);
  }
  return BigInt(Math.trunc(milliseconds * 1_000_000)).toString();
}

function stableStat(stat) {
  return {
    dev: stat.dev.toString(),
    gid: statInteger(stat.gid, "installed artifact GID"),
    ino: stat.ino.toString(),
    mode: statMode(stat),
    nlink: statInteger(stat.nlink, "installed artifact link count"),
    size: statInteger(stat.size, "installed artifact size"),
    uid: statInteger(stat.uid, "installed artifact UID"),
  };
}

function preciseInstalledStat(stat) {
  return {
    ...stableStat(stat),
    ctime_ns: statNanoseconds(stat, "ctime"),
    mtime_ns: statNanoseconds(stat, "mtime"),
  };
}

function readExactDescriptorBytes(fd, expectedSize, label, path) {
  const size = statInteger(expectedSize, `${label} size`);
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < bytes.length) {
    const count = readSync(fd, bytes, offset, bytes.length - offset, offset);
    if (count === 0) fail(`${label} became truncated during descriptor read: ${path}`);
    offset += count;
  }
  const trailing = Buffer.alloc(1);
  if (readSync(fd, trailing, 0, 1, bytes.length) !== 0) {
    fail(`${label} grew during descriptor read: ${path}`);
  }
  return bytes;
}

function assertOneLinkCanonicalRegular(path, stat, label, maxBytes) {
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    statInteger(stat.nlink, `${label} link count`) !== 1 ||
    realpathSync(path) !== path
  ) {
    fail(`${label} must be a canonical one-link regular file: ${path}`);
  }
  const size = statInteger(stat.size, `${label} size`);
  if (size > maxBytes) fail(`${label} exceeds its size limit: ${path}`);
}

function collectFinalOneLinkRegularSnapshot(
  path,
  label,
  expectedBytes,
  maxBytes,
  testHooks = undefined,
) {
  const before = lstatSync(path, { bigint: true });
  assertOneLinkCanonicalRegular(path, before, label, maxBytes);
  const fd = openSync(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | (constants.O_CLOEXEC ?? 0),
  );
  try {
    const opened = fstatSync(fd, { bigint: true });
    assertSameInstalledFileSnapshot(before, opened, `${label} final path and descriptor`, path);
    assertSamePreciseInstalledFileSnapshot(
      before,
      opened,
      `${label} final path and descriptor`,
      path,
    );
    runInstalledFileTestHook(testHooks, "afterFinalPathOpen");
    const bytes = readExactDescriptorBytes(fd, opened.size, label, path);
    const after = fstatSync(fd, { bigint: true });
    assertSameInstalledFileSnapshot(opened, after, `${label} final descriptor snapshots`, path);
    assertSamePreciseInstalledFileSnapshot(
      opened,
      after,
      `${label} final descriptor snapshots`,
      path,
    );
    if (!bytes.equals(expectedBytes)) fail(`${label} changed before its final descriptor read: ${path}`);
    const pathAfter = lstatSync(path, { bigint: true });
    assertOneLinkCanonicalRegular(path, pathAfter, `${label} final confirmation`, maxBytes);
    assertSameInstalledFileSnapshot(after, pathAfter, `${label} final descriptor and path`, path);
    assertSamePreciseInstalledFileSnapshot(
      after,
      pathAfter,
      `${label} final descriptor and path`,
      path,
    );
    return { stat: after };
  } finally {
    closeSync(fd);
  }
}

function readOneLinkRegularBoundToDescriptor(
  path,
  label,
  maxBytes = MAX_JSON_BYTES,
  testHooks = undefined,
) {
  const before = lstatSync(path, { bigint: true });
  assertOneLinkCanonicalRegular(path, before, label, maxBytes);
  const fd = openSync(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | (constants.O_CLOEXEC ?? 0),
  );
  try {
    const opened = fstatSync(fd, { bigint: true });
    assertSameInstalledFileSnapshot(before, opened, `${label} initial path and descriptor`, path);
    assertSamePreciseInstalledFileSnapshot(
      before,
      opened,
      `${label} initial path and descriptor`,
      path,
    );
    runInstalledFileTestHook(testHooks, "afterOpen");
    const bytes = readExactDescriptorBytes(fd, opened.size, label, path);
    const afterRead = fstatSync(fd, { bigint: true });
    assertSameInstalledFileSnapshot(opened, afterRead, `${label} descriptor read`, path);
    assertSamePreciseInstalledFileSnapshot(opened, afterRead, `${label} descriptor read`, path);
    runInstalledFileTestHook(testHooks, "afterFirstRead");
    const finalSnapshot = collectFinalOneLinkRegularSnapshot(
      path,
      label,
      bytes,
      maxBytes,
      testHooks,
    );
    assertSameInstalledFileSnapshot(
      afterRead,
      finalSnapshot.stat,
      `${label} initial and final descriptors`,
      path,
    );
    assertSamePreciseInstalledFileSnapshot(
      afterRead,
      finalSnapshot.stat,
      `${label} initial and final descriptors`,
      path,
    );
    return {
      bytes,
      fingerprint: preciseInstalledStat(finalSnapshot.stat),
    };
  } finally {
    closeSync(fd);
  }
}

export function readOneLinkRegularForTestV1(path, label, maxBytes, testHooks) {
  return readOneLinkRegularBoundToDescriptor(path, label, maxBytes, testHooks).bytes;
}

function collectExtendedMetadata(
  path,
  expectedType,
  { dereferenceStat = false, evidencePath = undefined, nodeStat = undefined } = {},
) {
  const statRecord = runAbsolute("/usr/bin/stat", [
    ...(dereferenceStat ? ["-L"] : []),
    "-c",
    "%d:%i:%u:%g:%a:%h:%s:%F",
    "--",
    path,
  ]);
  if (statRecord.exit_status !== 0 || statRecord.stderr !== "") fail(`stat failed for ${path}`);
  const expectedNodeStat = nodeStat ?? lstatSync(path);
  const statType = {
    directory: "directory",
    regular: "regular file",
    socket: "socket",
  }[expectedType];
  if (statType === undefined) fail(`unreviewed extended metadata type: ${expectedType}`);
  const expectedStatLine = `${expectedNodeStat.dev}:${expectedNodeStat.ino}:${expectedNodeStat.uid}:${expectedNodeStat.gid}:${Number.parseInt(
    statMode(expectedNodeStat),
    8,
  ).toString(8)}:${expectedNodeStat.nlink}:${expectedNodeStat.size}:${statType}\n`;
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
  const canonicalOutput = (stdout) => evidencePath === undefined
    ? stdout
    : stdout.split(path).join(evidencePath);
  return {
    acl_sha256: hashBytes(Buffer.from(canonicalOutput(acl.stdout))),
    capability_sha256: hashBytes(Buffer.from(canonicalOutput(capabilities.stdout))),
    expected_type: expectedType,
    stat_command_sha256: hashBytes(Buffer.from(canonicalOutput(statRecord.stdout))),
    xattr_sha256: hashBytes(Buffer.from(canonicalOutput(xattrs.stdout))),
  };
}

function assertSameInstalledFileSnapshot(left, right, label, path) {
  if (canonicalJson(stableStat(left)) !== canonicalJson(stableStat(right))) {
    fail(`installed artifact ${label} do not name the same stable file: ${path}`);
  }
}

function assertSamePreciseInstalledFileSnapshot(left, right, label, path) {
  if (canonicalJson(preciseInstalledStat(left)) !== canonicalJson(preciseInstalledStat(right))) {
    fail(`installed artifact ${label} changed precise metadata: ${path}`);
  }
}

function assertCanonicalInstalledFile(path, stat, label) {
  if (!stat.isFile() || stat.isSymbolicLink() || realpathSync(path) !== path) {
    fail(`installed artifact ${label} is not a canonical regular file: ${path}`);
  }
}

function runInstalledFileTestHook(testHooks, phase) {
  if (testHooks === undefined) return;
  const hook = testHooks[phase];
  if (hook !== undefined) hook();
}

// Preserve the externally verified v4 evidence shape while retaining the
// precise collector-local fingerprint needed to detect a same-inode
// write-and-restore between repeated secret checks. Offline evidence never
// gets to manufacture or replace this process-local comparison state.
const installedFilePreciseFingerprints = new WeakMap();

function collectFinalInstalledPathDescriptor(path, expectedBytes, testHooks = undefined) {
  const finalPathBeforeOpen = lstatSync(path, { bigint: true });
  assertCanonicalInstalledFile(path, finalPathBeforeOpen, "final path");
  const finalFd = openSync(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | (constants.O_CLOEXEC ?? 0),
  );
  try {
    const finalOpened = fstatSync(finalFd, { bigint: true });
    assertSameInstalledFileSnapshot(
      finalPathBeforeOpen,
      finalOpened,
      "final path snapshot and final descriptor",
      path,
    );
    assertSamePreciseInstalledFileSnapshot(
      finalPathBeforeOpen,
      finalOpened,
      "final path snapshot and final descriptor",
      path,
    );
    runInstalledFileTestHook(testHooks, "afterFinalPathOpen");
    const finalBytes = readExactDescriptorBytes(
      finalFd,
      finalOpened.size,
      "installed artifact final path",
      path,
    );
    const finalAfterRead = fstatSync(finalFd, { bigint: true });
    assertSameInstalledFileSnapshot(
      finalOpened,
      finalAfterRead,
      "final descriptor read snapshots",
      path,
    );
    assertSamePreciseInstalledFileSnapshot(
      finalOpened,
      finalAfterRead,
      "final descriptor read snapshots",
      path,
    );
    if (!finalBytes.equals(expectedBytes)) {
      fail(`installed artifact final path content changed: ${path}`);
    }
    const finalPathAfterOpen = lstatSync(path, { bigint: true });
    assertCanonicalInstalledFile(path, finalPathAfterOpen, "final path confirmation");
    assertSameInstalledFileSnapshot(
      finalAfterRead,
      finalPathAfterOpen,
      "final descriptor and final path confirmation",
      path,
    );
    assertSamePreciseInstalledFileSnapshot(
      finalAfterRead,
      finalPathAfterOpen,
      "final descriptor and final path confirmation",
      path,
    );
    return { stat: finalAfterRead };
  } finally {
    closeSync(finalFd);
  }
}

function collectInstalledFileBoundToDescriptor(expected, testHooks = undefined) {
  const path = expected.target_path;
  const before = lstatSync(path, { bigint: true });
  assertCanonicalInstalledFile(path, before, "initial path");
  const fd = openSync(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | (constants.O_CLOEXEC ?? 0),
  );
  try {
    const opened = fstatSync(fd, { bigint: true });
    assertSameInstalledFileSnapshot(before, opened, "initial path and opened descriptor", path);
    assertSamePreciseInstalledFileSnapshot(
      before,
      opened,
      "initial path and opened descriptor",
      path,
    );
    runInstalledFileTestHook(testHooks, "afterOpen");

    const bytes = readExactDescriptorBytes(
      fd,
      opened.size,
      "installed artifact initial path",
      path,
    );
    const afterFirstRead = fstatSync(fd, { bigint: true });
    assertSameInstalledFileSnapshot(opened, afterFirstRead, "initial descriptor read", path);
    assertSamePreciseInstalledFileSnapshot(opened, afterFirstRead, "initial descriptor read", path);
    runInstalledFileTestHook(testHooks, "afterFirstRead");
    const descriptorPath = `/proc/${process.pid}/fd/${fd}`;
    const descriptorSha256 = hashBytes(bytes);
    const canonicalSha256Output = `${descriptorSha256} *${path}\n`;
    const sha256Command = runAbsolute("/usr/bin/sha256sum", [
      "--binary",
      "--",
      descriptorPath,
    ]);
    const expectedSha256Output = `${descriptorSha256} *${descriptorPath}\n`;
    if (
      sha256Command.exit_status !== 0 ||
      sha256Command.stderr !== "" ||
      sha256Command.stdout !== expectedSha256Output
    ) {
      fail(`sha256sum failed for ${path}`);
    }
    const extendedMetadata = collectExtendedMetadata(descriptorPath, "regular", {
      dereferenceStat: true,
      evidencePath: path,
      nodeStat: afterFirstRead,
    });
    runInstalledFileTestHook(testHooks, "afterMetadataProbe");

    {
      const confirmationBytes = readExactDescriptorBytes(
        fd,
        afterFirstRead.size,
        "installed artifact confirmation",
        path,
      );
      if (!confirmationBytes.equals(bytes)) {
        fail(`installed artifact content changed during descriptor reread: ${path}`);
      }
    }

    const after = fstatSync(fd, { bigint: true });
    assertSameInstalledFileSnapshot(afterFirstRead, after, "opened descriptor snapshots", path);
    assertSamePreciseInstalledFileSnapshot(afterFirstRead, after, "opened descriptor snapshots", path);
    runInstalledFileTestHook(testHooks, "beforeFinalPathOpen");
    const finalPathSnapshot = collectFinalInstalledPathDescriptor(path, bytes, testHooks);
    assertSameInstalledFileSnapshot(
      after,
      finalPathSnapshot.stat,
      "opened descriptor and final path descriptor",
      path,
    );
    assertSamePreciseInstalledFileSnapshot(
      after,
      finalPathSnapshot.stat,
      "opened descriptor and final path descriptor",
      path,
    );
    const observed = {
      ...stableStat(after),
      file_type: "regular",
      sha256: descriptorSha256,
      // Preserve the stable evidence representation used by repeated secret
      // checks without retaining the process-local /proc descriptor pathname.
      // The raw command output was already checked exactly against that bound
      // descriptor above.
      sha256_command_sha256: hashBytes(Buffer.from(canonicalSha256Output)),
      target_path: path,
      ...extendedMetadata,
    };
    for (const key of ["gid", "mode", "nlink", "sha256", "uid"]) {
      if (observed[key] !== expected[key]) fail(`installed artifact ${key} mismatch: ${path}`);
    }
    installedFilePreciseFingerprints.set(
      observed,
      preciseInstalledStat(finalPathSnapshot.stat),
    );
    return observed;
  } finally {
    closeSync(fd);
  }
}

function collectInstalledFile(expected) {
  return collectInstalledFileBoundToDescriptor(expected);
}

// The production collector above never accepts hooks. This narrow export exists
// only so regression tests can place deterministic pathname substitutions at
// security-sensitive collection boundaries.
export function collectInstalledFileForTestV1(expected, testHooks) {
  return collectInstalledFileBoundToDescriptor(expected, testHooks);
}

function assertInstalledFileCollectionsUnchanged(before, after, stage, path) {
  const beforePrecise = installedFilePreciseFingerprints.get(before);
  const afterPrecise = installedFilePreciseFingerprints.get(after);
  if (
    beforePrecise === undefined ||
    afterPrecise === undefined ||
    canonicalJson(before) !== canonicalJson(after) ||
    canonicalJson(beforePrecise) !== canonicalJson(afterPrecise)
  ) {
    fail(`installed artifact metadata or content changed ${stage}: ${path}`);
  }
}

export function confirmInstalledFileAcrossCollectionsForTestV1(expected, betweenHook) {
  const before = collectInstalledFileBoundToDescriptor(expected);
  betweenHook();
  const after = collectInstalledFileBoundToDescriptor(expected);
  assertInstalledFileCollectionsUnchanged(before, after, "between test collections", expected.target_path);
  return true;
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
      !Number.isSafeInteger(identity.gid)
    ) {
      fail("service identity account binding is duplicated or malformed");
    }
    validateServiceIdentityId(identity.uid, `service identity policy[${index}].uid`);
    validateServiceIdentityId(identity.gid, `service identity policy[${index}].gid`);
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
  if (!databases.has("passwd") || !databases.has("group")) {
    fail("NSS backend must define both passwd and group sources");
  }
  const sources = {
    group: databases.get("group"),
    initgroups: "inherits-group",
    passwd: databases.get("passwd"),
  };
  if (databases.has("initgroups")) {
    fail("NSS backend must inherit group sources for initgroups");
  }
  return assertReviewedNssSources(sources, "NSS backend sources");
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

export function assertCompleteNssSnapshotUnchangedV2(expected, actual) {
  if (canonicalJson(expected) !== canonicalJson(actual)) {
    fail(
      "local NSS policy, identity files, or complete getent/id projection changed after complete enumeration",
    );
  }
  return true;
}

function confirmCompleteNssSnapshotUnchanged(nss) {
  return assertCompleteNssSnapshotUnchangedV2(nss, collectNss());
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

function collectAbsentRuntimeSockets(request, { allowEmpty = false } = {}) {
  const sockets = request.runtime_paths
    .filter((entry) => entry.file_type === "socket")
    .map(collectAbsentRuntimeSocket)
    .sort((left, right) => left.target_path < right.target_path ? -1 : left.target_path > right.target_path ? 1 : 0);
  if (!allowEmpty && sockets.length < 1) fail("edge runtime request has no socket listener to prove absent");
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

function secretDirectoryChainPaths(path) {
  if (path === "/") return [{ component: null, target_path: "/" }];
  validateAbsolutePath(path, "secret parent directory");
  const chain = [{ component: null, target_path: "/" }];
  let cursor = "";
  for (const component of path.slice(1).split("/")) {
    if (!/^[A-Za-z0-9._-]+$/u.test(component)) {
      fail(`secret parent contains an invalid directory component: ${path}`);
    }
    cursor += `/${component}`;
    chain.push({ component, target_path: cursor });
  }
  return chain;
}

function preciseDirectoryFingerprint(stat, precise, label) {
  const ordinary = stableStat(stat);
  const preciseStable = {
    dev: precise.dev.toString(),
    gid: precise.gid.toString(),
    ino: precise.ino.toString(),
    mode: (precise.mode & 0o7777n).toString(8).padStart(4, "0"),
    nlink: precise.nlink.toString(),
    size: precise.size.toString(),
    uid: precise.uid.toString(),
  };
  const ordinaryComparable = {
    dev: ordinary.dev,
    gid: ordinary.gid.toString(),
    ino: ordinary.ino,
    mode: ordinary.mode,
    nlink: ordinary.nlink.toString(),
    size: ordinary.size.toString(),
    uid: ordinary.uid.toString(),
  };
  if (canonicalJson(ordinaryComparable) !== canonicalJson(preciseStable)) {
    fail(`${label} changed between ordinary and precise stat snapshots`);
  }
  return {
    ...preciseStable,
    ctime_ns: precise.ctimeNs.toString(),
    mtime_ns: precise.mtimeNs.toString(),
  };
}

function snapshotSecretDirectoryPath(path, label) {
  const stat = lstatSync(path);
  const precise = lstatSync(path, { bigint: true });
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    !precise.isDirectory() ||
    precise.isSymbolicLink() ||
    realpathSync(path) !== path
  ) {
    fail(`${label} is not a canonical directory: ${path}`);
  }
  return {
    fingerprint: preciseDirectoryFingerprint(stat, precise, label),
    stat,
  };
}

function snapshotSecretDirectoryFd(fd, path, label) {
  const stat = fstatSync(fd);
  const precise = fstatSync(fd, { bigint: true });
  if (!stat.isDirectory() || !precise.isDirectory()) {
    fail(`${label} is not a directory: ${path}`);
  }
  return {
    fingerprint: preciseDirectoryFingerprint(stat, precise, label),
    stat,
  };
}

function assertSameSecretDirectorySnapshot(left, right, label, path) {
  if (canonicalJson(left.fingerprint) !== canonicalJson(right.fingerprint)) {
    fail(`${label}: ${path}`);
  }
}

function closeSecretDirectoryChain(nodes) {
  for (const node of [...nodes].reverse()) closeSync(node.fd);
}

function compareSecretDirectoryPaths(left, right) {
  const leftDepth = left === "/" ? 0 : left.split("/").length - 1;
  const rightDepth = right === "/" ? 0 : right.split("/").length - 1;
  if (leftDepth !== rightDepth) return leftDepth - rightDepth;
  return left < right ? -1 : left > right ? 1 : 0;
}

function openPinnedSecretDirectorySet(paths) {
  if (!Array.isArray(paths) || new Set(paths).size !== paths.length) {
    fail("secret directory descriptor set contains duplicate or malformed paths");
  }
  const orderedPaths = [...paths].sort(compareSecretDirectoryPaths);
  const nodes = [];
  const nodesByPath = new Map();
  try {
    for (const targetPath of orderedPaths) {
      if (targetPath !== "/") {
        validateAbsolutePath(targetPath, "secret parent directory set path");
      }
      const component = targetPath === "/" ? null : basename(targetPath);
      if (component !== null && !/^[A-Za-z0-9._-]+$/u.test(component)) {
        fail(`secret parent contains an invalid directory component: ${targetPath}`);
      }
      const entry = { component, target_path: targetPath };
      const initial = snapshotSecretDirectoryPath(
        entry.target_path,
        "secret directory initial pathname",
      );
      const parent = entry.target_path === "/"
        ? undefined
        : nodesByPath.get(dirname(entry.target_path));
      if (entry.target_path !== "/" && parent === undefined) {
        fail(`secret directory descriptor set is missing an ancestor: ${entry.target_path}`);
      }
      const openPath = parent === undefined
        ? "/"
        : `/proc/${process.pid}/fd/${parent.fd}/${entry.component}`;
      const fd = openSync(
        openPath,
        constants.O_RDONLY |
          constants.O_DIRECTORY |
          constants.O_NOFOLLOW |
          (constants.O_CLOEXEC ?? 0),
      );
      let retained = false;
      try {
        const opened = snapshotSecretDirectoryFd(
          fd,
          entry.target_path,
          "secret directory opened descriptor",
        );
        assertSameSecretDirectorySnapshot(
          initial,
          opened,
          "secret directory initial pathname/opened descriptor mismatch",
          entry.target_path,
        );
        const pathnameConfirmation = snapshotSecretDirectoryPath(
          entry.target_path,
          "secret directory pathname confirmation",
        );
        assertSameSecretDirectorySnapshot(
          opened,
          pathnameConfirmation,
          "secret directory opened descriptor/pathname confirmation mismatch",
          entry.target_path,
        );
        nodes.push({
          ...entry,
          fd,
          opened,
        });
        nodesByPath.set(entry.target_path, nodes.at(-1));
        retained = true;
      } finally {
        if (!retained) closeSync(fd);
      }
    }
    return nodes;
  } catch (error) {
    closeSecretDirectoryChain(nodes);
    throw error;
  }
}

function runSecretParentTestHook(testHooks, phase) {
  if (testHooks === undefined) return;
  const hook = testHooks[phase];
  if (hook !== undefined) hook();
}

function collectSecretParentDirectoriesBound(paths, testHooks = undefined) {
  const pinned = openPinnedSecretDirectorySet(paths);
  try {
    runSecretParentTestHook(testHooks, "afterPinnedChain");
    const extendedMetadataByPath = new Map();
    for (const node of pinned) {
      const descriptorPath = `/proc/${process.pid}/fd/${node.fd}`;
      extendedMetadataByPath.set(
        node.target_path,
        collectExtendedMetadata(descriptorPath, "directory", {
          dereferenceStat: true,
          evidencePath: node.target_path,
          nodeStat: node.opened.stat,
        }),
      );
    }
    runSecretParentTestHook(testHooks, "afterMetadataProbe");

    const afterProbe = pinned.map((node) => {
      const snapshot = snapshotSecretDirectoryFd(
        node.fd,
        node.target_path,
        "secret directory post-probe descriptor",
      );
      assertSameSecretDirectorySnapshot(
        node.opened,
        snapshot,
        "pinned secret directory metadata changed during probes",
        node.target_path,
      );
      return snapshot;
    });

    const finalChain = openPinnedSecretDirectorySet(paths);
    try {
      if (finalChain.length !== pinned.length) {
        fail("secret directory final descriptor set length changed");
      }
      for (let index = 0; index < pinned.length; index += 1) {
        if (pinned[index].target_path !== finalChain[index].target_path) {
          fail("secret directory final descriptor set path changed");
        }
        assertSameSecretDirectorySnapshot(
          afterProbe[index],
          finalChain[index].opened,
          "secret directory pinned/final descriptor mismatch",
          pinned[index].target_path,
        );
      }
    } finally {
      closeSecretDirectoryChain(finalChain);
    }

    const snapshotsByPath = new Map(
      pinned.map((node, index) => [node.target_path, afterProbe[index]]),
    );
    const evidence = paths.map((path) => {
      const snapshot = snapshotsByPath.get(path);
      const extendedMetadata = extendedMetadataByPath.get(path);
      if (!snapshot || !extendedMetadata) {
        fail(`secret directory evidence set is incomplete: ${path}`);
      }
      return {
        ...stableStat(snapshot.stat),
        file_type: "directory",
        target_path: path,
        ...extendedMetadata,
      };
    });
    const privateFingerprints = paths.map((path) => {
      const snapshot = snapshotsByPath.get(path);
      if (!snapshot) fail(`secret directory private fingerprint is missing: ${path}`);
      return {
        fingerprint: snapshot.fingerprint,
        target_path: path,
      };
    });
    return { evidence, privateFingerprints };
  } finally {
    closeSecretDirectoryChain(pinned);
  }
}

function collectSecretParentDirectories(secretFiles) {
  const paths = secretParentPaths(secretFiles);
  return collectSecretParentDirectoriesBound(paths);
}

// Production collection never accepts hooks. This export exists only for
// deterministic directory rename/replace regression tests.
export function collectSecretParentDirectoryForTestV1(path, testHooks) {
  const paths = secretDirectoryChainPaths(path).map((entry) => entry.target_path);
  return collectSecretParentDirectoriesBound(paths, testHooks).evidence.at(-1);
}

function assertSecretParentDirectoryBundlesUnchanged(initial, confirmation, stage) {
  if (canonicalJson(initial.evidence) !== canonicalJson(confirmation.evidence)) {
    fail(`secret parent directory metadata changed ${stage}`);
  }
  if (
    canonicalJson(initial.privateFingerprints) !==
    canonicalJson(confirmation.privateFingerprints)
  ) {
    fail(`secret parent directory namespace fingerprint changed ${stage}`);
  }
}

// Test-only cross-collection interlock: production collection stores the first
// private bundle and performs its confirmations without any caller callback.
export function confirmSecretParentDirectoryAcrossCollectionsForTestV1(
  path,
  betweenCollections,
) {
  const paths = secretDirectoryChainPaths(path).map((entry) => entry.target_path);
  const initial = collectSecretParentDirectoriesBound(paths);
  betweenCollections();
  const confirmation = collectSecretParentDirectoriesBound(paths);
  assertSecretParentDirectoryBundlesUnchanged(
    initial,
    confirmation,
    "between test collections",
  );
  return initial.evidence.at(-1);
}

function validateSecretParentDirectoryEvidenceMetadata(directory, path) {
  if (
    typeof directory.dev !== "string" ||
    !/^(?:0|[1-9][0-9]*)$/u.test(directory.dev) ||
    typeof directory.ino !== "string" ||
    !/^[1-9][0-9]*$/u.test(directory.ino) ||
    !Number.isSafeInteger(directory.uid) ||
    directory.uid < 0 ||
    directory.uid > 0xffff_ffff ||
    !Number.isSafeInteger(directory.gid) ||
    directory.gid < 0 ||
    directory.gid > 0xffff_ffff ||
    typeof directory.mode !== "string" ||
    !/^[0-7]{4}$/u.test(directory.mode) ||
    !Number.isSafeInteger(directory.nlink) ||
    directory.nlink < 1 ||
    !Number.isSafeInteger(directory.size) ||
    directory.size < 0
  ) {
    fail(`live secret parent directory metadata is malformed: ${path}`);
  }
}

function validateSecretParentDirectoryPolicyV1(
  secretFiles,
  serviceIdentities,
  parentDirectories,
) {
  const parentsByPath = new Map(
    parentDirectories.map((directory) => [directory.target_path, directory]),
  );
  if (parentsByPath.size !== parentDirectories.length) {
    fail("live secret parent directory evidence repeats a path");
  }
  for (const secret of secretFiles) {
    const consumer = serviceIdentities.find(
      (identity) => identity.unit_name === secret.consumer_unit_name,
    );
    if (
      !consumer ||
      secret.uid !== consumer.uid ||
      secret.gid !== consumer.gid ||
      secret.mode !== "0400"
    ) {
      fail(`live secret is not bound to its exact owner-only consumer: ${secret.target_path}`);
    }
    let cursor = dirname(secret.target_path);
    let finalParent = true;
    for (;;) {
      const directory = parentsByPath.get(cursor);
      if (!directory) {
        fail(`live secret ancestor evidence is missing: ${cursor}`);
      }
      if (
        !Number.isSafeInteger(directory.uid) ||
        directory.uid < 0 ||
        directory.uid > 0xffff_ffff ||
        typeof directory.mode !== "string" ||
        !/^[0-7]{4}$/u.test(directory.mode)
      ) {
        fail(`live secret ancestor metadata is malformed: ${cursor}`);
      }
      const permissions = Number.parseInt(directory.mode, 8);
      if (finalParent) {
        // This mirrors pir_private_files::validate_private_parent_fd_v1:
        // loading after a restart must see the service euid and exact 0700,
        // not merely a path that happened to pass a positive readability test.
        if (directory.uid !== consumer.uid || permissions !== 0o700) {
          fail(
            `live secret final parent must be consumer-owned mode 0700: ${cursor}`,
          );
        }
      } else {
        const rootOwnedSticky =
          directory.uid === 0 &&
          (permissions & 0o1000) !== 0 &&
          (permissions & 0o022) !== 0;
        if (
          (directory.uid !== 0 && directory.uid !== consumer.uid) ||
          ((permissions & 0o022) !== 0 && !rootOwnedSticky)
        ) {
          fail(
            `live secret ancestor violates the private-file loader policy: ${cursor}`,
          );
        }
      }
      if (cursor === "/") break;
      cursor = dirname(cursor);
      finalParent = false;
    }
  }
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
  if (pinned) {
    validateServiceIdentityId(pinned.uid, `${unit.unit_name} service uid`);
    validateServiceIdentityId(pinned.gid, `${unit.unit_name} service gid`);
  }
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
  "LimitNOFILE",
  "LimitNOFILESoft",
  "LockPersonality",
  "MemoryDenyWriteExecute",
  "MemoryMax",
  "MemorySwapCurrent",
  "MemorySwapMax",
  "NetworkNamespacePath",
  "NoNewPrivileges",
  "NotifyAccess",
  "PrivateDevices",
  "PrivateMounts",
  "PrivateTmp",
  "ProcSubset",
  "ProtectClock",
  "ProtectControlGroups",
  "ProtectHome",
  "ProtectHostname",
  "ProtectKernelLogs",
  "ProtectKernelModules",
  "ProtectKernelTunables",
  "ProtectProc",
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
  "StateDirectory",
  "StateDirectoryMode",
  "SupplementaryGroups",
  "SystemCallArchitectures",
  "TasksMax",
  "TemporaryFileSystem",
  "Type",
  "UMask",
  "UnsetEnvironment",
  "User",
  "WorkingDirectory",
]);

const EFFECTIVE_BASE_PROPERTIES = Object.freeze([
  "ActiveEnterTimestampMonotonic",
  "ActiveState",
  "BindPaths",
  "BindReadOnlyPaths",
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
  "InvocationID",
  "LoadState",
  "MainPID",
  "NeedDaemonReload",
  "Result",
  "RootDirectory",
  "RootImage",
  "SubState",
  "WatchdogUSec",
]);

function effectivePropertyNames() {
  const local = [...new Set([...EFFECTIVE_BASE_PROPERTIES, ...EFFECTIVE_CRITICAL_KEYS])].sort();
  if (canonicalJson(local) !== canonicalJson(RUNTIME_SYSTEMCTL_SHOW_PROPERTIES)) {
    fail("collector and rendered runtime systemctl property schemas diverged");
  }
  return [...RUNTIME_SYSTEMCTL_SHOW_PROPERTIES];
}

function effectiveBusctlPropertyNames() {
  const local = ["After", "Before", "BindsTo", "Conditions", "Requires"];
  if (canonicalJson(local) !== canonicalJson(RUNTIME_BUSCTL_UNIT_PROPERTIES)) {
    fail("collector and rendered runtime busctl property schemas diverged");
  }
  return [...RUNTIME_BUSCTL_UNIT_PROPERTIES];
}

const EFFECTIVE_CREDENTIAL_PROPERTY_SIGNATURES = Object.freeze({
  ImportCredential: "as",
  LoadCredential: "a(ss)",
  LoadCredentialEncrypted: "a(ss)",
  SetCredential: "a(say)",
  SetCredentialEncrypted: "a(say)",
});

function effectiveBusctlServicePropertyNames() {
  const local = [
    "ExecStartEx",
    "ExecStartPreEx",
    ...Object.keys(EFFECTIVE_CREDENTIAL_PROPERTY_SIGNATURES),
    "TimeoutStopUSec",
    "WatchdogTimestampMonotonic",
    "WatchdogUSec",
  ].sort();
  if (canonicalJson(local) !== canonicalJson(RUNTIME_BUSCTL_SERVICE_PROPERTIES)) {
    fail("collector and rendered runtime busctl service property schemas diverged");
  }
  return [...RUNTIME_BUSCTL_SERVICE_PROPERTIES];
}

function effectiveBusctlManagerPropertyNames() {
  const local = ["ServiceWatchdogs", "Version"];
  if (canonicalJson(local) !== canonicalJson(RUNTIME_BUSCTL_MANAGER_PROPERTIES)) {
    fail("collector and rendered runtime busctl manager property schemas diverged");
  }
  return [...RUNTIME_BUSCTL_MANAGER_PROPERTIES];
}

function validateRuntimePropertyRequestSchema(request, label) {
  if (request.systemd_version !== REVIEWED_SYSTEMD_VERSION) {
    fail(`${label} systemd_version is not the exact reviewed build`);
  }
  if (
    !Array.isArray(request.systemctl_show_properties) ||
    canonicalJson(request.systemctl_show_properties) !==
      canonicalJson(RUNTIME_SYSTEMCTL_SHOW_PROPERTIES)
  ) {
    fail(`${label} systemctl property schema is not the reviewed closed set`);
  }
  if (
    !Array.isArray(request.busctl_unit_properties) ||
    canonicalJson(request.busctl_unit_properties) !==
      canonicalJson(RUNTIME_BUSCTL_UNIT_PROPERTIES)
  ) {
    fail(`${label} busctl Unit property schema is not the reviewed closed set`);
  }
  if (
    !Array.isArray(request.busctl_service_properties) ||
    canonicalJson(request.busctl_service_properties) !==
      canonicalJson(RUNTIME_BUSCTL_SERVICE_PROPERTIES)
  ) {
    fail(`${label} busctl Service property schema is not the reviewed closed set`);
  }
  if (
    !Array.isArray(request.busctl_manager_properties) ||
    canonicalJson(request.busctl_manager_properties) !==
      canonicalJson(RUNTIME_BUSCTL_MANAGER_PROPERTIES)
  ) {
    fail(`${label} busctl Manager property schema is not the reviewed closed set`);
  }
}

function compareEffectiveConditionRecords(left, right) {
  const leftKey = `${left.type}\0${left.parameter}\0${left.negate ? "1" : "0"}`;
  const rightKey = `${right.type}\0${right.parameter}\0${right.negate ? "1" : "0"}`;
  return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
}

function expectedEffectiveConditions(unit) {
  if (!Array.isArray(unit.conditions) || unit.conditions.length > 64) {
    fail(`unit conditions are not a bounded array: ${unit.unit_name}`);
  }
  const records = unit.conditions.map((condition) => {
    if (typeof condition !== "string") {
      fail(`unit condition is not a string: ${unit.unit_name}`);
    }
    const match = /^ConditionPathExists=(!?)(\/[A-Za-z0-9._/-]+)$/u.exec(condition);
    if (!match || resolve(match[2]) !== match[2]) {
      fail(`unit has an unreviewed effective condition: ${unit.unit_name}`);
    }
    const negate = match[1] === "!";
    const consumedApproval = new Set([
      "/run/bitcoinpir-lightning-operator-approvals/guard-generation-approved",
      "/run/bitcoinpir-lightning-operator-approvals/preflight-generation-approved",
    ]).has(match[2]);
    return {
      negate,
      parameter: match[2],
      path_exists: consumedApproval ? false : !negate,
      result: 1,
      trigger: false,
      type: "ConditionPathExists",
    };
  }).sort(compareEffectiveConditionRecords);
  const keys = records.map((record) => `${record.type}\0${record.parameter}\0${record.negate}`);
  if (new Set(keys).size !== keys.length) {
    fail(`unit contains duplicate effective conditions: ${unit.unit_name}`);
  }
  return records;
}

export function systemdUnitObjectPathV1(unitName) {
  if (typeof unitName !== "string" || !/^[a-z0-9][a-z0-9_.@-]{0,127}\.service$/u.test(unitName)) {
    fail("systemd unit name cannot be mapped to a reviewed D-Bus object path");
  }
  const escaped = [...Buffer.from(unitName, "ascii")]
    .map((byte) =>
      (byte >= 0x30 && byte <= 0x39) ||
      (byte >= 0x41 && byte <= 0x5a) ||
      (byte >= 0x61 && byte <= 0x7a)
        ? String.fromCharCode(byte)
        : `_${byte.toString(16).padStart(2, "0")}`)
    .join("");
  return `/org/freedesktop/systemd1/unit/${escaped}`;
}

export function parseBusctlConditionsJsonV1(text, label = "systemd Conditions") {
  if (typeof text !== "string" || Buffer.byteLength(text, "utf8") > 128 * 1024) {
    fail(`${label} is not bounded busctl JSON`);
  }
  const parsed = parseStrictJson(text, label);
  exactKeys(parsed, ["data", "type"], label);
  if (parsed.type !== "a(sbbsi)" || !Array.isArray(parsed.data) || parsed.data.length > 64) {
    fail(`${label} does not have the reviewed a(sbbsi) shape`);
  }
  const records = parsed.data.map((tuple, index) => {
    if (
      !Array.isArray(tuple) ||
      tuple.length !== 5 ||
      tuple[0] !== "ConditionPathExists" ||
      typeof tuple[1] !== "boolean" ||
      typeof tuple[2] !== "boolean" ||
      typeof tuple[3] !== "string" ||
      !/^\/[A-Za-z0-9._/-]+$/u.test(tuple[3]) ||
      resolve(tuple[3]) !== tuple[3] ||
      !Number.isInteger(tuple[4]) ||
      !new Set([-1, 0, 1]).has(tuple[4])
    ) {
      fail(`${label}.data[${index}] is not a reviewed ConditionPathExists tuple`);
    }
    return {
      negate: tuple[2],
      parameter: tuple[3],
      result: tuple[4],
      trigger: tuple[1],
      type: tuple[0],
    };
  }).sort(compareEffectiveConditionRecords);
  const keys = records.map((record) => `${record.type}\0${record.parameter}\0${record.negate}`);
  if (new Set(keys).size !== keys.length) fail(`${label} contains duplicate conditions`);
  return records;
}

export function parseBusctlEmptyCredentialJsonV1(
  text,
  property,
  label = `systemd ${property}`,
) {
  if (
    typeof property !== "string" ||
    !Object.hasOwn(EFFECTIVE_CREDENTIAL_PROPERTY_SIGNATURES, property)
  ) {
    fail(`${label} is not a reviewed credential property`);
  }
  if (typeof text !== "string" || Buffer.byteLength(text, "utf8") > 4096) {
    fail(`${label} is not bounded busctl JSON`);
  }
  const parsed = parseStrictJson(text, label);
  exactKeys(parsed, ["data", "type"], label);
  const expectedType = EFFECTIVE_CREDENTIAL_PROPERTY_SIGNATURES[property];
  if (parsed.type !== expectedType || !Array.isArray(parsed.data)) {
    fail(`${label} does not have the reviewed ${expectedType} shape`);
  }
  if (parsed.data.length !== 0) {
    fail(`${label} must be the typed empty credential array`);
  }
  return { data: [], type: expectedType };
}

export function systemdCredentialBusctlArgvV1(unitName, property) {
  if (
    typeof property !== "string" ||
    !Object.hasOwn(EFFECTIVE_CREDENTIAL_PROPERTY_SIGNATURES, property)
  ) {
    fail("systemd credential busctl property is not reviewed");
  }
  return [
    "--json=short",
    "get-property",
    "org.freedesktop.systemd1",
    systemdUnitObjectPathV1(unitName),
    "org.freedesktop.systemd1.Service",
    property,
  ];
}

function validateEffectiveCredentialProperties(unitName, credentialProperties) {
  const credentialPropertyNames = Object.keys(
    EFFECTIVE_CREDENTIAL_PROPERTY_SIGNATURES,
  ).sort();
  exactKeys(
    credentialProperties,
    credentialPropertyNames,
    `effective credential properties for ${unitName}`,
  );
  for (const property of credentialPropertyNames) {
    const expectedType = EFFECTIVE_CREDENTIAL_PROPERTY_SIGNATURES[property];
    const value = credentialProperties[property];
    exactKeys(value, ["data", "type"], `${unitName}.${property}`);
    if (
      value.type !== expectedType ||
      !Array.isArray(value.data) ||
      value.data.length !== 0
    ) {
      fail(`effective ${property} is forbidden: ${unitName}`);
    }
  }
}

export function assertEffectiveCredentialSnapshotUnchangedV1(
  initial,
  confirmation,
  unitName,
) {
  validateEffectiveCredentialProperties(unitName, initial);
  validateEffectiveCredentialProperties(unitName, confirmation);
  if (canonicalJson(initial) !== canonicalJson(confirmation)) {
    fail(`credential properties changed during runtime collection: ${unitName}`);
  }
  return true;
}

const SYSTEMD_DEPENDENCY_PROPERTIES_V1 = Object.freeze([
  "After",
  "Before",
  "BindsTo",
  "Requires",
]);
const SYSTEMD_UNIT_NAME_V1 =
  /^(?=.{1,320}$)(?:[A-Za-z0-9:_.@-]|\\x[0-9a-f]{2})+\.(?:automount|device|mount|path|scope|service|slice|socket|swap|target|timer)$/u;

function validateCanonicalSystemdUnitNameSetV1(value, label) {
  if (!Array.isArray(value) || value.length > 256) {
    fail(`${label} is not a bounded systemd unit-name array`);
  }
  if (
    value.some((name) => typeof name !== "string" || !SYSTEMD_UNIT_NAME_V1.test(name)) ||
    new Set(value).size !== value.length ||
    canonicalJson([...value].sort()) !== canonicalJson(value)
  ) {
    fail(`${label} is not a canonical sorted systemd unit-name set`);
  }
  return value;
}

export function parseBusctlUnitNamesJsonV1(text, label = "systemd unit relation") {
  if (typeof text !== "string" || Buffer.byteLength(text, "utf8") > 128 * 1024) {
    fail(`${label} is not bounded busctl JSON`);
  }
  const parsed = parseStrictJson(text, label);
  exactKeys(parsed, ["data", "type"], label);
  if (parsed.type !== "as" || !Array.isArray(parsed.data)) {
    fail(`${label} does not have the reviewed as shape`);
  }
  const sorted = [...parsed.data].sort();
  validateCanonicalSystemdUnitNameSetV1(sorted, label);
  return sorted;
}

export function parseBusctlUnsignedJsonV1(text, label = "systemd unsigned property") {
  if (typeof text !== "string" || Buffer.byteLength(text, "utf8") > 4096) {
    fail(`${label} is not bounded busctl JSON`);
  }
  // Parse the raw integer token before JSON.parse can round UINT64_MAX.
  // The two alternatives are the only accepted exact-key object orderings.
  const patterns = [
    /^[\t\n\r ]*\{[\t\n\r ]*"type"[\t\n\r ]*:[\t\n\r ]*"t"[\t\n\r ]*,[\t\n\r ]*"data"[\t\n\r ]*:[\t\n\r ]*(0|[1-9][0-9]*)[\t\n\r ]*\}[\t\n\r ]*$/u,
    /^[\t\n\r ]*\{[\t\n\r ]*"data"[\t\n\r ]*:[\t\n\r ]*(0|[1-9][0-9]*)[\t\n\r ]*,[\t\n\r ]*"type"[\t\n\r ]*:[\t\n\r ]*"t"[\t\n\r ]*\}[\t\n\r ]*$/u,
  ];
  let decimal;
  for (const pattern of patterns) {
    const match = pattern.exec(text);
    if (match !== null) {
      decimal = match[1];
      break;
    }
  }
  if (decimal === undefined) {
    fail(`${label} does not have one strict raw-number t object`);
  }
  validateCanonicalUint64DecimalV1(decimal, label);
  return decimal;
}

function validateCanonicalUint64DecimalV1(value, label) {
  if (
    typeof value !== "string" ||
    !/^(?:0|[1-9][0-9]{0,19})$/u.test(value)
  ) {
    fail(`${label} is not a canonical uint64 decimal string`);
  }
  const parsed = BigInt(value);
  if (parsed > UINT64_MAX) {
    fail(`${label} is outside the uint64 range`);
  }
  return parsed;
}

// busctl serializes D-Bus `t` values as JSON number tokens. JavaScript cannot
// represent UINT64_MAX exactly, so the live-v7 watchdog field preserves the
// reviewed token as canonical decimal text instead of silently rounding it.
export function parseBusctlWatchdogUsecJsonV2(
  text,
  label = "systemd WatchdogUSec property",
) {
  if (typeof text !== "string" || Buffer.byteLength(text, "utf8") > 4096) {
    fail(`${label} is not bounded busctl JSON`);
  }
  const trimmed = text.trim();
  const match = /^(?:\{"type":"t","data":(0|[1-9][0-9]*)\}|\{"data":(0|[1-9][0-9]*),"type":"t"\})$/u.exec(
    trimmed,
  );
  const decimal = match?.[1] ?? match?.[2];
  if (decimal === undefined || decimal.length > 20 || BigInt(decimal) > 18_446_744_073_709_551_615n) {
    fail(`${label} does not have one canonical uint64 t token`);
  }
  return decimal;
}

export function parseBusctlBooleanJsonV1(text, label = "systemd boolean property") {
  if (typeof text !== "string" || Buffer.byteLength(text, "utf8") > 4096) {
    fail(`${label} is not bounded busctl JSON`);
  }
  const parsed = parseStrictJson(text, label);
  exactKeys(parsed, ["data", "type"], label);
  if (parsed.type !== "b" || typeof parsed.data !== "boolean") {
    fail(`${label} does not have one reviewed b value`);
  }
  return { signature: "b", value: parsed.data };
}

export function parseBusctlStringJsonV1(text, label = "systemd string property") {
  if (typeof text !== "string" || Buffer.byteLength(text, "utf8") > 4096) {
    fail(`${label} is not bounded busctl JSON`);
  }
  const parsed = parseStrictJson(text, label);
  exactKeys(parsed, ["data", "type"], label);
  if (
    parsed.type !== "s" ||
    typeof parsed.data !== "string" ||
    !/^[\x20-\x7e]{1,256}$/u.test(parsed.data)
  ) {
    fail(`${label} does not have one reviewed printable s value`);
  }
  return { signature: "s", value: parsed.data };
}

export function parseBusctlExecCommandExJsonV1(
  text,
  label = "systemd ExecCommandEx",
) {
  if (typeof text !== "string" || Buffer.byteLength(text, "utf8") > 256 * 1024) {
    fail(`${label} is not bounded busctl JSON`);
  }
  const parsed = parseStrictJson(text, label);
  exactKeys(parsed, ["data", "type"], label);
  if (
    parsed.type !== "a(sasasttttuii)" ||
    !Array.isArray(parsed.data) ||
    parsed.data.length > 64
  ) {
    fail(`${label} does not have the reviewed a(sasasttttuii) shape`);
  }
  return parsed.data.map((tuple, index) => {
    if (
      !Array.isArray(tuple) ||
      // a(sasasttttuii) is exactly: s, as, as, four t, one u and two i.
      tuple.length !== 10 ||
      typeof tuple[0] !== "string" ||
      !/^\/[A-Za-z0-9._/-]+$/u.test(tuple[0]) ||
      resolve(tuple[0]) !== tuple[0] ||
      !Array.isArray(tuple[1]) ||
      tuple[1].length < 1 ||
      tuple[1].length > 256 ||
      tuple[1][0] !== tuple[0] ||
      tuple[1].some((argument) =>
        typeof argument !== "string" ||
        argument.length < 1 ||
        argument.length > 4096 ||
        /[\0\r\n]/u.test(argument)) ||
      !Array.isArray(tuple[2]) ||
      tuple[2].some((flag) => flag !== "privileged") ||
      new Set(tuple[2]).size !== tuple[2].length ||
      tuple.slice(3).some((value) =>
        !Number.isSafeInteger(value) || value < 0)
    ) {
      fail(`${label}.data[${index}] is not one reviewed exec-command tuple`);
    }
    return {
      argv: tuple[1],
      flags: tuple[2],
      path: tuple[0],
    };
  });
}

export function parseBusctlExecStartPreExJsonV1(
  text,
  label = "systemd ExecStartPreEx",
) {
  return parseBusctlExecCommandExJsonV1(text, label);
}

function collectBusctlPropertyV1(unitName, interfaceName, property, parser) {
  const record = runAbsolute("/usr/bin/busctl", [
    "--json=short",
    "get-property",
    "org.freedesktop.systemd1",
    systemdUnitObjectPathV1(unitName),
    interfaceName,
    property,
  ]);
  if (record.exit_status !== 0 || record.stderr !== "") {
    fail(`busctl ${property} failed for ${unitName}`);
  }
  return parser(record.stdout, `${unitName}.${property}`);
}

function collectEffectiveConditions(unitName) {
  const propertyNames = effectiveBusctlPropertyNames();
  if (!propertyNames.includes("Conditions")) {
    fail("runtime busctl property set is not closed");
  }
  return collectBusctlPropertyV1(
    unitName,
    "org.freedesktop.systemd1.Unit",
    "Conditions",
    parseBusctlConditionsJsonV1,
  ).map((condition) => ({
    ...condition,
    path_exists: existsSync(condition.parameter),
  }));
}

function collectEffectiveUnitDependenciesV1(unitName) {
  const propertyNames = effectiveBusctlPropertyNames();
  const result = Object.create(null);
  for (const property of SYSTEMD_DEPENDENCY_PROPERTIES_V1) {
    if (!propertyNames.includes(property)) {
      fail("runtime busctl dependency property set is not closed");
    }
    result[property] = collectBusctlPropertyV1(
      unitName,
      "org.freedesktop.systemd1.Unit",
      property,
      parseBusctlUnitNamesJsonV1,
    );
  }
  return result;
}

function collectEffectiveServicePropertiesV1(unitName) {
  const propertyNames = effectiveBusctlServicePropertyNames();
  if (
    canonicalJson(propertyNames) !==
      canonicalJson(RUNTIME_BUSCTL_SERVICE_PROPERTIES)
  ) {
    fail("runtime busctl service property set is not closed");
  }
  return {
    ExecStartEx: collectBusctlPropertyV1(
      unitName,
      "org.freedesktop.systemd1.Service",
      "ExecStartEx",
      parseBusctlExecCommandExJsonV1,
    ),
    ExecStartPreEx: collectBusctlPropertyV1(
      unitName,
      "org.freedesktop.systemd1.Service",
      "ExecStartPreEx",
      parseBusctlExecCommandExJsonV1,
    ),
    TimeoutStopUSec: collectBusctlPropertyV1(
      unitName,
      "org.freedesktop.systemd1.Service",
      "TimeoutStopUSec",
      parseBusctlUnsignedJsonV1,
    ),
    WatchdogTimestampMonotonic: collectBusctlPropertyV1(
      unitName,
      "org.freedesktop.systemd1.Service",
      "WatchdogTimestampMonotonic",
      parseBusctlUnsignedJsonV1,
    ),
    WatchdogUSec: collectBusctlPropertyV1(
      unitName,
      "org.freedesktop.systemd1.Service",
      "WatchdogUSec",
      parseBusctlWatchdogUsecJsonV2,
    ),
  };
}

function collectEffectiveCredentialProperties(unitName) {
  const servicePropertyNames = effectiveBusctlServicePropertyNames();
  const credentialPropertyNames = Object.keys(
    EFFECTIVE_CREDENTIAL_PROPERTY_SIGNATURES,
  ).sort();
  const credentialProperties = Object.create(null);
  for (const property of credentialPropertyNames) {
    if (!servicePropertyNames.includes(property)) {
      fail("runtime busctl credential property set is not closed");
    }
    const record = runAbsolute(
      "/usr/bin/busctl",
      systemdCredentialBusctlArgvV1(unitName, property),
    );
    if (record.exit_status !== 0 || record.stderr !== "") {
      fail(`busctl credential property failed for ${unitName}.${property}`);
    }
    credentialProperties[property] = parseBusctlEmptyCredentialJsonV1(
      record.stdout,
      property,
      `${unitName}.${property}`,
    );
  }
  validateEffectiveCredentialProperties(unitName, credentialProperties);
  return credentialProperties;
}

function collectSystemdManagerPropertiesV1() {
  const properties = effectiveBusctlManagerPropertyNames();
  if (canonicalJson(properties) !== canonicalJson(["ServiceWatchdogs", "Version"])) {
    fail("runtime busctl manager property set is not closed");
  }
  const collect = (property, parse) => {
    const record = runAbsolute("/usr/bin/busctl", [
      "--system",
      "--json=short",
      "get-property",
      "org.freedesktop.systemd1",
      "/org/freedesktop/systemd1",
      "org.freedesktop.systemd1.Manager",
      property,
    ]);
    if (record.exit_status !== 0 || record.stderr !== "") {
      fail(`busctl ${property} failed for systemd manager`);
    }
    return parse(record.stdout, `systemd-manager.${property}`);
  };
  return {
    ServiceWatchdogs: collect("ServiceWatchdogs", parseBusctlBooleanJsonV1),
    Version: collect("Version", parseBusctlStringJsonV1),
  };
}

function validateEffectiveConditions(unit, conditions) {
  if (!Array.isArray(conditions)) fail(`effective conditions are missing: ${unit.unit_name}`);
  for (const [index, condition] of conditions.entries()) {
    exactKeys(
      condition,
      ["negate", "parameter", "path_exists", "result", "trigger", "type"],
      `${unit.unit_name}.conditions[${index}]`,
    );
  }
  if (canonicalJson(conditions) !== canonicalJson(expectedEffectiveConditions(unit))) {
    fail(`effective condition drift: ${unit.unit_name}`);
  }
}

function validateEffectiveUnitDependenciesV1(unit, dependencies) {
  exactKeys(
    dependencies,
    SYSTEMD_DEPENDENCY_PROPERTIES_V1,
    `${unit.unit_name}.unit_dependencies`,
  );
  exactKeys(
    unit.unit_dependencies,
    SYSTEMD_DEPENDENCY_PROPERTIES_V1,
    `${unit.unit_name}.rendered_unit_dependencies`,
  );
  for (const property of SYSTEMD_DEPENDENCY_PROPERTIES_V1) {
    const actual = validateCanonicalSystemdUnitNameSetV1(
      dependencies[property],
      `${unit.unit_name}.${property}`,
    );
    const expected = validateCanonicalSystemdUnitNameSetV1(
      unit.unit_dependencies[property],
      `${unit.unit_name}.rendered_${property}`,
    );
    if (expected.some((name) => !actual.includes(name))) {
      fail(`effective ${property} dependency drift: ${unit.unit_name}`);
    }
  }
}

function expectedTimeoutStopUsecV1(unit) {
  const values = unit.hardening.TimeoutStopSec;
  if (
    !Array.isArray(values) ||
    values.length !== 1 ||
    !/^[1-9][0-9]*$/u.test(values[0])
  ) {
    fail(`rendered TimeoutStopSec is not one positive integer: ${unit.unit_name}`);
  }
  const usec = BigInt(values[0]) * 1_000_000n;
  if (usec > UINT64_MAX) {
    fail(`rendered TimeoutStopSec is outside the reviewed range: ${unit.unit_name}`);
  }
  return usec.toString(10);
}

function validateReviewedTypedExecPolicyV2(unit) {
  const privilegedApprovalByUnit = new Map([
    [
      "bitcoinpir-cln-rpc-guard.service",
      {
        argv: [
          "/usr/bin/unlink",
          "--",
          "/run/bitcoinpir-lightning-operator-approvals/guard-generation-approved",
        ],
        flags: ["privileged"],
        path: "/usr/bin/unlink",
      },
    ],
    [
      "bitcoinpir-lightning-preflight.service",
      {
        argv: [
          "/usr/bin/unlink",
          "--",
          "/run/bitcoinpir-lightning-operator-approvals/preflight-generation-approved",
        ],
        flags: ["privileged"],
        path: "/usr/bin/unlink",
      },
    ],
  ]);
  for (const [typedKey, textKey] of [
    ["exec_start_ex", "exec_start"],
    ["exec_start_pre_ex", "exec_start_pre"],
  ]) {
    const typed = unit[typedKey];
    const text = unit[textKey];
    if (!Array.isArray(typed) || !Array.isArray(text) || typed.length !== text.length) {
      fail(`${unit.unit_name}.${typedKey} does not exactly cover ${textKey}`);
    }
    for (const [index, command] of typed.entries()) {
      exactKeys(command, ["argv", "flags", "path"], `${unit.unit_name}.${typedKey}[${index}]`);
      validateAbsolutePath(command.path, `${unit.unit_name}.${typedKey}[${index}].path`);
      if (
        !Array.isArray(command.argv) ||
        command.argv.length < 1 ||
        command.argv.length > 256 ||
        command.argv[0] !== command.path ||
        command.argv.some((argument) =>
          typeof argument !== "string" ||
          argument.length < 1 ||
          argument.length > 4096 ||
          /[\s\0\r\n]/u.test(argument)) ||
        !Array.isArray(command.flags) ||
        canonicalJson(command.argv.join(" ")) !== canonicalJson(text[index])
      ) {
        fail(`${unit.unit_name}.${typedKey}[${index}] is not a canonical approved command`);
      }
      const approvedPrivileged =
        typedKey === "exec_start_pre_ex" && index === 0
          ? privilegedApprovalByUnit.get(unit.unit_name)
          : undefined;
      if (
        canonicalJson(command.flags) !==
          canonicalJson(approvedPrivileged?.flags ?? []) ||
        (approvedPrivileged !== undefined &&
          canonicalJson(command) !== canonicalJson(approvedPrivileged))
      ) {
        fail(`${unit.unit_name}.${typedKey}[${index}] has unapproved exec flags`);
      }
    }
  }
}

function validateEffectiveServiceStaticPropertiesV2(unit, properties) {
  exactKeys(
    properties,
    [
      "ExecStartEx",
      "ExecStartPreEx",
      "TimeoutStopUSec",
      "WatchdogTimestampMonotonic",
      "WatchdogUSec",
    ],
    `${unit.unit_name}.service_properties`,
  );
  validateReviewedTypedExecPolicyV2(unit);
  if (canonicalJson(properties.ExecStartEx) !== canonicalJson(unit.exec_start_ex)) {
    fail(`effective ExecStartEx drift: ${unit.unit_name}`);
  }
  if (canonicalJson(properties.ExecStartPreEx) !== canonicalJson(unit.exec_start_pre_ex)) {
    fail(`effective ExecStartPreEx drift: ${unit.unit_name}`);
  }
  validateCanonicalUint64DecimalV1(
    properties.TimeoutStopUSec,
    `${unit.unit_name}.TimeoutStopUSec`,
  );
  validateCanonicalUint64DecimalV1(
    properties.WatchdogTimestampMonotonic,
    `${unit.unit_name}.WatchdogTimestampMonotonic`,
  );
  validateCanonicalUint64DecimalV1(
    properties.WatchdogUSec,
    `${unit.unit_name}.WatchdogUSec`,
  );
  if (properties.TimeoutStopUSec !== expectedTimeoutStopUsecV1(unit)) {
    fail(`effective TimeoutStopUSec drift: ${unit.unit_name}`);
  }
}

function validateEffectiveServicePropertiesV1(
  unit,
  properties,
  uptimeMilliseconds,
) {
  validateEffectiveServiceStaticPropertiesV2(unit, properties);
  const preflight = unit.unit_name === "bitcoinpir-lightning-preflight.service";
  const expectedWatchdogUsec = preflight ? "90000000" : "0";
  if (properties.WatchdogUSec !== expectedWatchdogUsec) {
    fail(`effective typed watchdog interval drift: ${unit.unit_name}`);
  }
  if (!preflight) {
    if (properties.WatchdogTimestampMonotonic !== "0") {
      fail(`effective typed watchdog is unreviewed: ${unit.unit_name}`);
    }
    return;
  }
  if (!Number.isSafeInteger(uptimeMilliseconds) || uptimeMilliseconds < 0) {
    fail(`watchdog freshness uptime is invalid: ${unit.unit_name}`);
  }
  const uptimeUsec = BigInt(uptimeMilliseconds) * 1000n;
  const timestamp = validateCanonicalUint64DecimalV1(
    properties.WatchdogTimestampMonotonic,
    `${unit.unit_name}.WatchdogTimestampMonotonic`,
  );
  const watchdogUsec = validateCanonicalUint64DecimalV1(
    properties.WatchdogUSec,
    `${unit.unit_name}.WatchdogUSec`,
  );
  if (
    timestamp === 0n ||
    timestamp > uptimeUsec ||
    uptimeUsec - timestamp >= watchdogUsec
  ) {
    fail(`effective watchdog timestamp is not fresh in this boot: ${unit.unit_name}`);
  }
}

function validateStoppedEffectiveServicePropertiesV2(unit, properties) {
  validateEffectiveServiceStaticPropertiesV2(unit, properties);
  if (properties.WatchdogUSec !== UINT64_MAX_DECIMAL) {
    fail(`stopped typed watchdog interval is not infinity: ${unit.unit_name}`);
  }
  if (properties.WatchdogTimestampMonotonic !== "0") {
    fail(`stopped typed watchdog timestamp is not zero: ${unit.unit_name}`);
  }
}

function validateSystemdManagerPropertiesV1(properties, label) {
  exactKeys(properties, ["ServiceWatchdogs", "Version"], label);
  exactKeys(properties.ServiceWatchdogs, ["signature", "value"], `${label}.ServiceWatchdogs`);
  if (
    properties.ServiceWatchdogs.signature !== "b" ||
    properties.ServiceWatchdogs.value !== true
  ) {
    fail(`${label}.ServiceWatchdogs must be typed b true`);
  }
  exactKeys(properties.Version, ["signature", "value"], `${label}.Version`);
  if (
    properties.Version.signature !== "s" ||
    properties.Version.value !== REVIEWED_SYSTEMD_MANAGER_VERSION
  ) {
    fail(
      `${label}.Version must be typed s ${REVIEWED_SYSTEMD_MANAGER_VERSION}`,
    );
  }
}

function validateSystemdManagerPassesV1(passes, label) {
  if (!Array.isArray(passes) || passes.length !== 2) {
    fail(`${label} property passes are incomplete`);
  }
  for (const [index, properties] of passes.entries()) {
    validateSystemdManagerPropertiesV1(properties, `${label} pass[${index}]`);
  }
}

export function assertEffectiveSystemdPolicySnapshotUnchangedV1(
  expectedDependencies,
  actualDependencies,
  expectedServiceProperties,
  actualServiceProperties,
  unitName = "systemd unit",
) {
  const expectedTimestamp = expectedServiceProperties?.WatchdogTimestampMonotonic;
  const actualTimestamp = actualServiceProperties?.WatchdogTimestampMonotonic;
  const expectedStatic = expectedServiceProperties === undefined ? undefined : {
    ...expectedServiceProperties,
    WatchdogTimestampMonotonic: "0",
  };
  const actualStatic = actualServiceProperties === undefined ? undefined : {
    ...actualServiceProperties,
    WatchdogTimestampMonotonic: "0",
  };
  const expectedTimestampValue = validateCanonicalUint64DecimalV1(
    expectedTimestamp,
    `${unitName}.expected WatchdogTimestampMonotonic`,
  );
  const actualTimestampValue = validateCanonicalUint64DecimalV1(
    actualTimestamp,
    `${unitName}.actual WatchdogTimestampMonotonic`,
  );
  if (
    canonicalJson(actualDependencies) !== canonicalJson(expectedDependencies) ||
    canonicalJson(actualStatic) !== canonicalJson(expectedStatic) ||
    actualTimestampValue < expectedTimestampValue
  ) {
    fail(`systemd dependency or service policy changed during live collection: ${unitName}`);
  }
  return true;
}

function validateStoppedEffectiveConditionsV2(unit, properties, conditions) {
  if (!Array.isArray(conditions)) {
    fail(`stopped effective conditions are missing: ${unit.unit_name}`);
  }
  const expected = expectedEffectiveConditions(unit);
  if (conditions.length !== expected.length) {
    fail(`stopped effective condition count drift: ${unit.unit_name}`);
  }
  let absentGlobalActivationSentinelObserved = false;
  let absentSelectionActivationSentinelObserved = false;
  for (let index = 0; index < expected.length; index += 1) {
    const actual = conditions[index];
    const definition = expected[index];
    exactKeys(
      actual,
      ["negate", "parameter", "path_exists", "result", "trigger", "type"],
      `${unit.unit_name}.stopped_conditions[${index}]`,
    );
    if (
      actual.negate !== definition.negate ||
      actual.parameter !== definition.parameter ||
      actual.trigger !== definition.trigger ||
      actual.type !== definition.type
    ) {
      fail(`stopped effective condition identity drift: ${unit.unit_name}`);
    }
    const conditionPassed = actual.negate !== actual.path_exists;
    if (actual.result !== -1 && actual.result !== (conditionPassed ? 1 : 0)) {
      fail(`stopped effective condition result is incoherent: ${unit.unit_name}`);
    }
    if (
      actual.parameter ===
      "/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED"
    ) {
      if (actual.negate || actual.path_exists || !new Set([-1, 0]).has(actual.result)) {
        fail(`stopped global activation sentinel is present: ${unit.unit_name}`);
      }
      absentGlobalActivationSentinelObserved = true;
    }
    if (
      actual.parameter ===
      "/etc/bitcoinpir/payment-v1/RELAY-SELECTION-RESOLVED"
    ) {
      if (actual.negate || actual.path_exists || !new Set([-1, 0]).has(actual.result)) {
        fail("stopped directory-relay selection activation sentinel is present");
      }
      absentSelectionActivationSentinelObserved = true;
    }
  }
  if (
    !absentGlobalActivationSentinelObserved ||
    (unit.unit_name === "bitcoinpir-directory-relay.service" &&
      !absentSelectionActivationSentinelObserved) ||
    properties.ConditionResult !== "no"
  ) {
    fail(`stopped effective conditions do not prove an inactive unit: ${unit.unit_name}`);
  }
}

export function assertEffectiveConditionSnapshotUnchangedV1(
  expected,
  actual,
  unitName = "systemd unit",
) {
  if (!Array.isArray(expected) || !Array.isArray(actual)) {
    fail(`${unitName} effective condition snapshots are incomplete`);
  }
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    fail(`systemd conditions changed during live collection: ${unitName}`);
  }
  return true;
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

function expectedEffectiveWords(key, values) {
  const words = expectedWords(values);
  if (key === "IPAddressAllow" && words.includes("localhost")) {
    return words
      .filter((word) => word !== "localhost")
      .concat(["127.0.0.0/8", "::1/128"])
      .sort();
  }
  if (key === "IPAddressDeny" && words.includes("any")) {
    return words
      .filter((word) => word !== "any")
      .concat(["0.0.0.0/0", "::/0"])
      .sort();
  }
  return words;
}

export function parseSystemctlExecArgvV1(value, label = "systemd Exec property") {
  if (value === "") return [];
  if (
    typeof value !== "string" ||
    Buffer.byteLength(value, "utf8") > 256 * 1024 ||
    /[\r\0]/u.test(value)
  ) {
    fail(`${label} has an unreviewed systemctl Exec serialization`);
  }
  const expectedFields = [
    "argv[]",
    "code",
    "ignore_errors",
    "path",
    "pid",
    "start_time",
    "status",
    "stop_time",
  ];
  const result = [];
  const recordPattern = /\{[^{}\r\n]*\}/gu;
  let cursor = 0;
  for (const match of value.matchAll(recordPattern)) {
    const separator = value.slice(cursor, match.index);
    if (
      (cursor === 0 && separator !== "") ||
      (cursor !== 0 && separator !== "\n")
    ) {
      fail(`${label} has an unreviewed systemctl Exec serialization`);
    }
    const serializedFields = match[0].slice(1, -1).split(";");
    const fields = {};
    for (const rawField of serializedFields) {
      const field = rawField.trim();
      const parsed = /^([A-Za-z][A-Za-z0-9_]*(?:\[\])?)=(.*)$/u.exec(field);
      if (parsed === null || !expectedFields.includes(parsed[1])) {
        fail(`${label} has an unknown systemctl Exec field`);
      }
      if (Object.hasOwn(fields, parsed[1])) {
        fail(`${label} repeats systemctl Exec field ${parsed[1]}`);
      }
      fields[parsed[1]] = parsed[2];
    }
    exactKeys(fields, expectedFields, `${label} systemctl Exec record`);

    const path = fields.path;
    const argv = fields["argv[]"];
    if (
      !/^\/[^\s;{}=]{0,4094}$/u.test(path) ||
      argv === "" ||
      argv.trim() !== argv ||
      /[;{}\r\n\0]/u.test(argv)
    ) {
      fail(`${label} has malformed systemctl Exec path or argv`);
    }
    const argv0 = /^(\S+)(?:\s|$)/u.exec(argv)?.[1];
    if (argv0 !== path) {
      fail(`${label} systemctl Exec path does not match argv[0]`);
    }
    if (fields.ignore_errors !== "no") {
      fail(`${label} permits systemctl Exec ignore_errors`);
    }
    for (const timeField of ["start_time", "stop_time"]) {
      if (!/^\[[^\[\]{};\r\n\0]{1,256}\]$/u.test(fields[timeField])) {
        fail(`${label} has malformed systemctl Exec ${timeField}`);
      }
    }
    if (!/^(?:0|[1-9][0-9]{0,19})$/u.test(fields.pid)) {
      fail(`${label} has malformed systemctl Exec pid`);
    }
    if (!new Set(["(null)", "dumped", "exited", "killed"]).has(fields.code)) {
      fail(`${label} has malformed systemctl Exec code`);
    }
    if (!/^(?:0|[1-9][0-9]{0,9})(?:\/(?:0|[1-9][0-9]{0,9}|[A-Z][A-Z0-9_-]{0,63}))?$/u.test(fields.status)) {
      fail(`${label} has malformed systemctl Exec status`);
    }
    result.push({
      argv,
      code: fields.code,
      ignore_errors: fields.ignore_errors,
      path,
      pid: fields.pid,
      start_time: fields.start_time,
      status: fields.status,
      stop_time: fields.stop_time,
    });
    cursor = match.index + match[0].length;
  }
  if (result.length === 0 || cursor !== value.length) {
    fail(`${label} has an unreviewed systemctl Exec serialization`);
  }
  return result;
}

function reviewedExecPolicy(commands, label) {
  if (!Array.isArray(commands)) fail(`${label} is not an argv list`);
  return commands.map((argv, index) => {
    if (
      typeof argv !== "string" ||
      argv === "" ||
      argv.trim() !== argv ||
      /[;{}\r\n\0]/u.test(argv)
    ) {
      fail(`${label}[${index}] is not a reviewed literal argv`);
    }
    const path = /^(\S+)(?:\s|$)/u.exec(argv)?.[1];
    if (!/^\/[^\s;{}=]{0,4094}$/u.test(path ?? "")) {
      fail(`${label}[${index}] has an unreviewed executable path`);
    }
    return { argv, ignore_errors: "no", path };
  });
}

function effectiveExecPolicy(records, label) {
  return records.map((record, index) => {
    const argv0 = /^(\S+)(?:\s|$)/u.exec(record.argv)?.[1];
    if (record.ignore_errors !== "no" || argv0 !== record.path) {
      fail(`${label}[${index}] has an unreviewed execution policy`);
    }
    return {
      argv: record.argv,
      ignore_errors: record.ignore_errors,
      path: record.path,
    };
  });
}

function validateSystemctlExecRuntimeMetadataV2(
  records,
  { active, kind, mainPid, label },
) {
  for (const [index, record] of records.entries()) {
    const recordLabel = `${label}[${index}]`;
    if (!active) {
      if (
        record.code !== "(null)" ||
        record.pid !== "0" ||
        record.start_time !== "[n/a]" ||
        record.stop_time !== "[n/a]" ||
        record.status !== "0/0"
      ) {
        fail(`${recordLabel} is not an unexecuted stopped command`);
      }
      continue;
    }
    if (kind === "start") {
      if (
        record.code !== "(null)" ||
        record.pid !== mainPid ||
        record.start_time === "[n/a]" ||
        record.stop_time !== "[n/a]" ||
        record.status !== "0/0"
      ) {
        fail(`${recordLabel} is not the reviewed running ExecStart`);
      }
      continue;
    }
    if (kind === "completed-oneshot-start") {
      if (
        record.code !== "exited" ||
        !/^[1-9][0-9]{0,19}$/u.test(record.pid) ||
        record.start_time === "[n/a]" ||
        record.stop_time === "[n/a]" ||
        record.status !== "0"
      ) {
        fail(`${recordLabel} is not the reviewed successful completed oneshot ExecStart`);
      }
      continue;
    }
    if (
      record.code !== "exited" ||
      !/^[1-9][0-9]{0,19}$/u.test(record.pid) ||
      record.start_time === "[n/a]" ||
      record.stop_time === "[n/a]" ||
      record.status !== "0"
    ) {
      fail(`${recordLabel} is not a successful completed ExecStartPre`);
    }
  }
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

function isReviewedDirectoryPublisherOneshotV1(unit, deploymentProfile) {
  return (
    deploymentProfile === "directory-publisher-netns-v1" &&
    unit?.unit_name === "bitcoinpir-payment-v1-directory-publisher.service" &&
    unit?.fragment_path ===
      "/etc/systemd/system/bitcoinpir-payment-v1-directory-publisher.service" &&
    canonicalJson(unit?.hardening?.Type) === canonicalJson(["oneshot"]) &&
    canonicalJson(unit?.hardening?.RemainAfterExit) === canonicalJson(["true"])
  );
}

function validateUnitLifecycle(
  unit,
  properties,
  uptimeFinishedMilliseconds,
  deploymentProfile,
) {
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
  if (isReviewedDirectoryPublisherOneshotV1(unit, deploymentProfile)) {
    if (
      properties.Type !== "oneshot" ||
      properties.RemainAfterExit !== "yes" ||
      mainPid !== 0 ||
      properties.ControlGroup !== "" ||
      properties.SubState !== "exited" ||
      properties.Result !== "success" ||
      properties.ExecMainCode !== "1" ||
      properties.ExecMainStatus !== "0" ||
      properties.NeedDaemonReload !== "no"
    ) {
      fail(`directory publisher is not one successful retained oneshot generation: ${unit.unit_name}`);
    }
    return { kind: "completed-oneshot", mainPid: 0 };
  }
  if (properties.ControlGroup !== expectedSystemUnitControlGroup(unit.unit_name)) {
    fail(`unit is outside its reviewed system.slice control group: ${unit.unit_name}`);
  }
  if (!["simple", "notify"].includes(properties.Type)) {
    fail(`unit has an unreviewed long-running Type: ${unit.unit_name}`);
  }
  if (mainPid === 0 || properties.SubState !== "running") {
    fail(`long-running unit has no active MainPID: ${unit.unit_name}`);
  }
  return { kind: "long-running", mainPid };
}

function validateEffectiveUnitStaticProperties(
  unit,
  properties,
  credentialProperties,
  deploymentProfile,
) {
  exactKeys(properties, effectivePropertyNames(), `effective properties for ${unit.unit_name}`);
  validateEffectiveCredentialProperties(unit.unit_name, credentialProperties);
  if (properties.FragmentPath !== unit.fragment_path) fail(`FragmentPath drift: ${unit.unit_name}`);
  if (properties.DropInPaths !== "") fail(`systemd drop-ins are forbidden: ${unit.unit_name}`);
  if (properties.LoadState !== "loaded") fail(`unit is not loaded: ${unit.unit_name}`);
  for (const forbidden of [
    "ExecStartPost",
    "ExecCondition",
    "EnvironmentFiles",
    "RootDirectory",
    "RootImage",
    "BindPaths",
  ]) {
    if (properties[forbidden] !== "") fail(`effective ${forbidden} is forbidden: ${unit.unit_name}`);
  }
  const isPublisher =
    unit.unit_name === "bitcoinpir-payment-v1-directory-publisher.service" &&
    unit.fragment_path ===
      "/etc/systemd/system/bitcoinpir-payment-v1-directory-publisher.service";
  if (!isPublisher) {
    if (properties.BindReadOnlyPaths !== "") {
      fail(`effective BindReadOnlyPaths is forbidden: ${unit.unit_name}`);
    }
  } else {
    const expected = [
      "/etc/netns/bpir-directory-publisher/hosts:/etc/hosts",
      "/etc/netns/bpir-directory-publisher/nsswitch.conf:/etc/nsswitch.conf",
      "/etc/netns/bpir-directory-publisher/resolv.conf:/etc/resolv.conf",
    ];
    const actual = splitLiteralWords(properties.BindReadOnlyPaths).map((value) =>
      value.endsWith(":rbind") ? value.slice(0, -6) : value);
    if (canonicalJson(actual) !== canonicalJson(expected)) {
      fail(`effective BindReadOnlyPaths drift: ${unit.unit_name}`);
    }
  }
  const parsedStart = parseSystemctlExecArgvV1(
    properties.ExecStart,
    `${unit.unit_name}.ExecStart`,
  );
  const parsedPre = parseSystemctlExecArgvV1(
    properties.ExecStartPre,
    `${unit.unit_name}.ExecStartPre`,
  );
  const active = properties.ActiveState === "active";
  const completedPublisherOneshot =
    active && isReviewedDirectoryPublisherOneshotV1(unit, deploymentProfile);
  validateSystemctlExecRuntimeMetadataV2(parsedStart, {
    active,
    kind: completedPublisherOneshot ? "completed-oneshot-start" : "start",
    label: `${unit.unit_name}.ExecStart`,
    mainPid: properties.MainPID,
  });
  validateSystemctlExecRuntimeMetadataV2(parsedPre, {
    active,
    kind: "pre",
    label: `${unit.unit_name}.ExecStartPre`,
    mainPid: properties.MainPID,
  });
  const actualStart = effectiveExecPolicy(
    parsedStart,
    `${unit.unit_name}.ExecStart`,
  );
  const actualPre = effectiveExecPolicy(
    parsedPre,
    `${unit.unit_name}.ExecStartPre`,
  );
  const approvedStart = reviewedExecPolicy(unit.exec_start, `${unit.unit_name}.exec_start`);
  const approvedPre = reviewedExecPolicy(unit.exec_start_pre, `${unit.unit_name}.exec_start_pre`);
  if (canonicalJson(actualStart) !== canonicalJson(approvedStart)) fail(`effective ExecStart drift: ${unit.unit_name}`);
  if (canonicalJson(actualPre) !== canonicalJson(approvedPre)) fail(`effective ExecStartPre drift: ${unit.unit_name}`);
  if (canonicalJson(splitLiteralWords(properties.Environment)) !== canonicalJson([...unit.environment].sort())) {
    fail(`effective Environment drift: ${unit.unit_name}`);
  }
  if (properties.NeedDaemonReload !== "no") {
    fail(`effective NeedDaemonReload drift: ${unit.unit_name}`);
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
    if (
      canonicalJson(splitLiteralWords(properties[key])) !==
      canonicalJson(expectedEffectiveWords(key, expected))
    ) {
      fail(`effective ${key} drift: ${unit.unit_name}`);
    }
  }
  const watchdog = unit.hardening.WatchdogSec;
  if (!new Set(["active", "inactive"]).has(properties.ActiveState)) {
    fail(`effective watchdog lifecycle is unreviewed: ${unit.unit_name}`);
  }
  if (properties.ActiveState === "inactive") {
    if (properties.WatchdogUSec !== "infinity") {
      fail(`stopped scalar watchdog interval is not infinity: ${unit.unit_name}`);
    }
  } else if (watchdog === undefined) {
    if (properties.WatchdogUSec !== "0") {
      fail(`live scalar watchdog interval is not zero: ${unit.unit_name}`);
    }
  } else if (
    canonicalJson(watchdog) !== canonicalJson(["90"]) ||
    properties.WatchdogUSec !== "1min 30s"
  ) {
    fail(`effective watchdog lease drift: ${unit.unit_name}`);
  }
  if (unit.hardening.LimitCORE !== undefined && properties.LimitCORESoft !== "0") {
    fail(`effective LimitCORESoft drift: ${unit.unit_name}`);
  }
  if (
    unit.hardening.LimitNOFILE !== undefined &&
    properties.LimitNOFILESoft !== unit.hardening.LimitNOFILE[0]
  ) {
    fail(`effective LimitNOFILESoft drift: ${unit.unit_name}`);
  }
  return true;
}

function validateEffectiveUnitProperties(
  unit,
  properties,
  credentialProperties,
  conditions,
  unitDependencies,
  serviceProperties,
  uptimeFinishedMilliseconds,
  deploymentProfile,
) {
  validateEffectiveUnitStaticProperties(
    unit,
    properties,
    credentialProperties,
    deploymentProfile,
  );
  validateEffectiveConditions(unit, conditions);
  validateEffectiveUnitDependenciesV1(unit, unitDependencies);
  validateEffectiveServicePropertiesV1(unit, serviceProperties, uptimeFinishedMilliseconds);
  if (
    unit.hardening.MemorySwapMax !== undefined &&
    properties.MemorySwapCurrent !== "0"
  ) {
    fail(`effective MemorySwapCurrent drift: ${unit.unit_name}`);
  }
  return validateUnitLifecycle(
    unit,
    properties,
    uptimeFinishedMilliseconds,
    deploymentProfile,
  );
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
    credential_properties: collectEffectiveCredentialProperties(unit.unit_name),
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

function collectStoppedUnitConfiguration(unit) {
  const conditions = collectEffectiveConditions(unit.unit_name);
  const credentialProperties = collectEffectiveCredentialProperties(unit.unit_name);
  const serviceProperties = collectEffectiveServicePropertiesV1(unit.unit_name);
  const properties = Object.create(null);
  for (const property of effectivePropertyNames()) {
    properties[property] = collectSystemctlValue(unit.unit_name, property);
  }
  validateEffectiveUnitStaticProperties(unit, properties, credentialProperties);
  validateStoppedEffectiveConditionsV2(unit, properties, conditions);
  validateStoppedEffectiveServicePropertiesV2(unit, serviceProperties);
  if (
    properties.ActiveState !== "inactive" ||
    properties.SubState !== "dead" ||
    properties.MainPID !== "0" ||
    properties.ControlGroup !== "" ||
    !new Set(["", "0".repeat(32)]).has(properties.InvocationID)
  ) {
    fail(`stopped unit effective configuration is not inactive: ${unit.unit_name}`);
  }
  if (
    unit.hardening.MemorySwapMax !== undefined &&
    properties.MemorySwapCurrent !== "[not set]"
  ) {
    fail(`stopped unit has an unreviewed MemorySwapCurrent value: ${unit.unit_name}`);
  }
  const fragmentBytes = readOneLinkRegular(
    unit.fragment_path,
    `stopped systemd fragment ${unit.unit_name}`,
    2 * 1024 * 1024,
  );
  const confirmedCredentialProperties = collectEffectiveCredentialProperties(
    unit.unit_name,
  );
  assertEffectiveCredentialSnapshotUnchangedV1(
    credentialProperties,
    confirmedCredentialProperties,
    unit.unit_name,
  );
  const confirmedConditions = collectEffectiveConditions(unit.unit_name);
  assertEffectiveConditionSnapshotUnchangedV1(
    conditions,
    confirmedConditions,
    unit.unit_name,
  );
  return {
    conditions,
    credential_properties: credentialProperties,
    fragment_sha256: hashBytes(fragmentBytes),
    properties,
    service_properties: serviceProperties,
    unit_name: unit.unit_name,
  };
}

function collectStoppedUnitConfigurations(request) {
  return request.units.map(collectStoppedUnitConfiguration);
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

function collectUnit(unit, nss, serviceIdentities, deploymentProfile) {
  const conditions = collectEffectiveConditions(unit.unit_name);
  const credentialProperties = collectEffectiveCredentialProperties(unit.unit_name);
  const unitDependencies = collectEffectiveUnitDependenciesV1(unit.unit_name);
  const serviceProperties = collectEffectiveServicePropertiesV1(unit.unit_name);
  const servicePropertiesUptimeMilliseconds = readLinuxUptimeMillisecondsV1();
  const properties = Object.create(null);
  for (const property of effectivePropertyNames()) {
    properties[property] = collectSystemctlValue(unit.unit_name, property);
  }
  const lifecycle = validateEffectiveUnitProperties(
    unit,
    properties,
    credentialProperties,
    conditions,
    unitDependencies,
    serviceProperties,
    servicePropertiesUptimeMilliseconds,
    deploymentProfile,
  );
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
  const confirmedCredentialProperties = collectEffectiveCredentialProperties(
    unit.unit_name,
  );
  assertEffectiveCredentialSnapshotUnchangedV1(
    credentialProperties,
    confirmedCredentialProperties,
    unit.unit_name,
  );
  const confirmedConditions = collectEffectiveConditions(unit.unit_name);
  assertEffectiveConditionSnapshotUnchangedV1(
    conditions,
    confirmedConditions,
    unit.unit_name,
  );
  const fragmentBytes = readOneLinkRegular(unit.fragment_path, `systemd fragment ${unit.unit_name}`, 2 * 1024 * 1024);
  return {
    conditions,
    credential_properties: credentialProperties,
    fragment_sha256: hashBytes(fragmentBytes),
    generation_confirmations: generationConfirmations,
    process_identity: processIdentity,
    properties,
    service_property_passes: [{
      observed_uptime_milliseconds: servicePropertiesUptimeMilliseconds,
      properties: serviceProperties,
    }],
    unit_dependencies: unitDependencies,
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

function readLinuxUptimeMillisecondsV1() {
  const uptimeText = readFileSync("/proc/uptime", "utf8").trim().split(/\s+/u)[0];
  const uptimeMilliseconds = Math.floor(Number(uptimeText) * 1000);
  if (!Number.isSafeInteger(uptimeMilliseconds) || uptimeMilliseconds < 0) {
    fail("Linux uptime is malformed");
  }
  return uptimeMilliseconds;
}

function readHostBinding() {
  const bootId = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
  validateUuid(bootId, "Linux boot id");
  const corePattern = readFileSync("/proc/sys/kernel/core_pattern", "utf8").trim();
  if (corePattern === "" || /[\r\n\0]/u.test(corePattern)) {
    fail("Linux core_pattern is malformed");
  }
  const machineId = readFileSync("/etc/machine-id");
  const uptimeMilliseconds = readLinuxUptimeMillisecondsV1();
  const kernel = runAbsolute("/usr/bin/uname", ["-r"]);
  const systemd = runAbsolute("/usr/bin/systemctl", ["--version"]);
  if (kernel.exit_status !== 0 || kernel.stderr !== "" || systemd.exit_status !== 0 || systemd.stderr !== "") {
    fail("host version collection failed");
  }
  const systemdVersion = systemd.stdout.split("\n", 1)[0];
  if (systemdVersion !== REVIEWED_SYSTEMD_VERSION) {
    fail("host systemd build is not the reviewed exact version");
  }
  const pidNamespace = readPidNamespaceBinding();
  return {
    boot_id: bootId,
    core_pattern: corePattern,
    kernel_release: kernel.stdout.trim(),
    machine_id_sha256: hashBytes(machineId),
    ...pidNamespace,
    systemd_version: systemdVersion,
    uptime_milliseconds: uptimeMilliseconds,
  };
}

function validateGenerationConfirmations(
  confirmations,
  properties,
  unitName,
  expectedCount = 3,
) {
  if (!Array.isArray(confirmations) || confirmations.length !== expectedCount) {
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
  if (lifecycle?.kind === "completed-oneshot") {
    if (processIdentity !== null) {
      fail(`completed oneshot unexpectedly retains process identity evidence: ${unitName}`);
    }
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
    nss.enumeration_kind !== NSS_ENUMERATION_KIND
  ) {
    fail("stopped-edge NSS evidence is not the reviewed files-authoritative profile");
  }
  assertReviewedNssSources(nss.sources, "stopped-edge NSS sources");
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
          "credential_properties",
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
      validateEffectiveCredentialProperties(
        expected.unit_name,
        state.credential_properties,
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

function validateStoppedInstalledFileSet(files, request, label) {
  if (!Array.isArray(files) || files.length !== request.installed_files.length) {
    fail(`${label} installed-file evidence is incomplete`);
  }
  for (let index = 0; index < request.installed_files.length; index += 1) {
    const expected = request.installed_files[index];
    const actual = files[index];
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
      `${label} installed_files[${index}]`,
    );
    for (const key of ["file_type", "gid", "mode", "nlink", "sha256", "target_path", "uid"]) {
      if (actual[key] !== expected[key]) {
        fail(`${label} installed-file ${key} drift: ${expected.target_path}`);
      }
    }
    for (const key of [
      "acl_sha256",
      "capability_sha256",
      "sha256_command_sha256",
      "stat_command_sha256",
      "xattr_sha256",
    ]) {
      validateDigest(actual[key], `${label} installed-file ${key}`);
    }
  }
}

function validateStoppedInstalledFilePasses(passes, request) {
  if (!Array.isArray(passes) || passes.length !== 2) {
    fail("stopped directory-relay installed-file evidence requires two complete passes");
  }
  for (const [index, pass] of passes.entries()) {
    validateStoppedInstalledFileSet(pass, request, `stopped directory-relay pass[${index}]`);
  }
  if (canonicalJson(passes[0]) !== canonicalJson(passes[1])) {
    fail("stopped directory-relay installed files changed during collection");
  }
}

function validateStoppedUnitConfigurationPasses(passes, request) {
  if (!Array.isArray(passes) || passes.length !== 2) {
    fail("stopped directory-relay effective-unit evidence requires two complete passes");
  }
  for (const [passIndex, pass] of passes.entries()) {
    if (!Array.isArray(pass) || pass.length !== request.units.length) {
      fail(`stopped directory-relay effective-unit pass[${passIndex}] is incomplete`);
    }
    for (const [index, actual] of pass.entries()) {
      const expected = request.units[index];
      exactKeys(
        actual,
        [
          "conditions",
          "credential_properties",
          "fragment_sha256",
          "properties",
          "service_properties",
          "unit_name",
        ],
        `stopped directory-relay effective-unit pass[${passIndex}][${index}]`,
      );
      const fragment = request.installed_files.find(
        (file) => file.target_path === expected.fragment_path,
      );
      if (
        actual.unit_name !== expected.unit_name ||
        fragment === undefined ||
        actual.fragment_sha256 !== fragment.sha256
      ) {
        fail(`stopped directory-relay fragment binding drift: ${expected.unit_name}`);
      }
      validateEffectiveUnitStaticProperties(
        expected,
        actual.properties,
        actual.credential_properties,
      );
      validateStoppedEffectiveConditionsV2(
        expected,
        actual.properties,
        actual.conditions,
      );
      validateStoppedEffectiveServicePropertiesV2(
        expected,
        actual.service_properties,
      );
      if (
        actual.properties.ActiveState !== "inactive" ||
        actual.properties.SubState !== "dead" ||
        actual.properties.MainPID !== "0" ||
        actual.properties.ControlGroup !== "" ||
        !new Set(["", "0".repeat(32)]).has(actual.properties.InvocationID)
      ) {
        fail(`stopped directory-relay effective unit is not inactive: ${expected.unit_name}`);
      }
      if (
        expected.hardening.MemorySwapMax !== undefined &&
        actual.properties.MemorySwapCurrent !== "[not set]"
      ) {
        fail(`stopped directory-relay has an unreviewed MemorySwapCurrent value: ${expected.unit_name}`);
      }
    }
  }
  if (canonicalJson(passes[0]) !== canonicalJson(passes[1])) {
    fail("stopped directory-relay effective unit changed during collection");
  }
}

function validateStoppedPrivateLoaderEvidenceV2(evidence, request) {
  const expectedParentPaths = secretParentPaths(request.secret_files);
  if (
    !Array.isArray(evidence.secret_parent_directories) ||
    evidence.secret_parent_directories.length !== expectedParentPaths.length
  ) {
    fail("stopped private-loader parent directory evidence is incomplete");
  }
  for (let index = 0; index < expectedParentPaths.length; index += 1) {
    const actual = evidence.secret_parent_directories[index];
    const expectedPath = expectedParentPaths[index];
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
      `stopped private-loader parent[${index}]`,
    );
    if (
      actual.target_path !== expectedPath ||
      actual.file_type !== "directory" ||
      actual.expected_type !== "directory"
    ) {
      fail(`stopped private-loader parent path/type drift: ${expectedPath}`);
    }
    validateSecretParentDirectoryEvidenceMetadata(actual, expectedPath);
    for (const key of [
      "acl_sha256",
      "capability_sha256",
      "stat_command_sha256",
      "xattr_sha256",
    ]) {
      validateDigest(actual[key], `stopped private-loader parent ${key}`);
    }
  }
  validateSecretParentDirectoryPolicyV1(
    request.secret_files,
    request.service_identities,
    evidence.secret_parent_directories,
  );

  const expectedAccessCount =
    request.secret_files.length * request.service_identities.length;
  if (
    !Array.isArray(evidence.secret_access_checks) ||
    evidence.secret_access_checks.length !== expectedAccessCount
  ) {
    fail("stopped private-loader access probes are incomplete");
  }
  let accessIndex = 0;
  for (const secret of request.secret_files) {
    for (const identity of request.service_identities) {
      const unit = request.units.find(
        (entry) => entry.unit_name === identity.unit_name,
      );
      const expectedIdentity = resolveExpectedUnitProcessIdentity(
        unit,
        evidence.nss,
        request.service_identities,
      );
      const expectedReadable = identity.unit_name === secret.consumer_unit_name;
      const actual = evidence.secret_access_checks[accessIndex];
      exactKeys(
        actual,
        [
          "argv",
          "exit_status",
          "expected_readable",
          "stderr",
          "stdout",
          "target_path",
          "unit_name",
        ],
        `stopped private-loader access[${accessIndex}]`,
      );
      if (
        actual.unit_name !== identity.unit_name ||
        actual.target_path !== secret.target_path ||
        actual.expected_readable !== expectedReadable ||
        actual.exit_status !== (expectedReadable ? 0 : 1) ||
        actual.stdout !== "" ||
        actual.stderr !== "" ||
        canonicalJson(actual.argv) !==
          canonicalJson(secretProbeArgv(expectedIdentity, secret.target_path))
      ) {
        fail(
          `stopped private-loader access isolation failed: ${identity.unit_name} -> ${secret.target_path}`,
        );
      }
      accessIndex += 1;
    }
  }
}

function validateSystemdAnalyzeEvidence(evidence, request, label) {
  exactKeys(evidence, ["argv", "exit_status", "stderr", "stdout"], `${label} systemd-analyze`);
  if (
    evidence.exit_status !== 0 ||
    evidence.stdout !== "" ||
    evidence.stderr !== "" ||
    canonicalJson(evidence.argv) !== canonicalJson(request.systemd_analyze_argv)
  ) {
    fail(`${label} systemd-analyze verify evidence failed`);
  }
}

function validateRuntimeSocketAbsencePasses(passes, request, { allowEmpty = false } = {}) {
  const expectedPaths = request.runtime_paths
    .filter((entry) => entry.file_type === "socket")
    .map((entry) => entry.target_path)
    .sort();
  if ((!allowEmpty && expectedPaths.length < 1) || !Array.isArray(passes) || passes.length !== 2) {
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

function validateStoppedHost(
  host,
  request,
  expectedMachineIdSha256,
  expectedBootId,
  expectedProfile = "edge-hetzner-v1",
) {
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
    request.deployment_profile !== expectedProfile ||
    host.systemd_version !== request.systemd_version ||
    host.core_pattern !== "|/usr/bin/false"
  ) {
    fail("stopped-edge host, boot, PID namespace, or core policy is not approved");
  }
}

function validateTrustedCommandClosure(commands, label, request) {
  const required = requiredCommandsForRequest(request);
  if (!Array.isArray(commands) || commands.length !== required.length + 1) {
    fail(`${label} does not bind the complete command TCB`);
  }
  for (const command of commands) {
    exactKeys(
      command,
      [
        "ctime_ns", "dev", "gid", "ino", "mode", "mtime_ns", "nlink",
        "path", "sha256", "size", "uid",
      ],
      `${label} command`,
    );
    validateAbsolutePath(command.path, `${label} command path`);
    validateDigest(command.sha256, `${label} command digest`);
    if (
      typeof command.dev !== "string" || !/^(?:0|[1-9][0-9]*)$/u.test(command.dev) ||
      typeof command.ino !== "string" || !/^[1-9][0-9]*$/u.test(command.ino) ||
      typeof command.ctime_ns !== "string" || !/^(?:0|[1-9][0-9]*)$/u.test(command.ctime_ns) ||
      typeof command.mtime_ns !== "string" || !/^(?:0|[1-9][0-9]*)$/u.test(command.mtime_ns) ||
      !Number.isSafeInteger(command.gid) || command.gid < 0 || command.gid > 0xffff_ffff ||
      !Number.isSafeInteger(command.size) || command.size < 1 || command.size > MAX_COMMAND_BYTES ||
      command.uid !== 0 ||
      command.nlink !== 1 ||
      !/^[0-7]{4}$/u.test(command.mode) ||
      (Number.parseInt(command.mode, 8) & 0o022) !== 0 ||
      (Number.parseInt(command.mode, 8) & 0o111) === 0
    ) {
      fail(`${label} has untrusted runtime command metadata: ${command.path}`);
    }
  }
  if (
    canonicalJson(commands.map((entry) => entry.path).sort()) !==
    canonicalJson([...required, "/usr/bin/node"].sort())
  ) {
    fail(`${label} command TCB paths are not closed`);
  }
}

function validateRuntimeServiceIdentityIds(serviceIdentities, label) {
  if (!Array.isArray(serviceIdentities) || serviceIdentities.length < 1) {
    fail(`${label} service identity bindings are missing`);
  }
  for (const [index, identity] of serviceIdentities.entries()) {
    validateServiceIdentityId(identity?.uid, `${label} service identity[${index}].uid`);
    validateServiceIdentityId(identity?.gid, `${label} service identity[${index}].gid`);
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
      "systemd_manager_passes",
      "trusted_commands",
      "unit_configuration_passes",
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
  validateRuntimePropertyRequestSchema(request, "stopped-edge request");
  validateRuntimeServiceIdentityIds(request.service_identities, "stopped-edge request");
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
  validateTrustedCommandClosure(evidence.trusted_commands, "stopped-edge evidence", request);
  const expectedProtected = validateStoppedNssEvidence(evidence.nss, request);
  validateStoppedAccountPolicy(evidence.account_policy, request, evidence.nss);
  validateSystemdManagerPassesV1(
    evidence.systemd_manager_passes,
    "stopped-edge systemd manager",
  );
  validateStoppedUnitPasses(evidence.stopped_unit_passes, request);
  validateStoppedUnitConfigurationPasses(evidence.unit_configuration_passes, request);
  validateRuntimeSocketAbsencePasses(evidence.runtime_socket_absence_passes, request);
  validateStoppedProtectedClosure(evidence.protected_process_closure, expectedProtected);
  return true;
}

export function validateStoppedRelayPreparationEvidence({
  evidence,
  request,
  expectedMachineIdSha256,
  expectedBootId,
  nowUnixSeconds,
  maxAgeSeconds = 120,
}) {
  validateRuntimePropertyRequestSchema(
    request,
    "stopped directory-relay request",
  );
  validateRuntimeServiceIdentityIds(
    request.service_identities,
    "stopped directory-relay request",
  );
  const relayUnit = request.units?.[0];
  const relayIdentity = request.service_identities?.[0];
  const relayConfigPath = "/etc/bitcoinpir/payment-v1/directory-relay/config.toml";
  const relayFragmentPath = "/etc/systemd/system/bitcoinpir-directory-relay.service";
  const relayBinaryManifestPath =
    "/etc/bitcoinpir/payment-v1/directory-relay/binary.sha256";
  const relayConfigManifestPath =
    "/etc/bitcoinpir/payment-v1/directory-relay/config.sha256";
  const relayInstalledTargets = request.installed_files?.map((file) => file.target_path);
  const resolvedRelay = isResolvedDirectoryRelayRuntimeRequest(request);
  const blockedRelay =
    canonicalJson(relayUnit?.exec_start) === canonicalJson(["/usr/bin/false"]) &&
    canonicalJson(relayUnit?.exec_start_pre) === canonicalJson([]);
  const relayBinaryPath = resolvedRelay
    ? relayUnit.exec_start[0].split(" ", 1)[0]
    : undefined;
  const expectedInstalledTargets = resolvedRelay
    ? [
        relayBinaryManifestPath,
        relayConfigManifestPath,
        relayConfigPath,
        relayFragmentPath,
        relayBinaryPath,
      ]
    : [relayConfigPath, relayFragmentPath];
  const expectedInstalledMetadata = new Map([
    [relayConfigPath, { gid: 52952, mode: "0400", uid: 52951 }],
    [relayFragmentPath, { gid: 0, mode: "0644", uid: 0 }],
    ...(resolvedRelay
      ? [
          [relayBinaryManifestPath, { gid: 0, mode: "0444", uid: 0 }],
          [relayConfigManifestPath, { gid: 0, mode: "0444", uid: 0 }],
          [relayBinaryPath, { gid: 0, mode: "0555", uid: 0 }],
        ]
      : []),
  ]);
  const installedShapeMatches =
    canonicalJson(relayInstalledTargets) === canonicalJson(expectedInstalledTargets) &&
    request.installed_files?.every((file) => {
      const expected = expectedInstalledMetadata.get(file.target_path);
      return (
        expected !== undefined &&
        file.file_type === "regular" &&
        file.uid === expected.uid &&
        file.gid === expected.gid &&
        file.mode === expected.mode &&
        file.nlink === 1
      );
    });
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
      "installed_file_passes",
      "manifest_sha256",
      "nss",
      "protected_process_closure",
      "runtime_socket_absence_passes",
      "schema_version",
      "secret_access_checks",
      "secret_parent_directories",
      "stopped_unit_passes",
      "systemd_analyze_verify",
      "systemd_manager_passes",
      "trusted_commands",
      "unit_configuration_passes",
    ],
    "stopped directory-relay preparation evidence",
  );
  if (
    evidence.schema_version !== STOPPED_RELAY_SCHEMA_VERSION ||
    evidence.evidence_kind !== STOPPED_RELAY_EVIDENCE_KIND ||
    evidence.collector !== RUNTIME_COLLECTOR ||
    request.schema_version !== LIVE_SCHEMA_VERSION ||
    request.collector !== RUNTIME_COLLECTOR ||
    request.deployment_profile !== "directory-relay-v1" ||
    evidence.manifest_sha256 !== request.manifest_sha256 ||
    evidence.approved_plan_sha256 !== request.approved_plan_sha256 ||
    request.units.length !== 1 ||
    request.service_identities.length !== 1 ||
    relayUnit.unit_name !== "bitcoinpir-directory-relay.service" ||
    relayUnit.fragment_path !== relayFragmentPath ||
    relayIdentity.unit_name !== relayUnit.unit_name ||
    relayIdentity.uid !== 52951 ||
    relayIdentity.gid !== 52952 ||
    (!blockedRelay && !resolvedRelay) ||
    canonicalJson(relayUnit.conditions) !== canonicalJson([
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/RELAY-ACTIVATION-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/RELAY-SELECTION-RESOLVED",
    ]) ||
    !installedShapeMatches ||
    canonicalJson(request.systemd_analyze_argv) !== canonicalJson([
      "/usr/bin/systemd-analyze",
      "verify",
      relayFragmentPath,
    ]) ||
    request.runtime_paths.length !== 0 ||
    request.secret_files.length !== 1 ||
    request.secret_files[0].consumer_unit_name !== relayUnit.unit_name ||
    request.secret_files[0].target_path !== relayConfigPath ||
    request.secret_files[0].uid !== relayIdentity.uid ||
    request.secret_files[0].gid !== relayIdentity.gid ||
    request.secret_files[0].mode !== "0400" ||
    request.tmpfiles_directories.length !== 0
  ) {
    fail("stopped directory-relay evidence schema, collector, profile, or unit binding is not reviewed");
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
    ["ProtectProc", "invisible"],
    ["ProcSubset", "pid"],
    ["Restart", resolvedRelay ? "on-failure" : "no"],
  ]) {
    if (canonicalJson(relayUnit.hardening[key] ?? []) !== canonicalJson([expected])) {
      fail(`stopped directory-relay request hardening drift: ${key}`);
    }
  }
  if (
    resolvedRelay &&
    (
      canonicalJson(relayUnit.hardening.RestartSec ?? []) !== canonicalJson(["5"]) ||
      canonicalJson(relayUnit.hardening.ReadOnlyPaths ?? []) !== canonicalJson([
        `/etc/bitcoinpir/payment-v1/directory-relay ${dirname(relayBinaryPath)}`,
      ])
    )
  ) {
    fail("stopped resolved directory-relay request hardening drift");
  }
  if (!resolvedRelay && relayUnit.hardening.RestartSec !== undefined) {
    fail("stopped blocked directory-relay request must not configure RestartSec");
  }
  if (
    typeof evidence.challenge_hex !== "string" ||
    !/^[0-9a-f]{64}$/u.test(evidence.challenge_hex) ||
    /^0{64}$/u.test(evidence.challenge_hex)
  ) {
    fail("stopped directory-relay challenge must be an internally random 256-bit value");
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
    fail("stopped directory-relay evidence collection window is stale or invalid");
  }
  exactKeys(evidence.collector_process, ["egid", "euid", "pid"], "stopped directory-relay collector process");
  if (evidence.collector_process.euid !== 0 || evidence.collector_process.egid !== 0) {
    fail("stopped directory-relay collector was not root");
  }
  validateStoppedHost(
    evidence.host,
    request,
    expectedMachineIdSha256,
    expectedBootId,
    "directory-relay-v1",
  );
  validateTrustedCommandClosure(
    evidence.trusted_commands,
    "stopped directory-relay evidence",
    request,
  );
  const expectedProtected = validateStoppedNssEvidence(evidence.nss, request);
  validateStoppedAccountPolicy(evidence.account_policy, request, evidence.nss);
  validateStoppedInstalledFilePasses(evidence.installed_file_passes, request);
  validateStoppedPrivateLoaderEvidenceV2(evidence, request);
  validateSystemdManagerPassesV1(
    evidence.systemd_manager_passes,
    "stopped directory-relay systemd manager",
  );
  validateStoppedUnitPasses(evidence.stopped_unit_passes, request);
  validateStoppedUnitConfigurationPasses(evidence.unit_configuration_passes, request);
  validateSystemdAnalyzeEvidence(
    evidence.systemd_analyze_verify,
    request,
    "stopped directory-relay",
  );
  validateRuntimeSocketAbsencePasses(
    evidence.runtime_socket_absence_passes,
    request,
    { allowEmpty: true },
  );
  validateStoppedProtectedClosure(evidence.protected_process_closure, expectedProtected);
  return true;
}

const PUBLISHER_NETNS_UNIT = "bitcoinpir-payment-v1-publisher-netns.service";
const PUBLISHER_CADDY_UNIT = "bhtm-caddy.service";
const PUBLISHER_NETNS_PATH = "/run/netns/bpir-directory-publisher";
const PUBLISHER_NETNS_FRAGMENT =
  "/etc/systemd/system/bitcoinpir-payment-v1-publisher-netns.service";
const PUBLISHER_CADDY_DROP_IN =
  "/etc/systemd/system/bhtm-caddy.service.d/bitcoinpir-publisher-netns.conf";
const PUBLISHER_CADDY_CONFIG = "/etc/caddy/Caddyfile";
const PUBLISHER_PUBLICATION_RECEIPT_DIRECTORY =
  "/var/lib/bitcoinpir-directory-publication";
const NSFS_MAGIC = 0x6e736673;
const PUBLISHER_MONITOR_BOUNDING_CAPABILITIES = "0000000000201000";
const PUBLISHER_OWNER_CONDITION_PATHS = Object.freeze([
  "/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
  "/etc/bitcoinpir/payment-v1/EDGE-ACTIVATION-APPROVED",
  "/etc/bitcoinpir/payment-v1/SOURCE-FAIR-PREFLIGHT-APPROVED",
  "/etc/bitcoinpir/payment-v1/DIRECTORY-PUBLISHER-PRIVATE-INGRESS-APPROVED",
  "/etc/bitcoinpir/payment-v1/PUBLISHER-NETNS-ACTIVATION-APPROVED",
]);
const PUBLISHER_OWNER_EFFECTIVE_PROPERTIES = Object.freeze([
  "ActiveEnterTimestampMonotonic",
  "ActiveState",
  "AmbientCapabilities",
  "CapabilityBoundingSet",
  "ConditionResult",
  "ControlGroup",
  "DropInPaths",
  "ExecStart",
  "ExecStartPre",
  "ExecStopPost",
  "FragmentPath",
  "Group",
  "InvocationID",
  "KillMode",
  "LimitCORE",
  "LimitCORESoft",
  "LoadState",
  "LockPersonality",
  "MainPID",
  "MemoryDenyWriteExecute",
  "MemoryMax",
  "MemorySwapCurrent",
  "MemorySwapMax",
  "NeedDaemonReload",
  "NoNewPrivileges",
  "NotifyAccess",
  "PartOf",
  "Restart",
  "RestrictAddressFamilies",
  "RestrictNamespaces",
  "RestrictRealtime",
  "RestrictSUIDSGID",
  "Result",
  "StateDirectory",
  "StateDirectoryMode",
  "StandardError",
  "StandardOutput",
  "SubState",
  "SystemCallArchitectures",
  "TasksMax",
  "TimeoutStartUSec",
  "TimeoutStopUSec",
  "Type",
  "UMask",
  "UnsetEnvironment",
  "User",
  "WorkingDirectory",
]);

function exactOptionValuesV1(argv, option, expectedCount, label) {
  const values = [];
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] !== option) continue;
    if (index + 1 >= argv.length || argv[index + 1].startsWith("--")) {
      fail(`${label} has a missing ${option} value`);
    }
    values.push(argv[index + 1]);
  }
  if (values.length !== expectedCount) {
    fail(`${label} must contain exactly ${expectedCount} ${option} option(s)`);
  }
  return values;
}

function expectedPublisherPublicationReceiptRequestV1(request) {
  const unit = request.units?.find(
    (candidate) =>
      candidate.unit_name ===
      "bitcoinpir-payment-v1-directory-publisher.service",
  );
  const identity = request.service_identities?.find(
    (candidate) => candidate.unit_name === unit?.unit_name,
  );
  const argv = unit?.exec_start_ex?.[0]?.argv;
  if (!identity || !Array.isArray(argv)) {
    fail("publisher publication receipt request lacks its exact unit/identity generation");
  }
  const artifactPaths = exactOptionValuesV1(
    argv,
    "--artifact",
    3,
    "publisher publication argv",
  ).sort();
  const manifestPath = exactOptionValuesV1(
    argv,
    "--artifact-manifest",
    1,
    "publisher publication argv",
  )[0];
  const receiptDirectory = exactOptionValuesV1(
    argv,
    "--receipt-directory",
    1,
    "publisher publication argv",
  )[0];
  const relayOrigins = exactOptionValuesV1(
    argv,
    "--relay",
    1,
    "publisher publication argv",
  );
  const publisherPubkey = exactOptionValuesV1(
    argv,
    "--directory-pubkey-hex",
    1,
    "publisher publication argv",
  )[0];
  if (
    receiptDirectory !== PUBLISHER_PUBLICATION_RECEIPT_DIRECTORY ||
    argv.filter((value) => value === "--centralized-single-relay").length !== 1
  ) {
    fail("publisher publication argv lost its fixed receipt or centralized mode");
  }
  const installedByPath = new Map(
    request.installed_files.map((file) => [file.target_path, file]),
  );
  const artifactManifest = installedByPath.get(manifestPath);
  const artifacts = artifactPaths.map((path) => installedByPath.get(path));
  if (!artifactManifest || artifacts.some((file) => !file)) {
    fail("publisher publication receipt inputs are not installed-file pins");
  }
  return {
    artifact_manifest: {
      path: manifestPath,
      sha256: artifactManifest.sha256,
    },
    artifacts: artifacts.map((file) => ({
      path: file.target_path,
      sha256: file.sha256,
    })),
    argv,
    argv_sha256: computeDirectoryPublishArgvSha256V1(argv),
    directory_mode: "centralized-single-relay",
    file: {
      directory: receiptDirectory,
      filename_suffix: ".json",
      gid: identity.gid,
      mode: "0600",
      nlink: 1,
      uid: identity.uid,
    },
    kind: "bitcoinpir-directory-publication-receipt-v1",
    publisher_pubkey_hex: publisherPubkey,
    relay_origins: relayOrigins,
    schema_version: 1,
  };
}

function expectedPublisherNetworkRequest(networkPolicySha256, publicationReceipt) {
  return {
    caddy_drop_in_path: PUBLISHER_CADDY_DROP_IN,
    caddy_service_unit: PUBLISHER_CADDY_UNIT,
    firewall: {
      forwarding_sysctls: {
        "net.ipv4.ip_forward": 0,
        "net.ipv6.conf.all.forwarding": 0,
      },
      interface: "bpir-pub-h",
      semantic_profile: "bitcoinpir-publisher-ufw-closed-v1",
      ufw_rules_in_install_order: [
        "prepend deny in on bpir-pub-h from any to any",
        "prepend allow in on bpir-pub-h from 10.203.0.2 to 10.203.0.1 proto tcp port 443",
        "route prepend deny in on bpir-pub-h from any to any",
        "route prepend deny out on bpir-pub-h from any to any",
      ],
    },
    forbidden_caddy_reverse_stop_edges: ["BindsTo", "PartOf", "Requires"],
    namespace: {
      client: "10.203.0.2/30",
      host: "10.203.0.1/30",
      name: "bpir-directory-publisher",
      path: PUBLISHER_NETNS_PATH,
    },
    namespace_owner_unit: PUBLISHER_NETNS_UNIT,
    network_policy_sha256: networkPolicySha256,
    publication_receipt: publicationReceipt,
    publication_mode: {
      centralized: true,
      degraded: true,
      name: "centralized-single-relay",
    },
    publication_time_firewall_binding: {
      activation_blocked: true,
      activation_blocker_condition_path:
        "/etc/bitcoinpir/payment-v1/PUBLISHER-LIVE-FIREWALL-LINEAGE-IMPLEMENTED",
      continuous_checks: [
        "reject-any-nftables-generation-event",
        "reject-xtables-lock-inode-drift",
      ],
      continuous_generation_guard_implemented: true,
      graceful_stop_barriers: [
        "require-empty-nftables-event-queue",
        "require-stable-xtables-lock-inode",
      ],
      guard_profile: "xtables-lock-and-host-nftables-generation-monitor-v1",
      implemented: false,
      initial_live_semantic_lineage: {
        binds_boot_id: false,
        binds_owner_invocation_id: false,
        binds_publication_approval: false,
        binds_rule_summary: false,
        implemented: false,
        required_before_owner_ready: true,
      },
      lifecycle_scope: "publisher-netns-owner-lifetime",
      missing_requirement: "owner-pre-ready-live-semantic-revalidation-lineage-v1",
      point_in_time_evidence_only: true,
      pre_ready_barriers: [
        "open-host-netns-nftables-multicast-before-network-setup",
        "hold-root-single-link-xtables-lock",
        "require-empty-nftables-event-queue",
        "repeat-full-stop-firewall-child-topology-barrier-immediately-before-ready",
      ],
      privileged_mutation_boundary: "non-adversarial-root-maintenance",
      semantic_pre_post_evidence_required: true,
      state_machine:
        "continuous-generation-guard-implemented-live-semantic-lineage-blocked",
    },
    publisher_unit: "bitcoinpir-payment-v1-directory-publisher.service",
  };
}

function publisherFirewallSemanticOutputs(outputs) {
  const canonicalLines = (text) => text
    .split("\n")
    .map((line) => line.trim().replace(/\s+/gu, " "))
    .filter((line) => line.includes("bpir-pub-h"));
  const nft = (text) => canonicalLines(text).map((line) => line
    .replace(/ counter packets [0-9]+ bytes [0-9]+/gu, "")
    .replace(/ # handle [0-9]+$/gu, ""));
  return {
    closed_prelude_profile: "ufw-base-before-user-and-user-prefix-v1",
    nft_ip6_forward: nft(outputs.nft_ip6_forward),
    nft_ip6_input: nft(outputs.nft_ip6_input),
    nft_ip_forward: nft(outputs.nft_ip_forward),
    nft_ip_input: nft(outputs.nft_ip_input),
    ufw_raw: canonicalLines(outputs.ufw_raw).map((line) =>
      line.replace(/^[0-9]+ [0-9]+ /u, "COUNTERS ")),
    ufw_status: canonicalLines(outputs.ufw_status).map((line) =>
      line.replace(/^\[\s*[0-9]+\]\s*/u, "")),
    validated_output_keys: [...PUBLISHER_FIREWALL_OUTPUT_KEYS],
  };
}

const EXPECTED_PUBLISHER_FIREWALL_SEMANTICS = Object.freeze({
  closed_prelude_profile: "ufw-base-before-user-and-user-prefix-v1",
  nft_ip6_forward: Object.freeze([
    'oifname "bpir-pub-h" drop',
    'iifname "bpir-pub-h" drop',
  ]),
  nft_ip6_input: Object.freeze(['iifname "bpir-pub-h" drop']),
  nft_ip_forward: Object.freeze([
    'oifname "bpir-pub-h" drop',
    'iifname "bpir-pub-h" drop',
  ]),
  nft_ip_input: Object.freeze([
    'ip saddr 10.203.0.2 ip daddr 10.203.0.1 iifname "bpir-pub-h" tcp dport 443 accept',
    'iifname "bpir-pub-h" drop',
  ]),
  ufw_raw: Object.freeze([
    "COUNTERS ACCEPT 6 -- bpir-pub-h * 10.203.0.2 10.203.0.1 tcp dpt:443",
    "COUNTERS DROP 0 -- bpir-pub-h * 0.0.0.0/0 0.0.0.0/0",
    "COUNTERS DROP 0 -- bpir-pub-h * 0.0.0.0/0 0.0.0.0/0",
    "COUNTERS DROP 0 -- * bpir-pub-h 0.0.0.0/0 0.0.0.0/0",
    "COUNTERS DROP 0 -- bpir-pub-h * ::/0 ::/0",
    "COUNTERS DROP 0 -- bpir-pub-h * ::/0 ::/0",
    "COUNTERS DROP 0 -- * bpir-pub-h ::/0 ::/0",
  ]),
  ufw_status: Object.freeze([
    "10.203.0.1 443/tcp on bpir-pub-h ALLOW IN 10.203.0.2",
    "Anywhere on bpir-pub-h DENY IN Anywhere",
    "Anywhere DENY FWD Anywhere on bpir-pub-h",
    "Anywhere on bpir-pub-h DENY FWD Anywhere (out)",
    "Anywhere (v6) on bpir-pub-h DENY IN Anywhere (v6)",
    "Anywhere (v6) DENY FWD Anywhere (v6) on bpir-pub-h",
    "Anywhere (v6) on bpir-pub-h DENY FWD Anywhere (v6) (out)",
  ]),
  validated_output_keys: PUBLISHER_FIREWALL_OUTPUT_KEYS,
});

function collectPublisherFirewallPass() {
  const run = (command, args, label, allowedStderr = [""]) => {
    const record = runAbsolute(command, args, { timeout: 30_000 });
    if (record.exit_status !== 0 || !allowedStderr.includes(record.stderr)) {
      fail(`${label} failed while collecting publisher firewall evidence`);
    }
    return record.stdout;
  };
  const nftCases = Object.freeze({
    nft_ip6_base_forward: ["ip6", "filter", "FORWARD"],
    nft_ip6_base_input: ["ip6", "filter", "INPUT"],
    nft_ip6_before_forward: ["ip6", "filter", "ufw6-before-forward"],
    nft_ip6_before_input: ["ip6", "filter", "ufw6-before-input"],
    nft_ip6_before_logging_forward: ["ip6", "filter", "ufw6-before-logging-forward"],
    nft_ip6_before_logging_input: ["ip6", "filter", "ufw6-before-logging-input"],
    nft_ip6_forward: ["ip6", "filter", "ufw6-user-forward"],
    nft_ip6_input: ["ip6", "filter", "ufw6-user-input"],
    nft_ip6_logging_deny: ["ip6", "filter", "ufw6-logging-deny"],
    nft_ip_base_forward: ["ip", "filter", "FORWARD"],
    nft_ip_base_input: ["ip", "filter", "INPUT"],
    nft_ip_before_forward: ["ip", "filter", "ufw-before-forward"],
    nft_ip_before_input: ["ip", "filter", "ufw-before-input"],
    nft_ip_before_logging_forward: ["ip", "filter", "ufw-before-logging-forward"],
    nft_ip_before_logging_input: ["ip", "filter", "ufw-before-logging-input"],
    nft_ip_forward: ["ip", "filter", "ufw-user-forward"],
    nft_ip_input: ["ip", "filter", "ufw-user-input"],
    nft_ip_logging_deny: ["ip", "filter", "ufw-logging-deny"],
    nft_ip_not_local: ["ip", "filter", "ufw-not-local"],
  });
  const outputs = Object.fromEntries(Object.entries(nftCases).map(([key, args]) => [
    key,
    run(
      "/usr/sbin/nft",
      ["list", "chain", ...args],
      `nft ${args[0]} ${args[2]}`,
      [
        "",
        `# Warning: table ${args[0]} filter is managed by iptables-nft, do not touch!\n`,
      ],
    ),
  ]));
  outputs.ufw_raw = run("/usr/sbin/ufw", ["show", "raw"], "ufw show raw");
  outputs.ufw_status = run("/usr/sbin/ufw", ["status", "numbered"], "ufw status numbered");
  if (canonicalJson(Object.keys(outputs).sort()) !== canonicalJson(PUBLISHER_FIREWALL_OUTPUT_KEYS)) {
    fail("publisher firewall collector output keys are not the reviewed closed set");
  }
  validatePublisherFirewallOutputs(outputs);
  const semantics = publisherFirewallSemanticOutputs(outputs);
  if (canonicalJson(semantics) !== canonicalJson(EXPECTED_PUBLISHER_FIREWALL_SEMANTICS)) {
    fail("publisher firewall semantic normalization drifted from the closed V1 policy");
  }
  return {
    output_sha256: Object.fromEntries(
      Object.entries(outputs).map(([key, value]) => [key, hashBytes(Buffer.from(value))]),
    ),
    semantic_outputs: semantics,
    semantic_profile: "bitcoinpir-publisher-ufw-closed-v1",
  };
}

function collectPublisherSysctls() {
  const readZero = (path, label) => {
    const value = readFileSync(path, "utf8");
    if (value !== "0\n") fail(`${label} must be disabled for the publisher namespace boundary`);
    return 0;
  };
  return {
    "net.ipv4.ip_forward": readZero("/proc/sys/net/ipv4/ip_forward", "IPv4 forwarding"),
    "net.ipv6.conf.all.forwarding": readZero(
      "/proc/sys/net/ipv6/conf/all/forwarding",
      "IPv6 forwarding",
    ),
  };
}

function collectPublisherCaddyConfigGeneration() {
  const observed = readOneLinkRegularBoundToDescriptor(
    PUBLISHER_CADDY_CONFIG,
    "publisher Caddy config generation",
    MAX_JSON_BYTES,
  );
  const generation = {
    ...observed.fingerprint,
    path: PUBLISHER_CADDY_CONFIG,
    sha256: hashBytes(observed.bytes),
  };
  if (
    generation.uid !== 0 ||
    generation.gid !== 0 ||
    generation.mode !== "0644" ||
    generation.nlink !== 1
  ) {
    fail("publisher Caddy config generation is not root:root mode 0644 with one link");
  }
  return generation;
}

function collectPublisherCaddyUnitGeneration() {
  const generation = {
    active_enter_timestamp_monotonic: collectSystemctlValue(
      PUBLISHER_CADDY_UNIT,
      "ActiveEnterTimestampMonotonic",
    ),
    active_state: collectSystemctlValue(PUBLISHER_CADDY_UNIT, "ActiveState"),
    invocation_id: collectSystemctlValue(PUBLISHER_CADDY_UNIT, "InvocationID"),
    load_state: collectSystemctlValue(PUBLISHER_CADDY_UNIT, "LoadState"),
    main_pid: collectSystemctlValue(PUBLISHER_CADDY_UNIT, "MainPID"),
    need_daemon_reload: collectSystemctlValue(PUBLISHER_CADDY_UNIT, "NeedDaemonReload"),
    sub_state: collectSystemctlValue(PUBLISHER_CADDY_UNIT, "SubState"),
  };
  if (
    generation.active_state !== "active" ||
    generation.sub_state !== "running" ||
    generation.load_state !== "loaded" ||
    generation.need_daemon_reload !== "no" ||
    !/^[1-9][0-9]*$/u.test(generation.active_enter_timestamp_monotonic) ||
    !/^[1-9][0-9]*$/u.test(generation.main_pid) ||
    !/^[0-9a-f]{32}$/u.test(generation.invocation_id) ||
    /^0{32}$/u.test(generation.invocation_id)
  ) {
    fail("shared Caddy is not one loaded active generation with NeedDaemonReload=no");
  }
  return generation;
}

function collectPublisherCaddyDependency() {
  const words = (property) => splitLiteralWords(collectSystemctlValue(PUBLISHER_CADDY_UNIT, property));
  const owner = PUBLISHER_NETNS_UNIT;
  const generationBefore = collectPublisherCaddyUnitGeneration();
  const configBefore = collectPublisherCaddyConfigGeneration();
  const dropIns = words("DropInPaths");
  if (
    new Set(dropIns).size !== dropIns.length ||
    canonicalJson(dropIns) !== canonicalJson([PUBLISHER_CADDY_DROP_IN])
  ) {
    fail("shared Caddy DropInPaths is not the singleton reviewed publisher namespace drop-in");
  }
  const snapshot = {
    after_namespace_owner: words("After").includes(owner),
    binds_to_namespace_owner: words("BindsTo").includes(owner),
    config_generation_confirmations: [],
    drop_in_paths: dropIns,
    drop_in_paths_sha256: hashBytes(Buffer.from(canonicalJson(dropIns))),
    generation_confirmations: [],
    part_of_namespace_owner: words("PartOf").includes(owner),
    requires_namespace_owner: words("Requires").includes(owner),
    wants_namespace_owner: words("Wants").includes(owner),
  };
  if (
    !snapshot.after_namespace_owner ||
    !snapshot.wants_namespace_owner ||
    snapshot.binds_to_namespace_owner ||
    snapshot.part_of_namespace_owner ||
    snapshot.requires_namespace_owner
  ) {
    fail("shared Caddy has an unsafe or incomplete effective publisher dependency graph");
  }
  const configAfter = collectPublisherCaddyConfigGeneration();
  const generationAfter = collectPublisherCaddyUnitGeneration();
  if (
    canonicalJson(configBefore) !== canonicalJson(configAfter) ||
    canonicalJson(generationBefore) !== canonicalJson(generationAfter)
  ) {
    fail("shared Caddy config or systemd generation changed during dependency collection");
  }
  snapshot.config_generation_confirmations.push(configBefore, configAfter);
  snapshot.generation_confirmations.push(generationBefore, generationAfter);
  return snapshot;
}

function publisherOwnerArtifactExpectations(request) {
  if (!Array.isArray(request.installed_files)) {
    fail("publisher runtime request does not bind installed artifacts");
  }
  const fragments = request.installed_files.filter(
    (file) => file?.target_path === PUBLISHER_NETNS_FRAGMENT,
  );
  const helpers = request.installed_files.filter((file) =>
    typeof file?.target_path === "string" &&
    /^\/opt\/bitcoinpir\/publisher-netns\/[0-9a-f]{64}\/payment-v1-publisher-netns$/u
      .test(file.target_path));
  if (fragments.length !== 1 || helpers.length !== 1) {
    fail("publisher request must bind exactly one namespace-owner fragment and helper");
  }
  const fragmentSha256 = validateDigest(
    fragments[0].sha256,
    "publisher namespace-owner fragment digest",
  );
  const helperSha256 = validateDigest(helpers[0].sha256, "publisher namespace helper digest");
  const helperPath = validateAbsolutePath(helpers[0].target_path, "publisher namespace helper path");
  if (helperPath.split("/").at(-2) !== helperSha256) {
    fail("publisher namespace helper path is not addressed by its requested digest");
  }
  return {
    fragment_sha256: fragmentSha256,
    helper_path: helperPath,
    helper_sha256: helperSha256,
  };
}

function collectPublisherOwnerArtifacts(request) {
  const expected = publisherOwnerArtifactExpectations(request);
  const fragmentSha256 = hashBytes(readOneLinkRegular(
    PUBLISHER_NETNS_FRAGMENT,
    "publisher namespace-owner fragment",
    2 * 1024 * 1024,
  ));
  const helperSha256 = hashBytes(readOneLinkRegular(
    expected.helper_path,
    "publisher namespace helper",
    32 * 1024 * 1024,
  ));
  if (
    fragmentSha256 !== expected.fragment_sha256 ||
    helperSha256 !== expected.helper_sha256
  ) {
    fail("publisher namespace-owner artifacts drifted from the runtime request");
  }
  return expected;
}

function expectedPublisherOwnerConditions() {
  return PUBLISHER_OWNER_CONDITION_PATHS.map((parameter) => ({
    negate: false,
    parameter,
    path_exists: true,
    result: 1,
    trigger: false,
    type: "ConditionPathExists",
  })).sort(compareEffectiveConditionRecords);
}

function validatePublisherOwnerConditions(conditions) {
  if (!Array.isArray(conditions)) fail("publisher namespace-owner Conditions are missing");
  for (const [index, condition] of conditions.entries()) {
    exactKeys(
      condition,
      ["negate", "parameter", "path_exists", "result", "trigger", "type"],
      `publisher namespace-owner Conditions[${index}]`,
    );
  }
  if (canonicalJson(conditions) !== canonicalJson(expectedPublisherOwnerConditions())) {
    fail("publisher namespace-owner effective Conditions drifted from the reviewed unit");
  }
}

function validatePublisherOwnerEffectiveProperties(properties, artifacts) {
  exactKeys(
    properties,
    PUBLISHER_OWNER_EFFECTIVE_PROPERTIES,
    "publisher namespace-owner effective properties",
  );
  const exact = {
    ActiveState: "active",
    AmbientCapabilities: "",
    ConditionResult: "yes",
    ControlGroup: expectedSystemUnitControlGroup(PUBLISHER_NETNS_UNIT),
    DropInPaths: "",
    FragmentPath: PUBLISHER_NETNS_FRAGMENT,
    Group: "root",
    KillMode: "control-group",
    LimitCORE: "0",
    LimitCORESoft: "0",
    LoadState: "loaded",
    LockPersonality: "yes",
    MemoryDenyWriteExecute: "yes",
    MemoryMax: "67108864",
    MemorySwapCurrent: "0",
    MemorySwapMax: "0",
    NeedDaemonReload: "no",
    NoNewPrivileges: "yes",
    NotifyAccess: "main",
    Restart: "no",
    RestrictNamespaces: "net",
    RestrictRealtime: "yes",
    RestrictSUIDSGID: "yes",
    Result: "success",
    StateDirectory: "bitcoinpir-publisher-netns",
    StateDirectoryMode: "0700",
    StandardError: "null",
    StandardOutput: "null",
    SubState: "running",
    SystemCallArchitectures: "native",
    TasksMax: "8",
    TimeoutStartUSec: "30s",
    TimeoutStopUSec: "30s",
    Type: "notify",
    UMask: "0077",
    User: "root",
    WorkingDirectory: "/var/lib/bitcoinpir-publisher-netns",
  };
  for (const [key, expected] of Object.entries(exact)) {
    if (properties[key] !== expected) {
      fail(`publisher namespace-owner effective ${key} drifted from the reviewed unit`);
    }
  }
  for (const [key, expected] of [
    ["CapabilityBoundingSet", ["CAP_NET_ADMIN", "CAP_SYS_ADMIN"]],
    ["PartOf", [PUBLISHER_CADDY_UNIT]],
    ["RestrictAddressFamilies", ["AF_NETLINK", "AF_UNIX"]],
    ["UnsetEnvironment", [
      "BASH_ENV",
      "ENV",
      "GLIBC_TUNABLES",
      "LD_AUDIT",
      "LD_LIBRARY_PATH",
      "LD_PRELOAD",
      "NODE_EXTRA_CA_CERTS",
      "NODE_OPTIONS",
      "NODE_PATH",
    ]],
  ]) {
    const actual = splitLiteralWords(properties[key]).map((value) =>
      key === "CapabilityBoundingSet" ? value.toUpperCase() : value);
    if (canonicalJson(actual) !== canonicalJson([...expected].sort())) {
      fail(`publisher namespace-owner effective ${key} drifted from the reviewed unit`);
    }
  }
  const helper = artifacts.helper_path;
  const startRecords = parseSystemctlExecArgvV1(
    properties.ExecStart,
    "publisher namespace-owner ExecStart",
  );
  const preRecords = parseSystemctlExecArgvV1(
    properties.ExecStartPre,
    "publisher namespace-owner ExecStartPre",
  );
  const stopPostRecords = parseSystemctlExecArgvV1(
    properties.ExecStopPost,
    "publisher namespace-owner ExecStopPost",
  );
  validateSystemctlExecRuntimeMetadataV2(startRecords, {
    active: true,
    kind: "start",
    label: "publisher namespace-owner ExecStart",
    mainPid: properties.MainPID,
  });
  validateSystemctlExecRuntimeMetadataV2(preRecords, {
    active: true,
    kind: "pre",
    label: "publisher namespace-owner ExecStartPre",
    mainPid: properties.MainPID,
  });
  validateSystemctlExecRuntimeMetadataV2(stopPostRecords, {
    active: false,
    kind: "stop-post",
    label: "publisher namespace-owner ExecStopPost",
    mainPid: "0",
  });
  if (
    canonicalJson(effectiveExecPolicy(preRecords, "publisher namespace-owner ExecStartPre")) !==
      canonicalJson(reviewedExecPolicy([
        `/usr/bin/test -x ${helper}`,
        "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/publisher-netns/helper.sha256",
        `${helper} self-test`,
      ], "publisher namespace-owner reviewed ExecStartPre")) ||
    canonicalJson(effectiveExecPolicy(startRecords, "publisher namespace-owner ExecStart")) !==
      canonicalJson(reviewedExecPolicy(
        [`${helper} run`],
        "publisher namespace-owner reviewed ExecStart",
      )) ||
    canonicalJson(effectiveExecPolicy(stopPostRecords, "publisher namespace-owner ExecStopPost")) !==
      canonicalJson(reviewedExecPolicy(
        [`${helper} cleanup`],
        "publisher namespace-owner reviewed ExecStopPost",
      ))
  ) {
    fail("publisher namespace-owner effective executable argv drifted from the pinned helper");
  }
  parseUnsignedDecimal(
    properties.ActiveEnterTimestampMonotonic,
    "publisher namespace-owner ActiveEnterTimestampMonotonic",
    { allowZero: false },
  );
  parseUnsignedDecimal(properties.MainPID, "publisher namespace-owner MainPID", {
    allowZero: false,
  });
  if (
    !/^[0-9a-f]{32}$/u.test(properties.InvocationID) ||
    /^0{32}$/u.test(properties.InvocationID)
  ) {
    fail("publisher namespace-owner InvocationID is not one active generation");
  }
}

function collectPublisherOwnerGeneration(properties) {
  const confirmation = {
    active_enter_timestamp_monotonic: collectSystemctlValue(
      PUBLISHER_NETNS_UNIT,
      "ActiveEnterTimestampMonotonic",
    ),
    active_state: collectSystemctlValue(PUBLISHER_NETNS_UNIT, "ActiveState"),
    control_group: collectSystemctlValue(PUBLISHER_NETNS_UNIT, "ControlGroup"),
    invocation_id: collectSystemctlValue(PUBLISHER_NETNS_UNIT, "InvocationID"),
    main_pid: collectSystemctlValue(PUBLISHER_NETNS_UNIT, "MainPID"),
    need_daemon_reload: collectSystemctlValue(PUBLISHER_NETNS_UNIT, "NeedDaemonReload"),
  };
  if (
    confirmation.active_enter_timestamp_monotonic !== properties.ActiveEnterTimestampMonotonic ||
    confirmation.active_state !== properties.ActiveState ||
    confirmation.control_group !== properties.ControlGroup ||
    confirmation.invocation_id !== properties.InvocationID ||
    confirmation.main_pid !== properties.MainPID ||
    confirmation.need_daemon_reload !== "no"
  ) {
    fail("publisher namespace-owner generation changed during live collection");
  }
  return confirmation;
}

function parsePublisherProcStatus(bytes, pid, label) {
  const identity = parseProcStatus(bytes, pid, { expectedTgid: pid, label });
  const lines = decodeProcText(bytes, label).split("\n");
  const unsignedField = (name) => {
    const matches = lines.filter((line) => line.startsWith(`${name}:`));
    if (matches.length !== 1) fail(`${label} must contain exactly one ${name}: field`);
    const value = matches[0].slice(name.length + 1).trim();
    if (!/^(?:0|[1-9][0-9]*)$/u.test(value)) fail(`${label} has malformed ${name}: value`);
    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed) || parsed < 0) fail(`${label} has out-of-range ${name}: value`);
    return parsed;
  };
  return {
    ...identity,
    noNewPrivileges: unsignedField("NoNewPrivs"),
    parentPid: unsignedField("PPid"),
    seccomp: unsignedField("Seccomp"),
  };
}

function readPublisherNetNamespace(path, label) {
  const stat = lstatSync(path);
  if (!stat.isSymbolicLink()) fail(`${label} is not a procfs namespace link`);
  const value = readlinkSync(path);
  if (!/^net:\[[1-9][0-9]*\]$/u.test(value)) fail(`${label} has a malformed network namespace id`);
  return value;
}

function collectPublisherExeBinding(pid, artifacts) {
  const procPath = `/proc/${pid}/exe`;
  if (!lstatSync(procPath).isSymbolicLink() || readlinkSync(procPath) !== artifacts.helper_path) {
    fail(`publisher monitor ${pid} does not execute the pinned helper path`);
  }
  const helperFd = openSync(
    artifacts.helper_path,
    constants.O_RDONLY | constants.O_NOFOLLOW | (constants.O_CLOEXEC ?? 0),
  );
  const procFd = openSync(procPath, constants.O_RDONLY | (constants.O_CLOEXEC ?? 0));
  try {
    const helperStat = fstatSync(helperFd, { bigint: true });
    const procStat = fstatSync(procFd, { bigint: true });
    if (
      helperStat.dev !== procStat.dev ||
      helperStat.ino !== procStat.ino ||
      !helperStat.isFile() ||
      !procStat.isFile()
    ) {
      fail(`publisher monitor ${pid} executable inode is not the installed pinned helper`);
    }
    return {
      dev: procStat.dev.toString(),
      ino: procStat.ino.toString(),
      path: artifacts.helper_path,
      sha256: artifacts.helper_sha256,
    };
  } finally {
    closeSync(procFd);
    closeSync(helperFd);
  }
}

function collectPublisherProcessSnapshot(pid, artifacts, label) {
  const path = `/proc/${pid}`;
  const directoryBefore = inspectProcDirectory(path, `${label} directory`);
  const statBefore = parseProcStat(
    readBoundedProcFile(`${path}/stat`, `${label} stat`, MAX_PROC_STAT_BYTES),
    pid,
    `${path}/stat`,
  );
  const cgroupBefore = parseUnifiedProcCgroup(
    readBoundedProcFile(`${path}/cgroup`, `${label} cgroup`, MAX_PROC_CGROUP_BYTES),
    `${path}/cgroup`,
  );
  const status = parsePublisherProcStatus(
    readBoundedProcFile(`${path}/status`, `${label} status`, MAX_PROC_STATUS_BYTES),
    pid,
    `${path}/status`,
  );
  const networkNamespace = readPublisherNetNamespace(`${path}/ns/net`, `${label} netns`);
  const executable = collectPublisherExeBinding(pid, artifacts);
  const cgroupAfter = parseUnifiedProcCgroup(
    readBoundedProcFile(`${path}/cgroup`, `${label} cgroup confirmation`, MAX_PROC_CGROUP_BYTES),
    `${path}/cgroup`,
  );
  const statAfter = parseProcStat(
    readBoundedProcFile(`${path}/stat`, `${label} stat confirmation`, MAX_PROC_STAT_BYTES),
    pid,
    `${path}/stat`,
  );
  const directoryAfter = inspectProcDirectory(path, `${label} directory confirmation`);
  if (
    canonicalJson(directoryBefore) !== canonicalJson(directoryAfter) ||
    statBefore.startTimeTicks !== statAfter.startTimeTicks ||
    cgroupBefore !== cgroupAfter
  ) {
    fail(`${label} restarted or moved cgroups while live evidence was collected`);
  }
  return {
    capabilities: status.capabilities,
    control_group: cgroupAfter,
    executable,
    gid: status.gid,
    groups: status.groups,
    net_namespace: networkNamespace,
    no_new_privs: status.noNewPrivileges,
    parent_pid: status.parentPid,
    pid,
    proc_directory_dev: directoryAfter.dev,
    proc_directory_ino: directoryAfter.ino,
    seccomp: status.seccomp,
    start_time_ticks: statAfter.startTimeTicks,
    uid: status.uid,
  };
}

function readPublisherDirectChildren(mainPid) {
  const path = `/proc/${mainPid}/task/${mainPid}/children`;
  const text = decodeProcText(
    readBoundedProcFile(path, "publisher namespace-owner direct children", 4096),
    path,
  ).trim();
  if (text === "") return [];
  const children = text.split(/\s+/u).map((value) => {
    const pid = parseUnsignedDecimal(value, "publisher namespace-owner child PID", {
      allowZero: false,
    });
    return pid;
  });
  if (children.length > 8 || new Set(children).size !== children.length) {
    fail("publisher namespace-owner direct child set is not bounded and unique");
  }
  return children.sort((left, right) => left - right);
}

function collectPublisherProcessPass(properties, artifacts, namespaceMount) {
  const mainPid = parseUnsignedDecimal(
    properties.MainPID,
    "publisher namespace-owner MainPID",
    { allowZero: false },
  );
  const childrenBefore = readPublisherDirectChildren(mainPid);
  if (childrenBefore.length !== 1) {
    fail("publisher namespace-owner must have exactly one direct client monitor");
  }
  const collectorNetNamespace = readPublisherNetNamespace(
    "/proc/self/ns/net",
    "publisher collector netns",
  );
  const main = collectPublisherProcessSnapshot(mainPid, artifacts, "publisher host monitor");
  const child = collectPublisherProcessSnapshot(
    childrenBefore[0],
    artifacts,
    "publisher client monitor",
  );
  const childrenAfter = readPublisherDirectChildren(mainPid);
  if (canonicalJson(childrenAfter) !== canonicalJson(childrenBefore)) {
    fail("publisher namespace-owner direct child set changed during live collection");
  }
  const pass = {
    child,
    collector_net_namespace: collectorNetNamespace,
    direct_children: childrenAfter,
    main,
  };
  validatePublisherProcessPass(pass, properties, artifacts, namespaceMount);
  return pass;
}

function validatePublisherProcessSnapshot(snapshot, {
  artifacts,
  expectedNetNamespace,
  expectedParentPid,
  expectedPid,
  label,
}) {
  exactKeys(
    snapshot,
    [
      "capabilities", "control_group", "executable", "gid", "groups",
      "net_namespace", "no_new_privs", "parent_pid", "pid", "proc_directory_dev",
      "proc_directory_ino", "seccomp", "start_time_ticks", "uid",
    ],
    label,
  );
  validateCapabilityRecord(snapshot.capabilities, `${label} capabilities`);
  if (
    snapshot.pid !== expectedPid ||
    snapshot.parent_pid !== expectedParentPid ||
    canonicalJson(snapshot.uid) !== canonicalJson([0, 0, 0, 0]) ||
    canonicalJson(snapshot.gid) !== canonicalJson([0, 0, 0, 0]) ||
    !Array.isArray(snapshot.groups) ||
    snapshot.groups.length > 1 ||
    snapshot.groups.some((gid) => gid !== 0) ||
    activeCapabilityMask(snapshot.capabilities) !== 0n ||
    snapshot.capabilities.bounding !== PUBLISHER_MONITOR_BOUNDING_CAPABILITIES ||
    snapshot.no_new_privs !== 1 ||
    snapshot.seccomp !== 2 ||
    snapshot.control_group !== expectedSystemUnitControlGroup(PUBLISHER_NETNS_UNIT) ||
    snapshot.net_namespace !== expectedNetNamespace ||
    !/^[1-9][0-9]*$/u.test(snapshot.proc_directory_dev) ||
    !/^[1-9][0-9]*$/u.test(snapshot.proc_directory_ino) ||
    !/^[1-9][0-9]*$/u.test(snapshot.start_time_ticks)
  ) {
    fail(`${label} is not the reviewed rootless-capability sandboxed monitor process`);
  }
  exactKeys(snapshot.executable, ["dev", "ino", "path", "sha256"], `${label} executable`);
  if (
    snapshot.executable.path !== artifacts.helper_path ||
    snapshot.executable.sha256 !== artifacts.helper_sha256 ||
    !/^[1-9][0-9]*$/u.test(snapshot.executable.dev) ||
    !/^[1-9][0-9]*$/u.test(snapshot.executable.ino)
  ) {
    fail(`${label} executable is not the requested content-addressed helper`);
  }
}

function validatePublisherProcessPass(pass, properties, artifacts, namespaceMount) {
  exactKeys(
    pass,
    ["child", "collector_net_namespace", "direct_children", "main"],
    "publisher namespace-owner process pass",
  );
  const mainPid = parseUnsignedDecimal(
    properties.MainPID,
    "publisher namespace-owner MainPID",
    { allowZero: false },
  );
  if (
    !Array.isArray(pass.direct_children) ||
    pass.direct_children.length !== 1 ||
    !Number.isSafeInteger(pass.direct_children[0]) ||
    pass.direct_children[0] < 1 ||
    !/^net:\[[1-9][0-9]*\]$/u.test(pass.collector_net_namespace)
  ) {
    fail("publisher namespace-owner does not have exactly one canonical direct child");
  }
  const targetNamespace = `net:[${namespaceMount.ino}]`;
  validatePublisherProcessSnapshot(pass.main, {
    artifacts,
    expectedNetNamespace: pass.collector_net_namespace,
    expectedParentPid: 1,
    expectedPid: mainPid,
    label: "publisher host monitor",
  });
  validatePublisherProcessSnapshot(pass.child, {
    artifacts,
    expectedNetNamespace: targetNamespace,
    expectedParentPid: mainPid,
    expectedPid: pass.direct_children[0],
    label: "publisher client monitor",
  });
  if (
    pass.child.pid !== pass.direct_children[0] ||
    pass.main.net_namespace === pass.child.net_namespace
  ) {
    fail("publisher monitor processes do not span the reviewed host/client namespaces");
  }
}

function collectPublisherNamespaceOwner(request, namespaceMount) {
  const artifacts = collectPublisherOwnerArtifacts(request);
  const conditionBefore = collectEffectiveConditions(PUBLISHER_NETNS_UNIT);
  validatePublisherOwnerConditions(conditionBefore);
  const properties = Object.create(null);
  for (const property of PUBLISHER_OWNER_EFFECTIVE_PROPERTIES) {
    properties[property] = collectSystemctlValue(PUBLISHER_NETNS_UNIT, property);
  }
  validatePublisherOwnerEffectiveProperties(properties, artifacts);
  const processBefore = collectPublisherProcessPass(properties, artifacts, namespaceMount);
  const generationBefore = collectPublisherOwnerGeneration(properties);
  const processAfter = collectPublisherProcessPass(properties, artifacts, namespaceMount);
  const generationAfter = collectPublisherOwnerGeneration(properties);
  const conditionAfter = collectEffectiveConditions(PUBLISHER_NETNS_UNIT);
  validatePublisherOwnerConditions(conditionAfter);
  if (
    canonicalJson(processBefore) !== canonicalJson(processAfter) ||
    canonicalJson(conditionBefore) !== canonicalJson(conditionAfter)
  ) {
    fail("publisher namespace-owner process tree or Conditions changed during live collection");
  }
  return {
    condition_confirmations: [conditionBefore, conditionAfter],
    effective_properties: properties,
    fragment_sha256: artifacts.fragment_sha256,
    generation_confirmations: [generationBefore, generationAfter],
    helper_path: artifacts.helper_path,
    helper_sha256: artifacts.helper_sha256,
    process_passes: [processBefore, processAfter],
  };
}

function collectPublisherNamespaceMount() {
  const mountInfo = readFileSync("/proc/self/mountinfo", "utf8");
  if (Buffer.byteLength(mountInfo, "utf8") > MAX_COMMAND_OUTPUT_BYTES || mountInfo.includes("\0")) {
    fail("mountinfo is malformed or oversized");
  }
  const matches = mountInfo.split("\n").filter((line) => {
    if (line === "") return false;
    const left = line.split(" - ")[0]?.split(" ");
    return left?.[4] === PUBLISHER_NETNS_PATH;
  });
  if (matches.length !== 1) fail("publisher namespace path is not one distinct mount point");
  const halves = matches[0].split(" - ");
  if (halves.length !== 2) fail("publisher namespace mountinfo record is malformed");
  const left = halves[0].split(" ");
  const right = halves[1].split(" ");
  if (left.length < 6 || right.length < 3) fail("publisher namespace mountinfo fields are incomplete");
  const stat = lstatSync(PUBLISHER_NETNS_PATH, { bigint: true });
  const statfs = statfsSync(PUBLISHER_NETNS_PATH, { bigint: true });
  const statfsType = Number(statfs.type);
  const snapshot = {
    dev: stat.dev.toString(),
    filesystem_type: right[0],
    ino: stat.ino.toString(),
    major_minor: left[2],
    mount_id: left[0],
    mount_source: right[1],
    parent_mount_id: left[1],
    root: left[3],
    statfs_type: statfsType,
  };
  if (
    !stat.isFile() ||
    snapshot.filesystem_type !== "nsfs" ||
    snapshot.mount_source !== "nsfs" ||
    snapshot.root !== "/" ||
    snapshot.statfs_type !== NSFS_MAGIC ||
    !/^[1-9][0-9]*$/u.test(snapshot.dev) ||
    !/^[1-9][0-9]*$/u.test(snapshot.ino) ||
    !/^[1-9][0-9]*$/u.test(snapshot.mount_id) ||
    !/^[1-9][0-9]*$/u.test(snapshot.parent_mount_id) ||
    !/^[0-9]+:[0-9]+$/u.test(snapshot.major_minor)
  ) {
    fail("publisher namespace mount is not the exact reviewed nsfs boundary");
  }
  return snapshot;
}

function collectPublisherNetworkSnapshot(request) {
  const namespaceMount = collectPublisherNamespaceMount();
  return {
    caddy_dependency: collectPublisherCaddyDependency(),
    forwarding_sysctls: collectPublisherSysctls(),
    namespace_mount: namespaceMount,
    namespace_owner: collectPublisherNamespaceOwner(request, namespaceMount),
  };
}

function publisherPublicationReceiptPathV1(expected, invocationId) {
  if (
    typeof invocationId !== "string" ||
    !/^[0-9a-f]{32}$/u.test(invocationId) ||
    /^0{32}$/u.test(invocationId)
  ) {
    fail("publisher receipt selection requires one non-zero lowercase InvocationID");
  }
  return `${expected.file.directory}/${invocationId}${expected.file.filename_suffix}`;
}

function parsePublisherArtifactEventIdentitiesV1(bytes, path) {
  const artifact = strictJsonBytes(bytes, `publisher artifact ${path}`);
  const isEventMessage = (value) =>
    Array.isArray(value) &&
    value.length === 2 &&
    value[0] === "EVENT" &&
    value[1] !== null &&
    typeof value[1] === "object" &&
    !Array.isArray(value[1]);
  const messages = isEventMessage(artifact)
    ? [artifact]
    : Array.isArray(artifact) && artifact.length === 16 && artifact.every(isEventMessage)
      ? artifact
      : fail(`publisher artifact ${path} is not one EVENT or one exact 16-EVENT bundle`);
  return messages.map((message, index) => {
    const event = message[1];
    exactKeys(
      event,
      ["content", "created_at", "id", "kind", "pubkey", "sig", "tags"],
      `publisher artifact ${path} EVENT[${index}]`,
    );
    if (
      !/^[0-9a-f]{64}$/u.test(event.id) ||
      !/^[0-9a-f]{64}$/u.test(event.pubkey) ||
      !/^[0-9a-f]{128}$/u.test(event.sig) ||
      !Number.isSafeInteger(event.created_at) ||
      event.created_at < 0 ||
      !Number.isSafeInteger(event.kind) ||
      event.kind < 0 ||
      typeof event.content !== "string" ||
      !Array.isArray(event.tags)
    ) {
      fail(`publisher artifact ${path} EVENT[${index}] identity is malformed`);
    }
    return Buffer.concat([
      Buffer.from(event.id, "hex"),
      Buffer.from(event.sig, "hex"),
    ]);
  });
}

function computePublisherEventSetFromArtifactBytesV1(artifacts) {
  const identities = [];
  const artifactEventCounts = [];
  for (const { bytes, path } of artifacts) {
    const events = parsePublisherArtifactEventIdentitiesV1(bytes, path);
    artifactEventCounts.push(events.length);
    identities.push(...events);
  }
  if (
    canonicalJson(artifactEventCounts.sort((left, right) => left - right)) !==
      canonicalJson([1, 1, 16])
  ) {
    fail("publisher artifacts are not the reviewed two entries plus checkpoint bundle");
  }
  identities.sort(Buffer.compare);
  for (let index = 1; index < identities.length; index += 1) {
    if (identities[index - 1].subarray(0, 32).equals(identities[index].subarray(0, 32))) {
      fail("publisher artifacts contain a duplicate Nostr event id");
    }
  }
  const count = identities.length;
  const encodedCount = Buffer.alloc(4);
  encodedCount.writeUInt32LE(count);
  const hasher = createHash("sha256")
    .update(Buffer.from("bitcoinpir-directory-event-set-v1\0", "utf8"))
    .update(encodedCount);
  for (const identity of identities) hasher.update(identity);
  return {
    event_count: count,
    event_set_digest_hex: hasher.digest("hex"),
  };
}

export function computePublisherArtifactEventSetForTestV1(artifactBytes) {
  if (
    !Array.isArray(artifactBytes) ||
    artifactBytes.length !== 3 ||
    artifactBytes.some(
      (bytes) => !Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > MAX_JSON_BYTES,
    )
  ) {
    fail("publisher event-set test inputs must be exactly three bounded Buffers");
  }
  return computePublisherEventSetFromArtifactBytesV1(
    artifactBytes.map((bytes, index) => ({
      bytes,
      path: `/test/publisher-artifact-${index}.json`,
    })),
  );
}

function collectPublisherCurrentEventSetV1(expected) {
  const artifacts = expected.artifacts.map((pin) => {
    const collected = readOneLinkRegularBoundToDescriptor(
      pin.path,
      `publisher artifact ${pin.path}`,
      MAX_JSON_BYTES,
    );
    if (hashBytes(collected.bytes) !== pin.sha256) {
      fail(`publisher artifact ${pin.path} no longer matches its installed-file pin`);
    }
    return { bytes: collected.bytes, path: pin.path };
  });
  return computePublisherEventSetFromArtifactBytesV1(artifacts);
}

function collectPublisherPublicationReceiptPassV1(request, invocationId) {
  const expected = expectedPublisherPublicationReceiptRequestV1(request);
  const receiptPath = publisherPublicationReceiptPathV1(expected, invocationId);
  const parentPath = expected.file.directory;
  const parentPaths = secretDirectoryChainPaths(parentPath).map(
    (entry) => entry.target_path,
  );
  const parentBundle = collectSecretParentDirectoriesBound(parentPaths);
  const parentDirectory = parentBundle.evidence.at(-1);
  const parentFingerprint = parentBundle.privateFingerprints.at(-1)?.fingerprint;
  if (
    parentDirectory?.target_path !== parentPath ||
    parentDirectory.uid !== expected.file.uid ||
    parentDirectory.gid !== expected.file.gid ||
    parentDirectory.mode !== "0700" ||
    parentDirectory.file_type !== "directory" ||
    parentFingerprint === undefined
  ) {
    fail("publisher publication receipt parent is not the publisher-owned 0700 StateDirectory");
  }
  const collected = readOneLinkRegularBoundToDescriptor(
    receiptPath,
    "publisher publication receipt",
    1024 * 1024,
  );
  const receipt = strictJsonBytes(collected.bytes, "publisher publication receipt");
  if (!collected.bytes.equals(Buffer.from(canonicalJson(receipt)))) {
    fail("publisher publication receipt bytes are not canonical JSON");
  }
  for (const key of ["gid", "mode", "nlink", "uid"]) {
    if (collected.fingerprint[key] !== expected.file[key]) {
      fail(`publisher publication receipt ${key} drifted`);
    }
  }
  const currentEventSet = collectPublisherCurrentEventSetV1(expected);
  return {
    ...collected.fingerprint,
    current_event_set: currentEventSet,
    parent_directory: parentDirectory,
    parent_fingerprint: parentFingerprint,
    path: receiptPath,
    receipt,
    sha256: hashBytes(collected.bytes),
  };
}

function collectPublisherNetworkRuntimeEvidence(request, publicationInvocationId) {
  if (request.publisher_network === undefined) return undefined;
  const receiptBefore = collectPublisherPublicationReceiptPassV1(
    request,
    publicationInvocationId,
  );
  const before = collectPublisherNetworkSnapshot(request);
  const firewallBefore = collectPublisherFirewallPass();
  const reload = runAbsolute("/usr/sbin/ufw", ["--dry-run", "reload"], {
    timeout: 30_000,
  });
  if (reload.exit_status !== 0) fail("UFW dry-run reload failed");
  const firewallAfter = collectPublisherFirewallPass();
  const after = collectPublisherNetworkSnapshot(request);
  const receiptAfter = collectPublisherPublicationReceiptPassV1(
    request,
    publicationInvocationId,
  );
  if (canonicalJson(before) !== canonicalJson(after)) {
    fail("publisher namespace or shared-Caddy boundary changed around UFW dry-run reload");
  }
  if (
    canonicalJson(firewallBefore.semantic_outputs) !==
      canonicalJson(firewallAfter.semantic_outputs)
  ) {
    fail("publisher firewall semantics changed around UFW dry-run reload");
  }
  if (canonicalJson(receiptBefore) !== canonicalJson(receiptAfter)) {
    fail("publisher publication receipt generation changed around UFW dry-run reload");
  }
  return {
    boundary_confirmations: [before, after],
    firewall_passes: [firewallBefore, firewallAfter],
    publication_receipt_passes: [receiptBefore, receiptAfter],
    ufw_dry_run_reload: {
      argv: reload.argv,
      exit_status: reload.exit_status,
      stderr_sha256: hashBytes(Buffer.from(reload.stderr)),
      stdout_sha256: hashBytes(Buffer.from(reload.stdout)),
    },
  };
}

function sealPublisherNamespaceOwnerRuntimeEvidence(
  publisherNetwork,
  request,
  publicationInvocationId,
) {
  if (publisherNetwork === undefined) return;
  const boundaries = publisherNetwork.boundary_confirmations;
  if (
    !Array.isArray(boundaries) ||
    boundaries.length !== 2 ||
    canonicalJson(boundaries[0]) !== canonicalJson(boundaries[1])
  ) {
    fail("publisher boundary changed before final namespace-owner sealing");
  }
  const referenceOwner = boundaries[1].namespace_owner;
  const referenceCaddy = boundaries[1].caddy_dependency;
  const receiptPasses = publisherNetwork.publication_receipt_passes;
  if (
    !Array.isArray(receiptPasses) ||
    receiptPasses.length !== 2 ||
    canonicalJson(receiptPasses[0]) !== canonicalJson(receiptPasses[1])
  ) {
    fail("publisher publication receipt changed before final sealing");
  }
  const finalConditions = collectEffectiveConditions(PUBLISHER_NETNS_UNIT);
  validatePublisherOwnerConditions(finalConditions);
  assertEffectiveConditionSnapshotUnchangedV1(
    referenceOwner.condition_confirmations.at(-1),
    finalConditions,
    PUBLISHER_NETNS_UNIT,
  );
  const finalGeneration = collectPublisherOwnerGeneration(
    referenceOwner.effective_properties,
  );
  const finalCaddyConfig = collectPublisherCaddyConfigGeneration();
  const finalCaddyGeneration = collectPublisherCaddyUnitGeneration();
  const finalReceipt = collectPublisherPublicationReceiptPassV1(
    request,
    publicationInvocationId,
  );
  if (
    canonicalJson(finalCaddyConfig) !==
      canonicalJson(referenceCaddy.config_generation_confirmations.at(-1)) ||
    canonicalJson(finalCaddyGeneration) !==
      canonicalJson(referenceCaddy.generation_confirmations.at(-1))
  ) {
    fail("publisher Caddy config or systemd generation changed before final sealing");
  }
  if (canonicalJson(finalReceipt) !== canonicalJson(receiptPasses[0])) {
    fail("publisher publication receipt changed before final sealing");
  }
  receiptPasses.push(finalReceipt);
  for (const boundary of boundaries) {
    const owner = boundary.namespace_owner;
    const caddy = boundary.caddy_dependency;
    if (
      canonicalJson(owner.effective_properties) !==
        canonicalJson(referenceOwner.effective_properties) ||
      canonicalJson(owner.condition_confirmations.at(-1)) !==
        canonicalJson(referenceOwner.condition_confirmations.at(-1)) ||
      canonicalJson(owner.generation_confirmations.at(-1)) !==
        canonicalJson(referenceOwner.generation_confirmations.at(-1)) ||
      canonicalJson(caddy) !== canonicalJson(referenceCaddy)
    ) {
      fail("publisher namespace-owner or Caddy evidence diverged before final sealing");
    }
    owner.condition_confirmations.push(finalConditions.map((entry) => ({ ...entry })));
    owner.generation_confirmations.push({ ...finalGeneration });
    caddy.config_generation_confirmations.push({ ...finalCaddyConfig });
    caddy.generation_confirmations.push({ ...finalCaddyGeneration });
  }
}

function crossSealPublisherPublicationAfterInstalledFilesV1(
  publisherNetwork,
  request,
  publicationUnit,
  publicationInvocationId,
) {
  if (publisherNetwork === undefined) return;
  const publicationRequestUnit = request.units.find(
    (unit) => unit.unit_name === request.publisher_network.publisher_unit,
  );
  if (publicationRequestUnit === undefined || publicationUnit === undefined) {
    fail("publisher publication cross-seal lacks its exact oneshot unit");
  }
  publicationUnit.generation_confirmations.push(
    confirmUnitGeneration(publicationRequestUnit, publicationUnit.properties),
  );
  const receiptPasses = publisherNetwork.publication_receipt_passes;
  if (!Array.isArray(receiptPasses) || receiptPasses.length !== 3) {
    fail("publisher publication receipt lacks its pre-file-revalidation seal");
  }
  const finalReceipt = collectPublisherPublicationReceiptPassV1(
    request,
    publicationInvocationId,
  );
  if (canonicalJson(finalReceipt) !== canonicalJson(receiptPasses[0])) {
    fail("publisher publication receipt changed after installed-file revalidation");
  }
  receiptPasses.push(finalReceipt);
}

function validatePublisherNamespaceOwnerEvidence(owner, request, namespaceMount) {
  const artifacts = publisherOwnerArtifactExpectations(request);
  exactKeys(
    owner,
    [
      "condition_confirmations", "effective_properties", "fragment_sha256",
      "generation_confirmations", "helper_path", "helper_sha256", "process_passes",
    ],
    "publisher namespace-owner evidence",
  );
  if (
    owner.fragment_sha256 !== artifacts.fragment_sha256 ||
    owner.helper_path !== artifacts.helper_path ||
    owner.helper_sha256 !== artifacts.helper_sha256
  ) {
    fail("publisher namespace-owner evidence is not bound to requested installed artifacts");
  }
  validateDigest(owner.fragment_sha256, "publisher namespace-owner evidence fragment digest");
  validateDigest(owner.helper_sha256, "publisher namespace-owner evidence helper digest");
  if (
    !Array.isArray(owner.condition_confirmations) ||
    owner.condition_confirmations.length !== 3 ||
    owner.condition_confirmations.some((confirmation) =>
      canonicalJson(confirmation) !== canonicalJson(owner.condition_confirmations[0]))
  ) {
    fail("publisher namespace-owner Conditions were not stable across three sealing passes");
  }
  for (const conditions of owner.condition_confirmations) {
    validatePublisherOwnerConditions(conditions);
  }
  validatePublisherOwnerEffectiveProperties(owner.effective_properties, artifacts);
  if (
    !Array.isArray(owner.generation_confirmations) ||
    owner.generation_confirmations.length !== 3 ||
    owner.generation_confirmations.some((confirmation) =>
      canonicalJson(confirmation) !== canonicalJson(owner.generation_confirmations[0]))
  ) {
    fail("publisher namespace-owner generation was not stable across three sealing passes");
  }
  for (const confirmation of owner.generation_confirmations) {
    exactKeys(
      confirmation,
      [
        "active_enter_timestamp_monotonic", "active_state", "control_group",
        "invocation_id", "main_pid", "need_daemon_reload",
      ],
      "publisher namespace-owner generation confirmation",
    );
    if (
      confirmation.active_enter_timestamp_monotonic !==
        owner.effective_properties.ActiveEnterTimestampMonotonic ||
      confirmation.active_state !== owner.effective_properties.ActiveState ||
      confirmation.control_group !== owner.effective_properties.ControlGroup ||
      confirmation.invocation_id !== owner.effective_properties.InvocationID ||
      confirmation.main_pid !== owner.effective_properties.MainPID ||
      confirmation.need_daemon_reload !== "no"
    ) {
      fail("publisher namespace-owner confirmation does not bind one loaded generation");
    }
  }
  if (
    !Array.isArray(owner.process_passes) ||
    owner.process_passes.length !== 2 ||
    canonicalJson(owner.process_passes[0]) !== canonicalJson(owner.process_passes[1])
  ) {
    fail("publisher namespace-owner process tree was not stable across two passes");
  }
  for (const pass of owner.process_passes) {
    validatePublisherProcessPass(
      pass,
      owner.effective_properties,
      artifacts,
      namespaceMount,
    );
  }
}

function validatePublisherCaddyConfigGenerationV1(generation, label) {
  exactKeys(
    generation,
    [
      "ctime_ns", "dev", "gid", "ino", "mode", "mtime_ns", "nlink",
      "path", "sha256", "size", "uid",
    ],
    label,
  );
  validateDigest(generation.sha256, `${label} digest`);
  if (
    generation.path !== PUBLISHER_CADDY_CONFIG ||
    generation.uid !== 0 ||
    generation.gid !== 0 ||
    generation.mode !== "0644" ||
    generation.nlink !== 1 ||
    typeof generation.dev !== "string" ||
    !/^(?:0|[1-9][0-9]*)$/u.test(generation.dev) ||
    typeof generation.ino !== "string" ||
    !/^[1-9][0-9]*$/u.test(generation.ino) ||
    typeof generation.ctime_ns !== "string" ||
    !/^(?:0|[1-9][0-9]*)$/u.test(generation.ctime_ns) ||
    typeof generation.mtime_ns !== "string" ||
    !/^(?:0|[1-9][0-9]*)$/u.test(generation.mtime_ns) ||
    !Number.isSafeInteger(generation.size) ||
    generation.size < 1 ||
    generation.size > MAX_JSON_BYTES
  ) {
    fail(`${label} is not the exact descriptor-bound root Caddyfile generation`);
  }
}

function validatePublisherCaddyUnitGenerationV1(generation, label) {
  exactKeys(
    generation,
    [
      "active_enter_timestamp_monotonic", "active_state", "invocation_id",
      "load_state", "main_pid", "need_daemon_reload", "sub_state",
    ],
    label,
  );
  if (
    generation.active_state !== "active" ||
    generation.sub_state !== "running" ||
    generation.load_state !== "loaded" ||
    generation.need_daemon_reload !== "no" ||
    !/^[1-9][0-9]*$/u.test(generation.active_enter_timestamp_monotonic) ||
    !/^[1-9][0-9]*$/u.test(generation.main_pid) ||
    !/^[0-9a-f]{32}$/u.test(generation.invocation_id) ||
    /^0{32}$/u.test(generation.invocation_id)
  ) {
    fail(`${label} does not bind one loaded active Caddy generation`);
  }
}

function validatePublisherPublicationReceiptPassesV1(passes, request) {
  const expected = expectedPublisherPublicationReceiptRequestV1(request);
  if (
    canonicalJson(request.publisher_network.publication_receipt) !==
    canonicalJson(expected)
  ) {
    fail("publisher publication receipt request drifted from the exact publication argv and pins");
  }
  if (
    !Array.isArray(passes) ||
    passes.length !== 4 ||
    passes.some((pass) => canonicalJson(pass) !== canonicalJson(passes[0]))
  ) {
    fail("publisher publication receipt was not stable across four descriptor-bound passes");
  }
  for (const [index, pass] of passes.entries()) {
    const label = `publisher publication receipt pass[${index}]`;
    const receipt = pass.receipt;
    const expectedReceiptPath = publisherPublicationReceiptPathV1(
      expected,
      receipt?.invocation_id,
    );
    exactKeys(
      pass,
      [
        "ctime_ns", "current_event_set", "dev", "gid", "ino", "mode", "mtime_ns", "nlink",
        "parent_directory", "parent_fingerprint", "path", "receipt", "sha256",
        "size", "uid",
      ],
      label,
    );
    for (const key of ["gid", "mode", "nlink", "uid"]) {
      if (pass[key] !== expected.file[key]) {
        fail(`${label} ${key} is not the exact requested receipt file`);
      }
    }
    if (pass.path !== expectedReceiptPath) {
      fail(`${label} pathname is not derived from its exact InvocationID`);
    }
    if (
      !/^(?:0|[1-9][0-9]*)$/u.test(pass.dev) ||
      !/^[1-9][0-9]*$/u.test(pass.ino) ||
      !/^(?:0|[1-9][0-9]*)$/u.test(pass.ctime_ns) ||
      !/^(?:0|[1-9][0-9]*)$/u.test(pass.mtime_ns) ||
      !Number.isSafeInteger(pass.size) ||
      pass.size < 1 ||
      pass.size > 1024 * 1024
    ) {
      fail(`${label} metadata is malformed`);
    }
    validateDigest(pass.sha256, `${label} digest`);
    const receiptBytes = Buffer.from(canonicalJson(pass.receipt));
    if (
      pass.size !== receiptBytes.byteLength ||
      pass.sha256 !== hashBytes(receiptBytes)
    ) {
      fail(`${label} size or digest does not bind its canonical receipt bytes`);
    }
    exactKeys(
      pass.parent_directory,
      [
        "acl_sha256", "capability_sha256", "dev", "expected_type", "file_type",
        "gid", "ino", "mode", "nlink", "size", "stat_command_sha256",
        "target_path", "uid", "xattr_sha256",
      ],
      `${label} parent directory`,
    );
    exactKeys(
      pass.parent_fingerprint,
      [
        "ctime_ns", "dev", "gid", "ino", "mode", "mtime_ns", "nlink",
        "size", "uid",
      ],
      `${label} parent fingerprint`,
    );
    if (
      pass.parent_directory.target_path !== expected.file.directory ||
      pass.parent_directory.file_type !== "directory" ||
      pass.parent_directory.expected_type !== "directory" ||
      pass.parent_directory.uid !== expected.file.uid ||
      pass.parent_directory.gid !== expected.file.gid ||
      pass.parent_directory.mode !== "0700" ||
      pass.parent_fingerprint.uid !== String(expected.file.uid) ||
      pass.parent_fingerprint.gid !== String(expected.file.gid) ||
      pass.parent_fingerprint.mode !== "0700"
    ) {
      fail(`${label} parent is not the exact publisher-owned 0700 StateDirectory`);
    }
    validateSecretParentDirectoryEvidenceMetadata(
      pass.parent_directory,
      pass.parent_directory.target_path,
    );
    for (const key of [
      "acl_sha256", "capability_sha256", "stat_command_sha256", "xattr_sha256",
    ]) {
      validateDigest(pass.parent_directory[key], `${label} parent ${key}`);
    }
    exactKeys(
      receipt,
      [
        "artifact_manifest", "artifacts", "argv", "argv_sha256",
        "directory_mode", "event_count", "event_set_digest_hex",
        "invocation_id", "kind", "outcome", "publisher_pubkey_hex",
        "relay_origins", "schema_version",
      ],
      `${label} document`,
    );
    exactKeys(
      pass.current_event_set,
      ["event_count", "event_set_digest_hex"],
      `${label} current artifact event set`,
    );
    for (const [key, expectedValue] of [
      ["artifact_manifest", expected.artifact_manifest],
      ["artifacts", expected.artifacts],
      ["argv", expected.argv],
      ["argv_sha256", expected.argv_sha256],
      ["directory_mode", expected.directory_mode],
      ["kind", expected.kind],
      ["publisher_pubkey_hex", expected.publisher_pubkey_hex],
      ["relay_origins", expected.relay_origins],
      ["schema_version", expected.schema_version],
    ]) {
      if (canonicalJson(receipt[key]) !== canonicalJson(expectedValue)) {
        fail(`${label} does not bind the current publication ${key} generation`);
      }
    }
    if (
      receipt.outcome !== "published" ||
      !Number.isSafeInteger(receipt.event_count) ||
      receipt.event_count < 1 ||
      receipt.event_count > 16 * 1024 ||
      !/^[0-9a-f]{64}$/u.test(receipt.event_set_digest_hex) ||
      !/^[0-9a-f]{32}$/u.test(receipt.invocation_id) ||
      /^0{32}$/u.test(receipt.invocation_id)
    ) {
      fail(`${label} does not describe one successful bounded publication generation`);
    }
    if (
      receipt.event_count !== pass.current_event_set.event_count ||
      receipt.event_set_digest_hex !== pass.current_event_set.event_set_digest_hex
    ) {
      fail(`${label} event count or digest was not recomputed from the current artifacts`);
    }
  }
}

function validatePublisherPublicationReceiptUnitBindingV1(evidence, request) {
  if (request.publisher_network === undefined) return;
  const pass = evidence.publisher_network.publication_receipt_passes[0];
  const receipt = pass.receipt;
  const unit = evidence.units.find(
    (candidate) =>
      candidate.unit_name === request.publisher_network.publisher_unit,
  );
  if (
    !unit ||
    unit.properties.InvocationID !== receipt.invocation_id ||
    unit.properties.ActiveState !== "active" ||
    unit.properties.SubState !== "exited" ||
    unit.properties.MainPID !== "0" ||
    unit.properties.Result !== "success"
  ) {
    fail("publisher publication receipt is not bound to the exact successful oneshot InvocationID");
  }
  const currentByPath = new Map(
    evidence.installed_files.map((file) => [file.target_path, file.sha256]),
  );
  for (const pin of [receipt.artifact_manifest, ...receipt.artifacts]) {
    if (currentByPath.get(pin.path) !== pin.sha256) {
      fail("publisher publication receipt does not bind the current installed artifact generation");
    }
  }
}

export function validatePublisherNetworkRuntimeEvidenceV1(evidence, request) {
  if (request.publisher_network === undefined) {
    if (evidence !== undefined) fail("non-publisher evidence contains a publisher network section");
    return true;
  }
  exactKeys(
    request.publisher_network,
    [
      "caddy_drop_in_path", "caddy_service_unit", "firewall",
      "forbidden_caddy_reverse_stop_edges", "namespace", "namespace_owner_unit",
      "network_policy_sha256", "publication_mode", "publication_receipt",
      "publication_time_firewall_binding",
      "publisher_unit",
    ],
    "publisher network runtime request",
  );
  validateDigest(request.publisher_network.network_policy_sha256, "publisher network policy digest");
  if (
    canonicalJson(request.publisher_network) !== canonicalJson(
      expectedPublisherNetworkRequest(
        request.publisher_network.network_policy_sha256,
        expectedPublisherPublicationReceiptRequestV1(request),
      ),
    )
  ) {
    fail("publisher network runtime request drifted from the centralized closed profile");
  }
  exactKeys(
    evidence,
    [
      "boundary_confirmations", "firewall_passes", "publication_receipt_passes",
      "ufw_dry_run_reload",
    ],
    "publisher network live evidence",
  );
  validatePublisherPublicationReceiptPassesV1(
    evidence.publication_receipt_passes,
    request,
  );
  if (
    !Array.isArray(evidence.boundary_confirmations) ||
    evidence.boundary_confirmations.length !== 2 ||
    canonicalJson(evidence.boundary_confirmations[0]) !==
      canonicalJson(evidence.boundary_confirmations[1])
  ) {
    fail("publisher boundary confirmations are incomplete or changed");
  }
  for (const boundary of evidence.boundary_confirmations) {
    exactKeys(
      boundary,
      ["caddy_dependency", "forwarding_sysctls", "namespace_mount", "namespace_owner"],
      "publisher boundary confirmation",
    );
    exactKeys(
      boundary.caddy_dependency,
      [
        "after_namespace_owner", "binds_to_namespace_owner",
        "config_generation_confirmations", "drop_in_paths",
        "drop_in_paths_sha256", "generation_confirmations",
        "part_of_namespace_owner", "requires_namespace_owner",
        "wants_namespace_owner",
      ],
      "publisher Caddy dependency evidence",
    );
    if (
      !boundary.caddy_dependency.after_namespace_owner ||
      !boundary.caddy_dependency.wants_namespace_owner ||
      boundary.caddy_dependency.binds_to_namespace_owner ||
      boundary.caddy_dependency.part_of_namespace_owner ||
      boundary.caddy_dependency.requires_namespace_owner
    ) {
      fail("publisher Caddy evidence contains a reverse stop edge or missing ordering edge");
    }
    if (
      canonicalJson(boundary.caddy_dependency.drop_in_paths) !==
        canonicalJson([PUBLISHER_CADDY_DROP_IN]) ||
      boundary.caddy_dependency.drop_in_paths_sha256 !== hashBytes(
        Buffer.from(canonicalJson([PUBLISHER_CADDY_DROP_IN])),
      )
    ) {
      fail("publisher Caddy DropInPaths is not the singleton reviewed drop-in");
    }
    validateDigest(
      boundary.caddy_dependency.drop_in_paths_sha256,
      "publisher Caddy drop-in-set digest",
    );
    if (
      !Array.isArray(boundary.caddy_dependency.config_generation_confirmations) ||
      boundary.caddy_dependency.config_generation_confirmations.length !== 3 ||
      boundary.caddy_dependency.config_generation_confirmations.some((confirmation) =>
        canonicalJson(confirmation) !==
          canonicalJson(boundary.caddy_dependency.config_generation_confirmations[0]))
    ) {
      fail("publisher Caddy config generation was not stable across three sealing passes");
    }
    for (const [index, generation] of
      boundary.caddy_dependency.config_generation_confirmations.entries()) {
      validatePublisherCaddyConfigGenerationV1(
        generation,
        `publisher Caddy config generation[${index}]`,
      );
    }
    if (
      !Array.isArray(boundary.caddy_dependency.generation_confirmations) ||
      boundary.caddy_dependency.generation_confirmations.length !== 3 ||
      boundary.caddy_dependency.generation_confirmations.some((confirmation) =>
        canonicalJson(confirmation) !==
          canonicalJson(boundary.caddy_dependency.generation_confirmations[0]))
    ) {
      fail("publisher Caddy systemd generation was not stable across three sealing passes");
    }
    for (const [index, generation] of
      boundary.caddy_dependency.generation_confirmations.entries()) {
      validatePublisherCaddyUnitGenerationV1(
        generation,
        `publisher Caddy systemd generation[${index}]`,
      );
    }
    if (canonicalJson(boundary.forwarding_sysctls) !== canonicalJson({
      "net.ipv4.ip_forward": 0,
      "net.ipv6.conf.all.forwarding": 0,
    })) {
      fail("publisher forwarding sysctl evidence is not closed");
    }
    exactKeys(
      boundary.namespace_mount,
      [
        "dev", "filesystem_type", "ino", "major_minor", "mount_id",
        "mount_source", "parent_mount_id", "root", "statfs_type",
      ],
      "publisher namespace mount evidence",
    );
    if (
      boundary.namespace_mount.filesystem_type !== "nsfs" ||
      boundary.namespace_mount.mount_source !== "nsfs" ||
      boundary.namespace_mount.root !== "/" ||
      boundary.namespace_mount.statfs_type !== NSFS_MAGIC ||
      !/^[1-9][0-9]*$/u.test(boundary.namespace_mount.dev) ||
      !/^[1-9][0-9]*$/u.test(boundary.namespace_mount.ino) ||
      !/^[1-9][0-9]*$/u.test(boundary.namespace_mount.mount_id) ||
      !/^[1-9][0-9]*$/u.test(boundary.namespace_mount.parent_mount_id) ||
      !/^[0-9]+:[0-9]+$/u.test(boundary.namespace_mount.major_minor)
    ) {
      fail("publisher namespace mount evidence is not one nsfs mount");
    }
    validatePublisherNamespaceOwnerEvidence(
      boundary.namespace_owner,
      request,
      boundary.namespace_mount,
    );
  }
  if (!Array.isArray(evidence.firewall_passes) || evidence.firewall_passes.length !== 2) {
    fail("publisher firewall requires two semantic passes");
  }
  for (const pass of evidence.firewall_passes) {
    exactKeys(
      pass,
      ["output_sha256", "semantic_outputs", "semantic_profile"],
      "publisher firewall pass",
    );
    if (
      pass.semantic_profile !== "bitcoinpir-publisher-ufw-closed-v1" ||
      canonicalJson(pass.semantic_outputs) !== canonicalJson(EXPECTED_PUBLISHER_FIREWALL_SEMANTICS)
    ) {
      fail("publisher firewall pass is not the closed UFW/raw/nft policy");
    }
    exactKeys(
      pass.output_sha256,
      PUBLISHER_FIREWALL_OUTPUT_KEYS,
      "publisher firewall output digests",
    );
    for (const [key, digest] of Object.entries(pass.output_sha256)) {
      validateDigest(digest, `publisher firewall ${key} digest`);
    }
  }
  if (
    canonicalJson(evidence.firewall_passes[0].semantic_outputs) !==
      canonicalJson(evidence.firewall_passes[1].semantic_outputs)
  ) {
    fail("publisher firewall semantic passes changed around dry-run reload");
  }
  exactKeys(
    evidence.ufw_dry_run_reload,
    ["argv", "exit_status", "stderr_sha256", "stdout_sha256"],
    "publisher UFW dry-run evidence",
  );
  if (
    canonicalJson(evidence.ufw_dry_run_reload.argv) !==
      canonicalJson(["/usr/sbin/ufw", "--dry-run", "reload"]) ||
    evidence.ufw_dry_run_reload.exit_status !== 0
  ) {
    fail("publisher UFW dry-run reload did not complete with exact argv");
  }
  validateDigest(evidence.ufw_dry_run_reload.stderr_sha256, "publisher UFW stderr digest");
  validateDigest(evidence.ufw_dry_run_reload.stdout_sha256, "publisher UFW stdout digest");
  return true;
}


function validateResolvedDirectoryRelayLiveRequestShape(request) {
  if (!isResolvedDirectoryRelayRuntimeRequest(request)) {
    fail("live directory relay request is not the exact resolved profile");
  }
  const unit = request.units[0];
  const identity = request.service_identities?.[0];
  const binaryPath = unit.exec_start[0].split(" ", 1)[0];
  const configPath = "/etc/bitcoinpir/payment-v1/directory-relay/config.toml";
  const fragmentPath = "/etc/systemd/system/bitcoinpir-directory-relay.service";
  const expected = new Map([
    [
      "/etc/bitcoinpir/payment-v1/directory-relay/binary.sha256",
      { gid: 0, mode: "0444", uid: 0 },
    ],
    [
      "/etc/bitcoinpir/payment-v1/directory-relay/config.sha256",
      { gid: 0, mode: "0444", uid: 0 },
    ],
    [configPath, { gid: 52952, mode: "0400", uid: 52951 }],
    [fragmentPath, { gid: 0, mode: "0644", uid: 0 }],
    [binaryPath, { gid: 0, mode: "0555", uid: 0 }],
  ]);
  const files = request.installed_files ?? [];
  const fileShapeMatches =
    canonicalJson(files.map((file) => file.target_path)) ===
      canonicalJson([...expected.keys()]) &&
    files.every((file) => {
      const metadata = expected.get(file.target_path);
      return (
        metadata !== undefined &&
        file.file_type === "regular" &&
        file.gid === metadata.gid &&
        file.mode === metadata.mode &&
        file.nlink === 1 &&
        file.uid === metadata.uid
      );
    });
  if (
    request.service_identities?.length !== 1 ||
    identity?.unit_name !== unit.unit_name ||
    identity.uid !== 52951 ||
    identity.gid !== 52952 ||
    !fileShapeMatches ||
    canonicalJson(request.systemd_analyze_argv) !== canonicalJson([
      "/usr/bin/systemd-analyze",
      "verify",
      fragmentPath,
    ]) ||
    request.runtime_paths?.length !== 0 ||
    request.tmpfiles_directories?.length !== 0 ||
    request.secret_files?.length !== 1 ||
    request.secret_files[0].consumer_unit_name !== unit.unit_name ||
    request.secret_files[0].target_path !== configPath ||
    request.secret_files[0].uid !== 52951 ||
    request.secret_files[0].gid !== 52952 ||
    request.secret_files[0].mode !== "0400" ||
    canonicalJson(unit.hardening.ReadOnlyPaths ?? []) !== canonicalJson([
      `/etc/bitcoinpir/payment-v1/directory-relay ${dirname(binaryPath)}`,
    ])
  ) {
    fail("live resolved directory-relay request artifact or identity closure is not reviewed");
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
  const hasPublisherNetwork = request.publisher_network !== undefined;
  if (
    request.deployment_profile === "directory-relay-v1" &&
    !isResolvedDirectoryRelayRuntimeRequest(request)
  ) {
    fail("unresolved directory-relay-v1 cannot produce live runtime evidence");
  }
  if (request.deployment_profile === "directory-relay-v1") {
    validateResolvedDirectoryRelayLiveRequestShape(request);
  }
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
      ...(hasPublisherNetwork ? ["publisher_network"] : []),
      "runtime_directories",
      "runtime_paths",
      "schema_version",
      "secret_access_checks",
      "secret_parent_directories",
      "systemd_analyze_verify",
      "systemd_manager_passes",
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
  validateRuntimePropertyRequestSchema(request, "runtime request");
  validatePublisherNetworkRuntimeEvidenceV1(evidence.publisher_network, request);
  if (!Array.isArray(request.service_identities) || request.service_identities.length !== request.units.length) {
    fail("runtime request service identity bindings are incomplete");
  }
  validateRuntimeServiceIdentityIds(request.service_identities, "live runtime request");
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
  if (evidence.host.systemd_version !== request.systemd_version) {
    fail("live evidence systemd build is not the reviewed request build");
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
  validateSystemdManagerPassesV1(
    evidence.systemd_manager_passes,
    "live systemd manager",
  );

  validateTrustedCommandClosure(evidence.trusted_commands, "live evidence", request);

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
    validateSecretParentDirectoryEvidenceMetadata(
      actual,
      expectedSecretParentPaths[index],
    );
    for (const key of ["acl_sha256", "capability_sha256", "stat_command_sha256", "xattr_sha256"]) {
      validateDigest(actual[key], `live secret parent ${key}`);
    }
  }
  validateSecretParentDirectoryPolicyV1(
    request.secret_files,
    request.service_identities,
    evidence.secret_parent_directories,
  );
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
      [
        "conditions",
        "credential_properties",
        "fragment_sha256",
        "generation_confirmations",
        "process_identity",
        "properties",
        "service_property_passes",
        "unit_dependencies",
        "unit_name",
      ],
      `live units[${index}]`,
    );
    if (actual.unit_name !== expected.unit_name || actual.properties.FragmentPath !== expected.fragment_path) {
      fail(`live systemd unit identity drift: ${expected.unit_name}`);
    }
    if (actual.properties.DropInPaths !== "") fail(`live systemd drop-in detected: ${expected.unit_name}`);
    for (const key of ["ExecStartPost", "ExecCondition", "EnvironmentFiles", "RootDirectory", "RootImage", "BindPaths"]) {
      if (actual.properties[key] !== "") fail(`live systemd ${key} is forbidden: ${expected.unit_name}`);
    }
    validateEffectiveCredentialProperties(
      expected.unit_name,
      actual.credential_properties,
    );
    const fragment = request.installed_files.find((file) => file.target_path === expected.fragment_path);
    if (!fragment || actual.fragment_sha256 !== fragment.sha256) {
      fail(`live systemd fragment hash drift: ${expected.unit_name}`);
    }
    if (
      !Array.isArray(actual.service_property_passes) ||
      actual.service_property_passes.length !== 2
    ) {
      fail(`live service property passes are incomplete: ${expected.unit_name}`);
    }
    for (const [passIndex, pass] of actual.service_property_passes.entries()) {
      exactKeys(
        pass,
        ["observed_uptime_milliseconds", "properties"],
        `live ${expected.unit_name} service property pass[${passIndex}]`,
      );
      if (
        !Number.isSafeInteger(pass.observed_uptime_milliseconds) ||
        pass.observed_uptime_milliseconds < evidence.host.uptime_started_milliseconds ||
        pass.observed_uptime_milliseconds > evidence.host.uptime_finished_milliseconds ||
        (passIndex > 0 &&
          pass.observed_uptime_milliseconds <
            actual.service_property_passes[passIndex - 1].observed_uptime_milliseconds)
      ) {
        fail(`live service property pass uptime is invalid: ${expected.unit_name}`);
      }
    }
    const lifecycle = validateEffectiveUnitProperties(
      expected,
      actual.properties,
      actual.credential_properties,
      actual.conditions,
      actual.unit_dependencies,
      actual.service_property_passes[0].properties,
      actual.service_property_passes[0].observed_uptime_milliseconds,
      request.deployment_profile,
    );
    validateEffectiveServicePropertiesV1(
      expected,
      actual.service_property_passes[1].properties,
      actual.service_property_passes[1].observed_uptime_milliseconds,
    );
    assertEffectiveSystemdPolicySnapshotUnchangedV1(
      actual.unit_dependencies,
      actual.unit_dependencies,
      actual.service_property_passes[0].properties,
      actual.service_property_passes[1].properties,
      expected.unit_name,
    );
    validateGenerationConfirmations(
      actual.generation_confirmations,
      actual.properties,
      expected.unit_name,
      request.publisher_network?.publisher_unit === expected.unit_name ? 4 : 3,
    );
    lifecycleByUnit.set(expected.unit_name, lifecycle);
  }
  validatePublisherPublicationReceiptUnitBindingV1(evidence, request);
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
    fail("live NSS evidence does not use the reviewed files-authoritative backend");
  }
  if (evidence.nss.enumeration_kind !== NSS_ENUMERATION_KIND) {
    fail("live NSS evidence does not use the reviewed complete-enumeration profile");
  }
  assertReviewedNssSources(evidence.nss.sources, "live NSS sources");
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
    finished.systemd_version === started.systemd_version &&
    canonicalJson(finished.pid1_nspid) === canonicalJson(started.pid1_nspid)
  );
}

function collectStoppedPreparationEvidence({
  bundleRoot,
  approvedManifestSha256,
  approvedPlanSha256,
  expectedMachineIdSha256,
}, {
  command,
  evidenceKind,
  profile,
  schemaVersion,
  allowEmptyRuntimeSockets,
  includeInstalledShape = false,
  includePrivateLoaderShape = false,
  validate,
}) {
  assertRootLinuxCollector(command);
  validateDigest(approvedManifestSha256, "approved manifest SHA-256");
  validateDigest(approvedPlanSha256, "approved plan SHA-256");
  validateDigest(expectedMachineIdSha256, "expected machine-id SHA-256");
  const { request } = readPinnedBundle(bundleRoot, approvedManifestSha256, approvedPlanSha256);
  if (request.deployment_profile !== profile) {
    fail(`${command} only accepts the reviewed ${profile} profile`);
  }
  const trustedCommands = beginTrustedCommandSession(
    [...requiredCommandsForRequest(request), process.execPath].sort(),
  );
  const started = Math.floor(Date.now() / 1000);
  const hostStarted = readHostBinding();
  if (hostStarted.machine_id_sha256 !== expectedMachineIdSha256) {
    fail("collector is running on an unapproved host");
  }
  const systemdManagerStarted = collectSystemdManagerPropertiesV1();
  validateSystemdManagerPropertiesV1(
    systemdManagerStarted,
    "initial stopped systemd manager properties",
  );
  const challengeHex = randomBytes(32).toString("hex");
  const nss = collectNss();
  const accountPolicyStarted = collectLockedServiceAccountPolicy(request, nss);
  const stoppedUnitStarted = collectStoppedUnitStates(request);
  const installedFilesStarted = includeInstalledShape
    ? request.installed_files.map(collectInstalledFile)
    : null;
  const secretParentDirectoryBundle = includePrivateLoaderShape
    ? collectSecretParentDirectories(request.secret_files)
    : null;
  const secretParentDirectories = secretParentDirectoryBundle?.evidence ?? null;
  const secretAccessChecks = includePrivateLoaderShape
    ? collectSecretAccessChecks(request, nss)
    : null;
  if (includePrivateLoaderShape) {
    confirmSecretFilesUnchanged(
      installedFilesStarted,
      request,
      "around stopped-loader access probes",
    );
    confirmSecretParentDirectoriesUnchanged(
      secretParentDirectoryBundle,
      request,
      "around stopped-loader access probes",
    );
  }
  const unitConfigurationStarted = collectStoppedUnitConfigurations(request);
  const analyze = includeInstalledShape
    ? runAbsolute(request.systemd_analyze_argv[0], request.systemd_analyze_argv.slice(1), {
      allowOutput: false,
      timeout: 30_000,
    })
    : null;
  if (analyze !== null && analyze.exit_status !== 0) {
    fail("stopped directory-relay systemd-analyze verify failed");
  }
  const runtimeSocketAbsenceStarted = collectAbsentRuntimeSockets(request, {
    allowEmpty: allowEmptyRuntimeSockets,
  });
  const protectedProcessClosure = collectProtectedCredentialProcessClosureV1(
    protectedCredentialsForRequest(request, nss),
  );
  const runtimeSocketAbsenceFinished = collectAbsentRuntimeSockets(request, {
    allowEmpty: allowEmptyRuntimeSockets,
  });
  const installedFilesFinished = includeInstalledShape
    ? request.installed_files.map(collectInstalledFile)
    : null;
  const accountPolicyFinished = collectLockedServiceAccountPolicy(request, nss);
  if (canonicalJson(accountPolicyStarted) !== canonicalJson(accountPolicyFinished)) {
    fail("service account login policy changed during stopped-edge collection");
  }
  confirmCompleteNssSnapshotUnchanged(nss);
  const hostFinished = readHostBinding();
  if (!sameHostGeneration(hostStarted, hostFinished)) {
    fail("host or boot identity changed during stopped-edge collection");
  }
  if (includePrivateLoaderShape) {
    confirmSecretFilesUnchanged(
      installedFilesStarted,
      request,
      "at the stopped-loader final seal",
    );
    confirmSecretParentDirectoriesUnchanged(
      secretParentDirectoryBundle,
      request,
      "at the stopped-loader final seal",
    );
  }
  // The final external-state pass is deliberately limited to typed credential
  // properties, Conditions and stopped-unit generation. It follows every
  // account, NSS, host and private-loader probe and immediately precedes the
  // timestamp/evidence object.
  const unitConfigurationFinished = collectStoppedUnitConfigurations(request);
  const stoppedUnitFinished = collectStoppedUnitStates(request);
  const systemdManagerFinished = collectSystemdManagerPropertiesV1();
  validateSystemdManagerPropertiesV1(
    systemdManagerFinished,
    "final stopped systemd manager properties",
  );
  const finished = Math.floor(Date.now() / 1000);
  finishTrustedCommandSession(trustedCommands);
  const evidence = {
    account_policy: accountPolicyFinished,
    approved_plan_sha256: approvedPlanSha256,
    challenge_hex: challengeHex,
    collected_finished_unix_seconds: finished,
    collected_started_unix_seconds: started,
    collector: RUNTIME_COLLECTOR,
    collector_process: { egid: process.getegid(), euid: process.geteuid(), pid: process.pid },
    evidence_kind: evidenceKind,
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
    ...(includeInstalledShape ? {
      installed_file_passes: [installedFilesStarted, installedFilesFinished],
    } : {}),
    manifest_sha256: approvedManifestSha256,
    nss,
    protected_process_closure: protectedProcessClosure,
    runtime_socket_absence_passes: [
      runtimeSocketAbsenceStarted,
      runtimeSocketAbsenceFinished,
    ],
    schema_version: schemaVersion,
    ...(includePrivateLoaderShape ? {
      secret_access_checks: secretAccessChecks,
      secret_parent_directories: secretParentDirectories,
    } : {}),
    stopped_unit_passes: [stoppedUnitStarted, stoppedUnitFinished],
    ...(includeInstalledShape ? {
      systemd_analyze_verify: analyze,
    } : {}),
    systemd_manager_passes: [systemdManagerStarted, systemdManagerFinished],
    trusted_commands: trustedCommands,
    unit_configuration_passes: [unitConfigurationStarted, unitConfigurationFinished],
  };
  validate({
    evidence,
    expectedBootId: hostStarted.boot_id,
    expectedMachineIdSha256,
    maxAgeSeconds: 0,
    nowUnixSeconds: finished,
    request,
  });
  return evidence;
}

function confirmSecretFilesUnchanged(installedFiles, request, stage) {
  for (const secret of request.secret_files) {
    const before = installedFiles.find((entry) => entry.target_path === secret.target_path);
    const expected = request.installed_files.find((entry) => entry.target_path === secret.target_path);
    if (!before || !expected) {
      fail(`secret is absent from installed-file closure: ${secret.target_path}`);
    }
    const after = collectInstalledFile(expected);
    assertInstalledFileCollectionsUnchanged(before, after, stage, secret.target_path);
  }
}

function confirmAllInstalledFilesUnchanged(installedFiles, request, stage) {
  if (
    installedFiles.length !== request.installed_files.length ||
    installedFiles.some(
      (entry, index) => entry.target_path !== request.installed_files[index].target_path,
    )
  ) {
    fail("installed-file evidence is not the exact ordered request closure");
  }
  for (let index = 0; index < request.installed_files.length; index += 1) {
    const expected = request.installed_files[index];
    const after = collectInstalledFile(expected);
    assertInstalledFileCollectionsUnchanged(
      installedFiles[index],
      after,
      stage,
      expected.target_path,
    );
  }
}

function confirmSecretParentDirectoriesUnchanged(
  secretParentDirectoryBundle,
  request,
  stage,
) {
  const confirmation = collectSecretParentDirectories(request.secret_files);
  assertSecretParentDirectoryBundlesUnchanged(
    secretParentDirectoryBundle,
    confirmation,
    stage,
  );
}

export function collectStoppedEdgeActivationEvidence(options) {
  return collectStoppedPreparationEvidence(options, {
    allowEmptyRuntimeSockets: false,
    command: "collect-stopped-edge",
    evidenceKind: STOPPED_EDGE_EVIDENCE_KIND,
    profile: "edge-hetzner-v1",
    schemaVersion: STOPPED_EDGE_SCHEMA_VERSION,
    validate: validateStoppedEdgeActivationEvidence,
  });
}

export function collectStoppedRelayPreparationEvidence(options) {
  return collectStoppedPreparationEvidence(options, {
    allowEmptyRuntimeSockets: true,
    command: "collect-stopped-relay",
    evidenceKind: STOPPED_RELAY_EVIDENCE_KIND,
    includeInstalledShape: true,
    includePrivateLoaderShape: true,
    profile: "directory-relay-v1",
    schemaVersion: STOPPED_RELAY_SCHEMA_VERSION,
    validate: validateStoppedRelayPreparationEvidence,
  });
}

export function collectLiveRuntimeEvidence({ bundleRoot, approvedManifestSha256, approvedPlanSha256, expectedMachineIdSha256 }) {
  assertRootLinuxCollector("collect-live");
  validateDigest(approvedManifestSha256, "approved manifest SHA-256");
  validateDigest(approvedPlanSha256, "approved plan SHA-256");
  validateDigest(expectedMachineIdSha256, "expected machine-id SHA-256");
  const { request } = readPinnedBundle(bundleRoot, approvedManifestSha256, approvedPlanSha256);
  if (
    request.deployment_profile === "directory-relay-v1" &&
    !isResolvedDirectoryRelayRuntimeRequest(request)
  ) {
    fail("unresolved directory-relay-v1 cannot produce live runtime evidence");
  }
  if (request.deployment_profile === "directory-relay-v1") {
    validateResolvedDirectoryRelayLiveRequestShape(request);
  }
  const trustedCommands = beginTrustedCommandSession(
    [...requiredCommandsForRequest(request), process.execPath].sort(),
  );
  const started = Math.floor(Date.now() / 1000);
  const hostStarted = readHostBinding();
  if (hostStarted.machine_id_sha256 !== expectedMachineIdSha256) fail("collector is running on an unapproved host");
  const systemdManagerStarted = collectSystemdManagerPropertiesV1();
  validateSystemdManagerPropertiesV1(
    systemdManagerStarted,
    "initial systemd manager properties",
  );
  const challengeHex = randomBytes(32).toString("hex");
  const nss = collectNss();
  const installedFiles = request.installed_files.map(collectInstalledFile);
  const runtimeDirectories = request.tmpfiles_directories.map((entry) => collectTmpfilesDirectory(entry, nss));
  const runtimePaths = request.runtime_paths.map(collectRuntimePath);
  const secretParentDirectoryBundle = collectSecretParentDirectories(request.secret_files);
  const secretParentDirectories = secretParentDirectoryBundle.evidence;
  const secretAccessChecks = collectSecretAccessChecks(request, nss);
  confirmSecretFilesUnchanged(installedFiles, request, "around access probes");
  confirmSecretParentDirectoriesUnchanged(
    secretParentDirectoryBundle,
    request,
    "around access probes",
  );
  const units = request.units.map((unit) =>
    collectUnit(
      unit,
      nss,
      request.service_identities,
      request.deployment_profile,
    ),
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
  confirmCompleteNssSnapshotUnchanged(nss);
  // Complete expensive secret revalidation only after every earlier long host,
  // systemd, procfs, NSS and runtime-path probe. File content/metadata is
  // rechecked first; the descriptor-bound directory-set pass then also catches
  // namespace changes made while those file probes ran.
  confirmSecretFilesUnchanged(
    installedFiles,
    request,
    "during final evidence sealing",
  );
  confirmSecretParentDirectoriesUnchanged(
    secretParentDirectoryBundle,
    request,
    "during final evidence sealing",
  );
  // The bounded publisher namespace/firewall transaction contains the last
  // long external-state probes. Complete it before the final lightweight unit
  // pass so no expensive command can widen the interval after the protected
  // service Conditions and generation are sealed.
  const publicationUnit = request.publisher_network === undefined
    ? undefined
    : units.find(
      (unit) =>
        unit.unit_name === request.publisher_network.publisher_unit,
    );
  if (request.publisher_network !== undefined && publicationUnit === undefined) {
    fail("publisher runtime request has no collected publication oneshot unit");
  }
  const publisherNetwork = collectPublisherNetworkRuntimeEvidence(
    request,
    publicationUnit?.properties.InvocationID,
  );
  // Per-unit checks inside collectUnit are not enough: the final external-state
  // pass is deliberately lightweight and comes after the expensive secret
  // commands. A profile sentinel or unit generation could otherwise change
  // while later probes run. Recheck structured credential properties and
  // Conditions, typed dependency/timeout state and each same unit generation
  // here. Every service-property read is immediately followed by the boot
  // uptime used for its watchdog-freshness bound; no earlier timestamp is
  // reused.
  const finalSystemdSnapshots = [];
  for (let index = 0; index < request.units.length; index += 1) {
    const finalCredentialProperties = collectEffectiveCredentialProperties(
      request.units[index].unit_name,
    );
    assertEffectiveCredentialSnapshotUnchangedV1(
      units[index].credential_properties,
      finalCredentialProperties,
      request.units[index].unit_name,
    );
    const finalConditions = collectEffectiveConditions(request.units[index].unit_name);
    const finalUnitDependencies = collectEffectiveUnitDependenciesV1(
      request.units[index].unit_name,
    );
    const finalServiceProperties = collectEffectiveServicePropertiesV1(
      request.units[index].unit_name,
    );
    const observedUptimeMilliseconds = readLinuxUptimeMillisecondsV1();
    assertEffectiveConditionSnapshotUnchangedV1(
      units[index].conditions,
      finalConditions,
      request.units[index].unit_name,
    );
    units[index].generation_confirmations.push(
      confirmUnitGeneration(request.units[index], units[index].properties),
    );
    finalSystemdSnapshots.push({
      observedUptimeMilliseconds,
      serviceProperties: finalServiceProperties,
      unitDependencies: finalUnitDependencies,
    });
  }
  const systemdManagerFinished = collectSystemdManagerPropertiesV1();
  validateSystemdManagerPropertiesV1(
    systemdManagerFinished,
    "final systemd manager properties",
  );
  const hostFinished = readHostBinding();
  if (!sameHostGeneration(hostStarted, hostFinished)) {
    fail("host or boot identity changed during live collection");
  }
  for (let index = 0; index < request.units.length; index += 1) {
    validateEffectiveServicePropertiesV1(
      request.units[index],
      finalSystemdSnapshots[index].serviceProperties,
      finalSystemdSnapshots[index].observedUptimeMilliseconds,
    );
    assertEffectiveSystemdPolicySnapshotUnchangedV1(
      units[index].unit_dependencies,
      finalSystemdSnapshots[index].unitDependencies,
      units[index].service_property_passes[0].properties,
      finalSystemdSnapshots[index].serviceProperties,
      request.units[index].unit_name,
    );
    units[index].service_property_passes.push({
      observed_uptime_milliseconds:
        finalSystemdSnapshots[index].observedUptimeMilliseconds,
      properties: finalSystemdSnapshots[index].serviceProperties,
    });
  }
  // The namespace owner is an auxiliary unit rather than a request.units entry.
  // Seal its effective Conditions and systemd generation after the same final
  // loop so owner-only activation sentinels and MainPID/InvocationID cannot
  // drift in the tail between network collection and evidence construction.
  sealPublisherNamespaceOwnerRuntimeEvidence(
    publisherNetwork,
    request,
    publicationUnit?.properties.InvocationID,
  );
  // The third descriptor-bound receipt read above seals the publication after
  // the final requested-unit and auxiliary namespace/Caddy generations. Only
  // now revalidate the entire installed-file closure, so a non-artifact unit or
  // helper cannot drift in the former tail window. A final lightweight
  // publication-unit/receipt cross-seal then proves that the successful oneshot
  // InvocationID and receipt generation still bracket that expensive pass.
  if (publisherNetwork !== undefined) {
    confirmAllInstalledFilesUnchanged(
      installedFiles,
      request,
      "after final publisher receipt sealing",
    );
    crossSealPublisherPublicationAfterInstalledFilesV1(
      publisherNetwork,
      request,
      publicationUnit,
      publicationUnit?.properties.InvocationID,
    );
  }
  const hostSealed = readHostBinding();
  if (!sameHostGeneration(hostStarted, hostSealed)) {
    fail("host or boot identity changed during publisher network sealing");
  }
  finishTrustedCommandSession(trustedCommands);
  const finished = Math.floor(Date.now() / 1000);
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
      uptime_finished_milliseconds: hostSealed.uptime_milliseconds,
      uptime_started_milliseconds: hostStarted.uptime_milliseconds,
    },
    installed_files: installedFiles,
    manifest_sha256: approvedManifestSha256,
    nss,
    protected_process_closure: protectedProcessClosure,
    ...(publisherNetwork === undefined ? {} : { publisher_network: publisherNetwork }),
    runtime_directories: runtimeDirectories,
    runtime_paths: runtimePaths,
    schema_version: LIVE_SCHEMA_VERSION,
    secret_access_checks: secretAccessChecks,
    secret_parent_directories: secretParentDirectories,
    systemd_analyze_verify: analyze,
    systemd_manager_passes: [systemdManagerStarted, systemdManagerFinished],
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
    "collect-stopped-relay",
    "verify-offline",
    "verify-stopped-edge-offline",
    "verify-stopped-relay-offline",
  ].includes(command)) {
    fail("usage: payment-v1-linux-runtime-evidence.mjs <collect-live|collect-stopped-edge|collect-stopped-relay|verify-offline|verify-stopped-edge-offline|verify-stopped-relay-offline> --bundle ABS --approved-manifest-sha256 HEX --approved-plan-sha256 HEX --expected-machine-id-sha256 HEX --output ABS | --evidence ABS --trusted-evidence-sha256 HEX --expected-boot-id UUID");
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
    const collectors = {
      "collect-live": collectLiveRuntimeEvidence,
      "collect-stopped-edge": collectStoppedEdgeActivationEvidence,
      "collect-stopped-relay": collectStoppedRelayPreparationEvidence,
    };
    const evidence = collectors[command](common);
    writeFileSync(values["--output"], canonicalJson(evidence), { flag: "wx", mode: 0o600 });
    const label = {
      "collect-live": "live",
      "collect-stopped-edge": "stopped-edge",
      "collect-stopped-relay": "stopped-directory-relay",
    }[command];
    process.stdout.write(`payment-v1-linux-runtime-evidence: ${label} PASS challenge=${evidence.challenge_hex}\n`);
    return;
  }
  const { request } = readPinnedBundle(common.bundleRoot, common.approvedManifestSha256, common.approvedPlanSha256);
  const evidenceBytes = readOneLinkRegular(values["--evidence"], "offline live evidence");
  if (hashBytes(evidenceBytes) !== values["--trusted-evidence-sha256"]) {
    fail("offline evidence does not match the out-of-band trusted SHA-256 pin");
  }
  const evidence = strictJsonBytes(evidenceBytes, "offline live evidence");
  const validators = {
    "verify-offline": validateLiveRuntimeEvidence,
    "verify-stopped-edge-offline": validateStoppedEdgeActivationEvidence,
    "verify-stopped-relay-offline": validateStoppedRelayPreparationEvidence,
  };
  const validate = validators[command];
  validate({
    evidence,
    expectedBootId: values["--expected-boot-id"],
    expectedMachineIdSha256: common.expectedMachineIdSha256,
    maxAgeSeconds: Number.MAX_SAFE_INTEGER,
    nowUnixSeconds: evidence.collected_finished_unix_seconds,
    request,
  });
  const label = {
    "verify-offline": "live",
    "verify-stopped-edge-offline": "stopped-edge",
    "verify-stopped-relay-offline": "stopped-directory-relay",
  }[command];
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
