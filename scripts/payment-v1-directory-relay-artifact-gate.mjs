#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import {
  validateRelayConfigExample,
  validateRelaySelection,
} from "./payment-v1-deployment-template-gate.mjs";
import {
  canonicalJson,
  parseStrictJson,
} from "./payment-v1-rendered-artifact-gate.mjs";

export const DIRECTORY_RELAY_BUILD_PROFILE =
  "bitcoinpir-directory-relay-linux-amd64-reproducible-v1";
export const DIRECTORY_RELAY_SOURCE_REPOSITORY =
  "https://github.com/Bitcoin-PIR/Bitcoin-PIR.git";
export const DIRECTORY_RELAY_BUILD_IMAGE =
  "docker.io/library/rust@sha256:4ec71e955e6c08aeb238885083222ddff79d82eb87654a96c76e38e94da1a53b";
export const DIRECTORY_RELAY_RUST_TOOLCHAIN =
  "1.94.1-x86_64-unknown-linux-gnu";
export const DIRECTORY_RELAY_UNPRIVILEGED_UID = 65532;
export const DIRECTORY_RELAY_UNPRIVILEGED_GID = 65532;
export const DIRECTORY_RELAY_CARGO_COMMAND =
  "cargo build --release --locked --offline -p bitcoinpir-directory-relay --bin bitcoinpir-directory-relay";
export const DIRECTORY_RELAY_PINNED_GIT_GLOBAL_OPTIONS = Object.freeze([
  "--no-replace-objects",
  "-c",
  "core.attributesFile=/dev/null",
  "--git-dir=/work/source.git",
]);

const MAX_ARCHIVE_BYTES = 512 * 1024 * 1024;
const MAX_BINARY_BYTES = 64 * 1024 * 1024;
const MAX_TEXT_BYTES = 2 * 1024 * 1024;
const ARTIFACT_FILE_RULES = Object.freeze({
  "Cargo.lock": Object.freeze({ maximumBytes: MAX_TEXT_BYTES, mode: "0444" }),
  "binary-version.txt": Object.freeze({ maximumBytes: 4096, mode: "0444" }),
  "bitcoinpir-directory-relay": Object.freeze({ maximumBytes: MAX_BINARY_BYTES, mode: "0555" }),
  "bitcoinpir-directory-relay.build-1": Object.freeze({ maximumBytes: MAX_BINARY_BYTES, mode: "0555" }),
  "bitcoinpir-directory-relay.build-2": Object.freeze({ maximumBytes: MAX_BINARY_BYTES, mode: "0555" }),
  "build-manifest.json": Object.freeze({ maximumBytes: MAX_TEXT_BYTES, mode: "0444" }),
  "git-version.txt": Object.freeze({ maximumBytes: 4096, mode: "0444" }),
  "source.tar": Object.freeze({ maximumBytes: MAX_ARCHIVE_BYTES, mode: "0444" }),
  "tar-version.txt": Object.freeze({ maximumBytes: 4096, mode: "0444" }),
});
const ARTIFACT_FILES = Object.freeze(Object.keys(ARTIFACT_FILE_RULES).sort());

function fail(message) {
  throw new Error(message);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function exactKeys(value, expected, label) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== null &&
      Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) {
    fail(`${label} keys must equal ${JSON.stringify(wanted)}, got ${JSON.stringify(actual)}`);
  }
}

function requireDigest(value, label) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value) || /^0{64}$/u.test(value)) {
    fail(`${label} must be a non-zero lowercase SHA-256`);
  }
  return value;
}

function requireCommit(value, label = "source commit") {
  if (typeof value !== "string" || !/^[0-9a-f]{40}$/u.test(value)) {
    fail(`${label} must be a full lowercase 40-hex commit`);
  }
  return value;
}

function currentEuid() {
  const value = process.geteuid?.() ?? process.getuid?.();
  if (!Number.isSafeInteger(value) || value < 0) {
    fail("current effective UID is unavailable");
  }
  return value;
}

function directoryChainPaths(path) {
  const absolute = resolve(path);
  const paths = [];
  let cursor = absolute;
  for (;;) {
    paths.push(cursor);
    const parent = dirname(cursor);
    if (parent === cursor) break;
    cursor = parent;
  }
  return paths.reverse();
}

function preciseDirectorySnapshot(path, fd, label) {
  const pathStat = lstatSync(path, { bigint: true });
  const descriptorStat = fstatSync(fd, { bigint: true });
  if (
    !pathStat.isDirectory() ||
    pathStat.isSymbolicLink() ||
    !descriptorStat.isDirectory() ||
    realpathSync(path) !== path
  ) {
    fail(`${label} is not one canonical descriptor-bound directory`);
  }
  const fingerprint = (stat) => ({
    ctime_ns: stat.ctimeNs.toString(),
    dev: stat.dev.toString(),
    gid: stat.gid.toString(),
    ino: stat.ino.toString(),
    mode: (stat.mode & 0o7777n).toString(8).padStart(4, "0"),
    mtime_ns: stat.mtimeNs.toString(),
    nlink: stat.nlink.toString(),
    size: stat.size.toString(),
    uid: stat.uid.toString(),
  });
  const pathname = fingerprint(pathStat);
  const descriptor = fingerprint(descriptorStat);
  if (canonicalJson(pathname) !== canonicalJson(descriptor)) {
    fail(`${label} pathname and descriptor fingerprints diverged`);
  }
  return pathname;
}

function stableDirectoryIdentity(snapshot) {
  return {
    dev: snapshot.dev,
    gid: snapshot.gid,
    ino: snapshot.ino,
    mode: snapshot.mode,
    uid: snapshot.uid,
  };
}

function preciseRegularFileFingerprint(stat) {
  return {
    ctime_ns: stat.ctimeNs.toString(),
    dev: stat.dev.toString(),
    gid: stat.gid.toString(),
    ino: stat.ino.toString(),
    mode: (stat.mode & 0o7777n).toString(8).padStart(4, "0"),
    mtime_ns: stat.mtimeNs.toString(),
    nlink: stat.nlink.toString(),
    size: stat.size.toString(),
    uid: stat.uid.toString(),
  };
}

function assertArtifactFileStat(stat, name, label, { requireFinalModes }) {
  const rule = ARTIFACT_FILE_RULES[name];
  if (rule === undefined) fail(`${label} has no allowlisted artifact rule: ${name}`);
  const mode = (stat.mode & 0o7777n).toString(8).padStart(4, "0");
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.nlink !== 1n ||
    stat.uid !== BigInt(currentEuid()) ||
    stat.size < 1n ||
    stat.size > BigInt(rule.maximumBytes) ||
    (stat.mode & 0o022n) !== 0n ||
    (stat.mode & 0o400n) === 0n ||
    (requireFinalModes && mode !== rule.mode)
  ) {
    const suffix = requireFinalModes ? ` with exact final mode ${rule.mode}` : "";
    fail(`${label} must be a bounded current-euid-owned one-link regular file${suffix}: ${name}`);
  }
}

function readDescriptorBoundArtifactFile(
  artifactRoot,
  name,
  label,
  { requireFinalModes },
) {
  const absolute = join(artifactRoot, name);
  let fd;
  let resealFd;
  try {
    const pathnameBefore = lstatSync(absolute, { bigint: true });
    assertArtifactFileStat(pathnameBefore, name, label, { requireFinalModes });
    fd = openSync(
      absolute,
      constants.O_RDONLY |
        constants.O_NOFOLLOW |
        (constants.O_CLOEXEC ?? 0),
    );
    const descriptorBefore = fstatSync(fd, { bigint: true });
    assertArtifactFileStat(descriptorBefore, name, label, { requireFinalModes });
    const initialFingerprint = preciseRegularFileFingerprint(pathnameBefore);
    if (
      canonicalJson(initialFingerprint) !==
      canonicalJson(preciseRegularFileFingerprint(descriptorBefore))
    ) {
      fail(`${label} pathname/opened-descriptor fingerprint mismatch: ${name}`);
    }

    const bytes = readFileSync(fd);
    const descriptorAfterRead = fstatSync(fd, { bigint: true });
    assertArtifactFileStat(descriptorAfterRead, name, label, { requireFinalModes });
    if (
      BigInt(bytes.length) !== descriptorAfterRead.size ||
      canonicalJson(initialFingerprint) !==
        canonicalJson(preciseRegularFileFingerprint(descriptorAfterRead))
    ) {
      fail(`${label} descriptor changed while bytes were read: ${name}`);
    }

    resealFd = openSync(
      absolute,
      constants.O_RDONLY |
        constants.O_NOFOLLOW |
        (constants.O_CLOEXEC ?? 0),
    );
    const resealedDescriptor = fstatSync(resealFd, { bigint: true });
    const pathnameAfter = lstatSync(absolute, { bigint: true });
    assertArtifactFileStat(resealedDescriptor, name, label, { requireFinalModes });
    assertArtifactFileStat(pathnameAfter, name, label, { requireFinalModes });
    if (
      realpathSync(absolute) !== absolute ||
      canonicalJson(initialFingerprint) !==
        canonicalJson(preciseRegularFileFingerprint(resealedDescriptor)) ||
      canonicalJson(initialFingerprint) !==
        canonicalJson(preciseRegularFileFingerprint(pathnameAfter))
    ) {
      fail(`${label} path did not reseal to the descriptor-bound precise fingerprint: ${name}`);
    }
    return {
      bytes,
      record: {
        file: name,
        fingerprint: initialFingerprint,
        sha256: sha256(bytes),
      },
    };
  } catch (error) {
    if (error instanceof Error && error.message.startsWith(label)) throw error;
    fail(`${label} could not descriptor-bind and reseal artifact file: ${name}`);
  } finally {
    if (resealFd !== undefined) closeSync(resealFd);
    if (fd !== undefined) closeSync(fd);
  }
}

export function snapshotCanonicalDirectoryChainV1(
  path,
  label = "directory chain",
  { ownerOnlyLeaf = false } = {},
) {
  const absolute = resolve(path);
  const paths = directoryChainPaths(absolute);
  const descriptors = [];
  try {
    const snapshots = paths.map((targetPath, index) => {
      const fd = openSync(
        targetPath,
        constants.O_RDONLY |
          constants.O_DIRECTORY |
          constants.O_NOFOLLOW |
          (constants.O_CLOEXEC ?? 0),
      );
      descriptors.push(fd);
      const fingerprint = preciseDirectorySnapshot(
        targetPath,
        fd,
        `${label}[${index}]`,
      );
      const uid = Number.parseInt(fingerprint.uid, 10);
      const mode = Number.parseInt(fingerprint.mode, 8);
      const rootOwnedSticky =
        uid === 0 && (mode & 0o1000) !== 0 && (mode & 0o022) !== 0;
      if (
        (uid !== 0 && uid !== currentEuid()) ||
        ((mode & 0o022) !== 0 && !rootOwnedSticky)
      ) {
        fail(`${label} contains an untrusted writable ancestor: ${targetPath}`);
      }
      if (
        ownerOnlyLeaf &&
        index === paths.length - 1 &&
        (uid !== currentEuid() || mode !== 0o700)
      ) {
        fail(`${label} leaf must be current-euid owned mode 0700`);
      }
      return { fingerprint, target_path: targetPath };
    });
    for (let index = 0; index < snapshots.length; index += 1) {
      const confirmation = preciseDirectorySnapshot(
        snapshots[index].target_path,
        descriptors[index],
        `${label} final[${index}]`,
      );
      const comparePreciseFingerprint = index === snapshots.length - 1;
      if (
        canonicalJson(
          comparePreciseFingerprint
            ? confirmation
            : stableDirectoryIdentity(confirmation),
        ) !==
        canonicalJson(
          comparePreciseFingerprint
            ? snapshots[index].fingerprint
            : stableDirectoryIdentity(snapshots[index].fingerprint),
        )
      ) {
        fail(`${label} changed while its descriptor chain was open`);
      }
    }
    return { absolute, directories: snapshots };
  } finally {
    for (const fd of descriptors.reverse()) closeSync(fd);
  }
}

export function assertCanonicalDirectoryChainUnchangedV1(
  expected,
  path,
  label = "directory chain",
  options = {},
) {
  const { allowLeafMetadataChange = false, ...snapshotOptions } = options;
  const current = snapshotCanonicalDirectoryChainV1(
    path,
    label,
    snapshotOptions,
  );
  if (
    current.absolute !== expected.absolute ||
    current.directories.length !== expected.directories.length
  ) {
    fail(`${label} path or depth changed during verification`);
  }
  for (let index = 0; index < expected.directories.length; index += 1) {
    const before = expected.directories[index];
    const after = current.directories[index];
    const comparePreciseFingerprint =
      index === expected.directories.length - 1 && !allowLeafMetadataChange;
    if (
      before.target_path !== after.target_path ||
      canonicalJson(
        comparePreciseFingerprint
          ? before.fingerprint
          : stableDirectoryIdentity(before.fingerprint),
      ) !==
        canonicalJson(
          comparePreciseFingerprint
            ? after.fingerprint
            : stableDirectoryIdentity(after.fingerprint),
        )
    ) {
      fail(`${label} descriptor chain or ABA fingerprint changed: ${before.target_path}`);
    }
  }
  return true;
}

function expectedArtifactFiles({ allowMissingManifest }) {
  return ARTIFACT_FILES.filter(
    (name) => !(allowMissingManifest && name === "build-manifest.json"),
  );
}

function assertClosedArtifactNames(actual, expected, label) {
  const observed = [...actual].sort();
  const wanted = [...expected].sort();
  if (
    observed.length !== wanted.length ||
    observed.some((name, index) => name !== wanted[index])
  ) {
    fail(`${label} files must equal ${JSON.stringify(wanted)}, got ${JSON.stringify(observed)}`);
  }
}

function collectBuildArtifactFastSealWithBytesV1(
  artifactRootInput,
  {
    allowMissingManifest = false,
    label = "artifact fast seal",
    requireFinalModes = true,
  } = {},
) {
  const chain = snapshotCanonicalDirectoryChainV1(
    artifactRootInput,
    `${label} parent chain`,
    { ownerOnlyLeaf: true },
  );
  const artifactRoot = chain.absolute;
  const expectedNames = expectedArtifactFiles({ allowMissingManifest });
  let rootFd;
  try {
    rootFd = openSync(
      artifactRoot,
      constants.O_RDONLY |
        constants.O_DIRECTORY |
        constants.O_NOFOLLOW |
        (constants.O_CLOEXEC ?? 0),
    );
    const rootBefore = preciseDirectorySnapshot(
      artifactRoot,
      rootFd,
      `${label} root before closed-world read`,
    );
    assertClosedArtifactNames(readdirSync(artifactRoot), expectedNames, label);
    const bytesByName = new Map();
    const files = expectedNames.map((name) => {
      const observed = readDescriptorBoundArtifactFile(
        artifactRoot,
        name,
        label,
        { requireFinalModes },
      );
      bytesByName.set(name, observed.bytes);
      return observed.record;
    });
    assertClosedArtifactNames(readdirSync(artifactRoot), expectedNames, `${label} final readdir`);
    const rootAfter = preciseDirectorySnapshot(
      artifactRoot,
      rootFd,
      `${label} root after closed-world read`,
    );
    if (canonicalJson(rootBefore) !== canonicalJson(rootAfter)) {
      fail(`${label} root precise fingerprint changed during closed-world read`);
    }
    assertCanonicalDirectoryChainUnchangedV1(
      chain,
      artifactRoot,
      `${label} parent chain`,
      { ownerOnlyLeaf: true },
    );
    return {
      bytesByName,
      seal: {
        files,
        root_identity: stableDirectoryIdentity(rootAfter),
        schema_version: 1,
      },
    };
  } finally {
    if (rootFd !== undefined) closeSync(rootFd);
  }
}

function assertBuildArtifactFastSealsEqual(expected, actual, label) {
  if (canonicalJson(expected) !== canonicalJson(actual)) {
    fail(`${label} changed across descriptor-bound fast seals`);
  }
  return true;
}

function assertManifestExtendsArtifactFastSeal(before, after) {
  const withoutManifest = {
    ...after,
    files: after.files.filter((entry) => entry.file !== "build-manifest.json"),
  };
  assertBuildArtifactFastSealsEqual(
    before,
    withoutManifest,
    "pre-manifest artifact set during manifest creation",
  );
  if (after.files.filter((entry) => entry.file === "build-manifest.json").length !== 1) {
    fail("generated manifest fast seal is incomplete");
  }
}

export function snapshotBuildArtifactFastSealV1(artifactRoot, options = {}) {
  return collectBuildArtifactFastSealWithBytesV1(artifactRoot, options).seal;
}

export function assertBuildArtifactFastSealUnchangedV1(
  expected,
  artifactRoot,
  label = "artifact fast seal",
  options = {},
) {
  const current = snapshotBuildArtifactFastSealV1(artifactRoot, {
    ...options,
    label,
  });
  return assertBuildArtifactFastSealsEqual(expected, current, label);
}

function requireCanonicalDirectory(path, label, { ownerOnly = false } = {}) {
  const absolute = resolve(path);
  const stat = lstatSync(absolute);
  if (!stat.isDirectory() || stat.isSymbolicLink() || realpathSync(absolute) !== absolute) {
    fail(`${label} must be a canonical non-symlink directory`);
  }
  if (ownerOnly && (stat.uid !== currentEuid() || (stat.mode & 0o7777) !== 0o700)) {
    fail(`${label} must be owned by the current effective UID with exact mode 0700`);
  }
  return absolute;
}

function snapshotCanonicalDirectory(path, label, options) {
  const absolute = requireCanonicalDirectory(path, label, options);
  const stat = lstatSync(absolute);
  return {
    absolute,
    dev: stat.dev,
    ino: stat.ino,
    mode: stat.mode & 0o7777,
    uid: stat.uid,
  };
}

function assertDirectorySnapshot(snapshot, label, options) {
  const current = snapshotCanonicalDirectory(snapshot.absolute, label, options);
  if (
    current.absolute !== snapshot.absolute ||
    current.dev !== snapshot.dev ||
    current.ino !== snapshot.ino ||
    current.mode !== snapshot.mode ||
    current.uid !== snapshot.uid
  ) {
    fail(`${label} path, inode, owner, or mode changed during verification`);
  }
}

function privateTemporaryDirectory(parent, prefix) {
  const root = realpathSync(mkdtempSync(join(parent, prefix)));
  chmodSync(root, 0o700);
  const stat = lstatSync(root);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o7777) !== 0o700) {
    fail("private verifier temporary directory is not canonical mode 0700");
  }
  return root;
}

function readOneLinkFile(path, label, maximumBytes) {
  const absolute = resolve(path);
  let fd;
  try {
    fd = openSync(absolute, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch {
    fail(`${label} must be a bounded canonical one-link regular file`);
  }
  try {
    const before = fstatSync(fd);
    if (
      !before.isFile() ||
      before.nlink !== 1 ||
      !Number.isSafeInteger(before.size) ||
      before.size < 1 ||
      before.size > maximumBytes
    ) {
      fail(`${label} must be a bounded canonical one-link regular file`);
    }
    const bytes = readFileSync(fd);
    const after = fstatSync(fd);
    const pathStat = lstatSync(absolute);
    if (
      !pathStat.isFile() ||
      pathStat.isSymbolicLink() ||
      pathStat.nlink !== 1 ||
      realpathSync(absolute) !== absolute ||
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs ||
      after.dev !== pathStat.dev ||
      after.ino !== pathStat.ino ||
      after.size !== pathStat.size ||
      after.nlink !== pathStat.nlink ||
      bytes.length !== after.size
    ) {
      fail(`${label} changed while it was read or is not canonical`);
    }
    return bytes;
  } finally {
    closeSync(fd);
  }
}

export function writeExactModePrivateFile(
  path,
  bytes,
  finalMode,
  label,
  maximumBytes,
  { writeBytes = writeFileSync } = {},
) {
  if (
    typeof label !== "string" ||
    label.length < 1 ||
    !Number.isSafeInteger(maximumBytes) ||
    maximumBytes < 1 ||
    !Buffer.isBuffer(bytes) ||
    bytes.length < 1 ||
    bytes.length > maximumBytes ||
    (finalMode !== 0o444 && finalMode !== 0o555) ||
    typeof writeBytes !== "function"
  ) {
    fail(`${label} must be bounded bytes with an allowlisted exact final mode`);
  }
  const absolute = resolve(path);
  const parent = requireCanonicalDirectory(dirname(absolute), `${label} parent`, {
    ownerOnly: true,
  });
  if (dirname(absolute) !== parent) {
    fail(`${label} must have one canonical owner-only parent`);
  }

  let parentFd;
  let writeFd;
  let verifyFd;
  let createdIdentity;
  let createdByThisCall = false;

  const closeDescriptors = ({ includeWriter = true } = {}) => {
    const errors = [];
    for (const [name, fd] of [
      ["verification", verifyFd],
      ["writer", writeFd],
      ["parent", parentFd],
    ]) {
      if (fd === undefined) continue;
      if (name === "writer" && !includeWriter) continue;
      try {
        closeSync(fd);
      } catch (error) {
        errors.push(new Error(`${label} ${name} descriptor close failed`, { cause: error }));
      }
      if (name === "verification") verifyFd = undefined;
      if (name === "writer") writeFd = undefined;
      if (name === "parent") parentFd = undefined;
    }
    return errors;
  };

  const cleanupCreatedPath = () => {
    if (createdIdentity === undefined) return;
    let stat;
    try {
      stat = lstatSync(absolute, { bigint: true });
    } catch (error) {
      if (error?.code === "ENOENT") return;
      throw error;
    }
    if (
      stat.dev === createdIdentity.dev &&
      stat.ino === createdIdentity.ino
    ) {
      unlinkSync(absolute);
    }
  };

  try {
    parentFd = openSync(
      parent,
      constants.O_RDONLY |
        constants.O_DIRECTORY |
        constants.O_NOFOLLOW |
        (constants.O_CLOEXEC ?? 0),
    );
    const parentBeforeCreate = preciseDirectorySnapshot(
      parent,
      parentFd,
      `${label} parent before create`,
    );
    if (
      Number.parseInt(parentBeforeCreate.uid, 10) !== currentEuid() ||
      Number.parseInt(parentBeforeCreate.mode, 8) !== 0o700
    ) {
      fail(`${label} descriptor-bound parent must remain current-euid owned mode 0700`);
    }

    writeFd = openSync(
      absolute,
      constants.O_RDWR |
        constants.O_CREAT |
        constants.O_EXCL |
        constants.O_NOFOLLOW |
        (constants.O_CLOEXEC ?? 0),
      0o600,
    );
    createdByThisCall = true;
    const createdStat = fstatSync(writeFd, { bigint: true });
    createdIdentity = { dev: createdStat.dev, ino: createdStat.ino };
    if (
      !createdStat.isFile() ||
      createdStat.isSymbolicLink() ||
      createdStat.nlink !== 1n ||
      createdStat.uid !== BigInt(currentEuid()) ||
      createdStat.size !== 0n
    ) {
      fail(`${label} did not create one empty current-euid-owned regular file`);
    }
    const parentAfterCreate = preciseDirectorySnapshot(
      parent,
      parentFd,
      `${label} parent after create`,
    );
    if (
      canonicalJson(stableDirectoryIdentity(parentAfterCreate)) !==
      canonicalJson(stableDirectoryIdentity(parentBeforeCreate))
    ) {
      fail(`${label} parent identity changed during exclusive creation`);
    }

    writeBytes(writeFd, bytes);
    fchmodSync(writeFd, finalMode);
    fsyncSync(writeFd);
    const writtenStat = fstatSync(writeFd, { bigint: true });
    if (
      !writtenStat.isFile() ||
      writtenStat.isSymbolicLink() ||
      writtenStat.nlink !== 1n ||
      writtenStat.uid !== BigInt(currentEuid()) ||
      writtenStat.size !== BigInt(bytes.length) ||
      (writtenStat.mode & 0o7777n) !== BigInt(finalMode)
    ) {
      fail(`${label} did not reach its descriptor-bound exact final mode`);
    }
    const descriptorFingerprint = preciseRegularFileFingerprint(writtenStat);

    verifyFd = openSync(
      absolute,
      constants.O_RDONLY |
        constants.O_NOFOLLOW |
        (constants.O_CLOEXEC ?? 0),
    );
    const verifyBefore = fstatSync(verifyFd, { bigint: true });
    if (
      canonicalJson(preciseRegularFileFingerprint(verifyBefore)) !==
      canonicalJson(descriptorFingerprint)
    ) {
      fail(`${label} verification descriptor did not bind the created inode`);
    }
    const observedBytes = readFileSync(verifyFd);
    const verifyAfter = fstatSync(verifyFd, { bigint: true });
    const pathAfter = lstatSync(absolute, { bigint: true });
    const parentAfterVerification = preciseDirectorySnapshot(
      parent,
      parentFd,
      `${label} parent after verification`,
    );
    if (
      !observedBytes.equals(bytes) ||
      canonicalJson(preciseRegularFileFingerprint(verifyAfter)) !==
        canonicalJson(descriptorFingerprint) ||
      canonicalJson(preciseRegularFileFingerprint(pathAfter)) !==
        canonicalJson(descriptorFingerprint) ||
      canonicalJson(parentAfterVerification) !== canonicalJson(parentAfterCreate) ||
      realpathSync(absolute) !== absolute
    ) {
      fail(`${label} path did not reseal to the exact-mode descriptor`);
    }
  } catch (error) {
    const secondaryErrors = [];
    if (createdByThisCall && createdIdentity === undefined && writeFd !== undefined) {
      try {
        const createdStat = fstatSync(writeFd, { bigint: true });
        createdIdentity = { dev: createdStat.dev, ino: createdStat.ino };
      } catch (identityError) {
        secondaryErrors.push(new Error(`${label} created inode identity recovery failed`, {
          cause: identityError,
        }));
      }
    }
    secondaryErrors.push(...closeDescriptors({ includeWriter: false }));
    try {
      cleanupCreatedPath();
    } catch (cleanupError) {
      secondaryErrors.push(new Error(`${label} exact created path cleanup failed`, {
        cause: cleanupError,
      }));
    }
    secondaryErrors.push(...closeDescriptors());
    if (secondaryErrors.length > 0) {
      throw new AggregateError(
        [error, ...secondaryErrors],
        `${label} failed and one or more cleanup operations also failed`,
        { cause: error },
      );
    }
    throw error;
  }

  const closeErrors = closeDescriptors();
  if (closeErrors.length > 0) {
    try {
      cleanupCreatedPath();
    } catch (cleanupError) {
      closeErrors.push(new Error(`${label} exact created path cleanup failed`, {
        cause: cleanupError,
      }));
    }
    throw new AggregateError(
      closeErrors,
      `${label} completed verification but descriptor close or cleanup failed`,
    );
  }
  return absolute;
}

function validateDockerPath(dockerPath) {
  if (typeof dockerPath !== "string" || !dockerPath.startsWith("/") || basename(dockerPath) !== "docker") {
    fail("Docker executable must be supplied as one absolute path ending in docker");
  }
}

export function validateDockerMountHostPath(path, label = "Docker mount host path") {
  if (
    typeof path !== "string" ||
    !path.startsWith("/") ||
    /[,\u0000-\u001f\u007f]/u.test(path)
  ) {
    fail(`${label} must be an absolute path without Docker mount delimiters or control bytes`);
  }
  return path;
}

export function requireWritableBindHostIdentity(
  uid = process.getuid?.(),
  gid = process.getgid?.(),
) {
  if (
    !Number.isSafeInteger(uid) ||
    !Number.isSafeInteger(gid) ||
    uid <= 0 ||
    gid <= 0
  ) {
    fail("writable bind mounts require a non-root numeric host UID/GID");
  }
  return { gid, uid };
}

export function pinnedDockerRun(
  dockerPath,
  mounts,
  command,
  label,
  maxBuffer = MAX_TEXT_BYTES,
  { environment = [], extraArgs = [], timeoutMs = 10 * 60 * 1000 } = {},
) {
  validateDockerPath(dockerPath);
  const args = [
    "run",
    "--rm",
    "--pull=never",
    "--platform",
    "linux/amd64",
    "--network",
    "none",
    "--read-only",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges",
    "--cpus",
    "2",
    "--ulimit",
    "nofile=4096:4096",
    "--ulimit",
    "core=0:0",
    ...extraArgs,
  ];
  for (const mount of mounts) args.push("--mount", mount);
  for (const entry of environment) args.push("--env", entry);
  args.push(DIRECTORY_RELAY_BUILD_IMAGE, ...command);
  const result = spawnSync(dockerPath, args, {
    encoding: null,
    env: { LC_ALL: "C", PATH: dirname(dockerPath) },
    killSignal: "SIGKILL",
    maxBuffer,
    shell: false,
    timeout: timeoutMs,
  });
  if (result.error) {
    const suffix = result.error.code === "ETIMEDOUT" ? " (timed out)" : "";
    fail(`${label} failed to execute${suffix}: ${result.error.message}`);
  }
  if (result.status !== 0 || result.signal !== null || (result.stderr?.length ?? 0) !== 0) {
    fail(`${label} failed closed`);
  }
  return result.stdout;
}

function validateGitVersion(value) {
  if (typeof value !== "string" || !/^git version [0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?\n$/u.test(value)) {
    fail("pinned source toolchain git --version output is not canonical");
  }
  return value.slice(0, -1);
}

function validateTarVersion(value) {
  if (typeof value !== "string" || !/^tar \(GNU tar\) [0-9]+\.[0-9]+(?:\.[0-9]+)?\n$/u.test(value)) {
    fail("pinned source toolchain tar --version output is not canonical");
  }
  return value.slice(0, -1);
}

function defaultCanonicalSourceRunner({ artifactRoot, dockerPath, repositoryRoot, sourceCommit }) {
  validateDockerMountHostPath(repositoryRoot, "repository mount path");
  const repositoryMount = `type=bind,src=${repositoryRoot},dst=/repository,readonly`;
  const pinnedGitShellArguments = DIRECTORY_RELAY_PINNED_GIT_GLOBAL_OPTIONS
    .map((value) => JSON.stringify(value))
    .join("\n            ");
  const outputRoot = privateTemporaryDirectory(dirname(artifactRoot), ".relay-source-proof.");
  try {
    validateDockerMountHostPath(outputRoot, "canonical source proof output mount path");
    const outputMount = `type=bind,src=${outputRoot},dst=/output`;
    const { uid, gid } = requireWritableBindHostIdentity();
    pinnedDockerRun(
      dockerPath,
      [repositoryMount, outputMount],
      [
        "/usr/bin/timeout",
        "--signal=KILL",
        "300s",
        "/bin/bash",
        "-ceu",
        `
          set -o pipefail
          if [[ ! -d /repository/.git/objects || -L /repository/.git/objects ]]; then
            exit 1
          fi
          if /usr/bin/find /repository/.git/objects -type l -print -quit | /usr/bin/grep -q .; then
            exit 1
          fi
          for alternate in \
            /repository/.git/objects/info/alternates \
            /repository/.git/objects/info/http-alternates; do
            if [[ -s "$alternate" ]]; then
              exit 1
            fi
          done
          /usr/bin/git init --bare --quiet /work/source.git
          /bin/cp -a /repository/.git/objects/. /work/source.git/objects/
          /bin/rm -rf /work/source.git/objects/info
          /bin/mkdir -m 0700 /work/source.git/objects/info
          git_source=(
            /usr/bin/git
            ${pinnedGitShellArguments}
          )
          resolved="$("\${git_source[@]}" rev-parse --verify "$SOURCE_COMMIT^{commit}")"
          if [[ "$resolved" != "$SOURCE_COMMIT" ]]; then
            exit 1
          fi
          "\${git_source[@]}" archive \
            --format=tar \
            --prefix="BitcoinPIR-$SOURCE_COMMIT/" \
            --output=/output/source.tar \
            "$SOURCE_COMMIT"
          "\${git_source[@]}" show "$SOURCE_COMMIT:Cargo.lock" > /output/commit-Cargo.lock
          /usr/bin/tar -xOf /output/source.tar \
            "BitcoinPIR-$SOURCE_COMMIT/Cargo.lock" > /output/archived-Cargo.lock
          /usr/bin/printf '%s\\n' "$resolved" > /output/resolved-commit.txt
          /usr/bin/git --version > /output/git-version.txt
          /usr/bin/tar --version | /usr/bin/sed -n '1p' > /output/tar-version.txt
        `,
      ],
      "pinned minimal-object-database canonical source proof",
      4096,
      {
        environment: [
          `SOURCE_COMMIT=${sourceCommit}`,
          "GIT_ATTR_NOSYSTEM=1",
          "GIT_CONFIG_GLOBAL=/dev/null",
          "GIT_CONFIG_NOSYSTEM=1",
          "GIT_DEFAULT_HASH=sha1",
          "GIT_NO_REPLACE_OBJECTS=1",
          "XDG_CONFIG_HOME=/nonexistent",
        ],
        extraArgs: [
          "--memory",
          "3221225472",
          "--memory-swap",
          "3221225472",
          "--pids-limit",
          "128",
          "--user",
          `${uid}:${gid}`,
          "--tmpfs",
          `/work:rw,exec,nosuid,nodev,size=2g,uid=${uid},gid=${gid},mode=0700`,
        ],
        timeoutMs: 310_000,
      },
    );
    const readProof = (name, label, maximumBytes) =>
      readOneLinkFile(join(outputRoot, name), label, maximumBytes);
    return {
      archivedCargoLock: readProof("archived-Cargo.lock", "archived Cargo.lock proof", MAX_TEXT_BYTES),
      commitCargoLock: readProof("commit-Cargo.lock", "commit Cargo.lock proof", MAX_TEXT_BYTES),
      gitVersion: readProof("git-version.txt", "pinned Git version proof", 4096).toString("utf8"),
      resolvedCommit: readProof("resolved-commit.txt", "resolved commit proof", 128).toString("utf8").trim(),
      sourceArchive: readProof("source.tar", "canonical source archive proof", MAX_ARCHIVE_BYTES),
      tarVersion: readProof("tar-version.txt", "pinned Tar version proof", 4096).toString("utf8"),
    };
  } finally {
    rmSync(outputRoot, { force: true, recursive: true });
  }
}

function defaultRebuildRunner({ artifactRoot, dockerPath, sourceArchive, sourceCommit }) {
  if (!Buffer.isBuffer(sourceArchive) || sourceArchive.length < 1) {
    fail("independent rebuild requires the already-verified source archive bytes");
  }
  const snapshotRoot = privateTemporaryDirectory(dirname(artifactRoot), ".relay-rebuild.");
  try {
    const snapshotPath = join(snapshotRoot, "source.tar");
    writeExactModePrivateFile(
      snapshotPath,
      sourceArchive,
      0o444,
      "private source archive snapshot",
      MAX_ARCHIVE_BYTES,
    );
    validateDockerMountHostPath(snapshotPath, "private source archive mount path");
    const sourceMount = `type=bind,src=${snapshotPath},dst=/input/source.tar,readonly`;
    const builds = [];
    for (const buildNumber of [1, 2]) {
      const bytes = pinnedDockerRun(
        dockerPath,
        [sourceMount],
        [
          "/usr/bin/timeout",
          "--signal=KILL",
          "1800s",
          "/bin/bash",
          "-ceu",
          `
            /bin/mkdir -p /work/source /work/target
            /usr/bin/tar -xf /input/source.tar -C /work/source
            cd "/work/source/BitcoinPIR-$SOURCE_COMMIT"
            ${DIRECTORY_RELAY_CARGO_COMMAND} >/dev/null 2>&1
            /bin/cat /work/target/release/bitcoinpir-directory-relay
          `,
        ],
        `pinned independent clean rebuild ${buildNumber}`,
        MAX_BINARY_BYTES,
        {
          environment: [
            "CARGO_INCREMENTAL=0",
            "CARGO_TARGET_DIR=/work/target",
            `RUSTFLAGS=-C debuginfo=0 -C strip=symbols --remap-path-prefix=/work/source/BitcoinPIR-${sourceCommit}=/workspace`,
            `RUSTUP_TOOLCHAIN=${DIRECTORY_RELAY_RUST_TOOLCHAIN}`,
            `SOURCE_COMMIT=${sourceCommit}`,
            "SOURCE_DATE_EPOCH=0",
          ],
          extraArgs: [
            "--memory",
            "6442450944",
            "--memory-swap",
            "6442450944",
            "--pids-limit",
            "512",
            "--user",
            `${DIRECTORY_RELAY_UNPRIVILEGED_UID}:${DIRECTORY_RELAY_UNPRIVILEGED_GID}`,
            "--tmpfs",
            `/work:rw,exec,nosuid,nodev,size=4g,uid=${DIRECTORY_RELAY_UNPRIVILEGED_UID},gid=${DIRECTORY_RELAY_UNPRIVILEGED_GID},mode=0700`,
          ],
          timeoutMs: 1_810_000,
        },
      );
      validateElfAmd64(bytes, `independent clean rebuild ${buildNumber}`);
      builds.push(bytes);
    }
    return builds;
  } finally {
    rmSync(snapshotRoot, { force: true, recursive: true });
  }
}

function validateElfAmd64(bytes, label) {
  if (
    bytes.length < 64 ||
    bytes[0] !== 0x7f ||
    bytes[1] !== 0x45 ||
    bytes[2] !== 0x4c ||
    bytes[3] !== 0x46 ||
    bytes[4] !== 2 ||
    bytes[5] !== 1 ||
    bytes.readUInt16LE(18) !== 0x3e
  ) {
    fail(`${label} must be one ELF64 little-endian x86-64 binary`);
  }
}

function defaultVersionRunner({ artifactRoot, dockerPath, selectedBinary }) {
  validateDockerPath(dockerPath);
  if (!Buffer.isBuffer(selectedBinary) || selectedBinary.length < 1) {
    fail("binary version proof requires the verified selected binary bytes");
  }
  const snapshotRoot = privateTemporaryDirectory(dirname(artifactRoot), ".relay-version.");
  try {
    const snapshotPath = join(snapshotRoot, "bitcoinpir-directory-relay");
    writeExactModePrivateFile(
      snapshotPath,
      selectedBinary,
      0o555,
      "private selected binary snapshot",
      MAX_BINARY_BYTES,
    );
    validateDockerMountHostPath(snapshotPath, "private selected binary mount path");
    return pinnedDockerRun(
      dockerPath,
      [`type=bind,src=${snapshotPath},dst=/proof/bitcoinpir-directory-relay,readonly`],
      [
        "/usr/bin/timeout",
        "--signal=KILL",
        "15s",
        "/proof/bitcoinpir-directory-relay",
        "--version",
      ],
      "pinned Linux-amd64 binary --version execution",
      4096,
      {
        extraArgs: [
          "--memory",
          "268435456",
          "--memory-swap",
          "268435456",
          "--pids-limit",
          "64",
          "--user",
          `${DIRECTORY_RELAY_UNPRIVILEGED_UID}:${DIRECTORY_RELAY_UNPRIVILEGED_GID}`,
          "--tmpfs",
          `/work:rw,exec,nosuid,nodev,size=64m,uid=${DIRECTORY_RELAY_UNPRIVILEGED_UID},gid=${DIRECTORY_RELAY_UNPRIVILEGED_GID},mode=0700`,
        ],
        timeoutMs: 25_000,
      },
    ).toString("utf8");
  } finally {
    rmSync(snapshotRoot, { force: true, recursive: true });
  }
}

function validateVersionOutput(value) {
  if (
    typeof value !== "string" ||
    !/^bitcoinpir-directory-relay [0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?\n$/u.test(value)
  ) {
    fail("binary --version output must be one canonical line");
  }
  return value.slice(0, -1);
}

function fileRecord(name, digest) {
  return { file: name, sha256: digest };
}

export function buildManifestFromFacts(facts) {
  requireCommit(facts.sourceCommit);
  for (const [name, digest] of Object.entries(facts.digests)) requireDigest(digest, `${name} digest`);
  if (facts.binaryVersionOutput !== validateVersionOutput(`${facts.binaryVersionOutput}\n`)) {
    fail("binary version fact is not canonical");
  }
  if (facts.gitVersionOutput !== validateGitVersion(`${facts.gitVersionOutput}\n`)) {
    fail("git version fact is not canonical");
  }
  if (facts.tarVersionOutput !== validateTarVersion(`${facts.tarVersionOutput}\n`)) {
    fail("tar version fact is not canonical");
  }
  return {
    binaries: [
      fileRecord("bitcoinpir-directory-relay.build-1", facts.digests.build1),
      fileRecord("bitcoinpir-directory-relay.build-2", facts.digests.build2),
    ],
    build: {
      cargo_command: DIRECTORY_RELAY_CARGO_COMMAND,
      container_image: DIRECTORY_RELAY_BUILD_IMAGE,
      docker_network: "none",
      docker_platform: "linux/amd64",
      rust_toolchain: DIRECTORY_RELAY_RUST_TOOLCHAIN,
      source_date_epoch: "0",
    },
    cargo_lock: fileRecord("Cargo.lock", facts.digests.cargoLock),
    profile: DIRECTORY_RELAY_BUILD_PROFILE,
    reproducibility: {
      byte_identical: true,
      clean_build_count: 2,
      verifier_clean_rebuild_count: 2,
      verifier_rebuilds_match_selected: true,
    },
    schema_version: 1,
    selected_binary: {
      file: "bitcoinpir-directory-relay",
      sha256: facts.digests.selected,
      version_output: facts.binaryVersionOutput,
    },
    source_archive: {
      file: "source.tar",
      git_archive_prefix: `BitcoinPIR-${facts.sourceCommit}/`,
      sha256: facts.digests.sourceArchive,
    },
    source_commit: facts.sourceCommit,
    source_repository: DIRECTORY_RELAY_SOURCE_REPOSITORY,
    source_toolchain: {
      container_image: DIRECTORY_RELAY_BUILD_IMAGE,
      docker_network: "none",
      docker_platform: "linux/amd64",
      git_input_profile: "minimal-bare-copied-objects-no-alternates-v1",
      git: {
        file: "git-version.txt",
        sha256: facts.digests.gitVersion,
        version_output: facts.gitVersionOutput,
      },
      tar: {
        file: "tar-version.txt",
        sha256: facts.digests.tarVersion,
        version_output: facts.tarVersionOutput,
      },
    },
  };
}

export function validateBuildManifest(manifest, facts) {
  exactKeys(
    manifest,
    [
      "binaries",
      "build",
      "cargo_lock",
      "profile",
      "reproducibility",
      "schema_version",
      "selected_binary",
      "source_archive",
      "source_commit",
      "source_repository",
      "source_toolchain",
    ],
    "directory relay build manifest",
  );
  const expected = buildManifestFromFacts(facts);
  if (canonicalJson(manifest) !== canonicalJson(expected)) {
    fail("directory relay build manifest does not exactly bind the verified artifact facts");
  }
  return true;
}

function requiredArtifactBytes(bytesByName, name, label = "artifact fast seal") {
  const bytes = bytesByName.get(name);
  if (!Buffer.isBuffer(bytes)) fail(`${label} is missing descriptor-bound bytes: ${name}`);
  return bytes;
}

function factsFromArtifactBytesV1(bytesByName, sourceCommitInput) {
  const sourceCommit = requireCommit(sourceCommitInput);
  const sourceArchive = requiredArtifactBytes(bytesByName, "source.tar");
  const cargoLock = requiredArtifactBytes(bytesByName, "Cargo.lock");
  const gitVersionBytes = requiredArtifactBytes(bytesByName, "git-version.txt");
  const tarVersionBytes = requiredArtifactBytes(bytesByName, "tar-version.txt");
  const recordedVersion = requiredArtifactBytes(bytesByName, "binary-version.txt");
  const binaryNames = [
    "bitcoinpir-directory-relay.build-1",
    "bitcoinpir-directory-relay.build-2",
    "bitcoinpir-directory-relay",
  ];
  const binaries = binaryNames.map((name) => requiredArtifactBytes(bytesByName, name));
  for (const [index, bytes] of binaries.entries()) validateElfAmd64(bytes, binaryNames[index]);
  if (!binaries[0].equals(binaries[1]) || !binaries[0].equals(binaries[2])) {
    fail("two clean-build binaries and selected binary are not byte-identical");
  }
  const binaryVersionText = new TextDecoder("utf-8", { fatal: true }).decode(recordedVersion);
  const gitVersionText = new TextDecoder("utf-8", { fatal: true }).decode(gitVersionBytes);
  const tarVersionText = new TextDecoder("utf-8", { fatal: true }).decode(tarVersionBytes);
  return {
    binaries,
    cargoLock,
    facts: {
      binaryVersionOutput: validateVersionOutput(binaryVersionText),
      digests: {
        build1: sha256(binaries[0]),
        build2: sha256(binaries[1]),
        cargoLock: sha256(cargoLock),
        gitVersion: sha256(gitVersionBytes),
        selected: sha256(binaries[2]),
        sourceArchive: sha256(sourceArchive),
        tarVersion: sha256(tarVersionBytes),
      },
      gitVersionOutput: validateGitVersion(gitVersionText),
      sourceCommit,
      tarVersionOutput: validateTarVersion(tarVersionText),
    },
    gitVersionText,
    recordedVersion,
    sourceArchive,
    tarVersionText,
  };
}

function runArtifactTestHook(testHooks, phase) {
  if (testHooks === undefined) return;
  const hook = testHooks[phase];
  if (hook !== undefined) hook();
}

function collectBuildArtifactDetails({
  artifactRoot: artifactRootInput,
  repositoryRoot: repositoryRootInput,
  sourceCommit: sourceCommitInput,
  dockerPath,
  canonicalSourceRunner = defaultCanonicalSourceRunner,
  rebuildRunner = defaultRebuildRunner,
  versionRunner = defaultVersionRunner,
  allowMissingManifest = false,
  requireFinalModes = !allowMissingManifest,
  testHooks = undefined,
}) {
  const initialArtifact = collectBuildArtifactFastSealWithBytesV1(
    artifactRootInput,
    {
      allowMissingManifest,
      label: "artifact initial fast seal",
      requireFinalModes,
    },
  );
  const artifactRoot = resolve(artifactRootInput);
  const repositoryRootSnapshot = snapshotCanonicalDirectory(repositoryRootInput, "repository root");
  const repositoryRoot = repositoryRootSnapshot.absolute;
  const gitRootSnapshot = snapshotCanonicalDirectory(
    join(repositoryRoot, ".git"),
    "repository object database",
  );
  const objectRootSnapshot = snapshotCanonicalDirectory(
    join(repositoryRoot, ".git", "objects"),
    "repository object database storage",
  );
  const sourceCommit = requireCommit(sourceCommitInput);
  const observed = factsFromArtifactBytesV1(initialArtifact.bytesByName, sourceCommit);
  const { binaries, cargoLock, facts, sourceArchive } = observed;
  const canonical = canonicalSourceRunner({
    artifactRoot,
    dockerPath,
    repositoryRoot,
    sourceCommit,
  });
  if (canonical === null || typeof canonical !== "object" || Array.isArray(canonical)) {
    fail("canonical source runner returned an invalid result");
  }
  if (canonical.resolvedCommit !== sourceCommit) {
    fail("source commit does not resolve to the exact full commit");
  }
  if (!Buffer.isBuffer(canonical.sourceArchive) || !sourceArchive.equals(canonical.sourceArchive)) {
    fail("source archive bytes do not equal canonical git archive of source_commit");
  }
  if (
    !Buffer.isBuffer(canonical.commitCargoLock) ||
    !Buffer.isBuffer(canonical.archivedCargoLock) ||
    !cargoLock.equals(canonical.commitCargoLock) ||
    !cargoLock.equals(canonical.archivedCargoLock)
  ) {
    fail("Cargo.lock bytes do not agree across source_commit, source archive, and artifact copy");
  }
  if (
    typeof canonical.gitVersion !== "string" ||
    typeof canonical.tarVersion !== "string" ||
    canonical.gitVersion !== observed.gitVersionText ||
    canonical.tarVersion !== observed.tarVersionText
  ) {
    fail("recorded Git/Tar version bytes do not equal the pinned source toolchain outputs");
  }
  const rebuiltBinaries = rebuildRunner({
    artifactRoot,
    dockerPath,
    sourceArchive,
    sourceCommit,
  });
  if (
    !Array.isArray(rebuiltBinaries) ||
    rebuiltBinaries.length !== 2 ||
    !rebuiltBinaries.every(Buffer.isBuffer)
  ) {
    fail("independent pinned rebuild runner returned an invalid result");
  }
  for (const [index, rebuilt] of rebuiltBinaries.entries()) {
    validateElfAmd64(rebuilt, `independent clean rebuild ${index + 1}`);
    if (!rebuilt.equals(binaries[0])) {
      fail(`independent clean rebuild ${index + 1} does not equal the selected artifact binary`);
    }
  }

  const versionText = versionRunner({
    artifactRoot,
    dockerPath,
    selectedBinary: binaries[2],
  });
  const binaryVersionOutput = validateVersionOutput(versionText);
  if (!observed.recordedVersion.equals(Buffer.from(versionText, "utf8"))) {
    fail("recorded version bytes do not equal --version output from selected binary");
  }
  if (binaryVersionOutput !== facts.binaryVersionOutput) {
    fail("recorded version bytes do not equal --version output from selected binary");
  }
  runArtifactTestHook(testHooks, "afterLongRunnersBeforeFinalSeal");
  const finalArtifact = collectBuildArtifactFastSealWithBytesV1(
    artifactRoot,
    {
      allowMissingManifest,
      label: "artifact post-runner final fast seal",
      requireFinalModes,
    },
  );
  assertBuildArtifactFastSealsEqual(
    initialArtifact.seal,
    finalArtifact.seal,
    "artifact set during long runner verification",
  );
  assertDirectorySnapshot(repositoryRootSnapshot, "repository root");
  assertDirectorySnapshot(gitRootSnapshot, "repository object database");
  assertDirectorySnapshot(objectRootSnapshot, "repository object database storage");

  return {
    artifactSeal: finalArtifact.seal,
    bytesByName: initialArtifact.bytesByName,
    facts,
  };
}

export function collectBuildArtifactFacts(options) {
  return collectBuildArtifactDetails(options).facts;
}

function parseCanonicalManifestBytes(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > MAX_TEXT_BYTES) {
    fail("build manifest bytes are missing or unbounded");
  }
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail("build manifest is not UTF-8");
  }
  const manifest = parseStrictJson(text, "directory relay build manifest");
  if (!bytes.equals(Buffer.from(canonicalJson(manifest), "utf8"))) {
    fail("build manifest is not canonical JSON");
  }
  return { bytes, manifest };
}

export function validateSelectionBindings({
  buildManifestBytes,
  configBytes,
  facts,
  manifest,
  selection,
}) {
  validateBuildManifest(manifest, facts);
  if (selection.status !== "RESOLVED") fail("artifact binding requires a RESOLVED relay selection");
  const expected = {
    binarySha256: facts.digests.selected,
    binaryVersionOutput: facts.binaryVersionOutput,
    buildManifestSha256: sha256(buildManifestBytes),
    cargoLockSha256: facts.digests.cargoLock,
    configSha256: sha256(configBytes),
    sourceArchiveSha256: facts.digests.sourceArchive,
    sourceCommit: facts.sourceCommit,
  };
  for (const [field, value] of Object.entries(expected)) {
    if (selection[field] !== value) fail(`relay selection ${field} does not bind verified artifact bytes`);
  }
  return true;
}

export function verifyBuildArtifactSet(options) {
  const details = collectBuildArtifactDetails(options);
  const { bytes, manifest } = parseCanonicalManifestBytes(
    requiredArtifactBytes(details.bytesByName, "build-manifest.json"),
  );
  validateBuildManifest(manifest, details.facts);
  runArtifactTestHook(options.testHooks, "afterManifestValidationBeforeFinalSeal");
  const finalSeal = snapshotBuildArtifactFastSealV1(options.artifactRoot, {
    label: "artifact post-manifest final fast seal",
    requireFinalModes: true,
  });
  assertBuildArtifactFastSealsEqual(
    details.artifactSeal,
    finalSeal,
    "artifact set across manifest validation",
  );
  return {
    artifactSeal: finalSeal,
    buildManifestBytes: bytes,
    facts: details.facts,
    manifest,
  };
}

export function fastSealBuildArtifactSet({
  artifactRoot,
  sourceCommit,
  testHooks = undefined,
}) {
  const initial = collectBuildArtifactFastSealWithBytesV1(artifactRoot, {
    label: "complete build artifact fast seal",
    requireFinalModes: true,
  });
  const observed = factsFromArtifactBytesV1(initial.bytesByName, sourceCommit);
  const { bytes, manifest } = parseCanonicalManifestBytes(
    requiredArtifactBytes(initial.bytesByName, "build-manifest.json"),
  );
  validateBuildManifest(manifest, observed.facts);
  runArtifactTestHook(testHooks, "afterFastManifestValidationBeforeReseal");
  const resealed = snapshotBuildArtifactFastSealV1(artifactRoot, {
    label: "complete build artifact fast reseal",
    requireFinalModes: true,
  });
  assertBuildArtifactFastSealsEqual(
    initial.seal,
    resealed,
    "complete build artifact fast seal",
  );
  return {
    artifactSeal: resealed,
    buildManifestBytes: bytes,
    facts: observed.facts,
    manifest,
  };
}

export function verifyResolvedSelection({ configPath, selectionPath, ...buildOptions }) {
  const verified = verifyBuildArtifactSet(buildOptions);
  const selectionText = readOneLinkFile(selectionPath, "relay selection", MAX_TEXT_BYTES).toString("utf8");
  const selection = validateRelaySelection(selectionText);
  const configBytes = readOneLinkFile(configPath, "directory relay config", 16 * 1024);
  const configText = new TextDecoder("utf-8", { fatal: true }).decode(configBytes);
  validateRelayConfigExample(configText, selection);
  validateSelectionBindings({
    ...verified,
    configBytes,
    selection,
  });
  assertBuildArtifactFastSealUnchangedV1(
    verified.artifactSeal,
    buildOptions.artifactRoot,
    "artifact set across selection validation",
    { requireFinalModes: true },
  );
  return true;
}

function parseCli(argv) {
  const command = argv[0];
  const chainCommands = new Set([
    "snapshot-directory-chain",
    "verify-directory-chain",
    "verify-directory-chain-identity",
  ]);
  if (
    ![
      "create-manifest",
      "fast-seal-build",
      "verify-build",
      "verify-selection",
      ...chainCommands,
    ].includes(command)
  ) {
    fail("usage: payment-v1-directory-relay-artifact-gate.mjs <create-manifest|fast-seal-build|verify-build|verify-selection|snapshot-directory-chain|verify-directory-chain|verify-directory-chain-identity> OPTIONS");
  }
  const values = Object.create(null);
  if (chainCommands.has(command)) {
    const allowed = new Set(["--directory", "--snapshot"]);
    for (let index = 1; index < argv.length; index += 2) {
      const flag = argv[index];
      const value = argv[index + 1];
      if (
        !allowed.has(flag) ||
        value === undefined ||
        values[flag] !== undefined
      ) {
        fail(`invalid, repeated, or missing directory-chain CLI option: ${flag ?? "<missing>"}`);
      }
      values[flag] = value;
    }
    if (
      values["--directory"] === undefined ||
      !values["--directory"].startsWith("/")
    ) {
      fail("directory-chain command requires --directory ABS");
    }
    if (
      command === "snapshot-directory-chain" &&
      values["--snapshot"] !== undefined
    ) {
      fail("snapshot-directory-chain forbids --snapshot");
    }
    if (
      command !== "snapshot-directory-chain" &&
      values["--snapshot"] === undefined
    ) {
      fail(`${command} requires --snapshot`);
    }
    return { command, values };
  }
  const allowed = new Set([
    "--repository",
    "--artifacts",
    "--source-commit",
    "--docker",
    "--output",
    "--selection",
    "--config",
  ]);
  for (let index = 1; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!allowed.has(flag) || value === undefined || values[flag] !== undefined) {
      fail(`invalid, repeated, or missing CLI option: ${flag ?? "<missing>"}`);
    }
    values[flag] = value;
  }
  const requiredFlags = command === "fast-seal-build"
    ? ["--artifacts", "--source-commit"]
    : ["--repository", "--artifacts", "--source-commit", "--docker"];
  for (const required of requiredFlags) {
    if (values[required] === undefined) fail(`missing required CLI option ${required}`);
  }
  for (const pathFlag of ["--repository", "--artifacts", "--docker", "--output", "--selection", "--config"]) {
    if (values[pathFlag] !== undefined && !values[pathFlag].startsWith("/")) {
      fail(`${pathFlag} must be absolute`);
    }
  }
  requireCommit(values["--source-commit"]);
  if (command === "fast-seal-build") {
    for (const forbidden of ["--repository", "--docker", "--output", "--selection", "--config"]) {
      if (values[forbidden] !== undefined) fail(`fast-seal-build forbids ${forbidden}`);
    }
  } else if (command === "create-manifest") {
    if (values["--output"] === undefined) fail("create-manifest requires --output");
    if (values["--selection"] !== undefined || values["--config"] !== undefined) {
      fail("create-manifest forbids selection/config inputs");
    }
  } else if (values["--output"] !== undefined) {
    fail(`${command} forbids --output`);
  }
  if (command === "verify-selection") {
    if (values["--selection"] === undefined || values["--config"] === undefined) {
      fail("verify-selection requires --selection and --config");
    }
  } else if (values["--selection"] !== undefined || values["--config"] !== undefined) {
    fail(`${command} forbids selection/config inputs`);
  }
  return { command, values };
}

function runCli(argv) {
  const { command, values } = parseCli(argv);
  if (command === "snapshot-directory-chain") {
    process.stdout.write(canonicalJson(snapshotCanonicalDirectoryChainV1(
      values["--directory"],
      "output parent chain",
    )));
    return;
  }
  if (
    command === "verify-directory-chain" ||
    command === "verify-directory-chain-identity"
  ) {
    const expected = parseStrictJson(
      values["--snapshot"],
      "output parent directory-chain snapshot",
    );
    assertCanonicalDirectoryChainUnchangedV1(
      expected,
      values["--directory"],
      "output parent chain",
      {
        allowLeafMetadataChange:
          command === "verify-directory-chain-identity",
      },
    );
    process.stdout.write("directory-relay-output-parent-chain=PASS\n");
    return;
  }
  if (command === "fast-seal-build") {
    const sealed = fastSealBuildArtifactSet({
      artifactRoot: values["--artifacts"],
      sourceCommit: values["--source-commit"],
    });
    process.stdout.write(canonicalJson(sealed.artifactSeal));
    return;
  }
  const common = {
    artifactRoot: values["--artifacts"],
    dockerPath: values["--docker"],
    repositoryRoot: values["--repository"],
    sourceCommit: values["--source-commit"],
  };
  if (command === "create-manifest") {
    if (resolve(values["--output"]) !== join(resolve(common.artifactRoot), "build-manifest.json")) {
      fail("build manifest output must be ARTIFACTS/build-manifest.json");
    }
    const details = collectBuildArtifactDetails({
      ...common,
      allowMissingManifest: true,
      requireFinalModes: false,
    });
    const bytes = Buffer.from(canonicalJson(buildManifestFromFacts(details.facts)), "utf8");
    writeExactModePrivateFile(
      values["--output"],
      bytes,
      0o444,
      "generated build manifest",
      MAX_TEXT_BYTES,
    );
    const complete = collectBuildArtifactFastSealWithBytesV1(common.artifactRoot, {
      label: "generated manifest complete fast seal",
      requireFinalModes: false,
    });
    assertManifestExtendsArtifactFastSeal(details.artifactSeal, complete.seal);
    const observed = factsFromArtifactBytesV1(
      complete.bytesByName,
      common.sourceCommit,
    );
    const parsed = parseCanonicalManifestBytes(
      requiredArtifactBytes(complete.bytesByName, "build-manifest.json"),
    );
    validateBuildManifest(parsed.manifest, observed.facts);
    if (canonicalJson(observed.facts) !== canonicalJson(details.facts)) {
      fail("generated manifest artifact facts changed after the long runner seal");
    }
    const finalSeal = snapshotBuildArtifactFastSealV1(common.artifactRoot, {
      label: "generated manifest final complete fast reseal",
      requireFinalModes: false,
    });
    assertBuildArtifactFastSealsEqual(
      complete.seal,
      finalSeal,
      "generated manifest complete artifact set",
    );
    process.stdout.write(`directory-relay-build-manifest-sha256=${sha256(bytes)}\n`);
    return;
  }
  if (command === "verify-build") {
    const { buildManifestBytes } = verifyBuildArtifactSet(common);
    process.stdout.write(`directory-relay-build-manifest-sha256=${sha256(buildManifestBytes)}\n`);
    return;
  }
  verifyResolvedSelection({
    ...common,
    configPath: values["--config"],
    selectionPath: values["--selection"],
  });
  process.stdout.write("payment-v1-directory-relay-artifact-gate=PASS\n");
}

const isMain =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href;

if (isMain) {
  try {
    runCli(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`payment-v1-directory-relay-artifact-gate=FAIL: ${error.message}\n`);
    process.exitCode = 1;
  }
}
