import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs, {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  acquireFilesystemLock,
} from "./payment-v1-integrated-caddy-overlay-transaction.mjs";
import { canonicalJson } from "./payment-v1-integrated-caddy-overlay-gate.mjs";

const ROOT_LINUX =
  process.platform === "linux" &&
  typeof process.geteuid === "function" &&
  process.geteuid() === 0;
const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const TRANSACTION_MODULE_URL = new URL(
  "./payment-v1-integrated-caddy-overlay-transaction.mjs",
  import.meta.url,
).href;

function regularPin(path) {
  const stat = lstatSync(path, { bigint: true });
  const bytes = readFileSync(path);
  return {
    ctime_ns: stat.ctimeNs.toString(),
    device: stat.dev.toString(),
    gid: Number(stat.gid),
    inode: stat.ino.toString(),
    mode: Number(stat.mode & 0o7777n).toString(8).padStart(4, "0"),
    mtime_ns: stat.mtimeNs.toString(),
    nlink: Number(stat.nlink),
    path,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    size: stat.size.toString(),
    uid: Number(stat.uid),
  };
}

function compileHelper(root, name, definitions = []) {
  const helper = join(root, name);
  const compile = spawnSync(
    process.env.CC ?? "cc",
    [
      "-std=c11",
      "-O2",
      "-Wall",
      "-Wextra",
      "-Werror",
      ...definitions,
      join(SCRIPT_DIRECTORY, "payment-v1-integrated-caddy-rename-exchange.c"),
      "-o",
      helper,
    ],
    { encoding: "utf8", timeout: 30_000 },
  );
  assert.equal(compile.status, 0, compile.stderr);
  chmodSync(helper, 0o555);
  return helper;
}

test("filesystem lock distinguishes a live holder from an exact stale process generation", {
  skip: ROOT_LINUX ? false : "root Linux descriptor and procfs semantics are required",
}, async (t) => {
  const root = mkdtempSync(join(tmpdir(), "bitcoinpir-overlay-lock-"));
  chmodSync(root, 0o700);
  t.after(() => rmSync(root, { force: true, recursive: true }));
  const lock = join(root, "transaction.lock");
  const release = acquireFilesystemLock(lock, {
    allowUnpinnedTestHelper: true,
    recoverStale: false,
    transactionId: "lock-live-test",
  });
  assert.equal(existsSync(join(lock, "owner.json")), true);
  assert.equal(existsSync(join(lock, "owner.json.pending")), false);
  await assert.rejects(
    async () => acquireFilesystemLock(lock, {
      allowUnpinnedTestHelper: true,
      recoverStale: false,
      transactionId: "lock-contender-test",
    }),
    /explicit recover command/,
  );
  await assert.rejects(
    async () => acquireFilesystemLock(lock, {
      allowUnpinnedTestHelper: true,
      recoverStale: true,
      transactionId: "lock-contender-test",
    }),
    /live process generation/,
  );
  await release();

  mkdirSync(lock, { mode: 0o700 });
  writeFileSync(
    join(lock, "owner.json"),
    canonicalJson({
      boot_id: "00000000-0000-4000-8000-000000000000",
      pid: 1,
      process_start_ticks: "1",
      transaction_id: "crashed-generation",
    }),
    { mode: 0o400 },
  );
  const releaseRecovered = acquireFilesystemLock(lock, {
    allowUnpinnedTestHelper: true,
    recoverStale: true,
    transactionId: "lock-recovery-test",
  });
  await releaseRecovered();

  mkdirSync(lock, { mode: 0o700 });
  writeFileSync(
    join(lock, "owner.json.pending"),
    canonicalJson({
      boot_id: "00000000-0000-4000-8000-000000000000",
      pid: 1,
      process_start_ticks: "1",
      transaction_id: "crashed-pending-generation",
    }),
    { mode: 0o400 },
  );
  const releasePendingRecovered = acquireFilesystemLock(lock, {
    allowUnpinnedTestHelper: true,
    recoverStale: true,
    transactionId: "lock-pending-recovery-test",
  });
  assert.equal(existsSync(join(lock, "owner.json")), true);
  assert.equal(existsSync(join(lock, "owner.json.pending")), false);
  await releasePendingRecovered();
});

test("stale-lock recovery refuses an unknown directory shape", {
  skip: ROOT_LINUX ? false : "root Linux descriptor and procfs semantics are required",
}, async (t) => {
  const root = mkdtempSync(join(tmpdir(), "bitcoinpir-overlay-lock-shape-"));
  chmodSync(root, 0o700);
  t.after(() => rmSync(root, { force: true, recursive: true }));
  const lock = join(root, "transaction.lock");
  assert.throws(
    () => acquireFilesystemLock(lock, {
      recoverStale: false,
      transactionId: "missing-helper-test",
    }),
    /requires the pinned no-replace helper/,
  );
  mkdirSync(lock, { mode: 0o700 });
  writeFileSync(join(lock, "unknown"), "do-not-delete\n", { mode: 0o400 });
  await assert.rejects(
    async () => acquireFilesystemLock(lock, {
      allowUnpinnedTestHelper: true,
      recoverStale: true,
      transactionId: "lock-recovery-test",
    }),
    /unknown shape/,
  );

  const splitLock = join(root, "transaction-split.lock");
  mkdirSync(splitLock, { mode: 0o700 });
  writeFileSync(join(splitLock, "owner.json"), "{}\n", { mode: 0o400 });
  writeFileSync(join(splitLock, "owner.json.pending"), "{}\n", { mode: 0o400 });
  await assert.rejects(
    async () => acquireFilesystemLock(splitLock, {
      allowUnpinnedTestHelper: true,
      recoverStale: true,
      transactionId: "lock-split-shape-test",
    }),
    /unknown shape/,
  );
  assert.equal(existsSync(join(splitLock, "owner.json")), true);
  assert.equal(existsSync(join(splitLock, "owner.json.pending")), true);

  const weakPendingLock = join(root, "transaction-weak-pending.lock");
  mkdirSync(weakPendingLock, { mode: 0o700 });
  writeFileSync(join(weakPendingLock, "owner.json.pending"), '{"boot_id":', {
    mode: 0o600,
  });
  await assert.rejects(
    async () => acquireFilesystemLock(weakPendingLock, {
      allowUnpinnedTestHelper: true,
      recoverStale: true,
      transactionId: "lock-weak-pending-test",
    }),
    /not one root-owned owner-only single-link record/,
  );
  assert.equal(existsSync(join(weakPendingLock, "owner.json.pending")), true);
});

test("stale-lock recovery reclaims only a malformed unpublished pending owner", {
  skip: ROOT_LINUX ? false : "root Linux descriptor and procfs semantics are required",
}, async (t) => {
  const root = mkdtempSync(join(tmpdir(), "bitcoinpir-overlay-lock-malformed-"));
  chmodSync(root, 0o700);
  t.after(() => rmSync(root, { force: true, recursive: true }));
  const lock = join(root, "transaction.lock");

  mkdirSync(lock, { mode: 0o700 });
  writeFileSync(join(lock, "owner.json.pending"), '{"boot_id":', { mode: 0o400 });
  const release = acquireFilesystemLock(lock, {
    allowUnpinnedTestHelper: true,
    recoverStale: true,
    transactionId: "lock-malformed-pending-recovery",
  });
  assert.equal(existsSync(join(lock, "owner.json")), true);
  assert.equal(existsSync(join(lock, "owner.json.pending")), false);
  await release();

  mkdirSync(lock, { mode: 0o700 });
  writeFileSync(join(lock, "owner.json"), '{"boot_id":', { mode: 0o400 });
  await assert.rejects(
    async () => acquireFilesystemLock(lock, {
      allowUnpinnedTestHelper: true,
      recoverStale: true,
      transactionId: "lock-malformed-authoritative-recovery",
    }),
    /authoritative lock owner is malformed; refusing stale-lock recovery/u,
  );
  assert.equal(readFileSync(join(lock, "owner.json"), "utf8"), '{"boot_id":');
});

test("SIGKILL during a partial pending-owner write is safely recoverable", {
  skip: ROOT_LINUX ? false : "root Linux descriptor and procfs semantics are required",
}, async (t) => {
  const root = mkdtempSync(join(tmpdir(), "bitcoinpir-overlay-lock-sigkill-"));
  chmodSync(root, 0o700);
  t.after(() => rmSync(root, { force: true, recursive: true }));
  const lock = join(root, "transaction.lock");
  const child = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `const { acquireFilesystemLock } = await import(${JSON.stringify(TRANSACTION_MODULE_URL)});
acquireFilesystemLock(process.argv[1], {
  allowUnpinnedTestHelper: true,
  recoverStale: false,
  transactionId: "lock-partial-write-sigkill",
  testOnlyFaultInjector(point) {
    if (point === "after-partial-write") process.kill(process.pid, "SIGKILL");
  },
});`,
      lock,
    ],
    { encoding: "utf8", timeout: 10_000 },
  );
  assert.equal(child.status, null, child.stderr);
  assert.equal(child.signal, "SIGKILL");
  assert.equal(existsSync(join(lock, "owner.json")), false);
  assert.equal(existsSync(join(lock, "owner.json.pending")), true);
  assert.equal(
    readFileSync(join(lock, "owner.json.pending"), "utf8").endsWith("}\n"),
    false,
  );

  const release = acquireFilesystemLock(lock, {
    allowUnpinnedTestHelper: true,
    recoverStale: true,
    transactionId: "lock-post-sigkill-recovery",
  });
  assert.equal(existsSync(join(lock, "owner.json")), true);
  assert.equal(existsSync(join(lock, "owner.json.pending")), false);
  await release();
});

test("production lock owner uses the pinned no-replace helper", {
  skip: ROOT_LINUX ? false : "root Linux descriptor and renameat2 semantics are required",
}, async (t) => {
  const root = mkdtempSync(join(tmpdir(), "bitcoinpir-overlay-lock-helper-"));
  chmodSync(root, 0o700);
  t.after(() => rmSync(root, { force: true, recursive: true }));
  const helper = join(root, "payment-v1-rename-exchange");
  const compile = spawnSync(
    process.env.CC ?? "cc",
    [
      "-std=c11",
      "-O2",
      "-Wall",
      "-Wextra",
      "-Werror",
      join(SCRIPT_DIRECTORY, "payment-v1-integrated-caddy-rename-exchange.c"),
      "-o",
      helper,
    ],
    { encoding: "utf8", timeout: 30_000 },
  );
  assert.equal(compile.status, 0, compile.stderr);
  chmodSync(helper, 0o555);
  const lock = join(root, "transaction.lock");
  const release = acquireFilesystemLock(lock, {
    helperPin: regularPin(helper),
    recoverStale: false,
    transactionId: "lock-pinned-helper-test",
  });
  assert.equal(existsSync(join(lock, "owner.json")), true);
  assert.equal(existsSync(join(lock, "owner.json.pending")), false);
  await release();
});

test("production lock owner classifies a helper error after atomic publication", {
  skip: ROOT_LINUX ? false : "root Linux descriptor and renameat2 semantics are required",
}, async (t) => {
  const root = mkdtempSync(join(tmpdir(), "bitcoinpir-overlay-lock-applied-error-"));
  chmodSync(root, 0o700);
  t.after(() => rmSync(root, { force: true, recursive: true }));
  const helper = compileHelper(
    root,
    "payment-v1-rename-fail-after",
    ["-DPAYMENT_V1_TEST_FAIL_AFTER_RENAME=1"],
  );
  const lock = join(root, "transaction.lock");
  const release = acquireFilesystemLock(lock, {
    helperPin: regularPin(helper),
    recoverStale: false,
    transactionId: "lock-applied-error-test",
  });
  assert.equal(existsSync(join(lock, "owner.json")), true);
  assert.equal(existsSync(join(lock, "owner.json.pending")), false);
  await release();
});

test("production lock owner fails closed when supplemental parent fsync is unprovable", {
  skip: ROOT_LINUX ? false : "root Linux descriptor and renameat2 semantics are required",
}, (t) => {
  const root = mkdtempSync(join(tmpdir(), "bitcoinpir-overlay-lock-fsync-error-"));
  chmodSync(root, 0o700);
  t.after(() => rmSync(root, { force: true, recursive: true }));
  const helper = compileHelper(
    root,
    "payment-v1-rename-fail-after",
    ["-DPAYMENT_V1_TEST_FAIL_AFTER_RENAME=1"],
  );
  const lock = join(root, "transaction.lock");
  const originalFsyncSync = fs.fsyncSync;
  let lockDirectoryFsyncs = 0;
  fs.fsyncSync = (fd) => {
    let descriptorPath = null;
    try {
      descriptorPath = readlinkSync(`/proc/self/fd/${fd}`);
    } catch {
      // Preserve the real fsync behavior for descriptors without procfs names.
    }
    if (descriptorPath === lock) {
      lockDirectoryFsyncs += 1;
      if (lockDirectoryFsyncs === 2) {
        const error = new Error("injected supplemental lock parent fsync failure");
        error.code = "EIO";
        throw error;
      }
    }
    return originalFsyncSync(fd);
  };
  syncBuiltinESMExports();
  try {
    assert.throws(
      () => acquireFilesystemLock(lock, {
        helperPin: regularPin(helper),
        recoverStale: false,
        transactionId: "lock-fsync-error-test",
      }),
      (error) => {
        assert.equal(error.name, "OverlayOutcomeUnknownError");
        assert.match(error.message, /lock owner publication outcome is unknown/);
        assert.match(
          error.publicationClassificationError?.message ?? "",
          /injected supplemental lock parent fsync failure/,
        );
        return true;
      },
    );
  } finally {
    fs.fsyncSync = originalFsyncSync;
    syncBuiltinESMExports();
  }
  assert.equal(lockDirectoryFsyncs, 2);
  assert.equal(existsSync(join(lock, "owner.json")), true);
  assert.equal(existsSync(join(lock, "owner.json.pending")), false);
});
