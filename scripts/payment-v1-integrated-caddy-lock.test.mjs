import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
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
