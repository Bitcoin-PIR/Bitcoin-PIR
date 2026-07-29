import assert from "node:assert/strict";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  acquireFilesystemLock,
} from "./payment-v1-integrated-caddy-overlay-transaction.mjs";
import { canonicalJson } from "./payment-v1-integrated-caddy-overlay-gate.mjs";

const ROOT_LINUX =
  process.platform === "linux" &&
  typeof process.geteuid === "function" &&
  process.geteuid() === 0;

test("filesystem lock distinguishes a live holder from an exact stale process generation", {
  skip: ROOT_LINUX ? false : "root Linux descriptor and procfs semantics are required",
}, async (t) => {
  const root = mkdtempSync(join(tmpdir(), "bitcoinpir-overlay-lock-"));
  chmodSync(root, 0o700);
  t.after(() => rmSync(root, { force: true, recursive: true }));
  const lock = join(root, "transaction.lock");
  const release = acquireFilesystemLock(lock, {
    recoverStale: false,
    transactionId: "lock-live-test",
  });
  await assert.rejects(
    async () => acquireFilesystemLock(lock, {
      recoverStale: false,
      transactionId: "lock-contender-test",
    }),
    /explicit recover command/,
  );
  await assert.rejects(
    async () => acquireFilesystemLock(lock, {
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
    recoverStale: true,
    transactionId: "lock-recovery-test",
  });
  await releaseRecovered();
});

test("stale-lock recovery refuses an unknown directory shape", {
  skip: ROOT_LINUX ? false : "root Linux descriptor and procfs semantics are required",
}, async (t) => {
  const root = mkdtempSync(join(tmpdir(), "bitcoinpir-overlay-lock-shape-"));
  chmodSync(root, 0o700);
  t.after(() => rmSync(root, { force: true, recursive: true }));
  const lock = join(root, "transaction.lock");
  mkdirSync(lock, { mode: 0o700 });
  writeFileSync(join(lock, "unknown"), "do-not-delete\n", { mode: 0o400 });
  await assert.rejects(
    async () => acquireFilesystemLock(lock, {
      recoverStale: true,
      transactionId: "lock-recovery-test",
    }),
    /unknown shape/,
  );
});
