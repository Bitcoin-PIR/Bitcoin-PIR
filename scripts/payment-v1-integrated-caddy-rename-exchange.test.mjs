import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  testOnlyAtomicPublicationFaultHarness,
} from "./payment-v1-integrated-caddy-overlay-transaction.mjs";

const REPOSITORY = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SOURCE = join(REPOSITORY, "scripts/payment-v1-integrated-caddy-rename-exchange.c");
const ROOT_LINUX = process.platform === "linux" && process.geteuid?.() === 0;

function run(binary, left, right) {
  return spawnSync(binary, ["--exchange", left, right], {
    encoding: "utf8",
    timeout: 10_000,
  });
}

function publish(binary, pending, final) {
  return spawnSync(binary, ["--publish", pending, final], {
    encoding: "utf8",
    timeout: 10_000,
  });
}

function runAsync(binary, left, right) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(binary, ["--exchange", left, right], {
      stdio: ["ignore", "ignore", "pipe"],
    });
    let stderr = "";
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.once("error", rejectPromise);
    child.once("exit", (status, signal) => resolvePromise({ signal, status, stderr }));
  });
}

test("Linux renameat2 helper exchanges regular entries and rejects aliasing boundaries", {
  skip: process.platform !== "linux" ? "Linux renameat2 is required" : false,
}, async (t) => {
  const root = mkdtempSync(join(tmpdir(), "bitcoinpir-rename-exchange-"));
  t.after(() => rmSync(root, { force: true, recursive: true }));
  const binary = join(root, "payment-v1-rename-exchange");
  const compile = spawnSync(
    process.env.CC ?? "cc",
    ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", SOURCE, "-o", binary],
    { encoding: "utf8", timeout: 30_000 },
  );
  assert.equal(compile.status, 0, compile.stderr);
  chmodSync(binary, 0o555);
  const version = spawnSync(binary, ["--version"], { encoding: "utf8", timeout: 10_000 });
  assert.equal(version.status, 0, version.stderr);
  assert.equal(version.stdout, "bitcoinpir-payment-v1-rename-exchange 3\n");

  const left = join(root, "left");
  const right = join(root, "right");
  writeFileSync(left, "left-generation\n", { mode: 0o600 });
  writeFileSync(right, "right-generation\n", { mode: 0o600 });
  let result = run(binary, left, right);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(readFileSync(left, "utf8"), "right-generation\n");
  assert.equal(readFileSync(right, "utf8"), "left-generation\n");

  result = run(binary, `${root}/./left`, right);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /dot or dot-dot components/);

  // An even number of concurrent atomic exchanges must leave both names and
  // both inodes present in their original post-first-exchange arrangement.
  const concurrent = await Promise.all(
    Array.from({ length: 16 }, () => runAsync(binary, left, right)),
  );
  assert.deepEqual(
    concurrent.map((entry) => [entry.status, entry.signal]),
    Array.from({ length: 16 }, () => [0, null]),
    concurrent.map((entry) => entry.stderr).join("\n"),
  );
  assert.equal(readFileSync(left, "utf8"), "right-generation\n");
  assert.equal(readFileSync(right, "utf8"), "left-generation\n");

  unlinkSync(left);
  symlinkSync(right, left);
  result = run(binary, left, right);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /single-link regular files/);
  assert.equal(readFileSync(right, "utf8"), "left-generation\n");

  unlinkSync(left);
  writeFileSync(left, "hardlinked\n", { mode: 0o600 });
  const alias = join(root, "left-alias");
  linkSync(left, alias);
  result = run(binary, left, right);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /single-link regular files/);

  const pending = join(root, "receipt.json.pending");
  const final = join(root, "receipt.json");
  writeFileSync(pending, "durable-receipt\n", { mode: 0o400 });
  result = publish(binary, pending, final);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(existsSync(pending), false);
  assert.equal(readFileSync(final, "utf8"), "durable-receipt\n");

  const secondPending = join(root, "second-receipt.json.pending");
  writeFileSync(secondPending, "must-not-clobber\n", { mode: 0o400 });
  result = publish(binary, secondPending, final);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /destination already exists|RENAME_NOREPLACE/);
  assert.equal(readFileSync(final, "utf8"), "durable-receipt\n");
  assert.equal(readFileSync(secondPending, "utf8"), "must-not-clobber\n");
});

test("Linux helper exposes applied-then-error classification and cannot mutate after parent death", {
  skip: process.platform !== "linux" ? "Linux renameat2 and prctl are required" : false,
}, async (t) => {
  const root = mkdtempSync(join(tmpdir(), "bitcoinpir-rename-crash-"));
  t.after(() => rmSync(root, { force: true, recursive: true }));

  const failBinary = join(root, "payment-v1-rename-fail-after");
  let compile = spawnSync(
    process.env.CC ?? "cc",
    [
      "-std=c11",
      "-O2",
      "-Wall",
      "-Wextra",
      "-Werror",
      "-DPAYMENT_V1_TEST_FAIL_AFTER_RENAME=1",
      SOURCE,
      "-o",
      failBinary,
    ],
    { encoding: "utf8", timeout: 30_000 },
  );
  assert.equal(compile.status, 0, compile.stderr);
  const appliedLeft = join(root, "applied-left");
  const appliedRight = join(root, "applied-right");
  writeFileSync(appliedLeft, "left-before\n", { mode: 0o600 });
  writeFileSync(appliedRight, "right-before\n", { mode: 0o600 });
  const applied = run(failBinary, appliedLeft, appliedRight);
  assert.notEqual(applied.status, 0);
  assert.match(applied.stderr, /injected failure after renameat2/);
  assert.equal(readFileSync(appliedLeft, "utf8"), "right-before\n");
  assert.equal(readFileSync(appliedRight, "utf8"), "left-before\n");

  const delayedBinary = join(root, "payment-v1-rename-delayed");
  compile = spawnSync(
    process.env.CC ?? "cc",
    [
      "-std=c11",
      "-O2",
      "-Wall",
      "-Wextra",
      "-Werror",
      "-DPAYMENT_V1_TEST_DELAY_BEFORE_RENAME_MS=1500",
      SOURCE,
      "-o",
      delayedBinary,
    ],
    { encoding: "utf8", timeout: 30_000 },
  );
  assert.equal(compile.status, 0, compile.stderr);
  const guardedLeft = join(root, "guarded-left");
  const guardedRight = join(root, "guarded-right");
  writeFileSync(guardedLeft, "guarded-left-before\n", { mode: 0o600 });
  writeFileSync(guardedRight, "guarded-right-before\n", { mode: 0o600 });
  const ready = join(root, "supervisor-ready");
  const supervisor = spawn(
    process.execPath,
    [
      "-e",
      [
        'const { spawn } = require("node:child_process");',
        'const { writeFileSync } = require("node:fs");',
        "const child = spawn(process.argv[1], [\"--exchange\", process.argv[2], process.argv[3]], { stdio: \"ignore\" });",
        "writeFileSync(process.argv[4], String(child.pid));",
        "child.unref();",
        "setInterval(() => {}, 1000);",
      ].join("\n"),
      delayedBinary,
      guardedLeft,
      guardedRight,
      ready,
    ],
    { stdio: "ignore" },
  );
  for (let attempt = 0; attempt < 40 && !existsSync(ready); attempt += 1) {
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 25));
  }
  assert.equal(existsSync(ready), true, "helper supervisor did not report readiness");
  await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
  const supervisorExit = new Promise((resolvePromise) => {
    supervisor.once("exit", (status, signal) => resolvePromise({ signal, status }));
  });
  supervisor.kill("SIGKILL");
  assert.deepEqual(await supervisorExit, { signal: "SIGKILL", status: null });
  await new Promise((resolvePromise) => setTimeout(resolvePromise, 2_000));
  assert.equal(readFileSync(guardedLeft, "utf8"), "guarded-left-before\n");
  assert.equal(readFileSync(guardedRight, "utf8"), "guarded-right-before\n");
});

test("real Linux atomic publication recovers every open/write/fsync/rename boundary", {
  skip: ROOT_LINUX ? false : "root Linux descriptor semantics are required",
}, async (t) => {
  const root = mkdtempSync(join(tmpdir(), "bitcoinpir-publication-faults-"));
  chmodSync(root, 0o700);
  t.after(() => rmSync(root, { force: true, recursive: true }));
  const binary = join(root, "payment-v1-rename-exchange");
  let compile = spawnSync(
    process.env.CC ?? "cc",
    ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", SOURCE, "-o", binary],
    { encoding: "utf8", timeout: 30_000 },
  );
  assert.equal(compile.status, 0, compile.stderr);
  chmodSync(binary, 0o555);

  const points = [
    "before-open",
    "after-open",
    "after-partial-write",
    "after-write",
    "after-file-fsync",
    "before-pending-dir-fsync",
    "after-pending-dir-fsync",
    "before-rename",
    "after-rename",
    "before-final-dir-fsync",
    "after-final-dir-fsync",
  ];
  for (const [index, faultAt] of points.entries()) {
    const directory = join(root, `phase-${index}`);
    mkdirSync(directory, { mode: 0o700 });
    const result = await testOnlyAtomicPublicationFaultHarness({
      bytes: Buffer.from(`phase=${faultAt}\n`),
      directory,
      faultAt,
      helperPath: binary,
    });
    assert.match(result.initial_error ?? "", /injected atomic-publication fault/, faultAt);
    assert.equal(result.pending, null, faultAt);
    if (["before-open", "after-open", "after-partial-write"].includes(faultAt)) {
      assert.equal(result.final, null, faultAt);
      assert.equal(result.settled, null, faultAt);
    } else {
      assert.notEqual(result.final, null, faultAt);
      assert.notEqual(result.settled, null, faultAt);
      assert.equal(result.final.snapshot.mode, "0400", faultAt);
      assert.equal(result.final.snapshot.nlink, 1, faultAt);
    }
    const second = await testOnlyAtomicPublicationFaultHarness({
      bytes: Buffer.from(`phase=${faultAt}\n`),
      directory,
      faultAt: "never",
      helperPath: binary,
    });
    const third = await testOnlyAtomicPublicationFaultHarness({
      bytes: Buffer.from(`phase=${faultAt}\n`),
      directory,
      faultAt: "never",
      helperPath: binary,
    });
    assert.equal(second.pending, null, `${faultAt} second recovery`);
    assert.equal(third.pending, null, `${faultAt} third recovery`);
    assert.notEqual(second.final, null, `${faultAt} second recovery`);
    assert.notEqual(third.final, null, `${faultAt} third recovery`);
    assert.equal(
      third.final.snapshot.inode,
      second.final.snapshot.inode,
      `${faultAt} third recovery replaced the durable generation`,
    );
  }

  const failBinary = join(root, "payment-v1-rename-fail-after");
  compile = spawnSync(
    process.env.CC ?? "cc",
    [
      "-std=c11",
      "-O2",
      "-Wall",
      "-Wextra",
      "-Werror",
      "-DPAYMENT_V1_TEST_FAIL_AFTER_RENAME=1",
      SOURCE,
      "-o",
      failBinary,
    ],
    { encoding: "utf8", timeout: 30_000 },
  );
  assert.equal(compile.status, 0, compile.stderr);
  chmodSync(failBinary, 0o555);
  const appliedDirectory = join(root, "applied-then-error");
  mkdirSync(appliedDirectory, { mode: 0o700 });
  const applied = await testOnlyAtomicPublicationFaultHarness({
    bytes: Buffer.from("applied-before-helper-error\n"),
    directory: appliedDirectory,
    faultAt: "never",
    helperPath: failBinary,
  });
  assert.match(applied.initial_error ?? "", /injected failure after renameat2/);
  assert.equal(applied.pending, null);
  assert.notEqual(applied.final, null);
  assert.notEqual(applied.settled, null);
});
