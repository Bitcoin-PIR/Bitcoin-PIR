import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  linkSync,
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

const REPOSITORY = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SOURCE = join(REPOSITORY, "scripts/payment-v1-integrated-caddy-rename-exchange.c");

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
