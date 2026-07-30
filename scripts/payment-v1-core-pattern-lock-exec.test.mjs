import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test, { after } from "node:test";
import { fileURLToPath } from "node:url";

const source = new URL("./payment-v1-core-pattern-lock-exec.c", import.meta.url);
const sourcePath = fileURLToPath(source);
const root = mkdtempSync(join(tmpdir(), "bitcoinpir-core-pattern-lock-exec-"));
const binary = join(root, "payment-v1-core-pattern-lock-exec");
const compiler = process.env.CC || "cc";
const compiled = spawnSync(
  compiler,
  ["-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", "-o", binary, sourcePath],
  { encoding: "utf8" },
);
assert.equal(compiled.status, 0, compiled.stderr || compiled.error?.message);
after(() => rmSync(root, { force: true, recursive: true }));

const node = "/usr/bin/node";
const ceremony =
  "/usr/local/libexec/bitcoinpir/payment-v1-core-pattern-ceremony.mjs";
const cleanEnvironment = {
  LANG: "C",
  LC_ALL: "C",
  PATH: "/usr/bin:/bin",
  TZ: "UTC",
};

const applyArgv = [
  "--",
  node,
  ceremony,
  "apply",
  "--plan",
  "/tmp/plan.json",
  "--approved-plan-sha256",
  "a".repeat(64),
  "--approved-source-sha256",
  "b".repeat(64),
  "--approval",
  "/tmp/approval.json",
  "--approved-approval-sha256",
  "c".repeat(64),
];

function invoke(args, extraEnvironment = {}) {
  return spawnSync(binary, args, {
    encoding: "utf8",
    env: { ...cleanEnvironment, ...extraEnvironment },
  });
}

function assertRejected(args, pattern = /unreviewed/u) {
  const result = invoke(args);
  assert.equal(result.status, 2, result.stderr);
  assert.match(result.stderr, pattern);
}

test("helper compiles warning-free and exposes only its reviewed version query", () => {
  const result = invoke(["--version"]);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "bitcoinpir-payment-v1-core-pattern-lock-exec 2\n");
});

test("only exact Node and canonical ceremony source reach maintenance-lock acquisition", () => {
  const accepted = invoke(applyArgv);
  assert.notEqual(accepted.status, 2, accepted.stderr);
  assert.doesNotMatch(accepted.stderr, /unreviewed/u);

  assertRejected(["--", "/bin/sh", ceremony, ...applyArgv.slice(3)]);
  assertRejected(["--", node, "/tmp/ceremony.mjs", ...applyArgv.slice(3)]);
});

test("Node execArgv and non-maintenance ceremony commands are rejected", () => {
  for (const injected of [
    "--inspect",
    "--require=/tmp/inject.cjs",
    "--experimental-loader=/tmp/inject.mjs",
    "--import=/tmp/inject.mjs",
  ]) {
    assertRejected(["--", node, injected, ceremony, ...applyArgv.slice(3)]);
  }
  for (const command of [
    "observe-plan",
    "validate-plan",
    "early-apport-gate",
    "early-sysctl-gate",
    "early-fail-closed",
  ]) {
    assertRejected(["--", node, ceremony, command]);
  }
});

test("each maintenance command requires its exact option set with no duplicates or extras", () => {
  assertRejected(applyArgv.slice(0, -2), /subcommand argv/u);
  assertRejected([...applyArgv, "--extra", "value"], /subcommand argv/u);
  const duplicate = [...applyArgv];
  duplicate[duplicate.indexOf("--approval")] = "--plan";
  assertRejected(duplicate, /subcommand argv/u);
  const empty = [...applyArgv];
  empty[empty.length - 1] = "";
  assertRejected(empty, /subcommand argv/u);

  const recover = [
    "--", node, ceremony, "recover",
    "--plan", "/tmp/plan.json",
    "--approved-plan-sha256", "a".repeat(64),
    "--approved-source-sha256", "b".repeat(64),
    "--recovery-approval", "/tmp/recovery.json",
    "--approved-recovery-approval-sha256", "c".repeat(64),
  ];
  const rollback = [
    "--", node, ceremony, "rollback",
    "--plan", "/tmp/plan.json",
    "--approved-plan-sha256", "a".repeat(64),
    "--approved-source-sha256", "b".repeat(64),
    "--rollback-approval", "/tmp/rollback.json",
    "--approved-rollback-approval-sha256", "c".repeat(64),
    "--approved-receipt-sha256", "d".repeat(64),
  ];
  for (const args of [recover, rollback]) {
    const accepted = invoke(args);
    assert.notEqual(accepted.status, 2, accepted.stderr);
    assert.doesNotMatch(accepted.stderr, /unreviewed/u);
  }
});

test("loader, Node, and inherited-lock environment injection is rejected before version or locks", () => {
  for (const name of [
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "GLIBC_TUNABLES",
    "NODE_OPTIONS",
    "NODE_PATH",
    "NODE_REPL_EXTERNAL_MODULE",
    "BITCOINPIR_CORE_PATTERN_MAINTENANCE_LOCK_FDS",
  ]) {
    // Keep loader variables empty so the platform loader reaches main; their
    // mere presence must still be rejected by the helper.
    const result = invoke(["--version"], { [name]: "" });
    assert.equal(result.status, 2, name + ": " + result.stderr);
    assert.match(result.stderr, /prohibited loader, Node, or inherited-lock environment/u);
  }
});

test("compiled source retains a closed execve environment and never delegates program choice", () => {
  const text = readFileSync(source, "utf8");
  assert.match(text, /execve\(NODE, &argv\[2\], environment\)/u);
  assert.doesNotMatch(text, /execvpe|execvp|system\s*\(/u);
  for (const exact of [
    '"LANG=C"',
    '"LC_ALL=C"',
    '"PATH=/usr/sbin:/usr/bin"',
    '"TZ=UTC"',
  ]) assert.ok(text.includes(exact), exact);
});
