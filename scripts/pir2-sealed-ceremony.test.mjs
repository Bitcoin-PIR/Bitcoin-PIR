// Offline checks of scripts/pir2-sealed-ceremony.sh: the exact command each
// action would run (dry runs), the BPIR_ADMIN prebuilt-binary override
// (docs/history/PIR2_DEPLOYMENT_PAIN_POINTS_2026-09.md #11), and the exit
// status the wrapper forwards from bpir-admin. Never invokes cargo.
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import test from "node:test";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const wrapper = resolve(repository, "scripts/pir2-sealed-ceremony.sh");
const CARGO = "cargo run --locked --offline -p bpir-admin --";

function run(args, extraEnv = {}) {
  const env = { ...process.env, ...extraEnv };
  if (!("BPIR_ADMIN" in extraEnv)) delete env.BPIR_ADMIN;
  return spawnSync("bash", [wrapper, ...args], { env, encoding: "utf8", timeout: 30_000 });
}

// A stand-in bpir-admin that echoes its argv and exits as told.
function fakeAdmin(exitCode) {
  const dir = mkdtempSync(join(tmpdir(), "bpir-admin-"));
  const bin = join(dir, "bpir-admin");
  writeFileSync(bin, `#!/bin/sh\nprintf 'FAKE_ADMIN_ARGV=%s\\n' "$*"\nexit ${exitCode}\n`);
  chmodSync(bin, 0o755);
  return { dir, bin };
}

function commandLine(stdout) {
  const line = stdout.split("\n").find((l) => l.startsWith("COMMAND="));
  assert.ok(line, stdout);
  return line.slice("COMMAND=".length).trim();
}

test("receipt --dry-run with no further options previews the cargo command (empty option list is valid)", () => {
  const r = run(["receipt", "--dry-run"]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.equal(commandLine(r.stdout), `${CARGO} pir2-sealed-receipt-verify`);
  assert.match(r.stdout, /^PASS sealed_receipt_verify dry_run=true$/m);
});

test("fetch and release dry runs forward their options verbatim", () => {
  const fetch = run(["fetch", "wss://example.invalid", "--out-dir", "/evidence", "--dry-run"]);
  assert.equal(fetch.status, 0, fetch.stdout + fetch.stderr);
  assert.equal(commandLine(fetch.stdout), `${CARGO} pir2-sealed-receipt-fetch wss://example.invalid --out-dir /evidence`);
  assert.match(fetch.stdout, /^PASS sealed_receipt_fetch dry_run=true$/m);
  const release = run(["release", "--dry-run", "--observe-receipt", "/observe.bin"]);
  assert.equal(release.status, 0, release.stdout + release.stderr);
  assert.equal(commandLine(release.stdout), `${CARGO} pir2-sealed-release --observe-receipt /observe.bin`);
  assert.match(release.stdout, /^PASS sealed_release dry_run=true$/m);
});

test("BPIR_ADMIN replaces the cargo invocation in the preview and runs the prebuilt binary", () => {
  const { bin } = fakeAdmin(0);
  const preview = run(["receipt", "--dry-run"], { BPIR_ADMIN: bin });
  assert.equal(preview.status, 0, preview.stdout + preview.stderr);
  assert.equal(commandLine(preview.stdout), `${bin} pir2-sealed-receipt-verify`);
  assert.doesNotMatch(preview.stdout, /cargo/);

  const receipt = run(["receipt", "--receipt", "/r.bin"], { BPIR_ADMIN: bin });
  assert.equal(receipt.status, 0, receipt.stdout + receipt.stderr);
  assert.match(receipt.stdout, /^\[stage\] accept sealed phase receipt/m);
  assert.match(receipt.stdout, /^FAKE_ADMIN_ARGV=pir2-sealed-receipt-verify --receipt \/r\.bin$/m);

  const fetch = run(["fetch", "wss://example.invalid", "--out-dir", "/evidence"], { BPIR_ADMIN: bin });
  assert.equal(fetch.status, 0, fetch.stdout + fetch.stderr);
  assert.match(fetch.stdout, /^FAKE_ADMIN_ARGV=pir2-sealed-receipt-fetch wss:\/\/example\.invalid --out-dir \/evidence$/m);

  const release = run(["release", "--out", "/release.bin"], { BPIR_ADMIN: bin });
  assert.equal(release.status, 0, release.stdout + release.stderr);
  assert.match(release.stdout, /^FAKE_ADMIN_ARGV=pir2-sealed-release --out \/release\.bin$/m);
  assert.match(release.stdout, /^PASS sealed_release$/m);

  // `--help` anywhere is the wrapper's own usage; bpir-admin is not invoked.
  const help = run(["receipt", "--help"], { BPIR_ADMIN: bin });
  assert.equal(help.status, 0, help.stdout + help.stderr);
  assert.match(help.stdout, /^usage: scripts\/pir2-sealed-ceremony\.sh release/m);
  assert.doesNotMatch(help.stdout, /FAKE_ADMIN_ARGV/);
});

test("a failing bpir-admin fails the wrapper with the same status and no PASS line", () => {
  const { bin } = fakeAdmin(3);
  const receipt = run(["receipt", "--receipt", "/r.bin"], { BPIR_ADMIN: bin });
  assert.equal(receipt.status, 3, receipt.stdout + receipt.stderr);
  const release = run(["release", "--out", "/release.bin"], { BPIR_ADMIN: bin });
  assert.equal(release.status, 3, release.stdout + release.stderr);
  assert.doesNotMatch(release.stdout, /^PASS sealed_release$/m);
});

test("BPIR_ADMIN must be an absolute path to an executable file", () => {
  const { dir, bin } = fakeAdmin(0);
  const notExecutable = join(dir, "notes.txt");
  writeFileSync(notExecutable, "not a binary\n");
  for (const value of ["target/release/bpir-admin", join(dir, "missing"), notExecutable, dir]) {
    const r = run(["receipt", "--dry-run"], { BPIR_ADMIN: value });
    assert.equal(r.status, 2, `${value}: ${r.stdout}${r.stderr}`);
    assert.match(r.stderr, /BPIR_ADMIN must be an absolute path to an executable file/);
    assert.doesNotMatch(r.stdout, /COMMAND=/);
  }
  const ok = run(["receipt", "--dry-run"], { BPIR_ADMIN: bin });
  assert.equal(ok.status, 0, ok.stdout + ok.stderr);
});

test("phase --dry-run never touches bpir-admin and an unknown action prints usage", () => {
  const nonce = "ab".repeat(32);
  const phase = run(["phase", "--phase", "observe", "--out", "/absolute/observe.startup.env",
    "--ordinal", "56", "--verifier-nonce-hex", nonce, "--dry-run"], { BPIR_ADMIN: "/nonexistent" });
  assert.equal(phase.status, 0, phase.stdout + phase.stderr);
  assert.match(phase.stdout, /^PASS sealed_phase_config=observe$/m);
  const bogus = run(["bogus"]);
  assert.equal(bogus.status, 2);
  assert.match(bogus.stderr, /usage: scripts\/pir2-sealed-ceremony\.sh release/);
});
