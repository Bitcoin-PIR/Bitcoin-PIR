// Offline checks of scripts/generate-release-record.sh: schema-v1 output from a fake UKI +
// sidecar, and --attest-log (docs/history/PIR2_DEPLOYMENT_PAIN_POINTS_2026-09.md #14): the
// measurement and served-manifest digests are taken only from a `bpir-admin attest` run whose
// REPORT_DATA binding and AMD chain verified and whose binary is the sidecar's.
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import test from "node:test";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const script = resolve(repository, "scripts/generate-release-record.sh");
const BIN = "11".repeat(32), ORAMCTL = "22".repeat(32), MEAS = "3a".repeat(48), DB0 = "44".repeat(32), DB1 = "55".repeat(32);

function fixture() {
  const dir = mkdtempSync(join(tmpdir(), "release-record-"));
  const uki = join(dir, "tier3-test.efi");
  writeFileSync(uki, "not-really-a-uki\n");
  writeFileSync(`${uki}.meta`, `kind=tier3\nbinary_sha256=${BIN}\noramctl_sha256=${ORAMCTL}\n`);
  return { dir, uki };
}

function attestLog(overrides = {}) {
  const o = { binary: BIN, measurement: MEAS, db0: DB0, db1: DB1, reportData: true, chain: true, ...overrides };
  return [
    "Server URL:        wss://example.invalid",
    "== Self-reported (server-side) ==",
    `binary_sha256:     ${o.binary}`,
    "git_rev:           deadbeef",
    "manifest roots (2 DBs):",
    `  db_id=0: ${o.db0}`,
    `  db_id=1: ${o.db1}`,
    "== SEV-SNP attestation ==",
    "Status:            ReportDataMatch",
    `Launch MEASUREMENT: ${o.measurement}`,
    o.reportData ? "✓ SEV-SNP REPORT_DATA binding verified." : "✗ REPORT_DATA does not match recomputation —",
    o.chain ? "✓ AMD ARK→ASK→VCEK chain and this attestation report's signature verified." : "",
    "",
  ].join("\n");
}

function run(args) {
  return spawnSync("bash", [script, ...args], { encoding: "utf8", timeout: 30_000 });
}

function fields(path) {
  return Object.fromEntries(readFileSync(path, "utf8").split("\n").filter(Boolean).map((l) => l.split("=", 2)));
}

test("without an attest log the record carries the sidecar hashes and lists the TODO fields", () => {
  const { dir, uki } = fixture();
  const out = join(dir, "record.env");
  const r = run(["--uki", uki, "--image-id", "999", "--server-id", "25285", "--runtime-rev", "r".repeat(40), "--web-pin-rev", "w".repeat(40), "--out", out]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  const f = fields(out);
  assert.equal(f.schema_version, "1");
  assert.equal(f.vpsbg_image_id, "999");
  assert.equal(f.unified_server_sha256, BIN);
  assert.equal(f.oramctl_sha256, ORAMCTL);
  assert.equal(f.measurement, "TODO");
  assert.equal(f.db0_server_manifest_sha256, "TODO");
  assert.match(r.stdout, /incomplete — fill in these fields/);
  assert.match(r.stdout, /db1_server_manifest_sha256/);
  assert.equal(Object.keys(f).length, 15, "schema v1 has exactly 15 fields");
});

test("--attest-log fills measurement and both served-manifest digests from a verified attest run", () => {
  const { dir, uki } = fixture();
  const log = join(dir, "attest.log"); writeFileSync(log, attestLog());
  const out = join(dir, "record.env");
  const r = run(["--uki", uki, "--image-id", "999", "--server-id", "25285", "--runtime-rev", "r".repeat(40), "--web-pin-rev", "w".repeat(40), "--attest-log", log, "--acceptance", "smoke_passed", "--out", out]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  const f = fields(out);
  assert.equal(f.measurement, MEAS);
  assert.equal(f.db0_server_manifest_sha256, DB0);
  assert.equal(f.db1_server_manifest_sha256, DB1);
  assert.equal(f.browser_acceptance, "smoke_passed");
  assert.match(r.stdout, /all schema-v1 fields filled/);
  assert.match(r.stderr, /attested values taken from/);
});

test("--attest-log is refused unless both verification lines are present and the binary is the sidecar's", () => {
  const { dir, uki } = fixture();
  const out = join(dir, "record.env");
  const cases = [
    ["no REPORT_DATA line", attestLog({ reportData: false }), /REPORT_DATA binding verification line/],
    ["no AMD chain line", attestLog({ chain: false }), /AMD chain \+ report-signature verification line/],
    ["other binary", attestLog({ binary: "99".repeat(32) }), /binary_sha256 differs from the UKI sidecar/],
    ["short measurement", attestLog({ measurement: "abcd" }), /not 96 hex/],
    ["missing db1", attestLog({ db1: "" }), /no value for db1/],
  ];
  for (const [label, text, pattern] of cases) {
    const log = join(dir, `attest-${label.replace(/\W+/g, "_")}.log`); writeFileSync(log, text);
    const r = run(["--uki", uki, "--image-id", "999", "--runtime-rev", "r".repeat(40), "--web-pin-rev", "w".repeat(40), "--attest-log", log, "--out", out]);
    assert.notEqual(r.status, 0, `${label}: should fail`);
    assert.match(r.stderr, pattern, label);
  }
  const missing = run(["--uki", uki, "--image-id", "999", "--runtime-rev", "r".repeat(40), "--web-pin-rev", "w".repeat(40), "--attest-log", join(dir, "nope.log"), "--out", out]);
  assert.equal(missing.status, 2);
});

test("an explicit flag that disagrees with the attest log is an error; an agreeing one is fine", () => {
  const { dir, uki } = fixture();
  const log = join(dir, "attest.log"); writeFileSync(log, attestLog());
  const out = join(dir, "record.env");
  const bad = run(["--uki", uki, "--image-id", "999", "--runtime-rev", "r".repeat(40), "--web-pin-rev", "w".repeat(40), "--attest-log", log, "--db0-manifest-sha256", "66".repeat(32), "--out", out]);
  assert.notEqual(bad.status, 0);
  assert.match(bad.stderr, /--db0 flag disagrees with the attest log/);
  const ok = run(["--uki", uki, "--image-id", "999", "--runtime-rev", "r".repeat(40), "--web-pin-rev", "w".repeat(40), "--attest-log", log, "--measurement", MEAS, "--out", out]);
  assert.equal(ok.status, 0, ok.stdout + ok.stderr);
  assert.equal(fields(out).measurement, MEAS);
});
