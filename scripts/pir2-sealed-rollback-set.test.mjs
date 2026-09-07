// Offline checks of scripts/pir2-sealed-rollback-set.sh against a temporary copy of the
// sealed data directory (docs/history/PIR2_DEPLOYMENT_PAIN_POINTS_2026-09.md #13):
// preserve refuses non-Ready startups and existing labels, verify detects tampering,
// detach-envelope only removes a matching canonical envelope, restore reinstates the set.
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import test from "node:test";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const script = resolve(repository, "scripts/pir2-sealed-rollback-set.sh");

function run(args) {
  return spawnSync("bash", [script, ...args], { encoding: "utf8", timeout: 30_000 });
}

function sealedRoot(startupPhase = "ready") {
  const root = mkdtempSync(join(tmpdir(), "pir2-sealed-"));
  writeFileSync(join(root, "credentials.envelope.bin"), "envelope-305\n");
  writeFileSync(join(root, "release.bin"), "release-gen6\n");
  writeFileSync(join(root, "identity.cert"), "cert-gen6\n");
  writeFileSync(join(root, "startup.env"), `schema=bitcoinpir-pir2-sealed-startup-v3\nprofile=pir2-snp-sealed-v1\nphase=${startupPhase}\nordinal=55\nverifier_nonce_hex=${"ab".repeat(32)}\n`);
  return root;
}

test("preserve copies the four files with a manifest, then verify and detach-envelope work", () => {
  const root = sealedRoot();
  const p = run(["preserve", "--root", root, "--label", "image305-test"]);
  assert.equal(p.status, 0, p.stdout + p.stderr);
  assert.match(p.stdout, /^PASS action=preserve label=image305-test$/m);
  const set = join(root, "rollback", "image305-test");
  for (const f of ["credentials.envelope.bin", "release.bin", "identity.cert", "startup.env", "MANIFEST.sha256"]) {
    assert.ok(existsSync(join(set, f)), `${f} preserved`);
    assert.equal(statSync(join(set, f)).mode & 0o777, 0o600, `${f} is 0600`);
  }
  assert.equal(statSync(set).mode & 0o777, 0o700);
  assert.equal(readFileSync(join(set, "startup.env"), "utf8"), readFileSync(join(root, "startup.env"), "utf8"));
  assert.equal(readFileSync(join(set, "MANIFEST.sha256"), "utf8").split("\n").filter(Boolean).length, 4);

  const again = run(["preserve", "--root", root, "--label", "image305-test"]);
  assert.equal(again.status, 1);
  assert.match(again.stderr, /already exists/);

  const v = run(["verify", "--root", root, "--label", "image305-test"]);
  assert.equal(v.status, 0, v.stdout + v.stderr);
  assert.match(v.stdout, /^PASS action=verify/m);

  const preview = run(["detach-envelope", "--root", root, "--label", "image305-test", "--dry-run"]);
  assert.equal(preview.status, 0, preview.stdout + preview.stderr);
  assert.match(preview.stdout, /^canonical_envelope=present$/m);
  assert.match(preview.stdout, /^PASS action=detach-envelope label=image305-test dry_run=true$/m);
  assert.ok(existsSync(join(root, "credentials.envelope.bin")), "dry run keeps the envelope");

  const detach = run(["detach-envelope", "--root", root, "--label", "image305-test", "--apply"]);
  assert.equal(detach.status, 0, detach.stdout + detach.stderr);
  assert.match(detach.stdout, /^envelope_removed=true$/m);
  assert.ok(!existsSync(join(root, "credentials.envelope.bin")), "envelope removed");
  assert.ok(existsSync(join(set, "credentials.envelope.bin")), "set keeps its copy");

  // Simulate the new image's Enroll/Ready having replaced everything, then roll back.
  writeFileSync(join(root, "credentials.envelope.bin"), "envelope-307\n");
  writeFileSync(join(root, "release.bin"), "release-gen7\n");
  writeFileSync(join(root, "identity.cert"), "cert-gen7\n");
  writeFileSync(join(root, "startup.env"), "phase=ready\nordinal=60\n");
  const plan = run(["restore", "--root", root, "--label", "image305-test", "--dry-run"]);
  assert.equal(plan.status, 0, plan.stdout + plan.stderr);
  assert.match(plan.stdout, /^planned_copy=.*startup\.env -> .*startup\.env$/m);
  assert.equal(readFileSync(join(root, "release.bin"), "utf8"), "release-gen7\n", "dry run changes nothing");
  const restore = run(["restore", "--root", root, "--label", "image305-test", "--apply"]);
  assert.equal(restore.status, 0, restore.stdout + restore.stderr);
  assert.match(restore.stdout, /^PASS action=restore label=image305-test$/m);
  assert.equal(readFileSync(join(root, "credentials.envelope.bin"), "utf8"), "envelope-305\n");
  assert.equal(readFileSync(join(root, "release.bin"), "utf8"), "release-gen6\n");
  assert.equal(readFileSync(join(root, "identity.cert"), "utf8"), "cert-gen6\n");
  assert.match(readFileSync(join(root, "startup.env"), "utf8"), /ordinal=55/);
});

test("preserve refuses a non-Ready startup unless --startup-from names the previous Ready file", () => {
  const root = sealedRoot("observe");
  const refused = run(["preserve", "--root", root, "--label", "image305-a"]);
  assert.equal(refused.status, 1);
  assert.match(refused.stderr, /phase=observe, not ready/);
  assert.ok(!existsSync(join(root, "rollback", "image305-a")));
  const backup = join(root, "startup.env.ready-ordinal55.bak");
  writeFileSync(backup, "phase=ready\nordinal=55\n");
  const ok = run(["preserve", "--root", root, "--label", "image305-a", "--startup-from", backup]);
  assert.equal(ok.status, 0, ok.stdout + ok.stderr);
  assert.match(readFileSync(join(root, "rollback", "image305-a", "startup.env"), "utf8"), /ordinal=55/);
});

test("verify and detach-envelope fail closed on a tampered set or a foreign canonical envelope", () => {
  const root = sealedRoot();
  assert.equal(run(["preserve", "--root", root, "--label", "image305-b"]).status, 0);
  const set = join(root, "rollback", "image305-b");
  writeFileSync(join(set, "release.bin"), "tampered\n");
  const v = run(["verify", "--root", root, "--label", "image305-b"]);
  assert.equal(v.status, 1);
  assert.match(v.stderr, /rollback set file changed: release\.bin/);
  const restore = run(["restore", "--root", root, "--label", "image305-b", "--apply"]);
  assert.equal(restore.status, 1, "restore refuses a tampered set");
  writeFileSync(join(set, "release.bin"), "release-gen6\n");
  assert.equal(run(["verify", "--root", root, "--label", "image305-b"]).status, 0);
  writeFileSync(join(root, "credentials.envelope.bin"), "some-other-envelope\n");
  const detach = run(["detach-envelope", "--root", root, "--label", "image305-b", "--apply"]);
  assert.equal(detach.status, 1);
  assert.match(detach.stderr, /canonical envelope differs from the rollback set/);
  assert.ok(existsSync(join(root, "credentials.envelope.bin")), "foreign envelope kept");
});

test("usage errors: unknown action, bad label, missing root", () => {
  assert.equal(run(["bogus"]).status, 2);
  const root = sealedRoot();
  const badLabel = run(["preserve", "--root", root, "--label", "../escape"]);
  assert.equal(badLabel.status, 2);
  assert.match(badLabel.stderr, /--label must be/);
  const noRoot = run(["verify", "--root", join(root, "missing"), "--label", "x"]);
  assert.equal(noRoot.status, 2);
  assert.match(noRoot.stderr, /root is not a directory/);
  const noSet = run(["verify", "--root", root, "--label", "never-preserved"]);
  assert.equal(noSet.status, 1);
  assert.match(noSet.stderr, /rollback set missing/);
});
