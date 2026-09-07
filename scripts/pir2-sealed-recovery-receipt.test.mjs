// Offline checks of scripts/pir2-sealed-recovery-receipt.sh against a fake recovery root
// (scripts/testdata/fake-recovery-curl.sh): waits for the expected phase/ordinal, accepts a
// receipt only when its sha256 equals the status declaration, quarantines a cached/stale
// download (the Cloudflare incident), and stops hard on timeout. Never touches the network.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, copyFileSync, existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import test from "node:test";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const script = resolve(repository, "scripts/pir2-sealed-recovery-receipt.sh");
const sha256 = (b) => createHash("sha256").update(b).digest("hex");
const BOOT = "3365ac41e7244c41872a6a164a12f443";

function harness() {
  const dir = mkdtempSync(join(tmpdir(), "recovery-"));
  const bin = join(dir, "bin"); mkdirSync(bin);
  copyFileSync(resolve(repository, "scripts/testdata/fake-recovery-curl.sh"), join(bin, "curl")); chmodSync(join(bin, "curl"), 0o755);
  const state = join(dir, "state"); mkdirSync(state);
  const out = join(dir, "out"); mkdirSync(out);
  writeFileSync(join(state, "log"), "");
  return { dir, bin, state, out };
}

function statusJson(phase, ordinal, receipt) {
  return JSON.stringify({ schema_version: 1, phase, ordinal, boot_id: BOOT, receipt_sha256: sha256(receipt) }) + "\n";
}

function run(h, args) {
  return spawnSync("bash", [script, ...args, "--out-dir", h.out, "--poll", "0", "--base-url", "https://fake.invalid"], {
    env: { ...process.env, PATH: `${h.bin}:${process.env.PATH}`, FAKE_RECOVERY_STATE: h.state },
    encoding: "utf8", timeout: 60_000,
  });
}

test("waits for the phase/ordinal, then accepts a receipt whose sha256 matches the status", () => {
  const h = harness();
  const receipt = Buffer.from("BPIRPRO1-observe-56-receipt-bytes");
  writeFileSync(join(h.state, "status.json"), statusJson("probe", 55, Buffer.from("old")));
  writeFileSync(join(h.state, "receipt.bin"), "old");
  writeFileSync(join(h.state, "status.ready.json"), statusJson("observe", 56, receipt));
  writeFileSync(join(h.state, "receipt.ready.bin"), receipt);
  writeFileSync(join(h.state, "script"), "noop\nreceipt-ready\nstatus-ready\n");
  const r = run(h, ["--phase", "observe", "--ordinal", "56", "--wait", "30"]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /^waiting elapsed=\d+ phase=probe ordinal=55$/m);
  assert.match(r.stdout, new RegExp(`^PASS pir2_sealed_recovery_receipt phase=observe ordinal=56 boot_id_hex=${BOOT} receipt_sha256=${sha256(receipt)}$`, "m"));
  assert.match(r.stdout, /^NEXT_STEP=run scripts\/pir2-sealed-ceremony\.sh release/m);
  assert.equal(readFileSync(join(h.out, "observe-ordinal56.receipt.bin")).toString(), receipt.toString());
  assert.ok(existsSync(join(h.out, "observe-ordinal56.status.json")));
  assert.match(readFileSync(join(h.out, "observe-ordinal56.receipt.headers.txt"), "utf8"), /cf-cache-status: MISS/);
  const urls = readFileSync(join(h.state, "log"), "utf8");
  assert.ok(/status\.json\?ts=\d+/.test(urls), "status requests are cache-busted");
  assert.ok(/pir2-sealed-receipt\.bin\?ts=\d+/.test(urls), "receipt requests are cache-busted");
});

test("a download whose sha256 differs from the status is quarantined and never accepted", () => {
  const h = harness();
  const fresh = Buffer.from("fresh-enroll-57");
  writeFileSync(join(h.state, "status.json"), statusJson("enroll", 57, fresh));
  writeFileSync(join(h.state, "receipt.bin"), "stale-observe-receipt-from-the-cdn-cache");
  writeFileSync(join(h.state, "script"), "");
  const r = run(h, ["--phase", "enroll", "--ordinal", "57", "--wait", "30", "--label", "r7-enroll-ordinal57"]);
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stdout, /RECEIPT_HASH_MATCH=false/);
  assert.match(r.stdout, /FETCH_FAILED after 3 attempts/);
  const files = readdirSync(h.out);
  assert.equal(files.filter((f) => /REJECTED-\d+-[123]\.bin$/.test(f)).length, 3, files.join(","));
  assert.ok(!files.includes("r7-enroll-ordinal57.receipt.bin"), "no accepted receipt file");
  assert.ok(!files.includes("r7-enroll-ordinal57.status.json"), "no status file left behind");
});

test("times out with HARD_STOP when the phase never appears; refuses overwrites, Ready, and bad args", () => {
  const h = harness();
  writeFileSync(join(h.state, "status.json"), statusJson("observe", 56, Buffer.from("x")));
  writeFileSync(join(h.state, "receipt.bin"), "x");
  writeFileSync(join(h.state, "script"), "");
  const r = run(h, ["--phase", "probe", "--ordinal", "58", "--wait", "1"]);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /HARD_STOP no probe\/58 status within 1s/);
  writeFileSync(join(h.out, "probe-ordinal58.receipt.bin"), "already");
  const clash = run(h, ["--phase", "probe", "--ordinal", "58", "--wait", "1"]);
  assert.equal(clash.status, 1);
  assert.match(clash.stderr, /refusing to overwrite/);
  const ready = run(h, ["--phase", "ready", "--ordinal", "60"]);
  assert.equal(ready.status, 2);
  assert.match(ready.stderr, /Ready receipts come over the WebSocket/);
  assert.equal(run(h, ["--phase", "observe", "--ordinal", "0"]).status, 2);
  const requestsBefore = readFileSync(join(h.state, "log"), "utf8");
  const dry = run(h, ["--phase", "observe", "--ordinal", "56", "--dry-run"]);
  assert.equal(dry.status, 0, dry.stdout + dry.stderr);
  assert.match(dry.stdout, /^PASS pir2_sealed_recovery_receipt dry_run=true$/m);
  assert.equal(readFileSync(join(h.state, "log"), "utf8"), requestsBefore, "dry run makes no request");
});
