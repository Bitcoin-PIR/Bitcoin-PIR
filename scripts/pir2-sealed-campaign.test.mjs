// Offline checks of scripts/pir2-sealed-campaign.sh: env/evidence validation (`plan`) and the
// --dry-run PLAN of every window, with curl/ssh/scp shimmed to fail so a dry run provably
// touches nothing (docs/history/PIR2_DEPLOYMENT_PAIN_POINTS_2026-09.md #9).
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import test from "node:test";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const script = resolve(repository, "scripts/pir2-sealed-campaign.sh");
const operatorPubkey = (() => {
  const src = readFileSync(resolve(repository, "web/src/production-providers.ts"), "utf8");
  const m = /PIR2_PROVIDER: ProductionProviderPin[\s\S]*?operatorPubkey: hexToBytes\(\s*'([0-9a-f]{64})'/.exec(src)
    ?? /PIR2_PROVIDER: ProductionProviderPin[\s\S]*?operatorPubkey: hexToBytes\([^']*'([0-9a-f]{64})'/.exec(src);
  assert.ok(m, "operator pubkey pin found in production-providers.ts");
  return m[1];
})();

function startup(phase, ordinal) {
  return `schema=bitcoinpir-pir2-sealed-startup-v3\nprofile=pir2-snp-sealed-v1\nphase=${phase}\nordinal=${ordinal}\nverifier_nonce_hex=${"ab".repeat(32)}\n`;
}

function fixture(overrides = {}) {
  const dir = mkdtempSync(join(tmpdir(), "campaign-"));
  const evidence = join(dir, "evidence"); mkdirSync(evidence, { mode: 0o700 });
  for (const [phase, ord] of [["observe", 56], ["enroll", 57], ["probe", 58], ["probe", 59], ["ready", 60]]) {
    writeFileSync(join(evidence, `${phase}-ordinal${ord}.startup.env`), startup(phase, ord));
  }
  const keys = join(dir, "keys"); mkdirSync(keys);
  for (const f of ["ark.pem", "ask.pem", "vcek.pem"]) writeFileSync(join(keys, f), "pem\n");
  writeFileSync(join(dir, "operator.key"), "k".repeat(32));
  writeFileSync(join(dir, "ovmf.fd"), "ovmf\n");
  const admin = join(dir, "bpir-admin"); writeFileSync(admin, "#!/bin/sh\nexit 0\n"); chmodSync(admin, 0o755);
  const ukiDir = join(dir, "uki"); mkdirSync(ukiDir);
  writeFileSync(join(ukiDir, "tier3-test.efi"), "uki\n");
  writeFileSync(join(ukiDir, "tier3-test.efi.meta"), `binary_sha256=${"11".repeat(32)}\n`);
  writeFileSync(join(ukiDir, "tier3-test.efi.sha256"), `${"22".repeat(32)}  tier3-test.efi\n`);
  // Shims: any network or remote tool reached during a dry run fails the test.
  const bin = join(dir, "bin"); mkdirSync(bin);
  for (const tool of ["curl", "ssh", "scp"]) { writeFileSync(join(bin, tool), "#!/bin/sh\necho 'NETWORK TOOL INVOKED' >&2\nexit 99\n"); chmodSync(join(bin, tool), 0o755); }
  const env = {
    REV: "6a407bdb923d9d1242cb706148e99afae8610c3b", TAG: "r7-test", GEN: "7", ROLLBACK_IMAGE: "305",
    SERVER_ID: "25285", EVIDENCE_DIR: evidence, BPIR_ADMIN: admin,
    ORD_OBSERVE: "56", ORD_ENROLL: "57", ORD_PROBE1: "58", ORD_PROBE2: "59", ORD_READY: "60",
    INPUTS_FROM: "/home/pir/data/production-builds/r6-prev", ORAMCTL_SHA256: "e6".repeat(32), BHTM_SHA256: "2e".repeat(32),
    UKI_LOCAL_DIR: ukiDir, ROLLBACK_LABEL: "image305-test", AMD_CERT_DIR: keys, OPERATOR_KEY: join(dir, "operator.key"), OVMF: join(dir, "ovmf.fd"),
    OPERATOR_PUBKEY_HEX: operatorPubkey, ARK_SHA256: "1f".repeat(32), PROVIDER_ID_HEX: "a6".repeat(32), SSH_PACE_SECONDS: "0",
    ...overrides,
  };
  const envFile = join(dir, "campaign.env");
  writeFileSync(envFile, Object.entries(env).filter(([, v]) => v !== undefined).map(([k, v]) => `${k}=${v}`).join("\n") + "\n");
  return { dir, evidence, envFile, bin, ukiDir };
}

function run(f, args) {
  return spawnSync("bash", [script, ...args, "--env", f.envFile], {
    env: { ...process.env, PATH: `${f.bin}:${process.env.PATH}` }, encoding: "utf8", timeout: 60_000,
  });
}
// printf %q escapes the dry-run placeholders (<image> → \<image\>); strip the backslashes before matching.
const plans = (r) => r.stdout.split("\n").filter((l) => l.startsWith("PLAN:")).map((l) => l.replace(/\\/g, ""));

test("plan validates the env file and the evidence directory", () => {
  const f = fixture();
  const ok = run(f, ["plan"]);
  assert.equal(ok.status, 0, ok.stdout + ok.stderr);
  assert.match(ok.stdout, /^PASS pir2_sealed_campaign action=plan$/m);
  assert.match(ok.stdout, /ordinals: observe=56 enroll=57 probe=58,59 ready=60/);

  const wrongPhase = fixture(); writeFileSync(join(wrongPhase.evidence, "ready-ordinal60.startup.env"), startup("probe", 60));
  const r1 = run(wrongPhase, ["plan"]); assert.equal(r1.status, 1); assert.match(r1.stderr, /is not phase=ready/);
  const badOrder = fixture({ ORD_READY: "58" });
  const r2 = run(badOrder, ["plan"]); assert.equal(r2.status, 2); assert.match(r2.stderr, /ordinals must increase/);
  const badKey = fixture(); writeFileSync(badKey.envFile, readFileSync(badKey.envFile, "utf8") + "EVIL=$(rm -rf /)\n");
  const r3 = run(badKey, ["plan"]); assert.equal(r3.status, 2); assert.match(r3.stderr, /unknown key 'EVIL'/);
  const badValue = fixture({ TAG: "r7 test" });
  const r4 = run(badValue, ["plan"]); assert.equal(r4.status, 2); assert.match(r4.stderr, /unsupported characters/);
  const wrongPin = fixture({ OPERATOR_PUBKEY_HEX: "ff".repeat(32) });
  const r5 = run(wrongPin, ["plan"]); assert.equal(r5.status, 1); assert.match(r5.stderr, /differs from the pin in web\/src\/production-providers\.ts/);
  const noAdmin = fixture({ BPIR_ADMIN: "/nonexistent/bpir-admin" });
  const r6 = run(noAdmin, ["plan"]); assert.equal(r6.status, 2); assert.match(r6.stderr, /BPIR_ADMIN is not an executable file/);
});

test("build --dry-run plans the whole first window in order without touching the network", () => {
  const f = fixture();
  const r = run(f, ["build", "--dry-run"]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.doesNotMatch(r.stderr, /NETWORK TOOL INVOKED/);
  const p = plans(r).join("\n");
  const order = [
    /git -C .* update-ref refs\/heads\/bpir-campaign-r7-test 6a407bdb/,
    /git -C .* bundle create .*source-r7-test\.bundle refs\/heads\/bpir-campaign-r7-test/,
    /git -C .* update-ref -d refs\/heads\/bpir-campaign-r7-test/,
    /vpsbg-data-disk\.sh open --server-id 25285 --image-id 305 --apply/,
    /pir2-sealed-rollback-set\.sh preserve --label image305-test/,
    /prep-inputs\.sh/, /build-runtime\.sh/, /build-uki\.sh/,
    /vpsbg-data-disk\.sh put --local .*observe-ordinal56\.startup\.env --remote \/home\/pir\/data\/pir2-sealed\/startup\.env/,
    /vpsbg-measured-boot\.sh upload --uki /,
    /vpsbg-data-disk\.sh close --server-id 25285 --image-id <image> --apply/,
    /pir2-sealed-recovery-receipt\.sh --phase observe --ordinal 56/,
    /pir2-sealed-ceremony\.sh release .*--identity-generation 7/,
  ];
  let at = 0;
  for (const re of order) { const i = p.slice(at).search(re); assert.ok(i >= 0, `plan lacks ${re} after position ${at}`); at += i; }
  assert.match(r.stdout, /^PASS pir2_sealed_campaign action=build image=<image> dry_run=true$/m);
  assert.doesNotMatch(readFileSync(f.envFile, "utf8"), /^IMAGE=/m, "dry run does not record an image id");
});

test("enroll, probe, and ready dry runs require IMAGE and plan their windows", () => {
  const noImage = fixture();
  const r0 = run(noImage, ["enroll", "--dry-run"]); assert.equal(r0.status, 2); assert.match(r0.stderr, /IMAGE is required for enroll/);

  const f = fixture({ IMAGE: "307" });
  const enroll = run(f, ["enroll", "--dry-run"]);
  assert.equal(enroll.status, 0, enroll.stdout + enroll.stderr);
  const pe = plans(enroll).join("\n");
  assert.match(pe, /open --server-id 25285 --image-id 307 --apply/);
  assert.match(pe, /pir2-sealed-rollback-set\.sh detach-envelope --label image305-test --apply/);
  assert.match(pe, /put --local .*release-generation7\.bin --remote \/home\/pir\/data\/pir2-sealed\/release\.bin/);
  assert.match(pe, /pir2-sealed-recovery-receipt\.sh --phase enroll --ordinal 57/);
  assert.match(pe, /pir2-sealed-ceremony\.sh receipt .*--expected-phase enroll --expected-ordinal 57/);
  assert.match(pe, /sign-identity --operator-key-path .* --server-id pir2-vpsbg-dpf-v1 .*--valid-from 0 --valid-until 0/);

  const probe = run(f, ["probe", "--ordinal", "58", "--with-cert", "--dry-run"]);
  assert.equal(probe.status, 0, probe.stdout + probe.stderr);
  const pp = plans(probe).join("\n");
  assert.match(pp, /identity-generation7-image307-runtime-v1\.cert --remote \/home\/pir\/data\/pir2-sealed\/identity\.cert/);
  assert.match(pp, /--expected-phase probe --expected-ordinal 58/);
  const probe2 = run(f, ["probe", "--ordinal", "59", "--dry-run"]);
  assert.equal(probe2.status, 0, probe2.stdout + probe2.stderr);
  assert.doesNotMatch(plans(probe2).join("\n"), /identity\.cert --apply/);
  assert.equal(run(f, ["probe", "--dry-run"]).status, 2, "probe needs --ordinal");

  const ready = run(f, ["ready", "--dry-run"]);
  assert.equal(ready.status, 0, ready.stdout + ready.stderr);
  const pr = plans(ready).join("\n");
  assert.match(pr, /put --local .*ready-ordinal60\.startup\.env/);
  assert.match(pr, /attest wss:\/\/weikeng2\.bitcoinpir\.org --expect-measurement <measurement> --expect-binary <binary_sha256> --expect-ark-fingerprint 1f1f/);
  assert.match(pr, /pir2-post-switch-check\.sh --server-id 25285 --pin-file .*attest-pin\.candidate-image307\.ts/);
  assert.match(pr, /channel-test wss:\/\/weikeng2\.bitcoinpir\.org/);
  assert.match(pr, /pir2-sealed-ceremony\.sh fetch wss:\/\/weikeng2\.bitcoinpir\.org --out-dir .*ready-ordinal60/);
  assert.match(pr, /generate-release-record\.sh --uki .*tier3-test\.efi --image-id 307 .*--attest-log .*ready-ordinal60-live-attest\.log/);
  assert.match(ready.stdout, /^PASS pir2_sealed_campaign action=ready image=307 dry_run=true$/m);
  for (const r of [enroll, probe, probe2, ready]) assert.doesNotMatch(r.stderr, /NETWORK TOOL INVOKED/);
});
