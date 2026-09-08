// Offline simulation of `scripts/vpsbg-data-disk.sh open --apply` against a
// fake VPSBG control plane and a fake sshd, covering the detach/stop race the
// real platform shows (docs/history/PIR2_DEPLOYMENT_PAIN_POINTS_2026-09.md #1).
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import test from "node:test";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const wrapper = resolve(repository, "scripts/vpsbg-data-disk.sh");

// The fake control plane (scripts/testdata/fake-vpsbg-curl.sh) keeps its state in files under STATE:
//   mode       measured | stock
//   running    true | false
//   ssh        0 | 1 (sshd answers)
//   script     newline-separated events applied on successive GET /servers/ID
//              reads: "stop-lands" (running=false), "ssh-up" (ssh=1),
//              "noop" (nothing). Consumed from the top.
//   stop_http  status code the next POST /stop answers (423 or 200)
//   log        appended request lines for assertions

function harness(initial) {
  const dir = mkdtempSync(join(tmpdir(), "vpsbg-open-"));
  const bin = join(dir, "bin"); mkdirSync(bin);
  const state = join(dir, "state"); mkdirSync(state);
  copyFileSync(resolve(repository, "scripts/testdata/fake-vpsbg-curl.sh"), join(bin, "curl")); chmodSync(join(bin, "curl"), 0o755);
  copyFileSync(resolve(repository, "scripts/testdata/fake-vpsbg-ssh.sh"), join(bin, "ssh")); chmodSync(join(bin, "ssh"), 0o755);
  for (const [k, v] of Object.entries({ start_works: "1", detached: "0", ...initial })) writeFileSync(join(state, k), `${v}\n`);
  writeFileSync(join(state, "log"), "");
  const token = join(dir, "token"); writeFileSync(token, "fake-token\n");
  const key = join(dir, "key"); writeFileSync(key, "fake-key\n");
  const hosts = join(dir, "known_hosts"); writeFileSync(hosts, "fake-hosts\n");
  const control = join(dir, "cm"); mkdirSync(control, { mode: 0o700 });
  const run = (action) => {
    const result = spawnSync("bash", [wrapper, action, "--server-id", "25285", "--image-id", "303", "--apply",
      "--token-file", token, "--ssh-key", key, "--known-hosts", hosts], {
      env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, FAKE_VPSBG_STATE: state,
        VPSBG_API_TOKEN_FILE: token, VPSBG_SSH_CONTROL_DIR: control, VPSBG_DATA_DISK_POLL_SECONDS: "0",
        VPSBG_DATA_DISK_HARD_STOP_SECONDS: "20", VPSBG_DATA_DISK_START_COOLDOWN_SECONDS: "0", VPSBG_DATA_DISK_STALL_SECONDS: "2" },
      encoding: "utf8", timeout: 60_000,
    });
    return { ...result, log: readFileSync(join(state, "log"), "utf8"), control };
  };
  return { run };
}
const runOpen = (initial) => harness(initial).run("open");

test("open survives the detach/stop race: 423 on stop, delayed stop lands, one start, then SSH", () => {
  // Detach flips the guest to stock+running immediately; the stop answers 423;
  // two reads later the delayed stop lands (guest off); the wrapper must start
  // it exactly once and then see sshd.
  const r = runOpen({ mode: "measured", running: "true", ssh: "0", stop_http: "423", script: "noop\nstop-lands\nnoop" });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /PASS action=open/);
  assert.equal((r.log.match(/\/servers\/25285\/start POST/g) || []).length, 1, r.log);
  assert.equal((r.log.match(/\/servers\/25285\/measured-boot POST/g) || []).length, 1, r.log);
  // One connection per window: every ssh carries the ControlMaster options, and a stale
  // master is torn down before the detach so it can never mask a dead guest.
  const sshLines = r.log.split("\n").filter((l) => l.startsWith("ssh "));
  assert.ok(sshLines.length >= 2, r.log);
  for (const l of sshLines) {
    assert.match(l, /-o ControlMaster=auto/);
    assert.match(l, new RegExp(`-o ControlPath=${r.control.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/%C`));
    assert.match(l, /-o ControlPersist=600/);
  }
  assert.match(sshLines[0], /-O exit root@/);
  assert.ok(r.log.indexOf("-O exit") < r.log.indexOf("/servers/25285/measured-boot POST"), "teardown precedes the detach");
});

test("close tears the control master down, then switches the recorded image", () => {
  const h = harness({ mode: "stock", running: "true", ssh: "1", stop_http: "200", script: "" });
  const r = h.run("close");
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /^\[stage\] close SSH control master$/m);
  assert.match(r.stdout, /^PASS action=switch server_id=25285 image_id=303$/m);
  assert.match(r.stdout, /^PASS action=close$/m);
  const sshLines = r.log.split("\n").filter((l) => l.startsWith("ssh "));
  assert.equal(sshLines.length, 1, r.log);
  assert.match(sshLines[0], /-o ControlMaster=auto .*-O exit root@/);
  assert.ok(r.log.indexOf("-O exit") < r.log.indexOf("/servers/25285/measured-boot POST"), "teardown precedes the switch");
});

test("open stops a guest that stays on the old kernel: stall → stop (423 retried) → off → start → SSH", () => {
  // No platform-side reboot here: status reads stock (config) with the guest
  // still running the measured kernel and no sshd. After the stall limit the
  // wrapper asks for a stop; the first answer is 423, the retry lands, the
  // guest is off, one start brings sshd up.
  const r = runOpen({ mode: "measured", running: "true", ssh: "0", stop_http: "423", script: "" });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /stop deferred \(HTTP 423/);
  assert.match(r.stdout, /PASS action=open/);
  assert.ok((r.log.match(/\/servers\/25285\/stop POST/g) || []).length >= 2, r.log);
  assert.equal((r.log.match(/\/servers\/25285\/start POST/g) || []).length, 1, r.log);
});

test("open hard-stops when the guest never reaches SSH and the platform keeps refusing the stop", () => {
  // stock+running without sshd, and every stop answers 423: nothing the
  // wrapper can do — it must give up at the hard stop, never start a running guest.
  const r = runOpen({ mode: "stock", running: "true", ssh: "0", stop_http: "423-always", script: "" });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /hard stop: guest did not reach boot_mode=stock with SSH/);
  assert.equal((r.log.match(/start POST/g) || []).length, 0, "a running guest is never restarted");
  assert.match(r.stdout, /stop deferred \(HTTP 423/);
});

test("open refuses to start a stock-but-off guest more than three times", () => {
  // Every start is undone by the platform (start_works=0): the wrapper must
  // give up after MAX_SETTLE_STARTS instead of looping until the hard stop.
  const r = runOpen({ mode: "stock", running: "false", ssh: "0", stop_http: "200", script: "", start_works: "0" });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /refusing to loop/);
  assert.equal((r.log.match(/\/servers\/25285\/start POST/g) || []).length, 3, r.log);
});
