#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";

import { runPinnedAdminProbe } from "./payment-v1-integrated-caddy-overlay-transaction.mjs";

function inodePin(path) {
  const stat = statSync(path, { bigint: true });
  const bytes = readFileSync(path);
  return {
    ctime_ns: stat.ctimeNs.toString(),
    device: stat.dev.toString(),
    gid: Number(stat.gid),
    inode: stat.ino.toString(),
    mode: (Number(stat.mode & 0o7777n)).toString(8).padStart(4, "0"),
    mtime_ns: stat.mtimeNs.toString(),
    nlink: Number(stat.nlink),
    path,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    size: stat.size.toString(),
    uid: Number(stat.uid),
  };
}

const nodePin = inodePin(process.execPath);
const gatePin = inodePin("/work/scripts/payment-v1-caddy-admin-uds-gate.mjs");
const probePin = inodePin("/work/scripts/payment-v1-caddy-admin-uds-probe.mjs");
const setprivPin = inodePin("/usr/bin/setpriv");
const mode = process.env.BPIR_REAL_ADAPTER_MODE ?? "good";

if (mode === "good") {
  const root = runPinnedAdminProbe({
    expected: "root-readback",
    gatePin,
    gid: 0,
    label: "root-real-adapter",
    nodePin,
    probePin,
    setprivPin,
    uid: 0,
  });
  assert.equal(root.cap_eff, "0000000000000000");
  assert.deepEqual(root.groups, [0]);
  assert.equal(root.listen, "unix//run/bitcoinpir-caddy-admin/admin.sock|0200");
  const denied = runPinnedAdminProbe({
    expected: "EACCES",
    gatePin,
    gid: 62902,
    label: "pir-real-adapter",
    nodePin,
    probePin,
    setprivPin,
    uid: 62902,
  });
  assert.equal(denied.cap_eff, "0000000000000000");
  assert.deepEqual(denied.groups, [62902]);
  assert.equal(denied.error, "EACCES");
  process.stdout.write("caddy-admin-uds-real-adapter=PASS mode=good setpriv=descriptor-pinned caps=zero groups=cleared\n");
} else if (mode === "permission-drift") {
  assert.throws(
    () => runPinnedAdminProbe({
      expected: "EACCES",
      gatePin,
      gid: 62902,
      label: "pir-real-adapter-drift",
      nodePin,
      probePin,
      setprivPin,
      uid: 62902,
    }),
    /unexpectedly reached the admin API/u,
  );
  process.stdout.write("caddy-admin-uds-real-adapter=PASS mode=permission-drift fail-closed=true\n");
} else {
  throw new Error(`unsupported BPIR_REAL_ADAPTER_MODE ${mode}`);
}
