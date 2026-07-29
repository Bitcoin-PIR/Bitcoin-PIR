import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

import {
  OVERLAY_STATE_FILES,
  OverlayTransactionError,
  executeOverlayTransaction,
  recoverOverlayTransaction,
  verifyWebSocketUpgrade,
} from "./payment-v1-integrated-caddy-overlay-transaction.mjs";
import {
  canonicalJson,
  computeApprovedOverlayPlanSha256,
} from "./payment-v1-integrated-caddy-overlay-gate.mjs";
import {
  TEST_PREIMAGE,
  TEST_REPOSITORY,
  makeIntegratedOverlayTestPlan,
  renderedManagedBlock,
  testSha256,
} from "./payment-v1-integrated-caddy-overlay-test-fixture.mjs";

test("WebSocket health proof verifies every RFC 6455 upgrade binding", () => {
  const key = "dGhlIHNhbXBsZSBub25jZQ==";
  const valid = Buffer.from([
    "HTTP/1.1 101 Switching Protocols",
    "Upgrade: websocket",
    "Connection: keep-alive, Upgrade",
    "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
  ].join("\r\n"));
  assert.equal(
    verifyWebSocketUpgrade({ expectedStatus: 101, headerBytes: valid, key }),
    101,
  );
  for (const [label, changed] of [
    ["wrong accept", valid.toString("ascii").replace("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", "invalid")],
    ["missing upgrade token", valid.toString("ascii").replace("keep-alive, Upgrade", "keep-alive")],
    ["wrong Upgrade", valid.toString("ascii").replace("Upgrade: websocket", "Upgrade: h2c")],
    ["wrong status", valid.toString("ascii").replace("101 Switching Protocols", "200 OK")],
  ]) {
    assert.throws(
      () => verifyWebSocketUpgrade({ expectedStatus: 101, headerBytes: Buffer.from(changed), key }),
      /WebSocket upgrade proof failed/,
      label,
    );
  }
});

test("real health and command adapters are fail-closed in source", () => {
  const source = readFileSync(
    join(TEST_REPOSITORY, "scripts/payment-v1-integrated-caddy-overlay-transaction.mjs"),
    "utf8",
  );
  assert.match(source, /rejectUnauthorized: true/u);
  assert.doesNotMatch(source, /rejectUnauthorized: false/u);
  assert.match(source, /killSignal: "SIGKILL"/u);
  assert.match(source, /sec-websocket-accept/iu);
});

function clone(value) {
  if (Buffer.isBuffer(value)) return Buffer.from(value);
  if (Array.isArray(value)) return value.map(clone);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, clone(entry)]));
  }
  return value;
}

function fileClone(file) {
  return { bytes: Buffer.from(file.bytes), snapshot: clone(file.snapshot) };
}

class MockOverlayOps {
  constructor(plan) {
    this.plan = plan;
    this.files = new Map();
    this.state = new Map();
    this.stateInitialized = false;
    this.inode = 80000;
    this.clock = 1700000001000000000n;
    this.exchangeHistory = [];
    this.reloadCalls = 0;
    this.releaseCalls = 0;
    this.failHealthLane = null;
    this.failRelease = false;
    this.raceTargetBeforeFirstExchange = false;
    this.raceTargetBeforeExchangeNumber = null;
    this.racedTargetSnapshot = null;
    this.#seedPins();
  }

  #putPin(pin, bytes = Buffer.from(`fixture:${pin.path}\n`)) {
    this.files.set(pin.path, { bytes: Buffer.from(bytes), snapshot: clone(pin) });
  }

  #seedPins() {
    const plan = this.plan;
    const manifest = Buffer.from(
      `${plan.runtime.exchange_helper.sha256}  ${plan.runtime.exchange_helper.path}\n`,
    );
    for (const pin of [
      plan.runtime.node_binary,
      plan.runtime.gate,
      plan.runtime.executor,
      plan.runtime.exchange_helper,
      plan.target.binary,
      plan.target.unit_fragment,
      plan.source_fair.haproxy_binary,
      plan.source_fair.haproxy_config,
      plan.source_fair.unit_fragment,
      ...plan.tls_dependencies.map((entry) => entry.pin),
    ]) this.#putPin(pin);
    this.#putPin(plan.runtime.exchange_manifest, manifest);
    this.#putPin(plan.runtime.managed_block, renderedManagedBlock(plan));
    this.#putPin(plan.target.config_preimage, TEST_PREIMAGE);
  }

  #snapshot(path, bytes, mode) {
    this.inode += 1;
    this.clock += 1n;
    return {
      ctime_ns: this.clock.toString(),
      device: "2049",
      gid: 0,
      inode: String(this.inode),
      mode,
      mtime_ns: this.clock.toString(),
      nlink: 1,
      path,
      sha256: testSha256(bytes),
      size: String(bytes.length),
      uid: 0,
    };
  }

  #store(path, bytes, mode) {
    if (this.files.has(path)) {
      const error = new Error(`exists: ${path}`);
      error.code = "EEXIST";
      throw error;
    }
    const file = { bytes: Buffer.from(bytes), snapshot: this.#snapshot(path, bytes, mode) };
    this.files.set(path, file);
    return file;
  }

  async acquireLock() {
    return async () => {
      this.releaseCalls += 1;
      if (this.failRelease) throw new Error("mock lock release failed");
    };
  }

  async exchange(left, right) {
    if (
      (this.raceTargetBeforeFirstExchange && this.exchangeHistory.length === 0) ||
      this.raceTargetBeforeExchangeNumber === this.exchangeHistory.length + 1
    ) {
      const bytes = Buffer.from("external-racing-caddyfile\n");
      const raced = { bytes, snapshot: this.#snapshot(right, bytes, "0644") };
      this.files.set(right, raced);
      this.racedTargetSnapshot = clone(raced.snapshot);
    }
    const leftFile = this.files.get(left);
    const rightFile = this.files.get(right);
    if (!leftFile || !rightFile) throw new Error("exchange entry missing");
    const before = { left: fileClone(leftFile), right: fileClone(rightFile) };
    const newLeft = fileClone(rightFile);
    const newRight = fileClone(leftFile);
    this.clock += 1n;
    newLeft.snapshot.path = left;
    newLeft.snapshot.ctime_ns = this.clock.toString();
    newRight.snapshot.path = right;
    newRight.snapshot.ctime_ns = this.clock.toString();
    this.files.set(left, newLeft);
    this.files.set(right, newRight);
    this.exchangeHistory.push({
      after: { left: fileClone(newLeft), right: fileClone(newRight) },
      before,
    });
  }

  async health(check) {
    if (check.lane === this.failHealthLane) throw new Error(`mock health failed: ${check.lane}`);
    return {
      body_sha256: check.expected_body_sha256,
      leaf_certificate_sha256: check.leaf_certificate_sha256,
      status: check.expected_status,
      success: true,
    };
  }

  async hostIdentity() {
    return {
      boot_id: "22345678-1234-4234-9234-123456789abc",
      machine_id_sha256: "9".repeat(64),
    };
  }

  async initializeStateDirectory() {
    if (this.stateInitialized) {
      const error = new Error("state exists");
      error.code = "EEXIST";
      throw error;
    }
    this.stateInitialized = true;
  }

  async readDirectory(path) {
    if (path === this.plan.target.config_parent.path) return clone(this.plan.target.config_parent);
    const dependency = this.plan.tls_dependencies.find((entry) => entry.parent.path === path);
    if (dependency) return clone(dependency.parent);
    throw new Error(`unknown directory ${path}`);
  }

  async readOptionalRegular(path) {
    const file = this.files.get(path);
    return file === undefined ? null : fileClone(file);
  }

  async readRegular(path) {
    const file = this.files.get(path);
    if (file === undefined) {
      const error = new Error(`missing: ${path}`);
      error.code = "ENOENT";
      throw error;
    }
    return fileClone(file);
  }

  async readRuntimePath(path) {
    const value = this.plan.source_fair.runtime_paths.find((entry) => entry.path === path);
    if (!value) throw new Error(`unknown runtime path ${path}`);
    return clone(value);
  }

  async readStateRecords() {
    return new Map([...this.state].map(([name, bytes]) => [name, Buffer.from(bytes)]));
  }

  async readUnitGeneration(unitName) {
    return clone(
      unitName === "bhtm-caddy.service"
        ? this.plan.target.unit_generation
        : this.plan.source_fair.unit_generation,
    );
  }

  async removeIfExact(path, expected) {
    const file = this.files.get(path);
    if (!file) return;
    for (const key of ["device", "gid", "inode", "mode", "mtime_ns", "nlink", "sha256", "size", "uid"]) {
      assert.equal(file.snapshot[key], expected[key], `cleanup pin ${key}`);
    }
    this.files.delete(path);
  }

  async run(argv) {
    if (argv[1] === "adapt") {
      return { status: 0, stderr: Buffer.alloc(0), stdout: Buffer.from('{"apps":{}}\n') };
    }
    if (argv[1] === "validate") {
      return { status: 0, stderr: Buffer.alloc(0), stdout: Buffer.alloc(0) };
    }
    if (argv[1] === "reload") {
      this.reloadCalls += 1;
      return { status: 0, stderr: Buffer.alloc(0), stdout: Buffer.alloc(0) };
    }
    throw new Error(`unexpected command ${argv.join(" ")}`);
  }

  async writeExclusive(path, bytes, mode) {
    const file = this.#store(path, bytes, mode);
    return {
      directoryFsync: true,
      exclusiveCreate: true,
      fileFsync: true,
      snapshot: clone(file.snapshot),
    };
  }

  async publishPendingReceipt(pendingPath, finalPath) {
    if (this.files.has(finalPath)) {
      const error = new Error(`exists: ${finalPath}`);
      error.code = "EEXIST";
      throw error;
    }
    const pending = this.files.get(pendingPath);
    if (pending === undefined) throw new Error(`missing: ${pendingPath}`);
    const published = fileClone(pending);
    published.snapshot.path = finalPath;
    this.files.delete(pendingPath);
    this.files.set(finalPath, published);
  }

  async writeReceipt(pendingPath, finalPath, bytes) {
    const pending = this.#store(pendingPath, bytes, "0400");
    await this.publishPendingReceipt(pendingPath, finalPath);
    const published = this.files.get(finalPath);
    return {
      directoryFsync: true,
      exclusiveCreate: true,
      fileFsync: true,
      snapshot: clone(published.snapshot),
      pendingSnapshot: clone(pending.snapshot),
    };
  }

  async writeState(_directory, filename, bytes) {
    if (this.state.has(filename)) {
      const error = new Error(`state exists: ${filename}`);
      error.code = "EEXIST";
      throw error;
    }
    this.state.set(filename, Buffer.from(bytes));
  }
}

async function successfulBaseline() {
  const plan = makeIntegratedOverlayTestPlan();
  const ops = new MockOverlayOps(plan);
  const approvedPlanSha256 = computeApprovedOverlayPlanSha256(plan);
  const receipt = await executeOverlayTransaction({ approvedPlanSha256, ops, plan });
  return { approvedPlanSha256, ops, plan, receipt };
}

function recoveryOpsFromBaseline(baseline, { pair, phases, receipt = null }) {
  const ops = new MockOverlayOps(baseline.plan);
  ops.stateInitialized = true;
  ops.state = new Map(
    phases.map((name) => [name, Buffer.from(baseline.ops.state.get(name))]),
  );
  const history = baseline.ops.exchangeHistory[0];
  const selected = pair === "installed" ? history.after : history.before;
  ops.files.set(baseline.plan.transaction.candidate_path, fileClone(selected.left));
  ops.files.set("/etc/caddy/Caddyfile", fileClone(selected.right));
  if (receipt !== null) {
    const bytes = Buffer.from(canonicalJson(receipt), "utf8");
    const file = {
      bytes,
      snapshot: {
        ctime_ns: "1700000002000000000",
        device: "2049",
        gid: 0,
        inode: "89999",
        mode: "0400",
        mtime_ns: "1700000002000000000",
        nlink: 1,
        path: baseline.plan.transaction.receipt_path,
        sha256: testSha256(bytes),
        size: String(bytes.length),
        uid: 0,
      },
    };
    ops.files.set(baseline.plan.transaction.receipt_path, file);
  }
  return ops;
}

function seedReceiptEntry(ops, path, bytes) {
  ops.files.set(path, {
    bytes: Buffer.from(bytes),
    snapshot: {
      ctime_ns: "1700000002000000000",
      device: "2049",
      gid: 0,
      inode: "89998",
      mode: "0400",
      mtime_ns: "1700000002000000000",
      nlink: 1,
      path,
      sha256: testSha256(bytes),
      size: String(bytes.length),
      uid: 0,
    },
  });
}

test("transaction commits only after verified exchange, health and durable receipt", async () => {
  const { ops, plan, receipt } = await successfulBaseline();
  assert.equal(receipt.outcome, "committed");
  assert.equal(ops.files.get("/etc/caddy/Caddyfile").snapshot.sha256, plan.managed_block.candidate_sha256);
  assert.equal(ops.files.has(plan.transaction.candidate_path), false);
  assert.equal(ops.state.has(OVERLAY_STATE_FILES.committed), true);
  assert.equal(ops.reloadCalls, 1);
  assert.equal(ops.releaseCalls, 1);
});

test("post-install health failure exchanges back, reloads and writes rolled-back receipt", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  const ops = new MockOverlayOps(plan);
  ops.failHealthLane = "provider";
  const approvedPlanSha256 = computeApprovedOverlayPlanSha256(plan);
  await assert.rejects(
    executeOverlayTransaction({ approvedPlanSha256, ops, plan }),
    (error) => {
      assert(error instanceof OverlayTransactionError);
      assert.equal(error.phase, "rolled-back");
      assert.equal(error.receipt.outcome, "rolled-back");
      return true;
    },
  );
  assert.equal(ops.files.get("/etc/caddy/Caddyfile").snapshot.sha256, plan.target.config_preimage.sha256);
  assert.equal(ops.files.has(plan.transaction.candidate_path), false);
  assert.equal(ops.reloadCalls, 2);
});

test("a final target race is exchanged back without reload or overwrite", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  const ops = new MockOverlayOps(plan);
  ops.raceTargetBeforeFirstExchange = true;
  const approvedPlanSha256 = computeApprovedOverlayPlanSha256(plan);
  await assert.rejects(
    executeOverlayTransaction({ approvedPlanSha256, ops, plan }),
    /exchange verification failed; exact pre-exchange entries were restored without reload/,
  );
  assert.equal(
    ops.files.get("/etc/caddy/Caddyfile").snapshot.sha256,
    ops.racedTargetSnapshot.sha256,
  );
  assert.equal(ops.reloadCalls, 0);
});

test("a rollback target race is exchanged back without a second reload or overwrite", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  const ops = new MockOverlayOps(plan);
  ops.failHealthLane = "provider";
  ops.raceTargetBeforeExchangeNumber = 2;
  const approvedPlanSha256 = computeApprovedOverlayPlanSha256(plan);
  await assert.rejects(
    executeOverlayTransaction({ approvedPlanSha256, ops, plan }),
    /rollback exchange verification failed; exact pre-exchange entries were restored without reload/,
  );
  assert.equal(
    ops.files.get("/etc/caddy/Caddyfile").snapshot.sha256,
    ops.racedTargetSnapshot.sha256,
  );
  assert.equal(ops.reloadCalls, 1);
});

test("release failure does not mask a rolled-back primary receipt", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  const ops = new MockOverlayOps(plan);
  ops.failHealthLane = "provider";
  ops.failRelease = true;
  const approvedPlanSha256 = computeApprovedOverlayPlanSha256(plan);
  await assert.rejects(
    executeOverlayTransaction({ approvedPlanSha256, ops, plan }),
    (error) => {
      assert.equal(error.phase, "rolled-back");
      assert.equal(error.receipt.outcome, "rolled-back");
      assert.match(error.lockReleaseError.message, /release failed/);
      return true;
    },
  );
});

test("release failure after success fails closed with the committed receipt", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  const ops = new MockOverlayOps(plan);
  ops.failRelease = true;
  const approvedPlanSha256 = computeApprovedOverlayPlanSha256(plan);
  await assert.rejects(
    executeOverlayTransaction({ approvedPlanSha256, ops, plan }),
    (error) => {
      assert.equal(error.phase, "lock-release-failed");
      assert.equal(error.receipt.outcome, "committed");
      return true;
    },
  );
});

test("recovery cleans an install-before crash without reloading", async () => {
  const baseline = await successfulBaseline();
  const ops = recoveryOpsFromBaseline(baseline, {
    pair: "rolled-back",
    phases: [OVERLAY_STATE_FILES.prepared],
  });
  const result = await recoverOverlayTransaction({
    approvedPlanSha256: baseline.approvedPlanSha256,
    ops,
    plan: baseline.plan,
  });
  assert.equal(result.outcome, "aborted-before-install");
  assert.equal(ops.files.has(baseline.plan.transaction.candidate_path), false);
  assert.equal(ops.reloadCalls, 0);
});

test("recovery rolls back a crash after exchange but before its phase record", async () => {
  const baseline = await successfulBaseline();
  const ops = recoveryOpsFromBaseline(baseline, {
    pair: "installed",
    phases: [OVERLAY_STATE_FILES.prepared],
  });
  const receipt = await recoverOverlayTransaction({
    approvedPlanSha256: baseline.approvedPlanSha256,
    ops,
    plan: baseline.plan,
  });
  assert.equal(receipt.outcome, "rolled-back");
  assert.equal(ops.reloadCalls, 1);
  assert.equal(ops.files.get("/etc/caddy/Caddyfile").snapshot.sha256, baseline.plan.target.config_preimage.sha256);
});

test("recovery rolls back a reload-before-receipt crash", async () => {
  const baseline = await successfulBaseline();
  const ops = recoveryOpsFromBaseline(baseline, {
    pair: "installed",
    phases: [
      OVERLAY_STATE_FILES.prepared,
      OVERLAY_STATE_FILES.exchanged,
      OVERLAY_STATE_FILES.reloaded,
    ],
  });
  const receipt = await recoverOverlayTransaction({
    approvedPlanSha256: baseline.approvedPlanSha256,
    ops,
    plan: baseline.plan,
  });
  assert.equal(receipt.outcome, "rolled-back");
  assert.equal(ops.reloadCalls, 1);
});

test("recovery completes an interrupted rollback from the exact file pair", async () => {
  const baseline = await successfulBaseline();
  const ops = recoveryOpsFromBaseline(baseline, {
    pair: "rolled-back",
    phases: [
      OVERLAY_STATE_FILES.prepared,
      OVERLAY_STATE_FILES.exchanged,
      OVERLAY_STATE_FILES.reloaded,
    ],
  });
  const previous = "reloaded";
  ops.state.set(
    OVERLAY_STATE_FILES.rollbackExchanged,
    Buffer.from(canonicalJson({
      approved_plan_sha256: baseline.approvedPlanSha256,
      phase: "rollback-exchanged",
      previous_phase: previous,
      schema_version: 1,
      transaction_id: baseline.plan.transaction_id,
    })),
  );
  const receipt = await recoverOverlayTransaction({
    approvedPlanSha256: baseline.approvedPlanSha256,
    ops,
    plan: baseline.plan,
  });
  assert.equal(receipt.outcome, "rolled-back");
  assert.equal(ops.reloadCalls, 1);
});

test("recovery records and completes a rollback exchanged before its phase write", async () => {
  const baseline = await successfulBaseline();
  const ops = recoveryOpsFromBaseline(baseline, {
    pair: "rolled-back",
    phases: [
      OVERLAY_STATE_FILES.prepared,
      OVERLAY_STATE_FILES.exchanged,
      OVERLAY_STATE_FILES.reloaded,
    ],
  });
  const receipt = await recoverOverlayTransaction({
    approvedPlanSha256: baseline.approvedPlanSha256,
    ops,
    plan: baseline.plan,
  });
  assert.equal(receipt.outcome, "rolled-back");
  assert.equal(ops.state.has(OVERLAY_STATE_FILES.rollbackExchanged), true);
  assert.equal(ops.reloadCalls, 1);
});

test("a durable committed receipt is finalized, never rolled back", async () => {
  const baseline = await successfulBaseline();
  const ops = recoveryOpsFromBaseline(baseline, {
    pair: "installed",
    phases: [
      OVERLAY_STATE_FILES.prepared,
      OVERLAY_STATE_FILES.exchanged,
      OVERLAY_STATE_FILES.reloaded,
    ],
    receipt: baseline.receipt,
  });
  const receipt = await recoverOverlayTransaction({
    approvedPlanSha256: baseline.approvedPlanSha256,
    ops,
    plan: baseline.plan,
  });
  assert.equal(receipt.outcome, "committed");
  assert.equal(ops.reloadCalls, 0);
  assert.equal(ops.files.get("/etc/caddy/Caddyfile").snapshot.sha256, baseline.plan.managed_block.candidate_sha256);
  assert.equal(ops.files.has(baseline.plan.transaction.candidate_path), false);
});

test("recovery atomically publishes a valid pending committed receipt", async () => {
  const baseline = await successfulBaseline();
  const ops = recoveryOpsFromBaseline(baseline, {
    pair: "installed",
    phases: [
      OVERLAY_STATE_FILES.prepared,
      OVERLAY_STATE_FILES.exchanged,
      OVERLAY_STATE_FILES.reloaded,
    ],
  });
  const bytes = Buffer.from(canonicalJson(baseline.receipt), "utf8");
  seedReceiptEntry(ops, baseline.plan.transaction.receipt_pending_path, bytes);

  const receipt = await recoverOverlayTransaction({
    approvedPlanSha256: baseline.approvedPlanSha256,
    ops,
    plan: baseline.plan,
  });

  assert.equal(receipt.outcome, "committed");
  assert.equal(ops.reloadCalls, 0);
  assert.equal(ops.files.has(baseline.plan.transaction.receipt_pending_path), false);
  assert.equal(ops.files.get(baseline.plan.transaction.receipt_path).bytes.equals(bytes), true);
  assert.equal(ops.files.has(baseline.plan.transaction.candidate_path), false);
});

test("recovery discards a truncated pending receipt before rolling back", async () => {
  const baseline = await successfulBaseline();
  const ops = recoveryOpsFromBaseline(baseline, {
    pair: "installed",
    phases: [
      OVERLAY_STATE_FILES.prepared,
      OVERLAY_STATE_FILES.exchanged,
      OVERLAY_STATE_FILES.reloaded,
    ],
  });
  seedReceiptEntry(
    ops,
    baseline.plan.transaction.receipt_pending_path,
    Buffer.from('{"schema_version":', "utf8"),
  );

  const receipt = await recoverOverlayTransaction({
    approvedPlanSha256: baseline.approvedPlanSha256,
    ops,
    plan: baseline.plan,
  });

  assert.equal(receipt.outcome, "rolled-back");
  assert.equal(ops.reloadCalls, 1);
  assert.equal(ops.files.has(baseline.plan.transaction.receipt_pending_path), false);
  assert.equal(ops.files.has(baseline.plan.transaction.receipt_path), true);
  assert.equal(
    ops.files.get("/etc/caddy/Caddyfile").snapshot.sha256,
    baseline.plan.target.config_preimage.sha256,
  );
});

test("recovery rejects nested state extensions before mutating the file pair", async () => {
  const baseline = await successfulBaseline();
  const ops = recoveryOpsFromBaseline(baseline, {
    pair: "installed",
    phases: [
      OVERLAY_STATE_FILES.prepared,
      OVERLAY_STATE_FILES.exchanged,
      OVERLAY_STATE_FILES.reloaded,
    ],
  });
  const reloaded = JSON.parse(ops.state.get(OVERLAY_STATE_FILES.reloaded).toString("utf8"));
  reloaded.reload.unreviewed = true;
  ops.state.set(OVERLAY_STATE_FILES.reloaded, Buffer.from(canonicalJson(reloaded)));

  await assert.rejects(
    recoverOverlayTransaction({
      approvedPlanSha256: baseline.approvedPlanSha256,
      ops,
      plan: baseline.plan,
    }),
    /reloaded state reload keys drifted/,
  );
  assert.equal(ops.exchangeHistory.length, 0);
  assert.equal(ops.reloadCalls, 0);
});

test("recovery rejects a later phase whose durable predecessor is missing", async () => {
  const baseline = await successfulBaseline();
  const ops = recoveryOpsFromBaseline(baseline, {
    pair: "installed",
    phases: [OVERLAY_STATE_FILES.prepared, OVERLAY_STATE_FILES.reloaded],
  });

  await assert.rejects(
    recoverOverlayTransaction({
      approvedPlanSha256: baseline.approvedPlanSha256,
      ops,
      plan: baseline.plan,
    }),
    /durable reloaded state is missing predecessor exchanged/,
  );
  assert.equal(ops.exchangeHistory.length, 0);
  assert.equal(ops.reloadCalls, 0);
});

test("recovery refuses an unknown digest pair without mutation", async () => {
  const baseline = await successfulBaseline();
  const ops = recoveryOpsFromBaseline(baseline, {
    pair: "installed",
    phases: [OVERLAY_STATE_FILES.prepared],
  });
  const unknown = Buffer.from("unknown external file\n");
  ops.files.get("/etc/caddy/Caddyfile").bytes = unknown;
  ops.files.get("/etc/caddy/Caddyfile").snapshot.sha256 = testSha256(unknown);
  await assert.rejects(
    recoverOverlayTransaction({
      approvedPlanSha256: baseline.approvedPlanSha256,
      ops,
      plan: baseline.plan,
    }),
    /unknown target\/candidate digest combination/,
  );
  assert.equal(ops.exchangeHistory.length, 0);
});
