import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

import {
  OVERLAY_STATE_FILES,
  OverlayTransactionError,
  executeOverlayTransaction,
  recoverOverlayTransaction,
  testOnlyNormalizeEffectiveUnitProperties,
  verifyWebSocketUpgrade,
} from "./payment-v1-integrated-caddy-overlay-transaction.mjs";
import {
  canonicalJson,
  computeApprovedOverlayPlanSha256,
} from "./payment-v1-integrated-caddy-overlay-gate.mjs";
import { canonicalJson as canonicalAdminUdsJson } from "./payment-v1-caddy-admin-uds-gate.mjs";
import {
  TEST_OVERLAY_ADAPTED_JSON,
  TEST_PREIMAGE,
  PUBLISHER_NETNS_DROPIN,
  TEST_REPOSITORY,
  makeIntegratedOverlayTestPlan,
  renderedManagedBlock,
  testCaddyEffectiveUnit,
  testCaddyProcessRuntime,
  testHardeningPlanBytes,
  testHardeningReceiptBytes,
  testPublisherNetnsPlanBytes,
  testPublisherNetnsReceiptBytes,
  testSha256,
} from "./payment-v1-integrated-caddy-overlay-test-fixture.mjs";

let mockMonotonicNs = 9_000_000_000n;

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

test("systemd 255 effective-unit serialization normalizes without retaining Environment values", () => {
  const normalized = testOnlyNormalizeEffectiveUnitProperties({
    After: "network.target bitcoinpir-payment-v1-publisher-netns.service",
    BindsTo: "",
    DropInPaths: "/etc/systemd/system/bhtm-caddy.service.d/bitcoinpir-publisher-netns.conf",
    Environment: "HOME=/var/lib/caddy XDG_CONFIG_HOME=/var/lib/caddy/.config XDG_DATA_HOME=/var/lib/caddy/.local/share",
    EnvironmentFiles: "",
    ExecReload: "{ path=/usr/local/bin/caddy ; argv[]=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --address unix//run/bitcoinpir-caddy-admin/admin.sock ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }",
    ExecStart: "{ path=/usr/local/bin/caddy ; argv[]=/usr/local/bin/caddy run --config /etc/caddy/Caddyfile --adapter caddyfile ; ignore_errors=no ; start_time=[Wed 2026-06-24 17:19:40 CEST] ; stop_time=[n/a] ; pid=639667 ; code=(null) ; status=0/0 }",
    FragmentPath: "/etc/systemd/system/bhtm-caddy.service",
    Group: "root",
    LimitCORE: "0",
    MemorySwapMax: "0",
    NeedDaemonReload: "no",
    PartOf: "",
    PassEnvironment: "",
    Requires: "system.slice",
    RuntimeDirectory: "bitcoinpir-caddy-admin",
    RuntimeDirectoryMode: "0700",
    RuntimeDirectoryPreserve: "no",
    StandardError: "null",
    StandardOutput: "null",
    UMask: "0077",
    UnsetEnvironment: "CADDY_ADMIN",
    User: "root",
    Wants: "bitcoinpir-payment-v1-publisher-netns.service",
  });
  assert.deepEqual(normalized.environment_names, ["HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME"]);
  assert.deepEqual(normalized.exec_start, {
    argv: "/usr/local/bin/caddy run --config /etc/caddy/Caddyfile --adapter caddyfile",
    ignore_errors: "no",
    path: "/usr/local/bin/caddy",
  });
  assert.equal(normalized.exec_reload.argv.endsWith("unix//run/bitcoinpir-caddy-admin/admin.sock"), true);
  assert.deepEqual(normalized.publisher_netns_dependency, {
    after_namespace_owner: true,
    binds_to_namespace_owner: false,
    dropin_paths: [
      "/etc/systemd/system/bhtm-caddy.service.d/bitcoinpir-publisher-netns.conf",
    ],
    need_daemon_reload: "no",
    part_of_namespace_owner: false,
    requires_namespace_owner: false,
    wants_namespace_owner: true,
  });
  assert.equal(JSON.stringify(normalized).includes("/var/lib/caddy"), false);
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
    this.failExchangeAfterApplyNumber = null;
    this.failExchangeBeforeApplyNumber = null;
    this.failReceiptAfterPublish = false;
    this.failFsyncParentAlways = false;
    this.failFsyncParentPathSuffix = null;
    this.failRemovePath = null;
    this.failStateAfterPublishPhase = null;
    this.failStateBeforePublishPhase = null;
    this.raceTargetBeforeFirstExchange = false;
    this.raceTargetBeforeExchangeNumber = null;
    this.racedTargetSnapshot = null;
    this.adminDirectoryMode = "0700";
    this.adminSocketMode = "0200";
    this.adminTcpResult = "connection-refused";
    this.adminUnexpectedReachableUid = null;
    this.adminCapEff = "0000000000000000";
    this.adminRootListen = "unix//run/bitcoinpir-caddy-admin/admin.sock|0200";
    this.adminBodySha256Override = null;
    this.adminBodySha256AfterFirstReload = null;
    this.adminBodySha256AfterHealth = null;
    this.adminProbeApiCalls = 0;
    this.healthCalls = 0;
    this.healthBoundaries = [];
    this.adaptedJson = clone(TEST_OVERLAY_ADAPTED_JSON);
    this.effectiveUnit = testCaddyEffectiveUnit(plan);
    this.processRuntime = testCaddyProcessRuntime(plan);
    this.publisherNetnsReceipt = JSON.parse(
      testPublisherNetnsReceiptBytes(plan).toString("utf8"),
    );
    this.driftAdminAfterFirstReload = false;
    this.driftBootDuringProbe = false;
    this.driftGenerationDuringProbe = false;
    this.hostIdentityCalls = 0;
    this.targetGenerationReads = 0;
    this.mutableDirectories = new Map();
    for (const [index, path] of [...new Set([
      this.plan.transaction.adapted_json_path.slice(0, this.plan.transaction.adapted_json_path.lastIndexOf("/")),
      this.plan.transaction.backup_path.slice(0, this.plan.transaction.backup_path.lastIndexOf("/")),
      this.plan.transaction.receipt_path.slice(0, this.plan.transaction.receipt_path.lastIndexOf("/")),
      this.plan.transaction.state_directory.slice(0, this.plan.transaction.state_directory.lastIndexOf("/")),
    ])].sort().entries()) {
      this.mutableDirectories.set(path, {
        device: "2049",
        gid: 0,
        inode: String(71000 + index),
        mode: "0700",
        path,
        uid: 0,
      });
    }
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
      plan.runtime.setpriv_binary,
      plan.runtime.admin_probe,
      plan.runtime.admin_uds_gate,
      plan.runtime.gate,
      plan.runtime.executor,
      plan.runtime.exchange_helper,
      plan.target.binary,
      plan.target.unit_fragment,
      plan.target.publisher_netns_ceremony.dropin,
      plan.target.publisher_netns_ceremony.plan,
      plan.target.publisher_netns_ceremony.receipt,
      plan.target.admin_uds_hardening.plan,
      plan.target.admin_uds_hardening.receipt,
      plan.source_fair.haproxy_binary,
      plan.source_fair.haproxy_config,
      plan.source_fair.unit_fragment,
      ...plan.tls_dependencies.map((entry) => entry.pin),
    ]) this.#putPin(pin);
    this.#putPin(
      plan.target.admin_uds_hardening.plan,
      testHardeningPlanBytes(plan),
    );
    this.#putPin(
      plan.target.admin_uds_hardening.receipt,
      testHardeningReceiptBytes(plan),
    );
    this.#putPin(
      plan.target.publisher_netns_ceremony.dropin,
      PUBLISHER_NETNS_DROPIN,
    );
    this.#putPin(
      plan.target.publisher_netns_ceremony.plan,
      testPublisherNetnsPlanBytes(plan),
    );
    this.#putPin(
      plan.target.publisher_netns_ceremony.receipt,
      testPublisherNetnsReceiptBytes(plan),
    );
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
    if (this.failExchangeBeforeApplyNumber === this.exchangeHistory.length + 1) {
      throw new Error("mock helper failed before applying exchange");
    }
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
    if (this.failExchangeAfterApplyNumber === this.exchangeHistory.length) {
      throw new Error("mock helper failed after applying exchange");
    }
  }

  async fsyncParent(path) {
    // The in-memory adapter has no volatile directory cache.
    if (this.failFsyncParentAlways) throw new Error("mock parent fsync failed");
    if (this.failFsyncParentPathSuffix !== null && path.endsWith(this.failFsyncParentPathSuffix)) {
      throw new Error("mock selected parent fsync failed");
    }
  }

  async fsyncRegular(path, expected) {
    const observed = this.files.get(path);
    if (observed === undefined || !sameSnapshot(observed.snapshot, expected)) {
      throw new Error(`mock fsync target drifted: ${path}`);
    }
  }

  async health(check, privateBoundary) {
    this.healthCalls += 1;
    this.healthBoundaries.push({
      boundary: privateBoundary === undefined ? null : clone(privateBoundary),
      lane: check.lane,
    });
    if (check.lane === this.failHealthLane) throw new Error(`mock health failed: ${check.lane}`);
    return {
      body_sha256: check.expected_body_sha256,
      leaf_certificate_sha256: check.leaf_certificate_sha256,
      status: check.expected_status,
      success: true,
    };
  }

  async hostIdentity() {
    this.hostIdentityCalls += 1;
    return {
      boot_id: this.driftBootDuringProbe && this.hostIdentityCalls >= 2
        ? "32345678-1234-4234-9234-123456789abc"
        : "22345678-1234-4234-9234-123456789abc",
      machine_id_sha256: "9".repeat(64),
    };
  }

  async monotonicNowNs() {
    mockMonotonicNs += 1n;
    return mockMonotonicNs.toString();
  }

  currentAdminBodySha256() {
    if (this.adminBodySha256Override !== null) return this.adminBodySha256Override;
    if (
      this.reloadCalls === 1 &&
      this.healthCalls > 0 &&
      this.adminBodySha256AfterHealth !== null
    ) {
      return this.adminBodySha256AfterHealth;
    }
    if (this.reloadCalls === 1 && this.adminBodySha256AfterFirstReload !== null) {
      return this.adminBodySha256AfterFirstReload;
    }
    const loaded = this.files.get(this.plan.target.config_preimage.path)?.snapshot.sha256;
    if (loaded === this.plan.managed_block.candidate_sha256) {
      return this.plan.managed_block.candidate_adapted_json_sha256;
    }
    if (loaded === this.plan.target.config_preimage.sha256) {
      return this.plan.target.admin_uds_hardening.adapted_json_sha256;
    }
    return "b".repeat(64);
  }

  async probeAdminApi({ expected, gid, label, uid }) {
    this.adminProbeApiCalls += 1;
    if (expected === "root-readback") {
      return {
        body_sha256: this.currentAdminBodySha256(),
        cap_eff: this.adminCapEff,
        error: null,
        gid,
        groups: [gid],
        label,
        listen: this.adminRootListen,
        path: "/config/",
        status: 200,
        transport: "unix",
        uid,
      };
    }
    if (uid === this.adminUnexpectedReachableUid) {
      return {
        body_sha256: this.currentAdminBodySha256(),
        cap_eff: this.adminCapEff,
        error: null,
        gid,
        groups: [gid],
        label,
        listen: this.adminRootListen,
        path: "/config/",
        status: 200,
        transport: "unix",
        uid,
      };
    }
    return {
      body_sha256: null,
      cap_eff: this.adminCapEff,
      error: "EACCES",
      gid,
      groups: [gid],
      label,
      listen: null,
      path: "/config/",
      status: null,
      transport: "unix",
      uid,
    };
  }

  async probeTcpAdmin() {
    return this.adminTcpResult;
  }

  async readAdminRuntimePath(path) {
    const directory = path === "/run/bitcoinpir-caddy-admin";
    return {
      ctime_ns: directory ? "1700000003000000000" : "1700000003000000001",
      device: "2049",
      gid: 0,
      inode: directory ? "61001" : "61002",
      mode: directory ? this.adminDirectoryMode : this.adminSocketMode,
      path,
      type: directory ? "directory" : "socket",
      uid: 0,
    };
  }

  async initializeStateDirectory() {
    if (this.stateInitialized) {
      const error = new Error("state exists");
      error.code = "EEXIST";
      throw error;
    }
    this.stateInitialized = true;
    return {
      device: "2049",
      gid: 0,
      inode: "70001",
      mode: "0700",
      path: this.plan.transaction.state_directory,
      uid: 0,
    };
  }

  async sealStateDirectory() {
    if (!this.stateInitialized) throw new Error("state directory missing");
    return {
      device: "2049",
      gid: 0,
      inode: "70001",
      mode: "0700",
      path: this.plan.transaction.state_directory,
      uid: 0,
    };
  }

  async readDirectory(path) {
    if (path === this.plan.target.config_parent.path) return clone(this.plan.target.config_parent);
    if (this.mutableDirectories.has(path)) return clone(this.mutableDirectories.get(path));
    const dependency = this.plan.tls_dependencies.find((entry) => entry.parent.path === path);
    if (dependency) return clone(dependency.parent);
    throw new Error(`unknown directory ${path}`);
  }

  async readEffectiveUnit(unitName) {
    if (unitName !== "bhtm-caddy.service") throw new Error(`unknown effective unit ${unitName}`);
    return clone(this.effectiveUnit);
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

  async readProcessRuntime(pid) {
    if (pid !== this.plan.target.unit_generation.main_pid) {
      throw new Error(`unknown process generation ${pid}`);
    }
    return clone(this.processRuntime);
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
    if (unitName === "bhtm-caddy.service") this.targetGenerationReads += 1;
    if (unitName === "bhtm-caddy.service" && this.driftGenerationDuringProbe && this.targetGenerationReads >= 3) {
      return {
        ...clone(this.plan.target.unit_generation),
        invocation_id: "32345678123442349234123456789abc",
      };
    }
    if (unitName === "bhtm-caddy.service") {
      return clone(this.plan.target.unit_generation);
    }
    if (unitName === "bitcoinpir-payment-v1-source-fair-edge.service") {
      return clone(this.plan.source_fair.unit_generation);
    }
    if (unitName === "bitcoinpir-payment-v1-publisher-netns.service") {
      const unit = this.publisherNetnsReceipt.netns_unit;
      return {
        active_enter_timestamp_monotonic: unit.active_enter_timestamp_monotonic,
        active_state: unit.active_state,
        can_reload: "no",
        control_group: "/system.slice/bitcoinpir-payment-v1-publisher-netns.service",
        invocation_id: unit.invocation_id,
        main_pid: unit.main_pid,
        sub_state: unit.sub_state,
        unit_name: unit.name,
      };
    }
    if (unitName === "bitcoinpir-payment-v1-directory-publisher.service") {
      return {
        active_enter_timestamp_monotonic: "0",
        active_state: "inactive",
        can_reload: "no",
        control_group: "",
        invocation_id: "",
        main_pid: "0",
        sub_state: "dead",
        unit_name: unitName,
      };
    }
    throw new Error(`unknown unit generation ${unitName}`);
  }

  async removeIfExact(path, expected) {
    const file = this.files.get(path);
    if (!file) return;
    if (path === this.failRemovePath) {
      this.failRemovePath = null;
      throw new Error(`mock exact removal failed: ${path}`);
    }
    for (const key of ["device", "gid", "inode", "mode", "mtime_ns", "nlink", "sha256", "size", "uid"]) {
      assert.equal(file.snapshot[key], expected[key], `cleanup pin ${key}`);
    }
    this.files.delete(path);
    if (path.startsWith(`${this.plan.transaction.state_directory}/`)) {
      this.state.delete(path.slice(path.lastIndexOf("/") + 1));
    }
  }

  async run(argv) {
    if (argv[1] === "adapt") {
      return {
        status: 0,
        stderr: Buffer.alloc(0),
        stdout: Buffer.from(`${canonicalJson(this.adaptedJson)}\n`),
      };
    }
    if (argv[1] === "validate") {
      return { status: 0, stderr: Buffer.alloc(0), stdout: Buffer.alloc(0) };
    }
    if (argv[1] === "reload") {
      this.reloadCalls += 1;
      if (this.driftAdminAfterFirstReload) {
        this.adminSocketMode = this.reloadCalls === 1 ? "0666" : "0200";
      }
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

  async publishPendingState(pendingPath, finalPath) {
    await this.publishPendingReceipt(pendingPath, finalPath);
    const filename = finalPath.slice(finalPath.lastIndexOf("/") + 1);
    this.state.set(filename, Buffer.from(this.files.get(finalPath).bytes));
    this.state.delete(`${filename}.pending`);
  }

  async writeReceipt(pendingPath, finalPath, bytes) {
    const pending = this.#store(pendingPath, bytes, "0400");
    await this.publishPendingReceipt(pendingPath, finalPath);
    if (this.failReceiptAfterPublish) {
      this.failReceiptAfterPublish = false;
      throw new Error("mock receipt helper failed after publish");
    }
    const published = this.files.get(finalPath);
    return {
      directoryFsync: true,
      exclusiveCreate: true,
      fileFsync: true,
      snapshot: clone(published.snapshot),
      pendingSnapshot: clone(pending.snapshot),
    };
  }

  async writeState(directory, filename, bytes) {
    const phase = JSON.parse(Buffer.from(bytes).toString("utf8")).phase;
    if (phase === this.failStateBeforePublishPhase) {
      this.failStateBeforePublishPhase = null;
      throw new Error(`mock phase ${phase} failed before publish`);
    }
    const pendingName = `${filename}.pending`;
    if (this.state.has(filename) || this.state.has(pendingName)) {
      const error = new Error(`state exists: ${filename}`);
      error.code = "EEXIST";
      throw error;
    }
    this.state.set(pendingName, Buffer.from(bytes));
    const pendingPath = `${directory}/${pendingName}`;
    const finalPath = `${directory}/${filename}`;
    this.#store(pendingPath, bytes, "0400");
    await this.publishPendingState(pendingPath, finalPath);
    if (phase === this.failStateAfterPublishPhase) {
      throw new Error(`mock phase ${phase} helper failed after publish`);
    }
  }
}

function sameSnapshot(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

async function successfulBaseline() {
  const plan = makeIntegratedOverlayTestPlan();
  const ops = new MockOverlayOps(plan);
  const approvedPlanSha256 = computeApprovedOverlayPlanSha256(plan);
  const receipt = await executeOverlayTransaction({ approvedPlanSha256, ops, plan });
  return { approvedPlanSha256, ops, plan, receipt };
}

async function rolledBackBaseline() {
  const plan = makeIntegratedOverlayTestPlan();
  const ops = new MockOverlayOps(plan);
  ops.failHealthLane = "provider";
  const approvedPlanSha256 = computeApprovedOverlayPlanSha256(plan);
  let receipt;
  try {
    await executeOverlayTransaction({ approvedPlanSha256, ops, plan });
    assert.fail("expected the fixture transaction to roll back");
  } catch (error) {
    assert.equal(error.phase, "rolled-back");
    receipt = error.receipt;
  }
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

function seedStatePending(ops, plan, filename, bytes) {
  const name = `${filename}.pending`;
  const path = `${plan.transaction.state_directory}/${name}`;
  ops.state.set(name, Buffer.from(bytes));
  seedReceiptEntry(ops, path, bytes);
}

test("transaction commits only after verified exchange, health and durable receipt", async () => {
  const { ops, plan, receipt } = await successfulBaseline();
  assert.equal(receipt.outcome, "committed");
  assert.equal(ops.files.get("/etc/caddy/Caddyfile").snapshot.sha256, plan.managed_block.candidate_sha256);
  assert.equal(ops.files.has(plan.transaction.candidate_path), false);
  assert.equal(ops.state.has(OVERLAY_STATE_FILES.committed), true);
  assert.equal(ops.reloadCalls, 1);
  assert.equal(ops.releaseCalls, 1);
  assert.deepEqual(
    ops.healthBoundaries.map(({ boundary, lane }) => ({
      lane,
      namespace: boundary === null
        ? "host"
        : `${boundary.namespace_device}:${boundary.namespace_inode}`,
    })),
    [
      { lane: "directory-public", namespace: "host" },
      {
        lane: "directory-publisher",
        namespace:
          `${plan.target.publisher_netns_ceremony.namespace_device}:` +
          plan.target.publisher_netns_ceremony.namespace_inode,
      },
      { lane: "issuer", namespace: "host" },
      { lane: "provider", namespace: "host" },
    ],
  );
  const publisherBoundary = ops.healthBoundaries[1].boundary;
  const ceremony = JSON.parse(testPublisherNetnsPlanBytes(plan).toString("utf8"));
  assert.deepEqual(publisherBoundary.launcher, ceremony.runtime.launcher);
  assert.equal(
    publisherBoundary.launcher_manifest_sha256,
    ceremony.runtime.launcher_manifest.sha256,
  );
  assert.equal(ops.adminProbeApiCalls, 12, "four fresh runtime collections probe root and both service UIDs");
});

test("transaction refuses a pinned but non-committed admin UDS prerequisite", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  const receipt = JSON.parse(testHardeningReceiptBytes(plan).toString("utf8"));
  receipt.outcome = "outcome-unknown";
  const bytes = Buffer.from(canonicalAdminUdsJson(receipt), "utf8");
  plan.target.admin_uds_hardening.receipt.sha256 = testSha256(bytes);
  plan.target.admin_uds_hardening.receipt.size = String(bytes.length);
  const ops = new MockOverlayOps(plan);
  ops.files.get(plan.target.admin_uds_hardening.receipt.path).bytes = bytes;
  await assert.rejects(
    executeOverlayTransaction({
      approvedPlanSha256: computeApprovedOverlayPlanSha256(plan),
      ops,
      plan,
    }),
    /only an exact committed hardening receipt is authoritative/u,
  );
  assert.equal(ops.reloadCalls, 0);
  assert.equal(ops.exchangeHistory.length, 0);
});

test("transaction rejects the former simplified hardening receipt before exchange", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  const simplified = {
    approved_plan_sha256: plan.target.admin_uds_hardening.approved_plan_sha256,
    deployment_profile: "bhtm-caddy-admin-uds-v1",
    outcome: "committed",
    transaction_id: plan.target.admin_uds_hardening.transaction_id,
  };
  const bytes = Buffer.from(canonicalAdminUdsJson(simplified), "utf8");
  plan.target.admin_uds_hardening.receipt.sha256 = testSha256(bytes);
  plan.target.admin_uds_hardening.receipt.size = String(bytes.length);
  const ops = new MockOverlayOps(plan);
  ops.files.get(plan.target.admin_uds_hardening.receipt.path).bytes = bytes;
  await assert.rejects(
    executeOverlayTransaction({
      approvedPlanSha256: computeApprovedOverlayPlanSha256(plan),
      ops,
      plan,
    }),
    /hardening receipt keys must equal/u,
  );
  assert.equal(ops.exchangeHistory.length, 0);
  assert.equal(ops.reloadCalls, 0);
});

test("transaction rejects a hardening plan and receipt from different approvals", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  const hardeningPlan = JSON.parse(testHardeningPlanBytes(plan).toString("utf8"));
  hardeningPlan.site_preservation.existing_site_inventory_sha256 = "f".repeat(64);
  const bytes = Buffer.from(canonicalAdminUdsJson(hardeningPlan), "utf8");
  plan.target.admin_uds_hardening.approved_plan_sha256 = testSha256(bytes);
  plan.target.admin_uds_hardening.plan.sha256 = testSha256(bytes);
  plan.target.admin_uds_hardening.plan.size = String(bytes.length);
  const ops = new MockOverlayOps(plan);
  ops.files.get(plan.target.admin_uds_hardening.plan.path).bytes = bytes;
  await assert.rejects(
    executeOverlayTransaction({
      approvedPlanSha256: computeApprovedOverlayPlanSha256(plan),
      ops,
      plan,
    }),
    /receipt does not bind the approved plan transaction/u,
  );
  assert.equal(ops.exchangeHistory.length, 0);
  assert.equal(ops.reloadCalls, 0);
});

test("transaction rejects a hardening adapted JSON digest drifted in its summary", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  plan.target.admin_uds_hardening.adapted_json_sha256 = "f".repeat(64);
  const ops = new MockOverlayOps(plan);
  await assert.rejects(
    executeOverlayTransaction({
      approvedPlanSha256: computeApprovedOverlayPlanSha256(plan),
      ops,
      plan,
    }),
    /full evidence does not equal the overlay preimage summary/u,
  );
  assert.equal(ops.exchangeHistory.length, 0);
  assert.equal(ops.reloadCalls, 0);
});

test("transaction rejects a hardening evidence transaction ID drifted from its summary", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  const originalId = plan.target.admin_uds_hardening.transaction_id;
  const changedId = "caddy-admin-uds-different-1";
  plan.target.admin_uds_hardening.transaction_id = changedId;
  plan.target.admin_uds_hardening.plan.path =
    plan.target.admin_uds_hardening.plan.path.replace(originalId, changedId);
  plan.target.admin_uds_hardening.receipt.path =
    plan.target.admin_uds_hardening.receipt.path.replace(originalId, changedId);
  const ops = new MockOverlayOps(plan);
  await assert.rejects(
    executeOverlayTransaction({
      approvedPlanSha256: computeApprovedOverlayPlanSha256(plan),
      ops,
      plan,
    }),
    /evidence transaction ID does not equal the overlay summary/u,
  );
  assert.equal(ops.exchangeHistory.length, 0);
  assert.equal(ops.reloadCalls, 0);
});

test("transaction rejects an admin UDS gate generation not pinned by hardening", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  plan.runtime.admin_uds_gate.inode = "999999";
  const ops = new MockOverlayOps(plan);
  await assert.rejects(
    executeOverlayTransaction({
      approvedPlanSha256: computeApprovedOverlayPlanSha256(plan),
      ops,
      plan,
    }),
    /admin UDS gate does not equal the exact approved hardening gate generation/u,
  );
  assert.equal(ops.exchangeHistory.length, 0);
  assert.equal(ops.reloadCalls, 0);
});

test("transaction rejects an admin probe generation not pinned by hardening", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  plan.runtime.admin_probe.inode = "999999";
  const ops = new MockOverlayOps(plan);
  await assert.rejects(
    executeOverlayTransaction({
      approvedPlanSha256: computeApprovedOverlayPlanSha256(plan),
      ops,
      plan,
    }),
    /admin probe does not equal the exact approved hardening probe generation/u,
  );
  assert.equal(ops.exchangeHistory.length, 0);
  assert.equal(ops.reloadCalls, 0);
});

test("transaction rejects a Node digest not pinned by hardening", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  plan.runtime.node_binary.sha256 = "e".repeat(64);
  const ops = new MockOverlayOps(plan);
  await assert.rejects(
    executeOverlayTransaction({
      approvedPlanSha256: computeApprovedOverlayPlanSha256(plan),
      ops,
      plan,
    }),
    /Node binary does not equal the approved hardening Node digest/u,
  );
  assert.equal(ops.exchangeHistory.length, 0);
  assert.equal(ops.reloadCalls, 0);
});

test("transaction rejects current admin UDS gate file drift before exchange", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  const ops = new MockOverlayOps(plan);
  ops.files.get(plan.runtime.admin_uds_gate.path).snapshot.inode = "999999";
  await assert.rejects(
    executeOverlayTransaction({
      approvedPlanSha256: computeApprovedOverlayPlanSha256(plan),
      ops,
      plan,
    }),
    /initial Caddy admin UDS gate drifted from the approved regular-file pin/u,
  );
  assert.equal(ops.exchangeHistory.length, 0);
  assert.equal(ops.reloadCalls, 0);
});

test("transaction rejects an internally consistent namespace receipt from a different Caddy generation", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  const ops = new MockOverlayOps(plan);
  const ceremonyPlan = JSON.parse(testPublisherNetnsPlanBytes(plan).toString("utf8"));
  const ceremonyReceipt = JSON.parse(
    testPublisherNetnsReceiptBytes(plan).toString("utf8"),
  );
  for (const caddy of [
    ceremonyPlan.caddy_preimage,
    ceremonyReceipt.caddy_before,
    ceremonyReceipt.caddy_after,
  ]) {
    caddy.unit.invocation_id = "d".repeat(32);
  }
  const ceremonyPlanBytes = Buffer.from(canonicalJson(ceremonyPlan), "utf8");
  const ceremonyPlanSha256 = testSha256(ceremonyPlanBytes);
  ceremonyReceipt.approved_plan_sha256 = ceremonyPlanSha256;
  const ceremonyReceiptBytes = Buffer.from(canonicalJson(ceremonyReceipt), "utf8");
  const planPin = plan.target.publisher_netns_ceremony.plan;
  const receiptPin = plan.target.publisher_netns_ceremony.receipt;
  plan.target.publisher_netns_ceremony.approved_plan_sha256 = ceremonyPlanSha256;
  planPin.sha256 = ceremonyPlanSha256;
  planPin.size = String(ceremonyPlanBytes.length);
  receiptPin.sha256 = testSha256(ceremonyReceiptBytes);
  receiptPin.size = String(ceremonyReceiptBytes.length);
  ops.files.set(planPin.path, {
    bytes: ceremonyPlanBytes,
    snapshot: clone(planPin),
  });
  ops.files.set(receiptPin.path, {
    bytes: ceremonyReceiptBytes,
    snapshot: clone(receiptPin),
  });

  await assert.rejects(
    executeOverlayTransaction({
      approvedPlanSha256: computeApprovedOverlayPlanSha256(plan),
      ops,
      plan,
    }),
    /did not occur on the exact hardened Caddy preimage generation/u,
  );
  assert.equal(ops.exchangeHistory.length, 0);
  assert.equal(ops.reloadCalls, 0);
});

function replacePublisherNetnsEvidence(plan, ops, { mutatePlan, mutateReceipt }) {
  const ceremonyPlan = JSON.parse(testPublisherNetnsPlanBytes(plan).toString("utf8"));
  const ceremonyReceipt = JSON.parse(testPublisherNetnsReceiptBytes(plan).toString("utf8"));
  mutatePlan?.(ceremonyPlan);
  mutateReceipt?.(ceremonyReceipt);
  const planBytes = Buffer.from(canonicalJson(ceremonyPlan), "utf8");
  const planSha256 = testSha256(planBytes);
  if (mutatePlan !== undefined) ceremonyReceipt.approved_plan_sha256 = planSha256;
  const receiptBytes = Buffer.from(canonicalJson(ceremonyReceipt), "utf8");
  const summary = plan.target.publisher_netns_ceremony;
  summary.approved_plan_sha256 = planSha256;
  summary.plan.sha256 = planSha256;
  summary.plan.size = String(planBytes.length);
  summary.receipt.sha256 = testSha256(receiptBytes);
  summary.receipt.size = String(receiptBytes.length);
  ops.files.set(summary.plan.path, { bytes: planBytes, snapshot: clone(summary.plan) });
  ops.files.set(summary.receipt.path, {
    bytes: receiptBytes,
    snapshot: clone(summary.receipt),
  });
}

for (const [label, mutation] of [
  ["host manager field", {
    mutatePlan: (value) => { value.host.systemd_manager_generation.pid1_start_ticks = "0"; },
  }],
  ["inactive Caddy preimage field", {
    mutatePlan: (value) => { value.caddy_preimage.unit.active_state = "inactive"; },
  }],
  ["activation approval field", {
    mutateReceipt: (value) => { value.activation_approval_sha256 = "A".repeat(64); },
  }],
  ["firewall pin field", {
    mutatePlan: (value) => { value.firewall_evidence.mode = "0444"; },
  }],
  ["installed-file field", {
    mutatePlan: (value) => { value.installed_files[1].pin.nlink = 2; },
  }],
  ["runtime field", {
    mutatePlan: (value) => { value.runtime.schema_validator.path = "/tmp/unreviewed.mjs"; },
  }],
  ["static ELF proof field", {
    mutatePlan: (value) => { value.launcher_static_elf.pt_interp = true; },
  }],
  ["loaded-unit field", {
    mutatePlan: (value) => { value.preimage.loaded_netns_unit.service.memory_max = "infinity"; },
  }],
  ["sentinel field", {
    mutatePlan: (value) => { value.activation_sentinels[0].mode = "0444"; },
  }],
  ["active namespace unit field", {
    mutateReceipt: (value) => { value.netns_unit.main_pid = "0"; },
  }],
  ["inactive publisher unit field", {
    mutateReceipt: (value) => { value.publisher_unit.active_state = "active"; },
  }],
  ["runtime topology field", {
    mutateReceipt: (value) => { value.topology.routes.client_main[0].gateway = "10.203.0.1"; },
  }],
]) {
  test(`shared schema-v2 validator rejects publisher ${label} mutation before exchange`, async () => {
    const plan = makeIntegratedOverlayTestPlan();
    const ops = new MockOverlayOps(plan);
    replacePublisherNetnsEvidence(plan, ops, mutation);
    await assert.rejects(
      executeOverlayTransaction({
        approvedPlanSha256: computeApprovedOverlayPlanSha256(plan),
        ops,
        plan,
      }),
      /publisher-netns-schema-v2/u,
    );
    assert.equal(ops.exchangeHistory.length, 0);
    assert.equal(ops.reloadCalls, 0);
  });
}

for (const [label, mutate, expected] of [
  [
    "schema-v1 publisher namespace receipt",
    (receipt) => { receipt.schema_version = 1; },
    /receipt identity or outcome drifted/u,
  ],
  [
    "publisher namespace invocation drift",
    (receipt) => { receipt.netns_unit.invocation_id = "e".repeat(32); },
    /does not bind the active isolated topology/u,
  ],
  [
    "publisher namespace topology drift",
    (receipt) => { receipt.topology.namespace.inode = "9999"; },
    /does not bind the active isolated topology/u,
  ],
]) {
  test(`transaction rejects ${label} before exchange`, async () => {
    const plan = makeIntegratedOverlayTestPlan();
    const ops = new MockOverlayOps(plan);
    const receipt = JSON.parse(
      testPublisherNetnsReceiptBytes(plan).toString("utf8"),
    );
    mutate(receipt);
    const bytes = Buffer.from(canonicalJson(receipt), "utf8");
    const pin = plan.target.publisher_netns_ceremony.receipt;
    pin.sha256 = testSha256(bytes);
    pin.size = String(bytes.length);
    ops.files.set(pin.path, { bytes, snapshot: clone(pin) });
    await assert.rejects(
      executeOverlayTransaction({
        approvedPlanSha256: computeApprovedOverlayPlanSha256(plan),
        ops,
        plan,
      }),
      expected,
    );
    assert.equal(ops.exchangeHistory.length, 0);
    assert.equal(ops.reloadCalls, 0);
  });
}

for (const [name, mutate, expected] of [
  ["runtime directory mode drift", (ops) => { ops.adminDirectoryMode = "0755"; }, /runtime directory does not match/u],
  ["socket mode drift", (ops) => { ops.adminSocketMode = "0666"; }, /admin socket does not match/u],
  ["service UID reaches admin", (ops) => { ops.adminUnexpectedReachableUid = 52902; }, /did not receive exact EACCES/u],
  ["TCP admin is reachable", (ops) => { ops.adminTcpResult = "connected"; }, /did not refuse the TCP admin probe/u],
  ["probe retains capabilities", (ops) => { ops.adminCapEff = "0000000000000002"; }, /root did not read back/u],
  ["root reads a different admin endpoint", (ops) => { ops.adminRootListen = "127.0.0.1:2019"; }, /root did not read back/u],
  ["root reads an unreviewed adapted JSON", (ops) => { ops.adminBodySha256Override = "b".repeat(64); }, /reviewed active adapted JSON/u],
  ["boot changes during probes", (ops) => { ops.driftBootDuringProbe = true; }, /boot drifted/u],
  ["Caddy generation changes during probes", (ops) => { ops.driftGenerationDuringProbe = true; }, /process generation drifted/u],
  ["effective FragmentPath drift", (ops) => { ops.effectiveUnit.fragment_path = "/run/systemd/transient/bhtm-caddy.service"; }, /effective systemd unit drifted/u],
  ["effective drop-in drift", (ops) => { ops.effectiveUnit.dropin_paths = ["/run/systemd/system/bhtm-caddy.service.d/override.conf"]; }, /effective systemd unit drifted/u],
  ["effective EnvironmentFile drift", (ops) => { ops.effectiveUnit.environment_files = ["/etc/default/caddy"]; }, /effective systemd unit drifted/u],
  ["effective NeedDaemonReload drift", (ops) => { ops.effectiveUnit.need_daemon_reload = "yes"; }, /effective systemd unit drifted/u],
  ["effective ExecStart drift", (ops) => { ops.effectiveUnit.exec_start.argv = "/bin/true"; }, /effective systemd unit drifted/u],
  ["effective ExecReload drift", (ops) => { ops.effectiveUnit.exec_reload = { argv: "/bin/true", ignore_errors: "no", path: "/bin/true" }; }, /effective systemd unit drifted/u],
  ["effective Environment drift", (ops) => { ops.effectiveUnit.environment_names = ["CADDY_ADMIN"]; }, /effective systemd unit drifted/u],
  ["effective PassEnvironment drift", (ops) => { ops.effectiveUnit.pass_environment = ["CADDY_ADMIN"]; }, /effective systemd unit drifted/u],
  ["effective UnsetEnvironment drift", (ops) => { ops.effectiveUnit.unset_environment = []; }, /effective systemd unit drifted/u],
  ["effective RuntimeDirectory drift", (ops) => { ops.effectiveUnit.runtime_directory = ["other"]; }, /effective systemd unit drifted/u],
  ["effective RuntimeDirectoryMode drift", (ops) => { ops.effectiveUnit.runtime_directory_mode = "0755"; }, /effective systemd unit drifted/u],
  ["effective RuntimeDirectoryPreserve drift", (ops) => { ops.effectiveUnit.runtime_directory_preserve = "yes"; }, /effective systemd unit drifted/u],
  ["effective LimitCORE drift", (ops) => { ops.effectiveUnit.limit_core = "infinity"; }, /effective systemd unit drifted/u],
  ["effective MemorySwapMax drift", (ops) => { ops.effectiveUnit.memory_swap_max = "infinity"; }, /effective systemd unit drifted/u],
  ["effective StandardOutput drift", (ops) => { ops.effectiveUnit.standard_output = "journal"; }, /effective systemd unit drifted/u],
  ["effective StandardError drift", (ops) => { ops.effectiveUnit.standard_error = "inherit"; }, /effective systemd unit drifted/u],
  ["effective UMask drift", (ops) => { ops.effectiveUnit.umask = "0022"; }, /effective systemd unit drifted/u],
  ["effective User drift", (ops) => { ops.effectiveUnit.user = "caddy"; }, /effective systemd unit drifted/u],
  ["effective Group drift", (ops) => { ops.effectiveUnit.group = "caddy"; }, /effective systemd unit drifted/u],
  ["process cmdline drift", (ops) => { ops.processRuntime.cmdline_argv = ["/bin/true"]; }, /current \/proc identity/u],
  ["process PID drift", (ops) => { ops.processRuntime.main_pid = "402"; }, /current \/proc identity/u],
  ["process start-time drift", (ops) => { ops.processRuntime.start_time_ticks = "0"; }, /current \/proc identity/u],
  ["process CADDY_ADMIN environment drift", (ops) => {
    ops.processRuntime.caddy_admin_environment_absent = false;
    ops.processRuntime.effective_environment_names.push("CADDY_ADMIN");
    ops.processRuntime.effective_environment_names.sort();
  }, /current \/proc identity/u],
]) {
  test(`transaction rejects ${name} before exchange`, async () => {
    const plan = makeIntegratedOverlayTestPlan();
    const ops = new MockOverlayOps(plan);
    mutate(ops);
    await assert.rejects(
      executeOverlayTransaction({
        approvedPlanSha256: computeApprovedOverlayPlanSha256(plan),
        ops,
        plan,
      }),
      expected,
    );
    assert.equal(ops.exchangeHistory.length, 0);
    assert.equal(ops.reloadCalls, 0);
  });
}

test("recovery rejects current no-op ExecReload before file-pair mutation or reload", async () => {
  const baseline = await successfulBaseline();
  const ops = recoveryOpsFromBaseline(baseline, {
    pair: "installed",
    phases: [
      OVERLAY_STATE_FILES.prepared,
      OVERLAY_STATE_FILES.exchanged,
      OVERLAY_STATE_FILES.reloaded,
    ],
  });
  ops.effectiveUnit.exec_reload = {
    argv: "/bin/true",
    ignore_errors: "no",
    path: "/bin/true",
  };
  const stateBefore = new Map([...ops.state].map(([name, bytes]) => [name, Buffer.from(bytes)]));
  await assert.rejects(
    recoverOverlayTransaction({
      approvedPlanSha256: baseline.approvedPlanSha256,
      ops,
      plan: baseline.plan,
    }),
    /current effective systemd unit drifted/u,
  );
  assert.equal(ops.exchangeHistory.length, 0);
  assert.equal(ops.reloadCalls, 0);
  assert.deepEqual(ops.state, stateBefore);
});

test("recovery rejects regressed persisted rollback probe time without normalization or side effects", async () => {
  const baseline = await rolledBackBaseline();
  const ops = recoveryOpsFromBaseline(baseline, {
    pair: "rolled-back",
    phases: [
      OVERLAY_STATE_FILES.prepared,
      OVERLAY_STATE_FILES.exchanged,
      OVERLAY_STATE_FILES.reloaded,
      OVERLAY_STATE_FILES.rollbackExchanged,
      OVERLAY_STATE_FILES.rollbackReloaded,
    ],
  });
  const record = JSON.parse(ops.state.get(OVERLAY_STATE_FILES.rollbackReloaded).toString("utf8"));
  record.after.admin_runtime.monotonic_start_ns = "1";
  record.after.admin_runtime.monotonic_end_ns = "2";
  ops.state.set(OVERLAY_STATE_FILES.rollbackReloaded, Buffer.from(canonicalJson(record)));
  const stateBefore = new Map([...ops.state].map(([name, bytes]) => [name, Buffer.from(bytes)]));
  await assert.rejects(
    recoverOverlayTransaction({
      approvedPlanSha256: baseline.approvedPlanSha256,
      ops,
      plan: baseline.plan,
    }),
    /final admin runtime probe predates its initial probe/u,
  );
  assert.equal(ops.exchangeHistory.length, 0);
  assert.equal(ops.reloadCalls, 0);
  assert.deepEqual(ops.state, stateBefore);
});

test("recovery rejects a pending regressed rollback probe before publishing the journal entry", async () => {
  const baseline = await rolledBackBaseline();
  const ops = recoveryOpsFromBaseline(baseline, {
    pair: "rolled-back",
    phases: [
      OVERLAY_STATE_FILES.prepared,
      OVERLAY_STATE_FILES.exchanged,
      OVERLAY_STATE_FILES.reloaded,
      OVERLAY_STATE_FILES.rollbackExchanged,
    ],
  });
  const record = JSON.parse(
    baseline.ops.state.get(OVERLAY_STATE_FILES.rollbackReloaded).toString("utf8"),
  );
  record.after.admin_runtime.monotonic_start_ns = "1";
  record.after.admin_runtime.monotonic_end_ns = "2";
  seedStatePending(
    ops,
    baseline.plan,
    OVERLAY_STATE_FILES.rollbackReloaded,
    Buffer.from(canonicalJson(record)),
  );
  const stateBefore = new Map([...ops.state].map(([name, bytes]) => [name, Buffer.from(bytes)]));
  await assert.rejects(
    recoverOverlayTransaction({
      approvedPlanSha256: baseline.approvedPlanSha256,
      ops,
      plan: baseline.plan,
    }),
    /final admin runtime probe predates its initial probe/u,
  );
  assert.equal(ops.state.has(OVERLAY_STATE_FILES.rollbackReloaded), false);
  assert.equal(ops.state.has(`${OVERLAY_STATE_FILES.rollbackReloaded}.pending`), true);
  assert.deepEqual(ops.state, stateBefore);
  assert.equal(ops.exchangeHistory.length, 0);
  assert.equal(ops.reloadCalls, 0);
});

test("post-reload admin permission drift triggers exact rollback", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  const ops = new MockOverlayOps(plan);
  ops.driftAdminAfterFirstReload = true;
  await assert.rejects(
    executeOverlayTransaction({
      approvedPlanSha256: computeApprovedOverlayPlanSha256(plan),
      ops,
      plan,
    }),
    (error) => {
      assert.match(error.message, /exact preimage was restored/u);
      assert.equal(error.receipt?.outcome, "rolled-back");
      return true;
    },
  );
  assert.equal(ops.exchangeHistory.length, 2);
  assert.equal(ops.reloadCalls, 2);
});

for (const [label, mutate] of [
  ["post-reload", (ops) => { ops.adminBodySha256AfterFirstReload = "b".repeat(64); }],
  ["post-health", (ops) => { ops.adminBodySha256AfterHealth = "b".repeat(64); }],
]) {
  test(`${label} adapted JSON digest drift triggers exact rollback`, async () => {
    const plan = makeIntegratedOverlayTestPlan();
    const ops = new MockOverlayOps(plan);
    mutate(ops);
    await assert.rejects(
      executeOverlayTransaction({
        approvedPlanSha256: computeApprovedOverlayPlanSha256(plan),
        ops,
        plan,
      }),
      (error) => {
        assert.match(error.message, /exact preimage was restored/u);
        assert.equal(error.receipt?.outcome, "rolled-back");
        return true;
      },
    );
    assert.equal(ops.exchangeHistory.length, 2);
    assert.equal(ops.reloadCalls, 2);
  });
}

test("adapted JSON with the wrong admin endpoint is rejected before exchange", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  const ops = new MockOverlayOps(plan);
  ops.adaptedJson = { admin: { listen: "127.0.0.1:2019" }, apps: {} };
  await assert.rejects(
    executeOverlayTransaction({
      approvedPlanSha256: computeApprovedOverlayPlanSha256(plan),
      ops,
      plan,
    }),
    /adapted Caddy JSON admin.listen/u,
  );
  assert.equal(ops.exchangeHistory.length, 0);
  assert.equal(ops.reloadCalls, 0);
});

for (const [label, mutate, expected] of [
  [
    "global logging sink",
    (adapted) => { adapted.logging = { logs: { default: { writer: { output: "file", filename: "/var/log/caddy.log" } } } }; },
    /global logging sink/u,
  ],
  [
    "server access log",
    (adapted) => { adapted.apps.http = { servers: { srv0: { logs: {}, routes: [] } } }; },
    /must not enable access logging/u,
  ],
]) {
  test(`adapted JSON rejects ${label} before exchange`, async () => {
    const plan = makeIntegratedOverlayTestPlan();
    const ops = new MockOverlayOps(plan);
    mutate(ops.adaptedJson);
    await assert.rejects(
      executeOverlayTransaction({
        approvedPlanSha256: computeApprovedOverlayPlanSha256(plan),
        ops,
        plan,
      }),
      expected,
    );
    assert.equal(ops.exchangeHistory.length, 0);
    assert.equal(ops.reloadCalls, 0);
  });
}

test("adapted JSON digest drift is rejected before exchange", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  const ops = new MockOverlayOps(plan);
  ops.adaptedJson = {
    admin: { listen: "unix//run/bitcoinpir-caddy-admin/admin.sock|0200" },
    apps: { http: {} },
  };
  await assert.rejects(
    executeOverlayTransaction({
      approvedPlanSha256: computeApprovedOverlayPlanSha256(plan),
      ops,
      plan,
    }),
    /adapted JSON drifted from the approved candidate/u,
  );
  assert.equal(ops.exchangeHistory.length, 0);
  assert.equal(ops.reloadCalls, 0);
});

test("an install exchange applied before helper error is re-synced and committed", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  const ops = new MockOverlayOps(plan);
  ops.failExchangeAfterApplyNumber = 1;
  const receipt = await executeOverlayTransaction({
    approvedPlanSha256: computeApprovedOverlayPlanSha256(plan),
    ops,
    plan,
  });
  assert.equal(receipt.outcome, "committed");
  assert.equal(ops.exchangeHistory.length, 1);
  assert.equal(ops.reloadCalls, 1);
});

test("a rollback exchange applied before helper error is re-synced and finalized", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  const ops = new MockOverlayOps(plan);
  ops.failHealthLane = "provider";
  ops.failExchangeAfterApplyNumber = 2;
  await assert.rejects(
    executeOverlayTransaction({
      approvedPlanSha256: computeApprovedOverlayPlanSha256(plan),
      ops,
      plan,
    }),
    (error) => {
      assert.equal(error.phase, "rolled-back");
      assert.equal(error.receipt.outcome, "rolled-back");
      return true;
    },
  );
  assert.equal(ops.exchangeHistory.length, 2);
  assert.equal(ops.reloadCalls, 2);
});

test("a receipt published before helper error is re-synced and remains committed", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  const ops = new MockOverlayOps(plan);
  ops.failReceiptAfterPublish = true;
  const receipt = await executeOverlayTransaction({
    approvedPlanSha256: computeApprovedOverlayPlanSha256(plan),
    ops,
    plan,
  });
  assert.equal(receipt.outcome, "committed");
  assert.equal(ops.files.has(plan.transaction.receipt_pending_path), false);
  assert.equal(ops.files.has(plan.transaction.receipt_path), true);
});

test("a visible receipt with unprovable parent fsync is not treated as durable", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  const ops = new MockOverlayOps(plan);
  ops.failReceiptAfterPublish = true;
  ops.failFsyncParentPathSuffix = plan.transaction.receipt_path;
  await assert.rejects(
    executeOverlayTransaction({
      approvedPlanSha256: computeApprovedOverlayPlanSha256(plan),
      ops,
      plan,
    }),
    (error) => {
      assert.equal(error.name, "OverlayOutcomeUnknownError");
      assert.match(error.message, /terminal receipt publication outcome is unknown/);
      return true;
    },
  );
  assert.equal(ops.files.has(plan.transaction.receipt_path), true);
  assert.equal(ops.files.has(plan.transaction.candidate_path), true);
  assert.equal(ops.state.has(OVERLAY_STATE_FILES.committed), false);
  assert.equal(ops.state.has(OVERLAY_STATE_FILES.rolledBack), false);
  assert.equal(ops.exchangeHistory.length, 1);
  assert.equal(ops.reloadCalls, 1);
});

test("prepared publication with unprovable parent durability preserves its candidate", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  const ops = new MockOverlayOps(plan);
  ops.failFsyncParentAlways = true;
  await assert.rejects(
    executeOverlayTransaction({
      approvedPlanSha256: computeApprovedOverlayPlanSha256(plan),
      ops,
      plan,
    }),
    (error) => {
      assert.equal(error.name, "OverlayOutcomeUnknownError");
      assert.match(error.message, /phase prepared publication outcome is unknown/);
      return true;
    },
  );
  assert.equal(ops.files.has(plan.transaction.candidate_path), true);
  assert.equal(ops.exchangeHistory.length, 0);
  assert.equal(ops.state.has(OVERLAY_STATE_FILES.aborted), false);
});

test("abort-finalization uncertainty preserves the initiating error and candidate", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  const ops = new MockOverlayOps(plan);
  ops.failExchangeBeforeApplyNumber = 1;
  ops.failStateAfterPublishPhase = "aborted-before-install";
  ops.failFsyncParentPathSuffix = OVERLAY_STATE_FILES.aborted;
  await assert.rejects(
    executeOverlayTransaction({
      approvedPlanSha256: computeApprovedOverlayPlanSha256(plan),
      ops,
      plan,
    }),
    (error) => {
      assert.equal(error.phase, "install-exchange-not-applied");
      assert.match(error.message, /did not apply the exchange/);
      assert.equal(error.abortFinalizationError?.name, "OverlayOutcomeUnknownError");
      return true;
    },
  );
  assert.equal(ops.files.has(plan.transaction.candidate_path), true);
  assert.equal(ops.exchangeHistory.length, 0);
  assert.equal(ops.reloadCalls, 0);
});

test("a fail-before-publish exchanged phase defers rollback to idempotent recovery", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  const ops = new MockOverlayOps(plan);
  const approvedPlanSha256 = computeApprovedOverlayPlanSha256(plan);
  ops.failStateBeforePublishPhase = "exchanged";

  await assert.rejects(
    executeOverlayTransaction({ approvedPlanSha256, ops, plan }),
    (error) => {
      assert.equal(error.name, "OverlayOutcomeUnknownError");
      assert.match(error.message, /installed Caddyfile pair has no durable exchanged phase/);
      return true;
    },
  );

  assert.equal(ops.exchangeHistory.length, 1);
  assert.equal(ops.reloadCalls, 0);
  assert.equal(ops.state.has(OVERLAY_STATE_FILES.prepared), true);
  assert.equal(ops.state.has(OVERLAY_STATE_FILES.exchanged), false);
  assert.equal(ops.files.has(plan.transaction.candidate_path), true);
  assert.equal(ops.files.has(plan.transaction.receipt_path), false);
  assert.equal(
    ops.files.get("/etc/caddy/Caddyfile").snapshot.sha256,
    plan.managed_block.candidate_sha256,
  );

  for (let attempt = 1; attempt <= 3; attempt += 1) {
    const receipt = await recoverOverlayTransaction({ approvedPlanSha256, ops, plan });
    assert.equal(receipt.outcome, "rolled-back", `attempt ${attempt}`);
  }
  assert.equal(ops.exchangeHistory.length, 2);
  assert.equal(ops.reloadCalls, 1);
  assert.equal(ops.state.has(OVERLAY_STATE_FILES.exchanged), true);
  assert.equal(ops.state.has(OVERLAY_STATE_FILES.rollbackExchanged), true);
  assert.equal(ops.state.has(OVERLAY_STATE_FILES.rolledBack), true);
  assert.equal(ops.files.has(plan.transaction.candidate_path), false);
});

test("a fail-before-publish abort phase preserves its candidate for idempotent recovery", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  const ops = new MockOverlayOps(plan);
  const approvedPlanSha256 = computeApprovedOverlayPlanSha256(plan);
  ops.failExchangeBeforeApplyNumber = 1;
  ops.failStateBeforePublishPhase = "aborted-before-install";

  await assert.rejects(
    executeOverlayTransaction({ approvedPlanSha256, ops, plan }),
    (error) => {
      assert.equal(error.phase, "install-exchange-not-applied");
      assert.match(error.abortFinalizationError?.message ?? "", /failed before publish/);
      return true;
    },
  );

  assert.equal(ops.exchangeHistory.length, 0);
  assert.equal(ops.reloadCalls, 0);
  assert.equal(ops.state.has(OVERLAY_STATE_FILES.prepared), true);
  assert.equal(ops.state.has(OVERLAY_STATE_FILES.aborted), false);
  assert.equal(ops.files.has(plan.transaction.candidate_path), true);

  for (let attempt = 1; attempt <= 3; attempt += 1) {
    const result = await recoverOverlayTransaction({ approvedPlanSha256, ops, plan });
    assert.equal(result.outcome, "aborted-before-install", `attempt ${attempt}`);
  }
  assert.equal(ops.state.has(OVERLAY_STATE_FILES.aborted), true);
  assert.equal(ops.files.has(plan.transaction.candidate_path), false);
  assert.equal(ops.reloadCalls, 0);
});

test("a candidate cleanup failure remains attached to the initiating error", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  const ops = new MockOverlayOps(plan);
  const approvedPlanSha256 = computeApprovedOverlayPlanSha256(plan);
  ops.failExchangeBeforeApplyNumber = 1;
  ops.failRemovePath = plan.transaction.candidate_path;

  await assert.rejects(
    executeOverlayTransaction({ approvedPlanSha256, ops, plan }),
    (error) => {
      assert.equal(error.phase, "install-exchange-not-applied");
      assert.equal(error.cleanupErrors?.length, 1);
      assert.match(error.cleanupErrors[0].message, /mock exact removal failed/);
      return true;
    },
  );
  assert.equal(ops.state.has(OVERLAY_STATE_FILES.aborted), true);
  assert.equal(ops.files.has(plan.transaction.candidate_path), true);

  const result = await recoverOverlayTransaction({ approvedPlanSha256, ops, plan });
  assert.equal(result.outcome, "aborted-before-install");
  assert.equal(ops.files.has(plan.transaction.candidate_path), false);
});

test("a wrapped pre-install error retains its candidate cleanup failure", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  const ops = new MockOverlayOps(plan);
  const approvedPlanSha256 = computeApprovedOverlayPlanSha256(plan);
  ops.failStateBeforePublishPhase = "prepared";
  ops.failRemovePath = plan.transaction.candidate_path;

  await assert.rejects(
    executeOverlayTransaction({ approvedPlanSha256, ops, plan }),
    (error) => {
      assert.equal(error.phase, "pre-install");
      assert.equal(error.cleanupErrors?.length, 1);
      assert.match(error.cleanupErrors[0].message, /mock exact removal failed/);
      return true;
    },
  );
  assert.equal(ops.state.size, 0);
  assert.equal(ops.files.has(plan.transaction.candidate_path), true);

  const result = await recoverOverlayTransaction({ approvedPlanSha256, ops, plan });
  assert.equal(result.outcome, "aborted-before-install");
  assert.equal(ops.files.has(plan.transaction.candidate_path), false);
});

test("a durable committed receipt remains attached when terminal state durability is unknown", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  const ops = new MockOverlayOps(plan);
  const approvedPlanSha256 = computeApprovedOverlayPlanSha256(plan);
  ops.failStateAfterPublishPhase = "committed";
  ops.failFsyncParentPathSuffix = OVERLAY_STATE_FILES.committed;

  await assert.rejects(
    executeOverlayTransaction({ approvedPlanSha256, ops, plan }),
    (error) => {
      assert.equal(error.phase, "commit-finalization-failed");
      assert.equal(error.receipt?.outcome, "committed");
      assert.equal(error.cause?.name, "OverlayOutcomeUnknownError");
      return true;
    },
  );
  assert.equal(ops.exchangeHistory.length, 1);
  assert.equal(ops.reloadCalls, 1);
  assert.equal(ops.files.has(plan.transaction.candidate_path), true);
  assert.equal(ops.files.has(plan.transaction.receipt_path), true);
  assert.equal(ops.state.has(OVERLAY_STATE_FILES.rolledBack), false);

  ops.failStateAfterPublishPhase = null;
  ops.failFsyncParentPathSuffix = null;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    const receipt = await recoverOverlayTransaction({ approvedPlanSha256, ops, plan });
    assert.equal(receipt.outcome, "committed", `attempt ${attempt}`);
  }
  assert.equal(ops.exchangeHistory.length, 1);
  assert.equal(ops.reloadCalls, 1);
  assert.equal(ops.files.has(plan.transaction.candidate_path), false);
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
      assert.match(error.primaryError.message, /mock health failed/);
      return true;
    },
  );
  assert.equal(ops.files.get("/etc/caddy/Caddyfile").snapshot.sha256, plan.target.config_preimage.sha256);
  assert.equal(ops.files.has(plan.transaction.candidate_path), false);
  assert.equal(ops.reloadCalls, 2);
});

test("an unknown install pair stops without compensating exchange, cleanup or reload", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  const ops = new MockOverlayOps(plan);
  ops.raceTargetBeforeFirstExchange = true;
  const approvedPlanSha256 = computeApprovedOverlayPlanSha256(plan);
  await assert.rejects(
    executeOverlayTransaction({ approvedPlanSha256, ops, plan }),
    (error) => {
      assert.equal(error.name, "OverlayOutcomeUnknownError");
      assert.match(error.message, /refusing rollback, terminal receipt and cleanup/);
      return true;
    },
  );
  assert.equal(ops.exchangeHistory.length, 1);
  assert.equal(ops.files.has(plan.transaction.candidate_path), true);
  assert.equal(ops.state.has(OVERLAY_STATE_FILES.aborted), false);
  assert.equal(ops.reloadCalls, 0);
});

test("an unknown rollback pair stops without compensation, receipt or cleanup", async () => {
  const plan = makeIntegratedOverlayTestPlan();
  const ops = new MockOverlayOps(plan);
  ops.failHealthLane = "provider";
  ops.raceTargetBeforeExchangeNumber = 2;
  const approvedPlanSha256 = computeApprovedOverlayPlanSha256(plan);
  await assert.rejects(
    executeOverlayTransaction({ approvedPlanSha256, ops, plan }),
    (error) => {
      assert.equal(error.name, "OverlayOutcomeUnknownError");
      assert.match(error.message, /refusing rollback, terminal receipt and cleanup/);
      return true;
    },
  );
  assert.equal(ops.exchangeHistory.length, 2);
  assert.equal(ops.files.has(plan.transaction.candidate_path), true);
  assert.equal(ops.files.has(plan.transaction.receipt_path), false);
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

test("aborted rolled-back-pair recovery rejects a currently loaded candidate", async () => {
  const baseline = await successfulBaseline();
  const ops = recoveryOpsFromBaseline(baseline, {
    pair: "rolled-back",
    phases: [OVERLAY_STATE_FILES.prepared],
  });
  ops.adminBodySha256Override = baseline.plan.managed_block.candidate_adapted_json_sha256;
  await assert.rejects(
    recoverOverlayTransaction({
      approvedPlanSha256: baseline.approvedPlanSha256,
      ops,
      plan: baseline.plan,
    }),
    /does not equal the reviewed active adapted JSON/u,
  );
  assert.equal(ops.files.has(baseline.plan.transaction.candidate_path), true);
  assert.equal(ops.reloadCalls, 0);
});

test("aborted preimage-only recovery rejects a currently loaded candidate", async () => {
  const baseline = await successfulBaseline();
  const ops = recoveryOpsFromBaseline(baseline, {
    pair: "rolled-back",
    phases: [],
  });
  ops.files.delete(baseline.plan.transaction.candidate_path);
  ops.adminBodySha256Override = baseline.plan.managed_block.candidate_adapted_json_sha256;
  await assert.rejects(
    recoverOverlayTransaction({
      approvedPlanSha256: baseline.approvedPlanSha256,
      ops,
      plan: baseline.plan,
    }),
    /does not equal the reviewed active adapted JSON/u,
  );
  assert.equal(ops.state.has(OVERLAY_STATE_FILES.aborted), false);
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

test("durable committed recovery rejects a currently loaded reviewed preimage", async () => {
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
  ops.adminBodySha256Override =
    baseline.plan.target.admin_uds_hardening.adapted_json_sha256;
  await assert.rejects(
    recoverOverlayTransaction({
      approvedPlanSha256: baseline.approvedPlanSha256,
      ops,
      plan: baseline.plan,
    }),
    /does not equal the reviewed active adapted JSON/u,
  );
  assert.equal(ops.reloadCalls, 0);
  assert.equal(ops.files.has(baseline.plan.transaction.candidate_path), true);
  assert.equal(ops.state.has(OVERLAY_STATE_FILES.committed), false);
});

test("durable rolled-back recovery rejects a currently loaded reviewed candidate", async () => {
  const baseline = await rolledBackBaseline();
  const ops = recoveryOpsFromBaseline(baseline, {
    pair: "rolled-back",
    phases: [
      OVERLAY_STATE_FILES.prepared,
      OVERLAY_STATE_FILES.exchanged,
      OVERLAY_STATE_FILES.reloaded,
      OVERLAY_STATE_FILES.rollbackExchanged,
      OVERLAY_STATE_FILES.rollbackReloaded,
    ],
    receipt: baseline.receipt,
  });
  ops.adminBodySha256Override = baseline.plan.managed_block.candidate_adapted_json_sha256;
  await assert.rejects(
    recoverOverlayTransaction({
      approvedPlanSha256: baseline.approvedPlanSha256,
      ops,
      plan: baseline.plan,
    }),
    /does not equal the reviewed active adapted JSON/u,
  );
  assert.equal(ops.reloadCalls, 0);
  assert.equal(ops.files.has(baseline.plan.transaction.candidate_path), true);
  assert.equal(ops.state.has(OVERLAY_STATE_FILES.rolledBack), false);
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

test("valid pending prepared state publishes once and second/third recovery stay idempotent", async () => {
  const baseline = await successfulBaseline();
  const ops = recoveryOpsFromBaseline(baseline, {
    pair: "rolled-back",
    phases: [],
  });
  seedStatePending(
    ops,
    baseline.plan,
    OVERLAY_STATE_FILES.prepared,
    baseline.ops.state.get(OVERLAY_STATE_FILES.prepared),
  );
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    const result = await recoverOverlayTransaction({
      approvedPlanSha256: baseline.approvedPlanSha256,
      ops,
      plan: baseline.plan,
    });
    assert.equal(result.outcome, "aborted-before-install", `attempt ${attempt}`);
  }
  assert.equal(ops.state.has(`${OVERLAY_STATE_FILES.prepared}.pending`), false);
  assert.equal(ops.state.has(OVERLAY_STATE_FILES.prepared), true);
  assert.equal(ops.state.has(OVERLAY_STATE_FILES.aborted), true);
  assert.equal(ops.reloadCalls, 0);
});

test("truncated pending prepared state is non-authoritative across three recoveries", async () => {
  const baseline = await successfulBaseline();
  const ops = recoveryOpsFromBaseline(baseline, {
    pair: "rolled-back",
    phases: [],
  });
  seedStatePending(
    ops,
    baseline.plan,
    OVERLAY_STATE_FILES.prepared,
    Buffer.from('{"schema_version":'),
  );
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    const result = await recoverOverlayTransaction({
      approvedPlanSha256: baseline.approvedPlanSha256,
      ops,
      plan: baseline.plan,
    });
    assert.equal(result.outcome, "aborted-before-install", `attempt ${attempt}`);
  }
  assert.equal(ops.state.size, 0);
  assert.equal(ops.reloadCalls, 0);
});

test("rolled-back terminal recovery is stable on second and third invocation", async () => {
  const baseline = await successfulBaseline();
  const ops = recoveryOpsFromBaseline(baseline, {
    pair: "installed",
    phases: [OVERLAY_STATE_FILES.prepared],
  });
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    const receipt = await recoverOverlayTransaction({
      approvedPlanSha256: baseline.approvedPlanSha256,
      ops,
      plan: baseline.plan,
    });
    assert.equal(receipt.outcome, "rolled-back", `attempt ${attempt}`);
  }
  assert.equal(ops.exchangeHistory.length, 1);
  assert.equal(ops.reloadCalls, 1);
});

test("recovery rejects mutable transaction parent identity drift before file-pair mutation", async () => {
  const baseline = await successfulBaseline();
  const ops = recoveryOpsFromBaseline(baseline, {
    pair: "installed",
    phases: [OVERLAY_STATE_FILES.prepared],
  });
  const receiptParent = baseline.plan.transaction.receipt_path.slice(
    0,
    baseline.plan.transaction.receipt_path.lastIndexOf("/"),
  );
  ops.mutableDirectories.get(receiptParent).inode = "999999";
  await assert.rejects(
    recoverOverlayTransaction({
      approvedPlanSha256: baseline.approvedPlanSha256,
      ops,
      plan: baseline.plan,
    }),
    /changed across crash recovery/,
  );
  assert.equal(ops.exchangeHistory.length, 0);
  assert.equal(ops.reloadCalls, 0);
});

test("recovery rejects a final receipt with wrong owner metadata", async () => {
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
  ops.files.get(baseline.plan.transaction.receipt_path).snapshot.uid = 1000;
  await assert.rejects(
    recoverOverlayTransaction({
      approvedPlanSha256: baseline.approvedPlanSha256,
      ops,
      plan: baseline.plan,
    }),
    /final receipt is not one root-owned owner-only single-link record/,
  );
  assert.equal(ops.exchangeHistory.length, 0);
  assert.equal(ops.reloadCalls, 0);
});

test("recovery treats a visible final receipt with failed parent fsync as outcome-unknown", async () => {
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
  ops.failFsyncParentPathSuffix = baseline.plan.transaction.receipt_path;
  await assert.rejects(
    recoverOverlayTransaction({
      approvedPlanSha256: baseline.approvedPlanSha256,
      ops,
      plan: baseline.plan,
    }),
    (error) => {
      assert.equal(error.name, "OverlayOutcomeUnknownError");
      assert.match(error.message, /final receipt durability is unknown/);
      return true;
    },
  );
  assert.equal(ops.exchangeHistory.length, 0);
  assert.equal(ops.reloadCalls, 0);
  assert.equal(ops.files.has(baseline.plan.transaction.candidate_path), true);
});

test("recovery makes visible phase records durable before they can authorize mutation", async () => {
  const baseline = await successfulBaseline();
  const ops = recoveryOpsFromBaseline(baseline, {
    pair: "installed",
    phases: [
      OVERLAY_STATE_FILES.prepared,
      OVERLAY_STATE_FILES.exchanged,
      OVERLAY_STATE_FILES.reloaded,
    ],
  });
  ops.failFsyncParentPathSuffix = "/.journal-durability";
  await assert.rejects(
    recoverOverlayTransaction({
      approvedPlanSha256: baseline.approvedPlanSha256,
      ops,
      plan: baseline.plan,
    }),
    (error) => {
      assert.equal(error.name, "OverlayOutcomeUnknownError");
      assert.match(error.message, /phase journal durability is unknown/);
      return true;
    },
  );
  assert.equal(ops.exchangeHistory.length, 0);
  assert.equal(ops.reloadCalls, 0);
  assert.equal(ops.files.has(baseline.plan.transaction.candidate_path), true);
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
  // Model a still-loaded reviewed candidate while the on-disk pair has been
  // replaced externally; recovery must still reject the unknown file pair.
  ops.adminBodySha256Override = baseline.plan.managed_block.candidate_adapted_json_sha256;
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
