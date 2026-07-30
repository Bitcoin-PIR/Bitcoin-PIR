import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  ADMIN_DIRECTORY,
  ADMIN_LISTEN,
  ADMIN_SOCKET,
  CADDY_BINARY_PATH,
  TARGET_CONFIG,
  TARGET_FRAGMENT,
  canonicalJson,
  computeApprovedPlanSha256,
  sha256,
} from "./payment-v1-caddy-admin-uds-gate.mjs";
import {
  CADDY_ADMIN_UDS_TEST_ONLY_IO,
  COLD_OUTCOMES,
  ColdOutcomeUnknownError,
  ColdTransactionError,
  executeCaddyAdminUdsTransaction,
  parseSystemdVersionOutput,
  validateSiteInventory,
} from "./payment-v1-caddy-admin-uds-transaction.mjs";
import { makeHardeningEvidence } from "./payment-v1-integrated-caddy-overlay-test-fixture.mjs";

function canonicalBytes(value) {
  return Buffer.from(canonicalJson(value), "utf8");
}

function siteInventory() {
  return {
    probes: [
      {
        address: "127.0.0.1",
        expected_body_sha256: "1".repeat(64),
        expected_status: 200,
        host_header: "upstream.example.net",
        id: "direct-upstream",
        kind: "direct-http",
        path: "/health",
        port: 18080,
      },
      {
        expected_body_sha256: "2".repeat(64),
        expected_leaf_sha256: "3".repeat(64),
        expected_status: 200,
        hostname: "public.example.net",
        id: "public-site",
        kind: "public-https",
        path: "/health",
        port: 443,
      },
      {
        address: "public.example.net",
        expected_leaf_sha256: "3".repeat(64),
        id: "tls-site",
        kind: "tls-handshake",
        port: 443,
        server_name: "public.example.net",
      },
    ],
    schema_version: 1,
  };
}

function fullSnapshot(pin, path = pin.path, seed = "90001") {
  return {
    ...pin,
    ctime_ns: "1700000001000000000",
    device: "2049",
    inode: seed,
    mtime_ns: "1700000001000000000",
    nlink: 1,
    path,
  };
}

function stoppedGeneration() {
  return {
    active_enter_timestamp_monotonic: "0",
    active_state: "inactive",
    control_group: "/system.slice/bhtm-caddy.service",
    invocation_id: "",
    main_pid: "0",
    sub_state: "dead",
    unit_name: "bhtm-caddy.service",
  };
}

function activeGeneration({ invocation, pid, timestamp }) {
  return {
    active_enter_timestamp_monotonic: timestamp,
    active_state: "active",
    control_group: "/system.slice/bhtm-caddy.service",
    invocation_id: invocation,
    main_pid: pid,
    sub_state: "running",
    unit_name: "bhtm-caddy.service",
  };
}

function makePlanAndInventory() {
  const evidence = makeHardeningEvidence(activeGeneration({
    invocation: "32345678123442349234123456789abe",
    pid: "4444",
    timestamp: "2000000",
  }));
  const inventory = siteInventory();
  const inventoryBytes = canonicalBytes(inventory);
  evidence.plan.site_preservation.existing_site_inventory_sha256 = sha256(inventoryBytes);
  evidence.plan.site_preservation.probe_ids = inventory.probes.map(({ id }) => id);
  return {
    ...evidence,
    approvedPlanSha256: computeApprovedPlanSha256(evidence.plan),
    inventory,
    inventoryBytes,
  };
}

function fakeOps(fixture, { failAt } = {}) {
  const { plan } = fixture;
  const files = new Map();
  const states = new Map();
  const calls = [];
  let generation = structuredClone(plan.preimage.unit_generation);
  let hardened = false;
  let locked = false;
  let released = false;
  const pendingFaults = new Set(Array.isArray(failAt) ? failAt : [failAt].filter(Boolean));
  let inode = 91000;
  const fault = (point) => {
    if (pendingFaults.delete(point)) {
      throw new Error(`injected ${point}`);
    }
  };
  const add = (path, bytes, snapshot) => {
    files.set(path, { bytes: Buffer.from(bytes), snapshot: structuredClone(snapshot) });
  };
  add(TARGET_CONFIG, fixture.configPreimage, plan.preimage.config);
  add(TARGET_FRAGMENT, fixture.unitPreimage, plan.preimage.unit);
  add(CADDY_BINARY_PATH, Buffer.from("binary"), plan.preimage.binary);
  for (const pin of [
    plan.runtime.executor,
    plan.runtime.gate,
    plan.runtime.node_binary,
    plan.runtime.probe,
    plan.runtime.setpriv_binary,
  ]) add(pin.path, Buffer.from(pin.path), pin);

  const oldAdmin = {
    body_sha256: plan.preimage.adapted_json_sha256,
    listen: "127.0.0.1:2019",
    status: 200,
    transport: "tcp",
  };
  const cloneFile = (entry) => ({
    bytes: Buffer.from(entry.bytes),
    snapshot: structuredClone(entry.snapshot),
  });
  const putContent = (path, bytes, pin, mode = pin.mode) => {
    inode += 1;
    const snapshot = fullSnapshot({
      gid: 0,
      mode,
      path,
      sha256: sha256(bytes),
      size: String(bytes.length),
      uid: 0,
    }, path, String(inode));
    add(path, bytes, snapshot);
    return cloneFile(files.get(path));
  };
  const processRuntime = () => ({
    caddy_admin_environment_absent: hardened,
    cmdline_argv: hardened
      ? [CADDY_BINARY_PATH, "run", "--config", TARGET_CONFIG, "--adapter", "caddyfile"]
      : [CADDY_BINARY_PATH, "run", "--environ", "--config", TARGET_CONFIG, "--adapter", "caddyfile"],
    effective_environment_names: hardened ? ["PATH"] : ["CADDY_ADMIN", "PATH"],
    exe_path: CADDY_BINARY_PATH,
    exe_snapshot: structuredClone(plan.preimage.binary),
    main_pid: generation.main_pid,
    start_time_ticks: hardened ? "888888" : "777777",
  });
  const ops = {
    calls,
    files,
    get locked() { return locked; },
    get released() { return released; },
    states,
    async acquireLock() {
      calls.push("lock");
      if (locked) throw new Error("lock busy");
      locked = true;
      return async () => {
        calls.push("unlock");
        fault("unlock");
        locked = false;
        released = true;
      };
    },
    async binaryVersion() { return "v2.11.4"; },
    async collectStoppedEvidence() {
      fault("stopped-evidence");
      return {
        admin_socket_absent: true,
        tcp_admin: [
          { endpoint: "127.0.0.1:2019", result: "connection-refused" },
          { endpoint: "[::1]:2019", result: "connection-refused" },
        ],
        unit_generation: structuredClone(generation),
        unit_job_absent: true,
      };
    },
    async hostIdentity() {
      return { boot_id: plan.privileged_access_inventory.boot_id, hostname: "fixture.invalid" };
    },
    async hostPrerequisites() {
      return { core_pattern: "|/usr/bin/false", euid: 0, platform: "linux", systemd_version: "255" };
    },
    async prepareArtifact(path, bytes, mode) {
      calls.push(`prepare:${path}`);
      fault(`prepare:${path}`);
      if (files.has(path)) throw new Error(`exclusive path exists: ${path}`);
      return putContent(path, bytes, { mode }, mode);
    },
    async probeAdminApi({ expected, label, uid }) {
      calls.push(`admin:${label}`);
      fault(`admin:${label}`);
      return expected === "root-readback"
        ? {
            body_sha256: plan.candidate.adapted_json_sha256,
            cap_eff: "0000000000000000",
            error: null,
            gid: 0,
            groups: [0],
            label,
            listen: ADMIN_LISTEN,
            path: "/config/",
            status: 200,
            transport: "unix",
            uid: 0,
          }
        : {
            body_sha256: null,
            cap_eff: "0000000000000000",
            error: "EACCES",
            gid: uid,
            groups: [uid],
            label,
            listen: null,
            path: "/config/",
            status: null,
            transport: "unix",
            uid,
          };
    },
    async probeLegacyAdmin() {
      calls.push("legacy-admin");
      fault("legacy-admin");
      return structuredClone(oldAdmin);
    },
    async probeTcpAdmin() {
      return [
        { endpoint: "127.0.0.1:2019", result: "connection-refused" },
        { endpoint: "[::1]:2019", result: "connection-refused" },
      ];
    },
    async publishReceipt(path, bytes, mode) {
      calls.push("publish-receipt");
      fault("publish-receipt");
      if (files.has(path)) throw new Error("receipt already exists");
      return putContent(path, bytes, { mode }, mode);
    },
    async publishState(_directory, name, bytes, mode) {
      calls.push(`state:${name}`);
      fault(`state:${name}`);
      if (states.has(name)) throw new Error(`state exists: ${name}`);
      states.set(name, { bytes: Buffer.from(bytes), mode });
    },
    async readAdminRuntimePath(path) {
      return path === ADMIN_DIRECTORY
        ? { gid: 0, mode: "0700", path, type: "directory", uid: 0 }
        : { gid: 0, mode: "0200", path: ADMIN_SOCKET, type: "socket", uid: 0 };
    },
    async readEffectiveUnit() {
      return {
        dropin_paths: [],
        effective_environment_names: ["PATH"],
        fragment_path: TARGET_FRAGMENT,
        need_daemon_reload: "no",
        properties: {
          Group: "root",
          LimitCORE: "0",
          MemorySwapMax: "0",
          RuntimeDirectory: "bitcoinpir-caddy-admin",
          RuntimeDirectoryMode: "0700",
          RuntimeDirectoryPreserve: "no",
          StandardError: "null",
          StandardOutput: "null",
          UMask: "0077",
          UnsetEnvironment: ["CADDY_ADMIN"],
          User: "root",
        },
      };
    },
    async readPreimageEffectiveUnit() {
      fault("preimage-effective-unit");
      return {
        dropin_paths: [],
        environment_files: [],
        exec_reload: {
          argv: `${CADDY_BINARY_PATH} reload --config ${TARGET_CONFIG} --adapter caddyfile --force`,
          ignore_errors: "no",
          path: CADDY_BINARY_PATH,
        },
        exec_start: {
          argv: `${CADDY_BINARY_PATH} run --environ --config ${TARGET_CONFIG} --adapter caddyfile`,
          ignore_errors: "no",
          path: CADDY_BINARY_PATH,
        },
        fragment_path: TARGET_FRAGMENT,
        need_daemon_reload: "no",
        pass_environment: [],
      };
    },
    async readProcessRuntime() { return processRuntime(); },
    async readRegular(path) {
      const value = files.get(path);
      if (value === undefined) throw Object.assign(new Error(`missing ${path}`), { code: "ENOENT" });
      return cloneFile(value);
    },
    async readUnitGeneration() { return structuredClone(generation); },
    async recoverySnapshot() {
      return {
        pair: files.has(TARGET_CONFIG) && files.has(TARGET_FRAGMENT) ? "collected" : "missing",
        unit_generation: structuredClone(generation),
      };
    },
    async replacePrepared({ pin, preparedPath, targetPath }) {
      calls.push(`replace:${targetPath}`);
      fault(targetPath === TARGET_CONFIG ? "replace-config" : "replace-unit");
      const prepared = files.get(preparedPath);
      if (prepared === undefined) throw new Error("prepared file missing");
      files.delete(preparedPath);
      putContent(targetPath, prepared.bytes, pin);
    },
    async restoreFromBackup({ backupPath, pin, targetPath }) {
      calls.push(`restore:${targetPath}`);
      const backup = files.get(backupPath);
      if (backup === undefined) throw new Error("backup missing");
      putContent(targetPath, backup.bytes, pin);
    },
    async selfIdentity() {
      const nodeCmdlineArgv = [
        plan.runtime.node_binary.path,
        plan.runtime.executor.path,
        "execute",
        "--plan",
        "/private/plan.json",
        "--site-inventory",
        "/private/site-inventory.json",
        "--approved-plan-sha256",
        fixture.approvedPlanSha256,
      ];
      return {
        executor_path: plan.runtime.executor.path,
        executor_snapshot: structuredClone(plan.runtime.executor),
        node_cmdline_argv: nodeCmdlineArgv,
        node_control_environment_names: [],
        node_exec_argv: [],
        node_proc_exe_path: plan.runtime.node_binary.path,
        node_proc_exe_snapshot: structuredClone(plan.runtime.node_binary),
        node_process_argv: structuredClone(nodeCmdlineArgv),
        node_process_exec_path: plan.runtime.node_binary.path,
        node_version: plan.runtime.node_version,
      };
    },
    async run(argv) {
      const command = argv[1];
      calls.push(`run:${command}`);
      fault(`run:${command}`);
      if (command === "stop") generation = stoppedGeneration();
      if (command === "start") {
        const config = files.get(TARGET_CONFIG);
        hardened = config?.snapshot.sha256 === plan.candidate.config.sha256;
        generation = activeGeneration({
          invocation: hardened
            ? "32345678123442349234123456789abe"
            : "42345678123442349234123456789abf",
          pid: hardened ? "4444" : "5555",
          timestamp: hardened ? "2000000" : "3000000",
        });
      }
      return { status: 0, stderr: Buffer.alloc(0), stdout: Buffer.alloc(0) };
    },
    async runSiteProbe(probe, phase) {
      calls.push(`site:${phase}:${probe.id}`);
      fault(`site:${phase}:${probe.id}`);
      return { id: probe.id, result: "passed" };
    },
    async verifyCandidate() {
      calls.push("verify-candidate");
      fault("verify-candidate");
      return Buffer.from(fixture.candidateAdaptedJson);
    },
    async verifyPreimage() {
      calls.push("verify-preimage");
      fault("verify-preimage");
      return Buffer.from(canonicalJson({
        admin: { listen: "127.0.0.1:2019" },
        apps: {},
      }));
    },
  };
  return ops;
}

test("site inventory is canonical, plan-bound and covers public/direct/TLS probes", () => {
  const fixture = makePlanAndInventory();
  assert.equal(
    validateSiteInventory({ bytes: fixture.inventoryBytes, plan: fixture.plan }).probes.length,
    3,
  );
  const reordered = structuredClone(fixture.inventory);
  reordered.probes.reverse();
  const reorderedBytes = canonicalBytes(reordered);
  const reorderedPlan = structuredClone(fixture.plan);
  reorderedPlan.site_preservation.existing_site_inventory_sha256 = sha256(reorderedBytes);
  assert.throws(
    () => validateSiteInventory({ bytes: reorderedBytes, plan: reorderedPlan }),
    /sorted and unique/u,
  );
  const missingTls = structuredClone(fixture.inventory);
  missingTls.probes = missingTls.probes.filter(({ kind }) => kind !== "tls-handshake");
  const missingBytes = canonicalBytes(missingTls);
  const missingPlan = structuredClone(fixture.plan);
  missingPlan.site_preservation.existing_site_inventory_sha256 = sha256(missingBytes);
  missingPlan.site_preservation.probe_ids = missingTls.probes.map(({ id }) => id);
  assert.throws(
    () => validateSiteInventory({ bytes: missingBytes, plan: missingPlan }),
    /3\.\.128|tls-handshake/u,
  );
});

test("legacy readback accepts only explicit loopback admin or the proven implicit default", () => {
  assert.equal(CADDY_ADMIN_UDS_TEST_ONLY_IO.validateLegacyAdminAdaptedJson({ apps: {} }), true);
  assert.equal(CADDY_ADMIN_UDS_TEST_ONLY_IO.validateLegacyAdminAdaptedJson({
    admin: { listen: "127.0.0.1:2019" },
    apps: {},
  }), true);
  assert.throws(
    () => CADDY_ADMIN_UDS_TEST_ONLY_IO.validateLegacyAdminAdaptedJson({
      admin: { listen: "0.0.0.0:2019" },
      apps: {},
    }),
    /admin\.listen/u,
  );
  assert.throws(
    () => CADDY_ADMIN_UDS_TEST_ONLY_IO.validateLegacyAdminAdaptedJson({
      apps: {},
      logging: {},
    }),
    /logging sink/u,
  );
});

test("systemd 255 preimage serialization binds the loaded unit to the disk profile", () => {
  assert.deepEqual(
    CADDY_ADMIN_UDS_TEST_ONLY_IO.normalizePreimageEffectiveUnitProperties({
      DropInPaths: "",
      EnvironmentFiles: "",
      ExecReload: "{ path=/usr/local/bin/caddy ; argv[]=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --force ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }",
      ExecStart: "{ path=/usr/local/bin/caddy ; argv[]=/usr/local/bin/caddy run --environ --config /etc/caddy/Caddyfile --adapter caddyfile ; ignore_errors=no ; start_time=[Wed 2026-06-24 17:19:40 CEST] ; stop_time=[n/a] ; pid=639667 ; code=(null) ; status=0/0 }",
      FragmentPath: TARGET_FRAGMENT,
      NeedDaemonReload: "no",
      PassEnvironment: "",
    }),
    {
      dropin_paths: [],
      environment_files: [],
      exec_reload: {
        argv: "/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --force",
        ignore_errors: "no",
        path: "/usr/local/bin/caddy",
      },
      exec_start: {
        argv: "/usr/local/bin/caddy run --environ --config /etc/caddy/Caddyfile --adapter caddyfile",
        ignore_errors: "no",
        path: "/usr/local/bin/caddy",
      },
      fragment_path: TARGET_FRAGMENT,
      need_daemon_reload: "no",
      pass_environment: [],
    },
  );
});

test("checked-in site-inventory skeleton stays canonical and aligned with the plan skeleton", () => {
  const inventoryText = readFileSync(new URL(
    "../docs/payment/render-plan-skeletons/bhtm-caddy-admin-uds-v1.site-inventory.json.example",
    import.meta.url,
  ), "utf8");
  const plan = JSON.parse(readFileSync(new URL(
    "../docs/payment/render-plan-skeletons/bhtm-caddy-admin-uds-v1.plan.json.example",
    import.meta.url,
  ), "utf8"));
  const inventory = JSON.parse(inventoryText);
  assert.equal(inventoryText, `${canonicalJson(inventory)}\n`);
  assert.deepEqual(
    inventory.probes.map(({ id }) => id),
    ["direct-upstream-health", "public-https-health", "public-tls-leaf"],
  );
  assert.deepEqual(
    [...new Set(inventory.probes.map(({ kind }) => kind))].sort(),
    ["direct-http", "public-https", "tls-handshake"],
  );
  assert.deepEqual(plan.site_preservation.probe_ids, inventory.probes.map(({ id }) => id));
});

test("complete cold transaction publishes a receipt only after every post-start proof", async () => {
  const fixture = makePlanAndInventory();
  const ops = fakeOps(fixture);
  const result = await executeCaddyAdminUdsTransaction({
    approvedPlanSha256: fixture.approvedPlanSha256,
    ops,
    plan: fixture.plan,
    siteInventoryBytes: fixture.inventoryBytes,
  });
  assert.equal(result.outcome, COLD_OUTCOMES.committed);
  assert.equal(result.receipt.outcome, "committed");
  assert.equal(ops.released, true);
  assert.equal(ops.locked, false);
  assert.ok(ops.calls.indexOf("publish-receipt") > ops.calls.indexOf("site:after:tls-site"));
  assert.ok(ops.calls.indexOf("publish-receipt") > ops.calls.indexOf("admin:pir"));
  assert.deepEqual(
    result.receipt.site_health.map(({ id }) => id),
    fixture.plan.site_preservation.probe_ids,
  );
});

test("pre-stop failure leaves the active pair and generation untouched", async () => {
  const fixture = makePlanAndInventory();
  const ops = fakeOps(fixture, { failAt: "verify-candidate" });
  await assert.rejects(
    executeCaddyAdminUdsTransaction({
      approvedPlanSha256: fixture.approvedPlanSha256,
      ops,
      plan: fixture.plan,
      siteInventoryBytes: fixture.inventoryBytes,
    }),
    (error) => {
      assert.ok(error instanceof ColdTransactionError);
      assert.equal(error.outcome, COLD_OUTCOMES.preStopFailed);
      return true;
    },
  );
  assert.equal(ops.files.get(TARGET_CONFIG).snapshot.sha256, fixture.plan.preimage.config.sha256);
  assert.equal(ops.files.get(TARGET_FRAGMENT).snapshot.sha256, fixture.plan.preimage.unit.sha256);
  assert.equal(ops.calls.includes("run:stop"), false);
  assert.equal(ops.calls.some((call) => call.startsWith("replace:")), false);
  assert.equal(ops.released, true);
});

test("unloaded or drifted disk unit and hot-loaded Caddy config fail before stop", async () => {
  for (const drift of [
    "need-daemon-reload",
    "fragment",
    "dropin",
    "environment-file",
    "pass-environment",
    "exec-start",
    "exec-reload",
    "hot-admin-config",
  ]) {
    const fixture = makePlanAndInventory();
    const ops = fakeOps(fixture);
    if (drift !== "hot-admin-config") {
      const original = ops.readPreimageEffectiveUnit;
      ops.readPreimageEffectiveUnit = async (...args) => {
        const value = await original(...args);
        if (drift === "need-daemon-reload") value.need_daemon_reload = "yes";
        if (drift === "fragment") value.fragment_path = "/run/systemd/transient/bhtm-caddy.service";
        if (drift === "dropin") value.dropin_paths = ["/run/systemd/system/bhtm-caddy.service.d/override.conf"];
        if (drift === "environment-file") value.environment_files = ["/etc/default/caddy"];
        if (drift === "pass-environment") value.pass_environment = ["CADDY_ADMIN"];
        if (drift === "exec-start") value.exec_start.argv = "/usr/bin/false";
        if (drift === "exec-reload") value.exec_reload.argv = "/usr/bin/false";
        return value;
      };
    } else {
      ops.probeLegacyAdmin = async () => ({
        body_sha256: "f".repeat(64),
        listen: "127.0.0.1:2019",
        status: 200,
        transport: "tcp",
      });
    }
    await assert.rejects(
      executeCaddyAdminUdsTransaction({
        approvedPlanSha256: fixture.approvedPlanSha256,
        ops,
        plan: fixture.plan,
        siteInventoryBytes: fixture.inventoryBytes,
      }),
      (error) => error instanceof ColdTransactionError && error.outcome === COLD_OUTCOMES.preStopFailed,
      drift,
    );
    assert.equal(ops.calls.includes("run:stop"), false, drift);
    assert.equal(ops.calls.some((call) => call.startsWith("replace:")), false, drift);
    assert.equal(ops.released, true, drift);
  }
});

test("disk preimage adapt output must match the approved canonical digest before stop", async () => {
  const fixture = makePlanAndInventory();
  const ops = fakeOps(fixture);
  ops.verifyPreimage = async () => Buffer.from(canonicalJson({
    admin: { listen: "127.0.0.1:2019" },
    apps: { http: { servers: { drifted: {} } } },
  }));
  await assert.rejects(
    executeCaddyAdminUdsTransaction({
      approvedPlanSha256: fixture.approvedPlanSha256,
      ops,
      plan: fixture.plan,
      siteInventoryBytes: fixture.inventoryBytes,
    }),
    (error) => error instanceof ColdTransactionError && error.outcome === COLD_OUTCOMES.preStopFailed,
  );
  assert.equal(ops.calls.includes("run:stop"), false);
  assert.equal(ops.released, true);
});

test("failed stop is outcome-unknown even while the old generation still appears active", async () => {
  const fixture = makePlanAndInventory();
  const ops = fakeOps(fixture, { failAt: "run:stop" });
  await assert.rejects(
    executeCaddyAdminUdsTransaction({
      approvedPlanSha256: fixture.approvedPlanSha256,
      ops,
      plan: fixture.plan,
      siteInventoryBytes: fixture.inventoryBytes,
    }),
    (error) => {
      assert.ok(error instanceof ColdOutcomeUnknownError);
      assert.equal(error.outcome, COLD_OUTCOMES.outcomeUnknown);
      assert.equal(error.phase, "stop-outcome-unknown-before-start");
      return true;
    },
  );
  assert.equal(ops.locked, true);
  assert.equal(ops.released, false);
});

test("failed stop with active-file side effects is outcome-unknown and retains the lock", async () => {
  const fixture = makePlanAndInventory();
  const ops = fakeOps(fixture, { failAt: "run:stop" });
  const originalRun = ops.run;
  ops.run = async (argv) => {
    try {
      return await originalRun(argv);
    } catch (error) {
      if (argv[1] === "stop") {
        ops.files.get(TARGET_CONFIG).snapshot.sha256 = "0".repeat(64);
      }
      throw error;
    }
  };
  await assert.rejects(
    executeCaddyAdminUdsTransaction({
      approvedPlanSha256: fixture.approvedPlanSha256,
      ops,
      plan: fixture.plan,
      siteInventoryBytes: fixture.inventoryBytes,
    }),
    (error) =>
      error instanceof ColdOutcomeUnknownError &&
      error.phase === "stop-outcome-unknown-before-start",
  );
  assert.equal(ops.states.has("40-recovery-required.json"), true);
  assert.equal(ops.locked, true);
  assert.equal(ops.released, false);
});

test("stopped mixed-pair failure restores both exact old preimages and verifies the old generation", async () => {
  const fixture = makePlanAndInventory();
  const ops = fakeOps(fixture, { failAt: "replace-unit" });
  await assert.rejects(
    executeCaddyAdminUdsTransaction({
      approvedPlanSha256: fixture.approvedPlanSha256,
      ops,
      plan: fixture.plan,
      siteInventoryBytes: fixture.inventoryBytes,
    }),
    (error) => {
      assert.ok(error instanceof ColdTransactionError);
      assert.equal(error.outcome, COLD_OUTCOMES.rolledBack);
      assert.equal(error.result.pair.before, "candidate/old");
      assert.equal(error.result.pair.after, "old/old");
      return true;
    },
  );
  assert.equal(ops.files.get(TARGET_CONFIG).snapshot.sha256, fixture.plan.preimage.config.sha256);
  assert.equal(ops.files.get(TARGET_FRAGMENT).snapshot.sha256, fixture.plan.preimage.unit.sha256);
  assert.ok(ops.calls.includes(`restore:${TARGET_CONFIG}`));
  assert.ok(ops.calls.includes(`restore:${TARGET_FRAGMENT}`));
  assert.ok(ops.calls.includes("site:rollback-after:tls-site"));
  assert.equal(ops.released, true);
});

test("rollback rejects a hardened argv under the exact legacy effective unit", async () => {
  const fixture = makePlanAndInventory();
  const ops = fakeOps(fixture, { failAt: "replace-unit" });
  const original = ops.readProcessRuntime;
  ops.readProcessRuntime = async (...args) => {
    const value = await original(...args);
    if (ops.calls.includes("run:start")) {
      value.caddy_admin_environment_absent = true;
      value.cmdline_argv = [
        CADDY_BINARY_PATH,
        "run",
        "--config",
        TARGET_CONFIG,
        "--adapter",
        "caddyfile",
      ];
    }
    return value;
  };
  await assert.rejects(
    executeCaddyAdminUdsTransaction({
      approvedPlanSha256: fixture.approvedPlanSha256,
      ops,
      plan: fixture.plan,
      siteInventoryBytes: fixture.inventoryBytes,
    }),
    (error) =>
      error instanceof ColdOutcomeUnknownError &&
      error.phase === "rollback-post-start-verification",
  );
  assert.equal(ops.states.has("50-rolled-back.json"), false);
  assert.equal(ops.locked, true);
});

test("rollback generation drift during long site probes is outcome-unknown", async () => {
  const fixture = makePlanAndInventory();
  const ops = fakeOps(fixture, { failAt: "replace-unit" });
  let driftAfterSites = false;
  const originalSiteProbe = ops.runSiteProbe;
  ops.runSiteProbe = async (probe, phase) => {
    const result = await originalSiteProbe(probe, phase);
    if (phase === "rollback-after" && probe.id === "tls-site") driftAfterSites = true;
    return result;
  };
  const originalGeneration = ops.readUnitGeneration;
  ops.readUnitGeneration = async (...args) => {
    const generation = await originalGeneration(...args);
    if (driftAfterSites) generation.invocation_id = "52345678123442349234123456789ac0";
    return generation;
  };
  await assert.rejects(
    executeCaddyAdminUdsTransaction({
      approvedPlanSha256: fixture.approvedPlanSha256,
      ops,
      plan: fixture.plan,
      siteInventoryBytes: fixture.inventoryBytes,
    }),
    (error) =>
      error instanceof ColdOutcomeUnknownError &&
      error.phase === "rollback-post-start-verification",
  );
  assert.equal(ops.states.has("50-rolled-back.json"), false);
  assert.equal(ops.locked, true);
});

test("post-start ambiguity forbids rollback, retains the lock and emits recovery state", async () => {
  const fixture = makePlanAndInventory();
  const ops = fakeOps(fixture, { failAt: "admin:root" });
  await assert.rejects(
    executeCaddyAdminUdsTransaction({
      approvedPlanSha256: fixture.approvedPlanSha256,
      ops,
      plan: fixture.plan,
      siteInventoryBytes: fixture.inventoryBytes,
    }),
    (error) => {
      assert.ok(error instanceof ColdOutcomeUnknownError);
      assert.equal(error.outcome, COLD_OUTCOMES.outcomeUnknown);
      assert.equal(error.phase, "post-start");
      assert.equal(error.result.automatic_rollback_performed, false);
      return true;
    },
  );
  assert.equal(ops.calls.some((call) => call.startsWith("restore:")), false);
  assert.equal(ops.calls.includes("publish-receipt"), false);
  assert.equal(ops.states.has("40-recovery-required.json"), true);
  assert.equal(ops.locked, true);
  assert.equal(ops.released, false);
});

test("receipt publication ambiguity is post-start outcome-unknown and never rolls back", async () => {
  const fixture = makePlanAndInventory();
  const ops = fakeOps(fixture, { failAt: "publish-receipt" });
  await assert.rejects(
    executeCaddyAdminUdsTransaction({
      approvedPlanSha256: fixture.approvedPlanSha256,
      ops,
      plan: fixture.plan,
      siteInventoryBytes: fixture.inventoryBytes,
    }),
    (error) => error instanceof ColdOutcomeUnknownError && error.phase === "post-start",
  );
  assert.equal(ops.calls.some((call) => call.startsWith("restore:")), false);
  assert.equal(ops.locked, true);
});

test("candidate start command ambiguity is post-start and cannot invoke rollback", async () => {
  const fixture = makePlanAndInventory();
  const ops = fakeOps(fixture, { failAt: "run:start" });
  await assert.rejects(
    executeCaddyAdminUdsTransaction({
      approvedPlanSha256: fixture.approvedPlanSha256,
      ops,
      plan: fixture.plan,
      siteInventoryBytes: fixture.inventoryBytes,
    }),
    (error) => error instanceof ColdOutcomeUnknownError && error.phase === "post-start",
  );
  assert.equal(ops.calls.some((call) => call.startsWith("restore:")), false);
  assert.equal(ops.states.has("40-recovery-required.json"), true);
  assert.equal(ops.locked, true);
});

test("unclassified stopped pair is left stopped with the lock retained", async () => {
  const fixture = makePlanAndInventory();
  const ops = fakeOps(fixture, { failAt: "replace-unit" });
  const originalReplace = ops.replacePrepared;
  ops.replacePrepared = async (options) => {
    try {
      return await originalReplace(options);
    } catch (error) {
      if (options.targetPath === TARGET_FRAGMENT) {
        const config = ops.files.get(TARGET_CONFIG);
        config.snapshot.sha256 = "f".repeat(64);
      }
      throw error;
    }
  };
  await assert.rejects(
    executeCaddyAdminUdsTransaction({
      approvedPlanSha256: fixture.approvedPlanSha256,
      ops,
      plan: fixture.plan,
      siteInventoryBytes: fixture.inventoryBytes,
    }),
    (error) =>
      error instanceof ColdOutcomeUnknownError &&
      error.phase === "stopped-pre-start-rollback-unavailable",
  );
  assert.equal(ops.calls.some((call) => call.startsWith("restore:")), false);
  assert.equal(ops.calls.filter((call) => call === "run:start").length, 0);
  assert.equal(ops.locked, true);
});

test("same-boot and exact legacy process generation/argv drift fail before stop", async () => {
  for (const drift of ["boot", "pid", "hardened-argv"]) {
    const fixture = makePlanAndInventory();
    const ops = fakeOps(fixture);
    if (drift === "boot") {
      ops.hostIdentity = async () => ({
        boot_id: "42345678-1234-4234-9234-123456789abc",
        hostname: "fixture.invalid",
      });
    } else if (drift === "pid") {
      const original = ops.readProcessRuntime;
      ops.readProcessRuntime = async (...args) => ({
        ...await original(...args),
        main_pid: "9999",
      });
    } else {
      const original = ops.readProcessRuntime;
      ops.readProcessRuntime = async (...args) => ({
        ...await original(...args),
        caddy_admin_environment_absent: true,
        cmdline_argv: [
          CADDY_BINARY_PATH,
          "run",
          "--config",
          TARGET_CONFIG,
          "--adapter",
          "caddyfile",
        ],
      });
    }
    await assert.rejects(
      executeCaddyAdminUdsTransaction({
        approvedPlanSha256: fixture.approvedPlanSha256,
        ops,
        plan: fixture.plan,
        siteInventoryBytes: fixture.inventoryBytes,
      }),
      (error) => error instanceof ColdTransactionError && error.outcome === COLD_OUTCOMES.preStopFailed,
      drift,
    );
    assert.equal(ops.calls.includes("run:stop"), false, drift);
  }
});

test("kernel core-pattern mismatch blocks before lock acquisition or filesystem work", async () => {
  const fixture = makePlanAndInventory();
  const ops = fakeOps(fixture);
  ops.hostPrerequisites = async () => ({
    core_pattern: "|/usr/share/apport/apport",
    euid: 0,
    platform: "linux",
    systemd_version: "255",
  });
  await assert.rejects(
    executeCaddyAdminUdsTransaction({
      approvedPlanSha256: fixture.approvedPlanSha256,
      ops,
      plan: fixture.plan,
      siteInventoryBytes: fixture.inventoryBytes,
    }),
    /kernel\.core_pattern must already equal/u,
  );
  assert.deepEqual(ops.calls, []);
});

test("non-root, non-Linux and non-systemd-255 hosts fail before lock acquisition", async () => {
  for (const prerequisites of [
    { core_pattern: "|/usr/bin/false", euid: 1000, platform: "linux", systemd_version: "255" },
    { core_pattern: "|/usr/bin/false", euid: 0, platform: "darwin", systemd_version: "255" },
    { core_pattern: "|/usr/bin/false", euid: 0, platform: "linux", systemd_version: "256" },
  ]) {
    const fixture = makePlanAndInventory();
    const ops = fakeOps(fixture);
    ops.hostPrerequisites = async () => prerequisites;
    await assert.rejects(
      executeCaddyAdminUdsTransaction({
        approvedPlanSha256: fixture.approvedPlanSha256,
        ops,
        plan: fixture.plan,
        siteInventoryBytes: fixture.inventoryBytes,
      }),
      /requires Linux root and exact systemd 255/u,
    );
    assert.deepEqual(ops.calls, []);
  }
});

test("systemd parser accepts the Ubuntu 24.04 systemd 255 first line and rejects ambiguous text", () => {
  assert.equal(
    parseSystemdVersionOutput(Buffer.from(
      "systemd 255 (255.4-1ubuntu8.16)\n+PAM +AUDIT +APPARMOR -SELINUX\n",
    )),
    "255",
  );
  assert.equal(parseSystemdVersionOutput(Buffer.from("systemd 255\n")), "255");
  assert.throws(
    () => parseSystemdVersionOutput(Buffer.from("wrapper\nsystemd 255 (255.4-1ubuntu8.16)\n")),
    /first line/u,
  );
  assert.throws(
    () => parseSystemdVersionOutput(Buffer.from("systemd 255 (unexpected suffix)\n")),
    /first line/u,
  );
});

test("executor, Node and launch control-plane drift fail before lock acquisition", async () => {
  for (const drift of ["executor", "node", "exec-argv", "environment", "cmdline"]) {
    const fixture = makePlanAndInventory();
    const ops = fakeOps(fixture);
    const original = ops.selfIdentity;
    ops.selfIdentity = async () => {
      const identity = await original();
      if (drift === "executor") identity.executor_snapshot.sha256 = "0".repeat(64);
      else if (drift === "node") identity.node_proc_exe_snapshot.sha256 = "0".repeat(64);
      else if (drift === "exec-argv") identity.node_exec_argv = ["--require", "/tmp/preload.cjs"];
      else if (drift === "environment") identity.node_control_environment_names = ["NODE_OPTIONS"];
      else identity.node_cmdline_argv.splice(2, 0, "--inspect=0.0.0.0:9229");
      return identity;
    };
    await assert.rejects(
      executeCaddyAdminUdsTransaction({
        approvedPlanSha256: fixture.approvedPlanSha256,
        ops,
        plan: fixture.plan,
        siteInventoryBytes: fixture.inventoryBytes,
      }),
      /self identity/u,
      drift,
    );
    assert.equal(ops.calls.includes("lock"), false, drift);
  }
});

test("Caddy proc-exe content drift fails before stop even when path and argv match", async () => {
  const fixture = makePlanAndInventory();
  const ops = fakeOps(fixture);
  const original = ops.readProcessRuntime;
  ops.readProcessRuntime = async (...args) => {
    const runtime = await original(...args);
    runtime.exe_snapshot.sha256 = "0".repeat(64);
    return runtime;
  };
  await assert.rejects(
    executeCaddyAdminUdsTransaction({
      approvedPlanSha256: fixture.approvedPlanSha256,
      ops,
      plan: fixture.plan,
      siteInventoryBytes: fixture.inventoryBytes,
    }),
    (error) => error instanceof ColdTransactionError && error.outcome === COLD_OUTCOMES.preStopFailed,
  );
  assert.equal(ops.calls.includes("run:stop"), false);
  assert.equal(ops.released, true);
});

test("inactive/dead without the full socket and TCP stopped proof is outcome-unknown", async () => {
  const fixture = makePlanAndInventory();
  const ops = fakeOps(fixture);
  ops.collectStoppedEvidence = async () => {
    throw new Error("persistent stopped evidence failure");
  };
  await assert.rejects(
    executeCaddyAdminUdsTransaction({
      approvedPlanSha256: fixture.approvedPlanSha256,
      ops,
      plan: fixture.plan,
      siteInventoryBytes: fixture.inventoryBytes,
    }),
    (error) =>
      error instanceof ColdOutcomeUnknownError &&
      error.phase === "stop-outcome-unknown-before-start",
  );
  assert.equal(ops.calls.some((call) => call.startsWith("restore:")), false);
  assert.equal(ops.calls.filter((call) => call === "run:start").length, 0);
  assert.equal(ops.locked, true);
  assert.equal(ops.released, false);
});

test("rollback restart-state publication failure retains the stopped old pair and lock", async () => {
  const fixture = makePlanAndInventory();
  const ops = fakeOps(fixture, {
    failAt: ["replace-unit", "state:30-rollback-start-requested.json"],
  });
  await assert.rejects(
    executeCaddyAdminUdsTransaction({
      approvedPlanSha256: fixture.approvedPlanSha256,
      ops,
      plan: fixture.plan,
      siteInventoryBytes: fixture.inventoryBytes,
    }),
    (error) =>
      error instanceof ColdOutcomeUnknownError &&
      error.phase === "stopped-pre-start-rollback-start-unrequested",
  );
  assert.equal(ops.files.get(TARGET_CONFIG).snapshot.sha256, fixture.plan.preimage.config.sha256);
  assert.equal(ops.files.get(TARGET_FRAGMENT).snapshot.sha256, fixture.plan.preimage.unit.sha256);
  assert.equal(ops.calls.filter((call) => call === "run:start").length, 0);
  assert.equal(ops.locked, true);
});

test("lock-release failure reports a committed receipt instead of misclassifying success", async () => {
  const fixture = makePlanAndInventory();
  const ops = fakeOps(fixture, { failAt: "unlock" });
  await assert.rejects(
    executeCaddyAdminUdsTransaction({
      approvedPlanSha256: fixture.approvedPlanSha256,
      ops,
      plan: fixture.plan,
      siteInventoryBytes: fixture.inventoryBytes,
    }),
    (error) => {
      assert.ok(error instanceof ColdTransactionError);
      assert.equal(error.outcome, COLD_OUTCOMES.committed);
      assert.equal(error.phase, "lock-release-failed");
      assert.equal(error.result.outcome, COLD_OUTCOMES.committed);
      assert.match(error.result.lock_release_error, /injected unlock/u);
      return true;
    },
  );
  assert.equal(ops.calls.includes("publish-receipt"), true);
  assert.equal(ops.locked, true);
});

test("lock-release failure preserves the verified rollback error and annotates cleanup", async () => {
  const fixture = makePlanAndInventory();
  const ops = fakeOps(fixture, { failAt: ["replace-unit", "unlock"] });
  await assert.rejects(
    executeCaddyAdminUdsTransaction({
      approvedPlanSha256: fixture.approvedPlanSha256,
      ops,
      plan: fixture.plan,
      siteInventoryBytes: fixture.inventoryBytes,
    }),
    (error) => {
      assert.ok(error instanceof ColdTransactionError);
      assert.equal(error.outcome, COLD_OUTCOMES.rolledBack);
      assert.match(error.lock_release_error, /injected unlock/u);
      return true;
    },
  );
  assert.equal(ops.locked, true);
});
