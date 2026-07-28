import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  LIVE_EVIDENCE_KIND,
  validateLiveRuntimeEvidence,
} from "./payment-v1-linux-runtime-evidence.mjs";
import {
  RUNTIME_COLLECTOR,
  RUNTIME_SYSTEMCTL_SHOW_PROPERTIES,
} from "./payment-v1-rendered-artifact-gate.mjs";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const COLLECTOR = join(SCRIPT_DIRECTORY, "payment-v1-linux-runtime-evidence.mjs");
const COMMANDS = [
  "/usr/bin/getent",
  "/usr/bin/getfacl",
  "/usr/bin/getfattr",
  "/usr/bin/id",
  "/usr/bin/node",
  "/usr/bin/setpriv",
  "/usr/bin/sha256sum",
  "/usr/bin/stat",
  "/usr/bin/systemctl",
  "/usr/bin/systemd-analyze",
  "/usr/bin/test",
  "/usr/bin/uname",
  "/usr/sbin/getcap",
];

function hash(value) {
  return createHash("sha256").update(value).digest("hex");
}

function clone(value) {
  return structuredClone(value);
}

function execValue(command) {
  return `{ path=${command.split(" ", 1)[0]} ; argv[]=${command} ; ignore_errors=no ; start_time=[n/a] ; }`;
}

function fixture() {
  const fragmentPath = "/etc/systemd/system/bitcoinpir-test.service";
  const binaryPath = `/opt/bitcoinpir/test/${hash("binary")}/test`;
  const unit = {
    conditions: ["ConditionPathExists=/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED"],
    environment: ["RUST_LOG=error"],
    environment_files: [],
    exec_start: [`${binaryPath} serve --config /etc/bitcoinpir/payment-v1/test/config.toml`],
    exec_start_pre: ["/usr/bin/test -x /opt/bitcoinpir/test/check"],
    fragment_path: fragmentPath,
    hardening: {
      AmbientCapabilities: [""],
      CapabilityBoundingSet: [""],
      Group: ["bitcoinpir-test"],
      LockPersonality: ["true"],
      MemoryDenyWriteExecute: ["true"],
      NoNewPrivileges: ["true"],
      PrivateDevices: ["true"],
      PrivateTmp: ["true"],
      ProtectControlGroups: ["true"],
      ProtectHome: ["true"],
      ProtectKernelLogs: ["true"],
      ProtectKernelModules: ["true"],
      ProtectKernelTunables: ["true"],
      ProtectSystem: ["strict"],
      ReadOnlyPaths: ["/etc/bitcoinpir/payment-v1/test"],
      Restart: ["no"],
      RestrictAddressFamilies: ["AF_UNIX", "AF_INET"],
      RestrictNamespaces: ["true"],
      RestrictRealtime: ["true"],
      RestrictSUIDSGID: ["true"],
      SupplementaryGroups: ["bitcoinpir-shared"],
      SystemCallArchitectures: ["native"],
      Type: ["simple"],
      UMask: ["0077"],
      User: ["bitcoinpir-test"],
      WorkingDirectory: ["/var/lib/bitcoinpir-test"],
    },
    unit_name: "bitcoinpir-test.service",
  };
  const installedFiles = [
    { file_type: "regular", gid: 0, mode: "0644", nlink: 1, sha256: hash("fragment"), target_path: fragmentPath, uid: 0 },
    { file_type: "regular", gid: 0, mode: "0555", nlink: 1, sha256: hash("binary"), target_path: binaryPath, uid: 0 },
  ];
  const request = {
    approved_plan_sha256: hash("plan"),
    collector: RUNTIME_COLLECTOR,
    deployment_profile: "test",
    installed_files: installedFiles,
    manifest_sha256: hash("manifest"),
    schema_version: 1,
    secret_files: [],
    service_identities: [{
      gid: 731,
      group_name: "bitcoinpir-test",
      uid: 730,
      unit_name: unit.unit_name,
      user_name: "bitcoinpir-test",
    }],
    systemctl_show_properties: RUNTIME_SYSTEMCTL_SHOW_PROPERTIES,
    systemd_analyze_argv: ["/usr/bin/systemd-analyze", "verify", fragmentPath],
    tmpfiles_directories: [
      { group_name: "bitcoinpir-shared", mode: "0710", target_path: "/run/bitcoinpir-test", user_name: "bitcoinpir-test" },
    ],
    units: [unit],
  };
  const properties = {
    ActiveEnterTimestampMonotonic: "4000000",
    ActiveState: "active",
    AmbientCapabilities: "",
    BindPaths: "",
    BindReadOnlyPaths: "",
    CapabilityBoundingSet: "",
    ConditionResult: "yes",
    Conditions: "ConditionPathExists=/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
    DropInPaths: "",
    Environment: "RUST_LOG=error",
    EnvironmentFiles: "",
    ExecCondition: "",
    ExecMainCode: "0",
    ExecMainStatus: "0",
    ExecStart: execValue(unit.exec_start[0]),
    ExecStartPost: "",
    ExecStartPre: execValue(unit.exec_start_pre[0]),
    FragmentPath: fragmentPath,
    Group: "bitcoinpir-test",
    IPAddressAllow: "",
    IPAddressDeny: "",
    InaccessiblePaths: "",
    InvocationID: "a".repeat(32),
    LoadCredential: "",
    LoadState: "loaded",
    LockPersonality: "yes",
    MainPID: "4242",
    MemoryDenyWriteExecute: "yes",
    NoNewPrivileges: "yes",
    PrivateDevices: "yes",
    PrivateTmp: "yes",
    ProtectClock: "",
    ProtectControlGroups: "yes",
    ProtectHome: "yes",
    ProtectHostname: "",
    ProtectKernelLogs: "yes",
    ProtectKernelModules: "yes",
    ProtectKernelTunables: "yes",
    ProtectSystem: "strict",
    ReadOnlyPaths: "/etc/bitcoinpir/payment-v1/test",
    ReadWritePaths: "",
    RemainAfterExit: "no",
    Restart: "no",
    Result: "success",
    RestrictAddressFamilies: "AF_INET AF_UNIX",
    RestrictNamespaces: "yes",
    RestrictRealtime: "yes",
    RestrictSUIDSGID: "yes",
    RootDirectory: "",
    RootImage: "",
    SetCredential: "",
    SubState: "running",
    SupplementaryGroups: "bitcoinpir-shared",
    SystemCallArchitectures: "native",
    Type: "simple",
    UMask: "0077",
    User: "bitcoinpir-test",
    WorkingDirectory: "/var/lib/bitcoinpir-test",
  };
  function richFile(expected, index) {
    return {
      acl_sha256: hash(`acl-${index}`),
      capability_sha256: hash(""),
      dev: "1",
      expected_type: "regular",
      ...expected,
      ino: String(100 + index),
      sha256_command_sha256: hash(`sha-command-${index}`),
      size: 100 + index,
      stat_command_sha256: hash(`stat-${index}`),
      xattr_sha256: hash(`xattr-${index}`),
    };
  }
  const machine = hash("machine");
  const boot = "12345678-1234-4abc-8def-123456789abc";
  const generationConfirmation = {
    active_enter_timestamp_monotonic: properties.ActiveEnterTimestampMonotonic,
    active_state: properties.ActiveState,
    invocation_id: properties.InvocationID,
    main_pid: properties.MainPID,
  };
  const processIdentity = {
    gid_after: [731, 731, 731, 731],
    gid_before: [731, 731, 731, 731],
    groups_after: [731, 732],
    groups_before: [731, 732],
    main_pid: 4242,
    proc_directory_dev_after: "9",
    proc_directory_dev_before: "9",
    proc_directory_ino_after: "99",
    proc_directory_ino_before: "99",
    process_state_after: "S",
    process_state_before: "R",
    start_time_ticks_after: "123456",
    start_time_ticks_before: "123456",
    uid_after: [730, 730, 730, 730],
    uid_before: [730, 730, 730, 730],
  };
  const evidence = {
    approved_plan_sha256: request.approved_plan_sha256,
    challenge_hex: hash("internal-random-challenge"),
    collected_finished_unix_seconds: 1_800_000_010,
    collected_started_unix_seconds: 1_800_000_000,
    collector: RUNTIME_COLLECTOR,
    collector_process: { egid: 0, euid: 0, pid: 42 },
    evidence_kind: LIVE_EVIDENCE_KIND,
    host: {
      boot_id: boot,
      kernel_release: "6.8.0-test",
      machine_id_sha256: machine,
      systemd_version: "systemd 257",
      uptime_finished_milliseconds: 5010,
      uptime_started_milliseconds: 5000,
    },
    installed_files: installedFiles.map(richFile),
    manifest_sha256: request.manifest_sha256,
    nss: {
      groups: [
        { gid: 731, members: [], name: "bitcoinpir-test" },
        { gid: 732, members: [], name: "bitcoinpir-shared" },
      ],
      users: [
        { name: "bitcoinpir-test", primary_gid: 731, supplementary_gids: [731], uid: 730 },
      ],
    },
    runtime_directories: [
      {
        acl_sha256: hash("dir-acl"),
        capability_sha256: hash(""),
        dev: "1",
        expected_type: "directory",
        file_type: "directory",
        gid: 732,
        group_name: "bitcoinpir-shared",
        ino: "200",
        mode: "0710",
        nlink: 2,
        size: 40,
        stat_command_sha256: hash("dir-stat"),
        target_path: "/run/bitcoinpir-test",
        uid: 730,
        user_name: "bitcoinpir-test",
        xattr_sha256: hash("dir-xattr"),
      },
    ],
    schema_version: 1,
    secret_access_checks: [],
    secret_parent_directories: [],
    systemd_analyze_verify: {
      argv: request.systemd_analyze_argv,
      exit_status: 0,
      stderr: "",
      stdout: "",
    },
    trusted_commands: COMMANDS.map((path, index) => ({
      gid: 0,
      mode: "0755",
      nlink: 1,
      path,
      sha256: hash(`command-${index}`),
      uid: 0,
    })),
    units: [{
      fragment_sha256: hash("fragment"),
      generation_confirmations: [clone(generationConfirmation), clone(generationConfirmation)],
      process_identity: processIdentity,
      properties,
      unit_name: unit.unit_name,
    }],
  };
  return { boot, evidence, machine, request };
}

function validate(value) {
  return validateLiveRuntimeEvidence({
    evidence: value.evidence,
    expectedBootId: value.boot,
    expectedMachineIdSha256: value.machine,
    maxAgeSeconds: 30,
    nowUnixSeconds: 1_800_000_020,
    request: value.request,
  });
}

function oneshotFixture() {
  const value = fixture();
  const fragmentPath = "/etc/systemd/system/bitcoinpir-lightning-preflight.service";
  const unit = value.request.units[0];
  unit.fragment_path = fragmentPath;
  unit.unit_name = "bitcoinpir-lightning-preflight.service";
  unit.hardening.Type = ["oneshot"];
  unit.hardening.RemainAfterExit = ["yes"];
  value.request.service_identities[0].unit_name = unit.unit_name;
  value.request.installed_files[0].target_path = fragmentPath;
  value.request.systemd_analyze_argv[2] = fragmentPath;
  value.evidence.installed_files[0].target_path = fragmentPath;
  value.evidence.systemd_analyze_verify.argv[2] = fragmentPath;
  const actual = value.evidence.units[0];
  actual.unit_name = unit.unit_name;
  actual.properties.FragmentPath = fragmentPath;
  actual.properties.Type = "oneshot";
  actual.properties.RemainAfterExit = "yes";
  actual.properties.MainPID = "0";
  actual.properties.SubState = "exited";
  actual.properties.Result = "success";
  actual.properties.ExecMainCode = "1";
  actual.properties.ExecMainStatus = "0";
  actual.generation_confirmations = actual.generation_confirmations.map((confirmation) => ({
    ...confirmation,
    main_pid: "0",
  }));
  actual.process_identity = null;
  return value;
}

function testProbeArgv({ gid, groups, uid }, targetPath) {
  return [
    "/usr/bin/setpriv",
    "--no-new-privs",
    "--inh-caps=-all",
    "--ambient-caps=-all",
    "--bounding-set=-all",
    "--reuid", String(uid),
    "--regid", String(gid),
    "--groups", groups.join(","),
    "--",
    "/usr/bin/test",
    "-r",
    targetPath,
  ];
}

function secretIsolationFixture() {
  const value = fixture();
  const peerUnit = clone(value.request.units[0]);
  peerUnit.unit_name = "bitcoinpir-z-peer.service";
  peerUnit.fragment_path = "/etc/systemd/system/bitcoinpir-z-peer.service";
  peerUnit.hardening.User = ["bitcoinpir-z-peer"];
  peerUnit.hardening.Group = ["bitcoinpir-z-peer"];
  peerUnit.hardening.SupplementaryGroups = ["bitcoinpir-test"];
  value.request.units.push(peerUnit);
  value.request.service_identities.push({
    gid: 734,
    group_name: "bitcoinpir-z-peer",
    uid: 733,
    unit_name: peerUnit.unit_name,
    user_name: "bitcoinpir-z-peer",
  });
  value.evidence.nss.groups.push({ gid: 734, members: [], name: "bitcoinpir-z-peer" });
  value.evidence.nss.users.push({ name: "bitcoinpir-z-peer", primary_gid: 734, supplementary_gids: [734], uid: 733 });

  const peerFragment = { file_type: "regular", gid: 0, mode: "0644", nlink: 1, sha256: hash("peer-fragment"), target_path: peerUnit.fragment_path, uid: 0 };
  value.request.installed_files.push(peerFragment);
  value.evidence.installed_files.push({
    ...clone(value.evidence.installed_files[0]),
    ...peerFragment,
    ino: "303",
    sha256_command_sha256: hash("peer-sha-command"),
    stat_command_sha256: hash("peer-stat"),
  });
  value.request.systemd_analyze_argv.push(peerUnit.fragment_path);
  value.evidence.systemd_analyze_verify.argv.push(peerUnit.fragment_path);
  const peerProperties = {
    ...clone(value.evidence.units[0].properties),
    FragmentPath: peerUnit.fragment_path,
    Group: "bitcoinpir-z-peer",
    InvocationID: "b".repeat(32),
    MainPID: "4243",
    SupplementaryGroups: "bitcoinpir-test",
    User: "bitcoinpir-z-peer",
  };
  const peerConfirmation = {
    active_enter_timestamp_monotonic: peerProperties.ActiveEnterTimestampMonotonic,
    active_state: "active",
    invocation_id: peerProperties.InvocationID,
    main_pid: peerProperties.MainPID,
  };
  value.evidence.units.push({
    fragment_sha256: peerFragment.sha256,
    generation_confirmations: [clone(peerConfirmation), clone(peerConfirmation)],
    process_identity: {
      gid_after: [734, 734, 734, 734],
      gid_before: [734, 734, 734, 734],
      groups_after: [731, 734],
      groups_before: [731, 734],
      main_pid: 4243,
      proc_directory_dev_after: "9",
      proc_directory_dev_before: "9",
      proc_directory_ino_after: "100",
      proc_directory_ino_before: "100",
      process_state_after: "S",
      process_state_before: "S",
      start_time_ticks_after: "123457",
      start_time_ticks_before: "123457",
      uid_after: [733, 733, 733, 733],
      uid_before: [733, 733, 733, 733],
    },
    properties: peerProperties,
    unit_name: peerUnit.unit_name,
  });

  const targetPath = "/etc/bitcoinpir/payment-v1/issuer/quote-signing.key";
  const secret = { file_type: "regular", gid: 731, mode: "0400", nlink: 1, sha256: hash("issuer-secret"), target_path: targetPath, uid: 730 };
  value.request.installed_files.push(secret);
  value.request.secret_files = [{ consumer_unit_name: value.request.units[0].unit_name, gid: 731, mode: "0400", target_path: targetPath, uid: 730 }];
  value.evidence.installed_files.push({
    ...clone(value.evidence.installed_files[0]),
    ...secret,
    ino: "304",
    sha256_command_sha256: hash("secret-sha-command"),
    stat_command_sha256: hash("secret-stat"),
  });
  const parents = [
    "/",
    "/etc",
    "/etc/bitcoinpir",
    "/etc/bitcoinpir/payment-v1",
    "/etc/bitcoinpir/payment-v1/issuer",
  ];
  value.evidence.secret_parent_directories = parents.map((target, index) => ({
    acl_sha256: hash(`parent-acl-${index}`),
    capability_sha256: hash(""),
    dev: "1",
    expected_type: "directory",
    file_type: "directory",
    gid: 0,
    ino: String(400 + index),
    mode: index === parents.length - 1 ? "0710" : "0755",
    nlink: 2,
    size: 40,
    stat_command_sha256: hash(`parent-stat-${index}`),
    target_path: target,
    uid: 0,
    xattr_sha256: hash(`parent-xattr-${index}`),
  }));
  value.evidence.secret_access_checks = [
    {
      argv: testProbeArgv({ gid: 731, groups: [731, 732], uid: 730 }, targetPath),
      exit_status: 0,
      expected_readable: true,
      stderr: "",
      stdout: "",
      target_path: targetPath,
      unit_name: value.request.units[0].unit_name,
    },
    {
      argv: testProbeArgv({ gid: 734, groups: [731, 734], uid: 733 }, targetPath),
      exit_status: 1,
      expected_readable: false,
      stderr: "",
      stdout: "",
      target_path: targetPath,
      unit_name: peerUnit.unit_name,
    },
  ];
  return value;
}

test("valid live evidence binds challenge, host, boot, files, NSS, units, and command TCB", () => {
  assert.equal(validate(fixture()), true);
});

test("reviewed preflight oneshot uses active-exited boot-bound completion evidence without fake procfs identity", () => {
  assert.equal(validate(oneshotFixture()), true);
  for (const [mutate, expected] of [
    [(value) => { value.evidence.units[0].properties.ExecMainCode = "0"; }, /oneshot completion proof/],
    [(value) => { value.evidence.units[0].properties.ExecMainStatus = "1"; }, /oneshot completion proof/],
    [(value) => { value.evidence.units[0].properties.SubState = "running"; }, /oneshot completion proof/],
    [(value) => { value.evidence.units[0].properties.MainPID = "42"; }, /oneshot completion proof/],
    [(value) => { value.evidence.units[0].properties.ActiveEnterTimestampMonotonic = "6000000"; }, /not bound to this boot/],
    [(value) => { value.evidence.units[0].properties.InvocationID = "0".repeat(32); }, /InvocationID/],
  ]) {
    const value = oneshotFixture();
    mutate(value);
    assert.throws(() => validate(value), expected);
  }
});

test("secret evidence binds parent metadata and positive owner/negative cross-role access probes", () => {
  assert.equal(validate(secretIsolationFixture()), true);
  const readableByPeer = secretIsolationFixture();
  readableByPeer.evidence.secret_access_checks[1].exit_status = 0;
  assert.throws(() => validate(readableByPeer), /secret access isolation/);
  const missingParent = secretIsolationFixture();
  missingParent.evidence.secret_parent_directories.pop();
  assert.throws(() => validate(missingParent), /parent directory evidence is incomplete/);
});

for (const [label, mutate, expected] of [
  ["drop-in", (f) => { f.evidence.units[0].properties.DropInPaths = "/etc/systemd/system/x.d/evil.conf"; }, /drop-in/],
  ["ExecStart reset", (f) => { f.evidence.units[0].properties.ExecStart = execValue("/usr/bin/true"); }, /ExecStart drift/],
  ["ExecStartPost", (f) => { f.evidence.units[0].properties.ExecStartPost = execValue("/usr/bin/true"); }, /ExecStartPost/],
  ["EnvironmentFile", (f) => { f.evidence.units[0].properties.EnvironmentFiles = "/tmp/evil"; }, /EnvironmentFiles/],
  ["credential", (f) => { f.evidence.units[0].properties.LoadCredential = "secret:/tmp/evil"; }, /LoadCredential/],
  ["root image", (f) => { f.evidence.units[0].properties.RootImage = "/tmp/root.img"; }, /RootImage/],
  ["file hash", (f) => { f.evidence.installed_files[0].sha256 = hash("evil"); }, /sha256 drift/],
  ["tmpfiles mode", (f) => { f.evidence.runtime_directories[0].mode = "0777"; }, /tmpfiles directory drift/],
  ["unexpected issuer group", (f) => { f.evidence.nss.users[0].supplementary_gids.push(999); }, /unexpected supplementary group/],
  ["inactive unit", (f) => { f.evidence.units[0].properties.ActiveState = "inactive"; }, /not active/],
  ["zero MainPID", (f) => { f.evidence.units[0].properties.MainPID = "0"; }, /no active MainPID/],
  ["effective Restart drift", (f) => { f.evidence.units[0].properties.Restart = "on-failure"; }, /Restart drift/],
  ["MainPID confirmation race", (f) => { f.evidence.units[0].generation_confirmations[1].main_pid = "4243"; }, /MainPID or InvocationID changed/],
  ["InvocationID generation race", (f) => { f.evidence.units[0].generation_confirmations[1].invocation_id = "b".repeat(32); }, /MainPID or InvocationID changed/],
  ["proc starttime race", (f) => { f.evidence.units[0].process_identity.start_time_ticks_after = "123457"; }, /restart race/],
  ["proc inode race", (f) => { f.evidence.units[0].process_identity.proc_directory_ino_after = "100"; }, /restart race/],
  ["old process retained supplementary group", (f) => {
    f.evidence.units[0].process_identity.groups_before.push(999);
    f.evidence.units[0].process_identity.groups_after.push(999);
  }, /process Groups drift/],
  ["running process UID drift", (f) => { f.evidence.units[0].process_identity.uid_after = [999, 999, 999, 999]; }, /Uid after/],
  ["command replacement", (f) => { f.evidence.trusted_commands[0].mode = "0777"; }, /untrusted runtime command/],
]) {
  test(`live verifier rejects ${label}`, () => {
    const value = fixture();
    mutate(value);
    assert.throws(() => validate(value), expected);
  });
}

test("live verifier rejects replay, foreign host, foreign boot, and forged challenge", () => {
  const stale = fixture();
  assert.throws(
    () => validateLiveRuntimeEvidence({ evidence: stale.evidence, expectedBootId: stale.boot, expectedMachineIdSha256: stale.machine, maxAgeSeconds: 5, nowUnixSeconds: 1_800_000_020, request: stale.request }),
    /stale/,
  );
  const host = fixture();
  host.machine = hash("another-machine");
  assert.throws(() => validate(host), /another host/);
  const boot = fixture();
  boot.boot = "87654321-4321-4abc-8def-123456789abc";
  assert.throws(() => validate(boot), /another boot/);
  const challenge = fixture();
  challenge.evidence.challenge_hex = "0".repeat(64);
  assert.throws(() => validate(challenge), /internally random/);
});

test("collect-live rejects caller JSON, caller challenge, and offline verification without a digest pin", () => {
  const base = [
    "--bundle", "/tmp/bundle",
    "--approved-manifest-sha256", hash("manifest"),
    "--approved-plan-sha256", hash("plan"),
    "--expected-machine-id-sha256", hash("machine"),
  ];
  const callerJson = spawnSync(process.execPath, [COLLECTOR, "collect-live", ...base, "--output", "/tmp/output", "--evidence", "/tmp/forged.json"], { encoding: "utf8" });
  assert.notEqual(callerJson.status, 0);
  assert.match(callerJson.stderr, /forbids caller evidence/);
  const challenge = spawnSync(process.execPath, [COLLECTOR, "collect-live", ...base, "--output", "/tmp/output", "--challenge", hash("chosen")], { encoding: "utf8" });
  assert.notEqual(challenge.status, 0);
  assert.match(challenge.stderr, /invalid, repeated, or missing CLI option/);
  const offline = spawnSync(process.execPath, [COLLECTOR, "verify-offline", ...base, "--evidence", "/tmp/forged.json", "--expected-boot-id", "12345678-1234-4abc-8def-123456789abc"], { encoding: "utf8" });
  assert.notEqual(offline.status, 0);
  assert.match(offline.stderr, /trusted-evidence-sha256/);
});

test("collect-live is Linux-only and root-only before any runtime evidence can be claimed", () => {
  if (process.platform === "linux" && process.geteuid?.() === 0 && process.execPath === "/usr/bin/node") return;
  const result = spawnSync(process.execPath, [
    COLLECTOR,
    "collect-live",
    "--bundle", "/tmp/missing-bundle",
    "--approved-manifest-sha256", hash("manifest"),
    "--approved-plan-sha256", hash("plan"),
    "--expected-machine-id-sha256", hash("machine"),
    "--output", "/tmp/nonexistent-parent/evidence.json",
  ], { encoding: "utf8" });
  assert.notEqual(result.status, 0);
});
