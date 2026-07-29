import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  assertLocalFilesNssPolicyUnchanged,
  LIVE_EVIDENCE_KIND,
  STOPPED_EDGE_EVIDENCE_KIND,
  NSS_BACKEND_PROFILE,
  NSS_ENUMERATION_KIND,
  PROTECTED_PROCESS_ENUMERATION_KIND,
  collectProtectedCredentialProcessClosureV1,
  collectVisibleNssEvidenceV2,
  parseGroupEnumerationV2,
  parseLocalFilesNsswitchV1,
  parseLockedServiceAccountPolicyV1,
  parsePasswdEnumerationV2,
  parseProcStatus,
  validateNonRootEdgeCapabilitiesV1,
  validateLiveRuntimeEvidence,
  validateStoppedEdgeActivationEvidence,
} from "./payment-v1-linux-runtime-evidence.mjs";
import {
  RUNTIME_COLLECTOR,
  RUNTIME_SYSTEMCTL_SHOW_PROPERTIES,
} from "./payment-v1-rendered-artifact-gate.mjs";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const COLLECTOR = join(SCRIPT_DIRECTORY, "payment-v1-linux-runtime-evidence.mjs");
const COMMANDS = [
  "/usr/bin/false",
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

function capabilityRecord(overrides = {}) {
  return {
    ambient: "0000000000000000",
    bounding: "0000000000000000",
    effective: "0000000000000000",
    inheritable: "0000000000000000",
    permitted: "0000000000000000",
    ...overrides,
  };
}

function sortNssEvidence(nss) {
  for (const group of nss.groups) group.members.sort();
  for (const user of nss.users) user.supplementary_gids.sort((left, right) => left - right);
  nss.groups.sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
  nss.users.sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
  return nss;
}

function execValue(command) {
  return `{ path=${command.split(" ", 1)[0]} ; argv[]=${command} ; ignore_errors=no ; start_time=[n/a] ; }`;
}

function protectedHolder({
  capabilities = capabilityRecord(),
  controlGroup,
  gid,
  groups,
  ino,
  pid,
  startTime,
  uid,
  tid = pid,
}) {
  return {
    capabilities,
    control_group: controlGroup,
    gid: [gid, gid, gid, gid],
    groups: [...groups],
    pid,
    proc_directory_dev: "9",
    proc_directory_ino: ino,
    start_time_ticks: startTime,
    tid,
    uid: [uid, uid, uid, uid],
  };
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
      LimitCORE: ["0"],
      LockPersonality: ["true"],
      MemoryDenyWriteExecute: ["true"],
      MemoryMax: ["268435456"],
      MemorySwapMax: ["0"],
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
      StandardError: ["null"],
      StandardOutput: ["null"],
      SupplementaryGroups: ["bitcoinpir-shared"],
      SystemCallArchitectures: ["native"],
      TasksMax: ["128"],
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
    runtime_paths: [{
      file_type: "socket",
      gid: 731,
      mode: "0660",
      target_path: "/run/bitcoinpir-test/service.sock",
      uid: 730,
    }],
    schema_version: 3,
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
    ControlGroup: "/system.slice/bitcoinpir-test.service",
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
    LimitCORE: "0",
    LimitCORESoft: "0",
    MainPID: "4242",
    MemoryDenyWriteExecute: "yes",
    MemoryMax: "268435456",
    MemorySwapCurrent: "0",
    MemorySwapMax: "0",
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
    StandardError: "null",
    StandardOutput: "null",
    SubState: "running",
    SupplementaryGroups: "bitcoinpir-shared",
    SystemCallArchitectures: "native",
    TasksMax: "128",
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
  function nssPolicyFile(path, index) {
    return {
      dev: "1",
      gid: 0,
      ino: String(600 + index),
      mode: "0644",
      nlink: 1,
      path,
      sha256: hash(`nss-policy-${index}`),
      size: 100 + index,
      uid: 0,
    };
  }
  const machine = hash("machine");
  const boot = "12345678-1234-4abc-8def-123456789abc";
  const generationConfirmation = {
    active_enter_timestamp_monotonic: properties.ActiveEnterTimestampMonotonic,
    active_state: properties.ActiveState,
    control_group: properties.ControlGroup,
    invocation_id: properties.InvocationID,
    main_pid: properties.MainPID,
  };
  const processIdentity = {
    capabilities_after: capabilityRecord(),
    capabilities_before: capabilityRecord(),
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
      collector_pid_namespace: "pid:[4026531836]",
      core_pattern: "|/usr/bin/false",
      kernel_release: "6.8.0-test",
      machine_id_sha256: machine,
      pid1_name: "systemd",
      pid1_nspid: [1],
      pid1_pid_namespace: "pid:[4026531836]",
      systemd_version: "systemd 257",
      uptime_finished_milliseconds: 5010,
      uptime_started_milliseconds: 5000,
    },
    installed_files: installedFiles.map(richFile),
    manifest_sha256: request.manifest_sha256,
    nss: {
      backend_profile: NSS_BACKEND_PROFILE,
      enumeration_kind: NSS_ENUMERATION_KIND,
      group_file: nssPolicyFile("/etc/group", 2),
      group_stdout_sha256: hash("group-enumeration"),
      groups: [
        { gid: 732, members: ["bitcoinpir-test"], name: "bitcoinpir-shared" },
        { gid: 731, members: [], name: "bitcoinpir-test" },
        { gid: 0, members: [], name: "root" },
      ],
      nsswitch_file: nssPolicyFile("/etc/nsswitch.conf", 0),
      passwd_file: nssPolicyFile("/etc/passwd", 1),
      passwd_stdout_sha256: hash("passwd-enumeration"),
      sources: {
        group: ["files"],
        initgroups: "inherits-group",
        passwd: ["files"],
      },
      users: [
        { name: "bitcoinpir-test", primary_gid: 731, supplementary_gids: [731, 732], uid: 730 },
        { name: "root", primary_gid: 0, supplementary_gids: [0], uid: 0 },
      ],
    },
    protected_process_closure: {
      enumeration_kind: PROTECTED_PROCESS_ENUMERATION_KIND,
      passes: [0, 1].map(() => ({
        holders: [protectedHolder({
          controlGroup: properties.ControlGroup,
          gid: 731,
          groups: [731, 732],
          ino: "99",
          pid: 4242,
          startTime: "123456",
          uid: 730,
        })],
        processes_enumerated: 1,
        threads_examined: 1,
      })),
      protected_gids: [731, 732],
      protected_uids: [730],
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
    runtime_paths: [{
      acl_sha256: hash("socket-acl"),
      capability_sha256: hash(""),
      dev: "1",
      expected_type: "socket",
      file_type: "socket",
      gid: 731,
      ino: "300",
      mode: "0660",
      nlink: 1,
      size: 0,
      stat_command_sha256: hash("socket-stat"),
      target_path: "/run/bitcoinpir-test/service.sock",
      uid: 730,
      xattr_sha256: hash("socket-xattr"),
    }],
    schema_version: 3,
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
      generation_confirmations: [
        clone(generationConfirmation),
        clone(generationConfirmation),
        clone(generationConfirmation),
      ],
      process_identity: processIdentity,
      properties,
      unit_name: unit.unit_name,
    }],
  };
  return { boot, evidence, machine, request };
}

function stoppedEdgeFixture() {
  const live = fixture();
  live.request.deployment_profile = "edge-hetzner-v1";
  const unitState = {
    active_state: "inactive",
    control_group: "",
    drop_in_paths: "",
    fragment_path: live.request.units[0].fragment_path,
    invocation_id: "",
    load_state: "loaded",
    main_pid: "0",
    sub_state: "dead",
    unit_name: live.request.units[0].unit_name,
  };
  const socketAbsence = {
    parent_dev: "1",
    parent_ino: "200",
    parent_path: "/run/bitcoinpir-test",
    parent_state: "canonical-directory",
    target_path: "/run/bitcoinpir-test/service.sock",
  };
  const shadowFile = {
    ...clone(live.evidence.nss.passwd_file),
    gid: 42,
    ino: "604",
    mode: "0640",
    path: "/etc/shadow",
    sha256: hash("shadow-policy"),
  };
  const evidence = {
    account_policy: {
      accounts: [{
        gid: 731,
        password_state: "locked",
        shell: "/usr/sbin/nologin",
        uid: 730,
        user_name: "bitcoinpir-test",
      }],
      passwd_file: clone(live.evidence.nss.passwd_file),
      shadow_file: shadowFile,
    },
    approved_plan_sha256: live.request.approved_plan_sha256,
    challenge_hex: hash("stopped-edge-internal-challenge"),
    collected_finished_unix_seconds: 1_800_000_010,
    collected_started_unix_seconds: 1_800_000_000,
    collector: RUNTIME_COLLECTOR,
    collector_process: { egid: 0, euid: 0, pid: 42 },
    evidence_kind: STOPPED_EDGE_EVIDENCE_KIND,
    host: clone(live.evidence.host),
    manifest_sha256: live.request.manifest_sha256,
    nss: clone(live.evidence.nss),
    protected_process_closure: {
      enumeration_kind: PROTECTED_PROCESS_ENUMERATION_KIND,
      passes: [0, 1].map(() => ({
        holders: [],
        processes_enumerated: 10,
        threads_examined: 12,
      })),
      protected_gids: [731, 732],
      protected_uids: [730],
    },
    runtime_socket_absence_passes: [
      [clone(socketAbsence)],
      [clone(socketAbsence)],
    ],
    schema_version: 2,
    stopped_unit_passes: [
      [clone(unitState)],
      [clone(unitState)],
    ],
    trusted_commands: clone(live.evidence.trusted_commands),
  };
  return { ...live, evidence };
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

function validateStopped(value) {
  return validateStoppedEdgeActivationEvidence({
    evidence: value.evidence,
    expectedBootId: value.boot,
    expectedMachineIdSha256: value.machine,
    maxAgeSeconds: 30,
    nowUnixSeconds: 1_800_000_020,
    request: value.request,
  });
}

function localFilesPolicySnapshot(nss) {
  return {
    evidence: {
      backend_profile: nss.backend_profile,
      group_file: clone(nss.group_file),
      nsswitch_file: clone(nss.nsswitch_file),
      passwd_file: clone(nss.passwd_file),
      sources: clone(nss.sources),
    },
    groupRecords: clone(nss.groups),
    passwdRecords: nss.users.map(({ supplementary_gids: _ignored, ...record }) => clone(record)),
  };
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
  actual.properties.ControlGroup = `/system.slice/${unit.unit_name}`;
  actual.properties.Type = "oneshot";
  actual.properties.RemainAfterExit = "yes";
  actual.properties.MainPID = "0";
  actual.properties.SubState = "exited";
  actual.properties.Result = "success";
  actual.properties.ExecMainCode = "1";
  actual.properties.ExecMainStatus = "0";
  actual.generation_confirmations = actual.generation_confirmations.map((confirmation) => ({
    ...confirmation,
    control_group: actual.properties.ControlGroup,
    main_pid: "0",
  }));
  actual.process_identity = null;
  for (const pass of value.evidence.protected_process_closure.passes) pass.holders = [];
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
  value.evidence.nss.groups.find((group) => group.gid === 731).members.push("bitcoinpir-z-peer");
  value.evidence.nss.users.push({ name: "bitcoinpir-z-peer", primary_gid: 734, supplementary_gids: [731, 734], uid: 733 });
  sortNssEvidence(value.evidence.nss);

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
    ControlGroup: `/system.slice/${peerUnit.unit_name}`,
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
    control_group: peerProperties.ControlGroup,
    invocation_id: peerProperties.InvocationID,
    main_pid: peerProperties.MainPID,
  };
  value.evidence.units.push({
    fragment_sha256: peerFragment.sha256,
    generation_confirmations: [
      clone(peerConfirmation),
      clone(peerConfirmation),
      clone(peerConfirmation),
    ],
    process_identity: {
      capabilities_after: capabilityRecord(),
      capabilities_before: capabilityRecord(),
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
  const holders = [
    clone(value.evidence.protected_process_closure.passes[0].holders[0]),
    protectedHolder({
      controlGroup: peerProperties.ControlGroup,
      gid: 734,
      groups: [731, 734],
      ino: "100",
      pid: 4243,
      startTime: "123457",
      uid: 733,
    }),
  ];
  value.evidence.protected_process_closure.passes = [0, 1].map(() => ({
    holders: clone(holders),
    processes_enumerated: 2,
    threads_examined: 2,
  }));
  value.evidence.protected_process_closure.protected_gids = [731, 732, 734];
  value.evidence.protected_process_closure.protected_uids = [730, 733];

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

test("complete NSS parsers retain every primary GID and canonicalize ASCII names and members", () => {
  assert.deepEqual(
    parsePasswdEnumerationV2([
      "rogue:x:900:731::/nonexistent:/usr/sbin/nologin",
      "Root:x:0:0:root:/root:/bin/sh",
      "",
    ].join("\n")),
    [
      { name: "Root", primary_gid: 0, uid: 0 },
      { name: "rogue", primary_gid: 731, uid: 900 },
    ],
  );
  assert.deepEqual(
    parseGroupEnumerationV2([
      "z-group:x:900:rogue,Root",
      "Root:x:0:",
      "",
    ].join("\n")),
    [
      { gid: 0, members: [], name: "Root" },
      { gid: 900, members: ["Root", "rogue"], name: "z-group" },
    ],
  );
});

test("complete NSS parsers reject ambiguous, noncanonical, or duplicate enumeration records", () => {
  for (const [parse, input, expected] of [
    [parsePasswdEnumerationV2, "root:x:00:0:root:/root:/bin/sh\n", /canonical unsigned decimal/],
    [parsePasswdEnumerationV2, "root:x:0:0:root:/root\n", /seven fields/],
    [parsePasswdEnumerationV2, "root:x:0:0:root:/root:/bin/sh\nroot:x:1:1::/:/bin/false\n", /repeats a user name/],
    [parseGroupEnumerationV2, "root:x:0:root,root\n", /duplicate or excessive members/],
    [parseGroupEnumerationV2, "root:x:0:\r\n", /malformed or oversized/],
  ]) {
    assert.throws(() => parse(input), expected);
  }
});

test("NSS policy accepts only local files with inherited initgroups", () => {
  assert.deepEqual(
    parseLocalFilesNsswitchV1([
      "passwd: files",
      "group: files # local groups are the sole authority",
      "hosts: files dns",
      "",
    ].join("\n")),
    {
      group: ["files"],
      initgroups: "inherits-group",
      passwd: ["files"],
    },
  );
  for (const input of [
    "passwd: files systemd\ngroup: files\n",
    "passwd: files\ngroup: files sss\n",
    "passwd: files\ngroup: files\ninitgroups: files\n",
    "passwd: files\npasswd: files\ngroup: files\n",
    "passwd: files\ngroup: files [SUCCESS=merge] systemd\n",
    "passwd: compat\ngroup: compat\n",
  ]) {
    assert.throws(
      () => parseLocalFilesNsswitchV1(input),
      /local-files-only|repeats|simple local profile/,
    );
  }
});

test("final NSS policy confirmation rejects identity or policy drift after enumeration", () => {
  const nss = fixture().evidence.nss;
  assert.equal(assertLocalFilesNssPolicyUnchanged(nss, localFilesPolicySnapshot(nss)), true);

  const changedPolicy = localFilesPolicySnapshot(nss);
  changedPolicy.evidence.group_file.sha256 = hash("changed-group-file");
  assert.throws(
    () => assertLocalFilesNssPolicyUnchanged(nss, changedPolicy),
    /changed after complete enumeration/,
  );

  const changedIdentity = localFilesPolicySnapshot(nss);
  changedIdentity.passwdRecords[0].uid += 1;
  assert.throws(
    () => assertLocalFilesNssPolicyUnchanged(nss, changedIdentity),
    /changed after complete enumeration/,
  );
});

test(
  "Linux smoke exercises real getent enumeration and id -G for every visible user",
  { skip: process.platform !== "linux" },
  () => {
    const nss = collectVisibleNssEvidenceV2();
    assert.equal(nss.enumeration_kind, NSS_ENUMERATION_KIND);
    assert.ok(nss.users.length > 0);
    assert.ok(nss.groups.length > 0);
    for (const user of nss.users) {
      assert.ok(user.supplementary_gids.includes(user.primary_gid));
    }
  },
);

test(
  "Linux smoke performs two complete bounded procfs thread-credential passes",
  { skip: process.platform !== "linux" },
  () => {
    const closure = collectProtectedCredentialProcessClosureV1({
      protectedGids: [],
      protectedUids: [],
    });
    assert.equal(closure.enumeration_kind, PROTECTED_PROCESS_ENUMERATION_KIND);
    assert.equal(closure.passes.length, 2);
    for (const pass of closure.passes) {
      assert.ok(pass.processes_enumerated >= 1);
      assert.ok(pass.threads_examined >= pass.processes_enumerated);
      assert.deepEqual(pass.holders, []);
    }
  },
);

test("procfs status treats repeated supplementary GIDs as one kernel credential set", () => {
  const identity = parseProcStatus(
    Buffer.from([
      "Tgid:\t42",
      "Pid:\t42",
      "Uid:\t730\t730\t730\t730",
      "Gid:\t731\t731\t731\t731",
      "Groups:\t732 731 732 731",
      "CapInh:\t0000000000000000",
      "CapPrm:\t0000000000000000",
      "CapEff:\t0000000000000000",
      "CapBnd:\t0000000000000400",
      "CapAmb:\t0000000000000000",
      "",
    ].join("\n")),
    42,
    { expectedTgid: 42, label: "test proc status" },
  );
  assert.deepEqual(identity.groups, [731, 732]);
  assert.deepEqual(identity.capabilities, capabilityRecord({
    bounding: "0000000000000400",
  }));
  assert.equal(identity.setidCapabilities, false);

  const setidIdentity = parseProcStatus(
    Buffer.from([
      "Tgid:\t43",
      "Pid:\t43",
      "Uid:\t730\t730\t730\t730",
      "Gid:\t731\t731\t731\t731",
      "Groups:\t731",
      "CapInh:\t0000000000000000",
      "CapPrm:\t00000000000000c0",
      "CapEff:\t0000000000000000",
      "CapBnd:\t00000000000000c0",
      "CapAmb:\t0000000000000000",
      "",
    ].join("\n")),
    43,
    { expectedTgid: 43, label: "setid proc status" },
  );
  assert.equal(setidIdentity.setidCapabilities, true);
});

test("non-root capability closure rejects file-permission and credential bypass powers", () => {
  for (const [name, mask] of [
    ["CAP_CHOWN", "0000000000000001"],
    ["CAP_DAC_OVERRIDE", "0000000000000002"],
    ["CAP_FOWNER", "0000000000000008"],
    ["CAP_SETFCAP", "0000000080000000"],
  ]) {
    assert.throws(
      () => validateNonRootEdgeCapabilitiesV1({
        capabilities: capabilityRecord({ effective: mask }),
        uid: [730, 730, 730, 730],
      }, 42, 42),
      /dangerous edge capabilities/,
      name,
    );
  }
  assert.equal(
    validateNonRootEdgeCapabilitiesV1({
      capabilities: capabilityRecord({
        ambient: "0000000000000400",
        bounding: "0000000000000400",
        effective: "0000000000000400",
        permitted: "0000000000000400",
      }),
      uid: [730, 730, 730, 730],
    }, 43, 43),
    true,
  );

  const caddy = fixture();
  const caddyUnitName = "bitcoinpir-payment-v1-public-edge.service";
  const caddyControlGroup = `/system.slice/${caddyUnitName}`;
  caddy.request.units[0].unit_name = caddyUnitName;
  caddy.request.units[0].hardening.AmbientCapabilities = ["CAP_NET_BIND_SERVICE"];
  caddy.request.units[0].hardening.CapabilityBoundingSet = ["CAP_NET_BIND_SERVICE"];
  caddy.request.service_identities[0].unit_name = caddyUnitName;
  caddy.evidence.units[0].unit_name = caddyUnitName;
  caddy.evidence.units[0].properties.ControlGroup = caddyControlGroup;
  caddy.evidence.units[0].properties.AmbientCapabilities = "CAP_NET_BIND_SERVICE";
  caddy.evidence.units[0].properties.CapabilityBoundingSet = "CAP_NET_BIND_SERVICE";
  for (const confirmation of caddy.evidence.units[0].generation_confirmations) {
    confirmation.control_group = caddyControlGroup;
  }
  const caddyCapabilities = capabilityRecord({
    ambient: "0000000000000400",
    bounding: "0000000000000400",
    effective: "0000000000000400",
    permitted: "0000000000000400",
  });
  caddy.evidence.units[0].process_identity.capabilities_before = clone(caddyCapabilities);
  caddy.evidence.units[0].process_identity.capabilities_after = clone(caddyCapabilities);
  for (const pass of caddy.evidence.protected_process_closure.passes) {
    pass.holders[0].control_group = caddyControlGroup;
    pass.holders[0].capabilities = clone(caddyCapabilities);
  }
  assert.equal(validate(caddy), true);
});

test("service-account policy requires pinned IDs, nologin shell, and a locked shadow password", () => {
  const identities = [{
    gid: 731,
    group_name: "bitcoinpir-test",
    uid: 730,
    unit_name: "bitcoinpir-test.service",
    user_name: "bitcoinpir-test",
  }];
  assert.deepEqual(
    parseLockedServiceAccountPolicyV1(
      "root:x:0:0:root:/root:/bin/bash\nbitcoinpir-test:x:730:731::/nonexistent:/usr/sbin/nologin\n",
      "root:*:1:0:99999:7:::\nbitcoinpir-test:!:1:0:99999:7:::\n",
      identities,
    ),
    [{
      gid: 731,
      password_state: "locked",
      shell: "/usr/sbin/nologin",
      uid: 730,
      user_name: "bitcoinpir-test",
    }],
  );
  assert.throws(
    () => parseLockedServiceAccountPolicyV1(
      "bitcoinpir-test:x:730:731::/home/test:/bin/bash\n",
      "bitcoinpir-test:secret:1:0:99999:7:::\n",
      identities,
    ),
    /login-disabled, and password-locked/,
  );
});

test("stopped-edge activation evidence closes units, sockets, identities, and login reacquisition", () => {
  const value = stoppedEdgeFixture();
  assert.equal(validateStopped(value), true);

  const active = stoppedEdgeFixture();
  active.evidence.stopped_unit_passes[1][0].active_state = "active";
  assert.throws(() => validateStopped(active), /not fully stopped/);

  const holder = stoppedEdgeFixture();
  holder.evidence.protected_process_closure.passes[0].holders.push(protectedHolder({
    controlGroup: "/user.slice/rogue.service",
    gid: 731,
    groups: [731],
    ino: "999",
    pid: 999,
    startTime: "888",
    uid: 730,
  }));
  assert.throws(() => validateStopped(holder), /protected credential holder/);

  const login = stoppedEdgeFixture();
  login.evidence.account_policy.accounts[0].shell = "/bin/bash";
  assert.throws(() => validateStopped(login), /not locked and login-disabled/);

  const socket = stoppedEdgeFixture();
  socket.evidence.runtime_socket_absence_passes[1][0].parent_ino = "201";
  assert.throws(() => validateStopped(socket), /absence changed/);

  const namespace = stoppedEdgeFixture();
  namespace.evidence.host.collector_pid_namespace = "pid:[4026539999]";
  assert.throws(() => validateStopped(namespace), /PID namespace/);

  const legacy = stoppedEdgeFixture();
  legacy.evidence.protected_process_closure.enumeration_kind =
    "procfs-v2-all-thread-credentials-two-pass-v1";
  assert.throws(() => validateStopped(legacy), /closure is incomplete/);

  const legacySchema = stoppedEdgeFixture();
  legacySchema.evidence.schema_version = 1;
  assert.throws(() => validateStopped(legacySchema), /evidence schema, collector/);
});

test("live verifier closes protected NSS primary, explicit, effective, UID, and GID aliases", () => {
  const roguePrimary = fixture();
  roguePrimary.evidence.nss.users.push({
    name: "rogue",
    primary_gid: 731,
    supplementary_gids: [731],
    uid: 900,
  });
  sortNssEvidence(roguePrimary.evidence.nss);
  assert.throws(() => validate(roguePrimary), /protected primary-GID holder drift/);

  const uidAlias = fixture();
  uidAlias.evidence.nss.groups.push({ gid: 900, members: [], name: "rogue" });
  uidAlias.evidence.nss.users.push({
    name: "rogue",
    primary_gid: 900,
    supplementary_gids: [900],
    uid: 730,
  });
  sortNssEvidence(uidAlias.evidence.nss);
  assert.throws(() => validate(uidAlias), /aliases a UID/);

  const gidAlias = fixture();
  gidAlias.evidence.nss.groups.push({ gid: 731, members: [], name: "rogue" });
  sortNssEvidence(gidAlias.evidence.nss);
  assert.throws(() => validate(gidAlias), /aliases a GID/);

  const rogueMember = fixture();
  rogueMember.evidence.nss.groups.push({ gid: 900, members: [], name: "rogue" });
  rogueMember.evidence.nss.groups.find((group) => group.gid === 732).members.push("rogue");
  rogueMember.evidence.nss.users.push({
    name: "rogue",
    primary_gid: 900,
    supplementary_gids: [732, 900],
    uid: 900,
  });
  sortNssEvidence(rogueMember.evidence.nss);
  assert.throws(
    () => validate(rogueMember),
    /protected explicit group membership drift|protected effective group membership drift/,
  );
});

test("live verifier closes stale protected UID/GID holders across every procfs thread", () => {
  const managedWorker = fixture();
  const worker = protectedHolder({
    controlGroup: "/system.slice/bitcoinpir-test.service",
    gid: 731,
    groups: [731, 732],
    ino: "101",
    pid: 4243,
    startTime: "123457",
    uid: 730,
  });
  for (const pass of managedWorker.evidence.protected_process_closure.passes) {
    pass.holders.push(clone(worker));
    pass.processes_enumerated += 1;
    pass.threads_examined += 1;
  }
  assert.equal(validate(managedWorker), true);

  const staleHolder = fixture();
  const rogue = protectedHolder({
    controlGroup: "/system.slice/unmanaged.service",
    gid: 900,
    groups: [732, 900],
    ino: "102",
    pid: 5000,
    startTime: "123458",
    uid: 900,
  });
  for (const pass of staleHolder.evidence.protected_process_closure.passes) {
    pass.holders.push(clone(rogue));
    pass.processes_enumerated += 1;
    pass.threads_examined += 1;
  }
  assert.throws(() => validate(staleHolder), /outside every managed unit cgroup/);

  const omittedMain = fixture();
  for (const pass of omittedMain.evidence.protected_process_closure.passes) {
    pass.holders = [clone(worker)];
  }
  assert.throws(() => validate(omittedMain), /omits managed MainPID/);

  const wrongUid = fixture();
  for (const pass of wrongUid.evidence.protected_process_closure.passes) {
    pass.holders[0].uid = [733, 733, 733, 733];
  }
  assert.throws(() => validate(wrongUid), /protected holder UID/);

  const dangerousHolder = fixture();
  for (const pass of dangerousHolder.evidence.protected_process_closure.passes) {
    pass.holders[0].capabilities.effective = "0000000000000002";
  }
  assert.throws(() => validate(dangerousHolder), /dangerous edge capabilities/);

  const dangerousMain = fixture();
  dangerousMain.evidence.units[0].process_identity.capabilities_before.effective =
    "0000000000000008";
  dangerousMain.evidence.units[0].process_identity.capabilities_after.effective =
    "0000000000000008";
  assert.throws(() => validate(dangerousMain), /dangerous edge capabilities/);

  const unconfiguredNetBind = fixture();
  for (const key of ["capabilities_before", "capabilities_after"]) {
    unconfiguredNetBind.evidence.units[0].process_identity[key] = capabilityRecord({
      bounding: "0000000000000400",
      effective: "0000000000000400",
      permitted: "0000000000000400",
    });
  }
  assert.throws(() => validate(unconfiguredNetBind), /exceed the reviewed bounding set/);

  const nonCaddyConfiguredNetBind = fixture();
  nonCaddyConfiguredNetBind.request.units[0].hardening.AmbientCapabilities = [
    "CAP_NET_BIND_SERVICE",
  ];
  nonCaddyConfiguredNetBind.request.units[0].hardening.CapabilityBoundingSet = [
    "CAP_NET_BIND_SERVICE",
  ];
  nonCaddyConfiguredNetBind.evidence.units[0].properties.AmbientCapabilities =
    "CAP_NET_BIND_SERVICE";
  nonCaddyConfiguredNetBind.evidence.units[0].properties.CapabilityBoundingSet =
    "CAP_NET_BIND_SERVICE";
  assert.throws(
    () => validate(nonCaddyConfiguredNetBind),
    /not a reviewed Caddy capability-bearing unit/,
  );

  const racedPass = fixture();
  racedPass.evidence.protected_process_closure.passes[1].holders[0].proc_directory_ino = "103";
  assert.throws(() => validate(racedPass), /holders changed between complete procfs passes/);

  const legacy = fixture();
  delete legacy.evidence.protected_process_closure;
  assert.throws(() => validate(legacy), /live runtime evidence keys/);
});

test("live verifier rejects omitted service identities and noncanonical complete NSS evidence", () => {
  const omitted = fixture();
  omitted.evidence.nss.users = omitted.evidence.nss.users.filter(
    (user) => user.name !== "bitcoinpir-test",
  );
  omitted.evidence.nss.groups.find((group) => group.gid === 732).members = [];
  assert.throws(
    () => validate(omitted),
    /tmpfiles directory NSS owner drift|primary identity drift/,
  );

  const unsortedUsers = fixture();
  unsortedUsers.evidence.nss.users.reverse();
  assert.throws(() => validate(unsortedUsers), /not canonically sorted/);

  const unsortedGroups = fixture();
  unsortedGroups.evidence.nss.groups.reverse();
  assert.throws(() => validate(unsortedGroups), /not canonically sorted/);

  const duplicateMember = fixture();
  duplicateMember.evidence.nss.groups[0].members.push("bitcoinpir-test");
  assert.throws(() => validate(duplicateMember), /group data is malformed/);

  const invalidUid = fixture();
  invalidUid.evidence.nss.users[0].uid = -1;
  assert.throws(() => validate(invalidUid), /user data is malformed/);

  const oversizedName = fixture();
  oversizedName.evidence.nss.users[0].name = `a${"b".repeat(128)}`;
  assert.throws(() => validate(oversizedName), /bounded canonical NSS name/);

  const duplicateSupplementary = fixture();
  duplicateSupplementary.evidence.nss.users[0].supplementary_gids.push(732);
  assert.throws(() => validate(duplicateSupplementary), /user data is malformed/);

  const unknownMember = fixture();
  unknownMember.evidence.nss.groups[0].members.push("rogue");
  assert.throws(() => validate(unknownMember), /group membership is inconsistent/);

  const maximumId = fixture();
  maximumId.evidence.nss.groups.push({ gid: 0xffff_ffff, members: [], name: "z-max" });
  maximumId.evidence.nss.users.push({
    name: "z-max",
    primary_gid: 0xffff_ffff,
    supplementary_gids: [0xffff_ffff],
    uid: 0xffff_ffff,
  });
  sortNssEvidence(maximumId.evidence.nss);
  assert.equal(validate(maximumId), true);

  const overflowingId = fixture();
  overflowingId.evidence.nss.groups.push({
    gid: 0x1_0000_0000,
    members: [],
    name: "z-overflow",
  });
  sortNssEvidence(overflowingId.evidence.nss);
  assert.throws(() => validate(overflowingId), /group data is malformed/);

  const excessiveUsers = fixture();
  for (let index = 0; index < 4095; index += 1) {
    excessiveUsers.evidence.nss.users.push({
      name: `u${String(index).padStart(4, "0")}`,
      primary_gid: 0,
      supplementary_gids: [0],
      uid: 1000 + index,
    });
  }
  sortNssEvidence(excessiveUsers.evidence.nss);
  assert.throws(() => validate(excessiveUsers), /record or byte bound/);

  const excessiveMembers = fixture();
  excessiveMembers.evidence.nss.groups.find((group) => group.gid === 0).members =
    Array.from({ length: 4097 }, (_, index) => `u${String(index).padStart(4, "0")}`);
  assert.throws(() => validate(excessiveMembers), /group data is malformed/);
});

test("live verifier rejects legacy request/evidence and untrusted NSS policy metadata", () => {
  const legacyEvidence = fixture();
  legacyEvidence.evidence.schema_version = 2;
  assert.throws(() => validate(legacyEvidence), /schema or kind/);

  const legacyRequest = fixture();
  legacyRequest.request.schema_version = 2;
  assert.throws(() => validate(legacyRequest), /request schema or collector/);

  const remoteBackend = fixture();
  remoteBackend.evidence.nss.sources.passwd.push("sss");
  assert.throws(() => validate(remoteBackend), /local-files-only profile/);

  const writablePolicy = fixture();
  writablePolicy.evidence.nss.nsswitch_file.mode = "0664";
  assert.throws(() => validate(writablePolicy), /metadata is not trusted/);

  const specialPolicy = fixture();
  specialPolicy.evidence.nss.group_file.mode = "4644";
  assert.throws(() => validate(specialPolicy), /metadata is not trusted/);

  const wrongPolicyPath = fixture();
  wrongPolicyPath.evidence.nss.passwd_file.path = "/tmp/passwd";
  assert.throws(() => validate(wrongPolicyPath), /metadata is not trusted/);
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
  ["foreign PID namespace", (f) => { f.evidence.host.collector_pid_namespace = "pid:[4026532557]"; }, /visible systemd PID namespace root/],
  ["non-systemd PID 1", (f) => { f.evidence.host.pid1_name = "sh"; }, /visible systemd PID namespace root/],
  ["ExecStart reset", (f) => { f.evidence.units[0].properties.ExecStart = execValue("/usr/bin/true"); }, /ExecStart drift/],
  ["ExecStartPost", (f) => { f.evidence.units[0].properties.ExecStartPost = execValue("/usr/bin/true"); }, /ExecStartPost/],
  ["EnvironmentFile", (f) => { f.evidence.units[0].properties.EnvironmentFiles = "/tmp/evil"; }, /EnvironmentFiles/],
  ["credential", (f) => { f.evidence.units[0].properties.LoadCredential = "secret:/tmp/evil"; }, /LoadCredential/],
  ["root image", (f) => { f.evidence.units[0].properties.RootImage = "/tmp/root.img"; }, /RootImage/],
  ["file hash", (f) => { f.evidence.installed_files[0].sha256 = hash("evil"); }, /sha256 drift/],
  ["tmpfiles mode", (f) => { f.evidence.runtime_directories[0].mode = "0777"; }, /tmpfiles directory drift/],
  ["tmpfiles UID", (f) => { f.evidence.runtime_directories[0].uid = 999; }, /tmpfiles directory NSS owner drift/],
  ["tmpfiles GID", (f) => { f.evidence.runtime_directories[0].gid = 999; }, /tmpfiles directory NSS owner drift/],
  ["tmpfiles evidence type", (f) => { f.evidence.runtime_directories[0].expected_type = "socket"; }, /tmpfiles directory drift/],
  ["runtime socket mode", (f) => { f.evidence.runtime_paths[0].mode = "0666"; }, /runtime path mode drift/],
  ["unexpected issuer group", (f) => { f.evidence.nss.users[0].supplementary_gids.push(999); }, /unexpected supplementary group|reverse group membership/],
  ["inactive unit", (f) => { f.evidence.units[0].properties.ActiveState = "inactive"; }, /not active/],
  ["ControlGroup drift", (f) => { f.evidence.units[0].properties.ControlGroup = "/system.slice/evil.service"; }, /reviewed system\.slice control group/],
  ["zero MainPID", (f) => { f.evidence.units[0].properties.MainPID = "0"; }, /no active MainPID/],
  ["effective Restart drift", (f) => { f.evidence.units[0].properties.Restart = "on-failure"; }, /Restart drift/],
  ["effective LimitCORE drift", (f) => { f.evidence.units[0].properties.LimitCORE = "infinity"; }, /LimitCORE drift/],
  ["effective LimitCORESoft drift", (f) => { f.evidence.units[0].properties.LimitCORESoft = "infinity"; }, /LimitCORESoft drift/],
  ["effective MemoryMax drift", (f) => { f.evidence.units[0].properties.MemoryMax = "infinity"; }, /MemoryMax drift/],
  ["effective MemorySwapCurrent drift", (f) => { f.evidence.units[0].properties.MemorySwapCurrent = "1"; }, /MemorySwapCurrent drift/],
  ["effective MemorySwapMax drift", (f) => { f.evidence.units[0].properties.MemorySwapMax = "infinity"; }, /MemorySwapMax drift/],
  ["effective TasksMax drift", (f) => { f.evidence.units[0].properties.TasksMax = "infinity"; }, /TasksMax drift/],
  ["effective StandardOutput drift", (f) => { f.evidence.units[0].properties.StandardOutput = "journal"; }, /StandardOutput drift/],
  ["effective StandardError drift", (f) => { f.evidence.units[0].properties.StandardError = "journal"; }, /StandardError drift/],
  ["MainPID confirmation race", (f) => { f.evidence.units[0].generation_confirmations[1].main_pid = "4243"; }, /unit generation changed/],
  ["InvocationID generation race", (f) => { f.evidence.units[0].generation_confirmations[1].invocation_id = "b".repeat(32); }, /unit generation changed/],
  ["final ControlGroup confirmation race", (f) => { f.evidence.units[0].generation_confirmations[2].control_group = "/system.slice/evil.service"; }, /unit generation changed/],
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

test("edge live evidence rejects a core pipe that can persist request-source memory", () => {
  const value = fixture();
  value.request.deployment_profile = "edge-hetzner-v1";
  value.evidence.host.core_pattern = "|/usr/lib/systemd/systemd-coredump";
  assert.throws(() => validate(value), /kernel\.core_pattern=\|\/usr\/bin\/false/);
});

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
  const stoppedCallerJson = spawnSync(process.execPath, [COLLECTOR, "collect-stopped-edge", ...base, "--output", "/tmp/output", "--evidence", "/tmp/forged.json"], { encoding: "utf8" });
  assert.notEqual(stoppedCallerJson.status, 0);
  assert.match(stoppedCallerJson.stderr, /collect-stopped-edge forbids caller evidence/);
  const stoppedOffline = spawnSync(process.execPath, [COLLECTOR, "verify-stopped-edge-offline", ...base, "--evidence", "/tmp/forged.json", "--expected-boot-id", "12345678-1234-4abc-8def-123456789abc"], { encoding: "utf8" });
  assert.notEqual(stoppedOffline.status, 0);
  assert.match(stoppedOffline.stderr, /trusted-evidence-sha256/);
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
