import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  assertEffectiveConditionSnapshotUnchangedV1,
  assertEffectiveCredentialSnapshotUnchangedV1,
  assertCompleteNssSnapshotUnchangedV2,
  assertEffectiveSystemdPolicySnapshotUnchangedV1,
  assertLocalFilesNssPolicyUnchanged,
  LIVE_EVIDENCE_KIND,
  STOPPED_EDGE_EVIDENCE_KIND,
  STOPPED_RELAY_EVIDENCE_KIND,
  NSS_BACKEND_PROFILE,
  NSS_ENUMERATION_KIND,
  PROTECTED_PROCESS_ENUMERATION_KIND,
  collectInstalledFileForTestV1,
  computePublisherArtifactEventSetForTestV1,
  confirmInstalledFileAcrossCollectionsForTestV1,
  confirmDescriptorBoundCommandPinsForTestV1,
  collectSecretParentDirectoryForTestV1,
  confirmSecretParentDirectoryAcrossCollectionsForTestV1,
  collectProtectedCredentialProcessClosureV1,
  collectVisibleNssEvidenceV2,
  parseGroupEnumerationV2,
  parseBusctlConditionsJsonV1,
  parseBusctlBooleanJsonV1,
  parseBusctlExecCommandExJsonV1,
  parseBusctlExecStartPreExJsonV1,
  parseBusctlEmptyCredentialJsonV1,
  parseBusctlStringJsonV1,
  parseBusctlUnitNamesJsonV1,
  parseBusctlUnsignedJsonV1,
  parseBusctlWatchdogUsecJsonV2,
  parseLocalFilesNsswitchV1,
  parseLockedServiceAccountPolicyV1,
  parsePasswdEnumerationV2,
  parseProcStatus,
  parseSystemctlExecArgvV1,
  systemdCredentialBusctlArgvV1,
  systemdUnitObjectPathV1,
  readOneLinkRegular,
  readOneLinkRegularForTestV1,
  runDescriptorBoundCommandForTestV1,
  runDescriptorBoundSetprivProbeForTestV1,
  validateNonRootEdgeCapabilitiesV1,
  validatePublisherNetworkRuntimeEvidenceV1,
  validateLiveRuntimeEvidence,
  validateStoppedEdgeActivationEvidence,
  validateStoppedRelayPreparationEvidence,
} from "./payment-v1-linux-runtime-evidence.mjs";
import {
  canonicalJson,
  computeDirectoryPublishArgvSha256V1,
  REVIEWED_SYSTEMD_MANAGER_VERSION,
  REVIEWED_SYSTEMD_VERSION,
  RUNTIME_BUSCTL_MANAGER_PROPERTIES,
  RUNTIME_BUSCTL_SERVICE_PROPERTIES,
  RUNTIME_BUSCTL_UNIT_PROPERTIES,
  RUNTIME_COLLECTOR,
  RUNTIME_SYSTEMCTL_SHOW_PROPERTIES,
} from "./payment-v1-rendered-artifact-gate.mjs";
import { PUBLISHER_FIREWALL_OUTPUT_KEYS } from "./payment-v1-publisher-netns-gate.mjs";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const COLLECTOR = join(SCRIPT_DIRECTORY, "payment-v1-linux-runtime-evidence.mjs");
const RENDERED_GATE = join(
  SCRIPT_DIRECTORY,
  "payment-v1-rendered-artifact-gate.mjs",
);
const TEMPLATE_GATE = join(
  SCRIPT_DIRECTORY,
  "payment-v1-deployment-template-gate.mjs",
);
const PUBLISHER_GATE = join(
  SCRIPT_DIRECTORY,
  "payment-v1-publisher-netns-gate.mjs",
);
const DIRECTORY_PUBLIC_HAPROXY_GATE = join(
  SCRIPT_DIRECTORY,
  "payment-v1-directory-public-haproxy-artifact-gate.mjs",
);
const REVIEWED_RUNTIME_EVIDENCE_MODULE_PATHS = new Set([
  COLLECTOR,
  RENDERED_GATE,
  TEMPLATE_GATE,
  PUBLISHER_GATE,
  DIRECTORY_PUBLIC_HAPROXY_GATE,
]);
const UINT64_MAX_DECIMAL = "18446744073709551615";
assert.equal(
  REVIEWED_SYSTEMD_VERSION,
  `systemd 255 (${REVIEWED_SYSTEMD_MANAGER_VERSION})`,
  "systemctl client and PID 1 manager build pins must remain coherent",
);
const COMMANDS = [
  "/usr/bin/busctl",
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
  "/usr/bin/unlink",
  "/usr/bin/uname",
  "/usr/sbin/getcap",
];
const INSTALLED_FILE_PROBE_COMMANDS = [
  "/usr/bin/getfacl",
  "/usr/bin/getfattr",
  "/usr/bin/sha256sum",
  "/usr/bin/stat",
  "/usr/bin/touch",
  "/usr/sbin/getcap",
];
const CAN_EXERCISE_INSTALLED_FILE_PROBES =
  process.platform === "linux" && INSTALLED_FILE_PROBE_COMMANDS.every(existsSync);
const CREDENTIAL_SERVICE_PROPERTIES = Object.freeze([
  "ImportCredential",
  "LoadCredential",
  "LoadCredentialEncrypted",
  "SetCredential",
  "SetCredentialEncrypted",
]);
const CAN_EXERCISE_DESCRIPTOR_COMMANDS =
  process.platform === "linux" &&
  existsSync("/proc/self/fd") &&
  existsSync("/usr/bin/true");
const CAN_EXERCISE_DESCRIPTOR_SETPRIV =
  CAN_EXERCISE_DESCRIPTOR_COMMANDS &&
  process.geteuid?.() === 0 &&
  existsSync("/usr/bin/setpriv") &&
  existsSync("/usr/bin/test");

function hash(value) {
  return createHash("sha256").update(value).digest("hex");
}

function clone(value) {
  return structuredClone(value);
}

function emptyCredentialProperties() {
  return {
    ImportCredential: { data: [], type: "as" },
    LoadCredential: { data: [], type: "a(ss)" },
    LoadCredentialEncrypted: { data: [], type: "a(ss)" },
    SetCredential: { data: [], type: "a(say)" },
    SetCredentialEncrypted: { data: [], type: "a(say)" },
  };
}

function staticModuleRequests(source, label) {
  const parser = String.raw`
    const { readFileSync } = require("node:fs");
    const { SourceTextModule } = require("node:vm");
    const parsedModule = new SourceTextModule(readFileSync(0, "utf8"));
    process.stdout.write(JSON.stringify(parsedModule.moduleRequests));
  `;
  const result = spawnSync(
    process.execPath,
    ["--experimental-vm-modules", "--no-warnings", "-e", parser],
    { encoding: "utf8", input: source, maxBuffer: 2 * 1024 * 1024 },
  );
  assert.equal(result.status, 0, `${label} must parse as ESM: ${result.stderr}`);
  assert.equal(result.signal, null, `${label} ESM parser was interrupted`);
  return JSON.parse(result.stdout);
}

function assertStaticModuleRequestShapeV1(request, label) {
  const keys = Object.keys(request).sort();
  const node22Keys = ["attributes", "specifier"];
  const node24Keys = ["attributes", "phase", "specifier"];
  assert.ok(
    [node22Keys, node24Keys].some(
      (expected) => JSON.stringify(keys) === JSON.stringify(expected),
    ),
    `${label} static module request shape changed`,
  );
  if (Object.hasOwn(request, "phase")) {
    assert.equal(
      request.phase,
      "evaluation",
      `${label} static module request phase must remain evaluation`,
    );
  }
  assert.deepEqual(
    request.attributes,
    {},
    `${label} static module request attributes must remain empty`,
  );
  assert.equal(typeof request.specifier, "string", `${label} specifier must be a string`);
}

function assertExactStaticModuleRequests(
  source,
  expected,
  modulePath,
  label = modulePath,
) {
  const builtins = [];
  const locals = [];
  for (const request of staticModuleRequests(source, label)) {
    assertStaticModuleRequestShapeV1(request, label);
    if (request.specifier.startsWith("node:")) {
      builtins.push(request.specifier);
      continue;
    }
    if (request.specifier.startsWith("./")) {
      const resolved = resolve(dirname(modulePath), request.specifier);
      assert.ok(
        REVIEWED_RUNTIME_EVIDENCE_MODULE_PATHS.has(resolved),
        `${label} local static module request leaves the reviewed five-file closure: ${request.specifier}`,
      );
      locals.push(request.specifier);
      continue;
    }
    assert.fail(`${label} contains an unreviewed static module request: ${request.specifier}`);
  }
  assert.deepEqual(
    builtins.sort(),
    [...expected.builtins].sort(),
    `${label} static Node builtin request set changed`,
  );
  assert.deepEqual(
    locals.sort(),
    [...expected.locals].sort(),
    `${label} local static module edge set changed`,
  );
}

function installedFileExpectation(path, bytes) {
  const stat = lstatSync(path, { bigint: true });
  return {
    gid: Number(stat.gid),
    mode: Number(stat.mode & 0o7777n).toString(8).padStart(4, "0"),
    nlink: Number(stat.nlink),
    sha256: hash(bytes),
    target_path: path,
    uid: Number(stat.uid),
  };
}

function createExactTimestampReference(root, target) {
  const reference = join(root, "timestamp-reference");
  writeFileSync(reference, "timestamp reference\n", { mode: 0o600 });
  const result = spawnSync("/usr/bin/touch", ["-r", target, "--", reference], {
    encoding: "utf8",
    shell: false,
  });
  assert.equal(result.status, 0, result.stderr);
  return reference;
}

function restoreExactTimestamps(reference, target) {
  const result = spawnSync("/usr/bin/touch", ["-r", reference, "--", target], {
    encoding: "utf8",
    shell: false,
  });
  assert.equal(result.status, 0, result.stderr);
}

function createExactDirectory(path, mode = 0o700) {
  mkdirSync(path, { mode });
  chmodSync(path, mode);
}

function directoryAbaHooks({ alternate, alternateParked, mutationParent, parked, target }) {
  return {
    afterMetadataProbe: () => {
      renameSync(target, alternateParked);
      renameSync(parked, target);
      // Make the parent mutation deterministic even on filesystems whose
      // directory timestamp granularity is coarser than the two renames.
      utimesSync(mutationParent, new Date(1_000), new Date(2_000));
    },
    afterPinnedChain: () => {
      renameSync(target, parked);
      renameSync(alternate, target);
    },
  };
}

test("systemd Conditions use the reviewed busctl object path and strict a(sbbsi) schema", () => {
  assert.equal(
    systemdUnitObjectPathV1("bitcoinpir-provider-direct.service"),
    "/org/freedesktop/systemd1/unit/bitcoinpir_2dprovider_2ddirect_2eservice",
  );
  const direct = "/etc/bitcoinpir/payment-v1/PROVIDER-DIRECT-ACTIVATION-APPROVED";
  const standard = "/etc/bitcoinpir/payment-v1/PROVIDER-ACTIVATION-APPROVED";
  const parsed = parseBusctlConditionsJsonV1(`${JSON.stringify({
    type: "a(sbbsi)",
    data: [
      ["ConditionPathExists", false, true, standard, 1],
      ["ConditionPathExists", false, false, direct, 1],
    ],
  })}\n`);
  assert.deepEqual(parsed, [
    {
      negate: true,
      parameter: standard,
      result: 1,
      trigger: false,
      type: "ConditionPathExists",
    },
    {
      negate: false,
      parameter: direct,
      result: 1,
      trigger: false,
      type: "ConditionPathExists",
    },
  ]);

  for (const [label, value] of [
    ["wrong signature", { type: "a(ss)", data: [] }],
    ["extra top-level key", { type: "a(sbbsi)", data: [], extra: true }],
    ["foreign condition type", { type: "a(sbbsi)", data: [["ConditionKernelCommandLine", false, false, direct, 1]] }],
    ["noncanonical path", { type: "a(sbbsi)", data: [["ConditionPathExists", false, false, "/etc/../tmp/x", 1]] }],
    ["invalid result", { type: "a(sbbsi)", data: [["ConditionPathExists", false, false, direct, 2]] }],
    ["short tuple", { type: "a(sbbsi)", data: [["ConditionPathExists", false, false, direct]] }],
    ["duplicate", { type: "a(sbbsi)", data: [
      ["ConditionPathExists", false, false, direct, 1],
      ["ConditionPathExists", false, false, direct, 1],
    ] }],
  ]) {
    assert.throws(
      () => parseBusctlConditionsJsonV1(JSON.stringify(value), label),
      /reviewed|duplicate|keys|shape/,
      label,
    );
  }
  assert.throws(() => systemdUnitObjectPathV1("../evil.service"), /cannot be mapped/);

  assert.equal(assertEffectiveConditionSnapshotUnchangedV1(parsed, clone(parsed), "direct"), true);
  const changed = clone(parsed);
  changed[0].result = 0;
  assert.throws(
    () => assertEffectiveConditionSnapshotUnchangedV1(parsed, changed, "direct"),
    /conditions changed during live collection: direct/,
  );
  assert.throws(
    () => assertEffectiveConditionSnapshotUnchangedV1(parsed, undefined, "direct"),
    /snapshots are incomplete/,
  );
});

test("systemd dependencies, commands, booleans and timeouts use strict typed busctl values", () => {
  assert.deepEqual(
    parseBusctlUnitNamesJsonV1(JSON.stringify({
      data: ["network-online.target", "basic.target", "dev-disk-by\\x2duuid.device"],
      type: "as",
    })),
    ["basic.target", "dev-disk-by\\x2duuid.device", "network-online.target"],
  );
  assert.equal(
    parseBusctlUnsignedJsonV1(
      JSON.stringify({ data: 30_000_000, type: "t" }),
      "TimeoutStopUSec",
    ),
    "30000000",
  );
  assert.equal(
    parseBusctlUnsignedJsonV1(
      '{"type":"t","data":18446744073709551615}',
      "inactive WatchdogUSec",
    ),
    UINT64_MAX_DECIMAL,
  );
  assert.equal(
    parseBusctlUnsignedJsonV1(
      '{"data":18446744073709551614,"type":"t"}',
      "max minus one",
    ),
    "18446744073709551614",
  );
  assert.notEqual(
    parseBusctlUnsignedJsonV1(
      '{"type":"t","data":9007199254740992}',
      "safe boundary plus one",
    ),
    parseBusctlUnsignedJsonV1(
      '{"type":"t","data":9007199254740993}',
      "unsafe adjacent integer",
    ),
  );
  assert.equal(
    parseBusctlWatchdogUsecJsonV2(
      '{"type":"t","data":18446744073709551615}',
    ),
    "18446744073709551615",
  );
  assert.equal(
    parseBusctlWatchdogUsecJsonV2('{"data":90000000,"type":"t"}'),
    "90000000",
  );
  for (const [label, value] of [
    ["quoted", '{"type":"t","data":"18446744073709551615"}'],
    ["overflow", '{"type":"t","data":18446744073709551616}'],
    ["negative", '{"type":"t","data":-1}'],
    ["noncanonical", '{"type":"t","data":01}'],
    ["wrong signature", '{"type":"u","data":90000000}'],
    ["foreign key", '{"type":"t","data":90000000,"unit":"evil"}'],
  ]) {
    assert.throws(
      () => parseBusctlWatchdogUsecJsonV2(value, label),
      /canonical uint64 t token/,
      label,
    );
  }
  assert.deepEqual(
    parseBusctlBooleanJsonV1(JSON.stringify({ data: true, type: "b" })),
    { signature: "b", value: true },
  );
  assert.deepEqual(
    parseBusctlStringJsonV1(JSON.stringify({
      data: REVIEWED_SYSTEMD_MANAGER_VERSION,
      type: "s",
    })),
    { signature: "s", value: REVIEWED_SYSTEMD_MANAGER_VERSION },
  );
  assert.deepEqual(
    parseBusctlExecCommandExJsonV1(
      '{"type":"a(sasasttttuii)","data":[["/usr/bin/sleep",["/usr/bin/sleep","infinity"],[],1,0,0,0,4242,0,0]]}',
      "ExecStartEx",
    ),
    [{
      argv: ["/usr/bin/sleep", "infinity"],
      flags: [],
      path: "/usr/bin/sleep",
    }],
  );
  const execTuple = [
    "/usr/bin/unlink",
    ["/usr/bin/unlink", "--", "/run/approval"],
    ["privileged"],
    1, 2, 3, 4, 1, 0, 0,
  ];
  assert.deepEqual(
    parseBusctlExecStartPreExJsonV1(JSON.stringify({
      data: [execTuple],
      type: "a(sasasttttuii)",
    })),
    [{
      argv: ["/usr/bin/unlink", "--", "/run/approval"],
      flags: ["privileged"],
      path: "/usr/bin/unlink",
    }],
  );
  // Exact tuple shape observed from systemd 255.4 for ssh.service on the
  // target Ubuntu 24.04 host. This guards against growing a synthetic fixture
  // that no longer matches the real D-Bus signature.
  assert.deepEqual(
    parseBusctlExecStartPreExJsonV1(
      '{"type":"a(sasasttttuii)","data":[["/usr/sbin/sshd",["/usr/sbin/sshd","-t"],[],0,0,0,0,0,0,0]]}',
    ),
    [{
      argv: ["/usr/sbin/sshd", "-t"],
      flags: [],
      path: "/usr/sbin/sshd",
    }],
  );
  assert.throws(
    () => parseBusctlExecStartPreExJsonV1(JSON.stringify({
      data: [[...execTuple, 0]],
      type: "a(sasasttttuii)",
    })),
    /reviewed exec-command tuple/,
  );
  for (const [label, value] of [
    ["wrong boolean type", { data: true, type: "u" }],
    ["nonboolean", { data: 1, type: "b" }],
  ]) {
    assert.throws(
      () => parseBusctlBooleanJsonV1(JSON.stringify(value), label),
      /reviewed b value/,
      label,
    );
  }
  for (const [label, value] of [
    ["wrong string type", { data: REVIEWED_SYSTEMD_MANAGER_VERSION, type: "as" }],
    ["nonstring", { data: 255, type: "s" }],
    ["control character", { data: "255.4\nforeign", type: "s" }],
  ]) {
    assert.throws(
      () => parseBusctlStringJsonV1(JSON.stringify(value), label),
      /printable s value/,
      label,
    );
  }
  for (const [label, value] of [
    ["wrong exec signature", { data: [execTuple], type: "a(sas)" }],
    ["foreign exec flag", { data: [[...execTuple.slice(0, 2), ["ambient"], ...execTuple.slice(3)]], type: "a(sasasttttuii)" }],
    ["path argv mismatch", { data: [["/usr/bin/test", ...execTuple.slice(1)]], type: "a(sasasttttuii)" }],
    ["oversized argv", { data: [["/usr/bin/test", Array(257).fill("x").with(0, "/usr/bin/test"), [], 0, 0, 0, 0, 0, 0, 0]], type: "a(sasasttttuii)" }],
  ]) {
    assert.throws(
      () => parseBusctlExecStartPreExJsonV1(JSON.stringify(value), label),
      /reviewed|shape/,
      label,
    );
  }

  for (const [label, value] of [
    ["wrong unit-array type", { data: [], type: "a(s)" }],
    ["duplicate unit", { data: ["a.service", "a.service"], type: "as" }],
    ["lookalike path", { data: ["../a.service"], type: "as" }],
    ["noncanonical escape", { data: ["dev-foo\\x2Dbar.device"], type: "as" }],
    ["oversized unit array", { data: Array.from({ length: 257 }, (_, index) => `u${index}.service`), type: "as" }],
  ]) {
    assert.throws(
      () => parseBusctlUnitNamesJsonV1(JSON.stringify(value), label),
      /reviewed|bounded|canonical|duplicate|shape|unit-name/,
      label,
    );
  }
  for (const [label, raw] of [
    ["wrong unsigned type", '{"data":30000000,"type":"u"}'],
    ["negative unsigned", '{"data":-1,"type":"t"}'],
    ["uint64 max plus one", '{"type":"t","data":18446744073709551616}'],
    ["Number-rounded uint64 max", '{"type":"t","data":18446744073709552000}'],
    ["leading-zero unsigned", '{"type":"t","data":01}'],
    ["exponent unsigned", '{"type":"t","data":1e3}'],
    ["quoted unsigned", '{"type":"t","data":"0"}'],
    ["duplicate data", '{"type":"t","data":0,"data":0}'],
    ["extra key", '{"type":"t","data":0,"extra":0}'],
    ["missing unsigned", '{"type":"t"}'],
  ]) {
    assert.throws(
      () => parseBusctlUnsignedJsonV1(raw, label),
      /raw-number|uint64|reviewed/,
      label,
    );
  }

  const dependencies = {
    After: ["basic.target", "network-online.target"],
    Before: ["shutdown.target"],
    BindsTo: [],
    Requires: [],
  };
  const service = {
    ExecStartEx: [],
    ExecStartPreEx: [],
    TimeoutStopUSec: "30000000",
    WatchdogTimestampMonotonic: "0",
    WatchdogUSec: "0",
  };
  assert.equal(
    assertEffectiveSystemdPolicySnapshotUnchangedV1(
      dependencies,
      clone(dependencies),
      service,
      clone(service),
      "test",
    ),
    true,
  );
  const unsafeEarlier = {
    ...service,
    WatchdogTimestampMonotonic: "9007199254740992",
  };
  const unsafeLater = {
    ...service,
    WatchdogTimestampMonotonic: "9007199254740993",
  };
  assert.equal(
    assertEffectiveSystemdPolicySnapshotUnchangedV1(
      dependencies,
      clone(dependencies),
      unsafeEarlier,
      unsafeLater,
      "unsafe monotonic timestamp",
    ),
    true,
  );
  assert.throws(
    () => assertEffectiveSystemdPolicySnapshotUnchangedV1(
      dependencies,
      clone(dependencies),
      unsafeLater,
      unsafeEarlier,
      "unsafe monotonic timestamp rollback",
    ),
    /policy changed during live collection/u,
  );
  const changed = clone(dependencies);
  changed.After = ["basic.target"];
  assert.throws(
    () => assertEffectiveSystemdPolicySnapshotUnchangedV1(
      dependencies,
      changed,
      service,
      service,
      "test",
    ),
    /policy changed during live collection/,
  );
});

test("systemctl Exec serialization accepts the real systemd 255 multi-command delimiter", () => {
  const firstCommand =
    "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/directory-relay/binary.sha256";
  const secondCommand =
    "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/directory-relay/config.sha256";
  const first =
    `{ path=/usr/bin/sha256sum ; argv[]=${firstCommand} ; ignore_errors=no ; ` +
    "start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }";
  const second =
    `{ path=/usr/bin/sha256sum ; argv[]=${secondCommand} ; ignore_errors=no ; ` +
    "start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }";

  assert.deepEqual(
    parseSystemctlExecArgvV1(`${first}\n${second}`, "real systemd 255 ExecStartPre"),
    [
      {
        argv: firstCommand,
        code: "(null)",
        ignore_errors: "no",
        path: "/usr/bin/sha256sum",
        pid: "0",
        start_time: "[n/a]",
        status: "0/0",
        stop_time: "[n/a]",
      },
      {
        argv: secondCommand,
        code: "(null)",
        ignore_errors: "no",
        path: "/usr/bin/sha256sum",
        pid: "0",
        start_time: "[n/a]",
        status: "0/0",
        stop_time: "[n/a]",
      },
    ],
  );
  assert.deepEqual(parseSystemctlExecArgvV1("", "empty ExecStartPre"), []);

  for (const malformed of [
    `${first}\n\n${second}`,
    `${first} ; ${second}`,
    `${first} ${second}`,
    `unreviewed-prefix${first}`,
    `${first}\r\n${second}`,
    `${first}\0`,
    `${first}\n${second}\n`,
  ]) {
    assert.throws(
      () => parseSystemctlExecArgvV1(malformed, "malformed ExecStartPre"),
      /unreviewed systemctl Exec serialization/,
    );
  }
});

test("systemctl Exec serialization rejects unreviewed record metadata", () => {
  const command = "/usr/bin/sha256sum --check /tmp/reviewed.sha256";
  const record =
    `{ path=/usr/bin/sha256sum ; argv[]=${command} ; ignore_errors=no ; ` +
    "start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }";
  for (const [label, malformed, pattern] of [
    ["path drift", record.replace("path=/usr/bin/sha256sum", "path=/usr/bin/true"), /path does not match argv\[0\]/],
    ["ignore errors", record.replace("ignore_errors=no", "ignore_errors=yes"), /permits systemctl Exec ignore_errors/],
    ["unknown field", record.replace("status=0/0", "status=0/0 ; unreviewed=yes"), /unknown systemctl Exec field/],
    ["duplicate field", record.replace("status=0/0", "status=0/0 ; path=/usr/bin/sha256sum"), /repeats systemctl Exec field path/],
    ["missing field", record.replace(" ; stop_time=[n/a]", ""), /keys must equal/],
    ["argv/path mismatch", record.replace(`argv[]=${command}`, "argv[]=/usr/bin/true"), /path does not match argv\[0\]/],
  ]) {
    assert.throws(
      () => parseSystemctlExecArgvV1(malformed, label),
      pattern,
      label,
    );
  }
});

test("systemd credential properties require the five reviewed typed empty arrays", () => {
  for (const [property, type] of [
    ["ImportCredential", "as"],
    ["LoadCredential", "a(ss)"],
    ["LoadCredentialEncrypted", "a(ss)"],
    ["SetCredential", "a(say)"],
    ["SetCredentialEncrypted", "a(say)"],
  ]) {
    assert.deepEqual(
      parseBusctlEmptyCredentialJsonV1(
        `${JSON.stringify({ data: [], type })}\n`,
        property,
      ),
      { data: [], type },
    );
  }

  for (const [label, property, value] of [
    ["ImportCredential wrong signature", "ImportCredential", { data: [], type: "a(ss)" }],
    ["LoadCredential wrong signature", "LoadCredential", { data: [], type: "a(say)" }],
    ["SetCredential wrong signature", "SetCredential", { data: [], type: "a(ss)" }],
    ["non-array data", "LoadCredential", { data: {}, type: "a(ss)" }],
    ["imported credential", "ImportCredential", { data: ["secret.*"], type: "as" }],
    ["loaded credential", "LoadCredential", { data: [["secret", "/tmp/secret"]], type: "a(ss)" }],
    ["encrypted loaded credential", "LoadCredentialEncrypted", { data: [["secret", "/tmp/secret"]], type: "a(ss)" }],
    ["inline credential", "SetCredential", { data: [["secret", [1, 2, 3]]], type: "a(say)" }],
    ["encrypted inline credential", "SetCredentialEncrypted", { data: [["secret", [1, 2, 3]]], type: "a(say)" }],
    ["extra key", "LoadCredential", { data: [], type: "a(ss)", value: "hidden" }],
  ]) {
    assert.throws(
      () => parseBusctlEmptyCredentialJsonV1(JSON.stringify(value), property, label),
      /shape|typed empty|keys/,
      label,
    );
  }
  assert.throws(
    () => parseBusctlEmptyCredentialJsonV1("[unprintable]", "LoadCredential"),
    /JSON/,
  );
  assert.throws(
    () => parseBusctlEmptyCredentialJsonV1(JSON.stringify({ data: [], type: "as" }), "PassCredential"),
    /not a reviewed credential property/,
  );
  assert.throws(
    () => parseBusctlEmptyCredentialJsonV1(`{"data":[],"type":"a(ss)","padding":"${"x".repeat(4096)}"}`, "LoadCredential"),
    /not bounded/,
  );

  const initial = emptyCredentialProperties();
  assert.equal(
    assertEffectiveCredentialSnapshotUnchangedV1(
      initial,
      clone(initial),
      "bitcoinpir-test.service",
    ),
    true,
  );
  const nonEmpty = clone(initial);
  nonEmpty.SetCredential.data.push(["secret", [1]]);
  assert.throws(
    () => assertEffectiveCredentialSnapshotUnchangedV1(
      initial,
      nonEmpty,
      "bitcoinpir-test.service",
    ),
    /SetCredential is forbidden/,
  );
});

test("runtime collector reads credentials only from the systemd Service interface", () => {
  for (const property of CREDENTIAL_SERVICE_PROPERTIES) {
    assert.deepEqual(
      systemdCredentialBusctlArgvV1("bitcoinpir-directory-relay.service", property),
      [
        "--json=short",
        "get-property",
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1/unit/bitcoinpir_2ddirectory_2drelay_2eservice",
        "org.freedesktop.systemd1.Service",
        property,
      ],
    );
  }
  assert.throws(
    () => systemdCredentialBusctlArgvV1(
      "bitcoinpir-directory-relay.service",
      "PassCredential",
    ),
    /not reviewed/,
  );
  const source = readFileSync(COLLECTOR, "utf8");
  const start = source.indexOf("function collectEffectiveCredentialProperties(unitName)");
  const end = source.indexOf("function validateEffectiveConditions", start);
  assert.ok(start >= 0 && end > start, "missing bounded credential collector");
  const collector = source.slice(start, end);
  assert.match(collector, /systemdCredentialBusctlArgvV1\(unitName, property\)/);
  assert.match(collector, /effectiveBusctlServicePropertyNames\(\)/);
  assert.doesNotMatch(collector, /systemctl/);
});

// This parser-backed check makes static dependency expansion review-visible.
// Exact five-file hashes, a frozen source commit, the exact Node/toolchain, and
// independent semantic review remain the authority. This is not a JavaScript
// sandbox and does not prove the absence of alternate runtime loader surfaces.
test("runtime evidence review aid keeps exact five-file static module requests", () => {
  for (const [modulePath, expected] of [
    [COLLECTOR, {
      builtins: [
        "node:child_process",
        "node:crypto",
        "node:fs",
        "node:path",
        "node:perf_hooks",
        "node:url",
      ],
      locals: [
        "./payment-v1-publisher-netns-gate.mjs",
        "./payment-v1-rendered-artifact-gate.mjs",
      ],
    }],
    [RENDERED_GATE, {
      builtins: ["node:crypto", "node:fs", "node:net", "node:path", "node:url"],
      locals: [
        "./payment-v1-deployment-template-gate.mjs",
        "./payment-v1-directory-public-haproxy-artifact-gate.mjs",
        "./payment-v1-publisher-netns-gate.mjs",
      ],
    }],
    [TEMPLATE_GATE, {
      builtins: ["node:crypto", "node:fs", "node:path", "node:url"],
      locals: [
        "./payment-v1-directory-public-haproxy-artifact-gate.mjs",
        "./payment-v1-publisher-netns-gate.mjs",
      ],
    }],
    [PUBLISHER_GATE, {
      builtins: ["node:crypto", "node:fs", "node:path", "node:url"],
      locals: [],
    }],
    [DIRECTORY_PUBLIC_HAPROXY_GATE, {
      builtins: ["node:crypto", "node:fs", "node:path", "node:url"],
      locals: [],
    }],
  ]) {
    assertExactStaticModuleRequests(
      readFileSync(modulePath, "utf8"),
      expected,
      modulePath,
    );
  }
});

test("static module request schema accepts only Node 22 and Node 24 evaluation shapes", () => {
  for (const [label, request] of [
    ["Node 22", { attributes: {}, specifier: "node:fs" }],
    ["Node 24", { attributes: {}, phase: "evaluation", specifier: "node:fs" }],
  ]) {
    assert.doesNotThrow(() => assertStaticModuleRequestShapeV1(request, label));
  }
  for (const [label, request, error] of [
    ["missing attributes", { specifier: "node:fs" }, /shape changed/u],
    ["extra key", { attributes: {}, extra: true, specifier: "node:fs" }, /shape changed/u],
    [
      "source phase",
      { attributes: {}, phase: "source", specifier: "node:fs" },
      /phase must remain evaluation/u,
    ],
    [
      "unknown phase",
      { attributes: {}, phase: "unknown", specifier: "node:fs" },
      /phase must remain evaluation/u,
    ],
    [
      "attributes",
      { attributes: { type: "json" }, specifier: "node:fs" },
      /attributes must remain empty/u,
    ],
    ["non-string specifier", { attributes: {}, specifier: 1 }, /specifier must be a string/u],
  ]) {
    assert.throws(() => assertStaticModuleRequestShapeV1(request, label), error, label);
  }
});

// moduleRequests intentionally exposes a dependency set: repeated requests are
// deduplicated by Node and comparison sorts away source order. Exact file hashes
// plus semantic review, not this aid, remain responsible for those source edits.
test("static module request review aid keeps dependency-set duplicate and order semantics", () => {
  const expected = { builtins: ["node:fs", "node:path"], locals: [] };
  for (const [label, source] of [
    ["baseline order", 'import "node:fs"; import "node:path";'],
    ["reverse order", 'import "node:path"; import "node:fs";'],
    [
      "duplicate request",
      'import "node:fs"; import "node:path"; import * as fs from "node:fs";',
    ],
  ]) {
    assert.doesNotThrow(() => assertExactStaticModuleRequests(
      source,
      expected,
      TEMPLATE_GATE,
      label,
    ));
  }
});

test("static module request review aid rejects changed edges and attributes", () => {
  const source = readFileSync(TEMPLATE_GATE, "utf8");
  const anchor = "export const ACTIVE_BASELINES";
  const expected = {
    builtins: ["node:crypto", "node:fs", "node:path", "node:url"],
    locals: [
      "./payment-v1-directory-public-haproxy-artifact-gate.mjs",
      "./payment-v1-publisher-netns-gate.mjs",
    ],
  };
  assert.doesNotThrow(() => assertExactStaticModuleRequests(
    source,
    expected,
    TEMPLATE_GATE,
    "unaltered template gate baseline",
  ));
  for (const [label, injection, error] of [
    ["unknown local", 'import unreviewed from "./static-unreviewed.mjs";', /leaves the reviewed five-file closure/u],
    ["unknown local side effect", 'import "./side-effect-unreviewed.mjs";', /leaves the reviewed five-file closure/u],
    ["unexpected reviewed edge", 'import unexpected from "./payment-v1-rendered-artifact-gate.mjs";', /local static module edge set changed/u],
    ["export-from", 'export { default as unreviewed } from "./export-unreviewed.mjs";', /leaves the reviewed five-file closure/u],
    ["export-star-from", 'export * from "./export-star-unreviewed.mjs";', /leaves the reviewed five-file closure/u],
    ["unknown builtin", 'import * as unreviewedVm from "node:vm";', /static Node builtin request set changed/u],
    ["package", 'import packageUnreviewed from "unreviewed-package";', /contains an unreviewed static module request/u],
    ["absolute", 'import absoluteUnreviewed from "/tmp/unreviewed.mjs";', /contains an unreviewed static module request/u],
    ["file URL", 'import fileUnreviewed from "file:///tmp/unreviewed.mjs";', /contains an unreviewed static module request/u],
    ["data URL", 'import dataUnreviewed from "data:text/javascript,export default 1";', /contains an unreviewed static module request/u],
    ["attributes", 'import * as attributedCrypto from "node:crypto" with { type: "json" };', /attributes must remain empty/u],
  ]) {
    assert.throws(
      () => assertExactStaticModuleRequests(
        source.replace(anchor, `${injection}\n\n${anchor}`),
        expected,
        TEMPLATE_GATE,
        label,
      ),
      error,
      label,
    );
  }
});

test("live collector seals expensive secrets before its final Conditions and generation pass", () => {
  const source = readFileSync(COLLECTOR, "utf8");
  const secretSealMarker = source.indexOf(
    "// Complete expensive secret revalidation only after every earlier long host,",
  );
  const finalStateMarker = source.indexOf(
    "// The bounded publisher namespace/firewall transaction contains the last",
    secretSealMarker,
  );
  const finalUnitMarker = source.indexOf(
    "// Per-unit checks inside collectUnit are not enough:",
    finalStateMarker,
  );
  const finishedMarker = source.indexOf(
    "  const finished = Math.floor(Date.now() / 1000);",
    finalStateMarker,
  );
  const evidenceMarker = source.indexOf("  const evidence = {", finishedMarker);

  assert.ok(secretSealMarker >= 0, "missing final secret-seal ordering marker");
  assert.ok(finalStateMarker > secretSealMarker, "publisher network sealing must follow secret sealing");
  assert.ok(finalUnitMarker > finalStateMarker, "publisher network probes must precede final unit sealing");
  assert.ok(finishedMarker > finalStateMarker, "collection finish timestamp must follow final unit-state pass");
  assert.ok(evidenceMarker > finishedMarker, "evidence construction must immediately follow final state sealing");

  const secretSealPass = source.slice(secretSealMarker, finalStateMarker);
  assert.match(secretSealPass, /confirmSecretFilesUnchanged\(/);
  assert.match(secretSealPass, /confirmSecretParentDirectoriesUnchanged\(/);

  const finalStatePass = source.slice(finalStateMarker, finishedMarker);
  assert.match(finalStatePass, /collectEffectiveCredentialProperties\(/);
  assert.match(finalStatePass, /collectPublisherNetworkRuntimeEvidence\(/);
  assert.match(finalStatePass, /publicationUnit\?\.properties\.InvocationID/);
  assert.match(finalStatePass, /confirmAllInstalledFilesUnchanged\(/);
  assert.match(finalStatePass, /collectEffectiveConditions\(/);
  assert.match(finalStatePass, /collectEffectiveUnitDependenciesV1\(/);
  assert.match(finalStatePass, /collectEffectiveServicePropertiesV1\(/);
  assert.match(finalStatePass, /assertEffectiveSystemdPolicySnapshotUnchangedV1\(/);
  assert.match(finalStatePass, /confirmUnitGeneration\(/);
  assert.match(finalStatePass, /sealPublisherNamespaceOwnerRuntimeEvidence\(/);
  assert.match(finalStatePass, /crossSealPublisherPublicationAfterInstalledFilesV1\(/);
  assert.match(finalStatePass, /finishTrustedCommandSession\(trustedCommands\)/);
  const networkIndex = finalStatePass.indexOf("collectPublisherNetworkRuntimeEvidence(");
  const requestedUnitIndex = finalStatePass.indexOf(
    "confirmUnitGeneration(request.units[index]",
  );
  const publisherSealIndex = finalStatePass.indexOf(
    "sealPublisherNamespaceOwnerRuntimeEvidence(",
  );
  const installedFileSealIndex = finalStatePass.indexOf(
    "confirmAllInstalledFilesUnchanged(",
  );
  const publicationCrossSealIndex = finalStatePass.indexOf(
    "crossSealPublisherPublicationAfterInstalledFilesV1(",
  );
  assert.ok(
    networkIndex < requestedUnitIndex &&
      requestedUnitIndex < publisherSealIndex &&
      publisherSealIndex < installedFileSealIndex &&
      installedFileSealIndex < publicationCrossSealIndex,
    "receipt, unit, receipt, installed-file, and unit/receipt seals must be strictly ordered",
  );
  assert.ok(
    requestedUnitIndex < publisherSealIndex,
    "auxiliary namespace owner must be sealed after the final requested-unit pass",
  );
  assert.ok(
    publicationCrossSealIndex <
      finalStatePass.indexOf("finishTrustedCommandSession(trustedCommands)"),
    "all external command pins must be rechecked after post-file publication cross-sealing",
  );
  const afterFinalUnitSeal = source.slice(finalUnitMarker, finishedMarker);
  assert.doesNotMatch(
    afterFinalUnitSeal,
    /confirmSecretFilesUnchanged|confirmSecretParentDirectoriesUnchanged|collectExtendedMetadata/,
    "secret and unbounded metadata probes must not run after final Conditions/generation sealing",
  );
  assert.doesNotMatch(
    afterFinalUnitSeal,
    /collectPublisherNetworkRuntimeEvidence/,
    "publisher network probes must not run after final Conditions/generation sealing",
  );
  const publisherSeal = source.slice(
    source.indexOf("function sealPublisherNamespaceOwnerRuntimeEvidence("),
    source.indexOf("function validatePublisherNamespaceOwnerEvidence("),
  );
  assert.match(publisherSeal, /collectPublisherCaddyConfigGeneration\(\)/);
  assert.match(publisherSeal, /collectPublisherCaddyUnitGeneration\(\)/);
  const publicationCrossSeal = source.slice(
    source.indexOf("function crossSealPublisherPublicationAfterInstalledFilesV1("),
    source.indexOf("function validatePublisherNamespaceOwnerEvidence("),
  );
  assert.match(publicationCrossSeal, /confirmUnitGeneration\(/);
  assert.match(publicationCrossSeal, /collectPublisherPublicationReceiptPassV1\(/);
});

test("stopped edge and relay collectors put only the final unit seal after long probes", () => {
  const source = readFileSync(COLLECTOR, "utf8");
  const collectorMarker = source.indexOf("function collectStoppedPreparationEvidence(");
  const secretSealMarker = source.indexOf(
    "      \"at the stopped-loader final seal\",",
    collectorMarker,
  );
  const finalStateMarker = source.indexOf(
    "// The final external-state pass is deliberately limited to typed credential",
    secretSealMarker,
  );
  const accountPolicyMarker = source.indexOf(
    "  const accountPolicyFinished = collectLockedServiceAccountPolicy(request, nss);",
    collectorMarker,
  );
  const nssMarker = source.indexOf("  confirmCompleteNssSnapshotUnchanged(nss);", accountPolicyMarker);
  const hostMarker = source.indexOf("  const hostFinished = readHostBinding();", nssMarker);
  const finishedMarker = source.indexOf(
    "  const finished = Math.floor(Date.now() / 1000);",
    finalStateMarker,
  );
  const evidenceMarker = source.indexOf("  const evidence = {", finishedMarker);

  assert.ok(collectorMarker >= 0, "missing stopped collector");
  assert.ok(secretSealMarker > collectorMarker, "missing stopped private-loader final seal");
  assert.ok(accountPolicyMarker > collectorMarker, "missing stopped account-policy confirmation");
  assert.ok(nssMarker > accountPolicyMarker, "NSS confirmation must follow account policy");
  assert.ok(hostMarker > nssMarker, "host confirmation must follow NSS confirmation");
  assert.ok(secretSealMarker > hostMarker, "private-loader seal must follow long host probes");
  assert.ok(finalStateMarker > secretSealMarker, "final stopped state must follow the private-loader seal");
  assert.ok(finishedMarker > finalStateMarker, "finish timestamp must follow final stopped state");
  assert.ok(evidenceMarker > finishedMarker, "evidence must immediately follow the stopped final seal");

  const finalStatePass = source.slice(finalStateMarker, finishedMarker);
  assert.match(finalStatePass, /collectStoppedUnitConfigurations\(/);
  assert.match(finalStatePass, /collectStoppedUnitStates\(/);
  assert.doesNotMatch(
    finalStatePass,
    /collectLockedServiceAccountPolicy|confirmCompleteNssSnapshotUnchanged|readHostBinding|confirmSecretFilesUnchanged|confirmSecretParentDirectoriesUnchanged|collectSecretAccessChecks|collectInstalledFile/,
    "no long host, private-loader or metadata probe may run after final Conditions/stopped-state sealing",
  );
});

test("publisher runtime recomputes the Rust event-set digest from two entries and one checkpoint bundle", () => {
  const event = (index) => [
    "EVENT",
    {
      content: "",
      created_at: 2_000,
      id: index.toString(16).padStart(64, "0"),
      kind: 30_078,
      pubkey: "ab".repeat(32),
      sig: (index + 32).toString(16).padStart(2, "0").repeat(64),
      tags: [],
    },
  ];
  const messages = Array.from({ length: 18 }, (_, index) => event(index + 1));
  const encode = (value) => Buffer.from(JSON.stringify(value));
  const artifacts = [
    encode(messages[0]),
    encode(messages[1]),
    encode(messages.slice(2)),
  ];
  assert.deepEqual(computePublisherArtifactEventSetForTestV1(artifacts), {
    event_count: 18,
    event_set_digest_hex:
      "679c55bb35ebba04b91dd9f8f84ac716111c490128c5f5af3b26ef1f31f89d9f",
  });
  assert.deepEqual(
    computePublisherArtifactEventSetForTestV1([
      artifacts[2],
      artifacts[1],
      artifacts[0],
    ]),
    computePublisherArtifactEventSetForTestV1(artifacts),
  );

  const duplicate = messages.map((message) => clone(message));
  duplicate[17][1].id = duplicate[16][1].id;
  assert.throws(
    () => computePublisherArtifactEventSetForTestV1([
      encode(duplicate[0]),
      encode(duplicate[1]),
      encode(duplicate.slice(2)),
    ]),
    /duplicate Nostr event id/u,
  );
  assert.throws(
    () => computePublisherArtifactEventSetForTestV1([
      artifacts[0],
      artifacts[1],
      encode(messages.slice(2, 17)),
    ]),
    /not one EVENT or one exact 16-EVENT bundle/u,
  );
});

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

function execValue(command, { pid = "0", state = "unrun" } = {}) {
  const metadata = {
    completed:
      `start_time=[Wed 2026-07-29 09:00:00 UTC] ; ` +
      `stop_time=[Wed 2026-07-29 09:00:01 UTC] ; pid=${pid} ; code=exited ; status=0`,
    running:
      `start_time=[Wed 2026-07-29 09:00:01 UTC] ; ` +
      `stop_time=[n/a] ; pid=${pid} ; code=(null) ; status=0/0`,
    unrun: "start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0",
  }[state];
  assert.notEqual(metadata, undefined);
  return (
    `{ path=${command.split(" ", 1)[0]} ; argv[]=${command} ; ignore_errors=no ; ` +
    `${metadata} }`
  );
}

function execCommandEx(command, flags = []) {
  const argv = command.split(/\s+/u);
  return { argv, flags: [...flags], path: argv[0] };
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
    exec_start_ex: [{
      argv: [binaryPath, "serve", "--config", "/etc/bitcoinpir/payment-v1/test/config.toml"],
      flags: [],
      path: binaryPath,
    }],
    exec_start_pre: ["/usr/bin/test -x /opt/bitcoinpir/test/check"],
    exec_start_pre_ex: [{
      argv: ["/usr/bin/test", "-x", "/opt/bitcoinpir/test/check"],
      flags: [],
      path: "/usr/bin/test",
    }],
    fragment_path: fragmentPath,
    hardening: {
      AmbientCapabilities: [""],
      CapabilityBoundingSet: [""],
      Group: ["bitcoinpir-test"],
      LimitCORE: ["0"],
      LimitNOFILE: ["4096"],
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
      TimeoutStopSec: ["30"],
      Type: ["simple"],
      UMask: ["0077"],
      User: ["bitcoinpir-test"],
      WorkingDirectory: ["/var/lib/bitcoinpir-test"],
    },
    unit_dependencies: {
      After: ["network-online.target"],
      Before: [],
      BindsTo: [],
      Requires: [],
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
    busctl_manager_properties: RUNTIME_BUSCTL_MANAGER_PROPERTIES,
    schema_version: 9,
    secret_files: [],
    service_identities: [{
      gid: 731,
      group_name: "bitcoinpir-test",
      uid: 730,
      unit_name: unit.unit_name,
      user_name: "bitcoinpir-test",
    }],
    busctl_service_properties: RUNTIME_BUSCTL_SERVICE_PROPERTIES,
    busctl_unit_properties: RUNTIME_BUSCTL_UNIT_PROPERTIES,
    systemctl_show_properties: RUNTIME_SYSTEMCTL_SHOW_PROPERTIES,
    systemd_version: REVIEWED_SYSTEMD_VERSION,
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
    ControlGroup: "/system.slice/bitcoinpir-test.service",
    DropInPaths: "",
    Environment: "RUST_LOG=error",
    EnvironmentFiles: "",
    ExecCondition: "",
    ExecMainCode: "0",
    ExecMainStatus: "0",
    ExecStart: execValue(unit.exec_start[0], { pid: "4242", state: "running" }),
    ExecStartPost: "",
    ExecStartPre: execValue(unit.exec_start_pre[0], { pid: "4241", state: "completed" }),
    FragmentPath: fragmentPath,
    Group: "bitcoinpir-test",
    IPAddressAllow: "",
    IPAddressDeny: "",
    InaccessiblePaths: "",
    InvocationID: "a".repeat(32),
    LoadState: "loaded",
    LockPersonality: "yes",
    LimitCORE: "0",
    LimitCORESoft: "0",
    LimitNOFILE: "4096",
    LimitNOFILESoft: "4096",
    MainPID: "4242",
    MemoryDenyWriteExecute: "yes",
    MemoryMax: "268435456",
    MemorySwapCurrent: "0",
    MemorySwapMax: "0",
    NeedDaemonReload: "no",
    NetworkNamespacePath: "",
    NoNewPrivileges: "yes",
    NotifyAccess: "none",
    PrivateDevices: "yes",
    PrivateMounts: "no",
    PrivateTmp: "yes",
    ProcSubset: "all",
    ProtectClock: "",
    ProtectControlGroups: "yes",
    ProtectHome: "yes",
    ProtectHostname: "",
    ProtectKernelLogs: "yes",
    ProtectKernelModules: "yes",
    ProtectKernelTunables: "yes",
    ProtectProc: "default",
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
    StandardError: "null",
    StandardOutput: "null",
    StateDirectory: "",
    StateDirectoryMode: "0755",
    SubState: "running",
    SupplementaryGroups: "bitcoinpir-shared",
    SystemCallArchitectures: "native",
    TasksMax: "128",
    TemporaryFileSystem: "",
    Type: "simple",
    UMask: "0077",
    UnsetEnvironment: "",
    User: "bitcoinpir-test",
    WatchdogUSec: "0",
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
      kernel_release: "6.8.0-test",
      machine_id_sha256: machine,
      pid1_name: "systemd",
      pid1_nspid: [1],
      pid1_pid_namespace: "pid:[4026531836]",
      systemd_version: REVIEWED_SYSTEMD_VERSION,
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
    schema_version: 9,
    secret_access_checks: [],
    secret_parent_directories: [],
    systemd_analyze_verify: {
      argv: request.systemd_analyze_argv,
      exit_status: 0,
      stderr: "",
      stdout: "",
    },
    systemd_manager_passes: [0, 1].map(() => ({
      ServiceWatchdogs: { signature: "b", value: true },
      Version: { signature: "s", value: REVIEWED_SYSTEMD_MANAGER_VERSION },
    })),
    trusted_commands: COMMANDS.map((path, index) => ({
      ctime_ns: String(1_800_000_000_000_000_000n + BigInt(index)),
      dev: String(200 + index),
      gid: 0,
      ino: String(10_000 + index),
      mode: "0755",
      mtime_ns: String(1_799_999_999_000_000_000n + BigInt(index)),
      nlink: 1,
      path,
      sha256: hash(`command-${index}`),
      size: 4096 + index,
      uid: 0,
    })),
    units: [{
      conditions: [{
        negate: false,
        parameter: "/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
        path_exists: true,
        result: 1,
        trigger: false,
        type: "ConditionPathExists",
      }],
      credential_properties: emptyCredentialProperties(),
      fragment_sha256: hash("fragment"),
      generation_confirmations: [
        clone(generationConfirmation),
        clone(generationConfirmation),
        clone(generationConfirmation),
      ],
      process_identity: processIdentity,
      properties,
      service_property_passes: [0, 1].map((index) => ({
        observed_uptime_milliseconds: 5000 + (index * 10),
        properties: {
          ExecStartEx: clone(unit.exec_start_ex),
          ExecStartPreEx: clone(unit.exec_start_pre_ex),
          TimeoutStopUSec: "30000000",
          WatchdogTimestampMonotonic: "0",
          WatchdogUSec: "0",
        },
      })),
      unit_dependencies: {
        After: ["basic.target", "network-online.target"],
        Before: ["shutdown.target"],
        BindsTo: [],
        Requires: [],
      },
      unit_name: unit.unit_name,
    }],
  };
  return { boot, evidence, machine, request };
}

function completedPublisherOneshotFixture() {
  const value = fixture();
  const network = publisherNetworkFixture();
  const unit = value.request.units[0];
  const actual = value.evidence.units[0];
  const fragmentPath =
    "/etc/systemd/system/bitcoinpir-payment-v1-directory-publisher.service";
  const unitName = "bitcoinpir-payment-v1-directory-publisher.service";

  unit.unit_name = unitName;
  unit.fragment_path = fragmentPath;
  unit.exec_start = clone(network.request.units[0].exec_start);
  unit.exec_start_ex = clone(network.request.units[0].exec_start_ex);
  unit.hardening.Type = ["oneshot"];
  unit.hardening.RemainAfterExit = ["true"];
  unit.hardening.StateDirectory = ["bitcoinpir-directory-publication"];
  unit.hardening.StateDirectoryMode = ["0700"];
  unit.hardening.ReadWritePaths = [
    "/var/lib/bitcoinpir-directory-publication",
  ];
  value.request.service_identities[0].unit_name = unitName;
  value.request.deployment_profile = "directory-publisher-netns-v1";
  value.request.publisher_network = clone(network.request.publisher_network);
  value.evidence.publisher_network = clone(network.evidence);
  value.request.systemd_analyze_argv = [
    "/usr/bin/systemd-analyze",
    "verify",
    fragmentPath,
  ];
  value.request.installed_files[0].target_path = fragmentPath;
  value.evidence.installed_files[0].target_path = fragmentPath;

  Object.assign(actual.properties, {
    BindReadOnlyPaths: [
      "/etc/netns/bpir-directory-publisher/hosts:/etc/hosts",
      "/etc/netns/bpir-directory-publisher/nsswitch.conf:/etc/nsswitch.conf",
      "/etc/netns/bpir-directory-publisher/resolv.conf:/etc/resolv.conf",
    ].join(" "),
    ControlGroup: "",
    ExecMainCode: "1",
    ExecMainStatus: "0",
    ExecStart: execValue(unit.exec_start[0], {
      pid: "4242",
      state: "completed",
    }),
    FragmentPath: fragmentPath,
    MainPID: "0",
    NeedDaemonReload: "no",
    ReadWritePaths: "/var/lib/bitcoinpir-directory-publication",
    RemainAfterExit: "yes",
    Result: "success",
    SubState: "exited",
    StateDirectory: "bitcoinpir-directory-publication",
    StateDirectoryMode: "0700",
    Type: "oneshot",
  });
  actual.process_identity = null;
  actual.unit_name = unitName;
  for (const pass of actual.service_property_passes) {
    pass.properties.ExecStartEx = clone(unit.exec_start_ex);
  }
  for (const confirmation of actual.generation_confirmations) {
    confirmation.control_group = "";
    confirmation.main_pid = "0";
  }
  actual.generation_confirmations.push(
    clone(actual.generation_confirmations.at(-1)),
  );
  for (const pass of value.evidence.protected_process_closure.passes) {
    pass.holders = [];
  }
  value.evidence.systemd_analyze_verify.argv = value.request.systemd_analyze_argv;
  for (const [index, expected] of network.request.installed_files.entries()) {
    value.request.installed_files.push(clone(expected));
    value.evidence.installed_files.push({
      ...clone(value.evidence.installed_files[0]),
      ...clone(expected),
      ino: String(900 + index),
      sha256_command_sha256: hash(`publisher-owner-sha-command-${index}`),
      stat_command_sha256: hash(`publisher-owner-stat-${index}`),
    });
  }
  for (const [index, path] of [
    "/usr/bin/python3.12",
    "/usr/sbin/nft",
    "/usr/sbin/ufw",
  ].entries()) {
    value.evidence.trusted_commands.push({
      ...clone(value.evidence.trusted_commands[0]),
      ino: String(20_000 + index),
      path,
      sha256: hash(`publisher-command-${index}`),
    });
  }
  return value;
}

function stoppedEdgeFixture() {
  const live = fixture();
  live.request.deployment_profile = "edge-hetzner-v1";
  const unitState = {
    active_state: "inactive",
    control_group: "",
    credential_properties: emptyCredentialProperties(),
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
  const stoppedProperties = clone(live.evidence.units[0].properties);
  Object.assign(stoppedProperties, {
    ActiveEnterTimestampMonotonic: "0",
    ActiveState: "inactive",
    ConditionResult: "no",
    ControlGroup: "",
    ExecStart: execValue(live.request.units[0].exec_start[0]),
    ExecStartPre: live.request.units[0].exec_start_pre.map((command) =>
      execValue(command)).join("\n"),
    InvocationID: "",
    MainPID: "0",
    MemorySwapCurrent: "[not set]",
    SubState: "dead",
    WatchdogUSec: "infinity",
  });
  const stoppedConditions = clone(live.evidence.units[0].conditions);
  const globalActivation = stoppedConditions.find((condition) =>
    condition.parameter === "/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED");
  globalActivation.path_exists = false;
  globalActivation.result = 0;
  const stoppedConfiguration = {
    conditions: stoppedConditions,
    credential_properties: emptyCredentialProperties(),
    fragment_sha256: hash("fragment"),
    properties: stoppedProperties,
    service_properties: {
      ExecStartEx: clone(live.request.units[0].exec_start_ex),
      ExecStartPreEx: clone(live.request.units[0].exec_start_pre_ex),
      TimeoutStopUSec: "30000000",
      WatchdogTimestampMonotonic: "0",
      WatchdogUSec: UINT64_MAX_DECIMAL,
    },
    unit_name: live.request.units[0].unit_name,
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
    schema_version: 5,
    stopped_unit_passes: [
      [clone(unitState)],
      [clone(unitState)],
    ],
    systemd_manager_passes: clone(live.evidence.systemd_manager_passes),
    trusted_commands: clone(live.evidence.trusted_commands),
    unit_configuration_passes: [
      [clone(stoppedConfiguration)],
      [clone(stoppedConfiguration)],
    ],
  };
  return { ...live, evidence };
}

function stoppedRelayFixture() {
  const live = fixture();
  const value = stoppedEdgeFixture();
  const previousUid = value.request.service_identities[0].uid;
  const previousGid = value.request.service_identities[0].gid;
  const relayUid = 52951;
  const relayGid = 52952;
  value.request.deployment_profile = "directory-relay-v1";
  value.request.runtime_paths = [];
  value.request.secret_files = [];
  value.request.tmpfiles_directories = [];
  const relayConfigPath =
    "/etc/bitcoinpir/payment-v1/directory-relay/config.toml";
  const relayFragmentPath =
    "/etc/systemd/system/bitcoinpir-directory-relay.service";
  value.request.units[0].unit_name = "bitcoinpir-directory-relay.service";
  value.request.units[0].fragment_path = relayFragmentPath;
  value.request.units[0].exec_start = ["/usr/bin/false"];
  value.request.units[0].exec_start_ex = [{
    argv: ["/usr/bin/false"],
    flags: [],
    path: "/usr/bin/false",
  }];
  value.request.units[0].exec_start_pre = [];
  value.request.units[0].exec_start_pre_ex = [];
  value.request.units[0].conditions = [
    "ConditionPathExists=/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
    "ConditionPathExists=/etc/bitcoinpir/payment-v1/RELAY-ACTIVATION-APPROVED",
    "ConditionPathExists=/etc/bitcoinpir/payment-v1/RELAY-SELECTION-RESOLVED",
  ];
  Object.assign(value.request.units[0].hardening, {
    LimitCORE: ["0"],
    LimitNOFILE: ["4096"],
    MemoryMax: ["536870912"],
    MemorySwapMax: ["0"],
    ProtectClock: ["true"],
    ProtectHostname: ["true"],
    ProtectProc: ["invisible"],
    ProcSubset: ["pid"],
    Restart: ["no"],
    StandardError: ["null"],
    StandardOutput: ["null"],
    TasksMax: ["128"],
  });
  value.request.service_identities[0].unit_name =
    "bitcoinpir-directory-relay.service";
  value.request.service_identities[0].uid = relayUid;
  value.request.service_identities[0].gid = relayGid;
  const relayUser = value.evidence.nss.users.find((entry) => entry.uid === previousUid);
  relayUser.uid = relayUid;
  relayUser.primary_gid = relayGid;
  relayUser.supplementary_gids = relayUser.supplementary_gids
    .map((gid) => gid === previousGid ? relayGid : gid)
    .sort((left, right) => left - right);
  const relayGroup = value.evidence.nss.groups.find((entry) => entry.gid === previousGid);
  relayGroup.gid = relayGid;
  value.evidence.account_policy.accounts[0].uid = relayUid;
  value.evidence.account_policy.accounts[0].gid = relayGid;
  value.evidence.protected_process_closure.protected_uids = [relayUid];
  value.evidence.protected_process_closure.protected_gids = [732, relayGid];
  sortNssEvidence(value.evidence.nss);
  value.request.installed_files = [
    {
      file_type: "regular",
      gid: value.request.service_identities[0].gid,
      mode: "0400",
      nlink: 1,
      sha256: hash("relay-config"),
      target_path: relayConfigPath,
      uid: value.request.service_identities[0].uid,
    },
    {
      file_type: "regular",
      gid: 0,
      mode: "0644",
      nlink: 1,
      sha256: hash("relay-fragment"),
      target_path: relayFragmentPath,
      uid: 0,
    },
  ];
  value.request.secret_files = [{
    consumer_unit_name: "bitcoinpir-directory-relay.service",
    gid: relayGid,
    mode: "0400",
    target_path: relayConfigPath,
    uid: relayUid,
  }];
  value.request.systemd_analyze_argv = [
    "/usr/bin/systemd-analyze",
    "verify",
    relayFragmentPath,
  ];
  value.evidence.evidence_kind = STOPPED_RELAY_EVIDENCE_KIND;
  value.evidence.schema_version = 4;
  value.evidence.runtime_socket_absence_passes = [[], []];
  for (const pass of value.evidence.stopped_unit_passes) {
    pass[0].unit_name = "bitcoinpir-directory-relay.service";
    pass[0].fragment_path = relayFragmentPath;
  }
  const richInstalledFile = (expected, source, index) => ({
    ...clone(source),
    ...expected,
    ino: String(900 + index),
    size: 200 + index,
  });
  const installedFiles = value.request.installed_files.map((expected, index) =>
    richInstalledFile(expected, live.evidence.installed_files[index], index),
  );
  value.evidence.installed_file_passes = [
    clone(installedFiles),
    clone(installedFiles),
  ];
  const properties = clone(live.evidence.units[0].properties);
  Object.assign(properties, {
    ActiveEnterTimestampMonotonic: "0",
    ActiveState: "inactive",
    ConditionResult: "no",
    ControlGroup: "",
    ExecStart: execValue("/usr/bin/false"),
    ExecStartPre: "",
    FragmentPath: relayFragmentPath,
    InvocationID: "",
    LimitNOFILE: "4096",
    LimitNOFILESoft: "4096",
    MainPID: "0",
    MemoryMax: "536870912",
    MemorySwapCurrent: "[not set]",
    ProtectClock: "yes",
    ProtectHostname: "yes",
    ProtectProc: "invisible",
    ProcSubset: "pid",
    SubState: "dead",
    WatchdogUSec: "infinity",
  });
  const conditions = value.request.units[0].conditions.map((condition) => ({
    negate: false,
    parameter: condition.slice("ConditionPathExists=".length),
    path_exists: false,
    result: -1,
    trigger: false,
    type: "ConditionPathExists",
  }));
  const unitConfiguration = {
    conditions,
    credential_properties: emptyCredentialProperties(),
    fragment_sha256: value.request.installed_files[1].sha256,
    properties,
    service_properties: {
      ExecStartEx: clone(value.request.units[0].exec_start_ex),
      ExecStartPreEx: [],
      TimeoutStopUSec: "30000000",
      WatchdogTimestampMonotonic: "0",
      WatchdogUSec: UINT64_MAX_DECIMAL,
    },
    unit_name: "bitcoinpir-directory-relay.service",
  };
  value.evidence.unit_configuration_passes = [
    [clone(unitConfiguration)],
    [clone(unitConfiguration)],
  ];
  value.evidence.systemd_analyze_verify = {
    argv: clone(value.request.systemd_analyze_argv),
    exit_status: 0,
    stderr: "",
    stdout: "",
  };
  const relayParents = [
    "/",
    "/etc",
    "/etc/bitcoinpir",
    "/etc/bitcoinpir/payment-v1",
    "/etc/bitcoinpir/payment-v1/directory-relay",
  ];
  value.evidence.secret_parent_directories = relayParents.map((target, index) => ({
    acl_sha256: hash(`relay-parent-acl-${index}`),
    capability_sha256: hash(""),
    dev: "1",
    expected_type: "directory",
    file_type: "directory",
    gid: index === relayParents.length - 1 ? relayGid : 0,
    ino: String(950 + index),
    mode: index === relayParents.length - 1 ? "0700" : "0755",
    nlink: 2,
    size: 40,
    stat_command_sha256: hash(`relay-parent-stat-${index}`),
    target_path: target,
    uid: index === relayParents.length - 1 ? relayUid : 0,
    xattr_sha256: hash(`relay-parent-xattr-${index}`),
  }));
  value.evidence.secret_access_checks = [{
    argv: testProbeArgv(
      { gid: relayGid, groups: [732, relayGid].sort((left, right) => left - right), uid: relayUid },
      relayConfigPath,
    ),
    exit_status: 0,
    expected_readable: true,
    stderr: "",
    stdout: "",
    target_path: relayConfigPath,
    unit_name: "bitcoinpir-directory-relay.service",
  }];
  return value;
}

function resolvedStoppedRelayFixture() {
  const value = stoppedRelayFixture();
  const binarySha256 = hash("resolved-relay-binary");
  const binaryPath =
    `/opt/bitcoinpir/directory-relay/${binarySha256}/bitcoinpir-directory-relay`;
  const binaryManifestPath =
    "/etc/bitcoinpir/payment-v1/directory-relay/binary.sha256";
  const configManifestPath =
    "/etc/bitcoinpir/payment-v1/directory-relay/config.sha256";
  const configPath = "/etc/bitcoinpir/payment-v1/directory-relay/config.toml";
  const fragmentPath = "/etc/systemd/system/bitcoinpir-directory-relay.service";
  const unit = value.request.units[0];
  unit.exec_start = [
    `${binaryPath} --config ${configPath}`,
  ];
  unit.exec_start_ex = unit.exec_start.map((command) => execCommandEx(command));
  unit.exec_start_pre = [
    `/usr/bin/sha256sum --check --strict ${binaryManifestPath}`,
    `/usr/bin/sha256sum --check --strict ${configManifestPath}`,
  ];
  unit.exec_start_pre_ex = unit.exec_start_pre.map((command) => execCommandEx(command));
  unit.hardening.IPAddressAllow = ["localhost"];
  unit.hardening.IPAddressDeny = ["any"];
  unit.hardening.Restart = ["on-failure"];
  unit.hardening.RestartSec = ["5"];
  unit.hardening.ReadOnlyPaths = [
    `/etc/bitcoinpir/payment-v1/directory-relay ${dirname(binaryPath)}`,
  ];
  value.request.installed_files = [
    { file_type: "regular", gid: 0, mode: "0444", nlink: 1, sha256: hash("binary-manifest"), target_path: binaryManifestPath, uid: 0 },
    { file_type: "regular", gid: 0, mode: "0444", nlink: 1, sha256: hash("config-manifest"), target_path: configManifestPath, uid: 0 },
    { file_type: "regular", gid: 52952, mode: "0400", nlink: 1, sha256: hash("relay-config"), target_path: configPath, uid: 52951 },
    { file_type: "regular", gid: 0, mode: "0644", nlink: 1, sha256: hash("resolved-relay-fragment"), target_path: fragmentPath, uid: 0 },
    { file_type: "regular", gid: 0, mode: "0555", nlink: 1, sha256: binarySha256, target_path: binaryPath, uid: 0 },
  ];
  const richPrototype = value.evidence.installed_file_passes[0][0];
  const richInstalled = value.request.installed_files.map((expected, index) => ({
    ...clone(richPrototype),
    ...expected,
    ino: String(1100 + index),
    size: 300 + index,
  }));
  value.evidence.installed_file_passes = [clone(richInstalled), clone(richInstalled)];
  const effective = value.evidence.unit_configuration_passes[0][0];
  effective.fragment_sha256 = hash("resolved-relay-fragment");
  effective.properties.ExecStart = execValue(unit.exec_start[0]);
  effective.properties.ExecStartPre = unit.exec_start_pre.map((command) =>
    execValue(command)).join("\n");
  effective.service_properties.ExecStartEx = clone(unit.exec_start_ex);
  effective.service_properties.ExecStartPreEx = clone(unit.exec_start_pre_ex);
  effective.properties.IPAddressAllow = "127.0.0.0/8 ::1/128";
  effective.properties.IPAddressDeny = "::/0 0.0.0.0/0";
  effective.properties.ReadOnlyPaths = unit.hardening.ReadOnlyPaths[0];
  effective.properties.Restart = "on-failure";
  value.evidence.unit_configuration_passes = [
    [clone(effective)],
    [clone(effective)],
  ];
  return value;
}

function resolvedLiveRelayFixture() {
  const value = fixture();
  const relayUid = 52951;
  const relayGid = 52952;
  const binarySha256 = hash("resolved-relay-live-binary");
  const binaryPath =
    `/opt/bitcoinpir/directory-relay/${binarySha256}/bitcoinpir-directory-relay`;
  const binaryManifestPath =
    "/etc/bitcoinpir/payment-v1/directory-relay/binary.sha256";
  const configManifestPath =
    "/etc/bitcoinpir/payment-v1/directory-relay/config.sha256";
  const configPath = "/etc/bitcoinpir/payment-v1/directory-relay/config.toml";
  const fragmentPath = "/etc/systemd/system/bitcoinpir-directory-relay.service";
  const unit = value.request.units[0];
  value.request.deployment_profile = "directory-relay-v1";
  unit.unit_name = "bitcoinpir-directory-relay.service";
  unit.fragment_path = fragmentPath;
  unit.conditions = [
    "ConditionPathExists=/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
    "ConditionPathExists=/etc/bitcoinpir/payment-v1/RELAY-ACTIVATION-APPROVED",
    "ConditionPathExists=/etc/bitcoinpir/payment-v1/RELAY-SELECTION-RESOLVED",
  ];
  unit.exec_start = [`${binaryPath} --config ${configPath}`];
  unit.exec_start_ex = unit.exec_start.map((command) => execCommandEx(command));
  unit.exec_start_pre = [
    `/usr/bin/sha256sum --check --strict ${binaryManifestPath}`,
    `/usr/bin/sha256sum --check --strict ${configManifestPath}`,
  ];
  unit.exec_start_pre_ex = unit.exec_start_pre.map((command) => execCommandEx(command));
  Object.assign(unit.hardening, {
    Group: ["bitcoinpir-directory-relay"],
    IPAddressAllow: ["localhost"],
    IPAddressDeny: ["any"],
    InaccessiblePaths: ["/run/bitcoinpir-source-fair-edge"],
    LimitCORE: ["0"],
    LimitNOFILE: ["4096"],
    MemoryMax: ["536870912"],
    MemorySwapMax: ["0"],
    ProtectClock: ["true"],
    ProtectHostname: ["true"],
    ProtectProc: ["invisible"],
    ProcSubset: ["pid"],
    ReadOnlyPaths: [
      `/etc/bitcoinpir/payment-v1/directory-relay ${dirname(binaryPath)}`,
    ],
    ReadWritePaths: ["/var/lib/bitcoinpir-directory-relay"],
    Restart: ["on-failure"],
    RestartSec: ["5"],
    RestrictAddressFamilies: ["AF_UNIX", "AF_INET", "AF_INET6"],
    StateDirectory: ["bitcoinpir-directory-relay"],
    StateDirectoryMode: ["0700"],
    TasksMax: ["128"],
    User: ["bitcoinpir-directory-relay"],
    WorkingDirectory: ["/var/lib/bitcoinpir-directory-relay"],
  });
  delete unit.hardening.SupplementaryGroups;
  value.request.service_identities = [{
    gid: relayGid,
    group_name: "bitcoinpir-directory-relay",
    uid: relayUid,
    unit_name: unit.unit_name,
    user_name: "bitcoinpir-directory-relay",
  }];
  value.request.installed_files = [
    { file_type: "regular", gid: 0, mode: "0444", nlink: 1, sha256: hash("live-binary-manifest"), target_path: binaryManifestPath, uid: 0 },
    { file_type: "regular", gid: 0, mode: "0444", nlink: 1, sha256: hash("live-config-manifest"), target_path: configManifestPath, uid: 0 },
    { file_type: "regular", gid: relayGid, mode: "0400", nlink: 1, sha256: hash("live-relay-config"), target_path: configPath, uid: relayUid },
    { file_type: "regular", gid: 0, mode: "0644", nlink: 1, sha256: hash("live-relay-fragment"), target_path: fragmentPath, uid: 0 },
    { file_type: "regular", gid: 0, mode: "0555", nlink: 1, sha256: binarySha256, target_path: binaryPath, uid: 0 },
  ];
  value.request.runtime_paths = [];
  value.request.tmpfiles_directories = [];
  value.request.secret_files = [{
    consumer_unit_name: unit.unit_name,
    gid: relayGid,
    mode: "0400",
    target_path: configPath,
    uid: relayUid,
  }];
  value.request.systemd_analyze_argv = [
    "/usr/bin/systemd-analyze",
    "verify",
    fragmentPath,
  ];

  const user = value.evidence.nss.users.find((entry) => entry.uid === 730);
  user.name = "bitcoinpir-directory-relay";
  user.uid = relayUid;
  user.primary_gid = relayGid;
  user.supplementary_gids = [relayGid];
  const group = value.evidence.nss.groups.find((entry) => entry.gid === 731);
  group.name = "bitcoinpir-directory-relay";
  group.gid = relayGid;
  value.evidence.nss.groups.find((entry) => entry.gid === 732).members = [];
  sortNssEvidence(value.evidence.nss);
  const richPrototype = value.evidence.installed_files[0];
  value.evidence.installed_files = value.request.installed_files.map((expected, index) => ({
    ...clone(richPrototype),
    ...expected,
    ino: String(1200 + index),
    size: 400 + index,
  }));
  value.evidence.runtime_directories = [];
  value.evidence.runtime_paths = [];
  const relayParents = [
    "/",
    "/etc",
    "/etc/bitcoinpir",
    "/etc/bitcoinpir/payment-v1",
    "/etc/bitcoinpir/payment-v1/directory-relay",
  ];
  value.evidence.secret_parent_directories = relayParents.map((target, index) => ({
    acl_sha256: hash(`live-relay-parent-acl-${index}`),
    capability_sha256: hash(""),
    dev: "1",
    expected_type: "directory",
    file_type: "directory",
    gid: index === relayParents.length - 1 ? relayGid : 0,
    ino: String(1250 + index),
    mode: index === relayParents.length - 1 ? "0700" : "0755",
    nlink: 2,
    size: 40,
    stat_command_sha256: hash(`live-relay-parent-stat-${index}`),
    target_path: target,
    uid: index === relayParents.length - 1 ? relayUid : 0,
    xattr_sha256: hash(`live-relay-parent-xattr-${index}`),
  }));
  value.evidence.secret_access_checks = [{
    argv: testProbeArgv(
      { gid: relayGid, groups: [relayGid], uid: relayUid },
      configPath,
    ),
    exit_status: 0,
    expected_readable: true,
    stderr: "",
    stdout: "",
    target_path: configPath,
    unit_name: unit.unit_name,
  }];
  value.evidence.systemd_analyze_verify.argv = clone(value.request.systemd_analyze_argv);
  const evidenceUnit = value.evidence.units[0];
  evidenceUnit.unit_name = unit.unit_name;
  evidenceUnit.fragment_sha256 = hash("live-relay-fragment");
  evidenceUnit.conditions = unit.conditions.map((condition) => ({
    negate: false,
    parameter: condition.slice("ConditionPathExists=".length),
    path_exists: true,
    result: 1,
    trigger: false,
    type: "ConditionPathExists",
  }));
  Object.assign(evidenceUnit.properties, {
    ControlGroup: `/system.slice/${unit.unit_name}`,
    ExecStart: execValue(unit.exec_start[0], { pid: "4242", state: "running" }),
    ExecStartPre: unit.exec_start_pre.map((command, index) =>
      execValue(command, { pid: String(4400 + index), state: "completed" })).join("\n"),
    FragmentPath: fragmentPath,
    Group: "bitcoinpir-directory-relay",
    IPAddressAllow: "127.0.0.0/8 ::1/128",
    IPAddressDeny: "::/0 0.0.0.0/0",
    InaccessiblePaths: "/run/bitcoinpir-source-fair-edge",
    MemoryMax: "536870912",
    ProtectClock: "yes",
    ProtectHostname: "yes",
    ProtectProc: "invisible",
    ProcSubset: "pid",
    ReadOnlyPaths: unit.hardening.ReadOnlyPaths[0],
    ReadWritePaths: "/var/lib/bitcoinpir-directory-relay",
    Restart: "on-failure",
    RestrictAddressFamilies: "AF_INET AF_INET6 AF_UNIX",
    StateDirectory: "bitcoinpir-directory-relay",
    StateDirectoryMode: "0700",
    SupplementaryGroups: "",
    User: "bitcoinpir-directory-relay",
    WorkingDirectory: "/var/lib/bitcoinpir-directory-relay",
  });
  for (const pass of evidenceUnit.service_property_passes) {
    pass.properties.ExecStartEx = clone(unit.exec_start_ex);
    pass.properties.ExecStartPreEx = clone(unit.exec_start_pre_ex);
  }
  for (const confirmation of evidenceUnit.generation_confirmations) {
    confirmation.control_group = evidenceUnit.properties.ControlGroup;
  }
  const process = evidenceUnit.process_identity;
  process.uid_before = [relayUid, relayUid, relayUid, relayUid];
  process.uid_after = clone(process.uid_before);
  process.gid_before = [relayGid, relayGid, relayGid, relayGid];
  process.gid_after = clone(process.gid_before);
  process.groups_before = [relayGid];
  process.groups_after = clone(process.groups_before);
  value.evidence.protected_process_closure.protected_uids = [relayUid];
  value.evidence.protected_process_closure.protected_gids = [relayGid];
  for (const pass of value.evidence.protected_process_closure.passes) {
    const holder = pass.holders[0];
    holder.control_group = evidenceUnit.properties.ControlGroup;
    holder.uid = [relayUid, relayUid, relayUid, relayUid];
    holder.gid = [relayGid, relayGid, relayGid, relayGid];
    holder.groups = [relayGid];
  }
  return value;
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

function validateStoppedRelay(value) {
  return validateStoppedRelayPreparationEvidence({
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

function preflightLeaseFixture() {
  const value = fixture();
  const fragmentPath = "/etc/systemd/system/bitcoinpir-lightning-preflight.service";
  const approvalPath =
    "/run/bitcoinpir-lightning-operator-approvals/preflight-generation-approved";
  const unit = value.request.units[0];
  unit.fragment_path = fragmentPath;
  unit.unit_name = "bitcoinpir-lightning-preflight.service";
  unit.hardening.Type = ["notify"];
  unit.hardening.NotifyAccess = ["main"];
  unit.hardening.WatchdogSec = ["90"];
  unit.conditions.push(`ConditionPathExists=${approvalPath}`);
  unit.exec_start_pre.unshift(`/usr/bin/unlink -- ${approvalPath}`);
  unit.exec_start_pre_ex.unshift({
    argv: ["/usr/bin/unlink", "--", approvalPath],
    flags: ["privileged"],
    path: "/usr/bin/unlink",
  });
  unit.unit_dependencies = {
    After: ["bitcoinpir-core-lightning.service"],
    Before: [
      "bitcoinpir-cln-rpc-guard.service",
      "bitcoinpir-payment-issuer.service",
    ],
    BindsTo: ["bitcoinpir-core-lightning.service"],
    Requires: ["bitcoinpir-core-lightning.service"],
  };
  value.request.service_identities[0].unit_name = unit.unit_name;
  value.request.installed_files[0].target_path = fragmentPath;
  value.request.systemd_analyze_argv[2] = fragmentPath;
  value.evidence.installed_files[0].target_path = fragmentPath;
  value.evidence.systemd_analyze_verify.argv[2] = fragmentPath;
  const actual = value.evidence.units[0];
  actual.unit_name = unit.unit_name;
  actual.properties.FragmentPath = fragmentPath;
  actual.properties.ControlGroup = `/system.slice/${unit.unit_name}`;
  actual.properties.Type = "notify";
  actual.properties.NotifyAccess = "main";
  actual.properties.WatchdogUSec = "1min 30s";
  actual.properties.ExecStartPre = unit.exec_start_pre.map((command, index) =>
    execValue(command, { pid: String(4300 + index), state: "completed" })).join("\n");
  actual.conditions.push({
    negate: false,
    parameter: approvalPath,
    path_exists: false,
    result: 1,
    trigger: false,
    type: "ConditionPathExists",
  });
  actual.conditions.sort((left, right) => left.parameter < right.parameter ? -1 : left.parameter > right.parameter ? 1 : 0);
  actual.service_property_passes = [
    {
      observed_uptime_milliseconds: 5000,
      properties: {
        ExecStartEx: clone(unit.exec_start_ex),
        ExecStartPreEx: clone(unit.exec_start_pre_ex),
        TimeoutStopUSec: "30000000",
        WatchdogTimestampMonotonic: "4500000",
        WatchdogUSec: "90000000",
      },
    },
    {
      observed_uptime_milliseconds: 5010,
      properties: {
        ExecStartEx: clone(unit.exec_start_ex),
        ExecStartPreEx: clone(unit.exec_start_pre_ex),
        TimeoutStopUSec: "30000000",
        WatchdogTimestampMonotonic: "4900000",
        WatchdogUSec: "90000000",
      },
    },
  ];
  actual.unit_dependencies = {
    After: ["basic.target", "bitcoinpir-core-lightning.service"],
    Before: [
      "bitcoinpir-cln-rpc-guard.service",
      "bitcoinpir-payment-issuer.service",
      "shutdown.target",
    ],
    BindsTo: ["bitcoinpir-core-lightning.service"],
    Requires: ["bitcoinpir-core-lightning.service"],
  };
  actual.generation_confirmations = actual.generation_confirmations.map((confirmation) => ({
    ...confirmation,
    control_group: actual.properties.ControlGroup,
  }));
  for (const pass of value.evidence.protected_process_closure.passes) {
    pass.holders[0].control_group = actual.properties.ControlGroup;
  }
  return value;
}

function publisherNetworkFixture() {
  const helperSha256 = hash("publisher-namespace-helper");
  const helperPath =
    `/opt/bitcoinpir/publisher-netns/${helperSha256}/payment-v1-publisher-netns`;
  const fragmentSha256 = hash("publisher-namespace-owner-fragment");
  const publicationInvocationId = "a".repeat(32);
  const publicationManifestPath =
    "/etc/bitcoinpir/payment-v1/directory-publisher/artifacts.sha256";
  const publicationArtifactPins = [
    ["checkpoints.json", hash("publisher-checkpoints")],
    ["provider-0.event.json", hash("publisher-provider-0")],
    ["provider-1.event.json", hash("publisher-provider-1")],
  ].map(([name, sha256]) => ({
    path: `/var/lib/bitcoinpir-directory-publisher/artifacts/${name}`,
    sha256,
  }));
  const publisherAdmin = `/opt/bitcoinpir/bpir-admin/${hash("publisher-admin")}/bpir-admin`;
  const publicationArgv = [
    publisherAdmin,
    "directory-artifact",
    "publish",
    ...publicationArtifactPins.flatMap((pin) => ["--artifact", pin.path]),
    "--artifact-manifest",
    publicationManifestPath,
    "--receipt-directory",
    "/var/lib/bitcoinpir-directory-publication",
    "--relay",
    "wss://publisher.internal.example",
    "--centralized-single-relay",
    "--directory-pubkey-hex",
    "0d399dc19efb5632e4a1d26ad5fec578fb401c6b3af80e234cea7339a8c7ad0c",
    "--now-unix",
    "2000",
    "--relay-timeout-seconds",
    "60",
  ];
  const publicationUnit = {
    exec_start: [publicationArgv.join(" ")],
    exec_start_ex: [{ argv: publicationArgv, flags: [], path: publisherAdmin }],
    unit_name: "bitcoinpir-payment-v1-directory-publisher.service",
  };
  const publicationIdentity = {
    gid: 731,
    group_name: "bitcoinpir-directory-publisher",
    uid: 730,
    unit_name: publicationUnit.unit_name,
    user_name: "bitcoinpir-directory-publisher",
  };
  const publicationManifestSha256 = hash("publisher-artifact-manifest");
  const publicationReceiptRequest = {
    artifact_manifest: {
      path: publicationManifestPath,
      sha256: publicationManifestSha256,
    },
    artifacts: publicationArtifactPins,
    argv: publicationArgv,
    argv_sha256: computeDirectoryPublishArgvSha256V1(publicationArgv),
    directory_mode: "centralized-single-relay",
    file: {
      directory: "/var/lib/bitcoinpir-directory-publication",
      filename_suffix: ".json",
      gid: publicationIdentity.gid,
      mode: "0600",
      nlink: 1,
      uid: publicationIdentity.uid,
    },
    kind: "bitcoinpir-directory-publication-receipt-v1",
    publisher_pubkey_hex:
      "0d399dc19efb5632e4a1d26ad5fec578fb401c6b3af80e234cea7339a8c7ad0c",
    relay_origins: ["wss://publisher.internal.example"],
    schema_version: 1,
  };
  const request = {
    caddy_drop_in_path:
      "/etc/systemd/system/bhtm-caddy.service.d/bitcoinpir-publisher-netns.conf",
    caddy_service_unit: "bhtm-caddy.service",
    firewall: {
      forwarding_sysctls: {
        "net.ipv4.ip_forward": 0,
        "net.ipv6.conf.all.forwarding": 0,
      },
      interface: "bpir-pub-h",
      semantic_profile: "bitcoinpir-publisher-ufw-closed-v1",
      ufw_rules_in_install_order: [
        "prepend deny in on bpir-pub-h from any to any",
        "prepend allow in on bpir-pub-h from 10.203.0.2 to 10.203.0.1 proto tcp port 443",
        "route prepend deny in on bpir-pub-h from any to any",
        "route prepend deny out on bpir-pub-h from any to any",
      ],
    },
    forbidden_caddy_reverse_stop_edges: ["BindsTo", "PartOf", "Requires"],
    namespace: {
      client: "10.203.0.2/30",
      host: "10.203.0.1/30",
      name: "bpir-directory-publisher",
      path: "/run/netns/bpir-directory-publisher",
    },
    namespace_owner_unit: "bitcoinpir-payment-v1-publisher-netns.service",
    network_policy_sha256: hash("publisher-network-policy"),
    publication_receipt: publicationReceiptRequest,
    publication_mode: {
      centralized: true,
      degraded: true,
      name: "centralized-single-relay",
    },
    publication_time_firewall_binding: {
      activation_blocked: true,
      activation_blocker_condition_path:
        "/etc/bitcoinpir/payment-v1/PUBLISHER-LIVE-FIREWALL-LINEAGE-IMPLEMENTED",
      continuous_checks: [
        "reject-any-nftables-generation-event",
        "reject-xtables-lock-inode-drift",
      ],
      continuous_generation_guard_implemented: true,
      graceful_stop_barriers: [
        "require-empty-nftables-event-queue",
        "require-stable-xtables-lock-inode",
      ],
      guard_profile: "xtables-lock-and-host-nftables-generation-monitor-v1",
      implemented: false,
      initial_live_semantic_lineage: {
        binds_boot_id: false,
        binds_owner_invocation_id: false,
        binds_publication_approval: false,
        binds_rule_summary: false,
        implemented: false,
        required_before_owner_ready: true,
      },
      lifecycle_scope: "publisher-netns-owner-lifetime",
      missing_requirement: "owner-pre-ready-live-semantic-revalidation-lineage-v1",
      point_in_time_evidence_only: true,
      pre_ready_barriers: [
        "open-host-netns-nftables-multicast-before-network-setup",
        "hold-root-single-link-xtables-lock",
        "require-empty-nftables-event-queue",
        "repeat-full-stop-firewall-child-topology-barrier-immediately-before-ready",
      ],
      privileged_mutation_boundary: "non-adversarial-root-maintenance",
      semantic_pre_post_evidence_required: true,
      state_machine:
        "continuous-generation-guard-implemented-live-semantic-lineage-blocked",
    },
    publisher_unit: "bitcoinpir-payment-v1-directory-publisher.service",
  };
  const installedFiles = [
    {
      file_type: "regular",
      gid: 0,
      mode: "0644",
      nlink: 1,
      sha256: fragmentSha256,
      target_path:
        "/etc/systemd/system/bitcoinpir-payment-v1-publisher-netns.service",
      uid: 0,
    },
    {
      file_type: "regular",
      gid: 0,
      mode: "0555",
      nlink: 1,
      sha256: helperSha256,
      target_path: helperPath,
      uid: 0,
    },
    {
      file_type: "regular",
      gid: 0,
      mode: "0444",
      nlink: 1,
      sha256: publicationManifestSha256,
      target_path: publicationManifestPath,
      uid: 0,
    },
    ...publicationArtifactPins.map((pin) => ({
      file_type: "regular",
      gid: 0,
      mode: "0444",
      nlink: 1,
      sha256: pin.sha256,
      target_path: pin.path,
      uid: 0,
    })),
  ];
  const ownerConditions = [
    "/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
    "/etc/bitcoinpir/payment-v1/EDGE-ACTIVATION-APPROVED",
    "/etc/bitcoinpir/payment-v1/SOURCE-FAIR-PREFLIGHT-APPROVED",
    "/etc/bitcoinpir/payment-v1/DIRECTORY-PUBLISHER-PRIVATE-INGRESS-APPROVED",
    "/etc/bitcoinpir/payment-v1/PUBLISHER-NETNS-ACTIVATION-APPROVED",
  ].map((parameter) => ({
    negate: false,
    parameter,
    path_exists: true,
    result: 1,
    trigger: false,
    type: "ConditionPathExists",
  })).sort((left, right) => left.parameter < right.parameter ? -1 : left.parameter > right.parameter ? 1 : 0);
  const ownerControlGroup =
    "/system.slice/bitcoinpir-payment-v1-publisher-netns.service";
  const ownerProperties = {
    ActiveEnterTimestampMonotonic: "7000000",
    ActiveState: "active",
    AmbientCapabilities: "",
    CapabilityBoundingSet: "CAP_NET_ADMIN CAP_SYS_ADMIN",
    ConditionResult: "yes",
    ControlGroup: ownerControlGroup,
    DropInPaths: "",
    ExecStart: execValue(`${helperPath} run`, { pid: "4402", state: "running" }),
    ExecStartPre: [
      `/usr/bin/test -x ${helperPath}`,
      "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/publisher-netns/helper.sha256",
      `${helperPath} self-test`,
    ].map((command, index) => execValue(command, {
      pid: String(4390 + index),
      state: "completed",
    })).join("\n"),
    ExecStopPost: execValue(`${helperPath} cleanup`),
    FragmentPath:
      "/etc/systemd/system/bitcoinpir-payment-v1-publisher-netns.service",
    Group: "root",
    InvocationID: "b".repeat(32),
    KillMode: "control-group",
    LimitCORE: "0",
    LimitCORESoft: "0",
    LoadState: "loaded",
    LockPersonality: "yes",
    MainPID: "4402",
    MemoryDenyWriteExecute: "yes",
    MemoryMax: "67108864",
    MemorySwapCurrent: "0",
    MemorySwapMax: "0",
    NeedDaemonReload: "no",
    NoNewPrivileges: "yes",
    NotifyAccess: "main",
    PartOf: "bhtm-caddy.service",
    Restart: "no",
    RestrictAddressFamilies: "AF_UNIX AF_NETLINK",
    RestrictNamespaces: "net",
    RestrictRealtime: "yes",
    RestrictSUIDSGID: "yes",
    Result: "success",
    StateDirectory: "bitcoinpir-publisher-netns",
    StateDirectoryMode: "0700",
    StandardError: "null",
    StandardOutput: "null",
    SubState: "running",
    SystemCallArchitectures: "native",
    TasksMax: "8",
    TimeoutStartUSec: "30s",
    TimeoutStopUSec: "30s",
    Type: "notify",
    UMask: "0077",
    UnsetEnvironment:
      "BASH_ENV ENV GLIBC_TUNABLES LD_AUDIT LD_LIBRARY_PATH LD_PRELOAD NODE_EXTRA_CA_CERTS NODE_OPTIONS NODE_PATH",
    User: "root",
    WorkingDirectory: "/var/lib/bitcoinpir-publisher-netns",
  };
  const ownerGeneration = {
    active_enter_timestamp_monotonic: ownerProperties.ActiveEnterTimestampMonotonic,
    active_state: "active",
    control_group: ownerControlGroup,
    invocation_id: ownerProperties.InvocationID,
    main_pid: ownerProperties.MainPID,
    need_daemon_reload: "no",
  };
  const monitorCapabilities = capabilityRecord({
    bounding: "0000000000201000",
  });
  const monitorProcess = ({
    exeIno,
    netNamespace,
    parentPid,
    pid,
    procIno,
    startTime,
  }) => ({
    capabilities: clone(monitorCapabilities),
    control_group: ownerControlGroup,
    executable: {
      dev: "21",
      ino: exeIno,
      path: helperPath,
      sha256: helperSha256,
    },
    gid: [0, 0, 0, 0],
    groups: [0],
    net_namespace: netNamespace,
    no_new_privs: 1,
    parent_pid: parentPid,
    pid,
    proc_directory_dev: "9",
    proc_directory_ino: procIno,
    seccomp: 2,
    start_time_ticks: startTime,
    uid: [0, 0, 0, 0],
  });
  const ownerProcessPass = {
    child: monitorProcess({
      exeIno: "700",
      netNamespace: "net:[4026532999]",
      parentPid: 4402,
      pid: 4403,
      procIno: "741",
      startTime: "500001",
    }),
    collector_net_namespace: "net:[4026531840]",
    direct_children: [4403],
    main: monitorProcess({
      exeIno: "700",
      netNamespace: "net:[4026531840]",
      parentPid: 1,
      pid: 4402,
      procIno: "740",
      startTime: "500000",
    }),
  };
  const boundary = {
    caddy_dependency: {
      after_namespace_owner: true,
      binds_to_namespace_owner: false,
      config_generation_confirmations: Array.from({ length: 3 }, () => ({
        ctime_ns: "1800000000000000000",
        dev: "22",
        gid: 0,
        ino: "88001",
        mode: "0644",
        mtime_ns: "1799999999000000000",
        nlink: 1,
        path: "/etc/caddy/Caddyfile",
        sha256: hash("publisher-caddy-config"),
        size: 4096,
        uid: 0,
      })),
      drop_in_paths: [
        "/etc/systemd/system/bhtm-caddy.service.d/bitcoinpir-publisher-netns.conf",
      ],
      drop_in_paths_sha256: hash(`${JSON.stringify([
        "/etc/systemd/system/bhtm-caddy.service.d/bitcoinpir-publisher-netns.conf",
      ])}\n`),
      generation_confirmations: Array.from({ length: 3 }, () => ({
        active_enter_timestamp_monotonic: "7100000",
        active_state: "active",
        invocation_id: "c".repeat(32),
        load_state: "loaded",
        main_pid: "4500",
        need_daemon_reload: "no",
        sub_state: "running",
      })),
      part_of_namespace_owner: false,
      requires_namespace_owner: false,
      wants_namespace_owner: true,
    },
    forwarding_sysctls: {
      "net.ipv4.ip_forward": 0,
      "net.ipv6.conf.all.forwarding": 0,
    },
    namespace_mount: {
      dev: "13",
      filesystem_type: "nsfs",
      ino: "4026532999",
      major_minor: "0:4",
      mount_id: "812",
      mount_source: "nsfs",
      parent_mount_id: "29",
      root: "/",
      statfs_type: 0x6e736673,
    },
    namespace_owner: {
      condition_confirmations: [
        clone(ownerConditions), clone(ownerConditions), clone(ownerConditions),
      ],
      effective_properties: ownerProperties,
      fragment_sha256: fragmentSha256,
      generation_confirmations: [
        clone(ownerGeneration), clone(ownerGeneration), clone(ownerGeneration),
      ],
      helper_path: helperPath,
      helper_sha256: helperSha256,
      process_passes: [clone(ownerProcessPass), clone(ownerProcessPass)],
    },
  };
  const semantic = {
    closed_prelude_profile: "ufw-base-before-user-and-user-prefix-v1",
    nft_ip6_forward: [
      'oifname "bpir-pub-h" drop',
      'iifname "bpir-pub-h" drop',
    ],
    nft_ip6_input: ['iifname "bpir-pub-h" drop'],
    nft_ip_forward: [
      'oifname "bpir-pub-h" drop',
      'iifname "bpir-pub-h" drop',
    ],
    nft_ip_input: [
      'ip saddr 10.203.0.2 ip daddr 10.203.0.1 iifname "bpir-pub-h" tcp dport 443 accept',
      'iifname "bpir-pub-h" drop',
    ],
    ufw_raw: [
      "COUNTERS ACCEPT 6 -- bpir-pub-h * 10.203.0.2 10.203.0.1 tcp dpt:443",
      "COUNTERS DROP 0 -- bpir-pub-h * 0.0.0.0/0 0.0.0.0/0",
      "COUNTERS DROP 0 -- bpir-pub-h * 0.0.0.0/0 0.0.0.0/0",
      "COUNTERS DROP 0 -- * bpir-pub-h 0.0.0.0/0 0.0.0.0/0",
      "COUNTERS DROP 0 -- bpir-pub-h * ::/0 ::/0",
      "COUNTERS DROP 0 -- bpir-pub-h * ::/0 ::/0",
      "COUNTERS DROP 0 -- * bpir-pub-h ::/0 ::/0",
    ],
    ufw_status: [
      "10.203.0.1 443/tcp on bpir-pub-h ALLOW IN 10.203.0.2",
      "Anywhere on bpir-pub-h DENY IN Anywhere",
      "Anywhere DENY FWD Anywhere on bpir-pub-h",
      "Anywhere on bpir-pub-h DENY FWD Anywhere (out)",
      "Anywhere (v6) on bpir-pub-h DENY IN Anywhere (v6)",
      "Anywhere (v6) DENY FWD Anywhere (v6) on bpir-pub-h",
      "Anywhere (v6) on bpir-pub-h DENY FWD Anywhere (v6) (out)",
    ],
    validated_output_keys: [...PUBLISHER_FIREWALL_OUTPUT_KEYS],
  };
  const firewallPass = {
    output_sha256: Object.fromEntries(PUBLISHER_FIREWALL_OUTPUT_KEYS.map(
      (name) => [name, hash(`publisher-${name}`)],
    )),
    semantic_outputs: semantic,
    semantic_profile: "bitcoinpir-publisher-ufw-closed-v1",
  };
  const evidence = {
    boundary_confirmations: [clone(boundary), clone(boundary)],
    firewall_passes: [clone(firewallPass), clone(firewallPass)],
    publication_receipt_passes: [],
    ufw_dry_run_reload: {
      argv: ["/usr/sbin/ufw", "--dry-run", "reload"],
      exit_status: 0,
      stderr_sha256: hash(""),
      stdout_sha256: hash("publisher-ufw-dry-run"),
    },
  };
  const publicationReceipt = {
    artifact_manifest: clone(publicationReceiptRequest.artifact_manifest),
    artifacts: clone(publicationReceiptRequest.artifacts),
    argv: clone(publicationReceiptRequest.argv),
    argv_sha256: publicationReceiptRequest.argv_sha256,
    directory_mode: publicationReceiptRequest.directory_mode,
    event_count: 18,
    event_set_digest_hex: hash("publisher-event-set"),
    invocation_id: publicationInvocationId,
    kind: publicationReceiptRequest.kind,
    outcome: "published",
    publisher_pubkey_hex: publicationReceiptRequest.publisher_pubkey_hex,
    relay_origins: clone(publicationReceiptRequest.relay_origins),
    schema_version: 1,
  };
  const parentDirectory = {
    acl_sha256: hash("publisher-receipt-parent-acl"),
    capability_sha256: hash(""),
    dev: "21",
    expected_type: "directory",
    file_type: "directory",
    gid: publicationIdentity.gid,
    ino: "91001",
    mode: "0700",
    nlink: 2,
    size: 4096,
    stat_command_sha256: hash("publisher-receipt-parent-stat"),
    target_path: "/var/lib/bitcoinpir-directory-publication",
    uid: publicationIdentity.uid,
    xattr_sha256: hash(""),
  };
  const parentFingerprint = {
    ctime_ns: "1800000000000000000",
    dev: parentDirectory.dev,
    gid: String(parentDirectory.gid),
    ino: parentDirectory.ino,
    mode: parentDirectory.mode,
    mtime_ns: "1799999999000000000",
    nlink: String(parentDirectory.nlink),
    size: String(parentDirectory.size),
    uid: String(parentDirectory.uid),
  };
  const publicationReceiptPass = {
    ctime_ns: "1800000001000000000",
    current_event_set: {
      event_count: publicationReceipt.event_count,
      event_set_digest_hex: publicationReceipt.event_set_digest_hex,
    },
    dev: "21",
    gid: publicationIdentity.gid,
    ino: "91002",
    mode: "0600",
    mtime_ns: "1800000000000000000",
    nlink: 1,
    parent_directory: parentDirectory,
    parent_fingerprint: parentFingerprint,
    path:
      `${publicationReceiptRequest.file.directory}/${publicationInvocationId}` +
      publicationReceiptRequest.file.filename_suffix,
    receipt: publicationReceipt,
    sha256: hash(canonicalJson(publicationReceipt)),
    size: Buffer.byteLength(canonicalJson(publicationReceipt)),
    uid: publicationIdentity.uid,
  };
  evidence.publication_receipt_passes = Array.from(
    { length: 4 },
    () => clone(publicationReceiptPass),
  );
  return {
    evidence,
    request: {
      installed_files: installedFiles,
      publisher_network: request,
      service_identities: [publicationIdentity],
      units: [publicationUnit],
    },
  };
}

function mutatePublisherOwners(value, mutate) {
  for (const boundary of value.evidence.boundary_confirmations) {
    mutate(boundary.namespace_owner, boundary);
  }
  return value;
}

function mutatePublisherProcessPasses(value, mutate) {
  return mutatePublisherOwners(value, (owner, boundary) => {
    for (const pass of owner.process_passes) mutate(pass, boundary);
  });
}

test("publisher network evidence binds nsfs, UFW raw/nft, sysctls, and one-way Caddy lifecycle", () => {
  const value = publisherNetworkFixture();
  assert.equal(validatePublisherNetworkRuntimeEvidenceV1(value.evidence, value.request), true);

  const source = readFileSync(COLLECTOR, "utf8");
  for (const key of PUBLISHER_FIREWALL_OUTPUT_KEYS) {
    assert.match(source, new RegExp(`\\b${key}:`, "u"), `collector must bind ${key}`);
  }

  const reverse = publisherNetworkFixture();
  reverse.evidence.boundary_confirmations[0].caddy_dependency.binds_to_namespace_owner = true;
  reverse.evidence.boundary_confirmations[1].caddy_dependency.binds_to_namespace_owner = true;
  assert.throws(
    () => validatePublisherNetworkRuntimeEvidenceV1(reverse.evidence, reverse.request),
    /reverse stop edge/u,
  );

  const extraDropIn = publisherNetworkFixture();
  for (const boundary of extraDropIn.evidence.boundary_confirmations) {
    boundary.caddy_dependency.drop_in_paths.push(
      "/etc/systemd/system/bhtm-caddy.service.d/unreviewed.conf",
    );
    boundary.caddy_dependency.drop_in_paths_sha256 = hash(JSON.stringify(
      boundary.caddy_dependency.drop_in_paths,
    ));
  }
  assert.throws(
    () => validatePublisherNetworkRuntimeEvidenceV1(extraDropIn.evidence, extraDropIn.request),
    /singleton reviewed drop-in/u,
  );

  for (const [label, mutate, expected] of [
    ["Caddy InvocationID", (generation) => { generation.invocation_id = "0".repeat(32); }, /loaded active Caddy generation/u],
    ["Caddy MainPID", (generation) => { generation.main_pid = "0"; }, /loaded active Caddy generation/u],
    ["Caddy NeedDaemonReload", (generation) => { generation.need_daemon_reload = "yes"; }, /loaded active Caddy generation/u],
  ]) {
    const candidate = publisherNetworkFixture();
    for (const boundary of candidate.evidence.boundary_confirmations) {
      for (const generation of boundary.caddy_dependency.generation_confirmations) {
        mutate(generation);
      }
    }
    assert.throws(
      () => validatePublisherNetworkRuntimeEvidenceV1(candidate.evidence, candidate.request),
      expected,
      label,
    );
  }

  const caddyConfigRace = publisherNetworkFixture();
  for (const boundary of caddyConfigRace.evidence.boundary_confirmations) {
    boundary.caddy_dependency.config_generation_confirmations[2].ino = "88002";
  }
  assert.throws(
    () => validatePublisherNetworkRuntimeEvidenceV1(
      caddyConfigRace.evidence,
      caddyConfigRace.request,
    ),
    /config generation was not stable/u,
  );

  const firewall = publisherNetworkFixture();
  firewall.evidence.firewall_passes[1].semantic_outputs.nft_ip_input.push(
    'iifname "bpir-pub-h" udp dport 53 accept',
  );
  assert.throws(
    () => validatePublisherNetworkRuntimeEvidenceV1(firewall.evidence, firewall.request),
    /closed UFW|changed around/u,
  );

  const mode = publisherNetworkFixture();
  mode.request.publisher_network.publication_mode.degraded = false;
  assert.throws(
    () => validatePublisherNetworkRuntimeEvidenceV1(mode.evidence, mode.request),
    /centralized closed profile/u,
  );

  const namespace = publisherNetworkFixture();
  namespace.request.publisher_network.namespace.client = "10.203.0.6/30";
  assert.throws(
    () => validatePublisherNetworkRuntimeEvidenceV1(namespace.evidence, namespace.request),
    /centralized closed profile/u,
  );

  const firewallRequest = publisherNetworkFixture();
  firewallRequest.request.publisher_network.firewall.ufw_rules_in_install_order.push(
    "allow out on bpir-pub-h to any proto udp port 53",
  );
  assert.throws(
    () => validatePublisherNetworkRuntimeEvidenceV1(
      firewallRequest.evidence,
      firewallRequest.request,
    ),
    /centralized closed profile/u,
  );

  const publisherUnit = publisherNetworkFixture();
  publisherUnit.request.publisher_network.publisher_unit = "bitcoinpir-unreviewed.service";
  assert.throws(
    () => validatePublisherNetworkRuntimeEvidenceV1(
      publisherUnit.evidence,
      publisherUnit.request,
    ),
    /centralized closed profile/u,
  );

  const publicationBinding = publisherNetworkFixture();
  publicationBinding.request.publisher_network.publication_time_firewall_binding.activation_blocked = false;
  assert.throws(
    () => validatePublisherNetworkRuntimeEvidenceV1(
      publicationBinding.evidence,
      publicationBinding.request,
    ),
    /centralized closed profile/u,
  );

  const missingFirewallOutput = publisherNetworkFixture();
  for (const pass of missingFirewallOutput.evidence.firewall_passes) {
    delete pass.output_sha256.nft_ip_base_input;
  }
  assert.throws(
    () => validatePublisherNetworkRuntimeEvidenceV1(
      missingFirewallOutput.evidence,
      missingFirewallOutput.request,
    ),
    /firewall output digests/u,
  );

  for (const [label, mutate, expression] of [
    ["zero namespace device", (candidate) => {
      for (const boundary of candidate.evidence.boundary_confirmations) {
        boundary.namespace_mount.dev = "0";
      }
    }, /nsfs mount/u],
    ["zero namespace inode", (candidate) => {
      for (const boundary of candidate.evidence.boundary_confirmations) {
        boundary.namespace_mount.ino = "0";
      }
    }, /nsfs mount/u],
    ["effective hardening mutation", (candidate) => mutatePublisherOwners(candidate, (owner) => {
      owner.effective_properties.NoNewPrivileges = "no";
    }), /NoNewPrivileges drifted/u],
    ["effective drop-in", (candidate) => mutatePublisherOwners(candidate, (owner) => {
      owner.effective_properties.DropInPaths = "/etc/systemd/system/unsafe.conf";
    }), /DropInPaths drifted/u],
    ["effective environment-removal mutation", (candidate) => mutatePublisherOwners(candidate, (owner) => {
      owner.effective_properties.UnsetEnvironment =
        "BASH_ENV ENV LD_PRELOAD NODE_OPTIONS";
    }), /UnsetEnvironment drifted/u],
    ["daemon reload pending", (candidate) => mutatePublisherOwners(candidate, (owner) => {
      owner.effective_properties.NeedDaemonReload = "yes";
      for (const confirmation of owner.generation_confirmations) {
        confirmation.need_daemon_reload = "yes";
      }
    }), /NeedDaemonReload drifted/u],
    ["condition mutation", (candidate) => mutatePublisherOwners(candidate, (owner) => {
      for (const conditions of owner.condition_confirmations) conditions.pop();
    }), /effective Conditions drifted/u],
    ["rogue effective argv", (candidate) => mutatePublisherOwners(candidate, (owner) => {
      owner.effective_properties.ExecStart = execValue(
        "/usr/bin/false run",
        { pid: "4402", state: "running" },
      );
    }), /executable argv drifted/u],
    ["main active capability", (candidate) => mutatePublisherProcessPasses(candidate, (pass) => {
      pass.main.capabilities.effective = "0000000000200000";
    }), /host monitor is not/u],
    ["child seccomp disabled", (candidate) => mutatePublisherProcessPasses(candidate, (pass) => {
      pass.child.seccomp = 0;
    }), /client monitor is not/u],
    ["no direct child", (candidate) => mutatePublisherProcessPasses(candidate, (pass) => {
      pass.direct_children = [];
    }), /exactly one canonical direct child/u],
    ["multiple direct children", (candidate) => mutatePublisherProcessPasses(candidate, (pass) => {
      pass.direct_children = [4403, 4404];
    }), /exactly one canonical direct child/u],
    ["wrong child namespace", (candidate) => mutatePublisherProcessPasses(candidate, (pass) => {
      pass.child.net_namespace = pass.collector_net_namespace;
    }), /client monitor is not/u],
    ["wrong child executable", (candidate) => mutatePublisherProcessPasses(candidate, (pass) => {
      pass.child.executable.path = "/usr/bin/false";
    }), /executable is not/u],
    ["wrong helper digest", (candidate) => mutatePublisherProcessPasses(candidate, (pass) => {
      pass.child.executable.sha256 = hash("rogue-helper");
    }), /executable is not/u],
    ["main UID mutation", (candidate) => mutatePublisherProcessPasses(candidate, (pass) => {
      pass.main.uid = [1, 1, 1, 1];
    }), /host monitor is not/u],
    ["child cgroup mutation", (candidate) => mutatePublisherProcessPasses(candidate, (pass) => {
      pass.child.control_group = "/system.slice/rogue.service";
    }), /client monitor is not/u],
    ["requested fragment digest mutation", (candidate) => {
      candidate.request.installed_files[0].sha256 = hash("rogue-fragment");
    }, /not bound to requested installed artifacts/u],
  ]) {
    const candidate = publisherNetworkFixture();
    mutate(candidate);
    assert.throws(
      () => validatePublisherNetworkRuntimeEvidenceV1(candidate.evidence, candidate.request),
      expression,
      label,
    );
  }
});

test("publisher receipt rejects artifact generation A after current pins advance to B", () => {
  const value = publisherNetworkFixture();
  const oldPin = value.request.publisher_network.publication_receipt.artifacts[0];
  const replacement = hash("publisher-artifact-generation-b");
  assert.notEqual(oldPin.sha256, replacement);
  oldPin.sha256 = replacement;
  const installed = value.request.installed_files.find(
    (file) => file.target_path === oldPin.path,
  );
  installed.sha256 = replacement;
  assert.throws(
    () => validatePublisherNetworkRuntimeEvidenceV1(value.evidence, value.request),
    /does not bind the current publication artifacts generation/u,
  );
});

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
    ExecStart: execValue(peerUnit.exec_start[0], { pid: "4243", state: "running" }),
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
    conditions: clone(value.evidence.units[0].conditions),
    credential_properties: emptyCredentialProperties(),
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
    service_property_passes: clone(value.evidence.units[0].service_property_passes),
    unit_dependencies: clone(value.evidence.units[0].unit_dependencies),
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
    gid: index === parents.length - 1 ? 731 : 0,
    ino: String(400 + index),
    mode: index === parents.length - 1 ? "0700" : "0755",
    nlink: 2,
    size: 40,
    stat_command_sha256: hash(`parent-stat-${index}`),
    target_path: target,
    uid: index === parents.length - 1 ? 730 : 0,
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

  const roundedWatchdogSentinel = fixture();
  roundedWatchdogSentinel.evidence.units[0].service_property_passes[0]
    .properties.WatchdogUSec = 18_446_744_073_709_552_000;
  assert.throws(
    () => validate(roundedWatchdogSentinel),
    /canonical uint64|typed watchdog is unreviewed/,
  );

  const dynamicIdentity = fixture();
  dynamicIdentity.request.service_identities[0].uid = 61_184;
  assert.throws(() => validate(dynamicIdentity), /static service uid\/gid.*DynamicUser/u);

  const privilegedStartRequest = fixture();
  privilegedStartRequest.request.units[0].exec_start_ex[0].flags = ["privileged"];
  assert.throws(() => validate(privilegedStartRequest), /unapproved exec flags/u);

  const typedStartPathDrift = fixture();
  typedStartPathDrift.evidence.units[0].service_property_passes[0]
    .properties.ExecStartEx[0].path = "/usr/bin/true";
  assert.throws(() => validate(typedStartPathDrift), /ExecStartEx drift/u);
});

test("systemd 255 text redundancy accepts one running start and completed pre-start", () => {
  const value = fixture();
  assert.match(value.evidence.units[0].properties.ExecStart, /code=\(null\) ; status=0\/0/u);
  assert.match(value.evidence.units[0].properties.ExecStartPre, /code=exited ; status=0/u);
  assert.equal(validate(value), true);
});

test("exact directory publisher accepts only a successful retained oneshot with no process holder", () => {
  const value = completedPublisherOneshotFixture();
  assert.equal(value.evidence.units[0].properties.MainPID, "0");
  assert.equal(value.evidence.units[0].properties.SubState, "exited");
  assert.equal(value.evidence.units[0].process_identity, null);
  assert.deepEqual(
    value.evidence.protected_process_closure.passes.map((pass) => pass.holders),
    [[], []],
  );
  assert.equal(validate(value), true);

  const mutations = [
    ["MainPID", "4242", /successful retained oneshot generation/u],
    ["SubState", "running", /successful retained oneshot generation/u],
    ["Result", "exit-code", /successful retained oneshot generation/u],
    ["ExecMainCode", "0", /successful retained oneshot generation/u],
    ["ExecMainStatus", "1", /successful retained oneshot generation/u],
    ["NeedDaemonReload", "yes", /NeedDaemonReload drift/u],
    ["RemainAfterExit", "no", /RemainAfterExit drift/u],
  ];
  for (const [property, replacement, pattern] of mutations) {
    const candidate = completedPublisherOneshotFixture();
    candidate.evidence.units[0].properties[property] = replacement;
    assert.throws(() => validate(candidate), pattern, property);
  }

  const runningExec = completedPublisherOneshotFixture();
  runningExec.evidence.units[0].properties.ExecStart = execValue(
    runningExec.request.units[0].exec_start[0],
    { pid: "4242", state: "running" },
  );
  assert.throws(
    () => validate(runningExec),
    /successful completed oneshot ExecStart/u,
  );

  const staleProcessIdentity = completedPublisherOneshotFixture();
  staleProcessIdentity.evidence.units[0].process_identity =
    fixture().evidence.units[0].process_identity;
  assert.throws(
    () => validate(staleProcessIdentity),
    /unexpectedly retains process identity evidence/u,
  );

  const staleCredentialHolder = completedPublisherOneshotFixture();
  const holder = protectedHolder({
    controlGroup:
      "/system.slice/bitcoinpir-payment-v1-directory-publisher.service",
    gid: 731,
    groups: [731, 732],
    ino: "99",
    pid: 4242,
    startTime: "123456",
    uid: 730,
  });
  for (const pass of staleCredentialHolder.evidence.protected_process_closure.passes) {
    pass.holders = [clone(holder)];
  }
  assert.throws(
    () => validate(staleCredentialHolder),
    /outside every managed unit cgroup/u,
  );

  const wrongReceiptInvocation = completedPublisherOneshotFixture();
  for (const pass of
    wrongReceiptInvocation.evidence.publisher_network.publication_receipt_passes) {
    pass.receipt.invocation_id = "e".repeat(32);
    pass.path =
      `/var/lib/bitcoinpir-directory-publication/${pass.receipt.invocation_id}.json`;
    pass.sha256 = hash(canonicalJson(pass.receipt));
    pass.size = Buffer.byteLength(canonicalJson(pass.receipt));
  }
  assert.throws(
    () => validate(wrongReceiptInvocation),
    /receipt is not bound to the exact successful oneshot InvocationID/u,
  );

  const reorderedReceiptArgv = completedPublisherOneshotFixture();
  for (const pass of
    reorderedReceiptArgv.evidence.publisher_network.publication_receipt_passes) {
    [pass.receipt.argv[3], pass.receipt.argv[4]] =
      [pass.receipt.argv[4], pass.receipt.argv[3]];
    pass.sha256 = hash(canonicalJson(pass.receipt));
    pass.size = Buffer.byteLength(canonicalJson(pass.receipt));
  }
  assert.throws(
    () => validate(reorderedReceiptArgv),
    /does not bind the current publication argv generation/u,
  );

  const forgedReceiptDigest = completedPublisherOneshotFixture();
  for (const pass of
    forgedReceiptDigest.evidence.publisher_network.publication_receipt_passes) {
    pass.sha256 = hash("forged receipt digest");
  }
  assert.throws(
    () => validate(forgedReceiptDigest),
    /size or digest does not bind its canonical receipt bytes/u,
  );

  const forgedReceiptSize = completedPublisherOneshotFixture();
  for (const pass of
    forgedReceiptSize.evidence.publisher_network.publication_receipt_passes) {
    pass.size += 1;
  }
  assert.throws(
    () => validate(forgedReceiptSize),
    /size or digest does not bind its canonical receipt bytes/u,
  );

  const staleCurrentArtifactSet = completedPublisherOneshotFixture();
  for (const pass of
    staleCurrentArtifactSet.evidence.publisher_network.publication_receipt_passes) {
    pass.current_event_set.event_set_digest_hex = hash("current artifact generation b");
  }
  assert.throws(
    () => validate(staleCurrentArtifactSet),
    /event count or digest was not recomputed from the current artifacts/u,
  );

  const missingPostFileReceiptSeal = completedPublisherOneshotFixture();
  missingPostFileReceiptSeal.evidence.publisher_network.publication_receipt_passes.pop();
  assert.throws(
    () => validate(missingPostFileReceiptSeal),
    /not stable across four descriptor-bound passes/u,
  );

  const postFileReceiptRace = completedPublisherOneshotFixture();
  postFileReceiptRace.evidence.publisher_network.publication_receipt_passes[3].ino =
    "91003";
  assert.throws(
    () => validate(postFileReceiptRace),
    /not stable across four descriptor-bound passes/u,
  );

  const postFileUnitRace = completedPublisherOneshotFixture();
  postFileUnitRace.evidence.units[0].generation_confirmations[3].invocation_id =
    "e".repeat(32);
  assert.throws(
    () => validate(postFileUnitRace),
    /unit generation changed during collection/u,
  );

  const wrongProfile = completedPublisherOneshotFixture();
  wrongProfile.request.deployment_profile = "test";
  assert.throws(
    () => validate(wrongProfile),
    /reviewed running ExecStart|unreviewed long-running Type/u,
  );

  const unreviewedOneshot = completedPublisherOneshotFixture();
  const unreviewedName = "bitcoinpir-unreviewed-oneshot.service";
  unreviewedOneshot.request.units[0].unit_name = unreviewedName;
  unreviewedOneshot.request.service_identities[0].unit_name = unreviewedName;
  unreviewedOneshot.evidence.units[0].unit_name = unreviewedName;
  unreviewedOneshot.evidence.units[0].properties.BindReadOnlyPaths = "";
  unreviewedOneshot.evidence.units[0].properties.ControlGroup =
    `/system.slice/${unreviewedName}`;
  unreviewedOneshot.evidence.units[0].properties.ExecStart = execValue(
    unreviewedOneshot.request.units[0].exec_start[0],
    { pid: "0", state: "running" },
  );
  for (const confirmation of
    unreviewedOneshot.evidence.units[0].generation_confirmations) {
    confirmation.control_group = `/system.slice/${unreviewedName}`;
  }
  assert.throws(
    () => validate(unreviewedOneshot),
    /publication receipt request lacks its exact unit\/identity generation|unreviewed long-running Type/u,
  );
});

test("systemd 255 watchdog text and typed uint64 agree with each lifecycle", () => {
  const ordinary = fixture();
  assert.equal(ordinary.evidence.units[0].properties.WatchdogUSec, "0");
  assert.equal(
    ordinary.evidence.units[0].service_property_passes[0].properties.WatchdogUSec,
    "0",
  );
  assert.equal(validate(ordinary), true);

  const stopped = stoppedEdgeFixture();
  assert.equal(
    stopped.evidence.unit_configuration_passes[0][0].properties.WatchdogUSec,
    "infinity",
  );
  assert.equal(
    stopped.evidence.unit_configuration_passes[0][0]
      .service_properties.WatchdogUSec,
    UINT64_MAX_DECIMAL,
  );
  assert.equal(validateStopped(stopped), true);

  const preflight = preflightLeaseFixture();
  assert.equal(preflight.evidence.units[0].properties.WatchdogUSec, "1min 30s");
  assert.equal(
    preflight.evidence.units[0].service_property_passes[0].properties.WatchdogUSec,
    "90000000",
  );
  assert.equal(validate(preflight), true);

  const ordinaryTextMismatch = fixture();
  ordinaryTextMismatch.evidence.units[0].properties.WatchdogUSec = "infinity";
  assert.throws(() => validate(ordinaryTextMismatch), /live scalar watchdog interval/u);

  const ordinaryTypedMismatch = fixture();
  ordinaryTypedMismatch.evidence.units[0].service_property_passes[0]
    .properties.WatchdogUSec = UINT64_MAX_DECIMAL;
  assert.throws(() => validate(ordinaryTypedMismatch), /typed watchdog interval/u);

  const stoppedTextMismatch = stoppedEdgeFixture();
  stoppedTextMismatch.evidence.unit_configuration_passes[0][0]
    .properties.WatchdogUSec = "0";
  assert.throws(() => validateStopped(stoppedTextMismatch), /stopped scalar watchdog interval/u);

  const stoppedTypedMismatch = stoppedEdgeFixture();
  stoppedTypedMismatch.evidence.unit_configuration_passes[0][0]
    .service_properties.WatchdogUSec = "0";
  assert.throws(() => validateStopped(stoppedTypedMismatch), /stopped typed watchdog interval/u);

  const preflightTextMismatch = preflightLeaseFixture();
  preflightTextMismatch.evidence.units[0].properties.WatchdogUSec = "0";
  assert.throws(() => validate(preflightTextMismatch), /watchdog lease drift/u);

  const preflightTypedMismatch = preflightLeaseFixture();
  preflightTypedMismatch.evidence.units[0].service_property_passes[0]
    .properties.WatchdogUSec = "0";
  assert.throws(() => validate(preflightTypedMismatch), /typed watchdog interval/u);
});

test("resolved directory relay can produce live evidence only for its closed artifact shape", () => {
  const value = resolvedLiveRelayFixture();
  assert.equal(validate(value), true);

  const missingConfigManifest = resolvedLiveRelayFixture();
  missingConfigManifest.request.installed_files.splice(1, 1);
  assert.throws(
    () => validate(missingConfigManifest),
    /artifact or identity closure/,
  );

  const publisherKey = resolvedLiveRelayFixture();
  publisherKey.request.installed_files.push({
    file_type: "regular",
    gid: 52952,
    mode: "0400",
    nlink: 1,
    sha256: hash("publisher-private-key"),
    target_path: "/etc/bitcoinpir/payment-v1/directory-relay/publisher-private.key",
    uid: 52951,
  });
  assert.throws(() => validate(publisherKey), /artifact or identity closure/);

  const weakRequestProc = resolvedLiveRelayFixture();
  weakRequestProc.request.units[0].hardening.ProtectProc = ["default"];
  assert.throws(
    () => validate(weakRequestProc),
    /unresolved directory-relay-v1|artifact or identity closure/u,
  );

  const weakEffectiveProc = resolvedLiveRelayFixture();
  weakEffectiveProc.evidence.units[0].properties.ProtectProc = "default";
  assert.throws(() => validate(weakEffectiveProc), /effective ProtectProc drift/u);

  const fullEffectiveProc = resolvedLiveRelayFixture();
  fullEffectiveProc.evidence.units[0].properties.ProcSubset = "all";
  assert.throws(() => validate(fullEffectiveProc), /effective ProcSubset drift/u);
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

test("NSS policy accepts only reviewed files-authoritative source sequences", () => {
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
  assert.deepEqual(
    parseLocalFilesNsswitchV1([
      "passwd: files systemd",
      "group: files systemd # Ubuntu's reviewed fallback sequence",
      "hosts: files dns",
      "",
    ].join("\n")),
    {
      group: ["files", "systemd"],
      initgroups: "inherits-group",
      passwd: ["files", "systemd"],
    },
  );
  for (const input of [
    "passwd: files systemd\ngroup: files\n",
    "passwd: files\ngroup: files systemd\n",
    "passwd: systemd files\ngroup: systemd files\n",
    "passwd: systemd\ngroup: systemd\n",
    "passwd: files systemd systemd\ngroup: files systemd systemd\n",
    "passwd: files\ngroup: files sss\n",
    "passwd: files ldap\ngroup: files ldap\n",
    "passwd: files dns\ngroup: files dns\n",
    "passwd: files winbind\ngroup: files winbind\n",
    "passwd: files nis\ngroup: files nis\n",
    "passwd: files\ngroup: files\ninitgroups: files\n",
    "passwd: files\npasswd: files\ngroup: files\n",
    "passwd: files\ngroup: files [SUCCESS=merge] systemd\n",
    "passwd: compat\ngroup: compat\n",
  ]) {
    assert.throws(
      () => parseLocalFilesNsswitchV1(input),
      /files-only or files-then-systemd|inherit group|repeats|simple local profile/,
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

test("final NSS snapshot confirmation repeats the complete getent and id projection", () => {
  const nss = fixture().evidence.nss;
  assert.equal(assertCompleteNssSnapshotUnchangedV2(nss, clone(nss)), true);

  const changedPasswdProjection = clone(nss);
  changedPasswdProjection.passwd_stdout_sha256 = hash("changed-passwd-projection");
  assert.throws(
    () => assertCompleteNssSnapshotUnchangedV2(nss, changedPasswdProjection),
    /complete getent\/id projection changed/,
  );

  const changedGroups = clone(nss);
  changedGroups.users[0].supplementary_gids = [731];
  assert.throws(
    () => assertCompleteNssSnapshotUnchangedV2(nss, changedGroups),
    /complete getent\/id projection changed/,
  );

  const changedFallback = clone(nss);
  changedFallback.sources.passwd = ["files", "systemd"];
  changedFallback.sources.group = ["files", "systemd"];
  assert.throws(
    () => assertCompleteNssSnapshotUnchangedV2(nss, changedFallback),
    /complete getent\/id projection changed/,
  );
});

test(
  "Linux one-link reader seals a transient same-inode rewrite before its final descriptor read",
  { skip: !CAN_EXERCISE_INSTALLED_FILE_PROBES },
  () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "bitcoinpir-one-link-")));
    try {
      const target = join(root, "artifact");
      const bytes = Buffer.from("descriptor-bound-original\n");
      const replacement = Buffer.from("descriptor-bound-replaced\n");
      assert.equal(replacement.length, bytes.length);
      writeFileSync(target, bytes, { mode: 0o640 });
      chmodSync(target, 0o640);
      const timestampReference = createExactTimestampReference(root, target);
      const initial = lstatSync(target, { bigint: true });

      assert.throws(
        () => readOneLinkRegularForTestV1(target, "test artifact", 4096, {
          afterFirstRead: () => {
            writeFileSync(target, replacement);
            writeFileSync(target, bytes);
            chmodSync(target, 0o640);
            restoreExactTimestamps(timestampReference, target);
            const restored = lstatSync(target, { bigint: true });
            assert.equal(restored.mtimeNs, initial.mtimeNs);
            assert.notEqual(restored.ctimeNs, initial.ctimeNs);
          },
        }),
        /changed precise metadata/,
      );
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  },
);

test(
  "Linux runtime commands execute the verified open descriptor",
  { skip: !CAN_EXERCISE_DESCRIPTOR_COMMANDS },
  () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "bitcoinpir-command-fd-")));
    try {
      const target = join(root, "command");
      writeFileSync(target, readFileSync("/usr/bin/true"));
      chmodSync(target, 0o755);
      const result = runDescriptorBoundCommandForTestV1(target, [], {});
      assert.equal(result.exit_status, 0);
      assert.equal(result.stdout, "");
      assert.equal(result.stderr, "");
      assert.deepEqual(result.argv, [target]);
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  },
);

test("final command-pin closure rechecks every pathname, inode, and SHA-256", () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "bitcoinpir-command-final-")));
  try {
    const first = join(root, "command-a");
    const second = join(root, "command-b");
    const replacement = join(root, "replacement");
    const parked = join(root, "parked");
    const bytes = process.platform === "linux"
      ? readFileSync("/usr/bin/true")
      : Buffer.from("#!/bin/sh\nexit 0\n", "utf8");
    for (const path of [first, second, replacement]) {
      writeFileSync(path, bytes);
      chmodSync(path, 0o755);
    }
    assert.notEqual(lstatSync(second).ino, lstatSync(replacement).ino);
    assert.throws(
      () => confirmDescriptorBoundCommandPinsForTestV1([first, second], () => {
        renameSync(second, parked);
        renameSync(replacement, second);
      }),
      /final runtime command pin pathname, inode, metadata, or SHA-256 changed/u,
    );
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test(
  "Linux setpriv access probe executes its nested test command by inherited descriptor",
  { skip: !CAN_EXERCISE_DESCRIPTOR_SETPRIV },
  () => {
    const result = runDescriptorBoundSetprivProbeForTestV1();
    assert.equal(result.exit_status, 0);
    assert.equal(result.stdout, "");
    assert.equal(result.stderr, "");
    assert.equal(result.argv.at(-3), "/usr/bin/test");
  },
);

for (const phase of ["afterDescriptorVerification", "afterSpawn"]) {
  test(
    `Linux descriptor command rejects pathname/inode replacement ${phase}`,
    { skip: !CAN_EXERCISE_DESCRIPTOR_COMMANDS },
    () => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), "bitcoinpir-command-path-")));
      try {
        const target = join(root, "command");
        const replacement = join(root, "replacement");
        const parked = join(root, "parked");
        const bytes = readFileSync("/usr/bin/true");
        for (const path of [target, replacement]) {
          writeFileSync(path, bytes);
          chmodSync(path, 0o755);
        }
        assert.notEqual(lstatSync(target).ino, lstatSync(replacement).ino);
        assert.throws(
          () => runDescriptorBoundCommandForTestV1(target, [], {
            [phase]: () => {
              renameSync(target, parked);
              renameSync(replacement, target);
            },
          }),
          /pathname, inode, metadata, or SHA-256 changed|changed precise metadata/u,
        );
      } finally {
        rmSync(root, { force: true, recursive: true });
      }
    },
  );
}

test(
  "Linux descriptor command rejects a same-inode SHA-256 race before exec",
  { skip: !CAN_EXERCISE_DESCRIPTOR_COMMANDS },
  () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "bitcoinpir-command-hash-")));
    try {
      const target = join(root, "command");
      const bytes = readFileSync("/usr/bin/true");
      const changed = Buffer.from(bytes);
      changed[changed.length - 1] ^= 0x01;
      writeFileSync(target, bytes);
      chmodSync(target, 0o755);
      const initial = lstatSync(target);
      assert.throws(
        () => runDescriptorBoundCommandForTestV1(target, [], {
          afterDescriptorVerification: () => {
            writeFileSync(target, changed);
            chmodSync(target, 0o755);
            assert.equal(lstatSync(target).ino, initial.ino);
          },
        }),
        /SHA-256 changed before descriptor execution/u,
      );
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  },
);

for (const phase of ["afterOpen", "afterFirstRead", "afterFinalPathOpen"]) {
  test(
    `Linux one-link reader rejects pathname replacement ${phase}`,
    { skip: !CAN_EXERCISE_INSTALLED_FILE_PROBES },
    () => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), "bitcoinpir-one-link-path-")));
      try {
        const target = join(root, "artifact");
        const replacement = join(root, "replacement");
        const parked = join(root, "parked");
        const bytes = Buffer.from("same-content-and-metadata\n");
        for (const path of [target, replacement]) {
          writeFileSync(path, bytes, { mode: 0o640 });
          chmodSync(path, 0o640);
        }
        assert.throws(
          () => readOneLinkRegularForTestV1(target, "test artifact", 4096, {
            [phase]: () => {
              renameSync(target, parked);
              renameSync(replacement, target);
            },
          }),
          /changed precise metadata|do not name the same stable file/,
        );
      } finally {
        rmSync(root, { force: true, recursive: true });
      }
    },
  );
}

for (const [label, mutation] of [
  ["truncation", Buffer.from("short\n")],
  ["growth", Buffer.from("descriptor-bound-original-with-growth\n")],
]) {
  test(
    `Linux one-link reader rejects descriptor ${label}`,
    { skip: !CAN_EXERCISE_INSTALLED_FILE_PROBES },
    () => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), "bitcoinpir-one-link-size-")));
      try {
        const target = join(root, "artifact");
        const bytes = Buffer.from("descriptor-bound-original\n");
        writeFileSync(target, bytes, { mode: 0o640 });
        chmodSync(target, 0o640);
        assert.throws(
          () => readOneLinkRegularForTestV1(target, "test artifact", 4096, {
            afterFirstRead: () => writeFileSync(target, mutation),
          }),
          /changed precise metadata|do not name the same stable file|final descriptor read/,
        );
      } finally {
        rmSync(root, { force: true, recursive: true });
      }
    },
  );
}

test(
  "Linux installed-file probes bind content and metadata to one open descriptor",
  { skip: !CAN_EXERCISE_INSTALLED_FILE_PROBES },
  () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "bitcoinpir-installed-fd-")));
    try {
      const target = join(root, "artifact");
      const bytes = Buffer.from("descriptor-bound-installed-artifact\n");
      writeFileSync(target, bytes, { mode: 0o640 });
      chmodSync(target, 0o640);
      const expected = installedFileExpectation(target, bytes);
      const observed = collectInstalledFileForTestV1(expected, {});
      const stat = lstatSync(target, { bigint: true });

      assert.equal(observed.dev, stat.dev.toString());
      assert.equal(observed.ino, stat.ino.toString());
      assert.equal(observed.sha256, expected.sha256);
      assert.equal(
        observed.sha256_command_sha256,
        hash(`${expected.sha256} *${target}\n`),
      );
      assert.equal(observed.expected_type, "regular");
      for (const field of [
        "acl_sha256",
        "capability_sha256",
        "sha256_command_sha256",
        "stat_command_sha256",
        "xattr_sha256",
      ]) {
        assert.match(observed[field], /^[0-9a-f]{64}$/u);
      }
      assert.deepEqual(collectInstalledFileForTestV1(expected, {}), observed);
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  },
);

for (const phase of [
  "afterOpen",
  "afterFirstRead",
  "afterMetadataProbe",
  "beforeFinalPathOpen",
  "afterFinalPathOpen",
]) {
  test(
    `Linux installed-file binding rejects same-metadata pathname replacement ${phase}`,
    { skip: !CAN_EXERCISE_INSTALLED_FILE_PROBES },
    () => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), "bitcoinpir-installed-race-")));
      try {
        const target = join(root, "artifact");
        const replacement = join(root, "replacement");
        const parked = join(root, "opened-artifact");
        const bytes = Buffer.from("same-content-and-metadata\n");
        for (const path of [target, replacement]) {
          writeFileSync(path, bytes, { mode: 0o640 });
          chmodSync(path, 0o640);
        }
        const expected = installedFileExpectation(target, bytes);
        const initial = lstatSync(target);
        const alternate = lstatSync(replacement);
        assert.notEqual(initial.ino, alternate.ino);
        for (const field of ["dev", "gid", "mode", "nlink", "size", "uid"]) {
          assert.equal(initial[field], alternate[field], `replacement ${field}`);
        }

        assert.throws(
          () => collectInstalledFileForTestV1(expected, {
            [phase]: () => {
              renameSync(target, parked);
              renameSync(replacement, target);
            },
          }),
          /changed precise metadata|do not name the same stable file/,
        );
      } finally {
        rmSync(root, { force: true, recursive: true });
      }
    },
  );
}

test(
  "Linux installed-file binding rejects a same-inode content rewrite after metadata probes",
  { skip: !CAN_EXERCISE_INSTALLED_FILE_PROBES },
  () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "bitcoinpir-installed-inplace-")));
    try {
      const target = join(root, "artifact");
      const bytes = Buffer.from("descriptor-bound-original\n");
      const replacement = Buffer.from("descriptor-bound-replaced\n");
      assert.equal(replacement.length, bytes.length);
      writeFileSync(target, bytes, { mode: 0o640 });
      chmodSync(target, 0o640);
      const expected = installedFileExpectation(target, bytes);
      const timestampReference = createExactTimestampReference(root, target);
      const initial = lstatSync(target, { bigint: true });

      assert.throws(
        () => collectInstalledFileForTestV1(expected, {
          afterMetadataProbe: () => {
            writeFileSync(target, replacement);
            chmodSync(target, 0o640);
            restoreExactTimestamps(timestampReference, target);
            const restored = lstatSync(target, { bigint: true });
            assert.equal(restored.mtimeNs, initial.mtimeNs);
          },
        }),
        /content changed during descriptor reread|changed precise metadata/,
      );
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  },
);

test(
  "Linux installed-file binding seals ctime across a transient same-inode rewrite",
  { skip: !CAN_EXERCISE_INSTALLED_FILE_PROBES },
  () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "bitcoinpir-installed-ctime-")));
    try {
      const target = join(root, "artifact");
      const bytes = Buffer.from("descriptor-bound-original\n");
      const replacement = Buffer.from("descriptor-bound-replaced\n");
      assert.equal(replacement.length, bytes.length);
      writeFileSync(target, bytes, { mode: 0o640 });
      chmodSync(target, 0o640);
      const expected = installedFileExpectation(target, bytes);
      const timestampReference = createExactTimestampReference(root, target);
      const initial = lstatSync(target, { bigint: true });

      assert.throws(
        () => collectInstalledFileForTestV1(expected, {
          afterMetadataProbe: () => {
            writeFileSync(target, replacement);
            writeFileSync(target, bytes);
            chmodSync(target, 0o640);
            restoreExactTimestamps(timestampReference, target);
            const restored = lstatSync(target, { bigint: true });
            assert.equal(restored.mtimeNs, initial.mtimeNs);
            assert.notEqual(restored.ctimeNs, initial.ctimeNs);
          },
        }),
        /changed precise metadata/,
      );
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  },
);

test(
  "Linux installed-file binding seals transient hardlink creation and removal",
  { skip: !CAN_EXERCISE_INSTALLED_FILE_PROBES },
  () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "bitcoinpir-installed-nlink-")));
    try {
      const target = join(root, "artifact");
      const alias = join(root, "transient-hardlink");
      const bytes = Buffer.from("descriptor-bound-original\n");
      writeFileSync(target, bytes, { mode: 0o640 });
      chmodSync(target, 0o640);
      const expected = installedFileExpectation(target, bytes);

      assert.throws(
        () => collectInstalledFileForTestV1(expected, {
          afterMetadataProbe: () => {
            linkSync(target, alias);
            unlinkSync(alias);
          },
        }),
        /changed precise metadata/,
      );
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  },
);

test(
  "Linux repeated installed-file collections retain a private precise fingerprint",
  { skip: !CAN_EXERCISE_INSTALLED_FILE_PROBES },
  () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "bitcoinpir-installed-cross-pass-")));
    try {
      const target = join(root, "artifact");
      const bytes = Buffer.from("descriptor-bound-original\n");
      const replacement = Buffer.from("descriptor-bound-replaced\n");
      assert.equal(replacement.length, bytes.length);
      writeFileSync(target, bytes, { mode: 0o640 });
      chmodSync(target, 0o640);
      const expected = installedFileExpectation(target, bytes);
      const timestampReference = createExactTimestampReference(root, target);
      const initial = lstatSync(target, { bigint: true });

      assert.throws(
        () => confirmInstalledFileAcrossCollectionsForTestV1(expected, () => {
          writeFileSync(target, replacement);
          writeFileSync(target, bytes);
          chmodSync(target, 0o640);
          restoreExactTimestamps(timestampReference, target);
          const restored = lstatSync(target, { bigint: true });
          assert.equal(restored.mtimeNs, initial.mtimeNs);
          assert.notEqual(restored.ctimeNs, initial.ctimeNs);
        }),
        /metadata or content changed between test collections/,
      );
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  },
);

test(
  "Linux secret-parent evidence walks and probes one descriptor-bound directory chain",
  { skip: !CAN_EXERCISE_INSTALLED_FILE_PROBES },
  () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "bitcoinpir-secret-chain-")));
    try {
      const target = join(root, "consumer");
      createExactDirectory(target);
      const observed = collectSecretParentDirectoryForTestV1(target, {});
      const stat = lstatSync(target);
      assert.equal(observed.target_path, target);
      assert.equal(observed.dev, stat.dev.toString());
      assert.equal(observed.ino, stat.ino.toString());
      assert.equal(observed.mode, "0700");
      assert.equal(observed.expected_type, "directory");
      assert.deepEqual(collectSecretParentDirectoryForTestV1(target, {}), observed);
      assert.deepEqual(
        confirmSecretParentDirectoryAcrossCollectionsForTestV1(target, () => {}),
        observed,
      );
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  },
);

for (const replacedComponent of ["final", "intermediate"]) {
  test(
    `Linux secret-parent descriptor walk rejects ${replacedComponent} directory ABA`,
    { skip: !CAN_EXERCISE_INSTALLED_FILE_PROBES },
    () => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), "bitcoinpir-secret-aba-")));
      try {
        const chainRoot = join(root, "chain");
        createExactDirectory(chainRoot);
        let alternate;
        let alternateParked;
        let mutationParent;
        let parked;
        let target;
        let targetPath;
        if (replacedComponent === "final") {
          const intermediate = join(chainRoot, "intermediate");
          createExactDirectory(intermediate);
          target = join(intermediate, "final");
          alternate = join(intermediate, "alternate-final");
          parked = join(intermediate, "parked-final");
          alternateParked = join(intermediate, "alternate-parked-final");
          mutationParent = intermediate;
          createExactDirectory(target);
          createExactDirectory(alternate);
          targetPath = target;
        } else {
          target = join(chainRoot, "intermediate");
          alternate = join(chainRoot, "alternate-intermediate");
          parked = join(chainRoot, "parked-intermediate");
          alternateParked = join(chainRoot, "alternate-parked-intermediate");
          mutationParent = chainRoot;
          createExactDirectory(target);
          createExactDirectory(alternate);
          createExactDirectory(join(target, "final"));
          createExactDirectory(join(alternate, "final"));
          targetPath = join(target, "final");
        }
        const originalInode = lstatSync(target).ino;
        const alternateInode = lstatSync(alternate).ino;
        assert.notEqual(originalInode, alternateInode);

        assert.throws(
          () => collectSecretParentDirectoryForTestV1(
            targetPath,
            directoryAbaHooks({
              alternate,
              alternateParked,
              mutationParent,
              parked,
              target,
            }),
          ),
          /independent stat mismatch|pinned secret directory metadata changed during probes|pinned\/final descriptor mismatch/,
        );
        assert.equal(lstatSync(target).ino, originalInode, "ABA restored original inode");
      } finally {
        rmSync(root, { force: true, recursive: true });
      }
    },
  );
}

test(
  "Linux final sealing rejects directory ABA between initial and confirmation collections",
  { skip: !CAN_EXERCISE_INSTALLED_FILE_PROBES },
  () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "bitcoinpir-secret-seal-")));
    try {
      const parent = join(root, "consumer");
      const target = join(parent, "keys");
      const alternate = join(parent, "alternate-keys");
      const parked = join(parent, "parked-keys");
      const alternateParked = join(parent, "alternate-parked-keys");
      createExactDirectory(parent);
      createExactDirectory(target);
      createExactDirectory(alternate);
      const originalInode = lstatSync(target).ino;

      assert.throws(
        () => confirmSecretParentDirectoryAcrossCollectionsForTestV1(
          target,
          () => {
            renameSync(target, parked);
            renameSync(alternate, target);
            renameSync(target, alternateParked);
            renameSync(parked, target);
            utimesSync(parent, new Date(3_000), new Date(4_000));
          },
        ),
        /secret parent directory namespace fingerprint changed between test collections/,
      );
      assert.equal(lstatSync(target).ino, originalInode, "ABA restored original inode");
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  },
);

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

  for (const id of [60_001, 61_184, 65_519, 65_534]) {
    const outsideStaticRange = clone(identities);
    outsideStaticRange[0].uid = id;
    assert.throws(
      () => parseLockedServiceAccountPolicyV1(
        `bitcoinpir-test:x:${id}:731::/nonexistent:/usr/sbin/nologin\n`,
        "bitcoinpir-test:!:1:0:99999:7:::\n",
        outsideStaticRange,
      ),
      /static service uid\/gid.*DynamicUser/u,
    );
  }
});

test("stopped-edge activation evidence closes units, sockets, identities, and login reacquisition", () => {
  const value = stoppedEdgeFixture();
  assert.equal(validateStopped(value), true);

  const reviewedSystemdFallback = stoppedEdgeFixture();
  reviewedSystemdFallback.evidence.nss.sources.passwd = ["files", "systemd"];
  reviewedSystemdFallback.evidence.nss.sources.group = ["files", "systemd"];
  assert.equal(validateStopped(reviewedSystemdFallback), true);

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

  const stoppedTypedStartDrift = stoppedEdgeFixture();
  stoppedTypedStartDrift.evidence.unit_configuration_passes[1][0]
    .service_properties.ExecStartEx[0].argv[0] = "/usr/bin/true";
  assert.throws(() => validateStopped(stoppedTypedStartDrift), /ExecStartEx drift/u);

  const stoppedForeignManager = stoppedEdgeFixture();
  stoppedForeignManager.evidence.systemd_manager_passes[1].Version.value =
    "255.4-1ubuntu8.14";
  assert.throws(
    () => validateStopped(stoppedForeignManager),
    /Version must be typed s 255\.4-1ubuntu8\.15/u,
  );

  const namespace = stoppedEdgeFixture();
  namespace.evidence.host.collector_pid_namespace = "pid:[4026539999]";
  assert.throws(() => validateStopped(namespace), /PID namespace/);

  const stoppedHostVersion = stoppedEdgeFixture();
  stoppedHostVersion.evidence.host.systemd_version = "systemd 255";
  assert.throws(() => validateStopped(stoppedHostVersion), /systemd|host, boot/u);

  const stoppedRequestVersion = stoppedEdgeFixture();
  stoppedRequestVersion.request.systemd_version = "systemd 255";
  assert.throws(() => validateStopped(stoppedRequestVersion), /systemd_version/u);

  const legacy = stoppedEdgeFixture();
  legacy.evidence.protected_process_closure.enumeration_kind =
    "procfs-v2-all-thread-credentials-two-pass-v1";
  assert.throws(() => validateStopped(legacy), /closure is incomplete/);

  const legacySchema = stoppedEdgeFixture();
  legacySchema.evidence.schema_version = 4;
  legacySchema.evidence.evidence_kind =
    "bitcoinpir-payment-v1-linux-root-stopped-edge-v4";
  legacySchema.evidence.collector =
    "bitcoinpir-payment-v1-linux-runtime-evidence-v7";
  assert.throws(() => validateStopped(legacySchema), /evidence schema, collector/);

  const legacyRequest = stoppedEdgeFixture();
  legacyRequest.request.schema_version = 7;
  legacyRequest.request.collector =
    "bitcoinpir-payment-v1-linux-runtime-evidence-v7";
  assert.throws(() => validateStopped(legacyRequest), /evidence schema, collector/);

  const missingCredentialRequestClosure = stoppedEdgeFixture();
  delete missingCredentialRequestClosure.request.busctl_service_properties;
  assert.throws(
    () => validateStopped(missingCredentialRequestClosure),
    /busctl Service property schema/,
  );
});

test("live and stopped evidence reject every non-empty typed credential property", () => {
  for (const property of CREDENTIAL_SERVICE_PROPERTIES) {
    const live = fixture();
    live.evidence.units[0].credential_properties[property].data =
      property === "ImportCredential"
        ? ["secret.*"]
        : property.startsWith("Load")
        ? [["secret", "/tmp/secret"]]
        : [["secret", [1, 2, 3]]];
    assert.throws(() => validate(live), new RegExp(property), `live ${property}`);

    const stoppedEdge = stoppedEdgeFixture();
    stoppedEdge.evidence.stopped_unit_passes[0][0]
      .credential_properties[property].data =
        property === "ImportCredential"
          ? ["secret.*"]
          : property.startsWith("Load")
          ? [["secret", "/tmp/secret"]]
          : [["secret", [1, 2, 3]]];
    assert.throws(
      () => validateStopped(stoppedEdge),
      new RegExp(property),
      `stopped edge ${property}`,
    );

    const stoppedRelay = stoppedRelayFixture();
    stoppedRelay.evidence.unit_configuration_passes[1][0]
      .credential_properties[property].data =
        property === "ImportCredential"
          ? ["secret.*"]
          : property.startsWith("Load")
          ? [["secret", "/tmp/secret"]]
          : [["secret", [1, 2, 3]]];
    assert.throws(
      () => validateStoppedRelay(stoppedRelay),
      new RegExp(property),
      `stopped relay ${property}`,
    );
  }
});

test("stopped directory-relay preparation is closed and can never become live evidence", () => {
  const value = stoppedRelayFixture();
  assert.equal(validateStoppedRelay(value), true);

  const reviewedSystemdFallback = stoppedRelayFixture();
  reviewedSystemdFallback.evidence.nss.sources.passwd = ["files", "systemd"];
  reviewedSystemdFallback.evidence.nss.sources.group = ["files", "systemd"];
  assert.equal(validateStoppedRelay(reviewedSystemdFallback), true);

  const active = stoppedRelayFixture();
  active.evidence.stopped_unit_passes[1][0].active_state = "active";
  assert.throws(() => validateStoppedRelay(active), /not fully stopped/);

  const executable = stoppedRelayFixture();
  executable.request.units[0].exec_start = ["/usr/bin/true"];
  assert.throws(() => validateStoppedRelay(executable), /unit binding/);

  const preStart = stoppedRelayFixture();
  preStart.request.units[0].exec_start_pre = ["/usr/bin/true"];
  assert.throws(() => validateStoppedRelay(preStart), /unit binding/);

  const weakRequestProc = stoppedRelayFixture();
  weakRequestProc.request.units[0].hardening.ProtectProc = ["default"];
  assert.throws(
    () => validateStoppedRelay(weakRequestProc),
    /request hardening drift: ProtectProc/u,
  );

  const fullEffectiveProc = stoppedRelayFixture();
  fullEffectiveProc.evidence.unit_configuration_passes[1][0].properties.ProcSubset = "all";
  assert.throws(
    () => validateStoppedRelay(fullEffectiveProc),
    /effective ProcSubset drift/u,
  );

  const wrongConfigOwner = stoppedRelayFixture();
  wrongConfigOwner.request.installed_files[0].uid = 0;
  assert.throws(() => validateStoppedRelay(wrongConfigOwner), /unit binding/);

  const runtimeSocket = stoppedRelayFixture();
  runtimeSocket.request.runtime_paths = [{
    file_type: "socket",
    gid: 731,
    mode: "0660",
    target_path: "/run/bitcoinpir-directory-relay/relay.sock",
    uid: 730,
  }];
  assert.throws(() => validateStoppedRelay(runtimeSocket), /unit binding/);

  const installedTamper = stoppedRelayFixture();
  installedTamper.evidence.installed_file_passes[1][0].sha256 = hash("tampered-config");
  assert.throws(() => validateStoppedRelay(installedTamper), /installed-file sha256 drift/);

  const effectiveStart = stoppedRelayFixture();
  effectiveStart.evidence.unit_configuration_passes[1][0].properties.ExecStart =
    execValue("/usr/bin/true");
  assert.throws(() => validateStoppedRelay(effectiveStart), /effective ExecStart drift/);

  const forgedEffectiveStartPath = stoppedRelayFixture();
  forgedEffectiveStartPath.evidence.unit_configuration_passes[1][0]
    .properties.ExecStart = forgedEffectiveStartPath.evidence
      .unit_configuration_passes[1][0].properties.ExecStart.replace(
        /\{ path=[^ ]+/u,
        "{ path=/usr/bin/true",
      );
  assert.throws(
    () => validateStoppedRelay(forgedEffectiveStartPath),
    /path does not match argv\[0\]/,
  );

  const ignoredEffectiveFailure = stoppedRelayFixture();
  ignoredEffectiveFailure.evidence.unit_configuration_passes[1][0]
    .properties.ExecStart = ignoredEffectiveFailure.evidence
      .unit_configuration_passes[1][0].properties.ExecStart.replace(
        "ignore_errors=no",
        "ignore_errors=yes",
      );
  assert.throws(
    () => validateStoppedRelay(ignoredEffectiveFailure),
    /permits systemctl Exec ignore_errors/,
  );

  const resolvedSelection = stoppedRelayFixture();
  for (const pass of resolvedSelection.evidence.unit_configuration_passes) {
    const selection = pass[0].conditions.find((condition) =>
      condition.parameter.endsWith("/RELAY-SELECTION-RESOLVED"));
    selection.path_exists = true;
    selection.result = 1;
  }
  assert.throws(
    () => validateStoppedRelay(resolvedSelection),
    /selection activation sentinel is present/,
  );

  const untypedCondition = stoppedRelayFixture();
  untypedCondition.evidence.unit_configuration_passes[0][0].conditions[0].result =
    "-1";
  assert.throws(
    () => validateStoppedRelay(untypedCondition),
    /condition result is incoherent/,
  );

  const unreadableConfig = stoppedRelayFixture();
  unreadableConfig.evidence.secret_access_checks[0].exit_status = 1;
  assert.throws(
    () => validateStoppedRelay(unreadableConfig),
    /access isolation failed/,
  );

  const unsafeConfigParent = stoppedRelayFixture();
  unsafeConfigParent.evidence.secret_parent_directories.at(-1).uid = 0;
  assert.throws(
    () => validateStoppedRelay(unsafeConfigParent),
    /final parent must be consumer-owned mode 0700/,
  );

  const unreviewedSwapCurrent = stoppedRelayFixture();
  unreviewedSwapCurrent.evidence.unit_configuration_passes[0][0].properties.MemorySwapCurrent =
    "18446744073709551615";
  assert.throws(
    () => validateStoppedRelay(unreviewedSwapCurrent),
    /unreviewed MemorySwapCurrent/,
  );

  const foreignManager = stoppedRelayFixture();
  foreignManager.evidence.systemd_manager_passes[0].Version.value =
    "255.4-1ubuntu8.14";
  assert.throws(
    () => validateStoppedRelay(foreignManager),
    /Version must be typed s 255\.4-1ubuntu8\.15/u,
  );

  const legacyRelaySchema = stoppedRelayFixture();
  legacyRelaySchema.evidence.schema_version = 3;
  legacyRelaySchema.evidence.evidence_kind =
    "bitcoinpir-payment-v1-linux-root-stopped-directory-relay-v3";
  legacyRelaySchema.evidence.collector =
    "bitcoinpir-payment-v1-linux-runtime-evidence-v7";
  assert.throws(
    () => validateStoppedRelay(legacyRelaySchema),
    /schema, collector, profile/,
  );

  const legacyRelayRequest = stoppedRelayFixture();
  legacyRelayRequest.request.schema_version = 7;
  legacyRelayRequest.request.collector =
    "bitcoinpir-payment-v1-linux-runtime-evidence-v7";
  assert.throws(
    () => validateStoppedRelay(legacyRelayRequest),
    /schema, collector, profile/,
  );

  const extraCredentialRequestClosure = stoppedRelayFixture();
  extraCredentialRequestClosure.request.busctl_service_properties = [
    ...RUNTIME_BUSCTL_SERVICE_PROPERTIES,
    "PassCredential",
  ];
  assert.throws(
    () => validateStoppedRelay(extraCredentialRequestClosure),
    /busctl Service property schema/,
  );

  const live = fixture();
  live.request.deployment_profile = "directory-relay-v1";
  assert.throws(() => validate(live), /unresolved directory-relay-v1/);
});

test("resolved directory-relay has stopped preparation evidence before sentinels exist", () => {
  const value = resolvedStoppedRelayFixture();
  assert.equal(validateStoppedRelay(value), true);

  const unexpandedAddressAlias = resolvedStoppedRelayFixture();
  for (const pass of unexpandedAddressAlias.evidence.unit_configuration_passes) {
    pass[0].properties.IPAddressAllow = "localhost";
  }
  assert.throws(
    () => validateStoppedRelay(unexpandedAddressAlias),
    /effective IPAddressAllow drift/,
  );

  const missingManifest = resolvedStoppedRelayFixture();
  missingManifest.request.installed_files.shift();
  assert.throws(() => validateStoppedRelay(missingManifest), /unit binding/);

  const weakBinary = resolvedStoppedRelayFixture();
  weakBinary.request.installed_files.at(-1).mode = "0755";
  assert.throws(() => validateStoppedRelay(weakBinary), /unit binding/);

  const wrongPreflight = resolvedStoppedRelayFixture();
  wrongPreflight.request.units[0].exec_start_pre[0] =
    "/usr/bin/sha256sum --check /etc/bitcoinpir/payment-v1/directory-relay/binary.sha256";
  assert.throws(() => validateStoppedRelay(wrongPreflight), /unit binding/);
});

test("runtime evidence regular-file reads use no-follow one-link fd semantics", (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "bitcoinpir-runtime-read-")));
  t.after(() => rmSync(root, { force: true, recursive: true }));
  const path = join(root, "evidence.json");
  writeFileSync(path, "{}\n");
  assert.equal(readOneLinkRegular(path, "test evidence").toString("utf8"), "{}\n");

  const link = join(root, "link.json");
  symlinkSync(path, link);
  assert.throws(() => readOneLinkRegular(link, "linked evidence"), /one-link regular file/u);

  const hardlink = join(root, "hardlink.json");
  linkSync(path, hardlink);
  assert.throws(() => readOneLinkRegular(path, "hardlinked evidence"), /one-link regular file/u);
  unlinkSync(hardlink);
  assert.equal(readFileSync(path, "utf8"), "{}\n");
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
  const v8Evidence = fixture();
  v8Evidence.evidence.schema_version = 8;
  assert.throws(() => validate(v8Evidence), /schema or kind/);

  const v8EvidenceKind = fixture();
  v8EvidenceKind.evidence.evidence_kind =
    "bitcoinpir-payment-v1-linux-root-live-v8";
  assert.throws(() => validate(v8EvidenceKind), /schema or kind/);

  const v8Request = fixture();
  v8Request.request.schema_version = 8;
  assert.throws(() => validate(v8Request), /request schema or collector/);

  const v8RequestCollector = fixture();
  v8RequestCollector.request.collector =
    "bitcoinpir-payment-v1-linux-runtime-evidence-v8";
  assert.throws(() => validate(v8RequestCollector), /request schema or collector/);

  const legacyEvidence = fixture();
  legacyEvidence.evidence.schema_version = 7;
  legacyEvidence.evidence.evidence_kind =
    "bitcoinpir-payment-v1-linux-root-live-v7";
  legacyEvidence.evidence.collector =
    "bitcoinpir-payment-v1-linux-runtime-evidence-v7";
  assert.throws(() => validate(legacyEvidence), /schema or kind/);

  const legacyRequest = fixture();
  legacyRequest.request.schema_version = 7;
  legacyRequest.request.collector =
    "bitcoinpir-payment-v1-linux-runtime-evidence-v7";
  assert.throws(() => validate(legacyRequest), /request schema or collector/);

  const foreignSystemdRequest = fixture();
  foreignSystemdRequest.request.systemd_version = "systemd 255";
  assert.throws(() => validate(foreignSystemdRequest), /systemd_version/u);

  const foreignSystemdEvidence = fixture();
  foreignSystemdEvidence.evidence.host.systemd_version = "systemd 255";
  assert.throws(() => validate(foreignSystemdEvidence), /systemd build/u);

  const previousEvidenceSchema = fixture();
  previousEvidenceSchema.evidence.schema_version = 6;
  assert.throws(() => validate(previousEvidenceSchema), /schema or kind/);

  const previousRequestSchema = fixture();
  previousRequestSchema.request.schema_version = 6;
  assert.throws(() => validate(previousRequestSchema), /request schema or collector/);

  const legacySystemctlConditions = fixture();
  legacySystemctlConditions.request.systemctl_show_properties = [
    ...legacySystemctlConditions.request.systemctl_show_properties,
    "Conditions",
  ];
  assert.throws(() => validate(legacySystemctlConditions), /systemctl property schema/);

  const legacySystemctlCredentials = fixture();
  legacySystemctlCredentials.request.systemctl_show_properties = [
    ...legacySystemctlCredentials.request.systemctl_show_properties,
    "LoadCredential",
    "SetCredential",
  ].sort();
  assert.throws(() => validate(legacySystemctlCredentials), /systemctl property schema/);

  const missingBusctlSchema = fixture();
  delete missingBusctlSchema.request.busctl_unit_properties;
  assert.throws(() => validate(missingBusctlSchema), /busctl Unit property schema/);

  const foreignBusctlSchema = fixture();
  foreignBusctlSchema.request.busctl_unit_properties = ["Conditions", "Triggers"];
  assert.throws(() => validate(foreignBusctlSchema), /busctl Unit property schema/);

  const missingServiceBusctlSchema = fixture();
  delete missingServiceBusctlSchema.request.busctl_service_properties;
  assert.throws(() => validate(missingServiceBusctlSchema), /busctl Service property schema/);

  const incompleteServiceBusctlSchema = fixture();
  incompleteServiceBusctlSchema.request.busctl_service_properties = [
    "LoadCredential",
    "SetCredential",
  ];
  assert.throws(() => validate(incompleteServiceBusctlSchema), /busctl Service property schema/);

  const missingCredentialEvidence = fixture();
  delete missingCredentialEvidence.evidence.units[0]
    .credential_properties.LoadCredentialEncrypted;
  assert.throws(() => validate(missingCredentialEvidence), /credential properties.*keys/);

  const extraCredentialEvidence = fixture();
  extraCredentialEvidence.evidence.units[0].credential_properties.PassCredential = {
    data: [],
    type: "as",
  };
  assert.throws(() => validate(extraCredentialEvidence), /credential properties.*keys/);

  const wrongCredentialType = fixture();
  wrongCredentialType.evidence.units[0]
    .credential_properties.SetCredentialEncrypted.type = "a(ss)";
  assert.throws(() => validate(wrongCredentialType), /SetCredentialEncrypted is forbidden/);

  const reviewedSystemdFallback = fixture();
  reviewedSystemdFallback.evidence.nss.sources.passwd = ["files", "systemd"];
  reviewedSystemdFallback.evidence.nss.sources.group = ["files", "systemd"];
  assert.equal(validate(reviewedSystemdFallback), true);

  const legacyNssProfile = fixture();
  legacyNssProfile.evidence.nss.backend_profile = "local-files-only-v1";
  assert.throws(() => validate(legacyNssProfile), /files-authoritative backend/);

  const missingBusctlServiceSchema = fixture();
  delete missingBusctlServiceSchema.request.busctl_service_properties;
  assert.throws(() => validate(missingBusctlServiceSchema), /busctl Service property schema/);

  const foreignBusctlServiceSchema = fixture();
  foreignBusctlServiceSchema.request.busctl_service_properties = ["TimeoutStopUSec", "RestartUSec"];
  assert.throws(() => validate(foreignBusctlServiceSchema), /busctl Service property schema/);

  const missingBusctlManagerSchema = fixture();
  delete missingBusctlManagerSchema.request.busctl_manager_properties;
  assert.throws(() => validate(missingBusctlManagerSchema), /busctl Manager property schema/);

  const foreignBusctlManagerSchema = fixture();
  foreignBusctlManagerSchema.request.busctl_manager_properties = ["RuntimeWatchdogUSec"];
  assert.throws(() => validate(foreignBusctlManagerSchema), /busctl Manager property schema/);

  const remoteBackend = fixture();
  remoteBackend.evidence.nss.sources.passwd.push("sss");
  assert.throws(() => validate(remoteBackend), /files-only or files-then-systemd/);

  const mixedFallback = fixture();
  mixedFallback.evidence.nss.sources.passwd.push("systemd");
  assert.throws(() => validate(mixedFallback), /files-only or files-then-systemd/);

  const wrongFallbackOrder = fixture();
  wrongFallbackOrder.evidence.nss.sources.passwd = ["systemd", "files"];
  wrongFallbackOrder.evidence.nss.sources.group = ["systemd", "files"];
  assert.throws(() => validate(wrongFallbackOrder), /files-only or files-then-systemd/);

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

test("reviewed preflight lease requires a live notify process and exact watchdog", () => {
  assert.equal(validate(preflightLeaseFixture()), true);
  for (const [mutate, expected] of [
    [(value) => { value.evidence.units[0].properties.NotifyAccess = "none"; }, /NotifyAccess drift/],
    [(value) => { value.evidence.units[0].properties.WatchdogUSec = "0"; }, /watchdog lease drift/],
    [(value) => { value.evidence.units[0].unit_dependencies.After = ["basic.target"]; }, /effective After dependency drift/],
    [(value) => { value.evidence.units[0].unit_dependencies.Before = ["shutdown.target"]; }, /effective Before dependency drift/],
    [(value) => { value.evidence.units[0].unit_dependencies.BindsTo = []; }, /effective BindsTo dependency drift/],
    [(value) => { value.evidence.units[0].unit_dependencies.Requires = []; }, /effective Requires dependency drift/],
    [(value) => { value.evidence.units[0].unit_dependencies.BindsTo = ["bitcoinpir-core-lightning-lookalike.service"]; }, /effective BindsTo dependency drift/],
    [(value) => { value.evidence.units[0].service_property_passes[0].properties.TimeoutStopUSec = 0; }, /canonical uint64 decimal string/],
    [(value) => { value.evidence.units[0].service_property_passes[1].properties.TimeoutStopUSec = "31000000"; }, /TimeoutStopUSec drift|service policy changed/],
    [(value) => { value.evidence.units[0].service_property_passes[0].properties.ExecStartPreEx[0].flags = []; }, /ExecStartPreEx drift/],
    [(value) => { value.evidence.units[0].service_property_passes[0].properties.WatchdogUSec = "0"; }, /typed watchdog interval drift/],
    [(value) => { value.evidence.units[0].service_property_passes[0].properties.WatchdogTimestampMonotonic = "0"; }, /timestamp is not fresh/],
    [(value) => { value.evidence.units[0].service_property_passes[0].properties.WatchdogTimestampMonotonic = "5000001"; }, /timestamp is not fresh/],
    [(value) => { value.evidence.units[0].service_property_passes[1].properties.WatchdogTimestampMonotonic = "4499999"; }, /policy changed/],
    [(value) => { value.evidence.units[0].service_property_passes[0].observed_uptime_milliseconds = 4999; }, /pass uptime is invalid/],
    [(value) => { value.evidence.units[0].service_property_passes[1].observed_uptime_milliseconds = 4999; }, /pass uptime is invalid/],
    [(value) => { value.evidence.systemd_manager_passes[0].ServiceWatchdogs.value = false; }, /typed b true/],
    [(value) => { value.evidence.systemd_manager_passes[1].ServiceWatchdogs.signature = "u"; }, /typed b true/],
    [(value) => { value.evidence.systemd_manager_passes[0].Version.value = "255.4-1ubuntu8.14"; }, /Version must be typed s 255\.4-1ubuntu8\.15/],
    [(value) => { value.evidence.systemd_manager_passes[1].Version.signature = "as"; }, /Version must be typed s 255\.4-1ubuntu8\.15/],
    [(value) => { value.evidence.units[0].properties.SubState = "exited"; }, /no active MainPID/],
    [(value) => { value.evidence.units[0].properties.MainPID = "0"; }, /reviewed running ExecStart/],
    [(value) => { value.evidence.units[0].properties.ActiveEnterTimestampMonotonic = "6000000"; }, /not bound to this boot/],
    [(value) => { value.evidence.units[0].properties.InvocationID = "0".repeat(32); }, /InvocationID/],
  ]) {
    const value = preflightLeaseFixture();
    mutate(value);
    assert.throws(() => validate(value), expected);
  }

  const equalTimestamp = preflightLeaseFixture();
  equalTimestamp.evidence.units[0].service_property_passes[1]
    .properties.WatchdogTimestampMonotonic = equalTimestamp.evidence.units[0]
      .service_property_passes[0].properties.WatchdogTimestampMonotonic;
  assert.equal(validate(equalTimestamp), true);

  const refreshedAfterHostStart = preflightLeaseFixture();
  refreshedAfterHostStart.evidence.units[0].service_property_passes[0]
    .observed_uptime_milliseconds = 5006;
  refreshedAfterHostStart.evidence.units[0].service_property_passes[0]
    .properties.WatchdogTimestampMonotonic = "5005000";
  refreshedAfterHostStart.evidence.units[0].service_property_passes[1]
    .properties.WatchdogTimestampMonotonic = "5009000";
  assert.equal(validate(refreshedAfterHostStart), true);

  const staleAfterFalseToTrue = preflightLeaseFixture();
  staleAfterFalseToTrue.evidence.host.uptime_started_milliseconds = 100_000;
  staleAfterFalseToTrue.evidence.host.uptime_finished_milliseconds = 100_010;
  staleAfterFalseToTrue.evidence.units[0].service_property_passes[0]
    .observed_uptime_milliseconds = 100_000;
  staleAfterFalseToTrue.evidence.units[0].service_property_passes[1]
    .observed_uptime_milliseconds = 100_010;
  staleAfterFalseToTrue.evidence.units[0].service_property_passes[0]
    .properties.WatchdogTimestampMonotonic = "10000000";
  staleAfterFalseToTrue.evidence.units[0].service_property_passes[1]
    .properties.WatchdogTimestampMonotonic = "10000000";
  assert.throws(() => validate(staleAfterFalseToTrue), /timestamp is not fresh/);
});

test("secret evidence binds parent metadata and positive owner/negative cross-role access probes", () => {
  assert.equal(validate(secretIsolationFixture()), true);
  const readableByPeer = secretIsolationFixture();
  readableByPeer.evidence.secret_access_checks[1].exit_status = 0;
  assert.throws(() => validate(readableByPeer), /secret access isolation/);
  const missingParent = secretIsolationFixture();
  missingParent.evidence.secret_parent_directories.pop();
  assert.throws(() => validate(missingParent), /parent directory evidence is incomplete/);

  const rootOwnedFinalParent = secretIsolationFixture();
  rootOwnedFinalParent.evidence.secret_parent_directories.at(-1).uid = 0;
  assert.throws(
    () => validate(rootOwnedFinalParent),
    /final parent must be consumer-owned mode 0700/,
  );

  const traversableFinalParent = secretIsolationFixture();
  traversableFinalParent.evidence.secret_parent_directories.at(-1).mode = "0710";
  assert.throws(
    () => validate(traversableFinalParent),
    /final parent must be consumer-owned mode 0700/,
  );

  const writableAncestor = secretIsolationFixture();
  writableAncestor.evidence.secret_parent_directories.find(
    (entry) => entry.target_path === "/etc/bitcoinpir/payment-v1",
  ).mode = "0775";
  assert.throws(
    () => validate(writableAncestor),
    /ancestor violates the private-file loader policy/,
  );

  const foreignAncestor = secretIsolationFixture();
  foreignAncestor.evidence.secret_parent_directories.find(
    (entry) => entry.target_path === "/etc/bitcoinpir",
  ).uid = 999;
  assert.throws(
    () => validate(foreignAncestor),
    /ancestor violates the private-file loader policy/,
  );

  const mismatchedSecretOwner = secretIsolationFixture();
  mismatchedSecretOwner.request.secret_files[0].uid = 999;
  assert.throws(
    () => validate(mismatchedSecretOwner),
    /secret is not bound to its exact owner-only consumer/,
  );

  const rootOwnedStickyAncestor = secretIsolationFixture();
  rootOwnedStickyAncestor.evidence.secret_parent_directories.find(
    (entry) => entry.target_path === "/etc/bitcoinpir",
  ).mode = "1777";
  assert.equal(validate(rootOwnedStickyAncestor), true);

  for (const [label, mutate] of [
    ["negative device", (directory) => { directory.dev = "-1"; }],
    ["noncanonical inode", (directory) => { directory.ino = "0404"; }],
    ["fractional gid", (directory) => { directory.gid = 731.5; }],
    ["zero links", (directory) => { directory.nlink = 0; }],
    ["negative size", (directory) => { directory.size = -1; }],
  ]) {
    const malformed = secretIsolationFixture();
    mutate(malformed.evidence.secret_parent_directories.at(-1));
    assert.throws(
      () => validate(malformed),
      /secret parent directory metadata is malformed/,
      label,
    );
  }
});

for (const [label, mutate, expected] of [
  ["drop-in", (f) => { f.evidence.units[0].properties.DropInPaths = "/etc/systemd/system/x.d/evil.conf"; }, /drop-in/],
  ["foreign PID namespace", (f) => { f.evidence.host.collector_pid_namespace = "pid:[4026532557]"; }, /visible systemd PID namespace root/],
  ["non-systemd PID 1", (f) => { f.evidence.host.pid1_name = "sh"; }, /visible systemd PID namespace root/],
  ["ExecStart reset", (f) => {
    f.evidence.units[0].properties.ExecStart = execValue(
      "/usr/bin/true",
      { pid: "4242", state: "running" },
    );
  }, /ExecStart drift/],
  ["ExecStartPost", (f) => { f.evidence.units[0].properties.ExecStartPost = execValue("/usr/bin/true"); }, /ExecStartPost/],
  ["EnvironmentFile", (f) => { f.evidence.units[0].properties.EnvironmentFiles = "/tmp/evil"; }, /EnvironmentFiles/],
  ["credential", (f) => { f.evidence.units[0].credential_properties.LoadCredential.data = [["secret", "/tmp/evil"]]; }, /LoadCredential/],
  ["root image", (f) => { f.evidence.units[0].properties.RootImage = "/tmp/root.img"; }, /RootImage/],
  ["file hash", (f) => { f.evidence.installed_files[0].sha256 = hash("evil"); }, /sha256 drift/],
  ["tmpfiles mode", (f) => { f.evidence.runtime_directories[0].mode = "0777"; }, /tmpfiles directory drift/],
  ["tmpfiles UID", (f) => { f.evidence.runtime_directories[0].uid = 999; }, /tmpfiles directory NSS owner drift/],
  ["tmpfiles GID", (f) => { f.evidence.runtime_directories[0].gid = 999; }, /tmpfiles directory NSS owner drift/],
  ["tmpfiles evidence type", (f) => { f.evidence.runtime_directories[0].expected_type = "socket"; }, /tmpfiles directory drift/],
  ["runtime socket mode", (f) => { f.evidence.runtime_paths[0].mode = "0666"; }, /runtime path mode drift/],
  ["unexpected issuer group", (f) => { f.evidence.nss.users[0].supplementary_gids.push(999); }, /unexpected supplementary group|reverse group membership/],
  ["inactive unit", (f) => { f.evidence.units[0].properties.ActiveState = "inactive"; }, /unexecuted stopped command/],
  ["missing effective condition", (f) => { f.evidence.units[0].conditions = []; }, /effective condition drift/],
  ["extra effective condition", (f) => { f.evidence.units[0].conditions.push({
    negate: true,
    parameter: "/etc/bitcoinpir/payment-v1/FOREIGN-ACTIVATION-APPROVED",
    path_exists: false,
    result: 1,
    trigger: false,
    type: "ConditionPathExists",
  }); }, /effective condition drift/],
  ["condition negation drift", (f) => { f.evidence.units[0].conditions[0].negate = true; }, /effective condition drift/],
  ["condition path drift", (f) => { f.evidence.units[0].conditions[0].parameter = "/etc/bitcoinpir/payment-v1/FOREIGN-ACTIVATION-APPROVED"; }, /effective condition drift/],
  ["condition path truth drift", (f) => { f.evidence.units[0].conditions[0].path_exists = false; }, /effective condition drift/],
  ["condition result not passed", (f) => { f.evidence.units[0].conditions[0].result = 0; }, /effective condition drift/],
  ["trigger condition drift", (f) => { f.evidence.units[0].conditions[0].trigger = true; }, /effective condition drift/],
  ["ControlGroup drift", (f) => { f.evidence.units[0].properties.ControlGroup = "/system.slice/evil.service"; }, /reviewed system\.slice control group/],
  ["zero MainPID", (f) => { f.evidence.units[0].properties.MainPID = "0"; }, /reviewed running ExecStart/],
  ["effective Restart drift", (f) => { f.evidence.units[0].properties.Restart = "on-failure"; }, /Restart drift/],
  ["effective LimitCORE drift", (f) => { f.evidence.units[0].properties.LimitCORE = "infinity"; }, /LimitCORE drift/],
  ["effective LimitCORESoft drift", (f) => { f.evidence.units[0].properties.LimitCORESoft = "infinity"; }, /LimitCORESoft drift/],
  ["effective LimitNOFILE drift", (f) => { f.evidence.units[0].properties.LimitNOFILE = "infinity"; }, /LimitNOFILE drift/],
  ["effective LimitNOFILESoft drift", (f) => { f.evidence.units[0].properties.LimitNOFILESoft = "1024"; }, /LimitNOFILESoft drift/],
  ["effective MemoryMax drift", (f) => { f.evidence.units[0].properties.MemoryMax = "infinity"; }, /MemoryMax drift/],
  ["effective MemorySwapCurrent drift", (f) => { f.evidence.units[0].properties.MemorySwapCurrent = "1"; }, /MemorySwapCurrent drift/],
  ["effective MemorySwapMax drift", (f) => { f.evidence.units[0].properties.MemorySwapMax = "infinity"; }, /MemorySwapMax drift/],
  ["effective NeedDaemonReload drift", (f) => { f.evidence.units[0].properties.NeedDaemonReload = "yes"; }, /NeedDaemonReload drift/],
  ["effective TasksMax drift", (f) => { f.evidence.units[0].properties.TasksMax = "infinity"; }, /TasksMax drift/],
  ["missing TemporaryFileSystem evidence", (f) => { delete f.evidence.units[0].properties.TemporaryFileSystem; }, /keys/u],
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
  ["command device omission", (f) => { delete f.evidence.trusted_commands[0].dev; }, /command keys/u],
  ["command malformed GID", (f) => { f.evidence.trusted_commands[0].gid = "0"; }, /untrusted runtime command/u],
  ["command zero inode", (f) => { f.evidence.trusted_commands[0].ino = "0"; }, /untrusted runtime command/u],
  ["command non-executable mode", (f) => { f.evidence.trusted_commands[0].mode = "0644"; }, /untrusted runtime command/u],
]) {
  test(`live verifier rejects ${label}`, () => {
    const value = fixture();
    mutate(value);
    assert.throws(() => validate(value), expected);
  });
}

test("edge live evidence validates without a host core-policy prerequisite", () => {
  const value = fixture();
  value.request.deployment_profile = "edge-hetzner-v1";
  assert.doesNotThrow(() => validate(value));
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
  const stoppedRelayCallerJson = spawnSync(process.execPath, [COLLECTOR, "collect-stopped-relay", ...base, "--output", "/tmp/output", "--evidence", "/tmp/forged.json"], { encoding: "utf8" });
  assert.notEqual(stoppedRelayCallerJson.status, 0);
  assert.match(stoppedRelayCallerJson.stderr, /collect-stopped-relay forbids caller evidence/);
  const stoppedOffline = spawnSync(process.execPath, [COLLECTOR, "verify-stopped-edge-offline", ...base, "--evidence", "/tmp/forged.json", "--expected-boot-id", "12345678-1234-4abc-8def-123456789abc"], { encoding: "utf8" });
  assert.notEqual(stoppedOffline.status, 0);
  assert.match(stoppedOffline.stderr, /trusted-evidence-sha256/);
  const stoppedRelayOffline = spawnSync(process.execPath, [COLLECTOR, "verify-stopped-relay-offline", ...base, "--evidence", "/tmp/forged.json", "--expected-boot-id", "12345678-1234-4abc-8def-123456789abc"], { encoding: "utf8" });
  assert.notEqual(stoppedRelayOffline.status, 0);
  assert.match(stoppedRelayOffline.stderr, /trusted-evidence-sha256/);
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
