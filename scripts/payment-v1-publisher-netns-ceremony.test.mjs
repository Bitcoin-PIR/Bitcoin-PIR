import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { canonicalJson } from "./payment-v1-integrated-caddy-overlay-gate.mjs";
import {
  APPLY_ACKNOWLEDGEMENTS,
  APPLY_APPROVAL_KIND,
  CEREMONY_KIND,
  FAILED_RECOVERY_ACKNOWLEDGEMENTS,
  FAILED_RECOVERY_APPROVAL_KIND,
  PUBLISHER_NETNS_CEREMONY_TEST_ONLY_IO as realFs,
  ROLLBACK_ACKNOWLEDGEMENTS,
  ROLLBACK_APPROVAL_KIND,
  assertPublisherRecoveryOwnsLifecycleLock,
  computePlanSha256,
  executeApply,
  executeRollback,
  formatPublisherNetnsCeremonyOutcomeV2,
  formatPublisherNetnsPlanValidationV2,
  parseSystemdExecRecordsV1,
  validateCeremonyPlan,
  validatePrivatePairV1,
  writeAllSyncV1,
} from "./payment-v1-publisher-netns-ceremony.mjs";
import {
  computePublisherNetnsFailedUnitSha256V1,
  inspectDynamicElfV1,
  inspectStaticElfV1,
  validatePublisherNetnsFailedRecoveryReceiptV1,
  validatePublisherNetnsFailedUnitV1,
  validatePublisherNetnsPlanV2,
  validatePublisherNodeElfClosureBytesV1,
} from "./payment-v1-publisher-netns-schema.mjs";

const NETNS_UNIT = "bitcoinpir-payment-v1-publisher-netns.service";
const PUBLISHER_UNIT = "bitcoinpir-payment-v1-directory-publisher.service";
const CADDY_UNIT = "bhtm-caddy.service";
const NOW = 1_788_000_000;
const CEREMONY_MODULE_URL = new URL(
  "./payment-v1-publisher-netns-ceremony.mjs",
  import.meta.url,
).href;

test("schema-v2 CLI status lines are explicit and machine-parseable", () => {
  assert.equal(
    formatPublisherNetnsPlanValidationV2("a".repeat(64)),
    `valid schema_version=2 plan_sha256=${"a".repeat(64)}\n`,
  );
  assert.equal(
    formatPublisherNetnsCeremonyOutcomeV2("committed", "/receipt.json"),
    "committed schema_version=2 receipt=/receipt.json\n",
  );
});

test("publisher recovery cannot clear another lifecycle transaction's stale lock", () => {
  const owner = {
    boot_id: "22345678-1234-4234-9234-123456789abc",
    pid: 999999,
    process_start_ticks: "1",
    transaction_id: "bhtm-caddy-admin-uds:admin-maintenance",
  };
  assert.throws(
    () => assertPublisherRecoveryOwnsLifecycleLock(owner, "publisher-activation"),
    /different transaction/u,
  );
  owner.transaction_id = "publisher-activation";
  assert.equal(
    assertPublisherRecoveryOwnsLifecycleLock(owner, "publisher-activation"),
    true,
  );
});

test("publisher recovery rejects malformed stale-lock process identities", () => {
  const valid = {
    boot_id: "22345678-1234-4234-9234-123456789abc",
    pid: 999999,
    process_start_ticks: "1",
    transaction_id: "publisher-activation",
  };
  for (const [field, value, expected] of [
    ["boot_id", "22345678123442349234123456789abc", /canonical nonzero UUID/u],
    ["boot_id", "00000000-0000-0000-0000-000000000000", /canonical nonzero UUID/u],
    ["pid", 0, /positive safe integer/u],
    ["pid", -1, /positive safe integer/u],
    ["pid", 1.5, /positive safe integer/u],
    ["pid", Number.MAX_SAFE_INTEGER + 1, /positive safe integer/u],
    ["pid", "1", /positive safe integer/u],
    ["process_start_ticks", "0", /canonical positive decimal/u],
    ["process_start_ticks", "01", /canonical positive decimal/u],
    ["process_start_ticks", 1, /canonical positive decimal/u],
  ]) {
    const owner = structuredClone(valid);
    owner[field] = value;
    assert.throws(
      () => assertPublisherRecoveryOwnsLifecycleLock(owner, valid.transaction_id),
      expected,
    );
  }
});

test("atomic record writes loop over short writes and reject non-progress", () => {
  const bytes = Buffer.from("short-write-proof", "utf8");
  const observed = Buffer.alloc(bytes.length);
  const calls = [];
  const written = writeAllSyncV1(17, bytes, (fd, buffer, offset, length, position) => {
    assert.equal(fd, 17);
    assert.equal(position, offset);
    const count = Math.min(3, length);
    buffer.copy(observed, position, offset, offset + count);
    calls.push({ count, length, offset, position });
    return count;
  });
  assert.equal(written, bytes.length);
  assert.equal(observed.equals(bytes), true);
  assert.equal(calls.length > 1, true);
  for (const invalid of [0, -1, 1.5, bytes.length + 1]) {
    assert.throws(
      () => writeAllSyncV1(17, bytes, () => invalid),
      /invalid short-write length/u,
    );
  }
});

function hash(value) {
  return createHash("sha256").update(value).digest("hex");
}

function pin(path, mode, label = path) {
  const bytes = Buffer.from(`${label}\n`, "utf8");
  return {
    ctime_ns: "100",
    device: "7",
    gid: 0,
    inode: String(1000 + Math.abs([...path].reduce((sum, char) => sum + char.charCodeAt(0), 0))),
    mode,
    mtime_ns: "90",
    nlink: 1,
    path,
    sha256: hash(bytes),
    size: String(bytes.length),
    uid: 0,
  };
}

function installedManifestBytes(installedFiles, ids) {
  return Buffer.from(ids.map((id) =>
    installedFiles.find((entry) => entry.id === id).pin)
  .sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0)
  .map((pinValue) => `${pinValue.sha256}  ${pinValue.path}\n`)
  .join(""), "utf8");
}

function launcherManifestBytes(runtime) {
  return Buffer.from([
    runtime.node,
    runtime.integrated_caddy_gate,
    runtime.executor,
    runtime.publisher_netns_gate,
    runtime.schema_validator,
    runtime.health_probe,
    runtime.node_loader_closure_manifest,
  ].map((pinValue) => `${pinValue.sha256}  ${pinValue.path}\n`).join(""), "utf8");
}

function nodeElfClosureFixture() {
  const closure = {
    activation_state:
      "descriptor-pinned-loader-recursive-needed-closure-and-double-maps-sampling",
    architecture: "elf64-le-x86_64",
    interpreter_soname: "ld-linux-x86-64.so.2",
    kind: "bitcoinpir-payment-v1-publisher-node-elf-closure-v1",
    node_needed: ["libc.so.6", "libm.so.6"],
    objects: [
      {
        needed: [],
        pin: pin(
          "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "0755", "ld-linux",
        ),
        soname: "ld-linux-x86-64.so.2",
      },
      {
        needed: ["ld-linux-x86-64.so.2"],
        pin: pin("/usr/lib/x86_64-linux-gnu/libc.so.6", "0755", "libc"),
        soname: "libc.so.6",
      },
      {
        needed: ["libc.so.6"],
        pin: pin("/usr/lib/x86_64-linux-gnu/libm.so.6", "0755", "libm"),
        soname: "libm.so.6",
      },
    ],
    pt_interp: "/lib64/ld-linux-x86-64.so.2",
    schema_version: 1,
  };
  for (const object of closure.objects) {
    const bytes = dynamicElfFixture({ needed: object.needed, soname: object.soname });
    object.pin.sha256 = hash(bytes);
    object.pin.size = String(bytes.length);
  }
  return closure;
}

function nodeLoaderClosureManifestBytes(closure) {
  return Buffer.from(closure.objects.map((object) =>
    `${object.pin.sha256}  ${object.pin.path}\n`).join(""), "utf8");
}

function staticElfFixture() {
  const bytes = Buffer.alloc(64 + 56);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  bytes.writeUInt16LE(2, 16);
  bytes.writeUInt16LE(62, 18);
  bytes.writeUInt32LE(1, 20);
  bytes.writeBigUInt64LE(64n, 32);
  bytes.writeUInt16LE(64, 52);
  bytes.writeUInt16LE(56, 54);
  bytes.writeUInt16LE(1, 56);
  bytes.writeUInt32LE(1, 64);
  return bytes;
}

function dynamicElfFixture({
  extraDynamicTags = [], interpreter = null, needed = [], soname = null,
} = {}) {
  const bytes = Buffer.alloc(4096);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  bytes.writeUInt16LE(3, 16);
  bytes.writeUInt16LE(62, 18);
  bytes.writeUInt32LE(1, 20);
  bytes.writeBigUInt64LE(64n, 32);
  bytes.writeUInt16LE(64, 52);
  bytes.writeUInt16LE(56, 54);
  const programHeaderCount = interpreter === null ? 2 : 3;
  bytes.writeUInt16LE(programHeaderCount, 56);
  const base = 0x400000n;
  const dynamicOffset = 512;
  const stringTableOffset = 1024;
  const strings = ["", ...needed, ...(soname === null ? [] : [soname])];
  const stringOffsets = new Map();
  let stringCursor = 0;
  for (const value of strings) {
    if (!stringOffsets.has(value)) stringOffsets.set(value, stringCursor);
    bytes.write(`${value}\0`, stringTableOffset + stringCursor, "ascii");
    stringCursor += Buffer.byteLength(value, "ascii") + 1;
  }
  const dynamicEntries = [
    ...needed.map((name) => [1n, BigInt(stringOffsets.get(name))]),
    [5n, base + BigInt(stringTableOffset)],
    [10n, BigInt(stringCursor)],
    ...(soname === null ? [] : [[14n, BigInt(stringOffsets.get(soname))]]),
    ...extraDynamicTags.map((tag) => [BigInt(tag), 0n]),
    [0n, 0n],
  ];
  for (const [index, [tag, value]] of dynamicEntries.entries()) {
    bytes.writeBigInt64LE(tag, dynamicOffset + index * 16);
    bytes.writeBigUInt64LE(value, dynamicOffset + index * 16 + 8);
  }
  const writeProgramHeader = (index, type, fileOffset, fileSize) => {
    const offset = 64 + index * 56;
    bytes.writeUInt32LE(type, offset);
    bytes.writeUInt32LE(type === 1 ? 5 : 4, offset + 4);
    bytes.writeBigUInt64LE(BigInt(fileOffset), offset + 8);
    bytes.writeBigUInt64LE(base + BigInt(fileOffset), offset + 16);
    bytes.writeBigUInt64LE(base + BigInt(fileOffset), offset + 24);
    bytes.writeBigUInt64LE(BigInt(fileSize), offset + 32);
    bytes.writeBigUInt64LE(BigInt(fileSize), offset + 40);
    bytes.writeBigUInt64LE(type === 1 ? 4096n : 8n, offset + 48);
  };
  writeProgramHeader(0, 1, 0, bytes.length);
  writeProgramHeader(1, 2, dynamicOffset, dynamicEntries.length * 16);
  if (interpreter !== null) {
    const interpreterOffset = 384;
    bytes.write(`${interpreter}\0`, interpreterOffset, "ascii");
    writeProgramHeader(2, 3, interpreterOffset, Buffer.byteLength(interpreter, "ascii") + 1);
  }
  return bytes;
}

function nodeElfFixtureBytes(closure) {
  return dynamicElfFixture({
    interpreter: closure.pt_interp,
    needed: closure.node_needed,
  });
}

function objectElfFixtureBytes(object) {
  return dynamicElfFixture({ needed: object.needed, soname: object.soname });
}

function installedFileBytes(id, topology, installedFiles = undefined) {
  if (id === "helper-binary") return Buffer.from("helper\n", "utf8");
  if (id === "caddy-netns-dropin") {
    return readFileSync(new URL(
      "../deploy/payment-v1/systemd/bhtm-caddy.publisher-netns.conf.in",
      import.meta.url,
    ));
  }
  if (id === "publisher-netns-unit") {
    return Buffer.from(readFileSync(new URL(
      "../deploy/payment-v1/systemd/payment-v1-publisher-netns.service.in",
      import.meta.url,
    ), "utf8").replaceAll("@PUBLISHER_NETNS_HELPER_SHA256@", hash("helper\n")), "utf8");
  }
  if (id === "network-policy") {
    return Buffer.from(readFileSync(new URL(
      "../deploy/payment-v1/network/directory-publisher-network-policy.json.in",
      import.meta.url,
    ), "utf8").replaceAll("@DIRECTORY_PUBLISHER_HTTPS_HOST@", topology.publisher_hostname), "utf8");
  }
  if (id === "netns-hosts") {
    return Buffer.from(
      `127.0.0.1 localhost\n${topology.host_address} ${topology.publisher_hostname}\n`,
      "utf8",
    );
  }
  if (id === "netns-resolv") {
    return Buffer.from("nameserver 127.0.0.1\noptions attempts:1 timeout:1\n", "utf8");
  }
  if (id === "netns-nsswitch") {
    return Buffer.from("passwd: files\ngroup: files\nhosts: files\nnetworks: files\n", "utf8");
  }
  if (id === "helper-manifest" && installedFiles !== undefined) {
    return installedManifestBytes(installedFiles, ["helper-binary"]);
  }
  if (id === "network-inputs-manifest" && installedFiles !== undefined) {
    return installedManifestBytes(installedFiles, [
      "netns-hosts", "netns-nsswitch", "netns-resolv", "network-policy",
    ]);
  }
  return Buffer.from(`${id}\n`, "utf8");
}

function inactive(name) {
  return {
    active_enter_timestamp_monotonic: "0",
    active_state: "inactive",
    invocation_id: "0".repeat(32),
    load_state: "loaded",
    main_pid: "0",
    name,
    need_daemon_reload: "no",
    sub_state: "dead",
  };
}

function active(name, id = "a".repeat(32), pid = "123") {
  return {
    active_enter_timestamp_monotonic: "123456",
    active_state: "active",
    invocation_id: id,
    load_state: "loaded",
    main_pid: pid,
    name,
    need_daemon_reload: "no",
    sub_state: "running",
  };
}

function failed(name, id = "d".repeat(32)) {
  return {
    active_enter_timestamp_monotonic: "0",
    active_state: "failed",
    exec_main_code: "2",
    exec_main_status: "15",
    inactive_enter_timestamp_monotonic: "123457",
    invocation_id: id,
    load_state: "loaded",
    main_pid: "0",
    name,
    need_daemon_reload: "no",
    result: "timeout",
    state_change_timestamp_monotonic: "123457",
    sub_state: "failed",
  };
}

function failedProjection(value) {
  return {
    active_enter_timestamp_monotonic: value.active_enter_timestamp_monotonic,
    active_state: value.active_state,
    invocation_id: value.invocation_id,
    load_state: value.load_state,
    main_pid: value.main_pid,
    name: value.name,
    need_daemon_reload: value.need_daemon_reload,
    sub_state: value.sub_state,
  };
}

function loadedNetnsUnit(installedFiles) {
  const helper = installedFiles.find((entry) => entry.id === "helper-binary").pin.path;
  return {
    condition_paths: [
      "/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
      "/etc/bitcoinpir/payment-v1/EDGE-ACTIVATION-APPROVED",
      "/etc/bitcoinpir/payment-v1/SOURCE-FAIR-PREFLIGHT-APPROVED",
      "/etc/bitcoinpir/payment-v1/DIRECTORY-PUBLISHER-PRIVATE-INGRESS-APPROVED",
      "/etc/bitcoinpir/payment-v1/PUBLISHER-NETNS-ACTIVATION-APPROVED",
    ],
    condition_source: "exact-fragment-pin-plus-NeedDaemonReload=no",
    dropin_paths: [],
    exec: {
      start: [{ argv: `${helper} run`, ignore_errors: "no", path: helper }],
      start_pre: [
        { argv: `/usr/bin/test -x ${helper}`, ignore_errors: "no", path: "/usr/bin/test" },
        {
          argv: "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/publisher-netns/helper.sha256",
          ignore_errors: "no",
          path: "/usr/bin/sha256sum",
        },
        { argv: `${helper} self-test`, ignore_errors: "no", path: helper },
      ],
      stop_post: [{ argv: `${helper} cleanup`, ignore_errors: "no", path: helper }],
    },
    fragment_path: "/etc/systemd/system/bitcoinpir-payment-v1-publisher-netns.service",
    need_daemon_reload: "no",
    relationships: {
      after: ["basic.target", "local-fs.target"],
      before: ["bhtm-caddy.service", "bitcoinpir-payment-v1-source-fair-edge.service"],
      binds_to: [],
      part_of: ["bhtm-caddy.service"],
      requires: [],
      wants: [],
    },
    service: {
      ambient_capabilities: [],
      capability_bounding_set: ["CAP_NET_ADMIN", "CAP_SYS_ADMIN"],
      group: "root",
      kill_mode: "control-group",
      limit_core: "0",
      lock_personality: "yes",
      memory_deny_write_execute: "yes",
      memory_max: "67108864",
      memory_swap_max: "0",
      no_new_privileges: "yes",
      notify_access: "main",
      restart: "no",
      restrict_address_families: ["AF_NETLINK", "AF_UNIX"],
      restrict_namespaces: "net",
      restrict_realtime: "yes",
      restrict_suid_sgid: "yes",
      standard_error: "null",
      standard_output: "null",
      state_directory: ["bitcoinpir-publisher-netns"],
      state_directory_mode: "0700",
      system_call_architectures: ["native"],
      tasks_max: "8",
      timeout_start_usec: "30s",
      timeout_stop_usec: "30s",
      type: "notify",
      umask: "0077",
      unset_environment: [
        "BASH_ENV", "ENV", "GLIBC_TUNABLES", "LD_AUDIT", "LD_LIBRARY_PATH",
        "LD_PRELOAD", "NODE_EXTRA_CA_CERTS", "NODE_OPTIONS", "NODE_PATH",
      ],
      user: "root",
      working_directory: "/var/lib/bitcoinpir-publisher-netns",
    },
  };
}

function nftChain(family, name, rules = []) {
  return `table ${family} filter {\n  chain ${name} {\n${rules.map((rule) =>
    `    ${rule}`).join("\n")}${rules.length === 0 ? "" : "\n"}  }\n}\n`;
}

function baseChain(family, hook) {
  const prefix = family === "ip" ? "ufw" : "ufw6";
  const suffix = hook.toLowerCase();
  return nftChain(family, hook, [
    `type filter hook ${suffix} priority filter; policy drop;`,
    `jump ${prefix}-before-logging-${suffix}`,
    `jump ${prefix}-before-${suffix}`,
    `jump ${prefix}-after-${suffix}`,
    `jump ${prefix}-after-logging-${suffix}`,
    `jump ${prefix}-reject-${suffix}`,
    `jump ${prefix}-track-${suffix}`,
  ]);
}

function firewallOutputs() {
  return {
    nft_ip6_base_forward: baseChain("ip6", "FORWARD"),
    nft_ip6_base_input: baseChain("ip6", "INPUT"),
    nft_ip6_before_forward: nftChain("ip6", "ufw6-before-forward", [
      "ct state related,established counter packets 0 bytes 0 accept",
      "jump ufw6-user-forward",
    ]),
    nft_ip6_before_input: nftChain("ip6", "ufw6-before-input", [
      'iifname "lo" counter packets 0 bytes 0 accept',
      "ct state related,established counter packets 0 bytes 0 accept",
      "jump ufw6-user-input",
    ]),
    nft_ip6_before_logging_forward: nftChain("ip6", "ufw6-before-logging-forward"),
    nft_ip6_before_logging_input: nftChain("ip6", "ufw6-before-logging-input"),
    nft_ip6_forward: nftChain("ip6", "ufw6-user-forward", [
      'oifname "bpir-pub-h" counter packets 0 bytes 0 drop',
      'iifname "bpir-pub-h" counter packets 0 bytes 0 drop',
    ]),
    nft_ip6_input: nftChain("ip6", "ufw6-user-input", [
      'iifname "bpir-pub-h" counter packets 0 bytes 0 drop',
    ]),
    nft_ip6_logging_deny: nftChain("ip6", "ufw6-logging-deny"),
    nft_ip_base_forward: baseChain("ip", "FORWARD"),
    nft_ip_base_input: baseChain("ip", "INPUT"),
    nft_ip_before_forward: nftChain("ip", "ufw-before-forward", [
      "ct state related,established counter packets 0 bytes 0 accept",
      "jump ufw-user-forward",
    ]),
    nft_ip_before_input: nftChain("ip", "ufw-before-input", [
      'iifname "lo" counter packets 0 bytes 0 accept',
      "ct state related,established counter packets 0 bytes 0 accept",
      "jump ufw-not-local",
      "jump ufw-user-input",
    ]),
    nft_ip_before_logging_forward: nftChain("ip", "ufw-before-logging-forward"),
    nft_ip_before_logging_input: nftChain("ip", "ufw-before-logging-input"),
    nft_ip_forward: nftChain("ip", "ufw-user-forward", [
      'oifname "bpir-pub-h" counter packets 0 bytes 0 drop',
      'iifname "bpir-pub-h" counter packets 0 bytes 0 drop',
    ]),
    nft_ip_input: nftChain("ip", "ufw-user-input", [
      'ip saddr 10.203.0.2 ip daddr 10.203.0.1 iifname "bpir-pub-h" tcp dport 443 counter packets 0 bytes 0 accept',
      'iifname "bpir-pub-h" counter packets 0 bytes 0 drop',
    ]),
    nft_ip_logging_deny: nftChain("ip", "ufw-logging-deny"),
    nft_ip_not_local: nftChain("ip", "ufw-not-local", [
      "fib daddr type local counter packets 0 bytes 0 return",
      "fib daddr type multicast counter packets 0 bytes 0 return",
      "fib daddr type broadcast counter packets 0 bytes 0 return",
      "limit rate 3/minute burst 10 packets counter packets 0 bytes 0 jump ufw-logging-deny",
      "counter packets 0 bytes 0 drop",
    ]),
    ufw_raw: `IPV4 (raw):
0 0 ACCEPT 6 -- bpir-pub-h * 10.203.0.2 10.203.0.1 tcp dpt:443
0 0 DROP 0 -- bpir-pub-h * 0.0.0.0/0 0.0.0.0/0
0 0 DROP 0 -- bpir-pub-h * 0.0.0.0/0 0.0.0.0/0
0 0 DROP 0 -- * bpir-pub-h 0.0.0.0/0 0.0.0.0/0
IPV6 (raw):
0 0 DROP 0 -- bpir-pub-h * ::/0 ::/0
0 0 DROP 0 -- bpir-pub-h * ::/0 ::/0
0 0 DROP 0 -- * bpir-pub-h ::/0 ::/0
`,
    ufw_status: `Status: active
[ 1] 10.203.0.1 443/tcp on bpir-pub-h ALLOW IN 10.203.0.2
[ 2] Anywhere on bpir-pub-h DENY IN Anywhere
[ 3] Anywhere DENY FWD Anywhere on bpir-pub-h
[ 4] Anywhere on bpir-pub-h DENY FWD Anywhere (out)
[ 5] Anywhere (v6) on bpir-pub-h DENY IN Anywhere (v6)
[ 6] Anywhere (v6) DENY FWD Anywhere (v6) on bpir-pub-h
[ 7] Anywhere (v6) on bpir-pub-h DENY FWD Anywhere (v6) (out)
`,
  };
}

function fixture() {
  const helperHash = hash("helper\n");
  const topology = {
    address_family: "ipv4",
    client_address: "10.203.0.2",
    client_interface: "bpir-pub-c",
    default_route: false,
    forwarding: false,
    host_address: "10.203.0.1",
    host_interface: "bpir-pub-h",
    host_port: 443,
    hosts_path: "/etc/netns/bpir-directory-publisher/hosts",
    namespace_name: "bpir-directory-publisher",
    namespace_path: "/run/netns/bpir-directory-publisher",
    nat: false,
    prefix_length: 30,
    publisher_hostname: "publisher.example.net",
  };
  const paths = [
    ["caddy-netns-dropin",
      "/etc/systemd/system/bhtm-caddy.service.d/bitcoinpir-publisher-netns.conf", "0644"],
    ["directory-publisher-unit",
      "/etc/systemd/system/bitcoinpir-payment-v1-directory-publisher.service", "0644"],
    ["helper-binary",
      `/opt/bitcoinpir/publisher-netns/${helperHash}/payment-v1-publisher-netns`, "0555"],
    ["helper-manifest", "/etc/bitcoinpir/payment-v1/publisher-netns/helper.sha256", "0444"],
    ["netns-hosts", topology.hosts_path, "0444"],
    ["netns-nsswitch", "/etc/netns/bpir-directory-publisher/nsswitch.conf", "0444"],
    ["netns-resolv", "/etc/netns/bpir-directory-publisher/resolv.conf", "0444"],
    ["network-inputs-manifest",
      "/etc/bitcoinpir/payment-v1/directory-publisher/network-inputs.sha256", "0444"],
    ["network-policy",
      "/etc/bitcoinpir/payment-v1/directory-publisher/network-policy.json", "0444"],
    ["publisher-netns-unit",
      "/etc/systemd/system/bitcoinpir-payment-v1-publisher-netns.service", "0644"],
  ];
  const installedFiles = paths.map(([id, path, mode]) => {
    const filePin = pin(path, mode, id === "helper-binary" ? "helper" : id);
    const bytes = installedFileBytes(id, topology);
    filePin.sha256 = hash(bytes);
    filePin.size = String(bytes.length);
    return { id, pin: filePin };
  });
  for (const id of ["helper-manifest", "network-inputs-manifest"]) {
    const entry = installedFiles.find((candidate) => candidate.id === id);
    const bytes = installedFileBytes(id, topology, installedFiles);
    entry.pin.sha256 = hash(bytes);
    entry.pin.size = String(bytes.length);
  }
  const sentinelPaths = [
    "/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
    "/etc/bitcoinpir/payment-v1/EDGE-ACTIVATION-APPROVED",
    "/etc/bitcoinpir/payment-v1/SOURCE-FAIR-PREFLIGHT-APPROVED",
    "/etc/bitcoinpir/payment-v1/DIRECTORY-PUBLISHER-PRIVATE-INGRESS-APPROVED",
    "/etc/bitcoinpir/payment-v1/PUBLISHER-NETNS-ACTIVATION-APPROVED",
  ];
  const firewallBytes = Buffer.from(canonicalJson(firewallOutputs()), "utf8");
  const firewallPin = pin(
    "/var/lib/bitcoinpir/payment-v1/publisher-netns/evidence/firewall.json", "0400", "firewall");
  firewallPin.sha256 = hash(firewallBytes);
  firewallPin.size = String(firewallBytes.length);
  const caddy = {
    config: pin("/etc/caddy/Caddyfile", "0644", "caddy-preimage"),
    dependency: {
      after_namespace_owner: true,
      binds_to_namespace_owner: false,
      drop_in_paths: [
        "/etc/systemd/system/bhtm-caddy.service.d/bitcoinpir-publisher-netns.conf",
      ],
      part_of_namespace_owner: false,
      requires_namespace_owner: false,
      wants_namespace_owner: true,
    },
    unit: active(CADDY_UNIT, "c".repeat(32), "900"),
  };
  const ceremonyId = "publisher-netns-20260730-a";
  const launcherBytes = staticElfFixture();
  const launcherSha256 = hash(launcherBytes);
  const runtime = {
    executor: pin(
      "/usr/local/libexec/bitcoinpir/payment-v1-publisher-netns-ceremony.mjs", "0555",
      "executor"),
    health_probe: pin(
      "/usr/local/libexec/bitcoinpir/payment-v1-publisher-private-health-probe.mjs",
      "0555",
      "publisher-private-health-probe",
    ),
    integrated_caddy_gate: pin(
      "/usr/local/libexec/bitcoinpir/payment-v1-integrated-caddy-overlay-gate.mjs",
      "0555",
      "integrated-caddy-gate",
    ),
    ip: pin("/usr/bin/ip", "0755", "ip"),
    launcher: pin(
      `/opt/bitcoinpir/publisher-netns-launcher/${launcherSha256}/payment-v1-publisher-netns-launcher`,
      "0555",
      "launcher",
    ),
    launcher_manifest: pin(
      "/etc/bitcoinpir/payment-v1/publisher-netns/launcher-inputs.sha256",
      "0444",
      "launcher-manifest",
    ),
    node: pin("/usr/bin/node", "0755", "node"),
    node_loader_closure_manifest: pin(
      "/etc/bitcoinpir/payment-v1/publisher-netns/node-loader-closure.sha256",
      "0444",
      "node-loader-closure-manifest",
    ),
    publisher_netns_gate: pin(
      "/usr/local/libexec/bitcoinpir/payment-v1-publisher-netns-gate.mjs",
      "0555",
      "publisher-netns-gate",
    ),
    schema_validator: pin(
      "/usr/local/libexec/bitcoinpir/payment-v1-publisher-netns-schema.mjs",
      "0555",
      "publisher-netns-schema",
    ),
    systemctl: pin("/usr/bin/systemctl", "0755", "systemctl"),
  };
  runtime.launcher.sha256 = launcherSha256;
  runtime.launcher.size = String(launcherBytes.length);
  const nodeElfClosure = nodeElfClosureFixture();
  const nodeBytes = nodeElfFixtureBytes(nodeElfClosure);
  runtime.node.sha256 = hash(nodeBytes);
  runtime.node.size = String(nodeBytes.length);
  const nodeLoaderClosureManifest = nodeLoaderClosureManifestBytes(nodeElfClosure);
  runtime.node_loader_closure_manifest.sha256 = hash(nodeLoaderClosureManifest);
  runtime.node_loader_closure_manifest.size = String(nodeLoaderClosureManifest.length);
  const launcherManifest = launcherManifestBytes(runtime);
  runtime.launcher_manifest.sha256 = hash(launcherManifest);
  runtime.launcher_manifest.size = String(launcherManifest.length);
  const plan = {
    activation_sentinels: sentinelPaths.map((path) => pin(path, "0400", basenameFor(path))),
    caddy_preimage: caddy,
    ceremony_id: ceremonyId,
    firewall_evidence: firewallPin,
    host: {
      boot_id: "01234567-89ab-cdef-0123-456789abcdef",
      machine_id_sha256: hash("machine-id"),
      systemd_manager_generation: {
        generators_finish_timestamp_monotonic: "1002",
        generators_start_timestamp_monotonic: "1001",
        pid1_exe_device: "2049",
        pid1_exe_inode: "501",
        pid1_exe_path: "/usr/lib/systemd/systemd",
        pid1_start_ticks: "100",
        units_load_finish_timestamp_monotonic: "1004",
        units_load_start_timestamp_monotonic: "1003",
      },
      systemd_version: "systemd 255 (255.4-1ubuntu8.10)",
    },
    installed_files: installedFiles,
    kind: CEREMONY_KIND,
    launcher_static_elf: inspectStaticElfV1(launcherBytes),
    node_elf_closure: nodeElfClosure,
    preimage: {
      host_interface: "absent",
      loaded_netns_unit: loadedNetnsUnit(installedFiles),
      namespace_path: "absent",
      netns_unit: inactive(NETNS_UNIT),
      publisher_unit: inactive(PUBLISHER_UNIT),
    },
    publisher_private_key_installed: false,
    relationship: {
      caddy_dependency: "Wants+After",
      integrated_profile: "integrated-existing-bhtm-caddy-v1",
      network_before_caddy: true,
      publisher_requires_namespace: true,
      receipt_generation_scope: "exact-boot-and-systemd-generation",
      reboot_recreation: "caddy-wants-after-persistent-sentinels",
      reverse_stop_propagation: false,
    },
    runtime,
    schema_version: 2,
    source_commit: "8".repeat(40),
    topology,
    transaction: {
      lock_path: "/run/lock/bitcoinpir-payment-v1-publisher-lifecycle.lock",
      receipt_path: `/var/lib/bitcoinpir/payment-v1/publisher-netns/receipts/${ceremonyId}.json`,
      rollback_receipt_path:
        `/var/lib/bitcoinpir/payment-v1/publisher-netns/receipts/${ceremonyId}.rollback.json`,
      state_directory:
        `/var/lib/bitcoinpir/payment-v1/publisher-netns/transactions/${ceremonyId}`,
    },
  };
  const planSha256 = computePlanSha256(plan);
  const approval = {
    acknowledgements: [...APPLY_ACKNOWLEDGEMENTS],
    approved_at_utc: new Date((NOW - 60) * 1000).toISOString().replace(".000Z", "Z"),
    approved_by: "security-reviewer:test-key-v1",
    ceremony_id: ceremonyId,
    decision: "approve-start-exact-publisher-netns",
    executor_sha256: plan.runtime.executor.sha256,
    expires_at_utc: new Date((NOW + 600) * 1000).toISOString().replace(".000Z", "Z"),
    kind: APPLY_APPROVAL_KIND,
    launcher_manifest_sha256: plan.runtime.launcher_manifest.sha256,
    launcher_sha256: plan.runtime.launcher.sha256,
    plan_sha256: planSha256,
    schema_version: 2,
  };
  return { approval, firewallBytes, plan, planSha256 };
}

function basenameFor(path) {
  return path.slice(path.lastIndexOf("/") + 1);
}

function topologyFixture(plan) {
  return {
    client: {
      address: plan.topology.client_address,
      alias: "bitcoinpir-payment-v1-publisher-netns:0123456789abcdef0123456789abcdef:client",
      index: 52,
      interface: plan.topology.client_interface,
      mac: "02:11:22:33:44:55",
      peer_index: 51,
      prefix_length: plan.topology.prefix_length,
      up: true,
    },
    forwarding_sysctls: {
      "net.ipv4.ip_forward": 0,
      "net.ipv6.conf.all.forwarding": 0,
    },
    host: {
      address: plan.topology.host_address,
      alias: "bitcoinpir-payment-v1-publisher-netns:0123456789abcdef0123456789abcdef:host",
      index: 51,
      interface: plan.topology.host_interface,
      mac: "02:aa:bb:cc:dd:ee",
      peer_index: 52,
      prefix_length: plan.topology.prefix_length,
      up: true,
    },
    namespace: {
      device: "13",
      inert_interfaces: [],
      inode: "9001",
      interface_names: ["lo", plan.topology.client_interface].sort(),
      loopback: {
        addresses: [{ family: "inet", local: "127.0.0.1", prefix_length: 8 }],
        alias: "",
        index: 1,
        up: true,
      },
      path: plan.topology.namespace_path,
      type: "nsfs",
    },
    routes: {
      client_main: [{ default: false, destination: "10.203.0.0/30", gateway: null, nat: false }],
      host_main: [{ default: false, destination: "10.203.0.0/30", gateway: null, nat: false }],
    },
  };
}

function fakeOps(fixtureValue) {
  const { firewallBytes, plan } = fixtureValue;
  const files = new Map();
  for (const entry of plan.installed_files) {
    files.set(entry.pin.path, {
      bytes: installedFileBytes(entry.id, plan.topology, plan.installed_files),
      snapshot: structuredClone(entry.pin),
    });
  }
  for (const [name, runtimePin] of Object.entries(plan.runtime)) {
    files.set(runtimePin.path, {
      bytes: name === "launcher"
        ? staticElfFixture()
        : name === "launcher_manifest"
        ? launcherManifestBytes(plan.runtime)
        : name === "node"
        ? nodeElfFixtureBytes(plan.node_elf_closure)
        : name === "node_loader_closure_manifest"
        ? nodeLoaderClosureManifestBytes(plan.node_elf_closure)
        : Buffer.from(`${name}\n`, "utf8"),
      snapshot: structuredClone(runtimePin),
    });
  }
  for (const object of plan.node_elf_closure.objects) {
    files.set(object.pin.path, {
      bytes: objectElfFixtureBytes(object),
      snapshot: structuredClone(object.pin),
    });
  }
  for (const sentinel of plan.activation_sentinels) {
    files.set(sentinel.path, { bytes: Buffer.from(`${basenameFor(sentinel.path)}\n`), snapshot: structuredClone(sentinel) });
  }
  files.set(plan.firewall_evidence.path, {
    bytes: firewallBytes,
    snapshot: structuredClone(plan.firewall_evidence),
  });
  const receipts = new Map();
  const states = new Map();
  let netns = structuredClone(plan.preimage.netns_unit);
  let failedNetns = null;
  let publisher = structuredClone(plan.preimage.publisher_unit);
  let caddy = structuredClone(plan.caddy_preimage);
  let host = structuredClone(plan.host);
  let loaded = structuredClone(plan.preimage.loaded_netns_unit);
  let topology = topologyFixture(plan);
  const calls = [];
  let startStatus = 0;
  let startError = null;
  let stopStatus = 0;
  let resetFailedStatus = 0;
  let resetFailedError = null;
  let jobAbsent = true;
  let networkAbsentOverride = null;
  let afterStart = () => {};
  let afterStop = () => {};
  let beforeNetworkAbsent = () => {};
  let beforeUnitJobAbsent = () => {};
  let beforeUnitState = () => {};
  let beforeLoadedNetnsUnit = () => {};
  let beforeHostIdentity = () => {};
  let afterWriteState = () => {};
  let lockHeld = false;
  const stateObservation = (key, value) => {
    const bytes = Buffer.from(canonicalJson(value), "utf8");
    const snapshot = pin(key, "0400", "state");
    snapshot.sha256 = hash(bytes);
    snapshot.size = String(bytes.length);
    return { bytes, snapshot, value: structuredClone(value) };
  };
  const ops = {
    calls,
    files,
    receipts,
    states,
    seedState(filename, value) {
      const key = `${plan.transaction.state_directory}/${filename}`;
      const observed = stateObservation(key, value);
      states.set(key, observed);
      return observed;
    },
    get caddy() { return caddy; },
    set caddy(value) { caddy = structuredClone(value); },
    get host() { return host; },
    set host(value) { host = structuredClone(value); },
    get loaded() { return loaded; },
    set loaded(value) { loaded = structuredClone(value); },
    get lockHeld() { return lockHeld; },
    get netns() { return netns; },
    set netns(value) {
      failedNetns = value.active_state === "failed" ? structuredClone(value) : null;
      netns = value.active_state === "failed" ? failedProjection(value) : structuredClone(value);
    },
    get failedNetns() { return failedNetns; },
    set failedNetns(value) {
      failedNetns = structuredClone(value);
      netns = failedProjection(value);
    },
    get publisher() { return publisher; },
    set publisher(value) { publisher = structuredClone(value); },
    set jobAbsent(value) { jobAbsent = value; },
    set networkAbsentOverride(value) { networkAbsentOverride = value; },
    set startError(value) { startError = value; },
    set startStatus(value) { startStatus = value; },
    set stopStatus(value) { stopStatus = value; },
    set resetFailedError(value) { resetFailedError = value; },
    set resetFailedStatus(value) { resetFailedStatus = value; },
    set afterStart(value) { afterStart = value; },
    set afterStop(value) { afterStop = value; },
    set beforeNetworkAbsent(value) { beforeNetworkAbsent = value; },
    set beforeUnitJobAbsent(value) { beforeUnitJobAbsent = value; },
    set beforeUnitState(value) { beforeUnitState = value; },
    set beforeLoadedNetnsUnit(value) { beforeLoadedNetnsUnit = value; },
    set beforeHostIdentity(value) { beforeHostIdentity = value; },
    set afterWriteState(value) { afterWriteState = value; },
    set topology(value) { topology = structuredClone(value); },
    async acquireLock(_path, { recoverStale }) {
      calls.push(["lock", recoverStale]);
      if (lockHeld && !recoverStale) throw new Error("lock held");
      lockHeld = true;
      return async () => { calls.push(["unlock"]); lockHeld = false; };
    },
    async caddyState() { return structuredClone(caddy); },
    async hostIdentity() {
      calls.push(["hostIdentity"]);
      beforeHostIdentity();
      return structuredClone(host);
    },
    async loadedNetnsUnit() {
      calls.push(["loadedNetnsUnit"]);
      beforeLoadedNetnsUnit();
      return structuredClone(loaded);
    },
    async failedUnitState(name) {
      calls.push(["failedUnitState", name]);
      if (name !== NETNS_UNIT || failedNetns === null) throw new Error("unit is not failed");
      return structuredClone(failedNetns);
    },
    async networkAbsent() {
      calls.push(["networkAbsent"]);
      beforeNetworkAbsent();
      return networkAbsentOverride ?? netns.active_state !== "active";
    },
    async networkState() { return structuredClone(topology); },
    async readOptionalRegular(path) {
      const value = receipts.get(path) ?? states.get(path);
      if (value === undefined) return null;
      return { bytes: Buffer.from(value.bytes), snapshot: structuredClone(value.snapshot) };
    },
    async readRegular(path) {
      const value = receipts.get(path) ?? files.get(path);
      if (value === undefined) throw new Error(`missing ${path}`);
      return { bytes: Buffer.from(value.bytes), snapshot: structuredClone(value.snapshot) };
    },
    async systemctl(args) {
      calls.push(["systemctl", ...args]);
      assert.deepEqual(args.slice(1), [NETNS_UNIT]);
      if (args[0] === "start" && startError !== null) {
        failedNetns = failed(NETNS_UNIT);
        netns = failedProjection(failedNetns);
        afterStart();
        throw startError;
      }
      if (args[0] === "start" && startStatus === 0) {
        netns = active(NETNS_UNIT);
        failedNetns = null;
        afterStart();
      }
      if (args[0] === "start" && startStatus !== 0) {
        failedNetns = failed(NETNS_UNIT);
        netns = failedProjection(failedNetns);
        afterStart();
      }
      if (args[0] === "stop" && stopStatus === 0) {
        netns = inactive(NETNS_UNIT);
        failedNetns = null;
        afterStop();
      }
      if (args[0] === "reset-failed") {
        if (resetFailedError !== null) {
          netns = inactive(NETNS_UNIT);
          failedNetns = null;
          throw resetFailedError;
        }
        if (resetFailedStatus === 0) {
          netns = inactive(NETNS_UNIT);
          failedNetns = null;
        }
      }
      return {
        status: args[0] === "start" ? startStatus :
          args[0] === "reset-failed" ? resetFailedStatus : stopStatus,
      };
    },
    async unitJobAbsent(name) {
      calls.push(["unitJobAbsent", name]);
      beforeUnitJobAbsent(name);
      return jobAbsent;
    },
    async unitState(name) {
      calls.push(["unitState", name]);
      beforeUnitState(name);
      if (name === NETNS_UNIT) return structuredClone(netns);
      if (name === PUBLISHER_UNIT) return structuredClone(publisher);
      throw new Error(`unknown unit ${name}`);
    },
    async writeReceipt(path, value) {
      if (receipts.has(path)) throw new Error("receipt exists");
      const bytes = Buffer.from(canonicalJson(value));
      const snapshot = pin(path, "0400", "receipt");
      snapshot.sha256 = hash(bytes);
      snapshot.size = String(bytes.length);
      const observed = { bytes, snapshot };
      receipts.set(path, observed);
      return observed;
    },
    async writeState(directory, filename, value) {
      const key = `${directory}/${filename}`;
      const existing = states.get(key);
      if (existing !== undefined && canonicalJson(existing.value) !== canonicalJson(value)) {
        throw new Error("state replay drifted");
      }
      if (existing === undefined) states.set(key, stateObservation(key, value));
      afterWriteState(filename, value);
    },
  };
  return ops;
}

function approvalDigest(value) {
  return hash(Buffer.from(canonicalJson(value)));
}

async function applyFixture(value, ops, recover = false) {
  return executeApply({
    approval: value.approval,
    approvedApprovalSha256: approvalDigest(value.approval),
    approvedPlanSha256: value.planSha256,
    nowUnix: NOW,
    ops,
    plan: value.plan,
    recover,
  });
}

function durableStartIntent(value, activationApprovalSha256 = approvalDigest(value.approval)) {
  return {
    approved_approval_sha256: activationApprovalSha256,
    approved_plan_sha256: value.planSha256,
    ceremony_id: value.plan.ceremony_id,
    phase: "start-intent",
    schema_version: 1,
  };
}

function failedRecoveryApproval(
  value,
  observedStartIntent,
  failedUnit,
  activationApprovalSha256 = approvalDigest(value.approval),
) {
  return {
    acknowledgements: [...FAILED_RECOVERY_ACKNOWLEDGEMENTS],
    activation_approval_sha256: activationApprovalSha256,
    approved_at_utc: new Date((NOW - 30) * 1000).toISOString().replace(".000Z", "Z"),
    approved_by: "security-reviewer:failed-recovery-test-key-v1",
    ceremony_id: value.plan.ceremony_id,
    decision: "approve-reset-exact-failed-publisher-netns",
    executor_sha256: value.plan.runtime.executor.sha256,
    expires_at_utc: new Date((NOW + 300) * 1000).toISOString().replace(".000Z", "Z"),
    failed_unit: structuredClone(failedUnit),
    failed_unit_sha256: computePublisherNetnsFailedUnitSha256V1(failedUnit),
    kind: FAILED_RECOVERY_APPROVAL_KIND,
    launcher_manifest_sha256: value.plan.runtime.launcher_manifest.sha256,
    launcher_sha256: value.plan.runtime.launcher.sha256,
    plan_sha256: value.planSha256,
    reset_failed_argv: ["reset-failed", NETNS_UNIT],
    schema_version: 1,
    start_intent_sha256: hash(observedStartIntent.bytes),
  };
}

async function recoverFailedFixture(value, ops, approval, nowUnix = NOW) {
  return executeApply({
    approval,
    approvedApprovalSha256: approvalDigest(approval),
    approvedPlanSha256: value.planSha256,
    nowUnix,
    ops,
    plan: value.plan,
    recover: true,
  });
}

test("closed publisher namespace ceremony plan validates", () => {
  const value = fixture();
  assert.equal(validateCeremonyPlan(value.plan), true);
  assert.equal(computePlanSha256(value.plan), value.planSha256);
  assert.equal(
    computePlanSha256(value.plan),
    hash(Buffer.from(canonicalJson(value.plan), "utf8")),
    "shared schema validator must preserve the established canonical plan digest",
  );
});

test("Node ELF closure is byte-verified and excludes unreachable preload objects", () => {
  const value = fixture();
  const closure = value.plan.node_elf_closure;
  const nodeBytes = nodeElfFixtureBytes(closure);
  const objectBytes = new Map(closure.objects.map((object) => [
    object.pin.path,
    objectElfFixtureBytes(object),
  ]));
  const inspected = validatePublisherNodeElfClosureBytesV1({
    closure,
    nodeBytes,
    objectBytes,
  });
  assert.equal(inspected.node.pt_interp, closure.pt_interp);
  assert.deepEqual(inspected.node.needed, closure.node_needed);

  const unreachable = structuredClone(value.plan);
  unreachable.node_elf_closure.objects.push({
    needed: [],
    pin: pin(
      "/usr/lib/x86_64-linux-gnu/libunreachable.so.1", "0755", "unreachable",
    ),
    soname: "libunreachable.so.1",
  });
  unreachable.runtime.node_loader_closure_manifest.sha256 = hash(
    nodeLoaderClosureManifestBytes(unreachable.node_elf_closure),
  );
  assert.throws(
    () => validatePublisherNetnsPlanV2(unreachable),
    /unreachable preload object/u,
  );

  const misordered = structuredClone(value.plan);
  const [loader, libc, libm] = misordered.node_elf_closure.objects;
  misordered.node_elf_closure.objects = [loader, libm, libc];
  misordered.runtime.node_loader_closure_manifest.sha256 = hash(
    nodeLoaderClosureManifestBytes(misordered.node_elf_closure),
  );
  assert.throws(
    () => validatePublisherNetnsPlanV2(misordered),
    /canonical dependency-first preload order/u,
  );
});

test("dynamic ELF parser rejects dependency-injection tags before activation", () => {
  for (const [tag, name] of [
    [15n, "DT_RPATH"],
    [29n, "DT_RUNPATH"],
    [0x6ffffefbn, "DT_DEPAUDIT"],
    [0x6ffffefcn, "DT_AUDIT"],
    [0x7ffffffdn, "DT_AUXILIARY"],
    [0x7fffffffn, "DT_FILTER"],
  ]) {
    assert.throws(
      () => inspectDynamicElfV1(dynamicElfFixture({
        extraDynamicTags: [tag],
        needed: ["libc.so.6"],
        soname: "libtest.so.1",
      })),
      new RegExp(name, "u"),
    );
  }
});

test("loaded-unit Exec parser accepts only exact systemd record separators", () => {
  const first =
    "{ path=/usr/bin/sha256sum ; argv[]=/usr/bin/sha256sum --check /one ; " +
    "ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }";
  const second =
    "{ path=/usr/bin/sha256sum ; argv[]=/usr/bin/sha256sum --check /two ; " +
    "ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }";
  const expected = [
    { argv: "/usr/bin/sha256sum --check /one", ignore_errors: "no", path: "/usr/bin/sha256sum" },
    { argv: "/usr/bin/sha256sum --check /two", ignore_errors: "no", path: "/usr/bin/sha256sum" },
  ];
  assert.deepEqual(parseSystemdExecRecordsV1(`${first}\n${second}`), expected);
  assert.deepEqual(parseSystemdExecRecordsV1(`${first} ; ${second}`), expected);
  for (const malformed of [
    `${first}${second}`,
    `${first} ${second}`,
    `${first}\n\n${second}`,
    ` ${first}`,
    `${first}\n`,
    `${first}\r\n${second}`,
    `${first}\0`,
  ]) {
    assert.throws(
      () => parseSystemdExecRecordsV1(malformed),
      /non-empty systemd Exec command list|unreviewed/u,
    );
  }
});

test("executor local import closure is exact and both sibling gates are plan-pinned", () => {
  const source = readFileSync(new URL(
    "./payment-v1-publisher-netns-ceremony.mjs",
    import.meta.url,
  ), "utf8");
  const localImports = [...source.matchAll(/from\s+"(\.\/[^"]+)";/gu)]
    .map((match) => match[1])
    .sort();
  assert.doesNotMatch(source, /\bimport\s*\(/u);
  assert.doesNotMatch(source, /\bexport\s+(?:\*|\{[^}]*\})\s+from\b/u);
  assert.deepEqual(localImports, [
    "./payment-v1-integrated-caddy-overlay-gate.mjs",
    "./payment-v1-publisher-netns-gate.mjs",
    "./payment-v1-publisher-netns-schema.mjs",
  ]);
  const value = fixture();
  assert.equal(
    value.plan.runtime.integrated_caddy_gate.path,
    "/usr/local/libexec/bitcoinpir/payment-v1-integrated-caddy-overlay-gate.mjs",
  );
  assert.equal(
    value.plan.runtime.publisher_netns_gate.path,
    "/usr/local/libexec/bitcoinpir/payment-v1-publisher-netns-gate.mjs",
  );
  value.plan.runtime.publisher_netns_gate.path =
    "/usr/local/libexec/bitcoinpir/unreviewed-gate.mjs";
  assert.throws(() => validateCeremonyPlan(value.plan), /path is not approved/u);
});

test("launcher and its seven-entry manifest are plan- and approval-bound", async () => {
  {
    const value = fixture();
    value.plan.runtime.launcher.path =
      "/opt/bitcoinpir/publisher-netns-launcher/unreviewed/payment-v1-publisher-netns-launcher";
    assert.throws(() => validateCeremonyPlan(value.plan), /path is not approved/u);
  }
  {
    const value = fixture();
    const ops = fakeOps(value);
    const manifest = ops.files.get(value.plan.runtime.launcher_manifest.path);
    manifest.bytes = Buffer.from(`${value.plan.runtime.node.sha256}  /usr/bin/node\n`, "utf8");
    await assert.rejects(
      () => applyFixture(value, ops),
      /launcher manifest does not bind the exact Node\/executor\/import closure/u,
    );
    assert.equal(ops.calls.some((call) => call[0] === "systemctl"), false);
  }
  {
    const value = fixture();
    value.approval.schema_version = 1;
    delete value.approval.launcher_sha256;
    delete value.approval.launcher_manifest_sha256;
    const ops = fakeOps(value);
    await assert.rejects(() => applyFixture(value, ops), /approval keys drifted|kind\/schema/u);
    assert.equal(ops.calls.some((call) => call[0] === "systemctl"), false);
  }
  {
    const value = fixture();
    value.approval.launcher_sha256 = "f".repeat(64);
    const ops = fakeOps(value);
    await assert.rejects(() => applyFixture(value, ops), /approval binding drifted/u);
    assert.equal(ops.calls.some((call) => call[0] === "systemctl"), false);
  }
});

test("private pair validator accepts RFC1918 and ULA point-to-point pairs", () => {
  assert.equal(validatePrivatePairV1({
    client: "10.20.30.2", family: "ipv4", host: "10.20.30.1", prefixLength: 30,
  }), true);
  assert.equal(validatePrivatePairV1({
    client: "fd42::2", family: "ipv6", host: "fd42::1", prefixLength: 126,
  }), true);
});

for (const [label, mutate, error] of [
  ["public address", (plan) => { plan.topology.host_address = "198.51.100.1"; }, /RFC1918/u],
  ["same address", (plan) => { plan.topology.client_address = plan.topology.host_address; }, /distinct/u],
  ["wrong family", (plan) => { plan.topology.address_family = "ipv6"; }, /declared family/u],
  ["interface overflow", (plan) => { plan.topology.host_interface = "sixteen-byte-name"; }, /1\.\.15/u],
  ["interface metacharacter", (plan) => { plan.topology.host_interface = "bpir.pub"; }, /interface name/u],
  ["loopback hosts path", (plan) => { plan.topology.hosts_path = "/etc/hosts"; }, /derive/u],
  ["default route", (plan) => { plan.topology.default_route = true; }, /close default routing/u],
  ["NAT", (plan) => { plan.topology.nat = true; }, /close default routing/u],
  ["forwarding", (plan) => { plan.topology.forwarding = true; }, /close default routing/u],
  ["publisher private key", (plan) => { plan.publisher_private_key_installed = true; }, /must be false/u],
  ["Caddy reverse coupling", (plan) => { plan.relationship.reverse_stop_propagation = true; },
    /one-way Caddy ordering/u],
  ["unloaded Caddy dependency", (plan) => {
    plan.caddy_preimage.dependency.requires_namespace_owner = true;
  }, /exact loaded one-way namespace relation/u],
  ["Caddy daemon-reload drift", (plan) => {
    plan.caddy_preimage.unit.need_daemon_reload = "yes";
  }, /unsealed systemd generation/u],
  ["inactive Caddy", (plan) => {
    plan.caddy_preimage.unit.active_state = "inactive";
  }, /live non-zero systemd generation/u],
  ["non-running Caddy", (plan) => {
    plan.caddy_preimage.unit.sub_state = "dead";
  }, /live non-zero systemd generation/u],
  ["zero Caddy MainPID", (plan) => {
    plan.caddy_preimage.unit.main_pid = "0";
  }, /live non-zero systemd generation/u],
  ["zero Caddy InvocationID", (plan) => {
    plan.caddy_preimage.unit.invocation_id = "0".repeat(32);
  }, /live non-zero systemd generation/u],
  ["zero Caddy activation timestamp", (plan) => {
    plan.caddy_preimage.unit.active_enter_timestamp_monotonic = "0";
  }, /live non-zero systemd generation/u],
  ["helper path digest", (plan) => {
    plan.installed_files.find((entry) => entry.id === "helper-binary").pin.sha256 = "f".repeat(64);
  }, /content-address|path is not approved/u],
]) {
  test(`plan rejects ${label}`, () => {
    const value = fixture();
    mutate(value.plan);
    assert.throws(() => validateCeremonyPlan(value.plan), error);
  });
}

for (const [label, mutate] of [
  ["active state", (unit) => { unit.active_state = "inactive"; }],
  ["running substate", (unit) => { unit.sub_state = "dead"; }],
  ["MainPID", (unit) => { unit.main_pid = "0"; }],
  ["InvocationID", (unit) => { unit.invocation_id = "0".repeat(32); }],
  ["activation timestamp", (unit) => { unit.active_enter_timestamp_monotonic = "0"; }],
]) {
  test(`shared schema independently rejects a non-live Caddy ${label}`, () => {
    const value = fixture();
    mutate(value.plan.caddy_preimage.unit);
    assert.throws(
      () => validatePublisherNetnsPlanV2(value.plan),
      /publisher-netns-schema-v2: .*live non-zero systemd generation/u,
    );
  });
}

test("apply starts only the exact netns unit and commits a closed receipt", async () => {
  const value = fixture();
  const ops = fakeOps(value);
  const receipt = await applyFixture(value, ops);
  assert.equal(receipt.outcome, "committed");
  assert.equal(receipt.netns_unit.active_state, "active");
  assert.deepEqual(ops.calls.filter((call) => call[0] === "systemctl"), [
    ["systemctl", "start", NETNS_UNIT],
  ]);
  assert.deepEqual(receipt.caddy_before, receipt.caddy_after);
  assert.equal(receipt.publisher_unit.active_state, "inactive");
  assert.equal(ops.receipts.has(value.plan.transaction.receipt_path), true);
});

test("exact committed apply replay is idempotent and does not start twice", async () => {
  const value = fixture();
  const ops = fakeOps(value);
  const first = await applyFixture(value, ops);
  const second = await applyFixture(value, ops);
  assert.equal(canonicalJson(second), canonicalJson(first));
  assert.equal(ops.calls.filter((call) => call[0] === "systemctl").length, 1);
});

test("committed replay refuses a pending PID1 job and recovery retains its lock", async () => {
  const value = fixture();
  const ops = fakeOps(value);
  await applyFixture(value, ops);
  ops.jobAbsent = false;
  ops.calls.length = 0;
  await assert.rejects(
    () => applyFixture(value, ops),
    /committed replay found a pending .*systemd job/us,
  );
  assert.equal(ops.lockHeld, false);
  assert.deepEqual(ops.calls.at(-1), ["unlock"]);
  ops.calls.length = 0;
  await assert.rejects(
    () => applyFixture(value, ops, true),
    /start outcome is unknown; shared lifecycle lock retained.*committed replay found a pending .*systemd job/us,
  );
  assert.equal(ops.lockHeld, true);
  assert.equal(ops.calls.some((call) => call[0] === "unlock"), false);
});

test("recover-commit reconciles a lost start response from exact live topology", async () => {
  const value = fixture();
  const ops = fakeOps(value);
  ops.netns = active(NETNS_UNIT);
  ops.seedState("05-start-intent.json", {
    approved_approval_sha256: approvalDigest(value.approval),
    approved_plan_sha256: value.planSha256,
    ceremony_id: value.plan.ceremony_id,
    phase: "start-intent",
    schema_version: 1,
  });
  const receipt = await applyFixture(value, ops, true);
  assert.equal(receipt.outcome, "committed");
  assert.equal(receipt.activation_approval_sha256, approvalDigest(value.approval));
  assert.equal(ops.calls.some((call) => call[0] === "systemctl"), false);
  assert.deepEqual(ops.calls[0], ["lock", true]);
});

test("plain apply never adopts an already-active namespace without explicit recovery", async () => {
  const value = fixture();
  const ops = fakeOps(value);
  ops.netns = active(NETNS_UNIT);
  await assert.rejects(() => applyFixture(value, ops), /use recover-commit/u);
  assert.equal(ops.receipts.size, 0);
  assert.equal(ops.calls.some((call) => call[0] === "systemctl"), false);
});

test("recover-commit requires and preserves the durable approval that authorized start", async () => {
  {
    const value = fixture();
    const ops = fakeOps(value);
    ops.netns = active(NETNS_UNIT);
    await assert.rejects(() => applyFixture(value, ops, true), /without the durable start intent/u);
    assert.equal(ops.receipts.size, 0);
  }
  {
    const value = fixture();
    const ops = fakeOps(value);
    const originalApprovalSha256 = "1".repeat(64);
    ops.netns = active(NETNS_UNIT);
    ops.seedState("05-start-intent.json", {
      approved_approval_sha256: originalApprovalSha256,
      approved_plan_sha256: value.planSha256,
      ceremony_id: value.plan.ceremony_id,
      phase: "start-intent",
      schema_version: 1,
    });
    const receipt = await applyFixture(value, ops, true);
    assert.equal(receipt.activation_approval_sha256, originalApprovalSha256);
    assert.equal(receipt.approved_approval_sha256, approvalDigest(value.approval));
  }
});

test("Caddy or publisher drift fails before namespace mutation", async () => {
  for (const drift of ["caddy", "publisher"]) {
    const value = fixture();
    const ops = fakeOps(value);
    if (drift === "caddy") {
      const changed = structuredClone(ops.caddy);
      changed.unit.main_pid = "901";
      ops.caddy = changed;
    } else {
      ops.publisher = active(PUBLISHER_UNIT, "b".repeat(32), "333");
    }
    await assert.rejects(() => applyFixture(value, ops), /Caddy preimage changed|publisher service/u);
    assert.equal(ops.calls.some((call) => call[0] === "systemctl"), false);
  }
});

test("namespace activation raced into the final pre-start window is never adopted", async () => {
  const value = fixture();
  const ops = fakeOps(value);
  let netnsReads = 0;
  ops.beforeUnitState = (name) => {
    if (name === NETNS_UNIT && ++netnsReads === 2) ops.netns = active(NETNS_UNIT);
  };
  await assert.rejects(
    () => applyFixture(value, ops),
    /final pre-start publisher namespace preimage changed/u,
  );
  assert.equal(ops.calls.some((call) => call[0] === "systemctl"), false);
  assert.equal(ops.receipts.size, 0);
});

test("the exact loaded unit and manager generation are rechecked immediately before start", async () => {
  const value = fixture();
  const ops = fakeOps(value);
  await applyFixture(value, ops);
  const startIndex = ops.calls.findIndex(
    (call) => call[0] === "systemctl" && call[1] === "start",
  );
  assert.deepEqual(ops.calls.slice(startIndex - 6, startIndex), [
    ["hostIdentity"],
    ["unitState", PUBLISHER_UNIT],
    ["loadedNetnsUnit"],
    ["unitState", NETNS_UNIT],
    ["networkAbsent"],
    ["unitJobAbsent", NETNS_UNIT],
  ]);
});

test("both pre-start closures reject a queued PID1 job without invoking start", async () => {
  for (const [jobRead, durableIntentWritten] of [[2, false], [4, true]]) {
    const value = fixture();
    const ops = fakeOps(value);
    let reads = 0;
    ops.beforeUnitJobAbsent = () => {
      reads += 1;
      if (reads === jobRead) ops.jobAbsent = false;
    };
    await assert.rejects(
      () => applyFixture(value, ops),
      /(?:pre-start|start-adjacent) retained a pending publisher namespace systemd job/u,
    );
    assert.equal(
      ops.states.has(`${value.plan.transaction.state_directory}/05-start-intent.json`),
      durableIntentWritten,
    );
    assert.equal(ops.calls.some(
      (call) => call[0] === "systemctl" && call[1] === "start"), false);
    assert.equal(ops.lockHeld, false);
  }
});

test("runtime input drift after durable start intent is rechecked before activation", async () => {
  const value = fixture();
  const ops = fakeOps(value);
  let tampered = false;
  ops.afterWriteState = (filename) => {
    if (filename !== "05-start-intent.json" || tampered) return;
    tampered = true;
    const path = value.plan.runtime.launcher_manifest.path;
    const observed = ops.files.get(path);
    observed.bytes = Buffer.from("unapproved launcher manifest\n", "utf8");
    observed.snapshot.sha256 = hash(observed.bytes);
    observed.snapshot.size = String(observed.bytes.length);
  };
  await assert.rejects(
    () => applyFixture(value, ops),
    /runtime command launcher_manifest drifted/u,
  );
  assert.equal(tampered, true);
  assert.equal(
    ops.states.has(`${value.plan.transaction.state_directory}/05-start-intent.json`),
    true,
  );
  assert.equal(ops.calls.some((call) => call[0] === "systemctl"), false);
  assert.equal(ops.receipts.size, 0);
});

for (const [label, mutate, expected] of [
  [
    "drop-in injection",
    (ops) => { ops.loaded.dropin_paths = ["/run/systemd/system/evil.conf"]; },
    /loaded publisher namespace unit drifted/u,
  ],
  [
    "ExecStart reset",
    (ops) => { ops.loaded.exec.start = []; },
    /loaded publisher namespace unit drifted/u,
  ],
  [
    "daemon-reload",
    (ops) => {
      ops.host.systemd_manager_generation.units_load_finish_timestamp_monotonic = "9999";
    },
    /host identity\/systemd generation drifted/u,
  ],
  [
    "daemon-reexec",
    (ops) => { ops.host.systemd_manager_generation.pid1_exe_inode = "9999"; },
    /host identity\/systemd generation drifted/u,
  ],
]) {
  test(`${label} race immediately before start fails closed`, async () => {
    const value = fixture();
    const ops = fakeOps(value);
    let loadedReads = 0;
    let hostReads = 0;
    if (label === "drop-in injection" || label === "ExecStart reset") {
      ops.beforeLoadedNetnsUnit = () => {
        loadedReads += 1;
        if (loadedReads === 3) mutate(ops);
      };
    } else {
      ops.beforeHostIdentity = () => {
        hostReads += 1;
        if (hostReads === 3) mutate(ops);
      };
    }
    await assert.rejects(() => applyFixture(value, ops), expected);
    assert.equal(ops.calls.some((call) => call[0] === "systemctl"), false);
    assert.equal(ops.receipts.size, 0);
  });
}

test("firewall evidence drift fails before namespace mutation", async () => {
  const value = fixture();
  const ops = fakeOps(value);
  const evidence = ops.files.get(value.plan.firewall_evidence.path);
  evidence.bytes = Buffer.from("{}", "utf8");
  await assert.rejects(() => applyFixture(value, ops), /firewall output keys/u);
  assert.equal(ops.calls.some((call) => call[0] === "systemctl"), false);
});

test("semantic Caddy ordering, namespace-unit and network-policy drift fail before mutation", async () => {
  for (const [id, transform, error] of [
    ["caddy-netns-dropin", (text) => text.replace(
      "Wants=bitcoinpir-payment-v1-publisher-netns.service",
      "Requires=bitcoinpir-payment-v1-publisher-netns.service",
    ), /Unit keys must equal|Wants must equal/u],
    ["publisher-netns-unit", (text) => text.replace("Restart=no", "Restart=always"),
      /Restart must equal/u],
    ["network-policy", (text) => text.replace(
      '"point_in_time_evidence_only": false',
      '"point_in_time_evidence_only": true',
    ), /closed V1 policy/u],
    ["helper-manifest", (text) => `${text[0] === "0" ? "1" : "0"}${text.slice(1)}`,
      /helper manifest does not bind/u],
    ["network-inputs-manifest",
      (text) => `${text[0] === "0" ? "1" : "0"}${text.slice(1)}`,
      /network-input manifest does not bind/u],
  ]) {
    const value = fixture();
    const ops = fakeOps(value);
    const installed = value.plan.installed_files.find((entry) => entry.id === id);
    const observed = ops.files.get(installed.pin.path);
    observed.bytes = Buffer.from(transform(observed.bytes.toString("utf8")), "utf8");
    await assert.rejects(() => applyFixture(value, ops), error);
    assert.equal(ops.calls.some((call) => call[0] === "systemctl"), false);
  }
});

test("a local gate import inode drift during start prevents receipt publication", async () => {
  const value = fixture();
  const ops = fakeOps(value);
  ops.afterStart = () => {
    const gate = ops.files.get(value.plan.runtime.publisher_netns_gate.path);
    gate.snapshot.inode = "999999";
  };
  await assert.rejects(
    () => applyFixture(value, ops),
    /runtime command publisher_netns_gate drifted/u,
  );
  assert.equal(ops.netns.active_state, "active");
  assert.equal(ops.receipts.size, 0);
  assert.equal(ops.lockHeld, true);
  assert.equal(ops.calls.some((call) => call[0] === "unlock"), false);
});

test("a host boot or systemd identity drift during start prevents receipt publication", async () => {
  const value = fixture();
  const ops = fakeOps(value);
  ops.afterStart = () => {
    const changed = structuredClone(ops.host);
    changed.boot_id = "f".repeat(32);
    ops.host = changed;
  };
  await assert.rejects(
    () => applyFixture(value, ops),
    /host boot\/systemd identity changed during namespace start/u,
  );
  assert.equal(ops.netns.active_state, "active");
  assert.equal(ops.receipts.size, 0);
  assert.equal(ops.lockHeld, true);
  assert.equal(ops.calls.some((call) => call[0] === "unlock"), false);
});

test("expired, overlong and future approvals fail before locking", async () => {
  for (const mutate of [
    (approval) => { approval.expires_at_utc = new Date((NOW - 1) * 1000).toISOString().replace(".000Z", "Z"); },
    (approval) => { approval.expires_at_utc = new Date((NOW + 7200) * 1000).toISOString().replace(".000Z", "Z"); },
    (approval) => { approval.approved_at_utc = new Date((NOW + 600) * 1000).toISOString().replace(".000Z", "Z"); },
  ]) {
    const value = fixture();
    mutate(value.approval);
    const ops = fakeOps(value);
    await assert.rejects(() => executeApply({
      approval: value.approval,
      approvedApprovalSha256: approvalDigest(value.approval),
      approvedPlanSha256: value.planSha256,
      nowUnix: NOW,
      ops,
      plan: value.plan,
    }), /not currently valid/u);
    assert.equal(ops.calls.length, 0);
  }
});

test("nonzero systemctl start is outcome-unknown and retains the shared lifecycle lock", async () => {
  const value = fixture();
  const ops = fakeOps(value);
  ops.startStatus = 1;
  await assert.rejects(
    () => applyFixture(value, ops),
    /start outcome is unknown; shared lifecycle lock retained.*returned nonzero/us,
  );
  assert.equal(ops.receipts.size, 0);
  assert.deepEqual(ops.caddy, value.plan.caddy_preimage);
  assert.equal(ops.lockHeld, true);
  assert.equal(ops.calls.some((call) => call[0] === "unlock"), false);
});

test("real systemd-shaped failed/failed state requires a separately bound reset approval", async () => {
  const value = fixture();
  const ops = fakeOps(value);
  ops.startStatus = 1;
  await assert.rejects(() => applyFixture(value, ops), /start outcome is unknown/u);
  assert.equal(ops.netns.active_state, "failed");
  validatePublisherNetnsFailedUnitV1(ops.failedNetns);
  ops.calls.length = 0;
  await assert.rejects(
    () => applyFixture(value, ops, true),
    /requires an exact failed-start recovery approval/u,
  );
  assert.equal(
    ops.calls.some((call) => call[0] === "systemctl" && call[1] === "reset-failed"),
    false,
  );
  assert.equal(ops.lockHeld, true);
});

test("failed-start recovery resets only the exact approved InvocationID and commits its receipt", async () => {
  const value = fixture();
  const ops = fakeOps(value);
  ops.startStatus = 1;
  await assert.rejects(() => applyFixture(value, ops), /start outcome is unknown/u);
  const observedStartIntent = ops.states.get(
    `${value.plan.transaction.state_directory}/05-start-intent.json`,
  );
  const recoveryApproval = failedRecoveryApproval(
    value,
    observedStartIntent,
    ops.failedNetns,
  );
  ops.calls.length = 0;
  const receipt = await recoverFailedFixture(value, ops, recoveryApproval);
  assert.equal(receipt.outcome, "failed-start-recovered");
  assert.equal(receipt.failed_unit.invocation_id, "d".repeat(32));
  assert.deepEqual(receipt.reset_failed_argv, ["reset-failed", NETNS_UNIT]);
  assert.equal(
    receipt.approved_recovery_approval_sha256,
    approvalDigest(recoveryApproval),
  );
  assert.equal(
    receipt.reset_intent_approval_sha256,
    approvalDigest(recoveryApproval),
  );
  assert.equal(receipt.recovered_unit.active_state, "inactive");
  assert.equal(receipt.topology_absent, true);
  assert.deepEqual(ops.calls.filter((call) => call[0] === "systemctl"), [
    ["systemctl", "reset-failed", NETNS_UNIT],
  ]);
  assert.equal(ops.lockHeld, false);
  assert.equal(
    ops.states.has(`${value.plan.transaction.state_directory}/06-reset-failed-intent.json`),
    true,
  );
  assert.equal(
    ops.states.has(`${value.plan.transaction.state_directory}/07-failed-start-recovered.json`),
    true,
  );
  assert.equal(
    validatePublisherNetnsFailedRecoveryReceiptV1({
      approvedPlanSha256: value.planSha256,
      approvedRecoveryApprovalSha256: approvalDigest(recoveryApproval),
      plan: value.plan,
      receipt,
    }),
    true,
  );
});

test("failed-start recovery refuses a different failed generation before reset", async () => {
  const value = fixture();
  const ops = fakeOps(value);
  ops.startStatus = 1;
  await assert.rejects(() => applyFixture(value, ops), /start outcome is unknown/u);
  const observedStartIntent = ops.states.get(
    `${value.plan.transaction.state_directory}/05-start-intent.json`,
  );
  const recoveryApproval = failedRecoveryApproval(
    value,
    observedStartIntent,
    ops.failedNetns,
  );
  ops.failedNetns = failed(NETNS_UNIT, "e".repeat(32));
  ops.calls.length = 0;
  await assert.rejects(
    () => recoverFailedFixture(value, ops, recoveryApproval),
    /current unit is not the exact approved failed invocation/u,
  );
  assert.equal(ops.calls.some((call) => call[0] === "systemctl"), false);
  assert.equal(ops.lockHeld, true);
});

test("failed-start recovery approval rejects broadened authority before locking", async () => {
  for (const [mutate, expected] of [
    [
      (approval) => { approval.reset_failed_argv = ["reset-failed", PUBLISHER_UNIT]; },
      /decision or fixed reset argv drifted/u,
    ],
    [
      (approval) => { approval.failed_unit.main_pid = "9"; },
      /not one terminal failed\/failed systemd invocation/u,
    ],
    [
      (approval) => {
        approval.expires_at_utc = new Date((NOW - 1) * 1000)
          .toISOString().replace(".000Z", "Z");
      },
      /not currently valid/u,
    ],
  ]) {
    const value = fixture();
    const ops = fakeOps(value);
    const observedStartIntent = ops.seedState(
      "05-start-intent.json",
      durableStartIntent(value),
    );
    ops.failedNetns = failed(NETNS_UNIT);
    const recoveryApproval = failedRecoveryApproval(
      value,
      observedStartIntent,
      ops.failedNetns,
    );
    mutate(recoveryApproval);
    await assert.rejects(
      () => recoverFailedFixture(value, ops, recoveryApproval),
      expected,
    );
    assert.equal(ops.calls.length, 0);
    assert.equal(ops.lockHeld, false);
  }
});

test("failed-start recovery binds both the durable intent and original activation approval", async () => {
  for (const mutate of [
    (approval) => { approval.start_intent_sha256 = "9".repeat(64); },
    (approval) => { approval.activation_approval_sha256 = "8".repeat(64); },
  ]) {
    const value = fixture();
    const ops = fakeOps(value);
    ops.startStatus = 1;
    await assert.rejects(() => applyFixture(value, ops), /start outcome is unknown/u);
    const observedStartIntent = ops.states.get(
      `${value.plan.transaction.state_directory}/05-start-intent.json`,
    );
    const recoveryApproval = failedRecoveryApproval(
      value,
      observedStartIntent,
      ops.failedNetns,
    );
    mutate(recoveryApproval);
    ops.calls.length = 0;
    await assert.rejects(
      () => recoverFailedFixture(value, ops, recoveryApproval),
      /does not bind the durable approved start attempt/u,
    );
    assert.equal(ops.calls.some((call) => call[0] === "systemctl"), false);
    assert.equal(ops.lockHeld, true);
  }
});

test("failed-start recovery never adopts inactive state without its exact reset intent", async () => {
  const value = fixture();
  const ops = fakeOps(value);
  ops.startStatus = 1;
  await assert.rejects(() => applyFixture(value, ops), /start outcome is unknown/u);
  const observedStartIntent = ops.states.get(
    `${value.plan.transaction.state_directory}/05-start-intent.json`,
  );
  const recoveryApproval = failedRecoveryApproval(
    value,
    observedStartIntent,
    ops.failedNetns,
  );
  ops.netns = inactive(NETNS_UNIT);
  ops.calls.length = 0;
  await assert.rejects(
    () => recoverFailedFixture(value, ops, recoveryApproval),
    /inactive state without its durable reset-failed intent/u,
  );
  assert.equal(ops.calls.some((call) => call[0] === "systemctl"), false);
  assert.equal(ops.lockHeld, true);
});

test("failed-start recovery proves no PID1 job and no topology before reset", async () => {
  for (const mutate of [
    (ops) => { ops.jobAbsent = false; },
    (ops) => { ops.networkAbsentOverride = false; },
  ]) {
    const value = fixture();
    const ops = fakeOps(value);
    ops.startStatus = 1;
    await assert.rejects(() => applyFixture(value, ops), /start outcome is unknown/u);
    const observedStartIntent = ops.states.get(
      `${value.plan.transaction.state_directory}/05-start-intent.json`,
    );
    const recoveryApproval = failedRecoveryApproval(
      value,
      observedStartIntent,
      ops.failedNetns,
    );
    mutate(ops);
    ops.calls.length = 0;
    await assert.rejects(
      () => recoverFailedFixture(value, ops, recoveryApproval),
      /pending publisher namespace systemd job|retained a publisher namespace nsfs path/u,
    );
    assert.equal(ops.calls.some((call) => call[0] === "systemctl"), false);
    assert.equal(ops.lockHeld, true);
  }
});

test("lost reset-failed response is completed from its durable intent without resetting twice", async () => {
  const value = fixture();
  const ops = fakeOps(value);
  ops.startStatus = 1;
  await assert.rejects(() => applyFixture(value, ops), /start outcome is unknown/u);
  const observedStartIntent = ops.states.get(
    `${value.plan.transaction.state_directory}/05-start-intent.json`,
  );
  const recoveryApproval = failedRecoveryApproval(
    value,
    observedStartIntent,
    ops.failedNetns,
  );
  ops.resetFailedError = new Error("systemctl reset-failed response lost");
  ops.calls.length = 0;
  await assert.rejects(
    () => recoverFailedFixture(value, ops, recoveryApproval),
    /reset-failed outcome is unknown; shared lifecycle lock retained.*response lost/us,
  );
  assert.equal(ops.netns.active_state, "inactive");
  assert.equal(ops.lockHeld, true);
  assert.equal(
    ops.calls.filter((call) => call[0] === "systemctl" && call[1] === "reset-failed").length,
    1,
  );
  ops.resetFailedError = null;
  ops.calls.length = 0;
  const receipt = await recoverFailedFixture(value, ops, recoveryApproval);
  assert.equal(receipt.outcome, "failed-start-recovered");
  assert.equal(ops.calls.some((call) => call[0] === "systemctl"), false);
  assert.equal(ops.lockHeld, false);
});

test("nonzero reset-failed accepts a fresh exact approval after expiry without replacing intent", async () => {
  const value = fixture();
  const ops = fakeOps(value);
  ops.startStatus = 1;
  await assert.rejects(() => applyFixture(value, ops), /start outcome is unknown/u);
  const observedStartIntent = ops.states.get(
    `${value.plan.transaction.state_directory}/05-start-intent.json`,
  );
  const recoveryApproval = failedRecoveryApproval(
    value,
    observedStartIntent,
    ops.failedNetns,
  );
  recoveryApproval.expires_at_utc = new Date((NOW + 1) * 1000)
    .toISOString().replace(".000Z", "Z");
  const firstApprovalSha256 = approvalDigest(recoveryApproval);
  ops.resetFailedStatus = 1;
  ops.calls.length = 0;
  await assert.rejects(
    () => recoverFailedFixture(value, ops, recoveryApproval),
    /reset-failed outcome is unknown; shared lifecycle lock retained.*returned nonzero/us,
  );
  assert.equal(ops.netns.active_state, "failed");
  assert.equal(ops.lockHeld, true);
  assert.equal(
    ops.states.has(`${value.plan.transaction.state_directory}/06-reset-failed-intent.json`),
    true,
  );
  assert.equal(
    [...ops.receipts.keys()].some((path) => path.endsWith(".failed-start-recovery.json")),
    false,
  );
  await assert.rejects(
    () => recoverFailedFixture(value, ops, recoveryApproval, NOW + 2),
    /not currently valid/u,
  );
  assert.equal(ops.lockHeld, true);
  ops.resetFailedStatus = 0;
  const freshApproval = failedRecoveryApproval(
    value,
    observedStartIntent,
    ops.failedNetns,
  );
  freshApproval.approved_at_utc = new Date((NOW + 1) * 1000)
    .toISOString().replace(".000Z", "Z");
  freshApproval.expires_at_utc = new Date((NOW + 302) * 1000)
    .toISOString().replace(".000Z", "Z");
  freshApproval.approved_by = "security-reviewer:fresh-failed-recovery-test-key-v1";
  const freshApprovalSha256 = approvalDigest(freshApproval);
  assert.notEqual(freshApprovalSha256, firstApprovalSha256);
  const receipt = await recoverFailedFixture(value, ops, freshApproval, NOW + 2);
  assert.equal(receipt.outcome, "failed-start-recovered");
  assert.equal(receipt.reset_intent_approval_sha256, firstApprovalSha256);
  assert.equal(receipt.approved_recovery_approval_sha256, freshApprovalSha256);
  assert.equal(ops.lockHeld, false);
});

test("failed-start recovery receipt replay accepts a fresh exact approval and never resets again", async () => {
  const value = fixture();
  const ops = fakeOps(value);
  ops.startStatus = 1;
  await assert.rejects(() => applyFixture(value, ops), /start outcome is unknown/u);
  const observedStartIntent = ops.states.get(
    `${value.plan.transaction.state_directory}/05-start-intent.json`,
  );
  const recoveryApproval = failedRecoveryApproval(
    value,
    observedStartIntent,
    ops.failedNetns,
  );
  const first = await recoverFailedFixture(value, ops, recoveryApproval);
  const replayApproval = structuredClone(recoveryApproval);
  replayApproval.approved_by = "security-reviewer:receipt-replay-test-key-v1";
  assert.notEqual(approvalDigest(replayApproval), approvalDigest(recoveryApproval));
  const terminalStatePath =
    `${value.plan.transaction.state_directory}/07-failed-start-recovered.json`;
  ops.states.delete(terminalStatePath);
  ops.calls.length = 0;
  const second = await recoverFailedFixture(value, ops, replayApproval);
  assert.equal(canonicalJson(second), canonicalJson(first));
  assert.equal(ops.states.has(terminalStatePath), true);
  assert.equal(ops.calls.some((call) => call[0] === "systemctl"), false);
  assert.equal(ops.lockHeld, false);
});

test("failed-start recovery receipt replay requires its durable reset intent", async () => {
  const value = fixture();
  const ops = fakeOps(value);
  ops.startStatus = 1;
  await assert.rejects(() => applyFixture(value, ops), /start outcome is unknown/u);
  const observedStartIntent = ops.states.get(
    `${value.plan.transaction.state_directory}/05-start-intent.json`,
  );
  const recoveryApproval = failedRecoveryApproval(
    value,
    observedStartIntent,
    ops.failedNetns,
  );
  await recoverFailedFixture(value, ops, recoveryApproval);
  ops.states.delete(`${value.plan.transaction.state_directory}/06-reset-failed-intent.json`);
  ops.calls.length = 0;
  await assert.rejects(
    () => recoverFailedFixture(value, ops, recoveryApproval),
    /no durable reset-failed intent/u,
  );
  assert.equal(ops.calls.some((call) => call[0] === "systemctl"), false);
  assert.equal(ops.lockHeld, true);
});

test("a durable start intent and its retained lock prevent an implicit start retry", async () => {
  const value = fixture();
  const ops = fakeOps(value);
  ops.startStatus = 1;
  await assert.rejects(() => applyFixture(value, ops), /start outcome is unknown/u);
  ops.startStatus = 0;
  await assert.rejects(
    () => applyFixture(value, ops),
    /lock held/u,
  );
  assert.equal(
    ops.calls.filter((call) => call[0] === "systemctl" && call[1] === "start").length,
    1,
  );
  assert.equal(ops.receipts.size, 0);
});

test("recover-commit releases a lost-start lock already in exact inactive terminal state", async () => {
  const value = fixture();
  const ops = fakeOps(value);
  ops.startStatus = 1;
  await assert.rejects(() => applyFixture(value, ops), /start outcome is unknown/u);
  ops.startStatus = 0;
  ops.netns = inactive(NETNS_UNIT);
  ops.calls.length = 0;
  await assert.rejects(
    () => applyFixture(value, ops, true),
    /proved the requested start did not commit/u,
  );
  assert.equal(ops.calls.some((call) => call[0] === "systemctl"), false);
  assert.equal(ops.receipts.size, 0);
  assert.equal(ops.lockHeld, false);
  assert.deepEqual(ops.calls.filter((call) => call[0] === "unitJobAbsent"), [
    ["unitJobAbsent", NETNS_UNIT],
    ["unitJobAbsent", NETNS_UNIT],
    ["unitJobAbsent", NETNS_UNIT],
  ]);
  assert.deepEqual(ops.calls.at(-1), ["unlock"]);
});

test("failed-start recovery retains the lock while a timed-out PID1 job remains pending", async () => {
  const value = fixture();
  const ops = fakeOps(value);
  ops.startError = new Error("systemctl start timed out");
  await assert.rejects(
    () => applyFixture(value, ops),
    /start outcome is unknown; shared lifecycle lock retained.*timed out/us,
  );
  ops.startError = null;
  const startIntent = ops.states.get(
    `${value.plan.transaction.state_directory}/05-start-intent.json`,
  );
  const recoveryApproval = failedRecoveryApproval(
    value,
    startIntent,
    ops.failedNetns,
  );
  ops.jobAbsent = false;
  ops.calls.length = 0;
  await assert.rejects(
    () => recoverFailedFixture(value, ops, recoveryApproval),
    /reset-failed outcome is unknown; shared lifecycle lock retained.*pending .*systemd job/us,
  );
  assert.equal(ops.lockHeld, true);
  assert.equal(ops.calls.some((call) => call[0] === "unlock"), false);
});

test("recover-commit retains the lock when an existing receipt is malformed", async () => {
  const value = fixture();
  const ops = fakeOps(value);
  ops.startStatus = 1;
  await assert.rejects(() => applyFixture(value, ops), /start outcome is unknown/u);
  const path = value.plan.transaction.receipt_path;
  ops.receipts.set(path, {
    bytes: Buffer.from("{\"truncated\":", "utf8"),
    snapshot: pin(path, "0400", "malformed receipt"),
  });
  ops.calls.length = 0;
  await assert.rejects(
    () => applyFixture(value, ops, true),
    /start outcome is unknown; shared lifecycle lock retained.*existing receipt has invalid JSON/us,
  );
  assert.equal(ops.lockHeld, true);
  assert.equal(ops.calls.some((call) => call[0] === "unlock"), false);
});

test("recover-commit terminalizes a start that activated after the caller timed out", async () => {
  const value = fixture();
  const ops = fakeOps(value);
  ops.startError = new Error("systemctl start timed out");
  ops.afterStart = () => { ops.netns = active(NETNS_UNIT, "d".repeat(32), "789"); };
  await assert.rejects(
    () => applyFixture(value, ops),
    /start outcome is unknown; shared lifecycle lock retained.*timed out/us,
  );
  assert.equal(ops.netns.active_state, "active");
  ops.startError = null;
  ops.calls.length = 0;
  const receipt = await applyFixture(value, ops, true);
  assert.equal(receipt.outcome, "committed");
  assert.equal(receipt.netns_unit.invocation_id, "d".repeat(32));
  assert.equal(ops.lockHeld, false);
  assert.equal(ops.calls.some((call) => call[0] === "systemctl"), false);
  assert.deepEqual(ops.calls.at(-1), ["unlock"]);
});

test("recover-commit retains the lock when late activation still has a PID1 job", async () => {
  const value = fixture();
  const ops = fakeOps(value);
  ops.startError = new Error("systemctl start timed out");
  ops.afterStart = () => { ops.netns = active(NETNS_UNIT, "d".repeat(32), "789"); };
  await assert.rejects(() => applyFixture(value, ops), /start outcome is unknown/u);
  ops.startError = null;
  ops.netns = inactive(NETNS_UNIT);
  ops.jobAbsent = false;
  ops.calls.length = 0;
  await assert.rejects(
    () => applyFixture(value, ops, true),
    /start outcome is unknown; shared lifecycle lock retained.*pending .*systemd job/us,
  );
  assert.equal(ops.receipts.size, 0);
  assert.equal(ops.lockHeld, true);
  assert.equal(ops.calls.some((call) => call[0] === "unlock"), false);
});

test("recover-commit retains the lock when a timed-out start activates late", async () => {
  const value = fixture();
  const ops = fakeOps(value);
  ops.startError = new Error("systemctl start timed out");
  await assert.rejects(() => applyFixture(value, ops), /start outcome is unknown/u);
  ops.startError = null;
  ops.netns = inactive(NETNS_UNIT);
  let absenceReads = 0;
  ops.beforeNetworkAbsent = () => {
    absenceReads += 1;
    if (absenceReads === 3) ops.netns = active(NETNS_UNIT, "c".repeat(32), "456");
  };
  ops.calls.length = 0;
  await assert.rejects(
    () => applyFixture(value, ops, true),
    /start outcome is unknown; shared lifecycle lock retained.*terminal failed-start recovery proof/us,
  );
  assert.equal(ops.netns.active_state, "active");
  assert.equal(ops.lockHeld, true);
  assert.equal(ops.calls.some((call) => call[0] === "unlock"), false);
});

test("recover-commit retains the lock on unit, network-absence or sentinel drift", async () => {
  for (const mutate of [
    (value, ops) => {
      const state = structuredClone(value.plan.preimage.netns_unit);
      state.need_daemon_reload = "yes";
      ops.netns = state;
    },
    (_value, ops) => { ops.networkAbsentOverride = false; },
    (value, ops) => {
      const sentinel = value.plan.activation_sentinels[0];
      const observed = ops.files.get(sentinel.path);
      observed.bytes = Buffer.from("drifted sentinel\n", "utf8");
    },
  ]) {
    const value = fixture();
    const ops = fakeOps(value);
    ops.startStatus = 1;
    await assert.rejects(() => applyFixture(value, ops), /start outcome is unknown/u);
    ops.startStatus = 0;
    mutate(value, ops);
    ops.calls.length = 0;
    await assert.rejects(
      () => applyFixture(value, ops, true),
      /start outcome is unknown; shared lifecycle lock retained/u,
    );
    assert.equal(ops.lockHeld, true);
    assert.equal(ops.calls.some((call) => call[0] === "unlock"), false);
  }
});

test("runtime accepts only the reviewed down, addressless kernel fallback tunnel subset", async () => {
  const value = fixture();
  const ops = fakeOps(value);
  const topology = topologyFixture(value.plan);
  topology.namespace.inert_interfaces = [{
    addresses: [], alias: "", index: 3, kind: "gre", name: "gre0", up: false,
  }];
  topology.namespace.interface_names.push("gre0");
  topology.namespace.interface_names.sort();
  ops.topology = topology;
  const receipt = await applyFixture(value, ops);
  assert.deepEqual(receipt.topology.namespace.inert_interfaces,
    topology.namespace.inert_interfaces);
});

test("runtime rejects active, addressed, aliased or wrong-kind fallback tunnel devices", async () => {
  for (const mutate of [
    (link) => { link.up = true; },
    (link) => { link.addresses = [{ family: "inet", local: "192.0.2.1", prefix_length: 32 }]; },
    (link) => { link.alias = "unreviewed"; },
    (link) => { link.kind = "wireguard"; },
  ]) {
    const value = fixture();
    const ops = fakeOps(value);
    const topology = topologyFixture(value.plan);
    const link = { addresses: [], alias: "", index: 3, kind: "gre", name: "gre0", up: false };
    mutate(link);
    topology.namespace.inert_interfaces = [link];
    topology.namespace.interface_names.push("gre0");
    topology.namespace.interface_names.sort();
    ops.topology = topology;
    await assert.rejects(() => applyFixture(value, ops), /non-inert kernel fallback/u);
    assert.equal(ops.receipts.size, 0);
  }
});

test("runtime interface, route and forwarding drift prevent commit", async () => {
  for (const mutate of [
    (topology) => topology.namespace.interface_names.push("eth9"),
    (topology) => { topology.routes.client_main[0].default = true; },
    (topology) => topology.routes.host_main.push(structuredClone(topology.routes.host_main[0])),
    (topology) => { topology.forwarding_sysctls["net.ipv4.ip_forward"] = 1; },
    (topology) => { topology.client.address = "10.203.0.3"; },
    (topology) => { topology.client.alias = topology.client.alias.replace(":client", ":host"); },
    (topology) => { topology.client.peer_index = 999; },
  ]) {
    const value = fixture();
    const ops = fakeOps(value);
    const topology = topologyFixture(value.plan);
    mutate(topology);
    ops.topology = topology;
    await assert.rejects(() => applyFixture(value, ops),
      /interface set|connected publisher subnet|default\/gateway\/NAT|forwarding|client drifted|veth pair/u);
    assert.equal(ops.receipts.size, 0);
  }
});

async function committedFixture() {
  const value = fixture();
  const ops = fakeOps(value);
  const receipt = await applyFixture(value, ops);
  const receiptBytes = ops.receipts.get(value.plan.transaction.receipt_path).bytes;
  const receiptSha256 = hash(receiptBytes);
  const rollbackApproval = {
    acknowledgements: [...ROLLBACK_ACKNOWLEDGEMENTS],
    approved_at_utc: new Date((NOW - 30) * 1000).toISOString().replace(".000Z", "Z"),
    approved_by: "security-reviewer:test-key-v1",
    ceremony_id: value.plan.ceremony_id,
    committed_receipt_sha256: receiptSha256,
    decision: "approve-stop-exact-publisher-netns",
    executor_sha256: value.plan.runtime.executor.sha256,
    expires_at_utc: new Date((NOW + 600) * 1000).toISOString().replace(".000Z", "Z"),
    kind: ROLLBACK_APPROVAL_KIND,
    launcher_manifest_sha256: value.plan.runtime.launcher_manifest.sha256,
    launcher_sha256: value.plan.runtime.launcher.sha256,
    plan_sha256: value.planSha256,
    schema_version: 2,
  };
  return { ops, receipt, receiptSha256, rollbackApproval, value };
}

async function rollbackFixture(committed, recover = false) {
  return executeRollback({
    approvedPlanSha256: committed.value.planSha256,
    approvedReceiptSha256: committed.receiptSha256,
    approvedRollbackApprovalSha256: approvalDigest(committed.rollbackApproval),
    nowUnix: NOW,
    ops: committed.ops,
    plan: committed.value.plan,
    recover,
    rollbackApproval: committed.rollbackApproval,
  });
}

test("separately approved rollback stops only the exact namespace unit", async () => {
  const committed = await committedFixture();
  committed.ops.calls.length = 0;
  const receipt = await rollbackFixture(committed);
  const rollbackApprovalSha256 = approvalDigest(committed.rollbackApproval);
  assert.equal(receipt.outcome, "rolled-back");
  assert.equal(receipt.stop_approval_sha256, rollbackApprovalSha256);
  assert.equal(receipt.approved_rollback_approval_sha256, rollbackApprovalSha256);
  assert.deepEqual(committed.ops.calls.filter((call) => call[0] === "systemctl"), [
    ["systemctl", "stop", NETNS_UNIT],
  ]);
  assert.deepEqual(receipt.caddy_after, committed.receipt.caddy_after);
  assert.equal(receipt.publisher_unit.active_state, "inactive");
});

test("rollback is idempotent after its durable receipt", async () => {
  const committed = await committedFixture();
  const first = await rollbackFixture(committed);
  const second = await rollbackFixture(committed);
  assert.equal(canonicalJson(second), canonicalJson(first));
  assert.equal(committed.ops.calls.filter((call) => call[0] === "systemctl" && call[1] === "stop").length, 1);
});

test("rollback refuses Caddy generation drift and receipt-binding drift", async () => {
  {
    const committed = await committedFixture();
    const changed = structuredClone(committed.ops.caddy);
    changed.unit.invocation_id = "d".repeat(32);
    committed.ops.caddy = changed;
    await assert.rejects(() => rollbackFixture(committed), /Caddy preimage changed|roll back the integrated/u);
    assert.equal(committed.ops.netns.active_state, "active");
  }
  {
    const committed = await committedFixture();
    committed.rollbackApproval.committed_receipt_sha256 = "e".repeat(64);
    await assert.rejects(() => rollbackFixture(committed), /does not bind/u);
    assert.equal(committed.ops.netns.active_state, "active");
  }
});

test("recover-rollback completes a lost stop response without another stop", async () => {
  const committed = await committedFixture();
  const stopApprovalSha256 = approvalDigest(committed.rollbackApproval);
  committed.ops.seedState("25-stop-intent.json", {
    approved_approval_sha256: stopApprovalSha256,
    approved_plan_sha256: committed.value.planSha256,
    ceremony_id: committed.value.plan.ceremony_id,
    committed_receipt_sha256: committed.receiptSha256,
    phase: "stop-intent",
    schema_version: 1,
  });
  committed.ops.netns = inactive(NETNS_UNIT);
  committed.rollbackApproval.approved_by = "security-reviewer:recovery-key-v1";
  committed.ops.calls.length = 0;
  const receipt = await rollbackFixture(committed, true);
  assert.equal(receipt.outcome, "rolled-back");
  assert.equal(receipt.stop_approval_sha256, stopApprovalSha256);
  assert.equal(
    receipt.approved_rollback_approval_sha256,
    approvalDigest(committed.rollbackApproval),
  );
  assert.equal(committed.ops.calls.some((call) => call[0] === "systemctl"), false);
  assert.deepEqual(committed.ops.calls[0], ["lock", true]);
});

test("recover-rollback never adopts an externally stopped namespace without its exact intent", async () => {
  {
    const committed = await committedFixture();
    committed.ops.netns = inactive(NETNS_UNIT);
    await assert.rejects(
      () => rollbackFixture(committed, true),
      /without the durable stop intent/u,
    );
    assert.equal(committed.ops.receipts.has(
      committed.value.plan.transaction.rollback_receipt_path), false);
  }
  {
    const committed = await committedFixture();
    committed.ops.seedState("25-stop-intent.json", {
      approved_approval_sha256: approvalDigest(committed.rollbackApproval),
      approved_plan_sha256: committed.value.planSha256,
      ceremony_id: committed.value.plan.ceremony_id,
      committed_receipt_sha256: "f".repeat(64),
      phase: "stop-intent",
      schema_version: 1,
    });
    committed.ops.netns = inactive(NETNS_UNIT);
    await assert.rejects(
      () => rollbackFixture(committed, true),
      /intent identity\/plan\/receipt binding drifted/u,
    );
    assert.equal(committed.ops.receipts.has(
      committed.value.plan.transaction.rollback_receipt_path), false);
  }
});

test("plain rollback never adopts an already-stopped namespace without explicit recovery", async () => {
  const committed = await committedFixture();
  committed.ops.netns = inactive(NETNS_UNIT);
  committed.ops.calls.length = 0;
  await assert.rejects(() => rollbackFixture(committed), /use recover-rollback/u);
  assert.equal(committed.ops.receipts.has(
    committed.value.plan.transaction.rollback_receipt_path), false);
  assert.equal(committed.ops.calls.some((call) => call[0] === "systemctl"), false);
});

test("rollback stop failure leaves the committed receipt authoritative and requires explicit recovery", async () => {
  const committed = await committedFixture();
  const stopApprovalSha256 = approvalDigest(committed.rollbackApproval);
  committed.ops.stopStatus = 1;
  await assert.rejects(() => rollbackFixture(committed), /unit stop failed/u);
  assert.equal(committed.ops.receipts.has(committed.value.plan.transaction.receipt_path), true);
  assert.equal(committed.ops.receipts.has(committed.value.plan.transaction.rollback_receipt_path), false);
  await assert.rejects(
    () => rollbackFixture(committed),
    /durable stop intent already exists/u,
  );
  committed.rollbackApproval.approved_by = "security-reviewer:retry-key-v1";
  committed.ops.stopStatus = 0;
  const recovered = await rollbackFixture(committed, true);
  assert.equal(recovered.stop_approval_sha256, stopApprovalSha256);
  assert.equal(
    recovered.approved_rollback_approval_sha256,
    approvalDigest(committed.rollbackApproval),
  );
  assert.equal(committed.ops.calls.filter(
    (call) => call[0] === "systemctl" && call[1] === "stop",
  ).length, 2);
});

test("a host boot or systemd identity drift during stop prevents rollback receipt publication", async () => {
  const committed = await committedFixture();
  committed.ops.afterStop = () => {
    const changed = structuredClone(committed.ops.host);
    changed.systemd_manager_start_ticks = "999999";
    committed.ops.host = changed;
  };
  await assert.rejects(
    () => rollbackFixture(committed),
    /host boot\/systemd identity changed during namespace stop/u,
  );
  assert.equal(committed.ops.netns.active_state, "inactive");
  assert.equal(committed.ops.receipts.has(
    committed.value.plan.transaction.rollback_receipt_path), false);
});

test("an installed input drift during stop prevents rollback receipt publication", async () => {
  const committed = await committedFixture();
  committed.ops.afterStop = () => {
    const policy = committed.value.plan.installed_files.find(
      (entry) => entry.id === "network-policy",
    );
    committed.ops.files.get(policy.pin.path).snapshot.inode = "999999";
  };
  await assert.rejects(
    () => rollbackFixture(committed),
    /installed file network-policy drifted/u,
  );
  assert.equal(committed.ops.netns.active_state, "inactive");
  assert.equal(committed.ops.receipts.has(
    committed.value.plan.transaction.rollback_receipt_path), false);
});

const ROOT_LINUX_LOCK_TEST = process.platform === "linux" && process.geteuid?.() === 0;
const DEAD_LOCK_OWNER = Object.freeze({
  ownerBootId: "32345678-1234-4234-9234-123456789abc",
  ownerPid: 999999,
  ownerProcessStartTicks: "1",
});

test("Linux explicit recovery converges every mkdir-to-owner publication crash window", {
  skip: !ROOT_LINUX_LOCK_TEST,
}, async () => {
  for (const crashPoint of [
    "after-lock-mkdir",
    "after-lock-owner-pending-fsync",
    "after-lock-owner-final-link",
  ]) {
    const parent = mkdtempSync(join(tmpdir(), "bpir-publisher-lock-create-crash-"));
    const lock = join(parent, "lifecycle.lock");
    const transactionId = `publisher-netns-apply:create-crash-${crashPoint}`;
    let injected = false;
    try {
      assert.throws(
        () => realFs.acquireLock(lock, {
          recoverStale: false,
          transactionId,
        }, {
          ...DEAD_LOCK_OWNER,
          checkpoint(name) {
            if (name === crashPoint) {
              injected = true;
              throw new Error(`injected lock crash at ${name}`);
            }
          },
        }),
        /injected lock crash/u,
      );
      assert.equal(injected, true);
      assert.throws(
        () => realFs.acquireLock(lock, { recoverStale: false, transactionId }),
        /EEXIST|file already exists/u,
      );

      const release = realFs.acquireLock(lock, { recoverStale: true, transactionId });
      assert.deepEqual(readdirSync(lock), ["owner.json"]);
      const owner = JSON.parse(readFileSync(join(lock, "owner.json"), "utf8"));
      assert.equal(owner.pid, process.pid);
      assert.equal(owner.transaction_id, transactionId);
      await release();
      assert.equal(existsSync(lock), false);
    } finally {
      rmSync(parent, { force: true, recursive: true });
    }
  }
});

test("Linux explicit recovery reclaims an exact partial pending owner after SIGKILL", {
  skip: !ROOT_LINUX_LOCK_TEST,
}, async () => {
  const parent = mkdtempSync(join(tmpdir(), "bpir-publisher-lock-partial-sigkill-"));
  const lock = join(parent, "lifecycle.lock");
  const transactionId = "publisher-netns-apply:partial-sigkill";
  try {
    const child = spawnSync(
      process.execPath,
      [
        "--input-type=module",
        "--eval",
        `import { writeSync } from "node:fs";
const { PUBLISHER_NETNS_CEREMONY_TEST_ONLY_IO: io } = await import(${JSON.stringify(CEREMONY_MODULE_URL)});
io.acquireLock(process.argv[1], {
  recoverStale: false,
  transactionId: process.argv[2],
}, {
  lockOwnerWriter(fd, bytes, offset, remaining, position) {
    const written = writeSync(fd, bytes, offset, Math.max(1, Math.floor(remaining / 2)), position);
    process.kill(process.pid, "SIGKILL");
    return written;
  },
});`,
        lock,
        transactionId,
      ],
      { encoding: "utf8", timeout: 10_000 },
    );
    assert.equal(child.status, null, child.stderr);
    assert.equal(child.signal, "SIGKILL");
    assert.deepEqual(readdirSync(lock), ["owner.json.pending"]);
    const partial = readFileSync(join(lock, "owner.json.pending"), "utf8");
    assert.equal(partial.length > 0, true);
    assert.equal(partial.endsWith("}"), false);

    const release = realFs.acquireLock(lock, { recoverStale: true, transactionId });
    assert.deepEqual(readdirSync(lock), ["owner.json"]);
    const owner = JSON.parse(readFileSync(join(lock, "owner.json"), "utf8"));
    assert.equal(owner.pid, process.pid);
    assert.equal(owner.transaction_id, transactionId);
    await release();
    assert.equal(existsSync(lock), false);
  } finally {
    rmSync(parent, { force: true, recursive: true });
  }
});

test("Linux malformed-pending recovery rejects deletion-adjacent generation drift", {
  skip: !ROOT_LINUX_LOCK_TEST,
}, () => {
  for (const [name, mutate, expectedEntries] of [
    ["content", (lock) => {
      writeFileSync(join(lock, "owner.json.pending"), '{"boot_id":"changed');
    }, ["owner.json.pending"]],
    ["inode", (lock) => {
      rmSync(join(lock, "owner.json.pending"), { force: true });
      writeFileSync(join(lock, "owner.json.pending"), '{"boot_id":', { mode: 0o400 });
    }, ["owner.json.pending"]],
    ["directory-entry", (lock) => {
      writeFileSync(join(lock, "unexpected-entry"), "drift", { mode: 0o400 });
    }, ["owner.json.pending", "unexpected-entry"]],
  ]) {
    const parent = mkdtempSync(join(tmpdir(), `bpir-publisher-lock-malformed-${name}-`));
    const lock = join(parent, "lifecycle.lock");
    const transactionId = `publisher-netns-apply:malformed-race-${name}`;
    try {
      mkdirSync(lock, { mode: 0o700 });
      writeFileSync(join(lock, "owner.json.pending"), '{"boot_id":', { mode: 0o400 });
      assert.throws(
        () => realFs.acquireLock(lock, { recoverStale: true, transactionId }, {
          checkpoint(checkpoint) {
            if (checkpoint === "before-malformed-pending-delete") mutate(lock);
          },
        }),
        /descriptor generation changed|inode, ctime, metadata, or content changed|directory generation changed|entries changed|unknown shape/u,
      );
      assert.deepEqual(readdirSync(lock), expectedEntries);
    } finally {
      rmSync(parent, { force: true, recursive: true });
    }
  }
});

test("Linux explicit recovery converges every stale-owner replacement crash window", {
  skip: !ROOT_LINUX_LOCK_TEST,
}, async () => {
  for (const crashPoint of [
    "after-lock-replacement-pending-fsync",
    "before-stale-owner-delete",
    "after-lock-replacement-owner-unlink",
    "after-lock-replacement-owner-link",
  ]) {
    const parent = mkdtempSync(join(tmpdir(), "bpir-publisher-lock-reclaim-crash-"));
    const lock = join(parent, "lifecycle.lock");
    const transactionId = `publisher-netns-apply:reclaim-crash-${crashPoint}`;
    try {
      realFs.acquireLock(lock, { recoverStale: false, transactionId }, DEAD_LOCK_OWNER);
      let injected = false;
      assert.throws(
        () => realFs.acquireLock(lock, { recoverStale: true, transactionId }, {
          ownerBootId: "42345678-1234-4234-9234-123456789abc",
          ownerPid: 999998,
          ownerProcessStartTicks: "2",
          checkpoint(name) {
            if (name === crashPoint) {
              injected = true;
              throw new Error(`injected stale replacement crash at ${name}`);
            }
          },
        }),
        /injected stale replacement crash/u,
      );
      assert.equal(injected, true);

      const release = realFs.acquireLock(lock, { recoverStale: true, transactionId });
      assert.deepEqual(readdirSync(lock), ["owner.json"]);
      const owner = JSON.parse(readFileSync(join(lock, "owner.json"), "utf8"));
      assert.equal(owner.pid, process.pid);
      assert.equal(owner.transaction_id, transactionId);
      await release();
      assert.equal(existsSync(lock), false);
    } finally {
      rmSync(parent, { force: true, recursive: true });
    }
  }
});

test("Linux stale reclaim revalidates the old descriptor generation and preserves a concurrent live lock", {
  skip: !ROOT_LINUX_LOCK_TEST,
}, async () => {
  const parent = mkdtempSync(join(tmpdir(), "bpir-publisher-lock-race-"));
  const lock = join(parent, "lifecycle.lock");
  const transactionId = "publisher-netns-apply:deterministic-race";
  let concurrentRelease = null;
  let raced = false;
  try {
    const staleRelease = realFs.acquireLock(
      lock,
      { recoverStale: false, transactionId },
      DEAD_LOCK_OWNER,
    );
    assert.throws(
      () => realFs.acquireLock(lock, { recoverStale: true, transactionId }, {
        checkpoint(name) {
          if (name === "after-stale-owner-validation" && !raced) {
            raced = true;
            concurrentRelease = realFs.acquireLock(lock, {
              recoverStale: true,
              transactionId,
            });
          }
        },
      }),
      /descriptor generation changed|record generation changed|directory generation changed/u,
    );
    assert.equal(raced, true);
    assert.equal(typeof concurrentRelease, "function");
    assert.deepEqual(readdirSync(lock), ["owner.json"]);
    const owner = JSON.parse(readFileSync(join(lock, "owner.json"), "utf8"));
    assert.equal(owner.pid, process.pid);
    assert.equal(owner.transaction_id, transactionId);
    await assert.rejects(
      () => staleRelease(),
      /transaction lock ownership changed/u,
    );
    assert.deepEqual(readdirSync(lock), ["owner.json"]);
    await concurrentRelease();
    assert.equal(existsSync(lock), false);
  } finally {
    rmSync(parent, { force: true, recursive: true });
  }
});

test("Linux crashed replacement normalization never deletes a concurrent completed live owner", {
  skip: !ROOT_LINUX_LOCK_TEST,
}, async () => {
  for (const [crashPoint, racePoint] of [
    [
      "after-lock-replacement-pending-fsync",
      "before-stale-replacement-pending-delete",
    ],
    [
      "after-lock-replacement-owner-link",
      "before-stale-linked-pending-delete",
    ],
  ]) {
    const parent = mkdtempSync(join(tmpdir(), "bpir-publisher-lock-normalize-race-"));
    const lock = join(parent, "lifecycle.lock");
    const transactionId = `publisher-netns-apply:normalize-race-${crashPoint}`;
    let concurrentRelease = null;
    let raced = false;
    try {
      realFs.acquireLock(lock, { recoverStale: false, transactionId }, DEAD_LOCK_OWNER);
      assert.throws(
        () => realFs.acquireLock(lock, { recoverStale: true, transactionId }, {
          ownerBootId: "42345678-1234-4234-9234-123456789abc",
          ownerPid: 999998,
          ownerProcessStartTicks: "2",
          checkpoint(name) {
            if (name === crashPoint) throw new Error(`injected normalize state at ${name}`);
          },
        }),
        /injected normalize state/u,
      );
      assert.throws(
        () => realFs.acquireLock(lock, { recoverStale: true, transactionId }, {
          checkpoint(name) {
            if (name === racePoint && !raced) {
              raced = true;
              concurrentRelease = realFs.acquireLock(lock, {
                recoverStale: true,
                transactionId,
              });
            }
          },
        }),
        /descriptor generation changed|record generation changed|directory generation changed|entries changed/u,
      );
      assert.equal(raced, true);
      assert.equal(typeof concurrentRelease, "function");
      assert.deepEqual(readdirSync(lock), ["owner.json"]);
      const owner = JSON.parse(readFileSync(join(lock, "owner.json"), "utf8"));
      assert.equal(owner.pid, process.pid);
      assert.equal(owner.transaction_id, transactionId);
      await concurrentRelease();
      assert.equal(existsSync(lock), false);
    } finally {
      rmSync(parent, { force: true, recursive: true });
    }
  }
});

test("Linux stale reclaim detects deletion-adjacent content, ctime, and directory-generation drift", {
  skip: !ROOT_LINUX_LOCK_TEST,
}, () => {
  for (const [name, mutate, expectedEntries] of [
    ["owner-content", (lock) => {
      const changed = {
        boot_id: DEAD_LOCK_OWNER.ownerBootId,
        pid: DEAD_LOCK_OWNER.ownerPid,
        process_start_ticks: "2",
        transaction_id: "publisher-netns-apply:deletion-adjacent-owner-content",
      };
      writeFileSync(join(lock, "owner.json"), canonicalJson(changed));
    }, ["owner.json"]],
    ["directory-entry", (lock) => {
      writeFileSync(join(lock, "unexpected-entry"), "drift", { mode: 0o400 });
    }, ["owner.json", "unexpected-entry"]],
  ]) {
    const parent = mkdtempSync(join(tmpdir(), `bpir-publisher-lock-${name}-`));
    const lock = join(parent, "lifecycle.lock");
    const transactionId = `publisher-netns-apply:deletion-adjacent-${name}`;
    try {
      realFs.acquireLock(lock, { recoverStale: false, transactionId }, DEAD_LOCK_OWNER);
      assert.throws(
        () => realFs.acquireLock(lock, { recoverStale: true, transactionId }, {
          checkpoint(checkpoint) {
            if (checkpoint === "before-stale-owner-delete") mutate(lock);
          },
        }),
        /descriptor generation changed|inode, ctime, metadata, or content changed|directory generation changed|entries changed|unknown shape/u,
      );
      assert.deepEqual(readdirSync(lock), expectedEntries);
      assert.equal(existsSync(join(lock, "owner.json.pending")), false);
    } finally {
      rmSync(parent, { force: true, recursive: true });
    }
  }
});

test("Linux recovery refuses a live pending-only owner publication", {
  skip: !ROOT_LINUX_LOCK_TEST,
}, () => {
  const parent = mkdtempSync(join(tmpdir(), "bpir-publisher-lock-live-pending-"));
  const lock = join(parent, "lifecycle.lock");
  const transactionId = "publisher-netns-apply:live-pending";
  try {
    assert.throws(
      () => realFs.acquireLock(lock, { recoverStale: false, transactionId }, {
        checkpoint(name) {
          if (name === "after-lock-owner-pending-fsync") {
            throw new Error("injected live pending crash");
          }
        },
      }),
      /injected live pending crash/u,
    );
    assert.deepEqual(readdirSync(lock), ["owner.json.pending"]);
    assert.throws(
      () => realFs.acquireLock(lock, { recoverStale: true, transactionId }),
      /publication is held by a live process generation/u,
    );
    assert.deepEqual(readdirSync(lock), ["owner.json.pending"]);
  } finally {
    rmSync(parent, { force: true, recursive: true });
  }
});

test("Linux recovery never adopts a pending owner from another transaction", {
  skip: !ROOT_LINUX_LOCK_TEST,
}, () => {
  const parent = mkdtempSync(join(tmpdir(), "bpir-publisher-lock-foreign-pending-"));
  const lock = join(parent, "lifecycle.lock");
  const originalTransaction = "publisher-netns-apply:original-pending";
  try {
    assert.throws(
      () => realFs.acquireLock(lock, {
        recoverStale: false,
        transactionId: originalTransaction,
      }, {
        ...DEAD_LOCK_OWNER,
        checkpoint(name) {
          if (name === "after-lock-owner-pending-fsync") {
            throw new Error("injected foreign pending crash");
          }
        },
      }),
      /injected foreign pending crash/u,
    );
    const before = readFileSync(join(lock, "owner.json.pending"));
    assert.throws(
      () => realFs.acquireLock(lock, {
        recoverStale: true,
        transactionId: "publisher-netns-rollback:foreign-pending",
      }),
      /different transaction/u,
    );
    assert.deepEqual(readdirSync(lock), ["owner.json.pending"]);
    assert.equal(readFileSync(join(lock, "owner.json.pending")).equals(before), true);
  } finally {
    rmSync(parent, { force: true, recursive: true });
  }
});

test("Linux executes the exact descriptor-approved command inode and rejects a pin drift", {
  skip: process.platform !== "linux" || process.geteuid?.() !== 0,
}, () => {
  const printfPath = "/usr/bin/printf";
  const pinValue = realFs.readRegular(printfPath).snapshot;
  const result = realFs.runPinnedBinary(pinValue, ["descriptor-ok\\n"]);
  assert.equal(result.status, 0);
  assert.equal(result.stderr.length, 0);
  assert.equal(result.stdout.toString("utf8"), "descriptor-ok\n");
  const drifted = structuredClone(pinValue);
  drifted.sha256 = "f".repeat(64);
  assert.throws(() => realFs.runPinnedBinary(drifted, ["must-not-run"]), /drifted before invocation/u);
});

test("Linux root-only receipt publication reconciles both durable pending crash windows", {
  skip: process.platform !== "linux" || process.geteuid?.() !== 0,
}, () => {
  const directory = mkdtempSync(join(tmpdir(), "bpir-publisher-netns-ceremony-"));
  chmodSync(directory, 0o700);
  try {
    const value = { kind: "receipt-test", schema_version: 1 };
    const bytes = Buffer.from(canonicalJson(value), "utf8");

    const pendingOnly = join(directory, "pending-only.json");
    writeFileSync(`${pendingOnly}.pending`, bytes, { mode: 0o400 });
    const recoveredPending = realFs.writeAtomicNoReplace(pendingOnly, value);
    assert.equal(recoveredPending.snapshot.nlink, 1);
    assert.equal(existsSync(`${pendingOnly}.pending`), false);
    assert.equal(readFileSync(pendingOnly).equals(bytes), true);

    const linkedFinal = join(directory, "linked-final.json");
    writeFileSync(`${linkedFinal}.pending`, bytes, { mode: 0o400 });
    linkSync(`${linkedFinal}.pending`, linkedFinal);
    const recoveredLink = realFs.writeAtomicNoReplace(linkedFinal, value);
    assert.equal(recoveredLink.snapshot.nlink, 1);
    assert.equal(existsSync(`${linkedFinal}.pending`), false);
    assert.equal(readFileSync(linkedFinal).equals(bytes), true);

    const contradictory = join(directory, "contradictory.json");
    writeFileSync(`${contradictory}.pending`, "wrong", { mode: 0o400 });
    assert.throws(
      () => realFs.writeAtomicNoReplace(contradictory, value),
      /unreviewed owner\/content\/link shape/u,
    );
    assert.equal(existsSync(contradictory), false);
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
});

test("privileged Linux reuses the pinned iproute2 descriptor inside the network namespace", {
  skip: process.platform !== "linux" || process.geteuid?.() !== 0 ||
    !existsSync("/usr/bin/ip"),
}, (context) => {
  const namespace = `bpir-ceremony-${process.pid}`;
  try {
    execFileSync("/usr/bin/ip", ["netns", "add", namespace], { stdio: "pipe" });
  } catch (error) {
    context.skip(`container lacks network-namespace privilege: ${error.message}`);
    return;
  }
  try {
    const ipPin = realFs.readRegular("/usr/bin/ip").snapshot;
    const result = realFs.runPinnedBinary(ipPin, [
      "netns", "exec", namespace, "/proc/self/fd/3", "-j", "link", "show",
    ]);
    assert.equal(result.status, 0);
    assert.equal(result.stderr.length, 0);
    const links = JSON.parse(result.stdout.toString("utf8"));
    assert.equal(links.some((link) => link.ifname === "lo"), true);
  } finally {
    execFileSync("/usr/bin/ip", ["netns", "delete", namespace], { stdio: "pipe" });
  }
});
