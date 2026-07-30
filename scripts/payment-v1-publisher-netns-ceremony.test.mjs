import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  linkSync,
  mkdtempSync,
  readFileSync,
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
  PUBLISHER_NETNS_CEREMONY_TEST_ONLY_IO as realFs,
  ROLLBACK_ACKNOWLEDGEMENTS,
  ROLLBACK_APPROVAL_KIND,
  computePlanSha256,
  executeApply,
  executeRollback,
  validateCeremonyPlan,
  validatePrivatePairV1,
} from "./payment-v1-publisher-netns-ceremony.mjs";

const NETNS_UNIT = "bitcoinpir-payment-v1-publisher-netns.service";
const PUBLISHER_UNIT = "bitcoinpir-payment-v1-directory-publisher.service";
const CADDY_UNIT = "bhtm-caddy.service";
const NOW = 1_788_000_000;

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
  const plan = {
    activation_sentinels: sentinelPaths.map((path) => pin(path, "0400", basenameFor(path))),
    caddy_preimage: caddy,
    ceremony_id: ceremonyId,
    firewall_evidence: firewallPin,
    host: {
      boot_id: "01234567-89ab-cdef-0123-456789abcdef",
      machine_id_sha256: hash("machine-id"),
      systemd_version: "systemd 255 (255.4-1ubuntu8.10)",
    },
    installed_files: installedFiles,
    kind: CEREMONY_KIND,
    preimage: {
      host_interface: "absent",
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
    runtime: {
      executor: pin(
        "/usr/local/libexec/bitcoinpir/payment-v1-publisher-netns-ceremony.mjs", "0555",
        "executor"),
      integrated_caddy_gate: pin(
        "/usr/local/libexec/bitcoinpir/payment-v1-integrated-caddy-overlay-gate.mjs",
        "0555",
        "integrated-caddy-gate",
      ),
      ip: pin("/usr/bin/ip", "0755", "ip"),
      node: pin("/usr/bin/node", "0755", "node"),
      publisher_netns_gate: pin(
        "/usr/local/libexec/bitcoinpir/payment-v1-publisher-netns-gate.mjs",
        "0555",
        "publisher-netns-gate",
      ),
      systemctl: pin("/usr/bin/systemctl", "0755", "systemctl"),
    },
    schema_version: 1,
    source_commit: "8".repeat(40),
    topology,
    transaction: {
      lock_path: "/run/bitcoinpir-payment-v1-publisher-netns-ceremony.lock",
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
    plan_sha256: planSha256,
    schema_version: 1,
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
      bytes: Buffer.from(`${name}\n`, "utf8"),
      snapshot: structuredClone(runtimePin),
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
  let publisher = structuredClone(plan.preimage.publisher_unit);
  let caddy = structuredClone(plan.caddy_preimage);
  let host = structuredClone(plan.host);
  let topology = topologyFixture(plan);
  const calls = [];
  let startStatus = 0;
  let stopStatus = 0;
  let afterStart = () => {};
  let afterStop = () => {};
  let beforeUnitState = () => {};
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
      states.set(key, stateObservation(key, value));
    },
    get caddy() { return caddy; },
    set caddy(value) { caddy = structuredClone(value); },
    get host() { return host; },
    set host(value) { host = structuredClone(value); },
    get netns() { return netns; },
    set netns(value) { netns = structuredClone(value); },
    get publisher() { return publisher; },
    set publisher(value) { publisher = structuredClone(value); },
    set startStatus(value) { startStatus = value; },
    set stopStatus(value) { stopStatus = value; },
    set afterStart(value) { afterStart = value; },
    set afterStop(value) { afterStop = value; },
    set beforeUnitState(value) { beforeUnitState = value; },
    set topology(value) { topology = structuredClone(value); },
    async acquireLock(_path, { recoverStale }) {
      calls.push(["lock", recoverStale]);
      if (lockHeld && !recoverStale) throw new Error("lock held");
      lockHeld = true;
      return async () => { calls.push(["unlock"]); lockHeld = false; };
    },
    async caddyState() { return structuredClone(caddy); },
    async hostIdentity() { return structuredClone(host); },
    async networkAbsent() { return netns.active_state === "inactive"; },
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
      if (args[0] === "start" && startStatus === 0) {
        netns = active(NETNS_UNIT);
        afterStart();
      }
      if (args[0] === "stop" && stopStatus === 0) {
        netns = inactive(NETNS_UNIT);
        afterStop();
      }
      return { status: args[0] === "start" ? startStatus : stopStatus };
    },
    async unitState(name) {
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

test("closed publisher namespace ceremony plan validates", () => {
  const value = fixture();
  assert.equal(validateCeremonyPlan(value.plan), true);
  assert.equal(computePlanSha256(value.plan), value.planSha256);
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
    /namespace preimage changed during apply preflight/u,
  );
  assert.equal(ops.calls.some((call) => call[0] === "systemctl"), false);
  assert.equal(ops.receipts.size, 0);
});

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
      '"point_in_time_evidence_only": true',
      '"point_in_time_evidence_only": false',
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

test("failed systemctl start publishes no receipt and never touches Caddy", async () => {
  const value = fixture();
  const ops = fakeOps(value);
  ops.startStatus = 1;
  await assert.rejects(() => applyFixture(value, ops), /unit start failed/u);
  assert.equal(ops.receipts.size, 0);
  assert.deepEqual(ops.caddy, value.plan.caddy_preimage);
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
    plan_sha256: value.planSha256,
    schema_version: 1,
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
