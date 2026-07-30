#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  closeSync,
  constants,
  fchmodSync,
  fchownSync,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  rmdirSync,
  statfsSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { isIP } from "node:net";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  canonicalJson,
  parseStrictJson,
} from "./payment-v1-integrated-caddy-overlay-gate.mjs";
import {
  validatePublisherCaddyDropIn,
  validatePublisherFirewallOutputs,
  validatePublisherNamespaceOwnerUnitV1,
  validatePublisherNetworkPolicy,
} from "./payment-v1-publisher-netns-gate.mjs";

export const CEREMONY_KIND = "bitcoinpir-payment-v1-publisher-netns-ceremony-v1";
export const APPLY_APPROVAL_KIND =
  "bitcoinpir-payment-v1-publisher-netns-apply-approval-v1";
export const ROLLBACK_APPROVAL_KIND =
  "bitcoinpir-payment-v1-publisher-netns-rollback-approval-v1";
export const RECEIPT_KIND = "bitcoinpir-payment-v1-publisher-netns-receipt-v1";
export const ROLLBACK_RECEIPT_KIND =
  "bitcoinpir-payment-v1-publisher-netns-rollback-receipt-v1";

const NETNS_UNIT = "bitcoinpir-payment-v1-publisher-netns.service";
const PUBLISHER_UNIT = "bitcoinpir-payment-v1-directory-publisher.service";
const CADDY_UNIT = "bhtm-caddy.service";
const CADDY_NETNS_DROP_IN =
  "/etc/systemd/system/bhtm-caddy.service.d/bitcoinpir-publisher-netns.conf";
const MAX_JSON_BYTES = 8 * 1024 * 1024;
const MAX_COMMAND_BYTES = 8 * 1024 * 1024;
const MAX_APPROVAL_WINDOW_SECONDS = 60 * 60;
const MAX_CLOCK_SKEW_SECONDS = 300;
const LOCK_OWNER = "owner.json";
const STATE_FILENAMES = Object.freeze([
  "00-prepared.json",
  "05-start-intent.json",
  "10-runtime-verified.json",
  "20-committed.json",
  "25-stop-intent.json",
  "30-rolled-back.json",
]);

export const APPLY_ACKNOWLEDGEMENTS = Object.freeze([
  "only-the-exact-publisher-network-namespace-unit-will-be-started",
  "caddy-source-fair-publisher-and-payment-services-will-not-be-started-stopped-or-reloaded",
  "no-activation-sentinel-firewall-rule-route-nat-forwarding-or-publication-will-be-created",
  "the-directory-publisher-private-key-must-remain-off-host-and-only-frozen-signed-public-artifacts-may-be-published",
]);

export const ROLLBACK_ACKNOWLEDGEMENTS = Object.freeze([
  "only-the-exact-publisher-network-namespace-unit-will-be-stopped",
  "rollback-is-forbidden-after-the-caddy-preimage-or-publisher-service-generation-changes",
  "caddy-source-fair-publisher-and-payment-services-will-not-be-started-stopped-or-reloaded",
  "installed-files-activation-sentinels-firewall-rules-and-signed-public-artifacts-will-not-be-removed",
]);

const EXPECTED_SENTINELS = Object.freeze([
  "/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
  "/etc/bitcoinpir/payment-v1/EDGE-ACTIVATION-APPROVED",
  "/etc/bitcoinpir/payment-v1/SOURCE-FAIR-PREFLIGHT-APPROVED",
  "/etc/bitcoinpir/payment-v1/DIRECTORY-PUBLISHER-PRIVATE-INGRESS-APPROVED",
  "/etc/bitcoinpir/payment-v1/PUBLISHER-NETNS-ACTIVATION-APPROVED",
]);

const EXPECTED_FILE_IDS = Object.freeze([
  "caddy-netns-dropin",
  "directory-publisher-unit",
  "helper-binary",
  "helper-manifest",
  "netns-hosts",
  "netns-nsswitch",
  "netns-resolv",
  "network-inputs-manifest",
  "network-policy",
  "publisher-netns-unit",
]);

const INERT_KERNEL_LINK_KINDS = Object.freeze({
  erspan0: "erspan",
  gre0: "gre",
  gretap0: "gretap",
  ip6_vti0: "vti6",
  ip6gre0: "ip6gre",
  ip6tnl0: "ip6tnl",
  ip_vti0: "vti",
  sit0: "sit",
  tunl0: "ipip",
});

function fail(message) {
  throw new Error(`publisher-netns-ceremony: ${message}`);
}

function exactKeys(value, expected, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (canonicalJson(actual) !== canonicalJson(wanted)) {
    fail(`${label} keys drifted: expected ${canonicalJson(wanted)}, got ${canonicalJson(actual)}`);
  }
}

function exactArray(actual, expected, label) {
  if (canonicalJson(actual) !== canonicalJson(expected)) fail(`${label} drifted`);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function validateSha256(value, label) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) {
    fail(`${label} must be 64 lowercase hexadecimal characters`);
  }
}

function validateDecimal(value, label, { nonzero = false } = {}) {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]*)$/u.test(value)) {
    fail(`${label} must be canonical unsigned decimal text`);
  }
  if (nonzero && value === "0") fail(`${label} must be non-zero`);
}

function validateSlug(value, label) {
  if (typeof value !== "string" || !/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/u.test(value)) {
    fail(`${label} must be a 1..64 byte lowercase slug`);
  }
}

function validateCanonicalAbsolute(path, label) {
  if (
    typeof path !== "string" ||
    path.length < 2 ||
    path.length > 4096 ||
    !path.startsWith("/") ||
    path.includes("\0") ||
    path.includes("//") ||
    path.split("/").some((part) => part === "." || part === "..") ||
    resolve(path) !== path
  ) {
    fail(`${label} must be one canonical absolute path`);
  }
}

function validateInterfaceName(value, label) {
  if (typeof value !== "string" || value.length < 1 || value.length > 15 ||
      !/^[a-z][a-z0-9_-]*$/u.test(value)) {
    fail(`${label} must be a 1..15 byte lowercase Linux interface name`);
  }
}

function parseIpv4(value, label) {
  if (isIP(value) !== 4 || !/^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){3}$/u.test(value)) {
    fail(`${label} must be canonical dotted-decimal IPv4`);
  }
  const octets = value.split(".").map(Number);
  if (octets.some((part) => part > 255)) fail(`${label} has an out-of-range octet`);
  return octets.reduce((sum, part) => (sum << 8n) | BigInt(part), 0n);
}

function parseIpv6(value, label) {
  if (isIP(value) !== 6 || value !== value.toLowerCase() || value.includes("%") ||
      /(?:^|:)0[0-9a-f]+/u.test(value)) {
    fail(`${label} must be canonical lowercase IPv6 without a zone identifier`);
  }
  const halves = value.split("::");
  if (halves.length > 2) fail(`${label} has more than one compression marker`);
  const left = halves[0] === "" ? [] : halves[0].split(":");
  const right = halves.length === 1 || halves[1] === "" ? [] : halves[1].split(":");
  if (left.concat(right).some((part) => !/^[0-9a-f]{1,4}$/u.test(part))) {
    fail(`${label} has a malformed hextet`);
  }
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) {
    fail(`${label} has the wrong hextet count`);
  }
  const words = [...left, ...Array(missing).fill("0"), ...right].map((part) => BigInt(`0x${part}`));
  return words.reduce((sum, part) => (sum << 16n) | part, 0n);
}

function privateIp(value, label) {
  const family = isIP(value);
  if (family === 4) {
    const address = parseIpv4(value, label);
    const first = Number(address >> 24n);
    const second = Number((address >> 16n) & 255n);
    const privateV4 = first === 10 || (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && second === 168);
    if (!privateV4) fail(`${label} must be RFC1918`);
    return { address, family: "ipv4" };
  }
  if (family === 6) {
    const address = parseIpv6(value, label);
    if ((address >> 121n) !== 0x7en) fail(`${label} must be RFC4193 ULA (fc00::/7)`);
    return { address, family: "ipv6" };
  }
  fail(`${label} must be RFC1918 IPv4 or RFC4193 ULA IPv6`);
}

export function validatePrivatePairV1({ client, family, host, prefixLength }) {
  const hostParsed = privateIp(host, "topology.host_address");
  const clientParsed = privateIp(client, "topology.client_address");
  if (hostParsed.family !== family || clientParsed.family !== family) {
    fail("topology addresses and declared family must match");
  }
  if (hostParsed.address === clientParsed.address) fail("host and client addresses must be distinct");
  const bits = family === "ipv4" ? 32 : 128;
  const expectedPrefix = family === "ipv4" ? 30 : 126;
  if (prefixLength !== expectedPrefix) {
    fail(`topology ${family} prefix_length must equal ${expectedPrefix}`);
  }
  const hostPartBits = BigInt(bits - prefixLength);
  if ((hostParsed.address >> hostPartBits) !== (clientParsed.address >> hostPartBits)) {
    fail("host and client addresses must share the exact point-to-point subnet");
  }
  const hostPartMask = (1n << hostPartBits) - 1n;
  const hostPart = hostParsed.address & hostPartMask;
  const clientPart = clientParsed.address & hostPartMask;
  if (!new Set([hostPart.toString(), clientPart.toString()]).has("1") ||
      !new Set([hostPart.toString(), clientPart.toString()]).has("2")) {
    fail("host and client must occupy the +1 and +2 point-to-point addresses");
  }
  return true;
}

function validateDnsHost(value, label) {
  if (typeof value !== "string" || value.length > 253 || value !== value.toLowerCase() ||
      value.endsWith(".") || value.split(".").length < 2 ||
      value.split(".").some((part) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(part))) {
    fail(`${label} must be a canonical lowercase DNS hostname`);
  }
}

function validateFilePin(value, label, { paths, modes, uid = 0, gid = 0 } = {}) {
  exactKeys(value, [
    "ctime_ns", "device", "gid", "inode", "mode", "mtime_ns", "nlink",
    "path", "sha256", "size", "uid",
  ], label);
  validateCanonicalAbsolute(value.path, `${label}.path`);
  if (paths !== undefined && !paths.includes(value.path)) fail(`${label}.path is not approved`);
  validateSha256(value.sha256, `${label}.sha256`);
  for (const key of ["device", "inode", "ctime_ns", "mtime_ns", "size"]) {
    validateDecimal(value[key], `${label}.${key}`, { nonzero: key === "inode" });
  }
  if (!Number.isSafeInteger(value.uid) || !Number.isSafeInteger(value.gid) ||
      !Number.isSafeInteger(value.nlink) || value.nlink !== 1 ||
      value.uid !== uid || value.gid !== gid || !modes.includes(value.mode)) {
    fail(`${label} owner, mode or single-link contract drifted`);
  }
}

function validateUnitState(value, label, { active, name }) {
  exactKeys(value, [
    "active_enter_timestamp_monotonic", "active_state", "invocation_id", "load_state",
    "main_pid", "name", "need_daemon_reload", "sub_state",
  ], label);
  if (value.name !== name) fail(`${label}.name drifted`);
  if (value.load_state !== "loaded") fail(`${label} must be loaded`);
  if (value.need_daemon_reload !== "no") fail(`${label} has an unsealed systemd generation`);
  validateDecimal(value.active_enter_timestamp_monotonic,
    `${label}.active_enter_timestamp_monotonic`);
  validateDecimal(value.main_pid, `${label}.main_pid`);
  if (active) {
    if (value.active_state !== "active" || value.sub_state !== "running" ||
        value.main_pid === "0" || !/^[0-9a-f]{32}$/u.test(value.invocation_id) ||
        /^0{32}$/u.test(value.invocation_id)) {
      fail(`${label} must be one live non-zero systemd generation`);
    }
  } else if (value.active_state !== "inactive" || value.sub_state !== "dead" ||
      value.main_pid !== "0" || !["", "0".repeat(32)].includes(value.invocation_id)) {
    fail(`${label} must be inactive/dead with no process generation`);
  }
}

function validateCaddyState(value, label) {
  exactKeys(value, ["config", "dependency", "unit"], label);
  validateFilePin(value.config, `${label}.config`, {
    paths: ["/etc/caddy/Caddyfile"], modes: ["0644"],
  });
  exactKeys(value.unit, [
    "active_enter_timestamp_monotonic", "active_state", "invocation_id", "load_state",
    "main_pid", "name", "need_daemon_reload", "sub_state",
  ], `${label}.unit`);
  if (value.unit.name !== CADDY_UNIT || value.unit.load_state !== "loaded") {
    fail(`${label}.unit must bind ${CADDY_UNIT}`);
  }
  if (value.unit.need_daemon_reload !== "no") {
    fail(`${label}.unit has an unsealed systemd generation`);
  }
  validateDecimal(value.unit.main_pid, `${label}.unit.main_pid`);
  validateDecimal(value.unit.active_enter_timestamp_monotonic,
    `${label}.unit.active_enter_timestamp_monotonic`);
  if (value.unit.active_state === "active") {
    if (value.unit.sub_state !== "running" || value.unit.main_pid === "0" ||
        !/^[0-9a-f]{32}$/u.test(value.unit.invocation_id) || /^0{32}$/u.test(value.unit.invocation_id)) {
      fail(`${label}.unit active generation is malformed`);
    }
  } else if (value.unit.active_state !== "inactive" || value.unit.sub_state !== "dead" ||
      value.unit.main_pid !== "0" || !["", "0".repeat(32)].includes(value.unit.invocation_id)) {
    fail(`${label}.unit must be active/running or inactive/dead`);
  }
  exactKeys(value.dependency, [
    "after_namespace_owner", "binds_to_namespace_owner", "drop_in_paths",
    "part_of_namespace_owner", "requires_namespace_owner",
    "wants_namespace_owner",
  ], `${label}.dependency`);
  if (
    value.dependency.after_namespace_owner !== true ||
    value.dependency.wants_namespace_owner !== true ||
    value.dependency.binds_to_namespace_owner !== false ||
    value.dependency.part_of_namespace_owner !== false ||
    value.dependency.requires_namespace_owner !== false ||
    canonicalJson(value.dependency.drop_in_paths) !==
      canonicalJson([CADDY_NETNS_DROP_IN])
  ) {
    fail(`${label}.dependency is not the exact loaded one-way namespace relation`);
  }
}

function validateTopology(value) {
  exactKeys(value, [
    "address_family", "client_address", "client_interface", "default_route",
    "forwarding", "host_address", "host_interface", "host_port", "hosts_path",
    "namespace_name", "namespace_path", "nat", "prefix_length", "publisher_hostname",
  ], "topology");
  validateInterfaceName(value.host_interface, "topology.host_interface");
  validateInterfaceName(value.client_interface, "topology.client_interface");
  if (value.host_interface === value.client_interface) fail("topology interfaces must be distinct");
  if (typeof value.namespace_name !== "string" || value.namespace_name.length > 32 ||
      !/^[a-z][a-z0-9_-]*$/u.test(value.namespace_name)) {
    fail("topology.namespace_name is malformed");
  }
  if (value.namespace_path !== `/run/netns/${value.namespace_name}` ||
      value.hosts_path !== `/etc/netns/${value.namespace_name}/hosts`) {
    fail("topology namespace and sealed hosts paths must derive from the exact namespace name");
  }
  validateCanonicalAbsolute(value.namespace_path, "topology.namespace_path");
  validateCanonicalAbsolute(value.hosts_path, "topology.hosts_path");
  validateDnsHost(value.publisher_hostname, "topology.publisher_hostname");
  validatePrivatePairV1({
    client: value.client_address,
    family: value.address_family,
    host: value.host_address,
    prefixLength: value.prefix_length,
  });
  if (value.default_route !== false || value.forwarding !== false || value.nat !== false ||
      value.host_port !== 443) {
    fail("topology must close default routing, forwarding and NAT and fix publisher port 443");
  }
  // The reviewed native helper is deliberately a single closed production
  // profile. The pair validator above also covers ULA for future separately
  // content-addressed helpers; this helper's constants remain exact RFC1918.
  if (canonicalJson(value) !== canonicalJson({
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
    publisher_hostname: value.publisher_hostname,
  })) {
    fail("topology does not equal the reviewed native-helper production profile");
  }
}

function expectedInstalledPaths(plan) {
  const helper = plan.installed_files.find((file) => file.id === "helper-binary")?.pin;
  const digest = helper?.sha256 ?? "invalid";
  return new Map([
    ["caddy-netns-dropin",
      "/etc/systemd/system/bhtm-caddy.service.d/bitcoinpir-publisher-netns.conf"],
    ["directory-publisher-unit",
      "/etc/systemd/system/bitcoinpir-payment-v1-directory-publisher.service"],
    ["helper-binary",
      `/opt/bitcoinpir/publisher-netns/${digest}/payment-v1-publisher-netns`],
    ["helper-manifest", "/etc/bitcoinpir/payment-v1/publisher-netns/helper.sha256"],
    ["netns-hosts", plan.topology.hosts_path],
    ["netns-nsswitch", `/etc/netns/${plan.topology.namespace_name}/nsswitch.conf`],
    ["netns-resolv", `/etc/netns/${plan.topology.namespace_name}/resolv.conf`],
    ["network-inputs-manifest",
      "/etc/bitcoinpir/payment-v1/directory-publisher/network-inputs.sha256"],
    ["network-policy",
      "/etc/bitcoinpir/payment-v1/directory-publisher/network-policy.json"],
    ["publisher-netns-unit",
      "/etc/systemd/system/bitcoinpir-payment-v1-publisher-netns.service"],
  ]);
}

function validateInstalledFiles(plan) {
  if (!Array.isArray(plan.installed_files) || plan.installed_files.length !== EXPECTED_FILE_IDS.length) {
    fail("installed_files must contain the exact closed publisher-network set");
  }
  exactArray(plan.installed_files.map((value) => value.id), EXPECTED_FILE_IDS,
    "installed_files canonical id order");
  const paths = expectedInstalledPaths(plan);
  for (const entry of plan.installed_files) {
    exactKeys(entry, ["id", "pin"], `installed_files.${entry.id}`);
    const binary = entry.id === "helper-binary";
    validateFilePin(entry.pin, `installed_files.${entry.id}.pin`, {
      paths: [paths.get(entry.id)], modes: binary ? ["0555"] :
        entry.id.endsWith("unit") || entry.id === "caddy-netns-dropin" ? ["0644"] : ["0444"],
    });
  }
  const helper = plan.installed_files.find((entry) => entry.id === "helper-binary").pin;
  if (helper.path.split("/").at(-2) !== helper.sha256) {
    fail("helper binary content-address directory must equal its SHA-256");
  }
}

function validateRuntime(value) {
  exactKeys(value, [
    "executor", "integrated_caddy_gate", "ip", "node",
    "publisher_netns_gate", "systemctl",
  ], "runtime");
  validateFilePin(value.executor, "runtime.executor", {
    paths: ["/usr/local/libexec/bitcoinpir/payment-v1-publisher-netns-ceremony.mjs"],
    modes: ["0555"],
  });
  validateFilePin(value.integrated_caddy_gate, "runtime.integrated_caddy_gate", {
    paths: [
      "/usr/local/libexec/bitcoinpir/payment-v1-integrated-caddy-overlay-gate.mjs",
    ],
    modes: ["0555"],
  });
  validateFilePin(value.publisher_netns_gate, "runtime.publisher_netns_gate", {
    paths: ["/usr/local/libexec/bitcoinpir/payment-v1-publisher-netns-gate.mjs"],
    modes: ["0555"],
  });
  validateFilePin(value.node, "runtime.node", {
    paths: ["/usr/bin/node"], modes: ["0555", "0755"],
  });
  validateFilePin(value.systemctl, "runtime.systemctl", {
    paths: ["/usr/bin/systemctl"], modes: ["0555", "0755"],
  });
  validateFilePin(value.ip, "runtime.ip", {
    paths: ["/usr/bin/ip"], modes: ["0555", "0755"],
  });
}

function validateTransaction(value, ceremonyId) {
  exactKeys(value, [
    "lock_path", "receipt_path", "rollback_receipt_path", "state_directory",
  ], "transaction");
  const root = "/var/lib/bitcoinpir/payment-v1/publisher-netns";
  const expected = {
    lock_path: "/run/bitcoinpir-payment-v1-publisher-netns-ceremony.lock",
    receipt_path: `${root}/receipts/${ceremonyId}.json`,
    rollback_receipt_path: `${root}/receipts/${ceremonyId}.rollback.json`,
    state_directory: `${root}/transactions/${ceremonyId}`,
  };
  if (canonicalJson(value) !== canonicalJson(expected)) fail("transaction paths drifted");
}

function expectedManifestBytes(plan, ids) {
  const entries = ids.map((id) => {
    const pin = plan.installed_files.find((entry) => entry.id === id)?.pin;
    if (pin === undefined) fail(`hash manifest references missing installed file ${id}`);
    return pin;
  }).sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
  return Buffer.from(
    entries.map((pin) => `${pin.sha256}  ${pin.path}\n`).join(""),
    "utf8",
  );
}

function rejectSecretSurface(plan) {
  if (plan.publisher_private_key_installed !== false) {
    fail("publisher_private_key_installed must be false");
  }
  const forbiddenName = /(?:^|[_-])(?:payment[_-]?preimage|payment[_-]?hash|invoice|cashu[_-]?proof|bearer[_-]?token)(?:$|[_-])/iu;
  const forbiddenPublisherKey = /(?:publisher|nostr)[_-]?(?:private|signing|secret)[_-]?(?:key|seed)/iu;
  const visit = (value, path = "plan") => {
    if (typeof value === "string") {
      if (/nsec1[023456789acdefghjklmnpqrstuvwxyz]{20,}/iu.test(value) ||
          forbiddenPublisherKey.test(value)) {
        fail(`${path} contains a forbidden publisher private-key value`);
      }
      return;
    }
    if (Array.isArray(value)) {
      value.forEach((entry, index) => visit(entry, `${path}[${index}]`));
      return;
    }
    if (value !== null && typeof value === "object") {
      for (const [key, entry] of Object.entries(value)) {
        if (path === "plan" && key === "publisher_private_key_installed") continue;
        if (forbiddenName.test(key) || forbiddenPublisherKey.test(key)) {
          fail(`${path}.${key} is a forbidden key/payment/query correlation field`);
        }
        visit(entry, `${path}.${key}`);
      }
    }
  };
  visit(plan);
}

export function validateCeremonyPlan(plan) {
  exactKeys(plan, [
    "activation_sentinels", "caddy_preimage", "ceremony_id", "firewall_evidence",
    "host", "installed_files", "kind", "preimage", "publisher_private_key_installed",
    "relationship", "runtime", "schema_version", "source_commit", "topology", "transaction",
  ], "plan");
  if (plan.schema_version !== 1 || plan.kind !== CEREMONY_KIND) fail("plan kind/schema drifted");
  validateSlug(plan.ceremony_id, "plan.ceremony_id");
  if (typeof plan.source_commit !== "string" || !/^[0-9a-f]{40}$/u.test(plan.source_commit)) {
    fail("plan.source_commit must be an exact lowercase Git commit");
  }
  validateTopology(plan.topology);
  validateInstalledFiles(plan);
  validateRuntime(plan.runtime);
  rejectSecretSurface(plan);
  if (!Array.isArray(plan.activation_sentinels) ||
      plan.activation_sentinels.length !== EXPECTED_SENTINELS.length) {
    fail("activation_sentinels must close the exact externally provisioned set");
  }
  exactArray(plan.activation_sentinels.map((pin) => pin.path), EXPECTED_SENTINELS,
    "activation_sentinels canonical path order");
  for (const [index, pin] of plan.activation_sentinels.entries()) {
    validateFilePin(pin, `activation_sentinels[${index}]`, {
      paths: [EXPECTED_SENTINELS[index]], modes: ["0400"],
    });
  }
  validateFilePin(plan.firewall_evidence, "firewall_evidence", {
    paths: ["/var/lib/bitcoinpir/payment-v1/publisher-netns/evidence/firewall.json"],
    modes: ["0400"],
  });
  exactKeys(plan.host, ["boot_id", "machine_id_sha256", "systemd_version"], "host");
  if (!/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u.test(plan.host.boot_id)) {
    fail("host.boot_id is malformed");
  }
  validateSha256(plan.host.machine_id_sha256, "host.machine_id_sha256");
  if (typeof plan.host.systemd_version !== "string" ||
      !/^systemd 255(?: \(255\.[0-9]+-[^)]+\))?$/u.test(plan.host.systemd_version)) {
    fail("host.systemd_version must be the exact reviewed systemd 255 line");
  }
  validateCaddyState(plan.caddy_preimage, "caddy_preimage");
  exactKeys(plan.preimage, ["namespace_path", "publisher_unit", "host_interface", "netns_unit"],
    "preimage");
  if (plan.preimage.namespace_path !== "absent" || plan.preimage.host_interface !== "absent") {
    fail("preimage namespace path and host interface must both be absent");
  }
  validateUnitState(plan.preimage.netns_unit, `preimage.${NETNS_UNIT}`, {
    active: false, name: NETNS_UNIT,
  });
  validateUnitState(plan.preimage.publisher_unit, `preimage.${PUBLISHER_UNIT}`, {
    active: false, name: PUBLISHER_UNIT,
  });
  exactKeys(plan.relationship, [
    "caddy_dependency", "integrated_profile", "network_before_caddy",
    "publisher_requires_namespace", "receipt_generation_scope", "reboot_recreation",
    "reverse_stop_propagation",
  ], "relationship");
  if (canonicalJson(plan.relationship) !== canonicalJson({
    caddy_dependency: "Wants+After",
    integrated_profile: "integrated-existing-bhtm-caddy-v1",
    network_before_caddy: true,
    publisher_requires_namespace: true,
    receipt_generation_scope: "exact-boot-and-systemd-generation",
    reboot_recreation: "caddy-wants-after-persistent-sentinels",
    reverse_stop_propagation: false,
  })) {
    fail("relationship does not equal the reviewed one-way Caddy ordering contract");
  }
  validateTransaction(plan.transaction, plan.ceremony_id);
  return true;
}

export function computePlanSha256(plan) {
  validateCeremonyPlan(plan);
  return sha256(Buffer.from(canonicalJson(plan), "utf8"));
}

function parseUtc(value, label) {
  if (typeof value !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u.test(value)) fail(`${label} must be whole-second UTC`);
  const millis = Date.parse(value);
  if (!Number.isSafeInteger(millis) || new Date(millis).toISOString() !== value.replace("Z", ".000Z")) {
    fail(`${label} is not canonical UTC`);
  }
  return Math.floor(millis / 1000);
}

function validateApprovalCommon(approval, plan, approvedPlanSha256, nowUnix, rollback) {
  const expectedKeys = rollback ? [
    "acknowledgements", "approved_at_utc", "approved_by", "ceremony_id",
    "committed_receipt_sha256", "decision", "executor_sha256", "expires_at_utc",
    "kind", "plan_sha256", "schema_version",
  ] : [
    "acknowledgements", "approved_at_utc", "approved_by", "ceremony_id", "decision",
    "executor_sha256", "expires_at_utc", "kind", "plan_sha256", "schema_version",
  ];
  exactKeys(approval, expectedKeys, rollback ? "rollback approval" : "apply approval");
  if (approval.schema_version !== 1 || approval.kind !==
      (rollback ? ROLLBACK_APPROVAL_KIND : APPLY_APPROVAL_KIND)) fail("approval kind/schema drifted");
  if (approval.ceremony_id !== plan.ceremony_id || approval.plan_sha256 !== approvedPlanSha256 ||
      approval.executor_sha256 !== plan.runtime.executor.sha256) fail("approval binding drifted");
  if (typeof approval.approved_by !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$/u.test(approval.approved_by)) {
    fail("approval approved_by identifier is malformed");
  }
  exactArray(approval.acknowledgements,
    rollback ? ROLLBACK_ACKNOWLEDGEMENTS : APPLY_ACKNOWLEDGEMENTS,
    "approval acknowledgements");
  const approved = parseUtc(approval.approved_at_utc, "approval.approved_at_utc");
  const expires = parseUtc(approval.expires_at_utc, "approval.expires_at_utc");
  if (expires <= approved || expires - approved > MAX_APPROVAL_WINDOW_SECONDS ||
      nowUnix < approved - MAX_CLOCK_SKEW_SECONDS || nowUnix > expires) {
    fail("approval is not currently valid within the one-hour window");
  }
  const decision = rollback ? "approve-stop-exact-publisher-netns" :
    "approve-start-exact-publisher-netns";
  if (approval.decision !== decision) fail("approval decision drifted");
  if (rollback) validateSha256(approval.committed_receipt_sha256,
    "rollback approval committed_receipt_sha256");
  return true;
}

function validateRuntimeTopology(value, plan) {
  exactKeys(value, [
    "client", "forwarding_sysctls", "host", "namespace", "routes",
  ], "runtime topology");
  exactKeys(value.namespace, [
    "device", "inert_interfaces", "inode", "interface_names", "loopback", "path", "type",
  ],
    "runtime topology.namespace");
  if (value.namespace.path !== plan.topology.namespace_path || value.namespace.type !== "nsfs") {
    fail("runtime namespace path/type drifted");
  }
  validateDecimal(value.namespace.device, "runtime namespace.device");
  validateDecimal(value.namespace.inode, "runtime namespace.inode", { nonzero: true });
  if (!Array.isArray(value.namespace.inert_interfaces) ||
      value.namespace.inert_interfaces.length > Object.keys(INERT_KERNEL_LINK_KINDS).length) {
    fail("runtime namespace inert interface set is malformed");
  }
  const inertNames = [];
  for (const [index, link] of value.namespace.inert_interfaces.entries()) {
    exactKeys(link, ["addresses", "alias", "index", "kind", "name", "up"],
      `runtime namespace.inert_interfaces[${index}]`);
    if (!(link.name in INERT_KERNEL_LINK_KINDS) ||
        link.kind !== INERT_KERNEL_LINK_KINDS[link.name] || link.alias !== "" ||
        link.up !== false || !Array.isArray(link.addresses) || link.addresses.length !== 0 ||
        !Number.isSafeInteger(link.index) || link.index < 1 || inertNames.includes(link.name)) {
      fail("runtime namespace contains a non-inert kernel fallback interface");
    }
    inertNames.push(link.name);
  }
  exactArray(inertNames, [...inertNames].sort(), "runtime namespace inert interface order");
  exactArray(value.namespace.interface_names,
    ["lo", plan.topology.client_interface, ...inertNames].sort(),
    "runtime namespace exact functional/inert interface set");
  exactKeys(value.namespace.loopback, ["addresses", "alias", "index", "up"],
    "runtime namespace.loopback");
  if (value.namespace.loopback.alias !== "" || value.namespace.loopback.up !== true ||
      !Number.isSafeInteger(value.namespace.loopback.index) || value.namespace.loopback.index < 1 ||
      canonicalJson(value.namespace.loopback.addresses) !== canonicalJson([{
        family: "inet", local: "127.0.0.1", prefix_length: 8,
      }])) {
    fail("runtime namespace loopback identity/address set drifted");
  }
  for (const side of ["host", "client"]) {
    exactKeys(value[side], [
      "address", "alias", "index", "interface", "mac", "peer_index", "prefix_length", "up",
    ],
      `runtime topology.${side}`);
    if (value[side].interface !== plan.topology[`${side}_interface`] ||
        value[side].address !== plan.topology[`${side}_address`] ||
        value[side].prefix_length !== plan.topology.prefix_length || value[side].up !== true ||
        !isLocalUnicastMac(value[side].mac) ||
        !Number.isSafeInteger(value[side].index) || value[side].index < 1 ||
        !Number.isSafeInteger(value[side].peer_index) || value[side].peer_index < 1) {
      fail(`runtime topology.${side} drifted`);
    }
  }
  const hostAlias = value.host.alias.match(
    /^bitcoinpir-payment-v1-publisher-netns:([0-9a-f]{32}):host$/u,
  );
  if (hostAlias === null || value.client.alias !==
      `bitcoinpir-payment-v1-publisher-netns:${hostAlias[1]}:client` ||
      value.host.index === value.client.index ||
      value.host.peer_index !== value.client.index ||
      value.client.peer_index !== value.host.index ||
      new Set([
        value.client.index, value.namespace.loopback.index,
        ...value.namespace.inert_interfaces.map((link) => link.index),
      ]).size !== value.namespace.inert_interfaces.length + 2) {
    fail("runtime veth pair identity drifted");
  }
  exactKeys(value.forwarding_sysctls,
    ["net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"], "runtime forwarding sysctls");
  if (value.forwarding_sysctls["net.ipv4.ip_forward"] !== 0 ||
      value.forwarding_sysctls["net.ipv6.conf.all.forwarding"] !== 0) {
    fail("host forwarding must remain disabled for both address families");
  }
  exactKeys(value.routes, ["client_main", "host_main"], "runtime routes");
  for (const key of ["client_main", "host_main"]) {
    if (!Array.isArray(value.routes[key]) || value.routes[key].length !== 1) {
      fail(`${key} must contain only the connected publisher subnet route`);
    }
    exactKeys(value.routes[key][0], ["default", "destination", "gateway", "nat"],
      `runtime routes.${key}[0]`);
    const route = value.routes[key][0];
    const expectedSubnet = plan.topology.address_family === "ipv4" ? "10.203.0.0/30" :
      "fd00::/126";
    if (route.default === true || route.gateway !== null || route.nat === true ||
        route.destination !== expectedSubnet) fail(`${key} contains a default/gateway/NAT route`);
  }
  return true;
}

function isLocalUnicastMac(value) {
  if (typeof value !== "string" || !/^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/u.test(value)) return false;
  return (Number.parseInt(value.slice(0, 2), 16) & 3) === 2;
}

function validateReceipt(receipt, plan, approvedPlanSha256) {
  exactKeys(receipt, [
    "activation_approval_sha256", "approved_approval_sha256", "approved_plan_sha256",
    "caddy_after", "caddy_before",
    "ceremony_id", "firewall_evidence_sha256", "host", "installed_files",
    "kind", "netns_unit", "outcome", "publisher_unit", "runtime", "schema_version",
    "sentinels", "topology",
  ], "receipt");
  if (receipt.schema_version !== 1 || receipt.kind !== RECEIPT_KIND ||
      receipt.ceremony_id !== plan.ceremony_id || receipt.approved_plan_sha256 !== approvedPlanSha256 ||
      receipt.outcome !== "committed") fail("receipt identity/outcome drifted");
  validateSha256(receipt.approved_approval_sha256, "receipt approved approval SHA-256");
  validateSha256(receipt.activation_approval_sha256, "receipt activation approval SHA-256");
  validateSha256(receipt.firewall_evidence_sha256, "receipt firewall evidence SHA-256");
  if (receipt.firewall_evidence_sha256 !== plan.firewall_evidence.sha256 ||
      canonicalJson(receipt.host) !== canonicalJson(plan.host) ||
      canonicalJson(receipt.caddy_before) !== canonicalJson(plan.caddy_preimage) ||
      canonicalJson(receipt.caddy_after) !== canonicalJson(plan.caddy_preimage) ||
      canonicalJson(receipt.installed_files) !== canonicalJson(plan.installed_files.map((entry) => entry.pin)) ||
      canonicalJson(receipt.runtime) !== canonicalJson(plan.runtime) ||
      canonicalJson(receipt.sentinels) !== canonicalJson(plan.activation_sentinels)) {
    fail("receipt closed input/runtime pins drifted");
  }
  validateUnitState(receipt.netns_unit, `receipt.${NETNS_UNIT}`, {
    active: true, name: NETNS_UNIT,
  });
  validateUnitState(receipt.publisher_unit, `receipt.${PUBLISHER_UNIT}`, {
    active: false, name: PUBLISHER_UNIT,
  });
  validateRuntimeTopology(receipt.topology, plan);
  return true;
}

function stateRecord(plan, approvedPlanSha256, approvedApprovalSha256, phase, extra = {}) {
  return {
    approved_approval_sha256: approvedApprovalSha256,
    approved_plan_sha256: approvedPlanSha256,
    ceremony_id: plan.ceremony_id,
    phase,
    schema_version: 1,
    ...extra,
  };
}

async function collectClosedInputs(plan, ops) {
  const installed = [];
  for (const entry of plan.installed_files) {
    const observed = await ops.readRegular(entry.pin.path);
    if (canonicalJson(observed.snapshot) !== canonicalJson(entry.pin)) {
      fail(`installed file ${entry.id} drifted`);
    }
    if (entry.id === "netns-hosts") {
      const expected = Buffer.from(
        `127.0.0.1 localhost\n${plan.topology.host_address} ${plan.topology.publisher_hostname}\n`,
        "utf8",
      );
      if (!observed.bytes.equals(expected)) fail("sealed namespace hosts bytes drifted");
    }
    if (entry.id === "netns-resolv" &&
        !observed.bytes.equals(Buffer.from("nameserver 127.0.0.1\noptions attempts:1 timeout:1\n", "utf8"))) {
      fail("sealed namespace resolver bytes drifted");
    }
    if (entry.id === "netns-nsswitch" && !observed.bytes.equals(Buffer.from(
      "passwd: files\ngroup: files\nhosts: files\nnetworks: files\n", "utf8"))) {
      fail("sealed namespace NSS bytes drifted");
    }
    if (entry.id === "helper-manifest" && !observed.bytes.equals(
      expectedManifestBytes(plan, ["helper-binary"]),
    )) {
      fail("publisher namespace helper manifest does not bind the exact helper pin");
    }
    if (entry.id === "network-inputs-manifest" && !observed.bytes.equals(
      expectedManifestBytes(plan, [
        "netns-hosts", "netns-nsswitch", "netns-resolv", "network-policy",
      ]),
    )) {
      fail("publisher network-input manifest does not bind the four exact input pins");
    }
    const text = observed.bytes.toString("utf8");
    if (entry.id === "caddy-netns-dropin") validatePublisherCaddyDropIn(text);
    if (entry.id === "publisher-netns-unit") validatePublisherNamespaceOwnerUnitV1(text);
    if (entry.id === "network-policy") {
      validatePublisherNetworkPolicy(text, plan.topology.publisher_hostname);
    }
    installed.push(observed.snapshot);
  }
  const runtime = {};
  for (const [name, pin] of Object.entries(plan.runtime)) {
    const observed = await ops.readRegular(pin.path);
    if (canonicalJson(observed.snapshot) !== canonicalJson(pin)) {
      fail(`runtime command ${name} drifted`);
    }
    runtime[name] = observed.snapshot;
  }
  const sentinels = [];
  for (const pin of plan.activation_sentinels) {
    const observed = await ops.readRegular(pin.path);
    if (canonicalJson(observed.snapshot) !== canonicalJson(pin)) fail(`sentinel ${pin.path} drifted`);
    sentinels.push(observed.snapshot);
  }
  const firewall = await ops.readRegular(plan.firewall_evidence.path);
  if (canonicalJson(firewall.snapshot) !== canonicalJson(plan.firewall_evidence)) {
    fail("publisher firewall evidence file drifted");
  }
  const parsed = parseStrictJson(firewall.bytes.toString("utf8"), "publisher firewall evidence");
  validatePublisherFirewallOutputs(parsed);
  return { installed, runtime, sentinels };
}

async function commonPreflight(plan, ops) {
  const host = await ops.hostIdentity();
  if (canonicalJson(host) !== canonicalJson(plan.host)) fail("host identity/systemd generation drifted");
  const caddy = await ops.caddyState();
  if (canonicalJson(caddy) !== canonicalJson(plan.caddy_preimage)) {
    fail("Caddy preimage changed; network ceremony must precede the integrated overlay");
  }
  const publisher = await ops.unitState(PUBLISHER_UNIT);
  if (canonicalJson(publisher) !== canonicalJson(plan.preimage.publisher_unit)) {
    fail("publisher service is not the exact inactive preimage");
  }
  const closed = await collectClosedInputs(plan, ops);
  return { caddy, closed, host, publisher };
}

async function buildCommittedReceipt({
  activationApprovalSha256,
  approvedApprovalSha256,
  approvedPlanSha256,
  before,
  ops,
  plan,
}) {
  const caddyAfter = await ops.caddyState();
  if (canonicalJson(caddyAfter) !== canonicalJson(before.caddy)) {
    fail("Caddy changed while provisioning the publisher namespace");
  }
  const publisher = await ops.unitState(PUBLISHER_UNIT);
  if (canonicalJson(publisher) !== canonicalJson(before.publisher)) {
    fail("publisher service changed during the network-only ceremony");
  }
  const netns = await ops.unitState(NETNS_UNIT);
  validateUnitState(netns, `runtime.${NETNS_UNIT}`, { active: true, name: NETNS_UNIT });
  const topology = await ops.networkState(plan);
  validateRuntimeTopology(topology, plan);
  const closedAfter = await collectClosedInputs(plan, ops);
  if (canonicalJson(closedAfter) !== canonicalJson(before.closed)) {
    fail("installed files, sentinels or firewall evidence changed during start");
  }
  const hostAfter = await ops.hostIdentity();
  if (canonicalJson(hostAfter) !== canonicalJson(before.host)) {
    fail("host boot/systemd identity changed during namespace start");
  }
  return {
    activation_approval_sha256: activationApprovalSha256,
    approved_approval_sha256: approvedApprovalSha256,
    approved_plan_sha256: approvedPlanSha256,
    caddy_after: caddyAfter,
    caddy_before: before.caddy,
    ceremony_id: plan.ceremony_id,
    firewall_evidence_sha256: plan.firewall_evidence.sha256,
    host: before.host,
    installed_files: closedAfter.installed,
    kind: RECEIPT_KIND,
    netns_unit: netns,
    outcome: "committed",
    publisher_unit: publisher,
    runtime: closedAfter.runtime,
    schema_version: 1,
    sentinels: closedAfter.sentinels,
    topology,
  };
}

async function applyLocked({ approvedApprovalSha256, approvedPlanSha256, ops, plan, recover }) {
  const existing = await ops.readOptionalRegular(plan.transaction.receipt_path);
  if (existing !== null) {
    const receipt = parseStrictJson(existing.bytes.toString("utf8"), "existing receipt");
    validateReceipt(receipt, plan, approvedPlanSha256);
    const before = await commonPreflight(plan, ops);
    const netns = await ops.unitState(NETNS_UNIT);
    if (canonicalJson(netns) !== canonicalJson(receipt.netns_unit)) {
      fail("committed receipt no longer describes the live namespace unit generation");
    }
    const topology = await ops.networkState(plan);
    if (canonicalJson(topology) !== canonicalJson(receipt.topology) ||
        canonicalJson(before.closed.installed) !== canonicalJson(receipt.installed_files) ||
        canonicalJson(before.closed.runtime) !== canonicalJson(receipt.runtime) ||
        canonicalJson(before.closed.sentinels) !== canonicalJson(receipt.sentinels)) {
      fail("committed receipt no longer describes the live closed topology/inputs");
    }
    await ops.writeState(plan.transaction.state_directory, "20-committed.json",
      stateRecord(plan, approvedPlanSha256, receipt.approved_approval_sha256, "committed", {
        receipt_sha256: sha256(existing.bytes),
      }));
    return receipt;
  }
  const current = await ops.unitState(NETNS_UNIT);
  if (canonicalJson(current) === canonicalJson(plan.preimage.netns_unit) &&
      !(await ops.networkAbsent(plan))) {
    fail("inactive namespace unit has an unknown namespace path or host-interface preimage");
  }
  if (canonicalJson(current) !== canonicalJson(plan.preimage.netns_unit) && !recover) {
    fail("publisher namespace is not the inactive preimage; use recover-commit for a lost start response");
  }
  const before = await commonPreflight(plan, ops);
  let started = false;
  let activationApprovalSha256 = approvedApprovalSha256;
  if (canonicalJson(current) === canonicalJson(plan.preimage.netns_unit)) {
    const finalPreStart = await ops.unitState(NETNS_UNIT);
    if (canonicalJson(finalPreStart) !== canonicalJson(plan.preimage.netns_unit) ||
        !(await ops.networkAbsent(plan))) {
      fail("publisher namespace preimage changed during apply preflight");
    }
    await ops.writeState(plan.transaction.state_directory, "00-prepared.json",
      stateRecord(plan, approvedPlanSha256, approvedApprovalSha256, "prepared"));
    await ops.writeState(plan.transaction.state_directory, "05-start-intent.json",
      stateRecord(plan, approvedPlanSha256, approvedApprovalSha256, "start-intent"));
    const result = await ops.systemctl(["start", NETNS_UNIT]);
    if (result.status !== 0) fail("exact publisher namespace unit start failed");
    started = true;
  } else {
    const intentPath = `${plan.transaction.state_directory}/05-start-intent.json`;
    const observedIntent = await ops.readOptionalRegular(intentPath);
    if (observedIntent === null) {
      fail("recover-commit found an active namespace without the durable start intent");
    }
    const intent = parseStrictJson(observedIntent.bytes.toString("utf8"), "durable start intent");
    exactKeys(intent, [
      "approved_approval_sha256", "approved_plan_sha256", "ceremony_id", "phase",
      "schema_version",
    ], "durable start intent");
    if (intent.schema_version !== 1 || intent.phase !== "start-intent" ||
        intent.ceremony_id !== plan.ceremony_id ||
        intent.approved_plan_sha256 !== approvedPlanSha256) {
      fail("durable start intent identity/plan binding drifted");
    }
    validateSha256(intent.approved_approval_sha256,
      "durable start intent approved approval SHA-256");
    activationApprovalSha256 = intent.approved_approval_sha256;
  }
  const receipt = await buildCommittedReceipt({
    activationApprovalSha256, approvedApprovalSha256, approvedPlanSha256, before, ops, plan,
  });
  await ops.writeState(plan.transaction.state_directory, "10-runtime-verified.json",
    stateRecord(plan, approvedPlanSha256, approvedApprovalSha256, "runtime-verified", {
      netns_invocation_id: receipt.netns_unit.invocation_id,
      namespace_device: receipt.topology.namespace.device,
      namespace_inode: receipt.topology.namespace.inode,
      start_invoked: started,
    }));
  await ops.writeReceipt(plan.transaction.receipt_path, receipt);
  await ops.writeState(plan.transaction.state_directory, "20-committed.json",
    stateRecord(plan, approvedPlanSha256, approvedApprovalSha256, "committed", {
      receipt_sha256: sha256(Buffer.from(canonicalJson(receipt), "utf8")),
    }));
  return receipt;
}

export async function executeApply({
  approval,
  approvedApprovalSha256,
  approvedPlanSha256,
  nowUnix,
  ops,
  plan,
  recover = false,
}) {
  validateCeremonyPlan(plan);
  if (computePlanSha256(plan) !== approvedPlanSha256) fail("plan digest was not independently approved");
  validateApprovalCommon(approval, plan, approvedPlanSha256, nowUnix, false);
  const approvalBytes = Buffer.from(canonicalJson(approval), "utf8");
  if (sha256(approvalBytes) !== approvedApprovalSha256) fail("apply approval digest drifted");
  const release = await ops.acquireLock(plan.transaction.lock_path, {
    recoverStale: recover,
    transactionId: plan.ceremony_id,
  });
  try {
    return await applyLocked({
      approvedApprovalSha256, approvedPlanSha256, ops, plan, recover,
    });
  } finally {
    await release();
  }
}

function validateRollbackReceipt(
  receipt,
  committed,
  plan,
  approvedPlanSha256,
  committedReceiptSha256,
) {
  exactKeys(receipt, [
    "approved_plan_sha256", "approved_rollback_approval_sha256",
    "ceremony_id", "committed_receipt_sha256", "caddy_after", "kind",
    "netns_unit", "outcome", "publisher_unit", "schema_version",
    "stop_approval_sha256", "topology_absent",
  ], "rollback receipt");
  if (receipt.schema_version !== 1 || receipt.kind !== ROLLBACK_RECEIPT_KIND ||
      receipt.ceremony_id !== plan.ceremony_id || receipt.approved_plan_sha256 !== approvedPlanSha256 ||
      receipt.outcome !== "rolled-back" || receipt.topology_absent !== true ||
      receipt.committed_receipt_sha256 !== committedReceiptSha256 ||
      canonicalJson(receipt.caddy_after) !== canonicalJson(committed.caddy_after)) {
    fail("rollback receipt identity/outcome drifted");
  }
  validateSha256(
    receipt.approved_rollback_approval_sha256,
    "rollback receipt terminalization approval SHA-256",
  );
  validateSha256(
    receipt.stop_approval_sha256,
    "rollback receipt stop approval SHA-256",
  );
  validateUnitState(receipt.netns_unit, `rollback.${NETNS_UNIT}`, {
    active: false, name: NETNS_UNIT,
  });
  validateUnitState(receipt.publisher_unit, `rollback.${PUBLISHER_UNIT}`, {
    active: false, name: PUBLISHER_UNIT,
  });
  return true;
}

async function rollbackLocked({
  approvedPlanSha256,
  approvedRollbackApprovalSha256,
  committed,
  committedReceiptSha256,
  ops,
  plan,
  recover,
}) {
  const existing = await ops.readOptionalRegular(plan.transaction.rollback_receipt_path);
  if (existing !== null) {
    const receipt = parseStrictJson(existing.bytes.toString("utf8"), "rollback receipt");
    validateRollbackReceipt(
      receipt,
      committed,
      plan,
      approvedPlanSha256,
      committedReceiptSha256,
    );
    await commonPreflight(plan, ops);
    const netns = await ops.unitState(NETNS_UNIT);
    if (canonicalJson(netns) !== canonicalJson(receipt.netns_unit) ||
        !(await ops.networkAbsent(plan))) {
      fail("rollback receipt no longer describes an absent publisher namespace");
    }
    return receipt;
  }
  const before = await commonPreflight(plan, ops);
  if (canonicalJson(before.caddy) !== canonicalJson(committed.caddy_after)) {
    fail("Caddy generation changed after namespace commit; roll back the integrated overlay first");
  }
  const current = await ops.unitState(NETNS_UNIT);
  if (current.active_state !== "active" && !recover) {
    fail("publisher namespace is not active; use recover-rollback for a lost stop response");
  }
  const stopIntentPath = `${plan.transaction.state_directory}/25-stop-intent.json`;
  const observedStopIntent = await ops.readOptionalRegular(stopIntentPath);
  let stopApprovalSha256 = approvedRollbackApprovalSha256;
  if (observedStopIntent !== null) {
    const intent = parseStrictJson(
      observedStopIntent.bytes.toString("utf8"),
      "durable stop intent",
    );
    exactKeys(intent, [
      "approved_approval_sha256", "approved_plan_sha256", "ceremony_id",
      "committed_receipt_sha256", "phase", "schema_version",
    ], "durable stop intent");
    if (
      intent.schema_version !== 1 ||
      intent.phase !== "stop-intent" ||
      intent.ceremony_id !== plan.ceremony_id ||
      intent.approved_plan_sha256 !== approvedPlanSha256 ||
      intent.committed_receipt_sha256 !== committedReceiptSha256
    ) {
      fail("durable stop intent identity/plan/receipt binding drifted");
    }
    validateSha256(
      intent.approved_approval_sha256,
      "durable stop intent approved rollback SHA-256",
    );
    stopApprovalSha256 = intent.approved_approval_sha256;
  } else if (current.active_state !== "active") {
    fail("recover-rollback found an inactive namespace without the durable stop intent");
  }
  if (current.active_state === "active") {
    if (canonicalJson(current) !== canonicalJson(committed.netns_unit)) {
      fail("publisher namespace systemd generation changed after commit");
    }
    if (observedStopIntent !== null && !recover) {
      fail("a durable stop intent already exists; use recover-rollback for an explicit retry");
    }
    if (observedStopIntent === null) {
      await ops.writeState(plan.transaction.state_directory, "25-stop-intent.json",
        stateRecord(plan, approvedPlanSha256, approvedRollbackApprovalSha256, "stop-intent", {
          committed_receipt_sha256: committedReceiptSha256,
        }));
    }
    const result = await ops.systemctl(["stop", NETNS_UNIT]);
    if (result.status !== 0) fail("exact publisher namespace unit stop failed");
  }
  const netnsAfter = await ops.unitState(NETNS_UNIT);
  validateUnitState(netnsAfter, `rollback.${NETNS_UNIT}`, {
    active: false, name: NETNS_UNIT,
  });
  if (!(await ops.networkAbsent(plan))) fail("namespace or owned host veth remains after stop");
  const caddyAfter = await ops.caddyState();
  if (canonicalJson(caddyAfter) !== canonicalJson(committed.caddy_after)) {
    fail("Caddy changed while stopping the publisher namespace");
  }
  const publisher = await ops.unitState(PUBLISHER_UNIT);
  if (canonicalJson(publisher) !== canonicalJson(plan.preimage.publisher_unit)) {
    fail("publisher service changed while stopping its namespace");
  }
  const closedAfter = await collectClosedInputs(plan, ops);
  if (canonicalJson(closedAfter) !== canonicalJson(before.closed)) {
    fail("installed files, sentinels or firewall evidence changed during stop");
  }
  const hostAfter = await ops.hostIdentity();
  if (canonicalJson(hostAfter) !== canonicalJson(before.host)) {
    fail("host boot/systemd identity changed during namespace stop");
  }
  const receipt = {
    approved_plan_sha256: approvedPlanSha256,
    approved_rollback_approval_sha256: approvedRollbackApprovalSha256,
    caddy_after: caddyAfter,
    ceremony_id: plan.ceremony_id,
    committed_receipt_sha256: committedReceiptSha256,
    kind: ROLLBACK_RECEIPT_KIND,
    netns_unit: netnsAfter,
    outcome: "rolled-back",
    publisher_unit: publisher,
    schema_version: 1,
    stop_approval_sha256: stopApprovalSha256,
    topology_absent: true,
  };
  await ops.writeReceipt(plan.transaction.rollback_receipt_path, receipt);
  await ops.writeState(plan.transaction.state_directory, "30-rolled-back.json",
    stateRecord(plan, approvedPlanSha256, approvedRollbackApprovalSha256, "rolled-back", {
      rollback_receipt_sha256: sha256(Buffer.from(canonicalJson(receipt), "utf8")),
    }));
  return receipt;
}

export async function executeRollback({
  approvedPlanSha256,
  approvedReceiptSha256,
  approvedRollbackApprovalSha256,
  nowUnix,
  ops,
  plan,
  recover = false,
  rollbackApproval,
}) {
  validateCeremonyPlan(plan);
  if (computePlanSha256(plan) !== approvedPlanSha256) fail("plan digest was not independently approved");
  validateApprovalCommon(rollbackApproval, plan, approvedPlanSha256, nowUnix, true);
  if (rollbackApproval.committed_receipt_sha256 !== approvedReceiptSha256) {
    fail("rollback approval does not bind the approved committed receipt");
  }
  const approvalBytes = Buffer.from(canonicalJson(rollbackApproval), "utf8");
  if (sha256(approvalBytes) !== approvedRollbackApprovalSha256) {
    fail("rollback approval digest drifted");
  }
  const observed = await ops.readRegular(plan.transaction.receipt_path);
  if (sha256(observed.bytes) !== approvedReceiptSha256) fail("committed receipt bytes drifted");
  const committed = parseStrictJson(observed.bytes.toString("utf8"), "committed receipt");
  validateReceipt(committed, plan, approvedPlanSha256);
  const release = await ops.acquireLock(plan.transaction.lock_path, {
    recoverStale: recover,
    transactionId: `${plan.ceremony_id}-rollback`,
  });
  try {
    return await rollbackLocked({
      approvedPlanSha256,
      approvedRollbackApprovalSha256,
      committed,
      committedReceiptSha256: approvedReceiptSha256,
      ops,
      plan,
      recover,
    });
  } finally {
    await release();
  }
}

function sameStableStat(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode &&
    left.uid === right.uid && left.gid === right.gid && left.nlink === right.nlink &&
    left.size === right.size && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

function snapshotFromOpenFile(path, stat, bytes) {
  return {
    ctime_ns: stat.ctimeNs.toString(),
    device: stat.dev.toString(),
    gid: Number(stat.gid),
    inode: stat.ino.toString(),
    mode: (Number(stat.mode) & 0o7777).toString(8).padStart(4, "0"),
    mtime_ns: stat.mtimeNs.toString(),
    nlink: Number(stat.nlink),
    path,
    sha256: sha256(bytes),
    size: stat.size.toString(),
    uid: Number(stat.uid),
  };
}

function openStableRegular(path) {
  const before = lstatSync(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) fail(`${path} is not a regular no-follow file`);
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC);
  try {
    const opened = fstatSync(fd, { bigint: true });
    if (!opened.isFile() || !sameStableStat(before, opened)) {
      fail(`${path} changed before its no-follow descriptor was opened`);
    }
    const bytes = readFileSync(fd);
    const afterDescriptor = fstatSync(fd, { bigint: true });
    const afterPath = lstatSync(path, { bigint: true });
    if (!afterPath.isFile() || afterPath.isSymbolicLink() ||
        !sameStableStat(opened, afterDescriptor) || !sameStableStat(opened, afterPath)) {
      fail(`${path} changed while it was read`);
    }
    return { bytes, fd, snapshot: snapshotFromOpenFile(path, opened, bytes) };
  } catch (error) {
    closeSync(fd);
    throw error;
  }
}

function regularSnapshot(path) {
  const opened = openStableRegular(path);
  closeSync(opened.fd);
  return { bytes: opened.bytes, snapshot: opened.snapshot };
}

function optionalRegular(path) {
  try {
    return regularSnapshot(path);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

function fsyncParent(path) {
  const fd = openSync(dirname(path), constants.O_RDONLY | constants.O_DIRECTORY |
    constants.O_NOFOLLOW | constants.O_CLOEXEC);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}

function secureDirectory(path, label = path) {
  const stat = lstatSync(path, { bigint: true });
  const mode = Number(stat.mode) & 0o7777;
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== 0n || stat.gid !== 0n ||
      mode !== 0o700) {
    fail(`${label} must be a root-owned no-follow 0700 directory`);
  }
  return stat;
}

function exactOwnerRecord(observed, path, bytes, allowedLinks = [1]) {
  if (!observed.bytes.equals(bytes) || observed.snapshot.path !== path ||
      observed.snapshot.mode !== "0400" || observed.snapshot.uid !== 0 ||
      observed.snapshot.gid !== 0 || !allowedLinks.includes(observed.snapshot.nlink)) {
    fail(`published record ${path} has an unreviewed owner/content/link shape`);
  }
}

function writeAtomicNoReplace(path, value) {
  const bytes = Buffer.from(canonicalJson(value), "utf8");
  const pending = `${path}.pending`;
  secureDirectory(dirname(path), `record parent ${dirname(path)}`);

  // Reconcile both crash windows before creating a new inode: (1) the pending
  // file was fsynced but not linked, or (2) the hard link was created but the
  // pending name was not removed. Any contradictory inode/content fails closed.
  let final = optionalRegular(path);
  let staged = optionalRegular(pending);
  if (final !== null) {
    if (staged !== null) {
      exactOwnerRecord(final, path, bytes, [2]);
      exactOwnerRecord(staged, pending, bytes, [2]);
      if (final.snapshot.device !== staged.snapshot.device ||
          final.snapshot.inode !== staged.snapshot.inode) {
        fail(`final and pending records disagree for ${path}`);
      }
      unlinkSync(pending);
      fsyncParent(path);
      final = regularSnapshot(path);
    }
    exactOwnerRecord(final, path, bytes);
    return final;
  }
  if (staged !== null) {
    exactOwnerRecord(staged, pending, bytes);
    try {
      linkSync(pending, path);
      fsyncParent(path);
    } catch (error) {
      final = optionalRegular(path);
      if (final === null || final.snapshot.device !== staged.snapshot.device ||
          final.snapshot.inode !== staged.snapshot.inode || !final.bytes.equals(bytes)) throw error;
    }
    unlinkSync(pending);
    fsyncParent(path);
    final = regularSnapshot(path);
    exactOwnerRecord(final, path, bytes);
    return final;
  }

  const fd = openSync(pending,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW | constants.O_CLOEXEC,
    0o400);
  try {
    fchmodSync(fd, 0o400);
    fchownSync(fd, 0, 0);
    writeSync(fd, bytes);
    fsyncSync(fd);
  } finally { closeSync(fd); }
  try {
    linkSync(pending, path);
    fsyncParent(path);
    unlinkSync(pending);
    fsyncParent(path);
  } catch (error) {
    const final = optionalRegular(path);
    const staged = optionalRegular(pending);
    if (final !== null && staged !== null && final.snapshot.device === staged.snapshot.device &&
        final.snapshot.inode === staged.snapshot.inode && final.bytes.equals(bytes) &&
        staged.bytes.equals(bytes)) {
      unlinkSync(pending);
      fsyncParent(path);
      const recovered = regularSnapshot(path);
      exactOwnerRecord(recovered, path, bytes);
      return recovered;
    }
    throw error;
  }
  const result = regularSnapshot(path);
  exactOwnerRecord(result, path, bytes);
  return result;
}

function processStartTicks(pid) {
  const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
  const close = stat.lastIndexOf(")");
  if (close < 0) fail("malformed /proc process stat");
  const fields = stat.slice(close + 2).split(" ");
  const value = fields[19];
  if (!/^[1-9][0-9]*$/u.test(value ?? "")) fail("malformed process start ticks");
  return value;
}

function currentBootId() {
  return readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
}

function acquireLock(path, { recoverStale, transactionId }) {
  const create = () => {
    mkdirSync(path, { mode: 0o700 });
    secureDirectory(path, "transaction lock");
    const owner = {
      boot_id: currentBootId(),
      pid: process.pid,
      process_start_ticks: processStartTicks(process.pid),
      transaction_id: transactionId,
    };
    writeAtomicNoReplace(`${path}/${LOCK_OWNER}`, owner);
    return owner;
  };
  let owner;
  try {
    owner = create();
  } catch (error) {
    if (error?.code !== "EEXIST" || !recoverStale) throw error;
    secureDirectory(path, "stale transaction lock");
    const entries = readdirSync(path, { withFileTypes: true });
    if (entries.length !== 1 || entries[0].name !== LOCK_OWNER || !entries[0].isFile()) {
      fail("stale lock has an unknown shape");
    }
    const observed = regularSnapshot(`${path}/${LOCK_OWNER}`);
    const old = parseStrictJson(observed.bytes.toString("utf8"), "stale lock owner");
    exactKeys(old, ["boot_id", "pid", "process_start_ticks", "transaction_id"], "stale lock owner");
    let live = old.boot_id === currentBootId();
    if (live) {
      try { live = processStartTicks(old.pid) === old.process_start_ticks; } catch { live = false; }
    }
    if (live) fail("transaction lock is held by a live process generation");
    unlinkSync(`${path}/${LOCK_OWNER}`);
    rmdirSync(path);
    fsyncParent(path);
    owner = create();
  }
  return async () => {
    secureDirectory(path, "transaction lock before release");
    const observed = regularSnapshot(`${path}/${LOCK_OWNER}`);
    const current = parseStrictJson(observed.bytes.toString("utf8"), "lock owner");
    if (canonicalJson(current) !== canonicalJson(owner)) fail("transaction lock ownership changed");
    const entries = readdirSync(path, { withFileTypes: true });
    if (entries.length !== 1 || entries[0].name !== LOCK_OWNER || !entries[0].isFile()) {
      fail("transaction lock directory changed before release");
    }
    unlinkSync(`${path}/${LOCK_OWNER}`);
    rmdirSync(path);
    fsyncParent(path);
  };
}

function invokePinned(pin, args, { maxBytes = MAX_COMMAND_BYTES, timeoutMs = 30_000 } = {}) {
  if (!Array.isArray(args) || args.some((part) => typeof part !== "string" || part.includes("\0"))) {
    fail("pinned command argv is malformed");
  }
  const opened = openStableRegular(pin.path);
  if (canonicalJson(opened.snapshot) !== canonicalJson(pin)) {
    closeSync(opened.fd);
    fail(`pinned command ${pin.path} drifted before invocation`);
  }
  let result;
  try {
    result = spawnSync("/proc/self/fd/3", args, {
      encoding: null,
      env: { LANG: "C", LC_ALL: "C", PATH: "/usr/sbin:/usr/bin" },
      killSignal: "SIGKILL",
      maxBuffer: maxBytes,
      shell: false,
      stdio: ["ignore", "pipe", "pipe", opened.fd],
      timeout: timeoutMs,
    });
  } finally {
    closeSync(opened.fd);
  }
  const after = regularSnapshot(pin.path);
  if (canonicalJson(after.snapshot) !== canonicalJson(pin)) {
    fail(`pinned command ${pin.path} drifted during invocation`);
  }
  if (result.error) fail(`command failed: ${result.error.message}`);
  return {
    status: result.status ?? 255,
    stderr: result.stderr ?? Buffer.alloc(0),
    stdout: result.stdout ?? Buffer.alloc(0),
  };
}

function systemctlProperties(name, properties, systemctlPin) {
  if (![NETNS_UNIT, PUBLISHER_UNIT, CADDY_UNIT].includes(name)) {
    fail(`unreviewed systemd unit state request: ${name}`);
  }
  const result = invokePinned(systemctlPin, ["show", name,
    ...properties.flatMap((property) => ["-p", property])]);
  if (result.status !== 0 || result.stderr.length !== 0) fail(`systemctl show failed for ${name}`);
  const values = new Map();
  for (const line of result.stdout.toString("utf8").trimEnd().split("\n")) {
    const equals = line.indexOf("=");
    if (equals < 1 || values.has(line.slice(0, equals))) fail(`malformed systemctl output for ${name}`);
    values.set(line.slice(0, equals), line.slice(equals + 1));
  }
  if (values.size !== properties.length ||
      properties.some((property) => !values.has(property))) {
    fail(`systemctl show omitted a requested property for ${name}`);
  }
  return values;
}

function systemctlUnit(name, systemctlPin) {
  const properties = [
    "LoadState", "ActiveState", "SubState", "MainPID", "InvocationID",
    "ActiveEnterTimestampMonotonic", "NeedDaemonReload",
  ];
  const values = systemctlProperties(name, properties, systemctlPin);
  return {
    active_enter_timestamp_monotonic: values.get("ActiveEnterTimestampMonotonic"),
    active_state: values.get("ActiveState"),
    invocation_id: values.get("InvocationID"),
    load_state: values.get("LoadState"),
    main_pid: values.get("MainPID"),
    name,
    need_daemon_reload: values.get("NeedDaemonReload"),
    sub_state: values.get("SubState"),
  };
}

function systemctlCaddyDependency(systemctlPin) {
  const properties = [
    "After", "BindsTo", "DropInPaths", "PartOf", "Requires", "Wants",
  ];
  const values = systemctlProperties(CADDY_UNIT, properties, systemctlPin);
  const words = (property) => {
    const text = values.get(property);
    if (text === "") return [];
    const result = text.split(" ");
    if (result.some((value) => value === "" || /[\0\r\n]/u.test(value)) ||
        new Set(result).size !== result.length) {
      fail(`systemctl ${property} for ${CADDY_UNIT} is not a unique word set`);
    }
    return result.sort();
  };
  const relation = (property) => words(property).includes(NETNS_UNIT);
  return {
    after_namespace_owner: relation("After"),
    binds_to_namespace_owner: relation("BindsTo"),
    drop_in_paths: words("DropInPaths"),
    part_of_namespace_owner: relation("PartOf"),
    requires_namespace_owner: relation("Requires"),
    wants_namespace_owner: relation("Wants"),
  };
}

function parseIpJson(result, label) {
  if (result.status !== 0 || result.stderr.length !== 0) fail(`${label} command failed`);
  return parseStrictJson(result.stdout.toString("utf8"), label);
}

function oneInterface(value, name, label) {
  if (!Array.isArray(value) || value.length !== 1 || value[0].ifname !== name) {
    fail(`${label} did not return the one requested interface`);
  }
  return value[0];
}

function sideFromIp(link, addr, plan, side) {
  const address = oneInterface(addr, plan.topology[`${side}_interface`], `${side} address`);
  const family = plan.topology.address_family === "ipv4" ? "inet" : "inet6";
  const candidates = (address.addr_info ?? []).filter((item) => item.family === family && item.scope === "global");
  if (candidates.length !== 1) fail(`${side} interface must have one global address`);
  return {
    address: candidates[0].local,
    alias: link.ifalias ?? "",
    index: link.ifindex,
    interface: link.ifname,
    mac: link.address,
    peer_index: link.link_index,
    prefix_length: candidates[0].prefixlen,
    up: Array.isArray(link.flags) && link.flags.includes("UP") && link.operstate === "UP",
  };
}

function addressSummary(link) {
  if (!Array.isArray(link.addr_info)) fail(`interface ${link.ifname} omitted addr_info`);
  return link.addr_info.map((address) => ({
    family: address.family,
    local: address.local,
    prefix_length: address.prefixlen,
  })).sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)));
}

function routeSummary(routes) {
  if (!Array.isArray(routes)) fail("ip route output is not an array");
  return routes.map((route) => ({
    default: route.dst === "default",
    destination: route.dst ?? null,
    gateway: route.gateway ?? null,
    nat: route.type === "nat" || route.encap?.type === "nat",
  }));
}

export function linuxOps(plan) {
  if (process.platform !== "linux" || process.geteuid?.() !== 0) {
    fail("real publisher netns ceremony requires Linux EUID 0");
  }
  validateCeremonyPlan(plan);
  const ip = plan.runtime.ip;
  const systemctl = plan.runtime.systemctl;
  return {
    async acquireLock(path, options) { return acquireLock(path, options); },
    async caddyState() {
      return {
        config: regularSnapshot("/etc/caddy/Caddyfile").snapshot,
        dependency: systemctlCaddyDependency(systemctl),
        unit: systemctlUnit(CADDY_UNIT, systemctl),
      };
    },
    async hostIdentity() {
      const version = invokePinned(systemctl, ["--version"]);
      if (version.status !== 0 || version.stderr.length !== 0) fail("systemctl --version failed");
      return {
        boot_id: currentBootId(),
        machine_id_sha256: sha256(readFileSync("/etc/machine-id")),
        systemd_version: version.stdout.toString("utf8").split("\n")[0],
      };
    },
    async networkAbsent(plan) {
      try { lstatSync(plan.topology.namespace_path); return false; } catch (error) { if (error.code !== "ENOENT") throw error; }
      try { lstatSync(`/sys/class/net/${plan.topology.host_interface}`); return false; } catch (error) { if (error.code !== "ENOENT") throw error; }
      return true;
    },
    async networkState(plan) {
      const hostLink = oneInterface(parseIpJson(invokePinned(ip, [
        "-j", "-details", "link", "show", "dev", plan.topology.host_interface,
      ]), "host link"), plan.topology.host_interface, "host link");
      const hostAddr = parseIpJson(invokePinned(ip, [
        "-j", "addr", "show", "dev", plan.topology.host_interface,
      ]), "host address");
      // Descriptor 3 remains the reviewed iproute2 inode in the outer `ip
      // netns exec` process and is reused as the inner executable. No PATH or
      // mutable pathname is consulted for either process generation.
      const inside = (args) => invokePinned(ip, [
        "netns", "exec", plan.topology.namespace_name, "/proc/self/fd/3", ...args,
      ]);
      const clientLinks = parseIpJson(inside(["-j", "-details", "addr", "show"]), "namespace links");
      const names = clientLinks.map((link) => link.ifname).sort();
      const clientLink = clientLinks.find((link) => link.ifname === plan.topology.client_interface);
      if (clientLink === undefined) fail("namespace client veth is absent");
      const loopback = clientLinks.find((link) => link.ifname === "lo");
      if (loopback === undefined) fail("namespace loopback is absent");
      const inertInterfaces = clientLinks
        .filter((link) => !["lo", plan.topology.client_interface].includes(link.ifname))
        .map((link) => ({
          addresses: addressSummary(link),
          alias: link.ifalias ?? "",
          index: link.ifindex,
          kind: link.linkinfo?.info_kind ?? "",
          name: link.ifname,
          up: Array.isArray(link.flags) && link.flags.includes("UP"),
        }))
        .sort((left, right) => left.name.localeCompare(right.name));
      const clientAddr = parseIpJson(inside(["-j", "addr", "show", "dev",
        plan.topology.client_interface]), "client address");
      const hostRoutes = parseIpJson(invokePinned(ip, [
        "-j", "route", "show", "table", "main", "dev", plan.topology.host_interface,
      ]), "host routes");
      const clientRoutes = parseIpJson(inside(["-j", "route", "show", "table", "main"]), "client routes");
      const ns = lstatSync(plan.topology.namespace_path, { bigint: true });
      const nsFilesystem = statfsSync(plan.topology.namespace_path, { bigint: true });
      if (nsFilesystem.type !== 0x6e736673n) fail("namespace filesystem type is not nsfs");
      return {
        client: sideFromIp(clientLink, clientAddr, plan, "client"),
        forwarding_sysctls: {
          "net.ipv4.ip_forward": Number(readFileSync("/proc/sys/net/ipv4/ip_forward", "utf8").trim()),
          "net.ipv6.conf.all.forwarding": Number(readFileSync(
            "/proc/sys/net/ipv6/conf/all/forwarding", "utf8").trim()),
        },
        host: sideFromIp(hostLink, hostAddr, plan, "host"),
        namespace: {
          device: ns.dev.toString(),
          inert_interfaces: inertInterfaces,
          inode: ns.ino.toString(),
          interface_names: names,
          loopback: {
            addresses: addressSummary(loopback),
            alias: loopback.ifalias ?? "",
            index: loopback.ifindex,
            up: Array.isArray(loopback.flags) && loopback.flags.includes("UP"),
          },
          path: plan.topology.namespace_path, type: "nsfs",
        },
        routes: { client_main: routeSummary(clientRoutes), host_main: routeSummary(hostRoutes) },
      };
    },
    async readOptionalRegular(path) { return optionalRegular(path); },
    async readRegular(path) { return regularSnapshot(path); },
    async systemctl(args) {
      if (![canonicalJson(["start", NETNS_UNIT]), canonicalJson(["stop", NETNS_UNIT])]
        .includes(canonicalJson(args))) {
        fail(`unreviewed systemctl mutation: ${args.join(" ")}`);
      }
      return invokePinned(systemctl, args, { timeoutMs: 60_000 });
    },
    async unitState(name) { return systemctlUnit(name, systemctl); },
    async writeReceipt(path, value) { return writeAtomicNoReplace(path, value); },
    async writeState(directory, filename, value) {
      secureDirectory(dirname(directory), `transaction root ${dirname(directory)}`);
      try {
        mkdirSync(directory, { mode: 0o700 });
        fsyncParent(directory);
      } catch (error) {
        if (error.code !== "EEXIST") throw error;
      }
      secureDirectory(directory, "transaction state directory");
      const entries = readdirSync(directory);
      const allowed = new Set(STATE_FILENAMES.flatMap((name) => [name, `${name}.pending`]));
      if (!STATE_FILENAMES.includes(filename) || entries.some((name) => !allowed.has(name))) {
        fail("transaction state directory contains an unknown entry");
      }
      const path = `${directory}/${filename}`;
      const existing = optionalRegular(path);
      if (existing !== null) {
        if (!existing.bytes.equals(Buffer.from(canonicalJson(value), "utf8"))) fail(`state ${filename} replay drifted`);
        return existing;
      }
      return writeAtomicNoReplace(path, value);
    },
  };
}

export const PUBLISHER_NETNS_CEREMONY_TEST_ONLY_IO = Object.freeze({
  readRegular: regularSnapshot,
  runPinnedBinary: invokePinned,
  writeAtomicNoReplace,
});

function parseArgs(argv) {
  const args = [...argv];
  const commandName = args.shift();
  const values = new Map();
  for (let index = 0; index < args.length; index += 2) {
    if (!args[index]?.startsWith("--") || args[index + 1] === undefined || values.has(args[index])) {
      fail("arguments must be unique --name value pairs");
    }
    values.set(args[index], args[index + 1]);
  }
  return { commandName, values };
}

function required(values, key) {
  const value = values.get(key);
  if (value === undefined) fail(`missing ${key}`);
  return value;
}

function readStrict(path, label) {
  validateCanonicalAbsolute(path, `${label} path`);
  const observed = regularSnapshot(path);
  if (observed.bytes.length > MAX_JSON_BYTES) fail(`${label} exceeds the byte bound`);
  return { observed, value: parseStrictJson(observed.bytes.toString("utf8"), label) };
}

async function main(argv) {
  const { commandName, values } = parseArgs(argv);
  if (!["apply", "recover-commit", "rollback", "recover-rollback", "validate-plan"].includes(commandName)) {
    fail("usage: publisher-netns-ceremony.mjs apply|recover-commit|rollback|recover-rollback|validate-plan --plan ABS ...");
  }
  const commonArgs = ["--approved-plan-sha256", "--approved-source-sha256", "--plan"];
  const commandArgs = commandName === "validate-plan" ? commonArgs :
    ["apply", "recover-commit"].includes(commandName) ? [
      ...commonArgs, "--approval", "--approved-approval-sha256",
    ] : [
      ...commonArgs, "--approved-receipt-sha256", "--approved-rollback-approval-sha256",
      "--rollback-approval",
    ];
  exactArray([...values.keys()].sort(), [...commandArgs].sort(), `${commandName} argument set`);
  const planRead = readStrict(required(values, "--plan"), "ceremony plan");
  const plan = planRead.value;
  validateCeremonyPlan(plan);
  const approvedPlanSha256 = required(values, "--approved-plan-sha256");
  validateSha256(approvedPlanSha256, "approved plan SHA-256");
  if (computePlanSha256(plan) !== approvedPlanSha256) fail("approved plan digest drifted");
  const approvedSourceSha256 = required(values, "--approved-source-sha256");
  if (approvedSourceSha256 !== plan.runtime.executor.sha256 ||
      fileURLToPath(import.meta.url) !== plan.runtime.executor.path ||
      process.execPath !== plan.runtime.node.path) {
    fail("executor source/path or Node path drifted from the exact plan");
  }
  for (const [name, pin] of Object.entries(plan.runtime)) {
    const observed = regularSnapshot(pin.path);
    if (canonicalJson(observed.snapshot) !== canonicalJson(pin)) {
      fail(`runtime command ${name} does not equal the approved plan pin`);
    }
  }
  if (commandName === "validate-plan") {
    process.stdout.write(`valid plan_sha256=${approvedPlanSha256}\n`);
    return;
  }
  const nowUnix = Math.floor(Date.now() / 1000);
  const ops = linuxOps(plan);
  let result;
  if (commandName === "apply" || commandName === "recover-commit") {
    const approvalRead = readStrict(required(values, "--approval"), "apply approval");
    result = await executeApply({
      approval: approvalRead.value,
      approvedApprovalSha256: required(values, "--approved-approval-sha256"),
      approvedPlanSha256,
      nowUnix,
      ops,
      plan,
      recover: commandName === "recover-commit",
    });
  } else {
    const approvalRead = readStrict(required(values, "--rollback-approval"),
      "rollback approval");
    result = await executeRollback({
      approvedPlanSha256,
      approvedReceiptSha256: required(values, "--approved-receipt-sha256"),
      approvedRollbackApprovalSha256: required(values, "--approved-rollback-approval-sha256"),
      nowUnix,
      ops,
      plan,
      recover: commandName === "recover-rollback",
      rollbackApproval: approvalRead.value,
    });
  }
  process.stdout.write(`${result.outcome} receipt=${commandName.startsWith("recover-rollback") || commandName === "rollback" ?
    plan.transaction.rollback_receipt_path : plan.transaction.receipt_path}\n`);
}

const isMain = process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (isMain) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
