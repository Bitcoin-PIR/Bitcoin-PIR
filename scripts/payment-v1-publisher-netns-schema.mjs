import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { resolve } from "node:path";

export const PUBLISHER_NETNS_PLAN_SCHEMA_VERSION = 2;
export const PUBLISHER_NETNS_RECEIPT_SCHEMA_VERSION = 2;
export const PUBLISHER_NETNS_CEREMONY_KIND =
  "bitcoinpir-payment-v1-publisher-netns-ceremony-v1";
export const PUBLISHER_NETNS_RECEIPT_KIND =
  "bitcoinpir-payment-v1-publisher-netns-receipt-v1";
export const PUBLISHER_NETNS_APPLY_APPROVAL_KIND =
  "bitcoinpir-payment-v1-publisher-netns-apply-approval-v1";
export const PUBLISHER_NETNS_ROLLBACK_APPROVAL_KIND =
  "bitcoinpir-payment-v1-publisher-netns-rollback-approval-v1";
export const PUBLISHER_NETNS_FAILED_RECOVERY_APPROVAL_KIND =
  "bitcoinpir-payment-v1-publisher-netns-failed-recovery-approval-v1";
export const PUBLISHER_NETNS_FAILED_RECOVERY_RECEIPT_KIND =
  "bitcoinpir-payment-v1-publisher-netns-failed-recovery-receipt-v1";
export const PUBLISHER_NODE_ELF_CLOSURE_KIND =
  "bitcoinpir-payment-v1-publisher-node-elf-closure-v1";
export const PUBLISHER_NODE_LOADER_CLOSURE_PATH =
  "/etc/bitcoinpir/payment-v1/publisher-netns/node-loader-closure.sha256";
export const PUBLISHER_NETNS_LIFECYCLE_LOCK =
  "/run/lock/bitcoinpir-payment-v1-publisher-lifecycle.lock";

export const PUBLISHER_NETNS_APPLY_ACKNOWLEDGEMENTS = Object.freeze([
  "only-the-exact-publisher-network-namespace-unit-will-be-started",
  "caddy-source-fair-publisher-and-payment-services-will-not-be-started-stopped-or-reloaded",
  "no-activation-sentinel-firewall-rule-route-nat-forwarding-or-publication-will-be-created",
  "the-directory-publisher-private-key-must-remain-off-host-and-only-frozen-signed-public-artifacts-may-be-published",
]);

export const PUBLISHER_NETNS_ROLLBACK_ACKNOWLEDGEMENTS = Object.freeze([
  "only-the-exact-publisher-network-namespace-unit-will-be-stopped",
  "rollback-is-forbidden-after-the-caddy-preimage-or-publisher-service-generation-changes",
  "caddy-source-fair-publisher-and-payment-services-will-not-be-started-stopped-or-reloaded",
  "installed-files-activation-sentinels-firewall-rules-and-signed-public-artifacts-will-not-be-removed",
]);

export const PUBLISHER_NETNS_FAILED_RECOVERY_ACKNOWLEDGEMENTS = Object.freeze([
  "only-the-approved-failed-publisher-namespace-invocation-will-be-reset",
  "reset-failed-will-use-the-fixed-argv-and-will-not-start-stop-reload-or-restart-any-unit",
  "the-durable-start-intent-original-activation-approval-and-failed-invocation-are-one-bound-attempt",
  "no-pid1-job-main-process-namespace-interface-or-input-generation-may-exist-or-drift-before-or-after-reset",
]);

export const PUBLISHER_NETNS_SENTINELS = Object.freeze([
  "/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
  "/etc/bitcoinpir/payment-v1/EDGE-ACTIVATION-APPROVED",
  "/etc/bitcoinpir/payment-v1/SOURCE-FAIR-PREFLIGHT-APPROVED",
  "/etc/bitcoinpir/payment-v1/DIRECTORY-PUBLISHER-PRIVATE-INGRESS-APPROVED",
  "/etc/bitcoinpir/payment-v1/PUBLISHER-NETNS-ACTIVATION-APPROVED",
]);

const NETNS_UNIT = "bitcoinpir-payment-v1-publisher-netns.service";
const PUBLISHER_UNIT = "bitcoinpir-payment-v1-directory-publisher.service";
const CADDY_UNIT = "bhtm-caddy.service";
const CADDY_NETNS_DROP_IN =
  "/etc/systemd/system/bhtm-caddy.service.d/bitcoinpir-publisher-netns.conf";
const NETNS_UNIT_FRAGMENT =
  "/etc/systemd/system/bitcoinpir-payment-v1-publisher-netns.service";
const SCHEMA_VALIDATOR_PATH =
  "/usr/local/libexec/bitcoinpir/payment-v1-publisher-netns-schema.mjs";
const MAX_APPROVAL_WINDOW_SECONDS = 60 * 60;
const MAX_CLOCK_SKEW_SECONDS = 300;
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
  throw new Error(`publisher-netns-schema-v2: ${message}`);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype ||
      Object.getPrototypeOf(value) === null);
}

function canonicalize(value) {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) fail("canonical JSON numbers must be safe integers");
    return String(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (isPlainObject(value)) {
    return `{${Object.keys(value).sort().map(
      (key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`,
    ).join(",")}}`;
  }
  fail("canonical JSON contains an unsupported value");
}

export function canonicalPublisherNetnsJsonV2(value) {
  return `${canonicalize(value)}\n`;
}

function same(left, right) {
  return canonicalPublisherNetnsJsonV2(left) === canonicalPublisherNetnsJsonV2(right);
}

function exactKeys(value, expected, label) {
  if (!isPlainObject(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (!same(actual, wanted)) fail(`${label} keys drifted`);
}

function exactArray(actual, expected, label) {
  if (!same(actual, expected)) fail(`${label} drifted`);
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
  if (typeof value !== "string" ||
      !/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/u.test(value)) {
    fail(`${label} must be a 1..64 byte lowercase slug`);
  }
}

function validateCanonicalAbsolute(path, label) {
  if (
    typeof path !== "string" || path.length < 2 || path.length > 4096 ||
    !path.startsWith("/") || path.includes("\0") || path.includes("//") ||
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
  if (isIP(value) !== 4 ||
      !/^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){3}$/u.test(value)) {
    fail(`${label} must be canonical dotted-decimal IPv4`);
  }
  const octets = value.split(".").map(Number);
  if (octets.some((part) => part > 255)) fail(`${label} has an out-of-range octet`);
  return octets.reduce((sum, part) => (sum << 8n) | BigInt(part), 0n);
}

function privateIpv4(value, label) {
  const address = parseIpv4(value, label);
  const first = Number(address >> 24n);
  const second = Number((address >> 16n) & 255n);
  if (!(first === 10 || (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && second === 168))) {
    fail(`${label} must be RFC1918`);
  }
  return address;
}

function validatePrivatePair(value) {
  if (value.address_family !== "ipv4" || value.prefix_length !== 30) {
    fail("topology addresses and declared family must match the reviewed IPv4 /30 profile");
  }
  const host = privateIpv4(value.host_address, "topology.host_address");
  const client = privateIpv4(value.client_address, "topology.client_address");
  if (host === client || (host >> 2n) !== (client >> 2n) ||
      new Set([(host & 3n).toString(), (client & 3n).toString()]).size !== 2 ||
      ![host & 3n, client & 3n].includes(1n) || ![host & 3n, client & 3n].includes(2n)) {
    fail("topology host/client must be distinct +1/+2 addresses in one private /30");
  }
}

function validateDnsHost(value, label) {
  if (typeof value !== "string" || value.length > 253 || value !== value.toLowerCase() ||
      value.endsWith(".") || value.split(".").length < 2 ||
      value.split(".").some(
        (part) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(part),
      )) {
    fail(`${label} must be a canonical lowercase DNS hostname`);
  }
}

function validateFilePin(value, label, { paths, modes, uid = 0, gid = 0 }) {
  exactKeys(value, [
    "ctime_ns", "device", "gid", "inode", "mode", "mtime_ns", "nlink",
    "path", "sha256", "size", "uid",
  ], label);
  validateCanonicalAbsolute(value.path, `${label}.path`);
  if (!paths.includes(value.path)) fail(`${label}.path is not approved`);
  validateSha256(value.sha256, `${label}.sha256`);
  for (const key of ["device", "inode", "ctime_ns", "mtime_ns", "size"]) {
    validateDecimal(value[key], `${label}.${key}`, { nonzero: key === "inode" });
  }
  if (!Number.isSafeInteger(value.uid) || !Number.isSafeInteger(value.gid) ||
      value.uid !== uid || value.gid !== gid || value.nlink !== 1 ||
      !modes.includes(value.mode)) {
    fail(`${label} owner, mode or single-link contract drifted`);
  }
}

function validateUnitState(value, label, { active, name }) {
  exactKeys(value, [
    "active_enter_timestamp_monotonic", "active_state", "invocation_id", "load_state",
    "main_pid", "name", "need_daemon_reload", "sub_state",
  ], label);
  if (value.need_daemon_reload !== "no") {
    fail(`${label} has an unsealed systemd generation`);
  }
  if (value.name !== name || value.load_state !== "loaded") {
    fail(`${label} identity or loaded generation drifted`);
  }
  validateDecimal(value.active_enter_timestamp_monotonic,
    `${label}.active_enter_timestamp_monotonic`);
  validateDecimal(value.main_pid, `${label}.main_pid`);
  if (active) {
    if (value.active_state !== "active" || value.sub_state !== "running" ||
        value.active_enter_timestamp_monotonic === "0" || value.main_pid === "0" ||
        !/^[0-9a-f]{32}$/u.test(value.invocation_id) ||
        /^0{32}$/u.test(value.invocation_id)) {
      fail(`${label} must be one live non-zero systemd generation`);
    }
  } else if (value.active_state !== "inactive" || value.sub_state !== "dead" ||
      value.main_pid !== "0" || !["", "0".repeat(32)].includes(value.invocation_id)) {
    fail(`${label} must be inactive/dead with no process generation`);
  }
}

const PUBLISHER_NETNS_FAILED_RESULTS = Object.freeze(new Set([
  "assert",
  "core-dump",
  "exit-code",
  "oom-kill",
  "protocol",
  "resources",
  "signal",
  "start-limit-hit",
  "timeout",
  "watchdog",
]));

export function validatePublisherNetnsFailedUnitV1(value, label = "failed publisher namespace unit") {
  exactKeys(value, [
    "active_enter_timestamp_monotonic", "active_state", "exec_main_code",
    "exec_main_status", "inactive_enter_timestamp_monotonic", "invocation_id",
    "load_state", "main_pid", "name", "need_daemon_reload", "result",
    "state_change_timestamp_monotonic", "sub_state",
  ], label);
  for (const key of [
    "active_enter_timestamp_monotonic", "exec_main_code", "exec_main_status",
    "inactive_enter_timestamp_monotonic", "main_pid", "state_change_timestamp_monotonic",
  ]) validateDecimal(value[key], `${label}.${key}`);
  const activeEnter = BigInt(value.active_enter_timestamp_monotonic);
  const inactiveEnter = BigInt(value.inactive_enter_timestamp_monotonic);
  const stateChange = BigInt(value.state_change_timestamp_monotonic);
  const terminalTimestampRelation =
    inactiveEnter > 0n &&
    inactiveEnter === stateChange &&
    (activeEnter === 0n || (activeEnter > 0n && activeEnter < inactiveEnter));
  if (
    value.name !== NETNS_UNIT ||
    value.load_state !== "loaded" ||
    value.need_daemon_reload !== "no" ||
    value.active_state !== "failed" ||
    value.sub_state !== "failed" ||
    value.main_pid !== "0" ||
    !terminalTimestampRelation ||
    !/^[0-9a-f]{32}$/u.test(value.invocation_id) ||
    /^0{32}$/u.test(value.invocation_id) ||
    !PUBLISHER_NETNS_FAILED_RESULTS.has(value.result)
  ) {
    fail(`${label} is not one terminal failed/failed systemd invocation`);
  }
  return true;
}

export function computePublisherNetnsFailedUnitSha256V1(value) {
  validatePublisherNetnsFailedUnitV1(value);
  return sha256(Buffer.from(canonicalPublisherNetnsJsonV2(value), "utf8"));
}

function expectedLoadedExec(plan) {
  const helper = plan.installed_files.find((entry) => entry.id === "helper-binary")?.pin;
  if (helper === undefined) fail("loaded namespace unit lacks its helper pin");
  return {
    start: [{ argv: `${helper.path} run`, ignore_errors: "no", path: helper.path }],
    start_pre: [
      { argv: `/usr/bin/test -x ${helper.path}`, ignore_errors: "no", path: "/usr/bin/test" },
      {
        argv: "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/publisher-netns/helper.sha256",
        ignore_errors: "no",
        path: "/usr/bin/sha256sum",
      },
      { argv: `${helper.path} self-test`, ignore_errors: "no", path: helper.path },
    ],
    stop_post: [{ argv: `${helper.path} cleanup`, ignore_errors: "no", path: helper.path }],
  };
}

function expectedLoadedServicePolicy() {
  return {
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
  };
}

function validateCanonicalWordSet(value, label) {
  if (!Array.isArray(value) || value.some((entry, index) =>
    typeof entry !== "string" || entry.length < 1 || /[\0\r\n\t ]/u.test(entry) ||
    (index > 0 && value[index - 1] >= entry))) {
    fail(`${label} must be a unique sorted non-empty systemd word set`);
  }
}

function validateLoadedNetnsUnit(value, plan, label) {
  exactKeys(value, [
    "condition_paths", "condition_source", "dropin_paths", "exec", "fragment_path",
    "need_daemon_reload", "relationships", "service",
  ], label);
  if (value.fragment_path !== NETNS_UNIT_FRAGMENT || !same(value.dropin_paths, []) ||
      value.need_daemon_reload !== "no" ||
      value.condition_source !== "exact-fragment-pin-plus-NeedDaemonReload=no" ||
      !same(value.condition_paths, PUBLISHER_NETNS_SENTINELS) ||
      !same(value.exec, expectedLoadedExec(plan)) ||
      !same(value.service, expectedLoadedServicePolicy())) {
    fail(`${label} drifted from the exact loaded publisher namespace unit policy`);
  }
  exactKeys(value.relationships,
    ["after", "before", "binds_to", "part_of", "requires", "wants"],
    `${label}.relationships`);
  for (const key of ["after", "before", "binds_to", "part_of", "requires", "wants"]) {
    validateCanonicalWordSet(value.relationships[key], `${label}.relationships.${key}`);
  }
  if (!value.relationships.after.includes("local-fs.target") ||
      !value.relationships.before.includes(CADDY_UNIT) ||
      !value.relationships.before.includes("bitcoinpir-payment-v1-source-fair-edge.service") ||
      !same(value.relationships.binds_to, []) ||
      !same(value.relationships.part_of, [CADDY_UNIT]) ||
      !same(value.relationships.requires, []) || !same(value.relationships.wants, [])) {
    fail(`${label}.relationships drifted from the reviewed one-way ordering contract`);
  }
}

function validateManagerGeneration(value, label) {
  exactKeys(value, [
    "generators_finish_timestamp_monotonic", "generators_start_timestamp_monotonic",
    "pid1_exe_device", "pid1_exe_inode", "pid1_exe_path", "pid1_start_ticks",
    "units_load_finish_timestamp_monotonic", "units_load_start_timestamp_monotonic",
  ], label);
  for (const key of [
    "generators_finish_timestamp_monotonic", "generators_start_timestamp_monotonic",
    "pid1_exe_device", "pid1_exe_inode", "pid1_start_ticks",
    "units_load_finish_timestamp_monotonic", "units_load_start_timestamp_monotonic",
  ]) validateDecimal(value[key], `${label}.${key}`, { nonzero: true });
  validateCanonicalAbsolute(value.pid1_exe_path, `${label}.pid1_exe_path`);
}

function validateCaddyState(value, label) {
  exactKeys(value, ["config", "dependency", "unit"], label);
  validateFilePin(value.config, `${label}.config`, {
    paths: ["/etc/caddy/Caddyfile"], modes: ["0644"],
  });
  validateUnitState(value.unit, `${label}.unit`, {
    active: true, name: CADDY_UNIT,
  });
  exactKeys(value.dependency, [
    "after_namespace_owner", "binds_to_namespace_owner", "drop_in_paths",
    "part_of_namespace_owner", "requires_namespace_owner", "wants_namespace_owner",
  ], `${label}.dependency`);
  if (value.dependency.after_namespace_owner !== true ||
      value.dependency.wants_namespace_owner !== true ||
      value.dependency.binds_to_namespace_owner !== false ||
      value.dependency.part_of_namespace_owner !== false ||
      value.dependency.requires_namespace_owner !== false ||
      !same(value.dependency.drop_in_paths, [CADDY_NETNS_DROP_IN])) {
    fail(`${label}.dependency is not the exact loaded one-way namespace relation`);
  }
}

function validateTopology(value) {
  exactKeys(value, [
    "address_family", "client_address", "client_interface", "default_route", "forwarding",
    "host_address", "host_interface", "host_port", "hosts_path", "namespace_name",
    "namespace_path", "nat", "prefix_length", "publisher_hostname",
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
    fail("topology namespace and hosts paths must derive from the exact namespace name");
  }
  validateCanonicalAbsolute(value.namespace_path, "topology.namespace_path");
  validateCanonicalAbsolute(value.hosts_path, "topology.hosts_path");
  validateDnsHost(value.publisher_hostname, "topology.publisher_hostname");
  validatePrivatePair(value);
  if (value.default_route !== false || value.forwarding !== false || value.nat !== false ||
      value.host_port !== 443) {
    fail("topology must close default routing, forwarding and NAT and fix publisher port 443");
  }
  if (!same(value, {
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
  const helper = plan.installed_files.find((entry) => entry.id === "helper-binary")?.pin;
  return new Map([
    ["caddy-netns-dropin", CADDY_NETNS_DROP_IN],
    ["directory-publisher-unit", "/etc/systemd/system/bitcoinpir-payment-v1-directory-publisher.service"],
    ["helper-binary", `/opt/bitcoinpir/publisher-netns/${helper?.sha256 ?? "invalid"}/payment-v1-publisher-netns`],
    ["helper-manifest", "/etc/bitcoinpir/payment-v1/publisher-netns/helper.sha256"],
    ["netns-hosts", plan.topology.hosts_path],
    ["netns-nsswitch", `/etc/netns/${plan.topology.namespace_name}/nsswitch.conf`],
    ["netns-resolv", `/etc/netns/${plan.topology.namespace_name}/resolv.conf`],
    ["network-inputs-manifest", "/etc/bitcoinpir/payment-v1/directory-publisher/network-inputs.sha256"],
    ["network-policy", "/etc/bitcoinpir/payment-v1/directory-publisher/network-policy.json"],
    ["publisher-netns-unit", NETNS_UNIT_FRAGMENT],
  ]);
}

function validateInstalledFiles(plan) {
  if (!Array.isArray(plan.installed_files) ||
      plan.installed_files.length !== EXPECTED_FILE_IDS.length) {
    fail("installed_files must contain the exact closed publisher-network set");
  }
  exactArray(plan.installed_files.map((entry) => entry.id), EXPECTED_FILE_IDS,
    "installed_files canonical id order");
  const paths = expectedInstalledPaths(plan);
  for (const entry of plan.installed_files) {
    exactKeys(entry, ["id", "pin"], `installed_files.${entry.id}`);
    const binary = entry.id === "helper-binary";
    validateFilePin(entry.pin, `installed_files.${entry.id}.pin`, {
      paths: [paths.get(entry.id)],
      modes: binary ? ["0555"] :
        entry.id.endsWith("unit") || entry.id === "caddy-netns-dropin" ? ["0644"] : ["0444"],
    });
  }
  const helper = plan.installed_files.find((entry) => entry.id === "helper-binary").pin;
  if (helper.path.split("/").at(-2) !== helper.sha256) {
    fail("helper binary content-address directory must equal its SHA-256");
  }
}

function validateRuntime(runtime) {
  exactKeys(runtime, [
    "executor", "health_probe", "integrated_caddy_gate", "ip", "launcher", "launcher_manifest", "node",
    "node_loader_closure_manifest", "publisher_netns_gate", "schema_validator", "systemctl",
  ], "runtime");
  const specifications = [
    ["launcher", [`/opt/bitcoinpir/publisher-netns-launcher/${runtime.launcher.sha256}/payment-v1-publisher-netns-launcher`], ["0555"]],
    ["launcher_manifest", ["/etc/bitcoinpir/payment-v1/publisher-netns/launcher-inputs.sha256"], ["0444"]],
    ["node_loader_closure_manifest", [PUBLISHER_NODE_LOADER_CLOSURE_PATH], ["0444"]],
    ["executor", ["/usr/local/libexec/bitcoinpir/payment-v1-publisher-netns-ceremony.mjs"], ["0555"]],
    ["health_probe", ["/usr/local/libexec/bitcoinpir/payment-v1-publisher-private-health-probe.mjs"], ["0555"]],
    ["integrated_caddy_gate", ["/usr/local/libexec/bitcoinpir/payment-v1-integrated-caddy-overlay-gate.mjs"], ["0555"]],
    ["publisher_netns_gate", ["/usr/local/libexec/bitcoinpir/payment-v1-publisher-netns-gate.mjs"], ["0555"]],
    ["schema_validator", [SCHEMA_VALIDATOR_PATH], ["0555"]],
    ["node", ["/usr/bin/node"], ["0555", "0755"]],
    ["systemctl", ["/usr/bin/systemctl"], ["0555", "0755"]],
    ["ip", ["/usr/bin/ip"], ["0555", "0755"]],
  ];
  for (const [name, paths, modes] of specifications) {
    validateFilePin(runtime[name], `runtime.${name}`, { paths, modes });
  }
}

export function expectedPublisherNetnsLauncherManifestBytesV2(runtime) {
  return Buffer.from([
    runtime.node,
    runtime.integrated_caddy_gate,
    runtime.executor,
    runtime.publisher_netns_gate,
    runtime.schema_validator,
    runtime.health_probe,
    runtime.node_loader_closure_manifest,
  ].map((pin) => `${pin.sha256}  ${pin.path}\n`).join(""), "utf8");
}

export function inspectStaticElfV1(bytes) {
  const input = Buffer.from(bytes);
  if (input.length < 64 || input[0] !== 0x7f || input.subarray(1, 4).toString("ascii") !== "ELF" ||
      input[4] !== 2 || input[5] !== 1 || input[6] !== 1 ||
      input.readUInt16LE(16) !== 2 || ![62, 183].includes(input.readUInt16LE(18)) ||
      input.readUInt32LE(20) !== 1 || input.readUInt16LE(52) !== 64 ||
      input.readUInt16LE(54) !== 56) {
    fail("launcher is not a reviewed ELF64 little-endian ET_EXEC format");
  }
  const phoff = input.readBigUInt64LE(32);
  const phnum = input.readUInt16LE(56);
  if (phnum < 1 || phnum > 128 || phoff > BigInt(Number.MAX_SAFE_INTEGER)) {
    fail("launcher ELF program-header table is outside the reviewed bounds");
  }
  const offset = Number(phoff);
  if (offset < 64 || offset + phnum * 56 > input.length) {
    fail("launcher ELF program-header table exceeds the pinned file");
  }
  let dynamic = false;
  let interpreter = false;
  for (let index = 0; index < phnum; index += 1) {
    const type = input.readUInt32LE(offset + index * 56);
    dynamic ||= type === 2;
    interpreter ||= type === 3;
  }
  if (dynamic || interpreter) {
    fail("launcher ELF contains PT_DYNAMIC or PT_INTERP and is not statically sealed");
  }
  return {
    byte_order: "little-endian",
    elf_class: "ELF64",
    machine: input.readUInt16LE(18) === 62 ? "EM_X86_64" : "EM_AARCH64",
    object_type: "ET_EXEC",
    program_header_count: phnum,
    pt_dynamic: false,
    pt_interp: false,
    sha256: sha256(input),
  };
}

function boundedElfRange(input, offsetValue, sizeValue, label) {
  if (
    offsetValue > BigInt(Number.MAX_SAFE_INTEGER) ||
    sizeValue > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    fail(`${label} exceeds the reviewed ELF offset range`);
  }
  const offset = Number(offsetValue);
  const size = Number(sizeValue);
  if (offset < 0 || size < 0 || offset + size > input.length) {
    fail(`${label} exceeds the pinned ELF bytes`);
  }
  return { offset, size };
}

function dynamicElfString(table, offset, label) {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset >= table.length) {
    fail(`${label} offset exceeds the ELF dynamic string table`);
  }
  const end = table.indexOf(0, offset);
  if (end < 0) fail(`${label} is not NUL terminated`);
  const bytes = table.subarray(offset, end);
  if ([...bytes].some((value) => value > 0x7f)) {
    fail(`${label} is not strict ASCII`);
  }
  const value = bytes.toString("ascii");
  if (!/^[A-Za-z0-9][A-Za-z0-9+_.-]{0,254}$/u.test(value)) {
    fail(`${label} is not one canonical dependency name`);
  }
  return value;
}

export function inspectDynamicElfV1(bytes) {
  const input = Buffer.from(bytes);
  if (
    input.length < 64 || input.length > 512 * 1024 * 1024 ||
    input[0] !== 0x7f || input.subarray(1, 4).toString("ascii") !== "ELF" ||
    input[4] !== 2 || input[5] !== 1 || input[6] !== 1 ||
    ![2, 3].includes(input.readUInt16LE(16)) || input.readUInt16LE(18) !== 62 ||
    input.readUInt32LE(20) !== 1 || input.readUInt16LE(52) !== 64 ||
    input.readUInt16LE(54) !== 56
  ) {
    fail("Node loader object is not a reviewed ELF64 little-endian x86-64 image");
  }
  const phoff = input.readBigUInt64LE(32);
  const phnum = input.readUInt16LE(56);
  if (phnum < 1 || phnum > 256) fail("Node loader ELF has an invalid program-header count");
  const phdrs = boundedElfRange(input, phoff, BigInt(phnum * 56), "Node loader program headers");
  const loads = [];
  let dynamic = null;
  let interpreter = null;
  for (let index = 0; index < phnum; index += 1) {
    const offset = phdrs.offset + index * 56;
    const type = input.readUInt32LE(offset);
    const fileOffset = input.readBigUInt64LE(offset + 8);
    const virtualAddress = input.readBigUInt64LE(offset + 16);
    const fileSize = input.readBigUInt64LE(offset + 32);
    boundedElfRange(input, fileOffset, fileSize, `Node loader program header[${index}]`);
    if (type === 1) {
      loads.push({ fileOffset, fileSize, virtualAddress });
    } else if (type === 2) {
      if (dynamic !== null) fail("Node loader ELF contains duplicate PT_DYNAMIC segments");
      dynamic = { fileOffset, fileSize };
    } else if (type === 3) {
      if (interpreter !== null) fail("Node loader ELF contains duplicate PT_INTERP segments");
      const range = boundedElfRange(input, fileOffset, fileSize, "Node loader PT_INTERP");
      if (
        range.size < 2 || range.size > 4096 || input[range.offset + range.size - 1] !== 0 ||
        input.subarray(range.offset, range.offset + range.size - 1).includes(0) ||
        [...input.subarray(range.offset, range.offset + range.size - 1)]
          .some((value) => value > 0x7f)
      ) {
        fail("Node loader PT_INTERP is not one bounded strict-ASCII NUL-terminated path");
      }
      interpreter = input.subarray(range.offset, range.offset + range.size - 1).toString("ascii");
      validateCanonicalAbsolute(interpreter, "Node loader PT_INTERP");
    }
  }
  if (dynamic === null || dynamic.fileSize < 16n || dynamic.fileSize % 16n !== 0n) {
    fail("Node loader ELF has no canonical PT_DYNAMIC table");
  }
  const dynamicRange = boundedElfRange(
    input,
    dynamic.fileOffset,
    dynamic.fileSize,
    "Node loader PT_DYNAMIC",
  );
  let stringTableAddress = null;
  let stringTableSize = null;
  let sonameOffset = null;
  const neededOffsets = [];
  const dynamicTags = [];
  let terminated = false;
  const forbiddenDynamicTags = new Map([
    [15n, "DT_RPATH"],
    [29n, "DT_RUNPATH"],
    [0x6ffffefbn, "DT_DEPAUDIT"],
    [0x6ffffefcn, "DT_AUDIT"],
    [0x7ffffffdn, "DT_AUXILIARY"],
    [0x7fffffffn, "DT_FILTER"],
  ]);
  for (let offset = dynamicRange.offset; offset < dynamicRange.offset + dynamicRange.size; offset += 16) {
    const tag = input.readBigInt64LE(offset);
    const value = input.readBigUInt64LE(offset + 8);
    if (tag === 0n) {
      terminated = true;
      break;
    }
    dynamicTags.push(tag.toString());
    const forbiddenTag = forbiddenDynamicTags.get(tag);
    if (forbiddenTag !== undefined) {
      fail(`Node loader ELF contains forbidden dependency-injection tag ${forbiddenTag}`);
    }
    if (tag === 1n) neededOffsets.push(value);
    if (tag === 5n) {
      if (stringTableAddress !== null) fail("Node loader ELF contains duplicate DT_STRTAB");
      stringTableAddress = value;
    }
    if (tag === 10n) {
      if (stringTableSize !== null) fail("Node loader ELF contains duplicate DT_STRSZ");
      stringTableSize = value;
    }
    if (tag === 14n) {
      if (sonameOffset !== null) fail("Node loader ELF contains duplicate DT_SONAME");
      sonameOffset = value;
    }
  }
  if (!terminated || stringTableAddress === null || stringTableSize === null ||
      stringTableSize < 1n || stringTableSize > 16n * 1024n * 1024n) {
    fail("Node loader ELF dynamic string-table metadata is incomplete");
  }
  const containingLoads = loads.filter((load) =>
    stringTableAddress >= load.virtualAddress &&
    stringTableAddress + stringTableSize <= load.virtualAddress + load.fileSize);
  if (containingLoads.length !== 1) {
    fail("Node loader ELF dynamic string table is not in one file-backed PT_LOAD segment");
  }
  const load = containingLoads[0];
  const tableOffset = load.fileOffset + (stringTableAddress - load.virtualAddress);
  const tableRange = boundedElfRange(input, tableOffset, stringTableSize, "Node loader string table");
  const table = input.subarray(tableRange.offset, tableRange.offset + tableRange.size);
  const needed = neededOffsets.map((offset, index) =>
    dynamicElfString(table, Number(offset), `Node loader DT_NEEDED[${index}]`));
  if (new Set(needed).size !== needed.length) {
    fail("Node loader ELF contains duplicate DT_NEEDED entries");
  }
  const soname = sonameOffset === null
    ? null
    : dynamicElfString(table, Number(sonameOffset), "Node loader DT_SONAME");
  return {
    architecture: "elf64-le-x86_64",
    dynamic_tags: [...new Set(dynamicTags)].sort((left, right) => {
      const leftValue = BigInt(left);
      const rightValue = BigInt(right);
      return leftValue < rightValue ? -1 : leftValue > rightValue ? 1 : 0;
    }),
    needed: [...needed].sort(),
    object_type: input.readUInt16LE(16) === 2 ? "ET_EXEC" : "ET_DYN",
    pt_interp: interpreter,
    soname,
  };
}

function canonicalPublisherNodeElfLoadOrderV1(value) {
  const bySoname = new Map(value.objects.map((object) => [object.soname, object]));
  const interpreter = value.interpreter_soname;
  const visited = new Set([interpreter]);
  const visiting = new Set();
  const order = [interpreter];
  const visit = (soname) => {
    if (visited.has(soname)) return;
    if (visiting.has(soname)) {
      fail("node_elf_closure contains a dependency cycle not anchored at the interpreter");
    }
    const object = bySoname.get(soname);
    if (object === undefined) {
      fail(`node_elf_closure is missing recursively required object ${soname}`);
    }
    visiting.add(soname);
    for (const needed of object.needed) visit(needed);
    visiting.delete(soname);
    visited.add(soname);
    order.push(soname);
  };
  const interpreterObject = bySoname.get(interpreter);
  if (interpreterObject === undefined) {
    fail("node_elf_closure is missing its interpreter object");
  }
  for (const needed of interpreterObject.needed) visit(needed);
  for (const needed of value.node_needed) visit(needed);
  if (visited.size !== value.objects.length) {
    fail("node_elf_closure contains an unreachable preload object");
  }
  return order;
}

export function expectedPublisherNodeLoaderClosureManifestBytesV1(closure) {
  return Buffer.from(
    closure.objects.map((object) => `${object.pin.sha256}  ${object.pin.path}\n`).join(""),
    "utf8",
  );
}

function validatePublisherNodeElfClosureV1(value, runtime) {
  exactKeys(value, [
    "activation_state", "architecture", "interpreter_soname", "kind", "node_needed",
    "objects", "pt_interp", "schema_version",
  ], "node_elf_closure");
  if (
    value.schema_version !== 1 || value.kind !== PUBLISHER_NODE_ELF_CLOSURE_KIND ||
    value.architecture !== "elf64-le-x86_64" ||
    value.activation_state !==
      "descriptor-pinned-loader-recursive-needed-closure-and-double-maps-sampling" ||
    value.pt_interp !== "/lib64/ld-linux-x86-64.so.2" ||
    value.interpreter_soname !== "ld-linux-x86-64.so.2" ||
    !Array.isArray(value.node_needed) || value.node_needed.length < 2 ||
    !Array.isArray(value.objects) || value.objects.length < 2 || value.objects.length > 32
  ) {
    fail("node_elf_closure does not use the reviewed Hetzner x86-64 loader profile");
  }
  if (
    !Array.isArray(value.node_needed) ||
    !value.node_needed.every((name) => /^[A-Za-z0-9][A-Za-z0-9+_.-]{0,254}$/u.test(name)) ||
    new Set(value.node_needed).size !== value.node_needed.length ||
    canonicalPublisherNetnsJsonV2(value.node_needed) !==
      canonicalPublisherNetnsJsonV2([...value.node_needed].sort())
  ) {
    fail("node_elf_closure.node_needed is not one sorted unique SONAME set");
  }
  const sonames = [];
  const paths = [];
  for (const [index, object] of value.objects.entries()) {
    const label = `node_elf_closure.objects[${index}]`;
    exactKeys(object, ["needed", "pin", "soname"], label);
    if (typeof object.soname !== "string" ||
        !/^[A-Za-z0-9][A-Za-z0-9+_.-]{0,254}$/u.test(object.soname)) {
      fail(`${label}.soname is malformed`);
    }
    if (!Array.isArray(object.needed) ||
        !object.needed.every((name) => /^[A-Za-z0-9][A-Za-z0-9+_.-]{0,254}$/u.test(name)) ||
        new Set(object.needed).size !== object.needed.length ||
        canonicalPublisherNetnsJsonV2(object.needed) !==
          canonicalPublisherNetnsJsonV2([...object.needed].sort())) {
      fail(`${label}.needed is not one sorted unique SONAME set`);
    }
    validateFilePin(object.pin, `${label}.pin`, {
      paths: [object.pin.path], modes: ["0444", "0555", "0644", "0755"],
    });
    if (!object.pin.path.startsWith("/usr/lib/x86_64-linux-gnu/") ||
        object.pin.path.slice("/usr/lib/x86_64-linux-gnu/".length).includes("/") ||
        !object.pin.path.split("/").at(-1).startsWith(object.soname)) {
      fail(`${label}.pin is outside the reviewed resolved host ABI directory`);
    }
    sonames.push(object.soname);
    paths.push(object.pin.path);
  }
  if (
    new Set(sonames).size !== sonames.length || new Set(paths).size !== paths.length ||
    !sonames.includes(value.interpreter_soname) ||
    value.node_needed.some((name) => !sonames.includes(name)) ||
    value.objects.some((object) => object.needed.some((name) => !sonames.includes(name)))
  ) {
    fail("node_elf_closure is not one unique and recursively closed object set");
  }
  if (
    value.objects[0].soname !== value.interpreter_soname ||
    value.objects[0].needed.length !== 0
  ) {
    fail("node_elf_closure interpreter must be the dependency-free explicit loader");
  }
  const canonicalLoadOrder = canonicalPublisherNodeElfLoadOrderV1(value);
  if (
    canonicalPublisherNetnsJsonV2(sonames) !== canonicalPublisherNetnsJsonV2(canonicalLoadOrder) ||
    value.objects[0].pin.path !==
      "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" ||
    value.objects.some((object, index) => index > 0 && object.needed.some((needed) =>
      needed !== value.interpreter_soname &&
      canonicalLoadOrder.indexOf(needed) >= index))
  ) {
    fail("node_elf_closure is not in canonical dependency-first preload order");
  }
  if (runtime.node_loader_closure_manifest.sha256 !==
      sha256(expectedPublisherNodeLoaderClosureManifestBytesV1(value))) {
    fail("Node loader closure manifest digest does not equal the plan-bound object closure");
  }
}

export function validatePublisherNodeElfClosureBytesV1({ closure, nodeBytes, objectBytes }) {
  const node = inspectDynamicElfV1(nodeBytes);
  if (
    node.pt_interp !== closure.pt_interp || node.soname !== null ||
    canonicalPublisherNetnsJsonV2(node.needed) !== canonicalPublisherNetnsJsonV2(closure.node_needed)
  ) {
    fail("pinned Node ELF PT_INTERP or direct DT_NEEDED set differs from its approved closure");
  }
  if (!(objectBytes instanceof Map) || objectBytes.size !== closure.objects.length) {
    fail("Node loader object byte closure is incomplete");
  }
  const objects = closure.objects.map((object, index) => {
    const bytes = objectBytes.get(object.pin.path);
    if (!Buffer.isBuffer(bytes) || sha256(bytes) !== object.pin.sha256) {
      fail(`Node loader object bytes differ from the approved pin: ${object.pin.path}`);
    }
    const inspection = inspectDynamicElfV1(bytes);
    if (
      (index === 0
        ? inspection.pt_interp !== null || inspection.needed.length !== 0
        : ![null, closure.pt_interp].includes(inspection.pt_interp)) ||
      inspection.soname !== object.soname ||
      canonicalPublisherNetnsJsonV2(inspection.needed) !==
        canonicalPublisherNetnsJsonV2(object.needed)
    ) {
      fail(`Node loader object ELF metadata differs from its approved closure: ${object.pin.path}`);
    }
    return { path: object.pin.path, ...inspection };
  });
  return { node, objects };
}

function validateLauncherStaticElfEvidence(value, launcherSha256) {
  exactKeys(value, [
    "byte_order", "elf_class", "machine", "object_type", "program_header_count",
    "pt_dynamic", "pt_interp", "sha256",
  ], "launcher_static_elf");
  if (value.byte_order !== "little-endian" || value.elf_class !== "ELF64" ||
      value.machine !== "EM_X86_64" || value.object_type !== "ET_EXEC" ||
      !Number.isSafeInteger(value.program_header_count) ||
      value.program_header_count < 1 || value.program_header_count > 128 ||
      value.pt_dynamic !== false || value.pt_interp !== false ||
      value.sha256 !== launcherSha256) {
    fail("launcher_static_elf is not the machine-verifiable static launcher proof");
  }
}

function validateTransaction(value, ceremonyId) {
  exactKeys(value,
    ["lock_path", "receipt_path", "rollback_receipt_path", "state_directory"],
    "transaction");
  const root = "/var/lib/bitcoinpir/payment-v1/publisher-netns";
  const expected = {
    lock_path: PUBLISHER_NETNS_LIFECYCLE_LOCK,
    receipt_path: `${root}/receipts/${ceremonyId}.json`,
    rollback_receipt_path: `${root}/receipts/${ceremonyId}.rollback.json`,
    state_directory: `${root}/transactions/${ceremonyId}`,
  };
  if (!same(value, expected)) fail("transaction paths drifted");
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
          forbiddenPublisherKey.test(value)) fail(`${path} contains a forbidden private key`);
    } else if (Array.isArray(value)) {
      value.forEach((entry, index) => visit(entry, `${path}[${index}]`));
    } else if (isPlainObject(value)) {
      for (const [key, entry] of Object.entries(value)) {
        if (path === "plan" && key === "publisher_private_key_installed") continue;
        if (forbiddenName.test(key) || forbiddenPublisherKey.test(key)) {
          fail(`${path}.${key} is a forbidden payment/query correlation field`);
        }
        visit(entry, `${path}.${key}`);
      }
    }
  };
  visit(plan);
}

export function validatePublisherNetnsPlanV2(plan) {
  exactKeys(plan, [
    "activation_sentinels", "caddy_preimage", "ceremony_id", "firewall_evidence", "host",
    "installed_files", "kind", "launcher_static_elf", "node_elf_closure", "preimage",
    "publisher_private_key_installed", "relationship", "runtime", "schema_version",
    "source_commit", "topology", "transaction",
  ], "plan");
  if (plan.schema_version !== PUBLISHER_NETNS_PLAN_SCHEMA_VERSION ||
      plan.kind !== PUBLISHER_NETNS_CEREMONY_KIND) fail("plan kind/schema drifted");
  validateSlug(plan.ceremony_id, "plan.ceremony_id");
  if (typeof plan.source_commit !== "string" || !/^[0-9a-f]{40}$/u.test(plan.source_commit)) {
    fail("plan.source_commit must be an exact lowercase Git commit");
  }
  validateTopology(plan.topology);
  validateInstalledFiles(plan);
  validateRuntime(plan.runtime);
  validateLauncherStaticElfEvidence(plan.launcher_static_elf, plan.runtime.launcher.sha256);
  validatePublisherNodeElfClosureV1(plan.node_elf_closure, plan.runtime);
  rejectSecretSurface(plan);
  if (!Array.isArray(plan.activation_sentinels) ||
      plan.activation_sentinels.length !== PUBLISHER_NETNS_SENTINELS.length) {
    fail("activation_sentinels must close the exact externally provisioned set");
  }
  exactArray(plan.activation_sentinels.map((pin) => pin.path),
    PUBLISHER_NETNS_SENTINELS, "activation_sentinels canonical path order");
  for (const [index, pin] of plan.activation_sentinels.entries()) {
    validateFilePin(pin, `activation_sentinels[${index}]`, {
      paths: [PUBLISHER_NETNS_SENTINELS[index]], modes: ["0400"],
    });
  }
  validateFilePin(plan.firewall_evidence, "firewall_evidence", {
    paths: ["/var/lib/bitcoinpir/payment-v1/publisher-netns/evidence/firewall.json"],
    modes: ["0400"],
  });
  exactKeys(plan.host,
    ["boot_id", "machine_id_sha256", "systemd_manager_generation", "systemd_version"],
    "host");
  if (!/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u.test(plan.host.boot_id)) {
    fail("host.boot_id is malformed");
  }
  validateSha256(plan.host.machine_id_sha256, "host.machine_id_sha256");
  if (typeof plan.host.systemd_version !== "string" ||
      !/^systemd 255(?: \(255\.[0-9]+-[^)]+\))?$/u.test(plan.host.systemd_version)) {
    fail("host.systemd_version must be the exact reviewed systemd 255 line");
  }
  validateManagerGeneration(plan.host.systemd_manager_generation,
    "host.systemd_manager_generation");
  validateCaddyState(plan.caddy_preimage, "caddy_preimage");
  exactKeys(plan.preimage,
    ["host_interface", "loaded_netns_unit", "namespace_path", "netns_unit", "publisher_unit"],
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
  validateLoadedNetnsUnit(plan.preimage.loaded_netns_unit, plan,
    "preimage.loaded_netns_unit");
  exactKeys(plan.relationship, [
    "caddy_dependency", "integrated_profile", "network_before_caddy",
    "publisher_requires_namespace", "receipt_generation_scope", "reboot_recreation",
    "reverse_stop_propagation",
  ], "relationship");
  if (!same(plan.relationship, {
    caddy_dependency: "Wants+After",
    integrated_profile: "integrated-existing-bhtm-caddy-v1",
    network_before_caddy: true,
    publisher_requires_namespace: true,
    receipt_generation_scope: "exact-boot-and-systemd-generation",
    reboot_recreation: "caddy-wants-after-persistent-sentinels",
    reverse_stop_propagation: false,
  })) fail("relationship does not equal the reviewed one-way Caddy ordering contract");
  validateTransaction(plan.transaction, plan.ceremony_id);
  return true;
}

export function computePublisherNetnsPlanSha256V2(plan) {
  validatePublisherNetnsPlanV2(plan);
  return sha256(Buffer.from(canonicalPublisherNetnsJsonV2(plan), "utf8"));
}

function parseUtc(value, label) {
  if (typeof value !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u.test(value)) {
    fail(`${label} must be whole-second UTC`);
  }
  const millis = Date.parse(value);
  if (!Number.isSafeInteger(millis) ||
      new Date(millis).toISOString() !== value.replace("Z", ".000Z")) {
    fail(`${label} is not canonical UTC`);
  }
  return Math.floor(millis / 1000);
}

export function validatePublisherNetnsApprovalV2({
  approval, approvedPlanSha256, nowUnix, plan, rollback = false,
}) {
  const expectedKeys = rollback ? [
    "acknowledgements", "approved_at_utc", "approved_by", "ceremony_id",
    "committed_receipt_sha256", "decision", "executor_sha256", "expires_at_utc",
    "kind", "launcher_manifest_sha256", "launcher_sha256", "plan_sha256", "schema_version",
  ] : [
    "acknowledgements", "approved_at_utc", "approved_by", "ceremony_id", "decision",
    "executor_sha256", "expires_at_utc", "kind", "launcher_manifest_sha256",
    "launcher_sha256", "plan_sha256", "schema_version",
  ];
  exactKeys(approval, expectedKeys, rollback ? "rollback approval" : "apply approval");
  if (approval.schema_version !== 2 || approval.kind !== (rollback ?
    PUBLISHER_NETNS_ROLLBACK_APPROVAL_KIND : PUBLISHER_NETNS_APPLY_APPROVAL_KIND) ||
    approval.ceremony_id !== plan.ceremony_id || approval.plan_sha256 !== approvedPlanSha256 ||
    approval.executor_sha256 !== plan.runtime.executor.sha256 ||
    approval.launcher_sha256 !== plan.runtime.launcher.sha256 ||
    approval.launcher_manifest_sha256 !== plan.runtime.launcher_manifest.sha256) {
    fail("approval binding drifted from identity, schema or closed inputs");
  }
  if (typeof approval.approved_by !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$/u.test(approval.approved_by)) {
    fail("approval approved_by identifier is malformed");
  }
  exactArray(approval.acknowledgements, rollback ?
    PUBLISHER_NETNS_ROLLBACK_ACKNOWLEDGEMENTS : PUBLISHER_NETNS_APPLY_ACKNOWLEDGEMENTS,
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

export function validatePublisherNetnsFailedRecoveryApprovalV1({
  approval, approvedPlanSha256, nowUnix, plan,
}) {
  validatePublisherNetnsPlanV2(plan);
  exactKeys(approval, [
    "acknowledgements", "activation_approval_sha256", "approved_at_utc", "approved_by",
    "ceremony_id", "decision", "executor_sha256", "expires_at_utc", "failed_unit",
    "failed_unit_sha256", "kind", "launcher_manifest_sha256", "launcher_sha256",
    "plan_sha256", "reset_failed_argv", "schema_version", "start_intent_sha256",
  ], "failed-start recovery approval");
  if (
    approval.schema_version !== 1 ||
    approval.kind !== PUBLISHER_NETNS_FAILED_RECOVERY_APPROVAL_KIND ||
    approval.ceremony_id !== plan.ceremony_id ||
    approval.plan_sha256 !== approvedPlanSha256 ||
    approvedPlanSha256 !== computePublisherNetnsPlanSha256V2(plan) ||
    approval.executor_sha256 !== plan.runtime.executor.sha256 ||
    approval.launcher_sha256 !== plan.runtime.launcher.sha256 ||
    approval.launcher_manifest_sha256 !== plan.runtime.launcher_manifest.sha256
  ) {
    fail("failed-start recovery approval binding drifted from identity or closed inputs");
  }
  if (typeof approval.approved_by !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$/u.test(approval.approved_by)) {
    fail("failed-start recovery approval approved_by identifier is malformed");
  }
  exactArray(
    approval.acknowledgements,
    PUBLISHER_NETNS_FAILED_RECOVERY_ACKNOWLEDGEMENTS,
    "failed-start recovery approval acknowledgements",
  );
  if (approval.decision !== "approve-reset-exact-failed-publisher-netns" ||
      !same(approval.reset_failed_argv, ["reset-failed", NETNS_UNIT])) {
    fail("failed-start recovery approval decision or fixed reset argv drifted");
  }
  for (const [value, label] of [
    [approval.activation_approval_sha256, "activation approval SHA-256"],
    [approval.failed_unit_sha256, "failed unit SHA-256"],
    [approval.start_intent_sha256, "start intent SHA-256"],
  ]) validateSha256(value, `failed-start recovery approval ${label}`);
  validatePublisherNetnsFailedUnitV1(
    approval.failed_unit,
    "failed-start recovery approval.failed_unit",
  );
  if (approval.failed_unit_sha256 !== computePublisherNetnsFailedUnitSha256V1(
    approval.failed_unit,
  )) fail("failed-start recovery approval failed-unit digest drifted");
  const approved = parseUtc(
    approval.approved_at_utc,
    "failed-start recovery approval.approved_at_utc",
  );
  const expires = parseUtc(
    approval.expires_at_utc,
    "failed-start recovery approval.expires_at_utc",
  );
  if (expires <= approved || expires - approved > MAX_APPROVAL_WINDOW_SECONDS ||
      nowUnix < approved - MAX_CLOCK_SKEW_SECONDS || nowUnix > expires) {
    fail("failed-start recovery approval is not currently valid within the one-hour window");
  }
  return true;
}

function isLocalUnicastMac(value) {
  return typeof value === "string" && /^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/u.test(value) &&
    (Number.parseInt(value.slice(0, 2), 16) & 3) === 2;
}

function validateRuntimeTopology(value, plan) {
  exactKeys(value, ["client", "forwarding_sysctls", "host", "namespace", "routes"],
    "runtime topology");
  exactKeys(value.namespace, [
    "device", "inert_interfaces", "inode", "interface_names", "loopback", "path", "type",
  ], "runtime topology.namespace");
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
    "runtime namespace exact interface set");
  exactKeys(value.namespace.loopback, ["addresses", "alias", "index", "up"],
    "runtime namespace.loopback");
  if (value.namespace.loopback.alias !== "" || value.namespace.loopback.up !== true ||
      !Number.isSafeInteger(value.namespace.loopback.index) || value.namespace.loopback.index < 1 ||
      !same(value.namespace.loopback.addresses,
        [{ family: "inet", local: "127.0.0.1", prefix_length: 8 }])) {
    fail("runtime namespace loopback identity/address set drifted");
  }
  for (const side of ["host", "client"]) {
    exactKeys(value[side], [
      "address", "alias", "index", "interface", "mac", "peer_index", "prefix_length", "up",
    ], `runtime topology.${side}`);
    if (value[side].interface !== plan.topology[`${side}_interface`] ||
        value[side].address !== plan.topology[`${side}_address`] ||
        value[side].prefix_length !== plan.topology.prefix_length || value[side].up !== true ||
        !isLocalUnicastMac(value[side].mac) || !Number.isSafeInteger(value[side].index) ||
        value[side].index < 1 || !Number.isSafeInteger(value[side].peer_index) ||
        value[side].peer_index < 1) fail(`runtime topology.${side} drifted`);
  }
  const hostAlias = value.host.alias.match(
    /^bitcoinpir-payment-v1-publisher-netns:([0-9a-f]{32}):host$/u,
  );
  if (hostAlias === null || value.client.alias !==
      `bitcoinpir-payment-v1-publisher-netns:${hostAlias[1]}:client` ||
      value.host.index === value.client.index || value.host.peer_index !== value.client.index ||
      value.client.peer_index !== value.host.index || new Set([
        value.client.index, value.namespace.loopback.index,
        ...value.namespace.inert_interfaces.map((link) => link.index),
      ]).size !== value.namespace.inert_interfaces.length + 2) {
    fail("runtime veth pair identity drifted");
  }
  exactKeys(value.forwarding_sysctls,
    ["net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"],
    "runtime forwarding sysctls");
  if (value.forwarding_sysctls["net.ipv4.ip_forward"] !== 0 ||
      value.forwarding_sysctls["net.ipv6.conf.all.forwarding"] !== 0) {
    fail("host forwarding must remain disabled");
  }
  exactKeys(value.routes, ["client_main", "host_main"], "runtime routes");
  for (const key of ["client_main", "host_main"]) {
    if (!Array.isArray(value.routes[key]) || value.routes[key].length !== 1) {
      fail(`${key} must contain only the connected publisher subnet route`);
    }
    exactKeys(value.routes[key][0], ["default", "destination", "gateway", "nat"],
      `runtime routes.${key}[0]`);
    const route = value.routes[key][0];
    if (route.default === true || route.gateway !== null || route.nat === true ||
        route.destination !== "10.203.0.0/30") {
      fail(`${key} contains a default, gateway or NAT route`);
    }
  }
}

export function validatePublisherNetnsReceiptV2({ receipt, plan, approvedPlanSha256 }) {
  validatePublisherNetnsPlanV2(plan);
  exactKeys(receipt, [
    "activation_approval_sha256", "approved_approval_sha256", "approved_plan_sha256",
    "caddy_after", "caddy_before", "ceremony_id", "firewall_evidence_sha256", "host",
    "installed_files", "kind", "loaded_netns_unit", "netns_unit", "outcome",
    "publisher_unit", "runtime", "schema_version", "sentinels", "topology",
  ], "receipt");
  if (receipt.schema_version !== PUBLISHER_NETNS_RECEIPT_SCHEMA_VERSION ||
      receipt.kind !== PUBLISHER_NETNS_RECEIPT_KIND || receipt.outcome !== "committed" ||
      receipt.ceremony_id !== plan.ceremony_id ||
      receipt.approved_plan_sha256 !== approvedPlanSha256 ||
      approvedPlanSha256 !== computePublisherNetnsPlanSha256V2(plan)) {
    fail("receipt identity or outcome drifted from schema or approved plan digest");
  }
  validateSha256(receipt.approved_approval_sha256, "receipt approved approval SHA-256");
  validateSha256(receipt.activation_approval_sha256, "receipt activation approval SHA-256");
  validateSha256(receipt.firewall_evidence_sha256, "receipt firewall evidence SHA-256");
  if (receipt.firewall_evidence_sha256 !== plan.firewall_evidence.sha256 ||
      !same(receipt.host, plan.host) || !same(receipt.caddy_before, plan.caddy_preimage) ||
      !same(receipt.caddy_after, plan.caddy_preimage) ||
      !same(receipt.installed_files, plan.installed_files.map((entry) => entry.pin)) ||
      !same(receipt.runtime, plan.runtime) ||
      !same(receipt.loaded_netns_unit, plan.preimage.loaded_netns_unit) ||
      !same(receipt.sentinels, plan.activation_sentinels)) {
    fail("receipt closed host/firewall/installed/runtime/loaded-unit/sentinel inputs drifted");
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

export function validatePublisherNetnsFailedRecoveryReceiptV1({
  approvedPlanSha256,
  approvedRecoveryApprovalSha256,
  plan,
  receipt,
}) {
  validatePublisherNetnsPlanV2(plan);
  exactKeys(receipt, [
    "activation_approval_sha256", "approved_plan_sha256",
    "approved_recovery_approval_sha256", "caddy", "ceremony_id",
    "failed_unit", "failed_unit_sha256", "firewall_evidence_sha256", "host",
    "installed_files", "kind", "loaded_netns_unit", "outcome", "publisher_unit",
    "recovered_unit", "reset_failed_argv", "reset_intent_approval_sha256", "runtime",
    "schema_version", "sentinels", "start_intent_sha256", "topology_absent",
  ], "failed-start recovery receipt");
  if (
    receipt.schema_version !== 1 ||
    receipt.kind !== PUBLISHER_NETNS_FAILED_RECOVERY_RECEIPT_KIND ||
    receipt.outcome !== "failed-start-recovered" ||
    receipt.ceremony_id !== plan.ceremony_id ||
    receipt.approved_plan_sha256 !== approvedPlanSha256 ||
    approvedPlanSha256 !== computePublisherNetnsPlanSha256V2(plan) ||
    receipt.approved_recovery_approval_sha256 !== approvedRecoveryApprovalSha256 ||
    receipt.topology_absent !== true ||
    !same(receipt.reset_failed_argv, ["reset-failed", NETNS_UNIT])
  ) {
    fail("failed-start recovery receipt identity or outcome drifted");
  }
  for (const [value, label] of [
    [receipt.activation_approval_sha256, "activation approval SHA-256"],
    [receipt.approved_recovery_approval_sha256, "recovery approval SHA-256"],
    [receipt.failed_unit_sha256, "failed unit SHA-256"],
    [receipt.firewall_evidence_sha256, "firewall evidence SHA-256"],
    [receipt.reset_intent_approval_sha256, "reset-intent approval SHA-256"],
    [receipt.start_intent_sha256, "start intent SHA-256"],
  ]) validateSha256(value, `failed-start recovery receipt ${label}`);
  validatePublisherNetnsFailedUnitV1(
    receipt.failed_unit,
    "failed-start recovery receipt.failed_unit",
  );
  if (
    receipt.failed_unit_sha256 !== computePublisherNetnsFailedUnitSha256V1(receipt.failed_unit) ||
    receipt.firewall_evidence_sha256 !== plan.firewall_evidence.sha256 ||
    !same(receipt.caddy, plan.caddy_preimage) ||
    !same(receipt.host, plan.host) ||
    !same(receipt.installed_files, plan.installed_files.map((entry) => entry.pin)) ||
    !same(receipt.loaded_netns_unit, plan.preimage.loaded_netns_unit) ||
    !same(receipt.publisher_unit, plan.preimage.publisher_unit) ||
    !same(receipt.recovered_unit, plan.preimage.netns_unit) ||
    !same(receipt.runtime, plan.runtime) ||
    !same(receipt.sentinels, plan.activation_sentinels)
  ) {
    fail("failed-start recovery receipt closed inputs or exact unit generations drifted");
  }
  return true;
}
