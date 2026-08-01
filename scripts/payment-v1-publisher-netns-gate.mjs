#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY = resolve(SCRIPT_DIRECTORY, "..");

export const PUBLISHER_NETNS_FILES = Object.freeze([
  "scripts/payment-v1-publisher-netns.c",
  "deploy/payment-v1/systemd/payment-v1-publisher-netns.service.in",
  "deploy/payment-v1/systemd/payment-v1-directory-publisher.service.in",
  "deploy/payment-v1/systemd/bhtm-caddy.publisher-netns.conf.in",
  "deploy/payment-v1/network/directory-publisher-hosts.conf.in",
  "deploy/payment-v1/network/directory-publisher-resolv.conf.in",
  "deploy/payment-v1/network/directory-publisher-nsswitch.conf.in",
  "deploy/payment-v1/network/directory-publisher-network-policy.json.in",
  "deploy/payment-v1/network/README.md",
]);

export function validatePublisherFailedRecoverySourcesV1(ceremonySource, schemaSource) {
  const ceremonyRequired = [
    'ops.systemctl(["reset-failed", NETNS_UNIT])',
    'canonicalJson(["reset-failed", NETNS_UNIT])',
    'await ops.unitJobAbsent(NETNS_UNIT)',
    'await ops.failedUnitState(NETNS_UNIT)',
    'await ops.networkAbsent(plan)',
    '"06-reset-failed-intent.json"',
    '"07-failed-start-recovered.json"',
  ];
  for (const required of ceremonyRequired) {
    if (!ceremonySource.includes(required)) {
      fail(`publisher failed-recovery ceremony lost exact guard: ${required}`);
    }
  }
  if (
    ceremonySource.includes('ops.systemctl(["reset-failed"])') ||
    ceremonySource.includes('ops.systemctl(["reset-failed", name])') ||
    ceremonySource.includes('ops.systemctl(["reset-failed", PUBLISHER_UNIT])')
  ) fail("publisher failed-recovery ceremony contains a broad reset-failed mutation");
  const schemaRequired = [
    '"bitcoinpir-payment-v1-publisher-netns-failed-recovery-approval-v1"',
    '"approve-reset-exact-failed-publisher-netns"',
    'value.active_state !== "failed"',
    'value.sub_state !== "failed"',
    'value.main_pid !== "0"',
    '!/^[0-9a-f]{32}$/u.test(value.invocation_id)',
    'approval.start_intent_sha256',
    'approval.activation_approval_sha256',
  ];
  for (const required of schemaRequired) {
    if (!schemaSource.includes(required)) {
      fail(`publisher failed-recovery schema lost exact binding: ${required}`);
    }
  }
  return true;
}

export const PUBLISHER_FIREWALL_OUTPUT_KEYS = Object.freeze([
  "nft_ip6_base_forward",
  "nft_ip6_base_input",
  "nft_ip6_before_forward",
  "nft_ip6_before_input",
  "nft_ip6_before_logging_forward",
  "nft_ip6_before_logging_input",
  "nft_ip6_forward",
  "nft_ip6_input",
  "nft_ip6_logging_deny",
  "nft_ip_base_forward",
  "nft_ip_base_input",
  "nft_ip_before_forward",
  "nft_ip_before_input",
  "nft_ip_before_logging_forward",
  "nft_ip_before_logging_input",
  "nft_ip_forward",
  "nft_ip_input",
  "nft_ip_logging_deny",
  "nft_ip_not_local",
  "ufw_raw",
  "ufw_status",
]);

function fail(message) {
  throw new Error(`publisher-netns-gate: ${message}`);
}

function read(root, relativePath) {
  return readFileSync(join(root, relativePath), "utf8");
}

function activeLines(text) {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "" && !line.startsWith("#"));
}

function directiveValues(text, key) {
  return activeLines(text)
    .filter((line) => line.startsWith(`${key}=`))
    .map((line) => line.slice(key.length + 1));
}

function sectionKeys(text, wantedSection) {
  let section = "";
  const keys = new Set();
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    const sectionMatch = /^\[([^\]]+)\]$/u.exec(line);
    if (sectionMatch) {
      section = sectionMatch[1];
      continue;
    }
    if (section !== wantedSection) continue;
    const equals = line.indexOf("=");
    if (equals <= 0) fail(`${wantedSection} contains a malformed directive`);
    keys.add(line.slice(0, equals));
  }
  return [...keys].sort();
}

function exactSectionKeys(text, section, wanted, label) {
  const actual = sectionKeys(text, section);
  const expected = [...wanted].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(`${label} ${section} keys must equal ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

function exactValues(text, key, wanted, label) {
  const actual = directiveValues(text, key);
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    fail(`${label} ${key} must equal ${JSON.stringify(wanted)}, got ${JSON.stringify(actual)}`);
  }
}

function requireOnce(text, needle, label) {
  const count = text.split(needle).length - 1;
  if (count !== 1) fail(`${label} must contain ${JSON.stringify(needle)} exactly once`);
}

function reject(text, expression, message) {
  if (expression.test(text)) fail(message);
}

function validateNoInstall(text, label) {
  reject(text, /^\[Install\]$/mu, `${label} must not contain an Install section`);
  reject(text, /^(?:WantedBy|RequiredBy|Also|Alias)=/mu,
    `${label} must not be installable`);
}

function validateHelperSource(source) {
  const label = "native namespace helper";
  reject(source, /^\s*#\s*undef\b/mu,
    `${label} must not undefine or shadow reviewed system constants`);
  const preprocessorSurface = `${source.split("\n")
    .map((line) => line.trim())
    .filter((line) => line.startsWith("#"))
    .join("\n")}\n`;
  const preprocessorDigest = createHash("sha256")
    .update(preprocessorSurface, "utf8")
    .digest("hex");
  if (preprocessorDigest !== "9eed848e2c7aebc74513fbc2b41c14f7bcb57a4cbba2d01387a3a5466388da4c") {
    fail(`${label} preprocessor surface drifted from the reviewed include/macro/branch set`);
  }
  for (const exact of [
    '#define STATE_DIRECTORY "/var/lib/bitcoinpir-publisher-netns"',
    '#define FINAL_NAMESPACE_PATH "/run/netns/bpir-directory-publisher"',
    '#define NAMESPACE_NAME "bpir-directory-publisher"',
    '#define HOST_IFNAME "bpir-pub-h"',
    '#define CLIENT_IFNAME "bpir-pub-c"',
    '#define HOST_ADDRESS_TEXT "10.203.0.1"',
    '#define CLIENT_ADDRESS_TEXT "10.203.0.2"',
    '#define PENDING_RECORD "pending.v1"',
    "#define ADDRESS_PREFIX 30U",
    '#define IF_ALIAS_PREFIX "bitcoinpir-payment-v1-publisher-netns:"',
  ]) requireOnce(source, exact, label);
  for (const phase of [
    "00-placeholder-intent", "00-prepared", "05-namespace-intent", "10-namespace",
    "20-final-intent", "30-final", "40-veth-intent", "50-veth",
    "41-veth-brand-intent", "42-veth-branded", "43-veth-install-intent",
    "44-veth-installed",
    "60-ready", "70-cleanup-intent", "90-clean", "90-clean-preactive",
  ]) {
    if (!source.includes(`\"${phase}\"`)) fail(`${label} lost ${phase}`);
  }
  for (const primitive of [
    "RENAME_NOREPLACE", "fdatasync", "fsync", "O_NOFOLLOW", "O_EXCL",
    "IFLA_IFALIAS", "IFLA_NET_NS_FD", "MS_BIND", "CLONE_NEWNET",
    "PR_SET_PDEATHSIG", "SYS_capset", "SECCOMP_MODE_FILTER",
    "SECCOMP_RET_KILL_PROCESS", "PR_SET_NO_NEW_PRIVS",
    "wait_for_client_monitor_ready", "publisher-sandbox-self-test",
    "NETLINK_NETFILTER", "NFNLGRP_NFTABLES", '"xtables.lock"',
    "LOCK_EX | LOCK_NB", "nftables_generation_is_quiet",
    "xtables_lock_guard_is_held",
    "publisher sandbox /run is not a private read-only tmpfs",
    "publisher sandbox private /run exposes a host runtime entry",
  ]) {
    if (!source.includes(primitive)) fail(`${label} lost ${primitive}`);
  }
  reject(source,
    /\b(?:system|popen|posix_spawn|posix_spawnp|execl|execle|execlp|execv|execve|execvp|execvpe|execveat|fexecve|dlopen|dlsym)\s*\(/u,
    `${label} must never invoke a shell or child executable`);
  reject(source, /\b(?:SYS|__NR)_(?:execve|execveat)\b/u,
    `${label} must never invoke an exec syscall directly`);
  reject(source, /\b(?:asm|__asm__)\b/u,
    `${label} must not use inline assembly to bypass reviewed syscall sites`);
  const reviewedDirectSyscalls = ["SYS_renameat2", "SYS_renameat2", "SYS_capset"];
  const actualDirectSyscalls = [...source.matchAll(
    /\bsyscall\s*\(\s*(SYS_[a-z0-9_]+)/gu,
  )].map((match) => match[1]);
  if (
    JSON.stringify(actualDirectSyscalls) !== JSON.stringify(reviewedDirectSyscalls) ||
    (source.match(/\bsyscall\s*\(/gu) ?? []).length !== reviewedDirectSyscalls.length
  ) {
    fail(`${label} direct syscall sites must equal the reviewed ordered set`);
  }
  const seccompRegionStart = source.indexOf("#define ALLOW_SYSCALL(name)");
  const seccompStart = source.indexOf("static int install_monitor_seccomp(void)");
  const seccompEnd = source.indexOf("static int check_ipv6_disabled", seccompStart);
  if (
    seccompRegionStart < 0 ||
    seccompStart <= seccompRegionStart ||
    seccompEnd <= seccompStart
  ) {
    fail(`${label} lost the bounded monitor seccomp function`);
  }
  const seccompRegion = source.slice(seccompRegionStart, seccompEnd)
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "");
  const reviewedSeccompRegion = [
    "#define ALLOW_SYSCALL(name) \\",
    "BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)__NR_##name, 0, 1), \\",
    "BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)",
    "static int install_monitor_seccomp(void)",
    "{",
    "struct sock_filter filter[] = {",
    "BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),",
    "#if defined(__x86_64__)",
    "BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),",
    "#elif defined(__aarch64__)",
    "BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),",
    "#endif",
    "BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),",
    "BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),",
    "ALLOW_SYSCALL(read),",
    "ALLOW_SYSCALL(write),",
    "ALLOW_SYSCALL(close),",
    "ALLOW_SYSCALL(sendto),",
    "ALLOW_SYSCALL(recvfrom),",
    "ALLOW_SYSCALL(pread64),",
    "ALLOW_SYSCALL(newfstatat),",
    "ALLOW_SYSCALL(statfs),",
    "ALLOW_SYSCALL(clock_nanosleep),",
    "ALLOW_SYSCALL(kill),",
    "ALLOW_SYSCALL(wait4),",
    "ALLOW_SYSCALL(rt_sigreturn),",
    "ALLOW_SYSCALL(exit),",
    "ALLOW_SYSCALL(exit_group),",
    "BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),",
    "};",
    "struct sock_fprog program = {",
    ".len = (unsigned short)ARRAY_LEN(filter),",
    ".filter = filter,",
    "};",
    "if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||",
    "prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 ||",
    "prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0) return -1;",
    "return 0;",
    "}",
  ];
  if (JSON.stringify(seccompRegion) !== JSON.stringify(reviewedSeccompRegion)) {
    fail(`${label} monitor seccomp program must equal the complete reviewed filter`);
  }
  if ((source.match(/\bSECCOMP_RET_KILL_PROCESS\b/gu) ?? []).length !== 2) {
    fail(`${label} must retain exactly two default-kill seccomp verdicts`);
  }
  const seccompBody = source.slice(seccompStart, seccompEnd);
  const reviewedMonitorSyscalls = [
    "read", "write", "close", "sendto", "recvfrom", "pread64", "newfstatat",
    "statfs", "clock_nanosleep", "kill", "wait4", "rt_sigreturn", "exit",
    "exit_group",
  ];
  const actualMonitorSyscalls = [...seccompBody.matchAll(
    /\bALLOW_SYSCALL\s*\(\s*([a-z0-9_]+)\s*\)/gu,
  )].map((match) => match[1]);
  const monitorAllowTokens = seccompBody.match(/\bALLOW_SYSCALL\b/gu) ?? [];
  if (
    JSON.stringify(actualMonitorSyscalls) !== JSON.stringify(reviewedMonitorSyscalls) ||
    monitorAllowTokens.length !== reviewedMonitorSyscalls.length ||
    (source.match(/\bSECCOMP_RET_ALLOW\b/gu) ?? []).length !== 1
  ) {
    fail(`${label} monitor seccomp allowlist must equal the reviewed ordered syscall set`);
  }
  reject(source, /\/bin\/(?:sh|bash)|\/usr\/bin\/(?:env|ip|nsenter|mount|umount|sysctl)/u,
    `${label} must not depend on shell/network mutation commands`);
  if (!source.includes("unknown preimage") || !source.includes("exact cleanup refused")) {
    fail(`${label} must document and implement unknown-preimage refusal`);
  }
  const setup = source.indexOf("static int setup_transaction(");
  const setupEnd = source.indexOf("static int recover_before_start(", setup);
  const setupBody = source.slice(setup, setupEnd);
  const preMutationJournal = setupBody.indexOf(
    "durable_no_replace_at(state_fd, PENDING_RECORD, pending)",
  );
  const transactionDirectory = setupBody.indexOf("mkdirat(state_fd, topology->txid, 0700)");
  const placeholderIntent = setupBody.indexOf(
    'durable_no_replace_at(tx_fd, "00-placeholder-intent", pending)',
  );
  const firstPlaceholder = setupBody.indexOf("create_placeholder(topology->tx_namespace_path");
  if (!(setup >= 0 && setupEnd > setup && preMutationJournal >= 0 &&
      preMutationJournal < transactionDirectory && transactionDirectory < placeholderIntent &&
      placeholderIntent < firstPlaceholder) ||
      !source.includes("cleanup_pending_before_active(state_fd)")) {
    fail(`${label} must journal before transaction-directory and hidden-placeholder mutation`);
  }
  for (const binding of [
    '{ "erspan0", "erspan" }', '{ "gre0", "gre" }',
    '{ "gretap0", "gretap" }', '{ "ip6_vti0", "vti6" }',
    '{ "ip6gre0", "ip6gre" }', '{ "ip6tnl0", "ip6tnl" }',
    '{ "ip_vti0", "vti" }', '{ "sit0", "sit" }',
    '{ "tunl0", "ipip" }',
  ]) {
    if (!source.includes(binding)) {
      fail(`${label} must bind every inert kernel-fallback name to its exact link kind`);
    }
  }
  if (!source.includes("strcmp(link.kind, inert_kernel_links[i].kind) == 0") ||
      !source.includes('strcmp(link->kind, "veth") != 0') ||
      !source.includes("link.flags & IFF_UP")) {
    fail(`${label} must close the inert kernel-fallback interface allowlist`);
  }
  const run = source.indexOf("static int run_service(void)");
  const firewallMonitor = source.indexOf(
    "open_nftables_generation_monitor()", run);
  const xtablesLock = source.indexOf("open_xtables_lock_guard(&xtables_guard)", run);
  const preSetupQuiet = source.indexOf(
    "nftables_generation_is_quiet(firewall_monitor_fd)", xtablesLock);
  const setupTransaction = source.indexOf("setup_transaction(", preSetupQuiet);
  const child = source.indexOf("if (monitor_child == 0)", run);
  const childDrop = source.indexOf("drop_capabilities()", child);
  const childSandbox = source.indexOf("install_monitor_seccomp()", childDrop);
  const childFirstCheck = source.indexOf("verify_client_topology(", childSandbox);
  const childReady = source.indexOf('write(monitor_ready_pipe[1], "1", 1)', childFirstCheck);
  const parent = source.indexOf("close(monitor_ready_pipe[1]);", childReady);
  const parentDrop = source.indexOf("drop_capabilities()", parent);
  const parentSandbox = source.indexOf("install_monitor_seccomp()", parentDrop);
  const parentFirewallQuiet = source.indexOf(
    "nftables_generation_is_quiet(firewall_monitor_fd)", parentSandbox);
  const parentFirewallLock = source.indexOf(
    "xtables_lock_guard_is_held(&xtables_guard)", parentFirewallQuiet);
  const parentFirstCheck = source.indexOf(
    "verify_host_topology(host_nl, &topology, true)", parentFirewallLock);
  const monitorReady = source.indexOf("wait_for_client_monitor_ready(", parentFirstCheck);
  const readiness = source.indexOf("notify_ready(&notifier)", run);
  const monitorLoop = source.indexOf("while (!stop_requested)", readiness);
  const continuousQuiet = source.indexOf(
    "nftables_generation_is_quiet(firewall_monitor_fd)", monitorLoop);
  const continuousLock = source.indexOf(
    "xtables_lock_guard_is_held(&xtables_guard)", continuousQuiet);
  const gracefulQuiet = source.indexOf(
    "nftables_generation_is_quiet(firewall_monitor_fd)", continuousLock);
  const gracefulLock = source.indexOf(
    "xtables_lock_guard_is_held(&xtables_guard)", gracefulQuiet);
  if (!(run >= 0 && run < firewallMonitor && firewallMonitor < xtablesLock &&
      xtablesLock < preSetupQuiet && preSetupQuiet < setupTransaction &&
      setupTransaction < child && child < childDrop && childDrop < childSandbox &&
      childSandbox < childFirstCheck && childFirstCheck < childReady && childReady < parent &&
      parent < parentDrop && parentDrop < parentSandbox &&
      parentSandbox < parentFirewallQuiet && parentFirewallQuiet < parentFirewallLock &&
      parentFirewallLock < parentFirstCheck &&
      parentFirstCheck < monitorReady && monitorReady < readiness && readiness < monitorLoop &&
      monitorLoop < continuousQuiet && continuousQuiet < continuousLock &&
      continuousLock < gracefulQuiet && gracefulQuiet < gracefulLock)) {
    fail(`${label} must seal firewall before setup, notify READY only after every monitor, and retain continuous plus graceful-stop checks`);
  }
}

export function validatePublisherNamespaceOwnerUnitV1(unitInput) {
  const label = "namespace owner unit";
  const helperDigests = [...unitInput.matchAll(
    /\/opt\/bitcoinpir\/publisher-netns\/([^/\s]+)\/payment-v1-publisher-netns/gu,
  )].map((match) => match[1]);
  if (helperDigests.length < 1 || new Set(helperDigests).size !== 1) {
    fail(`${label} must use one helper content address`);
  }
  const helperDigest = helperDigests[0];
  if (
    helperDigest !== "@PUBLISHER_NETNS_HELPER_SHA256@" &&
    !/^[0-9a-f]{64}$/u.test(helperDigest)
  ) {
    fail(`${label} helper content address is malformed`);
  }
  const unit = helperDigest === "@PUBLISHER_NETNS_HELPER_SHA256@"
    ? unitInput
    : unitInput.replaceAll(
      `/opt/bitcoinpir/publisher-netns/${helperDigest}/payment-v1-publisher-netns`,
      "/opt/bitcoinpir/publisher-netns/@PUBLISHER_NETNS_HELPER_SHA256@/payment-v1-publisher-netns",
    );
  validateNoInstall(unit, label);
  exactSectionKeys(unit, "Unit", [
    "Description", "After", "Before", "PartOf", "ConditionPathExists",
  ], label);
  exactSectionKeys(unit, "Service", [
    "Type", "NotifyAccess", "User", "Group", "UMask", "StateDirectory",
    "StateDirectoryMode", "WorkingDirectory", "UnsetEnvironment", "ExecStartPre", "ExecStart",
    "ExecStopPost", "Restart", "TimeoutStartSec", "TimeoutStopSec", "KillMode",
    "LimitCORE", "MemoryMax", "MemorySwapMax", "TasksMax", "StandardOutput",
    "StandardError", "NoNewPrivileges", "CapabilityBoundingSet",
    "AmbientCapabilities", "RestrictAddressFamilies", "RestrictNamespaces",
    "RestrictRealtime", "RestrictSUIDSGID", "LockPersonality",
    "MemoryDenyWriteExecute", "SystemCallArchitectures",
  ], label);
  const helper =
    "/opt/bitcoinpir/publisher-netns/@PUBLISHER_NETNS_HELPER_SHA256@/payment-v1-publisher-netns";
  const exact = {
    Description: ["BitcoinPIR Payment V1 sealed directory-publisher namespace (template only)"],
    After: ["local-fs.target"],
    Before: ["bitcoinpir-payment-v1-source-fair-edge.service bhtm-caddy.service"],
    PartOf: ["bhtm-caddy.service"],
    ConditionPathExists: [
      "/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
      "/etc/bitcoinpir/payment-v1/EDGE-ACTIVATION-APPROVED",
      "/etc/bitcoinpir/payment-v1/SOURCE-FAIR-PREFLIGHT-APPROVED",
      "/etc/bitcoinpir/payment-v1/DIRECTORY-PUBLISHER-PRIVATE-INGRESS-APPROVED",
      "/etc/bitcoinpir/payment-v1/PUBLISHER-NETNS-ACTIVATION-APPROVED",
    ],
    Type: ["notify"],
    NotifyAccess: ["main"],
    User: ["root"],
    Group: ["root"],
    UMask: ["0077"],
    StateDirectory: ["bitcoinpir-publisher-netns"],
    StateDirectoryMode: ["0700"],
    WorkingDirectory: ["/var/lib/bitcoinpir-publisher-netns"],
    UnsetEnvironment: [
      "BASH_ENV ENV GLIBC_TUNABLES LD_AUDIT LD_LIBRARY_PATH LD_PRELOAD NODE_EXTRA_CA_CERTS NODE_OPTIONS NODE_PATH",
    ],
    ExecStartPre: [
      `/usr/bin/test -x ${helper}`,
      "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/publisher-netns/helper.sha256",
      `${helper} self-test`,
    ],
    ExecStart: [`${helper} run`],
    ExecStopPost: [`${helper} cleanup`],
    Restart: ["no"],
    TimeoutStartSec: ["30"],
    TimeoutStopSec: ["30"],
    KillMode: ["control-group"],
    LimitCORE: ["0"],
    MemoryMax: ["67108864"],
    MemorySwapMax: ["0"],
    TasksMax: ["8"],
    StandardOutput: ["null"],
    StandardError: ["null"],
    NoNewPrivileges: ["true"],
    CapabilityBoundingSet: ["CAP_NET_ADMIN CAP_SYS_ADMIN"],
    AmbientCapabilities: [""],
    RestrictAddressFamilies: ["AF_UNIX AF_NETLINK"],
    RestrictNamespaces: ["net"],
    RestrictRealtime: ["true"],
    RestrictSUIDSGID: ["true"],
    LockPersonality: ["true"],
    MemoryDenyWriteExecute: ["true"],
    SystemCallArchitectures: ["native"],
  };
  for (const [key, values] of Object.entries(exact)) exactValues(unit, key, values, label);
  for (const mountNamespaceDirective of [
    "ProtectSystem", "ProtectHome", "PrivateTmp", "PrivateDevices",
    "ProtectKernelTunables", "ProtectControlGroups", "ReadOnlyPaths",
    "ReadWritePaths", "BindPaths", "BindReadOnlyPaths", "PrivateMounts",
  ]) {
    if (directiveValues(unit, mountNamespaceDirective).length !== 0)
      fail(`${label} ${mountNamespaceDirective} would hide the named nsfs mount`);
  }
}

export function validatePublisherCaddyDropIn(text) {
  const target = "bhtm-caddy";
  const label = `${target} namespace drop-in`;
  validateNoInstall(text, label);
  exactSectionKeys(text, "Unit", ["Wants", "After"], label);
  exactValues(text, "Wants", ["bitcoinpir-payment-v1-publisher-netns.service"], label);
  exactValues(text, "After", ["bitcoinpir-payment-v1-publisher-netns.service"], label);
  reject(text, /^(?:BindsTo|PartOf|Requires)=/mu,
    `${label} must not propagate namespace teardown to the shared service`);
  reject(text, /^\[Service\]$/mu, `${label} must not alter the target service sandbox`);
}

export function validatePublisherUnitV1(unitInput, concretePlaceholders = {}) {
  const label = "one-shot publisher unit";
  const adminDigests = [...unitInput.matchAll(
    /\/opt\/bitcoinpir\/bpir-admin\/([^/\s]+)\/bpir-admin/gu,
  )].map((match) => match[1]);
  const helperDigests = [...unitInput.matchAll(
    /\/opt\/bitcoinpir\/publisher-netns\/([^/\s]+)\/payment-v1-publisher-netns/gu,
  )].map((match) => match[1]);
  if (
    adminDigests.length < 1 || new Set(adminDigests).size !== 1 ||
    helperDigests.length < 1 || new Set(helperDigests).size !== 1
  ) {
    fail(`${label} must use one admin and one namespace-helper content address`);
  }
  const adminDigest = adminDigests[0];
  const helperDigest = helperDigests[0];
  for (const [digest, placeholder] of [
    [adminDigest, "@BPIR_ADMIN_SHA256@"],
    [helperDigest, "@PUBLISHER_NETNS_HELPER_SHA256@"],
  ]) {
    if (digest !== placeholder && !/^[0-9a-f]{64}$/u.test(digest)) {
      fail(`${label} content address is malformed`);
    }
  }
  let unit = unitInput
    .replaceAll(
      `/opt/bitcoinpir/bpir-admin/${adminDigest}/bpir-admin`,
      "/opt/bitcoinpir/bpir-admin/@BPIR_ADMIN_SHA256@/bpir-admin",
    )
    .replaceAll(
      `/opt/bitcoinpir/publisher-netns/${helperDigest}/payment-v1-publisher-netns`,
      "/opt/bitcoinpir/publisher-netns/@PUBLISHER_NETNS_HELPER_SHA256@/payment-v1-publisher-netns",
    );
  const concreteFragments = [
    ["CHECKPOINT_ARTIFACT", (value) => [
      `/var/lib/bitcoinpir-directory-publisher/artifacts/${value}`,
      "/var/lib/bitcoinpir-directory-publisher/artifacts/@CHECKPOINT_ARTIFACT@",
    ]],
    ["DIRECTORY_PUBLISHER_HTTPS_HOST", (value) => [
      `wss://${value}`,
      "wss://@DIRECTORY_PUBLISHER_HTTPS_HOST@",
    ]],
    ["DIRECTORY_PUBLISHER_PUBKEY_HEX", (value) => [
      `--directory-pubkey-hex ${value}`,
      "--directory-pubkey-hex @DIRECTORY_PUBLISHER_PUBKEY_HEX@",
    ]],
    ["DIRECTORY_PUBLISH_NOW_UNIX", (value) => [
      `--now-unix ${value}`,
      "--now-unix @DIRECTORY_PUBLISH_NOW_UNIX@",
    ]],
    ["PROVIDER_0_ENTRY_ARTIFACT", (value) => [
      `/var/lib/bitcoinpir-directory-publisher/artifacts/${value}`,
      "/var/lib/bitcoinpir-directory-publisher/artifacts/@PROVIDER_0_ENTRY_ARTIFACT@",
    ]],
    ["PROVIDER_1_ENTRY_ARTIFACT", (value) => [
      `/var/lib/bitcoinpir-directory-publisher/artifacts/${value}`,
      "/var/lib/bitcoinpir-directory-publisher/artifacts/@PROVIDER_1_ENTRY_ARTIFACT@",
    ]],
  ];
  for (const [key, fragments] of concreteFragments) {
    const value = concretePlaceholders[key];
    if (value !== undefined) {
      const [rendered, template] = fragments(String(value));
      unit = unit.replaceAll(rendered, template);
    }
  }
  validateNoInstall(unit, label);
  exactSectionKeys(unit, "Unit", [
    "Description", "Requires", "BindsTo", "After", "ConditionPathExists",
  ], label);
  exactSectionKeys(unit, "Service", [
    "Type", "RemainAfterExit", "User", "Group", "UMask", "StateDirectory",
    "StateDirectoryMode", "NetworkNamespacePath", "PrivateMounts",
    "BindReadOnlyPaths", "UnsetEnvironment", "ExecStartPre", "ExecStart",
    "Restart", "TimeoutStartSec", "TimeoutStopSec", "LimitCORE", "MemoryMax",
    "MemorySwapMax", "TasksMax", "StandardOutput", "StandardError",
    "NoNewPrivileges", "PrivateDevices", "PrivateTmp", "ProtectSystem",
    "ProtectHome", "ProtectKernelTunables", "ProtectKernelModules",
    "ProtectKernelLogs", "ProtectControlGroups", "ProtectClock",
    "ProtectHostname", "LockPersonality", "MemoryDenyWriteExecute",
    "RestrictSUIDSGID", "RestrictRealtime", "RestrictNamespaces",
    "SystemCallArchitectures", "CapabilityBoundingSet", "AmbientCapabilities",
    "RestrictAddressFamilies", "IPAddressDeny", "IPAddressAllow",
    "ReadOnlyPaths", "ReadWritePaths", "InaccessiblePaths", "TemporaryFileSystem",
  ], label);
  exactValues(unit, "Requires", [
    "bitcoinpir-payment-v1-publisher-netns.service bitcoinpir-payment-v1-source-fair-edge.service bhtm-caddy.service bitcoinpir-directory-relay.service",
  ], label);
  exactValues(unit, "BindsTo", [
    "bitcoinpir-payment-v1-publisher-netns.service",
  ], label);
  exactValues(unit, "After", [
    "bitcoinpir-payment-v1-publisher-netns.service bitcoinpir-payment-v1-source-fair-edge.service bhtm-caddy.service bitcoinpir-directory-relay.service",
  ], label);
  exactValues(unit, "Type", ["oneshot"], label);
  exactValues(unit, "RemainAfterExit", ["true"], label);
  exactValues(unit, "User", ["bitcoinpir-directory-publisher"], label);
  exactValues(unit, "Group", ["bitcoinpir-directory-publisher"], label);
  exactValues(unit, "StateDirectory", ["bitcoinpir-directory-publication"], label);
  exactValues(unit, "StateDirectoryMode", ["0700"], label);
  exactValues(unit, "NetworkNamespacePath",
    ["/run/netns/bpir-directory-publisher"], label);
  exactValues(unit, "Restart", ["no"], label);
  exactValues(unit, "CapabilityBoundingSet", [""], label);
  exactValues(unit, "AmbientCapabilities", [""], label);
  exactValues(unit, "IPAddressDeny", ["any"], label);
  exactValues(unit, "IPAddressAllow", ["10.203.0.1"], label);
  exactValues(unit, "RestrictAddressFamilies", ["AF_INET"], label);
  exactValues(unit, "TemporaryFileSystem", ["/run:ro"], label);
  exactValues(unit, "BindReadOnlyPaths", [
    "/etc/netns/bpir-directory-publisher/hosts:/etc/hosts",
    "/etc/netns/bpir-directory-publisher/resolv.conf:/etc/resolv.conf",
    "/etc/netns/bpir-directory-publisher/nsswitch.conf:/etc/nsswitch.conf",
  ], label);
  exactValues(unit, "UnsetEnvironment", [
    "BASH_ENV ENV GLIBC_TUNABLES LD_AUDIT LD_LIBRARY_PATH LD_PRELOAD NODE_EXTRA_CA_CERTS NODE_OPTIONS NODE_PATH http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy NO_PROXY no_proxy",
  ], label);
  const admin = "/opt/bitcoinpir/bpir-admin/@BPIR_ADMIN_SHA256@/bpir-admin";
  const helper =
    "/opt/bitcoinpir/publisher-netns/@PUBLISHER_NETNS_HELPER_SHA256@/payment-v1-publisher-netns";
  exactValues(unit, "ExecStartPre", [
    `/usr/bin/test -x ${admin}`,
    "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/directory-publisher/bpir-admin.sha256",
    "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/directory-publisher/artifacts.sha256",
    "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/directory-publisher/network-inputs.sha256",
    `${helper} publisher-sandbox-self-test`,
  ], label);
  exactValues(unit, "ConditionPathExists", [
    "/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
    "/etc/bitcoinpir/payment-v1/RELAY-SELECTION-RESOLVED",
    "/etc/bitcoinpir/payment-v1/DIRECTORY-PUBLISHER-PRIVATE-INGRESS-APPROVED",
    "/etc/bitcoinpir/payment-v1/PUBLISHER-NETNS-ACTIVATION-APPROVED",
    "/etc/bitcoinpir/payment-v1/PUBLISHER-SNI-SAN-APPROVED",
    "/etc/bitcoinpir/payment-v1/DIRECTORY-PUBLICATION-APPROVED",
  ], label);
  const starts = directiveValues(unit, "ExecStart");
  if (starts.length !== 1) fail(`${label} must have one ExecStart`);
  const command = starts[0];
  reject(command, /["'`;|&<>$]/u, `${label} ExecStart contains shell/meta syntax`);
  const tokens = command.split(/\s+/u);
  const wantedPrefix = [
    "/opt/bitcoinpir/bpir-admin/@BPIR_ADMIN_SHA256@/bpir-admin",
    "directory-artifact", "publish",
  ];
  if (JSON.stringify(tokens.slice(0, 3)) !== JSON.stringify(wantedPrefix))
    fail(`${label} has an unexpected executable/subcommand`);
  const wantedTokens = [
    ...wantedPrefix,
    "--artifact", "/var/lib/bitcoinpir-directory-publisher/artifacts/@PROVIDER_0_ENTRY_ARTIFACT@",
    "--artifact", "/var/lib/bitcoinpir-directory-publisher/artifacts/@PROVIDER_1_ENTRY_ARTIFACT@",
    "--artifact", "/var/lib/bitcoinpir-directory-publisher/artifacts/@CHECKPOINT_ARTIFACT@",
    "--artifact-manifest", "/etc/bitcoinpir/payment-v1/directory-publisher/artifacts.sha256",
    "--receipt-directory", "/var/lib/bitcoinpir-directory-publication",
    "--relay", "wss://@DIRECTORY_PUBLISHER_HTTPS_HOST@",
    "--centralized-single-relay",
    "--directory-pubkey-hex", "@DIRECTORY_PUBLISHER_PUBKEY_HEX@",
    "--now-unix", "@DIRECTORY_PUBLISH_NOW_UNIX@",
    "--relay-timeout-seconds", "60",
  ];
  reject(command, /(?:signing|private|secret)[-_]key|--validate-only|--force/iu,
    `${label} must not read a key or alter explicit publication semantics`);
  if (JSON.stringify(tokens) !== JSON.stringify(wantedTokens)) {
    fail(`${label} has an unreviewed publication argv shape`);
  }
  exactValues(unit, "ReadWritePaths", [
    "/var/lib/bitcoinpir-directory-publication",
  ], label);
  reject(unit, /Restart=(?!no)|StartLimit|OnFailure|ExecStartPost/u,
    `${label} must not introduce retry/restart orchestration`);
  exactValues(unit, "StandardOutput", ["null"], label);
  exactValues(unit, "StandardError", ["null"], label);
  const sandboxProbe = `${helper} publisher-sandbox-self-test`;
  if (directiveValues(unit, "ExecStartPre").filter((value) => value === sandboxProbe).length !== 1) {
    fail(`${label} must run the pinned AF_UNIX denial probe in its own sandbox`);
  }
  exactValues(unit, "InaccessiblePaths", [
    "-/etc/bitcoinpir/payment-v1/directory-publisher/keys -/var/lib/bitcoinpir-directory-relay -/var/lib/bitcoinpir-payment-issuer -/var/lib/bitcoinpir-provider",
  ], label);
  reject(unit, /(?:SyslogIdentifier|LogExtraFields|StandardOutput=(?!null)|StandardError=(?!null))/u,
    `${label} must not persist publisher output or request metadata`);
}

function validateNetworkFiles(hosts, resolv, nsswitch) {
  const hostLines = activeLines(hosts);
  const expectedHosts = [
    "127.0.0.1 localhost",
    "10.203.0.1 @DIRECTORY_PUBLISHER_HTTPS_HOST@",
  ];
  if (JSON.stringify(hostLines) !== JSON.stringify(expectedHosts))
    fail("publisher hosts file must bind the one centralized relay name only to the host veth");
  const resolvLines = activeLines(resolv);
  if (JSON.stringify(resolvLines) !== JSON.stringify([
    "nameserver 127.0.0.1", "options attempts:1 timeout:1",
  ])) fail("publisher resolver must be local and bounded");
  if (JSON.stringify(activeLines(nsswitch)) !== JSON.stringify([
    "passwd: files", "group: files", "hosts: files", "networks: files",
  ])) fail("publisher NSS must use files only");
}

function canonical(value) {
  if (value === null || typeof value === "boolean" || typeof value === "number") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  fail("network policy contains an unsupported JSON value");
}

export function validatePublisherNetworkPolicy(
  text,
  publisherHostname = "@DIRECTORY_PUBLISHER_HTTPS_HOST@",
) {
  let policy;
  try {
    policy = JSON.parse(text);
  } catch {
    fail("publisher network policy must be valid JSON");
  }
  const expected = {
    caddy_dependency: {
      after: "bitcoinpir-payment-v1-publisher-netns.service",
      forbidden_reverse_stop_edges: ["BindsTo", "PartOf", "Requires"],
      wants: "bitcoinpir-payment-v1-publisher-netns.service",
    },
    certificate_dns_sans: [
      publisherHostname,
    ],
    firewall: {
      forwarding_sysctls: {
        "net.ipv4.ip_forward": 0,
        "net.ipv6.conf.all.forwarding": 0,
      },
      interface: "bpir-pub-h",
      ufw_rules_in_install_order: [
        "prepend deny in on bpir-pub-h from any to any",
        "prepend allow in on bpir-pub-h from 10.203.0.2 to 10.203.0.1 proto tcp port 443",
        "route prepend deny in on bpir-pub-h from any to any",
        "route prepend deny out on bpir-pub-h from any to any",
      ],
    },
    namespace: {
      client: "10.203.0.2/30",
      host: "10.203.0.1/30",
      name: "bpir-directory-publisher",
      path: "/run/netns/bpir-directory-publisher",
    },
    publication_mode: {
      centralized: true,
      degraded: true,
      name: "centralized-single-relay",
    },
    publication_time_firewall_binding: {
      activation_blocked: false,
      continuous_checks: [
        "reject-any-nftables-generation-event",
        "reject-xtables-lock-inode-drift",
      ],
      graceful_stop_barriers: [
        "require-empty-nftables-event-queue",
        "require-stable-xtables-lock-inode",
      ],
      guard_profile: "xtables-lock-and-host-nftables-generation-monitor-v1",
      implemented: true,
      lifecycle_scope: "publisher-netns-owner-lifetime",
      point_in_time_evidence_only: false,
      pre_ready_barriers: [
        "open-host-netns-nftables-multicast-before-network-setup",
        "hold-root-single-link-xtables-lock",
        "require-empty-nftables-event-queue",
      ],
      privileged_mutation_boundary: "non-adversarial-root-maintenance",
      semantic_pre_post_evidence_required: true,
      state_machine: "sealed-before-ready-monitor-until-owner-exit",
    },
    schema_version: 2,
  };
  if (canonical(policy) !== canonical(expected)) {
    fail("publisher network policy must equal the closed V1 policy");
  }
}

function boundedCanonicalOutput(value, label) {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > 2 * 1024 * 1024 ||
      /[\0\r]/u.test(value)) {
    fail(`${label} must be bounded canonical LF text`);
  }
  return value.split("\n").map((line) => line.trim().replace(/\s+/gu, " "));
}

function exactPatternSet(lines, patterns, label) {
  if (lines.length !== patterns.length) {
    fail(`${label} must contain exactly ${patterns.length} publisher-interface rules`);
  }
  const unmatched = [...lines];
  for (const pattern of patterns) {
    const index = unmatched.findIndex((line) => pattern.test(line));
    if (index < 0) fail(`${label} is missing ${pattern}`);
    unmatched.splice(index, 1);
  }
}

function normalizedNftChain(text, family, chain) {
  const label = `nft ${family} ${chain}`;
  const lines = boundedCanonicalOutput(text, label).filter((line) => line !== "");
  if (
    lines.length < 4 ||
    lines[0] !== `table ${family} filter {` ||
    lines[1] !== `chain ${chain} {` ||
    lines.at(-2) !== "}" ||
    lines.at(-1) !== "}" ||
    lines.slice(2, -2).some((line) => line === "{" || line === "}" || line.startsWith("#"))
  ) {
    fail(`${label} does not have one canonical chain framing`);
  }
  return lines.slice(2, -2).map((line) => line
    .replace(/(?:^| )counter packets [0-9]+ bytes [0-9]+(?: |$)/gu, (match) =>
      match.startsWith(" ") && match.endsWith(" ") ? " " : "")
    .trim()
    .replace(/ # handle [0-9]+$/gu, ""));
}

function validateBaseChain(outputs, family, hook) {
  const prefix = family === "ip" ? "ufw" : "ufw6";
  const suffix = hook.toLowerCase();
  const key = `nft_${family}_base_${suffix}`;
  const rules = normalizedNftChain(outputs[key], family, hook);
  const expected = [
    `type filter hook ${suffix} priority filter; policy drop;`,
    `jump ${prefix}-before-logging-${suffix}`,
    `jump ${prefix}-before-${suffix}`,
    `jump ${prefix}-after-${suffix}`,
    `jump ${prefix}-after-logging-${suffix}`,
    `jump ${prefix}-reject-${suffix}`,
    `jump ${prefix}-track-${suffix}`,
  ];
  if (canonical(rules) !== canonical(expected)) {
    fail(`nft ${family} ${hook} must be the exact UFW drop-policy base chain`);
  }
}

function validateBeforeChain(outputs, family, hook) {
  const prefix = family === "ip" ? "ufw" : "ufw6";
  const suffix = hook.toLowerCase();
  const rules = normalizedNftChain(
    outputs[`nft_${family}_before_${suffix}`],
    family,
    `${prefix}-before-${suffix}`,
  );
  const userJump = `jump ${prefix}-user-${suffix}`;
  const userJumpIndexes = rules.flatMap((line, index) => line === userJump ? [index] : []);
  if (userJumpIndexes.length !== 1) {
    fail(`nft ${family} before-${suffix} must contain one user-chain jump`);
  }
  const statefulAccept = "ct state related,established accept";
  const statefulAcceptIndexes = rules.flatMap(
    (line, index) => line === statefulAccept ? [index] : [],
  );
  if (
    statefulAcceptIndexes.length !== 1 ||
    statefulAcceptIndexes[0] >= userJumpIndexes[0]
  ) {
    fail(
      `nft ${family} before-${suffix} must contain exactly one ` +
      "RELATED,ESTABLISHED accept before its user-chain jump",
    );
  }
  if (rules.at(-1) !== userJump) {
    fail(`nft ${family} before-${suffix} must end in one user-chain jump`);
  }
  for (const line of rules.slice(0, -1)) {
    if (/\b(?:goto|queue)\b/u.test(line)) {
      fail(`nft ${family} before-${suffix} contains an unsafe verdict`);
    }
    if (/\bjump\b/u.test(line)) {
      const allowedJumps = new Set([
        `jump ${prefix}-logging-deny`,
        ...(family === "ip" && hook === "INPUT" ? ["jump ufw-not-local"] : []),
      ]);
      const jump = line.slice(line.lastIndexOf("jump "));
      if (!allowedJumps.has(jump)) {
        fail(`nft ${family} before-${suffix} jumps to an unreviewed chain`);
      }
    }
    if (/\baccept$/u.test(line) && !reviewedUfwPreludeAccept(line, family, hook)) {
      fail(`nft ${family} before-${suffix} contains an unreviewed early accept`);
    }
  }
}

function reviewedUfwPreludeAccept(line, family, hook) {
  const common = [
    /^ct state related,established accept$/u,
    ...(hook === "INPUT" ? [/^iifname "lo" accept$/u] : []),
  ];
  if (family === "ip") {
    const icmp =
      /^ip protocol icmp icmp type (?:destination-unreachable|time-exceeded|parameter-problem|echo-request) accept$/u;
    const inputOnly = hook === "INPUT" ? [
      /^udp sport 67 udp dport 68 accept$/u,
      /^ip daddr 224\.0\.0\.251 udp dport 5353 accept$/u,
      /^ip daddr 239\.255\.255\.250 udp dport 1900 accept$/u,
    ] : [];
    return [...common, icmp, ...inputOnly].some((pattern) => pattern.test(line));
  }

  const controlTypes =
    /^meta l4proto ipv6-icmp icmpv6 type (?:destination-unreachable|packet-too-big|time-exceeded|parameter-problem|echo-request|echo-reply) accept$/u;
  const inputOnly = hook === "INPUT" ? [
    /^meta l4proto ipv6-icmp icmpv6 type (?:nd-router-solicit|nd-router-advert|nd-neighbor-solicit|nd-neighbor-advert) ip6 hoplimit 255 accept$/u,
    /^meta l4proto ipv6-icmp xt match "icmp6"(?: ip6 hoplimit 255)? accept$/u,
    /^ip6 saddr fe80::\/10 meta l4proto ipv6-icmp icmpv6 type (?:mld-listener-query|mld-listener-report|mld-listener-done) accept$/u,
    /^ip6 saddr fe80::\/10 meta l4proto ipv6-icmp xt match "icmp6"(?: ip6 hoplimit 1)? accept$/u,
    /^ip6 saddr fe80::\/10 ip6 daddr fe80::\/10 udp sport 547 udp dport 546 accept$/u,
    /^ip6 daddr ff02::fb udp dport 5353 accept$/u,
    /^ip6 daddr ff02::f udp dport 1900 accept$/u,
  ] : [];
  return [...common, controlTypes, ...inputOnly].some((pattern) => pattern.test(line));
}

function validateClosedUfwPrelude(outputs, family) {
  const prefix = family === "ip" ? "ufw" : "ufw6";
  for (const hook of ["INPUT", "FORWARD"]) {
    validateBaseChain(outputs, family, hook);
    const suffix = hook.toLowerCase();
    const logging = normalizedNftChain(
      outputs[`nft_${family}_before_logging_${suffix}`],
      family,
      `${prefix}-before-logging-${suffix}`,
    );
    if (logging.length !== 0) {
      fail(`nft ${family} before-logging-${suffix} must be empty with UFW logging off`);
    }
    validateBeforeChain(outputs, family, hook);
  }
  const loggingDeny = normalizedNftChain(
    outputs[`nft_${family}_logging_deny`],
    family,
    `${prefix}-logging-deny`,
  );
  if (loggingDeny.length !== 0) {
    fail(`nft ${family} logging-deny must be empty with UFW logging off`);
  }
  if (family === "ip") {
    const notLocal = normalizedNftChain(outputs.nft_ip_not_local, "ip", "ufw-not-local");
    const expected = [
      "fib daddr type local return",
      "fib daddr type multicast return",
      "fib daddr type broadcast return",
      "limit rate 3/minute burst 10 packets jump ufw-logging-deny",
      "drop",
    ];
    if (canonical(notLocal) !== canonical(expected)) {
      fail("nft ip ufw-not-local drifted from its non-accepting closed chain");
    }
  }
}

export function validatePublisherFirewallOutputs(outputs) {
  if (!outputs || canonical(Object.keys(outputs).sort()) !==
      canonical(PUBLISHER_FIREWALL_OUTPUT_KEYS)) {
    fail("publisher firewall output keys are not closed");
  }
  validateClosedUfwPrelude(outputs, "ip");
  validateClosedUfwPrelude(outputs, "ip6");
  const statusLines = boundedCanonicalOutput(outputs.ufw_status, "ufw status numbered")
    .filter((line) => line.includes("bpir-pub-h"))
    .map((line) => line.replace(/^\[\s*[0-9]+\]\s*/u, ""));
  exactPatternSet(statusLines, [
    /^10\.203\.0\.1 443\/tcp on bpir-pub-h ALLOW IN 10\.203\.0\.2$/u,
    /^Anywhere on bpir-pub-h DENY IN Anywhere$/u,
    /^Anywhere DENY FWD Anywhere on bpir-pub-h$/u,
    /^Anywhere on bpir-pub-h DENY FWD Anywhere \(out\)$/u,
    /^Anywhere \(v6\) on bpir-pub-h DENY IN Anywhere \(v6\)$/u,
    /^Anywhere \(v6\) DENY FWD Anywhere \(v6\) on bpir-pub-h$/u,
    /^Anywhere \(v6\) on bpir-pub-h DENY FWD Anywhere \(v6\) \(out\)$/u,
  ], "ufw status numbered");
  const allowIndex = statusLines.findIndex((line) => / ALLOW IN /u.test(line));
  const inputDenyIndex = statusLines.findIndex((line) =>
    /^Anywhere on bpir-pub-h DENY IN Anywhere$/u.test(line));
  if (allowIndex < 0 || inputDenyIndex < 0 || allowIndex >= inputDenyIndex) {
    fail("ufw input allow must precede the interface-wide IPv4 deny");
  }

  const rawLines = boundedCanonicalOutput(outputs.ufw_raw, "ufw show raw")
    .filter((line) => line.includes("bpir-pub-h"));
  exactPatternSet(rawLines, [
    /^[0-9]+ [0-9]+ ACCEPT 6 -- bpir-pub-h \* 10\.203\.0\.2 10\.203\.0\.1 tcp dpt:443$/u,
    /^[0-9]+ [0-9]+ DROP 0 -- bpir-pub-h \* 0\.0\.0\.0\/0 0\.0\.0\.0\/0$/u,
    /^[0-9]+ [0-9]+ DROP 0 -- bpir-pub-h \* 0\.0\.0\.0\/0 0\.0\.0\.0\/0$/u,
    /^[0-9]+ [0-9]+ DROP 0 -- \* bpir-pub-h 0\.0\.0\.0\/0 0\.0\.0\.0\/0$/u,
    /^[0-9]+ [0-9]+ DROP 0 -- bpir-pub-h \* ::\/0 ::\/0$/u,
    /^[0-9]+ [0-9]+ DROP 0 -- bpir-pub-h \* ::\/0 ::\/0$/u,
    /^[0-9]+ [0-9]+ DROP 0 -- \* bpir-pub-h ::\/0 ::\/0$/u,
  ], "ufw show raw");

  const nftCases = [
    ["nft_ip_input", [
      /^ip saddr 10\.203\.0\.2 ip daddr 10\.203\.0\.1 iifname "bpir-pub-h" tcp dport 443 accept$/u,
      /^iifname "bpir-pub-h" drop$/u,
    ]],
    ["nft_ip_forward", [
      /^iifname "bpir-pub-h" drop$/u,
      /^oifname "bpir-pub-h" drop$/u,
    ]],
    ["nft_ip6_input", [/^iifname "bpir-pub-h" drop$/u]],
    ["nft_ip6_forward", [
      /^iifname "bpir-pub-h" drop$/u,
      /^oifname "bpir-pub-h" drop$/u,
    ]],
  ];
  for (const [key, patterns] of nftCases) {
    const family = key.startsWith("nft_ip6") ? "ip6" : "ip";
    const chain = key.endsWith("_input")
      ? `${family === "ip" ? "ufw" : "ufw6"}-user-input`
      : `${family === "ip" ? "ufw" : "ufw6"}-user-forward`;
    const complete = normalizedNftChain(outputs[key], family, chain);
    const lines = complete.filter((line) => line.includes("bpir-pub-h"));
    exactPatternSet(lines, patterns, key);
    const wantedPrefix = key.endsWith("_input")
      ? lines
      : key.startsWith("nft_ip6")
        ? ['oifname "bpir-pub-h" drop', 'iifname "bpir-pub-h" drop']
        : ['oifname "bpir-pub-h" drop', 'iifname "bpir-pub-h" drop'];
    if (canonical(complete.slice(0, wantedPrefix.length)) !== canonical(wantedPrefix)) {
      fail(`${key} publisher rules must be the user-chain prefix before global allows`);
    }
  }
  return true;
}

export function validatePublisherNetnsTree(root) {
  const values = new Map(PUBLISHER_NETNS_FILES.map((path) => [path, read(root, path)]));
  validateHelperSource(values.get("scripts/payment-v1-publisher-netns.c"));
  validatePublisherNamespaceOwnerUnitV1(values.get(
    "deploy/payment-v1/systemd/payment-v1-publisher-netns.service.in"));
  validatePublisherUnitV1(values.get(
    "deploy/payment-v1/systemd/payment-v1-directory-publisher.service.in"));
  validatePublisherCaddyDropIn(values.get(
    "deploy/payment-v1/systemd/bhtm-caddy.publisher-netns.conf.in"));
  validateNetworkFiles(
    values.get("deploy/payment-v1/network/directory-publisher-hosts.conf.in"),
    values.get("deploy/payment-v1/network/directory-publisher-resolv.conf.in"),
    values.get("deploy/payment-v1/network/directory-publisher-nsswitch.conf.in"),
  );
  validatePublisherNetworkPolicy(values.get(
    "deploy/payment-v1/network/directory-publisher-network-policy.json.in"));
  const networkReadme = values.get("deploy/payment-v1/network/README.md");
  for (const blocker of [
    "relay selection", "UFW", "centralized-single-relay",
    "Namespace teardown", "must not be run on Hetzner",
  ]) {
    if (!networkReadme.includes(blocker))
      fail(`publisher network README lost blocker: ${blocker}`);
  }
  return true;
}

export function publisherFirewallEvidenceFromDirectory(directory) {
  const root = resolve(directory);
  const outputs = Object.fromEntries(PUBLISHER_FIREWALL_OUTPUT_KEYS.map((key) => [
    key,
    readFileSync(join(root, `${key}.txt`), "utf8"),
  ]));
  validatePublisherFirewallOutputs(outputs);
  return outputs;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (["verify-firewall-directory", "emit-firewall-json"].includes(process.argv[2])) {
    if (process.argv.length !== 4) fail(`usage: ${process.argv[2]} DIRECTORY`);
    const outputs = publisherFirewallEvidenceFromDirectory(process.argv[3]);
    if (process.argv[2] === "emit-firewall-json") process.stdout.write(canonical(outputs));
    else process.stdout.write("payment-v1 publisher firewall evidence: ok\n");
  } else if (process.argv.length === 2) {
    validatePublisherNetnsTree(REPOSITORY);
    process.stdout.write("payment-v1 publisher netns gate: ok\n");
  } else {
    fail("usage: payment-v1-publisher-netns-gate.mjs [verify-firewall-directory|emit-firewall-json DIRECTORY]");
  }
}
