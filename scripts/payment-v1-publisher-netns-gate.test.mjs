import assert from "node:assert/strict";
import {
  chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  PUBLISHER_NETNS_FILES,
  validatePublisherFirewallOutputs,
  validatePublisherNetnsTree,
} from "./payment-v1-publisher-netns-gate.mjs";

const REPOSITORY = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "bitcoinpir-publisher-netns-gate-"));
  for (const relativePath of PUBLISHER_NETNS_FILES) {
    const destination = join(root, relativePath);
    mkdirSync(dirname(destination), { recursive: true });
    copyFileSync(join(REPOSITORY, relativePath), destination);
    chmodSync(destination, 0o644);
  }
  return root;
}

function withFixture(run) {
  const root = fixture();
  try { run(root); } finally { rmSync(root, { recursive: true, force: true }); }
}

function mutate(root, path, transform) {
  const absolute = join(root, path);
  const before = readFileSync(absolute, "utf8");
  const after = transform(before);
  assert.notEqual(after, before);
  writeFileSync(absolute, after);
}

test("checked-in publisher namespace topology passes", () => {
  assert.equal(validatePublisherNetnsTree(REPOSITORY), true);
});

test("copied publisher namespace topology passes", () => {
  withFixture((root) => assert.equal(validatePublisherNetnsTree(root), true));
});

for (const [label, path, transform, error] of [
  ["shell execution", "scripts/payment-v1-publisher-netns.c",
    (text) => `${text}\nvoid bad(void) { system(\"ip link\"); }\n`, /shell or child executable/u],
  ["execve execution", "scripts/payment-v1-publisher-netns.c",
    (text) => `${text}\nint bad_execve(char **argv) { return execve(\"/tmp/owned\", argv, argv); }\n`,
    /shell or child executable/u],
  ["direct exec syscall", "scripts/payment-v1-publisher-netns.c",
    (text) => `${text}\nlong bad_execve_syscall(char **argv) { return syscall(SYS_execve, \"/tmp/owned\", argv, argv); }\n`,
    /exec syscall directly/u],
  ["numeric direct syscall", "scripts/payment-v1-publisher-netns.c",
    (text) => `${text}\nlong bad_numeric_syscall(void) { return syscall(59, 0, 0, 0); }\n`,
    /direct syscall sites must equal/u],
  ["extra monitor seccomp syscall", "scripts/payment-v1-publisher-netns.c",
    (text) => text.replace(
      "        ALLOW_SYSCALL(read),",
      "        ALLOW_SYSCALL(openat),\n        ALLOW_SYSCALL(read),",
    ), /complete reviewed filter/u],
  ["numeric monitor seccomp allow verdict", "scripts/payment-v1-publisher-netns.c",
    (text) => text.replace(
      "        ALLOW_SYSCALL(exit_group),\n        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),",
      "        ALLOW_SYSCALL(exit_group),\n        BPF_STMT(BPF_RET | BPF_K, 0x7fff0000U),",
    ), /complete reviewed filter/u],
  ["monitor seccomp kill macro shadow", "scripts/payment-v1-publisher-netns.c",
    (text) => text.replace(
      "#define ALLOW_SYSCALL(name)",
      "#undef SECCOMP_RET_KILL_PROCESS\n#define SECCOMP_RET_KILL_PROCESS 0x7fff0000U\n#define ALLOW_SYSCALL(name)",
    ), /must not undefine/u],
  ["cleanup intent", "scripts/payment-v1-publisher-netns.c",
    (text) => text.replace('"70-cleanup-intent"', '"71-cleanup-intent"'), /70-cleanup-intent/u],
  ["source address", "scripts/payment-v1-publisher-netns.c",
    (text) => text.replace('#define CLIENT_ADDRESS_TEXT "10.203.0.2"',
      '#define CLIENT_ADDRESS_TEXT "10.203.0.9"'), /preprocessor surface|CLIENT_ADDRESS_TEXT/u],
  ["seccomp", "scripts/payment-v1-publisher-netns.c",
    (text) => text.replaceAll("SECCOMP_RET_KILL_PROCESS", "SECCOMP_RET_ALLOW"), /SECCOMP_RET_KILL_PROCESS/u],
  ["early readiness", "scripts/payment-v1-publisher-netns.c",
    (text) => text.replace(
      "    if (verify_host_topology(host_nl, &topology, true) != 0 ||\n        monitor_fd_is_one(host_ipv6_fd) != 0 ||\n        wait_for_client_monitor_ready",
      "    if (notify_ready(&notifier) != 0) return -1;\n    if (verify_host_topology(host_nl, &topology, true) != 0 ||\n        monitor_fd_is_one(host_ipv6_fd) != 0 ||\n        wait_for_client_monitor_ready",
    ), /notify READY only after/u],
  ["mount namespace sandbox", "deploy/payment-v1/systemd/payment-v1-publisher-netns.service.in",
    (text) => text.replace("NoNewPrivileges=true", "ProtectSystem=strict\nNoNewPrivileges=true"),
    /Service keys must equal|would hide the named nsfs mount/u],
  ["namespace owner no-new-privileges", "deploy/payment-v1/systemd/payment-v1-publisher-netns.service.in",
    (text) => text.replace("NoNewPrivileges=true", "NoNewPrivileges=false"),
    /NoNewPrivileges must equal/u],
  ["namespace owner state directory mode", "deploy/payment-v1/systemd/payment-v1-publisher-netns.service.in",
    (text) => text.replace("StateDirectoryMode=0700", "StateDirectoryMode=0777"),
    /StateDirectoryMode must equal/u],
  ["namespace owner writable executable memory", "deploy/payment-v1/systemd/payment-v1-publisher-netns.service.in",
    (text) => text.replace("MemoryDenyWriteExecute=true", "MemoryDenyWriteExecute=false"),
    /MemoryDenyWriteExecute must equal/u],
  ["namespace owner shell preflight", "deploy/payment-v1/systemd/payment-v1-publisher-netns.service.in",
    (text) => text.replace("ExecStartPre=/usr/bin/test -x", "ExecStartPre=/bin/sh -c true\nExecStartPre=/usr/bin/test -x"),
    /ExecStartPre must equal/u],
  ["helper restart", "deploy/payment-v1/systemd/payment-v1-publisher-netns.service.in",
    (text) => text.replace("Restart=no", "Restart=on-failure"), /Restart must equal/u],
  ["Caddy lifecycle", "deploy/payment-v1/systemd/bhtm-caddy.publisher-netns.conf.in",
    (text) => text.replace("Wants=bitcoinpir-payment-v1-publisher-netns.service\n", ""),
    /Unit keys must equal|Wants must equal/u],
  ["Caddy reverse stop coupling", "deploy/payment-v1/systemd/bhtm-caddy.publisher-netns.conf.in",
    (text) => text.replace("After=bitcoinpir-payment-v1-publisher-netns.service\n",
      "After=bitcoinpir-payment-v1-publisher-netns.service\nBindsTo=bitcoinpir-payment-v1-publisher-netns.service\n"),
    /Unit keys must equal|must not propagate/u],
  ["publisher namespace", "deploy/payment-v1/systemd/payment-v1-directory-publisher.service.in",
    (text) => text.replace("NetworkNamespacePath=/run/netns/bpir-directory-publisher\n", ""),
    /Service keys must equal|NetworkNamespacePath must equal/u],
  ["publisher key", "deploy/payment-v1/systemd/payment-v1-directory-publisher.service.in",
    (text) => text.replace(" --now-unix", " --signing-key /tmp/key --now-unix"),
    /must not read a key/u],
  ["publisher centralized-mode flag", "deploy/payment-v1/systemd/payment-v1-directory-publisher.service.in",
    (text) => text.replace(" --centralized-single-relay", ""),
    /unreviewed publication argv shape/u],
  ["publisher second relay", "deploy/payment-v1/systemd/payment-v1-directory-publisher.service.in",
    (text) => text.replace(" --centralized-single-relay",
      " --relay wss:\/\/relay-two.invalid\/v1\/directory --centralized-single-relay"),
    /unreviewed publication argv shape/u],
  ["publisher retry", "deploy/payment-v1/systemd/payment-v1-directory-publisher.service.in",
    (text) => text.replace("Restart=no", "Restart=on-failure"), /Restart must equal/u],
  ["publisher host runtime visibility", "deploy/payment-v1/systemd/payment-v1-directory-publisher.service.in",
    (text) => text.replace("TemporaryFileSystem=/run:ro", "TemporaryFileSystem=/tmp:ro"),
    /TemporaryFileSystem must equal/u],
  ["publisher host run bind alias", "deploy/payment-v1/systemd/payment-v1-directory-publisher.service.in",
    (text) => text.replace(
      "BindReadOnlyPaths=/etc/bitcoinpir/payment-v1/directory-publisher/hosts:/etc/hosts",
      "BindReadOnlyPaths=/run:/host-run\nBindReadOnlyPaths=/etc/bitcoinpir/payment-v1/directory-publisher/hosts:/etc/hosts",
    ), /BindReadOnlyPaths must equal/u],
  ["external DNS", "deploy/payment-v1/network/directory-publisher-resolv.conf.in",
    (text) => text.replace("127.0.0.1", "1.1.1.1"), /resolver must be local/u],
  ["ambient NSS", "deploy/payment-v1/network/directory-publisher-nsswitch.conf.in",
    (text) => text.replace("hosts: files", "hosts: files dns"), /NSS must use files only/u],
]) {
  test(`gate rejects ${label}`, () => {
    withFixture((root) => {
      mutate(root, path, transform);
      assert.throws(() => validatePublisherNetnsTree(root), error);
    });
  });
}

function nftChain(family, name, rules = []) {
  return `table ${family} filter {
  chain ${name} {
${rules.map((rule) => `    ${rule}`).join("\n")}${rules.length === 0 ? "" : "\n"}  }
}
`;
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

test("closed UFW/raw/nft publisher firewall evidence passes", () => {
  assert.equal(validatePublisherFirewallOutputs(firewallOutputs()), true);
});

test("firewall evidence rejects an extra publisher-interface rule", () => {
  const outputs = firewallOutputs();
  outputs.nft_ip_input = outputs.nft_ip_input.replace(
    "  }\n}",
    "    iifname \"bpir-pub-h\" udp dport 53 counter packets 0 bytes 0 accept\n  }\n}",
  );
  assert.throws(() => validatePublisherFirewallOutputs(outputs), /exactly 2/u);
});

test("firewall evidence rejects a global input allow before the publisher prefix", () => {
  const outputs = firewallOutputs();
  outputs.nft_ip_input = outputs.nft_ip_input.replace(
    "  chain ufw-user-input {\n",
    "  chain ufw-user-input {\n    tcp dport 22 counter packets 0 bytes 0 accept\n",
  );
  assert.throws(() => validatePublisherFirewallOutputs(outputs), /before global allows/u);
});

test("firewall evidence rejects an interface-free UDP allow in the UFW prelude", () => {
  const outputs = firewallOutputs();
  outputs.nft_ip_before_input = outputs.nft_ip_before_input.replace(
    "    jump ufw-not-local",
    "    ip saddr 10.203.0.2 ip daddr 10.203.0.1 udp dport 31337 counter packets 0 bytes 0 accept\n    jump ufw-not-local",
  );
  assert.throws(
    () => validatePublisherFirewallOutputs(outputs),
    /unreviewed early accept/u,
  );
});

test("firewall evidence rejects a direct base-chain allow before UFW", () => {
  const outputs = firewallOutputs();
  outputs.nft_ip_base_input = outputs.nft_ip_base_input.replace(
    "    type filter hook input priority filter; policy drop;\n",
    "    type filter hook input priority filter; policy drop;\n    tcp dport 22 accept\n",
  );
  assert.throws(() => validatePublisherFirewallOutputs(outputs), /exact UFW drop-policy/u);
});

test("firewall evidence rejects a global forward allow before interface drops", () => {
  const outputs = firewallOutputs();
  outputs.nft_ip_forward = outputs.nft_ip_forward.replace(
    "  chain ufw-user-forward {\n",
    "  chain ufw-user-forward {\n    ct state new counter packets 0 bytes 0 accept\n",
  );
  assert.throws(() => validatePublisherFirewallOutputs(outputs), /before global allows/u);
});

test("firewall evidence rejects input deny before its sole allow", () => {
  const outputs = firewallOutputs();
  const lines = outputs.ufw_status.split("\n");
  [lines[1], lines[2]] = [lines[2], lines[1]];
  outputs.ufw_status = lines.join("\n");
  assert.throws(() => validatePublisherFirewallOutputs(outputs), /allow must precede/u);
});

test("optional compiled helper runs its pure self-test", { skip: !process.env.BPIR_PUBLISHER_NETNS_HELPER_BIN }, () => {
  const result = spawnSync(process.env.BPIR_PUBLISHER_NETNS_HELPER_BIN, ["self-test"], {
    encoding: "utf8",
    shell: false,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /self-test: ok/u);
});
