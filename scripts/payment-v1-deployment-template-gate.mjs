#!/usr/bin/env node

import { createHash } from "node:crypto";
import {
  lstatSync,
  readFileSync,
  readdirSync,
} from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const ACTIVE_BASELINES = Object.freeze({
  "deploy/systemd/pir-primary.service":
    "bec78a3771c3e4cb56445ba21842bdbb4198b4ccba2af3740ec39ffc8f929e7f",
  "deploy/systemd/pir-secondary.service":
    "177c238658dd00edb59e4d8c48776a3117c8fccf903317f8c1843d837a3848aa",
  "deploy/systemd/pir-vpsbg.service":
    "4b329ed00d182a09f1832218fd6683bc1e98087ee4ab3ece1ecf264bc422dba9",
  "deploy/systemd/dev-issuer.service":
    "07e500d2997ca50bc558d7694b54f709a338c16d1cf37cc05cceeb01c89f90de",
  "deploy/systemd/cloudflared.service":
    "2a405d952610f5132453c80198ab2486b3884ee83b8c4674d04425cc3c81715c",
  "scripts/dracut/97bpir-tier3-init/unified-server-run.sh":
    "5e1a0bc588326c0355f17a473d1c962b172f2aa4c4c0f1d9b18520964c5dc27c",
});

export const REVIEWED_PREPARATION_HASHES = Object.freeze({
  "deploy/payment-v1/edge/hetzner-public.Caddyfile.in":
    "d54ae5e0ec9fea4a72b1eb83ebe1225f18d386437b639db7bc49fa03f730a3d8",
  "deploy/payment-v1/edge/rollback-authority.Caddyfile.in":
    "7aa07c8d18c94708e6e58034066b1908456e6a5ac64d2ac2d169f4ed6822b95d",
  "deploy/payment-v1/lightning/activation-prerequisites.toml.example":
    "937737e212f2be0a2fda92fe1aaa421b1aeefdd074261ca78485ca9430d0c443",
  "deploy/payment-v1/lightning/cln-rpc-guard-tmpfiles.conf.in":
    "62b6a6108b4c5768f5de522d72d93a84e97e07f0d93f5dfc02265a87eb18fc31",
  "deploy/payment-v1/lightning/issuer-cln.args.in":
    "1da053febf373f7166935e0d57abe140e129931accbb856d93889c4fc979b6f4",
  "deploy/payment-v1/lightning/lightningd.conf.in":
    "58973f2b3992a6eb0a2cd4b94b6d878f01240b5ba92d84da5a91ef0c442159f9",
  "deploy/payment-v1/lightning/verify-layout.sh.in":
    "a3e3c9033bb0e258c2393117a4b3d17388002a21ae9b8259eed64b90bf2f57ea",
  "deploy/payment-v1/systemd/hetzner-core-lightning.service.in":
    "50e86c87bf435c94d62265854e211abb93bb25d6f3c1636c6893a25be80a8df9",
  "deploy/payment-v1/systemd/hetzner-cln-rpc-guard.service.in":
    "119ed3ce7b9c48c68b85dc8a37325a8c8c35b6a5f45137859d9b4fbe3f35b9aa",
  "deploy/payment-v1/systemd/hetzner-lightning-preflight.service.in":
    "e0fa6b1213ae660f74a541d086a16f0c20b8b8eac91f7afe780ffb4ff67ed2ee",
  "deploy/payment-v1/systemd/hetzner-payment-issuer.service.in":
    "c9557f8d547bc4b800593452f5308d91d65419603e5a5f046f5d06af9033b4e9",
  "deploy/payment-v1/systemd/payment-v1-edge.service.in":
    "49edab939937c98d420e6a6bef6ad3a834effa502630deb666229272993ca841",
});

export const REQUIRED_PREPARATION_FILES = Object.freeze([
  "deploy/payment-v1/README.md",
  "deploy/payment-v1/directory-relay.toml.example",
  "deploy/payment-v1/relay-selection.toml.example",
  "deploy/payment-v1/edge/README.md",
  "deploy/payment-v1/edge/hetzner-public.Caddyfile.in",
  "deploy/payment-v1/edge/rollback-authority.Caddyfile.in",
  "deploy/payment-v1/lightning/README.md",
  "deploy/payment-v1/lightning/activation-prerequisites.toml.example",
  "deploy/payment-v1/lightning/cln-rpc-guard-tmpfiles.conf.in",
  "deploy/payment-v1/lightning/issuer-cln.args.in",
  "deploy/payment-v1/lightning/lightningd.conf.in",
  "deploy/payment-v1/lightning/verify-layout.sh.in",
  "deploy/payment-v1/systemd/hetzner-core-lightning.service.in",
  "deploy/payment-v1/systemd/hetzner-cln-rpc-guard.service.in",
  "deploy/payment-v1/systemd/hetzner-lightning-preflight.service.in",
  "deploy/payment-v1/systemd/payment-v1-edge.service.in",
  "deploy/payment-v1/systemd/hetzner-provider.service.in",
  "deploy/payment-v1/systemd/hetzner-payment-issuer.service.in",
  "deploy/payment-v1/systemd/rollback-authority.service.in",
  "deploy/payment-v1/systemd/hetzner-directory-relay.service.in",
  "deploy/payment-v1/vpsbg/vpsbg-free-pow-service-auth.args.in",
  "docs/payment/HETZNER_VPSBG_DEPLOYMENT.md",
]);

const TEMPLATE_ROOT = "deploy/payment-v1";
const ACTIVATION_SENTINEL =
  "ConditionPathExists=/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED";
const UNSAFE_RELAY_COMMITS = new Set([
  "ff65ec2acd781150a585a78e1c60b0cdb104698e",
  "b5c1f642e4f4c3b9c54f5d18d66f4c53642076b4",
]);
const HASH_FIELDS = Object.freeze([
  "source_archive_sha256",
  "cargo_lock_sha256",
  "binary_sha256",
  "config_sha256",
]);
const UNRESOLVED_FIELDS = Object.freeze([
  "implementation",
  "source_repository",
  "source_commit",
  ...HASH_FIELDS,
  "binary_version_output",
  "publisher_pubkey_hex",
]);

function fail(message) {
  throw new Error(message);
}

function readRequired(root, relativePath) {
  const absolute = join(root, relativePath);
  let stat;
  try {
    stat = lstatSync(absolute);
  } catch {
    fail(`required deployment file is missing: ${relativePath}`);
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    fail(`deployment input must be a regular non-symlink file: ${relativePath}`);
  }
  return { absolute, stat, text: readFileSync(absolute, "utf8") };
}

function sha256File(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function requireText(text, needle, label) {
  if (!text.includes(needle)) {
    fail(`${label} is missing required text: ${needle}`);
  }
}

function rejectPattern(text, pattern, label, description) {
  if (pattern.test(text)) {
    fail(`${label} contains forbidden ${description}`);
  }
}

function parseSystemdUnit(text, label) {
  const logicalLines = [];
  let pending = "";
  for (const original of text.split(/\r?\n/u)) {
    const trimmed = original.trim();
    if (trimmed === "" || trimmed.startsWith("#") || trimmed.startsWith(";")) {
      continue;
    }
    const continued = original.trimEnd().endsWith("\\");
    const fragment = continued
      ? original.trimEnd().slice(0, -1).trim()
      : original.trim();
    pending = pending === "" ? fragment : `${pending} ${fragment}`;
    if (!continued) {
      logicalLines.push(pending);
      pending = "";
    }
  }
  if (pending !== "") fail(`${label} ends with an unterminated continuation`);

  const sections = new Map();
  let section;
  for (const line of logicalLines) {
    const sectionMatch = /^\[([A-Za-z][A-Za-z0-9]*)\]$/.exec(line);
    if (sectionMatch) {
      section = sectionMatch[1];
      if (sections.has(section)) fail(`${label} repeats [${section}]`);
      if (section !== "Unit" && section !== "Service") {
        fail(`${label} contains forbidden [${section}] section`);
      }
      sections.set(section, new Map());
      continue;
    }
    if (section === undefined) fail(`${label} has a directive outside a section`);
    const directive = /^([A-Za-z][A-Za-z0-9]*)=(.*)$/.exec(line);
    if (!directive) fail(`${label} has a malformed systemd directive: ${line}`);
    const key = directive[1];
    const value = directive[2].trim();
    if (value === "" && key !== "CapabilityBoundingSet" && key !== "AmbientCapabilities") {
      fail(`${label} contains forbidden empty ${key}= reset`);
    }
    const values = sections.get(section).get(key) ?? [];
    values.push(value);
    sections.get(section).set(key, values);
  }
  for (const required of ["Unit", "Service"]) {
    if (!sections.has(required)) fail(`${label} is missing [${required}]`);
  }
  return sections;
}

function directiveValues(unit, section, key) {
  return unit.get(section)?.get(key) ?? [];
}

function exactDirectiveValues(unit, section, key, expected, label) {
  const actual = directiveValues(unit, section, key);
  if (
    actual.length !== expected.length ||
    actual.some((value, index) => value !== expected[index])
  ) {
    fail(
      `${label} ${section}.${key} must equal ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
    );
  }
}

function onlyDirectiveValue(unit, section, key, label) {
  const values = directiveValues(unit, section, key);
  if (values.length !== 1) {
    fail(`${label} must contain exactly one ${section}.${key}`);
  }
  return values[0];
}

function exactDirectiveKeys(unit, section, expected, label) {
  const actual = [...(unit.get(section)?.keys() ?? [])].sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((value, index) => value !== wanted[index])
  ) {
    fail(
      `${label} ${section} directive keys must equal ${JSON.stringify(wanted)}, got ${JSON.stringify(actual)}`,
    );
  }
}

function validateExactCommand(command, prefix, options, label) {
  rejectPattern(command, /["'`;|&<>$]/u, label, "shell/meta syntax in ExecStart");
  const tokens = command.trim().split(/\s+/u);
  let cursor = 0;
  for (const expected of prefix) {
    if (tokens[cursor] !== expected) {
      fail(`${label} command prefix must contain ${expected} at argv[${cursor}]`);
    }
    cursor += 1;
  }
  for (const [flag, value] of options) {
    if (tokens[cursor] !== flag) {
      fail(`${label} must contain ${flag} exactly once and in canonical order`);
    }
    cursor += 1;
    if (value !== null) {
      if (tokens[cursor] !== value) {
        fail(`${label} ${flag} must equal ${value}`);
      }
      cursor += 1;
    }
  }
  if (cursor !== tokens.length) {
    fail(`${label} contains an unreviewed, duplicate, or positional argv value`);
  }
}

const COMMON_UNIT_KEYS = new Set([
  "Description",
  "After",
  "Wants",
  "Requires",
  "BindsTo",
  "Before",
  "ConditionPathExists",
]);
const BASIC_UNIT_KEYS = Object.freeze([
  "Description",
  "After",
  "Wants",
  "ConditionPathExists",
]);
const COMMON_SERVICE_KEYS = new Set([
  "Type",
  "User",
  "Group",
  "UMask",
  "StateDirectory",
  "StateDirectoryMode",
  "RuntimeDirectory",
  "RuntimeDirectoryMode",
  "WorkingDirectory",
  "ExecStart",
  "Restart",
  "RestartSec",
  "TimeoutStopSec",
  "TimeoutStartSec",
  "LimitNOFILE",
  "SupplementaryGroups",
  "Environment",
  "NoNewPrivileges",
  "PrivateTmp",
  "PrivateDevices",
  "ProtectSystem",
  "ProtectHome",
  "ProtectKernelTunables",
  "ProtectKernelModules",
  "ProtectKernelLogs",
  "ProtectControlGroups",
  "ProtectClock",
  "ProtectHostname",
  "LockPersonality",
  "MemoryDenyWriteExecute",
  "RestrictSUIDSGID",
  "RestrictNamespaces",
  "RestrictRealtime",
  "SystemCallArchitectures",
  "CapabilityBoundingSet",
  "AmbientCapabilities",
  "RestrictAddressFamilies",
  "IPAddressDeny",
  "IPAddressAllow",
  "ReadOnlyPaths",
  "ReadWritePaths",
  "InaccessiblePaths",
  "ExecStartPre",
  "RemainAfterExit",
]);

function validateDirectiveShape(unit, label) {
  for (const [section, directives] of unit) {
    const allowed = section === "Unit" ? COMMON_UNIT_KEYS : COMMON_SERVICE_KEYS;
    for (const [key, values] of directives) {
      if (!allowed.has(key)) fail(`${label} contains unreviewed ${section}.${key}`);
      if (
        values.length !== 1 &&
        key !== "ExecStartPre" &&
        key !== "ConditionPathExists"
      ) {
        fail(`${label} repeats singleton ${section}.${key}`);
      }
    }
  }
}

function validateInactiveSystemdTemplate(
  text,
  label,
  expectedConditions,
  { requireStateDirectoryMode = true } = {},
) {
  rejectPattern(text, /^\s*\[Install\]\s*$/m, label, "[Install] section");
  const unit = parseSystemdUnit(text, label);
  validateDirectiveShape(unit, label);
  exactDirectiveValues(
    unit,
    "Unit",
    "ConditionPathExists",
    expectedConditions,
    label,
  );
  if (requireStateDirectoryMode) {
    exactDirectiveValues(unit, "Service", "StateDirectoryMode", ["0700"], label);
  }
  exactDirectiveValues(unit, "Service", "NoNewPrivileges", ["true"], label);
  exactDirectiveValues(unit, "Service", "ProtectSystem", ["strict"], label);
  exactDirectiveValues(unit, "Service", "ProtectHome", ["true"], label);
  onlyDirectiveValue(unit, "Service", "ExecStart", label);
  return unit;
}

function validateCommonServiceHardening(unit, label, privateDevices) {
  for (const [key, value] of [
    ["Type", "simple"],
    ["UMask", "0077"],
    ["StateDirectoryMode", "0700"],
    ["TimeoutStopSec", "30"],
    ["NoNewPrivileges", "true"],
    ["PrivateTmp", "true"],
    ["ProtectSystem", "strict"],
    ["ProtectHome", "true"],
    ["ProtectKernelTunables", "true"],
    ["ProtectKernelModules", "true"],
    ["ProtectKernelLogs", "true"],
    ["ProtectControlGroups", "true"],
    ["LockPersonality", "true"],
    ["MemoryDenyWriteExecute", "true"],
    ["RestrictSUIDSGID", "true"],
    ["RestrictNamespaces", "true"],
    ["RestrictRealtime", "true"],
    ["SystemCallArchitectures", "native"],
    ["RestrictAddressFamilies", "AF_UNIX AF_INET AF_INET6"],
  ]) {
    exactDirectiveValues(unit, "Service", key, [value], label);
  }
  exactDirectiveValues(unit, "Service", "CapabilityBoundingSet", [""], label);
  exactDirectiveValues(unit, "Service", "AmbientCapabilities", [""], label);
  exactDirectiveValues(
    unit,
    "Service",
    "PrivateDevices",
    privateDevices ? ["true"] : [],
    label,
  );
}

function validatePinnedServiceSandbox(unit, label, type, capabilities) {
  exactDirectiveValues(unit, "Service", "Type", [type], label);
  exactDirectiveValues(unit, "Service", "UMask", ["0077"], label);
  for (const key of [
    "NoNewPrivileges",
    "PrivateDevices",
    "PrivateTmp",
    "ProtectHome",
    "ProtectKernelTunables",
    "ProtectKernelModules",
    "ProtectKernelLogs",
    "ProtectControlGroups",
    "ProtectClock",
    "ProtectHostname",
    "LockPersonality",
    "MemoryDenyWriteExecute",
    "RestrictSUIDSGID",
    "RestrictNamespaces",
    "RestrictRealtime",
  ]) {
    exactDirectiveValues(unit, "Service", key, ["true"], label);
  }
  exactDirectiveValues(unit, "Service", "ProtectSystem", ["strict"], label);
  exactDirectiveValues(unit, "Service", "SystemCallArchitectures", ["native"], label);
  exactDirectiveValues(
    unit,
    "Service",
    "CapabilityBoundingSet",
    [capabilities],
    label,
  );
  exactDirectiveValues(
    unit,
    "Service",
    "AmbientCapabilities",
    [capabilities],
    label,
  );
  exactDirectiveValues(
    unit,
    "Service",
    "RestrictAddressFamilies",
    ["AF_UNIX AF_INET AF_INET6"],
    label,
  );
}

function validateProductionForbiddenFlags(text, label) {
  const forbidden = [
    [/--allow-local-service-rollback-authority-dev(?:\s|$)/, "local provider rollback acknowledgement"],
    [/--allow-local-rollback-authority-dev(?:\s|$)/, "local issuer rollback acknowledgement"],
    [/(?:^|\s)--service-rollback-authority(?:\s|=)/m, "local provider rollback authority"],
    [/(?:^|\s)--rollback-authority(?:\s|=)/m, "local issuer rollback authority"],
    [/--allow-experimental-arc(?:\s|$)/, "experimental ARC acknowledgement"],
    [/--service-arc-key(?:\s|$)/, "provider ARC key"],
    [/(?:^|\s)--arc-key(?:\s|$)/m, "issuer ARC key"],
    [/--require-arc(?:\s|$)/, "legacy ARC gate"],
    [/--require-cashu(?:\s|$)/, "legacy Cashu gate"],
    [/--cashu-keyset(?:\s|$)/, "legacy Cashu keyset"],
    [/\bserve-fake\b/, "fake Lightning serving mode"],
    [/--fake-lightning-[a-z-]+(?:\s|$)/, "fake Lightning material"],
    [/--test-only-service-https-root-pem(?:\s|$)/, "test-only trust root"],
    [/--unsafe-debug-query-logging(?:\s|$)/, "unsafe query logging"],
    [/--service-free-ip-key(?:\s|$)/, "Free IP key behind a proxy"],
    [/--service-trust-direct-peer-ip(?:\s|$)/, "direct peer-IP trust behind a proxy"],
    [/--clearing-payout-target(?:\s|=|$)/, "production clearing payout target"],
    [/--clearing-payout-fee(?:\s|=|$)/, "production clearing payout fee"],
    [/--clearing-payout-intent-ttl-seconds(?:\s|=|$)/, "production payout intent TTL"],
  ];
  for (const [pattern, description] of forbidden) {
    rejectPattern(text, pattern, label, description);
  }
}

function validateHetznerProvider(text) {
  const label = "Hetzner provider template";
  const unit = validateInactiveSystemdTemplate(text, label, [
    "/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
  ]);
  exactDirectiveKeys(unit, "Unit", BASIC_UNIT_KEYS, label);
  exactDirectiveKeys(
    unit,
    "Service",
    [
      "Type", "User", "Group", "UMask", "StateDirectory", "StateDirectoryMode",
      "WorkingDirectory", "ExecStartPre", "ExecStart", "Restart", "RestartSec",
      "TimeoutStopSec", "LimitNOFILE", "NoNewPrivileges", "PrivateTmp",
      "PrivateDevices", "ProtectSystem", "ProtectHome", "ProtectKernelTunables",
      "ProtectKernelModules", "ProtectKernelLogs", "ProtectControlGroups",
      "ProtectClock", "ProtectHostname", "LockPersonality",
      "MemoryDenyWriteExecute", "RestrictSUIDSGID", "RestrictNamespaces",
      "RestrictRealtime", "SystemCallArchitectures", "CapabilityBoundingSet",
      "AmbientCapabilities", "RestrictAddressFamilies", "ReadOnlyPaths", "ReadWritePaths",
    ],
    label,
  );
  validateCommonServiceHardening(unit, label, true);
  exactDirectiveValues(unit, "Unit", "Description", ["BitcoinPIR Hetzner Payment V1 provider (template only)"], label);
  exactDirectiveValues(unit, "Unit", "After", ["network-online.target"], label);
  exactDirectiveValues(unit, "Unit", "Wants", ["network-online.target"], label);
  exactDirectiveValues(unit, "Service", "User", ["bitcoinpir-provider"], label);
  exactDirectiveValues(unit, "Service", "Group", ["bitcoinpir-provider"], label);
  exactDirectiveValues(unit, "Service", "StateDirectory", ["bitcoinpir-provider-payment-v1"], label);
  exactDirectiveValues(unit, "Service", "WorkingDirectory", ["/var/lib/bitcoinpir-provider-payment-v1"], label);
  exactDirectiveValues(unit, "Service", "Restart", ["on-failure"], label);
  exactDirectiveValues(unit, "Service", "RestartSec", ["5"], label);
  exactDirectiveValues(unit, "Service", "LimitNOFILE", ["65535"], label);
  exactDirectiveValues(unit, "Service", "ProtectClock", ["true"], label);
  exactDirectiveValues(unit, "Service", "ProtectHostname", ["true"], label);
  exactDirectiveValues(unit, "Service", "ReadOnlyPaths", ["/etc/bitcoinpir/payment-v1/provider"], label);
  exactDirectiveValues(unit, "Service", "ReadWritePaths", ["/var/lib/bitcoinpir-provider-payment-v1"], label);
  exactDirectiveValues(
    unit,
    "Service",
    "ExecStartPre",
    [
      "/usr/bin/test -x /opt/bitcoinpir/unified-server/@UNIFIED_SERVER_SHA256@/unified_server",
      "/usr/bin/sha256sum --check /etc/bitcoinpir/payment-v1/provider/unified-server.sha256",
    ],
    label,
  );
  const command = onlyDirectiveValue(unit, "Service", "ExecStart", label);
  validateProductionForbiddenFlags(command, label);
  validateExactCommand(
    command,
    ["/opt/bitcoinpir/unified-server/@UNIFIED_SERVER_SHA256@/unified_server"],
    [
      ["--bind-address", "127.0.0.1"],
      ["--port", "8191"],
      ["--role", "primary"],
      ["--serve-hints", null],
      ["--serve-queries", null],
      ["--pool-size", "8"],
      ["--pool-dir", "/var/lib/bitcoinpir-provider-payment-v1/hint-pool"],
      ["--config", "/etc/bitcoinpir/payment-v1/provider/databases.toml"],
      ["--identity-key-path", "/etc/bitcoinpir/payment-v1/provider/provider-identity.key"],
      ["--identity-cert-path", "/etc/bitcoinpir/payment-v1/provider/provider-identity.cert"],
      ["--identity-server-id", "@HETZNER_PROVIDER_SERVER_ID@"],
      ["--require-service-auth-v1", null],
      ["--service-policy", "/etc/bitcoinpir/payment-v1/provider/service-policy.bin"],
      ["--service-provider-id-hex", "@HETZNER_PROVIDER_ID_HEX@"],
      ["--service-policy-key-hex", "@HETZNER_POLICY_PUBKEY_HEX@"],
      ["--service-store", "/var/lib/bitcoinpir-provider-payment-v1/provider.sqlite3"],
      ["--service-remote-rollback-authority-config", "/etc/bitcoinpir/payment-v1/provider/remote-rollback-authority.toml"],
      ["--service-bat-key", "/etc/bitcoinpir/payment-v1/provider/cashu-bat.key"],
      ["--service-cashu-recovery-key", "1=/etc/bitcoinpir/payment-v1/provider/cashu-recovery-epoch-1.key"],
      ["--service-cashu-recovery-active-epoch", "1"],
      ["--service-cashu-custody-key", "1=/etc/bitcoinpir/payment-v1/provider/cashu-custody-epoch-1.key"],
      ["--service-cashu-custody-active-epoch", "1"],
      ["--service-cashu-exposure-limit", "@CASHU_MINT_ID_HEX@:sat:@CASHU_MAX_UNSETTLED_VALUE@:@CASHU_MAX_UNSETTLED_NOTES@"],
      ["--service-shared-authorization", "/etc/bitcoinpir/payment-v1/provider/shared-clearing-authorization.bin"],
      ["--service-shared-issuer-approval", "/etc/bitcoinpir/payment-v1/provider/shared-clearing-approval.bin"],
      ["--service-shared-operator-key-hex", "@HETZNER_OPERATOR_PUBKEY_HEX@"],
      ["--service-shared-issuer-settlement-key-hex", "@ISSUER_SETTLEMENT_PUBKEY_HEX@"],
      ["--service-shared-clearing-key", "/etc/bitcoinpir/payment-v1/provider/provider-clearing-signing.key"],
      ["--service-shared-idempotency-key", "/etc/bitcoinpir/payment-v1/provider/shared-redeem-idempotency.key"],
      ["--service-shared-minimum-authorization-epoch", "@SHARED_MINIMUM_AUTHORIZATION_EPOCH@"],
      ["--max-connections", "128"],
      ["--service-max-concurrent-auth", "16"],
      ["--service-max-concurrent-online-v2full-auth", "4"],
      ["--websocket-handshake-timeout-ms", "10000"],
      ["--connection-idle-timeout-ms", "30000"],
      ["--service-pre-auth-timeout-ms", "60000"],
    ],
    label,
  );
  const recovery = /--service-cashu-recovery-key\s+1=(\S+)/.exec(command)?.[1];
  const custody = /--service-cashu-custody-key\s+1=(\S+)/.exec(command)?.[1];
  if (recovery === undefined || custody === undefined || recovery === custody) {
    fail(`${label} must use distinct explicit Cashu recovery and custody keys`);
  }
}

function validateHetznerIssuer(text) {
  const label = "Hetzner issuer template";
  const unit = validateInactiveSystemdTemplate(text, label, [
    "/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
    "/etc/bitcoinpir/payment-v1/LIGHTNING-CUSTODY-APPROVED",
    "/etc/bitcoinpir/payment-v1/LIGHTNING-BACKUP-RESTORE-APPROVED",
  ]);
  exactDirectiveKeys(
    unit,
    "Unit",
    [
      "Description",
      "After",
      "Wants",
      "Requires",
      "BindsTo",
      "ConditionPathExists",
    ],
    label,
  );
  exactDirectiveKeys(
    unit,
    "Service",
    [
      "Type", "User", "Group", "UMask", "StateDirectory",
      "StateDirectoryMode", "WorkingDirectory", "ExecStartPre", "ExecStart", "Restart",
      "RestartSec", "TimeoutStopSec", "NoNewPrivileges", "PrivateTmp", "ProtectSystem",
      "PrivateDevices", "ProtectHome", "ProtectKernelTunables", "ProtectKernelModules",
      "ProtectKernelLogs", "ProtectControlGroups", "LockPersonality",
      "ProtectClock", "ProtectHostname",
      "MemoryDenyWriteExecute", "RestrictSUIDSGID", "RestrictNamespaces",
      "RestrictRealtime", "SystemCallArchitectures", "CapabilityBoundingSet",
      "AmbientCapabilities", "RestrictAddressFamilies", "ReadOnlyPaths", "ReadWritePaths",
      "InaccessiblePaths",
    ],
    label,
  );
  validateCommonServiceHardening(unit, label, true);
  exactDirectiveValues(unit, "Unit", "Description", ["BitcoinPIR Hetzner Core Lightning payment issuer (template only)"], label);
  exactDirectiveValues(unit, "Unit", "After", ["network-online.target bitcoinpir-core-lightning.service bitcoinpir-cln-rpc-guard.service bitcoinpir-lightning-preflight.service"], label);
  exactDirectiveValues(unit, "Unit", "Wants", ["network-online.target"], label);
  exactDirectiveValues(unit, "Unit", "Requires", ["bitcoinpir-core-lightning.service bitcoinpir-cln-rpc-guard.service bitcoinpir-lightning-preflight.service"], label);
  exactDirectiveValues(unit, "Unit", "BindsTo", ["bitcoinpir-core-lightning.service bitcoinpir-cln-rpc-guard.service bitcoinpir-lightning-preflight.service"], label);
  exactDirectiveValues(unit, "Service", "User", ["bitcoinpir-issuer"], label);
  exactDirectiveValues(unit, "Service", "Group", ["bitcoinpir-issuer"], label);
  exactDirectiveValues(unit, "Service", "StateDirectory", ["bitcoinpir-payment-issuer"], label);
  exactDirectiveValues(unit, "Service", "WorkingDirectory", ["/var/lib/bitcoinpir-payment-issuer"], label);
  exactDirectiveValues(unit, "Service", "Restart", ["on-failure"], label);
  exactDirectiveValues(unit, "Service", "RestartSec", ["5"], label);
  exactDirectiveValues(unit, "Service", "ProtectClock", ["true"], label);
  exactDirectiveValues(unit, "Service", "ProtectHostname", ["true"], label);
  exactDirectiveValues(unit, "Service", "ReadOnlyPaths", ["/etc/bitcoinpir/payment-v1/issuer /run/bitcoinpir-cln-rpc-guard/issuer /opt/bitcoinpir/payment-issuer/@PAYMENT_ISSUER_SHA256@"], label);
  exactDirectiveValues(unit, "Service", "ReadWritePaths", ["/var/lib/bitcoinpir-payment-issuer"], label);
  exactDirectiveValues(unit, "Service", "InaccessiblePaths", ["/srv/lightning /srv/bitcoin"], label);
  exactDirectiveValues(
    unit,
    "Service",
    "ExecStartPre",
    [
      "/usr/bin/test -x /opt/bitcoinpir/payment-issuer/@PAYMENT_ISSUER_SHA256@/payment-issuer",
      "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/issuer/payment-issuer.sha256",
    ],
    label,
  );
  const command = onlyDirectiveValue(unit, "Service", "ExecStart", label);
  validateProductionForbiddenFlags(command, label);
  validateExactCommand(
    command,
    [
      "/opt/bitcoinpir/payment-issuer/@PAYMENT_ISSUER_SHA256@/payment-issuer",
      "serve-cln",
    ],
    [
      ["--bind", "127.0.0.1:5610"],
      ["--max-connections", "128"],
      ["--quote-rate-per-minute", "60"],
      ["--status-rate-per-minute", "600"],
      ["--mutation-rate-per-minute", "120"],
      ["--reconciliation-rate-per-minute", "120"],
      ["--reconciliation-batch-size", "32"],
      ["--reconciliation-interval-seconds", "15"],
      ["--reconciliation-tick-budget-ms", "5000"],
      ["--max-outstanding-quotes", "4096"],
      ["--max-total-quotes", "16384"],
      ["--allow-origin", "@BITCOINPIR_WEB_ORIGIN@"],
      ["--store", "/var/lib/bitcoinpir-payment-issuer/issuer.sqlite3"],
      ["--remote-rollback-authority-config", "/etc/bitcoinpir/payment-v1/issuer/remote-rollback-authority.toml"],
      ["--quote-delegation", "/etc/bitcoinpir/payment-v1/issuer/quote-delegation.bin"],
      ["--quote-signing-key", "/etc/bitcoinpir/payment-v1/issuer/quote-signing.key"],
      ["--credential-derivation-key", "/etc/bitcoinpir/payment-v1/issuer/credential-derivation.key"],
      ["--service-policy", "/etc/bitcoinpir/payment-v1/issuer/service-policy.bin=@HETZNER_POLICY_PUBKEY_HEX@"],
      ["--receipt-signing-key", "/etc/bitcoinpir/payment-v1/issuer/direct-receipt-signing.key"],
      ["--bat-key", "/etc/bitcoinpir/payment-v1/issuer/cashu-bat.key"],
      ["--clearing-authorization", "/etc/bitcoinpir/payment-v1/issuer/provider-clearing-authorization.bin"],
      ["--clearing-approval", "/etc/bitcoinpir/payment-v1/issuer/provider-clearing-approval.bin"],
      ["--issuer-settlement-signing-key", "/etc/bitcoinpir/payment-v1/issuer/issuer-settlement-signing.key"],
      ["--redeem-response-derivation-key", "/etc/bitcoinpir/payment-v1/issuer/redeem-response-derivation.key"],
      ["--cln-rpc-socket", "/run/bitcoinpir-cln-rpc-guard/issuer/issuer-rpc"],
      ["--cln-rpc-expected-uid", "@CLN_GUARD_UID@"],
      ["--cln-rpc-expected-gid", "@ISSUER_GID@"],
      ["--cln-rpc-timeout-seconds", "10"],
    ],
    label,
  );
}

function validateRollbackAuthority(text) {
  const label = "rollback-authority template";
  const unit = validateInactiveSystemdTemplate(text, label, [
    "/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
  ]);
  exactDirectiveKeys(unit, "Unit", BASIC_UNIT_KEYS, label);
  exactDirectiveKeys(
    unit,
    "Service",
    [
      "Type", "User", "Group", "UMask", "StateDirectory", "StateDirectoryMode",
      "WorkingDirectory", "ExecStartPre", "ExecStart", "Restart", "RestartSec",
      "TimeoutStopSec", "NoNewPrivileges", "PrivateTmp", "ProtectSystem", "ProtectHome",
      "PrivateDevices", "ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs",
      "ProtectControlGroups", "LockPersonality", "MemoryDenyWriteExecute",
      "RestrictSUIDSGID", "RestrictNamespaces", "RestrictRealtime",
      "SystemCallArchitectures", "CapabilityBoundingSet", "AmbientCapabilities",
      "RestrictAddressFamilies", "IPAddressDeny", "IPAddressAllow", "ReadOnlyPaths",
      "ReadWritePaths",
    ],
    label,
  );
  validateCommonServiceHardening(unit, label, true);
  exactDirectiveValues(unit, "Unit", "Description", ["BitcoinPIR independent rollback authority (template only)"], label);
  exactDirectiveValues(unit, "Unit", "After", ["network-online.target"], label);
  exactDirectiveValues(unit, "Unit", "Wants", ["network-online.target"], label);
  exactDirectiveValues(unit, "Service", "User", ["bitcoinpir-rollback-authority"], label);
  exactDirectiveValues(unit, "Service", "Group", ["bitcoinpir-rollback-authority"], label);
  exactDirectiveValues(unit, "Service", "StateDirectory", ["bitcoinpir-rollback-authority"], label);
  exactDirectiveValues(unit, "Service", "WorkingDirectory", ["/var/lib/bitcoinpir-rollback-authority"], label);
  exactDirectiveValues(unit, "Service", "Restart", ["on-failure"], label);
  exactDirectiveValues(unit, "Service", "RestartSec", ["5"], label);
  exactDirectiveValues(unit, "Service", "ReadOnlyPaths", ["/etc/bitcoinpir/payment-v1/rollback-authority"], label);
  exactDirectiveValues(unit, "Service", "ReadWritePaths", ["/var/lib/bitcoinpir-rollback-authority"], label);
  exactDirectiveValues(
    unit,
    "Service",
    "ExecStartPre",
    [
      "/usr/bin/test -x /opt/bitcoinpir/rollback-authority/@ROLLBACK_AUTHORITY_SHA256@/rollback-authority",
      "/usr/bin/sha256sum --check /etc/bitcoinpir/payment-v1/rollback-authority/rollback-authority.sha256",
    ],
    label,
  );
  const command = onlyDirectiveValue(unit, "Service", "ExecStart", label);
  validateExactCommand(
    command,
    [
      "/opt/bitcoinpir/rollback-authority/@ROLLBACK_AUTHORITY_SHA256@/rollback-authority",
      "serve",
    ],
    [
      ["--bind", "127.0.0.1:8099"],
      ["--store", "/var/lib/bitcoinpir-rollback-authority/authority.sqlite3"],
      ["--authority-secret", "/etc/bitcoinpir/payment-v1/rollback-authority/authority.seed"],
      ["--authority-metadata", "/etc/bitcoinpir/payment-v1/rollback-authority/authority-public.txt"],
      ["--expected-authority-pubkey-hex", "@AUTHORITY_PUBKEY_HEX@"],
      ["--busy-timeout-ms", "5000"],
      ["--io-timeout-ms", "10000"],
      ["--max-connections", "32"],
    ],
    label,
  );
  exactDirectiveValues(unit, "Service", "IPAddressDeny", ["any"], label);
  exactDirectiveValues(unit, "Service", "IPAddressAllow", ["localhost"], label);
}

function validateCoreLightningUnit(text) {
  const label = "Hetzner Core Lightning template";
  const unit = validateInactiveSystemdTemplate(
    text,
    label,
    [
      "/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
      "/etc/bitcoinpir/payment-v1/LIGHTNING-CUSTODY-APPROVED",
      "/etc/bitcoinpir/payment-v1/LIGHTNING-BACKUP-RESTORE-APPROVED",
    ],
    { requireStateDirectoryMode: false },
  );
  exactDirectiveKeys(
    unit,
    "Unit",
    ["Description", "After", "Wants", "Requires", "ConditionPathExists"],
    label,
  );
  exactDirectiveKeys(
    unit,
    "Service",
    [
      "Type", "User", "Group", "SupplementaryGroups", "UMask", "RuntimeDirectory", "RuntimeDirectoryMode",
      "WorkingDirectory", "ExecStartPre", "ExecStart", "Restart", "RestartSec",
      "TimeoutStartSec", "TimeoutStopSec", "LimitNOFILE", "NoNewPrivileges",
      "PrivateDevices", "PrivateTmp", "ProtectSystem", "ProtectHome",
      "ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs",
      "ProtectControlGroups", "ProtectClock", "ProtectHostname", "LockPersonality",
      "MemoryDenyWriteExecute", "RestrictSUIDSGID", "RestrictRealtime",
      "RestrictNamespaces", "SystemCallArchitectures", "CapabilityBoundingSet",
      "AmbientCapabilities", "RestrictAddressFamilies", "ReadOnlyPaths", "ReadWritePaths",
    ],
    label,
  );
  validatePinnedServiceSandbox(unit, label, "simple", "");
  exactDirectiveValues(unit, "Unit", "Description", ["BitcoinPIR Hetzner issuer Core Lightning (template only)"], label);
  exactDirectiveValues(unit, "Unit", "After", ["network-online.target @BITCOIND_SYSTEMD_UNIT@"], label);
  exactDirectiveValues(unit, "Unit", "Wants", ["network-online.target"], label);
  exactDirectiveValues(unit, "Unit", "Requires", ["@BITCOIND_SYSTEMD_UNIT@"], label);
  exactDirectiveValues(unit, "Service", "User", ["bitcoinpir-lightning"], label);
  exactDirectiveValues(unit, "Service", "Group", ["bitcoinpir-cln-guard"], label);
  exactDirectiveValues(unit, "Service", "SupplementaryGroups", ["bitcoinpir-bitcoin-rpc"], label);
  exactDirectiveValues(unit, "Service", "RuntimeDirectory", ["bitcoinpir-core-lightning"], label);
  exactDirectiveValues(unit, "Service", "RuntimeDirectoryMode", ["0700"], label);
  exactDirectiveValues(unit, "Service", "WorkingDirectory", ["/srv/lightning/@LIGHTNING_NETWORK@"], label);
  exactDirectiveValues(unit, "Service", "Restart", ["on-failure"], label);
  exactDirectiveValues(unit, "Service", "RestartSec", ["5"], label);
  exactDirectiveValues(unit, "Service", "TimeoutStartSec", ["120"], label);
  exactDirectiveValues(unit, "Service", "TimeoutStopSec", ["120"], label);
  exactDirectiveValues(unit, "Service", "LimitNOFILE", ["65535"], label);
  exactDirectiveValues(
    unit,
    "Service",
    "ExecStartPre",
    [
      "/usr/bin/test -x /opt/bitcoinpir/core-lightning/@CLN_BUNDLE_SHA256@/bin/lightningd",
      "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/lightning/cln-bundle.sha256",
      "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/lightning/bitcoin-core-bundle.sha256",
      "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/lightning/lightningd-config.sha256",
      "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/lightning/layout-verifier.sha256",
      "/usr/local/libexec/bitcoinpir/verify-lightning-layout",
    ],
    label,
  );
  exactDirectiveValues(
    unit,
    "Service",
    "ExecStart",
    ["/opt/bitcoinpir/core-lightning/@CLN_BUNDLE_SHA256@/bin/lightningd --conf=/etc/bitcoinpir/payment-v1/lightning/lightningd.conf"],
    label,
  );
  exactDirectiveValues(
    unit,
    "Service",
    "ReadOnlyPaths",
    ["/etc/bitcoinpir/payment-v1/lightning /opt/bitcoinpir/core-lightning/@CLN_BUNDLE_SHA256@ /opt/bitcoinpir/bitcoin-core/@BITCOIN_CORE_BUNDLE_SHA256@"],
    label,
  );
  exactDirectiveValues(
    unit,
    "Service",
    "ReadWritePaths",
    ["/srv/lightning/@LIGHTNING_NETWORK@ /run/bitcoinpir-core-lightning"],
    label,
  );
}

function validateClnRpcGuardUnit(text) {
  const label = "Hetzner CLN RPC guard template";
  const unit = validateInactiveSystemdTemplate(
    text,
    label,
    [
      "/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
      "/etc/bitcoinpir/payment-v1/LIGHTNING-CUSTODY-APPROVED",
      "/etc/bitcoinpir/payment-v1/LIGHTNING-BACKUP-RESTORE-APPROVED",
    ],
    { requireStateDirectoryMode: false },
  );
  exactDirectiveKeys(
    unit,
    "Unit",
    ["Description", "After", "Requires", "BindsTo", "Before", "ConditionPathExists"],
    label,
  );
  exactDirectiveKeys(
    unit,
    "Service",
    [
      "Type", "User", "Group", "SupplementaryGroups", "UMask", "ExecStartPre",
      "ExecStart", "Restart", "TimeoutStopSec", "NoNewPrivileges",
      "PrivateTmp", "PrivateDevices", "ProtectSystem", "ProtectHome",
      "ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs",
      "ProtectControlGroups", "ProtectClock", "ProtectHostname", "LockPersonality",
      "MemoryDenyWriteExecute", "RestrictSUIDSGID", "RestrictNamespaces",
      "RestrictRealtime", "SystemCallArchitectures", "CapabilityBoundingSet",
      "AmbientCapabilities", "RestrictAddressFamilies", "ReadOnlyPaths", "ReadWritePaths",
    ],
    label,
  );
  for (const [key, value] of [
    ["Type", "simple"],
    ["User", "bitcoinpir-cln-rpc-guard"],
    ["Group", "bitcoinpir-cln-guard"],
    ["SupplementaryGroups", "bitcoinpir-issuer"],
    ["UMask", "0077"],
    ["Restart", "no"],
    ["TimeoutStopSec", "30"],
    ["NoNewPrivileges", "true"],
    ["PrivateTmp", "true"],
    ["PrivateDevices", "true"],
    ["ProtectSystem", "strict"],
    ["ProtectHome", "true"],
    ["ProtectKernelTunables", "true"],
    ["ProtectKernelModules", "true"],
    ["ProtectKernelLogs", "true"],
    ["ProtectControlGroups", "true"],
    ["ProtectClock", "true"],
    ["ProtectHostname", "true"],
    ["LockPersonality", "true"],
    ["MemoryDenyWriteExecute", "true"],
    ["RestrictSUIDSGID", "true"],
    ["RestrictNamespaces", "true"],
    ["RestrictRealtime", "true"],
    ["SystemCallArchitectures", "native"],
    ["RestrictAddressFamilies", "AF_UNIX"],
  ]) {
    exactDirectiveValues(unit, "Service", key, [value], label);
  }
  exactDirectiveValues(unit, "Unit", "Description", ["BitcoinPIR Core Lightning RPC allowlist guard (template only)"], label);
  exactDirectiveValues(unit, "Unit", "After", ["bitcoinpir-core-lightning.service"], label);
  exactDirectiveValues(unit, "Unit", "Requires", ["bitcoinpir-core-lightning.service"], label);
  exactDirectiveValues(unit, "Unit", "BindsTo", ["bitcoinpir-core-lightning.service"], label);
  exactDirectiveValues(unit, "Unit", "Before", ["bitcoinpir-payment-issuer.service"], label);
  exactDirectiveValues(unit, "Service", "CapabilityBoundingSet", [""], label);
  exactDirectiveValues(unit, "Service", "AmbientCapabilities", [""], label);
  exactDirectiveValues(
    unit,
    "Service",
    "ExecStartPre",
    [
      "/usr/bin/test -x /opt/bitcoinpir/cln-rpc-guard/@CLN_RPC_GUARD_SHA256@/bitcoinpir-cln-rpc-guard",
      "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/lightning/cln-rpc-guard.sha256",
    ],
    label,
  );
  validateExactCommand(
    onlyDirectiveValue(unit, "Service", "ExecStart", label),
    ["/opt/bitcoinpir/cln-rpc-guard/@CLN_RPC_GUARD_SHA256@/bitcoinpir-cln-rpc-guard"],
    [
      ["--listen-socket", "/run/bitcoinpir-cln-rpc-guard/issuer/issuer-rpc"],
      ["--upstream-socket", "/srv/lightning/@LIGHTNING_NETWORK@/lightning-rpc"],
      ["--guard-uid", "@CLN_GUARD_UID@"],
      ["--guard-gid", "@LIGHTNING_GID@"],
      ["--issuer-uid", "@ISSUER_UID@"],
      ["--issuer-gid", "@ISSUER_GID@"],
      ["--upstream-expected-uid", "@LIGHTNING_UID@"],
      ["--upstream-expected-gid", "@LIGHTNING_GID@"],
      ["--timeout-seconds", "10"],
      ["--max-in-flight", "32"],
      ["--max-invoice-msat", "@CLN_GUARD_MAX_INVOICE_MSAT@"],
      ["--max-invoices-per-minute", "@CLN_GUARD_MAX_INVOICES_PER_MINUTE@"],
      ["--max-invoice-burst", "@CLN_GUARD_MAX_INVOICE_BURST@"],
      ["--max-invoices-per-runtime", "@CLN_GUARD_MAX_INVOICES_PER_RUNTIME@"],
    ],
    label,
  );
  exactDirectiveValues(unit, "Service", "ReadOnlyPaths", ["/srv/lightning/@LIGHTNING_NETWORK@ /opt/bitcoinpir/cln-rpc-guard/@CLN_RPC_GUARD_SHA256@"], label);
  exactDirectiveValues(unit, "Service", "ReadWritePaths", ["/run/bitcoinpir-cln-rpc-guard"], label);
}

function validateLightningPreflightUnit(text) {
  const label = "Hetzner Lightning live-preflight template";
  const unit = validateInactiveSystemdTemplate(
    text,
    label,
    [
      "/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
      "/etc/bitcoinpir/payment-v1/LIGHTNING-CUSTODY-APPROVED",
      "/etc/bitcoinpir/payment-v1/LIGHTNING-BACKUP-RESTORE-APPROVED",
    ],
    { requireStateDirectoryMode: false },
  );
  exactDirectiveKeys(
    unit,
    "Unit",
    ["Description", "Requires", "BindsTo", "After", "Before", "ConditionPathExists"],
    label,
  );
  exactDirectiveKeys(
    unit,
    "Service",
    [
      "Type", "User", "Group", "SupplementaryGroups", "UMask", "ExecStartPre",
      "ExecStart", "RemainAfterExit", "TimeoutStartSec", "NoNewPrivileges",
      "PrivateDevices", "PrivateTmp", "ProtectSystem", "ProtectHome",
      "ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs",
      "ProtectControlGroups", "ProtectClock", "ProtectHostname", "LockPersonality",
      "MemoryDenyWriteExecute", "RestrictSUIDSGID", "RestrictRealtime",
      "RestrictNamespaces", "SystemCallArchitectures", "CapabilityBoundingSet",
      "AmbientCapabilities", "RestrictAddressFamilies", "IPAddressDeny",
      "IPAddressAllow", "ReadOnlyPaths",
    ],
    label,
  );
  validatePinnedServiceSandbox(unit, label, "oneshot", "");
  exactDirectiveValues(unit, "Unit", "Description", ["BitcoinPIR Hetzner live Core Lightning preflight (template only)"], label);
  exactDirectiveValues(unit, "Unit", "Requires", ["bitcoinpir-core-lightning.service"], label);
  exactDirectiveValues(unit, "Unit", "BindsTo", ["bitcoinpir-core-lightning.service"], label);
  exactDirectiveValues(unit, "Unit", "After", ["bitcoinpir-core-lightning.service"], label);
  exactDirectiveValues(unit, "Unit", "Before", ["bitcoinpir-payment-issuer.service"], label);
  exactDirectiveValues(unit, "Service", "User", ["bitcoinpir-lightning-preflight"], label);
  exactDirectiveValues(unit, "Service", "Group", ["bitcoinpir-lightning-preflight"], label);
  exactDirectiveValues(unit, "Service", "SupplementaryGroups", ["bitcoinpir-cln-guard bitcoinpir-bitcoin-rpc"], label);
  exactDirectiveValues(unit, "Service", "RemainAfterExit", ["yes"], label);
  exactDirectiveValues(unit, "Service", "TimeoutStartSec", ["60"], label);
  exactDirectiveValues(unit, "Service", "IPAddressDeny", ["any"], label);
  exactDirectiveValues(unit, "Service", "IPAddressAllow", ["localhost"], label);
  exactDirectiveValues(
    unit,
    "Service",
    "ExecStartPre",
    [
      "/usr/bin/test -x /opt/bitcoinpir/bpir-admin/@BPIR_ADMIN_SHA256@/bpir-admin",
      "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/lightning/bpir-admin.sha256",
      "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/lightning/preflight-config.sha256",
      "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/lightning/backup-receipt.sha256",
    ],
    label,
  );
  validateExactCommand(
    onlyDirectiveValue(unit, "Service", "ExecStart", label),
    [
      "/opt/bitcoinpir/bpir-admin/@BPIR_ADMIN_SHA256@/bpir-admin",
      "lightning-staging",
      "preflight",
    ],
    [
      ["--config", "/etc/bitcoinpir/payment-v1/lightning/preflight.toml"],
      ["--config-protected-parent", "/etc/bitcoinpir/payment-v1/lightning"],
      ["--config-expected-uid", "@PREFLIGHT_UID@"],
      ["--config-expected-gid", "@PREFLIGHT_GID@"],
    ],
    label,
  );
  exactDirectiveValues(
    unit,
    "Service",
    "ReadOnlyPaths",
    ["/etc/bitcoinpir/payment-v1/lightning /srv/lightning/@LIGHTNING_NETWORK@ /opt/bitcoinpir/bpir-admin/@BPIR_ADMIN_SHA256@ /opt/bitcoinpir/core-lightning/@CLN_BUNDLE_SHA256@ /opt/bitcoinpir/bitcoin-core/@BITCOIN_CORE_BUNDLE_SHA256@"],
    label,
  );
}

function validatePaymentEdgeUnit(text) {
  const label = "Payment V1 Caddy edge template";
  const unit = validateInactiveSystemdTemplate(text, label, [
    "/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
    "/etc/bitcoinpir/payment-v1/EDGE-PREFLIGHT-APPROVED",
  ]);
  exactDirectiveKeys(unit, "Unit", BASIC_UNIT_KEYS, label);
  exactDirectiveKeys(
    unit,
    "Service",
    [
      "Type", "User", "Group", "UMask", "StateDirectory", "StateDirectoryMode",
      "WorkingDirectory", "Environment", "ExecStartPre", "ExecStart", "Restart",
      "RestartSec", "TimeoutStartSec", "TimeoutStopSec", "LimitNOFILE",
      "AmbientCapabilities", "CapabilityBoundingSet", "NoNewPrivileges",
      "PrivateDevices", "PrivateTmp", "ProtectSystem", "ProtectHome",
      "ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs",
      "ProtectControlGroups", "ProtectClock", "ProtectHostname", "LockPersonality",
      "MemoryDenyWriteExecute", "RestrictSUIDSGID", "RestrictRealtime",
      "RestrictNamespaces", "SystemCallArchitectures", "RestrictAddressFamilies",
      "ReadOnlyPaths", "ReadWritePaths",
    ],
    label,
  );
  validatePinnedServiceSandbox(unit, label, "notify", "CAP_NET_BIND_SERVICE");
  exactDirectiveValues(unit, "Unit", "Description", ["BitcoinPIR Payment V1 pinned TLS edge (template only)"], label);
  exactDirectiveValues(unit, "Unit", "After", ["network-online.target"], label);
  exactDirectiveValues(unit, "Unit", "Wants", ["network-online.target"], label);
  exactDirectiveValues(unit, "Service", "User", ["bitcoinpir-payment-edge"], label);
  exactDirectiveValues(unit, "Service", "Group", ["bitcoinpir-payment-edge"], label);
  exactDirectiveValues(unit, "Service", "StateDirectory", ["bitcoinpir-payment-edge"], label);
  exactDirectiveValues(unit, "Service", "StateDirectoryMode", ["0700"], label);
  exactDirectiveValues(unit, "Service", "WorkingDirectory", ["/var/lib/bitcoinpir-payment-edge"], label);
  exactDirectiveValues(unit, "Service", "Environment", ["XDG_DATA_HOME=/var/lib/bitcoinpir-payment-edge/data XDG_CONFIG_HOME=/var/lib/bitcoinpir-payment-edge/config"], label);
  exactDirectiveValues(unit, "Service", "Restart", ["on-failure"], label);
  exactDirectiveValues(unit, "Service", "RestartSec", ["5"], label);
  exactDirectiveValues(unit, "Service", "TimeoutStartSec", ["60"], label);
  exactDirectiveValues(unit, "Service", "TimeoutStopSec", ["30"], label);
  exactDirectiveValues(unit, "Service", "LimitNOFILE", ["65535"], label);
  exactDirectiveValues(
    unit,
    "Service",
    "ExecStartPre",
    [
      "/usr/bin/test -x /opt/bitcoinpir/caddy/@CADDY_SHA256@/caddy",
      "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/edge/caddy.sha256",
      "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/edge/edge-config.sha256",
      "/opt/bitcoinpir/caddy/@CADDY_SHA256@/caddy validate --config /etc/bitcoinpir/payment-v1/edge/@EDGE_CADDYFILE@ --adapter caddyfile",
    ],
    label,
  );
  exactDirectiveValues(
    unit,
    "Service",
    "ExecStart",
    ["/opt/bitcoinpir/caddy/@CADDY_SHA256@/caddy run --config /etc/bitcoinpir/payment-v1/edge/@EDGE_CADDYFILE@ --adapter caddyfile"],
    label,
  );
  exactDirectiveValues(unit, "Service", "ReadOnlyPaths", ["/etc/bitcoinpir/payment-v1/edge"], label);
  exactDirectiveValues(unit, "Service", "ReadWritePaths", ["/var/lib/bitcoinpir-payment-edge"], label);
}

function activeTemplateLines(text, label) {
  rejectPattern(text, /\r/u, label, "carriage return");
  rejectPattern(text, /\0/u, label, "NUL byte");
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "" && !line.startsWith("#"));
}

function validateLightningdConfig(text) {
  const label = "Core Lightning configuration template";
  const actual = activeTemplateLines(text, label);
  const expected = [
    "network=@LIGHTNING_NETWORK@",
    "lightning-dir=/srv/lightning",
    "pid-file=/run/bitcoinpir-core-lightning/lightningd.pid",
    "rpc-file=lightning-rpc",
    "rpc-file-mode=0660",
    "allow-deprecated-apis=false",
    "database-upgrade=false",
    "bind-addr=@CLN_P2P_BIND_ADDR@",
    "announce-addr=@CLN_P2P_ANNOUNCE_ADDR@",
    "announce-addr-discovered=false",
    "autoconnect-seeker-peers=0",
    "disable-dns",
    "invoices-onchain-fallback=false",
    "log-level=unusual",
    "log-timestamps=true",
    "bitcoin-cli=/opt/bitcoinpir/bitcoin-core/@BITCOIN_CORE_BUNDLE_SHA256@/bin/bitcoin-cli",
    "bitcoin-datadir=/srv/bitcoin",
    "bitcoin-rpcconnect=127.0.0.1",
    "bitcoin-rpcport=@BITCOIN_RPC_PORT@",
    "bitcoin-rpcclienttimeout=30",
    "bitcoin-retry-timeout=30",
    "clear-plugins",
    "important-plugin=/opt/bitcoinpir/core-lightning/@CLN_BUNDLE_SHA256@/plugins/bcli",
    "important-plugin=/opt/bitcoinpir/core-lightning/@CLN_BUNDLE_SHA256@/plugins/chanbackup",
  ];
  if (
    actual.length !== expected.length ||
    actual.some((line, index) => line !== expected[index])
  ) {
    fail(`${label} active lines must equal the reviewed closed-world configuration`);
  }
  rejectPattern(
    text,
    /(?:^|\n)\s*(?:include|plugin|plugin-dir|rpcuser|rpcpassword|grpc-port|commando|developer)(?:=|\s|$)/iu,
    label,
    "dynamic plugin, include, credential, or remote-RPC option",
  );
}

function validateIssuerClnArgs(text, mode) {
  const label = "issuer Core Lightning argument template";
  requireText(text, "not an executable fragment", label);
  rejectPattern(text, /^\s*#!/mu, label, "shebang");
  rejectPattern(text, /^\s*exec(?:\s|$)/mu, label, "exec command");
  validateExactCommand(
    activeTemplateLines(text, label).join(" "),
    [],
    [
      ["--cln-rpc-socket", "/run/bitcoinpir-cln-rpc-guard/issuer/issuer-rpc"],
      ["--cln-rpc-expected-uid", "@CLN_GUARD_UID@"],
      ["--cln-rpc-expected-gid", "@ISSUER_GID@"],
    ],
    label,
  );
  if ((mode & 0o111) !== 0) fail(`${label} must remain non-executable`);
}

function validateClnGuardTmpfiles(text, mode) {
  const label = "CLN RPC guard tmpfiles template";
  const expected = [
    "d /run/bitcoinpir-cln-rpc-guard 0710 bitcoinpir-cln-rpc-guard bitcoinpir-issuer - -",
    "d /run/bitcoinpir-cln-rpc-guard/issuer 0710 bitcoinpir-cln-rpc-guard bitcoinpir-issuer - -",
  ];
  const actual = activeTemplateLines(text, label)
    .map((line) => line.split(/\s+/u).join(" "));
  if (
    actual.length !== expected.length ||
    actual.some((line, index) => line !== expected[index])
  ) {
    fail(`${label} active lines must equal the reviewed closed-world layout`);
  }
  if ((mode & 0o111) !== 0) fail(`${label} must remain non-executable`);
}

function validateActivationPrerequisites(text) {
  const label = "Lightning activation-prerequisites example";
  const values = parseRelaySelection(text);
  const unresolved = [
    "status",
    "network",
    "cln_bundle_sha256",
    "bitcoin_core_bundle_sha256",
    "cln_rpc_guard_binary_sha256",
    "cln_rpc_guard_unit_sha256",
    "cln_rpc_guard_tmpfiles_sha256",
    "lightningd_config_sha256",
    "preflight_config_sha256",
    "backup_receipt_sha256",
    "expected_cln_version",
    "expected_node_id_hex",
  ];
  const booleans = [
    "identity_secret_offline_restore_rehearsed",
    "channel_recovery_restore_rehearsed",
    "dynamic_datastore_restore_rehearsed",
    "stale_channel_state_rollback_rejected",
    "default_signet_chain_pins_verified",
    "exact_plugin_allowlist_verified",
    "strict_rpc_socket_layout_verified",
    "cross_uid_preflight_policy_verified",
    "bitcoin_rpc_cookie_boundary_verified",
    "cln_rpc_method_allowlist_guard_verified",
    "live_read_only_preflight_passed",
    "real_funds_authorized",
  ];
  const expectedKeys = ["schema_version", ...unresolved, ...booleans].sort();
  const actualKeys = [...values.keys()].sort();
  if (
    actualKeys.length !== expectedKeys.length ||
    actualKeys.some((key, index) => key !== expectedKeys[index])
  ) {
    fail(`${label} fields must equal the reviewed closed-world schema`);
  }
  exactField(values, "schema_version", 1);
  for (const field of unresolved) exactField(values, field, "UNRESOLVED");
  for (const field of booleans) exactField(values, field, false);
  requireText(text, "Before mainnet/real value", label);
}

function validateCaddyTemplate(text, label, requiredUpstreams) {
  requireText(text, "admin off", label);
  requireText(text, "persist_config off", label);
  requireText(text, "auto_https disable_redirects", label);
  requireText(text, "0rtt off", label);
  requireText(text, "strict_sni_host on", label);
  requireText(
    text,
    "exclude http.log.access http.log.error http.handlers.reverse_proxy",
    label,
  );
  rejectPattern(text, /\b(?:debug|trace)\b/iu, label, "debug/trace logging");
  rejectPattern(text, /(?:^|\n)\s*log\s*\{/mu, label, "site access-log directive");
  rejectPattern(text, /(?:^|\n)\s*(?:forward_auth|php_fastcgi|file_server|redir)\b/mu, label, "unreviewed handler");
  for (const upstream of requiredUpstreams) {
    const escaped = upstream.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
    const matches = text.match(new RegExp(`reverse_proxy\\s+${escaped}`, "gu")) ?? [];
    if (matches.length === 0) fail(`${label} must contain reviewed loopback upstream ${upstream}`);
  }
  rejectPattern(
    text,
    /(?:^|\n)\s*reverse_proxy[ \t]+(?!127\.0\.0\.1:(?:5610|8191|8080|8099)\b)\S+/gu,
    label,
    "non-reviewed or non-loopback upstream",
  );
}

function validateVpsbgFreePow(text, mode) {
  const label = "VPSBG Free-PoW argument fragment";
  requireText(text, "not a run script", label);
  requireText(text, "existing measured Tier 3 script", label);
  requireText(text, "FreeV1 / ProofOfWork", label);
  rejectPattern(text, /^\s*#!+/m, label, "shebang");
  rejectPattern(text, /^\s*exec(?:\s|$)/m, label, "exec command");
  const active = text
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line !== "" && !line.startsWith("#"))
    .join(" ");
  validateProductionForbiddenFlags(active, label);
  validateExactCommand(
    active,
    [],
    [
      ["--require-service-auth-v1", null],
      ["--service-policy", "/home/pir/data/payment-v1/vpsbg-free-pow-only-policy.bin"],
      ["--service-provider-id-hex", "@VPSBG_PROVIDER_ID_HEX@"],
      ["--service-policy-key-hex", "@VPSBG_POLICY_PUBKEY_HEX@"],
      ["--service-store", "/home/pir/data/payment-v1/provider.sqlite3"],
      ["--service-remote-rollback-authority-config", "/home/pir/data/payment-v1/remote-rollback-authority.toml"],
      ["--service-max-concurrent-auth", "16"],
      ["--service-pre-auth-timeout-ms", "60000"],
    ],
    label,
  );
  if ((mode & 0o111) !== 0) {
    fail(`${label} must remain non-executable`);
  }
}

function parseScalar(raw, lineNumber) {
  if (/^"[^"\r\n]*"$/.test(raw)) {
    return raw.slice(1, -1);
  }
  if (raw === "true") return true;
  if (raw === "false") return false;
  if (/^(0|[1-9][0-9]*)$/.test(raw)) return Number(raw);
  fail(`relay selection line ${lineNumber} has a non-canonical scalar`);
}

export function parseRelaySelection(text) {
  const result = new Map();
  for (const [index, original] of text.split(/\r?\n/u).entries()) {
    const line = original.trim();
    if (line === "" || line.startsWith("#")) continue;
    const match = /^([a-z][a-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
    if (!match) fail(`relay selection line ${index + 1} is not canonical key=value`);
    if (result.has(match[1])) fail(`relay selection repeats ${match[1]}`);
    result.set(match[1], parseScalar(match[2], index + 1));
  }
  return result;
}

function exactField(selection, name, expected) {
  if (selection.get(name) !== expected) {
    fail(`relay selection ${name} must equal ${JSON.stringify(expected)}`);
  }
}

function stringField(selection, name) {
  const value = selection.get(name);
  if (typeof value !== "string") fail(`relay selection ${name} must be a string`);
  return value;
}

export function validateRelaySelection(text) {
  const selection = parseRelaySelection(text);
  exactField(selection, "version", 1);
  exactField(selection, "listen_host", "127.0.0.1");
  exactField(selection, "allowed_kind", 30078);
  exactField(selection, "max_event_message_bytes", 262176);
  exactField(selection, "max_content_bytes", 196608);
  exactField(selection, "config_max_bytes", 16384);
  exactField(selection, "config_profile", "bitcoinpir-directory-relay-v1");
  exactField(selection, "publisher_private_key_installed", false);
  exactField(selection, "nip42_auth", false);
  exactField(selection, "access_logging", false);
  exactField(selection, "mutable_source_ref", false);

  const values = [...selection.values()].filter((value) => typeof value === "string");
  for (const value of values) {
    const lower = value.toLowerCase();
    if (lower.includes("nostr-rs-relay")) {
      fail("relay selection refuses nostr-rs-relay");
    }
    if (UNSAFE_RELAY_COMMITS.has(lower)) {
      fail(`relay selection refuses audited unsafe commit ${lower}`);
    }
  }

  const status = stringField(selection, "status");
  if (status === "UNRESOLVED") {
    for (const field of UNRESOLVED_FIELDS) exactField(selection, field, "UNRESOLVED");
    return { status };
  }
  if (status !== "RESOLVED") {
    fail("relay selection status must be UNRESOLVED or RESOLVED");
  }

  exactField(selection, "implementation", "bitcoinpir-directory-only");
  exactField(
    selection,
    "source_repository",
    "https://github.com/Bitcoin-PIR/Bitcoin-PIR.git",
  );
  const sourceCommit = stringField(selection, "source_commit");
  if (!/^[0-9a-f]{40}$/.test(sourceCommit)) {
    fail("resolved relay source_commit must be a full lowercase 40-hex commit");
  }
  if (UNSAFE_RELAY_COMMITS.has(sourceCommit)) {
    fail(`relay selection refuses audited unsafe commit ${sourceCommit}`);
  }
  for (const field of HASH_FIELDS) {
    if (!/^[0-9a-f]{64}$/.test(stringField(selection, field))) {
      fail(`resolved relay ${field} must be a lowercase SHA-256`);
    }
  }
  if (!/^bitcoinpir-directory-relay [0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/.test(
    stringField(selection, "binary_version_output"),
  )) {
    fail("resolved relay binary_version_output is not exact and canonical");
  }
  const publisherPubkey = stringField(selection, "publisher_pubkey_hex");
  if (!/^[0-9a-f]{64}$/.test(publisherPubkey)) {
    fail("resolved relay publisher_pubkey_hex must be lowercase 32-byte hex");
  }
  if (/^0{64}$/.test(publisherPubkey)) {
    fail("resolved relay publisher_pubkey_hex must be non-zero");
  }
  return {
    status,
    binarySha256: stringField(selection, "binary_sha256"),
    publisherPubkey,
  };
}

function validateRelayConfigExample(text, selection) {
  const label = "directory relay configuration example";
  if (Buffer.byteLength(text, "utf8") > 16 * 1024) {
    fail(`${label} exceeds the application 16 KiB input bound`);
  }
  const config = parseRelaySelection(text);
  const expectedKeys = [
    "profile",
    "listen",
    "database",
    "directory_pubkey_hex",
    "max_connections",
    "max_in_flight_operations",
    "max_operations_per_second",
    "max_egress_bytes_per_second",
    "max_egress_bytes_per_connection",
    "max_archive_events",
    "max_archive_bytes",
    "handshake_timeout_seconds",
    "idle_timeout_seconds",
    "connection_timeout_seconds",
    "operation_timeout_seconds",
    "egress_timeout_seconds",
  ].sort();
  const actualKeys = [...config.keys()].sort();
  if (
    actualKeys.length !== expectedKeys.length ||
    actualKeys.some((value, index) => value !== expectedKeys[index])
  ) {
    fail(`${label} fields do not match the application schema`);
  }
  for (const [field, expected] of [
    ["profile", "bitcoinpir-directory-relay-v1"],
    ["listen", "127.0.0.1:8080"],
    ["database", "/var/lib/bitcoinpir-directory-relay/relay.sqlite3"],
    ["max_connections", 64],
    ["max_in_flight_operations", 8],
    ["max_operations_per_second", 64],
    ["max_egress_bytes_per_second", 16_777_216],
    ["max_egress_bytes_per_connection", 67_108_864],
    ["max_archive_events", 100_000],
    ["max_archive_bytes", 268_435_456],
    ["handshake_timeout_seconds", 10],
    ["idle_timeout_seconds", 60],
    ["connection_timeout_seconds", 300],
    ["operation_timeout_seconds", 10],
    ["egress_timeout_seconds", 5],
  ]) {
    exactField(config, field, expected);
  }
  const expectedPublisher =
    selection.status === "RESOLVED"
      ? selection.publisherPubkey
      : "@DIRECTORY_PUBLISHER_PUBKEY_HEX@";
  exactField(config, "directory_pubkey_hex", expectedPublisher);
}

function recursiveFiles(root) {
  const output = [];
  const walk = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const absolute = join(directory, entry.name);
      if (entry.isSymbolicLink()) fail(`deployment template tree contains symlink: ${absolute}`);
      if (entry.isDirectory()) walk(absolute);
      else if (entry.isFile()) output.push(absolute);
      else fail(`deployment template tree contains non-regular entry: ${absolute}`);
    }
  };
  walk(root);
  return output;
}

function validateTemplateTreeShape(root) {
  const absoluteRoot = join(root, TEMPLATE_ROOT);
  const allowedPaths = new Set(
    REQUIRED_PREPARATION_FILES.filter((path) => path.startsWith(`${TEMPLATE_ROOT}/`)),
  );
  for (const absolute of recursiveFiles(absoluteRoot)) {
    const rel = relative(root, absolute);
    const stat = lstatSync(absolute);
    if ((stat.mode & 0o111) !== 0) {
      fail(`deployment template must not be executable: ${rel}`);
    }
    if (rel.endsWith(".service") || /\/run$/u.test(rel)) {
      fail(`deployment tree must not contain an activatable unit/script: ${rel}`);
    }
    if (
      !rel.endsWith(".service.in") &&
      !rel.endsWith(".args.in") &&
      !rel.endsWith(".Caddyfile.in") &&
      !rel.endsWith(".conf.in") &&
      !rel.endsWith(".sh.in") &&
      !rel.endsWith(".toml.example") &&
      !rel.endsWith(".md")
    ) {
      fail(`deployment tree contains an unreviewed file type: ${rel}`);
    }
    if (!allowedPaths.has(rel)) {
      fail(`deployment tree contains an unreviewed path: ${rel}`);
    }
  }
}

function validateActiveBaselines(root) {
  for (const [relativePath, expected] of Object.entries(ACTIVE_BASELINES)) {
    const { absolute, text } = readRequired(root, relativePath);
    const actual = sha256File(absolute);
    if (actual !== expected) {
      fail(`active deployment file changed outside this slice: ${relativePath}`);
    }
    rejectPattern(
      text,
      /--require-service-auth-v1|--service-policy(?:\s|=)|--service-store(?:\s|=)/,
      relativePath,
      "Payment V1 activation",
    );
  }
}

function validateReviewedPreparationHashes(root) {
  for (const [relativePath, expected] of Object.entries(
    REVIEWED_PREPARATION_HASHES,
  )) {
    const { absolute } = readRequired(root, relativePath);
    const actual = sha256File(absolute);
    if (actual !== expected) {
      fail(`reviewed deployment source SHA-256 changed: ${relativePath}`);
    }
  }
}

export function validateDeploymentTree(rootInput) {
  const root = resolve(rootInput);
  for (const required of REQUIRED_PREPARATION_FILES) readRequired(root, required);
  validateTemplateTreeShape(root);
  validateActiveBaselines(root);

  const provider = readRequired(
    root,
    "deploy/payment-v1/systemd/hetzner-provider.service.in",
  );
  validateHetznerProvider(provider.text);

  const issuer = readRequired(
    root,
    "deploy/payment-v1/systemd/hetzner-payment-issuer.service.in",
  );
  validateHetznerIssuer(issuer.text);

  const coreLightning = readRequired(
    root,
    "deploy/payment-v1/systemd/hetzner-core-lightning.service.in",
  );
  validateCoreLightningUnit(coreLightning.text);

  const clnRpcGuard = readRequired(
    root,
    "deploy/payment-v1/systemd/hetzner-cln-rpc-guard.service.in",
  );
  validateClnRpcGuardUnit(clnRpcGuard.text);

  const lightningPreflight = readRequired(
    root,
    "deploy/payment-v1/systemd/hetzner-lightning-preflight.service.in",
  );
  validateLightningPreflightUnit(lightningPreflight.text);

  const paymentEdge = readRequired(
    root,
    "deploy/payment-v1/systemd/payment-v1-edge.service.in",
  );
  validatePaymentEdgeUnit(paymentEdge.text);

  const activationPrerequisites = readRequired(
    root,
    "deploy/payment-v1/lightning/activation-prerequisites.toml.example",
  );
  validateActivationPrerequisites(activationPrerequisites.text);

  const lightningdConfig = readRequired(
    root,
    "deploy/payment-v1/lightning/lightningd.conf.in",
  );
  validateLightningdConfig(lightningdConfig.text);

  const issuerClnArgs = readRequired(
    root,
    "deploy/payment-v1/lightning/issuer-cln.args.in",
  );
  validateIssuerClnArgs(issuerClnArgs.text, issuerClnArgs.stat.mode);

  const clnGuardTmpfiles = readRequired(
    root,
    "deploy/payment-v1/lightning/cln-rpc-guard-tmpfiles.conf.in",
  );
  validateClnGuardTmpfiles(clnGuardTmpfiles.text, clnGuardTmpfiles.stat.mode);

  const layoutVerifier = readRequired(
    root,
    "deploy/payment-v1/lightning/verify-layout.sh.in",
  );
  if ((layoutVerifier.stat.mode & 0o111) !== 0) {
    fail("Lightning layout verifier source template must remain non-executable");
  }
  for (const required of [
    "[ \"${bpir_lightning_network}\" = 'signet' ] || bpir_fail",
    "-perm /077",
    "-links +1",
    "/usr/bin/getfacl",
    "${bpir_lightning_uid}:${bpir_lightning_gid}:660",
  ]) {
    requireText(layoutVerifier.text, required, "Lightning layout verifier template");
  }

  const publicEdge = readRequired(
    root,
    "deploy/payment-v1/edge/hetzner-public.Caddyfile.in",
  );
  validateCaddyTemplate(
    publicEdge.text,
    "Hetzner public Caddy template",
    ["127.0.0.1:8191", "127.0.0.1:5610", "127.0.0.1:8080"],
  );
  requireText(
    publicEdge.text,
    "path /v1/redeems /v1/settlement/balance",
    "Hetzner public Caddy template",
  );
  rejectPattern(
    publicEdge.text,
    /\/v1\/settlement\/(?:payout-intents|payouts|payout-status)\b/u,
    "Hetzner public Caddy template",
    "production payout route",
  );

  const authorityEdge = readRequired(
    root,
    "deploy/payment-v1/edge/rollback-authority.Caddyfile.in",
  );
  validateCaddyTemplate(
    authorityEdge.text,
    "rollback-authority Caddy template",
    ["127.0.0.1:8099"],
  );

  const authority = readRequired(
    root,
    "deploy/payment-v1/systemd/rollback-authority.service.in",
  );
  validateRollbackAuthority(authority.text);

  const vpsbg = readRequired(
    root,
    "deploy/payment-v1/vpsbg/vpsbg-free-pow-service-auth.args.in",
  );
  validateVpsbgFreePow(vpsbg.text, vpsbg.stat.mode);
  const deploymentDoc = readRequired(
    root,
    "docs/payment/HETZNER_VPSBG_DEPLOYMENT.md",
  );
  for (const required of [
    "P1 activation blocker",
    "attestation-gated key release",
    "host can read or copy",
  ]) {
    requireText(deploymentDoc.text, required, "Hetzner/VPSBG deployment document");
  }

  const selectionFile = readRequired(
    root,
    "deploy/payment-v1/relay-selection.toml.example",
  );
  const selection = validateRelaySelection(selectionFile.text);
  const relayConfig = readRequired(
    root,
    "deploy/payment-v1/directory-relay.toml.example",
  );
  validateRelayConfigExample(relayConfig.text, selection);
  const relayUnit = readRequired(
    root,
    "deploy/payment-v1/systemd/hetzner-directory-relay.service.in",
  );
  const relayLabel = "Hetzner directory relay template";
  const relayParsed = validateInactiveSystemdTemplate(relayUnit.text, relayLabel, [
    "/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
    "/etc/bitcoinpir/payment-v1/RELAY-SELECTION-RESOLVED",
  ]);
  exactDirectiveKeys(relayParsed, "Unit", BASIC_UNIT_KEYS, relayLabel);
  exactDirectiveKeys(
    relayParsed,
    "Service",
    [
      "Type", "User", "Group", "UMask", "StateDirectory", "StateDirectoryMode",
      "WorkingDirectory", "Environment", "ExecStart", "Restart", "TimeoutStopSec",
      "NoNewPrivileges", "PrivateTmp", "PrivateDevices", "ProtectSystem", "ProtectHome",
      "ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs",
      "ProtectControlGroups", "LockPersonality", "MemoryDenyWriteExecute",
      "RestrictSUIDSGID", "RestrictNamespaces", "RestrictRealtime",
      "SystemCallArchitectures", "CapabilityBoundingSet", "AmbientCapabilities",
      "RestrictAddressFamilies", "IPAddressDeny", "IPAddressAllow", "ReadOnlyPaths",
      "ReadWritePaths",
      ...(selection.status === "RESOLVED" ? ["ExecStartPre"] : []),
      ...(selection.status === "RESOLVED" ? ["RestartSec"] : []),
    ],
    relayLabel,
  );
  validateCommonServiceHardening(relayParsed, relayLabel, true);
  exactDirectiveValues(relayParsed, "Unit", "Description", ["BitcoinPIR Hetzner directory-only relay (blocked template)"], relayLabel);
  exactDirectiveValues(relayParsed, "Unit", "After", ["network-online.target"], relayLabel);
  exactDirectiveValues(relayParsed, "Unit", "Wants", ["network-online.target"], relayLabel);
  exactDirectiveValues(relayParsed, "Service", "User", ["bitcoinpir-directory-relay"], relayLabel);
  exactDirectiveValues(relayParsed, "Service", "Group", ["bitcoinpir-directory-relay"], relayLabel);
  exactDirectiveValues(relayParsed, "Service", "StateDirectory", ["bitcoinpir-directory-relay"], relayLabel);
  exactDirectiveValues(relayParsed, "Service", "WorkingDirectory", ["/var/lib/bitcoinpir-directory-relay"], relayLabel);
  exactDirectiveValues(relayParsed, "Service", "Environment", ["RUST_LOG=error"], relayLabel);
  exactDirectiveValues(relayParsed, "Service", "IPAddressDeny", ["any"], relayLabel);
  exactDirectiveValues(relayParsed, "Service", "IPAddressAllow", ["localhost"], relayLabel);
  exactDirectiveValues(relayParsed, "Service", "ReadOnlyPaths", ["/etc/bitcoinpir/payment-v1/directory-relay"], relayLabel);
  exactDirectiveValues(relayParsed, "Service", "ReadWritePaths", ["/var/lib/bitcoinpir-directory-relay"], relayLabel);
  rejectPattern(
    relayUnit.text,
    /publisher-(?:private|signing)-key|directory-(?:private|signing)-key/i,
    relayLabel,
    "directory publisher private-key installation",
  );
  const relayCommand = onlyDirectiveValue(relayParsed, "Service", "ExecStart", relayLabel);
  if (selection.status === "UNRESOLVED") {
    if (relayCommand !== "/usr/bin/false") {
      fail("unresolved relay template must fail closed with ExecStart=/usr/bin/false");
    }
    exactDirectiveValues(relayParsed, "Service", "ExecStartPre", [], relayLabel);
    exactDirectiveValues(relayParsed, "Service", "Restart", ["no"], relayLabel);
  } else {
    const expectedExecStart =
      `/opt/bitcoinpir/directory-relay/${selection.binarySha256}/` +
      "bitcoinpir-directory-relay --config " +
      "/etc/bitcoinpir/payment-v1/directory-relay/relay.toml";
    if (relayCommand !== expectedExecStart) {
      fail("resolved relay template must use only the pinned binary and one absolute --config path");
    }
    exactDirectiveValues(
      relayParsed,
      "Service",
      "ExecStartPre",
      [
        "/usr/bin/sha256sum --check /etc/bitcoinpir/payment-v1/directory-relay/binary.sha256",
        "/usr/bin/sha256sum --check /etc/bitcoinpir/payment-v1/directory-relay/config.sha256",
      ],
      relayLabel,
    );
    exactDirectiveValues(relayParsed, "Service", "Restart", ["on-failure"], relayLabel);
    exactDirectiveValues(relayParsed, "Service", "RestartSec", ["5"], relayLabel);
  }

  validateReviewedPreparationHashes(root);

  return true;
}

function parseCli(argv) {
  let root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--root" && i + 1 < argv.length) {
      root = resolve(argv[++i]);
    } else {
      fail(`usage: payment-v1-deployment-template-gate.mjs [--root REPOSITORY]`);
    }
  }
  return { root };
}

const invokedDirectly =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href;

if (invokedDirectly) {
  try {
    const { root } = parseCli(process.argv.slice(2));
    validateDeploymentTree(root);
    console.log("payment-v1-deployment-template-gate=PASS");
  } catch (error) {
    console.error(`payment-v1-deployment-template-gate=FAIL: ${error.message}`);
    process.exitCode = 1;
  }
}
