#!/usr/bin/env node

import { createECDH, createHash } from "node:crypto";
import {
  lstatSync,
  readFileSync,
  readdirSync,
} from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { validatePublisherNetnsTree } from "./payment-v1-publisher-netns-gate.mjs";
import {
  validateBuildManifestV1,
  validateClosedHaproxyConfigV1,
} from "./payment-v1-directory-public-haproxy-artifact-gate.mjs";

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
    "4f23190c44b03b326403cb5b68633e462024018e5404a2ed91c7e408072b6799",
});

export const REVIEWED_PREPARATION_HASHES = Object.freeze({
  "deploy/payment-v1/edge/directory-public-haproxy.cfg.in":
    "e33aec1e3fc70e6705ef9673fe5f0b0af11f86b8d550c03c52769fed7123ad93",
  "deploy/payment-v1/edge/directory-public-haproxy-build-manifest.json.in":
    "ea303dfe0de1b689d0f80d75b4b0edd32e5f94734bede5c5d282c4b2391b2d85",
  "deploy/payment-v1/edge/integrated-existing-bhtm-caddy-directory-public.managed.Caddyfile.in":
    "5114ce5b56b77f057df04453c7f4af55db47f4e59efb317df9f801207ebe2473",
  "deploy/payment-v1/edge/integrated-existing-bhtm-caddy.managed.Caddyfile.in":
    "afa1bb9e225f1ca2c998942aa33f4e5e4f2c3437d22d5ec2ecb6f565b135a675",
  "deploy/payment-v1/edge/hetzner-public.Caddyfile.in":
    "6a52ff0034390ffda572bd785e766653dc749736bd942f497a4b897778113983",
  "deploy/payment-v1/edge/rollback-authority.Caddyfile.in":
    "237162cb5d57333adf789e612fcdb4be602bf6e0c9cd99a03ecd079ab8aa257f",
  "deploy/payment-v1/edge/source-fair-haproxy.cfg.in":
    "d1770c45641a37dd7de083a4d6510b6aa14a34a30121420cdc160d345597ddcd",
  "deploy/payment-v1/lightning/activation-prerequisites.toml.example":
    "b5def27d9d5df397af5fafb91f0e64404b62a5c8131b9b3ae4aea187fbbcd6be",
  "deploy/payment-v1/lightning/cln-rpc-guard-tmpfiles.conf.in":
    "70a74e60514adaf5fb89b1461ffddc20c66a10dd127973d42d2144074011f3fc",
  "deploy/payment-v1/lightning/issuer-cln.args.in":
    "1da053febf373f7166935e0d57abe140e129931accbb856d93889c4fc979b6f4",
  "deploy/payment-v1/lightning/lightningd.conf.in":
    "b0402cc1caa0c1daa8244c85af7b728ffefb324ba9e510bfad029b972aadc847",
  "deploy/payment-v1/lightning/verify-layout.sh.in":
    "3604d6812c637503f333ced4b6789e75e75c65fde8f46a407a48f4809036134c",
  "deploy/payment-v1/systemd/hetzner-core-lightning.service.in":
    "8ac83d4a16f347381e1cd44fa3ce1cbf176c5dee909e87c65a7d204ee2ec512d",
  "deploy/payment-v1/systemd/hetzner-cln-rpc-guard.service.in":
    "87eef911c6c42bd1cb350b1990e4545ffe08ff2217d8b47aa806db33f6d0a93d",
  "deploy/payment-v1/systemd/hetzner-lightning-preflight.service.in":
    "150a073551f13a195ba52dc292a6aea10f80719fec32893c5394f8261f2a3f32",
  "deploy/payment-v1/systemd/hetzner-payment-issuer.service.in":
    "9f8e90084553bfa0e36768631e21295720b627fc0b25489d124ddee4657f823c",
  "deploy/payment-v1/systemd/bhtm-caddy.directory-public-edge.conf.in":
    "5a5927d344c5750da8882af981b67916bd2801551e3de2a62d03f6a99955e6d1",
  "deploy/payment-v1/systemd/payment-v1-directory-public-edge.service.in":
    "ab75460760ef79721bf430f9ae80d5b613cde0d58bc5cb88ee80d1f0b4693876",
  "deploy/payment-v1/systemd/payment-v1-edge.service.in":
    "163c213bbac472755b6def303b06bed1ec41c8001aa96e1f8df6a5edc5c3b53c",
  "deploy/payment-v1/systemd/payment-v1-public-edge.service.in":
    "8e416e9010f11722cfdf21433c86b9a1bb3dab380988bb62af7af565666f9453",
  "deploy/payment-v1/systemd/payment-v1-source-fair-edge.service.in":
    "f7cb021b605454861f5c52e2ddf11610b545227b8b343f19e0309ed07e753728",
  "scripts/payment-v1-directory-public-haproxy-artifact-gate.mjs":
    "840b364fa2513590ffcbfd5267dc7827f24e05d07512ec91bcf96e2286ef57b4",
});

export const REQUIRED_PREPARATION_FILES = Object.freeze([
  "deploy/payment-v1/README.md",
  "deploy/payment-v1/directory-relay.toml.example",
  "deploy/payment-v1/relay-selection.toml.example",
  "deploy/payment-v1/edge/README.md",
  "deploy/payment-v1/edge/directory-public-haproxy.cfg.in",
  "deploy/payment-v1/edge/directory-public-haproxy-build-manifest.json.in",
  "deploy/payment-v1/edge/integrated-existing-bhtm-caddy-directory-public.managed.Caddyfile.in",
  "deploy/payment-v1/edge/integrated-existing-bhtm-caddy.managed.Caddyfile.in",
  "deploy/payment-v1/edge/hetzner-public.Caddyfile.in",
  "deploy/payment-v1/edge/rollback-authority.Caddyfile.in",
  "deploy/payment-v1/edge/source-fair-haproxy.cfg.in",
  "deploy/payment-v1/lightning/README.md",
  "deploy/payment-v1/lightning/activation-prerequisites.toml.example",
  "deploy/payment-v1/lightning/cln-rpc-guard-tmpfiles.conf.in",
  "deploy/payment-v1/lightning/issuer-cln.args.in",
  "deploy/payment-v1/lightning/lightningd.conf.in",
  "deploy/payment-v1/lightning/verify-layout.sh.in",
  "deploy/payment-v1/systemd/hetzner-core-lightning.service.in",
  "deploy/payment-v1/systemd/hetzner-cln-rpc-guard.service.in",
  "deploy/payment-v1/systemd/hetzner-lightning-preflight.service.in",
  "deploy/payment-v1/systemd/bhtm-caddy.directory-public-edge.conf.in",
  "deploy/payment-v1/systemd/payment-v1-directory-public-edge.service.in",
  "deploy/payment-v1/systemd/payment-v1-edge.service.in",
  "deploy/payment-v1/systemd/payment-v1-public-edge.service.in",
  "deploy/payment-v1/systemd/payment-v1-source-fair-edge.service.in",
  "deploy/payment-v1/systemd/hetzner-provider-direct.service.in",
  "deploy/payment-v1/systemd/hetzner-provider-no-standard-cashu.service.in",
  "deploy/payment-v1/systemd/hetzner-provider.service.in",
  "deploy/payment-v1/systemd/hetzner-payment-issuer.service.in",
  "deploy/payment-v1/systemd/rollback-authority.service.in",
  "deploy/payment-v1/systemd/hetzner-directory-relay.service.in",
  "deploy/payment-v1/systemd/payment-v1-publisher-netns.service.in",
  "deploy/payment-v1/systemd/payment-v1-directory-publisher.service.in",
  "deploy/payment-v1/systemd/bhtm-caddy.publisher-netns.conf.in",
  "deploy/payment-v1/network/README.md",
  "deploy/payment-v1/network/directory-publisher-hosts.conf.in",
  "deploy/payment-v1/network/directory-publisher-network-policy.json.in",
  "deploy/payment-v1/network/directory-publisher-resolv.conf.in",
  "deploy/payment-v1/network/directory-publisher-nsswitch.conf.in",
  "deploy/payment-v1/vpsbg/vpsbg-free-pow-service-auth.args.in",
  "docs/payment/HETZNER_VPSBG_DEPLOYMENT.md",
  "scripts/payment-v1-publisher-netns.c",
  "scripts/payment-v1-directory-public-haproxy-artifact-gate.mjs",
]);

const TEMPLATE_ROOT = "deploy/payment-v1";
const ACTIVATION_SENTINEL =
  "ConditionPathExists=/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED";
const UNSAFE_RELAY_COMMITS = new Set([
  "ff65ec2acd781150a585a78e1c60b0cdb104698e",
  "b5c1f642e4f4c3b9c54f5d18d66f4c53642076b4",
]);
const CLN_INERT_PLUGIN_NAMES_V26066 = Object.freeze([
  "autoclean",
  "bookkeeper",
  "cln-askrene",
  "cln-bip353",
  "cln-bwatch",
  "cln-currencyrate",
  "cln-grpc",
  "cln-lsps-client",
  "cln-lsps-service",
  "cln-renepay",
  "cln-xpay",
  "clnrest",
  "commando",
  "exposesecret",
  "funder",
  "keysend",
  "offers",
  "pay",
  "recklessrpc",
  "recover",
  "spenderp",
  "sql",
  "topology",
  "txprepare",
  "wss-proxy",
]);
const HASH_FIELDS = Object.freeze([
  "source_archive_sha256",
  "cargo_lock_sha256",
  "build_manifest_sha256",
  "binary_sha256",
  "config_sha256",
]);
const UNRESOLVED_FIELDS = Object.freeze([
  "directory_mode",
  "implementation",
  "source_repository",
  "source_commit",
  ...HASH_FIELDS,
  "binary_version_output",
  "publisher_pubkey_hex",
]);
const RELAY_SELECTION_FIELDS = Object.freeze([
  "version",
  "status",
  "directory_mode",
  "implementation",
  "source_repository",
  "source_commit",
  ...HASH_FIELDS,
  "binary_version_output",
  "publisher_pubkey_hex",
  "listen_host",
  "allowed_kind",
  "max_event_message_bytes",
  "max_content_bytes",
  "config_max_bytes",
  "config_profile",
  "publisher_private_key_installed",
  "nip42_auth",
  "access_logging",
  "mutable_source_ref",
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
  "LimitCORE",
  "LimitNOFILE",
  "MemoryMax",
  "MemorySwapMax",
  "StandardError",
  "StandardOutput",
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
  "ProtectProc",
  "ProcSubset",
  "LockPersonality",
  "MemoryDenyWriteExecute",
  "RestrictSUIDSGID",
  "RestrictNamespaces",
  "RestrictRealtime",
  "SystemCallArchitectures",
  "TasksMax",
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
  "NotifyAccess",
  "WatchdogSec",
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

function validateHetznerProvider(
  text,
  { direct = false, noStandardCashu = false } = {},
) {
  if (direct && !noStandardCashu) {
    fail("direct provider validator must also disable Standard Cashu");
  }
  const label = direct
    ? "Hetzner direct provider template"
    : noStandardCashu
      ? "Hetzner provider without Standard Cashu template"
      : "Hetzner provider template";
  const configRoot = direct
    ? "/etc/bitcoinpir/payment-v1/provider-direct"
    : noStandardCashu
      ? "/etc/bitcoinpir/payment-v1/provider-no-standard-cashu"
      : "/etc/bitcoinpir/payment-v1/provider";
  const serviceName = direct
    ? "bitcoinpir-provider-direct"
    : noStandardCashu
      ? "bitcoinpir-provider-nocashu"
      : "bitcoinpir-provider";
  const stateDirectory = direct
    ? "bitcoinpir-provider-direct-payment-v1"
    : noStandardCashu
      ? "bitcoinpir-provider-nocashu-payment-v1"
      : "bitcoinpir-provider-payment-v1";
  const activationConditions = direct
    ? [
      "/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
      "/etc/bitcoinpir/payment-v1/PROVIDER-DIRECT-ACTIVATION-APPROVED",
      "!/etc/bitcoinpir/payment-v1/PROVIDER-ACTIVATION-APPROVED",
      "!/etc/bitcoinpir/payment-v1/PROVIDER-NO-STANDARD-CASHU-ACTIVATION-APPROVED",
    ]
    : noStandardCashu
      ? [
        "/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
        "/etc/bitcoinpir/payment-v1/PROVIDER-NO-STANDARD-CASHU-ACTIVATION-APPROVED",
        "!/etc/bitcoinpir/payment-v1/PROVIDER-ACTIVATION-APPROVED",
        "!/etc/bitcoinpir/payment-v1/PROVIDER-DIRECT-ACTIVATION-APPROVED",
      ]
      : [
        "/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
        "/etc/bitcoinpir/payment-v1/PROVIDER-ACTIVATION-APPROVED",
        "!/etc/bitcoinpir/payment-v1/PROVIDER-DIRECT-ACTIVATION-APPROVED",
        "!/etc/bitcoinpir/payment-v1/PROVIDER-NO-STANDARD-CASHU-ACTIVATION-APPROVED",
      ];
  const unit = validateInactiveSystemdTemplate(text, label, [
    ...activationConditions,
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
      "InaccessiblePaths",
    ],
    label,
  );
  validateCommonServiceHardening(unit, label, true);
  exactDirectiveValues(unit, "Unit", "Description", [
    direct
      ? "BitcoinPIR Hetzner Payment V1 direct provider (template only)"
      : noStandardCashu
      ? "BitcoinPIR Hetzner Payment V1 provider without Standard Cashu (template only)"
      : "BitcoinPIR Hetzner Payment V1 provider (template only)",
  ], label);
  exactDirectiveValues(unit, "Unit", "After", ["network-online.target"], label);
  exactDirectiveValues(unit, "Unit", "Wants", ["network-online.target"], label);
  exactDirectiveValues(unit, "Service", "User", [serviceName], label);
  exactDirectiveValues(unit, "Service", "Group", [serviceName], label);
  exactDirectiveValues(unit, "Service", "StateDirectory", [stateDirectory], label);
  exactDirectiveValues(unit, "Service", "WorkingDirectory", [`/var/lib/${stateDirectory}`], label);
  exactDirectiveValues(unit, "Service", "Restart", ["on-failure"], label);
  exactDirectiveValues(unit, "Service", "RestartSec", ["5"], label);
  exactDirectiveValues(unit, "Service", "LimitNOFILE", ["65535"], label);
  exactDirectiveValues(unit, "Service", "ProtectClock", ["true"], label);
  exactDirectiveValues(unit, "Service", "ProtectHostname", ["true"], label);
  exactDirectiveValues(unit, "Service", "ReadOnlyPaths", [configRoot], label);
  exactDirectiveValues(unit, "Service", "ReadWritePaths", [`/var/lib/${stateDirectory}`], label);
  exactDirectiveValues(unit, "Service", "InaccessiblePaths", ["/run/bitcoinpir-source-fair-edge"], label);
  exactDirectiveValues(
    unit,
    "Service",
    "ExecStartPre",
    [
      "/usr/bin/test -x /opt/bitcoinpir/unified-server/@UNIFIED_SERVER_SHA256@/unified_server",
      `/usr/bin/sha256sum --check ${configRoot}/unified-server.sha256`,
    ],
    label,
  );
  const command = onlyDirectiveValue(unit, "Service", "ExecStart", label);
  if (/(?:^|\s)--service-retained-policy(?:\s|=|$)/mu.test(command)) {
    fail(
      `${label} is a zero-retained closed profile and must not configure --service-retained-policy`,
    );
  }
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
      ["--pool-dir", `/var/lib/${stateDirectory}/hint-pool`],
      ["--config", `${configRoot}/databases.toml`],
      ["--identity-key-path", `${configRoot}/provider-identity.key`],
      ["--identity-cert-path", `${configRoot}/provider-identity.cert`],
      ["--identity-server-id", "@HETZNER_PROVIDER_SERVER_ID@"],
      ["--require-service-auth-v1", null],
      ["--service-policy", `${configRoot}/service-policy.bin`],
      ["--service-provider-id-hex", "@HETZNER_PROVIDER_ID_HEX@"],
      ["--service-policy-key-hex", "@HETZNER_POLICY_PUBKEY_HEX@"],
      ["--service-store", `/var/lib/${stateDirectory}/provider.sqlite3`],
      ["--service-remote-rollback-authority-config", `${configRoot}/remote-rollback-authority.toml`],
      ...(!direct ? [["--service-bat-key", `${configRoot}/cashu-bat.key`]] : []),
      ...(!noStandardCashu ? [
        ["--service-cashu-recovery-key", `1=${configRoot}/cashu-recovery-epoch-1.key`],
        ["--service-cashu-recovery-active-epoch", "1"],
        ["--service-cashu-custody-key", `1=${configRoot}/cashu-custody-epoch-1.key`],
        ["--service-cashu-custody-active-epoch", "1"],
        ["--service-cashu-exposure-limit", "@CASHU_MINT_ID_HEX@:sat:@CASHU_MAX_UNSETTLED_VALUE@:@CASHU_MAX_UNSETTLED_NOTES@"],
      ] : []),
      ...(!direct ? [
        ["--service-shared-authorization", `${configRoot}/shared-clearing-authorization.bin`],
        ["--service-shared-issuer-approval", `${configRoot}/shared-clearing-approval.bin`],
        ["--service-shared-operator-key-hex", "@HETZNER_OPERATOR_PUBKEY_HEX@"],
        ["--service-shared-issuer-settlement-key-hex", "@ISSUER_SETTLEMENT_PUBKEY_HEX@"],
        ["--service-shared-clearing-key", `${configRoot}/provider-clearing-signing.key`],
        ["--service-shared-idempotency-key", `${configRoot}/shared-redeem-idempotency.key`],
        ["--service-shared-minimum-authorization-epoch", "@SHARED_MINIMUM_AUTHORIZATION_EPOCH@"],
      ] : []),
      ["--max-connections", "128"],
      ["--service-max-concurrent-auth", "16"],
      ["--service-max-concurrent-online-v2full-auth", "4"],
      ["--websocket-handshake-timeout-ms", "10000"],
      ["--connection-idle-timeout-ms", "30000"],
      ["--service-pre-auth-timeout-ms", "60000"],
    ],
    label,
  );
  if (!noStandardCashu) {
    const recovery = /--service-cashu-recovery-key\s+1=(\S+)/.exec(command)?.[1];
    const custody = /--service-cashu-custody-key\s+1=(\S+)/.exec(command)?.[1];
    if (recovery === undefined || custody === undefined || recovery === custody) {
      fail(`${label} must use distinct explicit Cashu recovery and custody keys`);
    }
  }
}

function validateHetznerIssuer(text) {
  const label = "Hetzner issuer template";
  const unit = validateInactiveSystemdTemplate(text, label, [
    "/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
    "/etc/bitcoinpir/payment-v1/SIGNET-LIGHTNING-STAGING-APPROVED",
    "/etc/bitcoinpir/payment-v1/SIGNET-ISSUER-ACTIVATION-APPROVED",
    "/etc/bitcoinpir/payment-v1/LIGHTNING-CUSTODY-APPROVED",
    "/etc/bitcoinpir/payment-v1/LIGHTNING-IDENTITY-RESTORE-APPROVED",
    "/etc/bitcoinpir/payment-v1/LIGHTNING-BACKUP-RESTORE-APPROVED",
    "/etc/bitcoinpir/payment-v1/CLN-LOADER-MAPS-APPROVED",
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
  exactDirectiveValues(unit, "Service", "InaccessiblePaths", ["/srv/lightning /srv/bitcoin /run/bitcoinpir-source-fair-edge"], label);
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
      ["--clearing-provider-request-verifying-key", "/etc/bitcoinpir/payment-v1/issuer/provider-request-verifying.key"],
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
    "/etc/bitcoinpir/payment-v1/ROLLBACK-AUTHORITY-ACTIVATION-APPROVED",
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
      "/etc/bitcoinpir/payment-v1/SIGNET-LIGHTNING-STAGING-APPROVED",
      "/etc/bitcoinpir/payment-v1/LIGHTNING-CUSTODY-APPROVED",
      "/etc/bitcoinpir/payment-v1/LIGHTNING-IDENTITY-RESTORE-APPROVED",
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
      "WorkingDirectory", "Environment", "ExecStartPre", "ExecStart", "Restart", "RestartSec",
      "TimeoutStartSec", "TimeoutStopSec", "LimitNOFILE", "NoNewPrivileges",
      "PrivateDevices", "PrivateTmp", "ProtectSystem", "ProtectHome",
      "ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs",
      "ProtectControlGroups", "ProtectClock", "ProtectHostname", "LockPersonality",
      "MemoryDenyWriteExecute", "RestrictSUIDSGID", "RestrictRealtime",
      "RestrictNamespaces", "SystemCallArchitectures", "CapabilityBoundingSet",
      "AmbientCapabilities", "RestrictAddressFamilies", "InaccessiblePaths", "ReadOnlyPaths", "ReadWritePaths",
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
  exactDirectiveValues(
    unit,
    "Service",
    "Environment",
    ["LD_LIBRARY_PATH=/opt/bitcoinpir/core-lightning-libpq/@CLN_LIBPQ_SHA256@"],
    label,
  );
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
      "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/lightning/cln-libpq.sha256",
      "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/lightning/bitcoin-core-bundle.sha256",
      "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/lightning/lightningd-config.sha256",
      "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/lightning/layout-verifier.sha256",
      "/opt/bitcoinpir/core-lightning/@CLN_BUNDLE_SHA256@/bin/lightningd --conf=/etc/bitcoinpir/payment-v1/lightning/lightningd.conf --test-daemons-only --offline",
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
    "InaccessiblePaths",
    ["/srv/lightning/plugins"],
    label,
  );
  exactDirectiveValues(
    unit,
    "Service",
    "ReadOnlyPaths",
    ["/etc/bitcoinpir/payment-v1/lightning /opt/bitcoinpir/core-lightning/@CLN_BUNDLE_SHA256@/ /opt/bitcoinpir/core-lightning-libpq/@CLN_LIBPQ_SHA256@/ /opt/bitcoinpir/bitcoin-core/@BITCOIN_CORE_BUNDLE_SHA256@/"],
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
      "/etc/bitcoinpir/payment-v1/SIGNET-LIGHTNING-STAGING-APPROVED",
      "/etc/bitcoinpir/payment-v1/SIGNET-ISSUER-ACTIVATION-APPROVED",
      "/etc/bitcoinpir/payment-v1/LIGHTNING-CUSTODY-APPROVED",
      "/etc/bitcoinpir/payment-v1/LIGHTNING-IDENTITY-RESTORE-APPROVED",
      "/etc/bitcoinpir/payment-v1/LIGHTNING-BACKUP-RESTORE-APPROVED",
      "/etc/bitcoinpir/payment-v1/CLN-LOADER-MAPS-APPROVED",
      "/run/bitcoinpir-lightning-operator-approvals/guard-generation-approved",
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
  exactDirectiveValues(unit, "Unit", "After", ["bitcoinpir-core-lightning.service bitcoinpir-lightning-preflight.service"], label);
  exactDirectiveValues(unit, "Unit", "Requires", ["bitcoinpir-core-lightning.service bitcoinpir-lightning-preflight.service"], label);
  exactDirectiveValues(unit, "Unit", "BindsTo", ["bitcoinpir-core-lightning.service bitcoinpir-lightning-preflight.service"], label);
  exactDirectiveValues(unit, "Unit", "Before", ["bitcoinpir-payment-issuer.service"], label);
  exactDirectiveValues(unit, "Service", "CapabilityBoundingSet", [""], label);
  exactDirectiveValues(unit, "Service", "AmbientCapabilities", [""], label);
  exactDirectiveValues(
    unit,
    "Service",
    "ExecStartPre",
    [
      "+/usr/bin/unlink -- /run/bitcoinpir-lightning-operator-approvals/guard-generation-approved",
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
  exactDirectiveValues(unit, "Service", "ReadOnlyPaths", ["/usr/bin/unlink /srv/lightning/@LIGHTNING_NETWORK@ /opt/bitcoinpir/cln-rpc-guard/@CLN_RPC_GUARD_SHA256@"], label);
  exactDirectiveValues(unit, "Service", "ReadWritePaths", ["/run/bitcoinpir-cln-rpc-guard /run/bitcoinpir-lightning-operator-approvals"], label);
}

function validateLightningPreflightUnit(text) {
  const label = "Hetzner Lightning live-preflight template";
  const unit = validateInactiveSystemdTemplate(
    text,
    label,
    [
      "/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
      "/etc/bitcoinpir/payment-v1/SIGNET-LIGHTNING-STAGING-APPROVED",
      "/etc/bitcoinpir/payment-v1/SIGNET-ISSUER-ACTIVATION-APPROVED",
      "/etc/bitcoinpir/payment-v1/LIGHTNING-CUSTODY-APPROVED",
      "/etc/bitcoinpir/payment-v1/LIGHTNING-IDENTITY-RESTORE-APPROVED",
      "/etc/bitcoinpir/payment-v1/LIGHTNING-BACKUP-RESTORE-APPROVED",
      "/etc/bitcoinpir/payment-v1/CLN-LOADER-MAPS-APPROVED",
      "/run/bitcoinpir-lightning-operator-approvals/preflight-generation-approved",
    ],
    { requireStateDirectoryMode: true },
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
      "Type", "NotifyAccess", "User", "Group", "SupplementaryGroups", "UMask",
      "StateDirectory", "StateDirectoryMode", "RuntimeDirectory", "RuntimeDirectoryMode",
      "ExecStartPre", "ExecStart", "Restart", "WatchdogSec", "TimeoutStartSec",
      "TimeoutStopSec", "NoNewPrivileges",
      "PrivateDevices", "PrivateTmp", "ProtectSystem", "ProtectHome",
      "ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs",
      "ProtectControlGroups", "ProtectClock", "ProtectHostname", "LockPersonality",
      "MemoryDenyWriteExecute", "RestrictSUIDSGID", "RestrictRealtime",
      "RestrictNamespaces", "SystemCallArchitectures", "CapabilityBoundingSet",
      "AmbientCapabilities", "RestrictAddressFamilies", "IPAddressDeny",
      "IPAddressAllow", "ReadOnlyPaths", "ReadWritePaths",
    ],
    label,
  );
  validatePinnedServiceSandbox(unit, label, "notify", "");
  exactDirectiveValues(unit, "Unit", "Description", ["BitcoinPIR Hetzner live Core Lightning preflight lease (template only)"], label);
  exactDirectiveValues(unit, "Unit", "Requires", ["bitcoinpir-core-lightning.service"], label);
  exactDirectiveValues(unit, "Unit", "BindsTo", ["bitcoinpir-core-lightning.service"], label);
  exactDirectiveValues(unit, "Unit", "After", ["bitcoinpir-core-lightning.service"], label);
  exactDirectiveValues(unit, "Unit", "Before", ["bitcoinpir-cln-rpc-guard.service bitcoinpir-payment-issuer.service"], label);
  exactDirectiveValues(unit, "Service", "NotifyAccess", ["main"], label);
  exactDirectiveValues(unit, "Service", "User", ["bitcoinpir-lightning-preflight"], label);
  exactDirectiveValues(unit, "Service", "Group", ["bitcoinpir-lightning-preflight"], label);
  exactDirectiveValues(unit, "Service", "SupplementaryGroups", ["bitcoinpir-cln-guard bitcoinpir-bitcoin-rpc"], label);
  exactDirectiveValues(unit, "Service", "StateDirectory", ["bitcoinpir-lightning-preflight"], label);
  exactDirectiveValues(unit, "Service", "StateDirectoryMode", ["0700"], label);
  exactDirectiveValues(unit, "Service", "RuntimeDirectory", ["bitcoinpir-lightning-preflight"], label);
  exactDirectiveValues(unit, "Service", "RuntimeDirectoryMode", ["0700"], label);
  exactDirectiveValues(unit, "Service", "Restart", ["no"], label);
  exactDirectiveValues(unit, "Service", "WatchdogSec", ["90"], label);
  exactDirectiveValues(unit, "Service", "TimeoutStartSec", ["120"], label);
  exactDirectiveValues(unit, "Service", "TimeoutStopSec", ["30"], label);
  exactDirectiveValues(unit, "Service", "IPAddressDeny", ["any"], label);
  exactDirectiveValues(unit, "Service", "IPAddressAllow", ["localhost"], label);
  exactDirectiveValues(
    unit,
    "Service",
    "ExecStartPre",
    [
      "+/usr/bin/unlink -- /run/bitcoinpir-lightning-operator-approvals/preflight-generation-approved",
      "/usr/bin/test -x /opt/bitcoinpir/bpir-admin/@BPIR_ADMIN_SHA256@/bpir-admin",
      "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/lightning/bpir-admin.sha256",
      "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/lightning/preflight-config.sha256",
    ],
    label,
  );
  validateExactCommand(
    onlyDirectiveValue(unit, "Service", "ExecStart", label),
    [
      "/opt/bitcoinpir/bpir-admin/@BPIR_ADMIN_SHA256@/bpir-admin",
      "lightning-staging",
      "preflight-supervisor",
    ],
    [
      ["--config", "/etc/bitcoinpir/payment-v1/lightning/preflight.toml"],
      ["--config-protected-parent", "/etc/bitcoinpir/payment-v1/lightning"],
      ["--config-expected-uid", "0"],
      ["--config-expected-gid", "@PREFLIGHT_GID@"],
      ["--config-reader-expected-uid", "@PREFLIGHT_UID@"],
    ],
    label,
  );
  exactDirectiveValues(
    unit,
    "Service",
    "ReadOnlyPaths",
    ["/etc/bitcoinpir/payment-v1/lightning /var/lib/bitcoinpir-lightning-preflight /run/systemd/units /usr/bin/busctl /usr/bin/unlink /srv/lightning/@LIGHTNING_NETWORK@ /opt/bitcoinpir/bpir-admin/@BPIR_ADMIN_SHA256@ /opt/bitcoinpir/core-lightning/@CLN_BUNDLE_SHA256@ /opt/bitcoinpir/bitcoin-core/@BITCOIN_CORE_BUNDLE_SHA256@"],
    label,
  );
  exactDirectiveValues(
    unit,
    "Service",
    "ReadWritePaths",
    ["/run/bitcoinpir-lightning-preflight /run/bitcoinpir-lightning-operator-approvals"],
    label,
  );
}

function validatePaymentEdgeUnit(text) {
  const label = "Payment V1 rollback-authority Caddy edge template";
  const unit = validateInactiveSystemdTemplate(text, label, [
    "/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
    "/etc/bitcoinpir/payment-v1/ROLLBACK-EDGE-ACTIVATION-APPROVED",
    "/etc/bitcoinpir/payment-v1/EDGE-PREFLIGHT-APPROVED",
    "/etc/bitcoinpir/payment-v1/ROLLBACK-AUTHORITY-PRIVATE-INGRESS-APPROVED",
  ], { requireStateDirectoryMode: false });
  exactDirectiveKeys(unit, "Unit", BASIC_UNIT_KEYS, label);
  exactDirectiveKeys(
    unit,
    "Service",
    [
      "Type", "User", "Group", "UMask", "RuntimeDirectory", "RuntimeDirectoryMode",
      "WorkingDirectory", "Environment", "ExecStartPre", "ExecStart", "Restart",
      "RestartSec", "TimeoutStartSec", "TimeoutStopSec", "LimitNOFILE",
      "LimitCORE", "MemoryMax", "MemorySwapMax", "TasksMax", "StandardError",
      "StandardOutput",
      "AmbientCapabilities", "CapabilityBoundingSet", "NoNewPrivileges",
      "PrivateDevices", "PrivateTmp", "ProtectSystem", "ProtectHome",
      "ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs",
      "ProtectControlGroups", "ProtectClock", "ProtectHostname", "LockPersonality",
      "MemoryDenyWriteExecute", "RestrictSUIDSGID", "RestrictRealtime",
      "RestrictNamespaces", "SystemCallArchitectures", "RestrictAddressFamilies",
      "IPAddressDeny", "IPAddressAllow", "ReadOnlyPaths", "ReadWritePaths",
    ],
    label,
  );
  validatePinnedServiceSandbox(unit, label, "notify", "CAP_NET_BIND_SERVICE");
  exactDirectiveValues(unit, "Unit", "Description", ["BitcoinPIR Payment V1 pinned private rollback-authority TLS edge (template only)"], label);
  exactDirectiveValues(unit, "Unit", "After", ["network-online.target"], label);
  exactDirectiveValues(unit, "Unit", "Wants", ["network-online.target"], label);
  exactDirectiveValues(unit, "Service", "User", ["bitcoinpir-payment-edge"], label);
  exactDirectiveValues(unit, "Service", "Group", ["bitcoinpir-payment-edge"], label);
  exactDirectiveValues(unit, "Service", "RuntimeDirectory", ["bitcoinpir-rollback-authority-edge"], label);
  exactDirectiveValues(unit, "Service", "RuntimeDirectoryMode", ["0700"], label);
  exactDirectiveValues(unit, "Service", "WorkingDirectory", ["/run/bitcoinpir-rollback-authority-edge"], label);
  exactDirectiveValues(unit, "Service", "Environment", ["XDG_DATA_HOME=/run/bitcoinpir-rollback-authority-edge/data XDG_CONFIG_HOME=/run/bitcoinpir-rollback-authority-edge/config"], label);
  exactDirectiveValues(unit, "Service", "Restart", ["on-failure"], label);
  exactDirectiveValues(unit, "Service", "RestartSec", ["5"], label);
  exactDirectiveValues(unit, "Service", "TimeoutStartSec", ["60"], label);
  exactDirectiveValues(unit, "Service", "TimeoutStopSec", ["30"], label);
  exactDirectiveValues(unit, "Service", "LimitNOFILE", ["1024"], label);
  exactDirectiveValues(unit, "Service", "LimitCORE", ["0"], label);
  exactDirectiveValues(unit, "Service", "MemoryMax", ["268435456"], label);
  exactDirectiveValues(unit, "Service", "MemorySwapMax", ["0"], label);
  exactDirectiveValues(unit, "Service", "TasksMax", ["128"], label);
  exactDirectiveValues(unit, "Service", "StandardError", ["null"], label);
  exactDirectiveValues(unit, "Service", "StandardOutput", ["null"], label);
  exactDirectiveValues(unit, "Service", "IPAddressDeny", ["any"], label);
  exactDirectiveValues(unit, "Service", "IPAddressAllow", ["localhost @ROLLBACK_AUTHORITY_CLIENT_IP@"], label);
  exactDirectiveValues(
    unit,
    "Service",
    "ExecStartPre",
    [
      "/usr/bin/test -x /opt/bitcoinpir/caddy/@CADDY_SHA256@/caddy",
      "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/edge/caddy.sha256",
      "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/edge/edge-config.sha256",
      "/opt/bitcoinpir/caddy/@CADDY_SHA256@/caddy validate --config /etc/bitcoinpir/payment-v1/edge/rollback-authority.Caddyfile --adapter caddyfile",
    ],
    label,
  );
  exactDirectiveValues(
    unit,
    "Service",
    "ExecStart",
    ["/opt/bitcoinpir/caddy/@CADDY_SHA256@/caddy run --config /etc/bitcoinpir/payment-v1/edge/rollback-authority.Caddyfile --adapter caddyfile"],
    label,
  );
  exactDirectiveValues(unit, "Service", "ReadOnlyPaths", ["/etc/bitcoinpir/payment-v1/edge"], label);
  exactDirectiveValues(unit, "Service", "ReadWritePaths", ["/run/bitcoinpir-rollback-authority-edge"], label);
  rejectPattern(text, /(?:^|\n)\s*StateDirectory/um, label, "persistent state directory");
}

function validatePublicPaymentEdgeUnit(text) {
  const label = "Payment V1 public Caddy edge template";
  const unit = validateInactiveSystemdTemplate(text, label, [
    "/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
    "/etc/bitcoinpir/payment-v1/EDGE-ACTIVATION-APPROVED",
    "/etc/bitcoinpir/payment-v1/EDGE-PREFLIGHT-APPROVED",
    "/etc/bitcoinpir/payment-v1/SOURCE-FAIR-PREFLIGHT-APPROVED",
    "/etc/bitcoinpir/payment-v1/DIRECTORY-PUBLISHER-PRIVATE-INGRESS-APPROVED",
  ]);
  exactDirectiveKeys(unit, "Unit", [
    "Description", "After", "Wants", "Requires", "BindsTo", "ConditionPathExists",
  ], label);
  exactDirectiveKeys(unit, "Service", [
    "Type", "User", "Group", "SupplementaryGroups", "UMask", "StateDirectory",
    "StateDirectoryMode", "WorkingDirectory", "Environment", "ExecStartPre",
    "ExecStart", "Restart", "RestartSec", "TimeoutStartSec", "TimeoutStopSec",
    "LimitNOFILE", "MemoryMax", "TasksMax", "StandardError", "StandardOutput", "AmbientCapabilities",
    "LimitCORE", "MemorySwapMax",
    "CapabilityBoundingSet", "NoNewPrivileges", "PrivateDevices", "PrivateTmp",
    "ProtectSystem", "ProtectHome", "ProtectKernelTunables", "ProtectKernelModules",
    "ProtectKernelLogs", "ProtectControlGroups", "ProtectClock", "ProtectHostname",
    "LockPersonality", "MemoryDenyWriteExecute", "RestrictSUIDSGID",
    "RestrictRealtime", "RestrictNamespaces", "SystemCallArchitectures",
    "RestrictAddressFamilies", "ReadOnlyPaths", "ReadWritePaths",
  ], label);
  validatePinnedServiceSandbox(unit, label, "notify", "CAP_NET_BIND_SERVICE");
  exactDirectiveValues(unit, "Unit", "Description", ["BitcoinPIR Payment V1 pinned public TLS edge (template only)"], label);
  exactDirectiveValues(unit, "Unit", "After", ["network-online.target bitcoinpir-payment-v1-source-fair-edge.service"], label);
  exactDirectiveValues(unit, "Unit", "Wants", ["network-online.target"], label);
  exactDirectiveValues(unit, "Unit", "Requires", ["bitcoinpir-payment-v1-source-fair-edge.service"], label);
  exactDirectiveValues(unit, "Unit", "BindsTo", ["bitcoinpir-payment-v1-source-fair-edge.service"], label);
  exactDirectiveValues(unit, "Service", "User", ["bitcoinpir-payment-edge"], label);
  exactDirectiveValues(unit, "Service", "Group", ["bitcoinpir-payment-edge"], label);
  exactDirectiveValues(unit, "Service", "SupplementaryGroups", ["bitcoinpir-source-fair-edge"], label);
  exactDirectiveValues(unit, "Service", "StateDirectory", ["bitcoinpir-payment-edge"], label);
  exactDirectiveValues(unit, "Service", "WorkingDirectory", ["/var/lib/bitcoinpir-payment-edge"], label);
  exactDirectiveValues(unit, "Service", "Environment", ["XDG_DATA_HOME=/var/lib/bitcoinpir-payment-edge/data XDG_CONFIG_HOME=/var/lib/bitcoinpir-payment-edge/config"], label);
  exactDirectiveValues(unit, "Service", "Restart", ["on-failure"], label);
  exactDirectiveValues(unit, "Service", "RestartSec", ["5"], label);
  exactDirectiveValues(unit, "Service", "TimeoutStartSec", ["60"], label);
  exactDirectiveValues(unit, "Service", "TimeoutStopSec", ["30"], label);
  exactDirectiveValues(unit, "Service", "LimitNOFILE", ["4096"], label);
  exactDirectiveValues(unit, "Service", "LimitCORE", ["0"], label);
  exactDirectiveValues(unit, "Service", "MemoryMax", ["536870912"], label);
  exactDirectiveValues(unit, "Service", "MemorySwapMax", ["0"], label);
  exactDirectiveValues(unit, "Service", "TasksMax", ["512"], label);
  exactDirectiveValues(unit, "Service", "StandardError", ["null"], label);
  exactDirectiveValues(unit, "Service", "StandardOutput", ["null"], label);
  exactDirectiveValues(unit, "Service", "ExecStartPre", [
    "/usr/bin/test -x /opt/bitcoinpir/caddy/@CADDY_SHA256@/caddy",
    "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/edge/caddy.sha256",
    "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/edge/edge-config.sha256",
    "/usr/bin/test -S /run/bitcoinpir-source-fair-edge/provider.sock",
    "/usr/bin/test -S /run/bitcoinpir-source-fair-edge/issuer.sock",
    "/usr/bin/test -S /run/bitcoinpir-source-fair-edge/directory-public.sock",
    "/usr/bin/test -S /run/bitcoinpir-source-fair-edge/directory-publisher.sock",
    "/opt/bitcoinpir/caddy/@CADDY_SHA256@/caddy validate --config /etc/bitcoinpir/payment-v1/edge/hetzner-public.Caddyfile --adapter caddyfile",
  ], label);
  exactDirectiveValues(unit, "Service", "ExecStart", [
    "/opt/bitcoinpir/caddy/@CADDY_SHA256@/caddy run --config /etc/bitcoinpir/payment-v1/edge/hetzner-public.Caddyfile --adapter caddyfile",
  ], label);
  exactDirectiveValues(unit, "Service", "ReadOnlyPaths", ["/etc/bitcoinpir/payment-v1/edge /run/bitcoinpir-source-fair-edge"], label);
  exactDirectiveValues(unit, "Service", "ReadWritePaths", ["/var/lib/bitcoinpir-payment-edge"], label);
}

function validateSourceFairEdgeUnit(text) {
  const label = "Payment V1 HAProxy source-fair edge template";
  const unit = validateInactiveSystemdTemplate(text, label, [
    "/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
    "/etc/bitcoinpir/payment-v1/EDGE-ACTIVATION-APPROVED",
    "/etc/bitcoinpir/payment-v1/SOURCE-FAIR-PREFLIGHT-APPROVED",
    "/etc/bitcoinpir/payment-v1/DIRECTORY-PUBLISHER-PRIVATE-INGRESS-APPROVED",
  ], { requireStateDirectoryMode: false });
  exactDirectiveKeys(unit, "Unit", [
    "Description", "After", "Wants", "Before", "ConditionPathExists",
  ], label);
  exactDirectiveKeys(unit, "Service", [
    "Type", "User", "Group", "UMask", "RuntimeDirectory", "RuntimeDirectoryMode",
    "WorkingDirectory", "ExecStartPre", "ExecStart", "Restart", "RestartSec",
    "TimeoutStartSec", "TimeoutStopSec", "LimitNOFILE", "MemoryMax", "TasksMax",
    "LimitCORE", "MemorySwapMax",
    "StandardError", "StandardOutput",
    "NoNewPrivileges", "PrivateDevices", "PrivateTmp", "ProtectSystem",
    "ProtectHome", "ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs",
    "ProtectControlGroups", "ProtectClock", "ProtectHostname", "LockPersonality",
    "MemoryDenyWriteExecute", "RestrictSUIDSGID", "RestrictRealtime",
    "RestrictNamespaces", "SystemCallArchitectures", "CapabilityBoundingSet",
    "AmbientCapabilities", "RestrictAddressFamilies", "IPAddressDeny",
    "IPAddressAllow", "ReadOnlyPaths", "ReadWritePaths",
  ], label);
  for (const key of [
    "NoNewPrivileges", "PrivateDevices", "PrivateTmp", "ProtectHome",
    "ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs",
    "ProtectControlGroups", "ProtectClock", "ProtectHostname", "LockPersonality",
    "MemoryDenyWriteExecute", "RestrictSUIDSGID", "RestrictRealtime",
    "RestrictNamespaces",
  ]) exactDirectiveValues(unit, "Service", key, ["true"], label);
  exactDirectiveValues(unit, "Service", "ProtectSystem", ["strict"], label);
  exactDirectiveValues(unit, "Service", "SystemCallArchitectures", ["native"], label);
  exactDirectiveValues(unit, "Service", "CapabilityBoundingSet", [""], label);
  exactDirectiveValues(unit, "Service", "AmbientCapabilities", [""], label);
  exactDirectiveValues(unit, "Unit", "Description", ["BitcoinPIR Payment V1 pinned source-fair edge (template only)"], label);
  exactDirectiveValues(unit, "Unit", "After", ["network-online.target"], label);
  exactDirectiveValues(unit, "Unit", "Wants", ["network-online.target"], label);
  exactDirectiveValues(unit, "Unit", "Before", ["bitcoinpir-payment-v1-public-edge.service"], label);
  exactDirectiveValues(unit, "Service", "Type", ["notify"], label);
  exactDirectiveValues(unit, "Service", "User", ["bitcoinpir-source-fair-edge"], label);
  exactDirectiveValues(unit, "Service", "Group", ["bitcoinpir-source-fair-edge"], label);
  exactDirectiveValues(unit, "Service", "UMask", ["0007"], label);
  exactDirectiveValues(unit, "Service", "RuntimeDirectory", ["bitcoinpir-source-fair-edge"], label);
  exactDirectiveValues(unit, "Service", "RuntimeDirectoryMode", ["0750"], label);
  exactDirectiveValues(unit, "Service", "WorkingDirectory", ["/run/bitcoinpir-source-fair-edge"], label);
  exactDirectiveValues(unit, "Service", "Restart", ["on-failure"], label);
  exactDirectiveValues(unit, "Service", "RestartSec", ["5"], label);
  exactDirectiveValues(unit, "Service", "TimeoutStartSec", ["30"], label);
  exactDirectiveValues(unit, "Service", "TimeoutStopSec", ["15"], label);
  exactDirectiveValues(unit, "Service", "LimitNOFILE", ["2048"], label);
  exactDirectiveValues(unit, "Service", "LimitCORE", ["0"], label);
  exactDirectiveValues(unit, "Service", "MemoryMax", ["268435456"], label);
  exactDirectiveValues(unit, "Service", "MemorySwapMax", ["0"], label);
  exactDirectiveValues(unit, "Service", "TasksMax", ["128"], label);
  exactDirectiveValues(unit, "Service", "StandardError", ["null"], label);
  exactDirectiveValues(unit, "Service", "StandardOutput", ["null"], label);
  exactDirectiveValues(unit, "Service", "RestrictAddressFamilies", ["AF_UNIX AF_INET AF_INET6"], label);
  exactDirectiveValues(unit, "Service", "IPAddressDeny", ["any"], label);
  exactDirectiveValues(unit, "Service", "IPAddressAllow", ["localhost"], label);
  exactDirectiveValues(unit, "Service", "ExecStartPre", [
    "/usr/bin/test -x /opt/bitcoinpir/haproxy/@HAPROXY_SHA256@/haproxy",
    "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/source-fair-edge/haproxy.sha256",
    "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/source-fair-edge/source-fair-config.sha256",
    "/opt/bitcoinpir/haproxy/@HAPROXY_SHA256@/haproxy -c -q -f /etc/bitcoinpir/payment-v1/source-fair-edge/haproxy.cfg",
  ], label);
  exactDirectiveValues(unit, "Service", "ExecStart", [
    "/opt/bitcoinpir/haproxy/@HAPROXY_SHA256@/haproxy -Ws -db -q -f /etc/bitcoinpir/payment-v1/source-fair-edge/haproxy.cfg",
  ], label);
  exactDirectiveValues(unit, "Service", "ReadOnlyPaths", ["/etc/bitcoinpir/payment-v1/source-fair-edge /opt/bitcoinpir/haproxy/@HAPROXY_SHA256@"], label);
  exactDirectiveValues(unit, "Service", "ReadWritePaths", ["/run/bitcoinpir-source-fair-edge"], label);
  rejectPattern(text, /(?:^|\n)\s*StateDirectory/um, label, "persistent state directory");
}

function validateDirectoryPublicEdgeUnit(text) {
  const label = "Payment V1 directory-public HAProxy edge template";
  const unit = validateInactiveSystemdTemplate(text, label, [
    "/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
    "/etc/bitcoinpir/payment-v1/DIRECTORY-PUBLIC-EDGE-ACTIVATION-APPROVED",
    "/etc/bitcoinpir/payment-v1/DIRECTORY-PUBLIC-EDGE-PREFLIGHT-APPROVED",
    "/etc/bitcoinpir/payment-v1/DIRECTORY-PUBLIC-EDGE-SOURCE-READY-APPROVED",
    "/etc/bitcoinpir/payment-v1/DIRECTORY-PUBLIC-EDGE-GENERATION-GUARD-IMPLEMENTED",
  ], { requireStateDirectoryMode: false });
  exactDirectiveKeys(unit, "Unit", [
    "Description", "After", "Wants", "Before", "ConditionPathExists",
  ], label);
  exactDirectiveKeys(unit, "Service", [
    "Type", "User", "Group", "UMask", "RuntimeDirectory", "RuntimeDirectoryMode",
    "WorkingDirectory", "ExecStartPre", "ExecStart", "Restart",
    "TimeoutStartSec", "TimeoutStopSec", "LimitNOFILE", "LimitCORE",
    "MemoryMax", "MemorySwapMax", "TasksMax", "StandardOutput", "StandardError",
    "NoNewPrivileges", "PrivateDevices", "PrivateTmp", "ProtectSystem",
    "ProtectHome", "ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs",
    "ProtectControlGroups", "ProtectClock", "ProtectHostname", "ProtectProc", "ProcSubset",
    "LockPersonality", "MemoryDenyWriteExecute", "RestrictSUIDSGID", "RestrictRealtime",
    "RestrictNamespaces", "SystemCallArchitectures", "CapabilityBoundingSet",
    "AmbientCapabilities", "RestrictAddressFamilies", "IPAddressDeny",
    "IPAddressAllow", "ReadOnlyPaths", "ReadWritePaths",
  ], label);
  for (const key of [
    "NoNewPrivileges", "PrivateDevices", "PrivateTmp", "ProtectHome",
    "ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs",
    "ProtectControlGroups", "ProtectClock", "ProtectHostname", "LockPersonality",
    "MemoryDenyWriteExecute", "RestrictSUIDSGID", "RestrictRealtime",
    "RestrictNamespaces",
  ]) exactDirectiveValues(unit, "Service", key, ["true"], label);
  for (const [key, value] of [
    ["Description", "BitcoinPIR directory-public source-fair edge (template only)"],
    ["After", "network-online.target"],
    ["Wants", "network-online.target"],
    ["Before", "bhtm-caddy.service"],
  ]) exactDirectiveValues(unit, "Unit", key, [value], label);
  for (const [key, value] of [
    ["Type", "exec"],
    ["User", "bitcoinpir-directory-public-edge"],
    ["Group", "bitcoinpir-directory-public-edge"],
    ["UMask", "0007"],
    ["RuntimeDirectory", "bitcoinpir-directory-public-edge"],
    ["RuntimeDirectoryMode", "0750"],
    ["WorkingDirectory", "/run/bitcoinpir-directory-public-edge"],
    ["Restart", "no"],
    ["TimeoutStartSec", "30"],
    ["TimeoutStopSec", "15"],
    ["LimitNOFILE", "512"],
    ["LimitCORE", "0"],
    ["MemoryMax", "134217728"],
    ["MemorySwapMax", "0"],
    ["TasksMax", "64"],
    ["StandardOutput", "null"],
    ["StandardError", "null"],
    ["ProtectSystem", "strict"],
    ["ProtectProc", "invisible"],
    ["ProcSubset", "pid"],
    ["SystemCallArchitectures", "native"],
    ["CapabilityBoundingSet", ""],
    ["AmbientCapabilities", ""],
    ["RestrictAddressFamilies", "AF_UNIX AF_INET AF_INET6"],
    ["IPAddressDeny", "any"],
    ["IPAddressAllow", "localhost"],
    ["ReadOnlyPaths", "/etc/bitcoinpir/payment-v1/directory-public-edge /opt/bitcoinpir/haproxy/@HAPROXY_SHA256@"],
    ["ReadWritePaths", "/run/bitcoinpir-directory-public-edge"],
  ]) exactDirectiveValues(unit, "Service", key, [value], label);
  exactDirectiveValues(unit, "Service", "ExecStartPre", [
    "/usr/bin/test -x /opt/bitcoinpir/haproxy/@HAPROXY_SHA256@/haproxy",
    "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/directory-public-edge/haproxy.sha256",
    "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/directory-public-edge/directory-public-config.sha256",
    "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/directory-public-edge/haproxy-build-manifest.sha256",
    "/opt/bitcoinpir/haproxy/@HAPROXY_SHA256@/haproxy -c -q -f /etc/bitcoinpir/payment-v1/directory-public-edge/haproxy.cfg",
  ], label);
  exactDirectiveValues(unit, "Service", "ExecStart", [
    "/opt/bitcoinpir/haproxy/@HAPROXY_SHA256@/haproxy -W -db -q -f /etc/bitcoinpir/payment-v1/directory-public-edge/haproxy.cfg",
  ], label);
  rejectPattern(text, /(?:^|\n)\s*(?:StateDirectory|RestartSec|NotifyAccess)/mu, label, "persistent, restart or notify policy");
  rejectPattern(text, /(?:^|\s)-Ws(?:\s|$)/mu, label, "systemd-notify HAProxy mode unsupported by the static artifact");
}

function validateDirectoryPublicCaddyManagedBlock(text) {
  const label = "integrated existing bhtm-Caddy directory-public managed block";
  const begin =
    "# BEGIN BITCOINPIR PAYMENT V1 MANAGED BLOCK integrated-existing-bhtm-caddy-directory-public-v1";
  const end =
    "# END BITCOINPIR PAYMENT V1 MANAGED BLOCK integrated-existing-bhtm-caddy-directory-public-v1";
  if ((text.match(new RegExp(begin, "gu")) ?? []).length !== 1 ||
      (text.match(new RegExp(end, "gu")) ?? []).length !== 1) {
    fail(`${label} must contain one exact transaction marker pair`);
  }
  if (!text.endsWith("\n")) fail(`${label} must end in canonical LF`);
  rejectPattern(text, /\r|\0/u, label, "non-canonical text");
  rejectPattern(text, /(?:^|\n)\s*\{\s*(?:\n|$)/mu, label, "global options block");
  rejectPattern(text, /(?:^|\n)\s*(?:log|log_append|log_name)(?:\s|$)/mu, label, "logging");
  rejectPattern(text, /\b(?:import|invoke|forward_auth|php_fastcgi|file_server|redir)\b/mu, label, "unreviewed expansion or handler");
  const headers = topLevelCaddyBlockHeaders(text, label);
  if (JSON.stringify(headers) !== JSON.stringify(["@DIRECTORY_RELAY_WSS_HOST@ {"])) {
    fail(`${label} must contain exactly the public directory hostname block`);
  }
  const active = activeTemplateLines(text, label);
  const upstreams = active
    .filter((line) => line.startsWith("reverse_proxy "))
    .map((line) => /^reverse_proxy\s+(\S+)\s+\{$/u.exec(line)?.[1]);
  if (JSON.stringify(upstreams) !== JSON.stringify([
    "unix//run/bitcoinpir-directory-public-edge/directory-public.sock",
  ])) {
    fail(`${label} must use only the isolated directory-public Unix socket`);
  }
  for (const required of [
    "bind @PUBLIC_HTTPS_BIND@",
    "path /",
    "expression {http.request.uri} == \"/\"",
    "proxy_protocol v2",
    "header_up -*",
    "header_down -Set-Cookie",
    "respond \"\" 404",
  ]) requireText(active.join("\n"), required, label);
  rejectPattern(text, /reverse_proxy\s+(?:127\.0\.0\.1|localhost|\[[^\]]+\]|[A-Za-z0-9.-]+):/iu, label, "direct or hostname application bypass");
}

function validateDirectoryPublicCaddyDropin(text) {
  const label = "bhtm-Caddy directory-public ordering drop-in";
  const active = activeTemplateLines(text, label);
  const expected = [
    "[Unit]",
    "Wants=bitcoinpir-payment-v1-directory-public-edge.service",
    "After=bitcoinpir-payment-v1-directory-public-edge.service",
  ];
  if (JSON.stringify(active) !== JSON.stringify(expected)) {
    fail(`${label} must contain only the exact one-way ordering relation`);
  }
}

function validateDirectoryPublicBuildManifestTemplate(text) {
  const label = "directory-public static HAProxy build-manifest template";
  if ((text.match(/@HAPROXY_SHA256@/gu) ?? []).length !== 3) {
    fail(`${label} must bind the selected artifact digest exactly three times`);
  }
  const rendered = text.replaceAll("@HAPROXY_SHA256@", "0".repeat(64));
  let manifest;
  try {
    manifest = JSON.parse(rendered);
  } catch {
    fail(`${label} must remain valid JSON after placeholder rendering`);
  }
  validateBuildManifestV1(manifest);
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
    "log-level=unusual",
    "log-timestamps=true",
    "bitcoin-cli=/opt/bitcoinpir/bitcoin-core/@BITCOIN_CORE_BUNDLE_SHA256@/bin/bitcoin-cli",
    "bitcoin-datadir=/srv/bitcoin",
    "bitcoin-rpcconnect=127.0.0.1",
    "bitcoin-rpcport=@BITCOIN_RPC_PORT@",
    "bitcoin-rpcclienttimeout=30",
    "bitcoin-retry-timeout=30",
    ...CLN_INERT_PLUGIN_NAMES_V26066.map((name) => `disable-plugin=${name}`),
  ];
  if (
    actual.length !== expected.length ||
    actual.some((line, index) => line !== expected[index])
  ) {
    fail(`${label} active lines must equal the reviewed closed-world configuration`);
  }
  rejectPattern(
    text,
    /(?:^|\n)\s*(?:clear-plugins|important-plugin|include|plugin|plugin-dir|rpcuser|rpcpassword|grpc-port|commando|developer)(?:=|\s|$)/iu,
    label,
    "dynamic plugin, include, credential, or remote-RPC option",
  );
  rejectPattern(
    text,
    /(?:^|\n)\s*invoices-onchain-fallback(?:=|\s|$)/iu,
    label,
    "on-chain invoice fallback opt-in",
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
    "d /srv/lightning/plugins 0555 root root - -",
    "d /run/bitcoinpir-lightning-operator-approvals 0700 root root - -",
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
    "identity_restore_evidence_sha256",
    "channel_recovery_restore_evidence_sha256",
    "datastore_restore_evidence_sha256",
    "expected_cln_version",
    "expected_node_id_hex",
  ];
  const booleans = [
    "identity_secret_offline_restore_rehearsed",
    "identity_node_id_crosscheck_passed",
    "bootstrap_zero_channel_preflight_passed",
    "channel_recovery_restore_rehearsed",
    "dynamic_datastore_restore_rehearsed",
    "stale_channel_state_rollback_rejected",
    "default_signet_chain_pins_verified",
    "cln_selected_deployment_file_closure_verified",
    "cln_loader_maps_inode_evidence_verified",
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

function topLevelCaddyBlockHeaders(text, label) {
  const headers = [];
  let depth = 0;
  for (const rawLine of text.split("\n")) {
    const line = rawLine.trimStart().startsWith("#") ? "" : rawLine.trim();
    if (line === "") continue;
    const opens = [...line].filter((character) => character === "{").length;
    const closes = [...line].filter((character) => character === "}").length;
    if (depth === 0 && opens > 0) headers.push(line);
    depth += opens - closes;
    if (depth < 0) fail(`${label} has an unmatched top-level closing brace`);
  }
  if (depth !== 0) fail(`${label} has an unterminated top-level block`);
  return headers;
}

function validateCaddyTemplate(text, label, expectedUpstreams, expectedTopLevelHeaders) {
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
  rejectPattern(
    text,
    /\b(?:import|invoke)\b/mu,
    label,
    "Caddy import/invoke expansion outside the reviewed closed world",
  );
  rejectPattern(
    text,
    /(?:^|\n)\s*&?\([^\n)]+\)\s*\{/mu,
    label,
    "Caddy snippet or named route outside the reviewed closed world",
  );
  const topLevelHeaders = topLevelCaddyBlockHeaders(text, label);
  if (JSON.stringify(topLevelHeaders) !== JSON.stringify(expectedTopLevelHeaders)) {
    fail(
      `${label} top-level block headers must equal ${JSON.stringify(expectedTopLevelHeaders)}`,
    );
  }

  const active = activeTemplateLines(text, label);
  const actualUpstreams = active
    .filter((line) => line.startsWith("reverse_proxy "))
    .map((line) => {
      const match = /^reverse_proxy\s+(\S+)\s+\{$/u.exec(line);
      if (!match) fail(`${label} contains a malformed reverse_proxy directive`);
      return match[1];
    });
  const sortedActualUpstreams = [...actualUpstreams].sort();
  const sortedExpectedUpstreams = [...expectedUpstreams].sort();
  if (JSON.stringify(sortedActualUpstreams) !== JSON.stringify(sortedExpectedUpstreams)) {
    fail(
      `${label} reverse_proxy upstream multiset must equal ${JSON.stringify(sortedExpectedUpstreams)}`,
    );
  }
  const approvedUpstreams = new Set([
    "127.0.0.1:5610",
    "127.0.0.1:8191",
    "127.0.0.1:8080",
    "127.0.0.1:8099",
    "unix//run/bitcoinpir-source-fair-edge/provider.sock",
    "unix//run/bitcoinpir-source-fair-edge/issuer.sock",
    "unix//run/bitcoinpir-source-fair-edge/directory-public.sock",
    "unix//run/bitcoinpir-source-fair-edge/directory-publisher.sock",
  ]);
  for (const upstream of actualUpstreams) {
    if (!approvedUpstreams.has(upstream)) {
      fail(`${label} contains non-reviewed upstream ${upstream}`);
    }
  }
  for (const line of active.filter((candidate) => candidate.startsWith("proxy_protocol "))) {
    if (line !== "proxy_protocol v2") {
      fail(`${label} may use only the reviewed proxy_protocol v2 transport`);
    }
  }
}

function validateIntegratedExistingCaddyManagedBlock(text) {
  const label = "integrated existing bhtm-Caddy managed block";
  const begin =
    "# BEGIN BITCOINPIR PAYMENT V1 MANAGED BLOCK integrated-existing-bhtm-caddy-v1";
  const end =
    "# END BITCOINPIR PAYMENT V1 MANAGED BLOCK integrated-existing-bhtm-caddy-v1";
  if ((text.match(new RegExp(begin, "gu")) ?? []).length !== 1 ||
      (text.match(new RegExp(end, "gu")) ?? []).length !== 1) {
    fail(`${label} must contain one exact transaction marker pair`);
  }
  if (!text.endsWith("\n")) fail(`${label} must end in canonical LF`);
  rejectPattern(text, /\r|\0/u, label, "non-canonical text");
  rejectPattern(
    text,
    /(?:^|\n)\s*\{\s*(?:\n|$)/mu,
    label,
    "global options block that cannot be safely appended",
  );
  rejectPattern(
    text,
    /(?:^|\n)\s*(?:log|log_append|log_name)(?:\s|$)/mu,
    label,
    "application access logging",
  );
  rejectPattern(
    text,
    /\b(?:import|invoke|forward_auth|php_fastcgi|file_server|redir)\b/mu,
    label,
    "unreviewed expansion or handler",
  );
  const expectedTopLevelHeaders = [
    "@PROVIDER_WSS_HOST@ {",
    "@PAYMENT_ISSUER_HTTPS_HOST@ {",
    "@DIRECTORY_RELAY_WSS_HOST@ {",
    "@DIRECTORY_PUBLISHER_HTTPS_HOST@ {",
  ];
  const actualTopLevelHeaders = topLevelCaddyBlockHeaders(text, label);
  if (JSON.stringify(actualTopLevelHeaders) !== JSON.stringify(expectedTopLevelHeaders)) {
    fail(`${label} must contain exactly its four reviewed hostname blocks`);
  }
  for (const [siteAddress, siteLabel] of [
    ["@DIRECTORY_RELAY_WSS_HOST@", "public directory site"],
    ["@DIRECTORY_PUBLISHER_HTTPS_HOST@", "publisher directory site"],
  ]) {
    const siteActive = activeTemplateLines(
      caddySiteBlock(text, siteAddress, label),
      `${label} ${siteLabel}`,
    );
    const pathLines = siteActive.filter((line) => line.startsWith("path "));
    if (JSON.stringify(pathLines) !== JSON.stringify(["path /"])) {
      fail(`${label} ${siteLabel} must admit only the exact origin-root path`);
    }
    const uriExpressions = siteActive.filter((line) =>
      line.includes("{http.request.uri}"));
    if (
      JSON.stringify(uriExpressions) !==
      JSON.stringify(['expression {http.request.uri} == "/"'])
    ) {
      fail(`${label} ${siteLabel} must bind the exact origin-root request URI`);
    }
  }
  const expectedUpstreams = [
    "unix//run/bitcoinpir-source-fair-edge/provider.sock",
    ...Array(4).fill("unix//run/bitcoinpir-source-fair-edge/issuer.sock"),
    "unix//run/bitcoinpir-source-fair-edge/directory-public.sock",
    "unix//run/bitcoinpir-source-fair-edge/directory-publisher.sock",
  ].sort();
  const active = activeTemplateLines(text, label);
  const upstreams = active
    .filter((line) => line.startsWith("reverse_proxy "))
    .map((line) => {
      const match = /^reverse_proxy\s+(\S+)\s+\{$/u.exec(line);
      if (!match) fail(`${label} contains a malformed reverse_proxy directive`);
      return match[1];
    })
    .sort();
  if (JSON.stringify(upstreams) !== JSON.stringify(expectedUpstreams)) {
    fail(`${label} must use only the exact source-fair Unix socket multiset`);
  }
  for (const [line, count] of [
    ["header_up -*", 7],
    ["proxy_protocol v2", 7],
    ["respond \"\" 404", 4],
    ["bind @PUBLIC_HTTPS_BIND@", 3],
    ["bind @DIRECTORY_PUBLISHER_PRIVATE_BIND@", 1],
    ["remote_ip @DIRECTORY_PUBLISHER_CLIENT_IP@", 1],
    [
      "tls /etc/bitcoinpir/payment-v1/edge/directory-publisher-server.crt /etc/bitcoinpir/payment-v1/edge/directory-publisher-server.key",
      1,
    ],
  ]) {
    if (active.filter((entry) => entry === line).length !== count) {
      fail(`${label} must contain ${JSON.stringify(line)} exactly ${count} time(s)`);
    }
  }
  rejectPattern(
    text,
    /header_up\s+(?:Authorization|Cookie|Forwarded|Proxy-Authorization|Traceparent|Tracestate|Baggage|X-Forwarded(?:-[A-Za-z0-9-]+)?|X-Real-IP|X-Request-ID)\b/iu,
    label,
    "identity, auth, cookie or trace forwarding",
  );
  rejectPattern(
    text,
    /reverse_proxy\s+(?:https?:\/\/|127\.0\.0\.1|localhost|\[?::1\]?)/iu,
    label,
    "direct application bypass",
  );
}

function caddySiteBlock(text, siteAddress, label) {
  const lines = text.split("\n");
  const header = `${siteAddress} {`;
  const starts = lines
    .map((line, index) => line.trim() === header ? index : -1)
    .filter((index) => index >= 0);
  if (starts.length !== 1) {
    fail(`${label} must contain exactly one ${header} site block`);
  }

  let depth = 0;
  const block = [];
  for (let index = starts[0]; index < lines.length; index += 1) {
    const line = lines[index];
    block.push(line);
    if (!line.trimStart().startsWith("#")) {
      for (const character of line) {
        if (character === "{") depth += 1;
        if (character === "}") depth -= 1;
        if (depth < 0) fail(`${label} has an unbalanced ${siteAddress} site block`);
      }
    }
    if (depth === 0) return block.join("\n");
  }
  fail(`${label} has an unterminated ${siteAddress} site block`);
}

function exactCaddySiteBindingsAndUpstreams(
  text,
  siteAddress,
  expectedBinds,
  expectedUpstreams,
  label,
) {
  const block = caddySiteBlock(text, siteAddress, label);
  const active = activeTemplateLines(block, `${label} ${siteAddress} site`);
  const binds = active.filter((line) => line.startsWith("bind "));
  if (JSON.stringify(binds) !== JSON.stringify(expectedBinds)) {
    fail(`${label} ${siteAddress} site binds must equal ${JSON.stringify(expectedBinds)}`);
  }
  const upstreams = active
    .filter((line) => line.startsWith("reverse_proxy "))
    .map((line) => {
      const match = /^reverse_proxy\s+(\S+)\s+\{$/u.exec(line);
      if (!match) fail(`${label} has a malformed reverse_proxy in ${siteAddress}`);
      return match[1];
    });
  if (JSON.stringify(upstreams) !== JSON.stringify(expectedUpstreams)) {
    fail(
      `${label} ${siteAddress} site upstreams must equal ${JSON.stringify(expectedUpstreams)}`,
    );
  }
  return { active, block };
}

function requireExactActiveLine(active, line, expectedCount, label) {
  const actualCount = active.filter((candidate) => candidate === line).length;
  if (actualCount !== expectedCount) {
    fail(`${label} must contain ${JSON.stringify(line)} exactly ${expectedCount} time(s)`);
  }
}

function validateHetznerPublicCaddyLaneBindings(text) {
  const label = "Hetzner public Caddy template";
  exactCaddySiteBindingsAndUpstreams(
    text,
    "@PROVIDER_WSS_HOST@",
    ["bind @PUBLIC_HTTPS_BIND@"],
    ["unix//run/bitcoinpir-source-fair-edge/provider.sock"],
    label,
  );
  exactCaddySiteBindingsAndUpstreams(
    text,
    "@PAYMENT_ISSUER_HTTPS_HOST@",
    ["bind @PUBLIC_HTTPS_BIND@"],
    Array(4).fill("unix//run/bitcoinpir-source-fair-edge/issuer.sock"),
    label,
  );
  const reader = exactCaddySiteBindingsAndUpstreams(
    text,
    "@DIRECTORY_RELAY_WSS_HOST@",
    ["bind @PUBLIC_HTTPS_BIND@"],
    ["unix//run/bitcoinpir-source-fair-edge/directory-public.sock"],
    label,
  );
  const publisher = exactCaddySiteBindingsAndUpstreams(
    text,
    "@DIRECTORY_PUBLISHER_HTTPS_HOST@",
    ["bind @DIRECTORY_PUBLISHER_PRIVATE_BIND@"],
    ["unix//run/bitcoinpir-source-fair-edge/directory-publisher.sock"],
    label,
  );
  const noHostFallback = exactCaddySiteBindingsAndUpstreams(
    text,
    "https://:443",
    [
      "bind @PUBLIC_HTTPS_BIND@",
      "bind @DIRECTORY_PUBLISHER_PRIVATE_BIND@",
    ],
    [],
    label,
  );
  requireExactActiveLine(
    reader.active,
    "path /",
    1,
    `${label} public directory site`,
  );
  requireExactActiveLine(
    reader.active,
    'expression {http.request.uri} == "/"',
    1,
    `${label} public directory site`,
  );
  requireExactActiveLine(
    publisher.active,
    "path /",
    1,
    `${label} publisher site`,
  );
  requireExactActiveLine(
    publisher.active,
    'expression {http.request.uri} == "/"',
    1,
    `${label} publisher site`,
  );
  requireExactActiveLine(
    publisher.active,
    "remote_ip @DIRECTORY_PUBLISHER_CLIENT_IP@",
    1,
    `${label} publisher site`,
  );
  requireExactActiveLine(
    noHostFallback.active,
    "tls /etc/bitcoinpir/payment-v1/edge/directory-publisher-server.crt /etc/bitcoinpir/payment-v1/edge/directory-publisher-server.key",
    1,
    `${label} no-host fallback site`,
  );
  requireExactActiveLine(
    noHostFallback.active,
    "respond \"\" 404",
    1,
    `${label} no-host fallback site`,
  );
}

function validateSourceFairHaproxy(text) {
  const label = "Payment V1 HAProxy source-fair configuration";
  const active = activeTemplateLines(text, label);
  const activeText = active.join("\n");
  for (const required of [
    "maxconn 320",
    "backend provider_sources",
    "backend issuer_sources",
    "backend issuer_quote_sources",
    "backend issuer_quote_global",
    "backend directory_public_sources",
    "backend directory_publisher_sources",
    "bind /run/bitcoinpir-source-fair-edge/provider.sock accept-proxy mode 660",
    "bind /run/bitcoinpir-source-fair-edge/issuer.sock accept-proxy mode 660",
    "bind /run/bitcoinpir-source-fair-edge/directory-public.sock accept-proxy mode 660",
    "bind /run/bitcoinpir-source-fair-edge/directory-publisher.sock accept-proxy mode 660",
    "http-request deny deny_status 403 unless { src @DIRECTORY_PUBLISHER_CLIENT_IP@ }",
    "stick-table type ipv6 size 4096 expire 2m nopurge store conn_cur,conn_rate(10s),bytes_out_rate(1s)",
    "stick-table type ipv6 size 4096 expire 2m nopurge store conn_cur,conn_rate(10s),http_req_rate(60s),bytes_out_rate(1s)",
    "stick-table type integer size 1 expire 2m nopurge store http_req_rate(60s)",
    "http-request track-sc0 src,ipmask(32,64) table provider_sources",
    "http-request track-sc0 src,ipmask(32,64) table issuer_sources",
    "http-request track-sc0 src,ipmask(32,64) table directory_public_sources",
    "http-request track-sc0 src,ipmask(32,64) table directory_publisher_sources",
    "http-request track-sc1 src,ipmask(32,64) table issuer_quote_sources if quote_create",
    "http-request track-sc2 int(1) table issuer_quote_global if quote_create",
    "http-request deny deny_status 429 unless { sc0_tracked }",
    "http-request deny deny_status 429 if quote_create !{ sc1_tracked }",
    "http-request deny deny_status 429 if quote_create !{ sc2_tracked }",
    "http-request deny deny_status 429 if { sc0_conn_cur gt 8 }",
    "http-request deny deny_status 429 if { sc0_conn_cur gt 4 }",
    "http-request deny deny_status 429 if { sc0_conn_cur gt 2 }",
    "http-request deny deny_status 429 if quote_create { sc1_http_req_rate gt 6 }",
    "http-request deny deny_status 429 if quote_create { sc2_http_req_rate gt 60 }",
    "server provider 127.0.0.1:8191 maxconn 128",
    "server issuer 127.0.0.1:5610 maxconn 128",
    "server directory-public 127.0.0.1:8080 maxconn 48",
    "server directory-publisher 127.0.0.1:8081 maxconn 4",
  ]) requireText(activeText, required, label);
  const proxyBinds = active.filter((line) => /^bind .*accept-proxy mode 660$/u.test(line));
  if (proxyBinds.length !== 4) fail(`${label} must expose exactly four protected PROXY-v2 Unix sockets`);
  const tables = active.filter((line) => line.startsWith("stick-table "));
  if (tables.length !== 6 || tables.some((line) => !line.includes("expire 2m nopurge"))) {
    fail(`${label} must have exactly six bounded, expiring, non-evicting memory tables`);
  }
  const sourceTableFullChecks = active.filter((line) => line.includes("table_avl(") && line.includes("in_table("));
  if (sourceTableFullChecks.length !== 5) {
    fail(`${label} must fail closed when any source-keyed table is full`);
  }
  const trackedAllocationGuards = [
    [
      "http-request track-sc0 src,ipmask(32,64) table provider_sources",
      "http-request deny deny_status 429 unless { sc0_tracked }",
    ],
    [
      "http-request track-sc0 src,ipmask(32,64) table issuer_sources",
      "http-request deny deny_status 429 unless { sc0_tracked }",
    ],
    [
      "http-request track-sc1 src,ipmask(32,64) table issuer_quote_sources if quote_create",
      "http-request deny deny_status 429 if quote_create !{ sc1_tracked }",
    ],
    [
      "http-request track-sc2 int(1) table issuer_quote_global if quote_create",
      "http-request deny deny_status 429 if quote_create !{ sc2_tracked }",
    ],
    [
      "http-request track-sc0 src,ipmask(32,64) table directory_public_sources",
      "http-request deny deny_status 429 unless { sc0_tracked }",
    ],
    [
      "http-request track-sc0 src,ipmask(32,64) table directory_publisher_sources",
      "http-request deny deny_status 429 unless { sc0_tracked }",
    ],
  ];
  for (const [track, guard] of trackedAllocationGuards) {
    const trackIndex = active.indexOf(track);
    if (trackIndex < 0 || active[trackIndex + 1] !== guard) {
      fail(`${label} must immediately reject a failed ${track} allocation`);
    }
  }
  const publisherSourceGuard =
    "http-request deny deny_status 403 unless { src @DIRECTORY_PUBLISHER_CLIENT_IP@ }";
  if (
    active.filter((line) => line === publisherSourceGuard).length !== 1 ||
    active.indexOf(publisherSourceGuard) >=
      active.indexOf(
        "http-request track-sc0 src,ipmask(32,64) table directory_publisher_sources",
      )
  ) {
    fail(`${label} must reject the non-publisher source before allocating publisher state`);
  }
  const allocationGuardCount = active.filter((line) =>
    /sc[012]_tracked/u.test(line)
  ).length;
  if (allocationGuardCount !== trackedAllocationGuards.length) {
    fail(`${label} must have exactly six post-allocation tracking guards`);
  }
  if (
    active.filter((line) =>
      line === "http-request deny deny_status 404 unless { path -m str / }"
    ).length !== 2
  ) {
    fail(`${label} must admit the exact origin-root path on both directory lanes`);
  }
  const egressFilters = active.filter((line) => line.startsWith("filter bwlim-out "));
  const enabledEgressFilters = active.filter((line) => line.startsWith("http-request set-bandwidth-limit "));
  if (egressFilters.length !== 8 || enabledEgressFilters.length !== 8) {
    fail(`${label} must enforce shared-source and per-stream egress on every lane`);
  }
  if (active.filter((line) => line === "no log").length !== 1) {
    fail(`${label} must explicitly disable transaction logging once`);
  }
  const expectedApplicationServers = [
    "server directory-public 127.0.0.1:8080 maxconn 48",
    "server directory-publisher 127.0.0.1:8081 maxconn 4",
    "server issuer 127.0.0.1:5610 maxconn 128",
    "server provider 127.0.0.1:8191 maxconn 128",
  ];
  const applicationServers = active
    .filter((line) => line.startsWith("server "))
    .sort();
  if (JSON.stringify(applicationServers) !== JSON.stringify(expectedApplicationServers)) {
    fail(`${label} must open exactly the four reviewed source-free loopback application peers`);
  }
  for (const line of active) {
    if (/^log(?:\s|$)/u.test(line)) fail(`${label} contains a log target`);
  }
  rejectPattern(
    activeText,
    /(?:^|\s)(?:peers|stats|server-state-file|load-server-state-from-file|send-proxy(?:-v2)?|option\s+forwardfor|unique-id-format|capture|lua-load|filter\s+spoe)(?:\s|$)/u,
    label,
    "persistent/replicated state, identity forwarding, capture, or extension hook",
  );
  rejectPattern(activeText, /127\.0\.0\.1:8099/u, label, "rollback-authority routing");
  rejectPattern(activeText, /http-request\s+(?:add|set)-header/iu, label, "header identity injection");
  for (const header of [
    "Baggage", "CF-Connecting-IP", "Client-IP", "Fastly-Client-IP",
    "Fly-Client-IP", "Forwarded", "Traceparent", "Tracestate",
    "True-Client-IP", "Via", "X-Client-IP", "X-Cluster-Client-IP",
    "X-Correlation-ID", "X-Envoy-External-Address", "X-Forwarded-For",
    "X-Forwarded-Host", "X-Forwarded-Proto", "X-Original-Client-IP",
    "X-Original-Forwarded-For", "X-Real-IP", "X-Request-ID",
  ]) {
    if (active.filter((line) => line === `http-request del-header ${header}`).length !== 4) {
      fail(`${label} must delete ${header} independently on all four application lanes`);
    }
  }
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
      ["--service-storeless-free-pow-policy-digest-hex", "@VPSBG_FREE_POW_POLICY_DIGEST_HEX@"],
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
  const actualFields = [...selection.keys()].sort();
  const expectedFields = [...RELAY_SELECTION_FIELDS].sort();
  if (
    actualFields.length !== expectedFields.length ||
    actualFields.some((field, index) => field !== expectedFields[index])
  ) {
    fail(
      `relay selection fields must equal ${JSON.stringify(expectedFields)}, got ${JSON.stringify(actualFields)}`,
    );
  }
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

  const directoryMode = stringField(selection, "directory_mode");
  if (
    directoryMode !== "strict-multi-relay" &&
    directoryMode !== "centralized-single-relay"
  ) {
    fail(
      "resolved relay directory_mode must be strict-multi-relay or centralized-single-relay",
    );
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
    const digest = stringField(selection, field);
    if (!/^[0-9a-f]{64}$/.test(digest) || /^0{64}$/.test(digest)) {
      fail(`resolved relay ${field} must be a non-zero lowercase SHA-256`);
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
  try {
    const key = createECDH("secp256k1");
    key.setPublicKey(Buffer.from(`02${publisherPubkey}`, "hex"));
  } catch {
    fail("resolved relay publisher_pubkey_hex must be a valid secp256k1 x-only key");
  }
  return {
    status,
    directoryMode,
    sourceCommit,
    sourceArchiveSha256: stringField(selection, "source_archive_sha256"),
    cargoLockSha256: stringField(selection, "cargo_lock_sha256"),
    buildManifestSha256: stringField(selection, "build_manifest_sha256"),
    binarySha256: stringField(selection, "binary_sha256"),
    binaryVersionOutput: stringField(selection, "binary_version_output"),
    configSha256: stringField(selection, "config_sha256"),
    publisherPubkey,
  };
}

export function validateRelayConfigExample(text, selection) {
  const label = "directory relay configuration example";
  if (Buffer.byteLength(text, "utf8") > 16 * 1024) {
    fail(`${label} exceeds the application 16 KiB input bound`);
  }
  const config = parseRelaySelection(text);
  const expectedKeys = [
    "profile",
    "public_listen",
    "publisher_listen",
    "database",
    "directory_pubkey_hex",
    "max_connections",
    "max_public_connections",
    "max_publisher_connections",
    "max_in_flight_operations",
    "max_public_in_flight_operations",
    "max_publisher_in_flight_operations",
    "max_operations_per_second",
    "max_public_operations_per_second",
    "max_publisher_operations_per_second",
    "max_egress_bytes_per_second",
    "max_public_egress_bytes_per_second",
    "max_publisher_egress_bytes_per_second",
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
    ["public_listen", "127.0.0.1:8080"],
    ["publisher_listen", "127.0.0.1:8081"],
    ["database", "/var/lib/bitcoinpir-directory-relay/relay.sqlite3"],
    ["max_connections", 52],
    ["max_public_connections", 48],
    ["max_publisher_connections", 4],
    ["max_in_flight_operations", 8],
    ["max_public_in_flight_operations", 6],
    ["max_publisher_in_flight_operations", 2],
    ["max_operations_per_second", 64],
    ["max_public_operations_per_second", 48],
    ["max_publisher_operations_per_second", 16],
    ["max_egress_bytes_per_second", 16_777_216],
    ["max_public_egress_bytes_per_second", 12_582_912],
    ["max_publisher_egress_bytes_per_second", 4_194_304],
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
      !rel.endsWith(".cfg.in") &&
      !rel.endsWith(".conf.in") &&
      !rel.endsWith(".json.in") &&
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
  validatePublisherNetnsTree(root);

  const provider = readRequired(
    root,
    "deploy/payment-v1/systemd/hetzner-provider.service.in",
  );
  validateHetznerProvider(provider.text);

  const providerNoStandardCashu = readRequired(
    root,
    "deploy/payment-v1/systemd/hetzner-provider-no-standard-cashu.service.in",
  );
  validateHetznerProvider(providerNoStandardCashu.text, { noStandardCashu: true });

  const providerDirect = readRequired(
    root,
    "deploy/payment-v1/systemd/hetzner-provider-direct.service.in",
  );
  validateHetznerProvider(providerDirect.text, {
    direct: true,
    noStandardCashu: true,
  });

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

  const publicPaymentEdge = readRequired(
    root,
    "deploy/payment-v1/systemd/payment-v1-public-edge.service.in",
  );
  validatePublicPaymentEdgeUnit(publicPaymentEdge.text);

  const sourceFairEdgeUnit = readRequired(
    root,
    "deploy/payment-v1/systemd/payment-v1-source-fair-edge.service.in",
  );
  validateSourceFairEdgeUnit(sourceFairEdgeUnit.text);

  const sourceFairHaproxy = readRequired(
    root,
    "deploy/payment-v1/edge/source-fair-haproxy.cfg.in",
  );
  validateSourceFairHaproxy(sourceFairHaproxy.text);

  const directoryPublicEdgeUnit = readRequired(
    root,
    "deploy/payment-v1/systemd/payment-v1-directory-public-edge.service.in",
  );
  validateDirectoryPublicEdgeUnit(directoryPublicEdgeUnit.text);

  const directoryPublicHaproxy = readRequired(
    root,
    "deploy/payment-v1/edge/directory-public-haproxy.cfg.in",
  );
  validateClosedHaproxyConfigV1(directoryPublicHaproxy.text);

  const directoryPublicBuildManifest = readRequired(
    root,
    "deploy/payment-v1/edge/directory-public-haproxy-build-manifest.json.in",
  );
  validateDirectoryPublicBuildManifestTemplate(directoryPublicBuildManifest.text);

  const directoryPublicCaddyBlock = readRequired(
    root,
    "deploy/payment-v1/edge/integrated-existing-bhtm-caddy-directory-public.managed.Caddyfile.in",
  );
  validateDirectoryPublicCaddyManagedBlock(directoryPublicCaddyBlock.text);

  const directoryPublicCaddyDropin = readRequired(
    root,
    "deploy/payment-v1/systemd/bhtm-caddy.directory-public-edge.conf.in",
  );
  validateDirectoryPublicCaddyDropin(directoryPublicCaddyDropin.text);

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
  const activeLayoutVerifierLines = activeTemplateLines(
    layoutVerifier.text,
    "Lightning layout verifier template",
  );
  const forbiddenLoopStart = activeLayoutVerifierLines.indexOf(
    "for bpir_forbidden in \\",
  );
  const forbiddenLoopEnd = activeLayoutVerifierLines.indexOf(
    "do",
    forbiddenLoopStart + 1,
  );
  const forbiddenLoopPaths = activeLayoutVerifierLines.slice(
    forbiddenLoopStart + 1,
    forbiddenLoopEnd,
  );
  if (
    forbiddenLoopStart < 0 ||
    forbiddenLoopEnd < 0 ||
    JSON.stringify(forbiddenLoopPaths) !== JSON.stringify([
      '"${bpir_lightning_base}/config" \\',
      '"${bpir_lightning_dir}/config" \\',
      '"${bpir_lightning_dir}/config.setconfig" \\',
      '"${bpir_lightning_dir}/plugins"',
    ])
  ) {
    fail(
      "Lightning layout verifier must reject only the exact unmasked config and network-local plugin lookalikes",
    );
  }
  for (const required of [
    'bpir_hsm_secret="${bpir_lightning_dir}/hsm_secret"',
    '[ -f "${bpir_hsm_secret}" ] && [ ! -L "${bpir_hsm_secret}" ] || bpir_fail',
    '[ "$(/usr/bin/stat -c \'%u:%g:%a:%s\' -- "${bpir_hsm_secret}")" = "${bpir_lightning_uid}:${bpir_lightning_gid}:400:32" ] || bpir_fail',
  ]) {
    if (!activeLayoutVerifierLines.includes(required)) {
      fail("Lightning layout verifier template must enforce the exact native hsm_secret boundary");
    }
  }

  const publicEdge = readRequired(
    root,
    "deploy/payment-v1/edge/hetzner-public.Caddyfile.in",
  );
  validateCaddyTemplate(
    publicEdge.text,
    "Hetzner public Caddy template",
    [
      "unix//run/bitcoinpir-source-fair-edge/provider.sock",
      ...Array(4).fill("unix//run/bitcoinpir-source-fair-edge/issuer.sock"),
      "unix//run/bitcoinpir-source-fair-edge/directory-public.sock",
      "unix//run/bitcoinpir-source-fair-edge/directory-publisher.sock",
    ],
    [
      "{",
      "@PROVIDER_WSS_HOST@ {",
      "@PAYMENT_ISSUER_HTTPS_HOST@ {",
      "@DIRECTORY_RELAY_WSS_HOST@ {",
      "@DIRECTORY_PUBLISHER_HTTPS_HOST@ {",
      "https://:443 {",
    ],
  );
  validateHetznerPublicCaddyLaneBindings(publicEdge.text);
  for (const required of [
    "read_header 5s",
    "read_body 15s",
    "idle 60s",
    "max_header_size 16KiB",
    "bind @PUBLIC_HTTPS_BIND@",
    "bind @DIRECTORY_PUBLISHER_PRIVATE_BIND@",
    "remote_ip @DIRECTORY_PUBLISHER_CLIENT_IP@",
    "tls /etc/bitcoinpir/payment-v1/edge/directory-publisher-server.crt /etc/bitcoinpir/payment-v1/edge/directory-publisher-server.key",
  ]) requireText(publicEdge.text, required, "Hetzner public Caddy template");
  if ((publicEdge.text.match(/remote_ip @DIRECTORY_PUBLISHER_CLIENT_IP@/gu) ?? []).length !== 1) {
    fail("Hetzner public Caddy template must use the exact publisher client address once");
  }
  rejectPattern(
    publicEdge.text,
    /\b(?:client_auth|trust_pool)\b/u,
    "Hetzner public Caddy template",
    "publisher client-certificate requirement unsupported by bpir-admin",
  );
  if ((publicEdge.text.match(/proxy_protocol v2/gu) ?? []).length !== 7) {
    fail("Hetzner public Caddy template must use PROXY v2 on exactly seven reviewed upstream routes");
  }
  if ((publicEdge.text.match(/header_up -\*/gu) ?? []).length !== 7) {
    fail("Hetzner public Caddy template must clear all client headers on every upstream route");
  }
  rejectPattern(
    publicEdge.text,
    /header_up\s+(?:CF-Connecting-IP|Client-IP|Fastly-Client-IP|Fly-Client-IP|Forwarded|True-Client-IP|X-Client-IP|X-Cluster-Client-IP|X-Envoy-External-Address|X-Forwarded(?:-[A-Za-z0-9-]+)?|X-Original-(?:Client-IP|Forwarded-For)|X-Real-IP)\b/iu,
    "Hetzner public Caddy template",
    "source identity header forwarding",
  );
  rejectPattern(
    publicEdge.text,
    /reverse_proxy\s+127\.0\.0\.1:/u,
    "Hetzner public Caddy template",
    "direct business-service bypass",
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

  const integratedExistingCaddyBlock = readRequired(
    root,
    "deploy/payment-v1/edge/integrated-existing-bhtm-caddy.managed.Caddyfile.in",
  );
  validateIntegratedExistingCaddyManagedBlock(integratedExistingCaddyBlock.text);

  const authorityEdge = readRequired(
    root,
    "deploy/payment-v1/edge/rollback-authority.Caddyfile.in",
  );
  validateCaddyTemplate(
    authorityEdge.text,
    "rollback-authority Caddy template",
    ["127.0.0.1:8099"],
    ["{", "@ROLLBACK_AUTHORITY_HTTPS_HOST@ {"],
  );
  for (const required of [
    "bind @ROLLBACK_AUTHORITY_PRIVATE_BIND@",
    "tls /etc/bitcoinpir/payment-v1/edge/rollback-authority-server.crt /etc/bitcoinpir/payment-v1/edge/rollback-authority-server.key",
  ]) requireText(authorityEdge.text, required, "rollback-authority Caddy template");

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
    "Storeless measured-policy boundary",
    "exact protocol digest argument and the script that supplies it MUST be",
    "requires a new measured UKI",
    "opens no ProviderStore or rollback authority",
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
    "/etc/bitcoinpir/payment-v1/RELAY-ACTIVATION-APPROVED",
    "/etc/bitcoinpir/payment-v1/RELAY-SELECTION-RESOLVED",
  ]);
  exactDirectiveKeys(relayParsed, "Unit", BASIC_UNIT_KEYS, relayLabel);
  exactDirectiveKeys(
    relayParsed,
    "Service",
    [
      "Type", "User", "Group", "UMask", "StateDirectory", "StateDirectoryMode",
      "WorkingDirectory", "Environment", "ExecStart", "Restart", "TimeoutStopSec",
      "LimitCORE", "LimitNOFILE", "MemoryMax", "MemorySwapMax", "TasksMax",
      "StandardOutput", "StandardError",
      "NoNewPrivileges", "PrivateTmp", "PrivateDevices", "ProtectSystem", "ProtectHome",
      "ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs",
      "ProtectControlGroups", "ProtectClock", "ProtectHostname", "ProtectProc", "ProcSubset",
      "LockPersonality", "MemoryDenyWriteExecute",
      "RestrictSUIDSGID", "RestrictNamespaces", "RestrictRealtime",
      "SystemCallArchitectures", "CapabilityBoundingSet", "AmbientCapabilities",
      "RestrictAddressFamilies", "IPAddressDeny", "IPAddressAllow", "ReadOnlyPaths",
      "ReadWritePaths", "InaccessiblePaths",
      ...(selection.status === "RESOLVED" ? ["ExecStartPre"] : []),
      ...(selection.status === "RESOLVED" ? ["RestartSec"] : []),
    ],
    relayLabel,
  );
  validateCommonServiceHardening(relayParsed, relayLabel, true);
  exactDirectiveValues(
    relayParsed,
    "Unit",
    "Description",
    [
      selection.status === "RESOLVED"
        ? "BitcoinPIR Hetzner directory-only relay (resolved, sentinel-gated)"
        : "BitcoinPIR Hetzner directory-only relay (blocked template)",
    ],
    relayLabel,
  );
  exactDirectiveValues(relayParsed, "Unit", "After", ["network-online.target"], relayLabel);
  exactDirectiveValues(relayParsed, "Unit", "Wants", ["network-online.target"], relayLabel);
  exactDirectiveValues(relayParsed, "Service", "User", ["bitcoinpir-directory-relay"], relayLabel);
  exactDirectiveValues(relayParsed, "Service", "Group", ["bitcoinpir-directory-relay"], relayLabel);
  exactDirectiveValues(relayParsed, "Service", "StateDirectory", ["bitcoinpir-directory-relay"], relayLabel);
  exactDirectiveValues(relayParsed, "Service", "WorkingDirectory", ["/var/lib/bitcoinpir-directory-relay"], relayLabel);
  exactDirectiveValues(relayParsed, "Service", "Environment", ["RUST_LOG=error"], relayLabel);
  exactDirectiveValues(relayParsed, "Service", "LimitCORE", ["0"], relayLabel);
  exactDirectiveValues(relayParsed, "Service", "LimitNOFILE", ["4096"], relayLabel);
  exactDirectiveValues(relayParsed, "Service", "MemoryMax", ["536870912"], relayLabel);
  exactDirectiveValues(relayParsed, "Service", "MemorySwapMax", ["0"], relayLabel);
  exactDirectiveValues(relayParsed, "Service", "TasksMax", ["128"], relayLabel);
  exactDirectiveValues(relayParsed, "Service", "StandardOutput", ["null"], relayLabel);
  exactDirectiveValues(relayParsed, "Service", "StandardError", ["null"], relayLabel);
  exactDirectiveValues(relayParsed, "Service", "ProtectClock", ["true"], relayLabel);
  exactDirectiveValues(relayParsed, "Service", "ProtectHostname", ["true"], relayLabel);
  exactDirectiveValues(relayParsed, "Service", "ProtectProc", ["invisible"], relayLabel);
  exactDirectiveValues(relayParsed, "Service", "ProcSubset", ["pid"], relayLabel);
  exactDirectiveValues(relayParsed, "Service", "IPAddressDeny", ["any"], relayLabel);
  exactDirectiveValues(relayParsed, "Service", "IPAddressAllow", ["localhost"], relayLabel);
  exactDirectiveValues(
    relayParsed,
    "Service",
    "ReadOnlyPaths",
    [
      selection.status === "RESOLVED"
        ? `/etc/bitcoinpir/payment-v1/directory-relay /opt/bitcoinpir/directory-relay/${selection.binarySha256}`
        : "/etc/bitcoinpir/payment-v1/directory-relay",
    ],
    relayLabel,
  );
  exactDirectiveValues(relayParsed, "Service", "ReadWritePaths", ["/var/lib/bitcoinpir-directory-relay"], relayLabel);
  exactDirectiveValues(relayParsed, "Service", "InaccessiblePaths", ["/run/bitcoinpir-source-fair-edge"], relayLabel);
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
    if (sha256File(relayConfig.absolute) !== selection.configSha256) {
      fail("resolved relay config bytes do not equal relay selection config_sha256");
    }
    const expectedExecStart =
      `/opt/bitcoinpir/directory-relay/${selection.binarySha256}/` +
      "bitcoinpir-directory-relay --config " +
      "/etc/bitcoinpir/payment-v1/directory-relay/config.toml";
    if (relayCommand !== expectedExecStart) {
      fail("resolved relay template must use only the pinned binary and one absolute --config path");
    }
    exactDirectiveValues(
      relayParsed,
      "Service",
      "ExecStartPre",
      [
        "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/directory-relay/binary.sha256",
        "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/directory-relay/config.sha256",
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
