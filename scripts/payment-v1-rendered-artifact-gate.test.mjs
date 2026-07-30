import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  appendFileSync,
  chmodSync,
  copyFileSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  truncateSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  REVIEWED_SYSTEMD_VERSION,
  RUNTIME_BUSCTL_SERVICE_PROPERTIES,
  canonicalJson,
  computeApprovedPlanSha256,
  parseStrictJson,
  renderBundle,
  runtimeRequestFromManifest,
  verifyBundle,
} from "./payment-v1-rendered-artifact-gate.mjs";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY = resolve(SCRIPT_DIRECTORY, "..");
const GATE = join(SCRIPT_DIRECTORY, "payment-v1-rendered-artifact-gate.mjs");
const EDGE_UNIT = "deploy/payment-v1/systemd/payment-v1-public-edge.service.in";
const SOURCE_FAIR_UNIT = "deploy/payment-v1/systemd/payment-v1-source-fair-edge.service.in";
const LEGACY_EDGE_UNIT = "deploy/payment-v1/systemd/payment-v1-edge.service.in";
const EDGE_CONFIG = "deploy/payment-v1/edge/hetzner-public.Caddyfile.in";
const SOURCE_FAIR_CONFIG = "deploy/payment-v1/edge/source-fair-haproxy.cfg.in";
const INTEGRATED_CADDY_GATE =
  "scripts/payment-v1-integrated-caddy-overlay-gate.mjs";
const CADDY_ADMIN_UDS_GATE =
  "scripts/payment-v1-caddy-admin-uds-gate.mjs";
const CADDY_ADMIN_UDS_PROBE =
  "scripts/payment-v1-caddy-admin-uds-probe.mjs";
const CADDY_ADMIN_UDS_TRANSACTION =
  "scripts/payment-v1-caddy-admin-uds-transaction.mjs";
const INTEGRATED_CADDY_TRANSACTION =
  "scripts/payment-v1-integrated-caddy-overlay-transaction.mjs";
const INTEGRATED_CADDY_BLOCK =
  "deploy/payment-v1/edge/integrated-existing-bhtm-caddy.managed.Caddyfile.in";
const GUARD_UNIT = "deploy/payment-v1/systemd/hetzner-cln-rpc-guard.service.in";
const PREFLIGHT_UNIT = "deploy/payment-v1/systemd/hetzner-lightning-preflight.service.in";
const PROVIDER_UNIT = "deploy/payment-v1/systemd/hetzner-provider.service.in";
const PROVIDER_NO_STANDARD_CASHU_UNIT =
  "deploy/payment-v1/systemd/hetzner-provider-no-standard-cashu.service.in";
const PROVIDER_DIRECT_UNIT =
  "deploy/payment-v1/systemd/hetzner-provider-direct.service.in";
const RELAY_UNIT = "deploy/payment-v1/systemd/hetzner-directory-relay.service.in";
const RELAY_CONFIG = "deploy/payment-v1/directory-relay.toml.example";
const RELAY_SELECTION = "deploy/payment-v1/relay-selection.toml.example";
const ISSUER_TEMPLATES = [
  "deploy/payment-v1/lightning/cln-rpc-guard-tmpfiles.conf.in",
  "deploy/payment-v1/lightning/lightningd.conf.in",
  "deploy/payment-v1/lightning/verify-layout.sh.in",
  "deploy/payment-v1/systemd/hetzner-cln-rpc-guard.service.in",
  "deploy/payment-v1/systemd/hetzner-core-lightning.service.in",
  "deploy/payment-v1/systemd/hetzner-lightning-preflight.service.in",
  "deploy/payment-v1/systemd/hetzner-payment-issuer.service.in",
];
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
const PUBLISHER_NETNS_TEMPLATES = [
  "deploy/payment-v1/network/directory-publisher-hosts.conf.in",
  "deploy/payment-v1/network/directory-publisher-network-policy.json.in",
  "deploy/payment-v1/network/directory-publisher-nsswitch.conf.in",
  "deploy/payment-v1/network/directory-publisher-resolv.conf.in",
  "deploy/payment-v1/systemd/bhtm-caddy.publisher-netns.conf.in",
  "deploy/payment-v1/systemd/payment-v1-directory-publisher.service.in",
  "deploy/payment-v1/systemd/payment-v1-publisher-netns.service.in",
];

function hashBytes(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function hashFile(path) {
  return hashBytes(readFileSync(path));
}

function clone(value) {
  return structuredClone(value);
}

function writeParent(path, bytes, mode = 0o600) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, bytes, { mode });
}

function copySource(sourceRoot, sourcePath) {
  const destination = join(sourceRoot, ...sourcePath.split("/"));
  mkdirSync(dirname(destination), { recursive: true });
  copyFileSync(join(REPOSITORY, ...sourcePath.split("/")), destination);
}

function temporaryRoots(t) {
  const root = mkdtempSync(join(tmpdir(), "bpir-rendered-v2-"));
  t.after(() => rmSync(root, { force: true, recursive: true }));
  const sourceRoot = join(root, "source");
  const inputRoot = join(root, "input");
  mkdirSync(sourceRoot, { mode: 0o700 });
  mkdirSync(inputRoot, { mode: 0o700 });
  return { bundleRoot: join(root, "bundle"), inputRoot, root, sourceRoot };
}

function payloadClass(targetPath) {
  const name = basename(targetPath).toLowerCase();
  if (targetPath.startsWith("/opt/bitcoinpir/")) return "binary";
  if (name === "remote-rollback-authority.toml") return "secret";
  if (name.endsWith(".sha256")) return "hash-manifest";
  if (
    name.endsWith(".key") ||
    name.endsWith(".seed") ||
    /(?:secret|derivation|signing|custody|idempotency)/u.test(name)
  ) return "secret";
  if (name.endsWith(".bin") || /(?:policy|authorization|approval|delegation|receipt|metadata)/u.test(name)) {
    return "policy";
  }
  return "config";
}

function payloadMetadata(targetPath, issuerGid = 732, preflightGid = 736) {
  const artifactClass = payloadClass(targetPath);
  if (artifactClass === "binary") return { class: artifactClass, gid: 0, mode: "0555", uid: 0 };
  if (artifactClass === "hash-manifest") {
    return { class: artifactClass, gid: 0, mode: "0444", uid: 0 };
  }
  const gid = targetPath.startsWith("/etc/bitcoinpir/payment-v1/lightning/")
    ? preflightGid
    : issuerGid;
  return { class: artifactClass, gid, mode: "0440", uid: 0 };
}

function renderText(sourceRoot, sourcePath, placeholders) {
  let text = readFileSync(join(sourceRoot, sourcePath), "utf8");
  for (const [name, value] of Object.entries(placeholders)) {
    text = text.split(`@${name}@`).join(value);
  }
  assert.doesNotMatch(text, /@[A-Z][A-Z0-9_]+@/u);
  return text;
}

function addPayload(fixture, targetPath, bytes, index, metadata = {}) {
  const sourcePath = `payload/${String(index).padStart(3, "0")}-${basename(targetPath)}`;
  writeParent(join(fixture.inputRoot, sourcePath), bytes);
  return {
    ...payloadMetadata(targetPath),
    ...metadata,
    expected_sha256: hashBytes(bytes),
    source_path: sourcePath,
    target_path: targetPath,
  };
}

function makeEdgeFixture(t) {
  const fixture = temporaryRoots(t);
  copySource(fixture.sourceRoot, EDGE_UNIT);
  copySource(fixture.sourceRoot, SOURCE_FAIR_UNIT);
  copySource(fixture.sourceRoot, EDGE_CONFIG);
  copySource(fixture.sourceRoot, SOURCE_FAIR_CONFIG);
  const caddyBytes = Buffer.from("reviewed-caddy-v2\n");
  const caddySha = hashBytes(caddyBytes);
  const haproxyBytes = Buffer.from("reviewed-haproxy-v2\n");
  const haproxySha = hashBytes(haproxyBytes);
  const placeholders = {
    CADDY_SHA256: caddySha,
    DIRECTORY_PUBLISHER_CLIENT_IP: "10.23.0.6",
    DIRECTORY_PUBLISHER_HTTPS_HOST: "publisher.example.net",
    DIRECTORY_PUBLISHER_PRIVATE_BIND: "10.23.0.5",
    DIRECTORY_RELAY_WSS_HOST: "directory.example.net",
    HAPROXY_SHA256: haproxySha,
    PAYMENT_ISSUER_HTTPS_HOST: "pay.example.net",
    PROVIDER_WSS_HOST: "pir.example.net",
    PUBLIC_HTTPS_BIND: "198.51.100.23",
  };
  const renderedConfig = Buffer.from(renderText(fixture.sourceRoot, EDGE_CONFIG, placeholders));
  const renderedSourceFairConfig = Buffer.from(
    renderText(fixture.sourceRoot, SOURCE_FAIR_CONFIG, placeholders),
  );
  const targets = {
    caddyBinary: `/opt/bitcoinpir/caddy/${caddySha}/caddy`,
    caddyBinaryManifest: "/etc/bitcoinpir/payment-v1/edge/caddy.sha256",
    config: "/etc/bitcoinpir/payment-v1/edge/hetzner-public.Caddyfile",
    configManifest: "/etc/bitcoinpir/payment-v1/edge/edge-config.sha256",
    haproxyBinary: `/opt/bitcoinpir/haproxy/${haproxySha}/haproxy`,
    haproxyBinaryManifest: "/etc/bitcoinpir/payment-v1/source-fair-edge/haproxy.sha256",
    publisherCertificate: "/etc/bitcoinpir/payment-v1/edge/directory-publisher-server.crt",
    publisherKey: "/etc/bitcoinpir/payment-v1/edge/directory-publisher-server.key",
    sourceFairConfig: "/etc/bitcoinpir/payment-v1/source-fair-edge/haproxy.cfg",
    sourceFairConfigManifest: "/etc/bitcoinpir/payment-v1/source-fair-edge/source-fair-config.sha256",
  };
  const payloads = [
    [targets.caddyBinary, caddyBytes],
    [targets.caddyBinaryManifest, Buffer.from(`${caddySha}  ${targets.caddyBinary}\n`)],
    [
      targets.configManifest,
      Buffer.from(`${hashBytes(renderedConfig)}  ${targets.config}\n`),
    ],
    [targets.haproxyBinary, haproxyBytes],
    [
      targets.haproxyBinaryManifest,
      Buffer.from(`${haproxySha}  ${targets.haproxyBinary}\n`),
    ],
    [targets.publisherCertificate, Buffer.from("reviewed-publisher-certificate\n")],
    [targets.publisherKey, Buffer.from("reviewed-publisher-private-key\n")],
    [
      targets.sourceFairConfigManifest,
      Buffer.from(
        `${hashBytes(renderedSourceFairConfig)}  ${targets.sourceFairConfig}\n`,
      ),
    ],
  ];
  const plan = {
    deployment_id: "hetzner-edge-v1-test",
    deployment_profile: "edge-hetzner-v1",
    payload_artifacts: payloads.map(([target, bytes], index) => {
      if (target === targets.publisherKey) {
        return addPayload(fixture, target, bytes, index, {
          class: "secret", gid: 730, mode: "0400", uid: 729,
        });
      }
      if (target === targets.publisherCertificate) {
        return addPayload(fixture, target, bytes, index, {
          class: "config", gid: 730, mode: "0440", uid: 0,
        });
      }
      return addPayload(fixture, target, bytes, index);
    }),
    placeholders,
    rendered_artifacts: [
      {
        gid: 730,
        mode: "0440",
        source_path: EDGE_CONFIG,
        source_sha256: hashFile(join(fixture.sourceRoot, EDGE_CONFIG)),
        target_path: targets.config,
        uid: 0,
      },
      {
        gid: 0,
        mode: "0644",
        source_path: EDGE_UNIT,
        source_sha256: hashFile(join(fixture.sourceRoot, EDGE_UNIT)),
        target_path: "/etc/systemd/system/bitcoinpir-payment-v1-public-edge.service",
        uid: 0,
      },
      {
        gid: 732,
        mode: "0440",
        source_path: SOURCE_FAIR_CONFIG,
        source_sha256: hashFile(join(fixture.sourceRoot, SOURCE_FAIR_CONFIG)),
        target_path: targets.sourceFairConfig,
        uid: 0,
      },
      {
        gid: 0,
        mode: "0644",
        source_path: SOURCE_FAIR_UNIT,
        source_sha256: hashFile(join(fixture.sourceRoot, SOURCE_FAIR_UNIT)),
        target_path: "/etc/systemd/system/bitcoinpir-payment-v1-source-fair-edge.service",
        uid: 0,
      },
    ],
    schema_version: 2,
    systemd_version: REVIEWED_SYSTEMD_VERSION,
    service_identities: [
      {
        gid: 730,
        group_name: "bitcoinpir-payment-edge",
        uid: 729,
        unit_name: "bitcoinpir-payment-v1-public-edge.service",
        user_name: "bitcoinpir-payment-edge",
      },
      {
        gid: 732,
        group_name: "bitcoinpir-source-fair-edge",
        uid: 731,
        unit_name: "bitcoinpir-payment-v1-source-fair-edge.service",
        user_name: "bitcoinpir-source-fair-edge",
      },
    ],
  };
  return { ...fixture, plan, targets };
}

function makeIntegratedCaddySourceFairFixture(t) {
  const fixture = temporaryRoots(t);
  copySource(fixture.sourceRoot, SOURCE_FAIR_UNIT);
  copySource(fixture.sourceRoot, SOURCE_FAIR_CONFIG);
  copySource(fixture.sourceRoot, CADDY_ADMIN_UDS_GATE);
  copySource(fixture.sourceRoot, CADDY_ADMIN_UDS_PROBE);
  copySource(fixture.sourceRoot, CADDY_ADMIN_UDS_TRANSACTION);
  copySource(fixture.sourceRoot, INTEGRATED_CADDY_GATE);
  copySource(fixture.sourceRoot, INTEGRATED_CADDY_TRANSACTION);
  copySource(fixture.sourceRoot, INTEGRATED_CADDY_BLOCK);
  const haproxyBytes = Buffer.from("reviewed-integrated-haproxy-v1\n");
  const haproxySha = hashBytes(haproxyBytes);
  const exchangeBytes = Buffer.from("reviewed-rename-exchange-v1\n");
  const exchangeSha = hashBytes(exchangeBytes);
  const placeholders = {
    DIRECTORY_PUBLISHER_CLIENT_IP: "10.23.0.6",
    DIRECTORY_PUBLISHER_HTTPS_HOST: "publisher.example.net",
    DIRECTORY_PUBLISHER_PRIVATE_BIND: "10.23.0.5",
    DIRECTORY_RELAY_WSS_HOST: "directory.example.net",
    HAPROXY_SHA256: haproxySha,
    OVERLAY_EXCHANGE_SHA256: exchangeSha,
    PAYMENT_ISSUER_HTTPS_HOST: "pay.example.net",
    PROVIDER_WSS_HOST: "pir.example.net",
    PUBLIC_HTTPS_BIND: "198.51.100.23",
  };
  const renderedSourceFairConfig = Buffer.from(
    renderText(fixture.sourceRoot, SOURCE_FAIR_CONFIG, placeholders),
  );
  const targets = {
    haproxyBinary: `/opt/bitcoinpir/haproxy/${haproxySha}/haproxy`,
    haproxyBinaryManifest: "/etc/bitcoinpir/payment-v1/source-fair-edge/haproxy.sha256",
    exchangeBinary:
      `/opt/bitcoinpir/payment-v1-rename-exchange/${exchangeSha}/payment-v1-rename-exchange`,
    exchangeBinaryManifest:
      "/etc/bitcoinpir/payment-v1/integrated-existing-bhtm-caddy/rename-exchange.sha256",
    managedBlock:
      "/etc/bitcoinpir/payment-v1/integrated-existing-bhtm-caddy/managed.Caddyfile",
    sourceFairConfig: "/etc/bitcoinpir/payment-v1/source-fair-edge/haproxy.cfg",
    sourceFairConfigManifest:
      "/etc/bitcoinpir/payment-v1/source-fair-edge/source-fair-config.sha256",
  };
  const payloads = [
    [targets.exchangeBinary, exchangeBytes],
    [
      targets.exchangeBinaryManifest,
      Buffer.from(`${exchangeSha}  ${targets.exchangeBinary}\n`),
    ],
    [targets.haproxyBinary, haproxyBytes],
    [
      targets.haproxyBinaryManifest,
      Buffer.from(`${haproxySha}  ${targets.haproxyBinary}\n`),
    ],
    [
      targets.sourceFairConfigManifest,
      Buffer.from(
        `${hashBytes(renderedSourceFairConfig)}  ${targets.sourceFairConfig}\n`,
      ),
    ],
  ];
  const plan = {
    deployment_id: "integrated-existing-bhtm-caddy-v1-test",
    deployment_profile: "integrated-existing-bhtm-caddy-v1",
    payload_artifacts: payloads.map(([target, bytes], index) =>
      addPayload(fixture, target, bytes, index),
    ),
    placeholders,
    rendered_artifacts: [
      {
        gid: 0,
        mode: "0444",
        source_path: INTEGRATED_CADDY_BLOCK,
        source_sha256: hashFile(join(fixture.sourceRoot, INTEGRATED_CADDY_BLOCK)),
        target_path: targets.managedBlock,
        uid: 0,
      },
      {
        gid: 732,
        mode: "0440",
        source_path: SOURCE_FAIR_CONFIG,
        source_sha256: hashFile(join(fixture.sourceRoot, SOURCE_FAIR_CONFIG)),
        target_path: targets.sourceFairConfig,
        uid: 0,
      },
      {
        gid: 0,
        mode: "0644",
        source_path: SOURCE_FAIR_UNIT,
        source_sha256: hashFile(join(fixture.sourceRoot, SOURCE_FAIR_UNIT)),
        target_path:
          "/etc/systemd/system/bitcoinpir-payment-v1-source-fair-edge.service",
        uid: 0,
      },
      {
        gid: 0,
        mode: "0555",
        source_path: CADDY_ADMIN_UDS_GATE,
        source_sha256: hashFile(join(fixture.sourceRoot, CADDY_ADMIN_UDS_GATE)),
        target_path:
          "/usr/local/libexec/bitcoinpir/payment-v1-caddy-admin-uds-gate.mjs",
        uid: 0,
      },
      {
        gid: 0,
        mode: "0555",
        source_path: CADDY_ADMIN_UDS_PROBE,
        source_sha256: hashFile(join(fixture.sourceRoot, CADDY_ADMIN_UDS_PROBE)),
        target_path:
          "/usr/local/libexec/bitcoinpir/payment-v1-caddy-admin-uds-probe.mjs",
        uid: 0,
      },
      {
        gid: 0,
        mode: "0555",
        source_path: CADDY_ADMIN_UDS_TRANSACTION,
        source_sha256: hashFile(join(fixture.sourceRoot, CADDY_ADMIN_UDS_TRANSACTION)),
        target_path:
          "/usr/local/libexec/bitcoinpir/payment-v1-caddy-admin-uds-transaction.mjs",
        uid: 0,
      },
      {
        gid: 0,
        mode: "0555",
        source_path: INTEGRATED_CADDY_GATE,
        source_sha256: hashFile(join(fixture.sourceRoot, INTEGRATED_CADDY_GATE)),
        target_path:
          "/usr/local/libexec/bitcoinpir/payment-v1-integrated-caddy-overlay-gate.mjs",
        uid: 0,
      },
      {
        gid: 0,
        mode: "0555",
        source_path: INTEGRATED_CADDY_TRANSACTION,
        source_sha256: hashFile(
          join(fixture.sourceRoot, INTEGRATED_CADDY_TRANSACTION),
        ),
        target_path:
          "/usr/local/libexec/bitcoinpir/payment-v1-integrated-caddy-overlay-transaction.mjs",
        uid: 0,
      },
    ],
    schema_version: 2,
    systemd_version: REVIEWED_SYSTEMD_VERSION,
    service_identities: [
      {
        gid: 732,
        group_name: "bitcoinpir-source-fair-edge",
        uid: 731,
        unit_name: "bitcoinpir-payment-v1-source-fair-edge.service",
        user_name: "bitcoinpir-source-fair-edge",
      },
    ],
  };
  return { ...fixture, plan, targets };
}

function makePublisherNetnsFixture(t) {
  const fixture = temporaryRoots(t);
  for (const template of PUBLISHER_NETNS_TEMPLATES) copySource(fixture.sourceRoot, template);
  const helperBytes = Buffer.from("reviewed-publisher-netns-helper-v1\n");
  const helperSha = hashBytes(helperBytes);
  const adminBytes = Buffer.from("reviewed-bpir-admin-v1\n");
  const adminSha = hashBytes(adminBytes);
  const placeholders = {
    BPIR_ADMIN_SHA256: adminSha,
    CHECKPOINT_ARTIFACT: "checkpoints.json",
    DIRECTORY_PUBLISHER_HTTPS_HOST: "publisher.internal.example",
    DIRECTORY_PUBLISHER_PUBKEY_HEX: "2c".repeat(32),
    DIRECTORY_PUBLISH_NOW_UNIX: "2000",
    PROVIDER_0_ENTRY_ARTIFACT: "provider-0.event.json",
    PROVIDER_1_ENTRY_ARTIFACT: "provider-1.event.json",
    PUBLISHER_NETNS_HELPER_SHA256: helperSha,
  };
  const targets = {
    admin: `/opt/bitcoinpir/bpir-admin/${adminSha}/bpir-admin`,
    adminManifest: "/etc/bitcoinpir/payment-v1/directory-publisher/bpir-admin.sha256",
    artifactManifest: "/etc/bitcoinpir/payment-v1/directory-publisher/artifacts.sha256",
    checkpoint: "/var/lib/bitcoinpir-directory-publisher/artifacts/checkpoints.json",
    helper: `/opt/bitcoinpir/publisher-netns/${helperSha}/payment-v1-publisher-netns`,
    helperManifest: "/etc/bitcoinpir/payment-v1/publisher-netns/helper.sha256",
    networkManifest: "/etc/bitcoinpir/payment-v1/directory-publisher/network-inputs.sha256",
    provider0: "/var/lib/bitcoinpir-directory-publisher/artifacts/provider-0.event.json",
    provider1: "/var/lib/bitcoinpir-directory-publisher/artifacts/provider-1.event.json",
  };
  const signedArtifacts = new Map([
    [targets.checkpoint, Buffer.from('["signed-checkpoint-fixture"]\n')],
    [targets.provider0, Buffer.from('["EVENT",{"fixture":0}]\n')],
    [targets.provider1, Buffer.from('["EVENT",{"fixture":1}]\n')],
  ]);
  const renderedNetworkTargets = new Map([
    [
      "/etc/netns/bpir-directory-publisher/hosts",
      "deploy/payment-v1/network/directory-publisher-hosts.conf.in",
    ],
    [
      "/etc/bitcoinpir/payment-v1/directory-publisher/network-policy.json",
      "deploy/payment-v1/network/directory-publisher-network-policy.json.in",
    ],
    [
      "/etc/netns/bpir-directory-publisher/nsswitch.conf",
      "deploy/payment-v1/network/directory-publisher-nsswitch.conf.in",
    ],
    [
      "/etc/netns/bpir-directory-publisher/resolv.conf",
      "deploy/payment-v1/network/directory-publisher-resolv.conf.in",
    ],
  ]);
  const manifestBytes = (entries) => Buffer.from(
    [...entries]
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([target, bytes]) => `${hashBytes(bytes)}  ${target}\n`)
      .join(""),
  );
  const renderedNetworkBytes = new Map([...renderedNetworkTargets].map(([target, source]) => [
    target,
    Buffer.from(renderText(fixture.sourceRoot, source, placeholders)),
  ]));
  const payloads = [
    [targets.helper, helperBytes, undefined],
    [targets.helperManifest, Buffer.from(`${helperSha}  ${targets.helper}\n`), undefined],
    [targets.admin, adminBytes, undefined],
    [targets.adminManifest, Buffer.from(`${adminSha}  ${targets.admin}\n`), undefined],
    [targets.artifactManifest, manifestBytes(signedArtifacts), undefined],
    [targets.networkManifest, manifestBytes(renderedNetworkBytes), undefined],
    ...[...signedArtifacts].map(([target, bytes]) => [
      target,
      bytes,
      { class: "config", gid: 0, mode: "0444", uid: 0 },
    ]),
  ];
  const targetForSource = new Map([
    ["deploy/payment-v1/network/directory-publisher-hosts.conf.in",
      "/etc/netns/bpir-directory-publisher/hosts"],
    ["deploy/payment-v1/network/directory-publisher-network-policy.json.in",
      "/etc/bitcoinpir/payment-v1/directory-publisher/network-policy.json"],
    ["deploy/payment-v1/network/directory-publisher-nsswitch.conf.in",
      "/etc/netns/bpir-directory-publisher/nsswitch.conf"],
    ["deploy/payment-v1/network/directory-publisher-resolv.conf.in",
      "/etc/netns/bpir-directory-publisher/resolv.conf"],
    ["deploy/payment-v1/systemd/bhtm-caddy.publisher-netns.conf.in",
      "/etc/systemd/system/bhtm-caddy.service.d/bitcoinpir-publisher-netns.conf"],
    ["deploy/payment-v1/systemd/payment-v1-directory-publisher.service.in",
      "/etc/systemd/system/bitcoinpir-payment-v1-directory-publisher.service"],
    ["deploy/payment-v1/systemd/payment-v1-publisher-netns.service.in",
      "/etc/systemd/system/bitcoinpir-payment-v1-publisher-netns.service"],
  ]);
  const plan = {
    deployment_id: "directory-publisher-netns-v1-test",
    deployment_profile: "directory-publisher-netns-v1",
    payload_artifacts: payloads.map(([target, bytes, metadata], index) =>
      addPayload(fixture, target, bytes, index, metadata)),
    placeholders,
    rendered_artifacts: PUBLISHER_NETNS_TEMPLATES.map((sourcePath) => ({
      gid: 0,
      mode: sourcePath.includes("/network/") ? "0444" : "0644",
      source_path: sourcePath,
      source_sha256: hashFile(join(fixture.sourceRoot, sourcePath)),
      target_path: targetForSource.get(sourcePath),
      uid: 0,
    })),
    schema_version: 1,
    service_identities: [{
      gid: 742,
      group_name: "bitcoinpir-directory-publisher",
      uid: 741,
      unit_name: "bitcoinpir-payment-v1-directory-publisher.service",
      user_name: "bitcoinpir-directory-publisher",
    }],
  };
  return { ...fixture, plan, targets };
}

function issuerPlaceholders(binaryDigests) {
  return {
    BITCOIND_SYSTEMD_UNIT: "bitcoind.service",
    BITCOINPIR_WEB_ORIGIN: "https://app.example.net",
    BITCOIN_CORE_BUNDLE_SHA256: hashBytes("bitcoin-core-bundle"),
    BITCOIN_RPC_PORT: "38332",
    BPIR_ADMIN_SHA256: binaryDigests.admin,
    BUSCTL_SHA256: "5cca481831f317814f050f97e86467079140f61e9007a32385be724d1a481f14",
    CLN_BUNDLE_SHA256: hashBytes("cln-bundle"),
    CLN_LIBPQ_SHA256: binaryDigests.libpq,
    CLN_GUARD_MAX_INVOICE_BURST: "8",
    CLN_GUARD_MAX_INVOICE_MSAT: "10000000",
    CLN_GUARD_MAX_INVOICES_PER_MINUTE: "60",
    CLN_GUARD_MAX_INVOICES_PER_RUNTIME: "10000",
    CLN_GUARD_UID: "735",
    CLN_P2P_ANNOUNCE_ADDR: "lightning.example.net:9735",
    CLN_P2P_BIND_ADDR: "0.0.0.0:9735",
    CLN_RPC_GUARD_SHA256: binaryDigests.guard,
    HETZNER_POLICY_PUBKEY_HEX: "e".repeat(64),
    ISSUER_GID: "732",
    ISSUER_UID: "731",
    LIGHTNING_GID: "734",
    LIGHTNING_NETWORK: "signet",
    LIGHTNING_UID: "733",
    PAYMENT_ISSUER_SHA256: binaryDigests.issuer,
    PREFLIGHT_GID: "736",
    PREFLIGHT_UID: "737",
  };
}

function makeIssuerFixture(t) {
  const fixture = temporaryRoots(t);
  for (const source of ISSUER_TEMPLATES) copySource(fixture.sourceRoot, source);
  const binaryBytes = {
    admin: Buffer.from("reviewed-bpir-admin\n"),
    bitcoinCli: Buffer.from("reviewed-bitcoin-cli\n"),
    bcli: Buffer.from("reviewed-bcli\n"),
    chanbackup: Buffer.from("reviewed-chanbackup\n"),
    guard: Buffer.from("reviewed-cln-guard\n"),
    issuer: Buffer.from("reviewed-payment-issuer\n"),
    lightningChanneld: Buffer.from("reviewed-lightning-channeld\n"),
    lightningCli: Buffer.from("reviewed-lightning-cli\n"),
    lightningClosingd: Buffer.from("reviewed-lightning-closingd\n"),
    lightningConnectd: Buffer.from("reviewed-lightning-connectd\n"),
    lightningGossipCompactd: Buffer.from("reviewed-lightning-gossip-compactd\n"),
    lightningGossipd: Buffer.from("reviewed-lightning-gossipd\n"),
    lightningHsmd: Buffer.from("reviewed-lightning-hsmd\n"),
    lightningHsmtool: Buffer.from("reviewed-lightning-hsmtool\n"),
    libpq: Buffer.from("reviewed-libpq-so-5\n"),
    lightningOnchaind: Buffer.from("reviewed-lightning-onchaind\n"),
    lightningOpeningd: Buffer.from("reviewed-lightning-openingd\n"),
    lightningd: Buffer.from("reviewed-lightningd\n"),
  };
  const binaryDigests = Object.fromEntries(
    Object.entries(binaryBytes).map(([name, bytes]) => [name, hashBytes(bytes)]),
  );
  const inertPluginBytes = Object.fromEntries(
    CLN_INERT_PLUGIN_NAMES_V26066.map((name) => [
      name,
      Buffer.from(`reviewed-disabled-${name}\n`),
    ]),
  );
  const inertPluginDigests = Object.fromEntries(
    Object.entries(inertPluginBytes).map(([name, bytes]) => [name, hashBytes(bytes)]),
  );
  const placeholders = issuerPlaceholders(binaryDigests);
  const clnRoot = `/opt/bitcoinpir/core-lightning/${placeholders.CLN_BUNDLE_SHA256}`;
  const bitcoinRoot = `/opt/bitcoinpir/bitcoin-core/${placeholders.BITCOIN_CORE_BUNDLE_SHA256}`;
  const targets = {
    admin: `/opt/bitcoinpir/bpir-admin/${binaryDigests.admin}/bpir-admin`,
    bitcoinCli: `${bitcoinRoot}/bin/bitcoin-cli`,
    bcli: `${clnRoot}/libexec/c-lightning/plugins/bcli`,
    chanbackup: `${clnRoot}/libexec/c-lightning/plugins/chanbackup`,
    guard: `/opt/bitcoinpir/cln-rpc-guard/${binaryDigests.guard}/bitcoinpir-cln-rpc-guard`,
    issuer: `/opt/bitcoinpir/payment-issuer/${binaryDigests.issuer}/payment-issuer`,
    lightningChanneld: `${clnRoot}/libexec/c-lightning/lightning_channeld`,
    lightningCli: `${clnRoot}/bin/lightning-cli`,
    lightningClosingd: `${clnRoot}/libexec/c-lightning/lightning_closingd`,
    lightningConnectd: `${clnRoot}/libexec/c-lightning/lightning_connectd`,
    lightningGossipCompactd: `${clnRoot}/libexec/c-lightning/lightning_gossip_compactd`,
    lightningGossipd: `${clnRoot}/libexec/c-lightning/lightning_gossipd`,
    lightningHsmd: `${clnRoot}/libexec/c-lightning/lightning_hsmd`,
    lightningHsmtool: `${clnRoot}/bin/lightning-hsmtool`,
    libpq: `/opt/bitcoinpir/core-lightning-libpq/${binaryDigests.libpq}/libpq.so.5`,
    lightningOnchaind: `${clnRoot}/libexec/c-lightning/lightning_onchaind`,
    lightningOpeningd: `${clnRoot}/libexec/c-lightning/lightning_openingd`,
    lightningd: `${clnRoot}/bin/lightningd`,
  };
  const inertPluginTargets = Object.fromEntries(
    CLN_INERT_PLUGIN_NAMES_V26066.map((name) => [
      name,
      `${clnRoot}/libexec/c-lightning/plugins/${name}`,
    ]),
  );
  const renderedTargets = {
    config: "/etc/bitcoinpir/payment-v1/lightning/lightningd.conf",
    verifier: "/usr/local/libexec/bitcoinpir/verify-lightning-layout",
  };
  const renderedHashes = {
    config: hashBytes(renderText(fixture.sourceRoot, "deploy/payment-v1/lightning/lightningd.conf.in", placeholders)),
    verifier: hashBytes(renderText(fixture.sourceRoot, "deploy/payment-v1/lightning/verify-layout.sh.in", placeholders)),
  };
  const directFiles = {
    "/etc/bitcoinpir/payment-v1/issuer/cashu-bat.key": "bat-key\n",
    "/etc/bitcoinpir/payment-v1/issuer/credential-derivation.key": "credential-key\n",
    "/etc/bitcoinpir/payment-v1/issuer/direct-receipt-signing.key": "receipt-key\n",
    "/etc/bitcoinpir/payment-v1/issuer/issuer-settlement-signing.key": "settlement-key\n",
    "/etc/bitcoinpir/payment-v1/issuer/provider-clearing-approval.bin": "approval\n",
    "/etc/bitcoinpir/payment-v1/issuer/provider-clearing-authorization.bin": "authorization\n",
    "/etc/bitcoinpir/payment-v1/issuer/provider-request-verifying.key": "provider-request-key\n",
    "/etc/bitcoinpir/payment-v1/issuer/quote-delegation.bin": "delegation\n",
    "/etc/bitcoinpir/payment-v1/issuer/quote-signing.key": "quote-key\n",
    "/etc/bitcoinpir/payment-v1/issuer/redeem-response-derivation.key": "redeem-key\n",
    "/etc/bitcoinpir/payment-v1/issuer/remote-rollback-authority.toml":
      "schema = \"bitcoinpir_remote_rollback_authority_v1\"\n" +
      "client_signing_seed_path = \"/etc/bitcoinpir/payment-v1/issuer/remote-rollback-client-signing.seed\"\n" +
      "value_root_key_path = \"/etc/bitcoinpir/payment-v1/issuer/remote-rollback-value-root.key\"\n",
    "/etc/bitcoinpir/payment-v1/issuer/remote-rollback-client-signing.seed":
      "rollback-signing-seed\n",
    "/etc/bitcoinpir/payment-v1/issuer/remote-rollback-value-root.key":
      "rollback-value-root\n",
    "/etc/bitcoinpir/payment-v1/issuer/service-policy.bin": "policy\n",
    "/etc/bitcoinpir/payment-v1/lightning/preflight.toml":
      "profile = \"signet-v1\"\n\n" +
      "[systemd.busctl]\n" +
      "path = \"/usr/bin/busctl\"\n" +
      "protected_parent = \"/usr/bin\"\n" +
      `sha256_hex = \"${placeholders.BUSCTL_SHA256}\"\n` +
      "expected_uid = 0\n" +
      "expected_gid = 0\n",
  };
  const digestFor = new Map([
    ...Object.entries(targets).map(([name, target]) => [target, binaryDigests[name]]),
    ...Object.entries(inertPluginTargets).map(([name, target]) => [target, inertPluginDigests[name]]),
    [renderedTargets.config, renderedHashes.config],
    [renderedTargets.verifier, renderedHashes.verifier],
    ...Object.entries(directFiles).map(([target, bytes]) => [target, hashBytes(bytes)]),
  ]);
  const manifestEntries = {
    "/etc/bitcoinpir/payment-v1/issuer/payment-issuer.sha256": [targets.issuer],
    "/etc/bitcoinpir/payment-v1/lightning/bitcoin-core-bundle.sha256": [targets.bitcoinCli],
    "/etc/bitcoinpir/payment-v1/lightning/bpir-admin.sha256": [targets.admin],
    "/etc/bitcoinpir/payment-v1/lightning/cln-bundle.sha256": [
      targets.lightningCli,
      targets.lightningHsmtool,
      targets.lightningChanneld,
      targets.lightningClosingd,
      targets.lightningConnectd,
      targets.lightningGossipCompactd,
      targets.lightningGossipd,
      targets.lightningHsmd,
      targets.lightningOnchaind,
      targets.lightningOpeningd,
      targets.lightningd,
      targets.bcli,
      targets.chanbackup,
      ...Object.values(inertPluginTargets),
    ],
    "/etc/bitcoinpir/payment-v1/lightning/cln-libpq.sha256": [targets.libpq],
    "/etc/bitcoinpir/payment-v1/lightning/cln-rpc-guard.sha256": [targets.guard],
    "/etc/bitcoinpir/payment-v1/lightning/layout-verifier.sha256": [renderedTargets.verifier],
    "/etc/bitcoinpir/payment-v1/lightning/lightningd-config.sha256": [renderedTargets.config],
    "/etc/bitcoinpir/payment-v1/lightning/preflight-config.sha256": [
      "/etc/bitcoinpir/payment-v1/lightning/preflight.toml",
    ],
  };
  const manifestFiles = Object.fromEntries(
    Object.entries(manifestEntries).map(([target, dependencies]) => [
      target,
      `${dependencies
        .sort()
        .map((dependency) => `${digestFor.get(dependency)}  ${dependency}`)
        .join("\n")}\n`,
    ]),
  );
  const payloadContents = [
    ...Object.entries(targets).map(([name, target]) => [target, binaryBytes[name]]),
    ...Object.entries(inertPluginTargets).map(([name, target]) => [target, inertPluginBytes[name]]),
    ...Object.entries(directFiles),
    ...Object.entries(manifestFiles),
  ].sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
  const plan = {
    deployment_id: "issuer-lightning-signet-v1-test",
    deployment_profile: "issuer-lightning-signet-v1",
    payload_artifacts: payloadContents.map(([target, bytes], index) => {
      const artifact = addPayload(fixture, target, bytes, index);
      const remoteConfig = target ===
        "/etc/bitcoinpir/payment-v1/issuer/remote-rollback-authority.toml";
      if (Object.values(inertPluginTargets).includes(target)) {
        return { ...artifact, mode: "0444" };
      }
      return artifact.class === "secret" || remoteConfig
        ? { ...artifact, class: "secret", gid: Number(placeholders.ISSUER_GID), mode: "0400", uid: Number(placeholders.ISSUER_UID) }
        : artifact;
    }),
    placeholders,
    rendered_artifacts: ISSUER_TEMPLATES.map((sourcePath) => {
      const targetsBySource = {
        "deploy/payment-v1/lightning/cln-rpc-guard-tmpfiles.conf.in": "/etc/tmpfiles.d/bitcoinpir-cln-rpc-guard.conf",
        "deploy/payment-v1/lightning/lightningd.conf.in": renderedTargets.config,
        "deploy/payment-v1/lightning/verify-layout.sh.in": renderedTargets.verifier,
        "deploy/payment-v1/systemd/hetzner-cln-rpc-guard.service.in": "/etc/systemd/system/bitcoinpir-cln-rpc-guard.service",
        "deploy/payment-v1/systemd/hetzner-core-lightning.service.in": "/etc/systemd/system/bitcoinpir-core-lightning.service",
        "deploy/payment-v1/systemd/hetzner-lightning-preflight.service.in": "/etc/systemd/system/bitcoinpir-lightning-preflight.service",
        "deploy/payment-v1/systemd/hetzner-payment-issuer.service.in": "/etc/systemd/system/bitcoinpir-payment-issuer.service",
      };
      const nonRootConfig = sourcePath.endsWith("lightningd.conf.in");
      return {
        gid: nonRootConfig ? Number(placeholders.LIGHTNING_GID) : 0,
        mode: sourcePath.endsWith("lightningd.conf.in")
          ? "0440"
          : sourcePath.endsWith("verify-layout.sh.in")
            ? "0755"
            : "0644",
        source_path: sourcePath,
        source_sha256: hashFile(join(fixture.sourceRoot, sourcePath)),
        target_path: targetsBySource[sourcePath],
        uid: 0,
      };
    }),
    schema_version: 2,
    systemd_version: REVIEWED_SYSTEMD_VERSION,
    service_identities: [
      { gid: 734, group_name: "bitcoinpir-cln-guard", uid: 735, unit_name: "bitcoinpir-cln-rpc-guard.service", user_name: "bitcoinpir-cln-rpc-guard" },
      { gid: 734, group_name: "bitcoinpir-cln-guard", uid: 733, unit_name: "bitcoinpir-core-lightning.service", user_name: "bitcoinpir-lightning" },
      { gid: 736, group_name: "bitcoinpir-lightning-preflight", uid: 737, unit_name: "bitcoinpir-lightning-preflight.service", user_name: "bitcoinpir-lightning-preflight" },
      { gid: 732, group_name: "bitcoinpir-issuer", uid: 731, unit_name: "bitcoinpir-payment-issuer.service", user_name: "bitcoinpir-issuer" },
    ],
  };
  return { ...fixture, plan };
}

function makeProviderFixture(t, { direct = false, noStandardCashu = false } = {}) {
  const fixture = temporaryRoots(t);
  const source = direct
    ? PROVIDER_DIRECT_UNIT
    : noStandardCashu
      ? PROVIDER_NO_STANDARD_CASHU_UNIT
      : PROVIDER_UNIT;
  const configRoot = direct
    ? "/etc/bitcoinpir/payment-v1/provider-direct"
    : noStandardCashu
      ? "/etc/bitcoinpir/payment-v1/provider-no-standard-cashu"
      : "/etc/bitcoinpir/payment-v1/provider";
  copySource(fixture.sourceRoot, source);
  const binaryBytes = Buffer.from("reviewed-unified-server\n");
  const binarySha = hashBytes(binaryBytes);
  const binaryTarget = `/opt/bitcoinpir/unified-server/${binarySha}/unified_server`;
  const directFiles = {
    ...(!direct ? { [`${configRoot}/cashu-bat.key`]: "bat\n" } : {}),
    ...(!noStandardCashu ? {
      [`${configRoot}/cashu-custody-epoch-1.key`]: "custody\n",
      [`${configRoot}/cashu-recovery-epoch-1.key`]: "recovery\n",
    } : {}),
    [`${configRoot}/databases.toml`]: `profile = "${direct ? "provider-direct-v1" : noStandardCashu ? "provider-no-standard-cashu-v1" : "provider-v1"}"\n`,
    ...(!direct ? {
      [`${configRoot}/provider-clearing-signing.key`]: "clearing\n",
    } : {}),
    [`${configRoot}/provider-identity.cert`]: "certificate\n",
    [`${configRoot}/provider-identity.key`]: "identity\n",
    [`${configRoot}/remote-rollback-authority.toml`]:
      "schema = \"bitcoinpir_remote_rollback_authority_v1\"\n" +
      `client_signing_seed_path = "${configRoot}/remote-rollback-client-signing.seed"\n` +
      `value_root_key_path = "${configRoot}/remote-rollback-value-root.key"\n`,
    [`${configRoot}/remote-rollback-client-signing.seed`]: "rollback-signing-seed\n",
    [`${configRoot}/remote-rollback-value-root.key`]: "rollback-value-root\n",
    [`${configRoot}/service-policy.bin`]: "policy\n",
    ...(!direct ? {
      [`${configRoot}/shared-clearing-approval.bin`]: "approval\n",
      [`${configRoot}/shared-clearing-authorization.bin`]: "authorization\n",
      [`${configRoot}/shared-redeem-idempotency.key`]: "idempotency\n",
    } : {}),
  };
  const manifestTarget = `${configRoot}/unified-server.sha256`;
  const contents = [
    [binaryTarget, binaryBytes],
    [manifestTarget, `${binarySha}  ${binaryTarget}\n`],
    ...Object.entries(directFiles),
  ].sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
  const placeholders = {
    ...(!noStandardCashu ? {
      CASHU_MAX_UNSETTLED_NOTES: "1000",
      CASHU_MAX_UNSETTLED_VALUE: "100000",
      CASHU_MINT_ID_HEX: "3".repeat(64),
    } : {}),
    ...(!direct ? {
      HETZNER_OPERATOR_PUBKEY_HEX: "4".repeat(64),
      ISSUER_SETTLEMENT_PUBKEY_HEX: "5".repeat(64),
      SHARED_MINIMUM_AUTHORIZATION_EPOCH: "1",
    } : {}),
    HETZNER_POLICY_PUBKEY_HEX: "e".repeat(64),
    HETZNER_PROVIDER_ID_HEX: "f".repeat(64),
    HETZNER_PROVIDER_SERVER_ID: "hetzner-pir-0",
    UNIFIED_SERVER_SHA256: binarySha,
  };
  const plan = {
    deployment_id: direct
      ? "provider-direct-v1-test"
      : noStandardCashu
        ? "provider-no-standard-cashu-v1-test"
        : "provider-v1-test",
    deployment_profile: direct
      ? "provider-direct-v1"
      : noStandardCashu
        ? "provider-no-standard-cashu-v1"
        : "provider-v1",
    payload_artifacts: contents.map(([target, bytes], index) => {
      const artifact = addPayload(fixture, target, bytes, index);
      const remoteConfig = target === `${configRoot}/remote-rollback-authority.toml`;
      return artifact.class === "secret" || remoteConfig
        ? { ...artifact, class: "secret", gid: 741, mode: "0400", uid: 740 }
        : artifact;
    }),
    placeholders,
    rendered_artifacts: [{
      gid: 0,
      mode: "0644",
      source_path: source,
      source_sha256: hashFile(join(fixture.sourceRoot, source)),
      target_path: direct
        ? "/etc/systemd/system/bitcoinpir-provider-direct.service"
        : noStandardCashu
          ? "/etc/systemd/system/bitcoinpir-provider-no-standard-cashu.service"
          : "/etc/systemd/system/bitcoinpir-provider.service",
      uid: 0,
    }],
    schema_version: 2,
    systemd_version: REVIEWED_SYSTEMD_VERSION,
    service_identities: [{
      gid: 741,
      group_name: direct
        ? "bitcoinpir-provider-direct"
        : noStandardCashu
          ? "bitcoinpir-provider-nocashu"
          : "bitcoinpir-provider",
      uid: 740,
      unit_name: direct
        ? "bitcoinpir-provider-direct.service"
        : noStandardCashu
          ? "bitcoinpir-provider-no-standard-cashu.service"
          : "bitcoinpir-provider.service",
      user_name: direct
        ? "bitcoinpir-provider-direct"
        : noStandardCashu
          ? "bitcoinpir-provider-nocashu"
          : "bitcoinpir-provider",
    }],
  };
  return { ...fixture, plan };
}

function makeProviderNoStandardCashuFixture(t) {
  return makeProviderFixture(t, { noStandardCashu: true });
}

function makeProviderDirectFixture(t) {
  return makeProviderFixture(t, { direct: true, noStandardCashu: true });
}

function makeRollbackFixture(t) {
  const fixture = temporaryRoots(t);
  const source = "deploy/payment-v1/systemd/rollback-authority.service.in";
  copySource(fixture.sourceRoot, source);
  const binaryBytes = Buffer.from("reviewed-rollback-authority\n");
  const binarySha = hashBytes(binaryBytes);
  const binaryTarget = `/opt/bitcoinpir/rollback-authority/${binarySha}/rollback-authority`;
  const contents = [
    [binaryTarget, binaryBytes],
    ["/etc/bitcoinpir/payment-v1/rollback-authority/authority-public.txt", "public metadata\n"],
    ["/etc/bitcoinpir/payment-v1/rollback-authority/authority.seed", "secret seed\n"],
    [
      "/etc/bitcoinpir/payment-v1/rollback-authority/rollback-authority.sha256",
      `${binarySha}  ${binaryTarget}\n`,
    ],
  ].sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
  const plan = {
    deployment_id: "rollback-authority-v1-test",
    deployment_profile: "rollback-authority-v1",
    payload_artifacts: contents.map(([target, bytes], index) => {
      const artifact = addPayload(fixture, target, bytes, index);
      return artifact.class === "secret" ? { ...artifact, gid: 743, mode: "0400", uid: 742 } : artifact;
    }),
    placeholders: {
      AUTHORITY_PUBKEY_HEX: "7".repeat(64),
      ROLLBACK_AUTHORITY_SHA256: binarySha,
    },
    rendered_artifacts: [{
      gid: 0,
      mode: "0644",
      source_path: source,
      source_sha256: hashFile(join(fixture.sourceRoot, source)),
      target_path: "/etc/systemd/system/bitcoinpir-rollback-authority.service",
      uid: 0,
    }],
    schema_version: 2,
    systemd_version: REVIEWED_SYSTEMD_VERSION,
    service_identities: [{ gid: 743, group_name: "bitcoinpir-rollback-authority", uid: 742, unit_name: "bitcoinpir-rollback-authority.service", user_name: "bitcoinpir-rollback-authority" }],
  };
  return { ...fixture, plan };
}

function makeRollbackEdgeFixture(t) {
  const fixture = temporaryRoots(t);
  const source = "deploy/payment-v1/edge/rollback-authority.Caddyfile.in";
  copySource(fixture.sourceRoot, source);
  copySource(fixture.sourceRoot, LEGACY_EDGE_UNIT);
  const binaryBytes = Buffer.from("reviewed-caddy-rollback\n");
  const binarySha = hashBytes(binaryBytes);
  const binaryTarget = `/opt/bitcoinpir/caddy/${binarySha}/caddy`;
  const configTarget = "/etc/bitcoinpir/payment-v1/edge/rollback-authority.Caddyfile";
  const placeholders = {
    CADDY_SHA256: binarySha,
    ROLLBACK_AUTHORITY_CLIENT_IP: "10.44.0.2",
    ROLLBACK_AUTHORITY_HTTPS_HOST: "authority.example.net",
    ROLLBACK_AUTHORITY_PRIVATE_BIND: "10.44.0.3",
  };
  const configSha = hashBytes(renderText(fixture.sourceRoot, source, placeholders));
  const contents = [
    [binaryTarget, binaryBytes],
    ["/etc/bitcoinpir/payment-v1/edge/caddy.sha256", `${binarySha}  ${binaryTarget}\n`],
    ["/etc/bitcoinpir/payment-v1/edge/edge-config.sha256", `${configSha}  ${configTarget}\n`],
    ["/etc/bitcoinpir/payment-v1/edge/rollback-authority-server.crt", "reviewed rollback server certificate\n"],
    ["/etc/bitcoinpir/payment-v1/edge/rollback-authority-server.key", "reviewed rollback server private key\n"],
  ];
  const plan = {
    deployment_id: "rollback-edge-v1-test",
    deployment_profile: "edge-rollback-authority-v1",
    payload_artifacts: contents.map(([target, bytes], index) => {
      if (target.endsWith("rollback-authority-server.key")) {
        return addPayload(fixture, target, bytes, index, {
          class: "secret", gid: 730, mode: "0400", uid: 729,
        });
      }
      if (target.endsWith("rollback-authority-server.crt")) {
        return addPayload(fixture, target, bytes, index, {
          class: "config", gid: 730, mode: "0440", uid: 0,
        });
      }
      return addPayload(fixture, target, bytes, index);
    }),
    placeholders,
    rendered_artifacts: [
      {
        gid: 730,
        mode: "0440",
        source_path: source,
        source_sha256: hashFile(join(fixture.sourceRoot, source)),
        target_path: configTarget,
        uid: 0,
      },
      {
        gid: 0,
        mode: "0644",
        source_path: LEGACY_EDGE_UNIT,
        source_sha256: hashFile(join(fixture.sourceRoot, LEGACY_EDGE_UNIT)),
        target_path: "/etc/systemd/system/bitcoinpir-payment-v1-edge.service",
        uid: 0,
      },
    ],
    schema_version: 2,
    systemd_version: REVIEWED_SYSTEMD_VERSION,
    service_identities: [{
      gid: 730,
      group_name: "bitcoinpir-payment-edge",
      uid: 729,
      unit_name: "bitcoinpir-payment-v1-edge.service",
      user_name: "bitcoinpir-payment-edge",
    }],
  };
  return { ...fixture, plan };
}

function makeDirectoryRelayFixture(t) {
  const fixture = temporaryRoots(t);
  copySource(fixture.sourceRoot, RELAY_CONFIG);
  copySource(fixture.sourceRoot, RELAY_UNIT);
  copySource(fixture.sourceRoot, RELAY_SELECTION);
  const publisherPubkey =
    "0d399dc19efb5632e4a1d26ad5fec578fb401c6b3af80e234cea7339a8c7ad0c";
  writeFileSync(
    join(fixture.sourceRoot, RELAY_CONFIG),
    readFileSync(join(fixture.sourceRoot, RELAY_CONFIG), "utf8").replace(
      publisherPubkey,
      "@DIRECTORY_PUBLISHER_PUBKEY_HEX@",
    ),
  );
  let unresolvedSelection = readFileSync(
    join(fixture.sourceRoot, RELAY_SELECTION),
    "utf8",
  );
  unresolvedSelection = replaceRelaySelectionField(
    unresolvedSelection,
    "status",
    "UNRESOLVED",
  );
  for (const field of [
    "directory_mode",
    "implementation",
    "source_repository",
    "source_commit",
    "source_archive_sha256",
    "cargo_lock_sha256",
    "build_manifest_sha256",
    "binary_sha256",
    "binary_version_output",
    "config_sha256",
    "publisher_pubkey_hex",
  ]) {
    unresolvedSelection = replaceRelaySelectionField(
      unresolvedSelection,
      field,
      "UNRESOLVED",
    );
  }
  writeFileSync(join(fixture.sourceRoot, RELAY_SELECTION), unresolvedSelection);
  const resolvedBinarySha256 =
    "77571e6266ca2908483d7172d0cf5c542c16f818dad09767426439f0358e7eb8";
  writeFileSync(
    join(fixture.sourceRoot, RELAY_UNIT),
    readFileSync(join(fixture.sourceRoot, RELAY_UNIT), "utf8")
      .replace(
        "# BitcoinPIR Payment V1 deployment template; selection is resolved but activation is separate.",
        "# BitcoinPIR Payment V1 deployment template; relay selection is not resolved.",
      )
      .replace(
        "Description=BitcoinPIR Hetzner directory-only relay (resolved, sentinel-gated)",
        "Description=BitcoinPIR Hetzner directory-only relay (blocked template)",
      )
      .replace(/^ExecStartPre=.*\n/gmu, "")
      .replace(
        new RegExp(
          `^ExecStart=/opt/bitcoinpir/directory-relay/${resolvedBinarySha256}/bitcoinpir-directory-relay.*$`,
          "mu",
        ),
        "ExecStart=/usr/bin/false",
      )
      .replace("Restart=on-failure\nRestartSec=5", "Restart=no")
      .replace(
        `ReadOnlyPaths=/etc/bitcoinpir/payment-v1/directory-relay /opt/bitcoinpir/directory-relay/${resolvedBinarySha256}`,
        "ReadOnlyPaths=/etc/bitcoinpir/payment-v1/directory-relay",
      ),
  );
  const plan = {
    deployment_id: "directory-relay-v1-stopped-test",
    deployment_profile: "directory-relay-v1",
    payload_artifacts: [],
    placeholders: {
      DIRECTORY_PUBLISHER_PUBKEY_HEX: "8".repeat(64),
    },
    rendered_artifacts: [
      {
        gid: 52952,
        mode: "0400",
        source_path: RELAY_CONFIG,
        source_sha256: hashFile(join(fixture.sourceRoot, RELAY_CONFIG)),
        target_path: "/etc/bitcoinpir/payment-v1/directory-relay/config.toml",
        uid: 52951,
      },
      {
        gid: 0,
        mode: "0644",
        source_path: RELAY_UNIT,
        source_sha256: hashFile(join(fixture.sourceRoot, RELAY_UNIT)),
        target_path: "/etc/systemd/system/bitcoinpir-directory-relay.service",
        uid: 0,
      },
    ],
    relay_selection_sha256: hashFile(join(fixture.sourceRoot, RELAY_SELECTION)),
    schema_version: 2,
    systemd_version: REVIEWED_SYSTEMD_VERSION,
    service_identities: [{
      gid: 52952,
      group_name: "bitcoinpir-directory-relay",
      uid: 52951,
      unit_name: "bitcoinpir-directory-relay.service",
      user_name: "bitcoinpir-directory-relay",
    }],
  };
  return { ...fixture, plan };
}

function replaceRelaySelectionField(text, field, value) {
  const expression = new RegExp(`^${field}\\s*=.*$`, "mu");
  assert.match(text, expression);
  return text.replace(expression, `${field} = ${JSON.stringify(value)}`);
}

function makeResolvedDirectoryRelayFixture(t) {
  const fixture = makeDirectoryRelayFixture(t);
  const publisherPubkey =
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
  const binaryBytes = Buffer.from("reviewed-directory-relay-linux-amd64\n");
  const binarySha256 = hashBytes(binaryBytes);
  updateTemplate(fixture, RELAY_CONFIG, (text) =>
    text.replace("@DIRECTORY_PUBLISHER_PUBKEY_HEX@", publisherPubkey));
  const configSha256 = hashFile(join(fixture.sourceRoot, RELAY_CONFIG));
  updateTemplate(fixture, RELAY_UNIT, (text) =>
    text
      .replace(
        "ExecStart=/usr/bin/false",
        `ExecStartPre=/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/directory-relay/binary.sha256\n` +
        `ExecStartPre=/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/directory-relay/config.sha256\n` +
        `ExecStart=/opt/bitcoinpir/directory-relay/${binarySha256}/bitcoinpir-directory-relay --config /etc/bitcoinpir/payment-v1/directory-relay/config.toml`,
      )
      .replace("Restart=no", "Restart=on-failure\nRestartSec=5")
      .replace(
        "ReadOnlyPaths=/etc/bitcoinpir/payment-v1/directory-relay",
        `ReadOnlyPaths=/etc/bitcoinpir/payment-v1/directory-relay /opt/bitcoinpir/directory-relay/${binarySha256}`,
      ));
  let selection = readFileSync(join(fixture.sourceRoot, RELAY_SELECTION), "utf8");
  for (const [field, value] of Object.entries({
    status: "RESOLVED",
    directory_mode: "centralized-single-relay",
    implementation: "bitcoinpir-directory-only",
    source_repository: "https://github.com/Bitcoin-PIR/Bitcoin-PIR.git",
    source_commit: "1".repeat(40),
    source_archive_sha256: "2".repeat(64),
    cargo_lock_sha256: "3".repeat(64),
    build_manifest_sha256: "4".repeat(64),
    binary_sha256: binarySha256,
    binary_version_output: "bitcoinpir-directory-relay 0.1.0",
    config_sha256: configSha256,
    publisher_pubkey_hex: publisherPubkey,
  })) {
    selection = replaceRelaySelectionField(selection, field, value);
  }
  writeFileSync(join(fixture.sourceRoot, RELAY_SELECTION), selection);
  fixture.plan.deployment_id = "directory-relay-v1-resolved-test";
  fixture.plan.placeholders = {};
  fixture.plan.relay_selection_sha256 = hashFile(
    join(fixture.sourceRoot, RELAY_SELECTION),
  );
  const binaryTarget =
    `/opt/bitcoinpir/directory-relay/${binarySha256}/bitcoinpir-directory-relay`;
  fixture.plan.payload_artifacts = [
    addPayload(fixture, binaryTarget, binaryBytes, 0),
    addPayload(
      fixture,
      "/etc/bitcoinpir/payment-v1/directory-relay/binary.sha256",
      Buffer.from(`${binarySha256}  ${binaryTarget}\n`),
      1,
    ),
    addPayload(
      fixture,
      "/etc/bitcoinpir/payment-v1/directory-relay/config.sha256",
      Buffer.from(
        `${configSha256}  /etc/bitcoinpir/payment-v1/directory-relay/config.toml\n`,
      ),
      2,
    ),
  ];
  return fixture;
}

function approved(plan) {
  return computeApprovedPlanSha256(plan);
}

function renderFixture(fixture, outputRoot = fixture.bundleRoot) {
  return renderBundle({
    approvedPlanSha256: approved(fixture.plan),
    inputRoot: fixture.inputRoot,
    outputRoot,
    plan: fixture.plan,
    sourceRoot: fixture.sourceRoot,
  });
}

function verifyFixture(fixture, bundleRoot = fixture.bundleRoot) {
  return verifyBundle({
    approvedPlanSha256: approved(fixture.plan),
    bundleRoot,
    inputRoot: fixture.inputRoot,
    plan: fixture.plan,
    sourceRoot: fixture.sourceRoot,
  });
}

function updateTemplate(fixture, sourcePath, mutate) {
  const path = join(fixture.sourceRoot, sourcePath);
  const before = readFileSync(path, "utf8");
  const after = mutate(before);
  assert.notEqual(after, before);
  writeFileSync(path, after);
  fixture.plan.rendered_artifacts.find((entry) => entry.source_path === sourcePath).source_sha256 = hashFile(path);
}

function updatePayload(fixture, targetPath, mutate) {
  const artifact = fixture.plan.payload_artifacts.find(
    (entry) => entry.target_path === targetPath,
  );
  assert.ok(artifact, `missing payload fixture for ${targetPath}`);
  const path = join(fixture.inputRoot, artifact.source_path);
  const before = readFileSync(path, "utf8");
  const after = mutate(before);
  assert.notEqual(after, before);
  writeFileSync(path, after);
  artifact.expected_sha256 = hashFile(path);
}

test("edge bundle is deterministic, externally plan-pinned, and closed", (t) => {
  const fixture = makeEdgeFixture(t);
  const first = renderFixture(fixture);
  assert.equal(first.manifest.approved_plan_sha256, approved(fixture.plan));
  assert.equal(first.manifest.deployment_profile, "edge-hetzner-v1");
  assert.deepEqual(
    first.manifest.artifacts.map((artifact) => artifact.target_path),
    first.manifest.artifacts.map((artifact) => artifact.target_path).sort(),
  );
  assert.deepEqual(Object.keys(first.manifest.hash_bindings).sort(), [
    "binary", "config", "hash_manifest", "policy", "secret",
  ]);
  assert.equal(first.request.units.length, 2);
  assert.equal(first.request.schema_version, 8);
  assert.equal(first.request.systemd_version, REVIEWED_SYSTEMD_VERSION);
  assert.deepEqual(first.request.busctl_unit_properties, [
    "After",
    "Before",
    "BindsTo",
    "Conditions",
    "Requires",
  ]);
  assert.deepEqual(first.request.busctl_manager_properties, ["ServiceWatchdogs", "Version"]);
  assert.deepEqual(first.request.busctl_service_properties, [
    "ExecStartEx",
    "ExecStartPreEx",
    "ImportCredential",
    "LoadCredential",
    "LoadCredentialEncrypted",
    "SetCredential",
    "SetCredentialEncrypted",
    "TimeoutStopUSec",
    "WatchdogTimestampMonotonic",
    "WatchdogUSec",
  ]);
  assert.equal(first.request.systemctl_show_properties.includes("Conditions"), false);
  for (const property of [
    "ImportCredential",
    "LoadCredential",
    "LoadCredentialEncrypted",
    "SetCredential",
    "SetCredentialEncrypted",
  ]) {
    assert.equal(first.request.systemctl_show_properties.includes(property), false);
  }
  assert.deepEqual(
    first.request.busctl_service_properties,
    RUNTIME_BUSCTL_SERVICE_PROPERTIES,
  );
  assert.deepEqual(
    first.request.runtime_paths.map(({ file_type, mode, target_path }) => ({ file_type, mode, target_path })),
    [
      { file_type: "directory", mode: "0750", target_path: "/run/bitcoinpir-source-fair-edge" },
      { file_type: "socket", mode: "0660", target_path: "/run/bitcoinpir-source-fair-edge/directory-public.sock" },
      { file_type: "socket", mode: "0660", target_path: "/run/bitcoinpir-source-fair-edge/directory-publisher.sock" },
      { file_type: "socket", mode: "0660", target_path: "/run/bitcoinpir-source-fair-edge/issuer.sock" },
      { file_type: "socket", mode: "0660", target_path: "/run/bitcoinpir-source-fair-edge/provider.sock" },
    ],
  );
  assert.equal(verifyFixture(fixture).manifestSha256, first.manifestSha256);
  const secondRoot = join(fixture.root, "second");
  const second = renderFixture(fixture, secondRoot);
  assert.equal(second.manifestSha256, first.manifestSha256);
  assert.deepEqual(
    readdirSync(fixture.bundleRoot, { recursive: true }).sort(),
    readdirSync(secondRoot, { recursive: true }).sort(),
  );
});

test("render plans and manifests fail closed on old schemas or another systemd build", (t) => {
  const oldPlan = makeEdgeFixture(t);
  oldPlan.plan.schema_version = 1;
  assert.throws(
    () => renderFixture(oldPlan),
    /render plan schema_version must equal 2/u,
  );

  const foreignPlan = makeEdgeFixture(t);
  foreignPlan.plan.systemd_version = "systemd 255 (255.4-1ubuntu8.16)";
  assert.throws(
    () => renderFixture(foreignPlan),
    /render plan systemd_version must equal systemd 255 \(255\.4-1ubuntu8\.15\)/u,
  );

  const model = renderFixture(makeEdgeFixture(t));
  const oldManifest = clone(model.manifest);
  oldManifest.schema_version = 1;
  assert.throws(
    () => runtimeRequestFromManifest(
      oldManifest,
      hashBytes(Buffer.from(canonicalJson(oldManifest))),
    ),
    /rendered manifest schema_version must equal 2/u,
  );

  const foreignManifest = clone(model.manifest);
  foreignManifest.systemd_version = "systemd 255 (255.4-1ubuntu8.16)";
  assert.throws(
    () => runtimeRequestFromManifest(
      foreignManifest,
      hashBytes(Buffer.from(canonicalJson(foreignManifest))),
    ),
    /rendered manifest systemd_version must equal systemd 255 \(255\.4-1ubuntu8\.15\)/u,
  );
});

test("service identities and numeric identity placeholders stay below systemd DynamicUser space", (t) => {
  for (const id of [60_001, 61_184, 65_519, 65_534]) {
    const fixture = makeEdgeFixture(t);
    fixture.plan.service_identities[0].uid = id;
    assert.throws(
      () => renderFixture(fixture),
      /static service uid\/gid.*DynamicUser/u,
    );
  }

  const placeholder = makeIssuerFixture(t);
  placeholder.plan.placeholders.ISSUER_UID = "61184";
  assert.throws(
    () => renderFixture(placeholder),
    /placeholder ISSUER_UID must be in \[1, 60000\]/u,
  );

  const manifestFixture = makeEdgeFixture(t);
  const model = renderFixture(manifestFixture);
  const manifest = clone(model.manifest);
  manifest.service_identities[0].gid = 65_534;
  assert.throws(
    () => runtimeRequestFromManifest(manifest, model.manifestSha256),
    /static service uid\/gid.*DynamicUser/u,
  );
});

test("directory publisher namespace profile renders, verifies, and emits its closed runtime request", (t) => {
  const fixture = makePublisherNetnsFixture(t);
  const model = renderFixture(fixture);
  assert.equal(model.manifest.deployment_profile, "directory-publisher-netns-v1");
  assert.equal(verifyFixture(fixture).manifestSha256, model.manifestSha256);
  assert.deepEqual(
    model.manifest.runtime_units.map(({ unit_name }) => unit_name),
    ["bitcoinpir-payment-v1-directory-publisher.service"],
  );
  assert.deepEqual(model.request.publisher_network, {
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
    network_policy_sha256: model.manifest.artifacts.find(
      ({ target_path }) =>
        target_path ===
        "/etc/bitcoinpir/payment-v1/directory-publisher/network-policy.json",
    ).rendered_sha256,
    publication_mode: {
      centralized: true,
      degraded: true,
      name: "centralized-single-relay",
    },
    publication_time_firewall_binding: {
      activation_blocked: true,
      implemented: false,
      point_in_time_evidence_only: true,
    },
    publisher_unit: "bitcoinpir-payment-v1-directory-publisher.service",
  });

  const missingPublicationGuard = makePublisherNetnsFixture(t);
  const publisherTemplate =
    "deploy/payment-v1/systemd/payment-v1-directory-publisher.service.in";
  const publisherTemplatePath = join(missingPublicationGuard.sourceRoot, publisherTemplate);
  const guardedBytes = readFileSync(publisherTemplatePath, "utf8");
  assert.match(
    guardedBytes,
    /^ConditionPathExists=\/etc\/bitcoinpir\/payment-v1\/PUBLISHER-FIREWALL-GENERATION-GUARD-IMPLEMENTED$/mu,
  );
  writeFileSync(
    publisherTemplatePath,
    guardedBytes.replace(
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/PUBLISHER-FIREWALL-GENERATION-GUARD-IMPLEMENTED\n",
      "",
    ),
  );
  missingPublicationGuard.plan.rendered_artifacts.find(
    ({ source_path: sourcePath }) => sourcePath === publisherTemplate,
  ).source_sha256 = hashFile(publisherTemplatePath);
  assert.throws(
    () => renderFixture(missingPublicationGuard),
    /must retain the exact global and profile-specific activation conditions/u,
  );

  for (const artifact of fixture.plan.rendered_artifacts) {
    const missing = makePublisherNetnsFixture(t);
    missing.plan.rendered_artifacts = missing.plan.rendered_artifacts.filter(
      ({ target_path }) => target_path !== artifact.target_path,
    );
    assert.throws(
      () => renderFixture(missing),
      /deployment profile templates|dependency is missing|references missing artifact/u,
      artifact.target_path,
    );
  }
  for (const artifact of fixture.plan.payload_artifacts) {
    const missing = makePublisherNetnsFixture(t);
    missing.plan.payload_artifacts = missing.plan.payload_artifacts.filter(
      ({ target_path }) => target_path !== artifact.target_path,
    );
    assert.throws(
      () => renderFixture(missing),
      /dependency is missing|references missing artifact/u,
      artifact.target_path,
    );
  }

  for (const id of [60_001, 62_900, 62_999, 65_534]) {
    const invalid = makePublisherNetnsFixture(t);
    invalid.plan.service_identities[0].uid = id;
    invalid.plan.service_identities[0].gid = id;
    assert.throws(() => renderFixture(invalid), /static service uid\/gid/u);
  }
});

test("integrated existing-Caddy profile closes and proves its HAProxy socket boundary", (t) => {
  const fixture = makeIntegratedCaddySourceFairFixture(t);
  const model = renderFixture(fixture);
  assert.equal(
    model.manifest.deployment_profile,
    "integrated-existing-bhtm-caddy-v1",
  );
  assert.deepEqual(
    model.manifest.runtime_units.map((unit) => unit.unit_name),
    ["bitcoinpir-payment-v1-source-fair-edge.service"],
  );
  assert.equal(
    model.manifest.artifacts.some(
      (artifact) =>
        artifact.source_path === CADDY_ADMIN_UDS_GATE &&
        artifact.target_path ===
          "/usr/local/libexec/bitcoinpir/payment-v1-caddy-admin-uds-gate.mjs",
    ),
    true,
  );
  assert.equal(
    model.manifest.artifacts.some(
      (artifact) =>
        artifact.source_path === CADDY_ADMIN_UDS_PROBE &&
        artifact.target_path ===
          "/usr/local/libexec/bitcoinpir/payment-v1-caddy-admin-uds-probe.mjs",
    ),
    true,
  );
  assert.deepEqual(
    model.request.runtime_paths.map(({ file_type, mode, target_path }) => ({
      file_type,
      mode,
      target_path,
    })),
    [
      {
        file_type: "directory",
        mode: "0750",
        target_path: "/run/bitcoinpir-source-fair-edge",
      },
      {
        file_type: "socket",
        mode: "0660",
        target_path: "/run/bitcoinpir-source-fair-edge/directory-public.sock",
      },
      {
        file_type: "socket",
        mode: "0660",
        target_path: "/run/bitcoinpir-source-fair-edge/directory-publisher.sock",
      },
      {
        file_type: "socket",
        mode: "0660",
        target_path: "/run/bitcoinpir-source-fair-edge/issuer.sock",
      },
      {
        file_type: "socket",
        mode: "0660",
        target_path: "/run/bitcoinpir-source-fair-edge/provider.sock",
      },
    ],
  );
  assert.equal(verifyFixture(fixture).manifestSha256, model.manifestSha256);

  for (const artifact of fixture.plan.payload_artifacts) {
    const changed = clone(fixture.plan);
    changed.payload_artifacts = changed.payload_artifacts.filter(
      (entry) => entry.target_path !== artifact.target_path,
    );
    assert.throws(
      () => renderBundle({
        approvedPlanSha256: approved(changed),
        inputRoot: fixture.inputRoot,
        outputRoot: join(
          fixture.root,
          `integrated-missing-${hashBytes(artifact.target_path).slice(0, 10)}`,
        ),
        plan: changed,
        sourceRoot: fixture.sourceRoot,
      }),
      /dependency is missing|references missing artifact/,
      artifact.target_path,
    );
  }
});

test("integrated admin gate rejects additional module dependencies", (t) => {
  const fixture = makeIntegratedCaddySourceFairFixture(t);
  const gatePath = join(fixture.sourceRoot, CADDY_ADMIN_UDS_GATE);
  writeFileSync(
    gatePath,
    readFileSync(gatePath, "utf8").replace(
      "export const PLAN_SCHEMA_VERSION = 2;",
      'await import("./unreviewed-gate-helper.mjs");\n\nexport const PLAN_SCHEMA_VERSION = 2;',
    ),
  );
  const gate = fixture.plan.rendered_artifacts.find(
    (artifact) => artifact.source_path === CADDY_ADMIN_UDS_GATE,
  );
  gate.source_sha256 = hashFile(gatePath);
  assert.throws(
    () => renderFixture(fixture),
    /gate does not equal its exact reviewed source/u,
  );
});

test("integrated overlay gate rejects added dependencies and semantic drift", (t) => {
  const fixture = makeIntegratedCaddySourceFairFixture(t);
  const gatePath = join(fixture.sourceRoot, INTEGRATED_CADDY_GATE);
  const original = readFileSync(gatePath, "utf8");
  const gate = fixture.plan.rendered_artifacts.find(
    (artifact) => artifact.source_path === INTEGRATED_CADDY_GATE,
  );
  for (const changed of [
    original.replace(
      "export const OVERLAY_PLAN_SCHEMA_VERSION = 2;",
      'await import/* comment */("./unreviewed-overlay-helper.mjs");\n\nexport const OVERLAY_PLAN_SCHEMA_VERSION = 2;',
    ),
    original.replace(
      'export const OVERLAY_PROFILE = "integrated-existing-bhtm-caddy-v1";',
      'export const OVERLAY_PROFILE = "unreviewed-overlay-profile";',
    ),
  ]) {
    writeFileSync(gatePath, changed);
    gate.source_sha256 = hashFile(gatePath);
    assert.throws(
      () => renderFixture(fixture),
      /overlay gate does not equal its exact reviewed source/u,
    );
  }
});

test("integrated admin probe closes its exact descriptor-input bootstrap", (t) => {
  const fixture = makeIntegratedCaddySourceFairFixture(t);
  const probePath = join(fixture.sourceRoot, CADDY_ADMIN_UDS_PROBE);
  writeFileSync(
    probePath,
    readFileSync(probePath, "utf8").replace(
      'import { createHash } from "node:crypto";',
      'import { createHash } from "node:unreviewed-crypto";',
    ),
  );
  const probe = fixture.plan.rendered_artifacts.find(
    (artifact) => artifact.source_path === CADDY_ADMIN_UDS_PROBE,
  );
  probe.source_sha256 = hashFile(probePath);
  assert.throws(
    () => renderFixture(fixture),
    /probe does not have its exact reviewed import header/u,
  );
});

test("integrated admin probe rejects comment-separated dynamic, same-line static, and export-from imports", (t) => {
  const fixture = makeIntegratedCaddySourceFairFixture(t);
  const probePath = join(fixture.sourceRoot, CADDY_ADMIN_UDS_PROBE);
  const expected = 'import { createHash } from "node:crypto";';
  const original = readFileSync(probePath, "utf8");
  const probe = fixture.plan.rendered_artifacts.find(
    (artifact) => artifact.source_path === CADDY_ADMIN_UDS_PROBE,
  );
  for (const injection of [
    'await import/* comment */("./dynamic-unreviewed.mjs");',
    '0; import staticUnreviewed from "./static-unreviewed.mjs";',
    'export { default as unreviewed } from "./export-unreviewed.mjs";',
  ]) {
    writeFileSync(
      probePath,
      original.replace(
        "const socketPath =",
        `// ${expected}\n${injection}\n\nconst socketPath =`,
      ),
    );
    probe.source_sha256 = hashFile(probePath);
    assert.throws(
      () => renderFixture(fixture),
      /probe does not equal its exact reviewed source/u,
      injection,
    );
  }
});

test("integrated cold executor rejects source drift even when the render-plan source hash is updated", (t) => {
  const fixture = makeIntegratedCaddySourceFairFixture(t);
  const executorPath = join(fixture.sourceRoot, CADDY_ADMIN_UDS_TRANSACTION);
  writeFileSync(
    executorPath,
    readFileSync(executorPath, "utf8").replace(
      'const SYSTEMD_VERSION = "255";',
      'const SYSTEMD_VERSION = "256";',
    ),
  );
  const executor = fixture.plan.rendered_artifacts.find(
    (artifact) => artifact.source_path === CADDY_ADMIN_UDS_TRANSACTION,
  );
  executor.source_sha256 = hashFile(executorPath);
  assert.throws(
    () => renderFixture(fixture),
    /cold transaction executor does not equal its exact reviewed source/u,
  );
});

test("integrated transaction closes both local gate imports", (t) => {
  const fixture = makeIntegratedCaddySourceFairFixture(t);
  const executorPath = join(fixture.sourceRoot, INTEGRATED_CADDY_TRANSACTION);
  const expected = 'from "./payment-v1-caddy-admin-uds-gate.mjs";';
  writeFileSync(
    executorPath,
    readFileSync(executorPath, "utf8")
      .replace(expected, 'from "./unreviewed-admin-gate.mjs";')
      .replace(
        "const MAX_FILE_BYTES =",
        `// ${expected}\nconst MAX_FILE_BYTES =`,
      ),
  );
  const executor = fixture.plan.rendered_artifacts.find(
    (artifact) => artifact.source_path === INTEGRATED_CADDY_TRANSACTION,
  );
  executor.source_sha256 = hashFile(executorPath);
  assert.throws(
    () => renderFixture(fixture),
    /transaction executor does not have its exact reviewed import header/u,
  );
});

test("integrated transaction helper digest must equal the render plan", (t) => {
  const fixture = makeIntegratedCaddySourceFairFixture(t);
  const executorPath = join(fixture.sourceRoot, INTEGRATED_CADDY_TRANSACTION);
  const managedBlockPath = join(fixture.sourceRoot, INTEGRATED_CADDY_BLOCK);
  const approvedDigest = fixture.plan.placeholders.OVERLAY_EXCHANGE_SHA256;
  const unreviewedDigest = `${approvedDigest[0] === "0" ? "1" : "0"}${approvedDigest.slice(1)}`;
  writeFileSync(
    executorPath,
    readFileSync(executorPath, "utf8").replace(
      "@OVERLAY_EXCHANGE_SHA256@",
      unreviewedDigest,
    ),
  );
  writeFileSync(
    managedBlockPath,
    `${readFileSync(managedBlockPath, "utf8")}# retain reviewed placeholder @OVERLAY_EXCHANGE_SHA256@\n`,
  );
  const executor = fixture.plan.rendered_artifacts.find(
    (artifact) => artifact.source_path === INTEGRATED_CADDY_TRANSACTION,
  );
  executor.source_sha256 = hashFile(executorPath);
  const managedBlock = fixture.plan.rendered_artifacts.find(
    (artifact) => artifact.source_path === INTEGRATED_CADDY_BLOCK,
  );
  managedBlock.source_sha256 = hashFile(managedBlockPath);
  assert.throws(
    () => renderFixture(fixture),
    /transaction executor helper digest differs from the render plan/u,
  );
});

for (const directive of [
  "StandardOutput",
  "StandardError",
  "LimitCORE",
  "MemorySwapMax",
]) {
  test(`integrated existing-Caddy HAProxy keeps ${directive} fail-closed`, (t) => {
    const fixture = makeIntegratedCaddySourceFairFixture(t);
    updateTemplate(fixture, SOURCE_FAIR_UNIT, (text) =>
      text.replace(
        `${directive}=${directive.startsWith("Standard") ? "null" : "0"}`,
        `${directive}=${directive.startsWith("Standard") ? "journal" : "infinity"}`,
      ),
    );
    assert.throws(
      () => renderFixture(fixture),
      new RegExp(`${directive}=|request-source state cannot persist`),
    );
  });
}

for (const [sourcePath, label] of [
  [EDGE_UNIT, "public Caddy edge"],
  [SOURCE_FAIR_UNIT, "source-fair HAProxy edge"],
]) {
  for (const directive of ["StandardOutput", "StandardError", "LimitCORE", "MemorySwapMax"]) {
    const expectedValue = directive.startsWith("Standard") ? "null" : "0";
    test(`edge profile keeps ${label} ${directive}=${expectedValue}`, (t) => {
      const fixture = makeEdgeFixture(t);
      updateTemplate(fixture, sourcePath, (text) =>
        text.replace(
          `${directive}=${expectedValue}`,
          `${directive}=${directive.startsWith("Standard") ? "journal" : "infinity"}`,
        ),
      );
      assert.throws(
        () => renderFixture(fixture),
        new RegExp(`${directive}=|request-source state cannot persist`),
      );
    });
  }
}

for (const directive of ["StandardOutput", "StandardError", "LimitCORE", "MemorySwapMax"]) {
  test(`rollback edge keeps ${directive} fail-closed`, (t) => {
    const fixture = makeRollbackEdgeFixture(t);
    updateTemplate(fixture, LEGACY_EDGE_UNIT, (text) =>
      text.replace(
        `${directive}=${directive.startsWith("Standard") ? "null" : "0"}`,
        `${directive}=${directive.startsWith("Standard") ? "journal" : "infinity"}`,
      ),
    );
    assert.throws(
      () => renderFixture(fixture),
      new RegExp(`${directive}=|request-source state cannot persist`),
    );
  });
}

test("rollback edge requires distinct private bind and sole-client addresses", (t) => {
  for (const [field, value, expected] of [
    ["ROLLBACK_AUTHORITY_PRIVATE_BIND", "198.51.100.8", /RFC1918|ULA/],
    ["ROLLBACK_AUTHORITY_CLIENT_IP", "198.51.100.9", /RFC1918|ULA/],
  ]) {
    const fixture = makeRollbackEdgeFixture(t);
    fixture.plan.placeholders[field] = value;
    assert.throws(() => renderFixture(fixture), expected);
  }
  const same = makeRollbackEdgeFixture(t);
  same.plan.placeholders.ROLLBACK_AUTHORITY_CLIENT_IP =
    same.plan.placeholders.ROLLBACK_AUTHORITY_PRIVATE_BIND;
  assert.throws(
    () => renderFixture(same),
    /private bind and sole-client addresses must differ/,
  );
});

test("Hetzner edge binds one distinct same-family private publisher client", (t) => {
  for (const field of [
    "DIRECTORY_PUBLISHER_PRIVATE_BIND",
    "DIRECTORY_PUBLISHER_CLIENT_IP",
  ]) {
    const publicAddress = makeEdgeFixture(t);
    publicAddress.plan.placeholders[field] = "198.51.100.9";
    assert.throws(() => renderFixture(publicAddress), /RFC1918|ULA/);
  }

  const sameAsBind = makeEdgeFixture(t);
  sameAsBind.plan.placeholders.DIRECTORY_PUBLISHER_CLIENT_IP =
    sameAsBind.plan.placeholders.DIRECTORY_PUBLISHER_PRIVATE_BIND;
  assert.throws(() => renderFixture(sameAsBind), /roles must use distinct addresses/);

  const sameAsPublic = makeEdgeFixture(t);
  sameAsPublic.plan.placeholders.PUBLIC_HTTPS_BIND =
    sameAsPublic.plan.placeholders.DIRECTORY_PUBLISHER_CLIENT_IP;
  assert.throws(() => renderFixture(sameAsPublic), /roles must use distinct addresses/);

  const mixedFamily = makeEdgeFixture(t);
  mixedFamily.plan.placeholders.DIRECTORY_PUBLISHER_CLIENT_IP = "fd23::6";
  assert.throws(() => renderFixture(mixedFamily), /same IP family/);
});

test("complete issuer profile closes core, guard, tmpfiles, preflight, issuer, and referenced files", (t) => {
  const fixture = makeIssuerFixture(t);
  const model = renderFixture(fixture);
  assert.equal(model.request.units.length, 4);
  assert.equal(model.request.tmpfiles_directories.length, 4);
  assert.deepEqual(model.request.tmpfiles_directories.find(
    (directory) => directory.target_path === "/srv/lightning/plugins",
  ), {
    group_name: "root",
    mode: "0555",
    target_path: "/srv/lightning/plugins",
    user_name: "root",
  });
  assert.deepEqual(model.request.tmpfiles_directories.find(
    (directory) => directory.target_path ===
      "/run/bitcoinpir-lightning-operator-approvals",
  ), {
    group_name: "root",
    mode: "0700",
    target_path: "/run/bitcoinpir-lightning-operator-approvals",
    user_name: "root",
  });
  assert.equal(model.manifest.deployment_profile, "issuer-lightning-signet-v1");
  const byName = new Map(model.request.units.map((unit) => [unit.unit_name, unit]));
  const loaderMapsCondition =
    "ConditionPathExists=/etc/bitcoinpir/payment-v1/CLN-LOADER-MAPS-APPROVED";
  assert.equal(
    byName.get("bitcoinpir-core-lightning.service").conditions.includes(
      loaderMapsCondition,
    ),
    false,
  );
  for (const unitName of [
    "bitcoinpir-lightning-preflight.service",
    "bitcoinpir-cln-rpc-guard.service",
    "bitcoinpir-payment-issuer.service",
  ]) {
    assert.equal(byName.get(unitName).conditions.includes(loaderMapsCondition), true);
  }
  assert.deepEqual(
    { ...byName.get("bitcoinpir-cln-rpc-guard.service").unit_dependencies },
    {
      After: [
        "bitcoinpir-core-lightning.service",
        "bitcoinpir-lightning-preflight.service",
      ],
      Before: ["bitcoinpir-payment-issuer.service"],
      BindsTo: [
        "bitcoinpir-core-lightning.service",
        "bitcoinpir-lightning-preflight.service",
      ],
      Requires: [
        "bitcoinpir-core-lightning.service",
        "bitcoinpir-lightning-preflight.service",
      ],
    },
  );
  assert.deepEqual(
    byName.get("bitcoinpir-lightning-preflight.service").unit_dependencies.Before,
    ["bitcoinpir-cln-rpc-guard.service", "bitcoinpir-payment-issuer.service"],
  );
  assert.equal(
    byName.get("bitcoinpir-payment-issuer.service").unit_dependencies.BindsTo.includes(
      "bitcoinpir-lightning-preflight.service",
    ),
    true,
  );
  const preflight = byName.get("bitcoinpir-lightning-preflight.service");
  const guard = byName.get("bitcoinpir-cln-rpc-guard.service");
  assert.deepEqual(preflight.exec_start_pre_ex[0], {
    argv: [
      "/usr/bin/unlink",
      "--",
      "/run/bitcoinpir-lightning-operator-approvals/preflight-generation-approved",
    ],
    flags: ["privileged"],
    path: "/usr/bin/unlink",
  });
  assert.deepEqual(guard.exec_start_pre_ex[0], {
    argv: [
      "/usr/bin/unlink",
      "--",
      "/run/bitcoinpir-lightning-operator-approvals/guard-generation-approved",
    ],
    flags: ["privileged"],
    path: "/usr/bin/unlink",
  });
  assert.equal(
    model.request.units.flatMap((unit) => unit.exec_start_pre_ex)
      .filter((command) => command.flags.includes("privileged")).length,
    2,
  );
  assert.equal(verifyFixture(fixture).manifestSha256, model.manifestSha256);
});

test("issuer profile keeps the CLN guard deadman non-restarting", (t) => {
  const fixture = makeIssuerFixture(t);
  updateTemplate(fixture, GUARD_UNIT, (text) =>
    text.replace("Restart=no", "Restart=on-failure\nRestartSec=5"),
  );
  assert.throws(() => renderFixture(fixture), /CLN guard deadman Restart=no/);
});

for (const [label, unitPath] of [
  ["guard", GUARD_UNIT],
  ["preflight", PREFLIGHT_UNIT],
]) {
  test(`issuer ${label} approval command is the sole privileged pre-start`, (t) => {
    const unprivileged = makeIssuerFixture(t);
    updateTemplate(unprivileged, unitPath, (text) =>
      text.replace("ExecStartPre=+/usr/bin/unlink", "ExecStartPre=/usr/bin/unlink"),
    );
    assert.throws(
      () => renderFixture(unprivileged),
      new RegExp(`exact privileged ${label} approval token`),
    );

    const extraPrivileged = makeIssuerFixture(t);
    updateTemplate(extraPrivileged, unitPath, (text) =>
      text.replace("ExecStartPre=/usr/bin/test", "ExecStartPre=+/usr/bin/test"),
    );
    assert.throws(
      () => renderFixture(extraPrivileged),
      /privileged ExecStartPre flags beyond the approval unlink/,
    );
  });
}

for (const directive of ["PrivateDevices", "ProtectClock", "ProtectHostname"]) {
  test(`provider profile keeps ${directive}=true`, (t) => {
    const fixture = makeProviderFixture(t);
    updateTemplate(fixture, PROVIDER_UNIT, (text) =>
      text.replace(`${directive}=true`, `${directive}=false`),
    );
    assert.throws(() => renderFixture(fixture), new RegExp(`provider ${directive}=true`));
  });
}

test("no-Standard-Cashu provider profile excludes mint custody material", (t) => {
  const fixture = makeProviderNoStandardCashuFixture(t);
  const model = renderFixture(fixture);
  const targets = model.manifest.artifacts.map((artifact) => artifact.target_path);
  const unit = readFileSync(
    join(
      fixture.bundleRoot,
      "files/etc/systemd/system/bitcoinpir-provider-no-standard-cashu.service",
    ),
    "utf8",
  );
  assert.doesNotMatch(
    unit,
    /--service-cashu-(?:recovery|custody|exposure)/u,
  );
  assert.equal(
    targets.some((target) => /cashu-(?:recovery|custody)/u.test(target)),
    false,
  );
  assert.deepEqual(
    Object.keys(fixture.plan.placeholders).filter((name) => name.startsWith("CASHU_")),
    [],
  );
  assert.match(unit, /--require-service-auth-v1/u);
  assert.match(unit, /--service-bat-key/u);
  assert.match(unit, /--service-shared-authorization/u);

  const expanded = clone(fixture.plan);
  expanded.payload_artifacts.push(addPayload(
    fixture,
    "/etc/bitcoinpir/payment-v1/provider-no-standard-cashu/cashu-custody-epoch-1.key",
    "forbidden-custody\n",
    99,
    { class: "secret", gid: 741, mode: "0400", uid: 740 },
  ));
  assert.throws(
    () => renderBundle({
      approvedPlanSha256: approved(expanded),
      inputRoot: fixture.inputRoot,
      outputRoot: join(fixture.root, "forbidden-custody-bundle"),
      plan: expanded,
      sourceRoot: fixture.sourceRoot,
    }),
    /provider-no-standard-cashu-v1 payload targets/,
  );
});

test("no-Standard-Cashu provider profile rejects reintroduced mint material", (t) => {
  const fixture = makeProviderNoStandardCashuFixture(t);
  updateTemplate(fixture, PROVIDER_NO_STANDARD_CASHU_UNIT, (text) =>
    text.replace(
      "    --max-connections 128",
      "    --service-cashu-exposure-limit 11:sat:1:1 \\\n    --max-connections 128",
    ),
  );
  assert.throws(
    () => renderFixture(fixture),
    /must not configure Standard Cashu custody, recovery or exposure material/,
  );
});

for (const [label, factory, unit, freeIpKey] of [
  [
    "provider-v1",
    makeProviderFixture,
    PROVIDER_UNIT,
    "/etc/bitcoinpir/payment-v1/provider/shared-redeem-idempotency.key",
  ],
  [
    "provider-no-standard-cashu-v1",
    makeProviderNoStandardCashuFixture,
    PROVIDER_NO_STANDARD_CASHU_UNIT,
    "/etc/bitcoinpir/payment-v1/provider-no-standard-cashu/shared-redeem-idempotency.key",
  ],
]) {
  for (const [route, flags] of [
    ["ARC", "--allow-experimental-arc"],
    [
      "Free-IP",
      `--service-free-ip-key ${freeIpKey} \\\n    --service-trust-direct-peer-ip`,
    ],
  ]) {
    test(`${label} rendered profile rejects ${route} adapter reintroduction`, (t) => {
      const fixture = factory(t);
      updateTemplate(fixture, unit, (text) => text.replace(
        "    --max-connections 128",
        `    ${flags} \\\n    --max-connections 128`,
      ));
      assert.throws(
        () => renderFixture(fixture),
        /must keep production ARC and Free-IP adapters unavailable/,
      );
    });
  }
}

test("checked-in no-Standard-Cashu skeleton is explicit and deliberately unusable", (t) => {
  const fixture = temporaryRoots(t);
  const plan = parseStrictJson(
    readFileSync(
      join(
        REPOSITORY,
        "docs/payment/render-plan-skeletons/provider-no-standard-cashu-v1.plan.json.example",
      ),
      "utf8",
    ),
    "no-Standard-Cashu skeleton",
  );
  assert.equal(plan.deployment_profile, "provider-no-standard-cashu-v1");
  assert.equal(
    plan.payload_artifacts.some((artifact) =>
      /cashu-(?:recovery|custody)/u.test(artifact.target_path)),
    false,
  );
  assert.deepEqual(
    Object.keys(plan.placeholders).filter((name) => name.startsWith("CASHU_")),
    [],
  );
  assert.throws(
    () => renderBundle({
      approvedPlanSha256: computeApprovedPlanSha256(plan),
      inputRoot: fixture.inputRoot,
      outputRoot: fixture.bundleRoot,
      plan,
      sourceRoot: REPOSITORY,
    }),
    /repository example marker|SHA-256|replacement marker/,
  );
});

test("direct provider profile carries no optional payment adapter material", (t) => {
  const fixture = makeProviderDirectFixture(t);
  const model = renderFixture(fixture);
  const targets = model.manifest.artifacts.map((artifact) => artifact.target_path);
  const unit = readFileSync(
    join(fixture.bundleRoot, "files/etc/systemd/system/bitcoinpir-provider-direct.service"),
    "utf8",
  );
  assert.doesNotMatch(
    unit,
    /--service-(?:bat-key|cashu-[a-z-]+|shared-[a-z-]+|arc-key|free-ip-key|trust-direct-peer-ip)|--allow-experimental-arc/u,
  );
  assert.equal(fixture.plan.payload_artifacts.length, 9);
  assert.equal(
    targets.some((target) =>
      /cashu|shared|clearing|idempotency/u.test(target)),
    false,
  );
  assert.deepEqual(
    Object.keys(fixture.plan.placeholders).sort(),
    [
      "HETZNER_POLICY_PUBKEY_HEX",
      "HETZNER_PROVIDER_ID_HEX",
      "HETZNER_PROVIDER_SERVER_ID",
      "UNIFIED_SERVER_SHA256",
    ],
  );
  assert.match(unit, /--require-service-auth-v1/u);
  assert.match(unit, /--service-remote-rollback-authority-config/u);

  const expanded = clone(fixture.plan);
  expanded.payload_artifacts.push(addPayload(
    fixture,
    "/etc/bitcoinpir/payment-v1/provider-direct/cashu-bat.key",
    "forbidden-bat\n",
    99,
    { class: "secret", gid: 741, mode: "0400", uid: 740 },
  ));
  assert.throws(
    () => renderBundle({
      approvedPlanSha256: approved(expanded),
      inputRoot: fixture.inputRoot,
      outputRoot: join(fixture.root, "forbidden-bat-bundle"),
      plan: expanded,
      sourceRoot: fixture.sourceRoot,
    }),
    /provider-direct-v1 payload targets/,
  );
});

test("direct provider profile rejects reintroduced optional adapters", (t) => {
  for (const [flag, expected] of [
    [
      "--service-bat-key /private/bat.key",
      /must keep BAT, Standard Cashu, shared issuer, ARC and Free-IP adapters unavailable/,
    ],
    [
      "--service-cashu-exposure-limit 11:sat:1:1",
      /must keep BAT, Standard Cashu, shared issuer, ARC and Free-IP adapters unavailable/,
    ],
    [
      "--service-shared-authorization /private/shared.bin",
      /must keep BAT, Standard Cashu, shared issuer, ARC and Free-IP adapters unavailable/,
    ],
    [
      "--allow-experimental-arc",
      /must keep production ARC and Free-IP adapters unavailable/,
    ],
    [
      "--service-free-ip-key /private/free-ip.key",
      /must keep production ARC and Free-IP adapters unavailable/,
    ],
  ]) {
    const fixture = makeProviderDirectFixture(t);
    updateTemplate(fixture, PROVIDER_DIRECT_UNIT, (text) => text.replace(
      "    --max-connections 128",
      `    ${flag} \\\n    --max-connections 128`,
    ));
    assert.throws(
      () => renderFixture(fixture),
      expected,
      flag,
    );
  }
});

for (const [profile, factory, unit, configRoot] of [
  [
    "provider-v1",
    makeProviderFixture,
    PROVIDER_UNIT,
    "/etc/bitcoinpir/payment-v1/provider",
  ],
  [
    "provider-no-standard-cashu-v1",
    makeProviderNoStandardCashuFixture,
    PROVIDER_NO_STANDARD_CASHU_UNIT,
    "/etc/bitcoinpir/payment-v1/provider-no-standard-cashu",
  ],
  [
    "provider-direct-v1",
    makeProviderDirectFixture,
    PROVIDER_DIRECT_UNIT,
    "/etc/bitcoinpir/payment-v1/provider-direct",
  ],
]) {
  test(`${profile} rendered unit rejects retained-policy configuration`, (t) => {
    const fixture = factory(t);
    updateTemplate(fixture, unit, (text) => text.replace(
      "    --max-connections 128",
      `    --service-retained-policy ${configRoot}/retained-policy.bin \\\n    --max-connections 128`,
    ));
    assert.throws(
      () => renderFixture(fixture),
      /zero-retained closed profile.*--service-retained-policy/,
    );
  });

  test(`${profile} render plan rejects retained-policy payload material`, (t) => {
    const fixture = factory(t);
    fixture.plan.payload_artifacts.push(addPayload(
      fixture,
      `${configRoot}/retained-policy.bin`,
      "retained-policy\n",
      99,
    ));
    assert.throws(
      () => renderFixture(fixture),
      /zero-retained closed profile.*retained-policy payload material/,
    );
  });
}

test("checked-in direct provider skeleton is explicit and deliberately unusable", (t) => {
  const fixture = temporaryRoots(t);
  const plan = parseStrictJson(
    readFileSync(
      join(REPOSITORY, "docs/payment/render-plan-skeletons/provider-direct-v1.plan.json.example"),
      "utf8",
    ),
    "direct provider skeleton",
  );
  assert.equal(plan.deployment_profile, "provider-direct-v1");
  assert.equal(plan.payload_artifacts.length, 9);
  assert.equal(
    plan.payload_artifacts.some((artifact) =>
      /cashu|shared|clearing|idempotency/u.test(artifact.target_path)),
    false,
  );
  assert.throws(
    () => renderBundle({
      approvedPlanSha256: computeApprovedPlanSha256(plan),
      inputRoot: fixture.inputRoot,
      outputRoot: fixture.bundleRoot,
      plan,
      sourceRoot: REPOSITORY,
    }),
    /repository example marker|SHA-256|replacement marker/,
  );
});

test("checked-in resolved directory-relay skeleton is explicit and deliberately unusable", (t) => {
  const fixture = temporaryRoots(t);
  const plan = parseStrictJson(
    readFileSync(
      join(REPOSITORY, "docs/payment/render-plan-skeletons/directory-relay-v1.plan.json.example"),
      "utf8",
    ),
    "resolved directory-relay skeleton",
  );
  const binarySha256 =
    "77571e6266ca2908483d7172d0cf5c542c16f818dad09767426439f0358e7eb8";
  const binaryTarget =
    `/opt/bitcoinpir/directory-relay/${binarySha256}/bitcoinpir-directory-relay`;
  assert.equal(plan.deployment_profile, "directory-relay-v1");
  assert.deepEqual(Object.keys(plan.placeholders), []);
  assert.deepEqual(
    plan.payload_artifacts.map((artifact) => artifact.target_path),
    [
      "/etc/bitcoinpir/payment-v1/directory-relay/binary.sha256",
      "/etc/bitcoinpir/payment-v1/directory-relay/config.sha256",
      binaryTarget,
    ],
  );
  assert.equal(plan.payload_artifacts[2].expected_sha256, binarySha256);
  assert.equal(
    plan.payload_artifacts.some((artifact) =>
      /private|secret|publisher.*key/iu.test(`${artifact.source_path}\n${artifact.target_path}`)),
    false,
  );
  assert.throws(
    () => renderBundle({
      approvedPlanSha256: computeApprovedPlanSha256(plan),
      inputRoot: fixture.inputRoot,
      outputRoot: fixture.bundleRoot,
      plan,
      sourceRoot: REPOSITORY,
    }),
    /repository example marker|SHA-256|replacement marker/,
  );
});

for (const [label, factory, profile] of [
  ["stopped directory relay", makeDirectoryRelayFixture, "directory-relay-v1"],
  ["resolved directory relay", makeResolvedDirectoryRelayFixture, "directory-relay-v1"],
  ["provider", makeProviderFixture, "provider-v1"],
  [
    "provider without Standard Cashu",
    makeProviderNoStandardCashuFixture,
    "provider-no-standard-cashu-v1",
  ],
  ["direct provider", makeProviderDirectFixture, "provider-direct-v1"],
  ["rollback authority", makeRollbackFixture, "rollback-authority-v1"],
  ["rollback edge", makeRollbackEdgeFixture, "edge-rollback-authority-v1"],
]) {
  test(`${label} deployment profile is renderable and dependency-closed`, (t) => {
    const fixture = factory(t);
    const model = renderFixture(fixture);
    assert.equal(model.manifest.deployment_profile, profile);
    assert.equal(verifyFixture(fixture).manifestSha256, model.manifestSha256);
    for (const artifact of fixture.plan.payload_artifacts) {
      const changed = clone(fixture.plan);
      changed.payload_artifacts = changed.payload_artifacts.filter(
        (entry) => entry.target_path !== artifact.target_path,
      );
      assert.throws(
        () => renderBundle({
          approvedPlanSha256: approved(changed),
          inputRoot: fixture.inputRoot,
          outputRoot: join(fixture.root, `missing-${hashBytes(artifact.target_path).slice(0, 10)}`),
          plan: changed,
          sourceRoot: fixture.sourceRoot,
        }),
        /dependency is missing|references missing artifact|resolved directory-relay-v1 payload targets|provider-(?:v1|no-standard-cashu-v1|direct-v1) payload targets/,
        artifact.target_path,
      );
    }
  });
}

test("directory relay profile renders only blocked unit and bounded config", (t) => {
  const fixture = makeDirectoryRelayFixture(t);
  const model = renderFixture(fixture);
  assert.equal(model.manifest.deployment_profile, "directory-relay-v1");
  assert.deepEqual(
    model.manifest.artifacts.map((artifact) => artifact.target_path),
    [
      "/etc/bitcoinpir/payment-v1/directory-relay/config.toml",
      "/etc/systemd/system/bitcoinpir-directory-relay.service",
    ],
  );
  assert.equal(model.request.units.length, 1);
  assert.equal(model.request.units[0].exec_start[0], "/usr/bin/false");
  assert.deepEqual(model.request.units[0].exec_start_pre, []);
  assert.deepEqual(model.request.units[0].hardening.ProtectProc, ["invisible"]);
  assert.deepEqual(model.request.units[0].hardening.ProcSubset, ["pid"]);
  assert.deepEqual(model.request.runtime_paths, []);
  assert.deepEqual(model.request.secret_files, [{
    consumer_unit_name: "bitcoinpir-directory-relay.service",
    gid: 52952,
    mode: "0400",
    target_path: "/etc/bitcoinpir/payment-v1/directory-relay/config.toml",
    uid: 52951,
  }]);
  assert.equal(verifyFixture(fixture).manifestSha256, model.manifestSha256);
});

test("directory relay profile rejects activation, pre-start commands, weak hardening and payload smuggling", (t) => {
  const active = makeDirectoryRelayFixture(t);
  updateTemplate(active, RELAY_UNIT, (text) => text.replace("ExecStart=/usr/bin/false", "ExecStart=/usr/bin/true"));
  assert.throws(() => renderFixture(active), /exact blocked unit or exact resolved unit/);

  const preStart = makeDirectoryRelayFixture(t);
  updateTemplate(preStart, RELAY_UNIT, (text) => text.replace("ExecStart=/usr/bin/false", "ExecStartPre=/usr/bin/true\nExecStart=/usr/bin/false"));
  assert.throws(() => renderFixture(preStart), /exact blocked unit or exact resolved unit/);

  const journal = makeDirectoryRelayFixture(t);
  updateTemplate(journal, RELAY_UNIT, (text) => text.replace("StandardOutput=null", "StandardOutput=journal"));
  assert.throws(() => renderFixture(journal), /StandardOutput=null/);

  const visibleProc = makeDirectoryRelayFixture(t);
  updateTemplate(visibleProc, RELAY_UNIT, (text) =>
    text.replace("ProtectProc=invisible", "ProtectProc=default"));
  assert.throws(() => renderFixture(visibleProc), /ProtectProc=invisible/);

  const fullProc = makeDirectoryRelayFixture(t);
  updateTemplate(fullProc, RELAY_UNIT, (text) =>
    text.replace("ProcSubset=pid", "ProcSubset=all"));
  assert.throws(() => renderFixture(fullProc), /ProcSubset=pid/);

  const payload = makeDirectoryRelayFixture(t);
  payload.plan.payload_artifacts.push(addPayload(
    payload,
    "/etc/bitcoinpir/payment-v1/directory-relay/unreviewed.toml",
    "unreviewed\n",
    0,
    { class: "config", gid: 751, mode: "0440", uid: 0 },
  ));
  assert.throws(
    () => renderFixture(payload),
    /must not contain payload artifacts|not reachable from the closed deployment profile/,
  );
});

test("resolved directory relay binds selection, binary, manifests, config and unit", (t) => {
  const fixture = makeResolvedDirectoryRelayFixture(t);
  const model = renderFixture(fixture);
  const binary = fixture.plan.payload_artifacts.find((artifact) => artifact.class === "binary");
  assert.deepEqual(
    model.manifest.artifacts.map((artifact) => artifact.target_path),
    [
      "/etc/bitcoinpir/payment-v1/directory-relay/binary.sha256",
      "/etc/bitcoinpir/payment-v1/directory-relay/config.sha256",
      "/etc/bitcoinpir/payment-v1/directory-relay/config.toml",
      "/etc/systemd/system/bitcoinpir-directory-relay.service",
      binary.target_path,
    ],
  );
  assert.match(model.request.units[0].exec_start[0], new RegExp(`^${binary.target_path}`));
  assert.deepEqual(model.request.units[0].exec_start_pre, [
    "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/directory-relay/binary.sha256",
    "/usr/bin/sha256sum --check --strict /etc/bitcoinpir/payment-v1/directory-relay/config.sha256",
  ]);
  assert.deepEqual(model.request.units[0].hardening.ProtectProc, ["invisible"]);
  assert.deepEqual(model.request.units[0].hardening.ProcSubset, ["pid"]);
  assert.equal(verifyFixture(fixture).manifestSha256, model.manifestSha256);
});

test("resolved directory relay rejects selection and hash-manifest drift", (t) => {
  const selectionDrift = makeResolvedDirectoryRelayFixture(t);
  selectionDrift.plan.relay_selection_sha256 = "f".repeat(64);
  assert.throws(() => renderFixture(selectionDrift), /selection source hash/);

  const binaryManifest = makeResolvedDirectoryRelayFixture(t);
  const manifest = binaryManifest.plan.payload_artifacts.find((artifact) =>
    artifact.target_path.endsWith("/binary.sha256"));
  writeFileSync(
    join(binaryManifest.inputRoot, manifest.source_path),
    `${"a".repeat(64)}  /opt/bitcoinpir/directory-relay/${"a".repeat(64)}/bitcoinpir-directory-relay\n`,
  );
  manifest.expected_sha256 = hashFile(join(binaryManifest.inputRoot, manifest.source_path));
  assert.throws(
    () => renderFixture(binaryManifest),
    /does not bind exactly|wrong digest|references missing artifact/,
  );

  const privateKey = makeResolvedDirectoryRelayFixture(t);
  privateKey.plan.payload_artifacts.push(addPayload(
    privateKey,
    "/etc/bitcoinpir/payment-v1/directory-relay/publisher-private.key",
    "forbidden\n",
    9,
    { class: "secret", gid: 52952, mode: "0400", uid: 52951 },
  ));
  assert.throws(() => renderFixture(privateKey), /payload targets/);
});

test("directory relay config is bound to the real loader's exact owner-only metadata", (t) => {
  for (const [mutate, expected] of [
    [(artifact) => { artifact.uid = 0; }, /0400 for one owner|relay-owned UID 52951/u],
    [(artifact) => { artifact.gid = 0; }, /relay-owned UID 52951 GID 52952 mode 0400/u],
    [(artifact) => { artifact.mode = "0440"; }, /mode must be one of \["0400"\]|relay-owned UID 52951 GID 52952 mode 0400/u],
  ]) {
    const fixture = makeDirectoryRelayFixture(t);
    mutate(fixture.plan.rendered_artifacts[0]);
    assert.throws(() => renderFixture(fixture), expected);
  }
});

test("Hetzner edge rejects deletion of every template and payload dependency", (t) => {
  const fixture = makeEdgeFixture(t);
  for (const sourcePath of [EDGE_UNIT, EDGE_CONFIG]) {
    const changed = clone(fixture.plan);
    changed.rendered_artifacts = changed.rendered_artifacts.filter(
      (entry) => entry.source_path !== sourcePath,
    );
    assert.throws(
      () => renderBundle({ approvedPlanSha256: approved(changed), inputRoot: fixture.inputRoot, outputRoot: join(fixture.root, `missing-${basename(sourcePath)}`), plan: changed, sourceRoot: fixture.sourceRoot }),
      /deployment profile templates/,
    );
  }
  for (const artifact of fixture.plan.payload_artifacts) {
    const changed = clone(fixture.plan);
    changed.payload_artifacts = changed.payload_artifacts.filter(
      (entry) => entry.target_path !== artifact.target_path,
    );
    assert.throws(
      () => renderBundle({ approvedPlanSha256: approved(changed), inputRoot: fixture.inputRoot, outputRoot: join(fixture.root, `missing-${hashBytes(artifact.target_path).slice(0, 10)}`), plan: changed, sourceRoot: fixture.sourceRoot }),
      /dependency is missing|references missing artifact/,
    );
  }
});

test("issuer profile rejects deletion of every template dependency", (t) => {
  const fixture = makeIssuerFixture(t);
  for (const sourcePath of ISSUER_TEMPLATES) {
    const changed = clone(fixture.plan);
    changed.rendered_artifacts = changed.rendered_artifacts.filter((entry) => entry.source_path !== sourcePath);
    assert.throws(
      () => renderBundle({ approvedPlanSha256: approved(changed), inputRoot: fixture.inputRoot, outputRoot: join(fixture.root, `missing-template-${basename(sourcePath)}`), plan: changed, sourceRoot: fixture.sourceRoot }),
      /deployment profile templates/,
      sourcePath,
    );
  }
});

test("issuer profile rejects deletion of every referenced payload dependency", (t) => {
  const fixture = makeIssuerFixture(t);
  for (const artifact of fixture.plan.payload_artifacts) {
    const changed = clone(fixture.plan);
    changed.payload_artifacts = changed.payload_artifacts.filter((entry) => entry.target_path !== artifact.target_path);
    assert.throws(
      () => renderBundle({ approvedPlanSha256: approved(changed), inputRoot: fixture.inputRoot, outputRoot: join(fixture.root, `missing-payload-${hashBytes(artifact.target_path).slice(0, 12)}`), plan: changed, sourceRoot: fixture.sourceRoot }),
      /dependency is missing|references missing artifact|remote rollback .* payload is missing|missing its static preflight config/,
      artifact.target_path,
    );
  }
});

for (const [profile, factory, configRoot] of [
  ["issuer-lightning-signet-v1", makeIssuerFixture, "/etc/bitcoinpir/payment-v1/issuer"],
  ["provider-v1", makeProviderFixture, "/etc/bitcoinpir/payment-v1/provider"],
  [
    "provider-no-standard-cashu-v1",
    makeProviderNoStandardCashuFixture,
    "/etc/bitcoinpir/payment-v1/provider-no-standard-cashu",
  ],
  ["provider-direct-v1", makeProviderDirectFixture, "/etc/bitcoinpir/payment-v1/provider-direct"],
]) {
  test(`${profile} binds the complete owner-only remote rollback secret closure`, (t) => {
    const configTarget = `${configRoot}/remote-rollback-authority.toml`;
    const signingTarget = `${configRoot}/remote-rollback-client-signing.seed`;
    const valueTarget = `${configRoot}/remote-rollback-value-root.key`;

    const valid = factory(t);
    const model = renderFixture(valid);
    assert.deepEqual(
      model.request.secret_files
        .map((entry) => entry.target_path)
        .filter((target) => target.startsWith(`${configRoot}/remote-rollback`))
        .sort(),
      [configTarget, signingTarget, valueTarget].sort(),
    );

    const publicConfig = factory(t);
    const publicConfigArtifact = publicConfig.plan.payload_artifacts.find(
      (entry) => entry.target_path === configTarget,
    );
    publicConfigArtifact.class = "config";
    assert.throws(
      () => renderFixture(publicConfig),
      /target-derived class secret/,
    );

    const groupReadableConfig = factory(t);
    const groupReadableArtifact = groupReadableConfig.plan.payload_artifacts.find(
      (entry) => entry.target_path === configTarget,
    );
    groupReadableArtifact.uid = 0;
    groupReadableArtifact.mode = "0440";
    assert.throws(
      () => renderFixture(groupReadableConfig),
      /secret must be owned exclusively by/,
    );

    for (const missingTarget of [configTarget, signingTarget, valueTarget]) {
      const missing = factory(t);
      missing.plan.payload_artifacts = missing.plan.payload_artifacts.filter(
        (entry) => entry.target_path !== missingTarget,
      );
      assert.throws(
        () => renderFixture(missing),
        /remote rollback .* payload is missing|provider-(?:v1|no-standard-cashu-v1|direct-v1) payload targets/,
        missingTarget,
      );
    }

    for (const [label, mutate, expected] of [
      [
        "wrong signing path",
        (text) => text.replace(signingTarget, `${configRoot}/wrong-signing.seed`),
        /must bind exact client_signing_seed_path=/,
      ],
      [
        "wrong value-root path",
        (text) => text.replace(valueTarget, `${configRoot}/wrong-value-root.key`),
        /must bind exact value_root_key_path=/,
      ],
      [
        "duplicate signing path",
        (text) => `${text}client_signing_seed_path = "${signingTarget}"\n`,
        /must bind exact client_signing_seed_path=/,
      ],
      [
        "non-canonical newlines",
        (text) => text.replaceAll("\n", "\r\n"),
        /must use canonical LF text/,
      ],
    ]) {
      const malformed = factory(t);
      updatePayload(malformed, configTarget, mutate);
      assert.throws(() => renderFixture(malformed), expected, label);
    }
  });
}

test("profile rejects extra, stale, and cross-profile targets", (t) => {
  const extra = makeEdgeFixture(t);
  extra.plan.payload_artifacts.push(addPayload(extra, "/etc/bitcoinpir/payment-v1/edge/old.conf", "old\n", 99));
  assert.throws(() => renderFixture(extra), /not reachable from the closed deployment profile/);

  const stale = makeEdgeFixture(t);
  stale.plan.payload_artifacts[0].target_path = "/opt/bitcoinpir/caddy/old/caddy";
  assert.throws(() => renderFixture(stale), /CADDY_SHA256 must select|dependency is missing|references missing artifact/);

  const crossed = makeEdgeFixture(t);
  crossed.plan.deployment_profile = "edge-rollback-authority-v1";
  assert.throws(() => renderFixture(crossed), /deployment profile templates|must select rollback/);
});

test("approved plan digest is external, mandatory, and cannot self-authorize", (t) => {
  const fixture = makeEdgeFixture(t);
  assert.throws(
    () => renderBundle({ inputRoot: fixture.inputRoot, outputRoot: fixture.bundleRoot, plan: fixture.plan, sourceRoot: fixture.sourceRoot }),
    /externally approved plan SHA-256/,
  );
  assert.throws(
    () => renderBundle({ approvedPlanSha256: "1".repeat(64), inputRoot: fixture.inputRoot, outputRoot: fixture.bundleRoot, plan: fixture.plan, sourceRoot: fixture.sourceRoot }),
    /does not match the externally approved/,
  );
  fixture.plan.approved_plan_sha256 = approved(fixture.plan);
  assert.throws(() => renderFixture(fixture), /render plan keys must equal/);
});

for (const [directive, value] of [
  ["ExecStartPost", "/usr/bin/true"],
  ["ExecCondition", "/usr/bin/true"],
  ["EnvironmentFile", "/tmp/evil.env"],
  ["ImportCredential", "secret.*"],
  ["LoadCredential", "secret:/tmp/secret"],
  ["LoadCredentialEncrypted", "secret:/tmp/secret"],
  ["SetCredential", "secret:evil"],
  ["SetCredentialEncrypted", "secret:evil"],
  ["BindPaths", "/tmp:/etc"],
  ["BindReadOnlyPaths", "/tmp:/etc"],
  ["RootDirectory", "/tmp/root"],
  ["RootImage", "/tmp/root.img"],
  ["RootHash", "abc"],
  ["RootHashSignature", "/tmp/sig"],
  ["ExecStartPre", "+/usr/bin/true"],
]) {
  test(`systemd closed directive schema rejects ${directive}`, (t) => {
    const fixture = makeEdgeFixture(t);
    updateTemplate(fixture, EDGE_UNIT, (text) => text.replace("[Service]\n", `[Service]\n${directive}=${value}\n`));
    assert.throws(() => renderFixture(fixture), /closed-world forbidden directive|literal absolute executable/);
  });
}

for (const [label, mutation, expected] of [
  ["dollar expansion", (text) => text.replace("ExecStart=", "ExecStart=/usr/bin/echo $HOME\nExecStart="), /variable expansion/],
  ["percent expansion", (text) => text.replace("Description=", "Description=%n "), /percent specifier/],
  ["ExecStart reset", (text) => text.replace("\nExecStart=", "\nExecStart=\nExecStart="), /empty ExecStart= reset/],
  ["condition reset", (text) => text.replace("ConditionPathExists=/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED", "ConditionPathExists=\nConditionPathExists=/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED"), /empty ConditionPathExists= reset/],
]) {
  test(`systemd rejects ${label}`, (t) => {
    const fixture = makeEdgeFixture(t);
    updateTemplate(fixture, EDGE_UNIT, mutation);
    assert.throws(() => renderFixture(fixture), expected);
  });
}

test("payload class and target metadata are target-derived and secrets cannot be 0644", (t) => {
  const fixture = makeIssuerFixture(t);
  const secret = fixture.plan.payload_artifacts.find((entry) => entry.class === "secret");
  secret.mode = "0644";
  assert.throws(() => renderFixture(fixture), /0400 for one owner|secret must never/);

  const groupReadable = makeIssuerFixture(t);
  const issuerSecret = groupReadable.plan.payload_artifacts.find((entry) => entry.class === "secret");
  Object.assign(issuerSecret, { gid: 732, mode: "0440", uid: 0 });
  assert.throws(() => renderFixture(groupReadable), /owned exclusively by bitcoinpir-payment-issuer/);

  const crossRoleOwner = makeIssuerFixture(t);
  const guardOwnedSecret = crossRoleOwner.plan.payload_artifacts.find((entry) => entry.class === "secret");
  Object.assign(guardOwnedSecret, { gid: 734, mode: "0400", uid: 735 });
  assert.throws(() => renderFixture(crossRoleOwner), /owned exclusively by bitcoinpir-payment-issuer/);

  const wrongProviderOwner = makeProviderFixture(t);
  wrongProviderOwner.plan.payload_artifacts.find((entry) => entry.class === "secret").uid = 999;
  assert.throws(() => renderFixture(wrongProviderOwner), /owned exclusively by bitcoinpir-provider/);

  const wrongClass = makeEdgeFixture(t);
  wrongClass.plan.payload_artifacts[0].class = "config";
  assert.throws(() => renderFixture(wrongClass), /target-derived class binary|outside the reviewed config prefixes/);

  const wrongBinaryOwner = makeEdgeFixture(t);
  wrongBinaryOwner.plan.payload_artifacts[0].uid = 730;
  assert.throws(() => renderFixture(wrongBinaryOwner), /binary must be immutable root:root mode 0555/);

  const wrongManifestMode = makeEdgeFixture(t);
  wrongManifestMode.plan.payload_artifacts.find((entry) => entry.class === "hash-manifest").mode = "0644";
  assert.throws(() => renderFixture(wrongManifestMode), /hash manifest must be immutable root:root mode 0444/);
});

test("issuer Lightning preflight config and dynamic receipt ownership are closed", (t) => {
  for (const [field, value] of [
    ["uid", 737],
    ["gid", 734],
    ["mode", "0400"],
  ]) {
    const fixture = makeIssuerFixture(t);
    const config = fixture.plan.payload_artifacts.find(
      (entry) => entry.target_path === "/etc/bitcoinpir/payment-v1/lightning/preflight.toml",
    );
    config[field] = value;
    assert.throws(
      () => renderFixture(fixture),
      /preflight config must be root:PREFLIGHT_GID mode 0440|0400 for one owner/,
    );
  }

  for (const mutation of [
    (text) => text.replace('/usr/bin/busctl', '/usr/local/bin/busctl'),
    (text) => text.replace('expected_uid = 0', 'expected_uid = 737'),
    (text) => text.replace(
      /sha256_hex = "[0-9a-f]{64}"/u,
      `sha256_hex = "${"1".repeat(64)}"`,
    ),
    (text) => `${text}\n[systemd.busctl]\npath = "/usr/bin/busctl"\n`,
  ]) {
    const fixture = makeIssuerFixture(t);
    updatePayload(
      fixture,
      "/etc/bitcoinpir/payment-v1/lightning/preflight.toml",
      mutation,
    );
    assert.throws(
      () => renderFixture(fixture),
      /must contain exactly one \[systemd\.busctl\] table|must bind the exact render-plan BUSCTL_SHA256/,
    );
  }

  const staticReceipt = makeIssuerFixture(t);
  staticReceipt.plan.payload_artifacts.push(addPayload(
    staticReceipt,
    "/etc/bitcoinpir/payment-v1/lightning/backup-receipt.toml",
    "schema_version = 1\n",
    999,
    { class: "policy", gid: 736, mode: "0440", uid: 0 },
  ));
  assert.throws(
    () => renderFixture(staticReceipt),
    /backup receipt is dynamic StateDirectory data/,
  );

  for (const [mutation, expected] of [
    [
      (text) => text.replace("StateDirectoryMode=0700", "StateDirectoryMode=0750"),
      /StateDirectoryMode=0700/,
    ],
    [
      (text) => text.replace(" /var/lib/bitcoinpir-lightning-preflight", ""),
      /mount the preflight StateDirectory read-only/,
    ],
    [
      (text) => text.replace(" /run/systemd/units", ""),
      /mount the systemd invocation map read-only/,
    ],
    [
      (text) => text.replace(
        "ReadWritePaths=/run/bitcoinpir-lightning-preflight",
        "ReadWritePaths=/run",
      ),
      /expose only lease state and the root-only approval parent as writable/,
    ],
    [
      (text) => text.replace("Type=notify", "Type=oneshot"),
      /Type=notify/,
    ],
    [
      (text) => text.replace("WatchdogSec=90", "WatchdogSec=0"),
      /WatchdogSec=90/,
    ],
    [
      (text) => text.replace("preflight-supervisor", "preflight"),
      /invocation-bound preflight supervisor/,
    ],
    [
      (text) => text.replace("--config-expected-uid 0", "--config-expected-uid 737"),
      /--config-expected-uid 0|bind --config-expected-uid to 0/,
    ],
  ]) {
    const fixture = makeIssuerFixture(t);
    updateTemplate(
      fixture,
      "deploy/payment-v1/systemd/hetzner-lightning-preflight.service.in",
      mutation,
    );
    assert.throws(() => renderFixture(fixture), expected);
  }

  const rendered = renderFixture(makeIssuerFixture(t));
  const manifest = structuredClone(rendered.manifest);
  const unit = manifest.runtime_units.find(
    (entry) => entry.unit_name === "bitcoinpir-lightning-preflight.service",
  );
  unit.exec_start[0] = unit.exec_start[0].replace(
    "--config-reader-expected-uid 737",
    "--config-reader-expected-uid 738",
  );
  const readerUidIndex = unit.exec_start_ex[0].argv.indexOf("737");
  assert.notEqual(readerUidIndex, -1);
  unit.exec_start_ex[0].argv[readerUidIndex] = "738";
  assert.throws(
    () => runtimeRequestFromManifest(manifest, hashBytes(Buffer.from(canonicalJson(manifest)))),
    /bind --config-reader-expected-uid to 737/,
  );
});

test("hash manifests are strict, sorted, complete, and bind actual artifacts", (t) => {
  const wrong = makeEdgeFixture(t);
  const manifest = wrong.plan.payload_artifacts.find((entry) => entry.target_path.endsWith("caddy.sha256"));
  writeFileSync(join(wrong.inputRoot, manifest.source_path), `${"1".repeat(64)}  ${wrong.targets.caddyBinary}\n`);
  manifest.expected_sha256 = hashFile(join(wrong.inputRoot, manifest.source_path));
  assert.throws(() => renderFixture(wrong), /wrong digest/);

  const malformed = makeEdgeFixture(t);
  const second = malformed.plan.payload_artifacts.find((entry) => entry.target_path.endsWith("caddy.sha256"));
  writeFileSync(join(malformed.inputRoot, second.source_path), `${hashBytes("x")} *${malformed.targets.caddyBinary}\n`);
  second.expected_sha256 = hashFile(join(malformed.inputRoot, second.source_path));
  assert.throws(() => renderFixture(malformed), /strict sha256sum syntax/);

  const smuggled = makeEdgeFixture(t);
  const smuggledTarget = "/etc/bitcoinpir/payment-v1/edge/old.conf";
  const smuggledPayload = addPayload(smuggled, smuggledTarget, "old\n", 99);
  smuggled.plan.payload_artifacts.push(smuggledPayload);
  const scoped = smuggled.plan.payload_artifacts.find((entry) => entry.target_path.endsWith("caddy.sha256"));
  const original = readFileSync(join(smuggled.inputRoot, scoped.source_path), "utf8").trimEnd();
  writeFileSync(
    join(smuggled.inputRoot, scoped.source_path),
    `${hashBytes("old\n")}  ${smuggledTarget}\n${original}\n`,
  );
  scoped.expected_sha256 = hashFile(join(smuggled.inputRoot, scoped.source_path));
  assert.throws(() => renderFixture(smuggled), /must bind only/);

  const unsorted = makeIssuerFixture(t);
  const clnManifest = unsorted.plan.payload_artifacts.find((entry) =>
    entry.target_path.endsWith("/cln-bundle.sha256"),
  );
  const clnPath = join(unsorted.inputRoot, clnManifest.source_path);
  const reversed = readFileSync(clnPath, "utf8").trimEnd().split("\n").reverse().join("\n");
  writeFileSync(clnPath, `${reversed}\n`);
  clnManifest.expected_sha256 = hashFile(clnPath);
  assert.throws(() => renderFixture(unsorted), /bytewise ASCII sorted/);

  const incompleteCln = makeIssuerFixture(t);
  const incompleteManifest = incompleteCln.plan.payload_artifacts.find((entry) =>
    entry.target_path.endsWith("/cln-bundle.sha256"),
  );
  const incompletePath = join(incompleteCln.inputRoot, incompleteManifest.source_path);
  const withoutHsmd = readFileSync(incompletePath, "utf8")
    .split("\n")
    .filter((line) => !line.endsWith("/libexec/c-lightning/lightning_hsmd"))
    .join("\n");
  writeFileSync(incompletePath, withoutHsmd);
  incompleteManifest.expected_sha256 = hashFile(incompletePath);
  assert.throws(
    () => renderFixture(incompleteCln),
    /cln-bundle\.sha256 targets must equal the closed-world set/,
  );

  const extraCln = makeIssuerFixture(t);
  const extraClnBytes = Buffer.from("unreviewed-cln-plugin\n");
  const extraClnRoot =
    `/opt/bitcoinpir/core-lightning/${extraCln.plan.placeholders.CLN_BUNDLE_SHA256}`;
  const extraClnTarget = `${extraClnRoot}/libexec/c-lightning/plugins/evil`;
  extraCln.plan.payload_artifacts.push(
    addPayload(extraCln, extraClnTarget, extraClnBytes, 199),
  );
  const extraClnManifest = extraCln.plan.payload_artifacts.find((entry) =>
    entry.target_path.endsWith("/cln-bundle.sha256"),
  );
  const extraClnManifestPath = join(extraCln.inputRoot, extraClnManifest.source_path);
  const extraClnLines = [
    ...readFileSync(extraClnManifestPath, "utf8").trimEnd().split("\n"),
    `${hashBytes(extraClnBytes)}  ${extraClnTarget}`,
  ].sort((left, right) => {
    const leftTarget = left.slice(66);
    const rightTarget = right.slice(66);
    return leftTarget < rightTarget ? -1 : leftTarget > rightTarget ? 1 : 0;
  });
  writeFileSync(extraClnManifestPath, `${extraClnLines.join("\n")}\n`);
  extraClnManifest.expected_sha256 = hashFile(extraClnManifestPath);
  assert.throws(
    () => renderFixture(extraCln),
    /cln-bundle\.sha256 targets must equal the closed-world set/,
  );

  const executableDisabledPlugin = makeIssuerFixture(t);
  executableDisabledPlugin.plan.payload_artifacts.find((entry) =>
    entry.target_path.endsWith("/libexec/c-lightning/plugins/commando"),
  ).mode = "0555";
  assert.throws(
    () => renderFixture(executableDisabledPlugin),
    /disabled CLN plugin must be immutable root:root mode 0444/,
  );

  const inertAllowedPlugin = makeIssuerFixture(t);
  inertAllowedPlugin.plan.payload_artifacts.find((entry) =>
    entry.target_path.endsWith("/libexec/c-lightning/plugins/bcli"),
  ).mode = "0444";
  assert.throws(
    () => renderFixture(inertAllowedPlugin),
    /executable binary must be immutable root:root mode 0555/,
  );

  const missingLibpq = makeIssuerFixture(t);
  const missingLibpqManifest = missingLibpq.plan.payload_artifacts.find((entry) =>
    entry.target_path.endsWith("/cln-libpq.sha256"),
  );
  const missingLibpqPath = join(
    missingLibpq.inputRoot,
    missingLibpqManifest.source_path,
  );
  writeFileSync(
    missingLibpqPath,
    readFileSync(missingLibpqPath, "utf8")
      .split("\n")
      .filter((line) => !line.endsWith("/libpq.so.5"))
      .join("\n"),
  );
  missingLibpqManifest.expected_sha256 = hashFile(missingLibpqPath);
  assert.throws(() => renderFixture(missingLibpq), /non-empty|must bind only/);

  const extraLoader = makeIssuerFixture(t);
  const extraLoaderBytes = Buffer.from("unreviewed-loader-library\n");
  const extraLoaderTarget =
    `/opt/bitcoinpir/core-lightning-libpq/${extraLoader.plan.placeholders.CLN_LIBPQ_SHA256}` +
    "/libssl.so.3";
  extraLoader.plan.payload_artifacts.push(
    addPayload(extraLoader, extraLoaderTarget, extraLoaderBytes, 99),
  );
  const extraLoaderManifest = extraLoader.plan.payload_artifacts.find((entry) =>
    entry.target_path.endsWith("/cln-libpq.sha256"),
  );
  const extraLoaderManifestPath = join(
    extraLoader.inputRoot,
    extraLoaderManifest.source_path,
  );
  const extraLoaderLines = [
    ...readFileSync(extraLoaderManifestPath, "utf8").trimEnd().split("\n"),
    `${hashBytes(extraLoaderBytes)}  ${extraLoaderTarget}`,
  ].sort((left, right) => {
    const leftTarget = left.slice(66);
    const rightTarget = right.slice(66);
    return leftTarget < rightTarget ? -1 : leftTarget > rightTarget ? 1 : 0;
  });
  writeFileSync(extraLoaderManifestPath, `${extraLoaderLines.join("\n")}\n`);
  extraLoaderManifest.expected_sha256 = hashFile(extraLoaderManifestPath);
  assert.throws(
    () => renderFixture(extraLoader),
    /must bind only/,
  );
});

test("Core Lightning receives only its content-addressed private libpq root", (t) => {
  const template = "deploy/payment-v1/systemd/hetzner-core-lightning.service.in";
  const expectedEnvironment =
    "Environment=LD_LIBRARY_PATH=/opt/bitcoinpir/core-lightning-libpq/@CLN_LIBPQ_SHA256@";
  for (const [replacement, expected] of [
    ["", /content-addressed libpq root/],
    [
      "Environment=LD_LIBRARY_PATH=/tmp:/opt/bitcoinpir/core-lightning-libpq/@CLN_LIBPQ_SHA256@",
      /content-addressed libpq root/,
    ],
    ["Environment=LD_PRELOAD=/tmp/evil.so", /content-addressed libpq root/],
  ]) {
    const fixture = makeIssuerFixture(t);
    updateTemplate(fixture, template, (text) =>
      text.replace(`${expectedEnvironment}\n`, replacement === "" ? "" : `${replacement}\n`),
    );
    assert.throws(() => renderFixture(fixture), expected);
  }

  const unmounted = makeIssuerFixture(t);
  updateTemplate(unmounted, template, (text) =>
    text.replace(
      " /opt/bitcoinpir/core-lightning-libpq/@CLN_LIBPQ_SHA256@/",
      "",
    ),
  );
  assert.throws(
    () => renderFixture(unmounted),
    /mount exactly its config, CLN, libpq and Bitcoin Core roots read-only/,
  );

  const wrongDigest = makeIssuerFixture(t);
  wrongDigest.plan.placeholders.CLN_LIBPQ_SHA256 = "1".repeat(64);
  assert.throws(
    () => renderFixture(wrongDigest),
    /CLN_LIBPQ_SHA256 must select|must bind only|dependency is missing|references missing artifact/,
  );

  const dishonestDigest = makeIssuerFixture(t);
  const originalLibpqTarget = dishonestDigest.plan.payload_artifacts.find((entry) =>
    entry.target_path.endsWith("/libpq.so.5"),
  ).target_path;
  const dishonestLibpqTarget =
    `/opt/bitcoinpir/core-lightning-libpq/${"2".repeat(64)}/libpq.so.5`;
  dishonestDigest.plan.placeholders.CLN_LIBPQ_SHA256 = "2".repeat(64);
  dishonestDigest.plan.payload_artifacts.find((entry) =>
    entry.target_path === originalLibpqTarget
  ).target_path = dishonestLibpqTarget;
  const dishonestManifest = dishonestDigest.plan.payload_artifacts.find((entry) =>
    entry.target_path.endsWith("/cln-libpq.sha256"),
  );
  const dishonestManifestPath = join(
    dishonestDigest.inputRoot,
    dishonestManifest.source_path,
  );
  writeFileSync(
    dishonestManifestPath,
    readFileSync(dishonestManifestPath, "utf8").replace(
      originalLibpqTarget,
      dishonestLibpqTarget,
    ),
  );
  dishonestManifest.expected_sha256 = hashFile(dishonestManifestPath);
  assert.throws(
    () => renderFixture(dishonestDigest),
    /CLN_LIBPQ_SHA256 must equal the selected single-file binary digest/,
  );

  const model = renderFixture(makeIssuerFixture(t));
  const manifest = structuredClone(model.manifest);
  const unit = manifest.runtime_units.find(
    (entry) => entry.unit_name === "bitcoinpir-core-lightning.service",
  );
  unit.environment = ["LD_PRELOAD=/tmp/evil.so"];
  assert.throws(
    () => runtimeRequestFromManifest(
      manifest,
      hashBytes(Buffer.from(canonicalJson(manifest))),
    ),
    /content-addressed libpq root/,
  );

  const unmountedManifest = structuredClone(model.manifest);
  const unmountedUnit = unmountedManifest.runtime_units.find(
    (entry) => entry.unit_name === "bitcoinpir-core-lightning.service",
  );
  unmountedUnit.hardening.ReadOnlyPaths = [
    unmountedUnit.hardening.ReadOnlyPaths[0].replace(
      / \/opt\/bitcoinpir\/core-lightning-libpq\/[0-9a-f]{64}\//u,
      "",
    ),
  ];
  assert.throws(
    () => runtimeRequestFromManifest(
      unmountedManifest,
      hashBytes(Buffer.from(canonicalJson(unmountedManifest))),
    ),
    /mount exactly its config, CLN, libpq and Bitcoin Core roots read-only/,
  );
});

test("Core Lightning requires and masks its root-owned base plugin placeholder", (t) => {
  const template = "deploy/payment-v1/systemd/hetzner-core-lightning.service.in";
  const exact =
    "InaccessiblePaths=/srv/lightning/plugins";
  for (const replacement of [
    "",
    "InaccessiblePaths=-/srv/lightning/plugins",
    "InaccessiblePaths=/srv/lightning/@LIGHTNING_NETWORK@/plugins",
  ]) {
    const fixture = makeIssuerFixture(t);
    updateTemplate(fixture, template, (text) =>
      text.replace(`${exact}\n`, replacement === "" ? "" : `${replacement}\n`),
    );
    assert.throws(
      () => renderFixture(fixture),
      /fail closed unless it can mask the exact CLN base plugin directory|closed-world forbidden directive/,
    );
  }

  for (const [mutation, expected] of [
    [
      (text) => text.replace("d /srv/lightning/plugins                       0555 root root - -\n", ""),
      /exactly four directories|closed-world layout/,
    ],
    [
      (text) => text.replace("0555 root root", "0755 bitcoinpir-lightning root"),
      /closed-world layout|unreviewed runtime directory|mode/,
    ],
  ]) {
    const fixture = makeIssuerFixture(t);
    updateTemplate(
      fixture,
      "deploy/payment-v1/lightning/cln-rpc-guard-tmpfiles.conf.in",
      mutation,
    );
    assert.throws(() => renderFixture(fixture), expected);
  }

  const model = renderFixture(makeIssuerFixture(t));
  const manifest = structuredClone(model.manifest);
  const unit = manifest.runtime_units.find(
    (entry) => entry.unit_name === "bitcoinpir-core-lightning.service",
  );
  unit.hardening.InaccessiblePaths = ["-/srv/lightning/plugins"];
  assert.throws(
    () => runtimeRequestFromManifest(
      manifest,
      hashBytes(Buffer.from(canonicalJson(manifest))),
    ),
    /fail closed unless it can mask the exact CLN base plugin directory/,
  );

  const missingPlaceholderManifest = structuredClone(model.manifest);
  missingPlaceholderManifest.tmpfiles_directories =
    missingPlaceholderManifest.tmpfiles_directories.filter(
      (directory) => directory.target_path !== "/srv/lightning/plugins",
    );
  assert.throws(
    () => runtimeRequestFromManifest(
      missingPlaceholderManifest,
      hashBytes(Buffer.from(canonicalJson(missingPlaceholderManifest))),
    ),
    /tmpfiles directories must equal the exact protected host layout/,
  );
});

test("HAProxy content-address placeholder must equal the selected binary digest", (t) => {
  const fixture = makeEdgeFixture(t);
  fixture.plan.placeholders.HAPROXY_SHA256 = "1".repeat(64);
  assert.throws(
    () => renderFixture(fixture),
    /HAPROXY_SHA256 must select|must bind only|dependency is missing|references missing artifact/,
  );
});

test("systemd rejects duplicate single-valued directives even without an empty reset", (t) => {
  const fixture = makeEdgeFixture(t);
  updateTemplate(fixture, EDGE_UNIT, (text) =>
    text.replace("User=bitcoinpir-payment-edge", "User=bitcoinpir-payment-edge\nUser=root"),
  );
  assert.throws(() => renderFixture(fixture), /repeats single-valued directive Service.User/);
});

test("rendered profiles require exact profile-specific activation sentinels", (t) => {
  const fixture = makeEdgeFixture(t);
  updateTemplate(fixture, EDGE_UNIT, (text) =>
    text.replace(
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/EDGE-ACTIVATION-APPROVED",
      "ConditionPathExists=/etc/bitcoinpir/payment-v1/PROVIDER-ACTIVATION-APPROVED",
    ),
  );
  assert.throws(() => renderFixture(fixture), /profile-specific activation conditions/);

  for (const sourcePath of ISSUER_TEMPLATES.filter((path) => path.endsWith(".service.in"))) {
    const phaseSentinel = sourcePath.endsWith("hetzner-core-lightning.service.in")
      ? "SIGNET-LIGHTNING-STAGING-APPROVED"
      : "SIGNET-ISSUER-ACTIVATION-APPROVED";
    const issuer = makeIssuerFixture(t);
    updateTemplate(issuer, sourcePath, (text) =>
      text.replace(
        `ConditionPathExists=/etc/bitcoinpir/payment-v1/${phaseSentinel}\n`,
        "",
      ),
    );
    assert.throws(
      () => renderFixture(issuer),
      /profile-specific activation conditions/,
      sourcePath,
    );
  }

  for (const sourcePath of [
    GUARD_UNIT,
    PREFLIGHT_UNIT,
    "deploy/payment-v1/systemd/hetzner-payment-issuer.service.in",
  ]) {
    const issuer = makeIssuerFixture(t);
    updateTemplate(issuer, sourcePath, (text) =>
      text.replace(
        "ConditionPathExists=/etc/bitcoinpir/payment-v1/CLN-LOADER-MAPS-APPROVED\n",
        "",
      ),
    );
    assert.throws(
      () => renderFixture(issuer),
      /profile-specific activation conditions/,
      `${sourcePath} must retain the CLN loader maps approval blocker`,
    );
  }

  for (const [label, factory, unit, foreignSentinels] of [
    [
      "provider-v1",
      makeProviderFixture,
      PROVIDER_UNIT,
      [
        "PROVIDER-DIRECT-ACTIVATION-APPROVED",
        "PROVIDER-NO-STANDARD-CASHU-ACTIVATION-APPROVED",
      ],
    ],
    [
      "provider-no-standard-cashu-v1",
      makeProviderNoStandardCashuFixture,
      PROVIDER_NO_STANDARD_CASHU_UNIT,
      ["PROVIDER-ACTIVATION-APPROVED", "PROVIDER-DIRECT-ACTIVATION-APPROVED"],
    ],
    [
      "provider-direct-v1",
      makeProviderDirectFixture,
      PROVIDER_DIRECT_UNIT,
      [
        "PROVIDER-ACTIVATION-APPROVED",
        "PROVIDER-NO-STANDARD-CASHU-ACTIVATION-APPROVED",
      ],
    ],
  ]) {
    for (const sentinel of foreignSentinels) {
      const provider = factory(t);
      updateTemplate(provider, unit, (text) => text.replace(
        `ConditionPathExists=!/etc/bitcoinpir/payment-v1/${sentinel}\n`,
        "",
      ));
      assert.throws(
        () => renderFixture(provider),
        /profile-specific activation conditions/,
        `${label} must fail closed without negative ${sentinel}`,
      );
    }
  }
});

test("Lightning bootstrap cannot be collapsed into the post-channel issuer phase", (t) => {
  const coreTemplate = "deploy/payment-v1/systemd/hetzner-core-lightning.service.in";
  for (const forbidden of [
    "SIGNET-ISSUER-ACTIVATION-APPROVED",
    "LIGHTNING-BACKUP-RESTORE-APPROVED",
    "CLN-LOADER-MAPS-APPROVED",
  ]) {
    const fixture = makeIssuerFixture(t);
    updateTemplate(fixture, coreTemplate, (text) =>
      text.replace(
        "ConditionPathExists=/etc/bitcoinpir/payment-v1/LIGHTNING-CUSTODY-APPROVED\n",
        `ConditionPathExists=/etc/bitcoinpir/payment-v1/LIGHTNING-CUSTODY-APPROVED\nConditionPathExists=/etc/bitcoinpir/payment-v1/${forbidden}\n`,
      ),
    );
    assert.throws(() => renderFixture(fixture), /profile-specific activation conditions/);
  }

  for (const sourcePath of [
    "deploy/payment-v1/systemd/hetzner-cln-rpc-guard.service.in",
    "deploy/payment-v1/systemd/hetzner-lightning-preflight.service.in",
    "deploy/payment-v1/systemd/hetzner-payment-issuer.service.in",
  ]) {
    const fixture = makeIssuerFixture(t);
    updateTemplate(fixture, sourcePath, (text) =>
      text.replace(
        "ConditionPathExists=/etc/bitcoinpir/payment-v1/LIGHTNING-BACKUP-RESTORE-APPROVED\n",
        "",
      ),
    );
    assert.throws(() => renderFixture(fixture), /profile-specific activation conditions/);
  }
});

test("offline manifest verification rechecks profile-specific activation sentinels", (t) => {
  const fixture = makeEdgeFixture(t);
  const model = renderFixture(fixture);
  const manifest = structuredClone(model.manifest);
  manifest.runtime_units[0].conditions = manifest.runtime_units[0].conditions.filter(
    (condition) => !condition.endsWith("/EDGE-ACTIVATION-APPROVED"),
  );
  assert.throws(
    () => runtimeRequestFromManifest(
      manifest,
      hashBytes(Buffer.from(canonicalJson(manifest))),
    ),
    /profile-specific activation conditions/,
  );

  const issuer = renderFixture(makeIssuerFixture(t));
  for (let index = 0; index < issuer.manifest.runtime_units.length; index += 1) {
    const issuerManifest = structuredClone(issuer.manifest);
    const phaseSentinel = issuerManifest.runtime_units[index].unit_name ===
      "bitcoinpir-core-lightning.service"
      ? "/SIGNET-LIGHTNING-STAGING-APPROVED"
      : "/SIGNET-ISSUER-ACTIVATION-APPROVED";
    issuerManifest.runtime_units[index].conditions =
      issuerManifest.runtime_units[index].conditions.filter(
        (condition) => !condition.endsWith(phaseSentinel),
      );
    assert.throws(
      () => runtimeRequestFromManifest(
        issuerManifest,
        hashBytes(Buffer.from(canonicalJson(issuerManifest))),
      ),
      /profile-specific activation conditions/,
      issuerManifest.runtime_units[index].unit_name,
    );
  }

  for (const unitName of [
    "bitcoinpir-lightning-preflight.service",
    "bitcoinpir-cln-rpc-guard.service",
    "bitcoinpir-payment-issuer.service",
  ]) {
    const issuerManifest = structuredClone(issuer.manifest);
    const unit = issuerManifest.runtime_units.find(
      (entry) => entry.unit_name === unitName,
    );
    unit.conditions = unit.conditions.filter(
      (condition) => !condition.endsWith("/CLN-LOADER-MAPS-APPROVED"),
    );
    assert.throws(
      () => runtimeRequestFromManifest(
        issuerManifest,
        hashBytes(Buffer.from(canonicalJson(issuerManifest))),
      ),
      /profile-specific activation conditions/,
      `${unitName} offline manifest must retain the loader maps blocker`,
    );
  }

  const coreBlockedManifest = structuredClone(issuer.manifest);
  const coreUnit = coreBlockedManifest.runtime_units.find(
    (entry) => entry.unit_name === "bitcoinpir-core-lightning.service",
  );
  coreUnit.conditions.push(
    "ConditionPathExists=/etc/bitcoinpir/payment-v1/CLN-LOADER-MAPS-APPROVED",
  );
  coreUnit.conditions.sort();
  assert.throws(
    () => runtimeRequestFromManifest(
      coreBlockedManifest,
      hashBytes(Buffer.from(canonicalJson(coreBlockedManifest))),
    ),
    /profile-specific activation conditions/,
    "core-lightning must remain startable for no-funds loader maps collection",
  );

  const direct = renderFixture(makeProviderDirectFixture(t));
  const directManifest = structuredClone(direct.manifest);
  directManifest.runtime_units[0].conditions = directManifest.runtime_units[0].conditions.filter(
    (condition) => !condition.includes("!/") || !condition.includes("PROVIDER-ACTIVATION-APPROVED"),
  );
  assert.throws(
    () => runtimeRequestFromManifest(
      directManifest,
      hashBytes(Buffer.from(canonicalJson(directManifest))),
    ),
    /profile-specific activation conditions/,
  );
});

test("size, depth, ASCII path, source symlink, and hardlink limits fail closed", (t) => {
  const marker = makeEdgeFixture(t);
  marker.plan.payload_artifacts[0].source_path = "INVALID-REPLACE-IN-PRIVATE-INPUT-ROOT/edge/caddy";
  assert.throws(() => renderFixture(marker), /invalid replacement marker/);

  const deep = makeEdgeFixture(t);
  deep.plan.payload_artifacts[0].source_path = `${"a/".repeat(25)}caddy`;
  assert.throws(() => renderFixture(deep), /depth limit/);

  const nonAscii = makeEdgeFixture(t);
  nonAscii.plan.payload_artifacts[0].source_path = "payload/caddÿ";
  assert.throws(() => renderFixture(nonAscii), /portable relative path/);

  const huge = makeEdgeFixture(t);
  const binary = huge.plan.payload_artifacts.find((entry) => entry.class === "binary");
  truncateSync(join(huge.inputRoot, binary.source_path), 512 * 1024 * 1024 + 1);
  assert.throws(() => renderFixture(huge), /size limit/);

  const symlink = makeEdgeFixture(t);
  const sourcePath = join(symlink.sourceRoot, EDGE_CONFIG);
  rmSync(sourcePath);
  symlinkSync(join(REPOSITORY, EDGE_CONFIG), sourcePath);
  assert.throws(() => renderFixture(symlink), /symlink|resolves through/);

  const hardlink = makeEdgeFixture(t);
  linkSync(join(hardlink.inputRoot, hardlink.plan.payload_artifacts[0].source_path), join(hardlink.root, "alias"));
  assert.throws(() => renderFixture(hardlink), /exactly one hard link/);
});

test("repository example deployment ids fail closed", (t) => {
  const fixture = makeEdgeFixture(t);
  fixture.plan.deployment_id = "replace-edge-hetzner-v1";
  assert.throws(() => renderFixture(fixture), /repository example marker/);
});

test("bundle tree rejects tamper, extra file, extra directory, symlink, hardlink, and deep tree", (t) => {
  const tamper = makeEdgeFixture(t);
  renderFixture(tamper);
  appendFileSync(join(tamper.bundleRoot, "payment-v1-manifest.json"), " ");
  assert.throws(() => verifyFixture(tamper), /byte mismatch/);

  const extra = makeEdgeFixture(t);
  renderFixture(extra);
  writeFileSync(join(extra.bundleRoot, "extra"), "x", { mode: 0o600 });
  assert.throws(() => verifyFixture(extra), /bundle files must equal/);

  const directory = makeEdgeFixture(t);
  renderFixture(directory);
  mkdirSync(join(directory.bundleRoot, "extra"), { mode: 0o700 });
  assert.throws(() => verifyFixture(directory), /bundle directories must equal/);

  const symlink = makeEdgeFixture(t);
  renderFixture(symlink);
  symlinkSync("payment-v1-manifest.json", join(symlink.bundleRoot, "alias"));
  assert.throws(() => verifyFixture(symlink), /contains symlink/);

  const hardlink = makeEdgeFixture(t);
  renderFixture(hardlink);
  linkSync(join(hardlink.bundleRoot, "payment-v1-manifest.json"), join(hardlink.bundleRoot, "alias"));
  assert.throws(() => verifyFixture(hardlink), /multiple hard links/);

  const deep = makeEdgeFixture(t);
  renderFixture(deep);
  let cursor = deep.bundleRoot;
  for (let index = 0; index < 28; index += 1) {
    cursor = join(cursor, "d");
    mkdirSync(cursor, { mode: 0o700 });
  }
  assert.throws(() => verifyFixture(deep), /depth limit/);
});

test("CLI requires the external plan pin and rejects the retired shallow runtime verifier", (t) => {
  const fixture = makeEdgeFixture(t);
  const planPath = join(fixture.root, "plan.json");
  writeFileSync(planPath, canonicalJson(fixture.plan));
  const common = [
    "--source-root", fixture.sourceRoot,
    "--input-root", fixture.inputRoot,
    "--plan", planPath,
    "--approved-plan-sha256", approved(fixture.plan),
    "--bundle", fixture.bundleRoot,
  ];
  const missingPin = spawnSync(process.execPath, [GATE, "render", ...common.filter((_, index) => index < 6 || index > 7)], { encoding: "utf8" });
  assert.notEqual(missingPin.status, 0);
  const rendered = spawnSync(process.execPath, [GATE, "render", ...common], { encoding: "utf8" });
  assert.equal(rendered.status, 0, rendered.stderr);
  assert.equal(verifyFixture(fixture).manifest.deployment_profile, "edge-hetzner-v1");
  const retired = spawnSync(process.execPath, [GATE, "verify-runtime", ...common], {
    encoding: "utf8",
  });
  assert.notEqual(retired.status, 0);
  assert.match(retired.stderr, /<render\|verify>/);
});

test("strict JSON rejects duplicates and renderer never overwrites output", (t) => {
  assert.throws(() => parseStrictJson('{"a":1,"a":2}\n'), /repeats JSON key/);
  const fixture = makeEdgeFixture(t);
  mkdirSync(fixture.bundleRoot, { mode: 0o700 });
  assert.throws(() => renderFixture(fixture), /already exists/);
});
