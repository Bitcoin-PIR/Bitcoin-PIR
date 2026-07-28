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
  RUNTIME_COLLECTOR,
  canonicalJson,
  computeApprovedPlanSha256,
  parseStrictJson,
  renderBundle,
  validateRuntimeEvidence,
  verifyBundle,
} from "./payment-v1-rendered-artifact-gate.mjs";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY = resolve(SCRIPT_DIRECTORY, "..");
const GATE = join(SCRIPT_DIRECTORY, "payment-v1-rendered-artifact-gate.mjs");
const EDGE_UNIT = "deploy/payment-v1/systemd/payment-v1-edge.service.in";
const EDGE_CONFIG = "deploy/payment-v1/edge/hetzner-public.Caddyfile.in";
const GUARD_UNIT = "deploy/payment-v1/systemd/hetzner-cln-rpc-guard.service.in";
const PROVIDER_UNIT = "deploy/payment-v1/systemd/hetzner-provider.service.in";
const ISSUER_TEMPLATES = [
  "deploy/payment-v1/lightning/cln-rpc-guard-tmpfiles.conf.in",
  "deploy/payment-v1/lightning/lightningd.conf.in",
  "deploy/payment-v1/lightning/verify-layout.sh.in",
  "deploy/payment-v1/systemd/hetzner-cln-rpc-guard.service.in",
  "deploy/payment-v1/systemd/hetzner-core-lightning.service.in",
  "deploy/payment-v1/systemd/hetzner-lightning-preflight.service.in",
  "deploy/payment-v1/systemd/hetzner-payment-issuer.service.in",
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

function addPayload(fixture, targetPath, bytes, index) {
  const sourcePath = `payload/${String(index).padStart(3, "0")}-${basename(targetPath)}`;
  writeParent(join(fixture.inputRoot, sourcePath), bytes);
  return {
    ...payloadMetadata(targetPath),
    expected_sha256: hashBytes(bytes),
    source_path: sourcePath,
    target_path: targetPath,
  };
}

function makeEdgeFixture(t) {
  const fixture = temporaryRoots(t);
  copySource(fixture.sourceRoot, EDGE_UNIT);
  copySource(fixture.sourceRoot, EDGE_CONFIG);
  const caddyBytes = Buffer.from("reviewed-caddy-v2\n");
  const caddySha = hashBytes(caddyBytes);
  const placeholders = {
    CADDY_SHA256: caddySha,
    DIRECTORY_RELAY_WSS_HOST: "directory.example.net",
    EDGE_CADDYFILE: "hetzner-public.Caddyfile",
    PAYMENT_ISSUER_HTTPS_HOST: "pay.example.net",
    PROVIDER_WSS_HOST: "pir.example.net",
  };
  const renderedConfig = Buffer.from(renderText(fixture.sourceRoot, EDGE_CONFIG, placeholders));
  const targets = {
    binary: `/opt/bitcoinpir/caddy/${caddySha}/caddy`,
    binaryManifest: "/etc/bitcoinpir/payment-v1/edge/caddy.sha256",
    config: "/etc/bitcoinpir/payment-v1/edge/hetzner-public.Caddyfile",
    configManifest: "/etc/bitcoinpir/payment-v1/edge/edge-config.sha256",
  };
  const payloads = [
    [targets.binary, caddyBytes],
    [targets.binaryManifest, Buffer.from(`${caddySha}  ${targets.binary}\n`)],
    [
      targets.configManifest,
      Buffer.from(`${hashBytes(renderedConfig)}  ${targets.config}\n`),
    ],
  ];
  const plan = {
    deployment_id: "hetzner-edge-v1-test",
    deployment_profile: "edge-hetzner-v1",
    payload_artifacts: payloads.map(([target, bytes], index) => addPayload(fixture, target, bytes, index)),
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
        target_path: "/etc/systemd/system/bitcoinpir-payment-v1-edge.service",
        uid: 0,
      },
    ],
    schema_version: 1,
    service_identities: [{
      gid: 730,
      group_name: "bitcoinpir-payment-edge",
      uid: 729,
      unit_name: "bitcoinpir-payment-v1-edge.service",
      user_name: "bitcoinpir-payment-edge",
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
    CLN_BUNDLE_SHA256: hashBytes("cln-bundle"),
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
    lightningd: Buffer.from("reviewed-lightningd\n"),
  };
  const binaryDigests = Object.fromEntries(
    Object.entries(binaryBytes).map(([name, bytes]) => [name, hashBytes(bytes)]),
  );
  const placeholders = issuerPlaceholders(binaryDigests);
  const clnRoot = `/opt/bitcoinpir/core-lightning/${placeholders.CLN_BUNDLE_SHA256}`;
  const bitcoinRoot = `/opt/bitcoinpir/bitcoin-core/${placeholders.BITCOIN_CORE_BUNDLE_SHA256}`;
  const targets = {
    admin: `/opt/bitcoinpir/bpir-admin/${binaryDigests.admin}/bpir-admin`,
    bitcoinCli: `${bitcoinRoot}/bin/bitcoin-cli`,
    bcli: `${clnRoot}/plugins/bcli`,
    chanbackup: `${clnRoot}/plugins/chanbackup`,
    guard: `/opt/bitcoinpir/cln-rpc-guard/${binaryDigests.guard}/bitcoinpir-cln-rpc-guard`,
    issuer: `/opt/bitcoinpir/payment-issuer/${binaryDigests.issuer}/payment-issuer`,
    lightningd: `${clnRoot}/bin/lightningd`,
  };
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
    "/etc/bitcoinpir/payment-v1/issuer/quote-delegation.bin": "delegation\n",
    "/etc/bitcoinpir/payment-v1/issuer/quote-signing.key": "quote-key\n",
    "/etc/bitcoinpir/payment-v1/issuer/redeem-response-derivation.key": "redeem-key\n",
    "/etc/bitcoinpir/payment-v1/issuer/remote-rollback-authority.toml": "profile = \"remote-v1\"\n",
    "/etc/bitcoinpir/payment-v1/issuer/service-policy.bin": "policy\n",
    "/etc/bitcoinpir/payment-v1/lightning/backup-receipt.json": "{}\n",
    "/etc/bitcoinpir/payment-v1/lightning/preflight.toml": "profile = \"signet-v1\"\n",
  };
  const digestFor = new Map([
    ...Object.entries(targets).map(([name, target]) => [target, binaryDigests[name]]),
    [renderedTargets.config, renderedHashes.config],
    [renderedTargets.verifier, renderedHashes.verifier],
    ...Object.entries(directFiles).map(([target, bytes]) => [target, hashBytes(bytes)]),
  ]);
  const manifestEntries = {
    "/etc/bitcoinpir/payment-v1/issuer/payment-issuer.sha256": [targets.issuer],
    "/etc/bitcoinpir/payment-v1/lightning/backup-receipt.sha256": [
      "/etc/bitcoinpir/payment-v1/lightning/backup-receipt.json",
    ],
    "/etc/bitcoinpir/payment-v1/lightning/bitcoin-core-bundle.sha256": [targets.bitcoinCli],
    "/etc/bitcoinpir/payment-v1/lightning/bpir-admin.sha256": [targets.admin],
    "/etc/bitcoinpir/payment-v1/lightning/cln-bundle.sha256": [targets.lightningd, targets.bcli, targets.chanbackup],
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
    ...Object.entries(directFiles),
    ...Object.entries(manifestFiles),
  ].sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
  const plan = {
    deployment_id: "issuer-lightning-signet-v1-test",
    deployment_profile: "issuer-lightning-signet-v1",
    payload_artifacts: payloadContents.map(([target, bytes], index) => {
      const artifact = addPayload(fixture, target, bytes, index);
      return artifact.class === "secret"
        ? { ...artifact, gid: Number(placeholders.ISSUER_GID), mode: "0400", uid: Number(placeholders.ISSUER_UID) }
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
    schema_version: 1,
    service_identities: [
      { gid: 734, group_name: "bitcoinpir-cln-guard", uid: 735, unit_name: "bitcoinpir-cln-rpc-guard.service", user_name: "bitcoinpir-cln-rpc-guard" },
      { gid: 734, group_name: "bitcoinpir-cln-guard", uid: 733, unit_name: "bitcoinpir-core-lightning.service", user_name: "bitcoinpir-lightning" },
      { gid: 736, group_name: "bitcoinpir-lightning-preflight", uid: 737, unit_name: "bitcoinpir-lightning-preflight.service", user_name: "bitcoinpir-lightning-preflight" },
      { gid: 732, group_name: "bitcoinpir-issuer", uid: 731, unit_name: "bitcoinpir-payment-issuer.service", user_name: "bitcoinpir-issuer" },
    ],
  };
  return { ...fixture, plan };
}

function makeProviderFixture(t) {
  const fixture = temporaryRoots(t);
  const source = PROVIDER_UNIT;
  copySource(fixture.sourceRoot, source);
  const binaryBytes = Buffer.from("reviewed-unified-server\n");
  const binarySha = hashBytes(binaryBytes);
  const binaryTarget = `/opt/bitcoinpir/unified-server/${binarySha}/unified_server`;
  const directFiles = {
    "/etc/bitcoinpir/payment-v1/provider/cashu-bat.key": "bat\n",
    "/etc/bitcoinpir/payment-v1/provider/cashu-custody-epoch-1.key": "custody\n",
    "/etc/bitcoinpir/payment-v1/provider/cashu-recovery-epoch-1.key": "recovery\n",
    "/etc/bitcoinpir/payment-v1/provider/databases.toml": "profile = \"provider-v1\"\n",
    "/etc/bitcoinpir/payment-v1/provider/provider-clearing-signing.key": "clearing\n",
    "/etc/bitcoinpir/payment-v1/provider/provider-identity.cert": "certificate\n",
    "/etc/bitcoinpir/payment-v1/provider/provider-identity.key": "identity\n",
    "/etc/bitcoinpir/payment-v1/provider/remote-rollback-authority.toml": "profile = \"remote-v1\"\n",
    "/etc/bitcoinpir/payment-v1/provider/service-policy.bin": "policy\n",
    "/etc/bitcoinpir/payment-v1/provider/shared-clearing-approval.bin": "approval\n",
    "/etc/bitcoinpir/payment-v1/provider/shared-clearing-authorization.bin": "authorization\n",
    "/etc/bitcoinpir/payment-v1/provider/shared-redeem-idempotency.key": "idempotency\n",
  };
  const manifestTarget = "/etc/bitcoinpir/payment-v1/provider/unified-server.sha256";
  const contents = [
    [binaryTarget, binaryBytes],
    [manifestTarget, `${binarySha}  ${binaryTarget}\n`],
    ...Object.entries(directFiles),
  ].sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
  const placeholders = {
    CASHU_MAX_UNSETTLED_NOTES: "1000",
    CASHU_MAX_UNSETTLED_VALUE: "100000",
    CASHU_MINT_ID_HEX: "3".repeat(64),
    HETZNER_OPERATOR_PUBKEY_HEX: "4".repeat(64),
    HETZNER_POLICY_PUBKEY_HEX: "e".repeat(64),
    HETZNER_PROVIDER_ID_HEX: "f".repeat(64),
    HETZNER_PROVIDER_SERVER_ID: "hetzner-pir-0",
    ISSUER_SETTLEMENT_PUBKEY_HEX: "5".repeat(64),
    SHARED_MINIMUM_AUTHORIZATION_EPOCH: "1",
    UNIFIED_SERVER_SHA256: binarySha,
  };
  const plan = {
    deployment_id: "provider-v1-test",
    deployment_profile: "provider-v1",
    payload_artifacts: contents.map(([target, bytes], index) => {
      const artifact = addPayload(fixture, target, bytes, index);
      return artifact.class === "secret" ? { ...artifact, gid: 741, mode: "0400", uid: 740 } : artifact;
    }),
    placeholders,
    rendered_artifacts: [{
      gid: 0,
      mode: "0644",
      source_path: source,
      source_sha256: hashFile(join(fixture.sourceRoot, source)),
      target_path: "/etc/systemd/system/bitcoinpir-provider.service",
      uid: 0,
    }],
    schema_version: 1,
    service_identities: [{ gid: 741, group_name: "bitcoinpir-provider", uid: 740, unit_name: "bitcoinpir-provider.service", user_name: "bitcoinpir-provider" }],
  };
  return { ...fixture, plan };
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
    schema_version: 1,
    service_identities: [{ gid: 743, group_name: "bitcoinpir-rollback-authority", uid: 742, unit_name: "bitcoinpir-rollback-authority.service", user_name: "bitcoinpir-rollback-authority" }],
  };
  return { ...fixture, plan };
}

function makeRollbackEdgeFixture(t) {
  const fixture = temporaryRoots(t);
  const source = "deploy/payment-v1/edge/rollback-authority.Caddyfile.in";
  copySource(fixture.sourceRoot, source);
  copySource(fixture.sourceRoot, EDGE_UNIT);
  const binaryBytes = Buffer.from("reviewed-caddy-rollback\n");
  const binarySha = hashBytes(binaryBytes);
  const binaryTarget = `/opt/bitcoinpir/caddy/${binarySha}/caddy`;
  const configTarget = "/etc/bitcoinpir/payment-v1/edge/rollback-authority.Caddyfile";
  const placeholders = {
    CADDY_SHA256: binarySha,
    EDGE_CADDYFILE: "rollback-authority.Caddyfile",
    ROLLBACK_AUTHORITY_HTTPS_HOST: "authority.example.net",
  };
  const configSha = hashBytes(renderText(fixture.sourceRoot, source, placeholders));
  const contents = [
    [binaryTarget, binaryBytes],
    ["/etc/bitcoinpir/payment-v1/edge/caddy.sha256", `${binarySha}  ${binaryTarget}\n`],
    ["/etc/bitcoinpir/payment-v1/edge/edge-config.sha256", `${configSha}  ${configTarget}\n`],
  ];
  const plan = {
    deployment_id: "rollback-edge-v1-test",
    deployment_profile: "edge-rollback-authority-v1",
    payload_artifacts: contents.map(([target, bytes], index) => addPayload(fixture, target, bytes, index)),
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
        source_path: EDGE_UNIT,
        source_sha256: hashFile(join(fixture.sourceRoot, EDGE_UNIT)),
        target_path: "/etc/systemd/system/bitcoinpir-payment-v1-edge.service",
        uid: 0,
      },
    ],
    schema_version: 1,
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

function makeRuntimeEvidence(model) {
  return {
    collected_at_unix_seconds: 1_800_000_000,
    collector: RUNTIME_COLLECTOR,
    host: {
      boot_id: "12345678-1234-4abc-8def-123456789abc",
      kernel_release: "6.8.0-bitcoinpir",
      machine_id_sha256: hashBytes("test-machine"),
      systemd_version: "systemd-257.7",
    },
    installed_files: clone(model.request.installed_files),
    manifest_sha256: model.manifestSha256,
    schema_version: 1,
    systemd_analyze_verify: {
      argv: clone(model.request.systemd_analyze_argv),
      exit_status: 0,
      stderr: "",
      stdout: "",
    },
    units: model.request.units.map((unit) => ({
      active_state: "inactive",
      conditions: clone(unit.conditions),
      drop_in_paths: [],
      environment: clone(unit.environment),
      environment_files: clone(unit.environment_files),
      exec_start: clone(unit.exec_start),
      exec_start_pre: clone(unit.exec_start_pre),
      fragment_path: unit.fragment_path,
      hardening: clone(unit.hardening),
      load_state: "loaded",
      unit_name: unit.unit_name,
    })),
  };
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
  assert.equal(verifyFixture(fixture).manifestSha256, first.manifestSha256);
  const secondRoot = join(fixture.root, "second");
  const second = renderFixture(fixture, secondRoot);
  assert.equal(second.manifestSha256, first.manifestSha256);
  assert.deepEqual(
    readdirSync(fixture.bundleRoot, { recursive: true }).sort(),
    readdirSync(secondRoot, { recursive: true }).sort(),
  );
});

test("complete issuer profile closes core, guard, tmpfiles, preflight, issuer, and referenced files", (t) => {
  const fixture = makeIssuerFixture(t);
  const model = renderFixture(fixture);
  assert.equal(model.request.units.length, 4);
  assert.equal(model.request.tmpfiles_directories.length, 2);
  assert.equal(model.manifest.deployment_profile, "issuer-lightning-signet-v1");
  assert.equal(verifyFixture(fixture).manifestSha256, model.manifestSha256);
});

test("issuer profile keeps the CLN guard deadman non-restarting", (t) => {
  const fixture = makeIssuerFixture(t);
  updateTemplate(fixture, GUARD_UNIT, (text) =>
    text.replace("Restart=no", "Restart=on-failure\nRestartSec=5"),
  );
  assert.throws(() => renderFixture(fixture), /CLN guard deadman Restart=no/);
});

for (const directive of ["PrivateDevices", "ProtectClock", "ProtectHostname"]) {
  test(`provider profile keeps ${directive}=true`, (t) => {
    const fixture = makeProviderFixture(t);
    updateTemplate(fixture, PROVIDER_UNIT, (text) =>
      text.replace(`${directive}=true`, `${directive}=false`),
    );
    assert.throws(() => renderFixture(fixture), new RegExp(`provider ${directive}=true`));
  });
}

for (const [label, factory, profile] of [
  ["provider", makeProviderFixture, "provider-v1"],
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
        /dependency is missing|references missing artifact/,
        artifact.target_path,
      );
    }
  });
}

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
      /dependency is missing|references missing artifact/,
      artifact.target_path,
    );
  }
});

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
  ["LoadCredential", "secret:/tmp/secret"],
  ["SetCredential", "secret:evil"],
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

test("hash manifests are strict, sorted, complete, and bind actual artifacts", (t) => {
  const wrong = makeEdgeFixture(t);
  const manifest = wrong.plan.payload_artifacts.find((entry) => entry.target_path.endsWith("caddy.sha256"));
  writeFileSync(join(wrong.inputRoot, manifest.source_path), `${"1".repeat(64)}  ${wrong.targets.binary}\n`);
  manifest.expected_sha256 = hashFile(join(wrong.inputRoot, manifest.source_path));
  assert.throws(() => renderFixture(wrong), /wrong digest/);

  const malformed = makeEdgeFixture(t);
  const second = malformed.plan.payload_artifacts.find((entry) => entry.target_path.endsWith("caddy.sha256"));
  writeFileSync(join(malformed.inputRoot, second.source_path), `${hashBytes("x")} *${malformed.targets.binary}\n`);
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
});

test("systemd rejects duplicate single-valued directives even without an empty reset", (t) => {
  const fixture = makeEdgeFixture(t);
  updateTemplate(fixture, EDGE_UNIT, (text) =>
    text.replace("User=bitcoinpir-payment-edge", "User=bitcoinpir-payment-edge\nUser=root"),
  );
  assert.throws(() => renderFixture(fixture), /repeats single-valued directive Service.User/);
});

test("size, depth, ASCII path, source symlink, and hardlink limits fail closed", (t) => {
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

test("runtime structure remains manifest-bound and rejects drop-ins, reset effects, and drift", (t) => {
  const fixture = makeEdgeFixture(t);
  const model = renderFixture(fixture);
  const valid = makeRuntimeEvidence(model);
  assert.equal(validateRuntimeEvidence({ evidence: valid, model }), true);

  for (const [label, mutate, expected] of [
    ["drop-in", (e) => e.units[0].drop_in_paths.push("/etc/systemd/system/x.d/evil.conf"), /drop_in_paths must be empty/],
    ["ExecStart reset", (e) => { e.units[0].exec_start = ["/usr/bin/true"]; }, /exec_start does not match/],
    ["ExecStartPre reset", (e) => { e.units[0].exec_start_pre = []; }, /exec_start_pre does not match/],
    ["environment", (e) => e.units[0].environment.push("LD_PRELOAD=/tmp/evil"), /environment does not match/],
    ["fragment", (e) => { e.units[0].fragment_path = "/run/systemd/transient/evil.service"; }, /fragment_path does not match/],
    ["file hash", (e) => { e.installed_files[0].sha256 = "3".repeat(64); }, /installed file evidence does not match/],
    ["host state", (e) => { e.units[0].active_state = "failed"; }, /active_state must be/],
  ]) {
    const evidence = makeRuntimeEvidence(model);
    mutate(evidence);
    assert.throws(() => validateRuntimeEvidence({ evidence, model }), expected, label);
  }
});

test("CLI requires external plan and evidence pins; forged or unpinned runtime JSON fails", (t) => {
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
  const model = verifyFixture(fixture);
  const evidencePath = join(fixture.root, "evidence.json");
  const evidenceBytes = Buffer.from(canonicalJson(makeRuntimeEvidence(model)));
  writeFileSync(evidencePath, evidenceBytes);
  const unpinned = spawnSync(process.execPath, [GATE, "verify-runtime", ...common, "--evidence", evidencePath], { encoding: "utf8" });
  assert.notEqual(unpinned.status, 0);
  assert.match(unpinned.stderr, /externally trusted evidence/);
  const wrong = spawnSync(process.execPath, [GATE, "verify-runtime", ...common, "--evidence", evidencePath, "--trusted-evidence-sha256", "1".repeat(64)], { encoding: "utf8" });
  assert.notEqual(wrong.status, 0);
  const pinned = spawnSync(process.execPath, [GATE, "verify-runtime", ...common, "--evidence", evidencePath, "--trusted-evidence-sha256", hashBytes(evidenceBytes)], { encoding: "utf8" });
  assert.equal(pinned.status, 0, pinned.stderr);
  assert.match(pinned.stdout, /offline pinned runtime structure PASS/);
});

test("strict JSON rejects duplicates and renderer never overwrites output", (t) => {
  assert.throws(() => parseStrictJson('{"a":1,"a":2}\n'), /repeats JSON key/);
  const fixture = makeEdgeFixture(t);
  mkdirSync(fixture.bundleRoot, { mode: 0o700 });
  assert.throws(() => renderFixture(fixture), /already exists/);
});
